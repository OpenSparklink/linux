// SPDX-License-Identifier: GPL-2.0-only

//! Preallocated command storage shared by the kernel and standalone tests.
//! Callers supply absolute deadlines; no clock, allocation, I/O or locks here.

use super::sle_command_plan::{
    valid_parts, DiscoveryIntent, RecipePart, RecipeTag, RECIPE_PARAMS_MAX, RECIPE_STEPS_MAX,
};

pub(crate) struct CmdRequest {
    pub(crate) seq: u32,
    pub(crate) cookie: u64,
    pub(crate) recipe: Option<RecipeTag>,
    pub(crate) deadline: u64,
    pub(crate) opcode: u16,
    pub(crate) params: [u8; RECIPE_PARAMS_MAX],
    pub(crate) param_len: u16,
}

pub(crate) const CMD_REQ_QUEUE_DEPTH: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum QueueError {
    Invalid,
    Full,
}

pub(crate) struct CmdRequestQueue {
    pub(crate) entries: [Option<CmdRequest>; CMD_REQ_QUEUE_DEPTH],
    pub(crate) head: usize,
    pub(crate) tail: usize,
    pub(crate) count: u16,
}

impl CmdRequestQueue {
    #[cfg(test)]
    pub(crate) const fn new() -> Self {
        Self {
            entries: [const { None }; CMD_REQ_QUEUE_DEPTH],
            head: 0,
            tail: 0,
            count: 0,
        }
    }

    pub(crate) fn push_tagged(
        &mut self,
        opcode: u16,
        params: &[u8],
        seq: u32,
        cookie: u64,
        recipe: Option<RecipeTag>,
        deadline: u64,
    ) -> Result<(), QueueError> {
        if params.len() > RECIPE_PARAMS_MAX {
            return Err(QueueError::Invalid);
        }
        if recipe.is_some_and(|tag| {
            seq != 0
                || cookie == 0
                || tag.cookie != cookie
                || tag.count == 0
                || tag.count as usize > RECIPE_STEPS_MAX
                || tag.step >= tag.count
        }) {
            return Err(QueueError::Invalid);
        }
        if self.count as usize >= CMD_REQ_QUEUE_DEPTH {
            return Err(QueueError::Full);
        }
        let mut request = CmdRequest {
            seq,
            cookie,
            recipe,
            deadline,
            opcode,
            params: [0; RECIPE_PARAMS_MAX],
            param_len: params.len() as u16,
        };
        request.params[..params.len()].copy_from_slice(params);
        self.entries[self.tail] = Some(request);
        self.tail = (self.tail + 1) % CMD_REQ_QUEUE_DEPTH;
        self.count += 1;
        Ok(())
    }

    /// Capacity and every parameter are checked before cancellation/insertion.
    /// Contiguous steps share one cookie and deadline. Error leaves the queue
    /// unchanged; no partial SetParam/SetData/Enable sequence can escape.
    pub(crate) fn push_recipe(
        &mut self,
        parts: &[RecipePart<'_>],
        cookie: u64,
        intent: DiscoveryIntent,
        deadline: u64,
    ) -> Result<(), QueueError> {
        if cookie == 0 || !valid_parts(parts, usize::MAX) {
            return Err(QueueError::Invalid);
        }
        if parts.len() > self.available() {
            return Err(QueueError::Full);
        }
        // A queued disable is a physical barrier for a subsequent start's
        // configuration. A newer start may discard older starts, not stops.
        self.remove_matching(intent, intent.enabled());
        for (step, part) in parts.iter().enumerate() {
            let tag = RecipeTag {
                cookie,
                step: step as u8,
                count: parts.len() as u8,
                intent,
            };
            // Preflight proves both bounds; no concurrent insertion is allowed.
            self.push_tagged(part.opcode, part.params, 0, cookie, Some(tag), deadline)?;
        }
        Ok(())
    }

    pub(crate) fn pop(&mut self) -> Option<CmdRequest> {
        if self.count == 0 {
            return None;
        }
        let request = self.entries[self.head].take();
        self.head = (self.head + 1) % CMD_REQ_QUEUE_DEPTH;
        if request.is_some() {
            self.count -= 1;
        }
        request
    }

    pub(crate) fn available(&self) -> usize {
        CMD_REQ_QUEUE_DEPTH - self.count as usize
    }
    pub(crate) fn len(&self) -> u16 {
        self.count
    }
    pub(crate) fn is_empty(&self) -> bool {
        self.count == 0
    }

    pub(crate) fn first_deadline(&self) -> Option<u64> {
        self.entries[self.head]
            .as_ref()
            .map(|request| request.deadline)
    }

    /// Preserve unrelated/raw requests and their order, even across wraparound.
    /// The already-on-wire reservation lives in Host, not this queue.
    pub(crate) fn remove_recipes(&mut self, intent: DiscoveryIntent) {
        self.remove_matching(intent, false);
    }

    fn remove_matching(&mut self, intent: DiscoveryIntent, starts_only: bool) {
        let count = self.count;
        for _ in 0..count {
            let Some(request) = self.pop() else { break };
            if request.recipe.is_some_and(|tag| {
                tag.intent.same_domain(intent) && (!starts_only || tag.intent.enabled())
            }) {
                continue;
            }
            self.entries[self.tail] = Some(request);
            self.tail = (self.tail + 1) % CMD_REQ_QUEUE_DEPTH;
            self.count += 1;
        }
    }
}
