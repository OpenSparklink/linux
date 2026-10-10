// SPDX-License-Identifier: GPL-2.0

//! Per-registration USB command scheduler. Every command shares the same
//! credit budget and bounded queue. One on-wire command waits for its Status
//! or Complete; asynchronous domain completion is a separate Host operation.
//! Matching management replies have a dedicated slot, not the discovery ring.

use kernel::prelude::*;
use kernel::time::msecs_to_jiffies;

use super::sle_dli::{SleEvent, SleOpcode};
use super::sle_discovery_operation::{Operations, Operation, State, AdmissionError};
use super::sle_mgmt::{CmdRequest, CmdRequestQueue, CMD_TIMEOUT_MS};
use super::sle_command_plan::{DiscoveryIntent, RecipePart, RecipeProgress, RecipeReply, RecipeTag};

struct InFlight {
    opcode: u16,
    seq: u32,
    cookie: u64,
    enable: Option<bool>,
    peer_addr: Option<[u8; 6]>,
    deadline: u64,
    recipe: Option<RecipeTag>,
}

pub(crate) struct HostReply {
    pub(crate) seq: u32,
    pub(crate) event: SleEvent,
    pub(crate) current_intent: bool,
    pub(crate) enable: Option<bool>,
    pub(crate) peer_addr: Option<[u8; 6]>,
    pub(crate) recipe: Option<(DiscoveryIntent, RecipeReply)>,
}

/// Access only under the owner's IRQ-safe host lock. No I/O or allocation
/// takes place while it is locked. Sequence zero denotes a typed internal
/// command; nonzero sequences refer to that owner's raw DLI pending entries.
pub(crate) struct CommandHost {
    requests: CmdRequestQueue,
    credits: u8,
    active: Option<InFlight>,
    reply: Option<SleEvent>,
    fault: Option<Error>,
    next_cookie: u64,
    broadcast_cookie: u64,
    scan_cookie: u64,
    recipe: Option<(RecipeTag, RecipeProgress)>,
    operations: Operations,
    revoking: bool,
    revoke_cookies: [u64; 2],
    revoke_done: u8,
    revoke_deadline: u64,
    revoke_status: u8,
    revoke_opcode: u16,
    revoke_reply: bool,
}

impl CommandHost {
    pub(crate) fn new_boxed(credits: u8) -> Result<KBox<Self>> {
        KBox::init(
            init!(Self {
                requests <- CmdRequestQueue::new_in_place(),
                credits,
                active: None,
                reply: None,
                fault: None,
            next_cookie: 1,
            broadcast_cookie: 0,
            scan_cookie: 0,
            recipe: None,
                revoking: false, revoke_cookies: [0; 2], revoke_done: 0, revoke_deadline: 0,
                revoke_status: 0, revoke_opcode: 0, revoke_reply: false,
                operations <- init!(Operations {
                    entries <- pin_init::init_array_from_fn(|_| None),
                    initialized: false,
                    advertising: 0,
                    scanning: 0,
                }),
            }),
            GFP_KERNEL,
        )
    }

    pub(crate) fn enqueue(&mut self, opcode: u16, params: &[u8], seq: u32) -> Result {
        if let Some(error) = self.fault {
            return Err(error);
        }
        let cookie = self.next_cookie;
        let next_cookie = cookie.checked_add(1).ok_or(EOVERFLOW)?;
        self.requests.push_cookie(opcode, params, seq, cookie)?;
        self.next_cookie = next_cookie;
        if opcode == SleOpcode::EnableBroadcast as u16 {
            self.broadcast_cookie = cookie;
            self.supersede_recipe(DiscoveryIntent::Advertising(false));
        }
        if opcode == SleOpcode::EnableScan as u16 {
            self.scan_cookie = cookie;
            self.supersede_recipe(DiscoveryIntent::Scanning(false));
        }
        Ok(())
    }

    fn supersede_recipe(&mut self, intent: DiscoveryIntent) {
        self.requests.remove_recipes(intent);
        self.cancel_recipe_progress(intent);
    }

    fn cancel_recipe_progress(&mut self, intent: DiscoveryIntent) {
        if let Some((tag, progress)) = &mut self.recipe {
            if tag.intent.same_domain(intent) && tag.intent.enabled() { progress.cancel(); }
        }
    }

    /// Preflight/copy the complete sequence under this owner's Host lock.
    /// Contiguous requests cannot interleave with an unrelated raw command.
    /// Each step waits for matching successful Complete, including native
    /// Status acceptance. A newer same-domain recipe removes old queued
    /// steps, while its already-on-wire command retains its reply reservation.
    pub(crate) fn enqueue_recipe(
        &mut self, intent: DiscoveryIntent, parts: &[RecipePart<'_>],
    ) -> Result {
        if let Some(error) = self.fault { return Err(error); }
        let cookie = self.next_cookie;
        let next_cookie = cookie.checked_add(1).ok_or(EOVERFLOW)?;
        // A bounded lifetime for the whole recipe, not four fresh timeouts.
        // SAFETY: reading the kernel clock does not dereference user memory.
        let deadline = unsafe { kernel::bindings::jiffies_64 }
            .wrapping_add(msecs_to_jiffies(CMD_TIMEOUT_MS) as u64);
        self.requests.push_recipe(parts, cookie, intent, deadline)?;
        self.cancel_recipe_progress(intent);
        self.next_cookie = next_cookie;
        match intent {
            DiscoveryIntent::Advertising(_) => self.broadcast_cookie = cookie,
            DiscoveryIntent::Scanning(_) => self.scan_cookie = cookie,
        }
        Ok(())
    }

    pub(crate) fn submit_discovery(
        &mut self, request_id: u64, intent: DiscoveryIntent,
        parts: &[RecipePart<'_>], power_step: u8,
    ) -> Result {
        if power_step as usize > parts.len() { return Err(EINVAL); }
        let slot = self.operations.slot(request_id).map_err(|error| match error {
            AdmissionError::Invalid => EINVAL,
            AdmissionError::Duplicate => EEXIST,
            AdmissionError::Full => EBUSY,
        })?;
        if intent.enabled() && !self.operations.can_start(intent) { return Err(EBUSY); }
        let cookie = self.next_cookie;
        self.enqueue_recipe(intent, parts)?;
        // Queue/cookie admission succeeded. Neither failure path above changed
        // operation storage. Stop supersedes prior public operations only now.
        self.operations.cancel_domain(intent, -(kernel::bindings::ECANCELED as i32));
        self.operations.entries[slot] = Some(Operation {
            request_id, cookie, intent, state: State::Queued, error: 0,
            status: 0, opcode: 0, step: 0, count: parts.len() as u8,
            power_step, selected_power: None,
        });
        Ok(())
    }

    /// Retain any active wire slot, but prevent queued enables from escaping.
    /// Caller drains raw pending entries before providing driver-prepared stops.
    pub(crate) fn begin_revoke(&mut self, adv: &[RecipePart<'_>], scan: &[RecipePart<'_>]) -> Result {
        if let Some(error) = self.fault { return Err(error); }
        self.operations.cancel_domain(DiscoveryIntent::Advertising(false), -(kernel::bindings::ECANCELED as i32));
        self.operations.cancel_domain(DiscoveryIntent::Scanning(false), -(kernel::bindings::ECANCELED as i32));
        self.revoke_cookies[0] = self.next_cookie;
        self.enqueue_recipe(DiscoveryIntent::Advertising(false), adv)?;
        self.revoke_cookies[1] = self.next_cookie;
        if let Err(error) = self.enqueue_recipe(DiscoveryIntent::Scanning(false), scan) {
            self.fail(error); return Err(error);
        }
        self.revoking = true; self.revoke_done = 0;
        self.revoke_status = 0; self.revoke_opcode = 0; self.revoke_reply = false;
        // SAFETY: reading the kernel clock has no pointer preconditions.
        self.revoke_deadline = unsafe { kernel::bindings::jiffies_64 }
            .wrapping_add(msecs_to_jiffies(CMD_TIMEOUT_MS) as u64);
        Ok(())
    }
    pub(crate) fn quiet(&self) -> bool {
        self.active.is_none() && self.reply.is_none() && self.requests.is_empty()
    }
    pub(crate) fn revocation_detail(&self) -> (u8, u16, bool) {
        (self.revoke_status, self.revoke_opcode, self.revoke_reply)
    }
    pub(crate) fn revocation_result(&self) -> Option<Result> {
        if let Some(error) = self.fault { return Some(Err(error)); }
        if self.revoking && self.revoke_done == 3 && self.quiet() { Some(Ok(())) } else { None }
    }

    pub(crate) fn controller_status(&self) -> (u8, bool, Option<Error>) {
        (
            self.credits,
            self.operations.initialized && self.fault.is_none(),
            self.fault,
        )
    }

    pub(crate) fn discovery_result(&self, request_id: u64) -> Option<Operation> {
        self.operations.find(request_id)
    }
    pub(crate) fn discovery_radio(&self) -> (u32, u32, Option<Error>) {
        (self.operations.advertising, self.operations.scanning, self.fault)
    }

    fn current_recipe(&self, tag: RecipeTag) -> bool {
        tag.cookie == match tag.intent {
            DiscoveryIntent::Advertising(_) => self.broadcast_cookie,
            DiscoveryIntent::Scanning(_) => self.scan_cookie,
        }
    }

    pub(crate) fn can_send(&self) -> bool {
        self.fault.is_none()
            && self.credits > 0
            && self.active.is_none()
            && !self.requests.is_empty()
    }

    pub(crate) fn next(&mut self, valid_raw: impl Fn(u32) -> bool) -> Result<Option<CmdRequest>> {
        if !self.can_send() {
            return Ok(None);
        }
        let request = loop {
            let Some(request) = self.requests.pop() else { return Ok(None) };
            if let Some(tag) = request.recipe {
                if tag.intent.enabled() && !self.current_recipe(tag) { continue; }
                // SAFETY: only reads the kernel clock.
                if unsafe { kernel::bindings::jiffies_64 } >= request.deadline {
                    return Err(ETIMEDOUT);
                }
                if tag.step == 0 {
                    let progress = RecipeProgress::new(tag.count).ok_or(EINVAL)?;
                    self.recipe = Some((tag, progress));
                }
                let (root, progress) = self.recipe.as_mut().ok_or(EINVAL)?;
                if root.cookie != tag.cookie || !progress.sent(tag.step) {
                    return Err(EINVAL);
                }
            }
            if request.seq == 0 || valid_raw(request.seq) {
                break request;
            }
            // A cancelled/expired queued transaction never reaches the wire.
        };
        self.credits -= 1;
        if request.recipe.is_some() { self.operations.sent(request.cookie, request.recipe.unwrap().step, request.opcode); }
        self.active = Some(InFlight {
            opcode: request.opcode,
            seq: request.seq,
            cookie: request.cookie,
            enable: if (request.opcode == SleOpcode::EnableBroadcast as u16
                || request.opcode == SleOpcode::EnableScan as u16)
                && request.param_len == 1
                && request.params[0] <= 1
            {
                Some(request.params[0] == 1)
            } else {
                None
            },
            peer_addr: if request.opcode == SleOpcode::CreateConnection as u16
                && request.param_len == 6
            {
                let mut addr = [0u8; 6];
                addr.copy_from_slice(&request.params[..6]);
                Some(addr)
            } else {
                None
            },
            // SAFETY: reading the kernel clock does not dereference user memory.
            deadline: unsafe { kernel::bindings::jiffies_64 }
                .wrapping_add(msecs_to_jiffies(CMD_TIMEOUT_MS) as u64)
                .min(if request.recipe.is_some() { request.deadline } else { u64::MAX }),
            recipe: request.recipe,
        });
        Ok(Some(request))
    }

    /// Consume a matching response into its reserved slot. Other events
    /// retain their normal routing; they cannot complete a raw transaction.
    pub(crate) fn receive(&mut self, event: SleEvent) -> Option<SleEvent> {
        let opcode = match &event {
            SleEvent::CommandCredits { credits } => {
                self.credits = *credits;
                return Some(event);
            }
            SleEvent::CommandComplete {
                opcode,
                command_credits,
                ..
            } => {
                self.credits = *command_credits;
                *opcode as u16
            }
            SleEvent::CommandStatus {
                opcode,
                command_credits,
                status,
            } => {
                self.credits = *command_credits;
                if *status == super::sle_dli::SleStatus::Success
                    && self.active.as_ref().is_some_and(|active| active.recipe.is_some())
                {
                    return Some(event);
                }
                *opcode as u16
            }
            SleEvent::NativeCommandReply { opcode, command_credits, status, complete, .. } => {
                self.credits = *command_credits;
                // Native query Status only acknowledges acceptance. Keep the
                // active slot/deadline until matching Complete or failure.
                if !complete && *status == 0 {
                    return Some(event);
                }
                *opcode
            }
            _ => return Some(event),
        };
        if self.fault.is_none()
            && self.reply.is_none()
            && self
                .active
                .as_ref()
                .is_some_and(|active| active.opcode == opcode)
        {
            self.reply = Some(event);
            None
        } else {
            Some(event)
        }
    }

    /// The protocol consumer releases the on-wire slot. Keeping it occupied
    /// until consumption bounds management delivery even if RX is busy.
    pub(crate) fn take_reply(&mut self) -> Option<HostReply> {
        let event = self.reply.take()?;
        let active = self.active.take()?;
        let current_intent = if let Some(tag) = active.recipe {
            self.current_recipe(tag)
        } else if active.opcode == SleOpcode::EnableBroadcast as u16 {
            active.cookie == self.broadcast_cookie
        } else if active.opcode == SleOpcode::EnableScan as u16 {
            active.cookie == self.scan_cookie
        } else {
            true
        };
        if let Some(tag) = active.recipe {
            let (complete, status, data) = match &event {
                SleEvent::CommandComplete { status, data, .. } => (true, *status as u8, data.as_slice()),
                SleEvent::CommandStatus { status, .. } => (false, *status as u8, &[][..]),
                SleEvent::NativeCommandReply { status, complete, data, .. } => (*complete, *status, data.as_slice()),
                _ => (false, 0, &[][..]),
            };
            self.operations.reply(tag.cookie, tag.step, complete, status, data, current_intent);
        }
        let recipe = active.recipe.map(|tag| {
            let (complete, status) = match &event {
                SleEvent::CommandComplete { status, .. } => (true, *status as u8),
                SleEvent::CommandStatus { status, .. } => (false, *status as u8),
                SleEvent::NativeCommandReply { status, complete, .. } => (*complete, *status),
                _ => (false, 0),
            };
            let outcome = if let Some((root, progress)) = &mut self.recipe {
                if (!current_intent && tag.intent.enabled()) || root.cookie != tag.cookie {
                    progress.cancel();
                    RecipeReply::Ignored
                } else {
                    progress.reply(tag.step, complete, status)
                }
            } else { RecipeReply::Ignored };
            if outcome == RecipeReply::Failed {
                self.requests.remove_recipes(tag.intent);
                // Failed older stop barrier also invalidates newer queued work.
                // Preserve the matched operation's raw status as Failed.
                if !current_intent {
                    self.operations.cancel_domain(tag.intent, -(kernel::bindings::ECANCELED as i32));
                }
            }
            (tag.intent, outcome)
        });
        if let Some((_, outcome)) = recipe {
            if self.revoking {
                for i in 0..2 {
                    if self.revoke_cookies[i] != active.cookie { continue; }
                    match outcome {
                        RecipeReply::Finished => {
                            self.revoke_done |= 1 << i;
                            if i == 0 { self.operations.advertising = 1; }
                            else { self.operations.scanning = 1; }
                            if self.revoke_done == 3 { self.operations.initialized = true; }
                        }
                        RecipeReply::Failed => {
                            self.revoke_status = match &event {
                                SleEvent::NativeCommandReply { status, .. } => *status,
                                SleEvent::CommandComplete { status, .. } | SleEvent::CommandStatus { status, .. } => *status as u8,
                                _ => 0,
                            };
                            self.revoke_opcode = active.opcode; self.revoke_reply = true;
                            self.fail(EIO);
                        }
                        _ => {}
                    }
                }
            }
        }
        Some(HostReply {
            seq: active.seq,
            event,
            current_intent,
            enable: active.enable,
            peer_addr: active.peer_addr,
            recipe,
        })
    }

    pub(crate) fn timed_out(&self) -> bool {
        if self.fault.is_some() { return false; }
        // SAFETY: reading jiffies is safe in process/IRQ context.
        let now = unsafe { kernel::bindings::jiffies_64 };
        (self.revoking && self.revoke_done != 3 && now >= self.revoke_deadline)
            || (self.reply.is_none()
            && self
                .active
                .as_ref()
                .is_some_and(|active| now >= active.deadline))
            || self
                .requests
                .first_deadline()
                .is_some_and(|deadline| now >= deadline)
    }

    /// Latch a fault; never invent credits after uncertain transport outcome.
    /// The caller drains remaining requests and resolves that owner's entries.
    pub(crate) fn fail(&mut self, error: Error) -> Option<u32> {
        if self.fault.is_none() && self.revoking && !self.revoke_reply {
            self.revoke_opcode = self.active.as_ref().map_or(0, |active| active.opcode);
        }
        let error = *self.fault.get_or_insert(error);
        self.operations.fault(error.to_errno());
        self.credits = 0;
        self.reply = None;
        if let Some((_, progress)) = &mut self.recipe { progress.cancel(); }
        self.active.take().map(|active| active.seq)
    }

    pub(crate) fn cancel_next(&mut self) -> Option<CmdRequest> {
        self.requests.pop()
    }
}
