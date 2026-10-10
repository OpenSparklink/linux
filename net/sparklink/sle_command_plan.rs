// SPDX-License-Identifier: GPL-2.0-only

//! Allocation-free progress for one contiguous, typed command recipe.
//! Shared by the kernel Host and standalone selftests. Credits, transport,
//! opcode matching and timeouts belong to the enclosing registration's Host.

pub(crate) const RECIPE_STEPS_MAX: usize = 4;
pub(crate) const RECIPE_PARAMS_MAX: usize = 255;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DiscoveryIntent {
    Advertising(bool),
    /// Explicit parameter configuration followed by OFF; no enable step.
    AdvertisingStandby,
    Scanning(bool),
}

impl DiscoveryIntent {
    pub(crate) fn enabled(self) -> bool {
        match self {
            Self::AdvertisingStandby => false,
            Self::Advertising(enable) | Self::Scanning(enable) => enable,
        }
    }

    pub(crate) fn same_domain(self, other: Self) -> bool {
        matches!(
            (self, other),
            (Self::Advertising(_) | Self::AdvertisingStandby, Self::Advertising(_) | Self::AdvertisingStandby) | (Self::Scanning(_), Self::Scanning(_))
        )
    }
}

#[derive(Clone, Copy)]
pub(crate) struct RecipePart<'a> {
    pub(crate) opcode: u16,
    pub(crate) params: &'a [u8],
}

/// Only typed, sequence-zero requests carry this tag. One immutable cookie
/// identifies every step; never derive a native enable's intent from its
/// dialect-specific parameter length or an unrelated command's opcode.
#[derive(Clone, Copy)]
pub(crate) struct RecipeTag {
    pub(crate) cookie: u64,
    pub(crate) step: u8,
    pub(crate) count: u8,
    pub(crate) intent: DiscoveryIntent,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Ready(u8),
    Waiting(u8),
    Finished,
    Aborted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RecipeReply {
    Ignored,
    Accepted,
    Next,
    Finished,
    Failed,
}

pub(crate) struct RecipeProgress {
    count: u8,
    phase: Phase,
}

impl RecipeProgress {
    pub(crate) fn new(count: u8) -> Option<Self> {
        if count == 0 || count as usize > RECIPE_STEPS_MAX {
            return None;
        }
        Some(Self {
            count,
            phase: Phase::Ready(0),
        })
    }

    pub(crate) fn ready(&self, step: u8) -> bool {
        self.phase == Phase::Ready(step)
    }

    pub(crate) fn sent(&mut self, step: u8) -> bool {
        if !self.ready(step) {
            return false;
        }
        self.phase = Phase::Waiting(step);
        true
    }

    /// Call only for the Host's opcode-matched on-wire step. Successful
    /// Status is acceptance, never permission to send the next step.
    /// Any nonzero raw controller status is terminal for this recipe.
    pub(crate) fn reply(&mut self, step: u8, complete: bool, status: u8) -> RecipeReply {
        if self.phase != Phase::Waiting(step) {
            return RecipeReply::Ignored;
        }
        if status != 0 {
            self.phase = Phase::Aborted;
            return RecipeReply::Failed;
        }
        if !complete {
            return RecipeReply::Accepted;
        }
        if step + 1 == self.count {
            self.phase = Phase::Finished;
            RecipeReply::Finished
        } else {
            self.phase = Phase::Ready(step + 1);
            RecipeReply::Next
        }
    }

    pub(crate) fn cancel(&mut self) {
        self.phase = Phase::Aborted;
    }
}

/// Preflight the entire batch before changing queue/cookie/intent state.
/// Empty or oversized steps cannot leave a partially queued radio operation.
pub(crate) fn valid_parts(parts: &[RecipePart<'_>], available: usize) -> bool {
    !parts.is_empty()
        && parts.len() <= RECIPE_STEPS_MAX
        && parts.len() <= available
        && parts
            .iter()
            .all(|part| part.opcode != 0 && part.params.len() <= RECIPE_PARAMS_MAX)
}
