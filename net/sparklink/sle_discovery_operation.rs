// SPDX-License-Identifier: GPL-2.0-only
//! Bounded per-owner operation results. No allocation, clock, I/O or locks.

use super::sle_command_plan::DiscoveryIntent;
pub(crate) const CAPACITY: usize = 64;

#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum State {
    Queued = 1,
    Pending,
    Succeeded,
    Failed,
    Cancelled,
    Faulted,
}
impl State {
    pub(crate) fn terminal(self) -> bool {
        matches!(
            self,
            Self::Succeeded | Self::Failed | Self::Cancelled | Self::Faulted
        )
    }
}

#[derive(Clone, Copy)]
pub(crate) struct Operation {
    pub(crate) request_id: u64,
    pub(crate) cookie: u64,
    pub(crate) intent: DiscoveryIntent,
    pub(crate) state: State,
    pub(crate) error: i32,
    pub(crate) status: u8,
    pub(crate) opcode: u16,
    pub(crate) step: u8,
    pub(crate) count: u8,
    pub(crate) power_step: u8,
    pub(crate) selected_power: Option<i8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AdmissionError {
    Invalid,
    Duplicate,
    Full,
}

pub(crate) struct Operations {
    pub(crate) entries: [Option<Operation>; CAPACITY],
    // 0 unknown, 1 confirmed off, 2 confirmed on. Never mark off on submit.
    pub(crate) initialized: bool,
    pub(crate) advertising: u32,
    pub(crate) scanning: u32,
}

impl Operations {
    #[cfg(test)]
    pub(crate) const fn new() -> Self {
        Self {
            entries: [None; CAPACITY],
            initialized: false,
            advertising: 0,
            scanning: 0,
        }
    }
    /// Nonterminal entries never evict. Choose an empty slot or the oldest
    /// terminal operation; caller must commit only after queue admission.
    pub(crate) fn slot(&self, request_id: u64) -> Result<usize, AdmissionError> {
        if request_id == 0 {
            return Err(AdmissionError::Invalid);
        }
        if self.find(request_id).is_some() {
            return Err(AdmissionError::Duplicate);
        }
        if let Some(i) = self.entries.iter().position(Option::is_none) {
            return Ok(i);
        }
        self.entries
            .iter()
            .enumerate()
            .filter_map(|(i, op)| op.filter(|op| op.state.terminal()).map(|op| (i, op.cookie)))
            .min_by_key(|(_, cookie)| *cookie)
            .map(|(i, _)| i)
            .ok_or(AdmissionError::Full)
    }
    pub(crate) fn find(&self, request_id: u64) -> Option<Operation> {
        self.entries
            .iter()
            .flatten()
            .find(|op| op.request_id == request_id)
            .copied()
    }
    pub(crate) fn pending(&self, intent: DiscoveryIntent) -> bool {
        self.entries
            .iter()
            .flatten()
            .any(|op| !op.state.terminal() && op.intent.same_domain(intent))
    }
    pub(crate) fn can_start(&self, intent: DiscoveryIntent) -> bool {
        let (own, other, other_intent) = match intent {
            DiscoveryIntent::Advertising(_) => (
                self.advertising,
                self.scanning,
                DiscoveryIntent::Scanning(true),
            ),
            DiscoveryIntent::Scanning(_) => (
                self.scanning,
                self.advertising,
                DiscoveryIntent::Advertising(true),
            ),
        };
        own == 1 && other == 1 && !self.pending(intent) && !self.pending(other_intent)
    }
    pub(crate) fn cancel_domain(&mut self, intent: DiscoveryIntent, error: i32) {
        for op in self.entries.iter_mut().flatten() {
            if !op.state.terminal() && op.intent.same_domain(intent) {
                op.state = State::Cancelled;
                op.error = error;
            }
        }
    }
    pub(crate) fn sent(&mut self, cookie: u64, step: u8, opcode: u16) {
        if let Some(op) = self
            .entries
            .iter_mut()
            .flatten()
            .find(|op| op.cookie == cookie && !op.state.terminal())
        {
            op.state = State::Pending;
            op.step = step;
            op.opcode = opcode;
        }
    }
    /// Called only for the opcode-matched reserved Complete/failed Status.
    /// Superseded results remain terminal; old physical stop completions may
    /// still establish off, whereas old start completions cannot establish on.
    pub(crate) fn reply(
        &mut self,
        cookie: u64,
        step: u8,
        complete: bool,
        status: u8,
        data: &[u8],
        current: bool,
    ) {
        let Some(op) = self
            .entries
            .iter_mut()
            .flatten()
            .find(|op| op.cookie == cookie)
        else {
            return;
        };
        if op.state.terminal() {
            if op.state == State::Cancelled
                && op.intent.enabled()
                && complete
                && status == 0
                && step + 1 == op.count
            {
                // A cancelled on-wire enable may have reached the radio. Do
                // not confirm the replacement intent or pretend it stayed off.
                match op.intent {
                    DiscoveryIntent::Advertising(_) => self.advertising = 0,
                    DiscoveryIntent::Scanning(_) => self.scanning = 0,
                }
            }
            if op.state == State::Cancelled && !op.intent.enabled() && complete && status == 0 {
                match op.intent {
                    DiscoveryIntent::Advertising(_) => self.advertising = 1,
                    DiscoveryIntent::Scanning(_) => self.scanning = 1,
                }
            }
            return;
        }
        if !current {
            return;
        }
        op.step = step;
        op.status = status;
        if status != 0 {
            op.state = State::Failed;
            return;
        }
        if !complete {
            return;
        }
        if step == op.power_step && data.len() == 1 {
            op.selected_power = Some(data[0] as i8);
        }
        if step + 1 == op.count {
            op.state = State::Succeeded;
            let radio = if op.intent.enabled() { 2 } else { 1 };
            match op.intent {
                DiscoveryIntent::Advertising(_) => self.advertising = radio,
                DiscoveryIntent::Scanning(_) => self.scanning = radio,
            }
            if self.advertising == 1 && self.scanning == 1 {
                self.initialized = true;
            }
        } else {
            op.state = State::Queued;
        }
    }
    pub(crate) fn fault(&mut self, error: i32) {
        self.initialized = false;
        self.advertising = 0;
        self.scanning = 0;
        for op in self.entries.iter_mut().flatten() {
            if !op.state.terminal() {
                op.state = State::Faulted;
                op.error = error;
            }
        }
    }
}
