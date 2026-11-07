// SPDX-License-Identifier: GPL-2.0-only
pub(crate) const DLI_RING_SIZE: usize = 32;
    pub(crate) fn push_dli_event(&mut self, ev: SleDliEvent) {
        self.dli_ring[self.dli_tail] = ev;
        self.dli_tail = (self.dli_tail + 1) % DLI_RING_SIZE;
        if self.dli_tail == self.dli_head {
            self.dli_head = (self.dli_head + 1) % DLI_RING_SIZE;
        }
    }
    pub(crate) fn peek_dli_event(&self) -> Option<SleDliEvent> {
        if self.dli_head == self.dli_tail {
            return None;
        }
        Some(self.dli_ring[self.dli_head])
    }
    pub(crate) fn pop_dli_event(&mut self) -> Option<SleDliEvent> {
        let ev = self.peek_dli_event()?;
        self.dli_head = (self.dli_head + 1) % DLI_RING_SIZE;
        Some(ev)
    }