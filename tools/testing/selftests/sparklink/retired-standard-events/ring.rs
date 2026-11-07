pub(crate) struct ControllerEventRing {
    events: [(Option<u16>, Option<SleEvent>); CTRL_EVENT_RING_SIZE],
    head: usize,
    tail: usize,
    /// Cumulative count of events dropped due to ring overflow.
    pub(crate) dropped: u32,
}
impl ControllerEventRing {
    pub(crate) fn new() -> Self {
        Self {
            events: [const { (None, None) }; CTRL_EVENT_RING_SIZE],
            head: 0,
            tail: 0,
            dropped: 0,
        }
    }

    /// Initialize the ingress array in its final heap allocation.


    /// Push an event with an optional source device id.
    /// Returns `true` if the event was stored, `false` if dropped (ring full).
    pub(crate) fn push_tagged(&mut self, dev_id: Option<u16>, ev: SleEvent) -> bool {
        let next = (self.tail + 1) % CTRL_EVENT_RING_SIZE;
        if next == self.head {
            self.dropped = self.dropped.wrapping_add(1);
            return false;
        }
        self.events[self.tail] = (dev_id, Some(ev));
        self.tail = next;
        true
    }

    /// Push an event without device routing (processed on active device).
    pub(crate) fn push(&mut self, ev: SleEvent) {
        self.push_tagged(None, ev);
    }

    /// Pop the next event along with its source device id.
    pub(crate) fn pop_tagged(&mut self) -> Option<(Option<u16>, SleEvent)> {
        if self.head == self.tail {
            return None;
        }
        let (dev_id, ev) = core::mem::take(&mut self.events[self.head]);
        self.head = (self.head + 1) % CTRL_EVENT_RING_SIZE;
        ev.map(|e| (dev_id, e))
    }

    pub(crate) fn pop(&mut self) -> Option<SleEvent> {
        self.pop_tagged().map(|(_, ev)| ev)
    }

    pub(crate) fn pending(&self) -> usize {
        (self.tail + CTRL_EVENT_RING_SIZE - self.head) % CTRL_EVENT_RING_SIZE
    }
}
