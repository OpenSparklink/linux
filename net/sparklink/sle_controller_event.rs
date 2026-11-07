// SPDX-License-Identifier: GPL-2.0-only

//! Bounded complete native event log, owned by one registration. Driver RX
//! copies into preallocated slots under an IRQ-safe lock; each reader owns
//! its cursor. No allocation, shared dequeue or legacy field projection.

use kernel::prelude::*;
use super::sle_dev::DeviceIdentity;
use super::sle_uapi::{SleControllerEvent, CONTROLLER_EVENT_PAYLOAD_MAX};

pub(crate) const CAPACITY: usize = 32;

pub(crate) struct ControllerEventLog {
    records: [SleControllerEvent; CAPACITY],
    count: usize,
    tail: usize,
    seq: u64,
}

#[derive(Copy, Clone)]
pub(crate) struct Subscription {
    pub(crate) identity: DeviceIdentity,
    pub(crate) after_seq: u64,
}

impl ControllerEventLog {
    pub(crate) fn new_boxed() -> Result<KBox<Self>> {
        KBox::init(init!(Self {
            // SAFETY: the fixed record has only integers/bytes; zero is valid.
            records <- pin_init::init_array_from_fn(|_| unsafe { core::mem::zeroed::<SleControllerEvent>() }),
            count: 0,
            tail: 0,
            seq: 0,
        }), GFP_KERNEL)
    }

    pub(crate) fn current_seq(&self) -> u64 { self.seq }

    pub(crate) fn publish(&mut self, identity: DeviceIdentity, profile: u32,
                          event_code: u16, payload: &[u8]) -> Result {
        if payload.len() > CONTROLLER_EVENT_PAYLOAD_MAX {
            return Err(Error::from_errno(-(kernel::bindings::EMSGSIZE as i32)));
        }
        let seq = self.seq.checked_add(1).ok_or(EOVERFLOW)?;
        let record = &mut self.records[self.tail];
        record.seq = seq;
        record.generation = identity.generation;
        // SAFETY: reading CLOCK_BOOTTIME is valid in USB completion context.
        record.timestamp_ns = unsafe { kernel::bindings::ktime_get_boottime() } as u64;
        record.lost = 0;
        record.profile = profile;
        record.dev_index = identity.id;
        record.event_code = event_code;
        record.payload_len = payload.len() as u16;
        record.flags = 0;
        record._reserved = 0;
        record.payload.fill(0);
        record.payload[..payload.len()].copy_from_slice(payload);
        self.seq = seq;
        self.tail = (self.tail + 1) % CAPACITY;
        self.count = (self.count + 1).min(CAPACITY);
        Ok(())
    }

    /// Caller has validated cursor <= current_seq and registration generation.
    pub(crate) fn next_after(&self, after_seq: u64) -> Option<SleControllerEvent> {
        let oldest = (self.tail + CAPACITY - self.count) % CAPACITY;
        for offset in 0..self.count {
            let record = &self.records[(oldest + offset) % CAPACITY];
            if record.seq > after_seq {
                let mut result = *record;
                result.lost = record.seq - after_seq - 1;
                return Some(result);
            }
        }
        None
    }
}
