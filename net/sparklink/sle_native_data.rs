// SPDX-License-Identifier: GPL-2.0-only

//! Bounded native ACB ingress and controller packet debt. DTAP is above this.

use kernel::prelude::*;
use super::sle_data_credit::{CreditError, DataCredits};

const RX_PACKETS: usize = 16;
pub(crate) const MAXIMUM: usize = 2047;

pub(crate) struct Packet {
    pub(crate) lifetime: u64,
    pub(crate) security_revision: u64,
    pub(crate) handle: u16,
    pub(crate) bytes: KVec<u8>,
}

pub(crate) struct NativeData {
    pub(crate) credits: DataCredits,
    packets: [Option<Packet>; RX_PACKETS],
    partial: [Option<(Packet, u64)>; RX_PACKETS],
    pub(crate) dropped: u64,
    pub(crate) completion_errors: u64,
}

impl NativeData {
    pub(crate) fn new(maximum: u16, capacity: u8) -> Self {
        Self { credits: DataCredits::new(maximum, capacity),
            packets: [const { None }; RX_PACKETS], partial: [const { None }; RX_PACKETS],
            dropped: 0, completion_errors: 0 }
    }

    pub(crate) fn expire(&mut self, now: u64) {
        for partial in &mut self.partial {
            if partial.as_ref().is_some_and(|(_, deadline)| now >= *deadline) {
                *partial = None;
                self.dropped = self.dropped.saturating_add(1);
            }
        }
    }

    /// First fragments reserve the entire bounded buffer before IRQ locks.
    /// Continuations can only copy into already allocated spare capacity.
    /// True means a complete PDU was queued, not merely that a fragment was
    /// accepted. Only that transition gives a reader new consumable input.
    pub(crate) fn receive(&mut self, packet: Packet, boundary: u8, now: u64) -> Result<bool> {
        self.expire(now);
        let existing = self.partial.iter().position(|p| p.as_ref().is_some_and(|(p, _)|
            p.handle == packet.handle && p.lifetime == packet.lifetime));
        if boundary <= 1 {
            if let Some(index) = existing {
                self.partial[index] = None;
                self.dropped = self.dropped.saturating_add(1);
            }
            if boundary == 0 { return self.push(packet); }
            if packet.bytes.capacity() < MAXIMUM { return Err(EINVAL); }
            let Some(index) = self.partial.iter().position(Option::is_none) else {
                self.dropped = self.dropped.saturating_add(1);
                return Err(Error::from_errno(-(kernel::bindings::ENOBUFS as i32)));
            };
            self.partial[index] = Some((packet, now.saturating_add(5_000_000_000)));
            return Ok(false);
        }
        let Some(index) = existing else {
            self.dropped = self.dropped.saturating_add(1); return Err(EINVAL);
        };
        if self.partial[index].as_ref().unwrap().0.security_revision != packet.security_revision {
            self.partial[index] = None;
            self.dropped = self.dropped.saturating_add(1);
            return Err(EINVAL);
        }
        let current = self.partial[index].as_mut().unwrap();
        if current.0.bytes.len() + packet.bytes.len() > MAXIMUM {
            self.partial[index] = None;
            self.dropped = self.dropped.saturating_add(1);
            return Err(Error::from_errno(-(kernel::bindings::EMSGSIZE as i32)));
        }
        // Capacity was reserved at first-fragment ingress, so this cannot allocate.
        if current.0.bytes.extend_from_slice(&packet.bytes, GFP_ATOMIC).is_err() { return Err(ENOMEM); }
        if boundary == 3 {
            let (complete, _) = self.partial[index].take().unwrap();
            return self.push(complete);
        }
        Ok(false)
    }

    /// Already copied outside IRQ-safe locks; packet/byte limits are fixed.
    fn push(&mut self, packet: Packet) -> Result<bool> {
        if let Some(slot) = self.packets.iter_mut().find(|slot| slot.is_none()) {
            *slot = Some(packet); Ok(true)
        } else {
            self.dropped = self.dropped.saturating_add(1);
            Err(Error::from_errno(-(kernel::bindings::ENOBUFS as i32)))
        }
    }

    pub(crate) fn take(&mut self, lifetime: u64, handle: u16, capacity: usize) -> Result<Option<Packet>> {
        let Some(index) = self.packets.iter().position(|p| p.as_ref().is_some_and(|p|
            p.lifetime == lifetime && p.handle == handle)) else { return Ok(None); };
        if self.packets[index].as_ref().unwrap().bytes.len() > capacity {
            return Err(Error::from_errno(-(kernel::bindings::EMSGSIZE as i32)));
        }
        let result = self.packets[index].take();
        // Compact to keep FIFO order across holes created by per-link readers.
        for i in index..RX_PACKETS - 1 { self.packets[i] = self.packets[i + 1].take(); }
        Ok(result)
    }

    pub(crate) fn completed(&mut self, handle: u16, count: u8) {
        if self.credits.complete(handle, count).is_err() {
            self.completion_errors = self.completion_errors.saturating_add(1);
        }
    }

    /// Return retired buffers so their allocations are freed after IRQ locks.
    /// Keep queue order; the latest canonical table is the only lifetime source.
    pub(crate) fn reconcile(&mut self, links: &[Option<super::sle_link_observation::Link>; 16]) -> [Option<Packet>; RX_PACKETS] {
        for partial in &mut self.partial {
            if partial.as_ref().is_some_and(|(packet, _)| !links.iter().flatten().any(|link|
                link.handle == packet.handle && link.lifetime == packet.lifetime)) {
                // kfree is IRQ-safe; no allocation or I/O on link retirement.
                *partial = None;
            }
        }
        let mut retired = [const { None }; RX_PACKETS];
        let mut kept = 0;
        let mut removed = 0;
        for i in 0..RX_PACKETS {
            if let Some(packet) = self.packets[i].take() {
                if links.iter().flatten().any(|link| link.handle == packet.handle && link.lifetime == packet.lifetime) {
                    self.packets[kept] = Some(packet); kept += 1;
                } else {
                    retired[removed] = Some(packet); removed += 1;
                }
            }
        }
        retired
    }
}

pub(crate) fn error(error: CreditError) -> Error {
    match error {
        CreditError::Unsupported => Error::from_errno(-(kernel::bindings::EOPNOTSUPP as i32)),
        CreditError::Invalid => EINVAL,
        CreditError::TooLarge => Error::from_errno(-(kernel::bindings::EMSGSIZE as i32)),
        CreditError::WouldBlock => EAGAIN,
        CreditError::OldLifetime => Error::from_errno(-(kernel::bindings::ESTALE as i32)),
        CreditError::Fault => EIO,
    }
}
