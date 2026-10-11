// SPDX-License-Identifier: GPL-2.0

//! SparkLink management plane — command pending queue with timeout.
//!
//! Provides a fixed-size ring of `CmdPendingEntry` objects that track
//! in-flight commands sent to the DLI controller.  The `EventPump`
//! resolves entries when `CommandComplete` / `CommandStatus` events
//! arrive; stale entries are expired based on a jiffies deadline.
//!
//! This replaces the previous fire-and-forget `send_command` model and
//! mirrors the Bluetooth `hci_sent_cmd` / `req_wait_q` mechanism in a
//! simplified form suitable for the kernel Rust crate.

#![allow(dead_code)]

use core::sync::atomic::{AtomicU32, Ordering};
use kernel::prelude::*;
use kernel::time::msecs_to_jiffies;

// ---------------------------------------------------------------------------
// Pending entry
// ---------------------------------------------------------------------------

/// Marker value for a pending (unresolved) command.
pub(crate) const CMD_STATUS_PENDING: u32 = u32::MAX;

/// Maximum response data bytes stored per entry.
const CMD_DATA_MAX: usize = 64;

/// Default command timeout in milliseconds.
pub(crate) const CMD_TIMEOUT_MS: u32 = 5000;

/// A single in-flight command awaiting a response from the controller.
pub(crate) struct CmdPendingEntry {
    /// DLI opcode (OGF|OCF) that was sent.
    pub(crate) opcode: u16,
    /// Author of an explicitly submitted diagnostic; zero for internal work.
    pub(crate) file_id: u64,
    pub(crate) request_id: u64,
    pub(crate) timeout_ms: u32,
    /// Monotonically increasing sequence number (for dedup).
    pub(crate) seq: u32,
    /// Resolution status.
    ///
    /// - `CMD_STATUS_PENDING` — not yet resolved.
    /// - `0x8000_0000 | (status & 0xFF)` — resolved with DLI status.
    /// - `0x8000_0000 | 0x100` — resolved as timeout (ETIMEDOUT).
    pub(crate) status: AtomicU32,
    /// Response payload (valid only after resolution).
    pub(crate) data: [u8; CMD_DATA_MAX],
    /// Length of valid data.
    pub(crate) data_len: u16,
    pub(crate) error: i32,
    /// Deadline (jiffies) after which this entry is considered timed out.
    pub(crate) deadline: u64,
}

/// Bit set in `status` to indicate the entry is resolved.
pub(crate) const CMD_RESOLVED_BIT: u32 = 0x8000_0000;
/// Pseudo-status value for timeout.
pub(crate) const CMD_TIMEOUT_STATUS: u32 = CMD_RESOLVED_BIT | 0x100;

impl CmdPendingEntry {
    /// Create a new pending entry.
    pub(crate) fn new(opcode: u16, seq: u32, timeout_ms: u32) -> Self {
        let deadline = Self::jiffies_now().wrapping_add(msecs_to_jiffies(timeout_ms) as u64);
        Self {
            opcode,
            file_id: 0,
            request_id: 0,
            timeout_ms,
            seq,
            status: AtomicU32::new(CMD_STATUS_PENDING),
            data: [0u8; CMD_DATA_MAX],
            data_len: 0,
            error: 0,
            deadline,
        }
    }

    /// Check whether this entry is still pending.
    pub(crate) fn is_pending(&self) -> bool {
        self.status.load(Ordering::Acquire) == CMD_STATUS_PENDING
    }

    /// Check whether this entry has been resolved (complete or timeout).
    pub(crate) fn is_resolved(&self) -> bool {
        let status = self.status.load(Ordering::Acquire);
        // The pending sentinel is u32::MAX, so its high bit is also set.
        // It must be excluded before testing the resolved-status bit.
        status != CMD_STATUS_PENDING && status & CMD_RESOLVED_BIT != 0
    }

    /// Resolve this entry with a CommandComplete result.
    ///
    /// Stores an exact bounded response; oversized data fails with EMSGSIZE.
    pub(crate) fn resolve(&mut self, dli_status: u8, response: &[u8]) {
        if response.len() > CMD_DATA_MAX {
            self.error = -(kernel::bindings::EMSGSIZE as i32);
            self.data_len = 0;
            self.data.fill(0);
            self.status.store(CMD_RESOLVED_BIT | 0x200, Ordering::Release);
            return;
        }
        let copy_len = response.len();
        self.data[..copy_len].copy_from_slice(&response[..copy_len]);
        self.data_len = copy_len as u16;
        self.status.store(
            CMD_RESOLVED_BIT | (u32::from(dli_status)),
            Ordering::Release,
        );
    }

    /// Mark this entry as timed out.
    pub(crate) fn timeout(&mut self) {
        self.error = -(kernel::bindings::ETIMEDOUT as i32);
        self.status.store(CMD_TIMEOUT_STATUS, Ordering::Release);
    }

    /// Extract the DLI status from a resolved entry.
    /// Returns `None` if still pending.
    pub(crate) fn result_status(&self) -> Option<u8> {
        let v = self.status.load(Ordering::Acquire);
        if v != CMD_STATUS_PENDING && v & CMD_RESOLVED_BIT != 0 {
            if self.error != 0 {
                None // local failure — no DLI status
            } else {
                Some((v & 0xFF) as u8)
            }
        } else {
            None
        }
    }

    /// Read the current jiffies counter.
    fn jiffies_now() -> u64 {
        // SAFETY: reading jiffies_64 is always safe.
        unsafe { kernel::bindings::jiffies_64 }
    }

    /// Check whether this entry's deadline has passed.
    pub(crate) fn is_expired(&self) -> bool {
        Self::jiffies_now() >= self.deadline
    }
}

// ---------------------------------------------------------------------------
// Pending queue
// ---------------------------------------------------------------------------

/// Maximum number of simultaneously pending commands.
const CMD_QUEUE_DEPTH: usize = 32;

/// Fixed-size ring buffer of pending commands.
///
/// Access is serialized by the per-Runtime protocol mutex. Resolved entries
/// remain observable until a later admission reuses their bounded slot.
pub(crate) struct CmdPendingQueue {
    /// Circular buffer of entries.
    entries: [Option<CmdPendingEntry>; CMD_QUEUE_DEPTH],
    /// Next write position.
    tail: usize,
    /// Next sequence number.
    next_seq: u32,
    /// Count of pending (unresolved) entries.
    pub(crate) pending_count: u16,
    /// Cumulative count of commands submitted.
    pub(crate) total_submitted: u64,
    /// Cumulative count of commands resolved (complete or timeout).
    pub(crate) total_resolved: u64,
    /// Cumulative count of timeouts.
    pub(crate) total_timeouts: u64,
}

impl CmdPendingQueue {
    /// Build entries directly in the owner's allocation, without a large
    /// temporary array whose elimination would depend on optimization.
    pub(crate) fn new_in_place() -> impl pin_init::Init<Self> {
        init!(Self {
            entries <- pin_init::init_array_from_fn(|_| None),
            tail: 0,
            next_seq: 1,
            pending_count: 0,
            total_submitted: 0,
            total_resolved: 0,
            total_timeouts: 0,
        })
    }

    /// Create an empty queue.
    pub(crate) const fn new() -> Self {
        const NONE: Option<CmdPendingEntry> = None;
        Self {
            entries: [NONE; CMD_QUEUE_DEPTH],
            tail: 0,
            next_seq: 1,
            pending_count: 0,
            total_submitted: 0,
            total_resolved: 0,
            total_timeouts: 0,
        }
    }

    /// Submit a new command. Returns the sequence number on success,
    /// or `EBUSY` if the queue is full.
    pub(crate) fn submit(&mut self, opcode: u16) -> Result<u32> {
        self.submit_with_timeout(opcode, CMD_TIMEOUT_MS)
    }

    /// Submit a new command with a custom timeout.
    pub(crate) fn submit_with_timeout(&mut self, opcode: u16, timeout_ms: u32) -> Result<u32> {
        if self.pending_count as usize >= CMD_QUEUE_DEPTH {
            return Err(EBUSY);
        }
        // A resolved hole must not cause tail to overwrite another live
        // transaction. Find an available slot before assigning a sequence.
        let slot = (0..CMD_QUEUE_DEPTH)
            .map(|offset| (self.tail + offset) % CMD_QUEUE_DEPTH)
            .find(|&index| {
                self.entries[index]
                    .as_ref()
                    .is_none_or(|entry| entry.is_resolved())
            })
            .ok_or(EBUSY)?;
        let seq = self.next_seq;
        self.next_seq = self.next_seq.checked_add(1).ok_or(EOVERFLOW)?;

        let entry = CmdPendingEntry::new(opcode, seq, timeout_ms);
        self.entries[slot] = Some(entry);
        self.tail = (slot + 1) % CMD_QUEUE_DEPTH;
        self.pending_count += 1;
        self.total_submitted += 1;
        Ok(seq)
    }

    /// Find the oldest pending entry matching `opcode` and resolve it.
    ///
    /// Returns `true` if a matching entry was found and resolved.
    pub(crate) fn resolve(&mut self, opcode: u16, status: u8, data: &[u8]) -> bool {
        for entry in self.entries.iter_mut().flatten() {
            if entry.opcode == opcode && entry.is_pending() {
                entry.resolve(status, data);
                self.pending_count = self.pending_count.saturating_sub(1);
                self.total_resolved += 1;
                return true;
            }
        }
        false
    }

    /// Resolve only the sequence captured when this owner's command was
    /// issued. Internal/unmatched USB replies cannot consume a raw entry.
    pub(crate) fn resolve_seq(&mut self, seq: u32, status: u8, data: &[u8]) -> bool {
        if seq == 0 {
            return false;
        }
        for entry in self.entries.iter_mut().flatten() {
            if entry.seq == seq && entry.is_pending() {
                entry.resolve(status, data);
                self.pending_count = self.pending_count.saturating_sub(1);
                self.total_resolved += 1;
                return true;
            }
        }
        false
    }

    /// Roll back a submission rejected by the bounded transmit queue. The
    /// caller holds the protocol mutex, so no other consumer can resolve it.
    pub(crate) fn rollback(&mut self, seq: u32) {
        for slot in &mut self.entries {
            if slot
                .as_ref()
                .is_some_and(|entry| entry.seq == seq && entry.is_pending())
            {
                *slot = None;
                self.pending_count = self.pending_count.saturating_sub(1);
                self.total_submitted = self.total_submitted.saturating_sub(1);
                return;
            }
        }
    }

    /// Earliest unresolved author deadline, including requests still queued.
    /// Observational only: scheduling must neither expire nor renew a result.
    pub(crate) fn next_deadline(&self) -> Option<u64> {
        self.entries.iter().flatten().filter(|entry| entry.is_pending())
            .map(|entry| entry.deadline).min()
    }

    /// Expire all entries whose deadline has passed.
    ///
    /// Returns the number of entries that were timed out.
    pub(crate) fn expire_stale(&mut self) -> u32 {
        let mut expired = 0u32;
        for entry in self.entries.iter_mut().flatten() {
            if entry.is_pending() && entry.is_expired() {
                entry.timeout();
                self.pending_count = self.pending_count.saturating_sub(1);
                self.total_resolved += 1;
                self.total_timeouts += 1;
                expired += 1;
            }
        }
        expired
    }

    /// Associate an admitted sequence with the originating open file. Caller
    /// holds the same per-Runtime protocol mutex through submit/enqueue/tag.
    pub(crate) fn assign_owner(&mut self, seq: u32, file_id: u64) {
        if let Some(entry) = self.entries.iter_mut().flatten().find(|e| e.seq == seq) {
            entry.file_id = file_id;
        }
    }

    /// Retained admission identity belongs to one original open file.
    pub(crate) fn find_request(&self, file_id: u64, request_id: u64) -> Option<&CmdPendingEntry> {
        self.entries.iter().flatten().find(|e| e.file_id == file_id && e.request_id == request_id)
    }

    pub(crate) fn assign_request(&mut self, seq: u32, file_id: u64, request_id: u64) {
        if let Some(entry) = self.entries.iter_mut().flatten().find(|e| e.seq == seq) {
            entry.file_id = file_id;
            entry.request_id = request_id;
        }
    }

    /// Local cancellation does not invent a controller Status or free Host's
    /// on-wire reservation. A late reply cannot overwrite the final snapshot.
    pub(crate) fn cancel_seq(&mut self, seq: u32) {
        self.fail_seq(seq, -(kernel::bindings::ECANCELED as i32));
    }

    /// Transport/admission failures are local errno, never fabricated firmware
    /// status. Already-final (including cancelled) entries cannot be rewritten.
    pub(crate) fn fail_seq(&mut self, seq: u32, error: i32) {
        if error >= 0 { return; }
        if let Some(entry) = self.entries.iter_mut().flatten().find(|e| e.seq == seq && e.is_pending()) {
            entry.error = error;
            entry.data.fill(0);
            entry.data_len = 0;
            entry.status.store(CMD_RESOLVED_BIT | 0x200, Ordering::Release);
            self.pending_count = self.pending_count.saturating_sub(1);
            self.total_resolved += 1;
            if error == -(kernel::bindings::ETIMEDOUT as i32) { self.total_timeouts += 1; }
        }
    }

    /// Number of currently pending (unresolved) commands.
    pub(crate) fn pending(&self) -> u16 {
        self.pending_count
    }

    /// Look up a pending entry by sequence number.
    pub(crate) fn find_by_seq(&self, seq: u32) -> Option<&CmdPendingEntry> {
        self.entries
            .iter()
            .filter_map(|s| s.as_ref())
            .find(|e| e.seq == seq)
    }
}

// Command storage/progress is also compiled by the standalone Host selftest.
pub(crate) use super::sle_command_queue::{CmdRequest, CmdRequestQueue};
use super::sle_command_queue::QueueError;

impl From<QueueError> for Error {
    fn from(error: QueueError) -> Self {
        match error { QueueError::Invalid => EINVAL, QueueError::Full => EBUSY }
    }
}

impl CmdRequestQueue {
    pub(crate) fn new_in_place() -> impl pin_init::Init<Self> {
        init!(Self {
            entries <- pin_init::init_array_from_fn(|_| None),
            head: 0, tail: 0, count: 0,
        })
    }

    pub(crate) fn push(&mut self, opcode: u16, params: &[u8]) -> Result {
        self.push_tracked(opcode, params, 0)
    }

    pub(crate) fn push_tracked(&mut self, opcode: u16, params: &[u8], seq: u32) -> Result {
        self.push_cookie(opcode, params, seq, 0)
    }

    pub(crate) fn push_cookie(&mut self, opcode: u16, params: &[u8], seq: u32, cookie: u64) -> Result {
        // SAFETY: reads the kernel clock; no user memory or I/O.
        let deadline = unsafe { kernel::bindings::jiffies_64 }
            .wrapping_add(msecs_to_jiffies(CMD_TIMEOUT_MS) as u64);
        self.push_tagged(opcode, params, seq, cookie, None, deadline).map_err(Error::from)
    }
}
