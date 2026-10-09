// SPDX-License-Identifier: GPL-2.0

//! Per-registration USB command scheduler. Every command shares the same
//! credit budget and bounded queue. One on-wire command waits for its Status
//! or Complete; asynchronous domain completion is a separate Host operation.
//! Matching management replies have a dedicated slot, not the discovery ring.

use kernel::prelude::*;
use kernel::time::msecs_to_jiffies;

use super::sle_dli::{SleEvent, SleOpcode};
use super::sle_mgmt::{CmdRequest, CmdRequestQueue, CMD_TIMEOUT_MS};

struct InFlight {
    opcode: u16,
    seq: u32,
    cookie: u64,
    enable: Option<bool>,
    peer_addr: Option<[u8; 6]>,
    deadline: u64,
}

pub(crate) struct HostReply {
    pub(crate) seq: u32,
    pub(crate) event: SleEvent,
    pub(crate) current_intent: bool,
    pub(crate) enable: Option<bool>,
    pub(crate) peer_addr: Option<[u8; 6]>,
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
            }),
            GFP_KERNEL,
        )
    }

    pub(crate) fn enqueue(&mut self, opcode: u16, params: &[u8], seq: u32) -> Result {
        if let Some(error) = self.fault {
            return Err(error);
        }
        let cookie = self.next_cookie;
        self.requests.push_cookie(opcode, params, seq, cookie)?;
        self.next_cookie = self.next_cookie.wrapping_add(1).max(1);
        if opcode == SleOpcode::EnableBroadcast as u16 {
            self.broadcast_cookie = cookie;
        }
        if opcode == SleOpcode::EnableScan as u16 {
            self.scan_cookie = cookie;
        }
        Ok(())
    }

    pub(crate) fn can_send(&self) -> bool {
        self.fault.is_none()
            && self.credits > 0
            && self.active.is_none()
            && !self.requests.is_empty()
    }

    pub(crate) fn next(&mut self, valid_raw: impl Fn(u32) -> bool) -> Option<CmdRequest> {
        if !self.can_send() {
            return None;
        }
        let request = loop {
            let request = self.requests.pop()?;
            if request.seq == 0 || valid_raw(request.seq) {
                break request;
            }
            // A cancelled/expired queued transaction never reaches the wire.
        };
        self.credits -= 1;
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
                .wrapping_add(msecs_to_jiffies(CMD_TIMEOUT_MS) as u64),
        });
        Some(request)
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
            }
            | SleEvent::CommandStatus {
                opcode,
                command_credits,
                ..
            } => {
                self.credits = *command_credits;
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
        let current_intent = if active.opcode == SleOpcode::EnableBroadcast as u16 {
            active.cookie == self.broadcast_cookie
        } else if active.opcode == SleOpcode::EnableScan as u16 {
            active.cookie == self.scan_cookie
        } else {
            true
        };
        Some(HostReply {
            seq: active.seq,
            event,
            current_intent,
            enable: active.enable,
            peer_addr: active.peer_addr,
        })
    }

    pub(crate) fn timed_out(&self) -> bool {
        // SAFETY: reading jiffies is safe in process/IRQ context.
        let now = unsafe { kernel::bindings::jiffies_64 };
        (self.reply.is_none()
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
        self.fault = Some(error);
        self.credits = 0;
        self.reply = None;
        self.active.take().map(|active| active.seq)
    }

    pub(crate) fn cancel_next(&mut self) -> Option<CmdRequest> {
        self.requests.pop()
    }
}
