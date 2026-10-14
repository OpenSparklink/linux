// SPDX-License-Identifier: GPL-2.0-only
// Staged Native Host relay ownership; not linked into the default kernel yet.
// Pure transitions are shared verbatim with regression/formal harnesses.
// No crypto, synthetic Complete, command credit or trusted state lives here.

pub const PAYLOAD_MAX: usize = 255;
pub const QUEUE_DEPTH: usize = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Identity {
    pub controller: u16,
    pub generation: u64,
    pub lifetime: u64,
    pub handle: u16,
    pub grant_epoch: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Invalid,
    Stale,
    Expired,
    Closed,
    Full,
    Overflow,
    NeverSubmitted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Open,
    Closing,
    Closed,
    Uncertain,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ticket {
    pub identity: Identity,
    pub cookie: u64,
}

#[derive(Clone, Copy)]
pub struct Packet {
    pub ticket: Ticket,
    pub index: u16,
    length: u8,
    bytes: [u8; PAYLOAD_MAX],
}
impl Packet {
    /// Driver preparation still owns the dialect. This is the explicit SDK111
    /// 1812 parameter envelope, never a cast of the reference Host C structure.
    pub fn encode(&self, out: &mut [u8; PAYLOAD_MAX + 5]) -> usize {
        out[..2].copy_from_slice(&self.ticket.identity.handle.to_le_bytes());
        out[2..4].copy_from_slice(&self.index.to_le_bytes());
        out[4] = self.length;
        let end = 5 + self.length as usize;
        out[5..end].copy_from_slice(&self.bytes[..self.length as usize]);
        end
    }
}

#[derive(Clone, Copy)]
struct Active {
    packet: Packet,
    submitted: bool,
}

pub struct Session {
    identity: Identity,
    deadline: u64,
    phase: Phase,
    next_cookie: u64,
    queue: [Option<Packet>; QUEUE_DEPTH],
    active: Option<Active>,
    reset_required: bool,
}

impl Session {
    /// Caller must obtain current identity/epoch under Runtime's Host/gate
    /// locks and retain the physical ConnectionSession separately from fds.
    /// This type does not authorize pairing or validate the supplied grant.
    pub fn new(identity: Identity, now: u64, deadline: u64) -> Result<Self, Error> {
        if identity.generation == 0
            || identity.lifetime == 0
            || identity.grant_epoch == 0
            || identity.handle > 0x0fff
        {
            return Err(Error::Invalid);
        }
        if now >= deadline {
            return Err(Error::Expired);
        }
        Ok(Self {
            identity,
            deadline,
            phase: Phase::Open,
            next_cookie: 1,
            queue: [None; QUEUE_DEPTH],
            active: None,
            reset_required: false,
        })
    }
    pub fn phase(&self) -> Phase {
        self.phase
    }
    pub fn queued(&self) -> usize {
        self.queue.iter().flatten().count()
    }
    pub fn outstanding(&self) -> bool {
        self.active.is_some_and(|a| a.submitted)
    }
    pub fn reset_required(&self) -> bool {
        self.reset_required
    }

    fn admission(&mut self, current: Identity, now: u64) -> Result<(), Error> {
        if current != self.identity {
            return Err(Error::Stale);
        }
        self.expire(now);
        if now >= self.deadline {
            return Err(Error::Expired);
        }
        if self.phase != Phase::Open {
            return Err(Error::Closed);
        }
        Ok(())
    }

    pub fn enqueue(
        &mut self,
        current: Identity,
        now: u64,
        index: u16,
        bytes: &[u8],
    ) -> Result<Ticket, Error> {
        self.admission(current, now)?;
        if bytes.len() > PAYLOAD_MAX {
            return Err(Error::Invalid);
        }
        let slot = self
            .queue
            .iter()
            .position(Option::is_none)
            .ok_or(Error::Full)?;
        let cookie = self.next_cookie;
        let next = cookie.checked_add(1).ok_or(Error::Overflow)?;
        let mut packet = Packet {
            ticket: Ticket {
                identity: self.identity,
                cookie,
            },
            index,
            length: bytes.len() as u8,
            bytes: [0; PAYLOAD_MAX],
        };
        packet.bytes[..bytes.len()].copy_from_slice(bytes);
        self.queue[slot] = Some(packet);
        self.next_cookie = next;
        Ok(packet.ticket)
    }

    /// A prepared packet has consumed no protocol credit and done no I/O.
    /// One relay is active; the bounded queue handles T pub/confirm sequencing.
    pub fn prepare(&mut self, current: Identity, now: u64) -> Result<Option<Packet>, Error> {
        self.admission(current, now)?;
        if self.active.is_some() {
            return Ok(None);
        }
        let packet = self.queue[0].take();
        if let Some(packet) = packet {
            self.queue.rotate_left(1);
            self.active = Some(Active {
                packet,
                submitted: false,
            });
        }
        Ok(packet)
    }

    /// Linearization contract: Runtime holds Host/gate and the shared command
    /// reservation across this function. Submit atomically queues one prepared
    /// transfer, does not sleep/reenter Host, and Err means NEVER queued. Only
    /// the actual Host owns command credit; this ledger must not pay it back.
    pub fn commit(
        &mut self,
        ticket: Ticket,
        current: Identity,
        now: u64,
        submit: impl FnOnce() -> Result<(), ()>,
    ) -> Result<(), Error> {
        self.admission(current, now)?;
        let active = self.active.as_mut().ok_or(Error::Stale)?;
        if active.packet.ticket != ticket || active.submitted {
            return Err(Error::Stale);
        }
        if submit().is_err() {
            self.active = None;
            return Err(Error::NeverSubmitted);
        }
        active.submitted = true;
        Ok(())
    }

    /// USB completion is not DLI Complete, peer reception or authentication.
    /// Uncertain transport failure keeps the physical obligation and prevents
    /// a new session until a verified controller barrier; no retry here.
    pub fn transport_failed(&mut self, ticket: Ticket) -> Result<(), Error> {
        if !self
            .active
            .is_some_and(|a| a.packet.ticket == ticket && a.submitted)
        {
            return Err(Error::Stale);
        }
        self.queue.fill(None);
        self.phase = Phase::Uncertain;
        self.reset_required = true;
        Ok(())
    }

    /// The outer Host resolves its REAL on-wire reservation to ticket first.
    /// The wire carries only opcode, not cookie/generation/lifetime. This
    /// method does not prove duplicate/late firmware Complete attribution.
    /// Successful Status is acceptance only; terminal error Status or Complete
    /// pays this session obligation, never a different session's debt.
    pub fn reply(
        &mut self,
        ticket: Ticket,
        now: u64,
        complete: bool,
        status: u8,
    ) -> Option<(u8, bool)> {
        self.expire(now);
        if !self
            .active
            .is_some_and(|a| a.packet.ticket == ticket && a.submitted)
        {
            return None;
        }
        if !complete && status == 0 {
            return None;
        }
        self.active = None;
        let author_live = self.phase == Phase::Open;
        if self.phase == Phase::Closing {
            self.phase = Phase::Closed;
        }
        Some((status, author_live))
    }

    /// Revoking a policy author removes only unexecuted work. Submitted
    /// commands retain their real reply reservation, even after final fd close.
    pub fn withdraw(&mut self) {
        self.queue.fill(None);
        if self.phase == Phase::Uncertain {
            return;
        }
        if self.outstanding() {
            self.phase = Phase::Closing;
        } else {
            self.active = None;
            self.phase = Phase::Closed;
        }
    }
    pub fn expire(&mut self, now: u64) {
        if now < self.deadline || self.phase == Phase::Closed {
            return;
        }
        self.queue.fill(None);
        if self.outstanding() {
            self.phase = Phase::Uncertain;
            self.reset_required = true;
        } else if self.phase != Phase::Uncertain {
            self.active = None;
            self.phase = Phase::Closed;
        }
    }
    /// Call only after Backend stop/kill/join and a verified physical barrier.
    /// Controller reset/reinit belongs to Runtime; no fake callback is emitted.
    pub fn retired_after_barrier(&mut self) {
        self.queue.fill(None);
        self.active = None;
        self.phase = Phase::Closed;
        // Retained diagnostic: an uncertain generation cannot be reused.
    }
}
