// SPDX-License-Identifier: GPL-2.0-only
// Native Host relay transitions, owned by the physical ConnectionSession.
// Pure transitions are shared verbatim with regression/formal harnesses.
// No crypto, synthetic Complete, command credit or trusted state lives here.

pub(crate) const PAYLOAD_MAX: usize = 255;
pub(crate) const QUEUE_DEPTH: usize = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Identity {
    pub(crate) controller: u16,
    pub(crate) generation: u64,
    pub(crate) lifetime: u64,
    pub(crate) handle: u16,
    pub(crate) grant_epoch: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Error {
    Invalid,
    Unsupported,
    Stale,
    Expired,
    Closed,
    Full,
    Overflow,
    NeverSubmitted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Phase {
    Open,
    Closing,
    Closed,
    Uncertain,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Ticket {
    pub(crate) identity: Identity,
    pub(crate) cookie: u64,
}

#[derive(Clone, Copy)]
pub(crate) struct Packet {
    pub(crate) ticket: Ticket,
    pub(crate) index: u16,
    length: u8,
    bytes: [u8; PAYLOAD_MAX],
}
impl Packet {
    pub(crate) fn payload(&self) -> &[u8] {
        &self.bytes[..self.length as usize]
    }
    /// Driver preparation still owns the dialect. This is the explicit SDK111
    /// 1812 parameter envelope, never a cast of the reference Host C structure.
    #[cfg(any(test, kani))]
    pub(crate) fn encode(&self, out: &mut [u8; PAYLOAD_MAX + 5]) -> usize {
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

pub(crate) struct Session {
    identity: Identity,
    deadline: u64,
    phase: Phase,
    next_cookie: u64,
    queue: [Option<Packet>; QUEUE_DEPTH],
    active: Option<Active>,
    reset_required: bool,
    capability: Option<CapabilityExchange>,
}

impl Session {
    /// Caller must obtain current identity/epoch under Runtime's Host/gate
    /// locks and retain the physical ConnectionSession separately from fds.
    /// This type does not authorize pairing or validate the supplied grant.
    pub(crate) fn new(identity: Identity, now: u64, deadline: u64) -> Result<Self, Error> {
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
            capability: None,
        })
    }
    pub(crate) fn phase(&self) -> Phase {
        self.phase
    }
    pub(crate) fn queued(&self) -> usize {
        self.queue.iter().flatten().count()
    }
    pub(crate) fn outstanding(&self) -> bool {
        self.active.is_some_and(|a| a.submitted)
    }
    pub(crate) fn reset_required(&self) -> bool {
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

    pub(crate) fn enqueue(
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
    pub(crate) fn prepare(&mut self, current: Identity, now: u64) -> Result<Option<Packet>, Error> {
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
    pub(crate) fn commit(
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
        if let Some(c) = &mut self.capability {
            c.observation.flags |= 1;
        }
        Ok(())
    }

    /// USB completion is not DLI Complete, peer reception or authentication.
    /// Uncertain transport failure keeps the physical obligation and prevents
    /// a new session until a verified controller barrier; no retry here.
    pub(crate) fn transport_failed(&mut self, ticket: Ticket) -> Result<(), Error> {
        if !self
            .active
            .is_some_and(|a| a.packet.ticket == ticket && a.submitted)
        {
            return Err(Error::Stale);
        }
        self.queue.fill(None);
        if let Some(c) = &mut self.capability {
            if c.observation.state < 4 {
                c.observation.state = 5;
            }
        }
        self.phase = Phase::Uncertain;
        self.reset_required = true;
        Ok(())
    }

    /// The outer Host resolves its REAL on-wire reservation to ticket first.
    /// The wire carries only opcode, not cookie/generation/lifetime. This
    /// method does not prove duplicate/late firmware Complete attribution.
    /// Successful Status is acceptance only; terminal error Status or Complete
    /// pays this session obligation, never a different session's debt.
    pub(crate) fn reply(
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
        if let Some(c) = &mut self.capability {
            if author_live && c.observation.state < 4 {
                c.observation.status = status;
                if complete && status == 0 {
                    c.observation.flags |= 2;
                    if c.observation.flags & 4 != 0 {
                        c.observation.state = 4;
                        self.phase = Phase::Closed;
                    }
                } else {
                    c.observation.state = 5;
                    self.phase = Phase::Closed;
                }
            }
        }
        if self.phase == Phase::Closing {
            self.phase = Phase::Closed;
        }
        Some((status, author_live))
    }

    /// Revoking a policy author removes only unexecuted work. Submitted
    /// commands retain their real reply reservation, even after final fd close.
    pub(crate) fn withdraw(&mut self) {
        if let Some(c) = &mut self.capability {
            if c.observation.state < 4 {
                c.observation.state = 6;
            }
        }
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
    pub(crate) fn expire(&mut self, now: u64) {
        if now < self.deadline || self.phase == Phase::Closed {
            return;
        }
        if let Some(c) = &mut self.capability {
            if c.observation.state < 4 {
                c.observation.state = 7;
            }
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
    #[cfg(any(test, kani))]
    pub(crate) fn retired_after_barrier(&mut self) {
        self.queue.fill(None);
        self.active = None;
        self.phase = Phase::Closed;
        // Retained diagnostic: an uncertain generation cannot be reused.
    }
}

/// Initial request direction/length, independent of crypto or policy approval.
pub(crate) fn initial_pairing_request(role: u8, index: u16, length: usize) -> bool {
    matches!((role, index, length), (0, 0x0133, 1) | (1, 0x0134, 10))
}

/// Explicit limited exchange. These are local protocol observations, never
/// Paired, authenticated, trusted, encrypted, or a peer application ACK.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CapabilityObservation {
    pub(crate) state: u32, // 1 armed, 2 pending, 4 observed, 5 failed, 6 cancelled, 7 expired
    pub(crate) flags: u32, // actual TX submit=1, real successful Complete=2, peer RX=4
    pub(crate) status: u8,
    pub(crate) local: [u8; 10],
    pub(crate) peer: [u8; 10],
}

#[derive(Clone, Copy)]
struct CapabilityExchange {
    role: u8,
    observation: CapabilityObservation,
}

// SDK111 limited JustWorks capability offer. No IRK/address distribution,
// PSK/OOB/MITM or trusted result. Higher authentication/install stages remain
// unsupported; entering this exchange requires explicit manager approval.
const CAPABILITY_OFFER: [u8; 10] = [3, 0, 0, 16, 0, 2, 2, 2, 2, 0];

impl Session {
    pub(crate) fn deadline(&self) -> u64 {
        self.deadline
    }
    pub(crate) fn capability_exchange(&self) -> bool {
        self.capability.is_some()
    }

    /// One exchange per physical lifetime; the outer owner enforces no restart.
    /// Only G-initiated 134/135 is supported in this limited first mechanism.
    pub(crate) fn approve_capabilities(
        &mut self,
        current: Identity,
        now: u64,
        role: u8,
        initiate: bool,
    ) -> Result<Option<Packet>, Error> {
        self.admission(current, now)?;
        if self.capability.is_some()
            || self.active.is_some()
            || self.queued() != 0
            || self.next_cookie != 1
        {
            return Err(Error::Invalid);
        }
        if !matches!((role, initiate), (0, true) | (1, false)) {
            return Err(Error::Unsupported);
        }
        self.capability = Some(CapabilityExchange {
            role,
            observation: CapabilityObservation {
                state: if initiate { 2 } else { 1 },
                flags: 0,
                status: 0,
                local: CAPABILITY_OFFER,
                peer: [0; 10],
            },
        });
        if initiate {
            self.enqueue(current, now, 0x134, &CAPABILITY_OFFER)?;
            self.prepare(current, now)
        } else {
            Ok(None)
        }
    }

    /// Only real, identity-frozen ingress calls this; no user-supplied RX bytes.
    /// Late/wrong role/duplicate traffic cannot replace the observed peer offer.
    pub(crate) fn receive_capabilities(
        &mut self,
        current: Identity,
        now: u64,
        index: u16,
        bytes: &[u8],
    ) -> Result<Option<Packet>, Error> {
        self.admission(current, now)?;
        let exchange = self.capability.as_mut().ok_or(Error::Unsupported)?;
        if exchange.observation.state >= 4
            || exchange.observation.flags & 4 != 0
            || (exchange.role == 0 && exchange.observation.flags & 1 == 0)
        {
            return Err(Error::Stale);
        }
        if !matches!((exchange.role, index), (0, 0x135) | (1, 0x134)) || bytes != CAPABILITY_OFFER {
            exchange.observation.state = 5;
            self.withdraw();
            return Err(Error::Unsupported);
        }
        exchange.observation.peer.copy_from_slice(bytes);
        exchange.observation.flags |= 4;
        let respond = exchange.role == 1;
        if exchange.observation.flags & 2 != 0 {
            exchange.observation.state = 4;
            self.phase = Phase::Closed;
        } else {
            exchange.observation.state = 2;
        }
        if respond {
            self.enqueue(current, now, 0x135, &CAPABILITY_OFFER)?;
            self.prepare(current, now)
        } else {
            Ok(None)
        }
    }

    pub(crate) fn capability_observation(&mut self, now: u64) -> Option<CapabilityObservation> {
        self.expire(now);
        self.capability.map(|c| c.observation)
    }
}
