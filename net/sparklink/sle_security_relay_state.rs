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
    pairing: Option<Pairing>,
    installation: Option<Installation>,
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
            pairing: None,
            installation: None,
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
        if matches!(active.packet.index, 0x1c03 | 0x1c05) {
            if let Some(i) = &mut self.installation {
                i.pending = true;
            }
        }
        if let Some(pair) = &mut self.pairing {
            pair.last_submitted = active.packet.index;
        }
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
        let installation = matches!(self.active.as_ref()?.packet.index, 0x1c03 | 0x1c05);
        if !complete && status == 0 && !installation {
            return None;
        }
        self.active = None;
        if installation && status == 0 && self.phase == Phase::Open {
            if let Some(i) = &mut self.installation {
                i.accepted = true;
            }
        }
        let author_live = self.phase == Phase::Open;
        if let Some(c) = &mut self.capability {
            if author_live && c.observation.state < 4 {
                c.observation.status = status;
                if status == 0 && (complete || installation) {
                    if complete {
                        c.observation.flags |= 2;
                    }
                    if c.observation.flags & 4 != 0 && self.pairing.is_none() {
                        c.observation.state = 4;
                        self.phase = Phase::Closed;
                    }
                } else {
                    c.observation.state = 5;
                    self.queue.fill(None);
                    self.phase = Phase::Closed;
                }
            }
        }
        if self.phase == Phase::Closing && !self.installation_pending() {
            self.phase = Phase::Closed;
        }
        self.finish_pairing_if_drained();
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
        if self.outstanding() || self.installation_pending() {
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
        if self.outstanding() || self.installation_pending() {
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
        if let Some(i) = &mut self.installation {
            i.pending = false;
        }
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
    pub(crate) state: u32, // 1 armed, 2 pending, 4 caps, 5 failed, 6 cancelled, 7 expired, 8 candidate proof
    pub(crate) flags: u32, // actual TX submit=1, real successful Complete=2, peer RX=4
    pub(crate) status: u8,
    pub(crate) local: [u8; 10],
    pub(crate) peer: [u8; 10],
    pub(crate) error: i32,
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
                error: 0,
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

// The same relay Session owns the protocol order. Sleeping crypto returns a
// typed job receipt; it neither owns wire progress nor creates trusted state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CryptoKind {
    GPublicAndConfirm,
    TPublic,
    GNonce,
    TDerive,
    GDerive,
    GProofAndRespond,
    TProof,
}
#[derive(Clone, Copy)]
pub(crate) struct CryptoJob {
    pub(crate) ticket: Ticket,
    pub(crate) kind: CryptoKind,
    pub(crate) data: [u8; 64],
    pub(crate) confirm: [u8; 16],
}
#[derive(Clone, Copy)]
struct Pairing {
    expected: u16,
    last_submitted: u16,
    public: [u8; 64],
    confirm: [u8; 16],
    job: Option<(Ticket, CryptoKind)>,
    proof_verified: bool,
}

#[derive(Clone, Copy)]
struct Installation {
    role: u8,
    requested: bool,
    queued: bool,
    accepted: bool,
    encrypted: bool,
    pending: bool,
}

impl Session {
    pub(crate) fn key_agreement(&self) -> bool {
        self.pairing.is_some()
    }
    pub(crate) fn crypto_failed(&mut self, error: i32) {
        self.fail_pairing(error);
    }

    pub(crate) fn approve_key_agreement(
        &mut self,
        current: Identity,
        now: u64,
        role: u8,
        initiate: bool,
        public: [u8; 64],
    ) -> Result<Option<Packet>, Error> {
        let packet = self.approve_capabilities(current, now, role, initiate)?;
        self.pairing = Some(Pairing {
            expected: if initiate { 0x135 } else { 0x134 },
            last_submitted: 0,
            public,
            confirm: [0; 16],
            job: None,
            proof_verified: false,
        });
        Ok(packet)
    }

    fn fail_pairing(&mut self, error: i32) {
        if let Some(c) = &mut self.capability {
            if c.observation.state < 4 {
                c.observation.state = 5;
                c.observation.error = error;
            }
        }
        self.withdraw();
    }
    fn finish_pairing_if_drained(&mut self) {
        if self.phase != Phase::Open
            || self.active.is_some()
            || self.queued() != 0
            || !self
                .pairing
                .is_some_and(|p| p.proof_verified && p.job.is_none())
        {
            return;
        }
        if let Some(install) = self.installation {
            if install.accepted && install.encrypted {
                if let Some(c) = &mut self.capability {
                    c.observation.state = 9;
                }
                self.phase = Phase::Closed;
            }
            // Queueing uses the ORIGINAL deadline, never a fresh install timer.
            // No key is stored in this pure ledger, packet or Host queue.
        } else {
            if let Some(c) = &mut self.capability {
                c.observation.state = 8;
            }
            self.phase = Phase::Closed;
        }
    }

    /// Command credit/obligation is separate: successful Status pays the
    /// command reservation, never this asynchronous physical procedure.
    pub(crate) fn installation_pending(&self) -> bool {
        self.installation.is_some_and(|i| i.pending)
    }

    pub(crate) fn enable_installation(
        &mut self,
        current: Identity,
        now: u64,
        role: u8,
    ) -> Result<(), Error> {
        self.admission(current, now)?;
        if self.pairing.is_none() || self.installation.is_some() || role > 1 {
            return Err(Error::Invalid);
        }
        self.installation = Some(Installation {
            role,
            requested: false,
            queued: false,
            accepted: false,
            encrypted: false,
            pending: false,
        });
        Ok(())
    }

    /// Called by the same worker after proof/physical relay debt drains. T
    /// additionally needs its actual controller request, never a guessed event.
    pub(crate) fn progress_installation(
        &mut self,
        current: Identity,
        now: u64,
    ) -> Result<(), Error> {
        self.admission(current, now)?;
        let Some(i) = self.installation else {
            return Ok(());
        };
        if i.queued
            || self.active.is_some()
            || self.queued() != 0
            || !self
                .pairing
                .is_some_and(|p| p.proof_verified && p.job.is_none())
            || (i.role == 1 && !i.requested)
        {
            return Ok(());
        }
        self.enqueue(current, now, if i.role == 0 { 0x1c03 } else { 0x1c05 }, &[])?;
        if let Some(i) = &mut self.installation {
            i.queued = true;
        }
        if let Some(c) = &mut self.capability {
            c.observation.state = 3;
        }
        Ok(())
    }

    pub(crate) fn installation_matches(
        &mut self,
        current: Identity,
        now: u64,
        ticket: Ticket,
        index: u16,
    ) -> Result<(), Error> {
        self.admission(current, now)?;
        let i = self.installation.ok_or(Error::Unsupported)?;
        if !i.queued
            || ticket.identity != current
            || index != if i.role == 0 { 0x1c03 } else { 0x1c05 }
            || !self.active.is_some_and(|a| {
                a.packet.ticket == ticket && a.packet.index == index && !a.submitted
            })
            || !self.pairing.is_some_and(|p| p.proof_verified)
        {
            return Err(Error::Stale);
        }
        Ok(())
    }

    /// Ingress has frozen the physical lifetime. A bare event or successful
    /// Status cannot create proof or an encryption result. Early0011 is kept
    /// only after this exact install actually submitted, then waits for accept.
    pub(crate) fn installation_event(
        &mut self,
        current: Identity,
        now: u64,
        event: u16,
        status: u8,
        enabled: u8,
    ) -> Result<(), Error> {
        // Terminal success is a historical operation result, never permission
        // to keep reporting encryption after an actual off/failure/rekey event.
        // Revocation/physical lifetime are separately rechecked by Runtime.
        if current != self.identity {
            return Err(Error::Stale);
        }
        self.expire(now);
        if event == 0x0011 && self.installation_pending() {
            // Correlated physical terminal evidence can drain old obligation
            // after cancellation/expiry, but can never grant a new result.
            let i = self.installation.ok_or(Error::Unsupported)?;
            let expected = if i.role == 0 { 0x1c03 } else { 0x1c05 };
            let submitted = self.pairing.is_some_and(|p| p.last_submitted == expected);
            if !submitted && !(i.role == 1 && i.requested) {
                return Err(Error::Stale);
            }
            if !submitted && status == 0 && enabled == 1 {
                self.fail_pairing(-71);
                self.phase = Phase::Uncertain;
                self.reset_required = true;
                return Err(Error::Stale);
            }
            let known_terminal = status != 0 || enabled <= 2;
            if !known_terminal {
                self.fail_pairing(-71);
                self.phase = Phase::Uncertain;
                self.reset_required = true;
                return Err(Error::Unsupported);
            }
            if let Some(i) = &mut self.installation {
                i.pending = false;
            }
            if !submitted && self.phase == Phase::Open {
                self.fail_pairing(if status != 0 { -5 } else { -71 });
                return Err(Error::Closed);
            }
            if self.phase != Phase::Open {
                if self.phase == Phase::Closing && !self.outstanding() {
                    self.phase = Phase::Closed;
                }
                return Err(if now >= self.deadline {
                    Error::Expired
                } else {
                    Error::Closed
                });
            }
        }
        if event == 0x0011
            && self.phase == Phase::Closed
            && self.installation.is_some()
            && self.capability.is_some_and(|c| c.observation.state == 9)
            && (status != 0 || enabled != 1)
        {
            if let Some(c) = &mut self.capability {
                c.observation.state = 5;
                c.observation.status = status;
                c.observation.error = if status != 0 { -5 } else { -71 };
            }
            return Err(Error::Closed);
        }
        self.admission(current, now)?;
        let mut i = self.installation.ok_or(Error::Unsupported)?;
        if !self.pairing.is_some_and(|p| p.proof_verified) {
            return Err(Error::Stale);
        }
        match event {
            0x000e if i.role == 1 && !i.requested && !i.queued => {
                i.requested = true;
                i.pending = true; // Controller waiting for params is already a physical procedure.
            }
            0x0011 => {
                let expected = if i.role == 0 { 0x1c03 } else { 0x1c05 };
                if !i.queued || !self.pairing.is_some_and(|p| p.last_submitted == expected) {
                    return Err(Error::Stale);
                }
                if status != 0 || enabled != 1 {
                    self.fail_pairing(if status != 0 { -5 } else { -71 });
                    return Err(Error::Closed);
                }
                i.encrypted = true;
            }
            _ => return Err(Error::Unsupported),
        }
        self.installation = Some(i);
        self.finish_pairing_if_drained();
        Ok(())
    }

    /// G-initiated no-entry/no-MITM/no-Bond only. Every receive requires the
    /// prerequisite local packet to have ACTUALLY submitted, not just queued.
    /// No crypto is performed here or under the caller's IRQ lock.
    pub(crate) fn pairing_input(
        &mut self,
        current: Identity,
        now: u64,
        index: u16,
        bytes: &[u8],
    ) -> Result<Option<CryptoJob>, Error> {
        self.admission(current, now)?;
        let mut p = self.pairing.ok_or(Error::Unsupported)?;
        if p.job.is_some() {
            return Err(Error::Full);
        }
        if index != p.expected {
            self.fail_pairing(-71);
            return Err(Error::Unsupported);
        }
        let previous = match index {
            0x134 => 0,
            0x135 => 0x134,
            0x136 => 0x135,
            0x137 | 0x138 => 0x136,
            0x139 => 0x138,
            0x13a => 0x139,
            0x141 => 0x13a,
            0x142 => 0x141,
            _ => return Err(Error::Unsupported),
        };
        if p.last_submitted != previous {
            return Err(Error::Stale);
        }
        let mut data = [0; 64];
        let kind = match index {
            0x134 | 0x135 => {
                if bytes != CAPABILITY_OFFER {
                    self.fail_pairing(-95);
                    return Err(Error::Unsupported);
                }
                if let Some(c) = &mut self.capability {
                    c.observation.peer.copy_from_slice(bytes);
                    c.observation.flags |= 4;
                    c.observation.state = 2;
                }
                if index == 0x134 {
                    self.enqueue(current, now, 0x135, &CAPABILITY_OFFER)?;
                    p.expected = 0x136;
                } else {
                    let mut message = [0; 70];
                    message[..6].copy_from_slice(&[16, 1, 2, 2, 2, 2]);
                    message[6..].copy_from_slice(&p.public);
                    self.enqueue(current, now, 0x136, &message)?;
                    p.expected = 0x137;
                }
                self.pairing = Some(p);
                return Ok(None);
            }
            0x136 => {
                if bytes.len() != 70 || bytes[..6] != [16, 1, 2, 2, 2, 2] {
                    self.fail_pairing(-95);
                    return Err(Error::Unsupported);
                }
                data.copy_from_slice(&bytes[6..]);
                CryptoKind::GPublicAndConfirm
            }
            0x137 => {
                if bytes.len() != 64 {
                    self.fail_pairing(-22);
                    return Err(Error::Invalid);
                }
                data.copy_from_slice(bytes);
                CryptoKind::TPublic
            }
            0x138 | 0x139 | 0x13a | 0x141 | 0x142 => {
                if bytes.len() != 16 {
                    self.fail_pairing(-22);
                    return Err(Error::Invalid);
                }
                data[..16].copy_from_slice(bytes);
                match index {
                    0x138 => {
                        p.confirm.copy_from_slice(bytes);
                        CryptoKind::GNonce
                    }
                    0x139 => CryptoKind::TDerive,
                    0x13a => CryptoKind::GDerive,
                    0x141 => CryptoKind::GProofAndRespond,
                    _ => CryptoKind::TProof,
                }
            }
            _ => return Err(Error::Unsupported),
        };
        let cookie = self.next_cookie;
        self.next_cookie = cookie.checked_add(1).ok_or(Error::Overflow)?;
        let ticket = Ticket {
            identity: self.identity,
            cookie,
        };
        p.job = Some((ticket, kind));
        self.pairing = Some(p);
        Ok(Some(CryptoJob {
            ticket,
            kind,
            data,
            confirm: p.confirm,
        }))
    }

    /// The real crypto caller supplies this receipt, then Runtime still checks
    /// the real Host/gate at enqueue AND the final driver submission. A late
    /// job can never revive a cancelled/expired/foreign Session.
    pub(crate) fn pairing_output(
        &mut self,
        current: Identity,
        now: u64,
        job: CryptoJob,
        result: Result<[u8; 16], i32>,
    ) -> Result<(), Error> {
        self.admission(current, now)?;
        let mut p = self.pairing.ok_or(Error::Unsupported)?;
        if p.job != Some((job.ticket, job.kind)) || job.ticket.identity != current {
            return Err(Error::Stale);
        }
        p.job = None;
        let output = match result {
            Ok(value) => value,
            Err(error) => {
                self.fail_pairing(error);
                return Err(Error::Closed);
            }
        };
        match job.kind {
            CryptoKind::GPublicAndConfirm => {
                self.enqueue(current, now, 0x137, &p.public)?;
                self.enqueue(current, now, 0x138, &output)?;
                p.expected = 0x139;
            }
            CryptoKind::TPublic => {
                p.expected = 0x138;
            }
            CryptoKind::GNonce => {
                self.enqueue(current, now, 0x139, &output)?;
                p.expected = 0x13a;
            }
            CryptoKind::TDerive => {
                self.enqueue(current, now, 0x13a, &output)?;
                p.expected = 0x141;
            }
            CryptoKind::GDerive => {
                self.enqueue(current, now, 0x141, &output)?;
                p.expected = 0x142;
            }
            CryptoKind::GProofAndRespond => {
                self.enqueue(current, now, 0x142, &output)?;
                p.expected = 0;
                p.proof_verified = true;
            }
            CryptoKind::TProof => {
                p.expected = 0;
                p.proof_verified = true;
            }
        }
        self.pairing = Some(p);
        self.finish_pairing_if_drained();
        Ok(())
    }
}
