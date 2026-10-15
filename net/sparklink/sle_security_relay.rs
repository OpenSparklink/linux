// SPDX-License-Identifier: GPL-2.0-only
//! Physical Session owns one pinned relay ledger, independent of application fd.
//! Host commands retain the same C kref until real reply/fault, including revoke.
//! Manager approval enables explicit capability or candidate proof exchange.
//! Sleeping crypto is a dependency of this sole Session, outside IRQ locks.
//! Explicit no-MITM install is distinct from Agent consent/trusted identity/Bond.
use super::sle_security_relay_state::{self as relay, Identity, Ticket};
use core::{ffi::c_void, pin::Pin};
use kernel::{prelude::*, sync::lock::Lock};

extern "C" {
    fn sl_connection_session_security(session: *mut c_void) -> *mut c_void;
    fn sl_connection_session_get(session: *mut c_void);
    fn sl_connection_session_put(session: *mut c_void);
}
struct State {
    session: Option<relay::Session>,
    stopped: bool,
    author: u64,
    request: u64,
    role: u8,
    reset_reported: bool,
    material: Option<super::sle_pair_material::Material>,
}
#[pin_data]
struct Owner {
    identity: Identity,
    #[pin]
    state: Lock<State, super::sle_irq_lock::IrqLockBackend>,
}
fn now() -> u64 {
    // SAFETY: read-only CLOCK_MONOTONIC, same domain as the caller's original
    // deadline. Host jiffies are only a cleanup timer, never this authorization.
    (unsafe { kernel::bindings::ktime_get() }) as u64
}
fn error(e: relay::Error) -> Error {
    Error::from_errno(
        -(match e {
            relay::Error::Unsupported => kernel::bindings::EOPNOTSUPP,
            relay::Error::Invalid => kernel::bindings::EINVAL,
            relay::Error::Stale => kernel::bindings::ESTALE,
            relay::Error::Expired => kernel::bindings::ETIMEDOUT,
            relay::Error::Closed => kernel::bindings::ECANCELED,
            relay::Error::Full => kernel::bindings::ENOBUFS,
            relay::Error::Overflow => kernel::bindings::EOVERFLOW,
            relay::Error::NeverSubmitted => kernel::bindings::EIO,
        } as i32),
    )
}
#[no_mangle]
unsafe extern "C" fn sl_security_owner_create_rust(
    id: u16,
    generation: u64,
    lifetime: u64,
    handle: u16,
    epoch: u64,
) -> *mut c_void {
    if generation == 0 || lifetime == 0 || epoch == 0 || handle > 0x0fff {
        return core::ptr::null_mut();
    }
    let actor = KBox::pin_init(
        pin_init!(Owner {
            identity: Identity {controller:id,generation,lifetime,handle,grant_epoch:epoch},
            state <- super::sle_irq_lock::new_irq_lock!(State {session:None,stopped:false,author:0,request:0,role:0,reset_reported:false,material:None}, "sparklink_security_relay"),
        }),
        GFP_KERNEL,
    );
    match actor {
        // SAFETY: C keeps this allocation at the same address until final kref
        // release; it never moves the pinned lock or shares a mutable reference.
        Ok(actor) => KBox::into_raw(unsafe { Pin::into_inner_unchecked(actor) }).cast(),
        Err(_) => core::ptr::null_mut(),
    }
}
#[no_mangle]
unsafe extern "C" fn sl_security_owner_stop_rust(raw: *mut c_void) {
    if raw.is_null() {
        return;
    }
    // SAFETY: C physical Session reference retains the immutable owner.
    let owner = unsafe { &*raw.cast::<Owner>() };
    let mut state = owner.state.lock();
    state.stopped = true;
    if let Some(session) = &mut state.session {
        session.withdraw();
    }
    let material = state.material.take();
    drop(state);
    drop(material);
}
#[no_mangle]
unsafe extern "C" fn sl_security_owner_destroy_rust(raw: *mut c_void) {
    if raw.is_null() {
        return;
    }
    // SAFETY: final C kref, work/commands/socket refs gone. Destruction of the
    // fixed ledger is nonblocking; no barrier or successful Complete invented.
    drop(unsafe { KBox::from_raw(raw.cast::<Owner>()) });
}

/// Owning reference follows an internal command, not a caller's fd. Dropping
/// it is nonblocking: final C free has no work join or Host callback.
pub(crate) struct Command {
    pointer: *mut c_void,
    pub(crate) ticket: Ticket,
    index: u16,
    deadline: u64,
}
// SAFETY: C kref protects lifetime, pinned IRQ lock serializes all ledger access.
unsafe impl Send for Command {}
// SAFETY: immutable reference/ticket; methods only mutate through the IRQ lock.
unsafe impl Sync for Command {}
impl Clone for Command {
    fn clone(&self) -> Self {
        unsafe { sl_connection_session_get(self.pointer) };
        Self {
            pointer: self.pointer,
            ticket: self.ticket,
            index: self.index,
            deadline: self.deadline,
        }
    }
}
impl Drop for Command {
    fn drop(&mut self) {
        unsafe { sl_connection_session_put(self.pointer) };
    }
}
impl Command {
    fn owner(&self) -> &Owner {
        // SAFETY: our C kref retains the owner at an immutable address.
        unsafe { &*sl_connection_session_security(self.pointer).cast::<Owner>() }
    }
    /// Takes the distinct caller ref returned by Runtime::acquire_session.
    pub(crate) unsafe fn prepare_denial(
        pointer: *mut c_void,
        identity: Identity,
        deadline: u64,
    ) -> Result<(Self, relay::Packet)> {
        // SAFETY: caller gives a live reference to that exact physical Session.
        let owner = unsafe { &*sl_connection_session_security(pointer).cast::<Owner>() };
        let mut state = owner.state.lock();
        let prepared = (|| {
            if state.stopped || identity != owner.identity {
                return Err(ENODEV);
            }
            if state.session.is_some() {
                return Err(EBUSY);
            } // no same-life retry barrier yet
            let mut session = relay::Session::new(identity, now(), deadline).map_err(error)?;
            // Standard SM_ERR_PAIRING_NOT_SUPPORT=02. This is a real failure
            // message, not a fabricated successful pairing/capability reply.
            let ticket = session
                .enqueue(identity, now(), 0x0147, &[2])
                .map_err(error)?;
            if session.queued() != 1 {
                return Err(EIO);
            }
            let packet = session
                .prepare(identity, now())
                .map_err(error)?
                .ok_or(EIO)?;
            state.session = Some(session);
            Ok((ticket, packet))
        })();
        drop(state);
        match prepared {
            Ok((ticket, packet)) => Ok((
                Self {
                    pointer,
                    ticket,
                    index: packet.index,
                    deadline,
                },
                packet,
            )),
            Err(e) => {
                unsafe { sl_connection_session_put(pointer) };
                Err(e)
            }
        }
    }
    /// Caller holds canonical Host/gate; this final lock spans only prepared
    /// atomic queueing. No allocation, wait, join or Host reentry is permitted.
    pub(crate) fn commit(&self, submit: impl FnOnce() -> i32) -> i32 {
        let owner = self.owner();
        let mut state = owner.state.lock();
        if state.stopped {
            return ENODEV.to_errno();
        }
        let Some(session) = &mut state.session else {
            return EINVAL.to_errno();
        };
        let mut result = EINVAL.to_errno();
        match session.commit(self.ticket, owner.identity, now(), || {
            result = submit();
            if result == 0 { Ok(()) } else { Err(()) }
        }) {
            Ok(()) => 0,
            Err(relay::Error::NeverSubmitted) => result,
            Err(e) => error(e).to_errno(),
        }
    }
    /// SDK111 successful Complete echoes this submission's handle and index.
    /// Error Status/Complete has no guaranteed echo and can only end in failure.
    /// The echo has no lifetime token; reuse still needs a proven wire barrier.
    /// Frozen driver wire echo; set before cloning/admission, never after TX.
    pub(crate) fn bind_wire_echo_index(&mut self, index: u16) {
        self.index = index;
    }
    pub(crate) fn reply_matches(&self, complete: bool, status: u8, data: &[u8]) -> bool {
        if self.accepts_status() {
            return !complete
                || status != 0
                || data.is_empty()
                || (data.len() == 2
                    && u16::from_le_bytes([data[0], data[1]]) == self.ticket.identity.handle);
        }
        !complete
            || status != 0
            || (data.len() == 4
                && u16::from_le_bytes([data[0], data[1]]) == self.ticket.identity.handle
                && u16::from_le_bytes([data[2], data[3]]) == self.index)
    }
    pub(crate) fn accepts_status(&self) -> bool {
        matches!(self.index, 0x1c03 | 0x1c05)
    }
    /// Only a retained synchronous driver ticket can call this. The Host queue
    /// holds zero placeholders; the private key is copied to a driver buffer.
    pub(crate) fn materialize(&self, params: &mut [u8]) -> Result {
        if !self.accepts_status() {
            return Err(Error::from_errno(-(kernel::bindings::EOPNOTSUPP as i32)));
        }
        let role = if self.index == 0x1c03 { 0 } else { 1 };
        let length = if role == 0 { 21 } else { 20 };
        if params.len() != length
            || params[..2] != self.ticket.identity.handle.to_le_bytes()
            || params[2..18].iter().any(|b| *b != 0)
            || params[18..20] != [1, 1]
            || (role == 0 && params[20] != 0)
        {
            return Err(EINVAL);
        }
        let owner = self.owner();
        let mut state = owner.state.lock();
        if state.stopped {
            return Err(ENODEV);
        }
        state
            .session
            .as_mut()
            .ok_or(ENODEV)?
            .installation_matches(owner.identity, now(), self.ticket, self.index)
            .map_err(error)?;
        let out: &mut [u8; 16] = (&mut params[2..18]).try_into().map_err(|_| EINVAL)?;
        state.material.as_mut().ok_or(EIO)?.fill_install(role, out)
    }
    pub(crate) fn withdraw(&self) {
        let mut state = self.owner().state.lock();
        if let Some(session) = &mut state.session {
            session.expire(now());
            session.withdraw();
        }
        let material = state.material.take();
        drop(state);
        drop(material);
    }
    pub(crate) fn failed(&self, submitted: bool) {
        let mut state = self.owner().state.lock();
        if let Some(session) = &mut state.session {
            if submitted {
                let _ = session.transport_failed(self.ticket);
            } else {
                session.withdraw();
            }
            if session.reset_required() {
                pr_warn!("sparklink: security relay uncertain; physical barrier required\n");
            }
        }
        let material = state.material.take();
        drop(state);
        drop(material);
    }
    pub(crate) fn reply(&self, complete: bool, status: u8) {
        let mut state = self.owner().state.lock();
        if let Some(session) = &mut state.session {
            if session
                .reply(self.ticket, now(), complete, status)
                .is_some()
                && !session.capability_exchange()
                && session.phase() == relay::Phase::Open
            {
                session.withdraw();
            }
        }
        let material = if status != 0 {
            state.material.take()
        } else {
            None
        };
        drop(state);
        drop(material);
    }
}

impl super::ControllerRuntime {
    /// Default policy has no approved pairing/Agent yet. A correctly directed
    /// initial request gets a real bounded PairingNotSupported PDU, not success.
    /// Other SMP traffic is unsupported; no automatic crypto/key installation.
    pub(crate) fn deny_unapproved_pairing(
        &self,
        runtime: &super::ControllerState,
        lifetime: u64,
        handle: u16,
        index: u16,
        bytes: &[u8],
    ) -> Result {
        let epoch = {
            let host = self.host.lock();
            let (_, known, links) = host.link_snapshot();
            let link = links
                .iter()
                .flatten()
                .find(|l| known && l.lifetime == lifetime && l.handle == handle)
                .ok_or(Error::from_errno(-(kernel::bindings::ESTALE as i32)))?;
            if !relay::initial_pairing_request(link.role, index, bytes.len()) {
                return Err(Error::from_errno(-(kernel::bindings::EOPNOTSUPP as i32)));
            }
            host.grants
                .current_epoch()
                .ok_or(Error::from_errno(-(kernel::bindings::EACCES as i32)))?
        };
        let pointer = self.acquire_session(lifetime, handle, epoch)?;
        let identity = Identity {
            controller: self.identity.id,
            generation: self.identity.generation,
            lifetime,
            handle,
            grant_epoch: epoch,
        };
        let deadline = now()
            .checked_add(5_000_000_000)
            .ok_or(EOVERFLOW);
        let deadline = match deadline {
            Ok(d) => d,
            Err(e) => {
                unsafe { sl_connection_session_put(pointer) };
                return Err(e);
            }
        };
        let (command, packet) = unsafe { Command::prepare_denial(pointer, identity, deadline) }?;
        self.enqueue_security(runtime, command, packet)
    }
}

impl Command {
    /// Caller gives a distinct physical Session ref. Approval is under the
    /// Runtime Host/gate locks, never supplied by an ordinary application fd.
    unsafe fn approve(
        pointer: *mut c_void,
        identity: Identity,
        author: u64,
        request: u64,
        role: u8,
        initiate: bool,
        deadline: u64,
        mut material: Option<super::sle_pair_material::Material>,
        public: [u8; 64],
        install: bool,
    ) -> Result<Option<(Self, relay::Packet)>> {
        let owner = unsafe { &*sl_connection_session_security(pointer).cast::<Owner>() };
        let mut state = owner.state.lock();
        let result = (|| {
            if state.stopped || identity != owner.identity {
                return Err(ENODEV);
            }
            if state.session.is_some() {
                return Err(EBUSY);
            }
            let mut session = relay::Session::new(identity, now(), deadline).map_err(error)?;
            let packet = if material.is_some() {
                session.approve_key_agreement(identity, now(), role, initiate, public)
            } else {
                session.approve_capabilities(identity, now(), role, initiate)
            }
            .map_err(error)?;
            if install {
                session
                    .enable_installation(identity, now(), role)
                    .map_err(error)?;
            }
            state.session = Some(session);
            state.author = author;
            state.request = request;
            state.role = role;
            state.material = material.take();
            Ok(packet)
        })();
        drop(state);
        match result {
            Ok(Some(packet)) => Ok(Some((
                Self {
                    pointer,
                    ticket: packet.ticket,
                    index: packet.index,
                    deadline,
                },
                packet,
            ))),
            other => {
                unsafe { sl_connection_session_put(pointer) };
                other.map(|_| None)
            }
        }
    }

    /// Returns handled=true for an approved lifetime even on failure. Such a
    /// packet must not fall through and manufacture another denial procedure.
    unsafe fn receive(
        pointer: *mut c_void,
        identity: Identity,
        index: u16,
        bytes: &[u8],
        runtime: &super::ControllerRuntime,
    ) -> Result<(bool, Option<(Self, relay::Packet)>)> {
        let owner = unsafe { &*sl_connection_session_security(pointer).cast::<Owner>() };
        let mut state = owner.state.lock();
        if state.session.as_ref().is_some_and(|s| s.key_agreement()) {
            let job = if state.stopped || identity != owner.identity {
                Err(ENODEV)
            } else {
                state.session.as_mut().ok_or(ENODEV).and_then(|s| {
                    s.pairing_input(identity, now(), index, bytes)
                        .map_err(error)
                })
            };
            let result = match job {
                Ok(Some(job)) => {
                    let material = state.material.take();
                    drop(state);
                    let result = if let Some(mut material) = material {
                        // Actual P256/CMAC may sleep. No Owner/Host/gate guard
                        // or unretained C pointer crosses this operation.
                        let receipt = material.execute(&job);
                        let host = runtime.host.lock();
                        let gate = runtime.schedule_gate.lock();
                        let (_, known, links) = host.link_snapshot();
                        let live = !*gate
                            && host.admits_data()
                            && host.grants.permits(identity.grant_epoch)
                            && known
                            && links.iter().flatten().any(|l| {
                                l.lifetime == identity.lifetime && l.handle == identity.handle
                            });
                        let mut state = owner.state.lock();
                        let result = if !live || state.stopped {
                            Err(EACCES)
                        } else {
                            state.session.as_mut().ok_or(ENODEV).and_then(|s| {
                                s.pairing_output(identity, now(), job, receipt)
                                    .map_err(error)
                            })
                        };
                        if result.is_ok() {
                            state.material = Some(material);
                        } else if let Some(s) = &mut state.session {
                            s.withdraw();
                        }
                        drop(state);
                        drop(gate);
                        drop(host);
                        result
                    } else {
                        let mut state = owner.state.lock();
                        if let Some(s) = &mut state.session {
                            s.crypto_failed(EIO.to_errno());
                        }
                        Err(EIO)
                    };
                    result
                }
                Ok(None) => {
                    drop(state);
                    Ok(())
                }
                Err(e) => {
                    let material = state.material.take();
                    drop(state);
                    drop(material);
                    Err(e)
                }
            };
            unsafe { sl_connection_session_put(pointer) };
            return result.map(|()| (true, None));
        }
        let result = (|| {
            if state.stopped || identity != owner.identity {
                return Err(ENODEV);
            }
            let Some(session) = &mut state.session else {
                return Ok((false, None));
            };
            if !session.capability_exchange() {
                return Ok((false, None));
            }
            let packet = session
                .receive_capabilities(identity, now(), index, bytes)
                .map_err(error)?;
            Ok((true, packet.map(|p| (p, session.deadline()))))
        })();
        drop(state);
        match result {
            Ok((handled, Some((packet, deadline)))) => Ok((
                handled,
                Some((
                    Self {
                        pointer,
                        ticket: packet.ticket,
                        index: packet.index,
                        deadline,
                    },
                    packet,
                )),
            )),
            other => {
                unsafe { sl_connection_session_put(pointer) };
                other.map(|(handled, _)| (handled, None))
            }
        }
    }
}

impl super::ControllerRuntime {
    fn relay_identity(&self, lifetime: u64, handle: u16) -> Result<Identity> {
        let host = self.host.lock();
        let (_, known, links) = host.link_snapshot();
        if !known
            || !links
                .iter()
                .flatten()
                .any(|l| l.lifetime == lifetime && l.handle == handle)
        {
            return Err(Error::from_errno(-(kernel::bindings::ESTALE as i32)));
        }
        Ok(Identity {
            controller: self.identity.id,
            generation: self.identity.generation,
            lifetime,
            handle,
            grant_epoch: host.grants.current_epoch().ok_or(EACCES)?,
        })
    }

    fn enqueue_security(
        &self,
        runtime: &super::ControllerState,
        mut command: Command,
        packet: relay::Packet,
    ) -> Result {
        let super::sle_dli::ControllerBackend::Native(controller) = &runtime.controller;
        let plan = match controller.prepare_relay(&packet) {
            Ok(p) => p,
            Err(e) => {
                command.withdraw();
                return Err(e);
            }
        };
        command.bind_wire_echo_index(plan.3);
        let retained = command.clone();
        let sampled_ns = now();
        // SAFETY: read-only coarse Host clock, sampled after monotonic time.
        let jiffies_after = unsafe { kernel::bindings::jiffies_64 };
        // Use the actual kernel timer rate, not bindgen's userspace HZ macro.
        let hz = kernel::time::msecs_to_jiffies(1000) as u32;
        let deadline = match relay::host_wake_deadline(sampled_ns, command.deadline, jiffies_after, hz) {
            Ok(value) => value,
            Err(e) => { retained.withdraw(); return Err(error(e)); }
        };
        let mut host = self.host.lock();
        let gate = self.schedule_gate.lock();
        let result = if *gate {
            Err(ENODEV)
        } else {
            host.enqueue_relay(plan.0, &plan.1[..plan.2], deadline, command)
        };
        drop(gate);
        drop(host);
        if result.is_err() {
            retained.withdraw();
        }
        result
    }

    pub(crate) fn approve_security_capabilities(
        &self,
        runtime: &super::ControllerState,
        author: u64,
        request: &super::sle_uapi::SleSecurityNegotiationSubmit,
    ) -> Result {
        // The immutable caller deadline also covers policy/Agent/queue/crypto.
        // Session's every prepare/commit/input/query uses this same ns domain;
        // no conversion to Host timer ticks can extend authorization.
        let deadline = relay::original_deadline(now(), request.deadline_monotonic_ns, request.timeout_ms).map_err(error)?;
        let identity = self.relay_identity(request.lifetime, request.handle)?;
        let (material, public) = if matches!(request.flags, 2 | 3) {
            let mut snapshot: super::sle_uapi::SleControllerSnapshot =
                unsafe { core::mem::zeroed() };
            runtime.controller.provider().fill_snapshot(&mut snapshot);
            let mut material = super::sle_pair_material::Material::new(
                request.role,
                &snapshot.address,
                &request.address,
            )?;
            let public = material.public()?;
            (Some(material), public)
        } else {
            (None, [0; 64])
        };
        let pointer =
            self.acquire_session(identity.lifetime, identity.handle, identity.grant_epoch)?;
        let mut transferred = false;
        let result = (|| {
            let host = self.host.lock();
            let (_, known, links) = host.link_snapshot();
            let gate = self.schedule_gate.lock();
            if *gate {
                return Err(ENODEV);
            }
            if !host.grants.permits(identity.grant_epoch) {
                return Err(EACCES);
            }
            if !known
                || !links.iter().flatten().any(|l| {
                    l.lifetime == identity.lifetime
                        && l.handle == identity.handle
                        && l.role == request.role
                        && l.address_type == request.address_type
                        && l.address == request.address
                })
            {
                return Err(Error::from_errno(-(kernel::bindings::ESTALE as i32)));
            }
            // SAFETY: transfer exactly our caller ref after all validation.
            transferred = true;
            unsafe {
                Command::approve(
                    pointer,
                    identity,
                    author,
                    request.request_id,
                    request.role,
                    request.action == 2,
                    deadline,
                    material,
                    public,
                    request.flags == 3,
                )
            }
        })();
        if !transferred {
            unsafe { sl_connection_session_put(pointer) };
        }
        // Command::approve consumes the caller ref even on error.
        match result {
            Ok(Some((command, packet))) => self.enqueue_security(runtime, command, packet),
            Ok(None) => Ok(()),
            Err(e) => Err(e),
        }
    }

    pub(crate) fn cancel_security_author(
        &self, author: u64, lifetime: u64, handle: u16, request: u64,
    ) -> Result {
        let identity = self.relay_identity(lifetime, handle)?;
        let (pointer, epoch) = self.existing_session_for_event(lifetime, handle).ok_or(ENOENT)?;
        // Keep the event lookup's cloned kref through validation and material
        // destruction; cancellation must never allocate a replacement Session.
        let (result, material) = (|| {
            let host = self.host.lock();
            let (_, known, links) = host.link_snapshot();
            let gate = self.schedule_gate.lock();
            if *gate { return (Err(ENODEV), None); }
            if epoch != identity.grant_epoch || !host.admits_data() || !host.grants.permits(epoch) {
                return (Err(EACCES), None);
            }
            if !known || !links.iter().flatten().any(|l| l.lifetime == lifetime && l.handle == handle) {
                return (Err(Error::from_errno(-(kernel::bindings::ESTALE as i32))), None);
            }
            // SAFETY: lookup retains the C object and immutable security owner.
            let owner = unsafe { &*sl_connection_session_security(pointer).cast::<Owner>() };
            let mut state = owner.state.lock();
            if owner.identity != identity || state.stopped { return (Err(ENODEV), None); }
            if state.author != author || state.request != request { return (Err(ENOENT), None); }
            let result = state.session.as_mut().ok_or(ENOENT)
                .and_then(|session| session.cancel(identity, now()).map_err(error)).map(|_| ());
            let material = if result.is_ok() { state.material.take() } else { None };
            (result, material)
        })();
        drop(material); // wipe secrets outside Host/gate/Owner locks
        // SAFETY: release exactly the existing-lookup caller ref, never table ref.
        unsafe { sl_connection_session_put(pointer) };
        result
    }

    pub(crate) fn security_capability_observation(
        &self,
        author: u64,
        lifetime: u64,
        handle: u16,
        request: u64,
    ) -> Result<(relay::CapabilityObservation, u8)> {
        let identity = self.relay_identity(lifetime, handle)?;
        let pointer = self.acquire_session(lifetime, handle, identity.grant_epoch)?;
        let result = (|| {
            let host = self.host.lock();
            let (_, known, links) = host.link_snapshot();
            let gate = self.schedule_gate.lock();
            if *gate {
                return Err(ENODEV);
            }
            if !host.grants.permits(identity.grant_epoch) {
                return Err(EACCES);
            }
            if !known
                || !links
                    .iter()
                    .flatten()
                    .any(|l| l.lifetime == lifetime && l.handle == handle)
            {
                return Err(Error::from_errno(-(kernel::bindings::ESTALE as i32)));
            }
            let owner = unsafe { &*sl_connection_session_security(pointer).cast::<Owner>() };
            let mut state = owner.state.lock();
            let result = if state.stopped {
                Err(ENODEV)
            } else if state.author != author || state.request != request {
                Err(ENOENT)
            } else {
                let role = state.role;
                state
                    .session
                    .as_mut()
                    .and_then(|s| s.capability_observation(now()))
                    .map(|o| (o, role))
                    .ok_or(ENOENT)
            };
            drop(state);
            result
        })();
        unsafe { sl_connection_session_put(pointer) };
        result
    }

    pub(crate) fn receive_security_data(
        &self,
        runtime: &super::ControllerState,
        lifetime: u64,
        handle: u16,
        index: u16,
        bytes: &[u8],
    ) -> Result {
        let identity = self.relay_identity(lifetime, handle)?;
        let pointer = self.acquire_session(lifetime, handle, identity.grant_epoch)?;
        let (handled, packet) = unsafe { Command::receive(pointer, identity, index, bytes, self) }?;
        if let Some((command, packet)) = packet {
            return self.enqueue_security(runtime, command, packet);
        }
        if handled {
            Ok(())
        } else {
            self.deny_unapproved_pairing(runtime, lifetime, handle, index, bytes)
        }
    }

    pub(crate) fn receive_security_installation(
        &self,
        lifetime: u64,
        handle: u16,
        event: u16,
        status: u8,
        enabled: u8,
    ) -> Result {
        // This lookup never creates a Session and grants no new authorization.
        let (pointer, epoch) = self
            .existing_session_for_event(lifetime, handle)
            .ok_or(Error::from_errno(-(kernel::bindings::ESTALE as i32)))?;
        let identity = Identity {
            controller: self.identity.id,
            generation: self.identity.generation,
            lifetime,
            handle,
            grant_epoch: epoch,
        };
        let result = (|| {
            let host = self.host.lock();
            let gate = self.schedule_gate.lock();
            let (_, known, links) = host.link_snapshot();
            if *gate
                || !known
                || !links
                    .iter()
                    .flatten()
                    .any(|l| l.lifetime == lifetime && l.handle == handle)
            {
                return Err(Error::from_errno(-(kernel::bindings::ESTALE as i32)));
            }
            let owner = unsafe { &*sl_connection_session_security(pointer).cast::<Owner>() };
            if owner.identity != identity {
                return Err(Error::from_errno(-(kernel::bindings::ESTALE as i32)));
            }
            let mut state = owner.state.lock();
            let live = !state.stopped && host.admits_data() && host.grants.permits(epoch);
            let session = state
                .session
                .as_mut()
                .ok_or(Error::from_errno(-(kernel::bindings::EOPNOTSUPP as i32)))?;
            if !live {
                session.withdraw();
            }
            // Old physical receipt may pay old obligation; cannot recreate keys,
            // authorize the successor epoch or publish a new successful result.
            session
                .installation_event(identity, now(), event, status, enabled)
                .map_err(error)
        })();
        unsafe { sl_connection_session_put(pointer) };
        result
    }

    /// RX/Complete may queue more than one PDU (T public then confirm). Advance
    /// the same bounded ledger only after its previous actual reply is paid.
    pub(crate) fn progress_security(&self, runtime: &super::ControllerState) {
        let (_, known, links) = self.host.lock().link_snapshot();
        if !known {
            return;
        }
        for link in links.iter().flatten() {
            let Ok(identity) = self.relay_identity(link.lifetime, link.handle) else {
                continue;
            };
            let Ok(pointer) =
                self.acquire_session(link.lifetime, link.handle, identity.grant_epoch)
            else {
                continue;
            };
            let owner = unsafe { &*sl_connection_session_security(pointer).cast::<Owner>() };
            let mut state = owner.state.lock();
            let keep_material = state
                .session
                .as_mut()
                .and_then(|s| s.capability_observation(now()))
                .is_some_and(|o| matches!(o.state, 1 | 2 | 3 | 8));
            let warn_reset =
                !state.reset_reported && state.session.as_ref().is_some_and(|s| s.reset_required());
            if warn_reset {
                state.reset_reported = true;
            }
            let retired = if keep_material {
                None
            } else {
                state.material.take()
            };
            let packet = if state.stopped {
                None
            } else {
                state.session.as_mut().and_then(|s| {
                    if !s.key_agreement() || s.phase() != relay::Phase::Open {
                        None
                    } else {
                        let _ = s.progress_installation(identity, now());
                        s.prepare(identity, now())
                            .ok()
                            .flatten()
                            .map(|p| (p, s.deadline()))
                    }
                })
            };
            drop(state);
            drop(retired);
            if warn_reset {
                pr_warn!(
                    "sparklink: sle{} generation={} lifetime={} handle={} security outcome uncertain; physical link retirement required\n",
                    identity.controller,
                    identity.generation,
                    identity.lifetime,
                    identity.handle
                );
            }
            if let Some((packet, deadline)) = packet {
                let command = Command {
                    pointer,
                    ticket: packet.ticket,
                    index: packet.index,
                    deadline,
                };
                if let Err(e) = self.enqueue_security(runtime, command, packet) {
                    pr_debug!(
                        "sparklink: security continuation refused {}\n",
                        e.to_errno()
                    );
                }
            } else {
                unsafe { sl_connection_session_put(pointer) };
            }
        }
    }
}
