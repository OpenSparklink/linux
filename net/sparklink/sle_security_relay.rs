// SPDX-License-Identifier: GPL-2.0-only
//! Physical Session owns one pinned relay ledger, independent of application fd.
//! Host commands retain the same C kref until real reply/fault, including revoke.
//! No crypto, policy approval, successful pairing or trusted installation here.
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
}
#[pin_data]
struct Owner {
    identity: Identity,
    #[pin]
    state: Lock<State, super::sle_irq_lock::IrqLockBackend>,
}
fn now() -> u64 {
    // SAFETY: read-only kernel clock; all relay deadlines use jiffies.
    unsafe { kernel::bindings::jiffies_64 }
}
fn error(e: relay::Error) -> Error {
    Error::from_errno(
        -(match e {
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
            state <- super::sle_irq_lock::new_irq_lock!(State {session:None,stopped:false}, "sparklink_security_relay"),
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
            Ok((ticket, packet)) => Ok((Self { pointer, ticket }, packet)),
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
            if result == 0 {
                Ok(())
            } else {
                Err(())
            }
        }) {
            Ok(()) => 0,
            Err(relay::Error::NeverSubmitted) => result,
            Err(e) => error(e).to_errno(),
        }
    }
    pub(crate) fn withdraw(&self) {
        let mut state = self.owner().state.lock();
        if let Some(session) = &mut state.session {
            session.withdraw();
        }
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
    }
    pub(crate) fn reply(&self, complete: bool, status: u8) {
        let mut state = self.owner().state.lock();
        if let Some(session) = &mut state.session {
            if session
                .reply(self.ticket, now(), complete, status)
                .is_some()
                && session.phase() == relay::Phase::Open
            {
                session.withdraw();
            }
        }
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
            .checked_add(kernel::time::msecs_to_jiffies(5000) as u64)
            .ok_or(EOVERFLOW);
        let deadline = match deadline {
            Ok(d) => d,
            Err(e) => {
                unsafe { sl_connection_session_put(pointer) };
                return Err(e);
            }
        };
        let (command, packet) = unsafe { Command::prepare_denial(pointer, identity, deadline) }?;
        let super::sle_dli::ControllerBackend::Native(controller) = &runtime.controller;
        let plan = match controller.prepare_relay(&packet) {
            Ok(p) => p,
            Err(e) => {
                command.withdraw();
                return Err(e);
            }
        };
        let retained = command.clone();
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
}
