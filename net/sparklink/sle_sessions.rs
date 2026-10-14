// SPDX-License-Identifier: GPL-2.0-only
//! Runtime owns C connection sessions by immutable physical lifetime. Table
//! operations are process-context only; no mutex or Host guard spans stop/join.
use core::ffi::c_void;
use kernel::prelude::*;
use core::sync::atomic::Ordering;

extern "C" {
    fn sl_connection_session_create(id: u16, generation: u64, lifetime: u64, handle: u16, epoch: u64, maximum: u16) -> *mut c_void;
    fn sl_connection_session_get(session: *mut c_void);
    fn sl_connection_session_put(session: *mut c_void);
    fn sl_connection_session_stop(session: *mut c_void, error: i32);
}
pub(crate) struct Session {
    pub(crate) lifetime: u64,
    pub(crate) handle: u16,
    pub(crate) epoch: u64,
    pointer: *mut c_void,
}
// SAFETY: C kref and session/channel spinlocks protect the referenced object.
unsafe impl Send for Session {}
// SAFETY: pointer identity is immutable; C serializes state and work lifetime.
unsafe impl Sync for Session {}
impl Drop for Session {
    fn drop(&mut self) {
        // SAFETY: each table entry owns exactly the constructor's reference.
        unsafe { sl_connection_session_put(self.pointer) };
    }
}
impl super::ControllerRuntime {
    /// Session table -> Host -> data -> scheduling is process-context order.
    /// Driver atomic commit never takes the session table mutex.
    fn session_limits(&self, lifetime: u64, handle: u16, epoch: u64, admission: Option<(unsafe extern "C" fn(*mut c_void) -> i32, *mut c_void)>) -> Result<u16> {
        let host = self.host.lock();
        let (_, known, links) = host.link_snapshot();
        let data = self.data.lock();
        let gate = self.schedule_gate.lock();
        if *gate { return Err(ENODEV); }
        if let Some(error) = host.controller_status().2 { return Err(error); }
        if !self.transport_open.load(Ordering::Acquire) || !known { return Err(EAGAIN); }
        if !host.admits_data() || !host.grants.permits(epoch) { return Err(Error::from_errno(-(kernel::bindings::EACCES as i32))); }
        if !links.iter().flatten().any(|link| link.lifetime == lifetime && link.handle == handle) {
            return Err(Error::from_errno(-(kernel::bindings::ESTALE as i32)));
        }
        let maximum = data.credits.maximum().map_err(super::sle_native_data::error)?;
        if let Some((admit, context)) = admission {
            // SAFETY: callback is synchronous, atomic Session queue admission.
            // Host/data/gate remain locked; no allocation, wait or Host reentry.
            let result = unsafe { admit(context) };
            if result < 0 { return Err(Error::from_errno(result)); }
        }
        Ok(maximum)
    }
    pub(crate) fn acquire_session(&self, lifetime: u64, handle: u16, epoch: u64) -> Result<*mut c_void> {
        {
            let table = self.sessions.lock();
            self.session_limits(lifetime, handle, epoch, None)?;
            if let Some(existing) = table.iter().flatten().find(|s| s.lifetime == lifetime && s.handle == handle && s.epoch == epoch) {
                // SAFETY: table retains object; fd/actor receives a distinct ref.
                unsafe { sl_connection_session_get(existing.pointer) };
                return Ok(existing.pointer);
            }
        }
        let maximum = self.session_limits(lifetime, handle, epoch, None)?;
        if maximum <= 5 { return Err(Error::from_errno(-(kernel::bindings::EOPNOTSUPP as i32))); }
        // SAFETY: constructor allocates outside any table/IRQ locks; reference
        // is adopted by a table entry, or dropped if another opener won.
        let candidate = unsafe { sl_connection_session_create(self.identity.id, self.identity.generation, lifetime, handle, epoch, maximum) };
        if candidate.is_null() { return Err(ENOMEM); }
        let mut pending = Some(Session { lifetime, handle, epoch, pointer: candidate });
        let lookup = (|| -> Result<*mut c_void> {
            let mut table = self.sessions.lock();
            self.session_limits(lifetime, handle, epoch, None)?; // withdrawal race rechecked
            if let Some(existing) = table.iter().flatten().find(|s| s.lifetime == lifetime && s.handle == handle && s.epoch == epoch) {
                // SAFETY: table owns a live reference; return a distinct caller ref.
                unsafe { sl_connection_session_get(existing.pointer) };
                return Ok(existing.pointer);
            }
            let slot = table.iter_mut().find(|slot| slot.is_none()).ok_or(Error::from_errno(-(kernel::bindings::ENOBUFS as i32)))?;
            *slot = pending.take();
            // SAFETY: table now owns constructor reference; caller gets another.
            unsafe { sl_connection_session_get(candidate) };
            Ok(candidate)
        })();
        drop(pending); // unused allocation released outside table/Host locks
        lookup
    }
    pub(crate) fn reconcile_sessions(&self) {
        let mut retired = [const { None }; 16];
        let error;
        {
            let mut table = self.sessions.lock();
            // Fresh canonical state while the table is locked: an earlier
            // snapshot must never remove a concurrently inserted new session.
            let host = self.host.lock();
            let (_, known, links) = host.link_snapshot();
            let gate = self.schedule_gate.lock();
            error = if *gate { ENODEV.to_errno() }
                else if let Some(fault) = host.controller_status().2 { fault.to_errno() }
                else if !host.admits_data() { -(kernel::bindings::EACCES as i32) }
                else { -(kernel::bindings::ECONNRESET as i32) };
            for (index, entry) in table.iter_mut().enumerate() {
                if entry.as_ref().is_some_and(|session| !host.grants.permits(session.epoch) || *gate || error != -(kernel::bindings::ECONNRESET as i32)
                    || (known && !links.iter().flatten().any(|link|
                        link.lifetime == session.lifetime && link.handle == session.handle))) {
                    let denied = entry.as_ref().is_some_and(|session| !host.grants.permits(session.epoch));
                    retired[index] = entry.take().map(|session| (session,
                        if denied && error == -(kernel::bindings::ECONNRESET as i32) { -(kernel::bindings::EACCES as i32) } else { error }));
                }
            }
        }
        for (session, error) in retired.into_iter().flatten() {
            // SAFETY: table reference retains object; stop joins work before put.
            unsafe { sl_connection_session_stop(session.pointer, error) };
        }
        // Birth follows the canonical physical link, not first application fd.
        // Snapshot under Host/gate; allocate outside locks and recheck at adoption.
        let (links, epoch) = {
            let host = self.host.lock();
            let (_, known, links) = host.link_snapshot();
            let gate = self.schedule_gate.lock();
            if *gate || !known || !host.admits_data() || host.controller_status().2.is_some()
                || !self.transport_open.load(Ordering::Acquire) { return; }
            (links, host.grants.current_epoch())
        };
        let Some(epoch) = epoch else { return; };
        for link in links.into_iter().flatten() {
            if let Ok(session) = self.acquire_session(link.lifetime, link.handle, epoch) {
                // SAFETY: birth owns only table ref; release transient actor ref.
                unsafe { sl_connection_session_put(session) };
            }
        }
    }
    pub(crate) fn stop_sessions(&self, error: i32) {
        let retired = {
            let mut table = self.sessions.lock();
            core::mem::replace(&mut *table, [const { None }; 16])
        };
        for session in retired.into_iter().flatten() {
            // SAFETY: no table/Host/lifecycle guard; queued/in-flight work joins.
            unsafe { sl_connection_session_stop(session.pointer, error) };
        }
    }
}
#[no_mangle]
pub(crate) unsafe extern "C" fn sparklink_native_session_status_rust(
    id: u16, generation: u64, lifetime: u64, handle: u16, epoch: u64,
) -> i32 {
    let Some(owner) = super::sle_ingress::ingress_owner(super::sle_dev::DeviceIdentity { id, generation }) else { return ENODEV.to_errno(); };
    owner.session_limits(lifetime, handle, epoch, None).map_or_else(|error| error.to_errno(), |_| 0)
}
#[no_mangle]
pub(crate) unsafe extern "C" fn sparklink_native_session_get_rust(
    id: u16, generation: u64, lifetime: u64, handle: u16, epoch: u64, error: *mut i32,
) -> *mut c_void {
    if error.is_null() { return core::ptr::null_mut(); }
    let result = (|| -> Result<*mut c_void> {
        let owner = super::sle_ingress::ingress_owner(super::sle_dev::DeviceIdentity { id, generation }).ok_or(ENODEV)?;
        owner.acquire_session(lifetime, handle, epoch)
    })();
    match result {
        Ok(pointer) => { unsafe { *error = 0 }; pointer }
        Err(reason) => { unsafe { *error = reason.to_errno() }; core::ptr::null_mut() }
    }
}

/// Software admission shares the Host epoch lock with revoke, then Session lock
/// with fd close. Callback only transfers a prepared skb into a bounded queue.
#[no_mangle]
pub(crate) unsafe extern "C" fn sparklink_native_session_admit_rust(
    id: u16, generation: u64, lifetime: u64, handle: u16, epoch: u64,
    admit: Option<unsafe extern "C" fn(*mut c_void) -> i32>, context: *mut c_void,
) -> i32 {
    let Some(admit) = admit else { return EINVAL.to_errno(); };
    if context.is_null() { return EINVAL.to_errno(); }
    let Some(owner) = super::sle_ingress::ingress_owner(super::sle_dev::DeviceIdentity { id, generation }) else { return ENODEV.to_errno(); };
    owner.session_limits(lifetime, handle, epoch, Some((admit, context))).map_or_else(|error| error.to_errno(), |_| 0)
}
