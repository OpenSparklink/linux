// SPDX-License-Identifier: GPL-2.0

//! SparkLink (NearLink) protocol stack core.
//!
//! This module implements the SparkLink Controller Interface (SCI) framework
//! and provides device management, discovery, and control plane functionality
//! for the SparkLink short-range wireless communication system.
//!
//! The architecture follows a layered design aligned with the SparkLink
//! standard (T/XS 10002-2025, T/XS 20001-2025):
//!
//!   - SCI Core: Device lifecycle, registration, global device list
//!   - Discovery: Device discovery with discovery levels and filtering
//!   - Transport: Async/sync data link management
//!   - Security: SM2/SM3/SM4 pairing and encryption (future)

mod sle_backend;
mod sle_authorization;
mod sle_management;
mod sle_grant;
mod sle_configfs;
mod sle_command_plan;
mod sle_discovery_operation;
mod sle_connection_operation;
mod sle_command_queue;
mod sle_controller_event;
mod sle_dev;
mod sle_dli;
mod sle_host;
mod sle_irq_lock;
mod sle_ingress;
mod sle_mgmt;
mod sle_link_observation;
mod sle_native;
mod sle_sessions;
mod sle_security_relay;
mod sle_security_relay_state;
mod sle_pair_material;
mod sle_data_credit;
mod sle_native_data;
mod sle_snoop;
mod sle_uapi;
mod sle_standard_dli;
mod sle_workers;

use sle_dli::SleController;
use sle_uapi::*;
use sle_irq_lock::{IrqLockBackend, new_irq_lock};
use kernel::sync::lock::Lock;
use kernel::workqueue::{DelayedWork, new_delayed_work};

use kernel::configfs_attrs;
use kernel::sync::atomic::Relaxed;
use kernel::sync::Arc;
use kernel::{
    bindings, configfs,
    debugfs::{Dir, File},
    device::Device,
    fs::{File as FsFile, Kiocb},
    iov::IovIterDest,
    miscdevice::{MiscDevice, MiscDeviceOptions, MiscDeviceRegistration},
    new_mutex, new_poll_condvar,
    prelude::*,
    str::CString,
    sync::{
        aref::ARef,
        atomic::Atomic,
        poll::{PollCondVar, PollTable},
        Mutex,
    },
    transmute::FromBytes,
    uaccess::{UserPtr, UserSlice},
};


// ---------------------------------------------------------------------------
// Userspace read/write helpers for repr(C) ioctl structures
// ---------------------------------------------------------------------------

/// Read a repr(C) struct from userspace.
///
/// # Safety requirement on T
///
/// `T` must be `repr(C)` with only primitive fields so that every bit
/// pattern produced by FromBytes is valid.
///
/// All padding/reserved fields are checked for zero per kernel UAPI
/// guidelines (Documentation/process/botching-up-ioctls.rst).
fn read_user_struct<T: FromBytes + Sized + CheckReserved>(arg: usize) -> Result<T> {
    let slice = UserSlice::new(UserPtr::from_addr(arg), core::mem::size_of::<T>());
    let mut reader = slice.reader();
    let val: T = reader.read()?;
    val.check_reserved()?;
    Ok(val)
}

/// Write a repr(C) struct to userspace.
///
/// `T` must be `repr(C)` with only primitive fields and fully initialized
/// (typically via `core::mem::zeroed()` followed by field assignments) so
/// that converting it to a byte slice is defined behaviour.
fn write_user_struct<T: Sized>(arg: usize, val: &T) -> Result {
    // SAFETY: T is repr(C) with only primitive fields, caller guarantees
    // the value is fully initialized.
    let bytes = unsafe {
        core::slice::from_raw_parts(
            core::ptr::from_ref::<T>(val).cast::<u8>(),
            core::mem::size_of::<T>(),
        )
    };
    let slice = UserSlice::new(UserPtr::from_addr(arg), core::mem::size_of::<T>());
    slice.writer().write_slice(bytes)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Global device counter (shared with C genetlink code via FFI)
// ---------------------------------------------------------------------------

/// Return the number of registered SparkLink devices (C FFI export).
#[no_mangle]
pub extern "C" fn sparklink_genl_get_dev_count() -> u32 {
    let ss = SUBSYSTEM.lock();
    match ss.as_ref() {
        Some(shared) => shared.dev_registry.count() as u32,
        None => 0,
    }
}

/// Return the protocol stack version as a packed u32 (C FFI export).
#[no_mangle]
pub extern "C" fn sparklink_genl_get_proto_version() -> u32 {
    0x000300 // v0.3.0
}

// ---------------------------------------------------------------------------
// Generic Netlink C bridge (conditional on CONFIG_SPARKLINK_GENL)
// ---------------------------------------------------------------------------

#[cfg(CONFIG_SPARKLINK_GENL)]
mod genl_bridge {
    extern "C" {
        pub(crate) fn sparklink_genl_register() -> core::ffi::c_int;
        pub(crate) fn sparklink_genl_unregister();
    }

    pub(crate) struct GenlGuard;

    impl GenlGuard {
        pub(crate) fn new() -> kernel::error::Result<Self> {
            // SAFETY: sparklink_genl_register is defined in sparklink_genl.c
            let ret = unsafe { sparklink_genl_register() };
            if ret != 0 {
                return Err(kernel::error::Error::from_errno(ret));
            }
            Ok(Self)
        }
    }

    impl Drop for GenlGuard {
        fn drop(&mut self) {
            // SAFETY: sparklink_genl_unregister is defined in sparklink_genl.c
            unsafe {
                sparklink_genl_unregister();
            }
        }
    }


}

#[cfg(not(CONFIG_SPARKLINK_GENL))]
mod genl_bridge {
    pub(crate) struct GenlGuard;

    impl GenlGuard {
        pub(crate) fn new() -> kernel::error::Result<Self> {
            Ok(Self)
        }
    }


}

// ---------------------------------------------------------------------------
// Global shared subsystem state
// ---------------------------------------------------------------------------
// Each registered controller owns a heap-allocated Runtime for its lifetime.
// Selection changes only an index; protocol state is never copied or swapped.
// Protocol operations use each owner's mutex; the registry lock protects metadata only.

kernel::sync::global_lock! {
    // SAFETY: Initialized in module_init before any MiscDevice open() call.
    pub(crate) unsafe(uninit) static SUBSYSTEM: Mutex<Option<KBox<SubsystemShared>>> = None;
}

/// Number of currently open file descriptors.
static OPEN_FD_COUNT: kernel::sync::atomic::Atomic<u32> = kernel::sync::atomic::Atomic::new(0);

/// DLI event ring size (events consumed from controller by EventPump).

/// Protocol state owned by one controller for its entire registration lifetime.
///
/// Constructed directly on the heap: the combined state is too large for the
/// kernel stack. Queues and privacy state belong to the same owner as its backend.
pub(crate) struct ControllerState {
    pub(crate) identity: sle_dev::DeviceIdentity,
    pub(crate) dev_info: SciDevInfo,
    pub(crate) controller: sle_dli::ControllerBackend,
    pub(crate) cmd_pending: sle_mgmt::CmdPendingQueue,
}

impl ControllerState {
    #[inline(never)]
    pub(crate) fn new_boxed(_addr: [u8; 6], backend: sle_dli::ControllerBackend) -> Result<KBox<Self>> {
        KBox::init(
            init!(ControllerState {
                identity: sle_dev::DeviceIdentity { id: u16::MAX, generation: 0 },
                dev_info: unsafe { core::mem::zeroed() },
                controller: backend,
                cmd_pending <- sle_mgmt::CmdPendingQueue::new_in_place(),
            }),
            GFP_KERNEL,
        )
    }





}

/// Stable registration owner. Registry lookup clones this Arc and releases the
/// registry lock before protocol access. Removal empties `state`, so a retained
/// fd or worker reference cannot follow a reused registry index.
#[pin_data]
pub(crate) struct ControllerRuntime {
    pub(crate) identity: sle_dev::DeviceIdentity,
    pub(crate) protocol_profile: u32,
    #[pin]
    management: Mutex<sle_management::Management>,
    #[pin]
    pub(crate) controller_events: Lock<KBox<sle_controller_event::ControllerEventLog>, IrqLockBackend>,
    #[pin]
    pub(crate) controller_event_poll: PollCondVar,
    #[pin]
    pub(crate) snoop: Lock<KBox<sle_snoop::SnoopLog>, IrqLockBackend>,
    #[pin]
    pub(crate) snoop_poll: PollCondVar,
    #[pin]
    pub(crate) state: Mutex<Option<KBox<ControllerState>>>,
    /// Serializes Backend open against teardown, never protocol observation.
    #[pin]
    pub(crate) native_lifecycle: Mutex<()>,
    pub(crate) transport_open: core::sync::atomic::AtomicBool,
    #[pin]
    pub(crate) ingress: Lock<KBox<sle_dli::ControllerEventRing>, IrqLockBackend>,
    #[pin]
    pub(crate) host: Lock<KBox<sle_host::CommandHost>, IrqLockBackend>,
    #[pin]
    pub(crate) data: Lock<sle_native_data::NativeData, IrqLockBackend>,
    #[pin]
    pub(crate) data_poll: PollCondVar,
    #[pin]
    pub(crate) sessions: Mutex<[Option<sle_sessions::Session>; 16]>,
    /// Coalesced data hint only; actual state remains protected by its locks.
    pub(crate) session_data_pending: core::sync::atomic::AtomicBool,
    #[pin]
    pub(crate) rx_work: DelayedWork<ControllerRuntime, 0>,
    #[pin]
    pub(crate) tx_work: DelayedWork<ControllerRuntime, 1>,
    #[pin]
    pub(crate) schedule_gate: Lock<bool, IrqLockBackend>,
    pub(crate) fast_poll_remaining: core::sync::atomic::AtomicU32,
    pub(crate) dropped_commands: core::sync::atomic::AtomicU32,
    pub(crate) dropped_mac: core::sync::atomic::AtomicU32,
    pub(crate) dropped_decode: core::sync::atomic::AtomicU32,
}

/// Owned registration snapshot. Allocation and candidate destruction must not
/// borrow the registry or invoke transport callbacks while holding its mutex.
#[derive(Clone, Copy)]
struct RuntimeRegistration {
    identity: sle_dev::DeviceIdentity,
    bus: sle_dli::SleBus,
    addr: [u8; 6],
    name: [u8; 32],
}

impl ControllerRuntime {
    fn new(registration: RuntimeRegistration, mut state: KBox<ControllerState>, initial_command_credits: u8) -> Result<Arc<Self>> {
        state.identity = registration.identity;
        state.dev_info.index = registration.identity.id;
        state.dev_info.bus = registration.bus as u8;
        state.dev_info.addr = SleAddr { b: registration.addr };
        let len = registration.name.len().min(state.dev_info.name.len());
        state.dev_info.name[..len].copy_from_slice(&registration.name[..len]);
        let ingress = sle_dli::ControllerEventRing::new_boxed()?;
        let host = sle_host::CommandHost::new_boxed(initial_command_credits)?;
        let controller_events = sle_controller_event::ControllerEventLog::new_boxed()?;
        let snoop = sle_snoop::SnoopLog::new_boxed()?;
        let protocol_profile = state.controller.provider().profile();
        let (data_length, data_count) = state.controller.provider().data_limits();
        Arc::pin_init(pin_init!(Self {
            identity: registration.identity,
            protocol_profile,
            management <- new_mutex!(sle_management::Management::new(), "sparklink_management"),
            controller_events <- new_irq_lock!(controller_events, "sparklink_controller_events"),
            controller_event_poll <- new_poll_condvar!("sparklink_controller_event"),
            snoop <- new_irq_lock!(snoop, "sparklink_snoop"),
            snoop_poll <- new_poll_condvar!("sparklink_snoop_poll"),
            state <- new_mutex!(Some(state), "sparklink_runtime"),
            native_lifecycle <- new_mutex!((), "sparklink_native_lifecycle"),
            transport_open: core::sync::atomic::AtomicBool::new(false),
            ingress <- new_irq_lock!(ingress, "sparklink_runtime_rx"),
            host <- new_irq_lock!(host, "sparklink_runtime_host"),
            data <- new_irq_lock!(sle_native_data::NativeData::new(data_length, data_count), "sparklink_runtime_data"),
            data_poll <- new_poll_condvar!("sparklink_native_data"),
            sessions <- new_mutex!([const { None }; 16], "sparklink_sessions"),
            session_data_pending: core::sync::atomic::AtomicBool::new(false),
            rx_work <- new_delayed_work!("sparklink_runtime_rx_work"),
            tx_work <- new_delayed_work!("sparklink_runtime_tx_work"),
            schedule_gate <- new_irq_lock!(false, "sparklink_runtime_schedule"),
            fast_poll_remaining: core::sync::atomic::AtomicU32::new(0),
            dropped_commands: core::sync::atomic::AtomicU32::new(0),
            dropped_mac: core::sync::atomic::AtomicU32::new(0),
            dropped_decode: core::sync::atomic::AtomicU32::new(0),
        }), GFP_KERNEL)
    }

    /// Called in process context without the registry lock. In-flight protocol
    /// operations finish before invalidation; subsequent accesses get ENODEV.
    pub(crate) fn invalidate(self: &Arc<Self>) {
        // Close admission before waiting for a driver's blocking open. Its
        // eventual success may acquire resources, but cannot admit commands.
        *self.schedule_gate.lock() = true;
        self.transport_open.store(false, core::sync::atomic::Ordering::Release);
        // Observers must learn retirement while open/transport joins are still
        // pending. Poll registers first and rechecks the closed admission gate.
        self.controller_event_poll.notify_all();
        self.snoop_poll.notify_all();
        self.data_poll.notify_all();
        // A transaction may be faulting while copying its candidate lease.
        // Observers must not wait for that management mutex either.
        self.management.lock().settled(ENODEV.to_errno());
        // Session workers can wait for native_lifecycle. Join BEFORE taking it.
        self.stop_sessions(ENODEV.to_errno());
        let _lifecycle = self.native_lifecycle.lock();
        sle_ingress::unpublish_runtime(self);
        self.stop_workers();
        let state = self.state.lock().take();
        if let Some(state) = state {
            state.controller.close();
        }
        self.controller_event_poll.notify_all();
        self.snoop_poll.notify_all();
    }
}

/// Global registration metadata only; protocol access requires a File binding.
pub(crate) struct SubsystemShared {
    runtimes: [Option<Arc<ControllerRuntime>>; sle_dev::SLE_DEV_MAX],
    pub(crate) dev_registry: sle_dev::SleDevRegistry,
}

struct RuntimeContext {
    owner: Option<Arc<ControllerRuntime>>,
}

impl RuntimeContext {


    fn from_owner(owner: Arc<ControllerRuntime>) -> Self {
        Self { owner: Some(owner) }
    }

    fn lock(&self) -> Result<kernel::sync::lock::Guard<'_, Option<KBox<ControllerState>>, kernel::sync::lock::mutex::MutexBackend>> {
        let owner = self.owner.as_ref().ok_or(ENODEV)?;
        let guard = owner.state.lock();
        if guard.is_none() || *owner.schedule_gate.lock() { return Err(ENODEV); }
        Ok(guard)
    }
}

impl SubsystemShared {
    pub(crate) fn runtime(&self, id: u16) -> Option<Arc<ControllerRuntime>> {
        self.runtimes.get(id as usize)?.clone()
    }



}

pub(crate) fn runtime_snapshot() -> [Option<Arc<ControllerRuntime>>; sle_dev::SLE_DEV_MAX] {
    let ss = SUBSYSTEM.lock();
    core::array::from_fn(|id| ss.as_ref().and_then(|s| s.runtime(id as u16)))
}


/// Stop protocol operations and workers before the transport frees resources.
/// The registry keeps the index reserved until the transport joins its URBs.

// ---------------------------------------------------------------------------
// Transport device attach / detach (called from driver probe/remove)
// ---------------------------------------------------------------------------

/// One reservation allocator for actual providers. Metadata may be unknown;
/// registration reserves identity only, never Runtime/open/Ready.

pub(crate) fn reserve_backend_identity_profile(info: &sle_dli::SleControllerInfo, profile: u32) -> Result<sle_dev::DeviceIdentity> {
    let mut registry = SUBSYSTEM.lock();
    let shared = registry.as_mut().ok_or(ENODEV)?;
    let id = shared.dev_registry.register_pending(info)?;
    let dev = shared.dev_registry.get_mut(id).ok_or(ENODEV)?;
    dev.pending_profile = profile;
    Ok(dev.identity())
}

/// Validate a borrowed pending identity before adopting queried metadata.
/// Bus/profile are reservation provenance, not inferred from a reusable index.
pub(crate) fn validate_backend_reservation(identity: sle_dev::DeviceIdentity, bus: sle_dli::SleBus, profile: u32) -> Result {
    let registry = SUBSYSTEM.lock();
    let shared = registry.as_ref().ok_or(ENODEV)?;
    let dev = shared.dev_registry.get(identity.id).ok_or(ENODEV)?;
    if dev.identity() != identity || dev.test_flag(sle_dev::SLE_DEV_UNREGISTERING) { return Err(ENODEV); }
    if dev.bus() != bus || dev.pending_profile != profile { return Err(EINVAL); }
    if shared.runtime(identity.id).is_some() { return Err(EBUSY); }
    Ok(())
}

pub(crate) fn update_backend_pending(identity: sle_dev::DeviceIdentity, phase: u32, error: i32) -> Result {
    if error > 0 { return Err(EINVAL); }
    let mut registry = SUBSYSTEM.lock();
    let shared = registry.as_mut().ok_or(ENODEV)?;
    let dev = shared.dev_registry.get(identity.id).ok_or(ENODEV)?;
    if dev.identity() != identity || dev.test_flag(sle_dev::SLE_DEV_UNREGISTERING) { return Err(ENODEV); }
    if shared.runtime(identity.id).is_some() { return Err(EBUSY); }
    let dev = shared.dev_registry.get_mut(identity.id).ok_or(ENODEV)?;
    dev.pending_phase = phase;
    dev.pending_error = error;
    Ok(())
}

pub(crate) fn query_backend_pending(identity: sle_dev::DeviceIdentity) -> Result<(sle_dli::SleBus, u32, u32, i32)> {
    let registry = SUBSYSTEM.lock();
    let shared = registry.as_ref().ok_or(ENODEV)?;
    let dev = shared.dev_registry.get(identity.id).ok_or(ENODEV)?;
    if dev.identity() != identity || dev.test_flag(sle_dev::SLE_DEV_UNREGISTERING) { return Err(ENODEV); }
    if shared.runtime(identity.id).is_some() { return Err(EBUSY); }
    Ok((dev.bus(), dev.pending_profile, dev.pending_phase, dev.pending_error))
}

/// Linearizes at the Core registry lock. No Host/driver lock, allocation or I/O
/// is needed; Installed deliberately makes no statement about Host Ready.
pub(crate) fn snapshot_backend_registration(id: u16, generation: u64) -> Result<SleRegistrationSnapshot> {
    let registry = SUBSYSTEM.lock();
    let shared = registry.as_ref().ok_or(ENODEV)?;
    let dev = shared.dev_registry.get(id).ok_or(ENODEV)?;
    if generation != 0 && generation != dev.identity().generation { return Err(ENODEV); }
    let mut out: SleRegistrationSnapshot = unsafe { core::mem::zeroed() };
    out.version = 1;
    out.generation = dev.identity().generation;
    out.dev_index = id;
    out.bus = dev.bus() as u8;
    out.profile = dev.pending_profile;
    out.state = if dev.test_flag(sle_dev::SLE_DEV_UNREGISTERING) {
        REGISTRATION_RETIRING
    } else if let Some(owner) = shared.runtime(id) {
        if owner.identity != dev.identity() { return Err(EIO); }
        REGISTRATION_INSTALLED
    } else {
        out.phase = dev.pending_phase;
        out.error = dev.pending_error;
        if out.error < 0 { REGISTRATION_FAULT } else { REGISTRATION_PENDING }
    };
    Ok(out)
}

fn ioctl_registration_snapshot(arg: usize) -> Result<isize> {
    let input: SleRegistrationSnapshot = read_user_struct(arg)?;
    if input.version != 1 { return Err(Error::from_errno(-(bindings::EOPNOTSUPP as i32))); }
    if input.dev_index >= 16 || input.state != 0 || input.profile != 0 || input.phase != 0
        || input.error != 0 || input.bus != 0 { return Err(EINVAL); }
    let out = snapshot_backend_registration(input.dev_index, input.generation)?;
    // Copy outside the registry lock. The returned generation identifies the
    // observation even if removal/reuse happens while copy_to_user sleeps.
    write_user_struct(arg, &out)?;
    Ok(0)
}

/// Cancel only an uninstalled exact reservation. Never discard an installed
/// Runtime or release the identity of a concurrent retiring owner.
pub(crate) fn cancel_backend_reservation(identity: sle_dev::DeviceIdentity) {
    let mut registry = SUBSYSTEM.lock();
    let Some(shared) = registry.as_mut() else { return };
    if shared.runtime(identity.id).is_none() && shared.dev_registry.get(identity.id).is_some_and(|dev|
        dev.identity() == identity && !dev.test_flag(sle_dev::SLE_DEV_UNREGISTERING)) {
        let _ = shared.dev_registry.unregister(identity.id);
    }
}

/// Construct a candidate outside the registry lock, then publish against the
/// same reserved identity. A competing install/retire/reuse wins cleanly;
/// failed candidates drop after the registry guard, with no lock across I/O.
pub(crate) fn install_backend_runtime(
    identity: sle_dev::DeviceIdentity, state: KBox<ControllerState>, initial_command_credits: u8,
    queried: Option<([u8; 6], u32)>,
) -> Result<Arc<ControllerRuntime>> {
    let registration = {
        let registry = SUBSYSTEM.lock();
        let shared = registry.as_ref().ok_or(ENODEV)?;
        let dev = shared.dev_registry.get(identity.id).ok_or(ENODEV)?;
        if dev.identity() != identity || dev.test_flag(sle_dev::SLE_DEV_UNREGISTERING) { return Err(ENODEV); }
        if shared.runtime(identity.id).is_some() { return Err(EBUSY); }
        let mut name = [0; 32];
        let len = dev.name().len().min(name.len());
        name[..len].copy_from_slice(&dev.name()[..len]);
        RuntimeRegistration { identity, bus: dev.bus(),
            addr: queried.map_or(*dev.addr(), |info| info.0), name }
    };
    let owner = ControllerRuntime::new(registration, state, initial_command_credits)?;
    {
        let mut registry = SUBSYSTEM.lock();
        let shared = registry.as_mut().ok_or(ENODEV)?;
        let dev = shared.dev_registry.get(identity.id).ok_or(ENODEV)?;
        if dev.identity() != identity || dev.test_flag(sle_dev::SLE_DEV_UNREGISTERING) { return Err(ENODEV); }
        let slot = shared.runtimes.get_mut(identity.id as usize).ok_or(EINVAL)?;
        if slot.is_some() { return Err(EBUSY); }
        *slot = Some(owner.clone());
        if let Some((addr, version)) = queried { shared.dev_registry.update_hw_info(identity.id, addr, version); }
    }
    Ok(owner)
}

/// Reserve one exact identity before standard USB resources/bootstrap exist.
/// Unknown address/capabilities stay zero; no Runtime or Ready is published.

/// Detach a device from the subsystem.
///
/// Called from registered USB disconnect or module unload cleanup.
/// Removes the exact Runtime and unregisters its reserved SleDev. If the
/// device was the active one, reverts to the no-controller state.  If it
/// was inactive, its saved state is discarded.
pub(crate) fn sle_detach_device(identity: sle_dev::DeviceIdentity) {
    let dev_id = identity.id;
    let owner = {
        let mut guard = SUBSYSTEM.lock();
        let Some(ss) = Option::as_mut(&mut *guard) else { return };
        let Some(dev) = ss.dev_registry.get(dev_id) else { return };
        if dev.identity() != identity || dev.test_flag(sle_dev::SLE_DEV_UNREGISTERING) { return; }
        // Reserve the retiring identity until joined cleanup finishes. A
        // duplicate detach cannot free the index while this owner is draining.
        dev.begin_unregister();
        ss.runtimes.get_mut(dev_id as usize).and_then(Option::take)
    };
    if let Some(owner) = owner { owner.invalidate(); }
    let mut guard = SUBSYSTEM.lock();
    if let Some(ss) = Option::as_mut(&mut *guard) {
        if ss.dev_registry.get(dev_id).is_some_and(|dev| dev.identity() == identity) {
            let _ = ss.dev_registry.unregister(dev_id);
            pr_info!("sparklink: device sle{} detached\n", dev_id);
        }
    }
}

// ---------------------------------------------------------------------------
// Unified control plane operations (shared by ioctl + genetlink)
// ---------------------------------------------------------------------------

/// Start advertising / broadcast with the given interval.


/// Stop advertising / broadcast.


/// Start scanning with the given window and interval.


/// Stop scanning.


// ---------------------------------------------------------------------------
// C FFI exports for genetlink action commands
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Module definition
// ---------------------------------------------------------------------------

/// Guard that tears down the shared subsystem when the module is unloaded.
struct SubsystemGuard;

impl Drop for SubsystemGuard {
    fn drop(&mut self) {
        // Stop/drain each owner after releasing the registry lock.
        let subsystem = SUBSYSTEM.lock().take();
        if let Some(mut shared) = subsystem {
            for id in 0..sle_dev::SLE_DEV_MAX as u16 {
                if let Some(runtime) = shared.runtime(id) { runtime.invalidate(); }
                let _ = shared.dev_registry.unregister(id);
            }
        }
        pr_info!("sparklink: shared subsystem destroyed (module unload)\n");
    }
}

module! {
    type: SparkLinkModule,
    name: "sparklink",
    authors: ["SparkLink for Linux Contributors"],
    description: "SparkLink (NearLink) wireless communication subsystem",
    license: "GPL",
}

// ---------------------------------------------------------------------------
// debugfs observability layer — heap-allocated to avoid kernel stack overflow
// ---------------------------------------------------------------------------
#[pin_data]
struct DebugfsHolder {
    _debugfs: Dir,
    #[pin]
    _version: File<CString>,
    #[pin]
    _build_info: File<CString>,
    #[pin]
    _subsystems: File<CString>,
    #[pin]
    _dli_info: File<CString>,
    _mgmt_dir: Dir,
    #[pin]
    _mgmt_stats: File<CString>,
    _transport_dir: Dir,
    #[pin]
    _transport_info: File<Atomic<u32>>,
    _power_dir: Dir,
    #[pin]
    _power_stats: File<CString>,
    _conn_dir: Dir,
    #[pin]
    _conn_stats: File<CString>,
    #[pin]
    _device_list: File<Atomic<u32>>,
}

#[pin_data]
struct SparkLinkModule {
    _channel: ChannelGuard,
    #[pin]
    _miscdev: MiscDeviceRegistration<SparkLinkCtl>,
    _debugfs_holder: Pin<KBox<DebugfsHolder>>,
    _genl: genl_bridge::GenlGuard,
    #[pin]
    _configfs: configfs::Subsystem<sle_configfs::SparkLinkConfig>,
    /// Dropped LAST — after _miscdev closes all fds.
    _subsystem_guard: SubsystemGuard,
}

#[inline(never)]
fn init_version_string() -> Result<CString> {
    CString::try_from_fmt(fmt!("sparklink 0.3.0"))
}

#[inline(never)]
fn init_build_string() -> Result<CString> {
    CString::try_from_fmt(fmt!("sparklink subsystem\nstandard: T/XS 10002-2025, T/XS 20001-2025, T/XS 10003-2025\nmodules: core Host Session Channel crypto security dli; Native events; registry-only genl\nlanguage: Rust"))
}

#[inline(never)]
fn init_subsys_string() -> Result<CString> {
    CString::try_from_fmt(fmt!("Native Host/Session/Channel: discovery, physical links, data\nSecurity/RPA: unsupported pending per-connection mechanism\nPM: unsupported hardware control\nsle_dli: driver layer interface\nsle_standard_dli: standard DLI codec\nsparklink_genl: C Generic Netlink bridge"))
}

#[inline(never)]
fn init_debugfs() -> Result<Pin<KBox<DebugfsHolder>>> {
    let ver = init_version_string()?;
    let build = init_build_string()?;
    let subsys = init_subsys_string()?;
    let unavailable_connection_stats = CString::try_from_fmt(fmt!("legacy model retired: use identity-bound LinkSnapshot\n"))?;
    let unsupported_pm = CString::try_from_fmt(fmt!("unsupported: no qualified hardware PM snapshot\n"))?;

    let debugfs = Dir::new(c"sparklink");
    let mgmt_dir = debugfs.subdir(c"mgmt");
    let transport_dir = debugfs.subdir(c"transport");
    let power_dir = debugfs.subdir(c"power");
    let conn_dir = debugfs.subdir(c"connections");
    let unavailable_default_dli = CString::try_from_fmt(fmt!("legacy default projection retired: use selected ControllerSnapshot\n"))?;
    let unavailable_default_mgmt = CString::try_from_fmt(fmt!("legacy queue projection retired: use selected Native diagnostic result\n"))?;

    KBox::pin_init(
        pin_init!(DebugfsHolder {
            _version <- debugfs.read_only_file(c"version", ver),
            _build_info <- debugfs.read_only_file(c"build_info", build),
            _subsystems <- debugfs.read_only_file(c"subsystems", subsys),
            _dli_info <- debugfs.read_only_file(c"dli_controller", unavailable_default_dli),
            _mgmt_stats <- mgmt_dir.read_only_file(c"stats", unavailable_default_mgmt),
            _mgmt_dir: mgmt_dir,
            _transport_info <- transport_dir.read_callback_file(
                c"info",
                Atomic::<u32>::new(0),
                &|_dummy: &Atomic<u32>, f: &mut core::fmt::Formatter<'_>| {
                    let ss = SUBSYSTEM.lock();
                    if let Some(ref ss) = *ss {
                        writeln!(f, "identities_reserved: {}", ss.dev_registry.count())?;
                        writeln!(f, "runtimes_installed: {}", ss.runtimes.iter().flatten().count())?;
                    }
                    Ok(())
                },
            ),
            _transport_dir: transport_dir,
            _power_stats <- power_dir.read_only_file(c"stats", unsupported_pm),
            _power_dir: power_dir,
            _conn_stats <- conn_dir.read_only_file(c"stats", unavailable_connection_stats),
            _conn_dir: conn_dir,
            _device_list <- debugfs.read_callback_file(
                c"devices",
                Atomic::<u32>::new(0),
                &|_dummy: &Atomic<u32>, f: &mut core::fmt::Formatter<'_>| {
                    let ss = SUBSYSTEM.lock();
                    if let Some(ref ss) = *ss {
                        writeln!(f, "registered: {}", ss.dev_registry.count())?;
                        for dev in ss.dev_registry.iter() {
                            let name_end = dev.name.iter().position(|&b| b == 0)
                                .unwrap_or(dev.name.len());
                            let name_str = core::str::from_utf8(&dev.name[..name_end])
                                .unwrap_or("?");
                            writeln!(f, "  sle{}: {} bus={:?} addr={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} flags=0x{:08x}",
                                dev.id, name_str, dev.bus,
                                dev.addr[0], dev.addr[1], dev.addr[2],
                                dev.addr[3], dev.addr[4], dev.addr[5],
                                dev.flags())?;
                        }
                    }
                    Ok(())
                },
            ),
            _debugfs: debugfs,
        }),
        GFP_KERNEL,
    )
}

extern "C" {
    fn sl_channel_socket_init() -> i32;
    fn sl_channel_socket_exit();
}
struct ChannelGuard;
impl ChannelGuard {
    fn new() -> Result<Self> {
        // SAFETY: once-only core initialization; C owns family registration.
        let result = unsafe { sl_channel_socket_init() };
        if result < 0 { Err(Error::from_errno(result)) } else { Ok(Self) }
    }
}
impl Drop for ChannelGuard {
    fn drop(&mut self) {
        let owners = {
            let shared = SUBSYSTEM.lock();
            core::array::from_fn::<_, {sle_dev::SLE_DEV_MAX}, _>(|index|
                shared.as_ref().and_then(|s| s.runtimes[index].clone()))
        };
        for owner in owners.into_iter().flatten() {
            owner.stop_sessions(ENODEV.to_errno());
        }
        // SAFETY: sessions/work have drained before protocol registration ends.
        unsafe { sl_channel_socket_exit() };
    }
}

impl kernel::InPlaceModule for SparkLinkModule {
    fn init(_module: &'static ThisModule) -> impl PinInit<Self, Error> {
        pr_info!("sparklink: initialising SparkLink subsystem v0.3.0\n");

        // SAFETY: Called exactly once during module init.
        unsafe { SUBSYSTEM.init() };
        // SAFETY: Called exactly once during module init.
        unsafe { sle_ingress::init_ingress_routes() };

        let options = MiscDeviceOptions { name: c"sparklink" };

        try_pin_init!(Self {
            _channel: ChannelGuard::new()?,
            _miscdev <- MiscDeviceRegistration::register(options),
            _debugfs_holder: init_debugfs()?,
            _genl: genl_bridge::GenlGuard::new()?,
            _configfs <- {
                use sle_configfs::SparkLinkConfig;
                let item_type = configfs_attrs! {
                    container: configfs::Subsystem<SparkLinkConfig>,
                    data: SparkLinkConfig,
                    attributes: [
                        version: 0,
                    ],
                };
                configfs::Subsystem::new(
                    c"sparklink",
                    item_type,
                    SparkLinkConfig::new(),
                )
            },
            _subsystem_guard: init_subsystem()?,
        })
    }
}

#[inline(never)]
fn init_subsystem() -> Result<SubsystemGuard> {
    let mut ss = SUBSYSTEM.lock();

    // Only a bus driver's successful registration can create a Runtime.
    // Module load creates no synthetic controller or protocol state.
    let dev_registry = sle_dev::SleDevRegistry::new();
    let runtimes = core::array::from_fn(|_| None);
    *ss = Some(KBox::init(
        init!(SubsystemShared {
            runtimes,
            dev_registry,
        }),
        GFP_KERNEL,
    )?);
    drop(ss);
    for owner in runtime_snapshot().iter().flatten() { owner.start_workers(); }
    pr_info!("sparklink: shared subsystem initialised\n");
    Ok(SubsystemGuard)
}

// ---------------------------------------------------------------------------
// Misc device implementation: /dev/sparklink control interface
// ---------------------------------------------------------------------------
// Each open fd gets its own event queue for per-listener event delivery.
// Fds share only the selected owner's protocol mutex; selection never moves state.

#[pin_data(PinnedDrop)]
struct SparkLinkCtl {
    file_id: u64,
    /// Per-open monotonic watermark survives bounded result eviction/selection.
    #[pin]
    diagnostic_request_id: Mutex<u64>,
    #[pin]
    connection_request_id: Mutex<u64>,
    #[pin]
    operation: Mutex<()>,
    #[pin]
    owned_target: Mutex<Option<Arc<ControllerRuntime>>>,
    dev: ARef<Device>,
    /// None follows legacy selection; Some pins a registration identity.
    /// Removal leaves the binding stale, so a reused index cannot retarget it.
    #[pin]
    target: Mutex<Option<Arc<ControllerRuntime>>>,
    #[pin]
    controller_subscription: Mutex<Option<sle_controller_event::Subscription>>,
    #[pin]
    snoop_subscription: Mutex<Option<sle_controller_event::Subscription>>,
}

/// Advertising, scanning, device management ioctl sub-dispatcher.
#[inline(never)]
fn ioctl_dispatch_adv(context: &RuntimeContext, _me: Pin<&SparkLinkCtl>, cmd: u32, arg: usize) -> Result<isize> {
    match cmd {
        SL_IOCTL_START_ADV
        | SL_IOCTL_STOP_ADV
        | SL_IOCTL_START_SCAN
        | SL_IOCTL_STOP_SCAN
        | SL_IOCTL_DEV_COUNT
        | SL_IOCTL_DEV_INFO
        | SL_IOCTL_DEV_SWITCH
        | SL_IOCTL_DEV_LIST
        | SL_IOCTL_SCAN_RESULT_COUNT
        | SL_IOCTL_SET_SCAN_FILTER
        | SL_IOCTL_CLEAR_SCAN_FILTER => ioctl_dispatch_adv_basic(context, cmd, arg),
        SL_IOCTL_EXT_ADV_CONFIGURE
        | SL_IOCTL_EXT_ADV_SET_DATA
        | SL_IOCTL_EXT_ADV_SET_SCAN_RSP
        | SL_IOCTL_EXT_ADV_ENABLE
        | SL_IOCTL_EXT_ADV_DISABLE
        | SL_IOCTL_EXT_ADV_REMOVE
        | SL_IOCTL_EXT_ADV_INFO
        | SL_IOCTL_EXT_ADV_ENABLE_EX
        | SL_IOCTL_EXT_ADV_TICK => Err(Error::from_errno(-(bindings::EOPNOTSUPP as i32))),
        SL_IOCTL_INJECT_ADV | SL_IOCTL_INJECT_RAW_ADV => Err(Error::from_errno(-(bindings::EOPNOTSUPP as i32))),
        _ => Err(EINVAL),
    }
}


/// DEV_SELECT ioctl — per-fd device affinity.
///
/// Nonnegative indices bind this File to one exact registration owner.
/// -1 clears this File binding; there is no implicit controller selection.
/// dup/fork share the same File binding. An owned lease prevents rebinding.
#[inline(never)]
fn ioctl_dev_select(me: Pin<&SparkLinkCtl>, arg: usize) -> Result<isize> {
    if me.owned_target.lock().is_some() { return Err(EBUSY); }
    let val: i16 = read_user_struct(arg)?;
    if val < -1 {
        return Err(EINVAL);
    }
    let identity = if val >= 0 {
        let ss = SUBSYSTEM.lock();
        let s = ss.as_ref().ok_or(ENODEV)?;
        Some(s.runtime(val as u16).ok_or(ENODEV)?)
    } else {
        None
    };
    *me.target.lock() = identity;
    *me.controller_subscription.lock() = None;
    *me.snoop_subscription.lock() = None;
    Ok(0)
}

/// DEV_GET_ACTIVE reports the binding even when it is stale after removal.
#[inline(never)]
fn ioctl_dev_get_active(me: Pin<&SparkLinkCtl>, arg: usize) -> Result<isize> {
    let target = me.target.lock().clone();
    let effective = match target {
        Some(owner) => owner.identity.id,
        None => u16::MAX,
    };
    write_user_struct(arg, &effective)?;
    Ok(0)
}

/// Basic adv/scan/dev ioctl sub-dispatcher.
#[inline(never)]
fn ioctl_dispatch_adv_basic(context: &RuntimeContext, cmd: u32, arg: usize) -> Result<isize> {
    match cmd {
        SL_IOCTL_START_ADV | SL_IOCTL_STOP_ADV | SL_IOCTL_START_SCAN | SL_IOCTL_STOP_SCAN
            => Err(Error::from_errno(-(bindings::EOPNOTSUPP as i32))),
        SL_IOCTL_DEV_COUNT => {
            let ss = SUBSYSTEM.lock();
            let count = ss.as_ref().map_or(0, |s| s.dev_registry.count());
            Ok(count as isize)
        }
        SL_IOCTL_DEV_INFO => {
            let ss = context.lock()?;
            let s = ss.as_ref().ok_or(ENODEV)?;
            let mut info = s.dev_info;
            // This legacy metadata ABI cannot represent Native readiness/radio state.
            // Current state comes from ControllerSnapshot/typed discovery results.
            info.state = 0xff;
            drop(ss);
            write_user_struct(arg, &info)?;
            Ok(0)
        }
        SL_IOCTL_DEV_SWITCH => Err(Error::from_errno(-(bindings::EOPNOTSUPP as i32))),
        SL_IOCTL_DEV_LIST => {
            let ss = SUBSYSTEM.lock();
            let s = ss.as_ref().ok_or(ENODEV)?;
            let mask = s.dev_registry.allocated_mask();
            drop(ss);
            write_user_struct(arg, &mask)?;
            Ok(0)
        }
        SL_IOCTL_SCAN_RESULT_COUNT | SL_IOCTL_SET_SCAN_FILTER | SL_IOCTL_CLEAR_SCAN_FILTER
            => Err(Error::from_errno(-(bindings::EOPNOTSUPP as i32))),
        _ => Err(EINVAL),
    }
}

/// Extended advertising ioctl sub-dispatcher.


/// Connection data send — isolated for stack safety (SleConnData = 260B + tx_buf = 256B).


/// Connection data receive — isolated for stack safety (2x SleConnData = 520B).

#[inline(never)]
fn ioctl_dispatch_conn(_context: &RuntimeContext, _me: Pin<&SparkLinkCtl>, cmd: u32, _arg: usize) -> Result<isize> {
    match cmd {
        SL_IOCTL_CONNECT
        | SL_IOCTL_DISCONNECT
        | SL_IOCTL_CONN_INFO
        | SL_IOCTL_CONN_SEND
        | SL_IOCTL_CONN_RECV
        | SL_IOCTL_INJECT_CONN_RESP
        | SL_IOCTL_INJECT_CONN_DATA
        | SL_IOCTL_CONN_COUNT
        | SL_IOCTL_CONN_LIST
        | SL_IOCTL_SET_CONN_MTU
        | SL_IOCTL_CONN_READ_PEER_FEATURES
        | SL_IOCTL_CONN_READ_PEER_VERSION
        | SL_IOCTL_CONN_UPDATE_PARAMS
        | SL_IOCTL_CONN_PHY_UPDATE => Err(Error::from_errno(-(bindings::EOPNOTSUPP as i32))),
        _ => Err(EINVAL),
    }
}


/// AFH ioctl sub-dispatcher (channel map, RSSI, hopping).


/// Unqualified legacy security/AFH controls cannot publish local success.
#[inline(never)]
fn ioctl_dispatch_security(_context: &RuntimeContext, _cmd: u32, _arg: usize) -> Result<isize> {
    Err(Error::from_errno(-(bindings::EOPNOTSUPP as i32)))
}

/// Sync link ioctl sub-dispatcher (separate stack frame for large structs).


/// Sync data send ioctl — isolated for stack safety (256+251 byte locals).
#[inline(never)]


fn management_error(error: sle_management::Failure) -> Error {
    match error {
        sle_management::Failure::Busy => EBUSY,
        sle_management::Failure::Permission => EPERM,
        sle_management::Failure::Overflow => EOVERFLOW,
        sle_management::Failure::Invalid => EINVAL,
    }
}

/// Called with management mutex held, in process context. No registry or IRQ
/// lock spans allocation, driver preparation, copyout or transport operations.
#[inline(never)]
fn revoke_management(owner: &Arc<ControllerRuntime>, gate: &mut sle_management::Management, mode: u32) {
    // Linearize withdrawal before waiting for process-context state/preparation.
    owner.host.lock().revoke_connections();
    let result = (|| -> Result {
        let mut state = owner.state.lock();
        let state = Option::as_mut(&mut *state).ok_or(ENODEV)?;
        if *owner.schedule_gate.lock() { return Err(ENODEV); }
        {
            let mut host = owner.host.lock();
            if let Some(error) = host.controller_status().2 { return Err(error); }
            // Preserve sent/accepted author procedures and physical facts.
            // Managed cleanup will prepare real Disconnects in process context;
            // Diagnostic cannot claim or clean another physical session.
            if mode == sle_management::MANAGED { host.validate_connection_cleanup()?; }
            if mode == sle_management::DIAGNOSTIC && !host.links_clear_for_management() {
                return Err(Error::from_errno(-(bindings::EOPNOTSUPP as i32)));
            }
            let (adv, scan, _) = host.discovery_radio();
            // The native raw whitelist contains queries only. A quiet diagnostic
            // reader has not changed radio policy. Managed can also release an
            // untouched Setup lease without sending a stop for a nonexistent
            // advertising handle. Selected or uncertain policy still requires
            // real cleanup; neither exception confirms Off nor sets Ready.
            if host.links_clear_for_management() && host.quiet() && (mode == sle_management::DIAGNOSTIC
                || (mode == sle_management::MANAGED
                    && ((adv == 1 && scan == 1) || host.policy_untouched()))) {
                gate.settled(0); return Ok(());
            }
            // Admission and state serialization exclude a concurrent submit
            // or TX selection. Cancel never-selected typed policy without a
            // stop for a handle that has not been configured; retain Unknown
            // and cancelled operation results, rather than synthesizing Ready.
            if mode == sle_management::MANAGED && host.links_clear_for_management() && host.cancel_unsubmitted_policy() {
                gate.settled(0); return Ok(());
            }
        }
        if owner.protocol_profile == 0 && mode == sle_management::DIAGNOSTIC {
            let mut host = owner.host.lock();
            if !host.query_policy_untouched() {
                return Err(Error::from_errno(-(bindings::EOPNOTSUPP as i32)));
            }
            while let Some(request) = host.cancel_next() {
                state.cmd_pending.cancel_seq(request.seq);
            }
            // No typed policy was submitted. Keep the active physical reply
            // and original deadline; Free waits for quiet or reports a fault.
            return host.begin_revoke(&[], &[]);
        }
        let controller = state.controller.provider();
        let request = SleDiscoverySubmit {
            version: 1, generation: owner.identity.generation,
            profile: owner.protocol_profile, operation: 2,
            // SAFETY: integer-only structure with a valid all-zero baseline.
            ..unsafe { core::mem::zeroed() }
        };
        let adv = controller.prepare_discovery(&request)?;
        let scan = controller.prepare_discovery(&SleDiscoverySubmit { operation: 4, ..request })?;
        let mut adv_parts = [sle_command_plan::RecipePart { opcode: 0, params: &[] }; 4];
        let mut scan_parts = [sle_command_plan::RecipePart { opcode: 0, params: &[] }; 4];
        for (i, step) in adv.steps[..adv.count as usize].iter().enumerate() {
            adv_parts[i] = sle_command_plan::RecipePart { opcode: step.opcode, params: &step.params[..step.length as usize] };
        }
        for (i, step) in scan.steps[..scan.count as usize].iter().enumerate() {
            scan_parts[i] = sle_command_plan::RecipePart { opcode: step.opcode, params: &step.params[..step.length as usize] };
        }
        let mut host = owner.host.lock();
        // Preserve the active reply reservation and its deadline. Only queued
        // work is cancelled; cleanup stops follow the outstanding wire slot.
        while let Some(request) = host.cancel_next() {
            state.cmd_pending.cancel_seq(request.seq);
        }
        host.begin_revoke(&adv_parts[..adv.count as usize], &scan_parts[..scan.count as usize])
    })();
    if let Err(error) = result {
        owner.host.lock().fail(error);
        gate.settled(error.to_errno());
    }
    owner.kick_commands();
    owner.schedule_rx(0);
}

#[inline(never)]
fn ioctl_management(context: &RuntimeContext, me: Pin<&SparkLinkCtl>, cmd: u32, arg: usize) -> Result<isize> {
    let owner = context.owner.as_ref().ok_or(ENODEV)?;
    if me.target.lock().as_ref().map(|target| target.identity) != Some(owner.identity) { return Err(EINVAL); }
    if owner.protocol_profile > 1 { return Err(Error::from_errno(-(bindings::EOPNOTSUPP as i32))); }
    if *owner.schedule_gate.lock() { return Err(ENODEV); }
    // Observation copies user input/output without the management mutex. Only
    // constructing its owned integer snapshot needs admission serialization.
    let query: Option<SleManagementQuery> = if cmd == SL_IOCTL_MANAGEMENT_QUERY {
        Some(read_user_struct(arg)?)
    } else { None };
    let mut gate = owner.management.lock();
    if *owner.schedule_gate.lock() { return Err(ENODEV); }
    if gate.state == sle_management::REVOKING {
        if let Some(result) = owner.host.lock().revocation_result() {
            gate.settled(result.err().map_or(0, |error| error.to_errno()));
        }
    }
    if let Some(input) = query {
        if input.version != 1 { return Err(Error::from_errno(-(bindings::EOPNOTSUPP as i32))); }
        if input.generation != 0 && input.generation != owner.identity.generation { return Err(ENODEV); }
        let detail = if gate.state == sle_management::FAULTED { owner.host.lock().revocation_detail() } else { (0, 0, false) };
        let output = SleManagementQuery {
            version: 1, generation: owner.identity.generation,
            lease: gate.token_for(me.file_id), mode: gate.mode, state: gate.state,
            flags: u32::from(gate.owns(me.file_id)) | (u32::from(detail.2) << 1),
            error: gate.error, status: detail.0 as u32, opcode: detail.1 as u32, reserved: 0,
        };
        drop(gate);
        write_user_struct(arg, &output)?;
        return Ok(0);
    }
    let mut request: SleManagementRequest = read_user_struct(arg)?;
    if request.version != 1 { return Err(Error::from_errno(-(bindings::EOPNOTSUPP as i32))); }
    if request.generation == 0 || request.generation != owner.identity.generation { return Err(ENODEV); }
    if cmd == SL_IOCTL_MANAGEMENT_ACQUIRE {
        // Standard typed policy/initialization is not wired yet. Queries share
        // the same explicit exclusive Diagnostic authority, never Ready.
        if owner.protocol_profile == 0 && request.mode != sle_management::DIAGNOSTIC {
            return Err(Error::from_errno(-(bindings::EOPNOTSUPP as i32)));
        }
        if request.lease != 0 || me.owned_target.lock().is_some() { return Err(EINVAL); }
        if !owner.transport_open.load(core::sync::atomic::Ordering::Acquire) { return Err(EAGAIN); }
        if let Some(error) = owner.host.lock().controller_status().2 { return Err(error); }
        let token = gate.prepare(request.mode).map_err(management_error)?;
        {
            let host = owner.host.lock();
            if !host.quiet() || !host.links_clear_for_management() { return Err(EBUSY); }
        }
        request.lease = token;
        // No command has been admitted. EFAULT leaves ownership and counter
        // unchanged; commit cannot fail while the management mutex is held.
        write_user_struct(arg, &request)?;
        {
            // Copyout may sleep after retirement has closed admission. The
            // copied candidate is not a lease until this atomic liveness check
            // and commit succeed; an ioctl error never grants it authority.
            // Native ingress may update physical links while copyout sleeps.
            // Hold Host through commit, then gate, matching ingress lock order.
            let mut host = owner.host.lock();
            let stopping = owner.schedule_gate.lock();
            if *stopping { return Err(ENODEV); }
            if let Some(error) = host.controller_status().2 { return Err(error); }
            if !host.quiet() || !host.links_clear_for_management() { return Err(EBUSY); }
            if !host.grants.accepts(token) { return Err(EOVERFLOW); }
            host.resume_management()?;
            if !host.grants.activate(token, request.mode == sle_management::MANAGED) { return Err(EOVERFLOW); }
            gate.commit(me.file_id, request.mode, token);
        }
        *me.owned_target.lock() = Some(owner.clone());
    } else {
        if request.mode != gate.mode { return Err(EPERM); }
        gate.release(me.file_id, request.lease).map_err(management_error)?;
        *me.owned_target.lock() = None;
        revoke_management(owner, &mut gate, request.mode);
    }
    Ok(0)
}

/// Typed discovery is registration-bound, never a global/default route.
fn discovery_owner(context: &RuntimeContext, me: Pin<&SparkLinkCtl>) -> Result<Arc<ControllerRuntime>> {
    let selected = me.target.lock().clone().ok_or(EINVAL)?;
    let owner = context.owner.as_ref().ok_or(ENODEV)?;
    if selected.identity != owner.identity { return Err(ENODEV); }
    if owner.protocol_profile == 0 { return Err(Error::from_errno(-(bindings::EOPNOTSUPP as i32))); }
    Ok(owner.clone())
}

/// Snapshot needs explicit affinity for every profile; release registry before
/// touching protocol state. Metadata remains available after an owner fault.
#[inline(never)]
fn ioctl_controller_snapshot(
    context: &RuntimeContext,
    me: Pin<&SparkLinkCtl>,
    arg: usize,
) -> Result<isize> {
    let input: SleControllerSnapshot = read_user_struct(arg)?;
    if input.version != 1 {
        return Err(Error::from_errno(-(bindings::EOPNOTSUPP as i32)));
    }
    if input.flags != 0 {
        return Err(EINVAL);
    }
    let selected = me.target.lock().clone().ok_or(EINVAL)?;
    let owner = context.owner.as_ref().ok_or(ENODEV)?;
    if selected.identity != owner.identity
        || (input.generation != 0 && input.generation != owner.identity.generation)
    {
        return Err(ENODEV);
    }
    let guard = context.lock()?;
    let state = guard.as_ref().ok_or(ENODEV)?;
    // SAFETY: integer-only ABI, initializes padding and every output byte.
    let mut out: SleControllerSnapshot = unsafe { core::mem::zeroed() };
    out.version = 1;
    out.generation = owner.identity.generation;
    out.dev_index = owner.identity.id;
    out.profile = owner.protocol_profile;
    out.bus = state.controller.info().bus as u8;
    let (credits, native_ready, fault) = owner.host.lock().controller_status();
    out.command_credits = credits;
    state.controller.provider().fill_snapshot(&mut out);
    out.flags = if native_ready { 1 } else { 2 };
    if let Some(error) = fault {
        out.flags = 4;
        out.error = error.to_errno();
    }
    drop(guard);
    write_user_struct(arg, &out)?;
    Ok(0)
}

/// Explicit experimental capability/candidate procedure. Generic ioctl dispatch
/// holds the author's active Managed lease and CAP_NET_ADMIN throughout.
#[inline(never)]
fn ioctl_security_negotiation(
    context: &RuntimeContext,
    me: Pin<&SparkLinkCtl>,
    cmd: u32,
    arg: usize,
) -> Result<isize> {
    let owner = discovery_owner(context, me)?;
    if cmd == SL_IOCTL_SECURITY_NEGOTIATION_CANCEL {
        let input: SleSecurityNegotiationCancel = read_user_struct(arg)?;
        if input.version != 1 { return Err(Error::from_errno(-(bindings::EOPNOTSUPP as i32))); }
        if input.generation == 0 || input.lifetime == 0 || input.request_id == 0 || input.handle > 0x0fff {
            return Err(EINVAL);
        }
        if input.generation != owner.identity.generation { return Err(ENODEV); }
        owner.cancel_security_author(me.file_id, input.lifetime, input.handle, input.request_id)?;
        owner.kick_commands();
        owner.schedule_rx(0);
        return Ok(0);
    }
    if cmd == SL_IOCTL_SECURITY_NUMERIC_CONFIRM {
        let input:SleSecurityNumericConfirm=read_user_struct(arg)?;
        if input.version!=1 {return Err(Error::from_errno(-(bindings::EOPNOTSUPP as i32)));}
        if input.generation==0 || input.lifetime==0 || input.request_id==0 || input.handle>0x0fff || input.accept>1 || input.comparison_code>=1000000 {return Err(EINVAL);}
        if input.generation!=owner.identity.generation {return Err(ENODEV);}
        owner.confirm_security_numeric(me.file_id,&input)?;
        owner.kick_commands();owner.schedule_rx(0);return Ok(0);
    }
    if cmd == SL_IOCTL_SECURITY_NEGOTIATION_SUBMIT {
        let request: SleSecurityNegotiationSubmit = read_user_struct(arg)?;
        if request.version != 2 || request.profile != owner.protocol_profile {
            return Err(Error::from_errno(-(bindings::EOPNOTSUPP as i32)));
        }
        if !matches!(request.flags,1|2|3|4)
            || request.generation == 0
            || request.lifetime == 0
            || request.request_id == 0
            || request.handle > 0x0fff
            || !(1..=5000).contains(&request.timeout_ms)
        {
            return Err(EINVAL);
        }
        if !matches!((request.role, request.action), (1, 1) | (0, 2)) {
            return Err(Error::from_errno(-(bindings::EOPNOTSUPP as i32)));
        }
        if request.generation != owner.identity.generation {
            return Err(ENODEV);
        }
        let guard = context.lock()?;
        let runtime = guard.as_ref().ok_or(ENODEV)?;
        owner.approve_security_capabilities(runtime, me.file_id, &request)?;
        drop(guard);
        owner.kick_commands();
        owner.schedule_rx(0);
        return Ok(0);
    }
    let input: SleSecurityNegotiationResult = read_user_struct(arg)?;
    if input.version != 1 {
        return Err(Error::from_errno(-(bindings::EOPNOTSUPP as i32)));
    }
    if input.generation == 0
        || input.lifetime == 0
        || input.request_id == 0
        || input.handle > 0x0fff
        || input.profile != 0
        || input.state != 0
        || input.error != 0
        || input.flags != 0
        || input.role != 0
        || input.status != 0
        || input.local_caps != [0; 10]
        || input.peer_caps != [0; 10]
        || input.comparison_code != 0
    {
        return Err(EINVAL);
    }
    if input.generation != owner.identity.generation {
        return Err(ENODEV);
    }
    let (observation, role) = owner.security_capability_observation(
        me.file_id,
        input.lifetime,
        input.handle,
        input.request_id,
    )?;
    // SAFETY: padding-free ABI; zero every output/reserved byte before copyout.
    let mut output: SleSecurityNegotiationResult = unsafe { core::mem::zeroed() };
    output.version = 1;
    output.profile = owner.protocol_profile;
    output.generation = owner.identity.generation;
    output.lifetime = input.lifetime;
    output.request_id = input.request_id;
    output.handle = input.handle;
    output.role = role;
    output.state = observation.state;
    output.flags = observation.flags;
    output.status = observation.status;
    output.local_caps = observation.local;
    output.peer_caps = observation.peer;
    output.comparison_code = observation.comparison_code;
    output.error = if observation.error!=0 {observation.error}else{match observation.state {
        5 => {
            if observation.status == 0 {
                -(bindings::EOPNOTSUPP as i32)
            } else {
                EIO.to_errno()
            }
        }
        6 => -(bindings::ECANCELED as i32),
        7 => ETIMEDOUT.to_errno(),
        _ => 0,
    }};
    write_user_struct(arg, &output)?;
    Ok(0)
}

/// Typed native connection, all driver field validation before Host mutation.
/// Dispatch already holds file operation and Managed lease locks throughout admission.
#[inline(never)]
fn ioctl_connection_submit(context: &RuntimeContext, me: Pin<&SparkLinkCtl>, arg: usize) -> Result<isize> {
    let request: SleConnectionSubmit = read_user_struct(arg)?;
    if request.version != 2 { return Err(Error::from_errno(-(bindings::EOPNOTSUPP as i32))); }
    if request.flags != 0 || request.generation == 0 || request.request_id == 0
        || request.parameters.reserved != [0; 2] { return Err(EINVAL); }
    let owner = discovery_owner(context, me)?;
    if request.generation != owner.identity.generation { return Err(ENODEV); }
    if request.profile != owner.protocol_profile { return Err(Error::from_errno(-(bindings::EOPNOTSUPP as i32))); }
    // SAFETY: exact padding-free integer/byte ABI, initialized by copyin.
    let parameters_zero = unsafe { core::slice::from_raw_parts(core::ptr::from_ref(&request.parameters).cast::<u8>(), 60) }.iter().all(|b| *b == 0);
    let reference_zero = request.expected_lifetime == 0 && request.expected_address == [0;6]
        && request.expected_address_type == 0 && request.expected_role == 0;
    if request.operation == 3 {
        if request.timeout_ms != 0 || request.handle != 0 || request.reason != 0 || !parameters_zero || !reference_zero { return Err(EINVAL); }
        let state_guard = context.lock()?;
        let mut host = owner.host.lock();
        let gate = owner.schedule_gate.lock();
        if *gate { return Err(ENODEV); }
        host.cancel_connection(me.file_id, request.request_id)?;
        drop(gate); drop(host); drop(state_guard);
        owner.kick_commands(); owner.schedule_rx(0);
        return Ok(0);
    }
    if !(1..=10000).contains(&request.timeout_ms) || request.handle > 65535 || request.reason > 255 { return Err(EINVAL); }
    let intent = match request.operation {
        1 if request.handle == 0 && request.reason == 0 && reference_zero => sle_connection_operation::Intent::Create {
            address_type: u8::try_from(request.parameters.peer_address_type).map_err(|_| EINVAL)?,
            address: request.parameters.peer_address },
        2 if parameters_zero => sle_connection_operation::Intent::Disconnect { handle: request.handle as u16 },
        _ => return Err(Error::from_errno(-(bindings::EOPNOTSUPP as i32))),
    };
    let reference = if request.operation == 2 {
        let reference = sle_connection_operation::ExpectedLink { lifetime: request.expected_lifetime,
            handle: request.handle as u16, role: request.expected_role,
            address_type: request.expected_address_type, address: request.expected_address };
        if !reference.valid() { return Err(EINVAL); }
        Some(reference)
    } else { None };
    let state_guard = context.lock()?;
    let state = state_guard.as_ref().ok_or(ENODEV)?;
    let plan = state.controller.provider().prepare_connection(&request)?;
    let mut watermark = me.connection_request_id.lock();
    if request.request_id <= *watermark { return Err(Error::from_errno(-(bindings::ESTALE as i32))); }
    // Same Host -> scheduling gate order as atomic physical link ingress.
    let mut host = owner.host.lock();
    let gate = owner.schedule_gate.lock();
    if *gate { return Err(ENODEV); }
    host.submit_connection(me.file_id, request.request_id, intent, plan.operation,
        plan.opcode, &plan.params[..plan.length as usize], request.timeout_ms, reference)?;
    *watermark = request.request_id;
    drop(gate); drop(host); drop(watermark); drop(state_guard);
    owner.kick_commands(); owner.schedule_rx(0);
    Ok(0)
}

/// Author-only non-destructive history, available after cancellation/release/fault.
#[inline(never)]
fn ioctl_connection_result(context: &RuntimeContext, me: Pin<&SparkLinkCtl>, arg: usize) -> Result<isize> {
    let input: SleConnectionResult = read_user_struct(arg)?;
    if input.version != 1 { return Err(Error::from_errno(-(bindings::EOPNOTSUPP as i32))); }
    if input.flags != 0 || input.request_id == 0 || input.generation == 0 { return Err(EINVAL); }
    let owner = discovery_owner(context, me)?;
    if input.generation != owner.identity.generation { return Err(ENODEV); }
    let host = owner.host.lock();
    let gate = owner.schedule_gate.lock();
    if *gate { return Err(ENODEV); }
    let record = host.connection_result(me.file_id, input.request_id).ok_or(ENOENT)?;
    // SAFETY: all integer/byte fields, initialize every output byte.
    let mut output: SleConnectionResult = unsafe { core::mem::zeroed() };
    output.version = 1; output.profile = owner.protocol_profile;
    output.generation = owner.identity.generation; output.request_id = input.request_id;
    output.dev_index = owner.identity.id; output.state = record.state as u32;
    output.error = record.error; output.fault_error = record.fault_error;
    output.operation = match record.intent { sle_connection_operation::Intent::Create { .. } => 1, sle_connection_operation::Intent::Disconnect { .. } => 2 };
    if let Some(status) = record.command_status { output.flags |= 1; output.command_status = status as u32; }
    if let Some(status) = record.outcome_status { output.flags |= 2; output.outcome_status = status as u32; }
    if let Some(handle) = record.handle { output.flags |= 4; output.handle = handle as u32; }
    drop(gate); drop(host);
    write_user_struct(arg, &output)?;
    Ok(0)
}

/// Same Host -> gate -> event-log order as native physical ingress. Copyout
/// happens after releasing every IRQ-safe lock; no cursor or state is consumed.
#[inline(never)]
fn ioctl_link_snapshot(context: &RuntimeContext, me: Pin<&SparkLinkCtl>, arg: usize) -> Result<isize> {
    let input: SleLinkSnapshot = read_user_struct(arg)?;
    if input.version != 1 { return Err(Error::from_errno(-(bindings::EOPNOTSUPP as i32))); }
    if input.generation == 0 || input.event_seq != 0 || input.revision != 0 || input.profile != 0
        || input.flags != 0 || input.count != 0 || input.error != 0 || input.dev_index != 0
        || input.reserved != [0; 2] { return Err(EINVAL); }
    // SAFETY: the fixed padding-free table was fully initialized by copyin.
    if unsafe { core::slice::from_raw_parts(input.links.as_ptr().cast::<u8>(), 16 * 24) }.iter().any(|v| *v != 0) {
        return Err(EINVAL);
    }
    let owner = discovery_owner(context, me)?;
    if input.generation != owner.identity.generation { return Err(ENODEV); }
    if owner.protocol_profile == 0 { return Err(Error::from_errno(-(bindings::EOPNOTSUPP as i32))); }
    // SAFETY: every ABI field and reserved byte is initialized before copyout.
    let mut out: SleLinkSnapshot = unsafe { core::mem::zeroed() };
    out.version = 1; out.generation = owner.identity.generation;
    out.dev_index = owner.identity.id; out.profile = owner.protocol_profile;
    {
        let host = owner.host.lock();
        let gate = owner.schedule_gate.lock();
        if *gate { return Err(ENODEV); }
        let (revision, known, links) = host.link_snapshot();
        out.revision = revision;
        out.event_seq = owner.controller_events.lock().current_seq();
        if known {
            out.flags = LINK_SNAPSHOT_KNOWN;
            for link in links.iter().flatten() {
                out.links[out.count as usize] = SleLinkInfo { lifetime: link.lifetime, handle: link.handle,
                    role: link.role, address_type: link.address_type, address: link.address, reserved: [0; 6] };
                out.count += 1;
            }
        } else {
            out.error = -(bindings::EUCLEAN as i32); // unknown is not an empty table
        }
    }
    write_user_struct(arg, &out)?;
    Ok(0)
}

/// Explicit host fields and unused bytes are checked before any admission.
fn validate_discovery_submit(request: &SleDiscoverySubmit) -> Result<sle_command_plan::DiscoveryIntent> {
    use sle_command_plan::DiscoveryIntent;
    if request.version != DISCOVERY_VERSION { return Err(Error::from_errno(-(bindings::EOPNOTSUPP as i32))); }
    if request.request_id == 0 || request.generation == 0 || request.flags & !1 != 0
        || request.data_len > 251 || request.scan_response_len > 251 { return Err(EINVAL); }
    if request.data[request.data_len as usize..].iter().any(|b| *b != 0)
        || request.scan_response[request.scan_response_len as usize..].iter().any(|b| *b != 0)
        || (request.flags & 1 == 0 && request.scan_response_len != 0) { return Err(EINVAL); }
    // SAFETY: integer-only repr(C) structures, no padding (116/28 bytes).
    let adv_zero = unsafe { core::slice::from_raw_parts(core::ptr::from_ref(&request.advertising).cast::<u8>(), 116) }.iter().all(|b| *b == 0);
    let scan_zero = unsafe { core::slice::from_raw_parts(core::ptr::from_ref(&request.scanning).cast::<u8>(), 28) }.iter().all(|b| *b == 0);
    let intent = match request.operation {
        1 => { if !scan_zero { return Err(EINVAL); } DiscoveryIntent::Advertising(true) }
        2 => { if !adv_zero || !scan_zero { return Err(EINVAL); } DiscoveryIntent::Advertising(false) }
        3 => { if !adv_zero { return Err(EINVAL); } DiscoveryIntent::Scanning(true) }
        4 => { if !adv_zero || !scan_zero { return Err(EINVAL); } DiscoveryIntent::Scanning(false) }
        5 => { if !scan_zero { return Err(EINVAL); } DiscoveryIntent::AdvertisingStandby }
        6 => { if !adv_zero { return Err(EINVAL); } DiscoveryIntent::ScanningStandby }
        _ => return Err(Error::from_errno(-(bindings::EOPNOTSUPP as i32))),
    };
    if request.operation != 1 && (request.flags != 0 || request.data_len != 0
        || request.scan_response_len != 0 || request.duration != 0 || request.max_events != 0) { return Err(EINVAL); }
    if matches!(request.operation, 3 | 4 | 6) && request.handle != 0 { return Err(EINVAL); }
    Ok(intent)
}

/// _IOW avoids losing an accepted cookie to a post-admission EFAULT. The caller
/// supplies a nonzero correlation id and queries it without destructive reads.
#[inline(never)]
fn ioctl_discovery_submit(context: &RuntimeContext, me: Pin<&SparkLinkCtl>, arg: usize) -> Result<isize> {
    let request: SleDiscoverySubmit = read_user_struct(arg)?;
    let intent = validate_discovery_submit(&request)?;
    let owner = discovery_owner(context, me)?;
    if request.generation != owner.identity.generation { return Err(ENODEV); }
    if request.profile != owner.protocol_profile { return Err(Error::from_errno(-(bindings::EOPNOTSUPP as i32))); }
    let state_guard = context.lock()?;
    let state = state_guard.as_ref().ok_or(ENODEV)?;
    let plan = state.controller.provider().prepare_discovery(&request)?;
    let mut parts = [sle_command_plan::RecipePart { opcode: 0, params: &[] }; 4];
    for (i, step) in plan.steps[..plan.count as usize].iter().enumerate() {
        parts[i] = sle_command_plan::RecipePart { opcode: step.opcode, params: &step.params[..step.length as usize] };
    }
    // Match management commit and physical ingress: Host before retirement gate.
    // Hold both through the configuration observation and recipe admission.
    let mut host = owner.host.lock();
    let gate = owner.schedule_gate.lock();
    if *gate { return Err(ENODEV); }
    host.submit_discovery(request.request_id, intent, &parts[..plan.count as usize], plan.power_step as u8)?;
    drop(gate);
    drop(host);
    // Drop the protocol mutex before scheduling TX (and before any transport).
    drop(state_guard);
    owner.kick_commands();
    Ok(0)
}

#[inline(never)]
fn ioctl_discovery_result(context: &RuntimeContext, me: Pin<&SparkLinkCtl>, arg: usize) -> Result<isize> {
    let input: SleDiscoveryResult = read_user_struct(arg)?;
    if input.version != DISCOVERY_VERSION { return Err(Error::from_errno(-(bindings::EOPNOTSUPP as i32))); }
    if input.flags != 0 || (input.request_id != 0 && input.generation == 0) { return Err(EINVAL); }
    let owner = discovery_owner(context, me)?;
    if input.generation != 0 && input.generation != owner.identity.generation { return Err(ENODEV); }
    let state = context.lock()?;
    let host = owner.host.lock();
    let (advertising, scanning, fault) = host.discovery_radio();
    // SAFETY: all integers/byte arrays; initialize every output byte.
    let mut output: SleDiscoveryResult = unsafe { core::mem::zeroed() };
    output.version = DISCOVERY_VERSION; output.generation = owner.identity.generation;
    output.request_id = input.request_id; output.profile = owner.protocol_profile;
    output.dev_index = owner.identity.id; output.radio_adv = advertising; output.radio_scan = scanning;
    if let Some(error) = fault { output.flags = 1; output.error = error.to_errno(); }
    if input.request_id != 0 {
        let record = host.discovery_result(input.request_id).ok_or(ENOENT)?;
        output.operation = match record.intent {
            sle_command_plan::DiscoveryIntent::Advertising(true) => 1,
            sle_command_plan::DiscoveryIntent::Advertising(false) => 2,
            sle_command_plan::DiscoveryIntent::Scanning(true) => 3,
            sle_command_plan::DiscoveryIntent::Scanning(false) => 4,
            sle_command_plan::DiscoveryIntent::AdvertisingStandby => 5,
            sle_command_plan::DiscoveryIntent::ScanningStandby => 6,
        };
        output.state = record.state as u32; output.error = record.error;
        output.status = record.status; output.opcode = record.opcode;
        output.step = record.step; output.count = record.count;
        if let Some(power) = record.selected_power { output.power_valid = 1; output.selected_power = power as i32; }
    }
    drop(host); drop(state);
    write_user_struct(arg, &output)?;
    Ok(0)
}

/// Retain the exact receipt clock of the reserved final successful Complete.
#[inline(never)]
fn ioctl_discovery_timing(context:&RuntimeContext, me:Pin<&SparkLinkCtl>, arg:usize)->Result<isize> {
 let input:SleDiscoveryTiming=read_user_struct(arg)?;
 if input.version!=1 {return Err(Error::from_errno(-(bindings::EOPNOTSUPP as i32)));}
 if input.flags!=0 || input.generation==0 || input.request_id==0 {return Err(EINVAL);}
 let owner=discovery_owner(context,me)?;
 if input.generation!=owner.identity.generation {return Err(ENODEV);}
 let state=context.lock()?;
 let record=owner.host.lock().discovery_result(input.request_id).ok_or(ENOENT)?;
 // SAFETY: all fields are integers/bytes, initialize every output byte.
 let mut output:SleDiscoveryTiming=unsafe {core::mem::zeroed()};
 output.version=1;output.generation=owner.identity.generation;output.request_id=record.request_id;
 output.completed_boottime_ns=record.completed_boottime_ns;output.dev_index=owner.identity.id;
 output.state=record.state as u32;output.opcode=record.opcode;output.status=record.status;
 output.operation=match record.intent {
  sle_command_plan::DiscoveryIntent::Advertising(true)=>1,
  sle_command_plan::DiscoveryIntent::Advertising(false)=>2,
  sle_command_plan::DiscoveryIntent::Scanning(true)=>3,
  sle_command_plan::DiscoveryIntent::Scanning(false)=>4,
  sle_command_plan::DiscoveryIntent::AdvertisingStandby=>5,
  sle_command_plan::DiscoveryIntent::ScanningStandby=>6,
 };
 drop(state);write_user_struct(arg,&output)?;Ok(0)
}

/// Read one complete native record without mutating the controller protocol.
#[inline(never)]
fn ioctl_controller_event_get(context: &RuntimeContext, me: Pin<&SparkLinkCtl>, arg: usize) -> Result<isize> {
    if me.snoop_subscription.lock().is_some() { return Err(EBUSY); }
    let mut query: SleControllerEventQuery = read_user_struct(arg)?;
    if query.version != CONTROLLER_EVENT_VERSION { return Err(Error::from_errno(-(bindings::EOPNOTSUPP as i32))); }
    if query.flags != 0 || (query.after_seq != 0 && query.generation == 0) { return Err(EINVAL); }
    let owner = context.owner.as_ref().ok_or(ENODEV)?;
    let state = context.lock()?;
    if query.generation != 0 && query.generation != owner.identity.generation { return Err(ENODEV); }
    let event = {
        let log = owner.controller_events.lock();
        if query.after_seq > log.current_seq() { return Err(EINVAL); }
        log.next_after(query.after_seq)
    };
    *me.controller_subscription.lock() = Some(sle_controller_event::Subscription {
        identity: owner.identity, after_seq: query.after_seq,
    });
    drop(state);
    query.event = event.ok_or(EAGAIN)?;
    query.generation = owner.identity.generation;
    write_user_struct(arg, &query)?;
    // EFAULT must leave this fd's readiness cursor on the unread event.
    let mut subscription = me.controller_subscription.lock();
    if let Some(current) = Option::as_mut(&mut *subscription) {
        if current.identity == owner.identity {
            current.after_seq = current.after_seq.max(query.event.seq);
        }
    }
    Ok(0)
}

#[inline(never)]
fn ioctl_snoop_get(context: &RuntimeContext, me: Pin<&SparkLinkCtl>, arg: usize) -> Result<isize> {
    let mut query: SleSnoopQuery = read_user_struct(arg)?;
    if query.version != SNOOP_VERSION { return Err(Error::from_errno(-(bindings::EOPNOTSUPP as i32))); }
    if query.flags != 0 || query.reserved != 0 { return Err(EINVAL); }
    let owner = context.owner.as_ref().ok_or(ENODEV)?;
    if me.target.lock().as_ref().map(|target| target.identity) != Some(owner.identity) || query.generation == 0 { return Err(EINVAL); }
    if owner.protocol_profile > 1 { return Err(Error::from_errno(-(bindings::EOPNOTSUPP as i32))); }
    if me.controller_subscription.lock().is_some() { return Err(EBUSY); }
    let gate=owner.schedule_gate.lock();
    if *gate { return Err(ENODEV); }
    if query.generation != owner.identity.generation { return Err(ENODEV); }
    let record = {
        let log=owner.snoop.lock();
        if query.after_seq>log.current_seq() { return Err(EINVAL); }
        log.next_after(query.after_seq)
    };
    drop(gate);
    // The fd mutex may sleep; never acquire it under the IRQ retirement gate.
    // A concurrent retirement remains visible to poll and the next query.
    *me.snoop_subscription.lock()=Some(sle_controller_event::Subscription { identity:owner.identity,after_seq:query.after_seq });
    query.record=record.ok_or(EAGAIN)?;
    write_user_struct(arg,&query)?;
    if let Some(current)=Option::as_mut(&mut *me.snoop_subscription.lock()) {
        if current.identity==owner.identity { current.after_seq=current.after_seq.max(query.record.seq); }
    }
    Ok(0)
}

/// Fixed, idempotent query parameters belong to the registered dialect. No
/// caller payload, mutation, allocation, credit or transport effect here.
fn diagnostic_parameters(profile: u32, opcode: u16) -> Result<&'static [u8]> {
    match (profile, opcode) {
        (0, 0x0406) => Ok(&[0]), // standard alliance-assigned identifier
        (0, 0x0401..=0x0404) | (1, 0x0402 | 0x0403 | 0x0404 | 0x0406) => Ok(&[]),
        _ => Err(Error::from_errno(-(bindings::EOPNOTSUPP as i32))),
    }
}

/// Metadata-only admission: management mutex spans authorization/admission,
/// never usercopy. No default controller, transport I/O or policy/test hook.
#[inline(never)]
fn ioctl_diagnostic_submit(context: &RuntimeContext, me: Pin<&SparkLinkCtl>, arg: usize) -> Result<isize> {
    let mut input: SleDiagnosticSubmit = read_user_struct(arg)?;
    if input.version != 1 { return Err(Error::from_errno(-(bindings::EOPNOTSUPP as i32))); }
    if input.flags != 0 || input.reserved != 0 || input.generation == 0 || input.request_id == 0 || input.seq != 0
        || !(1..=sle_mgmt::CMD_TIMEOUT_MS).contains(&input.timeout_ms) || !matches!(input.action, 1 | 2) {
        return Err(EINVAL);
    }
    let owner = context.owner.as_ref().ok_or(ENODEV)?;
    if me.target.lock().as_ref().map(|t| t.identity) != Some(owner.identity) { return Err(EINVAL); }
    if input.generation != owner.identity.generation { return Err(ENODEV); }
    let params = diagnostic_parameters(owner.protocol_profile, input.opcode)?;
    if *owner.schedule_gate.lock() { return Err(ENODEV); }
    let management = owner.management.lock();
    management.authorize(me.file_id, sle_management::DIAGNOSTIC).map_err(management_error)?;
    let mut watermark = me.diagnostic_request_id.lock();
    {
        let mut state = context.lock()?;
        let state = Option::as_mut(&mut *state).ok_or(ENODEV)?;
        state.controller.validate_command(input.opcode, params)?;
        state.cmd_pending.expire_stale();
        if let Some(entry) = state.cmd_pending.find_request(me.file_id, input.request_id) {
            if entry.opcode != input.opcode || entry.timeout_ms != input.timeout_ms { return Err(EINVAL); }
            input.seq = entry.seq;
            if input.action == 2 {
                state.cmd_pending.cancel_seq(input.seq);
                owner.host.lock().cancel_diagnostic(input.seq);
            }
        } else {
            if input.request_id <= *watermark { return Err(Error::from_errno(-(bindings::ESTALE as i32))); }
            if input.action == 2 { return Err(ENOENT); }
            input.seq = state.cmd_pending.submit_with_timeout(input.opcode, input.timeout_ms)?;
            state.cmd_pending.assign_request(input.seq, me.file_id, input.request_id);
            let deadline = state.cmd_pending.find_by_seq(input.seq).ok_or(ENOENT)?.deadline;
            if let Err(error) = owner.host.lock().enqueue_diagnostic(input.opcode, params, input.seq, deadline) {
                state.cmd_pending.rollback(input.seq);
                return Err(error);
            }
            *watermark = input.request_id;
        }
    }
    drop(watermark);
    drop(management);
    owner.kick_commands();
    // An existing idle heartbeat may be later than this admission's deadline.
    // Wake RX to recompute the earliest absolute deadline under owner state.
    // Delayed enqueue alone cannot shorten already pending delayed work.
    owner.schedule_rx(0);
    // Committed ID/admission remain findable on EFAULT. Retrying cannot enqueue
    // a second command, extend its deadline or revive an evicted/cancelled ID.
    write_user_struct(arg, &input)?;
    Ok(0)
}

/// Non-destructive result for the diagnostic author. A local sequence is
/// assigned by admission and resolved only by the Host's captured wire slot.
#[inline(never)]
fn ioctl_diagnostic_result(context: &RuntimeContext, me: Pin<&SparkLinkCtl>, arg: usize) -> Result<isize> {
    let input: SleDiagnosticResult = read_user_struct(arg)?;
    if input.version != 1 { return Err(Error::from_errno(-(bindings::EOPNOTSUPP as i32))); }
    if input.flags != 0 || input.generation == 0 || input.seq == 0 { return Err(EINVAL); }
    let owner = context.owner.as_ref().ok_or(ENODEV)?;
    if me.target.lock().as_ref().map(|t| t.identity) != Some(owner.identity) { return Err(EINVAL); }
    if input.generation != owner.identity.generation { return Err(ENODEV); }
    if owner.protocol_profile > 1 { return Err(Error::from_errno(-(bindings::EOPNOTSUPP as i32))); }
    if *owner.schedule_gate.lock() { return Err(ENODEV); }
    owner.management.lock().authorize(me.file_id, sle_management::DIAGNOSTIC).map_err(management_error)?;
    let mut guard = context.lock()?;
    let state = Option::as_mut(&mut *guard).ok_or(ENODEV)?;
    state.cmd_pending.expire_stale();
    let entry = state.cmd_pending.find_by_seq(input.seq).ok_or(ENOENT)?;
    if entry.file_id != me.file_id { return Err(EPERM); }
    // SAFETY: only integer fields and byte arrays; all-zero is a valid baseline.
    let mut output: SleDiagnosticResult = unsafe { core::mem::zeroed() };
    output.version = 1; output.generation = owner.identity.generation;
    output.seq = entry.seq; output.opcode = entry.opcode;
    if entry.is_pending() {
        output.state = 1;
    } else if let Some(status) = entry.result_status() {
        output.state = if status == 0 { 2 } else { 3 };
        output.status = status;
        output.data_len = entry.data_len;
        output.data.copy_from_slice(&entry.data);
    } else {
        output.state = 3;
        output.error = entry.error;
    }
    drop(guard);
    // No result consumption or acknowledgement: an EFAULT is safely retryable.
    write_user_struct(arg, &output)?;
    Ok(0)
}

/// Infrastructure ioctl sub-dispatcher: PM, sync, DLI, events, PHY, role, RAL/RPA.
#[inline(never)]
fn ioctl_dispatch_infra(context: &RuntimeContext, me: Pin<&SparkLinkCtl>, cmd: u32, arg: usize) -> Result<isize> {
    match cmd {
        SL_IOCTL_SNOOP_GET => ioctl_snoop_get(context, me, arg),
        SL_IOCTL_DIAGNOSTIC_RESULT => ioctl_diagnostic_result(context, me, arg),
        SL_IOCTL_CONTROLLER_SNAPSHOT => ioctl_controller_snapshot(context, me, arg),
        SL_IOCTL_SECURITY_NEGOTIATION_SUBMIT | SL_IOCTL_SECURITY_NEGOTIATION_RESULT | SL_IOCTL_SECURITY_NEGOTIATION_CANCEL | SL_IOCTL_SECURITY_NUMERIC_CONFIRM => ioctl_security_negotiation(context,me,cmd,arg),
        SL_IOCTL_CONNECTION_SUBMIT => ioctl_connection_submit(context, me, arg),
        SL_IOCTL_CONNECTION_RESULT => ioctl_connection_result(context, me, arg),
        SL_IOCTL_LINK_SNAPSHOT => ioctl_link_snapshot(context, me, arg),
        SL_IOCTL_DISCOVERY_SUBMIT => ioctl_discovery_submit(context, me, arg),
        SL_IOCTL_DISCOVERY_RESULT => ioctl_discovery_result(context, me, arg),
        SL_IOCTL_DISCOVERY_TIMING => ioctl_discovery_timing(context, me, arg),
        SL_IOCTL_CONTROLLER_EVENT_GET => ioctl_controller_event_get(context, me, arg),
        // No qualified hardware PM transaction or snapshot is connected.
        SL_IOCTL_PM_INFO | SL_IOCTL_PM_SET_STATE | SL_IOCTL_PM_SET_INTERVAL
        | SL_IOCTL_PM_FORCE_ACTIVE | SL_IOCTL_PM_TICK | SL_IOCTL_PM_ACTIVITY
            => Err(Error::from_errno(-(bindings::EOPNOTSUPP as i32))),
        SL_IOCTL_SYNC_UCAST_PARAM
        | SL_IOCTL_SYNC_UCAST_CREATE
        | SL_IOCTL_SYNC_UCAST_REMOVE
        | SL_IOCTL_SYNC_MCAST_PARAM
        | SL_IOCTL_SYNC_MCAST_CREATE
        | SL_IOCTL_SYNC_MCAST_REMOVE
        | SL_IOCTL_SYNC_DATAPATH_CFG
        | SL_IOCTL_SYNC_DATAPATH_REMOVE
        | SL_IOCTL_SYNC_INFO
        | SL_IOCTL_SYNC_UCAST_ACCEPT
        | SL_IOCTL_SYNC_UCAST_REJECT
        | SL_IOCTL_SYNC_MCAST_ACCEPT
        | SL_IOCTL_SYNC_MCAST_REJECT => Err(Error::from_errno(-(bindings::EOPNOTSUPP as i32))),
        SL_IOCTL_SYNC_DATA_SEND => Err(Error::from_errno(-(bindings::EOPNOTSUPP as i32))),
        SL_IOCTL_DLI_INFO => Err(Error::from_errno(-(bindings::EOPNOTSUPP as i32))),
        SL_IOCTL_DLI_RESET => Err(Error::from_errno(-(bindings::EOPNOTSUPP as i32))),
        SL_IOCTL_DLI_SEND_CMD => Err(Error::from_errno(-(bindings::EOPNOTSUPP as i32))),
        SL_IOCTL_MGMT_STATS => {
            // Only actual standard Diagnostic author transactions use this
            // ledger. Never project its zero counters as Native Host state.
            if context.owner.as_ref().ok_or(ENODEV)?.protocol_profile != 0 {
                return Err(Error::from_errno(-(bindings::EOPNOTSUPP as i32)));
            }
            let ss = context.lock()?;
            let s = ss.as_ref().ok_or(ENODEV)?;
            let stats = SleMgmtStats {
                pending: s.cmd_pending.pending(),
                _pad: 0,
                total_submitted: s.cmd_pending.total_submitted as u32,
                total_resolved: s.cmd_pending.total_resolved as u32,
                total_timeouts: s.cmd_pending.total_timeouts as u32,
            };
            drop(ss);
            write_user_struct(arg, &stats)?;
            Ok(0)
        }
        SL_IOCTL_USB_DEV_COUNT => Err(Error::from_errno(-(bindings::EOPNOTSUPP as i32))),
        // No authenticated PHY transaction or confirmed hardware snapshot is
        // implemented. Local models must not impersonate controller state.
        SL_IOCTL_PHY_INFO
        | SL_IOCTL_PHY_SET_MCS
        | SL_IOCTL_PHY_SET_TXPOWER
        | SL_IOCTL_PHY_MCS_SELECT
        | SL_IOCTL_PHY_HOP_NEXT
        | SL_IOCTL_PHY_SET_BW
        | SL_IOCTL_PHY_GET_SINR
        | SL_IOCTL_PHY_SET_SINR => Err(Error::from_errno(-(bindings::EOPNOTSUPP as i32))),
        SL_IOCTL_SET_ROLE | SL_IOCTL_GET_ROLE
            => Err(Error::from_errno(-(bindings::EOPNOTSUPP as i32))),
        SL_IOCTL_RAL_ADD | SL_IOCTL_RAL_REMOVE | SL_IOCTL_RAL_CLEAR | SL_IOCTL_RAL_SIZE
        | SL_IOCTL_RAL_READ_PEER_RPA | SL_IOCTL_RAL_READ_LOCAL_RPA
        | SL_IOCTL_RPA_ENABLE | SL_IOCTL_RPA_SET_TIMEOUT
            => Err(Error::from_errno(-(bindings::EOPNOTSUPP as i32))),
        SL_IOCTL_MEAS_READ_CAP | SL_IOCTL_MEAS_SET_LINK_PARAM
        | SL_IOCTL_MEAS_ACTION | SL_IOCTL_MEAS_ENABLE
            => Err(Error::from_errno(-(bindings::EOPNOTSUPP as i32))),
        _ => Err(EINVAL),
    }
}

#[vtable]
impl MiscDevice for SparkLinkCtl {
    type Ptr = Pin<KBox<Self>>;

    fn open(_file: &FsFile, misc: &MiscDeviceRegistration<Self>) -> Result<Pin<KBox<Self>>> {
        let dev = ARef::from(misc.device());
        dev_info!(dev, "sparklink: control interface opened\n");

        // Subsystem is initialised at module load; just verify it exists.
        {
            let ss = SUBSYSTEM.lock();
            if ss.is_none() {
                dev_err!(dev, "sparklink: subsystem not initialised\n");
                return Err(ENODEV);
            }
        }
        static NEXT_FILE: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(1);
        let file_id = NEXT_FILE.fetch_update(core::sync::atomic::Ordering::Relaxed, core::sync::atomic::Ordering::Relaxed, |next| next.checked_add(1)).map_err(|_| EOVERFLOW)?;
        OPEN_FD_COUNT.fetch_add(1u32, Relaxed);

        KBox::try_pin_init(
            try_pin_init! {
                SparkLinkCtl {
                    file_id,
                    diagnostic_request_id <- new_mutex!(0),
                    connection_request_id <- new_mutex!(0),
                    operation <- new_mutex!(()),
                    owned_target <- new_mutex!(None),
                    dev: dev,
                    target <- new_mutex!(None),
                    controller_subscription <- new_mutex!(None),
                    snoop_subscription <- new_mutex!(None),
                }
            },
            GFP_KERNEL,
        )
    }

    fn read_iter(_kiocb: Kiocb<'_, Self::Ptr>, _iov: &mut IovIterDest<'_>) -> Result<usize> {
        Err(Error::from_errno(-(bindings::EOPNOTSUPP as i32)))
    }

    fn poll(me: Pin<&SparkLinkCtl>, file: &FsFile, table: &PollTable<'_>) -> u32 {
        let snoop_subscription = *me.snoop_subscription.lock();
        if let Some(subscription) = snoop_subscription {
            if sle_authorization::require_admin().is_err() { return bindings::POLLERR; }
            let target=me.target.lock().clone();
            let Some(owner)=target.as_ref() else { return bindings::POLLERR|bindings::POLLHUP; };
            if owner.identity!=subscription.identity { return bindings::POLLERR|bindings::POLLHUP; }
            table.register_wait(file,&owner.snoop_poll);
            if *owner.schedule_gate.lock() { return bindings::POLLERR|bindings::POLLHUP; }
            return if owner.snoop.lock().current_seq()>subscription.after_seq {bindings::POLLIN|bindings::POLLRDNORM} else {0};
        }
        let subscription = *me.controller_subscription.lock();
        if let Some(subscription) = subscription {
            let target = me.target.lock().clone();
            let context = match target {
                Some(owner) => RuntimeContext::from_owner(owner),
                None => RuntimeContext { owner: None },
            };
            let Some(owner) = context.owner.as_ref() else { return bindings::POLLERR | bindings::POLLHUP; };
            if owner.identity != subscription.identity { return bindings::POLLERR | bindings::POLLHUP; }
            table.register_wait(file, &owner.controller_event_poll);
            if context.lock().is_err() { return bindings::POLLERR | bindings::POLLHUP; }
            return if owner.controller_events.lock().current_seq() > subscription.after_seq {
                bindings::POLLIN | bindings::POLLRDNORM
            } else { 0 };
        }
        // Activate a canonical ControllerEvent or privileged snoop subscription first.
        bindings::POLLERR
    }

    fn ioctl(me: Pin<&SparkLinkCtl>, _file: &FsFile, cmd: u32, arg: usize) -> Result<isize> {
        let _operation = me.operation.lock();
        let access = sle_authorization::classify(cmd)?;
        if matches!(access, sle_authorization::Access::Protected | sle_authorization::Access::PrivilegedObserve) {
            sle_authorization::require_admin()?;
        }
        if matches!(cmd, SL_IOCTL_INJECT_ADV | SL_IOCTL_INJECT_RAW_ADV | SL_IOCTL_INJECT_CONN_RESP | SL_IOCTL_INJECT_CONN_DATA) {
            return Err(Error::from_errno(-(bindings::EOPNOTSUPP as i32)));
        }
        if matches!(cmd, SL_IOCTL_PM_INFO | SL_IOCTL_PM_SET_STATE | SL_IOCTL_PM_SET_INTERVAL
            | SL_IOCTL_PM_FORCE_ACTIVE | SL_IOCTL_PM_TICK | SL_IOCTL_PM_ACTIVITY) {
            return Err(Error::from_errno(-(bindings::EOPNOTSUPP as i32)));
        }
        // Unqualified legacy models are retired, even for privileged callers.
        if matches!(cmd,
            SL_IOCTL_MEAS_READ_CAP
            | SL_IOCTL_MEAS_SET_LINK_PARAM
            | SL_IOCTL_MEAS_ACTION
            | SL_IOCTL_MEAS_ENABLE
            | SL_IOCTL_DEV_SWITCH
            | SL_IOCTL_DLI_INFO
            | SL_IOCTL_DLI_RESET
            | SL_IOCTL_AFH_CLASSIFY
            | SL_IOCTL_AFH_GET_MAP
            | SL_IOCTL_AFH_HOP_NEXT
            | SL_IOCTL_AFH_REPORT_RETX
            | SL_IOCTL_AFH_REPORT_RSSI
            | SL_IOCTL_AFH_SET_MAP
            | SL_IOCTL_CLEAR_SCAN_FILTER
            | SL_IOCTL_CONNECT
            | SL_IOCTL_CONN_COUNT
            | SL_IOCTL_CONN_INFO
            | SL_IOCTL_CONN_LIST
            | SL_IOCTL_CONN_PHY_UPDATE
            | SL_IOCTL_CONN_READ_PEER_FEATURES
            | SL_IOCTL_CONN_READ_PEER_VERSION
            | SL_IOCTL_CONN_RECV
            | SL_IOCTL_CONN_SEND
            | SL_IOCTL_CONN_UPDATE_PARAMS
            | SL_IOCTL_DISCONNECT
            | SL_IOCTL_EXT_ADV_CONFIGURE
            | SL_IOCTL_EXT_ADV_DISABLE
            | SL_IOCTL_EXT_ADV_ENABLE
            | SL_IOCTL_EXT_ADV_ENABLE_EX
            | SL_IOCTL_EXT_ADV_INFO
            | SL_IOCTL_EXT_ADV_REMOVE
            | SL_IOCTL_EXT_ADV_SET_DATA
            | SL_IOCTL_EXT_ADV_SET_SCAN_RSP
            | SL_IOCTL_EXT_ADV_TICK
            | SL_IOCTL_GET_ROLE
            | SL_IOCTL_INJECT_CONN_DATA
            | SL_IOCTL_INJECT_CONN_RESP
            | SL_IOCTL_SCAN_RESULT_COUNT
            | SL_IOCTL_RAL_ADD
            | SL_IOCTL_RAL_CLEAR
            | SL_IOCTL_RAL_READ_LOCAL_RPA
            | SL_IOCTL_RAL_READ_PEER_RPA
            | SL_IOCTL_RAL_REMOVE
            | SL_IOCTL_RAL_SIZE
            | SL_IOCTL_RPA_ENABLE
            | SL_IOCTL_RPA_SET_TIMEOUT
            | SL_IOCTL_SEC_CONFIRM_PASSKEY
            | SL_IOCTL_SEC_ENCRYPT_ON
            | SL_IOCTL_SEC_GET_PASSKEY
            | SL_IOCTL_SEC_HMAC_TEST
            | SL_IOCTL_SEC_INFO
            | SL_IOCTL_SEC_INPUT_PASSKEY
            | SL_IOCTL_SEC_PAIR
            | SL_IOCTL_SEC_REJECT_PASSKEY
            | SL_IOCTL_SEC_RESET
            | SL_IOCTL_SEC_SET_OOB
            | SL_IOCTL_SEC_SET_PASSWORD
            | SL_IOCTL_SEC_SET_PSK
            | SL_IOCTL_SEC_SM3_TEST
            | SL_IOCTL_SEC_SM4_BLOCK_TEST
            | SL_IOCTL_SEC_SM4_DEC_TEST
            | SL_IOCTL_SEC_SM4_ENC_TEST
            | SL_IOCTL_SET_CONN_MTU
            | SL_IOCTL_SET_ROLE
            | SL_IOCTL_SET_SCAN_FILTER
            | SL_IOCTL_START_ADV
            | SL_IOCTL_START_SCAN
            | SL_IOCTL_STOP_ADV
            | SL_IOCTL_STOP_SCAN
            | SL_IOCTL_SYNC_DATAPATH_CFG
            | SL_IOCTL_SYNC_DATAPATH_REMOVE
            | SL_IOCTL_SYNC_DATA_SEND
            | SL_IOCTL_SYNC_INFO
            | SL_IOCTL_SYNC_MCAST_ACCEPT
            | SL_IOCTL_SYNC_MCAST_CREATE
            | SL_IOCTL_SYNC_MCAST_PARAM
            | SL_IOCTL_SYNC_MCAST_REJECT
            | SL_IOCTL_SYNC_MCAST_REMOVE
            | SL_IOCTL_SYNC_UCAST_ACCEPT
            | SL_IOCTL_SYNC_UCAST_CREATE
            | SL_IOCTL_SYNC_UCAST_PARAM
            | SL_IOCTL_SYNC_UCAST_REJECT
            | SL_IOCTL_SYNC_UCAST_REMOVE) {
            return Err(Error::from_errno(-(bindings::EOPNOTSUPP as i32)));
        }
        // Per-fd device routing: DEV_SELECT and DEV_GET_ACTIVE are handled
        // before capturing a RuntimeContext so they can query/set affinity.
        match cmd {
            SL_IOCTL_DEV_SELECT => return ioctl_dev_select(me, arg),
            SL_IOCTL_DEV_GET_ACTIVE => return ioctl_dev_get_active(me, arg),
            SL_IOCTL_REGISTRATION_SNAPSHOT => return ioctl_registration_snapshot(arg),
            _ => {}
        }

        let registry_operation = matches!(cmd,
            SL_IOCTL_DEV_COUNT | SL_IOCTL_DEV_LIST | SL_IOCTL_DEV_SWITCH
        );
        // Release the fd binding lock before taking the registry lock. read/poll
        // uses registry -> binding order; retaining this guard would invert it.
        let target = me.target.lock().clone();
        let context = if registry_operation {
            RuntimeContext { owner: None }
        } else {
            match target {
                Some(owner) => RuntimeContext::from_owner(owner),
                None => RuntimeContext { owner: None },
            }
        };
        let context = &context;
        if matches!(cmd, SL_IOCTL_MANAGEMENT_ACQUIRE | SL_IOCTL_MANAGEMENT_RELEASE | SL_IOCTL_MANAGEMENT_QUERY) {
            return ioctl_management(context, me, cmd, arg);
        }
        if cmd == SL_IOCTL_DLI_SEND_CMD {
            return Err(Error::from_errno(-(bindings::EOPNOTSUPP as i32)));
        }
        if cmd == SL_IOCTL_DIAGNOSTIC_SUBMIT {
            return ioctl_diagnostic_submit(context, me, arg);
        }
        // Admission serialization lasts through dispatch. Workers do not take
        // this mutex under the protocol mutex; revocation completion is in Host.
        let mut management_guard = if access == sle_authorization::Access::Protected && !registry_operation {
            context.owner.as_ref().map(|owner| owner.management.lock())
        } else { None };
        if let Some(gate) = management_guard.as_mut() {
            if *context.owner.as_ref().ok_or(ENODEV)?.schedule_gate.lock() { return Err(ENODEV); }
            let required_mode = if matches!(cmd, SL_IOCTL_DLI_SEND_CMD | SL_IOCTL_DLI_RESET) {
                sle_management::DIAGNOSTIC
            } else { sle_management::MANAGED };
            gate.authorize(me.file_id, required_mode).map_err(management_error)?;
        }

        match cmd {
            // --- Advertising, scanning, device management ---
            SL_IOCTL_START_ADV
            | SL_IOCTL_STOP_ADV
            | SL_IOCTL_START_SCAN
            | SL_IOCTL_STOP_SCAN
            | SL_IOCTL_DEV_COUNT
            | SL_IOCTL_DEV_INFO
                | SL_IOCTL_DEV_SWITCH
            | SL_IOCTL_DEV_LIST
            | SL_IOCTL_EXT_ADV_CONFIGURE
            | SL_IOCTL_EXT_ADV_SET_DATA
            | SL_IOCTL_EXT_ADV_SET_SCAN_RSP
            | SL_IOCTL_EXT_ADV_ENABLE
            | SL_IOCTL_EXT_ADV_DISABLE
            | SL_IOCTL_EXT_ADV_REMOVE
            | SL_IOCTL_EXT_ADV_INFO
            | SL_IOCTL_EXT_ADV_ENABLE_EX
            | SL_IOCTL_EXT_ADV_TICK
            | SL_IOCTL_INJECT_ADV
            | SL_IOCTL_INJECT_RAW_ADV
            | SL_IOCTL_SCAN_RESULT_COUNT
            | SL_IOCTL_SET_SCAN_FILTER
            | SL_IOCTL_CLEAR_SCAN_FILTER => ioctl_dispatch_adv(context, me, cmd, arg),
            // --- Connection management ---
            SL_IOCTL_CONNECT
            | SL_IOCTL_DISCONNECT
            | SL_IOCTL_CONN_INFO
            | SL_IOCTL_CONN_SEND
            | SL_IOCTL_CONN_RECV
            | SL_IOCTL_INJECT_CONN_RESP
            | SL_IOCTL_INJECT_CONN_DATA
            | SL_IOCTL_CONN_COUNT
            | SL_IOCTL_CONN_LIST
            | SL_IOCTL_SET_CONN_MTU
            | SL_IOCTL_CONN_READ_PEER_FEATURES
            | SL_IOCTL_CONN_READ_PEER_VERSION
            | SL_IOCTL_CONN_UPDATE_PARAMS
            | SL_IOCTL_CONN_PHY_UPDATE => ioctl_dispatch_conn(context, me, cmd, arg),
            // --- AFH and security ---
            SL_IOCTL_AFH_SET_MAP
            | SL_IOCTL_AFH_GET_MAP
            | SL_IOCTL_AFH_REPORT_RSSI
            | SL_IOCTL_AFH_CLASSIFY
            | SL_IOCTL_AFH_HOP_NEXT
            | SL_IOCTL_AFH_REPORT_RETX
            | SL_IOCTL_SEC_SET_PSK
            | SL_IOCTL_SEC_PAIR
            | SL_IOCTL_SEC_INFO
            | SL_IOCTL_SEC_ENCRYPT_ON
            | SL_IOCTL_SEC_SM3_TEST
            | SL_IOCTL_SEC_SM4_ENC_TEST
            | SL_IOCTL_SEC_SM4_DEC_TEST
            | SL_IOCTL_SEC_SM4_BLOCK_TEST
            | SL_IOCTL_SEC_HMAC_TEST
            | SL_IOCTL_SEC_RESET
            | SL_IOCTL_SEC_GET_PASSKEY
            | SL_IOCTL_SEC_CONFIRM_PASSKEY
            | SL_IOCTL_SEC_REJECT_PASSKEY
            | SL_IOCTL_SEC_SET_OOB
            | SL_IOCTL_SEC_INPUT_PASSKEY
            | SL_IOCTL_SEC_SET_PASSWORD => ioctl_dispatch_security(context, cmd, arg),
            // --- Infrastructure: PM, sync, DLI, events, PHY, role, RAL/RPA ---
            SL_IOCTL_PM_INFO
            | SL_IOCTL_PM_SET_STATE
            | SL_IOCTL_PM_SET_INTERVAL
            | SL_IOCTL_PM_FORCE_ACTIVE
            | SL_IOCTL_PM_TICK
            | SL_IOCTL_PM_ACTIVITY
            | SL_IOCTL_SYNC_UCAST_PARAM
            | SL_IOCTL_SYNC_UCAST_CREATE
            | SL_IOCTL_SYNC_UCAST_REMOVE
            | SL_IOCTL_SYNC_MCAST_PARAM
            | SL_IOCTL_SYNC_MCAST_CREATE
            | SL_IOCTL_SYNC_MCAST_REMOVE
            | SL_IOCTL_SYNC_DATAPATH_CFG
            | SL_IOCTL_SYNC_DATAPATH_REMOVE
            | SL_IOCTL_SYNC_INFO
            | SL_IOCTL_SYNC_UCAST_ACCEPT
            | SL_IOCTL_SYNC_UCAST_REJECT
            | SL_IOCTL_SYNC_MCAST_ACCEPT
            | SL_IOCTL_SYNC_MCAST_REJECT
            | SL_IOCTL_SYNC_DATA_SEND
            | SL_IOCTL_DLI_INFO
            | SL_IOCTL_CONTROLLER_EVENT_GET
            | SL_IOCTL_DIAGNOSTIC_RESULT
            | SL_IOCTL_SNOOP_GET
            | SL_IOCTL_CONTROLLER_SNAPSHOT
            | SL_IOCTL_SECURITY_NEGOTIATION_SUBMIT
            | SL_IOCTL_SECURITY_NEGOTIATION_RESULT
            | SL_IOCTL_SECURITY_NEGOTIATION_CANCEL
            | SL_IOCTL_SECURITY_NUMERIC_CONFIRM
            | SL_IOCTL_CONNECTION_SUBMIT
            | SL_IOCTL_CONNECTION_RESULT
            | SL_IOCTL_LINK_SNAPSHOT
            | SL_IOCTL_DISCOVERY_SUBMIT
            | SL_IOCTL_DISCOVERY_RESULT
            | SL_IOCTL_DISCOVERY_TIMING
            | SL_IOCTL_DLI_RESET
            | SL_IOCTL_DLI_SEND_CMD
            | SL_IOCTL_MGMT_STATS
            | SL_IOCTL_USB_DEV_COUNT
            | SL_IOCTL_PHY_INFO
            | SL_IOCTL_PHY_SET_MCS
            | SL_IOCTL_PHY_SET_TXPOWER
            | SL_IOCTL_PHY_MCS_SELECT
            | SL_IOCTL_PHY_HOP_NEXT
            | SL_IOCTL_PHY_SET_BW
            | SL_IOCTL_PHY_GET_SINR
            | SL_IOCTL_PHY_SET_SINR
            | SL_IOCTL_SET_ROLE
            | SL_IOCTL_GET_ROLE
            | SL_IOCTL_RAL_ADD
            | SL_IOCTL_RAL_REMOVE
            | SL_IOCTL_RAL_CLEAR
            | SL_IOCTL_RAL_SIZE
            | SL_IOCTL_RAL_READ_PEER_RPA
            | SL_IOCTL_RAL_READ_LOCAL_RPA
            | SL_IOCTL_RPA_ENABLE
            | SL_IOCTL_RPA_SET_TIMEOUT
            | SL_IOCTL_MEAS_READ_CAP
            | SL_IOCTL_MEAS_SET_LINK_PARAM
            | SL_IOCTL_MEAS_ACTION
            | SL_IOCTL_MEAS_ENABLE => ioctl_dispatch_infra(context, me, cmd, arg),
            _ => {
                // Invalid userspace requests are expected during probing and
                // fuzzing; keep their errno without flooding the kernel log.
                dev_dbg!(me.dev, "sparklink: unknown ioctl 0x{:x}\n", cmd);
                Err(ENOTTY)
            }
        }
    }
}


#[pinned_drop]
impl PinnedDrop for SparkLinkCtl {
    fn drop(self: Pin<&mut Self>) {
        if let Some(owner) = self.owned_target.lock().take() {
            let mut gate = owner.management.lock();
            if gate.owns(self.file_id) {
                let mode = gate.mode;
                let token = gate.token_for(self.file_id);
                let _ = gate.release(self.file_id, token);
                revoke_management(&owner, &mut gate, mode);
            }
        }
        OPEN_FD_COUNT.fetch_add(u32::MAX, Relaxed); // wrapping decrement
        dev_info!(self.dev, "sparklink: control interface closed\n");
    }
}
