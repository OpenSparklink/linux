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

mod sle_adv;
mod sle_authorization;
mod sle_management;
mod sle_configfs;
mod sle_conn;
mod sle_command_plan;
mod sle_discovery_operation;
mod sle_command_queue;
mod sle_controller_event;
mod sle_crypto;
mod sle_dev;
mod sle_dli;
mod sle_event;
mod sle_fw;
mod sle_host;
mod sle_irq_lock;
mod sle_mgmt;
mod sle_native;
mod sle_netlink;
mod sle_pdu;
mod sle_phy;
mod sle_power;
mod sle_security;
mod sle_snoop;
mod sle_serdev;
mod sle_spi;
mod sle_ssap;
mod sle_transport;
mod sle_uapi;
mod sle_uart;
mod sle_usb;
mod sle_workers;

use sle_dli::SleController;
use sle_uapi::*;
use sle_workers::{drain_controller_events, send_credit_grant};
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

use sle_adv::{AdvParams, AdvScanInner, ScanParams};
use sle_conn::{
    AccessResponseType, ConnManager, ConnState, GtRole, NegotiatedParams, CONN_DATA_MAX,
};
use sle_event::EventQueue;
use sle_power::PowerInner;
use sle_security::{RalEntry, RpaManager, SecurityInner};
use sle_ssap::SsapInner;

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

/// Get the current GT role (C FFI export). 0=TNode, 1=GNode.
#[no_mangle]
pub extern "C" fn sparklink_genl_get_role() -> u8 {
    let context = RuntimeContext::default_selection();
    let guard = context.lock().ok();
    let ss = guard.as_deref();
    match ss.and_then(Option::as_ref) {
        Some(shared) => shared.local_role as u8,
        None => 0,
    }
}

/// Set the local GT role (C FFI export). 0=TNode, 1=GNode.
/// Returns 0 on success, negative errno on failure.
#[no_mangle]
pub extern "C" fn sparklink_genl_set_role(role: u8) -> i32 {
    if let Err(error) = sle_authorization::require_admin() { return error.to_errno(); }
    let context = RuntimeContext::default_selection();
    if context.owner.as_ref().is_some_and(|owner| owner.protocol_profile != 0) { return EPERM.to_errno(); }
    let mut guard = context.lock().ok();
    let ss = guard.as_deref_mut();
    match ss.and_then(Option::as_mut) {
        Some(shared) => {
            shared.local_role = if role == 1 {
                GtRole::GNode
            } else {
                GtRole::TNode
            };
            0
        }
        None => -(bindings::ENODEV as i32),
    }
}

/// Connection info result for genl (C FFI).
///
/// Field order and explicit padding ensure identical layout on 32-bit
/// and 64-bit ABIs.  All u64 fields are placed at 8-byte aligned
/// offsets and explicit `_pad` fields replace compiler-inserted gaps.
#[repr(C)]
pub struct GenlConnInfo {
    /// Total TX bytes (offset 0, 8-byte aligned).
    pub tx_bytes: u64,
    /// Total RX bytes (offset 8).
    pub rx_bytes: u64,
    /// Connection handle (offset 16).
    pub handle: u16,
    /// Data channel MTU (offset 18).
    pub data_mtu: u16,
    /// Data channel MPS (offset 20).
    pub data_mps: u16,
    /// Service management channel MTU (offset 22).
    pub svc_mtu: u16,
    /// Peer SLE address (6 bytes, offset 24).
    pub peer_addr: [u8; 6],
    /// Connection state (offset 30).
    pub state: u8,
    /// Local GT role (0=T, 1=G) (offset 31).
    pub role: u8,
    /// Bandwidth in MHz (offset 32).
    pub bandwidth_mhz: u8,
    /// MCS index (offset 33).
    pub mcs_index: u8,
    /// Data channel transport mode (0=unreliable, 1=reliable) (offset 34).
    pub data_mode: u8,
    /// Explicit padding to 4-byte boundary (offset 35).
    pub _pad: [u8; 1],
}

/// Get connection info by handle (C FFI export).
/// Returns 0 on success, negative errno on failure.
///
/// # Safety
///
/// `out` must be a valid, aligned pointer to a `GenlConnInfo` struct.
#[no_mangle]
pub unsafe extern "C" fn sparklink_genl_get_conn_info(handle: u16, out: *mut GenlConnInfo) -> i32 {
    let context = RuntimeContext::default_selection();
    let guard = context.lock().ok();
    let ss = guard.as_deref();
    match ss.and_then(Option::as_ref) {
        Some(shared) => match shared.conn.info(handle) {
            Ok(entry) => {
                // SAFETY: caller guarantees out is a valid, aligned pointer.
                let info = unsafe { &mut *out };
                info.handle = entry.handle;
                info.state = entry.state as u8;
                info.role = entry.local_role as u8;
                info.peer_addr = entry.peer_addr;
                info.bandwidth_mhz = entry.params.bandwidth_mhz;
                info.mcs_index = entry.params.mcs_index;
                info.tx_bytes = entry.tx_bytes;
                info.rx_bytes = entry.rx_bytes;
                info.data_mtu = entry.channels.data.mtu;
                info.data_mps = entry.channels.data.mps;
                info.data_mode = entry.channels.data.mode as u8;
                info.svc_mtu = entry.channels.svc_mgmt.mtu;
                info._pad = [0];
                0
            }
            Err(_) => -(bindings::ENOENT as i32),
        },
        None => -(bindings::ENODEV as i32),
    }
}

/// Power management info result for genl (C FFI).
#[repr(C)]
pub struct GenlPmInfo {
    /// Power state.
    pub state: u8,
    /// Force-active flag.
    pub force_active: u8,
    /// Estimated power percentage.
    pub power_pct: u8,
    /// Padding.
    _pad: u8,
    /// State transition count.
    pub transitions: u32,
}

/// Get power management info (C FFI export).
///
/// # Safety
///
/// `out` must be a valid, aligned pointer to a `GenlPmInfo` struct.
#[no_mangle]
pub unsafe extern "C" fn sparklink_genl_get_pm_info(out: *mut GenlPmInfo) -> i32 {
    let context = RuntimeContext::default_selection();
    let guard = context.lock().ok();
    let ss = guard.as_deref();
    match ss.and_then(Option::as_ref) {
        Some(shared) => {
            // SAFETY: caller guarantees out is a valid, aligned pointer.
            let info = unsafe { &mut *out };
            info.state = shared.power.state as u8;
            info.force_active = if shared.power.is_forced_active() {
                1
            } else {
                0
            };
            info.power_pct = shared.power.estimated_power_pct();
            info._pad = 0;
            info.transitions = shared.power.stats.transitions;
            0
        }
        None => -(bindings::ENODEV as i32),
    }
}

/// DLI controller info result for genl (C FFI).
#[repr(C)]
pub struct GenlDliInfo {
    /// DLI bus type.
    pub bus_type: u8,
    /// Max concurrent connections.
    pub max_conn: u8,
    /// Supported transport modes (bitmask).
    pub transport_modes: u8,
    /// Measurement capabilities (bitmask).
    pub measurement_cap: u8,
    /// Firmware version.
    pub fw_version: u32,
    /// Feature bitmask.
    pub features: u64,
    /// Maximum MTU.
    pub max_mtu: u16,
    /// Maximum MPS.
    pub max_mps: u16,
    /// Security capabilities (bitmask).
    pub security_cap: u16,
    /// Extended feature bits 64-72.
    pub features_ext: u16,
}

/// Get DLI controller info (C FFI export).
///
/// # Safety
///
/// `out` must be a valid, aligned pointer to a `GenlDliInfo` struct.
#[no_mangle]
pub unsafe extern "C" fn sparklink_genl_get_dli_info(out: *mut GenlDliInfo) -> i32 {
    let context = RuntimeContext::default_selection();
    let guard = context.lock().ok();
    let ss = guard.as_deref();
    match ss.and_then(Option::as_ref) {
        Some(shared) => {
            let ci = shared.controller.info();
            // SAFETY: caller guarantees out is a valid, aligned pointer.
            let info = unsafe { &mut *out };
            info.bus_type = ci.bus as u8;
            info.max_conn = ci.max_connections;
            info.transport_modes = ci.transport_modes;
            info.measurement_cap = ci.measurement_cap;
            info.fw_version = ci.fw_version;
            info.features = ci.features;
            info.features_ext = ci.features_ext;
            info.max_mtu = ci.max_mtu;
            info.max_mps = ci.max_mps;
            info.security_cap = ci.security_cap;
            0
        }
        None => -(bindings::ENODEV as i32),
    }
}

// ---------------------------------------------------------------------------
// Generic Netlink C bridge (conditional on CONFIG_SPARKLINK_GENL)
// ---------------------------------------------------------------------------

#[cfg(CONFIG_SPARKLINK_GENL)]
mod genl_bridge {
    extern "C" {
        pub(crate) fn sparklink_genl_register() -> core::ffi::c_int;
        pub(crate) fn sparklink_genl_unregister();
        pub(crate) fn sparklink_genl_send_event(
            event_type: u8,
            handle: u16,
            addr: *const u8,
            addr_len: u32,
            payload: *const u8,
            payload_len: u32,
        ) -> core::ffi::c_int;
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

    /// Broadcast an event via genetlink multicast.
    pub(crate) fn notify_event(event_type: u8, handle: u16, addr: &[u8; 6]) {
        // SAFETY: sparklink_genl_send_event is defined in sparklink_genl.c
        unsafe {
            sparklink_genl_send_event(event_type, handle, addr.as_ptr(), 6, core::ptr::null(), 0);
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

    #[inline]
    pub(crate) fn notify_event(_event_type: u8, _handle: u16, _addr: &[u8; 6]) {}
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
pub(crate) const DLI_RING_SIZE: usize = 32;

/// Protocol state owned by one controller for its entire registration lifetime.
///
/// Constructed directly on the heap: the combined state is too large for the
/// kernel stack. Queues and privacy state belong to the same owner as its backend.
pub(crate) struct ControllerState {
    pub(crate) identity: sle_dev::DeviceIdentity,
    pub(crate) dev_info: SciDevInfo,
    pub(crate) controller: sle_dli::ControllerBackend,
    pub(crate) conn: ConnManager,
    pub(crate) adv_scan: AdvScanInner,
    pub(crate) security: SecurityInner,
    pub(crate) rpa: RpaManager,
    pub(crate) rpa_tick_accum: u16,
    pub(crate) ssap: SsapInner,
    pub(crate) power: PowerInner,
    pub(crate) phy: sle_phy::PhyConfig,
    pub(crate) local_role: GtRole,
    pub(crate) broadcast: sle_event::BroadcastRing,
    pub(crate) dli_ring: [SleDliEvent; DLI_RING_SIZE],
    pub(crate) dli_head: usize,
    pub(crate) dli_tail: usize,
    pub(crate) cmd_pending: sle_mgmt::CmdPendingQueue,
    pub(crate) cmd_queue: sle_mgmt::CmdRequestQueue,
    pub(crate) command_credits: u8,
}

impl ControllerState {
    #[inline(never)]
    pub(crate) fn new_boxed(addr: [u8; 6], backend: sle_dli::ControllerBackend) -> Result<KBox<Self>> {
        KBox::init(
            init!(ControllerState {
                identity: sle_dev::DeviceIdentity { id: u16::MAX, generation: 0 },
                dev_info: unsafe { core::mem::zeroed() },
                controller: backend,
                conn: ConnManager::new(addr),
                adv_scan: AdvScanInner::new(addr, b"sparklink"),
                security: SecurityInner::new(),
                rpa: RpaManager::new(),
                rpa_tick_accum: 0,
                ssap: SsapInner::new(),
                power: PowerInner::new(),
                phy: sle_phy::PhyConfig::default_config(),
                local_role: GtRole::TNode,
                broadcast <- sle_event::BroadcastRing::new_in_place(),
                // Initialize slots at their final address. A by-value zeroed
                // array can create a 16-KiB temporary after layout changes.
                dli_ring <- pin_init::init_array_from_fn(|_| SleDliEvent::default()),
                dli_head: 0,
                dli_tail: 0,
                cmd_pending <- sle_mgmt::CmdPendingQueue::new_in_place(),
                cmd_queue <- sle_mgmt::CmdRequestQueue::new_in_place(),
                command_credits: 1,
            }),
            GFP_KERNEL,
        )
    }

    pub(crate) fn process_ssap_pdu(&mut self, handle: u16, data: &[u8], response: &mut [u8]) -> Result<usize> {
        self.conn.process_ssap_pdu(handle, data, &mut self.ssap, response)
    }

    pub(crate) fn push_dli_event(&mut self, ev: SleDliEvent) {
        self.dli_ring[self.dli_tail] = ev;
        self.dli_tail = (self.dli_tail + 1) % DLI_RING_SIZE;
        if self.dli_tail == self.dli_head {
            self.dli_head = (self.dli_head + 1) % DLI_RING_SIZE;
        }
    }

    pub(crate) fn pop_dli_event(&mut self) -> Option<SleDliEvent> {
        if self.dli_head == self.dli_tail {
            return None;
        }
        let ev = self.dli_ring[self.dli_head];
        self.dli_head = (self.dli_head + 1) % DLI_RING_SIZE;
        Some(ev)
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
    /// Serializes native open against teardown, never protocol observation.
    #[pin]
    pub(crate) native_lifecycle: Mutex<()>,
    pub(crate) transport_open: core::sync::atomic::AtomicBool,
    #[pin]
    pub(crate) ingress: Lock<KBox<sle_dli::ControllerEventRing>, IrqLockBackend>,
    #[pin]
    pub(crate) host: Lock<KBox<sle_host::CommandHost>, IrqLockBackend>,
    #[pin]
    pub(crate) rx_work: DelayedWork<ControllerRuntime, 0>,
    #[pin]
    pub(crate) tx_work: DelayedWork<ControllerRuntime, 1>,
    #[pin]
    pub(crate) schedule_gate: Lock<bool, IrqLockBackend>,
    pub(crate) fast_poll_remaining: core::sync::atomic::AtomicU32,
    pub(crate) dropped_commands: core::sync::atomic::AtomicU32,
    pub(crate) dropped_mac: core::sync::atomic::AtomicU32,
}

impl ControllerRuntime {
    fn new(dev: &sle_dev::SleDev, mut state: KBox<ControllerState>) -> Result<Arc<Self>> {
        state.identity = dev.identity();
        state.dev_info.index = dev.id();
        state.dev_info.bus = dev.bus() as u8;
        state.dev_info.addr = SleAddr { b: *dev.addr() };
        let len = dev.name().len().min(state.dev_info.name.len());
        state.dev_info.name[..len].copy_from_slice(&dev.name()[..len]);
        let ingress = sle_dli::ControllerEventRing::new_boxed()?;
        let host = sle_host::CommandHost::new_boxed(state.command_credits)?;
        let controller_events = sle_controller_event::ControllerEventLog::new_boxed()?;
        let snoop = sle_snoop::SnoopLog::new_boxed()?;
        let protocol_profile = match &state.controller {
            sle_dli::ControllerBackend::Ws73(controller) => controller.profile(),
            _ => 0,
        };
        let initially_open = protocol_profile == 0;
        Arc::pin_init(pin_init!(Self {
            identity: dev.identity(),
            protocol_profile,
            management <- new_mutex!(sle_management::Management::new(), "sparklink_management"),
            controller_events <- new_irq_lock!(controller_events, "sparklink_controller_events"),
            controller_event_poll <- new_poll_condvar!("sparklink_controller_event"),
            snoop <- new_irq_lock!(snoop, "sparklink_snoop"),
            snoop_poll <- new_poll_condvar!("sparklink_snoop_poll"),
            state <- new_mutex!(Some(state), "sparklink_runtime"),
            native_lifecycle <- new_mutex!((), "sparklink_native_lifecycle"),
            transport_open: core::sync::atomic::AtomicBool::new(initially_open),
            ingress <- new_irq_lock!(ingress, "sparklink_runtime_rx"),
            host <- new_irq_lock!(host, "sparklink_runtime_host"),
            rx_work <- new_delayed_work!("sparklink_runtime_rx_work"),
            tx_work <- new_delayed_work!("sparklink_runtime_tx_work"),
            schedule_gate <- new_irq_lock!(false, "sparklink_runtime_schedule"),
            fast_poll_remaining: core::sync::atomic::AtomicU32::new(0),
            dropped_commands: core::sync::atomic::AtomicU32::new(0),
            dropped_mac: core::sync::atomic::AtomicU32::new(0),
        }), GFP_KERNEL)
    }

    /// Called in process context without the registry lock. In-flight protocol
    /// operations finish before invalidation; subsequent accesses get ENODEV.
    pub(crate) fn invalidate(self: &Arc<Self>) {
        // Close admission before waiting for a driver's blocking open. Its
        // eventual success may acquire resources, but cannot admit commands.
        *self.schedule_gate.lock() = true;
        self.transport_open.store(false, core::sync::atomic::Ordering::Release);
        self.management.lock().settled(ENODEV.to_errno());
        let _lifecycle = self.native_lifecycle.lock();
        sle_usb::unpublish_runtime(self);
        self.stop_workers();
        let state = self.state.lock().take();
        if let Some(state) = state {
            state.controller.close();
        }
        self.controller_event_poll.notify_all();
        self.snoop_poll.notify_all();
    }
}

/// Global metadata and compatibility default route; no protocol state bridge.
pub(crate) struct SubsystemShared {
    runtimes: [Option<Arc<ControllerRuntime>>; sle_dev::SLE_DEV_MAX],
    pub(crate) dev_registry: sle_dev::SleDevRegistry,
    pub(crate) active_dev_id: Option<u16>,
    pub(crate) proto_registry: sle_transport::SleProtoRegistry,
    pub(crate) dev_bindings: sle_transport::SleBindingTable,
}

struct RuntimeContext {
    owner: Option<Arc<ControllerRuntime>>,
}

impl RuntimeContext {
    fn default_selection() -> Self {
        let ss = SUBSYSTEM.lock();
        Self {
            owner: ss.as_ref().and_then(|s| s.active_dev_id.and_then(|id| s.runtime(id))),
        }
    }

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

    pub(crate) fn switch_to_device(&mut self, new_id: u16) -> Result {
        if self.dev_registry.get(new_id).is_none() || self.runtime(new_id).is_none() {
            return Err(ENODEV);
        }
        self.active_dev_id = Some(new_id);
        Ok(())
    }

    #[inline(never)]
    pub(crate) fn activate_new_device(&mut self, new_id: u16, state: KBox<ControllerState>) -> Result<Arc<ControllerRuntime>> {
        self.install_runtime(new_id, state, true)
    }

    pub(crate) fn install_runtime(&mut self, new_id: u16, state: KBox<ControllerState>, select: bool) -> Result<Arc<ControllerRuntime>> {
        let dev = self.dev_registry.get(new_id).ok_or(ENODEV)?;
        let slot = self.runtimes.get_mut(new_id as usize).ok_or(EINVAL)?;
        if slot.is_some() { return Err(EBUSY); }
        let runtime = ControllerRuntime::new(dev, state)?;
        *slot = Some(runtime.clone());
        if select { self.active_dev_id = Some(new_id); }
        Ok(runtime)
    }
}

pub(crate) fn runtime_snapshot() -> [Option<Arc<ControllerRuntime>>; sle_dev::SLE_DEV_MAX] {
    let ss = SUBSYSTEM.lock();
    core::array::from_fn(|id| ss.as_ref().and_then(|s| s.runtime(id as u16)))
}

pub(crate) fn runtime_by_id(id: u16) -> Option<Arc<ControllerRuntime>> {
    SUBSYSTEM.lock().as_ref().and_then(|s| s.runtime(id))
}

/// Probe may need the identity before its protocol Runtime is published.
pub(crate) fn registration_identity(id: u16) -> Option<sle_dev::DeviceIdentity> {
    SUBSYSTEM.lock().as_ref().and_then(|s| s.dev_registry.get(id).map(|d| d.identity()))
}

/// Stop protocol operations and workers before the transport frees resources.
/// The registry keeps the index reserved until the transport joins its URBs.
pub(crate) fn sle_quiesce_device(id: u16) {
    if let Some(owner) = runtime_by_id(id) { owner.invalidate(); }
}

// ---------------------------------------------------------------------------
// Transport device attach / detach (called from driver probe/remove)
// ---------------------------------------------------------------------------

/// Attach a newly-discovered physical device to the subsystem.
///
/// Called from USB probe, serdev probe, or any other transport driver's
/// hardware enumeration callback. Allocates a `SleDev` in the global
/// registry, creates a transport binding, and logs the attachment.
///
/// Returns the allocated device id on success.
pub(crate) fn sle_attach_device(info: &sle_transport::SleAttachInfo) -> Result<u16> {
    let mut ss = SUBSYSTEM.lock();
    let ss = Option::as_mut(&mut *ss).ok_or(ENODEV)?;

    // Look up the protocol to get bus type and defaults.
    let proto = ss.proto_registry.get(info.proto_id).ok_or(EINVAL)?;
    let bus = proto.bus;
    let default_pdu = proto.max_pdu;

    // Build a SleControllerInfo for device registration.
    let proto_name = proto.name;
    let name_bytes = proto_name.as_bytes();
    let mut name_buf = [0u8; 32];
    let copy_len = name_bytes.len().min(name_buf.len());
    name_buf[..copy_len].copy_from_slice(&name_bytes[..copy_len]);

    let ctrl_info = sle_dli::SleControllerInfo {
        name: name_buf,
        bus,
        addr: info.addr,
        fw_version: info.fw_version,
        features: info.features,
        features_ext: info.features_ext,
        max_pdu_payload: if info.max_pdu > 0 {
            info.max_pdu
        } else {
            default_pdu
        },
        max_connections: if info.max_connections > 0 {
            info.max_connections
        } else {
            8
        },
        ..Default::default()
    };

    // Register in the SleDev registry.
    let dev_id = ss.dev_registry.register(&ctrl_info)?;

    // Create the transport binding.
    let binding = sle_transport::SleDevBinding {
        dev_id,
        proto_id: info.proto_id,
        opened: false,
    };
    if let Err(e) = ss.dev_bindings.insert(binding) {
        let _ = ss.dev_registry.unregister(dev_id);
        return Err(e);
    }

    pr_info!(
        "sparklink: device sle{} attached via {} [{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}]\n",
        dev_id,
        proto_name,
        info.addr[0],
        info.addr[1],
        info.addr[2],
        info.addr[3],
        info.addr[4],
        info.addr[5],
    );

    Ok(dev_id)
}

/// Detach a device from the subsystem.
///
/// Called from USB disconnect, serdev remove, or module unload cleanup.
/// Removes the transport binding and unregisters the SleDev.  If the
/// device was the active one, reverts to the no-controller state.  If it
/// was inactive, its saved state is discarded.
pub(crate) fn sle_detach_device(dev_id: u16) {
    let owner = {
        let mut guard = SUBSYSTEM.lock();
        let Some(ss) = Option::as_mut(&mut *guard) else { return };
        ss.dev_bindings.remove(dev_id);
        if ss.active_dev_id == Some(dev_id) { ss.active_dev_id = None; }
        ss.runtimes.get_mut(dev_id as usize).and_then(Option::take)
    };
    if let Some(owner) = owner { owner.invalidate(); }
    let mut guard = SUBSYSTEM.lock();
    if let Some(ss) = Option::as_mut(&mut *guard) {
        let _ = ss.dev_registry.unregister(dev_id);
        pr_info!("sparklink: device sle{} detached\n", dev_id);
    }
}

// ---------------------------------------------------------------------------
// Unified control plane operations (shared by ioctl + genetlink)
// ---------------------------------------------------------------------------

/// Start advertising / broadcast with the given interval.
fn do_start_adv(context: &RuntimeContext, interval_ms: u32, discovery_level: u8) -> Result<i32> {
    let mode = sle_configfs::power_mode();
    if mode >= 2 {
        return Err(EPERM);
    }
    let interval = if interval_ms == 0 {
        u32::from(sle_configfs::adv_interval_ms())
    } else {
        interval_ms
    };
    let params = AdvParams {
        discovery_level,
        interval_slots: interval * 8,
        broadcast_type: sle_pdu::BroadcastType::AccessibleScannable,
        tx_power: 0,
    };
    let mut ss = context.lock()?;
    let s = Option::as_mut(&mut *ss).ok_or(ENODEV)?;
    if s.local_role != GtRole::GNode {
        return Err(EPERM);
    }
    s.adv_scan.start_advertising(params)?;
    // Collect registered SSAP service UUIDs for advertising payload
    let mut std_uuids = [0u16; 32];
    let std_count = s.ssap.collect_std_uuids(&mut std_uuids);
    let mut custom_uuids = [[0u8; 16]; 8];
    let custom_count = s.ssap.collect_custom_uuids(&mut custom_uuids);
    let _ = s.adv_scan.build_adv_pdu(
        &std_uuids[..std_count],
        &custom_uuids[..custom_count],
    );
    match s.controller.enable_broadcast(true) {
        Ok(()) => {
            drain_controller_events(s);
        }
        Err(e) => {
            s.adv_scan.abort_advertising();
            return Err(e);
        }
    }
    Ok(0)
}

/// Stop advertising / broadcast.
fn do_stop_adv(context: &RuntimeContext) -> Result<i32> {
    let mut ss = context.lock()?;
    let s = Option::as_mut(&mut *ss).ok_or(ENODEV)?;
    if !s.adv_scan.is_advertising() { return Err(EBUSY); }
    s.controller.enable_broadcast(false)?;
    s.adv_scan.stop_advertising()?;
    Ok(0)
}

/// Start scanning with the given window and interval.
fn do_start_scan(context: &RuntimeContext, window_ms: u32, interval_ms: u32, filter_level: u8) -> Result<i32> {
    let mode = sle_configfs::power_mode();
    if mode >= 2 {
        return Err(EPERM);
    }
    let window = if window_ms == 0 {
        u32::from(sle_configfs::scan_window_ms())
    } else {
        window_ms
    };
    let interval = if interval_ms == 0 {
        window * 2
    } else {
        interval_ms
    };
    let params = ScanParams {
        window_slots: window * 8,
        interval_slots: interval * 8,
        filter_level,
        active: false,
    };
    let mut ss = context.lock()?;
    let s = Option::as_mut(&mut *ss).ok_or(ENODEV)?;
    if s.local_role != GtRole::TNode {
        return Err(EPERM);
    }
    s.adv_scan.start_scanning(params)?;
    match s.controller.enable_scan(true) {
        Ok(()) => {
            drain_controller_events(s);
        }
        Err(e) => {
            s.adv_scan.abort_scanning();
            return Err(e);
        }
    }
    Ok(0)
}

/// Stop scanning.
fn do_stop_scan(context: &RuntimeContext) -> Result<i32> {
    let mut ss = context.lock()?;
    let s = Option::as_mut(&mut *ss).ok_or(ENODEV)?;
    if !s.adv_scan.is_scanning() { return Err(EBUSY); }
    s.controller.enable_scan(false)?;
    s.adv_scan.stop_scanning()?;
    Ok(0)
}

// ---------------------------------------------------------------------------
// C FFI exports for genetlink action commands
// ---------------------------------------------------------------------------

/// Start advertising (C FFI). Returns 0 on success, negative errno on failure.
#[no_mangle]
pub extern "C" fn sparklink_do_start_adv(interval_ms: u32, discovery_level: u8) -> i32 {
    if let Err(error) = sle_authorization::require_admin() { return error.to_errno(); }
    let context = RuntimeContext::default_selection();
    if context.owner.as_ref().is_some_and(|owner| owner.protocol_profile != 0) { return EPERM.to_errno(); }
    let context = &context;
    match do_start_adv(context, interval_ms, discovery_level) {
        Ok(v) => v,
        Err(e) => e.to_errno(),
    }
}

/// Stop advertising (C FFI). Returns 0 on success, negative errno on failure.
#[no_mangle]
pub extern "C" fn sparklink_do_stop_adv() -> i32 {
    if let Err(error) = sle_authorization::require_admin() { return error.to_errno(); }
    let context = RuntimeContext::default_selection();
    if context.owner.as_ref().is_some_and(|owner| owner.protocol_profile != 0) { return EPERM.to_errno(); }
    let context = &context;
    match do_stop_adv(context) {
        Ok(v) => v,
        Err(e) => e.to_errno(),
    }
}

/// Start scanning (C FFI). Returns 0 on success, negative errno on failure.
#[no_mangle]
pub extern "C" fn sparklink_do_start_scan(
    window_ms: u32,
    interval_ms: u32,
    filter_level: u8,
) -> i32 {
    if let Err(error) = sle_authorization::require_admin() { return error.to_errno(); }
    let context = RuntimeContext::default_selection();
    if context.owner.as_ref().is_some_and(|owner| owner.protocol_profile != 0) { return EPERM.to_errno(); }
    let context = &context;
    match do_start_scan(context, window_ms, interval_ms, filter_level) {
        Ok(v) => v,
        Err(e) => e.to_errno(),
    }
}

/// Stop scanning (C FFI). Returns 0 on success, negative errno on failure.
#[no_mangle]
pub extern "C" fn sparklink_do_stop_scan() -> i32 {
    if let Err(error) = sle_authorization::require_admin() { return error.to_errno(); }
    let context = RuntimeContext::default_selection();
    if context.owner.as_ref().is_some_and(|owner| owner.protocol_profile != 0) { return EPERM.to_errno(); }
    let context = &context;
    match do_stop_scan(context) {
        Ok(v) => v,
        Err(e) => e.to_errno(),
    }
}

/// Switch the subsystem controller backend to USB.
///
/// Called from USB probe after sle_attach_device and C-side registration
/// succeed. Creates per-device protocol state and switches the active
/// device by selecting its fixed Runtime slot. Other owners remain in place.
pub(crate) fn sle_switch_controller_usb(dev_id: u16, addr: [u8; 6], fw_version: u32, credits: u8) -> Result {
    let result = (|| -> Result<Arc<ControllerRuntime>> {
        let identity = registration_identity(dev_id).ok_or(ENODEV)?;
        let backend = sle_dli::ControllerBackend::new_usb(addr, identity);
        let mut state = ControllerState::new_boxed(addr, backend)?;
        state.command_credits = credits;
        let mut guard = SUBSYSTEM.lock();
        let ss = Option::as_mut(&mut *guard).ok_or(ENODEV)?;
        ss.dev_registry.update_hw_info(dev_id, addr, fw_version);
        ss.activate_new_device(dev_id, state)
    })();
    match result {
        Ok(owner) => {
            sle_usb::publish_runtime(&owner);
            let mut guard = owner.state.lock();
            if let Some(state) = Option::as_mut(&mut *guard) {
                if let Err(e) = state.controller.open() {
                    return Err(e);
                }
            }
            drop(guard);
            owner.start_workers();
            pr_info!("sparklink: controller switched to USB (sle{})\n", dev_id);
            Ok(())
        }
        Err(e) => Err(e),
    }
}

pub(crate) fn sle_suspend_device(dev_id: u16) {
    if let Some(owner) = runtime_by_id(dev_id) {
        if let Some(state) = Option::as_mut(&mut *owner.state.lock()) { let _ = state.power.suspend(); }
    }
}

pub(crate) fn sle_resume_device(dev_id: u16) {
    if let Some(owner) = runtime_by_id(dev_id) {
        if let Some(state) = Option::as_mut(&mut *owner.state.lock()) { state.power.resume(); }
    }
}

pub(crate) fn sle_switch_controller_serdev(dev_id: u16, addr: [u8; 6], fw_version: u32) {
    let result = (|| -> Result<Arc<ControllerRuntime>> {
        let backend = sle_dli::ControllerBackend::new_serdev(addr, dev_id);
        let state = ControllerState::new_boxed(addr, backend)?;
        let mut guard = SUBSYSTEM.lock();
        let ss = Option::as_mut(&mut *guard).ok_or(ENODEV)?;
        ss.dev_registry.update_hw_info(dev_id, addr, fw_version);
        ss.activate_new_device(dev_id, state)
    })();
    match result {
        Ok(owner) => owner.start_workers(),
        Err(e) => pr_err!("sparklink: activating serdev Runtime failed: {:?}\n", e),
    }
}

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
    adv_count: File<Atomic<usize>>,
    #[pin]
    scan_count: File<Atomic<usize>>,
    #[pin]
    conn_count: File<Atomic<usize>>,
    #[pin]
    ioctl_count: File<Atomic<usize>>,
    #[pin]
    _dli_info: File<Atomic<u32>>,
    _mgmt_dir: Dir,
    #[pin]
    _mgmt_stats: File<Atomic<u32>>,
    _transport_dir: Dir,
    #[pin]
    _transport_info: File<Atomic<u32>>,
    _power_dir: Dir,
    #[pin]
    _power_stats: File<Atomic<u32>>,
    _conn_dir: Dir,
    #[pin]
    _conn_stats: File<Atomic<u32>>,
    #[pin]
    _device_list: File<Atomic<u32>>,
}

#[pin_data]
struct SparkLinkModule {
    #[pin]
    _miscdev: MiscDeviceRegistration<SparkLinkCtl>,
    _debugfs_holder: Pin<KBox<DebugfsHolder>>,
    _genl: genl_bridge::GenlGuard,
    #[pin]
    _configfs: configfs::Subsystem<sle_configfs::SparkLinkConfig>,
    #[pin]
    _usb: sle_usb::UsbRegistration,
    /// Dropped LAST — after _miscdev closes all fds.
    _subsystem_guard: SubsystemGuard,
}

#[inline(never)]
fn init_version_string() -> Result<CString> {
    CString::try_from_fmt(fmt!("sparklink 0.3.0"))
}

#[inline(never)]
fn init_build_string() -> Result<CString> {
    CString::try_from_fmt(fmt!("sparklink subsystem\nstandard: T/XS 10002-2025, T/XS 20001-2025, T/XS 10003-2025\nmodules: core pdu adv conn crypto security ssap power event dli usb netlink\nlanguage: Rust"))
}

#[inline(never)]
fn init_subsys_string() -> Result<CString> {
    CString::try_from_fmt(fmt!("sle_pdu: frame codec\nsle_adv: advertising/scanning\nsle_conn: connection management\nsle_crypto: SM3/SM4 crypto\nsle_security: pairing/encryption\nsle_ssap: service access protocol\nsle_power: power management\nsle_event: async event notification\nsle_dli: driver layer interface\nsle_usb: USB transport\nsle_netlink: Generic Netlink protocol"))
}

#[inline(never)]
fn init_debugfs() -> Result<Pin<KBox<DebugfsHolder>>> {
    let ver = init_version_string()?;
    let build = init_build_string()?;
    let subsys = init_subsys_string()?;

    let debugfs = Dir::new(c"sparklink");
    let mgmt_dir = debugfs.subdir(c"mgmt");
    let transport_dir = debugfs.subdir(c"transport");
    let power_dir = debugfs.subdir(c"power");
    let conn_dir = debugfs.subdir(c"connections");

    KBox::pin_init(
        pin_init!(DebugfsHolder {
            _version <- debugfs.read_only_file(c"version", ver),
            _build_info <- debugfs.read_only_file(c"build_info", build),
            _subsystems <- debugfs.read_only_file(c"subsystems", subsys),
            adv_count <- debugfs.read_write_file(c"adv_count", Atomic::<usize>::new(0)),
            scan_count <- debugfs.read_write_file(c"scan_count", Atomic::<usize>::new(0)),
            conn_count <- debugfs.read_write_file(c"conn_count", Atomic::<usize>::new(0)),
            ioctl_count <- debugfs.read_write_file(c"ioctl_count", Atomic::<usize>::new(0)),
            _dli_info <- debugfs.read_callback_file(
                c"dli_controller",
                Atomic::<u32>::new(0),
                &|_dummy: &Atomic<u32>, f: &mut core::fmt::Formatter<'_>| {
                    let context = RuntimeContext::default_selection();
                    if let Ok(guard) = context.lock() {
                        let ss = guard.as_ref().expect("validated live Runtime");
                        let cinfo = ss.controller.info();
                        let major = (cinfo.fw_version >> 16) & 0xFF;
                        let minor = (cinfo.fw_version >> 8) & 0xFF;
                        let patch = cinfo.fw_version & 0xFF;
                        writeln!(f, "bus: {:?}", cinfo.bus)?;
                        writeln!(f, "firmware: {}.{}.{}", major, minor, patch)?;
                        writeln!(f, "features: 0x{:016x}", cinfo.features)?;
                        writeln!(f, "features_ext: 0x{:04x}", cinfo.features_ext)?;
                        writeln!(f, "max_connections: {}", cinfo.max_connections)?;
                        writeln!(f, "max_mtu: {}", cinfo.max_mtu)?;
                        writeln!(f, "max_mps: {}", cinfo.max_mps)?;
                        writeln!(f, "transport_modes: 0x{:02x}", cinfo.transport_modes)?;
                        writeln!(f, "measurement_cap: 0x{:02x}", cinfo.measurement_cap)?;
                        writeln!(f, "security_cap: 0x{:04x}", cinfo.security_cap)?;
                    }
                    Ok(())
                },
            ),
            _mgmt_stats <- mgmt_dir.read_callback_file(
                c"stats",
                Atomic::<u32>::new(0),
                &|_dummy: &Atomic<u32>, f: &mut core::fmt::Formatter<'_>| {
                    let context = RuntimeContext::default_selection();
                    if let Ok(guard) = context.lock() {
                        let ss = guard.as_ref().expect("validated live Runtime");
                        let q = &ss.cmd_pending;
                        writeln!(f, "pending: {}", q.pending_count)?;
                        writeln!(f, "submitted: {}", q.total_submitted)?;
                        writeln!(f, "resolved: {}", q.total_resolved)?;
                        writeln!(f, "timeouts: {}", q.total_timeouts)?;
                        writeln!(f, "cmd_queue_depth: {}", ss.cmd_queue.len())?;
                    }
                    Ok(())
                },
            ),
            _mgmt_dir: mgmt_dir,
            _transport_info <- transport_dir.read_callback_file(
                c"info",
                Atomic::<u32>::new(0),
                &|_dummy: &Atomic<u32>, f: &mut core::fmt::Formatter<'_>| {
                    let ss = SUBSYSTEM.lock();
                    if let Some(ref ss) = *ss {
                        writeln!(f, "protocols_registered: {}", ss.proto_registry.count())?;
                        writeln!(f, "devices_bound: {}", ss.dev_bindings.count())?;
                        for proto in ss.proto_registry.iter() {
                            writeln!(f, "  proto: {} (bus={:?}, max_pdu={})",
                                proto.name, proto.bus, proto.max_pdu)?;
                        }
                    }
                    Ok(())
                },
            ),
            _transport_dir: transport_dir,
            _power_stats <- power_dir.read_callback_file(
                c"stats",
                Atomic::<u32>::new(0),
                &|_dummy: &Atomic<u32>, f: &mut core::fmt::Formatter<'_>| {
                    let context = RuntimeContext::default_selection();
                    if let Ok(guard) = context.lock() {
                        let ss = guard.as_ref().expect("validated live Runtime");
                        let p = &ss.power;
                        writeln!(f, "state: {:?}", p.state)?;
                        writeln!(f, "forced_active: {}", p.is_forced_active())?;
                        writeln!(f, "active_events: {}", p.stats.active_events)?;
                        writeln!(f, "sniff_events: {}", p.stats.sniff_events)?;
                        writeln!(f, "idle_events: {}", p.stats.idle_events)?;
                        writeln!(f, "transitions: {}", p.stats.transitions)?;
                        writeln!(f, "force_active_count: {}", p.stats.force_active_count)?;
                        writeln!(f, "supervision_warnings: {}", p.stats.supervision_warnings)?;
                    }
                    Ok(())
                },
            ),
            _power_dir: power_dir,
            _conn_stats <- conn_dir.read_callback_file(
                c"stats",
                Atomic::<u32>::new(0),
                &|_dummy: &Atomic<u32>, f: &mut core::fmt::Formatter<'_>| {
                    let context = RuntimeContext::default_selection();
                    if let Ok(guard) = context.lock() {
                        let ss = guard.as_ref().expect("validated live Runtime");
                        writeln!(f, "active: {}", ss.conn.active_count())?;
                        writeln!(f, "total_created: {}", ss.conn.total_created)?;
                        writeln!(f, "total_completed: {}", ss.conn.total_completed)?;
                    }
                    Ok(())
                },
            ),
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

impl kernel::InPlaceModule for SparkLinkModule {
    fn init(_module: &'static ThisModule) -> impl PinInit<Self, Error> {
        pr_info!("sparklink: initialising SparkLink subsystem v0.3.0\n");

        // SAFETY: Called exactly once during module init.
        unsafe { SUBSYSTEM.init() };
        // SAFETY: Called exactly once during module init.
        unsafe { sle_serdev::init_serdev_parser() };
        // SAFETY: Called exactly once during module init.
        unsafe { sle_usb::init_usb_event_ring() };

        let options = MiscDeviceOptions { name: c"sparklink" };

        try_pin_init!(Self {
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
                        max_connections: 1,
                        adv_interval_ms: 2,
                        scan_window_ms: 3,
                        power_mode: 4,
                        controller_type: 5,
                    ],
                };
                configfs::Subsystem::new(
                    c"sparklink",
                    item_type,
                    SparkLinkConfig::new(),
                )
            },
            _subsystem_guard: init_subsystem()?,
            _usb <- sle_usb::UsbRegistration::new(c"sparklink_usb", _module),
        })
    }
}

#[inline(never)]
fn init_subsystem() -> Result<SubsystemGuard> {
    let mut ss = SUBSYSTEM.lock();
    let addr = [0x5E, 0x00, 0x00, 0x00, 0x00, 0x01];
    let controller = match sle_configfs::controller_type() {
        1 => sle_dli::ControllerBackend::new_uart(addr, sle_uart::UartConfig::default()),
        2 => sle_dli::ControllerBackend::new_spi(addr, sle_spi::SpiConfig::default()),
        _ => sle_dli::ControllerBackend::new_none(),
    };
    // Only open if a real backend was configured; None is deferred
    // until a USB/serdev device attaches.
    let _ = controller.open();

    let mut runtime = ControllerState::new_boxed(addr, controller)?;
    runtime.conn.set_max_connections(sle_configfs::max_connections() as usize);

    let mut proto_registry = sle_transport::SleProtoRegistry::new();
    sle_transport::register_builtin_protos(&mut proto_registry);

    let mut dev_registry = sle_dev::SleDevRegistry::new();
    // Only register a device at init if a real controller backend is
    // configured (UART/SPI via configfs).  For None (the default),
    // the first device is registered when a USB/serdev driver probes.
    let dev_id = if !runtime.controller.is_none() {
        let ctrl_info = runtime.controller.info();
        dev_registry.register(&ctrl_info).ok()
    } else {
        None
    };

    let mut runtimes = core::array::from_fn(|_| None);
    if let Some(id) = dev_id {
        runtimes[id as usize] = Some(ControllerRuntime::new(dev_registry.get(id).ok_or(ENODEV)?, runtime)?);
    }
    *ss = Some(KBox::init(
        init!(SubsystemShared {
            runtimes,
            dev_registry,
            active_dev_id: dev_id,
            proto_registry,
            dev_bindings: sle_transport::SleBindingTable::new(),
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
    #[pin]
    operation: Mutex<()>,
    #[pin]
    owned_target: Mutex<Option<Arc<ControllerRuntime>>>,
    #[pin]
    events: Mutex<EventQueue>,
    #[pin]
    event_poll: PollCondVar,
    dev: ARef<Device>,
    /// Broadcast ring cursor: sequence number of the last event this fd has seen.
    last_seq: core::sync::atomic::AtomicU64,
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
fn ioctl_dispatch_adv(context: &RuntimeContext, me: Pin<&SparkLinkCtl>, cmd: u32, arg: usize) -> Result<isize> {
    match cmd {
        SL_IOCTL_START_ADV
        | SL_IOCTL_STOP_ADV
        | SL_IOCTL_START_SCAN
        | SL_IOCTL_STOP_SCAN
        | SL_IOCTL_DEV_COUNT
        | SL_IOCTL_DEV_INFO
        | SL_IOCTL_DEV_REGISTER
        | SL_IOCTL_DEV_UNREGISTER
        | SL_IOCTL_DEV_SWITCH
        | SL_IOCTL_DEV_LIST
        | SL_IOCTL_SCAN_RESULT_COUNT
        | SL_IOCTL_SET_SCAN_FILTER
        | SL_IOCTL_CLEAR_SCAN_FILTER => ioctl_dispatch_adv_basic(context, me, cmd, arg),
        SL_IOCTL_EXT_ADV_CONFIGURE
        | SL_IOCTL_EXT_ADV_SET_DATA
        | SL_IOCTL_EXT_ADV_SET_SCAN_RSP
        | SL_IOCTL_EXT_ADV_ENABLE
        | SL_IOCTL_EXT_ADV_DISABLE
        | SL_IOCTL_EXT_ADV_REMOVE
        | SL_IOCTL_EXT_ADV_INFO
        | SL_IOCTL_EXT_ADV_ENABLE_EX
        | SL_IOCTL_EXT_ADV_TICK => ioctl_dispatch_ext_adv(context, cmd, arg),
        SL_IOCTL_INJECT_ADV => ioctl_inject_adv(context, me, arg),
        SL_IOCTL_INJECT_RAW_ADV => ioctl_inject_raw_adv(context, arg),
        _ => Err(EINVAL),
    }
}

/// DEV_SWITCH ioctl — changes only the legacy selection index.
#[inline(never)]
fn ioctl_dev_switch(arg: usize) -> Result<isize> {
    let target_id: u16 = read_user_struct(arg)?;
    let mut ss = SUBSYSTEM.lock();
    let s = Option::as_mut(&mut *ss).ok_or(ENODEV)?;
    if s.dev_registry.get(target_id).is_none() {
        return Err(ENODEV);
    }
    s.switch_to_device(target_id)?;
    pr_info!("sparklink: switched active device to sle{}\n", target_id);
    Ok(0)
}

/// DEV_SELECT ioctl — per-fd device affinity.
///
/// Sets which controller this fd targets.  -1 means follow the global
/// active_dev_id; ≥0 binds the fd to that specific controller.  On each
/// subsequent ioctl the handler will auto-switch if needed.
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
    // Events queued for a previous selection must not masquerade as the new one.
    *me.events.lock() = EventQueue::new();
    me.last_seq.store(sle_event::BroadcastRing::current_seq(), core::sync::atomic::Ordering::Relaxed);
    Ok(0)
}

/// DEV_GET_ACTIVE reports the binding even when it is stale after removal.
#[inline(never)]
fn ioctl_dev_get_active(me: Pin<&SparkLinkCtl>, arg: usize) -> Result<isize> {
    let target = me.target.lock().clone();
    let effective = match target {
        Some(owner) => owner.identity.id,
        None => SUBSYSTEM.lock().as_ref().ok_or(ENODEV)?.active_dev_id.unwrap_or(0xFFFF),
    };
    write_user_struct(arg, &effective)?;
    Ok(0)
}

/// Basic adv/scan/dev ioctl sub-dispatcher.
#[inline(never)]
fn ioctl_dispatch_adv_basic(context: &RuntimeContext, me: Pin<&SparkLinkCtl>, cmd: u32, arg: usize) -> Result<isize> {
    match cmd {
        SL_IOCTL_START_ADV => {
            let uparams: SleAdvParams = read_user_struct(arg)?;
            do_start_adv(context, u32::from(uparams.interval_ms), uparams.discovery_level)?;
            Ok(0)
        }
        SL_IOCTL_STOP_ADV => {
            do_stop_adv(context)?;
            Ok(0)
        }
        SL_IOCTL_START_SCAN => {
            let uparams: SleScanParams = read_user_struct(arg)?;
            do_start_scan(context,
                u32::from(uparams.window_ms),
                u32::from(uparams.interval_ms),
                uparams.filter_discovery_level,
            )?;
            Ok(0)
        }
        SL_IOCTL_STOP_SCAN => {
            do_stop_scan(context)?;
            Ok(0)
        }
        SL_IOCTL_DEV_COUNT => {
            let ss = SUBSYSTEM.lock();
            let count = ss.as_ref().map_or(0, |s| s.dev_registry.count());
            Ok(count as isize)
        }
        SL_IOCTL_DEV_INFO => {
            let ss = context.lock()?;
            let s = ss.as_ref().ok_or(ENODEV)?;
            let mut info = s.dev_info;
            info.state = if s.adv_scan.is_advertising() { SciState::Advertising as u8 }
                else if s.adv_scan.is_scanning() { SciState::Scanning as u8 }
                else { SciState::Idle as u8 };
            drop(ss);
            write_user_struct(arg, &info)?;
            Ok(0)
        }
        SL_IOCTL_DEV_REGISTER => {
            dev_info!(
                me.dev,
                "sparklink: DEV_REGISTER via ioctl (use module init for real registration)\n"
            );
            Ok(0)
        }
        SL_IOCTL_DEV_UNREGISTER => {
            dev_info!(
                me.dev,
                "sparklink: DEV_UNREGISTER via ioctl (use module unload for real unregistration)\n"
            );
            Ok(0)
        }
        SL_IOCTL_DEV_SWITCH => ioctl_dev_switch(arg),
        SL_IOCTL_DEV_LIST => {
            let ss = SUBSYSTEM.lock();
            let s = ss.as_ref().ok_or(ENODEV)?;
            let mask = s.dev_registry.allocated_mask();
            drop(ss);
            write_user_struct(arg, &mask)?;
            Ok(0)
        }
        SL_IOCTL_SCAN_RESULT_COUNT => {
            let mut ss = context.lock()?;
            let s = Option::as_mut(&mut *ss).ok_or(ENODEV)?;
            drain_controller_events(s);
            let count = s.adv_scan.scan_result_count();
            Ok(count as isize)
        }
        SL_IOCTL_SET_SCAN_FILTER => {
            let params: SleScanFilter = read_user_struct(arg)?;
            let count = (params.uuid_count as usize).min(sle_adv::SCAN_FILTER_MAX_UUIDS);
            let mut filter = sle_adv::ScanFilter::default();
            filter.uuid_count = count as u8;
            filter.uuids[..count].copy_from_slice(&params.uuids[..count]);
            let mut ss = context.lock()?;
            let s = Option::as_mut(&mut *ss).ok_or(ENODEV)?;
            s.adv_scan.set_scan_filter(filter);
            Ok(0)
        }
        SL_IOCTL_CLEAR_SCAN_FILTER => {
            let mut ss = context.lock()?;
            let s = Option::as_mut(&mut *ss).ok_or(ENODEV)?;
            s.adv_scan.clear_scan_filter();
            Ok(0)
        }
        _ => Err(EINVAL),
    }
}

/// Extended advertising ioctl sub-dispatcher.
#[inline(never)]
fn ioctl_dispatch_ext_adv(context: &RuntimeContext, cmd: u32, arg: usize) -> Result<isize> {
    match cmd {
        SL_IOCTL_EXT_ADV_CONFIGURE => {
            let cfg: SleExtAdvConfig = read_user_struct(arg)?;
            let primary_phy = sle_adv::ExtAdvPhy::from_raw(cfg.primary_phy).ok_or(EINVAL)?;
            let secondary_phy = sle_adv::ExtAdvPhy::from_raw(cfg.secondary_phy).ok_or(EINVAL)?;
            let bcast = sle_pdu::BroadcastType::from_raw(cfg.broadcast_type).ok_or(EINVAL)?;
            let params = sle_adv::ExtAdvParams {
                discovery_level: cfg.discovery_level,
                interval_slots: u32::from(cfg.interval_ms) * 8,
                broadcast_type: bcast,
                tx_power: cfg.tx_power_dbm,
                primary_phy,
                secondary_phy,
                sid: cfg.sid,
                include_tx_power: cfg.include_tx_power != 0,
                extended_adv_timing: cfg.ext_adv_timing,
            };
            let mut ss = context.lock()?;
            let s = Option::as_mut(&mut *ss).ok_or(ENODEV)?;
            s.adv_scan.ext_adv_configure(cfg.handle, params)?;
            Ok(0)
        }
        SL_IOCTL_EXT_ADV_SET_DATA => {
            let d: SleExtAdvData = read_user_struct(arg)?;
            let len = (d.data_len as usize).min(ADV_DATA_MAX);
            let mut ss = context.lock()?;
            let s = Option::as_mut(&mut *ss).ok_or(ENODEV)?;
            s.adv_scan.ext_adv_set_data(d.handle, &d.data[..len])?;
            Ok(0)
        }
        SL_IOCTL_EXT_ADV_SET_SCAN_RSP => {
            let d: SleExtAdvData = read_user_struct(arg)?;
            let len = (d.data_len as usize).min(ADV_DATA_MAX);
            let mut ss = context.lock()?;
            let s = Option::as_mut(&mut *ss).ok_or(ENODEV)?;
            s.adv_scan.ext_adv_set_scan_rsp(d.handle, &d.data[..len])?;
            Ok(0)
        }
        SL_IOCTL_EXT_ADV_ENABLE => {
            let handle: u8 = read_user_struct(arg)?;
            let mut ss = context.lock()?;
            let s = Option::as_mut(&mut *ss).ok_or(ENODEV)?;
            s.adv_scan.ext_adv_enable(handle)?;
            Ok(0)
        }
        SL_IOCTL_EXT_ADV_DISABLE => {
            let handle: u8 = read_user_struct(arg)?;
            let mut ss = context.lock()?;
            let s = Option::as_mut(&mut *ss).ok_or(ENODEV)?;
            s.adv_scan.ext_adv_disable(handle)?;
            Ok(0)
        }
        SL_IOCTL_EXT_ADV_REMOVE => {
            let handle: u8 = read_user_struct(arg)?;
            let mut ss = context.lock()?;
            let s = Option::as_mut(&mut *ss).ok_or(ENODEV)?;
            s.adv_scan.ext_adv_remove(handle)?;
            Ok(0)
        }
        SL_IOCTL_EXT_ADV_INFO => {
            let params: SleExtAdvInfo = read_user_struct(arg)?;
            let ss = context.lock()?;
            let s = ss.as_ref().ok_or(ENODEV)?;
            let (state, sid, phy, data_len, tx_count, timing, max_ev, ev_sent) =
                s.adv_scan.ext_adv_info(params.handle)?;
            drop(ss);
            let out = SleExtAdvInfo {
                handle: params.handle,
                state: match state {
                    sle_adv::ExtAdvState::Idle => 0,
                    sle_adv::ExtAdvState::Configured => 1,
                    sle_adv::ExtAdvState::Active => 2,
                },
                sid,
                primary_phy: phy,
                data_len: data_len as u16,
                ext_adv_timing: timing,
                max_adv_events: max_ev,
                tx_count,
                events_sent: ev_sent,
                _pad: [0u8; 4],
            };
            write_user_struct(arg, &out)?;
            Ok(0)
        }
        SL_IOCTL_EXT_ADV_ENABLE_EX => {
            let p: SleExtAdvEnableParams = read_user_struct(arg)?;
            let mut ss = context.lock()?;
            let s = Option::as_mut(&mut *ss).ok_or(ENODEV)?;
            s.adv_scan
                .ext_adv_enable_ex(p.handle, p.duration_10ms, p.max_adv_events)?;
            Ok(0)
        }
        SL_IOCTL_EXT_ADV_TICK => {
            let mut ss = context.lock()?;
            let s = Option::as_mut(&mut *ss).ok_or(ENODEV)?;
            let disabled = s.adv_scan.ext_adv_tick();
            // Drive RPA refresh: each tick is 10ms, accumulate into
            // full seconds for the RPA manager.
            s.rpa_tick_accum += 1;
            if s.rpa_tick_accum >= 100 {
                // 100 * 10ms = 1 second
                s.rpa_tick_accum = 0;
                s.rpa.rpa_tick(1);
            }
            Ok(disabled as c_long)
        }
        _ => Err(EINVAL),
    }
}

/// INJECT_ADV — large structs (AdvDataBuilder, AdvPdu), isolated for stack safety.
#[inline(never)]
fn ioctl_inject_adv(context: &RuntimeContext, me: Pin<&SparkLinkCtl>, arg: usize) -> Result<isize> {
    let inject: SleInjectAdv = read_user_struct(arg)?;
    let mut builder = sle_pdu::AdvDataBuilder::new();
    let _ = builder.push_discovery_level(inject.discovery_level);
    let _ = builder.push_sle_addr(&inject.addr);
    let name_len = (inject.name_len as usize).min(ADV_NAME_MAX);
    if name_len > 0 {
        let _ = builder.push_complete_name(&inject.name[..name_len]);
    }
    let pdu = sle_pdu::AdvPdu::build(
        sle_pdu::BroadcastType::AccessibleScannable,
        sle_pdu::PacketType::BasicAdv,
        0,
        &builder,
    );
    {
        let mut ss = context.lock()?;
        let s = Option::as_mut(&mut *ss).ok_or(ENODEV)?;
        s.adv_scan.process_adv_pdu(&pdu, inject.rssi)?;
    }
    let name_len = (inject.name_len as usize).min(31);
    SparkLinkCtl::broadcast_event(
                context,
        me.as_ref(),
        sle_event::SleWireEvent::adv_report(
            inject.addr,
            inject.rssi,
            inject.discovery_level,
            &inject.name[..name_len],
        ),
    )?;
    genl_bridge::notify_event(0x02, 0, &inject.addr);
    dev_info!(
        me.dev,
        "sparklink: injected ADV from {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} rssi={}\n",
        inject.addr[0],
        inject.addr[1],
        inject.addr[2],
        inject.addr[3],
        inject.addr[4],
        inject.addr[5],
        inject.rssi
    );
    Ok(0)
}

/// INJECT_RAW_ADV — large SleInjectRawAdv struct, isolated for stack safety.
#[inline(never)]
fn ioctl_inject_raw_adv(context: &RuntimeContext, arg: usize) -> Result<isize> {
    let inject: SleInjectRawAdv = read_user_struct(arg)?;
    let len = inject.pdu_len as usize;
    if !(6..=264).contains(&len) {
        return Err(EINVAL);
    }
    let pdu = sle_pdu::AdvPdu::deserialize(&inject.pdu_data[..len]).ok_or(EINVAL)?;
    {
        let mut ss = context.lock()?;
        let s = Option::as_mut(&mut *ss).ok_or(ENODEV)?;
        s.adv_scan.process_adv_pdu(&pdu, inject.rssi)?;
    }
    Ok(0)
}

/// Connection data send — isolated for stack safety (SleConnData = 260B + tx_buf = 256B).
#[inline(never)]
fn ioctl_conn_send(context: &RuntimeContext, arg: usize) -> Result<isize> {
    let cd: SleConnData = read_user_struct(arg)?;
    let len = (cd.length as usize).min(CONN_DATA_MAX);
    let mut ss = context.lock()?;
    let s = Option::as_mut(&mut *ss).ok_or(ENODEV)?;
    let handle = s.conn.resolve_handle(cd.handle)?;
    let sent = s.conn.send(handle, &cd.data[..len])?;
    let mut tx_buf = [0u8; 1 + CONN_DATA_MAX];
    tx_buf[0] = sle_conn::tcid::DEFAULT_DATA as u8;
    tx_buf[1..1 + len].copy_from_slice(&cd.data[..len]);
    s.controller.send_data(cd.handle, &tx_buf[..1 + len])?;
    Ok(sent as isize)
}

/// Connection data receive — isolated for stack safety (2x SleConnData = 520B).
#[inline(never)]
fn ioctl_conn_recv(context: &RuntimeContext, arg: usize) -> Result<isize> {
    let cd: SleConnData = read_user_struct(arg)?;
    let mut ss = context.lock()?;
    let s = Option::as_mut(&mut *ss).ok_or(ENODEV)?;
    let handle = s.conn.resolve_handle(cd.handle)?;
    let mut out: SleConnData = unsafe { core::mem::zeroed() };
    out.handle = handle;
    let recv_len = s.conn.recv(handle, &mut out.data)?;
    out.length = recv_len.min(CONN_DATA_MAX) as u16;
    drop(ss);
    write_user_struct(arg, &out)?;
    Ok(0)
}

fn ioctl_dispatch_conn(context: &RuntimeContext, me: Pin<&SparkLinkCtl>, cmd: u32, arg: usize) -> Result<isize> {
    match cmd {
        SL_IOCTL_CONNECT => {
            SparkLinkCtl::check_power_active()?;
            let cp: SleConnectParams = read_user_struct(arg)?;
            let role = if cp.gt_role == 1 {
                GtRole::GNode
            } else {
                GtRole::TNode
            };
            let handle = {
                let mut ss = context.lock()?;
                let s = Option::as_mut(&mut *ss).ok_or(ENODEV)?;
                let handle = s.conn.connect(cp.peer_addr, role)?;
                match s.controller.create_connection(&cp.peer_addr) {
                    Ok(()) => {
                        drain_controller_events(s);
                        s.conn.confirm_connecting_by_addr(&cp.peer_addr);
                    }
                    Err(e) => {
                        s.conn.abort_connecting(handle);
                        return Err(e);
                    }
                }
                handle
            };
            SparkLinkCtl::broadcast_event(
                context,
                me.as_ref(),
                sle_event::SleWireEvent::conn_state(handle, 0, 1, cp.peer_addr, 0),
            )?;
            Ok(handle as isize)
        }
        SL_IOCTL_DISCONNECT => {
            let handle: u16 = read_user_struct(arg)?;
            let (handle, peer_addr, old_state, new_state) = {
                let mut ss = context.lock()?;
                let s = Option::as_mut(&mut *ss).ok_or(ENODEV)?;
                let handle = s.conn.resolve_handle(handle)?;
                let peer_addr = s.conn.info(handle).map(|e| e.peer_addr).unwrap_or([0u8; 6]);
                let old_state = s.conn.info(handle).map(|e| e.state as u8).unwrap_or(0);
                let asynchronous = s.controller.uses_command_host();
                let wire_handle = if asynchronous {
                    s.conn.controller_handle(handle)?
                } else {
                    Some(handle)
                };
                s.conn.disconnect(handle)?;
                // Before ConnectionEstablished, retain the outgoing entry.
                // Its completion learns the controller handle and sends the
                // deferred disconnect; a queued command is not a disconnect.
                if let Some(wire_handle) = wire_handle {
                    match s.controller.disconnect(wire_handle) {
                        Ok(()) => {
                            drain_controller_events(s);
                            if !asynchronous && s.conn
                                .info(handle)
                                .map(|e| e.state == ConnState::DisconnectPending)
                                .unwrap_or(false)
                            {
                                s.conn.confirm_disconnecting(handle);
                            }
                        }
                        Err(error) => {
                            s.conn.abort_disconnecting(handle);
                            return Err(error);
                        }
                    }
                }
                let new_state = s.conn.info(handle).map(|e| e.state as u8).unwrap_or(0);
                (handle, peer_addr, old_state, new_state)
            };
            SparkLinkCtl::broadcast_event(
                context,
                me.as_ref(),
                sle_event::SleWireEvent::conn_state(handle, old_state, new_state, peer_addr, 0),
            )?;
            Ok(0)
        }
        SL_IOCTL_CONN_INFO => {
            let req: SleConnInfo = read_user_struct(arg)?;
            let ss = context.lock()?;
            let s = ss.as_ref().ok_or(ENODEV)?;
            let handle = if req.handle == 0 {
                let (handles, count) = s.conn.active_handles();
                if count == 0 {
                    return Err(EPIPE);
                }
                handles[0]
            } else {
                req.handle
            };
            let entry = s.conn.info(handle)?;
            let mut info: SleConnInfo = unsafe { core::mem::zeroed() };
            info.handle = entry.handle;
            info.state = entry.state as u8;
            info.peer_addr = entry.peer_addr;
            info.local_role = entry.local_role as u8;
            info.bandwidth_mhz = entry.params.bandwidth_mhz;
            info.mcs_index = entry.params.mcs_index;
            info.event_group_period = entry.params.event_group_period;
            info.supervision_timeout = entry.params.supervision_timeout;
            info.tx_seq = entry.seq.tx_seq;
            info.rx_seq = entry.seq.rx_seq;
            info.tx_pending = entry.tx_queue.len() as u16;
            info.rx_pending = entry.rx_queue.len() as u16;
            info.tx_bytes = entry.tx_bytes;
            info.rx_bytes = entry.rx_bytes;
            info.data_mtu = entry.channels.data.mtu;
            info.data_mps = entry.channels.data.mps;
            info.data_mode = entry.channels.data.mode as u8;
            info.svc_mtu = entry.channels.svc_mgmt.mtu;
            if let Some(session) = &entry.ssap_session {
                info.ssap_mtu = session.mtu;
                info.ssap_info_exchanged = if session.info_exchanged { 1 } else { 0 };
                info.ssap_reliable_mode = if session.reliable_mode { 1 } else { 0 };
                info.ssap_version_major = session.version.0;
            }
            info.smtc_tx_credits = entry.channels.svc_mgmt.tx_credits;
            info.smtc_rx_credits = entry.channels.svc_mgmt.rx_credits;
            info.dudtc_tx_credits = entry.channels.data.tx_credits;
            info.dudtc_rx_credits = entry.channels.data.rx_credits;
            drop(ss);
            write_user_struct(arg, &info)?;
            Ok(0)
        }
        SL_IOCTL_CONN_SEND => ioctl_conn_send(context, arg),
        SL_IOCTL_CONN_RECV => ioctl_conn_recv(context, arg),
        SL_IOCTL_INJECT_CONN_RESP => {
            let resp: SleInjectConnResp = read_user_struct(arg)?;
            let resp_type = AccessResponseType::from_raw(resp.response_type).ok_or(EINVAL)?;
            let params = NegotiatedParams {
                bandwidth_mhz: resp.bandwidth_mhz,
                mcs_index: resp.mcs_index,
                supervision_timeout: resp.supervision_timeout,
                ..Default::default()
            };
            let (handle, peer_addr, result) = {
                let mut ss = context.lock()?;
                let s = Option::as_mut(&mut *ss).ok_or(ENODEV)?;
                let handle = s.conn.resolve_handle(resp.handle)?;
                let peer_addr = s.conn.info(handle).map(|e| e.peer_addr).unwrap_or([0u8; 6]);
                let result = s.conn.process_access_response(handle, resp_type, params);
                if result.is_err() && s.controller.uses_command_host() {
                    if let Some(wire_handle) = s.conn.retire_rejected_link(handle) {
                        s.controller.disconnect(wire_handle)?;
                    }
                }
                if result.is_ok() && resp.data_mtu > 0 {
                    let mps = if resp.data_mps > 0 {
                        Some(resp.data_mps)
                    } else {
                        None
                    };
                    let _ = s.conn.set_data_mtu(handle, resp.data_mtu, mps);
                }
                (handle, peer_addr, result)
            };
            match &result {
                Ok(()) => {
                    SparkLinkCtl::broadcast_event(
                context,
                        me.as_ref(),
                        sle_event::SleWireEvent::conn_state(handle, 1, 2, peer_addr, 0),
                    )?;
                }
                Err(_) => {
                    SparkLinkCtl::broadcast_event(
                context,
                        me.as_ref(),
                        sle_event::SleWireEvent::conn_state(
                            handle,
                            1,
                            0,
                            peer_addr,
                            resp.response_type,
                        ),
                    )?;
                }
            }
            result.map(|()| 0isize)
        }
        SL_IOCTL_INJECT_CONN_DATA => ioctl_inject_conn_data(context, me, arg),
        SL_IOCTL_CONN_COUNT => {
            let ss = context.lock()?;
            let s = ss.as_ref().ok_or(ENODEV)?;
            Ok(s.conn.active_count() as isize)
        }
        SL_IOCTL_CONN_LIST => {
            let ss = context.lock()?;
            let s = ss.as_ref().ok_or(ENODEV)?;
            let (handles, count) = s.conn.active_handles();
            let mut list: SleConnList = unsafe { core::mem::zeroed() };
            let count = count.min(8);
            list.count = count as u16;
            list.handles[..count].copy_from_slice(&handles[..count]);
            drop(ss);
            write_user_struct(arg, &list)?;
            Ok(0)
        }
        SL_IOCTL_SET_CONN_MTU => {
            let params: SleConnMtuParams = read_user_struct(arg)?;
            let mps = if params.mps > 0 {
                Some(params.mps)
            } else {
                None
            };
            let mut ss = context.lock()?;
            let s = Option::as_mut(&mut *ss).ok_or(ENODEV)?;
            let handle = s.conn.resolve_handle(params.handle)?;
            s.conn.set_data_mtu(handle, params.mtu, mps)?;
            Ok(0)
        }
        SL_IOCTL_CONN_READ_PEER_FEATURES => {
            let req: SleConnPeerCap = read_user_struct(arg)?;
            let mut ss = context.lock()?;
            let s = Option::as_mut(&mut *ss).ok_or(ENODEV)?;
            let handle = s.conn.resolve_handle(req.handle)?;
            let entry = s.conn.info(handle)?;
            if !entry.peer_cap.features_valid {
                let hb = handle.to_le_bytes();
                s.controller
                    .send_command(sle_dli::SleOpcode::ReadFeatures, &hb)?;
                drain_controller_events(s);
            }
            let entry = s.conn.info(handle)?;
            let mut out: SleConnPeerCap = unsafe { core::mem::zeroed() };
            out.handle = handle;
            out.features = entry.peer_cap.features;
            out.features_valid = if entry.peer_cap.features_valid { 1 } else { 0 };
            out.version = entry.peer_cap.version;
            out.manufacturer = entry.peer_cap.manufacturer;
            out.subversion = entry.peer_cap.subversion;
            out.version_valid = if entry.peer_cap.version_valid { 1 } else { 0 };
            drop(ss);
            write_user_struct(arg, &out)?;
            Ok(0)
        }
        SL_IOCTL_CONN_READ_PEER_VERSION => {
            let req: SleConnPeerCap = read_user_struct(arg)?;
            let mut ss = context.lock()?;
            let s = Option::as_mut(&mut *ss).ok_or(ENODEV)?;
            let handle = s.conn.resolve_handle(req.handle)?;
            let entry = s.conn.info(handle)?;
            if !entry.peer_cap.version_valid {
                let hb = handle.to_le_bytes();
                s.controller
                    .send_command(sle_dli::SleOpcode::ReadVersion, &hb)?;
                drain_controller_events(s);
            }
            let entry = s.conn.info(handle)?;
            let mut out: SleConnPeerCap = unsafe { core::mem::zeroed() };
            out.handle = handle;
            out.features = entry.peer_cap.features;
            out.features_valid = if entry.peer_cap.features_valid { 1 } else { 0 };
            out.version = entry.peer_cap.version;
            out.manufacturer = entry.peer_cap.manufacturer;
            out.subversion = entry.peer_cap.subversion;
            out.version_valid = if entry.peer_cap.version_valid { 1 } else { 0 };
            drop(ss);
            write_user_struct(arg, &out)?;
            Ok(0)
        }
        SL_IOCTL_CONN_UPDATE_PARAMS => {
            let up: SleConnParamUpdate = read_user_struct(arg)?;
            let mut ss = context.lock()?;
            let s = Option::as_mut(&mut *ss).ok_or(ENODEV)?;
            let handle = s.conn.resolve_handle(up.handle)?;
            let interval = if up.interval_max > 0 {
                up.interval_max
            } else {
                up.interval_min
            };
            s.conn
                .update_conn_params(handle, interval, up.latency, up.supervision_timeout)?;
            let mut params = [0u8; 10];
            params[0..2].copy_from_slice(&handle.to_le_bytes());
            params[2..4].copy_from_slice(&up.interval_min.to_le_bytes());
            params[4..6].copy_from_slice(&up.interval_max.to_le_bytes());
            params[6..8].copy_from_slice(&up.latency.to_le_bytes());
            params[8..10].copy_from_slice(&up.supervision_timeout.to_le_bytes());
            s.controller
                .send_command(sle_dli::SleOpcode::ConnParamUpdate, &params)?;
            Ok(0)
        }
        SL_IOCTL_CONN_PHY_UPDATE => {
            let pu: SleConnPhyUpdate = read_user_struct(arg)?;
            let mut ss = context.lock()?;
            let s = Option::as_mut(&mut *ss).ok_or(ENODEV)?;
            let handle = s.conn.resolve_handle(pu.handle)?;
            let mcs = if pu.mcs_index != 0xFF {
                pu.mcs_index
            } else {
                s.conn.info(handle)?.params.mcs_index
            };
            let bw = if pu.bandwidth_mhz != 0 {
                pu.bandwidth_mhz
            } else {
                s.conn.info(handle)?.params.bandwidth_mhz
            };
            s.conn.update_phy_params(handle, mcs, bw)?;
            let mut params = [0u8; 4];
            params[0..2].copy_from_slice(&handle.to_le_bytes());
            params[2] = mcs;
            params[3] = bw;
            s.controller
                .send_command(sle_dli::SleOpcode::SetPhyParam, &params)?;
            Ok(0)
        }
        _ => Err(EINVAL),
    }
}

/// INJECT_CONN_DATA — largest single ioctl, isolated for stack safety.
#[inline(never)]
fn ioctl_inject_conn_data(context: &RuntimeContext, me: Pin<&SparkLinkCtl>, arg: usize) -> Result<isize> {
    let cd: SleConnData = read_user_struct(arg)?;
    let len = cd.length as usize;
    // An injected transport frame must contain data. Validate before handle
    // lookup or any TCID/SSAP access; oversized input must not be truncated.
    if len == 0 || len > CONN_DATA_MAX {
        return Err(EINVAL);
    }
    let raw = &cd.data[..len];
    {
        let mut ss = context.lock()?;
        let s = Option::as_mut(&mut *ss).ok_or(ENODEV)?;
        let s = &mut **s;
        let handle = s.conn.resolve_handle(cd.handle)?;
        if !raw.is_empty()
            && u16::from(raw[0]) == sle_conn::tcid::MANAGEMENT
            && raw.len() >= sle_conn::CREDIT_GRANT_PDU_SIZE
            && raw[1] == sle_conn::CREDIT_GRANT_PDU_TYPE
        {
            // Credit grant signaling (T/XS 20002-2025 §7.3.3):
            // [TCID 0x02] [code 0xFC] [identifier] [length LE16] [target_tcid] [credits LE16]
            let target_tcid = u16::from(raw[5]);
            let credits = u16::from_le_bytes([raw[6], raw[7]]);
            let _ = s.conn.receive_credits(handle, target_tcid, credits);
        } else if !raw.is_empty()
            && u16::from(raw[0]) == sle_conn::tcid::MANAGEMENT
            && raw.len() >= 5
            && raw[1] != sle_conn::CREDIT_GRANT_PDU_TYPE
        {
            // Transport control signaling (T/XS 20002-2025 §7.3.4).
            let sig_data = &raw[1..];
            let mut resp_buf = [0u8; 32];
            let resp_len = s
                .conn
                .handle_transport_signaling(handle, sig_data, &mut resp_buf)
                .unwrap_or(0);
            if resp_len > 0 {
                let _ = s.controller.send_data(handle, &resp_buf[..resp_len]);
            }
        } else if !raw.is_empty()
            && u16::from(raw[0]) == sle_conn::tcid::SERVICE_MGMT
            && raw.len() > 1
        {
            let needs_grant = s
                .conn
                .consume_rx_credit(handle, sle_conn::tcid::SERVICE_MGMT);
            let pdu_data = &raw[1..];
            let mut resp_buf = [0u8; sle_ssap::SSAP_PDU_MAX];
            let resp_len = s.process_ssap_pdu(handle, pdu_data, &mut resp_buf)
                .unwrap_or(0);
            if resp_len > 0
                && s.conn
                    .consume_tx_credit(handle, sle_conn::tcid::SERVICE_MGMT)
                    .is_ok()
            {
                let mut tx_buf = [0u8; 1 + sle_ssap::SSAP_PDU_MAX];
                tx_buf[0] = sle_conn::tcid::SERVICE_MGMT as u8;
                tx_buf[1..1 + resp_len].copy_from_slice(&resp_buf[..resp_len]);
                let _ = s.controller.send_data(handle, &tx_buf[..1 + resp_len]);
            }
            // Drain at most 8 queued notifications to bound lock hold time.
            for _ in 0..8 {
                let n = match s.ssap.dequeue_notification() {
                    Some(n) => n,
                    None => break,
                };
                if s.conn
                    .consume_tx_credit(handle, sle_conn::tcid::SERVICE_MGMT)
                    .is_err()
                {
                    break;
                }
                let pdu = if n.indication {
                    sle_ssap::SsapPdu::ValueInd {
                        handle: n.handle,
                        data: n.data,
                    }
                } else {
                    sle_ssap::SsapPdu::ValueNtf {
                        handle: n.handle,
                        data: n.data,
                    }
                };
                let mut ntf_buf = [0u8; 1 + sle_ssap::SSAP_PDU_MAX];
                ntf_buf[0] = sle_conn::tcid::SERVICE_MGMT as u8;
                if let Ok(pdu_len) = pdu.encode(&mut ntf_buf[1..]) {
                    if pdu_len > 0 {
                        let _ = s.controller.send_data(handle, &ntf_buf[..1 + pdu_len]);
                    }
                }
            }
            if needs_grant {
                if let Ok((granted, id)) = s.conn.grant_credits(handle, sle_conn::tcid::SERVICE_MGMT) {
                    send_credit_grant(&s.controller, handle, sle_conn::tcid::SERVICE_MGMT, granted, id);
                }
            }
            // After ExchangeInfo negotiation: if reliable mode is agreed
            // but the reliable channel is not yet created, initiate TCID_Connect_Req.
            let needs_connect = s
                .conn
                .get_ssap_session(handle)
                .map(|sess| sess.reliable_mode && sess.reliable_tcid.is_none())
                .unwrap_or(false);
            if needs_connect {
                let cfg = sle_conn::ReliableModeConfig::default();
                let mut sig_buf = [0u8; 24];
                if let Ok(sig_len) =
                    s.conn.build_tcid_connect_req(handle, &cfg, &mut sig_buf)
                {
                    let _ = s.controller.send_data(handle, &sig_buf[..sig_len]);
                }
            }
        } else {
            // Check if this is an SSAP PDU on the dynamic reliable channel.
            let first_byte_tcid = u16::from(raw[0]);
            let is_ssap_reliable = raw.len() > 1
                && s.conn
                    .ssap_reliable_tcid(handle)
                    .map(|t| t == first_byte_tcid)
                    .unwrap_or(false);
            if is_ssap_reliable {
                let needs_grant = s.conn.consume_rx_credit(handle, first_byte_tcid);
                let pdu_data = &raw[1..];
                let mut resp_buf = [0u8; sle_ssap::SSAP_PDU_MAX];
                let resp_len = s.process_ssap_pdu(handle, pdu_data, &mut resp_buf)
                    .unwrap_or(0);
                if resp_len > 0
                    && s.conn.consume_tx_credit(handle, first_byte_tcid).is_ok()
                {
                    let mut tx_buf = [0u8; 1 + sle_ssap::SSAP_PDU_MAX];
                    tx_buf[0] = first_byte_tcid as u8;
                    tx_buf[1..1 + resp_len].copy_from_slice(&resp_buf[..resp_len]);
                    let _ = s.controller.send_data(handle, &tx_buf[..1 + resp_len]);
                }
                if needs_grant {
                    if let Ok((granted, id)) = s.conn.grant_credits(handle, first_byte_tcid) {
                        send_credit_grant(&s.controller, handle, first_byte_tcid, granted, id);
                    }
                }
            } else {
                let payload = if !raw.is_empty()
                    && u16::from(raw[0]) == sle_conn::tcid::DEFAULT_DATA
                    && raw.len() > 1
                {
                    let _ = s
                        .conn
                        .consume_rx_credit(handle, sle_conn::tcid::DEFAULT_DATA);
                    &raw[1..]
                } else {
                    raw
                };
                let seq = {
                    let entry = s.conn.info(handle)?;
                    entry.seq.rx_seq
                };
                s.conn.receive_data(handle, payload, seq)?;
            }
        }
    }
    SparkLinkCtl::broadcast_event(
                context,
        me.as_ref(),
        sle_event::SleWireEvent::data_received(cd.handle, len as u16),
    )?;
    dev_info!(
        me.dev,
        "sparklink: injected {} bytes connection data (handle={})\n",
        len,
        cd.handle
    );
    Ok(0)
}

/// AFH ioctl sub-dispatcher (channel map, RSSI, hopping).
#[inline(never)]
fn ioctl_afh(context: &RuntimeContext, cmd: u32, arg: usize) -> Result<isize> {
    match cmd {
        SL_IOCTL_AFH_SET_MAP => {
            let params: SleAfhMapParams = read_user_struct(arg)?;
            let map = sle_phy::ChannelMap::from_raw(params.map);
            let mut ss = context.lock()?;
            let s = Option::as_mut(&mut *ss).ok_or(ENODEV)?;
            let handle = s.conn.resolve_handle(params.handle)?;
            let min_ch = if params.min_channels > 0 {
                params.min_channels
            } else {
                2
            };
            s.conn.set_channel_map(handle, map, min_ch)?;
            Ok(0)
        }
        SL_IOCTL_AFH_GET_MAP => {
            let params: SleAfhMapParams = read_user_struct(arg)?;
            let mut ss = context.lock()?;
            let s = Option::as_mut(&mut *ss).ok_or(ENODEV)?;
            let handle = s.conn.resolve_handle(params.handle)?;
            let map = s.conn.get_channel_map(handle)?;
            drop(ss);
            let out = SleAfhMapParams {
                handle,
                min_channels: 0,
                _pad: 0,
                map: map.map,
                used_count: map.used_count(),
                _pad2: 0,
            };
            write_user_struct(arg, &out)?;
            Ok(0)
        }
        SL_IOCTL_AFH_REPORT_RSSI => {
            let rpt: SleAfhRssiReport = read_user_struct(arg)?;
            let mut ss = context.lock()?;
            let s = Option::as_mut(&mut *ss).ok_or(ENODEV)?;
            let handle = s.conn.resolve_handle(rpt.handle)?;
            s.conn.report_rssi(handle, rpt.channel, rpt.rssi_dbm)?;
            Ok(0)
        }
        SL_IOCTL_AFH_CLASSIFY => {
            let params: SleAfhClassifyParams = read_user_struct(arg)?;
            let mut ss = context.lock()?;
            let s = Option::as_mut(&mut *ss).ok_or(ENODEV)?;
            let handle = s.conn.resolve_handle(params.handle)?;
            let min_ch = if params.min_channels > 0 {
                params.min_channels
            } else {
                2
            };
            let map = s
                .conn
                .classify_channels(handle, params.threshold_dbm, min_ch)?;
            drop(ss);
            let out = SleAfhClassifyParams {
                handle,
                threshold_dbm: params.threshold_dbm,
                min_channels: min_ch,
                map_out: map.map,
                used_count: map.used_count(),
                _pad: 0,
            };
            write_user_struct(arg, &out)?;
            Ok(0)
        }
        SL_IOCTL_AFH_HOP_NEXT => {
            let params: SleAfhHopInfo = read_user_struct(arg)?;
            let mut ss = context.lock()?;
            let s = Option::as_mut(&mut *ss).ok_or(ENODEV)?;
            let handle = s.conn.resolve_handle(params.handle)?;
            let (ch, freq, ec) = s.conn.hop_next(handle)?;
            drop(ss);
            let out = SleAfhHopInfo {
                handle,
                channel: ch,
                _pad: 0,
                freq_mhz: freq,
                event_counter: ec,
            };
            write_user_struct(arg, &out)?;
            Ok(0)
        }
        SL_IOCTL_AFH_REPORT_RETX => {
            let rpt: SleAfhRetxReport = read_user_struct(arg)?;
            let mut ss = context.lock()?;
            let s = Option::as_mut(&mut *ss).ok_or(ENODEV)?;
            let handle = s.conn.resolve_handle(rpt.handle)?;
            s.conn
                .report_retx(handle, rpt.channel, rpt.retransmitted != 0)?;
            Ok(0)
        }
        _ => Err(EINVAL),
    }
}

/// Security ioctl sub-dispatcher (pairing, encryption, crypto tests).
#[inline(never)]
fn ioctl_security(context: &RuntimeContext, cmd: u32, arg: usize) -> Result<isize> {
    match cmd {
        SL_IOCTL_SEC_SET_PSK => {
            let params: SlePskParams = read_user_struct(arg)?;
            let mut ss = context.lock()?;
            let s = Option::as_mut(&mut *ss).ok_or(ENODEV)?;
            s.security.set_psk(params.psk);
            Ok(0)
        }
        SL_IOCTL_SEC_PAIR => {
            let params: SlePairParams = read_user_struct(arg)?;
            let mut ss = context.lock()?;
            let s = Option::as_mut(&mut *ss).ok_or(ENODEV)?;
            match params.method {
                1 => s.security.pair_just_works()?,
                2 => s.security.pair_psk()?,
                3 => s.security.pair_numeric_comparison()?,
                4 => s.security.pair_passkey_entry()?,
                5 => s.security.pair_oob()?,
                6 => s.security.pair_password()?,
                _ => return Err(EINVAL),
            }
            let handle = s.conn.first_active_handle().unwrap_or(0);
            let auth_req: u8 = if params.method == 3 { 0x04 } else { 0x00 };
            s.controller.request_pair(handle, auth_req, params.method)?;
            drain_controller_events(s);
            Ok(0)
        }
        SL_IOCTL_SEC_INFO => {
            let info = {
                let ss = context.lock()?;
                let s = ss.as_ref().ok_or(ENODEV)?;
                let mut info: SleSecInfo = unsafe { core::mem::zeroed() };
                info.state = s.security.state as u8;
                info.method = s.security.method as u8;
                info.mode = s.security.mode as u8;
                info.enc_enabled = if s.security.is_encrypted() { 1 } else { 0 };
                info.enc_key_fingerprint = s.security.enc_key_fingerprint();
                info
            };
            write_user_struct(arg, &info)?;
            Ok(0)
        }
        SL_IOCTL_SEC_ENCRYPT_ON => {
            let mut ss = context.lock()?;
            let s = Option::as_mut(&mut *ss).ok_or(ENODEV)?;
            s.security.enable_encryption()?;
            s.controller.start_encrypt()?;
            Ok(0)
        }
        SL_IOCTL_SEC_SM3_TEST => {
            let mut ht: SleHashTest = read_user_struct(arg)?;
            let in_len = (ht.in_len as usize).min(HASH_INPUT_MAX);
            let digest = SecurityInner::sm3_hash(&ht.data[..in_len]);
            ht.digest = digest;
            write_user_struct(arg, &ht)?;
            Ok(0)
        }
        SL_IOCTL_SEC_SM4_ENC_TEST => {
            let mut cd: SleConnData = read_user_struct(arg)?;
            let len = (cd.length as usize).min(CONN_DATA_MAX);
            {
                let mut ss = context.lock()?;
                let s = Option::as_mut(&mut *ss).ok_or(ENODEV)?;
                s.security.encrypt_test(&mut cd.data[..len])?;
            }
            write_user_struct(arg, &cd)?;
            Ok(0)
        }
        SL_IOCTL_SEC_SM4_DEC_TEST => {
            let mut cd: SleConnData = read_user_struct(arg)?;
            let len = (cd.length as usize).min(CONN_DATA_MAX);
            {
                let mut ss = context.lock()?;
                let s = Option::as_mut(&mut *ss).ok_or(ENODEV)?;
                s.security.decrypt_test(&mut cd.data[..len])?;
            }
            write_user_struct(arg, &cd)?;
            Ok(0)
        }
        SL_IOCTL_SEC_SM4_BLOCK_TEST => {
            let mut bt: SleSm4BlockTest = read_user_struct(arg)?;
            let ctx = sle_crypto::Sm4Key::new(&bt.key);
            bt.output = if bt.decrypt != 0 {
                ctx.decrypt_block(&bt.input)
            } else {
                ctx.encrypt_block(&bt.input)
            };
            write_user_struct(arg, &bt)?;
            Ok(0)
        }
        SL_IOCTL_SEC_HMAC_TEST => {
            let mut ht: SleHmacTest = read_user_struct(arg)?;
            let klen = (ht.key_len as usize).min(HMAC_KEY_MAX);
            let dlen = (ht.data_len as usize).min(HMAC_DATA_MAX);
            ht.digest = sle_crypto::hmac_sm3(&ht.key[..klen], &ht.data[..dlen]);
            write_user_struct(arg, &ht)?;
            Ok(0)
        }
        SL_IOCTL_SEC_RESET => {
            let mut ss = context.lock()?;
            let s = Option::as_mut(&mut *ss).ok_or(ENODEV)?;
            s.security.reset();
            Ok(0)
        }
        SL_IOCTL_SEC_GET_PASSKEY => {
            let ss = context.lock()?;
            let s = ss.as_ref().ok_or(ENODEV)?;
            let passkey = s.security.get_passkey()?;
            drop(ss);
            write_user_struct(arg, &passkey)?;
            Ok(0)
        }
        SL_IOCTL_SEC_CONFIRM_PASSKEY => {
            let mut ss = context.lock()?;
            let s = Option::as_mut(&mut *ss).ok_or(ENODEV)?;
            s.security.confirm_passkey()?;
            Ok(0)
        }
        SL_IOCTL_SEC_REJECT_PASSKEY => {
            let mut ss = context.lock()?;
            let s = Option::as_mut(&mut *ss).ok_or(ENODEV)?;
            s.security.reject_passkey();
            Ok(0)
        }
        SL_IOCTL_SEC_SET_OOB => {
            ioctl_set_oob(context, arg)?;
            Ok(0)
        }
        SL_IOCTL_SEC_INPUT_PASSKEY => {
            let params: SlePasskeyInput = read_user_struct(arg)?;
            let mut ss = context.lock()?;
            let s = Option::as_mut(&mut *ss).ok_or(ENODEV)?;
            s.security.input_passkey(params.passkey)?;
            Ok(0)
        }
        SL_IOCTL_SEC_SET_PASSWORD => {
            let params: SlePasswordParams = read_user_struct(arg)?;
            let mut ss = context.lock()?;
            let s = Option::as_mut(&mut *ss).ok_or(ENODEV)?;
            s.security.set_password(&params.data, params.len)?;
            Ok(0)
        }
        _ => Err(EINVAL),
    }
}

/// Local SSAP ioctl sub-dispatcher (service DB, property R/W).
#[inline(never)]
fn ioctl_ssap_local(context: &RuntimeContext, cmd: u32, arg: usize) -> Result<isize> {
    match cmd {
        SL_IOCTL_SSAP_REGISTER_SVC => {
            let mut ss = context.lock()?;
            let s = Option::as_mut(&mut *ss).ok_or(ENODEV)?;
            s.ssap.register_device_info_service()?;
            Ok(0)
        }
        SL_IOCTL_SSAP_INFO => {
            let info = {
                let ss = context.lock()?;
                let s = ss.as_ref().ok_or(ENODEV)?;
                let mut info: SsapSummary = unsafe { core::mem::zeroed() };
                info.service_count = s.ssap.service_count() as u16;
                info.property_count = s.ssap.property_count() as u16;
                info.total_entries = s.ssap.total_entries() as u16;
                info.mtu = s.ssap.negotiated.mtu;
                info.notification_count = s.ssap.notification_count() as u16;
                info
            };
            write_user_struct(arg, &info)?;
            Ok(0)
        }
        SL_IOCTL_SSAP_READ => {
            let rw: SsapReadWrite = read_user_struct(arg)?;
            let ss = context.lock()?;
            let s = ss.as_ref().ok_or(ENODEV)?;
            let data = s.ssap.read_property(rw.handle)?;
            let mut out: SsapReadWrite = unsafe { core::mem::zeroed() };
            out.handle = rw.handle;
            let copy_len = data.len().min(SSAP_DATA_MAX);
            out.length = copy_len as u16;
            out.data[..copy_len].copy_from_slice(&data[..copy_len]);
            drop(ss);
            write_user_struct(arg, &out)?;
            Ok(0)
        }
        SL_IOCTL_SSAP_WRITE => {
            let rw: SsapReadWrite = read_user_struct(arg)?;
            let len = (rw.length as usize).min(SSAP_DATA_MAX);
            let mut ss = context.lock()?;
            let s = Option::as_mut(&mut *ss).ok_or(ENODEV)?;
            s.ssap.write_property(rw.handle, &rw.data[..len])?;
            Ok(0)
        }
        SL_IOCTL_SSAP_FIND_SVC => {
            let ss = context.lock()?;
            let s = ss.as_ref().ok_or(ENODEV)?;
            let services = s.ssap.find_primary_services();
            let mut list: SsapServiceList = unsafe { core::mem::zeroed() };
            let count = services.len().min(15);
            list.count = count as u16;
            for (i, (start, end, uuid)) in services.iter().take(15).enumerate() {
                list.services[i].start_handle = *start;
                list.services[i].end_handle = *end;
                list.services[i].uuid16 = uuid.as_u16().unwrap_or(0);
                list.services[i].primary = 1;
            }
            drop(ss);
            write_user_struct(arg, &list)?;
            Ok(0)
        }
        SL_IOCTL_SSAP_NOTIFY => {
            let handle: u16 = read_user_struct(arg)?;
            let mut ss = context.lock()?;
            let s = Option::as_mut(&mut *ss).ok_or(ENODEV)?;
            s.ssap.notify(handle)?;
            Ok(0)
        }
        SL_IOCTL_SSAP_DEQUEUE_NTF => {
            let mut ss = context.lock()?;
            let s = Option::as_mut(&mut *ss).ok_or(ENODEV)?;
            let ntf = s.ssap.dequeue_notification();
            match ntf {
                Some(n) => {
                    let mut out: SsapNotification = unsafe { core::mem::zeroed() };
                    out.handle = n.handle;
                    out.indication = if n.indication { 1 } else { 0 };
                    let copy_len = n.data.len().min(SSAP_DATA_MAX);
                    out.length = copy_len as u8;
                    out.data[..copy_len].copy_from_slice(&n.data[..copy_len]);
                    drop(ss);
                    write_user_struct(arg, &out)?;
                    Ok(0)
                }
                None => Err(EAGAIN),
            }
        }
        SL_IOCTL_SSAP_ADD_SVC => {
            let mut cmd_data: SsapAddService = read_user_struct(arg)?;
            let uuid = if cmd_data.uuid16 != 0 {
                sle_ssap::SsapUuid::Uuid16(cmd_data.uuid16)
            } else {
                sle_ssap::SsapUuid::Uuid128(cmd_data.uuid128)
            };
            let primary = cmd_data.primary != 0;
            let mut ss = context.lock()?;
            let s = Option::as_mut(&mut *ss).ok_or(ENODEV)?;
            let handle = s.ssap.register_service(uuid, primary)?;
            cmd_data.start_handle = handle;
            drop(ss);
            write_user_struct(arg, &cmd_data)?;
            Ok(0)
        }
        SL_IOCTL_SSAP_ADD_PROP => {
            let mut cmd_data: SsapAddProperty = read_user_struct(arg)?;
            let uuid = sle_ssap::SsapUuid::Uuid16(cmd_data.uuid16);
            let ops = sle_ssap::OpIndicator::from_raw(u32::from(cmd_data.ops));
            let len = (cmd_data.value_len as usize).min(SSAP_VALUE_MAX);
            let mut ss = context.lock()?;
            let s = Option::as_mut(&mut *ss).ok_or(ENODEV)?;
            let handle = s.ssap.add_property(uuid, ops, &cmd_data.value[..len])?;
            cmd_data.handle = handle;
            drop(ss);
            write_user_struct(arg, &cmd_data)?;
            Ok(0)
        }
        SL_IOCTL_SSAP_REMOVE_SVC => {
            let start_handle: u16 = read_user_struct(arg)?;
            let mut ss = context.lock()?;
            let s = Option::as_mut(&mut *ss).ok_or(ENODEV)?;
            s.ssap.remove_service(start_handle)?;
            Ok(0)
        }
        _ => Err(EINVAL),
    }
}

/// AFH, security, SSAP ioctl router — delegates to domain-specific handlers.
#[inline(never)]
fn ioctl_dispatch_sec_ssap(context: &RuntimeContext, cmd: u32, arg: usize) -> Result<isize> {
    match cmd {
        SL_IOCTL_AFH_SET_MAP
        | SL_IOCTL_AFH_GET_MAP
        | SL_IOCTL_AFH_REPORT_RSSI
        | SL_IOCTL_AFH_CLASSIFY
        | SL_IOCTL_AFH_HOP_NEXT
        | SL_IOCTL_AFH_REPORT_RETX => ioctl_afh(context, cmd, arg),

        SL_IOCTL_SEC_SET_PSK
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
        | SL_IOCTL_SEC_SET_PASSWORD => ioctl_security(context, cmd, arg),

        SL_IOCTL_SSAP_REGISTER_SVC
        | SL_IOCTL_SSAP_INFO
        | SL_IOCTL_SSAP_READ
        | SL_IOCTL_SSAP_WRITE
        | SL_IOCTL_SSAP_FIND_SVC
        | SL_IOCTL_SSAP_NOTIFY
        | SL_IOCTL_SSAP_DEQUEUE_NTF
        | SL_IOCTL_SSAP_ADD_SVC
        | SL_IOCTL_SSAP_ADD_PROP
        | SL_IOCTL_SSAP_REMOVE_SVC => ioctl_ssap_local(context, cmd, arg),

        SL_IOCTL_SSAP_EXCHANGE_INFO
        | SL_IOCTL_SSAP_REMOTE_DISCOVER
        | SL_IOCTL_SSAP_REMOTE_READ
        | SL_IOCTL_SSAP_REMOTE_WRITE
        | SL_IOCTL_SSAP_REMOTE_EVENT
        | SL_IOCTL_SSAP_CALL_METHOD
        | SL_IOCTL_SSAP_FIND_BY_UUID
        | SL_IOCTL_SSAP_READ_BY_UUID => ioctl_ssap_remote(context, cmd, arg),

        _ => Err(EINVAL),
    }
}

/// Remote SSAP client-side ioctl sub-dispatcher.
///
/// Sends SSAP request PDUs to connected remote peers via the SMTC
/// service management channel. Responses arrive asynchronously through
/// the normal PDU receive path and are cached in `remote_db`.
#[inline(never)]
fn ioctl_ssap_remote(context: &RuntimeContext, cmd: u32, arg: usize) -> Result<isize> {
    match cmd {
        SL_IOCTL_SSAP_EXCHANGE_INFO => {
            let params: SsapRemoteCmd = read_user_struct(arg)?;
            let mut ss = context.lock()?;
            let s = Option::as_mut(&mut *ss).ok_or(ENODEV)?;
            let handle = s.conn.resolve_handle(params.conn_handle)?;
            let mut buf = [0u8; sle_ssap::SSAP_PDU_MAX];
            let session = s.conn.get_ssap_session(handle).ok_or(ENOENT)?;
            let pdu_len = session.build_exchange_info_req(247, &mut buf)?;
            if pdu_len > 0 {
                s.conn
                    .consume_tx_credit(handle, sle_conn::tcid::SERVICE_MGMT)?;
                let mut tx_buf = [0u8; 1 + sle_ssap::SSAP_PDU_MAX];
                tx_buf[0] = sle_conn::tcid::SERVICE_MGMT as u8;
                tx_buf[1..1 + pdu_len].copy_from_slice(&buf[..pdu_len]);
                s.controller.send_data(handle, &tx_buf[..1 + pdu_len])?;
            }
            Ok(0)
        }
        SL_IOCTL_SSAP_REMOTE_DISCOVER => {
            let mut params: SsapRemoteDiscover = read_user_struct(arg)?;
            let mut ss = context.lock()?;
            let s = Option::as_mut(&mut *ss).ok_or(ENODEV)?;
            let handle = s.conn.resolve_handle(params.conn_handle)?;
            let mut buf = [0u8; sle_ssap::SSAP_PDU_MAX];
            let session = s.conn.get_ssap_session(handle).ok_or(ENOENT)?;
            let pdu_len = session.build_find_structure_req(
                params.start_handle,
                params.end_handle,
                &mut buf,
            )?;
            // Return current remote_db entry count before sending
            params.count = session.remote_db.entry_count() as u16;
            if pdu_len > 0 {
                s.conn
                    .consume_tx_credit(handle, sle_conn::tcid::SERVICE_MGMT)?;
                let mut tx_buf = [0u8; 1 + sle_ssap::SSAP_PDU_MAX];
                tx_buf[0] = sle_conn::tcid::SERVICE_MGMT as u8;
                tx_buf[1..1 + pdu_len].copy_from_slice(&buf[..pdu_len]);
                s.controller.send_data(handle, &tx_buf[..1 + pdu_len])?;
            }
            drop(ss);
            write_user_struct(arg, &params)?;
            Ok(0)
        }
        SL_IOCTL_SSAP_REMOTE_READ => {
            let params: SsapRemoteReadWrite = read_user_struct(arg)?;
            let mut ss = context.lock()?;
            let s = Option::as_mut(&mut *ss).ok_or(ENODEV)?;
            let handle = s.conn.resolve_handle(params.conn_handle)?;
            let mut buf = [0u8; sle_ssap::SSAP_PDU_MAX];
            let session = s.conn.get_ssap_session(handle).ok_or(ENOENT)?;
            let pdu_len = session.build_read_req(params.handle, &mut buf)?;
            if pdu_len > 0 {
                s.conn
                    .consume_tx_credit(handle, sle_conn::tcid::SERVICE_MGMT)?;
                let mut tx_buf = [0u8; 1 + sle_ssap::SSAP_PDU_MAX];
                tx_buf[0] = sle_conn::tcid::SERVICE_MGMT as u8;
                tx_buf[1..1 + pdu_len].copy_from_slice(&buf[..pdu_len]);
                s.controller.send_data(handle, &tx_buf[..1 + pdu_len])?;
            }
            Ok(0)
        }
        SL_IOCTL_SSAP_REMOTE_WRITE => {
            let params: SsapRemoteReadWrite = read_user_struct(arg)?;
            let mut ss = context.lock()?;
            let s = Option::as_mut(&mut *ss).ok_or(ENODEV)?;
            let handle = s.conn.resolve_handle(params.conn_handle)?;
            let data_len = (params.length as usize).min(params.data.len());
            let mut buf = [0u8; sle_ssap::SSAP_PDU_MAX];
            let session = s.conn.get_ssap_session(handle).ok_or(ENOENT)?;
            let pdu_len = session.build_write_req(
                params.handle,
                &params.data[..data_len],
                &mut buf,
            )?;
            if pdu_len > 0 {
                s.conn
                    .consume_tx_credit(handle, sle_conn::tcid::SERVICE_MGMT)?;
                let mut tx_buf = [0u8; 1 + sle_ssap::SSAP_PDU_MAX];
                tx_buf[0] = sle_conn::tcid::SERVICE_MGMT as u8;
                tx_buf[1..1 + pdu_len].copy_from_slice(&buf[..pdu_len]);
                s.controller.send_data(handle, &tx_buf[..1 + pdu_len])?;
            }
            Ok(0)
        }
        SL_IOCTL_SSAP_REMOTE_EVENT => {
            let mut ss = context.lock()?;
            let s = Option::as_mut(&mut *ss).ok_or(ENODEV)?;
            // Pop remote event from the first connection that has one
            let evt = s.conn.pop_any_remote_event();
            match evt {
                Some((conn_handle, re)) => {
                    let mut out: SsapNotification = unsafe { core::mem::zeroed() };
                    out.handle = re.handle;
                    out.indication = re.indication as u8;
                    let copy_len = re.data.len().min(out.data.len());
                    out.data[..copy_len].copy_from_slice(&re.data[..copy_len]);
                    out.length = copy_len as u8;
                    // Encode conn_handle in unused notification_count area
                    let _ = conn_handle;
                    drop(ss);
                    write_user_struct(arg, &out)?;
                    Ok(0)
                }
                None => Err(EAGAIN),
            }
        }
        SL_IOCTL_SSAP_CALL_METHOD => {
            let params: SsapRemoteReadWrite = read_user_struct(arg)?;
            let mut ss = context.lock()?;
            let s = Option::as_mut(&mut *ss).ok_or(ENODEV)?;
            let handle = s.conn.resolve_handle(params.conn_handle)?;
            let data_len = (params.length as usize).min(params.data.len());
            let mut buf = [0u8; sle_ssap::SSAP_PDU_MAX];
            let session = s.conn.get_ssap_session(handle).ok_or(ENOENT)?;
            let pdu_len = session.build_call_method_req(
                params.handle,
                &params.data[..data_len],
                &mut buf,
            )?;
            if pdu_len > 0 {
                s.conn
                    .consume_tx_credit(handle, sle_conn::tcid::SERVICE_MGMT)?;
                let mut tx_buf = [0u8; 1 + sle_ssap::SSAP_PDU_MAX];
                tx_buf[0] = sle_conn::tcid::SERVICE_MGMT as u8;
                tx_buf[1..1 + pdu_len].copy_from_slice(&buf[..pdu_len]);
                s.controller.send_data(handle, &tx_buf[..1 + pdu_len])?;
            }
            Ok(0)
        }
        SL_IOCTL_SSAP_FIND_BY_UUID => {
            let params: SsapUuidOp = read_user_struct(arg)?;
            let uuid = if params.uuid16 != 0 {
                sle_ssap::SsapUuid::Uuid16(params.uuid16)
            } else {
                sle_ssap::SsapUuid::Uuid128(params.uuid128)
            };
            let mut ss = context.lock()?;
            let s = Option::as_mut(&mut *ss).ok_or(ENODEV)?;
            let handle = s.conn.resolve_handle(params.conn_handle)?;
            let mut buf = [0u8; sle_ssap::SSAP_PDU_MAX];
            let session = s.conn.get_ssap_session(handle).ok_or(ENOENT)?;
            let pdu_len = session.build_find_by_uuid_req(&uuid, &mut buf)?;
            if pdu_len > 0 {
                s.conn
                    .consume_tx_credit(handle, sle_conn::tcid::SERVICE_MGMT)?;
                let mut tx_buf = [0u8; 1 + sle_ssap::SSAP_PDU_MAX];
                tx_buf[0] = sle_conn::tcid::SERVICE_MGMT as u8;
                tx_buf[1..1 + pdu_len].copy_from_slice(&buf[..pdu_len]);
                s.controller.send_data(handle, &tx_buf[..1 + pdu_len])?;
            }
            Ok(0)
        }
        SL_IOCTL_SSAP_READ_BY_UUID => {
            let params: SsapUuidOp = read_user_struct(arg)?;
            let uuid = if params.uuid16 != 0 {
                sle_ssap::SsapUuid::Uuid16(params.uuid16)
            } else {
                sle_ssap::SsapUuid::Uuid128(params.uuid128)
            };
            let mut ss = context.lock()?;
            let s = Option::as_mut(&mut *ss).ok_or(ENODEV)?;
            let handle = s.conn.resolve_handle(params.conn_handle)?;
            let mut buf = [0u8; sle_ssap::SSAP_PDU_MAX];
            let session = s.conn.get_ssap_session(handle).ok_or(ENOENT)?;
            let pdu_len = session.build_read_by_uuid_req(&uuid, &mut buf)?;
            if pdu_len > 0 {
                s.conn
                    .consume_tx_credit(handle, sle_conn::tcid::SERVICE_MGMT)?;
                let mut tx_buf = [0u8; 1 + sle_ssap::SSAP_PDU_MAX];
                tx_buf[0] = sle_conn::tcid::SERVICE_MGMT as u8;
                tx_buf[1..1 + pdu_len].copy_from_slice(&buf[..pdu_len]);
                s.controller.send_data(handle, &tx_buf[..1 + pdu_len])?;
            }
            Ok(0)
        }
        _ => Err(EINVAL),
    }
}

/// Handle SEC_SET_OOB ioctl in a separate stack frame to avoid
/// bloating the main ioctl function's stack usage.
#[inline(never)]
fn ioctl_set_oob(context: &RuntimeContext, arg: usize) -> Result {
    let params: SleOobData = read_user_struct(arg)?;
    let mut ss = context.lock()?;
    let s = Option::as_mut(&mut *ss).ok_or(ENODEV)?;
    s.security.set_oob_data(&params.data);
    Ok(())
}

/// Handle RAL_ADD ioctl in a separate stack frame (SleRalAddParams is 44 bytes).
#[inline(never)]
fn ioctl_ral_add(context: &RuntimeContext, arg: usize) -> Result {
    let params: SleRalAddParams = read_user_struct(arg)?;
    let entry = RalEntry {
        peer_id_type: params.peer_id_type,
        resolve_algo: params.resolve_algo,
        peer_irkid: params.peer_irkid,
        local_irkid: params.local_irkid,
        peer_id: params.peer_id,
        peer_irk: params.peer_irk,
        local_irk: params.local_irk,
    };
    let mut ss = context.lock()?;
    let s = Option::as_mut(&mut *ss).ok_or(ENODEV)?;
    s.rpa.ral_add(entry)
}

/// Handle RAL_READ_PEER_RPA / RAL_READ_LOCAL_RPA ioctls.
#[inline(never)]
fn ioctl_ral_read_rpa(context: &RuntimeContext, arg: usize, is_local: bool) -> Result {
    let mut params: SleRalQueryParams = read_user_struct(arg)?;
    let rpa = {
        let ss = context.lock()?;
        let s = ss.as_ref().ok_or(ENODEV)?;
        if is_local {
            s.rpa.read_local_rpa(params.id_type, &params.id)?
        } else {
            s.rpa.read_peer_rpa(params.id_type, &params.id)?
        }
    };
    params.rpa = rpa;
    write_user_struct(arg, &params)
}

/// Sync link ioctl sub-dispatcher (separate stack frame for large structs).
#[inline(never)]
fn ioctl_sync_link(context: &RuntimeContext, cmd: u32, arg: usize) -> Result<isize> {
    match cmd {
        SL_IOCTL_SYNC_UCAST_PARAM => {
            let mut cfg = read_user_struct::<SleSyncCigConfig>(arg)?;
            let params = sle_conn::SyncCigParams {
                cig_id: cfg.cig_id,
                sdu_interval_g2t: cfg.sdu_interval_g2t,
                sdu_interval_t2g: cfg.sdu_interval_t2g,
                max_sdu_g2t: cfg.max_sdu_g2t,
                max_sdu_t2g: cfg.max_sdu_t2g,
                retransmit_g2t: cfg.retransmit_g2t,
                retransmit_t2g: cfg.retransmit_t2g,
                max_latency_g2t: cfg.max_latency_g2t,
                max_latency_t2g: cfg.max_latency_t2g,
                adapt_mode: cfg.adapt_mode,
                link_count: cfg.link_count,
            };
            let mut ss = context.lock()?;
            let s = Option::as_mut(&mut *ss).ok_or(ENODEV)?;
            let result = s.conn.sync_ucast_configure(&params)?;
            cfg.cig_id = result.cig_id;
            cfg.link_count = result.link_count;
            cfg.handles_out = result.handles;
            let (links, cnt) = s.conn.sync_links_for_group(
                result.cig_id, sle_conn::SyncLinkType::Unicast);
            let (buf, len) = sle_conn::encode_sync_param_cmd(
                result.cig_id,
                params.sdu_interval_g2t, params.sdu_interval_t2g,
                params.adapt_mode,
                params.max_latency_g2t, params.max_latency_t2g,
                cnt, &links[..cnt as usize],
            );
            let _ = s.controller.send_command(
                sle_dli::SleOpcode::SyncUcastParam, &buf[..len]);
            drop(ss);
            write_user_struct(arg, &cfg)?;
            Ok(0)
        }
        SL_IOCTL_SYNC_UCAST_CREATE => {
            let cmd_data = read_user_struct::<SleSyncCreateCmd>(arg)?;
            let count = cmd_data.link_count.min(8) as usize;
            let mut ss = context.lock()?;
            let s = Option::as_mut(&mut *ss).ok_or(ENODEV)?;
            let created = s
                .conn
                .sync_ucast_create(cmd_data.group_id, &cmd_data.acl_handles[..count])?;
            let (links, cnt) = s.conn.sync_links_for_group(
                cmd_data.group_id, sle_conn::SyncLinkType::Unicast);
            let (buf, len) = sle_conn::encode_sync_create_cmd(
                cmd_data.group_id, &links[..cnt as usize]);
            let _ = s.controller.send_command(
                sle_dli::SleOpcode::SyncUcastCreate, &buf[..len]);
            Ok(created as isize)
        }
        SL_IOCTL_SYNC_UCAST_REMOVE => {
            let cig_id = read_user_struct::<u8>(arg)?;
            let mut ss = context.lock()?;
            let s = Option::as_mut(&mut *ss).ok_or(ENODEV)?;
            s.conn.sync_ucast_remove(cig_id)?;
            let _ = s.controller.send_command(
                sle_dli::SleOpcode::SyncUcastRemove, &[cig_id]);
            Ok(0)
        }
        SL_IOCTL_SYNC_MCAST_PARAM => {
            let mut cfg = read_user_struct::<SleSyncBigConfig>(arg)?;
            let params = sle_conn::SyncBigParams {
                big_id: cfg.big_id,
                sdu_interval_g2t: cfg.sdu_interval_g2t,
                sdu_interval_t2g: cfg.sdu_interval_t2g,
                max_sdu_g2t: cfg.max_sdu_g2t,
                max_sdu_t2g: cfg.max_sdu_t2g,
                retransmit_g2t: cfg.retransmit_g2t,
                retransmit_t2g: cfg.retransmit_t2g,
                max_latency_g2t: cfg.max_latency_g2t,
                max_latency_t2g: cfg.max_latency_t2g,
                adapt_mode: cfg.adapt_mode,
                link_count: cfg.link_count,
            };
            let mut ss = context.lock()?;
            let s = Option::as_mut(&mut *ss).ok_or(ENODEV)?;
            let result = s.conn.sync_mcast_configure(&params)?;
            cfg.big_id = result.big_id;
            cfg.link_count = result.link_count;
            cfg.handles_out = result.handles;
            let (links, cnt) = s.conn.sync_links_for_group(
                result.big_id, sle_conn::SyncLinkType::Multicast);
            let (buf, len) = sle_conn::encode_sync_param_cmd(
                result.big_id,
                params.sdu_interval_g2t, params.sdu_interval_t2g,
                params.adapt_mode,
                params.max_latency_g2t, params.max_latency_t2g,
                cnt, &links[..cnt as usize],
            );
            let _ = s.controller.send_command(
                sle_dli::SleOpcode::SyncMcastParam, &buf[..len]);
            drop(ss);
            write_user_struct(arg, &cfg)?;
            Ok(0)
        }
        SL_IOCTL_SYNC_MCAST_CREATE => {
            let cmd_data = read_user_struct::<SleSyncCreateCmd>(arg)?;
            let count = cmd_data.link_count.min(8) as usize;
            let mut ss = context.lock()?;
            let s = Option::as_mut(&mut *ss).ok_or(ENODEV)?;
            let created = s
                .conn
                .sync_mcast_create(cmd_data.group_id, &cmd_data.acl_handles[..count])?;
            let (links, cnt) = s.conn.sync_links_for_group(
                cmd_data.group_id, sle_conn::SyncLinkType::Multicast);
            let (buf, len) = sle_conn::encode_sync_create_cmd(
                cmd_data.group_id, &links[..cnt as usize]);
            let _ = s.controller.send_command(
                sle_dli::SleOpcode::SyncMcastCreate, &buf[..len]);
            Ok(created as isize)
        }
        SL_IOCTL_SYNC_MCAST_REMOVE => {
            let big_id = read_user_struct::<u8>(arg)?;
            let mut ss = context.lock()?;
            let s = Option::as_mut(&mut *ss).ok_or(ENODEV)?;
            s.conn.sync_mcast_remove(big_id)?;
            let _ = s.controller.send_command(
                sle_dli::SleOpcode::SyncMcastRemove, &[big_id]);
            Ok(0)
        }
        SL_IOCTL_SYNC_DATAPATH_CFG => {
            let cmd_data = read_user_struct::<SleSyncDatapathCmd>(arg)?;
            let mut ss = context.lock()?;
            let s = Option::as_mut(&mut *ss).ok_or(ENODEV)?;
            s.conn.sync_datapath_config(
                cmd_data.sync_handle,
                cmd_data.direction,
                cmd_data.path_id,
                cmd_data.codec_id,
            )?;
            let (buf, len) = sle_conn::encode_sync_datapath_cmd(
                cmd_data.sync_handle, cmd_data.direction,
                cmd_data.path_id, cmd_data.codec_id);
            let _ = s.controller.send_command(
                sle_dli::SleOpcode::SyncDataPathConfig, &buf[..len]);
            Ok(0)
        }
        SL_IOCTL_SYNC_DATAPATH_REMOVE => {
            let sync_handle = read_user_struct::<u16>(arg)?;
            let mut ss = context.lock()?;
            let s = Option::as_mut(&mut *ss).ok_or(ENODEV)?;
            s.conn.sync_datapath_remove(sync_handle)?;
            let mut buf = [0u8; 3];
            buf[0..2].copy_from_slice(&sync_handle.to_le_bytes());
            buf[2] = 0xFF;
            let _ = s.controller.send_command(
                sle_dli::SleOpcode::SyncDataPathRemove, &buf);
            Ok(0)
        }
        SL_IOCTL_SYNC_INFO => {
            let mut info = read_user_struct::<SleSyncLinkInfo>(arg)?;
            let ss = context.lock()?;
            let s = ss.as_ref().ok_or(ENODEV)?;
            let link = s.conn.sync_link_info(info.sync_handle)?;
            info.acl_handle = link.acl_handle;
            info.group_id = link.cig_id;
            info.stream_id = link.cis_id;
            info.link_type = link.link_type as u8;
            info.state = link.state as u8;
            info.sdu_interval_g2t = link.sdu_interval_g2t;
            info.sdu_interval_t2g = link.sdu_interval_t2g;
            info.max_sdu_g2t = link.max_sdu_g2t;
            info.max_sdu_t2g = link.max_sdu_t2g;
            info.datapath_configured = if link.datapath_configured { 1 } else { 0 };
            drop(ss);
            write_user_struct(arg, &info)?;
            Ok(0)
        }
        SL_IOCTL_SYNC_UCAST_ACCEPT => {
            let sync_handle = read_user_struct::<u16>(arg)?;
            let mut ss = context.lock()?;
            let s = Option::as_mut(&mut *ss).ok_or(ENODEV)?;
            s.conn.sync_ucast_accept(sync_handle)?;
            let _ = s.controller.send_command(
                sle_dli::SleOpcode::SyncUcastAccept,
                &sync_handle.to_le_bytes());
            Ok(0)
        }
        SL_IOCTL_SYNC_UCAST_REJECT => {
            let cmd = read_user_struct::<SleSyncRejectCmd>(arg)?;
            let mut ss = context.lock()?;
            let s = Option::as_mut(&mut *ss).ok_or(ENODEV)?;
            s.conn.sync_ucast_reject(cmd.sync_handle, cmd.reason)?;
            let mut buf = [0u8; 3];
            buf[0..2].copy_from_slice(&cmd.sync_handle.to_le_bytes());
            buf[2] = cmd.reason;
            let _ = s.controller.send_command(
                sle_dli::SleOpcode::SyncUcastReject, &buf);
            Ok(0)
        }
        SL_IOCTL_SYNC_MCAST_ACCEPT => {
            let sync_handle = read_user_struct::<u16>(arg)?;
            let mut ss = context.lock()?;
            let s = Option::as_mut(&mut *ss).ok_or(ENODEV)?;
            s.conn.sync_mcast_accept(sync_handle)?;
            let _ = s.controller.send_command(
                sle_dli::SleOpcode::SyncMcastAccept,
                &sync_handle.to_le_bytes());
            Ok(0)
        }
        SL_IOCTL_SYNC_MCAST_REJECT => {
            let cmd = read_user_struct::<SleSyncRejectCmd>(arg)?;
            let mut ss = context.lock()?;
            let s = Option::as_mut(&mut *ss).ok_or(ENODEV)?;
            s.conn.sync_mcast_reject(cmd.sync_handle, cmd.reason)?;
            let mut buf = [0u8; 3];
            buf[0..2].copy_from_slice(&cmd.sync_handle.to_le_bytes());
            buf[2] = cmd.reason;
            let _ = s.controller.send_command(
                sle_dli::SleOpcode::SyncMcastReject, &buf);
            Ok(0)
        }
        _ => Err(EINVAL),
    }
}

/// Sync data send ioctl — isolated for stack safety (256+251 byte locals).
#[inline(never)]
fn ioctl_sync_data_send(context: &RuntimeContext, arg: usize) -> Result<isize> {
    let cmd = read_user_struct::<SleSyncDataCmd>(arg)?;
    let len = (cmd.len as usize).min(247);
    let ss = context.lock()?;
    let s = ss.as_ref().ok_or(ENODEV)?;
    let link = s.conn.sync_link_info(cmd.sync_handle)?;
    if link.state != sle_conn::SyncLinkState::Active {
        return Err(EPIPE);
    }
    if !link.datapath_configured {
        return Err(EINVAL);
    }
    let seg = match cmd.segment {
        0 => sle_conn::SyncSegment::Complete,
        1 => sle_conn::SyncSegment::First,
        2 => sle_conn::SyncSegment::Middle,
        _ => sle_conn::SyncSegment::Last,
    };
    let hdr = sle_conn::encode_sync_data_header(
        cmd.sync_handle, seg, false, cmd.priority != 0,
        len as u16);
    let mut tx_buf = [0u8; 4 + 247];
    tx_buf[..4].copy_from_slice(&hdr);
    tx_buf[4..4 + len].copy_from_slice(&cmd.data[..len]);
    s.controller.send_data(cmd.sync_handle, &tx_buf[..4 + len])?;
    Ok(len as isize)
}

/// DLI command ioctl — isolated for stack safety (SleDliCmd = 248 bytes).
#[inline(never)]
fn ioctl_dli_send_cmd(context: &RuntimeContext, arg: usize) -> Result<isize> {
    let mut cmd_data: SleDliCmd = read_user_struct(arg)?;
    let param_len = cmd_data.param_len as usize;
    if param_len > DLI_PARAM_MAX {
        return Err(EINVAL);
    }
    if sle_dli::sle_opcode_from_u16(cmd_data.opcode).is_none() {
        return Err(EINVAL);
    }
    {
        let mut ss = context.lock()?;
        let s = Option::as_mut(&mut *ss).ok_or(ENODEV)?;
        s.controller.validate_command(cmd_data.opcode, &cmd_data.params[..param_len])?;
        cmd_data.seq = s.cmd_pending.submit(cmd_data.opcode)?;
        let enqueue = if s.controller.uses_command_host() {
            context.owner.as_ref().ok_or(ENODEV)?.host.lock().enqueue(
                cmd_data.opcode, &cmd_data.params[..param_len], cmd_data.seq,
            )
        } else {
            s.cmd_queue.push_tracked(cmd_data.opcode, &cmd_data.params[..param_len], cmd_data.seq)
        };
        if let Err(error) = enqueue {
            s.cmd_pending.rollback(cmd_data.seq);
            return Err(error);
        }
    }
    context.owner.as_ref().ok_or(ENODEV)?.kick_commands();
    write_user_struct(arg, &cmd_data)?;
    Ok(0)
}

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
    let result = (|| -> Result {
        let mut state = owner.state.lock();
        let state = Option::as_mut(&mut *state).ok_or(ENODEV)?;
        if *owner.schedule_gate.lock() { return Err(ENODEV); }
        {
            let host = owner.host.lock();
            if let Some(error) = host.controller_status().2 { return Err(error); }
            let (adv, scan, _) = host.discovery_radio();
            // The native raw whitelist contains queries only. A quiet diagnostic
            // reader has not changed radio policy. Managed requires confirmed Off.
            if host.quiet() && (mode == sle_management::DIAGNOSTIC || (adv == 1 && scan == 1)) {
                gate.settled(0); return Ok(());
            }
        }
        let controller = match &state.controller {
            sle_dli::ControllerBackend::Ws73(controller) => controller,
            _ => return Err(Error::from_errno(-(bindings::EOPNOTSUPP as i32))),
        };
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
            state.cmd_pending.resolve_seq(request.seq, 0x03, &[]);
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
    if owner.protocol_profile == 0 { return Err(Error::from_errno(-(bindings::EOPNOTSUPP as i32))); }
    let mut gate = owner.management.lock();
    if *owner.schedule_gate.lock() { return Err(ENODEV); }
    if gate.state == sle_management::REVOKING {
        if let Some(result) = owner.host.lock().revocation_result() {
            gate.settled(result.err().map_or(0, |error| error.to_errno()));
        }
    }
    if cmd == SL_IOCTL_MANAGEMENT_QUERY {
        let input: SleManagementQuery = read_user_struct(arg)?;
        if input.version != 1 { return Err(Error::from_errno(-(bindings::EOPNOTSUPP as i32))); }
        if input.generation != 0 && input.generation != owner.identity.generation { return Err(ENODEV); }
        let detail = if gate.state == sle_management::FAULTED { owner.host.lock().revocation_detail() } else { (0, 0, false) };
        let output = SleManagementQuery {
            version: 1, generation: owner.identity.generation,
            lease: gate.token_for(me.file_id), mode: gate.mode, state: gate.state,
            flags: u32::from(gate.owns(me.file_id)) | (u32::from(detail.2) << 1),
            error: gate.error, status: detail.0 as u32, opcode: detail.1 as u32, reserved: 0,
        };
        write_user_struct(arg, &output)?;
        return Ok(0);
    }
    let mut request: SleManagementRequest = read_user_struct(arg)?;
    if request.version != 1 { return Err(Error::from_errno(-(bindings::EOPNOTSUPP as i32))); }
    if request.generation == 0 || request.generation != owner.identity.generation { return Err(ENODEV); }
    if cmd == SL_IOCTL_MANAGEMENT_ACQUIRE {
        if request.lease != 0 || me.owned_target.lock().is_some() { return Err(EINVAL); }
        if !owner.transport_open.load(core::sync::atomic::Ordering::Acquire) { return Err(EAGAIN); }
        if let Some(error) = owner.host.lock().controller_status().2 { return Err(error); }
        let token = gate.prepare(request.mode).map_err(management_error)?;
        if !owner.host.lock().quiet() { return Err(EBUSY); }
        request.lease = token;
        // No command has been admitted. EFAULT leaves ownership and counter
        // unchanged; commit cannot fail while the management mutex is held.
        write_user_struct(arg, &request)?;
        gate.commit(me.file_id, request.mode, token);
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
    match &state.controller {
        sle_dli::ControllerBackend::Ws73(controller) => {
            controller.fill_snapshot(&mut out);
            out.flags = if native_ready { 1 } else { 2 };
        }
        _ => {
            let info = state.controller.info();
            out.address = info.addr;
            out.version_tuple[..4].copy_from_slice(&info.fw_version.to_le_bytes());
            out.features[..8].copy_from_slice(&info.features.to_le_bytes());
            out.features[8..].copy_from_slice(&info.features_ext.to_le_bytes());
            out.flags = 1; // legacy Runtime availability, not full queried metadata
        }
    }
    if let Some(error) = fault {
        out.flags = 4;
        out.error = error.to_errno();
    }
    drop(guard);
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
        _ => return Err(Error::from_errno(-(bindings::EOPNOTSUPP as i32))),
    };
    if request.operation != 1 && (request.flags != 0 || request.data_len != 0
        || request.scan_response_len != 0 || request.duration != 0 || request.max_events != 0) { return Err(EINVAL); }
    if request.operation >= 3 && request.handle != 0 { return Err(EINVAL); }
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
    if sle_configfs::power_mode() >= 2 { return Err(EPERM); }
    let state_guard = context.lock()?;
    let state = state_guard.as_ref().ok_or(ENODEV)?;
    let plan = match &state.controller {
        sle_dli::ControllerBackend::Ws73(controller) => controller.prepare_discovery(&request)?,
        _ => return Err(Error::from_errno(-(bindings::EOPNOTSUPP as i32))),
    };
    let mut parts = [sle_command_plan::RecipePart { opcode: 0, params: &[] }; 4];
    for (i, step) in plan.steps[..plan.count as usize].iter().enumerate() {
        parts[i] = sle_command_plan::RecipePart { opcode: step.opcode, params: &step.params[..step.length as usize] };
    }
    let gate = owner.schedule_gate.lock();
    if *gate { return Err(ENODEV); }
    owner.host.lock().submit_discovery(request.request_id, intent, &parts[..plan.count as usize], plan.power_step as u8)?;
    drop(gate);
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
    let owner = context.owner.as_ref().ok_or(ENODEV)?;
    if me.target.lock().as_ref().map(|target| target.identity) != Some(owner.identity) || query.generation == 0 { return Err(EINVAL); }
    if owner.protocol_profile != 1 { return Err(Error::from_errno(-(bindings::EOPNOTSUPP as i32))); }
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

/// Infrastructure ioctl sub-dispatcher: PM, sync, DLI, events, PHY, role, RAL/RPA.
#[inline(never)]
fn ioctl_dispatch_infra(context: &RuntimeContext, me: Pin<&SparkLinkCtl>, cmd: u32, arg: usize) -> Result<isize> {
    match cmd {
        SL_IOCTL_SNOOP_GET => ioctl_snoop_get(context, me, arg),
        SL_IOCTL_CONTROLLER_SNAPSHOT => ioctl_controller_snapshot(context, me, arg),
        SL_IOCTL_DISCOVERY_SUBMIT => ioctl_discovery_submit(context, me, arg),
        SL_IOCTL_DISCOVERY_RESULT => ioctl_discovery_result(context, me, arg),
        SL_IOCTL_DISCOVERY_TIMING => ioctl_discovery_timing(context, me, arg),
        SL_IOCTL_CONTROLLER_EVENT_GET => ioctl_controller_event_get(context, me, arg),
        SL_IOCTL_PM_INFO => {
            let info = {
                let ss = context.lock()?;
                let s = ss.as_ref().ok_or(ENODEV)?;
                let mut info: SlePmInfo = unsafe { core::mem::zeroed() };
                info.state = s.power.state as u8;
                info.force_active = if s.power.is_forced_active() { 1 } else { 0 };
                info.power_pct = s.power.estimated_power_pct();
                info.current_interval = s.power.interval.current_interval;
                info.supervision_timeout = s.power.interval.supervision_timeout;
                info.latency = s.power.interval.latency;
                info.idle_count = s.power.stats.active_events.min(u64::from(u16::MAX)) as u16;
                info.transitions = s.power.stats.transitions;
                info.active_events = s.power.stats.active_events;
                info.sniff_events = s.power.stats.sniff_events;
                info.idle_events = s.power.stats.idle_events;
                info
            };
            write_user_struct(arg, &info)?;
            Ok(0)
        }
        SL_IOCTL_PM_SET_STATE => {
            let cmd_data: SlePmStateCmd = read_user_struct(arg)?;
            let mut ss = context.lock()?;
            let s = Option::as_mut(&mut *ss).ok_or(ENODEV)?;
            match cmd_data.target_state {
                0 => {
                    s.power.resume();
                    Ok(0)
                }
                1 => {
                    s.power.on_activity();
                    s.power.force_active(false);
                    Ok(0)
                }
                3 => {
                    s.power.suspend()?;
                    Ok(0)
                }
                _ => Err(EINVAL),
            }
        }
        SL_IOCTL_PM_SET_INTERVAL => {
            let params: SlePmInterval = read_user_struct(arg)?;
            let interval = sle_power::ConnInterval {
                min_interval: params.min_interval,
                max_interval: params.max_interval,
                current_interval: params.min_interval,
                latency: params.latency,
                supervision_timeout: params.supervision_timeout,
            };
            let mut ss = context.lock()?;
            let s = Option::as_mut(&mut *ss).ok_or(ENODEV)?;
            s.power.update_interval(interval)?;
            Ok(0)
        }
        SL_IOCTL_PM_FORCE_ACTIVE => {
            let enable: u8 = read_user_struct(arg)?;
            let mut ss = context.lock()?;
            let s = Option::as_mut(&mut *ss).ok_or(ENODEV)?;
            s.power.force_active(enable != 0);
            Ok(0)
        }
        SL_IOCTL_PM_TICK => {
            let mut ss = context.lock()?;
            let s = Option::as_mut(&mut *ss).ok_or(ENODEV)?;
            s.power.on_tick();
            Ok(0)
        }
        SL_IOCTL_PM_ACTIVITY => {
            let mut ss = context.lock()?;
            let s = Option::as_mut(&mut *ss).ok_or(ENODEV)?;
            s.power.on_activity();
            Ok(0)
        }
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
        | SL_IOCTL_SYNC_MCAST_REJECT => ioctl_sync_link(context, cmd, arg),
        SL_IOCTL_SYNC_DATA_SEND => ioctl_sync_data_send(context, arg),
        SL_IOCTL_EVENT_COUNT => {
            let count = me.events.lock().pending();
            Ok(count as isize)
        }
        SL_IOCTL_EVENT_STATS => {
            let guard = me.events.lock();
            let stats = SleEventStats {
                pending: guard.pending() as u32,
                _pad: 0,
                total_enqueued: guard.total_enqueued,
                total_dropped: guard.total_dropped,
                total_delivered: guard.total_delivered,
            };
            drop(guard);
            write_user_struct(arg, &stats)?;
            Ok(0)
        }
        SL_IOCTL_DLI_INFO => {
            let ss = context.lock()?;
            let s = ss.as_ref().ok_or(ENODEV)?;
            let cinfo = s.controller.info();
            let mut name = [0u8; 32];
            let copy_len = cinfo.name.len().min(31);
            name[..copy_len].copy_from_slice(&cinfo.name[..copy_len]);
            let info = SleDliInfo {
                bus: cinfo.bus as u8,
                _pad: [0u8; 3],
                firmware_version: cinfo.fw_version,
                features: cinfo.features,
                max_connections: cinfo.max_connections,
                max_adv_sets: sle_adv::EXT_ADV_MAX_SETS as u8,
                transport_modes: cinfo.transport_modes,
                measurement_cap: cinfo.measurement_cap,
                max_mtu: cinfo.max_mtu,
                max_mps: cinfo.max_mps,
                security_cap: cinfo.security_cap,
                features_ext: cinfo.features_ext,
                name,
                _reserved: [0u8; 4],
            };
            drop(ss);
            write_user_struct(arg, &info)?;
            Ok(0)
        }
        SL_IOCTL_DLI_POLL_EVENT => {
            let mut ss = context.lock()?;
            let s = Option::as_mut(&mut *ss).ok_or(ENODEV)?;
            if let Some(dli_ev) = s.pop_dli_event() {
                drop(ss);
                write_user_struct(arg, &dli_ev)?;
                return Ok(0);
            }
            match s.controller.poll_event() {
                Some(ev) => {
                    let dli_ev = sle_dli_event_to_wire(&ev);
                    drop(ss);
                    write_user_struct(arg, &dli_ev)?;
                    Ok(0)
                }
                None => Err(EAGAIN),
            }
        }
        SL_IOCTL_DLI_RESET => {
            let mut ss = context.lock()?;
            let s = Option::as_mut(&mut *ss).ok_or(ENODEV)?;
            s.controller.reset()?;
            Ok(0)
        }
        SL_IOCTL_DLI_SEND_CMD => ioctl_dli_send_cmd(context, arg),
        SL_IOCTL_MGMT_STATS => {
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
        SL_IOCTL_SUBSYS_STATS => {
            let (dev_count, proto_count, binding_count) = {
                let guard = SUBSYSTEM.lock();
                let s = guard.as_ref().ok_or(ENODEV)?;
                (s.dev_registry.count() as u16, s.proto_registry.count(), s.dev_bindings.count())
            };
            let ss = context.lock()?;
            let s = ss.as_ref().ok_or(ENODEV)?;
            let stats = SleSubsysStats {
                dev_count,
                proto_count,
                binding_count,
                active_connections: s.conn.active_count() as u16,
                mgmt_pending: s.cmd_pending.pending_count,
                total_conn_created: s.conn.total_created as u32,
                total_conn_completed: s.conn.total_completed as u32,
                total_mgmt_submitted: s.cmd_pending.total_submitted as u32,
                total_mgmt_timeouts: s.cmd_pending.total_timeouts as u32,
                power_state: s.power.state as u8,
                _pad: [0; 3],
                power_transitions: s.power.stats.transitions,
                crc_errors: sle_pdu::crc_error_count(),
            };
            drop(ss);
            write_user_struct(arg, &stats)?;
            Ok(0)
        }
        SL_IOCTL_USB_DEV_COUNT => Ok(sle_usb::usb_device_count() as isize),
        SL_IOCTL_PHY_INFO => {
            let ss = context.lock()?;
            let s = ss.as_ref().ok_or(ENODEV)?;
            let mcs = sle_phy::mcs_lookup(s.phy.mcs_index);
            let info = SlePhyInfo {
                mcs_index: s.phy.mcs_index,
                bandwidth_mhz: s.phy.bandwidth_mhz,
                pilot_density: s.phy.pilot_density,
                tx_power_dbm: s.phy.tx_power_dbm,
                mimo_mode: s.phy.antenna.mode as u8,
                num_tx_ant: s.phy.antenna.num_tx,
                num_rx_ant: s.phy.antenna.num_rx,
                ofdm: if mcs.is_some_and(|m| m.ofdm) { 1 } else { 0 },
                data_rate_kbps: s.phy.effective_data_rate_kbps(),
                hop_channel: s.phy.hopping.last_channel,
                hop_increment: s.phy.hopping.hop_increment,
                hop_used_channels: s.phy.hopping.channel_map.used_count(),
                modulation: mcs.map_or(0, |m| m.modulation as u8),
                code_rate_num: mcs.map_or(0, |m| m.code_rate.num),
                code_rate_den: mcs.map_or(0, |m| m.code_rate.den),
                ..Default::default()
            };
            drop(ss);
            write_user_struct(arg, &info)?;
            Ok(0)
        }
        SL_IOCTL_PHY_SET_MCS => {
            let cmd_data: SlePhyMcsCmd = read_user_struct(arg)?;
            let mut ss = context.lock()?;
            let s = Option::as_mut(&mut *ss).ok_or(ENODEV)?;
            s.phy.set_mcs(cmd_data.mcs_index)?;
            s.controller.set_coding_modulation(cmd_data.mcs_index)?;
            Ok(0)
        }
        SL_IOCTL_PHY_SET_TXPOWER => {
            let cmd_data: SlePhyTxPowerCmd = read_user_struct(arg)?;
            let mut ss = context.lock()?;
            let s = Option::as_mut(&mut *ss).ok_or(ENODEV)?;
            s.phy.set_tx_power(cmd_data.tx_power_dbm)?;
            s.controller.set_tx_power(cmd_data.tx_power_dbm)?;
            Ok(0)
        }
        SL_IOCTL_PHY_MCS_SELECT => {
            let mut sel: SlePhyMcsSelect = read_user_struct(arg)?;
            let ss = context.lock()?;
            let s = ss.as_ref().ok_or(ENODEV)?;
            let best = sle_phy::mcs_select_with_thresholds(
                sel.min_kbps,
                sel.bandwidth_mhz,
                sel.sinr_db_x10,
                &s.phy.sinr_thresholds,
            );
            sel.selected_mcs = best;
            sel.effective_kbps = sle_phy::data_rate_kbps(best, sel.bandwidth_mhz).unwrap_or(0);
            drop(ss);
            write_user_struct(arg, &sel)?;
            Ok(0)
        }
        SL_IOCTL_PHY_HOP_NEXT => {
            let mut ss = context.lock()?;
            let s = Option::as_mut(&mut *ss).ok_or(ENODEV)?;
            let ch = s.phy.hopping.next_channel();
            let info = SlePhyHopInfo {
                channel: ch,
                freq_mhz: sle_phy::HoppingState::channel_to_freq(ch),
                event_counter: s.phy.hopping.event_counter,
                ..Default::default()
            };
            drop(ss);
            write_user_struct(arg, &info)?;
            Ok(0)
        }
        SL_IOCTL_PHY_SET_BW => {
            let cmd_data: SlePhyBwCmd = read_user_struct(arg)?;
            let mut ss = context.lock()?;
            let s = Option::as_mut(&mut *ss).ok_or(ENODEV)?;
            s.phy.set_bandwidth(cmd_data.bandwidth_mhz)?;
            s.controller.set_bandwidth(cmd_data.bandwidth_mhz)?;
            Ok(0)
        }
        SL_IOCTL_PHY_GET_SINR => {
            let ss = context.lock()?;
            let s = ss.as_ref().ok_or(ENODEV)?;
            let out = SleSinrThresholds {
                thresholds: s.phy.sinr_thresholds,
                _pad: [0; 2],
            };
            drop(ss);
            write_user_struct(arg, &out)?;
            Ok(0)
        }
        SL_IOCTL_PHY_SET_SINR => {
            let cmd_data: SleSinrThresholds = read_user_struct(arg)?;
            let mut ss = context.lock()?;
            let s = Option::as_mut(&mut *ss).ok_or(ENODEV)?;
            s.phy.sinr_thresholds = cmd_data.thresholds;
            Ok(0)
        }
        SL_IOCTL_SET_ROLE => {
            let role_byte: u8 = read_user_struct(arg)?;
            let role = match role_byte {
                0 => GtRole::TNode,
                1 => GtRole::GNode,
                _ => return Err(EINVAL),
            };
            let mut ss = context.lock()?;
            let s = Option::as_mut(&mut *ss).ok_or(ENODEV)?;
            if s.conn.active_handles().1 > 0 {
                dev_warn!(
                    me.dev,
                    "sparklink: cannot change role with active connections\n"
                );
                return Err(EBUSY);
            }
            s.local_role = role;
            dev_info!(me.dev, "sparklink: local role set to {:?}\n", role);
            Ok(0)
        }
        SL_IOCTL_GET_ROLE => {
            let ss = context.lock()?;
            let s = ss.as_ref().ok_or(ENODEV)?;
            write_user_struct(arg, &(s.local_role as u8))?;
            Ok(0)
        }
        SL_IOCTL_RAL_ADD => {
            ioctl_ral_add(context, arg)?;
            Ok(0)
        }
        SL_IOCTL_RAL_REMOVE => {
            let params: SleRalRemoveParams = read_user_struct(arg)?;
            let mut ss = context.lock()?;
            let s = Option::as_mut(&mut *ss).ok_or(ENODEV)?;
            s.rpa.ral_remove(params.peer_id_type, &params.peer_id)?;
            Ok(0)
        }
        SL_IOCTL_RAL_CLEAR => {
            let mut ss = context.lock()?;
            let s = Option::as_mut(&mut *ss).ok_or(ENODEV)?;
            s.rpa.ral_clear()?;
            Ok(0)
        }
        SL_IOCTL_RAL_SIZE => {
            let ss = context.lock()?;
            let s = ss.as_ref().ok_or(ENODEV)?;
            let count = s.rpa.ral_size();
            write_user_struct(arg, &count)?;
            Ok(0)
        }
        SL_IOCTL_RAL_READ_PEER_RPA => {
            ioctl_ral_read_rpa(context, arg, false)?;
            Ok(0)
        }
        SL_IOCTL_RAL_READ_LOCAL_RPA => {
            ioctl_ral_read_rpa(context, arg, true)?;
            Ok(0)
        }
        SL_IOCTL_RPA_ENABLE => {
            let enable: u8 = read_user_struct(arg)?;
            let mut ss = context.lock()?;
            let s = Option::as_mut(&mut *ss).ok_or(ENODEV)?;
            s.rpa.set_enabled(enable != 0);
            Ok(0)
        }
        SL_IOCTL_RPA_SET_TIMEOUT => {
            let secs: u16 = read_user_struct(arg)?;
            let mut ss = context.lock()?;
            let s = Option::as_mut(&mut *ss).ok_or(ENODEV)?;
            s.rpa.set_timeout(secs);
            Ok(0)
        }
        // -- Narrowband AFH measurement (T/XS 10003-2025 §8.7) --
        SL_IOCTL_MEAS_READ_CAP => {
            let ss = context.lock()?;
            let s = ss.as_ref().ok_or(ENODEV)?;
            let cinfo = s.controller.info();
            let cap = SleMeasCap {
                meas_types: cinfo.measurement_cap,
                max_instances: 1,
                antenna_count: 1,
                _reserved: 0,
            };
            drop(ss);
            write_user_struct(arg, &cap)?;
            Ok(0)
        }
        SL_IOCTL_MEAS_SET_LINK_PARAM => {
            let params: SleMeasLinkParam = read_user_struct(arg)?;
            let mut buf = [0u8; 8];
            buf[0..2].copy_from_slice(&params.handle.to_le_bytes());
            buf[2] = params.meas_type;
            buf[3] = params.config_index;
            buf[4..6].copy_from_slice(&params.interval.to_le_bytes());
            buf[6..8].copy_from_slice(&params.duration.to_le_bytes());
            let ss = context.lock()?;
            let s = ss.as_ref().ok_or(ENODEV)?;
            s.controller.send_command(sle_dli::SleOpcode::SetMeasLinkParam, &buf)?;
            Ok(0)
        }
        SL_IOCTL_MEAS_ACTION => {
            let action: SleMeasAction = read_user_struct(arg)?;
            let buf = [
                action.handle.to_le_bytes()[0],
                action.handle.to_le_bytes()[1],
                action.action,
                action.config_index,
            ];
            let ss = context.lock()?;
            let s = ss.as_ref().ok_or(ENODEV)?;
            s.controller.send_command(sle_dli::SleOpcode::MeasAction, &buf)?;
            Ok(0)
        }
        SL_IOCTL_MEAS_ENABLE => {
            let enable: u8 = read_user_struct(arg)?;
            let ss = context.lock()?;
            let s = ss.as_ref().ok_or(ENODEV)?;
            s.controller.send_command(sle_dli::SleOpcode::EnableMeas, &[enable])?;
            Ok(0)
        }
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
                    operation <- new_mutex!(()),
                    owned_target <- new_mutex!(None),
                    events <- new_mutex!(EventQueue::new()),
                    event_poll <- new_poll_condvar!("sparklink_event"),
                    dev: dev,
                    last_seq: core::sync::atomic::AtomicU64::new(
                        sle_event::BroadcastRing::current_seq()
                    ),
                    target <- new_mutex!(None),
                    controller_subscription <- new_mutex!(None),
                    snoop_subscription <- new_mutex!(None),
                }
            },
            GFP_KERNEL,
        )
    }

    fn read_iter(kiocb: Kiocb<'_, Self::Ptr>, iov: &mut IovIterDest<'_>) -> Result<usize> {
        let me = kiocb.file();
        // Sync broadcast events into per-fd queue before reading.
        Self::sync_broadcast(me.as_ref());
        let mut guard = me.events.lock();
        if !guard.has_events() {
            return Err(EAGAIN);
        }
        let mut total = 0usize;
        let evt_size = core::mem::size_of::<sle_event::SleWireEvent>();
        while guard.has_events() && iov.len() >= evt_size {
            if let Some(evt) = guard.dequeue() {
                let bytes: &[u8] = evt.as_bytes();
                let written = iov.copy_to_iter(bytes);
                if written == 0 {
                    break;
                }
                total += written;
            }
        }
        Ok(total)
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
                None => RuntimeContext::default_selection(),
            };
            let Some(owner) = context.owner.as_ref() else { return bindings::POLLERR | bindings::POLLHUP; };
            if owner.identity != subscription.identity { return bindings::POLLERR | bindings::POLLHUP; }
            table.register_wait(file, &owner.controller_event_poll);
            if context.lock().is_err() { return bindings::POLLERR | bindings::POLLHUP; }
            return if owner.controller_events.lock().current_seq() > subscription.after_seq {
                bindings::POLLIN | bindings::POLLRDNORM
            } else { 0 };
        }
        table.register_wait(file, &me.event_poll);
        // Sync broadcast events into per-fd queue before checking.
        Self::sync_broadcast(me.as_ref());
        let guard = me.events.lock();
        let mut mask = 0u32;
        if guard.has_events() {
            mask |= bindings::POLLIN | bindings::POLLRDNORM;
        }
        mask
    }

    fn ioctl(me: Pin<&SparkLinkCtl>, _file: &FsFile, cmd: u32, arg: usize) -> Result<isize> {
        let _operation = me.operation.lock();
        let access = sle_authorization::classify(cmd)?;
        if matches!(access, sle_authorization::Access::Protected | sle_authorization::Access::PrivilegedObserve) {
            sle_authorization::require_admin()?;
        }
        // Per-fd device routing: DEV_SELECT and DEV_GET_ACTIVE are handled
        // before capturing a RuntimeContext so they can query/set affinity.
        match cmd {
            SL_IOCTL_DEV_SELECT => return ioctl_dev_select(me, arg),
            SL_IOCTL_DEV_GET_ACTIVE => return ioctl_dev_get_active(me, arg),
            _ => {}
        }

        let registration_only = matches!(cmd,
            SL_IOCTL_DEV_COUNT | SL_IOCTL_DEV_LIST | SL_IOCTL_DEV_REGISTER |
            SL_IOCTL_DEV_UNREGISTER | SL_IOCTL_DEV_SWITCH
        );
        // Release the fd binding lock before taking the registry lock. read/poll
        // uses registry -> binding order; retaining this guard would invert it.
        let target = me.target.lock().clone();
        let context = if registration_only {
            RuntimeContext { owner: None }
        } else {
            match target {
                Some(owner) => RuntimeContext::from_owner(owner),
                None => RuntimeContext::default_selection(),
            }
        };
        let context = &context;
        if matches!(cmd, SL_IOCTL_MANAGEMENT_ACQUIRE | SL_IOCTL_MANAGEMENT_RELEASE | SL_IOCTL_MANAGEMENT_QUERY) {
            return ioctl_management(context, me, cmd, arg);
        }
        // Admission serialization lasts through dispatch. Workers do not take
        // this mutex under the protocol mutex; revocation completion is in Host.
        let mut management_guard = if access == sle_authorization::Access::Protected && !registration_only {
            context.owner.as_ref().filter(|owner| owner.protocol_profile != 0).map(|owner| owner.management.lock())
        } else { None };
        if let Some(gate) = management_guard.as_mut() {
            if *context.owner.as_ref().ok_or(ENODEV)?.schedule_gate.lock() { return Err(ENODEV); }
            let required_mode = if matches!(cmd, SL_IOCTL_DLI_SEND_CMD | SL_IOCTL_DLI_POLL_EVENT | SL_IOCTL_DLI_RESET) {
                sle_management::DIAGNOSTIC
            } else { sle_management::MANAGED };
            gate.authorize(me.file_id, required_mode).map_err(management_error)?;
        }
        // Observation never applies global policy or modifies Runtime state.
        if !registration_only && access == sle_authorization::Access::Protected {
            Self::sync_power_mode(context)?;
        }

        match cmd {
            // --- Advertising, scanning, device management ---
            SL_IOCTL_START_ADV
            | SL_IOCTL_STOP_ADV
            | SL_IOCTL_START_SCAN
            | SL_IOCTL_STOP_SCAN
            | SL_IOCTL_DEV_COUNT
            | SL_IOCTL_DEV_INFO
            | SL_IOCTL_DEV_REGISTER
            | SL_IOCTL_DEV_UNREGISTER
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
            // --- AFH, security, SSAP ---
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
            | SL_IOCTL_SEC_SET_PASSWORD
            | SL_IOCTL_SSAP_REGISTER_SVC
            | SL_IOCTL_SSAP_INFO
            | SL_IOCTL_SSAP_READ
            | SL_IOCTL_SSAP_WRITE
            | SL_IOCTL_SSAP_FIND_SVC
            | SL_IOCTL_SSAP_NOTIFY
            | SL_IOCTL_SSAP_DEQUEUE_NTF
            | SL_IOCTL_SSAP_ADD_SVC
            | SL_IOCTL_SSAP_ADD_PROP
            | SL_IOCTL_SSAP_REMOVE_SVC
            | SL_IOCTL_SSAP_EXCHANGE_INFO
            | SL_IOCTL_SSAP_REMOTE_DISCOVER
            | SL_IOCTL_SSAP_REMOTE_READ
            | SL_IOCTL_SSAP_REMOTE_WRITE
            | SL_IOCTL_SSAP_REMOTE_EVENT => ioctl_dispatch_sec_ssap(context, cmd, arg),
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
            | SL_IOCTL_EVENT_COUNT
            | SL_IOCTL_EVENT_STATS
            | SL_IOCTL_DLI_INFO
            | SL_IOCTL_CONTROLLER_EVENT_GET
            | SL_IOCTL_SNOOP_GET
            | SL_IOCTL_CONTROLLER_SNAPSHOT
            | SL_IOCTL_DISCOVERY_SUBMIT
            | SL_IOCTL_DISCOVERY_RESULT
            | SL_IOCTL_DISCOVERY_TIMING
            | SL_IOCTL_DLI_POLL_EVENT
            | SL_IOCTL_DLI_RESET
            | SL_IOCTL_DLI_SEND_CMD
            | SL_IOCTL_MGMT_STATS
            | SL_IOCTL_SUBSYS_STATS
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

impl SparkLinkCtl {
    /// Synchronize configfs power_mode into SubsystemShared.
    /// Called at the beginning of ioctls that initiate active operations.
    fn sync_power_mode(context: &RuntimeContext) -> Result {
        let configfs_mode = sle_configfs::power_mode();
        let mut ss = context.lock()?;
        if let Some(ref mut shared) = *ss {
            let old_pct = shared.power.estimated_power_pct();
            if shared.power.set_mode(configfs_mode) {
                let new_pct = shared.power.estimated_power_pct();
                pr_info!(
                    "sparklink: power mode changed to {} ({}% -> {}%)\n",
                    configfs_mode,
                    old_pct,
                    new_pct
                );
                // Push a power changed event through per-fd EventQueue path
                // instead of broadcast ring (avoid pub visibility issue).
            }
        }
        Ok(())
    }

    /// Check if the subsystem power mode allows active operations.
    /// Returns Err(EPERM) if in idle mode.
    fn check_power_active() -> Result {
        let mode = sle_configfs::power_mode();
        if mode >= 2 {
            // Idle or suspended — reject active operations.
            return Err(EPERM);
        }
        Ok(())
    }

    /// Synchronize events from the global broadcast ring into this fd's
    /// per-listener event queue. Called before read() and poll() so that
    /// all open fds see the same event stream regardless of which fd
    /// triggered the operation that produced the event.
    fn sync_broadcast(me: Pin<&SparkLinkCtl>) {
        let cur = sle_event::BroadcastRing::current_seq();
        let my_seq = me.last_seq.load(core::sync::atomic::Ordering::Relaxed);
        if cur <= my_seq {
            return; // no new events
        }
        let target = me.target.lock().clone();
        let context = match target {
            Some(owner) => RuntimeContext { owner: Some(owner) },
            None => RuntimeContext::default_selection(),
        };
        let Ok(guard) = context.lock() else { return };
        let Some(runtime) = guard.as_ref() else { return };
        let mut eq = me.events.lock();
        let (copied, new_seq) = runtime.broadcast.drain_since(my_seq, &mut eq);
        if copied > 0 {
            me.last_seq.store(new_seq, core::sync::atomic::Ordering::Relaxed);
        }
    }

    /// Publish an event to the global broadcast ring (visible to all fds)
    /// and also push it into this fd's local queue for immediate reads.
    fn broadcast_event(context: &RuntimeContext, me: Pin<&SparkLinkCtl>, event: sle_event::SleWireEvent) -> Result {
        {
            let mut ss = context.lock()?;
            if let Some(ref mut shared) = *ss {
                shared.broadcast.publish(event);
            }
        }
        // Also push directly to this fd so the caller gets immediate read.
        me.events.lock().push_raw(event);
        let new_seq = sle_event::BroadcastRing::current_seq();
        me.last_seq
            .store(new_seq, core::sync::atomic::Ordering::Relaxed);
        me.event_poll.notify_all();
        Ok(())
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
