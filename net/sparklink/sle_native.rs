// SPDX-License-Identifier: GPL-2.0-only

//! Native WS73 bootstrap owner. Transport callbacks retain their context;
//! protocol scheduling and transaction credit belong to ControllerRuntime.
//! Registration remains SETUP until the complete native Host path is ready.

use core::sync::atomic::{AtomicBool, Ordering};
use core::ffi::c_void;
use core::cell::Cell;
use kernel::sync::Arc;
use kernel::prelude::*;

const PROTOCOL_ERROR: i32 = -(kernel::bindings::EPROTO as i32);
const UNSUPPORTED: i32 = -(kernel::bindings::EOPNOTSUPP as i32);

use super::sle_command_plan::{DiscoveryIntent, RecipeTag};
use super::sle_uapi::{SleDiscoveryAdvConfig, SleDiscoveryScanConfig, SleDiscoverySubmit, SleConnectionSubmit, SleConnectionParameters};
use super::sle_dev::DeviceIdentity;
use super::sle_dli::{SleBus, SleController, SleControllerInfo, SleEvent, SleOpcode};

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct NativeInfo {
    profile: u32,
    version: [u8; 5],
    features: [u8; 10],
    address: [u8; 6],
    command_credits: u8,
    acb_length: u16,
    icb_length: u16,
    acb_count: u8,
    icb_count: u8,
}

const _: () = assert!(core::mem::size_of::<NativeInfo>() == 32);
const _: () = assert!(core::mem::offset_of!(NativeInfo, features) == 9);
const _: () = assert!(core::mem::offset_of!(NativeInfo, address) == 19);
const _: () = assert!(core::mem::offset_of!(NativeInfo, acb_length) == 26);

#[repr(C)]
pub(crate) struct NativeIdentity {
    id: u16,
    generation: u64,
}

#[repr(C)]
struct NativeDiscoveryRequest {
    operation: u32,
    advertising: *const SleDiscoveryAdvConfig,
    scanning: *const SleDiscoveryScanConfig,
    handle: u32, duration: u32, max_events: u32,
    data: *const u8, data_size: u32, scan_response_present: u32,
    scan_response: *const u8, scan_response_size: u32,
}
#[repr(C)]
pub(crate) struct NativeDiscoveryStep {
    pub(crate) opcode: u16, pub(crate) length: u16,
    pub(crate) params: [u8; 255],
}
#[repr(C)]
pub(crate) struct NativeDiscoveryPlan {
    pub(crate) operation: u32, pub(crate) count: u32, pub(crate) power_step: u32,
    pub(crate) steps: [NativeDiscoveryStep; 4],
}
const _: () = assert!(core::mem::size_of::<NativeDiscoveryPlan>() == 1052);

#[repr(C)]
struct NativeConnectionRequest { operation: u32, handle: u32, reason: u32, parameters: SleConnectionParameters }
#[repr(C)]
pub(crate) struct NativeConnectionPlan { pub operation: u32, pub opcode: u16, pub length: u16, pub params: [u8; 32] }
extern "C" {
    fn sparklink_native_transport_prepare_connection(transport: *mut c_void,
        request: *const NativeConnectionRequest, plan: *mut NativeConnectionPlan) -> i32;
    fn sparklink_native_transport_validate_connection(transport: *mut c_void,
        operation: u32, opcode: u16, params: *const u8, length: usize) -> i32;
    fn sparklink_native_transport_prepare(
        transport: *mut c_void, request: *const NativeDiscoveryRequest,
        plan: *mut NativeDiscoveryPlan,
    ) -> i32;
    fn sparklink_native_transport_free(transport: *mut c_void);
    fn sparklink_native_transport_get(transport: *mut c_void);
    fn sparklink_native_transport_open(transport: *mut c_void, id: u16, generation: u64) -> i32;
    fn sparklink_native_transport_close(transport: *mut c_void);
    fn sparklink_native_transport_validate(
        transport: *mut c_void, opcode: u16, params: *const u8, length: usize,
    ) -> i32;
    fn sparklink_native_transport_validate_step(
        transport: *mut c_void, operation: u32, step: u32, count: u32,
        opcode: u16, params: *const u8, length: usize,
    ) -> i32;
    fn sparklink_native_transport_command(
        transport: *mut c_void, opcode: u16, params: *const u8, length: usize,
    ) -> i32;
    fn sparklink_native_transport_acb(transport: *mut c_void, ticket: *mut c_void, handle: u16,
        data: *const u8, length: usize) -> i32;
    fn sparklink_native_transport_has_acb(transport: *mut c_void) -> bool;
}

pub(crate) struct NativeController {
    transport: *mut c_void,
    identity: DeviceIdentity,
    metadata: NativeInfo,
    opened: AtomicBool,
}

// SAFETY: C retains its context and operations; lifecycle closes only after
// joining workers. The single TX worker and driver serialize transport I/O.
unsafe impl Send for NativeController {}
// SAFETY: identity/metadata are immutable after publication, opened is atomic,
// and transport I/O is serialized by the TX worker plus the driver's I/O mutex.
unsafe impl Sync for NativeController {}

impl Drop for NativeController {
    fn drop(&mut self) {
        self.close();
        // SAFETY: this Backend exclusively owns the C retained transport.
        unsafe { sparklink_native_transport_free(self.transport) };
    }
}

/// Independent retained transport for blocking open or the TX worker. Lifecycle
/// serialization joins open, and invalidation joins TX before closing Backend.
/// Neither operation retains Runtime state or can follow a reused identity.
pub(crate) struct NativeCommandTransport {
    transport: *mut c_void,
}

impl Drop for NativeCommandTransport {
    fn drop(&mut self) {
        // SAFETY: command_transport acquired exactly one retained reference.
        unsafe { sparklink_native_transport_free(self.transport) };
    }
}

impl NativeController {
    pub(crate) fn profile(&self) -> u32 { self.metadata.profile }
    pub(crate) fn data_limits(&self) -> (u16, u8) {
        // SAFETY: retained immutable copied driver operations; no I/O.
        if unsafe { sparklink_native_transport_has_acb(self.transport) } {
            (self.metadata.acb_length, self.metadata.acb_count)
        } else { (0, 0) }
    }
    pub(crate) fn command_transport(&self) -> NativeCommandTransport {
        // SAFETY: this Backend owns a live reference during acquisition.
        unsafe { sparklink_native_transport_get(self.transport) };
        NativeCommandTransport { transport: self.transport }
    }
    fn result(ret: i32) -> Result {
        if ret < 0 { Err(Error::from_errno(ret)) } else { Ok(()) }
    }

    pub(crate) fn fill_snapshot(&self, out: &mut super::sle_uapi::SleControllerSnapshot) {
        out.valid_fields = 1;
        out.version_tuple = self.metadata.version;
        out.features = self.metadata.features;
        out.address = self.metadata.address;
        out.acb_length = self.metadata.acb_length;
        out.icb_length = self.metadata.icb_length;
        out.acb_count = self.metadata.acb_count;
        out.icb_count = self.metadata.icb_count;
    }
    pub(crate) fn prepare_discovery(&self, request: &SleDiscoverySubmit) -> Result<KBox<NativeDiscoveryPlan>> {
        let mut plan = KBox::init(init!(NativeDiscoveryPlan {
            operation: 0, count: 0, power_step: 0,
            // SAFETY: repr(C) integers/bytes accept an all-zero value.
            steps <- pin_init::init_array_from_fn(|_| unsafe { core::mem::zeroed::<NativeDiscoveryStep>() }),
        }), GFP_KERNEL)?;
        let input = NativeDiscoveryRequest {
            operation: request.operation,
            advertising: if matches!(request.operation, 1 | 5) { &request.advertising } else { core::ptr::null() },
            scanning: if matches!(request.operation, 3 | 6) { &request.scanning } else { core::ptr::null() },
            handle: request.handle, duration: request.duration, max_events: request.max_events,
            data: if request.data_len > 0 { request.data.as_ptr() } else { core::ptr::null() },
            data_size: request.data_len, scan_response_present: request.flags & 1,
            scan_response: if request.flags & 1 != 0 { request.scan_response.as_ptr() } else { core::ptr::null() },
            scan_response_size: request.scan_response_len,
        };
        // SAFETY: retained driver, immutable kernel request and disjoint heap
        // output live for this call. Driver may not retain pointers or do I/O.
        Self::result(unsafe { sparklink_native_transport_prepare(self.transport, &input, &mut *plan) })?;
        if plan.operation != request.operation || !(1..=4).contains(&plan.count)
            || plan.power_step > plan.count { return Err(EINVAL); }
        for (step, part) in plan.steps[..plan.count as usize].iter().enumerate() {
            if part.opcode == 0 || part.length as usize > part.params.len() { return Err(EINVAL); }
            // Validate the whole prepared group before allocating Host state.
            Self::result(unsafe { sparklink_native_transport_validate_step(self.transport,
                plan.operation, step as u32, plan.count, part.opcode,
                part.params.as_ptr(), part.length as usize) })?;
        }
        Ok(plan)
    }

    pub(crate) fn prepare_connection(&self, request: &SleConnectionSubmit) -> Result<NativeConnectionPlan> {
        let input = NativeConnectionRequest { operation: request.operation, handle: request.handle,
            reason: request.reason, parameters: request.parameters };
        let mut plan = NativeConnectionPlan { operation: 0, opcode: 0, length: 0, params: [0; 32] };
        // SAFETY: retained transport; disjoint immutable input/output live for
        // this side-effect-free call; no pointer is retained by the driver.
        Self::result(unsafe { sparklink_native_transport_prepare_connection(self.transport, &input, &mut plan) })?;
        if plan.operation != request.operation || plan.opcode == 0 || plan.length as usize > plan.params.len() { return Err(EINVAL); }
        // SAFETY: driver owns dialect; validate the complete plan before Host admission.
        Self::result(unsafe { sparklink_native_transport_validate_connection(self.transport,
            plan.operation, plan.opcode, plan.params.as_ptr(), plan.length as usize) })?;
        Ok(plan)
    }

    pub(crate) fn validate_command(&self, opcode: u16, params: &[u8]) -> Result {
        // SAFETY: this Backend retains the driver/context. Validation neither
        // performs I/O nor changes transaction/credit state; the driver owns
        // its supported command dialect, independently of standard USB.
        Self::result(unsafe {
            sparklink_native_transport_validate(self.transport, opcode, params.as_ptr(), params.len())
        })
    }

    pub(crate) fn send_command_transport(
        &self, opcode: u16, params: &[u8], recipe: Option<RecipeTag>,
    ) -> Result {
        self.command_transport().send(opcode, params, recipe)
    }
}

impl super::ControllerRuntime {
    fn open_native(self: &kernel::sync::Arc<Self>) -> Result {
        let _lifecycle = self.native_lifecycle.lock();
        let transport = {
            let state = self.state.lock();
            if *self.schedule_gate.lock() { return Err(ENODEV); }
            let Some(super::sle_dli::ControllerBackend::Native(controller)) =
                state.as_ref().map(|state| &state.controller) else { return Err(ENODEV) };
            controller.command_transport()
        };
        // Publish ingress before open submits RX. Invalidation closes its
        // gate immediately, then joins this lifecycle before unpublishing.
        super::sle_ingress::publish_runtime(self)?;
        // SAFETY: independent reference retains the driver; lifecycle excludes
        // close. No registry, management, Runtime state or IRQ lock spans I/O.
        NativeController::result(unsafe {
            sparklink_native_transport_open(transport.transport, self.identity.id, self.identity.generation)
        })?;
        {
            let state = self.state.lock();
            let Some(super::sle_dli::ControllerBackend::Native(controller)) =
                state.as_ref().map(|state| &state.controller) else {
                drop(state);
                // SAFETY: successful open must be closed even if adoption fails.
                unsafe { sparklink_native_transport_close(transport.transport) };
                return Err(ENODEV);
            };
            // Transfer successful-open cleanup to Backend even when retirement
            // won. Teardown cannot take state until this lifecycle is released.
            controller.opened.store(true, Ordering::Release);
            let stopping = self.schedule_gate.lock();
            if *stopping { return Err(ENODEV); }
            self.transport_open.store(true, Ordering::Release);
        }
        // Ingress is already published. Do not republish a retired registration.
        self.schedule_rx(kernel::time::msecs_to_jiffies(500));
        Ok(())
    }
}

impl NativeCommandTransport {
    pub(crate) fn send(&self, opcode: u16, params: &[u8], recipe: Option<RecipeTag>) -> Result {
        self.send_typed(opcode, params, recipe, None)
    }
    pub(crate) fn send_typed(&self, opcode: u16, params: &[u8], recipe: Option<RecipeTag>, connection: Option<u32>) -> Result {
        if connection.is_some() && recipe.is_some() { return Err(EINVAL); }
        if let Some(operation) = connection {
            // SAFETY: only the typed Host creates this tag. Retained driver
            // validates its dialect; raw validate_command remains query-only.
            NativeController::result(unsafe { sparklink_native_transport_validate_connection(
                self.transport, operation, opcode, params.as_ptr(), params.len()) })?;
        } else if let Some(tag) = recipe {
            // The tag was generated by this owner's typed Host, never from
            // raw DLI input. The driver validates both sequence position and
            // its wire schema; no core vendor-opcode whitelist is introduced.
            let operation = match tag.intent {
                DiscoveryIntent::Advertising(true) => 1,
                DiscoveryIntent::Advertising(false) => 2,
                DiscoveryIntent::Scanning(true) => 3,
                DiscoveryIntent::Scanning(false) => 4,
                DiscoveryIntent::AdvertisingStandby => 5,
                DiscoveryIntent::ScanningStandby => 6,
            };
            // SAFETY: retained driver/context and borrowed parameter buffer
            // are live throughout this side-effect-free validation call.
            NativeController::result(unsafe {
                sparklink_native_transport_validate_step(self.transport,
                    operation | if tag.recreate { 0x100 } else { 0 },
                    tag.step as u32, tag.count as u32, opcode, params.as_ptr(), params.len())
            })?;
        } else {
            // SAFETY: retained operations/context and borrowed params are live.
            NativeController::result(unsafe {
                sparklink_native_transport_validate(self.transport, opcode, params.as_ptr(), params.len())
            })?;
        }
        // SAFETY: retained transport lives until this handle drops. Called only
        // by this owner's TX worker after reserving a command credit.
        NativeController::result(unsafe {
            sparklink_native_transport_command(self.transport, opcode, params.as_ptr(), params.len())
        })
    }
}

impl SleController for NativeController {
    fn info(&self) -> SleControllerInfo {
        let mut name = [0; 32];
        name[..11].copy_from_slice(b"ws73-native");
        SleControllerInfo {
            name, bus: SleBus::Usb, addr: self.metadata.address,
            // Legacy projection only; the retained tuple contains all 5 bytes.
            fw_version: u32::from_le_bytes(self.metadata.version[..4].try_into().unwrap()),
            features: u64::from_le_bytes(self.metadata.features[..8].try_into().unwrap()),
            features_ext: u16::from_le_bytes(self.metadata.features[8..].try_into().unwrap()),
            max_pdu_payload: self.metadata.acb_length,
            // These queries do not establish connection count, MTU or these
            // policy capabilities. Never borrow standard USB defaults.
            max_connections: 0, max_mtu: 0, max_mps: 0,
            transport_modes: 0, measurement_cap: 0, security_cap: 0,
        }
    }

    fn open(&self) -> Result {
        // SAFETY: registration assigned this identity before opening RX.
        Self::result(unsafe {
            sparklink_native_transport_open(self.transport, self.identity.id, self.identity.generation)
        })?;
        self.opened.store(true, Ordering::Release);
        Ok(())
    }

    fn close(&self) {
        if self.opened.swap(false, Ordering::AcqRel) {
            // SAFETY: close joins callbacks while the context is retained.
            unsafe { sparklink_native_transport_close(self.transport) };
        }
    }

    fn send_command(&self, opcode: SleOpcode, params: &[u8]) -> Result {
        if !self.opened.load(Ordering::Acquire) { return Err(EAGAIN); }
        self.validate_command(opcode as u16, params)?;
        let owner = super::sle_ingress::ingress_owner(self.identity).ok_or(ENODEV)?;
        super::sle_ingress::enqueue_command(&owner, opcode as u16, params, None)
    }

    fn send_data(&self, _handle: u16, _data: &[u8]) -> Result { Err(Error::from_errno(UNSUPPORTED)) }
    fn poll_event(&self) -> Option<SleEvent> { None }
    fn reset(&self) -> Result { Err(Error::from_errno(UNSUPPORTED)) }
}

/// C wrapper validates pointers and transfers its retained transport on every
/// return path. Register actual metadata without synthesizing capabilities.
#[no_mangle]
pub(crate) unsafe extern "C" fn sparklink_native_register_rust(
    info: *const NativeInfo, transport: *mut c_void, out: *mut NativeIdentity,
) -> i32 {
    // SAFETY: C wrapper requires live metadata/out and an owned transport.
    let metadata = unsafe { *info };
    let mut controller = NativeController {
        transport, metadata, identity: DeviceIdentity { id: u16::MAX, generation: 0 },
        opened: AtomicBool::new(false),
    };
    let result = (|| -> Result {
        if metadata.profile != 1 { return Err(Error::from_errno(UNSUPPORTED)); }
        if metadata.address == [0; 6] || metadata.address == [255; 6]
            || metadata.acb_length > 2047 || metadata.icb_length > 2047
            || (metadata.acb_length == 0) != (metadata.acb_count == 0)
            || (metadata.icb_length == 0) != (metadata.icb_count == 0)
        { return Err(Error::from_errno(PROTOCOL_ERROR)); }
        let ctrl_info = controller.info();
        let mut registry = super::SUBSYSTEM.lock();
        let ss = registry.as_mut().ok_or(ENODEV)?;
        let id = ss.dev_registry.register_pending(&ctrl_info)?;
        controller.identity = ss.dev_registry.get(id).ok_or(ENODEV)?.identity();
        let identity = controller.identity;
        // No driver callbacks or blocking I/O while holding the registry lock.
        drop(registry);
        let installed = (|| -> Result<kernel::sync::Arc<super::ControllerRuntime>> {
            let mut state = super::ControllerState::new_boxed(
                metadata.address, super::sle_dli::ControllerBackend::Native(controller),
            )?;
            state.command_credits = metadata.command_credits;
            let mut registry = super::SUBSYSTEM.lock();
            let ss = registry.as_mut().ok_or(ENODEV)?;
            if !ss.dev_registry.get(id).is_some_and(|dev| dev.identity() == identity
                && !dev.test_flag(super::sle_dev::SLE_DEV_UNREGISTERING)) { return Err(ENODEV); }
            ss.install_runtime(id, state, false)
        })();
        let owner = match installed {
            Ok(owner) => owner,
            Err(error) => {
                let mut registry = super::SUBSYSTEM.lock();
                if let Some(ss) = registry.as_mut() {
                    if ss.runtime(id).is_none() && ss.dev_registry.get(id).is_some_and(|dev| dev.identity() == identity
                        && !dev.test_flag(super::sle_dev::SLE_DEV_UNREGISTERING)) {
                        let _ = ss.dev_registry.unregister(id);
                    }
                }
                return Err(error);
            }
        };
        if let Err(error) = owner.open_native() {
            // A concurrent unregister may finish and reuse this index before
            // open returns. Cleanup must target only the original generation.
            sparklink_native_unregister_rust(id, identity.generation);
            return Err(error);
        }
        // SAFETY: output is live for this C call. Written only on success.
        unsafe { *out = NativeIdentity { id, generation: identity.generation } };
        pr_info!("sparklink: native WS73 sle{} generation={} registered SETUP, not Ready\n",
                 id, identity.generation);
        Ok(())
    })();
    NativeController::result_to_errno(result)
}

impl NativeController {
    fn result_to_errno(result: Result) -> i32 {
        match result { Ok(()) => 0, Err(error) => error.to_errno() }
    }
}

#[no_mangle]
pub(crate) extern "C" fn sparklink_native_unregister_rust(id: u16, generation: u64) {
    let identity = DeviceIdentity { id, generation };
    let owner = {
        let mut registry = super::SUBSYSTEM.lock();
        let Some(ss) = registry.as_mut() else { return };
        let Some(dev) = ss.dev_registry.get(id) else { return };
        if dev.identity() != identity { return; }
        dev.begin_unregister();
        let Some(owner) = ss.runtimes.get_mut(id as usize).and_then(Option::take) else { return };
        if ss.active_dev_id == Some(id) { ss.active_dev_id = None; }
        owner
    };
    // Index remains reserved while work and transport callbacks are joined.
    owner.invalidate();
    let mut registry = super::SUBSYSTEM.lock();
    if let Some(ss) = registry.as_mut() {
        if ss.dev_registry.get(id).is_some_and(|dev| dev.identity() == identity) {
            let _ = ss.dev_registry.unregister(id);
        }
    }
}

/// Observational driver watchdog. The exact owner remains pinned while the
/// Host is sampled; no Runtime/Host state or readiness is changed here.
#[no_mangle]
pub(crate) extern "C" fn sparklink_native_health_rust(id: u16, generation: u64) -> i32 {
    let Some(owner) = super::sle_ingress::ingress_owner(DeviceIdentity { id, generation }) else {
        return ENODEV.to_errno();
    };
    // Observers follow the same Host -> gate order as RX/data admission.
    let host = owner.host.lock();
    let gate = owner.schedule_gate.lock();
    if *gate {
        return ENODEV.to_errno();
    }
    let (_, ready, fault) = host.controller_status();
    if let Some(error) = fault {
        return error.to_errno();
    }
    let (advertising, scanning, _) = host.discovery_radio();
    if ready && matches!(advertising, 1 | 2) && matches!(scanning, 1 | 2) {
        2
    } else {
        1
    }
}

/// Callback receives a validated HCC slot, not a complete USB aggregate.
#[no_mangle]
pub(crate) unsafe extern "C" fn sparklink_native_snoop_rx_rust(id:u16, generation:u64, data:*const u8, length:usize) {
    if data.is_null() || length==0 || length>20*1024 { return; }
    let Some(owner)=super::sle_ingress::ingress_owner(DeviceIdentity {id,generation}) else { return; };
    if owner.protocol_profile!=1 { return; }
    // SAFETY: driver retains its validated HCC slot until the callback returns.
    let data=unsafe {core::slice::from_raw_parts(data,length)};
    let gate=owner.schedule_gate.lock();
    if *gate {return;}
    owner.snoop.lock().rx(owner.identity,owner.protocol_profile,data);
    drop(gate); owner.snoop_poll.notify_all();
}

#[no_mangle]
pub(crate) unsafe extern "C" fn sparklink_native_snoop_tx_rust(id:u16, generation:u64, opcode:u16, params:*const u8, length:usize, status:i32) {
    if params.is_null() || length>u16::MAX as usize {return;}
    let Some(owner)=super::sle_ingress::ingress_owner(DeviceIdentity {id,generation}) else {return;};
    if owner.protocol_profile!=1 {return;}
    // SAFETY: driver retains the command parameter buffer for this callback.
    let params=unsafe {core::slice::from_raw_parts(params,length)};
    let gate=owner.schedule_gate.lock();
    if *gate {return;}
    owner.snoop.lock().tx(owner.identity,owner.protocol_profile,opcode,params,status);
    drop(gate); owner.snoop_poll.notify_all();
}

/// Callback receives a validated HCC slot, not a complete USB aggregate.
#[no_mangle]
pub(crate) unsafe extern "C" fn sparklink_native_event_rust(
    id: u16, generation: u64, profile: u32, event_code: u16, params: *const u8, length: usize,
) -> i32 {
    // SAFETY: preserves the driver's original live buffer contract.
    unsafe { publish_native_event(id, generation, profile, event_code, params, length, None) }
}

#[no_mangle]
pub(crate) unsafe extern "C" fn sparklink_native_link_event_rust(
    id: u16, generation: u64, profile: u32, event_code: u16,
    params: *const u8, length: usize,
    evidence: *const super::sle_link_observation::LinkEvidence,
) -> i32 {
    if evidence.is_null() { return EINVAL.to_errno(); }
    // SAFETY: the driver retains an aligned initialized evidence value and
    // immutable original parameter bytes throughout this callback. Copy now.
    let evidence = unsafe { *evidence };
    unsafe { publish_native_event(id, generation, profile, event_code, params, length, Some(evidence)) }
}

unsafe fn publish_native_event(
    id: u16, generation: u64, profile: u32, event_code: u16,
    params: *const u8, length: usize,
    evidence: Option<super::sle_link_observation::LinkEvidence>,
) -> i32 {
    if params.is_null() { return EINVAL.to_errno(); }
    if length > super::sle_uapi::CONTROLLER_EVENT_PAYLOAD_MAX { return -(kernel::bindings::EMSGSIZE as i32); }
    let Some(owner) = super::sle_ingress::ingress_owner(DeviceIdentity { id, generation }) else {
        return ENODEV.to_errno();
    };
    if profile == 0 || profile != owner.protocol_profile { return PROTOCOL_ERROR; }
    // Management replies cannot bypass the Host's reserved matching slot.
    if event_code <= 2 { return PROTOCOL_ERROR; }
    // SAFETY: driver retains a validated live parameter buffer for this call.
    let bytes = unsafe { core::slice::from_raw_parts(params, length) };
    // Host -> scheduling gate is the admission lock order. Never hold the
    // scheduling gate while waiting for Host: management/TX may hold Host.
    let mut host = owner.host.lock();
    let mut data = if evidence.is_some() { Some(owner.data.lock()) } else { None };
    let gate = owner.schedule_gate.lock();
    if *gate { return ENODEV.to_errno(); }
    if let Some(evidence) = evidence { host.observe_link(&evidence); }
    let retired = data.as_mut().and_then(|data| {
        let (_, known, links) = host.link_snapshot();
        known.then(|| data.reconcile(&links))
    });
    // A log overflow/error must not undo a real physical cleanup obligation.
    let result = owner.controller_events.lock().publish(owner.identity, profile, event_code, bytes);
    drop(gate);
    drop(data);
    drop(host);
    drop(retired);
    // Physical outcomes must progress teardown even when event-log publication
    // failed. Queue work only after releasing both IRQ-safe guards.
    if evidence.is_some() { owner.schedule_rx(0); owner.data_poll.notify_all(); }
    if result.is_ok() { owner.controller_event_poll.notify_all(); }
    NativeController::result_to_errno(result)
}

/// Callback receives a validated HCC slot, not a complete USB aggregate.
#[no_mangle]
pub(crate) unsafe extern "C" fn sparklink_native_receive_rust(
    id: u16, generation: u64, data: *const u8, length: usize,
) -> i32 {
    if data.is_null() || !(5..=super::sle_native_data::MAXIMUM + 5).contains(&length) { return PROTOCOL_ERROR; }
    let Some(owner) = super::sle_ingress::ingress_owner(DeviceIdentity { id, generation }) else {
        return ENODEV.to_errno();
    };
    // SAFETY: transport retains a live buffer throughout this callback.
    let packet = unsafe { core::slice::from_raw_parts(data, length) };
    let event = u16::from_le_bytes([packet[1], packet[2]]);
    let count = u16::from_le_bytes([packet[3], packet[4]]) as usize;
    if packet[0] == 0xa3 {
        if count == 0 || count != length - 5 { return PROTOCOL_ERROR; }
        if event & 0x4000 != 0 { return UNSUPPORTED; }
        let boundary = ((event >> 12) & 3) as u8;
        let handle = event & 0x0fff;
        // SAFETY: monotonic read-only kernel clock; deadline never refreshed by continuations.
        let now = unsafe { kernel::bindings::ktime_get_boottime() } as u64;
        // Copy before acquiring IRQ-safe Host/data/gate locks.
        let mut bytes = KVec::new();
        if boundary == 1 && bytes.reserve(super::sle_native_data::MAXIMUM, GFP_ATOMIC).is_err() { return ENOMEM.to_errno(); }
        if bytes.extend_from_slice(&packet[5..], GFP_ATOMIC).is_err() { return ENOMEM.to_errno(); }
        let host = owner.host.lock();
        let (_, known, links) = host.link_snapshot();
        let mut data = owner.data.lock();
        let gate = owner.schedule_gate.lock();
        if *gate { return ENODEV.to_errno(); }
        let retired = if known { Some(data.reconcile(&links)) } else { None };
        let link = if known { links.iter().flatten().find(|link| link.handle == handle) } else { None };
        if let Some(link) = link {
            let _ = data.receive(super::sle_native_data::Packet { lifetime: link.lifetime, handle, bytes }, boundary, now);
        } else {
            data.dropped = data.dropped.saturating_add(1);
        }
        drop(gate); drop(data); drop(host);
        drop(retired);
        owner.data_poll.notify_all();
        owner.schedule_rx(0);
        return 0; // bounded ingress drop is not a USB/device recovery request
    }
    if length > 260 { return PROTOCOL_ERROR; }
    if packet[0] != 0xa2 || count != length - 5 { return PROTOCOL_ERROR; }
    let params = &packet[5..];
    if event == 9 {
        if params.len() != 3 { return PROTOCOL_ERROR; }
        let handle = u16::from_le_bytes([params[0], params[1]]);
        let mut data = owner.data.lock();
        let gate = owner.schedule_gate.lock();
        if *gate { return ENODEV.to_errno(); }
        data.completed(handle, params[2]);
        drop(gate); drop(data);
        owner.data_poll.notify_all();
        return 0; // data accounting never changes command credit
    }
    let event = match event {
        1 | 2 => {
            if params.len() < 3 { return PROTOCOL_ERROR; }
            let opcode = u16::from_le_bytes([params[0], params[1]]);
            if opcode == 0 {
                if params.len() != 3 { return PROTOCOL_ERROR; }
                SleEvent::CommandCredits { credits: params[2] }
            } else {
                if params.len() < 4 || (event == 1 && params.len() != 4) {
                    return PROTOCOL_ERROR;
                }
                // The native driver validates its successful return schema
                // before ingress. Keep its opcode dialect out of the core.
                if params.len() - 4 > 240 { return EOVERFLOW.to_errno(); }
                let mut bytes = KVec::new();
                if bytes.extend_from_slice(&params[4..], GFP_ATOMIC).is_err() { return ENOMEM.to_errno(); }
                SleEvent::NativeCommandReply {
                    opcode, command_credits: params[2], status: params[3], complete: event == 2, data: bytes,
                }
            }
        }
        0xa => {
            if params.len() != 1 { return PROTOCOL_ERROR; }
            SleEvent::HardwareError { code: params[0] }
        }
        _ => return UNSUPPORTED,
    };
    super::sle_ingress::enqueue_rx(&owner, event);
    0
}

/// Internal channel entry point. The old handle-only trait stays unsupported.
#[no_mangle]
pub(crate) unsafe extern "C" fn sparklink_native_acb_limits_rust(
    id: u16, generation: u64, lifetime: u64, handle: u16, maximum: *mut u16,
) -> i32 {
    if maximum.is_null() { return EINVAL.to_errno(); }
    let Some(owner) = super::sle_ingress::ingress_owner(DeviceIdentity { id, generation }) else { return ENODEV.to_errno(); };
    let host = owner.host.lock();
    let (_, known, links) = host.link_snapshot();
    let data = owner.data.lock();
    let gate = owner.schedule_gate.lock();
    if *gate { return ENODEV.to_errno(); }
    if !known { return EAGAIN.to_errno(); }
    if !links.iter().flatten().any(|link| link.handle == handle && link.lifetime == lifetime) {
        return -(kernel::bindings::ESTALE as i32);
    }
    match data.credits.maximum() {
        Ok(value) => {
            // SAFETY: internal caller provides a writable kernel u16 for this call.
            unsafe { *maximum = value }; 0
        }
        Err(error) => super::sle_native_data::error(error).to_errno(),
    }
}

/// One process-context operation retains Runtime and Backend through the
/// driver's preparation, atomic commit and joined completion. The opaque C
/// pointer must not escape the blocking send callback. Not a public ABI.
struct NativeTxTicket {
    owner: Arc<super::ControllerRuntime>,
    lifetime: u64,
    handle: u16,
    length: usize,
    epoch: Option<u64>,
    consent: Option<unsafe extern "C" fn(*mut c_void, unsafe extern "C" fn(*mut c_void) -> i32, *mut c_void) -> i32>,
    scope: *mut c_void,
    attempted: Cell<bool>,
    submitted: Cell<bool>,
}

/// Driver has prepared an immutable transfer. Exactly one callback may attempt
/// commit. Host -> data -> scheduling locks serialize actual USB queueing with
/// physical link publication, fault/revoke and registration withdrawal. The
/// callback MUST be a non-sleeping atomic submission, with no Host reentry.
/// Completion/wait/kill happen after these guards have all been released.
#[no_mangle]
pub(crate) unsafe extern "C" fn sparklink_native_tx_commit_rust(
    opaque: *mut c_void, submit: Option<unsafe extern "C" fn(*mut c_void) -> i32>, context: *mut c_void,
) -> i32 {
    if opaque.is_null() || submit.is_none() { return EINVAL.to_errno(); }
    // SAFETY: only the retained driver callback receives this live ticket;
    // it invokes commit synchronously on the same process-context thread.
    let ticket = unsafe { &*opaque.cast::<NativeTxTicket>() };
    if ticket.attempted.replace(true) { return -(kernel::bindings::EALREADY as i32); }
    let owner = &ticket.owner;
    let host = owner.host.lock();
    let (_, known, links) = host.link_snapshot();
    let mut data = owner.data.lock();
    let gate = owner.schedule_gate.lock();
    if *gate { return ENODEV.to_errno(); }
    if !owner.transport_open.load(Ordering::Acquire) || !known { return EAGAIN.to_errno(); }
    if !host.admits_data() { return -(kernel::bindings::EACCES as i32); }
    if ticket.epoch.is_some_and(|epoch| !host.grants.permits(epoch)) { return -(kernel::bindings::EACCES as i32); }
    if !links.iter().flatten().any(|link| link.handle == ticket.handle && link.lifetime == ticket.lifetime) {
        return -(kernel::bindings::ESTALE as i32);
    }
    if let Err(error) = data.credits.reserve(ticket.lifetime, ticket.handle, ticket.length) {
        return super::sle_native_data::error(error).to_errno();
    }
    // SAFETY: registered Backend contract permits only an already prepared
    // atomic queue operation (WS73: usb_submit_urb(..., GFP_ATOMIC)). No wait,
    // kernel allocation with sleeping flags, protocol callback or decode here.
    let result = if let Some(consent) = ticket.consent {
        // SAFETY: scope belongs to the live session worker; consent holds its
        // state lock through the same prepared atomic queue operation.
        unsafe { consent(ticket.scope, submit.unwrap(), context) }
    } else { unsafe { submit.unwrap()(context) } };
    if result == 0 {
        ticket.submitted.set(true); // USB queued; only genuine NOCP pays debt.
    } else if data.credits.unsubmitted(ticket.lifetime, ticket.handle).is_err() {
        data.credits.transport_failed();
        return EIO.to_errno();
    }
    result
}

/// Internal channel entry point. The old handle-only trait stays unsupported.
#[no_mangle]
pub(crate) unsafe extern "C" fn sparklink_native_acb_send_rust(
    id: u16, generation: u64, lifetime: u64, handle: u16, data: *const u8, length: usize,
) -> i32 {
    // SAFETY: preserves internal caller buffer lifetime until driver joins.
    unsafe { native_acb_send(id, generation, lifetime, handle, data, length, None, None, core::ptr::null_mut()) }
}
#[no_mangle]
pub(crate) unsafe extern "C" fn sparklink_native_acb_send_guarded_rust(
    id: u16, generation: u64, lifetime: u64, handle: u16, data: *const u8, length: usize, epoch: u64,
    consent: Option<unsafe extern "C" fn(*mut c_void, unsafe extern "C" fn(*mut c_void) -> i32, *mut c_void) -> i32>, scope: *mut c_void,
) -> i32 {
    if consent.is_none() || scope.is_null() { return EINVAL.to_errno(); }
    // SAFETY: session worker holds its reference and scope until this returns.
    unsafe { native_acb_send(id, generation, lifetime, handle, data, length, Some(epoch), consent, scope) }
}
unsafe fn native_acb_send(
    id: u16, generation: u64, lifetime: u64, handle: u16, data: *const u8, length: usize,
    epoch: Option<u64>, consent: Option<unsafe extern "C" fn(*mut c_void, unsafe extern "C" fn(*mut c_void) -> i32, *mut c_void) -> i32>, scope: *mut c_void,
) -> i32 {
    if data.is_null() || length == 0 || length > super::sle_native_data::MAXIMUM { return EINVAL.to_errno(); }
    let Some(owner) = super::sle_ingress::ingress_owner(DeviceIdentity { id, generation }) else { return ENODEV.to_errno(); };
    let _lifecycle = owner.native_lifecycle.lock();
    let transport = {
        let state = owner.state.lock();
        let Some(super::sle_dli::ControllerBackend::Native(controller)) = state.as_ref().map(|s| &s.controller) else {
            return UNSUPPORTED;
        };
        controller.command_transport()
    };
    {
        let host = owner.host.lock();
        let (_, known, links) = host.link_snapshot();
        let data = owner.data.lock();
        let gate = owner.schedule_gate.lock();
        if *gate { return ENODEV.to_errno(); }
        if !owner.transport_open.load(Ordering::Acquire) || !known { return EAGAIN.to_errno(); }
        if !host.admits_data() { return -(kernel::bindings::EACCES as i32); }
        if epoch.is_some_and(|epoch| !host.grants.permits(epoch)) { return -(kernel::bindings::EACCES as i32); }
        if !links.iter().flatten().any(|link| link.handle == handle && link.lifetime == lifetime) {
            return -(kernel::bindings::ESTALE as i32);
        }
        match data.credits.maximum() {
            Ok(maximum) if length <= maximum as usize => (),
            Ok(_) => return -(kernel::bindings::EMSGSIZE as i32),
            Err(error) => return super::sle_native_data::error(error).to_errno(),
        }
    }
    let mut ticket = NativeTxTicket { owner: owner.clone(), lifetime, handle, length, epoch,
        consent, scope, attempted: Cell::new(false), submitted: Cell::new(false) };
    // SAFETY: caller owns immutable bytes, the ticket and retained Backend
    // remain live until the blocking driver callback joins its completion.
    let result = unsafe { sparklink_native_transport_acb(transport.transport,
        (&mut ticket as *mut NativeTxTicket).cast(), handle, data, length) };
    let result = if result == 0 && !ticket.submitted.get() { PROTOCOL_ERROR } else { result };
    if result != 0 && ticket.submitted.get() { owner.data.lock().credits.transport_failed(); }
    owner.data_poll.notify_all();
    result
}

/// Internal DTAP consumer; a stale lifetime cannot consume another link's RX.
#[no_mangle]
pub(crate) unsafe extern "C" fn sparklink_native_acb_take_rust(
    id: u16, generation: u64, lifetime: u64, handle: u16,
    data: *mut u8, capacity: usize, length: *mut usize,
) -> i32 {
    if data.is_null() || length.is_null() { return EINVAL.to_errno(); }
    let Some(owner) = super::sle_ingress::ingress_owner(DeviceIdentity { id, generation }) else { return ENODEV.to_errno(); };
    let host = owner.host.lock();
    let (_, known, links) = host.link_snapshot();
    let mut queue = owner.data.lock();
    let gate = owner.schedule_gate.lock();
    if *gate { return ENODEV.to_errno(); }
    if !known { return EAGAIN.to_errno(); }
    if !links.iter().flatten().any(|link| link.handle == handle && link.lifetime == lifetime) {
        return -(kernel::bindings::ESTALE as i32);
    }
    let packet = match queue.take(lifetime, handle, capacity) {
        Ok(Some(packet)) => packet,
        Ok(None) => return EAGAIN.to_errno(),
        Err(error) => return error.to_errno(),
    };
    drop(gate); drop(queue); drop(host);
    // SAFETY: caller provides writable, disjoint kernel data/length buffers.
    // Capacity was checked without consuming on EMSGSIZE; packet owns bytes.
    unsafe { core::ptr::copy_nonoverlapping(packet.bytes.as_ptr(), data, packet.bytes.len());
        *length = packet.bytes.len(); }
    0
}
