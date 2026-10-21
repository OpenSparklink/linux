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
use super::sle_dli::{SleBus, SleController, SleControllerInfo, SleEvent};

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
pub(crate) struct BackendPending { bus: u32, profile: u32, phase: u32, error: i32 }
const _: () = assert!(core::mem::size_of::<BackendPending>() == 16);

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
    fn sparklink_native_transport_prepare_runtime_address(transport:*mut c_void,address:*const u8,
        opcode:*mut u16,params:*mut u8,capacity:usize)->i32;
    fn sparklink_native_transport_validate_runtime_address(transport:*mut c_void,opcode:u16,
        params:*const u8,size:usize)->i32;
    fn sparklink_native_transport_prepare_relay(transport:*mut c_void, handle:u16, index:u16,
        payload:*const u8, size:usize, opcode:*mut u16, params:*mut u8, capacity:usize, echo_index:*mut u16)->i32;
    fn sparklink_native_transport_validate_relay(transport:*mut c_void, opcode:u16, params:*const u8, size:usize)->i32;
    fn sparklink_native_transport_prepare_connection(transport: *mut c_void,
        request: *const NativeConnectionRequest, plan: *mut NativeConnectionPlan) -> i32;
    fn sparklink_native_transport_validate_connection(transport: *mut c_void,
        operation: u32, opcode: u16, params: *const u8, length: usize) -> i32;
    fn sparklink_native_transport_prepare(
        transport: *mut c_void, request: *const NativeDiscoveryRequest,
        plan: *mut NativeDiscoveryPlan,
    ) -> i32;
    fn sparklink_native_transport_bus(transport: *const c_void) -> u32;
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
    fn sparklink_native_transport_has_command_ticket(transport: *mut c_void) -> bool;
    fn sparklink_native_transport_command_ticketed(transport: *mut c_void, ticket: *mut c_void,
        opcode: u16, params: *const u8, length: usize) -> i32;
    fn sparklink_native_transport_acb(transport: *mut c_void, ticket: *mut c_void, handle: u16, boundary: u8,
        data: *const u8, length: usize) -> i32;
    fn sparklink_native_transport_has_acb(transport: *mut c_void) -> bool;
}

pub(crate) struct NativeController {
    transport: *mut c_void,
    identity: DeviceIdentity,
    metadata: NativeInfo,
    bus: SleBus,
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
    never_submitted: Cell<bool>,
}

impl Drop for NativeCommandTransport {
    fn drop(&mut self) {
        // SAFETY: command_transport acquired exactly one retained reference.
        unsafe { sparklink_native_transport_free(self.transport) };
    }
}

impl NativeController {
    pub(crate) fn profile(&self) -> u32 { self.metadata.profile }
    pub(crate) fn prepare_runtime_address(&self,address:&[u8;6])->Result<(u16,[u8;6])> {
        if !unsafe {sparklink_native_transport_has_command_ticket(self.transport)} {
            return Err(Error::from_errno(UNSUPPORTED));
        }
        let mut opcode=0;let mut params=[0;6];
        // SAFETY: retained driver,live borrowed input and exact initialized outputs;
        // preparation is side-effect free. Only the driver's dialect builds bytes.
        let length=unsafe {sparklink_native_transport_prepare_runtime_address(self.transport,
            address.as_ptr(),&mut opcode,params.as_mut_ptr(),params.len())};
        if length<0 {return Err(Error::from_errno(length));}
        if length!=6 || opcode==0 {return Err(Error::from_errno(PROTOCOL_ERROR));}
        Self::result(unsafe {sparklink_native_transport_validate_runtime_address(self.transport,
            opcode,params.as_ptr(),params.len())})?;
        Ok((opcode,params))
    }
    /// Caller holds Runtime state and Host;source is the reserved real readback.
    /// This copies an observation,not a software-only setter or storage write.
    pub(crate) fn observe_runtime_address(&mut self,address:[u8;6]) {self.metadata.address=address;}
    pub(crate) fn data_limits(&self) -> (u16, u8) {
        // SAFETY: retained immutable copied driver operations; no I/O.
        if unsafe { sparklink_native_transport_has_acb(self.transport) } {
            (self.metadata.acb_length, self.metadata.acb_count)
        } else { (0, 0) }
    }
    pub(crate) fn command_transport(&self) -> NativeCommandTransport {
        // SAFETY: this Backend owns a live reference during acquisition.
        unsafe { sparklink_native_transport_get(self.transport) };
        NativeCommandTransport { transport: self.transport, never_submitted: Cell::new(false) }
    }
    fn result(ret: i32) -> Result {
        if ret == 0 { Ok(()) } else if ret < 0 { Err(Error::from_errno(ret)) } else { Err(EIO) }
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
        // A manager may have observed Setup before a separate exclusive
        // volatile-address lease. Never configure an old public own address
        // from that cached snapshot after management is acquired again.
        if self.metadata.profile==1 && matches!(request.operation,1|5)
            && request.advertising.own_address_type==0
            && request.advertising.own_address!=self.metadata.address {
            return Err(Error::from_errno(-(kernel::bindings::ESTALE as i32)));
        }
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

    pub(crate) fn prepare_relay(&self, packet:&super::sle_security_relay_state::Packet)->Result<(u16,[u8;255],usize,u16)> {
        let mut opcode=0;let mut params=[0;255];let mut echo_index=0;let bytes=packet.payload();
        // SAFETY: retained provider; synchronous side-effect-free dialect codec.
        let size=unsafe {sparklink_native_transport_prepare_relay(self.transport,packet.ticket.identity.handle,
            packet.index,bytes.as_ptr(),bytes.len(),&mut opcode,params.as_mut_ptr(),params.len(),&mut echo_index)};
        if size<0 {return Err(Error::from_errno(size));}
        if size as usize>params.len() || opcode==0 {return Err(EINVAL);}
        Self::result(unsafe {sparklink_native_transport_validate_relay(self.transport,opcode,params.as_ptr(),size as usize)})?;
        Ok((opcode,params,size as usize,echo_index))
    }

    pub(crate) fn validate_command(&self, opcode: u16, params: &[u8]) -> Result {
        // SAFETY: this Backend retains the driver/context. Validation neither
        // performs I/O nor changes transaction/credit state; the driver owns
        // its supported command dialect, independently of standard USB.
        Self::result(unsafe {
            sparklink_native_transport_validate(self.transport, opcode, params.as_ptr(), params.len())
        })
    }

}

impl super::ControllerRuntime {
    fn open_native(self: &kernel::sync::Arc<Self>) -> Result {
        let _lifecycle = self.native_lifecycle.lock();
        let transport = {
            let state = self.state.lock();
            if *self.schedule_gate.lock() { return Err(ENODEV); }
            let Some(backend) =
                state.as_ref().map(|state| &state.controller) else { return Err(ENODEV) };
            backend.provider().command_transport()
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
            let Some(backend) =
                state.as_ref().map(|state| &state.controller) else {
                drop(state);
                // SAFETY: successful open must be closed even if adoption fails.
                unsafe { sparklink_native_transport_close(transport.transport) };
                return Err(ENODEV);
            };
            let controller = backend.provider();
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

    pub(crate) fn send_typed(&self, owner: &super::ControllerRuntime, cookie: u64,
        opcode: u16, params: &[u8], recipe: Option<RecipeTag>, connection: Option<u32>, relay:bool) -> Result {
        self.never_submitted.set(true); // validation performs no I/O
        if connection.is_some() && recipe.is_some() || relay && (connection.is_some() || recipe.is_some()) { return Err(EINVAL); }
        let runtime_address = { owner.host.lock().runtime_address_command(owner.identity.generation,cookie) };
        if runtime_address {
            if relay || connection.is_some() || recipe.is_some()
                || !unsafe {sparklink_native_transport_has_command_ticket(self.transport)} {return Err(EINVAL);}
            NativeController::result(unsafe {sparklink_native_transport_validate_runtime_address(
                self.transport,opcode,params.as_ptr(),params.len())})?;
        } else if relay {
            // Relay ledger/debt requires the final atomic ticket, never legacy
            // unguarded send even if a provider implements dialect callbacks.
            if !unsafe {sparklink_native_transport_has_command_ticket(self.transport)} {return Err(Error::from_errno(-(kernel::bindings::EOPNOTSUPP as i32)));}
            NativeController::result(unsafe {sparklink_native_transport_validate_relay(self.transport,opcode,params.as_ptr(),params.len())})?;
        } else if let Some(operation) = connection {
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
        // SAFETY: retained immutable provider; callback availability is stable.
        if unsafe { sparklink_native_transport_has_command_ticket(self.transport) } {
            self.never_submitted.set(false);
            let mut ticket = NativeCommandTicket { owner, cookie, opcode,
                attempted: Cell::new(false), submitted: Cell::new(false), materialized:Cell::new(false) };
            // SAFETY: driver may use the borrowed ticket only synchronously,
            // and must join transfer callbacks before this stack object retires.
            let result = unsafe { sparklink_native_transport_command_ticketed(self.transport,
                (&mut ticket as *mut NativeCommandTicket<'_>).cast(), opcode, params.as_ptr(), params.len()) };
            if result > 0 || (result == 0 && !ticket.submitted.get()) { return Err(Error::from_errno(PROTOCOL_ERROR)); }
            if result < 0 && !ticket.submitted.get() { self.never_submitted.set(true); }
            NativeController::result(result)
        } else {
            self.never_submitted.set(false); // legacy failure has no queue evidence
            // Explicit legacy path for other providers pending migration;
            // this is not a ticketed transport or Native security capability.
            NativeController::result(unsafe {
                sparklink_native_transport_command(self.transport, opcode, params.as_ptr(), params.len())
            })
        }
    }
}

impl super::sle_backend::CommandPort for NativeCommandTransport {
    fn never_submitted(&self) -> bool { self.never_submitted.get() }
    fn submit(&self, owner: &super::ControllerRuntime, cookie: u64, opcode: u16,
        params: &[u8], recipe: Option<RecipeTag>, connection: Option<u32>, relay:bool) -> Result {
        self.send_typed(owner, cookie, opcode, params, recipe, connection, relay)
    }
}

struct NativeCommandTicket<'a> {
    owner: &'a super::ControllerRuntime,
    cookie: u64,
    opcode: u16,
    attempted: Cell<bool>,
    submitted: Cell<bool>,
    materialized: Cell<bool>,
}

/// Driver preparation, not a submission. No material can leave through UAPI;
/// final commit revalidates the same Host/gate after this copy.
#[no_mangle]
pub(crate) unsafe extern "C" fn sparklink_native_command_materialize_rust(
    opaque:*mut c_void, id:u16, generation:u64, params:*mut u8, length:usize,
)->i32 {
    if opaque.is_null() || params.is_null() || !(20..=21).contains(&length) {return EINVAL.to_errno();}
    let ticket=unsafe {&*opaque.cast::<NativeCommandTicket<'_>>()};
    if ticket.attempted.get() {return -(kernel::bindings::EALREADY as i32);}
    let owner=ticket.owner;
    if owner.identity!=(DeviceIdentity{id,generation}) {return -(kernel::bindings::ESTALE as i32);}
    let host=owner.host.lock();let gate=owner.schedule_gate.lock();
    if *gate || !owner.transport_open.load(Ordering::Acquire) {return ENODEV.to_errno();}
    let output=unsafe {core::slice::from_raw_parts_mut(params,length)};
    if ticket.materialized.get() {return -(kernel::bindings::EALREADY as i32);}
    match host.materialize_relay(ticket.cookie,ticket.opcode,output) {
        Ok(())=>{ticket.materialized.set(true);0}, Err(e)=>e.to_errno(),
    }
}

#[no_mangle]
pub(crate) unsafe extern "C" fn sparklink_native_command_commit_rust(
    opaque: *mut c_void, id: u16, generation: u64,
    submit: Option<unsafe extern "C" fn(*mut c_void) -> i32>, context: *mut c_void,
) -> i32 {
    if opaque.is_null() || submit.is_none() { return EINVAL.to_errno(); }
    // SAFETY: opaque belongs to this synchronous retained driver's call.
    let ticket = unsafe { &*opaque.cast::<NativeCommandTicket<'_>>() };
    if ticket.attempted.replace(true) { return -(kernel::bindings::EALREADY as i32); }
    let owner = ticket.owner;
    if owner.identity != (DeviceIdentity { id, generation }) { return -(kernel::bindings::ESTALE as i32); }
    let mut host = owner.host.lock();
    let gate = owner.schedule_gate.lock();
    if *gate { return ENODEV.to_errno(); }
    if !owner.transport_open.load(Ordering::Acquire) { return EAGAIN.to_errno(); }
    if let Err(error) = host.validate_command_commit(ticket.cookie, ticket.opcode) { return error.to_errno(); }
    if host.needs_materialization(ticket.cookie) && !ticket.materialized.get() {return -(kernel::bindings::EACCES as i32);}
    // SAFETY: prepared non-sleeping queue operation; guards serialize queueing
    // with Host withdrawal/link publication. No decode, wait or Host reentry.
    let result = host.commit_relay(ticket.cookie, || unsafe { submit.unwrap()(context) });
    if result == 0 {
        host.command_committed(ticket.cookie);
        ticket.submitted.set(true);
    }
    result // Neither USB admission nor failure fabricates command credit.
}

/// Backend descriptor IDs are internal and differ from public bus values.
/// Reject unknown provenance instead of projecting it onto a physical bus.
fn backend_bus(bus: u32) -> Result<SleBus> {
    match bus {
        1 => Ok(SleBus::Usb),
        2 => Ok(SleBus::Test),
        _ => Err(Error::from_errno(UNSUPPORTED)),
    }
}

impl SleController for NativeController {
    fn info(&self) -> SleControllerInfo {
        SleControllerInfo {
            bus: self.bus, addr: self.metadata.address,
        }
    }

    fn close(&self) {
        if self.opened.swap(false, Ordering::AcqRel) {
            // SAFETY: close joins callbacks while the context is retained.
            unsafe { sparklink_native_transport_close(self.transport) };
        }
    }

}

/// Caller owns the reservation until successful install, cancellation or removal.
#[no_mangle]
pub(crate) unsafe extern "C" fn sparklink_backend_reserve_rust(bus: u32, profile: u32, out: *mut NativeIdentity) -> i32 {
    let result = (|| -> Result {
        if out.is_null() { return Err(EINVAL); }
        if profile > 1 { return Err(Error::from_errno(UNSUPPORTED)); }
        let mut info = SleControllerInfo::default();
        info.bus = backend_bus(bus)?;
        let identity = super::reserve_backend_identity_profile(&info, profile)?;
        // SAFETY: checked live C output, written only on success.
        unsafe { *out = NativeIdentity { id: identity.id, generation: identity.generation } };
        Ok(())
    })();
    NativeController::result_to_errno(result)
}

#[no_mangle]
pub(crate) extern "C" fn sparklink_backend_cancel_rust(id: u16, generation: u64) {
    super::cancel_backend_reservation(DeviceIdentity { id, generation });
}

#[no_mangle]
pub(crate) extern "C" fn sparklink_backend_pending_update_rust(id: u16, generation: u64, phase: u32, error: i32) -> i32 {
    NativeController::result_to_errno(super::update_backend_pending(DeviceIdentity { id, generation }, phase, error))
}

#[no_mangle]
pub(crate) unsafe extern "C" fn sparklink_backend_pending_query_rust(id: u16, generation: u64, out: *mut BackendPending) -> i32 {
    if out.is_null() { return EINVAL.to_errno(); }
    match super::query_backend_pending(DeviceIdentity { id, generation }) {
        Ok((bus, profile, phase, error)) => {
            // SAFETY: C requires a live output. Returned bus is the public value.
            unsafe { *out = BackendPending { bus: bus as u32, profile, phase, error } };
            0
        }
        Err(error) => error.to_errno(),
    }
}

/// C wrapper validates pointers and transfers its retained transport on every
/// return path. Register actual metadata without synthesizing capabilities.
#[no_mangle]
pub(crate) unsafe extern "C" fn sparklink_native_register_rust(
    info: *const NativeInfo, transport: *mut c_void, reserved: *const NativeIdentity, out: *mut NativeIdentity,
) -> i32 {
    // SAFETY: C wrapper requires live metadata/out and an owned transport.
    let metadata = unsafe { *info };
    let mut controller = NativeController {
        transport, metadata, identity: DeviceIdentity { id: u16::MAX, generation: 0 },
        bus: SleBus::None, opened: AtomicBool::new(false),
    };
    let result = (|| -> Result {
        // SAFETY: this controller owns the retained transport; provenance is
        // copied before get/register callbacks and immutable for its lifetime.
        controller.bus = backend_bus(unsafe { sparklink_native_transport_bus(transport) })?;
        if metadata.profile > 1 { return Err(Error::from_errno(UNSUPPORTED)); }
        if metadata.address == [0; 6] || metadata.address == [255; 6]
            || metadata.acb_length > 2047 || metadata.icb_length > 2047
            || (metadata.acb_length == 0) != (metadata.acb_count == 0)
            || (metadata.icb_length == 0) != (metadata.icb_count == 0)
        { return Err(Error::from_errno(PROTOCOL_ERROR)); }
        let ctrl_info = controller.info();
        let borrowed = !reserved.is_null();
        let identity = if borrowed {
            // SAFETY: C copied the live caller reservation for this call.
            let input = unsafe { &*reserved };
            let identity = DeviceIdentity { id: input.id, generation: input.generation };
            super::validate_backend_reservation(identity, controller.bus, metadata.profile)?;
            identity
        } else { super::reserve_backend_identity_profile(&ctrl_info, metadata.profile)? };
        let id = identity.id;
        controller.identity = identity;
        // Candidate construction and driver put/drop are outside the registry.
        let installed = (|| -> Result<kernel::sync::Arc<super::ControllerRuntime>> {
            let state = super::ControllerState::new_boxed(
                metadata.address, super::sle_dli::ControllerBackend::Native(controller),
            )?;
            super::install_backend_runtime(identity, state, metadata.command_credits, Some(metadata.address))
        })();
        let owner = match installed {
            Ok(owner) => owner,
            Err(error) => {
                if !borrowed { super::cancel_backend_reservation(identity); }
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
        pr_info!("sparklink: provider sle{} generation={} profile={} registered SETUP, not Ready\n",
                 id, identity.generation, metadata.profile);
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
    super::sle_detach_device(DeviceIdentity { id, generation });
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

#[no_mangle]
pub(crate) unsafe extern "C" fn sparklink_native_current_address_rust(id:u16,generation:u64,address:*mut u8)->i32 {
    let result=(||->Result {
        if address.is_null() {return Err(EINVAL);}
        let owner=super::sle_ingress::ingress_owner(DeviceIdentity{id,generation}).ok_or(ENODEV)?;
        let guard=owner.state.lock();
        let state=guard.as_ref().ok_or(ENODEV)?;
        let host=owner.host.lock();
        if *owner.schedule_gate.lock() {return Err(ENODEV);}
        if let Some(error)=host.controller_status().2 {return Err(error);}
        if !host.address_metadata_valid() {return Err(EAGAIN);}
        let value=state.controller.info().addr;
        // SAFETY: internal caller provides six live bytes;copied only on success.
        unsafe {core::ptr::copy_nonoverlapping(value.as_ptr(),address,6)};
        Ok(())
    })();
    NativeController::result_to_errno(result)
}

/// Callback receives a complete standard event packet or WS73 HCC slot;
/// attribution comes from the immutable registration, not packet bytes.
#[no_mangle]
pub(crate) unsafe extern "C" fn sparklink_native_snoop_rx_rust(id:u16, generation:u64, data:*const u8, length:usize) {
    if data.is_null() || length==0 || length>20*1024 { return; }
    let Some(owner)=super::sle_ingress::ingress_owner(DeviceIdentity {id,generation}) else { return; };
    if owner.protocol_profile>1 { return; }
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
    if owner.protocol_profile>1 || (owner.protocol_profile==0 && length>u16::MAX as usize-4) {return;}
    // SAFETY: driver retains the command parameter buffer for this callback.
    let params=unsafe {core::slice::from_raw_parts(params,length)};
    let gate=owner.schedule_gate.lock();
    if *gate {return;}
    owner.snoop.lock().tx(owner.identity,owner.protocol_profile,opcode,params,status);
    drop(gate); owner.snoop_poll.notify_all();
}

/// Callback receives a complete standard event packet or WS73 HCC slot;
/// attribution comes from the immutable registration, not packet bytes.
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

/// Common ControllerData envelope (NearLink Host f087 DLI_ControllerDataEvt).
/// No structure cast/padding, SMP index interpretation, authorization or
/// lifecycle acceptance occurs here. Those belong to the Session actor.
fn native_controller_data_valid(params: &[u8]) -> bool {
    if !(5..=260).contains(&params.len()) { return false; }
    let handle = u16::from_le_bytes([params[0], params[1]]);
    handle <= 0x0fff && params[4] as usize == params.len() - 5
}

/// Callback receives a complete standard event packet or WS73 HCC slot;
/// attribution comes from the immutable registration, not packet bytes.
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
        let queued = if let Some(link) = link {
            matches!(data.receive(super::sle_native_data::Packet { lifetime: link.lifetime, security_revision: link.security_revision, handle, bytes }, boundary, now), Ok(true))
        } else {
            data.dropped = data.dropped.saturating_add(1);
            false
        };
        drop(gate); drop(data); drop(host);
        drop(retired);
        // Intermediate PB fragments and bounded drops do not make data
        // readable. Do not wake every Session to retry TX without new RX or
        // credit; leave any already-published hint intact. NOCP and lifecycle
        // notifications retain their independent paths below and in Runtime.
        if queued {
            owner.data_poll.notify_all();
            owner.kick_session_data();
        }
        return 0; // bounded ingress drop is not a USB/device recovery request
    }
    if packet[0] != 0xa2 || count != length - 5 { return PROTOCOL_ERROR; }
    let params = &packet[5..];
    if event == 0x0014 {
        if !native_controller_data_valid(params) {return PROTOCOL_ERROR;}
        let handle=u16::from_le_bytes([params[0],params[1]]);
        let index=u16::from_le_bytes([params[2],params[3]]);
        let mut bytes=KVec::new();
        if bytes.extend_from_slice(&params[5..],GFP_ATOMIC).is_err() {return ENOMEM.to_errno();}
        let lifetime={
            let host=owner.host.lock();let (_,known,links)=host.link_snapshot();
            let gate=owner.schedule_gate.lock();
            if *gate {return ENODEV.to_errno();}
            if !host.admits_data() {return -(kernel::bindings::EACCES as i32);}
            let Some(link)=links.iter().flatten().find(|link|known&&link.handle==handle) else {return -(kernel::bindings::ESTALE as i32);};
            link.lifetime
        };
        // Freeze observed lifetime BEFORE queueing; a later link publication
        // cannot reassign this software packet. Old firmware packets after
        // handle reuse still require the separate physical drain barrier.
        super::sle_ingress::enqueue_rx(&owner,SleEvent::NativeControllerData {lifetime,handle,index,data:bytes});
        return 0; // finite ingress admission, never peer acceptance/authentication
    }
    if matches!(event, 0x000e | 0x0011) {
        if (event==0x000e && params.len()!=2) || (event==0x0011 && params.len()!=4) {return PROTOCOL_ERROR;}
        let (status,handle,enabled)=if event==0x000e {(0,u16::from_le_bytes([params[0],params[1]]),0)}
            else {(params[0],u16::from_le_bytes([params[1],params[2]]),params[3])};
        if handle>0x0fff {return PROTOCOL_ERROR;}
        // Installation receipts may settle an existing physical obligation
        // after grant withdrawal. The worker only targets the original Session;
        // this metadata path neither creates one nor admits application data.
        let (lifetime,security_revision)={
            let mut host=owner.host.lock();let gate=owner.schedule_gate.lock();
            if *gate {return ENODEV.to_errno();}
            // Publish the per-link barrier before the ordinary RX ring. Even
            // ring loss or a waiting worker cannot leave old security current.
            let Some(receipt)=host.security_receipt(handle) else {return -(kernel::bindings::ESTALE as i32);};
            receipt
        };
        super::sle_ingress::enqueue_rx(&owner,SleEvent::NativeSecurityInstallation{lifetime,security_revision,handle,event,status,enabled});
        owner.kick_session_data(); // wake protected bindings even if ordinary event queue lost
        return 0;
    }
    if length > 260 { return PROTOCOL_ERROR; }
    if event == 9 {
        if params.len() != 3 { return PROTOCOL_ERROR; }
        let handle = u16::from_le_bytes([params[0], params[1]]);
        let mut data = owner.data.lock();
        let gate = owner.schedule_gate.lock();
        if *gate { return ENODEV.to_errno(); }
        data.completed(handle, params[2]);
        drop(gate); drop(data);
        owner.data_poll.notify_all();
        owner.kick_session_data(); // real data accounting, never command credit
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
    consent: Option<unsafe extern "C" fn(*mut c_void, u64, unsafe extern "C" fn(*mut c_void) -> i32, *mut c_void) -> i32>,
    scope: *mut c_void,
    attempted: Cell<bool>,
    submitted: Cell<bool>,
    credit_blocked: Cell<bool>, // exact reserve result, not an errno heuristic
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
    let Some(link) = links.iter().flatten().find(|link| link.handle == ticket.handle && link.lifetime == ticket.lifetime) else {
        return -(kernel::bindings::ESTALE as i32);
    };
    if let Err(error) = data.credits.reserve(ticket.lifetime, ticket.handle, ticket.length) {
        ticket.credit_blocked.set(error == super::sle_data_credit::CreditError::WouldBlock);
        return super::sle_native_data::error(error).to_errno();
    }
    // SAFETY: registered Backend contract permits only an already prepared
    // atomic queue operation (WS73: usb_submit_urb(..., GFP_ATOMIC)). No wait,
    // kernel allocation with sleeping flags, protocol callback or decode here.
    let result = if let Some(consent) = ticket.consent {
        // SAFETY: scope belongs to the live session worker; consent holds its
        // state lock through the same prepared atomic queue operation.
        unsafe { consent(ticket.scope, link.security_revision, submit.unwrap(), context) }
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
    unsafe { native_acb_send(id, generation, lifetime, handle, data, length, 0, None, None, core::ptr::null_mut(), core::ptr::null_mut()) }
}
/// Same retained Ticket/commit path, with a typed internal EAGAIN reason.
/// A credit wait can sleep until a real NOCP/event or its original deadline;
/// transport/visibility EAGAIN must retain a finite retry source. Not UAPI.
#[no_mangle]
pub(crate) unsafe extern "C" fn sparklink_native_acb_send_deferred_rust(
    id: u16, generation: u64, lifetime: u64, handle: u16, boundary: u8,
    data: *const u8, length: usize, epoch: u64,
    consent: Option<unsafe extern "C" fn(*mut c_void, u64, unsafe extern "C" fn(*mut c_void) -> i32, *mut c_void) -> i32>,
    scope: *mut c_void, wait: *mut u32,
) -> i32 {
    if consent.is_none() || scope.is_null() || wait.is_null() { return EINVAL.to_errno(); }
    // SAFETY: C worker owns the writable reason and synchronous scope/buffer.
    unsafe { native_acb_send(id, generation, lifetime, handle, data, length,
        boundary, Some(epoch), consent, scope, wait) }
}
unsafe fn native_acb_send(
    id: u16, generation: u64, lifetime: u64, handle: u16, data: *const u8, length: usize, boundary: u8,
    epoch: Option<u64>, consent: Option<unsafe extern "C" fn(*mut c_void, u64, unsafe extern "C" fn(*mut c_void) -> i32, *mut c_void) -> i32>, scope: *mut c_void, wait: *mut u32,
) -> i32 {
    // SAFETY: optional internal output lives throughout this synchronous call.
    // Early transport/identity visibility EAGAIN is a finite retry, never credit.
    if !wait.is_null() { unsafe { *wait = 2 }; }
    if boundary > 3 || data.is_null() || length == 0 || length > super::sle_native_data::MAXIMUM { return EINVAL.to_errno(); }
    let Some(owner) = super::sle_ingress::ingress_owner(DeviceIdentity { id, generation }) else { return ENODEV.to_errno(); };
    let _lifecycle = owner.native_lifecycle.lock();
    let transport = {
        let state = owner.state.lock();
        let Some(backend) = state.as_ref().map(|s| &s.controller) else {
            return UNSUPPORTED;
        };
        let controller = backend.provider();
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
        consent, scope, attempted: Cell::new(false), submitted: Cell::new(false), credit_blocked: Cell::new(false) };
    // SAFETY: caller owns immutable bytes, the ticket and retained Backend
    // remain live until the blocking driver callback joins its completion.
    let result = unsafe { sparklink_native_transport_acb(transport.transport,
        (&mut ticket as *mut NativeTxTicket).cast(), handle, boundary, data, length) };
    let result = if result == 0 && !ticket.submitted.get() { PROTOCOL_ERROR } else { result };
    if result != 0 && ticket.submitted.get() { owner.data.lock().credits.transport_failed(); }
    if !wait.is_null() {
        // Only an actual failed reserve marks CREDIT. A generic driver EAGAIN
        // or accepted-but-uncertain failure can never masquerade as that wait.
        unsafe { *wait = if result != EAGAIN.to_errno() { 0 }
            else if ticket.credit_blocked.get() { 1 } else { 2 } };
    }
    owner.data_poll.notify_all();
    result
}

/// Internal DTAP consumer; a stale lifetime cannot consume another link's RX.
#[no_mangle]
pub(crate) unsafe extern "C" fn sparklink_native_acb_take_rust(
    id: u16, generation: u64, lifetime: u64, handle: u16,
    data: *mut u8, capacity: usize, length: *mut usize, security_revision: *mut u64,
) -> i32 {
    if data.is_null() || length.is_null() || security_revision.is_null() { return EINVAL.to_errno(); }
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
        *length = packet.bytes.len(); *security_revision = packet.security_revision; }
    0
}
