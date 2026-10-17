// SPDX-License-Identifier: GPL-2.0

//! SparkLink userspace API (UAPI) definitions.
//!
//! IOCTL command codes and all associated repr(C) data structures
//! exchanged between the `/dev/sparklink` char device and userspace.

use kernel::ioctl::{_IOR, _IOW, _IOWR};
use kernel::prelude::*;
use kernel::transmute::FromBytes;


// ---------------------------------------------------------------------------
// Padding / reserved field validation (per botching-up-ioctls.rst)
// ---------------------------------------------------------------------------

/// Helper trait: is a padding field all-zero?
pub(crate) trait IsZeroPad {
    fn is_zero(&self) -> bool;
}

impl IsZeroPad for u8 {
    fn is_zero(&self) -> bool { *self == 0 }
}
impl IsZeroPad for u16 {
    fn is_zero(&self) -> bool { *self == 0 }
}
impl IsZeroPad for u32 {
    fn is_zero(&self) -> bool { *self == 0 }
}
impl<const N: usize> IsZeroPad for [u8; N] {
    fn is_zero(&self) -> bool { self.iter().all(|&b| b == 0) }
}

/// Rejects non-zero padding/reserved fields from userspace, preventing
/// forward-compatibility issues when these fields gain meaning later.
pub(crate) trait CheckReserved {
    fn check_reserved(&self) -> Result<()> {
        Ok(())
    }
}

/// Generate `CheckReserved` impl that rejects non-zero padding fields.
/// Use the no-argument form for structs without padding.
macro_rules! impl_check_reserved {
    ($ty:ty, [ $($field:ident),+ $(,)? ]) => {
        impl CheckReserved for $ty {
            fn check_reserved(&self) -> Result<()> {
                $(
                    if !IsZeroPad::is_zero(&self.$field) {
                        return Err(EINVAL);
                    }
                )+
                Ok(())
            }
        }
    };
    ($ty:ty) => {
        impl CheckReserved for $ty {}
    };
}

// Scalar types passed to read_user_struct — no padding to check.
impl CheckReserved for u8 {}
impl CheckReserved for u16 {}
impl CheckReserved for i16 {}

// ---------------------------------------------------------------------------
// Buffer size constants (used by IOCTL handlers for bounds clamping)
// ---------------------------------------------------------------------------

/// Maximum name length in SleInjectAdv / SleAdvParams.
/// Maximum advertising/scan data payload.
/// Maximum DLI command parameter length.
pub(crate) const DLI_PARAM_MAX: usize = 240;

// ---------------------------------------------------------------------------
// IOCTL definitions for the /dev/sparklink control interface
// ---------------------------------------------------------------------------

pub(crate) const SL_MAGIC: u32 = 'S' as u32;

// Only currently implemented control/observation operations are declared.
// Retired raw numbers are test-only historical encodings,never reused.

/// Get the number of registered SCI devices.
pub(crate) const SL_IOCTL_DEV_COUNT: u32 = _IOR::<u32>(SL_MAGIC, 0x03);

/// Get device info by index.
pub(crate) const SL_IOCTL_DEV_INFO: u32 = _IOR::<SciDevInfo>(SL_MAGIC, 0x04);

/// List all registered device IDs (returns bitmask u16).
pub(crate) const SL_IOCTL_DEV_LIST: u32 = _IOR::<u16>(SL_MAGIC, 0x06);

/// Select per-fd device affinity (i16: -1 = follow global, ≥0 = bind to device).
///
/// Unlike DEV_SWITCH (which changes the global active controller),
/// DEV_SELECT only affects the calling fd.  On each subsequent ioctl,
/// the handler auto-switches to the fd's target device if needed.
pub(crate) const SL_IOCTL_DEV_SELECT: u32 = _IOW::<i16>(SL_MAGIC, 0x07);

/// Query the effective device for this fd (returns u16).
/// If the fd has a per-fd affinity, returns that; otherwise returns
/// this File binding (or 0xFFFF when unselected); no global fallback.
pub(crate) const SL_IOCTL_DEV_GET_ACTIVE: u32 = _IOR::<u16>(SL_MAGIC, 0x08);

pub(crate) const SL_IOCTL_CONTROLLER_EVENT_GET: u32 =
    _IOWR::<SleControllerEventQuery>(SL_MAGIC, 0x87);

/// Get management plane pending queue statistics.
pub(crate) const SL_IOCTL_MGMT_STATS: u32 = _IOR::<SleMgmtStats>(SL_MAGIC, 0x85);

// ---------------------------------------------------------------------------
// SparkLink address (6 bytes, same as SLE MAC layer identifier)
// ---------------------------------------------------------------------------

// Native event observations retain their exact current layout and cursor contract.
pub(crate) const CONTROLLER_EVENT_VERSION: u32 = 1;
pub(crate) const CONTROLLER_EVENT_PAYLOAD_MAX: usize = 288;

/// Complete native controller parameters, attributed to one registration.
#[repr(C, align(8))]
#[derive(Copy, Clone)]
pub(crate) struct SleControllerEvent {
    pub seq: u64,
    pub generation: u64,
    pub timestamp_ns: u64,
    pub lost: u64,
    pub profile: u32,
    pub dev_index: u16,
    pub event_code: u16,
    pub payload_len: u16,
    pub flags: u16,
    pub _reserved: u32,
    pub payload: [u8; CONTROLLER_EVENT_PAYLOAD_MAX],
}

/// Versioned non-destructive cursor request; event is output only.
#[repr(C, align(8))]
#[derive(Copy, Clone)]
pub(crate) struct SleControllerEventQuery {
    pub after_seq: u64,
    pub generation: u64,
    pub version: u32,
    pub flags: u32,
    pub event: SleControllerEvent,
}

// SAFETY: both repr(C) types contain only integer fields and byte arrays;
// every input bit pattern is valid. Query fields are checked by the handler.
unsafe impl FromBytes for SleControllerEvent {}
unsafe impl FromBytes for SleControllerEventQuery {}

const _: () = assert!(core::mem::size_of::<SleControllerEvent>() == 336);
const _: () = assert!(core::mem::offset_of!(SleControllerEvent, payload) == 48);
const _: () = assert!(core::mem::size_of::<SleControllerEventQuery>() == 360);
const _: () = assert!(core::mem::offset_of!(SleControllerEventQuery, event) == 24);

/// SLE media access layer identifier, 6 bytes.
#[repr(C)]
#[derive(Copy, Clone, Default)]
pub(crate) struct SleAddr {
    /// Raw 6-byte SLE address.
    pub b: [u8; 6],
}

// ---------------------------------------------------------------------------
// Userspace data structures (ioctl payloads)
// ---------------------------------------------------------------------------

/// Device information returned to userspace.
#[repr(C)]
#[derive(Copy, Clone, Default)]
pub(crate) struct SciDevInfo {
    /// SCI device index.
    pub index: u16,
    /// Legacy metadata observation;query reports0xff,never Host Ready.
    pub state: u8,
    /// Validated provider transport provenance,not protocol capability.
    pub bus: u8,
    /// SLE address.
    pub addr: SleAddr,
    /// Device name (UTF-8, null-padded).
    pub name: [u8; 32],
    pub(crate) _reserved: [u8; 24],
}


// ---------------------------------------------------------------------------
// DLI controller information
// ---------------------------------------------------------------------------


/// Management plane pending queue statistics.
#[repr(C)]
#[derive(Copy, Clone, Default)]
pub(crate) struct SleMgmtStats {
    /// Currently pending (unresolved) commands.
    pub pending: u16,
    pub(crate) _pad: u16,
    /// Total commands submitted.
    pub total_submitted: u32,
    /// Total commands resolved (complete or timeout).
    pub total_resolved: u32,
    /// Total command timeouts.
    pub total_timeouts: u32,
}

// SAFETY: SleMgmtStats is repr(C) with only primitive fields.
unsafe impl FromBytes for SleMgmtStats {}

// ---------------------------------------------------------------------------
// CheckReserved implementations — reject non-zero padding from userspace
// ---------------------------------------------------------------------------

impl_check_reserved!(SciDevInfo, [_reserved]);
impl_check_reserved!(SleMgmtStats, [_pad]);

// Structs without padding fields — no-op validation.
// Query.event is output-only. Only the handler validates input version/flags.
impl_check_reserved!(SleControllerEventQuery);

pub(crate) const SL_IOCTL_DISCOVERY_SUBMIT: u32 = _IOW::<SleDiscoverySubmit>(SL_MAGIC, 0x88);
pub(crate) const SL_IOCTL_DISCOVERY_RESULT: u32 = _IOWR::<SleDiscoveryResult>(SL_MAGIC, 0x89);
pub(crate) const DISCOVERY_VERSION: u32 = 1;
#[repr(C)]
#[derive(Copy, Clone)]
pub(crate) struct SleDiscoveryAdvConfig {
    pub handle: u32,
    pub mode: u32,
    pub gt_role: u32,
    pub interval_min: u32,
    pub interval_max: u32,
    pub channel_map: u32,
    pub own_address_type: u32,
    pub peer_address_type: u32,
    pub own_address: [u8; 6],
    pub peer_address: [u8; 6],
    pub filter: u32,
    pub tx_power: i32,
    pub primary_frame: u32,
    pub secondary_frame: u32,
    pub secondary_phy: u32,
    pub secondary_pilot: u32,
    pub secondary_mcs: u32,
    pub secondary_max_skip: u32,
    pub sid: u32,
    pub request_notification: u32,
    pub max_requests: u32,
    pub request_rx_duration: u32,
    pub conn_interval_min: u32,
    pub conn_interval_max: u32,
    pub conn_max_latency: u32,
    pub supervision_timeout: u32,
    pub min_event_length: u32,
    pub max_event_length: u32,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub(crate) struct SleDiscoveryScanConfig {
    pub own_address_type: u32,
    pub filter: u32,
    pub frame_types: u32,
    pub active: u32,
    pub interval: u32,
    pub window: u32,
    pub filter_duplicates: u32,
}
#[repr(C, align(8))]
#[derive(Copy, Clone)]
pub(crate) struct SleDiscoverySubmit {
    pub version: u32,
    pub profile: u32,
    pub operation: u32,
    pub flags: u32,
    pub generation: u64,
    pub request_id: u64,
    pub advertising: SleDiscoveryAdvConfig,
    pub scanning: SleDiscoveryScanConfig,
    pub handle: u32,
    pub duration: u32,
    pub max_events: u32,
    pub data_len: u32,
    pub scan_response_len: u32,
    pub reserved: u32,
    pub data: [u8; 251],
    pub scan_response: [u8; 251],
    pub reserved_tail: [u8; 2],
}
#[repr(C, align(8))]
#[derive(Copy, Clone)]
pub(crate) struct SleDiscoveryResult {
    pub generation: u64,
    pub request_id: u64,
    pub version: u32,
    pub flags: u32,
    pub profile: u32,
    pub operation: u32,
    pub state: u32,
    pub error: i32,
    pub selected_power: i32,
    pub radio_adv: u32,
    pub radio_scan: u32,
    pub dev_index: u16,
    pub opcode: u16,
    pub step: u8,
    pub count: u8,
    pub status: u8,
    pub power_valid: u8,
    pub reserved: [u8; 4],
}
// SAFETY: repr(C) integer-only structure, all bit patterns valid.
unsafe impl FromBytes for SleDiscoveryAdvConfig {}
// SAFETY: repr(C) integer-only structure, all bit patterns valid.
unsafe impl FromBytes for SleDiscoveryScanConfig {}
// SAFETY: repr(C) integer-only structure, all bit patterns valid.
unsafe impl FromBytes for SleDiscoverySubmit {}
// SAFETY: repr(C) integer-only structure, all bit patterns valid.
unsafe impl FromBytes for SleDiscoveryResult {}
impl CheckReserved for SleDiscoverySubmit {
    fn check_reserved(&self) -> Result {
        if self.reserved != 0 || self.reserved_tail != [0; 2] { Err(EINVAL) } else { Ok(()) }
    }
}
impl CheckReserved for SleDiscoveryResult {
    fn check_reserved(&self) -> Result {
        if self.reserved != [0; 4] { Err(EINVAL) } else { Ok(()) }
    }
}

const _: () = assert!(core::mem::size_of::<SleDiscoveryAdvConfig>() == 116);
const _: () = assert!(core::mem::size_of::<SleDiscoveryScanConfig>() == 28);
const _: () = assert!(core::mem::size_of::<SleDiscoverySubmit>() == 704);
const _: () = assert!(core::mem::offset_of!(SleDiscoverySubmit, data) == 200);
const _: () = assert!(core::mem::size_of::<SleDiscoveryResult>() == 64);
const _: () = assert!(core::mem::offset_of!(SleDiscoveryResult, dev_index) == 52);

pub(crate) const SL_IOCTL_CONTROLLER_SNAPSHOT: u32 = _IOWR::<SleControllerSnapshot>(SL_MAGIC, 0x8a);
/// Core registration observation, independent of fd affinity and Host Ready.
pub(crate) const SL_IOCTL_REGISTRATION_SNAPSHOT: u32 = _IOWR::<SleRegistrationSnapshot>(SL_MAGIC, 0x9f);
pub(crate) const REGISTRATION_PENDING: u32 = 1;
pub(crate) const REGISTRATION_FAULT: u32 = 2;
pub(crate) const REGISTRATION_INSTALLED: u32 = 3;
pub(crate) const REGISTRATION_RETIRING: u32 = 4;
#[repr(C, align(8))]
#[derive(Copy, Clone)]
pub(crate) struct SleRegistrationSnapshot {
    pub generation: u64,
    pub version: u32,
    pub state: u32,
    pub profile: u32,
    pub phase: u32,
    pub error: i32,
    pub dev_index: u16,
    pub bus: u8,
    pub reserved_byte: u8,
    pub reserved: [u8; 8],
}
// SAFETY: integer-only repr(C) type; every bit pattern is valid.
unsafe impl FromBytes for SleRegistrationSnapshot {}
impl CheckReserved for SleRegistrationSnapshot {
    fn check_reserved(&self) -> Result {
        if self.reserved_byte != 0 || self.reserved != [0; 8] { Err(EINVAL) } else { Ok(()) }
    }
}
const _: () = assert!(core::mem::size_of::<SleRegistrationSnapshot>() == 40);

#[repr(C, align(8))]
#[derive(Copy, Clone)]
pub(crate) struct SleControllerSnapshot {
    pub generation: u64,
    pub version: u32,
    pub flags: u32,
    pub profile: u32,
    pub valid_fields: u32,
    pub dev_index: u16,
    pub bus: u8,
    pub command_credits: u8,
    pub acb_length: u16,
    pub icb_length: u16,
    pub acb_count: u8,
    pub icb_count: u8,
    pub version_tuple: [u8; 5],
    pub features: [u8; 10],
    pub address: [u8; 6],
    pub reserved_byte: u8,
    pub error: i32,
    pub reserved: [u8; 4],
}
// SAFETY: integer-only repr(C) type; every bit pattern is valid.
unsafe impl FromBytes for SleControllerSnapshot {}
impl CheckReserved for SleControllerSnapshot {
    fn check_reserved(&self) -> Result {
        if self.reserved_byte != 0 || self.reserved != [0; 4] {
            Err(EINVAL)
        } else {
            Ok(())
        }
    }
}
const _: () = assert!(core::mem::size_of::<SleControllerSnapshot>() == 64);


pub(crate) const SL_IOCTL_MANAGEMENT_ACQUIRE: u32 = _IOWR::<SleManagementRequest>(SL_MAGIC, 0x8b);
pub(crate) const SL_IOCTL_MANAGEMENT_RELEASE: u32 = _IOW::<SleManagementRequest>(SL_MAGIC, 0x8c);
pub(crate) const SL_IOCTL_MANAGEMENT_QUERY: u32 = _IOWR::<SleManagementQuery>(SL_MAGIC, 0x8d);
#[repr(C, align(8))]
#[derive(Clone, Copy)]
pub(crate) struct SleManagementRequest {
    pub generation: u64, pub lease: u64,
    pub version: u32, pub mode: u32, pub flags: u32, pub reserved: u32,
}
#[repr(C, align(8))]
#[derive(Clone, Copy)]
pub(crate) struct SleManagementQuery {
    pub generation: u64, pub lease: u64,
    pub version: u32, pub mode: u32, pub state: u32, pub flags: u32,
    pub error: i32, pub status: u32, pub opcode: u32, pub reserved: u32,
}
// SAFETY: integer-only repr(C) types; all bit patterns valid.
unsafe impl FromBytes for SleManagementRequest {}
// SAFETY: integer-only repr(C) types; all bit patterns valid.
unsafe impl FromBytes for SleManagementQuery {}
impl CheckReserved for SleManagementRequest {
    fn check_reserved(&self) -> Result { if self.flags != 0 || self.reserved != 0 { Err(EINVAL) } else { Ok(()) } }
}
impl CheckReserved for SleManagementQuery {
    fn check_reserved(&self) -> Result {
        if self.lease != 0 || self.mode != 0 || self.state != 0 || self.flags != 0
            || self.error != 0 || self.status != 0 || self.opcode != 0 || self.reserved != 0 { Err(EINVAL) } else { Ok(()) }
    }
}
const _: () = assert!(core::mem::size_of::<SleManagementRequest>() == 32);
const _: () = assert!(core::mem::size_of::<SleManagementQuery>() == 48);

pub(crate) const SNOOP_VERSION: u32 = 1;
pub(crate) const SNOOP_PAYLOAD_MAX: usize = 320;
pub(crate) const SNOOP_TRUNCATED: u16 = 1;
pub(crate) const SNOOP_REDACTED: u16 = 2;
#[repr(C, align(8))]
#[derive(Clone, Copy)]
pub(crate) struct SleSnoopRecord {
    pub seq: u64, pub generation: u64, pub timestamp_ns: u64, pub lost: u64,
    pub profile: u32, pub original_length: u32, pub status: i32,
    pub dev_index: u16, pub direction: u8, pub format: u8,
    pub captured_length: u16, pub flags: u16, pub reserved: u32,
    pub payload: [u8; SNOOP_PAYLOAD_MAX],
}
#[repr(C, align(8))]
#[derive(Clone, Copy)]
pub(crate) struct SleSnoopQuery {
    pub generation: u64, pub after_seq: u64, pub version: u32, pub flags: u32,
    pub reserved: u64, pub record: SleSnoopRecord,
}
// SAFETY: these types contain only integers and byte arrays.
unsafe impl FromBytes for SleSnoopRecord {}
// SAFETY: these types contain only integers and byte arrays.
unsafe impl FromBytes for SleSnoopQuery {}
impl CheckReserved for SleSnoopQuery {
    fn check_reserved(&self) -> Result { if self.flags != 0 || self.reserved != 0 { Err(EINVAL) } else { Ok(()) } }
}
pub(crate) const SL_IOCTL_SNOOP_GET: u32 = _IOWR::<SleSnoopQuery>(SL_MAGIC, 0x8e);
const _: () = assert!(core::mem::size_of::<SleSnoopRecord>() == 376);
const _: () = assert!(core::mem::size_of::<SleSnoopQuery>() == 408);

/// Read-only final Complete timing; existing 64-byte result ABI is unchanged.
pub(crate) const SL_IOCTL_DISCOVERY_TIMING: u32 = _IOWR::<SleDiscoveryTiming>(SL_MAGIC, 0x8f);
#[repr(C, align(8))]
#[derive(Copy, Clone)]
pub(crate) struct SleDiscoveryTiming {
    pub generation: u64,
    pub request_id: u64,
    pub completed_boottime_ns: u64,
    pub version: u32,
    pub flags: u32,
    pub operation: u32,
    pub state: u32,
    pub dev_index: u16,
    pub opcode: u16,
    pub status: u8,
    pub reserved: [u8; 3],
}
// SAFETY: repr(C), integer/byte fields; every bit pattern valid.
unsafe impl FromBytes for SleDiscoveryTiming {}
impl CheckReserved for SleDiscoveryTiming {
 fn check_reserved(&self)->Result { if self.reserved==[0;3] {Ok(())} else {Err(EINVAL)} }
}
const _: () = assert!(core::mem::size_of::<SleDiscoveryTiming>()==48);

/// Owner-private bounded diagnostic result; input version/flags/generation/seq.
#[repr(C, align(8))]
#[derive(Copy, Clone)]
pub(crate) struct SleDiagnosticResult {
    pub version: u32,
    pub flags: u32,
    pub generation: u64,
    pub seq: u32,
    pub state: u32,
    pub error: i32,
    pub opcode: u16,
    pub status: u8,
    pub(crate) _pad: u8,
    pub data_len: u16,
    pub(crate) _reserved: [u8; 6],
    pub data: [u8; 64],
}
// SAFETY: repr(C), integer and byte-array fields; every bit pattern is valid.
unsafe impl FromBytes for SleDiagnosticResult {}
impl_check_reserved!(SleDiagnosticResult, [_pad, _reserved]);
const _: () = assert!(core::mem::size_of::<SleDiagnosticResult>() == 104);
pub(crate) const SL_IOCTL_DIAGNOSTIC_RESULT: u32 = _IOWR::<SleDiagnosticResult>(SL_MAGIC, 0xd0);

/// Idempotent metadata diagnostic admission/cancel; request ID is local only.
#[repr(C, align(8))]
#[derive(Copy, Clone)]
pub(crate) struct SleDiagnosticSubmit {
    pub version: u32,
    pub flags: u32,
    pub generation: u64,
    pub request_id: u64,
    pub timeout_ms: u32,
    pub opcode: u16,
    pub reserved: u16,
    pub seq: u32,
    pub action: u32,
}
// SAFETY: fixed integer fields, no implicit padding.
unsafe impl FromBytes for SleDiagnosticSubmit {}
impl_check_reserved!(SleDiagnosticSubmit, [reserved]);
const _: () = assert!(core::mem::size_of::<SleDiagnosticSubmit>() == 40);
pub(crate) const SL_IOCTL_DIAGNOSTIC_SUBMIT: u32 = _IOWR::<SleDiagnosticSubmit>(SL_MAGIC, 0xd1);

pub(crate) const SL_IOCTL_CONNECTION_SUBMIT: u32 = _IOW::<SleConnectionSubmit>(SL_MAGIC, 0x9c);
pub(crate) const SL_IOCTL_CONNECTION_RESULT: u32 = _IOWR::<SleConnectionResult>(SL_MAGIC, 0x9d);
#[repr(C)]
#[derive(Copy, Clone)]
pub(crate) struct SleConnectionParameters {
    pub filter: u32, pub own_address_type: u32, pub peer_address_type: u32,
    pub peer_address: [u8; 6], pub reserved: [u8; 2],
    pub gt_negotiate: u32, pub frame: u32,
    pub scan_interval: u32, pub scan_window: u32, pub interval_min: u32, pub interval_max: u32,
    pub latency: u32, pub supervision_timeout: u32, pub event_min: u32, pub event_max: u32,
}
#[repr(C, align(8))]
#[derive(Copy, Clone)]
pub(crate) struct SleConnectionSubmit {
    pub version: u32, pub profile: u32, pub operation: u32, pub flags: u32,
    pub generation: u64, pub request_id: u64,
    pub timeout_ms: u32, pub handle: u32, pub reason: u32, pub reserved: u32,
    pub parameters: SleConnectionParameters, pub reserved_tail: u32,
    pub expected_lifetime: u64, pub expected_address: [u8; 6],
    pub expected_address_type: u8, pub expected_role: u8,
}
#[repr(C, align(8))]
#[derive(Copy, Clone)]
pub(crate) struct SleConnectionResult {
    pub version: u32, pub profile: u32, pub state: u32, pub operation: u32,
    pub generation: u64, pub request_id: u64, pub error: i32, pub fault_error: i32,
    pub command_status: u32, pub outcome_status: u32, pub handle: u32, pub flags: u32,
    pub dev_index: u16, pub reserved: [u8; 6],
}
impl_check_reserved!(SleConnectionSubmit, [reserved, reserved_tail]);
impl_check_reserved!(SleConnectionResult);
const _: () = assert!(core::mem::size_of::<SleConnectionParameters>() == 60);
const _: () = assert!(core::mem::size_of::<SleConnectionSubmit>() == 128);
const _: () = assert!(core::mem::size_of::<SleConnectionResult>() == 64);

// SAFETY: padding-free repr(C) integers and byte arrays accept all bit patterns.
unsafe impl FromBytes for SleConnectionParameters {}
// SAFETY: integer-only repr(C) request; reserved input is validated separately.
unsafe impl FromBytes for SleConnectionSubmit {}
// SAFETY: integer-only repr(C) result with initialized output bytes.
unsafe impl FromBytes for SleConnectionResult {}

pub(crate) const SL_IOCTL_LINK_SNAPSHOT: u32 = _IOWR::<SleLinkSnapshot>(SL_MAGIC, 0x9e);
pub(crate) const LINK_SNAPSHOT_KNOWN: u32 = 1;
#[repr(C, align(8))]
#[derive(Copy, Clone)]
pub(crate) struct SleLinkInfo {
    pub lifetime: u64, pub handle: u16, pub role: u8, pub address_type: u8,
    pub address: [u8; 6], pub reserved: [u8; 6],
}
#[repr(C, align(8))]
#[derive(Copy, Clone)]
pub(crate) struct SleLinkSnapshot {
    pub generation: u64, pub event_seq: u64, pub revision: u64,
    pub version: u32, pub profile: u32, pub flags: u32, pub count: u32,
    pub error: i32, pub dev_index: u16, pub reserved: [u8; 2],
    pub links: [SleLinkInfo; 16],
}
impl_check_reserved!(SleLinkSnapshot);
// SAFETY: padding-free repr(C), only integer fields and byte arrays.
unsafe impl FromBytes for SleLinkSnapshot {}
const _: () = assert!(core::mem::size_of::<SleLinkInfo>() == 24);
const _: () = assert!(core::mem::size_of::<SleLinkSnapshot>() == 432);

/// Explicit experimental capability exchange. Never a trusted security result.
#[repr(C, align(8))]
#[derive(Copy, Clone)]
pub(crate) struct SleSecurityNegotiationSubmit {
    pub generation:u64,pub lifetime:u64,pub request_id:u64,pub deadline_monotonic_ns:u64,
    pub version:u32,pub profile:u32,pub action:u32,pub flags:u32,pub timeout_ms:u32,
    pub handle:u16,pub role:u8,pub address_type:u8,pub address:[u8;6],pub reserved:[u8;2],
}
#[repr(C, align(8))]
#[derive(Copy, Clone)]
pub(crate) struct SleSecurityNegotiationResult {
    pub generation:u64,pub lifetime:u64,pub request_id:u64,
    pub version:u32,pub profile:u32,pub state:u32,pub error:i32,pub flags:u32,
    pub handle:u16,pub role:u8,pub status:u8,pub local_caps:[u8;10],pub peer_caps:[u8;10],pub comparison_code:u32,
}
/// Local author withdrawal, independent of physical Session/controller ownership.
#[repr(C, align(8))]
#[derive(Copy, Clone)]
pub(crate) struct SleSecurityNegotiationCancel {
    pub generation: u64, pub lifetime: u64, pub request_id: u64,
    pub version: u32, pub handle: u16, pub reserved: u16,
}
impl_check_reserved!(SleSecurityNegotiationCancel, [reserved]);
// SAFETY: padding-free integers, all bit patterns valid, reserved checked.
unsafe impl FromBytes for SleSecurityNegotiationCancel {}
const _: () = assert!(core::mem::size_of::<SleSecurityNegotiationCancel>() == 32);
pub(crate) const SL_IOCTL_SECURITY_NEGOTIATION_CANCEL: u32 =
    _IOW::<SleSecurityNegotiationCancel>(SL_MAGIC, 0xd4);
impl_check_reserved!(SleSecurityNegotiationSubmit, [reserved]);
impl_check_reserved!(SleSecurityNegotiationResult);
// SAFETY: both layouts are padding-free integers/byte arrays, all bit patterns valid.
unsafe impl FromBytes for SleSecurityNegotiationSubmit {}
// SAFETY: padding-free integer/byte layout, initialized output only.
unsafe impl FromBytes for SleSecurityNegotiationResult {}
const _: ()=assert!(core::mem::size_of::<SleSecurityNegotiationSubmit>()==64);
const _: ()=assert!(core::mem::size_of::<SleSecurityNegotiationResult>()==72);
pub(crate) const SL_IOCTL_SECURITY_NEGOTIATION_SUBMIT:u32=_IOW::<SleSecurityNegotiationSubmit>(SL_MAGIC,0xd2);
pub(crate) const SL_IOCTL_SECURITY_NEGOTIATION_RESULT:u32=_IOWR::<SleSecurityNegotiationResult>(SL_MAGIC,0xd3);

#[repr(C, align(8))]
#[derive(Copy, Clone)]
pub(crate) struct SleSecurityNumericConfirm {
    pub generation:u64, pub lifetime:u64, pub request_id:u64,
    pub version:u32, pub comparison_code:u32, pub handle:u16, pub accept:u8, pub reserved:[u8;5],
}
impl_check_reserved!(SleSecurityNumericConfirm,[reserved]);
// SAFETY: padding-free integer/byte layout, all bit patterns valid, reserved checked.
unsafe impl FromBytes for SleSecurityNumericConfirm {}
const _: ()=assert!(core::mem::size_of::<SleSecurityNumericConfirm>()==40);
pub(crate) const SL_IOCTL_SECURITY_NUMERIC_CONFIRM:u32=_IOW::<SleSecurityNumericConfirm>(SL_MAGIC,0xd5);

#[repr(C, align(8))]
#[derive(Clone, Copy)]
pub(crate) struct SleConnectionSecurity {
    pub(crate) generation:u64, pub(crate) lifetime:u64, pub(crate) security_epoch:u64,
    pub(crate) version:u32, pub(crate) profile:u32, pub(crate) level:u32, pub(crate) flags:u32,
    pub(crate) handle:u16, pub(crate) method:u8, pub(crate) key_size:u8, pub(crate) error:i32,
}
impl_check_reserved!(SleConnectionSecurity);
// SAFETY: initialized integer-only ABI, every bit pattern valid.
unsafe impl FromBytes for SleConnectionSecurity {}
const _: ()=assert!(core::mem::size_of::<SleConnectionSecurity>()==48);
pub(crate) const SL_IOCTL_CONNECTION_SECURITY:u32=_IOWR::<SleConnectionSecurity>(SL_MAGIC,0xd6);
