// SPDX-License-Identifier: GPL-2.0

//! SparkLink USB transport for SLE DLI controllers.
//!
//! Implements DLI packet framing over USB and provides [`UsbController`]
//! which implements the [`SleController`] trait for USB-attached
//! SparkLink radio controllers.
//!
//! Protocol follows T/XS 10003-2025 USB transport binding:
//!
//! USB interface descriptor:
//!   bInterfaceClass     = 0xE0   Wireless Controller
//!   bInterfaceSubClass  = 0x01   RF Controller
//!   bInterfaceProtocol  = 0x05   SparkLink DLI
//!
//! Endpoint mapping (host perspective, T/XS 10003-2025 Table 3):
//!   EP0  Control           DLI instructions (standard path)
//!   INT  Interrupt IN 0x91 DLI events from controller (64B)
//!   BLK  Bulk IN      0x92 Async data from controller
//!   BLK  Bulk OUT     0x12 Async data and commands to controller

#![allow(dead_code, unreachable_pub)]

use kernel::alloc::KVec;
use kernel::device;
use kernel::prelude::*;
use kernel::usb;

use core::sync::atomic::{AtomicU32, Ordering};

use super::sle_dli::{
    DliPacketType, SleBus, SleController, SleControllerInfo, SleEvent, SleFeature, SleOpcode,
    SleStatus, SLE_MEAS_PATH_LOSS, SLE_MEAS_RSSI, SLE_SEC_AES_CCM, SLE_SEC_ECDH_P256, SLE_SEC_SC,
    SLE_TRANSPORT_FRAGMENTED, SLE_TRANSPORT_RELIABLE, SLE_TRANSPORT_UNRELIABLE,
};
use super::sle_transport::{SleAttachInfo, SleProtoId};

// ---------------------------------------------------------------------------
// IRQ-safe route lookup; ingress storage and work belong to the retained owner.
// ---------------------------------------------------------------------------

super::sle_irq_lock::irq_global_lock!(RUNTIME_ROUTES: [Option<kernel::sync::Arc<super::ControllerRuntime>>; super::sle_dev::SLE_DEV_MAX] = [const { None }; super::sle_dev::SLE_DEV_MAX]);

/// # Safety
/// Call exactly once before publishing any transport owner.
pub(crate) unsafe fn init_usb_event_ring() {
    // SAFETY: module initialization is single-threaded.
    unsafe { RUNTIME_ROUTES.init() };
}

pub(crate) fn publish_runtime(owner: &kernel::sync::Arc<super::ControllerRuntime>) {
    let previous = {
        let mut routes = RUNTIME_ROUTES.lock();
        routes[owner.identity.id as usize].replace(owner.clone())
    };
    drop(previous);
}

pub(crate) fn unpublish_runtime(owner: &kernel::sync::Arc<super::ControllerRuntime>) {
    let previous = {
        let mut routes = RUNTIME_ROUTES.lock();
        let slot = &mut routes[owner.identity.id as usize];
        if slot.as_ref().is_some_and(|r| r.identity == owner.identity) {
            slot.take()
        } else {
            None
        }
    };
    drop(previous);
}

pub(crate) fn ingress_owner(
    identity: super::sle_dev::DeviceIdentity,
) -> Option<kernel::sync::Arc<super::ControllerRuntime>> {
    RUNTIME_ROUTES
        .lock()
        .get(identity.id as usize)
        .and_then(|slot| {
            slot.as_ref()
                .filter(|owner| owner.identity == identity)
                .cloned()
        })
}

pub(crate) fn drain_runtime_events(
    owner: &super::ControllerRuntime,
    out: &mut [(Option<u16>, Option<SleEvent>)],
) -> usize {
    let mut count = 0;
    let mut ring = owner.ingress.lock();
    while count < out.len() {
        let Some((id, event)) = ring.pop_tagged() else {
            break;
        };
        out[count] = (id, Some(event));
        count += 1;
    }
    count
}

/// Inline draining never removes events belonging to another device.
pub(crate) fn drain_usb_events_for(
    identity: super::sle_dev::DeviceIdentity,
    out: &mut [(Option<u16>, Option<SleEvent>)],
) -> usize {
    ingress_owner(identity).map_or(0, |owner| drain_runtime_events(&owner, out))
}

static DECODE_DROPS: AtomicU32 = AtomicU32::new(0);

pub(crate) struct RxDropStats {
    pub(crate) ring: u32,
    pub(crate) command_complete: u32,
    pub(crate) mac_complete: u32,
    pub(crate) decode: u32,
}

pub(crate) fn take_dropped_stats(owner: &super::ControllerRuntime) -> RxDropStats {
    let ring = core::mem::take(&mut owner.ingress.lock().dropped);
    RxDropStats {
        ring,
        command_complete: owner.dropped_commands.swap(0, Ordering::Relaxed),
        mac_complete: owner.dropped_mac.swap(0, Ordering::Relaxed),
        // Decode failures before attribution remain a transport diagnostic.
        decode: DECODE_DROPS.swap(0, Ordering::Relaxed),
    }
}

pub(crate) fn enqueue_rx(owner: &kernel::sync::Arc<super::ControllerRuntime>, event: SleEvent) {
    let command = matches!(&event, SleEvent::CommandComplete { .. } | SleEvent::NativeCommandReply { .. });
    let mac = matches!(
        &event,
        SleEvent::CommandComplete {
            opcode: SleOpcode::ReadMacAddr,
            ..
        }
    );
    let stopping = owner.schedule_gate.lock();
    if *stopping {
        return;
    }
    let event = owner.host.lock().receive(event);
    let Some(event) = event else {
        // A matching reply is retained in the Host's reserved slot. It
        // cannot be lost when discovery/data fill the ordinary RX ring.
        drop(stopping);
        owner.schedule_rx(0);
        return;
    };
    let accepted = owner
        .ingress
        .lock()
        .push_tagged(Some(owner.identity.id), event);
    if !accepted {
        if command {
            owner.dropped_commands.fetch_add(1, Ordering::Relaxed);
        }
        if mac {
            owner.dropped_mac.fetch_add(1, Ordering::Relaxed);
        }
    }
    drop(stopping);
    owner.schedule_rx(0);
}

// ---------------------------------------------------------------------------
// USB FFI — C wrapper functions from sle_usb_ffi.c
// ---------------------------------------------------------------------------

/// Opaque handle returned by `sle_usb_alloc_ctx()`.
///
/// The real struct lives in C (`struct sle_urb_ctx`). Rust only holds
/// a pointer and never dereferences it directly.
#[repr(C)]
pub struct SleUrbCtxOpaque {
    _opaque: [u8; 0],
}

extern "C" {
    fn sle_usb_alloc_ctx(buf_size: i32) -> *mut SleUrbCtxOpaque;
    fn sle_usb_free_ctx(ctx: *mut SleUrbCtxOpaque);
    fn sle_usb_submit_bulk_out(
        ctx: *mut SleUrbCtxOpaque,
        udev: *mut core::ffi::c_void,
        ep: u8,
        data: *const u8,
        len: i32,
        rust_ctx: *mut core::ffi::c_void,
        timeout_ms: i32,
    ) -> i32;
    fn sle_usb_submit_bulk_in(
        ctx: *mut SleUrbCtxOpaque,
        udev: *mut core::ffi::c_void,
        ep: u8,
        rust_ctx: *mut core::ffi::c_void,
    ) -> i32;
    fn sle_usb_submit_intr_in(
        ctx: *mut SleUrbCtxOpaque,
        udev: *mut core::ffi::c_void,
        ep: u8,
        rust_ctx: *mut core::ffi::c_void,
        interval: i32,
    ) -> i32;
    fn sle_usb_kill_ctx(ctx: *mut SleUrbCtxOpaque);
    fn sle_usb_sync_bulk_out(
        udev: *mut core::ffi::c_void,
        ep: u8,
        data: *const u8,
        len: i32,
        timeout_ms: i32,
    ) -> i32;
    fn sle_usb_sync_bulk_in(
        udev: *mut core::ffi::c_void,
        ep: u8,
        buf: *mut u8,
        size: i32,
        timeout_ms: i32,
    ) -> i32;

    // Per-device USB state table: high-level send functions
    fn sle_usb_dev_register(dev_id: i32, intf_ptr: *mut core::ffi::c_void, generation: u64) -> i32;
    fn sle_usb_dev_unregister(dev_id: i32);
    fn sle_usb_dev_send_cmd(dev_id: i32, opcode: u16, params: *const u8, plen: i32) -> i32;
    fn sle_usb_dev_send_data(dev_id: i32, handle: u16, data: *const u8, len: i32) -> i32;
    fn sle_usb_dev_start_evt(dev_id: i32) -> i32;
    fn sle_usb_dev_stop_evt(dev_id: i32);
    fn sle_usb_dev_start_data(dev_id: i32) -> i32;
    fn sle_usb_dev_stop_data(dev_id: i32);
    fn sle_usb_dev_init_controller(dev_id: i32) -> i32;
    fn sle_usb_dev_get_fw_version(dev_id: i32) -> u32;
    fn sle_usb_dev_get_command_credits(dev_id: i32) -> u8;
    fn sle_usb_dev_get_mac(dev_id: i32, mac: *mut u8) -> i32;
    fn sle_usb_dev_suspend(dev_id: i32) -> i32;
    fn sle_usb_dev_resume(dev_id: i32) -> i32;
}

// ---------------------------------------------------------------------------
// URB context: safe Rust wrapper
// ---------------------------------------------------------------------------

/// Safe wrapper around the C-side URB context.
///
/// Owns the allocation and frees it on drop. Provides methods for
/// submitting and cancelling transfers without exposing raw pointers.
pub(crate) struct SleUrbCtx {
    inner: *mut SleUrbCtxOpaque,
}

// SAFETY: The C-side sle_urb_ctx is heap-allocated and has no thread
// affinity. USB core completion callbacks are synchronized via
// usb_kill_urb before free.
unsafe impl Send for SleUrbCtx {}
// SAFETY: Access to the inner pointer is synchronized by usb_kill_urb
// before deallocation; callback serialization is handled by USB core.
unsafe impl Sync for SleUrbCtx {}

impl SleUrbCtx {
    /// Allocate a new URB context with the given buffer size.
    pub(crate) fn new(buf_size: usize) -> Result<Self> {
        // SAFETY: sle_usb_alloc_ctx handles all internal allocation.
        let ptr = unsafe { sle_usb_alloc_ctx(buf_size as i32) };
        if ptr.is_null() {
            return Err(ENOMEM);
        }
        Ok(Self { inner: ptr })
    }

    /// Submit a bulk OUT (TX) transfer asynchronously.
    ///
    /// `udev_ptr` is the raw `struct usb_device *` from the kernel.
    /// Completion will invoke `sparklink_usb_complete` with `rust_ctx`.
    pub(crate) fn submit_bulk_out(
        &self,
        udev_ptr: *mut core::ffi::c_void,
        ep: u8,
        data: &[u8],
        rust_ctx: *mut core::ffi::c_void,
    ) -> Result {
        // SAFETY: inner is valid (checked in new), data pointer and len
        // are consistent, udev_ptr must be valid by caller contract.
        let ret = unsafe {
            sle_usb_submit_bulk_out(
                self.inner,
                udev_ptr,
                ep,
                data.as_ptr(),
                data.len() as i32,
                rust_ctx,
                0,
            )
        };
        if ret < 0 {
            Err(Error::from_errno(ret))
        } else {
            Ok(())
        }
    }

    /// Submit a bulk IN (RX) transfer asynchronously.
    pub(crate) fn submit_bulk_in(
        &self,
        udev_ptr: *mut core::ffi::c_void,
        ep: u8,
        rust_ctx: *mut core::ffi::c_void,
    ) -> Result {
        // SAFETY: inner/udev_ptr valid by caller contract.
        let ret = unsafe { sle_usb_submit_bulk_in(self.inner, udev_ptr, ep, rust_ctx) };
        if ret < 0 {
            Err(Error::from_errno(ret))
        } else {
            Ok(())
        }
    }

    /// Submit an interrupt IN transfer (auto-resubmitting).
    pub(crate) fn submit_intr_in(
        &self,
        udev_ptr: *mut core::ffi::c_void,
        ep: u8,
        rust_ctx: *mut core::ffi::c_void,
        interval: i32,
    ) -> Result {
        // SAFETY: inner/udev_ptr valid by caller contract.
        let ret = unsafe { sle_usb_submit_intr_in(self.inner, udev_ptr, ep, rust_ctx, interval) };
        if ret < 0 {
            Err(Error::from_errno(ret))
        } else {
            Ok(())
        }
    }

    /// Cancel a pending transfer.
    pub(crate) fn kill(&self) {
        // SAFETY: inner is valid.
        unsafe { sle_usb_kill_ctx(self.inner) };
    }
}

impl Drop for SleUrbCtx {
    fn drop(&mut self) {
        // SAFETY: inner was allocated by sle_usb_alloc_ctx.
        unsafe { sle_usb_free_ctx(self.inner) };
    }
}

// ---------------------------------------------------------------------------
// Synchronous bulk transfer helpers
// ---------------------------------------------------------------------------

/// Blocking bulk OUT transfer — sends `data` and waits for completion.
///
/// Returns the number of bytes actually transferred.
pub(crate) fn sync_bulk_out(
    udev_ptr: *mut core::ffi::c_void,
    ep: u8,
    data: &[u8],
    timeout_ms: i32,
) -> Result<usize> {
    // SAFETY: udev_ptr must be a valid struct usb_device pointer.
    let ret = unsafe {
        sle_usb_sync_bulk_out(udev_ptr, ep, data.as_ptr(), data.len() as i32, timeout_ms)
    };
    if ret < 0 {
        Err(Error::from_errno(ret))
    } else {
        Ok(ret as usize)
    }
}

/// Blocking bulk IN transfer — waits for data from the device.
///
/// Returns slice length of received data in the provided buffer.
pub(crate) fn sync_bulk_in(
    udev_ptr: *mut core::ffi::c_void,
    ep: u8,
    buf: &mut [u8],
    timeout_ms: i32,
) -> Result<usize> {
    // SAFETY: udev_ptr valid, buf pointer and size consistent.
    let ret = unsafe {
        sle_usb_sync_bulk_in(udev_ptr, ep, buf.as_mut_ptr(), buf.len() as i32, timeout_ms)
    };
    if ret < 0 {
        Err(Error::from_errno(ret))
    } else {
        Ok(ret as usize)
    }
}

// ---------------------------------------------------------------------------
// Completion callback from C — receives URB completion events
// ---------------------------------------------------------------------------

/// Generic transfer completion has no registration identity. It may report
/// transport status but must never infer an RX owner from an opaque pointer.
#[no_mangle]
pub(crate) extern "C" fn sparklink_usb_complete(
    _ctx: *mut core::ffi::c_void,
    _data: *const u8,
    length: i32,
    status: i32,
) {
    pr_debug!(
        "sparklink-usb: unregistered completion status={} len={}\n",
        status,
        length
    );
}

/// Registered RX endpoints carry identity copied into their C URB allocation
/// before first submission. This never reads identity from a reusable C slot.
#[no_mangle]
pub(crate) extern "C" fn sparklink_usb_registered_complete(
    dev_id: u32,
    generation: u64,
    data: *const u8,
    length: i32,
    status: i32,
) {
    if status != 0 || length <= 0 || data.is_null() {
        return;
    }
    if dev_id >= super::sle_dev::SLE_DEV_MAX as u32 || generation == 0 {
        return;
    }
    let identity = super::sle_dev::DeviceIdentity {
        id: dev_id as u16,
        generation,
    };
    // The retained owner stays the same through decoding and enqueue. A remove
    // that races decoding closes its scheduling gate, never selects a new slot.
    let Some(owner) = ingress_owner(identity) else {
        return;
    };

    let len = length as usize;
    // SAFETY: data points to the URB transfer buffer which is valid
    // during the completion callback. length is the actual bytes
    // transferred, guaranteed <= buffer size by USB core.
    let slice = unsafe { core::slice::from_raw_parts(data, len) };

    // Check if this is a DLI async data packet (0xA3 prefix, from Bulk IN)
    if len >= 5 && slice[0] == 0xA3 {
        // Parse DLI async data: [0xA3][link_id_seg:2][plen:2][payload...]
        let link_id_seg = u16::from_le_bytes([slice[1], slice[2]]);
        let handle = (link_id_seg >> 4) & 0x0FFF;
        let payload = &slice[5..];
        let mut data_vec = KVec::new();
        if data_vec.extend_from_slice(payload, GFP_ATOMIC).is_err() {
            DECODE_DROPS.fetch_add(1, Ordering::Relaxed);
            return;
        }
        let sle_evt = SleEvent::DataReceived {
            handle,
            data: data_vec,
        };
        enqueue_rx(&owner, sle_evt);
        return;
    }

    // Try to parse as a DLI event packet
    match parse_event_packet(slice) {
        Ok(evt) => {
            if let Some(sle_evt) = event_to_sle(&evt) {
                enqueue_rx(&owner, sle_evt);
            } else {
                DECODE_DROPS.fetch_add(1, Ordering::Relaxed);
                pr_debug!(
                    "sparklink-usb: unknown event code=0x{:04x} len={}\n",
                    evt.event_code,
                    len
                );
            }
        }
        Err(_) => {
            DECODE_DROPS.fetch_add(1, Ordering::Relaxed);
            pr_debug!(
                "sparklink-usb: parse failed len={} first={:02x}\n",
                len,
                if len > 0 { slice[0] } else { 0 }
            );
        }
    }
}

// ---------------------------------------------------------------------------
// USB descriptor class / subclass / protocol
// ---------------------------------------------------------------------------

/// USB interface class for SLE wireless controllers.
pub const SLE_USB_CLASS: u8 = 0xE0;
/// USB interface subclass: RF controller.
pub const SLE_USB_SUBCLASS: u8 = 0x01;
/// USB interface protocol: SparkLink DLI.
pub const SLE_USB_PROTOCOL: u8 = 0x05;

// ---------------------------------------------------------------------------
// Endpoint addresses and sizes (host perspective)
// ---------------------------------------------------------------------------

/// Interrupt IN endpoint for DLI events (T/XS 10003-2025 Table 3).
pub const EP_EVENT_IN: u8 = 0x91;
/// Bulk IN endpoint for async data reception (T/XS 10003-2025 Table 3).
pub const EP_DATA_IN: u8 = 0x92;
/// Bulk OUT endpoint for async data and commands (T/XS 10003-2025 Table 3).
pub const EP_CMD_DATA_OUT: u8 = 0x12;

/// Interrupt endpoint max packet size.
pub const EP_EVENT_MAX_PKT: usize = 64;
/// Bulk endpoint max packet size (full-speed).
pub const EP_BULK_FS_MAX_PKT: usize = 64;
/// Bulk endpoint max packet size (high-speed).
pub const EP_BULK_HS_MAX_PKT: usize = 512;

/// USB class request type for DLI control transfers.
pub const SLE_USB_REQ_TYPE: u8 = 0x20;

// ---------------------------------------------------------------------------
// Timeouts (milliseconds)
// ---------------------------------------------------------------------------

/// Timeout for DLI command responses.
pub const CMD_TIMEOUT_MS: u32 = 5000;
/// Timeout for bulk data transfers.
pub const DATA_TIMEOUT_MS: u32 = 1000;
/// Interval for polling the event interrupt endpoint.
pub const EVENT_POLL_INTERVAL_MS: u32 = 4;

// ---------------------------------------------------------------------------
// DLI packet size limits
// ---------------------------------------------------------------------------

/// Maximum parameter length in a DLI command or event packet.
pub const DLI_PARAM_MAX: usize = 255;

/// Maximum async data payload (9-bit length field).
pub const DLI_DATA_PAYLOAD_MAX: usize = 511;

// ---------------------------------------------------------------------------
// DLI USB packet builders
// ---------------------------------------------------------------------------

/// Build a DLI command packet for USB bulk OUT transmission.
///
/// Wire format per T/XS 10003-2025 §7.2 (all multi-byte values
/// little-endian):
///
///     Byte 0:      0xA1 (DliPacketType::Command)
///     Bytes 1-2:   opcode (LE16)
///     Bytes 3-4:   parameter length (LE16)
///     Bytes 5..N:  parameters
pub fn build_command_packet(opcode: SleOpcode, params: &[u8]) -> Result<KVec<u8>> {
    let param_len = params.len().min(DLI_PARAM_MAX);
    let total = 5 + param_len;
    let mut buf = KVec::with_capacity(total, GFP_KERNEL)?;

    buf.push(DliPacketType::Command as u8, GFP_KERNEL)?;
    let op = opcode as u16;
    buf.push(op as u8, GFP_KERNEL)?;
    buf.push((op >> 8) as u8, GFP_KERNEL)?;
    let plen = param_len as u16;
    buf.push(plen as u8, GFP_KERNEL)?;
    buf.push((plen >> 8) as u8, GFP_KERNEL)?;
    for &b in &params[..param_len] {
        buf.push(b, GFP_KERNEL)?;
    }
    Ok(buf)
}

/// Build a DLI async unicast data packet for USB bulk OUT.
///
/// Wire format:
///
///     Byte 0:      0xA3 (DliPacketType::AsyncUnicast)
///     Bytes 1-2:   link_id_seg field (LE16)
///                  [15:4] = link_id (12 bits)
///                  [3:2]  = segmentation (2 bits)
///                  [1]    = reserved
///                  [0]    = priority
///     Bytes 3-4:   data_len field (LE16)
///                  [8:0]  = payload length (9 bits)
///                  [15:9] = reserved
///     Bytes 5..N:  payload
pub fn build_async_data_packet(
    link_id: u16,
    seg: u8,
    priority: bool,
    data: &[u8],
) -> Result<KVec<u8>> {
    let payload_len = data.len().min(DLI_DATA_PAYLOAD_MAX);
    let total = 5 + payload_len;
    let mut buf = KVec::with_capacity(total, GFP_KERNEL)?;

    buf.push(DliPacketType::AsyncUnicast as u8, GFP_KERNEL)?;

    let link_id_seg: u16 =
        ((link_id & 0x0FFF) << 4) | (u16::from(seg & 0x03) << 2) | u16::from(priority);
    buf.push(link_id_seg as u8, GFP_KERNEL)?;
    buf.push((link_id_seg >> 8) as u8, GFP_KERNEL)?;

    let data_len_field: u16 = (payload_len as u16) & 0x01FF;
    buf.push(data_len_field as u8, GFP_KERNEL)?;
    buf.push((data_len_field >> 8) as u8, GFP_KERNEL)?;

    for &b in &data[..payload_len] {
        buf.push(b, GFP_KERNEL)?;
    }
    Ok(buf)
}

// ---------------------------------------------------------------------------
// DLI USB packet parsers
// ---------------------------------------------------------------------------

/// Parsed DLI event from the interrupt IN endpoint.
pub struct DliUsbEvent {
    /// Raw event code (T/XS 10003-2025).
    pub event_code: u16,
    /// Event parameters.
    pub params: KVec<u8>,
}

/// Parse a raw DLI event received on the interrupt IN endpoint.
///
/// Wire format per T/XS 10003-2025 §7.3 (no packet type byte — implicit
/// from endpoint):
///
///     Bytes 0-1:   event_code (LE16)
///     Bytes 2-3:   parameter length (LE16)
///     Bytes 4..N:  parameters
pub fn parse_event_packet(data: &[u8]) -> Result<DliUsbEvent> {
    if data.len() < 4 {
        return Err(EINVAL);
    }
    let event_code = u16::from_le_bytes([data[0], data[1]]);
    let param_len = u16::from_le_bytes([data[2], data[3]]) as usize;

    // T/XS 10003-2025: controller must support at least 255 bytes.
    // Cap at DLI_PARAM_MAX to prevent excessive allocation from
    // malformed hardware responses.
    if param_len > super::sle_uapi::DLI_PARAM_MAX {
        return Err(EINVAL);
    }

    if data.len() < 4 + param_len {
        return Err(EINVAL);
    }

    let mut params = KVec::with_capacity(param_len, GFP_ATOMIC)?;
    for &b in &data[4..4 + param_len] {
        params.push(b, GFP_ATOMIC)?;
    }

    Ok(DliUsbEvent { event_code, params })
}

/// Parsed async data header.
pub struct DliAsyncHeader {
    /// 12-bit link identifier.
    pub link_id: u16,
    /// 2-bit segmentation indicator (0=complete, 1=first, 2=cont, 3=last).
    pub seg: u8,
    /// Priority flag.
    pub priority: bool,
    /// Payload length (9 bits).
    pub data_len: u16,
}

/// Extract discovery_level from raw advertising TLV data.
///
/// Scans the TLV entries (type 0x01 = discovery level per T/XS 20001)
/// and returns the 3-bit discovery level value. Returns 0 if not found.
fn extract_discovery_level(data: &[u8]) -> u8 {
    let mut i = 0;
    while i + 1 < data.len() {
        let len = data[i] as usize;
        if len == 0 || i + 1 + len > data.len() {
            break;
        }
        let typ = data[i + 1];
        if typ == 0x01 && len >= 2 {
            return data[i + 2] & 0x07;
        }
        i += 1 + len;
    }
    0
}

/// Parse the async/sync data header from a bulk IN packet.
///
/// Expects the raw packet starting with the type byte already stripped
/// (or starting at byte 1 of the full packet).
pub fn parse_async_data_header(data: &[u8]) -> Result<DliAsyncHeader> {
    if data.len() < 4 {
        return Err(EINVAL);
    }

    let link_id_seg = u16::from_le_bytes([data[0], data[1]]);
    let data_len_field = u16::from_le_bytes([data[2], data[3]]);

    Ok(DliAsyncHeader {
        link_id: (link_id_seg >> 4) & 0x0FFF,
        seg: ((link_id_seg >> 2) & 0x03) as u8,
        priority: (link_id_seg & 1) != 0,
        data_len: data_len_field & 0x01FF,
    })
}

/// Convert a raw event code and parameters into an [`SleEvent`].
pub fn event_to_sle(evt: &DliUsbEvent) -> Option<SleEvent> {
    match evt.event_code {
        // T/XS 10003-2025 9.1.2: opcode(2), credits(1), return params.
        // Nonzero-opcode return params start with that command's status byte.
        0x0002 => {
            if evt.params.len() < 3 {
                return None;
            }
            let opcode_raw = u16::from_le_bytes([evt.params[0], evt.params[1]]);
            let command_credits = evt.params[2];
            if opcode_raw == 0 {
                if evt.params.len() != 3 {
                    return None;
                }
                return Some(SleEvent::CommandCredits {
                    credits: command_credits,
                });
            }
            if evt.params.len() < 4 {
                return None;
            }
            let mut data = KVec::new();
            data.extend_from_slice(&evt.params[4..], GFP_ATOMIC).ok()?;
            Some(SleEvent::CommandComplete {
                opcode: super::sle_dli::sle_opcode_from_u16(opcode_raw)?,
                command_credits,
                status: raw_to_status(evt.params[3]),
                data,
            })
        }
        // T/XS 10003-2025 9.1.1: opcode(2), credits(1), status(1).
        0x0001 => {
            if evt.params.len() != 4 {
                return None;
            }
            let opcode_raw = u16::from_le_bytes([evt.params[0], evt.params[1]]);
            let command_credits = evt.params[2];
            if opcode_raw == 0 {
                return Some(SleEvent::CommandCredits {
                    credits: command_credits,
                });
            }
            Some(SleEvent::CommandStatus {
                opcode: super::sle_dli::sle_opcode_from_u16(opcode_raw)?,
                command_credits,
                status: raw_to_status(evt.params[3]),
            })
        }
        // ConnEstablished (0x0015): [status:1] [handle:2] [addr:6]
        0x0015 => {
            if evt.params.len() < 9 {
                return None;
            }
            let status_raw = evt.params[0];
            let handle = u16::from_le_bytes([evt.params[1], evt.params[2]]);
            let mut addr = [0u8; 6];
            addr.copy_from_slice(&evt.params[3..9]);
            Some(SleEvent::ConnComplete {
                handle,
                addr,
                status: raw_to_status(status_raw),
            })
        }
        // DisconnectDone (0x0005): [handle:2] [reason:1]
        0x0005 => {
            if evt.params.len() < 3 {
                return None;
            }
            let handle = u16::from_le_bytes([evt.params[0], evt.params[1]]);
            let reason = evt.params[2];
            Some(SleEvent::Disconnected { handle, reason })
        }
        // BroadcastReport (0x001A): [addr:6] [rssi:1] [data_len:1] [data:N]
        0x001A => {
            if evt.params.len() < 8 {
                return None;
            }
            let mut addr = [0u8; 6];
            addr.copy_from_slice(&evt.params[..6]);
            let rssi = evt.params[6] as i8;
            let data_len = evt.params[7] as usize;
            let data_end = 8 + data_len;
            if data_end > evt.params.len() {
                return None;
            }
            let mut data = KVec::new();
            for &b in &evt.params[8..data_end] {
                data.push(b, GFP_ATOMIC).ok()?;
            }
            let discovery_level = extract_discovery_level(data.as_slice());
            Some(SleEvent::AdvReport {
                addr,
                rssi,
                discovery_level,
                data,
            })
        }
        // HwError (0x000A): [code:1]
        0x000A => {
            if evt.params.is_empty() {
                return None;
            }
            Some(SleEvent::HardwareError {
                code: evt.params[0],
            })
        }
        // EncStatusChange (0x0011): [handle:2] [enabled:1]
        0x0011 => {
            if evt.params.len() < 3 {
                return None;
            }
            let handle = u16::from_le_bytes([evt.params[0], evt.params[1]]);
            Some(SleEvent::EncryptionChanged {
                handle,
                enabled: evt.params[2] != 0,
            })
        }
        // PairRequest (0x001D): [addr:6] [method:1]
        0x001D => {
            if evt.params.len() < 7 {
                return None;
            }
            let mut addr = [0u8; 6];
            addr.copy_from_slice(&evt.params[..6]);
            Some(SleEvent::PairRequest {
                addr,
                method: evt.params[6],
            })
        }
        // PairInfoExchange (0x001E): [handle:2][io_cap:1][oob:1][auth_req:1]
        //   [max_key:1][sec_dist:1][crypto_cap:4][psk:1]
        0x001E => {
            if evt.params.len() < 12 {
                return None;
            }
            let handle = u16::from_le_bytes([evt.params[0], evt.params[1]]);
            let mut crypto_cap = [0u8; 4];
            crypto_cap.copy_from_slice(&evt.params[7..11]);
            Some(SleEvent::PairInfoExchange {
                handle,
                io_cap: evt.params[2],
                oob_flag: evt.params[3],
                auth_req: evt.params[4],
                max_key_len: evt.params[5],
                sec_dist: evt.params[6],
                psk_ind: evt.params[11],
                crypto_cap,
            })
        }
        // PairInfoReport (0x001F): same layout as 0x001E
        0x001F => {
            if evt.params.len() < 12 {
                return None;
            }
            let handle = u16::from_le_bytes([evt.params[0], evt.params[1]]);
            let mut crypto_cap = [0u8; 4];
            crypto_cap.copy_from_slice(&evt.params[7..11]);
            Some(SleEvent::PairInfoReport {
                handle,
                io_cap: evt.params[2],
                oob_flag: evt.params[3],
                auth_req: evt.params[4],
                max_key_len: evt.params[5],
                sec_dist: evt.params[6],
                psk_ind: evt.params[11],
                crypto_cap,
            })
        }
        // PairOptionReport (0x0020): [handle:2][key_len:1][auth_method:1]
        //   [crypto_alg:4][pubkey:N]
        0x0020 => {
            if evt.params.len() < 8 {
                return None;
            }
            let handle = u16::from_le_bytes([evt.params[0], evt.params[1]]);
            let key_len = evt.params[2];
            let auth_method = evt.params[3];
            let mut crypto_alg = [0u8; 4];
            crypto_alg.copy_from_slice(&evt.params[4..8]);
            let mut public_key = KVec::new();
            for &b in &evt.params[8..] {
                public_key.push(b, GFP_ATOMIC).ok()?;
            }
            Some(SleEvent::PairOptionReport {
                handle,
                key_len,
                auth_method,
                crypto_alg,
                public_key,
            })
        }
        // RemotePublicKey (0x0021): [handle:2][pubkey:N]
        0x0021 => {
            if evt.params.len() < 2 {
                return None;
            }
            let handle = u16::from_le_bytes([evt.params[0], evt.params[1]]);
            let mut public_key = KVec::new();
            for &b in &evt.params[2..] {
                public_key.push(b, GFP_ATOMIC).ok()?;
            }
            Some(SleEvent::PeerPublicKey { handle, public_key })
        }
        // PairExtData (0x0022): [handle:2][ext_x:N/2][ext_y:N/2]
        0x0022 => {
            if evt.params.len() < 2 {
                return None;
            }
            let handle = u16::from_le_bytes([evt.params[0], evt.params[1]]);
            let rest = &evt.params[2..];
            let half = rest.len() / 2;
            let mut ext_pubkey_x = KVec::new();
            for &b in &rest[..half] {
                ext_pubkey_x.push(b, GFP_ATOMIC).ok()?;
            }
            let mut ext_pubkey_y = KVec::new();
            for &b in &rest[half..] {
                ext_pubkey_y.push(b, GFP_ATOMIC).ok()?;
            }
            Some(SleEvent::PairExtData {
                handle,
                ext_pubkey_x,
                ext_pubkey_y,
            })
        }
        // KeypressNotify (0x0023): [handle:2][action:4]
        0x0023 => {
            if evt.params.len() < 6 {
                return None;
            }
            let handle = u16::from_le_bytes([evt.params[0], evt.params[1]]);
            let mut action = [0u8; 4];
            action.copy_from_slice(&evt.params[2..6]);
            Some(SleEvent::KeypressNotify { handle, action })
        }
        // PairRandom (0x0024): [handle:2][random:16]
        0x0024 => {
            if evt.params.len() < 18 {
                return None;
            }
            let handle = u16::from_le_bytes([evt.params[0], evt.params[1]]);
            let mut random = [0u8; 16];
            random.copy_from_slice(&evt.params[2..18]);
            Some(SleEvent::PairRandom { handle, random })
        }
        // PairConfirm (0x0025): [handle:2][confirm:16]
        0x0025 => {
            if evt.params.len() < 18 {
                return None;
            }
            let handle = u16::from_le_bytes([evt.params[0], evt.params[1]]);
            let mut confirm = [0u8; 16];
            confirm.copy_from_slice(&evt.params[2..18]);
            Some(SleEvent::PairConfirm { handle, confirm })
        }
        // DHKeyCheck (0x0026): [handle:2][dhkey_check:16]
        0x0026 => {
            if evt.params.len() < 18 {
                return None;
            }
            let handle = u16::from_le_bytes([evt.params[0], evt.params[1]]);
            let mut dhkey_check = [0u8; 16];
            dhkey_check.copy_from_slice(&evt.params[2..18]);
            Some(SleEvent::DHKeyCheck {
                handle,
                dhkey_check,
            })
        }
        // PairFailure (0x0027): [handle:2][reason:1]
        0x0027 => {
            if evt.params.len() < 3 {
                return None;
            }
            let handle = u16::from_le_bytes([evt.params[0], evt.params[1]]);
            Some(SleEvent::PairFailure {
                handle,
                reason: evt.params[2],
            })
        }
        // PeerFeatures (0x0016): [handle:2] [status:1] [pad:1] [features:10]
        0x0016 => {
            if evt.params.len() < 14 {
                return None;
            }
            let handle = u16::from_le_bytes([evt.params[0], evt.params[1]]);
            let status = evt.params[2];
            let mut features = [0u8; 10];
            features.copy_from_slice(&evt.params[4..14]);
            Some(SleEvent::ReadPeerFeatures {
                handle,
                status,
                features,
            })
        }
        // PeerVersion (0x0017): [handle:2] [status:1] [version:1] [mfr:2] [subver:2]
        0x0017 => {
            if evt.params.len() < 8 {
                return None;
            }
            let handle = u16::from_le_bytes([evt.params[0], evt.params[1]]);
            let status = evt.params[2];
            let version = evt.params[3];
            let manufacturer = u16::from_le_bytes([evt.params[4], evt.params[5]]);
            let subversion = u16::from_le_bytes([evt.params[6], evt.params[7]]);
            Some(SleEvent::ReadPeerVersion {
                handle,
                status,
                version,
                manufacturer,
                subversion,
            })
        }
        // PhyParamUpdate (0x0018): [handle:2] [mcs_index:1] [bandwidth:1]
        0x0018 => {
            if evt.params.len() < 4 {
                return None;
            }
            let handle = u16::from_le_bytes([evt.params[0], evt.params[1]]);
            Some(SleEvent::PhyUpdate {
                handle,
                mcs_index: evt.params[2],
                bandwidth_mhz: evt.params[3],
            })
        }
        // ConnParamUpdate (0x0019): [handle:2] [interval:2] [latency:2] [timeout:2]
        0x0019 => {
            if evt.params.len() < 8 {
                return None;
            }
            let handle = u16::from_le_bytes([evt.params[0], evt.params[1]]);
            let interval = u16::from_le_bytes([evt.params[2], evt.params[3]]);
            let latency = u16::from_le_bytes([evt.params[4], evt.params[5]]);
            let timeout = u16::from_le_bytes([evt.params[6], evt.params[7]]);
            Some(SleEvent::ConnParamUpdate {
                handle,
                interval,
                latency,
                timeout,
            })
        }
        // DataLenChange (0x0003): [handle:2] [max_tx:2] [max_rx:2]
        0x0003 => {
            if evt.params.len() < 6 {
                return None;
            }
            let handle = u16::from_le_bytes([evt.params[0], evt.params[1]]);
            let max_tx = u16::from_le_bytes([evt.params[2], evt.params[3]]);
            let max_rx = u16::from_le_bytes([evt.params[4], evt.params[5]]);
            Some(SleEvent::DataLenChange {
                handle,
                max_tx_octets: max_tx,
                max_rx_octets: max_rx,
            })
        }
        // PeerConnParamReq (0x0007): [handle:2] [imin:2] [imax:2] [lat:2] [tmo:2]
        0x0007 => {
            if evt.params.len() < 10 {
                return None;
            }
            let handle = u16::from_le_bytes([evt.params[0], evt.params[1]]);
            Some(SleEvent::PeerConnParamReq {
                handle,
                interval_min: u16::from_le_bytes([evt.params[2], evt.params[3]]),
                interval_max: u16::from_le_bytes([evt.params[4], evt.params[5]]),
                latency: u16::from_le_bytes([evt.params[6], evt.params[7]]),
                timeout: u16::from_le_bytes([evt.params[8], evt.params[9]]),
            })
        }
        // PowerChangeReport (0x0008): [handle:2] [reason:1] [frame:1] [bw:1]
        //   [pilot:1] [tx_power:1] [level:1] [offset:1]
        0x0008 => {
            if evt.params.len() < 9 {
                return None;
            }
            let handle = u16::from_le_bytes([evt.params[0], evt.params[1]]);
            Some(SleEvent::PowerChangeReport {
                handle,
                reason: evt.params[2],
                frame_type: evt.params[3],
                bandwidth: evt.params[4],
                pilot_density: evt.params[5],
                tx_power: evt.params[6] as i8,
                power_level: evt.params[7],
                offset: evt.params[8] as i8,
            })
        }
        // NumCompletedPackets (0x0009): [handle:2] [num:1]
        0x0009 => {
            if evt.params.len() < 3 {
                return None;
            }
            let handle = u16::from_le_bytes([evt.params[0], evt.params[1]]);
            Some(SleEvent::NumCompletedPackets {
                handle,
                num_completed: evt.params[2],
            })
        }
        // DataBufOverflow (0x000B): [link_type:1]
        0x000B => {
            if evt.params.is_empty() {
                return None;
            }
            Some(SleEvent::DataBufOverflow {
                link_type: evt.params[0],
            })
        }
        // EncParamReq (0x000E): [handle:2]
        0x000E => {
            if evt.params.len() < 2 {
                return None;
            }
            let handle = u16::from_le_bytes([evt.params[0], evt.params[1]]);
            Some(SleEvent::EncryptionParamReq { handle })
        }
        // ReadPeerPower (0x001B): [handle:2] [status:1] [frame:1] [bw:1]
        //   [pilot:1] [tx_power:1] [level:1]
        0x001B => {
            if evt.params.len() < 8 {
                return None;
            }
            let handle = u16::from_le_bytes([evt.params[0], evt.params[1]]);
            Some(SleEvent::ReadPeerPower {
                handle,
                status: evt.params[2],
                frame_type: evt.params[3],
                bandwidth: evt.params[4],
                pilot_density: evt.params[5],
                tx_power: evt.params[6] as i8,
                power_level: evt.params[7],
            })
        }
        // NbfhMeasInfo (0x0028): [handle:2][meas_type:2][status:1][config_index:1]
        0x0028 => {
            if evt.params.len() < 6 {
                return None;
            }
            let handle = u16::from_le_bytes([evt.params[0], evt.params[1]]);
            let meas_type = u16::from_le_bytes([evt.params[2], evt.params[3]]);
            Some(SleEvent::NarrowbandMeasInfo {
                handle,
                meas_type,
                status: evt.params[4],
                config_index: evt.params[5],
            })
        }
        // NbfhMeasStateChange (0x0029): [status:1][config_index:1][meas_state:1]
        0x0029 => {
            if evt.params.len() < 3 {
                return None;
            }
            Some(SleEvent::NarrowbandMeasStateChange {
                status: evt.params[0],
                config_index: evt.params[1],
                meas_state: evt.params[2],
            })
        }
        // NbfhMeasParams (0x002A): [handle:2][status:1][config_index:1]
        0x002A => {
            if evt.params.len() < 4 {
                return None;
            }
            let handle = u16::from_le_bytes([evt.params[0], evt.params[1]]);
            Some(SleEvent::NarrowbandMeasParamReport {
                handle,
                status: evt.params[2],
                config_index: evt.params[3],
            })
        }
        // LocalNbfhMeasCap (0x002B): [status:1][antenna_count:1][signal_cap:4][report_cap:4]
        0x002B => {
            if evt.params.len() < 10 {
                return None;
            }
            let mut signal_cap = [0u8; 4];
            signal_cap.copy_from_slice(&evt.params[2..6]);
            let mut report_cap = [0u8; 4];
            report_cap.copy_from_slice(&evt.params[6..10]);
            Some(SleEvent::LocalNarrowbandMeasCap {
                status: evt.params[0],
                antenna_count: evt.params[1],
                signal_cap,
                report_cap,
            })
        }
        // RemoteNbfhMeasCap (0x002C): [handle:2][status:1][antenna_count:1][signal_cap:4][report_cap:4]
        0x002C => {
            if evt.params.len() < 12 {
                return None;
            }
            let handle = u16::from_le_bytes([evt.params[0], evt.params[1]]);
            let mut signal_cap = [0u8; 4];
            signal_cap.copy_from_slice(&evt.params[4..8]);
            let mut report_cap = [0u8; 4];
            report_cap.copy_from_slice(&evt.params[8..12]);
            Some(SleEvent::PeerNarrowbandMeasCap {
                handle,
                status: evt.params[2],
                antenna_count: evt.params[3],
                signal_cap,
                report_cap,
            })
        }
        // MeasStateChange (0x002D): [source:2][status:1][instance_handle:1][instance_state:1]
        0x002D => {
            if evt.params.len() < 5 {
                return None;
            }
            let source = u16::from_le_bytes([evt.params[0], evt.params[1]]);
            Some(SleEvent::MeasStateChange {
                source,
                status: evt.params[2],
                instance_handle: evt.params[3],
                instance_state: evt.params[4],
            })
        }
        // MeasReport (0x002E): [source:2][meas_source:2][seq:2][instance_handle:1][meas_count:1]
        0x002E => {
            if evt.params.len() < 8 {
                return None;
            }
            let source = u16::from_le_bytes([evt.params[0], evt.params[1]]);
            let meas_source = u16::from_le_bytes([evt.params[2], evt.params[3]]);
            let seq = u16::from_le_bytes([evt.params[4], evt.params[5]]);
            Some(SleEvent::MeasQuantityReport {
                source,
                meas_source,
                seq,
                instance_handle: evt.params[6],
                meas_count: evt.params[7],
            })
        }
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Raw value conversion helpers
// ---------------------------------------------------------------------------

fn raw_to_status(raw: u8) -> SleStatus {
    match raw {
        0x00 => SleStatus::Success,
        0x01 => SleStatus::UnknownCommand,
        0x02 => SleStatus::InvalidParameters,
        0x03 => SleStatus::HardwareFailure,
        0x04 => SleStatus::ResourceExhausted,
        0x05 => SleStatus::NotConnected,
        0x06 => SleStatus::AlreadyActive,
        0x07 => SleStatus::PermissionDenied,
        0x08 => SleStatus::Timeout,
        _ => SleStatus::HardwareFailure,
    }
}

// ---------------------------------------------------------------------------
// USB controller (SleController implementation)
// ---------------------------------------------------------------------------

/// USB-attached SLE controller state.
///
/// Constructed during USB probe when a matching device is detected.
/// Uses bulk and interrupt transfers to communicate with the radio
/// controller firmware over the DLI protocol.
///
/// Actual USB I/O is delegated to the C FFI layer which maintains a
/// per-device table mapping `dev_id` to `usb_device` and URB contexts.
pub struct UsbController {
    addr: [u8; 6],
    opened: bool,
    /// Device ID in the sle_dev registry. Used to index the C-side
    /// USB device table for actual I/O.
    dev_id: u16,
    identity: super::sle_dev::DeviceIdentity,
}

impl UsbController {
    /// Create a new USB controller handle.
    ///
    /// `addr` is the 6-byte SLE MAC address read from the controller
    /// during probe via the ReadLocalAddr (0x0404) command.
    /// `dev_id` is the device ID returned by `sle_attach_device`.
    pub fn new(addr: [u8; 6], identity: super::sle_dev::DeviceIdentity) -> Self {
        Self {
            addr,
            opened: false,
            dev_id: identity.id,
            identity,
        }
    }

    /// Only the owner's TX worker may call this transport operation after
    /// reserving its command slot and a controller credit.
    pub(crate) fn send_command_transport(&self, opcode: u16, params: &[u8]) -> Result {
        // SAFETY: worker retains its registration owner; removal drains the
        // worker before unregistering/freeing the C transport. Data is live.
        let ret = unsafe {
            sle_usb_dev_send_cmd(
                i32::from(self.dev_id),
                opcode,
                params.as_ptr(),
                params.len() as i32,
            )
        };
        if ret < 0 {
            Err(Error::from_errno(ret))
        } else {
            Ok(())
        }
    }
}

impl SleController for UsbController {
    fn info(&self) -> SleControllerInfo {
        let mut info = SleControllerInfo::default();
        let name = b"sparklink-usb";
        info.name[..name.len()].copy_from_slice(name);
        info.bus = SleBus::Usb;
        info.addr = self.addr;
        info.fw_version = 0; // read from device during open
        info.features = (SleFeature::Encryption as u64)
            | (SleFeature::DataLenUpdate as u64)
            | (SleFeature::Mcs4 as u64)
            | (SleFeature::Bw2m as u64)
            | (SleFeature::Pilot8to1 as u64)
            | (SleFeature::Crc32 as u64);
        info.max_pdu_payload = 255;
        info.max_connections = 8;
        info.max_mtu = 512;
        info.max_mps = 255;
        info.transport_modes =
            SLE_TRANSPORT_UNRELIABLE | SLE_TRANSPORT_RELIABLE | SLE_TRANSPORT_FRAGMENTED;
        info.measurement_cap = SLE_MEAS_RSSI | SLE_MEAS_PATH_LOSS;
        info.security_cap = SLE_SEC_AES_CCM | SLE_SEC_ECDH_P256 | SLE_SEC_SC;
        info
    }

    fn open(&self) -> Result {
        // Register event listener via the C device table.
        // SAFETY: dev_id was validated during probe.
        let ret = unsafe { sle_usb_dev_start_evt(i32::from(self.dev_id)) };
        if ret < 0 {
            pr_warn!("sparklink-usb: event listener start failed: {}\n", ret);
            return Err(Error::from_errno(ret));
        }
        // Start bulk IN listener for async data (T/XS 10003-2025 §7.4).
        let ret = unsafe { sle_usb_dev_start_data(i32::from(self.dev_id)) };
        if ret < 0 {
            pr_warn!("sparklink-usb: data listener start failed: {}\n", ret);
            // SAFETY: no binding can survive failed open; join its first listener.
            unsafe { sle_usb_dev_stop_evt(i32::from(self.dev_id)) };
            return Err(Error::from_errno(ret));
        }
        pr_info!("sparklink-usb: open dev_id={}\n", self.dev_id);
        Ok(())
    }

    fn close(&self) {
        // SAFETY: dev_id was validated during probe; stop is idempotent.
        unsafe { sle_usb_dev_stop_evt(i32::from(self.dev_id)) };
        unsafe { sle_usb_dev_stop_data(i32::from(self.dev_id)) };
        pr_info!("sparklink-usb: close dev_id={}\n", self.dev_id);
    }

    fn send_command(&self, opcode: SleOpcode, params: &[u8]) -> Result {
        let owner = ingress_owner(self.identity).ok_or(ENODEV)?;
        let stopping = owner.schedule_gate.lock();
        if *stopping {
            return Err(ENODEV);
        }
        owner.host.lock().enqueue(opcode as u16, params, 0)?;
        drop(stopping);
        owner.kick_commands();
        Ok(())
    }

    fn send_data(&self, handle: u16, data: &[u8]) -> Result {
        // SAFETY: dev_id is valid, data pointer and length are consistent.
        let ret = unsafe {
            sle_usb_dev_send_data(
                i32::from(self.dev_id),
                handle,
                data.as_ptr(),
                data.len() as i32,
            )
        };
        if ret < 0 {
            pr_debug!("sparklink-usb: data tx handle={} failed: {}\n", handle, ret);
            return Err(Error::from_errno(ret));
        }
        pr_debug!(
            "sparklink-usb: data tx handle={} ({} bytes)\n",
            handle,
            data.len()
        );
        Ok(())
    }

    fn poll_event(&self) -> Option<SleEvent> {
        // USB events are drained from the owner's ingress with device
        // routing in the owner RX worker, without a shared ingress ring.
        None
    }

    fn reset(&self) -> Result {
        self.send_command(SleOpcode::Reset, &[])
    }
}

// ---------------------------------------------------------------------------
// USB driver integration — hardware discovery
// ---------------------------------------------------------------------------

/// Counter for discovered USB SLE devices.
static USB_DEV_COUNT: AtomicU32 = AtomicU32::new(0);

/// Returns the number of currently attached USB SLE controllers.
pub fn usb_device_count() -> u32 {
    USB_DEV_COUNT.load(Ordering::Relaxed)
}

kernel::usb_device_table!(
    SLE_USB_IDS,
    MODULE_SLE_USB_TABLE,
    <SleUsbDriver as usb::Driver>::IdInfo,
    [
        // QEMU usb-sle-dli virtual controller (VID:PID 0x1234:0x5678)
        (usb::DeviceId::from_id(0x1234, 0x5678), ()),
        // Match by interface class/subclass/protocol:
        //   Wireless Controller (0xE0) / RF Controller (0x01) / SparkLink DLI (0x05)
        (
            usb::DeviceId::from_interface_info(SLE_USB_CLASS, SLE_USB_SUBCLASS, SLE_USB_PROTOCOL,),
            (),
        ),
    ]
);

/// Per-device state stored as driver data during probe.
#[pin_data]
pub(crate) struct SleUsbDriver {
    /// Allocated device id from the SleDev registry (u16::MAX = not attached).
    dev_id: u16,
}

/// Prepare a binding in process context; failed preparation is not a device.
fn probe_usb_device(interface: &usb::Interface<device::Core>) -> Result<u16> {
    pr_info!("sparklink-usb: SLE controller discovered\n");

    // Build attach info for the transport framework.
    // In a real driver this would read the MAC address and firmware
    // version from the device via control transfers.
    let count = USB_DEV_COUNT.load(Ordering::Relaxed) + 1;
    let mut addr = [0x5E, 0x00, 0x00, 0x00, 0x01, count as u8];
    let attach = SleAttachInfo::new(SleProtoId::UsbBulk, addr);

    let dev_id = super::sle_attach_device(&attach)?;
    let mut fw_version: u32 = 0;
    let result = (|| -> Result {
        pr_info!("sparklink-usb: attached as sle{}\n", dev_id);

        // Register the USB interface in the C-side device table so
        // send_command / send_data can perform actual I/O.
        //
        // The interface pointer survives as long as the driver is
        // bound (guaranteed by USB core).
        let intf_ptr = core::ptr::from_ref::<usb::Interface<device::Core>>(interface)
            as *mut core::ffi::c_void;
        // SAFETY: dev_id is valid; intf_ptr points to a live USB
        // interface that outlives this driver binding.
        let generation = super::registration_identity(dev_id)
            .ok_or(ENODEV)?
            .generation;
        let reg_ret = unsafe { sle_usb_dev_register(i32::from(dev_id), intf_ptr, generation) };
        if reg_ret < 0 {
            return Err(Error::from_errno(reg_ret));
        } else {
            // Run the init sequence: Reset → ReadLocalVersion → ReadMacAddr.
            // Require matching successful replies; a failed bootstrap
            // cannot publish a usable placeholder Runtime.
            // SAFETY: dev_id is valid; init sequence is idempotent.
            let init_ret = unsafe { sle_usb_dev_init_controller(i32::from(dev_id)) };
            if init_ret < 0 {
                return Err(Error::from_errno(init_ret));
            }
            if init_ret == 0 {
                // Read back real MAC address and firmware version
                // from the C device table and update the device info.
                let mut real_mac = [0u8; 6];
                // SAFETY: dev_id is valid, real_mac buffer is 6 bytes.
                let mac_ret =
                    unsafe { sle_usb_dev_get_mac(i32::from(dev_id), real_mac.as_mut_ptr()) };
                if mac_ret == 0 && real_mac != [0u8; 6] {
                    // Use real MAC from controller
                    addr = real_mac;
                }
                // SAFETY: dev_id is valid.
                fw_version = unsafe { sle_usb_dev_get_fw_version(i32::from(dev_id)) };
                pr_info!(
                        "sparklink-usb: init OK fw=0x{:08x} mac={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}\n",
                        fw_version,
                        addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]
                    );

                // Attempt firmware download (non-fatal if firmware
                // blob is absent or already programmed).
                let fw_name = kernel::c_str!("sparklink/sle_usb_v1.bin");
                let kern_dev: &kernel::device::Device<kernel::device::Core> = interface.as_ref();
                match super::sle_fw::load_usb_firmware(dev_id, fw_name, kern_dev) {
                    Ok(r) => pr_info!("sparklink-usb: firmware loaded ({} bytes)\n", r.size),
                    Err(_) => pr_debug!("sparklink-usb: firmware load skipped\n"),
                }
            }
        }

        // Switch the subsystem controller backend to USB and sync
        // the device registry with real hardware info.
        // SAFETY: mandatory bootstrap completed on this still-live binding.
        let credits = unsafe { sle_usb_dev_get_command_credits(i32::from(dev_id)) };
        super::sle_switch_controller_usb(dev_id, addr, fw_version, credits)?;
        Ok(())
    })();
    if let Err(error) = result {
        super::sle_quiesce_device(dev_id);
        // SAFETY: probe owns this index; joins URBs before releasing it.
        unsafe { sle_usb_dev_unregister(i32::from(dev_id)) };
        super::sle_detach_device(dev_id);
        return Err(error);
    }
    USB_DEV_COUNT.fetch_add(1, Ordering::Relaxed);

    Ok(dev_id)
}

impl usb::Driver for SleUsbDriver {
    type IdInfo = ();
    const ID_TABLE: usb::IdTable<Self::IdInfo> = &SLE_USB_IDS;

    fn probe(
        interface: &usb::Interface<device::Core>,
        _id: &usb::DeviceId,
        _info: &Self::IdInfo,
    ) -> impl PinInit<Self, Error> {
        try_pin_init!(Self {
            dev_id: probe_usb_device(interface)?
        })
    }

    fn disconnect(_interface: &usb::Interface<device::Core>, data: Pin<&Self>) {
        pr_info!("sparklink-usb: SLE controller removed\n");
        USB_DEV_COUNT.fetch_sub(1, Ordering::Relaxed);

        let dev_id = data.dev_id;
        if dev_id != u16::MAX {
            // Reject new protocol access and join workers while C resources
            // are still live. Keep the registry index reserved through free.
            super::sle_quiesce_device(dev_id);
            // Stop URBs and unregister from C device table.
            // SAFETY: dev_id is valid; unregister kills URBs and frees C resources.
            unsafe { sle_usb_dev_unregister(i32::from(dev_id)) };
            super::sle_detach_device(dev_id);
            pr_info!("sparklink-usb: detached sle{}\n", dev_id);
        }
    }

    fn suspend(
        _interface: &usb::Interface<device::Core>,
        data: Pin<&Self>,
        _event: kernel::ffi::c_int,
    ) -> Result {
        let dev_id = data.dev_id;
        if dev_id == u16::MAX {
            return Ok(());
        }
        // SAFETY: dev_id is valid; suspend stops pending URBs.
        let ret = unsafe { sle_usb_dev_suspend(i32::from(dev_id)) };
        if ret < 0 {
            pr_err!("sparklink-usb: suspend sle{} failed: {}\n", dev_id, ret);
            return Err(Error::from_errno(ret));
        }
        super::sle_suspend_device(dev_id);
        pr_info!("sparklink-usb: sle{} suspended\n", dev_id);
        Ok(())
    }

    fn resume(_interface: &usb::Interface<device::Core>, data: Pin<&Self>) -> Result {
        let dev_id = data.dev_id;
        if dev_id == u16::MAX {
            return Ok(());
        }
        // SAFETY: dev_id is valid; resume restarts URB submissions.
        let ret = unsafe { sle_usb_dev_resume(i32::from(dev_id)) };
        if ret < 0 {
            pr_err!("sparklink-usb: resume sle{} failed: {}\n", dev_id, ret);
            return Err(Error::from_errno(ret));
        }
        super::sle_resume_device(dev_id);
        pr_info!("sparklink-usb: sle{} resumed\n", dev_id);
        Ok(())
    }
}

/// Type alias for USB driver registration used by the core module.
pub(crate) type UsbRegistration = kernel::driver::Registration<usb::Adapter<SleUsbDriver>>;
