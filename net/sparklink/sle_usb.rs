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

use kernel::alloc::KVec;
use kernel::device;
use kernel::prelude::*;
use kernel::usb;

use core::sync::atomic::{AtomicU32, Ordering};

use super::sle_dli::{
    SleBus, SleController, SleControllerInfo, SleEvent, SleOpcode, SleStatus,
};
use super::sle_dev::DeviceIdentity;

use super::sle_ingress::{enqueue_rx, ingress_owner};

// ---------------------------------------------------------------------------
// USB FFI — C wrapper functions from sle_usb_ffi.c
// ---------------------------------------------------------------------------

/// Independent C allocation; immutable identity and retained USB references.
#[repr(C)]
pub(crate) struct UsbDeviceOpaque { _opaque: [u8; 0] }

/// Internal C snapshot layout, copied once after complete bootstrap, before
/// Runtime publication. Every field is queried; these are not policy limits.
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct UsbCapabilities {
    command_max: u16,
    acb_length: u16,
    icb_length: u16,
    acb_count: u8,
    icb_count: u8,
    features: [u8; 10],
}
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct UsbMetadata {
    capabilities: UsbCapabilities,
    version: [u8; 5],
    address: [u8; 6],
    command_credits: u8,
}
const _: () = assert!(core::mem::size_of::<UsbCapabilities>() == 18);
const _: () = assert!(core::mem::size_of::<UsbMetadata>() == 30);
const _: () = assert!(core::mem::align_of::<UsbMetadata>() == 2);
const _: () = assert!(core::mem::offset_of!(UsbMetadata, version) == 18);
const _: () = assert!(core::mem::offset_of!(UsbMetadata, address) == 23);
const _: () = assert!(core::mem::offset_of!(UsbMetadata, command_credits) == 29);

pub(crate) struct UsbDevice { context: *mut UsbDeviceOpaque }
// SAFETY: owned reference pins C context; all process operations serialize in C.
unsafe impl Send for UsbDevice {}
unsafe impl Sync for UsbDevice {}
impl Clone for UsbDevice {
    fn clone(&self) -> Self {
        // SAFETY: self owns a live reference; get performs no I/O.
        unsafe { sle_usb_dev_get(self.context) };
        Self { context: self.context }
    }
}
impl Drop for UsbDevice {
    fn drop(&mut self) {
        // SAFETY: drop releases exactly this reference; C final put joins URBs.
        unsafe { sle_usb_dev_put(self.context) };
    }
}
impl UsbDevice {
    pub(crate) fn as_raw(&self) -> *mut UsbDeviceOpaque { self.context }
    fn create(identity: DeviceIdentity, interface: *mut core::ffi::c_void) -> Result<Self> {
        let mut context = core::ptr::null_mut();
        // SAFETY: probe retains interface through this call; out is live.
        let result = unsafe { sle_usb_dev_register(i32::from(identity.id), interface, identity.generation, &mut context) };
        if result != 0 { return Err(if result < 0 { Error::from_errno(result) } else { EIO }); }
        if context.is_null() { return Err(EIO); }
        Ok(Self { context })
    }
    fn retire(&self) {
        // SAFETY: retained allocation; invalidates and joins, does not put.
        unsafe { sle_usb_dev_unregister(self.context) };
    }
}

extern "C" {
    // Retained per-probe USB context: high-level operations
    fn sle_usb_dev_register(dev_id: i32, intf_ptr: *mut core::ffi::c_void, generation: u64, output: *mut *mut UsbDeviceOpaque) -> i32;
    fn sle_usb_dev_get(context: *mut UsbDeviceOpaque);
    fn sle_usb_dev_put(context: *mut UsbDeviceOpaque);
    fn sle_usb_dev_unregister(context: *mut UsbDeviceOpaque);
    fn sle_usb_dev_send_cmd(context: *mut UsbDeviceOpaque, opcode: u16, params: *const u8, plen: i32) -> i32;
    fn sle_usb_dev_send_data(context: *mut UsbDeviceOpaque, handle: u16, data: *const u8, len: i32) -> i32;
    fn sle_usb_dev_start_evt(context: *mut UsbDeviceOpaque) -> i32;
    fn sle_usb_dev_stop_evt(context: *mut UsbDeviceOpaque);
    fn sle_usb_dev_start_data(context: *mut UsbDeviceOpaque) -> i32;
    fn sle_usb_dev_stop_data(context: *mut UsbDeviceOpaque);
    fn sle_usb_dev_init_controller(context: *mut UsbDeviceOpaque) -> i32;
    fn sle_usb_dev_get_fw_version(context: *mut UsbDeviceOpaque) -> u32;
    fn sle_usb_dev_get_metadata(context: *mut UsbDeviceOpaque, output: *mut UsbMetadata) -> i32;
    fn sle_usb_dev_get_command_credits(context: *mut UsbDeviceOpaque) -> u8;
    fn sle_usb_dev_get_mac(context: *mut UsbDeviceOpaque, mac: *mut u8) -> i32;
    fn sle_usb_dev_suspend(context: *mut UsbDeviceOpaque) -> i32;
    fn sle_usb_dev_resume(context: *mut UsbDeviceOpaque) -> i32;
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
            owner.dropped_decode.fetch_add(1, Ordering::Relaxed);
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
                owner.dropped_decode.fetch_add(1, Ordering::Relaxed);
                pr_debug!(
                    "sparklink-usb: unknown event code=0x{:04x} len={}\n",
                    evt.event_code,
                    len
                );
            }
        }
        Err(_) => {
            owner.dropped_decode.fetch_add(1, Ordering::Relaxed);
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
const SLE_USB_CLASS: u8 = 0xE0;
/// USB interface subclass: RF controller.
const SLE_USB_SUBCLASS: u8 = 0x01;
/// USB interface protocol: SparkLink DLI.
const SLE_USB_PROTOCOL: u8 = 0x05;

// ---------------------------------------------------------------------------
// DLI USB packet parsers
// ---------------------------------------------------------------------------

/// Parsed DLI event from the interrupt IN endpoint.
struct DliUsbEvent {
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
fn parse_event_packet(data: &[u8]) -> Result<DliUsbEvent> {
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

/// Convert a raw event code and parameters into an [`SleEvent`].
fn event_to_sle(evt: &DliUsbEvent) -> Option<SleEvent> {
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
/// Actual USB I/O uses a retained per-probe C allocation.
/// Runtime reference to a specific USB allocation, never an index lookup.
#[derive(Clone)]
pub(crate) struct UsbController {
    metadata: UsbMetadata,
    /// Owns the immutable USB allocation independently of registry reuse.
    device: UsbDevice,
    identity: super::sle_dev::DeviceIdentity,
}

impl UsbController {
    /// Create a new USB controller handle.
    ///
    /// `addr` is the 6-byte SLE MAC address read from the controller
    /// during probe via the ReadMacAddr (0x0406) command.
    /// Identity comes from the pending reservation retained through USB cleanup.
    pub(crate) fn new(addr: [u8; 6], fw_version: u32, credits: u8, identity: super::sle_dev::DeviceIdentity, device: UsbDevice) -> Result<Self> {
        let mut metadata = UsbMetadata::default();
        // SAFETY: owned retained context and complete repr(C) writable snapshot;
        // C observes all fields and validity together under its I/O mutex.
        let ret = unsafe { sle_usb_dev_get_metadata(device.as_raw(), &mut metadata) };
        if ret != 0 { return Err(if ret < 0 { Error::from_errno(ret) } else { EIO }); }
        // The caller's identity query must refer to this same observation.
        if metadata.address != addr || metadata.command_credits != credits ||
            u32::from_le_bytes(metadata.version[..4].try_into().unwrap()) != fw_version { return Err(EPROTO); }
        Ok(Self { metadata, device, identity })
    }

    pub(crate) fn fill_snapshot(&self, out: &mut super::sle_uapi::SleControllerSnapshot) {
        // Immutable queried observation only, independent of Host readiness.
        let metadata = &self.metadata;
        out.valid_fields = 1;
        out.version_tuple = metadata.version;
        out.address = metadata.address;
        out.features = metadata.capabilities.features;
        out.acb_length = metadata.capabilities.acb_length;
        out.icb_length = metadata.capabilities.icb_length;
        out.acb_count = metadata.capabilities.acb_count;
        out.icb_count = metadata.capabilities.icb_count;
    }

    /// Only the owner's TX worker may call this transport operation after
    /// reserving its command slot and a controller credit.
    pub(crate) fn send_command_transport(&self, opcode: u16, params: &[u8]) -> Result {
        if params.len() > usize::from(self.metadata.capabilities.command_max) ||
            params.len() > super::sle_uapi::DLI_PARAM_MAX { return Err(EINVAL); }
        // SAFETY: worker retains its registration owner; removal drains the
        // worker before unregistering/freeing the C transport. Data is live.
        let ret = unsafe {
            sle_usb_dev_send_cmd(
                self.device.as_raw(),
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
        info.addr = self.metadata.address;
        // Immutable queried tuple, no C I/O lock or transport wait in info().
        info.fw_version = u32::from_le_bytes(self.metadata.version[..4].try_into().unwrap());
        info.features = u64::from_le_bytes(self.metadata.capabilities.features[..8].try_into().unwrap());
        info.features_ext = u16::from_le_bytes(self.metadata.capabilities.features[8..].try_into().unwrap());
        // ACB buffers are not SSAP MTU/MPS, DTAP modes, connection counts or
        // security policy. Those still-unqueried fields remain unavailable.

        info
    }

    fn open(&self) -> Result {
        // Start the listener using this retained allocation.
        // SAFETY: this controller owns its context reference.
        let ret = unsafe { sle_usb_dev_start_evt(self.device.as_raw()) };
        if ret < 0 {
            pr_warn!("sparklink-usb: event listener start failed: {}\n", ret);
            return Err(Error::from_errno(ret));
        }
        // Start bulk IN listener for async data (T/XS 10003-2025 §7.4).
        let ret = unsafe { sle_usb_dev_start_data(self.device.as_raw()) };
        if ret < 0 {
            pr_warn!("sparklink-usb: data listener start failed: {}\n", ret);
            // SAFETY: no binding can survive failed open; join its first listener.
            unsafe { sle_usb_dev_stop_evt(self.device.as_raw()) };
            return Err(Error::from_errno(ret));
        }
        pr_info!("sparklink-usb: open dev_id={}\n", self.identity.id);
        Ok(())
    }

    fn close(&self) {
        // SAFETY: owned context reference; stop is idempotent.
        unsafe { sle_usb_dev_stop_evt(self.device.as_raw()) };
        unsafe { sle_usb_dev_stop_data(self.device.as_raw()) };
        pr_info!("sparklink-usb: close dev_id={}\n", self.identity.id);
    }

    fn send_command(&self, opcode: SleOpcode, params: &[u8]) -> Result {
        let owner = ingress_owner(self.identity).ok_or(ENODEV)?;
        use super::sle_command_plan::DiscoveryIntent;
        let intent = if params.len() == 1 && params[0] <= 1 {
            if opcode == SleOpcode::EnableBroadcast {
                Some(DiscoveryIntent::Advertising(params[0] == 1))
            } else if opcode == SleOpcode::EnableScan {
                Some(DiscoveryIntent::Scanning(params[0] == 1))
            } else { None }
        } else { None };
        super::sle_ingress::enqueue_command(&owner, opcode as u16, params, intent)
    }

    fn send_data(&self, handle: u16, data: &[u8]) -> Result {
        // SAFETY: owned context reference, data pointer and length are consistent.
        let ret = unsafe {
            sle_usb_dev_send_data(
                self.device.as_raw(),
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

impl super::sle_backend::CommandPort for UsbController {
    fn submit(&self, opcode: u16, params: &[u8], recipe: Option<super::sle_command_plan::RecipeTag>, connection: Option<u32>) -> Result {
        // No typed connection or WS73 multi-step recipe implementation exists
        // for this standard provider yet; never silently drop those obligations.
        if connection.is_some() { return Err(Error::from_errno(-(kernel::bindings::EOPNOTSUPP as i32))); }
        if params.len() > super::sle_uapi::DLI_PARAM_MAX { return Err(EINVAL); }
        if let Some(tag) = recipe {
            use super::sle_command_plan::DiscoveryIntent;
            if tag.step != 0 || tag.count != 1 || tag.recreate {
                return Err(Error::from_errno(-(kernel::bindings::EOPNOTSUPP as i32)));
            }
            let (expected, enabled) = match tag.intent {
                DiscoveryIntent::Advertising(enabled) => (SleOpcode::EnableBroadcast as u16, enabled),
                DiscoveryIntent::Scanning(enabled) => (SleOpcode::EnableScan as u16, enabled),
                _ => return Err(Error::from_errno(-(kernel::bindings::EOPNOTSUPP as i32))),
            };
            if opcode != expected || params != [u8::from(enabled)] { return Err(EINVAL); }
        }
        self.send_command_transport(opcode, params)
    }
}

// ---------------------------------------------------------------------------
// USB driver integration — hardware discovery
// ---------------------------------------------------------------------------

/// Counter for discovered USB SLE devices.
static USB_DEV_COUNT: AtomicU32 = AtomicU32::new(0);

/// Returns the number of currently attached USB SLE controllers.
pub(crate) fn usb_device_count() -> u32 {
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
pub(crate) struct SleUsbDriver { binding: UsbBinding }
struct UsbBinding { identity: DeviceIdentity, device: UsbDevice }

/// Require bootstrap and optional firmware before reading publishable identity.
fn prepare_usb_controller(
    device: &UsbDevice,
    dev: &kernel::device::Device,
) -> Result<([u8; 6], u32)> {
    // Bootstrap must establish a real controller before optional firmware.
    initialize_usb_controller(device)?;
    let fw_name = kernel::c_str!("sparklink/sle_usb_v1.bin");
    match super::sle_fw::load_usb_firmware(device, fw_name, dev) {
        Ok(size) => {
            pr_info!("sparklink-usb: firmware loaded ({} bytes)\n", size);
            // Cached identity predates the download. Require fresh successful
            // Reset/version/MAC replies before publishing this binding.
            initialize_usb_controller(device)?;
        }
        Err(ENOENT) => pr_debug!("sparklink-usb: optional firmware absent\n"),
        Err(error) => return Err(error),
    }

    let mut addr = [0u8; 6];
    // SAFETY: probe owns a live registered binding; addr has six bytes.
    let ret = unsafe { sle_usb_dev_get_mac(device.as_raw(), addr.as_mut_ptr()) };
    if ret != 0 {
        return Err(if ret < 0 { Error::from_errno(ret) } else { EIO });
    }
    if addr == [0; 6] || addr == [0xff; 6] {
        return Err(Error::from_errno(-(kernel::bindings::EPROTO as i32)));
    }
    // SAFETY: the mandatory successful bootstrap populated this binding.
    let fw_version = unsafe { sle_usb_dev_get_fw_version(device.as_raw()) };
    Ok((addr, fw_version))
}

fn initialize_usb_controller(device: &UsbDevice) -> Result {
    // SAFETY: probe owns the live registered interface throughout this call.
    let ret = unsafe { sle_usb_dev_init_controller(device.as_raw()) };
    if ret != 0 {
        return Err(if ret < 0 { Error::from_errno(ret) } else { EIO });
    }
    Ok(())
}

/// Publish only the freshly prepared identity; failures join and detach.
fn probe_usb_device(interface: &usb::Interface<device::Core>) -> Result<UsbBinding> {
    pr_info!("sparklink-usb: SLE controller discovered\n");

    let identity = super::reserve_usb_identity()?;
    let dev_id = identity.id;
    let mut registered: Option<UsbDevice> = None;
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
        registered = Some(UsbDevice::create(identity, intf_ptr)?);
        let device = registered.as_ref().ok_or(ENODEV)?;
        let kern_dev: &kernel::device::Device<kernel::device::Core> = interface.as_ref();
        let (addr, fw_version) = prepare_usb_controller(device, kern_dev)?;

        // Switch the subsystem controller backend to USB and sync
        // the device registry with real hardware info.
        // SAFETY: mandatory bootstrap completed on this still-live binding.
        let credits = unsafe { sle_usb_dev_get_command_credits(device.as_raw()) };
        super::sle_switch_controller_usb(identity, device.clone(), addr, fw_version, credits)?;
        Ok(())
    })();
    if let Err(error) = result {
        super::sle_quiesce_device(identity);
        if let Some(device) = registered.as_ref() { device.retire(); }
        super::sle_detach_device(identity);
        return Err(error);
    }
    USB_DEV_COUNT.fetch_add(1, Ordering::Relaxed);

    Ok(UsbBinding { identity, device: registered.ok_or(ENODEV)? })
}

impl usb::Driver for SleUsbDriver {
    type IdInfo = ();
    const ID_TABLE: usb::IdTable<Self::IdInfo> = &SLE_USB_IDS;

    fn probe(
        interface: &usb::Interface<device::Core>,
        _id: &usb::DeviceId,
        _info: &Self::IdInfo,
    ) -> impl PinInit<Self, Error> {
        try_pin_init!(Self { binding: probe_usb_device(interface)? })
    }

    fn disconnect(_interface: &usb::Interface<device::Core>, data: Pin<&Self>) {
        pr_info!("sparklink-usb: SLE controller removed\n");
        USB_DEV_COUNT.fetch_sub(1, Ordering::Relaxed);

        let identity = data.binding.identity;
        let dev_id = identity.id;
        if dev_id != u16::MAX {
            // Reject new protocol access and join workers while C resources
            // are still live. Keep the registry index reserved through free.
            super::sle_quiesce_device(identity);
            // Stop URBs and unregister from C device table.
            // SAFETY: dev_id is valid; unregister kills URBs and frees C resources.
            data.binding.device.retire();
            super::sle_detach_device(identity);
            pr_info!("sparklink-usb: detached sle{}\n", dev_id);
        }
    }

    fn suspend(
        _interface: &usb::Interface<device::Core>,
        data: Pin<&Self>,
        _event: kernel::ffi::c_int,
    ) -> Result {
        let identity = data.binding.identity;
        let dev_id = identity.id;
        if dev_id == u16::MAX {
            return Ok(());
        }
        // SAFETY: dev_id is valid; suspend stops pending URBs.
        let ret = unsafe { sle_usb_dev_suspend(data.binding.device.as_raw()) };
        if ret < 0 {
            pr_err!("sparklink-usb: suspend sle{} failed: {}\n", dev_id, ret);
            return Err(Error::from_errno(ret));
        }
        super::sle_suspend_device(identity);
        pr_info!("sparklink-usb: sle{} suspended\n", dev_id);
        Ok(())
    }

    fn resume(_interface: &usb::Interface<device::Core>, data: Pin<&Self>) -> Result {
        let identity = data.binding.identity;
        let dev_id = identity.id;
        if dev_id == u16::MAX {
            return Ok(());
        }
        // SAFETY: dev_id is valid; resume restarts URB submissions.
        let ret = unsafe { sle_usb_dev_resume(data.binding.device.as_raw()) };
        if ret < 0 {
            pr_err!("sparklink-usb: resume sle{} failed: {}\n", dev_id, ret);
            return Err(Error::from_errno(ret));
        }
        super::sle_resume_device(identity);
        pr_info!("sparklink-usb: sle{} resumed\n", dev_id);
        Ok(())
    }
}

/// Type alias for USB driver registration used by the core module.
pub(crate) type UsbRegistration = kernel::driver::Registration<usb::Adapter<SleUsbDriver>>;
