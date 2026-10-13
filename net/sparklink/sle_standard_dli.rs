// SPDX-License-Identifier: GPL-2.0
//! Standard DLI event codec/attributed ingress. Physical USB lives in drivers.
use kernel::alloc::KVec;
use kernel::prelude::*;
use core::sync::atomic::Ordering;
use super::sle_dli::{SleEvent, SleStatus};
use super::sle_ingress::{enqueue_rx, ingress_owner};

/// Registered RX endpoints carry identity copied into their C URB allocation
/// before first submission. This never reads identity from a reusable C slot.
#[no_mangle]
pub(crate) extern "C" fn sparklink_standard_receive_rust(
    dev_id: u32,
    generation: u64,
    data: *const u8,
    length: i32,
    lane: u8,
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

    if owner.protocol_profile != 0 { return; }
    // Standard USB types are implicit in endpoint lanes. The unqualified old
    // handle-only bulk data route has no canonical Session/ticket owner yet.
    if lane != 1 {
        owner.dropped_decode.fetch_add(1, Ordering::Relaxed);
        return;
    }
    let len = length as usize;
    // SAFETY: C's registered event URB retains the immutable owner and supplies
    // its live transfer buffer with USB-core-validated actual_length.
    let slice = unsafe { core::slice::from_raw_parts(data, len) };

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

