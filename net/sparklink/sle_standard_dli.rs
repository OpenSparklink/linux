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
    // Independent privileged trace precedes schema parsing; neither malformed
    // packets nor a slow reader may consume or complete a Host transaction.
    unsafe { super::sle_native::sparklink_native_snoop_rx_rust(
        identity.id, identity.generation, data, len) };


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
        // Only the controller-scoped fault has an unsolicited standard consumer.
        // Other standard business events have no qualified lifetime/Session
        // consumer. Reject/count them at ingress; never construct then discard
        // connection, pairing, security or delivery state.
        0x000A => {
            if evt.params.len() != 1 { return None; }
            Some(SleEvent::HardwareError { code: evt.params[0] })
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

