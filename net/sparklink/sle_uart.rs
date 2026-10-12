// SPDX-License-Identifier: GPL-2.0

//! Experimental UART framing; hardware controller operations are unsupported.
//!
//! Implements DLI packet framing over UART following T/XS 10003-2025
//! UART transport binding. The framing is similar to the Bluetooth HCI
//! H4 protocol: a one-byte packet type indicator followed by a
//! type-specific header and payload.
//!
//! UART transport frame format:
//!   [0]     Packet type indicator (DliPacketType)
//!   [1..N]  Type-specific header (opcode/handle + length)
//!   [N..]   Payload data
//!
//! Command frame (Host -> Controller):
//!   [0]     0xA1 (Command)
//!   [1..2]  Opcode (little-endian)
//!   [3]     Parameter length
//!   [4..]   Parameters
//!
//! Event frame (Controller -> Host):
//!   [0]     0xA2 (Event)
//!   [1..2]  Event code (little-endian)
//!   [3]     Parameter length
//!   [4..]   Parameters
//!
//! Data frame (bidirectional):
//!   [0]     0xA3/0xA4/0xA5 (Async/Sync/Multicast)
//!   [1..2]  Handle (little-endian, lower 12 bits) + flags (upper 4 bits)
//!   [3..4]  Data length (little-endian)
//!   [5..]   Payload
//!
//! Default UART configuration:
//!   Baud rate: 115200 (configurable up to 3000000)
//!   Data bits: 8
//!   Stop bits: 1
//!   Parity:    None
//!   Flow ctrl: Hardware (RTS/CTS) recommended

use kernel::alloc::KVec;
use kernel::prelude::*;

use super::sle_dli::{
    DliPacketType,
};

// A complete decoded frame is consumed before unsupported RX directions are
// rejected by serdev; this preserves byte-stream framing without executing it.
pub const MAX_PAYLOAD_LEN: usize = 255;

// =========================================================================
// UART receiver state machine
// =========================================================================

/// Parser states for the DLI UART byte stream.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Default)]
enum RxState {
    /// Waiting for a packet type indicator byte.
    #[default]
    WaitType,
    /// Reading the type-specific header bytes.
    ReadHeader {
        pkt_type: DliPacketType,
        /// Number of header bytes collected so far.
        count: usize,
        /// Total header bytes expected (not including the type byte).
        expected: usize,
    },
    /// Reading the payload/parameter bytes.
    ReadPayload {
        pkt_type: DliPacketType,
        /// Number of payload bytes collected so far.
        count: usize,
        /// Total payload bytes expected.
        expected: usize,
    },
}

/// Parsed DLI frame from the UART stream.
pub enum UartFrame {
    /// Command frame (host to controller, but also used for parsing).
    Command { opcode: u16, params: KVec<u8> },
    /// Event frame from the controller.
    Event { event_code: u16, params: KVec<u8> },
    /// Data frame (async unicast, sync unicast, or multicast).
    Data {
        pkt_type: DliPacketType,
        handle: u16,
        flags: u8,
        payload: KVec<u8>,
    },
}

/// UART frame parser.
///
/// Feeds bytes from the UART receiver one at a time (or in chunks)
/// and produces complete frames when enough data is accumulated.
pub struct UartParser {
    state: RxState,
    /// Partial header accumulator (max 4 bytes).
    header: [u8; 4],
    /// Payload accumulator.
    payload: KVec<u8>,
}

impl UartParser {
    /// Create a new parser in the idle state.
    pub fn new() -> Self {
        Self {
            state: RxState::WaitType,
            header: [0u8; 4],
            payload: KVec::new(),
        }
    }

    /// Reset the parser to the initial state.
    pub fn reset(&mut self) {
        self.state = RxState::WaitType;
        self.payload.clear();
    }

    /// Feed a single byte into the parser.
    ///
    /// Returns `Some(UartFrame)` when a complete frame is assembled.
    /// Returns `None` if more bytes are needed.
    /// On protocol errors, the parser resets and returns `None`.
    pub fn feed(&mut self, byte: u8) -> Option<UartFrame> {
        match self.state {
            RxState::WaitType => {
                let pkt_type = match byte {
                    0xA1 => DliPacketType::Command,
                    0xA2 => DliPacketType::Event,
                    0xA3 => DliPacketType::AsyncUnicast,
                    0xA4 => DliPacketType::SyncUnicast,
                    0xA5 => DliPacketType::AsyncMulticast,
                    _ => return None, // skip unknown bytes
                };
                // Header size depends on type
                // All DLI frame types use 4-byte header after type byte:
                // Command: opcode(2)+len(2), Event: event_code(2)+len(2),
                // Data: handle(2)+len(2).
                let hdr_size = 4;
                self.state = RxState::ReadHeader {
                    pkt_type,
                    count: 0,
                    expected: hdr_size,
                };
                None
            }
            RxState::ReadHeader {
                pkt_type,
                count,
                expected,
            } => {
                self.header[count] = byte;
                let new_count = count + 1;
                if new_count < expected {
                    self.state = RxState::ReadHeader {
                        pkt_type,
                        count: new_count,
                        expected,
                    };
                    return None;
                }
                // Header complete, determine payload length.
                // All DLI frame types use LE16 length at header[2..3].
                let payload_len = u16::from_le_bytes([self.header[2], self.header[3]]) as usize;
                if payload_len == 0 {
                    let frame = self.build_frame(pkt_type);
                    self.reset();
                    return frame;
                }
                if payload_len > MAX_PAYLOAD_LEN {
                    // Protocol error: payload too large
                    self.reset();
                    return None;
                }
                self.payload.clear();
                self.state = RxState::ReadPayload {
                    pkt_type,
                    count: 0,
                    expected: payload_len,
                };
                None
            }
            RxState::ReadPayload {
                pkt_type,
                count,
                expected,
            } => {
                if self.payload.push(byte, GFP_KERNEL).is_err() {
                    // OOM: discard partial frame
                    self.reset();
                    return None;
                }
                let new_count = count + 1;
                if new_count < expected {
                    self.state = RxState::ReadPayload {
                        pkt_type,
                        count: new_count,
                        expected,
                    };
                    return None;
                }
                // Payload complete
                let frame = self.build_frame(pkt_type);
                self.reset();
                frame
            }
        }
    }

    /// Feed a byte slice and collect all completed frames.
    pub fn feed_bytes(&mut self, data: &[u8], out: &mut KVec<UartFrame>) {
        for &b in data {
            if let Some(frame) = self.feed(b) {
                let _ = out.push(frame, GFP_KERNEL);
            }
        }
    }

    /// Build a frame from the accumulated header and payload.
    fn build_frame(&mut self, pkt_type: DliPacketType) -> Option<UartFrame> {
        match pkt_type {
            DliPacketType::Command => {
                let opcode = u16::from_le_bytes([self.header[0], self.header[1]]);
                let mut params = KVec::new();
                core::mem::swap(&mut params, &mut self.payload);
                Some(UartFrame::Command { opcode, params })
            }
            DliPacketType::Event => {
                let event_code = u16::from_le_bytes([self.header[0], self.header[1]]);
                let mut params = KVec::new();
                core::mem::swap(&mut params, &mut self.payload);
                Some(UartFrame::Event { event_code, params })
            }
            _ => {
                let raw_handle = u16::from_le_bytes([self.header[0], self.header[1]]);
                let handle = raw_handle & 0x0FFF;
                let flags = (raw_handle >> 12) as u8;
                let mut payload = KVec::new();
                core::mem::swap(&mut payload, &mut self.payload);
                Some(UartFrame::Data {
                    pkt_type,
                    handle,
                    flags,
                    payload,
                })
            }
        }
    }
}
