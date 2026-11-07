// SPDX-License-Identifier: GPL-2.0
// Historical experimental format, NOT T/XS 20001 conformance or a production backend.
use kernel::alloc::KVec;
use kernel::prelude::*;
use crate::sle_ssap::{EntryCategory, EntryInfo, SsapError, SsapMsgCode, SsapUuid};

/// Maximum raw PDU buffer size. Bounded by the service management
/// channel MTU (default 247, negotiable up to controller max_mtu).
pub const SSAP_PDU_MAX: usize = 247;

/// Parsed SSAP PDU.
#[derive(Debug)]
pub enum SsapPdu {
    /// Error response: request opcode, error handle, error code.
    ErrorRsp {
        req_opcode: u8,
        handle: u16,
        error: SsapError,
    },
    /// Exchange info request (T/XS 20001-2025 §7.4.4.3).
    ExchangeInfoReq {
        mcc: u8,
        mtu: u16,
        version: (u8, u8),
        ext_mcc: [u8; 4],
    },
    /// Exchange info response (T/XS 20001-2025 §7.4.4.3).
    ExchangeInfoRsp {
        mcc: u8,
        mtu: u16,
        version: (u8, u8),
        ext_mcc: [u8; 4],
    },
    /// Find structure request: start/end handle range.
    FindStructureReq { start_handle: u16, end_handle: u16 },
    /// Find structure response: list of (handle, category, uuid) entries.
    FindStructureRsp { entries: KVec<EntryInfo> },
    /// Find by UUID request: UUID to search for.
    FindByUuidReq { uuid: SsapUuid },
    /// Find by UUID response: matched handle + entry info.
    FindByUuidRsp { handle: u16, data: KVec<u8> },
    /// Read request: attribute handle + offset for long reads.
    ReadReq { handle: u16, offset: u16 },
    /// Read response: attribute value.
    ReadRsp { data: KVec<u8> },
    /// Read by UUID request.
    ReadByUuidReq { uuid: SsapUuid },
    /// Read by UUID response: handle + value.
    ReadByUuidRsp { handle: u16, data: KVec<u8> },
    /// Write command (no response): handle + offset + value.
    WriteCmd { handle: u16, offset: u16, data: KVec<u8> },
    /// Write request (with response): handle + offset + value.
    WriteReq { handle: u16, offset: u16, data: KVec<u8> },
    /// Write response: handle.
    WriteRsp { handle: u16 },
    /// Value notification: handle + value.
    ValueNtf { handle: u16, data: KVec<u8> },
    /// Value indication: handle + value.
    ValueInd { handle: u16, data: KVec<u8> },
    /// Value acknowledgement: handle.
    ValueAck { handle: u16 },
    /// Call method command (no response): handle + input data.
    CallMethodCmd { handle: u16, data: KVec<u8> },
    /// Call method request (with response): handle + input data.
    CallMethodReq { handle: u16, data: KVec<u8> },
    /// Call method response: handle + output data.
    CallMethodRsp { handle: u16, data: KVec<u8> },
}

impl SsapPdu {
    /// Encode this PDU into a byte buffer.
    /// Returns the number of bytes written, or ENOMEM/EINVAL on error.
    pub fn encode(&self, buf: &mut [u8]) -> Result<usize> {
        match self {
            SsapPdu::ErrorRsp {
                req_opcode,
                handle,
                error,
            } => {
                if buf.len() < 4 {
                    return Err(ENOMEM);
                }
                buf[0] = SsapMsgCode::ErrorRsp as u8;
                buf[1] = *req_opcode;
                buf[2..4].copy_from_slice(&handle.to_le_bytes());
                buf[4] = *error as u8;
                Ok(5)
            }
            SsapPdu::ExchangeInfoReq {
                mcc,
                mtu,
                version,
                ext_mcc,
            } => {
                let needed = Self::exchange_info_encode_len(*mcc);
                if buf.len() < needed {
                    return Err(ENOMEM);
                }
                buf[0] = SsapMsgCode::ExchangeInfoReq as u8;
                Ok(Self::encode_exchange_info_fields(
                    &mut buf[1..],
                    *mcc,
                    *mtu,
                    *version,
                    ext_mcc,
                ) + 1)
            }
            SsapPdu::ExchangeInfoRsp {
                mcc,
                mtu,
                version,
                ext_mcc,
            } => {
                let needed = Self::exchange_info_encode_len(*mcc);
                if buf.len() < needed {
                    return Err(ENOMEM);
                }
                buf[0] = SsapMsgCode::ExchangeInfoRsp as u8;
                Ok(Self::encode_exchange_info_fields(
                    &mut buf[1..],
                    *mcc,
                    *mtu,
                    *version,
                    ext_mcc,
                ) + 1)
            }
            SsapPdu::FindStructureReq {
                start_handle,
                end_handle,
            } => {
                if buf.len() < 5 {
                    return Err(ENOMEM);
                }
                buf[0] = SsapMsgCode::FindStructureReq as u8;
                buf[1..3].copy_from_slice(&start_handle.to_le_bytes());
                buf[3..5].copy_from_slice(&end_handle.to_le_bytes());
                Ok(5)
            }
            SsapPdu::FindStructureRsp { entries } => {
                // Each entry: handle(2) + category(1) + uuid_len(1) + uuid(2 or 16)
                let hdr = 1;
                let needed = hdr
                    + entries
                        .iter()
                        .map(|e| {
                            4 + match e.uuid {
                                SsapUuid::Uuid16(_) => 2,
                                SsapUuid::Uuid128(_) => 16,
                            }
                        })
                        .sum::<usize>();
                if buf.len() < needed {
                    return Err(ENOMEM);
                }
                buf[0] = SsapMsgCode::FindStructureRsp as u8;
                let mut off = 1;
                for e in entries.iter() {
                    buf[off..off + 2].copy_from_slice(&e.handle.to_le_bytes());
                    buf[off + 2] = e.category as u8;
                    match e.uuid {
                        SsapUuid::Uuid16(v) => {
                            buf[off + 3] = 2;
                            buf[off + 4..off + 6].copy_from_slice(&v.to_le_bytes());
                            off += 6;
                        }
                        SsapUuid::Uuid128(v) => {
                            buf[off + 3] = 16;
                            buf[off + 4..off + 20].copy_from_slice(&v);
                            off += 20;
                        }
                    }
                }
                Ok(off)
            }
            SsapPdu::FindByUuidReq { uuid } => {
                match uuid {
                    SsapUuid::Uuid16(v) => {
                        if buf.len() < 4 {
                            return Err(ENOMEM);
                        }
                        buf[0] = SsapMsgCode::FindByUuidReq as u8;
                        buf[1] = 2; // uuid length
                        buf[2..4].copy_from_slice(&v.to_le_bytes());
                        Ok(4)
                    }
                    SsapUuid::Uuid128(v) => {
                        if buf.len() < 18 {
                            return Err(ENOMEM);
                        }
                        buf[0] = SsapMsgCode::FindByUuidReq as u8;
                        buf[1] = 16;
                        buf[2..18].copy_from_slice(v);
                        Ok(18)
                    }
                }
            }
            SsapPdu::FindByUuidRsp { handle, data } => {
                let need = 3 + data.len();
                if buf.len() < need {
                    return Err(ENOMEM);
                }
                buf[0] = SsapMsgCode::FindByUuidRsp as u8;
                buf[1..3].copy_from_slice(&handle.to_le_bytes());
                buf[3..3 + data.len()].copy_from_slice(data);
                Ok(need)
            }
            SsapPdu::ReadReq { handle, offset } => {
                if buf.len() < 5 {
                    return Err(ENOMEM);
                }
                buf[0] = SsapMsgCode::ReadReq as u8;
                buf[1..3].copy_from_slice(&handle.to_le_bytes());
                buf[3..5].copy_from_slice(&offset.to_le_bytes());
                Ok(5)
            }
            SsapPdu::ReadRsp { data } => {
                if buf.len() < 1 + data.len() {
                    return Err(ENOMEM);
                }
                buf[0] = SsapMsgCode::ReadRsp as u8;
                buf[1..1 + data.len()].copy_from_slice(data);
                Ok(1 + data.len())
            }
            SsapPdu::ReadByUuidReq { uuid } => {
                match uuid {
                    SsapUuid::Uuid16(v) => {
                        if buf.len() < 4 {
                            return Err(ENOMEM);
                        }
                        buf[0] = SsapMsgCode::ReadByUuidReq as u8;
                        buf[1] = 2;
                        buf[2..4].copy_from_slice(&v.to_le_bytes());
                        Ok(4)
                    }
                    SsapUuid::Uuid128(v) => {
                        if buf.len() < 18 {
                            return Err(ENOMEM);
                        }
                        buf[0] = SsapMsgCode::ReadByUuidReq as u8;
                        buf[1] = 16;
                        buf[2..18].copy_from_slice(v);
                        Ok(18)
                    }
                }
            }
            SsapPdu::ReadByUuidRsp { handle, data } => {
                let need = 3 + data.len();
                if buf.len() < need {
                    return Err(ENOMEM);
                }
                buf[0] = SsapMsgCode::ReadByUuidRsp as u8;
                buf[1..3].copy_from_slice(&handle.to_le_bytes());
                buf[3..3 + data.len()].copy_from_slice(data);
                Ok(need)
            }
            SsapPdu::WriteCmd { handle, offset, data } => {
                if buf.len() < 5 + data.len() {
                    return Err(ENOMEM);
                }
                buf[0] = SsapMsgCode::WriteCmd as u8;
                buf[1..3].copy_from_slice(&handle.to_le_bytes());
                buf[3..5].copy_from_slice(&offset.to_le_bytes());
                buf[5..5 + data.len()].copy_from_slice(data);
                Ok(5 + data.len())
            }
            SsapPdu::WriteReq { handle, offset, data } => {
                if buf.len() < 5 + data.len() {
                    return Err(ENOMEM);
                }
                buf[0] = SsapMsgCode::WriteReq as u8;
                buf[1..3].copy_from_slice(&handle.to_le_bytes());
                buf[3..5].copy_from_slice(&offset.to_le_bytes());
                buf[5..5 + data.len()].copy_from_slice(data);
                Ok(5 + data.len())
            }
            SsapPdu::WriteRsp { handle } => {
                if buf.len() < 3 {
                    return Err(ENOMEM);
                }
                buf[0] = SsapMsgCode::WriteRsp as u8;
                buf[1..3].copy_from_slice(&handle.to_le_bytes());
                Ok(3)
            }
            SsapPdu::ValueNtf { handle, data } => {
                if buf.len() < 3 + data.len() {
                    return Err(ENOMEM);
                }
                buf[0] = SsapMsgCode::ValueNtf as u8;
                buf[1..3].copy_from_slice(&handle.to_le_bytes());
                buf[3..3 + data.len()].copy_from_slice(data);
                Ok(3 + data.len())
            }
            SsapPdu::ValueInd { handle, data } => {
                if buf.len() < 3 + data.len() {
                    return Err(ENOMEM);
                }
                buf[0] = SsapMsgCode::ValueInd as u8;
                buf[1..3].copy_from_slice(&handle.to_le_bytes());
                buf[3..3 + data.len()].copy_from_slice(data);
                Ok(3 + data.len())
            }
            SsapPdu::ValueAck { handle } => {
                if buf.len() < 3 {
                    return Err(ENOMEM);
                }
                buf[0] = SsapMsgCode::ValueAck as u8;
                buf[1..3].copy_from_slice(&handle.to_le_bytes());
                Ok(3)
            }
            SsapPdu::CallMethodCmd { handle, data } => {
                let need = 3 + data.len();
                if buf.len() < need {
                    return Err(ENOMEM);
                }
                buf[0] = SsapMsgCode::CallMethodCmd as u8;
                buf[1..3].copy_from_slice(&handle.to_le_bytes());
                buf[3..3 + data.len()].copy_from_slice(data);
                Ok(need)
            }
            SsapPdu::CallMethodReq { handle, data } => {
                let need = 3 + data.len();
                if buf.len() < need {
                    return Err(ENOMEM);
                }
                buf[0] = SsapMsgCode::CallMethodReq as u8;
                buf[1..3].copy_from_slice(&handle.to_le_bytes());
                buf[3..3 + data.len()].copy_from_slice(data);
                Ok(need)
            }
            SsapPdu::CallMethodRsp { handle, data } => {
                let need = 3 + data.len();
                if buf.len() < need {
                    return Err(ENOMEM);
                }
                buf[0] = SsapMsgCode::CallMethodRsp as u8;
                buf[1..3].copy_from_slice(&handle.to_le_bytes());
                buf[3..3 + data.len()].copy_from_slice(data);
                Ok(need)
            }
        }
    }

    /// Compute encoded size for ExchangeInfo fields (excluding opcode).
    fn exchange_info_encode_len(mcc: u8) -> usize {
        let mut n = 2; // opcode + mcc
        if mcc & 0x01 != 0 {
            n += 2;
        } // MTU
        if mcc & 0x02 != 0 {
            n += 2;
        } // version
        if mcc & 0x04 != 0 {
            n += 4;
        } // ext_mcc
        n
    }

    /// Encode ExchangeInfo conditional fields after the opcode byte.
    /// Returns the number of bytes written into `buf`.
    fn encode_exchange_info_fields(
        buf: &mut [u8],
        mcc: u8,
        mtu: u16,
        version: (u8, u8),
        ext_mcc: &[u8; 4],
    ) -> usize {
        let mut pos = 0;
        buf[pos] = mcc;
        pos += 1;
        if mcc & 0x01 != 0 {
            buf[pos..pos + 2].copy_from_slice(&mtu.to_le_bytes());
            pos += 2;
        }
        if mcc & 0x02 != 0 {
            buf[pos] = version.0;
            buf[pos + 1] = version.1;
            pos += 2;
        }
        if mcc & 0x04 != 0 {
            buf[pos..pos + 4].copy_from_slice(ext_mcc);
            pos += 4;
        }
        pos
    }

    /// Decode ExchangeInfo conditional fields from payload.
    /// Returns (mcc, mtu, version, ext_mcc).
    fn decode_exchange_info_fields(
        payload: &[u8],
    ) -> (u8, u16, (u8, u8), [u8; 4]) {
        // Backward compatibility: if payload is exactly 2 bytes, it is the
        // old format (MTU only, no MCC byte).
        if payload.len() == 2 {
            return (
                0x01,
                u16::from_le_bytes([payload[0], payload[1]]),
                (1, 0),
                [0; 4],
            );
        }
        if payload.is_empty() {
            return (0, 247, (1, 0), [0; 4]);
        }
        let mcc = payload[0];
        let mut off = 1;
        let mtu = if mcc & 0x01 != 0 && off + 2 <= payload.len() {
            let v = u16::from_le_bytes([payload[off], payload[off + 1]]);
            off += 2;
            v
        } else {
            247
        };
        let version = if mcc & 0x02 != 0 && off + 2 <= payload.len() {
            let v = (payload[off], payload[off + 1]);
            off += 2;
            v
        } else {
            (1, 0)
        };
        let mut ext_mcc = [0u8; 4];
        if mcc & 0x04 != 0 && off + 4 <= payload.len() {
            ext_mcc.copy_from_slice(&payload[off..off + 4]);
        }
        (mcc, mtu, version, ext_mcc)
    }

    /// Decode a raw byte buffer into an SSAP PDU.
    /// Returns the parsed PDU or EINVAL if malformed.
    pub fn decode(buf: &[u8]) -> Result<Self> {
        if buf.is_empty() {
            return Err(EINVAL);
        }
        let opcode = buf[0];
        let payload = &buf[1..];
        match opcode {
            0x01 => {
                // ErrorRsp: req_opcode(1) + handle(2) + error(1) = 4
                if payload.len() < 4 {
                    return Err(EINVAL);
                }
                Ok(SsapPdu::ErrorRsp {
                    req_opcode: payload[0],
                    handle: u16::from_le_bytes([payload[1], payload[2]]),
                    error: SsapError::from_raw(payload[3]),
                })
            }
            0x02 => {
                if payload.is_empty() {
                    return Err(EINVAL);
                }
                let (mcc, mtu, version, ext_mcc) =
                    Self::decode_exchange_info_fields(payload);
                Ok(SsapPdu::ExchangeInfoReq {
                    mcc,
                    mtu,
                    version,
                    ext_mcc,
                })
            }
            0x03 => {
                if payload.is_empty() {
                    return Err(EINVAL);
                }
                let (mcc, mtu, version, ext_mcc) =
                    Self::decode_exchange_info_fields(payload);
                Ok(SsapPdu::ExchangeInfoRsp {
                    mcc,
                    mtu,
                    version,
                    ext_mcc,
                })
            }
            0x04 => {
                if payload.len() < 4 {
                    return Err(EINVAL);
                }
                Ok(SsapPdu::FindStructureReq {
                    start_handle: u16::from_le_bytes([payload[0], payload[1]]),
                    end_handle: u16::from_le_bytes([payload[2], payload[3]]),
                })
            }
            0x05 => {
                let mut entries = KVec::new();
                let mut off = 0;
                while off + 4 <= payload.len() {
                    let handle = u16::from_le_bytes([payload[off], payload[off + 1]]);
                    let category_raw = payload[off + 2];
                    let uuid_len = payload[off + 3] as usize;
                    off += 4;
                    if off + uuid_len > payload.len() {
                        break;
                    }
                    let uuid = if uuid_len == 2 {
                        SsapUuid::Uuid16(u16::from_le_bytes([payload[off], payload[off + 1]]))
                    } else if uuid_len == 16 {
                        let mut u = [0u8; 16];
                        u.copy_from_slice(&payload[off..off + 16]);
                        SsapUuid::Uuid128(u)
                    } else {
                        off += uuid_len;
                        continue;
                    };
                    let category = match category_raw {
                        0x00 => EntryCategory::PrimaryService,
                        0x01 => EntryCategory::SecondaryService,
                        0x02 => EntryCategory::Property,
                        0x03 => EntryCategory::Method,
                        0x04 => EntryCategory::Event,
                        0x05 => EntryCategory::ServiceRef,
                        0x08 => EntryCategory::CustomPrimaryService,
                        0x09 => EntryCategory::CustomSecondaryService,
                        0x0A => EntryCategory::CustomProperty,
                        0x0B => EntryCategory::CustomMethod,
                        0x0C => EntryCategory::CustomEvent,
                        0x0D => EntryCategory::CustomServiceRef,
                        _ => {
                            off += uuid_len;
                            continue;
                        }
                    };
                    let _ = entries.push(
                        EntryInfo {
                            handle,
                            category,
                            uuid,
                        },
                        GFP_KERNEL,
                    );
                    off += uuid_len;
                }
                Ok(SsapPdu::FindStructureRsp { entries })
            }
            0x06 => {
                // FindByUuidReq: uuid_len(1) + uuid(2 or 16)
                if payload.is_empty() {
                    return Err(EINVAL);
                }
                let uuid_len = payload[0] as usize;
                if payload.len() < 1 + uuid_len {
                    return Err(EINVAL);
                }
                let uuid = if uuid_len == 2 {
                    SsapUuid::Uuid16(u16::from_le_bytes([payload[1], payload[2]]))
                } else if uuid_len == 16 {
                    let mut v = [0u8; 16];
                    v.copy_from_slice(&payload[1..17]);
                    SsapUuid::Uuid128(v)
                } else {
                    return Err(EINVAL);
                };
                Ok(SsapPdu::FindByUuidReq { uuid })
            }
            0x07 => {
                // FindByUuidRsp: handle(2) + data
                if payload.len() < 2 {
                    return Err(EINVAL);
                }
                let handle = u16::from_le_bytes([payload[0], payload[1]]);
                let mut data = KVec::new();
                for &b in &payload[2..] {
                    data.push(b, GFP_KERNEL)?;
                }
                Ok(SsapPdu::FindByUuidRsp { handle, data })
            }
            0x08 => {
                if payload.len() < 2 {
                    return Err(EINVAL);
                }
                let handle = u16::from_le_bytes([payload[0], payload[1]]);
                let offset = if payload.len() >= 4 {
                    u16::from_le_bytes([payload[2], payload[3]])
                } else {
                    0
                };
                Ok(SsapPdu::ReadReq { handle, offset })
            }
            0x09 => {
                let mut data = KVec::new();
                for &b in payload {
                    data.push(b, GFP_KERNEL)?;
                }
                Ok(SsapPdu::ReadRsp { data })
            }
            0x0A => {
                // ReadByUuidReq: uuid_len(1) + uuid(2 or 16)
                if payload.is_empty() {
                    return Err(EINVAL);
                }
                let uuid_len = payload[0] as usize;
                if payload.len() < 1 + uuid_len {
                    return Err(EINVAL);
                }
                let uuid = if uuid_len == 2 {
                    SsapUuid::Uuid16(u16::from_le_bytes([payload[1], payload[2]]))
                } else if uuid_len == 16 {
                    let mut v = [0u8; 16];
                    v.copy_from_slice(&payload[1..17]);
                    SsapUuid::Uuid128(v)
                } else {
                    return Err(EINVAL);
                };
                Ok(SsapPdu::ReadByUuidReq { uuid })
            }
            0x0B => {
                // ReadByUuidRsp: handle(2) + data
                if payload.len() < 2 {
                    return Err(EINVAL);
                }
                let handle = u16::from_le_bytes([payload[0], payload[1]]);
                let mut data = KVec::new();
                for &b in &payload[2..] {
                    data.push(b, GFP_KERNEL)?;
                }
                Ok(SsapPdu::ReadByUuidRsp { handle, data })
            }
            0x0C => {
                if payload.len() < 2 {
                    return Err(EINVAL);
                }
                let handle = u16::from_le_bytes([payload[0], payload[1]]);
                let (offset, data_start) = if payload.len() >= 4 {
                    (u16::from_le_bytes([payload[2], payload[3]]), 4)
                } else {
                    (0u16, 2)
                };
                let mut data = KVec::new();
                for &b in &payload[data_start..] {
                    data.push(b, GFP_KERNEL)?;
                }
                Ok(SsapPdu::WriteCmd { handle, offset, data })
            }
            0x0D => {
                if payload.len() < 2 {
                    return Err(EINVAL);
                }
                let handle = u16::from_le_bytes([payload[0], payload[1]]);
                let (offset, data_start) = if payload.len() >= 4 {
                    (u16::from_le_bytes([payload[2], payload[3]]), 4)
                } else {
                    (0u16, 2)
                };
                let mut data = KVec::new();
                for &b in &payload[data_start..] {
                    data.push(b, GFP_KERNEL)?;
                }
                Ok(SsapPdu::WriteReq { handle, offset, data })
            }
            0x0E => {
                if payload.len() < 2 {
                    return Err(EINVAL);
                }
                Ok(SsapPdu::WriteRsp {
                    handle: u16::from_le_bytes([payload[0], payload[1]]),
                })
            }
            0x0F => {
                if payload.len() < 2 {
                    return Err(EINVAL);
                }
                let handle = u16::from_le_bytes([payload[0], payload[1]]);
                let mut data = KVec::new();
                for &b in &payload[2..] {
                    data.push(b, GFP_KERNEL)?;
                }
                Ok(SsapPdu::ValueNtf { handle, data })
            }
            0x10 => {
                if payload.len() < 2 {
                    return Err(EINVAL);
                }
                let handle = u16::from_le_bytes([payload[0], payload[1]]);
                let mut data = KVec::new();
                for &b in &payload[2..] {
                    data.push(b, GFP_KERNEL)?;
                }
                Ok(SsapPdu::ValueInd { handle, data })
            }
            0x11 => {
                if payload.len() < 2 {
                    return Err(EINVAL);
                }
                Ok(SsapPdu::ValueAck {
                    handle: u16::from_le_bytes([payload[0], payload[1]]),
                })
            }
            0x12 | 0x13 => {
                if payload.len() < 2 {
                    return Err(EINVAL);
                }
                let handle = u16::from_le_bytes([payload[0], payload[1]]);
                let mut data = KVec::new();
                for &b in &payload[2..] {
                    data.push(b, GFP_KERNEL)?;
                }
                if opcode == 0x12 {
                    Ok(SsapPdu::CallMethodCmd { handle, data })
                } else {
                    Ok(SsapPdu::CallMethodReq { handle, data })
                }
            }
            0x14 => {
                if payload.len() < 2 {
                    return Err(EINVAL);
                }
                let handle = u16::from_le_bytes([payload[0], payload[1]]);
                let mut data = KVec::new();
                for &b in &payload[2..] {
                    data.push(b, GFP_KERNEL)?;
                }
                Ok(SsapPdu::CallMethodRsp { handle, data })
            }
            _ => Err(EINVAL),
        }
    }
}

