// SPDX-License-Identifier: GPL-2.0
// Historical unused codec from K5a49caef. Not a production module.
// Includes old truncation/reserved-bit behavior as regression witnesses.

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

