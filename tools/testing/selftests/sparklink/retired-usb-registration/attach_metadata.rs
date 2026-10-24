// SPDX-License-Identifier: GPL-2.0-only
// Exact historical metadata projection, no production caller.
    let bus = proto.bus;

    // Build a SleControllerInfo for device registration.
    let proto_name = proto.name;
    let name_bytes = proto_name.as_bytes();
    let mut name_buf = [0u8; 32];
    let copy_len = name_bytes.len().min(name_buf.len());
    name_buf[..copy_len].copy_from_slice(&name_bytes[..copy_len]);

    let ctrl_info = sle_dli::SleControllerInfo {
        name: name_buf,
        bus,
        addr: info.addr,
        fw_version: info.fw_version,
        features: info.features,
        features_ext: info.features_ext,
        max_pdu_payload: info.max_pdu,
        max_connections: info.max_connections,
        ..Default::default()
    };

