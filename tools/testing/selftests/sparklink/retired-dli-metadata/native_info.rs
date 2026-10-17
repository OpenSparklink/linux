// SPDX-License-Identifier: GPL-2.0
// Exact b35 projection. Not current provider state or a production consumer.
    fn info(&self) -> SleControllerInfo {
        let mut name = [0; 32];
        let label: &[u8] = if self.bus == SleBus::Test { b"sparklink-test" } else if self.metadata.profile == 0 { b"standard-dli-usb" } else { b"ws73-native" };
        name[..label.len()].copy_from_slice(label);
        SleControllerInfo {
            name, bus: self.bus, addr: self.metadata.address,
            // Legacy projection only; the retained tuple contains all 5 bytes.
            fw_version: u32::from_le_bytes(self.metadata.version[..4].try_into().unwrap()),
            features: u64::from_le_bytes(self.metadata.features[..8].try_into().unwrap()),
            features_ext: u16::from_le_bytes(self.metadata.features[8..].try_into().unwrap()),
            max_pdu_payload: if self.metadata.profile == 0 { 0 } else { self.metadata.acb_length },
            // These queries do not establish connection count, MTU or these
            // policy capabilities. Never borrow standard USB defaults.
            max_connections: 0, max_mtu: 0, max_mps: 0,
            transport_modes: 0, measurement_cap: 0, security_cap: 0,
        }
    }
