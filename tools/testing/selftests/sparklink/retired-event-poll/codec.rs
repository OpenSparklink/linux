// SPDX-License-Identifier: GPL-2.0-only
pub(crate) fn sle_dli_event_to_wire(ev: &sle_dli::SleEvent) -> SleDliEvent {
    let mut out = SleDliEvent::default();
    match ev {
        sle_dli::SleEvent::NativeCommandReply { opcode, status, complete, data, .. } => {
            out.event_type = if *complete { 1 } else { 2 };
            out.opcode = *opcode;
            out.status = *status;
            let n = data.len().min(out.data.len());
            out.data_len = n as u16;
            out.data[..n].copy_from_slice(&data[..n]);
        }
        sle_dli::SleEvent::CommandCredits { credits } => {
            out.event_type = 1;
            out.data_len = 1;
            out.data[0] = *credits;
        }
        sle_dli::SleEvent::CommandComplete {
            opcode,
            status,
            data,
            ..
        } => {
            out.event_type = 0x01;
            out.status = *status as u8;
            out.opcode = *opcode as u16;
            let len = data.len().min(240);
            out.data_len = len as u16;
            out.data[..len].copy_from_slice(&data[..len]);
        }
        sle_dli::SleEvent::CommandStatus { opcode, status, .. } => {
            out.event_type = 0x02;
            out.status = *status as u8;
            out.opcode = *opcode as u16;
        }
        sle_dli::SleEvent::AdvReport {
            addr,
            rssi,
            discovery_level,
            data,
        } => {
            out.event_type = 0x03;
            out.addr = *addr;
            out.data[0] = *rssi as u8;
            out.data[1] = *discovery_level;
            let len = data.len().min(238);
            out.data_len = (len + 2) as u16;
            out.data[2..2 + len].copy_from_slice(&data[..len]);
        }
        sle_dli::SleEvent::ConnComplete {
            handle,
            addr,
            status,
        } => {
            out.event_type = 0x04;
            out.handle = *handle;
            out.addr = *addr;
            out.status = *status as u8;
        }
        sle_dli::SleEvent::DataReceived { handle, data } => {
            out.event_type = 0x05;
            out.handle = *handle;
            let len = data.len().min(240);
            out.data_len = len as u16;
            out.data[..len].copy_from_slice(&data[..len]);
        }
        sle_dli::SleEvent::Disconnected { handle, reason } => {
            out.event_type = 0x06;
            out.handle = *handle;
            out.data[0] = *reason;
            out.data_len = 1;
        }
        sle_dli::SleEvent::EncryptionChanged { handle, enabled } => {
            out.event_type = 0x07;
            out.handle = *handle;
            out.data[0] = if *enabled { 1 } else { 0 };
            out.data_len = 1;
        }
        sle_dli::SleEvent::PairRequest { addr, method } => {
            out.event_type = 0x08;
            out.addr = *addr;
            out.data[0] = *method;
            out.data_len = 1;
        }
        sle_dli::SleEvent::HardwareError { code } => {
            out.event_type = 0x09;
            out.data[0] = *code;
            out.data_len = 1;
        }
        sle_dli::SleEvent::BroadcastEnd { reason } => {
            out.event_type = 0x0A;
            out.data[0] = *reason;
            out.data_len = 1;
        }
        sle_dli::SleEvent::PhyUpdate {
            handle,
            mcs_index,
            bandwidth_mhz,
        } => {
            out.event_type = 0x0B;
            out.handle = *handle;
            out.data[0] = *mcs_index;
            out.data[1] = *bandwidth_mhz;
            out.data_len = 2;
        }
        sle_dli::SleEvent::ConnParamUpdate {
            handle,
            interval,
            latency,
            timeout,
        } => {
            out.event_type = 0x0C;
            out.handle = *handle;
            out.data[0] = (*interval & 0xFF) as u8;
            out.data[1] = (*interval >> 8) as u8;
            out.data[2] = (*latency & 0xFF) as u8;
            out.data[3] = (*latency >> 8) as u8;
            out.data[4] = (*timeout & 0xFF) as u8;
            out.data[5] = (*timeout >> 8) as u8;
            out.data_len = 6;
        }
        sle_dli::SleEvent::DataLenChange {
            handle,
            max_tx_octets,
            max_rx_octets,
        } => {
            out.event_type = 0x0D;
            out.handle = *handle;
            out.data[0] = (*max_tx_octets & 0xFF) as u8;
            out.data[1] = (*max_tx_octets >> 8) as u8;
            out.data[2] = (*max_rx_octets & 0xFF) as u8;
            out.data[3] = (*max_rx_octets >> 8) as u8;
            out.data_len = 4;
        }
        sle_dli::SleEvent::DataBufOverflow { link_type } => {
            out.event_type = 0x0E;
            out.data[0] = *link_type;
            out.data_len = 1;
        }
        sle_dli::SleEvent::PeerConnParamReq {
            handle,
            interval_min,
            interval_max,
            latency,
            timeout,
        } => {
            out.event_type = 0x0F;
            out.handle = *handle;
            out.data[0] = (*interval_min & 0xFF) as u8;
            out.data[1] = (*interval_min >> 8) as u8;
            out.data[2] = (*interval_max & 0xFF) as u8;
            out.data[3] = (*interval_max >> 8) as u8;
            out.data[4] = (*latency & 0xFF) as u8;
            out.data[5] = (*latency >> 8) as u8;
            out.data[6] = (*timeout & 0xFF) as u8;
            out.data[7] = (*timeout >> 8) as u8;
            out.data_len = 8;
        }

        // --- HIGH priority events ---
        sle_dli::SleEvent::PowerChangeReport {
            handle,
            reason,
            frame_type,
            bandwidth,
            pilot_density,
            tx_power,
            power_level,
            offset,
        } => {
            out.event_type = 0x10;
            out.handle = *handle;
            out.data[0] = *reason;
            out.data[1] = *frame_type;
            out.data[2] = *bandwidth;
            out.data[3] = *pilot_density;
            out.data[4] = *tx_power as u8;
            out.data[5] = *power_level;
            out.data[6] = *offset as u8;
            out.data_len = 7;
        }
        sle_dli::SleEvent::NumCompletedPackets {
            handle,
            num_completed,
        } => {
            out.event_type = 0x11;
            out.handle = *handle;
            out.data[0] = *num_completed;
            out.data_len = 1;
        }
        sle_dli::SleEvent::EncryptionParamReq { handle } => {
            out.event_type = 0x12;
            out.handle = *handle;
        }

        // --- MEDIUM — Peer Info events ---
        sle_dli::SleEvent::ControllerSignalData {
            handle,
            signal_id,
            data,
        } => {
            out.event_type = 0x13;
            out.handle = *handle;
            out.opcode = *signal_id;
            let len = data.len().min(240);
            out.data_len = len as u16;
            out.data[..len].copy_from_slice(&data[..len]);
        }
        sle_dli::SleEvent::ReadPeerFeatures {
            handle,
            status,
            features,
        } => {
            out.event_type = 0x14;
            out.handle = *handle;
            out.status = *status;
            out.data[..10].copy_from_slice(features);
            out.data_len = 10;
        }
        sle_dli::SleEvent::ReadPeerVersion {
            handle,
            status,
            version,
            manufacturer,
            subversion,
        } => {
            out.event_type = 0x15;
            out.handle = *handle;
            out.status = *status;
            out.data[0] = *version;
            out.data[1] = (*manufacturer & 0xFF) as u8;
            out.data[2] = (*manufacturer >> 8) as u8;
            out.data[3] = (*subversion & 0xFF) as u8;
            out.data[4] = (*subversion >> 8) as u8;
            out.data_len = 5;
        }
        sle_dli::SleEvent::ReadPeerPower {
            handle,
            status,
            frame_type,
            bandwidth,
            pilot_density,
            tx_power,
            power_level,
        } => {
            out.event_type = 0x16;
            out.handle = *handle;
            out.status = *status;
            out.data[0] = *frame_type;
            out.data[1] = *bandwidth;
            out.data[2] = *pilot_density;
            out.data[3] = *tx_power as u8;
            out.data[4] = *power_level;
            out.data_len = 5;
        }
        sle_dli::SleEvent::InquiryRequestReport {
            adv_handle,
            addr_type,
            addr,
            rssi,
            data,
        } => {
            out.event_type = 0x17;
            out.addr = *addr;
            out.data[0] = *adv_handle;
            out.data[1] = *addr_type;
            out.data[2] = *rssi as u8;
            let len = data.len().min(237);
            out.data[3..3 + len].copy_from_slice(&data[..len]);
            out.data_len = (3 + len) as u16;
        }

        // --- MEDIUM — Pairing events ---
        sle_dli::SleEvent::PairInfoExchange {
            handle,
            io_cap,
            oob_flag,
            auth_req,
            max_key_len,
            sec_dist,
            psk_ind,
            crypto_cap,
        } => {
            out.event_type = 0x18;
            out.handle = *handle;
            out.data[0] = *io_cap;
            out.data[1] = *oob_flag;
            out.data[2] = *auth_req;
            out.data[3] = *max_key_len;
            out.data[4] = *sec_dist;
            out.data[5] = *psk_ind;
            out.data[6..10].copy_from_slice(crypto_cap);
            out.data_len = 10;
        }
        sle_dli::SleEvent::PairInfoReport {
            handle,
            io_cap,
            oob_flag,
            auth_req,
            max_key_len,
            sec_dist,
            psk_ind,
            crypto_cap,
        } => {
            out.event_type = 0x19;
            out.handle = *handle;
            out.data[0] = *io_cap;
            out.data[1] = *oob_flag;
            out.data[2] = *auth_req;
            out.data[3] = *max_key_len;
            out.data[4] = *sec_dist;
            out.data[5] = *psk_ind;
            out.data[6..10].copy_from_slice(crypto_cap);
            out.data_len = 10;
        }
        sle_dli::SleEvent::PairOptionReport {
            handle,
            key_len,
            auth_method,
            crypto_alg,
            public_key,
        } => {
            out.event_type = 0x1A;
            out.handle = *handle;
            out.data[0] = *key_len;
            out.data[1] = *auth_method;
            out.data[2..6].copy_from_slice(crypto_alg);
            let len = public_key.len().min(32);
            out.data[6..6 + len].copy_from_slice(&public_key[..len]);
            out.data_len = (6 + len) as u16;
        }
        sle_dli::SleEvent::PeerPublicKey { handle, public_key } => {
            out.event_type = 0x1B;
            out.handle = *handle;
            let len = public_key.len().min(32);
            out.data[..len].copy_from_slice(&public_key[..len]);
            out.data_len = len as u16;
        }
        sle_dli::SleEvent::PairExtData {
            handle,
            ext_pubkey_x,
            ext_pubkey_y,
        } => {
            out.event_type = 0x1C;
            out.handle = *handle;
            let lx = ext_pubkey_x.len().min(32);
            out.data[..lx].copy_from_slice(&ext_pubkey_x[..lx]);
            let ly = ext_pubkey_y.len().min(32);
            out.data[32..32 + ly].copy_from_slice(&ext_pubkey_y[..ly]);
            out.data_len = (32 + ly) as u16;
        }
        sle_dli::SleEvent::KeypressNotify { handle, action } => {
            out.event_type = 0x1D;
            out.handle = *handle;
            out.data[..4].copy_from_slice(action);
            out.data_len = 4;
        }
        sle_dli::SleEvent::PairRandom { handle, random } => {
            out.event_type = 0x1E;
            out.handle = *handle;
            out.data[..16].copy_from_slice(random);
            out.data_len = 16;
        }
        sle_dli::SleEvent::PairConfirm { handle, confirm } => {
            out.event_type = 0x1F;
            out.handle = *handle;
            out.data[..16].copy_from_slice(confirm);
            out.data_len = 16;
        }
        sle_dli::SleEvent::DHKeyCheck {
            handle,
            dhkey_check,
        } => {
            out.event_type = 0x20;
            out.handle = *handle;
            out.data[..16].copy_from_slice(dhkey_check);
            out.data_len = 16;
        }
        sle_dli::SleEvent::PairFailure { handle, reason } => {
            out.event_type = 0x21;
            out.handle = *handle;
            out.data[0] = *reason;
            out.data_len = 1;
        }

        // --- LOW — Measurement events ---
        sle_dli::SleEvent::NarrowbandMeasInfo {
            handle,
            meas_type,
            status,
            config_index,
        } => {
            out.event_type = 0x22;
            out.handle = *handle;
            out.status = *status;
            out.data[0] = (*meas_type & 0xFF) as u8;
            out.data[1] = (*meas_type >> 8) as u8;
            out.data[2] = *config_index;
            out.data_len = 3;
        }
        sle_dli::SleEvent::NarrowbandMeasStateChange {
            status,
            config_index,
            meas_state,
        } => {
            out.event_type = 0x23;
            out.status = *status;
            out.data[0] = *config_index;
            out.data[1] = *meas_state;
            out.data_len = 2;
        }
        sle_dli::SleEvent::NarrowbandMeasParamReport {
            handle,
            status,
            config_index,
        } => {
            out.event_type = 0x24;
            out.handle = *handle;
            out.status = *status;
            out.data[0] = *config_index;
            out.data_len = 1;
        }
        sle_dli::SleEvent::LocalNarrowbandMeasCap {
            status,
            antenna_count,
            signal_cap,
            report_cap,
        } => {
            out.event_type = 0x25;
            out.status = *status;
            out.data[0] = *antenna_count;
            out.data[1..5].copy_from_slice(signal_cap);
            out.data[5..9].copy_from_slice(report_cap);
            out.data_len = 9;
        }
        sle_dli::SleEvent::PeerNarrowbandMeasCap {
            handle,
            status,
            antenna_count,
            signal_cap,
            report_cap,
        } => {
            out.event_type = 0x26;
            out.handle = *handle;
            out.status = *status;
            out.data[0] = *antenna_count;
            out.data[1..5].copy_from_slice(signal_cap);
            out.data[5..9].copy_from_slice(report_cap);
            out.data_len = 9;
        }
        sle_dli::SleEvent::MeasStateChange {
            source,
            status,
            instance_handle,
            instance_state,
        } => {
            out.event_type = 0x27;
            out.status = *status;
            out.data[0] = (*source & 0xFF) as u8;
            out.data[1] = (*source >> 8) as u8;
            out.data[2] = *instance_handle;
            out.data[3] = *instance_state;
            out.data_len = 4;
        }
        sle_dli::SleEvent::MeasQuantityReport {
            source,
            meas_source,
            seq,
            instance_handle,
            meas_count,
        } => {
            out.event_type = 0x28;
            out.data[0] = (*source & 0xFF) as u8;
            out.data[1] = (*source >> 8) as u8;
            out.data[2] = (*meas_source & 0xFF) as u8;
            out.data[3] = (*meas_source >> 8) as u8;
            out.data[4] = (*seq & 0xFF) as u8;
            out.data[5] = (*seq >> 8) as u8;
            out.data[6] = *instance_handle;
            out.data[7] = *meas_count;
            out.data_len = 8;
        }

        // --- LOW — SLB events ---
        sle_dli::SleEvent::SlbAdvReport {
            mac_addr,
            channel,
            bandwidth,
            rssi,
            data,
        } => {
            out.event_type = 0x29;
            out.addr = *mac_addr;
            out.data[0] = (*channel & 0xFF) as u8;
            out.data[1] = (*channel >> 8) as u8;
            out.data[2] = *bandwidth;
            out.data[3] = *rssi as u8;
            let len = data.len().min(236);
            out.data[4..4 + len].copy_from_slice(&data[..len]);
            out.data_len = (4 + len) as u16;
        }
        sle_dli::SleEvent::SlbConnComplete {
            handle,
            status,
            peer_addr,
        } => {
            out.event_type = 0x2A;
            out.handle = *handle;
            out.status = *status;
            out.addr = *peer_addr;
        }
        sle_dli::SleEvent::SlbUcastChannelComplete {
            channel_handle,
            conn_handle,
            status,
            max_pkt_len,
            max_pkt_count,
        } => {
            out.event_type = 0x2B;
            out.handle = *channel_handle;
            out.status = *status;
            out.data[0] = (*conn_handle & 0xFF) as u8;
            out.data[1] = (*conn_handle >> 8) as u8;
            out.data[2] = (*max_pkt_len & 0xFF) as u8;
            out.data[3] = (*max_pkt_len >> 8) as u8;
            out.data[4] = (*max_pkt_count & 0xFF) as u8;
            out.data[5] = (*max_pkt_count >> 8) as u8;
            out.data_len = 6;
        }
        sle_dli::SleEvent::SlbUcastChannelUpdate {
            channel_handle,
            status,
            max_pkt_len,
            max_pkt_count,
        } => {
            out.event_type = 0x2C;
            out.handle = *channel_handle;
            out.status = *status;
            out.data[0] = (*max_pkt_len & 0xFF) as u8;
            out.data[1] = (*max_pkt_len >> 8) as u8;
            out.data[2] = (*max_pkt_count & 0xFF) as u8;
            out.data[3] = (*max_pkt_count >> 8) as u8;
            out.data_len = 4;
        }
        sle_dli::SleEvent::SlbChannelDelete {
            channel_handle,
            status,
        } => {
            out.event_type = 0x2D;
            out.handle = *channel_handle;
            out.status = *status;
        }
        sle_dli::SleEvent::SlbNumCompletedPackets {
            channel_handle,
            num_completed,
        } => {
            out.event_type = 0x2E;
            out.handle = *channel_handle;
            out.data[0] = *num_completed;
            out.data_len = 1;
        }

        // --- LOW — Sync Link events ---
        sle_dli::SleEvent::TimeSyncStatusUpdate {
            sync_status,
            clock_source,
            accuracy,
        } => {
            out.event_type = 0x2F;
            out.data[0] = *sync_status;
            out.data[1] = *clock_source;
            out.data[2] = (*accuracy & 0xFF) as u8;
            out.data[3] = ((*accuracy >> 8) & 0xFF) as u8;
            out.data[4] = ((*accuracy >> 16) & 0xFF) as u8;
            out.data[5] = ((*accuracy >> 24) & 0xFF) as u8;
            out.data_len = 6;
        }
        sle_dli::SleEvent::TimeSyncRequest {
            time_seq,
            send_time,
        } => {
            out.event_type = 0x30;
            out.data[0] = (*time_seq & 0xFF) as u8;
            out.data[1] = ((*time_seq >> 8) & 0xFF) as u8;
            out.data[2] = ((*time_seq >> 16) & 0xFF) as u8;
            out.data[3] = ((*time_seq >> 24) & 0xFF) as u8;
            out.data[4..12].copy_from_slice(send_time);
            out.data_len = 12;
        }
        sle_dli::SleEvent::SyncUcastSetupRequest {
            async_handle,
            sync_handle,
            event_group_set_id,
            event_group_id,
        } => {
            out.event_type = 0x31;
            out.handle = *async_handle;
            out.data[0] = (*sync_handle & 0xFF) as u8;
            out.data[1] = (*sync_handle >> 8) as u8;
            out.data[2] = *event_group_set_id;
            out.data[3] = *event_group_id;
            out.data_len = 4;
        }
        sle_dli::SleEvent::SyncUcastSetupComplete {
            async_handle,
            sync_handle,
            status,
        } => {
            out.event_type = 0x32;
            out.handle = *async_handle;
            out.status = *status;
            out.data[0] = (*sync_handle & 0xFF) as u8;
            out.data[1] = (*sync_handle >> 8) as u8;
            out.data_len = 2;
        }
        sle_dli::SleEvent::SyncMcastSetupRequest {
            async_handle,
            sync_handle,
        } => {
            out.event_type = 0x33;
            out.handle = *async_handle;
            out.data[0] = (*sync_handle & 0xFF) as u8;
            out.data[1] = (*sync_handle >> 8) as u8;
            out.data_len = 2;
        }
        sle_dli::SleEvent::SyncMcastSetupComplete {
            async_handle,
            sync_handle,
            status,
        } => {
            out.event_type = 0x34;
            out.handle = *async_handle;
            out.status = *status;
            out.data[0] = (*sync_handle & 0xFF) as u8;
            out.data[1] = (*sync_handle >> 8) as u8;
            out.data_len = 2;
        }
    }
    out
}
