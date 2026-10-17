fn sle_dli_event_to_broadcast(ev: &sle_dli::SleEvent) -> sle_event::SleWireEvent {
    match ev {
        sle_dli::SleEvent::NativeCommandReply { opcode, status, complete, data, .. } => {
            if *complete {
                sle_event::SleWireEvent::command_complete(*opcode, *status, data.as_slice())
            } else {
                sle_event::SleWireEvent::command_status(*opcode, *status)
            }
        }
        sle_dli::SleEvent::CommandCredits { credits } => {
            sle_event::SleWireEvent::command_complete(0, 0, &[*credits])
        }
        sle_dli::SleEvent::CommandComplete {
            opcode,
            status,
            data,
            ..
        } => sle_event::SleWireEvent::command_complete(
            *opcode as u16,
            *status as u8,
            data.as_slice(),
        ),
        sle_dli::SleEvent::CommandStatus { opcode, status, .. } => {
            sle_event::SleWireEvent::command_status(*opcode as u16, *status as u8)
        }
        sle_dli::SleEvent::ConnComplete {
            handle,
            addr,
            status,
        } => {
            let new_state = if *status == sle_dli::SleStatus::Success {
                2u8
            } else {
                0u8
            };
            sle_event::SleWireEvent::conn_state(*handle, 1, new_state, *addr, *status as u8)
        }
        sle_dli::SleEvent::Disconnected { handle, reason } => {
            sle_event::SleWireEvent::conn_state(*handle, 2, 0, [0u8; 6], *reason)
        }
        sle_dli::SleEvent::AdvReport {
            addr,
            rssi,
            discovery_level,
            data,
        } => sle_event::SleWireEvent::adv_report(*addr, *rssi, *discovery_level, data.as_slice()),
        sle_dli::SleEvent::DataReceived { handle, data } => {
            sle_event::SleWireEvent::data_received(*handle, data.len() as u16)
        }
        sle_dli::SleEvent::HardwareError { code } => sle_event::SleWireEvent::hardware_error(*code),
        sle_dli::SleEvent::EncryptionChanged { handle, enabled } => {
            // Map to SecurityChanged wire event.
            sle_event::SleWireEvent::conn_state(
                *handle,
                0,
                if *enabled { 1 } else { 0 },
                [0u8; 6],
                0,
            )
        }
        sle_dli::SleEvent::PairRequest { addr, .. } => {
            sle_event::SleWireEvent::conn_state(0, 0, 0, *addr, 0)
        }
        sle_dli::SleEvent::BroadcastEnd { reason } => {
            sle_event::SleWireEvent::broadcast_end(*reason)
        }
        sle_dli::SleEvent::PhyUpdate {
            handle,
            mcs_index,
            bandwidth_mhz,
        } => sle_event::SleWireEvent::phy_update(*handle, *mcs_index, *bandwidth_mhz),
        sle_dli::SleEvent::ConnParamUpdate {
            handle,
            interval,
            latency,
            timeout,
        } => sle_event::SleWireEvent::conn_param_update(*handle, *interval, *latency, *timeout),
        sle_dli::SleEvent::DataLenChange {
            handle,
            max_tx_octets,
            max_rx_octets,
        } => sle_event::SleWireEvent::data_len_change(*handle, *max_tx_octets, *max_rx_octets),
        sle_dli::SleEvent::DataBufOverflow { link_type } => {
            sle_event::SleWireEvent::data_buf_overflow(*link_type)
        }
        sle_dli::SleEvent::PeerConnParamReq {
            handle,
            interval_min,
            interval_max,
            latency,
            timeout,
        } => sle_event::SleWireEvent::peer_conn_param_req(
            *handle,
            *interval_min,
            *interval_max,
            *latency,
            *timeout,
        ),

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
        } => sle_event::SleWireEvent::power_change_report(
            *handle,
            *reason,
            *frame_type,
            *bandwidth,
            *pilot_density,
            *tx_power,
            *power_level,
            *offset,
        ),
        sle_dli::SleEvent::NumCompletedPackets {
            handle,
            num_completed,
        } => sle_event::SleWireEvent::num_completed_packets(*handle, *num_completed),
        sle_dli::SleEvent::EncryptionParamReq { handle } => {
            sle_event::SleWireEvent::encryption_param_req(*handle)
        }

        // --- MEDIUM — Peer Info events ---
        sle_dli::SleEvent::ControllerSignalData {
            handle,
            signal_id,
            data,
        } => {
            let mut evt = sle_event::ControllerSignalDataEvent {
                handle: *handle,
                signal_id: *signal_id,
                data_len: data.len().min(32) as u8,
                _pad: 0,
                data: [0u8; 32],
            };
            let len = data.len().min(32);
            evt.data[..len].copy_from_slice(&data[..len]);
            sle_event::SleWireEvent::from_payload_pub(
                sle_event::SleEventType::ControllerSignalData,
                &evt,
            )
        }
        sle_dli::SleEvent::ReadPeerFeatures {
            handle,
            status,
            features,
        } => {
            let evt = sle_event::ReadPeerFeaturesEvent {
                handle: *handle,
                status: *status,
                _pad: 0,
                features: *features,
            };
            sle_event::SleWireEvent::from_payload_pub(
                sle_event::SleEventType::ReadPeerFeatures,
                &evt,
            )
        }
        sle_dli::SleEvent::ReadPeerVersion {
            handle,
            status,
            version,
            manufacturer,
            subversion,
        } => {
            let evt = sle_event::ReadPeerVersionEvent {
                handle: *handle,
                manufacturer: *manufacturer,
                subversion: *subversion,
                status: *status,
                version: *version,
            };
            sle_event::SleWireEvent::from_payload_pub(
                sle_event::SleEventType::ReadPeerVersion,
                &evt,
            )
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
            let evt = sle_event::ReadPeerPowerEvent {
                handle: *handle,
                status: *status,
                frame_type: *frame_type,
                bandwidth: *bandwidth,
                pilot_density: *pilot_density,
                tx_power: *tx_power,
                power_level: *power_level,
            };
            sle_event::SleWireEvent::from_payload_pub(sle_event::SleEventType::ReadPeerPower, &evt)
        }
        sle_dli::SleEvent::InquiryRequestReport {
            adv_handle,
            addr_type,
            addr,
            rssi,
            ..
        } => {
            let evt = sle_event::InquiryRequestReportEvent {
                addr: *addr,
                addr_type: *addr_type,
                adv_handle: *adv_handle,
                rssi: *rssi,
                data_len: 0,
                _pad: [0u8; 2],
            };
            sle_event::SleWireEvent::from_payload_pub(
                sle_event::SleEventType::InquiryRequestReport,
                &evt,
            )
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
            let evt = sle_event::PairInfoEvent {
                handle: *handle,
                io_cap: *io_cap,
                oob_flag: *oob_flag,
                auth_req: *auth_req,
                max_key_len: *max_key_len,
                sec_dist: *sec_dist,
                psk_ind: *psk_ind,
                crypto_cap: *crypto_cap,
            };
            sle_event::SleWireEvent::from_payload_pub(
                sle_event::SleEventType::PairInfoExchangeReq,
                &evt,
            )
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
            let evt = sle_event::PairInfoEvent {
                handle: *handle,
                io_cap: *io_cap,
                oob_flag: *oob_flag,
                auth_req: *auth_req,
                max_key_len: *max_key_len,
                sec_dist: *sec_dist,
                psk_ind: *psk_ind,
                crypto_cap: *crypto_cap,
            };
            sle_event::SleWireEvent::from_payload_pub(sle_event::SleEventType::PairInfoReport, &evt)
        }
        sle_dli::SleEvent::PairOptionReport {
            handle,
            key_len,
            auth_method,
            crypto_alg,
            public_key,
        } => {
            let mut evt = sle_event::PairOptionReportEvent {
                handle: *handle,
                key_len: *key_len,
                auth_method: *auth_method,
                crypto_alg: *crypto_alg,
                public_key: [0u8; 32],
            };
            let len = public_key.len().min(32);
            evt.public_key[..len].copy_from_slice(&public_key[..len]);
            sle_event::SleWireEvent::from_payload_pub(
                sle_event::SleEventType::PairOptionReport,
                &evt,
            )
        }
        sle_dli::SleEvent::PeerPublicKey { handle, public_key } => {
            let mut evt = sle_event::PeerPublicKeyReportEvent {
                handle: *handle,
                _pad: [0u8; 2],
                public_key: [0u8; 32],
            };
            let len = public_key.len().min(32);
            evt.public_key[..len].copy_from_slice(&public_key[..len]);
            sle_event::SleWireEvent::from_payload_pub(
                sle_event::SleEventType::PeerPublicKeyReport,
                &evt,
            )
        }
        sle_dli::SleEvent::PairExtData {
            handle,
            ext_pubkey_x,
            ..
        } => {
            let mut evt = sle_event::PairExtDataReportEvent {
                handle: *handle,
                _pad: [0u8; 2],
                ext_key_data: [0u8; 36],
            };
            let len = ext_pubkey_x.len().min(32);
            evt.ext_key_data[..len].copy_from_slice(&ext_pubkey_x[..len]);
            sle_event::SleWireEvent::from_payload_pub(
                sle_event::SleEventType::PairExtDataReport,
                &evt,
            )
        }
        sle_dli::SleEvent::KeypressNotify { handle, action } => {
            let evt = sle_event::KeypressNotificationEvent {
                handle: *handle,
                _pad: [0u8; 2],
                action: *action,
            };
            sle_event::SleWireEvent::from_payload_pub(
                sle_event::SleEventType::KeypressNotification,
                &evt,
            )
        }
        sle_dli::SleEvent::PairRandom { handle, random } => {
            let evt = sle_event::PairRandomReportEvent {
                handle: *handle,
                _pad: [0u8; 2],
                random: *random,
            };
            sle_event::SleWireEvent::from_payload_pub(
                sle_event::SleEventType::PairRandomReport,
                &evt,
            )
        }
        sle_dli::SleEvent::PairConfirm { handle, confirm } => {
            let evt = sle_event::PairConfirmReportEvent {
                handle: *handle,
                _pad: [0u8; 2],
                confirm: *confirm,
            };
            sle_event::SleWireEvent::from_payload_pub(
                sle_event::SleEventType::PairConfirmReport,
                &evt,
            )
        }
        sle_dli::SleEvent::DHKeyCheck {
            handle,
            dhkey_check,
        } => {
            let evt = sle_event::DHKeyCheckReportEvent {
                handle: *handle,
                _pad: [0u8; 2],
                dhkey_check: *dhkey_check,
            };
            sle_event::SleWireEvent::from_payload_pub(
                sle_event::SleEventType::DHKeyCheckReport,
                &evt,
            )
        }
        sle_dli::SleEvent::PairFailure { handle, reason } => {
            let evt = sle_event::PairFailureReportEvent {
                handle: *handle,
                reason: *reason,
                _pad: 0,
            };
            sle_event::SleWireEvent::from_payload_pub(
                sle_event::SleEventType::PairFailureReport,
                &evt,
            )
        }

        // --- LOW — Measurement events ---
        sle_dli::SleEvent::NarrowbandMeasInfo {
            handle,
            meas_type,
            status,
            config_index,
        } => {
            let evt = sle_event::NarrowbandMeasInfoEvent {
                handle: *handle,
                meas_type: *meas_type,
                status: *status,
                config_index: *config_index,
                _pad: [0u8; 2],
            };
            sle_event::SleWireEvent::from_payload_pub(
                sle_event::SleEventType::NarrowbandMeasInfo,
                &evt,
            )
        }
        sle_dli::SleEvent::NarrowbandMeasStateChange {
            status,
            config_index,
            meas_state,
        } => {
            let evt = sle_event::NarrowbandMeasStateChangeEvent {
                status: *status,
                config_index: *config_index,
                meas_state: *meas_state,
                _pad: 0,
            };
            sle_event::SleWireEvent::from_payload_pub(
                sle_event::SleEventType::NarrowbandMeasStateChange,
                &evt,
            )
        }
        sle_dli::SleEvent::NarrowbandMeasParamReport {
            handle,
            status,
            config_index,
        } => {
            let evt = sle_event::NarrowbandMeasParamReportEvent {
                handle: *handle,
                status: *status,
                config_index: *config_index,
            };
            sle_event::SleWireEvent::from_payload_pub(
                sle_event::SleEventType::NarrowbandMeasParamReport,
                &evt,
            )
        }
        sle_dli::SleEvent::LocalNarrowbandMeasCap {
            status,
            antenna_count,
            signal_cap,
            report_cap,
        } => {
            let evt = sle_event::LocalNarrowbandMeasCapEvent {
                status: *status,
                antenna_count: *antenna_count,
                signal_cap: *signal_cap,
                report_cap: *report_cap,
            };
            sle_event::SleWireEvent::from_payload_pub(
                sle_event::SleEventType::LocalNarrowbandMeasCap,
                &evt,
            )
        }
        sle_dli::SleEvent::PeerNarrowbandMeasCap {
            handle,
            status,
            antenna_count,
            signal_cap,
            report_cap,
        } => {
            let evt = sle_event::PeerNarrowbandMeasCapEvent {
                handle: *handle,
                status: *status,
                antenna_count: *antenna_count,
                signal_cap: *signal_cap,
                report_cap: *report_cap,
            };
            sle_event::SleWireEvent::from_payload_pub(
                sle_event::SleEventType::PeerNarrowbandMeasCap,
                &evt,
            )
        }
        sle_dli::SleEvent::MeasStateChange {
            source,
            status,
            instance_handle,
            instance_state,
        } => {
            let evt = sle_event::MeasStateChangeEvent {
                source: *source,
                status: *status,
                instance_handle: *instance_handle,
                instance_state: *instance_state,
                _pad: [0u8; 3],
            };
            sle_event::SleWireEvent::from_payload_pub(
                sle_event::SleEventType::MeasStateChange,
                &evt,
            )
        }
        sle_dli::SleEvent::MeasQuantityReport {
            source,
            meas_source,
            seq,
            instance_handle,
            meas_count,
        } => {
            let evt = sle_event::MeasQuantityReportEvent {
                source: *source,
                meas_source: *meas_source,
                seq: *seq,
                instance_handle: *instance_handle,
                meas_count: *meas_count,
            };
            sle_event::SleWireEvent::from_payload_pub(
                sle_event::SleEventType::MeasQuantityReport,
                &evt,
            )
        }

        // --- LOW — SLB events ---
        sle_dli::SleEvent::SlbAdvReport {
            mac_addr,
            channel,
            bandwidth,
            rssi,
            ..
        } => {
            let evt = sle_event::SlbAdvReportEvent {
                mac_addr: *mac_addr,
                channel: *channel,
                bandwidth: *bandwidth,
                rssi: *rssi,
                data_len: 0,
                _pad: 0,
            };
            sle_event::SleWireEvent::from_payload_pub(sle_event::SleEventType::SlbAdvReport, &evt)
        }
        sle_dli::SleEvent::SlbConnComplete {
            handle,
            status,
            peer_addr,
        } => {
            let evt = sle_event::SlbConnCompleteEvent {
                handle: *handle,
                status: *status,
                _pad: 0,
                peer_addr: *peer_addr,
                _pad2: [0u8; 2],
            };
            sle_event::SleWireEvent::from_payload_pub(
                sle_event::SleEventType::SlbConnComplete,
                &evt,
            )
        }
        sle_dli::SleEvent::SlbUcastChannelComplete {
            channel_handle,
            conn_handle,
            status,
            max_pkt_len,
            max_pkt_count,
        } => {
            let evt = sle_event::SlbUcastChannelCompleteEvent {
                channel_handle: *channel_handle,
                conn_handle: *conn_handle,
                max_pkt_len: *max_pkt_len,
                max_pkt_count: *max_pkt_count,
                status: *status,
                _pad: 0,
            };
            sle_event::SleWireEvent::from_payload_pub(
                sle_event::SleEventType::SlbUcastChannelComplete,
                &evt,
            )
        }
        sle_dli::SleEvent::SlbUcastChannelUpdate {
            channel_handle,
            status,
            max_pkt_len,
            max_pkt_count,
        } => {
            let evt = sle_event::SlbUcastChannelUpdateEvent {
                channel_handle: *channel_handle,
                max_pkt_len: *max_pkt_len,
                max_pkt_count: *max_pkt_count,
                status: *status,
                _pad: 0,
            };
            sle_event::SleWireEvent::from_payload_pub(
                sle_event::SleEventType::SlbUcastChannelUpdate,
                &evt,
            )
        }
        sle_dli::SleEvent::SlbChannelDelete {
            channel_handle,
            status,
        } => {
            let evt = sle_event::SlbChannelDeleteEvent {
                channel_handle: *channel_handle,
                status: *status,
                _pad: 0,
            };
            sle_event::SleWireEvent::from_payload_pub(
                sle_event::SleEventType::SlbChannelDelete,
                &evt,
            )
        }
        sle_dli::SleEvent::SlbNumCompletedPackets {
            channel_handle,
            num_completed,
        } => {
            let evt = sle_event::SlbNumCompletedPacketsEvent {
                channel_handle: *channel_handle,
                num_completed: *num_completed,
                _pad: 0,
            };
            sle_event::SleWireEvent::from_payload_pub(
                sle_event::SleEventType::SlbNumCompletedPackets,
                &evt,
            )
        }

        // --- LOW — Sync Link events ---
        sle_dli::SleEvent::TimeSyncStatusUpdate {
            sync_status,
            clock_source,
            accuracy,
        } => {
            let evt = sle_event::TimeSyncStatusUpdateEvent {
                accuracy: *accuracy,
                sync_status: *sync_status,
                clock_source: *clock_source,
                _pad: [0u8; 2],
            };
            sle_event::SleWireEvent::from_payload_pub(
                sle_event::SleEventType::TimeSyncStatusUpdate,
                &evt,
            )
        }
        sle_dli::SleEvent::TimeSyncRequest {
            time_seq,
            send_time,
        } => {
            let evt = sle_event::TimeSyncRequestEvent {
                time_seq: *time_seq,
                send_time: *send_time,
            };
            sle_event::SleWireEvent::from_payload_pub(
                sle_event::SleEventType::TimeSyncRequest,
                &evt,
            )
        }
        sle_dli::SleEvent::SyncUcastSetupRequest {
            async_handle,
            sync_handle,
            event_group_set_id,
            event_group_id,
        } => {
            let evt = sle_event::SyncUcastSetupRequestEvent {
                async_handle: *async_handle,
                sync_handle: *sync_handle,
                event_group_set_id: *event_group_set_id,
                event_group_id: *event_group_id,
                _pad: [0u8; 2],
            };
            sle_event::SleWireEvent::from_payload_pub(
                sle_event::SleEventType::SyncUcastSetupRequest,
                &evt,
            )
        }
        sle_dli::SleEvent::SyncUcastSetupComplete {
            async_handle,
            sync_handle,
            status,
        } => {
            let evt = sle_event::SyncUcastSetupCompleteEvent {
                async_handle: *async_handle,
                sync_handle: *sync_handle,
                status: *status,
                _pad: [0u8; 3],
            };
            sle_event::SleWireEvent::from_payload_pub(
                sle_event::SleEventType::SyncUcastSetupComplete,
                &evt,
            )
        }
        sle_dli::SleEvent::SyncMcastSetupRequest {
            async_handle,
            sync_handle,
        } => {
            let evt = sle_event::SyncMcastSetupRequestEvent {
                async_handle: *async_handle,
                sync_handle: *sync_handle,
            };
            sle_event::SleWireEvent::from_payload_pub(
                sle_event::SleEventType::SyncMcastSetupRequest,
                &evt,
            )
        }
        sle_dli::SleEvent::SyncMcastSetupComplete {
            async_handle,
            sync_handle,
            status,
        } => {
            let evt = sle_event::SyncMcastSetupCompleteEvent {
                async_handle: *async_handle,
                sync_handle: *sync_handle,
                status: *status,
                _pad: [0u8; 3],
            };
            sle_event::SleWireEvent::from_payload_pub(
                sle_event::SleEventType::SyncMcastSetupComplete,
                &evt,
            )
        }
    }
}
