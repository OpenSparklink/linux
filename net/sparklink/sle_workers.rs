// SPDX-License-Identifier: GPL-2.0

//! Background workers for SparkLink subsystem.
//!
//! Every ControllerRuntime embeds separate RX and TX delayed work. Queue-owned
//! Arc references keep that registration alive without an owner/worker cycle.

use kernel::prelude::*;
use kernel::sync::Arc;
use kernel::time::msecs_to_jiffies;
use kernel::workqueue::{self, impl_has_delayed_work, DelayedWork, WorkItem};
use pin_init::init_array_from_fn;

use super::genl_bridge;
use super::sle_conn;
use super::sle_dli;
use super::sle_dli::SleController;
use super::sle_event;
use super::sle_ssap;
use super::sle_uapi::*;
use super::sle_usb;
use super::{ControllerRuntime, ControllerState};

/// Flush executes the callback so Rust reclaims the queue-owned Arc. Call only
/// with the scheduling gate closed, retaining the owner and holding no locks.
fn flush_work<T, const ID: u64>(work: &DelayedWork<T, ID>) {
    // SAFETY: owner Arc is retained and the initialized delayed work is pinned.
    let raw = unsafe { workqueue::Work::raw_get(DelayedWork::raw_as_work(work)) };
    // SAFETY: raw_as_work yields this delayed_work's work field.
    let delayed = unsafe { kernel::container_of!(raw, kernel::bindings::delayed_work, work) };
    // SAFETY: no scheduling or self-rearm can occur after the gate closes.
    unsafe { kernel::bindings::flush_delayed_work(delayed) };
}

/// Heartbeat interval for supervision timeouts and cleanup (ms).
/// The pump no longer self-schedules at this interval for event
/// processing — it is kicked immediately by producers.  The heartbeat
/// ensures periodic maintenance even when no events arrive.
const EVENT_PUMP_HEARTBEAT_MS: u32 = 500;

type TaggedEventBatch = [(Option<u16>, Option<sle_dli::SleEvent>); 64];

/// Construct RX staging directly on the heap. Inline draining can run under
/// an ioctl frame and must leave room for connection creation and allocation.
fn new_event_batch() -> Result<KBox<TaggedEventBatch>> {
    KBox::init(init_array_from_fn(|_| (None, None)), GFP_KERNEL)
}

impl_has_delayed_work! {
    impl HasDelayedWork<ControllerRuntime, 0> for ControllerRuntime { self.rx_work }
    impl HasDelayedWork<ControllerRuntime, 1> for ControllerRuntime { self.tx_work }
}

// ---------------------------------------------------------------------------
// Unified controller event processing
// ---------------------------------------------------------------------------

/// Consume the retained management reply under this owner's protocol mutex.
/// Generic/discovery ingress pressure cannot steal the result or its sequence.
fn process_host_reply(owner: &Arc<ControllerRuntime>, state: &mut ControllerState) -> bool {
    let reply = owner.host.lock().take_reply();
    let Some(reply) = reply else {
        return false;
    };
    match &reply.event {
        sle_dli::SleEvent::CommandComplete { status, data, .. } => {
            state
                .cmd_pending
                .resolve_seq(reply.seq, *status as u8, data.as_slice());
        }
        sle_dli::SleEvent::CommandStatus { status, .. }
            if *status != sle_dli::SleStatus::Success =>
        {
            state.cmd_pending.resolve_seq(reply.seq, *status as u8, &[]);
            if let Some(addr) = reply.peer_addr {
                state.conn.abort_controller_connect(&addr);
            }
        }
        sle_dli::SleEvent::NativeCommandReply { status, complete, data, .. }
            if *complete || *status != 0 =>
        {
            state.cmd_pending.resolve_seq(reply.seq, *status, data.as_slice());
        }
        _ => {} // Successful Status awaits a domain-specific terminal event.
    }
    // A disable or superseded enable response must not confirm a newer
    // pending start that happens to use the same DLI opcode.
    // Failure of an older disable barrier must also abort a newer pending
    // start whose parameters cannot safely follow that failed disable.
    let barrier_failed = reply.recipe.is_some_and(|(intent, outcome)|
        !intent.enabled() && outcome == super::sle_command_plan::RecipeReply::Failed);
    if reply.current_intent || barrier_failed {
        if let Some((intent, outcome)) = reply.recipe {
            use super::sle_command_plan::{DiscoveryIntent, RecipeReply};
            match (intent, outcome) {
                (DiscoveryIntent::Advertising(_) | DiscoveryIntent::AdvertisingStandby, RecipeReply::Failed) => state.adv_scan.abort_advertising(),
                (DiscoveryIntent::Scanning(_), RecipeReply::Failed) => state.adv_scan.abort_scanning(),
                (DiscoveryIntent::Advertising(true), RecipeReply::Finished) => state.adv_scan.confirm_advertising(),
                (DiscoveryIntent::Scanning(true), RecipeReply::Finished) => state.adv_scan.confirm_scanning(),
                _ => {}
            }
        } else if let sle_dli::SleEvent::CommandComplete { opcode, status, .. } = &reply.event {
            match opcode {
                sle_dli::SleOpcode::EnableBroadcast => {
                    if reply.enable == Some(true) && *status == sle_dli::SleStatus::Success {
                        state.adv_scan.confirm_advertising();
                    } else if *status != sle_dli::SleStatus::Success {
                        state.adv_scan.abort_advertising();
                    }
                }
                sle_dli::SleOpcode::EnableScan => {
                    if reply.enable == Some(true) && *status == sle_dli::SleStatus::Success {
                        state.adv_scan.confirm_scanning();
                    } else if *status != sle_dli::SleStatus::Success {
                        state.adv_scan.abort_scanning();
                    }
                }
                _ => {}
            }
        }
    }
    process_controller_event(state, &reply.event);
    owner.kick_commands();
    true
}

fn fail_host(owner: &Arc<ControllerRuntime>, state: &mut ControllerState, error: Error) {
    let mut host = owner.host.lock();
    if let Some(seq) = host.fail(error) {
        state.cmd_pending.resolve_seq(seq, 0x03, &[]);
    }
    while let Some(request) = host.cancel_next() {
        state.cmd_pending.resolve_seq(request.seq, 0x03, &[]);
    }
    state.adv_scan.abort_advertising();
    state.adv_scan.abort_scanning();
}

/// Send a credit grant PDU on the management channel (CMTC).
///
/// Format per T/XS 20002-2025 §7.3.3 control signaling:
/// `[TCID_CMTC] [code=0xFC] [identifier] [length LE16=0x0003] [target_tcid] [credits LE16]`
pub(crate) fn send_credit_grant(
    ctrl: &sle_dli::ControllerBackend,
    handle: u16,
    target_tcid: u16,
    credits: u16,
    identifier: u8,
) {
    let mut buf = [0u8; sle_conn::CREDIT_GRANT_PDU_SIZE];
    buf[0] = sle_conn::tcid::MANAGEMENT as u8;
    buf[1] = sle_conn::CREDIT_GRANT_PDU_TYPE;
    buf[2] = identifier;
    buf[3] = 0x03; // length LE16 low byte: target_tcid(1) + credits(2)
    buf[4] = 0x00; // length LE16 high byte
    buf[5] = target_tcid as u8;
    let c = credits.to_le_bytes();
    buf[6] = c[0];
    buf[7] = c[1];
    let _ = ctrl.send_data(handle, &buf);
}

/// Process a single controller event: resolve pending commands, drive
/// state machine transitions, and publish to broadcast ring / DLI ring.
///
/// Called from both `EventPump` (periodic background) and inline after
/// ioctl commands (immediate drain for synchronous controller backends).
#[inline(never)]
pub(crate) fn process_controller_event(shared: &mut ControllerState, ev: &sle_dli::SleEvent) {
    // Credits are an absolute controller advertisement, not an increment.
    // A successful CommandStatus accepts asynchronous work; it does not finish it.
    // USB raw results are resolved by the Host's captured sequence, below.
    // Unmatched or internal USB responses must never consume a raw entry.
    if !shared.controller.uses_command_host() {
        match ev {
            sle_dli::SleEvent::CommandCredits { credits } => shared.command_credits = *credits,
            sle_dli::SleEvent::CommandComplete {
                opcode,
                command_credits,
                status,
                data,
            } => {
                shared.command_credits = *command_credits;
                shared
                    .cmd_pending
                    .resolve(*opcode as u16, *status as u8, data.as_slice());
            }
            sle_dli::SleEvent::CommandStatus {
                opcode,
                command_credits,
                status,
            } => {
                shared.command_credits = *command_credits;
                if *status != sle_dli::SleStatus::Success {
                    shared
                        .cmd_pending
                        .resolve(*opcode as u16, *status as u8, &[]);
                }
            }
            _ => {}
        }
    }

    // 2. Drive pending state machine transitions (DLI async confirmation).
    match ev {
        sle_dli::SleEvent::CommandComplete { opcode, status, .. }
            if !shared.controller.uses_command_host() =>
        {
            match opcode {
                sle_dli::SleOpcode::EnableBroadcast => {
                    if *status == sle_dli::SleStatus::Success {
                        shared.adv_scan.confirm_advertising();
                    } else {
                        shared.adv_scan.abort_advertising();
                    }
                }
                sle_dli::SleOpcode::EnableScan => {
                    if *status == sle_dli::SleStatus::Success {
                        shared.adv_scan.confirm_scanning();
                    } else {
                        shared.adv_scan.abort_scanning();
                    }
                }
                _ => {}
            }
        }
        sle_dli::SleEvent::ConnComplete {
            handle: evt_handle,
            addr,
            status,
        } => {
            if *status == sle_dli::SleStatus::Success {
                if let Some((host_handle, disconnect_pending)) =
                    shared.conn.record_controller_handle(addr, *evt_handle)
                {
                    if disconnect_pending {
                        if shared.controller.disconnect(*evt_handle).is_err() {
                            shared.conn.abort_disconnecting(host_handle);
                        }
                    }
                } else if !shared.conn.has_addr(addr) {
                    // Incoming connection — no prior ConnectPending entry
                    // and no existing entry for this address.
                    let _ = shared.conn.accept_incoming(*evt_handle, addr);
                }
                genl_bridge::notify_event(0x01, 0, addr);
            } else {
                shared.conn.abort_controller_connect(addr);
            }
        }
        sle_dli::SleEvent::Disconnected { handle, .. } => {
            let host_handle = shared.conn.host_handle(*handle).unwrap_or(*handle);
            let peer_addr = shared
                .conn
                .info(host_handle)
                .map(|e| e.peer_addr)
                .unwrap_or([0u8; 6]);
            shared.conn.confirm_disconnecting_by_handle(host_handle);
            genl_bridge::notify_event(0x01, host_handle, &peer_addr);
        }
        sle_dli::SleEvent::AdvReport {
            addr,
            rssi,
            discovery_level,
            data,
        } => {
            let _ =
                shared
                    .adv_scan
                    .process_adv_report(addr, *rssi, *discovery_level, data.as_slice());
            genl_bridge::notify_event(0x02, 0, addr);
        }
        sle_dli::SleEvent::DataReceived { handle, data } => {
            let raw = data.as_slice();
            if raw.is_empty() {
                // Empty payload, nothing to route.
            } else if u16::from(raw[0]) == sle_conn::tcid::MANAGEMENT
                && raw.len() >= sle_conn::CREDIT_GRANT_PDU_SIZE
                && raw[1] == sle_conn::CREDIT_GRANT_PDU_TYPE
            {
                // Credit grant signaling on management channel (T/XS 20002-2025 §7.3.3).
                // Format: [TCID 0x02] [code 0xFC] [identifier] [length LE16] [target_tcid] [credits LE16]
                let target_tcid = u16::from(raw[5]);
                let credits = u16::from_le_bytes([raw[6], raw[7]]);
                let _ = shared.conn.receive_credits(*handle, target_tcid, credits);
            } else if u16::from(raw[0]) == sle_conn::tcid::MANAGEMENT
                && raw.len() >= 5
                && raw[1] != sle_conn::CREDIT_GRANT_PDU_TYPE
            {
                // Transport control signaling on management channel (T/XS 20002-2025 §7.3.4).
                let sig_data = &raw[1..];
                let mut resp_buf = [0u8; 32];
                let resp_len = shared
                    .conn
                    .handle_transport_signaling(*handle, sig_data, &mut resp_buf)
                    .unwrap_or(0);
                if resp_len > 0 {
                    let _ = shared.controller.send_data(*handle, &resp_buf[..resp_len]);
                }
            } else if u16::from(raw[0]) == sle_conn::tcid::SERVICE_MGMT && raw.len() > 1 {
                // SSAP PDU on service management channel (TCID 0x0A).
                // Track RX credit for the reliable SMTC channel.
                let needs_grant = shared
                    .conn
                    .consume_rx_credit(*handle, sle_conn::tcid::SERVICE_MGMT);
                let pdu_data = &raw[1..];
                let mut resp_buf = [0u8; sle_ssap::SSAP_PDU_MAX];
                let resp_len = shared
                    .process_ssap_pdu(*handle, pdu_data, &mut resp_buf)
                    .unwrap_or(0);
                // Send response PDU back with TCID prefix, consuming TX credit.
                if resp_len > 0
                    && shared
                        .conn
                        .consume_tx_credit(*handle, sle_conn::tcid::SERVICE_MGMT)
                        .is_ok()
                {
                    let mut tx_buf = [0u8; 1 + sle_ssap::SSAP_PDU_MAX];
                    tx_buf[0] = sle_conn::tcid::SERVICE_MGMT as u8;
                    tx_buf[1..1 + resp_len].copy_from_slice(&resp_buf[..resp_len]);
                    let _ = shared
                        .controller
                        .send_data(*handle, &tx_buf[..1 + resp_len]);
                }
                // Drain pending notifications/indications triggered by the PDU.
                while let Some(n) = shared.ssap.dequeue_notification() {
                    if shared
                        .conn
                        .consume_tx_credit(*handle, sle_conn::tcid::SERVICE_MGMT)
                        .is_err()
                    {
                        break; // No credits remaining for notifications.
                    }
                    let pdu = if n.indication {
                        sle_ssap::SsapPdu::ValueInd {
                            handle: n.handle,
                            data: n.data,
                        }
                    } else {
                        sle_ssap::SsapPdu::ValueNtf {
                            handle: n.handle,
                            data: n.data,
                        }
                    };
                    let mut ntf_buf = [0u8; 1 + sle_ssap::SSAP_PDU_MAX];
                    ntf_buf[0] = sle_conn::tcid::SERVICE_MGMT as u8;
                    if let Ok(pdu_len) = pdu.encode(&mut ntf_buf[1..]) {
                        if pdu_len > 0 {
                            let _ = shared
                                .controller
                                .send_data(*handle, &ntf_buf[..1 + pdu_len]);
                        }
                    }
                }
                // Send credit grant if RX credits are low.
                if needs_grant {
                    if let Ok((granted, id)) = shared
                        .conn
                        .grant_credits(*handle, sle_conn::tcid::SERVICE_MGMT)
                    {
                        send_credit_grant(
                            &shared.controller,
                            *handle,
                            sle_conn::tcid::SERVICE_MGMT,
                            granted,
                            id,
                        );
                    }
                }
                // After ExchangeInfo negotiation: if reliable mode is agreed
                // but the reliable channel is not yet created, initiate
                // TCID_Connect_Req on the management channel.
                let needs_connect = shared
                    .conn
                    .get_ssap_session(*handle)
                    .map(|sess| sess.reliable_mode && sess.reliable_tcid.is_none())
                    .unwrap_or(false);
                if needs_connect {
                    let cfg = sle_conn::ReliableModeConfig::default();
                    let mut sig_buf = [0u8; 24];
                    if let Ok(sig_len) =
                        shared
                            .conn
                            .build_tcid_connect_req(*handle, &cfg, &mut sig_buf)
                    {
                        let _ = shared.controller.send_data(*handle, &sig_buf[..sig_len]);
                    }
                }
            } else {
                // Check if this is an SSAP PDU on the dynamic reliable channel.
                let first_byte_tcid = u16::from(raw[0]);
                let is_ssap_reliable = raw.len() > 1
                    && shared
                        .conn
                        .ssap_reliable_tcid(*handle)
                        .map(|t| t == first_byte_tcid)
                        .unwrap_or(false);
                if is_ssap_reliable {
                    // SSAP PDU on reliable transport channel.
                    let needs_grant = shared.conn.consume_rx_credit(*handle, first_byte_tcid);
                    let pdu_data = &raw[1..];
                    let mut resp_buf = [0u8; sle_ssap::SSAP_PDU_MAX];
                    let resp_len = shared
                        .process_ssap_pdu(*handle, pdu_data, &mut resp_buf)
                        .unwrap_or(0);
                    if resp_len > 0
                        && shared
                            .conn
                            .consume_tx_credit(*handle, first_byte_tcid)
                            .is_ok()
                    {
                        let mut tx_buf = [0u8; 1 + sle_ssap::SSAP_PDU_MAX];
                        tx_buf[0] = first_byte_tcid as u8;
                        tx_buf[1..1 + resp_len].copy_from_slice(&resp_buf[..resp_len]);
                        let _ = shared
                            .controller
                            .send_data(*handle, &tx_buf[..1 + resp_len]);
                    }
                    if needs_grant {
                        if let Ok((granted, id)) =
                            shared.conn.grant_credits(*handle, first_byte_tcid)
                        {
                            send_credit_grant(
                                &shared.controller,
                                *handle,
                                first_byte_tcid,
                                granted,
                                id,
                            );
                        }
                    }
                } else {
                    // User data — strip TCID prefix if present, enqueue to rx_queue.
                    let tcid = if u16::from(raw[0]) == sle_conn::tcid::DEFAULT_DATA && raw.len() > 1
                    {
                        let _ = shared
                            .conn
                            .consume_rx_credit(*handle, sle_conn::tcid::DEFAULT_DATA);
                        sle_conn::tcid::DEFAULT_DATA
                    } else {
                        0 // Legacy data without TCID prefix.
                    };
                    let payload = if tcid != 0 { &raw[1..] } else { raw };
                    let seq = shared.conn.info(*handle).map(|e| e.seq.rx_seq).unwrap_or(0);
                    let _ = shared.conn.receive_data(*handle, payload, seq);
                }
            }
        }
        // -----------------------------------------------------------------
        // Pairing events — drive the security state machine and
        // send response commands back to the controller.
        // -----------------------------------------------------------------
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
            if let Ok(reply) = shared.security.on_pair_info_exchange(
                *handle,
                *io_cap,
                *oob_flag,
                *auth_req,
                *max_key_len,
                *sec_dist,
                *psk_ind,
                crypto_cap,
            ) {
                let _ = shared.controller.pair_info_exchange_reply(&reply);
            }
        }
        sle_dli::SleEvent::PairOptionReport {
            handle,
            key_len,
            auth_method,
            crypto_alg,
            public_key,
        } => {
            if let Ok(accept) = shared.security.on_pair_option_report(
                *handle,
                *key_len,
                *auth_method,
                crypto_alg,
                public_key.as_slice(),
            ) {
                let _ = shared.controller.pair_option_accept(&accept);
            }
        }
        sle_dli::SleEvent::PairRandom { handle, random } => {
            if let Ok(resp) = shared.security.on_pair_random(*handle, random) {
                let _ = shared.controller.pair_random(&resp);
            }
        }
        sle_dli::SleEvent::PairConfirm { handle, confirm } => {
            if let Ok(resp) = shared.security.on_pair_confirm(*handle, confirm) {
                let _ = shared.controller.pair_confirm(&resp);
            }
        }
        sle_dli::SleEvent::DHKeyCheck {
            handle,
            dhkey_check,
        } => {
            if let Ok(resp) = shared.security.on_dhkey_verify(*handle, dhkey_check) {
                let _ = shared.controller.dhkey_verify(&resp);
            }
        }
        sle_dli::SleEvent::PairFailure { handle, reason } => {
            shared.security.on_pair_failure(*handle, *reason);
        }
        // -----------------------------------------------------------------
        // Sync link setup events — update ConnManager state machine.
        // -----------------------------------------------------------------
        sle_dli::SleEvent::SyncUcastSetupRequest {
            async_handle,
            sync_handle,
            event_group_set_id,
            event_group_id,
        } => {
            let _ = shared.conn.handle_sync_ucast_setup_request(
                *async_handle,
                *sync_handle,
                *event_group_set_id,
                *event_group_id,
            );
        }
        sle_dli::SleEvent::SyncUcastSetupComplete {
            sync_handle,
            status,
            ..
        } => {
            let _ = shared
                .conn
                .handle_sync_ucast_setup_complete(*sync_handle, *status);
        }
        sle_dli::SleEvent::SyncMcastSetupRequest {
            async_handle,
            sync_handle,
        } => {
            let _ = shared
                .conn
                .handle_sync_mcast_setup_request(*async_handle, *sync_handle);
        }
        sle_dli::SleEvent::SyncMcastSetupComplete {
            sync_handle,
            status,
            ..
        } => {
            let _ = shared
                .conn
                .handle_sync_mcast_setup_complete(*sync_handle, *status);
        }
        _ => {}
    }

    // 3. Publish to broadcast ring and DLI event ring.
    let wire = sle_dli_event_to_broadcast(ev);
    shared.broadcast.publish(wire);
    let dli_ev = sle_dli_event_to_wire(ev);
    shared.push_dli_event(dli_ev);
}

/// Drain all immediately available controller events and process them.
///
/// Used after ioctl commands to handle synchronous controller responses
/// (UartController, SpiController) inline without waiting for the
/// next EventPump cycle. Also drains USB event ring entries so that
/// multi-step protocol exchanges (e.g. pairing) can complete within
/// a single ioctl call.
pub(crate) fn drain_controller_events(shared: &mut ControllerState) {
    let mut tagged = match new_event_batch() {
        Ok(batch) => batch,
        Err(_) => {
            // Leave USB events in their queue for the background worker.
            pr_err!("sparklink: cannot allocate inline RX staging\n");
            return;
        }
    };
    // Multiple rounds: each round may generate new DLI commands whose
    // responses arrive in a subsequent round. Limit total iterations
    // to bound lock hold time on the ioctl path.
    let mut total = 0u32;
    for _round in 0..4 {
        let mut drained_this_round = 0u32;

        if let Some(owner) = sle_usb::ingress_owner(shared.identity) {
            if process_host_reply(&owner, shared) {
                drained_this_round += 1;
                total += 1;
            }
        }

        // 1. Inline controller events (UART/SPI synchronous responses)
        while let Some(ev) = shared.controller.poll_event() {
            process_controller_event(shared, &ev);
            drained_this_round += 1;
            total += 1;
            if total >= 32 {
                return;
            }
        }

        // 2. USB event ring entries (with device-ID filtering)
        // Do not dequeue more events than this invocation can process.
        let count =
            sle_usb::drain_usb_events_for(shared.identity, &mut tagged[..(32 - total) as usize]);
        for item in tagged.iter_mut().take(count) {
            let (dev_id, ev_opt) = core::mem::take(item);
            if let Some(ev) = ev_opt {
                debug_assert_eq!(dev_id, Some(shared.identity.id));
                process_controller_event(shared, &ev);
                drained_this_round += 1;
                total += 1;
                if total >= 32 {
                    return;
                }
            }
        }

        if drained_this_round == 0 {
            break;
        }
    }
}

impl ControllerRuntime {
    pub(crate) fn start_workers(self: &Arc<Self>) {
        sle_usb::publish_runtime(self);
        self.schedule_rx(msecs_to_jiffies(EVENT_PUMP_HEARTBEAT_MS));
    }

    pub(crate) fn schedule_rx(self: &Arc<Self>, delay: kernel::time::Jiffies) {
        let stopping = self.schedule_gate.lock();
        if !*stopping {
            if delay == 0 {
                // SAFETY: this pinned delayed_work is never disabled and all
                // scheduling is serialized with stop/flush by this gate.
                // mod_delayed_work returns false for a NEW queue reference:
                // __enqueue then transfers the incoming Arc to the trampoline.
                // If already pending, it returns true: keep the prior queue
                // reference and return/drop the unused incoming Arc. No raw
                // callback can run without a corresponding Rust-owned Arc.
                let _ = unsafe {
                    <Arc<Self> as workqueue::RawWorkItem<0>>::__enqueue(self.clone(), |work| {
                        let delayed =
                            kernel::container_of!(work, kernel::bindings::delayed_work, work);
                        !kernel::bindings::mod_delayed_work_on(
                            kernel::bindings::wq_misc_consts_WORK_CPU_UNBOUND as i32,
                            kernel::bindings::system_wq,
                            delayed,
                            0,
                        )
                    })
                };
            } else {
                // A heartbeat/self-rearm must not postpone an existing kick.
                let _ = workqueue::system().enqueue_delayed::<_, 0>(self.clone(), delay);
            }
        }
    }

    pub(crate) fn kick_commands(self: &Arc<Self>) {
        let stopping = self.schedule_gate.lock();
        if !*stopping {
            let _ = workqueue::system().enqueue_delayed::<_, 1>(self.clone(), 0);
        }
    }

    pub(crate) fn stop_workers(self: &Arc<Self>) {
        *self.schedule_gate.lock() = true;
        self.host.lock().fail(ENODEV);
        flush_work(&self.rx_work);
        flush_work(&self.tx_work);
    }
}

impl WorkItem<0> for ControllerRuntime {
    type Pointer = Arc<ControllerRuntime>;

    fn run(this: Arc<ControllerRuntime>) {
        if *this.schedule_gate.lock() {
            return;
        }
        let mut pumped = 0u32;
        let mut rearm_jiffies = msecs_to_jiffies(EVENT_PUMP_HEARTBEAT_MS) as u64;
        let mut batch = new_event_batch().ok();
        let drops = sle_usb::take_dropped_stats(&this);
        if drops.ring > 0 || drops.command_complete > 0 || drops.decode > 0 {
            pr_warn!("sparklink: sle{} USB RX loss: ring={} command_complete={} mac_complete={} decode={}\n",
                this.identity.id, drops.ring, drops.command_complete, drops.mac_complete, drops.decode);
        }
        for _pass in 0..16 {
            let tagged: &mut [_] = match batch.as_deref_mut() {
                Some(events) => events,
                None => &mut [],
            };
            let mut drained = 0;
            {
                let mut guard = this.state.lock();
                let Some(runtime) = Option::as_mut(&mut *guard) else {
                    return;
                };
                if process_host_reply(&this, runtime) {
                    pumped += 1;
                    drained += 1;
                }
                while let Some(ev) = runtime.controller.poll_event() {
                    process_controller_event(runtime, &ev);
                    pumped += 1;
                    drained += 1;
                    if pumped >= 256 {
                        break;
                    }
                }
                // Inline and worker drains share this owner's state lock. Do
                // not prefetch older events before waiting for that lock: an
                // ioctl could otherwise process newer events ahead of them.
                let budget = tagged.len().min((256 - pumped) as usize);
                let count = sle_usb::drain_runtime_events(&this, &mut tagged[..budget]);
                for item in tagged.iter_mut().take(count) {
                    let (id, event) = core::mem::take(item);
                    if let Some(ev) = event {
                        debug_assert_eq!(id, Some(this.identity.id));
                        process_controller_event(runtime, &ev);
                        pumped += 1;
                        drained += 1;
                    }
                }
                if drained == 0 || pumped >= 256 {
                    if runtime.controller.uses_command_host()
                        && this.host.lock().timed_out()
                    {
                        fail_host(&this, runtime, ETIMEDOUT);
                        pr_warn!(
                            "sparklink: sle{} USB command Host timed out\n",
                            this.identity.id
                        );
                    }
                    let expired = runtime.cmd_pending.expire_stale();
                    if expired > 0 {
                        pr_warn!(
                            "sparklink: sle{}: {} pending commands timed out\n",
                            this.identity.id,
                            expired
                        );
                    }
                    runtime.cmd_pending.gc();
                    let mut timeout_buf = [0u16; sle_conn::MAX_CONNECTIONS];
                    let n = runtime.conn.check_supervision_timeouts(&mut timeout_buf);
                    for &h in &timeout_buf[..n] {
                        if let Ok(peer) = runtime.conn.timeout_disconnect(h) {
                            runtime
                                .broadcast
                                .publish(sle_event::SleWireEvent::conn_state(
                                    h,
                                    sle_conn::ConnState::Connected as u8,
                                    sle_conn::ConnState::Idle as u8,
                                    peer,
                                    0x08,
                                ));
                        }
                    }
                    if let Some(j) = runtime.conn.next_supervision_jiffies() {
                        rearm_jiffies = rearm_jiffies.min(j);
                    }
                }
            }
            if drained == 0 || pumped >= 256 {
                break;
            }
        }
        if pumped > 0 {
            this.fast_poll_remaining
                .store(64, core::sync::atomic::Ordering::Relaxed);
            rearm_jiffies = 1;
        } else {
            let remaining = this
                .fast_poll_remaining
                .load(core::sync::atomic::Ordering::Relaxed);
            if remaining > 0 {
                this.fast_poll_remaining
                    .store(remaining - 1, core::sync::atomic::Ordering::Relaxed);
                rearm_jiffies = 1;
            }
        }
        // An inline drain may already have taken the grant; check the owner
        // state even on an empty RX pass. Queue TX after releasing its mutex.
        let can_send = {
            let state = this.state.lock();
            state.as_ref().is_some_and(|state| {
                if state.controller.uses_command_host() {
                    this.host.lock().can_send()
                } else {
                    state.command_credits > 0 && !state.cmd_queue.is_empty()
                }
            })
        };
        if can_send {
            this.kick_commands();
        }
        this.schedule_rx(rearm_jiffies as kernel::time::Jiffies);
    }
}

impl WorkItem<1> for ControllerRuntime {
    type Pointer = Arc<ControllerRuntime>;

    fn run(this: Arc<ControllerRuntime>) {
        if *this.schedule_gate.lock() {
            return;
        }
        let more = {
            let mut guard = this.state.lock();
            let Some(runtime) = Option::as_mut(&mut *guard) else {
                return;
            };
            if runtime.controller.uses_command_host() {
                let request = this.host.lock().next(|seq| {
                    runtime
                        .cmd_pending
                        .find_by_seq(seq)
                        .is_some_and(|entry| entry.is_pending() && !entry.is_expired())
                });
                let request = match request {
                    Ok(request) => request,
                    Err(error) => { fail_host(&this, runtime, error); return; }
                };
                if let Some(request) = request {
                    if let sle_dli::ControllerBackend::Ws73(controller) = &runtime.controller {
                        let transport = controller.command_transport();
                        // Own the transport independently. RPC snapshots and
                        // RX processing must not wait for a blocking USB OUT.
                        drop(guard);
                        match transport.send(request.opcode,
                            &request.params[..request.param_len as usize], request.recipe) {
                            Ok(()) => {
                                if this.host.lock().transport_complete(request.cookie) {
                                    this.schedule_rx(0);
                                }
                            }
                            Err(error) => {
                                let mut guard = this.state.lock();
                                if let Some(runtime) = Option::as_mut(&mut *guard) {
                                    fail_host(&this, runtime, error);
                                }
                            }
                        }
                        return;
                    }
                    if let Err(error) = runtime.controller.send_command_transport(
                        request.opcode,
                        &request.params[..request.param_len as usize],
                        request.recipe,
                    ) {
                        fail_host(&this, runtime, error);
                    } else if this.host.lock().transport_complete(request.cookie) {
                        this.schedule_rx(0);
                    }
                }
                // Reply consumption, not bulk acceptance, releases this slot.
                return;
            }
            for _ in 0..8 {
                if runtime.command_credits == 0 {
                    break;
                }
                let Some(req) = runtime.cmd_queue.pop() else {
                    break;
                };
                let plen = req.param_len as usize;
                runtime.command_credits -= 1;
                if runtime
                    .controller
                    .send_command_raw(req.opcode, &req.params[..plen])
                    .is_err()
                {
                    runtime.cmd_pending.resolve_seq(req.seq, 0x03, &[]);
                }
            }
            runtime.command_credits > 0 && !runtime.cmd_queue.is_empty()
        };
        if more {
            this.kick_commands();
        }
    }
}

/// Convert a DLI SleEvent into a SleWireEvent for broadcast ring insertion.
#[inline(never)]
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
