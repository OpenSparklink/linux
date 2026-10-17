pub enum SleEvent {
    /// Unsolicited opcode-zero command credit update; not a transaction result.
    CommandCredits { credits: u8 },
    /// Command completed with status and optional return data.
    CommandComplete {
        opcode: SleOpcode,
        command_credits: u8,
        status: SleStatus,
        data: KVec<u8>,
    },
    /// Command pending (asynchronous processing started).
    CommandStatus {
        opcode: SleOpcode,
        command_credits: u8,
        status: SleStatus,
    },
    /// Native dialect command result: exact opcode and status, without enum aliases.
    NativeCommandReply {
        opcode: u16,
        command_credits: u8,
        status: u8,
        complete: bool,
        data: KVec<u8>,
    },
    /// Native controller relay, lifetime frozen at ingress, never security trust.
    NativeControllerData { lifetime:u64, handle:u16, index:u16, data:KVec<u8> },
    /// Native schema validated; actual lifetime frozen before RX queueing. Not trust.
    NativeSecurityInstallation {lifetime:u64, security_revision:u64, handle:u16, event:u16, status:u8, enabled:u8},
    /// Advertising / broadcast report received during scanning.
    AdvReport {
        addr: [u8; 6],
        rssi: i8,
        discovery_level: u8,
        data: KVec<u8>,
    },
    /// Connection established.
    ConnComplete {
        handle: u16,
        addr: [u8; 6],
        status: SleStatus,
    },
    /// Data received on a connection.
    DataReceived { handle: u16, data: KVec<u8> },
    /// Connection lost.
    Disconnected { handle: u16, reason: u8 },
    /// Encryption status changed on a connection.
    EncryptionChanged { handle: u16, enabled: bool },
    /// Pairing request from a remote peer.
    PairRequest { addr: [u8; 6], method: u8 },
    /// Controller hardware error.
    HardwareError { code: u8 },
    /// Broadcast / advertising terminated by the controller.
    BroadcastEnd { reason: u8 },
    /// PHY parameters updated on a connection.
    PhyUpdate {
        handle: u16,
        mcs_index: u8,
        bandwidth_mhz: u8,
    },
    /// Connection parameters updated.
    ConnParamUpdate {
        handle: u16,
        interval: u16,
        latency: u16,
        timeout: u16,
    },
    /// Data length changed on a connection.
    DataLenChange {
        handle: u16,
        max_tx_octets: u16,
        max_rx_octets: u16,
    },
    /// Controller data buffer overflow.
    DataBufOverflow { link_type: u8 },
    /// Remote peer requests connection parameter change.
    PeerConnParamReq {
        handle: u16,
        interval_min: u16,
        interval_max: u16,
        latency: u16,
        timeout: u16,
    },

    // --- HIGH priority (§9.1.7, §9.1.8, §9.1.11) ---
    /// TX power change report (§9.1.7).
    PowerChangeReport {
        handle: u16,
        reason: u8,
        frame_type: u8,
        bandwidth: u8,
        pilot_density: u8,
        tx_power: i8,
        power_level: u8,
        offset: i8,
    },
    /// Number of completed packets (§9.1.8).
    NumCompletedPackets { handle: u16, num_completed: u8 },
    /// Link encryption parameter request (§9.1.11).
    EncryptionParamReq { handle: u16 },

    // --- MEDIUM — Peer Info (§9.1.13, §9.1.15–§9.1.16, §9.1.20–§9.1.21) ---
    /// Controller control signaling data (§9.1.13).
    ControllerSignalData {
        handle: u16,
        signal_id: u16,
        data: KVec<u8>,
    },
    /// Read peer features complete (§9.1.15).
    ReadPeerFeatures {
        handle: u16,
        status: u8,
        features: [u8; 10],
    },
    /// Read peer version info complete (§9.1.16).
    ReadPeerVersion {
        handle: u16,
        status: u8,
        version: u8,
        manufacturer: u16,
        subversion: u16,
    },
    /// Read peer TX power complete (§9.1.20).
    ReadPeerPower {
        handle: u16,
        status: u8,
        frame_type: u8,
        bandwidth: u8,
        pilot_density: u8,
        tx_power: i8,
        power_level: u8,
    },
    /// Inquiry (scan) request report (§9.1.21).
    InquiryRequestReport {
        adv_handle: u8,
        addr_type: u8,
        addr: [u8; 6],
        rssi: i8,
        data: KVec<u8>,
    },

    // --- MEDIUM — Pairing (§9.1.23–§9.1.32) ---
    // NOTE: PairRequest (§9.1.22) already exists above.
    /// Pairing information exchange request (§9.1.23).
    PairInfoExchange {
        handle: u16,
        io_cap: u8,
        oob_flag: u8,
        auth_req: u8,
        max_key_len: u8,
        sec_dist: u8,
        psk_ind: u8,
        crypto_cap: [u8; 4],
    },
    /// Pairing information report (§9.1.24).
    PairInfoReport {
        handle: u16,
        io_cap: u8,
        oob_flag: u8,
        auth_req: u8,
        max_key_len: u8,
        sec_dist: u8,
        psk_ind: u8,
        crypto_cap: [u8; 4],
    },
    /// Pairing option report (§9.1.25).
    PairOptionReport {
        handle: u16,
        key_len: u8,
        auth_method: u8,
        crypto_alg: [u8; 4],
        public_key: KVec<u8>,
    },
    /// Peer public key report (§9.1.26).
    PeerPublicKey { handle: u16, public_key: KVec<u8> },
    /// Pairing extended data report (§9.1.27).
    PairExtData {
        handle: u16,
        ext_pubkey_x: KVec<u8>,
        ext_pubkey_y: KVec<u8>,
    },
    /// Keypress notification (§9.1.28).
    KeypressNotify { handle: u16, action: [u8; 4] },
    /// Pairing random number report (§9.1.29).
    PairRandom { handle: u16, random: [u8; 16] },
    /// Pairing confirm code report (§9.1.30).
    PairConfirm { handle: u16, confirm: [u8; 16] },
    /// DH key check report (§9.1.31).
    DHKeyCheck { handle: u16, dhkey_check: [u8; 16] },
    /// Pairing failure report (§9.1.32).
    PairFailure { handle: u16, reason: u8 },

    // --- LOW — Narrowband Measurement (§9.1.33–§9.1.39) ---
    /// Narrowband measurement info (§9.1.33).
    NarrowbandMeasInfo {
        handle: u16,
        meas_type: u16,
        status: u8,
        config_index: u8,
    },
    /// Narrowband measurement state change (§9.1.34).
    NarrowbandMeasStateChange {
        status: u8,
        config_index: u8,
        meas_state: u8,
    },
    /// Narrowband measurement parameter report (§9.1.35).
    NarrowbandMeasParamReport {
        handle: u16,
        status: u8,
        config_index: u8,
    },
    /// Local narrowband measurement capabilities (§9.1.36).
    LocalNarrowbandMeasCap {
        status: u8,
        antenna_count: u8,
        signal_cap: [u8; 4],
        report_cap: [u8; 4],
    },
    /// Peer narrowband measurement capabilities (§9.1.37).
    PeerNarrowbandMeasCap {
        handle: u16,
        status: u8,
        antenna_count: u8,
        signal_cap: [u8; 4],
        report_cap: [u8; 4],
    },
    /// Measurement state change (§9.1.38).
    MeasStateChange {
        source: u16,
        status: u8,
        instance_handle: u8,
        instance_state: u8,
    },
    /// Measurement quantity report (§9.1.39).
    MeasQuantityReport {
        source: u16,
        meas_source: u16,
        seq: u16,
        instance_handle: u8,
        meas_count: u8,
    },

    // --- LOW — SLB (§9.1.40–§9.1.45) ---
    /// SLB advertising report (§9.1.40).
    SlbAdvReport {
        mac_addr: [u8; 6],
        channel: u16,
        bandwidth: u8,
        rssi: i8,
        data: KVec<u8>,
    },
    /// SLB connection established (§9.1.41).
    SlbConnComplete {
        handle: u16,
        status: u8,
        peer_addr: [u8; 6],
    },
    /// SLB unicast logical channel established (§9.1.42).
    SlbUcastChannelComplete {
        channel_handle: u16,
        conn_handle: u16,
        status: u8,
        max_pkt_len: u16,
        max_pkt_count: u16,
    },
    /// SLB unicast logical channel updated (§9.1.43).
    SlbUcastChannelUpdate {
        channel_handle: u16,
        status: u8,
        max_pkt_len: u16,
        max_pkt_count: u16,
    },
    /// SLB logical channel deleted (§9.1.44).
    SlbChannelDelete { channel_handle: u16, status: u8 },
    /// SLB completed packets count (§9.1.45).
    SlbNumCompletedPackets {
        channel_handle: u16,
        num_completed: u8,
    },

    // --- LOW — Sync Link (§9.1.46–§9.1.51) ---
    /// Time synchronization status update (§9.1.46).
    TimeSyncStatusUpdate {
        sync_status: u8,
        clock_source: u8,
        accuracy: u32,
    },
    /// Time synchronization request (§9.1.47).
    TimeSyncRequest { time_seq: u32, send_time: [u8; 8] },
    /// Synchronous unicast link setup request (§9.1.48).
    SyncUcastSetupRequest {
        async_handle: u16,
        sync_handle: u16,
        event_group_set_id: u8,
        event_group_id: u8,
    },
    /// Synchronous unicast link setup complete (§9.1.49).
    SyncUcastSetupComplete {
        async_handle: u16,
        sync_handle: u16,
        status: u8,
    },
    /// Synchronous multicast link setup request (§9.1.50).
    SyncMcastSetupRequest { async_handle: u16, sync_handle: u16 },
    /// Synchronous multicast link setup complete (§9.1.51).
    SyncMcastSetupComplete {
        async_handle: u16,
        sync_handle: u16,
        status: u8,
    },
}
