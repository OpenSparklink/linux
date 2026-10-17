pub(crate) struct SleDev {
    /// Unique device index (0-based), allocated from `SleDevRegistry`.
    pub(crate) id: u16,
    generation: u64,
    /// Device name, e.g. `"sle0"`, NUL-terminated.
    pub(crate) name: [u8; SLE_DEV_NAME_LEN],
    /// Transport bus type.
    pub(crate) bus: SleBus,
    /// Core pending diagnostics; never transport/Host Ready.
    pub(crate) pending_profile: u32,
    pub(crate) pending_phase: u32,
    pub(crate) pending_error: i32,
    /// 6-byte SLE MAC address.
    pub(crate) addr: [u8; 6],
    /// Lifecycle and operational state flags (see `SLE_DEV_*` constants).
    flags: AtomicU32,
    /// Firmware version (packed major.minor.patch).
    fw_version: u32,
}

impl SleDev {
    pub(crate) fn new(id: u16, generation: u64, info: &SleControllerInfo) -> Self {
        let mut name = [0u8; SLE_DEV_NAME_LEN];
        // Format name as "sleN\0".
        let prefix = b"sle";
        name[..prefix.len()].copy_from_slice(prefix);
        // Simple itoa for small ids (0..999).
        let id_val = id as usize;
        if id_val < 10 {
            name[3] = b'0' + id_val as u8;
        } else if id_val < 100 {
            name[3] = b'0' + (id_val / 10) as u8;
            name[4] = b'0' + (id_val % 10) as u8;
        } else {
            name[3] = b'0' + (id_val / 100) as u8;
            name[4] = b'0' + ((id_val / 10) % 10) as u8;
            name[5] = b'0' + (id_val % 10) as u8;
        }

        Self {
            id,
            generation,
            name,
            bus: info.bus,
            pending_profile: 0, pending_phase: 0, pending_error: 0,
            addr: info.addr,
            flags: AtomicU32::new(SLE_DEV_SETUP),
            fw_version: info.fw_version,
        }
    }
    pub(crate) fn update_hw_info(&mut self, addr: [u8; 6], fw_version: u32) {
        self.addr = addr;
        self.fw_version = fw_version;
    }
}

    pub(crate) fn update_hw_info(&mut self, id: u16, addr: [u8; 6], fw_version: u32) {
        if let Some(dev) = self.get_mut(id) {
            dev.update_hw_info(addr, fw_version);
        }
    }
