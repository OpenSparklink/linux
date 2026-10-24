pub(crate) enum SleBus {
    None = 0,
    Usb = 4,
    Test = 6,
}

pub(crate) struct SleControllerInfo {
    /// Validated provider provenance; None is an unpopulated reservation.
    pub bus: SleBus,
    /// Observed address, or zero before bootstrap.
    pub addr: [u8; 6],
    /// Legacy registry observation. Not the authoritative five-byte version.
    pub fw_version: u32,
}

impl Default for SleControllerInfo {
    fn default() -> Self {
        Self { bus: SleBus::None, addr: [0; 6], fw_version: 0 }
    }
}
