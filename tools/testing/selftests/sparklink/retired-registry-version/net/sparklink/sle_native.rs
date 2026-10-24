pub(crate) struct NativeInfo {
    profile: u32,
    version: [u8; 5],
    features: [u8; 10],
    address: [u8; 6],
    command_credits: u8,
    acb_length: u16,
    icb_length: u16,
    acb_count: u8,
    icb_count: u8,
}

fn backend_bus(bus: u32) -> Result<SleBus> {
    match bus {
        1 => Ok(SleBus::Usb),
        2 => Ok(SleBus::Test),
        _ => Err(Error::from_errno(UNSUPPORTED)),
    }
}

impl SleController for NativeController {
    fn info(&self) -> SleControllerInfo {
        SleControllerInfo {
            bus: self.bus, addr: self.metadata.address,
            // Registry observation only. fill_snapshot retains all five bytes.
            fw_version: u32::from_le_bytes(self.metadata.version[..4].try_into().unwrap()),
        }
    }
}

    pub(crate) fn fill_snapshot(&self, out: &mut super::sle_uapi::SleControllerSnapshot) {
        out.valid_fields = 1;
        out.version_tuple = self.metadata.version;
        out.features = self.metadata.features;
        out.address = self.metadata.address;
        out.acb_length = self.metadata.acb_length;
        out.icb_length = self.metadata.icb_length;
        out.acb_count = self.metadata.acb_count;
        out.icb_count = self.metadata.icb_count;
    }
