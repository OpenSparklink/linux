// SPDX-License-Identifier: GPL-2.0-only
// Actual projection/conversion; dependency errno and transport/identity types only.
#[derive(Debug, PartialEq, Eq)]
struct Error(i32);
impl Error { fn from_errno(code: i32) -> Self { Self(code) } }
type Result<T> = std::result::Result<T, Error>;
const UNSUPPORTED: i32 = -95;
// @@BUS_ENUM@@
// @@INFO_STRUCT@@
// @@NATIVE_INFO@@
struct NativeController { metadata: NativeInfo, bus: SleBus }
impl NativeController {
    // @@PROJECTION@@
}
// @@CONVERSION@@
fn controller(bus: u32) -> NativeController {
    NativeController { bus: backend_bus(bus).unwrap(), metadata: NativeInfo {
        profile: 1, version: [1,2,3,4,5], features: [0xa5;10], address: [1;6],
        command_credits: 1, acb_length: 254, acb_count: 5, icb_length: 0, icb_count: 0,
    } }
}
#[test]
fn usb_retains_physical_projection() {
    let c=controller(1); let info=c.info();
    assert_eq!(info.bus,SleBus::Usb); assert_eq!(info.bus as u8,4);
    assert!(info.name.starts_with(b"ws73-native\0"));
    assert_eq!(info.addr,c.metadata.address); assert_eq!(info.max_pdu_payload,254);
}
#[test]
fn test_is_not_physical_or_virtual() {
    let c=controller(2); let info=c.info();
    assert_eq!(info.bus,SleBus::Test); assert_eq!(info.bus as u8,6);
    assert_ne!(info.bus,SleBus::Usb); assert_ne!(info.bus,SleBus::None);
    assert!(info.name.starts_with(b"sparklink-test\0"));
    assert_eq!(info.addr,c.metadata.address);
}
#[test]
fn unsupported_origins_do_not_fall_back_to_usb() {
    for raw in [0,3,4,5,6,255,u32::MAX] { assert_eq!(backend_bus(raw),Err(Error(-95))); }
}
#[test]
fn provenance_is_independent_of_wire_capabilities() {
    for bus in [1,2] {
        let c=controller(bus); let info=c.info();
        assert_eq!(c.bus,backend_bus(bus).unwrap());
        // Provenance projection does not replace the retained input metadata.
        assert_eq!((c.metadata.profile,c.metadata.command_credits,c.metadata.acb_count), (1,1,5));
        assert_eq!((c.metadata.icb_length,c.metadata.icb_count), (0,0));
        assert_eq!(info.features,u64::from_le_bytes([0xa5;8]));
        assert_eq!(info.features_ext,u16::from_le_bytes([0xa5;2]));
        assert_eq!((info.max_connections,info.max_mtu,info.max_mps),(0,0,0));
        assert_eq!((info.transport_modes,info.measurement_cap,info.security_cap),(0,0,0));
    }
}
