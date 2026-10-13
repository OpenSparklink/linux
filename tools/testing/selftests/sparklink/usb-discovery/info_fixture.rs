// SPDX-License-Identifier: GPL-2.0-only
// Actual info/default/attach projection; remaining types/FFI are dependencies.
use std::sync::atomic::{AtomicU32, Ordering};
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub enum SleBus {
    #[default]
    None,
    Usb,
    Uart,
}
// @@INFO_STRUCT@@
impl Default for SleControllerInfo {
    // @@DEFAULT@@
}
static FW: AtomicU32 = AtomicU32::new(0);
struct UsbDevice;impl UsbDevice{fn as_raw(&self)->i32{7}}
unsafe fn sle_usb_dev_get_fw_version(id: i32) -> u32 {
    assert_eq!(id, 7);
    FW.load(Ordering::Relaxed)
}
unsafe fn sle_serdev_dev_get_fw_version(id: i32) -> u32 {
    assert_eq!(id, 8);
    FW.load(Ordering::Relaxed)
}
struct UsbController {
    addr: [u8; 6],
    device: UsbDevice,
}
impl UsbController {
    // @@USB_INFO@@
}
struct SerdevController {
    addr: [u8; 6],
    dev_id: u16,
}
impl SerdevController {
    // @@SERDEV_INFO@@
}
mod sle_dli {
    pub use super::{SleControllerInfo, SleBus};
}
struct SleAttachInfo {
    addr: [u8; 6],
    fw_version: u32,
    features: u64,
    features_ext: u16,
    max_pdu: u16,
    max_connections: u8,
}
struct Proto {
    name: &'static str,
    bus: SleBus,
    max_pdu: u16,
}
fn attach_projection(info: &SleAttachInfo, proto: &Proto) -> SleControllerInfo {
    // @@ATTACH_METADATA@@
    ctrl_info
}
fn unavailable(i: &SleControllerInfo) {
    assert_eq!(i.features | u64::from(i.features_ext), 0);
    assert_eq!(
        (i.max_pdu_payload, i.max_connections, i.max_mtu, i.max_mps),
        (0, 0, 0, 0)
    );
    assert_eq!(i.transport_modes | i.measurement_cap, 0);
    assert_eq!(i.security_cap, 0);
}
#[test]
fn default_does_not_fabricate_radio_or_connection_capabilities() {
    let i = SleControllerInfo::default();
    unavailable(&i);
    assert_eq!(i.bus, SleBus::None);
    assert_eq!(i.addr, [0; 6]);
    assert_eq!(i.fw_version, 0);
}
#[test]
fn usb_info_retains_only_queried_identity_and_firmware() {
    for fw in [0, 0x016c00a1, u32::MAX] {
        FW.store(fw, Ordering::Relaxed);
        let i = UsbController {
            addr: [1; 6],
            device:UsbDevice,
        }
        .info();
        unavailable(&i);
        assert_eq!(i.bus, SleBus::Usb);
        assert_eq!(i.addr, [1; 6]);
        assert_eq!(i.fw_version, fw);
        assert!(i.name.starts_with(b"sparklink-usb\0"));
    }
}
#[test]
fn serdev_codec_limits_do_not_advertise_hardware_support() {
    FW.store(0x11223344, Ordering::Relaxed);
    let i = SerdevController {
        addr: [2; 6],
        dev_id: 8,
    }
    .info();
    unavailable(&i);
    assert_eq!(i.bus, SleBus::Uart);
    assert_eq!(i.addr, [2; 6]);
    assert_eq!(i.fw_version, 0x11223344);
    assert!(i.name.starts_with(b"sparklink-serdev\0"));
}
#[test]
fn attach_does_not_replace_unknowns_with_bus_codec_defaults() {
    let info = SleAttachInfo {
        addr: [3; 6],
        fw_version: 4,
        features: 0,
        features_ext: 0,
        max_pdu: 0,
        max_connections: 0,
    };
    for max_pdu in [0, 255, 512, u16::MAX] {
        let proto = Proto {
            name: "usb",
            bus: SleBus::Usb,
            max_pdu,
        };
        let i = attach_projection(&info, &proto);
        unavailable(&i);
        assert_eq!(i.addr, [3; 6]);
        assert_eq!(i.fw_version, 4);
        assert_eq!(i.bus, SleBus::Usb);
        assert_eq!(proto.max_pdu, max_pdu);
    }
}
#[test]
fn explicit_attach_metadata_is_preserved_without_extra_claims() {
    let info = SleAttachInfo {
        addr: [4; 6],
        fw_version: 7,
        features: 0x13579,
        features_ext: 0x89,
        max_pdu: 128,
        max_connections: 2,
    };
    let proto = Proto {
        name: "usb",
        bus: SleBus::Usb,
        max_pdu: 65535,
    };
    let i = attach_projection(&info, &proto);
    assert_eq!(
        (
            i.features,
            i.features_ext,
            i.max_pdu_payload,
            i.max_connections
        ),
        (0x13579, 0x89, 128, 2)
    );
    assert_eq!(
        (
            i.max_mtu,
            i.max_mps,
            i.transport_modes,
            i.measurement_cap,
            i.security_cap
        ),
        (0, 0, 0, 0, 0)
    );
}

fn reserve_projection()->SleControllerInfo {
 // @@RESERVE_METADATA@@
 info
}
#[test] fn pending_identity_has_unknown_address_version_and_no_queried_capabilities(){
 let info=reserve_projection();assert_eq!(info.addr,[0;6]);assert_eq!(info.fw_version,0);assert_eq!(info.bus,SleBus::Usb);unavailable(&info);
}
#[test] fn unrelated_firmware_getter_does_not_backfill_pending_identity(){
 FW.store(0xffff,Ordering::Relaxed);let info=reserve_projection();assert_eq!(info.addr,[0;6]);assert_eq!(info.fw_version,0);unavailable(&info);
}
