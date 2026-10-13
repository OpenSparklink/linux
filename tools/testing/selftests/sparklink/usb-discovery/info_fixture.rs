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
unsafe fn sle_serdev_dev_get_fw_version(id: i32) -> u32 {
    assert_eq!(id, 8);
    FW.load(Ordering::Relaxed)
}
// @@USB_METADATA_TYPES@@
#[derive(Clone, Copy)]struct Identity;
mod sle_dev { pub(crate) type DeviceIdentity=super::Identity; }
#[derive(Clone)]struct UsbDevice;
struct UsbDeviceOpaque;
impl UsbDevice { fn as_raw(&self)->*mut UsbDeviceOpaque { std::ptr::null_mut() } }
#[derive(Clone,Copy,Debug,PartialEq,Eq)]struct Error(i32);
impl Error { fn from_errno(n:i32)->Self { Self(n) } }
type Result<T> = std::result::Result<T,Error>;
const EIO:Error=Error(-5);const EPROTO:Error=Error(-71);
static INPUT:std::sync::Mutex<(i32,UsbMetadata)>=std::sync::Mutex::new((0,UsbMetadata{capabilities:UsbCapabilities{command_max:255,acb_length:0,icb_length:0,acb_count:0,icb_count:0,features:[0;10]},version:[0;5],address:[0;6],command_credits:0}));
unsafe fn sle_usb_dev_get_metadata(_: *mut UsbDeviceOpaque,output:*mut UsbMetadata)->i32 { let input=INPUT.lock().unwrap();if input.0==0 { unsafe{*output=input.1;} }input.0 }
// @@SNAPSHOT_TYPE@@
mod sle_uapi { pub(crate) use super::SleControllerSnapshot; }
struct UsbController { metadata:UsbMetadata,device:UsbDevice,identity:Identity }
impl UsbController {
    // @@USB_NEW@@
    // @@USB_SNAPSHOT@@
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
            metadata: UsbMetadata {address:[1;6],version:[fw.to_le_bytes()[0],fw.to_le_bytes()[1],fw.to_le_bytes()[2],fw.to_le_bytes()[3],0xab],..Default::default()}, device:UsbDevice,identity:Identity,
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

fn metadata()->UsbMetadata { UsbMetadata{capabilities:UsbCapabilities{command_max:65535,acb_length:2047,icb_length:1024,acb_count:255,icb_count:2,features:[1,2,3,4,5,6,7,8,9,0xab]},version:[1,2,3,4,5],address:[1,2,3,4,5,6],command_credits:2} }
#[test]fn actual_constructor_keeps_one_observation_and_full_projection(){
 let m=metadata();*INPUT.lock().unwrap()=(0,m);let c=UsbController::new(m.address,0x04030201,2,Identity,UsbDevice).unwrap();let i=c.info();assert_eq!(i.addr,m.address);assert_eq!(i.features,u64::from_le_bytes([1,2,3,4,5,6,7,8]));assert_eq!(i.features_ext,0xab09);assert_eq!((i.max_pdu_payload,i.max_connections,i.max_mtu,i.max_mps,i.transport_modes,i.security_cap),(0,0,0,0,0,0));let _=&c.device;let _=&c.identity;
}
#[test]fn actual_constructor_rejects_unknown_retired_and_positive_ffi(){
 let m=metadata();for (ret,expected) in [(-61,-61),(-19,-19),(1,-5)]{*INPUT.lock().unwrap()=(ret,m);assert!(matches!(UsbController::new(m.address,0x04030201,2,Identity,UsbDevice),Err(e) if e==Error(expected)));}
}
#[test]fn actual_constructor_rejects_mixed_identity_version_and_credit_observations(){
 let m=metadata();*INPUT.lock().unwrap()=(0,m);for (addr,fw,credits) in [([7;6],0x04030201,2),(m.address,0x05030201,2),(m.address,0x04030201,1)]{assert!(matches!(UsbController::new(addr,fw,credits,Identity,UsbDevice),Err(EPROTO)));}
}
#[test]fn actual_snapshot_layout_and_complete_fields_do_not_overwrite_host_state(){
 assert_eq!(std::mem::size_of::<UsbMetadata>(),30);assert_eq!(std::mem::align_of::<UsbMetadata>(),2);assert_eq!(std::mem::offset_of!(UsbMetadata,version),18);assert_eq!(std::mem::offset_of!(UsbMetadata,address),23);assert_eq!(std::mem::offset_of!(UsbMetadata,command_credits),29);
 let m=metadata();let c=UsbController{metadata:m,device:UsbDevice,identity:Identity};let mut s=SleControllerSnapshot{flags:4,command_credits:7,error:-5,..Default::default()};c.fill_snapshot(&mut s);assert_eq!(s.valid_fields,1);assert_eq!(s.features,m.capabilities.features);assert_eq!(s.address,m.address);assert_eq!(s.version_tuple,m.version);assert_eq!((s.acb_length,s.acb_count,s.icb_length,s.icb_count),(2047,255,1024,2));assert_eq!((s.flags,s.command_credits,s.error),(4,7,-5));assert_eq!((s.generation,s.version,s.profile,s.dev_index,s.bus,s.reserved_byte,s.reserved),(0,0,0,0,0,0,[0;4]));
}
