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
mod sle_uapi { // @@SNAPSHOT@@
}
// @@DEFAULT@@
struct NativeController { metadata: NativeInfo, bus: SleBus }
impl NativeController {
    // @@PROJECTION@@
    // @@FILL_SNAPSHOT@@
}
// @@CONVERSION@@
fn controller(bus: u32) -> NativeController {
    NativeController { bus: backend_bus(bus).unwrap(), metadata: NativeInfo {
        profile: 1, version: [1,2,3,4,5], features: [0xa5;10], address: [1;6],
        command_credits: 1, acb_length: 254, acb_count: 5, icb_length: 0, icb_count: 0,
    } }
}
fn snapshot(c:&NativeController)->sle_uapi::SleControllerSnapshot {
    let mut out:sle_uapi::SleControllerSnapshot=unsafe{std::mem::zeroed()};
    c.fill_snapshot(&mut out);
    assert_eq!((out.generation,out.version,out.profile,out.dev_index,out.bus,out.reserved_byte,out.reserved),(0,0,0,0,0,0,[0;4]),"metadata must not manufacture identity or policy state");
    assert_eq!(c.metadata.command_credits,1,"bootstrap credit remains separate Host input");out
}
#[test]fn usb_retains_only_registration_identity(){let c=controller(1);let i=c.info();assert_eq!((i.bus as u8,i.addr),(4,[1;6]));}
#[test]fn test_provenance_never_becomes_usb(){let c=controller(2);assert_eq!(c.info().bus as u8,6);assert_ne!(c.info().bus,SleBus::Usb);}
#[test]fn unsupported_origins_do_not_fall_back_to_usb(){for raw in [0,3,4,5,6,255,u32::MAX]{assert_eq!(backend_bus(raw),Err(Error(-95)));}}
#[test]fn snapshot_retains_full_queried_wire_metadata(){for bus in [1,2]{let c=controller(bus);let i=snapshot(&c);assert_eq!(i.valid_fields,1);assert_eq!(i.version_tuple,[1,2,3,4,5]);assert_eq!(i.features,[0xa5;10]);assert_eq!(i.address,[1;6]);assert_eq!((i.acb_length,i.acb_count,i.icb_length,i.icb_count),(254,5,0,0));assert_eq!((i.flags,i.error,i.command_credits),(0,0,0),"metadata cannot manufacture Runtime status");}}
#[test]fn standard_profile_does_not_manufacture_ws73_capability(){let mut c=controller(1);c.metadata.profile=0;c.metadata.acb_length=0;c.metadata.acb_count=0;let i=snapshot(&c);assert_eq!((c.info().bus,i.acb_length,i.acb_count),(SleBus::Usb,0,0));assert_eq!((i.version_tuple,i.features),([1,2,3,4,5],[0xa5;10]));assert_eq!(i.flags,0);}
