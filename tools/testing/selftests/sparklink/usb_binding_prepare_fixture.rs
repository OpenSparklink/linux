// SPDX-License-Identifier: GPL-2.0-only
// Actual current standard prepare/init; dependencies are controlled, no firmware or USB I/O.
extern crate self as kernel;
#[derive(Clone,Copy,Debug,PartialEq,Eq)]struct Error(i32);
impl Error { fn from_errno(n:i32)->Self{Self(n)} }
const EIO:Error=Error(-5);const ENODEV:Error=Error(-19);
type Result<T=()> = std::result::Result<T,Error>;
mod bindings { pub const EPROTO:u32=71; }
mod device {pub(crate) struct Device;}
struct UsbDevice;
impl UsbDevice {fn as_raw(&self)->usize{123}}
struct State { init:i32,mac:i32,address:[u8;6],version:u32,calls:Vec<&'static str> }
static STATE:std::sync::Mutex<Option<State>>=std::sync::Mutex::new(None);
fn reset(){*STATE.lock().unwrap()=Some(State{init:0,mac:0,address:[1,2,3,4,5,6],version:0x12345678,calls:vec![]});}
fn state<T>(f:impl FnOnce(&mut State)->T)->T{f(STATE.lock().unwrap().as_mut().unwrap())}
unsafe fn sle_usb_dev_init_controller(id:usize)->i32{assert_eq!(id,123);state(|s|{s.calls.push("init");s.init})}
unsafe fn sle_usb_dev_get_mac(id:usize,out:*mut u8)->i32{assert_eq!(id,123);state(|s|{s.calls.push("mac");if s.mac==0{unsafe{std::ptr::copy_nonoverlapping(s.address.as_ptr(),out,6);}}s.mac})}
unsafe fn sle_usb_dev_get_fw_version(id:usize)->u32{assert_eq!(id,123);state(|s|{s.calls.push("version");s.version})}
// @@INIT@@
// @@PREPARE@@
#[test]fn standard_prepare_queries_running_device_without_generic_firmware_stage(){reset();assert_eq!(prepare_usb_controller(&UsbDevice,&device::Device),Ok(([1,2,3,4,5,6],0x12345678)));assert_eq!(state(|s|s.calls.clone()),["init","mac","version"]);}
#[test]fn failed_or_positive_init_never_queries_or_publishes_metadata(){for ret in [-19,-110,1]{reset();state(|s|s.init=ret);assert_eq!(prepare_usb_controller(&UsbDevice,&device::Device),Err(if ret<0{Error(ret)}else{EIO}));assert_eq!(state(|s|s.calls.clone()),["init"]);}}
#[test]fn failed_or_positive_address_never_uses_default_version(){for ret in [-19,-61,1]{reset();state(|s|s.mac=ret);assert_eq!(prepare_usb_controller(&UsbDevice,&device::Device),Err(if ret<0{Error(ret)}else{EIO}));assert_eq!(state(|s|s.calls.clone()),["init","mac"]);}}
#[test]fn zero_and_ff_address_fail_before_version(){for address in [[0;6],[255;6]]{reset();state(|s|s.address=address);assert_eq!(prepare_usb_controller(&UsbDevice,&device::Device),Err(Error(-71)));assert_eq!(state(|s|s.calls.clone()),["init","mac"]);}}
#[test]fn independent_calls_do_not_hide_failed_init(){reset();state(|s|s.init=ENODEV.0);assert_eq!(prepare_usb_controller(&UsbDevice,&device::Device),Err(ENODEV));reset();assert!(prepare_usb_controller(&UsbDevice,&device::Device).is_ok());}

use std::sync::atomic::{AtomicUsize,Ordering};
use std::sync::{Arc,OnceLock};
mod sle_dev {pub const SLE_DEV_MAX:usize=16;#[derive(Clone,Copy)]pub struct DeviceIdentity{pub id:u16,pub generation:u64}}
struct Owner { dropped_decode:AtomicUsize,protocol_profile:u32 }
static OWNER:OnceLock<Arc<Owner>>=OnceLock::new();
static PARSES:AtomicUsize=AtomicUsize::new(0);
static QUEUED:AtomicUsize=AtomicUsize::new(0);
fn ingress_owner(identity:sle_dev::DeviceIdentity)->Option<Arc<Owner>>{if identity.id==2&&identity.generation==3{Some(OWNER.get_or_init(||Arc::new(Owner{dropped_decode:AtomicUsize::new(0),protocol_profile:0})).clone())}else{None}}
struct Parsed{event_code:u16}
fn parse_event_packet(data:&[u8])->Result<Parsed>{PARSES.fetch_add(1,Ordering::Relaxed);if data.first()==Some(&2){Ok(Parsed{event_code:2})}else{Err(EIO)}}
fn event_to_sle(_: &Parsed)->Option<()>{Some(())}
fn enqueue_rx(_: &Owner,_:()){QUEUED.fetch_add(1,Ordering::Relaxed);}
macro_rules! pr_debug { ($($t:tt)*) => {let _=format_args!($($t)*);}; }
mod sle_native {
 pub(crate) unsafe fn sparklink_native_snoop_rx_rust(id:u16,generation:u64,data:*const u8,length:usize) {
  assert_eq!((id,generation),(2,3));
  let bytes=unsafe {std::slice::from_raw_parts(data,length)};
  super::OBSERVED.lock().unwrap().push(bytes.to_vec());
 }
}
static OBSERVED:std::sync::Mutex<Vec<Vec<u8>>>=std::sync::Mutex::new(Vec::new());
mod actual_rx {
 use super::*;
 // @@RX@@
}
use actual_rx::sparklink_standard_receive_rust;
fn rx_reset(){OBSERVED.lock().unwrap().clear();PARSES.store(0,Ordering::Relaxed);QUEUED.store(0,Ordering::Relaxed);OWNER.get_or_init(||Arc::new(Owner{dropped_decode:AtomicUsize::new(0),protocol_profile:0})).dropped_decode.store(0,Ordering::Relaxed);}
#[test]fn event_lane_uses_decoder_dependency_without_uart_marker(){rx_reset();let data=[2,0,4,0,3,4,1,0];sparklink_standard_receive_rust(2,3,data.as_ptr(),8,1,0);assert_eq!(PARSES.load(Ordering::Relaxed),1);assert_eq!(QUEUED.load(Ordering::Relaxed),1);assert_eq!(*OBSERVED.lock().unwrap(),vec![data.to_vec()]);}
#[test]fn bulk_or_unknown_lane_never_enters_event_or_legacy_data_decoder(){rx_reset();for lane in [0,2,3]{sparklink_standard_receive_rust(2,3,1usize as *const u8,8,lane,0);}assert_eq!(PARSES.load(Ordering::Relaxed),0);assert_eq!(QUEUED.load(Ordering::Relaxed),0);assert_eq!(OWNER.get().unwrap().dropped_decode.load(Ordering::Relaxed),3);}
#[test]fn status_stale_zero_generation_and_bad_index_precede_buffer_access(){rx_reset();for(id,generation,status)in[(2,3,-19),(16,3,0),(2,0,0),(2,4,0)]{sparklink_standard_receive_rust(id,generation,1usize as *const u8,8,1,status);}assert_eq!(PARSES.load(Ordering::Relaxed),0);assert_eq!(QUEUED.load(Ordering::Relaxed),0);}

#[test]fn observation_preserves_malformed_packet_before_decoder_failure(){
 rx_reset();let bytes=[0xfe,0,0,0];sparklink_standard_receive_rust(2,3,bytes.as_ptr(),bytes.len() as i32,1,0);
 assert_eq!(*OBSERVED.lock().unwrap(),vec![bytes.to_vec()]);assert_eq!(PARSES.load(Ordering::Relaxed),1);
 assert_eq!(QUEUED.load(Ordering::Relaxed),0);assert_eq!(OWNER.get().unwrap().dropped_decode.load(Ordering::Relaxed),1);
}
