// SPDX-License-Identifier: GPL-2.0-only
// Actual Native submit body; provider status/queue evidence are dependencies.
const PROTOCOL_ERROR:i32=-71;
struct NativeController;
impl NativeController {fn result(value:i32)->Result {if value<0{Err(value)}else{Ok(())}}}
struct NativeCommandTransport {transport:*mut c_void,never_submitted:Cell<bool>}
static mut VALIDATION:i32=0;
static mut IO_RESULT:i32=0;
static mut GUARDED:bool=true;
static mut QUEUED:bool=false;
static mut IO_CALLS:u32=0;
unsafe fn sparklink_native_transport_validate_connection(_: *mut c_void,_:u32,_:u16,_:*const u8,_:usize)->i32 {unsafe{VALIDATION}}
unsafe fn sparklink_native_transport_validate_step(_: *mut c_void,_:u32,_:u32,_:u32,_:u16,_:*const u8,_:usize)->i32 {unsafe{VALIDATION}}
unsafe fn sparklink_native_transport_validate(_: *mut c_void,_:u16,_:*const u8,_:usize)->i32 {unsafe{VALIDATION}}
unsafe fn sparklink_native_transport_has_command_ticket(_: *mut c_void)->bool {unsafe{GUARDED}}
unsafe fn sparklink_native_transport_command_ticketed(_: *mut c_void,t:*mut c_void,_:u16,_:*const u8,_:usize)->i32 {
 unsafe{IO_CALLS+=1;(*t.cast::<NativeCommandTicket<'_>>()).submitted.set(QUEUED);IO_RESULT}
}
unsafe fn sparklink_native_transport_command(_: *mut c_void,_:u16,_:*const u8,_:usize)->i32 {unsafe{IO_CALLS+=1;IO_RESULT}}
impl NativeCommandTransport {
 // @@SEND@@
}
#[test] fn actual_sender_classifies_only_proved_negative_unqueued_outcomes(){
 for case in 0..7 {
  unsafe{VALIDATION=if case==0{-95}else{0};IO_RESULT=match case{1=>-12,2=>-32,3=>1,4=>0,5=>-5,_=>0};GUARDED=case!=5;QUEUED=case==2||case==6;IO_CALLS=0;}
  let owner=ControllerRuntime{identity:DeviceIdentity{id:1,generation:2},host:FixtureLock(std::sync::Mutex::new(host())),schedule_gate:FixtureLock(std::sync::Mutex::new(false)),transport_open:AtomicBool::new(true)};
  let port=NativeCommandTransport{transport:core::ptr::null_mut(),never_submitted:Cell::new(false)};
  let result=port.send_typed(&owner,1,0x0404,&[],None,None,false);
  assert_eq!(result,[Err(-95),Err(-12),Err(-32),Err(-71),Err(-71),Err(-5),Ok(())][case]);
  assert_eq!(port.never_submitted.get(),case==0||case==1);assert_eq!(unsafe{IO_CALLS},if case==0{0}else{1});
 }
}

unsafe fn sparklink_native_transport_validate_relay(_p:*mut core::ffi::c_void,_op:u16,_v:*const u8,_n:usize)->i32{unsafe{VALIDATION}}
unsafe fn sparklink_native_transport_validate_runtime_address(_p:*mut core::ffi::c_void,_op:u16,_v:*const u8,_n:usize)->i32{unsafe{VALIDATION}}

#[test] fn relay_refuses_legacy_before_any_validation_io() {unsafe {
 let owner=ControllerRuntime {identity:DeviceIdentity {id:42,generation:2},host:FixtureLock(std::sync::Mutex::new(host())),schedule_gate:FixtureLock(std::sync::Mutex::new(false)),transport_open:std::sync::atomic::AtomicBool::new(true)};
 let port=NativeCommandTransport{transport:core::ptr::null_mut(),never_submitted:Cell::new(false)};
 GUARDED=false;IO_CALLS=0;VALIDATION=0;
 assert_eq!(port.send_typed(&owner,1,0x1812,&[0,0,0x47,1,1,2],None,None,true),Err(-95));
 assert!(port.never_submitted.get());assert_eq!({IO_CALLS},0);GUARDED=true;
}}
