// SPDX-License-Identifier: GPL-2.0-only
// Actual Rust commit body + full actual Host. Locks/transport are dependencies.
use core::cell::Cell;
use core::ffi::c_void;
use core::sync::atomic::{AtomicBool, Ordering};
#[derive(Clone,Copy,PartialEq,Eq)] struct DeviceIdentity { id:u16,generation:u64 }
struct FixtureLock<T>(std::sync::Mutex<T>);
impl<T> FixtureLock<T> { fn lock(&self)->std::sync::MutexGuard<'_,T>{self.0.lock().unwrap()} }
struct ControllerRuntime { identity:DeviceIdentity,host:FixtureLock<CommandHost>,schedule_gate:FixtureLock<bool>,transport_open:AtomicBool }
const ENODEV:i32=-19;
// @@TICKET@@
// @@COMMIT@@
struct Submit<'a> { owner:&'a ControllerRuntime,calls:Cell<u32>,result:i32 }
unsafe extern "C" fn atomic_submit(context:*mut c_void)->i32 {
 let c=unsafe{&*context.cast::<Submit<'_>>()};
 assert!(c.owner.host.0.try_lock().is_err());assert!(c.owner.schedule_gate.0.try_lock().is_err());
 c.calls.set(c.calls.get()+1);c.result
}
#[test] fn command_ticket_atomic_callback_once_under_actual_host_gate(){
 clock(1);let mut h=host();create(&mut h,1);let r=h.next(|_|true).unwrap().unwrap();
 let owner=ControllerRuntime{identity:DeviceIdentity{id:1,generation:2},host:FixtureLock(std::sync::Mutex::new(h)),schedule_gate:FixtureLock(std::sync::Mutex::new(false)),transport_open:AtomicBool::new(true)};
 let mut ticket=NativeCommandTicket{owner:&owner,cookie:r.cookie,opcode:r.opcode,attempted:Cell::new(false),submitted:Cell::new(false),materialized:Cell::new(false)};
 let mut context=Submit{owner:&owner,calls:Cell::new(0),result:0};
 let pointer=(&mut ticket as *mut NativeCommandTicket<'_>).cast();let ctx=(&mut context as *mut Submit<'_>).cast();
 assert_eq!(unsafe{sparklink_native_command_commit_rust(pointer,1,2,Some(atomic_submit),ctx)},0);
 assert!(ticket.submitted.get());assert_eq!(context.calls.get(),1);assert!(owner.host.lock().active.as_ref().unwrap().transport_submitted);
 assert_eq!(unsafe{sparklink_native_command_commit_rust(pointer,1,2,Some(atomic_submit),ctx)},-114);assert_eq!(context.calls.get(),1);
}
#[test] fn command_ticket_wrong_registration_withdrawal_deadline_and_refusal(){
 for case in 0..6 {
  clock(1);let mut h=host();h.enqueue_diagnostic(0x0404,&[],9,100).unwrap();let r=h.next(|_|true).unwrap().unwrap();
  if case==3 {h.cancel_diagnostic(9);}if case==4 {clock(100);}
  let owner=ControllerRuntime{identity:DeviceIdentity{id:1,generation:2},host:FixtureLock(std::sync::Mutex::new(h)),schedule_gate:FixtureLock(std::sync::Mutex::new(case==1)),transport_open:AtomicBool::new(case!=2)};
  let mut ticket=NativeCommandTicket{owner:&owner,cookie:r.cookie,opcode:r.opcode,attempted:Cell::new(false),submitted:Cell::new(false),materialized:Cell::new(false)};
  let mut context=Submit{owner:&owner,calls:Cell::new(0),result:if case==5{-12}else{0}};
  let ret=unsafe{sparklink_native_command_commit_rust((&mut ticket as *mut NativeCommandTicket<'_>).cast(),1,if case==0{3}else{2},Some(atomic_submit),(&mut context as *mut Submit<'_>).cast())};
  assert_eq!(ret,[-116,-19,-11,-125,-110,-12][case]);assert!(!ticket.submitted.get());
  assert_eq!(context.calls.get(),if case==5{1}else{0});assert!(!owner.host.lock().active.as_ref().unwrap().transport_submitted);
 }
}

#[test] fn hardware_fault_prevents_actual_atomic_command_submission() {
 clock(1);let mut h=host();h.enqueue_diagnostic(0x0404,&[],9,100).unwrap();let q=h.next(|_|true).unwrap().unwrap();
 let owner=ControllerRuntime{identity:DeviceIdentity{id:1,generation:2},host:FixtureLock(std::sync::Mutex::new(h)),schedule_gate:FixtureLock(std::sync::Mutex::new(false)),transport_open:AtomicBool::new(true)};
 owner.host.lock().receive(SleEvent::HardwareError{code:7});
 let mut ticket=NativeCommandTicket{owner:&owner,cookie:q.cookie,opcode:q.opcode,attempted:Cell::new(false),submitted:Cell::new(false),materialized:Cell::new(false)};
 let mut context=Submit{owner:&owner,calls:Cell::new(0),result:0};
 assert_eq!(unsafe{sparklink_native_command_commit_rust((&mut ticket as *mut NativeCommandTicket<'_>).cast(),1,2,Some(atomic_submit),(&mut context as *mut Submit<'_>).cast())},-5);
 assert_eq!(context.calls.get(),0);assert!(!ticket.submitted.get());assert!(owner.host.lock().active.is_some());
}
