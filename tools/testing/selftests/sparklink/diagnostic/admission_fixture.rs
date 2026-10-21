#[allow(dead_code, reason="Actual query dependency;metadata fixture does not exercise Managed reads")]
#[path="sle_link_query.rs"] mod sle_link_query;
#[allow(dead_code, reason="Actual query identity dependency;not live connection acceptance")]
#[path="sle_connection_operation.rs"] mod sle_connection_operation;
// SPDX-License-Identifier: GPL-2.0-only
// Actual submit handler, pending module, queue and Host enqueue/cancel bodies.
// Locks, clock, usercopy, owner lease and driver validation are dependencies.
extern crate self as kernel;
extern crate self as pin_init;
#[allow(dead_code)] // Actual relay dependency; this fixture does not submit SMP.
#[path = "sle_security_relay_state.rs"] mod sle_security_relay_state;
#[allow(dead_code)]
mod sle_security_relay { include!("relay_owner_fixture.rs"); }
pub trait Init<T> {}
pub struct FixtureInit<T>(std::marker::PhantomData<T>);
impl<T> Init<T> for FixtureInit<T> {}
macro_rules! init { ($($tokens:tt)*) => { crate::FixtureInit::<Self>(std::marker::PhantomData) }; }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Error(i32);
impl Error { pub fn from_errno(n: i32) -> Self { Self(n) } }
pub mod prelude {
 pub use crate::Error;
 pub type Result<T = ()> = core::result::Result<T, Error>;
 pub const EINVAL: Error = Error(-22); pub const EBUSY: Error = Error(-16);
 pub const EOVERFLOW: Error = Error(-75); pub const ENODEV: Error = Error(-19);
 pub const ENOENT: Error = Error(-2); pub const EPERM: Error = Error(-1);
 pub const EFAULT: Error = Error(-14);
}
pub mod bindings {
 pub unsafe fn ktime_get()->i64 {unsafe {jiffies_64 as i64 * 1_000_000}}
 pub const EOPNOTSUPP: u32 = 95; pub const ESTALE: u32 = 116;
 pub const EMSGSIZE: u32 = 90; pub const ETIMEDOUT: u32 = 110; pub const ECANCELED: u32 = 125;
 pub static mut JIFFIES_64: u64 = 0; pub use JIFFIES_64 as jiffies_64;
}
// Same clock-domain dependency as the existing jiffies fixture.
pub mod time { pub fn msecs_to_jiffies(ms: u32) -> u64 { u64::from(ms) } }
#[allow(dead_code)] // Whole production dependency; unused recipe functions outside this admission fixture.
#[path = "sle_command_plan.rs"] mod sle_command_plan;
#[allow(dead_code)] // Whole production queue also supplies unrelated recipe operations.
#[path = "sle_command_queue.rs"] mod sle_command_queue;
#[allow(dead_code, reason="Full production module; this fixture exercises only documented pending/admission subset")]
#[path = "sle_mgmt.rs"] mod sle_mgmt;
use prelude::*;
use sle_mgmt::CmdPendingQueue;
use std::pin::Pin;
use std::sync::{Mutex,MutexGuard};
struct TestMutex<T>(Mutex<T>);
impl<T> TestMutex<T> { fn new(v:T)->Self{Self(Mutex::new(v))} fn lock(&self)->MutexGuard<'_,T>{self.0.lock().unwrap()} }
#[derive(Clone,Copy,PartialEq,Eq)] struct Identity {generation:u64}
struct Target {identity:Identity}
struct Management {file:u64}
impl Management {fn authorize(&self,file:u64,mode:u32)->Result{if self.file==file&&mode==2 {Ok(())}else{Err(EPERM)}}}
mod sle_management {pub const DIAGNOSTIC:u32=2;}
fn management_error(e:Error)->Error{e}
#[derive(Clone,Copy,Debug,PartialEq,Eq)] struct Active {seq:u32,withdrawn:bool}
struct Host {
 requests:sle_command_queue::CmdRequestQueue, fault:Option<Error>, next_cookie:u64,
 // Reservation sentinels are inspected, not used to fake receive success.
 active:Option<Active>, credits:u8, reply:Option<u32>,
}
impl Host {
 // @@ENQUEUE@@
 // @@CANCEL@@
}
struct Owner {identity:Identity,protocol_profile:u32,management:TestMutex<Management>,schedule_gate:TestMutex<bool>,host:TestMutex<Host>}
impl Owner {fn schedule_rx(&self, delay: u32) {assert_eq!(delay,0); RX_WAKES.with(|n|n.set(n.get()+1));}
    fn kick_commands(&self){}}
struct Controller(u32);
impl Controller {fn validate_command(&self,opcode:u16,params:&[u8])->Result{if params == diagnostic_parameters(self.0,opcode)? {Ok(())}else{Err(Error(-95))}}}
struct State {cmd_pending:CmdPendingQueue,controller:Controller}
impl Owner {
 fn expire_command_deadlines(&self,state:&mut State) {
  // Only the queued-ledger adapter is modeled here. Expired physical slots
  // and existing-fault/author composition must use the actual Host runner.
  let now=unsafe{bindings::jiffies_64};let host=self.host.lock();
  assert!(host.active.is_none()||state.cmd_pending.next_deadline().is_none_or(|d|d>now));
  assert!(host.fault.is_none()||state.cmd_pending.pending()==0);
  state.cmd_pending.expire_at(now);
 }
}
struct RuntimeContext {owner:Option<Owner>,state:TestMutex<Option<State>>}
impl RuntimeContext {fn lock(&self)->Result<MutexGuard<'_,Option<State>>>{Ok(self.state.lock())}}
struct SparkLinkCtl {file_id:u64,target:TestMutex<Option<Target>>,diagnostic_request_id:TestMutex<u64>}
// @@PARAMETERS@@
// @@SUBMIT_STRUCT@@
thread_local! {
 static INPUT:std::cell::RefCell<SleDiagnosticSubmit>=std::cell::RefCell::new(request(1));
 static OUTPUT:std::cell::RefCell<Option<SleDiagnosticSubmit>>=const{std::cell::RefCell::new(None)};
}
fn read_user_struct(_:usize)->Result<SleDiagnosticSubmit>{INPUT.with(|p|{let v=*p.borrow();if v.reserved==0{Ok(v)}else{Err(EINVAL)}})}
fn write_user_struct(arg:usize,v:&SleDiagnosticSubmit)->Result {if arg==0 {return Err(EFAULT)} OUTPUT.with(|p|*p.borrow_mut()=Some(*v));Ok(())}
// @@SUBMIT_HANDLER@@
fn request(id:u64)->SleDiagnosticSubmit{SleDiagnosticSubmit{version:1,flags:0,generation:7,request_id:id,timeout_ms:5000,opcode:0x0406,reserved:0,seq:0,action:1}}
thread_local! {static RX_WAKES:std::cell::Cell<u32>=const {std::cell::Cell::new(0)};}
fn setup()->(RuntimeContext,SparkLinkCtl){
 RX_WAKES.with(|n|n.set(0));
 let _ = core::mem::size_of::<sle_mgmt::CmdRequest>();
 let identity=Identity{generation:7};
 (RuntimeContext{owner:Some(Owner{identity,protocol_profile:1,management:TestMutex::new(Management{file:42}),schedule_gate:TestMutex::new(false),host:TestMutex::new(Host{requests:sle_command_queue::CmdRequestQueue::new(),fault:None,next_cookie:1,active:None,credits:3,reply:None})}),state:TestMutex::new(Some(State{cmd_pending:CmdPendingQueue::new(),controller:Controller(1)}))},SparkLinkCtl{file_id:42,target:TestMutex::new(Some(Target{identity})),diagnostic_request_id:TestMutex::new(0)})
}
fn submit(c:&RuntimeContext,f:&SparkLinkCtl,r:SleDiagnosticSubmit,arg:usize)->Result<isize>{INPUT.with(|p|*p.borrow_mut()=r);OUTPUT.with(|p|*p.borrow_mut()=None);ioctl_diagnostic_submit(c,Pin::new(f),arg)}
fn seq()->u32{OUTPUT.with(|p|p.borrow().as_ref().unwrap().seq)}
#[test] fn copyout_failure_is_findable_idempotent_without_new_deadline(){
 let(c,f)=setup();assert_eq!(submit(&c,&f,request(1),0),Err(EFAULT));
 let first=c.state.lock().as_ref().unwrap().cmd_pending.find_request(42,1).unwrap().seq;
 for _ in 0..3{assert_eq!(submit(&c,&f,request(1),1),Ok(0));assert_eq!(seq(),first);}
 let state=c.state.lock();let q=&state.as_ref().unwrap().cmd_pending;
 assert_eq!((q.total_submitted,q.pending_count,q.find_by_seq(first).unwrap().deadline),(1,1,5000));
 let h=c.owner.as_ref().unwrap().host.lock();assert_eq!(h.requests.len(),1);assert_eq!(h.next_cookie,2);
}
#[test] fn retained_completed_retry_does_not_resend_or_change_data(){
 let(c,f)=setup();submit(&c,&f,request(1),1).unwrap();let first=seq();
 c.state.lock().as_mut().unwrap().cmd_pending.resolve_seq(first,0,&[9]);
 let mut cancel=request(1);cancel.action=2;submit(&c,&f,cancel,1).unwrap();submit(&c,&f,request(1),1).unwrap();
 let state=c.state.lock();let e=state.as_ref().unwrap().cmd_pending.find_by_seq(first).unwrap();
 assert_eq!((e.error,e.data[0],e.result_status()),(0,9,Some(0)));
 assert_eq!(c.owner.as_ref().unwrap().host.lock().next_cookie,2);
}
#[test] fn queued_cancel_preserves_unrelated_order_and_is_repeatable_after_efault(){
 let(c,f)=setup();for id in 1..=3{submit(&c,&f,request(id),1).unwrap();}
 let mut cancel=request(2);cancel.action=2;assert_eq!(submit(&c,&f,cancel,0),Err(EFAULT));submit(&c,&f,cancel,1).unwrap();let second=seq();
 let state=c.state.lock();let q=&state.as_ref().unwrap().cmd_pending;assert_eq!((q.pending_count,q.total_resolved,q.find_by_seq(second).unwrap().error),(2,1,-125));
 let mut h=c.owner.as_ref().unwrap().host.lock();assert_eq!(h.requests.pop().unwrap().seq,1);assert_eq!(h.requests.pop().unwrap().seq,3);assert!(h.requests.pop().is_none());
}
#[test] fn on_wire_cancel_keeps_reservation_and_late_reply_cannot_change_final(){
 let(c,f)=setup();submit(&c,&f,request(1),1).unwrap();let first=seq();
 {let mut h=c.owner.as_ref().unwrap().host.lock();h.requests.pop();h.active=Some(Active{seq:first,withdrawn:false});h.credits=0;h.reply=Some(first);}
 let mut cancel=request(1);cancel.action=2;submit(&c,&f,cancel,1).unwrap();
 {let h=c.owner.as_ref().unwrap().host.lock();assert_eq!((h.active,h.credits,h.reply),(Some(Active{seq:first,withdrawn:true}),0,Some(first)));}
 let mut state=c.state.lock();let q=&mut state.as_mut().unwrap().cmd_pending;
 assert!(!q.resolve_seq(first,0,&[9]));assert_eq!(q.find_by_seq(first).unwrap().error,-125);
}
#[test] fn eviction_watermark_prevents_old_id_from_becoming_new_command(){
 let(c,f)=setup();for id in 1..=33 {submit(&c,&f,request(id),1).unwrap();let seq=seq();c.state.lock().as_mut().unwrap().cmd_pending.resolve_seq(seq,0,&[]);}
 assert_eq!(submit(&c,&f,request(1),1),Err(Error(-116)));let mut cancel=request(1);cancel.action=2;assert_eq!(submit(&c,&f,cancel,1),Err(Error(-116)));
 assert_eq!(*f.diagnostic_request_id.lock(),33);assert_eq!(c.state.lock().as_ref().unwrap().cmd_pending.total_submitted,33);
}
#[test] fn changed_payload_old_ids_and_unknown_cancel_fail(){
 let(c,f)=setup();submit(&c,&f,request(5),1).unwrap();
 let mut changed=request(5);changed.opcode=0x0403;assert_eq!(submit(&c,&f,changed,1),Err(EINVAL));changed=request(5);changed.timeout_ms=100;assert_eq!(submit(&c,&f,changed,1),Err(EINVAL));
 assert_eq!(submit(&c,&f,request(4),1),Err(Error(-116)));let mut cancel=request(6);cancel.action=2;assert_eq!(submit(&c,&f,cancel,1),Err(ENOENT));assert_eq!(*f.diagnostic_request_id.lock(),5);
}
#[test] fn enqueue_failure_rolls_back_identity_count_and_watermark(){
 let(c,f)=setup();c.owner.as_ref().unwrap().host.lock().fault=Some(EBUSY);
 assert_eq!(submit(&c,&f,request(1),1),Err(EBUSY));assert_eq!(*f.diagnostic_request_id.lock(),0);
 assert_eq!(c.state.lock().as_ref().unwrap().cmd_pending.total_submitted,0);
 c.owner.as_ref().unwrap().host.lock().fault=None;submit(&c,&f,request(1),1).unwrap();assert_ne!(seq(),0);
}
#[test] fn invalid_fields_generation_profile_and_retired_runtime_reject(){
 let(mut c,f)=setup();let mut r=request(1);r.version=2;assert_eq!(submit(&c,&f,r,1),Err(Error(-95)));
 for r in [SleDiagnosticSubmit{flags:1,..request(1)},SleDiagnosticSubmit{generation:0,..request(1)},request(0),SleDiagnosticSubmit{timeout_ms:0,..request(1)},SleDiagnosticSubmit{timeout_ms:5001,..request(1)},SleDiagnosticSubmit{reserved:1,..request(1)},SleDiagnosticSubmit{seq:1,..request(1)},SleDiagnosticSubmit{action:3,..request(1)}]{assert_eq!(submit(&c,&f,r,1),Err(EINVAL));}
 let r=SleDiagnosticSubmit{generation:8,..request(1)};assert_eq!(submit(&c,&f,r,1),Err(ENODEV));
 let r=SleDiagnosticSubmit{opcode:0x0c05,..request(1)};assert_eq!(submit(&c,&f,r,1),Err(Error(-95)));
 c.owner.as_mut().unwrap().protocol_profile=2;assert_eq!(submit(&c,&f,request(1),1),Err(Error(-95)));c.owner.as_mut().unwrap().protocol_profile=1;
 let o=c.owner.as_ref().unwrap();*o.schedule_gate.lock()=true;o.management.lock().file=0;assert_eq!(submit(&c,&f,request(1),1),Err(ENODEV));
}
#[test] fn another_author_cannot_cancel_original_even_with_own_lease(){
 let(c,f)=setup();submit(&c,&f,request(1),1).unwrap();
 let other=SparkLinkCtl{file_id:43,target:TestMutex::new(Some(Target{identity:Identity{generation:7}})),diagnostic_request_id:TestMutex::new(0)};
 let mut cancel=request(1);cancel.action=2;assert_eq!(submit(&c,&other,cancel,1),Err(EPERM));
 c.owner.as_ref().unwrap().management.lock().file=43;assert_eq!(submit(&c,&other,cancel,1),Err(ENOENT));
 assert!(c.state.lock().as_ref().unwrap().cmd_pending.find_request(42,1).unwrap().is_pending());
 submit(&c,&other,request(1),1).unwrap();assert_eq!(seq(),2);
}

#[test] fn expiry_retry_keeps_deadline_and_cannot_revive_or_cancel_timeout(){
 let(c,f)=setup();let mut r=request(1);r.timeout_ms=1;submit(&c,&f,r,1).unwrap();let first=seq();
 // SAFETY: fixture clock is isolated and tests execute serially.
 unsafe {bindings::jiffies_64=2};
 let repeated=submit(&c,&f,r,1);r.action=2;let cancelled=submit(&c,&f,r,1);
 // SAFETY: restore fixture clock before assertions/other tests.
 unsafe {bindings::jiffies_64=0};
 assert_eq!(repeated,Ok(0));assert_eq!(cancelled,Ok(0));
 let state=c.state.lock();let q=&state.as_ref().unwrap().cmd_pending;let e=q.find_by_seq(first).unwrap();
 assert_eq!((e.error,e.deadline,q.total_submitted,q.total_timeouts),(-110,1,1,1));
}
#[test] fn full_pending_and_host_queues_do_not_commit_invisible_request_ids(){
 let(c,f)=setup();for id in 1..=32 {submit(&c,&f,request(id),1).unwrap();}
 assert_eq!(submit(&c,&f,request(33),1),Err(EBUSY));assert_eq!(*f.diagnostic_request_id.lock(),32);
 let(c,f)=setup();{let mut h=c.owner.as_ref().unwrap().host.lock();for seq in 1..=64{h.requests.push_tagged(0x0406,&[],seq,0,None,5000).unwrap();}}
 assert_eq!(submit(&c,&f,request(1),1),Err(EBUSY));assert_eq!(*f.diagnostic_request_id.lock(),0);assert_eq!(c.state.lock().as_ref().unwrap().cmd_pending.total_submitted,0);
}

#[test] fn committed_admission_and_retry_wake_rx_but_rejection_does_not(){
 let(c,f)=setup();assert_eq!(submit(&c,&f,request(1),0),Err(EFAULT));
 assert_eq!(RX_WAKES.with(|n|n.get()),1);
 let deadline=c.state.lock().as_ref().unwrap().cmd_pending.find_request(42,1).unwrap().deadline;
 submit(&c,&f,request(1),1).unwrap();
 assert_eq!(RX_WAKES.with(|n|n.get()),2);
 assert_eq!(c.state.lock().as_ref().unwrap().cmd_pending.find_request(42,1).unwrap().deadline,deadline);
 let mut bad=request(2);bad.timeout_ms=0;assert_eq!(submit(&c,&f,bad,1),Err(EINVAL));
 assert_eq!(RX_WAKES.with(|n|n.get()),2);
}

#[test] fn standard_fixed_address_type_reaches_actual_queue_and_retries_once() {
 let(mut c,f)=setup();c.owner.as_mut().unwrap().protocol_profile=0;c.state.lock().as_mut().unwrap().controller.0=0;
 let r=SleDiagnosticSubmit{opcode:0x0406,..request(1)};submit(&c,&f,r,1).unwrap();submit(&c,&f,r,1).unwrap();
 let mut h=c.owner.as_ref().unwrap().host.lock();assert_eq!(h.requests.len(),1);let q=h.requests.pop().unwrap();
 assert_eq!(q.opcode,0x0406);assert_eq!(q.param_len,1);assert_eq!(q.params[0],0);
 assert_eq!(*f.diagnostic_request_id.lock(),1);
}
#[test] fn dialect_query_parameters_are_exact_and_mutations_always_reject() {
 for opcode in 0..=u16::MAX {
  for profile in [0,1,2,u32::MAX] {
   let expected=match (profile,opcode) {(0,0x0406)=>Some(&[0][..]),(0,0x0401..=0x0404)|(1,0x0402|0x0403|0x0404|0x0406)=>Some(&[][..]),_=>None};
   match expected {Some(p)=>assert_eq!(diagnostic_parameters(profile,opcode),Ok(p)),None=>assert_eq!(diagnostic_parameters(profile,opcode),Err(Error(-95)))}
  }
 }
}
