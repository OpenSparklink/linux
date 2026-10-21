// SPDX-License-Identifier: GPL-2.0-only
// Actual Host, pending ledger, RX admission and worker functions. Mutex/Arc,
// clock, nonexecuted kernel allocator initializer and full ring are dependencies.
// This is not IRQ/workqueue concurrency, USB, firmware or RF qualification.
mod hardware_fault_worker {
use super::*;
use std::sync::{Arc,Mutex,MutexGuard};
use std::sync::atomic::{AtomicU32,Ordering};
struct Lock<T>(Mutex<T>);
impl<T> Lock<T>{fn lock(&self)->MutexGuard<'_,T>{self.0.lock().unwrap()}}
struct Identity{id:u16,generation:u64}
struct FullRing{calls:u32}
impl FullRing {fn push_tagged(&mut self,_id:Option<u16>,_event:SleEvent)->bool{self.calls+=1;false}}
pub(crate) struct ControllerRuntime{identity:Identity,host:Lock<CommandHost>,schedule_gate:Lock<bool>,ingress:Lock<FullRing>,dropped_commands:AtomicU32,dropped_mac:AtomicU32,wakes:AtomicU32,kicks:AtomicU32}
impl ControllerRuntime{
 fn schedule_rx(&self,delay:u32){assert_eq!(delay,0);assert!(self.host.0.try_lock().is_ok());assert!(self.schedule_gate.0.try_lock().is_ok());self.wakes.fetch_add(1,Ordering::Relaxed);}
 fn kick_commands(&self){self.kicks.fetch_add(1,Ordering::Relaxed);}
}
struct Provider { address:[u8;6] }
impl Provider { fn observe_runtime_address(&mut self,address:[u8;6]) { self.address=address; } }
struct Controller { provider:Provider }
impl Controller { fn provider_mut(&mut self)->&mut Provider { &mut self.provider } }
struct DevInfo { addr:super::sle_uapi::SleAddr }
pub(crate) struct ControllerState{cmd_pending:crate::hardware_fault_pending::CmdPendingQueue,controller:Controller,dev_info:DevInfo}
thread_local!{static LOG:std::cell::RefCell<Vec<String>>=const{std::cell::RefCell::new(Vec::new())};}
macro_rules! pr_warn {($($arg:tt)*)=>{LOG.with(|v|v.borrow_mut().push(format!($($arg)*)));}}
impl ControllerRuntime {
// @@EXPIRE@@
}
// @@WORKER@@
// @@FAIL@@
// @@FAIL_LOCKED@@
// @@ENQUEUE@@
fn owner(id:u16)->Arc<ControllerRuntime>{Arc::new(ControllerRuntime{identity:Identity{id,generation:7},host:Lock(Mutex::new(host())),schedule_gate:Lock(Mutex::new(false)),ingress:Lock(Mutex::new(FullRing{calls:0})),dropped_commands:AtomicU32::new(0),dropped_mac:AtomicU32::new(0),wakes:AtomicU32::new(0),kicks:AtomicU32::new(0)})}
fn state()->ControllerState{ControllerState{cmd_pending:crate::hardware_fault_pending::CmdPendingQueue::new(),controller:Controller{provider:Provider{address:[9;6]}},dev_info:DevInfo{addr:super::sle_uapi::SleAddr{b:[9;6]}}}}
fn admit(o:&Arc<ControllerRuntime>,s:&mut ControllerState,request:u64)->u32{
 let seq=s.cmd_pending.submit_with_timeout(0x0404,100).unwrap();s.cmd_pending.assign_request(seq,42,request);
 let deadline=s.cmd_pending.find_by_seq(seq).unwrap().deadline;o.host.lock().enqueue_diagnostic(0x0404,&[],seq,deadline).unwrap();seq
}
fn entry(s:&ControllerState,seq:u32)->&crate::hardware_fault_pending::CmdPendingEntry{s.cmd_pending.find_by_seq(seq).unwrap()}
fn begin(o:&Arc<ControllerRuntime>)->u64{let mut h=o.host.lock();let q=h.next(|_|true).unwrap().unwrap();h.command_committed(q.cookie);h.transport_complete(q.cookie);q.cookie}
fn reply(o:&Arc<ControllerRuntime>){o.host.lock().receive(SleEvent::NativeCommandReply{opcode:0x0404,command_credits:1,status:0,complete:true,data:vec![9]});}
fn address(o:&Arc<ControllerRuntime>,s:&mut ControllerState)->(u32,u64,u64){
 let value=[0xa6,0x7b,0x73,0x10,0xe0,1];
 let seq=s.cmd_pending.submit_with_timeout(0x0405,500).unwrap();s.cmd_pending.assign_request(seq,42,1);
 let deadline=entry(s,seq).deadline;
 o.host.lock().operations=Operations::new();
 o.host.lock().enqueue_runtime_address(7,42,1,seq,500,deadline,value,0x0405,&value).unwrap();
 let cookie=begin(o);(seq,cookie,deadline)
}
#[test]fn original_address_deadline_publishes_actual_host_fault_before_author_timeout(){
 for delta in [-1i64,0,1]{clock(1);let o=owner(1);let mut s=state();let(seq,cookie,deadline)=address(&o,&mut s);
  clock((deadline as i64+delta)as u64);o.expire_command_deadlines(&mut s);
  if delta<0 {assert!(entry(&s,seq).is_pending());assert!(o.host.lock().fault.is_none());assert!(o.host.lock().active.is_some());}
  else {
   assert_eq!((entry(&s,seq).error,entry(&s,seq).deadline,s.cmd_pending.total_resolved),(-110,deadline,1));
   assert_eq!(o.host.lock().controller_status(),(0,false,Some(-110)));assert!(!o.host.lock().address_metadata_valid());
   for _ in 0..3{o.expire_command_deadlines(&mut s);}assert_eq!(s.cmd_pending.total_resolved,1);
   o.host.lock().receive(SleEvent::NativeCommandReply{opcode:0x0405,command_credits:1,status:0,complete:true,data:vec![]});
   assert!(!o.host.lock().transport_complete(cookie));assert!(!process_host_events(&o,&mut s));
   assert_eq!((entry(&s,seq).error,s.cmd_pending.total_resolved),(-110,1));assert_eq!(o.host.lock().credits,0);
  }
 }
}
#[test]fn unselected_query_expiry_does_not_fabricate_host_fault_or_refund_credit(){
 clock(1);let o=owner(1);let mut s=state();let seq=admit(&o,&mut s,1);let deadline=entry(&s,seq).deadline;
 o.host.lock().credits=0;clock(deadline);o.expire_command_deadlines(&mut s);
 assert_eq!(entry(&s,seq).error,-110);assert!(o.host.lock().fault.is_none());assert_eq!(o.host.lock().credits,0);
 assert!(o.host.lock().next(|n|entry(&s,n).is_pending()).unwrap().is_none());
 // A zero-credit scheduler does not consume even an expired software entry.
 // Keep the bounded queue; only a real credit observation enables its drain.
 assert!(!o.host.lock().quiet());assert_eq!(o.host.lock().requests.len(),1);
 o.host.lock().receive(SleEvent::CommandCredits{credits:1});
 assert!(o.host.lock().next(|n|entry(&s,n).is_pending()).unwrap().is_none());assert!(o.host.lock().quiet());
 assert_eq!(o.host.lock().credits,1);
}
#[test]fn first_fault_and_cancelled_author_survive_shared_expiry_and_late_reply(){
 for cancelled in [false,true]{clock(1);let o=owner(1);let mut s=state();let(seq,cookie,deadline)=address(&o,&mut s);
  if cancelled{s.cmd_pending.cancel_seq(seq);o.host.lock().withdraw_runtime_address(seq);}
  o.host.lock().receive(SleEvent::HardwareError{code:7});clock(deadline);o.expire_command_deadlines(&mut s);
  assert_eq!(entry(&s,seq).error,if cancelled{-125}else{-5});assert_eq!(o.host.lock().fault,Some(EIO));
  assert!(!o.host.lock().transport_complete(cookie));process_host_events(&o,&mut s);o.expire_command_deadlines(&mut s);
  assert_eq!(s.cmd_pending.total_resolved,1);assert_eq!(o.host.lock().credits,0);
 }
}
#[test]fn address_set_complete_does_not_renew_original_readback_deadline(){
 clock(1);let o=owner(1);let mut s=state();let(seq,_,deadline)=address(&o,&mut s);
 o.host.lock().receive(SleEvent::NativeCommandReply{opcode:0x0405,command_credits:1,status:0,complete:true,data:vec![]});
 assert!(process_host_events(&o,&mut s));assert_eq!(entry(&s,seq).result_status(),Some(0));assert!(!o.host.lock().address_metadata_valid());
 clock(deadline);o.expire_command_deadlines(&mut s);assert_eq!(o.host.lock().fault,Some(ETIMEDOUT));
 assert_eq!(entry(&s,seq).result_status(),Some(0));assert_eq!(s.controller.provider.address,[9;6]);assert_eq!(s.dev_info.addr.b,[9;6]);
}
#[test]fn shared_expiry_never_advances_another_controller(){
 clock(1);let a=owner(1);let b=owner(2);let mut sa=state();let mut sb=state();let(qa,_,deadline)=address(&a,&mut sa);
 let qb=sb.cmd_pending.submit_with_timeout(0x0404,5000).unwrap();sb.cmd_pending.assign_request(qb,42,1);
 let end=entry(&sb,qb).deadline;b.host.lock().enqueue_diagnostic(0x0404,&[],qb,end).unwrap();begin(&b);
 clock(deadline);a.expire_command_deadlines(&mut sa);assert_eq!(entry(&sa,qa).error,-110);
 assert!(entry(&sb,qb).is_pending());assert!(b.host.lock().fault.is_none());reply(&b);assert!(process_host_events(&b,&mut sb));assert_eq!(entry(&sb,qb).result_status(),Some(0));
}
#[test]fn real_worker_fault_drains_actual_author_ledger_once(){
 clock(1);LOG.with(|l|l.borrow_mut().clear());let o=owner(1);let mut s=state();let a=admit(&o,&mut s,1);let b=admit(&o,&mut s,2);let cookie=begin(&o);
 assert!(o.host.lock().receive(SleEvent::HardwareError{code:7}).is_none());assert!(o.host.lock().active.as_ref().unwrap().transport_submitted);
 assert!(process_host_events(&o,&mut s));assert_eq!((entry(&s,a).error,entry(&s,b).error),(-5,-5));assert_eq!(s.cmd_pending.pending(),0);assert_eq!(s.cmd_pending.total_resolved,2);
 assert!(!process_host_events(&o,&mut s));reply(&o);assert!(!o.host.lock().transport_complete(cookie));assert!(!process_host_events(&o,&mut s));fail_host(&o,&mut s,-110);
 assert_eq!(s.cmd_pending.total_resolved,2);assert_eq!(entry(&s,a).error,-5);assert_eq!(o.host.lock().credits,0);
 LOG.with(|l|{let v=l.borrow();assert_eq!(v.len(),1);assert!(v[0].contains("sle1 generation=7"));assert!(v[0].contains("0x07"));});
}
#[test]fn cancelled_author_keeps_original_terminal_and_physical_reservation(){
 clock(1);let o=owner(1);let mut s=state();let a=admit(&o,&mut s,1);let b=admit(&o,&mut s,2);begin(&o);
 s.cmd_pending.cancel_seq(a);o.host.lock().cancel_diagnostic(a);o.host.lock().receive(SleEvent::HardwareError{code:1});
 assert!(o.host.lock().active.is_some());assert!(process_host_events(&o,&mut s));assert_eq!(entry(&s,a).error,-125);assert_eq!(entry(&s,b).error,-5);assert_eq!(s.cmd_pending.total_resolved,2);
}
#[test]fn author_original_deadline_and_prior_success_cannot_be_rewritten(){
 for completed in [false,true]{clock(1);let o=owner(1);let mut s=state();let a=admit(&o,&mut s,1);let deadline=entry(&s,a).deadline;begin(&o);
  if completed {reply(&o);assert!(process_host_events(&o,&mut s));assert_eq!(entry(&s,a).result_status(),Some(0));}else{clock(deadline);assert_eq!(s.cmd_pending.expire_at(unsafe { kernel::bindings::jiffies_64 }),1);assert_eq!(entry(&s,a).error,-110);}
  o.host.lock().receive(SleEvent::HardwareError{code:2});assert!(process_host_events(&o,&mut s));assert_eq!(entry(&s,a).deadline,deadline);assert_eq!(s.cmd_pending.total_resolved,1);
  if completed{assert_eq!(entry(&s,a).result_status(),Some(0));}else{assert_eq!(entry(&s,a).error,-110);}
 }
}
#[test]fn actual_ring_overflow_cannot_drop_fault_or_its_wake(){
 clock(1);let o=owner(1);let mut s=state();let a=admit(&o,&mut s,1);begin(&o);
 // Full-ring dependency is fail-closed, with an ordinary command as a negative
 // control proving this fixture really refuses and counts normal RX traffic.
 enqueue_rx(&o,SleEvent::NativeCommandReply{opcode:0x0403,command_credits:1,status:0,complete:true,data:vec![]});
 assert_eq!(o.ingress.lock().calls,1);assert_eq!(o.dropped_commands.load(Ordering::Relaxed),1);
 enqueue_rx(&o,SleEvent::HardwareError{code:8});assert_eq!(o.ingress.lock().calls,1);assert_eq!(o.wakes.load(Ordering::Relaxed),2);
 assert_eq!(o.host.lock().controller_status(),(0,false,Some(EIO)));assert!(process_host_events(&o,&mut s));assert_eq!(entry(&s,a).error,-5);
}
#[test]fn worker_fault_isolation_uses_distinct_hosts_and_actual_ledgers(){
 clock(1);let a=owner(1);let b=owner(2);let mut sa=state();let mut sb=state();let qa=admit(&a,&mut sa,1);let qb=admit(&b,&mut sb,1);begin(&a);begin(&b);
 enqueue_rx(&a,SleEvent::HardwareError{code:9});assert!(process_host_events(&a,&mut sa));assert_eq!(entry(&sa,qa).error,-5);
 assert!(entry(&sb,qb).is_pending());assert!(b.host.lock().controller_status().1);assert!(b.host.lock().admits_data());reply(&b);assert!(process_host_events(&b,&mut sb));assert_eq!(entry(&sb,qb).result_status(),Some(0));assert_eq!(entry(&sb,qb).data[0],9);
 assert_eq!(a.kicks.load(Ordering::Relaxed),0);assert_eq!(b.kicks.load(Ordering::Relaxed),1);
}
#[test]fn first_latched_fault_drives_worker_and_ledger_even_if_transport_error_wins_state_lock(){
 clock(1);let o=owner(1);let mut s=state();let a=admit(&o,&mut s,1);begin(&o);o.host.lock().receive(SleEvent::HardwareError{code:10});
 fail_host(&o,&mut s,-19);assert_eq!(entry(&s,a).error,-5);assert_eq!(o.host.lock().fault,Some(EIO));assert!(process_host_events(&o,&mut s));assert_eq!(s.cmd_pending.total_resolved,1);
}
}
