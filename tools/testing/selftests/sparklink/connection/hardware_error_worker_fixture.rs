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
struct ControllerState{cmd_pending:crate::hardware_fault_pending::CmdPendingQueue}
thread_local!{static LOG:std::cell::RefCell<Vec<String>>=const{std::cell::RefCell::new(Vec::new())};}
macro_rules! pr_warn {($($arg:tt)*)=>{LOG.with(|v|v.borrow_mut().push(format!($($arg)*)));}}
// @@WORKER@@
// @@FAIL@@
// @@ENQUEUE@@
fn owner(id:u16)->Arc<ControllerRuntime>{Arc::new(ControllerRuntime{identity:Identity{id,generation:7},host:Lock(Mutex::new(host())),schedule_gate:Lock(Mutex::new(false)),ingress:Lock(Mutex::new(FullRing{calls:0})),dropped_commands:AtomicU32::new(0),dropped_mac:AtomicU32::new(0),wakes:AtomicU32::new(0),kicks:AtomicU32::new(0)})}
fn state()->ControllerState{ControllerState{cmd_pending:crate::hardware_fault_pending::CmdPendingQueue::new()}}
fn admit(o:&Arc<ControllerRuntime>,s:&mut ControllerState,request:u64)->u32{
 let seq=s.cmd_pending.submit_with_timeout(0x0404,100).unwrap();s.cmd_pending.assign_request(seq,42,request);
 let deadline=s.cmd_pending.find_by_seq(seq).unwrap().deadline;o.host.lock().enqueue_diagnostic(0x0404,&[],seq,deadline).unwrap();seq
}
fn entry(s:&ControllerState,seq:u32)->&crate::hardware_fault_pending::CmdPendingEntry{s.cmd_pending.find_by_seq(seq).unwrap()}
fn begin(o:&Arc<ControllerRuntime>)->u64{let mut h=o.host.lock();let q=h.next(|_|true).unwrap().unwrap();h.command_committed(q.cookie);h.transport_complete(q.cookie);q.cookie}
fn reply(o:&Arc<ControllerRuntime>){o.host.lock().receive(SleEvent::NativeCommandReply{opcode:0x0404,command_credits:1,status:0,complete:true,data:vec![9]});}
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
  if completed {reply(&o);assert!(process_host_events(&o,&mut s));assert_eq!(entry(&s,a).result_status(),Some(0));}else{clock(deadline);assert_eq!(s.cmd_pending.expire_stale(),1);assert_eq!(entry(&s,a).error,-110);}
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
