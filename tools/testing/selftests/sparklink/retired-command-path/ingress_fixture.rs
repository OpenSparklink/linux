// SPDX-License-Identifier: GPL-2.0-only
// Actual production route/queue functions below. std Mutex/Arc, queue storage
// and event payload are fixtures, not kernel IRQ or workqueue refinement.
extern crate self as kernel;
pub mod sync { pub use std::sync::Arc; }
use std::sync::{Arc, LazyLock, Mutex, MutexGuard, Barrier};
use std::sync::atomic::{AtomicU32, Ordering};
use std::collections::VecDeque;
use std::cell::RefCell;
use std::ops::{Deref,DerefMut};
thread_local!{static HELD:RefCell<Vec<u8>>=const{RefCell::new(Vec::new())};}
type Result = std::result::Result<(), i32>;
const EINVAL:i32=-22;const ENODEV:i32=-19;const EBUSY:i32=-16;
trait Errno{fn to_errno(&self)->i32;}impl Errno for i32{fn to_errno(&self)->i32{*self}}
use sle_dev::DeviceIdentity;
struct Fault(i32);impl Fault{fn to_errno(&self)->i32{self.0}}
struct Lock<T>{inner:Mutex<T>,rank:u8}
struct Guard<'a,T>{inner:MutexGuard<'a,T>,rank:u8}
impl<T> Deref for Guard<'_,T>{type Target=T;fn deref(&self)->&T{&self.inner}}
impl<T> DerefMut for Guard<'_,T>{fn deref_mut(&mut self)->&mut T{&mut self.inner}}
impl<T> Drop for Guard<'_,T>{fn drop(&mut self){HELD.with(|s|assert_eq!(s.borrow_mut().pop(),Some(self.rank)));}}
impl<T> Lock<T>{fn new(t:T)->Self{Self::rank(t,40)} fn rank(t:T,rank:u8)->Self{Self{inner:Mutex::new(t),rank}}
 fn lock(&self)->Guard<'_,T>{HELD.with(|s|{if let Some(prior)=s.borrow().last(){assert!(*prior<=self.rank,"lock order inversion: {} -> {}",prior,self.rank);}});let inner=self.inner.lock().unwrap();HELD.with(|s|s.borrow_mut().push(self.rank));Guard{inner,rank:self.rank}}}
fn no_locks(){HELD.with(|s|assert!(s.borrow().is_empty()));}
mod sle_dev {
 pub const SLE_DEV_MAX:usize=16;
 #[derive(Clone,Copy,Debug,Eq,PartialEq)]
 // @@IDENTITY@@
}
#[derive(Debug,PartialEq,Eq)] enum SleOpcode{ReadMacAddr}
#[derive(Debug,PartialEq,Eq)] enum SleEvent{Packet(u32),CommandComplete{opcode:SleOpcode},NativeCommandReply{}}
mod sle_command_plan{#[derive(Clone,Copy,Debug,Eq,PartialEq)] pub enum DiscoveryIntent{Advertising(bool),Scanning(bool)} pub struct RecipePart<'a>{pub opcode:u16,pub params:&'a[u8]}}
struct Host{reserved:bool,fail:bool,received:u32,queued:u32,ready:bool,radio:(u8,u8),fault:Option<Fault>}
impl Host{fn controller_status(&self)->((),bool,Option<&Fault>){((),self.ready,self.fault.as_ref())}fn discovery_radio(&self)->(u8,u8,()){(self.radio.0,self.radio.1,())}fn receive(&mut self,event:SleEvent)->Option<SleEvent>{self.received+=1;if self.reserved{None}else{Some(event)}}
 fn enqueue(&mut self,opcode:u16,params:&[u8],seq:u32)->Result{assert_eq!(seq,0);assert_ne!(opcode,0);assert!(!params.is_empty());if self.fail{Err(EBUSY)}else{self.queued+=1;Ok(())}}
 fn enqueue_recipe(&mut self,intent:sle_command_plan::DiscoveryIntent,parts:&[sle_command_plan::RecipePart<'_>])->Result{assert!(matches!(intent,sle_command_plan::DiscoveryIntent::Advertising(true)|sle_command_plan::DiscoveryIntent::Scanning(true)));assert_eq!(parts.len(),1);self.enqueue(parts[0].opcode,parts[0].params,0)}}
struct Queue{dropped:u32,entries:VecDeque<(Option<u16>,SleEvent)>}
impl Queue{fn push_tagged(&mut self,id:Option<u16>,event:SleEvent)->bool{self.entries.push_back((id,event));true}fn pop_tagged(&mut self)->Option<(Option<u16>,SleEvent)>{self.entries.pop_front()}}
struct ControllerRuntime{identity:sle_dev::DeviceIdentity,schedule_gate:Lock<bool>,host:Lock<Host>,scheduled:AtomicU32,kicked:AtomicU32,ingress:Lock<Queue>,dropped_commands:AtomicU32,dropped_mac:AtomicU32,dropped_decode:AtomicU32}
fn owner(id:u16,generation:u64)->Arc<ControllerRuntime>{Arc::new(ControllerRuntime{identity:sle_dev::DeviceIdentity{id,generation},schedule_gate:Lock::rank(false,30),host:Lock::rank(Host{reserved:false,fail:false,received:0,queued:0,ready:false,radio:(1,1),fault:None},10),scheduled:AtomicU32::new(0),kicked:AtomicU32::new(0),ingress:Lock::new(Queue{dropped:0,entries:VecDeque::new()}),dropped_commands:AtomicU32::new(0),dropped_mac:AtomicU32::new(0),dropped_decode:AtomicU32::new(0)})}
impl ControllerRuntime{fn schedule_rx(&self,_delay:u32){no_locks();self.scheduled.fetch_add(1,Ordering::Relaxed);}fn kick_commands(&self){no_locks();self.kicked.fetch_add(1,Ordering::Relaxed);}}
mod actual {
 use super::*;
 static RUNTIME_ROUTES:LazyLock<Lock<[Option<Arc<ControllerRuntime>>;16]>>=LazyLock::new(||Lock::new(std::array::from_fn(|_|None)));
 // @@FUNCTIONS@@
 // @@STATS@@
 // @@HEALTH@@
 fn clear(){*RUNTIME_ROUTES.lock()=std::array::from_fn(|_|None);}
 #[test] fn publication_is_idempotent_and_keeps_one_route_reference(){
  clear();let a=owner(0,1);assert!(ingress_owner(a.identity).is_none());
  assert_eq!(publish_runtime(&a),Ok(()));assert_eq!(publish_runtime(&a),Ok(()));assert_eq!(Arc::strong_count(&a),2);
  let lookup=ingress_owner(a.identity).unwrap();assert!(Arc::ptr_eq(&lookup,&a));drop(lookup);unpublish_runtime(&a);assert_eq!(Arc::strong_count(&a),1);
 }
 #[test] fn occupied_slot_is_not_overwritten_even_by_same_identity_other_owner(){
  clear();let a=owner(0,1);let b=owner(0,2);let impostor=owner(0,1);
  assert_eq!(publish_runtime(&a),Ok(()));assert_eq!(publish_runtime(&b),Err(EBUSY));assert_eq!(publish_runtime(&impostor),Err(EBUSY));
  unpublish_runtime(&b);unpublish_runtime(&impostor);assert!(Arc::ptr_eq(&ingress_owner(a.identity).unwrap(),&a));assert!(ingress_owner(b.identity).is_none());
 }
 #[test] fn retirement_and_index_reuse_do_not_republish_or_erase_new_owner(){
  clear();let a=owner(0,1);let b=owner(0,2);publish_runtime(&a).unwrap();*a.schedule_gate.lock()=true;unpublish_runtime(&a);
  publish_runtime(&b).unwrap();assert_eq!(publish_runtime(&a),Err(ENODEV));unpublish_runtime(&a);
  assert!(ingress_owner(a.identity).is_none());assert!(Arc::ptr_eq(&ingress_owner(b.identity).unwrap(),&b));
 }
 #[test] fn invalid_identity_is_rejected_without_bounds_access(){
  clear();let bad=owner(16,1);let zero=owner(0,0);assert_eq!(publish_runtime(&bad),Err(EINVAL));assert_eq!(publish_runtime(&zero),Err(EINVAL));unpublish_runtime(&bad);assert!(ingress_owner(bad.identity).is_none());
 }
 #[test] fn independent_queues_and_decode_diagnostics_are_consumed_only_by_owner(){
  clear();let a=owner(0,1);let b=owner(1,2);publish_runtime(&a).unwrap();publish_runtime(&b).unwrap();
  a.ingress.lock().entries.push_back((Some(0),SleEvent::Packet(11)));b.ingress.lock().entries.push_back((Some(1),SleEvent::Packet(22)));
  a.dropped_decode.store(7,Ordering::Relaxed);b.dropped_decode.store(9,Ordering::Relaxed);a.dropped_commands.store(2,Ordering::Relaxed);a.dropped_mac.store(3,Ordering::Relaxed);a.ingress.lock().dropped=4;
  let drops=take_dropped_stats(&a);assert_eq!((drops.ring,drops.command_complete,drops.mac_complete,drops.decode),(4,2,3,7));assert_eq!(take_dropped_stats(&a).decode,0);assert_eq!(take_dropped_stats(&b).decode,9);
  let mut out=[(None,None)];assert_eq!(drain_runtime_events(&a,&mut out),1);assert_eq!(out[0],(Some(0),Some(SleEvent::Packet(11))));
  let mut out=[(None,None)];assert_eq!(drain_runtime_events(&b,&mut out),1);assert_eq!(out[0],(Some(1),Some(SleEvent::Packet(22))));
 }
 #[test] fn competing_publication_has_one_winner_and_preserves_its_owner(){
  clear();let a=owner(0,1);let b=owner(0,2);let barrier=Arc::new(Barrier::new(3));
  let submit=|o:Arc<ControllerRuntime>|{let barrier=barrier.clone();std::thread::spawn(move||{barrier.wait();publish_runtime(&o)})};
  let ta=submit(a.clone());let tb=submit(b.clone());barrier.wait();let ra=ta.join().unwrap();let rb=tb.join().unwrap();assert_eq!(usize::from(ra.is_ok())+usize::from(rb.is_ok()),1);
  let(winner,loser)=if ra.is_ok(){(a,b)}else{(b,a)};unpublish_runtime(&loser);assert!(Arc::ptr_eq(&ingress_owner(winner.identity).unwrap(),&winner));
 }
 #[test] fn actual_rx_host_gate_order_reserved_reply_and_retirement_are_enforced(){
  clear();let a=owner(0,1);enqueue_rx(&a,SleEvent::Packet(11));assert_eq!(a.host.lock().received,1);assert_eq!(a.ingress.lock().entries.len(),1);assert_eq!(a.scheduled.load(Ordering::Relaxed),1);
  a.host.lock().reserved=true;enqueue_rx(&a,SleEvent::CommandComplete{opcode:SleOpcode::ReadMacAddr});assert_eq!(a.host.lock().received,2);assert_eq!(a.ingress.lock().entries.len(),1);assert_eq!(a.scheduled.load(Ordering::Relaxed),2);
  *a.schedule_gate.lock()=true;enqueue_rx(&a,SleEvent::NativeCommandReply{});assert_eq!(a.host.lock().received,2);assert_eq!(a.scheduled.load(Ordering::Relaxed),2);no_locks();
 }
 #[test] fn actual_command_admission_orders_host_gate_and_never_kicks_failed_or_retired(){
  clear();let a=owner(0,1);enqueue_command(&a,7,&[1],None).unwrap();
  for intent in [sle_command_plan::DiscoveryIntent::Advertising(true),sle_command_plan::DiscoveryIntent::Scanning(true)]{enqueue_command(&a,8,&[1],Some(intent)).unwrap();}
  assert_eq!(a.host.lock().queued,3);assert_eq!(a.kicked.load(Ordering::Relaxed),3);
  a.host.lock().fail=true;assert_eq!(enqueue_command(&a,9,&[1],None),Err(EBUSY));assert_eq!(a.kicked.load(Ordering::Relaxed),3);
  *a.schedule_gate.lock()=true;assert_eq!(enqueue_command(&a,9,&[1],None),Err(ENODEV));assert_eq!(a.host.lock().queued,3);assert_eq!(a.kicked.load(Ordering::Relaxed),3);no_locks();
 }
 #[test] fn actual_health_observer_obeys_host_gate_and_does_not_mutate_other_owner(){
  clear();let a=owner(0,1);let b=owner(1,2);publish_runtime(&a).unwrap();publish_runtime(&b).unwrap();
  assert_eq!(sparklink_native_health_rust(0,1),1);a.host.lock().ready=true;assert_eq!(sparklink_native_health_rust(0,1),2);assert_eq!(sparklink_native_health_rust(1,2),1);
  a.host.lock().radio=(0,1);assert_eq!(sparklink_native_health_rust(0,1),1);a.host.lock().fault=Some(Fault(-5));assert_eq!(sparklink_native_health_rust(0,1),-5);
  *a.schedule_gate.lock()=true;assert_eq!(sparklink_native_health_rust(0,1),ENODEV);assert_eq!(sparklink_native_health_rust(0,2),ENODEV);assert_eq!(sparklink_native_health_rust(1,2),1);no_locks();
 }
}
