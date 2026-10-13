// SPDX-License-Identifier: GPL-2.0-only
// Actual production route/queue functions below. std Mutex/Arc, queue storage
// and event payload are fixtures, not kernel IRQ or workqueue refinement.
extern crate self as kernel;
pub mod sync { pub use std::sync::Arc; }
use std::sync::{Arc, LazyLock, Mutex, MutexGuard, Barrier};
use std::sync::atomic::{AtomicU32, Ordering};
use std::collections::VecDeque;
type Result = std::result::Result<(), i32>;
const EINVAL:i32=-22;const ENODEV:i32=-19;const EBUSY:i32=-16;
struct Lock<T>(Mutex<T>);
impl<T> Lock<T>{fn new(t:T)->Self{Self(Mutex::new(t))} fn lock(&self)->MutexGuard<'_,T>{self.0.lock().unwrap()}}
mod sle_dev {
 pub const SLE_DEV_MAX:usize=16;
 #[derive(Clone,Copy,Debug,Eq,PartialEq)]
 // @@IDENTITY@@
}
#[derive(Debug,PartialEq,Eq)] enum SleEvent{Packet(u32)}
struct Queue{dropped:u32,entries:VecDeque<(Option<u16>,SleEvent)>}
impl Queue{fn pop_tagged(&mut self)->Option<(Option<u16>,SleEvent)>{self.entries.pop_front()}}
struct ControllerRuntime{identity:sle_dev::DeviceIdentity,schedule_gate:Lock<bool>,ingress:Lock<Queue>,dropped_commands:AtomicU32,dropped_mac:AtomicU32,dropped_decode:AtomicU32}
fn owner(id:u16,generation:u64)->Arc<ControllerRuntime>{Arc::new(ControllerRuntime{identity:sle_dev::DeviceIdentity{id,generation},schedule_gate:Lock::new(false),ingress:Lock::new(Queue{dropped:0,entries:VecDeque::new()}),dropped_commands:AtomicU32::new(0),dropped_mac:AtomicU32::new(0),dropped_decode:AtomicU32::new(0)})}
mod actual {
 use super::*;
 static RUNTIME_ROUTES:LazyLock<Lock<[Option<Arc<ControllerRuntime>>;16]>>=LazyLock::new(||Lock::new(std::array::from_fn(|_|None)));
 // @@FUNCTIONS@@
 // @@STATS@@
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
  let mut out=[(None,None)];assert_eq!(drain_events_for(a.identity,&mut out),1);assert_eq!(out[0],(Some(0),Some(SleEvent::Packet(11))));
  let mut out=[(None,None)];assert_eq!(drain_events_for(b.identity,&mut out),1);assert_eq!(out[0],(Some(1),Some(SleEvent::Packet(22))));
 }
 #[test] fn competing_publication_has_one_winner_and_preserves_its_owner(){
  clear();let a=owner(0,1);let b=owner(0,2);let barrier=Arc::new(Barrier::new(3));
  let submit=|o:Arc<ControllerRuntime>|{let barrier=barrier.clone();std::thread::spawn(move||{barrier.wait();publish_runtime(&o)})};
  let ta=submit(a.clone());let tb=submit(b.clone());barrier.wait();let ra=ta.join().unwrap();let rb=tb.join().unwrap();assert_eq!(usize::from(ra.is_ok())+usize::from(rb.is_ok()),1);
  let(winner,loser)=if ra.is_ok(){(a,b)}else{(b,a)};unpublish_runtime(&loser);assert!(Arc::ptr_eq(&ingress_owner(winner.identity).unwrap(),&winner));
 }
}
