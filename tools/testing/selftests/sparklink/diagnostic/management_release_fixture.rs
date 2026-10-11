// SPDX-License-Identifier: GPL-2.0-only
// Actual Host predicates and core release decision; lock/transport dependencies
// are fixtures. This does not prove fd-close, scheduling, hardware or RF.
#[allow(dead_code)]
#[path="sle_command_plan.rs"] mod sle_command_plan;
#[allow(dead_code)]
#[path="sle_command_queue.rs"] mod sle_command_queue;
#[allow(dead_code)]
#[path="sle_discovery_operation.rs"] mod sle_discovery_operation;
#[path="sle_management.rs"] mod sle_management;
use std::cell::{RefCell,Ref};
use sle_command_queue::CmdRequestQueue;
use sle_discovery_operation::{Operations,Operation,State};
type Error=i32;
type Result=std::result::Result<(),Error>;
struct Lock(RefCell<Host>);
impl Lock {fn lock(&self)->Ref<'_,Host>{self.0.borrow()}}
struct Owner {host:Lock}
struct Host {requests:CmdRequestQueue,credits:u8,active:Option<()>,reply:Option<()>,
 fault:Option<Error>,recipe:Option<()>,broadcast_cookie:u64,scan_cookie:u64,
 operations:Operations,revoking:bool,next_cookie:u64}
impl Host {
 // @@HOST_METHODS@@
}
fn candidate(owner:&Owner,gate:&mut sle_management::Management,mode:u32)->Result {
 // @@CORE_DECISION@@
 Err(-999) // actual controller preparation/cleanup would follow this point
}
fn host()->Host {Host{requests:CmdRequestQueue::new(),credits:1,active:None,reply:None,
 fault:None,recipe:None,broadcast_cookie:0,scan_cookie:0,operations:Operations::new(),
 revoking:false,next_cookie:1}}
fn operation()->Operation {Operation{request_id:1,cookie:1,
 intent:sle_command_plan::DiscoveryIntent::AdvertisingStandby,state:State::Cancelled,
 error:-125,status:0,opcode:0,step:0,count:4,power_step:0,selected_power:None,
 completed_boottime_ns:0}}
fn released(h:Host,mode:u32)->(Owner,sle_management::Management,Result) {
 let owner=Owner{host:Lock(RefCell::new(h))};let mut gate=sle_management::Management::new();
 assert_eq!(gate.authorize(42,mode),Err(sle_management::Failure::Permission));
 let token=gate.prepare(mode).unwrap();gate.commit(42,mode,token);
 assert_eq!(gate.authorize(42,mode),Ok(()));
 assert_eq!(gate.authorize(43,mode),Err(sle_management::Failure::Permission));
 gate.release(42,token).unwrap();
 assert_eq!(gate.authorize(42,mode),Err(sle_management::Failure::Busy));
 let result=candidate(&owner,&mut gate,mode);(owner,gate,result)
}
#[test] fn untouched_managed_release_is_free_and_stays_unknown_not_ready(){
 let (owner,gate,r)=released(host(),sle_management::MANAGED);assert_eq!(r,Ok(()));
 assert_eq!((gate.state,gate.mode,gate.error),(sle_management::FREE,0,0));
 assert_eq!(gate.token_for(42),0);assert!(!gate.owns(42));
 let h=owner.host.lock();assert!(h.policy_untouched());
 assert_eq!(h.discovery_radio(),(0,0,None));assert_eq!(h.controller_status(),(1,false,None));
}
#[test] fn metadata_cookie_history_does_not_fabricate_radio_policy(){
 for cookie in [1,2,100,u64::MAX] {let mut h=host();h.next_cookie=cookie;
  let (o,g,r)=released(h,sle_management::MANAGED);assert_eq!(r,Ok(()));
  assert_eq!(g.state,sle_management::FREE);assert_eq!(o.host.lock().next_cookie,cookie);
  assert!(!o.host.lock().controller_status().1);
 }
}
#[test] fn every_radio_state_other_than_unknown_or_both_confirmed_off_requires_cleanup(){
 for adv in 0..=2 {for scan in 0..=2 {
  let mut h=host();h.operations.advertising=adv;h.operations.scanning=scan;
  let (_,g,r)=released(h,sle_management::MANAGED);
  if (adv,scan)==(0,0)||(adv,scan)==(1,1) {assert_eq!(r,Ok(()));assert_eq!(g.state,sle_management::FREE)}
  else {assert_eq!(r,Err(-999));assert_eq!(g.state,sle_management::REVOKING)}
 }}
}
#[test] fn partial_initialization_or_cancelled_operations_are_not_untouched(){
 for slot in 0..sle_discovery_operation::CAPACITY {
  for state in [State::Queued,State::Pending,State::Succeeded,State::Failed,State::Cancelled,State::Faulted] {
   let mut h=host();let mut op=operation();op.state=state;h.operations.entries[slot]=Some(op);
   assert!(!h.policy_untouched());let (_,g,r)=released(h,sle_management::MANAGED);
   assert_eq!(r,Err(-999));assert_eq!(g.state,sle_management::REVOKING);
  }
 }
}
#[test] fn retained_policy_cookies_exclude_unknown_fast_release(){
 for (a,b) in [(1,0),(0,1),(1,1),(u64::MAX,u64::MAX)] {
  let mut h=host();h.broadcast_cookie=a;h.scan_cookie=b;
  assert!(!h.policy_untouched());let (_,g,r)=released(h,sle_management::MANAGED);
  assert_eq!(r,Err(-999));assert_eq!(g.state,sle_management::REVOKING);
 }
}
#[test] fn active_reply_or_queue_for_either_mode_must_drain(){
 for mode in [sle_management::MANAGED,sle_management::DIAGNOSTIC] {for kind in 0..3 {
  let mut h=host();match kind {0=>h.active=Some(()),1=>h.reply=Some(()),_=>h.requests.push_tagged(0x0406,&[],1,1,None,100).unwrap()}
  assert!(!h.policy_untouched());let (_,g,r)=released(h,mode);
  assert_eq!(r,Err(-999));assert_eq!(g.state,sle_management::REVOKING);
 }}
}
#[test] fn unknown_with_recipe_revocation_or_initialized_history_is_not_pristine(){
 for kind in 0..3 {let mut h=host();match kind {0=>h.recipe=Some(()),1=>h.revoking=true,_=>h.operations.initialized=true}
  assert!(!h.policy_untouched());let (_,g,r)=released(h,sle_management::MANAGED);
  assert_eq!(r,Err(-999));assert_eq!(g.state,sle_management::REVOKING);
 }
}
#[test] fn original_host_error_is_not_normalized_to_success(){
 for mode in [sle_management::MANAGED,sle_management::DIAGNOSTIC] {for error in [-5,-110,-19] {
  let mut h=host();h.fault=Some(error);assert!(!h.policy_untouched());
  let (_,g,r)=released(h,mode);assert_eq!(r,Err(error));assert_eq!(g.state,sle_management::REVOKING);
 }}
}
#[test] fn already_confirmed_off_uses_existing_barrier_without_erasing_history(){
 let mut h=host();h.operations.initialized=true;h.operations.advertising=1;h.operations.scanning=1;
 h.operations.entries[0]=Some(operation());h.broadcast_cookie=8;h.scan_cookie=9;
 let (o,g,r)=released(h,sle_management::MANAGED);assert_eq!(r,Ok(()));assert_eq!(g.state,sle_management::FREE);
 let h=o.host.lock();assert_eq!(h.discovery_radio(),(1,1,None));assert!(h.controller_status().1);
 assert_eq!((h.broadcast_cookie,h.scan_cookie),(8,9));assert!(h.operations.entries[0].is_some());
}
#[test] fn query_only_diagnostic_retains_existing_quiet_release_contract(){
 let mut h=host();h.operations.entries[0]=Some(operation());h.broadcast_cookie=1;
 let (o,g,r)=released(h,sle_management::DIAGNOSTIC);assert_eq!(r,Ok(()));assert_eq!(g.state,sle_management::FREE);
 assert_eq!(o.host.lock().discovery_radio(),(0,0,None));
}
