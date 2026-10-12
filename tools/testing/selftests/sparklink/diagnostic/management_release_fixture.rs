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
#[path="sle_link_observation.rs"] mod sle_link_observation;
#[allow(dead_code)]
#[path="sle_connection_operation.rs"] mod sle_connection_operation;
use std::cell::{RefCell,RefMut};
use sle_command_queue::{CmdRequestQueue,CmdRequest};
use sle_command_plan::{DiscoveryIntent,RecipeTag,RecipeProgress,RecipePart};
use sle_discovery_operation::{Operations,Operation,State};
mod under_test {
use super::*;
type Error=i32;
type Result<T=()>=std::result::Result<T,Error>;
mod kernel {pub mod bindings {pub const ECANCELED:u32=125;pub const EOPNOTSUPP:u32=95;pub const ESTALE:u32=116;#[allow(non_upper_case_globals)] pub static mut jiffies_64:u64=1;}}
use kernel::bindings;
fn error_from_errno(value:i32)->i32 {value}
const ENODEV:i32=-19;const EBUSY:i32=-16;
const EINVAL:i32=-22;const ETIMEDOUT:i32=-110;const EOVERFLOW:i32=-75;
trait Errno {fn to_errno(self)->i32;}
impl Errno for i32 {fn to_errno(self)->i32{self}}
// Kernel Error dependency fixture; queue/policy functions are actual source.
impl From<sle_command_queue::QueueError> for i32 {fn from(error:sle_command_queue::QueueError)->i32 {match error {sle_command_queue::QueueError::Invalid=>-22,sle_command_queue::QueueError::Full=>-16}}}
fn msecs_to_jiffies(ms:u32)->u64 {ms as u64}
// @@TIMEOUT@@
#[allow(dead_code)]
enum SleOpcode {
// @@OPCODES@@
}
#[allow(dead_code)]
// @@IN_FLIGHT@@
struct Lock(RefCell<Host>);
impl Lock {fn lock(&self)->RefMut<'_,Host>{self.0.borrow_mut()}}
struct BoolLock(RefCell<bool>);
impl BoolLock {fn lock(&self)->RefMut<'_,bool>{self.0.borrow_mut()}}
struct Owner {host:Lock,schedule_gate:BoolLock}
struct Host {connections:sle_connection_operation::Connections,links:sle_link_observation::LinkObservation,requests:CmdRequestQueue,credits:u8,active:Option<InFlight>,reply:Option<()>,
 fault:Option<Error>,recipe:Option<(RecipeTag,RecipeProgress)>,broadcast_cookie:u64,scan_cookie:u64,
 advertising_set:sle_command_plan::AdvertisingSet,operations:Operations,selected_policy_domains:u8,data_revoked:bool,revoking:bool,next_cookie:u64,revoke_done:u8,revoke_cookies:[u64;2],revoke_deadline:u64,revoke_status:u8,revoke_opcode:u16,revoke_reply:bool}
impl Host {
 // @@HOST_METHODS@@
}
fn candidate(owner:&Owner,gate:&mut sle_management::Management,mode:u32)->Result {
 // @@CORE_DECISION@@
 Err(-999) // actual controller preparation/cleanup would follow this point
}
fn host()->Host {Host{connections:sle_connection_operation::Connections::new(),links:sle_link_observation::LinkObservation::new(),requests:CmdRequestQueue::new(),credits:1,active:None,reply:None,
 fault:None,recipe:None,broadcast_cookie:0,scan_cookie:0,operations:Operations::new(),advertising_set:sle_command_plan::AdvertisingSet::Unknown,
 selected_policy_domains:0,data_revoked:false,revoking:false,next_cookie:1,revoke_done:0,revoke_cookies:[0;2],revoke_deadline:0,revoke_status:0,revoke_opcode:0,revoke_reply:false}}
struct Caller {file_id:u64}
struct Request {mode:u32}
fn after_copyout_commit(owner:&Owner,gate:&mut sle_management::Management,token:u64)->Result {
 let me=Caller{file_id:42};let request=Request{mode:sle_management::MANAGED};
 // @@CORE_COMMIT@@
 Ok(())
}
#[test] fn sleeping_copyout_candidate_does_not_grant_authority_after_link_fault_or_retirement(){
 for kind in 0..5 {
  let owner=Owner{host:Lock(RefCell::new(host())),schedule_gate:BoolLock(RefCell::new(false))};
  let mut gate=sle_management::Management::new();let token=gate.prepare(sle_management::MANAGED).unwrap();
  // The user candidate has been copied, but the source commit is not yet run.
  match kind {
   0=>owner.host.lock().observe_link(&sle_link_observation::LinkEvidence{kind:1,status:0,handle:7,role:0,address_type:0,address:[1;6],reserved:[0;2]}),
   1=>owner.host.lock().active=Some(active()),
   2=>owner.host.lock().fault=Some(-5),
   3=>*owner.schedule_gate.lock()=true,
   _=>{}
  }
  let result=after_copyout_commit(&owner,&mut gate,token);
  if kind==4 {assert_eq!(result,Ok(()));assert!(gate.owns(42));assert_eq!(gate.token_for(42),token);}
  else {assert_eq!(result,Err(if kind==2{-5}else if kind==3{-19}else{-16}));
   assert_eq!(gate.state,sle_management::FREE);assert!(!gate.owns(42));assert_eq!(gate.token_for(42),0);
   assert_eq!(gate.prepare(sle_management::MANAGED).unwrap(),token); // no counter consumed
  }
 }
}
#[test] fn new_lease_commit_retires_only_settled_old_revocation(){
 for complete in [false,true] {
  let mut h=host();h.revoking=true;h.revoke_done=if complete{3}else{0};h.selected_policy_domains=3;
  h.operations.advertising=1;h.operations.scanning=1;h.operations.initialized=true;
  let owner=Owner{host:Lock(RefCell::new(h)),schedule_gate:BoolLock(RefCell::new(false))};
  let mut gate=sle_management::Management::new();let token=gate.prepare(sle_management::MANAGED).unwrap();
  let result=after_copyout_commit(&owner,&mut gate,token);
  let h=owner.host.lock();assert_eq!(h.credits,1);assert!(h.operations.initialized);
  if complete {assert_eq!(result,Ok(()));assert!(!h.revoking);assert_eq!(h.selected_policy_domains,0);assert!(gate.owns(42));}
  else {assert_eq!(result,Err(-16));assert!(h.revoking);assert_eq!(h.selected_policy_domains,3);assert_eq!(gate.state,sle_management::FREE);}
 }
}
fn active()->InFlight {InFlight{opcode:0x0406,seq:1,cookie:1,enable:None,peer_addr:None,deadline:1000,recipe:None,connection:None,transport_done:false,advertising_params:None,advertising_was_absent:false}}
fn recipe()->(RecipeTag,RecipeProgress) {(RecipeTag{cookie:1,step:0,count:2,intent:DiscoveryIntent::AdvertisingStandby,recreate:false},RecipeProgress::new(2).unwrap())}
fn operation()->Operation {Operation{request_id:1,cookie:1,
 intent:sle_command_plan::DiscoveryIntent::AdvertisingStandby,state:State::Cancelled,
 error:-125,status:0,opcode:0,step:0,count:4,power_step:0,selected_power:None,
 completed_boottime_ns:0}}
fn released(h:Host,mode:u32)->(Owner,sle_management::Management,Result) {
 let owner=Owner{host:Lock(RefCell::new(h)),schedule_gate:BoolLock(RefCell::new(false))};let mut gate=sle_management::Management::new();
 assert_eq!(gate.authorize(42,mode),Err(sle_management::Failure::Permission));
 let token=gate.prepare(mode).unwrap();gate.commit(42,mode,token);
 assert_eq!(gate.authorize(42,mode),Ok(()));
 assert_eq!(gate.authorize(43,mode),Err(sle_management::Failure::Permission));
 gate.release(42,token).unwrap();
 assert_eq!(gate.authorize(42,mode),Err(sle_management::Failure::Busy));
 let result=candidate(&owner,&mut gate,mode);(owner,gate,result)
}
#[test] fn observed_link_blocks_both_managed_and_diagnostic_fast_release(){
 for mode in [sle_management::MANAGED,sle_management::DIAGNOSTIC] {
  let mut h=host();h.operations.initialized=true;h.operations.advertising=1;h.operations.scanning=1;
  h.observe_link(&sle_link_observation::LinkEvidence{kind:1,status:0,handle:7,role:0,address_type:0,address:[1;6],reserved:[0;2]});
  assert!(h.quiet());assert!(!h.links_clear_for_management());
  let(o,g,r)=released(h,mode);assert_eq!(r,Err(if mode==sle_management::DIAGNOSTIC{-95}else{-999}));assert_eq!(g.state,sle_management::REVOKING);
  // Managed proceeds to real driver preparation; Diagnostic rejects. Neither
  // fast path settles Free merely because advertising/scanning are Off.
  let h=o.host.lock();assert_eq!(h.discovery_radio(),(1,1,None));assert!(h.controller_status().1);
 }
}
#[test] fn failed_or_wrong_disconnect_does_not_permit_handoff(){
 let mut h=host();h.observe_link(&sle_link_observation::LinkEvidence{kind:1,status:0,handle:7,role:0,address_type:0,address:[1;6],reserved:[0;2]});
 for (status,handle) in [(1,7),(0,8)] {
  h.observe_link(&sle_link_observation::LinkEvidence{kind:2,status,handle,role:0,address_type:0,address:[0;6],reserved:[0;2]});
  assert!(!h.links_clear_for_management());
 }
 h.observe_link(&sle_link_observation::LinkEvidence{kind:2,status:0,handle:7,role:0,address_type:0,address:[0;6],reserved:[0;2]});
 assert!(h.links_clear_for_management());let(_,g,r)=released(h,sle_management::MANAGED);
 assert_eq!(r,Ok(()));assert_eq!(g.state,sle_management::FREE);
}
#[test] fn uncertain_handle_reuse_cannot_be_cleared_by_disconnect(){
 let mut h=host();for address in [[1;6],[2;6]] {
  h.observe_link(&sle_link_observation::LinkEvidence{kind:1,status:0,handle:7,role:0,address_type:0,address,reserved:[0;2]});
 }
 h.observe_link(&sle_link_observation::LinkEvidence{kind:2,status:0,handle:7,role:0,address_type:0,address:[0;6],reserved:[0;2]});
 assert!(!h.links_clear_for_management());let(_,g,r)=released(h,sle_management::MANAGED);
 assert_eq!(r,Err(-95));assert_eq!(g.state,sle_management::REVOKING);
}
#[test] fn link_ingress_during_radio_cleanup_cannot_settle_free(){
 let mut h=host();h.revoking=true;h.revoke_done=3;
 assert_eq!(h.revocation_result(),Some(Ok(())));
 h.observe_link(&sle_link_observation::LinkEvidence{kind:1,status:0,handle:7,role:0,address_type:0,address:[1;6],reserved:[0;2]});
 assert_eq!(h.revocation_result(),None);
 assert_eq!(h.begin_revoke(&[],&[]),Ok(()));assert_eq!(h.revocation_result(),None);
}
#[test] fn selected_advertising_does_not_stop_untouched_unknown_scanning(){
 let mut h=host();h.selected_policy_domains=1;h.operations.advertising=1;h.credits=0;
 h.begin_revoke(&[RecipePart{opcode:0x0c05,params:&[0;5]}],&[RecipePart{opcode:0x1002,params:&[0;2]}]).unwrap();
 assert_eq!(h.revoke_done,2);assert_eq!(h.requests.len(),1);assert_eq!(h.revoke_cookies[1],0);
 // Actual retained-Off path consumes no new wire slot or credit.
 assert!(h.next(|_|false).unwrap().is_none());assert_eq!(h.revocation_result(),Some(Ok(())));
 assert_eq!(h.discovery_radio(),(1,0,None));assert!(!h.controller_status().1);
}
#[test] fn untouched_diagnostic_slot_retains_original_reservation_without_radio_stops(){
 let mut h=host();h.active=Some(active());
 h.begin_revoke(&[RecipePart{opcode:0x0c05,params:&[0;5]}],&[RecipePart{opcode:0x1002,params:&[0;2]}]).unwrap();
 assert_eq!(h.requests.len(),0);assert_eq!(h.active.as_ref().unwrap().deadline,1000);
 assert_eq!(h.revoke_done,3);assert_eq!(h.revocation_result(),None);
 assert_eq!(h.discovery_radio(),(0,0,None));assert!(!h.controller_status().1);
}
#[test] fn selection_history_survives_result_eviction_and_both_domains_still_require_stops(){
 let mut h=queued_policy();assert!(h.next(|_|false).unwrap().is_some());assert_eq!(h.selected_policy_domains,1);
 h.active=None;h.recipe=None;h.requests=CmdRequestQueue::new();h.operations.entries=[None;sle_discovery_operation::CAPACITY];h.broadcast_cookie=0;
 assert!(!h.policy_untouched());assert!(!h.policy_unsubmitted());
 h.selected_policy_domains|=6;h.begin_revoke(&[RecipePart{opcode:0x0c05,params:&[0;5]}],&[RecipePart{opcode:0x1002,params:&[0;2]}]).unwrap();
 assert_eq!(h.revoke_done,0);assert_eq!(h.requests.len(),2);assert_ne!(h.revoke_cookies[0],0);assert_ne!(h.revoke_cookies[1],0);
}
#[test] fn actual_scan_parameter_selection_keeps_unknown_but_control_selection_requires_stop(){
 for control in [false,true] {
  let mut h=host();h.operations.advertising=1;h.scan_cookie=1;
  let params=[RecipePart{opcode:0x1001,params:&[0;8]},RecipePart{opcode:0x1002,params:&[1,0]},RecipePart{opcode:0x1002,params:&[0;2]}];
  let stop=[RecipePart{opcode:0x1002,params:&[0;2]}];
  h.requests.push_recipe(if control{&stop}else{&params},1,
   if control{DiscoveryIntent::Scanning(false)}else{DiscoveryIntent::ScanningStandby},1000).unwrap();
  let request=h.next(|_|false).unwrap().unwrap();assert_eq!(request.opcode,if control{0x1002}else{0x1001});
  assert_eq!(h.selected_policy_domains,if control{6}else{2});assert!(!h.policy_unsubmitted());
  // Core drains never-selected steps before begin_revoke, retaining active.
  h.requests=CmdRequestQueue::new();h.next_cookie=2;
  h.begin_revoke(&[RecipePart{opcode:0x0c05,params:&[0;5]}],&stop).unwrap();
  assert_eq!(h.active.as_ref().unwrap().deadline,1000);assert_eq!(h.revocation_result(),None);
  assert_eq!(h.requests.len(),if control{2}else{1});assert_eq!(h.revoke_done,if control{0}else{2});
  assert_eq!(h.discovery_radio(),(1,0,None));assert!(!h.controller_status().1);
 }
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
  let mut h=host();match kind {0=>h.active=Some(active()),1=>h.reply=Some(()),_=>h.requests.push_tagged(0x0406,&[],1,1,None,100).unwrap()}
  assert!(!h.policy_untouched());let (_,g,r)=released(h,mode);
  assert_eq!(r,Err(-999));assert_eq!(g.state,sle_management::REVOKING);
 }}
}
#[test] fn unknown_with_recipe_revocation_or_initialized_history_is_not_pristine(){
 for kind in 0..3 {let mut h=host();match kind {0=>h.recipe=Some(recipe()),1=>h.revoking=true,_=>h.operations.initialized=true}
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

fn queued_policy()->Host {
 let mut h=host();let mut op=operation();op.state=State::Queued;op.error=0;
 h.broadcast_cookie=op.cookie;h.operations.entries[0]=Some(op);
 h.requests.push_recipe(&[
  sle_command_plan::RecipePart{opcode:0x0c02,params:&[0;49]},
  sle_command_plan::RecipePart{opcode:0x0c05,params:&[0;5]},
 ],op.cookie,op.intent,1000).unwrap();h.next_cookie=2;h
}
#[test] fn never_selected_queue_cancels_without_credit_or_radio_success(){
 let h=queued_policy();assert!(!h.quiet());assert!(h.policy_unsubmitted());
 let(o,g,r)=released(h,sle_management::MANAGED);assert_eq!(r,Ok(()));
 assert_eq!((g.state,g.mode,g.error),(sle_management::FREE,0,0));
 let h=o.host.lock();assert!(h.quiet());assert_eq!(h.controller_status(),(1,false,None));
 assert_eq!(h.discovery_radio(),(0,0,None));assert_eq!((h.next_cookie,h.broadcast_cookie,h.scan_cookie),(2,1,0));
 let op=h.operations.find(1).unwrap();assert_eq!(op.state,State::Cancelled);
 assert_eq!((op.error,op.opcode,op.step,op.status,op.completed_boottime_ns),(-125,0,0,0,0));
 assert!(op.selected_power.is_none());assert!(h.policy_unsubmitted());
}
#[test] fn selection_or_reserved_reply_blocks_no_io_cancellation_atomically(){
 for kind in 0..3 {let mut h=queued_policy();match kind {0=>h.active=Some(active()),1=>h.reply=Some(()),_=>h.recipe=Some(recipe())}
  assert!(!h.policy_unsubmitted());assert!(!h.cancel_unsubmitted_policy());
  assert_eq!(h.requests.len(),2);assert_eq!(h.operations.find(1).unwrap().state,State::Queued);
  let(_,g,r)=released(h,sle_management::MANAGED);assert_eq!(r,Err(-999));assert_eq!(g.state,sle_management::REVOKING);
 }
}
#[test] fn every_piece_of_wire_or_terminal_evidence_rejects_fast_release(){
 for kind in 0..12 {let mut h=queued_policy();let op=h.operations.entries[0].as_mut().unwrap();
  match kind {0=>op.state=State::Pending,1=>op.state=State::Succeeded,2=>op.state=State::Failed,
   3=>op.state=State::Faulted,4=>op.opcode=0x0c02,5=>op.step=1,6=>op.status=0x1e,
   7=>op.selected_power=Some(0),8=>op.completed_boottime_ns=1,9=>op.error=-5,
   10=>op.count=0,_=>op.power_step=op.count+1}
  assert!(!h.cancel_unsubmitted_policy());assert_eq!(h.requests.len(),2);
  let(_,g,r)=released(h,sle_management::MANAGED);assert_eq!(r,Err(-999));assert_eq!(g.state,sle_management::REVOKING);
 }
}
#[test] fn raw_or_unowned_recipe_queue_requires_existing_cleanup(){
 for kind in 0..3 {let mut h=queued_policy();h.requests=CmdRequestQueue::new();
  match kind {0=>h.requests.push_tagged(0x0406,&[],1,2,None,1000).unwrap(),
   1=>h.requests.push_tagged(0x0406,&[],0,2,None,1000).unwrap(),
   _=>h.requests.push_recipe(&[sle_command_plan::RecipePart{opcode:0x0c05,params:&[0;5]}],2,sle_command_plan::DiscoveryIntent::Advertising(false),1000).unwrap()}
  assert!(!h.cancel_unsubmitted_policy());assert_eq!(h.requests.len(),1);
  let(_,g,r)=released(h,sle_management::MANAGED);assert_eq!(r,Err(-999));assert_eq!(g.state,sle_management::REVOKING);
 }
}
#[test] fn cancellation_and_eviction_never_erase_selected_recipe_evidence(){
 let mut h=queued_policy();h.recipe=Some(recipe());h.operations.entries[0].as_mut().unwrap().state=State::Cancelled;
 h.operations.entries[0].as_mut().unwrap().error=-125;
 assert!(!h.cancel_unsubmitted_policy());h.operations.entries=[None;sle_discovery_operation::CAPACITY];
 h.broadcast_cookie=0;h.requests=CmdRequestQueue::new();assert!(!h.policy_unsubmitted());
 assert!(!h.cancel_unsubmitted_policy());assert!(!h.policy_untouched());
}
#[test] fn cancelled_only_history_can_release_but_preserves_results_and_peer(){
 let mut h=queued_policy();h.operations.cancel_domain(sle_command_plan::DiscoveryIntent::Advertising(false),-125);
 h.requests=CmdRequestQueue::new();let peer=queued_policy();let(o,g,r)=released(h,sle_management::MANAGED);
 assert_eq!(r,Ok(()));assert_eq!(g.state,sle_management::FREE);
 assert_eq!(o.host.lock().operations.find(1).unwrap().state,State::Cancelled);
 assert_eq!(peer.requests.len(),2);assert_eq!(peer.operations.find(1).unwrap().state,State::Queued);
 let mut h=queued_policy();h.operations.entries[0].as_mut().unwrap().state=State::Cancelled;
 h.operations.entries[0].as_mut().unwrap().error=-5;assert!(!h.cancel_unsubmitted_policy());
}
#[test] fn setup_fault_revocation_initialization_and_radio_changes_reject_cancellation(){
 for kind in 0..5 {let mut h=queued_policy();match kind {0=>h.fault=Some(-5),1=>h.revoking=true,
  2=>h.operations.initialized=true,3=>h.operations.advertising=1,_=>h.operations.scanning=2}
  assert!(!h.cancel_unsubmitted_policy());assert_eq!(h.requests.len(),2);
 }
 let(_,g,r)=released(queued_policy(),sle_management::DIAGNOSTIC);
 assert_eq!(r,Err(-999));assert_eq!(g.state,sle_management::REVOKING);
}
#[test] fn superseded_queue_history_and_zero_credit_are_not_hardware_mutation(){
 for credit in [0,1,255] {let mut h=queued_policy();h.credits=credit;
  let mut old=operation();old.request_id=2;old.cookie=1;old.error=-125;
  h.operations.entries[1]=Some(old);
  h.operations.entries[0].as_mut().unwrap().cookie=2;h.broadcast_cookie=2;
  h.requests=CmdRequestQueue::new();h.requests.push_recipe(&[sle_command_plan::RecipePart{opcode:0x0c02,params:&[0;49]}],2,sle_command_plan::DiscoveryIntent::AdvertisingStandby,1000).unwrap();
  let(o,g,r)=released(h,sle_management::MANAGED);assert_eq!(r,Ok(()));assert_eq!(g.state,sle_management::FREE);
  let h=o.host.lock();assert_eq!(h.credits,credit);assert_eq!(h.discovery_radio(),(0,0,None));
  assert_eq!(h.operations.find(2).unwrap().state,State::Cancelled);
 }
}
#[test] fn actual_tx_selection_creates_durable_evidence_before_transport(){
 let mut h=queued_policy();let request=h.next(|_|false).unwrap().unwrap();
 assert_eq!((request.opcode,request.cookie,request.seq),(0x0c02,1,0));
 assert!(h.recipe.is_some());assert!(h.active.is_some());assert_eq!(h.credits,0);
 let op=h.operations.find(1).unwrap();assert_eq!(op.state,State::Pending);assert_eq!(op.opcode,0x0c02);
 assert!(!h.cancel_unsubmitted_policy());assert_eq!(h.requests.len(),1);
 // Fixture retirement/eviction, not a simulated production Complete.
 h.active=None;h.requests=CmdRequestQueue::new();h.operations.entries=[None;sle_discovery_operation::CAPACITY];
 h.broadcast_cookie=0;assert!(!h.cancel_unsubmitted_policy());assert!(h.recipe.is_some());
}
#[test] fn actual_zero_credit_selection_leaves_never_selected_queue_cancellable(){
 let mut h=queued_policy();h.credits=0;assert!(h.next(|_|false).unwrap().is_none());
 assert_eq!(h.requests.len(),2);assert!(h.recipe.is_none());assert!(h.active.is_none());
 assert!(h.cancel_unsubmitted_policy());assert!(h.quiet());assert_eq!(h.credits,0);
 assert_eq!(h.discovery_radio(),(0,0,None));assert!(!h.controller_status().1);
}
#[test] fn real_selection_and_local_cancellation_cannot_change_peer_queue(){
 let mut target=queued_policy();let mut peer=queued_policy();
 assert!(target.cancel_unsubmitted_policy());let r=peer.next(|_|false).unwrap().unwrap();
 assert_eq!(r.opcode,0x0c02);assert_eq!(peer.operations.find(1).unwrap().state,State::Pending);
 assert_eq!(target.operations.find(1).unwrap().state,State::Cancelled);
 assert!(target.active.is_none());assert!(peer.active.is_some());assert_eq!(target.credits,1);
}

#[test] fn ordinary_recipe_keeps_its_original_whole_budget_after_helper_refactor(){
 let mut h=host();
 h.enqueue_recipe(DiscoveryIntent::Scanning(false),&[RecipePart{opcode:0x1002,params:&[0;2]}]).unwrap();
 let r=h.requests.pop().unwrap();assert_eq!(r.deadline,1+CMD_TIMEOUT_MS as u64);assert_eq!(r.recipe.unwrap().cookie,r.cookie);
}

}
