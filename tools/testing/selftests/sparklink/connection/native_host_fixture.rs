// SPDX-License-Identifier: GPL-2.0-only
// Actual Host methods with clock, kernel errno, allocation and wire-event
// dependency fixtures. No hardware, VFS permission or scheduler acceptance.
#[allow(dead_code)] #[path="sle_command_plan.rs"] mod sle_command_plan;
#[allow(dead_code)] #[path="sle_command_queue.rs"] mod sle_command_queue;
#[allow(dead_code)] #[path="sle_discovery_operation.rs"] mod sle_discovery_operation;
#[path="sle_connection_operation.rs"] mod sle_connection_operation;
#[path="sle_link_observation.rs"] mod sle_link_observation;
mod sle_dli {pub(crate) use super::actual_host::SleStatus;}
#[allow(dead_code)]
mod actual_host {
use super::*;
use sle_command_queue::{CmdRequest,CmdRequestQueue};
use sle_command_plan::{DiscoveryIntent,RecipePart,RecipeProgress,RecipeReply,RecipeTag};
use sle_discovery_operation::{Operations,Operation,State,AdmissionError};
type Error=i32; type Result<T=()>=std::result::Result<T,Error>;
const EAGAIN:i32=-11;const EINVAL:i32=-22;const EBUSY:i32=-16;const EEXIST:i32=-17;const ENOENT:i32=-2;
const EOVERFLOW:i32=-75;const ETIMEDOUT:i32=-110;const EIO:i32=-5;
mod kernel {pub mod bindings {
 pub const EOPNOTSUPP:u32=95;pub const ENOTCONN:u32=107;pub const EPROTO:u32=71;pub const ECANCELED:u32=125;
 #[allow(non_upper_case_globals)] pub static mut jiffies_64:u64=1;
 pub unsafe fn ktime_get_boottime()->i64 {unsafe{jiffies_64 as i64 * 1000000}}
}}
fn error_from_errno(value:i32)->i32 {value}
trait Errno {fn to_errno(self)->i32;} impl Errno for i32 {fn to_errno(self)->i32{self}}
impl From<sle_command_queue::QueueError> for i32 {fn from(e:sle_command_queue::QueueError)->i32 {
 match e {sle_command_queue::QueueError::Invalid=>EINVAL,sle_command_queue::QueueError::Full=>EBUSY}}}
fn msecs_to_jiffies(ms:u32)->u64 {ms as u64}
// @@TIMEOUT@@
#[derive(Clone,Copy)] #[repr(u16)] pub(crate) enum SleOpcode {
// @@OPCODES@@
}
#[derive(Clone,Copy,PartialEq)] #[repr(u8)] pub(crate) enum SleStatus {Success=0,Rejected=1}
pub(crate) enum SleEvent {
 CommandCredits{credits:u8},
 CommandComplete{opcode:SleOpcode,command_credits:u8,status:SleStatus,data:Vec<u8>},
 CommandStatus{opcode:SleOpcode,command_credits:u8,status:SleStatus},
 NativeCommandReply{opcode:u16,command_credits:u8,status:u8,complete:bool,data:Vec<u8>},
 Other,
}
impl CmdRequestQueue {
// @@PUSH_COOKIE@@
}
// @@ACTUAL_HOST@@
fn host()->CommandHost {let mut operations=Operations::new();operations.initialized=true;CommandHost {requests:CmdRequestQueue::new(),links:sle_link_observation::LinkObservation::new(),
 connections:sle_connection_operation::Connections::new(),credits:1,active:None,reply:None,fault:None,next_cookie:1,
 broadcast_cookie:0,scan_cookie:0,recipe:None,operations,selected_policy_domains:0,
 revoking:false,revoke_cookies:[0;2],revoke_done:0,revoke_deadline:0,revoke_status:0,revoke_opcode:0,revoke_reply:false}}
fn clock(now:u64){unsafe{kernel::bindings::jiffies_64=now}}
fn create(h:&mut CommandHost,id:u64){h.submit_connection(42,id,sle_connection_operation::Intent::Create{address_type:0,address:[1;6]},1,0x1401,&[1;27],100).unwrap()}
fn status(opcode:u16,status:u8)->SleEvent {SleEvent::NativeCommandReply{opcode,command_credits:1,status,complete:false,data:vec![]}}
fn up(h:&mut CommandHost,address:[u8;6]){h.observe_link(&sle_link_observation::LinkEvidence{kind:1,status:0,handle:7,role:0,address_type:0,address,reserved:[0;2]})}
fn down(h:&mut CommandHost){h.observe_link(&sle_link_observation::LinkEvidence{kind:2,status:0,handle:7,role:0,address_type:0,address:[0;6],reserved:[0;2]})}
#[test] fn real_status_out_and_physical_outcome_require_all_three_and_disconnect_obligation(){
 clock(1);let mut h=host();create(&mut h,1);let r=h.next(|_|true).unwrap().unwrap();assert_eq!(r.connection,Some(1));
 assert!(h.receive(status(0x1401,0)).is_none());assert!(h.take_reply().is_none());
 assert!(h.transport_complete(r.cookie));assert!(h.take_reply().is_some());
 assert_eq!(h.connection_result(42,1).unwrap().state,sle_connection_operation::State::AwaitingOutcome);
 up(&mut h,[1;6]);assert_eq!(h.connection_result(42,1).unwrap().state,sle_connection_operation::State::Succeeded);
 assert!(!h.links_clear_for_management());assert!(h.submit_connection(42,2,sle_connection_operation::Intent::Disconnect{handle:8},2,0x1403,&[8,0,19],100).is_err());
 h.submit_connection(42,2,sle_connection_operation::Intent::Disconnect{handle:7},2,0x1403,&[7,0,19],100).unwrap();
 let r=h.next(|_|true).unwrap().unwrap();h.transport_complete(r.cookie);h.receive(status(0x1403,0));h.take_reply();
 assert!(!h.links_clear_for_management());down(&mut h);assert!(h.links_clear_for_management());
 assert_eq!(h.connection_result(42,2).unwrap().state,sle_connection_operation::State::Succeeded);
}
#[test] fn never_selected_revoke_removes_only_its_command_and_preserves_peer(){
 clock(1);let mut a=host();let mut b=host();create(&mut a,1);create(&mut b,1);
 a.revoke_connections();assert!(a.next(|_|true).unwrap().is_none());assert_eq!(a.credits,1);
 assert!(a.links_clear_for_management());assert_eq!(a.connection_result(42,1).unwrap().state,sle_connection_operation::State::Cancelled);
 assert!(b.next(|_|true).unwrap().is_some());assert!(!b.links_clear_for_management());
}
#[test] fn cancelled_inflight_author_keeps_reservation_and_late_handle_without_fake_free(){
 clock(1);let mut h=host();create(&mut h,1);let r=h.next(|_|true).unwrap().unwrap();h.cancel_connection(42,1).unwrap();
 assert!(!h.links_clear_for_management());assert!(h.next(|_|true).unwrap().is_none());
 up(&mut h,[1;6]);h.receive(status(0x1401,0));h.transport_complete(r.cookie);h.take_reply();
 let o=h.connection_result(42,1).unwrap();assert_eq!((o.state,o.error,o.handle),(sle_connection_operation::State::Cancelled,-125,Some(7)));
 assert!(!h.links_clear_for_management());h.operations.advertising=1;h.operations.scanning=1;
 assert_eq!(revoke(&mut h),Ok(()));assert_eq!(h.revocation_result(),None);assert_eq!(h.cleanup_candidate(),Ok(Some(7)));
 assert!(h.connection_result(43,1).is_none());
}
#[test] fn queued_expiry_is_local_but_accepted_expiry_faults_only_owner(){
 clock(1);let mut a=host();create(&mut a,1);clock(101);assert!(!a.timed_out());assert!(a.next(|_|true).unwrap().is_none());assert!(a.fault.is_none());
 clock(1);let mut a=host();let b=host();create(&mut a,1);let r=a.next(|_|true).unwrap().unwrap();a.transport_complete(r.cookie);a.receive(status(0x1401,0));a.take_reply();
 clock(101);assert!(a.timed_out());a.fail(ETIMEDOUT);up(&mut a,[1;6]);
 assert_eq!(a.connection_result(42,1).unwrap().state,sle_connection_operation::State::Faulted);assert!(!a.links_clear_for_management());assert!(b.fault.is_none());
}
#[test] fn native_queries_and_discovery_still_require_complete_after_successful_status(){
 clock(1);let mut h=host();h.enqueue_diagnostic(0x0403,9,100).unwrap();let r=h.next(|_|true).unwrap().unwrap();
 assert!(h.receive(status(0x0403,0)).is_some());assert!(!h.transport_complete(r.cookie));assert!(h.take_reply().is_none());
 h.receive(SleEvent::NativeCommandReply{opcode:0x0403,command_credits:1,status:0,complete:true,data:vec![0]});assert!(h.take_reply().is_some());
 let parts=[RecipePart{opcode:0x0c04,params:&[0]}];h.enqueue_recipe(DiscoveryIntent::Advertising(false),&parts).unwrap();let r=h.next(|_|true).unwrap().unwrap();
 assert!(h.receive(status(0x0c04,0)).is_some());assert!(!h.transport_complete(r.cookie));assert!(h.take_reply().is_none());
}
#[test] fn wrong_opcode_or_peer_does_not_complete_operation_but_physical_observation_survives(){
 clock(1);let mut h=host();create(&mut h,1);let r=h.next(|_|true).unwrap().unwrap();
 assert!(h.receive(status(0x1403,0)).is_some());h.transport_complete(r.cookie);h.receive(status(0x1401,0));h.take_reply();up(&mut h,[2;6]);
 assert_eq!(h.connection_result(42,1).unwrap().state,sle_connection_operation::State::AwaitingOutcome);assert!(!h.links_clear_for_management());
}
#[test] fn wrong_reply_class_and_transfer_failure_never_publish_connection_success(){
 clock(1);let mut h=host();create(&mut h,1);let r=h.next(|_|true).unwrap().unwrap();h.transport_complete(r.cookie);
 h.receive(SleEvent::NativeCommandReply{opcode:0x1401,command_credits:1,status:0,complete:true,data:vec![]});h.take_reply();
 assert_eq!(h.fault,Some(-71));assert_ne!(h.connection_result(42,1).unwrap().state,sle_connection_operation::State::Succeeded);
 clock(1);let mut h=host();create(&mut h,1);h.next(|_|true).unwrap().unwrap();h.cancel_connection(42,1).unwrap();h.fail(-5);
 assert_eq!((h.connection_result(42,1).unwrap().state,h.connection_result(42,1).unwrap().error),(sle_connection_operation::State::Cancelled,-125));assert!(!h.links_clear_for_management());
}
#[test] fn setup_or_inconsistent_internal_tag_is_rejected_before_queue_cookie_and_credit(){
 clock(1);let mut h=host();h.operations.initialized=false;
 let intent=sle_connection_operation::Intent::Create{address_type:0,address:[1;6]};
 assert_eq!(h.submit_connection(42,1,intent,1,0x1401,&[1;27],100),Err(EAGAIN));
 h.operations.initialized=true;assert_eq!(h.submit_connection(42,1,intent,2,0x1401,&[1;27],100),Err(EINVAL));
 assert_eq!(h.credits,1);assert_eq!(h.next_cookie,1);assert!(h.requests.is_empty());assert!(h.connection_result(42,1).is_none());
}

#[test] fn contradictory_controller_evidence_faults_with_protocol_reason_not_later_timeout(){
 clock(1);let mut h=host();create(&mut h,1);let r=h.next(|_|true).unwrap().unwrap();up(&mut h,[1;6]);
 h.transport_complete(r.cookie);h.receive(status(0x1401,1));h.take_reply();
 assert_eq!(h.fault,Some(-71));let o=h.connection_result(42,1).unwrap();
 assert_eq!((o.state,o.error,o.fault_error),(sle_connection_operation::State::Faulted,-71,-71));
 assert_eq!((o.command_status,o.outcome_status,o.handle),(Some(1),Some(0),Some(7)));
 clock(1000);h.fail(-110);let o=h.connection_result(42,1).unwrap();assert_eq!((o.error,o.fault_error),(-71,-71));assert!(!h.links_clear_for_management());
}

fn revoke(h:&mut CommandHost)->Result {
 let adv=[RecipePart{opcode:0x0c05,params:&[0,0,0,0,0]}];let scan=[RecipePart{opcode:SleOpcode::EnableScan as u16,params:&[0;8]}];
 h.begin_revoke(&adv,&scan)
}
fn off(h:&mut CommandHost){h.operations.advertising=1;h.operations.scanning=1;}
fn cleanup_down(h:&mut CommandHost,handle:u16){h.observe_link(&sle_link_observation::LinkEvidence{kind:2,status:0,handle:handle as u32,role:0,address_type:0,address:[0;6],reserved:[0;2]});}
#[test] fn revoke_waits_for_accepted_create_then_real_disconnect_all_arrival_orders(){
 for order in [[0,1,2],[0,2,1],[1,0,2],[1,2,0],[2,0,1],[2,1,0]] {
  clock(1);let mut h=host();off(&mut h);create(&mut h,1);let create_wire=h.next(|_|true).unwrap().unwrap();
  h.revoke_connections();revoke(&mut h).unwrap();assert_eq!(h.cleanup_candidate(),Ok(None));assert!(h.revocation_result().is_none());
  h.receive(status(0x1401,0));h.transport_complete(create_wire.cookie);h.take_reply();assert_eq!(h.cleanup_candidate(),Ok(None));
  up(&mut h,[1;6]);assert_eq!(h.cleanup_candidate(),Ok(Some(7)));
  assert!(h.submit_cleanup(7,0x1403,&[7,0,0x13]).unwrap());let cleanup=h.next(|_|true).unwrap().unwrap();
  assert_eq!(cleanup.connection,Some(2));assert_ne!(cleanup.cookie,create_wire.cookie);
  for (index,step) in order.into_iter().enumerate() {
   match step {0=>{h.transport_complete(cleanup.cookie);h.take_reply();},1=>{h.receive(status(0x1403,0));h.take_reply();},_=>cleanup_down(&mut h,7)};
   if index<2 {assert!(h.revocation_result().is_none());} else {assert!(h.next(|_|true).unwrap().is_none());assert_eq!(h.revocation_result().unwrap(),Ok(()));}
  }
  let original=h.connection_result(42,1).unwrap();assert_eq!((original.state,original.error,original.handle),(sle_connection_operation::State::Cancelled,-125,Some(7)));
 }
}
#[test] fn already_connected_handles_zero_and_max_are_cleaned_without_public_result_replacement(){
 clock(1);let mut h=host();off(&mut h);
 for handle in [0,65535] {h.observe_link(&sle_link_observation::LinkEvidence{kind:1,status:0,handle,role:0,address_type:0,address:[1;6],reserved:[0;2]});}
 revoke(&mut h).unwrap();
 for handle in [0,65535] {
  assert_eq!(h.cleanup_candidate(),Ok(Some(handle)));assert!(h.submit_cleanup(handle,0x1403,&[(handle&255)as u8,(handle>>8)as u8,0x13]).unwrap());
  let wire=h.next(|_|true).unwrap().unwrap();h.transport_complete(wire.cookie);h.receive(status(0x1403,0));h.take_reply();
  assert!(h.revocation_result().is_none());cleanup_down(&mut h,handle);
 }
 assert!(h.next(|_|true).unwrap().is_none());assert_eq!(h.revocation_result().unwrap(),Ok(()));assert!(h.connection_result(42,1).is_none());
}
#[test] fn cleanup_candidate_recheck_does_not_send_for_a_gone_link_or_other_handle(){
 clock(1);let mut h=host();off(&mut h);up(&mut h,[1;6]);revoke(&mut h).unwrap();
 assert_eq!(h.cleanup_candidate(),Ok(Some(7)));assert!(!h.submit_cleanup(8,0x1403,&[8,0,0x13]).unwrap());
 let cookie=h.next_cookie;cleanup_down(&mut h,7);assert!(!h.submit_cleanup(7,0x1403,&[7,0,0x13]).unwrap());
 assert_eq!(h.next_cookie,cookie);assert!(h.next(|_|true).unwrap().is_none());assert!(h.requests.is_empty());assert_eq!(h.revocation_result().unwrap(),Ok(()));
}
#[test] fn failed_cleanup_or_uncertain_out_after_disconnect_is_faulted_and_peer_untouched(){
 for transfer_error in [false,true] {
  clock(1);let mut h=host();let b=host();off(&mut h);up(&mut h,[1;6]);revoke(&mut h).unwrap();h.submit_cleanup(7,0x1403,&[7,0,0x13]).unwrap();
  let wire=h.next(|_|true).unwrap().unwrap();
  if transfer_error {cleanup_down(&mut h,7);h.fail(-5);} else {h.transport_complete(wire.cookie);h.receive(status(0x1403,1));h.take_reply();}
  assert_eq!(h.revocation_result().unwrap(),Err(if transfer_error{-5}else{-121}));assert!(!h.links_clear_for_management());assert!(b.fault.is_none());
 }
}
#[test] fn accepted_without_outcome_revoke_has_one_finite_budget_and_no_fake_cancel(){
 clock(1);let mut h=host();off(&mut h);create(&mut h,1);let wire=h.next(|_|true).unwrap().unwrap();
 h.receive(status(0x1401,0));h.transport_complete(wire.cookie);h.take_reply();h.revoke_connections();revoke(&mut h).unwrap();
 let deadline=h.revoke_deadline;for _ in 0..10 {assert_eq!(h.cleanup_candidate(),Ok(None));assert_eq!(h.revoke_deadline,deadline);assert!(h.next(|_|true).unwrap().is_none());}
 clock(101);assert!(h.timed_out());h.fail(-110);assert_eq!(h.revocation_result().unwrap(),Err(-110));assert!(!h.timed_out());
 let original=h.connection_result(42,1).unwrap();assert_eq!((original.state,original.error,original.fault_error),(sle_connection_operation::State::Cancelled,-125,-110));
}

}
