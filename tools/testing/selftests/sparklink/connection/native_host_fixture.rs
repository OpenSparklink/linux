#[allow(dead_code)] #[path="sle_security_relay_state.rs"] mod sle_security_relay_state;
#[allow(dead_code)] mod sle_security_relay { include!("relay_owner_fixture.rs"); }
// SPDX-License-Identifier: GPL-2.0-only
// Actual Host methods with clock, kernel errno, allocation and wire-event
// dependency fixtures. No hardware, VFS permission or scheduler acceptance.
#[allow(dead_code)] #[path="sle_command_plan.rs"] mod sle_command_plan;
#[allow(dead_code)] #[path="sle_command_queue.rs"] mod sle_command_queue;
#[allow(dead_code)] #[path="sle_discovery_operation.rs"] mod sle_discovery_operation;
#[path="sle_grant.rs"] mod sle_grant;
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
 pub const EACCES:u32=13;pub const EOPNOTSUPP:u32=95;pub const ENOTCONN:u32=107;pub const ESTALE:u32=116;pub const EPROTO:u32=71;pub const ECANCELED:u32=125;pub const EALREADY:u32=114;
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
// @@COMMAND_CALLBACK@@
// @@COMMAND_OUTCOME@@
fn host()->CommandHost {let mut operations=Operations::new();operations.initialized=true;CommandHost {requests:CmdRequestQueue::new(),links:sle_link_observation::LinkObservation::new(),
 connections:sle_connection_operation::Connections::new(),credits:1,credit_revision:0,active:None,reply:None,fault:None,next_cookie:1,
 broadcast_cookie:0,scan_cookie:0,recipe:None,operations,advertising_set:sle_command_plan::AdvertisingSet::Unknown,selected_policy_domains:0,
 grants:sle_grant::LeaseAuthority::new(),data_revoked:false,revoking:false,revoke_cookies:[0;2],revoke_done:0,revoke_deadline:0,revoke_status:0,revoke_opcode:0,revoke_reply:false}}
fn clock(now:u64){super::sle_security_relay::clock(now);unsafe{kernel::bindings::jiffies_64=now}}
fn reference(handle:u16)->sle_connection_operation::ExpectedLink { sle_connection_operation::ExpectedLink { lifetime:1,handle,role:0,address_type:0,address:[1;6] } }
fn create(h:&mut CommandHost,id:u64){h.submit_connection(42,id,sle_connection_operation::Intent::Create{address_type:0,address:[1;6]},1,0x1401,&[1;27],100,None).unwrap()}
#[test] fn stale_peer_reference_rejects_before_admission_without_mutation(){
 clock(1);let mut h=host();up(&mut h,[1;6]);let cookie=h.next_cookie;
 for changed in [sle_connection_operation::ExpectedLink{lifetime:2,..reference(7)},
  sle_connection_operation::ExpectedLink{role:1,..reference(7)},
  sle_connection_operation::ExpectedLink{address_type:1,..reference(7)},
  sle_connection_operation::ExpectedLink{address:[2;6],..reference(7)}] {
  assert_eq!(h.submit_connection(42,1,sle_connection_operation::Intent::Disconnect{handle:7},2,0x1403,&[7,0,19],100,Some(changed)),Err(-116));
  assert_eq!(h.next_cookie,cookie);assert!(h.connection_result(42,1).is_none());assert_eq!(h.credits,1);
 }
 assert!(h.next(|_|true).unwrap().is_none());assert!(h.links.contains(7));
}
#[test] fn queued_disconnect_cannot_target_a_reused_handle_even_for_same_peer(){
 for address in [[1;6],[2;6]] {
  clock(1);let mut h=host();up(&mut h,[1;6]);h.credits=0;
  h.submit_connection(42,1,sle_connection_operation::Intent::Disconnect{handle:7},2,0x1403,&[7,0,19],100,Some(reference(7))).unwrap();
  h.observe_link(&sle_link_observation::LinkEvidence{kind:2,status:0,handle:7,role:0,address_type:0,address:[0;6],reserved:[0;2]});
  up(&mut h,address);h.credits=1;assert!(h.next(|_|true).unwrap().is_none());assert_eq!(h.credits,1);
  let o=h.connection_result(42,1).unwrap();assert_eq!((o.state,o.error,o.fault_error),(sle_connection_operation::State::Failed,-116,0));
  assert_eq!((o.command_status,o.outcome_status,o.handle),(None,None,None));assert!(h.fault.is_none());
  let (_,known,links)=h.link_snapshot();assert!(known);assert_eq!(links[0].unwrap().lifetime,3);assert_eq!(links[0].unwrap().address,address);
 }
}
fn status(opcode:u16,status:u8)->SleEvent {SleEvent::NativeCommandReply{opcode,command_credits:1,status,complete:false,data:vec![]}}
fn up(h:&mut CommandHost,address:[u8;6]){h.observe_link(&sle_link_observation::LinkEvidence{kind:1,status:0,handle:7,role:0,address_type:0,address,reserved:[0;2]})}
fn down(h:&mut CommandHost){h.observe_link(&sle_link_observation::LinkEvidence{kind:2,status:0,handle:7,role:0,address_type:0,address:[0;6],reserved:[0;2]})}
#[test] fn real_status_out_and_physical_outcome_require_all_three_and_disconnect_obligation(){
 clock(1);let mut h=host();create(&mut h,1);let r=h.next(|_|true).unwrap().unwrap();assert_eq!(r.connection,Some(1));
 assert!(h.receive(status(0x1401,0)).is_none());assert!(h.take_reply().is_none());
 assert!(h.transport_complete(r.cookie));assert!(h.take_reply().is_some());
 assert_eq!(h.connection_result(42,1).unwrap().state,sle_connection_operation::State::AwaitingOutcome);
 up(&mut h,[1;6]);assert_eq!(h.connection_result(42,1).unwrap().state,sle_connection_operation::State::Succeeded);
 assert!(!h.links_clear_for_management());assert!(h.submit_connection(42,2,sle_connection_operation::Intent::Disconnect{handle:8},2,0x1403,&[8,0,19],100,Some(reference(8))).is_err());
 h.submit_connection(42,2,sle_connection_operation::Intent::Disconnect{handle:7},2,0x1403,&[7,0,19],100,Some(reference(7))).unwrap();
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

#[test] fn final_command_commit_checks_real_slot_and_never_pays_credit(){
 clock(1);let mut h=host();create(&mut h,1);let r=h.next(|_|true).unwrap().unwrap();
 let credits=h.credits;
 assert_eq!(h.validate_command_commit(r.cookie+1,r.opcode),Err(EINVAL));
 assert_eq!(h.validate_command_commit(r.cookie,r.opcode+1),Err(EINVAL));
 assert_eq!(h.validate_command_commit(r.cookie,r.opcode),Ok(()));
 h.command_committed(r.cookie);assert_eq!(h.validate_command_commit(r.cookie,r.opcode),Err(-114));
 assert_eq!(h.credits,credits);assert!(!h.transport_complete(r.cookie+1));
}

#[test] fn prepared_diagnostic_cancel_and_deadline_block_actual_submit(){
 clock(1);let mut h=host();h.enqueue_diagnostic(0x0404,&[],9,100).unwrap();
 let r=h.next(|_|true).unwrap().unwrap();h.cancel_diagnostic(9);
 assert_eq!(h.validate_command_commit(r.cookie,r.opcode),Err(-125));assert!(!h.active.as_ref().unwrap().transport_submitted);
 let mut peer=host();peer.enqueue_diagnostic(0x0404,&[],10,100).unwrap();let p=peer.next(|_|true).unwrap().unwrap();
 assert_eq!(peer.validate_command_commit(p.cookie,p.opcode),Ok(()));clock(100);
 assert_eq!(peer.validate_command_commit(p.cookie,p.opcode),Err(ETIMEDOUT));
}

#[test] fn prepared_disconnect_keeps_reference_after_outcome_and_handle_reuse(){
 clock(1);let mut h=host();create(&mut h,1);let first=h.next(|_|true).unwrap().unwrap();
 h.transport_complete(first.cookie);h.receive(status(0x1401,0));h.take_reply();up(&mut h,[1;6]);
 h.submit_connection(42,2,sle_connection_operation::Intent::Disconnect{handle:7},2,0x1403,&[7,0,19],100,Some(reference(7))).unwrap();
 let r=h.next(|_|true).unwrap().unwrap();assert_eq!(h.validate_command_commit(r.cookie,r.opcode),Ok(()));
 down(&mut h);up(&mut h,[1;6]);
 assert!(h.active.as_ref().unwrap().connection_reference.is_some());
 assert_eq!(h.validate_command_commit(r.cookie,r.opcode),Err(-116));assert!(!h.active.as_ref().unwrap().transport_submitted);
}

#[test] fn prepared_connection_author_cancel_and_lease_revoke_cannot_newly_submit(){
 for revoke in [false,true] {
  clock(1);let mut h=host();create(&mut h,1);let r=h.next(|_|true).unwrap().unwrap();
  if revoke {h.revoke_connections();}else{h.cancel_connection(42,1).unwrap();}
  assert_eq!(h.validate_command_commit(r.cookie,r.opcode),Err(-125));assert!(!h.active.as_ref().unwrap().transport_submitted);
 }
}

#[test] fn definitely_unsubmitted_cancel_releases_only_software_reservation(){
 clock(1);let mut h=host();create(&mut h,1);let r=h.next(|_|true).unwrap().unwrap();
 h.cancel_connection(42,1).unwrap();assert_eq!(h.credits,0);
 assert_eq!(h.abort_unsubmitted(r.cookie,-125),Ok(()));assert_eq!(h.credits,1);assert!(h.active.is_none());
 assert!(h.fault.is_none());assert!(h.connections.clear());
 let result=h.connection_result(42,1).unwrap();assert_eq!(result.state,sle_connection_operation::State::Cancelled);
 assert!(result.command_status.is_none());assert!(result.outcome_status.is_none());
 create(&mut h,2);assert!(h.next(|_|true).unwrap().is_some());
}

#[test] fn unsubmitted_credit_rollback_never_adds_to_new_absolute_grant(){
 for grant in [0,1,255] {
  clock(1);let mut h=host();h.enqueue_diagnostic(0x0404,&[],9,100).unwrap();let r=h.next(|_|true).unwrap().unwrap();
  h.receive(SleEvent::CommandCredits{credits:grant});
  if grant==0 {assert_eq!(h.validate_command_commit(r.cookie,r.opcode),Err(EAGAIN));}
  assert_eq!(h.abort_unsubmitted(r.cookie,-12),Ok(()));assert_eq!(h.credits,grant);
  assert!(h.fault.is_none());assert!(h.active.is_none());
 }
}

#[test] fn real_submit_reply_fault_and_cleanup_do_not_allow_credit_rollback(){
 for case in 0..4 {
  clock(1);let mut h=host();h.enqueue_diagnostic(0x0404,&[],9,100).unwrap();let r=h.next(|_|true).unwrap().unwrap();
  match case {0=>h.command_committed(r.cookie),1=>{h.receive(SleEvent::NativeCommandReply{opcode:r.opcode,command_credits:1,status:0,complete:true,data:vec![]});},2=>{h.fault=Some(EIO);},_=>{h.credit_revision=u64::MAX;h.receive(SleEvent::CommandCredits{credits:1});}}
  let credits=h.credits;assert!(h.abort_unsubmitted(r.cookie,-12).is_err());assert_eq!(h.credits,credits);
 }
}
#[test] fn settled_revoke_new_lease_accepts_create_without_losing_history_or_credits(){
 clock(1);let mut h=host();h.operations.advertising=1;h.operations.scanning=1;
 h.advertising_set=sle_command_plan::AdvertisingSet::Configured([0;49]);create(&mut h,1);h.revoke_connections();
 revoke(&mut h).unwrap();assert!(h.next(|_|true).unwrap().is_none());assert_eq!(h.revocation_result(),Some(Ok(())));
 assert_eq!(h.submit_connection(43,1,sle_connection_operation::Intent::Create{address_type:0,address:[1;6]},1,0x1401,&[1;27],100,None),Err(EBUSY));
 let credits=h.credits;h.resume_management().unwrap();assert!(!h.revoking);assert_eq!(h.credits,credits);
 assert_eq!(h.connection_result(42,1).unwrap().state,sle_connection_operation::State::Cancelled);
 assert!(h.operations.initialized);assert_eq!(h.discovery_radio(),(1,1,None));
 h.submit_connection(43,1,sle_connection_operation::Intent::Create{address_type:0,address:[1;6]},1,0x1401,&[1;27],100,None).unwrap();
 assert_eq!(h.connection_result(42,1).unwrap().state,sle_connection_operation::State::Cancelled);
}
#[test] fn resume_rejects_pending_reply_physical_obligation_and_fault_without_reset(){
 clock(1);let mut h=host();create(&mut h,1);let wire=h.next(|_|true).unwrap().unwrap();
 h.revoke_connections();h.begin_revoke(&[],&[]).unwrap();assert_eq!(h.resume_management(),Err(EBUSY));assert!(h.revoking);
 h.receive(status(0x1401,0));h.transport_complete(wire.cookie);assert_eq!(h.resume_management(),Err(EBUSY));
 h.take_reply();up(&mut h,[1;6]);assert_eq!(h.resume_management(),Err(EBUSY));assert!(h.links.contains(7));
 h.fail(-5);assert_eq!(h.resume_management(),Err(-5));assert!(h.revoking);assert!(h.links.contains(7));
}
#[test] fn untouched_setup_resume_never_invents_ready_off_or_credits(){
 let mut h=host();h.operations.initialized=false;h.operations.advertising=0;h.operations.scanning=0;h.credits=0;
 h.resume_management().unwrap();assert!(!h.operations.initialized);assert_eq!(h.discovery_radio(),(0,0,None));assert_eq!(h.credits,0);
 assert_eq!(h.submit_connection(42,1,sle_connection_operation::Intent::Create{address_type:0,address:[1;6]},1,0x1401,&[1;27],100,None),Err(EAGAIN));
}
#[test] fn canonical_snapshot_never_calls_faulted_or_uncertain_absence_known(){
 clock(1);let mut a=host();let b=host();assert!(a.link_snapshot().1);
 up(&mut a,[1;6]);assert_eq!(a.link_snapshot().0,1);assert_eq!(a.link_snapshot().2[0].unwrap().lifetime,1);
 a.fail(-5);assert!(!a.link_snapshot().1);assert_eq!(a.link_snapshot().2[0].unwrap().handle,7);
 assert!(b.link_snapshot().1);assert_eq!(b.link_snapshot().0,0);
 let mut c=host();create(&mut c,1);c.next(|_|true).unwrap().unwrap();c.connections.fault(-5);
 assert!(c.fault.is_none());assert!(!c.link_snapshot().1);
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
 clock(1);let mut h=host();h.enqueue_diagnostic(0x0403,&[],9,100).unwrap();let r=h.next(|_|true).unwrap().unwrap();
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
 assert_eq!(h.submit_connection(42,1,intent,1,0x1401,&[1;27],100,None),Err(EAGAIN));
 h.operations.initialized=true;assert_eq!(h.submit_connection(42,1,intent,2,0x1401,&[1;27],100,None),Err(EINVAL));
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

fn adparams(mode:u8)->[u8;49] {
 let mut p=[0;49];p[1]=mode;p[2]=if mode==3{0}else{2};
 p[3..6].copy_from_slice(&[0xb0,4,0]);p[6..9].copy_from_slice(&[0xb0,4,0]);p[9]=7;p[25]=127;
 if mode==3{p[34]=1;p[37]=100;p[39]=100;}p[43]=200;p
}
fn adhost()->CommandHost {let mut h=host();h.operations.advertising=1;h.operations.scanning=1;
 h.advertising_set=sle_command_plan::AdvertisingSet::Configured(adparams(0));h}
fn adsubmit(h:&mut CommandHost,id:u64,p:&[u8;49],response:bool)->Result {
 let data=[0,3,1,42];let enable=[1,0,0,0,0];
 let mut parts=[RecipePart{opcode:0x0c02,params:p},RecipePart{opcode:0x0c03,params:&data},
 RecipePart{opcode:0x0c05,params:&enable},RecipePart{opcode:0x0c05,params:&enable}];
 if response{parts[2]=RecipePart{opcode:0x0c04,params:&data};}
 h.submit_discovery(id,DiscoveryIntent::Advertising(true),&parts[..if response{4}else{3}],0)
}
fn adack(h:&mut CommandHost,r:&CmdRequest,code:u8) {
 h.transport_complete(r.cookie);h.receive(SleEvent::NativeCommandReply{opcode:r.opcode,command_credits:1,status:code,complete:true,
 data:if r.opcode==0x0c02{vec![20]}else{vec![]}});h.take_reply();
}
#[test] fn mode_transition_recreates_before_configuration_and_preserves_power_step(){
 clock(1);let mut h=adhost();adsubmit(&mut h,1,&adparams(3),false).unwrap();
 let op=h.discovery_result(1).unwrap();assert_eq!((op.count,op.power_step),(4,1));
 let mut deadline=None;
 for opcode in [0x0c08,0x0c02,0x0c03,0x0c05] {
  let r=h.next(|_|true).unwrap().unwrap();assert_eq!(r.opcode,opcode);assert!(r.recipe.unwrap().recreate);
  if let Some(d)=deadline{assert_eq!(r.deadline,d)}else{deadline=Some(r.deadline)}
  adack(&mut h,&r,0);
 }
 assert!(h.next(|_|true).unwrap().is_none());let op=h.discovery_result(1).unwrap();
 assert_eq!(op.state,State::Succeeded);assert_eq!(op.selected_power,Some(20));assert!(h.controller_status().1);
 assert_eq!(h.advertising_set,sle_command_plan::AdvertisingSet::Configured(adparams(3)));
}
#[test] fn identical_configuration_retains_original_three_step_path(){
 clock(1);let mut h=adhost();adsubmit(&mut h,1,&adparams(0),false).unwrap();
 for opcode in [0x0c02,0x0c03,0x0c05] {let r=h.next(|_|true).unwrap().unwrap();assert_eq!(r.opcode,opcode);assert!(!r.recipe.unwrap().recreate);adack(&mut h,&r,0);}
 assert_eq!(h.discovery_result(1).unwrap().count,3);
}
#[test] fn scan_response_transition_is_bounded_five_steps(){
 clock(1);let mut h=adhost();adsubmit(&mut h,1,&adparams(3),true).unwrap();
 for opcode in [0x0c08,0x0c02,0x0c03,0x0c04,0x0c05] {let r=h.next(|_|true).unwrap().unwrap();assert_eq!(r.opcode,opcode);adack(&mut h,&r,0);}
 assert_eq!(h.discovery_result(1).unwrap().count,5);
}
#[test] fn failed_removal_never_commits_absence_or_runs_recreation(){
 clock(1);let mut h=adhost();adsubmit(&mut h,1,&adparams(3),false).unwrap();let r=h.next(|_|true).unwrap().unwrap();adack(&mut h,&r,0x12);
 assert_eq!(h.advertising_set,sle_command_plan::AdvertisingSet::Configured(adparams(0)));
 assert!(h.next(|_|true).unwrap().is_none());assert_eq!(h.discovery_result(1).unwrap().state,State::Failed);
 assert!(!h.controller_status().1);assert_eq!(h.operations.advertising,0);
}
#[test] fn removal_receipt_waits_for_successful_out_and_correct_reply(){
 clock(1);let mut h=adhost();adsubmit(&mut h,1,&adparams(3),false).unwrap();let r=h.next(|_|true).unwrap().unwrap();
 assert!(h.receive(SleEvent::NativeCommandReply{opcode:0x0c02,command_credits:1,status:0,complete:true,data:vec![20]}).is_some());
 assert!(h.receive(SleEvent::NativeCommandReply{opcode:0x0c08,command_credits:1,status:0,complete:true,data:vec![]}).is_none());
 assert!(h.take_reply().is_none());assert!(h.advertising_set.configured());
 h.transport_complete(r.cookie);h.take_reply();assert_eq!(h.advertising_set,sle_command_plan::AdvertisingSet::Absent);assert!(!h.controller_status().1);
}
#[test] fn cancelled_late_removal_does_not_flip_author_or_stop_missing_set(){
 clock(1);let mut h=adhost();adsubmit(&mut h,1,&adparams(3),false).unwrap();let r=h.next(|_|true).unwrap().unwrap();
 revoke(&mut h).unwrap();adack(&mut h,&r,0);assert_eq!(h.advertising_set,sle_command_plan::AdvertisingSet::Absent);
 assert!(h.next(|_|true).unwrap().is_none());assert_eq!(h.revocation_result(),Some(Ok(())));
 assert_eq!(h.discovery_result(1).unwrap().state,State::Cancelled);assert!(!h.controller_status().1);
 h.resume_management().unwrap();assert_eq!(h.advertising_set,sle_command_plan::AdvertisingSet::Absent);
}
#[test] fn cancelled_selected_creation_waits_for_actual_reply_then_retains_known_off(){
 clock(1);let mut h=adhost();adsubmit(&mut h,1,&adparams(3),false).unwrap();let remove=h.next(|_|true).unwrap().unwrap();adack(&mut h,&remove,0);
 let configure=h.next(|_|true).unwrap().unwrap();assert_eq!(configure.opcode,0x0c02);assert_eq!(h.operations.advertising,0);
 revoke(&mut h).unwrap();assert!(h.next(|_|true).unwrap().is_none());adack(&mut h,&configure,0);
 assert_eq!(h.advertising_set,sle_command_plan::AdvertisingSet::Configured(adparams(3)));
 assert!(h.next(|_|true).unwrap().is_none());assert_eq!(h.revocation_result(),Some(Ok(())));
 assert_eq!(h.discovery_result(1).unwrap().state,State::Cancelled);assert!(h.controller_status().1);
}
#[test] fn new_parameter_recipe_rejects_cancelled_old_inflight_configuration(){
 clock(1);let mut h=adhost();adsubmit(&mut h,1,&adparams(0),false).unwrap();let r=h.next(|_|true).unwrap().unwrap();
 h.operations.cancel_domain(DiscoveryIntent::Advertising(false),-125);let n=h.requests.len();
 assert_eq!(adsubmit(&mut h,2,&adparams(3),false),Err(EBUSY));assert_eq!(h.requests.len(),n);assert!(h.discovery_result(2).is_none());
 adack(&mut h,&r,0);
}
#[test] fn initial_unknown_standby_keeps_original_off_requirement(){
 clock(1);let mut h=host();h.operations.initialized=false;let p=adparams(0);let off=[0;5];
 h.submit_discovery(1,DiscoveryIntent::AdvertisingStandby,&[RecipePart{opcode:0x0c02,params:&p},RecipePart{opcode:0x0c05,params:&off}],0).unwrap();
 let r=h.next(|_|true).unwrap().unwrap();adack(&mut h,&r,0);assert!(h.advertising_set.configured());assert_eq!(h.operations.advertising,0);assert!(!h.controller_status().1);
}


#[test] fn actual_host_data_withdrawal_is_immediate_and_resume_requires_clean_links() {
 let mut a=host();let b=host();assert!(a.admits_data());assert!(b.admits_data());
 a.revoke_connections();assert!(!a.admits_data());assert!(b.admits_data());
 a.resume_management().unwrap();assert!(a.admits_data());
 up(&mut a,[1;6]);a.revoke_connections();assert!(!a.admits_data());
 assert_eq!(a.resume_management(),Err(EBUSY));assert!(!a.admits_data());
 a.fail(-5);assert!(!a.admits_data());assert!(b.admits_data());
}


fn relay_host() -> (CommandHost,super::sle_security_relay::Command) {
 clock(1);let mut h=host();assert!(h.grants.activate(1,true));
 h.observe_link(&sle_link_observation::LinkEvidence{kind:1,status:0,handle:0,role:0,address_type:0,address:[1;6],reserved:[0;2]});
 let identity=super::sle_security_relay_state::Identity{controller:42,generation:2,lifetime:1,handle:0,grant_epoch:1};
 let command=super::sle_security_relay::prepare(identity,100);
 (h,command)
}
#[test] fn actual_relay_shares_slot_credit_and_requires_real_complete() {
 let(mut h,c)=relay_host();h.enqueue_relay(0x1812,&[0,0,0x47,1,1,2],100,c.clone()).unwrap();
 let q=h.next(|_|true).unwrap().unwrap();assert!(q.relay.is_some());assert_eq!(h.credits,0);
 h.validate_command_commit(q.cookie,0x1812).unwrap();let mut submits=0;
 assert_eq!(h.commit_relay(q.cookie,||{submits+=1;0}),0);h.command_committed(q.cookie);assert_eq!(submits,1);
 assert_ne!(c.commit(||panic!("duplicate submitted")),0);
 assert!(h.transport_complete(q.cookie)==false);assert!(h.active.is_some());assert_eq!(h.credits,0);
 h.receive(SleEvent::NativeCommandReply{opcode:0x1812,command_credits:1,status:0,complete:false,data:vec![]});
 assert!(h.take_reply().is_none());assert!(h.active.is_some());
 h.receive(SleEvent::NativeCommandReply{opcode:0x1812,command_credits:1,status:0,complete:true,data:vec![]});
 assert!(h.take_reply().is_some());assert!(h.active.is_none());assert_eq!(h.credits,1);
 assert_ne!(c.commit(||panic!("closed relay reused")),0);
}
#[test] fn actual_relay_revoke_before_commit_and_queued_expiry_do_not_submit() {
 let(mut h,c)=relay_host();h.enqueue_relay(0x1812,&[0,0,0x47,1,1,2],100,c.clone()).unwrap();
 let q=h.next(|_|true).unwrap().unwrap();h.revoke_connections();assert_eq!(h.validate_command_commit(q.cookie,0x1812),Err(-13));
 assert_ne!(h.commit_relay(q.cookie,||panic!("revoked queued")),0);h.abort_unsubmitted(q.cookie,-13).unwrap();assert_eq!(h.credits,1);
 let(mut h,c)=relay_host();h.credits=0;h.enqueue_relay(0x1812,&[0,0,0x47,1,1,2],10,c.clone()).unwrap();clock(11);
 assert!(!h.timed_out());assert!(h.requests.is_empty());assert_eq!(h.credits,0);assert!(h.fault.is_none());
 assert_ne!(c.commit(||panic!("expired queued")),0);
}
#[test] fn actual_relay_revoke_retains_inflight_and_peer_remains_independent() {
 let(mut h,c)=relay_host();h.enqueue_relay(0x1812,&[0,0,0x47,1,1,2],100,c.clone()).unwrap();let q=h.next(|_|true).unwrap().unwrap();
 assert_eq!(h.commit_relay(q.cookie,||0),0);h.command_committed(q.cookie);h.transport_complete(q.cookie);h.revoke_connections();
 assert!(h.active.is_some());assert_eq!(h.credits,0);
 h.receive(SleEvent::NativeCommandReply{opcode:0x1812,command_credits:1,status:0,complete:true,data:vec![]});
 assert!(h.take_reply().is_some());assert_eq!(h.credits,1);assert_ne!(c.commit(||panic!("withdrawn")),0);
 let(mut peer,p)=relay_host();peer.enqueue_relay(0x1812,&[0,0,0x47,1,1,2],100,p).unwrap();assert!(peer.next(|_|true).unwrap().is_some());
}
}
