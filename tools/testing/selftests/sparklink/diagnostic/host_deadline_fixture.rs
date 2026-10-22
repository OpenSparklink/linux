#[allow(dead_code, reason="Actual query dependency;metadata fixture does not exercise Managed reads")]
#[path="sle_link_command.rs"] mod sle_link_command;
#[path="sle_runtime_address.rs"] mod runtime_address;
// SPDX-License-Identifier: GPL-2.0-only
// Actual Host deadline selection body, production queue/recipe dependencies.
// Allocation, I/O and timers are not executed by this standalone fixture.
#[allow(dead_code)] // Actual relay dependency; this fixture only observes deadlines.
#[path = "sle_security_relay_state.rs"] mod sle_security_relay_state;
#[allow(dead_code)]
mod sle_security_relay { include!("relay_owner_fixture.rs"); }
#[allow(dead_code)]
#[path="sle_command_plan.rs"] mod sle_command_plan;
#[allow(dead_code)]
#[path="sle_command_queue.rs"] mod sle_command_queue;
#[allow(dead_code)]
#[path="sle_connection_operation.rs"] mod sle_connection_operation;
#[allow(dead_code)]
#[path="sle_link_observation.rs"] mod sle_link_observation;
use sle_command_plan::{DiscoveryIntent, RecipePart};
use sle_command_queue::CmdRequestQueue;
struct Active { deadline:u64, transport_done:bool }
struct Host { runtime_address:Option<runtime_address::Mutation>,links:sle_link_observation::LinkObservation, connections:sle_connection_operation::Connections, fault:Option<u8>, revoking:bool, revoke_done:u8, revoke_deadline:u64,
 active:Option<Active>, reply:Option<()>, requests:CmdRequestQueue }
impl Host {
 // @@HOST_DEADLINE@@
}
fn host()->Host {Host{runtime_address:None,links:sle_link_observation::LinkObservation::new(),connections:sle_connection_operation::Connections::new(),fault:None,revoking:false,revoke_done:0,revoke_deadline:5000,
 active:None,reply:None,requests:CmdRequestQueue::new()}}
#[test] fn empty_and_faulted_have_no_rearm_deadline(){
 let mut h=host();assert_eq!(h.next_deadline(),None);
 h.active=Some(Active{deadline:100,transport_done:false});h.fault=Some(1);
 assert_eq!(h.next_deadline(),None);
}
#[test] fn active_slot_keeps_original_deadline_after_transport_acceptance(){
 let mut h=host();h.active=Some(Active{deadline:100,transport_done:false});
 assert_eq!(h.next_deadline(),Some(100));h.active.as_mut().unwrap().transport_done=true;
 for _ in 0..8 {assert_eq!(h.next_deadline(),Some(100));}
 // Local author cancellation deliberately does not remove this reservation.
}
#[test] fn reply_and_transport_ack_both_required_before_excluding_active(){
 let mut h=host();h.active=Some(Active{deadline:100,transport_done:false});h.reply=Some(());
 assert_eq!(h.next_deadline(),Some(100));h.active.as_mut().unwrap().transport_done=true;
 assert_eq!(h.next_deadline(),None);
}
#[test] fn queued_recipe_deadline_needs_no_controller_credit_or_wire_activity(){
 let mut h=host();let parts=[RecipePart{opcode:0x0c04,params:&[]}];
 h.requests.push_recipe(&parts,1,DiscoveryIntent::Scanning(false),50).unwrap();
 assert_eq!(h.next_deadline(),Some(50));assert_eq!(h.requests.len(),1);
}
#[test] fn earliest_cleanup_active_or_recipe_is_selected_without_consumption(){
 for a in [1,10,100,5000] {for r in [1,10,100,5000] {for q in [1,10,100,5000] {
  let mut h=host();h.active=Some(Active{deadline:a,transport_done:true});
  h.revoking=true;h.revoke_deadline=r;
  h.requests.push_recipe(&[RecipePart{opcode:0x0c04,params:&[]}],1,DiscoveryIntent::Scanning(false),q).unwrap();
  assert_eq!(h.next_deadline(),Some(a.min(r).min(q)));assert_eq!(h.requests.len(),1);
  h.revoke_done=3;assert_eq!(h.next_deadline(),Some(a.min(q)));
 }}}
}
#[test] fn raw_queue_uses_author_deadline_and_is_not_consumed_by_host_observer(){
 let mut h=host();h.requests.push_tagged(0x0403,&[],7,1,None,100).unwrap();
 assert_eq!(h.next_deadline(),None);assert_eq!(h.requests.len(),1);
}
