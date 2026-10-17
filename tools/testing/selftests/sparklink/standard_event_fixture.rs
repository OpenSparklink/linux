// SPDX-License-Identifier: GPL-2.0-only
// Production pure decoder/ring bodies; allocator/errno dependencies are explicit.
// Historical module allows unconsumed legacy payloads only in this test binary.
#[derive(Debug, PartialEq, Eq)] struct Error(i32);
const EINVAL:Error=Error(-22);
type Result<T>=std::result::Result<T,Error>;
const GFP_ATOMIC:u32=0;
struct KVec<T>(Vec<T>);
impl<T:Clone> KVec<T> {
 fn new()->Self{Self(Vec::new())}
 fn with_capacity(n:usize,_f:u32)->Result<Self>{Ok(Self(Vec::with_capacity(n)))}
 fn push(&mut self,t:T,_f:u32)->Result<()>{self.0.push(t);Ok(())}
 fn extend_from_slice(&mut self,s:&[T],_f:u32)->Result<()>{self.0.extend_from_slice(s);Ok(())}
 fn as_slice(&self)->&[T]{&self.0}
}
impl<T> std::ops::Deref for KVec<T>{type Target=[T];fn deref(&self)->&[T]{&self.0}}
mod sle_uapi {// @@PRODUCTION_BUDGET@@
}
mod sle_dli {
 use super::*;
 // @@OPCODE@@
 // @@STATUS@@
 // @@OPCODE_PARSE@@
 // @@EVENT@@
}
use sle_dli::{SleEvent,SleStatus};
// @@EVENT_STRUCT@@
// @@PARSE@@
// @@DECODE@@
// @@STATUS_PARSE@@
const CTRL_EVENT_RING_SIZE:usize=32;
// @@RING_STRUCT@@
impl ControllerEventRing {
 // @@RING_PUSH@@
 // @@RING_POP@@
}
#[allow(dead_code)]
mod historical {
 use super::{KVec,SleStatus,DliUsbEvent,GFP_ATOMIC};
 use super::sle_dli::SleOpcode;
 const CTRL_EVENT_RING_SIZE:usize=32;
 // @@OLD_EVENTS@@
 // @@OLD_DECODER@@
 // @@OLD_RING@@
 pub(super) fn witnesses(){
  let data=KVec(vec![1,2,3,4,5,6,(-42_i8)as u8,3,2,1,7]);
  match event_to_sle(&super::DliUsbEvent{event_code:0x1a,params:data}).unwrap(){
   SleEvent::AdvReport{addr,rssi,discovery_level,data}=>{assert_eq!(addr,[1,2,3,4,5,6]);assert_eq!(rssi,-42);assert_eq!(discovery_level,7);assert_eq!(data.as_slice(),&[2,1,7]);},_=>panic!("wrong history")
  }
  for (code,n) in [(0x15,9),(5,3),(0x11,3),(0x1d,7),(3,6),(7,10),(8,9),(9,3),(0xb,1),(0xe,2),(0x16,14),(0x17,8),(0x18,4),(0x19,8),(0x1b,8)]{
   assert!(event_to_sle(&super::DliUsbEvent{event_code:code,params:KVec(vec![0;n])}).is_some(),"history code={code}");
   assert!(event_to_sle(&super::DliUsbEvent{event_code:code,params:KVec(vec![0;n-1])}).is_none(),"history truncated code={code}");
  }
  assert_eq!(extract_discovery_level(&[0]),0);assert_eq!(extract_discovery_level(&[4,1,7]),0);
  let mut r=ControllerEventRing::new();assert_eq!(r.pending(),0);
  for i in 0..31 {r.push(SleEvent::HardwareError{code:i});}
  r.push(SleEvent::HardwareError{code:255});assert_eq!(r.dropped,1);assert_eq!(r.pending(),31);
  for i in 0..31 {assert!(matches!(r.pop(),Some(SleEvent::HardwareError{code}) if code==i));}
  assert!(r.pop().is_none());assert_eq!(r.pending(),0);
 }
}
fn event(code:u16,params:&[u8])->Option<SleEvent>{event_to_sle(&DliUsbEvent{event_code:code,params:KVec(params.to_vec())})}
#[test] fn command_results_and_credit_exact_schema(){
 assert!(matches!(event(2,&[0,0,3]),Some(SleEvent::CommandCredits{credits:3})));
 assert!(event(2,&[0,0,3,0]).is_none());assert!(event(2,&[4,4,1]).is_none());
 assert!(matches!(event(2,&[4,4,1,0,0xaa]),Some(SleEvent::CommandComplete{opcode:sle_dli::SleOpcode::ReadLocalVersion,command_credits:1,status:SleStatus::Success,data}) if data.as_slice()==[0xaa]));
 assert!(matches!(event(1,&[4,4,1,8]),Some(SleEvent::CommandStatus{opcode:sle_dli::SleOpcode::ReadLocalVersion,command_credits:1,status:SleStatus::Timeout})));
 assert!(event(1,&[4,4,1]).is_none());assert!(event(1,&[4,4,1,0,0]).is_none());assert!(event(2,&[0xff,0xff,1,0]).is_none());
}
#[test] fn hardware_error_requires_exact_single_code(){
 assert!(event(10,&[]).is_none());assert!(event(10,&[0,0]).is_none());
 for code in 0..=255{assert!(matches!(event(10,&[code]),Some(SleEvent::HardwareError{code:c}) if c==code));}
}
#[test] fn unconsumed_business_codes_refused_then_valid_command_recovers(){
 for code in 0..=255u16{if [1,2,10].contains(&code){continue;}for n in [0,1,3,9,14,64,255]{assert!(event(code,&vec![0;n]).is_none(),"code={code}");}}
 assert!(matches!(event(2,&[4,4,1,0]),Some(SleEvent::CommandComplete{..})));
}
#[test] fn actual_parser_and_rejected_event_do_not_hold_state(){
 let n=sle_uapi::DLI_PARAM_MAX;let mut bytes=vec![2,0,n as u8,(n>>8) as u8];bytes.extend(std::iter::repeat_n(0,n));assert_eq!(parse_event_packet(&bytes).unwrap().params.len(),n);
 let over=n+1;let mut bytes=vec![2,0,over as u8,(over>>8) as u8];bytes.extend(std::iter::repeat_n(0,over));assert!(parse_event_packet(&bytes).is_err());
 for bad in [vec![],vec![1,0,0],vec![1,0,1,0],vec![1,0,0,1]]{assert!(parse_event_packet(&bad).is_err());}
 let p=parse_event_packet(&[10,0,1,0,7]).unwrap();assert!(matches!(event_to_sle(&p),Some(SleEvent::HardwareError{code:7})));
 let p=parse_event_packet(&[5,0,3,0,0,0,0]).unwrap();assert!(event_to_sle(&p).is_none());
 let p=parse_event_packet(&[2,0,4,0,4,4,1,0]).unwrap();assert!(matches!(event_to_sle(&p),Some(SleEvent::CommandComplete{..})));
}
#[test] fn actual_tagged_ring_order_overflow_and_wrap(){
 let mut r=ControllerEventRing{events:[const{(None,None)};CTRL_EVENT_RING_SIZE],head:0,tail:0,dropped:0};
 for round in 0..3{for code in 0..31{assert!(r.push_tagged(Some(round),SleEvent::HardwareError{code}));}assert!(!r.push_tagged(Some(99),SleEvent::HardwareError{code:255}));
 for code in 0..31{let (id,e)=r.pop_tagged().unwrap();assert_eq!(id,Some(round));assert!(matches!(e,SleEvent::HardwareError{code:c} if c==code));}assert!(r.pop_tagged().is_none());}assert_eq!(r.dropped,3);
}
#[test] fn native_event_model_preserves_lifetime_fields(){
 let e=SleEvent::NativeControllerData{lifetime:12,handle:3,index:4,data:KVec(vec![5])};assert!(matches!(e,SleEvent::NativeControllerData{lifetime:12,handle:3,index:4,data} if data.as_slice()==[5]));
 let e=SleEvent::NativeSecurityInstallation{lifetime:12,security_revision:7,handle:3,event:17,status:0,enabled:1};assert!(matches!(e,SleEvent::NativeSecurityInstallation{lifetime:12,security_revision:7,handle:3,event:17,status:0,enabled:1}));
 let e=SleEvent::NativeCommandReply{opcode:4,command_credits:1,status:0,complete:true,data:KVec::new()};assert!(matches!(e,SleEvent::NativeCommandReply{opcode:4,command_credits:1,status:0,complete:true,data} if data.is_empty()));
}
#[test] fn historical_unconsumed_decoder_and_unattributed_ring_only(){historical::witnesses();}
