// SPDX-License-Identifier: GPL-2.0-only
// Actual process-context cleanup caller with explicit driver/IRQ/owner fixtures.
// No transport or real VFS/device operation is performed here.
use std::cell::{RefCell,RefMut}; use std::rc::Rc; type Arc<T>=Rc<T>;
#[derive(Clone,Copy,Debug,PartialEq)] struct Error(i32);
const ENODEV:Error=Error(-19);type Result<T>=std::result::Result<T,Error>;
thread_local!{static HELD:RefCell<Vec<&'static str>>=const{RefCell::new(vec![])};static OWNER:RefCell<Option<Arc<ControllerRuntime>>>=const{RefCell::new(None)};}
struct Lock<T>{name:&'static str,value:RefCell<T>}struct Guard<'a,T>{name:&'static str,value:RefMut<'a,T>}
impl<T> Lock<T>{fn lock(&self)->Guard<'_,T>{HELD.with(|v|v.borrow_mut().push(self.name));Guard{name:self.name,value:self.value.borrow_mut()}}}
impl<T> std::ops::Deref for Guard<'_,T>{type Target=T;fn deref(&self)->&T{&self.value}}
impl<T> std::ops::DerefMut for Guard<'_,T>{fn deref_mut(&mut self)->&mut T{&mut self.value}}
impl<T> Drop for Guard<'_,T>{fn drop(&mut self){HELD.with(|v|assert_eq!(v.borrow_mut().pop(),Some(self.name)));}}
struct Host{candidate:Option<u16>,submissions:Vec<(u16,u16,Vec<u8>)>}
impl Host{fn cleanup_candidate(&self)->Result<Option<u16>>{Ok(self.candidate)}
 fn submit_cleanup(&mut self,h:u16,opcode:u16,p:&[u8])->Result<bool>{
  if self.candidate!=Some(h){return Ok(false)} self.submissions.push((h,opcode,p.to_vec()));Ok(true)
 }}
struct Identity{generation:u64} struct ControllerRuntime{identity:Identity,protocol_profile:u32,host:Lock<Host>,schedule_gate:Lock<bool>}
struct ControllerState{controller:sle_dli::ControllerBackend}
#[repr(C)] struct SleConnectionSubmit{version:u32,profile:u32,operation:u32,generation:u64,handle:u32,reason:u32,request_id:u64,params:[u8;60]}
struct Plan{opcode:u16,length:u16,params:[u8;3]}
struct Driver{scenario:u8}
impl Driver{fn prepare_connection(&self,r:&SleConnectionSubmit)->Result<Plan>{
 HELD.with(|v|assert!(v.borrow().is_empty(),"driver callback under IRQ guard"));
 assert_eq!((r.version,r.profile,r.operation,r.generation,r.handle,r.reason,r.request_id),(1,1,2,7,0,0x13,0));assert_eq!(r.params,[0;60]);
 OWNER.with(|v|{let borrowed=v.borrow();let o=borrowed.as_ref().unwrap();match self.scenario{1=>o.host.lock().candidate=None,2=>*o.schedule_gate.lock()=true,_=>{}}});
 if self.scenario==3{return Err(Error(-95))} Ok(Plan{opcode:0x1403,length:3,params:[0,0,0x13]})
}}
mod sle_dli{use super::*;pub enum ControllerBackend{Native(Driver)} impl ControllerBackend{pub(super) fn provider(&self)->&Driver{let Self::Native(c)=self;c}}}
mod actual{use super::*;
// @@ACTUAL_PREPARE@@
pub(super) fn invoke(o:&Arc<ControllerRuntime>,s:&ControllerState)->Result<bool>{progress_connection_cleanup(o,s)}
}
fn owner()->Arc<ControllerRuntime>{let o=Rc::new(ControllerRuntime{identity:Identity{generation:7},protocol_profile:1,host:Lock{name:"host",value:RefCell::new(Host{candidate:Some(0),submissions:vec![]})},schedule_gate:Lock{name:"gate",value:RefCell::new(false)}});OWNER.with(|v|*v.borrow_mut()=Some(o.clone()));o}
#[test] fn callback_has_no_irq_guard_and_rechecks_link_and_retirement(){
 for scenario in 0..4{let o=owner();let s=ControllerState{controller:sle_dli::ControllerBackend::Native(Driver{scenario})};let r=actual::invoke(&o,&s);
  assert_eq!(r,match scenario{0=>Ok(true),1=>Ok(false),2=>Err(ENODEV),_=>Err(Error(-95))});
  let h=o.host.lock();assert_eq!(h.submissions.len(),usize::from(scenario==0));if scenario==0{assert_eq!(h.submissions[0],(0,0x1403,vec![0,0,0x13]));}
 }
}
#[test] fn unsupported_controller_and_no_candidate_admit_no_operation(){
 let o=owner();let s=ControllerState{controller:sle_dli::ControllerBackend::Native(Driver{scenario:3})};assert_eq!(actual::invoke(&o,&s),Err(Error(-95)));assert!(o.host.lock().submissions.is_empty());
 o.host.lock().candidate=None;assert_eq!(actual::invoke(&o,&s),Ok(false));assert!(o.host.lock().submissions.is_empty());
}
