// SPDX-License-Identifier: GPL-2.0-only
// Actual native publisher and physical-link state module. Owner lookup, IRQ
// locks, event-log storage and notifications below are dependency fixtures.
#[path="sle_link_observation.rs"] mod sle_link_observation;
use sle_link_observation::{LinkEvidence,LinkObservation};
use std::cell::{RefCell,RefMut};
use std::rc::Rc;
#[derive(Clone,Copy,Debug,PartialEq)] struct Error(i32);
impl Error {fn to_errno(self)->i32{self.0}}
const EINVAL:Error=Error(-22);const ENODEV:Error=Error(-19);const PROTOCOL_ERROR:i32=-71;
mod kernel {pub mod bindings {pub const EMSGSIZE:i32=90;}}
mod sle_uapi {pub const CONTROLLER_EVENT_PAYLOAD_MAX:usize=288;}
#[derive(Clone,Copy,PartialEq)] struct DeviceIdentity {id:u16,generation:u64}
struct Lock<T> {name:&'static str,value:RefCell<T>}
struct Guard<'a,T> {name:&'static str,value:RefMut<'a,T>}
impl<T> Lock<T> {
 fn new(name:&'static str,value:T)->Self{Self{name,value:RefCell::new(value)}}
 fn lock(&self)->Guard<'_,T>{trace(format!("{}+",self.name));Guard{name:self.name,value:self.value.borrow_mut()}}
}
impl<T> std::ops::Deref for Guard<'_,T>{type Target=T;fn deref(&self)->&T{&self.value}}
impl<T> std::ops::DerefMut for Guard<'_,T>{fn deref_mut(&mut self)->&mut T{&mut self.value}}
impl<T> Drop for Guard<'_,T>{fn drop(&mut self){trace(format!("{}-",self.name));}}
struct Host {links:LinkObservation}
impl Host {fn observe_link(&mut self,e:&LinkEvidence){self.links.observe(e)}
fn link_snapshot(&self)->(u64,bool,[Option<sle_link_observation::Link>;16]){self.links.snapshot()}}
struct Data;
impl Data{fn reconcile(&mut self,_:&[Option<sle_link_observation::Link>;16])->Vec<()>{Vec::new()}}
#[derive(Clone,Debug,PartialEq)] struct Record {id:u16,generation:u64,profile:u32,event:u16,body:Vec<u8>}
struct Log {records:Vec<Record>,fail:bool}
impl Log {fn publish(&mut self,id:DeviceIdentity,profile:u32,event:u16,body:&[u8])->Result<(),Error>{
 if self.fail{return Err(Error(-75))} self.records.push(Record{id:id.id,generation:id.generation,profile,event,body:body.to_vec()});Ok(())
}}
struct Poll(&'static str);
impl Poll {fn notify_all(&self){trace(self.0.into());}}
struct Owner {identity:DeviceIdentity,protocol_profile:u32,host:Lock<Host>,data:Lock<Data>,data_poll:Poll,schedule_gate:Lock<bool>,controller_events:Lock<Log>,controller_event_poll:Poll}
impl Owner {fn schedule_rx(&self,delay:u64){assert_eq!(delay,0);trace("rx".into());}
fn new(id:u16,generation:u64)->Rc<Self>{Rc::new(Self{identity:DeviceIdentity{id,generation},protocol_profile:1,
 host:Lock::new("host",Host{links:LinkObservation::new()}),data:Lock::new("data",Data),data_poll:Poll("data_notify"),schedule_gate:Lock::new("gate",false),controller_events:Lock::new("log",Log{records:vec![],fail:false}),controller_event_poll:Poll("notify")})}}
thread_local! {static OWNERS:RefCell<Vec<Rc<Owner>>>=const{RefCell::new(vec![])};static TRACE:RefCell<Vec<String>>=const{RefCell::new(vec![])};}
fn trace(v:String){TRACE.with(|t|t.borrow_mut().push(v));}
mod sle_ingress {use super::*;pub fn ingress_owner(id:DeviceIdentity)->Option<Rc<Owner>>{OWNERS.with(|o|o.borrow().iter().find(|o|o.identity==id).cloned())}}
struct NativeController;
impl NativeController {fn result_to_errno(v:Result<(),Error>)->i32{v.err().map_or(0,|e|e.0)}}
mod under_test {
use super::*;
// @@INGRESS@@
pub(super) unsafe fn invoke(id:u16,g:u64,p:u32,code:u16,body:*const u8,n:usize,e:Option<LinkEvidence>)->i32 {
 unsafe { publish_native_event(id,g,p,code,body,n,e) }
}
}
fn setup()->(Rc<Owner>,Rc<Owner>){let a=Owner::new(0,7);let b=Owner::new(1,8);OWNERS.with(|o|*o.borrow_mut()=vec![a.clone(),b.clone()]);TRACE.with(|t|t.borrow_mut().clear());(a,b)}
fn up()->LinkEvidence{LinkEvidence{kind:1,status:0,handle:7,role:1,address_type:0,address:[1;6],reserved:[0;2]}}
fn publish(id:u16,g:u64,p:u32,code:u16,body:&[u8],e:Option<LinkEvidence>)->i32{unsafe{under_test::invoke(id,g,p,code,body.as_ptr(),body.len(),e)}}
#[test] fn actual_publisher_keeps_raw_body_and_obligation_and_reverse_unlocks(){
 let(a,b)=setup();let body=[0xaa;32];assert_eq!(publish(0,7,1,0x1401,&body,Some(up())),0);
 let order=TRACE.with(|t|t.borrow().clone());assert_eq!(order,["host+","data+","gate+","log+","log-","gate-","data-","host-","rx","data_notify","notify"]);
 assert!(!a.host.lock().links.clear_for_management());assert!(b.host.lock().links.clear_for_management());
 assert_eq!(a.controller_events.lock().records,[Record{id:0,generation:7,profile:1,event:0x1401,body:body.to_vec()}]);
}
#[test] fn retained_obligation_survives_event_log_failure(){
 let(a,_)=setup();a.controller_events.lock().fail=true;
 assert_eq!(publish(0,7,1,0x15,&[0;11],Some(up())),-75);assert!(!a.host.lock().links.clear_for_management());
 assert!(a.controller_events.lock().records.is_empty());assert!(!TRACE.with(|t|t.borrow().iter().any(|x|x=="notify")));
 assert_eq!(TRACE.with(|t|t.borrow().iter().filter(|x|x.as_str()=="rx").count()),1);
}
#[test] fn management_events_profile_retirement_and_oversize_cannot_mutate_owner(){
 for (id,g,p,code,n,expected) in [(0,7,1,1,11,-71),(0,7,1,2,11,-71),(0,6,1,0x15,11,-19),(0,7,2,0x15,11,-71),(0,7,0,0x15,11,-71),(0,7,1,0x15,289,-90)] {
  let(a,b)=setup();assert_eq!(publish(id,g,p,code,&vec![0;n],Some(up())),expected);
  assert!(a.host.lock().links.clear_for_management());assert!(b.host.lock().links.clear_for_management());assert!(a.controller_events.lock().records.is_empty());
 }
 let(a,_)=setup();*a.schedule_gate.lock()=true;assert_eq!(publish(0,7,1,0x15,&[0;11],Some(up())),-19);assert!(a.host.lock().links.clear_for_management());
}
#[test] fn exact_generation_disconnect_and_failed_outcome_do_not_cross_owners(){
 let(a,b)=setup();assert_eq!(publish(0,7,1,0x1401,&[0;11],Some(up())),0);
 let mut down=up();down.kind=2;down.status=1;assert_eq!(publish(0,7,1,0x1405,&[0;4],Some(down)),0);assert!(!a.host.lock().links.clear_for_management());
 down.status=0;assert_eq!(publish(1,8,1,5,&[0;4],Some(down)),0);assert!(!a.host.lock().links.clear_for_management());assert!(b.host.lock().links.clear_for_management());
 assert_eq!(publish(0,7,1,5,&[0;4],Some(down)),0);assert!(a.host.lock().links.clear_for_management());
}
#[test] fn log_only_notifications_do_not_imply_links(){
 let(a,_)=setup();assert_eq!(publish(0,7,1,0x180b,&[0;23],None),0);assert!(a.host.lock().links.clear_for_management());
}
