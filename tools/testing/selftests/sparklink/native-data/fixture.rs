// SPDX-License-Identifier: GPL-2.0-only
// Actual ACB ingress/send/take and budget/queue modules. Locks, owner lookup,
// allocations, Backend/USB and wakeups are dependencies, not hardware evidence.
extern crate self as kernel;
use std::cell::{Cell, RefCell, RefMut};
use std::rc::Rc as Arc;
type ControllerRuntime = Owner;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::ffi::c_void;
#[derive(Clone, Copy, Debug, PartialEq)] pub struct Error(i32);
impl Error {pub fn from_errno(n:i32)->Self{Self(n)} pub fn to_errno(self)->i32{self.0}}
pub type Result<T=()> = std::result::Result<T, Error>;
pub const EINVAL:Error=Error(-22);pub const ENODEV:Error=Error(-19);pub const EAGAIN:Error=Error(-11);
pub const EMSGSIZE:Error=Error(-90);pub const EIO:Error=Error(-5);pub const ENOBUFS:Error=Error(-105);
pub const ENOMEM:Error=Error(-12);pub const EOVERFLOW:Error=Error(-75);pub const GFP_ATOMIC:()=();
pub mod bindings {pub const EPROTO:i32=71;pub const EALREADY:i32=114;pub const ECONNRESET:i32=104;pub const EACCES:i32=13;pub const ESTALE:i32=116;pub const EOPNOTSUPP:i32=95;pub const ENOBUFS:i32=105;pub const EMSGSIZE:i32=90;
pub unsafe fn ktime_get_boottime()->i64{super::NOW.with(|n|*n.borrow() as i64)}}
pub mod prelude {pub use crate::{Error,Result,KVec,ENODEV,EINVAL,ENOBUFS,EMSGSIZE,EAGAIN,EIO,ENOMEM,GFP_ATOMIC};}
#[derive(Debug)] pub struct KVec<T>(Vec<T>);
impl<T> KVec<T> {
 fn new()->Self{Self(Vec::new())}
 fn len(&self)->usize{self.0.len()}
 fn as_ptr(&self)->*const T{self.0.as_ptr()}
 fn capacity(&self)->usize{self.0.capacity()}
 fn reserve(&mut self,n:usize,_:())->Result{self.0.reserve(n);Ok(())}
}
impl<T> std::ops::Deref for KVec<T>{type Target=[T];fn deref(&self)->&[T]{&self.0}}
impl<T:Clone> KVec<T> {fn extend_from_slice(&mut self,v:&[T],_:())->Result{self.0.extend_from_slice(v);Ok(())}}
#[path="sle_link_observation.rs"] mod sle_link_observation;
#[path="sle_data_credit.rs"] mod sle_data_credit;
#[path="sle_native_data.rs"] mod sle_native_data;
#[path="sle_grant.rs"] mod sle_grant;
#[path="sle_sessions.rs"] mod sle_sessions;
use sle_link_observation::{LinkEvidence,LinkObservation};
const PROTOCOL_ERROR:i32=-71;const UNSUPPORTED:i32=-95;
#[derive(Clone,Copy,PartialEq)] pub(crate) struct DeviceIdentity{id:u16,generation:u64}
mod sle_dev {pub(crate) use super::DeviceIdentity;}
struct Lock<T>(RefCell<T>);
impl<T> Lock<T>{fn new(v:T)->Self{Self(RefCell::new(v))}fn lock(&self)->RefMut<'_,T>{self.0.borrow_mut()}}
struct Host{grants:sle_grant::LeaseAuthority,links:LinkObservation,data_revoked:bool,fault:Option<Error>}
impl Host{fn controller_status(&self)->(u32,bool,Option<Error>){(0,true,self.fault)}
// @@ADMITTED@@
fn link_snapshot(&self)->(u64,bool,[Option<sle_link_observation::Link>;16]){self.links.snapshot()}}
struct Poll;impl Poll{fn notify_all(&self){}}
struct Dummy{transport:*mut c_void}
impl Dummy{fn command_transport(&self)->NativeCommandTransport{NativeCommandTransport{transport:self.transport}}}
struct NativeCommandTransport{transport:*mut c_void}
mod sle_dli{pub enum ControllerBackend{Native(super::Dummy)}
impl ControllerBackend{pub(super) fn provider(&self)->&super::Dummy{let Self::Native(c)=self;c}}
}
struct State{controller:sle_dli::ControllerBackend}
struct Owner{
 identity:DeviceIdentity,host:Lock<Host>,data:Lock<sle_native_data::NativeData>,data_poll:Poll,
 sessions:Lock<[Option<sle_sessions::Session>;16]>,schedule_gate:Lock<bool>,native_lifecycle:Lock<()>,state:Lock<Option<State>>,transport_open:AtomicBool,
 commands:RefCell<Vec<SleEvent>>,
}
impl Owner{fn new(id:u16,generation:u64)->Rc<Self>{Rc::new(Self{
 identity:DeviceIdentity{id,generation},host:Lock::new(Host{grants:{let mut g=sle_grant::LeaseAuthority::new();assert!(g.activate(1,true));g},links:LinkObservation::new(),data_revoked:false,fault:None}),
 data:Lock::new(sle_native_data::NativeData::new(254,5)),data_poll:Poll,sessions:Lock::new([const{None};16]),schedule_gate:Lock::new(false),
 native_lifecycle:Lock::new(()),state:Lock::new(Some(State{controller:sle_dli::ControllerBackend::Native(Dummy{transport:(id as usize+1) as *mut c_void})})),
 transport_open:AtomicBool::new(true),commands:RefCell::new(Vec::new()),
})}}
impl Owner{fn schedule_rx(&self,delay:u64){assert_eq!(delay,0)}}
#[derive(Debug)] enum SleEvent{
 CommandCredits{credits:u8},
 NativeCommandReply{opcode:u16,command_credits:u8,status:u8,complete:bool,data:KVec<u8>},
 HardwareError{code:u8},
 NativeControllerData{lifetime:u64,handle:u16,index:u16,data:KVec<u8>},
}
thread_local!{
 static OWNERS:RefCell<Vec<Rc<Owner>>>=const{RefCell::new(Vec::new())};
 static TX:RefCell<Vec<(usize,u16,Vec<u8>)>>=const{RefCell::new(Vec::new())};
 static BEFORE_COMMIT:RefCell<u8>=const{RefCell::new(0)};
 static SUBMIT_RESULT:RefCell<i32>=const{RefCell::new(0)};
 static TX_RESULT:RefCell<i32>=const{RefCell::new(0)};
 static EARLY_COMPLETE:RefCell<bool>=const{RefCell::new(false)};
 static NOW:RefCell<u64>=const{RefCell::new(1)};
}
mod sle_ingress{use super::*;
 pub fn ingress_owner(id:DeviceIdentity)->Option<Rc<Owner>>{OWNERS.with(|o|o.borrow().iter().find(|o|o.identity==id).cloned())}
 pub fn enqueue_rx(owner:&Owner,event:SleEvent){owner.commands.borrow_mut().push(event);}
}
struct Submission {p:*mut c_void,handle:u16,data:*const u8,n:usize}
unsafe extern "C" fn atomic_submit(context:*mut c_void)->i32{
 let x=unsafe{&*context.cast::<Submission>()};
 let owner=OWNERS.with(|o|o.borrow()[x.p as usize-1].clone());
 // Actual commit body must hold all three guards at the queue operation.
 assert!(owner.host.0.try_borrow_mut().is_err());
 assert!(owner.data.0.try_borrow_mut().is_err());
 assert!(owner.schedule_gate.0.try_borrow_mut().is_err());
 let result=SUBMIT_RESULT.with(|r|*r.borrow());
 if result==0 {TX.with(|t|t.borrow_mut().push((x.p as usize,x.handle,
     unsafe{std::slice::from_raw_parts(x.data,x.n)}.to_vec())));}
 result
}
unsafe fn sparklink_native_transport_acb(p:*mut c_void,ticket:*mut c_void,handle:u16,data:*const u8,n:usize)->i32{
 let owner=OWNERS.with(|o|o.borrow()[p as usize-1].clone());
 let mode=BEFORE_COMMIT.with(|b|*b.borrow());
 match mode {
  1=>link(&owner,handle,2),
  2=>owner.host.lock().data_revoked=true,
  3=>*owner.schedule_gate.lock()=true,
  4=>{link(&owner,handle,2);link(&owner,handle,1);},
  7=>{let mut host=owner.host.lock();host.grants.revoke();assert!(host.grants.activate(2,true));},
  5=>return 0, // deliberately lying fixture; production entry must reject it.
  _=>(),
 }
 let mut submission=Submission{p,handle,data,n};
 let result=unsafe{under_test::sparklink_native_tx_commit_rust(ticket,Some(atomic_submit),
     (&mut submission as *mut Submission).cast())};
 if mode==6 {assert_eq!(unsafe{under_test::sparklink_native_tx_commit_rust(ticket,Some(atomic_submit),
     (&mut submission as *mut Submission).cast())},-114);}
 if result!=0{return result;}
 if EARLY_COMPLETE.with(|e|*e.borrow()){
  // Completion can arrive before driver return, but after the atomic submit
  // guard releases. This is dependency injection, not a hardware completion.
  assert_eq!(receive(owner.identity.id,owner.identity.generation,&[0xa2,9,0,3,0,handle as u8,(handle>>8)as u8,1]),0);
 }
 TX_RESULT.with(|r|*r.borrow())
}
mod under_test{use super::*;
// @@TICKET@@
// @@COMMIT@@
// @@CONTROLLER_DATA@@
// @@RECEIVE@@
// @@SEND@@
// @@SEND_COMMON@@
// @@GUARDED_SEND@@
// @@TAKE@@
}
fn setup()->(Rc<Owner>,Rc<Owner>){let a=Owner::new(0,7);let b=Owner::new(1,8);
 OWNERS.with(|o|*o.borrow_mut()=vec![a.clone(),b.clone()]);TX.with(|t|t.borrow_mut().clear());
 BEFORE_COMMIT.with(|b|*b.borrow_mut()=0);SUBMIT_RESULT.with(|r|*r.borrow_mut()=0);
 TX_RESULT.with(|r|*r.borrow_mut()=0);EARLY_COMPLETE.with(|e|*e.borrow_mut()=false);NOW.with(|n|*n.borrow_mut()=1);(a,b)}
fn link(owner:&Owner,handle:u16,kind:u32){owner.host.lock().links.observe(&LinkEvidence{kind,status:0,handle:handle as u32,role:1,address_type:0,address:[1;6],reserved:[0;2]});}
fn receive(id:u16,g:u64,bytes:&[u8])->i32{unsafe{under_test::sparklink_native_receive_rust(id,g,bytes.as_ptr(),bytes.len())}}
fn send(id:u16,g:u64,life:u64,handle:u16,bytes:&[u8])->i32{unsafe{under_test::sparklink_native_acb_send_rust(id,g,life,handle,bytes.as_ptr(),bytes.len())}}
fn take(id:u16,g:u64,life:u64,handle:u16,capacity:usize)->(i32,Vec<u8>){let mut out=vec![0;capacity];let mut n=0;
 let ret=unsafe{under_test::sparklink_native_acb_take_rust(id,g,life,handle,out.as_mut_ptr(),capacity,&mut n)};out.truncate(n);(ret,out)}
fn acb(handle:u16,payload:&[u8])->Vec<u8>{let mut p=vec![0xa3,handle as u8,(handle>>8)as u8,payload.len()as u8,(payload.len()>>8)as u8];p.extend_from_slice(payload);p}
#[test] fn actual_receive_binds_controller_generation_lifetime_and_preserves_fifo(){
 let(a,b)=setup();link(&a,0,1);link(&b,0,1);
 assert_eq!(receive(0,6,&acb(0,&[1])),-19);
 assert_eq!(receive(0,7,&acb(0,&[1,2])),0);assert_eq!(receive(0,7,&acb(0,&[3,4])),0);
 assert_eq!(take(1,8,1,0,2).0,-11);assert_eq!(take(0,7,1,0,1).0,-90);
 assert_eq!(take(0,7,1,0,2),(0,vec![1,2]));assert_eq!(take(0,7,1,0,2),(0,vec![3,4]));
 assert_eq!(receive(0,7,&acb(0,&[5])),0);link(&a,0,2);link(&a,0,1);
 assert_eq!(take(0,7,1,0,2).0,-116);assert_eq!(receive(0,7,&acb(0,&[6])),0);
 assert_eq!(take(0,7,3,0,2),(0,vec![6]));assert!(a.commands.borrow().is_empty());
}
#[test] fn actual_rx_is_bounded_and_drops_do_not_fault_other_controller(){
 let(a,b)=setup();link(&a,0,1);link(&b,0,1);
 for i in 0..17{assert_eq!(receive(0,7,&acb(0,&[i])),0)}
 assert_eq!(a.data.lock().dropped,1);assert_eq!(b.data.lock().dropped,0);
 assert_eq!(receive(1,8,&acb(0,&[99])),0);assert_eq!(take(1,8,1,0,1),(0,vec![99]));
 for i in 0..16{assert_eq!(take(0,7,1,0,1),(0,vec![i]))}
 assert_eq!(take(0,7,1,0,1).0,-11);
}
#[test] fn actual_send_limits_credit_and_completion_does_not_touch_commands(){
 let(a,b)=setup();link(&a,0,1);link(&b,0,1);
 assert_eq!(send(0,7,1,0,&[0;255]),-90);assert_eq!(send(0,7,9,0,&[1]),-116);
 for _ in 0..5{assert_eq!(send(0,7,1,0,&[7]),0)}
 assert_eq!(send(0,7,1,0,&[7]),-11);assert_eq!(send(1,8,1,0,&[8]),0);
 assert_eq!(TX.with(|t|t.borrow().len()),6);
 assert_eq!(receive(0,7,&[0xa2,9,0,3,0,0,0,0]),0);assert_eq!(send(0,7,1,0,&[7]),-11);
 assert_eq!(receive(0,7,&[0xa2,9,0,3,0,0,0,2]),0);assert_eq!(send(0,7,1,0,&[7]),0);
 assert!(a.commands.borrow().is_empty());assert_eq!(a.data.lock().completion_errors,1);
 assert_eq!(a.data.lock().credits.maximum(),Ok(254));
}
#[test] fn actual_completion_before_usb_return_is_accounted_and_old_debt_blocks_reuse(){
 let(a,_)=setup();link(&a,0,1);EARLY_COMPLETE.with(|e|*e.borrow_mut()=true);
 for _ in 0..10{assert_eq!(send(0,7,1,0,&[9]),0)}
 EARLY_COMPLETE.with(|e|*e.borrow_mut()=false);assert_eq!(send(0,7,1,0,&[9]),0);
 link(&a,0,2);link(&a,0,1);assert_eq!(send(0,7,3,0,&[9]),-116);
 assert_eq!(receive(0,7,&[0xa2,9,0,3,0,0,0,1]),0);assert_eq!(send(0,7,3,0,&[9]),0);
}
#[test] fn malformed_or_uncertain_data_never_refills_or_becomes_success(){
 let(a,b)=setup();link(&a,0,1);link(&b,0,1);
 for p in [vec![0xa3,0,0,2,0,1],vec![0xa2,9,0,2,0,0,0]]{assert_eq!(receive(0,7,&p),-71)}
 assert_eq!(receive(0,7,&[0xa3,0,0x40,1,0,1]),-95);
 assert_eq!(send(0,7,1,0,&[1]),0);assert_eq!(receive(0,7,&[0xa2,9,0,3,0,0,0,2]),0);
 assert_eq!(send(0,7,1,0,&[1]),-5);assert_eq!(send(1,8,1,0,&[1]),0);
 let(a,_)=setup();link(&a,0,1);TX_RESULT.with(|r|*r.borrow_mut()=-110);
 assert_eq!(send(0,7,1,0,&[1]),-110);TX_RESULT.with(|r|*r.borrow_mut()=0);
 assert_eq!(send(0,7,1,0,&[1]),-5);
 *a.schedule_gate.lock()=true;assert_eq!(send(0,7,1,0,&[1]),-19);
}
#[test] fn actual_fragments_reassemble_without_crossing_controllers(){
 let(a,b)=setup();link(&a,0,1);link(&b,0,1);
 assert_eq!(receive(0,7,&acb(0x1000,b"first")),0);
 assert_eq!(receive(1,8,&acb(0x1000,b"other")),0);
 assert_eq!(take(0,7,1,0,20).0,-11);
 assert_eq!(receive(0,7,&acb(0x2000,b"middle")),0);
 assert_eq!(receive(1,8,&acb(0x3000,b"last")),0);
 assert_eq!(receive(0,7,&acb(0x3000,b"last")),0);
 assert_eq!(take(0,7,1,0,20),(0,b"firstmiddlelast".to_vec()));
 assert_eq!(take(1,8,1,0,20),(0,b"otherlast".to_vec()));
 assert!(a.commands.borrow().is_empty());
}
#[test] fn stale_expired_oversized_and_orphan_fragments_do_not_deliver_or_refill(){
 let(a,_)=setup();link(&a,0,1);
 assert_eq!(receive(0,7,&acb(0x3000,b"orphan")),0);assert_eq!(take(0,7,1,0,20).0,-11);
 receive(0,7,&acb(0x1000,b"old"));link(&a,0,2);link(&a,0,1);
 receive(0,7,&acb(0x3000,b"wrong life"));assert_eq!(take(0,7,3,0,20).0,-11);
 receive(0,7,&acb(0x1000,b"timeout"));NOW.with(|n|*n.borrow_mut()=5_000_000_002);
 receive(0,7,&acb(0x3000,b"late"));assert_eq!(take(0,7,3,0,20).0,-11);
 receive(0,7,&acb(0x1000,&[1;2040]));receive(0,7,&acb(0x3000,&[1;8]));
 assert_eq!(take(0,7,3,0,2047).0,-11);
 assert_eq!(send(0,7,3,0,b"still live"),0);
}
#[test] fn existing_management_frames_still_delegate_without_data_credit(){
 let(a,_)=setup();
 assert_eq!(receive(0,7,&[0xa2,2,0,3,0,0,0,4]),0);
 assert_eq!(receive(0,7,&[0xa2,2,0,5,0,2,4,1,0,0xaa]),0);
 assert_eq!(receive(0,7,&[0xa2,10,0,1,0,7]),0);
 let commands=a.commands.borrow();assert_eq!(commands.len(),3);
 assert!(matches!(&commands[0],SleEvent::CommandCredits{credits:4}));
 match &commands[1]{SleEvent::NativeCommandReply{opcode,command_credits,status,complete,data}=>{
  assert_eq!((*opcode,*command_credits,*status,*complete),(0x0402,1,0,true));assert_eq!(data.0,[0xaa]);
 },_=>panic!("management reply changed")}
 assert!(matches!(&commands[2],SleEvent::HardwareError{code:7}));
}

#[test] fn actual_ticket_rechecks_down_revoke_retirement_and_reused_handle_before_submit(){
 for (mode,expected) in [(1,-116),(2,-13),(3,-19),(4,-116),(5,-71)] {
  let(a,b)=setup();link(&a,0,1);link(&b,0,1);
  BEFORE_COMMIT.with(|v|*v.borrow_mut()=mode);
  assert_eq!(send(0,7,1,0,b"never queue"),expected);
  assert!(TX.with(|t|t.borrow().is_empty()));
  assert_eq!(a.data.lock().credits.maximum(),Ok(254));
  BEFORE_COMMIT.with(|v|*v.borrow_mut()=0);
  assert_eq!(send(1,8,1,0,b"independent"),0);
 }
}
#[test] fn actual_never_queued_failure_rolls_back_only_current_reservation(){
 let(a,_)=setup();link(&a,0,1);
 assert_eq!(send(0,7,1,0,b"old queued debt"),0);
 SUBMIT_RESULT.with(|r|*r.borrow_mut()=-12);
 for _ in 0..32 {assert_eq!(send(0,7,1,0,b"never queued"),-12);}
 assert_eq!(a.data.lock().credits.maximum(),Ok(254));
 assert_eq!(TX.with(|t|t.borrow().len()),1);
 SUBMIT_RESULT.with(|r|*r.borrow_mut()=0);
 for _ in 0..4 {assert_eq!(send(0,7,1,0,b"accepted"),0);}
 assert_eq!(send(0,7,1,0,b"full"),-11);
 assert_eq!(receive(0,7,&[0xa2,9,0,3,0,0,0,5]),0);
 assert_eq!(send(0,7,1,0,b"new"),0);
}
#[test] fn actual_ticket_is_single_attempt_and_usb_success_still_owes_nocp(){
 let(a,_)=setup();link(&a,0,1);BEFORE_COMMIT.with(|v|*v.borrow_mut()=6);
 for _ in 0..5 {assert_eq!(send(0,7,1,0,b"queued once"),0);}
 assert_eq!(TX.with(|t|t.borrow().len()),5);
 assert_eq!(send(0,7,1,0,b"credit exhausted"),-11);
}

struct ConsentScope { live: bool }
unsafe extern "C" fn consent_scope(scope:*mut c_void,submit:unsafe extern "C" fn(*mut c_void)->i32,context:*mut c_void)->i32 {
 let scope=unsafe{&*scope.cast::<ConsentScope>()};
 if !scope.live {-125} else {unsafe{submit(context)}}
}
#[test] fn actual_guarded_entry_rejects_retired_binding_without_losing_prior_debt(){
 let(a,_)=setup();link(&a,0,1);
 let mut scope=ConsentScope{live:true};
 let bytes=b"guarded";
 let send_guarded=|scope:&mut ConsentScope|unsafe{under_test::sparklink_native_acb_send_guarded_rust(
  0,7,1,0,bytes.as_ptr(),bytes.len(),1,Some(consent_scope),(scope as *mut ConsentScope).cast())};
 assert_eq!(send_guarded(&mut scope),0);
 scope.live=false;
 for _ in 0..32 {assert_eq!(send_guarded(&mut scope),-125);}
 assert_eq!(TX.with(|t|t.borrow().len()),1);
 scope.live=true;
 for _ in 0..4 {assert_eq!(send_guarded(&mut scope),0);}
 assert_eq!(send_guarded(&mut scope),-11);
 assert_eq!(a.data.lock().credits.maximum(),Ok(254));
}

struct FakeSession {refs:usize, stopped:bool, id:u16, generation:u64, lifetime:u64, handle:u16}
#[no_mangle] unsafe extern "C" fn sl_connection_session_create(id:u16,generation:u64,lifetime:u64,handle:u16,epoch:u64,maximum:u16)->*mut c_void {
 assert!(maximum>5);assert_ne!(epoch,0);Box::into_raw(Box::new(FakeSession{refs:1,stopped:false,id,generation,lifetime,handle})).cast()
}
#[no_mangle] unsafe extern "C" fn sl_connection_session_get(p:*mut c_void){unsafe{(*p.cast::<FakeSession>()).refs+=1;}}
#[no_mangle] unsafe extern "C" fn sl_connection_session_put(p:*mut c_void){unsafe{
 let s=&mut *p.cast::<FakeSession>();assert!(s.refs>0);s.refs-=1;
 if s.refs==0 {drop(Box::from_raw(p.cast::<FakeSession>()));}
}}
#[no_mangle] unsafe extern "C" fn sl_connection_session_stop(p:*mut c_void,error:i32){unsafe{
 let s=&mut *p.cast::<FakeSession>();assert!(error<0);s.stopped=true;
 let owner=sle_ingress::ingress_owner(DeviceIdentity{id:s.id,generation:s.generation}).unwrap();
 assert!(owner.sessions.0.try_borrow_mut().is_ok());
 assert!(owner.host.0.try_borrow_mut().is_ok());
 assert!(owner.native_lifecycle.0.try_borrow_mut().is_ok());
}}
fn session(id:u16,generation:u64,life:u64,handle:u16)->(*mut c_void,i32){let mut error=0;
 let p=unsafe{sle_sessions::sparklink_native_session_get_rust(id,generation,life,handle,1,&mut error)};(p,error)}
#[test] fn actual_runtime_session_get_shares_one_owner_and_preserves_lifetime(){
 let(a,b)=setup();link(&a,0,1);link(&b,0,1);
 let(p,e)=session(0,7,1,0);assert_eq!(e,0);assert!(!p.is_null());
 let(q,e)=session(0,7,1,0);assert_eq!(e,0);assert_eq!(p,q);
 unsafe{assert_eq!((*p.cast::<FakeSession>()).refs,3);assert_eq!((*p.cast::<FakeSession>()).lifetime,1);assert_eq!((*p.cast::<FakeSession>()).handle,0);}
 let(other,e)=session(1,8,1,0);assert_eq!(e,0);assert_ne!(p,other);
 assert_eq!(session(0,7,9,0).1,-116);assert_eq!(session(0,8,1,0).1,-19);
 link(&a,0,2);a.reconcile_sessions();
 unsafe{assert!((*p.cast::<FakeSession>()).stopped);assert_eq!((*p.cast::<FakeSession>()).refs,2);assert!(!(*other.cast::<FakeSession>()).stopped);}
 link(&a,0,1);let(new,e)=session(0,7,3,0);assert_eq!(e,0);assert_ne!(p,new);
 a.stop_sessions(-19);b.stop_sessions(-19);
 unsafe{for pointer in [p,q,other,new]{sl_connection_session_put(pointer);}}
}

#[test] fn physical_session_birth_precedes_fd_and_reuses_one_table_owner(){
 let(a,b)=setup();link(&a,0,1);link(&b,0,1);
 assert!(a.sessions.lock().iter().all(Option::is_none));a.reconcile_sessions();
 assert!(a.sessions.lock()[0].is_some());
 let(p,e)=session(0,7,1,0);assert_eq!(e,0);a.reconcile_sessions();
 unsafe{assert_eq!((*p.cast::<FakeSession>()).refs,2);}
 let(q,e)=session(0,7,1,0);assert_eq!(e,0);assert_eq!(q,p);
 unsafe{assert_eq!((*p.cast::<FakeSession>()).refs,3);sl_connection_session_put(q);}

 assert!(b.sessions.lock().iter().all(Option::is_none));
 a.host.lock().grants.revoke();a.reconcile_sessions();assert!(a.sessions.lock().iter().all(Option::is_none));
 b.reconcile_sessions();assert!(b.sessions.lock()[0].is_some());
 unsafe{assert!((*p.cast::<FakeSession>()).stopped);sl_connection_session_put(p);}
}
#[test] fn actual_session_status_and_revocation_are_per_runtime_and_join_outside_locks(){
 let(a,b)=setup();link(&a,0,1);link(&b,0,1);
 let(p,_)=session(0,7,1,0);let(q,_)=session(1,8,1,0);
 a.host.lock().data_revoked=true;
 assert_eq!(unsafe{sle_sessions::sparklink_native_session_status_rust(0,7,1,0,1)},-13);
 assert_eq!(session(0,7,1,0).1,-13);
 a.reconcile_sessions();
 unsafe{assert!((*p.cast::<FakeSession>()).stopped);assert!(!(*q.cast::<FakeSession>()).stopped);}
 b.stop_sessions(-19);unsafe{sl_connection_session_put(p);sl_connection_session_put(q);}
}

#[test] fn actual_successor_epoch_rejects_old_ticket_without_refunding_old_debt() {
 let(a,b)=setup();link(&a,0,1);link(&b,0,1);
 let mut scope=ConsentScope{live:true};let bytes=b"epoch";
 let guarded=|epoch|unsafe{under_test::sparklink_native_acb_send_guarded_rust(0,7,1,0,bytes.as_ptr(),bytes.len(),epoch,Some(consent_scope),(&mut scope as *mut ConsentScope).cast())};
 let mut guarded=guarded;
 assert_eq!(guarded(1),0);
 BEFORE_COMMIT.with(|v|*v.borrow_mut()=7);
 assert_eq!(guarded(1),-13); // validated old epoch before driver; successor before commit
 BEFORE_COMMIT.with(|v|*v.borrow_mut()=0);
 assert_eq!(guarded(1),-13);assert_eq!(guarded(0),-13);
 assert_eq!(unsafe{sle_sessions::sparklink_native_session_status_rust(0,7,1,0,1)},-13);
 assert_eq!(unsafe{sle_sessions::sparklink_native_session_status_rust(1,8,1,0,1)},0);
 // New epoch does not inherit/erase old debt: only four more physical slots.
 for _ in 0..4 {assert_eq!(guarded(2),0);}assert_eq!(guarded(2),-11);
 assert_eq!(TX.with(|v|v.borrow().len()),5);
 a.stop_sessions(-19);b.stop_sessions(-19);
}

unsafe extern "C" fn actual_admission_callback(context:*mut c_void)->i32 {
 let count=unsafe{&mut *context.cast::<usize>()};
 let owner=OWNERS.with(|o|o.borrow()[0].clone());
 assert!(owner.host.0.try_borrow_mut().is_err());
 assert!(owner.data.0.try_borrow_mut().is_err());
 assert!(owner.schedule_gate.0.try_borrow_mut().is_err());
 *count+=1;0
}
#[test] fn actual_queue_admission_holds_authority_and_successor_denies_stale_callback() {
 let(a,b)=setup();link(&a,0,1);link(&b,0,1);let mut count=0usize;
 let mut admit=|epoch|unsafe{sle_sessions::sparklink_native_session_admit_rust(0,7,1,0,epoch,Some(actual_admission_callback),(&mut count as *mut usize).cast())};
 assert_eq!(admit(1),0);
 {let mut host=a.host.lock();host.grants.revoke();assert!(host.grants.activate(2,true));}
 assert_eq!(admit(1),-13);assert_eq!(admit(0),-13);assert_eq!(admit(2),0);assert_eq!(count,2);
 assert_eq!(unsafe{sle_sessions::sparklink_native_session_admit_rust(0,7,1,0,2,None,core::ptr::null_mut())},-22);
 a.stop_sessions(-19);b.stop_sessions(-19);
}
#[test] fn actual_reconcile_retires_old_authority_even_after_successor_published() {
 let(a,b)=setup();link(&a,0,1);link(&b,0,1);let(p,_)=session(0,7,1,0);let(q,_)=session(1,8,1,0);
 {let mut host=a.host.lock();host.grants.revoke();assert!(host.grants.activate(2,true));}
 a.reconcile_sessions();
 unsafe{assert!((*p.cast::<FakeSession>()).stopped);assert!(!(*q.cast::<FakeSession>()).stopped);}
 assert_eq!(session(0,7,1,0).1,-13);
 b.stop_sessions(-19);unsafe{sl_connection_session_put(p);sl_connection_session_put(q);}
}


fn controller_data(handle:u16,index:u16,payload:&[u8])->Vec<u8>{
 let n=payload.len()+5;let mut p=vec![0xa2,0x14,0,n as u8,(n>>8) as u8];
 p.extend_from_slice(&handle.to_le_bytes());p.extend_from_slice(&index.to_le_bytes());
 p.push(payload.len() as u8);p.extend_from_slice(payload);p
}
#[test] fn controller_data_all_u8_payload_lengths_freeze_observed_lifetime(){
 let(a,b)=setup();link(&a,0,1);link(&b,0,1);
 for len in 0..=255 {
  let packet=controller_data(0,0x0134,&vec![0xa5;len]);
  assert_eq!(receive(0,7,&packet),0,"payload {len}");
 }
 assert_eq!(a.commands.borrow().len(),256);assert!(b.commands.borrow().is_empty());
 for (n,e) in a.commands.borrow().iter().enumerate() {
  match e {SleEvent::NativeControllerData{lifetime,handle,index,data}=>{
   assert_eq!((*lifetime,*handle,*index),(1,0,0x0134));assert_eq!(data.0,vec![0xa5;n]);
  },_=>panic!("wrong event")}
 }
 assert_eq!(take(0,7,1,0,2047).0,-11);assert_eq!(take(1,8,1,0,2047).0,-11);
 // Unsupported security cannot refill or spend either controller's ACB debt.
 for _ in 0..5 {assert_eq!(send(0,7,1,0,b"own data"),0);}
 assert_eq!(send(0,7,1,0,b"full"),-11);assert_eq!(send(1,8,1,0,b"peer data"),0);
}
#[test] fn controller_data_truncated_overlong_mismatched_handle_is_malformed(){
 setup();
 let packet=controller_data(0x0fff,0x0147,&[2;255]);assert_eq!(packet.len(),265);
 for n in 0..packet.len(){assert_eq!(receive(0,7,&packet[..n]),-71,"cut {n}");}
 for offset in [3,4,9]{let mut p=packet.clone();p[offset]^=1;assert_eq!(receive(0,7,&p),-71);}
 let mut p=packet.clone();p.push(0);p[3]=5;p[4]=1;assert_eq!(receive(0,7,&p),-71);
 assert_eq!(receive(0,7,&controller_data(0x1000,0x0133,&[0])),-71);
 assert_eq!(receive(0,7,&controller_data(0xffff,0x0133,&[0])),-71);
}
#[test] fn controller_data_budget_does_not_expand_other_event_or_reply_budgets(){
 let(a,_)=setup();let mut p=controller_data(0,0x0134,&[0;255]);
 p[1]=0x18;assert_eq!(receive(0,7,&p),-71); // unrelated 265-byte event
 p[1]=2;assert_eq!(receive(0,7,&p),-71); // command Complete still bounded
 p[0]=0x55;p[1]=0x14;assert_eq!(receive(0,7,&p),-71);
 assert!(a.commands.borrow().is_empty());
}
#[test] fn controller_data_does_not_resolve_retired_registration(){
 setup();let p=controller_data(0,0x0134,&[0;255]);
 assert_eq!(receive(0,99,&p),-19);assert_eq!(receive(3,7,&p),-19);
}
