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
pub mod sync {pub use std::rc::Rc as Arc;}
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
fn security_receipt(&mut self,handle:u16)->Option<(u64,u64)>{self.links.security_receipt(handle)}
fn link_snapshot(&self)->(u64,bool,[Option<sle_link_observation::Link>;16]){self.links.snapshot()}}
struct Poll(Cell<usize>);impl Poll{fn notify_all(&self){self.0.set(self.0.get()+1);}}
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
 session_data_pending:AtomicBool,
 rx_schedules:Cell<usize>,
}
impl Owner{fn new(id:u16,generation:u64)->Rc<Self>{Rc::new(Self{
 identity:DeviceIdentity{id,generation},host:Lock::new(Host{grants:{let mut g=sle_grant::LeaseAuthority::new();assert!(g.activate(1,true));g},links:LinkObservation::new(),data_revoked:false,fault:None}),
 data:Lock::new(sle_native_data::NativeData::new(254,5)),data_poll:Poll(Cell::new(0)),sessions:Lock::new([const{None};16]),schedule_gate:Lock::new(false),
 native_lifecycle:Lock::new(()),state:Lock::new(Some(State{controller:sle_dli::ControllerBackend::Native(Dummy{transport:(id as usize+1) as *mut c_void})})),
 transport_open:AtomicBool::new(true),commands:RefCell::new(Vec::new()),
 session_data_pending:AtomicBool::new(false),
 rx_schedules:Cell::new(0),
})}}
impl Owner{fn schedule_rx(&self,delay:u64){assert_eq!(delay,0);self.rx_schedules.set(self.rx_schedules.get()+1);}}
#[derive(Debug)] enum SleEvent{
 CommandCredits{credits:u8},
 NativeCommandReply{opcode:u16,command_credits:u8,status:u8,complete:bool,data:KVec<u8>},
 HardwareError{code:u8},
 NativeControllerData{lifetime:u64,handle:u16,index:u16,data:KVec<u8>},
 // @@SECURITY_INSTALL_EVENT@@
}
thread_local!{
 static OWNERS:RefCell<Vec<Rc<Owner>>>=const{RefCell::new(Vec::new())};
 static PUBLISH_DURING_HINT:Cell<bool>=const{Cell::new(false)};
 static TX:RefCell<Vec<(usize,u16,Vec<u8>)>>=const{RefCell::new(Vec::new())};
 static BEFORE_COMMIT:RefCell<u8>=const{RefCell::new(0)};
 static SUBMIT_CALLS:Cell<usize>=const{Cell::new(0)};
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
 SUBMIT_CALLS.with(|v|v.set(v.get()+1));
 let result=SUBMIT_RESULT.with(|r|*r.borrow());
 if result==0 {TX.with(|t|t.borrow_mut().push((x.p as usize,x.handle,
     unsafe{std::slice::from_raw_parts(x.data,x.n)}.to_vec())));}
 result
}
unsafe fn sparklink_native_transport_acb(p:*mut c_void,ticket:*mut c_void,handle:u16,boundary:u8,data:*const u8,n:usize)->i32{
 assert!(boundary <= 3);
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
// @@DEFERRED_SEND@@
// @@TAKE@@
}
fn setup()->(Rc<Owner>,Rc<Owner>){let a=Owner::new(0,7);let b=Owner::new(1,8);
 PUBLISH_DURING_HINT.with(|v|v.set(false));
 OWNERS.with(|o|*o.borrow_mut()=vec![a.clone(),b.clone()]);TX.with(|t|t.borrow_mut().clear());
 SUBMIT_CALLS.with(|v|v.set(0));
 BEFORE_COMMIT.with(|b|*b.borrow_mut()=0);SUBMIT_RESULT.with(|r|*r.borrow_mut()=0);
 TX_RESULT.with(|r|*r.borrow_mut()=0);EARLY_COMPLETE.with(|e|*e.borrow_mut()=false);NOW.with(|n|*n.borrow_mut()=1);(a,b)}
fn link(owner:&Owner,handle:u16,kind:u32){owner.host.lock().links.observe(&LinkEvidence{kind,status:0,handle:handle as u32,role:1,address_type:0,address:[1;6],reserved:[0;2]});}
fn receive(id:u16,g:u64,bytes:&[u8])->i32{unsafe{under_test::sparklink_native_receive_rust(id,g,bytes.as_ptr(),bytes.len())}}
fn send(id:u16,g:u64,life:u64,handle:u16,bytes:&[u8])->i32{unsafe{under_test::sparklink_native_acb_send_rust(id,g,life,handle,bytes.as_ptr(),bytes.len())}}
fn take(id:u16,g:u64,life:u64,handle:u16,capacity:usize)->(i32,Vec<u8>){let mut out=vec![0;capacity];let mut n=0;let mut security_revision=0;
 let ret=unsafe{under_test::sparklink_native_acb_take_rust(id,g,life,handle,out.as_mut_ptr(),capacity,&mut n,&mut security_revision)};out.truncate(n);(ret,out)}
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
 assert_eq!((a.rx_schedules.get(),b.rx_schedules.get()),(0,0));
 assert_eq!((a.data_poll.0.get(),b.data_poll.0.get()),(0,0));
 assert_eq!(receive(1,8,&acb(0x3000,b"last")),0);
 assert_eq!(receive(0,7,&acb(0x3000,b"last")),0);
 assert_eq!((a.rx_schedules.get(),b.rx_schedules.get()),(1,1));
 assert_eq!((a.data_poll.0.get(),b.data_poll.0.get()),(1,1));
 assert_eq!(take(0,7,1,0,20),(0,b"firstmiddlelast".to_vec()));
 assert_eq!(take(1,8,1,0,20),(0,b"otherlast".to_vec()));
 assert!(a.commands.borrow().is_empty());
}
#[test] fn dropped_or_incomplete_rx_never_notifies_but_later_complete_pdu_does(){
 let(a,b)=setup();link(&a,0,1);link(&b,0,1);
 for packet in [acb(0x3000,b"orphan"),acb(1,b"unknown handle"),acb(0x1000,b"first"),acb(0x2000,b"middle")] {
  assert_eq!(receive(0,7,&packet),0);
 }
 assert_eq!(a.rx_schedules.get(),0);assert_eq!(a.data_poll.0.get(),0);
 assert!(!a.session_data_pending.load(Ordering::Acquire));
 for _ in 0..16 {assert_eq!(receive(0,7,&acb(0,b"queued")),0);}
 assert_eq!(a.rx_schedules.get(),16);assert_eq!(a.data_poll.0.get(),16);
 // A full queue drops a complete PDU without creating a new readiness hint.
 a.session_data_pending.store(false,Ordering::Release);
 assert_eq!(receive(0,7,&acb(0,b"full")),0);
 assert_eq!(a.rx_schedules.get(),16);assert_eq!(a.data_poll.0.get(),16);
 assert!(!a.session_data_pending.load(Ordering::Acquire));
 assert_eq!(take(0,7,1,0,20),(0,b"queued".to_vec()));
 assert_eq!(receive(0,7,&acb(0,b"resumed")),0);
 assert_eq!(a.rx_schedules.get(),17);assert_eq!(a.data_poll.0.get(),17);
 assert_eq!(b.rx_schedules.get(),0);assert_eq!(b.data_poll.0.get(),0);
}
#[test] fn partial_rx_preserves_pending_credit_hint_and_original_expiry(){
 let(a,b)=setup();link(&a,0,1);link(&b,0,1);
 assert_eq!(send(0,7,1,0,b"one debt"),0);
 let polls_before=a.data_poll.0.get(); // TX accounting already notifies poll.
 assert_eq!(receive(0,7,&[0xa2,9,0,3,0,0,0,1]),0);
 assert_eq!(a.rx_schedules.get(),1);assert_eq!(a.data_poll.0.get(),polls_before+1);
 assert!(a.session_data_pending.load(Ordering::Acquire));
 assert_eq!(receive(0,7,&acb(0x1000,b"first")),0);
 NOW.with(|n|*n.borrow_mut()=4_000_000_000);
 assert_eq!(receive(0,7,&acb(0x2000,b"middle")),0);
 assert_eq!(a.rx_schedules.get(),1);assert_eq!(a.data_poll.0.get(),polls_before+1);
 assert!(a.session_data_pending.load(Ordering::Acquire));
 NOW.with(|n|*n.borrow_mut()=5_000_000_002);
 assert_eq!(receive(0,7,&acb(0x3000,b"expired")),0);
 assert_eq!(a.rx_schedules.get(),1);assert_eq!(take(0,7,1,0,100).0,-11);
 assert_eq!(receive(0,7,&acb(0,b"new complete")),0);
 assert_eq!(a.rx_schedules.get(),2);assert_eq!(a.data_poll.0.get(),polls_before+2);
 assert_eq!(take(0,7,1,0,100),(0,b"new complete".to_vec()));
 assert_eq!(b.rx_schedules.get(),0);
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

// Test argument adapter only: no alternative send/credit/transition logic.
unsafe fn test_guarded(id:u16,generation:u64,lifetime:u64,handle:u16,boundary:u8,
 data:*const u8,length:usize,epoch:u64,
 consent:Option<unsafe extern "C" fn(*mut c_void,u64,unsafe extern "C" fn(*mut c_void)->i32,*mut c_void)->i32>,scope:*mut c_void)->i32 {
 let mut wait=0;
 unsafe{under_test::sparklink_native_acb_send_deferred_rust(id,generation,lifetime,handle,boundary,
  data,length,epoch,consent,scope,&mut wait)}
}
struct ConsentScope { live: bool }
unsafe extern "C" fn consent_scope(scope:*mut c_void,_revision:u64,submit:unsafe extern "C" fn(*mut c_void)->i32,context:*mut c_void)->i32 {
 let scope=unsafe{&*scope.cast::<ConsentScope>()};
 if !scope.live {-125} else {unsafe{submit(context)}}
}
#[test] fn actual_guarded_entry_rejects_retired_binding_without_losing_prior_debt(){
 let(a,_)=setup();link(&a,0,1);
 let mut scope=ConsentScope{live:true};
 let bytes=b"guarded";
 let send_guarded=|scope:&mut ConsentScope|unsafe{test_guarded(
  0,7,1,0,0,bytes.as_ptr(),bytes.len(),1,Some(consent_scope),(scope as *mut ConsentScope).cast())};
 assert_eq!(send_guarded(&mut scope),0);
 scope.live=false;
 for _ in 0..32 {assert_eq!(send_guarded(&mut scope),-125);}
 assert_eq!(TX.with(|t|t.borrow().len()),1);
 scope.live=true;
 for _ in 0..4 {assert_eq!(send_guarded(&mut scope),0);}
 assert_eq!(send_guarded(&mut scope),-11);
 assert_eq!(a.data.lock().credits.maximum(),Ok(254));
}

struct FakeSession {refs:usize, stopped:bool, id:u16, generation:u64, lifetime:u64, handle:u16, kicks:usize}
#[no_mangle] unsafe extern "C" fn sl_connection_session_create(id:u16,generation:u64,lifetime:u64,handle:u16,epoch:u64,maximum:u16)->*mut c_void {
 assert!(maximum>5);assert_ne!(epoch,0);Box::into_raw(Box::new(FakeSession{refs:1,stopped:false,id,generation,lifetime,handle,kicks:0})).cast()
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
// C queue/worker is an explicit dependency here, tested by its own extracted
// production body and later in a running VM. This receipt grants no credit.
#[no_mangle] unsafe extern "C" fn sl_connection_session_kick(p:*mut c_void){unsafe{
 let s=&mut *p.cast::<FakeSession>();assert!(s.refs>1&&!s.stopped);
 let owner=sle_ingress::ingress_owner(DeviceIdentity{id:s.id,generation:s.generation}).unwrap();
 assert!(owner.sessions.0.try_borrow_mut().is_ok());
 assert!(owner.host.0.try_borrow_mut().is_ok());
 assert!(owner.data.0.try_borrow_mut().is_ok());
 assert!(owner.schedule_gate.0.try_borrow_mut().is_ok());
 s.kicks+=1;
 // Controlled model counterexample boundary: new producer after the actual
 // AtomicBool swap/target snapshot, before the notification callback returns.
 if PUBLISH_DURING_HINT.with(|v|v.replace(false)) {
  assert_eq!(receive(owner.identity.id,owner.identity.generation,&acb(s.handle,&[2])),0);
 }
}}
#[test] fn actual_runtime_data_hint_coalesces_after_unlock_without_peer_or_stale_grants(){
 let(a,b)=setup();link(&a,0,1);link(&b,0,1);let(p,_)=session(0,7,1,0);let(q,_)=session(1,8,1,0);
 a.notify_session_data();unsafe{assert_eq!((*p.cast::<FakeSession>()).kicks,0);}
 assert_eq!(receive(0,6,&acb(0,&[1])),-19);assert!(!a.session_data_pending.load(Ordering::Acquire));
 assert_eq!(receive(0,7,&acb(0,&[1])),0);
 assert_eq!(receive(0,7,&[0xa2,9,0,3,0,0,0,0]),0);
 assert!(a.session_data_pending.load(Ordering::Acquire));
 PUBLISH_DURING_HINT.with(|v|v.set(true));
 a.notify_session_data();assert!(a.session_data_pending.load(Ordering::Acquire));
 unsafe{assert_eq!((*p.cast::<FakeSession>()).kicks,1);assert_eq!((*p.cast::<FakeSession>()).refs,2);assert_eq!((*q.cast::<FakeSession>()).kicks,0);}
 assert_eq!(a.rx_schedules.get(),3); // actual RX/NOCP/injected-RX all request Runtime work
 a.notify_session_data();assert!(!a.session_data_pending.load(Ordering::Acquire));
 unsafe{assert_eq!((*p.cast::<FakeSession>()).kicks,2);assert_eq!((*p.cast::<FakeSession>()).refs,2);}
 assert_eq!(take(0,7,1,0,1),(0,vec![1])); // hint did not steal RX
 assert_eq!(take(0,7,1,0,1),(0,vec![2]));
 {a.host.lock().grants.revoke();}a.reconcile_sessions();
 a.kick_session_data();a.notify_session_data();
 unsafe{assert!((*p.cast::<FakeSession>()).stopped);assert_eq!((*p.cast::<FakeSession>()).kicks,2);}
 a.stop_sessions(-19);b.stop_sessions(-19);unsafe{sl_connection_session_put(p);sl_connection_session_put(q);}
}
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
 a.host.lock().grants.revoke();a.reconcile_sessions();assert_eq!(a.sessions.lock().iter().flatten().count(),1);
 link(&a,0,2);a.reconcile_sessions();assert!(a.sessions.lock().iter().all(Option::is_none));
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
 let guarded=|epoch|unsafe{test_guarded(0,7,1,0,0,bytes.as_ptr(),bytes.len(),epoch,Some(consent_scope),(&mut scope as *mut ConsentScope).cast())};
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

unsafe extern "C" fn actual_admission_callback(context:*mut c_void,_revision:u64)->i32 {
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

#[test]
fn actual_fragment_entry_uses_individual_credit_and_rejects_invalid_pb() {
 let (a, _b)=setup();link(&a,0,1);
 let mut scope=ConsentScope{live:true};
 let bytes=[0x5a;254];
 let call=|pb, scope:&mut ConsentScope|unsafe{
  test_guarded(0,7,1,0,pb,
    bytes.as_ptr(),bytes.len(),1,Some(consent_scope),(scope as *mut ConsentScope).cast())
 };
 assert_eq!(call(4,&mut scope),-22);
 assert!(TX.with(|t|t.borrow().is_empty()));
 for pb in [1,2,2,2,2] {assert_eq!(call(pb,&mut scope),0);}
 assert_eq!(call(3,&mut scope),-11);
 assert_eq!(receive(0,7,&[0xa2,9,0,3,0,0,0,2]),0);
 assert_eq!(call(3,&mut scope),0);
 scope.live=false;
 assert_eq!(call(1,&mut scope),-125);
 assert_eq!(TX.with(|t|t.borrow().len()),6);
 a.host.lock().grants.revoke();
 assert_eq!(call(3,&mut scope),-13);
}

unsafe extern "C" fn actual_inspection_callback(value:*const sle_data_credit::CreditSnapshot,_revision:u64,context:*mut c_void)->i32 {
 let snapshot=unsafe{&*value};let count=unsafe{&mut *context.cast::<usize>()};
 let owner=OWNERS.with(|o|o.borrow()[0].clone());
 assert!(owner.host.0.try_borrow_mut().is_err()&&owner.data.0.try_borrow_mut().is_err()&&owner.schedule_gate.0.try_borrow_mut().is_err());
 assert_eq!((snapshot.capacity,snapshot.outstanding,snapshot.connection_debt,snapshot.peak_reserved),(5,1,1,1));
 *count+=1;0
}
#[test] fn actual_credit_observation_is_locked_current_authority_and_never_refills() {
 let(a,_)=setup();link(&a,0,1);assert_eq!(send(0,7,1,0,b"observed"),0);let mut count=0usize;
 let inspect=|epoch,count:&mut usize|unsafe{sle_sessions::sparklink_native_session_inspect_rust(0,7,1,0,epoch,Some(actual_inspection_callback),(count as *mut usize).cast())};
 assert_eq!(inspect(1,&mut count),0);assert_eq!(inspect(1,&mut count),0);assert_eq!(count,2);
 a.host.lock().grants.revoke();assert_eq!(inspect(1,&mut count),-13);assert_eq!(count,2);
 assert_eq!(a.data.lock().credits.snapshot(1,0).outstanding,1);
}

fn security_event(event:u16,body:&[u8])->Vec<u8>{let mut v=vec![0xa2,event as u8,(event>>8)as u8,body.len()as u8,0];v.extend_from_slice(body);v}
#[test] fn installation_event_ingress_freezes_exact_physical_lifetime_without_qualification(){
 let(a,b)=setup();link(&a,0,1);link(&b,0,1);
 assert_eq!(receive(0,7,&security_event(0xe,&[0,0])),0);
 assert_eq!(receive(0,7,&security_event(0x11,&[0,0,0,1])),0);
 link(&a,0,2);link(&a,0,1);
 assert_eq!(receive(0,7,&security_event(0x11,&[1,0,0,255])),0); // status/value stay opaque here
 let events=a.commands.borrow();assert_eq!(events.len(),3);assert!(b.commands.borrow().is_empty());
 for (n,e) in events.iter().enumerate(){match e{SleEvent::NativeSecurityInstallation{lifetime,security_revision,handle,event,status,enabled}=>{
  assert_eq!((*lifetime,*handle),(if n==2{3}else{1},0));
  assert_eq!(*security_revision,if n==1 {3}else{2});
  assert_eq!((*event,*status,*enabled),if n==0{(0xe,0,0)}else if n==1{(0x11,0,1)}else{(0x11,1,255)});
 },_=>panic!("wrong metadata variant")}}
}
#[test] fn installation_event_malformed_foreign_or_unmanaged_cannot_become_receipt(){
 let(a,_)=setup();link(&a,0,1);
 for (event,body) in [(0xe,&[0,0][..]),(0x11,&[0,0,0,1][..])]{
  let packet=security_event(event,body);
  for cut in 0..packet.len(){assert_eq!(receive(0,7,&packet[..cut]),-71);}
  let mut extra=packet.clone();extra.push(0);extra[3]+=1;assert_eq!(receive(0,7,&extra),-71);
  assert_eq!(receive(0,8,&packet),-19);
 }
 assert_eq!(receive(0,7,&security_event(0xe,&[1,0])),-116);
 assert_eq!(receive(0,7,&security_event(0x11,&[0,0,0x10,1])),-71);
 {let mut h=a.host.lock();h.grants.revoke();h.data_revoked=true;}assert_eq!(receive(0,7,&security_event(0x11,&[0,0,0,1])),0);
 assert_eq!(a.commands.borrow().len(),1); // Metadata survives revoke; it is not data/credential admission.
}

#[test] fn revoked_physical_session_keeps_one_owner_until_real_down_and_cannot_be_replaced_by_new_epoch(){
 let(a,b)=setup();link(&a,0,1);link(&b,0,1);b.reconcile_sessions();
 let(peer,_)=b.existing_session_for_event(1,0).unwrap();
 let(p,_)=session(0,7,1,0);
 {let mut h=a.host.lock();h.grants.revoke();assert!(h.grants.activate(2,true));}
 a.reconcile_sessions();
 assert_eq!(a.sessions.lock().iter().flatten().count(),1);
 let(q,epoch)=a.existing_session_for_event(1,0).unwrap();assert_eq!(q,p);assert_eq!(epoch,1);
 unsafe{assert!((*p.cast::<FakeSession>()).stopped);sl_connection_session_put(q);}
 let mut error=0;let new=unsafe{sle_sessions::sparklink_native_session_get_rust(0,7,1,0,2,&mut error)};
 assert!(new.is_null());assert_eq!(error,-116);assert_eq!(a.sessions.lock().iter().flatten().count(),1);
 link(&a,0,2);a.reconcile_sessions();assert!(a.existing_session_for_event(1,0).is_none());
 assert_eq!(a.sessions.lock().iter().flatten().count(),0);
 unsafe{sl_connection_session_put(p);}
 assert_eq!(b.sessions.lock().iter().flatten().count(),1);
 let(peer_after,_)=b.existing_session_for_event(1,0).unwrap();assert_eq!(peer,peer_after);
 unsafe{assert!(!(*peer.cast::<FakeSession>()).stopped);sl_connection_session_put(peer);sl_connection_session_put(peer_after);}
 b.stop_sessions(-19);
}

// Seeded stateful exploration through the actual production ingress/commit,
// authority and ledger. Dependency fixtures above remain explicit: this is
// neither exhaustive proof nor a claim about NOCP hardware attribution.
fn sequence_credit(owner:&Owner)->(u16,u16,u16,u64) {
 let data=owner.data.lock();let snapshot=data.credits.snapshot(1,0);
 let sum:u16=(1..=65).map(|lifetime|data.credits.snapshot(lifetime,0).connection_debt).sum();
 assert_eq!(sum,snapshot.outstanding,"retained old debt must still account for outstanding");
 assert!(snapshot.outstanding<=snapshot.capacity && snapshot.peak_reserved<=snapshot.capacity);
 assert!(snapshot.outstanding<=snapshot.peak_reserved);
 (snapshot.outstanding,sum,snapshot.peak_reserved,snapshot.pool_exhaustions)
}
fn sequence_send(owner:&Owner,scope:&mut ConsentScope,generation:u64,lifetime:u64,epoch:u64)->i32 {
 let bytes=b"sequence";
 let before=TX.with(|v|v.borrow().len());
 let eligible={let host=owner.host.lock();let(_,known,links)=host.link_snapshot();
  generation==owner.identity.generation && known && host.admits_data() && host.grants.permits(epoch)
   && links.iter().flatten().any(|link|link.handle==0 && link.lifetime==lifetime)
   && !*owner.schedule_gate.lock() && owner.transport_open.load(Ordering::Acquire) && scope.live};
 let result=unsafe{test_guarded(owner.identity.id,generation,lifetime,0,0,
   bytes.as_ptr(),bytes.len(),epoch,Some(consent_scope),(scope as *mut ConsentScope).cast())};
 let after=TX.with(|v|v.borrow().len());
 assert!(after==before || after==before+1);
 if after!=before {assert!(eligible,"no new physical submit from revoked/stale/cancelled admission");}
 result
}
#[test] fn actual_seeded_submission_revocation_completion_sequences() {
 const SEED:u64=0x730111;
 let mut counts=[0usize;16];let mut accepted=0usize;let mut refused=0usize;
 let mut failure_attempts=0usize;let mut atomic_rejections=0usize;let mut uncertain=0usize;
 for case in 0..1024u64 {
  let(a,b)=setup();link(&a,0,1);link(&b,0,1);
  let mut scope=ConsentScope{live:true};let mut peer=ConsentScope{live:true};
  assert_eq!(sequence_send(&a,&mut scope,7,1,1),0); // valid physical obligation first
  let mut random=SEED^case.wrapping_mul(0x9e3779b97f4a7c15);let mut trace=Vec::new();
  for _ in 0..32 {
   random^=random<<13;random^=random>>7;random^=random<<17;
   let operation=(random&15) as usize;counts[operation]+=1;trace.push(operation);
   let checked=std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
   let old=sequence_credit(&a);let peer_before=sequence_credit(&b);
   match operation {
    0=>{if sequence_send(&a,&mut scope,7,1,1)==0{accepted+=1;}else{refused+=1;}},
    1=>a.host.lock().grants.revoke(),
    2=>{a.host.lock().grants.activate(2,true);},
    3=>link(&a,0,2),
    4=>link(&a,0,1),
    5=>{receive(0,7,&[0xa2,9,0,3,0,0,0,1]);},
    6=>{let calls=SUBMIT_CALLS.with(Cell::get);SUBMIT_RESULT.with(|v|*v.borrow_mut()=-12);
      sequence_send(&a,&mut scope,7,1,1);SUBMIT_RESULT.with(|v|*v.borrow_mut()=0);
      assert_eq!(sequence_credit(&a).0,old.0,"never-queued failure cannot pay old debt: {trace:?}");
      failure_attempts+=1;atomic_rejections+=SUBMIT_CALLS.with(Cell::get)-calls;},
    7=>{TX_RESULT.with(|v|*v.borrow_mut()=-110);
      let submitted=TX.with(|v|v.borrow().len());sequence_send(&a,&mut scope,7,1,1);
      TX_RESULT.with(|v|*v.borrow_mut()=0);
      if TX.with(|v|v.borrow().len())!=submitted {
       assert_eq!(sequence_credit(&a).0,old.0+1,"uncertain failure retains physical debt: {trace:?}");
       assert_eq!(a.data.lock().credits.maximum(),Err(sle_data_credit::CreditError::Fault));uncertain+=1;
      }},
    8=>scope.live=false, // author withdrawal is one-way for this binding
    9=>{assert_eq!(sequence_send(&a,&mut scope,6,1,1),-19);},
    10=>a.transport_open.store(false,Ordering::Release),
    11=>*a.schedule_gate.lock()=true,
    12=>{let mut mode=((random>>8)%5) as u8;
      mode=[1,2,3,4,7][mode as usize];
      if mode==7 && !a.host.lock().grants.accepts(2){mode=2;}
      BEFORE_COMMIT.with(|v|*v.borrow_mut()=mode);
      sequence_send(&a,&mut scope,7,1,1);BEFORE_COMMIT.with(|v|*v.borrow_mut()=0);},
    13=>{let(epoch,lifetime)={let host=a.host.lock();let(_,_,links)=host.link_snapshot();
      (host.grants.current_epoch().unwrap_or(0),links.iter().flatten().next().map_or(0,|link|link.lifetime))};
      if sequence_send(&a,&mut scope,7,lifetime,epoch)==0{accepted+=1;}else{refused+=1;}},
    14=>{sequence_send(&b,&mut peer,8,1,1);},
    15=>{receive(0,7,&[0xa2,2,0,3,0,0,0,4]);
      assert_eq!(sequence_credit(&a),old,"command credit cannot refill data: {trace:?}");},
    _=>unreachable!(),
   }
   let after=sequence_credit(&a);assert!(after.2>=old.2 && after.3>=old.3,"generation counters monotonic: {trace:?}");
   if ![0,5,6,7,12,13].contains(&operation){assert_eq!(after.0,old.0,"non-data transition erased debt: {trace:?}");}
   if operation!=14{assert_eq!(sequence_credit(&b),peer_before,"cross-controller mutation: {trace:?}");}
   }));
   if let Err(error)=checked {
    let message=error.downcast_ref::<String>().map(String::as_str).or_else(||error.downcast_ref::<&str>().copied()).unwrap_or("non-string panic");
    panic!("sequence failure seed={SEED} case={case} operations={trace:?}: {message}");
   }
  }
 }
 assert!(counts.iter().all(|count|*count>1000));assert!(accepted>0 && refused>0 && uncertain>0 && atomic_rejections>0);
 println!("ACTUAL_NATIVE_SEQUENCE_FUZZ seed={SEED} cases=1024 events=32768 primed=1024 accepted={accepted} refused={refused} failure_attempts={failure_attempts} atomic_rejections={atomic_rejections} uncertain={uncertain}");
}

#[test] fn actual_deferred_reason_distinguishes_full_pool_from_transport_retry() {
 let(a,_)=setup();link(&a,0,1);let mut scope=ConsentScope{live:true};let mut wait=99;
 let bytes=b"classified";
 let call=|wait:&mut u32,scope:&mut ConsentScope|unsafe{
  under_test::sparklink_native_acb_send_deferred_rust(0,7,1,0,0,bytes.as_ptr(),bytes.len(),1,
   Some(consent_scope),(scope as *mut ConsentScope).cast(),wait)};
 SUBMIT_RESULT.with(|r|*r.borrow_mut()=-11);
 assert_eq!(call(&mut wait,&mut scope),-11);assert_eq!(wait,2);
 assert_eq!(a.data.lock().credits.snapshot(1,0).outstanding,0);
 SUBMIT_RESULT.with(|r|*r.borrow_mut()=0);
 for _ in 0..5 {assert_eq!(call(&mut wait,&mut scope),0);assert_eq!(wait,0);}
 assert_eq!(call(&mut wait,&mut scope),-11);assert_eq!(wait,1);
 // Only the real production NOCP transition makes progress possible here.
 assert_eq!(receive(0,7,&[0xa2,9,0,3,0,0,0,1]),0);
 assert_eq!(call(&mut wait,&mut scope),0);assert_eq!(wait,0);
}
#[test] fn actual_deferred_reason_does_not_hide_uncertain_or_precheck_failure() {
 let(a,_)=setup();link(&a,0,1);let mut scope=ConsentScope{live:true};let mut wait=99;
 let bytes=b"uncertain";
 let call=|wait:&mut u32,scope:&mut ConsentScope|unsafe{
  under_test::sparklink_native_acb_send_deferred_rust(0,7,1,0,0,bytes.as_ptr(),bytes.len(),1,
   Some(consent_scope),(scope as *mut ConsentScope).cast(),wait)};
 a.transport_open.store(false,Ordering::Release);
 assert_eq!(call(&mut wait,&mut scope),-11);assert_eq!(wait,2);
 a.transport_open.store(true,Ordering::Release);
 TX_RESULT.with(|r|*r.borrow_mut()=-11);
 assert_eq!(call(&mut wait,&mut scope),-11);assert_eq!(wait,2);
 assert_eq!(a.data.lock().credits.snapshot(1,0).outstanding,1);
 assert_eq!(call(&mut wait,&mut scope),-5); // uncertain debt never refunded
}

#[test] fn security_barrier_is_visible_before_queued_receipt_processing_or_loss() {
 let(a,b)=setup();link(&a,0,1);link(&b,0,1);
 let before=a.host.lock().link_snapshot().2[0].unwrap().security_revision;
 assert_eq!(before,1);
 assert_eq!(receive(0,7,&security_event(0x11,&[0,0,0,0])),0);
 // Fixture deliberately discards the ordinary queued event. The actual
 // production IRQ ingress has already invalidated the previous revision.
 a.commands.borrow_mut().clear();
 assert_eq!(a.host.lock().link_snapshot().2[0].unwrap().security_revision,2);
 assert_eq!(b.host.lock().link_snapshot().2[0].unwrap().security_revision,1);
}

#[test] fn acb_security_revision_is_frozen_before_take_and_never_crosses_pb_reassembly() {
 let(a,_)=setup();link(&a,0,1);
 assert_eq!(receive(0,7,&acb(0,b"old")),0);
 assert_eq!(receive(0,7,&security_event(0x11,&[0,0,0,1])),0);
 let mut out=[0;64];let mut n=0;let mut revision=0;
 assert_eq!(unsafe{under_test::sparklink_native_acb_take_rust(0,7,1,0,out.as_mut_ptr(),64,&mut n,&mut revision)},0);
 assert_eq!((revision,&out[..n]),(1,&b"old"[..]));
 assert_eq!(receive(0,7,&acb(0x1000,b"prefix")),0);
 assert_eq!(receive(0,7,&security_event(0x11,&[0,0,0,0])),0);
 assert_eq!(receive(0,7,&acb(0x3000,b"old continuation")),0);
 assert_eq!(take(0,7,1,0,64).0,-11);
 assert_eq!(a.data.lock().dropped,1);
 assert_eq!(receive(0,7,&acb(0,b"current")),0);
 assert_eq!(unsafe{under_test::sparklink_native_acb_take_rust(0,7,1,0,out.as_mut_ptr(),64,&mut n,&mut revision)},0);
 assert_eq!((revision,&out[..n]),(3,&b"current"[..]));
}
struct RevisionReceipt { observed:u64, result:i32 }
unsafe extern "C" fn revision_consent(scope:*mut c_void,revision:u64,submit:unsafe extern "C" fn(*mut c_void)->i32,context:*mut c_void)->i32 {
 let scope=unsafe{&mut *scope.cast::<RevisionReceipt>()};scope.observed=revision;
 if scope.result!=0 {scope.result} else {unsafe{submit(context)}}
}
#[test] fn actual_atomic_submit_supplies_current_receipt_and_rejection_keeps_prior_credit() {
 let(a,_)=setup();link(&a,0,1);let bytes=b"prepared";
 let mut scope=RevisionReceipt{observed:0,result:0};
 assert_eq!(unsafe{test_guarded(0,7,1,0,0,bytes.as_ptr(),bytes.len(),1,Some(revision_consent),(&mut scope as *mut RevisionReceipt).cast())},0);
 assert_eq!(scope.observed,1);
 a.host.lock().security_receipt(0).unwrap();scope.result=-13;
 assert_eq!(unsafe{test_guarded(0,7,1,0,0,bytes.as_ptr(),bytes.len(),1,Some(revision_consent),(&mut scope as *mut RevisionReceipt).cast())},-13);
 assert_eq!(scope.observed,2);
 assert_eq!(a.data.lock().credits.snapshot(1,0).outstanding,1);
 assert_eq!(TX.with(|t|t.borrow().len()),1);
}
