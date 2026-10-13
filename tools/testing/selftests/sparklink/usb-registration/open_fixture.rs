// SPDX-License-Identifier: GPL-2.0-only
// Actual Core adoption + USB open/close bodies; Mutex/FFI/route dependencies.
use std::sync::{Arc,Mutex,MutexGuard};
use std::sync::atomic::{AtomicBool,Ordering};
use std::cell::RefCell;
#[derive(Debug,Clone,Copy,Eq,PartialEq)]struct Error(i32);
impl Error{fn from_errno(v:i32)->Self{Self(v)}}
type Result=std::result::Result<(),Error>;
const ENODEV:Error=Error(-19);
macro_rules! pr_info{($($t:tt)*)=>{let _=format_args!($($t)*);}}
macro_rules! pr_warn{($($t:tt)*)=>{let _=format_args!($($t)*);}}
struct Lock<T>(Mutex<T>);impl<T> Lock<T>{fn new(t:T)->Self{Self(Mutex::new(t))}fn lock(&self)->MutexGuard<'_,T>{self.0.lock().unwrap()}}
#[derive(Clone)]struct Identity{id:u16}
#[derive(Clone)]struct UsbDevice;impl UsbDevice{fn as_raw(&self)->i32{7}}
#[derive(Clone)]struct UsbController{device:UsbDevice,identity:Identity}
impl UsbController{
 // @@USB_OPEN@@
 // @@USB_CLOSE@@
}
mod sle_dli{pub enum ControllerBackend{Usb(super::UsbController)}}
struct State{controller:sle_dli::ControllerBackend}
struct ControllerRuntime{identity:Identity,native_lifecycle:Lock<()>,state:Lock<Option<State>>,schedule_gate:Lock<bool>,transport_open:AtomicBool}
impl ControllerRuntime{fn start_workers(&self){assert!(self.transport_open.load(Ordering::Acquire));assert!(self.native_lifecycle.0.try_lock().is_ok());calls("workers");}}
struct Scenario{owner:Option<Arc<ControllerRuntime>>,calls:Vec<&'static str>,evt:i32,data:i32,retire:bool}
thread_local!{static SCENARIO:RefCell<Scenario>=const{RefCell::new(Scenario{owner:None,calls:Vec::new(),evt:0,data:0,retire:false})};}
fn calls(name:&'static str){SCENARIO.with(|s|s.borrow_mut().calls.push(name));}
fn before_io(id:i32){assert_eq!(id,7);SCENARIO.with(|s|{let r=s.borrow();let o=r.owner.as_ref().unwrap();assert!(o.state.0.try_lock().is_ok(),"state mutex spans I/O");assert!(o.native_lifecycle.0.try_lock().is_err(),"lifecycle not held");assert!(!o.transport_open.load(Ordering::Acquire),"open published before listeners succeed");});}
unsafe fn sle_usb_dev_start_evt(id:i32)->i32{before_io(id);calls("evt");SCENARIO.with(|s|s.borrow().evt)}
unsafe fn sle_usb_dev_start_data(id:i32)->i32{before_io(id);calls("data");SCENARIO.with(|s|{let r=s.borrow();if r.retire{*r.owner.as_ref().unwrap().schedule_gate.lock()=true;}r.data})}
unsafe fn sle_usb_dev_stop_evt(id:i32){before_io(id);calls("stop_evt");}
unsafe fn sle_usb_dev_stop_data(id:i32){before_io(id);calls("stop_data");}
mod sle_ingress{use super::*;pub fn publish_runtime(o:&Arc<ControllerRuntime>)->Result{calls("route");if *o.schedule_gate.lock(){Err(ENODEV)}else{Ok(())}}}
// @@CORE_OPEN@@
fn setup(evt:i32,data:i32,retire:bool)->Arc<ControllerRuntime>{let o=Arc::new(ControllerRuntime{identity:Identity{id:7},native_lifecycle:Lock::new(()),state:Lock::new(Some(State{controller:sle_dli::ControllerBackend::Usb(UsbController{device:UsbDevice,identity:Identity{id:7}})})),schedule_gate:Lock::new(false),transport_open:AtomicBool::new(false)});SCENARIO.with(|s|*s.borrow_mut()=Scenario{owner:Some(o.clone()),calls:Vec::new(),evt,data,retire});o}
fn observed()->Vec<&'static str>{SCENARIO.with(|s|s.borrow().calls.clone())}
#[test]fn success_adopts_only_after_both_listeners_and_unlocked_state(){let o=setup(0,0,false);assert_eq!(open_usb_runtime(&o),Ok(()));assert!(o.transport_open.load(Ordering::Acquire));assert_eq!(observed(),["route","evt","data","workers"]);}
#[test]fn first_listener_failure_does_not_start_second_or_publish_open(){let o=setup(-5,0,false);assert_eq!(open_usb_runtime(&o),Err(Error(-5)));assert!(!o.transport_open.load(Ordering::Acquire));assert_eq!(observed(),["route","evt"]);}
#[test]fn second_listener_failure_joins_partial_first(){let o=setup(0,-5,false);assert_eq!(open_usb_runtime(&o),Err(Error(-5)));assert!(!o.transport_open.load(Ordering::Acquire));assert_eq!(observed(),["route","evt","data","stop_evt"]);}
#[test]fn retirement_during_open_closes_both_and_does_not_adopt(){let o=setup(0,0,true);assert_eq!(open_usb_runtime(&o),Err(ENODEV));assert!(!o.transport_open.load(Ordering::Acquire));assert_eq!(observed(),["route","evt","data","stop_evt","stop_data"]);}
#[test]fn retired_before_open_never_touches_resources(){let o=setup(0,0,false);*o.schedule_gate.lock()=true;assert_eq!(open_usb_runtime(&o),Err(ENODEV));assert_eq!(observed(),["route"]);assert!(!o.transport_open.load(Ordering::Acquire));}
#[test]fn absent_state_cannot_announce_success(){let o=setup(0,0,false);*o.state.lock()=None;assert_eq!(open_usb_runtime(&o),Err(ENODEV));assert_eq!(observed(),["route"]);assert!(!o.transport_open.load(Ordering::Acquire));}
