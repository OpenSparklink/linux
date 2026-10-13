// SPDX-License-Identifier: GPL-2.0-only
// Actual reserve/install/cancel/retire bodies. Runtime allocation, locks and
// candidate destruction are instrumented dependencies, not kernel callbacks.
use std::sync::{Arc,Mutex,MutexGuard};
use std::sync::atomic::{AtomicU32,Ordering};
use std::cell::Cell;
type Result<T=()>=std::result::Result<T,i32>;
const ENOSPC:i32=-28;const ENODEV:i32=-19;const EINVAL:i32=-22;const EBUSY:i32=-16;const ENOMEM:i32=-12;
type KBox<T>=Box<T>;
macro_rules! pr_info{($($arg:tt)*)=>{let _=format_args!($($arg)*);}}
#[derive(Clone,Copy,Debug,Default,PartialEq,Eq)]pub enum SleBus{#[default]None=0,Usb=4,Test=6}
#[derive(Default)]struct SleDevStats;
mod sle_dli{pub use super::SleBus;
 // @@INFO@@
 impl Default for SleControllerInfo{// @@INFO_DEFAULT@@
 }
}
use sle_dli::SleControllerInfo;
// @@CONSTANTS@@
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
// @@IDENTITY@@
// @@DEVICE@@
impl SleDev{
 // @@DEV_NEW@@
 // @@DEV_IDENTITY@@
 // @@DEV_BUS@@
 // @@DEV_NAME@@
 // @@DEV_ADDR@@
 // @@DEV_UPDATE@@
 // @@BEGIN_UNREGISTER@@
 // @@TEST_FLAG@@
}
// @@REGISTRY@@
impl SleDevRegistry{
 // @@REG_NEW@@
 // @@REGISTER_PENDING@@
 // @@GET@@
 // @@GET_MUT@@
 // @@UNREGISTER@@
 // @@REG_UPDATE@@
}
mod sle_dev{pub(crate) use super::{DeviceIdentity,SLE_DEV_UNREGISTERING};}
struct Shared{dev_registry:SleDevRegistry,runtimes:[Option<Arc<ControllerRuntime>>;SLE_DEV_MAX],active_dev_id:Option<u16>}
impl Shared{
 fn new()->Self{Self{dev_registry:SleDevRegistry::new(),runtimes:std::array::from_fn(|_|None),active_dev_id:None}}
 fn runtime(&self,id:u16)->Option<Arc<ControllerRuntime>>{self.runtimes.get(id as usize).and_then(Clone::clone)}
}
struct Lock<T>(Mutex<T>);impl<T> Lock<T>{fn lock(&self)->MutexGuard<'_,T>{self.0.lock().unwrap()}}
static SUBSYSTEM:Lock<Option<Shared>>=Lock(Mutex::new(None));
#[derive(Clone,Copy)]
// @@REGISTRATION@@
// @@RESERVE@@
// @@INSTALL@@
// @@CANCEL@@
// @@DETACH@@
thread_local!{static HOOK:Cell<u8>=const{Cell::new(0)};}
static CONSTRUCTIONS:AtomicU32=AtomicU32::new(0);
static DROPS:AtomicU32=AtomicU32::new(0);
struct ControllerState;
impl Drop for ControllerState{
 fn drop(&mut self){assert!(SUBSYSTEM.0.try_lock().is_ok(),"state/driver destructor under registry lock");DROPS.fetch_add(1,Ordering::Relaxed);}
}
struct ControllerRuntime{identity:DeviceIdentity,registration:RuntimeRegistration,_state:KBox<ControllerState>}
impl ControllerRuntime{
 fn new(registration:RuntimeRegistration,state:KBox<ControllerState>)->Result<Arc<Self>>{
  assert!(SUBSYSTEM.0.try_lock().is_ok(),"allocation/callback dependency under registry lock");
  CONSTRUCTIONS.fetch_add(1,Ordering::Relaxed);
  match HOOK.with(|h|h.replace(0)){
   1=>return Err(ENOMEM),
   2=>sle_detach_device(registration.identity),
   3=>{sle_detach_device(registration.identity);reserve_backend_identity(&SleControllerInfo::default()).unwrap();},
   4=>{let peer=Self::new(registration,Box::new(ControllerState)).unwrap();SUBSYSTEM.lock().as_mut().unwrap().runtimes[registration.identity.id as usize]=Some(peer);},
   5=>{let prior=SUBSYSTEM.lock().take();drop(prior);},
   6=>{SUBSYSTEM.lock().as_ref().unwrap().dev_registry.get(registration.identity.id).unwrap().begin_unregister();},
   _=>(),
  }
  Ok(Arc::new(Self{identity:registration.identity,registration,_state:state}))
 }
 fn invalidate(&self){assert!(SUBSYSTEM.0.try_lock().is_ok());}
}
fn setup()->DeviceIdentity{
 let old={let mut s=SUBSYSTEM.lock();let old=s.take();*s=Some(Shared::new());old};drop(old);
 CONSTRUCTIONS.store(0,Ordering::Relaxed);DROPS.store(0,Ordering::Relaxed);HOOK.with(|h|h.set(0));
 let info=SleControllerInfo::default();
 assert_eq!(info.name,[0;32]);
 assert_eq!((info.features_ext,info.max_pdu_payload,info.max_mtu,info.max_mps,info.transport_modes,info.measurement_cap,info.security_cap),(0,0,0,0,0,0,0));
 reserve_backend_identity(&info).unwrap()
}
fn install(id:DeviceIdentity,hook:u8,select:bool)->Result<Arc<ControllerRuntime>>{
 HOOK.with(|h|h.set(hook));install_backend_runtime(id,Box::new(ControllerState),select,Some(([9;6],77)))
}
fn failed(r:Result<Arc<ControllerRuntime>>,e:i32){assert!(matches!(r,Err(n) if n==e));}
#[test]fn candidate_allocation_and_drop_outside_registry(){let id=setup();failed(install(id,1,true),ENOMEM);assert_eq!(DROPS.load(Ordering::Relaxed),1);let s=SUBSYSTEM.lock();assert!(s.as_ref().unwrap().runtime(id.id).is_none());assert_eq!(s.as_ref().unwrap().active_dev_id,None);}
#[test]fn successful_candidate_publishes_exact_identity_queried_metadata_and_selection(){
 let id=setup();let o=install(id,0,true).unwrap();assert_eq!(o.identity,id);assert_eq!(o.registration.addr,[9;6]);assert_eq!(o.registration.bus,SleBus::None);assert!(o.registration.name.starts_with(b"sle0\0"));
 let s=SUBSYSTEM.lock();let d=s.as_ref().unwrap().dev_registry.get(id.id).unwrap();assert_eq!((d.addr,d.fw_version),([9;6],77));assert_eq!((d.features,d.max_connections),(0,0));assert_eq!(s.as_ref().unwrap().active_dev_id,Some(id.id));assert_eq!(d.flags.load(Ordering::Acquire),SLE_DEV_SETUP);let _=&d.stats;
}
#[test]fn successful_unselected_native_candidate_keeps_peer_selection(){
 let id=setup();let peer=reserve_backend_identity(&SleControllerInfo{bus:SleBus::Test,addr:[3;6],..Default::default()}).unwrap();let p=install_backend_runtime(peer,Box::new(ControllerState),true,None).unwrap();let o=install(id,0,false).unwrap();assert_eq!(o.identity,id);assert_eq!(p.registration.bus,SleBus::Test);assert_eq!(p.registration.addr,[3;6]);assert_eq!(SUBSYSTEM.lock().as_ref().unwrap().active_dev_id,Some(peer.id));
}
#[test]fn retire_during_candidate_construction_rejects_publication(){let id=setup();failed(install(id,2,true),ENODEV);assert_eq!(DROPS.load(Ordering::Relaxed),1);assert!(SUBSYSTEM.lock().as_ref().unwrap().dev_registry.get(id.id).is_none());}
#[test]fn reuse_during_construction_preserves_new_generation(){let id=setup();failed(install(id,3,true),ENODEV);cancel_backend_reservation(id);let s=SUBSYSTEM.lock();let d=s.as_ref().unwrap().dev_registry.get(id.id).unwrap();assert_ne!(d.identity(),id);assert_eq!(d.addr,[0;6]);assert_eq!(s.as_ref().unwrap().active_dev_id,None);}
#[test]fn competing_installer_is_not_replaced_and_failed_candidate_metadata_not_published(){let id=setup();failed(install(id,4,true),EBUSY);let s=SUBSYSTEM.lock();assert!(s.as_ref().unwrap().runtime(id.id).is_some());assert_eq!(s.as_ref().unwrap().dev_registry.get(id.id).unwrap().addr,[0;6]);assert_eq!(s.as_ref().unwrap().active_dev_id,None);}
#[test]fn subsystem_removal_during_construction_drops_candidate_outside_lock(){let id=setup();failed(install(id,5,true),ENODEV);assert_eq!(DROPS.load(Ordering::Relaxed),1);assert!(SUBSYSTEM.lock().is_none());}
#[test]fn retiring_identity_is_not_published_or_cancelled(){let id=setup();failed(install(id,6,true),ENODEV);cancel_backend_reservation(id);assert!(SUBSYSTEM.lock().as_ref().unwrap().dev_registry.get(id.id).unwrap().test_flag(SLE_DEV_UNREGISTERING));}
#[test]fn stale_and_busy_prechecks_do_not_allocate_or_drop_under_lock(){let id=setup();failed(install(DeviceIdentity{id:id.id,generation:id.generation+1},0,true),ENODEV);assert_eq!(CONSTRUCTIONS.load(Ordering::Relaxed),0);let o=install(id,0,false).unwrap();failed(install(id,0,true),EBUSY);assert_eq!(CONSTRUCTIONS.load(Ordering::Relaxed),1);assert_eq!(o.identity,id);}
#[test]fn construction_failure_cancellation_preserves_other_owner(){let id=setup();let peer=reserve_backend_identity(&SleControllerInfo::default()).unwrap();let p=install(peer,0,true).unwrap();failed(install(id,1,false),ENOMEM);cancel_backend_reservation(id);let s=SUBSYSTEM.lock();assert!(s.as_ref().unwrap().dev_registry.get(id.id).is_none());assert!(Arc::ptr_eq(&p,&s.as_ref().unwrap().runtime(peer.id).unwrap()));assert_eq!(s.as_ref().unwrap().active_dev_id,Some(peer.id));}
