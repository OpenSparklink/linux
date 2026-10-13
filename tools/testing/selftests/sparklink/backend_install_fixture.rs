// SPDX-License-Identifier: GPL-2.0-only
// Actual reserve/install/cancel/retire bodies. Runtime allocation, locks and
// candidate destruction are instrumented dependencies, not kernel callbacks.
use std::sync::{Arc,Mutex,MutexGuard};
use std::sync::atomic::{AtomicU32,Ordering};
use std::cell::Cell;
type Result<T=()>=std::result::Result<T,i32>;
const ENOSPC:i32=-28;const ENODEV:i32=-19;const EINVAL:i32=-22;const EBUSY:i32=-16;const ENOMEM:i32=-12;
const EIO:i32=-5;
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
struct Shared{dev_registry:SleDevRegistry,runtimes:[Option<Arc<ControllerRuntime>>;SLE_DEV_MAX]}
impl Shared{
 fn new()->Self{Self{dev_registry:SleDevRegistry::new(),runtimes:std::array::from_fn(|_|None)}}
 fn runtime(&self,id:u16)->Option<Arc<ControllerRuntime>>{self.runtimes.get(id as usize).and_then(Clone::clone)}
}
struct Lock<T>(Mutex<T>);impl<T> Lock<T>{fn lock(&self)->MutexGuard<'_,T>{self.0.lock().unwrap()}}
static SUBSYSTEM:Lock<Option<Shared>>=Lock(Mutex::new(None));
#[derive(Clone,Copy)]
// @@REGISTRATION@@
// @@RESERVE_PROFILE@@
// @@VALIDATE@@
// @@UPDATE_PENDING@@
// @@QUERY_PENDING@@
#[derive(Debug)]
// @@SNAPSHOT_TYPE@@
// @@SNAPSHOT_CONSTANTS@@
// @@SNAPSHOT@@
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
struct ControllerRuntime{identity:DeviceIdentity,registration:RuntimeRegistration,_state:KBox<ControllerState>,bootstrap_credits:u8}
impl ControllerRuntime{
 fn new(registration:RuntimeRegistration,state:KBox<ControllerState>,bootstrap_credits:u8)->Result<Arc<Self>>{
  assert!(SUBSYSTEM.0.try_lock().is_ok(),"allocation/callback dependency under registry lock");
  CONSTRUCTIONS.fetch_add(1,Ordering::Relaxed);
  match HOOK.with(|h|h.replace(0)){
   1=>return Err(ENOMEM),
   2=>sle_detach_device(registration.identity),
   3=>{sle_detach_device(registration.identity);reserve_backend_identity(&SleControllerInfo::default()).unwrap();},
   4=>{let peer=Self::new(registration,Box::new(ControllerState),bootstrap_credits).unwrap();SUBSYSTEM.lock().as_mut().unwrap().runtimes[registration.identity.id as usize]=Some(peer);},
   5=>{let prior=SUBSYSTEM.lock().take();drop(prior);},
   6=>{SUBSYSTEM.lock().as_ref().unwrap().dev_registry.get(registration.identity.id).unwrap().begin_unregister();},
   _=>(),
  }
  Ok(Arc::new(Self{identity:registration.identity,registration,_state:state,bootstrap_credits}))
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
fn install(id:DeviceIdentity,hook:u8)->Result<Arc<ControllerRuntime>>{
 HOOK.with(|h|h.set(hook));install_backend_runtime(id,Box::new(ControllerState),1,Some(([9;6],77)))
}
fn failed(r:Result<Arc<ControllerRuntime>>,e:i32){assert!(matches!(r,Err(n) if n==e));}
#[test]fn candidate_allocation_and_drop_outside_registry(){let id=setup();failed(install(id,1),ENOMEM);assert_eq!(DROPS.load(Ordering::Relaxed),1);let s=SUBSYSTEM.lock();assert!(s.as_ref().unwrap().runtime(id.id).is_none());}
#[test]fn successful_candidate_publishes_exact_identity_queried_metadata(){
 let id=setup();let o=install(id,0).unwrap();assert_eq!(o.identity,id);assert_eq!(o.registration.addr,[9;6]);assert_eq!(o.registration.bus,SleBus::None);assert!(o.registration.name.starts_with(b"sle0\0"));
 let s=SUBSYSTEM.lock();let d=s.as_ref().unwrap().dev_registry.get(id.id).unwrap();assert_eq!((d.addr,d.fw_version),([9;6],77));assert_eq!((d.features,d.max_connections),(0,0));assert_eq!(d.flags.load(Ordering::Acquire),SLE_DEV_SETUP);let _=&d.stats;
}
#[test]fn successful_native_candidate_keeps_peer_owner(){
 let id=setup();let peer=reserve_backend_identity(&SleControllerInfo{bus:SleBus::Test,addr:[3;6],..Default::default()}).unwrap();let p=install_backend_runtime(peer,Box::new(ControllerState),1,None).unwrap();let o=install(id,0).unwrap();assert_eq!(o.identity,id);assert_eq!(p.registration.bus,SleBus::Test);assert_eq!(p.registration.addr,[3;6]);
}
#[test]fn retire_during_candidate_construction_rejects_publication(){let id=setup();failed(install(id,2),ENODEV);assert_eq!(DROPS.load(Ordering::Relaxed),1);assert!(SUBSYSTEM.lock().as_ref().unwrap().dev_registry.get(id.id).is_none());}
#[test]fn reuse_during_construction_preserves_new_generation(){let id=setup();failed(install(id,3),ENODEV);cancel_backend_reservation(id);let s=SUBSYSTEM.lock();let d=s.as_ref().unwrap().dev_registry.get(id.id).unwrap();assert_ne!(d.identity(),id);assert_eq!(d.addr,[0;6]);}
#[test]fn competing_installer_is_not_replaced_and_failed_candidate_metadata_not_published(){let id=setup();failed(install(id,4),EBUSY);let s=SUBSYSTEM.lock();assert!(s.as_ref().unwrap().runtime(id.id).is_some());assert_eq!(s.as_ref().unwrap().dev_registry.get(id.id).unwrap().addr,[0;6]);}
#[test]fn subsystem_removal_during_construction_drops_candidate_outside_lock(){let id=setup();failed(install(id,5),ENODEV);assert_eq!(DROPS.load(Ordering::Relaxed),1);assert!(SUBSYSTEM.lock().is_none());}
#[test]fn retiring_identity_is_not_published_or_cancelled(){let id=setup();failed(install(id,6),ENODEV);cancel_backend_reservation(id);assert!(SUBSYSTEM.lock().as_ref().unwrap().dev_registry.get(id.id).unwrap().test_flag(SLE_DEV_UNREGISTERING));}
#[test]fn stale_and_busy_prechecks_do_not_allocate_or_drop_under_lock(){let id=setup();failed(install(DeviceIdentity{id:id.id,generation:id.generation+1},0),ENODEV);assert_eq!(CONSTRUCTIONS.load(Ordering::Relaxed),0);let o=install(id,0).unwrap();failed(install(id,0),EBUSY);assert_eq!(CONSTRUCTIONS.load(Ordering::Relaxed),1);assert_eq!(o.identity,id);}
#[test]fn construction_failure_cancellation_preserves_other_owner(){let id=setup();let peer=reserve_backend_identity(&SleControllerInfo::default()).unwrap();let p=install(peer,0).unwrap();failed(install(id,1),ENOMEM);cancel_backend_reservation(id);let s=SUBSYSTEM.lock();assert!(s.as_ref().unwrap().dev_registry.get(id.id).is_none());assert!(Arc::ptr_eq(&p,&s.as_ref().unwrap().runtime(peer.id).unwrap()));}

#[test]fn early_pending_identity_preserves_unknown_metadata_and_profile(){
 let _=setup();let id=reserve_backend_identity_profile(&SleControllerInfo{bus:SleBus::Usb,..Default::default()},1).unwrap();
 assert_eq!(query_backend_pending(id),Ok((SleBus::Usb,1,0,0)));assert_eq!(validate_backend_reservation(id,SleBus::Usb,1),Ok(()));
 assert_eq!(validate_backend_reservation(id,SleBus::Test,1),Err(EINVAL));assert_eq!(validate_backend_reservation(id,SleBus::Usb,0),Err(EINVAL));
 let s=SUBSYSTEM.lock();let d=s.as_ref().unwrap().dev_registry.get(id.id).unwrap();assert_eq!((d.addr,d.fw_version,d.features,d.max_connections),([0;6],0,0,0));assert_eq!(d.flags.load(Ordering::Acquire),SLE_DEV_SETUP);
}
#[test]fn pending_fault_is_core_owned_and_positive_errors_rejected(){
 let id=setup();assert_eq!(update_backend_pending(id,10,-110),Ok(()));assert_eq!(query_backend_pending(id),Ok((SleBus::None,0,10,-110)));
 assert_eq!(update_backend_pending(id,11,1),Err(EINVAL));assert_eq!(query_backend_pending(id),Ok((SleBus::None,0,10,-110)));
 assert_eq!(update_backend_pending(id,12,0),Ok(()));assert_eq!(query_backend_pending(id),Ok((SleBus::None,0,12,0)));
}
#[test]fn late_pending_callback_cannot_touch_reused_generation(){
 let old=setup();cancel_backend_reservation(old);let fresh=reserve_backend_identity(&SleControllerInfo::default()).unwrap();assert_eq!(old.id,fresh.id);
 assert_eq!(update_backend_pending(old,10,-5),Err(ENODEV));assert_eq!(query_backend_pending(old),Err(ENODEV));assert_eq!(validate_backend_reservation(old,SleBus::None,0),Err(ENODEV));assert_eq!(query_backend_pending(fresh),Ok((SleBus::None,0,0,0)));
}
#[test]fn pending_diagnostics_and_adoption_cannot_change_installed_or_retiring_owner(){
 let id=setup();let o=install(id,0).unwrap();assert_eq!(update_backend_pending(id,10,-5),Err(EBUSY));assert_eq!(query_backend_pending(id),Err(EBUSY));assert_eq!(validate_backend_reservation(id,SleBus::None,0),Err(EBUSY));assert_eq!(o.identity,id);
 let pending=reserve_backend_identity(&SleControllerInfo::default()).unwrap();SUBSYSTEM.lock().as_ref().unwrap().dev_registry.get(pending.id).unwrap().begin_unregister();
 assert_eq!(update_backend_pending(pending,10,-5),Err(ENODEV));assert_eq!(query_backend_pending(pending),Err(ENODEV));assert_eq!(validate_backend_reservation(pending,SleBus::None,0),Err(ENODEV));
}

#[test]fn snapshot_pending_fault_and_exact_generation_are_authoritative(){
 let id=setup();let s=snapshot_backend_registration(id.id,0).unwrap();assert_eq!(s.reserved_byte,0);assert_eq!((s.generation,s.dev_index,s.state,s.phase,s.error,s.reserved),(id.generation,id.id,REGISTRATION_PENDING,0,0,[0;8]));
 update_backend_pending(id,3,-2).unwrap();let f=snapshot_backend_registration(id.id,id.generation).unwrap();assert_eq!((f.state,f.phase,f.error),(REGISTRATION_FAULT,3,-2));
 assert_eq!(snapshot_backend_registration(id.id,id.generation+1).unwrap_err(),ENODEV);
}
#[test]fn snapshot_does_not_expose_pending_error_after_install_or_retirement(){
 let id=setup();update_backend_pending(id,3,-2).unwrap();let _o=install(id,0).unwrap();let s=snapshot_backend_registration(id.id,0).unwrap();assert_eq!((s.state,s.phase,s.error),(REGISTRATION_INSTALLED,0,0));
 SUBSYSTEM.lock().as_ref().unwrap().dev_registry.get(id.id).unwrap().begin_unregister();let s=snapshot_backend_registration(id.id,0).unwrap();assert_eq!((s.state,s.phase,s.error),(REGISTRATION_RETIRING,0,0));
}
#[test]fn snapshot_old_generation_is_rejected_without_retaining_cancelled_identity(){
 let old=setup();cancel_backend_reservation(old);assert_eq!(snapshot_backend_registration(old.id,0).unwrap_err(),ENODEV);let new=reserve_backend_identity(&SleControllerInfo::default()).unwrap();assert_eq!(old.id,new.id);assert_eq!(snapshot_backend_registration(old.id,old.generation).unwrap_err(),ENODEV);assert_eq!(snapshot_backend_registration(new.id,new.generation).unwrap().generation,new.generation);
}
#[test]fn snapshot_keeps_fault_and_installed_peer_separate_and_rejects_missing_slot(){
 let id=setup();update_backend_pending(id,3,-2).unwrap();let p=reserve_backend_identity_profile(&SleControllerInfo{bus:SleBus::Usb,..Default::default()},1).unwrap();let _o=install(p,0).unwrap();assert_eq!(snapshot_backend_registration(id.id,0).unwrap().error,-2);let s=snapshot_backend_registration(p.id,p.generation).unwrap();assert_eq!((s.bus,s.profile,s.state),(4,1,REGISTRATION_INSTALLED));assert_eq!(snapshot_backend_registration(16,0).unwrap_err(),ENODEV);
}

#[test]fn actual_install_forwards_bootstrap_credit_seed_without_a_default(){
 for credit in [0,1,7,255] {let id=setup();let owner=install_backend_runtime(id,Box::new(ControllerState),credit,None).unwrap();assert_eq!(owner.bootstrap_credits,credit);}
}
