// SPDX-License-Identifier: GPL-2.0-only
// Actual constructor/registry/reservation code; logging and subsystem lock are
// dependencies. No USB callbacks, transport ownership or Ready proof.
use std::sync::{Mutex,MutexGuard,Arc};
use std::sync::atomic::{AtomicU32,Ordering};
type Result<T=()>=std::result::Result<T,i32>;
const ENOSPC:i32=-28;const ENODEV:i32=-19;
macro_rules! pr_info{($($arg:tt)*)=>{let _=format_args!($($arg)*);}}
#[derive(Clone,Copy,Debug,Default,PartialEq,Eq)] pub enum SleBus{#[default]None,Usb}
mod sle_dli {pub use super::SleBus;
 // @@INFO@@
 impl Default for SleControllerInfo{// @@INFO_DEFAULT@@
 }
}
use sle_dli::SleControllerInfo;
// @@CONSTANTS@@
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
// @@IDENTITY@@
// @@DEVICE@@
impl SleDev {
 // @@DEV_NEW@@
 // @@DEV_IDENTITY@@
 // @@BEGIN_UNREGISTER@@
 // @@TEST_FLAG@@
}
// @@REGISTRY@@
impl SleDevRegistry {
 // @@REG_NEW@@
 // @@REGISTER_PENDING@@
 // @@GET@@
 // @@GET_MUT@@
 // @@UNREGISTER@@
}
mod sle_dev {pub(crate) use super::{DeviceIdentity,SLE_DEV_UNREGISTERING};}
struct Shared{dev_registry:SleDevRegistry,runtimes:[Option<Arc<Runtime>>;SLE_DEV_MAX],active_dev_id:Option<u16>}
impl Shared{fn runtime(&self,id:u16)->Option<Arc<Runtime>>{self.runtimes.get(id as usize).and_then(Clone::clone)} fn new()->Self{Self{dev_registry:SleDevRegistry::new(),runtimes:std::array::from_fn(|_|None),active_dev_id:None}}}
struct Lock<T>(Mutex<T>);impl<T> Lock<T>{fn lock(&self)->MutexGuard<'_,T>{self.0.lock().unwrap()}}
static SUBSYSTEM:Lock<Option<Shared>>=Lock(Mutex::new(None));
// @@RESERVE_PROFILE@@
// @@RESERVE_BACKEND@@
// @@CANCEL@@
// @@RESERVE@@
mod native_unregistration {use super::DeviceIdentity;
 // @@UNREGISTER_NATIVE@@
}
// @@DETACH@@
struct Runtime{identity:DeviceIdentity,invalidations:AtomicU32}
impl Runtime{fn invalidate(&self){self.invalidations.fetch_add(1,Ordering::Relaxed);
 // Deterministic competing-caller window dependency, not a real callback.
 {let s=SUBSYSTEM.lock();let d=s.as_ref().unwrap().dev_registry.get(self.identity.id).unwrap();assert!(d.test_flag(SLE_DEV_UNREGISTERING));}
 sle_detach_device(self.identity);
 assert!(SUBSYSTEM.lock().as_ref().unwrap().dev_registry.get(self.identity.id).is_some(),"duplicate detach freed index before joined cleanup");
}}

#[test]fn constructor_has_only_setup_and_preserves_explicit_metadata(){
 let info=SleControllerInfo{addr:[3;6],fw_version:7,bus:SleBus::Usb,..Default::default()};let d=SleDev::new(4,5,&info);
 assert_eq!(d.flags.load(Ordering::Acquire),SLE_DEV_SETUP);assert_eq!((d.pending_profile,d.pending_phase,d.pending_error),(0,0,0));assert_eq!((d.id,d.generation,d.addr,d.fw_version,d.bus),(4,5,[3;6],7,SleBus::Usb));assert_eq!(&d.name[..4],b"sle4");
}
#[test]fn full_registry_cannot_invent_ready_or_extra_slot(){
 let mut r=SleDevRegistry::new();for id in 0..SLE_DEV_MAX{let got=r.register_pending(&SleControllerInfo::default()).unwrap();assert_eq!(got as usize,id);assert_eq!(r.get(got).unwrap().flags.load(Ordering::Acquire),SLE_DEV_SETUP);}
 assert_eq!(r.register_pending(&SleControllerInfo::default()),Err(ENOSPC));assert_eq!(r.allocated,u16::MAX);
}
#[test]fn index_reuse_gets_new_generation_and_stale_identity_is_distinct(){
 let mut r=SleDevRegistry::new();let id=r.register_pending(&SleControllerInfo::default()).unwrap();let first=r.get(id).unwrap().identity();r.unregister(id).unwrap();assert!(r.get(id).is_none());let next=r.register_pending(&SleControllerInfo::default()).unwrap();let second=r.get(next).unwrap().identity();assert_eq!(first.id,second.id);assert!(second.generation>first.generation);
}
#[test]fn generation_exhaustion_does_not_allocate_or_publish(){
 let mut r=SleDevRegistry::new();r.next_generation=u64::MAX;assert_eq!(r.register_pending(&SleControllerInfo::default()),Err(ENOSPC));assert_eq!(r.allocated,0);assert!(r.slots.iter().all(Option::is_none));
}
#[test]fn actual_usb_reservation_is_pending_unknown_and_requires_subsystem(){
 *SUBSYSTEM.lock()=None;assert_eq!(reserve_usb_identity(),Err(ENODEV));*SUBSYSTEM.lock()=Some(Shared::new());let identity=reserve_usb_identity().unwrap();let s=SUBSYSTEM.lock();let d=s.as_ref().unwrap().dev_registry.get(identity.id).unwrap();assert_eq!(d.identity(),identity);assert_eq!(d.flags.load(Ordering::Acquire),SLE_DEV_SETUP);assert_eq!((d.addr,d.fw_version,d.bus),([0;6],0,SleBus::Usb));
}

#[test]fn actual_detach_rejects_stale_identity_and_preserves_other_owner(){
 *SUBSYSTEM.lock()=Some(Shared::new());let a=reserve_usb_identity().unwrap();let b=reserve_usb_identity().unwrap();let oa=Arc::new(Runtime{identity:a,invalidations:AtomicU32::new(0)});let ob=Arc::new(Runtime{identity:b,invalidations:AtomicU32::new(0)});
 {let mut g=SUBSYSTEM.lock();let s=g.as_mut().unwrap();s.runtimes[a.id as usize]=Some(oa.clone());s.runtimes[b.id as usize]=Some(ob.clone());s.active_dev_id=Some(b.id);}
 sle_detach_device(DeviceIdentity{id:b.id,generation:b.generation+1});assert_eq!(ob.invalidations.load(Ordering::Relaxed),0);assert_eq!(SUBSYSTEM.lock().as_ref().unwrap().active_dev_id,Some(b.id));
 sle_detach_device(a);assert_eq!(oa.invalidations.load(Ordering::Relaxed),1);assert_eq!(ob.invalidations.load(Ordering::Relaxed),0);let s=SUBSYSTEM.lock();assert!(s.as_ref().unwrap().dev_registry.get(a.id).is_none());assert!(s.as_ref().unwrap().dev_registry.get(b.id).is_some());assert_eq!(s.as_ref().unwrap().active_dev_id,Some(b.id));
}
#[test]fn actual_detach_pending_identity_without_runtime_frees_only_exact_generation(){
 *SUBSYSTEM.lock()=Some(Shared::new());let old=reserve_usb_identity().unwrap();sle_detach_device(old);let new=reserve_usb_identity().unwrap();assert_eq!(old.id,new.id);assert_ne!(old.generation,new.generation);sle_detach_device(old);assert_eq!(SUBSYSTEM.lock().as_ref().unwrap().dev_registry.get(new.id).unwrap().identity(),new);
}

#[test]fn native_unregister_without_runtime_releases_pending_exact_identity(){
 *SUBSYSTEM.lock()=Some(Shared::new());let a=reserve_usb_identity().unwrap();let b=reserve_usb_identity().unwrap();
 native_unregistration::sparklink_native_unregister_rust(a.id,a.generation);
 assert!(SUBSYSTEM.lock().as_ref().unwrap().dev_registry.get(a.id).is_none());
 assert_eq!(SUBSYSTEM.lock().as_ref().unwrap().dev_registry.get(b.id).unwrap().identity(),b);
 let new=reserve_usb_identity().unwrap();assert_eq!(new.id,a.id);assert_ne!(new.generation,a.generation);
 native_unregistration::sparklink_native_unregister_rust(a.id,a.generation);
 assert_eq!(SUBSYSTEM.lock().as_ref().unwrap().dev_registry.get(new.id).unwrap().identity(),new);
}
#[test]fn reservation_cancel_preserves_installed_or_retiring_owners(){
 *SUBSYSTEM.lock()=Some(Shared::new());let a=reserve_usb_identity().unwrap();let b=reserve_usb_identity().unwrap();let c=reserve_usb_identity().unwrap();
 {let mut g=SUBSYSTEM.lock();let s=g.as_mut().unwrap();s.runtimes[b.id as usize]=Some(Arc::new(Runtime{identity:b,invalidations:AtomicU32::new(0)}));s.dev_registry.get(c.id).unwrap().begin_unregister();}
 cancel_backend_reservation(a);assert!(SUBSYSTEM.lock().as_ref().unwrap().dev_registry.get(a.id).is_none());
 cancel_backend_reservation(b);assert!(SUBSYSTEM.lock().as_ref().unwrap().runtime(b.id).is_some());
 cancel_backend_reservation(c);assert!(SUBSYSTEM.lock().as_ref().unwrap().dev_registry.get(c.id).is_some());
}
