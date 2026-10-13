// SPDX-License-Identifier: GPL-2.0-only
// Actual retained selector/submission bodies, allocation/USB/provider dependencies.
use std::sync::{Arc,Mutex};
#[derive(Debug,Clone,Copy,PartialEq,Eq)] struct Error(i32);
type Result<T=()>=std::result::Result<T,Error>;

mod kernel { pub mod alloc {
 pub type KBox<T>=Box<T>;
} }
const GFP_KERNEL:u32=0;
// The actual selector uses fallible kernel KBox::new; this fixture retains the
// same construction/cast and supplies the allocator dependency only.
struct FallibleBox;
impl FallibleBox { fn new<T>(value:T,_flags:u32)->Result<Box<T>>{Ok(Box::new(value))} }
#[derive(Clone,Copy,Debug,PartialEq,Eq)] enum DiscoveryIntent{Advertising(bool),Scanning(bool),AdvertisingStandby,ScanningStandby}
#[derive(Clone,Copy,Debug,PartialEq,Eq)] struct RecipeTag{step:u8,count:u8,intent:DiscoveryIntent,recreate:bool}
mod sle_backend { use crate::{Result,RecipeTag};
 // @@TRAIT@@
}
struct NativeCommandTransport{context:Arc<Mutex<Vec<(u16,Vec<u8>,Option<RecipeTag>,Option<u32>)>>>}
impl NativeCommandTransport{fn send_typed(&self,op:u16,p:&[u8],r:Option<RecipeTag>,c:Option<u32>)->Result{self.context.lock().unwrap().push((op,p.to_vec(),r,c));Ok(())}}
// @@NATIVE_PORT@@
struct NativeController{context:Arc<Mutex<Vec<(u16,Vec<u8>,Option<RecipeTag>,Option<u32>)>>>}
impl NativeController{fn command_transport(&self)->NativeCommandTransport{NativeCommandTransport{context:self.context.clone()}}}
enum ControllerBackend{Native(NativeController)}
impl ControllerBackend{
 // @@SELECTOR@@
}
fn tag(intent:DiscoveryIntent)->RecipeTag{RecipeTag{step:0,count:1,intent,recreate:false}}
#[test]fn native_port_preserves_full_typed_tags_and_owns_context_after_drop(){let context=Arc::new(Mutex::new(vec![]));let c=ControllerBackend::Native(NativeController{context:context.clone()});let p=c.command_port().unwrap();drop(c);let r=Some(tag(DiscoveryIntent::Scanning(true)));p.submit(0x1234,&[1,2],r,None).unwrap();p.submit(0x5678,&[3],None,Some(2)).unwrap();assert_eq!(*context.lock().unwrap(),[(0x1234,vec![1,2],r,None),(0x5678,vec![3],None,Some(2))]);for intent in [DiscoveryIntent::Advertising(false),DiscoveryIntent::AdvertisingStandby,DiscoveryIntent::ScanningStandby]{let t=Some(tag(intent));p.submit(0x99,&[],t,None).unwrap();assert_eq!(context.lock().unwrap().last().unwrap().2,t);}}

#[test]fn independently_retained_common_ports_never_redirect_to_other_provider(){
 let a=Arc::new(Mutex::new(vec![]));let b=Arc::new(Mutex::new(vec![]));let ca=ControllerBackend::Native(NativeController{context:a.clone()});let cb=ControllerBackend::Native(NativeController{context:b.clone()});let p=ca.command_port().unwrap();drop(ca);p.submit(0x0404,&[],None,None).unwrap();assert_eq!(a.lock().unwrap().len(),1);assert!(b.lock().unwrap().is_empty());drop(cb);
}
