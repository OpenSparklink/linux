// SPDX-License-Identifier: GPL-2.0-only
// Actual retained selector/submission bodies, allocation/USB/provider dependencies.
use std::sync::{Arc,Mutex};
#[derive(Debug,Clone,Copy,PartialEq,Eq)] struct Error(i32);
type Result<T=()>=std::result::Result<T,Error>;
const EINVAL:Error=Error(-22);
impl Error { fn from_errno(n:i32)->Self{Self(n)} }
mod kernel { pub mod bindings{pub const EOPNOTSUPP:u32=95;} pub mod alloc {
 pub type KBox<T>=Box<T>;
} }
const GFP_KERNEL:u32=0;
// The actual selector uses fallible kernel KBox::new; this fixture retains the
// same construction/cast and supplies the allocator dependency only.
struct FallibleBox;
impl FallibleBox { fn new<T>(value:T,_flags:u32)->Result<Box<T>>{Ok(Box::new(value))} }
#[derive(Clone,Copy,Debug,PartialEq,Eq)] enum DiscoveryIntent{Advertising(bool),Scanning(bool),AdvertisingStandby,ScanningStandby}
#[derive(Clone,Copy,Debug,PartialEq,Eq)] struct RecipeTag{step:u8,count:u8,intent:DiscoveryIntent,recreate:bool}
mod sle_command_plan { pub(super) use super::RecipeTag; }
mod sle_uapi { pub const DLI_PARAM_MAX:usize=255; }
mod sle_backend { use crate::{Result,RecipeTag};
 // @@TRAIT@@
}
#[derive(Clone)]struct UsbController{context:Arc<Mutex<Vec<(u16,Vec<u8>)>>>}
impl UsbController {
 // @@USB_VALIDATE@@
 fn send_command_transport(&self,op:u16,p:&[u8])->Result{self.context.lock().unwrap().push((op,p.to_vec()));Ok(())} }
// @@USB_PORT@@
struct NativeCommandTransport{context:Arc<Mutex<Vec<(u16,Vec<u8>,Option<RecipeTag>,Option<u32>)>>>}
impl NativeCommandTransport{fn send_typed(&self,op:u16,p:&[u8],r:Option<RecipeTag>,c:Option<u32>)->Result{self.context.lock().unwrap().push((op,p.to_vec(),r,c));Ok(())}}
// @@NATIVE_PORT@@
struct NativeController{context:Arc<Mutex<Vec<(u16,Vec<u8>,Option<RecipeTag>,Option<u32>)>>>}
impl NativeController{fn command_transport(&self)->NativeCommandTransport{NativeCommandTransport{context:self.context.clone()}}}
enum ControllerBackend{Usb(UsbController),Native(NativeController)}
impl ControllerBackend{
 // @@SELECTOR@@
}
fn tag(intent:DiscoveryIntent)->RecipeTag{RecipeTag{step:0,count:1,intent,recreate:false}}
fn usb()->(ControllerBackend,Arc<Mutex<Vec<(u16,Vec<u8>)>>>){let context=Arc::new(Mutex::new(vec![]));(ControllerBackend::Usb(UsbController{context:context.clone()}),context)}
#[test]fn retained_usb_port_survives_controller_drop_without_redirecting(){let (a,c)=usb();let p=a.command_port().unwrap();drop(a);let (b,d)=usb();p.submit(0x0404,&[],None,None).unwrap();assert_eq!(*c.lock().unwrap(),[(0x0404,vec![])]);assert!(d.lock().unwrap().is_empty());drop(b);}
#[test]fn usb_unqualified_mutation_tags_are_rejected(){let (c,out)=usb();let p=c.command_port().unwrap();for on in [false,true]{assert_eq!(p.submit(0x0c05,&[on as u8],Some(tag(DiscoveryIntent::Advertising(on))),None),Err(Error(-95)));assert_eq!(p.submit(0x1002,&[on as u8],Some(tag(DiscoveryIntent::Scanning(on))),None),Err(Error(-95)));}assert!(out.lock().unwrap().is_empty());}
#[test]fn usb_does_not_discard_connection_or_vendor_recipe_obligations(){let(c,out)=usb();let p=c.command_port().unwrap();assert_eq!(p.submit(0x1401,&[],None,Some(1)),Err(Error(-95)));for intent in [DiscoveryIntent::AdvertisingStandby,DiscoveryIntent::ScanningStandby]{assert_eq!(p.submit(0x0c05,&[0],Some(tag(intent)),None),Err(Error(-95)));}for t in [RecipeTag{step:1,..tag(DiscoveryIntent::Advertising(true))},RecipeTag{count:2,..tag(DiscoveryIntent::Advertising(true))},RecipeTag{recreate:true,..tag(DiscoveryIntent::Advertising(true))}]{assert_eq!(p.submit(0x0c05,&[1],Some(t),None),Err(Error(-95)));}assert!(out.lock().unwrap().is_empty());}
#[test]fn malformed_tag_or_oversize_never_reaches_transport(){let(c,out)=usb();let p=c.command_port().unwrap();for (op,params) in [(0x1002,vec![1]),(0x0c05,vec![0]),(0x0c05,vec![1,1])]{assert_eq!(p.submit(op,&params,Some(tag(DiscoveryIntent::Advertising(true))),None),Err(Error(-95)));}assert_eq!(p.submit(0x0404,&[0;256],None,None),Err(EINVAL));assert!(out.lock().unwrap().is_empty());}
#[test]fn native_port_preserves_full_typed_tags_and_owns_context_after_drop(){let context=Arc::new(Mutex::new(vec![]));let c=ControllerBackend::Native(NativeController{context:context.clone()});let p=c.command_port().unwrap();drop(c);let r=Some(tag(DiscoveryIntent::Scanning(true)));p.submit(0x1234,&[1,2],r,None).unwrap();p.submit(0x5678,&[3],None,Some(2)).unwrap();assert_eq!(*context.lock().unwrap(),[(0x1234,vec![1,2],r,None),(0x5678,vec![3],None,Some(2))]);}
