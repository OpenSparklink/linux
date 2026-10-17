# SPDX-License-Identifier: GPL-2.0-only
"""Actual Command body/ledger; kernel lock/clock/allocation/C kref dependencies."""
from pathlib import Path


def write_fixture(root, directory):
    net = root / 'net/sparklink'
    source = (net / 'sle_security_relay.rs').read_text()
    body = source[source.index('pub(crate) struct Command'):source.index('impl super::ControllerRuntime')]
    error = source[source.index('fn error('):source.index('#[no_mangle]')]
    dependency = '''
use std::{ffi::c_void,cell::{Cell,RefCell,RefMut}};
use super::sle_security_relay_state::{self as relay,Identity,Ticket};
#[derive(Clone,Copy,Debug)] pub(crate) struct Error(i32);
impl Error {fn from_errno(n:i32)->Self{Self(n)} pub(crate) fn to_errno(self)->i32{self.0}}
type Result<T=()> = std::result::Result<T,Error>;
const ENODEV:Error=Error(-19);const EINVAL:Error=Error(-22);const EBUSY:Error=Error(-16);const EIO:Error=Error(-5);
mod kernel {pub mod bindings {pub const EOPNOTSUPP:u32=95;pub const EINVAL:u32=22;pub const ESTALE:u32=116;pub const ETIMEDOUT:u32=110;pub const ECANCELED:u32=125;pub const ENOBUFS:u32=105;pub const EOVERFLOW:u32=75;pub const EIO:u32=5;}}
macro_rules! pr_warn {($($arg:tt)*)=>{{}};}
struct Lock<T>(RefCell<T>);impl<T> Lock<T>{fn lock(&self)->RefMut<'_,T>{self.0.borrow_mut()}}
// This fixture cannot materialize any key: real crypto/installation gets its
// own actual-kernel VM and real USB gates; unsupported never becomes success.
struct Material;
impl Material {fn fill_install(&mut self,_role:u8,_out:&mut [u8;16])->Result{Err(Error(-95))}}
struct State {session:Option<relay::Session>,stopped:bool,material:Option<Box<Material>>}
struct Owner {identity:Identity,state:Lock<State>}
struct Allocation {owner:Owner,refs:Cell<usize>}
thread_local! {static CLOCK:Cell<u64>=const{Cell::new(1)};}
fn now()->u64 {CLOCK.with(Cell::get)}
pub(crate) fn clock(n:u64){CLOCK.with(|c|c.set(n));}
unsafe fn sl_connection_session_security(p:*mut c_void)->*mut c_void{unsafe{std::ptr::addr_of_mut!((*p.cast::<Allocation>()).owner).cast()}}
unsafe fn sl_connection_session_get(p:*mut c_void){let a=unsafe{&*p.cast::<Allocation>()};a.refs.set(a.refs.get()+1);}
unsafe fn sl_connection_session_put(p:*mut c_void){let a=unsafe{&*p.cast::<Allocation>()};let n=a.refs.get();assert!(n>0);a.refs.set(n-1);if n==1 {drop(unsafe{Box::from_raw(p.cast::<Allocation>())});}}
pub(crate) fn prepare(identity:Identity,deadline:u64)->Command {
 let p=Box::into_raw(Box::new(Allocation{owner:Owner{identity,state:Lock(RefCell::new(State{session:None,stopped:false,material:None}))},refs:Cell::new(1)})).cast();
 unsafe{Command::prepare_denial(p,identity,deadline)}.unwrap().0
}
'''
    Path(directory, 'relay_owner_fixture.rs').write_text(dependency + error + body)
    Path(directory, 'sle_security_relay_state.rs').write_bytes((net / 'sle_security_relay_state.rs').read_bytes())
