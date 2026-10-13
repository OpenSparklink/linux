// SPDX-License-Identifier: GPL-2.0-only
// Verbatim pending module and ioctl handler; clock, allocation, locks,
// lease and usercopy dependencies are fixtures, not live VFS qualification.
extern crate self as kernel;
extern crate self as pin_init;
pub trait Init<T> {}
pub struct FixtureInit<T>(std::marker::PhantomData<T>);
impl<T> Init<T> for FixtureInit<T> {}
macro_rules! init {
    ($($tokens:tt)*) => { crate::FixtureInit::<Self>(std::marker::PhantomData) };
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Error(i32);
impl Error { pub fn from_errno(n: i32) -> Self { Self(n) } }
pub mod prelude {
    pub use crate::Error;
    pub type Result<T = ()> = core::result::Result<T, Error>;
    pub const EINVAL: Error = Error(-22);
    pub const EBUSY: Error = Error(-16);
    pub const EOVERFLOW: Error = Error(-75);
    pub const ENODEV: Error = Error(-19);
    pub const ENOENT: Error = Error(-2);
    pub const EPERM: Error = Error(-1);
    pub const EFAULT: Error = Error(-14);
}
pub mod bindings {
    pub const EOPNOTSUPP: u32 = 95;
    pub const EMSGSIZE: u32 = 90;
    pub const ETIMEDOUT: u32 = 110;
    pub const ECANCELED: u32 = 125;
    pub static mut JIFFIES_64: u64 = 0;
    pub use JIFFIES_64 as jiffies_64;
}
pub mod time { pub fn msecs_to_jiffies(ms: u32) -> u64 { u64::from(ms) } }
// Request queue allocation/transmit is outside this result-query fixture.
pub mod sle_command_queue {
    pub struct CmdRequest;
    pub enum QueueError { Invalid, Full }
    pub struct CmdRequestQueue;
    impl CmdRequestQueue {
        pub fn push_tagged(&mut self, _: u16, _: &[u8], _: u32, _: u64,
                           _: Option<()>, _: u64) -> Result<(), QueueError> { Ok(()) }
    }
}
#[path = "sle_mgmt.rs"] mod sle_mgmt;
use prelude::*;
use sle_mgmt::CmdPendingQueue;
use std::pin::Pin;
use std::sync::{Mutex, MutexGuard};
struct TestMutex<T>(Mutex<T>);
impl<T> TestMutex<T> {
    fn new(t: T) -> Self { Self(Mutex::new(t)) }
    fn lock(&self) -> MutexGuard<'_, T> { self.0.lock().unwrap() }
}
#[derive(Clone, Copy, PartialEq, Eq)]
struct Identity { generation: u64 }
struct Target { identity: Identity }
struct Management { file: u64 }
impl Management {
    fn authorize(&self, file: u64, mode: u32) -> Result {
        if self.file == file && mode == 2 { Ok(()) } else { Err(EPERM) }
    }
}
mod sle_management { pub const DIAGNOSTIC: u32 = 2; }
fn management_error(e: Error) -> Error { e }
struct Owner {
    identity: Identity, protocol_profile: u32, management: TestMutex<Management>,
    schedule_gate: TestMutex<bool>,
}
struct State { cmd_pending: CmdPendingQueue }
struct RuntimeContext { owner: Option<Owner>, state: TestMutex<Option<State>> }
impl RuntimeContext {
    fn lock(&self) -> Result<MutexGuard<'_, Option<State>>> { Ok(self.state.lock()) }
}
struct SparkLinkCtl { file_id: u64, target: TestMutex<Option<Target>> }
// @@RESULT_STRUCT@@
thread_local! {
    static INPUT: std::cell::RefCell<SleDiagnosticResult> = std::cell::RefCell::new(zero());
    static OUTPUT: std::cell::RefCell<Option<SleDiagnosticResult>> = const { std::cell::RefCell::new(None) };
}
fn zero() -> SleDiagnosticResult {
    // SAFETY: the canonical declaration only contains integer/byte fields.
    unsafe { core::mem::zeroed() }
}
fn read_user_struct(_: usize) -> Result<SleDiagnosticResult> {
    INPUT.with(|p| {
        let p = *p.borrow();
        if p._pad != 0 || p._reserved != [0; 6] { Err(EINVAL) } else { Ok(p) }
    })
}
fn write_user_struct(arg: usize, output: &SleDiagnosticResult) -> Result {
    if arg == 0 { return Err(EFAULT); }
    OUTPUT.with(|p| *p.borrow_mut() = Some(*output));
    Ok(())
}
// @@RESULT_HANDLER@@
fn setup(author: u64) -> (RuntimeContext, SparkLinkCtl, u32) {
    let _ = core::mem::size_of::<sle_mgmt::CmdRequest>();
    let identity = Identity { generation: 7 };
    let mut queue = CmdPendingQueue::new();
    let seq = queue.submit(0x0403).unwrap();
    queue.assign_owner(seq, author);
    let ctx = RuntimeContext {
        owner: Some(Owner { identity, protocol_profile: 1,
                          schedule_gate: TestMutex::new(false),
                          management: TestMutex::new(Management { file: 42 }) }),
        state: TestMutex::new(Some(State { cmd_pending: queue })),
    };
    let ctl = SparkLinkCtl { file_id: 42, target: TestMutex::new(Some(Target { identity })) };
    let mut input = zero(); input.version = 1; input.generation = 7; input.seq = seq;
    INPUT.with(|p| *p.borrow_mut() = input);
    OUTPUT.with(|p| *p.borrow_mut() = None);
    (ctx, ctl, seq)
}
fn fetch(ctx: &RuntimeContext, ctl: &SparkLinkCtl) -> SleDiagnosticResult {
    assert_eq!(ioctl_diagnostic_result(ctx, Pin::new(ctl), 1), Ok(0));
    OUTPUT.with(|p| p.borrow().unwrap())
}
#[test]
fn pending_then_exact_complete_stays_repeatable() {
    let (ctx, ctl, seq) = setup(42);
    let p = fetch(&ctx, &ctl); assert_eq!((p.state, p.data_len, p.error), (1, 0, 0));
    assert!(ctx.state.lock().as_mut().unwrap().cmd_pending.resolve_seq(seq, 0, &[0x80; 10]));
    for _ in 0..3 {
        let r = fetch(&ctx, &ctl);
        assert_eq!((r.generation, r.seq, r.opcode, r.state), (7, seq, 0x0403, 2));
        assert_eq!((r.error, r.status, r.data_len), (0, 0, 10));
        assert_eq!(&r.data[..10], &[0x80; 10]);
        assert_eq!(&r.data[10..], &[0; 54]);
    }
}
#[test]
fn failed_copy_does_not_consume_result() {
    let (ctx, ctl, seq) = setup(42);
    assert!(ctx.state.lock().as_mut().unwrap().cmd_pending.resolve_seq(seq, 0, &[1, 2, 3]));
    assert_eq!(ioctl_diagnostic_result(&ctx, Pin::new(&ctl), 0), Err(EFAULT));
    assert!(OUTPUT.with(|p| p.borrow().is_none()));
    let r = fetch(&ctx, &ctl); assert_eq!((r.state, r.data_len), (2, 3));
    assert_eq!(&r.data[..3], &[1, 2, 3]);
}
#[test]
fn controller_failure_is_not_success() {
    let (ctx, ctl, seq) = setup(42);
    ctx.state.lock().as_mut().unwrap().cmd_pending.resolve_seq(seq, 0xfd, &[]);
    let r = fetch(&ctx, &ctl); assert_eq!((r.state, r.error, r.status), (3, 0, 0xfd));
}
#[test]
fn oversized_response_is_not_truncated_success() {
    let (ctx, ctl, seq) = setup(42);
    ctx.state.lock().as_mut().unwrap().cmd_pending.resolve_seq(seq, 0, &[1; 65]);
    let r = fetch(&ctx, &ctl); assert_eq!((r.state, r.error, r.data_len), (3, -90, 0));
    assert_eq!(r.data, [0; 64]);
}
#[test]
fn owner_and_diagnostic_lease_are_independent_checks() {
    let (ctx, ctl, _) = setup(43);
    assert_eq!(ioctl_diagnostic_result(&ctx, Pin::new(&ctl), 1), Err(EPERM));
    let (ctx, ctl, _) = setup(42);
    ctx.owner.as_ref().unwrap().management.lock().file = 43;
    assert_eq!(ioctl_diagnostic_result(&ctx, Pin::new(&ctl), 1), Err(EPERM));
}
#[test]
fn identity_version_profile_and_missing_sequence_fail() {
    let (mut ctx, ctl, _) = setup(42);
    INPUT.with(|p| p.borrow_mut().generation = 8);
    assert_eq!(ioctl_diagnostic_result(&ctx, Pin::new(&ctl), 1), Err(ENODEV));
    INPUT.with(|p| { p.borrow_mut().generation = 7; p.borrow_mut().version = 2; });
    assert_eq!(ioctl_diagnostic_result(&ctx, Pin::new(&ctl), 1), Err(Error(-95)));
    INPUT.with(|p| { p.borrow_mut().version = 1; p.borrow_mut().seq = 999; });
    assert_eq!(ioctl_diagnostic_result(&ctx, Pin::new(&ctl), 1), Err(ENOENT));
    ctx.owner.as_mut().unwrap().protocol_profile = 2;
    assert_eq!(ioctl_diagnostic_result(&ctx, Pin::new(&ctl), 1), Err(Error(-95)));
    ctx.owner.as_mut().unwrap().protocol_profile = 1;
    *ctl.target.lock() = None;
    assert_eq!(ioctl_diagnostic_result(&ctx, Pin::new(&ctl), 1), Err(EINVAL));
    ctx.owner = None;
    assert_eq!(ioctl_diagnostic_result(&ctx, Pin::new(&ctl), 1), Err(ENODEV));
}

#[test]
fn retired_runtime_is_enodev_before_revoked_lease_permission() {
    let (ctx, ctl, _) = setup(42);
    let owner = ctx.owner.as_ref().unwrap();
    *owner.schedule_gate.lock() = true;
    owner.management.lock().file = 0;
    assert_eq!(ioctl_diagnostic_result(&ctx, Pin::new(&ctl), 1), Err(ENODEV));
}
