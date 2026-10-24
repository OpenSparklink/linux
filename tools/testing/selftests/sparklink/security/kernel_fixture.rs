// SPDX-License-Identifier: GPL-2.0-only
// Standalone dependency fixture; production implementations are compiled verbatim.
extern crate self as kernel;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Error(pub i32);
impl Error {
    pub fn from_errno(value: i32) -> Self {
        Self(value)
    }
}
pub mod error {
    pub fn to_result(value: i32) -> crate::prelude::Result {
        if value < 0 {
            Err(crate::Error(value))
        } else {
            Ok(())
        }
    }
}
pub mod bindings {
    pub const EOPNOTSUPP: u32 = 95;
}
pub mod prelude {
    pub use crate::{pr_info, Error};
    pub type Result<T = ()> = core::result::Result<T, Error>;
    pub const EINVAL: Error = Error(-22);
    pub const EOVERFLOW: Error = Error(-75);
    pub const EPERM: Error = Error(-1);
    pub const EBUSY: Error = Error(-16);
    pub const ENOMEM: Error = Error(-12);
    pub const EEXIST: Error = Error(-17);
    pub const ENOENT: Error = Error(-2);
}
#[macro_export]
macro_rules! pr_info { ($($arg:tt)*) => { { let _ = format_args!($($arg)*); } }; }
use std::sync::atomic::{AtomicI32, AtomicUsize, Ordering::SeqCst};
static ERROR: AtomicI32 = AtomicI32::new(0);
static FAIL_CALL: AtomicUsize = AtomicUsize::new(0);
static CALLS: AtomicUsize = AtomicUsize::new(0);
fn inject(error: i32, call: usize) {
    CALLS.store(0, SeqCst);
    ERROR.store(error, SeqCst);
    FAIL_CALL.store(call, SeqCst);
}
fn outcome() -> i32 {
    let n = CALLS.fetch_add(1, SeqCst) + 1;
    if FAIL_CALL.load(SeqCst) == 0 || FAIL_CALL.load(SeqCst) == n {
        ERROR.load(SeqCst)
    } else {
        0
    }
}
unsafe fn output(p: *mut u8, len: usize) -> i32 {
    // Even a failing dependency may have modified its private output.
    unsafe {
        core::ptr::write_bytes(p, 0x5a, len);
    }
    outcome()
}
#[unsafe(no_mangle)]
unsafe extern "C" fn sle_sm3_hash(_: *const u8, _: u32, p: *mut u8) -> i32 {
    unsafe { output(p, 32) }
}
#[unsafe(no_mangle)]
unsafe extern "C" fn sle_hmac_sm3(_: *const u8, _: u32, _: *const u8, _: u32, p: *mut u8) -> i32 {
    unsafe { output(p, 32) }
}
#[unsafe(no_mangle)]
unsafe extern "C" fn sle_sm4_ecb_crypt(_: *const u8, _: *const u8, p: *mut u8, _: i32) -> i32 {
    unsafe { output(p, 16) }
}
#[unsafe(no_mangle)]
unsafe extern "C" fn sle_sm4_ctr_crypt(_: *const u8, iv: *mut u8, data: *mut u8, len: u32) -> i32 {
    let ret = outcome();
    // Transactional destination behavior is checked separately using actual C body.
    if ret == 0 {
        unsafe {
            core::ptr::write_bytes(data, 0x5a, len as usize);
            core::ptr::write_bytes(iv, 0x6a, 16);
        }
    }
    ret
}
#[unsafe(no_mangle)]
unsafe extern "C" fn sle_ecdh_generate(a: *mut u8, b: *mut u8) -> i32 {
    unsafe {
        core::ptr::write_bytes(a, 0x5a, 32);
        output(b, 64)
    }
}
#[unsafe(no_mangle)]
unsafe extern "C" fn sle_ecdh_shared_secret(_: *const u8, _: *const u8, p: *mut u8) -> i32 {
    unsafe { output(p, 32) }
}
// Runner appends modules with exact source paths. Tests run single-threaded.
