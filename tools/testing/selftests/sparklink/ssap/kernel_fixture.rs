// SPDX-License-Identifier: GPL-2.0-only
// Allocation dependency only: actual production module is compiled verbatim.
extern crate self as kernel;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Error(pub i32);
impl Error {
    pub fn from_errno(value: i32) -> Self {
        Self(value)
    }
}
pub mod bindings {
    pub const EOPNOTSUPP: u32 = 95;
}
pub mod prelude {
    pub use crate::Error;
    pub type Result<T = ()> = core::result::Result<T, Error>;
    pub const GFP_KERNEL: () = ();
    pub const EINVAL: Error = Error(-22);
    pub const ENODEV: Error = Error(-19);
    pub const ENOENT: Error = Error(-2);
    pub const ENOSPC: Error = Error(-28);
    pub const EACCES: Error = Error(-13);
    pub const ENOMEM: Error = Error(-12);
}
pub mod sle_conn {
    pub mod tcid {
        pub const SERVICE_MGMT: u16 = 0x0a;
    }
}
use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
static ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);
static FAIL_AT: AtomicUsize = AtomicUsize::new(0);
fn fail_at(call: usize) {
    ALLOCATIONS.store(0, SeqCst);
    FAIL_AT.store(call, SeqCst);
}
fn allocation() -> prelude::Result {
    let call = ALLOCATIONS.fetch_add(1, SeqCst) + 1;
    if call == FAIL_AT.load(SeqCst) {
        Err(prelude::ENOMEM)
    } else {
        Ok(())
    }
}
pub mod alloc {
    use crate::{allocation, prelude::*};
    #[derive(Debug)]
    pub struct KVec<T>(Vec<T>);
    impl<T> KVec<T> {
        pub fn new() -> Self {
            Self(Vec::new())
        }
        pub fn push(&mut self, value: T, _: ()) -> Result {
            allocation()?;
            self.0.push(value);
            Ok(())
        }
        pub fn remove(&mut self, index: usize) -> Result<T> {
            if index >= self.0.len() {
                return Err(EINVAL);
            }
            Ok(self.0.remove(index))
        }
        pub fn clear(&mut self) {
            self.0.clear();
        }
    }
    impl<T: Clone> KVec<T> {
        pub fn extend_from_slice(&mut self, data: &[T], _: ()) -> Result {
            if !data.is_empty() {
                allocation()?;
            }
            self.0.extend_from_slice(data);
            Ok(())
        }
    }
    impl<T> core::ops::Deref for KVec<T> {
        type Target = [T];
        fn deref(&self) -> &[T] {
            &self.0
        }
    }
    impl<T> core::ops::DerefMut for KVec<T> {
        fn deref_mut(&mut self) -> &mut [T] {
            &mut self.0
        }
    }
}
// Runner appends production module, localized historical codec and child regressions.
