// SPDX-License-Identifier: GPL-2.0

//! Short IRQ-safe locks for transport ingress and work references.
//!
//! Protected operations must not allocate with sleeping flags, sleep, decode
//! packets or perform blocking I/O. The one explicit exception is prepared ACB
//! commit: an atomic USB queue call under Host/data/admission guards, with no
//! wait or protocol reentry. Completion joining is always outside all guards.
//! Raw spinlocks also retain this constraint on PREEMPT_RT kernels.

use kernel::{bindings, sync::lock::Backend};

extern "C" {
    fn sle_irq_lock_init(
        lock: *mut bindings::raw_spinlock_t,
        name: *const kernel::ffi::c_char,
        key: *mut core::ffi::c_void,
    );
    fn sle_irq_lock(lock: *mut bindings::raw_spinlock_t) -> kernel::ffi::c_ulong;
    fn sle_irq_trylock(
        lock: *mut bindings::raw_spinlock_t,
        flags: *mut kernel::ffi::c_ulong,
    ) -> i32;
    fn sle_irq_unlock(lock: *mut bindings::raw_spinlock_t, flags: kernel::ffi::c_ulong);
    fn sle_irq_assert_held(lock: *mut bindings::raw_spinlock_t);
}

pub(crate) struct IrqLockBackend;

// SAFETY: raw_spin_lock_irqsave provides mutual exclusion and prevents local
// IRQ reentry. The guard saves the caller's IRQ flags, restored on unlock.
// The default relock acquires using the same method and replaces those flags.
unsafe impl Backend for IrqLockBackend {
    type State = bindings::raw_spinlock_t;
    type GuardState = kernel::ffi::c_ulong;

    unsafe fn init(
        ptr: *mut Self::State,
        name: *const kernel::ffi::c_char,
        key: *mut bindings::lock_class_key,
    ) {
        // SAFETY: the caller provides pinned writable state and static metadata.
        unsafe { sle_irq_lock_init(ptr, name, key.cast()) };
    }

    unsafe fn lock(ptr: *mut Self::State) -> Self::GuardState {
        // SAFETY: caller guarantees initialization and valid pinned state.
        unsafe { sle_irq_lock(ptr) }
    }

    unsafe fn try_lock(ptr: *mut Self::State) -> Option<Self::GuardState> {
        let mut flags = 0;
        // SAFETY: same state guarantee; flags is writable for this call.
        if unsafe { sle_irq_trylock(ptr, &mut flags) } != 0 {
            Some(flags)
        } else {
            None
        }
    }

    unsafe fn unlock(ptr: *mut Self::State, flags: &Self::GuardState) {
        // SAFETY: caller owns this lock; flags came from its acquisition.
        unsafe { sle_irq_unlock(ptr, *flags) };
    }

    unsafe fn assert_is_held(ptr: *mut Self::State) {
        // SAFETY: caller guarantees initialized state.
        unsafe { sle_irq_assert_held(ptr) };
    }
}

/// Each invocation has its own static lock class. Initialize exactly once,
/// before callbacks can use the generated lock, just like global_lock!.
macro_rules! irq_global_lock {
    ($name:ident : $value_type:ty = $value:expr) => {
        #[allow(non_camel_case_types)]
        enum $name {}

        impl kernel::sync::lock::GlobalLockBackend for $name {
            const NAME: &'static kernel::str::CStr = kernel::c_str!(stringify!($name));
            type Item = $value_type;
            type Backend = $crate::sle_irq_lock::IrqLockBackend;

            fn get_lock_class() -> Pin<&'static kernel::sync::LockClassKey> {
                kernel::static_lock_class!()
            }
        }

        // SAFETY: all callers initialize this static before exposing callbacks.
        static $name: kernel::sync::lock::GlobalLock<$name> =
            unsafe { kernel::sync::lock::GlobalLock::new($value) };
    };
}

pub(crate) use irq_global_lock;

macro_rules! new_irq_lock {
    ($value:expr, $name:literal) => {
        kernel::sync::lock::Lock::<_, $crate::sle_irq_lock::IrqLockBackend>::new(
            $value,
            kernel::c_str!($name),
            kernel::static_lock_class!(),
        )
    };
}

pub(crate) use new_irq_lock;
