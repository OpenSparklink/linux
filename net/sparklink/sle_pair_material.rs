// SPDX-License-Identifier: GPL-2.0-only
//! Sole Session crypto dependency. No protocol state, wire queue or policy.
//! The caller owns an exclusive material value while outside IRQ locks.
use super::sle_security_relay_state::{CryptoJob, CryptoKind, CryptoReceipt};
use core::{ffi::c_void, ptr::NonNull};
use kernel::prelude::*;

extern "C" {
    fn sl_pair_material_create(
        role: u8,
        method: u8,
        local: *const u8,
        remote: *const u8,
        out: *mut *mut c_void,
    ) -> i32;
    fn sl_pair_material_numeric(material: *mut c_void, out: *mut u32) -> i32;
    fn sl_pair_material_destroy(material: *mut c_void);
    fn sl_pair_material_install(material: *mut c_void, role: u8, out: *mut u8) -> i32;
    fn sl_pair_material_public(material: *mut c_void, out: *mut u8) -> i32;
    fn sl_pair_material_peer(material: *mut c_void, peer: *const u8) -> i32;
    fn sl_pair_material_confirm(material: *mut c_void, out: *mut u8) -> i32;
    fn sl_pair_material_nonce(material: *mut c_void, out: *mut u8) -> i32;
    fn sl_pair_material_derive(
        material: *mut c_void,
        nonce: *const u8,
        confirm: *const u8,
        out: *mut u8,
    ) -> i32;
    fn sl_pair_material_verify(material: *mut c_void, proof: *const u8, out: *mut u8) -> i32;
}

pub(crate) struct Material(NonNull<c_void>);
// SAFETY: exclusively moved out of the IRQ-protected Owner; neither cloned nor
// shared during crypto. The retaining C Session kref is separate from this value.
unsafe impl Send for Material {}
impl Drop for Material {
    fn drop(&mut self) {
        unsafe { sl_pair_material_destroy(self.0.as_ptr()) };
    }
}
impl Material {
    pub(crate) fn new(role: u8, local: &[u8; 6], remote: &[u8; 6], numeric: bool) -> Result<Self> {
        let mut pointer = core::ptr::null_mut();
        // SAFETY: all fixed-width inputs/output live across this sleeping call.
        kernel::error::to_result(unsafe {
            sl_pair_material_create(
                role,
                if numeric { 0 } else { 1 },
                local.as_ptr(),
                remote.as_ptr(),
                &mut pointer,
            )
        })?;
        NonNull::new(pointer).map(Self).ok_or(EIO)
    }
    pub(crate) fn public(&mut self) -> Result<[u8; 64]> {
        let mut out = [0; 64];
        kernel::error::to_result(unsafe {
            sl_pair_material_public(self.0.as_ptr(), out.as_mut_ptr())
        })?;
        Ok(out)
    }
    /// Only the final driver preparation uses this non-sleeping copy. No
    /// private key crosses the generic Host queue or a public observation.
    pub(crate) fn fill_install(&mut self, role: u8, out: &mut [u8; 16]) -> Result {
        kernel::error::to_result(unsafe {
            sl_pair_material_install(self.0.as_ptr(), role, out.as_mut_ptr())
        })
    }
    pub(crate) fn execute(&mut self, job: &CryptoJob) -> core::result::Result<CryptoReceipt, i32> {
        let mut out = [0; 16];
        let mut nonce = [0; 16];
        let mut number = 0;
        let pointer = self.0.as_ptr();
        // SAFETY: unique material, fixed buffers, all crypto in sleepable context.
        let result = unsafe {
            match job.kind {
                CryptoKind::GPublicAndConfirm
                | CryptoKind::TPublic
                | CryptoKind::NumericPublicAndConfirm => {
                    let error = sl_pair_material_peer(pointer, job.data.as_ptr());
                    if error != 0 {
                        error
                    } else if job.kind == CryptoKind::NumericPublicAndConfirm {
                        let error = sl_pair_material_confirm(pointer, out.as_mut_ptr());
                        if error != 0 {
                            error
                        } else {
                            sl_pair_material_nonce(pointer, nonce.as_mut_ptr())
                        }
                    } else if job.kind == CryptoKind::GPublicAndConfirm {
                        sl_pair_material_confirm(pointer, out.as_mut_ptr())
                    } else {
                        0
                    }
                }
                CryptoKind::NumericGDerive | CryptoKind::NumericTDerive => {
                    let error = sl_pair_material_derive(
                        pointer,
                        job.data.as_ptr(),
                        if job.kind == CryptoKind::NumericGDerive {
                            job.confirm.as_ptr()
                        } else {
                            core::ptr::null()
                        },
                        out.as_mut_ptr(),
                    );
                    if error != 0 {
                        error
                    } else {
                        let error = sl_pair_material_numeric(pointer, &mut number);
                        if error != 0 {
                            error
                        } else {
                            sl_pair_material_nonce(pointer, nonce.as_mut_ptr())
                        }
                    }
                }
                CryptoKind::GNonce => sl_pair_material_nonce(pointer, out.as_mut_ptr()),
                CryptoKind::GDerive => sl_pair_material_derive(
                    pointer,
                    job.data.as_ptr(),
                    job.confirm.as_ptr(),
                    out.as_mut_ptr(),
                ),
                CryptoKind::TDerive => {
                    let error = sl_pair_material_derive(
                        pointer,
                        job.data.as_ptr(),
                        core::ptr::null(),
                        out.as_mut_ptr(),
                    );
                    if error != 0 {
                        error
                    } else {
                        sl_pair_material_nonce(pointer, out.as_mut_ptr())
                    }
                }
                CryptoKind::GProofAndRespond | CryptoKind::TProof => {
                    sl_pair_material_verify(pointer, job.data.as_ptr(), out.as_mut_ptr())
                }
            }
        };
        if result == 0 {
            Ok(CryptoReceipt {
                output: out,
                nonce,
                comparison: if matches!(
                    job.kind,
                    CryptoKind::NumericGDerive | CryptoKind::NumericTDerive
                ) {
                    Some(number)
                } else {
                    None
                },
            })
        } else {
            Err(if result < 0 { result } else { EIO.to_errno() })
        }
    }
}
