// SPDX-License-Identifier: GPL-2.0-only
//! Retained provider submission handle. The Runtime owns identity/Host credit;
//! acquiring a handle retains provider resources but submits no I/O. Blocking
//! submission happens after releasing Runtime state, never under Host/IRQ locks.
use kernel::prelude::*;
use super::sle_command_plan::RecipeTag;

/// Process-context, one-worker handle. It is not transferred between workers.
/// Submission success means transport completion, not controller Complete or
/// peer receipt. Typed tags grant no raw command/management permission.
pub(crate) trait CommandPort {
    fn submit(&self, opcode: u16, params: &[u8], recipe: Option<RecipeTag>, connection: Option<u32>) -> Result;
}
