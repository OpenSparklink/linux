// SPDX-License-Identifier: GPL-2.0-only
//! Registration-local file ownership. The Runtime mutex serializes transitions
//! with admission; this state contains no I/O, allocation or process identity.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Failure { Busy, Permission, Overflow, Invalid }

pub(crate) const MANAGED: u32 = 1;
pub(crate) const DIAGNOSTIC: u32 = 2;
pub(crate) const FREE: u32 = 0;
pub(crate) const HELD: u32 = 1;
pub(crate) const REVOKING: u32 = 2;
pub(crate) const FAULTED: u32 = 3;

pub(crate) struct Management {
    pub(crate) state: u32,
    pub(crate) mode: u32,
    pub(crate) error: i32,
    file: u64,
    token: u64,
}

impl Management {
    pub(crate) const fn new() -> Self {
        Self { state: FREE, mode: 0, error: 0, file: 0, token: 0 }
    }
    pub(crate) fn prepare(&self, mode: u32) -> Result<u64, Failure> {
        if mode != MANAGED && mode != DIAGNOSTIC { return Err(Failure::Invalid); }
        if self.state != FREE { return Err(Failure::Busy); }
        self.token.checked_add(1).ok_or(Failure::Overflow)
    }
    // Caller holds the Runtime management mutex through copyout and commit.
    pub(crate) fn commit(&mut self, file: u64, mode: u32, token: u64) {
        self.file = file; self.mode = mode; self.token = token;
        self.state = HELD; self.error = 0;
    }
    pub(crate) fn owns(&self, file: u64) -> bool {
        self.state == HELD && self.file == file
    }
    pub(crate) fn token_for(&self, file: u64) -> u64 {
        if self.owns(file) { self.token } else { 0 }
    }
    pub(crate) fn authorize(&self, file: u64, mode: u32) -> Result<(), Failure> {
        if self.state == REVOKING || self.state == FAULTED { return Err(Failure::Busy); }
        if !self.owns(file) || self.mode != mode { return Err(Failure::Permission); }
        Ok(())
    }
    pub(crate) fn release(&mut self, file: u64, token: u64) -> Result<(), Failure> {
        if !self.owns(file) || token == 0 || self.token != token { return Err(Failure::Permission); }
        self.file = 0; self.mode = 0; self.state = REVOKING;
        Ok(())
    }
    pub(crate) fn settled(&mut self, error: i32) {
        self.file = 0; self.mode = 0; self.error = error;
        self.state = if error == 0 { FREE } else { FAULTED };
    }
}
