// SPDX-License-Identifier: GPL-2.0-only
//! Production lease authority, serialized by Runtime Host IRQ lock. Identity
//! (controller/generation/lifetime/channel) is retained by Session/Binding.
//! This state never pays physical debt and never treats a successor as renewal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct LeaseAuthority { last: u64, active: u64 }
impl LeaseAuthority {
    pub(crate) const fn new() -> Self { Self { last: 0, active: 0 } }
    pub(crate) fn accepts(&self, epoch: u64) -> bool { epoch != 0 && epoch > self.last }
    pub(crate) fn activate(&mut self, epoch: u64, managed: bool) -> bool {
        if !self.accepts(epoch) { return false; }
        self.last = epoch;
        self.active = if managed { epoch } else { 0 };
        true
    }
    pub(crate) fn revoke(&mut self) { self.active = 0; }
    pub(crate) fn permits(&self, epoch: u64) -> bool { epoch != 0 && self.active == epoch }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn constructor_rejects_and_successor_never_revives_old_epoch() {
        let mut authority = LeaseAuthority::new();
        assert!(!authority.permits(0)); assert!(!authority.permits(1));
        assert!(authority.activate(1, true)); assert!(authority.permits(1));
        authority.revoke(); assert!(!authority.permits(1));
        assert!(!authority.activate(1, true)); assert!(authority.activate(2, true));
        assert!(!authority.permits(1)); assert!(authority.permits(2));
    }
    #[test] fn diagnostic_and_overflow_do_not_authorize_or_cross_devices() {
        let mut a = LeaseAuthority::new(); let mut b = LeaseAuthority::new();
        assert!(a.activate(1, true)); assert!(b.activate(1, true));
        a.revoke(); assert!(b.permits(1));
        assert!(a.activate(2, false)); assert!(!a.permits(2));
        assert!(a.activate(u64::MAX, true)); a.revoke();
        assert!(!a.activate(0, true)); assert!(!a.activate(u64::MAX, true));
        assert!(!a.permits(u64::MAX)); assert!(b.permits(1));
    }
}

#[cfg(kani)]
mod proofs {
    use super::*;
    #[kani::proof]
    fn lease_authority_constructor_and_transition_induction() {
        let initial = LeaseAuthority::new();
        assert!(!initial.permits(kani::any()));
        let last: u64 = kani::any();
        let active: u64 = kani::any();
        kani::assume(active == 0 || (last != 0 && active == last));
        let mut authority = LeaseAuthority { last, active };
        let before = authority;
        let epoch: u64 = kani::any();
        if kani::any() {
            let managed: bool = kani::any();
            let accepted = authority.activate(epoch, managed);
            assert!(accepted == (epoch != 0 && epoch > before.last));
            if !accepted { assert!(authority == before); }
            else { assert!(authority.last == epoch); assert!(authority.active == if managed {epoch} else {0}); }
        } else { authority.revoke(); assert!(authority.active == 0); }
        assert!(authority.last >= before.last);
        assert!(authority.active == 0 || (authority.last != 0 && authority.active == authority.last));
    }
    #[kani::proof]
    fn revoked_epoch_never_revives_in_successor() {
        let old: u64 = kani::any(); let next: u64 = kani::any();
        let mut authority = LeaseAuthority::new();
        let activated = authority.activate(old, true);
        authority.revoke();
        assert!(!authority.permits(old));
        let accepted = authority.activate(next, kani::any());
        if activated { assert!(!authority.permits(old)); }
        if accepted && next != old { assert!(!authority.permits(old)); }
    }
}
