// SPDX-License-Identifier: GPL-2.0-only

//! ACB packet budget, independent of command credits and DTAP peer flow control.
//! One instance belongs to one controller generation. USB success is not NOCP.

const LINKS: usize = 16;

#[derive(Clone, Copy)]
struct Debt { handle: u16, lifetime: u64, packets: u16 }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CreditError { Unsupported, Invalid, TooLarge, WouldBlock, OldLifetime, Fault }

pub(crate) struct DataCredits {
    maximum: u16,
    capacity: u8,
    outstanding: u16,
    debts: [Option<Debt>; LINKS],
    uncertain: bool,
}

impl DataCredits {
    pub(crate) fn maximum(&self) -> Result<u16, CreditError> {
        if self.uncertain { return Err(CreditError::Fault); }
        if self.maximum == 0 || self.capacity == 0 { return Err(CreditError::Unsupported); }
        Ok(self.maximum)
    }
    pub(crate) const fn new(maximum: u16, capacity: u8) -> Self {
        Self { maximum, capacity, outstanding: 0, debts: [None; LINKS], uncertain: false }
    }

    pub(crate) fn reserve(&mut self, lifetime: u64, handle: u16, size: usize) -> Result<(), CreditError> {
        if self.uncertain { return Err(CreditError::Fault); }
        if self.maximum == 0 || self.capacity == 0 { return Err(CreditError::Unsupported); }
        if self.maximum > 2047 || lifetime == 0 || handle > 0x0fff || size == 0 {
            return Err(CreditError::Invalid);
        }
        if size > self.maximum as usize { return Err(CreditError::TooLarge); }
        let existing = self.debts.iter().position(|d| d.is_some_and(|d| d.handle == handle));
        if existing.is_some_and(|i| self.debts[i].is_some_and(|d| d.lifetime != lifetime)) {
            return Err(CreditError::OldLifetime);
        }
        if self.outstanding >= self.capacity as u16 { return Err(CreditError::WouldBlock); }
        let index = existing.or_else(|| self.debts.iter().position(Option::is_none))
            .ok_or(CreditError::WouldBlock)?;
        let packets = self.debts[index].map_or(0, |d| d.packets) + 1;
        self.debts[index] = Some(Debt { lifetime, handle, packets });
        self.outstanding += 1;
        Ok(())
    }

    /// NOCP only identifies handle/count: retain old lifetime debt until paid.
    /// An unknown or excess count is uncertain accounting, never a pool refill.
    pub(crate) fn complete(&mut self, handle: u16, count: u8) -> Result<(), CreditError> {
        if self.uncertain { return Err(CreditError::Fault); }
        if count == 0 { return Err(CreditError::Invalid); }
        let Some(index) = self.debts.iter().position(|d| d.is_some_and(|d| d.handle == handle)) else {
            self.uncertain = true;
            return Err(CreditError::Fault);
        };
        let mut debt = self.debts[index].unwrap();
        if count as u16 > debt.packets {
            self.uncertain = true;
            return Err(CreditError::Fault);
        }
        debt.packets -= count as u16;
        self.outstanding -= count as u16;
        self.debts[index] = if debt.packets == 0 { None } else { Some(debt) };
        Ok(())
    }

    /// Roll back only a reservation made under the same data lock immediately
    /// before an atomic submit callback that returned nonzero (never queued).
    /// No NOCP or another reserve may intervene; never use after USB acceptance.
    pub(crate) fn unsubmitted(&mut self, lifetime: u64, handle: u16) -> Result<(), CreditError> {
        if self.uncertain { return Err(CreditError::Fault); }
        let index = self.debts.iter().position(|d| d.is_some_and(|d|
            d.handle == handle && d.lifetime == lifetime)).ok_or(CreditError::Invalid)?;
        let mut debt = self.debts[index].unwrap();
        if debt.packets == 0 || self.outstanding == 0 { return Err(CreditError::Invalid); }
        debt.packets -= 1;
        self.outstanding -= 1;
        self.debts[index] = if debt.packets == 0 { None } else { Some(debt) };
        Ok(())
    }

    /// Failed/short/uncertain transport cannot safely return a reserved credit.
    pub(crate) fn transport_failed(&mut self) { self.uncertain = true; }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn known_unsubmitted_rolls_back_only_current_lifetime_debt() {
        let mut c = DataCredits::new(254, 5);
        c.reserve(1, 0, 4).unwrap();
        c.reserve(1, 0, 4).unwrap();
        c.reserve(2, 1, 4).unwrap();
        assert_eq!(c.unsubmitted(3, 0), Err(CreditError::Invalid));
        assert_eq!(c.outstanding, 3);
        assert_eq!(c.unsubmitted(1, 0), Ok(()));
        assert_eq!(c.outstanding, 2);
        assert_eq!(c.complete(0, 1), Ok(()));
        assert_eq!(c.complete(1, 1), Ok(()));
        assert_eq!(c.outstanding, 0);
    }
    #[test]
    fn unsubmitted_cannot_refund_uncertain_or_already_paid_debt() {
        let mut c = DataCredits::new(254, 5);
        c.reserve(1, 0, 4).unwrap();
        c.transport_failed();
        assert_eq!(c.unsubmitted(1, 0), Err(CreditError::Fault));
        assert_eq!(c.outstanding, 1);
        let mut c = DataCredits::new(254, 5);
        c.reserve(1, 0, 4).unwrap();
        c.complete(0, 1).unwrap();
        assert_eq!(c.unsubmitted(1, 0), Err(CreditError::Invalid));
        assert_eq!(c.outstanding, 0);
    }
    #[test]
    fn actual_count_is_the_only_refill_and_pool_is_per_controller() {
        let mut a = DataCredits::new(254, 5);
        let mut b = DataCredits::new(254, 5);
        for _ in 0..5 { assert_eq!(a.reserve(1, 0, 254), Ok(())); }
        assert_eq!(a.reserve(1, 0, 1), Err(CreditError::WouldBlock));
        assert_eq!(b.reserve(1, 0, 1), Ok(()));
        assert_eq!(a.complete(0, 0), Err(CreditError::Invalid));
        assert_eq!(a.outstanding, 5);
        assert_eq!(a.complete(0, 2), Ok(()));
        assert_eq!(a.outstanding, 3);
        assert_eq!(a.reserve(1, 0, 1), Ok(()));
        assert_eq!(b.outstanding, 1);
    }
    #[test]
    fn old_debt_blocks_reused_handle_but_not_other_links() {
        let mut c = DataCredits::new(254, 5);
        c.reserve(1, 0, 4).unwrap();
        assert_eq!(c.reserve(3, 0, 4), Err(CreditError::OldLifetime));
        assert_eq!(c.reserve(2, 1, 4), Ok(()));
        c.complete(0, 1).unwrap();
        assert_eq!(c.reserve(3, 0, 4), Ok(()));
        assert_eq!(c.debts.iter().flatten().find(|d| d.handle == 0).unwrap().lifetime, 3);
    }
    #[test]
    fn wire_duplicate_after_reuse_is_indistinguishable_without_barrier() {
        // Reproduce the NOCPReuse TLC counterexample using the actual ledger.
        // This documents an OPEN attribution risk, not a safety qualification
        // or evidence that the firmware actually emits duplicate completions.
        let mut c = DataCredits::new(254, 5);
        c.reserve(1, 0, 4).unwrap();
        c.complete(0, 1).unwrap(); // genuine old completion: old debt is paid
        c.reserve(3, 0, 4).unwrap(); // current policy now permits reuse
        assert_eq!(c.debts[0].unwrap().lifetime, 3);
        // Wire handle/count alone cannot distinguish a duplicate old event.
        assert_eq!(c.complete(0, 1), Ok(()));
        assert_eq!(c.outstanding, 0);
        assert!(c.debts[0].is_none());
    }
    #[test]
    fn over_completion_and_uncertain_usb_never_invent_capacity() {
        let mut c = DataCredits::new(254, 5);
        c.reserve(1, 0, 4).unwrap();
        assert_eq!(c.complete(0, 2), Err(CreditError::Fault));
        assert_eq!(c.outstanding, 1);
        assert_eq!(c.reserve(1, 0, 4), Err(CreditError::Fault));
        let mut c = DataCredits::new(254, 5);
        c.reserve(1, 0, 4).unwrap(); c.transport_failed();
        assert_eq!(c.complete(0, 1), Err(CreditError::Fault));
        assert_eq!(c.outstanding, 1);
    }
    #[test]
    fn unsupported_limits_and_bad_identity_are_noop() {
        for (length, count) in [(0, 0), (254, 0), (0, 5)] {
            let mut c = DataCredits::new(length, count);
            assert_eq!(c.reserve(1, 0, 1), Err(CreditError::Unsupported));
            assert_eq!(c.outstanding, 0);
        }
        let mut c = DataCredits::new(254, 5);
        assert_eq!(c.reserve(1, 0, 255), Err(CreditError::TooLarge));
        assert_eq!(c.reserve(0, 0, 1), Err(CreditError::Invalid));
        assert_eq!(c.reserve(1, 0x1000, 1), Err(CreditError::Invalid));
        assert_eq!(c.reserve(1, 0, 0), Err(CreditError::Invalid));
        assert_eq!(c.outstanding, 0);
        assert_eq!(c.complete(1, 1), Err(CreditError::Fault));
    }
}

#[cfg(kani)]
mod verification {
    use super::*;

    fn invariant(c: &DataCredits) -> bool {
        let mut sum = 0u32;
        for i in 0..LINKS {
            if let Some(d) = c.debts[i] {
                if d.packets == 0 || d.lifetime == 0 || d.handle > 0x0fff { return false; }
                sum += d.packets as u32;
                for j in 0..i {
                    if c.debts[j].is_some_and(|old| old.handle == d.handle) { return false; }
                }
            }
        }
        sum == c.outstanding as u32 && c.outstanding <= c.capacity as u16
    }
    fn symbolic_valid() -> DataCredits {
        let mut debts = [None; LINKS];
        for slot in &mut debts {
            if kani::any::<bool>() {
                *slot = Some(Debt { handle: kani::any(), lifetime: kani::any(), packets: kani::any() });
            }
        }
        let c = DataCredits { maximum: kani::any(), capacity: kani::any(),
            outstanding: kani::any(), debts, uncertain: kani::any() };
        // Inductive representation invariant; no assumption that hardware
        // count/handle is accurate, timely, unique or from a current lifetime.
        kani::assume(invariant(&c));
        c
    }
    fn same_debts(a: &DataCredits, b: &DataCredits) -> bool {
        for i in 0..LINKS {
            if a.debts[i].map(|d| (d.handle,d.lifetime,d.packets)) !=
                b.debts[i].map(|d| (d.handle,d.lifetime,d.packets)) { return false; }
        }
        true
    }
    fn duplicate(c: &DataCredits) -> DataCredits {
        DataCredits { maximum:c.maximum, capacity:c.capacity,
            outstanding:c.outstanding, debts:c.debts, uncertain:c.uncertain }
    }
    #[kani::proof]
    #[kani::unwind(17)]
    fn initialization_all_parameters() {
        let c = DataCredits::new(kani::any(), kani::any());
        assert!(invariant(&c));
        assert_eq!(c.outstanding, 0);
    }
    #[kani::proof]
    #[kani::unwind(17)]
    fn reservation_preserves_invariant_and_old_debt() {
        let mut c = symbolic_valid();
        let before = duplicate(&c);
        let lifetime = kani::any(); let handle = kani::any();
        let result = c.reserve(lifetime, handle, kani::any());
        assert!(invariant(&c));
        if result.is_ok() {
            assert_eq!(c.outstanding, before.outstanding + 1);
            assert!(c.debts.iter().flatten().any(|d| d.handle==handle && d.lifetime==lifetime));
            for d in before.debts.iter().flatten() {
                assert!(c.debts.iter().flatten().any(|next| next.handle==d.handle && next.lifetime==d.lifetime));
            }
        } else {
            assert_eq!(c.outstanding, before.outstanding);
            assert!(same_debts(&c,&before));
        }
    }
    #[kani::proof]
    #[kani::unwind(17)]
    fn rejected_atomic_submission_restores_exact_prior_ledger() {
        let mut c = symbolic_valid();
        let before = duplicate(&c);
        let lifetime = kani::any(); let handle = kani::any();
        if c.reserve(lifetime, handle, kani::any()).is_ok() {
            // Actual commit holds the data lock over reserve/submit/rollback.
            // No controller completion is assumed authentic or timely here.
            assert_eq!(c.unsubmitted(lifetime, handle), Ok(()));
            assert!(invariant(&c));
            assert_eq!(c.outstanding, before.outstanding);
            assert!(same_debts(&c, &before));
            assert_eq!(c.uncertain, before.uncertain);
        }
    }
    #[kani::proof]
    #[kani::unwind(17)]
    fn arbitrary_completion_preserves_invariant_and_exact_accounting() {
        let mut c = symbolic_valid(); let before = duplicate(&c);
        let count:u8 = kani::any();
        let result = c.complete(kani::any(), count);
        assert!(invariant(&c));
        if result.is_ok() {
            assert!(count > 0);
            assert_eq!(c.outstanding, before.outstanding - count as u16);
        } else {
            assert_eq!(c.outstanding, before.outstanding);
            assert!(same_debts(&c,&before));
        }
        // Physical attribution of an old duplicate after debt was paid is
        // deliberately not claimed: the wire has only handle/count.
    }
    #[kani::proof]
    #[kani::unwind(17)]
    fn uncertain_transport_never_refunds_or_refills() {
        let mut c = symbolic_valid(); let before = duplicate(&c);
        c.transport_failed();
        assert!(invariant(&c));
        assert_eq!(c.complete(kani::any(), kani::any()), Err(CreditError::Fault));
        assert_eq!(c.reserve(kani::any(),kani::any(),kani::any()), Err(CreditError::Fault));
        assert_eq!(c.outstanding, before.outstanding);
        assert!(same_debts(&c,&before));
    }
    #[kani::proof]
    #[kani::unwind(17)]
    fn separate_controllers_do_not_share_ledger_mutations() {
        let mut a = symbolic_valid(); let b = symbolic_valid(); let original_b=duplicate(&b);
        let _=a.reserve(kani::any(),kani::any(),kani::any());
        let _=a.complete(kani::any(),kani::any());
        a.transport_failed();
        assert!(invariant(&a) && invariant(&b));
        assert_eq!(b.outstanding, original_b.outstanding);
        assert!(same_debts(&b,&original_b));
    }
}
