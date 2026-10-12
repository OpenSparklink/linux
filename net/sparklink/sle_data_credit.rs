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

    /// Failed/short/uncertain transport cannot safely return a reserved credit.
    pub(crate) fn transport_failed(&mut self) { self.uncertain = true; }
}

#[cfg(test)]
mod tests {
    use super::*;
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
