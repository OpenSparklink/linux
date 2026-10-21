// SPDX-License-Identifier: GPL-2.0-only
//! Immutable connection observation identity and reply shape. The pending
//! ledger owns author results; Host owns credits and physical obligations.
//! No clock, allocation, I/O, mutable qualification or alternate scheduler.

use super::sle_connection_operation::ExpectedLink;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind { Rssi = 1, Phy = 2 }

impl Kind {
    pub(crate) fn parse(value: u8) -> Option<Self> {
        match value { 1 => Some(Self::Rssi), 2 => Some(Self::Phy), _ => None }
    }
    /// Private provider recipe selector, not ConnectionSubmit operation 3.
    pub(crate) fn provider_operation(self) -> u32 {
        match self { Self::Rssi => 4, Self::Phy => 5 }
    }
    pub(crate) fn reply_len(self) -> usize {
        match self { Self::Rssi => 3, Self::Phy => 10 }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Scope {
    pub(crate) link: ExpectedLink,
    pub(crate) lease_epoch: u64,
    pub(crate) kind: Kind,
}

impl Scope {
    pub(crate) fn valid(self) -> bool { self.link.valid() && self.lease_epoch != 0 }
    /// Acceptance Status is not a sample. Error Status/Complete remains a
    /// controller error, without inventing a success body. Only a successful
    /// Complete must echo this captured handle and the full bounded layout.
    pub(crate) fn reply_matches(self, complete: bool, status: u8, data: &[u8]) -> bool {
        if !complete || status != 0 { return true; }
        data.len() == self.kind.reply_len()
            && u16::from_le_bytes([data[0], data[1]]) == self.link.handle
    }
    /// RSSI 127 is the specified invalid sentinel. PHY exposes eight bounded
    /// wire fields; interpreting the SDK dialect is a separate qualification.
    pub(crate) fn value_available(self, data: &[u8]) -> bool {
        self.reply_matches(true, 0, data) && (self.kind != Kind::Rssi || data[2] != 127)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn scope(kind: Kind) -> Scope {
        Scope { kind, lease_epoch: 7, link: ExpectedLink {
            lifetime: 11, handle: 0x1234, role: 0, address_type: 0, address: [1;6] } }
    }
    #[test] fn typed_inputs_and_identity_are_finite() {
        for n in 0..=255 { assert_eq!(Kind::parse(n).is_some(), n == 1 || n == 2); }
        let s = scope(Kind::Rssi); assert!(s.valid());
        assert!(!Scope { lease_epoch: 0, ..s }.valid());
        assert!(!Scope { link: ExpectedLink { lifetime: 0, ..s.link }, ..s }.valid());
        assert_eq!(s.kind.provider_operation(),4); assert_eq!(Kind::Phy.provider_operation(),5);
    }
    #[test] fn full_shape_echo_and_rssi_sentinel_are_separate() {
        let s = scope(Kind::Rssi);
        for n in 0..=255 {
            let data=[0x34,0x12,n]; assert!(s.reply_matches(true,0,&data));
            assert_eq!(s.value_available(&data), n != 127);
        }
        for data in [&[][..], &[0x34,0x12][..], &[0x34,0x12,1,0][..], &[0x35,0x12,1][..]] {
            assert!(!s.reply_matches(true,0,data)); assert!(!s.value_available(data));
        }
        assert!(s.reply_matches(false,0,&[])); assert!(s.reply_matches(false,1,&[]));
        assert!(s.reply_matches(true,1,&[])); // failure never grants a sample
    }
    #[test] fn phy_is_exact_bounded_wire_observation_not_policy() {
        let s=scope(Kind::Phy);let mut data=[0xff;10];data[..2].copy_from_slice(&s.link.handle.to_le_bytes());
        assert!(s.value_available(&data));
        for n in 0..10 {assert!(!s.value_available(&data[..n]));}
        assert!(!s.value_available(&[0;11]));
    }
}
