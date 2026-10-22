// SPDX-License-Identifier: GPL-2.0-only
//! Immutable Managed link command identity and reply shape. The pending
//! ledger owns author results; Host owns credits and physical obligations.
//! No clock, allocation, I/O, mutable qualification or alternate scheduler.

use super::sle_connection_operation::ExpectedLink;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind { Rssi = 1, Phy = 2, PayloadPreference = 3 }

impl Kind {
    pub(crate) fn parse(value: u8) -> Option<Self> {
        match value { 1 => Some(Self::Rssi), 2 => Some(Self::Phy), 3 => Some(Self::PayloadPreference), _ => None }
    }
    /// Private provider recipe selector, not ConnectionSubmit operation 3.
    pub(crate) fn provider_operation(self) -> u32 {
        match self { Self::Rssi => 4, Self::Phy => 5, Self::PayloadPreference => 6 }
    }
    pub(crate) fn reply_len(self) -> usize {
        match self { Self::Rssi => 3, Self::Phy => 10, Self::PayloadPreference => 2 }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Scope {
    pub(crate) link: ExpectedLink,
    pub(crate) lease_epoch: u64,
    pub(crate) kind: Kind,
    /// Requested link payload preference, not a negotiated MTU or credit.
    /// Queries require zero; preference requires an encodable nonzero LE16.
    pub(crate) argument: u16,
    pub(crate) deadline_monotonic_ns: u64,
}

impl Scope {
    pub(crate) fn valid(self) -> bool {
        self.link.valid() && self.lease_epoch != 0 && self.deadline_monotonic_ns != 0
            && ((self.kind == Kind::PayloadPreference) == (self.argument != 0))
    }
    pub(crate) fn expired(self, now_ns: u64) -> bool { now_ns >= self.deadline_monotonic_ns }
    /// Acceptance Status is not a sample. Error Status/Complete remains a
    /// controller error, without inventing a success body. Only a successful
    /// Complete must echo this captured handle and the full bounded layout.
    pub(crate) fn reply_matches(self, complete: bool, status: u8, data: &[u8]) -> bool {
        if !self.valid() { return false; }
        if !complete || status != 0 { return true; }
        // SDK110 E Complete echoes handle LE16, not the requested octets or
        // generation. This is not an effective payload/MTU observation.
        data.len() == self.kind.reply_len()
            && u16::from_le_bytes([data[0], data[1]]) == self.link.handle
    }
    /// RSSI 127 is the specified invalid sentinel. PHY exposes eight bounded
    /// wire fields; interpreting the SDK dialect is a separate qualification.
    pub(crate) fn value_available(self, data: &[u8]) -> bool {
        self.kind != Kind::PayloadPreference && self.reply_matches(true, 0, data)
            && (self.kind != Kind::Rssi || data[2] != 127)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn scope(kind: Kind) -> Scope {
        Scope { kind, argument: 0, lease_epoch: 7, deadline_monotonic_ns: 100_000_000, link: ExpectedLink {
            lifetime: 11, handle: 0x1234, role: 0, address_type: 0, address: [1;6] } }
    }
    #[test] fn typed_inputs_and_identity_are_finite() {
        for n in 0..=255 { assert_eq!(Kind::parse(n).is_some(), (1..=3).contains(&n)); }
        let s = scope(Kind::Rssi); assert!(s.valid());
        assert!(!Scope { lease_epoch: 0, ..s }.valid());
        assert!(!Scope { deadline_monotonic_ns: 0, ..s }.valid());
        assert!(!s.expired(99_999_999)); assert!(s.expired(100_000_000));
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
    #[test] fn payload_ack_never_grants_a_sample_or_changes_the_requested_argument() {
        let base = scope(Kind::PayloadPreference);
        assert!(!base.valid());
        for n in 1..=u16::MAX {
            let s = Scope { argument: n, ..base };
            assert!(s.valid()); assert!(s.reply_matches(true, 0, &[0x34,0x12]));
            assert!(!s.value_available(&[0x34,0x12]));
            for data in [&[][..], &[0x34][..], &[0x35,0x12][..], &[0x34,0x12,0][..]] {
                assert!(!s.reply_matches(true, 0, data));
            }
            assert!(!Scope { kind: Kind::Rssi, ..s }.valid());
            assert_eq!(s.kind.provider_operation(), 6);
        }
    }
}
