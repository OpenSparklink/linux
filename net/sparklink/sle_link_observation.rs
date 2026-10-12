// SPDX-License-Identifier: GPL-2.0-only

//! Physical link obligations observed directly at native ingress. This is not
//! command acceptance, an operation-result store or a connection initiator.
//! Events must not disappear from cleanup decisions when a reader overruns.

/// Driver-normalized link facts, independent of vendor event numbering and
/// payload layout. The complete original event body is logged separately.
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct LinkEvidence {
    pub(crate) kind: u32, // 1 connected outcome, 2 disconnected outcome
    pub(crate) status: u32,
    pub(crate) handle: u32,
    pub(crate) role: u32,
    pub(crate) address_type: u32,
    pub(crate) address: [u8; 6],
    pub(crate) reserved: [u8; 2],
}

pub(crate) const CAPACITY: usize = 16;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct Link {
    pub(crate) lifetime: u64,
    pub(crate) handle: u16,
    pub(crate) role: u8,
    pub(crate) address_type: u8,
    pub(crate) address: [u8; 6],
}

pub(crate) struct LinkObservation {
    links: [Option<Link>; CAPACITY],
    uncertain: bool,
    revision: u64,
}

impl LinkObservation {
    pub(crate) const fn new() -> Self {
        Self { links: [None; CAPACITY], uncertain: false, revision: 0 }
    }

    pub(crate) fn clear_for_management(&self) -> bool {
        !self.uncertain && self.links.iter().all(Option::is_none)
    }

    pub(crate) fn contains(&self, handle: u16) -> bool {
        !self.uncertain && self.links.iter().flatten().any(|link| link.handle == handle)
    }

    pub(crate) fn known(&self) -> bool { !self.uncertain }
    pub(crate) fn matches(&self, lifetime: u64, handle: u16, role: u8, address_type: u8, address: [u8;6]) -> bool {
        self.known() && lifetime != 0 && self.links.iter().flatten().any(|link|
            link.handle == handle && link.lifetime == lifetime
                && link.role == role && link.address_type == address_type && link.address == address)
    }
    /// Caller holds the registration Host lock. This is observed physical
    /// state, not command history or a synthetic controller list response.
    pub(crate) fn snapshot(&self) -> (u64, bool, [Option<Link>; CAPACITY]) {
        (self.revision, self.known(), self.links)
    }
    fn advance(&mut self) -> Option<u64> {
        let Some(next) = self.revision.checked_add(1) else {
            self.uncertain = true;
            return None;
        };
        self.revision = next;
        Some(next)
    }
    pub(crate) fn first_handle(&self) -> Option<u16> {
        self.known().then(|| self.links.iter().flatten().next().map(|link| link.handle)).flatten()
    }

    /// Failed outcomes never establish/remove links. Wire schema and opcode
    /// aliases belong to the driver, not the generic Host cleanup domain.
    pub(crate) fn observe(&mut self, evidence: &LinkEvidence) {
        if evidence.reserved != [0; 2] || !(1..=2).contains(&evidence.kind)
            || evidence.status > 255 || evidence.handle > 65535 {
            self.uncertain = true;
            return;
        }
        if evidence.status != 0 { return; }
        let handle = evidence.handle as u16;
        if evidence.kind == 2 {
            if let Some(index) = self.links.iter().position(|slot|
                slot.as_ref().is_some_and(|link| link.handle == handle)) {
                if self.advance().is_some() { self.links[index] = None; }
            }
            return;
        }
        if evidence.role > 1 || evidence.address_type > 255
            || evidence.address == [0; 6] || evidence.address == [255; 6] {
            self.uncertain = true;
            return;
        }
        let link = Link { lifetime: 0, handle, role: evidence.role as u8,
            address_type: evidence.address_type as u8, address: evidence.address };
        if let Some(existing) = self.links.iter().flatten().find(|entry| entry.handle == handle) {
            if existing.role != link.role || existing.address_type != link.address_type
                || existing.address != link.address { self.uncertain = true; }
        } else if let Some(index) = self.links.iter().position(Option::is_none) {
            if let Some(lifetime) = self.advance() { self.links[index] = Some(Link { lifetime, ..link }); }
        } else {
            self.uncertain = true;
        }
    }

}

#[cfg(test)]
mod tests {
    use super::*;
    fn connected(handle: u16, address: [u8; 6]) -> LinkEvidence {
        LinkEvidence {kind:1,status:0,handle:handle as u32,role:0,address_type:0,address,reserved:[0;2]}
    }
    fn disconnected(handle: u16) -> LinkEvidence {
        LinkEvidence {kind:2,status:0,handle:handle as u32,role:0,address_type:0,address:[0;6],reserved:[0;2]}
    }
    #[test]
    fn snapshot_lifetime_survives_duplicates_and_detects_handle_reuse() {
        let mut state=LinkObservation::new();assert_eq!(state.snapshot().0,0);
        state.observe(&connected(7,[1;6]));let (revision,known,links)=state.snapshot();
        assert!(known);assert_eq!(revision,1);assert_eq!(links[0].unwrap().lifetime,1);
        assert!(state.matches(1,7,0,0,[1;6]));assert!(!state.matches(1,7,1,0,[1;6]));
        assert!(!state.matches(1,7,0,1,[1;6]));assert!(!state.matches(1,7,0,0,[2;6]));
        state.observe(&connected(7,[1;6]));assert_eq!(state.snapshot().0,1);
        state.observe(&disconnected(8));assert_eq!(state.snapshot().0,1);
        state.observe(&disconnected(7));assert_eq!(state.snapshot().0,2);
        state.observe(&connected(7,[2;6]));let (revision,known,links)=state.snapshot();
        assert!(known);assert_eq!(revision,3);assert_eq!(links[0].unwrap().lifetime,3);
        assert_eq!(links[0].unwrap().address,[2;6]);
        assert!(!state.matches(1,7,0,0,[1;6]));assert!(state.matches(3,7,0,0,[2;6]));
    }
    #[test]
    fn lifetime_exhaustion_never_reuses_a_token_or_hides_an_obligation() {
        let mut state=LinkObservation::new();state.observe(&connected(7,[1;6]));
        state.revision=u64::MAX;state.observe(&disconnected(7));
        assert!(!state.snapshot().1);assert_eq!(state.snapshot().2[0].unwrap().handle,7);
        assert!(!state.clear_for_management());
    }
    #[test]
    fn exact_handle_is_required_and_duplicate_delivery_is_harmless() {
        let mut state=LinkObservation::new();
        state.observe(&connected(7,[1;6]));state.observe(&connected(7,[1;6]));
        assert!(state.known());assert_eq!(state.first_handle(),Some(7));
        assert!(!state.clear_for_management());
        state.observe(&disconnected(8));assert!(!state.clear_for_management());
        state.observe(&disconnected(7));assert!(state.clear_for_management());
    }
    #[test]
    fn failed_outcomes_and_two_registrations_are_independent() {
        let mut a=LinkObservation::new();let mut b=LinkObservation::new();
        let mut failure=connected(1,[1;6]);failure.status=0x1c;
        a.observe(&failure);assert!(a.clear_for_management());
        a.observe(&connected(1,[1;6]));b.observe(&connected(2,[2;6]));
        assert!(a.contains(1));assert!(!a.contains(2));assert!(b.contains(2));
        let mut failed=disconnected(1);failed.status=1;
        a.observe(&failed);assert!(!a.clear_for_management());
        a.observe(&disconnected(1));assert!(a.clear_for_management());assert!(!a.contains(1));
        assert!(!b.clear_for_management());
    }
    #[test]
    fn conflicts_malformed_success_and_overflow_stay_uncertain() {
        for kind in 0..8 {
            let mut state=LinkObservation::new();state.observe(&connected(1,[1;6]));
            let mut extra=connected(2,[2;6]);
            match kind {
                0=>extra=connected(1,[2;6]),
                1=>extra.address=[0;6],
                2=>extra.kind=3,
                3=>extra.reserved=[1;2],
                4=>extra.role=2,
                5=>extra.handle=65536,
                6=>extra.address_type=256,
                _=>for h in 2..=17 { state.observe(&connected(h,[2;6])); },
            }
            state.observe(&extra);
            assert!(!state.contains(1));assert!(!state.known());assert_eq!(state.first_handle(),None);
            for h in 1..=17 {state.observe(&disconnected(h));}
            assert!(!state.clear_for_management());
        }
        assert!(LinkObservation::new().clear_for_management());
    }
    #[test]
    fn address_type_is_opaque_and_not_a_bluetooth_or_vendor_enum() {
        for address_type in 0..=255 {
            let mut state=LinkObservation::new();let mut up=connected(1,[1;6]);up.address_type=address_type;
            state.observe(&up);assert!(!state.clear_for_management());
            state.observe(&disconnected(1));assert!(state.clear_for_management());
        }
    }
    #[test]
    fn capacity_is_a_bound_not_an_inferred_controller_limit() {
        let mut state=LinkObservation::new();
        for h in 0..CAPACITY as u16 {state.observe(&connected(h,[1;6]));}
        for h in 0..CAPACITY as u16 {state.observe(&disconnected(h));}
        assert!(state.clear_for_management());
        assert_eq!(core::mem::size_of::<LinkEvidence>(),28);
    }
}
