// SPDX-License-Identifier: GPL-2.0-only
//! Native author history and three-evidence connection procedure. Physical
//! link obligations and per-lifetime identity remain separate from results.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub(crate) enum State { Queued = 1, OnWire = 2, AwaitingOutcome = 3, Succeeded = 4, Failed = 5, Cancelled = 6, Faulted = 7 }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Intent { Create { address_type: u8, address: [u8; 6] }, Disconnect { handle: u16 } }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Outcome { Connected { status: u8, handle: u16, address_type: u8, address: [u8; 6] }, Disconnected { status: u8, handle: u16 } }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Error { Invalid, Busy, Duplicate, Mismatch }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ExpectedLink {
    pub(crate) lifetime: u64, pub(crate) handle: u16, pub(crate) role: u8,
    pub(crate) address_type: u8, pub(crate) address: [u8; 6],
}
impl ExpectedLink {
    pub(crate) fn valid(&self) -> bool {
        self.lifetime != 0 && self.role <= 1 && self.address != [0;6] && self.address != [255;6]
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Operation {
    pub(crate) id: u64, pub(crate) cookie: u64, pub(crate) intent: Intent, pub(crate) state: State,
    pub(crate) error: i32, pub(crate) command_status: Option<u8>, pub(crate) outcome_status: Option<u8>,
    pub(crate) fault_error: i32, pub(crate) handle: Option<u16>,
    pub(crate) reference: Option<ExpectedLink>,
    deadline: u64, sent: bool, out_complete: bool, accepted: bool,
    outcome: Option<Outcome>,
}

pub(crate) struct Session {
    generation: u64,
    operation: Option<Operation>,
    // Single outstanding procedure is a Host admission policy, not a claim
    // about the controller's maximum connection count.
    outstanding: bool,
    uncertain: bool,
}

impl Session {
    const fn empty() -> Self {
        Self { generation: 1, operation: None, outstanding: false, uncertain: false }
    }
    #[cfg(test)]
    pub(crate) fn new(generation: u64) -> Result<Self, Error> {
        if generation == 0 { return Err(Error::Invalid); }
        Ok(Self { generation, operation: None, outstanding: false, uncertain: false })
    }
    #[cfg(test)]
    pub(crate) fn query(&self, generation: u64, id: u64) -> Result<Option<Operation>, Error> {
        if generation != self.generation { return Err(Error::Mismatch); }
        Ok(self.operation.filter(|o| o.id == id))
    }
    pub(crate) fn reserve(&mut self, generation: u64, id: u64, cookie: u64, intent: Intent,
                   now: u64, deadline: u64) -> Result<(), Error> {
        if generation != self.generation { return Err(Error::Mismatch); }
        if id == 0 || cookie == 0 || deadline <= now { return Err(Error::Invalid); }
        if self.operation.is_some_and(|o| o.id == id) { return Err(Error::Duplicate); }
        if self.outstanding || self.uncertain { return Err(Error::Busy); }
        self.operation = Some(Operation { id, cookie, intent, state: State::Queued, error: 0,
            command_status: None, outcome_status: None, fault_error: 0, handle: None, deadline, sent: false, out_complete: false,
            accepted: false, outcome: None, reference: None });
        self.outstanding = true;
        Ok(())
    }
    pub(crate) fn sent(&mut self, cookie: u64) -> Result<(), Error> {
        let o = self.operation.as_mut().ok_or(Error::Invalid)?;
        if o.cookie != cookie || o.state != State::Queued { return Err(Error::Mismatch); }
        o.sent = true; o.state = State::OnWire; Ok(())
    }
    pub(crate) fn out_complete(&mut self, cookie: u64, result: Result<(), i32>) -> Result<(), Error> {
        let o = self.operation.as_mut().ok_or(Error::Invalid)?;
        if o.cookie != cookie || !o.sent { return Err(Error::Mismatch); }
        if let Err(error) = result {
            o.fault_error = error; if o.state != State::Cancelled { o.state = State::Faulted; o.error = error; }
            self.uncertain = true; return Ok(());
        }
        o.out_complete = true; self.settle(); Ok(())
    }
    pub(crate) fn status(&mut self, cookie: u64, status: u8) -> Result<(), Error> {
        let o = self.operation.as_mut().ok_or(Error::Invalid)?;
        if o.cookie != cookie || !o.sent || o.accepted || o.command_status.is_some() { return Err(Error::Mismatch); }
        o.command_status = Some(status); o.accepted = status == 0;
        self.settle(); Ok(())
    }
    pub(crate) fn outcome(&mut self, generation: u64, value: Outcome) -> Result<(), Error> {
        if generation != self.generation { return Err(Error::Mismatch); }
        let o = self.operation.as_mut().ok_or(Error::Invalid)?;
        if !o.sent || !self.outstanding || o.outcome.is_some() { return Err(Error::Mismatch); }
        let matches = match (o.intent, value) {
            (Intent::Create { address_type, address }, Outcome::Connected { address_type: t, address: a, .. }) => address_type == t && address == a,
            (Intent::Disconnect { handle }, Outcome::Disconnected { handle: h, .. }) => handle == h,
            _ => false,
        };
        if !matches { return Err(Error::Mismatch); }
        o.outcome = Some(value);
        let (status, handle) = match value { Outcome::Connected { status, handle, .. } | Outcome::Disconnected { status, handle } => (status, handle) };
        o.outcome_status = Some(status); o.handle = Some(handle);
        self.settle(); Ok(())
    }
    fn settle(&mut self) {
        let Some(o) = self.operation.as_mut() else { return };
        if !o.out_complete || self.uncertain { return; }
        if o.command_status.is_some_and(|status| status != 0) {
            // Contradictory success outcome cannot be discarded as harmless.
            if o.outcome.is_some_and(|e| match e { Outcome::Connected { status, .. } | Outcome::Disconnected { status, .. } => status == 0 }) {
                self.uncertain = true; o.fault_error = -71;
                if o.state != State::Cancelled { o.state = State::Faulted; o.error = -71; }
                return;
            }
            self.outstanding = false;
            if o.state != State::Cancelled { o.state = State::Failed; o.error = -121; }
            return;
        }
        if !o.accepted { return; }
        let Some(outcome) = o.outcome else {
            if o.state != State::Cancelled { o.state = State::AwaitingOutcome; }
            return;
        };
        let (status,handle) = match outcome {
            Outcome::Connected { status,handle,.. } | Outcome::Disconnected { status,handle } => (status,handle),
        };
        o.handle = Some(handle); o.outcome_status = Some(status); self.outstanding = false;
        if o.state != State::Cancelled {
            o.state = if status == 0 { State::Succeeded } else { State::Failed };
            o.error = if status == 0 { 0 } else { -121 };
        }
    }
    pub(crate) fn cancel(&mut self, id: u64) -> Result<(), Error> {
        let o = self.operation.as_mut().ok_or(Error::Invalid)?;
        if o.id != id || !self.outstanding { return Err(Error::Mismatch); }
        o.state = State::Cancelled; o.error = -125;
        if !o.sent { self.outstanding = false; }
        // An on-wire author cancellation never cancels physical creation or
        // releases its command/outcome reservation. Caller must close any
        // late real link using its independently observed physical state.
        Ok(())
    }
    pub(crate) fn expire(&mut self, now: u64) {
        let Some(o) = self.operation.as_mut() else { return };
        if !self.outstanding || self.uncertain || now < o.deadline { return; }
        o.fault_error = -110;
        if o.state != State::Cancelled { o.error = -110; o.state = if o.sent { State::Faulted } else { State::Failed }; }
        if o.sent { self.uncertain = true; } else { self.outstanding = false; }
    }
    pub(crate) fn reservation_clear(&self) -> bool { !self.outstanding && !self.uncertain }
}

/// Fixed-size result retention is independent of physical links. Evicting an
/// author result never clears uncertainty, a wire reservation or LinkObservation.
#[derive(Clone, Copy)]
struct Record { file: u64, request: u64, operation: Operation }
const HISTORY: usize = 32;
pub(crate) struct Connections {
    session: Session,
    file: u64,
    request: u64,
    history: [Option<Record>; HISTORY],
    cursor: usize,
    cleanup: Option<Session>,
}
impl Connections {
    #[cfg(test)]
    pub(crate) const fn new() -> Self {
        Self { session: Session::empty(),
            file: 0, request: 0, history: [None; HISTORY], cursor: 0, cleanup: None }
    }
    #[cfg(not(test))]
    pub(crate) fn new_in_place() -> impl pin_init::Init<Self> {
        use kernel::prelude::*;
        init!(Self {
            session: Session::empty(),
            file: 0, request: 0, cursor: 0, cleanup: None,
            history <- pin_init::init_array_from_fn(|_| None),
        })
    }
    pub(crate) fn query(&self, file: u64, request: u64) -> Option<Operation> {
        if self.file == file && self.request == request { return self.session.operation; }
        self.history.iter().flatten().find(|r| r.file == file && r.request == request).map(|r| r.operation)
    }
    pub(crate) fn preflight(&self, file: u64, request: u64) -> Result<(), Error> {
        if file == 0 || request == 0 { return Err(Error::Invalid); }
        if self.query(file, request).is_some() { return Err(Error::Duplicate); }
        if !self.clear() { return Err(Error::Busy); }
        Ok(())
    }
    pub(crate) fn reserve(&mut self, file: u64, request: u64, cookie: u64, intent: Intent,
                         now: u64, deadline: u64, reference: Option<ExpectedLink>) -> Result<(), Error> {
        self.preflight(file, request)?;
        if cookie == 0 || deadline <= now { return Err(Error::Invalid); }
        if let Some(reference) = reference {
            if !reference.valid() || intent != (Intent::Disconnect { handle: reference.handle }) { return Err(Error::Invalid); }
        }
        let old = self.session.operation;
        self.session.reserve(1, cookie, cookie, intent, now, deadline)?;
        if let Some(operation) = self.session.operation.as_mut() { operation.reference = reference; }
        if let Some(operation) = old {
            self.history[self.cursor] = Some(Record { file: self.file, request: self.request, operation });
            self.cursor = (self.cursor + 1) % HISTORY;
        }
        self.file = file; self.request = request;
        Ok(())
    }
    fn matching_session(&mut self, cookie: u64) -> Option<&mut Session> {
        if self.session.operation.is_some_and(|o| o.cookie == cookie) { return Some(&mut self.session); }
        self.cleanup.as_mut().filter(|s| s.operation.is_some_and(|o| o.cookie == cookie))
    }
    pub(crate) fn sent(&mut self, cookie: u64) -> Result<(), Error> {
        self.matching_session(cookie).ok_or(Error::Mismatch)?.sent(cookie)
    }
    pub(crate) fn reference(&self, cookie: u64) -> Option<ExpectedLink> {
        self.session.operation.filter(|o| o.cookie == cookie).and_then(|o| o.reference)
    }
    pub(crate) fn reject_before_send(&mut self, cookie: u64, error: i32) -> Result<(), Error> {
        let session = self.matching_session(cookie).ok_or(Error::Mismatch)?;
        let operation = session.operation.as_mut().ok_or(Error::Mismatch)?;
        if operation.sent || operation.state != State::Queued { return Err(Error::Mismatch); }
        operation.state = State::Failed; operation.error = error;
        session.outstanding = false;
        Ok(())
    }
    pub(crate) fn out_complete(&mut self, cookie: u64) {
        if let Some(session) = self.matching_session(cookie) { let _ = session.out_complete(cookie, Ok(())); }
    }
    pub(crate) fn status(&mut self, cookie: u64, status: u8) -> Result<(), Error> {
        self.matching_session(cookie).ok_or(Error::Mismatch)?.status(cookie, status)
    }
    pub(crate) fn outcome(&mut self, value: Outcome) {
        let _ = self.session.outcome(1, value);
        if let Some(cleanup) = self.cleanup.as_mut() { let _ = cleanup.outcome(1, value); }
    }
    /// Internal cleanup reuses the same three-evidence procedure, without
    /// replacing/evicting the cancelled author's public record or watermark.
    pub(crate) fn reserve_cleanup(&mut self, cookie: u64, handle: u16, now: u64, deadline: u64) -> Result<(), Error> {
        if !self.clear() { return Err(Error::Busy); }
        let mut session = Session::empty();
        session.reserve(1, cookie, cookie, Intent::Disconnect { handle }, now, deadline)?;
        self.cleanup = Some(session);
        Ok(())
    }
    pub(crate) fn cancel(&mut self, file: u64, request: u64) -> Result<Option<u64>, Error> {
        if file != self.file || request != self.request { return Err(Error::Mismatch); }
        let o = self.session.operation.ok_or(Error::Mismatch)?;
        if !self.session.outstanding { return Ok(None); }
        self.session.cancel(o.id)?;
        Ok((!o.sent).then_some(o.cookie))
    }
    pub(crate) fn revoke(&mut self) -> Option<u64> {
        if !self.session.outstanding { return None; }
        self.cancel(self.file, self.request).ok().flatten()
    }
    pub(crate) fn clear(&self) -> bool {
        self.session.reservation_clear() && self.cleanup.as_ref().is_none_or(Session::reservation_clear)
    }
    pub(crate) fn fault_reason(&self) -> Option<i32> {
        let author = self.session.operation.filter(|_| self.session.uncertain).map(|o| o.fault_error).filter(|error| *error != 0);
        author.or_else(|| self.cleanup.as_ref().and_then(|s| s.operation).and_then(|o| {
            if matches!(o.state, State::Failed | State::Faulted) { Some(if o.fault_error != 0 { o.fault_error } else { o.error }) } else { None }
        }))
    }
    pub(crate) fn next_deadline(&self) -> Option<u64> {
        let deadline = |s: &Session| s.operation.filter(|_| s.outstanding && !s.uncertain).map(|o| o.deadline);
        [deadline(&self.session), self.cleanup.as_ref().and_then(deadline)].into_iter().flatten().min()
    }
    pub(crate) fn expire(&mut self, now: u64) -> Option<u64> {
        let old = self.session.operation;
        self.session.expire(now);
        if let Some(cleanup) = self.cleanup.as_mut() { cleanup.expire(now); }
        old.filter(|o| !o.sent && now >= o.deadline && !self.session.outstanding).map(|o| o.cookie)
    }
    pub(crate) fn fault(&mut self, error: i32) {
        fn latch(session: &mut Session, error: i32) {
            let Some(o) = session.operation.as_mut() else { return };
            if !session.outstanding { return; }
            if o.fault_error == 0 { o.fault_error = error; }
            if !matches!(o.state, State::Cancelled | State::Faulted) { o.state = State::Faulted; o.error = o.fault_error; }
            if o.sent { session.uncertain = true; } else { session.outstanding = false; }
        }
        latch(&mut self.session, error);
        if let Some(cleanup) = self.cleanup.as_mut() { latch(cleanup, error); }
    }

}

#[cfg(test)]
mod tests {
    use super::*;
    fn create()->Intent {Intent::Create {address_type:0,address:[1;6]}}
    fn up(status:u8)->Outcome {Outcome::Connected {status,handle:7,address_type:0,address:[1;6]}}
    fn session()->Session {let mut s=Session::new(1).unwrap();s.reserve(1,10,20,create(),0,30).unwrap();s.sent(20).unwrap();s}
    #[test]
    fn queued_reference_rejection_has_no_fabricated_wire_facts() {
        let reference=ExpectedLink {lifetime:1,handle:7,role:0,address_type:0,address:[1;6]};
        let mut c=Connections::new();
        c.reserve(42,1,10,Intent::Disconnect{handle:7},0,100,Some(reference)).unwrap();
        assert_eq!(c.reference(10),Some(reference));c.reject_before_send(10,-116).unwrap();
        let o=c.query(42,1).unwrap();assert_eq!((o.state,o.error,o.fault_error),(State::Failed,-116,0));
        assert_eq!((o.command_status,o.outcome_status,o.handle),(None,None,None));assert!(c.clear());
        c.reserve(42,2,20,create(),0,100,None).unwrap();c.sent(20).unwrap();
        assert_eq!(c.reject_before_send(20,-116),Err(Error::Mismatch));
    }
    #[test] fn status_is_acceptance_and_all_three_evidences_are_required() {
        for order in [[0,1,2],[0,2,1],[1,0,2],[1,2,0],[2,0,1],[2,1,0]] {
            let mut s=session();
            for (n,step) in order.into_iter().enumerate() {
                match step {0=>s.out_complete(20,Ok(())).unwrap(),1=>s.status(20,0).unwrap(),_=>s.outcome(1,up(0)).unwrap()}
                assert_eq!(s.query(1,10).unwrap().unwrap().state==State::Succeeded,n==2);
            }
            assert!(s.reservation_clear());
        }
    }
    #[test] fn cancelled_author_does_not_become_successful_after_late_real_link() {
        let mut s=session();s.cancel(10).unwrap();assert!(!s.reservation_clear());
        s.outcome(1,up(0)).unwrap();s.status(20,0).unwrap();s.out_complete(20,Ok(())).unwrap();
        let o=s.query(1,10).unwrap().unwrap();assert_eq!((o.state,o.error,o.handle),(State::Cancelled,-125,Some(7)));
        assert!(s.reservation_clear()); // physical link obligation remains in separate observation domain
    }
    #[test] fn wrong_identity_cookie_peer_handle_and_event_kind_do_not_complete() {
        let mut s=session();assert_eq!(s.out_complete(21,Ok(())),Err(Error::Mismatch));
        assert_eq!(s.outcome(2,up(0)),Err(Error::Mismatch));
        assert_eq!(s.outcome(1,Outcome::Connected{status:0,handle:7,address_type:1,address:[1;6]}),Err(Error::Mismatch));
        assert_eq!(s.outcome(1,Outcome::Disconnected{status:0,handle:7}),Err(Error::Mismatch));
        assert!(s.query(2,10).is_err());assert!(s.query(1,11).unwrap().is_none());
        let mut d=Session::new(2).unwrap();d.reserve(2,1,2,Intent::Disconnect{handle:7},0,30).unwrap();d.sent(2).unwrap();
        assert_eq!(d.outcome(2,Outcome::Disconnected{status:0,handle:8}),Err(Error::Mismatch));
        d.status(2,0).unwrap();d.out_complete(2,Ok(())).unwrap();assert_eq!(d.query(2,1).unwrap().unwrap().state,State::AwaitingOutcome);
        d.outcome(2,Outcome::Disconnected{status:0,handle:7}).unwrap();assert_eq!(d.query(2,1).unwrap().unwrap().state,State::Succeeded);
    }
    #[test] fn uncertain_send_and_accepted_timeout_block_reuse_and_late_success() {
        for transport_error in [false,true] {
            let mut s=session();s.status(20,0).unwrap();
            if transport_error{s.out_complete(20,Err(-5)).unwrap()}else{s.out_complete(20,Ok(())).unwrap();s.expire(30)}
            assert!(!s.reservation_clear());assert_eq!(s.query(1,10).unwrap().unwrap().state,State::Faulted);
            s.outcome(1,up(0)).unwrap();assert_eq!(s.query(1,10).unwrap().unwrap().state,State::Faulted);
            assert_eq!(s.reserve(1,11,21,create(),31,60),Err(Error::Busy));
        }
    }
    #[test] fn never_selected_cancellation_and_timeout_need_no_wire_cleanup() {
        for cancel in [false,true] {
            let mut s=Session::new(1).unwrap();s.reserve(1,10,20,create(),0,30).unwrap();
            if cancel{s.cancel(10).unwrap()}else{s.expire(30)}
            assert!(s.reservation_clear());assert_eq!(s.sent(20),Err(Error::Mismatch));
            s.reserve(1,11,21,create(),31,60).unwrap();
        }
    }
    #[test] fn cancelled_author_error_survives_transport_fault_and_deadline() {
        for fault in [false,true] {
            let mut s=session();s.cancel(10).unwrap();
            if fault{s.out_complete(20,Err(-5)).unwrap()}else{s.expire(30)}
            let o=s.query(1,10).unwrap().unwrap();assert_eq!((o.state,o.error),(State::Cancelled,-125));
            assert_eq!(o.fault_error,if fault{-5}else{-110});assert!(!s.reservation_clear());
        }
    }
    #[test] fn status_failure_conflicting_with_physical_success_is_uncertain() {
        let mut s=session();s.outcome(1,up(0)).unwrap();s.status(20,1).unwrap();s.out_complete(20,Ok(())).unwrap();
        let o=s.query(1,10).unwrap().unwrap();assert_eq!((o.state,o.error,o.fault_error),(State::Faulted,-71,-71));
        assert!(!s.reservation_clear());
    }
    #[test] fn failed_controller_status_and_outcome_preserve_raw_failures() {
        let mut s=session();s.status(20,0x0f).unwrap();s.out_complete(20,Ok(())).unwrap();
        let o=s.query(1,10).unwrap().unwrap();assert_eq!((o.state,o.command_status,o.outcome_status,o.error),(State::Failed,Some(0x0f),None,-121));
        let mut s=session();s.status(20,0).unwrap();s.out_complete(20,Ok(())).unwrap();s.outcome(1,up(0x1c)).unwrap();
        let o=s.query(1,10).unwrap().unwrap();assert_eq!((o.state,o.command_status,o.outcome_status,o.error),(State::Failed,Some(0),Some(0x1c),-121));
    }
    #[test] fn bounded_history_preserves_authors_and_cannot_revive_evicted_results() {
        let mut c=Connections::new();
        for id in 1..=40 {
            c.reserve(42,id,id,create(),id*100,id*100+50,None).unwrap();
            assert_eq!(c.cancel(43,id),Err(Error::Mismatch));
            assert_eq!(c.cancel(42,id),Ok(Some(id)));
            assert!(c.clear());
        }
        assert!(c.query(42,7).is_none());
        assert_eq!(c.query(42,8).unwrap().state,State::Cancelled);
        assert_eq!(c.query(42,40).unwrap().state,State::Cancelled);
        assert!(c.query(43,40).is_none());
        assert_eq!(c.preflight(42,40),Err(Error::Duplicate));
    }
    #[test] fn storage_revoke_deadline_and_fault_do_not_forget_physical_reservations() {
        let mut c=Connections::new();c.reserve(42,1,10,create(),0,100,None).unwrap();
        assert_eq!(c.next_deadline(),Some(100));assert_eq!(c.revoke(),Some(10));assert!(c.clear());
        c.reserve(42,2,20,create(),0,100,None).unwrap();c.sent(20).unwrap();
        assert_eq!(c.revoke(),None);assert!(!c.clear());
        c.outcome(up(0));c.status(20,0).unwrap();c.out_complete(20);
        assert_eq!(c.query(42,2).unwrap().state,State::Cancelled);assert!(c.clear());
        c.reserve(42,3,30,create(),0,100,None).unwrap();assert_eq!(c.expire(100),Some(30));assert!(c.clear());
        c.reserve(42,4,40,create(),0,100,None).unwrap();c.sent(40).unwrap();c.fault(-5);
        c.expire(1000);c.outcome(up(0));c.out_complete(40);assert!(!c.clear());
        c.fault(-110);assert_eq!(c.query(42,4).unwrap().fault_error,-5);
        assert_eq!(c.fault_reason(),Some(-5));
        let o=c.query(42,4).unwrap();assert_eq!((o.state,o.error,o.handle),(State::Faulted,-5,Some(7)));
    }

    #[test] fn internal_cleanup_keeps_author_record_and_requires_exact_real_outcome() {
        let mut c=Connections::new();c.reserve(42,1,10,create(),0,100,None).unwrap();c.cancel(42,1).unwrap();
        c.reserve_cleanup(20,7,1,100).unwrap();assert!(!c.clear());c.sent(20).unwrap();c.status(20,0).unwrap();c.out_complete(20);
        c.outcome(Outcome::Disconnected{status:0,handle:8});assert!(!c.clear());
        c.outcome(Outcome::Disconnected{status:0,handle:7});assert!(c.clear());
        assert_eq!((c.query(42,1).unwrap().state,c.query(42,1).unwrap().error),(State::Cancelled,-125));
    }

}
