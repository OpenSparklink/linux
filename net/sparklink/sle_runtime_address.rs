// SPDX-License-Identifier: GPL-2.0

//! One explicitly authorized volatile address mutation per registration.
//! No I/O, allocation, address allocation rule or second command scheduler.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Stage { Queued, SetComplete, Verified, Failed }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Failure { Invalid, Stale, Pending, Late, Mismatch }

pub(crate) struct Mutation {
    pub generation: u64,
    pub author: u64,
    pub request_id: u64,
    pub seq: u32,
    pub cookie: u64,
    pub timeout_ms: u32,
    pub deadline: u64,
    pub address: [u8; 6],
    pub stage: Stage,
}

impl Mutation {
    pub(crate) fn new(generation:u64, author:u64, request_id:u64, seq:u32,
        cookie:u64, timeout_ms:u32, deadline:u64, address:[u8;6])->Result<Self,Failure> {
        // All-FF is already excluded from Native metadata. These checks do
        // not claim official allocation or replace actual firmware validation.
        if generation==0 || author==0 || request_id==0 || seq==0 || cookie==0
            || !(1..=5000).contains(&timeout_ms) || deadline==0
            || address==[0;6] || address==[255;6] {return Err(Failure::Invalid);}
        Ok(Self {generation,author,request_id,seq,cookie,timeout_ms,deadline,address,stage:Stage::Queued})
    }

    pub(crate) fn retry(&self, generation:u64, author:u64, request_id:u64,
        timeout_ms:u32, address:[u8;6])->Result<u32,Failure> {
        if generation!=self.generation || author!=self.author || request_id!=self.request_id {
            return Err(Failure::Stale);
        }
        if timeout_ms!=self.timeout_ms || address!=self.address {return Err(Failure::Invalid);}
        Ok(self.seq) // Never replace the original deadline or submit again.
    }

    pub(crate) fn setter_reply(&mut self, cookie:u64, complete:bool, status:u8, bytes:usize) {
        if cookie!=self.cookie || self.stage!=Stage::Queued || (!complete && status==0) {return;}
        self.stage=if complete && status==0 && bytes==0 {Stage::SetComplete}else{Stage::Failed};
    }

    pub(crate) fn verify(&mut self, generation:u64, seq:u32, now:u64,
        bytes:&[u8])->Result<[u8;6],Failure> {
        if generation!=self.generation || seq<=self.seq {return Err(Failure::Stale);}
        if self.stage!=Stage::SetComplete {return Err(Failure::Pending);}
        if now>=self.deadline {self.stage=Stage::Failed;return Err(Failure::Late);}
        if bytes!=self.address {self.stage=Stage::Failed;return Err(Failure::Mismatch);}
        self.stage=Stage::Verified;Ok(self.address)
    }

    pub(crate) fn unverified(&self)->bool {self.stage!=Stage::Verified}
    pub(crate) fn next_deadline(&self)->Option<u64> {self.unverified().then_some(self.deadline)}
    pub(crate) fn withdraw(&mut self) {if self.unverified() {self.stage=Stage::Failed;}}
}

#[cfg(test)]
mod tests {
    use super::*;
    const ADDRESS:[u8;6]=[0xa6,0x7b,0x73,0x10,0xe0,1];
    fn mutation()->Mutation {Mutation::new(7,11,13,17,19,5000,101,ADDRESS).unwrap()}
    #[test]
    fn constructor_rejects_invalid_identity_and_current_metadata_values() {
        for (g,a,r,s,c,t,d,address) in [(0,11,13,17,19,5000,101,ADDRESS),
            (7,0,13,17,19,5000,101,ADDRESS),(7,11,0,17,19,5000,101,ADDRESS),
            (7,11,13,0,19,5000,101,ADDRESS),(7,11,13,17,0,5000,101,ADDRESS),
            (7,11,13,17,19,0,101,ADDRESS),(7,11,13,17,19,5001,101,ADDRESS),
            (7,11,13,17,19,5000,0,ADDRESS),(7,11,13,17,19,5000,101,[0;6]),
            (7,11,13,17,19,5000,101,[255;6])] {
            assert_eq!(Mutation::new(g,a,r,s,c,t,d,address).err(),Some(Failure::Invalid));
        }
    }
    #[test]
    fn pending_and_status_acceptance_are_not_verified_identity() {
        let mut a=mutation();assert!(a.unverified());assert_eq!(a.next_deadline(),Some(101));
        assert_eq!(a.verify(7,18,1,&ADDRESS),Err(Failure::Pending));
        a.setter_reply(19,false,0,0);assert_eq!(a.stage,Stage::Queued);
    }
    #[test]
    fn wrong_cookie_cannot_complete_setter() {
        let mut a=mutation();a.setter_reply(20,true,0,0);assert_eq!(a.stage,Stage::Queued);
    }
    #[test]
    fn rejection_and_bad_success_shape_remain_unverified() {
        for (complete,status,bytes) in [(true,15,0),(false,15,0),(true,0,1)] {
            let mut a=mutation();a.setter_reply(19,complete,status,bytes);
            assert_eq!(a.stage,Stage::Failed);assert!(a.unverified());
            assert_eq!(a.verify(7,18,1,&ADDRESS),Err(Failure::Pending));
        }
    }
    #[test]
    fn only_post_complete_matching_readback_before_deadline_verifies() {
        let mut a=mutation();a.setter_reply(19,true,0,0);
        assert_eq!(a.stage,Stage::SetComplete);assert_eq!(a.verify(7,18,100,&ADDRESS),Ok(ADDRESS));
        assert!(!a.unverified());assert_eq!(a.next_deadline(),None);
    }
    #[test]
    fn old_generation_and_old_query_do_not_change_pending_stage() {
        let mut a=mutation();a.setter_reply(19,true,0,0);
        for (generation,seq) in [(6,18),(8,18),(7,16),(7,17)] {
            assert_eq!(a.verify(generation,seq,1,&ADDRESS),Err(Failure::Stale));
            assert_eq!(a.stage,Stage::SetComplete);
        }
    }
    #[test]
    fn mismatched_or_short_readback_poison_instead_of_fallback() {
        for bytes in [&ADDRESS[..5],&[0u8;6][..]] {
            let mut a=mutation();a.setter_reply(19,true,0,0);
            assert_eq!(a.verify(7,18,1,bytes),Err(Failure::Mismatch));
            assert_eq!(a.stage,Stage::Failed);assert_eq!(a.verify(7,19,2,&ADDRESS),Err(Failure::Pending));
        }
    }
    #[test]
    fn original_deadline_and_retry_parameters_cannot_be_replaced() {
        let mut a=mutation();assert_eq!(a.retry(7,11,13,5000,ADDRESS),Ok(17));assert_eq!(a.deadline,101);
        assert_eq!(a.retry(7,11,13,4999,ADDRESS),Err(Failure::Invalid));
        assert_eq!(a.retry(7,11,14,5000,ADDRESS),Err(Failure::Stale));
        assert_eq!(a.retry(7,12,13,5000,ADDRESS),Err(Failure::Stale));
        a.setter_reply(19,true,0,0);assert_eq!(a.verify(7,18,101,&ADDRESS),Err(Failure::Late));
    }
    #[test]
    fn withdrawal_keeps_deadline_and_cannot_gain_new_qualification() {
        let mut a=mutation();a.withdraw();a.setter_reply(19,true,0,0);
        assert_eq!(a.stage,Stage::Failed);assert_eq!(a.next_deadline(),Some(101));
        assert_eq!(a.verify(7,18,1,&ADDRESS),Err(Failure::Pending));
    }
    #[test]
    fn completed_observation_is_not_rewritten_by_late_reply_or_withdrawal() {
        let mut a=mutation();a.setter_reply(19,true,0,0);a.verify(7,18,100,&ADDRESS).unwrap();
        a.setter_reply(19,true,15,0);a.withdraw();assert_eq!(a.stage,Stage::Verified);
        assert_eq!(a.verify(7,19,100,&[0;6]),Err(Failure::Pending));
    }
}
