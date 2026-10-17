// SPDX-License-Identifier: GPL-2.0-only
#[cfg(test)]
mod diagnostic_pending_tests {
    use super::*;
    #[test]
    fn resolved_slot_retained_until_bounded_replacement() {
        let mut q = CmdPendingQueue::new();
        let seq = q.submit_with_timeout(0x0403, CMD_TIMEOUT_MS).unwrap(); q.assign_request(seq, 42, 0);
        assert!(q.resolve_seq(seq, 0, &[1]));
        for _ in 0..31 { q.submit_with_timeout(0x0402, CMD_TIMEOUT_MS).unwrap(); }
        assert_eq!(q.find_by_seq(seq).unwrap().file_id, 42);
        q.submit_with_timeout(0x0402, CMD_TIMEOUT_MS).unwrap();
        assert!(q.find_by_seq(seq).is_none());
        assert_eq!(q.pending_count, 32);
        assert_eq!(q.submit_with_timeout(0x0402, CMD_TIMEOUT_MS), Err(EBUSY));
    }
    #[test]
    fn duplicate_or_unmatched_reply_cannot_rewrite_completed_result() {
        let mut q = CmdPendingQueue::new();
        let seq = q.submit_with_timeout(0x0403, CMD_TIMEOUT_MS).unwrap();
        assert!(!q.resolve_seq(0, 0, &[9]));
        assert!(!q.resolve_seq(seq + 1, 0, &[9]));
        assert!(q.resolve_seq(seq, 0, &[1]));
        assert!(!q.resolve_seq(seq, 0xfd, &[9]));
        let e = q.find_by_seq(seq).unwrap();
        assert_eq!((e.result_status(), e.data[0], q.total_resolved), (Some(0), 1, 1));
    }
    #[test]
    fn timeout_retained_and_rollback_has_no_result() {
        let mut q = CmdPendingQueue::new();
        let seq = q.submit_with_timeout(0x0403, 0).unwrap();
        assert_eq!(q.expire_stale(), 1); assert_eq!(q.expire_stale(), 0);
        let e = q.find_by_seq(seq).unwrap();
        assert_eq!((e.error, e.result_status(), e.data_len), (-110, None, 0));
        assert!(!q.resolve_seq(seq, 0, &[9]));
        let rejected = q.submit_with_timeout(0x0402, CMD_TIMEOUT_MS).unwrap(); q.rollback(rejected);
        assert!(q.find_by_seq(rejected).is_none());
        assert_eq!((q.pending_count, q.total_timeouts, q.total_submitted), (0, 1, 1));
    }
    #[test]
    fn sequence_exhaustion_fails_without_alias_or_accounting_change() {
        let mut q = CmdPendingQueue::new();
        q.next_seq = u32::MAX;
        assert_eq!(q.submit_with_timeout(0x0403, CMD_TIMEOUT_MS), Err(EOVERFLOW));
        assert_eq!((q.pending_count, q.total_submitted, q.tail), (0, 0, 0));
    }
    #[test]
    fn local_host_failure_keeps_errno_and_never_fabricates_controller_status() {
        let mut q = CmdPendingQueue::new();
        let seq = q.submit_with_timeout(0x0406, CMD_TIMEOUT_MS).unwrap();
        q.fail_seq(seq, -110); q.fail_seq(seq, -5);
        assert!(!q.resolve_seq(seq, 0, &[9]));
        let e = q.find_by_seq(seq).unwrap();
        assert_eq!((e.error, e.result_status(), e.data_len), (-110, None, 0));
        assert_eq!((q.pending_count, q.total_resolved, q.total_timeouts), (0, 1, 1));
    }
    #[test]
    fn earliest_pending_deadline_excludes_completed_cancelled_and_rolled_back() {
        let mut q = CmdPendingQueue::new();
        let now = unsafe { kernel::bindings::jiffies_64 };
        let long = q.submit_with_timeout(0x0406, 700).unwrap();
        let short = q.submit_with_timeout(0x0403, 100).unwrap();
        let middle = q.submit_with_timeout(0x0404, 300).unwrap();
        assert_eq!(q.next_deadline(), Some(now + 100));
        assert_eq!((q.total_submitted, q.total_resolved, q.pending_count), (3, 0, 3));
        q.resolve_seq(short, 0, &[]);
        assert_eq!(q.next_deadline(), Some(now + 300));
        q.cancel_seq(middle);
        assert_eq!(q.next_deadline(), Some(now + 700));
        q.rollback(long);
        assert_eq!(q.next_deadline(), None);
    }
    #[test]
    fn deadline_observation_does_not_expire_or_renew_an_entry() {
        let mut q = CmdPendingQueue::new();
        let seq = q.submit_with_timeout(0x0403, 0).unwrap();
        let original = q.find_by_seq(seq).unwrap().deadline;
        for _ in 0..8 { assert_eq!(q.next_deadline(), Some(original)); }
        assert_eq!((q.pending_count, q.total_resolved, q.total_timeouts), (1, 0, 0));
        assert_eq!(q.expire_stale(), 1);
        assert_eq!(q.next_deadline(), None);
        assert_eq!((q.total_resolved, q.total_timeouts), (1, 1));
    }

}
