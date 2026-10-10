// SPDX-License-Identifier: GPL-2.0-only
#[cfg(test)]
mod diagnostic_pending_tests {
    use super::*;
    #[test]
    fn resolved_slot_retained_until_bounded_replacement() {
        let mut q = CmdPendingQueue::new();
        let seq = q.submit(0x0403).unwrap(); q.assign_owner(seq, 42);
        assert!(q.resolve_seq(seq, 0, &[1]));
        for _ in 0..31 { q.submit(0x0402).unwrap(); }
        assert_eq!(q.find_by_seq(seq).unwrap().file_id, 42);
        q.submit(0x0402).unwrap();
        assert!(q.find_by_seq(seq).is_none());
        assert_eq!(q.pending_count, 32);
        assert_eq!(q.submit(0x0402), Err(EBUSY));
    }
    #[test]
    fn duplicate_or_unmatched_reply_cannot_rewrite_completed_result() {
        let mut q = CmdPendingQueue::new();
        let seq = q.submit(0x0403).unwrap();
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
        let rejected = q.submit(0x0402).unwrap(); q.rollback(rejected);
        assert!(q.find_by_seq(rejected).is_none());
        assert_eq!((q.pending_count, q.total_timeouts, q.total_submitted), (0, 1, 1));
    }
    #[test]
    fn sequence_exhaustion_fails_without_alias_or_accounting_change() {
        let mut q = CmdPendingQueue::new();
        q.next_seq = u32::MAX;
        assert_eq!(q.submit(0x0403), Err(EOVERFLOW));
        assert_eq!((q.pending_count, q.total_submitted, q.tail), (0, 0, 0));
    }
}
