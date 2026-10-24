// SPDX-License-Identifier: GPL-2.0-only
#[cfg(test)]
mod containment_regression {
    use super::*;
    use crate::{fail_at, ALLOCATIONS};
    use std::sync::atomic::Ordering::SeqCst;

    fn database(ops: OpIndicator) -> (SsapInner, u16) {
        fail_at(0);
        let mut db = SsapInner::new();
        db.register_service(SsapUuid::Uuid16(0x180f), true).unwrap();
        let handle = db
            .add_property(SsapUuid::Uuid16(0x2a19), ops, b"previous")
            .unwrap();
        (db, handle)
    }

    #[test]
    fn hostile_ingress_cannot_allocate_mutate_publish_or_ack() {
        let (mut db, handle) = database(OpIndicator::READ | OpIndicator::WRITE_WITH_RSP);
        let mut session = SsapSession::new(7);
        let mut response = [0xa5; 247];
        let mut wire = vec![0xff; 65536];
        // Includes legacy and standard control-byte opcodes; ingress rejects
        // before decode rather than claiming either format conforms.
        for opcode in 0u8..=255 {
            wire[0] = opcode;
            for size in [0, 1, 5, 247, 248, 512, 65535, 65536] {
                fail_at(1);
                assert_eq!(
                    session.process_incoming(&mut db, &wire[..size], &mut response),
                    Err(Error(-95))
                );
                assert_eq!(ALLOCATIONS.load(SeqCst), 0);
                assert_eq!(response, [0xa5; 247]);
                assert!(!session.info_exchanged && !session.reliable_mode);
                assert_eq!(db.notification_count(), 0);
            }
        }
        fail_at(0);
        assert_eq!(&*db.read_property(handle).unwrap(), b"previous");
        assert!(session.remote_db.entries.is_empty() && session.remote_db.remote_events.is_empty());
    }

    #[test]
    fn repeated_full_fragments_have_no_transaction_accumulator() {
        let (mut db, _) = database(OpIndicator::READ);
        let mut session = SsapSession::new(1);
        let mut response = [0x5a; 247];
        fail_at(1);
        for _ in 0..1024 {
            assert_eq!(
                session.process_incoming(&mut db, &[0x09; 247], &mut response),
                Err(Error(-95))
            );
        }
        assert_eq!(ALLOCATIONS.load(SeqCst), 0);
        assert_eq!(response, [0x5a; 247]);
    }

    #[test]
    fn method_without_profile_callback_does_not_echo_or_modify_database() {
        let (mut db, _) = database(OpIndicator::READ);
        let handle = db.add_method(SsapUuid::Uuid16(0x7001)).unwrap();
        fail_at(1);
        assert!(matches!(
            db.call_method(handle, b"would echo"),
            Err(Error(-95))
        ));
        assert_eq!(ALLOCATIONS.load(SeqCst), 0);
        assert!(db.services[0].methods[0].input.is_empty());
        assert!(db.services[0].methods[0].output.is_empty());
    }

    #[test]
    fn unowned_notifications_are_rejected_and_local_write_does_not_enqueue() {
        let (mut db, handle) = database(
            OpIndicator::READ
                | OpIndicator::WRITE_WITH_RSP
                | OpIndicator::NOTIFY
                | OpIndicator::INDICATE
                | OpIndicator::CLIENT_CFG_WR,
        );
        db.set_client_config(handle, 3).unwrap();
        fail_at(1);
        assert_eq!(db.notify(handle), Err(Error(-95)));
        assert_eq!(db.indicate(handle), Err(Error(-95)));
        assert_eq!(ALLOCATIONS.load(SeqCst), 0);
        fail_at(0);
        db.write_property(handle, b"local staging").unwrap();
        assert_eq!(db.notification_count(), 0);
    }

    #[test]
    fn failed_replacement_keeps_previous_property_value() {
        let (mut db, handle) = database(OpIndicator::READ | OpIndicator::WRITE_WITH_RSP);
        fail_at(1);
        assert_eq!(db.write_property(handle, b"replacement"), Err(ENOMEM));
        fail_at(0);
        assert_eq!(&*db.read_property(handle).unwrap(), b"previous");
        db.write_property(handle, b"replacement").unwrap();
        assert_eq!(&*db.read_property(handle).unwrap(), b"replacement");
    }

    #[test]
    fn local_write_limits_and_read_notify_permission_are_enforced() {
        let (mut db, handle) = database(OpIndicator::READ | OpIndicator::WRITE_WITH_RSP);
        db.services[0].properties[0].max_len = 8;
        assert_eq!(db.write_property(handle, &[0; 9]), Err(EINVAL));
        assert_eq!(db.write_property(handle, &[0; 513]), Err(EINVAL));
        assert_eq!(&*db.read_property(handle).unwrap(), b"previous");
        let (mut db, handle) = database(OpIndicator::READ | OpIndicator::NOTIFY);
        assert_eq!(db.write_property(handle, b"deny"), Err(EACCES));
        // T/XS 20001-2025 table32: b2 is write-with-response, b3 is notification.
        assert_eq!((OpIndicator::READ | OpIndicator::NOTIFY).bits(), 0x09);
        assert!(!(OpIndicator::READ | OpIndicator::NOTIFY).contains(OpIndicator::WRITE_WITH_RSP));
    }
    #[test]
    fn reserved_bits_reject_before_database_mutation_and_full_permissions_match_table32() {
        let flags = [
            OpIndicator::READ,
            OpIndicator::WRITE_NO_RSP,
            OpIndicator::WRITE_WITH_RSP,
            OpIndicator::NOTIFY,
            OpIndicator::INDICATE,
            OpIndicator::BROADCAST,
            OpIndicator::DESC_WRITABLE,
            OpIndicator::CLIENT_CFG_WR,
            OpIndicator::SERVER_CFG_WR,
        ];
        assert_eq!(
            flags.map(OpIndicator::bits),
            [1, 2, 4, 8, 16, 32, 256, 512, 1024]
        );
        for bit in 0..32 {
            if (1 << bit) & 0x73f == 0 {
                assert_eq!(OpIndicator::try_from_raw((1 << bit) | 9), Err(EINVAL));
            }
        }
        for bits in [0, 2, 4, 9, 16, 0x73f] {
            assert_eq!(OpIndicator::try_from_raw(bits).unwrap().bits(), bits);
        }
        let (mut db, _) = database(OpIndicator::READ);
        let next = db.next_handle;
        assert_eq!(
            db.add_property(SsapUuid::Uuid16(7), OpIndicator::READ, &[0; 513]),
            Err(EINVAL)
        );
        assert_eq!(db.next_handle, next);
        assert_eq!(db.property_count(), 1);
    }
}
