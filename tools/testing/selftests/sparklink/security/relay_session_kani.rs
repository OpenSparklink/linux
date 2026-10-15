// SPDX-License-Identifier: GPL-2.0-only
pub mod relay {
    include!("../../../../../net/sparklink/sle_security_relay_state.rs");

    #[cfg(kani)]
    mod verification {
        use super::*;
        fn key() -> Identity {
            Identity {
                controller: 1,
                generation: 2,
                lifetime: 3,
                handle: 0,
                grant_epoch: 4,
            }
        }

        // Exact production transitions, one capability request and one real
        // reply. The callback is nondeterministic accepted/NEVER queued; it
        // does not model HCD locks, callback draining or wire uniqueness.
        #[kani::proof]
        #[kani::unwind(12)]
        fn capability_withdraw_deadline_and_submit() {
            let mut s = match Session::new(key(), 0, 100) {
                Ok(value) => value,
                Err(_) => {
                    assert!(false);
                    return;
                }
            };
            let packet = match s.approve_capabilities(key(), 1, 0, true) {
                Ok(Some(value)) => value,
                _ => {
                    assert!(false);
                    return;
                }
            };
            let before: bool = kani::any();
            let expiry: bool = kani::any();
            let accepted: bool = kani::any();
            let foreign: bool = kani::any();
            let now: u64 = kani::any();
            if before {
                if expiry {
                    s.expire(100);
                } else {
                    s.withdraw();
                }
            }
            let mut current = key();
            if foreign {
                current.lifetime = 4;
            }
            let mut called = false;
            let result = s.commit(packet.ticket, current, now, || {
                called = true;
                if accepted { Ok(()) } else { Err(()) }
            });
            let submitted = !before && !foreign && now < 100 && accepted;
            assert!(result.is_ok() == submitted);
            assert!(called == (!before && !foreign && now < 100));
            assert!(s.outstanding() == submitted);
            if expiry {
                s.expire(100);
            } else {
                s.withdraw();
            }
            assert!(s.outstanding() == submitted);
            assert!(s.queued() == 0);
            let mut resubmitted = false;
            assert!(
                s.commit(packet.ticket, key(), 101, || {
                    resubmitted = true;
                    Ok(())
                })
                .is_err()
            );
            assert!(!resubmitted);
            let offer = [3, 0, 0, 16, 0, 2, 2, 2, 2, 0];
            assert!(s.receive_capabilities(key(), 101, 0x135, &offer).is_err());
            // A terminal reply may pay only the original physical obligation.
            let paid = s.reply(packet.ticket, 102, true, 0);
            assert!(paid.is_some() == submitted);
            assert!(!s.outstanding());
            let observation = match s.capability_observation(102) {
                Some(value) => value,
                None => {
                    assert!(false);
                    return;
                }
            };
            assert!(observation.state != 4);
            assert!(observation.flags & 6 == 0);
            assert!((observation.flags & 1 != 0) == submitted);
        }

        #[kani::proof]
        #[kani::unwind(12)]
        fn capability_requires_peer_and_terminal_complete() {
            let mut s = match Session::new(key(), 0, 100) {
                Ok(value) => value,
                Err(_) => {
                    assert!(false);
                    return;
                }
            };
            let packet = match s.approve_capabilities(key(), 1, 0, true) {
                Ok(Some(value)) => value,
                _ => {
                    assert!(false);
                    return;
                }
            };
            let offer = [3, 0, 0, 16, 0, 2, 2, 2, 2, 0];
            assert!(s.receive_capabilities(key(), 2, 0x135, &offer).is_err());
            assert!(s.commit(packet.ticket, key(), 3, || Ok(())).is_ok());
            // A successful Status is not a terminal Complete.
            assert!(s.reply(packet.ticket, 4, false, 0).is_none());
            assert!(s.outstanding());
            let complete_first: bool = kani::any();
            let fail: bool = kani::any();
            if complete_first {
                assert!(
                    s.reply(packet.ticket, 5, true, if fail { 1 } else { 0 })
                        .is_some()
                );
            } else {
                assert!(s.receive_capabilities(key(), 5, 0x135, &offer).is_ok());
            }
            let partial = match s.capability_observation(6) {
                Some(value) => value,
                None => {
                    assert!(false);
                    return;
                }
            };
            assert!(partial.state != 4);
            if complete_first {
                let received = s.receive_capabilities(key(), 7, 0x135, &offer);
                assert!(received.is_ok() != fail);
            } else {
                assert!(
                    s.reply(packet.ticket, 7, true, if fail { 1 } else { 0 })
                        .is_some()
                );
            }
            let terminal = match s.capability_observation(8) {
                Some(value) => value,
                None => {
                    assert!(false);
                    return;
                }
            };
            assert!((terminal.state == 4) != fail);
            if !fail {
                assert!(terminal.flags == 7);
            }
            assert!(!s.outstanding());
            assert!(s.reply(packet.ticket, 9, true, 0).is_none());
        }

        #[kani::proof]
        #[kani::unwind(12)]
        fn bounded_transitions() {
            let mut s = Session::new(key(), 0, 100).unwrap();
            let mut ticket = Ticket {
                identity: key(),
                cookie: 0,
            };
            for _ in 0..8 {
                let now: u64 = kani::any();
                let action: u8 = kani::any();
                match action % 9 {
                    0 => {
                        let bytes: [u8; 3] = kani::any();
                        let length: u8 = kani::any();
                        if let Ok(t) =
                            s.enqueue(key(), now, kani::any(), &bytes[..(length % 4) as usize])
                        {
                            ticket = t;
                        }
                    }
                    1 => {
                        let _ = s.prepare(key(), now);
                    }
                    2 => {
                        let previous = s.phase();
                        let in_flight = s.outstanding();
                        let accepted: bool = kani::any();
                        let mut called = false;
                        let result = s.commit(ticket, key(), now, || {
                            called = true;
                            if accepted { Ok(()) } else { Err(()) }
                        });
                        if called {
                            assert_eq!(previous, Phase::Open);
                            assert!(!in_flight);
                            assert!(now < 100);
                        }
                        if result.is_ok() {
                            assert!(called);
                            assert!(s.outstanding());
                        }
                        if called && !accepted {
                            assert_eq!(result, Err(Error::NeverSubmitted));
                            assert!(!s.outstanding());
                        }
                    }
                    3 => {
                        let was_active = s.outstanding();
                        let complete: bool = kani::any();
                        let status: u8 = kani::any();
                        if let Some((observed, author_live)) =
                            s.reply(ticket, now, complete, status)
                        {
                            assert!(was_active);
                            assert!(complete || status != 0);
                            assert_eq!(observed, status);
                            assert!(!s.outstanding());
                            if author_live {
                                assert_eq!(s.phase(), Phase::Open);
                                assert!(now < 100);
                            }
                        }
                    }
                    4 => {
                        let was_active = s.outstanding();
                        s.withdraw();
                        assert_eq!(s.queued(), 0);
                        assert_eq!(s.outstanding(), was_active);
                    }
                    5 => {
                        s.expire(now);
                        if now >= 100 {
                            assert_ne!(s.phase(), Phase::Open);
                            assert_eq!(s.queued(), 0);
                        }
                    }
                    6 => {
                        if s.transport_failed(ticket).is_ok() {
                            assert!(s.outstanding());
                            assert!(s.reset_required());
                        }
                    }
                    7 => {
                        let mut wrong = key();
                        wrong.lifetime = 4;
                        let mut called = false;
                        assert_eq!(
                            s.commit(ticket, wrong, now, || {
                                called = true;
                                Ok(())
                            }),
                            Err(Error::Stale)
                        );
                        assert!(!called);
                    }
                    _ => {
                        let mut wrong = ticket;
                        wrong.identity.generation = 3;
                        assert_eq!(s.reply(wrong, now, true, 0), None);
                    }
                }
                assert!(s.queued() <= QUEUE_DEPTH);
                if s.reset_required() {
                    assert_ne!(s.phase(), Phase::Open);
                }
                if s.phase() == Phase::Closed {
                    assert!(!s.outstanding());
                    assert_eq!(s.queued(), 0);
                }
                if s.phase() != Phase::Open {
                    assert_eq!(s.queued(), 0);
                }
            }
        }

        #[kani::proof]
        #[kani::unwind(12)]
        fn arbitrary_cookie_overflow_and_snapshot() {
            let mut s = Session::new(key(), 0, 100).unwrap();
            let cookie: u64 = kani::any();
            s.next_cookie = cookie; // Construct arbitrary counter state, not a second implementation.
            let bytes: [u8; 3] = kani::any();
            let result = s.enqueue(key(), 1, kani::any(), &bytes);
            if cookie == u64::MAX {
                assert_eq!(result, Err(Error::Overflow));
                assert_eq!(s.queued(), 0);
            } else {
                assert_eq!(result.unwrap().cookie, cookie);
                assert_eq!(s.next_cookie, cookie + 1);
                let packet = s.prepare(key(), 2).unwrap().unwrap();
                let mut out = [0u8; 260];
                assert_eq!(packet.encode(&mut out), 8);
                assert_eq!(&out[..2], &key().handle.to_le_bytes());
                assert_eq!(out[4], 3);
                assert_eq!(&out[5..8], &bytes);
            }
        }
    }
}
