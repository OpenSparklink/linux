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
