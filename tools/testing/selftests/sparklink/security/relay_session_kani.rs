// SPDX-License-Identifier: GPL-2.0-only
pub mod relay {
    include!("../../../../../net/sparklink/sle_security_relay_state.rs");

    #[cfg(kani)]
    mod verification {
        use super::*;
        /// Verify production deadline arithmetic over all input bit patterns,
        /// including expired/oversized budgets and overflow, without a clock
        /// or always-successful USB dependency fixture.
        #[kani::proof]
        fn absolute_policy_deadline_and_host_timer() {
            let now: u64 = kani::any();
            let deadline: u64 = kani::any();
            let maximum_ms: u32 = kani::any();
            if let Ok(accepted) = original_deadline(now, deadline, maximum_ms) {
                assert_eq!(accepted, deadline);
                assert!(deadline > now);
                assert!((1..=5000).contains(&maximum_ms));
                assert!(deadline - now <= u64::from(maximum_ms) * 1_000_000);
            }
            if deadline <= now || maximum_ms == 0 || maximum_ms > 5000 {
                assert!(original_deadline(now, deadline, maximum_ms).is_err());
            }
            let ticks: u64 = kani::any();
            // Scope: x86 supported CONFIG_HZ choices. The qualified VM config
            // is1000; production obtains its rate from msecs_to_jiffies(1000),
            // never from userspace HZ. Timer argument is not a UAPI input.
            let hz: u32 = match kani::any::<u8>() {0 => 100, 1 => 250, 2 => 300, _ => 1000};
            if let Ok(wake) = host_wake_deadline(now, deadline, ticks, hz) {
                assert!(deadline > now && deadline - now <= 5_000_000_000 && hz != 0);
                let scaled = (deadline - now).checked_mul(u64::from(hz)).unwrap();
                let rounded = scaled.checked_add(999_999_999).unwrap() / 1_000_000_000;
                assert!(wake > ticks);
                assert_eq!(wake - ticks, rounded + 1);
            }
        }

        fn key() -> Identity {
            Identity {
                controller: 1,
                generation: 2,
                lifetime: 3,
                handle: 0,
                grant_epoch: 4,
            }
        }

        // All helpers below invoke the same production transitions. Fixed
        // public-body fixtures do not prove crypto; each crypto/submit result
        // and each actual controller status has failure branches.
        fn finish_local_relay(s: &mut Session, packet: Packet, now: u64) -> bool {
            let queued: bool = kani::any();
            let result = s.commit(packet.ticket, key(), now, || {
                if queued { Ok(()) } else { Err(()) }
            });
            assert_eq!(result.is_ok(), queued);
            if !queued {
                s.withdraw();
                assert!(!s.outstanding());
                return false;
            }
            let status: u8 = kani::any();
            assert!(s.reply(packet.ticket, now + 1, true, status).is_some());
            assert!(!s.outstanding());
            if status != 0 {
                assert_ne!(s.capability_observation(now + 1).unwrap().state, 9);
                return false;
            }
            true
        }
        fn receive_crypto(s: &mut Session, index: u16, body: &[u8], now: u64) -> bool {
            let job = s.pairing_input(key(), now, index, body).unwrap().unwrap();
            let succeeds: bool = kani::any();
            let result = s.pairing_output(
                key(),
                now + 1,
                job,
                if succeeds { Ok([2; 16]) } else { Err(-129) },
            );
            assert_eq!(result.is_ok(), succeeds);
            if !succeeds {
                assert_ne!(s.capability_observation(now + 1).unwrap().state, 9);
            }
            succeeds
        }

        fn withdraw_install_author(s: &mut Session, now: u64) {
            let request_cancel: bool = kani::any();
            if request_cancel {
                assert_eq!(s.cancel(key(), now), Ok(true));
                assert_eq!(s.cancel(key(), now), Ok(false));
            } else {
                s.withdraw();
            }
        }

        #[kani::proof]
        #[kani::unwind(80)]
        fn installation_submit_cancel_accept_and_event() {
            let mut s = Session::new(key(), 0, 100).unwrap();
            let first = s
                .approve_key_agreement(key(), 1, 0, true, [1; 64])
                .unwrap()
                .unwrap();
            s.enable_installation(key(), 1, 0).unwrap();
            if !finish_local_relay(&mut s, first, 2) {
                return;
            }
            s.pairing_input(key(), 4, 0x135, &CAPABILITY_OFFER).unwrap();
            let public = s.prepare(key(), 5).unwrap().unwrap();
            if !finish_local_relay(&mut s, public, 6) {
                return;
            }
            if !receive_crypto(&mut s, 0x137, &[1; 64], 8) {
                return;
            }
            for (incoming, now) in [(0x138, 10), (0x13a, 14)] {
                if !receive_crypto(&mut s, incoming, &[1; 16], now) {
                    return;
                }
                let packet = s.prepare(key(), now + 2).unwrap().unwrap();
                if !finish_local_relay(&mut s, packet, now + 2) {
                    return;
                }
            }
            if !receive_crypto(&mut s, 0x142, &[1; 16], 18) {
                return;
            }
            assert_ne!(s.capability_observation(20).unwrap().state, 9);
            s.progress_installation(key(), 21).unwrap();
            let packet = s.prepare(key(), 22).unwrap().unwrap();
            assert_eq!(packet.index, 0x1c03);
            assert!(packet.payload().is_empty());
            let cancellation: u8 = kani::any();
            kani::assume(cancellation <= 5);
            if cancellation == 1 {
                withdraw_install_author(&mut s, 23);
            }
            if cancellation == 2 {
                s.expire(100);
            }
            let now = if cancellation == 2 { 100 } else { 23 };
            let material = s.installation_matches(key(), now, packet.ticket, packet.index);
            assert_eq!(material.is_ok(), cancellation != 1 && cancellation != 2);
            if cancellation == 3 {
                withdraw_install_author(&mut s, 23);
            }
            let accepted: bool = kani::any();
            let mut called = false;
            let submit = s.commit(packet.ticket, key(), now, || {
                called = true;
                if accepted { Ok(()) } else { Err(()) }
            });
            if (1..=3).contains(&cancellation) {
                assert!(!called);
                assert!(submit.is_err());
                assert!(!s.outstanding());
                assert!(s.installation_event(key(), now, 0x11, 0, 1).is_err());
                return;
            }
            assert!(called);
            assert_eq!(submit.is_ok(), accepted);
            if !accepted {
                s.withdraw();
                assert!(!s.outstanding());
                return;
            }
            assert!(s.outstanding());
            if cancellation == 4 {
                withdraw_install_author(&mut s, 24);
                assert!(s.outstanding());
                s.reply(packet.ticket, 25, false, 0).unwrap();
                assert!(!s.outstanding());
                assert!(s.installation_event(key(), 26, 0x11, 0, 1).is_err());
                assert_ne!(s.capability_observation(27).unwrap().state, 9);
                return;
            }
            if cancellation == 5 {
                s.reply(packet.ticket, 25, false, 0).unwrap();
                assert!(!s.outstanding());
                assert!(s.installation_pending());
                let expire: bool = kani::any();
                if expire {
                    s.expire(100);
                } else {
                    withdraw_install_author(&mut s, 26);
                }
                assert_ne!(s.phase(), Phase::Closed);
                assert!(s.installation_pending());
                assert!(
                    s.installation_event(key(), if expire { 101 } else { 26 }, 0x11, 0, 1)
                        .is_err()
                );
                assert!(!s.installation_pending());
                assert_ne!(s.capability_observation(102).unwrap().state, 9);
                return;
            }
            let event_first: bool = kani::any();
            let status: u8 = kani::any();
            let enabled: u8 = kani::any();
            let command_status: u8 = kani::any();
            if event_first {
                let _ = s.installation_event_at(key(), 25, 0x11, status, enabled, 2);
            }
            s.reply(packet.ticket, 26, false, command_status).unwrap();
            if !event_first {
                let _ = s.installation_event_at(key(), 27, 0x11, status, enabled, 2);
            }
            assert!(!s.outstanding());
            let good = status == 0 && enabled == 1 && command_status == 0;
            assert_eq!(s.capability_observation(28).unwrap().state == 9, good);
            if good {
                assert_eq!(s.security_observation(key(),2).unwrap().level,1);
                assert_eq!(s.security_observation(key(),3).unwrap().level,0);
                assert!(s.installation_event_at(key(),101,0x11,0,0,3).is_err());
                assert!(s.installation_event_at(key(),102,0x11,0,1,4).is_err());
                assert_eq!(s.capability_observation(103).unwrap().state,9);
                assert_eq!(s.security_observation(key(),4).unwrap().level,0);
            }
        }

        #[kani::proof]
        #[kani::unwind(80)]
        fn key_agreement_job_cancel_and_physical_obligation() {
            let mut s = match Session::new(key(), 0, 100) {
                Ok(value) => value,
                Err(_) => {
                    assert!(false);
                    return;
                }
            };
            assert!(s.approve_key_agreement(key(), 1, 1, false, [1; 64]).is_ok());
            assert!(
                s.pairing_input(key(), 2, 0x134, &[3, 0, 0, 16, 0, 2, 2, 2, 2, 0])
                    .is_ok()
            );
            let packet = match s.prepare(key(), 3) {
                Ok(Some(value)) => value,
                _ => {
                    assert!(false);
                    return;
                }
            };
            let accepted: bool = kani::any();
            let committed = s.commit(packet.ticket, key(), 4, || {
                if accepted { Ok(()) } else { Err(()) }
            });
            assert!(committed.is_ok() == accepted);
            let mut body = [1; 70];
            body[..6].copy_from_slice(&[16, 1, 2, 2, 2, 2]);
            let result = s.pairing_input(key(), 5, 0x136, &body);
            if !accepted {
                assert!(result.is_err());
                assert!(!s.outstanding());
                return;
            }
            let job = match result {
                Ok(Some(value)) => value,
                _ => {
                    assert!(false);
                    return;
                }
            };
            let expire: bool = kani::any();
            let crypto_success: bool = kani::any();
            if expire {
                s.expire(100);
            } else {
                s.withdraw();
            }
            assert!(s.outstanding());
            let bytes: [u8; 16] = kani::any();
            assert!(
                s.pairing_output(
                    key(),
                    if expire { 100 } else { 6 },
                    job,
                    if crypto_success { Ok(bytes) } else { Err(-129) }
                )
                .is_err()
            );
            assert!(s.queued() == 0);
            assert!(s.outstanding());
            assert!(s.reply(packet.ticket, 101, true, 0).is_some());
            assert!(!s.outstanding());
            let observation = match s.capability_observation(102) {
                Some(value) => value,
                None => {
                    assert!(false);
                    return;
                }
            };
            assert!(observation.state != 4 && observation.state != 8);
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
