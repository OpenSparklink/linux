// SPDX-License-Identifier: GPL-2.0-only
#[path = "../../../../../net/sparklink/sle_security_relay_state.rs"]
mod relay;
use relay::*;

fn identity() -> Identity {
    Identity {
        controller: 1,
        generation: 2,
        lifetime: 3,
        handle: 0,
        grant_epoch: 4,
    }
}
fn session() -> Session {
    Session::new(identity(), 10, 100).unwrap()
}

// This is a protocol/lifetime dependency fixture, not a crypto algorithm. The
// real C primitives/material get separate actual-kernel VM tests and RF proof.
fn agreement(fail: Option<CryptoKind>, withdraw: Option<CryptoKind>, expire: bool) {
    let _ = agreement_session(fail, withdraw, expire, false);
}
fn agreement_session(
    fail: Option<CryptoKind>,
    withdraw: Option<CryptoKind>,
    expire: bool,
    install: bool,
) -> Option<[Session; 2]> {
    let g = identity();
    let mut t = g;
    t.controller = 2;
    t.generation = 3;
    let mut sides = [session(), Session::new(t, 10, 100).unwrap()];
    let initial = sides[0]
        .approve_key_agreement(g, 11, 0, true, [1; 64])
        .unwrap()
        .unwrap();
    assert!(
        sides[1]
            .approve_key_agreement(t, 11, 1, false, [2; 64])
            .unwrap()
            .is_none()
    );
    if install {
        sides[0].enable_installation(g, 11, 0).unwrap();
        sides[1].enable_installation(t, 11, 1).unwrap();
    }
    let mut pending = std::collections::VecDeque::from([(0, initial)]);
    let mut count = 0;
    while let Some((source, packet)) = pending.pop_front() {
        let identities = [g, t];
        let target = 1 - source;
        sides[source]
            .commit(packet.ticket, identities[source], 12, || Ok(()))
            .unwrap();
        let job = sides[target]
            .pairing_input(identities[target], 13, packet.index, packet.payload())
            .unwrap();
        if let Some(job) = job {
            if packet.index == 0x136 {
                assert_eq!(&job.data[..], &packet.payload()[6..]);
            } else if packet.index == 0x137 {
                assert_eq!(&job.data[..], packet.payload());
            } else {
                assert_eq!(&job.data[..16], packet.payload());
            }
            if job.kind == CryptoKind::GDerive {
                assert_eq!(job.confirm, [3; 16]);
            }
            if withdraw == Some(job.kind) {
                if expire {
                    sides[target].expire(100);
                } else {
                    sides[target].withdraw();
                }
                assert!(
                    sides[target]
                        .pairing_output(
                            identities[target],
                            if expire { 100 } else { 14 },
                            job,
                            Ok([3; 16])
                        )
                        .is_err()
                );
                assert_ne!(sides[target].capability_observation(100).unwrap().state, 8);
                return None;
            }
            let receipt = if fail == Some(job.kind) {
                Err(-129)
            } else {
                Ok([3; 16])
            };
            let result = sides[target].pairing_output(identities[target], 14, job, receipt);
            if fail == Some(job.kind) {
                assert!(result.is_err());
                let observation = sides[target].capability_observation(14).unwrap();
                assert_eq!((observation.state, observation.error), (5, -129));
                return None;
            }
            result.unwrap();
        }
        assert!(sides[source].reply(packet.ticket, 15, true, 0).is_some());
        count += 1;
        for n in [0, 1] {
            if sides[n].phase() == Phase::Open {
                if let Some(packet) = sides[n].prepare(identities[n], 16).unwrap() {
                    pending.push_back((n, packet));
                }
            }
        }
        assert!(count <= 9);
    }
    assert_eq!(count, 9);
    for s in &mut sides {
        assert!(s.key_agreement());
        assert_eq!(s.phase(), if install { Phase::Open } else { Phase::Closed });
        assert!(!s.outstanding());
        assert_eq!(s.queued(), 0);
        let result = s.capability_observation(16).unwrap();
        assert_eq!(
            (result.state, result.flags, result.error),
            (if install { 2 } else { 8 }, 7, 0)
        );
    }
    Some(sides)
}

#[test]
fn same_session_full_key_agreement_protocol_and_crypto_failures() {
    agreement(None, None, false);
    for kind in [
        CryptoKind::GPublicAndConfirm,
        CryptoKind::TPublic,
        CryptoKind::GNonce,
        CryptoKind::TDerive,
        CryptoKind::GDerive,
        CryptoKind::GProofAndRespond,
        CryptoKind::TProof,
    ] {
        agreement(Some(kind), None, false);
        agreement(None, Some(kind), false);
        agreement(None, Some(kind), true);
    }
    let mut s = session();
    s.approve_key_agreement(identity(), 11, 1, false, [1; 64])
        .unwrap();
    s.crypto_failed(-5);
    assert_eq!(s.capability_observation(12).unwrap().error, -5);
}

#[test]
fn crypto_job_requires_original_identity_ticket_and_nonterminal_session() {
    let key = identity();
    let mut s = session();
    s.approve_key_agreement(key, 11, 1, false, [1; 64]).unwrap();
    assert!(
        s.pairing_input(key, 12, 0x134, &[3, 0, 0, 16, 0, 2, 2, 2, 2, 0])
            .unwrap()
            .is_none()
    );
    let response = s.prepare(key, 13).unwrap().unwrap();
    s.commit(response.ticket, key, 14, || Ok(())).unwrap();
    let mut message = [1; 70];
    message[..6].copy_from_slice(&[16, 1, 2, 2, 2, 2]);
    let job = s.pairing_input(key, 15, 0x136, &message).unwrap().unwrap();
    assert!(s.outstanding());
    for n in 0..6 {
        let mut bad = job;
        match n {
            0 => bad.ticket.identity.controller += 1,
            1 => bad.ticket.identity.generation += 1,
            2 => bad.ticket.identity.lifetime += 1,
            3 => bad.ticket.identity.handle += 1,
            4 => bad.ticket.identity.grant_epoch += 1,
            _ => bad.ticket.cookie += 1,
        }
        assert_eq!(
            s.pairing_output(key, 16, bad, Ok([3; 16])),
            Err(Error::Stale)
        );
        assert_eq!(s.queued(), 0);
        assert!(s.outstanding());
    }
    let mut wrong_kind = job;
    wrong_kind.kind = CryptoKind::TPublic;
    assert_eq!(
        s.pairing_output(key, 16, wrong_kind, Ok([3; 16])),
        Err(Error::Stale)
    );
    s.withdraw();
    assert!(s.outstanding());
    assert_eq!(
        s.pairing_output(key, 17, job, Ok([3; 16])),
        Err(Error::Closed)
    );
    assert!(s.reply(response.ticket, 18, true, 0).is_some());
    assert!(!s.outstanding());
    assert_eq!(s.capability_observation(18).unwrap().state, 6);
}

#[test]
fn initialization_and_lengths() {
    let mut invalid = identity();
    invalid.generation = 0;
    assert!(matches!(
        Session::new(invalid, 10, 100),
        Err(Error::Invalid)
    ));
    invalid = identity();
    invalid.lifetime = 0;
    assert!(matches!(
        Session::new(invalid, 10, 100),
        Err(Error::Invalid)
    ));
    invalid = identity();
    invalid.grant_epoch = 0;
    assert!(matches!(
        Session::new(invalid, 10, 100),
        Err(Error::Invalid)
    ));
    invalid = identity();
    invalid.handle = 0x1000;
    assert!(matches!(
        Session::new(invalid, 10, 100),
        Err(Error::Invalid)
    ));
    assert!(matches!(
        Session::new(identity(), 100, 100),
        Err(Error::Expired)
    ));
    for length in 0..=256 {
        let mut s = session();
        let bytes = vec![0xa5; length];
        let result = s.enqueue(identity(), 10, 0x0134, &bytes);
        if length == 256 {
            assert_eq!(result, Err(Error::Invalid));
            continue;
        }
        let ticket = result.unwrap();
        let packet = s.prepare(identity(), 11).unwrap().unwrap();
        assert_eq!(packet.ticket, ticket);
        let mut out = [0xcc; 260];
        let size = packet.encode(&mut out);
        assert_eq!(size, length + 5);
        assert_eq!(&out[..5], &[0, 0, 0x34, 1, length as u8]);
        assert_eq!(&out[5..size], &bytes);
        assert!(out[size..].iter().all(|b| *b == 0xcc));
    }
}

#[test]
fn serialization_credit_and_status() {
    let mut s = session();
    let first = s.enqueue(identity(), 10, 0x0137, &[1; 64]).unwrap();
    let second = s.enqueue(identity(), 10, 0x0138, &[2; 16]).unwrap();
    assert_eq!(s.enqueue(identity(), 10, 0x0139, &[3]), Err(Error::Full));
    assert_eq!(s.queued(), QUEUE_DEPTH);
    assert_eq!(s.prepare(identity(), 11).unwrap().unwrap().ticket, first);
    assert_eq!(s.queued(), 1);
    assert!(!s.outstanding());
    let mut submits = 0;
    s.commit(first, identity(), 12, || {
        submits += 1;
        Ok(())
    })
    .unwrap();
    assert_eq!(submits, 1);
    assert!(s.outstanding());
    assert_eq!(
        s.commit(first, identity(), 13, || {
            submits += 1;
            Ok(())
        }),
        Err(Error::Stale)
    );
    assert_eq!(submits, 1);
    assert!(s.prepare(identity(), 13).unwrap().is_none());
    assert_eq!(s.reply(first, 14, false, 0), None); // Successful Status is not Complete.
    assert!(s.outstanding());
    assert_eq!(s.reply(second, 14, true, 0), None); // Foreign reservation cannot pay debt.
    assert!(s.outstanding());
    assert_eq!(s.reply(first, 15, true, 0), Some((0, true)));
    assert!(!s.outstanding());
    assert_eq!(s.prepare(identity(), 16).unwrap().unwrap().ticket, second);
    assert_eq!(s.reply(first, 16, true, 0), None); // Local duplicate does not revive.
    s.commit(second, identity(), 17, || Ok(())).unwrap();
    assert_eq!(s.reply(second, 18, false, 0x06), Some((0x06, true)));
}

#[test]
fn prepared_revocation_never_submits() {
    let mut s = session();
    let t = s.enqueue(identity(), 10, 0x0134, &[1]).unwrap();
    s.prepare(identity(), 11).unwrap();
    s.withdraw();
    let mut submitted = false;
    assert_eq!(
        s.commit(t, identity(), 12, || {
            submitted = true;
            Ok(())
        }),
        Err(Error::Closed)
    );
    assert!(!submitted);
    assert!(!s.outstanding());
    assert_eq!(s.phase(), Phase::Closed);
}

#[test]
fn in_flight_author_close_keeps_physical_obligation() {
    let mut s = session();
    let t = s.enqueue(identity(), 10, 0x0134, &[1]).unwrap();
    s.prepare(identity(), 11).unwrap();
    s.commit(t, identity(), 12, || Ok(())).unwrap();
    s.enqueue(identity(), 12, 0x0135, &[2]).unwrap();
    s.withdraw();
    assert_eq!(s.phase(), Phase::Closing);
    assert_eq!(s.queued(), 0);
    assert!(s.outstanding());
    assert_eq!(s.enqueue(identity(), 13, 0x0134, &[3]), Err(Error::Closed));
    assert_eq!(s.reply(t, 13, false, 0), None);
    assert_eq!(s.phase(), Phase::Closing);
    assert_eq!(s.reply(t, 14, true, 0), Some((0, false)));
    assert!(!s.outstanding());
    assert_eq!(s.phase(), Phase::Closed);
}

#[test]
fn original_deadline_covers_prepared_submitted_and_closing() {
    for submitted in [false, true] {
        for closing in [false, true] {
            let mut s = session();
            let t = s.enqueue(identity(), 10, 0x0134, &[1]).unwrap();
            s.prepare(identity(), 11).unwrap();
            if submitted {
                s.commit(t, identity(), 12, || Ok(())).unwrap();
            }
            if closing {
                s.withdraw();
            }
            s.expire(100);
            assert_eq!(
                s.phase(),
                if submitted {
                    Phase::Uncertain
                } else {
                    Phase::Closed
                }
            );
            assert_eq!(s.reset_required(), submitted);
            assert_eq!(s.outstanding(), submitted);
            if submitted {
                assert_eq!(s.reply(t, 101, true, 0), Some((0, false)));
                assert_eq!(s.phase(), Phase::Uncertain);
                assert!(s.reset_required());
            }
            assert_eq!(
                s.enqueue(identity(), 101, 0x0134, &[1]),
                Err(Error::Expired)
            );
            s.retired_after_barrier();
            assert_eq!(s.phase(), Phase::Closed);
            assert!(!s.outstanding());
        }
    }
}

#[test]
fn identity_and_device_isolation() {
    let mut s = session();
    let mut peer_id = identity();
    peer_id.controller = 2;
    let mut peer = Session::new(peer_id, 10, 100).unwrap();
    let t = s.enqueue(identity(), 10, 0x0134, &[1]).unwrap();
    s.prepare(identity(), 11).unwrap();
    for field in 0..5 {
        let mut stale = identity();
        match field {
            0 => stale.controller += 1,
            1 => stale.generation += 1,
            2 => stale.lifetime += 1,
            3 => stale.handle += 1,
            _ => stale.grant_epoch += 1,
        }
        let mut called = false;
        assert_eq!(
            s.commit(t, stale, 12, || {
                called = true;
                Ok(())
            }),
            Err(Error::Stale)
        );
        assert!(!called);
        assert!(!s.outstanding());
    }
    s.commit(t, identity(), 13, || Ok(())).unwrap();
    s.transport_failed(t).unwrap();
    assert!(s.reset_required());
    assert!(s.outstanding());
    peer.enqueue(peer_id, 14, 0x0134, &[2]).unwrap();
    assert_eq!(peer.phase(), Phase::Open);
    assert_eq!(peer.queued(), 1);
    assert!(!peer.reset_required());
    s.withdraw();
    assert_eq!(s.phase(), Phase::Uncertain);
    s.retired_after_barrier();
    assert_eq!(s.transport_failed(t), Err(Error::Stale));
}

#[test]
fn certain_submit_refusal_is_not_a_controller_completion() {
    let mut s = session();
    let t = s.enqueue(identity(), 10, 0x0134, &[1]).unwrap();
    s.prepare(identity(), 11).unwrap();
    assert_eq!(
        s.commit(t, identity(), 12, || Err(())),
        Err(Error::NeverSubmitted)
    );
    assert!(!s.outstanding());
    assert!(!s.reset_required());
    assert_eq!(s.reply(t, 13, true, 0), None);
}

#[test]
fn payload_view_is_exact_without_driver_envelope() {
    let mut s = session();
    s.enqueue(identity(), 10, 0x0147, &[2]).unwrap();
    let p = s.prepare(identity(), 11).unwrap().unwrap();
    assert_eq!(p.payload(), &[2]);
}

#[test]
fn initial_request_role_and_length_are_exact() {
    for role in 0..=2 {
        for length in 0..=255 {
            for index in [0x0133, 0x0134, 0x0135, 0x0147] {
                let expected = (role == 0 && index == 0x0133 && length == 1)
                    || (role == 1 && index == 0x0134 && length == 10);
                assert_eq!(initial_pairing_request(role, index, length), expected);
            }
        }
    }
}

#[test]
fn explicit_approved_capabilities_reuse_real_ticket_ledger() {
    let id = identity();
    let mut g = session();
    let mut t = session();
    let request = g.approve_capabilities(id, 11, 0, true).unwrap().unwrap();
    assert_eq!(request.index, 0x134);
    assert_eq!(request.payload(), [3, 0, 0, 16, 0, 2, 2, 2, 2, 0]);
    assert!(g.capability_exchange());
    assert_eq!(g.deadline(), 100);
    assert!(t.approve_capabilities(id, 11, 1, false).unwrap().is_none());
    // Before actual submission an unsolicited response cannot finish G.
    assert!(matches!(
        g.receive_capabilities(id, 12, 0x135, request.payload()),
        Err(Error::Stale)
    ));
    g.commit(request.ticket, id, 12, || Ok(())).unwrap();
    let response = t
        .receive_capabilities(id, 13, 0x134, request.payload())
        .unwrap()
        .unwrap();
    t.commit(response.ticket, id, 14, || Ok(())).unwrap();
    assert_eq!(g.capability_observation(15).unwrap().state, 2);
    assert_eq!(g.reply(request.ticket, 15, false, 0), None); // Status isn't Complete.
    g.receive_capabilities(id, 16, 0x135, response.payload())
        .unwrap();
    assert_eq!(g.capability_observation(16).unwrap().flags, 5);
    g.reply(request.ticket, 17, true, 0).unwrap();
    t.reply(response.ticket, 18, true, 0).unwrap();
    for s in [&mut g, &mut t] {
        let observation = s.capability_observation(19).unwrap();
        assert_eq!(observation.state, 4);
        assert_eq!(observation.flags, 7);
        assert_eq!(observation.peer, observation.local);
        assert_eq!(s.phase(), Phase::Closed);
        assert!(!s.outstanding());
        assert!(matches!(
            s.approve_capabilities(id, 20, 0, true),
            Err(Error::Closed)
        ));
        assert!(matches!(
            s.receive_capabilities(id, 20, 0x135, response.payload()),
            Err(Error::Closed)
        ));
    }
}

#[test]
fn approval_expiry_withdrawal_and_uncertain_failure_never_gain_capabilities() {
    for cause in 0..3 {
        let id = identity();
        let mut s = session();
        let packet = s.approve_capabilities(id, 11, 0, true).unwrap().unwrap();
        s.commit(packet.ticket, id, 12, || Ok(())).unwrap();
        match cause {
            0 => s.expire(100),
            1 => s.withdraw(),
            _ => {
                s.transport_failed(packet.ticket).unwrap();
            }
        }
        let before = s.capability_observation(100).unwrap();
        assert_ne!(before.state, 4);
        assert_eq!(before.flags, 1);
        assert!(s.outstanding());
        s.reply(packet.ticket, 101, true, 0).unwrap();
        assert_ne!(s.capability_observation(102).unwrap().state, 4);
        assert!(!s.outstanding());
        assert!(
            s.receive_capabilities(id, 102, 0x135, packet.payload())
                .is_err()
        );
    }
}

#[test]
fn stale_identity_wrong_role_and_unsupported_capabilities_do_not_send() {
    let id = identity();
    let mut s = session();
    assert!(matches!(
        s.approve_capabilities(id, 11, 1, true),
        Err(Error::Unsupported)
    ));
    let mut old = id;
    old.grant_epoch += 1;
    assert!(matches!(
        s.approve_capabilities(old, 11, 0, true),
        Err(Error::Stale)
    ));
    s.approve_capabilities(id, 11, 1, false).unwrap();
    assert!(matches!(
        s.receive_capabilities(old, 12, 0x134, &[3, 0, 0, 16, 0, 2, 2, 2, 2, 0]),
        Err(Error::Stale)
    ));
    assert!(matches!(
        s.receive_capabilities(id, 13, 0x134, &[3, 0, 5, 16, 0, 2, 2, 2, 2, 0]),
        Err(Error::Unsupported)
    ));
    let observation = s.capability_observation(14).unwrap();
    assert_eq!(observation.state, 5);
    assert_eq!(observation.flags, 0);
    assert!(!s.outstanding());
    assert!(matches!(s.prepare(id, 15), Err(Error::Closed)));
}

#[test]
fn capability_complete_before_receive_failure_and_passive_expiry_are_terminal() {
    let id = identity();
    let offer = [3, 0, 0, 16, 0, 2, 2, 2, 2, 0];
    let mut good = session();
    let p = good.approve_capabilities(id, 11, 0, true).unwrap().unwrap();
    good.commit(p.ticket, id, 12, || Ok(())).unwrap();
    good.reply(p.ticket, 13, true, 0).unwrap();
    assert_eq!(good.capability_observation(14).unwrap().flags, 3);
    good.receive_capabilities(id, 15, 0x135, &offer).unwrap();
    assert_eq!(good.capability_observation(16).unwrap().state, 4);
    let mut failed = session();
    let p = failed
        .approve_capabilities(id, 11, 0, true)
        .unwrap()
        .unwrap();
    failed.commit(p.ticket, id, 12, || Ok(())).unwrap();
    failed.reply(p.ticket, 13, false, 0x0c).unwrap();
    assert_eq!(failed.capability_observation(14).unwrap().state, 5);
    assert!(failed.receive_capabilities(id, 15, 0x135, &offer).is_err());
    assert_eq!(failed.capability_observation(16).unwrap().status, 0x0c);
    let mut passive = session();
    passive.approve_capabilities(id, 11, 1, false).unwrap();
    assert_eq!(passive.capability_observation(100).unwrap().state, 7);
    assert!(
        passive
            .receive_capabilities(id, 101, 0x134, &offer)
            .is_err()
    );
    assert!(!passive.outstanding());
    assert_eq!(passive.queued(), 0);
    let mut refused = session();
    let p = refused
        .approve_capabilities(id, 11, 0, true)
        .unwrap()
        .unwrap();
    assert!(matches!(
        refused.commit(p.ticket, id, 12, || Err(())),
        Err(Error::NeverSubmitted)
    ));
    refused.withdraw();
    assert!(!refused.outstanding());
    assert_eq!(refused.capability_observation(13).unwrap().state, 6);
}

#[test]
fn same_session_installation_requires_proof_role_request_actual_submit_accept_and_event() {
    for event_first in [false, true] {
        for complete in [false, true] {
            let mut sides = agreement_session(None, None, false, true).unwrap();
            let mut ids = [identity(), identity()];
            ids[1].controller = 2;
            ids[1].generation = 3;
            for n in 0..2 {
                let s = &mut sides[n];
                let id = ids[n];
                assert_eq!(s.installation_event(id, 17, 0x11, 0, 1), Err(Error::Stale));
                if n == 1 {
                    s.progress_installation(id, 17).unwrap();
                    assert!(s.prepare(id, 17).unwrap().is_none());
                    let mut old = id;
                    old.lifetime += 1;
                    assert_eq!(s.installation_event(old, 17, 0xe, 0, 0), Err(Error::Stale));
                    s.installation_event(id, 17, 0xe, 0, 0).unwrap();
                    assert_eq!(
                        s.installation_event(id, 17, 0xe, 0, 0),
                        Err(Error::Unsupported)
                    );
                } else {
                    assert_eq!(
                        s.installation_event(id, 17, 0xe, 0, 0),
                        Err(Error::Unsupported)
                    );
                }
                s.progress_installation(id, 18).unwrap();
                let p = s.prepare(id, 19).unwrap().unwrap();
                assert_eq!(p.index, if n == 0 { 0x1c03 } else { 0x1c05 });
                assert!(p.payload().is_empty());
                s.installation_matches(id, 20, p.ticket, p.index).unwrap();
                assert_eq!(
                    s.installation_matches(id, 20, p.ticket, 0x134),
                    Err(Error::Stale)
                );
                let mut wrong = p.ticket;
                wrong.cookie += 1;
                assert_eq!(
                    s.installation_matches(id, 20, wrong, p.index),
                    Err(Error::Stale)
                );
                s.commit(p.ticket, id, 21, || Ok(())).unwrap();
                assert_eq!(
                    s.installation_matches(id, 22, p.ticket, p.index),
                    Err(Error::Stale)
                );
                if event_first {
                    s.installation_event(id, 23, 0x11, 0, 1).unwrap();
                }
                assert_eq!(s.capability_observation(24).unwrap().state, 3);
                s.reply(p.ticket, 25, complete, 0).unwrap();
                if !event_first {
                    assert_eq!(s.capability_observation(26).unwrap().state, 3);
                    s.installation_event(id, 27, 0x11, 0, 1).unwrap();
                }
                assert_eq!(s.capability_observation(28).unwrap().state, 9);
                assert_eq!(s.phase(), Phase::Closed);
                assert!(!s.outstanding());
                assert_eq!(s.installation_event(id, 29, 0x11, 0, 1), Err(Error::Closed));
                // An actual later off event also invalidates the observation
                // beyond the old operation deadline; a late on cannot revive it.
                assert_eq!(
                    s.installation_event(id, 101, 0x11, 0, 0),
                    Err(Error::Closed)
                );
                assert_eq!(s.capability_observation(102).unwrap().state, 5);
                assert_eq!(
                    s.installation_event(id, 103, 0x11, 0, 1),
                    Err(Error::Expired)
                );
                assert_ne!(s.capability_observation(104).unwrap().state, 9);
            }
        }
    }
}

#[test]
fn installation_withdraw_expiry_reject_late_materialization_and_preserve_physical_debt() {
    for expire in [false, true] {
        for submitted in [false, true] {
            let mut sides = agreement_session(None, None, false, true).unwrap();
            let s = &mut sides[0];
            let id = identity();
            s.progress_installation(id, 18).unwrap();
            let p = s.prepare(id, 19).unwrap().unwrap();
            if submitted {
                s.commit(p.ticket, id, 20, || Ok(())).unwrap();
            }
            if expire {
                s.expire(100);
            } else {
                s.withdraw();
            }
            assert!(
                s.installation_matches(id, if expire { 100 } else { 21 }, p.ticket, p.index)
                    .is_err()
            );
            assert!(
                s.installation_event(id, if expire { 100 } else { 21 }, 0x11, 0, 1)
                    .is_err()
            );
            let mut callback = false;
            assert!(
                s.commit(p.ticket, id, if expire { 100 } else { 22 }, || {
                    callback = true;
                    Ok(())
                })
                .is_err()
            );
            assert!(!callback);
            assert_eq!(s.outstanding(), submitted);
            if submitted {
                s.reply(p.ticket, 101, false, 0).unwrap();
                assert!(!s.outstanding());
            }
            assert_ne!(s.capability_observation(102).unwrap().state, 9);
        }
    }
}

#[test]
fn failed_or_disabled_encryption_never_qualifies_and_keeps_inflight_acceptance_debt() {
    for (status, enabled) in [(1, 1), (0, 0), (0, 2)] {
        let mut sides = agreement_session(None, None, false, true).unwrap();
        let s = &mut sides[0];
        let id = identity();
        s.progress_installation(id, 18).unwrap();
        let p = s.prepare(id, 19).unwrap().unwrap();
        s.commit(p.ticket, id, 20, || Ok(())).unwrap();
        assert!(s.installation_event(id, 21, 0x11, status, enabled).is_err());
        assert!(s.outstanding());
        assert_eq!(s.capability_observation(22).unwrap().state, 5);
        s.reply(p.ticket, 23, false, 0).unwrap();
        assert_ne!(s.capability_observation(24).unwrap().state, 9);
    }
}

#[test]
fn uncertain_install_write_retains_obligation_and_requires_physical_barrier() {
    let mut sides = agreement_session(None, None, false, true).unwrap();
    let s = &mut sides[0];
    let id = identity();
    s.progress_installation(id, 18).unwrap();
    let p = s.prepare(id, 19).unwrap().unwrap();
    s.commit(p.ticket, id, 20, || Ok(())).unwrap();
    s.transport_failed(p.ticket).unwrap();
    assert!(s.outstanding());
    assert!(s.reset_required());
    assert_eq!(s.phase(), Phase::Uncertain);
    assert!(s.installation_event(id, 21, 0x11, 0, 1).is_err());
    assert!(s.installation_matches(id, 21, p.ticket, p.index).is_err());
    s.reply(p.ticket, 22, false, 0).unwrap();
    assert!(!s.outstanding());
    assert_ne!(s.capability_observation(23).unwrap().state, 9);
    assert_eq!(s.phase(), Phase::Uncertain);
}

#[test]
fn command_status_does_not_retire_async_installation_on_cancel_or_original_expiry() {
    for expire in [false, true] {
        let mut sides = agreement_session(None, None, false, true).unwrap();
        let s = &mut sides[0];
        let id = identity();
        s.progress_installation(id, 18).unwrap();
        let p = s.prepare(id, 19).unwrap().unwrap();
        s.commit(p.ticket, id, 20, || Ok(())).unwrap();
        assert!(s.installation_pending());
        s.reply(p.ticket, 21, false, 0).unwrap();
        assert!(!s.outstanding());
        assert!(s.installation_pending());
        if expire {
            s.expire(100);
        } else {
            s.withdraw();
        }
        assert_eq!(
            s.phase(),
            if expire {
                Phase::Uncertain
            } else {
                Phase::Closing
            }
        );
        assert!(s.installation_pending());
        assert_ne!(
            s.capability_observation(if expire { 100 } else { 22 })
                .unwrap()
                .state,
            9
        );
        assert!(
            s.installation_event(id, if expire { 101 } else { 23 }, 0x11, 0, 1)
                .is_err()
        );
        assert!(!s.installation_pending());
        assert_ne!(s.capability_observation(102).unwrap().state, 9);
        assert_eq!(
            s.phase(),
            if expire {
                Phase::Uncertain
            } else {
                Phase::Closed
            }
        );
        if expire {
            assert!(s.reset_required());
        }
    }
}

#[test]
fn unknown_installation_event_never_discharges_physical_debt() {
    let mut sides = agreement_session(None, None, false, true).unwrap();
    let s = &mut sides[0];
    let id = identity();
    s.progress_installation(id, 18).unwrap();
    let p = s.prepare(id, 19).unwrap().unwrap();
    s.commit(p.ticket, id, 20, || Ok(())).unwrap();
    s.reply(p.ticket, 21, false, 0).unwrap();
    assert_eq!(
        s.installation_event(id, 22, 0x11, 0, 255),
        Err(Error::Unsupported)
    );
    assert!(s.installation_pending());
    assert!(s.reset_required());
    assert_eq!(s.phase(), Phase::Uncertain);
    s.retired_after_barrier();
    assert!(!s.installation_pending());
    assert_eq!(s.phase(), Phase::Closed);
}

#[test]
fn responder_key_request_already_owns_physical_debt_before_local_submission() {
    for expire in [false, true] {
        let mut sides = agreement_session(None, None, false, true).unwrap();
        let s = &mut sides[1];
        let mut id = identity();
        id.controller = 2;
        id.generation = 3;
        s.installation_event(id, 17, 0xe, 0, 0).unwrap();
        assert!(s.installation_pending());
        assert!(!s.outstanding());
        assert_eq!(s.queued(), 0);
        if expire {
            s.expire(100);
        } else {
            s.withdraw();
        }
        assert_eq!(
            s.phase(),
            if expire {
                Phase::Uncertain
            } else {
                Phase::Closing
            }
        );
        assert!(s.installation_pending());
        assert!(s.progress_installation(id, 101).is_err());
        assert!(s.installation_event(id, 102, 0x11, 1, 0).is_err());
        assert!(!s.installation_pending());
        assert_ne!(s.capability_observation(103).unwrap().state, 9);
    }
}

#[test]
fn encryption_without_current_responder_key_is_never_current_credential() {
    let mut sides = agreement_session(None, None, false, true).unwrap();
    let s = &mut sides[1];
    let mut id = identity();
    id.controller = 2;
    id.generation = 3;
    s.installation_event(id, 17, 0xe, 0, 0).unwrap();
    assert_eq!(s.installation_event(id, 18, 0x11, 0, 1), Err(Error::Stale));
    assert!(s.installation_pending());
    assert!(s.reset_required());
    assert_eq!(s.phase(), Phase::Uncertain);
    assert_ne!(s.capability_observation(19).unwrap().state, 9);
}

#[test]
fn author_cancel_validates_identity_and_requires_an_approved_request() {
    let mut s = session();
    let id = identity();
    let mut stale = id;
    stale.lifetime += 1;
    assert_eq!(s.cancel(stale, 1), Err(Error::Stale));
    assert_eq!(s.cancel(id, 1), Err(Error::Unsupported));
    assert_eq!(s.phase(), Phase::Open);
    assert!(!s.outstanding());
}

#[test]
fn author_cancel_before_submit_rejects_old_ticket_and_keeps_one_terminal() {
    let id = identity();
    let mut s = session();
    let p = s.approve_capabilities(id, 1, 0, true).unwrap().unwrap();
    let mut stale = id;
    stale.grant_epoch += 1;
    assert_eq!(s.cancel(stale, 2), Err(Error::Stale));
    assert_eq!(s.cancel(id, 2), Ok(true));
    assert_eq!(s.phase(), Phase::Closed);
    assert_eq!(s.capability_observation(3).unwrap().state, 6);
    let mut called = false;
    assert!(s.commit(p.ticket, id, 3, || { called = true; Ok(()) }).is_err());
    assert!(!called);
    assert_eq!(s.cancel(id, 4), Ok(false));
    assert_eq!(s.capability_observation(101).unwrap().state, 6);
}

#[test]
fn author_cancel_retains_submitted_relay_until_actual_reply() {
    let id = identity();
    let mut s = session();
    let p = s.approve_capabilities(id, 1, 0, true).unwrap().unwrap();
    s.commit(p.ticket, id, 2, || Ok(())).unwrap();
    assert_eq!(s.cancel(id, 3), Ok(true));
    assert!(s.outstanding());
    assert_eq!(s.phase(), Phase::Closing);
    assert!(s.reply(p.ticket, 4, true, 0).is_some());
    assert!(!s.outstanding());
    assert_eq!(s.phase(), Phase::Closed);
    assert_eq!(s.capability_observation(5).unwrap().state, 6);
    assert_eq!(s.cancel(id, 5), Ok(false));
}

#[test]
fn author_cancel_after_install_status_keeps_async_debt_and_does_not_qualify_late_event() {
    let mut sides = agreement_session(None, None, false, true).unwrap();
    for (n, s) in sides.iter_mut().enumerate() {
        let mut id = identity();
        if n == 1 { id.controller = 2; id.generation = 3; s.installation_event(id, 17, 0xe, 0, 0).unwrap(); }
        s.progress_installation(id, 18).unwrap();
        let p = s.prepare(id, 19).unwrap().unwrap();
        s.commit(p.ticket, id, 20, || Ok(())).unwrap();
        s.reply(p.ticket, 21, false, 0).unwrap();
        assert!(!s.outstanding());
        assert!(s.installation_pending());
        assert_eq!(s.cancel(id, 22), Ok(true));
        assert_eq!(s.phase(), Phase::Closing);
        assert!(s.installation_pending());
        assert_eq!(s.cancel(id, 23), Ok(false));
        assert!(s.installation_pending());
        assert!(s.installation_event(id, 24, 0x11, 0, 1).is_err());
        assert!(!s.installation_pending());
        assert_eq!(s.capability_observation(25).unwrap().state, 6);
    }
}

#[test]
fn author_cancel_does_not_rewrite_completed_controller_encryption_or_expired_result() {
    let mut sides = agreement_session(None, None, false, true).unwrap();
    let id = identity();
    let s = &mut sides[0];
    s.progress_installation(id, 18).unwrap();
    let p = s.prepare(id, 19).unwrap().unwrap();
    s.commit(p.ticket, id, 20, || Ok(())).unwrap();
    s.reply(p.ticket, 21, false, 0).unwrap();
    s.installation_event(id, 22, 0x11, 0, 1).unwrap();
    assert_eq!(s.capability_observation(23).unwrap().state, 9);
    assert_eq!(s.cancel(id, 24), Ok(false));
    assert_eq!(s.capability_observation(25).unwrap().state, 9);
    let mut expired = session();
    expired.approve_capabilities(id, 1, 1, false).unwrap();
    assert_eq!(expired.cancel(id, 100), Ok(false));
    assert_eq!(expired.capability_observation(101).unwrap().state, 7);
}
