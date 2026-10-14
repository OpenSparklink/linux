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
 let mut s=session();s.enqueue(identity(),10,0x0147,&[2]).unwrap();
 let p=s.prepare(identity(),11).unwrap().unwrap();assert_eq!(p.payload(),&[2]);
}

#[test] fn initial_request_role_and_length_are_exact() {
 for role in 0..=2 {for length in 0..=255 {for index in [0x0133,0x0134,0x0135,0x0147] {
  let expected=(role==0&&index==0x0133&&length==1)||(role==1&&index==0x0134&&length==10);
  assert_eq!(initial_pairing_request(role,index,length),expected);
 }}}
}
