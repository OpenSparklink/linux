// SPDX-License-Identifier: GPL-2.0-only
#![allow(dead_code)]
#[path = "../../../../net/sparklink/sle_command_plan.rs"]
mod sle_command_plan;
#[path = "../../../../net/sparklink/sle_discovery_operation.rs"]
mod sle_discovery_operation;
use sle_command_plan::DiscoveryIntent as I;
use sle_discovery_operation::{AdmissionError as E, Operation, Operations, State, CAPACITY};
fn add(ops: &mut Operations, id: u64, intent: I, count: u8) {
    let slot = ops.slot(id).unwrap();
    ops.entries[slot] = Some(Operation {
        request_id: id,
        cookie: id,
        intent,
        state: State::Queued,
        error: 0,
        status: 0,
        opcode: 0,
        step: 0,
        count,
        power_step: if intent == I::Advertising(true) {
            0
        } else {
            count
        },
        selected_power: None,
    });
}
#[test]
fn admission_and_terminal_eviction() {
    let mut o = Operations::new();
    assert_eq!(o.slot(0), Err(E::Invalid));
    for id in 1..=CAPACITY as u64 {
        add(&mut o, id, I::Advertising(false), 1);
    }
    assert_eq!(o.slot(1), Err(E::Duplicate));
    assert_eq!(o.slot(65), Err(E::Full));
    o.entries[17].as_mut().unwrap().state = State::Succeeded;
    let slot = o.slot(65).unwrap();
    assert_eq!(slot, 17);
    add(&mut o, 65, I::Scanning(false), 1);
    assert!(o.find(18).is_none());
    for id in 66..400 {
        o.entries[17].as_mut().unwrap().state = State::Succeeded;
        add(&mut o, id, I::Advertising(false), 1);
        assert!(o.find(id).is_some());
        assert!(o.find(1).is_some()); // nonterminal record survives every eviction
    }
}
#[test]
fn status_complete_power_and_failure_each_step() {
    for fail in 0..4 {
        for status in 1..=255 {
            let mut o = Operations::new();
            add(&mut o, 1, I::Advertising(true), 4);
            for step in 0..=fail {
                o.sent(1, step, 0xc02 + step as u16);
                o.reply(1, step, false, 0, &[], true);
                assert_eq!(o.find(1).unwrap().state, State::Pending);
                o.reply(
                    1,
                    step,
                    true,
                    if step == fail { status } else { 0 },
                    &[0xd6],
                    true,
                );
            }
            let r = o.find(1).unwrap();
            assert_eq!(r.state, State::Failed);
            assert_eq!(r.status, status);
            assert_eq!(r.step, fail);
            assert_eq!(r.error, 0);
            assert_eq!(r.selected_power, if fail == 0 { None } else { Some(-42) });
            assert_eq!(o.advertising, 0); // never confirm a failed enable
        }
    }
}
#[test]
fn stop_stays_on_until_complete_and_failed_stop_keeps_on() {
    let mut o = Operations::new();
    o.advertising = 2;
    add(&mut o, 1, I::Advertising(false), 1);
    o.sent(1, 0, 0xc05);
    o.reply(1, 0, false, 0, &[], true);
    assert_eq!(o.advertising, 2);
    o.reply(1, 0, true, 0xfd, &[], true);
    assert_eq!(o.advertising, 2);
    add(&mut o, 2, I::Advertising(false), 1);
    o.sent(2, 0, 0xc05);
    o.reply(2, 0, true, 0, &[], true);
    assert_eq!(o.advertising, 1);
}
#[test]
fn cancelled_enable_is_uncertain_until_stop_barrier() {
    let mut o = Operations::new();
    o.advertising = 1;
    o.scanning = 1;
    add(&mut o, 1, I::Advertising(true), 3);
    o.sent(1, 2, 0xc05);
    o.cancel_domain(I::Advertising(false), -125);
    add(&mut o, 2, I::Advertising(false), 1);
    o.reply(1, 2, true, 0, &[], false);
    assert_eq!(o.advertising, 0);
    assert_eq!(o.find(1).unwrap().state, State::Cancelled);
    o.sent(2, 0, 0xc05);
    o.reply(2, 0, true, 0, &[], true);
    assert_eq!(o.advertising, 1);
    assert!(o.can_start(I::Scanning(true)));
}
#[test]
fn radio_unknown_and_other_domain_pending_block_start() {
    let mut o = Operations::new();
    assert!(!o.can_start(I::Advertising(true)));
    o.advertising = 1;
    assert!(!o.can_start(I::Advertising(true)));
    o.scanning = 1;
    assert!(o.can_start(I::Advertising(true)));
    add(&mut o, 1, I::Scanning(false), 1);
    assert!(!o.can_start(I::Advertising(true)));
    o.sent(1, 0, 0x1002);
    o.reply(1, 0, true, 0, &[], true);
    assert!(o.can_start(I::Advertising(true)));
}
#[test]
fn faults_are_per_owner_and_do_not_rewrite_terminal_results() {
    let mut a = Operations::new();
    let mut b = Operations::new();
    for o in [&mut a, &mut b] {
        add(o, 1, I::Advertising(false), 1);
        add(o, 2, I::Scanning(false), 1);
    }
    a.sent(1, 0, 0xc05);
    a.reply(1, 0, true, 0, &[], true);
    a.fault(-110);
    assert_eq!(a.find(1).unwrap().state, State::Succeeded);
    assert_eq!(a.find(2).unwrap().state, State::Faulted);
    assert_eq!(a.find(2).unwrap().error, -110);
    assert_eq!(a.advertising, 0);
    assert_eq!(b.find(2).unwrap().state, State::Queued);
}
#[test]
fn result_reads_are_independent_and_original_power_byte_survives() {
    for byte in 0..=255u8 {
        let mut o = Operations::new();
        add(&mut o, 1, I::Advertising(true), 1);
        o.sent(1, 0, 0xc05);
        o.reply(1, 0, true, 0, &[byte], true);
        for _ in 0..10 {
            let r = o.find(1).unwrap();
            assert_eq!(r.selected_power, Some(byte as i8));
            assert_eq!(r.state, State::Succeeded);
        }
        assert_eq!(o.advertising, 2);
    }
}
