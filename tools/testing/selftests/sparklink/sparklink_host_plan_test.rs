// SPDX-License-Identifier: GPL-2.0-only
//! Tests compile the production allocation-free queue/progress modules.
//! No USB/firmware execution or claim of native on-wire recipe/RF acceptance.

#[path = "../../../../net/sparklink/sle_command_plan.rs"]
mod sle_command_plan;
#[path = "../../../../net/sparklink/sle_command_queue.rs"]
mod sle_command_queue;

use sle_command_plan::{
    DiscoveryIntent as Intent, RecipePart, RecipeProgress, RecipeReply as Reply, RecipeTag,
};
use sle_command_queue::{CmdRequestQueue, QueueError, CMD_REQ_QUEUE_DEPTH};

fn parts() -> [RecipePart<'static>; 4] {
    [
        RecipePart {
            opcode: 0x0c02,
            params: &[0; 49],
        },
        RecipePart {
            opcode: 0x0c03,
            params: &[0, 3, 0],
        },
        RecipePart {
            opcode: 0x0c04,
            params: &[0, 3, 0],
        },
        RecipePart {
            opcode: 0x0c05,
            params: &[1, 0, 0, 0, 0],
        },
    ]
}

#[test]
fn progress_count_bounds() {
    for count in 0..=255 {
        assert_eq!(
            RecipeProgress::new(count).is_some(),
            (1..=4).contains(&count)
        );
    }
}

#[test]
fn successful_complete_only_advances_each_step() {
    for count in 1..=4 {
        let mut progress = RecipeProgress::new(count).unwrap();
        for step in 0..count {
            assert!(progress.ready(step));
            assert!(progress.sent(step));
            assert!(!progress.sent(step));
            for _ in 0..8 {
                assert_eq!(progress.reply(step, false, 0), Reply::Accepted);
                assert!(!progress.ready(step + 1));
            }
            assert_eq!(
                progress.reply(step.wrapping_add(1), true, 0),
                Reply::Ignored
            );
            assert_eq!(
                progress.reply(step, true, 0),
                if step + 1 == count {
                    Reply::Finished
                } else {
                    Reply::Next
                }
            );
            assert_eq!(progress.reply(step, true, 0), Reply::Ignored);
        }
        for step in 0..count {
            assert!(!progress.sent(step));
        }
    }
}

#[test]
fn all_failure_statuses_abort_at_every_step() {
    for complete in [false, true] {
        for status in 1..=255 {
            for failed in 0..4 {
                let mut progress = RecipeProgress::new(4).unwrap();
                for step in 0..failed {
                    assert!(progress.sent(step));
                    assert_eq!(progress.reply(step, true, 0), Reply::Next);
                }
                assert!(progress.sent(failed));
                assert_eq!(progress.reply(failed, complete, status), Reply::Failed);
                for step in 0..4 {
                    assert!(!progress.sent(step));
                }
                assert_eq!(progress.reply(failed, true, 0), Reply::Ignored);
            }
        }
    }
}

#[test]
fn canceled_ready_or_on_wire_never_advances() {
    for waiting in [false, true] {
        for canceled in 0..4 {
            let mut progress = RecipeProgress::new(4).unwrap();
            for step in 0..canceled {
                assert!(progress.sent(step));
                assert_eq!(progress.reply(step, true, 0), Reply::Next);
            }
            if waiting {
                assert!(progress.sent(canceled));
            }
            progress.cancel();
            assert_eq!(progress.reply(canceled, true, 0), Reply::Ignored);
            for step in 0..4 {
                assert!(!progress.sent(step));
            }
        }
    }
}

#[test]
fn two_owners_progress_independently() {
    let mut a = RecipeProgress::new(4).unwrap();
    let mut b = RecipeProgress::new(2).unwrap();
    assert!(a.sent(0));
    assert!(b.sent(0));
    assert_eq!(a.reply(0, false, 0xfe), Reply::Failed);
    assert_eq!(b.reply(0, false, 0), Reply::Accepted);
    assert_eq!(b.reply(0, true, 0), Reply::Next);
    a.cancel();
    assert!(b.sent(1));
    assert_eq!(b.reply(1, true, 0), Reply::Finished);
}

fn raw(queue: &mut CmdRequestQueue, seq: u32) {
    queue
        .push_tagged(
            0x0404,
            &seq.to_le_bytes(),
            seq,
            u64::from(seq),
            None,
            1000 + u64::from(seq),
        )
        .unwrap();
}

fn check_raw(queue: &mut CmdRequestQueue, seq: u32) {
    let request = queue.pop().unwrap();
    assert_eq!(request.opcode, 0x0404);
    assert_eq!(request.seq, seq);
    assert_eq!(request.cookie, u64::from(seq));
    assert_eq!(request.deadline, 1000 + u64::from(seq));
    assert!(request.recipe.is_none());
    assert_eq!(request.param_len, 4);
    assert_eq!(&request.params[..4], &seq.to_le_bytes());
    assert!(request.params[4..].iter().all(|byte| *byte == 0));
}

#[test]
fn raw_fifo_all_ring_positions() {
    let mut queue = CmdRequestQueue::new();
    for cycle in 0..128 {
        for seq in 1..=64 {
            raw(&mut queue, seq + cycle * 64);
        }
        assert_eq!(queue.len(), 64);
        assert_eq!(queue.available(), 0);
        assert_eq!(
            queue.push_tagged(1, &[], 999, 0, None, 0),
            Err(QueueError::Full)
        );
        for seq in 1..=64 {
            check_raw(&mut queue, seq + cycle * 64);
        }
        assert!(queue.is_empty());
        assert!(queue.pop().is_none());
        // Advance by one to exercise every head/tail position.
        raw(&mut queue, 999);
        check_raw(&mut queue, 999);
    }
}

#[test]
fn whole_recipe_preflight_capacity_is_atomic() {
    for existing in 0..=64 {
        for count in 1..=4 {
            let mut queue = CmdRequestQueue::new();
            for seq in 1..=existing {
                raw(&mut queue, seq);
            }
            let result = queue.push_recipe(&parts()[..count], 100, Intent::Advertising(true), 2000);
            assert_eq!(
                result,
                if existing as usize + count <= CMD_REQ_QUEUE_DEPTH {
                    Ok(())
                } else {
                    Err(QueueError::Full)
                }
            );
            for seq in 1..=existing {
                check_raw(&mut queue, seq);
            }
            if result.is_ok() {
                for step in 0..count {
                    let request = queue.pop().unwrap();
                    let tag = request.recipe.unwrap();
                    assert_eq!(
                        (request.seq, request.cookie, request.deadline),
                        (0, 100, 2000)
                    );
                    assert_eq!(
                        (tag.cookie, tag.step, tag.count),
                        (100, step as u8, count as u8)
                    );
                    assert_eq!(tag.intent, Intent::Advertising(true));
                    assert_eq!(request.opcode, parts()[step].opcode);
                    assert_eq!(
                        &request.params[..request.param_len as usize],
                        parts()[step].params
                    );
                }
            }
            assert!(queue.is_empty());
        }
    }
}

#[test]
fn invalid_last_step_never_cancels_old_recipe() {
    for bad in 0..4 {
        let mut queue = CmdRequestQueue::new();
        queue
            .push_recipe(&parts(), 1, Intent::Advertising(true), 123)
            .unwrap();
        let mut invalid = parts();
        invalid[bad].params = &[0; 256];
        assert_eq!(
            queue.push_recipe(&invalid, 2, Intent::Advertising(false), 456),
            Err(QueueError::Invalid)
        );
        assert_eq!(queue.len(), 4);
        for step in 0..4 {
            let request = queue.pop().unwrap();
            assert_eq!(request.cookie, 1);
            assert_eq!(request.deadline, 123);
            assert_eq!(request.recipe.unwrap().step, step);
        }
    }
}

#[test]
fn invalid_empty_oversized_or_zero_opcode_recipe() {
    let mut queue = CmdRequestQueue::new();
    raw(&mut queue, 1);
    let five = [
        RecipePart {
            opcode: 1,
            params: &[],
        },
        RecipePart {
            opcode: 2,
            params: &[],
        },
        RecipePart {
            opcode: 3,
            params: &[],
        },
        RecipePart {
            opcode: 4,
            params: &[],
        },
        RecipePart {
            opcode: 5,
            params: &[],
        },
    ];
    assert_eq!(
        queue.push_recipe(&[], 1, Intent::Scanning(true), 0),
        Err(QueueError::Invalid)
    );
    assert_eq!(
        queue.push_recipe(&five, 1, Intent::Scanning(true), 0),
        Err(QueueError::Invalid)
    );
    assert_eq!(
        queue.push_recipe(&parts(), 0, Intent::Scanning(true), 0),
        Err(QueueError::Invalid)
    );
    assert_eq!(
        queue.push_recipe(
            &[RecipePart {
                opcode: 0,
                params: &[]
            }],
            1,
            Intent::Scanning(true),
            0
        ),
        Err(QueueError::Invalid)
    );
    check_raw(&mut queue, 1);
    assert!(queue.is_empty());
}

#[test]
fn replacing_domain_preserves_other_domain_and_raw_order_after_wrap() {
    for position in 0..64 {
        let mut queue = CmdRequestQueue::new();
        for seq in 1..=position {
            raw(&mut queue, seq);
            check_raw(&mut queue, seq);
        }
        raw(&mut queue, 10);
        queue
            .push_recipe(&parts(), 20, Intent::Advertising(true), 200)
            .unwrap();
        raw(&mut queue, 30);
        queue
            .push_recipe(&parts()[..2], 40, Intent::Scanning(true), 400)
            .unwrap();
        raw(&mut queue, 50);
        queue
            .push_recipe(&parts()[..1], 60, Intent::Advertising(false), 600)
            .unwrap();
        check_raw(&mut queue, 10);
        check_raw(&mut queue, 30);
        for step in 0..2 {
            let request = queue.pop().unwrap();
            assert_eq!(request.cookie, 40);
            assert_eq!(request.recipe.unwrap().step, step);
        }
        check_raw(&mut queue, 50);
        let request = queue.pop().unwrap();
        assert_eq!(request.cookie, 60);
        assert_eq!(request.recipe.unwrap().intent, Intent::Advertising(false));
        assert!(queue.is_empty());
    }
}

#[test]
fn failing_recipe_removal_keeps_unrelated_fifo() {
    let mut queue = CmdRequestQueue::new();
    queue
        .push_recipe(&parts(), 10, Intent::Advertising(true), 100)
        .unwrap();
    let on_wire = queue.pop().unwrap();
    raw(&mut queue, 20);
    queue
        .push_recipe(&parts()[..2], 30, Intent::Scanning(true), 300)
        .unwrap();
    queue.remove_recipes(Intent::Advertising(false));
    assert_eq!(on_wire.recipe.unwrap().count, 4); // retained by Host, not the queue
    check_raw(&mut queue, 20);
    for _ in 0..2 {
        assert_eq!(queue.pop().unwrap().cookie, 30);
    }
    assert!(queue.is_empty());
}

#[test]
fn subsequent_start_keeps_queued_disable_barrier() {
    let mut queue = CmdRequestQueue::new();
    let stop = [RecipePart {
        opcode: 0x0c05,
        params: &[0, 0, 0, 0, 0],
    }];
    queue
        .push_recipe(&parts(), 10, Intent::Advertising(true), 100)
        .unwrap();
    queue
        .push_recipe(&stop, 20, Intent::Advertising(false), 200)
        .unwrap();
    queue
        .push_recipe(&parts(), 30, Intent::Advertising(true), 300)
        .unwrap();
    let request = queue.pop().unwrap();
    assert_eq!(request.cookie, 20);
    assert_eq!(request.recipe.unwrap().intent, Intent::Advertising(false));
    for step in 0..4 {
        let request = queue.pop().unwrap();
        assert_eq!(request.cookie, 30);
        assert_eq!(request.recipe.unwrap().step, step);
    }
    assert!(queue.is_empty());
}

#[test]
fn every_internal_parameter_length_and_zero_tail() {
    for length in 0..=255 {
        let payload = [0xa7; 255];
        let mut queue = CmdRequestQueue::new();
        queue
            .push_recipe(
                &[RecipePart {
                    opcode: 0x0c03,
                    params: &payload[..length],
                }],
                1,
                Intent::Advertising(true),
                42,
            )
            .unwrap();
        let request = queue.pop().unwrap();
        assert_eq!(request.param_len as usize, length);
        assert_eq!(&request.params[..length], &payload[..length]);
        assert!(request.params[length..].iter().all(|byte| *byte == 0));
    }
}

#[test]
fn malformed_tags_are_rejected_without_raw_insertion() {
    for count in 0..=5 {
        for step in 0..=5 {
            let tag = RecipeTag {
                cookie: 1,
                step,
                count,
                intent: Intent::Scanning(true),
            };
            let mut queue = CmdRequestQueue::new();
            let result = queue.push_tagged(0x1002, &[1, 0], 0, 1, Some(tag), 50);
            assert_eq!(result.is_ok(), count > 0 && count <= 4 && step < count);
            assert_eq!(queue.len(), u16::from(result.is_ok()));
            assert_eq!(
                queue.push_tagged(0x1002, &[1, 0], 7, 1, Some(tag), 50),
                Err(QueueError::Invalid)
            );
            assert_eq!(
                queue.push_tagged(0x1002, &[1, 0], 0, 2, Some(tag), 50),
                Err(QueueError::Invalid)
            );
            assert_eq!(
                queue.push_tagged(0x1002, &[1, 0], 0, 0, Some(tag), 50),
                Err(QueueError::Invalid)
            );
        }
    }
}

#[test]
fn passive_probe_has_an_intermediate_enable_and_a_final_stop_barrier() {
    let i = Intent::ScanningStandby;
    assert!(!i.enabled());
    assert!(i.has_enable());
    for step in 0..3 { assert_eq!(i.enables_step(step, 3), step == 1); }
    assert!(!Intent::AdvertisingStandby.has_enable());
    assert!(Intent::Advertising(true).enables_step(2, 3));
    let mut q = CmdRequestQueue::new();
    let probe = [RecipePart { opcode: 0x1001, params: &[0;8] },
                 RecipePart { opcode: 0x1002, params: &[1,0] },
                 RecipePart { opcode: 0x1002, params: &[0,0] }];
    q.push_recipe(&probe, 1, i, 100).unwrap();
    q.push_recipe(&probe[..2], 2, Intent::Scanning(true), 100).unwrap();
    // A new start must preserve the old final-OFF recipe as a barrier.
    assert_eq!(q.pop().unwrap().cookie, 1);
    q.remove_recipes(Intent::Scanning(false));
    assert!(q.pop().is_none());
}

#[test]
fn internal_revocation_retains_only_exact_cookie_single_step_confirmed_off() {
    use sle_command_plan::retained_revocation_off as retained;
    for (intent, domain) in [(Intent::Advertising(false), 0), (Intent::Scanning(false), 1)] {
        let tag=RecipeTag {cookie:11+domain as u64, step:0, count:1, intent};
        assert_eq!(retained(tag,[11,12],[1,1]),Some(domain));
        for state in [0,2,3,u32::MAX] {
            let mut radio=[1,1];radio[domain]=state;
            assert_eq!(retained(tag,[11,12],radio),None);
        }
        assert_eq!(retained(RecipeTag {cookie:99,..tag},[11,12],[1,1]),None);
        assert_eq!(retained(RecipeTag {cookie:0,..tag},[0,0],[1,1]),None);
        assert_eq!(retained(RecipeTag {count:2,..tag},[11,12],[1,1]),None);
        assert_eq!(retained(RecipeTag {step:1,..tag},[11,12],[1,1]),None);
    }
    for intent in [Intent::Advertising(true),Intent::Scanning(true),Intent::AdvertisingStandby,Intent::ScanningStandby] {
        assert_eq!(retained(RecipeTag {cookie:11,step:0,count:1,intent},[11,12],[1,1]),None);
    }
    let mut q=CmdRequestQueue::new();assert!(q.first_recipe().is_none());
    q.push_recipe(&parts()[..1],11,Intent::Advertising(false),10).unwrap();
    assert_eq!(q.first_recipe().unwrap().cookie,11);
    q.pop();assert!(q.first_recipe().is_none());
}

#[test]
fn remove_diagnostic_preserves_fifo_for_every_ring_position() {
    for shift in 0..64 {
        let mut q = CmdRequestQueue::new();
        for _ in 0..shift { raw(&mut q, 999); check_raw(&mut q, 999); }
        for seq in 1..=64 { raw(&mut q, seq); }
        q.remove_seq(0); assert_eq!(q.len(), 64);
        for seq in [1, 32, 64, 1000] { q.remove_seq(seq); }
        assert_eq!(q.len(), 61);
        for seq in 2..64 { if seq != 32 { check_raw(&mut q, seq); } }
        assert!(q.is_empty());
    }
}
#[test]
fn queued_raw_deadline_does_not_hide_recipe_deadline_or_fake_wire_fault() {
    let mut q = CmdRequestQueue::new();
    q.push_tagged(0x0406, &[], 1, 1, None, 1).unwrap();
    assert_eq!(q.first_recipe_deadline(), None);
    q.push_recipe(&parts(), 2, Intent::Scanning(true), 123).unwrap();
    assert_eq!(q.first_recipe_deadline(), Some(123));
    q.remove_seq(1); assert_eq!(q.first_recipe_deadline(), Some(123));
}

#[test]
fn revocation_mask_preserves_parameter_only_unknown_and_requires_scan_control() {
    // Registration/selection/known-radio cases, including conservative invalid history.
    for (selected, radio, required) in [
        (0, [0, 0], 0), (1, [0, 0], 1), (2, [0, 0], 0), (3, [0, 0], 1),
        (6, [0, 0], 2), (7, [0, 0], 3), (2, [0, 1], 2),
        (0, [1, 0], 1), (0, [0, 2], 2), (1, [0, 1], 3), (2, [1, 0], 1),
        (255, [0, 0], 3),
    ] {
        assert_eq!(sle_command_plan::revocation_required_domains(selected, radio), required);
    }
}

#[test]
fn native_connection_cancellation_preserves_mixed_queue_and_wraparound_order() {
    for rotation in 0..80 {
        let mut q = CmdRequestQueue::new();
        for _ in 0..rotation {
            q.push_tagged(0x0403, &[], 1, 1, None, 100).unwrap();
            q.pop().unwrap();
        }
        q.push_tagged(0x0403, &[7], 9, 50, None, 100).unwrap();
        q.push_connection(0x1401, &[1; 27], 51, 1, 115).unwrap();
        q.push_recipe(&parts(), 52, Intent::Advertising(false), 120).unwrap();
        q.push_tagged(0x0406, &[8], 10, 53, None, 130).unwrap();
        let conn = q.entries.iter().flatten().find(|r| r.cookie == 51).unwrap();
        assert_eq!((conn.connection, conn.seq, conn.deadline, conn.param_len), (Some(1), 0, 115, 27));
        assert_eq!(conn.params[..27], [1; 27]);
        let length = q.len();
        assert_eq!(q.push_connection(0x1401, &[], 54, 3, 150), Err(QueueError::Invalid));
        assert_eq!(q.len(), length);
        q.remove_cookie(51);
        let first = q.pop().unwrap();
        assert_eq!((first.cookie, first.seq, first.connection, first.params[0]), (50, 9, None, 7));
        for step in 0..4 {
            let request = q.pop().unwrap();
            assert_eq!(request.cookie, 52);
            assert_eq!(request.recipe.unwrap().step, step);
            assert_eq!(request.connection, None);
        }
        let last = q.pop().unwrap();
        assert_eq!((last.cookie, last.seq, last.connection, last.params[0]), (53, 10, None, 8));
        assert!(q.is_empty());
    }
}
