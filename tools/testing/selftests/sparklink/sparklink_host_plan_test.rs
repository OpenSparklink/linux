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
        assert_eq!(queue.first_deadline(), None);
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
        assert_eq!(queue.first_deadline(), Some(123));
        for step in 0..4 {
            let request = queue.pop().unwrap();
            assert_eq!(request.cookie, 1);
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
