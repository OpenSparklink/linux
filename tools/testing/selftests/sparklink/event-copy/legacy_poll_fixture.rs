// SPDX-License-Identifier: GPL-2.0-only
// Actual ring/handler bodies and canonical declaration. Controller codec,
// usercopy and std mutex are dependencies, not real kernel/VFS qualification.
use std::cell::RefCell;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex, MutexGuard};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Error(i32);
type Result<T = ()> = core::result::Result<T, Error>;
const EAGAIN: Error = Error(-11);
const EFAULT: Error = Error(-14);
const ENODEV: Error = Error(-19);
// @@WIRE@@
// @@SIZE@@

struct Controller {
    incoming: VecDeque<SleDliEvent>,
    polls: usize,
}
impl Controller {
    fn poll_event(&mut self) -> Option<SleDliEvent> {
        self.polls += 1;
        self.incoming.pop_front()
    }
}
fn sle_dli_event_to_wire(event: &SleDliEvent) -> SleDliEvent {
    *event
}
struct ControllerState {
    dli_ring: [SleDliEvent; DLI_RING_SIZE],
    dli_head: usize,
    dli_tail: usize,
    controller: Controller,
}
impl ControllerState {
    // @@RING@@
}
struct RuntimeContext {
    state: Arc<Mutex<Option<ControllerState>>>,
}
impl RuntimeContext {
    fn lock(&self) -> Result<MutexGuard<'_, Option<ControllerState>>> {
        Ok(self.state.lock().unwrap())
    }
}
thread_local! {
    static LOCK_CHECK: RefCell<Option<Arc<Mutex<Option<ControllerState>>>>> = const { RefCell::new(None) };
    static OUTPUT: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
}
fn bytes(event: &SleDliEvent) -> &[u8] {
    // SAFETY: the canonical repr(C) has integer/byte fields and explicit padding;
    // every fixture event is fully initialized with the actual Default impl.
    unsafe {
        core::slice::from_raw_parts(
            (event as *const SleDliEvent).cast(),
            core::mem::size_of::<SleDliEvent>(),
        )
    }
}
fn write_user_struct(prefix: usize, event: &SleDliEvent) -> Result {
    LOCK_CHECK.with(|state| {
        assert!(
            state.borrow().as_ref().unwrap().try_lock().is_err(),
            "actual handler released state before copy/commit"
        )
    });
    OUTPUT.with(|out| *out.borrow_mut() = bytes(event)[..prefix].to_vec());
    if prefix < core::mem::size_of::<SleDliEvent>() {
        Err(EFAULT)
    } else {
        Ok(())
    }
}
// @@HANDLER@@

fn event(tag: u8) -> SleDliEvent {
    let mut event = SleDliEvent::default();
    event.event_type = 1;
    event.opcode = 0x0406;
    event.data_len = 6;
    event.data[..6].copy_from_slice(&[tag; 6]);
    event
}
fn setup(ring: &[u8], incoming: &[u8]) -> RuntimeContext {
    let mut state = ControllerState {
        dli_ring: [SleDliEvent::default(); DLI_RING_SIZE],
        dli_head: 0,
        dli_tail: 0,
        controller: Controller {
            incoming: incoming.iter().copied().map(event).collect(),
            polls: 0,
        },
    };
    for &tag in ring {
        state.push_dli_event(event(tag));
    }
    RuntimeContext {
        state: Arc::new(Mutex::new(Some(state))),
    }
}
fn poll(context: &RuntimeContext, prefix: usize) -> (Result<isize>, Vec<u8>) {
    LOCK_CHECK.with(|state| *state.borrow_mut() = Some(context.state.clone()));
    OUTPUT.with(|out| out.borrow_mut().clear());
    let result = ioctl_legacy_dli_poll(context, prefix);
    let out = OUTPUT.with(|out| out.borrow().clone());
    LOCK_CHECK.with(|state| *state.borrow_mut() = None);
    (result, out)
}
fn take(context: &RuntimeContext, tag: u8) {
    assert_eq!(poll(context, 256), (Ok(0), bytes(&event(tag)).to_vec()));
}

#[test]
fn canonical_layout_and_padding_are_initialized() {
    let e = event(17);
    assert_eq!(core::mem::size_of::<SleDliEvent>(), 256);
    assert_eq!(
        (
            e.event_type,
            e.status,
            e.handle,
            e.opcode,
            e.data_len,
            e.addr,
            e._pad
        ),
        (1, 0, 0, 0x0406, 6, [0; 6], [0; 2])
    );
    assert_eq!(&e.data[6..], &[0; 234]);
}
#[test]
fn every_ring_copy_prefix_preserves_head_and_fifo() {
    for n in 0..256 {
        let ctx = setup(&[17, 18], &[19]);
        assert_eq!(
            poll(&ctx, n),
            (Err(EFAULT), bytes(&event(17))[..n].to_vec())
        );
        {
            let s = ctx.lock().unwrap();
            let s = s.as_ref().unwrap();
            assert_eq!((s.dli_head, s.dli_tail, s.controller.polls), (0, 2, 0));
        }
        take(&ctx, 17);
        take(&ctx, 18);
        take(&ctx, 19);
        assert_eq!(poll(&ctx, 256), (Err(EAGAIN), vec![]));
    }
}
#[test]
fn every_backend_copy_prefix_stages_once_and_retries_before_next_backend_event() {
    for n in 0..256 {
        let ctx = setup(&[], &[23, 24]);
        assert_eq!(
            poll(&ctx, n),
            (Err(EFAULT), bytes(&event(23))[..n].to_vec())
        );
        {
            let s = ctx.lock().unwrap();
            let s = s.as_ref().unwrap();
            assert_eq!(
                (
                    s.dli_head,
                    s.dli_tail,
                    s.controller.polls,
                    s.controller.incoming.len()
                ),
                (0, 1, 1, 1)
            );
        }
        assert_eq!(
            poll(&ctx, 128),
            (Err(EFAULT), bytes(&event(23))[..128].to_vec())
        );
        take(&ctx, 23);
        assert_eq!(ctx.lock().unwrap().as_ref().unwrap().controller.polls, 1);
        take(&ctx, 24);
        assert_eq!(ctx.lock().unwrap().as_ref().unwrap().controller.polls, 2);
    }
}
#[test]
fn existing_ring_precedes_backend_and_commit_is_single_consumption() {
    let ctx = setup(&[1, 2], &[3]);
    take(&ctx, 1);
    take(&ctx, 2);
    assert_eq!(ctx.lock().unwrap().as_ref().unwrap().controller.polls, 0);
    take(&ctx, 3);
    assert_eq!(poll(&ctx, 256), (Err(EAGAIN), vec![]));
}
#[test]
fn ring_wrap_overflow_remain_distinct_from_copy_faults() {
    let ctx = setup(&(0..65).collect::<Vec<_>>(), &[]);
    assert_eq!(
        poll(&ctx, 127),
        (Err(EFAULT), bytes(&event(34))[..127].to_vec())
    );
    for tag in 34..65 {
        take(&ctx, tag);
    }
    assert_eq!(poll(&ctx, 256), (Err(EAGAIN), vec![]));
}
#[test]
fn empty_and_retired_contexts_do_not_copy_or_claim_success() {
    let ctx = setup(&[], &[]);
    assert_eq!(poll(&ctx, 256), (Err(EAGAIN), vec![]));
    *ctx.lock().unwrap() = None;
    assert_eq!(poll(&ctx, 256), (Err(ENODEV), vec![]));
}
