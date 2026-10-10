// SPDX-License-Identifier: GPL-2.0-only
// Actual module/read_iter; only kernel lock, iterator and errno dependencies
// are fixtures. Do not interpret these tests as live usercopy or RF evidence.
extern crate self as kernel;
extern crate self as pin_init;

// In-place initialization is not exercised by these copy-boundary tests.
pub trait Init<T> {}
pub struct FixtureInit<T>(std::marker::PhantomData<T>);
impl<T> Init<T> for FixtureInit<T> {}
macro_rules! init {
    ($($tokens:tt)*) => {
        crate::FixtureInit::<Self>(std::marker::PhantomData)
    };
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Error(i32);
pub mod prelude {
    pub use crate::Error;
    pub type Result<T = ()> = core::result::Result<T, Error>;
    pub const EAGAIN: Error = Error(-11);
    pub const EFAULT: Error = Error(-14);
    pub const EINVAL: Error = Error(-22);
}
macro_rules! pr_warn {
    ($($arg:tt)*) => { let _ = format_args!($($arg)*); };
}
#[path = "sle_event.rs"]
mod sle_event;
use prelude::*;
use sle_event::{EventQueue, SleWireEvent};
use std::marker::PhantomData;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard};

const RECORD: usize = core::mem::size_of::<SleWireEvent>();
fn record(tag: u8) -> SleWireEvent {
    SleWireEvent::data_received(tag.into(), 1)
}
fn queue(tags: &[u8]) -> EventQueue {
    let mut q = EventQueue::new();
    for &tag in tags {
        q.push_raw(record(tag));
    }
    q
}
fn read_tags(q: &mut EventQueue, records: usize) -> Vec<u8> {
    let mut tags = Vec::new();
    let copied = q
        .copy_records(records * RECORD, |bytes| {
            tags.push(bytes[2]);
            bytes.len()
        })
        .unwrap();
    assert_eq!(copied, tags.len() * RECORD);
    tags
}

struct QueueMutex(Mutex<EventQueue>);
impl QueueMutex {
    fn lock(&self) -> MutexGuard<'_, EventQueue> {
        self.0.lock().unwrap()
    }
}
struct SparkLinkCtl {
    events: QueueMutex,
}
impl SparkLinkCtl {
    // Broadcast routing is explicitly outside this fixture's qualification.
    fn sync_broadcast(_: Pin<&Self>) {}
}
struct Kiocb<'a, T> {
    me: Pin<&'a SparkLinkCtl>,
    marker: PhantomData<T>,
}
impl<T> Kiocb<'_, T> {
    fn file(&self) -> Pin<&SparkLinkCtl> {
        self.me
    }
}
struct IovIterDest<'a> {
    capacity: usize,
    plan: &'a [usize],
    calls: usize,
    copied: Vec<u8>,
}
impl IovIterDest<'_> {
    fn len(&self) -> usize {
        self.capacity
    }
    fn copy_to_iter(&mut self, bytes: &[u8]) -> usize {
        let n = self.plan.get(self.calls).copied().unwrap_or(bytes.len());
        assert!(n <= bytes.len() && n <= self.capacity);
        self.calls += 1;
        self.copied.extend_from_slice(&bytes[..n]);
        self.capacity -= n;
        n
    }
}
trait MiscDevice {
    type Ptr;
    fn read_iter(kiocb: Kiocb<'_, Self::Ptr>, iov: &mut IovIterDest<'_>) -> Result<usize>;
}
impl MiscDevice for SparkLinkCtl {
    type Ptr = Pin<Box<Self>>;
    // @@READ_ITER@@
}
fn actual_read(
    me: Pin<&SparkLinkCtl>,
    capacity: usize,
    plan: &[usize],
) -> (Result<usize>, Vec<u8>) {
    let kiocb = Kiocb {
        me,
        marker: PhantomData,
    };
    let mut iov = IovIterDest {
        capacity,
        plan,
        calls: 0,
        copied: Vec::new(),
    };
    (SparkLinkCtl::read_iter(kiocb, &mut iov), iov.copied)
}

#[test]
fn every_partial_first_record_preserves_head_and_accounting() {
    for n in 0..RECORD {
        let mut q = queue(&[17, 18]);
        assert_eq!(q.copy_records(2 * RECORD, |_| n), Err(EFAULT));
        assert_eq!(
            (
                q.pending(),
                q.total_delivered,
                q.total_dropped,
                q.total_enqueued
            ),
            (2, 0, 0, 2)
        );
        assert_eq!(read_tags(&mut q, 2), [17, 18]);
    }
}
#[test]
fn every_partial_later_record_returns_only_committed_records() {
    for n in 0..RECORD {
        let mut q = queue(&[9, 10, 11]);
        let mut calls = 0;
        assert_eq!(
            q.copy_records(3 * RECORD, |_| {
                calls += 1;
                if calls == 1 {
                    RECORD
                } else {
                    n
                }
            }),
            Ok(RECORD)
        );
        assert_eq!((q.pending(), q.total_delivered), (2, 1));
        assert_eq!(read_tags(&mut q, 2), [10, 11]);
    }
}
#[test]
fn zero_short_and_empty_buffers_have_explicit_results() {
    let mut q = queue(&[1]);
    assert_eq!(q.copy_records(0, |_| panic!("zero read copied")), Ok(0));
    for n in 1..RECORD {
        assert_eq!(
            q.copy_records(n, |_| panic!("short buffer copied")),
            Err(EINVAL)
        );
    }
    assert_eq!((q.pending(), q.total_delivered), (1, 0));
    assert_eq!(read_tags(&mut q, 1), [1]);
    assert_eq!(
        q.copy_records(RECORD, |_| panic!("empty queue copied")),
        Err(EAGAIN)
    );
}
#[test]
fn capacity_tail_cannot_split_or_consume_next_record() {
    for tail in 0..RECORD {
        let mut q = queue(&[1, 2, 3]);
        let mut tags = Vec::new();
        assert_eq!(
            q.copy_records(2 * RECORD + tail, |b| {
                tags.push(b[2]);
                b.len()
            }),
            Ok(2 * RECORD)
        );
        assert_eq!(tags, [1, 2]);
        assert_eq!(read_tags(&mut q, 1), [3]);
    }
}
#[test]
fn wrap_and_explicit_overflow_are_distinct_from_copy_faults() {
    let mut q = EventQueue::new();
    for tag in 0..80 {
        q.push_raw(record(tag));
    }
    assert_eq!((q.pending(), q.total_dropped), (64, 16));
    assert_eq!(q.copy_records(RECORD, |_| 0), Err(EFAULT));
    assert_eq!(read_tags(&mut q, 64), (16..80).collect::<Vec<_>>());
    for tag in 80..100 {
        q.push_raw(record(tag));
    }
    assert_eq!(read_tags(&mut q, 20), (80..100).collect::<Vec<_>>());
    assert_eq!((q.total_delivered, q.total_dropped), (84, 16));
}
#[test]
fn independent_queues_do_not_lose_each_others_events() {
    let mut ring = sle_event::BroadcastRing::new();
    let before = sle_event::BroadcastRing::current_seq();
    ring.publish(record(4));
    ring.publish(record(5));
    let mut a = EventQueue::new();
    let mut b = EventQueue::new();
    let (a_count, a_seq) = ring.drain_since(before, &mut a);
    let (b_count, b_seq) = ring.drain_since(before, &mut b);
    assert_eq!((a_count, b_count), (2, 2));
    assert_eq!(a_seq, b_seq);
    assert_eq!(a.copy_records(RECORD, |_| RECORD - 1), Err(EFAULT));
    assert_eq!(read_tags(&mut b, 2), [4, 5]);
    assert_eq!(read_tags(&mut a, 2), [4, 5]);
}
#[test]
fn actual_read_iter_preserves_partial_record_and_returns_complete_prefix() {
    let me = Box::pin(SparkLinkCtl {
        events: QueueMutex(Mutex::new(queue(&[7, 8, 9]))),
    });
    let (result, bytes) = actual_read(me.as_ref(), 3 * RECORD, &[RECORD, RECORD - 1]);
    assert_eq!(result, Ok(RECORD));
    assert_eq!(bytes.len(), 2 * RECORD - 1);
    assert_eq!(me.events.lock().total_delivered, 1);
    let (result, bytes) = actual_read(me.as_ref(), 2 * RECORD, &[]);
    assert_eq!(result, Ok(2 * RECORD));
    assert_eq!((bytes[2], bytes[RECORD + 2]), (8, 9));
}
#[test]
fn actual_read_iter_fault_short_and_zero_do_not_report_eof_for_pending_record() {
    let me = Box::pin(SparkLinkCtl {
        events: QueueMutex(Mutex::new(queue(&[23]))),
    });
    assert_eq!(actual_read(me.as_ref(), RECORD, &[0]).0, Err(EFAULT));
    assert_eq!(actual_read(me.as_ref(), RECORD - 1, &[]).0, Err(EINVAL));
    assert_eq!(actual_read(me.as_ref(), 0, &[]).0, Ok(0));
    {
        let q = me.events.lock();
        assert_eq!((q.pending(), q.total_delivered), (1, 0));
    }
    assert_eq!(actual_read(me.as_ref(), RECORD, &[]).0, Ok(RECORD));
}
#[test]
fn shared_fd_serializes_readers_and_producers_through_commit() {
    let q = Arc::new(Mutex::new(queue(&[31, 32])));
    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let (finish_tx, finish_rx) = std::sync::mpsc::channel();
    let reader = Arc::clone(&q);
    let task = std::thread::spawn(move || {
        reader.lock().unwrap().copy_records(RECORD, |_| {
            entered_tx.send(()).unwrap();
            finish_rx.recv().unwrap();
            RECORD
        })
    });
    entered_rx.recv().unwrap();
    assert!(
        q.try_lock().is_err(),
        "queue must remain locked during copy"
    );
    finish_tx.send(()).unwrap();
    assert_eq!(task.join().unwrap(), Ok(RECORD));
    let mut q = q.lock().unwrap();
    q.push_raw(record(33));
    assert_eq!(read_tags(&mut q, 2), [32, 33]);
}
