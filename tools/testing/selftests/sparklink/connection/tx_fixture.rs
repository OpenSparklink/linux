// SPDX-License-Identifier: GPL-2.0-only
// Only dependencies are fixtures. Sender and ioctl bodies are production inputs.
extern crate self as kernel;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Error(pub i32);
impl Error {
    pub fn from_errno(n: i32) -> Self {
        Self(n)
    }
}
pub type Result<T = ()> = core::result::Result<T, Error>;
pub const EINVAL: Error = Error(-22);
pub const EPIPE: Error = Error(-32);
pub const EFBIG: Error = Error(-27);
pub const EOVERFLOW: Error = Error(-75);
pub const ENOENT: Error = Error(-2);
pub const ENODEV: Error = Error(-19);
pub mod bindings {
    pub const EOPNOTSUPP: u32 = 95;
    pub const EMSGSIZE: u32 = 90;
}
pub const CONN_DATA_MAX: usize = 255;
fn jiffies_now() -> u64 {
    999
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnState {
    Connecting,
    Connected,
    DisconnectPending,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChannelState {
    Closed,
    Open,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransportMode {
    Unreliable,
    Reliable,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Channel {
    pub state: ChannelState,
    pub mode: TransportMode,
    pub mtu: u16,
    pub mps: u16,
    pub tx_credits: u16,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Channels {
    pub data: Channel,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SeqTracker {
    pub tx_seq: u8,
    pub modulus: u8,
}
impl SeqTracker {
    // @@SEQ_METHOD@@
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnEntry {
    pub handle: u16,
    pub controller_handle: Option<u16>,
    pub state: ConnState,
    pub channels: Channels,
    pub seq: SeqTracker,
    pub tx_bytes: u64,
    pub last_activity: u64,
}
pub struct ConnManager {
    pub connections: Vec<ConnEntry>,
}
impl ConnManager {
    // @@CONN_METHODS@@
}
use std::sync::{Mutex, MutexGuard};
pub struct Controller {
    pub mapped: bool,
    pub error: Option<Error>,
    pub packets: Mutex<Vec<(u16, Vec<u8>)>>,
}
impl Controller {
    fn uses_command_host(&self) -> bool {
        self.mapped
    }
    fn send_data(&self, h: u16, p: &[u8]) -> Result {
        self.packets.lock().unwrap().push((h, p.to_vec()));
        self.error.map_or(Ok(()), Err)
    }
}
pub struct ControllerState {
    pub controller: Controller,
    pub conn: ConnManager,
}
pub struct RuntimeContext(pub Mutex<Option<ControllerState>>);
impl RuntimeContext {
    fn lock(&self) -> Result<MutexGuard<'_, Option<ControllerState>>> {
        Ok(self.0.lock().unwrap())
    }
}
#[derive(Clone, Copy)]
pub struct SleConnData {
    pub handle: u16,
    pub length: u16,
    pub data: [u8; CONN_DATA_MAX],
}
fn read_user_struct<T: Copy>(arg: usize) -> Result<T> {
    Ok(unsafe { *(arg as *const T) })
}
pub mod sle_conn {
    pub mod tcid {
        pub const DEFAULT_DATA: u16 = 0x1f;
    }
}
// @@IOCTL@@
fn entry(h: u16) -> ConnEntry {
    ConnEntry {
        handle: h,
        controller_handle: None,
        state: ConnState::Connected,
        channels: Channels {
            data: Channel {
                state: ChannelState::Open,
                mode: TransportMode::Unreliable,
                mtu: 247,
                mps: 247,
                tx_credits: 0,
            },
        },
        seq: SeqTracker {
            tx_seq: 0,
            modulus: 2,
        },
        tx_bytes: 0,
        last_activity: 7,
    }
}
fn runtime(mapped: bool) -> RuntimeContext {
    RuntimeContext(Mutex::new(Some(ControllerState {
        controller: Controller {
            mapped,
            error: None,
            packets: Mutex::new(Vec::new()),
        },
        conn: ConnManager {
            connections: vec![entry(42), entry(77)],
        },
    })))
}
fn submit(r: &RuntimeContext, h: u16, length: u16) -> Result<isize> {
    let v = SleConnData {
        handle: h,
        length,
        data: [0xa5; CONN_DATA_MAX],
    };
    ioctl_conn_send(r, &v as *const _ as usize)
}
fn snapshot(r: &RuntimeContext) -> Vec<ConnEntry> {
    r.lock().unwrap().as_ref().unwrap().conn.connections.clone()
}
fn calls(r: &RuntimeContext) -> usize {
    r.lock()
        .unwrap()
        .as_ref()
        .unwrap()
        .controller
        .packets
        .lock()
        .unwrap()
        .len()
}
#[test]
fn sustained_submission_has_no_phantom_depth_64_queue() {
    let r = runtime(false);
    for _ in 0..128 {
        assert_eq!(submit(&r, 42, 4), Ok(4));
    }
    assert_eq!(calls(&r), 128);
    let s = snapshot(&r);
    assert_eq!(s[0].tx_bytes, 512);
    assert_eq!(s[0].seq.tx_seq, 0);
    assert_eq!(s[1].tx_bytes, 0);
}
#[test]
fn backend_errno_does_not_commit_accounting() {
    for n in [-12, -19, -5, -95, -11] {
        let r = runtime(false);
        r.lock().unwrap().as_mut().unwrap().controller.error = Some(Error(n));
        let before = snapshot(&r);
        assert_eq!(submit(&r, 42, 4), Err(Error(n)));
        assert_eq!(snapshot(&r), before);
        assert_eq!(calls(&r), 1);
    }
}
#[test]
fn default_handle_resolves_first_connected_owner() {
    let r = runtime(false);
    r.lock().unwrap().as_mut().unwrap().conn.connections[0].state = ConnState::Connecting;
    assert_eq!(submit(&r, 0, 4), Ok(4));
    let s = r.lock().unwrap();
    let c = &s.as_ref().unwrap().controller;
    assert_eq!(
        c.packets.lock().unwrap()[0],
        (77, vec![0x1f, 0xa5, 0xa5, 0xa5, 0xa5])
    );
    assert_eq!(s.as_ref().unwrap().conn.connections[0].tx_bytes, 0);
}
#[test]
fn learned_wire_handle_is_used_without_changing_host_identity() {
    let r = runtime(true);
    r.lock().unwrap().as_mut().unwrap().conn.connections[0].controller_handle = Some(0x123);
    assert_eq!(submit(&r, 0, 4), Ok(4));
    let s = r.lock().unwrap();
    assert_eq!(
        s.as_ref().unwrap().controller.packets.lock().unwrap()[0].0,
        0x123
    );
    assert_eq!(s.as_ref().unwrap().conn.connections[0].handle, 42);
}
#[test]
fn missing_wire_handle_is_not_guessed() {
    let r = runtime(true);
    let before = snapshot(&r);
    assert_eq!(submit(&r, 42, 4), Err(EPIPE));
    assert_eq!(snapshot(&r), before);
    assert_eq!(calls(&r), 0);
}
#[test]
fn invalid_lengths_do_not_truncate_or_submit() {
    let r = runtime(false);
    let before = snapshot(&r);
    for len in [0, 256, u16::MAX] {
        assert_eq!(submit(&r, 42, len), Err(EINVAL));
    }
    assert_eq!(snapshot(&r), before);
    assert_eq!(calls(&r), 0);
}
#[test]
fn disconnected_closed_unknown_and_empty_selection_reject() {
    let r = runtime(false);
    r.lock().unwrap().as_mut().unwrap().conn.connections[0].state = ConnState::DisconnectPending;
    assert_eq!(submit(&r, 42, 4), Err(EPIPE));
    r.lock().unwrap().as_mut().unwrap().conn.connections[1]
        .channels
        .data
        .state = ChannelState::Closed;
    assert_eq!(submit(&r, 77, 4), Err(EPIPE));
    assert_eq!(submit(&r, 999, 4), Err(ENOENT));
    r.lock().unwrap().as_mut().unwrap().conn.connections[1].state = ConnState::Connecting;
    assert_eq!(submit(&r, 0, 4), Err(EPIPE));
    assert_eq!(calls(&r), 0);
}
#[test]
fn reliable_is_unsupported_without_credit_or_sequence_loss() {
    let r = runtime(false);
    r.lock().unwrap().as_mut().unwrap().conn.connections[0]
        .channels
        .data
        .mode = TransportMode::Reliable;
    let before = snapshot(&r);
    assert_eq!(submit(&r, 42, 4), Err(Error(-95)));
    assert_eq!(snapshot(&r), before);
    assert_eq!(calls(&r), 0);
}
#[test]
fn mtu_and_fragmentation_boundaries_fail_before_submission() {
    let r = runtime(false);
    r.lock().unwrap().as_mut().unwrap().conn.connections[0]
        .channels
        .data
        .mtu = 3;
    assert_eq!(submit(&r, 42, 4), Err(EFBIG));
    r.lock().unwrap().as_mut().unwrap().conn.connections[0]
        .channels
        .data
        .mtu = 8;
    r.lock().unwrap().as_mut().unwrap().conn.connections[0]
        .channels
        .data
        .mps = 3;
    assert_eq!(submit(&r, 42, 4), Err(Error(-90)));
    assert_eq!(calls(&r), 0);
}
#[test]
fn overflow_is_checked_before_backend_acceptance() {
    let r = runtime(false);
    r.lock().unwrap().as_mut().unwrap().conn.connections[0].tx_bytes = u64::MAX - 2;
    let before = snapshot(&r);
    assert_eq!(submit(&r, 42, 4), Err(EOVERFLOW));
    assert_eq!(snapshot(&r), before);
    assert_eq!(calls(&r), 0);
}
#[test]
fn independent_runtimes_and_retry_commit_once() {
    let a = runtime(false);
    let b = runtime(false);
    a.lock().unwrap().as_mut().unwrap().controller.error = Some(ENODEV);
    assert_eq!(submit(&a, 0, 4), Err(ENODEV));
    assert_eq!(submit(&b, 0, 4), Ok(4));
    a.lock().unwrap().as_mut().unwrap().controller.error = None;
    assert_eq!(submit(&a, 0, 4), Ok(4));
    assert_eq!(snapshot(&a)[0].tx_bytes, 4);
    assert_eq!(snapshot(&b)[0].tx_bytes, 4);
    assert_eq!(calls(&a), 2);
    assert_eq!(calls(&b), 1);
}
