// SPDX-License-Identifier: GPL-2.0

//! Background workers for SparkLink subsystem.
//!
//! Every ControllerRuntime embeds separate RX and TX delayed work. Queue-owned
//! Arc references keep that registration alive without an owner/worker cycle.

use kernel::prelude::*;
use kernel::sync::Arc;
use kernel::time::msecs_to_jiffies;
use kernel::workqueue::{self, impl_has_delayed_work, DelayedWork, WorkItem};
use pin_init::init_array_from_fn;

use super::sle_dli;
use super::sle_uapi::*;
use super::sle_ingress;
use super::{ControllerRuntime, ControllerState};

/// Flush executes the callback so Rust reclaims the queue-owned Arc. Call only
/// with the scheduling gate closed, retaining the owner and holding no locks.
fn flush_work<T, const ID: u64>(work: &DelayedWork<T, ID>) {
    // SAFETY: owner Arc is retained and the initialized delayed work is pinned.
    let raw = unsafe { workqueue::Work::raw_get(DelayedWork::raw_as_work(work)) };
    // SAFETY: raw_as_work yields this delayed_work's work field.
    let delayed = unsafe { kernel::container_of!(raw, kernel::bindings::delayed_work, work) };
    // SAFETY: no scheduling or self-rearm can occur after the gate closes.
    unsafe { kernel::bindings::flush_delayed_work(delayed) };
}

/// Heartbeat interval for supervision timeouts and cleanup (ms).
/// The pump no longer self-schedules at this interval for event
/// processing — it is kicked immediately by producers.  The heartbeat
/// ensures periodic maintenance even when no events arrive.
const EVENT_PUMP_HEARTBEAT_MS: u32 = 500;

type TaggedEventBatch = [(Option<u16>, Option<sle_dli::SleEvent>); 64];

/// Construct RX staging directly on the heap. Inline draining can run under
/// an ioctl frame and must leave room for connection creation and allocation.
fn new_event_batch() -> Result<KBox<TaggedEventBatch>> {
    KBox::init(init_array_from_fn(|_| (None, None)), GFP_KERNEL)
}

impl_has_delayed_work! {
    impl HasDelayedWork<ControllerRuntime, 0> for ControllerRuntime { self.rx_work }
    impl HasDelayedWork<ControllerRuntime, 1> for ControllerRuntime { self.tx_work }
}

// ---------------------------------------------------------------------------
// Unified controller event processing
// ---------------------------------------------------------------------------

/// Runtime state serializes driver preparation with retirement. No IRQ-safe
/// Host/gate guard spans callbacks, allocation or transport I/O. Candidate is
/// rechecked under Host -> gate before reserving a new internal typed request.
fn progress_connection_cleanup(owner: &Arc<ControllerRuntime>, state: &ControllerState) -> Result<bool> {
    let candidate = owner.host.lock().cleanup_candidate()?;
    let Some(handle) = candidate else { return Ok(false); };
    let controller = state.controller.provider();
    // Normal local management termination. This is a protocol reason, not a
    // vendor opcode; the retained driver owns wire preparation and validation.
    let request = SleConnectionSubmit {
        version: 1, profile: owner.protocol_profile, operation: 2,
        generation: owner.identity.generation, handle: handle as u32, reason: 0x13,
        // SAFETY: integer/byte-only repr(C); no uninitialized request fields.
        ..unsafe { core::mem::zeroed() }
    };
    let plan = controller.prepare_connection(&request)?;
    let mut host = owner.host.lock();
    let gate = owner.schedule_gate.lock();
    if *gate { return Err(ENODEV); }
    let result = host.submit_cleanup(handle, plan.opcode, &plan.params[..plan.length as usize]);
    drop(gate); drop(host);
    result
}

/// Consume the retained management reply under this owner's protocol mutex.
/// Generic/discovery ingress pressure cannot steal the result or its sequence.
fn process_host_reply(owner: &Arc<ControllerRuntime>, state: &mut ControllerState) -> bool {
    let reply = owner.host.lock().take_reply();
    let Some(reply) = reply else {
        return false;
    };
    // Admission deadlines include queue, transport and final Host processing.
    // A late Complete releases its real reservation but cannot revive a timed
    // out author result; queued expirations do not invent hardware failure.
    state.cmd_pending.expire_stale();
    match &reply.event {
        sle_dli::SleEvent::CommandComplete { status, data, .. } => {
            state
                .cmd_pending
                .resolve_seq(reply.seq, *status as u8, data.as_slice());
        }
        sle_dli::SleEvent::CommandStatus { status, .. }
            if *status != sle_dli::SleStatus::Success =>
        {
            state.cmd_pending.resolve_seq(reply.seq, *status as u8, &[]);

        }
        sle_dli::SleEvent::NativeCommandReply { status, complete, data, .. }
            if *complete || *status != 0 =>
        {
            state.cmd_pending.resolve_seq(reply.seq, *status, data.as_slice());
        }
        _ => {} // Successful Status awaits a domain-specific terminal event.
    }
    owner.kick_commands();
    true
}

fn fail_host(owner: &Arc<ControllerRuntime>, state: &mut ControllerState, error: Error) {
    let mut host = owner.host.lock();
    if let Some(seq) = host.fail(error) {
        state.cmd_pending.fail_seq(seq, error.to_errno());
    }
    while let Some(request) = host.cancel_next() {
        state.cmd_pending.fail_seq(request.seq, error.to_errno());
    }
}


impl ControllerRuntime {
    pub(crate) fn start_workers(self: &Arc<Self>) {
        self.schedule_rx(msecs_to_jiffies(EVENT_PUMP_HEARTBEAT_MS));
    }

    pub(crate) fn schedule_rx(self: &Arc<Self>, delay: kernel::time::Jiffies) {
        let stopping = self.schedule_gate.lock();
        if !*stopping {
            if delay == 0 {
                // SAFETY: this pinned delayed_work is never disabled and all
                // scheduling is serialized with stop/flush by this gate.
                // mod_delayed_work returns false for a NEW queue reference:
                // __enqueue then transfers the incoming Arc to the trampoline.
                // If already pending, it returns true: keep the prior queue
                // reference and return/drop the unused incoming Arc. No raw
                // callback can run without a corresponding Rust-owned Arc.
                let _ = unsafe {
                    <Arc<Self> as workqueue::RawWorkItem<0>>::__enqueue(self.clone(), |work| {
                        let delayed =
                            kernel::container_of!(work, kernel::bindings::delayed_work, work);
                        !kernel::bindings::mod_delayed_work_on(
                            kernel::bindings::wq_misc_consts_WORK_CPU_UNBOUND as i32,
                            kernel::bindings::system_wq,
                            delayed,
                            0,
                        )
                    })
                };
            } else {
                // A heartbeat/self-rearm must not postpone an existing kick.
                let _ = workqueue::system().enqueue_delayed::<_, 0>(self.clone(), delay);
            }
        }
    }

    pub(crate) fn kick_commands(self: &Arc<Self>) {
        let stopping = self.schedule_gate.lock();
        if !*stopping {
            let _ = workqueue::system().enqueue_delayed::<_, 1>(self.clone(), 0);
        }
    }

    pub(crate) fn stop_workers(self: &Arc<Self>) {
        *self.schedule_gate.lock() = true;
        self.host.lock().fail(ENODEV);
        flush_work(&self.rx_work);
        flush_work(&self.tx_work);
    }
}

impl WorkItem<0> for ControllerRuntime {
    type Pointer = Arc<ControllerRuntime>;

    fn run(this: Arc<ControllerRuntime>) {
        if *this.schedule_gate.lock() {
            return;
        }
        let mut pumped = 0u32;
        // Reclaim incomplete native SDUs even when no later USB data arrives.
        // SAFETY: read-only monotonic clock; buffer destruction is IRQ-safe.
        this.data.lock().expire(unsafe { kernel::bindings::ktime_get_boottime() } as u64);
        let mut rearm_jiffies = msecs_to_jiffies(EVENT_PUMP_HEARTBEAT_MS) as u64;
        let mut batch = new_event_batch().ok();
        let drops = sle_ingress::take_dropped_stats(&this);
        if drops.ring > 0 || drops.command_complete > 0 || drops.decode > 0 {
            pr_warn!("sparklink: sle{} RX loss: ring={} command_complete={} mac_complete={} decode={}\n",
                this.identity.id, drops.ring, drops.command_complete, drops.mac_complete, drops.decode);
        }
        for _pass in 0..16 {
            let tagged: &mut [_] = match batch.as_deref_mut() {
                Some(events) => events,
                None => &mut [],
            };
            let mut drained = 0;
            {
                let mut guard = this.state.lock();
                let Some(runtime) = Option::as_mut(&mut *guard) else {
                    return;
                };
                if process_host_reply(&this, runtime) {
                    pumped += 1;
                    drained += 1;
                }
                // Inline and worker drains share this owner's state lock. Do
                // not prefetch older events before waiting for that lock: an
                // ioctl could otherwise process newer events ahead of them.
                let budget = tagged.len().min((256 - pumped) as usize);
                let count = sle_ingress::drain_runtime_events(&this, &mut tagged[..budget]);
                for item in tagged.iter_mut().take(count) {
                    let (id, event) = core::mem::take(item);
                    if let Some(sle_dli::SleEvent::NativeControllerData {lifetime,handle,index,data})=&event {
                        if let Err(error)=this.deny_unapproved_pairing(runtime,*lifetime,*handle,*index,data.as_slice()) {
                            pr_debug!("sparklink: relay admission refused {}\n",error.to_errno());
                        }
                    }
                    if event.is_some() {
                        debug_assert_eq!(id, Some(this.identity.id));
                        pumped += 1;
                        drained += 1;
                    }
                }
                if drained == 0 || pumped >= 256 {
                    if let Err(error) = progress_connection_cleanup(&this, runtime) {
                        fail_host(&this, runtime, error);
                    }
                    if this.host.lock().timed_out()
                    {
                        fail_host(&this, runtime, ETIMEDOUT);
                        pr_warn!(
                            "sparklink: sle{} USB command Host timed out\n",
                            this.identity.id
                        );
                    }
                    let expired = runtime.cmd_pending.expire_stale();
                    if expired > 0 {
                        pr_warn!(
                            "sparklink: sle{}: {} pending commands timed out\n",
                            this.identity.id,
                            expired
                        );
                    }

                }
            }
            if drained == 0 || pumped >= 256 {
                break;
            }
        }
        if pumped > 0 {
            this.fast_poll_remaining
                .store(64, core::sync::atomic::Ordering::Relaxed);
            rearm_jiffies = 1;
        } else {
            let remaining = this
                .fast_poll_remaining
                .load(core::sync::atomic::Ordering::Relaxed);
            if remaining > 0 {
                this.fast_poll_remaining
                    .store(remaining - 1, core::sync::atomic::Ordering::Relaxed);
                rearm_jiffies = 1;
            }
        }
        // Session ownership follows canonical physical links/withdrawal.
        this.reconcile_sessions();
        // An inline drain may already have taken the grant; check the owner
        // state even on an empty RX pass. Queue TX after releasing its mutex.
        let can_send = {
            let state = this.state.lock();
            state.as_ref().is_some_and(|state| {
                // Deadlines cover queue wait as well as transport/reply wait.
                // Recompute after every wake: a retry or a busy event stream
                // must not reset the original deadline to a fresh heartbeat.
                // SAFETY: jiffies is a read-only kernel clock.
                let now = unsafe { kernel::bindings::jiffies_64 };
                let host = this.host.lock();
                for deadline in [state.cmd_pending.next_deadline(), host.next_deadline()]
                    .into_iter().flatten() {
                    rearm_jiffies = rearm_jiffies.min(deadline.saturating_sub(now).max(1));
                }
                host.can_send()
            })
        };
        if can_send {
            this.kick_commands();
        }
        this.schedule_rx(rearm_jiffies as kernel::time::Jiffies);
    }
}

impl WorkItem<1> for ControllerRuntime {
    type Pointer = Arc<ControllerRuntime>;

    fn run(this: Arc<ControllerRuntime>) {
        if *this.schedule_gate.lock() { return; }
        let mut guard = this.state.lock();
        let Some(runtime) = Option::as_mut(&mut *guard) else { return; };
        let request = this.host.lock().next(|seq| {
            runtime.cmd_pending.find_by_seq(seq)
                .is_some_and(|entry| entry.is_pending() && !entry.is_expired())
        });
        let request = match request {
            Ok(request) => request,
            Err(error) => { fail_host(&this, runtime, error); return; }
        };
        if let Some(request) = request {
            let transport = match runtime.controller.command_port() {
                Ok(port) => port,
                Err(error) => { fail_host(&this, runtime, error); return; }
            };
            // Retained provider owns resources. No Runtime/Host/IRQ guard
            // spans a blocking transport transfer or join.
            drop(guard);
            match transport.submit(&this, request.cookie, request.opcode,
                &request.params[..request.param_len as usize], request.recipe, request.connection, request.relay.is_some()) {
                Ok(()) => {
                    if this.host.lock().transport_complete(request.cookie) { this.schedule_rx(0); }
                }
                Err(error) => {
                    let mut guard = this.state.lock();
                    if let Some(runtime) = Option::as_mut(&mut *guard) {
                        let rolled_back = transport.never_submitted()
                            && this.host.lock().abort_unsubmitted(request.cookie, error).is_ok();
                        if rolled_back {
                            runtime.cmd_pending.fail_seq(request.seq, error.to_errno());
                            this.kick_commands(); this.schedule_rx(0);
                        } else { fail_host(&this, runtime, error); }
                    }
                }
            }
        }
        // Reply consumption, not bulk acceptance, releases the protocol slot.
    }
}
