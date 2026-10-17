// SPDX-License-Identifier: GPL-2.0-only
//! Bus-independent attributed Runtime ingress. No USB driver or codec here.

use kernel::prelude::*;
use core::sync::atomic::Ordering;
use super::sle_dli::{SleEvent, SleOpcode};

// ---------------------------------------------------------------------------
// IRQ-safe route lookup; ingress storage and work belong to the retained owner.
// ---------------------------------------------------------------------------

super::sle_irq_lock::irq_global_lock!(RUNTIME_ROUTES: [Option<kernel::sync::Arc<super::ControllerRuntime>>; super::sle_dev::SLE_DEV_MAX] = [const { None }; super::sle_dev::SLE_DEV_MAX]);

/// # Safety
/// Call exactly once before publishing any transport owner.
pub(crate) unsafe fn init_ingress_routes() {
    // SAFETY: module initialization is single-threaded.
    unsafe { RUNTIME_ROUTES.init() };
}

pub(crate) fn publish_runtime(owner: &kernel::sync::Arc<super::ControllerRuntime>) -> Result {
    if owner.identity.id as usize >= super::sle_dev::SLE_DEV_MAX || owner.identity.generation == 0 {
        return Err(EINVAL);
    }
    // Gate -> routes. Lookup releases routes before taking the gate; no
    // reverse nesting. A retired registration can never republish its route.
    let stopping = owner.schedule_gate.lock();
    if *stopping { return Err(ENODEV); }
    let mut routes = RUNTIME_ROUTES.lock();
    let slot = &mut routes[owner.identity.id as usize];
    if let Some(current) = slot {
        return if kernel::sync::Arc::ptr_eq(current, owner) { Ok(()) } else { Err(EBUSY) };
    }
    *slot = Some(owner.clone());
    Ok(())
}

pub(crate) fn unpublish_runtime(owner: &kernel::sync::Arc<super::ControllerRuntime>) {
    let previous = {
        let mut routes = RUNTIME_ROUTES.lock();
        routes.get_mut(owner.identity.id as usize).and_then(|slot| {
            if slot.as_ref().is_some_and(|r| kernel::sync::Arc::ptr_eq(r, owner)) {
                slot.take()
            } else { None }
        })
    };
    drop(previous);
}

pub(crate) fn ingress_owner(
    identity: super::sle_dev::DeviceIdentity,
) -> Option<kernel::sync::Arc<super::ControllerRuntime>> {
    RUNTIME_ROUTES
        .lock()
        .get(identity.id as usize)
        .and_then(|slot| {
            slot.as_ref()
                .filter(|owner| owner.identity == identity)
                .cloned()
        })
}

pub(crate) fn drain_runtime_events(
    owner: &super::ControllerRuntime,
    out: &mut [(Option<u16>, Option<SleEvent>)],
) -> usize {
    let mut count = 0;
    let mut ring = owner.ingress.lock();
    while count < out.len() {
        let Some((id, event)) = ring.pop_tagged() else {
            break;
        };
        out[count] = (id, Some(event));
        count += 1;
    }
    count
}

/// Inline draining never removes events belonging to another device.

pub(crate) struct RxDropStats {
    pub(crate) ring: u32,
    pub(crate) command_complete: u32,
    pub(crate) mac_complete: u32,
    pub(crate) decode: u32,
}

pub(crate) fn take_dropped_stats(owner: &super::ControllerRuntime) -> RxDropStats {
    let ring = core::mem::take(&mut owner.ingress.lock().dropped);
    RxDropStats {
        ring,
        command_complete: owner.dropped_commands.swap(0, Ordering::Relaxed),
        mac_complete: owner.dropped_mac.swap(0, Ordering::Relaxed),
        // Decoding is charged to the retained registration, never another bus.
        decode: owner.dropped_decode.swap(0, Ordering::Relaxed),
    }
}

pub(crate) fn enqueue_rx(owner: &kernel::sync::Arc<super::ControllerRuntime>, event: SleEvent) {
    let command = matches!(&event, SleEvent::CommandComplete { .. } | SleEvent::NativeCommandReply { .. });
    let mac = matches!(
        &event,
        SleEvent::CommandComplete {
            opcode: SleOpcode::ReadMacAddr,
            ..
        }
    );
    // Host -> gate -> ingress, matching data admission and atomic submission.
    // Holding gate before Host would invert those paths. Reverse guard release
    // also preserves nested IRQ-save state; schedule only after both unlock.
    let mut host = owner.host.lock();
    let stopping = owner.schedule_gate.lock();
    if *stopping {
        return;
    }
    let event = host.receive(event);
    let Some(event) = event else {
        // A matching reply is retained in the Host's reserved slot. It
        // cannot be lost when discovery/data fill the ordinary RX ring.
        drop(stopping);
        drop(host);
        owner.schedule_rx(0);
        return;
    };
    let accepted = owner
        .ingress
        .lock()
        .push_tagged(Some(owner.identity.id), event);
    if !accepted {
        if command {
            owner.dropped_commands.fetch_add(1, Ordering::Relaxed);
        }
        if mac {
            owner.dropped_mac.fetch_add(1, Ordering::Relaxed);
        }
    }
    drop(stopping);
    drop(host);
    owner.schedule_rx(0);
}

