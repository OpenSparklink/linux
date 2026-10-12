// SPDX-License-Identifier: GPL-2.0

//! Per-registration USB command scheduler. Every command shares the same
//! credit budget and bounded queue. One on-wire command waits for its Status
//! or Complete; asynchronous domain completion is a separate Host operation.
//! Matching management replies have a dedicated slot, not the discovery ring.

use kernel::prelude::*;
use kernel::time::msecs_to_jiffies;

use super::sle_dli::{SleEvent, SleOpcode};
use super::sle_discovery_operation::{Operations, Operation, State, AdmissionError};
use super::sle_mgmt::{CmdRequest, CmdRequestQueue, CMD_TIMEOUT_MS};
use super::sle_command_plan::{DiscoveryIntent, RecipePart, RecipeProgress, RecipeReply, RecipeTag};

struct InFlight {
    opcode: u16,
    seq: u32,
    cookie: u64,
    enable: Option<bool>,
    peer_addr: Option<[u8; 6]>,
    deadline: u64,
    recipe: Option<RecipeTag>,
    connection: Option<u32>,
    transport_done: bool,
    advertising_params: Option<[u8; 49]>,
    advertising_was_absent: bool,
}

pub(crate) struct HostReply {
    pub(crate) seq: u32,
    pub(crate) event: SleEvent,
    pub(crate) current_intent: bool,
    pub(crate) enable: Option<bool>,
    pub(crate) peer_addr: Option<[u8; 6]>,
    pub(crate) recipe: Option<(DiscoveryIntent, RecipeReply)>,
}

/// Access only under the owner's IRQ-safe host lock. No I/O or allocation
/// takes place while it is locked. Sequence zero denotes a typed internal
/// command; nonzero sequences refer to that owner's raw DLI pending entries.
pub(crate) struct CommandHost {
    requests: CmdRequestQueue,
    links: super::sle_link_observation::LinkObservation,
    connections: super::sle_connection_operation::Connections,
    credits: u8,
    active: Option<InFlight>,
    reply: Option<(SleEvent, u64)>,
    fault: Option<Error>,
    next_cookie: u64,
    broadcast_cookie: u64,
    scan_cookie: u64,
    recipe: Option<(RecipeTag, RecipeProgress)>,
    operations: Operations,
    advertising_set: super::sle_command_plan::AdvertisingSet,
    // Adv / scan params / scan control selection; never cleared by eviction.
    selected_policy_domains: u8,
    revoking: bool,
    revoke_cookies: [u64; 2],
    revoke_done: u8,
    revoke_deadline: u64,
    revoke_status: u8,
    revoke_opcode: u16,
    revoke_reply: bool,
}

impl CommandHost {
    pub(crate) fn new_boxed(credits: u8) -> Result<KBox<Self>> {
        KBox::init(
            init!(Self {
                requests <- CmdRequestQueue::new_in_place(),
                links: super::sle_link_observation::LinkObservation::new(),
                connections <- super::sle_connection_operation::Connections::new_in_place(),
                credits,
                active: None,
                reply: None,
                fault: None,
            next_cookie: 1,
            broadcast_cookie: 0,
            scan_cookie: 0,
            recipe: None,
                revoking: false, revoke_cookies: [0; 2], revoke_done: 0, revoke_deadline: 0,
                revoke_status: 0, revoke_opcode: 0, revoke_reply: false,
                selected_policy_domains: 0,
                advertising_set: super::sle_command_plan::AdvertisingSet::Unknown,
                operations <- init!(Operations {
                    entries <- pin_init::init_array_from_fn(|_| None),
                    initialized: false,
                    advertising: 0,
                    scanning: 0,
                }),
            }),
            GFP_KERNEL,
        )
    }

    pub(crate) fn enqueue(&mut self, opcode: u16, params: &[u8], seq: u32) -> Result {
        if let Some(error) = self.fault {
            return Err(error);
        }
        let cookie = self.next_cookie;
        let next_cookie = cookie.checked_add(1).ok_or(EOVERFLOW)?;
        self.requests.push_cookie(opcode, params, seq, cookie)?;
        self.next_cookie = next_cookie;
        if opcode == SleOpcode::EnableBroadcast as u16 {
            self.broadcast_cookie = cookie;
            self.supersede_recipe(DiscoveryIntent::Advertising(false));
        }
        if opcode == SleOpcode::EnableScan as u16 {
            self.scan_cookie = cookie;
            self.supersede_recipe(DiscoveryIntent::Scanning(false));
        }
        Ok(())
    }

    /// Metadata-only diagnostic admission supplies the original absolute
    /// deadline; queue wait does not grant a fresh full timeout on transmission.
    pub(crate) fn enqueue_diagnostic(&mut self, opcode: u16, seq: u32, deadline: u64) -> Result {
        if let Some(error) = self.fault { return Err(error); }
        let cookie = self.next_cookie;
        let next_cookie = cookie.checked_add(1).ok_or(EOVERFLOW)?;
        self.requests.push_tagged(opcode, &[], seq, cookie, None, deadline).map_err(Error::from)?;
        self.next_cookie = next_cookie;
        Ok(())
    }

    pub(crate) fn cancel_diagnostic(&mut self, seq: u32) {
        self.requests.remove_seq(seq);
        // active/reply/credits/deadline remain untouched. Cancelling an on-wire
        // author waits for its real reply or a normal uncertain-outcome fault.
    }

    fn supersede_recipe(&mut self, intent: DiscoveryIntent) {
        self.requests.remove_recipes(intent);
        self.cancel_recipe_progress(intent);
    }

    fn cancel_recipe_progress(&mut self, intent: DiscoveryIntent) {
        if let Some((tag, progress)) = &mut self.recipe {
            if tag.intent.same_domain(intent) && tag.intent.has_enable() { progress.cancel(); }
        }
    }

    /// Preflight/copy the complete sequence under this owner's Host lock.
    /// Contiguous requests cannot interleave with an unrelated raw command.
    /// Each step waits for matching successful Complete, including native
    /// Status acceptance. A newer same-domain recipe removes old queued
    /// steps, while its already-on-wire command retains its reply reservation.
    pub(crate) fn enqueue_recipe(&mut self, intent: DiscoveryIntent, parts: &[RecipePart<'_>]) -> Result {
        // SAFETY: fixed whole-recipe budget, not a timeout per step.
        let deadline = unsafe { kernel::bindings::jiffies_64 }
            .wrapping_add(msecs_to_jiffies(CMD_TIMEOUT_MS) as u64);
        self.enqueue_recipe_until(intent, parts, deadline)
    }
    fn enqueue_recipe_until(&mut self, intent: DiscoveryIntent, parts: &[RecipePart<'_>], deadline: u64) -> Result {
        if let Some(error) = self.fault { return Err(error); }
        let cookie = self.next_cookie;
        let next_cookie = cookie.checked_add(1).ok_or(EOVERFLOW)?;
        self.requests.push_recipe(parts, cookie, intent, deadline)?;
        self.cancel_recipe_progress(intent);
        self.next_cookie = next_cookie;
        match intent {
            DiscoveryIntent::Advertising(_) | DiscoveryIntent::AdvertisingStandby => self.broadcast_cookie = cookie,
            DiscoveryIntent::Scanning(_) | DiscoveryIntent::ScanningStandby => self.scan_cookie = cookie,
        }
        Ok(())
    }

    pub(crate) fn submit_discovery(
        &mut self, request_id: u64, intent: DiscoveryIntent,
        parts: &[RecipePart<'_>], power_step: u8,
    ) -> Result {
        if power_step as usize > parts.len() { return Err(EINVAL); }
        if !self.connections.clear() { return Err(EBUSY); }
        // A cancelled selected configuration can still change the physical
        // handle. Do not snapshot its old configuration for a newer recipe.
        if parts.first().is_some_and(|part| part.opcode == 0x0c02)
            && (self.active.is_some() || self.reply.is_some()
                || self.operations.pending(DiscoveryIntent::Advertising(false))) {
            return Err(EBUSY);
        }
        let recreate = if matches!(intent, DiscoveryIntent::Advertising(true) | DiscoveryIntent::AdvertisingStandby) {
            let first = parts.first().ok_or(EINVAL)?;
            if first.opcode != 0x0c02 { return Err(EINVAL); }
            match self.advertising_set.recreate(first.params) {
                Some(recreate) => recreate,
                None if intent == DiscoveryIntent::AdvertisingStandby => false,
                None => return Err(EBUSY),
            }
        } else { false };
        if recreate && self.operations.advertising != 1 { return Err(EBUSY); }
        let mut expanded = [RecipePart { opcode: 0, params: &[] }; super::sle_command_plan::RECIPE_STEPS_MAX];
        let remove = [0u8];
        let (parts, power_step) = if recreate {
            if parts.len() + 1 > expanded.len() { return Err(EINVAL); }
            expanded[0] = RecipePart { opcode: 0x0c08, params: &remove };
            expanded[1..parts.len() + 1].copy_from_slice(parts);
            (&expanded[..parts.len() + 1], power_step.checked_add(1).ok_or(EINVAL)?)
        } else { (parts, power_step) };
        let slot = self.operations.slot(request_id).map_err(|error| match error {
            AdmissionError::Invalid => EINVAL,
            AdmissionError::Duplicate => EEXIST,
            AdmissionError::Full => EBUSY,
        })?;
        if intent.enabled() && !self.operations.can_start(intent) { return Err(EBUSY); }
        if intent == DiscoveryIntent::ScanningStandby && !self.operations.can_initialize_scan() { return Err(EBUSY); }
        let cookie = self.next_cookie;
        self.enqueue_recipe(intent, parts)?;
        // Queue/cookie admission succeeded. Neither failure path above changed
        // operation storage. Stop supersedes prior public operations only now.
        self.operations.cancel_domain(intent, -(kernel::bindings::ECANCELED as i32));
        self.operations.entries[slot] = Some(Operation {
            request_id, cookie, intent, state: State::Queued, error: 0,
            status: 0, opcode: 0, step: 0, count: parts.len() as u8,
            power_step, selected_power: None, completed_boottime_ns: 0,
        });
        Ok(())
    }

    pub(crate) fn submit_connection(&mut self, file: u64, request: u64,
        intent: super::sle_connection_operation::Intent, operation: u32,
        opcode: u16, params: &[u8], timeout_ms: u32) -> Result {
        use super::sle_connection_operation::{Error as Admission, Intent};
        if let Some(error) = self.fault { return Err(error); }
        if self.revoking { return Err(EBUSY); }
        if !matches!((operation, intent), (1, Intent::Create { .. }) | (2, Intent::Disconnect { .. })) { return Err(EINVAL); }
        if matches!(intent, Intent::Create { .. }) && !self.operations.initialized { return Err(EAGAIN); }
        self.connections.preflight(file, request).map_err(|e| match e {
            Admission::Invalid => EINVAL, Admission::Duplicate => EEXIST,
            Admission::Busy => EBUSY, Admission::Mismatch => EINVAL,
        })?;
        match intent {
            Intent::Create { .. } => {
                if !self.links.clear_for_management() { return Err(EBUSY); }
            }
            Intent::Disconnect { handle } => {
                if !self.links.contains(handle) { return Err(Error::from_errno(-(kernel::bindings::ENOTCONN as i32))); }
            }
        }
        if !(1..=10000).contains(&timeout_ms) { return Err(EINVAL); }
        let cookie = self.next_cookie;
        let next = cookie.checked_add(1).ok_or(EOVERFLOW)?;
        // SAFETY: clock read has no pointer preconditions.
        let now = unsafe { kernel::bindings::jiffies_64 };
        let deadline = now.checked_add(msecs_to_jiffies(timeout_ms) as u64).ok_or(EOVERFLOW)?;
        self.requests.push_connection(opcode, params, cookie, operation, deadline).map_err(Error::from)?;
        if self.connections.reserve(file, request, cookie, intent, now, deadline).is_err() {
            self.requests.remove_cookie(cookie); return Err(EINVAL);
        }
        self.next_cookie = next;
        Ok(())
    }
    pub(crate) fn connection_result(&self, file: u64, request: u64) -> Option<super::sle_connection_operation::Operation> {
        self.connections.query(file, request)
    }
    pub(crate) fn cancel_connection(&mut self, file: u64, request: u64) -> Result {
        let cookie = self.connections.cancel(file, request).map_err(|_| ENOENT)?;
        if let Some(cookie) = cookie { self.requests.remove_cookie(cookie); }
        Ok(())
    }
    pub(crate) fn revoke_connections(&mut self) {
        if let Some(cookie) = self.connections.revoke() { self.requests.remove_cookie(cookie); }
    }

    /// Retain any active wire slot, but prevent queued enables from escaping.
    /// Caller drains raw pending entries before providing driver-prepared stops.
    pub(crate) fn validate_connection_cleanup(&self) -> Result {
        if let Some(error) = self.fault { return Err(error); }
        if !self.links.known() { return Err(Error::from_errno(-(kernel::bindings::EOPNOTSUPP as i32))); }
        if let Some(error) = self.connections.fault_reason() { return Err(Error::from_errno(error)); }
        Ok(())
    }
    pub(crate) fn begin_revoke(&mut self, adv: &[RecipePart<'_>], scan: &[RecipePart<'_>]) -> Result {
        self.validate_connection_cleanup()?;
        // SAFETY: read the fixed original pending budget before queuing stops.
        let now = unsafe { kernel::bindings::jiffies_64 };
        self.revoke_deadline = self.connections.next_deadline().unwrap_or(now).max(now)
            .saturating_add(msecs_to_jiffies(CMD_TIMEOUT_MS) as u64);
        self.operations.cancel_domain(DiscoveryIntent::Advertising(false), -(kernel::bindings::ECANCELED as i32));
        self.operations.cancel_domain(DiscoveryIntent::Scanning(false), -(kernel::bindings::ECANCELED as i32));
        let required = super::sle_command_plan::revocation_required_domains(
            self.selected_policy_domains, [self.operations.advertising, self.operations.scanning]);
        self.revoke_cookies = [0; 2];
        for (domain, intent, parts) in [(0, DiscoveryIntent::Advertising(false), adv),
                                       (1, DiscoveryIntent::Scanning(false), scan)] {
            if required & (1 << domain) == 0 { continue; }
            self.revoke_cookies[domain] = self.next_cookie;
            if let Err(error) = self.enqueue_recipe_until(intent, parts, self.revoke_deadline) {
                let _ = self.fail(error); return Err(error);
            }
        }
        self.revoking = true; self.revoke_done = !required & 3;
        self.revoke_status = 0; self.revoke_opcode = 0; self.revoke_reply = false;
        Ok(())
    }
    pub(crate) fn cleanup_candidate(&self) -> Result<Option<u16>> {
        if !self.revoking { return Ok(None); }
        self.validate_connection_cleanup()?;
        if !self.connections.clear() { return Ok(None); }
        Ok(self.links.first_handle())
    }
    pub(crate) fn submit_cleanup(&mut self, handle: u16, opcode: u16, params: &[u8]) -> Result<bool> {
        if self.cleanup_candidate()? != Some(handle) { return Ok(false); }
        // SAFETY: clock read; preparation occurred outside the IRQ-safe lock.
        let now = unsafe { kernel::bindings::jiffies_64 };
        if now >= self.revoke_deadline { return Err(ETIMEDOUT); }
        let cookie = self.next_cookie;
        let next = cookie.checked_add(1).ok_or(EOVERFLOW)?;
        self.requests.push_cleanup(opcode, params, cookie, self.revoke_deadline).map_err(Error::from)?;
        if self.connections.reserve_cleanup(cookie, handle, now, self.revoke_deadline).is_err() {
            self.requests.remove_cookie(cookie); return Err(EBUSY);
        }
        self.next_cookie = next;
        Ok(true)
    }
    pub(crate) fn observe_link(&mut self, evidence: &super::sle_link_observation::LinkEvidence) {
        self.links.observe(evidence);
        // SAFETY: reads only the registration-local deadline clock.
        let now = unsafe { kernel::bindings::jiffies_64 };
        if let Some(cookie) = self.connections.expire(now) { self.requests.remove_cookie(cookie); }
        // Independent physical obligations are updated even for unmatched,
        // cancelled, failed or evicted author results. Never infer a link from Status.
        if evidence.reserved != [0; 2] || evidence.status > 255 || evidence.handle > 65535 { return; }
        use super::sle_connection_operation::Outcome;
        match evidence.kind {
            1 if evidence.address_type <= 255 && evidence.role <= 1 => {
                self.connections.outcome(Outcome::Connected { status: evidence.status as u8,
                    handle: evidence.handle as u16, address_type: evidence.address_type as u8, address: evidence.address });
            }
            2 => self.connections.outcome(Outcome::Disconnected { status: evidence.status as u8, handle: evidence.handle as u16 }),
            _ => {}
        }
        if let Some(error) = self.connections.fault_reason() { self.fail(Error::from_errno(error)); }
    }
    pub(crate) fn links_clear_for_management(&self) -> bool {
        self.links.clear_for_management() && self.connections.clear()
    }

    pub(crate) fn quiet(&self) -> bool {
        self.active.is_none() && self.reply.is_none() && self.requests.is_empty()
    }
    /// Called only at an atomically checked new management lease commit.
    /// Keep physical state, author history and genuine credits; retire only
    /// the previous lease's already-settled cleanup bookkeeping.
    pub(crate) fn resume_management(&mut self) -> Result {
        if let Some(error) = self.fault { return Err(error); }
        if !self.quiet() || !self.links_clear_for_management()
            || (self.revoking && !self.revocation_result().is_some_and(|result| result.is_ok())) {
            return Err(EBUSY);
        }
        self.revoking = false;
        self.revoke_cookies = [0; 2]; self.revoke_done = 0; self.revoke_deadline = 0;
        self.revoke_status = 0; self.revoke_opcode = 0; self.revoke_reply = false;
        self.selected_policy_domains = 0; self.recipe = None;
        Ok(())
    }
    /// An unconfigured controller has no advertising handle to stop. Derive
    /// this exception from the same Host state that records policy admission;
    /// unknown after any recipe, cancellation or fault is not untouched.
    /// Settling a lease here does not establish Off or make the radio Ready.
    pub(crate) fn policy_untouched(&self) -> bool {
        self.quiet() && self.fault.is_none() && !self.revoking
            && self.recipe.is_none() && self.selected_policy_domains == 0 && self.broadcast_cookie == 0 && self.scan_cookie == 0
            && !self.operations.initialized
            && self.operations.advertising == 0 && self.operations.scanning == 0
            && self.operations.entries.iter().all(Option::is_none)
    }
    /// Native raw admission is query-only. A typed recipe sets `recipe` before
    /// handing any step to transport, and that evidence survives cancellation
    /// and result eviction. Queued policy can therefore be cancelled locally
    /// only while all of this owner's state proves it was never selected.
    /// This is not a predicate for partially initialized or uncertain hardware.
    pub(crate) fn policy_unsubmitted(&self) -> bool {
        if self.policy_untouched() { return true; }
        self.active.is_none() && self.reply.is_none() && self.fault.is_none()
            && !self.revoking && self.recipe.is_none() && self.selected_policy_domains == 0 && !self.operations.initialized
            && self.operations.advertising == 0 && self.operations.scanning == 0
            && self.operations.entries.iter().flatten().all(|op| {
                ((op.state == State::Queued && op.error == 0)
                    || (op.state == State::Cancelled && op.error == -(kernel::bindings::ECANCELED as i32)))
                    && op.cookie != 0 && op.opcode == 0 && op.step == 0
                    && (1..=super::sle_command_plan::RECIPE_STEPS_MAX as u8).contains(&op.count) && op.power_step <= op.count
                    && op.status == 0 && op.selected_power.is_none()
                    && op.completed_boottime_ns == 0
                    && op.cookie <= match op.intent {
                        DiscoveryIntent::Advertising(_) | DiscoveryIntent::AdvertisingStandby => self.broadcast_cookie,
                        DiscoveryIntent::Scanning(_) | DiscoveryIntent::ScanningStandby => self.scan_cookie,
                    }
            })
            && [self.broadcast_cookie, self.scan_cookie].into_iter().all(|cookie| {
                cookie == 0 || self.operations.entries.iter().flatten().any(|op| op.cookie == cookie)
            })
            && self.requests.entries.iter().flatten().all(|request| {
                request.seq == 0 && request.recipe.is_some_and(|tag| {
                    self.operations.entries.iter().flatten().any(|op| op.cookie == tag.cookie)
                })
            })
    }

    /// Caller holds management admission and protocol state as well as Host.
    /// No raw pending entry, active reservation, credit or radio state changes.
    pub(crate) fn cancel_unsubmitted_policy(&mut self) -> bool {
        if !self.policy_unsubmitted() { return false; }
        while self.requests.pop().is_some() {}
        self.operations.cancel_domain(DiscoveryIntent::Advertising(false), -(kernel::bindings::ECANCELED as i32));
        self.operations.cancel_domain(DiscoveryIntent::Scanning(false), -(kernel::bindings::ECANCELED as i32));
        true
    }
    pub(crate) fn revocation_detail(&self) -> (u8, u16, bool) {
        (self.revoke_status, self.revoke_opcode, self.revoke_reply)
    }
    pub(crate) fn revocation_result(&self) -> Option<Result> {
        if let Some(error) = self.fault { return Some(Err(error)); }
        if self.revoking && self.revoke_done == 3 && self.quiet() {
            if self.links_clear_for_management() { Some(Ok(())) } else { None }
        } else { None }
    }

    pub(crate) fn controller_status(&self) -> (u8, bool, Option<Error>) {
        (
            self.credits,
            self.operations.initialized && self.fault.is_none(),
            self.fault,
        )
    }

    pub(crate) fn discovery_result(&self, request_id: u64) -> Option<Operation> {
        self.operations.find(request_id)
    }
    pub(crate) fn discovery_radio(&self) -> (u32, u32, Option<Error>) {
        (self.operations.advertising, self.operations.scanning, self.fault)
    }

    fn current_recipe(&self, tag: RecipeTag) -> bool {
        tag.cookie == match tag.intent {
            DiscoveryIntent::Advertising(_) | DiscoveryIntent::AdvertisingStandby => self.broadcast_cookie,
            DiscoveryIntent::Scanning(_) | DiscoveryIntent::ScanningStandby => self.scan_cookie,
        }
    }

    pub(crate) fn can_send(&self) -> bool {
        self.fault.is_none()
            && (self.credits > 0 || self.retained_revocation_ready())
            && self.active.is_none()
            && !self.requests.is_empty()
            && (!self.revoking || self.requests.first_recipe().is_none() || self.links_clear_for_management())
    }

    fn retained_revocation(&self, tag: RecipeTag) -> Option<usize> {
        if !self.revoking { return None; }
        super::sle_command_plan::retained_revocation_off(tag, self.revoke_cookies,
            [self.operations.advertising, self.operations.scanning])
    }

    fn retained_revocation_ready(&self) -> bool {
        self.requests.first_recipe().and_then(|tag| self.retained_revocation(tag)).is_some()
    }

    pub(crate) fn next(&mut self, valid_raw: impl Fn(u32) -> bool) -> Result<Option<CmdRequest>> {
        // SAFETY: read only the clock under this owner's Host lock.
        let now = unsafe { kernel::bindings::jiffies_64 };
        if let Some(cookie) = self.connections.expire(now) { self.requests.remove_cookie(cookie); }
        if let Some(error) = self.connections.fault_reason() { return Err(Error::from_errno(error)); }
        if !self.can_send() {
            return Ok(None);
        }
        let request = loop {
            // Retaining an actual OFF needs no credit. A later domain that
            // needs I/O must still await the controller's genuine grant.
            if self.credits == 0 && !self.retained_revocation_ready() { return Ok(None); }
            // Radio controls cannot interfere with a pending connection or
            // known link during revoke. Process-context RX prioritizes a real
            // Disconnect at the queue front when an exact handle is available.
            if self.revoking && self.requests.first_recipe().is_some() && !self.links_clear_for_management() { return Ok(None); }
            let Some(request) = self.requests.pop() else { return Ok(None) };
            if let Some(tag) = request.recipe {
                if tag.intent.has_enable() && !self.current_recipe(tag) { continue; }
                // SAFETY: only reads the kernel clock.
                if unsafe { kernel::bindings::jiffies_64 } >= request.deadline {
                    return Err(ETIMEDOUT);
                }
                if let Some(domain) = self.retained_revocation(tag) {
                    // No OUT, new Complete, clock, credit or public operation
                    // is fabricated. A preceding late OFF was consumed first;
                    // uncertain/cancelled enables remain unknown and cannot
                    // take this path. Both domains must settle before reuse.
                    self.revoke_done |= 1 << domain;
                    if self.revoke_done == 3 {
                        self.operations.initialized = self.advertising_set.configured()
                            && self.operations.advertising == 1 && self.operations.scanning == 1;
                    }
                    continue;
                }
                if tag.step == 0 {
                    let progress = RecipeProgress::new(tag.count).ok_or(EINVAL)?;
                    self.recipe = Some((tag, progress));
                }
                let (root, progress) = self.recipe.as_mut().ok_or(EINVAL)?;
                if root.cookie != tag.cookie || !progress.sent(tag.step) {
                    return Err(EINVAL);
                }
            }
            if request.seq == 0 || valid_raw(request.seq) {
                break request;
            }
            // A cancelled/expired queued transaction never reaches the wire.
        };
        if request.connection.is_some() {
            self.connections.sent(request.cookie).map_err(|_| EINVAL)?;
        }
        self.credits -= 1;
        let advertising_was_absent = self.advertising_set == super::sle_command_plan::AdvertisingSet::Absent;
        let advertising_params = if request.opcode == 0x0c02 && request.param_len == 49 {
            let mut params = [0u8; 49];
            params.copy_from_slice(&request.params[..49]);
            Some(params)
        } else { None };
        if request.opcode == 0x0c08 || (advertising_params.is_some() && advertising_was_absent) {
            // Until a real reply, removal or creation may have reached the
            // controller. A cached previous OFF is not a completion of it.
            self.operations.advertising = 0;
            self.operations.initialized = false;
        }
        if let Some(tag) = request.recipe {
            self.selected_policy_domains |= match tag.intent {
                DiscoveryIntent::Advertising(_) | DiscoveryIntent::AdvertisingStandby => 1,
                DiscoveryIntent::Scanning(_) | DiscoveryIntent::ScanningStandby => {
                    // Parameters do not enable a scanner. Preserve Unknown on
                    // parameter-only cancellation; any other selected scan
                    // command is conservatively a control barrier obligation.
                    if request.opcode == SleOpcode::SetScanParam as u16 { 2 } else { 6 }
                }
            };
            self.operations.sent(request.cookie, tag.step, request.opcode);
        }
        self.active = Some(InFlight {
            opcode: request.opcode,
            seq: request.seq,
            cookie: request.cookie,
            enable: if (request.opcode == SleOpcode::EnableBroadcast as u16
                || request.opcode == SleOpcode::EnableScan as u16)
                && request.param_len == 1
                && request.params[0] <= 1
            {
                Some(request.params[0] == 1)
            } else {
                None
            },
            peer_addr: if request.opcode == SleOpcode::CreateConnection as u16
                && request.param_len == 6
            {
                let mut addr = [0u8; 6];
                addr.copy_from_slice(&request.params[..6]);
                Some(addr)
            } else {
                None
            },
            // SAFETY: reading the kernel clock does not dereference user memory.
            deadline: unsafe { kernel::bindings::jiffies_64 }
                .wrapping_add(msecs_to_jiffies(CMD_TIMEOUT_MS) as u64)
                .min(request.deadline),
            recipe: request.recipe,
            connection: request.connection,
            transport_done: false,
            advertising_params,
            advertising_was_absent,
        });
        Ok(Some(request))
    }

    /// Consume a matching response into its reserved slot. Other events
    /// retain their normal routing; they cannot complete a raw transaction.
    pub(crate) fn receive(&mut self, event: SleEvent) -> Option<SleEvent> {
        let opcode = match &event {
            SleEvent::CommandCredits { credits } => {
                self.credits = *credits;
                return Some(event);
            }
            SleEvent::CommandComplete {
                opcode,
                command_credits,
                ..
            } => {
                self.credits = *command_credits;
                *opcode as u16
            }
            SleEvent::CommandStatus {
                opcode,
                command_credits,
                status,
            } => {
                self.credits = *command_credits;
                if *status == super::sle_dli::SleStatus::Success
                    && self.active.as_ref().is_some_and(|active| active.recipe.is_some())
                {
                    return Some(event);
                }
                *opcode as u16
            }
            SleEvent::NativeCommandReply { opcode, command_credits, status, complete, .. } => {
                self.credits = *command_credits;
                // Native query Status only acknowledges acceptance. Keep the
                // active slot/deadline until matching Complete or failure.
                if !complete && *status == 0
                    && !self.active.as_ref().is_some_and(|active| active.opcode == *opcode && active.connection.is_some()) {
                    return Some(event);
                }
                *opcode
            }
            _ => return Some(event),
        };
        if self.fault.is_none()
            && self.reply.is_none()
            && self
                .active
                .as_ref()
                .is_some_and(|active| active.opcode == opcode)
        {
            // SAFETY: CLOCK_BOOTTIME may be read under this IRQ-safe Host lock.
            let received = unsafe { kernel::bindings::ktime_get_boottime() } as u64;
            self.reply = Some((event, received));
            None
        } else {
            Some(event)
        }
    }

    /// A device reply may arrive before the blocking OUT call returns. Retain
    /// it, but do not publish terminal success until the transfer succeeded.
    pub(crate) fn transport_complete(&mut self, cookie: u64) -> bool {
        if self.fault.is_some() { return false; }
        // SAFETY: absolute admission deadline, not a new USB completion budget.
        let now = unsafe { kernel::bindings::jiffies_64 };
        if let Some(cookie) = self.connections.expire(now) { self.requests.remove_cookie(cookie); }
        let Some(active) = self.active.as_mut() else { return false; };
        if active.cookie != cookie { return false; }
        active.transport_done = true;
        if active.connection.is_some() { self.connections.out_complete(cookie); }
        self.reply.is_some()
    }

    /// The protocol consumer releases the on-wire slot. Keeping it occupied
    /// until consumption bounds management delivery even if RX is busy.
    pub(crate) fn take_reply(&mut self) -> Option<HostReply> {
        if !self.active.as_ref().is_some_and(|active| active.transport_done) { return None; }
        let (event, received) = self.reply.take()?;
        let active = self.active.take()?;
        let successful_complete = matches!(&event,
            SleEvent::NativeCommandReply { complete: true, status: 0, .. })
            || matches!(&event, SleEvent::CommandComplete { status: super::sle_dli::SleStatus::Success, .. });
        if successful_complete {
            if active.opcode == 0x0c08 {
                self.advertising_set = super::sle_command_plan::AdvertisingSet::Absent;
                // An acknowledged deletion proves absence, not a fake STOP.
                self.operations.advertising = 1;
                self.operations.initialized = false;
            } else if let Some(params) = active.advertising_params {
                self.advertising_set = super::sle_command_plan::AdvertisingSet::Configured(params);
                if active.advertising_was_absent {
                    // A new set was created after actual deletion and no
                    // enable has yet been selected. Initial Unknown setup
                    // still needs its original explicit OFF receipt.
                    self.operations.advertising = 1;
                }
            }
        }
        if active.connection.is_some() {
            // SAFETY: final Host processing remains in the whole-operation budget.
            self.connections.expire(unsafe { kernel::bindings::jiffies_64 });
            match &event {
                SleEvent::NativeCommandReply { complete: false, status, .. } => {
                    if self.connections.status(active.cookie, *status).is_err() {
                        self.fail(Error::from_errno(-(kernel::bindings::EPROTO as i32)));
                    }
                }
                _ => { self.fail(Error::from_errno(-(kernel::bindings::EPROTO as i32))); }
            }
            if let Some(error) = self.connections.fault_reason() {
                self.fail(Error::from_errno(error));
            }
        }
        let current_intent = if let Some(tag) = active.recipe {
            self.current_recipe(tag)
        } else if active.opcode == SleOpcode::EnableBroadcast as u16 {
            active.cookie == self.broadcast_cookie
        } else if active.opcode == SleOpcode::EnableScan as u16 {
            active.cookie == self.scan_cookie
        } else {
            true
        };
        if let Some(tag) = active.recipe {
            let (complete, status, data) = match &event {
                SleEvent::CommandComplete { status, data, .. } => (true, *status as u8, data.as_slice()),
                SleEvent::CommandStatus { status, .. } => (false, *status as u8, &[][..]),
                SleEvent::NativeCommandReply { status, complete, data, .. } => (*complete, *status, data.as_slice()),
                _ => (false, 0, &[][..]),
            };
            self.operations.reply(tag.cookie, tag.step, complete, status, data, current_intent, received);
        }
        let recipe = active.recipe.map(|tag| {
            let (complete, status) = match &event {
                SleEvent::CommandComplete { status, .. } => (true, *status as u8),
                SleEvent::CommandStatus { status, .. } => (false, *status as u8),
                SleEvent::NativeCommandReply { status, complete, .. } => (*complete, *status),
                _ => (false, 0),
            };
            let outcome = if let Some((root, progress)) = &mut self.recipe {
                if (!current_intent && tag.intent.has_enable()) || root.cookie != tag.cookie {
                    progress.cancel();
                    RecipeReply::Ignored
                } else {
                    progress.reply(tag.step, complete, status)
                }
            } else { RecipeReply::Ignored };
            if outcome == RecipeReply::Failed {
                self.requests.remove_recipes(tag.intent);
                // Failed older stop barrier also invalidates newer queued work.
                // Preserve the matched operation's raw status as Failed.
                if !current_intent {
                    self.operations.cancel_domain(tag.intent, -(kernel::bindings::ECANCELED as i32));
                }
            }
            (tag.intent, outcome)
        });
        if let Some((_, outcome)) = recipe {
            if outcome == RecipeReply::Finished && current_intent
                && active.recipe.is_some_and(|tag| tag.intent == DiscoveryIntent::Advertising(true))
                && self.advertising_set.configured()
                && self.operations.advertising == 2 && self.operations.scanning == 1 {
                self.operations.initialized = true;
            }
            if self.revoking {
                for i in 0..2 {
                    if self.revoke_cookies[i] != active.cookie { continue; }
                    match outcome {
                        RecipeReply::Finished => {
                            self.revoke_done |= 1 << i;
                            if i == 0 { self.operations.advertising = 1; }
                            else { self.operations.scanning = 1; }
                            if self.revoke_done == 3 {
                                self.operations.initialized = self.advertising_set.configured()
                                    && self.operations.advertising == 1 && self.operations.scanning == 1;
                            }
                        }
                        RecipeReply::Failed => {
                            self.revoke_status = match &event {
                                SleEvent::NativeCommandReply { status, .. } => *status,
                                SleEvent::CommandComplete { status, .. } | SleEvent::CommandStatus { status, .. } => *status as u8,
                                _ => 0,
                            };
                            self.revoke_opcode = active.opcode; self.revoke_reply = true;
                            self.fail(EIO);
                        }
                        _ => {}
                    }
                }
            }
        }
        Some(HostReply {
            seq: active.seq,
            event,
            current_intent,
            enable: active.enable,
            peer_addr: active.peer_addr,
            recipe,
        })
    }

    /// Earliest wire/cleanup deadline, even after local author cancellation.
    /// A delivered reply releases its slot only when the worker consumes it.
    pub(crate) fn next_deadline(&self) -> Option<u64> {
        if self.fault.is_some() { return None; }
        let revoke = (self.revoking && (self.revoke_done != 3 || !self.links_clear_for_management())).then_some(self.revoke_deadline);
        let active = self.active.as_ref()
            .filter(|active| !active.transport_done || self.reply.is_none())
            .map(|active| active.deadline);
        [revoke, active, self.requests.first_recipe_deadline(), self.connections.next_deadline()]
            .into_iter().flatten().min()
    }

    pub(crate) fn timed_out(&mut self) -> bool {
        if self.fault.is_some() { return false; }
        // SAFETY: reading jiffies is safe in process/IRQ context.
        let now = unsafe { kernel::bindings::jiffies_64 };
        if let Some(cookie) = self.connections.expire(now) { self.requests.remove_cookie(cookie); }
        !self.connections.clear() && self.connections.next_deadline().is_none()
            || self.next_deadline().is_some_and(|deadline| now >= deadline)
    }

    /// Latch a fault; never invent credits after uncertain transport outcome.
    /// The caller drains remaining requests and resolves that owner's entries.
    pub(crate) fn fail(&mut self, error: Error) -> Option<u32> {
        if self.fault.is_none() && self.revoking && !self.revoke_reply {
            self.revoke_opcode = self.active.as_ref().map_or(0, |active| active.opcode);
        }
        let error = *self.fault.get_or_insert(error);
        self.operations.fault(error.to_errno());
        self.connections.fault(error.to_errno());
        self.credits = 0;
        self.reply = None;
        if let Some((_, progress)) = &mut self.recipe { progress.cancel(); }
        self.active.take().map(|active| active.seq)
    }

    pub(crate) fn cancel_next(&mut self) -> Option<CmdRequest> {
        self.requests.pop()
    }
}
