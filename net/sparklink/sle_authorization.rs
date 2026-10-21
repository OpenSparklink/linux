// SPDX-License-Identifier: GPL-2.0
//! Explicit ioctl authorization. Direction bits do not describe side effects:
//! raw event consumption, remote reads and secret retrieval are protected too.
use kernel::{bindings, prelude::*};
use super::sle_uapi::*;

#[derive(Clone, Copy, PartialEq)]
pub(crate) enum Access { Observe, Affinity, Protected, PrivilegedObserve }

pub(crate) fn classify(cmd: u32) -> Result<Access> {
    match cmd {
        SL_IOCTL_SNOOP_GET | SL_IOCTL_DIAGNOSTIC_RESULT => Ok(Access::PrivilegedObserve),
        SL_IOCTL_DEV_GET_ACTIVE
        | SL_IOCTL_DEV_SELECT => Ok(Access::Affinity),
        SL_IOCTL_MANAGEMENT_QUERY
        | SL_IOCTL_CONTROLLER_EVENT_GET
        | SL_IOCTL_CONTROLLER_SNAPSHOT
        | SL_IOCTL_REGISTRATION_SNAPSHOT
        | SL_IOCTL_DEV_COUNT
        | SL_IOCTL_DEV_INFO
        | SL_IOCTL_DEV_LIST
        | SL_IOCTL_CONNECTION_RESULT
        | SL_IOCTL_LINK_SNAPSHOT
        | SL_IOCTL_DISCOVERY_RESULT
        | SL_IOCTL_DISCOVERY_TIMING
        | SL_IOCTL_MGMT_STATS
         => Ok(Access::Observe),
        SL_IOCTL_SECURITY_NEGOTIATION_SUBMIT
        | SL_IOCTL_SECURITY_NEGOTIATION_RESULT
        | SL_IOCTL_SECURITY_NUMERIC_CONFIRM
        | SL_IOCTL_CONNECTION_SECURITY
        | SL_IOCTL_SECURITY_NEGOTIATION_CANCEL
        | SL_IOCTL_DIAGNOSTIC_SUBMIT
        | SL_IOCTL_RUNTIME_ADDRESS_SUBMIT
        | SL_IOCTL_MANAGEMENT_ACQUIRE
        | SL_IOCTL_MANAGEMENT_RELEASE
        | SL_IOCTL_CONNECTION_SUBMIT
        | SL_IOCTL_DISCOVERY_SUBMIT
         => Ok(Access::Protected),
        _ => Err(ENOTTY),
    }
}

pub(crate) fn require_admin() -> Result {
    // SAFETY: capable reads the current task credentials and performs the LSM
    // check in the initial user namespace; it has no pointer preconditions.
    if unsafe { bindings::capable(bindings::CAP_NET_ADMIN as i32) } { Ok(()) } else { Err(EPERM) }
}
