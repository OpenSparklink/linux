// SPDX-License-Identifier: GPL-2.0
//! Explicit ioctl authorization. Direction bits do not describe side effects:
//! raw event consumption, remote reads and secret retrieval are protected too.
use kernel::{bindings, prelude::*};
use super::sle_uapi::*;

#[derive(Clone, Copy, PartialEq)]
pub(crate) enum Access { Observe, Affinity, Protected, PrivilegedObserve }

pub(crate) fn classify(cmd: u32) -> Result<Access> {
    match cmd {
        SL_IOCTL_SNOOP_GET => Ok(Access::PrivilegedObserve),
        SL_IOCTL_DEV_GET_ACTIVE
        | SL_IOCTL_DEV_SELECT => Ok(Access::Affinity),
        SL_IOCTL_MANAGEMENT_QUERY
        | SL_IOCTL_AFH_GET_MAP
        | SL_IOCTL_CONN_COUNT
        | SL_IOCTL_CONN_INFO
        | SL_IOCTL_CONN_LIST
        | SL_IOCTL_CONTROLLER_EVENT_GET
        | SL_IOCTL_CONTROLLER_SNAPSHOT
        | SL_IOCTL_DEV_COUNT
        | SL_IOCTL_DEV_INFO
        | SL_IOCTL_DEV_LIST
        | SL_IOCTL_DISCOVERY_RESULT
        | SL_IOCTL_DLI_INFO
        | SL_IOCTL_EVENT_COUNT
        | SL_IOCTL_EVENT_STATS
        | SL_IOCTL_EXT_ADV_INFO
        | SL_IOCTL_GET_ROLE
        | SL_IOCTL_MEAS_READ_CAP
        | SL_IOCTL_MGMT_STATS
        | SL_IOCTL_PHY_GET_SINR
        | SL_IOCTL_PHY_INFO
        | SL_IOCTL_PM_INFO
        | SL_IOCTL_RAL_SIZE
        | SL_IOCTL_SCAN_RESULT_COUNT
        | SL_IOCTL_SEC_HMAC_TEST
        | SL_IOCTL_SEC_INFO
        | SL_IOCTL_SEC_SM3_TEST
        | SL_IOCTL_SEC_SM4_BLOCK_TEST
        | SL_IOCTL_SEC_SM4_DEC_TEST
        | SL_IOCTL_SEC_SM4_ENC_TEST
        | SL_IOCTL_SSAP_FIND_SVC
        | SL_IOCTL_SSAP_INFO
        | SL_IOCTL_SSAP_READ
        | SL_IOCTL_SUBSYS_STATS
        | SL_IOCTL_SYNC_INFO
        | SL_IOCTL_USB_DEV_COUNT => Ok(Access::Observe),
        SL_IOCTL_MANAGEMENT_ACQUIRE
        | SL_IOCTL_MANAGEMENT_RELEASE
        | SL_IOCTL_AFH_CLASSIFY
        | SL_IOCTL_AFH_HOP_NEXT
        | SL_IOCTL_AFH_REPORT_RETX
        | SL_IOCTL_AFH_REPORT_RSSI
        | SL_IOCTL_AFH_SET_MAP
        | SL_IOCTL_CLEAR_SCAN_FILTER
        | SL_IOCTL_CONNECT
        | SL_IOCTL_CONN_PHY_UPDATE
        | SL_IOCTL_CONN_READ_PEER_FEATURES
        | SL_IOCTL_CONN_READ_PEER_VERSION
        | SL_IOCTL_CONN_RECV
        | SL_IOCTL_CONN_SEND
        | SL_IOCTL_CONN_UPDATE_PARAMS
        | SL_IOCTL_DEV_REGISTER
        | SL_IOCTL_DEV_SWITCH
        | SL_IOCTL_DEV_UNREGISTER
        | SL_IOCTL_DISCONNECT
        | SL_IOCTL_DISCOVERY_SUBMIT
        | SL_IOCTL_DLI_POLL_EVENT
        | SL_IOCTL_DLI_RESET
        | SL_IOCTL_DLI_SEND_CMD
        | SL_IOCTL_EXT_ADV_CONFIGURE
        | SL_IOCTL_EXT_ADV_DISABLE
        | SL_IOCTL_EXT_ADV_ENABLE
        | SL_IOCTL_EXT_ADV_ENABLE_EX
        | SL_IOCTL_EXT_ADV_REMOVE
        | SL_IOCTL_EXT_ADV_SET_DATA
        | SL_IOCTL_EXT_ADV_SET_SCAN_RSP
        | SL_IOCTL_EXT_ADV_TICK
        | SL_IOCTL_INJECT_ADV
        | SL_IOCTL_INJECT_CONN_DATA
        | SL_IOCTL_INJECT_CONN_RESP
        | SL_IOCTL_INJECT_RAW_ADV
        | SL_IOCTL_MEAS_ACTION
        | SL_IOCTL_MEAS_ENABLE
        | SL_IOCTL_MEAS_SET_LINK_PARAM
        | SL_IOCTL_PHY_HOP_NEXT
        | SL_IOCTL_PHY_MCS_SELECT
        | SL_IOCTL_PHY_SET_BW
        | SL_IOCTL_PHY_SET_MCS
        | SL_IOCTL_PHY_SET_SINR
        | SL_IOCTL_PHY_SET_TXPOWER
        | SL_IOCTL_PM_ACTIVITY
        | SL_IOCTL_PM_FORCE_ACTIVE
        | SL_IOCTL_PM_SET_INTERVAL
        | SL_IOCTL_PM_SET_STATE
        | SL_IOCTL_PM_TICK
        | SL_IOCTL_RAL_ADD
        | SL_IOCTL_RAL_CLEAR
        | SL_IOCTL_RAL_READ_LOCAL_RPA
        | SL_IOCTL_RAL_READ_PEER_RPA
        | SL_IOCTL_RAL_REMOVE
        | SL_IOCTL_RPA_ENABLE
        | SL_IOCTL_RPA_SET_TIMEOUT
        | SL_IOCTL_SEC_CONFIRM_PASSKEY
        | SL_IOCTL_SEC_ENCRYPT_ON
        | SL_IOCTL_SEC_GET_PASSKEY
        | SL_IOCTL_SEC_INPUT_PASSKEY
        | SL_IOCTL_SEC_PAIR
        | SL_IOCTL_SEC_REJECT_PASSKEY
        | SL_IOCTL_SEC_RESET
        | SL_IOCTL_SEC_SET_OOB
        | SL_IOCTL_SEC_SET_PASSWORD
        | SL_IOCTL_SEC_SET_PSK
        | SL_IOCTL_SET_CONN_MTU
        | SL_IOCTL_SET_ROLE
        | SL_IOCTL_SET_SCAN_FILTER
        | SL_IOCTL_SSAP_ADD_PROP
        | SL_IOCTL_SSAP_ADD_SVC
        | SL_IOCTL_SSAP_CALL_METHOD
        | SL_IOCTL_SSAP_DEQUEUE_NTF
        | SL_IOCTL_SSAP_EXCHANGE_INFO
        | SL_IOCTL_SSAP_FIND_BY_UUID
        | SL_IOCTL_SSAP_NOTIFY
        | SL_IOCTL_SSAP_READ_BY_UUID
        | SL_IOCTL_SSAP_REGISTER_SVC
        | SL_IOCTL_SSAP_REMOTE_DISCOVER
        | SL_IOCTL_SSAP_REMOTE_EVENT
        | SL_IOCTL_SSAP_REMOTE_READ
        | SL_IOCTL_SSAP_REMOTE_WRITE
        | SL_IOCTL_SSAP_REMOVE_SVC
        | SL_IOCTL_SSAP_WRITE
        | SL_IOCTL_START_ADV
        | SL_IOCTL_START_SCAN
        | SL_IOCTL_STOP_ADV
        | SL_IOCTL_STOP_SCAN
        | SL_IOCTL_SYNC_DATAPATH_CFG
        | SL_IOCTL_SYNC_DATAPATH_REMOVE
        | SL_IOCTL_SYNC_DATA_SEND
        | SL_IOCTL_SYNC_MCAST_ACCEPT
        | SL_IOCTL_SYNC_MCAST_CREATE
        | SL_IOCTL_SYNC_MCAST_PARAM
        | SL_IOCTL_SYNC_MCAST_REJECT
        | SL_IOCTL_SYNC_MCAST_REMOVE
        | SL_IOCTL_SYNC_UCAST_ACCEPT
        | SL_IOCTL_SYNC_UCAST_CREATE
        | SL_IOCTL_SYNC_UCAST_PARAM
        | SL_IOCTL_SYNC_UCAST_REJECT
        | SL_IOCTL_SYNC_UCAST_REMOVE => Ok(Access::Protected),
        _ => Err(ENOTTY),
    }
}

pub(crate) fn require_admin() -> Result {
    // SAFETY: capable reads the current task credentials and performs the LSM
    // check in the initial user namespace; it has no pointer preconditions.
    if unsafe { bindings::capable(bindings::CAP_NET_ADMIN as i32) } { Ok(()) } else { Err(EPERM) }
}
