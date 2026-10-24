fn ioctl_dispatch_adv(context: &RuntimeContext, _me: Pin<&SparkLinkCtl>, cmd: u32, arg: usize) -> Result<isize> {
    match cmd {
        SL_IOCTL_START_ADV
        | SL_IOCTL_STOP_ADV
        | SL_IOCTL_START_SCAN
        | SL_IOCTL_STOP_SCAN
        | SL_IOCTL_DEV_COUNT
        | SL_IOCTL_DEV_INFO
        | SL_IOCTL_DEV_SWITCH
        | SL_IOCTL_DEV_LIST
        | SL_IOCTL_SCAN_RESULT_COUNT
        | SL_IOCTL_SET_SCAN_FILTER
        | SL_IOCTL_CLEAR_SCAN_FILTER => ioctl_dispatch_adv_basic(context, cmd, arg),
        SL_IOCTL_EXT_ADV_CONFIGURE
        | SL_IOCTL_EXT_ADV_SET_DATA
        | SL_IOCTL_EXT_ADV_SET_SCAN_RSP
        | SL_IOCTL_EXT_ADV_ENABLE
        | SL_IOCTL_EXT_ADV_DISABLE
        | SL_IOCTL_EXT_ADV_REMOVE
        | SL_IOCTL_EXT_ADV_INFO
        | SL_IOCTL_EXT_ADV_ENABLE_EX
        | SL_IOCTL_EXT_ADV_TICK => Err(Error::from_errno(-(bindings::EOPNOTSUPP as i32))),
        SL_IOCTL_INJECT_ADV | SL_IOCTL_INJECT_RAW_ADV => Err(Error::from_errno(-(bindings::EOPNOTSUPP as i32))),
        _ => Err(EINVAL),
    }
}

fn ioctl_dispatch_adv_basic(context: &RuntimeContext, cmd: u32, arg: usize) -> Result<isize> {
    match cmd {
        SL_IOCTL_START_ADV | SL_IOCTL_STOP_ADV | SL_IOCTL_START_SCAN | SL_IOCTL_STOP_SCAN
            => Err(Error::from_errno(-(bindings::EOPNOTSUPP as i32))),
        SL_IOCTL_DEV_COUNT => {
            let ss = SUBSYSTEM.lock();
            let count = ss.as_ref().map_or(0, |s| s.dev_registry.count());
            Ok(count as isize)
        }
        SL_IOCTL_DEV_INFO => {
            let ss = context.lock()?;
            let s = ss.as_ref().ok_or(ENODEV)?;
            let mut info = s.dev_info;
            // This legacy metadata ABI cannot represent Native readiness/radio state.
            // Current state comes from ControllerSnapshot/typed discovery results.
            info.state = 0xff;
            drop(ss);
            write_user_struct(arg, &info)?;
            Ok(0)
        }
        SL_IOCTL_DEV_SWITCH => Err(Error::from_errno(-(bindings::EOPNOTSUPP as i32))),
        SL_IOCTL_DEV_LIST => {
            let ss = SUBSYSTEM.lock();
            let s = ss.as_ref().ok_or(ENODEV)?;
            let mask = s.dev_registry.allocated_mask();
            drop(ss);
            write_user_struct(arg, &mask)?;
            Ok(0)
        }
        SL_IOCTL_SCAN_RESULT_COUNT | SL_IOCTL_SET_SCAN_FILTER | SL_IOCTL_CLEAR_SCAN_FILTER
            => Err(Error::from_errno(-(bindings::EOPNOTSUPP as i32))),
        _ => Err(EINVAL),
    }
}

fn ioctl_dispatch_conn(_context: &RuntimeContext, _me: Pin<&SparkLinkCtl>, cmd: u32, _arg: usize) -> Result<isize> {
    match cmd {
        SL_IOCTL_CONNECT
        | SL_IOCTL_DISCONNECT
        | SL_IOCTL_CONN_INFO
        | SL_IOCTL_CONN_SEND
        | SL_IOCTL_CONN_RECV
        | SL_IOCTL_INJECT_CONN_RESP
        | SL_IOCTL_INJECT_CONN_DATA
        | SL_IOCTL_CONN_COUNT
        | SL_IOCTL_CONN_LIST
        | SL_IOCTL_SET_CONN_MTU
        | SL_IOCTL_CONN_READ_PEER_FEATURES
        | SL_IOCTL_CONN_READ_PEER_VERSION
        | SL_IOCTL_CONN_UPDATE_PARAMS
        | SL_IOCTL_CONN_PHY_UPDATE => Err(Error::from_errno(-(bindings::EOPNOTSUPP as i32))),
        _ => Err(EINVAL),
    }
}

fn ioctl_dispatch_security(_context: &RuntimeContext, _cmd: u32, _arg: usize) -> Result<isize> {
    Err(Error::from_errno(-(bindings::EOPNOTSUPP as i32)))
}

fn ioctl_dispatch_infra(context: &RuntimeContext, me: Pin<&SparkLinkCtl>, cmd: u32, arg: usize) -> Result<isize> {
    match cmd {
        SL_IOCTL_SNOOP_GET => ioctl_snoop_get(context, me, arg),
        SL_IOCTL_DIAGNOSTIC_RESULT => ioctl_diagnostic_result(context, me, arg),
        SL_IOCTL_CONTROLLER_SNAPSHOT => ioctl_controller_snapshot(context, me, arg),
        SL_IOCTL_SECURITY_NEGOTIATION_SUBMIT | SL_IOCTL_SECURITY_NEGOTIATION_RESULT | SL_IOCTL_SECURITY_NEGOTIATION_CANCEL | SL_IOCTL_SECURITY_NUMERIC_CONFIRM | SL_IOCTL_CONNECTION_SECURITY => ioctl_security_negotiation(context,me,cmd,arg),
        SL_IOCTL_CONNECTION_SUBMIT => ioctl_connection_submit(context, me, arg),
        SL_IOCTL_CONNECTION_RESULT => ioctl_connection_result(context, me, arg),
        SL_IOCTL_LINK_SNAPSHOT => ioctl_link_snapshot(context, me, arg),
        SL_IOCTL_DISCOVERY_SUBMIT => ioctl_discovery_submit(context, me, arg),
        SL_IOCTL_DISCOVERY_RESULT => ioctl_discovery_result(context, me, arg),
        SL_IOCTL_DISCOVERY_TIMING => ioctl_discovery_timing(context, me, arg),
        SL_IOCTL_CONTROLLER_EVENT_GET => ioctl_controller_event_get(context, me, arg),
        // No qualified hardware PM transaction or snapshot is connected.
        SL_IOCTL_PM_INFO | SL_IOCTL_PM_SET_STATE | SL_IOCTL_PM_SET_INTERVAL
        | SL_IOCTL_PM_FORCE_ACTIVE | SL_IOCTL_PM_TICK | SL_IOCTL_PM_ACTIVITY
            => Err(Error::from_errno(-(bindings::EOPNOTSUPP as i32))),
        SL_IOCTL_SYNC_UCAST_PARAM
        | SL_IOCTL_SYNC_UCAST_CREATE
        | SL_IOCTL_SYNC_UCAST_REMOVE
        | SL_IOCTL_SYNC_MCAST_PARAM
        | SL_IOCTL_SYNC_MCAST_CREATE
        | SL_IOCTL_SYNC_MCAST_REMOVE
        | SL_IOCTL_SYNC_DATAPATH_CFG
        | SL_IOCTL_SYNC_DATAPATH_REMOVE
        | SL_IOCTL_SYNC_INFO
        | SL_IOCTL_SYNC_UCAST_ACCEPT
        | SL_IOCTL_SYNC_UCAST_REJECT
        | SL_IOCTL_SYNC_MCAST_ACCEPT
        | SL_IOCTL_SYNC_MCAST_REJECT => Err(Error::from_errno(-(bindings::EOPNOTSUPP as i32))),
        SL_IOCTL_SYNC_DATA_SEND => Err(Error::from_errno(-(bindings::EOPNOTSUPP as i32))),
        SL_IOCTL_DLI_INFO => Err(Error::from_errno(-(bindings::EOPNOTSUPP as i32))),
        SL_IOCTL_DLI_RESET => Err(Error::from_errno(-(bindings::EOPNOTSUPP as i32))),
        SL_IOCTL_DLI_SEND_CMD => Err(Error::from_errno(-(bindings::EOPNOTSUPP as i32))),
        SL_IOCTL_MGMT_STATS => {
            // Only actual standard Diagnostic author transactions use this
            // ledger. Never project its zero counters as Native Host state.
            if context.owner.as_ref().ok_or(ENODEV)?.protocol_profile != 0 {
                return Err(Error::from_errno(-(bindings::EOPNOTSUPP as i32)));
            }
            let ss = context.lock()?;
            let s = ss.as_ref().ok_or(ENODEV)?;
            let stats = SleMgmtStats {
                pending: s.cmd_pending.pending(),
                _pad: 0,
                total_submitted: s.cmd_pending.total_submitted as u32,
                total_resolved: s.cmd_pending.total_resolved as u32,
                total_timeouts: s.cmd_pending.total_timeouts as u32,
            };
            drop(ss);
            write_user_struct(arg, &stats)?;
            Ok(0)
        }
        SL_IOCTL_USB_DEV_COUNT => Err(Error::from_errno(-(bindings::EOPNOTSUPP as i32))),
        // No authenticated PHY transaction or confirmed hardware snapshot is
        // implemented. Local models must not impersonate controller state.
        SL_IOCTL_PHY_INFO
        | SL_IOCTL_PHY_SET_MCS
        | SL_IOCTL_PHY_SET_TXPOWER
        | SL_IOCTL_PHY_MCS_SELECT
        | SL_IOCTL_PHY_HOP_NEXT
        | SL_IOCTL_PHY_SET_BW
        | SL_IOCTL_PHY_GET_SINR
        | SL_IOCTL_PHY_SET_SINR => Err(Error::from_errno(-(bindings::EOPNOTSUPP as i32))),
        SL_IOCTL_SET_ROLE | SL_IOCTL_GET_ROLE
            => Err(Error::from_errno(-(bindings::EOPNOTSUPP as i32))),
        SL_IOCTL_RAL_ADD | SL_IOCTL_RAL_REMOVE | SL_IOCTL_RAL_CLEAR | SL_IOCTL_RAL_SIZE
        | SL_IOCTL_RAL_READ_PEER_RPA | SL_IOCTL_RAL_READ_LOCAL_RPA
        | SL_IOCTL_RPA_ENABLE | SL_IOCTL_RPA_SET_TIMEOUT
            => Err(Error::from_errno(-(bindings::EOPNOTSUPP as i32))),
        SL_IOCTL_MEAS_READ_CAP | SL_IOCTL_MEAS_SET_LINK_PARAM
        | SL_IOCTL_MEAS_ACTION | SL_IOCTL_MEAS_ENABLE
            => Err(Error::from_errno(-(bindings::EOPNOTSUPP as i32))),
        _ => Err(EINVAL),
    }
}
