        SL_IOCTL_INJECT_CONN_RESP => {
            let resp: SleInjectConnResp = read_user_struct(arg)?;
            let resp_type = AccessResponseType::from_raw(resp.response_type).ok_or(EINVAL)?;
            let params = NegotiatedParams {
                bandwidth_mhz: resp.bandwidth_mhz,
                mcs_index: resp.mcs_index,
                supervision_timeout: resp.supervision_timeout,
                ..Default::default()
            };
            let (handle, peer_addr, result) = {
                let mut ss = context.lock()?;
                let s = Option::as_mut(&mut *ss).ok_or(ENODEV)?;
                let handle = s.conn.resolve_handle(resp.handle)?;
                let peer_addr = s.conn.info(handle).map(|e| e.peer_addr).unwrap_or([0u8; 6]);
                let result = s.conn.process_access_response(handle, resp_type, params);
                if result.is_err() && s.controller.uses_command_host() {
                    if let Some(wire_handle) = s.conn.retire_rejected_link(handle) {
                        s.controller.disconnect(wire_handle)?;
                    }
                }
                if result.is_ok() && resp.data_mtu > 0 {
                    let mps = if resp.data_mps > 0 {
                        Some(resp.data_mps)
                    } else {
                        None
                    };
                    let _ = s.conn.set_data_mtu(handle, resp.data_mtu, mps);
                }
                (handle, peer_addr, result)
            };
            match &result {
                Ok(()) => {
}
                Err(_) => {
}
            }
            result.map(|()| 0isize)
        }
