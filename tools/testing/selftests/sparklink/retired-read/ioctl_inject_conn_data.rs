fn ioctl_inject_conn_data(context: &RuntimeContext, me: Pin<&SparkLinkCtl>, arg: usize) -> Result<isize> {
    let cd: SleConnData = read_user_struct(arg)?;
    let len = cd.length as usize;
    // An injected transport frame must contain data. Validate before handle
    // lookup or any TCID/SSAP access; oversized input must not be truncated.
    if len == 0 || len > CONN_DATA_MAX {
        return Err(EINVAL);
    }
    let raw = &cd.data[..len];
    {
        let mut ss = context.lock()?;
        let s = Option::as_mut(&mut *ss).ok_or(ENODEV)?;
        let s = &mut **s;
        let handle = s.conn.resolve_handle(cd.handle)?;
        if !raw.is_empty()
            && u16::from(raw[0]) == sle_conn::tcid::MANAGEMENT
            && raw.len() >= sle_conn::CREDIT_GRANT_PDU_SIZE
            && raw[1] == sle_conn::CREDIT_GRANT_PDU_TYPE
        {
            // Credit grant signaling (T/XS 20002-2025 §7.3.3):
            // [TCID 0x02] [code 0xFC] [identifier] [length LE16] [target_tcid] [credits LE16]
            let target_tcid = u16::from(raw[5]);
            let credits = u16::from_le_bytes([raw[6], raw[7]]);
            let _ = s.conn.receive_credits(handle, target_tcid, credits);
        } else if !raw.is_empty()
            && u16::from(raw[0]) == sle_conn::tcid::MANAGEMENT
            && raw.len() >= 5
            && raw[1] != sle_conn::CREDIT_GRANT_PDU_TYPE
        {
            // Transport control signaling (T/XS 20002-2025 §7.3.4).
            let sig_data = &raw[1..];
            let mut resp_buf = [0u8; 32];
            let resp_len = s
                .conn
                .handle_transport_signaling(handle, sig_data, &mut resp_buf)?;
            if resp_len > 0 {
                let _ = s.controller.send_data(handle, &resp_buf[..resp_len]);
            }
        } else if !raw.is_empty()
            && u16::from(raw[0]) == sle_conn::tcid::SERVICE_MGMT
        {
            return Err(Error::from_errno(-(kernel::bindings::EOPNOTSUPP as i32)));
        } else {
            // Unqualified dynamic reliable input has no production consumer.
            let first_byte_tcid = u16::from(raw[0]);
            let is_dynamic_reliable = raw.len() > 1
                && s.conn
                    .dynamic_reliable_tcid(handle)
                    .map(|t| t == first_byte_tcid)
                    .unwrap_or(false);
            if is_dynamic_reliable {
                return Err(Error::from_errno(-(kernel::bindings::EOPNOTSUPP as i32)));
            } else {
                let payload = if !raw.is_empty()
                    && u16::from(raw[0]) == sle_conn::tcid::DEFAULT_DATA
                    && raw.len() > 1
                {
                    let _ = s
                        .conn
                        .consume_rx_credit(handle, sle_conn::tcid::DEFAULT_DATA);
                    &raw[1..]
                } else {
                    raw
                };
                let seq = {
                    let entry = s.conn.info(handle)?;
                    entry.seq.rx_seq
                };
                s.conn.receive_data(handle, payload, seq)?;
            }
        }
    }
    SparkLinkCtl::broadcast_event(
                context,
        me.as_ref(),
        sle_event::SleWireEvent::data_received(cd.handle, len as u16),
    )?;
    dev_info!(
        me.dev,
        "sparklink: injected {} bytes connection data (handle={})\n",
        len,
        cd.handle
    );
    Ok(0)
}
