fn ioctl_security(context: &RuntimeContext, cmd: u32, arg: usize) -> Result<isize> {
    match cmd {
        SL_IOCTL_SEC_SET_PSK => {
            let params: SlePskParams = read_user_struct(arg)?;
            let mut ss = context.lock()?;
            let s = Option::as_mut(&mut *ss).ok_or(ENODEV)?;
            s.security.set_psk(params.psk);
            Ok(0)
        }
        SL_IOCTL_SEC_PAIR => Err(Error::from_errno(-(bindings::EOPNOTSUPP as i32))),
        SL_IOCTL_SEC_INFO => {
            let info = {
                let ss = context.lock()?;
                let s = ss.as_ref().ok_or(ENODEV)?;
                let mut info: SleSecInfo = unsafe { core::mem::zeroed() };
                info.state = s.security.state as u8;
                info.method = s.security.method as u8;
                info.mode = s.security.mode as u8;
                info.enc_enabled = if s.security.is_encrypted() { 1 } else { 0 };
                info.enc_key_fingerprint = s.security.enc_key_fingerprint()?;
                info
            };
            write_user_struct(arg, &info)?;
            Ok(0)
        }
        SL_IOCTL_SEC_ENCRYPT_ON => {
            let mut ss = context.lock()?;
            let s = Option::as_mut(&mut *ss).ok_or(ENODEV)?;
            s.security.enable_encryption()?;
            Ok(0)
        }
        // Legacy test ioctls are not a production crypto interface. Algorithm
        // and failure tests exercise the wrappers in dedicated selftests.
        SL_IOCTL_SEC_SM3_TEST
        | SL_IOCTL_SEC_SM4_ENC_TEST
        | SL_IOCTL_SEC_SM4_DEC_TEST
        | SL_IOCTL_SEC_SM4_BLOCK_TEST
        | SL_IOCTL_SEC_HMAC_TEST => Err(Error::from_errno(-(bindings::EOPNOTSUPP as i32))),
        SL_IOCTL_SEC_RESET => {
            let mut ss = context.lock()?;
            let s = Option::as_mut(&mut *ss).ok_or(ENODEV)?;
            s.security.reset();
            Ok(0)
        }
        SL_IOCTL_SEC_GET_PASSKEY => {
            let ss = context.lock()?;
            let s = ss.as_ref().ok_or(ENODEV)?;
            let passkey = s.security.get_passkey()?;
            drop(ss);
            write_user_struct(arg, &passkey)?;
            Ok(0)
        }
        SL_IOCTL_SEC_CONFIRM_PASSKEY => {
            let mut ss = context.lock()?;
            let s = Option::as_mut(&mut *ss).ok_or(ENODEV)?;
            s.security.confirm_passkey()?;
            Ok(0)
        }
        SL_IOCTL_SEC_REJECT_PASSKEY => {
            let mut ss = context.lock()?;
            let s = Option::as_mut(&mut *ss).ok_or(ENODEV)?;
            s.security.reject_passkey();
            Ok(0)
        }
        SL_IOCTL_SEC_SET_OOB => {
            ioctl_set_oob(context, arg)?;
            Ok(0)
        }
        SL_IOCTL_SEC_INPUT_PASSKEY => {
            let params: SlePasskeyInput = read_user_struct(arg)?;
            let mut ss = context.lock()?;
            let s = Option::as_mut(&mut *ss).ok_or(ENODEV)?;
            s.security.input_passkey(params.passkey)?;
            Ok(0)
        }
        SL_IOCTL_SEC_SET_PASSWORD => {
            let params: SlePasswordParams = read_user_struct(arg)?;
            let mut ss = context.lock()?;
            let s = Option::as_mut(&mut *ss).ok_or(ENODEV)?;
            s.security.set_password(&params.data, params.len)?;
            Ok(0)
        }
        _ => Err(EINVAL),
    }
}

/// AFH and security ioctl router — delegates to domain-specific handlers.
#[inline(never)]
fn ioctl_dispatch_security(context: &RuntimeContext, cmd: u32, arg: usize) -> Result<isize> {
    match cmd {
        SL_IOCTL_AFH_SET_MAP
        | SL_IOCTL_AFH_GET_MAP
        | SL_IOCTL_AFH_REPORT_RSSI
        | SL_IOCTL_AFH_CLASSIFY
        | SL_IOCTL_AFH_HOP_NEXT
        | SL_IOCTL_AFH_REPORT_RETX => Err(Error::from_errno(-(bindings::EOPNOTSUPP as i32))),

        SL_IOCTL_SEC_SET_PSK
        | SL_IOCTL_SEC_PAIR
        | SL_IOCTL_SEC_INFO
        | SL_IOCTL_SEC_ENCRYPT_ON
        | SL_IOCTL_SEC_SM3_TEST
        | SL_IOCTL_SEC_SM4_ENC_TEST
        | SL_IOCTL_SEC_SM4_DEC_TEST
        | SL_IOCTL_SEC_SM4_BLOCK_TEST
        | SL_IOCTL_SEC_HMAC_TEST
        | SL_IOCTL_SEC_RESET
        | SL_IOCTL_SEC_GET_PASSKEY
        | SL_IOCTL_SEC_CONFIRM_PASSKEY
        | SL_IOCTL_SEC_REJECT_PASSKEY
        | SL_IOCTL_SEC_SET_OOB
        | SL_IOCTL_SEC_INPUT_PASSKEY
        | SL_IOCTL_SEC_SET_PASSWORD => ioctl_security(context, cmd, arg),

        _ => Err(EINVAL),
    }
}

/// Handle SEC_SET_OOB ioctl in a separate stack frame to avoid
/// bloating the main ioctl function's stack usage.
#[inline(never)]
fn ioctl_set_oob(context: &RuntimeContext, arg: usize) -> Result {
    let params: SleOobData = read_user_struct(arg)?;
    let mut ss = context.lock()?;
    let s = Option::as_mut(&mut *ss).ok_or(ENODEV)?;
    s.security.set_oob_data(&params.data)?;
    Ok(())
}

/// Handle RAL_ADD ioctl in a separate stack frame (SleRalAddParams is 44 bytes).
#[inline(never)]
fn ioctl_ral_add(context: &RuntimeContext, arg: usize) -> Result {
    let params: SleRalAddParams = read_user_struct(arg)?;
    let entry = RalEntry {
        peer_id_type: params.peer_id_type,
        resolve_algo: params.resolve_algo,
        peer_irkid: params.peer_irkid,
        local_irkid: params.local_irkid,
        peer_id: params.peer_id,
        peer_irk: params.peer_irk,
        local_irk: params.local_irk,
    };
    let mut ss = context.lock()?;
    let s = Option::as_mut(&mut *ss).ok_or(ENODEV)?;
    s.rpa.ral_add(entry)
}

/// Handle RAL_READ_PEER_RPA / RAL_READ_LOCAL_RPA ioctls.
#[inline(never)]
fn ioctl_ral_read_rpa(context: &RuntimeContext, arg: usize, is_local: bool) -> Result {
    let mut params: SleRalQueryParams = read_user_struct(arg)?;
    let rpa = {
        let ss = context.lock()?;
        let s = ss.as_ref().ok_or(ENODEV)?;
        if is_local {
            s.rpa.read_local_rpa(params.id_type, &params.id)?
        } else {
            s.rpa.read_peer_rpa(params.id_type, &params.id)?
        }
    };
    params.rpa = rpa;
    write_user_struct(arg, &params)
}

