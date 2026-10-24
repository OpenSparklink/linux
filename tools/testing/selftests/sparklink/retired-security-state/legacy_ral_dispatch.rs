        SL_IOCTL_RAL_ADD => {
            ioctl_ral_add(context, arg)?;
            Ok(0)
        }
        SL_IOCTL_RAL_REMOVE => {
            let params: SleRalRemoveParams = read_user_struct(arg)?;
            let mut ss = context.lock()?;
            let s = Option::as_mut(&mut *ss).ok_or(ENODEV)?;
            s.rpa.ral_remove(params.peer_id_type, &params.peer_id)?;
            Ok(0)
        }
        SL_IOCTL_RAL_CLEAR => {
            let mut ss = context.lock()?;
            let s = Option::as_mut(&mut *ss).ok_or(ENODEV)?;
            s.rpa.ral_clear()?;
            Ok(0)
        }
        SL_IOCTL_RAL_SIZE => {
            let ss = context.lock()?;
            let s = ss.as_ref().ok_or(ENODEV)?;
            let count = s.rpa.ral_size();
            write_user_struct(arg, &count)?;
            Ok(0)
        }
        SL_IOCTL_RAL_READ_PEER_RPA => {
            ioctl_ral_read_rpa(context, arg, false)?;
            Ok(0)
        }
        SL_IOCTL_RAL_READ_LOCAL_RPA => {
            ioctl_ral_read_rpa(context, arg, true)?;
            Ok(0)
        }
        SL_IOCTL_RPA_ENABLE => {
            let enable: u8 = read_user_struct(arg)?;
            let mut ss = context.lock()?;
            let s = Option::as_mut(&mut *ss).ok_or(ENODEV)?;
            s.rpa.set_enabled(enable != 0);
            Ok(0)
        }
        SL_IOCTL_RPA_SET_TIMEOUT => {
            let secs: u16 = read_user_struct(arg)?;
            let mut ss = context.lock()?;
            let s = Option::as_mut(&mut *ss).ok_or(ENODEV)?;
            s.rpa.set_timeout(secs);
            Ok(0)
        }
