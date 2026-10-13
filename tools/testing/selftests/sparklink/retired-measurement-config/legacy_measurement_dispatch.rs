        // -- Narrowband AFH measurement (T/XS 10003-2025 §8.7) --
        SL_IOCTL_MEAS_READ_CAP => {
            let ss = context.lock()?;
            let s = ss.as_ref().ok_or(ENODEV)?;
            let cinfo = s.controller.info();
            let cap = SleMeasCap {
                meas_types: cinfo.measurement_cap,
                max_instances: 1,
                antenna_count: 1,
                _reserved: 0,
            };
            drop(ss);
            write_user_struct(arg, &cap)?;
            Ok(0)
        }
        SL_IOCTL_MEAS_SET_LINK_PARAM => {
            let params: SleMeasLinkParam = read_user_struct(arg)?;
            let mut buf = [0u8; 8];
            buf[0..2].copy_from_slice(&params.handle.to_le_bytes());
            buf[2] = params.meas_type;
            buf[3] = params.config_index;
            buf[4..6].copy_from_slice(&params.interval.to_le_bytes());
            buf[6..8].copy_from_slice(&params.duration.to_le_bytes());
            let ss = context.lock()?;
            let s = ss.as_ref().ok_or(ENODEV)?;
            s.controller.send_command(sle_dli::SleOpcode::SetMeasLinkParam, &buf)?;
            Ok(0)
        }
        SL_IOCTL_MEAS_ACTION => {
            let action: SleMeasAction = read_user_struct(arg)?;
            let buf = [
                action.handle.to_le_bytes()[0],
                action.handle.to_le_bytes()[1],
                action.action,
                action.config_index,
            ];
            let ss = context.lock()?;
            let s = ss.as_ref().ok_or(ENODEV)?;
            s.controller.send_command(sle_dli::SleOpcode::MeasAction, &buf)?;
            Ok(0)
        }
        SL_IOCTL_MEAS_ENABLE => {
            let enable: u8 = read_user_struct(arg)?;
            let ss = context.lock()?;
            let s = ss.as_ref().ok_or(ENODEV)?;
            s.controller.send_command(sle_dli::SleOpcode::EnableMeas, &[enable])?;
            Ok(0)
        }
