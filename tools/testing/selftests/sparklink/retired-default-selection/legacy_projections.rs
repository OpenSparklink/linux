    fn default_selection() -> Self {
        let ss = SUBSYSTEM.lock();
        Self {
            owner: ss.as_ref().and_then(|s| s.active_dev_id.and_then(|id| s.runtime(id))),
        }
    }

    pub(crate) fn switch_to_device(&mut self, new_id: u16) -> Result {
        if self.dev_registry.get(new_id).is_none() || self.runtime(new_id).is_none() {
            return Err(ENODEV);
        }
        self.active_dev_id = Some(new_id);
        Ok(())
    }

fn ioctl_dev_switch(arg: usize) -> Result<isize> {
    let target_id: u16 = read_user_struct(arg)?;
    let mut ss = SUBSYSTEM.lock();
    let s = Option::as_mut(&mut *ss).ok_or(ENODEV)?;
    if s.dev_registry.get(target_id).is_none() {
        return Err(ENODEV);
    }
    s.switch_to_device(target_id)?;
    pr_info!("sparklink: switched active device to sle{}\n", target_id);
    Ok(0)
}

            _dli_info <- debugfs.read_callback_file(
                c"dli_controller",
                Atomic::<u32>::new(0),
                &|_dummy: &Atomic<u32>, f: &mut core::fmt::Formatter<'_>| {
                    let context = RuntimeContext::default_selection();
                    if let Ok(guard) = context.lock() {
                        let ss = guard.as_ref().expect("validated live Runtime");
                        let cinfo = ss.controller.info();
                        let major = (cinfo.fw_version >> 16) & 0xFF;
                        let minor = (cinfo.fw_version >> 8) & 0xFF;
                        let patch = cinfo.fw_version & 0xFF;
                        writeln!(f, "bus: {:?}", cinfo.bus)?;
                        writeln!(f, "firmware: {}.{}.{}", major, minor, patch)?;
                        writeln!(f, "features: 0x{:016x}", cinfo.features)?;
                        writeln!(f, "features_ext: 0x{:04x}", cinfo.features_ext)?;
                        writeln!(f, "max_connections: {}", cinfo.max_connections)?;
                        writeln!(f, "max_mtu: {}", cinfo.max_mtu)?;
                        writeln!(f, "max_mps: {}", cinfo.max_mps)?;
                        writeln!(f, "transport_modes: 0x{:02x}", cinfo.transport_modes)?;
                        writeln!(f, "measurement_cap: 0x{:02x}", cinfo.measurement_cap)?;
                        writeln!(f, "security_cap: 0x{:04x}", cinfo.security_cap)?;
                    }
                    Ok(())
                },
            ),
            _mgmt_stats <- mgmt_dir.read_callback_file(
                c"stats",
                Atomic::<u32>::new(0),
                &|_dummy: &Atomic<u32>, f: &mut core::fmt::Formatter<'_>| {
                    let context = RuntimeContext::default_selection();
                    if let Ok(guard) = context.lock() {
                        let ss = guard.as_ref().expect("validated live Runtime");
                        let q = &ss.cmd_pending;
                        writeln!(f, "pending: {}", q.pending_count)?;
                        writeln!(f, "submitted: {}", q.total_submitted)?;
                        writeln!(f, "resolved: {}", q.total_resolved)?;
                        writeln!(f, "timeouts: {}", q.total_timeouts)?;
                        writeln!(f, "cmd_queue_depth: {}", ss.cmd_queue.len())?;
                    }
                    Ok(())
                },
            ),


        SL_IOCTL_DLI_INFO => {
            let ss = context.lock()?;
            let s = ss.as_ref().ok_or(ENODEV)?;
            let cinfo = s.controller.info();
            let mut name = [0u8; 32];
            let copy_len = cinfo.name.len().min(31);
            name[..copy_len].copy_from_slice(&cinfo.name[..copy_len]);
            let info = SleDliInfo {
                bus: cinfo.bus as u8,
                _pad: [0u8; 3],
                firmware_version: cinfo.fw_version,
                features: cinfo.features,
                max_connections: cinfo.max_connections,
                max_adv_sets: 0, // Unavailable in this legacy ABI, not a capability promise.
                transport_modes: cinfo.transport_modes,
                measurement_cap: cinfo.measurement_cap,
                max_mtu: cinfo.max_mtu,
                max_mps: cinfo.max_mps,
                security_cap: cinfo.security_cap,
                features_ext: cinfo.features_ext,
                name,
                _reserved: [0u8; 4],
            };
            drop(ss);
            write_user_struct(arg, &info)?;
            Ok(0)
        }


        SL_IOCTL_MGMT_STATS => {
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


        SL_IOCTL_DLI_RESET => {
            let mut ss = context.lock()?;
            let s = Option::as_mut(&mut *ss).ok_or(ENODEV)?;
            s.controller.reset()?;
            Ok(0)
        }
