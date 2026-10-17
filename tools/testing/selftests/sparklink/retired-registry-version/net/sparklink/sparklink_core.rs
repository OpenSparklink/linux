pub(crate) fn install_backend_runtime(
    identity: sle_dev::DeviceIdentity, state: KBox<ControllerState>, initial_command_credits: u8,
    queried: Option<([u8; 6], u32)>,
) -> Result<Arc<ControllerRuntime>> {
    let registration = {
        let registry = SUBSYSTEM.lock();
        let shared = registry.as_ref().ok_or(ENODEV)?;
        let dev = shared.dev_registry.get(identity.id).ok_or(ENODEV)?;
        if dev.identity() != identity || dev.test_flag(sle_dev::SLE_DEV_UNREGISTERING) { return Err(ENODEV); }
        if shared.runtime(identity.id).is_some() { return Err(EBUSY); }
        let mut name = [0; 32];
        let len = dev.name().len().min(name.len());
        name[..len].copy_from_slice(&dev.name()[..len]);
        RuntimeRegistration { identity, bus: dev.bus(),
            addr: queried.map_or(*dev.addr(), |info| info.0), name }
    };
    let owner = ControllerRuntime::new(registration, state, initial_command_credits)?;
    {
        let mut registry = SUBSYSTEM.lock();
        let shared = registry.as_mut().ok_or(ENODEV)?;
        let dev = shared.dev_registry.get(identity.id).ok_or(ENODEV)?;
        if dev.identity() != identity || dev.test_flag(sle_dev::SLE_DEV_UNREGISTERING) { return Err(ENODEV); }
        let slot = shared.runtimes.get_mut(identity.id as usize).ok_or(EINVAL)?;
        if slot.is_some() { return Err(EBUSY); }
        *slot = Some(owner.clone());
        if let Some((addr, version)) = queried { shared.dev_registry.update_hw_info(identity.id, addr, version); }
    }
    Ok(owner)
}
