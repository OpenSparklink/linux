// Retired static installation/open, not production.
/// Switch the subsystem controller backend to USB.
///
/// Called from USB probe after identity reservation and C-side registration
/// succeed. Creates per-device protocol state and switches the active
/// device by selecting its fixed Runtime slot. Other owners remain in place.
pub(crate) fn sle_switch_controller_usb(identity: sle_dev::DeviceIdentity, device: sle_usb::UsbDevice, addr: [u8; 6], fw_version: u32, credits: u8) -> Result {
    let backend = sle_dli::ControllerBackend::new_usb(addr, fw_version, credits, identity, device)?;
    let mut state = ControllerState::new_boxed(addr, backend)?;
    state.command_credits = credits;
    let owner = install_backend_runtime(identity, state, true, Some((addr, fw_version)))?;
    open_usb_runtime(&owner)
}

/// Listener startup/adoption under the shared Backend lifecycle barrier.
/// The cloned USB transport retains resources of this exact reservation.
pub(crate) fn open_usb_runtime(owner: &Arc<ControllerRuntime>) -> Result {
    // Same open/close barrier as Native. Teardown closes the gate
    // immediately, then joins this before taking state/C resources.
    let lifecycle = owner.native_lifecycle.lock();
    sle_ingress::publish_runtime(owner)?;
    let transport = {
        let guard = owner.state.lock();
        if *owner.schedule_gate.lock() { return Err(ENODEV); }
        let Some(sle_dli::ControllerBackend::Usb(transport)) =
            guard.as_ref().map(|state| &state.controller) else { return Err(ENODEV) };
        transport.clone()
    };
    // No state/registry/Host/IRQ lock across listener startup. Failed
    // open cleans its partial listener; successful but retired open
    // must be joined before this borrowed handle is discarded.
    transport.open()?;
    {
        let gate = owner.schedule_gate.lock();
        if *gate {
            drop(gate);
            transport.close();
            return Err(ENODEV);
        }
        owner.transport_open.store(true, core::sync::atomic::Ordering::Release);
    }
    drop(lifecycle);
    owner.start_workers();
    pr_info!("sparklink: controller switched to USB (sle{})\n", owner.identity.id);
    Ok(())
}
