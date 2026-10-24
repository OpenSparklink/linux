// Retired optional-firmware bootstrap, never production.
fn initialize_usb_controller(device: &UsbDevice) -> Result {
    // SAFETY: probe owns the live registered interface throughout this call.
    let ret = unsafe { sle_usb_dev_init_controller(device.as_raw()) };
    if ret != 0 {
        return Err(if ret < 0 { Error::from_errno(ret) } else { EIO });
    }
    Ok(())
}
fn prepare_usb_controller(
    device: &UsbDevice,
    dev: &kernel::device::Device,
) -> Result<([u8; 6], u32)> {
    // Bootstrap must establish a real controller before optional firmware.
    initialize_usb_controller(device)?;
    let fw_name = kernel::c_str!("sparklink/sle_usb_v1.bin");
    match super::sle_fw::load_usb_firmware(device, fw_name, dev) {
        Ok(size) => {
            pr_info!("sparklink-usb: firmware loaded ({} bytes)\n", size);
            // Cached identity predates the download. Require fresh successful
            // Reset/version/MAC replies before publishing this binding.
            initialize_usb_controller(device)?;
        }
        Err(ENOENT) => pr_debug!("sparklink-usb: optional firmware absent\n"),
        Err(error) => return Err(error),
    }

    let mut addr = [0u8; 6];
    // SAFETY: probe owns a live registered binding; addr has six bytes.
    let ret = unsafe { sle_usb_dev_get_mac(device.as_raw(), addr.as_mut_ptr()) };
    if ret != 0 {
        return Err(if ret < 0 { Error::from_errno(ret) } else { EIO });
    }
    if addr == [0; 6] || addr == [0xff; 6] {
        return Err(Error::from_errno(-(kernel::bindings::EPROTO as i32)));
    }
    // SAFETY: the mandatory successful bootstrap populated this binding.
    let fw_version = unsafe { sle_usb_dev_get_fw_version(device.as_raw()) };
    Ok((addr, fw_version))
}
fn probe_usb_device(interface: &usb::Interface<device::Core>) -> Result<UsbBinding> {
    pr_info!("sparklink-usb: SLE controller discovered\n");

    let identity = super::reserve_usb_identity()?;
    let dev_id = identity.id;
    let mut registered: Option<UsbDevice> = None;
    let result = (|| -> Result {
        pr_info!("sparklink-usb: attached as sle{}\n", dev_id);

        // Register the USB interface in the C-side device table so
        // send_command / send_data can perform actual I/O.
        //
        // The interface pointer survives as long as the driver is
        // bound (guaranteed by USB core).
        let intf_ptr = core::ptr::from_ref::<usb::Interface<device::Core>>(interface)
            as *mut core::ffi::c_void;
        // SAFETY: dev_id is valid; intf_ptr points to a live USB
        // interface that outlives this driver binding.
        registered = Some(UsbDevice::create(identity, intf_ptr)?);
        let device = registered.as_ref().ok_or(ENODEV)?;
        let kern_dev: &kernel::device::Device<kernel::device::Core> = interface.as_ref();
        let (addr, fw_version) = prepare_usb_controller(device, kern_dev)?;

        // Switch the subsystem controller backend to USB and sync
        // the device registry with real hardware info.
        // SAFETY: mandatory bootstrap completed on this still-live binding.
        let credits = unsafe { sle_usb_dev_get_command_credits(device.as_raw()) };
        super::sle_switch_controller_usb(identity, device.clone(), addr, fw_version, credits)?;
        Ok(())
    })();
    if let Err(error) = result {
        super::sle_quiesce_device(identity);
        if let Some(device) = registered.as_ref() { device.retire(); }
        super::sle_detach_device(identity);
        return Err(error);
    }
    USB_DEV_COUNT.fetch_add(1, Ordering::Relaxed);

    Ok(UsbBinding { identity, device: registered.ok_or(ENODEV)? })
}
