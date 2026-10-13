// Retired experiment, not compiled into kernel; historical tests only.
// SPDX-License-Identifier: GPL-2.0

//! Firmware loading for the legacy generic USB controller backend.
//!
//! The caller supplies the firmware filename. The firmware
//! blob is loaded from the standard Linux firmware search path
//! (`/lib/firmware/`) using `kernel::firmware::Firmware`, then sent to
//! the controller in chunks via the USB bulk OUT endpoint.
//!
//! Native WS73 firmware is owned separately by `drivers/sparklink/ws73`.
//!
//! Download protocol (over USB):
//!
//! ```text
//!   Host                          Controller
//!    |                                |
//!    |-- FW_DOWNLOAD_START (size) --> |
//!    |                                |
//!    |-- FW_DATA chunk 0 ----------> |
//!    |-- FW_DATA chunk 1 ----------> |
//!    |   ...                          |
//!    |-- FW_DATA chunk N ----------> |
//!    |                                |
//!    |-- FW_DOWNLOAD_DONE ---------> |
//!    |<-- CommandComplete (status) -- |
//! ```
//!

use kernel::firmware::Firmware;
use kernel::prelude::*;

// ---------------------------------------------------------------------------
// FFI declarations — C-side firmware download
// ---------------------------------------------------------------------------

extern "C" {
    fn sle_usb_dev_download_fw(context: *mut super::sle_usb::UsbDeviceOpaque, data: *const u8, size: i32, chunk_size: i32) -> i32;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Default chunk size for firmware download (bytes).
/// 0 delegates chunk sizing to the C USB transport.
const FW_DEFAULT_CHUNK_SIZE: i32 = 0;

/// Maximum firmware size (4 MiB) — prevents i32 overflow in FFI call and
/// rejects unreasonably large blobs early.
const FW_MAX_SIZE: usize = 4 * 1024 * 1024;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Load firmware for a USB-attached SLE controller.
///
/// Attempts to load the firmware file from `/lib/firmware/sparklink/`
/// and download it to the controller via USB bulk transfer.
///
/// `dev` is the kernel `device::Device` reference used for the firmware
/// request (typically from the USB interface).
///
/// `dev_id` is the device ID in the USB device table.
///
/// Returns `Ok(size)` on success, `Err` if the firmware
/// file is not found or the download protocol fails.
///
/// Errors are returned to the caller; fallback policy belongs to its probe.
pub(crate) fn load_usb_firmware(
    device: &super::sle_usb::UsbDevice,
    fw_name: &kernel::str::CStr,
    dev: &kernel::device::Device,
) -> Result<usize> {
    // Request firmware from the standard search path.
    let fw = match Firmware::request(fw_name, dev) {
        Ok(fw) => fw,
        Err(e) => {
            pr_info!("sparklink-fw: firmware request failed: {}\n", e.to_errno());
            return Err(e);
        }
    };

    let size = fw.size();
    if size == 0 {
        pr_warn!("sparklink-fw: firmware file is empty\n");
        return Err(EINVAL);
    }
    if size > FW_MAX_SIZE {
        pr_err!(
            "sparklink-fw: firmware too large ({} bytes, max {})\n",
            size,
            FW_MAX_SIZE
        );
        return Err(EFBIG);
    }

    pr_info!("sparklink-fw: loaded {} bytes, starting download\n", size);

    // Download via the C FFI layer.
    // SAFETY: fw.data() returns a valid slice for the firmware lifetime,
    // sle_usb_dev_download_fw copies from it synchronously.
    let ret = unsafe {
        sle_usb_dev_download_fw(
            device.as_raw(),
            fw.data().as_ptr(),
            size as i32,
            FW_DEFAULT_CHUNK_SIZE,
        )
    };

    if ret != 0 {
        pr_err!(
            "sparklink-fw: download failed: {}\n",
            ret
        );
        return Err(if ret < 0 { Error::from_errno(ret) } else { EIO });
    }

    Ok(size)
}
