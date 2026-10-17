// SPDX-License-Identifier: GPL-2.0

//! SparkLink configfs interface.
//!
//! Exposes runtime-configurable parameters under
//! `/sys/kernel/config/sparklink/`:
//!
//! - `version` (read-only): protocol stack version string
//! - `max_connections` (read/write): maximum simultaneous connections (1..8)
//! - `adv_interval_ms` (read/write): default advertising interval
//! - `scan_window_ms` (read/write): default scan window
//! - `power_mode`: unsupported retired global policy; no controller PM effect

use kernel::configfs;
use kernel::new_mutex;
use kernel::page::PAGE_SIZE;
use kernel::prelude::*;
use kernel::sync::Mutex;


const VERSION_STR: &[u8] = b"0.3.0\n";

#[pin_data]
pub(crate) struct SparkLinkConfig {
    #[pin]
    _dummy: Mutex<()>,
}

impl SparkLinkConfig {
    pub(crate) fn new() -> impl PinInit<Self, Error> {
        try_pin_init!(Self {
            _dummy <- new_mutex!(()),
        })
    }
}

// Attribute 0: version (read-only)
#[vtable]
impl configfs::AttributeOperations<0> for SparkLinkConfig {
    type Data = SparkLinkConfig;

    fn show(_data: &SparkLinkConfig, page: &mut [u8; PAGE_SIZE]) -> Result<usize> {
        page[..VERSION_STR.len()].copy_from_slice(VERSION_STR);
        Ok(VERSION_STR.len())
    }
}

// Attribute 1: retired local default; Native parameters come from typed requests.
#[vtable]
impl configfs::AttributeOperations<1> for SparkLinkConfig {
    type Data = SparkLinkConfig;
    fn show(_data: &SparkLinkConfig, _page: &mut [u8; PAGE_SIZE]) -> Result<usize> {
        Err(Error::from_errno(-(kernel::bindings::EOPNOTSUPP as i32)))
    }
    fn store(_data: &SparkLinkConfig, _page: &[u8]) -> Result {
        super::sle_authorization::require_admin()?;
        Err(Error::from_errno(-(kernel::bindings::EOPNOTSUPP as i32)))
    }
}

// Attribute 2: retired local default; Native parameters come from typed requests.
#[vtable]
impl configfs::AttributeOperations<2> for SparkLinkConfig {
    type Data = SparkLinkConfig;
    fn show(_data: &SparkLinkConfig, _page: &mut [u8; PAGE_SIZE]) -> Result<usize> {
        Err(Error::from_errno(-(kernel::bindings::EOPNOTSUPP as i32)))
    }
    fn store(_data: &SparkLinkConfig, _page: &[u8]) -> Result {
        super::sle_authorization::require_admin()?;
        Err(Error::from_errno(-(kernel::bindings::EOPNOTSUPP as i32)))
    }
}

// Attribute 3: retired local default; Native parameters come from typed requests.
#[vtable]
impl configfs::AttributeOperations<3> for SparkLinkConfig {
    type Data = SparkLinkConfig;
    fn show(_data: &SparkLinkConfig, _page: &mut [u8; PAGE_SIZE]) -> Result<usize> {
        Err(Error::from_errno(-(kernel::bindings::EOPNOTSUPP as i32)))
    }
    fn store(_data: &SparkLinkConfig, _page: &[u8]) -> Result {
        super::sle_authorization::require_admin()?;
        Err(Error::from_errno(-(kernel::bindings::EOPNOTSUPP as i32)))
    }
}

// Attribute 4: unsupported historical global policy; never affects controllers.
#[vtable]
impl configfs::AttributeOperations<4> for SparkLinkConfig {
    type Data = SparkLinkConfig;
    fn show(_data: &SparkLinkConfig, _page: &mut [u8; PAGE_SIZE]) -> Result<usize> {
        Err(Error::from_errno(-(kernel::bindings::EOPNOTSUPP as i32)))
    }
    fn store(_data: &SparkLinkConfig, _page: &[u8]) -> Result {
        super::sle_authorization::require_admin()?;
        Err(Error::from_errno(-(kernel::bindings::EOPNOTSUPP as i32)))
    }
}

// Attribute 5: controller_type (read/write, 0=none, 1=uart, 2=spi, 4=usb)
#[vtable]
impl configfs::AttributeOperations<5> for SparkLinkConfig {
    type Data = SparkLinkConfig;

    fn show(_data: &SparkLinkConfig, page: &mut [u8; PAGE_SIZE]) -> Result<usize> {
        let label = b"none\n";
        page[..label.len()].copy_from_slice(label);
        Ok(label.len())
    }

    fn store(_data: &SparkLinkConfig, page: &[u8]) -> Result {
        super::sle_authorization::require_admin()?;
        let s = core::str::from_utf8(page).map_err(|_| EINVAL)?;
        match s.trim() {
            "none" | "0" => {},
            // A global selector cannot attach a real device. These old names
            // are rejected until a registered bus Backend supplies the state.
            "uart" | "1" | "spi" | "2" | "usb" | "4" =>
                return Err(Error::from_errno(-(kernel::bindings::EOPNOTSUPP as i32))),
            _ => return Err(EINVAL),
        }
        Ok(())
    }
}
