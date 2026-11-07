// SPDX-License-Identifier: GPL-2.0

//! SparkLink configfs interface.
//!
//! Exposes runtime-configurable parameters under
//! `/sys/kernel/config/sparklink/`:
//!
//! - `version` (read-only): protocol stack version string
//! No global radio/power/backend selector exists. Device parameters belong
//! to typed Native requests; board/firmware input belongs to matched drivers.

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
