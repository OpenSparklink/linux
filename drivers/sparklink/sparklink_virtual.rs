// SPDX-License-Identifier: GPL-2.0

//! Virtual SparkLink controller driver for testing.
//!
//! This placeholder only logs module load/unload. It does not register a
//! controller. Existing core-owned virtual development tests are separate;
//! driver registration and lifecycle migration remain open in issues #9/#12.

use kernel::prelude::*;

module! {
    type: SparkLinkVirtual,
    name: "sparklink_virtual",
    authors: ["SparkLink for Linux Contributors"],
    description: "Virtual SparkLink controller driver",
    license: "GPL",
}

struct SparkLinkVirtual;

impl kernel::Module for SparkLinkVirtual {
    fn init(_module: &'static ThisModule) -> Result<Self> {
        pr_info!("sparklink_virtual: virtual controller loaded\n");
        Ok(SparkLinkVirtual)
    }
}

impl Drop for SparkLinkVirtual {
    fn drop(&mut self) {
        pr_info!("sparklink_virtual: virtual controller unloaded\n");
    }
}
