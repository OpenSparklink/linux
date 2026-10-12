// SPDX-License-Identifier: GPL-2.0

//! SparkLink transport protocol registration and driver attach framework.
//!
//! Provides the infrastructure for SparkLink controller drivers to register
//! transport protocols and attach physical devices to the subsystem at
//! probe time, following the same model as Bluetooth's `hci_uart_proto` +
//! `hci_register_dev()`.
//!
//! Only the USB transport descriptor is registered by the production core.
//! Historical H4/SPI descriptors have no registered bus provider and are not
//! advertised. They remain experimental references outside the default graph.
//! The remaining static registry is to be replaced by the shared Backend seam;
//! a descriptor is not evidence of initialized hardware or transport capability.

use kernel::prelude::*;

use super::sle_dli::SleBus;

// =========================================================================
// Transport protocol registration
// =========================================================================

/// Maximum number of registered transport protocols.
const MAX_PROTOS: usize = 8;

/// Well-known transport protocol identifiers.
///
/// Follows the hci_uart numbering convention: each transport framing
/// format gets a unique slot in the protocol registry.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum SleProtoId {
    /// UART H4-style framing (packet type indicator + header + payload).
    H4Uart = 0,
    /// USB bulk/interrupt endpoint transport.
    UsbBulk = 1,
    /// SPI register-based transport.
    Spi = 2,
    /// Reserved.
    Reserved = 3,
}

/// Static properties of a transport protocol (like `hci_uart_proto`).
///
/// Each transport framing format (H4, USB bulk, SPI register)
/// registers one of these at module init time.
pub(crate) struct SleProtoEntry {
    /// Protocol identifier.
    pub id: SleProtoId,
    /// Human-readable name (e.g. "sparklink-h4").
    pub name: &'static str,
    /// Bus type for devices using this protocol.
    pub bus: SleBus,
    /// Default max PDU payload (can be overridden per-device).
    pub max_pdu: u16,
    /// Expected initial baud rate (UART only, 0 for others).
    pub init_speed: u32,
    /// Expected operational baud rate (UART only, 0 for others).
    pub oper_speed: u32,
}

/// Global transport protocol registry.
///
/// Transport modules call `register()` during their module_init to make
/// their framing protocol available. When a physical device is probed,
/// the probe handler calls `sle_attach_device()` with the protocol id
/// to create a device entry.
pub(crate) struct SleProtoRegistry {
    slots: [Option<SleProtoEntry>; MAX_PROTOS],
    count: u8,
}

impl SleProtoRegistry {
    pub(crate) const fn new() -> Self {
        Self {
            slots: [const { None }; MAX_PROTOS],
            count: 0,
        }
    }

    /// Register a transport protocol.
    ///
    /// Returns `EINVAL` if the id exceeds the registry capacity, or
    /// `EEXIST` if a protocol with the same id is already registered.
    pub(crate) fn register(&mut self, entry: SleProtoEntry) -> Result {
        let idx = entry.id as usize;
        if idx >= MAX_PROTOS {
            return Err(EINVAL);
        }
        if self.slots[idx].is_some() {
            return Err(EEXIST);
        }
        self.slots[idx] = Some(entry);
        self.count += 1;
        Ok(())
    }

    /// Unregister a transport protocol by id.
    ///
    /// Returns `EBUSY` if any device binding still references this protocol.
    pub(crate) fn unregister(
        &mut self,
        id: SleProtoId,
        bindings: &SleBindingTable,
    ) -> Result {
        let idx = id as usize;
        if idx >= MAX_PROTOS {
            return Err(EINVAL);
        }
        if self.slots[idx].is_none() {
            return Err(ENOENT);
        }
        if bindings.has_bindings_for(id) {
            return Err(EBUSY);
        }
        self.slots[idx] = None;
        self.count = self.count.saturating_sub(1);
        Ok(())
    }

    /// Look up a registered protocol.
    pub(crate) fn get(&self, id: SleProtoId) -> Option<&SleProtoEntry> {
        let idx = id as usize;
        if idx < MAX_PROTOS {
            self.slots[idx].as_ref()
        } else {
            None
        }
    }

    /// Number of registered protocols.
    pub(crate) fn count(&self) -> u8 {
        self.count
    }

    /// Iterate registered protocols.
    pub(crate) fn iter(&self) -> impl Iterator<Item = &SleProtoEntry> {
        self.slots.iter().filter_map(|s| s.as_ref())
    }
}

// =========================================================================
// Device attach / detach
// =========================================================================

/// Information passed to `sle_attach_device()` by driver probe callbacks.
///
/// Combines the transport protocol id with per-device properties
/// discovered during hardware enumeration.
pub(crate) struct SleAttachInfo {
    /// Which transport protocol this device uses.
    pub proto_id: SleProtoId,
    /// 6-byte SLE MAC address (read from the device or defaulted).
    pub addr: [u8; 6],
    /// Firmware version (0 if not yet known).
    pub fw_version: u32,
    /// Feature bitmask (0 if not yet read).
    pub features: u64,
    /// Extended feature bits 64-72.
    pub features_ext: u16,
    /// Queried maximum PDU payload size (0 = unknown/unavailable).
    pub max_pdu: u16,
    /// Queried connection limit (0 = unknown/unavailable, not unlimited).
    pub max_connections: u8,
}

impl SleAttachInfo {
    /// Create an attach-info with minimal fields; the rest use defaults.
    pub(crate) fn new(proto_id: SleProtoId, addr: [u8; 6]) -> Self {
        Self {
            proto_id,
            addr,
            fw_version: 0,
            features: 0,
            features_ext: 0,
            max_pdu: 0,
            max_connections: 0,
        }
    }
}

/// Outcome of a successful `sle_attach_device()` call.
pub(crate) struct SleAttachResult {
    /// Allocated device id from the SleDev registry.
    pub dev_id: u16,
}

// =========================================================================
// Device binding record
// =========================================================================

/// Maximum number of concurrently bound transport devices.
const MAX_BOUND_DEVS: usize = 16;

/// Per-device binding linking a SleDev to its transport protocol.
///
/// Created by `sle_attach_device()`, removed by `sle_detach_device()`.
/// This record tracks the association between a device in the registry
/// and the transport protocol used to communicate with the hardware,
/// similar to how each `hci_dev` in Bluetooth stores its transport ops.
pub(crate) struct SleDevBinding {
    /// Device id in the SleDev registry.
    pub dev_id: u16,
    /// Transport protocol used by this device.
    pub proto_id: SleProtoId,
    /// Whether the device has been opened (transport active).
    pub opened: bool,
}

/// Table of active device bindings.
///
/// Indexed by device id for O(1) lookup. Entries are allocated on
/// `sle_attach_device()` and freed on `sle_detach_device()`.
pub(crate) struct SleBindingTable {
    slots: [Option<SleDevBinding>; MAX_BOUND_DEVS],
    count: u8,
}

impl SleBindingTable {
    pub(crate) const fn new() -> Self {
        Self {
            slots: [const { None }; MAX_BOUND_DEVS],
            count: 0,
        }
    }

    /// Insert a binding. Returns `ENOMEM` if the table is full.
    pub(crate) fn insert(&mut self, binding: SleDevBinding) -> Result {
        let idx = binding.dev_id as usize;
        if idx >= MAX_BOUND_DEVS {
            return Err(ENOMEM);
        }
        if self.slots[idx].is_some() {
            return Err(EEXIST);
        }
        self.slots[idx] = Some(binding);
        self.count += 1;
        Ok(())
    }

    /// Remove a binding by device id.
    pub(crate) fn remove(&mut self, dev_id: u16) -> Option<SleDevBinding> {
        let idx = dev_id as usize;
        if idx >= MAX_BOUND_DEVS {
            return None;
        }
        let entry = self.slots[idx].take();
        if entry.is_some() {
            self.count = self.count.saturating_sub(1);
        }
        entry
    }

    /// Look up a binding by device id.
    pub(crate) fn get(&self, dev_id: u16) -> Option<&SleDevBinding> {
        let idx = dev_id as usize;
        if idx < MAX_BOUND_DEVS {
            self.slots[idx].as_ref()
        } else {
            None
        }
    }

    /// Mutable lookup.
    pub(crate) fn get_mut(&mut self, dev_id: u16) -> Option<&mut SleDevBinding> {
        let idx = dev_id as usize;
        if idx < MAX_BOUND_DEVS {
            self.slots[idx].as_mut()
        } else {
            None
        }
    }

    /// Number of bound devices.
    pub(crate) fn count(&self) -> u8 {
        self.count
    }

    /// Check if any binding references the given protocol.
    pub(crate) fn has_bindings_for(&self, proto_id: SleProtoId) -> bool {
        self.slots
            .iter()
            .any(|s| matches!(s, Some(b) if b.proto_id == proto_id))
    }

    /// Iterate bound devices.
    pub(crate) fn iter(&self) -> impl Iterator<Item = &SleDevBinding> {
        self.slots.iter().filter_map(|s| s.as_ref())
    }
}

// =========================================================================
// Built-in protocol definitions
// =========================================================================

/// Built-in USB bulk transport protocol entry.
pub(crate) const USB_BULK_PROTO: SleProtoEntry = SleProtoEntry {
    id: SleProtoId::UsbBulk,
    name: "sparklink-usb",
    bus: SleBus::Usb,
    max_pdu: 255,
    init_speed: 0,
    oper_speed: 0,
};

/// Register all built-in transport protocols into the given registry.
pub(crate) fn register_builtin_protos(reg: &mut SleProtoRegistry) {
    let _ = reg.register(USB_BULK_PROTO);
}
