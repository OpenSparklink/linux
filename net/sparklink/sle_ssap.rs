// SPDX-License-Identifier: GPL-2.0

//! SLE Service Access Protocol (SSAP) — attribute service layer.
//!
//! Legacy local service staging and connection metadata. This is NOT a
//! qualified SSAP wire implementation; the replacement Engine lives in slkd.
//!
//! Core concepts:
//!   - Service: a group of related entries with a UUID
//!   - Property: readable/writable data with operation indicators
//!   - Method: callable function interface with input/output
//!   - Event: server-initiated notification or indication
//!   - Descriptor: metadata attached to a property (format, config)
//!
//! Remote transactions, notifications, indications and method echo are
//! unsupported until a standard Engine and per-connection PDU owner are ready.

#![allow(dead_code, unreachable_pub)]

use kernel::alloc::KVec;
use kernel::prelude::*;

// ---------------------------------------------------------------------------
// SSAP message codes (T/XS 20001-2025 table 7.4)
// ---------------------------------------------------------------------------

/// SSAP protocol message types.
#[repr(u8)]
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum SsapMsgCode {
    ErrorRsp = 0x01,
    ExchangeInfoReq = 0x02,
    ExchangeInfoRsp = 0x03,
    FindStructureReq = 0x04,
    FindStructureRsp = 0x05,
    FindByUuidReq = 0x06,
    FindByUuidRsp = 0x07,
    ReadReq = 0x08,
    ReadRsp = 0x09,
    ReadByUuidReq = 0x0A,
    ReadByUuidRsp = 0x0B,
    WriteCmd = 0x0C,
    WriteReq = 0x0D,
    WriteRsp = 0x0E,
    ValueNtf = 0x0F,
    ValueInd = 0x10,
    ValueAck = 0x11,
    CallMethodCmd = 0x12,
    CallMethodReq = 0x13,
    CallMethodRsp = 0x14,
}

// ---------------------------------------------------------------------------
// Entry categories (T/XS 20001-2025 section 7.4.3)
// ---------------------------------------------------------------------------

/// Category byte for a service entry.
#[repr(u8)]
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum EntryCategory {
    PrimaryService = 0x00,
    SecondaryService = 0x01,
    Property = 0x02,
    Method = 0x03,
    Event = 0x04,
    ServiceRef = 0x05,
    CustomPrimaryService = 0x08,
    CustomSecondaryService = 0x09,
    CustomProperty = 0x0A,
    CustomMethod = 0x0B,
    CustomEvent = 0x0C,
    CustomServiceRef = 0x0D,
}

// ---------------------------------------------------------------------------
// UUID representation
// ---------------------------------------------------------------------------

/// Service/characteristic UUID: either 16-bit standard or 128-bit custom.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum SsapUuid {
    /// Standard 16-bit UUID from the SparkLink allocated range.
    Uuid16(u16),
    /// Vendor-specific 128-bit UUID.
    Uuid128([u8; 16]),
}

impl SsapUuid {
    /// Check if this is a custom UUID (128 bits).
    pub fn is_custom(&self) -> bool {
        matches!(self, SsapUuid::Uuid128(_))
    }

    /// Return the 16-bit value, or None for 128-bit UUIDs.
    pub fn as_u16(&self) -> Option<u16> {
        match self {
            SsapUuid::Uuid16(v) => Some(*v),
            SsapUuid::Uuid128(_) => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Operation indicator (4 bytes, T/XS 20001-2025 section 7.4.3.5)
// ---------------------------------------------------------------------------

/// Operation permissions on a property entry (4-byte bitmask).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct OpIndicator(u32);

impl OpIndicator {
    /// Property can be read.
    pub const READ: Self = Self(1 << 0);
    /// Property can be written without response.
    pub const WRITE_NO_RSP: Self = Self(1 << 1);
    /// Property can be written with response.
    pub const WRITE_WITH_RSP: Self = Self(1 << 2);
    /// Server can send notifications (no ack).
    pub const NOTIFY: Self = Self(1 << 3);
    /// Server can send indications (with ack).
    pub const INDICATE: Self = Self(1 << 4);
    /// Property value carried in broadcast PDUs.
    pub const BROADCAST: Self = Self(1 << 5);
    /// Description descriptor is writable.
    pub const DESC_WRITABLE: Self = Self(1 << 8);
    /// Client config descriptor is writable.
    pub const CLIENT_CFG_WR: Self = Self(1 << 9);
    /// Server config descriptor is writable.
    pub const SERVER_CFG_WR: Self = Self(1 << 10);

    /// Create an empty indicator with no flags set.
    pub const fn empty() -> Self {
        Self(0)
    }

    /// Check if all bits in `other` are set in `self`.
    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    /// Raw u32 value.
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// Construct from a raw bitmask value.
    pub const fn from_raw(v: u32) -> Self {
        Self(v)
    }
}

impl core::ops::BitOr for OpIndicator {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

impl core::ops::BitAnd for OpIndicator {
    type Output = Self;
    fn bitand(self, rhs: Self) -> Self {
        Self(self.0 & rhs.0)
    }
}

// ---------------------------------------------------------------------------
// Descriptors
// ---------------------------------------------------------------------------

/// Standard descriptor types (T/XS 20001-2025 section 7.4.3.7).
#[repr(u8)]
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum DescriptorType {
    /// UTF-8 text description of the property.
    PropertyDesc = 0x01,
    /// Per-client notification/indication configuration (2 bytes).
    ClientConfig = 0x02,
    /// Server broadcast configuration (2 bytes).
    ServerConfig = 0x03,
    /// Property format (7 bytes): type, exponent, unit, desc.
    PropertyFormat = 0x04,
}

/// Data type codes for PropertyFormat descriptor.
#[repr(u8)]
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum DataType {
    Uint8 = 0x01,
    Uint16 = 0x02,
    Uint32 = 0x03,
    Uint64 = 0x04,
    Int8 = 0x05,
    Int16 = 0x06,
    Int32 = 0x07,
    Int64 = 0x08,
    Boolean = 0x09,
    Float32 = 0x0A,
    Float64 = 0x0B,
    Utf8String = 0x0C,
    Utf16String = 0x0D,
    Array = 0x0E,
    Structure = 0x0F,
}

/// Client configuration descriptor flags.
#[repr(u16)]
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum ClientConfigFlag {
    /// Notifications disabled.
    None = 0x0000,
    /// Notifications enabled.
    Notification = 0x0001,
    /// Indications enabled.
    Indication = 0x0002,
}

/// Descriptor storage.
pub struct Descriptor {
    pub dtype: DescriptorType,
    pub data: KVec<u8>,
}

// ---------------------------------------------------------------------------
// Property / Method / Event entries
// ---------------------------------------------------------------------------

/// Maximum value length for an in-memory property.
pub const PROPERTY_VALUE_MAX: usize = 512;

/// A single property entry in a service.
pub struct PropertyEntry {
    /// Handle assigned by the server (0x0010..0xFFFF).
    pub handle: u16,
    /// UUID identifying the property type.
    pub uuid: SsapUuid,
    /// Operation indicator flags.
    pub ops: OpIndicator,
    /// Current value bytes (up to PROPERTY_VALUE_MAX).
    pub value: KVec<u8>,
    /// Attached descriptors.
    pub descriptors: KVec<Descriptor>,
    /// Client-config: notifications/indications enabled.
    pub client_cfg: u16,
    /// Per-property maximum value length (defaults to PROPERTY_VALUE_MAX).
    pub max_len: u16,
}

/// A method entry in a service.
pub struct MethodEntry {
    pub handle: u16,
    pub uuid: SsapUuid,
    /// Input parameter buffer (from last call).
    pub input: KVec<u8>,
    /// Output result buffer (from last call).
    pub output: KVec<u8>,
}

/// An event entry in a service.
pub struct EventEntry {
    pub handle: u16,
    pub uuid: SsapUuid,
    /// Whether this event is enabled for the client.
    pub enabled: bool,
    /// Last event data payload.
    pub data: KVec<u8>,
}

// ---------------------------------------------------------------------------
// Service structure
// ---------------------------------------------------------------------------

/// A registered service in the SSAP database.
pub struct ServiceEntry {
    /// Start handle of the service.
    pub start_handle: u16,
    /// End handle of the service (inclusive).
    pub end_handle: u16,
    /// Service UUID.
    pub uuid: SsapUuid,
    /// Whether this is a primary or secondary service.
    pub primary: bool,
    /// Properties within this service.
    pub properties: KVec<PropertyEntry>,
    /// Methods within this service.
    pub methods: KVec<MethodEntry>,
    /// Events within this service.
    pub events: KVec<EventEntry>,
}

// ---------------------------------------------------------------------------
// SSAP exchange info (capability negotiation)
// ---------------------------------------------------------------------------

/// Negotiated SSAP parameters after EXCHANGE_INFO handshake.
#[derive(Copy, Clone, Debug)]
pub struct SsapNegotiated {
    /// Effective MTU: min(client_mtu, server_mtu).
    pub mtu: u16,
    /// Protocol version (major, minor).
    pub version: (u8, u8),
    /// Whether reliable transport mode is agreed.
    pub reliable_mode: bool,
    /// Whether SSAP fragmentation sequence is agreed.
    pub frag_seq: bool,
    /// Negotiated max SSAP message transaction ID count (0 = disabled).
    pub max_tid: u8,
}

impl Default for SsapNegotiated {
    fn default() -> Self {
        Self {
            mtu: 247,
            version: (1, 0),
            reliable_mode: false,
            frag_seq: false,
            max_tid: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// SSAP error codes (T/XS 20001-2025 section 7.4.8)
// ---------------------------------------------------------------------------

/// SSAP protocol error codes for ERROR_RSP.
#[repr(u8)]
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum SsapError {
    /// Operation completed successfully.
    Success = 0x00,
    /// Invalid handle.
    InvalidHandle = 0x01,
    /// Read not permitted.
    ReadNotPermitted = 0x02,
    /// Write not permitted.
    WriteNotPermitted = 0x03,
    /// Invalid message code.
    InvalidMsgCode = 0x04,
    /// Authentication required.
    AuthRequired = 0x05,
    /// Request not supported.
    RequestNotSupported = 0x06,
    /// Invalid offset.
    InvalidOffset = 0x07,
    /// Insufficient resources.
    InsufficientResources = 0x08,
    /// Service not found.
    ServiceNotFound = 0x09,
    /// Property not found.
    PropertyNotFound = 0x0A,
    /// Method access error.
    MethodAccessError = 0x0C,
}

impl SsapError {
    /// Decode from raw byte, defaulting to RequestNotSupported for unknown values.
    pub fn from_raw(v: u8) -> Self {
        match v {
            0x00 => Self::Success,
            0x01 => Self::InvalidHandle,
            0x02 => Self::ReadNotPermitted,
            0x03 => Self::WriteNotPermitted,
            0x04 => Self::InvalidMsgCode,
            0x05 => Self::AuthRequired,
            0x06 => Self::RequestNotSupported,
            0x07 => Self::InvalidOffset,
            0x08 => Self::InsufficientResources,
            0x09 => Self::ServiceNotFound,
            0x0A => Self::PropertyNotFound,
            0x0C => Self::MethodAccessError,
            _ => Self::RequestNotSupported,
        }
    }
}

// ---------------------------------------------------------------------------
// SSAP inner state (runs inside a Mutex in sparklink_core)
// ---------------------------------------------------------------------------

/// The full SSAP server/client state for one file descriptor.
pub struct SsapInner {
    /// Registered local services.
    pub services: KVec<ServiceEntry>,
    /// Next handle to assign.
    next_handle: u16,
    /// Capability negotiation result.
    pub negotiated: SsapNegotiated,
}

impl SsapInner {
    /// Create a new empty SSAP context.
    pub fn new() -> Self {
        Self {
            services: KVec::new(),
            next_handle: 0x0010, // First user handle
            negotiated: SsapNegotiated::default(),
        }
    }

    // -----------------------------------------------------------------------
    // Handle allocation
    // -----------------------------------------------------------------------

    fn alloc_handle(&mut self) -> Result<u16> {
        let h = self.next_handle;
        self.next_handle = h.checked_add(1).ok_or(ENOSPC)?;
        Ok(h)
    }

    fn alloc_handles(&mut self, count: u16) -> Result<u16> {
        let start = self.next_handle;
        self.next_handle = start.checked_add(count).ok_or(ENOSPC)?;
        Ok(start)
    }

    // -----------------------------------------------------------------------
    // Service registration
    // -----------------------------------------------------------------------

    /// Register a new primary service with a 16-bit UUID.
    /// Returns the service start handle.
    pub fn register_service(&mut self, uuid: SsapUuid, primary: bool) -> Result<u16> {
        let start = self.alloc_handle()?;
        let svc = ServiceEntry {
            start_handle: start,
            end_handle: start, // Updated as entries are added
            uuid,
            primary,
            properties: KVec::new(),
            methods: KVec::new(),
            events: KVec::new(),
        };
        self.services.push(svc, GFP_KERNEL)?;
        Ok(start)
    }

    /// Add a property to the last registered service.
    pub fn add_property(
        &mut self,
        uuid: SsapUuid,
        ops: OpIndicator,
        initial_value: &[u8],
    ) -> Result<u16> {
        let handle = self.alloc_handle()?;
        let svc = self.services.last_mut().ok_or(ENODEV)?;

        let mut value = KVec::new();
        value.extend_from_slice(initial_value, GFP_KERNEL)?;

        let prop = PropertyEntry {
            handle,
            uuid,
            ops,
            value,
            descriptors: KVec::new(),
            client_cfg: 0,
            max_len: PROPERTY_VALUE_MAX as u16,
        };
        svc.properties.push(prop, GFP_KERNEL)?;
        svc.end_handle = handle;
        Ok(handle)
    }

    /// Add a method to the last registered service.
    pub fn add_method(&mut self, uuid: SsapUuid) -> Result<u16> {
        let handle = self.alloc_handle()?;
        let svc = self.services.last_mut().ok_or(ENODEV)?;

        let method = MethodEntry {
            handle,
            uuid,
            input: KVec::new(),
            output: KVec::new(),
        };
        svc.methods.push(method, GFP_KERNEL)?;
        svc.end_handle = handle;
        Ok(handle)
    }

    /// Add an event to the last registered service.
    pub fn add_event(&mut self, uuid: SsapUuid) -> Result<u16> {
        let handle = self.alloc_handle()?;
        let svc = self.services.last_mut().ok_or(ENODEV)?;

        let event = EventEntry {
            handle,
            uuid,
            enabled: false,
            data: KVec::new(),
        };
        svc.events.push(event, GFP_KERNEL)?;
        svc.end_handle = handle;
        Ok(handle)
    }

    /// Add a descriptor to the last property of the last service.
    pub fn add_descriptor(&mut self, dtype: DescriptorType, data: &[u8]) -> Result {
        let svc = self.services.last_mut().ok_or(ENODEV)?;
        let prop = svc.properties.last_mut().ok_or(ENODEV)?;

        let mut d = KVec::new();
        d.extend_from_slice(data, GFP_KERNEL)?;

        let desc = Descriptor { dtype, data: d };
        prop.descriptors.push(desc, GFP_KERNEL)?;
        Ok(())
    }

    /// Remove a service by its start handle.
    pub fn remove_service(&mut self, start_handle: u16) -> Result {
        let idx = self
            .services
            .iter()
            .position(|s| s.start_handle == start_handle);
        match idx {
            Some(i) => {
                let _ = self.services.remove(i);
                Ok(())
            }
            None => Err(ENOENT),
        }
    }

    /// Collect all registered standard (16-bit) service UUIDs.
    ///
    /// Used by the advertising engine to populate the FullStdServiceList TLV.
    pub fn collect_std_uuids(&self, out: &mut [u16; 32]) -> usize {
        let mut n = 0usize;
        for svc in self.services.iter() {
            if let SsapUuid::Uuid16(v) = svc.uuid {
                if n < out.len() {
                    out[n] = v;
                    n += 1;
                }
            }
        }
        n
    }

    /// Collect all registered custom (128-bit) service UUIDs.
    ///
    /// Used by the advertising engine to populate the FullCustomServiceList TLV.
    pub fn collect_custom_uuids(&self, out: &mut [[u8; 16]; 8]) -> usize {
        let mut n = 0usize;
        for svc in self.services.iter() {
            if let SsapUuid::Uuid128(v) = svc.uuid {
                if n < out.len() {
                    out[n] = v;
                    n += 1;
                }
            }
        }
        n
    }

    // -----------------------------------------------------------------------
    // Service discovery (FINDSTRUCTURE)
    // -----------------------------------------------------------------------

    /// Find all primary services. Returns (start_handle, end_handle, uuid) tuples.
    pub fn find_primary_services(&self) -> KVec<(u16, u16, SsapUuid)> {
        let mut result = KVec::new();
        for svc in self.services.iter() {
            if svc.primary {
                let _ = result.push((svc.start_handle, svc.end_handle, svc.uuid), GFP_KERNEL);
            }
        }
        result
    }

    /// Find a service by UUID.
    pub fn find_service_by_uuid(&self, uuid: &SsapUuid) -> Option<&ServiceEntry> {
        self.services.iter().find(|s| &s.uuid == uuid)
    }

    /// Find all entries within a handle range (service discovery).
    pub fn find_in_range(&self, start: u16, end: u16) -> KVec<EntryInfo> {
        let mut result = KVec::new();
        for svc in self.services.iter() {
            if svc.start_handle >= start && svc.start_handle <= end {
                let cat = if svc.primary {
                    EntryCategory::PrimaryService
                } else {
                    EntryCategory::SecondaryService
                };
                let _ = result.push(
                    EntryInfo {
                        handle: svc.start_handle,
                        category: cat,
                        uuid: svc.uuid,
                    },
                    GFP_KERNEL,
                );
            }
            for p in svc.properties.iter() {
                if p.handle >= start && p.handle <= end {
                    let _ = result.push(
                        EntryInfo {
                            handle: p.handle,
                            category: EntryCategory::Property,
                            uuid: p.uuid,
                        },
                        GFP_KERNEL,
                    );
                }
            }
            for m in svc.methods.iter() {
                if m.handle >= start && m.handle <= end {
                    let _ = result.push(
                        EntryInfo {
                            handle: m.handle,
                            category: EntryCategory::Method,
                            uuid: m.uuid,
                        },
                        GFP_KERNEL,
                    );
                }
            }
            for e in svc.events.iter() {
                if e.handle >= start && e.handle <= end {
                    let _ = result.push(
                        EntryInfo {
                            handle: e.handle,
                            category: EntryCategory::Event,
                            uuid: e.uuid,
                        },
                        GFP_KERNEL,
                    );
                }
            }
        }
        result
    }

    // -----------------------------------------------------------------------
    // Read / Write operations
    // -----------------------------------------------------------------------

    /// Read a property value by handle.
    pub fn read_property(&self, handle: u16) -> Result<KVec<u8>> {
        for svc in self.services.iter() {
            for p in svc.properties.iter() {
                if p.handle == handle {
                    if !p.ops.contains(OpIndicator::READ) {
                        return Err(EACCES);
                    }
                    let mut out = KVec::new();
                    out.extend_from_slice(&p.value, GFP_KERNEL)?;
                    return Ok(out);
                }
            }
        }
        Err(ENOENT)
    }

    /// Read a property by UUID (finds the first matching property).
    pub fn read_by_uuid(&self, uuid: &SsapUuid) -> Result<(u16, KVec<u8>)> {
        for svc in self.services.iter() {
            for p in svc.properties.iter() {
                if &p.uuid == uuid && p.ops.contains(OpIndicator::READ) {
                    let mut out = KVec::new();
                    out.extend_from_slice(&p.value, GFP_KERNEL)?;
                    return Ok((p.handle, out));
                }
            }
        }
        Err(ENOENT)
    }

    /// Write a property value by handle (write-with-response).
    pub fn write_property(&mut self, handle: u16, data: &[u8]) -> Result {
        if data.len() > PROPERTY_VALUE_MAX {
            return Err(EINVAL);
        }
        for svc in self.services.iter_mut() {
            for p in svc.properties.iter_mut() {
                if p.handle != handle {
                    continue;
                }
                if !p.ops.contains(OpIndicator::WRITE_WITH_RSP)
                    && !p.ops.contains(OpIndicator::WRITE_NO_RSP)
                {
                    return Err(EACCES);
                }
                if data.len() > p.max_len as usize {
                    return Err(EINVAL);
                }
                let mut replacement = KVec::new();
                replacement.extend_from_slice(data, GFP_KERNEL)?;
                p.value = replacement;
                // Local staging is not a remote service publication. Notification
                // routing/credits/ACKs require the userspace Engine and channel owner.
                return Ok(());
            }
        }
        Err(ENOENT)
    }

    /// Write client-configuration descriptor for a property.
    pub fn set_client_config(&mut self, handle: u16, config: u16) -> Result {
        for svc in self.services.iter_mut() {
            for p in svc.properties.iter_mut() {
                if p.handle == handle {
                    if !p.ops.contains(OpIndicator::CLIENT_CFG_WR) {
                        return Err(EACCES);
                    }
                    p.client_cfg = config;
                    return Ok(());
                }
            }
        }
        Err(ENOENT)
    }

    // -----------------------------------------------------------------------
    // Notification / indication
    // -----------------------------------------------------------------------

    /// Send a server-initiated notification for a property handle.
    pub fn notify(&mut self, _handle: u16) -> Result {
        Err(Error::from_errno(-(kernel::bindings::EOPNOTSUPP as i32)))
    }

    /// Send a server-initiated indication for a property handle.
    pub fn indicate(&mut self, _handle: u16) -> Result {
        Err(Error::from_errno(-(kernel::bindings::EOPNOTSUPP as i32)))
    }


    /// Get the number of pending notifications.
    pub fn notification_count(&self) -> usize {
        0 // No notification queue without a qualified connection owner.
    }

    // -----------------------------------------------------------------------
    // Method invocation
    // -----------------------------------------------------------------------

    /// No Profile callback is connected; reject instead of echoing success.
    pub fn call_method(&mut self, _handle: u16, _input: &[u8]) -> Result<KVec<u8>> {
        Err(Error::from_errno(-(kernel::bindings::EOPNOTSUPP as i32)))
    }

    // -----------------------------------------------------------------------
    // Built-in demo service: SparkLink Device Info
    // -----------------------------------------------------------------------

    /// Register the standard SparkLink device information service.
    /// UUID 0x0001 with properties: device_name (0x1001), firmware_version (0x1002).
    pub fn register_device_info_service(&mut self) -> Result {
        let svc_uuid = SsapUuid::Uuid16(0x0001);
        self.register_service(svc_uuid, true)?;

        // Property: Device Name (readable)
        let name = b"SparkLink Device";
        self.add_property(SsapUuid::Uuid16(0x1001), OpIndicator::READ, name)?;

        // Property: Firmware Version (readable)
        let fw = b"0.3.0";
        self.add_property(SsapUuid::Uuid16(0x1002), OpIndicator::READ, fw)?;

        // Property: Status (readable, writable, notifiable)
        let status: [u8; 1] = [0x00]; // idle
        let status_handle = self.add_property(
            SsapUuid::Uuid16(0x1003),
            OpIndicator::READ
                | OpIndicator::WRITE_WITH_RSP
                | OpIndicator::NOTIFY
                | OpIndicator::CLIENT_CFG_WR,
            &status,
        )?;

        // Add format descriptor to the status property
        let format = [
            DataType::Uint8 as u8, // type
            0x00,                  // decimal exponent
            0x00,                  // binary exponent
            0x00,
            0x00, // unit UUID (none)
            0x00,
            0x00, // description UUID (none)
        ];
        self.add_descriptor(DescriptorType::PropertyFormat, &format)?;

        // Event: Status Change
        self.add_event(SsapUuid::Uuid16(0x8001))?;

        // Method: Reset device (input: none, output: status byte)
        self.add_method(SsapUuid::Uuid16(0x7001))?;

        let _ = status_handle;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Summary / debug info
    // -----------------------------------------------------------------------

    /// Get total count of registered services.
    pub fn service_count(&self) -> usize {
        self.services.len()
    }

    /// Get total property count across all services.
    pub fn property_count(&self) -> usize {
        self.services.iter().map(|s| s.properties.len()).sum()
    }

    /// Get total handle count (services + properties + methods + events).
    pub fn total_entries(&self) -> usize {
        self.services
            .iter()
            .map(|s| 1 + s.properties.len() + s.methods.len() + s.events.len())
            .sum()
    }
}

// ---------------------------------------------------------------------------
// Discovery result info
// ---------------------------------------------------------------------------

/// Simplified entry info returned from discovery queries.
#[derive(Copy, Clone, Debug)]
pub struct EntryInfo {
    pub handle: u16,
    pub category: EntryCategory,
    pub uuid: SsapUuid,
}

// Legacy session metadata pending replacement by userspace SSAP ownership.

/// Per-connection SSAP session state.
///
/// Retained transport metadata for caller migration. No negotiation is run
/// and no services are published by this legacy context.
pub struct SsapSession {
    /// Connection handle this session is bound to.
    pub conn_handle: u16,
    /// Transport channel TCID (normally SERVICE_MGMT = 0x0A).
    pub tcid: u16,
    /// Negotiated MTU for this session.
    pub mtu: u16,
    /// Whether ExchangeInfo has completed.
    pub info_exchanged: bool,
    /// Peer supports SSAP reliable mode transport.
    pub reliable_mode: bool,
    /// Peer supports SSAP fragmentation sequence.
    pub frag_seq: bool,
    /// Negotiated max SSAP message transaction ID count (0 = disabled).
    pub max_tid: u8,
    /// Negotiated protocol version.
    pub version: (u8, u8),
    /// TCID for the reliable transport channel (None = not established).
    pub reliable_tcid: Option<u16>,
    /// Remote service cache for this peer.
    pub remote_db: RemoteServiceDb,
}

impl SsapSession {
    /// Create a new SSAP session bound to a connection.
    pub fn new(conn_handle: u16) -> Self {
        Self {
            conn_handle,
            tcid: crate::sle_conn::tcid::SERVICE_MGMT,
            mtu: 247,
            info_exchanged: false,
            reliable_mode: false,
            frag_seq: false,
            max_tid: 0,
            version: (1, 0),
            reliable_tcid: None,
            remote_db: RemoteServiceDb::new(),
        }
    }

    /// No legacy wire engine is available in production. The replacement SSAP
    /// Engine belongs to slkd and requires a qualified per-connection PDU fd.
    pub fn process_incoming(
        &mut self,
        _ssap: &mut SsapInner,
        _pdu_data: &[u8],
        _resp_buf: &mut [u8],
    ) -> Result<usize> {
        Err(Error::from_errno(-(kernel::bindings::EOPNOTSUPP as i32)))
    }
}

// ---------------------------------------------------------------------------
// Remote service database cache
// ---------------------------------------------------------------------------

/// Cached remote service database discovered via SSAP.
///
/// Stores the structural view of a remote peer's service database
/// obtained through FindStructure requests. This allows the local
/// host to look up remote handles without repeated over-the-air queries.
pub struct RemoteServiceDb {
    /// Discovered entries from the remote peer.
    pub entries: KVec<EntryInfo>,
    /// Whether a full discovery has been completed.
    pub discovery_complete: bool,
    /// Last-read property value (placeholder for request-response routing).
    pub last_read_value: KVec<u8>,
    /// Inbound remote notification/indication events.
    pub remote_events: KVec<RemoteEvent>,
    /// Last error received from remote peer.
    pub last_error: Option<SsapError>,
}

/// An inbound notification or indication from a remote peer.
pub struct RemoteEvent {
    /// Property handle on the remote device.
    pub handle: u16,
    /// True if indication (requires ACK), false if notification.
    pub indication: bool,
    /// Event data payload.
    pub data: KVec<u8>,
}

impl RemoteServiceDb {
    /// Create an empty remote service cache.
    pub fn new() -> Self {
        Self {
            entries: KVec::new(),
            discovery_complete: false,
            last_read_value: KVec::new(),
            remote_events: KVec::new(),
            last_error: None,
        }
    }

    /// Add a discovered entry to the cache.
    pub fn add_entry(&mut self, entry: EntryInfo) -> Result {
        // Avoid duplicates by handle.
        for existing in self.entries.iter() {
            if existing.handle == entry.handle {
                return Ok(());
            }
        }
        self.entries.push(entry, GFP_KERNEL)?;
        Ok(())
    }

    /// Find a remote service by UUID.
    pub fn find_service_by_uuid(&self, uuid: &SsapUuid) -> Option<&EntryInfo> {
        self.entries.iter().find(|e| {
            (e.category == EntryCategory::PrimaryService
                || e.category == EntryCategory::CustomPrimaryService)
                && e.uuid == *uuid
        })
    }

    /// Get all discovered primary services.
    pub fn primary_services(&self) -> impl Iterator<Item = &EntryInfo> {
        self.entries.iter().filter(|e| {
            e.category == EntryCategory::PrimaryService
                || e.category == EntryCategory::CustomPrimaryService
        })
    }

    /// Clear the cache (e.g. on disconnection).
    pub fn clear(&mut self) {
        self.entries.clear();
        self.last_read_value.clear();
        self.remote_events.clear();
        self.last_error = None;
        self.discovery_complete = false;
    }

    /// Number of cached entries.
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    /// Store an inbound remote notification/indication.
    pub fn push_remote_event(
        &mut self,
        handle: u16,
        indication: bool,
        data: &[u8],
    ) -> Result {
        let mut d = KVec::new();
        d.extend_from_slice(data, GFP_KERNEL)?;
        let evt = RemoteEvent {
            handle,
            indication,
            data: d,
        };
        self.remote_events.push(evt, GFP_KERNEL)?;
        Ok(())
    }

    /// Pop the oldest remote event, if any.
    pub fn pop_remote_event(&mut self) -> Option<RemoteEvent> {
        if self.remote_events.is_empty() {
            None
        } else {
            self.remote_events.remove(0).ok()
        }
    }
}
