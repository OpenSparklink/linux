// SPDX-License-Identifier: GPL-2.0-only
/// DLI event returned to userspace via DLI_POLL_EVENT ioctl.
#[repr(C)]
#[derive(Copy, Clone)]
pub(crate) struct SleDliEvent {
    /// Event type discriminator.
    pub event_type: u8,
    /// Status code (0 = success).
    pub status: u8,
    /// Associated connection handle (if any).
    pub handle: u16,
    /// Opcode that triggered this event (for CommandComplete/Status).
    pub opcode: u16,
    /// Payload length.
    pub data_len: u16,
    /// Event payload.
    pub data: [u8; 240],
    /// Associated address (for conn/adv events).
    pub addr: [u8; 6],
    pub(crate) _pad: [u8; 2],
}

impl Default for SleDliEvent {
    fn default() -> Self {
        // SAFETY: SleDliEvent is repr(C) with all primitive fields; zeroed is valid.
        unsafe { core::mem::zeroed() }
    }
}

