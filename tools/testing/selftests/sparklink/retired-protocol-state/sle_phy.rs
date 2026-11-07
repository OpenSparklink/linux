// SPDX-License-Identifier: GPL-2.0

//! Channel-map/hopping helpers still called by the legacy connection path.
//! Hardware PHY configuration is not provided by these local algorithms.
//! Retained pending connection/TCID migration; no PHY support claim.

// =========================================================================
// Frequency hopping (T/XS 10002-2025 section 5.3)
//
// SLE uses adaptive frequency hopping (AFH) across the 2.4 GHz ISM
// band. The channel map has 79 channels (0-78), each 1 MHz wide,
// starting at 2402 MHz (channel 0).
//
// The hopping sequence is generated using a permutation-based algorithm
// that maps (connection_event_counter, hop_increment, channel_map) to
// a used channel index, avoiding channels marked as bad in the map.
// =========================================================================

/// Total number of frequency channels in the SLE band (2402-2480 MHz).
pub(crate) const NUM_CHANNELS: u8 = 79;

/// Channel map: bitmask of usable channels (79 bits).
/// Bit N set = channel N is usable.
#[derive(Copy, Clone, Debug)]
pub(crate) struct ChannelMap {
    /// 10-byte bitmask (80 bits, only bits 0-78 used).
    pub(crate) map: [u8; 10],
    /// Number of used channels (cached).
    used_count: u8,
}

impl ChannelMap {
    /// Create a channel map where all 79 channels are usable.
    pub(crate) fn all_used() -> Self {
        let mut map = [0xFFu8; 10];
        // Clear bit 79 (not a valid channel)
        map[9] &= 0x7F;
        Self {
            map,
            used_count: NUM_CHANNELS,
        }
    }

    /// Create a channel map from a raw 10-byte bitmask.
    pub(crate) fn from_raw(raw: [u8; 10]) -> Self {
        let mut s = Self {
            map: raw,
            used_count: 0,
        };
        s.map[9] &= 0x7F; // mask off bit 79
        s.recount();
        s
    }

    /// Recalculate the used channel count.
    fn recount(&mut self) {
        let mut count = 0u8;
        for ch in 0..NUM_CHANNELS {
            if self.is_used(ch) {
                count += 1;
            }
        }
        self.used_count = count;
    }

    /// Check if a channel is marked as usable.
    pub(crate) fn is_used(&self, channel: u8) -> bool {
        if channel >= NUM_CHANNELS {
            return false;
        }
        let byte_idx = (channel / 8) as usize;
        let bit_idx = channel % 8;
        (self.map[byte_idx] >> bit_idx) & 1 != 0
    }

    /// Mark a channel as used or unused.
    pub(crate) fn set_used(&mut self, channel: u8, used: bool) {
        if channel >= NUM_CHANNELS {
            return;
        }
        let byte_idx = (channel / 8) as usize;
        let bit_idx = channel % 8;
        if used {
            self.map[byte_idx] |= 1 << bit_idx;
        } else {
            self.map[byte_idx] &= !(1 << bit_idx);
        }
        self.recount();
    }

    /// Number of usable channels.
    pub(crate) fn used_count(&self) -> u8 {
        self.used_count
    }

    /// Get the Nth used channel (0-indexed among used channels).
    /// Returns `None` if n >= used_count.
    pub(crate) fn nth_used(&self, n: u8) -> Option<u8> {
        let mut count = 0u8;
        for ch in 0..NUM_CHANNELS {
            if self.is_used(ch) {
                if count == n {
                    return Some(ch);
                }
                count += 1;
            }
        }
        None
    }
}

/// Frequency hopping state for a connection.
#[derive(Clone, Debug)]
pub(crate) struct HoppingState {
    /// Hop increment (1-78), derived from connection parameters.
    pub(crate) hop_increment: u8,
    /// Current channel map.
    pub(crate) channel_map: ChannelMap,
    /// Connection event counter (wraps at u16::MAX).
    pub(crate) event_counter: u16,
    /// Last selected channel.
    pub(crate) last_channel: u8,
}

impl HoppingState {
    /// Create a new hopping state with given increment and channel map.
    pub(crate) fn new(hop_increment: u8, channel_map: ChannelMap) -> Self {
        let hop = if hop_increment == 0 || hop_increment >= NUM_CHANNELS {
            7 // default to 7 if invalid
        } else {
            hop_increment
        };
        Self {
            hop_increment: hop,
            channel_map,
            event_counter: 0,
            last_channel: 0,
        }
    }

    /// Compute the next channel for the current event counter and advance.
    ///
    /// Algorithm per T/XS 10002-2025 section 5.3:
    /// 1. unmapped_channel = (last_channel + hop_increment) mod 79
    /// 2. If unmapped_channel is in the channel map, use it directly
    /// 3. Otherwise, remap: used_channel[unmapped_channel mod used_count]
    pub(crate) fn next_channel(&mut self) -> u8 {
        let unmapped = (u16::from(self.last_channel) + u16::from(self.hop_increment))
            % u16::from(NUM_CHANNELS);
        let unmapped = unmapped as u8;

        let channel = if self.channel_map.is_used(unmapped) {
            unmapped
        } else {
            let used = self.channel_map.used_count();
            if used == 0 {
                0 // degenerate case: no channels available
            } else {
                let remap_idx = unmapped % used;
                self.channel_map.nth_used(remap_idx).unwrap_or(0)
            }
        };

        self.last_channel = channel;
        self.event_counter = self.event_counter.wrapping_add(1);
        channel
    }

    /// Get the RF frequency in MHz for a channel index.
    /// Channel 0 = 2402 MHz, Channel 78 = 2480 MHz.
    pub(crate) fn channel_to_freq(channel: u8) -> u16 {
        2402 + u16::from(channel)
    }

    /// Update the channel map (e.g., after AFH classification).
    pub(crate) fn update_map(&mut self, new_map: ChannelMap) {
        self.channel_map = new_map;
    }
}
