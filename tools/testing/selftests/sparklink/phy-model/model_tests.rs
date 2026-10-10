// SPDX-License-Identifier: GPL-2.0-only
// Historical local model tests, not standard vectors or hardware PHY evidence.
extern crate self as kernel;
pub mod prelude {
    #[derive(Debug, PartialEq, Eq)]
    pub struct Error(pub i32);
    pub type Result<T = ()> = core::result::Result<T, Error>;
    pub const EINVAL: Error = Error(-22);
}
#[path = "channel.rs"]
pub mod channel;
#[path = "legacy_model.rs"]
pub mod legacy_model;

#[cfg(test)]
mod tests {
    use super::{channel::*, legacy_model::*, prelude::*};

    #[test]
    fn channel_map_boundary_masks_and_empty_map_do_not_escape_range() {
        let mut map = ChannelMap::from_raw([255; 10]);
        assert_eq!(map.used_count(), 79);
        assert!(!map.is_used(79));
        assert_eq!(map.nth_used(78), Some(78));
        assert_eq!(map.nth_used(79), None);
        map.set_used(78, false);
        assert_eq!(map.used_count(), 78);
        map.set_used(255, true);
        assert_eq!(map.used_count(), 78);
        let mut hop = HoppingState::new(78, map);
        for _ in 0..65536 {
            let channel = hop.next_channel();
            assert!(channel < 79 && map.is_used(channel));
        }
        assert_eq!(hop.event_counter, 0);
        hop.update_map(ChannelMap::from_raw([0; 10]));
        assert_eq!(hop.next_channel(), 0);
        assert_eq!(HoppingState::channel_to_freq(78), 2480);
    }

    #[test]
    fn local_parameter_validation_and_roundtrip_are_not_hardware_state() {
        let mut model = PhyConfig::default_config();
        for invalid in [13, 255] {
            assert_eq!(model.set_mcs(invalid), Err(EINVAL));
            assert_eq!(model.mcs_index, 4);
        }
        for invalid in [0, 3, 255] {
            assert_eq!(model.set_bandwidth(invalid), Err(EINVAL));
            assert_eq!(model.bandwidth_mhz, 1);
        }
        for invalid in [-128, -21, 21, 127] {
            assert_eq!(model.set_tx_power(invalid), Err(EINVAL));
            assert_eq!(model.tx_power_dbm, 10);
        }
        let mut short = [0xa5; 6];
        assert_eq!(model.encode_dli_params(&mut short), 0);
        assert_eq!(short, [0xa5; 6]);
        let mut encoded = [0; 7];
        assert_eq!(model.encode_dli_params(&mut encoded), 7);
        let mut restored = PhyConfig::default_config();
        restored.set_mcs(0).unwrap();
        restored.decode_dli_params(&encoded).unwrap();
        assert_eq!(restored.mcs_index, model.mcs_index);
        assert_eq!(restored.effective_data_rate_kbps(), model.effective_data_rate_kbps());
        assert_eq!(restored.to_feature_bits(), model.to_feature_bits());
    }

    #[test]
    fn historical_table_selection_and_antenna_bounds() {
        assert!(mcs_lookup(13).is_none());
        assert!(data_rate_kbps(255, 4).is_none());
        for modulation in [0, 1, 2, 3, 4] {
            assert!(Modulation::from_raw(modulation).unwrap().bits_per_symbol() > 0);
        }
        assert!(Modulation::from_raw(5).is_none());
        let local = AntennaConfig { num_tx: 2, num_rx: 2,
            mode: MimoMode::Siso, calibrated: false };
        assert_eq!(AntennaConfig::negotiate_mode(&local, &local), MimoMode::SpatialMux2x2);
        assert_eq!(MimoMode::SpatialMux2x2.num_streams(), 2);
        assert!(MimoMode::from_raw(5).is_none());
        for sinr in [-1000, 0, 1000] {
            assert!(mcs_select(1, 1, sinr) < 13);
        }
        assert!(MCS_TABLE.iter().all(|m| m.code_rate.efficiency_x1000() <= 1000));
    }
}
