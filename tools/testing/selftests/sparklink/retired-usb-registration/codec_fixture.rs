// SPDX-License-Identifier: GPL-2.0-only
// Allocation/errno dependencies only; archive remains separate from live parser.
#[derive(Debug, PartialEq, Eq)]
struct Error(i32);
const EINVAL: Error = Error(-22);
type Result<T> = std::result::Result<T, Error>;
const GFP_KERNEL: u32 = 0;
const GFP_ATOMIC: u32 = 1;
struct KVec<T>(Vec<T>);
impl<T> KVec<T> {
    fn with_capacity(size: usize, _flags: u32) -> Result<Self> { Ok(Self(Vec::with_capacity(size))) }
    fn push(&mut self, value: T, _flags: u32) -> Result<()> { self.0.push(value); Ok(()) }
}
impl<T> std::ops::Deref for KVec<T> {
    type Target = [T];
    fn deref(&self) -> &[T] { &self.0 }
}
#[repr(u8)]
enum DliPacketType { Command = 0xa1, AsyncUnicast = 0xa3 }
#[repr(u16)]
#[derive(Clone, Copy)]
enum SleOpcode { Reset = 0x401 }
mod sle_uapi { // @@PRODUCTION_BUDGET@@
}
mod archived {
    use super::*;
    // @@ARCHIVE@@
}
mod live {
    use super::*;
    // @@EVENT_STRUCT@@
    // @@EVENT_PARSE@@
    #[test]
    fn actual_parser_short_header_rejected() { assert!(matches!(parse_event_packet(&[0, 0, 0]), Err(EINVAL))); }
    #[test]
    fn actual_parser_missing_or_overlimit_payload_rejected() {
        assert!(matches!(parse_event_packet(&[2, 0, 1, 0]), Err(EINVAL)));
        assert!(matches!(parse_event_packet(&[2, 0, 0, 1]), Err(EINVAL)));
    }
    #[test]
    fn actual_parser_exact_empty_and_maximum_payload() {
        let empty = parse_event_packet(&[2, 0, 0, 0]).unwrap();
        assert_eq!(empty.event_code, 2); assert!(empty.params.is_empty());
        let size = sle_uapi::DLI_PARAM_MAX;
        let mut bytes = vec![2, 0, size as u8, (size >> 8) as u8];
        bytes.extend((0..size).map(|i| i as u8));
        let event = parse_event_packet(&bytes).unwrap();
        assert_eq!(event.event_code, 2); assert_eq!(&*event.params, &bytes[4..]);
        let over = size + 1;
        let mut bytes = vec![2,0,over as u8,(over >> 8) as u8];
        bytes.extend(std::iter::repeat_n(0,over));
        assert!(matches!(parse_event_packet(&bytes),Err(EINVAL)));
        for n in [255usize,256] {
            if n <= size { continue; }
            let mut bytes=vec![2,0,n as u8,(n >> 8) as u8];bytes.extend(std::iter::repeat_n(0,n));
            assert!(matches!(parse_event_packet(&bytes),Err(EINVAL)));
        }
    }
    #[test]
    fn actual_parser_trailing_bytes_not_part_of_declared_payload() {
        let event = parse_event_packet(&[2, 0, 1, 0, 0xab, 0xcd]).unwrap();
        assert_eq!(&*event.params, &[0xab]);
    }
}
#[test]
fn historical_command_encoder_truncation_witness_only() {
    let packet = archived::build_command_packet(SleOpcode::Reset, &[0xa5; 256]).unwrap();
    assert_eq!(&packet[..5], &[0xa1, 1, 4, 255, 0]); assert_eq!(packet.len(), 260);
}
#[test]
fn historical_async_encoder_masks_identity_and_truncates_witness_only() {
    let packet = archived::build_async_data_packet(0xfabc, 0xff, true, &[0x5a; 512]).unwrap();
    assert_eq!(&packet[..5], &[0xa3, 0xcd, 0xab, 255, 1]); assert_eq!(packet.len(), 516);
}
#[test]
fn historical_async_parser_reserved_bits_ignored_witness_only() {
    assert!(matches!(archived::parse_async_data_header(&[0, 0, 0]), Err(EINVAL)));
    let header = archived::parse_async_data_header(&[0xcf, 0xab, 0xff, 0xff]).unwrap();
    assert_eq!(header.link_id, 0xabc); assert_eq!(header.seg, 3);
    assert!(header.priority); assert_eq!(header.data_len, 511);
}
