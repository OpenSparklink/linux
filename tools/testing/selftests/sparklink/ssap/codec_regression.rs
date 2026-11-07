// SPDX-License-Identifier: GPL-2.0-only
#[cfg(test)]
mod historical_regression {
    use super::*;
    use crate::fail_at;

    #[test]
    fn old_offset_format_preserved_only_as_historical_codec_evidence() {
        fail_at(0);
        let mut output = [0; SSAP_PDU_MAX];
        let pdu = SsapPdu::ReadReq {
            handle: 0x1234,
            offset: 0x5678,
        };
        assert_eq!(pdu.encode(&mut output).unwrap(), 5);
        assert_eq!(&output[..5], &[8, 0x34, 0x12, 0x78, 0x56]);
        assert!(matches!(
            SsapPdu::decode(&output[..5]).unwrap(),
            SsapPdu::ReadReq {
                handle: 0x1234,
                offset: 0x5678
            }
        ));
        assert!(SsapPdu::decode(&[8, 0]).is_err());
        assert_eq!(pdu.encode(&mut output[..4]), Err(ENOMEM));
    }
}
