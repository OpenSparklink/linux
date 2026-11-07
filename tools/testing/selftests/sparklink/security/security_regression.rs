// SPDX-License-Identifier: GPL-2.0-only
// Appended as child tests of the exact retired sle_security.rs; crypto wrappers remain source-identical.
#[cfg(test)]
mod remediation_tests {
    use super::*;
    use crate::{inject, CALLS};
    use std::sync::atomic::Ordering::SeqCst;
    fn unsupported<T: core::fmt::Debug>(r: Result<T>) {
        assert_eq!(r.unwrap_err(), Error(-95));
    }
    fn empty(s: &SecurityInner) {
        assert_eq!(s.state, SecurityState::Idle);
        assert_eq!(s.method, PairingMethod::Unpaired);
        assert!(
            s.link_key.is_none()
                && s.enc_key.is_none()
                && s.int_key.is_none()
                && s.sm4_ctx.is_none()
        );
        assert_eq!((s.tx_counter, s.rx_counter), (0, 0));
    }
    #[test]
    fn every_pairing_step_rejects_without_crypto_or_success() {
        inject(-12, 0);
        let mut s = SecurityInner::new();
        for method in [
            PairingMethod::JustWorks,
            PairingMethod::Psk,
            PairingMethod::NumericComparison,
            PairingMethod::PasskeyEntry,
            PairingMethod::Oob,
            PairingMethod::Password,
        ] {
            unsupported(s.start_pairing(method));
            empty(&s);
        }
        for handle in [0, 1, 65535] {
            for n in [0, 1, 31, 32, 63, 64, 65, 256] {
                unsupported(s.on_pair_option_report(handle, 16, 0, &[0; 4], &vec![0; n]));
                empty(&s);
            }
            unsupported(s.on_pair_info_exchange(handle, 0, 0, 0, 16, 0, 0, &[0; 4]));
            empty(&s);
            for proof in [[0; 16], [0xff; 16], [0x5a; 16]] {
                unsupported(s.on_pair_random(handle, &proof));
                empty(&s);
                unsupported(s.on_pair_confirm(handle, &proof));
                empty(&s);
                // Unsolicited/late proof cannot install a previously populated key.
                s.state = SecurityState::Encrypted;
                s.link_key = Some([9; 16]);
                unsupported(s.on_dhkey_verify(handle, &proof));
                empty(&s);
            }
        }
        unsupported(s.confirm_passkey());
        unsupported(s.input_passkey(123456));
        empty(&s);
        assert_eq!(CALLS.load(SeqCst), 0);
        unsupported(s.enable_encryption());
    }
    #[test]
    fn legacy_enable_never_claims_hardware_state_or_changes_keys() {
        inject(0, 0);
        for state in [SecurityState::Idle, SecurityState::Pairing,
                      SecurityState::Paired, SecurityState::Encrypted] {
            let mut s = SecurityInner::new();
            s.state = state;
            s.link_key = Some([1; 16]);
            s.enc_key = Some([2; 16]);
            s.int_key = Some([3; 16]);
            s.sm4_ctx = Some(Sm4Key::new(&[2; 16]));
            s.tx_counter = 7;
            s.rx_counter = 9;
            unsupported(s.enable_encryption());
            assert_eq!(s.state, state);
            assert_eq!(s.link_key, Some([1; 16]));
            assert_eq!(s.enc_key, Some([2; 16]));
            assert_eq!(s.int_key, Some([3; 16]));
            assert!(s.sm4_ctx.is_some());
            assert_eq!((s.tx_counter, s.rx_counter), (7, 9));
            assert_eq!(CALLS.load(SeqCst), 0);
        }
    }
    #[test]
    fn crypto_wrappers_preserve_original_errors() {
        for errno in [-12, -22, -2, -5, -110] {
            inject(errno, 0);
            assert_eq!(Sm3::hash(b"x"), Err(Error(errno)));
            assert_eq!(sle_crypto::hmac_sm3(b"k", b"x"), Err(Error(errno)));
            let key = Sm4Key::new(&[0; 16]);
            assert_eq!(key.encrypt_block(&[0; 16]), Err(Error(errno)));
            assert_eq!(key.decrypt_block(&[0; 16]), Err(Error(errno)));
            assert_eq!(
                sle_crypto::EcdhKeyPair::generate().err(),
                Some(Error(errno))
            );
            assert_eq!(
                sle_crypto::ecdh_shared_secret(&[0; 32], &[0; 64]),
                Err(Error(errno))
            );
            assert_eq!(sle_crypto::derive_keys(&[0; 16]), Err(Error(errno)));
        }
    }
    #[test]
    fn failed_second_kdf_does_not_commit_keys() {
        let mut s = SecurityInner::new();
        s.link_key = Some([1; 16]);
        inject(-12, 2);
        assert_eq!(s.derive_session_keys(), Err(Error(-12)));
        assert!(s.enc_key.is_none() && s.int_key.is_none() && s.sm4_ctx.is_none());
        assert_eq!(s.state, SecurityState::Idle);
        assert_eq!(CALLS.load(SeqCst), 2);
    }
    #[test]
    fn ctr_error_and_counter_overflow_do_not_commit() {
        let mut s = SecurityInner::new();
        s.state = SecurityState::Encrypted;
        s.sm4_ctx = Some(Sm4Key::new(&[1; 16]));
        s.tx_counter = 7;
        s.rx_counter = 9;
        let mut data = [0x33; 17];
        inject(-5, 0);
        assert_eq!(s.encrypt(&mut data), Err(Error(-5)));
        assert_eq!(s.tx_counter, 7);
        assert_eq!(s.decrypt(&mut data), Err(Error(-5)));
        assert_eq!(s.rx_counter, 9);
        assert_eq!(data, [0x33; 17]);
        s.tx_counter = u32::MAX;
        s.rx_counter = u32::MAX;
        inject(0, 0);
        assert_eq!(s.encrypt(&mut data), Err(EOVERFLOW));
        assert_eq!(s.decrypt(&mut data), Err(EOVERFLOW));
        assert_eq!(CALLS.load(SeqCst), 0);
        assert_eq!(data, [0x33; 17]);
        s.tx_counter = 7;
        s.rx_counter = 9;
        assert_eq!(s.encrypt(&mut data), Ok(7));
        assert_eq!(s.tx_counter, 9);
        assert_eq!(s.decrypt(&mut data), Ok(()));
        assert_eq!(s.rx_counter, 11);
    }
    #[test]
    fn hashes_and_password_length_fail_without_replacing_state() {
        let mut s = SecurityInner::new();
        s.oob_hash = Some([3; 32]);
        s.pwd_hash = Some([4; 32]);
        inject(-12, 0);
        assert_eq!(s.set_oob_data(b"bad"), Err(Error(-12)));
        assert_eq!(s.oob_hash, Some([3; 32]));
        assert_eq!(s.set_password(b"bad", 3), Err(Error(-12)));
        assert_eq!(s.pwd_hash, Some([4; 32]));
        inject(0, 0);
        assert_eq!(s.set_password(b"x", 32), Err(EINVAL));
        assert_eq!(CALLS.load(SeqCst), 0);
    }
    #[test]
    fn rpa_crypto_failure_preserves_address_and_counter() {
        let mut r = RpaManager::new();
        let mut e = RalEntry::zeroed();
        e.local_irk = [1; 16];
        r.ral_add(e).unwrap();
        r.set_enabled(true);
        r.set_timeout(1);
        r.local_rpa = [9; 6];
        r.refresh_counter = 12;
        for call in [1, 2] {
            inject(-12, call);
            assert_eq!(r.rpa_tick(1), Err(Error(-12)));
            assert_eq!(r.local_rpa, [9; 6]);
            assert_eq!(r.refresh_counter, 12);
        }
        inject(0, 0);
        assert_eq!(r.rpa_tick(0), Ok(true));
        assert_eq!(r.refresh_counter, 13);
    }
}
