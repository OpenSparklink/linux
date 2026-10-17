    // Legacy connection/discovery/DTAP/sync projections are retired.
    // Native Host and Session own the actual physical and data state.
    match ev {
        // -----------------------------------------------------------------
        // Pairing events — drive the security state machine and
        // send response commands back to the controller.
        // -----------------------------------------------------------------
        sle_dli::SleEvent::PairInfoExchange {
            handle,
            io_cap,
            oob_flag,
            auth_req,
            max_key_len,
            sec_dist,
            psk_ind,
            crypto_cap,
        } => {
            if let Ok(reply) = shared.security.on_pair_info_exchange(
                *handle,
                *io_cap,
                *oob_flag,
                *auth_req,
                *max_key_len,
                *sec_dist,
                *psk_ind,
                crypto_cap,
            ) {
                let _ = shared.controller.pair_info_exchange_reply(&reply);
            }
        }
        sle_dli::SleEvent::PairOptionReport {
            handle,
            key_len,
            auth_method,
            crypto_alg,
            public_key,
        } => {
            if let Ok(accept) = shared.security.on_pair_option_report(
                *handle,
                *key_len,
                *auth_method,
                crypto_alg,
                public_key.as_slice(),
            ) {
                let _ = shared.controller.pair_option_accept(&accept);
            }
        }
        sle_dli::SleEvent::PairRandom { handle, random } => {
            if let Ok(resp) = shared.security.on_pair_random(*handle, random) {
                let _ = shared.controller.pair_random(&resp);
            }
        }
        sle_dli::SleEvent::PairConfirm { handle, confirm } => {
            if let Ok(resp) = shared.security.on_pair_confirm(*handle, confirm) {
                let _ = shared.controller.pair_confirm(&resp);
            }
        }
        sle_dli::SleEvent::DHKeyCheck {
            handle,
            dhkey_check,
        } => {
            if let Ok(resp) = shared.security.on_dhkey_verify(*handle, dhkey_check) {
                let _ = shared.controller.dhkey_verify(&resp);
            }
        }
        sle_dli::SleEvent::PairFailure { handle, reason } => {
            shared.security.on_pair_failure(*handle, *reason);
        }
        // -----------------------------------------------------------------

        _ => {}
    }
