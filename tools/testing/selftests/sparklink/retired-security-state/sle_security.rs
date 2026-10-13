// SPDX-License-Identifier: GPL-2.0

//! SLE security state machine.
//!
//! Legacy security controls. Pairing is unavailable until a validated
//! per-connection authentication/relay implementation is installed. Never
//! derive production keys from test nonces or accept an unverified peer.

#![allow(dead_code, unreachable_pub)]

use crate::sle_crypto::{self, Sm3, Sm4Key};
use kernel::prelude::*;

// ---------------------------------------------------------------------------
// Security levels (T/XS 10002-2025 section 9)
// ---------------------------------------------------------------------------

/// Security mode for an SLE connection.
#[repr(u8)]
#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
pub enum SecurityMode {
    /// Encryption enabled, integrity enabled.
    #[default]
    EncAndInt = 0,
    /// Encryption disabled, integrity enabled.
    IntOnly = 1,
    /// Encryption enabled, integrity disabled.
    EncOnly = 2,
    /// No security (plaintext).
    None = 3,
}

// ---------------------------------------------------------------------------
// Pairing methods
// ---------------------------------------------------------------------------

/// Pairing method used to establish the link key.
#[repr(u8)]
#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
pub enum PairingMethod {
    /// No pairing performed yet.
    #[default]
    Unpaired = 0,
    /// Just Works: automatic key generation, no MITM protection.
    JustWorks = 1,
    /// Pre-shared key: both sides hold the same 128-bit secret.
    Psk = 2,
    /// Numeric comparison: 6-digit passkey displayed on both sides,
    /// user confirms match (MITM protected, §8.6.10 auth_method=0x00).
    NumericComparison = 3,
    /// Passkey entry: 6-digit passkey displayed on one device,
    /// user inputs on the other (§8.6.10 auth_method=0x02).
    PasskeyEntry = 4,
    /// Out-of-band: key material pre-exchanged via NFC/QR etc.
    /// (§8.6.10 auth_method=0x04, §8.6.12 配对扩展数据).
    Oob = 5,
    /// Password verification: variable-length password used as
    /// authentication material (§8.6.10 auth_method=0x03).
    Password = 6,
}

// ---------------------------------------------------------------------------
// Security state machine
// ---------------------------------------------------------------------------

/// Security state of the connection.
#[repr(u8)]
#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
pub enum SecurityState {
    /// No pairing attempted.
    #[default]
    Idle = 0,
    /// Pairing is in progress.
    Pairing = 1,
    /// Pairing complete, keys derived.
    Paired = 2,
    /// Encryption active on data path.
    Encrypted = 3,
    /// Awaiting user confirmation of numeric passkey.
    AwaitingConfirm = 4,
    /// Awaiting user passkey input (passkey entry mode).
    AwaitingPasskey = 5,
}

// ---------------------------------------------------------------------------
// Security context
// ---------------------------------------------------------------------------

/// Legacy controller-local security context, pending per-connection replacement.
/// Pairing entry points reject unsupported authentication and clear session state.
pub struct SecurityInner {
    /// Current security state.
    pub state: SecurityState,
    /// Pairing method.
    pub method: PairingMethod,
    /// Security mode (encryption + integrity configuration).
    pub mode: SecurityMode,
    /// Pre-shared key (if provided).
    psk: Option<[u8; 16]>,
    /// Link key derived from pairing (128-bit).
    link_key: Option<[u8; 16]>,
    /// Encryption key for SM4 (128-bit, derived from link key).
    enc_key: Option<[u8; 16]>,
    /// Integrity key for HMAC-SM3 (128-bit, derived from link key).
    int_key: Option<[u8; 16]>,
    /// SM4 key context for encryption (lazily initialized).
    sm4_ctx: Option<Sm4Key>,
    /// CTR nonce (12 bytes, fixed per connection).
    ctr_nonce: [u8; 12],
    /// TX packet counter for CTR mode.
    tx_counter: u32,
    /// RX packet counter for CTR mode.
    rx_counter: u32,
    /// 6-digit passkey for numeric comparison (0..999999).
    passkey: Option<u32>,
    /// OOB hash: SM3 digest of remote OOB key material.
    oob_hash: Option<[u8; 32]>,
    /// Password hash: SM3 digest of the password.
    pwd_hash: Option<[u8; 32]>,
}

impl SecurityInner {
    /// Create a new idle security context.
    pub fn new() -> Self {
        Self {
            state: SecurityState::Idle,
            method: PairingMethod::Unpaired,
            mode: SecurityMode::EncAndInt,
            psk: None,
            link_key: None,
            enc_key: None,
            int_key: None,
            sm4_ctx: None,
            ctr_nonce: [0u8; 12],
            tx_counter: 0,
            rx_counter: 0,
            passkey: None,
            oob_hash: None,
            pwd_hash: None,
        }
    }

    /// Set the pre-shared key for PSK pairing.
    pub fn set_psk(&mut self, psk: [u8; 16]) {
        self.psk = Some(psk);
        pr_info!("sparklink: PSK configured\n");
    }

    // -----------------------------------------------------------------
    // Legacy pairing is fail-closed pending the per-connection mechanism.
    // Keeping these entry points temporarily lets callers propagate unsupported
    // before submitting any DLI request. They cannot emit authentication replies.
    // -----------------------------------------------------------------

    /// Reject pairing until peer authentication is implemented and verified.
    pub fn start_pairing(&mut self, _method: PairingMethod) -> Result {
        self.reset();
        Err(Error::from_errno(-(kernel::bindings::EOPNOTSUPP as i32)))
    }

    /// Reject an unverified legacy pairing step and discard session state.
    pub fn on_pair_info_exchange(
        &mut self,
        _handle: u16,
        _io_cap: u8,
        _oob_flag: u8,
        _auth_req: u8,
        _max_key_len: u8,
        _sec_dist: u8,
        _psk_ind: u8,
        _crypto_cap: &[u8; 4],
    ) -> Result<[u8; 12]> {
        self.reset();
        Err(Error::from_errno(-(kernel::bindings::EOPNOTSUPP as i32)))
    }

    /// Reject an unverified legacy pairing step and discard session state.
    pub fn on_pair_option_report(
        &mut self,
        _handle: u16,
        _key_len: u8,
        _auth_method: u8,
        _crypto_alg: &[u8; 4],
        _public_key: &[u8],
    ) -> Result<[u8; 34]> {
        self.reset();
        Err(Error::from_errno(-(kernel::bindings::EOPNOTSUPP as i32)))
    }

    /// Reject an unverified legacy pairing step and discard session state.
    pub fn on_pair_random(&mut self, _handle: u16, _random: &[u8; 16]) -> Result<[u8; 18]> {
        self.reset();
        Err(Error::from_errno(-(kernel::bindings::EOPNOTSUPP as i32)))
    }

    /// Reject an unverified legacy pairing step and discard session state.
    pub fn on_pair_confirm(&mut self, _handle: u16, _confirm: &[u8; 16]) -> Result<[u8; 18]> {
        self.reset();
        Err(Error::from_errno(-(kernel::bindings::EOPNOTSUPP as i32)))
    }

    /// Reject an unverified legacy pairing step and discard session state.
    pub fn on_dhkey_verify(&mut self, _handle: u16, _dhkey_check: &[u8; 16]) -> Result<[u8; 18]> {
        self.reset();
        Err(Error::from_errno(-(kernel::bindings::EOPNOTSUPP as i32)))
    }

    /// Handle PairFailure event (0x0027) from controller.
    pub fn on_pair_failure(&mut self, _handle: u16, reason: u8) {
        pr_info!("sparklink: pairing failed (reason=0x{:02x})\n", reason);
        self.reset();
    }

    // -----------------------------------------------------------------
    // Existing callers receive unsupported; no local/test key generation.
    // -----------------------------------------------------------------

    /// Initiate Just Works pairing via DLI command.
    pub fn pair_just_works(&mut self) -> Result {
        self.start_pairing(PairingMethod::JustWorks)
    }

    /// Initiate PSK pairing via DLI command.
    pub fn pair_psk(&mut self) -> Result {
        if self.psk.is_none() {
            return Err(EINVAL);
        }
        self.start_pairing(PairingMethod::Psk)
    }

    /// Initiate numeric comparison pairing via DLI command.
    pub fn pair_numeric_comparison(&mut self) -> Result {
        self.start_pairing(PairingMethod::NumericComparison)
    }

    /// Get the 6-digit passkey for numeric comparison.
    ///
    /// Only valid in AwaitingConfirm or AwaitingPasskey state.
    pub fn get_passkey(&self) -> Result<u32> {
        if self.state != SecurityState::AwaitingConfirm
            && self.state != SecurityState::AwaitingPasskey
        {
            return Err(EINVAL);
        }
        self.passkey.ok_or(EINVAL)
    }

    /// Reject an unverified legacy pairing step and discard session state.
    pub fn confirm_passkey(&mut self) -> Result {
        self.reset();
        Err(Error::from_errno(-(kernel::bindings::EOPNOTSUPP as i32)))
    }

    /// User rejected the passkey (mismatch).
    ///
    /// Returns to Idle state, discards all ephemeral material.
    pub fn reject_passkey(&mut self) {
        self.passkey = None;
        self.link_key = None;
        self.state = SecurityState::Idle;
        self.method = PairingMethod::Unpaired;
        pr_info!("sparklink: numeric comparison rejected by user\n");
    }

    // -----------------------------------------------------------------
    // Passkey entry (§8.6.10 auth_method=0x02, §8.6.13)
    // -----------------------------------------------------------------

    /// Initiate passkey entry pairing via DLI command.
    pub fn pair_passkey_entry(&mut self) -> Result {
        self.start_pairing(PairingMethod::PasskeyEntry)
    }

    /// Reject an unverified legacy pairing step and discard session state.
    pub fn input_passkey(&mut self, _value: u32) -> Result {
        self.reset();
        Err(Error::from_errno(-(kernel::bindings::EOPNOTSUPP as i32)))
    }

    // -----------------------------------------------------------------
    // OOB pairing (§8.6.10 auth_method=0x04, §8.6.12)
    // -----------------------------------------------------------------

    /// Set OOB data (remote public key X[32] + Y[32]).
    ///
    /// Immediately hashes the data via SM3 and stores only the digest
    /// to minimize memory footprint.
    pub fn set_oob_data(&mut self, data: &[u8]) -> Result {
        self.oob_hash = Some(Sm3::hash(data)?);
        pr_info!(
            "sparklink: OOB data configured ({} bytes, hashed)\n",
            data.len()
        );
        Ok(())
    }

    /// Initiate OOB pairing via DLI command.
    pub fn pair_oob(&mut self) -> Result {
        if self.oob_hash.is_none() {
            return Err(EINVAL);
        }
        self.start_pairing(PairingMethod::Oob)
    }

    // -----------------------------------------------------------------
    // Password pairing (§8.6.10 auth_method=0x03, §8.6.28)
    // -----------------------------------------------------------------

    /// Set the password for password-based pairing.
    ///
    /// Password length must be 1..32 bytes. The password is immediately
    /// hashed via SM3 and only the digest is retained.
    pub fn set_password(&mut self, pwd: &[u8], len: u8) -> Result {
        let l = len as usize;
        if l == 0 || l > 32 || l > pwd.len() {
            return Err(EINVAL);
        }
        self.pwd_hash = Some(Sm3::hash(&pwd[..l])?);
        pr_info!("sparklink: password configured ({} bytes, hashed)\n", len);
        Ok(())
    }

    /// Initiate password-based pairing via DLI command.
    pub fn pair_password(&mut self) -> Result {
        if self.pwd_hash.is_none() {
            return Err(EINVAL);
        }
        self.start_pairing(PairingMethod::Password)
    }

    /// Derive encryption and integrity keys from the link key.
    fn derive_session_keys(&mut self) -> Result {
        let lk = self.link_key.ok_or(EINVAL)?;
        let (ek, ik) = sle_crypto::derive_keys(&lk)?;
        self.enc_key = Some(ek);
        self.int_key = Some(ik);

        // Initialize SM4 context and nonce
        self.sm4_ctx = Some(Sm4Key::new(&ek));
        // Derive CTR nonce from integrity key (first 12 bytes)
        self.ctr_nonce.copy_from_slice(&ik[..12]);
        self.tx_counter = 0;
        self.rx_counter = 0;

        pr_info!("sparklink: session keys derived\n");
        Ok(())
    }

    /// Legacy adapter-global enable cannot establish a per-connection key,
    /// installation transaction, or matching hardware completion. Reject it
    /// without modifying credentials, counters or the reported security state.
    pub fn enable_encryption(&mut self) -> Result {
        Err(Error::from_errno(-(kernel::bindings::EOPNOTSUPP as i32)))
    }

    /// Check if encryption is active.
    pub fn is_encrypted(&self) -> bool {
        self.state == SecurityState::Encrypted
    }

    /// Encrypt data in-place using SM4-CTR.
    ///
    /// Returns the TX counter used (for the receiver to use the same).
    pub fn encrypt(&mut self, data: &mut [u8]) -> Result<u32> {
        if !self.is_encrypted() {
            return Err(EPERM);
        }
        let ctx = self.sm4_ctx.as_ref().ok_or(EINVAL)?;
        let ctr = self.tx_counter;
        let blocks = u32::try_from(data.len().div_ceil(16)).map_err(|_| EOVERFLOW)?;
        let next = self.tx_counter.checked_add(blocks).ok_or(EOVERFLOW)?;
        sle_crypto::sm4_ctr(ctx, &self.ctr_nonce, ctr, data)?;
        self.tx_counter = next;
        Ok(ctr)
    }

    /// Decrypt data in-place using SM4-CTR.
    pub fn decrypt(&mut self, data: &mut [u8]) -> Result {
        if !self.is_encrypted() {
            return Err(EPERM);
        }
        let ctx = self.sm4_ctx.as_ref().ok_or(EINVAL)?;
        let ctr = self.rx_counter;
        let blocks = u32::try_from(data.len().div_ceil(16)).map_err(|_| EOVERFLOW)?;
        let next = self.rx_counter.checked_add(blocks).ok_or(EOVERFLOW)?;
        sle_crypto::sm4_ctr(ctx, &self.ctr_nonce, ctr, data)?;
        self.rx_counter = next;
        Ok(())
    }

    /// Get the first 4 bytes of SM3(enc_key) for verification.
    pub fn enc_key_fingerprint(&self) -> Result<[u8; 4]> {
        match &self.enc_key {
            Some(ek) => {
                let h = Sm3::hash(ek)?;
                Ok([h[0], h[1], h[2], h[3]])
            }
            None => Ok([0u8; 4]),
        }
    }

    /// Reset security state (e.g. on disconnect).
    pub fn reset(&mut self) {
        self.state = SecurityState::Idle;
        self.method = PairingMethod::Unpaired;
        self.link_key = None;
        self.enc_key = None;
        self.int_key = None;
        self.sm4_ctx = None;
        self.ctr_nonce = [0u8; 12];
        self.tx_counter = 0;
        self.rx_counter = 0;
        self.passkey = None;
        self.oob_hash = None;
        self.pwd_hash = None;
    }
}

// ---------------------------------------------------------------------------
// RAL — Resolving Address List (T/XS 10003-2025 §8.6.18-8.6.25)
// ---------------------------------------------------------------------------

/// Maximum number of entries in the RAL.
const RAL_MAX_ENTRIES: usize = 8;

/// A single entry in the Resolving Address List.
///
/// Each entry maps a peer identity to IRK pairs used for RPA
/// generation and resolution.
#[derive(Copy, Clone)]
pub struct RalEntry {
    /// Peer identity address type (0x00=alliance, 0x02=local, 0x06=private).
    pub peer_id_type: u8,
    /// Resolution algorithm bits: bit0=local algo, bit1=peer algo
    /// (0=AES-CMAC, 1=HMAC-SM3).
    pub resolve_algo: u8,
    /// Peer IRKID.
    pub peer_irkid: u8,
    /// Local IRKID.
    pub local_irkid: u8,
    /// Peer identity address (6 bytes).
    pub peer_id: [u8; 6],
    /// Peer Identity Resolving Key (16 bytes).
    pub peer_irk: [u8; 16],
    /// Local Identity Resolving Key (16 bytes).
    pub local_irk: [u8; 16],
}

impl RalEntry {
    const fn zeroed() -> Self {
        Self {
            peer_id_type: 0,
            resolve_algo: 0,
            peer_irkid: 0,
            local_irkid: 0,
            peer_id: [0u8; 6],
            peer_irk: [0u8; 16],
            local_irk: [0u8; 16],
        }
    }
}

/// RPA manager: manages the RAL and RPA generation/resolution.
pub struct RpaManager {
    /// RAL entries (first `count` are valid).
    entries: [RalEntry; RAL_MAX_ENTRIES],
    /// Number of valid entries.
    count: u8,
    /// Whether RPA resolution is enabled.
    enabled: bool,
    /// RPA timeout in seconds (0 = no auto-refresh).
    timeout_secs: u16,
    /// Monotonic counter for RPA refresh entropy.
    refresh_counter: u32,
    /// Elapsed seconds since last RPA refresh.
    elapsed_secs: u16,
    /// Cached local RPA (regenerated on timeout).
    local_rpa: [u8; 6],
}

impl RpaManager {
    /// Create a new empty RPA manager.
    pub fn new() -> Self {
        Self {
            entries: [RalEntry::zeroed(); RAL_MAX_ENTRIES],
            count: 0,
            enabled: false,
            timeout_secs: 0,
            refresh_counter: 0,
            elapsed_secs: 0,
            local_rpa: [0u8; 6],
        }
    }

    /// Add a device to the RAL.
    ///
    /// RPA resolution must be disabled before calling this.
    pub fn ral_add(&mut self, entry: RalEntry) -> Result {
        if self.enabled {
            return Err(EBUSY);
        }
        if (self.count as usize) >= RAL_MAX_ENTRIES {
            return Err(ENOMEM);
        }
        // Check for duplicate peer identity
        for i in 0..(self.count as usize) {
            if self.entries[i].peer_id_type == entry.peer_id_type
                && self.entries[i].peer_id == entry.peer_id
            {
                return Err(EEXIST);
            }
        }
        self.entries[self.count as usize] = entry;
        self.count += 1;
        pr_info!("sparklink: RAL entry added (count={})\n", self.count);
        Ok(())
    }

    /// Remove a device from the RAL by peer identity.
    ///
    /// RPA resolution must be disabled before calling this.
    pub fn ral_remove(&mut self, peer_id_type: u8, peer_id: &[u8; 6]) -> Result {
        if self.enabled {
            return Err(EBUSY);
        }
        for i in 0..(self.count as usize) {
            if self.entries[i].peer_id_type == peer_id_type && self.entries[i].peer_id == *peer_id {
                // Swap-remove: replace with last entry
                let last = (self.count - 1) as usize;
                if i != last {
                    self.entries[i] = self.entries[last];
                }
                self.entries[last] = RalEntry::zeroed();
                self.count -= 1;
                pr_info!("sparklink: RAL entry removed (count={})\n", self.count);
                return Ok(());
            }
        }
        Err(ENOENT)
    }

    /// Clear all RAL entries.
    ///
    /// RPA resolution must be disabled before calling this.
    pub fn ral_clear(&mut self) -> Result {
        if self.enabled {
            return Err(EBUSY);
        }
        self.entries = [RalEntry::zeroed(); RAL_MAX_ENTRIES];
        self.count = 0;
        pr_info!("sparklink: RAL cleared\n");
        Ok(())
    }

    /// Return the current number of RAL entries.
    pub fn ral_size(&self) -> u8 {
        self.count
    }

    /// Generate an RPA from an IRK using HMAC-SM3.
    ///
    /// RPA format: hash[0..3] || prand[0..3]
    /// prand[0] top 2 bits forced to 0b01 (resolvable marker).
    /// The `counter` parameter provides entropy so that successive
    /// calls with the same IRK produce different addresses.
    fn generate_rpa_with_counter(irk: &[u8; 16], counter: u32) -> Result<[u8; 6]> {
        let cb = counter.to_le_bytes();
        let mut seed = [0u8; 20];
        seed[..16].copy_from_slice(irk);
        seed[16..20].copy_from_slice(&cb);
        let pk = Sm3::hash(&seed)?;
        let mut prand = [pk[0], pk[1], pk[2]];
        // Force top 2 bits to 01 (resolvable private address)
        prand[0] = (prand[0] & 0x3F) | 0x40;

        // hash = HMAC-SM3(IRK, prand) truncated to 3 bytes
        let h = sle_crypto::hmac_sm3(irk, &prand)?;
        Ok([h[0], h[1], h[2], prand[0], prand[1], prand[2]])
    }

    /// Compatibility wrapper using counter=0 for deterministic tests.
    fn generate_rpa(irk: &[u8; 16]) -> Result<[u8; 6]> {
        Self::generate_rpa_with_counter(irk, 0)
    }

    /// Look up a peer and return its RPA (generated from peer IRK).
    pub fn read_peer_rpa(&self, peer_id_type: u8, peer_id: &[u8; 6]) -> Result<[u8; 6]> {
        for i in 0..(self.count as usize) {
            if self.entries[i].peer_id_type == peer_id_type && self.entries[i].peer_id == *peer_id {
                return Self::generate_rpa(&self.entries[i].peer_irk);
            }
        }
        Err(ENOENT)
    }

    /// Look up by local identity info and return local RPA.
    pub fn read_local_rpa(&self, local_id_type: u8, local_id: &[u8; 6]) -> Result<[u8; 6]> {
        // In the standard, local RPA is per-device. We look for the
        // first entry whose peer_id matches; in practice the local_irk
        // is the same across entries. For testing, we return the RPA
        // from the first matching or first entry.
        for i in 0..(self.count as usize) {
            if self.entries[i].peer_id_type == local_id_type && self.entries[i].peer_id == *local_id
            {
                return Self::generate_rpa(&self.entries[i].local_irk);
            }
        }
        // Fallback: use first entry's local_irk if any
        if self.count > 0 {
            return Self::generate_rpa(&self.entries[0].local_irk);
        }
        Err(ENOENT)
    }

    /// Enable or disable RPA resolution.
    pub fn set_enabled(&mut self, enable: bool) {
        self.enabled = enable;
        pr_info!(
            "sparklink: RPA resolution {}\n",
            if enable { "enabled" } else { "disabled" }
        );
    }

    /// Check if RPA resolution is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Set the RPA timeout in seconds.
    pub fn set_timeout(&mut self, secs: u16) {
        self.timeout_secs = secs;
        pr_info!("sparklink: RPA timeout set to {} seconds\n", secs);
    }

    /// Get the current RPA timeout.
    pub fn timeout(&self) -> u16 {
        self.timeout_secs
    }

    /// Get the cached local RPA (valid only when enabled and RAL non-empty).
    pub fn cached_local_rpa(&self) -> [u8; 6] {
        self.local_rpa
    }

    /// Advance the RPA timer by `delta_secs` seconds.
    ///
    /// When the elapsed time exceeds `timeout_secs`, the local RPA is
    /// regenerated from the first RAL entry's local IRK with a fresh
    /// counter value.  Returns `true` if the RPA was refreshed.
    pub fn rpa_tick(&mut self, delta_secs: u16) -> Result<bool> {
        if !self.enabled || self.timeout_secs == 0 || self.count == 0 {
            return Ok(false);
        }
        self.elapsed_secs = self.elapsed_secs.saturating_add(delta_secs);
        if self.elapsed_secs < self.timeout_secs {
            return Ok(false);
        }
        let next = self.refresh_counter.checked_add(1).ok_or(EOVERFLOW)?;
        let address = Self::generate_rpa_with_counter(&self.entries[0].local_irk, next)?;
        self.elapsed_secs = 0;
        self.refresh_counter = next;
        self.local_rpa = address;
        pr_info!(
            "sparklink: RPA refreshed (counter={})\n",
            self.refresh_counter
        );
        Ok(true)
    }
}
