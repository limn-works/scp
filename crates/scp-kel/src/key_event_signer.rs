//! The one signer contract every key-event member signs through: a root
//! member, a K′ member or a next-set member (§9.7.4.2 R10, "A device signs
//! only a legal event at the head it holds").
//!
//! [`KeyEventSigner`] hands a substrate one of three byte strings, each
//! computed here in Rust: a checked change's digest `D` (the raw arm), its
//! `key_event_challenge` (the assertion arm), or a [`CustodyProbe`]'s fixed
//! bytes (§9.7.4.1 item 5, step d). Its one change input is a
//! [`SigningChange`], which only [`HeldHead::check_next`](crate::HeldHead::check_next)
//! and [`SigningChange::inception`] construct, so no signer receives bytes a
//! caller assembled.
//!
//! The contract lives in this crate, which depends on no platform crate, so
//! the ADR-057 in-browser client implements it directly.

use core::future::Future;

use rand_core::RngCore;
use sha2::{Digest, Sha256};

use crate::IndexedSignature;
use crate::constants::CUSTODY_PROBE_SEPARATOR;
use crate::validate::SigningChange;

/// The bytes of a [`CustodyProbe`]'s assertion-arm challenge:
/// `"SCP-CUSTODY-PROBE-V1:"` followed by the 32-byte nonce (§9.7.4.1 item 5,
/// step d).
pub const CUSTODY_PROBE_CHALLENGE_LEN: usize = CUSTODY_PROBE_SEPARATOR.len() + 32;

/// `Send` on every target but `wasm32`, and no bound on `wasm32`.
///
/// A [`KeyEventSigner`]'s futures carry this bound. A native signer's future
/// crosses threads on a multi-threaded runtime, so it must be `Send`. The
/// browser client's signer awaits a wasm-bindgen `JsFuture`, which is not
/// `Send`, and wasm32 runs on one thread.
#[cfg(not(target_arch = "wasm32"))]
pub trait MaybeSend: Send {}
#[cfg(not(target_arch = "wasm32"))]
impl<T: Send + ?Sized> MaybeSend for T {}

/// `Send` on every target but `wasm32`, and no bound on `wasm32`.
///
/// A [`KeyEventSigner`]'s futures carry this bound. A native signer's future
/// crosses threads on a multi-threaded runtime, so it must be `Send`. The
/// browser client's signer awaits a wasm-bindgen `JsFuture`, which is not
/// `Send`, and wasm32 runs on one thread.
#[cfg(target_arch = "wasm32")]
pub trait MaybeSend {}
#[cfg(target_arch = "wasm32")]
impl<T: ?Sized> MaybeSend for T {}

/// A custody that signs as a key-event member (§9.7.4.2 R10).
///
/// `Member` names one key the custody holds. Neither method has a default
/// body, so an implementor that omits one does not compile.
pub trait KeyEventSigner {
    /// The custody's name for one of its key-event keys.
    type Member;

    /// Signs `change` with `member`.
    ///
    /// The raw arm signs the change's digest `D`
    /// ([`SigningChange::digest`]); the assertion arm passes
    /// [`SigningChange::key_event_challenge`] to its authenticator.
    ///
    /// # Errors
    ///
    /// [`KeyEventSignError`] naming why `member` did not sign.
    fn sign_change(
        &self,
        member: &Self::Member,
        change: &SigningChange,
    ) -> impl Future<Output = Result<IndexedSignature, KeyEventSignError>> + MaybeSend;

    /// Signs `probe` with `member`: §9.7.4.1 item 5's reachability
    /// confirmation.
    ///
    /// The raw arm signs [`CustodyProbe::raw_digest`]; the assertion arm
    /// passes [`CustodyProbe::assertion_challenge`] to its authenticator.
    ///
    /// # Errors
    ///
    /// [`KeyEventSignError`] naming why `member` did not sign.
    fn sign_probe(
        &self,
        member: &Self::Member,
        probe: &CustodyProbe,
    ) -> impl Future<Output = Result<IndexedSignature, KeyEventSignError>> + MaybeSend;
}

/// The custody-reachability probe of §9.7.4.1 item 5, step d: one test
/// signature over bytes no key-event signature covers.
///
/// Its separator `"SCP-CUSTODY-PROBE-V1:"` differs from the key-event
/// preimage separator and from the key-event challenge separator, so no
/// probe value equals an event digest or a key-event challenge.
///
/// [`fresh`](Self::fresh) draws the nonce from the operating system's random
/// source and is the constructor a ceremony uses, because step d requires
/// "32 fresh random bytes". [`new`](Self::new) takes the nonce from its
/// caller for known-answer tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CustodyProbe {
    nonce: [u8; 32],
}

impl CustodyProbe {
    /// A probe over 32 bytes drawn from the operating system's random source.
    ///
    /// # Errors
    ///
    /// [`ProbeNonceError`] when the random source fails. The probe is never
    /// built from a fallback nonce.
    pub fn fresh() -> Result<Self, ProbeNonceError> {
        let mut nonce = [0u8; 32];
        rand_core::OsRng
            .try_fill_bytes(&mut nonce)
            .map_err(|error| ProbeNonceError(error.to_string()))?;
        Ok(Self { nonce })
    }

    /// A probe over `nonce`.
    ///
    /// A ceremony calls [`fresh`](Self::fresh): a repeated nonce yields a
    /// digest the key has already signed, and a stored signature over that
    /// digest shows only that the key was reachable once.
    #[must_use]
    pub const fn new(nonce: [u8; 32]) -> Self {
        Self { nonce }
    }

    /// The raw-arm digest: `SHA-256("SCP-CUSTODY-PROBE-V1:" ‖ nonce)`.
    #[must_use]
    pub fn raw_digest(&self) -> [u8; 32] {
        Sha256::new()
            .chain_update(CUSTODY_PROBE_SEPARATOR)
            .chain_update(self.nonce)
            .finalize()
            .into()
    }

    /// The assertion-arm `WebAuthn` challenge: `"SCP-CUSTODY-PROBE-V1:" ‖
    /// nonce`, the same prefix over the same random bytes (§9.7.4.1 item 5,
    /// step d).
    #[must_use]
    pub const fn assertion_challenge(&self) -> [u8; CUSTODY_PROBE_CHALLENGE_LEN] {
        let mut challenge = [0u8; CUSTODY_PROBE_CHALLENGE_LEN];
        let (separator, nonce) = challenge.split_at_mut(CUSTODY_PROBE_SEPARATOR.len());
        separator.copy_from_slice(CUSTODY_PROBE_SEPARATOR);
        nonce.copy_from_slice(&self.nonce);
        challenge
    }
}

/// The operating system's random source failed, so
/// [`CustodyProbe::fresh`] built no probe.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("the operating system's random source failed: {0}")]
pub struct ProbeNonceError(String);

/// Why a [`KeyEventSigner`] did not sign.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum KeyEventSignError {
    /// The member is not a key-event key, so it signs no change and no probe.
    #[error("the member is not a key-event key")]
    WrongKeyType,
    /// The custody holds no member by that name.
    #[error("the custody holds no such member")]
    MemberNotFound,
    /// The custody does not offer key-event signing.
    #[error("unsupported: {0}")]
    Unsupported(&'static str),
    /// The substrate failed: closed or locked storage, a failed decrypt, or a
    /// host error.
    #[error("the custody substrate failed: {0}")]
    Substrate(String),
}

#[cfg(test)]
mod tests {
    use super::{CUSTODY_PROBE_CHALLENGE_LEN, CustodyProbe};

    /// The nonce `00 01 … 1f`.
    const COUNTING_NONCE: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

    fn hex32(text: &str) -> Result<[u8; 32], String> {
        let bytes = hex::decode(text).map_err(|e| e.to_string())?;
        bytes
            .try_into()
            .map_err(|b: Vec<u8>| format!("{} bytes, not 32", b.len()))
    }

    #[test]
    fn custody_probe_raw_digest_kat() -> Result<(), String> {
        assert_eq!(
            CustodyProbe::new(hex32(COUNTING_NONCE)?).raw_digest(),
            hex32("c36069dcc0cd6126d3371115304869d93b17e91dbdbe59d5ca58b8d442f8ffd1")?,
        );
        assert_eq!(
            CustodyProbe::new([0x5a; 32]).raw_digest(),
            hex32("b02faa3696917a54fb2fceff73015251ac8d039c93fd07d42621d6e70b3078a7")?,
        );
        Ok(())
    }

    #[test]
    fn custody_probe_assertion_challenge_kat() -> Result<(), String> {
        let challenge = CustodyProbe::new(hex32(COUNTING_NONCE)?).assertion_challenge();
        assert_eq!(CUSTODY_PROBE_CHALLENGE_LEN, 53);
        let expected = hex::decode(
            "5343502d435553544f44592d50524f42452d56313a\
             000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        )
        .map_err(|e| e.to_string())?;
        assert_eq!(challenge.as_slice(), expected.as_slice());
        Ok(())
    }

    #[test]
    fn fresh_probes_draw_distinct_nonces() -> Result<(), String> {
        let first = CustodyProbe::fresh().map_err(|e| e.to_string())?;
        let second = CustodyProbe::fresh().map_err(|e| e.to_string())?;
        assert_ne!(first, second);
        assert_ne!(first.raw_digest(), CustodyProbe::new([0; 32]).raw_digest());
        Ok(())
    }
}
