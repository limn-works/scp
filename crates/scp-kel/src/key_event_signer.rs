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
use scp_crypto::p256::{P256PublicKey, verify_prehash_strict};
use sha2::{Digest, Sha256};

use crate::constants::{CUSTODY_PROBE_SEPARATOR, RAW_SIGNATURE_BYTES};
use crate::event::SignatureForm;
use crate::signature::verify_assertion;
use crate::validate::SigningChange;
use crate::{AssertionSignature, IndexedSignature, IndexedSignatureError};

/// [`RAW_SIGNATURE_BYTES`] as an array length; 64 fits every `usize`.
const RAW_LEN: usize = RAW_SIGNATURE_BYTES as usize;

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
    ) -> impl Future<Output = Result<ProbeSignature, KeyEventSignError>> + MaybeSend;
}

/// The custody-reachability probe of §9.7.4.1 item 5, step d: one test
/// signature over bytes no key-event signature covers.
///
/// Its separator `"SCP-CUSTODY-PROBE-V1:"` differs from the key-event
/// preimage separator and from the key-event challenge separator, so no
/// probe value equals an event digest or a key-event challenge.
///
/// [`fresh`](Self::fresh) draws the nonce from the operating system's random
/// source and is the only constructor production code can reach, because
/// step d requires "32 fresh random bytes". `new`, which takes the nonce from
/// its caller for known-answer tests, compiles only under `cfg(test)` or the
/// `testing` feature. A probe is neither `Clone` nor `Copy`, so each probe a
/// ceremony signs comes from its own `fresh` call.
///
/// ```compile_fail,E0599
/// // Without the `testing` feature no caller picks the nonce.
/// let probe = scp_kel::CustodyProbe::new([0; 32]);
/// ```
///
/// ```compile_fail,E0599
/// // A probe cannot be duplicated and signed twice.
/// let probe = scp_kel::CustodyProbe::fresh()?;
/// let again = probe.clone();
/// # Ok::<(), scp_kel::ProbeNonceError>(())
/// ```
#[derive(Debug, PartialEq, Eq)]
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

    /// A probe over `nonce`, for known-answer tests (spec 25 §25.34).
    ///
    /// A ceremony calls [`fresh`](Self::fresh): a repeated nonce yields a
    /// digest the key has already signed, and a stored signature over that
    /// digest shows only that the key was reachable once.
    #[cfg(any(test, feature = "testing"))]
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

/// A signature over a [`CustodyProbe`], in one of the two forms §9.7.4.2
/// field 7 names.
///
/// It is a type of its own, with no conversion to or from
/// [`IndexedSignature`], so a probe signature cannot be placed in a key
/// event's signature field. [`verify`](Self::verify) is its only check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeSignature(ProbeSignatureForm);

#[derive(Debug, Clone, PartialEq, Eq)]
enum ProbeSignatureForm {
    Raw([u8; RAW_LEN]),
    Assertion(AssertionSignature),
}

impl ProbeSignature {
    /// A raw-form probe signature: a 64-byte low-`s` ECDSA P-256 signature
    /// over [`CustodyProbe::raw_digest`].
    #[must_use]
    pub const fn raw(signature: [u8; RAW_LEN]) -> Self {
        Self(ProbeSignatureForm::Raw(signature))
    }

    /// An assertion-form probe signature: a `WebAuthn` assertion whose
    /// challenge is [`CustodyProbe::assertion_challenge`].
    #[must_use]
    pub const fn assertion(assertion: AssertionSignature) -> Self {
        Self(ProbeSignatureForm::Assertion(assertion))
    }

    /// The form this signature takes.
    #[must_use]
    pub const fn form(&self) -> SignatureForm {
        match self.0 {
            ProbeSignatureForm::Raw(_) => SignatureForm::Raw,
            ProbeSignatureForm::Assertion(_) => SignatureForm::WebAuthnAssertion,
        }
    }

    /// Checks this signature against `probe` and the 33-byte SEC1 point
    /// `key` (§9.7.4.1 item 5, step d: "verified against the public key the
    /// commitment covers").
    ///
    /// The raw form is checked with §9.5's strict verifier over
    /// [`CustodyProbe::raw_digest`]. The assertion form runs every check
    /// [`verify_indexed`](crate::verify_indexed) runs on a key-event
    /// assertion, with [`CustodyProbe::assertion_challenge`] in place of
    /// `"SCP-KEY-EVENT-V1:" ‖ D`. Both values are recomputed from `probe`, so
    /// a signature over an event digest or a key-event challenge fails.
    ///
    /// # Errors
    ///
    /// The [`IndexedSignatureError`] naming the first check that fails.
    pub fn verify(
        &self,
        probe: &CustodyProbe,
        key: &[u8; 33],
    ) -> Result<(), IndexedSignatureError> {
        let key = P256PublicKey::from_sec1(key).map_err(IndexedSignatureError::InvalidKey)?;
        match &self.0 {
            ProbeSignatureForm::Raw(signature) => {
                verify_prehash_strict(&key, &probe.raw_digest(), signature)
                    .map_err(IndexedSignatureError::Signature)
            }
            ProbeSignatureForm::Assertion(assertion) => {
                verify_assertion(&key, &probe.assertion_challenge(), assertion)
            }
        }
    }
}

/// Why a [`KeyEventSigner`] did not sign.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
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
    #[error("the custody substrate failed ({code}): {message}")]
    Substrate {
        /// The SCP error code of the substrate's failure, such as
        /// `SCP-STORAGE-8000`.
        code: &'static str,
        /// The substrate's description of the failure.
        message: String,
    },
}

#[cfg(test)]
mod tests {
    //! Known-answer tests against spec 25 §25.34 Vector 83
    //! (`.docs/specs/25-test-vectors.md`).

    use scp_crypto::p256::{P256SecretKey, SeedLabel, sign_prehash_rfc6979};
    use sha2::{Digest, Sha256};

    use super::{CUSTODY_PROBE_CHALLENGE_LEN, CustodyProbe, KeyEventSignError, ProbeSignature};
    use crate::signature::{base64url_unpadded, key_event_challenge};
    use crate::{AssertionSignature, IndexedSignatureError};

    /// Vector 83a's nonce, `00 01 … 1f`.
    const COUNTING_NONCE: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    /// §25.2's reference seed.
    const REFERENCE_SEED: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
    /// Vector 83a's raw signature by the reference key.
    const V83A_SIGNATURE: &str = "6f4a8e41a55455a45ea941e003199263aeb225e799c5453d56870e2561c94ec6\
                                  082078272e8a524df06c647899a9fe4ad4cf7e809a501fe38fd9e6e6a90629ac";
    /// Vector 41's event digest `D`.
    const V41_DIGEST: &str = "d8ba4ebad52657208736f4cac675352f5f9cc0aa837620f8d742dbf42aeedbd7";

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn hex32(text: &str) -> Result<[u8; 32], String> {
        let bytes = hex::decode(text).map_err(|e| e.to_string())?;
        bytes
            .try_into()
            .map_err(|b: Vec<u8>| format!("{} bytes, not 32", b.len()))
    }

    fn reference() -> Result<P256SecretKey, String> {
        Ok(P256SecretKey::from_seed(
            SeedLabel::TestVectorKey,
            &hex32(REFERENCE_SEED)?,
        ))
    }

    /// An assertion with user presence and verification set, over
    /// `challenge`, signed by the reference key.
    fn assertion_over(challenge: &[u8]) -> Result<AssertionSignature, Box<dyn std::error::Error>> {
        let mut authenticator = vec![0u8; 37];
        if let Some(flags) = authenticator.get_mut(32) {
            *flags = 0x05;
        }
        let client_data_json = format!(
            r#"{{"type":"webauthn.get","challenge":"{}","origin":"https://ctx.network","crossOrigin":false}}"#,
            base64url_unpadded(challenge)
        )
        .into_bytes();
        let message: [u8; 32] = Sha256::new()
            .chain_update(&authenticator)
            .chain_update(Sha256::digest(&client_data_json))
            .finalize()
            .into();
        let signature = sign_prehash_rfc6979(&reference()?, &message)?;
        Ok(AssertionSignature::new(
            authenticator,
            client_data_json,
            signature,
        )?)
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

    #[test]
    fn vector_83a_raw_signature_verifies_as_a_probe_signature() -> TestResult {
        let probe = CustodyProbe::new(hex32(COUNTING_NONCE)?);
        let key = reference()?.public_key().to_compressed();
        let signature: [u8; 64] = hex::decode(V83A_SIGNATURE)?
            .try_into()
            .map_err(|_| "Vector 83a's signature is not 64 bytes")?;
        assert_eq!(
            sign_prehash_rfc6979(&reference()?, &probe.raw_digest())?,
            signature
        );
        ProbeSignature::raw(signature).verify(&probe, &key)?;
        Ok(())
    }

    #[test]
    fn a_raw_key_event_signature_does_not_verify_as_a_probe_signature() -> TestResult {
        let probe = CustodyProbe::new(hex32(COUNTING_NONCE)?);
        let key = reference()?.public_key().to_compressed();
        let over_event = sign_prehash_rfc6979(&reference()?, &hex32(V41_DIGEST)?)?;
        assert!(matches!(
            ProbeSignature::raw(over_event).verify(&probe, &key),
            Err(IndexedSignatureError::Signature(_))
        ));
        Ok(())
    }

    #[test]
    fn an_assertion_over_the_probe_challenge_verifies_as_a_probe_signature() -> TestResult {
        let probe = CustodyProbe::new(hex32(COUNTING_NONCE)?);
        let key = reference()?.public_key().to_compressed();
        let assertion = assertion_over(&probe.assertion_challenge())?;
        ProbeSignature::assertion(assertion).verify(&probe, &key)?;
        Ok(())
    }

    #[test]
    fn a_key_event_assertion_does_not_verify_as_a_probe_signature() -> TestResult {
        let probe = CustodyProbe::new(hex32(COUNTING_NONCE)?);
        let key = reference()?.public_key().to_compressed();
        let assertion = assertion_over(&key_event_challenge(&hex32(V41_DIGEST)?))?;
        assert_eq!(
            ProbeSignature::assertion(assertion).verify(&probe, &key),
            Err(IndexedSignatureError::ChallengeMismatch)
        );
        Ok(())
    }

    #[test]
    fn a_substrate_failure_names_its_error_code() {
        let error = KeyEventSignError::Substrate {
            code: "SCP-STORAGE-8000",
            message: "storage is locked".to_owned(),
        };
        assert_eq!(
            error.to_string(),
            "the custody substrate failed (SCP-STORAGE-8000): storage is locked"
        );
    }
}
