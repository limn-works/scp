//! The participation signing seed, its wrap, and the derive-and-compare check.
//!
//! `07-trust-validation-and-capabilities.md` §7.3.2.1, "Seed custody and admin
//! rotation", defines both. The seed is sealed under HPKE base mode, DHKEM(P-256, HKDF-SHA256),
//! HKDF-SHA256, AES-128-GCM, to the holding admin's `scp_wrapping_key`
//! (`0xFF01`) MLS leaf key, with
//! `info = "scp-participation-seed-wrap:" || context_id` (UTF-8, no length
//! prefix) and an empty AAD (§9.18.3 of the security-model spec registers the
//! prefix; spec 25 §25.32 Vector 67 pins the bytes).
//!
//! HPKE base mode authenticates no sender: anyone who holds the recipient's
//! public `0xFF01` key can seal a seed of their own choosing to it. So
//! [`open_participation_seed`] returns no seed until it has derived the
//! participation signing key from it ([`P256SecretKey::from_participation_seed`])
//! and found that key's public half equal to the `signer_public_key` the
//! context publishes.
//!
//! What the types enforce:
//!
//! - A [`ParticipationSeed`] has two public constructors:
//!   [`ParticipationSeed::generate`], which draws the §7.3.2.1 `CSPRNG(32)` from
//!   `OsRng`, and [`open_participation_seed`], which returns one only after the
//!   derive-and-compare check passed. Its fields are private, and no public function
//!   takes or returns its seed bytes, so no caller outside this
//!   module builds one from bytes of its own.
//! - A [`ParticipationSeed`] carries the `context_id` it was generated for or
//!   checked under, and its signer derived under that `context_id`.
//!   [`seal_participation_seed`] takes the seed and a recipient and no
//!   `context_id`: it seals under the seed's own `context_id`, so a seed checked
//!   under context A cannot be wrapped for context B.
//! - Outside the crate the seed bytes are reachable only through the derivation
//!   the producer signs with: [`ParticipationSeed::signer`].
//!
//! What the types do not enforce: [`P256SecretKey::from_participation_seed`]
//! (scp-crypto) and `custody::open_with_external_dh` (this crate's HPKE module)
//! stay public, so a caller that opens a wrap with the raw HPKE call holds
//! plaintext bytes and can derive a signer from them. Neither path yields a
//! [`ParticipationSeed`], so neither can seal a wrap through this module.
//!
//! A struct literal is refused, because the fields are private:
//!
//! ```compile_fail,E0451
//! use scp_protocol::trust::participation_seed::ParticipationSeed;
//! let _ = ParticipationSeed { seed: todo!(), context_id: todo!(), signer: todo!() };
//! ```
//!
//! No raw-bytes constructor exists:
//!
//! ```compile_fail,E0599
//! use scp_protocol::trust::participation_seed::ParticipationSeed;
//! let _ = ParticipationSeed::from_bytes([0u8; 32], "context-alpha");
//! ```
//!
//! The seal takes no `context_id` to wrap under:
//!
//! ```compile_fail,E0061
//! use scp_crypto::p256::P256SecretKey;
//! use scp_protocol::crypto::hpke::p256::P256Point;
//! use scp_protocol::trust::participation_seed::{ParticipationSeed, seal_participation_seed};
//! let seed = ParticipationSeed::generate("context-alpha").unwrap();
//! let recipient = P256Point::from(&P256SecretKey::random(&mut rand::rngs::OsRng).public_key());
//! let _ = seal_participation_seed(&seed, &recipient, "context-beta");
//! ```
//!
//! The positive control, which compiles and runs:
//!
//! ```
//! use scp_crypto::p256::P256SecretKey;
//! use scp_protocol::crypto::hpke::p256::P256Point;
//! use scp_protocol::trust::participation_seed::{ParticipationSeed, seal_participation_seed};
//! let seed = ParticipationSeed::generate("context-alpha")?;
//! let recipient = P256Point::from(&P256SecretKey::random(&mut rand::rngs::OsRng).public_key());
//! let wrapped = seal_participation_seed(&seed, &recipient)?;
//! assert_eq!(wrapped.recipient_wrapping_key, recipient);
//! assert_eq!(seed.context_id(), "context-alpha");
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! The opener's wrapping private key never reaches this module:
//! [`open_participation_seed`] takes the DHKEM `DH(skR, enc)` output, which a
//! caller obtains from `KeyCustody::dh_agree` on its custody-held wrapping key.

use rand::RngCore;
use scp_crypto::p256::{P256PublicKey, P256SecretKey};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::crypto::hpke::HpkeError;
use crate::crypto::hpke::p256::{self as hpke_p256, P256Point, ValidatedEnc, custody};

/// The HPKE `info` prefix of the participation seed wrap (§7.3.2.1, §9.18.3).
/// The full `info` is this prefix followed by the `context_id`'s UTF-8 bytes,
/// with no length prefix.
pub const PARTICIPATION_SEED_WRAP_INFO_PREFIX: &[u8] = b"scp-participation-seed-wrap:";

/// The seed wrap's AEAD additional data, which §7.3.2.1 fixes as empty: no AAD
/// value can bind which seed is inside, so the derive-and-compare check binds
/// it instead.
const SEED_WRAP_AAD: &[u8] = b"";

/// Length of a `participation_signing_seed` (§7.3.2.1: `CSPRNG(32)`).
pub const PARTICIPATION_SEED_LEN: usize = 32;

/// A `participation_signing_seed` sealed to one holder's `scp_wrapping_key`
/// (`0xFF01`) leaf key (§7.3.2.1).
///
/// `Debug` prints the two public points and the ciphertext's length, never the
/// ciphertext.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WrappedParticipationSeed {
    /// The `scp_wrapping_key` the seed is sealed to: HPKE's `pkR`.
    pub recipient_wrapping_key: P256Point,
    /// The HPKE encapsulated key.
    pub enc: P256Point,
    /// The AEAD ciphertext and tag: 48 bytes for a 32-byte seed.
    #[serde(with = "serde_bytes")]
    pub ciphertext: Vec<u8>,
}

impl core::fmt::Debug for WrappedParticipationSeed {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("WrappedParticipationSeed")
            .field("recipient_wrapping_key", &self.recipient_wrapping_key)
            .field("enc", &self.enc)
            .field("ciphertext_len", &self.ciphertext.len())
            .finish()
    }
}

/// A context's `participation_signing_seed`, bound to the `context_id` it
/// belongs to, with the signing key derived from it under that `context_id`
/// (§7.3.2.1).
///
/// The public constructors are [`ParticipationSeed::generate`] (a fresh
/// `CSPRNG(32)` draw, for context creation and `RotateParticipationKey`) and
/// [`open_participation_seed`] (a wrap that passed the derive-and-compare
/// check). The seed is held in [`Zeroizing`] memory and the signer zeroizes its
/// scalar on drop. `Debug` prints the `context_id` and the signer's public key
/// only.
pub struct ParticipationSeed {
    seed: Zeroizing<[u8; PARTICIPATION_SEED_LEN]>,
    context_id: String,
    signer: P256SecretKey,
}

impl ParticipationSeed {
    /// Draws a new seed from `OsRng` for `context_id` (§7.3.2.1:
    /// `participation_signing_seed = CSPRNG(32)`).
    ///
    /// # Errors
    ///
    /// [`ParticipationSeedError::EmptyContextId`] for an empty `context_id`,
    /// and [`ParticipationSeedError::Randomness`] if the operating system's
    /// random source fails.
    pub fn generate(context_id: &str) -> Result<Self, ParticipationSeedError> {
        Self::generate_from(&mut rand::rngs::OsRng, context_id)
    }

    /// The body of [`generate`](Self::generate) over an injected random
    /// source, so a test can drive the randomness-failure path.
    fn generate_from(
        rng: &mut impl RngCore,
        context_id: &str,
    ) -> Result<Self, ParticipationSeedError> {
        check_context_id(context_id)?;
        let mut seed = Zeroizing::new([0u8; PARTICIPATION_SEED_LEN]);
        rng.try_fill_bytes(seed.as_mut())
            .map_err(ParticipationSeedError::Randomness)?;
        Ok(Self::from_checked(seed, context_id))
    }

    /// Binds `seed` to a non-empty `context_id` the caller has already checked,
    /// deriving the signer under it. Private: every caller is a constructor
    /// above or [`open_participation_seed`] after its compare.
    fn from_checked(seed: Zeroizing<[u8; PARTICIPATION_SEED_LEN]>, context_id: &str) -> Self {
        let signer = P256SecretKey::from_participation_seed(&seed, context_id);
        Self {
            seed,
            context_id: context_id.to_owned(),
            signer,
        }
    }

    /// The `context_id` this seed was generated for or checked under; a seal
    /// of this seed binds this `context_id` into its `info`.
    #[must_use]
    pub fn context_id(&self) -> &str {
        &self.context_id
    }

    /// The context's participation signing key, derived from the seed under
    /// [`context_id`](Self::context_id). Its public half is the context's
    /// `signer_public_key`.
    #[must_use]
    pub const fn signer(&self) -> &P256SecretKey {
        &self.signer
    }
}

impl core::fmt::Debug for ParticipationSeed {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ParticipationSeed")
            .field("context_id", &self.context_id)
            .field("signer_public_key", &self.signer.public_key())
            .finish_non_exhaustive()
    }
}

/// Errors from generating, sealing or opening a participation seed. No variant
/// carries seed, ciphertext or private-key bytes.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ParticipationSeedError {
    /// The `context_id` was empty, so the wrap `info` and the signer derivation
    /// would bind no context.
    #[error("participation seed needs a non-empty context_id")]
    EmptyContextId,
    /// The operating system's random source failed to produce the seed.
    #[error("participation seed generation could not draw random bytes")]
    Randomness(#[source] rand::Error),
    /// The HPKE seal failed.
    #[error("participation seed wrap seal failed")]
    Seal(#[source] HpkeError),
    /// The caller's wrapping key is not the `recipient_wrapping_key` the wrap
    /// names, so the wrap is not addressed to it.
    #[error("participation seed wrap is addressed to another recipient_wrapping_key")]
    WrongRecipient,
    /// The HPKE open failed: a wrong `DH` output, a wrap made for another
    /// `context_id`, or a tampered `enc`, ciphertext or recipient field.
    #[error("participation seed wrap did not open")]
    Open(#[source] HpkeError),
    /// The wrap opened to a plaintext that is not exactly 32 bytes.
    #[error("participation seed wrap opened to {0} bytes, not the 32 of a seed")]
    InvalidSeedLength(usize),
    /// The opened seed derives a participation public key other than the
    /// context's current `signer_public_key`; §7.3.2.1 requires refusing it.
    #[error(
        "opened participation seed derives a signer key other than the context's signer_public_key"
    )]
    SignerKeyMismatch,
}

/// Seals `seed` to `recipient` (a holder's `scp_wrapping_key` leaf key) under
/// the seed's own [`context_id`](ParticipationSeed::context_id) and a fresh
/// ephemeral key (§7.3.2.1).
///
/// # Errors
///
/// [`ParticipationSeedError::Seal`] if HPKE fails.
pub fn seal_participation_seed(
    seed: &ParticipationSeed,
    recipient: &P256Point,
) -> Result<WrappedParticipationSeed, ParticipationSeedError> {
    seal_with(seed, recipient, hpke_p256::seal)
}

/// The body of [`seal_participation_seed`] over an injected HPKE seal, so the
/// Vector 67 test runs this same `info` and AAD construction under its fixed
/// ephemeral key.
fn seal_with(
    seed: &ParticipationSeed,
    recipient: &P256Point,
    seal: impl FnOnce(&P256Point, &[u8], &[u8], &[u8]) -> Result<(P256Point, Vec<u8>), HpkeError>,
) -> Result<WrappedParticipationSeed, ParticipationSeedError> {
    let info = seed_wrap_info(&seed.context_id)?;
    let (enc, ciphertext) = seal(recipient, &info, SEED_WRAP_AAD, seed.seed.as_ref())
        .map_err(ParticipationSeedError::Seal)?;
    Ok(WrappedParticipationSeed {
        recipient_wrapping_key: *recipient,
        enc,
        ciphertext,
    })
}

/// Opens `wrapped` for `context_id` and runs the §7.3.2.1 derive-and-compare check.
///
/// `expected_signer_public_key` is the `signer_public_key` the context
/// currently publishes, taken from the opener's own state. `dh` is
/// `KeyCustody::dh_agree(h, wrapped.enc.as_bytes())` for the custody handle `h`
/// of the opener's wrapping key, and `recipient` is that key's public half. The
/// wrapping private key never leaves custody. The returned seed is bound to
/// `context_id`.
///
/// # Errors
///
/// - [`ParticipationSeedError::EmptyContextId`] for an empty `context_id`.
/// - [`ParticipationSeedError::WrongRecipient`] when `recipient` is not
///   `wrapped.recipient_wrapping_key`; checked before any HPKE work.
/// - [`ParticipationSeedError::Open`] when HPKE fails: another `DH` output,
///   another `context_id`, or a tampered wrap.
/// - [`ParticipationSeedError::InvalidSeedLength`] when the plaintext is not
///   32 bytes.
/// - [`ParticipationSeedError::SignerKeyMismatch`] when the seed derives a key
///   other than `expected_signer_public_key`.
pub fn open_participation_seed(
    dh: &[u8; 32],
    recipient: &P256Point,
    wrapped: &WrappedParticipationSeed,
    context_id: &str,
    expected_signer_public_key: &P256PublicKey,
) -> Result<ParticipationSeed, ParticipationSeedError> {
    let info = seed_wrap_info(context_id)?;
    // Both points are public, so the comparison needs no constant time.
    if *recipient != wrapped.recipient_wrapping_key {
        return Err(ParticipationSeedError::WrongRecipient);
    }
    let plaintext = custody::open_with_external_dh(
        dh,
        recipient.as_bytes(),
        &ValidatedEnc::from(wrapped.enc),
        &info,
        SEED_WRAP_AAD,
        &wrapped.ciphertext,
    )
    .map_err(ParticipationSeedError::Open)?;
    if plaintext.len() != PARTICIPATION_SEED_LEN {
        return Err(ParticipationSeedError::InvalidSeedLength(plaintext.len()));
    }
    let mut seed = Zeroizing::new([0u8; PARTICIPATION_SEED_LEN]);
    seed.copy_from_slice(&plaintext);
    let opened = ParticipationSeed::from_checked(seed, context_id);
    if opened.signer.public_key() != *expected_signer_public_key {
        return Err(ParticipationSeedError::SignerKeyMismatch);
    }
    Ok(opened)
}

/// Refuses an empty `context_id`.
const fn check_context_id(context_id: &str) -> Result<(), ParticipationSeedError> {
    if context_id.is_empty() {
        return Err(ParticipationSeedError::EmptyContextId);
    }
    Ok(())
}

/// `PARTICIPATION_SEED_WRAP_INFO_PREFIX || context_id`, refusing an empty
/// `context_id`.
fn seed_wrap_info(context_id: &str) -> Result<Vec<u8>, ParticipationSeedError> {
    check_context_id(context_id)?;
    Ok([PARTICIPATION_SEED_WRAP_INFO_PREFIX, context_id.as_bytes()].concat())
}

#[cfg(test)]
mod tests {
    use std::error::Error as _;

    use scp_crypto::p256::ecdh_p256;

    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    const CONTEXT: &str = "context-alpha";
    const OTHER_CONTEXT: &str = "context-beta";
    /// §25.32: the seed `00` through `1f`.
    const VECTOR_SEED: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    /// §25.32 Vector 66 `signer_public_key`, compressed.
    const VECTOR_SIGNER_PK: &str =
        "02ae8181b600262629a7d73b40f05cb6785e5ae6e34f816db22d260ec50d1ea887";
    /// §25.2 reference private scalar: Vector 67's recipient.
    const REFERENCE_SCALAR: &str =
        "6f0712104c3f61ba04526a822836d3f4a13be12e09a8c3c7586b2da0c795998b";
    /// §25.2 secondary private scalar: Vector 67's fixed ephemeral.
    const SECONDARY_SCALAR: &str =
        "0fed5549df222a5cf0b537e423fbd60875c6fb2b334b381a0c0a6c89eae9ac6a";
    /// §25.32 Vector 67 `enc`.
    const VECTOR_ENC: &str = "0423702a648232f2d00713de9289753c2fbd4c4efa7e1e33905e3723a412b20a\
                              ead0992a08064d996d9268dc511c7430f3a4e614871d4a888b52a8dbecb56d6da6";
    /// §25.32 Vector 67 ciphertext.
    const VECTOR_CT: &str = "56c81f506f32f056c2a8e7242e8afc476e846ba65b54e1b496bc2345837d4bd1\
                             3807770941f5a06f0a4d1916612b4b02";

    fn arr<const N: usize>(s: &str) -> Result<[u8; N], Box<dyn std::error::Error>> {
        hex::decode(s)?
            .try_into()
            .map_err(|v: Vec<u8>| format!("expected {N} bytes, got {}", v.len()).into())
    }

    fn key(scalar: &str) -> Result<P256SecretKey, Box<dyn std::error::Error>> {
        Ok(P256SecretKey::from_scalar_bytes(&arr(scalar)?)?)
    }

    /// A seed of fixed bytes for `context_id`, through the module's private
    /// constructor, which no caller outside this module reaches.
    fn fixed_seed(bytes: [u8; 32], context_id: &str) -> ParticipationSeed {
        ParticipationSeed::from_checked(Zeroizing::new(bytes), context_id)
    }

    /// A holder whose wrapping private key stands in for custody: `agree` is
    /// what `KeyCustody::dh_agree` returns for the wrap's `enc`.
    struct Holder {
        sk: P256SecretKey,
    }

    impl Holder {
        fn new(byte: u8) -> Self {
            Self {
                sk: P256SecretKey::from_seed(
                    scp_crypto::p256::SeedLabel::TestVectorKey,
                    &[byte; 32],
                ),
            }
        }

        fn point(&self) -> P256Point {
            P256Point::from(&self.sk.public_key())
        }

        fn agree(&self, wrapped: &WrappedParticipationSeed) -> Zeroizing<[u8; 32]> {
            ecdh_p256(&self.sk, ValidatedEnc::from(wrapped.enc).point())
        }

        fn open(
            &self,
            wrapped: &WrappedParticipationSeed,
            context_id: &str,
            expected: &P256PublicKey,
        ) -> Result<ParticipationSeed, ParticipationSeedError> {
            open_participation_seed(
                &self.agree(wrapped),
                &self.point(),
                wrapped,
                context_id,
                expected,
            )
        }
    }

    fn signer_pk(seed: &[u8; 32], context_id: &str) -> P256PublicKey {
        P256SecretKey::from_participation_seed(seed, context_id).public_key()
    }

    /// A random source whose every draw fails, as `OsRng` does when the
    /// operating system's source is unavailable.
    struct FailingRng;

    impl RngCore for FailingRng {
        fn next_u32(&mut self) -> u32 {
            unreachable!("generate draws through try_fill_bytes only")
        }
        fn next_u64(&mut self) -> u64 {
            unreachable!("generate draws through try_fill_bytes only")
        }
        fn fill_bytes(&mut self, _: &mut [u8]) {
            unreachable!("generate draws through try_fill_bytes only")
        }
        fn try_fill_bytes(&mut self, _: &mut [u8]) -> Result<(), rand::Error> {
            Err(rand::Error::new(std::io::Error::other("no entropy")))
        }
    }

    #[test]
    fn seed_wrap_round_trips() -> TestResult {
        let holder = Holder::new(1);
        let bytes = [0x5au8; 32];
        let seed = fixed_seed(bytes, CONTEXT);
        let wrapped = seal_participation_seed(&seed, &holder.point())?;
        assert_eq!(wrapped.recipient_wrapping_key, holder.point());
        assert_eq!(wrapped.ciphertext.len(), 48);
        let opened = holder.open(&wrapped, CONTEXT, &signer_pk(&bytes, CONTEXT))?;
        assert_eq!(*opened.seed, bytes);
        assert_eq!(opened.context_id(), CONTEXT);
        assert_eq!(opened.signer().public_key(), signer_pk(&bytes, CONTEXT));
        Ok(())
    }

    /// `generate` binds a fresh draw to its `context_id` and derives the
    /// §7.3.2.1 signer from that draw under that `context_id`.
    #[test]
    fn generate_draws_a_fresh_seed_bound_to_its_context() -> TestResult {
        let first = ParticipationSeed::generate(CONTEXT)?;
        let second = ParticipationSeed::generate(CONTEXT)?;
        assert_ne!(*first.seed, *second.seed);
        assert_eq!(first.context_id(), CONTEXT);
        assert_eq!(first.signer().public_key(), signer_pk(&first.seed, CONTEXT));
        assert!(matches!(
            ParticipationSeed::generate(""),
            Err(ParticipationSeedError::EmptyContextId)
        ));
        Ok(())
    }

    #[test]
    fn generate_reports_a_failed_random_source() -> TestResult {
        let error = ParticipationSeed::generate_from(&mut FailingRng, CONTEXT)
            .err()
            .ok_or("generate succeeded without randomness")?;
        assert!(
            matches!(error, ParticipationSeedError::Randomness(_)),
            "{error:?}"
        );
        assert!(error.source().is_some());
        Ok(())
    }

    /// The §7.3.2.1 re-wrap: a seed opened under one context re-wraps to a new
    /// holder under that same context, and the new holder opens it there and
    /// derives the same signer. `seal_participation_seed` takes no
    /// `context_id`, so the re-wrap cannot name another context (the module
    /// doc's `compile_fail,E0061` block); a new holder that opens it under
    /// another context is refused by the `info` binding.
    #[test]
    fn rewrap_of_opened_seed_stays_bound_to_its_context() -> TestResult {
        let outgoing = Holder::new(1);
        let incoming = Holder::new(2);
        let bytes = [0x5au8; 32];
        let published = signer_pk(&bytes, CONTEXT);
        let wrapped = seal_participation_seed(&fixed_seed(bytes, CONTEXT), &outgoing.point())?;
        let opened = outgoing.open(&wrapped, CONTEXT, &published)?;

        let rewrapped = seal_participation_seed(&opened, &incoming.point())?;
        let reopened = incoming.open(&rewrapped, CONTEXT, &published)?;
        assert_eq!(*reopened.seed, bytes);
        assert_eq!(reopened.context_id(), CONTEXT);
        assert_eq!(reopened.signer().public_key(), published);

        let elsewhere = incoming.open(&rewrapped, OTHER_CONTEXT, &signer_pk(&bytes, OTHER_CONTEXT));
        assert!(
            matches!(
                elsewhere,
                Err(ParticipationSeedError::Open(HpkeError::OpenFailed(_)))
            ),
            "{elsewhere:?}"
        );
        Ok(())
    }

    /// A wrap made for one context does not open under another context's
    /// `info`: the AEAD fails, before any derivation. The opener expects the
    /// key the seed derives under the other context, so only the `info`
    /// binding can refuse it.
    #[test]
    fn seed_wrap_rejects_other_context() -> TestResult {
        let holder = Holder::new(1);
        let bytes = [0x5au8; 32];
        let wrapped = seal_participation_seed(&fixed_seed(bytes, CONTEXT), &holder.point())?;
        let result = holder.open(&wrapped, OTHER_CONTEXT, &signer_pk(&bytes, OTHER_CONTEXT));
        assert!(
            matches!(
                result,
                Err(ParticipationSeedError::Open(HpkeError::OpenFailed(_)))
            ),
            "{result:?}"
        );
        Ok(())
    }

    /// An opener whose key is not the wrap's `recipient_wrapping_key` gets
    /// `WrongRecipient`, not an AEAD failure.
    #[test]
    fn seed_wrap_rejects_other_recipient() -> TestResult {
        let holder = Holder::new(1);
        let other = Holder::new(2);
        let bytes = [0x5au8; 32];
        let wrapped = seal_participation_seed(&fixed_seed(bytes, CONTEXT), &holder.point())?;
        let result = other.open(&wrapped, CONTEXT, &signer_pk(&bytes, CONTEXT));
        assert!(
            matches!(result, Err(ParticipationSeedError::WrongRecipient)),
            "{result:?}"
        );
        Ok(())
    }

    /// A wrap whose `recipient_wrapping_key` field was rewritten to name
    /// another holder passes the field compare and still fails HPKE, because
    /// `kem_context` binds the `pkR` the seal used.
    #[test]
    fn seed_wrap_rejects_rewritten_recipient_field() -> TestResult {
        let holder = Holder::new(1);
        let other = Holder::new(2);
        let bytes = [0x5au8; 32];
        let mut wrapped = seal_participation_seed(&fixed_seed(bytes, CONTEXT), &holder.point())?;
        wrapped.recipient_wrapping_key = other.point();
        let result = other.open(&wrapped, CONTEXT, &signer_pk(&bytes, CONTEXT));
        assert!(
            matches!(
                result,
                Err(ParticipationSeedError::Open(HpkeError::OpenFailed(_)))
            ),
            "{result:?}"
        );
        Ok(())
    }

    #[test]
    fn seed_wrap_rejects_tampered_ct() -> TestResult {
        let holder = Holder::new(1);
        let bytes = [0x5au8; 32];
        let expected = signer_pk(&bytes, CONTEXT);
        let wrapped = seal_participation_seed(&fixed_seed(bytes, CONTEXT), &holder.point())?;
        for i in 0..wrapped.ciphertext.len() {
            let mut tampered = wrapped.clone();
            tampered.ciphertext[i] ^= 0x01;
            let result = holder.open(&tampered, CONTEXT, &expected);
            assert!(
                matches!(
                    result,
                    Err(ParticipationSeedError::Open(HpkeError::OpenFailed(_)))
                ),
                "byte {i}: {result:?}"
            );
        }
        // Positive control: the untampered wrap opens.
        holder.open(&wrapped, CONTEXT, &expected)?;
        Ok(())
    }

    /// A wrap whose plaintext is 31 or 33 bytes opens under HPKE and is
    /// refused for its length.
    #[test]
    fn seed_wrap_rejects_non_32_plaintext() -> TestResult {
        let holder = Holder::new(1);
        let info = seed_wrap_info(CONTEXT)?;
        for len in [0usize, 31, 33, 64] {
            let (enc, ciphertext) =
                hpke_p256::seal(&holder.point(), &info, SEED_WRAP_AAD, &vec![0x5a; len])?;
            let wrapped = WrappedParticipationSeed {
                recipient_wrapping_key: holder.point(),
                enc,
                ciphertext,
            };
            let result = holder.open(&wrapped, CONTEXT, &signer_pk(&[0x5a; 32], CONTEXT));
            assert!(
                matches!(result, Err(ParticipationSeedError::InvalidSeedLength(l)) if l == len),
                "{len}: {result:?}"
            );
        }
        Ok(())
    }

    /// §25.32 Vector 67, both directions: the pinned `enc` and ciphertext open
    /// under the §25.2 reference key to the Vector 66 seed (which passes the
    /// compare against Vector 66's key), and sealing that seed under the
    /// fixed secondary ephemeral reproduces them.
    #[test]
    fn seed_wrap_matches_spec25_vector() -> TestResult {
        let recipient_sk = key(REFERENCE_SCALAR)?;
        let recipient = P256Point::from(&recipient_sk.public_key());
        let bytes: [u8; 32] = arr(VECTOR_SEED)?;
        let expected = P256PublicKey::from_sec1(&hex::decode(VECTOR_SIGNER_PK)?)?;
        let wrapped = WrappedParticipationSeed {
            recipient_wrapping_key: recipient,
            enc: P256Point::try_from(arr::<65>(VECTOR_ENC)?)?,
            ciphertext: hex::decode(VECTOR_CT)?,
        };

        let dh = ecdh_p256(&recipient_sk, ValidatedEnc::from(wrapped.enc).point());
        assert_eq!(
            hex::encode(*dh),
            "39cc00defd06eb2704dc5604630f54f7196fa7f402f8236214fb5fbac9e6f4ad"
        );
        let opened = open_participation_seed(&dh, &recipient, &wrapped, CONTEXT, &expected)?;
        assert_eq!(*opened.seed, bytes);

        let ephemeral = key(SECONDARY_SCALAR)?;
        let resealed = seal_with(&opened, &recipient, |r, info, aad, pt| {
            hpke_p256::seal_with_fixed_ephemeral(&ephemeral, r, info, aad, pt)
        })?;
        assert_eq!(resealed, wrapped);
        Ok(())
    }

    /// HPKE base mode authenticates no sender, so a seed anyone sealed to the
    /// holder's public key opens; the derive-and-compare check refuses it.
    #[test]
    fn open_seed_rejects_seed_not_matching_signer_public_key() -> TestResult {
        let holder = Holder::new(1);
        let context_seed = [0x5au8; 32];
        let published = signer_pk(&context_seed, CONTEXT);

        let attacker_seed = ParticipationSeed::generate(CONTEXT)?;
        let forged = seal_participation_seed(&attacker_seed, &holder.point())?;
        let result = holder.open(&forged, CONTEXT, &published);
        assert!(
            matches!(result, Err(ParticipationSeedError::SignerKeyMismatch)),
            "{result:?}"
        );

        // Positive control: the context's own seed passes the same compare.
        let genuine = seal_participation_seed(&fixed_seed(context_seed, CONTEXT), &holder.point())?;
        holder.open(&genuine, CONTEXT, &published)?;
        Ok(())
    }

    #[test]
    fn empty_context_id_is_refused() -> TestResult {
        let holder = Holder::new(1);
        let bytes = [0x5au8; 32];
        let wrapped = seal_participation_seed(&fixed_seed(bytes, CONTEXT), &holder.point())?;
        assert!(matches!(
            holder.open(&wrapped, "", &signer_pk(&bytes, CONTEXT)),
            Err(ParticipationSeedError::EmptyContextId)
        ));
        Ok(())
    }

    /// `Seal` and `Open` keep the HPKE error as their `source()`, and their
    /// messages do not repeat its text.
    #[test]
    fn seal_and_open_errors_chain_their_hpke_source() -> TestResult {
        let holder = Holder::new(1);
        let seed = fixed_seed([0x5a; 32], CONTEXT);
        let seal_error = seal_with(&seed, &holder.point(), |_, _, _, _| {
            Err(HpkeError::SealFailed("inner seal text".into()))
        })
        .err()
        .ok_or("injected seal failure sealed")?;
        assert!(matches!(seal_error, ParticipationSeedError::Seal(_)));

        let mut tampered = seal_participation_seed(&seed, &holder.point())?;
        tampered.ciphertext[0] ^= 1;
        let open_error = holder
            .open(&tampered, CONTEXT, &seed.signer().public_key())
            .err()
            .ok_or("tampered wrap opened")?;
        assert!(matches!(open_error, ParticipationSeedError::Open(_)));

        for error in [&seal_error, &open_error] {
            let source = error.source().ok_or("no source")?;
            assert!(source.downcast_ref::<HpkeError>().is_some(), "{source:?}");
            assert!(!error.to_string().contains(&source.to_string()), "{error}");
        }
        Ok(())
    }

    /// No `Debug` or `Display` output of the wrap, the seed, or any error
    /// contains the seed, the ciphertext, or the derived private scalar, in
    /// hex or as a byte list.
    #[test]
    fn debug_and_display_print_no_secret_bytes() -> TestResult {
        let holder = Holder::new(1);
        let bytes: [u8; 32] = arr(VECTOR_SEED)?;
        let wrapped = seal_participation_seed(&fixed_seed(bytes, CONTEXT), &holder.point())?;
        let opened = holder.open(&wrapped, CONTEXT, &signer_pk(&bytes, CONTEXT))?;
        let scalar = opened.signer().to_scalar_bytes();

        let secrets: [&[u8]; 3] = [&bytes, &wrapped.ciphertext, scalar.as_ref()];
        let mut outputs = vec![format!("{wrapped:?}"), format!("{opened:?}")];
        for error in [
            ParticipationSeedError::EmptyContextId,
            ParticipationSeedError::Randomness(rand::Error::new(std::io::Error::other("x"))),
            ParticipationSeedError::Seal(HpkeError::SealFailed("x".into())),
            ParticipationSeedError::WrongRecipient,
            ParticipationSeedError::Open(HpkeError::OpenFailed("x".into())),
            ParticipationSeedError::InvalidSeedLength(31),
            ParticipationSeedError::SignerKeyMismatch,
        ] {
            outputs.push(format!("{error:?}"));
            outputs.push(error.to_string());
        }
        // Real errors from the open path, whose messages come from HPKE.
        let mut tampered = wrapped.clone();
        tampered.ciphertext[0] ^= 1;
        let open_error = holder
            .open(&tampered, CONTEXT, &signer_pk(&bytes, CONTEXT))
            .err()
            .ok_or("tampered wrap opened")?;
        outputs.push(format!("{open_error:?}"));
        outputs.push(open_error.to_string());

        for secret in secrets {
            let as_hex = hex::encode(secret);
            // An 8-byte window catches a printed prefix or a partial dump.
            let as_list = format!("{:?}", &secret[..8]);
            let as_list = &as_list[1..as_list.len() - 1];
            for output in &outputs {
                assert!(!output.contains(&as_hex[..16]), "{output}");
                assert!(!output.contains(as_list), "{output}");
            }
        }
        // The positive controls: each Debug names what it may print.
        assert!(outputs[0].contains("ciphertext_len: 48"), "{}", outputs[0]);
        assert!(outputs[1].contains(CONTEXT), "{}", outputs[1]);
        Ok(())
    }
}
