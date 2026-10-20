//! The participation signing seed wrap and its derive-and-compare check.
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
//! [`open_participation_seed`] does not return a seed until it has derived the
//! participation signing key from it ([`P256SecretKey::from_participation_seed`])
//! and found that key's public half equal to the `signer_public_key` the
//! context publishes. An [`OpenedParticipationSeed`] exists only after that
//! comparison passed, and it carries the derived signer, so no caller signs
//! with, or re-wraps, a seed the check has not accepted.
//!
//! The opener's wrapping private key never reaches this module:
//! [`open_participation_seed`] takes the DHKEM `DH(skR, enc)` output, which a
//! caller obtains from `KeyCustody::dh_agree` on its custody-held wrapping key.

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

/// A participation seed that opened and passed the §7.3.2.1 derive-and-compare
/// check, with the signing key derived from it for its context.
///
/// [`open_participation_seed`] is the only constructor. The seed is held in
/// [`Zeroizing`] memory and the signer zeroizes its scalar on drop. `Debug`
/// prints the signer's public key only.
pub struct OpenedParticipationSeed {
    seed: Zeroizing<[u8; PARTICIPATION_SEED_LEN]>,
    signer: P256SecretKey,
}

impl OpenedParticipationSeed {
    /// The opened seed, for a re-wrap to a new holder key (§7.3.2.1).
    #[must_use]
    pub fn seed(&self) -> &[u8; PARTICIPATION_SEED_LEN] {
        &self.seed
    }

    /// The context's participation signing key, derived from the seed under
    /// the opened context's `context_id`.
    #[must_use]
    pub const fn signer(&self) -> &P256SecretKey {
        &self.signer
    }
}

impl core::fmt::Debug for OpenedParticipationSeed {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("OpenedParticipationSeed")
            .field("signer_public_key", &self.signer.public_key())
            .finish_non_exhaustive()
    }
}

/// Errors from sealing or opening a participation seed wrap. No variant
/// carries seed, ciphertext or private-key bytes.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ParticipationSeedError {
    /// The `context_id` was empty, so the wrap `info` and the signer derivation
    /// would bind no context.
    #[error("participation seed wrap needs a non-empty context_id")]
    EmptyContextId,
    /// The HPKE seal failed.
    #[error("participation seed wrap seal failed: {0}")]
    Seal(HpkeError),
    /// The HPKE open failed: a wrong recipient key or `DH` output, a wrap made
    /// for another `context_id`, or a tampered `enc` or ciphertext.
    #[error("participation seed wrap did not open: {0}")]
    Open(HpkeError),
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

/// Seals `seed` to `recipient` (a holder's `scp_wrapping_key` leaf key) for
/// `context_id`, under a fresh ephemeral key (§7.3.2.1).
///
/// # Errors
///
/// [`ParticipationSeedError::EmptyContextId`] for an empty `context_id`, and
/// [`ParticipationSeedError::Seal`] if HPKE fails.
pub fn seal_participation_seed(
    seed: &[u8; PARTICIPATION_SEED_LEN],
    recipient: &P256Point,
    context_id: &str,
) -> Result<WrappedParticipationSeed, ParticipationSeedError> {
    seal_with(seed, recipient, context_id, hpke_p256::seal)
}

/// The body of [`seal_participation_seed`] over an injected HPKE seal, so the
/// Vector 67 test runs this same `info` and AAD construction under its fixed
/// ephemeral key.
fn seal_with(
    seed: &[u8; PARTICIPATION_SEED_LEN],
    recipient: &P256Point,
    context_id: &str,
    seal: impl FnOnce(&P256Point, &[u8], &[u8], &[u8]) -> Result<(P256Point, Vec<u8>), HpkeError>,
) -> Result<WrappedParticipationSeed, ParticipationSeedError> {
    let info = seed_wrap_info(context_id)?;
    let (enc, ciphertext) =
        seal(recipient, &info, SEED_WRAP_AAD, seed).map_err(ParticipationSeedError::Seal)?;
    Ok(WrappedParticipationSeed {
        recipient_wrapping_key: *recipient,
        enc,
        ciphertext,
    })
}

/// Opens `wrapped` for `context_id` and runs the §7.3.2.1 derive-and-compare check.
///
/// `expected_signer_public_key` is the `signer_public_key` the context
/// currently publishes, taken from the opener's own state. `dh` is `KeyCustody::dh_agree(h, wrapped.enc.as_bytes())` for the custody
/// handle `h` of the opener's wrapping key, and `recipient` is that key's
/// public half. The wrapping private key never leaves custody.
///
/// # Errors
///
/// - [`ParticipationSeedError::EmptyContextId`] for an empty `context_id`.
/// - [`ParticipationSeedError::Open`] when HPKE fails: another recipient,
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
) -> Result<OpenedParticipationSeed, ParticipationSeedError> {
    let info = seed_wrap_info(context_id)?;
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
    let signer = P256SecretKey::from_participation_seed(&seed, context_id);
    if signer.public_key() != *expected_signer_public_key {
        return Err(ParticipationSeedError::SignerKeyMismatch);
    }
    Ok(OpenedParticipationSeed { seed, signer })
}

/// `PARTICIPATION_SEED_WRAP_INFO_PREFIX || context_id`, refusing an empty
/// `context_id`.
fn seed_wrap_info(context_id: &str) -> Result<Vec<u8>, ParticipationSeedError> {
    if context_id.is_empty() {
        return Err(ParticipationSeedError::EmptyContextId);
    }
    Ok([PARTICIPATION_SEED_WRAP_INFO_PREFIX, context_id.as_bytes()].concat())
}

#[cfg(test)]
mod tests {
    use scp_crypto::p256::ecdh_p256;

    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    const CONTEXT: &str = "context-alpha";
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
        ) -> Result<OpenedParticipationSeed, ParticipationSeedError> {
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

    #[test]
    fn seed_wrap_round_trips() -> TestResult {
        let holder = Holder::new(1);
        let seed = [0x5au8; 32];
        let wrapped = seal_participation_seed(&seed, &holder.point(), CONTEXT)?;
        assert_eq!(wrapped.recipient_wrapping_key, holder.point());
        assert_eq!(wrapped.ciphertext.len(), 48);
        let opened = holder.open(&wrapped, CONTEXT, &signer_pk(&seed, CONTEXT))?;
        assert_eq!(opened.seed(), &seed);
        assert_eq!(opened.signer().public_key(), signer_pk(&seed, CONTEXT));
        Ok(())
    }

    /// A wrap made for one context does not open under another context's
    /// `info`: the AEAD fails, before any derivation. The opener expects the
    /// key the seed derives under the other context, so only the `info`
    /// binding can refuse it.
    #[test]
    fn seed_wrap_rejects_other_context() -> TestResult {
        let holder = Holder::new(1);
        let seed = [0x5au8; 32];
        let wrapped = seal_participation_seed(&seed, &holder.point(), CONTEXT)?;
        let other = "context-beta";
        let result = holder.open(&wrapped, other, &signer_pk(&seed, other));
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
    fn seed_wrap_rejects_other_recipient() -> TestResult {
        let holder = Holder::new(1);
        let other = Holder::new(2);
        let seed = [0x5au8; 32];
        let wrapped = seal_participation_seed(&seed, &holder.point(), CONTEXT)?;
        let result = other.open(&wrapped, CONTEXT, &signer_pk(&seed, CONTEXT));
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
        let seed = [0x5au8; 32];
        let expected = signer_pk(&seed, CONTEXT);
        let wrapped = seal_participation_seed(&seed, &holder.point(), CONTEXT)?;
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
        let seed: [u8; 32] = arr(VECTOR_SEED)?;
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
        assert_eq!(opened.seed(), &seed);

        let ephemeral = key(SECONDARY_SCALAR)?;
        let resealed = seal_with(&seed, &recipient, CONTEXT, |r, info, aad, pt| {
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

        let mut attacker_seed = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut attacker_seed);
        let forged = seal_participation_seed(&attacker_seed, &holder.point(), CONTEXT)?;
        let result = holder.open(&forged, CONTEXT, &published);
        assert!(
            matches!(result, Err(ParticipationSeedError::SignerKeyMismatch)),
            "{result:?}"
        );

        // Positive control: the context's own seed passes the same compare.
        let genuine = seal_participation_seed(&context_seed, &holder.point(), CONTEXT)?;
        holder.open(&genuine, CONTEXT, &published)?;
        Ok(())
    }

    #[test]
    fn empty_context_id_is_refused() -> TestResult {
        let holder = Holder::new(1);
        let seed = [0x5au8; 32];
        assert!(matches!(
            seal_participation_seed(&seed, &holder.point(), ""),
            Err(ParticipationSeedError::EmptyContextId)
        ));
        let wrapped = seal_participation_seed(&seed, &holder.point(), CONTEXT)?;
        assert!(matches!(
            holder.open(&wrapped, "", &signer_pk(&seed, CONTEXT)),
            Err(ParticipationSeedError::EmptyContextId)
        ));
        Ok(())
    }

    /// No `Debug` or `Display` output of the wrap, the opened seed, or any
    /// error contains the seed, the ciphertext, or the derived private scalar,
    /// in hex or as a byte list.
    #[test]
    fn debug_and_display_print_no_secret_bytes() -> TestResult {
        let holder = Holder::new(1);
        let seed: [u8; 32] = arr(VECTOR_SEED)?;
        let wrapped = seal_participation_seed(&seed, &holder.point(), CONTEXT)?;
        let opened = holder.open(&wrapped, CONTEXT, &signer_pk(&seed, CONTEXT))?;
        let scalar = opened.signer().to_scalar_bytes();

        let secrets: [&[u8]; 3] = [&seed, &wrapped.ciphertext, scalar.as_ref()];
        let mut outputs = vec![format!("{wrapped:?}"), format!("{opened:?}")];
        for error in [
            ParticipationSeedError::EmptyContextId,
            ParticipationSeedError::Seal(HpkeError::SealFailed("x".into())),
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
            .open(&tampered, CONTEXT, &signer_pk(&seed, CONTEXT))
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
        // The positive control: the wrap's Debug names what it may print.
        assert!(outputs[0].contains("ciphertext_len: 48"), "{}", outputs[0]);
        Ok(())
    }
}
