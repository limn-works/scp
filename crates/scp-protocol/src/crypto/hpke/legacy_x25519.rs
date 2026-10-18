//! RFC 9180 `DHKEM(X25519, HKDF-SHA256)` (KEM `0x0020`), `HKDF-SHA256`,
//! `AES-128-GCM`, Base mode, with a 32-byte `enc`.
//!
//! §9.5 mandates the P-256 suite in [`super::p256`]. This module is crate
//! private and stays only for two callers:
//!
//! - PSK recovery (§3.7.2), which wraps a PSK to a device's X25519 key while
//!   identity keys are still Ed25519. It reaches this suite only through
//!   the PSK wrapping function at the root of [`super`].
//! - The X25519 invitation seal in [`crate::crypto::envelope_seal`], until
//!   the invitation moves to the P-256 wrapping key.
//!
//! The move of identity keys to P-256 deletes this module. It shares the
//! labeled KDF, `KeySchedule` and AEAD layers of its parent and owns only the
//! X25519 KEM steps.
//!
//! # Zeroization
//!
//! `x25519-dalek` `EphemeralSecret`/`SharedSecret` zeroize on drop with the
//! in-tree `zeroize` feature, and each `.as_bytes()` copy is wrapped in
//! [`Zeroizing`].

use rand::rngs::OsRng;
use x25519_dalek::{EphemeralSecret, PublicKey as X25519Pub, StaticSecret};
use zeroize::Zeroizing;

use super::{
    HPKE_AEAD_ID, HPKE_KDF_ID, HpkeError, aead_open, aead_seal, dhkem_extract_and_expand,
    hpke_suite_id_for, kem_suite_id_for, key_schedule_base,
};

/// KEM id for `DHKEM(X25519, HKDF-SHA256)`, RFC 9180 §7.1.
pub const HPKE_KEM_ID: u16 = 0x0020;

/// Length of the X25519 encapsulated key (`enc`), bytes.
pub const HPKE_ENC_LEN: usize = 32;

/// X25519 raw scalar/point length, bytes.
const X25519_LEN: usize = 32;

/// The X25519 suite's KEM `suite_id`.
const fn kem_suite_id() -> [u8; 5] {
    kem_suite_id_for(HPKE_KEM_ID)
}

/// The X25519 suite's HPKE `suite_id`.
const fn hpke_suite_id() -> [u8; 10] {
    hpke_suite_id_for(HPKE_KEM_ID, HPKE_KDF_ID, HPKE_AEAD_ID)
}

/// Single-shot Base-mode HPKE seal.
///
/// Generates a fresh ephemeral X25519 keypair, performs DHKEM Encap to the
/// recipient public key, runs `KeySchedule_base`, and AEAD-seals `pt` at
/// sequence 0. Each seal makes a fresh HPKE context, so the AEAD nonce is
/// always `base_nonce`.
///
/// Returns `(enc, ct)` where `enc` is the 32-byte encapsulated key (the
/// ephemeral public key) and `ct` is `ciphertext || tag` (`pt.len() + 16`
/// bytes).
///
/// # Errors
///
/// [`HpkeError::SealFailed`] if KDF or AEAD encryption fails (operationally
/// unreachable with valid inputs).
pub fn seal(
    recipient_pk: &[u8; 32],
    info: &[u8],
    aad: &[u8],
    pt: &[u8],
) -> Result<([u8; HPKE_ENC_LEN], Vec<u8>), HpkeError> {
    let ephemeral = EphemeralSecret::random_from_rng(OsRng);
    let enc = X25519Pub::from(&ephemeral);
    seal_with_ephemeral_secret(ephemeral, enc, recipient_pk, info, aad, pt)
}

/// Single-shot Base-mode HPKE open with a **software-held** recipient secret.
///
/// `pkRm` (the recipient public key needed for `kem_context = enc || pkRm`) is
/// derived internally from `recipient_sk` via the X25519 basepoint
/// multiplication.
///
/// # Errors
///
/// [`HpkeError::InvalidKey`] if `enc` is not a valid X25519 point usable for
/// DH; [`HpkeError::OpenFailed`] if KDF or AEAD verification fails (wrong key,
/// wrong `info`/`aad`, tampered `enc`/`ct`).
pub fn open(
    recipient_sk: &[u8; 32],
    enc: &[u8; HPKE_ENC_LEN],
    info: &[u8],
    aad: &[u8],
    ct: &[u8],
) -> Result<Vec<u8>, HpkeError> {
    // Recipient static secret (zeroize-on-drop) and its public key (pkRm).
    let sk_copy = Zeroizing::new(*recipient_sk);
    let sk = StaticSecret::from(*sk_copy);
    let pk_rm = X25519Pub::from(&sk);

    // DHKEM Decap: dh = DH(skR, enc).
    let enc_pub = X25519Pub::from(*enc);
    let dh = sk.diffie_hellman(&enc_pub);
    let dh_bytes = Zeroizing::new(*dh.as_bytes());

    decap_and_open(&dh_bytes, &pk_rm.to_bytes(), enc, info, aad, ct)
}

/// Deterministic seal core, exercised by the RFC 9180 A.1 KATs.
///
/// `#[cfg(test)]` ONLY: a deterministic ephemeral is a footgun if reachable
/// from production; it exists solely to inject the fixed RFC 9180 A.1 `skEm`
/// into the known-answer tests.
#[cfg(test)]
fn seal_with_ephemeral(
    eph_sk: [u8; 32],
    recipient_pk: &[u8; 32],
    info: &[u8],
    aad: &[u8],
    pt: &[u8],
) -> Result<([u8; HPKE_ENC_LEN], Vec<u8>), HpkeError> {
    // Build a StaticSecret from the fixed scalar-seed bytes. x25519-dalek
    // StaticSecret::from clamps on use; RFC 9180 A.1 skEm is already a valid
    // X25519 secret, so this reproduces enc/pkEm exactly.
    let sk_copy = Zeroizing::new(eph_sk);
    let static_sk = StaticSecret::from(*sk_copy);
    let enc = X25519Pub::from(&static_sk);
    let recipient = X25519Pub::from(*recipient_pk);
    let dh = static_sk.diffie_hellman(&recipient);
    let dh_bytes = Zeroizing::new(*dh.as_bytes());
    finish_seal(&dh_bytes, &enc.to_bytes(), recipient_pk, info, aad, pt)
}

/// Encap + `KeySchedule` + AEAD seal from an `EphemeralSecret`.
fn seal_with_ephemeral_secret(
    ephemeral: EphemeralSecret,
    enc: X25519Pub,
    recipient_pk: &[u8; 32],
    info: &[u8],
    aad: &[u8],
    pt: &[u8],
) -> Result<([u8; HPKE_ENC_LEN], Vec<u8>), HpkeError> {
    let recipient = X25519Pub::from(*recipient_pk);
    let dh = ephemeral.diffie_hellman(&recipient);
    let dh_bytes = Zeroizing::new(*dh.as_bytes());
    finish_seal(&dh_bytes, &enc.to_bytes(), recipient_pk, info, aad, pt)
}

/// Shared Encap tail: `kem_context = enc || pkR`, `ExtractAndExpand`,
/// `KeySchedule`, AEAD seal.
fn finish_seal(
    dh_bytes: &[u8; X25519_LEN],
    enc_bytes: &[u8; HPKE_ENC_LEN],
    recipient_pk: &[u8; 32],
    info: &[u8],
    aad: &[u8],
    pt: &[u8],
) -> Result<([u8; HPKE_ENC_LEN], Vec<u8>), HpkeError> {
    // kem_context = enc || pkRm
    let mut kem_context = [0u8; HPKE_ENC_LEN + 32];
    kem_context[..HPKE_ENC_LEN].copy_from_slice(enc_bytes);
    kem_context[HPKE_ENC_LEN..].copy_from_slice(recipient_pk);

    let shared_secret = dhkem_extract_and_expand(kem_suite_id(), dh_bytes, &kem_context)?;
    let ks = key_schedule_base(&hpke_suite_id(), &shared_secret, info)?;
    let ct = aead_seal(&ks, aad, pt)?;
    Ok((*enc_bytes, ct))
}

/// Shared Decap tail: `kem_context = enc || pkRm`, `ExtractAndExpand`,
/// `KeySchedule`, AEAD open. `dh_bytes` is `DH(skR, enc)`.
fn decap_and_open(
    dh_bytes: &[u8; X25519_LEN],
    recipient_pk: &[u8; 32],
    enc: &[u8; HPKE_ENC_LEN],
    info: &[u8],
    aad: &[u8],
    ct: &[u8],
) -> Result<Vec<u8>, HpkeError> {
    let mut kem_context = [0u8; HPKE_ENC_LEN + 32];
    kem_context[..HPKE_ENC_LEN].copy_from_slice(enc);
    kem_context[HPKE_ENC_LEN..].copy_from_slice(recipient_pk);

    let shared_secret = dhkem_extract_and_expand(kem_suite_id(), dh_bytes, &kem_context)?;
    let ks = key_schedule_base(&hpke_suite_id(), &shared_secret, info)?;
    aead_open(&ks, aad, ct)
}

// ---------------------------------------------------------------------------
// Tests — RFC 9180 Appendix A.1 KATs + roundtrips + negatives
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::super::{HPKE_NSECRET, HPKE_TAG_LEN};
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    // RFC 9180 Appendix A.1 — DHKEM(X25519, HKDF-SHA256), HKDF-SHA256,
    // AES-128-GCM, Base mode. Values transcribed verbatim from
    // https://www.rfc-editor.org/rfc/rfc9180#appendix-A.1
    const A1_INFO: &str = "4f6465206f6e2061204772656369616e2055726e";
    const A1_SKEM: &str = "52c4a758a802cd8b936eceea314432798d5baf2d7e9235dc084ab1b9cfa2f736";
    const A1_PKEM: &str = "37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431";
    const A1_SKRM: &str = "4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8";
    const A1_PKRM: &str = "3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d";
    const A1_SHARED_SECRET: &str =
        "fe0e18c9f024ce43799ae393c7e8fe8fce9d218875e8227b0187c04e7d2ea1fc";
    const A1_KEY: &str = "4531685d41d65f03dc48f6b8302c05b0";
    const A1_BASE_NONCE: &str = "56d890e5accaaf011cff4b7d";
    // seq 0
    const A1_PT: &str = "4265617574792069732074727574682c20747275746820626561757479";
    const A1_AAD: &str = "436f756e742d30";
    const A1_CT: &str = "f938558b5d72f1a23810b4be2ab4f84331acc02fc97babc53a52ae8218a355a96d8770ac83d07bea87e13c512a";

    fn arr32(s: &str) -> Result<[u8; 32], Box<dyn std::error::Error>> {
        hex::decode(s)?
            .try_into()
            .map_err(|_| "test vector is not 32 bytes".into())
    }

    /// A.1: `enc` / `pkEm` derived from the fixed `skEm` matches the RFC.
    #[test]
    fn a1_enc_matches() -> TestResult {
        let static_sk = StaticSecret::from(arr32(A1_SKEM)?);
        let enc = X25519Pub::from(&static_sk);
        assert_eq!(
            hex::encode(enc.to_bytes()),
            A1_PKEM,
            "A.1 enc/pkEm mismatch"
        );
        Ok(())
    }

    /// A.1: DHKEM `ExtractAndExpand` reproduces the RFC `shared_secret`.
    #[test]
    fn a1_shared_secret_matches() -> TestResult {
        // dh = DH(skEm, pkRm)
        let static_sk = StaticSecret::from(arr32(A1_SKEM)?);
        let pk_rm = X25519Pub::from(arr32(A1_PKRM)?);
        let dh = static_sk.diffie_hellman(&pk_rm);

        // kem_context = enc || pkRm
        let mut kem_context = hex::decode(A1_PKEM)?;
        kem_context.extend_from_slice(&hex::decode(A1_PKRM)?);

        let ss = dhkem_extract_and_expand(kem_suite_id(), dh.as_bytes(), &kem_context)?;
        assert_eq!(
            hex::encode(ss.as_ref()),
            A1_SHARED_SECRET,
            "A.1 shared_secret mismatch"
        );
        Ok(())
    }

    /// A.1: `KeySchedule_base` reproduces the RFC `key` and `base_nonce`.
    #[test]
    fn a1_key_schedule_matches() -> TestResult {
        let shared_secret: [u8; HPKE_NSECRET] = arr32(A1_SHARED_SECRET)?;
        let info = hex::decode(A1_INFO)?;
        let ks = key_schedule_base(&hpke_suite_id(), &shared_secret, &info)?;
        assert_eq!(hex::encode(ks.key.as_ref()), A1_KEY, "A.1 key mismatch");
        assert_eq!(
            hex::encode(ks.base_nonce.as_ref()),
            A1_BASE_NONCE,
            "A.1 base_nonce mismatch"
        );
        Ok(())
    }

    /// A.1: full deterministic seal (fixed `skEm`) reproduces `enc` and the
    /// seq-0 ciphertext byte-for-byte.
    #[test]
    fn a1_seal_seq0_matches() -> TestResult {
        let info = hex::decode(A1_INFO)?;
        let aad = hex::decode(A1_AAD)?;
        let pt = hex::decode(A1_PT)?;
        let pk_rm = arr32(A1_PKRM)?;

        let (enc, ct) = seal_with_ephemeral(arr32(A1_SKEM)?, &pk_rm, &info, &aad, &pt)?;
        assert_eq!(hex::encode(enc), A1_PKEM, "A.1 seal enc mismatch");
        assert_eq!(hex::encode(&ct), A1_CT, "A.1 seal ct mismatch");
        Ok(())
    }

    /// A.1: software `open` recovers the plaintext from the RFC vector.
    #[test]
    fn a1_open_recovers_pt() -> TestResult {
        let info = hex::decode(A1_INFO)?;
        let aad = hex::decode(A1_AAD)?;
        let ct = hex::decode(A1_CT)?;

        let pt = open(&arr32(A1_SKRM)?, &arr32(A1_PKEM)?, &info, &aad, &ct)?;
        assert_eq!(hex::encode(&pt), A1_PT, "A.1 open plaintext mismatch");
        Ok(())
    }

    /// Randomized roundtrip: software seal → software open.
    #[test]
    fn roundtrip_seal_open() -> TestResult {
        let sk = StaticSecret::random_from_rng(OsRng);
        let pk = X25519Pub::from(&sk);

        for len in [0usize, 1, 16, 32, 64, 1000] {
            let pt = vec![0xA5u8; len];
            let info = b"scp-test-info";
            let aad = b"scp-test-aad";
            let (enc, ct) = seal(&pk.to_bytes(), info, aad, &pt)?;
            assert_eq!(ct.len(), pt.len() + HPKE_TAG_LEN);
            let got = open(&sk.to_bytes(), &enc, info, aad, &ct)?;
            assert_eq!(got, pt, "roundtrip len {len}");
        }
        Ok(())
    }

    /// Negative: tampered ciphertext fails.
    #[test]
    fn tampered_ct_fails() -> TestResult {
        let sk = StaticSecret::random_from_rng(OsRng);
        let pk = X25519Pub::from(&sk);
        let (enc, mut ct) = seal(&pk.to_bytes(), b"i", b"a", b"secret")?;
        ct[0] ^= 0x01;
        assert!(open(&sk.to_bytes(), &enc, b"i", b"a", &ct).is_err());
        Ok(())
    }

    /// Negative: tampered `enc` fails.
    #[test]
    fn tampered_enc_fails() -> TestResult {
        let sk = StaticSecret::random_from_rng(OsRng);
        let pk = X25519Pub::from(&sk);
        let (mut enc, ct) = seal(&pk.to_bytes(), b"i", b"a", b"secret")?;
        enc[0] ^= 0x01;
        assert!(open(&sk.to_bytes(), &enc, b"i", b"a", &ct).is_err());
        Ok(())
    }

    /// Negative: wrong recipient key fails.
    #[test]
    fn wrong_recipient_fails() -> TestResult {
        let sk = StaticSecret::random_from_rng(OsRng);
        let pk = X25519Pub::from(&sk);
        let wrong = StaticSecret::random_from_rng(OsRng);
        let (enc, ct) = seal(&pk.to_bytes(), b"i", b"a", b"secret")?;
        assert!(open(&wrong.to_bytes(), &enc, b"i", b"a", &ct).is_err());
        Ok(())
    }

    /// Negative: wrong `info` (domain separation) fails.
    #[test]
    fn wrong_info_fails() -> TestResult {
        let sk = StaticSecret::random_from_rng(OsRng);
        let pk = X25519Pub::from(&sk);
        let (enc, ct) = seal(&pk.to_bytes(), b"info-a", b"a", b"secret")?;
        assert!(open(&sk.to_bytes(), &enc, b"info-b", b"a", &ct).is_err());
        Ok(())
    }

    /// Negative: wrong `aad` fails.
    #[test]
    fn wrong_aad_fails() -> TestResult {
        let sk = StaticSecret::random_from_rng(OsRng);
        let pk = X25519Pub::from(&sk);
        let (enc, ct) = seal(&pk.to_bytes(), b"i", b"aad-a", b"secret")?;
        assert!(open(&sk.to_bytes(), &enc, b"i", b"aad-b", &ct).is_err());
        Ok(())
    }
}

/// Cross-validation of this suite against the `hpke-rs` RFC 9180 reference
/// implementation (a dev-dependency that never ships).
///
/// Any transcription or composition error the A.1 KATs miss surfaces here as
/// an interop failure against a separate codebase. These tests live in the
/// crate because the module is crate private; the P-256 interop tests stay in
/// `tests/hpke_oracle.rs`.
#[cfg(all(test, not(target_arch = "wasm32")))]
mod hpke_rs_oracle {
    use hpke_rs::hpke_types::{AeadAlgorithm, KdfAlgorithm, KemAlgorithm};
    use hpke_rs::{Hpke, HpkePrivateKey, HpkePublicKey, Mode};
    use hpke_rs_rust_crypto::HpkeRustCrypto;

    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    /// The X25519 suite under the `hpke-rs` reference implementation:
    /// DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 / AES-128-GCM, Base mode.
    fn ref_hpke() -> Hpke<HpkeRustCrypto> {
        Hpke::<HpkeRustCrypto>::new(
            Mode::Base,
            KemAlgorithm::DhKem25519,
            KdfAlgorithm::HkdfSha256,
            AeadAlgorithm::Aes128Gcm,
        )
    }

    fn fresh_keypair() -> (StaticSecret, [u8; 32]) {
        let sk = StaticSecret::random_from_rng(OsRng);
        let pk = X25519Pub::from(&sk).to_bytes();
        (sk, pk)
    }

    /// Our `seal` → reference `open`. Run across several input shapes.
    ///
    /// Empty plaintext is intentionally NOT exercised in this direction:
    /// `hpke-rs`'s `open` rejects an empty recovered plaintext as
    /// `InvalidInput` (its `bytes_to_option` maps an empty result to `None`).
    /// That is a quirk of the reference receiver, not of our seal: the empty
    /// case is covered by the in-crate roundtrip test and by the
    /// reference→ours direction below.
    #[test]
    fn our_seal_opens_under_reference() -> TestResult {
        let cases: &[(&[u8], &[u8], &[u8])] = &[
            (b"", b"", b"x"),
            (
                b"scp-sender-key-v1",
                b"aad",
                b"32-byte-payload-padded-to-len!!!",
            ),
            (b"info", b"", &[0xAB; 100]),
            (b"\x00\x01\x02", b"\xff\xfe", b"x"),
        ];

        for (idx, (info, aad, pt)) in cases.iter().enumerate() {
            let (sk, pk) = fresh_keypair();
            let (enc, ct) = seal(&pk, info, aad, pt)?;

            let recovered = ref_hpke()
                .open(
                    &enc,
                    &HpkePrivateKey::new(sk.to_bytes().to_vec()),
                    info,
                    aad,
                    &ct,
                    None,
                    None,
                    None,
                )
                .map_err(|e| format!("case {idx}: reference open failed: {e:?}"))?;
            assert_eq!(recovered.as_slice(), *pt, "case {idx}: plaintext mismatch");
        }
        Ok(())
    }

    /// Reference `seal` → our `open`. Run across several input shapes.
    #[test]
    fn reference_seal_opens_under_ours() -> TestResult {
        let cases: &[(&[u8], &[u8], &[u8])] = &[
            (b"", b"", b""),
            (b"scp-access-key-v1", b"aad-bytes", b"the quick brown fox"),
            (b"info", b"", &[0x5A; 257]),
            (b"\x10\x20", b"\x30", b"yz"),
        ];

        for (idx, (info, aad, pt)) in cases.iter().enumerate() {
            let (sk, pk) = fresh_keypair();

            let (enc, ct) = ref_hpke()
                .seal(
                    &HpkePublicKey::new(pk.to_vec()),
                    info,
                    aad,
                    pt,
                    None,
                    None,
                    None,
                )
                .map_err(|e| format!("case {idx}: reference seal failed: {e:?}"))?;

            let enc_arr: [u8; 32] = enc
                .as_slice()
                .try_into()
                .map_err(|_| format!("case {idx}: reference enc is not 32 bytes"))?;
            let recovered = open(&sk.to_bytes(), &enc_arr, info, aad, &ct)?;
            assert_eq!(recovered.as_slice(), *pt, "case {idx}: plaintext mismatch");
        }
        Ok(())
    }
}
