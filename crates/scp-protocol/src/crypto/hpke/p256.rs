//! RFC 9180 HPKE under the suite §9.5 mandates: `DHKEM(P-256, HKDF-SHA256)`,
//! `HKDF-SHA256`, `AES-128-GCM`, Base mode, single-shot.
//!
//! - KEM:  `DHKEM(P-256, HKDF-SHA256)` — suite id `0x0010`
//! - KDF:  `HKDF-SHA256`               — suite id `0x0001`
//! - AEAD: `AES-128-GCM`               — suite id `0x0001`
//!
//! The encapsulated key `enc` and every recipient public key are the 65-byte
//! uncompressed SEC1 point (RFC 9180 §7.1, `SerializePublicKey`); a private key
//! is the 32-byte big-endian scalar (`SerializePrivateKey`). The DH output is
//! the 32-byte x-coordinate of the shared point (RFC 9180 §7.1.1).
//!
//! Point validation (§9.5): every recipient key passed to [`seal`] and every
//! `enc` goes through [`P256PublicKey::from_sec1`] before any scalar
//! multiplication. That rejects a length other than 65, a leading byte other
//! than `0x04`, a point off the curve, and the point at infinity, which closes
//! the invalid-curve attack §9.5 names. [`open`] validates `enc` itself. The
//! custody path takes only a [`ValidatedEnc`], whose one constructor is
//! [`validate_enc`], so a caller holds a validated `enc` before it can ask
//! custody for `DH(skR, enc)`.
//!
//! Each [`seal`] draws a fresh ephemeral key as `DeriveKeyPair(random(Nsk))`,
//! which RFC 9180 §4 names as an implementation of `GenerateKeyPair`, so the one
//! [`derive_key_pair`] routine serves both the RFC 9180 A.3 known-answer tests
//! and production. The HPKE context performs exactly one `Seal` at sequence
//! number 0; nothing here exports secrets or supplies an external nonce.

use rand::RngCore;
use rand::rngs::OsRng;
use scp_crypto::p256::{P256PublicKey, P256SigningKey, ecdh_p256};
use zeroize::Zeroizing;

use super::{
    HPKE_TAG_LEN, HpkeError, KeyScheduleOutput, aead_open, aead_seal, dhkem_extract_and_expand,
    hpke_suite_id_for, kem_suite_id_for, key_schedule_base, labeled_expand, labeled_extract,
};

/// KEM id for `DHKEM(P-256, HKDF-SHA256)` — RFC 9180 §7.1.
pub const KEM_ID: u16 = 0x0010;

/// KDF id for `HKDF-SHA256` — RFC 9180 §7.2.
pub const KDF_ID: u16 = 0x0001;

/// AEAD id for `AES-128-GCM` — RFC 9180 §7.3.
pub const AEAD_ID: u16 = 0x0001;

/// Length of the encapsulated key `enc` (`Nenc`), bytes: an uncompressed SEC1
/// point.
pub const ENC_LEN: usize = 65;

/// Length of a serialized public key (`Npk`), bytes: an uncompressed SEC1
/// point.
pub const PUBLIC_KEY_LEN: usize = 65;

/// Length of a serialized private key (`Nsk`), bytes: a big-endian scalar.
pub const PRIVATE_KEY_LEN: usize = 32;

/// AEAD tag length: `ct.len() == pt.len() + TAG_LEN`.
pub const TAG_LEN: usize = HPKE_TAG_LEN;

/// `"KEM" || I2OSP(0x0010, 2)` (RFC 9180 §4.1).
const KEM_SUITE_ID: [u8; 5] = kem_suite_id_for(KEM_ID);

/// `"HPKE" || I2OSP(0x0010, 2) || I2OSP(0x0001, 2) || I2OSP(0x0001, 2)`
/// (RFC 9180 §5.1).
const HPKE_SUITE_ID: [u8; 10] = hpke_suite_id_for(KEM_ID, KDF_ID, AEAD_ID);

/// RFC 9180 §7.1.3 `DeriveKeyPair(ikm)` for DHKEM(P-256, HKDF-SHA256):
///
/// ```text
/// dkp_prk = LabeledExtract("", "dkp_prk", ikm)
/// for counter in 0..=255:
///     bytes = LabeledExpand(dkp_prk, "candidate", I2OSP(counter, 1), 32)
///     bytes[0] &= 0xff
///     sk = OS2IP(bytes); if 0 < sk < n: return sk
/// ```
///
/// The P-256 bitmask is `0xff`, so the masking step leaves `bytes` unchanged
/// and is not written out. The labels use the KEM suite id.
///
/// # Errors
///
/// [`HpkeError::InvalidKey`] when `ikm` is shorter than `Nsk` (32 bytes), or
/// when all 256 candidates fall outside `[1, n − 1]` (probability about
/// 2^-8192). RFC 9180 §7.1.3 says `ikm` SHOULD be at least `Nsk` bytes; SCP
/// rejects a shorter one.
pub fn derive_key_pair(ikm: &[u8]) -> Result<P256SigningKey, HpkeError> {
    if ikm.len() < PRIVATE_KEY_LEN {
        return Err(HpkeError::InvalidKey(format!(
            "DeriveKeyPair ikm must be at least {PRIVATE_KEY_LEN} bytes, got {}",
            ikm.len()
        )));
    }
    let dkp_prk = labeled_extract(b"", &KEM_SUITE_ID, b"dkp_prk", ikm);
    select_candidate(|counter, candidate| expand_candidate(&dkp_prk, counter, candidate))
}

/// One `DeriveKeyPair` expansion (RFC 9180 §7.1.3):
/// `LabeledExpand(dkp_prk, "candidate", I2OSP(counter, 1), Nsk)`.
fn expand_candidate(
    dkp_prk: &[u8; 32],
    counter: u8,
    out: &mut [u8; PRIVATE_KEY_LEN],
) -> Result<(), HpkeError> {
    labeled_expand(dkp_prk, &KEM_SUITE_ID, b"candidate", &[counter], out)
}

/// The `DeriveKeyPair` rejection loop: for `counter` in `0..=255`, `expand`
/// writes the candidate for that counter, and the first candidate in
/// `[1, n − 1]` becomes the key.
///
/// Private, so the only production `expand` is the `LabeledExpand` in
/// [`derive_key_pair`]; the tests pass fixed candidates to reach the
/// rejection branch, which the real expansion reaches with probability
/// about 2^-32.
fn select_candidate(
    mut expand: impl FnMut(u8, &mut [u8; PRIVATE_KEY_LEN]) -> Result<(), HpkeError>,
) -> Result<P256SigningKey, HpkeError> {
    for counter in 0..=u8::MAX {
        let mut candidate = Zeroizing::new([0u8; PRIVATE_KEY_LEN]);
        expand(counter, &mut candidate)?;
        if let Ok(sk) = P256SigningKey::from_scalar_bytes(&candidate) {
            return Ok(sk);
        }
    }
    Err(HpkeError::InvalidKey(
        "DeriveKeyPair found no valid P-256 scalar in 256 candidates".to_owned(),
    ))
}

/// Single-shot Base-mode HPKE seal to a P-256 recipient.
///
/// Validates `recipient_pk` (§9.5 point validation), draws a fresh ephemeral
/// key, performs DHKEM Encap, runs `KeySchedule_base`, and AEAD-seals `pt` at
/// sequence 0.
///
/// Returns `(enc, ct)`: `enc` is the 65-byte uncompressed ephemeral public key
/// and `ct` is `ciphertext || tag` (`pt.len() + 16` bytes).
///
/// # Errors
///
/// [`HpkeError::InvalidKey`] if `recipient_pk` is not a valid uncompressed
/// P-256 point; [`HpkeError::SealFailed`] if KDF or AEAD encryption fails
/// (operationally unreachable with valid inputs).
pub fn seal(
    recipient_pk: &[u8; PUBLIC_KEY_LEN],
    info: &[u8],
    aad: &[u8],
    pt: &[u8],
) -> Result<([u8; ENC_LEN], Vec<u8>), HpkeError> {
    let mut ikm = Zeroizing::new([0u8; PRIVATE_KEY_LEN]);
    OsRng.fill_bytes(ikm.as_mut());
    let ephemeral = derive_key_pair(ikm.as_ref())?;
    seal_with_ephemeral(&ephemeral, recipient_pk, info, aad, pt)
}

/// Single-shot Base-mode HPKE open with a **software-held** recipient scalar.
///
/// `pkRm` is derived from `recipient_sk`. `enc` is taken as a slice because it
/// arrives from the wire; its length and point are validated here. For
/// custody-held keys use [`custody::open_with_external_dh`].
///
/// # Errors
///
/// [`HpkeError::InvalidKey`] if `recipient_sk` is zero or not below the group
/// order, or if `enc` is not 65 bytes, is not led by `0x04`, or is not on the
/// curve; [`HpkeError::OpenFailed`] if AEAD verification fails (wrong key,
/// wrong `info`/`aad`, tampered `enc`/`ct`).
pub fn open(
    recipient_sk: &[u8; PRIVATE_KEY_LEN],
    enc: &[u8],
    info: &[u8],
    aad: &[u8],
    ct: &[u8],
) -> Result<Vec<u8>, HpkeError> {
    let enc = validate_enc(enc)?;
    let sk = P256SigningKey::from_scalar_bytes(recipient_sk)
        .map_err(|e| HpkeError::InvalidKey(format!("recipient scalar: {e}")))?;
    let pk_rm = sk.public_key().to_uncompressed();
    let dh = ecdh_p256(&sk, enc.point());
    decap_and_open(&dh, &pk_rm, enc.as_bytes(), info, aad, ct)
}

/// A P-256 HPKE encapsulated key that has passed §9.5 point validation:
/// exactly 65 bytes, led by `0x04`, on the curve, and not the point at
/// infinity.
///
/// [`validate_enc`] is the only constructor. [`custody::open_with_external_dh`]
/// takes this type rather than bytes, so the order §9.5 requires (validate,
/// then agree) is fixed by the types: the caller validates the wire `enc`,
/// passes [`ValidatedEnc::as_bytes`] to `KeyCustody::dh_agree`, and passes the
/// same value to the open.
///
/// Raw bytes do not satisfy the custody open:
///
/// ```compile_fail
/// use scp_protocol::crypto::hpke::p256::custody::open_with_external_dh;
/// let enc = [0x04u8; 65];
/// let _ = open_with_external_dh(&[0u8; 32], &[0x04u8; 65], &enc[..], b"", b"", b"");
/// ```
///
/// A [`ValidatedEnc`] does:
///
/// ```no_run
/// use scp_protocol::crypto::hpke::p256::{custody::open_with_external_dh, validate_enc};
/// # fn f(wire_enc: &[u8], dh: &[u8; 32], pk_rm: &[u8; 65]) -> Result<(), Box<dyn std::error::Error>> {
/// let enc = validate_enc(wire_enc)?;
/// let _ = open_with_external_dh(dh, pk_rm, &enc, b"", b"", b"");
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ValidatedEnc {
    bytes: [u8; ENC_LEN],
    point: P256PublicKey,
}

impl ValidatedEnc {
    /// The 65-byte uncompressed SEC1 encoding: the bytes to pass to
    /// `KeyCustody::dh_agree` and the `enc` bound into `kem_context`.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; ENC_LEN] {
        &self.bytes
    }

    /// The validated point.
    #[must_use]
    pub const fn point(&self) -> &P256PublicKey {
        &self.point
    }
}

/// §9.5 point validation of a wire-read `enc`.
///
/// # Errors
///
/// [`HpkeError::InvalidKey`] if `enc` is not 65 bytes, is not led by `0x04`,
/// is not on the curve, or is the point at infinity.
pub fn validate_enc(enc: &[u8]) -> Result<ValidatedEnc, HpkeError> {
    let bytes: [u8; ENC_LEN] = enc.try_into().map_err(|_| {
        HpkeError::InvalidKey(format!(
            "P-256 HPKE enc must be {ENC_LEN} bytes, got {}",
            enc.len()
        ))
    })?;
    let point = P256PublicKey::from_sec1(&bytes)
        .map_err(|e| HpkeError::InvalidKey(format!("P-256 HPKE enc: {e}")))?;
    Ok(ValidatedEnc { bytes, point })
}

/// HPKE open paths for P-256 recipient keys held inside a `KeyCustody`
/// boundary.
pub mod custody {
    use super::{HpkeError, PUBLIC_KEY_LEN, ValidatedEnc, decap_and_open};

    /// Single-shot Base-mode HPKE open where `DH(skR, enc)` was computed inside
    /// a `KeyCustody` boundary.
    ///
    /// # Caller contract (load-bearing — read this)
    ///
    /// In this order, for one and the same custody key handle `h`:
    ///
    /// 1. `enc` = `validate_enc(wire_enc)?` ([`validate_enc`](super::validate_enc)). §9.5
    ///    requires this before any key agreement, and the type makes it the
    ///    only way to call this function.
    /// 2. `dh` = `KeyCustody::dh_agree(h, enc.as_bytes())`: the 32-byte
    ///    x-coordinate of `skR · enc`.
    /// 3. `recipient_pk` (`pkRm`) = the 65-byte uncompressed public key of `h`.
    ///
    /// A mismatched `dh`, `pkRm`, or `enc` fails closed as an AEAD tag
    /// mismatch, indistinguishable from a wrong-key error. `enc || pkRm` is
    /// bound into the shared secret, so a ciphertext sealed to one recipient
    /// cannot be reinterpreted as sealed to another.
    ///
    /// # Errors
    ///
    /// [`HpkeError::OpenFailed`] if AEAD verification fails.
    pub fn open_with_external_dh(
        dh: &[u8; 32],
        recipient_pk: &[u8; PUBLIC_KEY_LEN],
        enc: &ValidatedEnc,
        info: &[u8],
        aad: &[u8],
        ct: &[u8],
    ) -> Result<Vec<u8>, HpkeError> {
        decap_and_open(dh, recipient_pk, enc.as_bytes(), info, aad, ct)
    }
}

/// Encap from a given ephemeral key + `KeySchedule` + AEAD seal at sequence 0.
///
/// Private: the only production caller is [`seal`], which passes a fresh
/// random ephemeral. The known-answer tests pass the RFC 9180 A.3 `skEm`.
fn seal_with_ephemeral(
    ephemeral: &P256SigningKey,
    recipient_pk: &[u8; PUBLIC_KEY_LEN],
    info: &[u8],
    aad: &[u8],
    pt: &[u8],
) -> Result<([u8; ENC_LEN], Vec<u8>), HpkeError> {
    let recipient = P256PublicKey::from_sec1(recipient_pk)
        .map_err(|e| HpkeError::InvalidKey(format!("P-256 HPKE recipient key: {e}")))?;
    let enc = ephemeral.public_key().to_uncompressed();
    let dh = ecdh_p256(ephemeral, &recipient);
    let ks = encap_key_schedule(&dh, &enc, recipient_pk, info)?;
    let ct = aead_seal(&ks, aad, pt)?;
    Ok((enc, ct))
}

/// Decap tail: `KeySchedule` from `dh`, then AEAD open at sequence 0.
fn decap_and_open(
    dh: &[u8; 32],
    recipient_pk: &[u8; PUBLIC_KEY_LEN],
    enc: &[u8; ENC_LEN],
    info: &[u8],
    aad: &[u8],
    ct: &[u8],
) -> Result<Vec<u8>, HpkeError> {
    let ks = encap_key_schedule(dh, enc, recipient_pk, info)?;
    aead_open(&ks, aad, ct)
}

/// `kem_context = enc || pkRm`, DHKEM `ExtractAndExpand`, then
/// `KeySchedule_base`, all under the P-256 suite ids.
fn encap_key_schedule(
    dh: &[u8; 32],
    enc: &[u8; ENC_LEN],
    recipient_pk: &[u8; PUBLIC_KEY_LEN],
    info: &[u8],
) -> Result<KeyScheduleOutput, HpkeError> {
    let mut kem_context = [0u8; ENC_LEN + PUBLIC_KEY_LEN];
    kem_context[..ENC_LEN].copy_from_slice(enc);
    kem_context[ENC_LEN..].copy_from_slice(recipient_pk);
    let shared_secret = dhkem_extract_and_expand(KEM_SUITE_ID, dh, &kem_context)?;
    key_schedule_base(&HPKE_SUITE_ID, &shared_secret, info)
}

// ---------------------------------------------------------------------------
// Tests — RFC 9180 Appendix A.3.1 KAT, roundtrips, negatives
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::super::{key_schedule_context_base, key_schedule_secret_base};
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    // RFC 9180 Appendix A.3.1 — DHKEM(P-256, HKDF-SHA256), HKDF-SHA256,
    // AES-128-GCM, Base mode. Values transcribed from
    // https://www.rfc-editor.org/rfc/rfc9180#appendix-A.3.1, with the RFC's
    // line-wrapped hex joined.
    const MODE: u8 = 0;
    const A3_KEM_ID: u16 = 16;
    const A3_KDF_ID: u16 = 1;
    const A3_AEAD_ID: u16 = 1;
    const INFO: &str = "4f6465206f6e2061204772656369616e2055726e";
    const IKM_E: &str = "4270e54ffd08d79d5928020af4686d8f6b7d35dbe470265f1f5aa22816ce860e";
    const PK_EM: &str = "04a92719c6195d5085104f469a8b9814d5838ff72b60501e2c4466e5e67b32\
                         5ac98536d7b61a1af4b78e5b7f951c0900be863c403ce65c9bfcb9382657222d18c4";
    const SK_EM: &str = "4995788ef4b9d6132b249ce59a77281493eb39af373d236a1fe415cb0c2d7beb";
    const IKM_R: &str = "668b37171f1072f3cf12ea8a236a45df23fc13b82af3609ad1e354f6ef817550";
    const PK_RM: &str = "04fe8c19ce0905191ebc298a9245792531f26f0cece2460639e8bc39cb7f70\
                         6a826a779b4cf969b8a0e539c7f62fb3d30ad6aa8f80e30f1d128aafd68a2ce72ea0";
    const SK_RM: &str = "f3ce7fdae57e1a310d87f1ebbde6f328be0a99cdbcadf4d6589cf29de4b8ffd2";
    const ENC: &str = "04a92719c6195d5085104f469a8b9814d5838ff72b60501e2c4466e5e67b325\
                       ac98536d7b61a1af4b78e5b7f951c0900be863c403ce65c9bfcb9382657222d18c4";
    const SHARED_SECRET: &str = "c0d26aeab536609a572b07695d933b589dcf363ff9d93c93adea537aeabb8cb8";
    const KEY_SCHEDULE_CONTEXT: &str = "00b88d4e6d91759e65e87c470e8b9141113e9ad5f0c8ce\
                                        efc1e088c82e6980500798e486f9c9c09c9b5c753ac72d6005de254c607d1b534ed1\
                                        1d493ae1c1d9ac85";
    const SECRET: &str = "2eb7b6bf138f6b5aff857414a058a3f1750054a9ba1f72c2cf0684a6f20b10e1";
    const KEY: &str = "868c066ef58aae6dc589b6cfdd18f97e";
    const BASE_NONCE: &str = "4e0bc5018beba4bf004cca59";
    const EXPORTER_SECRET: &str =
        "14ad94af484a7ad3ef40e9f3be99ecc6fa9036df9d4920548424df127ee0d99f";

    const PT: &str = "4265617574792069732074727574682c20747275746820626561757479";

    /// A.3.1.1: `(sequence number, aad, nonce, ct)`.
    const ENCRYPTIONS: [(u64, &str, &str, &str); 6] = [
        (
            0,
            "436f756e742d30",
            "4e0bc5018beba4bf004cca59",
            "5ad590bb8baa577f8619db35a36311226a896e7342a6d836d8b7bcd2f20b6c7f\
             9076ac232e3ab2523f39513434",
        ),
        (
            1,
            "436f756e742d31",
            "4e0bc5018beba4bf004cca58",
            "fa6f037b47fc21826b610172ca9637e82d6e5801eb31cbd3748271affd4ecb06\
             646e0329cbdf3c3cd655b28e82",
        ),
        (
            2,
            "436f756e742d32",
            "4e0bc5018beba4bf004cca5b",
            "895cabfac50ce6c6eb02ffe6c048bf53b7f7be9a91fc559402cbc5b8dcaeb52b\
             2ccc93e466c28fb55fed7a7fec",
        ),
        (
            4,
            "436f756e742d34",
            "4e0bc5018beba4bf004cca5d",
            "8787491ee8df99bc99a246c4b3216d3d57ab5076e18fa27133f520703bc70ec9\
             99dd36ce042e44f0c3169a6a8f",
        ),
        (
            255,
            "436f756e742d323535",
            "4e0bc5018beba4bf004ccaa6",
            "2ad71c85bf3f45c6eca301426289854b31448bcf8a8ccb1deef3ebd87f60848a\
             a53c538c30a4dac71d619ee2cd",
        ),
        (
            256,
            "436f756e742d323536",
            "4e0bc5018beba4bf004ccb59",
            "10f179686aa2caec1758c8e554513f16472bd0a11e2a907dde0b212cbe87d74f\
             367f8ffe5e41cd3e9962a6afb2",
        ),
    ];

    /// A.3.1.2: `(exporter_context, L, exported_value)`.
    const EXPORTS: [(&str, usize, &str); 3] = [
        (
            "",
            32,
            "5e9bc3d236e1911d95e65b576a8a86d478fb827e8bdfe77b741b289890490d4d",
        ),
        (
            "00",
            32,
            "6cff87658931bda83dc857e6353efe4987a201b849658d9b047aab4cf216e796",
        ),
        (
            "54657374436f6e74657874",
            32,
            "d8f1ea7942adbba7412c6d431c62d01371ea476b823eb697e1f6e6cae1dab85a",
        ),
    ];

    fn unhex(s: &str) -> Result<Vec<u8>, hex::FromHexError> {
        hex::decode(s)
    }

    fn arr<const N: usize>(s: &str) -> Result<[u8; N], Box<dyn std::error::Error>> {
        unhex(s)?
            .try_into()
            .map_err(|v: Vec<u8>| format!("expected {N} bytes, got {}", v.len()).into())
    }

    /// The A.3.1 recipient key and the Encap intermediates (`dh`, `enc`).
    fn a3_encap() -> Result<(P256SigningKey, [u8; 32]), Box<dyn std::error::Error>> {
        let sk_e = derive_key_pair(&unhex(IKM_E)?)?;
        let pk_r = P256PublicKey::from_sec1(&unhex(PK_RM)?)?;
        let dh = ecdh_p256(&sk_e, &pk_r);
        Ok((sk_e, *dh))
    }

    /// RFC 9180 §5.2 `ComputeNonce(seq)`: `base_nonce XOR I2OSP(seq, Nn)`.
    fn compute_nonce(base_nonce: &[u8; 12], seq: u64) -> [u8; 12] {
        let mut nonce = *base_nonce;
        for (n, s) in nonce[4..].iter_mut().zip(seq.to_be_bytes()) {
            *n ^= s;
        }
        nonce
    }

    /// A.3.1 header: mode, `kem_id`, `kdf_id`, `aead_id` equal the suite ids
    /// this module seals under, and the suite-id byte strings follow them.
    #[test]
    fn suite_ids_match_rfc9180_a3_1() {
        assert_eq!(MODE, 0x00, "Base mode byte");
        assert_eq!(KEM_ID, A3_KEM_ID);
        assert_eq!(KDF_ID, A3_KDF_ID);
        assert_eq!(AEAD_ID, A3_AEAD_ID);
        assert_eq!(KEM_SUITE_ID, *b"KEM\x00\x10");
        assert_eq!(HPKE_SUITE_ID, *b"HPKE\x00\x10\x00\x01\x00\x01");
        assert_eq!(ENC_LEN, 65);
    }

    /// A.3.1: `DeriveKeyPair(ikmE)` yields `skEm`/`pkEm`, and
    /// `DeriveKeyPair(ikmR)` yields `skRm`/`pkRm`.
    #[test]
    fn derive_key_pair_matches_rfc9180_a3_1() -> TestResult {
        let sk_e = derive_key_pair(&unhex(IKM_E)?)?;
        assert_eq!(hex::encode(sk_e.to_scalar_bytes().as_ref()), SK_EM, "skEm");
        assert_eq!(
            hex::encode(sk_e.public_key().to_uncompressed()),
            PK_EM,
            "pkEm"
        );

        let sk_r = derive_key_pair(&unhex(IKM_R)?)?;
        assert_eq!(hex::encode(sk_r.to_scalar_bytes().as_ref()), SK_RM, "skRm");
        assert_eq!(
            hex::encode(sk_r.public_key().to_uncompressed()),
            PK_RM,
            "pkRm"
        );
        Ok(())
    }

    /// A.3.1: DHKEM `ExtractAndExpand` over `DH(skEm, pkRm)` and
    /// `enc || pkRm` reproduces `shared_secret`, and the recipient's
    /// `DH(skRm, enc)` agrees.
    #[test]
    fn shared_secret_matches_rfc9180_a3_1() -> TestResult {
        let (_, dh) = a3_encap()?;
        let mut kem_context = unhex(ENC)?;
        kem_context.extend_from_slice(&unhex(PK_RM)?);
        let ss = dhkem_extract_and_expand(KEM_SUITE_ID, &dh, &kem_context)?;
        assert_eq!(hex::encode(ss.as_ref()), SHARED_SECRET, "shared_secret");

        let sk_r = P256SigningKey::from_scalar_bytes(&arr::<32>(SK_RM)?)?;
        let enc = P256PublicKey::from_sec1(&unhex(ENC)?)?;
        assert_eq!(*ecdh_p256(&sk_r, &enc), dh, "Decap DH equals Encap DH");
        Ok(())
    }

    /// A.3.1: `KeySchedule_base` reproduces `key_schedule_context`, `secret`,
    /// `key`, `base_nonce`, and `exporter_secret`; A.3.1.2 exported values
    /// follow from `exporter_secret`.
    ///
    /// SCP never exports, so the exporter is computed here from the
    /// production context and secret with the production `LabeledExpand`
    /// (`exporter_secret = LabeledExpand(secret, "exp", ctx, Nh)`,
    /// `Export = LabeledExpand(exporter_secret, "sec", exporter_context, L)`).
    #[test]
    fn key_schedule_matches_rfc9180_a3_1() -> TestResult {
        let info = unhex(INFO)?;
        let shared_secret = arr::<32>(SHARED_SECRET)?;

        let ctx = key_schedule_context_base(&HPKE_SUITE_ID, &info);
        assert_eq!(
            hex::encode(&ctx),
            KEY_SCHEDULE_CONTEXT,
            "key_schedule_context"
        );

        let secret = key_schedule_secret_base(&HPKE_SUITE_ID, &shared_secret);
        assert_eq!(hex::encode(secret.as_ref()), SECRET, "secret");

        let ks = key_schedule_base(&HPKE_SUITE_ID, &shared_secret, &info)?;
        assert_eq!(hex::encode(ks.key.as_ref()), KEY, "key");
        assert_eq!(
            hex::encode(ks.base_nonce.as_ref()),
            BASE_NONCE,
            "base_nonce"
        );

        let mut exporter_secret = [0u8; 32];
        labeled_expand(&secret, &HPKE_SUITE_ID, b"exp", &ctx, &mut exporter_secret)?;
        assert_eq!(
            hex::encode(exporter_secret),
            EXPORTER_SECRET,
            "exporter_secret"
        );

        for (exporter_context, len, expected) in EXPORTS {
            let mut out = vec![0u8; len];
            labeled_expand(
                &exporter_secret,
                &HPKE_SUITE_ID,
                b"sec",
                &unhex(exporter_context)?,
                &mut out,
            )?;
            assert_eq!(hex::encode(&out), expected, "export {exporter_context:?}");
        }
        Ok(())
    }

    /// A.3.1: the full deterministic Encap + seal from `ikmE` reproduces `enc`
    /// and the sequence-0 ciphertext byte for byte, and `open` with `skRm`
    /// recovers `pt`.
    #[test]
    fn seal_seq0_matches_rfc9180_a3_1() -> TestResult {
        let (sk_e, _) = a3_encap()?;
        let (_, aad, _, ct_expected) = ENCRYPTIONS[0];
        let (enc, ct) = seal_with_ephemeral(
            &sk_e,
            &arr::<65>(PK_RM)?,
            &unhex(INFO)?,
            &unhex(aad)?,
            &unhex(PT)?,
        )?;
        assert_eq!(hex::encode(enc), ENC, "enc");
        assert_eq!(hex::encode(&ct), ct_expected, "seq 0 ct");

        let pt = open(&arr::<32>(SK_RM)?, &enc, &unhex(INFO)?, &unhex(aad)?, &ct)?;
        assert_eq!(hex::encode(pt), PT, "seq 0 open");
        Ok(())
    }

    /// A.3.1.1: every listed encryption. The single-shot API seals only at
    /// sequence 0, so each later sequence number runs the production AEAD
    /// over the production `key` with `ComputeNonce(seq)` in place of
    /// `base_nonce`.
    #[test]
    fn encryptions_match_rfc9180_a3_1_1() -> TestResult {
        let ks = key_schedule_base(&HPKE_SUITE_ID, &arr::<32>(SHARED_SECRET)?, &unhex(INFO)?)?;
        let pt = unhex(PT)?;
        for (seq, aad, nonce, ct_expected) in ENCRYPTIONS {
            let seq_nonce = compute_nonce(&ks.base_nonce, seq);
            assert_eq!(hex::encode(seq_nonce), nonce, "seq {seq} nonce");
            let seq_ks = KeyScheduleOutput {
                key: Zeroizing::new(*ks.key),
                base_nonce: Zeroizing::new(seq_nonce),
            };
            let ct = aead_seal(&seq_ks, &unhex(aad)?, &pt)?;
            assert_eq!(hex::encode(&ct), ct_expected, "seq {seq} ct");
            assert_eq!(aead_open(&seq_ks, &unhex(aad)?, &ct)?, pt, "seq {seq} open");
        }
        Ok(())
    }

    /// A.3.1: the custody open path, given `DH(skRm, enc)` from outside,
    /// recovers the sequence-0 plaintext.
    #[test]
    fn custody_open_recovers_rfc9180_a3_1_pt() -> TestResult {
        let (_, aad, _, ct) = ENCRYPTIONS[0];
        let sk_r = P256SigningKey::from_scalar_bytes(&arr::<32>(SK_RM)?)?;
        let enc = validate_enc(&unhex(ENC)?)?;
        let dh = ecdh_p256(&sk_r, enc.point());
        let pt = custody::open_with_external_dh(
            &dh,
            &arr::<65>(PK_RM)?,
            &enc,
            &unhex(INFO)?,
            &unhex(aad)?,
            &unhex(ct)?,
        )?;
        assert_eq!(hex::encode(pt), PT);
        Ok(())
    }

    fn fresh_recipient() -> Result<([u8; 32], [u8; 65]), HpkeError> {
        let mut ikm = [0u8; 32];
        OsRng.fill_bytes(&mut ikm);
        let sk = derive_key_pair(&ikm)?;
        Ok((*sk.to_scalar_bytes(), sk.public_key().to_uncompressed()))
    }

    /// Random round trips across plaintext lengths, through both open paths.
    #[test]
    fn seal_then_open_round_trips() -> TestResult {
        let (sk, pk) = fresh_recipient()?;
        for len in [0usize, 1, 16, 32, 64, 1000] {
            let pt = vec![0xA5u8; len];
            let (enc, ct) = seal(&pk, b"info", b"aad", &pt)?;
            assert_eq!(ct.len(), pt.len() + TAG_LEN);
            assert_eq!(open(&sk, &enc, b"info", b"aad", &ct)?, pt, "len {len}");

            let sk_key = P256SigningKey::from_scalar_bytes(&sk)?;
            let valid = validate_enc(&enc)?;
            assert_eq!(valid.as_bytes(), &enc, "ValidatedEnc keeps the wire bytes");
            let dh = ecdh_p256(&sk_key, valid.point());
            let got = custody::open_with_external_dh(&dh, &pk, &valid, b"info", b"aad", &ct)?;
            assert_eq!(got, pt, "custody len {len}");
        }
        Ok(())
    }

    /// Negative: an `enc` that is not 65 bytes is rejected as an invalid key
    /// before any DH: by `open`, and by `validate_enc`, the only way to reach
    /// the custody open. Covers the 33-byte compressed form
    /// of a valid point, a 64-byte truncation, a 66-byte extension, and
    /// empty.
    #[test]
    fn open_rejects_enc_not_65_bytes() -> TestResult {
        let (sk, pk) = fresh_recipient()?;
        let (enc, ct) = seal(&pk, b"i", b"a", b"secret")?;
        assert!(validate_enc(&enc).is_ok(), "a sealed enc must validate");
        let compressed = P256PublicKey::from_sec1(&enc)?.to_compressed();
        let mut long = enc.to_vec();
        long.push(0);
        let bad: [&[u8]; 4] = [&compressed, &enc[..64], &long, &[]];
        for enc_bad in bad {
            let len = enc_bad.len();
            assert!(
                matches!(
                    open(&sk, enc_bad, b"i", b"a", &ct),
                    Err(HpkeError::InvalidKey(_))
                ),
                "open accepted a {len}-byte enc"
            );
            assert!(
                matches!(validate_enc(enc_bad), Err(HpkeError::InvalidKey(_))),
                "validate_enc accepted a {len}-byte enc"
            );
        }
        Ok(())
    }

    /// Negative: a 65-byte `enc` led by `0x04` whose coordinates are off the
    /// curve is rejected as an invalid key before any DH: by `open`, by
    /// `validate_enc` (the only way to reach the custody open), and as a seal
    /// recipient. The off-curve point is the RFC's valid `enc`
    /// with its last `y` byte flipped, which breaks `y² = x³ − 3x + b`.
    #[test]
    fn open_rejects_enc_off_curve() -> TestResult {
        let (sk, pk) = fresh_recipient()?;
        let (_, ct) = seal(&pk, b"i", b"a", b"secret")?;

        let mut off_curve = arr::<65>(ENC)?;
        off_curve[64] ^= 0x01;
        assert!(
            P256PublicKey::from_sec1(&off_curve).is_err(),
            "test point must be off curve"
        );

        let mut bad_prefix = arr::<65>(ENC)?;
        bad_prefix[0] = 0x06;

        let all_zero_x = {
            let mut p = [0u8; 65];
            p[0] = 0x04;
            p
        };

        for bad in [off_curve, bad_prefix, all_zero_x] {
            assert!(
                matches!(
                    open(&sk, &bad, b"i", b"a", &ct),
                    Err(HpkeError::InvalidKey(_))
                ),
                "open accepted invalid enc {}",
                hex::encode(bad)
            );
            assert!(
                matches!(validate_enc(&bad), Err(HpkeError::InvalidKey(_))),
                "validate_enc accepted invalid enc {}",
                hex::encode(bad)
            );
            assert!(
                matches!(seal(&bad, b"i", b"a", b"x"), Err(HpkeError::InvalidKey(_))),
                "seal accepted invalid recipient {}",
                hex::encode(bad)
            );
        }
        Ok(())
    }

    /// Negative: a tampered `ct`, a valid `enc` from a different seal, the
    /// wrong recipient, the wrong `info`, the wrong `aad`, and the wrong `pkRm`
    /// on the custody path each fail as an AEAD open failure.
    #[test]
    fn open_fails_on_any_mismatch() -> TestResult {
        let (sk, pk) = fresh_recipient()?;
        let (enc, ct) = seal(&pk, b"info", b"aad", b"secret")?;

        let mut tampered = ct.clone();
        tampered[0] ^= 0x01;
        assert!(matches!(
            open(&sk, &enc, b"info", b"aad", &tampered),
            Err(HpkeError::OpenFailed(_))
        ));

        let (other_enc, _) = seal(&pk, b"info", b"aad", b"secret")?;
        assert!(matches!(
            open(&sk, &other_enc, b"info", b"aad", &ct),
            Err(HpkeError::OpenFailed(_))
        ));

        let (wrong_scalar, wrong_public) = fresh_recipient()?;
        assert!(matches!(
            open(&wrong_scalar, &enc, b"info", b"aad", &ct),
            Err(HpkeError::OpenFailed(_))
        ));
        assert!(matches!(
            open(&sk, &enc, b"other", b"aad", &ct),
            Err(HpkeError::OpenFailed(_))
        ));
        assert!(matches!(
            open(&sk, &enc, b"info", b"other", &ct),
            Err(HpkeError::OpenFailed(_))
        ));

        let sk_key = P256SigningKey::from_scalar_bytes(&sk)?;
        let valid = validate_enc(&enc)?;
        let dh = ecdh_p256(&sk_key, valid.point());
        assert!(matches!(
            custody::open_with_external_dh(&dh, &wrong_public, &valid, b"info", b"aad", &ct),
            Err(HpkeError::OpenFailed(_))
        ));
        Ok(())
    }

    /// The P-256 group order `n`.
    const ORDER: &str = "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551";

    /// `DeriveKeyPair`'s loop rejects a candidate equal to `n` (counter 0) and
    /// one equal to `0` (counter 1), and takes the counter-2 candidate.
    #[test]
    fn select_candidate_skips_n_and_zero() -> TestResult {
        let order = arr::<32>(ORDER)?;
        let chosen = arr::<32>(SK_RM)?;
        let mut seen = Vec::new();
        let sk = select_candidate(|counter, out| {
            seen.push(counter);
            *out = match counter {
                0 => order,
                1 => [0u8; 32],
                _ => chosen,
            };
            Ok(())
        })?;
        assert_eq!(seen, [0, 1, 2], "counters tried");
        assert_eq!(*sk.to_scalar_bytes(), chosen, "counter-2 candidate chosen");
        Ok(())
    }

    /// `expand_candidate` at counters 0, 1 and 255 equals an independent
    /// HKDF-Expand of `I2OSP(32, 2) || "HPKE-v1" || "KEM" || 0x0010 ||
    /// "candidate" || counter`, and counters 1 and 255 differ from counter 0.
    #[test]
    fn expand_candidate_binds_the_counter() -> TestResult {
        let prk = arr::<32>(SK_RM)?;
        let independent = |counter: u8| -> Result<[u8; 32], String> {
            let mut info = Vec::new();
            info.extend_from_slice(&[0x00, 0x20]);
            info.extend_from_slice(b"HPKE-v1");
            info.extend_from_slice(b"KEM\x00\x10");
            info.extend_from_slice(b"candidate");
            info.push(counter);
            let mut out = [0u8; 32];
            hkdf::Hkdf::<sha2::Sha256>::from_prk(&prk)
                .map_err(|e| e.to_string())?
                .expand(&info, &mut out)
                .map_err(|e| e.to_string())?;
            Ok(out)
        };
        let mut at = [[0u8; 32]; 3];
        for (slot, counter) in at.iter_mut().zip([0u8, 1, 255]) {
            expand_candidate(&prk, counter, slot)?;
            assert_eq!(*slot, independent(counter)?, "counter {counter}");
        }
        assert_ne!(at[1], at[0], "counter 1 differs from counter 0");
        assert_ne!(at[2], at[0], "counter 255 differs from counter 0");
        Ok(())
    }

    /// `DeriveKeyPair`'s loop tries all 256 counters, 0 through 255, before it
    /// fails with `InvalidKey`.
    #[test]
    fn select_candidate_fails_after_256_invalid_candidates() -> TestResult {
        let order = arr::<32>(ORDER)?;
        let mut seen = Vec::new();
        let result = select_candidate(|counter, out| {
            seen.push(counter);
            *out = order;
            Ok(())
        });
        assert!(matches!(result, Err(HpkeError::InvalidKey(_))));
        assert_eq!(seen, (0..=u8::MAX).collect::<Vec<_>>(), "counters tried");
        Ok(())
    }

    /// Negative: a recipient scalar of zero or of the group order is rejected,
    /// and `DeriveKeyPair` rejects `ikm` shorter than `Nsk`.
    #[test]
    fn rejects_invalid_scalars_and_short_ikm() -> TestResult {
        let (_, pk) = fresh_recipient()?;
        let (enc, ct) = seal(&pk, b"i", b"a", b"x")?;
        let order = arr::<32>(ORDER)?;
        for sk in [[0u8; 32], order] {
            assert!(matches!(
                open(&sk, &enc, b"i", b"a", &ct),
                Err(HpkeError::InvalidKey(_))
            ));
        }
        assert!(matches!(
            derive_key_pair(&[0u8; 31]),
            Err(HpkeError::InvalidKey(_))
        ));
        Ok(())
    }
}
