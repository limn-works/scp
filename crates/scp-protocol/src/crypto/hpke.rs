//! RFC 9180 HPKE — Base-mode single-shot, one suite, hand-implemented.
//!
//! This is the single, authoritative HPKE core for all SCP key-distribution
//! paths (sender keys §9.16.2, access keys §9.17.1, broadcast keys §5.14.2,
//! invitations §5.12.3.1, PSK distribution §3.7.2). It implements exactly one
//! RFC 9180 ciphersuite — the SCP suite (§9.5):
//!
//! - KEM:  `DHKEM(X25519, HKDF-SHA256)` — suite id `0x0020`
//! - KDF:  `HKDF-SHA256`               — suite id `0x0001`
//! - AEAD: `AES-128-GCM`               — suite id `0x0001`
//!
//! Only the **single-shot Base mode** is implemented: each [`seal`] generates a
//! fresh ephemeral keypair, the HPKE context performs exactly one `Seal`
//! (sequence number 0), so the AEAD nonce is always `base_nonce` (no sequence
//! counter, no `ComputeNonce` increment is ever exercised). This matches the
//! protocol: every key-distribution operation creates a fresh HPKE context.
//!
//! # Why hand-implemented
//!
//! The labeled-KDF composition layer (`LabeledExtract`/`LabeledExpand`, DHKEM
//! `ExtractAndExpand`, `KeySchedule_base`) is the precise layer that five prior
//! hand-rolled "HPKE" copies got wrong (they skipped DHKEM `ExtractAndExpand`
//! and `KeySchedule`, used a custom `info`, and put a random nonce on the
//! wire). Re-implementing it here — over the RustCrypto-family `hkdf`/`sha2`/`aes-gcm`
//! and `x25519-dalek` primitives already in this crate — keeps the wasm32
//! artifact free of extra transitive crates and makes the construction fully
//! auditable. Correctness is pinned by the RFC 9180 Appendix A.1 known-answer
//! tests (including intermediate values) and cross-validated against the
//! `hpke-rs` reference implementation as a dev-dependency oracle.
//!
//! # Custody Decap
//!
//! For recipient secret keys held inside a `KeyCustody` boundary, the raw
//! X25519 DH scalar multiplication happens in custody and only the DH output
//! crosses the boundary. [`custody::open_with_external_dh`] completes RFC 9180
//! DHKEM Decap + `KeySchedule` + AEAD open from that DH output plus the
//! recipient public key. See that function's documentation for the strict
//! caller contract.
//!
//! # Zeroization
//!
//! All secret intermediates (`dh`, `eae_prk`, `shared_secret`, `secret`,
//! `key`, `base_nonce`, and the seq-0 AEAD nonce derived from it) are wrapped
//! in [`Zeroizing`] for their full memory lifetime. `x25519-dalek`
//! `EphemeralSecret`/`SharedSecret` zeroize on drop with the in-tree `zeroize`
//! feature; each `.as_bytes()` copy is wrapped in [`Zeroizing`]. NOTE:
//! `hkdf::Hkdf<Sha256>` does not zeroize its internal PRK/HMAC state on drop —
//! a known, accepted, codebase-wide limitation of the RustCrypto-family `hkdf` crate;
//! no custom wrapper is added.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes128Gcm, Nonce};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey as X25519Pub, StaticSecret};
use zeroize::Zeroizing;

// ---------------------------------------------------------------------------
// Suite constants
// ---------------------------------------------------------------------------

/// KEM id for `DHKEM(X25519, HKDF-SHA256)` — RFC 9180 §7.1.
pub const HPKE_KEM_ID: u16 = 0x0020;

/// KDF id for `HKDF-SHA256` — RFC 9180 §7.2.
pub const HPKE_KDF_ID: u16 = 0x0001;

/// AEAD id for `AES-128-GCM` — RFC 9180 §7.3.
pub const HPKE_AEAD_ID: u16 = 0x0001;

/// Length of the X25519 encapsulated key (`enc`), bytes.
pub const HPKE_ENC_LEN: usize = 32;

/// AEAD tag length: `ct.len() == pt.len() + HPKE_TAG_LEN`.
pub const HPKE_TAG_LEN: usize = 16;

/// AEAD key length (`Nk` for AES-128-GCM), bytes.
const HPKE_AEAD_KEY_LEN: usize = 16;

/// AEAD nonce length (`Nn` for AES-128-GCM), bytes.
const HPKE_AEAD_NONCE_LEN: usize = 12;

/// DHKEM shared-secret length (`Nsecret` for DHKEM(X25519, HKDF-SHA256)), bytes.
const HPKE_NSECRET: usize = 32;

/// X25519 raw scalar/point length, bytes.
const X25519_LEN: usize = 32;

/// RFC 9180 §4 version label, prefixed to every labeled-KDF input.
const HPKE_VERSION_LABEL: &[u8] = b"HPKE-v1";

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors produced by the HPKE core.
#[derive(Debug, thiserror::Error)]
pub enum HpkeError {
    /// A key (recipient public, ephemeral, or DH output) was malformed.
    #[error("invalid HPKE key material: {0}")]
    InvalidKey(String),

    /// AEAD open failed: tag mismatch, wrong key, wrong `info`/`aad`, tampered
    /// ciphertext, or (for the custody variant) wrong `dh`/`pkRm`/`enc`.
    #[error("HPKE open failed: {0}")]
    OpenFailed(String),

    /// AEAD seal failed (operationally unreachable for AES-128-GCM with a
    /// valid key and nonce).
    #[error("HPKE seal failed: {0}")]
    SealFailed(String),
}

// ---------------------------------------------------------------------------
// Labeled KDF (RFC 9180 §4)
// ---------------------------------------------------------------------------

/// Builds the KEM `suite_id`: `"KEM" || I2OSP(kem_id, 2)` (RFC 9180 §4.1).
fn kem_suite_id() -> [u8; 5] {
    let mut id = [0u8; 5];
    id[0..3].copy_from_slice(b"KEM");
    id[3..5].copy_from_slice(&HPKE_KEM_ID.to_be_bytes());
    id
}

/// Builds the HPKE `suite_id`:
/// `"HPKE" || I2OSP(kem_id, 2) || I2OSP(kdf_id, 2) || I2OSP(aead_id, 2)`
/// (RFC 9180 §5.1).
fn hpke_suite_id() -> [u8; 10] {
    let mut id = [0u8; 10];
    id[0..4].copy_from_slice(b"HPKE");
    id[4..6].copy_from_slice(&HPKE_KEM_ID.to_be_bytes());
    id[6..8].copy_from_slice(&HPKE_KDF_ID.to_be_bytes());
    id[8..10].copy_from_slice(&HPKE_AEAD_ID.to_be_bytes());
    id
}

/// `LabeledExtract(salt, label, ikm)` (RFC 9180 §4):
/// `Extract(salt, "HPKE-v1" || suite_id || label || ikm)`.
///
/// Returns the HKDF PRK (32 bytes for HKDF-SHA256). `suite_id` is the caller's
/// (KEM vs HPKE) suite identifier.
fn labeled_extract(salt: &[u8], suite_id: &[u8], label: &[u8], ikm: &[u8]) -> Zeroizing<[u8; 32]> {
    // labeled_ikm = "HPKE-v1" || suite_id || label || ikm
    let mut labeled_ikm = Zeroizing::new(Vec::with_capacity(
        HPKE_VERSION_LABEL.len() + suite_id.len() + label.len() + ikm.len(),
    ));
    labeled_ikm.extend_from_slice(HPKE_VERSION_LABEL);
    labeled_ikm.extend_from_slice(suite_id);
    labeled_ikm.extend_from_slice(label);
    labeled_ikm.extend_from_slice(ikm);

    // HKDF-Extract(salt, IKM) = HMAC(salt, IKM); hkdf crate exposes this via
    // Hkdf::extract (salt None == all-zero salt block, which is NOT what we
    // want — RFC 9180 uses an explicit possibly-empty salt). Pass Some(salt)
    // so an empty salt is the empty byte string per HKDF (RFC 5869 §2.2).
    let (prk, _hk) = Hkdf::<Sha256>::extract(Some(salt), &labeled_ikm);
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(&prk);
    out
}

/// `LabeledExpand(prk, label, info, L)` (RFC 9180 §4):
/// `Expand(prk, I2OSP(L, 2) || "HPKE-v1" || suite_id || label || info, L)`.
///
/// Writes exactly `out.len()` bytes; `out.len()` is the RFC's `L`.
fn labeled_expand(
    prk: &[u8; 32],
    suite_id: &[u8],
    label: &[u8],
    info: &[u8],
    out: &mut [u8],
) -> Result<(), HpkeError> {
    let l = u16::try_from(out.len())
        .map_err(|_| HpkeError::SealFailed("HPKE expand length exceeds u16".to_owned()))?;

    // labeled_info = I2OSP(L, 2) || "HPKE-v1" || suite_id || label || info
    let mut labeled_info = Vec::with_capacity(
        2 + HPKE_VERSION_LABEL.len() + suite_id.len() + label.len() + info.len(),
    );
    labeled_info.extend_from_slice(&l.to_be_bytes());
    labeled_info.extend_from_slice(HPKE_VERSION_LABEL);
    labeled_info.extend_from_slice(suite_id);
    labeled_info.extend_from_slice(label);
    labeled_info.extend_from_slice(info);

    // HKDF-Expand from an existing PRK: reconstruct the HKDF state from the PRK.
    let hk = Hkdf::<Sha256>::from_prk(prk)
        .map_err(|e| HpkeError::SealFailed(format!("HKDF from_prk: {e}")))?;
    hk.expand(&labeled_info, out)
        .map_err(|e| HpkeError::SealFailed(format!("HKDF expand: {e}")))
}

// ---------------------------------------------------------------------------
// DHKEM (RFC 9180 §4.1)
// ---------------------------------------------------------------------------

/// DHKEM `ExtractAndExpand(dh, kem_context)` (RFC 9180 §4.1):
/// `eae_prk = LabeledExtract("", "eae_prk", dh)`;
/// `shared_secret = LabeledExpand(eae_prk, "shared_secret", kem_context, Nsecret)`.
///
/// Uses the **KEM** suite id. Returns the 32-byte KEM shared secret.
fn dhkem_extract_and_expand(
    dh: &[u8; X25519_LEN],
    kem_context: &[u8],
) -> Result<Zeroizing<[u8; HPKE_NSECRET]>, HpkeError> {
    let suite_id = kem_suite_id();
    let eae_prk = labeled_extract(b"", &suite_id, b"eae_prk", dh);
    let mut shared_secret = Zeroizing::new([0u8; HPKE_NSECRET]);
    labeled_expand(
        &eae_prk,
        &suite_id,
        b"shared_secret",
        kem_context,
        shared_secret.as_mut(),
    )?;
    Ok(shared_secret)
}

// ---------------------------------------------------------------------------
// KeySchedule (RFC 9180 §5.1, mode_base)
// ---------------------------------------------------------------------------

/// AEAD material derived from `KeySchedule_base`.
struct KeyScheduleOutput {
    key: Zeroizing<[u8; HPKE_AEAD_KEY_LEN]>,
    base_nonce: Zeroizing<[u8; HPKE_AEAD_NONCE_LEN]>,
}

/// RFC 9180 §5.1 `KeySchedule(mode_base, shared_secret, info, psk="", psk_id="")`.
///
/// Derives the AEAD `key` and `base_nonce`. The `mode` byte is `0x00`
/// (`mode_base`). Uses the **HPKE** suite id. The exporter secret is not derived
/// (SCP never uses HPKE export).
fn key_schedule_base(
    shared_secret: &[u8; HPKE_NSECRET],
    info: &[u8],
) -> Result<KeyScheduleOutput, HpkeError> {
    let suite_id = hpke_suite_id();

    // psk_id_hash = LabeledExtract("", "psk_id_hash", default_psk_id="")
    let psk_id_hash = labeled_extract(b"", &suite_id, b"psk_id_hash", b"");
    // info_hash = LabeledExtract("", "info_hash", info)
    let info_hash = labeled_extract(b"", &suite_id, b"info_hash", info);

    // key_schedule_context = mode || psk_id_hash || info_hash
    let mut ks_context = Vec::with_capacity(1 + psk_id_hash.len() + info_hash.len());
    ks_context.push(0x00); // mode_base
    ks_context.extend_from_slice(psk_id_hash.as_ref());
    ks_context.extend_from_slice(info_hash.as_ref());

    // secret = LabeledExtract(shared_secret, "secret", default_psk="")
    let secret = labeled_extract(shared_secret, &suite_id, b"secret", b"");

    // key = LabeledExpand(secret, "key", key_schedule_context, Nk)
    let mut key = Zeroizing::new([0u8; HPKE_AEAD_KEY_LEN]);
    labeled_expand(&secret, &suite_id, b"key", &ks_context, key.as_mut())?;

    // base_nonce = LabeledExpand(secret, "base_nonce", key_schedule_context, Nn)
    let mut base_nonce = Zeroizing::new([0u8; HPKE_AEAD_NONCE_LEN]);
    labeled_expand(
        &secret,
        &suite_id,
        b"base_nonce",
        &ks_context,
        base_nonce.as_mut(),
    )?;

    Ok(KeyScheduleOutput { key, base_nonce })
}

// ---------------------------------------------------------------------------
// AEAD (seq 0 only)
// ---------------------------------------------------------------------------

/// Seals `pt` with AES-128-GCM at sequence number 0 (`nonce == base_nonce`).
fn aead_seal(ks: &KeyScheduleOutput, aad: &[u8], pt: &[u8]) -> Result<Vec<u8>, HpkeError> {
    let cipher = Aes128Gcm::new_from_slice(ks.key.as_ref())
        .map_err(|e| HpkeError::SealFailed(format!("AES-128-GCM key: {e}")))?;
    // seq 0: nonce = base_nonce XOR 0 = base_nonce. Hold the nonce in a
    // Zeroizing copy so it is not a bare unzeroed stack value.
    let nonce_bytes: Zeroizing<[u8; HPKE_AEAD_NONCE_LEN]> = Zeroizing::new(*ks.base_nonce);
    cipher
        .encrypt(
            Nonce::from_slice(nonce_bytes.as_ref()),
            Payload { msg: pt, aad },
        )
        .map_err(|e| HpkeError::SealFailed(e.to_string()))
}

/// Opens `ct` with AES-128-GCM at sequence number 0 (`nonce == base_nonce`).
fn aead_open(ks: &KeyScheduleOutput, aad: &[u8], ct: &[u8]) -> Result<Vec<u8>, HpkeError> {
    let cipher = Aes128Gcm::new_from_slice(ks.key.as_ref())
        .map_err(|e| HpkeError::OpenFailed(format!("AES-128-GCM key: {e}")))?;
    let nonce_bytes: Zeroizing<[u8; HPKE_AEAD_NONCE_LEN]> = Zeroizing::new(*ks.base_nonce);
    cipher
        .decrypt(
            Nonce::from_slice(nonce_bytes.as_ref()),
            Payload { msg: ct, aad },
        )
        .map_err(|e| HpkeError::OpenFailed(e.to_string()))
}

// ---------------------------------------------------------------------------
// Public single-shot API
// ---------------------------------------------------------------------------

/// Single-shot Base-mode HPKE seal.
///
/// Generates a fresh ephemeral X25519 keypair, performs DHKEM Encap to the
/// recipient public key, runs `KeySchedule_base`, and AEAD-seals `pt` at
/// sequence 0.
///
/// Returns `(enc, ct)` where `enc` is the 32-byte encapsulated key (the
/// ephemeral public key) and `ct` is `ciphertext || tag` (`pt.len() + 16`
/// bytes). Every SCP wire format carries `enc` as its own field, so the tuple
/// shape requires zero reassembly at call sites.
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
/// multiplication. For custody-held secrets use
/// [`custody::open_with_external_dh`] instead.
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
/// `#[cfg(test)]` + `pub(crate)` ONLY: a deterministic ephemeral is a footgun
/// if reachable from production; it exists solely to inject the fixed RFC 9180
/// A.1 `skEm` into the known-answer tests.
#[cfg(test)]
pub(crate) fn seal_with_ephemeral(
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

// ---------------------------------------------------------------------------
// Internal seal/decap helpers
// ---------------------------------------------------------------------------

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

    let shared_secret = dhkem_extract_and_expand(dh_bytes, &kem_context)?;
    let ks = key_schedule_base(&shared_secret, info)?;
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

    let shared_secret = dhkem_extract_and_expand(dh_bytes, &kem_context)?;
    let ks = key_schedule_base(&shared_secret, info)?;
    aead_open(&ks, aad, ct)
}

// ---------------------------------------------------------------------------
// Custody Decap variant
// ---------------------------------------------------------------------------

/// HPKE open paths for recipient keys held inside a `KeyCustody` boundary.
pub mod custody {
    use super::{HPKE_ENC_LEN, HpkeError, X25519_LEN, decap_and_open};

    /// Single-shot Base-mode HPKE open where the KEM Diffie-Hellman output was
    /// computed inside a `KeyCustody` boundary.
    ///
    /// RFC 9180 DHKEM Decap is `shared_secret = ExtractAndExpand(dh, enc ||
    /// pkRm)` where `dh = DH(skR, enc)`. The scalar multiplication `DH(skR,
    /// enc)` is the only step that must touch the non-extractable recipient
    /// secret; everything after it (`ExtractAndExpand`, `KeySchedule`, AEAD open)
    /// is pure. This function takes that custody-computed `dh` plus the
    /// recipient public key `pkRm` and completes the open in software, so the
    /// wrapping private key never leaves custody.
    ///
    /// # Caller contract (load-bearing — read this)
    ///
    /// The ONLY sound inputs are, for one and the same custody key handle `h`
    /// and one and the same encapsulated key `enc`:
    ///
    /// - `dh` = `KeyCustody::dh_agree(h, enc)` — the raw X25519 DH output for
    ///   `h` against this exact `enc`.
    /// - `recipient_pk` (`pkRm`) = `KeyCustody::public_key(h)` — the X25519
    ///   public key of that same handle `h`.
    /// - `enc` — the exact encapsulated key the seal produced and the same one
    ///   passed to `dh_agree`.
    ///
    /// Same handle, same `enc`, throughout. A mismatched `dh`, `pkRm`, or `enc`
    /// fails closed (AEAD tag mismatch), but indistinguishably from a
    /// wrong-key error — there is no separate signal. Binding `enc || pkRm`
    /// into the shared secret (which the legacy hand-rolled paths did NOT do)
    /// closes the unknown-key-share gap: a ciphertext sealed to one recipient
    /// cannot be reinterpreted as sealed to another.
    ///
    /// # Errors
    ///
    /// [`HpkeError::OpenFailed`] if the KDF or AEAD verification fails (wrong
    /// `dh`/`pkRm`/`enc`/`info`/`aad`, or tampered `ct`).
    pub fn open_with_external_dh(
        dh: &[u8; X25519_LEN],
        recipient_pk: &[u8; 32],
        enc: &[u8; HPKE_ENC_LEN],
        info: &[u8],
        aad: &[u8],
        ct: &[u8],
    ) -> Result<Vec<u8>, HpkeError> {
        decap_and_open(dh, recipient_pk, enc, info, aad, ct)
    }
}

// ---------------------------------------------------------------------------
// Tests — RFC 9180 Appendix A.1 KATs + roundtrips + negatives
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

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

    fn unhex(s: &str) -> Vec<u8> {
        hex::decode(s).unwrap()
    }

    fn arr32(s: &str) -> [u8; 32] {
        unhex(s).try_into().unwrap()
    }

    /// A.1: `enc` / `pkEm` derived from the fixed `skEm` matches the RFC.
    #[test]
    fn a1_enc_matches() {
        let sk = arr32(A1_SKEM);
        let static_sk = StaticSecret::from(sk);
        let enc = X25519Pub::from(&static_sk);
        assert_eq!(
            hex::encode(enc.to_bytes()),
            A1_PKEM,
            "A.1 enc/pkEm mismatch"
        );
    }

    /// A.1: DHKEM `ExtractAndExpand` reproduces the RFC `shared_secret`.
    #[test]
    fn a1_shared_secret_matches() {
        // dh = DH(skEm, pkRm)
        let static_sk = StaticSecret::from(arr32(A1_SKEM));
        let pk_rm = X25519Pub::from(arr32(A1_PKRM));
        let dh = static_sk.diffie_hellman(&pk_rm);

        // kem_context = enc || pkRm
        let mut kem_context = Vec::new();
        kem_context.extend_from_slice(&unhex(A1_PKEM));
        kem_context.extend_from_slice(&unhex(A1_PKRM));

        let ss = dhkem_extract_and_expand(dh.as_bytes(), &kem_context).unwrap();
        assert_eq!(
            hex::encode(ss.as_ref()),
            A1_SHARED_SECRET,
            "A.1 shared_secret mismatch"
        );
    }

    /// A.1: `KeySchedule_base` reproduces the RFC `key` and `base_nonce`.
    #[test]
    fn a1_key_schedule_matches() {
        let shared_secret: [u8; HPKE_NSECRET] = unhex(A1_SHARED_SECRET).try_into().unwrap();
        let info = unhex(A1_INFO);
        let ks = key_schedule_base(&shared_secret, &info).unwrap();
        assert_eq!(hex::encode(ks.key.as_ref()), A1_KEY, "A.1 key mismatch");
        assert_eq!(
            hex::encode(ks.base_nonce.as_ref()),
            A1_BASE_NONCE,
            "A.1 base_nonce mismatch"
        );
    }

    /// A.1: full deterministic seal (fixed `skEm`) reproduces `enc` and the
    /// seq-0 ciphertext byte-for-byte.
    #[test]
    fn a1_seal_seq0_matches() {
        let info = unhex(A1_INFO);
        let aad = unhex(A1_AAD);
        let pt = unhex(A1_PT);
        let pk_rm = arr32(A1_PKRM);

        let (enc, ct) = seal_with_ephemeral(arr32(A1_SKEM), &pk_rm, &info, &aad, &pt).unwrap();
        assert_eq!(hex::encode(enc), A1_PKEM, "A.1 seal enc mismatch");
        assert_eq!(hex::encode(&ct), A1_CT, "A.1 seal ct mismatch");
    }

    /// A.1: software `open` recovers the plaintext from the RFC vector.
    #[test]
    fn a1_open_recovers_pt() {
        let info = unhex(A1_INFO);
        let aad = unhex(A1_AAD);
        let enc = arr32(A1_PKEM);
        let ct = unhex(A1_CT);
        let sk_rm = arr32(A1_SKRM);

        let pt = open(&sk_rm, &enc, &info, &aad, &ct).unwrap();
        assert_eq!(hex::encode(&pt), A1_PT, "A.1 open plaintext mismatch");
    }

    /// A.1: custody-path open (external DH = `DH(skRm, enc)`) recovers the
    /// plaintext from the same RFC vector.
    #[test]
    fn a1_custody_open_recovers_pt() {
        let info = unhex(A1_INFO);
        let aad = unhex(A1_AAD);
        let enc = arr32(A1_PKEM);
        let ct = unhex(A1_CT);
        let pk_rm = arr32(A1_PKRM);

        // Simulate KeyCustody::dh_agree(handle, enc) = DH(skRm, enc).
        let sk_rm = StaticSecret::from(arr32(A1_SKRM));
        let enc_pub = X25519Pub::from(enc);
        let dh = sk_rm.diffie_hellman(&enc_pub);

        let pt =
            custody::open_with_external_dh(dh.as_bytes(), &pk_rm, &enc, &info, &aad, &ct).unwrap();
        assert_eq!(
            hex::encode(&pt),
            A1_PT,
            "A.1 custody open plaintext mismatch"
        );
    }

    /// Randomized roundtrip: software seal → software open.
    #[test]
    fn roundtrip_seal_open() {
        let sk = StaticSecret::random_from_rng(OsRng);
        let pk = X25519Pub::from(&sk);

        for len in [0usize, 1, 16, 32, 64, 1000] {
            let pt = vec![0xA5u8; len];
            let info = b"scp-test-info";
            let aad = b"scp-test-aad";
            let (enc, ct) = seal(&pk.to_bytes(), info, aad, &pt).unwrap();
            assert_eq!(ct.len(), pt.len() + HPKE_TAG_LEN);
            let got = open(&sk.to_bytes(), &enc, info, aad, &ct).unwrap();
            assert_eq!(got, pt, "roundtrip len {len}");
        }
    }

    /// Randomized roundtrip: software seal → custody-path open.
    #[test]
    fn roundtrip_seal_custody_open() {
        let sk = StaticSecret::random_from_rng(OsRng);
        let pk = X25519Pub::from(&sk);
        let pt = b"the quick brown fox jumps over the lazy dog";
        let info = b"info";
        let aad = b"aad";

        let (enc, ct) = seal(&pk.to_bytes(), info, aad, pt).unwrap();

        let enc_pub = X25519Pub::from(enc);
        let dh = sk.diffie_hellman(&enc_pub);
        let got =
            custody::open_with_external_dh(dh.as_bytes(), &pk.to_bytes(), &enc, info, aad, &ct)
                .unwrap();
        assert_eq!(got.as_slice(), pt);
    }

    /// Negative: tampered ciphertext fails.
    #[test]
    fn tampered_ct_fails() {
        let sk = StaticSecret::random_from_rng(OsRng);
        let pk = X25519Pub::from(&sk);
        let (enc, mut ct) = seal(&pk.to_bytes(), b"i", b"a", b"secret").unwrap();
        ct[0] ^= 0x01;
        assert!(open(&sk.to_bytes(), &enc, b"i", b"a", &ct).is_err());
    }

    /// Negative: tampered `enc` fails.
    #[test]
    fn tampered_enc_fails() {
        let sk = StaticSecret::random_from_rng(OsRng);
        let pk = X25519Pub::from(&sk);
        let (mut enc, ct) = seal(&pk.to_bytes(), b"i", b"a", b"secret").unwrap();
        enc[0] ^= 0x01;
        assert!(open(&sk.to_bytes(), &enc, b"i", b"a", &ct).is_err());
    }

    /// Negative: wrong recipient key fails.
    #[test]
    fn wrong_recipient_fails() {
        let sk = StaticSecret::random_from_rng(OsRng);
        let pk = X25519Pub::from(&sk);
        let wrong = StaticSecret::random_from_rng(OsRng);
        let (enc, ct) = seal(&pk.to_bytes(), b"i", b"a", b"secret").unwrap();
        assert!(open(&wrong.to_bytes(), &enc, b"i", b"a", &ct).is_err());
    }

    /// Negative: wrong `info` (domain separation) fails.
    #[test]
    fn wrong_info_fails() {
        let sk = StaticSecret::random_from_rng(OsRng);
        let pk = X25519Pub::from(&sk);
        let (enc, ct) = seal(&pk.to_bytes(), b"info-a", b"a", b"secret").unwrap();
        assert!(open(&sk.to_bytes(), &enc, b"info-b", b"a", &ct).is_err());
    }

    /// Negative: wrong `aad` fails.
    #[test]
    fn wrong_aad_fails() {
        let sk = StaticSecret::random_from_rng(OsRng);
        let pk = X25519Pub::from(&sk);
        let (enc, ct) = seal(&pk.to_bytes(), b"i", b"aad-a", b"secret").unwrap();
        assert!(open(&sk.to_bytes(), &enc, b"i", b"aad-b", &ct).is_err());
    }

    /// Negative: custody open with the wrong `pkRm` (right `dh`) fails — the
    /// `kem_context` binding catches the mismatch.
    #[test]
    fn custody_wrong_pkrm_fails() {
        let sk = StaticSecret::random_from_rng(OsRng);
        let pk = X25519Pub::from(&sk);
        let (enc, ct) = seal(&pk.to_bytes(), b"i", b"a", b"secret").unwrap();

        let enc_pub = X25519Pub::from(enc);
        let dh = sk.diffie_hellman(&enc_pub);

        let wrong_pk = X25519Pub::from(&StaticSecret::random_from_rng(OsRng));
        assert!(
            custody::open_with_external_dh(
                dh.as_bytes(),
                &wrong_pk.to_bytes(),
                &enc,
                b"i",
                b"a",
                &ct
            )
            .is_err()
        );
    }
}
