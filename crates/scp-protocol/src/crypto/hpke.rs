//! RFC 9180 HPKE — Base-mode single-shot, hand-implemented.
//!
//! This is the single, authoritative HPKE core for all SCP key-distribution
//! paths (sender keys §9.16.2, access keys §9.17.1, broadcast keys §5.14.2,
//! invitations §5.12.3.1, PSK distribution §3.7.2). This module root holds
//! the labeled KDF, `KeySchedule`, and AEAD layers that every suite shares.
//!
//! [`p256`] is the suite §9.5 mandates: `DHKEM(P-256, HKDF-SHA256)` (KEM
//! `0x0010`), `HKDF-SHA256` (KDF `0x0001`), `AES-128-GCM` (AEAD `0x0001`),
//! with a 65-byte uncompressed SEC1 `enc` and public key.
//!
//! It is the only suite: every caller, the invitation seal and the PSK
//! recovery wrap included, seals to a P-256 key.
//!
//! Only the **single-shot Base mode** is implemented: each seal generates a
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
//! primitives already in this crate — keeps the wasm32 artifact free of extra
//! transitive crates and makes the construction fully auditable. Correctness
//! is pinned by the RFC 9180 Appendix A.3 (P-256) known-answer tests, including intermediate values, and cross-validated
//! against the `hpke-rs` reference implementation as a dev-dependency oracle.
//!
//! # Custody Decap
//!
//! For recipient secret keys held inside a `KeyCustody` boundary, the raw DH
//! scalar multiplication happens in custody and only the DH output crosses
//! the boundary. [`p256::custody::open_with_external_dh`] completes RFC 9180
//! DHKEM Decap + `KeySchedule` + AEAD open from that DH output plus the
//! recipient public key. See that function's documentation for the strict
//! caller contract.
//!
//! # Zeroization
//!
//! All secret intermediates (`dh`, `eae_prk`, `shared_secret`, `secret`,
//! `key`, `base_nonce`, and the seq-0 AEAD nonce derived from it) are wrapped
//! in [`Zeroizing`] for their full memory lifetime. NOTE: `hkdf::Hkdf<Sha256>`
//! does not zeroize its internal PRK/HMAC state on drop — a known, accepted,
//! codebase-wide limitation of the RustCrypto-family `hkdf` crate; no custom
//! wrapper is added.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes128Gcm, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

pub mod p256;

// ---------------------------------------------------------------------------
// Suite constants
// ---------------------------------------------------------------------------

/// KDF id for `HKDF-SHA256` — RFC 9180 §7.2.
pub const HPKE_KDF_ID: u16 = 0x0001;

/// AEAD id for `AES-128-GCM` — RFC 9180 §7.3.
pub const HPKE_AEAD_ID: u16 = 0x0001;

/// AEAD tag length: `ct.len() == pt.len() + HPKE_TAG_LEN`.
pub const HPKE_TAG_LEN: usize = 16;

/// AEAD key length (`Nk` for AES-128-GCM), bytes.
const HPKE_AEAD_KEY_LEN: usize = 16;

/// AEAD nonce length (`Nn` for AES-128-GCM), bytes.
const HPKE_AEAD_NONCE_LEN: usize = 12;

/// DHKEM shared-secret length (`Nsecret`), bytes: 32 for
/// DHKEM(P-256, HKDF-SHA256).
const HPKE_NSECRET: usize = 32;

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

/// Builds a KEM `suite_id`: `"KEM" || I2OSP(kem_id, 2)` (RFC 9180 §4.1).
const fn kem_suite_id_for(kem_id: u16) -> [u8; 5] {
    let k = kem_id.to_be_bytes();
    [b'K', b'E', b'M', k[0], k[1]]
}

/// Builds an HPKE `suite_id`:
/// `"HPKE" || I2OSP(kem_id, 2) || I2OSP(kdf_id, 2) || I2OSP(aead_id, 2)`
/// (RFC 9180 §5.1).
const fn hpke_suite_id_for(kem_id: u16, kdf_id: u16, aead_id: u16) -> [u8; 10] {
    let k = kem_id.to_be_bytes();
    let f = kdf_id.to_be_bytes();
    let a = aead_id.to_be_bytes();
    [b'H', b'P', b'K', b'E', k[0], k[1], f[0], f[1], a[0], a[1]]
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
    //
    // `extract` returns the PRK by value and also keeps it inside the returned
    // `Hkdf` (as HMAC key state). The by-value copy is wiped below once it
    // sits in `Zeroizing`. Wiping the `Hkdf` copy is best effort only: `hmac`
    // 0.12 implements no `ZeroizeOnDrop`, so that state is left in memory
    // when `_hk` drops.
    let (mut prk, _hk) = Hkdf::<Sha256>::extract(Some(salt), &labeled_ikm);
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(&prk);
    prk.as_mut_slice().zeroize();
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
    // Wiping that state is best effort only: `hmac` 0.12 implements no
    // `ZeroizeOnDrop`, so the HMAC key state derived from `prk` is left in
    // memory when `hk` drops.
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
/// `kem_suite_id` is the suite's **KEM** suite id. `Nsecret` is 32 bytes for
/// DHKEM(P-256, HKDF-SHA256), and `dh` is the 32-byte P-256 x-coordinate.
fn dhkem_extract_and_expand(
    kem_suite_id: [u8; 5],
    dh: &[u8; 32],
    kem_context: &[u8],
) -> Result<Zeroizing<[u8; HPKE_NSECRET]>, HpkeError> {
    let eae_prk = labeled_extract(b"", &kem_suite_id, b"eae_prk", dh);
    let mut shared_secret = Zeroizing::new([0u8; HPKE_NSECRET]);
    labeled_expand(
        &eae_prk,
        &kem_suite_id,
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

/// `key_schedule_context = mode_base || psk_id_hash || info_hash`
/// (RFC 9180 §5.1, `psk_id = ""`). `hpke_suite_id` is the suite's **HPKE**
/// suite id.
fn key_schedule_context_base(hpke_suite_id: &[u8; 10], info: &[u8]) -> Vec<u8> {
    // psk_id_hash = LabeledExtract("", "psk_id_hash", default_psk_id="")
    let psk_id_hash = labeled_extract(b"", hpke_suite_id, b"psk_id_hash", b"");
    // info_hash = LabeledExtract("", "info_hash", info)
    let info_hash = labeled_extract(b"", hpke_suite_id, b"info_hash", info);

    let mut ks_context = Vec::with_capacity(1 + psk_id_hash.len() + info_hash.len());
    ks_context.push(0x00); // mode_base
    ks_context.extend_from_slice(psk_id_hash.as_ref());
    ks_context.extend_from_slice(info_hash.as_ref());
    ks_context
}

/// `secret = LabeledExtract(shared_secret, "secret", default_psk="")`
/// (RFC 9180 §5.1).
fn key_schedule_secret_base(
    hpke_suite_id: &[u8; 10],
    shared_secret: &[u8; HPKE_NSECRET],
) -> Zeroizing<[u8; 32]> {
    labeled_extract(shared_secret, hpke_suite_id, b"secret", b"")
}

/// RFC 9180 §5.1 `KeySchedule(mode_base, shared_secret, info, psk="", psk_id="")`.
///
/// Derives the AEAD `key` and `base_nonce`. The `mode` byte is `0x00`
/// (`mode_base`). `hpke_suite_id` is the suite's **HPKE** suite id. The
/// exporter secret is not derived (SCP never uses HPKE export).
fn key_schedule_base(
    hpke_suite_id: &[u8; 10],
    shared_secret: &[u8; HPKE_NSECRET],
    info: &[u8],
) -> Result<KeyScheduleOutput, HpkeError> {
    let ks_context = key_schedule_context_base(hpke_suite_id, info);
    let secret = key_schedule_secret_base(hpke_suite_id, shared_secret);

    // key = LabeledExpand(secret, "key", key_schedule_context, Nk)
    let mut key = Zeroizing::new([0u8; HPKE_AEAD_KEY_LEN]);
    labeled_expand(&secret, hpke_suite_id, b"key", &ks_context, key.as_mut())?;

    // base_nonce = LabeledExpand(secret, "base_nonce", key_schedule_context, Nn)
    let mut base_nonce = Zeroizing::new([0u8; HPKE_AEAD_NONCE_LEN]);
    labeled_expand(
        &secret,
        hpke_suite_id,
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
