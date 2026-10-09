//! Shared broadcast key-distribution value-shape helpers (spec §5.14.2).
//!
//! The pull-based broadcast key-distribution protocol has two FFI seams that
//! were byte-for-byte identical across the `PyO3`, `UniFFI`, and napi-rs
//! bridges:
//!
//! 1. **Grant → sealed JSON.** On a granted key request the bridge turns a
//!    [`KeyRequestDecision::Grant`] into a [`SealedBroadcastKey`] and
//!    serializes it to JSON. The hand-populated `author_did` / `context_id`
//!    echo is a drift hazard if each bridge open-codes it.
//! 2. **Sealed JSON → raw key.** On open the bridge deserializes the
//!    [`SealedBroadcastKey`], validates the 32-byte P-256 wrapping scalar, and calls
//!    [`open_broadcast_key`] to recover the raw broadcast key.
//!
//! 3. **Request → wrapping public key.** Before dispatching a key request the
//!    bridge parses the requester's `wrapping_pubkey` with
//!    [`parse_wrapping_pubkey`]: exactly 65 bytes, a valid uncompressed P-256
//!    point (§9.5).
//!
//! All three seams are pure value-shape logic with no per-bridge state, so they live
//! here once. Each bridge keeps its own `#[pyo3]` / `#[uniffi::export]` /
//! `#[napi]` wrapper and maps the structured errors below to its own error type
//! and code (ADR-048 §7 per-SDK idiom — only the value-shape logic is shared).
//!
//! Requires the `resolvers` feature (scp-core).

use scp_core::context::broadcast::{KeyRequestDecision, SealedBroadcastKey};
use scp_core::crypto::sender_keys::broadcast::open_broadcast_key;
use scp_protocol::crypto::hpke::p256::P256Point;

/// The exact byte length of a legitimate wrapping secret: the DHKEM(P-256)
/// scalar (§9.5).
const WRAPPING_SECRET_LEN: usize = 32;

/// The exact byte length of a wrapping public key: the uncompressed
/// DHKEM(P-256) point (§9.5).
const WRAPPING_PUBKEY_LEN: usize = 65;

/// Failure modes for [`parse_wrapping_pubkey`].
///
/// Each bridge maps both variants to its caller-input validation error.
#[derive(Debug)]
pub enum WrappingPubkeyError {
    /// The key was not exactly 65 bytes.
    InvalidLength {
        /// The actual length supplied.
        actual: usize,
    },
    /// The key was 65 bytes but not a valid uncompressed P-256 point (wrong
    /// tag, a coordinate at or above the field prime, or off the curve).
    InvalidPoint {
        /// Crypto-layer detail.
        detail: String,
    },
}

impl core::fmt::Display for WrappingPubkeyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidLength { actual } => write!(
                f,
                "wrapping_pubkey must be {WRAPPING_PUBKEY_LEN} bytes (an uncompressed P-256 \
                 point), got {actual}"
            ),
            Self::InvalidPoint { detail } => write!(
                f,
                "wrapping_pubkey is not a valid uncompressed P-256 point: {detail}"
            ),
        }
    }
}

impl std::error::Error for WrappingPubkeyError {}

/// Parses a broadcast key requester's wrapping public key (§5.14.2, §9.5).
///
/// The key must be exactly 65 bytes and a valid uncompressed P-256 point, so a
/// malformed key fails at the bridge with a validation error instead of
/// reaching the author's seal.
///
/// # Errors
///
/// Returns [`WrappingPubkeyError::InvalidLength`] for any length other than
/// 65, and [`WrappingPubkeyError::InvalidPoint`] for a 65-byte value that is
/// not a valid uncompressed P-256 point.
pub fn parse_wrapping_pubkey(bytes: &[u8]) -> Result<P256Point, WrappingPubkeyError> {
    match scp_crypto::p256::P256PublicKey::from_uncompressed(bytes) {
        Ok(point) => Ok(P256Point::from(&point)),
        Err(scp_crypto::p256::P256Error::InvalidUncompressedLength(actual)) => {
            Err(WrappingPubkeyError::InvalidLength { actual })
        }
        Err(e) => Err(WrappingPubkeyError::InvalidPoint {
            detail: e.to_string(),
        }),
    }
}

/// Builds and JSON-serializes a [`SealedBroadcastKey`] from a broadcast
/// key-request [`KeyRequestDecision`].
///
/// On [`KeyRequestDecision::Grant`], constructs the wire-serializable sealed
/// key — echoing `author_did` and `context_id` so the opener can reconstruct
/// the HPKE `info`/`aad` binding (§5.14.2) — and returns `Some(json)`. On
/// [`KeyRequestDecision::Deny`], returns `None`: per §5.14.8 a denied requester
/// receives no key material.
///
/// The raw broadcast key is never present in `decision` (the protocol layer
/// seals it inside `handle_key_request`), so no key material crosses this
/// helper either — only the already-sealed `enc`/`ct`.
///
/// # Errors
///
/// Returns [`serde_json::Error`] if serialization of the sealed key fails.
pub fn seal_decision_to_json(
    decision: KeyRequestDecision,
    author_did: &str,
    context_id: &str,
) -> Result<Option<String>, serde_json::Error> {
    match decision {
        KeyRequestDecision::Grant { enc, ct, epoch } => {
            let sealed = SealedBroadcastKey {
                enc,
                ct,
                epoch,
                author_did: author_did.to_owned(),
                context_id: context_id.to_owned(),
            };
            Ok(Some(serde_json::to_string(&sealed)?))
        }
        KeyRequestDecision::Deny { .. } => Ok(None),
    }
}

/// Failure modes for [`open_sealed_broadcast_key`].
///
/// Each bridge maps every variant to its own error type and code. The variants
/// carry enough detail for a bridge to build an actionable message without
/// re-deriving context.
#[derive(Debug)]
pub enum OpenSealedKeyError {
    /// `sealed_json` was not a valid [`SealedBroadcastKey`] JSON document.
    InvalidJson {
        /// serde-supplied parse detail.
        detail: String,
    },
    /// The wrapping secret was not exactly 32 bytes.
    InvalidSecretLength {
        /// The actual length supplied.
        actual: usize,
    },
    /// HPKE open failed (wrong secret, tampered ciphertext, binding mismatch,
    /// or a malformed sealed ciphertext length).
    OpenFailed {
        /// Crypto-layer detail.
        detail: String,
    },
}

impl core::fmt::Display for OpenSealedKeyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidJson { detail } => {
                write!(f, "invalid sealed broadcast key JSON: {detail}")
            }
            Self::InvalidSecretLength { actual } => {
                write!(f, "wrapping_secret must be 32 bytes, got {actual}")
            }
            Self::OpenFailed { detail } => write!(f, "broadcast key open failed: {detail}"),
        }
    }
}

impl std::error::Error for OpenSealedKeyError {}

/// Opens an HPKE-sealed broadcast key (§5.14.2) from its wire JSON using a
/// software-held 32-byte DHKEM(P-256) wrapping scalar, returning the raw 32-byte
/// AES-256 broadcast key bytes.
///
/// `sealed_json` is the JSON produced by [`seal_decision_to_json`] on grant;
/// `wrapping_secret` must match the `wrapping_pubkey` presented on the request.
/// Pure crypto — no bridge state.
///
/// # Errors
///
/// Returns [`OpenSealedKeyError`] if `sealed_json` is malformed, the wrapping
/// secret is not 32 bytes, or the HPKE open fails. Each bridge maps the variant
/// to its own error type/code.
pub fn open_sealed_broadcast_key(
    sealed_json: &str,
    wrapping_secret: &[u8],
) -> Result<Vec<u8>, OpenSealedKeyError> {
    let sealed: SealedBroadcastKey =
        serde_json::from_str(sealed_json).map_err(|e| OpenSealedKeyError::InvalidJson {
            detail: e.to_string(),
        })?;
    let secret = wrapping_secret_array(wrapping_secret)?;
    let key = open_broadcast_key(
        &sealed.ct,
        &sealed.enc,
        &secret,
        &sealed.context_id,
        &sealed.author_did,
        sealed.epoch,
    )
    .map_err(|e| OpenSealedKeyError::OpenFailed {
        detail: e.to_string(),
    })?;
    Ok(key.as_bytes().to_vec())
}

/// Copies the caller's wrapping scalar into a [`Zeroizing`](zeroize::Zeroizing) array, so the one
/// copy this module makes is wiped when it drops.
fn wrapping_secret_array(
    wrapping_secret: &[u8],
) -> Result<zeroize::Zeroizing<[u8; WRAPPING_SECRET_LEN]>, OpenSealedKeyError> {
    let mut secret = zeroize::Zeroizing::new([0u8; WRAPPING_SECRET_LEN]);
    if wrapping_secret.len() != WRAPPING_SECRET_LEN {
        return Err(OpenSealedKeyError::InvalidSecretLength {
            actual: wrapping_secret.len(),
        });
    }
    secret.copy_from_slice(wrapping_secret);
    Ok(secret)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use scp_core::crypto::sender_keys::broadcast::{
        generate_broadcast_key, seal_broadcast_key_to_subscriber,
    };
    use scp_core::crypto::sender_keys::generate_wrapping_keypair;

    /// Compile-time check: the copied wrapping scalar is `Zeroizing`, so a
    /// plain-array return type stops this module compiling.
    #[test]
    fn wrapping_secret_copy_is_zeroizing() {
        fn zeroizing(x: &zeroize::Zeroizing<[u8; 32]>) -> [u8; 32] {
            **x
        }
        let secret = wrapping_secret_array(&[9; 32]).unwrap();
        assert_eq!(zeroizing(&secret), [9; 32]);
        assert!(matches!(
            wrapping_secret_array(&[9; 31]),
            Err(OpenSealedKeyError::InvalidSecretLength { actual: 31 })
        ));
    }

    const CTX: &str = "ctx-broadcast-common-test";
    const AUTHOR: &str = "did:dht:z6MkBroadcastAuthorCommonTest";

    /// Builds a real granted decision by sealing a freshly generated broadcast
    /// key to a known DHKEM(P-256) keypair, so the round-trip exercises real
    /// crypto.
    fn grant_for(wrapping_pub: &P256Point, epoch: u64) -> KeyRequestDecision {
        let key = generate_broadcast_key(AUTHOR);
        let (ct, enc) =
            seal_broadcast_key_to_subscriber(key.key(), wrapping_pub, CTX, AUTHOR, epoch).unwrap();
        KeyRequestDecision::Grant { enc, ct, epoch }
    }

    /// A fresh DHKEM(P-256) wrapping keypair: the 32-byte scalar and its
    /// 65-byte uncompressed public point.
    fn wrapping_keypair() -> ([u8; 32], P256Point) {
        let (public, secret) = generate_wrapping_keypair();
        (*secret, public)
    }

    #[test]
    fn deny_serializes_to_none() {
        let decision = KeyRequestDecision::Deny {
            reason: "key request denied".to_owned(),
        };
        let out = seal_decision_to_json(decision, AUTHOR, CTX).unwrap();
        assert!(out.is_none());
    }

    #[test]
    fn grant_seals_then_opens_roundtrip() {
        let (secret, public) = wrapping_keypair();
        let decision = grant_for(&public, 3);
        let json = seal_decision_to_json(decision, AUTHOR, CTX)
            .unwrap()
            .expect("grant must serialize to Some");

        // The serialized shape must echo the binding fields and carry the
        // array-of-numbers ct/enc the cross-SDK contract relies on.
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(value["ct"].is_array());
        assert!(value["enc"].is_array());
        assert_eq!(value["author_did"], AUTHOR);
        assert_eq!(value["context_id"], CTX);

        let opened = open_sealed_broadcast_key(&json, &secret).unwrap();
        assert_eq!(opened.len(), 32);
    }

    #[test]
    fn open_rejects_malformed_json() {
        let err = open_sealed_broadcast_key("not json", &[0u8; 32]).unwrap_err();
        assert!(matches!(err, OpenSealedKeyError::InvalidJson { .. }));
    }

    #[test]
    fn open_rejects_wrong_length_secret() {
        let (_secret, public) = wrapping_keypair();
        let json = seal_decision_to_json(grant_for(&public, 0), AUTHOR, CTX)
            .unwrap()
            .unwrap();
        let err = open_sealed_broadcast_key(&json, b"short").unwrap_err();
        assert!(matches!(
            err,
            OpenSealedKeyError::InvalidSecretLength { actual: 5 }
        ));
    }

    #[test]
    fn parse_wrapping_pubkey_accepts_a_valid_point() {
        let (_secret, public) = wrapping_keypair();
        assert_eq!(parse_wrapping_pubkey(public.as_bytes()).unwrap(), public);
    }

    #[test]
    fn parse_wrapping_pubkey_rejects_32_bytes() {
        let err = parse_wrapping_pubkey(&[0x42; 32]).unwrap_err();
        assert!(matches!(
            err,
            WrappingPubkeyError::InvalidLength { actual: 32 }
        ));
        assert!(err.to_string().contains("must be 65 bytes"), "{err}");
    }

    #[test]
    fn parse_wrapping_pubkey_rejects_an_off_curve_point() {
        // The uncompressed tag with the point (0, 0), which is not on the curve.
        let mut off_curve = [0u8; 65];
        off_curve[0] = 0x04;
        assert!(matches!(
            parse_wrapping_pubkey(&off_curve).unwrap_err(),
            WrappingPubkeyError::InvalidPoint { .. }
        ));
        // A valid point under the compressed tag is rejected too.
        let (_secret, public) = wrapping_keypair();
        let mut public = *public.as_bytes();
        public[0] = 0x02;
        assert!(matches!(
            parse_wrapping_pubkey(&public).unwrap_err(),
            WrappingPubkeyError::InvalidPoint { .. }
        ));
    }

    #[test]
    fn open_rejects_wrong_secret() {
        let (_secret, public) = wrapping_keypair();
        let json = seal_decision_to_json(grant_for(&public, 0), AUTHOR, CTX)
            .unwrap()
            .unwrap();
        // A different valid P-256 scalar cannot open the sealed key.
        let (wrong, _wrong_public) = wrapping_keypair();
        let err = open_sealed_broadcast_key(&json, &wrong).unwrap_err();
        assert!(matches!(err, OpenSealedKeyError::OpenFailed { .. }));
    }
}
