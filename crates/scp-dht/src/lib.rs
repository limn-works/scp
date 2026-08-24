//! DHT transport layer for the Shared Context Protocol (SCP).
//!
//! This crate owns the BEP44 signed-mutable-item transport used for DID
//! publishing and resolution — the [`DhtClient`] trait, the [`DhtRecord`]
//! value type, the [`InMemoryDhtClient`] test/dev backend, the production
//! `PkarrDhtClient` (behind the `production-dht` feature), and the pure BEP44
//! signable/verification helpers.
//!
//! It is a native leaf crate: it has **no `scp-*` dependencies**, which
//! guarantees the `scp-identity` → `scp-dht` edge is one-way and acyclic. The
//! DID-method layer in `scp-identity` maps [`DhtError`] into its own
//! `IdentityError` via a `From` impl.
//!
//! See ADR-057 (T1c-a) and ADR-003 in `.docs/adrs/phase-1.md`.

#![forbid(unsafe_code)]

use ed25519_dalek::VerifyingKey;

mod dht_client;

pub use dht_client::{DhtClient, DhtLookup, DhtRecord, DisabledDhtClient};
// `InMemoryDhtClient` is a §17.17.3 resolve nullifier — never shippable. It is
// compiled only under the `testing` feature — the SINGLE activation path
// (ADR-062 §Decision 1 / A5; never a bare `#[cfg(test)]` disjunct), so a shipped
// production graph cannot name the type. This crate's own tests activate it via
// the `testing` dev-dependency.
#[cfg(feature = "testing")]
pub use dht_client::InMemoryDhtClient;
#[cfg(feature = "production-dht")]
pub use dht_client::{PkarrDhtClient, PkarrDhtClientBuilder};

/// Errors produced by the DHT transport layer.
///
/// This is the transport-layer error channel for [`DhtClient::publish`],
/// [`DhtClient::resolve`], and the BEP44 verification helper
/// [`verify_bep44_signature`]. `scp-identity` maps each variant into the
/// identically-named `IdentityError` variant via a `From` impl, preserving
/// the message.
#[derive(Debug, thiserror::Error)]
pub enum DhtError {
    /// Publishing a BEP44 mutable item to the DHT failed.
    #[error("DHT publish failed: {0}")]
    DhtPublishFailed(String),

    /// Resolving a BEP44 mutable item from the DHT failed.
    #[error("DHT resolve failed: {0}")]
    DhtResolveFailed(String),

    /// BEP44 signature verification failed on a resolved DHT record.
    #[error("BEP44 signature verification failed: {0}")]
    Bep44SignatureInvalid(String),

    /// The DHT layer is disabled (`DhtMode::Disabled`). Both operations are
    /// refused fail-closed: publishing discloses no address, and resolution
    /// reports that the arm reached no DHT node rather than claiming the DHT
    /// holds no record. Emitted by [`DisabledDhtClient`].
    #[error(
        "DHT layer disabled: the arm reached no DHT node (fail-closed — no address disclosed, no absence claimed)"
    )]
    Disabled,
}

/// A DHT HTTP gateway URL was malformed.
///
/// The **single** gateway-URL validation contract, shared by every gateway
/// caller — the FFI-bridge DHT client ([`crate::PkarrDhtClient`] via
/// `scp-ffi-common`'s `ClientDhtConfig::into_client`) and the node/self-host
/// pkarr builder (`scp-node`'s `build_pkarr_client`) — so both fail closed on the
/// same rule instead of diverging (one validating, the other accepting any
/// non-empty string). Each caller maps this into its own error type.
#[derive(Debug, thiserror::Error)]
#[error("invalid DHT gateway URL {url:?}: {reason}")]
pub struct GatewayUrlError {
    /// The offending URL.
    pub url: String,
    /// Why it was rejected.
    pub reason: String,
}

/// Validates a DHT gateway URL, **failing closed** on anything but a well-formed
/// `http`/`https` URL with a non-empty, control-char-free host.
///
/// This is the one validation contract shared across the FFI-bridge DHT client
/// and the node/self-host pkarr builder (see [`GatewayUrlError`]). It performs a
/// pure O(n) scan with no allocations on the happy path and has no dependency on
/// the `production-dht` feature, so both callers can validate before building.
///
/// # Errors
///
/// Returns [`GatewayUrlError`] when `url` does not start with `http://` or
/// `https://`, or its host segment is empty or contains whitespace / control
/// characters.
pub fn validate_gateway_url(url: &str) -> Result<(), GatewayUrlError> {
    let invalid = |reason: &str| GatewayUrlError {
        url: url.to_owned(),
        reason: reason.to_owned(),
    };

    let ((Some(rest), _) | (_, Some(rest))) =
        (url.strip_prefix("https://"), url.strip_prefix("http://"))
    else {
        return Err(invalid("must start with http:// or https://"));
    };

    // Host is the segment before the first '/', '?' or '#'; it must be non-empty
    // and free of whitespace/control characters. `split` always yields at least
    // one element, so `next()` is `Some`; fall back to `rest` defensively.
    let host = rest.split(['/', '?', '#']).next().unwrap_or(rest);
    if host.is_empty() || host.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(invalid("missing or malformed host"));
    }
    Ok(())
}

/// Constructs the BEP44 signable payload for a value and sequence number.
///
/// BEP44 signing payload format (without salt):
/// `"3:seqi" + seq + "e1:v" + val_len + ":" + val`
///
/// This is a standalone function usable from both the DID-method layer and
/// relay-based resolution (§3.10.2).
#[must_use]
pub fn bep44_signable(value: &[u8], seq: u64) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(b"3:seqi");
    payload.extend_from_slice(seq.to_string().as_bytes());
    payload.extend_from_slice(b"e1:v");
    payload.extend_from_slice(value.len().to_string().as_bytes());
    payload.extend_from_slice(b":");
    payload.extend_from_slice(value);
    payload
}

/// Verifies a BEP44 Ed25519 signature over the given value and sequence.
///
/// Constructs the BEP44 signable payload, then verifies the Ed25519 signature
/// against `public_key`. Used by both DHT resolution and relay-based resolution
/// (§3.10.2).
///
/// # Errors
///
/// Returns [`DhtError::Bep44SignatureInvalid`] if the signature does not verify
/// or the public key is invalid.
pub fn verify_bep44_signature(
    public_key: &[u8; 32],
    signature: &[u8; 64],
    value: &[u8],
    seq: u64,
) -> Result<(), DhtError> {
    let verifying_key = VerifyingKey::from_bytes(public_key)
        .map_err(|e| DhtError::Bep44SignatureInvalid(format!("invalid public key: {e}")))?;

    let sig = ed25519_dalek::Signature::from_bytes(signature);
    let payload = bep44_signable(value, seq);

    verifying_key
        .verify_strict(&payload, &sig)
        .map_err(|e| DhtError::Bep44SignatureInvalid(format!("signature verification failed: {e}")))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    #[test]
    fn bep44_signable_format_is_correct() {
        let value = b"test";
        let seq = 42;
        let signable = bep44_signable(value, seq);

        // Expected: "3:seqi42e1:v4:test"
        let expected = b"3:seqi42e1:v4:test";
        assert_eq!(signable, expected);
    }

    #[test]
    fn verify_bep44_signature_roundtrips() {
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let verifying_key = signing_key.verifying_key();
        let value = b"a serialized did document";
        let seq = 3u64;

        let payload = bep44_signable(value, seq);
        let signature = signing_key.sign(&payload);

        verify_bep44_signature(verifying_key.as_bytes(), &signature.to_bytes(), value, seq)
            .expect("valid BEP44 signature must verify");
    }

    #[test]
    fn verify_bep44_signature_rejects_tampered_value() {
        let signing_key = SigningKey::from_bytes(&[9u8; 32]);
        let verifying_key = signing_key.verifying_key();
        let value = b"original";
        let seq = 1u64;

        let payload = bep44_signable(value, seq);
        let signature = signing_key.sign(&payload);

        // Tamper: verify against a different value than what was signed.
        let result = verify_bep44_signature(
            verifying_key.as_bytes(),
            &signature.to_bytes(),
            b"tampered",
            seq,
        );

        assert!(matches!(result, Err(DhtError::Bep44SignatureInvalid(_))));
    }

    #[test]
    fn verify_bep44_signature_rejects_tampered_seq() {
        let signing_key = SigningKey::from_bytes(&[11u8; 32]);
        let verifying_key = signing_key.verifying_key();
        let value = b"payload";
        let seq = 5u64;

        let payload = bep44_signable(value, seq);
        let signature = signing_key.sign(&payload);

        // Tamper: verify against a different sequence number.
        let result =
            verify_bep44_signature(verifying_key.as_bytes(), &signature.to_bytes(), value, 6);

        assert!(matches!(result, Err(DhtError::Bep44SignatureInvalid(_))));
    }
}
