//! Shared bridge adapter types for the UCAN validation pipeline.
//!
//! These adapters bridge `scp-core`'s validation traits to the FFI runtime.
//! All FFI bridges (`PyO3`, napi-rs, `UniFFI`) import from this crate to
//! avoid duplicating the bridge adapter implementations.

use std::collections::HashMap;

use scp_core::crypto::ucan::UcanError as CoreUcanError;
use scp_core::crypto::ucan::UcanToken;
use scp_core::crypto::ucan::validate::{
    DidResolver, NonceTracker as NonceTrackerTrait, ProofResolver, RevocationChecker,
};
use scp_identity::cache::Clock;

// ---------------------------------------------------------------------------
// BridgeDidResolver
// ---------------------------------------------------------------------------

/// Bridge [`DidResolver`] that extracts Ed25519 public keys from DID strings.
///
/// Supports:
/// - `did:dht:z{z-base-32-encoded-pubkey}` -- production format.
/// - `did:key:{hex-encoded-pubkey}` -- testing only (requires `testing` feature).
///
/// This resolver operates in-memory with no network calls. `did:dht:` DIDs
/// encode the public key directly in the DID string using z-base-32, so
/// resolution is a simple decode operation.
pub struct BridgeDidResolver;

impl DidResolver for BridgeDidResolver {
    fn resolve_public_key(&self, did: &str) -> Result<[u8; 32], CoreUcanError> {
        if let Some(suffix) = did.strip_prefix("did:dht:z") {
            let decoded = zbase32::decode(suffix).map_err(|_| {
                CoreUcanError::MalformedToken(format!("z-base-32 decode failed for DID: {did}"))
            })?;
            let bytes: [u8; 32] = decoded.try_into().map_err(|v: Vec<u8>| {
                CoreUcanError::MalformedToken(format!(
                    "DID public key must be 32 bytes, got {}",
                    v.len()
                ))
            })?;
            return Ok(bytes);
        }

        // did:key:{hex} is a non-standard test convenience. Gated behind the
        // `testing` feature (or #[cfg(test)]) to prevent acceptance in release
        // builds. See: https://github.com/limn-works/scp/issues/128
        #[cfg(any(test, feature = "testing"))]
        if let Some(hex_str) = did.strip_prefix("did:key:") {
            let bytes = hex::decode(hex_str).map_err(|e| {
                CoreUcanError::MalformedToken(format!("hex decode failed for did:key DID: {e}"))
            })?;
            let pk: [u8; 32] = bytes.try_into().map_err(|v: Vec<u8>| {
                CoreUcanError::MalformedToken(format!(
                    "DID public key must be 32 bytes, got {}",
                    v.len()
                ))
            })?;
            return Ok(pk);
        }

        Err(CoreUcanError::MalformedToken(format!(
            "unsupported DID method: {did} (expected did:dht:)"
        )))
    }
}

// ---------------------------------------------------------------------------
// BridgeRevocationChecker
// ---------------------------------------------------------------------------

/// Bridge [`RevocationChecker`] that wraps the context's [`RevocationList`].
///
/// Holds a reference to the revocation list from the [`ContextRuntime`] and
/// delegates the `is_revoked` check. This uses the content-hash CID format
/// from `scp_core::crypto::ucan::revoke::compute_revocation_cid`.
pub struct BridgeRevocationChecker<'a> {
    pub revocation_list: &'a scp_core::crypto::ucan::revoke::RevocationList,
}

impl RevocationChecker for BridgeRevocationChecker<'_> {
    fn is_revoked(&self, token_cid: &str) -> bool {
        self.revocation_list.is_revoked(token_cid)
    }
}

// ---------------------------------------------------------------------------
// BridgeProofResolver
// ---------------------------------------------------------------------------

/// Bridge [`ProofResolver`] backed by an in-memory `HashMap`.
///
/// Stores parent UCAN tokens by their CID for delegation chain traversal.
/// In the bridge layer, the caller can supply proof tokens alongside the
/// token being validated. For now this starts empty -- root tokens (no
/// delegation chain) are fully supported, and delegated tokens require the
/// proof chain to be pre-registered.
pub struct BridgeProofResolver {
    pub proofs: HashMap<String, UcanToken>,
}

impl ProofResolver for BridgeProofResolver {
    fn resolve_proof(&self, cid: &str) -> Result<UcanToken, CoreUcanError> {
        self.proofs.get(cid).cloned().ok_or_else(|| {
            CoreUcanError::DelegationChainBroken(format!("proof CID not found: {cid}"))
        })
    }
}

// ---------------------------------------------------------------------------
// BridgeNonceTracker
// ---------------------------------------------------------------------------

/// Adapter that implements the `validate::NonceTracker` trait for
/// `nonce::NonceTracker<C>`.
///
/// The `nonce::NonceTracker` struct and `validate::NonceTracker` trait have
/// the same `check_and_record` method signature but are separate types. This
/// adapter bridges the two by wrapping a mutable reference to the struct.
pub struct BridgeNonceTracker<'a, C: Clock> {
    pub inner: &'a mut scp_core::crypto::ucan::nonce::NonceTracker<C>,
}

impl<C: Clock> NonceTrackerTrait for BridgeNonceTracker<'_, C> {
    fn check_and_record(&mut self, nonce: &str, token_expiry: u64) -> Result<(), CoreUcanError> {
        self.inner.check_and_record(nonce, token_expiry)
    }
}
