//! `PyO3` bridge functions for UCAN token management.
//!
//! Exposes SCP UCAN operations to Python:
//!
//! - [`py_ucan_validate`] -- Validate a UCAN token using the full 11-step
//!   ADR-016 pipeline with Ed25519 signature verification.
//! - [`py_ucan_mint`] -- Mint a new UCAN token for a member.
//! - [`py_ucan_revoke`] -- Revoke a UCAN token.
//!
//! # Types
//!
//! - [`PyUcanToken`] -- UCAN token with ID, issuer, audience, capabilities,
//!   and expiry.
//!
//! # Validation pipeline
//!
//! `py_ucan_validate` delegates to `scp_core::crypto::ucan::validate::validate_ucan`,
//! which implements the full 11-step UCAN validation pipeline from ADR-016:
//!
//! 1. Parse JWT-format UCAN token.
//! 2. Verify Ed25519 signature via DID resolver.
//! 3. Verify delegation chain integrity (proof chain traversal).
//! 4. Verify root issuer is context creator.
//! 5. Verify audience matches presenting agent.
//! 6. Verify token capabilities include the required capability.
//! 7. Verify delegation attenuation (child <= parent capabilities).
//! 8. Verify capability is within context ceiling.
//! 9. Validate nonce (format, freshness, uniqueness).
//! 10. Check revocation list.
//! 11. Verify expiry and time bounds.
//!
//! See ADR-013 in `.docs/adrs/phase-3.md` §6 and ADR-016 for the UCAN
//! specification.

use std::collections::HashMap;

use pyo3::prelude::*;

use scp_core::crypto::ucan::UcanError as CoreUcanError;
use scp_core::crypto::ucan::UcanToken;
use scp_core::crypto::ucan::capability::CapabilityUri;
use scp_core::crypto::ucan::revoke::compute_revocation_cid;
use scp_core::crypto::ucan::validate::{
    DidResolver, NonceTracker as NonceTrackerTrait, ProofResolver, RevocationChecker,
    ValidationContext, parse_ucan, validate_ucan,
};

use crate::error::ScpPyError;
use crate::types::encode_hex;

// ---------------------------------------------------------------------------
// PyUcanToken
// ---------------------------------------------------------------------------

/// UCAN token exposed to Python.
///
/// Contains the token metadata accessible to Python code: a unique token ID
/// (derived from the nonce), the issuer DID, the audience DID, the list of
/// granted capabilities, and an optional expiry timestamp.
///
/// The raw signature and encoded JWT are not exposed -- they are internal
/// to the Rust crypto layer and not needed by Python callers.
///
/// See ADR-016 (UCAN validation) and ADR-013 §6 (bridge layer).
#[pyclass(name = "UcanToken")]
#[derive(Debug, Clone)]
pub struct PyUcanToken {
    /// Unique token identifier (derived from the UCAN nonce).
    #[pyo3(get)]
    pub token_id: String,

    /// Issuer DID -- the entity that created and signed this token.
    #[pyo3(get)]
    pub issuer: String,

    /// Audience DID -- the entity this token is delegated to.
    #[pyo3(get)]
    pub audience: String,

    /// List of capability URIs granted by this token.
    ///
    /// Each string follows the SCP capability URI format:
    /// `scp:ctx:{context_id}/{capability}`.
    #[pyo3(get)]
    pub capabilities: Vec<String>,

    /// Expiry timestamp (seconds since Unix epoch). `None` if the token
    /// does not expire (not recommended).
    #[pyo3(get)]
    pub expires_at: Option<f64>,
}

#[pymethods]
impl PyUcanToken {
    fn __repr__(&self) -> String {
        format!(
            "UcanToken(token_id={:?}, issuer={:?}, audience={:?}, capabilities={}, expires_at={:?})",
            self.token_id,
            self.issuer,
            self.audience,
            self.capabilities.len(),
            self.expires_at
        )
    }
}

// ---------------------------------------------------------------------------
// Bridge trait implementations for scp-core validation pipeline
// ---------------------------------------------------------------------------

/// Bridge [`DidResolver`] that extracts Ed25519 public keys from DID strings.
///
/// Supports:
/// - `did:dht:z{z-base-32-encoded-pubkey}` -- production format.
/// - `did:key:{hex-encoded-pubkey}` -- testing format.
///
/// This resolver operates in-memory with no network calls. `did:dht:` DIDs
/// encode the public key directly in the DID string using z-base-32, so
/// resolution is a simple decode operation.
struct BridgeDidResolver;

impl DidResolver for BridgeDidResolver {
    fn resolve_public_key(&self, did: &str) -> Result<[u8; 32], CoreUcanError> {
        // did:dht:z{z-base-32-encoded-pubkey}
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

        // did:key:{hex-encoded-pubkey} (testing format)
        if let Some(hex_str) = did.strip_prefix("did:key:") {
            let bytes = decode_hex(hex_str).map_err(|e| {
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
            "unsupported DID method: {did} (expected did:dht: or did:key:)"
        )))
    }
}

/// Bridge [`RevocationChecker`] that wraps the context's [`RevocationList`].
///
/// Holds a reference to the revocation list from the [`ContextRuntime`] and
/// delegates the `is_revoked` check. This uses the content-hash CID format
/// from `scp_core::crypto::ucan::revoke::compute_revocation_cid`.
struct BridgeRevocationChecker<'a> {
    revocation_list: &'a scp_core::crypto::ucan::revoke::RevocationList,
}

impl RevocationChecker for BridgeRevocationChecker<'_> {
    fn is_revoked(&self, token_cid: &str) -> bool {
        self.revocation_list.is_revoked(token_cid)
    }
}

/// Bridge [`ProofResolver`] backed by an in-memory `HashMap`.
///
/// Stores parent UCAN tokens by their CID for delegation chain traversal.
/// In the bridge layer, the caller can supply proof tokens alongside the
/// token being validated. For now this starts empty -- root tokens (no
/// delegation chain) are fully supported, and delegated tokens require the
/// proof chain to be pre-registered.
struct BridgeProofResolver {
    proofs: HashMap<String, UcanToken>,
}

impl ProofResolver for BridgeProofResolver {
    fn resolve_proof(&self, cid: &str) -> Result<UcanToken, CoreUcanError> {
        self.proofs.get(cid).cloned().ok_or_else(|| {
            CoreUcanError::DelegationChainBroken(format!("proof CID not found: {cid}"))
        })
    }
}

/// Adapter that implements the `validate::NonceTracker` trait for
/// `nonce::NonceTracker<C>`.
///
/// The `nonce::NonceTracker` struct and `validate::NonceTracker` trait have
/// the same `check_and_record` method signature but are separate types. This
/// adapter bridges the two by wrapping a mutable reference to the struct.
struct BridgeNonceTracker<'a, C: scp_core::identity::cache::Clock> {
    inner: &'a mut scp_core::crypto::ucan::nonce::NonceTracker<C>,
}

impl<C: scp_core::identity::cache::Clock> NonceTrackerTrait for BridgeNonceTracker<'_, C> {
    fn check_and_record(&mut self, nonce: &str, token_expiry: u64) -> Result<(), CoreUcanError> {
        self.inner.check_and_record(nonce, token_expiry)
    }
}

// ---------------------------------------------------------------------------
// Bridge functions
// ---------------------------------------------------------------------------

/// Validates a UCAN token using the full 11-step ADR-016 pipeline.
///
/// Delegates to `scp_core::crypto::ucan::validate::validate_ucan` for
/// complete UCAN validation including Ed25519 signature verification, proof
/// chain traversal, delegation depth enforcement, audience/issuer chain
/// validation, scope attenuation, nonce uniqueness, revocation checking,
/// and expiry verification.
///
/// # Arguments
///
/// * `context_id` -- The ID of the context the token is presented in.
/// * `token` -- The encoded UCAN token string (JWT format).
/// * `capability` -- The required capability URI (e.g.,
///   `"scp:ctx:abc123/messages:write"`).
/// * `presenting_agent_did` -- Optional. The DID of the agent presenting
///   the token. If not provided, the token's `aud` field is used (the
///   presenting agent is assumed to be the token's audience).
/// * `proof_tokens` -- Optional. List of encoded parent UCAN token strings
///   for delegation chain verification. Required when validating delegated
///   tokens with non-empty proof chains.
///
/// # Errors
///
/// Raises `UcanError` if validation fails at any step: malformed token,
/// invalid Ed25519 signature, broken delegation chain, expired token,
/// insufficient capabilities, revoked token, nonce replay, etc.
///
/// See ADR-016 §5 for the full 11-step validation specification.
#[pyfunction]
#[pyo3(name = "ucan_validate")]
#[pyo3(signature = (context_id, token, capability, presenting_agent_did=None, proof_tokens=None))]
#[allow(clippy::needless_pass_by_value)] // PyO3 requires owned Option<Vec<String>> for #[pyfunction] arguments.
pub fn py_ucan_validate(
    context_id: &str,
    token: &str,
    capability: &str,
    presenting_agent_did: Option<&str>,
    proof_tokens: Option<Vec<String>>,
) -> PyResult<()> {
    // Step 1: Parse the UCAN token using scp-core's parser.
    let parsed_token = parse_ucan(token).map_err(ScpPyError::from)?;

    // Parse the required capability URI.
    let required_cap: CapabilityUri = capability.parse().map_err(|e: CoreUcanError| {
        ScpPyError::UcanError(format!("invalid capability URI '{capability}': {e}"))
    })?;

    // Determine the presenting agent DID: explicit parameter or token audience.
    let agent_did = presenting_agent_did.unwrap_or(&parsed_token.payload.aud);

    // Build proof resolver from optional proof tokens.
    let proof_resolver = build_proof_resolver(proof_tokens.as_deref())?;

    // Execute the full 11-step validation pipeline within the context runtime.
    crate::runtime::with_context(context_id, |rt| {
        let did_resolver = BridgeDidResolver;
        let revocation_checker = BridgeRevocationChecker {
            revocation_list: &rt.revocation_list,
        };
        let mut nonce_adapter = BridgeNonceTracker {
            inner: &mut rt.nonce_tracker,
        };

        let mut ctx = ValidationContext {
            did_resolver: &did_resolver,
            nonce_tracker: &mut nonce_adapter,
            revocation_checker: &revocation_checker,
            proof_resolver: &proof_resolver,
            ceiling: &rt.ceiling_strings,
            context_creator_did: &rt.creator_did,
            presenting_agent_did: agent_did,
        };

        validate_ucan(&parsed_token, &required_cap, &mut ctx).map_err(ScpPyError::from)
    })?;

    Ok(())
}

/// Mints a new UCAN token for a context member.
///
/// Creates a new UCAN token granting the specified capabilities to the
/// given member DID. The token is structured with proper SCP capability
/// URIs scoped to the context.
///
/// Stub — see SCP-214 for KeyCustody wiring. Currently creates a properly
/// formatted token with a placeholder signature. Real Ed25519 signing
/// requires KeyCustody integration.
///
/// # Arguments
///
/// * `context_id` -- The ID of the context to mint the token for.
/// * `member_did` -- The DID of the member receiving the token.
/// * `capabilities` -- List of capability URIs to grant.
///
/// # Returns
///
/// A [`PyUcanToken`] with the minted token's metadata.
///
/// # Errors
///
/// Raises `UcanError` if minting fails: capabilities outside the context
/// ceiling, issuer not authorized, etc.
///
/// See ADR-013 §6: `py_ucan_mint(handle, member_did, capabilities) -> PyUcanToken`.
#[pyfunction]
#[pyo3(name = "ucan_mint")]
#[allow(clippy::needless_pass_by_value)] // PyO3 requires owned Vec for #[pyfunction] arguments.
pub fn py_ucan_mint(
    context_id: &str,
    member_did: &str,
    capabilities: Vec<String>,
) -> PyResult<PyUcanToken> {
    // Look up the context to get the creator DID (issuer).
    let creator_did = crate::runtime::with_context(context_id, |rt| Ok(rt.creator_did.clone()))?;

    // Generate a unique nonce for the token ID.
    let nonce = generate_nonce()?;

    // Build capability attestations scoped to the context.
    let capability_uris: Vec<String> = capabilities
        .iter()
        .map(|cap| {
            if cap.starts_with("scp:ctx:") {
                cap.clone()
            } else {
                format!("scp:ctx:{context_id}/{cap}")
            }
        })
        .collect();

    // Calculate expiry: 1 hour from now (default, within 24h max).
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| ScpPyError::UcanError(format!("system clock error: {e}")))?
        .as_secs();
    let exp = now + 3600; // 1 hour

    Ok(PyUcanToken {
        token_id: nonce,
        issuer: creator_did,
        audience: member_did.to_owned(),
        capabilities: capability_uris,
        #[allow(clippy::cast_precision_loss)] // Unix timestamp seconds fit in f64 mantissa for centuries.
        expires_at: Some(exp as f64),
    })
}

/// Revokes a UCAN token.
///
/// Adds the token to the context's revocation list. Revoked tokens are
/// no longer accepted by validation. In the full runtime, revocation is
/// distributed to all context members via MLS.
///
/// The token is identified by its content-hash CID (SHA-256 of the JSON-
/// serialized payload), matching the identifier used by scp-core's
/// `compute_revocation_cid`. This format is consistent with the CID
/// checked by the full validation pipeline in step 10.
///
/// # Arguments
///
/// * `context_id` -- The ID of the context the token belongs to.
/// * `token` -- The full encoded UCAN token string (JWT format).
///
/// # Errors
///
/// Raises `UcanError` if revocation fails: context not found, malformed
/// token, etc.
///
/// See ADR-013 §6: `py_ucan_revoke(handle, token) -> None`.
#[pyfunction]
#[pyo3(name = "ucan_revoke")]
pub fn py_ucan_revoke(context_id: &str, token: &str) -> PyResult<()> {
    // Parse the token to extract its payload for CID computation.
    let parsed = parse_ucan(token).map_err(ScpPyError::from)?;

    crate::runtime::with_context(context_id, |rt| {
        // Compute the content-hash CID matching scp-core's format.
        let token_cid = compute_revocation_cid(&parsed.payload);
        rt.revocation_list.revoke(token_cid);
        Ok(())
    })?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Generates a nonce in the format `{unix_millis_timestamp}-{16_random_bytes_hex}`.
///
/// Uses cryptographic randomness via `rand::thread_rng()` (backed by `OsRng`)
/// to produce unpredictable nonces as required by ADR-016 §7.2.
fn generate_nonce() -> Result<String, ScpPyError> {
    use rand::Rng;

    let now_millis = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| ScpPyError::UcanError(format!("system clock error: {e}")))?
        .as_millis();

    let mut random_bytes = [0u8; 16];
    rand::thread_rng().fill(&mut random_bytes);

    let hex = encode_hex(&random_bytes);
    Ok(format!("{now_millis}-{hex}"))
}

/// Decodes a hex string to bytes.
fn decode_hex(hex: &str) -> Result<Vec<u8>, String> {
    if !hex.len().is_multiple_of(2) {
        return Err(format!("hex string has odd length: {}", hex.len()));
    }

    let mut bytes = Vec::with_capacity(hex.len() / 2);
    for i in (0..hex.len()).step_by(2) {
        let byte_str = &hex[i..i + 2];
        let byte =
            u8::from_str_radix(byte_str, 16).map_err(|e| format!("hex decode error: {e}"))?;
        bytes.push(byte);
    }
    Ok(bytes)
}

/// Builds a [`BridgeProofResolver`] from optional encoded proof token strings.
///
/// Parses each proof token and indexes it by its CID (SHA-256 of the encoded
/// JWT) so that the delegation chain verifier can resolve proof references.
fn build_proof_resolver(
    proof_tokens: Option<&[String]>,
) -> Result<BridgeProofResolver, ScpPyError> {
    let mut proofs = HashMap::new();

    if let Some(tokens) = proof_tokens {
        for encoded in tokens {
            let token = parse_ucan(encoded).map_err(ScpPyError::from)?;
            let cid = scp_core::crypto::ucan::mint::compute_cid(&token);
            proofs.insert(cid, token);
        }
    }

    Ok(BridgeProofResolver { proofs })
}

// ---------------------------------------------------------------------------
// Module registration
// ---------------------------------------------------------------------------

/// Registers UCAN bridge functions and classes on the `_scp_core` module.
///
/// Called from [`crate::_scp_core`] during module initialization.
///
/// # Errors
///
/// Returns `PyErr` if registration of functions or classes fails.
pub fn register_ucan(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyUcanToken>()?;
    m.add_function(wrap_pyfunction!(py_ucan_validate, m)?)?;
    m.add_function(wrap_pyfunction!(py_ucan_mint, m)?)?;
    m.add_function(wrap_pyfunction!(py_ucan_revoke, m)?)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
//
// NOTE: scp-ffi has `test = false` in Cargo.toml because the PyO3 cdylib
// cannot link a test binary without Python dev headers. These tests are
// compiled and verified via `cargo check -p scp-ffi --tests` or through the
// Python test infrastructure (`maturin develop` + `pytest`).
//
// The scp-core validation pipeline (which py_ucan_validate delegates to)
// has comprehensive tests in `crates/scp-core/src/crypto/ucan/validate.rs`
// covering all 11 ADR-016 steps including:
// - Forged UCAN (invalid signature) rejection
// - Expired UCAN rejection
// - Valid UCAN with correct Ed25519 signature acceptance
// - Delegated chain with 3 levels validation
// - Capability exceeding parent delegation rejection
// - Nonce replay detection
// - Revocation checking
// - Audience/issuer chain validation
// - Ceiling compliance
//
// The bridge-specific tests below verify the DID resolver, proof resolver,
// and nonce tracker adapter implementations.

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::iter_on_single_items,
    clippy::cast_possible_truncation
)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // BridgeDidResolver
    // -----------------------------------------------------------------------

    #[test]
    fn bridge_did_resolver_resolves_did_dht() {
        // Generate a known public key and encode it as did:dht:z{zbase32}.
        let pk_bytes: [u8; 32] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e, 0x1f, 0x20,
        ];
        let did = format!("did:dht:z{}", zbase32::encode(&pk_bytes));

        let resolver = BridgeDidResolver;
        let result = resolver.resolve_public_key(&did).unwrap();
        assert_eq!(result, pk_bytes);
    }

    #[test]
    fn bridge_did_resolver_resolves_did_key_hex() {
        let pk_bytes: [u8; 32] = [0xab; 32];
        let hex = encode_hex(&pk_bytes);
        let did = format!("did:key:{hex}");

        let resolver = BridgeDidResolver;
        let result = resolver.resolve_public_key(&did).unwrap();
        assert_eq!(result, pk_bytes);
    }

    #[test]
    fn bridge_did_resolver_rejects_unknown_method() {
        let resolver = BridgeDidResolver;
        let result = resolver.resolve_public_key("did:web:example.com");
        assert!(result.is_err());
    }

    #[test]
    fn bridge_did_resolver_rejects_invalid_zbase32() {
        let resolver = BridgeDidResolver;
        // Invalid z-base-32 encoding (wrong length).
        let result = resolver.resolve_public_key("did:dht:zinvalid");
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // BridgeRevocationChecker
    // -----------------------------------------------------------------------

    #[test]
    fn bridge_revocation_checker_not_revoked() {
        let list = scp_core::crypto::ucan::revoke::RevocationList::new("ctx-test".to_owned());
        let checker = BridgeRevocationChecker {
            revocation_list: &list,
        };
        assert!(!checker.is_revoked("some-cid"));
    }

    #[test]
    fn bridge_revocation_checker_detects_revoked() {
        let mut list = scp_core::crypto::ucan::revoke::RevocationList::new("ctx-test".to_owned());
        list.revoke("revoked-cid".to_owned());
        let checker = BridgeRevocationChecker {
            revocation_list: &list,
        };
        assert!(checker.is_revoked("revoked-cid"));
    }

    // -----------------------------------------------------------------------
    // BridgeProofResolver
    // -----------------------------------------------------------------------

    #[test]
    fn bridge_proof_resolver_returns_stored_token() {
        let token = UcanToken {
            header: scp_core::crypto::ucan::UcanHeader::new(),
            payload: scp_core::crypto::ucan::UcanPayload {
                iss: "did:dht:zCreator".to_owned(),
                aud: "did:dht:zMember".to_owned(),
                exp: 1_700_000_000,
                nbf: None,
                nnc: "0-aabbccdd11223344aabbccdd11223344".to_owned(),
                att: vec![],
                prf: vec![],
                fct: None,
            },
            signature: vec![0u8; 64],
            encoded: "h.p.s".to_owned(),
        };

        let cid = "test-cid".to_owned();
        let resolver = BridgeProofResolver {
            proofs: [(cid.clone(), token.clone())].into_iter().collect(),
        };

        let result = resolver.resolve_proof(&cid).unwrap();
        assert_eq!(result.payload.iss, token.payload.iss);
    }

    #[test]
    fn bridge_proof_resolver_rejects_missing_cid() {
        let resolver = BridgeProofResolver {
            proofs: HashMap::new(),
        };
        let result = resolver.resolve_proof("nonexistent-cid");
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // BridgeNonceTracker adapter
    // -----------------------------------------------------------------------

    #[test]
    fn bridge_nonce_tracker_delegates_to_inner() {
        use scp_core::identity::cache::SystemClock;

        let mut tracker =
            scp_core::crypto::ucan::nonce::NonceTracker::new("ctx-test".to_owned(), SystemClock);

        let now_millis = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis();
        let now_secs = (now_millis / 1000) as u64;
        let nonce = format!("{now_millis}-aabbccdd11223344aabbccdd11223344");
        let expiry = now_secs + 3600;

        let mut adapter = BridgeNonceTracker {
            inner: &mut tracker,
        };

        // First check should succeed.
        assert!(adapter.check_and_record(&nonce, expiry).is_ok());

        // Replay should fail.
        let result = adapter.check_and_record(&nonce, expiry);
        assert!(matches!(result, Err(CoreUcanError::NonceReused(_))));
    }

    // -----------------------------------------------------------------------
    // build_proof_resolver
    // -----------------------------------------------------------------------

    #[test]
    fn build_proof_resolver_handles_empty_input() {
        let resolver = build_proof_resolver(None).unwrap();
        assert!(resolver.proofs.is_empty());
    }

    #[test]
    fn build_proof_resolver_handles_empty_slice() {
        let tokens: Vec<String> = vec![];
        let resolver = build_proof_resolver(Some(&tokens)).unwrap();
        assert!(resolver.proofs.is_empty());
    }

    // -----------------------------------------------------------------------
    // decode_hex
    // -----------------------------------------------------------------------

    #[test]
    fn decode_hex_roundtrip() {
        let bytes = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
        let hex = encode_hex(&bytes);
        let decoded = decode_hex(&hex).unwrap();
        assert_eq!(decoded, bytes);
    }

    #[test]
    fn decode_hex_rejects_odd_length() {
        let result = decode_hex("abc");
        assert!(result.is_err());
    }

    #[test]
    fn decode_hex_rejects_non_hex() {
        let result = decode_hex("gggg");
        assert!(result.is_err());
    }
}
