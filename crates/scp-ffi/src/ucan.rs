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

use scp_core::crypto::ucan::Attenuation;
use scp_core::crypto::ucan::UcanError as CoreUcanError;
use scp_core::crypto::ucan::capability::CapabilityUri;
use scp_core::crypto::ucan::mint::{DelegateParams, MintParams, delegate_ucan, mint_ucan};
use scp_core::crypto::ucan::revoke::revoke_ucan as core_revoke_ucan;
use scp_core::crypto::ucan::validate::{
    DEFAULT_CLOCK_SKEW_TOLERANCE_SECS, ValidationContext, parse_ucan, validate_ucan,
};

use crate::bridge_adapters::{
    BridgeNonceTracker, BridgeProofResolver, BridgeRevocationChecker, DispatchDidResolver,
};
use crate::error::ScpPyError;
use crate::validate;

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

    /// Proof chain -- CIDs of parent UCAN tokens forming the delegation
    /// chain. Empty for root tokens issued by the context creator.
    #[pyo3(get)]
    pub proofs: Vec<String>,
}

#[pymethods]
impl PyUcanToken {
    fn __repr__(&self) -> String {
        format!(
            "UcanToken(token_id={:?}, issuer={:?}, audience={:?}, capabilities={}, expires_at={:?}, proofs={})",
            self.token_id,
            self.issuer,
            self.audience,
            self.capabilities.len(),
            self.expires_at,
            self.proofs.len()
        )
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
    validate::validate_context_id(context_id)?;
    validate::validate_ucan_token(token)?;
    validate::validate_capability_uri(capability)?;
    if let Some(did) = presenting_agent_did {
        validate::validate_did(did)?;
    }
    if let Some(ref tokens) = proof_tokens {
        for t in tokens {
            validate::validate_ucan_token(t)?;
        }
    }
    // Step 1: Parse the UCAN token using scp-core's parser.
    let parsed_token = parse_ucan(token).map_err(ScpPyError::from)?;

    // Parse the required capability URI.
    let required_cap: CapabilityUri = capability.parse().map_err(|e: CoreUcanError| {
        ScpPyError::ucan(format!("invalid capability URI '{capability}': {e}"))
    })?;

    // Determine the presenting agent DID: explicit parameter or token audience.
    let agent_did = presenting_agent_did.unwrap_or(&parsed_token.payload.aud);

    // Build proof resolver from optional proof tokens.
    let proof_resolver = build_proof_resolver(proof_tokens.as_deref())?;

    // Execute the full 11-step validation pipeline within the context runtime.
    // Use production DID resolver when available (#311), fallback to string-only.
    crate::runtime::with_context(context_id, |rt| {
        let production_resolver = crate::runtime::did_resolver();
        let did_resolver =
            DispatchDidResolver::new(production_resolver.map(std::convert::AsRef::as_ref));
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
            clock_skew_tolerance_secs: DEFAULT_CLOCK_SKEW_TOLERANCE_SECS,
            clock: &scp_primitives::SystemClock,
        };

        validate_ucan(&parsed_token, &required_cap, &mut ctx).map_err(ScpPyError::from)
    })?;

    Ok(())
}

/// Mints a new UCAN token for a context member.
///
/// Creates a new UCAN token granting the specified capabilities to the
/// given member DID. The token is structured with proper SCP capability
/// URIs scoped to the context. Real Ed25519 signing requires `KeyCustody`
/// integration (SCP-214).
///
/// # Arguments
///
/// * `context_id` -- The ID of the context to mint the token for.
/// * `member_did` -- The DID of the member receiving the token.
/// * `capabilities` -- List of capability strings (e.g., `"messages:write"`).
///
/// # Returns
///
/// A [`PyUcanToken`] with the minted token's metadata.
///
/// # Errors
///
/// Raises `ValidationError` if `member_did` fails `validate_did`
/// (empty, malformed `did:{method}:{id}` format, or control characters),
/// if any capability URI fails `validate_capability_uri`, or if any
/// proof token fails `validate_ucan_token`.
///
/// Raises `UcanError` if minting fails: capabilities outside the context
/// ceiling, issuer not authorized, signing fails, etc.
///
/// See ADR-013 §6 and SCP-214 criterion 7.
#[pyfunction]
#[pyo3(name = "ucan_mint")]
#[pyo3(signature = (context_id, member_did, capabilities, proofs=None))]
#[allow(clippy::needless_pass_by_value)] // PyO3 requires owned Vec/Option<Vec> for #[pyfunction] arguments.
pub fn py_ucan_mint(
    context_id: &str,
    member_did: &str,
    capabilities: Vec<String>,
    proofs: Option<Vec<String>>,
) -> PyResult<PyUcanToken> {
    validate::validate_context_id(context_id)?;
    validate::validate_did(member_did)?;
    for cap in &capabilities {
        validate::validate_capability_uri(cap)?;
    }
    if let Some(ref tokens) = proofs {
        for t in tokens {
            validate::validate_ucan_token(t)?;
        }
    }
    // Look up the context to get the creator DID (issuer).
    let creator_did = crate::runtime::with_context(context_id, |rt| Ok(rt.creator_did.clone()))?;

    let rt = crate::runtime()?;
    let context_id_owned = context_id.to_owned();
    let _nonce = scp_core::crypto::ucan::nonce::generate_nonce(&scp_primitives::SystemClock);

    // Mint using real scp_core::mint_ucan with Ed25519 signing via
    // the retained KeyCustody. See SCP-214 criterion 7.
    let token = crate::runtime::with_identity(&creator_did, |entry| {
        // Get the ceiling from the context runtime for mint-time enforcement (#339).
        let ceiling_strings =
            crate::runtime::with_context(&context_id_owned, |rt| Ok(rt.ceiling_strings.clone()))?;

        let params = MintParams {
            issuer_did: &creator_did,
            issuer_key: &entry.identity.active_signing_key,
            audience_did: member_did,
            context_id: &context_id_owned,
            capabilities: &capabilities,
            lifetime_secs: 3600,
            not_before: None,
            proofs: proofs.unwrap_or_default(),
            facts: None,
            key_scope: None,
            signing_key_id: None,
            ceiling: Some(ceiling_strings),
        };

        let result = rt.block_on(async {
            mint_ucan(
                &params,
                entry.custody.as_ref(),
                &scp_primitives::SystemClock,
            )
            .await
        });
        result.map_err(ScpPyError::from)
    })?;

    // Convert capability attestations to URI strings for Python.
    let capability_uris: Vec<String> = token.payload.att.iter().map(|a| a.with.clone()).collect();

    Ok(PyUcanToken {
        token_id: token.payload.nnc.clone(),
        issuer: token.payload.iss.clone(),
        audience: token.payload.aud.clone(),
        capabilities: capability_uris,
        // Unix timestamp seconds fit in f64 mantissa for centuries.
        #[allow(clippy::cast_precision_loss)]
        expires_at: Some(token.payload.exp as f64),
        proofs: token.payload.prf,
    })
}

/// Delegates a UCAN token to another member.
///
/// Creates a delegated UCAN from an existing parent token, signed with the
/// delegator's Ed25519 key via the retained `KeyCustody` provider.
/// Delegation enforces attenuation (capabilities can only narrow, never
/// widen).
///
/// # Arguments
///
/// * `context_id` -- The ID of the context.
/// * `delegator_did` -- The DID of the entity delegating (must match
///   parent token's audience).
/// * `delegatee_did` -- The DID of the entity receiving the delegation.
/// * `parent_token` -- The encoded parent UCAN token (JWT format).
/// * `capabilities` -- List of capability URI strings to delegate (must be
///   subset of parent's capabilities).
///
/// # Returns
///
/// A [`PyUcanToken`] with the delegated token's metadata.
///
/// # Errors
///
/// Raises `ValidationError` if `delegator_did` or `delegatee_did` fails
/// `validate_did` (empty, malformed `did:{method}:{id}` format, or
/// control characters), if `parent_token` fails `validate_ucan_token`,
/// or if any capability URI fails `validate_capability_uri`.
///
/// Raises `UcanError` if delegation fails: delegator not matching parent
/// audience, capabilities wider than parent, signing failure, etc.
///
/// See ADR-016 criterion 4 and SCP-214 criterion 8.
#[pyfunction]
// PyO3 requires owned types for #[pyfunction] arguments.
#[pyo3(name = "ucan_delegate")]
#[allow(clippy::needless_pass_by_value)]
pub fn py_ucan_delegate(
    context_id: &str,
    delegator_did: &str,
    delegatee_did: &str,
    parent_token: &str,
    capabilities: Vec<String>,
) -> PyResult<PyUcanToken> {
    validate::validate_context_id(context_id)?;
    validate::validate_did(delegator_did)?;
    validate::validate_did(delegatee_did)?;
    validate::validate_ucan_token(parent_token)?;
    for cap in &capabilities {
        validate::validate_capability_uri(cap)?;
    }
    // Parse the parent token.
    let parsed_parent = parse_ucan(parent_token).map_err(ScpPyError::from)?;

    // Build attenuated capabilities from the capability URI strings.
    let attenuations: Vec<Attenuation> = capabilities
        .iter()
        .map(|cap| {
            let cap_uri = if cap.starts_with("scp:ctx:") {
                cap.clone()
            } else {
                format!("scp:ctx:{context_id}/{cap}")
            };
            let action = cap_uri.rsplit_once('/').map_or_else(
                || cap.clone(),
                |(_, a)| {
                    a.split_once(':')
                        .map_or_else(|| a.to_owned(), |(_, act)| act.to_owned())
                },
            );
            Attenuation {
                with: cap_uri,
                can: action,
            }
        })
        .collect();

    let rt = crate::runtime()?;

    // Get the ceiling from the context runtime for delegation-time enforcement (#339).
    let ceiling_strings =
        crate::runtime::with_context(context_id, |rt| Ok(rt.ceiling_strings.clone()))?;

    let token = crate::runtime::with_identity(delegator_did, |entry| {
        let params = DelegateParams {
            parent_token: &parsed_parent,
            delegator_did,
            delegator_key: &entry.identity.active_signing_key,
            delegatee_did,
            attenuated_capabilities: &attenuations,
            lifetime_secs: 3600,
            facts: None,
            key_scope: None,
            signing_key_id: None,
            ceiling: Some(ceiling_strings.clone()),
        };

        let result = rt.block_on(async {
            delegate_ucan(
                &params,
                entry.custody.as_ref(),
                &scp_primitives::SystemClock,
            )
            .await
        });
        result.map_err(ScpPyError::from)
    })?;

    let capability_uris: Vec<String> = token.payload.att.iter().map(|a| a.with.clone()).collect();

    Ok(PyUcanToken {
        token_id: token.payload.nnc.clone(),
        issuer: token.payload.iss.clone(),
        audience: token.payload.aud.clone(),
        // Unix timestamp seconds fit in f64 mantissa for centuries.
        capabilities: capability_uris,
        #[allow(clippy::cast_precision_loss)]
        expires_at: Some(token.payload.exp as f64),
        proofs: token.payload.prf,
    })
}

/// Revokes a UCAN token using the full revocation pipeline.
///
/// Performs the complete UCAN revocation flow from ADR-016:
///
/// 1. **Authorization** -- Verifies the revoker is the token's issuer or the
///    context creator via `BridgeRevocationAuthorizer`.
/// 2. **Local revocation** -- Adds the token CID to the context's
///    `RevocationList` (fail-closed via `RevocationPending` state).
/// 3. **Distribution** -- Logs the revocation for transport-layer broadcast
///    (MLS distribution deferred to transport connection).
/// 4. **Event logging** -- Appends a `TokenRevoked` event to the context's
///    Merkle event log.
///
/// # Arguments
///
/// * `context_id` -- The ID of the context the token belongs to.
/// * `token` -- The full encoded UCAN token string (JWT format).
/// * `revoker_did` -- The DID of the entity requesting the revocation. Must
///   be either the token's issuer or the context creator.
///
/// # Errors
///
/// Raises `UcanError` if revocation fails: unauthorized revoker, context not
/// found, malformed token, or event log append failure.
///
/// See ADR-016 acceptance criterion 5. Closes #499.
#[pyfunction]
#[pyo3(name = "ucan_revoke")]
pub fn py_ucan_revoke(context_id: &str, token: &str, revoker_did: &str) -> PyResult<()> {
    validate::validate_context_id(context_id)?;
    validate::validate_ucan_token(token)?;
    validate::validate_did(revoker_did)?;

    // Parse the token to extract the issuer DID for authorization.
    let parsed = parse_ucan(token).map_err(ScpPyError::from)?;

    crate::runtime::with_context(context_id, |rt| {
        use crate::bridge_adapters::{
            BridgeRevocationAuthorizer, BridgeRevocationDistributor, BridgeRevocationEventLogger,
        };
        use std::cell::RefCell;

        let authorizer = BridgeRevocationAuthorizer {
            issuer_did: parsed.payload.iss.clone(),
            creator_did: rt.creator_did.clone(),
        };
        let distributor = BridgeRevocationDistributor;
        let event_log_cell = RefCell::new(&mut rt.event_log);
        let event_logger = BridgeRevocationEventLogger {
            event_log: &event_log_cell,
        };

        core_revoke_ucan(
            &mut rt.revocation_list,
            token,
            revoker_did,
            &authorizer,
            &distributor,
            &event_logger,
        )
        .map_err(ScpPyError::from)
    })?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Builds a [`BridgeProofResolver`] from optional encoded proof token strings.
///
/// Parses each proof token and indexes it by its CID (SHA-256 of the encoded
/// JWT) so that the delegation chain verifier can resolve proof references.
pub(crate) fn build_proof_resolver(
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

/// Public alias for `build_proof_resolver` used by `tools.rs` and `mcp.rs`.
///
/// Accepts the same `Option<&[String]>` parameter as the internal function.
pub(crate) fn build_proof_resolver_from_tokens(
    proof_tokens: Option<&[String]>,
) -> Result<BridgeProofResolver, ScpPyError> {
    build_proof_resolver(proof_tokens)
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
    m.add_function(wrap_pyfunction!(py_ucan_delegate, m)?)?;
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

    use scp_core::crypto::ucan::UcanToken;
    use scp_core::crypto::ucan::validate::{
        DidResolver, NonceTracker as NonceTrackerTrait, ProofResolver, RevocationChecker,
    };
    use scp_ffi_common::BridgeDidResolver;

    // -----------------------------------------------------------------------
    // BridgeDidResolver
    // -----------------------------------------------------------------------

    #[test]
    fn bridge_did_resolver_resolves_did_dht() {
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
        let hex_str = hex::encode(pk_bytes);
        let did = format!("did:key:{hex_str}");

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
        use scp_identity::cache::SystemClock;

        let mut tracker =
            scp_core::crypto::ucan::nonce::NonceTracker::new("ctx-test".to_owned(), SystemClock);

        let now_millis = scp_core::time::now_millis().expect("clock unavailable in test");
        let now_secs = now_millis / 1000;
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
    // hex roundtrip (via hex crate, validates bridge_adapters integration)
    // -----------------------------------------------------------------------

    #[test]
    fn hex_encode_decode_roundtrip() {
        let bytes = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
        let encoded = hex::encode(bytes);
        let decoded = hex::decode(&encoded).unwrap();
        assert_eq!(decoded, bytes);
    }

    #[test]
    fn hex_decode_rejects_odd_length() {
        let result = hex::decode("abc");
        assert!(result.is_err());
    }

    #[test]
    fn hex_decode_rejects_non_hex() {
        let result = hex::decode("gggg");
        assert!(result.is_err());
    }
}
