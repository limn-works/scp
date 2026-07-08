//! `PyO3` bridge functions for UCAN token management.
//!
//! Exposes SCP UCAN operations to Python as methods on the `SCP` class:
//!
//! - `PyScp::ucan_validate` -- Validate a UCAN token using the full 11-step
//!   ADR-016 pipeline with Ed25519 signature verification.
//! - `PyScp::ucan_mint` -- Mint a new UCAN token for a member.
//! - `PyScp::ucan_delegate` -- Delegate a UCAN token to another member.
//! - `PyScp::ucan_revoke` -- Revoke a UCAN token.
//!
//! Migrated from flat `#[pyfunction]` exports to `#[pymethods] impl PyScp`
//! methods in Phase 4 PR 4 sub-slice C (#1549).
//!
//! # Types
//!
//! - [`PyUcanToken`] -- UCAN token with ID, issuer, audience, capabilities,
//!   and expiry.
//!
//! # Validation pipeline
//!
//! `ucan_validate` delegates to `scp_core::crypto::ucan::validate::validate_ucan`,
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
    CapabilityValidation, DEFAULT_CLOCK_SKEW_TOLERANCE_SECS, ValidationContext, evaluate_ucan,
    parse_ucan, validate_ucan,
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
/// granted capabilities, an optional expiry timestamp, and the encoded JWT.
///
/// The encoded JWT is exposed so callers can feed a freshly minted token back
/// into `ucan_validate` / `ucan_evaluate` / `ucan_delegate` (which all take the
/// JWT string), matching the `encoded` accessor the NAPI and `UniFFI` bridges
/// already expose. The raw signature remains internal to the Rust crypto layer.
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

    /// Encoded JWT string (`header.payload.signature`).
    ///
    /// The full wire form of the token, suitable for passing back into
    /// `ucan_validate` / `ucan_evaluate` / `ucan_delegate`. Mirrors the
    /// `encoded` accessor on the NAPI `NapiUcanToken` and `UniFFI` `UcanToken`.
    #[pyo3(get)]
    pub encoded: String,

    /// Bridge instance affinity id (Phase 4 PR 1 — #1549).
    ///
    /// `dead_code` allowance: future commits of this PR will add
    /// `check_handle` at every entry point that accepts a `UcanToken`.
    #[allow(dead_code)]
    pub(crate) instance_id: u64,
}

impl PyUcanToken {
    /// Stamps the given bridge instance's `instance_id` on this token.
    /// Called by constructor sites so handle-affinity checks can reject
    /// cross-instance reuse.
    pub(crate) const fn stamp_instance_id(mut self, bi: &crate::runtime::PyBridgeInstance) -> Self {
        self.instance_id = bi.core.instance_id();
        self
    }
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
// PyCapabilityValidation
// ---------------------------------------------------------------------------

/// Structured, side-effect-free result of evaluating a UCAN token.
///
/// Produced by [`PyScp::ucan_evaluate`], this mirrors scp-core's
/// [`CapabilityValidation`] — the diagnostic counterpart to the fail-closed
/// `ucan_validate` gate. Each boolean reflects whether the corresponding
/// pipeline stage ran and passed; because the pipeline short-circuits, a field
/// is `true` only if its stage AND every prior stage passed.
///
/// Unlike `ucan_validate`, evaluation records NO state — the nonce is probed
/// read-only and never recorded, so `ucan_evaluate` is safe to call repeatedly
/// on the same token. The result is a point-in-time diagnostic snapshot, NOT a
/// promise that a subsequent `ucan_validate` will accept the token.
///
/// See ADR-016 and `scp_core::crypto::ucan::validate::CapabilityValidation`.
//
// Six per-stage outcome flags are the mandated public shape of this diagnostic
// (one boolean per pipeline stage group), mirroring scp-core's
// `CapabilityValidation`. These are pure data — not behavior-selecting flags —
// so the `struct_excessive_bools` suggestion (a state machine / two-variant
// enums) would obscure, not clarify, the API and break the flat named-field
// shape the SDK trust signal consumes.
#[allow(clippy::struct_excessive_bools)]
#[pyclass(name = "CapabilityValidation")]
#[derive(Debug, Clone)]
pub struct PyCapabilityValidation {
    /// Step 1: the token parsed and its header/attestation set validated.
    #[pyo3(get)]
    pub tokens_valid: bool,
    /// Steps 2-7: signature, delegation chain, root issuer, audience, key
    /// scope, capability grant-match, Category-A enforcement, and attenuation
    /// all passed (whole-chain).
    #[pyo3(get)]
    pub signatures_valid: bool,
    /// Step 8: every granted capability is within the context's ceiling.
    #[pyo3(get)]
    pub within_ceiling: bool,
    /// Step 9: nonce format, freshness, and uniqueness passed (probed
    /// read-only — the nonce is NOT recorded).
    #[pyo3(get)]
    pub nonce_valid: bool,
    /// Step 10: the token's revocation CID is not on the revocation list.
    #[pyo3(get)]
    pub not_revoked: bool,
    /// Step 11: `exp`/`nbf` time bounds are valid (within clock-skew tolerance).
    #[pyo3(get)]
    pub time_bounds_valid: bool,
}

impl From<CapabilityValidation> for PyCapabilityValidation {
    fn from(v: CapabilityValidation) -> Self {
        Self {
            tokens_valid: v.tokens_valid,
            signatures_valid: v.signatures_valid,
            within_ceiling: v.within_ceiling,
            nonce_valid: v.nonce_valid,
            not_revoked: v.not_revoked,
            time_bounds_valid: v.time_bounds_valid,
        }
    }
}

#[pymethods]
impl PyCapabilityValidation {
    fn __repr__(&self) -> String {
        format!(
            "CapabilityValidation(tokens_valid={}, signatures_valid={}, within_ceiling={}, \
             nonce_valid={}, not_revoked={}, time_bounds_valid={})",
            self.tokens_valid,
            self.signatures_valid,
            self.within_ceiling,
            self.nonce_valid,
            self.not_revoked,
            self.time_bounds_valid
        )
    }
}

// ---------------------------------------------------------------------------
// PyScp methods — migrated from #[pyfunction] exports (Phase 4 PR 4, #1549).
// ---------------------------------------------------------------------------

#[pymethods]
impl crate::scp::PyScp {
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
    /// * `presenting_agent_did` -- REQUIRED (non-optional). The DID of the agent
    ///   presenting the token. It is a required parameter — never defaulted to
    ///   the token's own `aud`. Defaulting would make the step-5 audience check a
    ///   tautological self-check (`aud == aud`) that does NOT bind the token to
    ///   any external subject, so a token addressed to someone else would pass
    ///   (trust inflation). An empty/whitespace value is rejected by
    ///   `validate_did` (it is not a valid `did:` string). Mirrors the diagnostic
    ///   `ucan_evaluate` gate.
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
    #[pyo3(signature = (context_id, token, capability, presenting_agent_did, proof_tokens=None))]
    #[allow(clippy::needless_pass_by_value)] // PyO3 requires owned Option<Vec<String>> for method arguments.
    pub fn ucan_validate(
        &self,
        context_id: &str,
        token: &str,
        capability: &str,
        presenting_agent_did: &str,
        proof_tokens: Option<Vec<String>>,
    ) -> PyResult<()> {
        let bi = &*self.inner;
        validate::validate_context_id(context_id)?;
        validate::validate_ucan_token(token)?;
        validate::validate_capability_uri(capability)?;
        // FAIL CLOSED (no silent security default): the presenting agent DID is a
        // REQUIRED parameter (never defaulted to the token's own `aud`, which
        // would make the step-5 audience check tautological and inflate trust for
        // a token addressed to someone else). Trimmed for input hygiene (parity
        // with `ucan_evaluate_on`/NAPI); `validate_did` then rejects an empty or
        // whitespace-only value (not a valid `did:` string). Mirrors
        // `ucan_evaluate`.
        let presenting_agent_did = presenting_agent_did.trim();
        validate::validate_did(presenting_agent_did)?;
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

        // Presenting agent DID is a required parameter — never the token aud.
        let agent_did = presenting_agent_did;

        // Build proof resolver from optional proof tokens.
        let proof_resolver = build_proof_resolver(proof_tokens.as_deref())?;

        // Execute the full 11-step validation pipeline within the context runtime.
        // Use production DID resolver when available (#311), fallback to string-only.
        crate::runtime::with_context(bi, context_id, |rt| {
            let production_resolver = crate::runtime::did_resolver(bi);
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
                clock: &scp_clock::SystemClock,
            };

            validate_ucan(&parsed_token, &required_cap, &mut ctx).map_err(ScpPyError::from)
        })?;

        Ok(())
    }

    /// Evaluates a UCAN token and returns a structured per-stage validity
    /// summary instead of throwing at the first failure.
    ///
    /// This is the diagnostic, **side-effect-free** counterpart to
    /// [`PyScp::ucan_validate`]. It runs the EXACT same 11-step ADR-016
    /// pipeline via `scp_core::crypto::ucan::validate::evaluate_ucan`, but:
    ///
    /// - returns a [`PyCapabilityValidation`] (six booleans) rather than
    ///   raising on the first failing stage; and
    /// - is **read-only** — the nonce is probed (never recorded), so calling
    ///   `ucan_evaluate` does NOT consume the token's nonce. A later
    ///   `ucan_validate` can still accept the same token.
    ///
    /// # Arguments
    ///
    /// `context_id`, `token`, optional `capability`, REQUIRED
    /// `presenting_agent_did`, and optional `proof_tokens` for delegation chains.
    ///
    /// FAIL CLOSED: `presenting_agent_did` is a REQUIRED (non-optional) parameter
    /// (no silent security default). It is never defaulted to the token's own
    /// `aud` — defaulting would make the step-5 audience check a tautological
    /// self-check (`aud == aud`) that does NOT bind the token to any external
    /// subject, so a token addressed to someone else would report
    /// `signatures_valid` (trust inflation). An empty/whitespace value is rejected
    /// by `validate_did`. The SDK trust path always passes the subject; raw
    /// diagnostic callers must pass an explicit presenting agent.
    ///
    /// `capability` is OPTIONAL. When omitted (or empty), the token is evaluated
    /// for INTRINSIC validity only — no specific capability is challenged, so the
    /// invoked-capability grant-match step is skipped (mirroring
    /// `evaluate_ucan(None, ..)` in scp-core). This is the mode the SDK trust
    /// signal uses. When a capability IS supplied, the token must additionally
    /// grant it (identical to the historical mandatory-capability behavior). The
    /// enforcing gate [`PyScp::ucan_validate`] keeps a MANDATORY capability.
    ///
    /// # Returns
    ///
    /// A [`PyCapabilityValidation`]. A token that cannot be parsed yields
    /// `tokens_valid=False` with every later field `False`.
    ///
    /// # Errors
    ///
    /// Raises `ValidationError` only for malformed FFI inputs (invalid
    /// `context_id`/`token`/`capability`/`did` strings) or an unparseable
    /// token / capability URI. Capability/signature/expiry failures are
    /// reported via the returned booleans, not as exceptions.
    ///
    /// See ADR-016 §5 and `CapabilityValidation` in scp-core.
    #[pyo3(signature = (context_id, token, capability, presenting_agent_did, proof_tokens=None))]
    #[allow(clippy::needless_pass_by_value)] // PyO3 requires owned Option<Vec<String>> for method arguments.
    pub fn ucan_evaluate(
        &self,
        context_id: &str,
        token: &str,
        capability: Option<&str>,
        presenting_agent_did: &str,
        proof_tokens: Option<Vec<String>>,
    ) -> PyResult<PyCapabilityValidation> {
        let bi = &*self.inner;
        validate::validate_context_id(context_id)?;
        validate::validate_ucan_token(token)?;
        // An empty/whitespace-only capability means "no challenge" — treat it as
        // absent rather than validating it as a (non-empty) URI.
        let capability = capability.filter(|c| !c.trim().is_empty());
        if let Some(cap) = capability {
            validate::validate_capability_uri(cap)?;
        }
        // FAIL CLOSED (no silent security default): the presenting agent DID is a
        // REQUIRED parameter (never defaulted to the token's own `aud`, which
        // would make the step-5 audience check tautological and inflate trust for
        // a token addressed to someone else). Trimmed for input hygiene (parity
        // with NAPI); `validate_did` then rejects an empty or whitespace-only
        // value (not a valid `did:` string).
        let presenting_agent_did = presenting_agent_did.trim();
        validate::validate_did(presenting_agent_did)?;
        if let Some(ref tokens) = proof_tokens {
            for t in tokens {
                validate::validate_ucan_token(t)?;
            }
        }
        // Step 1: Parse the UCAN token using scp-core's parser.
        let parsed_token = parse_ucan(token).map_err(ScpPyError::from)?;

        // Parse the optional required capability URI. `None` => intrinsic-validity
        // diagnostic (no invoked-capability grant-match challenge).
        let required_cap: Option<CapabilityUri> = capability
            .map(|cap| {
                cap.parse::<CapabilityUri>().map_err(|e: CoreUcanError| {
                    ScpPyError::ucan(format!("invalid capability URI '{cap}': {e}"))
                })
            })
            .transpose()?;

        // The presenting agent DID is a required parameter, validated above.
        let agent_did = presenting_agent_did;

        // Build proof resolver from optional proof tokens.
        let proof_resolver = build_proof_resolver(proof_tokens.as_deref())?;

        // Run the read-only evaluation pipeline within the context runtime.
        // evaluate_ucan takes `&ValidationContext` and never records the nonce,
        // so a read-only probe of the nonce tracker suffices.
        let result = crate::runtime::with_context(bi, context_id, |rt| {
            let production_resolver = crate::runtime::did_resolver(bi);
            let did_resolver =
                DispatchDidResolver::new(production_resolver.map(std::convert::AsRef::as_ref));
            let revocation_checker = BridgeRevocationChecker {
                revocation_list: &rt.revocation_list,
            };
            let mut nonce_adapter = BridgeNonceTracker {
                inner: &mut rt.nonce_tracker,
            };

            let ctx = ValidationContext {
                did_resolver: &did_resolver,
                nonce_tracker: &mut nonce_adapter,
                revocation_checker: &revocation_checker,
                proof_resolver: &proof_resolver,
                ceiling: &rt.ceiling_strings,
                context_creator_did: &rt.creator_did,
                presenting_agent_did: agent_did,
                clock_skew_tolerance_secs: DEFAULT_CLOCK_SKEW_TOLERANCE_SECS,
                clock: &scp_clock::SystemClock,
            };

            Ok(evaluate_ucan(&parsed_token, required_cap.as_ref(), &ctx))
        })?;

        Ok(PyCapabilityValidation::from(result))
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
    #[pyo3(signature = (context_id, member_did, capabilities, proofs=None))]
    #[allow(clippy::needless_pass_by_value)] // PyO3 requires owned Vec/Option<Vec> for method arguments.
    pub fn ucan_mint(
        &self,
        context_id: &str,
        member_did: &str,
        capabilities: Vec<String>,
        proofs: Option<Vec<String>>,
    ) -> PyResult<PyUcanToken> {
        let bi = &*self.inner;
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
        let creator_did =
            crate::runtime::with_context(bi, context_id, |rt| Ok(rt.creator_did.clone()))?;

        let rt = crate::runtime()?;
        let context_id_owned = context_id.to_owned();
        let _nonce = scp_core::crypto::ucan::nonce::generate_nonce(&scp_clock::SystemClock);

        // Mint using real scp_core::mint_ucan with Ed25519 signing via
        // the retained KeyCustody. See SCP-214 criterion 7.
        let token = crate::runtime::with_identity(bi, &creator_did, |entry| {
            // Get the ceiling from the context runtime for mint-time enforcement (#339).
            let ceiling_strings = crate::runtime::with_context(bi, &context_id_owned, |rt| {
                Ok(rt.ceiling_strings.clone())
            })?;

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
                mint_ucan(&params, entry.custody.as_ref(), &scp_clock::SystemClock).await
            });
            result.map_err(ScpPyError::from)
        })?;

        // Convert capability attestations to URI strings for Python.
        let capability_uris: Vec<String> =
            token.payload.att.iter().map(|a| a.with.clone()).collect();

        Ok(PyUcanToken {
            token_id: token.payload.nnc.clone(),
            issuer: token.payload.iss.clone(),
            audience: token.payload.aud.clone(),
            capabilities: capability_uris,
            // Unix timestamp seconds fit in f64 mantissa for centuries.
            #[allow(clippy::cast_precision_loss)]
            expires_at: Some(token.payload.exp as f64),
            encoded: token.encoded,
            proofs: token.payload.prf,
            instance_id: scp_ffi_common::bridge_instance::UNSET_INSTANCE_ID,
        }
        .stamp_instance_id(bi))
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
    // PyO3 requires owned types for method arguments.
    #[allow(clippy::needless_pass_by_value)]
    pub fn ucan_delegate(
        &self,
        context_id: &str,
        delegator_did: &str,
        delegatee_did: &str,
        parent_token: &str,
        capabilities: Vec<String>,
    ) -> PyResult<PyUcanToken> {
        let bi = &*self.inner;
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
            crate::runtime::with_context(bi, context_id, |rt| Ok(rt.ceiling_strings.clone()))?;

        let token = crate::runtime::with_identity(bi, delegator_did, |entry| {
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
                delegate_ucan(&params, entry.custody.as_ref(), &scp_clock::SystemClock).await
            });
            result.map_err(ScpPyError::from)
        })?;

        let capability_uris: Vec<String> =
            token.payload.att.iter().map(|a| a.with.clone()).collect();

        Ok(PyUcanToken {
            token_id: token.payload.nnc.clone(),
            issuer: token.payload.iss.clone(),
            audience: token.payload.aud.clone(),
            // Unix timestamp seconds fit in f64 mantissa for centuries.
            capabilities: capability_uris,
            #[allow(clippy::cast_precision_loss)]
            expires_at: Some(token.payload.exp as f64),
            encoded: token.encoded,
            proofs: token.payload.prf,
            instance_id: scp_ffi_common::bridge_instance::UNSET_INSTANCE_ID,
        }
        .stamp_instance_id(bi))
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
    pub fn ucan_revoke(&self, context_id: &str, token: &str, revoker_did: &str) -> PyResult<()> {
        let bi = &*self.inner;
        validate::validate_context_id(context_id)?;
        validate::validate_ucan_token(token)?;
        validate::validate_did(revoker_did)?;

        // Parse the token to extract the issuer DID for authorization.
        let parsed = parse_ucan(token).map_err(ScpPyError::from)?;

        crate::runtime::with_context(bi, context_id, |rt| {
            use crate::bridge_adapters::{
                BridgeRevocationAuthorizer, BridgeRevocationDistributor,
                BridgeRevocationEventLogger,
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

        // Spec §19.5: when the revoked token is a spending UCAN, its revocation
        // must ALSO reach the owning context actor's Class-S
        // `revoked_spending_ucan_cids` set — the authoritative paid-action gate
        // consulted by `validate_spending_ucan_signed`. The `RevocationList`
        // written above only gates the general `validate_ucan` presentation
        // boundaries; without this second write a revoked spending UCAN would
        // keep authorizing payments. Non-spending tokens are unaffected (they
        // touch only the `RevocationList`, as before).
        if scp_core::crypto::ucan::spending::is_spending_ucan(&parsed) {
            use pyo3::exceptions::PyRuntimeError;

            let rt = crate::runtime()?;
            let sup = crate::runtime::supervisor(bi)
                .map_err(|e| PyRuntimeError::new_err(e.to_string()))?
                .clone();
            let ctx = context_id.to_owned();
            let encoded_token = token.to_owned();
            let revoker = revoker_did.to_owned();
            rt.block_on(async move {
                sup.revoke_spending_ucan(&ctx, &encoded_token, revoker)
                    .await
            })
            .map_err(ScpPyError::from)?;
        }

        Ok(())
    }
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

/// Registers UCAN bridge classes on the `_scp_core` module.
///
/// Post-migration (Phase 4 PR 4 sub-slice C) UCAN operations are exposed as
/// methods on `SCP` (see the `#[pymethods]` block above) and registered
/// automatically with the class. Only [`PyUcanToken`] still requires manual
/// class registration here.
///
/// # Errors
///
/// Returns `PyErr` if registration of classes fails.
pub fn register_ucan(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyUcanToken>()?;
    m.add_class::<PyCapabilityValidation>()?;
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
// The scp-core validation pipeline (which `ucan_validate` delegates to)
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

    use scp_clock::Clock;
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
        use scp_clock::SystemClock;

        let mut tracker =
            scp_core::crypto::ucan::nonce::NonceTracker::new("ctx-test".to_owned(), SystemClock);

        let now_millis = scp_clock::SystemClock.now_millis();
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

    // -----------------------------------------------------------------------
    // ucan_evaluate fail-closed audience (no silent self-default)
    // -----------------------------------------------------------------------

    /// An empty/whitespace `presenting_agent_did` is rejected by `validate_did`
    /// (it is not a valid `did:` string). Omission is impossible — the parameter
    /// is a required non-`Option` `&str`, so the type system enforces presence.
    /// The check fires before context lookup, so no registered context is needed.
    #[test]
    fn ucan_evaluate_rejects_empty_presenting_agent_did() {
        let scp = crate::scp::PyScp::new_in_memory_for_test();
        let result = scp.ucan_evaluate("ctx-1", "header.payload.sig", None, "   ", None);
        assert!(
            result.is_err(),
            "ucan_evaluate must fail closed when presenting_agent_did is empty"
        );
    }

    // -----------------------------------------------------------------------
    // ucan_validate fail-closed audience (no silent self-default) — symmetric
    // with the diagnostic `ucan_evaluate` gate above.
    // -----------------------------------------------------------------------

    /// An empty/whitespace `presenting_agent_did` is rejected by `validate_did`
    /// on the enforcing gate. Omission is impossible — the parameter is a required
    /// non-`Option` `&str`, so the type system enforces presence.
    #[test]
    fn ucan_validate_rejects_empty_presenting_agent_did() {
        let scp = crate::scp::PyScp::new_in_memory_for_test();
        let result =
            scp.ucan_validate("ctx-1", "header.payload.sig", "messages:write", "   ", None);
        assert!(
            result.is_err(),
            "ucan_validate must fail closed when presenting_agent_did is empty"
        );
    }
}
