//! `wasm-bindgen` bridge for trust engine operations.
//!
//! Exposes trust engine operations to JavaScript (browser target):
//!
//! - `trust_query_score` — Query participation-based trust data.
//! - `trust_verify_attestation` — Verify an attestation (throws — requires `WebCrypto`).
//! - `trust_create_challenge` — Create a challenge request.
//! - `trust_verify_response` — Verify a challenge response (throws — requires `WebCrypto`).
//! - `verify_participation_requirements` — Verify a DID meets participation requirements.
//! - `aggregate_trust_input` — Aggregate trust inputs (throws — requires native bridge).
//!
//! # WASM constraints
//!
//! This bridge does NOT depend on `scp-core` (tokio multi-thread incompatible
//! with `wasm32-unknown-unknown`). Trust functions that require Ed25519
//! signature verification (`trust_verify_attestation`, `trust_verify_response`)
//! throw `SCP-TRUST-800x` errors to prevent silent false negatives — the
//! TypeScript wrapper layer must implement these via `WebCrypto`. The query
//! and challenge creation functions work fully using WASM-local state.
//! `aggregate_trust_input` requires the full scp-core trust pipeline and
//! must be implemented via the native (NAPI) bridge.
//!
//! See ADR-022 in `.docs/adrs/phase-4.md`.

use js_sys::Promise;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::future_to_promise;

use crate::error::ScpWasmError;

// ---------------------------------------------------------------------------
// trust_query_score
// ---------------------------------------------------------------------------

/// Queries participation-based trust data for a DID within a context.
///
/// Returns a JSON string with `message_count`, `governance_count`, and
/// `composite_score` fields.
///
/// # JS usage
///
/// ```js
/// const scoreJson = await trust_query_score("did:key:alice", "ctx-1");
/// const score = JSON.parse(scoreJson);
/// console.log(score.message_count);    // 0
/// console.log(score.composite_score);  // 0.0
/// ```
#[wasm_bindgen]
pub fn trust_query_score(did: String, context_id: String) -> Promise {
    future_to_promise(async move {
        if did.is_empty() {
            return Err(ScpWasmError::validation("DID must not be empty"));
        }
        if context_id.is_empty() {
            return Err(ScpWasmError::validation("context_id must not be empty"));
        }

        let (message_count, governance_count) =
            crate::runtime::query_trust_event_counts(&context_id, &did);

        let total = message_count + governance_count;
        #[allow(clippy::cast_precision_loss)]
        let composite_score = (1.0 + total as f64).log10().min(1.0);

        let result = serde_json::json!({
            "message_count": message_count,
            "governance_count": governance_count,
            "composite_score": composite_score,
        });

        Ok(JsValue::from_str(&result.to_string()))
    })
}

// ---------------------------------------------------------------------------
// trust_verify_attestation
// ---------------------------------------------------------------------------

/// Verifies an attestation.
///
/// **Always throws** `SCP-VALID-7070` — full attestation verification
/// requires Ed25519 signature verification via `WebCrypto`, which must be
/// implemented in the TypeScript wrapper layer. This function validates
/// the JSON structure but rejects with an explicit error rather than
/// returning a silent `false`.
///
/// # JS usage
///
/// ```js
/// try {
///     await trust_verify_attestation(attestationJson);
/// } catch (e) {
///     // e.message contains "[SCP-VALID-7070] trust error: ..."
///     // Implement verification via WebCrypto in the TS wrapper.
/// }
/// ```
#[wasm_bindgen]
pub fn trust_verify_attestation(attestation_json: String) -> Promise {
    future_to_promise(async move {
        if attestation_json.is_empty() {
            return Err(ScpWasmError::validation(
                "attestation JSON must not be empty",
            ));
        }

        // Parse to validate JSON structure.
        let _: serde_json::Value = serde_json::from_str(&attestation_json).map_err(|e| {
            JsValue::from_str(&format!(
                "[SCP-VALID-7012] failed to parse attestation JSON: {e}"
            ))
        })?;

        // Signature verification requires `WebCrypto` (Ed25519) — must be
        // implemented in the TypeScript wrapper layer. Throw an explicit error
        // so callers cannot silently consume a false negative.
        Err(ScpWasmError::Trust {
            message: "attestation signature verification requires WebCrypto \
                      — implement in TypeScript wrapper layer"
                .to_owned(),
            code: "SCP-VALID-7070".to_owned(),
        }
        .into_js()
        .into())
    })
}

// ---------------------------------------------------------------------------
// trust_create_challenge
// ---------------------------------------------------------------------------

/// Creates a challenge request for capability verification.
///
/// Generates a UUID v4 challenge ID and returns a JSON object with the
/// challenge metadata. The challenge is not signed (signing requires
/// `WebCrypto` Ed25519 from the TypeScript wrapper).
///
/// # Arguments
///
/// - `challenger_did` — DID of the entity issuing the challenge.
/// - `target_did` — DID of the entity being challenged.
///
/// # JS usage
///
/// ```js
/// const resultJson = await trust_create_challenge("did:key:challenger", "did:key:target");
/// const result = JSON.parse(resultJson);
/// console.log(result.challenge_id);
/// ```
#[wasm_bindgen]
pub fn trust_create_challenge(challenger_did: String, target_did: String) -> Promise {
    future_to_promise(async move {
        if challenger_did.is_empty() {
            return Err(ScpWasmError::validation("challenger DID must not be empty"));
        }
        if !challenger_did.starts_with("did:") {
            return Err(ScpWasmError::validation(
                "challenger DID must start with 'did:'",
            ));
        }
        if challenger_did
            .chars()
            .any(|c| c < '\u{0020}' || c == '\u{007F}')
        {
            return Err(ScpWasmError::validation(
                "challenger DID must not contain control characters",
            ));
        }
        if target_did.is_empty() {
            return Err(ScpWasmError::validation("target DID must not be empty"));
        }

        let challenge_id = uuid::Uuid::new_v4().to_string();

        let result = serde_json::json!({
            "challenge_id": challenge_id,
            "challenge_json": serde_json::json!({
                "challenge_id": challenge_id,
                "challenge_type": "SchemaValidation",
                "challenger_did": challenger_did,
                "subject_did": target_did,
                "capability_uri": "scp:capability:schema-validation",
                "parameters": {},
                "timeout_secs": 300,
                "signature": [],
            }).to_string(),
        });

        Ok(JsValue::from_str(&result.to_string()))
    })
}

// ---------------------------------------------------------------------------
// trust_verify_response
// ---------------------------------------------------------------------------

/// Verifies a challenge response.
///
/// **Always throws** `SCP-VALID-7071` — full response verification
/// requires Ed25519 signature verification via `WebCrypto`, which must be
/// implemented in the TypeScript wrapper layer. This function validates
/// the JSON structure but rejects with an explicit error rather than
/// returning a silent `false`.
///
/// # JS usage
///
/// ```js
/// try {
///     await trust_verify_response(challengeJson, responseJson);
/// } catch (e) {
///     // e.message contains "[SCP-VALID-7071] trust error: ..."
///     // Implement verification via WebCrypto in the TS wrapper.
/// }
/// ```
#[wasm_bindgen]
pub fn trust_verify_response(challenge_json: String, response_json: String) -> Promise {
    future_to_promise(async move {
        if challenge_json.is_empty() || response_json.is_empty() {
            return Err(ScpWasmError::validation(
                "challenge and response JSON must not be empty",
            ));
        }

        // Parse to validate JSON structure.
        let _: serde_json::Value = serde_json::from_str(&challenge_json).map_err(|e| {
            JsValue::from_str(&format!(
                "[SCP-VALID-7016] failed to parse challenge JSON: {e}"
            ))
        })?;
        let _: serde_json::Value = serde_json::from_str(&response_json).map_err(|e| {
            JsValue::from_str(&format!(
                "[SCP-VALID-7017] failed to parse response JSON: {e}"
            ))
        })?;

        // Signature verification requires `WebCrypto` — must be implemented in
        // the TypeScript wrapper layer. Throw an explicit error so callers
        // cannot silently consume a false negative.
        Err(ScpWasmError::Trust {
            message: "challenge response signature verification requires WebCrypto \
                      — implement in TypeScript wrapper layer"
                .to_owned(),
            code: "SCP-VALID-7071".to_owned(),
        }
        .into_js()
        .into())
    })
}

// ---------------------------------------------------------------------------
// verify_participation_requirements (SCP-BA-004)
// ---------------------------------------------------------------------------

/// Local re-implementation of `scp_core::trust::ParticipationFact` for WASM.
///
/// Matches the Rust serde representation exactly (unit enum variants).
#[derive(serde::Deserialize)]
enum WasmParticipationFact {
    ParticipationDuration,
    GovernanceActionsAgainst,
    GovernanceActionsBy,
    ToolInvocationCount,
    ContextCreationCount,
    RoleProgressionCount,
    AttestationCount,
}

impl WasmParticipationFact {
    fn extract_value(&self, profile: &WasmParticipationProfile) -> u64 {
        match self {
            Self::ParticipationDuration => profile.participation_duration_secs,
            Self::GovernanceActionsAgainst => profile.governance_actions_against,
            Self::GovernanceActionsBy => profile.governance_actions_by,
            Self::ToolInvocationCount => profile.tool_invocation_count,
            Self::ContextCreationCount => profile.context_creation_count,
            Self::RoleProgressionCount => profile.role_progression_count,
            Self::AttestationCount => profile.attestation_count,
        }
    }
}

/// Local re-implementation of `scp_core::trust::ParticipationThreshold` for WASM.
///
/// Matches the Rust serde representation (externally tagged enum with value).
#[derive(serde::Deserialize)]
enum WasmParticipationThreshold {
    GreaterThan(u64),
    LessThan(u64),
    AtLeast(u64),
    AtMost(u64),
    Equals(u64),
}

impl WasmParticipationThreshold {
    fn is_satisfied(&self, value: u64) -> bool {
        match self {
            Self::GreaterThan(threshold) => value > *threshold,
            Self::LessThan(threshold) => value < *threshold,
            Self::AtLeast(threshold) => value >= *threshold,
            Self::AtMost(threshold) => value <= *threshold,
            Self::Equals(threshold) => value == *threshold,
        }
    }
}

/// Local re-implementation of `scp_core::trust::RequireParticipation` for WASM.
#[derive(serde::Deserialize)]
struct WasmRequireParticipation {
    fact: WasmParticipationFact,
    threshold: WasmParticipationThreshold,
    max_age_secs: u64,
    min_contexts: u32,
}

/// Domain separator for participation profile signing (must match
/// `scp_core::trust::participation::DOMAIN_PARTICIPATION_V1`).
const DOMAIN_PARTICIPATION_V1: &[u8] = b"SCP-PARTICIPATION-V1:";

/// Local re-implementation of `scp_core::trust::ParticipationProfile` for WASM.
#[derive(serde::Deserialize)]
struct WasmParticipationProfile {
    subject_did: String,
    participation_duration_secs: u64,
    governance_actions_against: u64,
    governance_actions_by: u64,
    tool_invocation_count: u64,
    context_creation_count: u64,
    role_progression_count: u64,
    attestation_count: u64,
    updated_at: u64,
    event_log_root: Vec<u8>,
    signer_public_key: Vec<u8>,
    signature: Vec<u8>,
}

impl WasmParticipationProfile {
    /// Returns the deterministic signable bytes for this profile.
    ///
    /// Must be algorithm-identical to `scp_core::trust::ParticipationProfile::signable_bytes`.
    /// See that function for the byte layout specification.
    fn signable_bytes(&self) -> Vec<u8> {
        let did_bytes = self.subject_did.as_bytes();
        let capacity = DOMAIN_PARTICIPATION_V1.len() + 4 + did_bytes.len() + 64 + 64;
        let mut buf = Vec::with_capacity(capacity);

        buf.extend_from_slice(DOMAIN_PARTICIPATION_V1);

        #[allow(clippy::cast_possible_truncation)]
        buf.extend_from_slice(&(did_bytes.len() as u32).to_be_bytes());
        buf.extend_from_slice(did_bytes);

        buf.extend_from_slice(&self.participation_duration_secs.to_be_bytes());
        buf.extend_from_slice(&self.governance_actions_against.to_be_bytes());
        buf.extend_from_slice(&self.governance_actions_by.to_be_bytes());
        buf.extend_from_slice(&self.tool_invocation_count.to_be_bytes());
        buf.extend_from_slice(&self.context_creation_count.to_be_bytes());
        buf.extend_from_slice(&self.role_progression_count.to_be_bytes());
        buf.extend_from_slice(&self.attestation_count.to_be_bytes());
        buf.extend_from_slice(&self.updated_at.to_be_bytes());

        buf.extend_from_slice(&self.event_log_root);
        buf.extend_from_slice(&self.signer_public_key);

        buf
    }
}

/// Verifies participation profiles against admission requirements.
///
/// Both inputs are JSON strings:
/// - `profile_json`: JSON array of `ParticipationProfile` objects matching
///   the `scp-core` type (with `subject_did`, fact count fields, `updated_at`,
///   `event_log_root`, `signer_public_key`, `signature`).
/// - `requirements_json`: JSON array of `RequireParticipation` objects
///   matching the `scp-core` type (with `fact`, `threshold`, `max_age_secs`,
///   `min_contexts`).
///
/// Returns `true` if all requirements are satisfied. Throws an error with
/// a diagnostic message if any requirement fails or if the JSON is malformed.
///
/// Performs full Ed25519 signature verification on all profiles (matching
/// `scp_core::trust::verify_participation_requirements`), followed by
/// freshness, threshold, and `min_contexts` checks.
///
/// See §7.3.2.1.
///
/// # Errors
///
/// Returns `JsValue` error if JSON parsing fails, if any signature is
/// invalid, or if any participation requirement is not satisfied (with a
/// diagnostic message).
///
/// # JS usage
///
/// ```js
/// const ok = verify_participation_requirements(
///     '[{"subject_did":"did:dht:z6MkAlice","participation_duration_secs":3600,...}]',
///     '[{"fact":"ParticipationDuration","threshold":{"AtLeast":100},"max_age_secs":3600,"min_contexts":1}]'
/// );
/// // ok === true on success, throws on failure
/// ```
#[wasm_bindgen]
pub fn verify_participation_requirements(
    profile_json: String,
    requirements_json: String,
) -> Result<bool, JsValue> {
    use ed25519_dalek::{Signature, VerifyingKey};

    let profiles: Vec<WasmParticipationProfile> =
        serde_json::from_str(&profile_json).map_err(|e| {
            ScpWasmError::validation(&format!("failed to parse participation profiles JSON: {e}"))
        })?;

    let requirements: Vec<WasmRequireParticipation> = serde_json::from_str(&requirements_json)
        .map_err(|e| {
            ScpWasmError::validation(&format!(
                "failed to parse participation requirements JSON: {e}"
            ))
        })?;

    // Step 1: Verify all signatures up front. Any invalid signature is a
    // hard failure regardless of which requirements use it. Matches
    // scp-core's verify_participation_requirements step 1.
    for profile in &profiles {
        let pk_bytes: [u8; 32] = profile
            .signer_public_key
            .as_slice()
            .try_into()
            .map_err(|_| {
                ScpWasmError::validation(&format!(
                    "signer_public_key must be 32 bytes, got {}",
                    profile.signer_public_key.len()
                ))
            })?;

        let verifying_key = VerifyingKey::from_bytes(&pk_bytes).map_err(|e| {
            ScpWasmError::validation(&format!(
                "invalid signer public key for {}: {e}",
                &profile.subject_did
            ))
        })?;

        let sig_bytes: [u8; 64] = profile.signature.as_slice().try_into().map_err(|_| {
            ScpWasmError::validation(&format!(
                "signature must be 64 bytes, got {}",
                profile.signature.len()
            ))
        })?;

        let signature = Signature::from_bytes(&sig_bytes);
        let signable = profile.signable_bytes();

        verifying_key
            .verify_strict(&signable, &signature)
            .map_err(|e| {
                ScpWasmError::validation(&format!(
                    "participation profile signature verification failed for {}: {e}",
                    &profile.subject_did
                ))
            })?;
    }

    // Step 2: Check each requirement independently.
    // Current time in seconds since UNIX epoch (using js_sys::Date for WASM).
    #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
    let current_time = (js_sys::Date::now() / 1000.0) as u64;

    for requirement in &requirements {
        // Freshness: filter out stale profiles.
        let fresh_profiles: Vec<&WasmParticipationProfile> = profiles
            .iter()
            .filter(|p| {
                let age = current_time.saturating_sub(p.updated_at);
                age <= requirement.max_age_secs
            })
            .collect();

        // Threshold + min_contexts: count distinct signers only from profiles
        // that satisfy the threshold. A profile that is fresh but below the
        // threshold should NOT contribute to the min_contexts count.
        let mut distinct_signers = std::collections::HashSet::new();
        for p in &fresh_profiles {
            let value = requirement.fact.extract_value(p);
            if requirement.threshold.is_satisfied(value) {
                distinct_signers.insert(&p.signer_public_key);
            }
        }

        if distinct_signers.is_empty() {
            return Err(ScpWasmError::validation(
                "participation admission verification failed: threshold not met",
            ));
        }

        #[allow(clippy::cast_possible_truncation)]
        if (distinct_signers.len() as u32) < requirement.min_contexts {
            return Err(ScpWasmError::validation(&format!(
                "participation admission verification failed: need {} distinct source contexts, got {}",
                requirement.min_contexts,
                distinct_signers.len()
            )));
        }
    }

    Ok(true)
}

// ---------------------------------------------------------------------------
// aggregate_trust_input
// ---------------------------------------------------------------------------

/// Aggregates all trust engine layers into a single `TrustInput`.
///
/// **Always throws** `SCP-VALID-7072` — full trust aggregation requires the
/// scp-core trust pipeline (participation record computation, attestation
/// cache with TTL-based refresh, threshold counting) which depends on tokio
/// multi-thread and cannot run in `wasm32-unknown-unknown`. Use the native
/// (NAPI) bridge for trust aggregation.
///
/// # JS usage
///
/// ```js
/// try {
///     await aggregate_trust_input(contextId, subjectDid, ...);
/// } catch (e) {
///     // e.message contains "[SCP-VALID-7072] trust error: ..."
///     // Use the native (NAPI) bridge instead.
/// }
/// ```
#[wasm_bindgen]
#[allow(clippy::too_many_arguments)]
pub fn aggregate_trust_input(
    _context_id: String,
    _subject_did: String,
    _events_json: String,
    _merkle_root_json: String,
    _consequence_rules_json: String,
    _threshold_requirements_json: String,
    _attestor_sets_json: String,
    _cached_attestations_json: String,
    _challenge_results_json: String,
) -> Promise {
    future_to_promise(async move {
        Err(ScpWasmError::Trust {
            message: "trust aggregation requires the full scp-core pipeline \
                      — use the native (NAPI) bridge instead of the WASM bridge"
                .to_owned(),
            code: "SCP-VALID-7072".to_owned(),
        }
        .into_js()
        .into())
    })
}
