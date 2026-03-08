//! `wasm-bindgen` bridge for trust engine operations.
//!
//! Exposes trust engine operations to JavaScript (browser target):
//!
//! - [`trust_query_score`] — Query participation-based trust data.
//! - [`trust_verify_attestation`] — Verify an attestation (throws — requires WebCrypto).
//! - [`trust_create_challenge`] — Create a challenge request.
//! - [`trust_verify_response`] — Verify a challenge response (throws — requires WebCrypto).
//!
//! # WASM constraints
//!
//! This bridge does NOT depend on `scp-core` (tokio multi-thread incompatible
//! with `wasm32-unknown-unknown`). Trust functions that require Ed25519
//! signature verification (`trust_verify_attestation`, `trust_verify_response`)
//! throw `SCP-TRUST-800x` errors to prevent silent false negatives — the
//! TypeScript wrapper layer must implement these via `WebCrypto`. The query
//! and challenge creation functions work fully using WASM-local state.
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
/// **Always throws** `SCP-TRUST-8001` — full attestation verification
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
///     // e.message contains "[SCP-TRUST-8001] trust error: ..."
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
            code: "SCP-TRUST-8001".to_owned(),
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
/// # JS usage
///
/// ```js
/// const resultJson = await trust_create_challenge("did:key:target");
/// const result = JSON.parse(resultJson);
/// console.log(result.challenge_id);
/// ```
#[wasm_bindgen]
pub fn trust_create_challenge(target_did: String) -> Promise {
    future_to_promise(async move {
        if target_did.is_empty() {
            return Err(ScpWasmError::validation("target DID must not be empty"));
        }

        let challenge_id = uuid::Uuid::new_v4().to_string();

        let result = serde_json::json!({
            "challenge_id": challenge_id,
            "challenge_json": serde_json::json!({
                "challenge_id": challenge_id,
                "challenge_type": "SchemaValidation",
                "challenger_did": "did:key:ephemeral-challenger",
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
/// **Always throws** `SCP-TRUST-8002` — full response verification
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
///     // e.message contains "[SCP-TRUST-8002] trust error: ..."
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
            code: "SCP-TRUST-8002".to_owned(),
        }
        .into_js()
        .into())
    })
}
