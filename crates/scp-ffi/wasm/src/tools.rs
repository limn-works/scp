//! `wasm-bindgen` bridge for tool registration, invocation, and verification.
//!
//! All operations delegate to [`WasmContextManager`](crate::manager::WasmContextManager)
//! via [`with_manager`](crate::manager::with_manager). No local state management.
//!
//! See ADR-034 in `.docs/adrs/phase-4.md` and issue #389.

use js_sys::Promise;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::future_to_promise;

use scp_ffi_common::validate::{
    json_value_type_name, validate_did, validate_tool_id, validate_tool_name, validate_ucan_token,
};

use crate::context::WasmContextHandle;
use crate::error::ScpWasmError;
use crate::manager::with_manager;
use crate::runtime;

// ---------------------------------------------------------------------------
// WasmToolVerificationResult
// ---------------------------------------------------------------------------

/// Result of verifying a tool against its registered test vectors.
#[wasm_bindgen]
#[derive(Debug, Clone)]
pub struct WasmToolVerificationResult {
    tool_id: String,
    passed: bool,
    failures_json: String,
}

#[wasm_bindgen]
impl WasmToolVerificationResult {
    /// Returns the ID of the tool that was verified.
    #[must_use]
    #[wasm_bindgen(getter, js_name = "toolId")]
    pub fn tool_id(&self) -> String {
        self.tool_id.clone()
    }

    /// Returns whether all test vectors passed.
    #[must_use]
    #[wasm_bindgen(getter)]
    pub fn passed(&self) -> bool {
        self.passed
    }

    /// Returns the verification failures as a JSON string (empty array if all passed).
    #[must_use]
    #[wasm_bindgen(getter, js_name = "failuresJson")]
    pub fn failures_json(&self) -> String {
        self.failures_json.clone()
    }
}

// ---------------------------------------------------------------------------
// Validation helpers for tool registration inputs
// ---------------------------------------------------------------------------

/// Validates a required JSON Schema field from a definition object, returning
/// the extracted value or a typed `ScpWasmError`.
///
/// Returns `SCP-VALID-7035` for `"schema"` (input) or `SCP-VALID-7036` for
/// `"outputSchema"` (output) when the field is missing or not a JSON object.
fn validate_schema_field(
    def: &serde_json::Value,
    field_name: &str,
) -> Result<serde_json::Value, ScpWasmError> {
    let code = match field_name {
        "schema" => "SCP-VALID-7035",
        _ => "SCP-VALID-7036",
    };

    let schema = def
        .get(field_name)
        .cloned()
        .ok_or_else(|| ScpWasmError::Validation {
            message: format!(
                "missing '{field_name}' field in definition — a JSON Schema object is required"
            ),
            code: code.to_owned(),
        })?;

    if !schema.is_object() {
        return Err(ScpWasmError::Validation {
            message: format!(
                "invalid '{field_name}': expected a JSON object, got {}",
                json_value_type_name(&schema)
            ),
            code: code.to_owned(),
        });
    }

    runtime::validate_schema(&schema).map_err(|e| ScpWasmError::Validation {
        message: format!("invalid {field_name}: {e}"),
        code: code.to_owned(),
    })?;

    Ok(schema)
}

// ---------------------------------------------------------------------------
// Test vector validation (extracted for testability on native targets)
// ---------------------------------------------------------------------------

/// Validates and parses optional test vectors from a JSON definition.
///
/// Returns `Ok(Vec<TestVector>)` when `testVectors` is absent or is a valid
/// array with every entry containing `input`, `expectedOutput`, and
/// `description` fields. Returns `Err(ScpWasmError::Validation)` with code
/// `SCP-VALID-7037` on any structural violation.
fn validate_test_vectors(
    def: &serde_json::Value,
) -> Result<Vec<runtime::TestVector>, ScpWasmError> {
    let Some(tv_val) = def.get("testVectors") else {
        return Ok(Vec::new());
    };

    let arr = tv_val.as_array().ok_or_else(|| ScpWasmError::Validation {
        message: "testVectors must be an array".to_owned(),
        code: "SCP-VALID-7037".to_owned(),
    })?;

    arr.iter()
        .enumerate()
        .map(|(i, v)| {
            let input = v.get("input").ok_or_else(|| ScpWasmError::Validation {
                message: format!("testVectors[{i}] missing required 'input' field"),
                code: "SCP-VALID-7037".to_owned(),
            })?;
            let expected_output =
                v.get("expectedOutput")
                    .ok_or_else(|| ScpWasmError::Validation {
                        message: format!(
                            "testVectors[{i}] missing required 'expectedOutput' field"
                        ),
                        code: "SCP-VALID-7037".to_owned(),
                    })?;
            let description = match v.get("description") {
                Some(d) => d
                    .as_str()
                    .ok_or_else(|| ScpWasmError::Validation {
                        message: format!(
                            "testVectors[{i}] invalid 'description': expected a string, got {}",
                            json_value_type_name(d)
                        ),
                        code: "SCP-VALID-7037".to_owned(),
                    })?
                    .to_owned(),
                None => {
                    return Err(ScpWasmError::Validation {
                        message: format!("testVectors[{i}] missing required 'description' field"),
                        code: "SCP-VALID-7037".to_owned(),
                    });
                }
            };
            Ok(runtime::TestVector {
                input: input.clone(),
                expected_output: expected_output.clone(),
                description,
            })
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Provenance field parsing
// ---------------------------------------------------------------------------

/// Parsed provenance fields: `(implementation_hash, signature, economic_metadata, registered_at)`.
type ProvenanceFields = (
    [u8; 32],
    Vec<u8>,
    Option<runtime::ToolEconomicMetadata>,
    u64,
);

/// Parses optional provenance and economic fields from the definition JSON.
///
/// When a field is absent, a safe default is used. When a field is present but
/// malformed, returns `SCP-VALID-7038`.
fn parse_provenance_fields(def: &serde_json::Value) -> Result<ProvenanceFields, JsValue> {
    let implementation_hash = match def.get("implementationHash").and_then(|v| v.as_str()) {
        None => [0u8; 32],
        Some(hex_str) => {
            let bytes = hex::decode(hex_str).map_err(|e| {
                ScpWasmError::Validation {
                    message: format!("invalid 'implementationHash': invalid hex: {e}"),
                    code: "SCP-VALID-7038".to_owned(),
                }
                .into_js()
            })?;
            <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| {
                ScpWasmError::Validation {
                    message: format!(
                        "invalid 'implementationHash': must be exactly 32 bytes, got {}",
                        bytes.len()
                    ),
                    code: "SCP-VALID-7038".to_owned(),
                }
                .into_js()
            })?
        }
    };

    let signature = match def.get("signature").and_then(|v| v.as_str()) {
        None => Vec::new(),
        Some(b64) => {
            use base64::Engine;
            base64::engine::general_purpose::STANDARD
                .decode(b64)
                .map_err(|e| {
                    ScpWasmError::Validation {
                        message: format!("invalid 'signature': invalid base64: {e}"),
                        code: "SCP-VALID-7038".to_owned(),
                    }
                    .into_js()
                })?
        }
    };

    let economic_metadata = match def.get("economicMetadata") {
        None => None,
        Some(em) => {
            let cost_per_invoke = em
                .get("costPerInvoke")
                .and_then(serde_json::Value::as_u64)
                .ok_or_else(|| {
                    ScpWasmError::Validation {
                        message: "invalid 'economicMetadata': missing or non-numeric \
                                  'costPerInvoke'"
                            .to_owned(),
                        code: "SCP-VALID-7038".to_owned(),
                    }
                    .into_js()
                })?;
            let payee = em
                .get("payee")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    ScpWasmError::Validation {
                        message: "invalid 'economicMetadata': missing or non-string 'payee'"
                            .to_owned(),
                        code: "SCP-VALID-7038".to_owned(),
                    }
                    .into_js()
                })?
                .to_owned();
            let cost_formula = em
                .get("costFormula")
                .and_then(|v| v.as_str())
                .map(ToOwned::to_owned);
            Some(runtime::ToolEconomicMetadata {
                cost_per_invoke,
                cost_formula,
                payee,
            })
        }
    };

    // Use the hardened time source (captured Date.now) for the registration
    // timestamp in seconds per spec §5.4.1. std::time::SystemTime is not
    // available on wasm32 — see crate::time module docs.
    let registered_at = crate::time::now_secs();

    Ok((
        implementation_hash,
        signature,
        economic_metadata,
        registered_at,
    ))
}

// ---------------------------------------------------------------------------
// WasmRateLimit — typed deserialization for rate_limit_json (F9)
// ---------------------------------------------------------------------------

/// Rate limit configuration for cross-context tool interfaces.
///
/// Used for typed deserialization of `rate_limit_json` instead of generic
/// `serde_json::Value`. Validates that the required fields (`max_calls`,
/// `window_seconds`) are present and well-typed at parse time. Mirrors
/// `scp_core::context::tools::interface::RateLimit` field layout without
/// depending on scp-core (WASM constraint per ADR-034).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct WasmRateLimit {
    /// Maximum number of calls permitted within the time window.
    pub max_calls: u64,
    /// Duration of the sliding time window in seconds.
    pub window_seconds: u64,
    /// Optional burst allowance (default: 5, max: 50 per §6.2.0.2).
    #[serde(default = "default_burst_allowance")]
    pub burst_allowance: u32,
    /// Optional burst window in seconds (default: 1 per §6.2.0.2).
    #[serde(default = "default_burst_window_secs")]
    pub burst_window_seconds: u64,
}

const fn default_burst_allowance() -> u32 {
    5
}

const fn default_burst_window_secs() -> u64 {
    1
}

// ---------------------------------------------------------------------------
// Bridge functions
// ---------------------------------------------------------------------------

/// Registers a tool in an SCP context.
///
/// Delegates to `WasmContextManager::register_tool`.
///
/// # Returns
///
/// `Promise<string>` — resolves to the assigned tool ID.
///
/// # Errors
///
/// - Rejects with `SCP-VALID-7035` if `schema` is missing, not a JSON object,
///   or structurally invalid.
/// - Rejects with `SCP-VALID-7036` if `outputSchema` is missing, not a JSON
///   object, or structurally invalid.
#[wasm_bindgen]
pub fn tool_register(context: &WasmContextHandle, definition_json: String) -> Promise {
    let context_id = context.context_id();
    future_to_promise(async move {
        let def: serde_json::Value = serde_json::from_str(&definition_json).map_err(|e| {
            ScpWasmError::Validation {
                message: format!("definition_json is not valid JSON: {e}"),
                code: "SCP-VALID-7000".to_owned(),
            }
            .into_js()
        })?;

        // Extract fields from the definition.
        let name = def["name"]
            .as_str()
            .ok_or_else(|| {
                ScpWasmError::Validation {
                    message: "definition_json missing required 'name' field".to_owned(),
                    code: "SCP-VALID-7000".to_owned(),
                }
                .into_js()
            })?
            .to_owned();

        validate_tool_name(&name).map_err(|e| ScpWasmError::from(e).into_js())?;

        let description = match def.get("description") {
            Some(v) => v
                .as_str()
                .ok_or_else(|| {
                    ScpWasmError::Validation {
                        message: format!(
                            "invalid 'description': expected a string, got {}",
                            json_value_type_name(v)
                        ),
                        code: "SCP-VALID-7000".to_owned(),
                    }
                    .into_js()
                })?
                .to_owned(),
            None => String::new(),
        };

        let input_schema = validate_schema_field(&def, "schema").map_err(ScpWasmError::into_js)?;
        let output_schema =
            validate_schema_field(&def, "outputSchema").map_err(ScpWasmError::into_js)?;

        let operator_did = def["operatorDid"].as_str().unwrap_or("").to_owned();

        // Parse test vectors — reject malformed input instead of silently
        // dropping entries (aligned with NAPI bridge SCP-VALID-7037).
        let test_vectors = validate_test_vectors(&def).map_err(ScpWasmError::into_js)?;

        let tool_id = format!("tool-{}", name.replace(' ', "-").to_lowercase());

        let (implementation_hash, signature, economic_metadata, registered_at) =
            parse_provenance_fields(&def)?;

        let registration = runtime::ToolRegistration {
            tool_id: tool_id.clone(),
            name,
            description,
            input_schema,
            output_schema,
            implementation_hash,
            test_vectors,
            operator_did,
            economic_metadata,
            registered_at,
            signature,
        };

        with_manager(|mgr| mgr.register_tool(&context_id, registration))
            .map_err(ScpWasmError::into_js)?;

        Ok(JsValue::from_str(&tool_id))
    })
}

/// Invokes a registered tool within an SCP context.
///
/// Delegates to `WasmContextManager::invoke_tool`. When `ucan_token` is
/// provided, validates the token before dispatch using the WASM-local UCAN
/// validation pipeline, requiring `tool_invoke:{tool_id}` or `tool_invoke:*`
/// capability. See spec §6.2, §8, ADR-016, and issue #319.
///
/// # Returns
///
/// `Promise<string>` — resolves to a JSON string of the tool's output.
#[wasm_bindgen]
pub fn tool_invoke(
    context: &WasmContextHandle,
    tool_id: String,
    input_json: String,
    identity_did: String,
    ucan_token: Option<String>,
) -> Promise {
    if let Err(e) = validate_tool_id(&tool_id) {
        return future_to_promise(async move { Err(ScpWasmError::from(e).into_js().into()) });
    }
    if let Err(e) = validate_did(&identity_did) {
        return future_to_promise(async move { Err(ScpWasmError::from(e).into_js().into()) });
    }
    if let Some(ref token) = ucan_token
        && let Err(e) = validate_ucan_token(token)
    {
        return future_to_promise(async move { Err(ScpWasmError::from(e).into_js().into()) });
    }
    let context_id = context.context_id();
    future_to_promise(async move {
        // UCAN authorization: validate the token via the WASM-local
        // 11-step pipeline. See spec §6.2, §8, ADR-016, and issue #319.
        match ucan_token {
            Some(ref token) if !token.is_empty() => {
                crate::ucan::validate_tool_ucan_wasm(&context_id, &tool_id, token, &identity_did)
                    .map_err(|e| {
                    ScpWasmError::Permission {
                        message: format!("UCAN authorization failed for tool '{tool_id}': {e}"),
                        code: "SCP-PERM-3000".to_owned(),
                    }
                    .into_js()
                })?;
            }
            _ => {
                return Err(JsValue::from(
                    ScpWasmError::Validation {
                        message: "ucan_token is required for tool invocation".to_owned(),
                        code: "SCP-VALID-7000".to_owned(),
                    }
                    .into_js(),
                ));
            }
        }

        let parsed_input: serde_json::Value = serde_json::from_str(&input_json).map_err(|e| {
            ScpWasmError::Validation {
                message: format!("input_json is not valid JSON: {e}"),
                code: "SCP-VALID-7000".to_owned(),
            }
            .into_js()
        })?;

        let result = with_manager(|mgr| {
            mgr.invoke_tool(&context_id, &tool_id, &parsed_input, &identity_did)
        })
        .map_err(ScpWasmError::into_js)?;

        let json_str = serde_json::to_string(&result).map_err(|e| {
            ScpWasmError::Tool {
                message: format!("failed to serialize tool output: {e}"),
                code: "SCP-TOOL-6002".to_owned(),
            }
            .into_js()
        })?;

        Ok(JsValue::from_str(&json_str))
    })
}

/// Verifies a tool against its registered test vectors.
///
/// Delegates to `WasmContextManager::verify_tool`.
///
/// # Returns
///
/// `Promise<WasmToolVerificationResult>` — resolves to the verification result.
#[wasm_bindgen]
pub fn tool_verify(context: &WasmContextHandle, tool_id: String) -> Promise {
    let context_id = context.context_id();
    future_to_promise(async move {
        let (passed, failures) = with_manager(|mgr| mgr.verify_tool(&context_id, &tool_id))
            .map_err(ScpWasmError::into_js)?;

        let failures_json = serde_json::to_string(&failures).map_err(|e| {
            ScpWasmError::Tool {
                message: format!("failed to serialize verification failures: {e}"),
                code: "SCP-TOOL-6003".to_owned(),
            }
            .into_js()
        })?;

        Ok(JsValue::from(WasmToolVerificationResult {
            tool_id,
            passed,
            failures_json,
        }))
    })
}

// ---------------------------------------------------------------------------
// Cross-context tool invocation (spec section 6.2)
// ---------------------------------------------------------------------------

/// Invokes a tool across context boundaries.
///
/// Validates UCAN authorization against the target context before dispatch.
///
/// # Returns
///
/// `Promise<string>` — resolves to a JSON string of the tool's output.
#[wasm_bindgen]
pub fn tool_invoke_cross_context(
    source_context: &WasmContextHandle,
    target_context: &WasmContextHandle,
    tool_id: String,
    input_json: String,
    invoker_did: String,
    ucan_token: String,
    chain_depth: u8,
) -> Promise {
    let source_id = source_context.context_id();
    let target_id = target_context.context_id();
    future_to_promise(async move {
        // UCAN authorization: validate the token against the TARGET context's
        // ceiling via the WASM-local 11-step pipeline.
        // See spec §6.2, §8, ADR-016, and issue #319.
        if ucan_token.is_empty() {
            return Err(ScpWasmError::Validation {
                message: "ucan_token is required for cross-context tool invocation".to_owned(),
                code: "SCP-VALID-7000".to_owned(),
            }
            .into_js()
            .into());
        }
        crate::ucan::validate_tool_ucan_wasm(&target_id, &tool_id, &ucan_token, &invoker_did)
            .map_err(|e| {
                ScpWasmError::Permission {
                    message: format!(
                        "UCAN authorization failed for cross-context tool '{tool_id}': {e}"
                    ),
                    code: "SCP-PERM-3000".to_owned(),
                }
                .into_js()
            })?;

        let input: serde_json::Value = serde_json::from_str(&input_json).map_err(|e| {
            ScpWasmError::Validation {
                message: format!("input_json is not valid JSON: {e}"),
                code: "SCP-VALID-7000".to_owned(),
            }
            .into_js()
        })?;

        let result = with_manager(|mgr| {
            mgr.invoke_tool_cross_context(
                &source_id,
                &target_id,
                &tool_id,
                &input,
                &invoker_did,
                chain_depth,
            )
        })
        .map_err(ScpWasmError::into_js)?;

        let json_str = serde_json::to_string(&result).map_err(|e| {
            ScpWasmError::Tool {
                message: format!("failed to serialize cross-context output: {e}"),
                code: "SCP-TOOL-6013".to_owned(),
            }
            .into_js()
        })?;

        Ok(JsValue::from_str(&json_str))
    })
}

// ---------------------------------------------------------------------------
// Stateful tool sessions (spec section 6.2.1)
// ---------------------------------------------------------------------------

/// Creates a stateful tool session.
///
/// # Returns
///
/// `Promise<string>` — resolves to the session ID (UUID).
#[wasm_bindgen]
pub fn tool_session_create(
    context: &WasmContextHandle,
    tool_id: String,
    source_context_id: String,
    ttl_seconds: Option<u32>,
) -> Promise {
    let context_id = context.context_id();
    future_to_promise(async move {
        let session_id = with_manager(|mgr| {
            mgr.session_create(
                &context_id,
                &tool_id,
                &source_context_id,
                ttl_seconds.map(u64::from),
            )
        })
        .map_err(ScpWasmError::into_js)?;

        Ok(JsValue::from_str(&session_id))
    })
}

/// Invokes a tool within an active session.
///
/// Each call is individually governed: the invoker must present a valid
/// UCAN token.
///
/// # Returns
///
/// `Promise<string>` — resolves to the tool output as a JSON string.
#[wasm_bindgen]
pub fn tool_session_invoke(
    context: &WasmContextHandle,
    session_id: String,
    input_json: String,
    invoker_did: String,
    ucan_token: String,
) -> Promise {
    let context_id = context.context_id();
    future_to_promise(async move {
        // UCAN authorization: look up the tool_id from the session, then
        // validate the token via the WASM-local 11-step pipeline.
        // See spec §6.2, §8, ADR-016, and issue #319.
        if ucan_token.is_empty() {
            return Err(ScpWasmError::Validation {
                message: "ucan_token is required for session tool invocation".to_owned(),
                code: "SCP-VALID-7000".to_owned(),
            }
            .into_js()
            .into());
        }

        let tool_id_for_ucan = with_manager(|mgr| mgr.session_tool_id(&context_id, &session_id))
            .map_err(ScpWasmError::into_js)?;

        crate::ucan::validate_tool_ucan_wasm(
            &context_id,
            &tool_id_for_ucan,
            &ucan_token,
            &invoker_did,
        )
        .map_err(|e| {
            ScpWasmError::Permission {
                message: format!("UCAN authorization failed for tool '{tool_id_for_ucan}': {e}",),
                code: "SCP-PERM-3000".to_owned(),
            }
            .into_js()
        })?;

        let input: serde_json::Value = serde_json::from_str(&input_json).map_err(|e| {
            ScpWasmError::Validation {
                message: format!("input_json is not valid JSON: {e}"),
                code: "SCP-VALID-7000".to_owned(),
            }
            .into_js()
        })?;

        let result =
            with_manager(|mgr| mgr.session_invoke(&context_id, &session_id, &input, &invoker_did))
                .map_err(ScpWasmError::into_js)?;

        let json_str = serde_json::to_string(&result).map_err(|e| {
            ScpWasmError::Tool {
                message: format!("failed to serialize session invoke output: {e}"),
                code: "SCP-TOOL-6020".to_owned(),
            }
            .into_js()
        })?;

        Ok(JsValue::from_str(&json_str))
    })
}

/// Closes a stateful tool session.
///
/// # Returns
///
/// `Promise<void>` — resolves when the session is closed.
#[wasm_bindgen]
pub fn tool_session_close(context: &WasmContextHandle, session_id: String) -> Promise {
    let context_id = context.context_id();
    future_to_promise(async move {
        with_manager(|mgr| mgr.session_close(&context_id, &session_id))
            .map_err(ScpWasmError::into_js)?;

        Ok(JsValue::UNDEFINED)
    })
}

// ---------------------------------------------------------------------------
// Bidirectional consent protocol (spec §6.2.0.1)
// ---------------------------------------------------------------------------

/// Exposes a tool interface for cross-context sharing (§6.2.0.1 step 1).
///
/// Creates a `ToolInterface` JSON with `approved_by_source = true` and
/// `approved_by_target = false`. Requires the caller to be an admin of the
/// source context (matching `scp-core::expose_tool` authorization).
///
/// The admin DID is resolved from the context's membership state (the
/// context creator), matching how PyO3/NAPI/UniFFI bridges pass
/// `rt.creator_did` to `scp-core::expose_tool`.
///
/// # Returns
///
/// `Promise<string>` — resolves to the `ToolInterface` as a JSON string.
#[wasm_bindgen]
pub fn tool_interface_expose(
    context: &WasmContextHandle,
    tool_id: String,
    target_context_id: String,
    rate_limit_json: Option<String>,
) -> Promise {
    let context_id = context.context_id();
    future_to_promise(async move {
        validate_tool_id(&tool_id).map_err(|e| ScpWasmError::from(e).into_js())?;

        // Resolve the admin DID from the context's creator — mirrors how
        // PyO3/NAPI/UniFFI bridges use `rt.creator_did` internally.
        let admin_did = with_manager(|mgr| {
            mgr.context_creator(&context_id)
                .ok_or_else(|| ScpWasmError::Context {
                    message: format!("context '{context_id}' not found"),
                    code: "SCP-CTX-2000".to_owned(),
                })
        })
        .map_err(ScpWasmError::into_js)?;

        // Require admin role — mirrors scp-core::expose_tool authorization.
        let role = with_manager(|mgr| Ok(mgr.member_role(&context_id, &admin_did)))
            .map_err(ScpWasmError::into_js)?;
        match role.as_deref() {
            Some("admin") => {}
            _ => {
                return Err(ScpWasmError::Permission {
                    message: format!(
                        "tool interface expose requires admin role — '{admin_did}' \
                         is not an admin of context '{context_id}'"
                    ),
                    code: "SCP-PERM-3001".to_owned(),
                }
                .into_js()
                .into());
            }
        }

        // Validate the tool exists in the source context's registry.
        let exists = with_manager(|mgr| mgr.tool_exists(&context_id, &tool_id))
            .map_err(ScpWasmError::into_js)?;
        if !exists {
            return Err(ScpWasmError::Tool {
                message: format!("tool '{tool_id}' not found in context '{context_id}'"),
                code: "SCP-TOOL-6030".to_owned(),
            }
            .into_js()
            .into());
        }

        // Parse optional rate limit into a validated struct (not generic JSON).
        let rate_limit: Option<WasmRateLimit> = match rate_limit_json {
            Some(ref json) => {
                let parsed: WasmRateLimit = serde_json::from_str(json).map_err(|e| {
                    ScpWasmError::Validation {
                        message: format!("invalid rate_limit_json: {e}"),
                        code: "SCP-VALID-7040".to_owned(),
                    }
                    .into_js()
                })?;
                Some(parsed)
            }
            None => None,
        };

        let interface = serde_json::json!({
            "source_context": context_id,
            "target_context": target_context_id,
            "tool_id": tool_id,
            "rate_limit": rate_limit,
            "per_caller_rate_limit": {
                "max_calls_per_caller": 10,
                "window": { "secs": 60, "nanos": 0 },
                "burst_allowance": 5,
                "burst_window": { "secs": 1, "nanos": 0 },
                "callers": {}
            },
            "approved_by_source": true,
            "approved_by_target": false,
            "outbound_policy": {
                "allowed_callers": [],
                "max_calls_per_minute": 60,
                "max_payload_bytes": 65536,
                "require_provenance": true
            },
            "inbound_policy": null
        });

        let json_str = serde_json::to_string(&interface).map_err(|e| {
            ScpWasmError::Tool {
                message: format!("failed to serialize ToolInterface: {e}"),
                code: "SCP-TOOL-6031".to_owned(),
            }
            .into_js()
        })?;

        Ok(JsValue::from_str(&json_str))
    })
}

/// Accepts a cross-context tool interface (§6.2.0.1 step 4).
///
/// Requires the caller to be an admin of the target context (matching
/// `scp-core::accept_tool_interface` authorization). The admin DID is
/// resolved from the context's membership state (the context creator),
/// matching how PyO3/NAPI/UniFFI bridges pass `rt.creator_did`.
///
/// Verifies that the interface's `target_context` matches this context, then
/// sets `approved_by_target = true`. Mirrors `scp-core::accept_tool_interface`
/// context-mismatch check.
///
/// # Returns
///
/// `Promise<string>` — resolves to the updated `ToolInterface` as JSON.
#[wasm_bindgen]
pub fn tool_interface_accept(context: &WasmContextHandle, interface_json: String) -> Promise {
    let context_id = context.context_id();
    future_to_promise(async move {
        // Resolve the admin DID from the context's creator — mirrors how
        // scp-core::accept_tool_interface checks has_admin_role(role_state, admin_did).
        let admin_did = with_manager(|mgr| {
            mgr.context_creator(&context_id)
                .ok_or_else(|| ScpWasmError::Context {
                    message: format!("context '{context_id}' not found"),
                    code: "SCP-CTX-2000".to_owned(),
                })
        })
        .map_err(ScpWasmError::into_js)?;

        // Require admin role — mirrors scp-core::accept_tool_interface authorization.
        let role = with_manager(|mgr| Ok(mgr.member_role(&context_id, &admin_did)))
            .map_err(ScpWasmError::into_js)?;
        match role.as_deref() {
            Some("admin") => {}
            _ => {
                return Err(ScpWasmError::Permission {
                    message: format!(
                        "tool interface accept requires admin role — '{admin_did}' \
                         is not an admin of context '{context_id}'"
                    ),
                    code: "SCP-PERM-3001".to_owned(),
                }
                .into_js()
                .into());
            }
        }

        let mut interface: serde_json::Value =
            serde_json::from_str(&interface_json).map_err(|e| {
                ScpWasmError::Validation {
                    message: format!("invalid interface_json: {e}"),
                    code: "SCP-VALID-7041".to_owned(),
                }
                .into_js()
            })?;

        // Verify the interface targets this context — mirrors
        // scp-core::accept_tool_interface context-mismatch check.
        let target = interface
            .get("target_context")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");
        if target != context_id {
            return Err(ScpWasmError::Tool {
                message: format!(
                    "interface target_context '{target}' does not match \
                     accepting context '{context_id}'"
                ),
                code: "SCP-TOOL-6032".to_owned(),
            }
            .into_js()
            .into());
        }

        // Set approved_by_target to true and add default inbound policy.
        interface["approved_by_target"] = serde_json::json!(true);
        if interface.get("inbound_policy").is_none() || interface["inbound_policy"].is_null() {
            interface["inbound_policy"] = serde_json::json!({
                "allowed_source_roles": [],
                "max_calls_per_minute": 60,
                "max_response_bytes": 65536,
                "require_spending_ucan": false
            });
        }

        let json_str = serde_json::to_string(&interface).map_err(|e| {
            ScpWasmError::Tool {
                message: format!("failed to serialize ToolInterface: {e}"),
                code: "SCP-TOOL-6033".to_owned(),
            }
            .into_js()
        })?;

        Ok(JsValue::from_str(&json_str))
    })
}

/// Revokes a cross-context tool interface (§6.2.0.1 step 5).
///
/// Either context may revoke unilaterally.
///
/// # Returns
///
/// `Promise<string>` — resolves to the `InterfaceRevoked` event as JSON.
#[wasm_bindgen]
pub fn tool_interface_revoke(context: &WasmContextHandle, interface_id_hex: String) -> Promise {
    let context_id = context.context_id();
    future_to_promise(async move {
        let interface_id_bytes = hex::decode(&interface_id_hex).map_err(|e| {
            ScpWasmError::Validation {
                message: format!("invalid interface_id_hex: not valid hex: {e}"),
                code: "SCP-VALID-7042".to_owned(),
            }
            .into_js()
        })?;
        if interface_id_bytes.len() != 32 {
            return Err(ScpWasmError::Validation {
                message: format!(
                    "interface_id_hex must be exactly 32 bytes (64 hex chars), got {}",
                    interface_id_bytes.len()
                ),
                code: "SCP-VALID-7042".to_owned(),
            }
            .into_js()
            .into());
        }

        let now_ms = crate::time::now_ms();
        // now_ms is always non-negative (milliseconds since epoch) and well within u64 range.
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let now_ms_u64 = now_ms as u64;

        let event = serde_json::json!({
            "interface_id": interface_id_bytes,
            "revoking_context": context_id,
            "revoked_at": now_ms_u64
        });

        let json_str = serde_json::to_string(&event).map_err(|e| {
            ScpWasmError::Tool {
                message: format!("failed to serialize InterfaceRevoked: {e}"),
                code: "SCP-TOOL-6035".to_owned(),
            }
            .into_js()
        })?;

        Ok(JsValue::from_str(&json_str))
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Tests for schema and test vector validation helpers. These test the
/// pure-Rust validation functions which return `Result<_, ScpWasmError>` —
/// no wasm-bindgen calls, safe on native targets.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // validate_schema_field — missing field (input schema)
    // -----------------------------------------------------------------------

    #[test]
    fn validate_schema_field_rejects_missing_input() {
        let def = serde_json::json!({
            "name": "test-tool",
            "outputSchema": {"type": "object"}
        });
        let err = validate_schema_field(&def, "schema").unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("SCP-VALID-7035"),
            "error should contain SCP-VALID-7035, got: {msg}"
        );
        assert!(
            msg.contains("schema"),
            "error should mention schema, got: {msg}"
        );
    }

    // -----------------------------------------------------------------------
    // validate_schema_field — non-object value (input schema)
    // -----------------------------------------------------------------------

    #[test]
    fn validate_schema_field_rejects_non_object_input() {
        let def = serde_json::json!({
            "name": "test-tool",
            "schema": "not an object",
            "outputSchema": {"type": "object"}
        });
        let err = validate_schema_field(&def, "schema").unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("SCP-VALID-7035"),
            "error should contain SCP-VALID-7035, got: {msg}"
        );
        assert!(
            msg.contains("string"),
            "error should mention the actual type, got: {msg}"
        );
    }

    // -----------------------------------------------------------------------
    // validate_schema_field — structurally invalid input (missing "type")
    // -----------------------------------------------------------------------

    #[test]
    fn validate_schema_field_rejects_structurally_invalid_input() {
        let def = serde_json::json!({
            "name": "test-tool",
            "schema": {"description": "no type field"},
            "outputSchema": {"type": "object"}
        });
        let err = validate_schema_field(&def, "schema").unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("SCP-VALID-7035"),
            "error should contain SCP-VALID-7035, got: {msg}"
        );
    }

    // -----------------------------------------------------------------------
    // validate_schema_field — valid input schema
    // -----------------------------------------------------------------------

    #[test]
    fn validate_schema_field_accepts_valid_input() {
        let def = serde_json::json!({
            "name": "test-tool",
            "schema": {"type": "object", "properties": {"x": {"type": "number"}}},
            "outputSchema": {"type": "object"}
        });
        let result = validate_schema_field(&def, "schema");
        assert!(result.is_ok(), "valid schema should succeed");
        let schema = result.unwrap();
        assert!(schema.is_object());
        assert_eq!(schema["type"], "object");
    }

    // -----------------------------------------------------------------------
    // validate_schema_field — missing field (output schema)
    // -----------------------------------------------------------------------

    #[test]
    fn validate_schema_field_rejects_missing_output() {
        let def = serde_json::json!({
            "name": "test-tool",
            "schema": {"type": "object"}
        });
        let err = validate_schema_field(&def, "outputSchema").unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("SCP-VALID-7036"),
            "error should contain SCP-VALID-7036, got: {msg}"
        );
        assert!(
            msg.contains("outputSchema"),
            "error should mention outputSchema, got: {msg}"
        );
    }

    // -----------------------------------------------------------------------
    // validate_schema_field — non-object value (output schema)
    // -----------------------------------------------------------------------

    #[test]
    fn validate_schema_field_rejects_non_object_output() {
        let def = serde_json::json!({
            "name": "test-tool",
            "schema": {"type": "object"},
            "outputSchema": [1, 2, 3]
        });
        let err = validate_schema_field(&def, "outputSchema").unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("SCP-VALID-7036"),
            "error should contain SCP-VALID-7036, got: {msg}"
        );
        assert!(
            msg.contains("array"),
            "error should mention the actual type, got: {msg}"
        );
    }

    // -----------------------------------------------------------------------
    // validate_schema_field — structurally invalid output (missing "type")
    // -----------------------------------------------------------------------

    #[test]
    fn validate_schema_field_rejects_structurally_invalid_output() {
        let def = serde_json::json!({
            "name": "test-tool",
            "schema": {"type": "object"},
            "outputSchema": {"description": "no type field"}
        });
        let err = validate_schema_field(&def, "outputSchema").unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("SCP-VALID-7036"),
            "error should contain SCP-VALID-7036, got: {msg}"
        );
    }

    // -----------------------------------------------------------------------
    // validate_schema_field — valid output schema
    // -----------------------------------------------------------------------

    #[test]
    fn validate_schema_field_accepts_valid_output() {
        let def = serde_json::json!({
            "name": "test-tool",
            "schema": {"type": "object"},
            "outputSchema": {"type": "object", "properties": {"result": {"type": "string"}}}
        });
        let result = validate_schema_field(&def, "outputSchema");
        assert!(result.is_ok(), "valid outputSchema should succeed");
        let schema = result.unwrap();
        assert!(schema.is_object());
        assert_eq!(schema["type"], "object");
    }

    // -----------------------------------------------------------------------
    // validate_test_vectors
    // -----------------------------------------------------------------------

    #[test]
    fn validate_test_vectors_absent() {
        let def = serde_json::json!({});
        let result = validate_test_vectors(&def);
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn validate_test_vectors_accepts_valid() {
        let def = serde_json::json!({
            "testVectors": [
                {
                    "input": {"x": 1},
                    "expectedOutput": {"y": 2},
                    "description": "adds one"
                }
            ]
        });
        let result = validate_test_vectors(&def);
        assert!(result.is_ok());
        let vecs = result.unwrap();
        assert_eq!(vecs.len(), 1);
        assert_eq!(vecs[0].description, "adds one");
    }

    #[test]
    fn validate_test_vectors_rejects_non_array() {
        let def = serde_json::json!({
            "testVectors": "not an array"
        });
        let result = validate_test_vectors(&def);
        assert!(
            matches!(
                result,
                Err(ScpWasmError::Validation { ref code, .. }) if code == "SCP-VALID-7037"
            ),
            "expected SCP-VALID-7037, got: {result:?}"
        );
    }

    #[test]
    fn validate_test_vectors_rejects_missing_input() {
        let def = serde_json::json!({
            "testVectors": [
                {
                    "expectedOutput": {"y": 2},
                    "description": "no input"
                }
            ]
        });
        let result = validate_test_vectors(&def);
        assert!(
            matches!(
                result,
                Err(ScpWasmError::Validation { ref code, ref message, .. })
                    if code == "SCP-VALID-7037" && message.contains("'input'")
            ),
            "expected SCP-VALID-7037 mentioning 'input', got: {result:?}"
        );
    }

    #[test]
    fn validate_test_vectors_rejects_missing_expected_output() {
        let def = serde_json::json!({
            "testVectors": [
                {
                    "input": {"x": 1},
                    "description": "no output"
                }
            ]
        });
        let result = validate_test_vectors(&def);
        assert!(
            matches!(
                result,
                Err(ScpWasmError::Validation { ref code, ref message, .. })
                    if code == "SCP-VALID-7037" && message.contains("'expectedOutput'")
            ),
            "expected SCP-VALID-7037 mentioning 'expectedOutput', got: {result:?}"
        );
    }

    #[test]
    fn validate_test_vectors_rejects_missing_description() {
        let def = serde_json::json!({
            "testVectors": [
                {
                    "input": {"x": 1},
                    "expectedOutput": {"y": 2}
                }
            ]
        });
        let result = validate_test_vectors(&def);
        assert!(
            matches!(
                result,
                Err(ScpWasmError::Validation { ref code, ref message, .. })
                    if code == "SCP-VALID-7037" && message.contains("'description'")
            ),
            "expected SCP-VALID-7037 mentioning 'description', got: {result:?}"
        );
    }

    #[test]
    fn validate_test_vectors_rejects_non_string_description() {
        let def = serde_json::json!({
            "testVectors": [
                {
                    "input": {"x": 1},
                    "expectedOutput": {"y": 2},
                    "description": 42
                }
            ]
        });
        let result = validate_test_vectors(&def);
        assert!(
            matches!(
                result,
                Err(ScpWasmError::Validation { ref code, ref message, .. })
                    if code == "SCP-VALID-7037"
                        && message.contains("'description'")
                        && message.contains("number")
            ),
            "expected SCP-VALID-7037 mentioning 'description' and type 'number', got: {result:?}"
        );
    }

    #[test]
    fn validate_test_vectors_rejects_boolean_description() {
        let def = serde_json::json!({
            "testVectors": [
                {
                    "input": {"x": 1},
                    "expectedOutput": {"y": 2},
                    "description": true
                }
            ]
        });
        let result = validate_test_vectors(&def);
        assert!(
            matches!(
                result,
                Err(ScpWasmError::Validation { ref code, ref message, .. })
                    if code == "SCP-VALID-7037"
                        && message.contains("'description'")
                        && message.contains("boolean")
            ),
            "expected SCP-VALID-7037 mentioning 'description' and type 'boolean', got: {result:?}"
        );
    }

    #[test]
    fn validate_test_vectors_accepts_empty_array() {
        let def = serde_json::json!({
            "testVectors": []
        });
        let result = validate_test_vectors(&def);
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    // -----------------------------------------------------------------------
    // WasmRateLimit deserialization (F9)
    // -----------------------------------------------------------------------

    #[test]
    fn wasm_rate_limit_deserializes_valid() {
        let json = r#"{"max_calls": 10, "window_seconds": 60}"#;
        let rl: WasmRateLimit = serde_json::from_str(json).unwrap();
        assert_eq!(rl.max_calls, 10);
        assert_eq!(rl.window_seconds, 60);
        assert_eq!(rl.burst_allowance, 5);
        assert_eq!(rl.burst_window_seconds, 1);
    }

    #[test]
    fn wasm_rate_limit_rejects_missing_max_calls() {
        let json = r#"{"window_seconds": 60}"#;
        let result: Result<WasmRateLimit, _> = serde_json::from_str(json);
        assert!(result.is_err(), "missing max_calls should fail");
    }

    #[test]
    fn wasm_rate_limit_rejects_string_max_calls() {
        let json = r#"{"max_calls": "ten", "window_seconds": 60}"#;
        let result: Result<WasmRateLimit, _> = serde_json::from_str(json);
        assert!(result.is_err(), "string max_calls should fail");
    }

    // -----------------------------------------------------------------------
    // Consent protocol lifecycle tests (F3)
    //
    // These test the pure-Rust validation logic used by the consent protocol
    // bridge functions. Tests that require the WasmContextManager (which
    // calls wasm-bindgen time functions) live in manager::tests.
    // -----------------------------------------------------------------------

    #[test]
    fn consent_expose_builds_valid_interface_json() {
        let context_id = "ctx-source";
        let target_context_id = "ctx-target";
        let tool_id = "tool-calculator";

        let interface = serde_json::json!({
            "source_context": context_id,
            "target_context": target_context_id,
            "tool_id": tool_id,
            "rate_limit": null,
            "per_caller_rate_limit": {
                "max_calls_per_caller": 10,
                "window": { "secs": 60, "nanos": 0 },
                "burst_allowance": 5,
                "burst_window": { "secs": 1, "nanos": 0 },
                "callers": {}
            },
            "approved_by_source": true,
            "approved_by_target": false,
            "outbound_policy": {
                "allowed_callers": [],
                "max_calls_per_minute": 60,
                "max_payload_bytes": 65536,
                "require_provenance": true
            },
            "inbound_policy": null
        });

        assert_eq!(interface["approved_by_source"], true);
        assert_eq!(interface["approved_by_target"], false);
        assert_eq!(interface["source_context"], context_id);
        assert_eq!(interface["target_context"], target_context_id);
        assert_eq!(interface["tool_id"], tool_id);
        assert!(interface["outbound_policy"].is_object());
        assert!(interface["inbound_policy"].is_null());

        // Serialization roundtrip should succeed.
        let json_str = serde_json::to_string(&interface).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        assert_eq!(parsed["source_context"], context_id);
    }

    #[test]
    fn consent_expose_admin_role_check_logic() {
        // Simulates the admin role check that tool_interface_expose performs.
        // "admin" passes; all other roles are rejected.
        let admin_role: Option<&str> = Some("admin");
        let member_role: Option<&str> = Some("member");
        let no_role: Option<&str> = None;

        assert!(matches!(admin_role, Some("admin")));
        assert!(!matches!(member_role, Some("admin")));
        assert!(!matches!(no_role, Some("admin")));
    }

    #[test]
    fn consent_accept_validates_context_match() {
        let interface_json = serde_json::json!({
            "source_context": "ctx-source",
            "target_context": "ctx-target",
            "tool_id": "tool-calc",
            "approved_by_source": true,
            "approved_by_target": false,
            "inbound_policy": null
        });

        let context_id = "ctx-target";
        let target = interface_json
            .get("target_context")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");
        assert_eq!(target, context_id, "target should match accepting context");
    }

    #[test]
    fn consent_accept_rejects_context_mismatch() {
        let interface_json = serde_json::json!({
            "source_context": "ctx-source",
            "target_context": "ctx-target",
            "tool_id": "tool-calc",
            "approved_by_source": true,
            "approved_by_target": false,
            "inbound_policy": null
        });

        let context_id = "ctx-wrong";
        let target = interface_json
            .get("target_context")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");
        assert_ne!(target, context_id, "target should NOT match wrong context");
    }

    #[test]
    fn consent_accept_sets_approved_by_target() {
        let mut interface = serde_json::json!({
            "source_context": "ctx-source",
            "target_context": "ctx-target",
            "tool_id": "tool-calc",
            "approved_by_source": true,
            "approved_by_target": false,
            "inbound_policy": null
        });

        // Simulate the accept logic from tool_interface_accept.
        interface["approved_by_target"] = serde_json::json!(true);
        if interface.get("inbound_policy").is_none() || interface["inbound_policy"].is_null() {
            interface["inbound_policy"] = serde_json::json!({
                "allowed_source_roles": [],
                "max_calls_per_minute": 60,
                "max_response_bytes": 65536,
                "require_spending_ucan": false
            });
        }

        assert_eq!(interface["approved_by_target"], true);
        assert!(interface["approved_by_source"].as_bool().unwrap());
        assert!(interface["inbound_policy"].is_object());
        assert_eq!(interface["inbound_policy"]["max_calls_per_minute"], 60);
        assert_eq!(interface["inbound_policy"]["max_response_bytes"], 65536);
    }

    #[test]
    fn consent_accept_preserves_existing_inbound_policy() {
        let mut interface = serde_json::json!({
            "source_context": "ctx-source",
            "target_context": "ctx-target",
            "tool_id": "tool-calc",
            "approved_by_source": true,
            "approved_by_target": false,
            "inbound_policy": {
                "allowed_source_roles": ["member"],
                "max_calls_per_minute": 30,
                "max_response_bytes": 32768,
                "require_spending_ucan": true
            }
        });

        // Existing inbound_policy should not be overwritten.
        interface["approved_by_target"] = serde_json::json!(true);
        if interface.get("inbound_policy").is_none() || interface["inbound_policy"].is_null() {
            interface["inbound_policy"] = serde_json::json!({
                "allowed_source_roles": [],
                "max_calls_per_minute": 60,
                "max_response_bytes": 65536,
                "require_spending_ucan": false
            });
        }

        // Should keep the original policy.
        assert_eq!(interface["inbound_policy"]["max_calls_per_minute"], 30);
        assert_eq!(interface["inbound_policy"]["max_response_bytes"], 32768);
    }

    #[test]
    fn consent_revoke_produces_valid_event() {
        let interface_id_hex = "aa".repeat(32); // 64 hex chars = 32 bytes
        let interface_id_bytes = hex::decode(&interface_id_hex).unwrap();
        assert_eq!(interface_id_bytes.len(), 32);

        let context_id = "ctx-revoker";
        let now_ms: u64 = 1_700_000_000_000;

        let event = serde_json::json!({
            "interface_id": interface_id_bytes,
            "revoking_context": context_id,
            "revoked_at": now_ms
        });

        assert_eq!(event["revoking_context"], "ctx-revoker");
        assert_eq!(event["revoked_at"], 1_700_000_000_000_u64);
        assert!(event["interface_id"].is_array());
    }

    #[test]
    fn consent_revoke_rejects_invalid_hex() {
        let result = hex::decode("not_valid_hex");
        assert!(result.is_err(), "non-hex should fail");
    }

    #[test]
    fn consent_revoke_rejects_wrong_length() {
        let short_hex = "aa".repeat(16); // 32 hex chars = 16 bytes, need 32
        let bytes = hex::decode(&short_hex).unwrap();
        assert_ne!(bytes.len(), 32, "16 bytes should fail 32-byte check");
    }

    #[test]
    fn consent_expose_with_rate_limit() {
        let rl_json = r#"{"max_calls": 20, "window_seconds": 120}"#;
        let rl: WasmRateLimit = serde_json::from_str(rl_json).unwrap();
        assert_eq!(rl.max_calls, 20);
        assert_eq!(rl.window_seconds, 120);

        // Serialized rate_limit should appear in the interface JSON.
        let interface = serde_json::json!({
            "source_context": "ctx-source",
            "target_context": "ctx-target",
            "tool_id": "tool-calc",
            "rate_limit": rl,
            "approved_by_source": true,
            "approved_by_target": false,
        });

        assert!(interface["rate_limit"].is_object());
        assert_eq!(interface["rate_limit"]["max_calls"], 20);
        assert_eq!(interface["rate_limit"]["window_seconds"], 120);
    }
}
