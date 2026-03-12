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
}
