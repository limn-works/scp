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
    validate_did, validate_tool_id, validate_tool_name, validate_ucan_token,
};

use crate::context::WasmContextHandle;
use crate::error::ScpWasmError;
use crate::manager::with_manager;
use crate::runtime;

/// Returns a human-readable type name for a JSON value (for error messages).
const fn json_value_type_name(v: &serde_json::Value) -> &'static str {
    match v {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "boolean",
        serde_json::Value::Number(_) => "number",
        serde_json::Value::String(_) => "string",
        serde_json::Value::Array(_) => "array",
        serde_json::Value::Object(_) => "object",
    }
}

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
    #[must_use]
    #[wasm_bindgen(getter, js_name = "toolId")]
    pub fn tool_id(&self) -> String {
        self.tool_id.clone()
    }

    #[must_use]
    #[wasm_bindgen(getter)]
    pub fn passed(&self) -> bool {
        self.passed
    }

    #[must_use]
    #[wasm_bindgen(getter, js_name = "failuresJson")]
    pub fn failures_json(&self) -> String {
        self.failures_json.clone()
    }
}

// ---------------------------------------------------------------------------
// Validation helpers for tool registration inputs
// ---------------------------------------------------------------------------

/// Extracts and validates a required JSON Schema field from a definition object.
///
/// Returns `SCP-VALID-7035` for `"schema"` (input) or `SCP-VALID-7036` for
/// `"outputSchema"` (output) when the field is missing or not a JSON object.
fn extract_schema_field(
    def: &serde_json::Value,
    field_name: &str,
) -> Result<serde_json::Value, JsValue> {
    let code = match field_name {
        "schema" => "SCP-VALID-7035",
        _ => "SCP-VALID-7036",
    };

    let schema = def.get(field_name).cloned().ok_or_else(|| {
        ScpWasmError::Validation {
            message: format!(
                "missing '{field_name}' field in definition — a JSON Schema object is required"
            ),
            code: code.to_owned(),
        }
        .into_js()
    })?;

    if !schema.is_object() {
        Err(ScpWasmError::Validation {
            message: format!(
                "invalid '{field_name}': expected a JSON object, got {}",
                json_value_type_name(&schema)
            ),
            code: code.to_owned(),
        }
        .into_js())?;
    }

    // Validate against JSON Schema meta-schema.
    runtime::validate_schema(&schema).map_err(|e| {
        ScpWasmError::Validation {
            message: format!("invalid {field_name}: {e}"),
            code: code.to_owned(),
        }
        .into_js()
    })?;

    Ok(schema)
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

        let description = def["description"].as_str().unwrap_or("").to_owned();

        let input_schema = extract_schema_field(&def, "schema")?;
        let output_schema = extract_schema_field(&def, "outputSchema")?;

        let operator_did = def["operatorDid"].as_str().unwrap_or("").to_owned();

        // Parse test vectors.
        let test_vectors: Vec<runtime::TestVector> = match def.get("testVectors") {
            None => Vec::new(),
            Some(tv_value) => {
                let arr = tv_value.as_array().ok_or_else(|| {
                    ScpWasmError::Validation {
                        message: format!(
                            "invalid 'testVectors': expected an array, got {}",
                            json_value_type_name(tv_value)
                        ),
                        code: "SCP-VALID-7037".to_owned(),
                    }
                    .into_js()
                })?;

                let mut vectors = Vec::with_capacity(arr.len());
                for (i, entry) in arr.iter().enumerate() {
                    let input = entry.get("input").ok_or_else(|| {
                        ScpWasmError::Validation {
                            message: format!(
                                "test vector at index {i} is missing required 'input' field"
                            ),
                            code: "SCP-VALID-7037".to_owned(),
                        }
                        .into_js()
                    })?;
                    let expected_output = entry.get("expectedOutput").ok_or_else(|| {
                        ScpWasmError::Validation {
                            message: format!(
                                "test vector at index {i} is missing required 'expectedOutput' field"
                            ),
                            code: "SCP-VALID-7037".to_owned(),
                        }
                        .into_js()
                    })?;
                    vectors.push(runtime::TestVector {
                        input: input.clone(),
                        expected_output: expected_output.clone(),
                        description: entry
                            .get("description")
                            .and_then(|d| d.as_str())
                            .unwrap_or("")
                            .to_owned(),
                    });
                }
                vectors
            }
        };

        let tool_id = format!("tool-{}", name.replace(' ', "-").to_lowercase());

        let registration = runtime::ToolRegistration {
            tool_id: tool_id.clone(),
            name,
            description,
            input_schema,
            output_schema,
            test_vectors,
            operator_did,
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
    ttl_seconds: u32,
) -> Promise {
    let context_id = context.context_id();
    future_to_promise(async move {
        let session_id = with_manager(|mgr| {
            mgr.session_create(
                &context_id,
                &tool_id,
                &source_context_id,
                u64::from(ttl_seconds),
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
