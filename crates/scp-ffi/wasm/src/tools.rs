//! `wasm-bindgen` bridge for tool registration, invocation, and verification.
//!
//! All operations delegate to [`WasmContextManager`](crate::manager::WasmContextManager)
//! via [`with_manager`](crate::manager::with_manager). No local state management.
//!
//! See ADR-034 in `.docs/adrs/phase-4.md` and issue #389.

use js_sys::Promise;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::future_to_promise;

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
// Bridge functions
// ---------------------------------------------------------------------------

/// Registers a tool in an SCP context.
///
/// Delegates to `WasmContextManager::register_tool`.
///
/// # Returns
///
/// `Promise<string>` — resolves to the assigned tool ID.
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

        let description = def["description"].as_str().unwrap_or("").to_owned();

        let input_schema = def
            .get("schema")
            .cloned()
            .unwrap_or_else(|| serde_json::json!({"type": "object"}));

        let output_schema = def
            .get("outputSchema")
            .cloned()
            .unwrap_or_else(|| serde_json::json!({"type": "object"}));

        let operator_did = def["operatorDid"].as_str().unwrap_or("").to_owned();

        // Validate schemas.
        runtime::validate_schema(&input_schema).map_err(|e| {
            ScpWasmError::Validation {
                message: format!("invalid input schema: {e}"),
                code: "SCP-VALID-7000".to_owned(),
            }
            .into_js()
        })?;

        runtime::validate_schema(&output_schema).map_err(|e| {
            ScpWasmError::Validation {
                message: format!("invalid output schema: {e}"),
                code: "SCP-VALID-7000".to_owned(),
            }
            .into_js()
        })?;

        // Parse test vectors.
        let test_vectors: Vec<runtime::TestVector> = def
            .get("testVectors")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| {
                        Some(runtime::TestVector {
                            input: v.get("input")?.clone(),
                            expected_output: v.get("expectedOutput")?.clone(),
                            description: v
                                .get("description")
                                .and_then(|d| d.as_str())
                                .unwrap_or("")
                                .to_owned(),
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();

        let tool_id = format!("tool-{}", uuid::Uuid::new_v4().as_hyphenated());

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
/// Delegates to `WasmContextManager::invoke_tool`.
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
) -> Promise {
    let context_id = context.context_id();
    future_to_promise(async move {
        let input: serde_json::Value = serde_json::from_str(&input_json).map_err(|e| {
            ScpWasmError::Validation {
                message: format!("input_json is not valid JSON: {e}"),
                code: "SCP-VALID-7000".to_owned(),
            }
            .into_js()
        })?;

        let result =
            with_manager(|mgr| mgr.invoke_tool(&context_id, &tool_id, &input, &identity_did))
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

        let failures_json = serde_json::to_string(&failures).unwrap_or_else(|_| "[]".to_owned());

        Ok(JsValue::from(WasmToolVerificationResult {
            tool_id,
            passed,
            failures_json,
        }))
    })
}
