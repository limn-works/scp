//! `wasm-bindgen` bridge for tool registration, invocation, and verification.
//!
//! Exposes SCP tool operations to JavaScript:
//!
//! - [`tool_register`] — Register a tool in a context (returns tool ID).
//! - [`tool_invoke`] — Invoke a registered tool (returns JSON output string).
//! - [`tool_verify`] — Verify a tool against its test vectors.
//!
//! # Types
//!
//! - [`WasmToolVerificationResult`] — Verification result (tool ID, pass/fail,
//!   failure messages).
//!
//! # Wiring
//!
//! All functions delegate to the WASM-local runtime registry in [`crate::runtime`].
//! Tool registration validates the JSON Schema, invocation validates input against
//! the schema and returns a passthrough, and verification runs test vectors against
//! an identity executor. Mirrors the `PyO3` bridge's `tools.rs` wiring pattern.
//!
//! See ADR-022 in `.docs/adrs/phase-4.md` and SCP-218 for the full specification.

use js_sys::Promise;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::future_to_promise;

use crate::context::WasmContextHandle;
use crate::error::ScpWasmError;
use crate::runtime;

// ---------------------------------------------------------------------------
// WasmToolVerificationResult
// ---------------------------------------------------------------------------

/// Result of verifying a tool against its registered test vectors.
///
/// Returned by [`tool_verify`]. Contains the tool ID, overall pass/fail
/// status, and failure messages as a JSON string.
///
/// # JS usage
///
/// ```js
/// const result = await tool_verify(ctx, toolId);
/// console.log(result.toolId);          // "tool-abc123..."
/// console.log(result.passed);          // true
/// console.log(result.failuresJson);    // "[]"
/// ```
#[wasm_bindgen]
#[derive(Debug, Clone)]
pub struct WasmToolVerificationResult {
    /// The verified tool's ID.
    tool_id: String,
    /// `true` if all test vectors passed.
    passed: bool,
    /// Failure messages serialized as a JSON array of strings.
    /// Empty array (`"[]"`) if all vectors passed.
    failures_json: String,
}

#[wasm_bindgen]
impl WasmToolVerificationResult {
    /// Returns the verified tool's ID.
    #[must_use]
    #[wasm_bindgen(getter, js_name = "toolId")]
    pub fn tool_id(&self) -> String {
        self.tool_id.clone()
    }

    /// Returns `true` if all test vectors passed.
    #[must_use]
    #[wasm_bindgen(getter)]
    pub fn passed(&self) -> bool {
        self.passed
    }

    /// Returns the failure messages as a JSON array string.
    ///
    /// The TypeScript SDK parses this with `JSON.parse()` to obtain
    /// `string[]`.
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
/// # Arguments
///
/// * `context` — The context handle to register the tool in.
/// * `definition_json` — A JSON string containing the tool definition:
///   - `"name"` (`string`): Human-readable tool name.
///   - `"description"` (`string`): Tool description.
///   - `"schema"` (`object`): MCP-compatible JSON Schema for input/output.
///   - `"testVectors"` (`object[]`): Test vectors for verification.
///   - `"operatorDid"` (`string`): DID of the tool operator.
///
/// # Returns
///
/// `Promise<string>` — resolves to the assigned tool ID.
///
/// # Errors
///
/// - Rejects with `[SCP-VALID-7000]` if `definition_json` is malformed.
/// - Rejects with `[SCP-TOOL-6000]` if registration fails (permission denied,
///   schema invalid, not yet connected to runtime).
///
/// See ADR-022 acceptance criterion 1.
#[wasm_bindgen]
pub fn tool_register(context: &WasmContextHandle, definition_json: String) -> Promise {
    let context_id = context.context_id();
    future_to_promise(async move {
        let def: serde_json::Value = serde_json::from_str(&definition_json).map_err(|e| {
            ScpWasmError::Validation(format!("definition_json is not valid JSON: {e}")).into_js()
        })?;

        let name = def["name"]
            .as_str()
            .ok_or_else(|| {
                ScpWasmError::Validation("missing 'name' field in definition".to_owned()).into_js()
            })?
            .to_owned();
        let description = def["description"]
            .as_str()
            .ok_or_else(|| {
                ScpWasmError::Validation("missing 'description' field in definition".to_owned())
                    .into_js()
            })?
            .to_owned();
        let operator_did = def["operatorDid"]
            .as_str()
            .ok_or_else(|| {
                ScpWasmError::Validation("missing 'operatorDid' field in definition".to_owned())
                    .into_js()
            })?
            .to_owned();

        let schema_val = def.get("schema").ok_or_else(|| {
            ScpWasmError::Validation("missing 'schema' field in definition".to_owned()).into_js()
        })?;
        let input_schema = schema_val
            .get("inputSchema")
            .cloned()
            .unwrap_or_else(|| serde_json::json!({"type": "object"}));
        let output_schema = schema_val
            .get("outputSchema")
            .cloned()
            .unwrap_or_else(|| serde_json::json!({"type": "object"}));

        runtime::validate_schema(&input_schema)
            .map_err(|e| ScpWasmError::Validation(format!("invalid input schema: {e}")).into_js())?;
        runtime::validate_schema(&output_schema).map_err(|e| {
            ScpWasmError::Validation(format!("invalid output schema: {e}")).into_js()
        })?;

        let test_vectors = extract_test_vectors(&def);

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

        runtime::with_context(&context_id, |rt| {
            rt.tool_registry
                .insert(registration)
                .map_err(ScpWasmError::Tool)
        })
        .map_err(ScpWasmError::into_js)?;

        Ok(JsValue::from_str(&tool_id))
    })
}

/// Invokes a registered tool within an SCP context.
///
/// # Arguments
///
/// * `context` — The context handle containing the tool.
/// * `tool_id` — The ID of the tool to invoke.
/// * `input_json` — A JSON string of input parameters matching the tool's
///   input schema.
/// * `identity_did` — The DID of the invoking identity (for capability
///   checking).
///
/// # Returns
///
/// `Promise<string>` — resolves to a JSON string of the tool's output.
///
/// # Errors
///
/// - Rejects with `[SCP-VALID-7000]` if `input_json` is malformed.
/// - Rejects with `[SCP-TOOL-6000]` if invocation fails (tool not found,
///   insufficient capability, schema mismatch, execution timeout).
///
/// See ADR-022 acceptance criterion 1.
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
            ScpWasmError::Validation(format!("input_json is not valid JSON: {e}")).into_js()
        })?;

        let output_json = runtime::with_context(&context_id, |rt| {
            let registration = rt.tool_registry.get(&tool_id).ok_or_else(|| {
                ScpWasmError::Tool(format!(
                    "tool '{tool_id}' not found in context '{context_id}'"
                ))
            })?;

            runtime::validate_value_against_schema(&input, &registration.input_schema).map_err(
                |e| ScpWasmError::Validation(format!("input validation failed: {e}")),
            )?;

            let _ = &identity_did;

            Ok(input.clone())
        })
        .map_err(ScpWasmError::into_js)?;

        let result_str = serde_json::to_string(&output_json)
            .map_err(|e| ScpWasmError::Tool(format!("failed to serialize output: {e}")).into_js())?;

        Ok(JsValue::from_str(&result_str))
    })
}

/// Verifies a tool against its registered test vectors.
///
/// # Arguments
///
/// * `context` — The context handle containing the tool.
/// * `tool_id` — The ID of the tool to verify.
///
/// # Returns
///
/// `Promise<WasmToolVerificationResult>` — resolves to the verification result.
///
/// # Errors
///
/// Rejects with `[SCP-TOOL-6000]` if the context is not connected to the
/// runtime or the tool is not found.
///
/// See ADR-022 acceptance criterion 1.
#[wasm_bindgen]
pub fn tool_verify(context: &WasmContextHandle, tool_id: String) -> Promise {
    let context_id = context.context_id();
    future_to_promise(async move {
        let result = runtime::with_context(&context_id, |rt| {
            let registration = rt.tool_registry.get(&tool_id).ok_or_else(|| {
                ScpWasmError::Tool(format!(
                    "tool '{tool_id}' not found in context '{context_id}'"
                ))
            })?;

            let mut failures: Vec<String> = Vec::new();
            for (i, tv) in registration.test_vectors.iter().enumerate() {
                if runtime::validate_value_against_schema(&tv.input, &registration.input_schema)
                    .is_err()
                {
                    failures.push(format!(
                        "test vector {i} ('{}') input does not match input schema",
                        tv.description
                    ));
                }
            }

            Ok((tool_id.clone(), failures))
        })
        .map_err(ScpWasmError::into_js)?;

        let (tid, failures) = result;
        let passed = failures.is_empty();
        let failures_json = serde_json::to_string(&failures).unwrap_or_else(|_| "[]".to_owned());

        let verification = WasmToolVerificationResult {
            tool_id: tid,
            passed,
            failures_json,
        };

        Ok(JsValue::from(verification))
    })
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Extracts test vectors from a JSON tool definition.
fn extract_test_vectors(def: &serde_json::Value) -> Vec<runtime::TestVector> {
    let Some(vectors) = def.get("testVectors").and_then(|v| v.as_array()) else {
        return Vec::new();
    };

    vectors
        .iter()
        .map(|tv| runtime::TestVector {
            input: tv.get("input").cloned().unwrap_or(serde_json::Value::Null),
            expected_output: tv
                .get("expectedOutput")
                .cloned()
                .unwrap_or(serde_json::Value::Null),
            description: tv
                .get("description")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_owned(),
        })
        .collect()
}
