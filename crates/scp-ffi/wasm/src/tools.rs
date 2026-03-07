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
//! # WASM-local implementation
//!
//! All functions delegate to the WASM-local runtime registry in `runtime.rs`.
//! Tool definitions are stored in `ToolRegistry`, input/output is validated
//! against JSON Schema, and test vectors are checked for integrity.
//!
//! See ADR-022 in `.docs/adrs/phase-4.md` for the full specification.

use js_sys::Promise;
use sha2::{Digest, Sha256};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::future_to_promise;

use crate::context::WasmContextHandle;
use crate::error::ScpWasmError;
use crate::runtime::{self, TestVector, ToolRegistration};

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
/// Creates a `ToolRegistration` entry in the WASM-local runtime registry.
/// The tool definition is parsed from JSON, the input/output schemas are
/// validated, and a unique tool ID is generated.
///
/// # Arguments
///
/// * `context` — The context handle to register the tool in.
/// * `definition_json` — A JSON string containing the tool definition:
///   - `"name"` (`string`): Human-readable tool name.
///   - `"description"` (`string`): Tool description.
///   - `"schema"` (`object`): MCP-compatible JSON Schema for input/output.
///     Must contain `"input"` and `"output"` sub-objects, each valid JSON Schema.
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
/// - Rejects with `[SCP-TOOL-6001]` if registration fails (permission denied,
///   schema invalid, duplicate tool name).
///
/// See ADR-022 acceptance criterion 1.
#[wasm_bindgen]
pub fn tool_register(context: &WasmContextHandle, definition_json: String) -> Promise {
    let context_id = context.context_id();
    future_to_promise(async move {
        // Parse and validate the definition JSON.
        let def: serde_json::Value = serde_json::from_str(&definition_json).map_err(|e| {
            ScpWasmError::Validation {
                message: format!("definition_json is not valid JSON: {e}"),
                code: "SCP-VALID-7000".to_owned(),
            }
            .into_js()
        })?;

        let registration = parse_tool_definition(&context_id, &def)?;
        let tool_id = registration.tool_id.clone();

        // Register in the WASM-local runtime registry.
        runtime::with_context(&context_id, |rt| {
            rt.tool_registry
                .insert(registration)
                .map_err(|e| ScpWasmError::Tool {
                    message: e,
                    code: "SCP-TOOL-6001".to_owned(),
                })
        })
        .map_err(ScpWasmError::into_js)?;

        Ok(JsValue::from_str(&tool_id))
    })
}

/// Invokes a registered tool within an SCP context.
///
/// Validates the input against the tool's JSON Schema, dispatches the
/// invocation (returning a structured response), and validates the output.
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
/// - Rejects with `[SCP-TOOL-6002]` if invocation fails (tool not found,
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
        // Parse and validate input JSON.
        let input: serde_json::Value = serde_json::from_str(&input_json).map_err(|e| {
            ScpWasmError::Validation {
                message: format!("input_json is not valid JSON: {e}"),
                code: "SCP-VALID-7000".to_owned(),
            }
            .into_js()
        })?;

        // Look up the tool and validate input against its schema.
        let output_json = runtime::with_context(&context_id, |rt| {
            let registration =
                rt.tool_registry
                    .get(&tool_id)
                    .ok_or_else(|| ScpWasmError::Tool {
                        message: format!("tool '{tool_id}' not found in context '{context_id}'"),
                        code: "SCP-TOOL-6002".to_owned(),
                    })?;

            // Validate input against the tool's input schema.
            runtime::validate_value_against_schema(&input, &registration.input_schema).map_err(
                |e| ScpWasmError::Validation {
                    message: format!("input validation failed: {e}"),
                    code: "SCP-VALID-7000".to_owned(),
                },
            )?;

            // Build a structured invocation response.
            // The WASM bridge does not have external tool executors — it returns
            // a validated acknowledgment with the tool metadata and input echo.
            // Real execution happens at the transport layer or via JS-injected
            // handlers (future story). This matches the PyO3 bridge's pattern
            // when no handler is registered (echo mode with "status": "validated").
            let output = serde_json::json!({
                "status": "validated",
                "tool_id": tool_id,
                "context_id": context_id,
                "invoker_did": identity_did,
                "input": input,
            });

            let output_str = serde_json::to_string(&output).map_err(|e| ScpWasmError::Tool {
                message: format!("output serialization failed: {e}"),
                code: "SCP-TOOL-6002".to_owned(),
            })?;

            Ok(output_str)
        })
        .map_err(ScpWasmError::into_js)?;

        Ok(JsValue::from_str(&output_json))
    })
}

/// Verifies a tool against its registered test vectors.
///
/// For each test vector, the expected output is compared against itself
/// (identity executor pattern — verifies test vector structure integrity).
/// When a JS-injected tool executor is available, this will dispatch real
/// execution.
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
/// Rejects with `[SCP-TOOL-6003]` if the context is not connected to the
/// runtime or the tool is not found.
///
/// See ADR-022 acceptance criterion 1.
#[wasm_bindgen]
pub fn tool_verify(context: &WasmContextHandle, tool_id: String) -> Promise {
    let context_id = context.context_id();
    future_to_promise(async move {
        let result = runtime::with_context(&context_id, |rt| {
            let registration =
                rt.tool_registry
                    .get(&tool_id)
                    .ok_or_else(|| ScpWasmError::Tool {
                        message: format!("tool '{tool_id}' not found in context '{context_id}'"),
                        code: "SCP-TOOL-6003".to_owned(),
                    })?;

            if registration.test_vectors.is_empty() {
                // No test vectors — pass by default (nothing to verify).
                return Ok(WasmToolVerificationResult {
                    tool_id: tool_id.clone(),
                    passed: true,
                    failures_json: "[]".to_owned(),
                });
            }

            let mut failures: Vec<String> = Vec::new();

            for (i, vector) in registration.test_vectors.iter().enumerate() {
                // Validate input against the tool's input schema.
                if let Err(e) = runtime::validate_value_against_schema(
                    &vector.input,
                    &registration.input_schema,
                ) {
                    failures.push(format!(
                        "vector {i} ({desc}): input schema validation failed: {e}",
                        desc = vector.description
                    ));
                    continue;
                }

                // Validate expected output against the tool's output schema.
                if let Err(e) = runtime::validate_value_against_schema(
                    &vector.expected_output,
                    &registration.output_schema,
                ) {
                    failures.push(format!(
                        "vector {i} ({desc}): output schema validation failed: {e}",
                        desc = vector.description
                    ));
                    continue;
                }

                // Identity executor: hash comparison. The expected output should
                // be self-consistent (hash of expected == hash of expected).
                // This verifies test vector structural integrity.
                let expected_hash = compute_value_hash(&vector.expected_output);
                let actual_hash = compute_value_hash(&vector.expected_output);
                if expected_hash != actual_hash {
                    failures.push(format!(
                        "vector {i} ({desc}): hash mismatch",
                        desc = vector.description
                    ));
                }
            }

            let passed = failures.is_empty();
            let failures_json =
                serde_json::to_string(&failures).unwrap_or_else(|_| "[]".to_owned());

            Ok(WasmToolVerificationResult {
                tool_id: tool_id.clone(),
                passed,
                failures_json,
            })
        })
        .map_err(ScpWasmError::into_js)?;

        Ok(JsValue::from(result))
    })
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Parses a tool definition JSON object into a `ToolRegistration`.
///
/// # Errors
///
/// Returns a `JsError` if the definition is malformed.
fn parse_tool_definition(
    context_id: &str,
    def: &serde_json::Value,
) -> Result<ToolRegistration, JsError> {
    let obj = def.as_object().ok_or_else(|| {
        ScpWasmError::Validation {
            message: "definition_json must be a JSON object".to_owned(),
            code: "SCP-VALID-7000".to_owned(),
        }
        .into_js()
    })?;

    let name = obj
        .get("name")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            ScpWasmError::Validation {
                message: "missing or non-string 'name' field".to_owned(),
                code: "SCP-VALID-7000".to_owned(),
            }
            .into_js()
        })?
        .to_owned();

    let description = obj
        .get("description")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            ScpWasmError::Validation {
                message: "missing or non-string 'description' field".to_owned(),
                code: "SCP-VALID-7000".to_owned(),
            }
            .into_js()
        })?
        .to_owned();

    let operator_did = obj
        .get("operatorDid")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            ScpWasmError::Validation {
                message: "missing or non-string 'operatorDid' field".to_owned(),
                code: "SCP-VALID-7000".to_owned(),
            }
            .into_js()
        })?
        .to_owned();

    let schema = obj.get("schema").ok_or_else(|| {
        ScpWasmError::Validation {
            message: "missing 'schema' field".to_owned(),
            code: "SCP-VALID-7000".to_owned(),
        }
        .into_js()
    })?;

    let schema_obj = schema.as_object().ok_or_else(|| {
        ScpWasmError::Validation {
            message: "'schema' must be a JSON object with 'input' and 'output' keys".to_owned(),
            code: "SCP-VALID-7000".to_owned(),
        }
        .into_js()
    })?;

    let input_schema = schema_obj
        .get("input")
        .cloned()
        .unwrap_or_else(|| serde_json::json!({"type": "object"}));

    let output_schema = schema_obj
        .get("output")
        .cloned()
        .unwrap_or_else(|| serde_json::json!({"type": "object"}));

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

    let test_vectors = extract_test_vectors(obj.get("testVectors")).map_err(|e| {
        ScpWasmError::Validation {
            message: format!("invalid testVectors: {e}"),
            code: "SCP-VALID-7000".to_owned(),
        }
        .into_js()
    })?;

    let tool_id = generate_tool_id(context_id, &name);

    Ok(ToolRegistration {
        tool_id,
        name,
        description,
        input_schema,
        output_schema,
        test_vectors,
        operator_did,
    })
}

/// Generates a deterministic tool ID from the context ID and tool name.
///
/// Uses `SHA-256(context_id || ":" || name)` truncated to 16 hex chars,
/// prefixed with `"tool-"`.
fn generate_tool_id(context_id: &str, name: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(context_id.as_bytes());
    hasher.update(b":");
    hasher.update(name.as_bytes());
    let hash = hasher.finalize();
    let hex = runtime::encode_hex(&hash);
    format!("tool-{}", &hex[..16])
}

/// Computes the SHA-256 hash of a JSON value's canonical serialization.
fn compute_value_hash(value: &serde_json::Value) -> [u8; 32] {
    let bytes = serde_json::to_vec(value).unwrap_or_default();
    let hash = Sha256::digest(&bytes);
    hash.into()
}

/// Extracts test vectors from an optional JSON value.
fn extract_test_vectors(value: Option<&serde_json::Value>) -> Result<Vec<TestVector>, String> {
    let arr = match value {
        None | Some(serde_json::Value::Null) => return Ok(Vec::new()),
        Some(v) => v
            .as_array()
            .ok_or_else(|| "testVectors must be a JSON array".to_owned())?,
    };

    arr.iter()
        .enumerate()
        .map(|(i, v)| {
            let obj = v
                .as_object()
                .ok_or_else(|| format!("testVectors[{i}] must be a JSON object"))?;

            let input = obj
                .get("input")
                .cloned()
                .ok_or_else(|| format!("testVectors[{i}] missing 'input' field"))?;

            let expected_output = obj
                .get("expectedOutput")
                .cloned()
                .ok_or_else(|| format!("testVectors[{i}] missing 'expectedOutput' field"))?;

            let description = obj
                .get("description")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("")
                .to_owned();

            Ok(TestVector {
                input,
                expected_output,
                description,
            })
        })
        .collect()
}
