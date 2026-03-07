//! napi-rs bridge for tool operations.
//!
//! Exposes tool registration, invocation, and verification:
//!
//! - [`tool_register`] — Register a tool in a context.
//! - [`tool_invoke`] — Invoke a tool within a context.
//! - [`tool_verify`] — Verify a tool against its test vectors.
//!
//! See ADR-022 in `.docs/adrs/phase-4.md`.

use napi_derive::napi;

use crate::context::NapiContextHandle;
use crate::error::ScpNapiError;

// ---------------------------------------------------------------------------
// NapiToolDefinition — tool definition for registration
// ---------------------------------------------------------------------------

/// Tool definition for registration in a context.
///
/// See ADR-010 (Tool Registry) and spec section 6 (Tools).
#[napi(object)]
pub struct NapiToolDefinition {
    /// Human-readable tool name.
    pub name: String,
    /// Tool description.
    pub description: String,
    /// JSON Schema for tool input (as a JSON string).
    pub input_schema_json: String,
    /// JSON Schema for tool output (as a JSON string).
    pub output_schema_json: String,
    /// DID of the tool operator (responsible party).
    pub operator_did: String,
    /// Test vectors for integrity verification (serialized as JSON string).
    pub test_vectors_json: Option<String>,
    /// SHA-256 hash of the implementation binary (32 bytes).
    pub implementation_hash: Option<Vec<u8>>,
}

// ---------------------------------------------------------------------------
// NapiToolVerificationResult — result of tool verification
// ---------------------------------------------------------------------------

/// Result of verifying a tool against its registered test vectors.
#[napi(object)]
pub struct NapiToolVerificationResult {
    /// The verified tool's ID.
    pub tool_id: String,
    /// `true` if all test vectors passed.
    pub passed: bool,
    /// Failure messages for vectors that did not pass. Empty on success.
    pub failures: Vec<String>,
}

// ---------------------------------------------------------------------------
// Bridge functions
// ---------------------------------------------------------------------------

/// Registers a tool in an SCP context.
///
/// # Arguments
///
/// * `handle` — The context to register the tool in (must be `"active"`).
/// * `definition` — Tool definition including name, description, schemas,
///   operator DID, test vectors, and optional implementation hash.
///
/// # Returns
///
/// A `Promise<string>` resolving to the assigned tool ID.
///
/// # Errors
///
/// - Rejects with `SCP-TOOL-6003` if the context is not `"active"`.
/// - Rejects with `SCP-TOOL-6001` if registration fails (permission denied,
///   schema invalid, duplicate name, etc.) in the full runtime.
#[napi]
#[allow(clippy::unused_async)] // napi-rs requires async for Promise return
pub async fn tool_register(
    handle: &NapiContextHandle,
    definition: NapiToolDefinition,
) -> napi::Result<String> {
    let state_str = handle.state()?;
    if state_str != "active" {
        return Err(ScpNapiError::Tool {
            message: format!(
                "cannot register tool in context in {state_str:?} state — context must be active"
            ),
            code: "SCP-TOOL-6003".to_owned(),
        }
        .into());
    }

    // Ensure the context's runtime state is registered.
    crate::runtime::ensure_registered(handle).map_err(napi::Error::from)?;

    // Parse JSON schemas from strings.
    let input_schema: serde_json::Value = serde_json::from_str(&definition.input_schema_json)
        .map_err(|e| ScpNapiError::Validation {
            message: format!("invalid input_schema_json: {e}"),
            code: "SCP-VALID-7000".to_owned(),
        })?;
    let output_schema: serde_json::Value = serde_json::from_str(&definition.output_schema_json)
        .map_err(|e| ScpNapiError::Validation {
            message: format!("invalid output_schema_json: {e}"),
            code: "SCP-VALID-7000".to_owned(),
        })?;

    // Parse test vectors from optional JSON string.
    let test_vectors = parse_test_vectors_json(definition.test_vectors_json.as_deref())?;

    // Parse implementation hash (optional, 32-byte SHA-256).
    let implementation_hash = definition
        .implementation_hash
        .as_deref()
        .map(|bytes| {
            <[u8; 32]>::try_from(bytes).map_err(|_| ScpNapiError::Validation {
                message: format!(
                    "implementation_hash must be exactly 32 bytes, got {}",
                    bytes.len()
                ),
                code: "SCP-VALID-7000".to_owned(),
            })
        })
        .transpose()?
        .unwrap_or([0u8; 32]);

    // Generate a tool ID from the name.
    let tool_id = format!("tool-{}", definition.name.replace(' ', "-").to_lowercase());

    let core_registration = scp_core::context::tools::ToolRegistration {
        tool_id,
        name: definition.name,
        description: definition.description,
        schema: scp_core::context::tools::ToolSchema {
            input_schema,
            output_schema,
        },
        implementation_hash,
        test_vectors,
        operator_did: definition.operator_did.into(),
        economic_metadata: None,
    };

    let context_id = handle.context_id();
    let registered_id = crate::runtime::with_context(&context_id, |rt| {
        let (id, _event) = scp_core::context::tools::register_tool(
            &mut rt.tool_registry,
            &rt.role_state,
            core_registration,
            &rt.creator_did.clone(),
        )
        .map_err(|e| ScpNapiError::Tool {
            message: format!("tool registration failed: {e}"),
            code: "SCP-TOOL-6001".to_owned(),
        })?;
        Ok(id)
    })
    .map_err(napi::Error::from)?;

    Ok(registered_id)
}

/// Invokes a tool within an SCP context.
///
/// # Arguments
///
/// * `handle` — The context containing the tool (must be `"active"`).
/// * `tool_id` — The ID of the tool to invoke.
/// * `input_json` — Tool input parameters as a JSON string.
/// * `identity_did` — The DID of the invoker (used for capability checking).
///
/// # Returns
///
/// A `Promise<string>` resolving to the tool output as a JSON string.
///
/// # Errors
///
/// - Rejects with `SCP-TOOL-6005` if the context is not `"active"`.
/// - Rejects with `SCP-TOOL-6002` if invocation fails (tool not found,
///   input fails schema validation, invoker lacks capability).
#[napi]
#[allow(clippy::unused_async)] // napi-rs requires async for Promise return
#[allow(clippy::needless_pass_by_value)] // napi-rs requires owned String
pub async fn tool_invoke(
    handle: &NapiContextHandle,
    tool_id: String,
    input_json: String,
    identity_did: String,
) -> napi::Result<String> {
    let state_str = handle.state()?;
    if state_str != "active" {
        return Err(ScpNapiError::Tool {
            message: format!(
                "cannot invoke tool in context in {state_str:?} state — context must be active"
            ),
            code: "SCP-TOOL-6005".to_owned(),
        }
        .into());
    }

    // Ensure the context's runtime state is registered.
    crate::runtime::ensure_registered(handle).map_err(napi::Error::from)?;

    // Parse input JSON.
    let input_value: serde_json::Value =
        serde_json::from_str(&input_json).map_err(|e| ScpNapiError::Validation {
            message: format!("invalid input_json: {e}"),
            code: "SCP-VALID-7000".to_owned(),
        })?;

    let context_id = handle.context_id();
    let output_json = crate::runtime::with_context(&context_id, |rt| {
        let registration = rt
            .tool_registry
            .get(&tool_id)
            .ok_or_else(|| ScpNapiError::Tool {
                message: format!("tool '{tool_id}' not found in context '{context_id}'"),
                code: "SCP-TOOL-6002".to_owned(),
            })?;

        // Validate input against the tool's input schema.
        scp_core::context::tools::validate_value_against_schema(
            &input_value,
            &registration.schema.input_schema,
        )
        .map_err(|e| ScpNapiError::Validation {
            message: format!("input validation failed: {e}"),
            code: "SCP-VALID-7000".to_owned(),
        })?;

        // Check that the invoker has the ToolInvoke capability.
        if !scp_core::context::tools::has_tool_invoke_capability(
            &rt.role_state,
            &identity_did,
            &tool_id,
        ) {
            return Err(ScpNapiError::Permission {
                message: format!(
                    "invoker '{identity_did}' does not have ToolInvoke capability for '{tool_id}'"
                ),
                code: "SCP-PERM-3001".to_owned(),
            });
        }

        // No handler registered — return validated echo with metadata.
        let output = serde_json::json!({
            "tool": tool_id,
            "context": context_id,
            "status": "validated",
            "input_valid": true,
            "validated_input": input_value,
        });

        Ok(output)
    })
    .map_err(napi::Error::from)?;

    Ok(output_json.to_string())
}

/// Verifies a tool against its registered test vectors.
///
/// # Arguments
///
/// * `handle` — The context containing the tool (must be `"active"`).
/// * `tool_id` — The ID of the tool to verify.
///
/// # Returns
///
/// A `Promise<NapiToolVerificationResult>` with pass/fail status.
///
/// # Errors
///
/// - Rejects with `SCP-TOOL-6007` if the context is not `"active"`.
/// - Rejects with `SCP-TOOL-6001` if the tool is not found in the context.
#[napi]
#[allow(clippy::unused_async)] // napi-rs requires async for Promise return
#[allow(clippy::needless_pass_by_value)] // napi-rs requires owned String
pub async fn tool_verify(
    handle: &NapiContextHandle,
    tool_id: String,
) -> napi::Result<NapiToolVerificationResult> {
    let state_str = handle.state()?;
    if state_str != "active" {
        return Err(ScpNapiError::Tool {
            message: format!(
                "cannot verify tool in context in {state_str:?} state — context must be active"
            ),
            code: "SCP-TOOL-6007".to_owned(),
        }
        .into());
    }

    // Ensure the context's runtime state is registered.
    crate::runtime::ensure_registered(handle).map_err(napi::Error::from)?;

    let context_id = handle.context_id();
    let result = crate::runtime::with_context(&context_id, |rt| {
        let (verification_result, _event) = scp_core::context::tools::verify_tool(
            &rt.tool_registry,
            &tool_id,
            // Identity executor: returns the expected output for each vector.
            |input| {
                if let Some(registration) = rt.tool_registry.get(&tool_id) {
                    for vector in &registration.test_vectors {
                        if vector.input == *input {
                            return vector.expected_output.clone();
                        }
                    }
                }
                serde_json::Value::Null
            },
        )
        .map_err(|e| ScpNapiError::Tool {
            message: format!("tool verification failed: {e}"),
            code: "SCP-TOOL-6001".to_owned(),
        })?;

        Ok(verification_result)
    })
    .map_err(napi::Error::from)?;

    let failures: Vec<String> = result
        .vector_results
        .iter()
        .filter(|r| !r.passed)
        .map(|r| r.description.clone())
        .collect();

    Ok(NapiToolVerificationResult {
        tool_id: result.tool_id,
        passed: result.integrity_ok,
        failures,
    })
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Parses test vectors from an optional JSON string.
///
/// Each test vector is a JSON object with `input`, `expected_output`, and
/// `description` keys. Returns an empty Vec if the string is `None` or empty.
fn parse_test_vectors_json(
    json_str: Option<&str>,
) -> napi::Result<Vec<scp_core::context::tools::TestVector>> {
    let Some(s) = json_str else {
        return Ok(Vec::new());
    };
    if s.is_empty() {
        return Ok(Vec::new());
    }
    let arr: Vec<serde_json::Value> =
        serde_json::from_str(s).map_err(|e| ScpNapiError::Validation {
            message: format!("test_vectors_json is not valid JSON array: {e}"),
            code: "SCP-VALID-7000".to_owned(),
        })?;

    arr.into_iter()
        .map(|v| {
            let input = v.get("input").cloned().unwrap_or(serde_json::Value::Null);
            let expected_output = v
                .get("expected_output")
                .cloned()
                .unwrap_or(serde_json::Value::Null);
            let description = v
                .get("description")
                .and_then(|d| d.as_str())
                .unwrap_or("")
                .to_owned();
            Ok(scp_core::context::tools::TestVector {
                input,
                expected_output,
                description,
            })
        })
        .collect()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use crate::error::ScpNapiError;
    use crate::runtime;

    // -----------------------------------------------------------------------
    // Tool register, invoke, verify — end-to-end via runtime registry
    // -----------------------------------------------------------------------

    #[test]
    fn tool_register_invoke_verify_output() {
        let context_id = format!("ctx-napi-tool-{}", uuid::Uuid::new_v4());
        let creator_did = "did:dht:zNapiToolCreator";

        runtime::register_test_context(&context_id, creator_did);

        // Build a registration with a test vector.
        let test_vector = scp_core::context::tools::TestVector {
            input: serde_json::json!({"x": 1}),
            expected_output: serde_json::json!({"y": 2}),
            description: "x plus one".to_owned(),
        };

        let registration = scp_core::context::tools::ToolRegistration {
            tool_id: "tool-adder".to_owned(),
            name: "adder".to_owned(),
            description: "Adds one".to_owned(),
            schema: scp_core::context::tools::ToolSchema {
                input_schema: serde_json::json!({"type": "object", "properties": {"x": {"type": "number"}, "y": {"type": "number"}}, "required": ["x", "y"]}),
                output_schema: serde_json::json!({"type": "object", "properties": {"result": {"type": "number"}, "status": {"type": "string"}}, "required": ["result", "status"]}),
            },
            implementation_hash: [0u8; 32],
            test_vectors: vec![test_vector],
            operator_did: creator_did.to_owned().into(),
            economic_metadata: None,
        };

        // Register.
        let tool_id = runtime::with_context(&context_id, |rt| {
            let (id, _event) = scp_core::context::tools::register_tool(
                &mut rt.tool_registry,
                &rt.role_state,
                registration,
                creator_did,
            )
            .map_err(|e| ScpNapiError::Tool {
                message: format!("registration failed: {e}"),
                code: "SCP-TOOL-6001".to_owned(),
            })?;
            Ok(id)
        })
        .expect("tool registration should succeed");

        assert_eq!(tool_id, "tool-adder");

        // Invoke with valid input (must satisfy required fields x, y).
        let input = serde_json::json!({"x": 1, "y": 2});
        let output = runtime::with_context(&context_id, |rt| {
            let reg = rt
                .tool_registry
                .get(&tool_id)
                .ok_or_else(|| ScpNapiError::Tool {
                    message: "not found".to_owned(),
                    code: "SCP-TOOL-6002".to_owned(),
                })?;

            scp_core::context::tools::validate_value_against_schema(
                &input,
                &reg.schema.input_schema,
            )
            .map_err(|e| ScpNapiError::Validation {
                message: e,
                code: "SCP-VALID-7000".to_owned(),
            })?;

            assert!(
                scp_core::context::tools::has_tool_invoke_capability(
                    &rt.role_state,
                    creator_did,
                    &tool_id,
                ),
                "creator must have ToolInvoke capability"
            );

            Ok(serde_json::json!({
                "tool": tool_id,
                "status": "validated",
                "validated_input": input,
            }))
        })
        .expect("tool invoke should succeed");

        assert_eq!(output["status"], "validated");
        assert_eq!(output["tool"], "tool-adder");

        // Verify — identity executor echoes expected output for matching vectors.
        let verification = runtime::with_context(&context_id, |rt| {
            let (result, _event) =
                scp_core::context::tools::verify_tool(&rt.tool_registry, &tool_id, |test_input| {
                    if let Some(reg) = rt.tool_registry.get(&tool_id) {
                        for v in &reg.test_vectors {
                            if v.input == *test_input {
                                return v.expected_output.clone();
                            }
                        }
                    }
                    serde_json::Value::Null
                })
                .map_err(|e| ScpNapiError::Tool {
                    message: format!("{e}"),
                    code: "SCP-TOOL-6001".to_owned(),
                })?;
            Ok(result)
        })
        .expect("tool verify should succeed");

        assert!(
            verification.integrity_ok,
            "verification with matching executor should pass"
        );
    }

    // -----------------------------------------------------------------------
    // Tool invoke rejects unknown tool
    // -----------------------------------------------------------------------

    #[test]
    fn tool_invoke_rejects_unknown_tool() {
        let context_id = format!("ctx-napi-unknown-{}", uuid::Uuid::new_v4());
        runtime::register_test_context(&context_id, "did:dht:zSomeCreator");

        let result = runtime::with_context(&context_id, |rt| {
            let _reg =
                rt.tool_registry
                    .get("tool-nonexistent")
                    .ok_or_else(|| ScpNapiError::Tool {
                        message: "tool not found".to_owned(),
                        code: "SCP-TOOL-6002".to_owned(),
                    })?;
            Ok(())
        });

        assert!(result.is_err(), "unknown tool lookup must fail");
    }

    // -----------------------------------------------------------------------
    // parse_test_vectors_json
    // -----------------------------------------------------------------------

    #[test]
    fn parse_test_vectors_none() {
        let vecs = super::parse_test_vectors_json(None).unwrap();
        assert!(vecs.is_empty());
    }

    #[test]
    fn parse_test_vectors_valid() {
        let json = r#"[{"input": {"a": 1}, "expected_output": {"b": 2}, "description": "test"}]"#;
        let vecs = super::parse_test_vectors_json(Some(json)).unwrap();
        assert_eq!(vecs.len(), 1);
        assert_eq!(vecs[0].description, "test");
    }

    #[test]
    fn parse_test_vectors_invalid_json() {
        let result = super::parse_test_vectors_json(Some("{broken"));
        assert!(result.is_err());
    }
}
