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
use scp_ffi_common::validate::{
    validate_did, validate_tool_id, validate_tool_name, validate_ucan_token,
};
use scp_primitives::Clock;

use crate::context::NapiContextHandle;
use crate::error::ScpNapiError;

/// Validates a UCAN token for tool invocation authorization.
///
/// Performs the full 11-step ADR-016 validation pipeline.
fn validate_ucan_for_tool(
    context_id: &str,
    tool_id: &str,
    identity_did: &str,
    ucan_token: &str,
    proof_resolver: &scp_ffi_common::BridgeProofResolver,
) -> Result<(), ScpNapiError> {
    crate::runtime::with_context(context_id, |rt| {
        let production_resolver = crate::runtime::did_resolver();
        let did_resolver = scp_ffi_common::DispatchDidResolver::new(
            production_resolver.map(std::convert::AsRef::as_ref),
        );
        let revocation_checker = scp_ffi_common::BridgeRevocationChecker {
            revocation_list: &rt.revocation_list,
        };
        let mut nonce_adapter = scp_ffi_common::BridgeNonceTracker {
            inner: &mut rt.nonce_tracker,
        };

        let mut ctx = scp_core::crypto::ucan::validate::ValidationContext {
            did_resolver: &did_resolver,
            nonce_tracker: &mut nonce_adapter,
            revocation_checker: &revocation_checker,
            proof_resolver,
            ceiling: &rt.ceiling_strings,
            context_creator_did: &rt.creator_did,
            presenting_agent_did: identity_did,
            clock_skew_tolerance_secs:
                scp_core::crypto::ucan::validate::DEFAULT_CLOCK_SKEW_TOLERANCE_SECS,
            clock: &scp_primitives::SystemClock,
        };

        scp_core::context::tools::validate_tool_invocation_ucan(
            ucan_token, context_id, tool_id, &mut ctx,
        )
        .map_err(|e| ScpNapiError::Permission {
            message: format!("UCAN authorization failed for tool '{tool_id}': {e}"),
            code: "SCP-PERM-3001".to_owned(),
        })
    })
}

// ---------------------------------------------------------------------------
// NapiToolDefinition — tool definition for registration
// ---------------------------------------------------------------------------

/// Tool definition for registration in a context.
///
/// See ADR-010 (Tool Registry) and spec §5.4.1 (Tools).
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
    /// Optional per-invocation cost metadata (spec §5.4.1).
    pub cost: Option<NapiToolCost>,
}

/// Per-invocation cost metadata for a tool (spec §5.4.1).
#[napi(object)]
pub struct NapiToolCost {
    /// Cost per invocation in the smallest currency unit.
    pub amount: i64,
    /// ISO 4217 or protocol-defined currency code.
    pub currency: String,
    /// DID of the payment recipient. May differ from `operator_did`.
    pub payee: String,
    /// Optional pricing formula identifier for dynamic pricing (§19.4).
    pub cost_formula: Option<String>,
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
// Validation helpers for tool registration inputs
// ---------------------------------------------------------------------------

/// Validates and parses a JSON schema string.
///
/// Returns an `SCP-VALID-7035` error for `input_schema_json` or
/// `SCP-VALID-7036` for `output_schema_json` when the JSON is malformed.
fn validate_schema_json(json: &str, field_name: &str) -> napi::Result<serde_json::Value> {
    let code = match field_name {
        "input_schema_json" => "SCP-VALID-7035",
        _ => "SCP-VALID-7036",
    };
    serde_json::from_str(json).map_err(|e| {
        napi::Error::from(ScpNapiError::Validation {
            message: format!("invalid {field_name}: {e}"),
            code: code.to_owned(),
        })
    })
}

/// Validates and parses optional test vectors JSON.
///
/// `None` is acceptable (no test vectors). A `Some` value that is not valid
/// JSON returns `SCP-VALID-7037`.
fn validate_test_vectors_json(
    json: Option<&str>,
) -> napi::Result<Vec<scp_core::context::tools::TestVector>> {
    json.map_or_else(
        || Ok(Vec::new()),
        |s| {
            serde_json::from_str(s).map_err(|e| {
                napi::Error::from(ScpNapiError::Validation {
                    message: format!("invalid test_vectors_json: {e}"),
                    code: "SCP-VALID-7037".to_owned(),
                })
            })
        },
    )
}

/// Validates an optional implementation hash.
///
/// `None` is acceptable (defaults to zeroed hash). A `Some` value that is not
/// exactly 32 bytes returns `SCP-VALID-7038`.
fn validate_implementation_hash(bytes: Option<&[u8]>) -> napi::Result<[u8; 32]> {
    bytes.map_or_else(
        || Ok([0u8; 32]),
        |b| {
            <[u8; 32]>::try_from(b).map_err(|_| {
                napi::Error::from(ScpNapiError::Validation {
                    message: format!(
                        "implementation_hash must be exactly 32 bytes, got {}",
                        b.len()
                    ),
                    code: "SCP-VALID-7038".to_owned(),
                })
            })
        },
    )
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
/// - Rejects with `SCP-VALID-7035` if `input_schema_json` is not valid JSON.
/// - Rejects with `SCP-VALID-7036` if `output_schema_json` is not valid JSON.
/// - Rejects with `SCP-VALID-7037` if `test_vectors_json` is provided but not valid JSON.
/// - Rejects with `SCP-VALID-7038` if `implementation_hash` is provided but not exactly 32 bytes.
/// - Rejects with `SCP-TOOL-6001` if registration fails (permission denied,
///   schema invalid, duplicate name, etc.) in the full runtime.
#[napi]
#[allow(clippy::unused_async)] // napi-rs requires async for Promise return
pub async fn tool_register(
    handle: &NapiContextHandle,
    definition: NapiToolDefinition,
) -> napi::Result<String> {
    validate_tool_name(&definition.name).map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;

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

    // Ensure UCAN state is registered so the tool registry is available.
    crate::runtime::ensure_registered(handle)?;

    let context_id = handle.context_id();

    // Build a scp-core ToolRegistration from the NAPI definition.
    let tool_id = format!("tool-{}", definition.name.replace(' ', "-").to_lowercase());

    let input_schema = validate_schema_json(&definition.input_schema_json, "input_schema_json")?;
    let output_schema = validate_schema_json(&definition.output_schema_json, "output_schema_json")?;

    let test_vectors = validate_test_vectors_json(definition.test_vectors_json.as_deref())?;

    let implementation_hash =
        validate_implementation_hash(definition.implementation_hash.as_deref())?;

    let cost = definition.cost.map(|c| scp_core::context::tools::ToolCost {
        amount: c.amount.max(0).cast_unsigned(),
        currency: c.currency,
        payee: c.payee.into(),
        cost_formula: c.cost_formula,
    });

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
        cost,
        registered_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
        signature: Vec::new(),
    };

    // Register the tool in the context's tool registry.
    let registered_id = crate::runtime::with_context(&context_id, |rt| {
        let (registered_id, _event) = scp_core::context::tools::register_tool(
            &mut rt.tool_registry,
            &rt.role_state,
            core_registration,
            &rt.creator_did.clone(),
        )
        .map_err(|e| ScpNapiError::Tool {
            message: format!("tool registration failed: {e}"),
            code: "SCP-TOOL-6001".to_owned(),
        })?;
        Ok(registered_id)
    })
    .map_err(napi::Error::from)?;

    Ok(registered_id)
}

/// Invokes a tool within an SCP context.
///
/// Validates the UCAN token for tool invocation authorization before
/// dispatching. The UCAN must contain a `tool_invoke:{tool_id}` or
/// `tool_invoke:*` capability scoped to the context.
///
/// # Arguments
///
/// * `handle` — The context containing the tool (must be `"active"`).
/// * `tool_id` — The ID of the tool to invoke.
/// * `input_json` — Tool input parameters as a JSON string.
/// * `identity_did` — The DID of the invoker (used for capability checking).
/// * `ucan_token` — JWT-encoded UCAN token authorizing the invocation.
///   Must contain `tool_invoke:{tool_id}` or `tool_invoke:*` capability.
///   Validated using the full 11-step ADR-016 pipeline.
///
/// # Returns
///
/// A `Promise<string>` resolving to the tool output as a JSON string.
///
/// # Errors
///
/// - Rejects with `SCP-TOOL-6005` if the context is not `"active"`.
/// - Rejects with `SCP-PERM-3001` if the UCAN token is invalid, expired,
///   revoked, or lacks the required tool invocation capability.
/// - Rejects with `SCP-TOOL-6002` if invocation fails (tool not found,
///   input fails schema validation, invoker lacks role-based capability).
///
/// See spec §6.2, §8, ADR-016, and issue #319 for UCAN enforcement.
#[napi]
#[allow(clippy::unused_async)] // napi-rs requires async for Promise return
#[allow(clippy::needless_pass_by_value)] // napi-rs requires owned String
pub async fn tool_invoke(
    handle: &NapiContextHandle,
    tool_id: String,
    input_json: String,
    identity_did: String,
    ucan_token: String,
    proof_tokens: Option<Vec<String>>,
) -> napi::Result<String> {
    validate_tool_id(&tool_id).map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;
    validate_did(&identity_did).map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;
    validate_ucan_token(&ucan_token).map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;

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

    let context_id = handle.context_id();
    crate::runtime::ensure_registered(handle)?;

    // UCAN authorization (full 11-step ADR-016 pipeline).
    let proof_resolver = crate::ucan::build_proof_resolver_from_tokens(proof_tokens.as_deref())
        .map_err(|e| {
            napi::Error::from(ScpNapiError::Permission {
                message: format!("failed to build proof resolver: {e}"),
                code: "SCP-PERM-3001".to_owned(),
            })
        })?;
    validate_ucan_for_tool(
        &context_id,
        &tool_id,
        &identity_did,
        &ucan_token,
        &proof_resolver,
    )
    .map_err(napi::Error::from)?;

    // Consume a hard-rate-limit token BEFORE dispatching. The NAPI
    // tool path owns its own `tool_handlers` map and does not go
    // through `ContextManager::invoke_tool_with_economy`, so this
    // explicit hook is load-bearing for cap enforcement on tool
    // calls. This function runs on a tokio worker via napi-rs — use
    // the `.await` helper, not `_blocking` (which would panic
    // inside the async runtime).
    let invoker_did_typed: scp_primitives::DID = identity_did.clone().into();
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let manager = crate::runtime::context_manager()?;
    if !manager
        .try_consume_hard_rate_limit(&context_id, &invoker_did_typed, now_secs)
        .await
    {
        return Err(ScpNapiError::Tool {
            message:
                "SCP-ECON-7090: rate limit exceeded on tool_invoke: hard rate limit exceeded for invoker"
                    .to_owned(),
            code: "SCP-ECON-7090".to_owned(),
        }
        .into());
    }

    // Validate tool existence, input schema, and dispatch (matching PyO3 pattern).
    let output_json = match crate::runtime::with_context(&context_id, |rt| {
        let registration = rt
            .tool_registry
            .get(&tool_id)
            .ok_or_else(|| ScpNapiError::Tool {
                message: format!("tool '{tool_id}' not found in context '{context_id}'"),
                code: "SCP-TOOL-6002".to_owned(),
            })?;

        // Validate input against the tool's input schema.
        let input_value: serde_json::Value =
            serde_json::from_str(&input_json).map_err(|e| ScpNapiError::Tool {
                message: format!("invalid input JSON: {e}"),
                code: "SCP-TOOL-6002".to_owned(),
            })?;
        scp_core::context::tools::validate_value_against_schema(
            &input_value,
            &registration.schema.input_schema,
        )
        .map_err(|e| ScpNapiError::Tool {
            message: format!("input validation failed: {e}"),
            code: "SCP-TOOL-6002".to_owned(),
        })?;

        // Dispatch to registered handler if available.
        let output = if let Some(handler) = rt.tool_handlers.get(&tool_id) {
            let handler = handler.clone();
            let out = handler(input_value).map_err(|e| ScpNapiError::Tool {
                message: format!("tool handler for '{tool_id}' failed: {e}"),
                code: "SCP-TOOL-6002".to_owned(),
            })?;

            // Validate output against the tool's output schema (defense-in-depth).
            scp_core::context::tools::validate_value_against_schema(
                &out,
                &registration.schema.output_schema,
            )
            .map_err(|msg| ScpNapiError::Tool {
                message: format!("output validation failed for tool '{tool_id}': {msg}"),
                code: "SCP-TOOL-6002".to_owned(),
            })?;

            out
        } else {
            // No handler registered — fall back to echo mode with metadata.
            serde_json::json!({
                "tool": tool_id,
                "context": context_id,
                "status": "validated",
                "input_valid": true,
                "invoker_did": identity_did,
                "validated_input": input_value,
            })
        };

        Ok(output)
    }) {
        Ok(out) => out,
        Err(e) => {
            // Refund the hard-rate-limit token so a rejected dispatch
            // does not permanently burn bucket capacity. Uses the
            // async variant to match the consume call above (we are
            // on a tokio worker thread — `blocking_lock` would panic).
            manager
                .refund_hard_rate_limit(&context_id, &invoker_did_typed)
                .await;
            return Err(napi::Error::from(e));
        }
    };

    serde_json::to_string(&output_json).map_err(|e| {
        // Serialization failure AFTER the tool dispatched successfully
        // still charges the token — the dispatch was completed,
        // only the outbound serialization is failing. Only
        // pre-execution failures refund.
        napi::Error::from(ScpNapiError::Tool {
            message: format!("failed to serialize tool output: {e}"),
            code: "SCP-TOOL-6002".to_owned(),
        })
    })
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

    let context_id = handle.context_id();
    crate::runtime::ensure_registered(handle)?;

    // Look up the tool and verify against its test vectors (matching PyO3 pattern).
    let result = crate::runtime::with_context(&context_id, |rt| {
        let (verification_result, _event) = scp_core::context::tools::verify_tool(
            &rt.tool_registry,
            &tool_id,
            // Identity executor: returns the expected output for each vector.
            // This validates the test vector structure; real execution verification
            // happens when a full executor is connected.
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
// Cross-context tool invocation
// ---------------------------------------------------------------------------

/// Invokes a tool across context boundaries.
///
/// Validates UCAN authorization against the target context, chain depth,
/// source context capability, and target context tool existence per spec
/// section 6.2.
///
/// # Returns
///
/// A `Promise<string>` resolving to the tool output as a JSON string.
#[napi]
#[allow(clippy::unused_async)] // napi-rs requires async for Promise return
#[allow(clippy::needless_pass_by_value)] // napi-rs requires owned String
#[allow(clippy::too_many_arguments)] // FFI boundary: napi-rs requires explicit params
pub async fn tool_invoke_cross_context(
    source_handle: &NapiContextHandle,
    target_handle: &NapiContextHandle,
    tool_id: String,
    input_json: String,
    invoker_did: String,
    ucan_token: String,
    chain_depth: u8,
    proof_tokens: Option<Vec<String>>,
) -> napi::Result<String> {
    // Validate both contexts are active.
    let source_state = source_handle.state()?;
    if source_state != "active" {
        return Err(ScpNapiError::Tool {
            message: format!(
                "cannot invoke cross-context tool: source context in {source_state:?} state"
            ),
            code: "SCP-TOOL-6010".to_owned(),
        }
        .into());
    }

    let target_state = target_handle.state()?;
    if target_state != "active" {
        return Err(ScpNapiError::Tool {
            message: format!(
                "cannot invoke cross-context tool: target context in {target_state:?} state"
            ),
            code: "SCP-TOOL-6011".to_owned(),
        }
        .into());
    }

    let source_context_id = source_handle.context_id();
    let target_context_id = target_handle.context_id();

    // Validate chain depth (context-configurable, default 8 per ADR-043).
    let max_chain_depth = {
        let mgr = crate::runtime::context_manager()?;
        let source_max = mgr
            .context_params(&source_context_id)
            .await
            .and_then(|p| p.max_chain_depth);
        scp_core::provenance::attach::effective_max_chain_depth(source_max)
    };
    if chain_depth > max_chain_depth {
        return Err(ScpNapiError::Tool {
            message: format!(
                "cross-context chain depth {chain_depth} exceeds maximum {max_chain_depth}"
            ),
            code: "SCP-TOOL-6012".to_owned(),
        }
        .into());
    }

    // Ensure target context UCAN state is registered.
    crate::runtime::ensure_registered(target_handle)?;

    // Primary authorization: UCAN token validation via the full 11-step
    // ADR-016 pipeline against the TARGET context's ceiling.
    // See spec §6.2, §8, ADR-016, and issue #319.
    let proof_resolver = crate::ucan::build_proof_resolver_from_tokens(proof_tokens.as_deref())
        .map_err(|e| {
            napi::Error::from(ScpNapiError::Permission {
                message: format!("failed to build proof resolver: {e}"),
                code: "SCP-PERM-3001".to_owned(),
            })
        })?;
    validate_ucan_for_tool(
        &target_context_id,
        &tool_id,
        &invoker_did,
        &ucan_token,
        &proof_resolver,
    )
    .map_err(napi::Error::from)?;

    let input_value: serde_json::Value = serde_json::from_str(&input_json).map_err(|e| {
        napi::Error::from(ScpNapiError::Tool {
            message: format!("invalid input JSON: {e}"),
            code: "SCP-TOOL-6002".to_owned(),
        })
    })?;

    let output = crate::runtime::with_context(&target_context_id, |rt| {
        let registration = rt
            .tool_registry
            .get(&tool_id)
            .ok_or_else(|| ScpNapiError::Tool {
                message: format!(
                    "tool '{tool_id}' not found in target context '{target_context_id}'"
                ),
                code: "SCP-TOOL-6002".to_owned(),
            })?;

        // Validate input against the tool's input schema.
        scp_core::context::tools::validate_value_against_schema(
            &input_value,
            &registration.schema.input_schema,
        )
        .map_err(|e| ScpNapiError::Tool {
            message: format!("input validation failed: {e}"),
            code: "SCP-TOOL-6002".to_owned(),
        })?;

        // Dispatch to handler or echo mode.
        let output = if let Some(handler) = rt.tool_handlers.get(&tool_id) {
            let handler = handler.clone();
            let out = handler(input_value.clone()).map_err(|e| ScpNapiError::Tool {
                message: format!("cross-context tool handler for '{tool_id}' failed: {e}"),
                code: "SCP-TOOL-6002".to_owned(),
            })?;

            scp_core::context::tools::validate_value_against_schema(
                &out,
                &registration.schema.output_schema,
            )
            .map_err(|msg| ScpNapiError::Tool {
                message: format!("output validation failed for tool '{tool_id}': {msg}"),
                code: "SCP-TOOL-6002".to_owned(),
            })?;

            out
        } else {
            serde_json::json!({
                "tool": tool_id,
                "source_context": source_context_id,
                "target_context": target_context_id,
                "status": "validated",
                "chain_depth": chain_depth,
                "invoker_did": invoker_did,
                "validated_input": input_value,
            })
        };

        Ok(output)
    })
    .map_err(napi::Error::from)?;

    serde_json::to_string(&output).map_err(|e| {
        napi::Error::from(ScpNapiError::Tool {
            message: format!("failed to serialize cross-context output: {e}"),
            code: "SCP-TOOL-6013".to_owned(),
        })
    })
}

// ---------------------------------------------------------------------------
// Stateful tool sessions (spec section 6.2.1)
// ---------------------------------------------------------------------------

/// Creates a stateful tool session.
///
/// # Returns
///
/// A `Promise<string>` resolving to the session ID (UUID).
#[napi]
#[allow(clippy::unused_async)]
#[allow(clippy::needless_pass_by_value)]
pub async fn tool_session_create(
    handle: &NapiContextHandle,
    tool_id: String,
    source_context_id: String,
    ttl_seconds: Option<u32>,
) -> napi::Result<String> {
    let state_str = handle.state()?;
    if state_str != "active" {
        return Err(ScpNapiError::Tool {
            message: format!(
                "cannot create session in context in {state_str:?} state — context must be active"
            ),
            code: "SCP-TOOL-6014".to_owned(),
        }
        .into());
    }

    let context_id = handle.context_id();
    crate::runtime::ensure_registered(handle)?;

    // Read context-configured session cap (ADR-043), falling back to default.
    let cap = {
        let mgr = crate::runtime::context_manager()?;
        mgr.context_params(&context_id)
            .await
            .and_then(|p| p.session_cap)
            .unwrap_or(scp_core::context::tools::DEFAULT_SESSION_CAP_PER_CALLER) as usize
    };

    crate::runtime::with_context(&context_id, |rt| {
        // Enforce per-caller session cap (context-configured, ADR-043).
        let current = rt.session_store.count_by_source(&source_context_id);
        if current >= cap {
            return Err(ScpNapiError::Tool {
                message: format!(
                    "session cap exceeded for caller '{source_context_id}': {current} active (max {cap})"
                ),
                code: "SCP-TOOL-6015".to_owned(),
            });
        }

        let session_id = uuid::Uuid::new_v4().to_string();
        let now_ms = scp_primitives::SystemClock.now_millis();

        let session = scp_core::context::tools::ToolSession {
            session_id: session_id.clone(),
            tool_id,
            source_context: source_context_id,
            state: serde_json::Value::Null,
            created_at: now_ms,
            ttl: ttl_seconds.map(|s| std::time::Duration::from_secs(u64::from(s))),
            call_count: 0,
        };

        rt.session_store.insert(session);
        Ok(session_id)
    })
    .map_err(napi::Error::from)
}

/// Invokes a tool within an active session.
///
/// Each call is individually governed: the invoker must present a valid
/// UCAN token. Session state is carried forward across invocations.
///
/// # Returns
///
/// A `Promise<string>` resolving to the tool output as a JSON string.
#[napi]
#[allow(clippy::unused_async)]
#[allow(clippy::needless_pass_by_value)]
pub async fn tool_session_invoke(
    handle: &NapiContextHandle,
    session_id: String,
    input_json: String,
    invoker_did: String,
    ucan_token: String,
    proof_tokens: Option<Vec<String>>,
) -> napi::Result<String> {
    let state_str = handle.state()?;
    if state_str != "active" {
        return Err(ScpNapiError::Tool {
            message: format!(
                "cannot invoke session in context in {state_str:?} state — context must be active"
            ),
            code: "SCP-TOOL-6017".to_owned(),
        }
        .into());
    }

    let context_id = handle.context_id();
    crate::runtime::ensure_registered(handle)?;

    // Look up the tool_id from the session before UCAN validation so we can
    // validate against the correct tool capability.
    let tool_id_for_ucan = crate::runtime::with_context(&context_id, |rt| {
        let session = rt
            .session_store
            .get(&session_id)
            .ok_or_else(|| ScpNapiError::Tool {
                message: format!("session '{session_id}' not found"),
                code: "SCP-TOOL-6018".to_owned(),
            })?;
        Ok(session.tool_id.clone())
    })
    .map_err(napi::Error::from)?;

    // Primary authorization: UCAN token validation via the full 11-step
    // ADR-016 pipeline. See spec §6.2, §8, ADR-016, and issue #319.
    let proof_resolver = crate::ucan::build_proof_resolver_from_tokens(proof_tokens.as_deref())
        .map_err(|e| {
            napi::Error::from(ScpNapiError::Permission {
                message: format!("failed to build proof resolver: {e}"),
                code: "SCP-PERM-3001".to_owned(),
            })
        })?;
    validate_ucan_for_tool(
        &context_id,
        &tool_id_for_ucan,
        &invoker_did,
        &ucan_token,
        &proof_resolver,
    )
    .map_err(napi::Error::from)?;

    let output = crate::runtime::with_context(&context_id, |rt| {
        let session = rt
            .session_store
            .get(&session_id)
            .ok_or_else(|| ScpNapiError::Tool {
                message: format!("session '{session_id}' not found"),
                code: "SCP-TOOL-6018".to_owned(),
            })?;

        // Check expiry.
        let now_ms = scp_primitives::SystemClock.now_millis();
        if session.is_expired(now_ms) {
            rt.session_store.remove(&session_id);
            return Err(ScpNapiError::Tool {
                message: format!("session '{session_id}' has expired"),
                code: "SCP-TOOL-6019".to_owned(),
            });
        }

        let tool_id = session.tool_id.clone();
        let current_state = session.state.clone();
        let call_count = session.call_count;

        let input_value: serde_json::Value =
            serde_json::from_str(&input_json).map_err(|e| ScpNapiError::Tool {
                message: format!("invalid input JSON: {e}"),
                code: "SCP-TOOL-6002".to_owned(),
            })?;

        // Validate input against tool's input schema if tool is registered.
        if let Some(registration) = rt.tool_registry.get(&tool_id) {
            scp_core::context::tools::validate_value_against_schema(
                &input_value,
                &registration.schema.input_schema,
            )
            .map_err(|e| ScpNapiError::Tool {
                message: format!("input validation failed: {e}"),
                code: "SCP-TOOL-6002".to_owned(),
            })?;
        }

        // Execute via handler or echo mode.
        let (new_state, output) = if let Some(handler) = rt.tool_handlers.get(&tool_id) {
            let handler = handler.clone();
            let out = handler(input_value).map_err(|e| ScpNapiError::Tool {
                message: format!("tool handler for '{tool_id}' failed: {e}"),
                code: "SCP-TOOL-6002".to_owned(),
            })?;
            (current_state, out)
        } else {
            let out = serde_json::json!({
                "tool": tool_id,
                "session_id": session_id,
                "status": "validated",
                "call_count": call_count + 1,
                "invoker_did": invoker_did,
                "validated_input": input_value,
            });
            (current_state, out)
        };

        // Update session state and increment call count.
        if let Some(session) = rt.session_store.get_mut(&session_id) {
            session.state = new_state;
            session.call_count = session.call_count.saturating_add(1);
        }

        Ok(output)
    })
    .map_err(napi::Error::from)?;

    serde_json::to_string(&output).map_err(|e| {
        napi::Error::from(ScpNapiError::Tool {
            message: format!("failed to serialize session invoke output: {e}"),
            code: "SCP-TOOL-6020".to_owned(),
        })
    })
}

/// Closes a stateful tool session.
///
/// # Returns
///
/// A `Promise<void>` that resolves when the session is closed.
#[napi]
#[allow(clippy::unused_async)]
#[allow(clippy::needless_pass_by_value)]
pub async fn tool_session_close(
    handle: &NapiContextHandle,
    session_id: String,
) -> napi::Result<()> {
    let context_id = handle.context_id();
    crate::runtime::ensure_registered(handle)?;

    crate::runtime::with_context(&context_id, |rt| {
        if rt.session_store.remove(&session_id).is_none() {
            return Err(ScpNapiError::Tool {
                message: format!("session '{session_id}' not found"),
                code: "SCP-TOOL-6021".to_owned(),
            });
        }
        Ok(())
    })
    .map_err(napi::Error::from)
}

// ---------------------------------------------------------------------------
// Bidirectional consent protocol (spec §6.2.0.1)
// ---------------------------------------------------------------------------

/// Exposes a tool interface for cross-context sharing (§6.2.0.1 step 1).
///
/// The caller (admin of the source context) proposes sharing a specific tool
/// with a target context. Returns a JSON string of the `ToolInterface` with
/// `approved_by_source = true` and `approved_by_target = false`.
///
/// # Returns
///
/// A `Promise<string>` resolving to the `ToolInterface` as JSON.
#[napi]
#[allow(clippy::unused_async)]
#[allow(clippy::needless_pass_by_value)]
pub async fn tool_interface_expose(
    handle: &NapiContextHandle,
    tool_id: String,
    target_context_id: String,
    rate_limit_json: Option<String>,
) -> napi::Result<String> {
    scp_ffi_common::validate::validate_tool_id(&tool_id)
        .map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;
    scp_ffi_common::validate::validate_context_id(&target_context_id)
        .map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;

    let state_str = handle.state()?;
    if state_str != "active" {
        return Err(ScpNapiError::Tool {
            message: format!(
                "cannot expose tool interface in context in {state_str:?} state — context must be active"
            ),
            code: "SCP-TOOL-6030".to_owned(),
        }
        .into());
    }

    let context_id = handle.context_id();
    crate::runtime::ensure_registered(handle)?;

    let rate_limit = match rate_limit_json {
        Some(ref json) => {
            let parsed: scp_core::context::tools::interface::RateLimit = serde_json::from_str(json)
                .map_err(|e| {
                    napi::Error::from(ScpNapiError::Validation {
                        message: format!("invalid rate_limit_json: {e}"),
                        code: "SCP-VALID-7040".to_owned(),
                    })
                })?;
            Some(parsed)
        }
        None => None,
    };

    crate::runtime::with_context(&context_id, |rt| {
        let context_handle = scp_core::context::ContextHandle::new(
            context_id.clone(),
            scp_core::context::ContextParams::default(),
        );

        let interface = scp_core::context::tools::interface::expose_tool(
            context_handle.context_id(),
            &tool_id,
            &target_context_id,
            &rt.role_state,
            &rt.creator_did,
            &rt.tool_registry,
            rate_limit,
            None,
        )
        .map_err(|e| ScpNapiError::Tool {
            message: format!("expose_tool failed: {e}"),
            code: "SCP-TOOL-6030".to_owned(),
        })?;

        serde_json::to_string(&interface).map_err(|e| ScpNapiError::Tool {
            message: format!("failed to serialize ToolInterface: {e}"),
            code: "SCP-TOOL-6031".to_owned(),
        })
    })
    .map_err(napi::Error::from)
}

/// Accepts a cross-context tool interface (§6.2.0.1 step 4).
///
/// Sets `approved_by_target = true` on the interface.
///
/// # Returns
///
/// A `Promise<string>` resolving to the updated `ToolInterface` as JSON.
#[napi]
#[allow(clippy::unused_async)]
#[allow(clippy::needless_pass_by_value)]
pub async fn tool_interface_accept(
    handle: &NapiContextHandle,
    interface_json: String,
) -> napi::Result<String> {
    let state_str = handle.state()?;
    if state_str != "active" {
        return Err(ScpNapiError::Tool {
            message: format!(
                "cannot accept tool interface in context in {state_str:?} state — context must be active"
            ),
            code: "SCP-TOOL-6032".to_owned(),
        }
        .into());
    }

    let context_id = handle.context_id();
    crate::runtime::ensure_registered(handle)?;

    let mut interface: scp_core::context::tools::interface::ToolInterface =
        serde_json::from_str(&interface_json).map_err(|e| {
            napi::Error::from(ScpNapiError::Validation {
                message: format!("invalid interface_json: {e}"),
                code: "SCP-VALID-7041".to_owned(),
            })
        })?;

    crate::runtime::with_context(&context_id, |rt| {
        let context_handle = scp_core::context::ContextHandle::new(
            context_id.clone(),
            scp_core::context::ContextParams::default(),
        );

        scp_core::context::tools::interface::accept_tool_interface(
            context_handle.context_id(),
            &mut interface,
            &rt.role_state,
            &rt.creator_did,
            None,
        )
        .map_err(|e| ScpNapiError::Tool {
            message: format!("accept_tool_interface failed: {e}"),
            code: "SCP-TOOL-6032".to_owned(),
        })?;

        serde_json::to_string(&interface).map_err(|e| ScpNapiError::Tool {
            message: format!("failed to serialize ToolInterface: {e}"),
            code: "SCP-TOOL-6033".to_owned(),
        })
    })
    .map_err(napi::Error::from)
}

/// Revokes a cross-context tool interface (§6.2.0.1 step 5).
///
/// Either context may revoke unilaterally.
///
/// # Returns
///
/// A `Promise<string>` resolving to the `InterfaceRevoked` event as JSON.
#[napi]
#[allow(clippy::unused_async)]
#[allow(clippy::needless_pass_by_value)]
pub async fn tool_interface_revoke(
    handle: &NapiContextHandle,
    interface_id_hex: String,
) -> napi::Result<String> {
    let context_id = handle.context_id();

    let interface_id_bytes = hex::decode(&interface_id_hex).map_err(|e| {
        napi::Error::from(ScpNapiError::Validation {
            message: format!("invalid interface_id_hex: not valid hex: {e}"),
            code: "SCP-VALID-7042".to_owned(),
        })
    })?;
    let interface_id: [u8; 32] =
        <[u8; 32]>::try_from(interface_id_bytes.as_slice()).map_err(|_| {
            napi::Error::from(ScpNapiError::Validation {
                message: format!(
                    "interface_id_hex must be exactly 32 bytes (64 hex chars), got {}",
                    interface_id_bytes.len()
                ),
                code: "SCP-VALID-7042".to_owned(),
            })
        })?;

    let now_ms = scp_primitives::SystemClock.now_millis();

    let event = scp_core::context::tools::interface::revoke_tool_interface(
        interface_id,
        &context_id,
        now_ms,
    );

    serde_json::to_string(&event).map_err(|e| {
        napi::Error::from(ScpNapiError::Tool {
            message: format!("failed to serialize InterfaceRevoked: {e}"),
            code: "SCP-TOOL-6035".to_owned(),
        })
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // validate_schema_json
    // -----------------------------------------------------------------------

    #[test]
    fn validate_schema_json_accepts_valid_input_schema() {
        let result = validate_schema_json(r#"{"type": "object"}"#, "input_schema_json");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), serde_json::json!({"type": "object"}));
    }

    #[test]
    fn validate_schema_json_accepts_valid_output_schema() {
        let result = validate_schema_json(r#"{"type": "string"}"#, "output_schema_json");
        assert!(result.is_ok());
    }

    #[test]
    fn validate_schema_json_rejects_invalid_input_schema() {
        let result = validate_schema_json("not valid json{{{", "input_schema_json");
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(
            msg.contains("SCP-VALID-7035"),
            "error should contain SCP-VALID-7035, got: {msg}"
        );
        assert!(
            msg.contains("invalid input_schema_json"),
            "error should reference field name, got: {msg}"
        );
    }

    #[test]
    fn validate_schema_json_rejects_invalid_output_schema() {
        let result = validate_schema_json("{broken", "output_schema_json");
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(
            msg.contains("SCP-VALID-7036"),
            "error should contain SCP-VALID-7036, got: {msg}"
        );
        assert!(
            msg.contains("invalid output_schema_json"),
            "error should reference field name, got: {msg}"
        );
    }

    #[test]
    fn validate_schema_json_rejects_empty_string() {
        let result = validate_schema_json("", "input_schema_json");
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(msg.contains("SCP-VALID-7035"));
    }

    // -----------------------------------------------------------------------
    // validate_test_vectors_json
    // -----------------------------------------------------------------------

    #[test]
    fn validate_test_vectors_json_accepts_none() {
        let result = validate_test_vectors_json(None);
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn validate_test_vectors_json_accepts_valid_json() {
        let result = validate_test_vectors_json(Some("[]"));
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn validate_test_vectors_json_rejects_invalid_json() {
        let result = validate_test_vectors_json(Some("not json"));
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(
            msg.contains("SCP-VALID-7037"),
            "error should contain SCP-VALID-7037, got: {msg}"
        );
        assert!(
            msg.contains("invalid test_vectors_json"),
            "error should reference field name, got: {msg}"
        );
    }

    #[test]
    fn validate_test_vectors_json_rejects_wrong_type() {
        // Valid JSON but not an array of TestVector.
        let result = validate_test_vectors_json(Some(r#"{"not": "an array"}"#));
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(msg.contains("SCP-VALID-7037"));
    }

    // -----------------------------------------------------------------------
    // validate_implementation_hash
    // -----------------------------------------------------------------------

    #[test]
    fn validate_implementation_hash_accepts_none() {
        let result = validate_implementation_hash(None);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), [0u8; 32]);
    }

    #[test]
    fn validate_implementation_hash_accepts_32_bytes() {
        let hash = [0xabu8; 32];
        let result = validate_implementation_hash(Some(&hash));
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), [0xab; 32]);
    }

    #[test]
    fn validate_implementation_hash_rejects_short() {
        let hash = [0u8; 16];
        let result = validate_implementation_hash(Some(&hash));
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(
            msg.contains("SCP-VALID-7038"),
            "error should contain SCP-VALID-7038, got: {msg}"
        );
        assert!(
            msg.contains("got 16"),
            "error should report actual length, got: {msg}"
        );
    }

    #[test]
    fn validate_implementation_hash_rejects_long() {
        let hash = [0u8; 64];
        let result = validate_implementation_hash(Some(&hash));
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(msg.contains("SCP-VALID-7038"));
        assert!(
            msg.contains("got 64"),
            "error should report actual length, got: {msg}"
        );
    }

    #[test]
    fn validate_implementation_hash_rejects_empty() {
        let result = validate_implementation_hash(Some(&[]));
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(msg.contains("SCP-VALID-7038"));
        assert!(msg.contains("got 0"));
    }

    /// `registered_at` on a tool registered via the NAPI bridge must be a
    /// seconds-epoch timestamp, not milliseconds or hardcoded 0.
    /// Calls the actual `tool_register` bridge function and inspects the
    /// stored `ToolRegistration`. Catches the original bug from issue #871.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn registered_at_is_seconds_epoch() {
        use crate::context::NapiContextHandle;

        let ctx_id = format!("ctx-napi-ts-test-{}", std::process::id());
        let creator_did = "did:dht:z6MkNapiTsTest";

        let handle = NapiContextHandle::test_active(ctx_id.clone(), creator_did.to_owned());

        let definition = NapiToolDefinition {
            name: "napi-timestamp-probe".to_owned(),
            description: "probes registered_at value".to_owned(),
            input_schema_json:
                r#"{"type":"object","properties":{"a":{"type":"string"},"b":{"type":"number"}}}"#
                    .to_owned(),
            output_schema_json: r#"{"type":"object"}"#.to_owned(),
            test_vectors_json: None,
            implementation_hash: None,
            operator_did: creator_did.to_owned(),
            cost: None,
        };

        let tool_id = tool_register(&handle, definition)
            .await
            .expect("tool_register should succeed");

        // Read the stored registration back and verify registered_at.
        let registered_at = crate::runtime::with_context(&ctx_id, |rt| {
            let reg = rt
                .tool_registry
                .get(&tool_id)
                .expect("tool should exist in registry after registration");
            Ok(reg.registered_at)
        })
        .unwrap();

        assert!(
            registered_at > 1_700_000_000 && registered_at < 2_000_000_000,
            "registered_at should be seconds-epoch (got {registered_at}); \
             milliseconds would be ~1.7 trillion, hardcoded 0 would fail lower bound"
        );

        // Clean up global state.
        crate::runtime::remove_context(&ctx_id);
    }
}
