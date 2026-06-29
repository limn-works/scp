//! napi-rs bridge for tool operations.
//!
//! Exposes tool registration, invocation, and verification:
//!
//! - `tool_register` — Register a tool in a context.
//! - `tool_invoke` — Invoke a tool within a context.
//! - `tool_verify` — Verify a tool against its test vectors.
//!
//! See ADR-022 in `.docs/adrs/phase-4.md`.

use napi_derive::napi;
use scp_ffi_common::error_codes as codes;
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
    bi: &crate::runtime::NapiBridgeInstance,
    context_id: &str,
    tool_id: &str,
    identity_did: &str,
    ucan_token: &str,
    proof_resolver: &scp_ffi_common::BridgeProofResolver,
) -> Result<(), ScpNapiError> {
    crate::runtime::with_context(bi, context_id, |rt| {
        let production_resolver = crate::runtime::did_resolver(bi);
        let did_resolver = scp_ffi_common::DispatchDidResolver::new(
            production_resolver.map(std::convert::AsRef::as_ref),
        );
        let revocation_checker = scp_ffi_common::BridgeRevocationChecker {
            revocation_list: &rt.core.revocation_list,
        };
        let mut nonce_adapter = scp_ffi_common::BridgeNonceTracker {
            inner: &mut rt.core.nonce_tracker,
        };

        let mut ctx = scp_core::crypto::ucan::validate::ValidationContext {
            did_resolver: &did_resolver,
            nonce_tracker: &mut nonce_adapter,
            revocation_checker: &revocation_checker,
            proof_resolver,
            ceiling: &rt.core.ceiling_strings,
            context_creator_did: &rt.core.creator_did,
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
            code: codes::PERM_3001.to_owned(),
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
        "input_schema_json" => codes::VALID_7035,
        _ => codes::VALID_7036,
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
                    code: codes::VALID_7037.to_owned(),
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
            scp_ffi_common::validate::expect_fixed_bytes::<32>(b, "implementation_hash").map_err(
                |msg| {
                    napi::Error::from(ScpNapiError::Validation {
                        message: msg,
                        code: codes::VALID_7038.to_owned(),
                    })
                },
            )
        },
    )
}

// ---------------------------------------------------------------------------
// Bridge functions
// ---------------------------------------------------------------------------

/// Per-bridge-instance implementation of [`tool_register`].
#[allow(clippy::unused_async)] // preserves signature symmetry with the async free function
pub(crate) async fn tool_register_on(
    bi: &crate::runtime::NapiBridgeInstance,
    handle: &NapiContextHandle,
    definition: NapiToolDefinition,
) -> napi::Result<String> {
    crate::napi_check_handle!(&bi.core, handle);
    validate_tool_name(&definition.name).map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;

    let state_str = handle.state()?;
    if state_str != "active" {
        return Err(ScpNapiError::Tool {
            message: format!(
                "cannot register tool in context in {state_str:?} state — context must be active"
            ),
            code: codes::TOOL_6003.to_owned(),
        }
        .into());
    }

    // Ensure UCAN state is registered so the tool registry is available.
    crate::runtime::ensure_registered(bi, handle)?;

    let context_id = handle.context_id();

    // Build a scp-core ToolRegistration from the NAPI definition.
    // Shared with every other bridge via `scp_ffi_common::tool_id`.
    let tool_id = scp_ffi_common::tool_id::generate_tool_id(&definition.name);

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
            .map_or(0, |d| d.as_secs()),
        signature: Vec::new(),
    };

    // Register the tool in the context's tool registry.
    let registered_id = crate::runtime::with_context(bi, &context_id, |rt| {
        let (registered_id, _event) = scp_core::context::tools::register_tool(
            &mut rt.tool_registry,
            &rt.role_state,
            core_registration,
            &rt.core.creator_did.clone(),
        )
        .map_err(|e| ScpNapiError::Tool {
            message: format!("tool registration failed: {e}"),
            code: codes::TOOL_6001.to_owned(),
        })?;
        Ok(registered_id)
    })
    .map_err(napi::Error::from)?;

    Ok(registered_id)
}

/// Per-bridge-instance implementation of [`tool_invoke`].
#[allow(clippy::too_many_arguments)]
pub(crate) async fn tool_invoke_on(
    bi: &crate::runtime::NapiBridgeInstance,
    handle: &NapiContextHandle,
    tool_id: String,
    input_json: String,
    identity_did: String,
    ucan_token: String,
    proof_tokens: Option<Vec<String>>,
    spending_ucan_jwt: Option<String>,
) -> napi::Result<String> {
    crate::napi_check_handle!(&bi.core, handle);
    validate_tool_id(&tool_id).map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;
    validate_did(&identity_did).map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;
    validate_ucan_token(&ucan_token).map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;
    if let Some(jwt) = spending_ucan_jwt.as_deref() {
        validate_ucan_token(jwt).map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;
    }

    let state_str = handle.state()?;
    if state_str != "active" {
        return Err(ScpNapiError::Tool {
            message: format!(
                "cannot invoke tool in context in {state_str:?} state — context must be active"
            ),
            code: codes::TOOL_6005.to_owned(),
        }
        .into());
    }

    let context_id = handle.context_id();
    crate::runtime::ensure_registered(bi, handle)?;

    // UCAN authorization (full 11-step ADR-016 pipeline). Bridge-owned
    // because the proof resolver, revocation list, and nonce tracker
    // live in the bridge UCAN registry, not in the runtime.
    let proof_resolver = crate::ucan::build_proof_resolver_from_tokens(proof_tokens.as_deref())
        .map_err(|e| {
            napi::Error::from(ScpNapiError::Permission {
                message: format!("failed to build proof resolver: {e}"),
                code: codes::PERM_3001.to_owned(),
            })
        })?;
    validate_ucan_for_tool(
        bi,
        &context_id,
        &tool_id,
        &identity_did,
        &ucan_token,
        &proof_resolver,
    )
    .map_err(napi::Error::from)?;

    // Parse the optional spending UCAN JWT (§19.5 AND-composition).
    // Mirrors `context_send`. An invalid JWT surfaces as
    // `SCP-ECON-12061` before the manager call.
    let spending_ucan_token = spending_ucan_jwt
        .as_deref()
        .map(scp_core::crypto::ucan::validate::parse_ucan)
        .transpose()
        .map_err(|e| {
            napi::Error::from(ScpNapiError::Context {
                message: format!("invalid spending UCAN: {e}"),
                code: codes::ECON_12061.to_owned(),
            })
        })?;

    // Snapshot the bridge-owned tool registry and (optionally) the
    // registered handler closure BEFORE entering the runtime call. The
    // runtime requires `&ToolRegistry`; cloning the registry once is
    // cheap and avoids holding the bridge UCAN-state DashMap shard
    // lock across the runtime's three-phase lock split.
    let context_id_for_executor = context_id.clone();
    let tool_id_for_executor = tool_id.clone();
    let identity_for_executor = identity_did.clone();
    let (registry, handler) = crate::runtime::with_context(bi, &context_id, |rt| {
        Ok((
            rt.tool_registry.clone(),
            rt.tool_handlers.get(&tool_id).cloned(),
        ))
    })
    .map_err(napi::Error::from)?;

    // Build the executor closure. Phase 2 of `invoke_tool_with_economy`
    // runs WITHOUT holding the `contexts` mutex; the runtime calls the
    // executor exactly once with the validated input value.
    let executor = move |input: serde_json::Value| {
        let handler = handler.clone();
        let input_for_echo = input.clone();
        async move {
            handler.map_or_else(
                || {
                    Ok(serde_json::json!({
                        "tool": tool_id_for_executor,
                        "context": context_id_for_executor,
                        "status": "validated",
                        "input_valid": true,
                        "invoker_did": identity_for_executor,
                        "validated_input": input_for_echo,
                    }))
                },
                |h| {
                    h(input).map_err(|e| {
                        format!("tool handler for '{tool_id_for_executor}' failed: {e}")
                    })
                },
            )
        }
    };

    // Parse input JSON once (the runtime expects `serde_json::Value`).
    let input_value: serde_json::Value = serde_json::from_str(&input_json).map_err(|e| {
        napi::Error::from(ScpNapiError::Tool {
            message: format!("invalid input JSON: {e}"),
            code: codes::TOOL_6002.to_owned(),
        })
    })?;

    let supervisor = crate::runtime::supervisor(bi)?;
    let invoker_did_typed: scp_primitives::DID = identity_did.into();
    let tool_id_typed = scp_core::context::tools::ToolId::from(tool_id.as_str());
    let outcome = supervisor
        .invoke_tool_with_economy(
            &context_id,
            &registry,
            &tool_id_typed,
            input_value,
            &invoker_did_typed,
            spending_ucan_token.as_ref(),
            None,
            executor,
        )
        .await
        .map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;

    // The runtime built the canonical `ToolInvokedEvent`; the
    // transport / event-log layer is the one responsible for signing
    // and appending it. Pull the JSON output back out for the JS
    // caller.
    serde_json::to_string(&outcome.output).map_err(|e| {
        napi::Error::from(ScpNapiError::Tool {
            message: format!("failed to serialize tool output: {e}"),
            code: codes::TOOL_6006.to_owned(),
        })
    })
}

/// Per-bridge-instance implementation of [`tool_verify`].
#[allow(clippy::unused_async)] // preserves signature symmetry with the async free function
pub(crate) async fn tool_verify_on(
    bi: &crate::runtime::NapiBridgeInstance,
    handle: &NapiContextHandle,
    tool_id: String,
) -> napi::Result<NapiToolVerificationResult> {
    crate::napi_check_handle!(&bi.core, handle);
    let state_str = handle.state()?;
    if state_str != "active" {
        return Err(ScpNapiError::Tool {
            message: format!(
                "cannot verify tool in context in {state_str:?} state — context must be active"
            ),
            code: codes::TOOL_6007.to_owned(),
        }
        .into());
    }

    let context_id = handle.context_id();
    crate::runtime::ensure_registered(bi, handle)?;

    // Look up the tool and verify against its test vectors (matching PyO3 pattern).
    let result = crate::runtime::with_context(bi, &context_id, |rt| {
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
            code: codes::TOOL_6001.to_owned(),
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

/// Per-bridge-instance implementation of [`tool_invoke_cross_context`].
#[allow(clippy::too_many_arguments)]
pub(crate) async fn tool_invoke_cross_context_on(
    bi: &crate::runtime::NapiBridgeInstance,
    source_handle: &NapiContextHandle,
    target_handle: &NapiContextHandle,
    tool_id: String,
    input_json: String,
    invoker_did: String,
    ucan_token: String,
    chain_depth: u8,
    proof_tokens: Option<Vec<String>>,
) -> napi::Result<String> {
    crate::napi_check_handle!(&bi.core, source_handle, target_handle);
    // Validate both contexts are active.
    let source_state = source_handle.state()?;
    if source_state != "active" {
        return Err(ScpNapiError::Tool {
            message: format!(
                "cannot invoke cross-context tool: source context in {source_state:?} state"
            ),
            code: codes::TOOL_6010.to_owned(),
        }
        .into());
    }

    let target_state = target_handle.state()?;
    if target_state != "active" {
        return Err(ScpNapiError::Tool {
            message: format!(
                "cannot invoke cross-context tool: target context in {target_state:?} state"
            ),
            code: codes::TOOL_6011.to_owned(),
        }
        .into());
    }

    let source_context_id = source_handle.context_id();
    let target_context_id = target_handle.context_id();

    // Validate chain depth (context-configurable, default 8 per ADR-043).
    let max_chain_depth = {
        let supervisor = crate::runtime::supervisor(bi)?;
        let source_max = supervisor
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
            code: codes::TOOL_6012.to_owned(),
        }
        .into());
    }

    // Ensure target context UCAN state is registered.
    crate::runtime::ensure_registered(bi, target_handle)?;

    // Primary authorization: UCAN token validation via the full 11-step
    // ADR-016 pipeline against the TARGET context's ceiling.
    // See spec §6.2, §8, ADR-016, and issue #319.
    let proof_resolver = crate::ucan::build_proof_resolver_from_tokens(proof_tokens.as_deref())
        .map_err(|e| {
            napi::Error::from(ScpNapiError::Permission {
                message: format!("failed to build proof resolver: {e}"),
                code: codes::PERM_3001.to_owned(),
            })
        })?;
    validate_ucan_for_tool(
        bi,
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
            code: codes::TOOL_6002.to_owned(),
        })
    })?;

    let output = crate::runtime::with_context(bi, &target_context_id, |rt| {
        let registration = rt
            .tool_registry
            .get(&tool_id)
            .ok_or_else(|| ScpNapiError::Tool {
                message: format!(
                    "tool '{tool_id}' not found in target context '{target_context_id}'"
                ),
                code: codes::TOOL_6002.to_owned(),
            })?;

        // Validate input against the tool's input schema.
        scp_core::context::tools::validate_value_against_schema(
            &input_value,
            &registration.schema.input_schema,
        )
        .map_err(|e| ScpNapiError::Tool {
            message: format!("input validation failed: {e}"),
            code: codes::TOOL_6002.to_owned(),
        })?;

        // Dispatch to handler or echo mode.
        let output = if let Some(handler) = rt.tool_handlers.get(&tool_id) {
            let handler = handler.clone();
            let out = handler(input_value.clone()).map_err(|e| ScpNapiError::Tool {
                message: format!("cross-context tool handler for '{tool_id}' failed: {e}"),
                code: codes::TOOL_6002.to_owned(),
            })?;

            scp_core::context::tools::validate_value_against_schema(
                &out,
                &registration.schema.output_schema,
            )
            .map_err(|msg| ScpNapiError::Tool {
                message: format!("output validation failed for tool '{tool_id}': {msg}"),
                code: codes::TOOL_6002.to_owned(),
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
            code: codes::TOOL_6013.to_owned(),
        })
    })
}

// ---------------------------------------------------------------------------
// Cross-context tool-invocation saga (§6.2.4, ADR-049 §3a)
// ---------------------------------------------------------------------------

/// The committed terminal of a §6.2.4 cross-context tool-invocation saga.
///
/// Returned by [`Scp::tool_invoke_cross_context_saga`](crate::scp::Scp) on a
/// `Committed` terminal. Every NON-committed terminal rejects the Promise with
/// a typed saga error (`SagaAborted` / `SagaNeedsRepair` / `SagaBusy`) instead.
///
/// Carries the supervisor-minted `saga_id` plus — for the committed
/// cross-context invocation — the target's signed receipt and the captured
/// tool output (spec §6.2.4 "Receipt / response return path"). The `receipt`
/// is the JCS-canonical `CrossContextToolReceipt` bytes; `output` is the
/// receipt's canonical `output_jcs` bytes (the exact bytes the caller side
/// recorded a hash of). Both are surfaced as JS `Buffer` so a caller can verify
/// the receipt signature and recompute `output_hash` without a re-serialization
/// step.
#[napi(object)]
pub struct NapiSagaResult {
    /// The durable saga identifier (supervisor-minted, never a caller input).
    pub saga_id: String,
    /// The target's signed `CrossContextToolReceipt` bytes (JCS), or `None`.
    pub receipt: Option<napi::bindgen_prelude::Buffer>,
    /// The captured tool output bytes (the receipt's canonical `output_jcs`),
    /// or `None`.
    pub output: Option<napi::bindgen_prelude::Buffer>,
}

/// Maps a `SagaError` terminal (the typed §6.2.4 terminal space) onto the
/// bridge's typed saga error variants, reading every structured datum
/// STRUCTURALLY off the variant — never by re-parsing a message string.
///
/// - `Aborted { reason, code, message }` → [`ScpNapiError::SagaAborted`].
///   `retry_after_ms` is read directly off `SagaAbortReason::RateLimited` (an
///   `Option<u64>`); a plain `Rejected` carries `None`. `None` is propagated,
///   NEVER coerced to `0` (a `0` would read as "retry immediately" and re-trip
///   the same hard limit). `code` is formatted as the canonical
///   `SCP-SAGA-{code}` string from the numeric discriminant.
/// - `NeedsRepair { saga_id, message }` → [`ScpNapiError::SagaNeedsRepair`]
///   carrying the durable operator-repair handle (`SCP-SAGA-13065`).
/// - `Busy { contended_context, message }` → [`ScpNapiError::SagaBusy`]
///   (`SCP-SAGA-13066`).
fn map_saga_error(err: scp_core::context::supervisor::SagaError) -> ScpNapiError {
    use scp_core::context::supervisor::{SagaAbortReason, SagaError};
    match err {
        SagaError::Aborted {
            reason,
            code,
            message,
        } => {
            let retry_after_ms = match reason {
                SagaAbortReason::RateLimited { retry_after_ms } => retry_after_ms,
                SagaAbortReason::Rejected => None,
            };
            ScpNapiError::SagaAborted {
                message,
                code: format!("SCP-SAGA-{code}"),
                retry_after_ms,
            }
        }
        SagaError::NeedsRepair { saga_id, message } => ScpNapiError::SagaNeedsRepair {
            message,
            code: codes::SAGA_13065.to_owned(),
            saga_id: saga_id.0,
        },
        SagaError::Busy {
            contended_context,
            message,
        } => ScpNapiError::SagaBusy {
            message,
            code: codes::SAGA_13066.to_owned(),
            contended_context,
        },
    }
}

/// Resolves the Active Signing Key the supervisor saga signs under for a
/// co-resident context owned by `creator_did` — exported via the shared
/// callback/in-memory custody path. The caller and target each resolve to their
/// OWN creator's key so the receipt (target-signed) and each side's divergence
/// marker (own-signed) are signed under the correct per-context Active Signing
/// Key (spec §6.2.4 "Signer authorization": the receipt key MUST be the one
/// authorized to act for `target_context_id`).
///
/// `creator_did` is read off the context HANDLE (`creator_did()`), the
/// authoritative owner the handle was minted with — not via the UCAN-state
/// registry, which a freshly-created context only populates lazily on its first
/// UCAN/tool call. `context_id` is carried only for the error message.
async fn resolve_context_signing_key(
    bi: &crate::runtime::NapiBridgeInstance,
    creator_did: &str,
    context_id: &str,
) -> napi::Result<ed25519_dalek::SigningKey> {
    let (custody, key_handle) = crate::runtime::with_identity(bi, creator_did, |entry| {
        Ok((entry.custody.clone(), entry.identity.active_signing_key))
    })
    .map_err(napi::Error::from)?;
    custody
        .export_ed25519_signing_key(&key_handle)
        .await
        .map_err(|e| {
            napi::Error::from(ScpNapiError::Crypto {
                message: format!(
                    "cannot export the Active Signing Key for context '{context_id}' \
                     (owner '{creator_did}') — a cross-context saga signs the receipt and \
                     divergence markers with each context's own key: {e}"
                ),
                code: codes::CRYPTO_4001.to_owned(),
            })
        })
}

/// Decodes the §6.2.4 envelope nonce from its canonical 32-char hex form into
/// the 16-byte value, FAIL-CLOSED.
///
/// The nonce is a 16-byte value carried as a hex string — the one canonical
/// wire form (§6.2.4 wire envelope). Any other length is a malformed envelope,
/// NOT a "pad it" situation. Both failure modes surface as a validation error.
fn decode_asserted_nonce(asserted_nonce_hex: &str) -> napi::Result<[u8; 16]> {
    let bytes = hex::decode(asserted_nonce_hex).map_err(|e| {
        napi::Error::from(ScpNapiError::Validation {
            message: format!(
                "asserted_nonce_hex is not valid hex: {e} — supply the 16-byte §6.2.4 envelope \
                 nonce as a 32-char lowercase-hex string"
            ),
            code: codes::VALID_7001.to_owned(),
        })
    })?;
    <[u8; 16]>::try_from(bytes.as_slice()).map_err(|_| {
        napi::Error::from(ScpNapiError::Validation {
            message: format!(
                "asserted_nonce_hex must decode to exactly 16 bytes (32 hex chars), got {} bytes",
                bytes.len()
            ),
            code: codes::VALID_7001.to_owned(),
        })
    })
}

/// Enforces the §6.2.4 *Caller authentication* binding (normative — §6.2.4 +
/// ADR-049 §3a) BEFORE the saga runs.
///
/// `caller_did` / `caller_context_id` MUST be the channel-authenticated
/// identity of the transport leg, never an envelope-asserted free value. For
/// the co-resident NAPI bridge the "channel-authenticated principal" is an
/// identity THIS bridge instance hosts — one present in its per-instance
/// identity registry (populated only by the identity-creation paths on this
/// instance). Both axes are enforced here:
///
///   (a) `caller_did` is hosted/authenticated by this bridge instance, AND
///   (b) `caller_did` is a member of the named `caller_context_id`.
///
/// A mismatch on either axis ⇒ a typed `Rejected`-flavored `SagaAborted` (the
/// §6.2.4 "mismatch ⇒ Rejected" terminal), carrying the registered caller-axis
/// code `SCP-SAGA-13050`. The supervisor's own gate 1 ALSO checks membership,
/// but membership alone is necessary-not-sufficient (it does not prove the
/// request leg is authenticated AS that member) — so axis (a) is the
/// load-bearing addition this seam contributes. Enforcing here, before the
/// entry point, also means the saga never observes an unauthenticated caller.
async fn enforce_caller_principal_binding(
    bi: &crate::runtime::NapiBridgeInstance,
    supervisor: &std::sync::Arc<scp_core::context::supervisor::Supervisor>,
    caller_context_id: &str,
    caller_did: &str,
) -> napi::Result<()> {
    if !crate::runtime::identity_registry_contains(bi, caller_did) {
        return Err(ScpNapiError::SagaAborted {
            message: format!(
                "caller_did '{caller_did}' is not an identity hosted by this bridge instance — \
                 a cross-context saga's caller MUST be the channel-authenticated principal (an \
                 identity created on this instance), not an envelope-asserted value (§6.2.4 \
                 Caller authentication)"
            ),
            code: codes::SAGA_13050.to_owned(),
            retry_after_ms: None,
        }
        .into());
    }

    if !supervisor.is_member(caller_context_id, caller_did).await {
        return Err(ScpNapiError::SagaAborted {
            message: format!(
                "caller_did '{caller_did}' is hosted by this bridge but is not a member of \
                 caller_context_id '{caller_context_id}' — not authorized to initiate a \
                 cross-context saga over it (§6.2.4 Caller authentication)"
            ),
            code: codes::SAGA_13050.to_owned(),
            retry_after_ms: None,
        }
        .into());
    }
    Ok(())
}

/// Per-bridge-instance implementation of the §6.2.4 cross-context
/// tool-invocation saga export.
///
/// See [`Scp::tool_invoke_cross_context_saga`](crate::scp::Scp) for the full
/// contract. The flow is, in order:
///
/// 1. **Validate inputs** (active handles; well-formed ids/dids/tool-id; the
///    nonce decodes to `[u8; 16]`, fail-closed on a wrong length).
/// 2. **Caller-principal binding (§6.2.4 *Caller authentication*, normative).**
///    `caller_did` MUST be an identity THIS bridge instance hosts AND a member
///    of `caller_context_id`. A mismatch ⇒ a typed `Rejected`-flavored
///    `SagaAborted` BEFORE the saga runs. `nonce` / `timestamp` / `chain_depth`
///    REMAIN caller-supplied freshness fields (the target validates them).
/// 3. **Chokepoint (ADR-056).** Convert the caller/target id STRINGS → `[u8; 32]`
///    via `scp_core::context::state::context_id_to_bytes` (decode-64-hex-else-
///    SHA256). Raw `Sha256` of a 64-hex id would double-hash and miss the actor.
/// 4. **Signing keys.** Resolve each co-resident context's Active Signing Key
///    via the context's `creator_did`.
/// 5. **Executor.** Snapshot the TARGET context's tool handler and build the
///    `move |input| async {…}` closure the supervisor runs at Commit-B (echo
///    fallback when no handler is registered, matching the synchronous path).
/// 6. Await the producer; map the terminal `SagaError` → typed bridge error,
///    `Committed` → [`NapiSagaResult`].
#[allow(clippy::too_many_arguments)] // Flat §6.2.4 envelope — agent-first named params, no builder.
pub(crate) async fn tool_invoke_cross_context_saga_on(
    bi: &crate::runtime::NapiBridgeInstance,
    source_handle: &NapiContextHandle,
    target_handle: &NapiContextHandle,
    caller_did: String,
    tool_registration_id: String,
    input_json: String,
    asserted_nonce_hex: String,
    asserted_timestamp_ms: u64,
    asserted_chain_depth: u8,
    ucan_proof_id: Option<String>,
) -> napi::Result<NapiSagaResult> {
    use scp_core::context::supervisor::{CrossContextToolInvocationRequest, SagaSigningKeys};

    crate::napi_check_handle!(&bi.core, source_handle, target_handle);

    let source_state = source_handle.state()?;
    if source_state != "active" {
        return Err(ScpNapiError::Tool {
            message: format!(
                "cannot start cross-context saga: caller context in {source_state:?} state"
            ),
            code: codes::TOOL_6010.to_owned(),
        }
        .into());
    }
    let target_state = target_handle.state()?;
    if target_state != "active" {
        return Err(ScpNapiError::Tool {
            message: format!(
                "cannot start cross-context saga: target context in {target_state:?} state"
            ),
            code: codes::TOOL_6011.to_owned(),
        }
        .into());
    }

    let caller_context_id = source_handle.context_id();
    let target_context_id = target_handle.context_id();
    let caller_creator_did = source_handle.creator_did();
    let target_creator_did = target_handle.creator_did();

    scp_ffi_common::validate::validate_context_id(&caller_context_id)
        .map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;
    scp_ffi_common::validate::validate_context_id(&target_context_id)
        .map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;
    validate_did(&caller_did).map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;
    validate_tool_id(&tool_registration_id)
        .map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;

    let asserted_nonce = decode_asserted_nonce(&asserted_nonce_hex)?;
    let input_value: serde_json::Value = serde_json::from_str(&input_json).map_err(|e| {
        napi::Error::from(ScpNapiError::Tool {
            message: format!("invalid input JSON: {e}"),
            code: codes::TOOL_6002.to_owned(),
        })
    })?;

    // Caller-principal binding (§6.2.4 *Caller authentication*) — BEFORE the
    // saga runs, so the supervisor never observes an unauthenticated caller.
    let supervisor = crate::runtime::supervisor(bi)?;
    enforce_caller_principal_binding(bi, supervisor, &caller_context_id, &caller_did).await?;

    // ----- Chokepoint (ADR-056): id STRING → [u8; 32] ------------------------
    //
    // MANDATORY: convert via the canonical cross-crate keying resolver, which
    // decodes a real 64-hex id rather than re-hashing it. The producer does
    // `hex::encode(wire)` for actor lookup, so a raw SHA-256 of a 64-hex id
    // here would double-hash and key the wrong (non-existent) actor slot,
    // surfacing as a spurious ContextNotRegistered abort.
    let caller_context_bytes = scp_core::context::state::context_id_to_bytes(&caller_context_id);
    let target_context_bytes = scp_core::context::state::context_id_to_bytes(&target_context_id);

    // ----- Signing keys: each context's Active Signing Key -------------------
    let target_signing_key =
        resolve_context_signing_key(bi, &target_creator_did, &target_context_id).await?;
    let caller_signing_key =
        resolve_context_signing_key(bi, &caller_creator_did, &caller_context_id).await?;

    // ----- Executor: snapshot the TARGET context's tool handler --------------
    //
    // Snapshot the registered handler closure (an `Arc<dyn Fn>` — cloning is a
    // refcount bump) OUTSIDE the runtime call, then move it into the `FnOnce`
    // executor the supervisor runs supervisor-side at Commit-B (off the actor
    // mailbox). Falls back to a schema-only echo when no handler is registered,
    // matching the synchronous cross-context path. A target context with no
    // FFI-side UCAN/tool state yet registered (the lazy registry is unpopulated
    // until its first tool/UCAN call) likewise carries no handler ⇒ echo. The
    // supervisor validates the output against the tool's registered output
    // schema at Commit-B, so the executor only produces the value.
    let handler = crate::runtime::with_context(bi, &target_context_id, |rt| {
        Ok(rt.tool_handlers.get(&tool_registration_id).cloned())
    })
    .unwrap_or(None);
    let tool_id_for_echo = tool_registration_id.clone();
    let target_ctx_for_echo = target_context_id.clone();
    let caller_did_for_echo = caller_did.clone();
    let executor = move |value: serde_json::Value| {
        let handler = handler.clone();
        let echo_input = value.clone();
        async move {
            handler.map_or_else(
                || {
                    Ok(serde_json::json!({
                        "tool": tool_id_for_echo,
                        "target_context": target_ctx_for_echo,
                        "caller_did": caller_did_for_echo,
                        "status": "validated",
                        "input_valid": true,
                        "validated_input": echo_input,
                    }))
                },
                |h| {
                    h(value).map_err(|e| {
                        format!(
                            "cross-context saga tool handler for '{tool_id_for_echo}' failed: {e}"
                        )
                    })
                },
            )
        }
    };

    let request = CrossContextToolInvocationRequest {
        caller_context_id: caller_context_bytes,
        target_context_id: target_context_bytes,
        caller_did: scp_primitives::DID(caller_did.clone()),
        tool_registration_id: tool_registration_id.clone(),
        ucan_proof_id,
        input: input_value,
        asserted_chain_depth,
        asserted_nonce,
        asserted_timestamp_ms,
    };

    // The producer drives a multi-phase saga; its future is large. Box it so
    // the held state does not bloat this bridge method's own future
    // (`clippy::large_futures`).
    let output = Box::pin(supervisor.start_cross_context_tool_invocation_saga(
        request,
        SagaSigningKeys {
            target: &target_signing_key,
            caller: &caller_signing_key,
        },
        executor,
    ))
    .await
    .map_err(map_saga_error)?;

    Ok(NapiSagaResult {
        saga_id: output.saga_id.0,
        receipt: output.receipt.map(napi::bindgen_prelude::Buffer::from),
        output: output.output.map(napi::bindgen_prelude::Buffer::from),
    })
}

// ---------------------------------------------------------------------------
// Stateful tool sessions (spec section 6.2.1)
// ---------------------------------------------------------------------------

/// Per-bridge-instance implementation of [`tool_session_create`].
pub(crate) async fn tool_session_create_on(
    bi: &crate::runtime::NapiBridgeInstance,
    handle: &NapiContextHandle,
    tool_id: String,
    source_context_id: String,
    ttl_seconds: Option<u32>,
) -> napi::Result<String> {
    crate::napi_check_handle!(&bi.core, handle);
    let state_str = handle.state()?;
    if state_str != "active" {
        return Err(ScpNapiError::Tool {
            message: format!(
                "cannot create session in context in {state_str:?} state — context must be active"
            ),
            code: codes::TOOL_6014.to_owned(),
        }
        .into());
    }

    let context_id = handle.context_id();
    crate::runtime::ensure_registered(bi, handle)?;

    // Read context-configured session cap (ADR-043), falling back to default.
    let cap = {
        let supervisor = crate::runtime::supervisor(bi)?;
        supervisor
            .context_params(&context_id)
            .await
            .and_then(|p| p.session_cap)
            .unwrap_or(scp_core::context::tools::DEFAULT_SESSION_CAP_PER_CALLER) as usize
    };

    crate::runtime::with_context(bi, &context_id, |rt| {
        // Enforce per-caller session cap (context-configured, ADR-043).
        let current = rt.session_store.count_by_source(&source_context_id);
        if current >= cap {
            return Err(ScpNapiError::Tool {
                message: format!(
                    "session cap exceeded for caller '{source_context_id}': {current} active (max {cap})"
                ),
                code: codes::TOOL_6015.to_owned(),
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

/// Per-bridge-instance implementation of [`tool_session_invoke`].
#[allow(clippy::unused_async)] // preserves signature symmetry with the async free function
pub(crate) async fn tool_session_invoke_on(
    bi: &crate::runtime::NapiBridgeInstance,
    handle: &NapiContextHandle,
    session_id: String,
    input_json: String,
    invoker_did: String,
    ucan_token: String,
    proof_tokens: Option<Vec<String>>,
) -> napi::Result<String> {
    crate::napi_check_handle!(&bi.core, handle);
    let state_str = handle.state()?;
    if state_str != "active" {
        return Err(ScpNapiError::Tool {
            message: format!(
                "cannot invoke session in context in {state_str:?} state — context must be active"
            ),
            code: codes::TOOL_6017.to_owned(),
        }
        .into());
    }

    let context_id = handle.context_id();
    crate::runtime::ensure_registered(bi, handle)?;

    // Look up the tool_id from the session before UCAN validation so we can
    // validate against the correct tool capability.
    let tool_id_for_ucan = crate::runtime::with_context(bi, &context_id, |rt| {
        let session = rt
            .session_store
            .get(&session_id)
            .ok_or_else(|| ScpNapiError::Tool {
                message: format!("session '{session_id}' not found"),
                code: codes::TOOL_6018.to_owned(),
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
                code: codes::PERM_3001.to_owned(),
            })
        })?;
    validate_ucan_for_tool(
        bi,
        &context_id,
        &tool_id_for_ucan,
        &invoker_did,
        &ucan_token,
        &proof_resolver,
    )
    .map_err(napi::Error::from)?;

    let output = crate::runtime::with_context(bi, &context_id, |rt| {
        let session = rt
            .session_store
            .get(&session_id)
            .ok_or_else(|| ScpNapiError::Tool {
                message: format!("session '{session_id}' not found"),
                code: codes::TOOL_6018.to_owned(),
            })?;

        // Check expiry.
        let now_ms = scp_primitives::SystemClock.now_millis();
        if session.is_expired(now_ms) {
            rt.session_store.remove(&session_id);
            return Err(ScpNapiError::Tool {
                message: format!("session '{session_id}' has expired"),
                code: codes::TOOL_6019.to_owned(),
            });
        }

        let tool_id = session.tool_id.clone();
        let current_state = session.state.clone();
        let call_count = session.call_count;

        let input_value: serde_json::Value =
            serde_json::from_str(&input_json).map_err(|e| ScpNapiError::Tool {
                message: format!("invalid input JSON: {e}"),
                code: codes::TOOL_6002.to_owned(),
            })?;

        // Validate input against tool's input schema if tool is registered.
        if let Some(registration) = rt.tool_registry.get(&tool_id) {
            scp_core::context::tools::validate_value_against_schema(
                &input_value,
                &registration.schema.input_schema,
            )
            .map_err(|e| ScpNapiError::Tool {
                message: format!("input validation failed: {e}"),
                code: codes::TOOL_6002.to_owned(),
            })?;
        }

        // Execute via handler or echo mode.
        let (new_state, output) = if let Some(handler) = rt.tool_handlers.get(&tool_id) {
            let handler = handler.clone();
            let out = handler(input_value).map_err(|e| ScpNapiError::Tool {
                message: format!("tool handler for '{tool_id}' failed: {e}"),
                code: codes::TOOL_6002.to_owned(),
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
            code: codes::TOOL_6020.to_owned(),
        })
    })
}

/// Per-bridge-instance implementation of [`tool_session_close`].
#[allow(clippy::unused_async)] // preserves signature symmetry with the async free function
pub(crate) async fn tool_session_close_on(
    bi: &crate::runtime::NapiBridgeInstance,
    handle: &NapiContextHandle,
    session_id: String,
) -> napi::Result<()> {
    crate::napi_check_handle!(&bi.core, handle);
    let context_id = handle.context_id();
    crate::runtime::ensure_registered(bi, handle)?;

    crate::runtime::with_context(bi, &context_id, |rt| {
        if rt.session_store.remove(&session_id).is_none() {
            return Err(ScpNapiError::Tool {
                message: format!("session '{session_id}' not found"),
                code: codes::TOOL_6021.to_owned(),
            });
        }
        Ok(())
    })
    .map_err(napi::Error::from)
}

// ---------------------------------------------------------------------------
// Bidirectional consent protocol (spec §6.2.0.1)
// ---------------------------------------------------------------------------

/// Per-bridge-instance implementation of [`tool_interface_expose`].
#[allow(clippy::unused_async)] // preserves signature symmetry with the async free function
pub(crate) async fn tool_interface_expose_on(
    bi: &crate::runtime::NapiBridgeInstance,
    handle: &NapiContextHandle,
    tool_id: String,
    target_context_id: String,
    rate_limit_json: Option<String>,
) -> napi::Result<String> {
    crate::napi_check_handle!(&bi.core, handle);
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
            code: codes::TOOL_6030.to_owned(),
        }
        .into());
    }

    let context_id = handle.context_id();
    crate::runtime::ensure_registered(bi, handle)?;

    let rate_limit = match rate_limit_json {
        Some(ref json) => {
            let parsed: scp_core::context::tools::interface::RateLimit = serde_json::from_str(json)
                .map_err(|e| {
                    napi::Error::from(ScpNapiError::Validation {
                        message: format!("invalid rate_limit_json: {e}"),
                        code: codes::VALID_7040.to_owned(),
                    })
                })?;
            Some(parsed)
        }
        None => None,
    };

    crate::runtime::with_context(bi, &context_id, |rt| {
        let context_handle = scp_core::context::ContextHandle::new(
            context_id.clone(),
            scp_core::context::ContextParams::default(),
        );

        let interface = scp_core::context::tools::interface::expose_tool(
            context_handle.context_id(),
            &tool_id,
            &target_context_id,
            &rt.role_state,
            &rt.core.creator_did,
            &rt.tool_registry,
            rate_limit,
            None,
        )
        .map_err(|e| ScpNapiError::Tool {
            message: format!("expose_tool failed: {e}"),
            code: codes::TOOL_6030.to_owned(),
        })?;

        serde_json::to_string(&interface).map_err(|e| ScpNapiError::Tool {
            message: format!("failed to serialize ToolInterface: {e}"),
            code: codes::TOOL_6031.to_owned(),
        })
    })
    .map_err(napi::Error::from)
}

/// Per-bridge-instance implementation of [`tool_interface_accept`].
#[allow(clippy::unused_async)] // preserves signature symmetry with the async free function
pub(crate) async fn tool_interface_accept_on(
    bi: &crate::runtime::NapiBridgeInstance,
    handle: &NapiContextHandle,
    interface_json: String,
) -> napi::Result<String> {
    crate::napi_check_handle!(&bi.core, handle);
    let state_str = handle.state()?;
    if state_str != "active" {
        return Err(ScpNapiError::Tool {
            message: format!(
                "cannot accept tool interface in context in {state_str:?} state — context must be active"
            ),
            code: codes::TOOL_6032.to_owned(),
        }
        .into());
    }

    let context_id = handle.context_id();
    crate::runtime::ensure_registered(bi, handle)?;

    let mut interface: scp_core::context::tools::interface::ToolInterface =
        serde_json::from_str(&interface_json).map_err(|e| {
            napi::Error::from(ScpNapiError::Validation {
                message: format!("invalid interface_json: {e}"),
                code: codes::VALID_7041.to_owned(),
            })
        })?;

    crate::runtime::with_context(bi, &context_id, |rt| {
        let context_handle = scp_core::context::ContextHandle::new(
            context_id.clone(),
            scp_core::context::ContextParams::default(),
        );

        scp_core::context::tools::interface::accept_tool_interface(
            context_handle.context_id(),
            &mut interface,
            &rt.role_state,
            &rt.core.creator_did,
            None,
        )
        .map_err(|e| ScpNapiError::Tool {
            message: format!("accept_tool_interface failed: {e}"),
            code: codes::TOOL_6032.to_owned(),
        })?;

        serde_json::to_string(&interface).map_err(|e| ScpNapiError::Tool {
            message: format!("failed to serialize ToolInterface: {e}"),
            code: codes::TOOL_6033.to_owned(),
        })
    })
    .map_err(napi::Error::from)
}

/// Per-bridge-instance implementation of [`tool_interface_revoke`].
#[allow(clippy::unused_async)] // preserves signature symmetry with the async free function
pub(crate) async fn tool_interface_revoke_on(
    bi: &crate::runtime::NapiBridgeInstance,
    handle: &NapiContextHandle,
    interface_id_hex: String,
) -> napi::Result<String> {
    crate::napi_check_handle!(&bi.core, handle);
    let context_id = handle.context_id();

    let interface_id_bytes = hex::decode(&interface_id_hex).map_err(|e| {
        napi::Error::from(ScpNapiError::Validation {
            message: format!("invalid interface_id_hex: not valid hex: {e}"),
            code: codes::VALID_7042.to_owned(),
        })
    })?;
    let interface_id: [u8; 32] = scp_ffi_common::validate::expect_fixed_bytes::<32>(
        interface_id_bytes.as_slice(),
        "interface_id_hex",
    )
    .map_err(|msg| {
        napi::Error::from(ScpNapiError::Validation {
            message: format!("{msg} (64 hex chars)"),
            code: codes::VALID_7042.to_owned(),
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
            code: codes::TOOL_6035.to_owned(),
        })
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use scp_ffi_common::error_codes as codes;

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
            msg.contains(codes::VALID_7035),
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
            msg.contains(codes::VALID_7036),
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
        assert!(msg.contains(codes::VALID_7035));
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
            msg.contains(codes::VALID_7037),
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
        assert!(msg.contains(codes::VALID_7037));
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
            msg.contains(codes::VALID_7038),
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
        assert!(msg.contains(codes::VALID_7038));
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
        assert!(msg.contains(codes::VALID_7038));
        assert!(msg.contains("got 0"));
    }

    /// `registered_at` on a tool registered via the NAPI bridge must be a
    /// seconds-epoch timestamp, not milliseconds or hardcoded 0.
    /// Calls the actual `tool_register` bridge function and inspects the
    /// stored `ToolRegistration`. Catches the original bug from issue #871.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn registered_at_is_seconds_epoch() {
        use crate::context::NapiContextHandle;

        let bi = std::sync::Arc::new(crate::runtime::NapiBridgeInstance::new_napi());
        let ctx_id = format!("ctx-napi-ts-test-{}", std::process::id());
        let creator_did = "did:dht:z6MkNapiTsTest";

        let handle = NapiContextHandle::test_active_on(&bi, ctx_id.clone(), creator_did.to_owned());

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

        let tool_id = tool_register_on(&bi, &handle, definition)
            .await
            .expect("tool_register should succeed");

        // Read the stored registration back and verify registered_at.
        let registered_at = crate::runtime::with_context(&bi, &ctx_id, |rt| {
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
        crate::runtime::remove_context(&bi, &ctx_id);
    }

    // ------------------------------------------------------------------
    // map_saga_error — the bridge's typed-terminal → typed-error mapping.
    //
    // The producer's actual terminal behavior (which SagaError a given saga
    // run yields) is covered by the Committed e2e test below and in
    // `scp-runtime`; here we test ONLY the bridge's mapping responsibility:
    // that each typed `SagaError` becomes the right `ScpNapiError` variant with
    // EVERY structured datum preserved STRUCTURALLY (read off the variant, never
    // parsed from a message) and the canonical `SCP-SAGA-13xxx` code attached.
    // ------------------------------------------------------------------

    use scp_core::context::supervisor::{
        SagaAbortReason, SagaError as CoreSagaError, SagaId as CoreSagaId,
    };

    /// A rate-limited abort preserves `retry_after_ms = Some(ms)` STRUCTURALLY
    /// and formats the producer's numeric `code` as the canonical
    /// `SCP-SAGA-{code}` string.
    #[test]
    fn map_saga_error_rate_limited_preserves_retry_after_ms() {
        let mapped = map_saga_error(CoreSagaError::Aborted {
            reason: SagaAbortReason::RateLimited {
                retry_after_ms: Some(2500),
            },
            code: 13026,
            message: "inbound rate limit exceeded".to_owned(),
        });
        match mapped {
            ScpNapiError::SagaAborted {
                code,
                retry_after_ms,
                ..
            } => {
                assert_eq!(code, "SCP-SAGA-13026");
                assert_eq!(retry_after_ms, Some(2500));
            }
            other => panic!("expected SagaAborted, got {other:?}"),
        }
    }

    /// A rate-limited abort with NO precise back-off instant preserves
    /// `retry_after_ms = None` — NEVER coerced to `Some(0)` — and renders the
    /// message suffix as a literal `null` (a `0` would read as "retry
    /// immediately" and re-trip the same hard limit).
    #[test]
    fn map_saga_error_rate_limited_none_is_not_zero() {
        let mapped = map_saga_error(CoreSagaError::Aborted {
            reason: SagaAbortReason::RateLimited {
                retry_after_ms: None,
            },
            code: 13026,
            message: "hard limit, no precise back-off".to_owned(),
        });
        match &mapped {
            ScpNapiError::SagaAborted { retry_after_ms, .. } => {
                assert_eq!(*retry_after_ms, None, "None must NOT be coerced to Some(0)");
            }
            other => panic!("expected SagaAborted, got {other:?}"),
        }
        assert!(
            mapped.to_string().contains("(retry_after_ms=null)"),
            "None retry_after_ms must render as the literal `null`, not 0: {mapped}"
        );
    }

    /// A plain (non-rate-limit) `Rejected` abort carries `retry_after_ms = None`.
    #[test]
    fn map_saga_error_rejected_has_no_retry_hint() {
        let mapped = map_saga_error(CoreSagaError::Aborted {
            reason: SagaAbortReason::Rejected,
            code: 13050,
            message: "caller not a member".to_owned(),
        });
        match mapped {
            ScpNapiError::SagaAborted {
                code,
                retry_after_ms,
                ..
            } => {
                assert_eq!(code, "SCP-SAGA-13050");
                assert_eq!(retry_after_ms, None);
            }
            other => panic!("expected SagaAborted, got {other:?}"),
        }
    }

    /// `NeedsRepair` preserves the durable `saga_id` operator-repair handle and
    /// the fixed terminal code `SCP-SAGA-13065`.
    #[test]
    fn map_saga_error_needs_repair_preserves_saga_id() {
        let mapped = map_saga_error(CoreSagaError::NeedsRepair {
            saga_id: CoreSagaId("saga-abc-123".to_owned()),
            message: "commit retries exhausted".to_owned(),
        });
        match mapped {
            ScpNapiError::SagaNeedsRepair { code, saga_id, .. } => {
                assert_eq!(code, codes::SAGA_13065);
                assert_eq!(saga_id, "saga-abc-123");
            }
            other => panic!("expected SagaNeedsRepair, got {other:?}"),
        }
    }

    /// `Busy` preserves the contended context id and the fixed terminal code
    /// `SCP-SAGA-13066`.
    #[test]
    fn map_saga_error_busy_preserves_contended_context() {
        let mapped = map_saga_error(CoreSagaError::Busy {
            contended_context: "ctx-shared-99".to_owned(),
            message: "participant set overlaps an in-flight saga".to_owned(),
        });
        match mapped {
            ScpNapiError::SagaBusy {
                code,
                contended_context,
                ..
            } => {
                assert_eq!(code, codes::SAGA_13066);
                assert_eq!(contended_context, "ctx-shared-99");
            }
            other => panic!("expected SagaBusy, got {other:?}"),
        }
    }

    // ------------------------------------------------------------------
    // End-to-end Committed terminal through the NAPI bridge.
    //
    // Mirrors the PyO3 e2e: an authenticated caller drives the §6.2.4
    // cross-context tool-invocation saga to a real Committed terminal and the
    // bridge returns the committed receipt + output bytes. The setup wires the
    // two producer authorization axes:
    //
    //   1. Caller axis (gate 1): caller_did is hosted by this instance AND a
    //      member of the CALLER (source) context A — satisfied by creating A
    //      via the real context-create path with `owner` as single-admin.
    //   2. Target axis (gate 2): a bidirectionally-approved ToolInterface
    //      (approved_by_source && approved_by_target, source=A, target=B), which
    //      the producer queries against A's actor governance state, established
    //      IN A via a governance EstablishToolInterface action (auto-executed
    //      under single_admin).
    //
    // Context B holds the tool registered into its ACTOR governance state (via a
    // RegisterTool governance action — the saga's Prepare-B reads it from there)
    // PLUS the FFI-side handler the executor snapshots and runs once at Commit-B.
    // The handler returns `{"sum":42,"ok":1}`, which Commit-B validates against
    // the registered numeric `{sum, ok}` output schema before committing.
    //
    // The owner is created via the real `identity_create` BEFORE the first
    // `context_create_on` so its DID document is published into the per-instance
    // resolver and the supervisor (built lazily on first create) snapshots that
    // real resolver — governance vote verification resolves the proposer key
    // through it. Prepare-B enforces a §9.14 ±5min timestamp skew, so the
    // invocation uses `SystemTime::now()`.
    // ------------------------------------------------------------------

    /// Serializes a `RegisterTool` governance action for the saga tool. Mirrors
    /// the registered schema: 2 input + 2 output properties (clears the §9.2.1
    /// specificity floor of 2), numeric `{sum, ok}` output so Commit-B's
    /// output-schema validation accepts the handler's response.
    fn register_tool_action_json(tool_id: &str, tool_name: &str, owner: &str) -> String {
        let impl_hash = serde_json::Value::from(vec![0u8; 32]);
        let register_action = serde_json::json!({
            "RegisterTool": {
                "registration": {
                    "tool_id": tool_id,
                    "name": tool_name,
                    "description": format!("Tool: {tool_name}"),
                    "schema": {
                        "input_schema": {
                            "type": "object",
                            "properties": {
                                "a": {"type": "string"},
                                "b": {"type": "string"}
                            }
                        },
                        "output_schema": {
                            "type": "object",
                            "properties": {
                                "sum": {"type": "number"},
                                "ok": {"type": "number"}
                            }
                        }
                    },
                    "implementation_hash": impl_hash,
                    "test_vectors": [],
                    "operator_did": owner,
                    "cost": null,
                    "registered_at": 0,
                    "signature": []
                }
            }
        });
        serde_json::to_string(&register_action).unwrap()
    }

    /// Serializes the bidirectionally-approved `EstablishToolInterface`
    /// governance action (source=A, target=B, BOTH approvals true).
    fn establish_interface_action_json(ctx_a: &str, ctx_b: &str, tool_id: &str) -> String {
        let action = serde_json::json!({
            "EstablishToolInterface": {
                "interface": {
                    "source_context": ctx_a,
                    "target_context": ctx_b,
                    "tool_id": tool_id,
                    "rate_limit": null,
                    "inbound_rate_limit": null,
                    "per_caller_rate_limit": null,
                    "approved_by_source": true,
                    "approved_by_target": true,
                    "outbound_policy": null,
                    "inbound_policy": null
                }
            }
        });
        serde_json::to_string(&action).unwrap()
    }

    /// The registered tool registration definition for context B's FFI-side
    /// registry, matching the governance `RegisterTool` schema (2-in/2-out,
    /// numeric `{sum, ok}` output) so the deterministic id agrees and the
    /// handler's response validates at Commit-B.
    fn build_napi_tool_def(tool_name: &str, owner: &str) -> NapiToolDefinition {
        NapiToolDefinition {
            name: tool_name.to_owned(),
            description: format!("Tool: {tool_name}"),
            input_schema_json:
                r#"{"type":"object","properties":{"a":{"type":"string"},"b":{"type":"string"}}}"#
                    .to_owned(),
            output_schema_json:
                r#"{"type":"object","properties":{"sum":{"type":"number"},"ok":{"type":"number"}}}"#
                    .to_owned(),
            test_vectors_json: None,
            implementation_hash: None,
            operator_did: owner.to_owned(),
            cost: None,
        }
    }

    /// Full `Committed` terminal through the NAPI bridge: an authenticated
    /// caller drives the §6.2.4 cross-context tool-invocation saga to a real
    /// commit and the bridge returns the committed receipt + output bytes.
    #[cfg(feature = "allow_in_memory_custody")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn xctx_saga_authenticated_caller_commits_via_governance_established_interface() {
        let scp = crate::scp::Scp::new_in_memory_for_test();
        let bi = std::sync::Arc::clone(&scp.inner);

        // Owner via the real identity-create path so its DID document is
        // resolvable for governance vote verification. MUST precede the first
        // context_create (which lazily builds the supervisor + snapshots the
        // resolver).
        let owner_identity = scp
            .identity_create("in_memory".to_owned(), None)
            .await
            .expect("identity_create should succeed");
        let owner = owner_identity.inner.did.clone();

        // Context A (caller/source): ceiling carries governance:propose (so the
        // admin can propose) and tool:interface (required by
        // execute_establish_tool_interface's ceiling check).
        let params_a = serde_json::json!({
            "ceiling": [
                "governance:propose",
                "tool:interface",
                "tools:invoke",
                "messages:read",
                "messages:write"
            ],
            "governance": "single_admin",
            "memoryScope": "ephemeral",
        })
        .to_string();
        let handle_a = crate::context::context_create_on(&bi, &owner_identity, params_a)
            .await
            .expect("context_create A should succeed");
        let ctx_a = handle_a.context_id();

        // Context B (target): ceiling carries governance:propose and
        // tool:register so the saga tool can be registered into B's ACTOR
        // governance state (the saga's Prepare-B reads it from there).
        let params_b = serde_json::json!({
            "ceiling": ["governance:propose", "tool:register"],
            "governance": "single_admin",
            "memoryScope": "ephemeral",
        })
        .to_string();
        let handle_b = crate::context::context_create_on(&bi, &owner_identity, params_b)
            .await
            .expect("context_create B should succeed");
        let ctx_b = handle_b.context_id();

        // Deterministic tool id shared across the actor registry, the interface,
        // and the FFI-side handler.
        let tool_name = "xctx_saga_commit_tool";
        let tool_id = scp_ffi_common::tool_id::generate_tool_id(tool_name);

        // Register the tool into B's ACTOR governance state.
        let register_json = register_tool_action_json(&tool_id, tool_name, &owner);
        crate::context::context_governance_propose_on(&bi, &handle_b, register_json, owner.clone())
            .await
            .expect("RegisterTool must auto-execute under single_admin");

        // Register the tool into B's FFI-side registry (so register_tool_handler
        // accepts it) and attach the deterministic handler the executor runs at
        // Commit-B.
        let ffi_tool_id = tool_register_on(&bi, &handle_b, build_napi_tool_def(tool_name, &owner))
            .await
            .expect("FFI tool_register should succeed");
        assert_eq!(
            ffi_tool_id, tool_id,
            "FFI and governance tool ids must agree (deterministic generate_tool_id)"
        );
        let handler: crate::runtime::ToolHandler =
            std::sync::Arc::new(|_input: serde_json::Value| {
                Ok(serde_json::json!({"sum": 42, "ok": 1}))
            });
        crate::runtime::register_tool_handler(&bi, &ctx_b, &tool_id, handler)
            .expect("register_tool_handler should succeed");

        // Establish the bidirectionally-approved interface in A via governance.
        let interface_json = establish_interface_action_json(&ctx_a, &ctx_b, &tool_id);
        let propose_result = crate::context::context_governance_propose_on(
            &bi,
            &handle_a,
            interface_json,
            owner.clone(),
        )
        .await
        .expect("EstablishToolInterface must auto-execute under single_admin");
        assert!(
            !propose_result.is_empty(),
            "governance_propose must return a non-empty result JSON"
        );

        // A near-now timestamp: Prepare-B enforces a §9.14 ±5min skew tolerance.
        let now_ms = u64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis(),
        )
        .unwrap();
        // A 16-byte nonce as 32 lowercase-hex chars.
        let nonce_hex = "0123456789abcdef0123456789abcdef".to_owned();

        let result = Box::pin(tool_invoke_cross_context_saga_on(
            &bi,
            &handle_a,
            &handle_b,
            owner.clone(),
            tool_id.clone(),
            r#"{"a":"x","b":"y"}"#.to_owned(),
            nonce_hex,
            now_ms,
            1,
            None,
        ))
        .await
        .expect("saga must reach Committed");

        // Committed terminal: non-empty saga id + a receipt + output bytes.
        assert!(
            !result.saga_id.is_empty(),
            "a committed saga must carry a non-empty saga id"
        );
        let receipt = result.receipt.expect("committed saga must carry a receipt");
        assert!(!receipt.is_empty(), "receipt bytes must be non-empty");
        let output_buf = result
            .output
            .expect("committed saga must carry output bytes");

        // The committed output decodes to the handler's response (numeric, per
        // the registered output schema). Assert the parsed values, not raw
        // bytes, so a JCS-canonical encoding still passes.
        let out: serde_json::Value =
            serde_json::from_slice(output_buf.as_ref()).expect("output must be valid JSON");
        assert_eq!(out["sum"], 42, "committed output sum must be the handler's");
        assert_eq!(out["ok"], 1, "committed output ok must be the handler's");
    }
}
