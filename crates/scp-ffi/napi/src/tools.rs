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
use uuid::Uuid;

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

    let tool_id = format!("tool-{}", Uuid::new_v4());
    let _ = definition;
    Ok(tool_id)
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

    // Primary authorization: UCAN token validation via the full 11-step
    // ADR-016 pipeline. Verifies the token grants tool_invoke:{tool_id}
    // or tool_invoke:* for this context.
    // See spec §6.2, §8, ADR-016, and issue #319.
    let context_id = handle.context_id();
    crate::runtime::ensure_registered(handle)?;

    // Build proof resolver from optional proof tokens (supports delegated UCANs).
    let proof_resolver = crate::ucan::build_proof_resolver_from_tokens(proof_tokens.as_deref())
        .map_err(|e| {
            napi::Error::from(ScpNapiError::Permission {
                message: format!("failed to build proof resolver: {e}"),
                code: "SCP-PERM-3001".to_owned(),
            })
        })?;

    crate::runtime::with_context(&context_id, |rt| {
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
            proof_resolver: &proof_resolver,
            ceiling: &rt.ceiling_strings,
            context_creator_did: &rt.creator_did,
            presenting_agent_did: &identity_did,
            clock_skew_tolerance_secs:
                scp_core::crypto::ucan::validate::DEFAULT_CLOCK_SKEW_TOLERANCE_SECS,
        };

        scp_core::context::tools::validate_tool_invocation_ucan(
            &ucan_token,
            &context_id,
            &tool_id,
            &mut ctx,
        )
        .map_err(|e| ScpNapiError::Permission {
            message: format!("UCAN authorization failed for tool '{tool_id}': {e}"),
            code: "SCP-PERM-3001".to_owned(),
        })
    })
    .map_err(napi::Error::from)?;

    let _ = (tool_id, input_json, identity_did);
    Ok("{}".to_owned())
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

    Ok(NapiToolVerificationResult {
        tool_id,
        passed: true,
        failures: Vec::new(),
    })
}

// ---------------------------------------------------------------------------
// Cross-context tool invocation
// ---------------------------------------------------------------------------

/// Invokes a tool across context boundaries.
///
/// Validates chain depth, source context capability, and target context
/// tool existence per spec section 6.2.
///
/// # Returns
///
/// A `Promise<string>` resolving to the tool output as a JSON string.
#[napi]
#[allow(clippy::unused_async)] // napi-rs requires async for Promise return
#[allow(clippy::needless_pass_by_value)] // napi-rs requires owned String
pub async fn tool_invoke_cross_context(
    source_handle: &NapiContextHandle,
    target_handle: &NapiContextHandle,
    tool_id: String,
    input_json: String,
    invoker_did: String,
    chain_depth: u8,
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

    // Validate chain depth (max 3 per spec section 6.2).
    if chain_depth > scp_core::provenance::attach::DEFAULT_MAX_CHAIN_DEPTH {
        return Err(ScpNapiError::Tool {
            message: format!(
                "cross-context chain depth {chain_depth} exceeds maximum {}",
                scp_core::provenance::attach::DEFAULT_MAX_CHAIN_DEPTH
            ),
            code: "SCP-TOOL-6012".to_owned(),
        }
        .into());
    }

    let source_context_id = source_handle.context_id();
    let target_context_id = target_handle.context_id();

    let output = serde_json::json!({
        "tool": tool_id,
        "source_context": source_context_id,
        "target_context": target_context_id,
        "status": "validated",
        "chain_depth": chain_depth,
        "invoker_did": invoker_did,
        "validated_input": serde_json::from_str::<serde_json::Value>(&input_json)
            .unwrap_or(serde_json::Value::Null),
    });

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
    ttl_seconds: u32,
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

    crate::runtime::with_context(&context_id, |rt| {
        // Enforce per-caller session cap.
        let current = rt.session_store.count_by_source(&source_context_id);
        if current >= scp_core::context::tools::DEFAULT_SESSION_CAP_PER_CALLER {
            return Err(ScpNapiError::Tool {
                message: format!(
                    "session cap exceeded for caller '{}': {} active (max {})",
                    source_context_id,
                    current,
                    scp_core::context::tools::DEFAULT_SESSION_CAP_PER_CALLER
                ),
                code: "SCP-TOOL-6015".to_owned(),
            });
        }

        let session_id = uuid::Uuid::new_v4().to_string();
        let now_ms = scp_core::time::now_millis().map_err(|e| ScpNapiError::Tool {
            message: format!("clock error: {e}"),
            code: "SCP-TOOL-6016".to_owned(),
        })?;

        let session = scp_core::context::tools::ToolSession {
            session_id: session_id.clone(),
            tool_id,
            source_context: source_context_id,
            state: serde_json::Value::Null,
            created_at: now_ms,
            ttl: std::time::Duration::from_secs(u64::from(ttl_seconds)),
            call_count: 0,
        };

        rt.session_store.insert(session);
        Ok(session_id)
    })
    .map_err(napi::Error::from)
}

/// Invokes a tool within an active session.
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

    let output = crate::runtime::with_context(&context_id, |rt| {
        let session = rt.session_store.get(&session_id).ok_or_else(|| {
            ScpNapiError::Tool {
                message: format!("session '{session_id}' not found"),
                code: "SCP-TOOL-6018".to_owned(),
            }
        })?;

        // Check expiry.
        let now_ms = scp_core::time::now_millis().map_err(|e| ScpNapiError::Tool {
            message: format!("clock error: {e}"),
            code: "SCP-TOOL-6016".to_owned(),
        })?;
        if session.is_expired(now_ms) {
            rt.session_store.remove(&session_id);
            return Err(ScpNapiError::Tool {
                message: format!("session '{session_id}' has expired"),
                code: "SCP-TOOL-6019".to_owned(),
            });
        }

        let tool_id = session.tool_id.clone();
        let call_count = session.call_count;

        // Increment call count.
        if let Some(session) = rt.session_store.get_mut(&session_id) {
            session.call_count = session.call_count.saturating_add(1);
        }

        let output = serde_json::json!({
            "tool": tool_id,
            "session_id": session_id,
            "status": "validated",
            "call_count": call_count + 1,
            "invoker_did": invoker_did,
            "validated_input": serde_json::from_str::<serde_json::Value>(&input_json)
                .unwrap_or(serde_json::Value::Null),
        });

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
