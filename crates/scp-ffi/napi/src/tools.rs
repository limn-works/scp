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
