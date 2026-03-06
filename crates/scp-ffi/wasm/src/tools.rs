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
//! # Bridge stub behavior
//!
//! All functions in this module are bridge stubs that return typed errors.
//! The full protocol implementation (tool registration in MLS group state,
//! capability-gated invocation, schema validation) is implemented in scp-core
//! and will be connected in a future story when WASM-compatible scp-core
//! bindings are available.
//!
//! See ADR-022 in `.docs/adrs/phase-4.md` for the full specification.

use js_sys::Promise;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::future_to_promise;

use crate::context::WasmContextHandle;
use crate::error::ScpWasmError;

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
/// - Rejects with `[SCP-TOOL-6001]` if registration fails (permission denied,
///   schema invalid, not yet connected to runtime).
///
/// See ADR-022 acceptance criterion 1.
#[wasm_bindgen]
pub fn tool_register(context: &WasmContextHandle, definition_json: String) -> Promise {
    let context_id = context.context_id();
    future_to_promise(async move {
        // Validate that definition_json is valid JSON.
        let _def: serde_json::Value = serde_json::from_str(&definition_json).map_err(|e| {
            ScpWasmError::Validation {
                message: format!("definition_json is not valid JSON: {e}"),
                code: "SCP-VALID-7000".to_owned(),
            }
            .into_js()
        })?;

        let _ = context_id;

        Err(ScpWasmError::Tool {
            message: "not yet connected to runtime — tool registration requires a live context \
                      handle wired to scp-core"
                .to_owned(),
            code: "SCP-TOOL-6001".to_owned(),
        }
        .into_js()
        .into())
    })
}

/// Invokes a registered tool within an SCP context.
///
/// Validates the UCAN token for tool invocation authorization before
/// dispatching. The UCAN must contain a `tool_invoke:{tool_id}` or
/// `tool_invoke:*` capability scoped to the context.
///
/// # Arguments
///
/// * `context` — The context handle containing the tool.
/// * `tool_id` — The ID of the tool to invoke.
/// * `input_json` — A JSON string of input parameters matching the tool's
///   input schema.
/// * `identity_did` — The DID of the invoking identity (for capability
///   checking).
/// * `ucan_token` — JWT-encoded UCAN token authorizing the invocation.
///   Must contain `tool_invoke:{tool_id}` or `tool_invoke:*` capability.
///
/// # Returns
///
/// `Promise<string>` — resolves to a JSON string of the tool's output.
///
/// # Errors
///
/// - Rejects with `[SCP-VALID-7000]` if `input_json` is malformed.
/// - Rejects with `[SCP-PERM-3001]` if the UCAN token is invalid, expired,
///   revoked, or lacks the required tool invocation capability.
/// - Rejects with `[SCP-TOOL-6002]` if invocation fails (tool not found,
///   insufficient capability, schema mismatch, execution timeout).
///
/// See ADR-022 acceptance criterion 1.
/// See spec §6.2, §8, ADR-016, and issue #319 for UCAN enforcement.
#[wasm_bindgen]
pub fn tool_invoke(
    context: &WasmContextHandle,
    tool_id: String,
    input_json: String,
    identity_did: String,
    ucan_token: String,
) -> Promise {
    let context_id = context.context_id();
    future_to_promise(async move {
        // Validate that input_json is valid JSON.
        let _input: serde_json::Value = serde_json::from_str(&input_json).map_err(|e| {
            ScpWasmError::Validation {
                message: format!("input_json is not valid JSON: {e}"),
                code: "SCP-VALID-7000".to_owned(),
            }
            .into_js()
        })?;

        // Validate that ucan_token is non-empty (basic check; full validation
        // requires runtime wiring which is deferred to SCP-218).
        if ucan_token.is_empty() {
            return Err(ScpWasmError::Permission {
                message: "UCAN token required for tool invocation — empty token provided"
                    .to_owned(),
                code: "SCP-PERM-3001".to_owned(),
            }
            .into_js()
            .into());
        }

        // WASM bridge validates UCAN structure (JWT format) as defense-in-depth.
        // Full 11-step validation requires WebCrypto key custody wiring (SCP-218).
        // See CLAUDE.md §UCAN Validation — Known Gaps.
        crate::runtime::with_context(&context_id, |rt| {
            crate::runtime::validate_tool_ucan_wasm(
                &ucan_token,
                &context_id,
                &tool_id,
                &identity_did,
                rt,
            )
        })
        .map_err(|e| {
            ScpWasmError::Permission {
                message: format!("UCAN authorization failed for tool '{tool_id}': {e}"),
                code: "SCP-PERM-3001".to_owned(),
            }
            .into_js()
        })?;

        let _ = (context_id, tool_id, identity_did);

        Err(ScpWasmError::Tool {
            message: "not yet connected to runtime — tool invocation requires a live context \
                      handle wired to scp-core"
                .to_owned(),
            code: "SCP-TOOL-6002".to_owned(),
        }
        .into_js()
        .into())
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
/// Rejects with `[SCP-TOOL-6003]` if the context is not connected to the
/// runtime or the tool is not found.
///
/// See ADR-022 acceptance criterion 1.
#[wasm_bindgen]
pub fn tool_verify(context: &WasmContextHandle, tool_id: String) -> Promise {
    let context_id = context.context_id();
    future_to_promise(async move {
        let _ = (context_id, tool_id);

        Err(ScpWasmError::Tool {
            message: "not yet connected to runtime — tool verification requires a live context \
                      handle wired to scp-core"
                .to_owned(),
            code: "SCP-TOOL-6003".to_owned(),
        }
        .into_js()
        .into())
    })
}
