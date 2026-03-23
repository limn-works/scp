//! `wasm-bindgen` bridge for context lifecycle and messaging.
//!
//! All context operations delegate to [`WasmContextManager`](crate::manager::WasmContextManager)
//! via [`with_manager`](crate::manager::with_manager). No local state management or
//! algorithm re-implementation — the manager owns all context state.
//!
//! See ADR-034 in `.docs/adrs/phase-4.md` and issue #389.

use base64::Engine as _;
use js_sys::Promise;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::future_to_promise;

use scp_ffi_common::validate::validate_did;
use scp_protocol::context::params::TemplateId;
use scp_protocol::context::templates::{
    template_params as protocol_template_params,
    validate_against_template as protocol_validate_against_template,
    validate_context_params as protocol_validate_context_params,
};

use crate::error::ScpWasmError;
use crate::manager::with_manager;
use scp_protocol::context::governance::GovernanceAction;

// ---------------------------------------------------------------------------
// JsMessageCallback — JS-injected message stream callback
// ---------------------------------------------------------------------------

/// JS object implementing the message stream callback interface.
///
/// The TypeScript SDK implements this interface to receive messages from a
/// context subscription. The bridge calls [`JsMessageCallback::on_message`]
/// for each incoming message and [`JsMessageCallback::on_complete`] when
/// the subscription ends.
#[wasm_bindgen]
extern "C" {
    /// A JS object implementing the message stream callback interface.
    pub type JsMessageCallback;

    /// Called for each incoming message on the subscribed context.
    #[wasm_bindgen(method, js_name = "onMessage")]
    pub fn on_message(this: &JsMessageCallback, message: WasmMessage);

    /// Called when the message stream ends.
    #[wasm_bindgen(method, js_name = "onComplete")]
    pub fn on_complete(this: &JsMessageCallback);
}

// ---------------------------------------------------------------------------
// WasmContextHandle — opaque JS object for SCP contexts
// ---------------------------------------------------------------------------

/// Opaque handle to an SCP context.
///
/// All fields populated per spec §5.7. The handle is a lightweight view
/// backed by state in the `WasmContextManager`. Bridge functions use the
/// `contextId` to look up state in the manager.
#[wasm_bindgen]
#[derive(Debug, Clone)]
pub struct WasmContextHandle {
    context_id: String,
    state: std::cell::RefCell<String>,
    creator_did: String,
    mode: String,
    ceiling: Vec<String>,
    ceiling_policy: String,
    ttl_seconds: Option<u64>,
    promotion_policy: Option<String>,
    governance: String,
    member_count: u64,
    economic_policy: Option<String>,
    /// Minimum protocol version as `[major, minor]`, or `None` if unset.
    min_protocol_version: Option<Vec<u8>>,
}

#[wasm_bindgen]
impl WasmContextHandle {
    /// Returns the unique context identifier.
    #[must_use]
    #[wasm_bindgen(getter, js_name = "contextId")]
    pub fn context_id(&self) -> String {
        self.context_id.clone()
    }

    /// Returns the current context lifecycle state (e.g., `"active"`, `"closed"`).
    #[must_use]
    #[wasm_bindgen(getter)]
    pub fn state(&self) -> String {
        self.state.borrow().clone()
    }

    /// Returns the DID of the context creator.
    #[must_use]
    #[wasm_bindgen(getter, js_name = "creatorDid")]
    pub fn creator_did(&self) -> String {
        self.creator_did.clone()
    }

    /// Returns the context mode (e.g., `"standard"`, `"broadcast"`).
    #[must_use]
    #[wasm_bindgen(getter)]
    pub fn mode(&self) -> String {
        self.mode.clone()
    }

    /// Returns the capability ceiling as an array of capability URI strings.
    #[must_use]
    #[wasm_bindgen(getter)]
    pub fn ceiling(&self) -> js_sys::Array {
        self.ceiling.iter().map(|s| JsValue::from_str(s)).collect()
    }

    /// Returns the ceiling enforcement policy (e.g., `"strict"`, `"permissive"`).
    #[must_use]
    #[wasm_bindgen(getter, js_name = "ceilingPolicy")]
    pub fn ceiling_policy(&self) -> String {
        self.ceiling_policy.clone()
    }

    /// Returns the context TTL in seconds, or `undefined` if no TTL is set.
    #[must_use]
    #[wasm_bindgen(getter, js_name = "ttlSeconds")]
    pub fn ttl_seconds(&self) -> Option<u32> {
        self.ttl_seconds
            .map(|n| u32::try_from(n).unwrap_or(u32::MAX))
    }

    /// Returns the promotion policy, or `undefined` if unset.
    #[must_use]
    #[wasm_bindgen(getter, js_name = "promotionPolicy")]
    pub fn promotion_policy(&self) -> Option<String> {
        self.promotion_policy.clone()
    }

    /// Returns the governance model (e.g., `"single_admin"`, `"threshold"`).
    #[must_use]
    #[wasm_bindgen(getter)]
    pub fn governance(&self) -> String {
        self.governance.clone()
    }

    /// Returns the current number of context members.
    #[must_use]
    #[wasm_bindgen(getter, js_name = "memberCount")]
    pub fn member_count(&self) -> u32 {
        u32::try_from(self.member_count).unwrap_or(u32::MAX)
    }

    /// Returns the economic policy as a JSON string, or `undefined` if unset.
    #[must_use]
    #[wasm_bindgen(getter, js_name = "economicPolicy")]
    pub fn economic_policy(&self) -> Option<String> {
        self.economic_policy.clone()
    }

    /// Returns the minimum protocol version as a `[major, minor]` JS array,
    /// or `undefined` if no minimum is set. Mirrors the NAPI bridge's
    /// `minProtocolVersion` field on the TypeScript `ContextHandle`.
    #[must_use]
    #[wasm_bindgen(getter, js_name = "minProtocolVersion")]
    pub fn min_protocol_version(&self) -> JsValue {
        self.min_protocol_version
            .as_ref()
            .map_or(JsValue::UNDEFINED, |v| {
                let arr = js_sys::Array::new();
                arr.push(&JsValue::from(v[0]));
                arr.push(&JsValue::from(v[1]));
                arr.into()
            })
    }
}

impl WasmContextHandle {
    /// Creates a handle from manager metadata.
    fn from_metadata(meta: crate::manager::ContextMetadata) -> Self {
        Self {
            context_id: meta.context_id,
            state: std::cell::RefCell::new(meta.state),
            creator_did: meta.creator_did,
            mode: meta.mode,
            ceiling: meta.ceiling,
            ceiling_policy: meta.ceiling_policy,
            ttl_seconds: meta.ttl_seconds,
            promotion_policy: meta.promotion_policy,
            governance: meta.governance,
            member_count: meta.member_count,
            economic_policy: meta.economic_policy,
            min_protocol_version: meta.min_protocol_version.map(|(maj, min)| vec![maj, min]),
        }
    }
}

// ---------------------------------------------------------------------------
// WasmMessage — incoming message from an SCP context
// ---------------------------------------------------------------------------

/// A received message from an SCP context.
#[wasm_bindgen]
#[derive(Debug, Clone)]
pub struct WasmMessage {
    sender_did: String,
    payload_base64: String,
    timestamp: f64,
    context_id: String,
    sequence: u64,
}

#[wasm_bindgen]
impl WasmMessage {
    /// Returns the DID of the message sender.
    #[must_use]
    #[wasm_bindgen(getter, js_name = "senderDid")]
    pub fn sender_did(&self) -> String {
        self.sender_did.clone()
    }

    /// Returns the message payload as a base64-encoded string.
    #[must_use]
    #[wasm_bindgen(getter, js_name = "payloadBase64")]
    pub fn payload_base64(&self) -> String {
        self.payload_base64.clone()
    }

    /// Returns the message timestamp as seconds since the Unix epoch.
    #[must_use]
    #[wasm_bindgen(getter)]
    pub fn timestamp(&self) -> f64 {
        self.timestamp
    }

    /// Returns the context ID the message belongs to.
    #[must_use]
    #[wasm_bindgen(getter, js_name = "contextId")]
    pub fn context_id(&self) -> String {
        self.context_id.clone()
    }

    /// Returns the per-sender sequence number for this message.
    ///
    /// Returns `u32` (not `u64`) to avoid wasm-bindgen mapping to JavaScript
    /// `BigInt`. Follows the crate convention used by `member_count()` and `ttl_seconds()`.
    #[must_use]
    #[wasm_bindgen(getter)]
    pub fn sequence(&self) -> u32 {
        u32::try_from(self.sequence).unwrap_or(u32::MAX)
    }
}

// ---------------------------------------------------------------------------
// Bridge functions — all delegate to WasmContextManager
// ---------------------------------------------------------------------------

/// Creates a new SCP context.
///
/// Delegates to `WasmContextManager::create_context`. Returns a
/// `WasmContextHandle` with all §5.7 metadata fields populated.
#[wasm_bindgen]
pub fn context_create(identity_did: String, params_json: String) -> Promise {
    if let Err(e) = validate_did(&identity_did) {
        return future_to_promise(async move { Err(ScpWasmError::from(e).into_js().into()) });
    }
    future_to_promise(async move {
        let params: serde_json::Value = serde_json::from_str(&params_json).map_err(|e| {
            ScpWasmError::Validation {
                message: format!(
                    "params_json is not valid JSON: {e} — pass a JSON-encoded context parameters object"
                ),
                code: "SCP-VALID-7000".to_owned(),
            }
            .into_js()
        })?;

        // Validate minProtocolVersion at the bridge boundary (defense-in-depth).
        // The manager also validates, but catching malformed input here gives
        // callers a clearer error before any state mutation. Stricter than the
        // NAPI bridge's lenient parsing — rejects malformed values that NAPI
        // silently ignores (spec §13.4).
        validate_min_protocol_version(&params).map_err(ScpWasmError::into_js)?;

        let context_id = format!("ctx-{}", uuid::Uuid::new_v4().as_hyphenated());

        with_manager(|mgr| mgr.create_context(&context_id, &identity_did, &params))
            .map_err(ScpWasmError::into_js)?;

        let meta = with_manager(|mgr| {
            mgr.context_metadata(&context_id)
                .ok_or_else(|| ScpWasmError::Context {
                    message: "context creation succeeded but metadata lookup failed".to_owned(),
                    code: "SCP-CTX-2001".to_owned(),
                })
        })
        .map_err(ScpWasmError::into_js)?;

        let handle = WasmContextHandle::from_metadata(meta);
        Ok(JsValue::from(handle))
    })
}

/// Joins an existing SCP context.
///
/// Delegates to `WasmContextManager::join_context`.
#[wasm_bindgen]
pub fn context_join(handle: &WasmContextHandle, identity_did: String) -> Promise {
    if let Err(e) = validate_did(&identity_did) {
        return future_to_promise(async move { Err(ScpWasmError::from(e).into_js().into()) });
    }
    let context_id = handle.context_id();

    future_to_promise(async move {
        with_manager(|mgr| mgr.join_context(&context_id, &identity_did))
            .map_err(ScpWasmError::into_js)?;
        Ok(JsValue::UNDEFINED)
    })
}

/// Leaves an SCP context.
///
/// Delegates to `WasmContextManager::leave_context`.
#[wasm_bindgen]
pub fn context_leave(handle: &WasmContextHandle, identity_did: String) -> Promise {
    if let Err(e) = validate_did(&identity_did) {
        return future_to_promise(async move { Err(ScpWasmError::from(e).into_js().into()) });
    }
    let context_id = handle.context_id();

    future_to_promise(async move {
        with_manager(|mgr| mgr.leave_context(&context_id, &identity_did))
            .map_err(ScpWasmError::into_js)?;
        Ok(JsValue::UNDEFINED)
    })
}

/// Closes an SCP context.
///
/// Delegates to `WasmContextManager::close_context`. Authorization enforced:
/// only the creator or an admin can close.
#[wasm_bindgen]
pub fn context_close(handle: &WasmContextHandle, identity_did: String) -> Promise {
    if let Err(e) = validate_did(&identity_did) {
        return future_to_promise(async move { Err(ScpWasmError::from(e).into_js().into()) });
    }
    let context_id = handle.context_id();

    // Update handle state synchronously before the async boundary, since
    // wasm-bindgen requires the async closure to be 'static (no &handle).
    // The manager validates authorization; if it fails, the state was
    // already "closed" but the context is still registered in the manager.
    let close_result = with_manager(|mgr| mgr.close_context(&context_id, &identity_did));

    match close_result {
        Ok(()) => {
            "closed".clone_into(&mut handle.state.borrow_mut());
            future_to_promise(async move { Ok(JsValue::UNDEFINED) })
        }
        Err(e) => future_to_promise(async move { Err(e.into_js().into()) }),
    }
}

/// Sends a message to an SCP context.
///
/// Delegates to `WasmContextManager::send_message`.
#[wasm_bindgen]
pub fn context_send(
    handle: &WasmContextHandle,
    identity_did: String,
    payload_base64: String,
) -> Promise {
    if let Err(e) = validate_did(&identity_did) {
        return future_to_promise(async move { Err(ScpWasmError::from(e).into_js().into()) });
    }
    let context_id = handle.context_id();

    future_to_promise(async move {
        if payload_base64.is_empty() {
            return Err(ScpWasmError::Validation {
                message:
                    "payload_base64 must not be empty — encode payload bytes as base64 before calling context_send"
                        .to_owned(),
                code: "SCP-VALID-7000".to_owned(),
            }
            .into_js()
            .into());
        }

        with_manager(|mgr| mgr.send_message(&context_id, &identity_did, &payload_base64))
            .map_err(ScpWasmError::into_js)?;

        Ok(JsValue::UNDEFINED)
    })
}

/// Decrypts a message received from an encrypted SCP context.
///
/// Reverses the double encryption: MLS decrypt -> sender key decrypt.
/// Returns the decrypted plaintext as a `Uint8Array`.
///
/// # Errors
///
/// Returns an error if the context has no MLS encryption state, or if
/// decryption fails.
#[wasm_bindgen]
pub fn context_decrypt_message(
    handle: &WasmContextHandle,
    sender_did: String,
    ciphertext_base64: String,
    epoch: u64,
    sequence: u64,
) -> Promise {
    if let Err(e) = validate_did(&sender_did) {
        return future_to_promise(async move { Err(ScpWasmError::from(e).into_js().into()) });
    }
    let context_id = handle.context_id();

    future_to_promise(async move {
        let plaintext = with_manager(|mgr| {
            mgr.decrypt_message(
                &context_id,
                &sender_did,
                &ciphertext_base64,
                epoch,
                sequence,
            )
        })
        .map_err(ScpWasmError::into_js)?;

        // Return as Uint8Array.
        let js_array = js_sys::Uint8Array::from(plaintext.as_slice());
        Ok(JsValue::from(js_array))
    })
}

/// Generates an MLS key package for joining an encrypted context.
///
/// Returns the TLS-serialized key package bytes as a `Uint8Array`. The
/// private key material is retained internally for later use by
/// [`context_join_encrypted`].
///
/// This must be called BEFORE `context_join_encrypted` — the returned
/// key package is sent to the adder, who uses it to produce a Welcome.
///
/// # Errors
///
/// Returns an error if key package generation fails.
#[wasm_bindgen]
pub fn context_generate_key_package(handle: &WasmContextHandle, identity_did: String) -> Promise {
    if let Err(e) = validate_did(&identity_did) {
        return future_to_promise(async move { Err(ScpWasmError::from(e).into_js().into()) });
    }
    let context_id = handle.context_id();

    future_to_promise(async move {
        let kp_bytes =
            with_manager(|mgr| mgr.generate_key_package_for_join(&context_id, &identity_did))
                .map_err(ScpWasmError::into_js)?;

        let js_array = js_sys::Uint8Array::from(kp_bytes.as_slice());
        Ok(JsValue::from(js_array))
    })
}

/// Joins an encrypted SCP context using an MLS Welcome message.
///
/// Processes the Welcome to reconstruct the MLS group state, then sets up
/// the sender key layer. A key package must have been previously generated
/// via [`context_generate_key_package`] for the same context and identity.
///
/// # Errors
///
/// Returns an error if no pending key package exists, the Welcome cannot
/// be processed, or the context is not active.
#[wasm_bindgen]
pub fn context_join_encrypted(
    handle: &WasmContextHandle,
    identity_did: String,
    welcome_bytes: Vec<u8>,
) -> Promise {
    if let Err(e) = validate_did(&identity_did) {
        return future_to_promise(async move { Err(ScpWasmError::from(e).into_js().into()) });
    }
    let context_id = handle.context_id();

    future_to_promise(async move {
        with_manager(|mgr| mgr.join_context_encrypted(&context_id, &identity_did, &welcome_bytes))
            .map_err(ScpWasmError::into_js)?;

        Ok(JsValue::UNDEFINED)
    })
}

/// Subscribes to incoming messages from an SCP context.
///
/// Registers a JS callback. In the full runtime, the transport layer calls
/// `callback.on_message()` for each incoming message.
///
/// # Errors
///
/// Returns an error if the context is not in `"active"` state.
#[wasm_bindgen]
pub fn context_subscribe(
    handle: &WasmContextHandle,
    callback: JsMessageCallback,
) -> Result<(), JsError> {
    let context_id = handle.context_id();

    with_manager(|mgr| {
        let state = mgr.context_state(&context_id).unwrap_or_default();
        if state != "active" {
            return Err(ScpWasmError::Context {
                message: format!(
                    "cannot subscribe to context in '{state}' state — context must be 'active'"
                ),
                code: "SCP-CTX-2021".to_owned(),
            });
        }
        Ok(())
    })
    .map_err(ScpWasmError::into_js)?;

    // Signal completion — the TypeScript wrapper manages the actual stream.
    callback.on_complete();
    Ok(())
}

// ---------------------------------------------------------------------------
// Membership query bridge functions
// ---------------------------------------------------------------------------

/// Returns the member count for a context.
///
/// Delegates to `WasmContextManager::member_count`.
#[wasm_bindgen]
pub fn context_member_count(handle: &WasmContextHandle) -> Option<u32> {
    let context_id = handle.context_id();
    with_manager(|mgr| {
        Ok(mgr
            .member_count(&context_id)
            .map(|c| u32::try_from(c).unwrap_or(u32::MAX)))
    })
    .ok()
    .flatten()
}

/// Returns `true` if the DID is a member of the context.
///
/// Delegates to `WasmContextManager::is_member`.
#[wasm_bindgen]
pub fn context_is_member(handle: &WasmContextHandle, did: String) -> bool {
    if validate_did(&did).is_err() {
        return false;
    }
    let context_id = handle.context_id();
    with_manager(|mgr| Ok(mgr.is_member(&context_id, &did))).unwrap_or(false)
}

/// Returns all member DIDs as a JSON array string.
///
/// Delegates to `WasmContextManager::member_dids`.
#[wasm_bindgen]
pub fn context_member_dids(handle: &WasmContextHandle) -> String {
    let context_id = handle.context_id();
    let dids = with_manager(|mgr| Ok(mgr.member_dids(&context_id))).unwrap_or_default();
    serde_json::to_string(&dids).unwrap_or_else(|_| "[]".to_owned())
}

/// Returns the role for a member, or `null` if not found.
///
/// Delegates to `WasmContextManager::member_role`.
#[wasm_bindgen]
pub fn context_member_role(handle: &WasmContextHandle, did: String) -> Option<String> {
    if validate_did(&did).is_err() {
        return None;
    }
    let context_id = handle.context_id();
    with_manager(|mgr| Ok(mgr.member_role(&context_id, &did)))
        .ok()
        .flatten()
}

// ---------------------------------------------------------------------------
// Event drain bridge function
// ---------------------------------------------------------------------------

/// Drains all events from the context's receive buffer.
///
/// Returns a JSON array of events. Delegates to `WasmContextManager::drain_events`.
#[wasm_bindgen]
pub fn context_drain_events(handle: &WasmContextHandle) -> String {
    let context_id = handle.context_id();
    let events = with_manager(|mgr| Ok(mgr.drain_events(&context_id))).unwrap_or_default();
    serde_json::to_string(&events).unwrap_or_else(|_| "[]".to_owned())
}

// ---------------------------------------------------------------------------
// Governance bridge function
// ---------------------------------------------------------------------------

/// Executes a governance action on a context.
///
/// Delegates to `WasmContextManager::execute_governance_action`.
/// All 24 `GovernanceAction` variants are dispatchable.
///
/// Authorization is enforced: the `initiator_did` must be a member with
/// the capability required for the specific governance action. For example,
/// `RemoveMember` requires `member_remove:*` (admin-only by default),
/// `ChangeRole` requires `role_assign:*`, etc.
///
/// # Arguments
///
/// * `handle` — The context handle.
/// * `initiator_did` — DID of the member requesting the governance action.
/// * `proposal_id` — Unique proposal ID for replay protection.
/// * `action_json` — JSON-encoded governance action (see `GovernanceAction`).
///
/// # Returns
///
/// `Promise<string>` — resolves to a JSON result of the governance action.
#[wasm_bindgen]
pub fn context_execute_governance(
    handle: &WasmContextHandle,
    initiator_did: String,
    proposal_id: String,
    action_json: String,
) -> Promise {
    if let Err(e) = validate_did(&initiator_did) {
        return future_to_promise(async move { Err(ScpWasmError::from(e).into_js().into()) });
    }
    let context_id = handle.context_id();

    future_to_promise(async move {
        let action: GovernanceAction = serde_json::from_str(&action_json).map_err(|e| {
            ScpWasmError::Validation {
                message: format!("action_json is not valid: {e}"),
                code: "SCP-VALID-7000".to_owned(),
            }
            .into_js()
        })?;

        let result = with_manager(|mgr| {
            mgr.execute_governance_action(&context_id, &initiator_did, &proposal_id, &action)
        })
        .map_err(ScpWasmError::into_js)?;

        let json_str = serde_json::to_string(&result).map_err(|e| {
            ScpWasmError::Context {
                message: format!("failed to serialize governance result: {e}"),
                code: "SCP-CTX-2001".to_owned(),
            }
            .into_js()
        })?;

        Ok(JsValue::from_str(&json_str))
    })
}

// ---------------------------------------------------------------------------
// Governance proposal lifecycle bridge functions (#621)
// ---------------------------------------------------------------------------

/// Proposes a governance action for voting.
///
/// Delegates to `WasmContextManager::propose_governance_action`.
/// For `single_admin` contexts, the proposal is auto-approved and executed.
/// For multi-admin models (threshold, majority, unanimity), the proposal
/// enters `Pending` status.
///
/// # Arguments
///
/// * `handle` — The context handle.
/// * `proposer_did` — DID of the proposer.
/// * `proposal_id` — Unique proposal ID for replay protection.
/// * `action_json` — JSON-encoded governance action.
///
/// # Returns
///
/// `Promise<string>` — JSON with `proposal_id`, `status`, `execution_result`.
#[wasm_bindgen]
pub fn context_governance_propose(
    handle: &WasmContextHandle,
    proposer_did: String,
    proposal_id: String,
    action_json: String,
) -> Promise {
    if let Err(e) = validate_did(&proposer_did) {
        return future_to_promise(async move { Err(ScpWasmError::from(e).into_js().into()) });
    }
    let context_id = handle.context_id();

    future_to_promise(async move {
        let action: GovernanceAction = serde_json::from_str(&action_json).map_err(|e| {
            ScpWasmError::Validation {
                message: format!("action_json is not valid: {e}"),
                code: "SCP-CTX-2040".to_owned(),
            }
            .into_js()
        })?;

        let result = with_manager(|mgr| {
            mgr.propose_governance_action(&context_id, &proposer_did, &proposal_id, &action)
        })
        .map_err(ScpWasmError::into_js)?;

        let json_str = serde_json::to_string(&result).map_err(|e| {
            ScpWasmError::Context {
                message: format!("failed to serialize proposal result: {e}"),
                code: "SCP-CTX-2041".to_owned(),
            }
            .into_js()
        })?;

        Ok(JsValue::from_str(&json_str))
    })
}

/// Casts an approval vote on a pending governance proposal.
///
/// Delegates to `WasmContextManager::approve_governance_proposal`.
///
/// # Arguments
///
/// * `handle` — The context handle.
/// * `proposal_id` — The proposal to vote on.
/// * `voter_did` — DID of the voter.
///
/// # Returns
///
/// `Promise<string>` — JSON with `status`.
#[wasm_bindgen]
pub fn context_governance_approve(
    handle: &WasmContextHandle,
    proposal_id: String,
    voter_did: String,
) -> Promise {
    if let Err(e) = validate_did(&voter_did) {
        return future_to_promise(async move { Err(ScpWasmError::from(e).into_js().into()) });
    }
    let context_id = handle.context_id();

    future_to_promise(async move {
        let result = with_manager(|mgr| {
            mgr.approve_governance_proposal(&context_id, &proposal_id, &voter_did)
        })
        .map_err(ScpWasmError::into_js)?;

        let json_str = serde_json::to_string(&result).map_err(|e| {
            ScpWasmError::Context {
                message: format!("failed to serialize approval result: {e}"),
                code: "SCP-CTX-2042".to_owned(),
            }
            .into_js()
        })?;

        Ok(JsValue::from_str(&json_str))
    })
}

/// Casts a rejection vote on a pending governance proposal.
///
/// Delegates to `WasmContextManager::reject_governance_proposal`.
///
/// # Arguments
///
/// * `handle` — The context handle.
/// * `proposal_id` — The proposal to vote on.
/// * `voter_did` — DID of the voter.
///
/// # Returns
///
/// `Promise<string>` — JSON with `status`.
#[wasm_bindgen]
pub fn context_governance_reject(
    handle: &WasmContextHandle,
    proposal_id: String,
    voter_did: String,
) -> Promise {
    if let Err(e) = validate_did(&voter_did) {
        return future_to_promise(async move { Err(ScpWasmError::from(e).into_js().into()) });
    }
    let context_id = handle.context_id();

    future_to_promise(async move {
        let result = with_manager(|mgr| {
            mgr.reject_governance_proposal(&context_id, &proposal_id, &voter_did)
        })
        .map_err(ScpWasmError::into_js)?;

        let json_str = serde_json::to_string(&result).map_err(|e| {
            ScpWasmError::Context {
                message: format!("failed to serialize rejection result: {e}"),
                code: "SCP-CTX-2043".to_owned(),
            }
            .into_js()
        })?;

        Ok(JsValue::from_str(&json_str))
    })
}

/// Withdraws a previously cast vote on a pending governance proposal.
///
/// Delegates to `WasmContextManager::withdraw_governance_vote`.
///
/// # Arguments
///
/// * `handle` — The context handle.
/// * `proposal_id` — The proposal to withdraw from.
/// * `voter_did` — DID of the voter.
///
/// # Returns
///
/// `Promise<string>` — JSON with `status`.
#[wasm_bindgen]
pub fn context_governance_withdraw(
    handle: &WasmContextHandle,
    proposal_id: String,
    voter_did: String,
) -> Promise {
    if let Err(e) = validate_did(&voter_did) {
        return future_to_promise(async move { Err(ScpWasmError::from(e).into_js().into()) });
    }
    let context_id = handle.context_id();

    future_to_promise(async move {
        let result =
            with_manager(|mgr| mgr.withdraw_governance_vote(&context_id, &proposal_id, &voter_did))
                .map_err(ScpWasmError::into_js)?;

        let json_str = serde_json::to_string(&result).map_err(|e| {
            ScpWasmError::Context {
                message: format!("failed to serialize withdrawal result: {e}"),
                code: "SCP-CTX-2044".to_owned(),
            }
            .into_js()
        })?;

        Ok(JsValue::from_str(&json_str))
    })
}

// ---------------------------------------------------------------------------
// Governance query bridge functions (#621)
// ---------------------------------------------------------------------------

/// Retrieves a single governance proposal by ID.
///
/// Delegates to `WasmContextManager::get_proposal`.
///
/// # Returns
///
/// `Promise<string>` — JSON with proposal details.
#[wasm_bindgen]
pub fn context_governance_get_proposal(handle: &WasmContextHandle, proposal_id: String) -> Promise {
    let context_id = handle.context_id();

    future_to_promise(async move {
        let result = with_manager(|mgr| mgr.get_proposal(&context_id, &proposal_id))
            .map_err(ScpWasmError::into_js)?;

        let json_str = serde_json::to_string(&result).map_err(|e| {
            ScpWasmError::Context {
                message: format!("failed to serialize proposal: {e}"),
                code: "SCP-CTX-2045".to_owned(),
            }
            .into_js()
        })?;

        Ok(JsValue::from_str(&json_str))
    })
}

/// Lists all pending governance proposals for a context.
///
/// Delegates to `WasmContextManager::list_proposals`.
///
/// # Returns
///
/// `Promise<string>` — JSON array of proposals.
#[wasm_bindgen]
pub fn context_governance_list_proposals(handle: &WasmContextHandle) -> Promise {
    let context_id = handle.context_id();

    future_to_promise(async move {
        let result =
            with_manager(|mgr| mgr.list_proposals(&context_id)).map_err(ScpWasmError::into_js)?;

        let json_str = serde_json::to_string(&result).map_err(|e| {
            ScpWasmError::Context {
                message: format!("failed to serialize proposals: {e}"),
                code: "SCP-CTX-2046".to_owned(),
            }
            .into_js()
        })?;

        Ok(JsValue::from_str(&json_str))
    })
}

// ---------------------------------------------------------------------------
// Ceiling modification, close, checkpoint, restore (#559)
// ---------------------------------------------------------------------------

/// Applies a pending ceiling modification if the notification period has elapsed.
///
/// Returns `true` if applied, `false` otherwise.
#[wasm_bindgen]
pub fn context_apply_pending_ceiling_modification(
    handle: &WasmContextHandle,
    current_timestamp: f64,
) -> Promise {
    let context_id = handle.context_id();
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let ts = current_timestamp as u64;

    future_to_promise(async move {
        let applied = with_manager(|mgr| mgr.apply_pending_ceiling_modification(&context_id, ts))
            .map_err(ScpWasmError::into_js)?;

        Ok(JsValue::from_bool(applied))
    })
}

/// Finalizes the cooperative close flow for a context in `Closing` state.
///
/// Transitions from `closing` to `closed` and records a `ContextClosed` event.
#[wasm_bindgen]
pub fn context_finalize_close(handle: &WasmContextHandle) -> Promise {
    let context_id = handle.context_id();

    future_to_promise(async move {
        with_manager(|mgr| mgr.finalize_close(&context_id)).map_err(ScpWasmError::into_js)?;

        Ok(JsValue::undefined())
    })
}

/// Creates a governance checkpoint for a context (ADR-031 §9).
///
/// # Returns
///
/// `Promise<string>` — JSON with the checkpoint object.
#[wasm_bindgen]
#[allow(clippy::too_many_arguments)]
pub fn context_create_governance_checkpoint(
    handle: &WasmContextHandle,
    checkpoint_seq: f64,
    merkle_root_hex: String,
    event_count: f64,
    last_event_hash_hex: String,
    state_snapshot_hash_hex: String,
    creator_did: String,
    creator_signature_hex: String,
) -> Promise {
    if let Err(e) = validate_did(&creator_did) {
        return future_to_promise(async move { Err(ScpWasmError::from(e).into_js().into()) });
    }
    let context_id = handle.context_id();

    future_to_promise(async move {
        let merkle_root = parse_wasm_hex_32(&merkle_root_hex, "merkle_root")?;
        let last_event_hash = parse_wasm_hex_32(&last_event_hash_hex, "last_event_hash")?;
        let state_snapshot_hash =
            parse_wasm_hex_32(&state_snapshot_hash_hex, "state_snapshot_hash")?;
        let creator_signature = hex::decode(&creator_signature_hex).map_err(|e| {
            ScpWasmError::Validation {
                message: format!("invalid creator_signature hex: {e}"),
                code: "SCP-CTX-2062".to_owned(),
            }
            .into_js()
        })?;

        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let seq = checkpoint_seq as u64;
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let count = event_count as u64;

        let checkpoint = with_manager(|mgr| {
            mgr.create_governance_checkpoint(
                &context_id,
                seq,
                &merkle_root,
                count,
                &last_event_hash,
                &state_snapshot_hash,
                &creator_did,
                &creator_signature,
            )
        })
        .map_err(ScpWasmError::into_js)?;

        let json_str = serde_json::to_string(&checkpoint).map_err(|e| {
            ScpWasmError::Context {
                message: format!("serialization failed: {e}"),
                code: "SCP-CTX-2062".to_owned(),
            }
            .into_js()
        })?;

        Ok(JsValue::from_str(&json_str))
    })
}

/// Adds a cosignature to an existing governance checkpoint (ADR-031 §9).
///
/// # Returns
///
/// `Promise<string>` — JSON with `{ "attestation_status": string, "checkpoint": object }`.
#[wasm_bindgen]
pub fn context_add_checkpoint_cosignature(
    handle: &WasmContextHandle,
    checkpoint_json: String,
    signer_did: String,
    signature_hex: String,
) -> Promise {
    if let Err(e) = validate_did(&signer_did) {
        return future_to_promise(async move { Err(ScpWasmError::from(e).into_js().into()) });
    }
    let context_id = handle.context_id();

    future_to_promise(async move {
        let mut checkpoint: serde_json::Value =
            serde_json::from_str(&checkpoint_json).map_err(|e| {
                ScpWasmError::Validation {
                    message: format!("invalid checkpoint JSON: {e}"),
                    code: "SCP-CTX-2063".to_owned(),
                }
                .into_js()
            })?;

        let signature = hex::decode(&signature_hex).map_err(|e| {
            ScpWasmError::Validation {
                message: format!("invalid signature hex: {e}"),
                code: "SCP-CTX-2063".to_owned(),
            }
            .into_js()
        })?;

        let status = with_manager(|mgr| {
            mgr.add_checkpoint_cosignature(&context_id, &mut checkpoint, &signer_did, &signature)
        })
        .map_err(ScpWasmError::into_js)?;

        let response = serde_json::json!({
            "attestation_status": status,
            "checkpoint": checkpoint,
        });
        let json_str = serde_json::to_string(&response).map_err(|e| {
            ScpWasmError::Context {
                message: format!("serialization failed: {e}"),
                code: "SCP-CTX-2063".to_owned(),
            }
            .into_js()
        })?;

        Ok(JsValue::from_str(&json_str))
    })
}

/// Restores a single persisted context from storage.
///
/// WASM contexts are ephemeral (ADR-034), so this always returns an error.
#[wasm_bindgen]
pub fn context_restore(context_id: String) -> Promise {
    future_to_promise(async move {
        with_manager(|mgr| mgr.restore_context(&context_id)).map_err(ScpWasmError::into_js)?;
        Ok(JsValue::undefined())
    })
}

/// Restores all persisted contexts from storage.
///
/// WASM contexts are ephemeral (ADR-034), so this always returns an error.
#[wasm_bindgen]
pub fn context_restore_all() -> Promise {
    future_to_promise(async move {
        let restored =
            with_manager(|mgr| mgr.restore_all_contexts()).map_err(ScpWasmError::into_js)?;

        let json_str = serde_json::to_string(&restored).map_err(|e| {
            ScpWasmError::Context {
                message: format!("serialization failed: {e}"),
                code: "SCP-CTX-2065".to_owned(),
            }
            .into_js()
        })?;

        Ok(JsValue::from_str(&json_str))
    })
}

/// Parses a hex string into a 32-byte array for WASM bridge.
fn parse_wasm_hex_32(hex_str: &str, field_name: &str) -> Result<[u8; 32], JsValue> {
    let bytes = hex::decode(hex_str).map_err(|e| {
        ScpWasmError::Validation {
            message: format!("invalid {field_name} hex: {e}"),
            code: "SCP-CTX-2062".to_owned(),
        }
        .into_js()
    })?;
    let arr: [u8; 32] = bytes.try_into().map_err(|v: Vec<u8>| {
        ScpWasmError::Validation {
            message: format!("{field_name} must be 32 bytes, got {}", v.len()),
            code: "SCP-CTX-2062".to_owned(),
        }
        .into_js()
    })?;
    Ok(arr)
}

// ---------------------------------------------------------------------------
// Broadcast bridge functions
// ---------------------------------------------------------------------------

/// Subscribes a DID to a broadcast context.
///
/// Delegates to `WasmContextManager::subscribe_broadcast`.
#[wasm_bindgen]
pub fn broadcast_subscribe(handle: &WasmContextHandle, subscriber_did: String) -> Promise {
    if let Err(e) = validate_did(&subscriber_did) {
        return future_to_promise(async move { Err(ScpWasmError::from(e).into_js().into()) });
    }
    let context_id = handle.context_id();

    future_to_promise(async move {
        with_manager(|mgr| mgr.subscribe_broadcast(&context_id, &subscriber_did))
            .map_err(ScpWasmError::into_js)?;
        Ok(JsValue::UNDEFINED)
    })
}

/// Publishes a message to a broadcast context.
///
/// Delegates to `WasmContextManager::publish_broadcast`.
#[wasm_bindgen]
pub fn broadcast_publish(
    handle: &WasmContextHandle,
    author_did: String,
    payload_base64: String,
) -> Promise {
    if let Err(e) = validate_did(&author_did) {
        return future_to_promise(async move { Err(ScpWasmError::from(e).into_js().into()) });
    }
    let context_id = handle.context_id();

    future_to_promise(async move {
        with_manager(|mgr| mgr.publish_broadcast(&context_id, &author_did, &payload_base64))
            .map_err(ScpWasmError::into_js)?;
        Ok(JsValue::UNDEFINED)
    })
}

/// Publishes a single asset to a broadcast context as structured content (SCP-290).
///
/// Takes a JSON object string `{ "path", "contentType", "bodyBase64" }` for
/// consistency with the batch method `broadcastPublishAssets`.
///
/// Returns a JS object with `blobId` and `etag` string properties.
///
/// Delegates to `WasmContextManager::publish_broadcast_asset`.
#[wasm_bindgen(js_name = "broadcastPublishAsset")]
pub fn broadcast_publish_asset(
    handle: &WasmContextHandle,
    author_did: String,
    asset_json: String,
    deploy_id: Option<String>,
) -> Promise {
    if let Err(e) = validate_did(&author_did) {
        return future_to_promise(async move { Err(ScpWasmError::from(e).into_js().into()) });
    }
    let context_id = handle.context_id();

    future_to_promise(async move {
        // Parse the asset JSON object.
        let asset: serde_json::Value = serde_json::from_str(&asset_json).map_err(|e| {
            ScpWasmError::Context {
                message: format!("invalid asset JSON: {e}"),
                code: "SCP-CTX-2073".to_owned(),
            }
            .into_js()
        })?;

        let path = asset
            .get("path")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                ScpWasmError::Context {
                    message: "asset must have a 'path' string field".to_owned(),
                    code: "SCP-CTX-2073".to_owned(),
                }
                .into_js()
            })?
            .to_owned();

        let content_type = asset
            .get("contentType")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                ScpWasmError::Context {
                    message: "asset must have a 'contentType' string field".to_owned(),
                    code: "SCP-CTX-2073".to_owned(),
                }
                .into_js()
            })?
            .to_owned();

        let body_base64 = asset
            .get("bodyBase64")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                ScpWasmError::Context {
                    message: "asset must have a 'bodyBase64' string field".to_owned(),
                    code: "SCP-CTX-2073".to_owned(),
                }
                .into_js()
            })?;

        let body = base64::engine::general_purpose::STANDARD
            .decode(body_base64)
            .map_err(|e| {
                ScpWasmError::Context {
                    message: format!("invalid base64 body: {e}"),
                    code: "SCP-CTX-2073".to_owned(),
                }
                .into_js()
            })?;

        let (blob_id, etag, deploy_id_out) = with_manager(|mgr| {
            mgr.publish_broadcast_asset(
                &context_id,
                &author_did,
                &path,
                &content_type,
                &body,
                deploy_id.as_deref(),
            )
        })
        .map_err(ScpWasmError::into_js)?;

        let result = js_sys::Object::new();
        js_sys::Reflect::set(
            &result,
            &JsValue::from_str("blobId"),
            &JsValue::from_str(&blob_id),
        )
        .map_err(|_| JsValue::from_str("failed to set blobId"))?;
        js_sys::Reflect::set(
            &result,
            &JsValue::from_str("etag"),
            &JsValue::from_str(&etag),
        )
        .map_err(|_| JsValue::from_str("failed to set etag"))?;
        js_sys::Reflect::set(
            &result,
            &JsValue::from_str("deployId"),
            &JsValue::from_str(&deploy_id_out),
        )
        .map_err(|_| JsValue::from_str("failed to set deployId"))?;

        Ok(result.into())
    })
}

/// Publishes multiple assets to a broadcast context as structured content (SCP-290).
///
/// Takes an array of `{ path, contentType, bodyBase64 }` objects and an optional
/// `deployId`. Returns an array of `{ blobId, etag }` objects.
///
/// Delegates to `WasmContextManager::publish_broadcast_assets`.
/// Builds a JS batch publish result from per-asset tuples and a shared deploy ID.
fn build_batch_js_result(
    results: Vec<(String, String, String)>,
    deploy_id: &str,
) -> Result<JsValue, JsValue> {
    let js_results = js_sys::Array::new();
    for (blob_id, etag, did) in results {
        let obj = js_sys::Object::new();
        js_sys::Reflect::set(
            &obj,
            &JsValue::from_str("blobId"),
            &JsValue::from_str(&blob_id),
        )
        .map_err(|_| JsValue::from_str("failed to set blobId"))?;
        js_sys::Reflect::set(&obj, &JsValue::from_str("etag"), &JsValue::from_str(&etag))
            .map_err(|_| JsValue::from_str("failed to set etag"))?;
        js_sys::Reflect::set(
            &obj,
            &JsValue::from_str("deployId"),
            &JsValue::from_str(&did),
        )
        .map_err(|_| JsValue::from_str("failed to set deployId"))?;
        js_results.push(&obj);
    }
    let batch = js_sys::Object::new();
    js_sys::Reflect::set(&batch, &JsValue::from_str("results"), &js_results.into())
        .map_err(|_| JsValue::from_str("failed to set results"))?;
    js_sys::Reflect::set(
        &batch,
        &JsValue::from_str("deployId"),
        &JsValue::from_str(deploy_id),
    )
    .map_err(|_| JsValue::from_str("failed to set deployId"))?;
    Ok(batch.into())
}

#[wasm_bindgen(js_name = "broadcastPublishAssets")]
pub fn broadcast_publish_assets(
    handle: &WasmContextHandle,
    author_did: String,
    assets_json: String,
    deploy_id: Option<String>,
) -> Promise {
    if let Err(e) = validate_did(&author_did) {
        return future_to_promise(async move { Err(ScpWasmError::from(e).into_js().into()) });
    }
    let context_id = handle.context_id();

    future_to_promise(async move {
        // Parse the assets JSON array.
        let assets_value: serde_json::Value = serde_json::from_str(&assets_json).map_err(|e| {
            ScpWasmError::Context {
                message: format!("invalid assets JSON: {e}"),
                code: "SCP-CTX-2073".to_owned(),
            }
            .into_js()
        })?;
        let assets_arr = assets_value.as_array().ok_or_else(|| {
            ScpWasmError::Context {
                message: "assets must be a JSON array".to_owned(),
                code: "SCP-CTX-2073".to_owned(),
            }
            .into_js()
        })?;

        let mut parsed_assets: Vec<(String, String, Vec<u8>)> =
            Vec::with_capacity(assets_arr.len());
        for item in assets_arr {
            let path = item
                .get("path")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    ScpWasmError::Context {
                        message: "each asset must have a 'path' string field".to_owned(),
                        code: "SCP-CTX-2073".to_owned(),
                    }
                    .into_js()
                })?
                .to_owned();
            let ct = item
                .get("contentType")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    ScpWasmError::Context {
                        message: "each asset must have a 'contentType' string field".to_owned(),
                        code: "SCP-CTX-2073".to_owned(),
                    }
                    .into_js()
                })?
                .to_owned();
            let body_b64 = item
                .get("bodyBase64")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    ScpWasmError::Context {
                        message: "each asset must have a 'bodyBase64' string field".to_owned(),
                        code: "SCP-CTX-2073".to_owned(),
                    }
                    .into_js()
                })?;
            let body = base64::engine::general_purpose::STANDARD
                .decode(body_b64)
                .map_err(|e| {
                    ScpWasmError::Context {
                        message: format!("invalid base64 body: {e}"),
                        code: "SCP-CTX-2073".to_owned(),
                    }
                    .into_js()
                })?;
            parsed_assets.push((path, ct, body));
        }

        let (results, batch_deploy_id) = with_manager(|mgr| {
            mgr.publish_broadcast_assets(
                &context_id,
                &author_did,
                &parsed_assets,
                deploy_id.as_deref(),
            )
        })
        .map_err(ScpWasmError::into_js)?;

        build_batch_js_result(results, &batch_deploy_id)
    })
}

/// Unsubscribes from a broadcast context.
///
/// Delegates to `WasmContextManager::unsubscribe_broadcast`.
#[wasm_bindgen]
pub fn broadcast_unsubscribe(handle: &WasmContextHandle, subscriber_did: String) -> Promise {
    if let Err(e) = validate_did(&subscriber_did) {
        return future_to_promise(async move { Err(ScpWasmError::from(e).into_js().into()) });
    }
    let context_id = handle.context_id();

    future_to_promise(async move {
        with_manager(|mgr| mgr.unsubscribe_broadcast(&context_id, &subscriber_did))
            .map_err(ScpWasmError::into_js)?;
        Ok(JsValue::UNDEFINED)
    })
}

/// Blocks a subscriber in a broadcast context.
///
/// Delegates to `WasmContextManager::block_broadcast_subscriber`.
#[wasm_bindgen]
pub fn broadcast_block(
    handle: &WasmContextHandle,
    subscriber_did: String,
    blocker_did: String,
) -> Promise {
    if let Err(e) = validate_did(&subscriber_did) {
        return future_to_promise(async move { Err(ScpWasmError::from(e).into_js().into()) });
    }
    if let Err(e) = validate_did(&blocker_did) {
        return future_to_promise(async move { Err(ScpWasmError::from(e).into_js().into()) });
    }
    let context_id = handle.context_id();

    future_to_promise(async move {
        with_manager(|mgr| {
            mgr.block_broadcast_subscriber(&context_id, &blocker_did, &subscriber_did)
        })
        .map_err(ScpWasmError::into_js)?;
        Ok(JsValue::UNDEFINED)
    })
}

/// Unblocks a previously blocked subscriber in a broadcast context (§9.16.8).
///
/// Forward-only: the unblocked subscriber can request the current key on
/// next pull but cannot decrypt content from the block period.
///
/// Delegates to `WasmContextManager::unblock_broadcast_subscriber`.
#[wasm_bindgen]
pub fn broadcast_unblock(
    handle: &WasmContextHandle,
    subscriber_did: String,
    unblocker_did: String,
) -> Promise {
    if let Err(e) = validate_did(&subscriber_did) {
        return future_to_promise(async move { Err(ScpWasmError::from(e).into_js().into()) });
    }
    if let Err(e) = validate_did(&unblocker_did) {
        return future_to_promise(async move { Err(ScpWasmError::from(e).into_js().into()) });
    }
    let context_id = handle.context_id();

    future_to_promise(async move {
        with_manager(|mgr| {
            mgr.unblock_broadcast_subscriber(&context_id, &unblocker_did, &subscriber_did)
        })
        .map_err(ScpWasmError::into_js)?;
        Ok(JsValue::UNDEFINED)
    })
}

/// Returns the number of subscribers in a broadcast context.
///
/// Returns `null` if the context is not a broadcast context.
#[wasm_bindgen]
pub fn broadcast_subscriber_count(handle: &WasmContextHandle) -> Option<u32> {
    let context_id = handle.context_id();
    with_manager(|mgr| {
        Ok(mgr
            .broadcast_subscriber_count(&context_id)
            .map(|n| u32::try_from(n).unwrap_or(u32::MAX)))
    })
    .ok()
    .flatten()
}

/// Returns `true` if the given DID is a subscriber in a broadcast context.
#[wasm_bindgen]
pub fn broadcast_is_subscriber(handle: &WasmContextHandle, did: String) -> bool {
    if validate_did(&did).is_err() {
        return false;
    }
    let context_id = handle.context_id();
    with_manager(|mgr| Ok(mgr.is_broadcast_subscriber(&context_id, &did))).unwrap_or(false)
}

/// Returns the admission policy for a broadcast context as a JSON string.
///
/// Returns `null` if the context is not a broadcast context.
#[wasm_bindgen]
pub fn broadcast_admission(handle: &WasmContextHandle) -> Option<String> {
    let context_id = handle.context_id();
    with_manager(|mgr| Ok(mgr.broadcast_admission(&context_id)))
        .ok()
        .flatten()
}

/// Handles a broadcast key request and returns a grant/deny decision as JSON.
///
/// Returns a JSON string: `{"decision": "grant"}` or `{"decision": "deny", "reason": "..."}`.
#[wasm_bindgen]
pub fn broadcast_handle_key_request(
    handle: &WasmContextHandle,
    author_did: String,
    requester_did: String,
) -> Promise {
    if let Err(e) = validate_did(&author_did) {
        return future_to_promise(async move { Err(ScpWasmError::from(e).into_js().into()) });
    }
    if let Err(e) = validate_did(&requester_did) {
        return future_to_promise(async move { Err(ScpWasmError::from(e).into_js().into()) });
    }
    let context_id = handle.context_id();

    future_to_promise(async move {
        let result = with_manager(|mgr| {
            mgr.handle_broadcast_key_request(&context_id, &author_did, &requester_did)
        })
        .map_err(ScpWasmError::into_js)?;

        Ok(JsValue::from_str(&result))
    })
}

// ---------------------------------------------------------------------------
// Economic policy bridge (§19.3, ADR-033)
// ---------------------------------------------------------------------------

/// Rejects direct economic policy mutation — use governance flow instead
/// (§19.3, #728).
///
/// Economic policy changes MUST go through the governance proposal flow
/// (`SetEconomicPolicy` action) to ensure event logging and the mandatory
/// 24-hour notification period.
///
/// # Errors
///
/// Always returns a `JsError` directing the caller to use governance.
#[wasm_bindgen]
pub fn context_set_economic_policy(
    _handle: &WasmContextHandle,
    _policy_json: String,
) -> Result<(), JsError> {
    Err(ScpWasmError::Permission {
        message: "economic policy changes must go through governance \
                  (propose SetEconomicPolicy action). Direct mutation is \
                  not permitted — see spec §19.3"
            .to_owned(),
        code: "SCP-CTX-2013".to_owned(),
    }
    .into_js())
}

/// Returns the economic policy for a context as a JSON string, or `null`.
#[wasm_bindgen]
pub fn context_get_economic_policy(handle: &WasmContextHandle) -> Option<String> {
    let context_id = handle.context_id();
    with_manager(|mgr| Ok(mgr.get_economic_policy(&context_id)))
        .ok()
        .flatten()
}

// ---------------------------------------------------------------------------
// Context export/import bridge functions (#424)
// ---------------------------------------------------------------------------

/// Exports a context's full state as serialized JSON bytes.
///
/// Returns a `Promise<Uint8Array>` containing a versioned JSON envelope with
/// the context snapshot. The bytes are suitable for backup, migration, or
/// transfer to another WASM node.
///
/// Delegates to `WasmContextManager::export_context`.
#[wasm_bindgen]
pub fn context_export(handle: &WasmContextHandle) -> Promise {
    let context_id = handle.context_id();
    let exporter_did = handle.creator_did();

    future_to_promise(async move {
        let bytes = with_manager(|mgr| mgr.export_context(&context_id, &exporter_did))
            .map_err(ScpWasmError::into_js)?;

        let len = u32::try_from(bytes.len()).map_err(|_| {
            ScpWasmError::Context {
                message: "export data exceeds 4 GiB — too large for WASM Uint8Array".to_owned(),
                code: "SCP-CTX-2030".to_owned(),
            }
            .into_js()
        })?;
        let array = js_sys::Uint8Array::new_with_length(len);
        array.copy_from(&bytes);
        Ok(array.into())
    })
}

/// Imports a context from serialized JSON bytes produced by [`context_export`].
///
/// Returns a `Promise<string>` resolving to the context ID of the imported
/// context. The context becomes active and available for operations.
///
/// Delegates to `WasmContextManager::import_context`.
#[wasm_bindgen]
pub fn context_import(data: Vec<u8>) -> Promise {
    future_to_promise(async move {
        let context_id =
            with_manager(|mgr| mgr.import_context(&data)).map_err(ScpWasmError::into_js)?;
        Ok(JsValue::from_str(&context_id))
    })
}

// ---------------------------------------------------------------------------
// TTL bridge functions
// ---------------------------------------------------------------------------

/// Returns the remaining TTL in seconds, or `null` if no TTL.
#[wasm_bindgen]
pub fn context_ttl_remaining(handle: &WasmContextHandle) -> Option<u32> {
    let context_id = handle.context_id();
    with_manager(|mgr| {
        Ok(mgr
            .ttl_remaining(&context_id)
            .map(|t| u32::try_from(t).unwrap_or(u32::MAX)))
    })
    .ok()
    .flatten()
}

/// Extends the TTL by the given number of seconds.
///
/// Returns `true` if the extension was applied.
#[wasm_bindgen]
pub fn context_extend_ttl(handle: &WasmContextHandle, additional_secs: u32) -> Promise {
    let context_id = handle.context_id();
    let additional_secs_u64 = u64::from(additional_secs);

    future_to_promise(async move {
        let applied = with_manager(|mgr| mgr.extend_ttl(&context_id, additional_secs_u64))
            .map_err(ScpWasmError::into_js)?;
        Ok(JsValue::from_bool(applied))
    })
}

/// Handles TTL expiry for a context.
///
/// Transitions the context to `"expired"` state and records a
/// `ContextExpired` event.
#[wasm_bindgen]
pub fn context_handle_ttl_expiry(handle: &WasmContextHandle) -> Promise {
    let context_id = handle.context_id();

    future_to_promise(async move {
        with_manager(|mgr| mgr.handle_ttl_expiry(&context_id)).map_err(ScpWasmError::into_js)?;
        Ok(JsValue::UNDEFINED)
    })
}

/// Proposes a TTL extension from a specific member.
///
/// Returns `true` if the extension was applied. In the WASM bridge, TTL
/// extension is immediate (no multi-member unanimity — the TypeScript SDK
/// coordinates consensus).
#[wasm_bindgen]
pub fn context_propose_ttl_extension(
    handle: &WasmContextHandle,
    proposer_did: String,
    extension_secs: u32,
) -> Promise {
    if let Err(e) = validate_did(&proposer_did) {
        return future_to_promise(async move { Err(ScpWasmError::from(e).into_js().into()) });
    }
    let context_id = handle.context_id();
    let extension_secs_u64 = u64::from(extension_secs);

    future_to_promise(async move {
        let applied = with_manager(|mgr| {
            mgr.propose_ttl_extension(&context_id, &proposer_did, extension_secs_u64)
        })
        .map_err(ScpWasmError::into_js)?;
        Ok(JsValue::from_bool(applied))
    })
}

/// Resets the TTL timer to a new duration.
///
/// Replaces the context's TTL with the given value.
#[wasm_bindgen]
pub fn context_reset_ttl_timer(handle: &WasmContextHandle, new_duration_secs: u32) -> Promise {
    let context_id = handle.context_id();
    let new_duration_secs_u64 = u64::from(new_duration_secs);

    future_to_promise(async move {
        with_manager(|mgr| mgr.reset_ttl_timer(&context_id, new_duration_secs_u64))
            .map_err(ScpWasmError::into_js)?;
        Ok(JsValue::UNDEFINED)
    })
}

// ---------------------------------------------------------------------------
// App Sandboxing (#595, spec §8.4.1, §8.4.2)
// ---------------------------------------------------------------------------

/// Maps a resource category + action to canonical capability name strings,
/// matching `scp-core`'s `CapabilityEntry::to_capabilities()` exactly.
///
/// Returns a `Vec<String>` because some (category, action) pairs produce
/// multiple capabilities (e.g., `("governance", "admin")` yields both
/// `governance:propose` and `governance:vote`).
///
/// The `is_tool` flag indicates the resource path ends with `tools/{name}`,
/// meaning the action targets a specific tool (not the tools category itself).
///
/// Core source of truth: `crates/scp-core/src/context/app_sandbox.rs`
/// `CapabilityEntry::to_capabilities()`.
fn map_capability_names(category: &str, action: &str, is_tool: bool) -> Vec<String> {
    match (category, action, is_tool) {
        // ToolInvoke(specific) -- resource ends with tools/{tool_name}
        (_, "invoke", true) => vec![format!("tool_invoke:{category}")],
        // MessagesRead -- core accepts ("messaging"|"members", "read")
        ("messaging" | "members", "read", _) => vec!["messages:read".to_owned()],
        // MessagesWrite -- core accepts ("messaging", "write") only
        ("messaging", "write", _) => vec!["messages:write".to_owned()],
        // MemberInvite -- core accepts ("members", "write"|"admin")
        ("members", "write" | "admin", _) => vec!["member:invite".to_owned()],
        // ToolInvokeAll
        ("tools", "invoke", _) => vec!["tool_invoke:*".to_owned()],
        // ToolRegister -- core accepts ("tools", "register"|"admin")
        ("tools", "register" | "admin", _) => vec!["tool:register".to_owned()],
        // GovernancePropose -- core accepts ("governance", "write")
        ("governance", "write", _) => vec!["governance:propose".to_owned()],
        // GovernancePropose + GovernanceVote -- core accepts ("governance", "admin")
        ("governance", "admin", _) => vec![
            "governance:propose".to_owned(),
            "governance:vote".to_owned(),
        ],
        // RoleAssign -- core accepts ("roles", "admin")
        ("roles", "admin", _) => vec!["role:assign".to_owned()],
        // ContextClose -- core accepts ("context", "admin")
        ("context", "admin", _) => vec!["context:close".to_owned()],
        // Bridging (spec section 12)
        ("bridging", _, _) => vec!["bridging".to_owned()],
        // MediaVoice (spec section 10.9.1)
        ("media", "voice", _) => vec!["media:voice".to_owned()],
        // MediaVideo (spec section 10.9.1)
        ("media", "video", _) => vec!["media:video".to_owned()],
        // MediaScreenShare (spec section 10.9.1)
        ("media", "screen_share", _) => vec!["media:screen_share".to_owned()],
        // MetadataEdit -- core accepts ("metadata", "write"|"admin")
        ("metadata", "write" | "admin", _) => vec!["metadata:edit".to_owned()],
        // Custom capabilities -- anything not matching a known pattern.
        // Uses Capability::name() format (not Display), e.g. "category:action".
        _ => vec![format!("{category}:{action}")],
    }
}

/// Builds a sandbox validation error result JSON string.
fn sandbox_err(app_did: &str, error: &str) -> Result<String, JsError> {
    let result = serde_json::json!({
        "valid": false,
        "signatureVerified": false,
        "grantedCapabilities": [],
        "error": error,
        "appDid": app_did
    });
    serde_json::to_string(&result).map_err(|e| JsError::new(&format!("serialization failed: {e}")))
}

/// Validates a capability declaration JSON string against a context ceiling and
/// role capabilities. Returns a JSON string with validation result.
///
/// The declaration JSON must be a valid `CapabilityDeclaration` per spec §8.4.1.
/// WASM bridge performs structural + capability validation but does NOT perform
/// Ed25519 signature verification. The `signatureVerified` field in the result
/// is always `false` -- callers MUST verify the signature themselves (e.g. via
/// `WebCrypto`) before trusting the result.
///
/// Result JSON: `{ valid, signatureVerified, grantedCapabilities, error, appDid }`.
///
/// # Errors
///
/// Returns `JsError` if the declaration JSON is malformed or serialization fails.
#[wasm_bindgen]
pub fn sandbox_validate_declaration(
    declaration_json: String,
    ceiling_capabilities: Vec<String>,
    role_capabilities: Vec<String>,
) -> Result<String, JsError> {
    use std::collections::HashSet;

    let decl: serde_json::Value = serde_json::from_str(&declaration_json)
        .map_err(|e| JsError::new(&format!("invalid declaration JSON: {e}")))?;

    let app_did = decl
        .get("app_id")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_owned();

    // app_id must start with "did:" (spec §8.4.1).
    if !app_did.starts_with("did:") {
        return sandbox_err(&app_did, "invalid app_id: must start with \"did:\"");
    }
    // scp_version must be present (spec §8.4.1).
    if decl.get("scp_version").and_then(|v| v.as_str()).is_none() {
        return sandbox_err(&app_did, "missing required field: scp_version");
    }
    // signature must be present (spec §8.4.1).
    if decl.get("signature").is_none() {
        return sandbox_err(&app_did, "missing required field: signature");
    }

    // Structural validation.
    let app_name = decl.get("app_name").and_then(|v| v.as_str()).unwrap_or("");
    if app_name.is_empty() || app_name.len() > 128 {
        return sandbox_err(&app_did, "invalid app_name: must be 1-128 UTF-8 bytes");
    }

    let capabilities = decl
        .get("capabilities")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    if capabilities.is_empty() || capabilities.len() > 64 {
        return sandbox_err(&app_did, "capabilities must have 1-64 entries");
    }

    // Extract requested capabilities from declaration.
    let mut requested: Vec<String> = Vec::new();
    for cap_entry in &capabilities {
        let resource = cap_entry
            .get("resource")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let actions = cap_entry
            .get("actions")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();

        let category = resource.rsplit('/').next().unwrap_or(resource);
        let parts: Vec<&str> = resource.split('/').collect();
        let is_tool = parts.len() >= 2 && parts[parts.len() - 2] == "tools";

        for action_val in &actions {
            let action = action_val.as_str().unwrap_or("");
            requested.extend(map_capability_names(category, action, is_tool));
        }
    }

    // All-or-nothing ceiling + role check.
    let ceiling_set: HashSet<&str> = ceiling_capabilities.iter().map(String::as_str).collect();
    let role_set: HashSet<&str> = role_capabilities.iter().map(String::as_str).collect();

    for cap in &requested {
        let in_ceiling = ceiling_set.contains(cap.as_str())
            || (cap.starts_with("tool_invoke:") && ceiling_set.contains("tool_invoke:*"));
        let in_role = role_set.contains(cap.as_str())
            || (cap.starts_with("tool_invoke:") && role_set.contains("tool_invoke:*"));
        if !in_ceiling || !in_role {
            return sandbox_err(&app_did, &format!("capability denied: {cap}"));
        }
    }

    let result = serde_json::json!({
        "valid": true,
        "signatureVerified": false,
        "grantedCapabilities": requested,
        "error": null,
        "appDid": app_did
    });
    serde_json::to_string(&result).map_err(|e| JsError::new(&format!("serialization failed: {e}")))
}

/// Checks whether a given capability is allowed for an app binding.
#[wasm_bindgen]
pub fn sandbox_check_capability(
    granted_capabilities: Vec<String>,
    required_capability: String,
) -> bool {
    use std::collections::HashSet;

    let granted: HashSet<&str> = granted_capabilities.iter().map(String::as_str).collect();

    if granted.contains(required_capability.as_str()) {
        return true;
    }
    // ToolInvokeAll covers any specific ToolInvoke.
    if required_capability.starts_with("tool_invoke:")
        && required_capability != "tool_invoke:*"
        && granted.contains("tool_invoke:*")
    {
        return true;
    }
    false
}

// ---------------------------------------------------------------------------
// Bridge-level validation helpers
// ---------------------------------------------------------------------------

/// Validates `minProtocolVersion` from a context params JSON value at the
/// bridge boundary.
///
/// Checks structural validity only (array shape, element types, u8 range).
/// Version compatibility against the SDK's `SCP_PROTOCOL_VERSION` is checked
/// by the manager's `parse_and_check_min_protocol_version`. This function
/// provides defense-in-depth: malformed input is rejected before any state
/// mutation.
///
/// Accepts:
/// - Absent / `null` → `Ok(())`
/// - `[major, minor]` where both are u64 in `0..=255` → `Ok(())`
///
/// Rejects:
/// - Non-array values (e.g. `"1.0"`, `42`)
/// - Arrays with fewer than 2 elements
/// - Non-numeric elements (e.g. `["1", "0"]`)
/// - Values exceeding `u8::MAX`
fn validate_min_protocol_version(params: &serde_json::Value) -> Result<(), ScpWasmError> {
    let field = &params["minProtocolVersion"];

    // Absent or null → no minimum, nothing to validate.
    if field.is_null() {
        return Ok(());
    }

    let arr = field.as_array().ok_or_else(|| ScpWasmError::Validation {
        message: format!("minProtocolVersion must be a [major, minor] array, got: {field}"),
        code: "SCP-VALID-7002".to_owned(),
    })?;

    if arr.len() < 2 {
        return Err(ScpWasmError::Validation {
            message: format!(
                "minProtocolVersion must have at least 2 elements [major, minor], got {len}",
                len = arr.len()
            ),
            code: "SCP-VALID-7002".to_owned(),
        });
    }

    // Validate major version element.
    let raw_major = arr[0].as_u64().ok_or_else(|| ScpWasmError::Validation {
        message: format!(
            "minProtocolVersion[0] (major) must be a non-negative integer, got: {}",
            arr[0]
        ),
        code: "SCP-VALID-7002".to_owned(),
    })?;
    if raw_major > u64::from(u8::MAX) {
        return Err(ScpWasmError::Validation {
            message: format!("minProtocolVersion[0] (major) exceeds u8 range: {raw_major}"),
            code: "SCP-VALID-7002".to_owned(),
        });
    }

    // Validate minor version element.
    let raw_minor = arr[1].as_u64().ok_or_else(|| ScpWasmError::Validation {
        message: format!(
            "minProtocolVersion[1] (minor) must be a non-negative integer, got: {}",
            arr[1]
        ),
        code: "SCP-VALID-7002".to_owned(),
    })?;
    if raw_minor > u64::from(u8::MAX) {
        return Err(ScpWasmError::Validation {
            message: format!("minProtocolVersion[1] (minor) exceeds u8 range: {raw_minor}"),
            code: "SCP-VALID-7002".to_owned(),
        });
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Invitation evaluation pipeline (#614)
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// WASM-local rate limit tracker (B1 — #614)
// ---------------------------------------------------------------------------

/// WASM-local rate limit tracker for invitation auto-accept.
///
/// Mirrors `scp_core::context::invitation::RateLimitTracker` behavior using
/// `js_sys::Date::now()` timestamps (milliseconds since epoch) instead of
/// `std::time::Instant` (unavailable on `wasm32-unknown-unknown`).
///
/// Stored per-identity-DID in a `thread_local` `HashMap`.
struct WasmRateLimitTracker {
    /// Timestamps of auto-accept events in milliseconds since epoch.
    accepts_ms: Vec<f64>,
}

impl WasmRateLimitTracker {
    /// Creates a new empty tracker.
    const fn new() -> Self {
        Self {
            accepts_ms: Vec::new(),
        }
    }

    /// Records an auto-accept event at the current time.
    fn record_accept(&mut self) {
        self.accepts_ms.push(js_sys::Date::now());
    }

    /// Checks whether an additional auto-accept is allowed under the given
    /// rate limit (`max_count` within `window_secs`). Prunes expired entries.
    fn is_allowed(&mut self, max_count: u32, window_secs: f64) -> bool {
        let now_ms = js_sys::Date::now();
        let window_ms = window_secs * 1000.0;
        self.accepts_ms.retain(|&t| (now_ms - t) < window_ms);
        self.accepts_ms.len() < max_count as usize
    }
}

thread_local! {
    /// Per-identity-DID rate limit trackers for invitation auto-accept.
    static RATE_LIMIT_TRACKERS: std::cell::RefCell<std::collections::HashMap<String, WasmRateLimitTracker>>
        = std::cell::RefCell::new(std::collections::HashMap::new());
}

/// Executes `f` with a mutable reference to the rate limit tracker for the
/// given identity DID, creating one if it does not exist.
fn with_rate_limit_tracker<F, T>(identity_did: &str, f: F) -> T
where
    F: FnOnce(&mut WasmRateLimitTracker) -> T,
{
    RATE_LIMIT_TRACKERS.with(|trackers| {
        let mut map = trackers.borrow_mut();
        let tracker = map
            .entry(identity_did.to_owned())
            .or_insert_with(WasmRateLimitTracker::new);
        f(tracker)
    })
}

// ---------------------------------------------------------------------------
// MetadataRecord inspection (§5.7.2, #615)
// ---------------------------------------------------------------------------

/// WASM-local `MetadataRecord` definition matching scp-core's
/// `context::metadata::MetadataRecord`. Uses the same serde field names.
/// Remains WASM-local because the scp-core `MetadataRecord` depends on
/// async context state not available in the WASM bridge.
#[derive(serde::Serialize, serde::Deserialize)]
struct WasmMetadataRecord {
    context_id: String,
    sequence: u64,
    signer_did: String,
    timestamp: u64,
    structural: serde_json::Value,
    operational: serde_json::Value,
    #[serde(with = "serde_bytes")]
    signature: Vec<u8>,
}

/// Serializes a `MetadataRecord` to a JSON string.
///
/// Constructs a `MetadataRecord` from the provided fields and returns its
/// JSON representation. The `signature` field is provided as a hex-encoded
/// string (64 bytes = 128 hex characters).
///
/// WASM re-implementation per ADR-034 (no scp-core dependency).
///
/// # Errors
///
/// Returns `JsError` if any input is malformed or serialization fails.
#[wasm_bindgen(js_name = "metadataRecordToJson")]
pub fn metadata_record_to_json(
    context_id: String,
    sequence: u32,
    signer_did: String,
    timestamp: f64,
    structural_json: String,
    operational_json: String,
    signature_hex: String,
) -> Result<String, JsError> {
    use scp_ffi_common::validate::{validate_context_id, validate_did};

    validate_context_id(&context_id)
        .map_err(|e| ScpWasmError::Validation {
            message: e.to_string(),
            code: "SCP-VALID-7001".to_owned(),
        })
        .map_err(ScpWasmError::into_js)?;

    validate_did(&signer_did)
        .map_err(|e| ScpWasmError::Validation {
            message: e.to_string(),
            code: "SCP-VALID-7001".to_owned(),
        })
        .map_err(ScpWasmError::into_js)?;

    if sequence == 0 {
        return Err(ScpWasmError::Validation {
            message: "MetadataRecord sequence must start at 1 (per spec §5.7.2)".to_owned(),
            code: "SCP-VALID-7001".to_owned(),
        }
        .into_js());
    }

    let structural: serde_json::Value = serde_json::from_str(&structural_json).map_err(|e| {
        ScpWasmError::Validation {
            message: format!("invalid structural metadata JSON: {e}"),
            code: "SCP-VALID-7001".to_owned(),
        }
        .into_js()
    })?;

    let operational: serde_json::Value = serde_json::from_str(&operational_json).map_err(|e| {
        ScpWasmError::Validation {
            message: format!("invalid operational metadata JSON: {e}"),
            code: "SCP-VALID-7001".to_owned(),
        }
        .into_js()
    })?;

    let signature = hex::decode(&signature_hex).map_err(|e| {
        ScpWasmError::Validation {
            message: format!("invalid signature hex: {e}"),
            code: "SCP-VALID-7001".to_owned(),
        }
        .into_js()
    })?;
    if signature.len() != 64 {
        return Err(ScpWasmError::Validation {
            message: format!("signature must be 64 bytes (got {})", signature.len()),
            code: "SCP-VALID-7001".to_owned(),
        }
        .into_js());
    }

    #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
    let ts = timestamp as u64;
    let record = WasmMetadataRecord {
        context_id,
        sequence: u64::from(sequence),
        signer_did,
        timestamp: ts,
        structural,
        operational,
        signature,
    };

    serde_json::to_string(&record).map_err(|e| {
        ScpWasmError::Validation {
            message: format!("failed to serialize MetadataRecord: {e}"),
            code: "SCP-VALID-7001".to_owned(),
        }
        .into_js()
    })
}

/// Deserializes a `MetadataRecord` from a JSON string.
///
/// Returns the validated and re-serialized JSON.
///
/// # Errors
///
/// Returns `JsError` if the JSON is malformed, or if semantic validation
/// fails (sequence < 1, signature length != 64, missing structural/operational
/// fields).
#[wasm_bindgen(js_name = "metadataRecordFromJson")]
pub fn metadata_record_from_json(json_str: String) -> Result<String, JsError> {
    let record: WasmMetadataRecord = serde_json::from_str(&json_str).map_err(|e| {
        ScpWasmError::Validation {
            message: format!("invalid MetadataRecord JSON: {e}"),
            code: "SCP-VALID-7001".to_owned(),
        }
        .into_js()
    })?;

    // F6: sequence must be >= 1 (spec §5.7.2)
    if record.sequence == 0 {
        return Err(ScpWasmError::Validation {
            message: "MetadataRecord sequence must start at 1 (per spec §5.7.2)".to_owned(),
            code: "SCP-VALID-7001".to_owned(),
        }
        .into_js());
    }

    // F7: signature must be exactly 64 bytes (Ed25519)
    if record.signature.len() != 64 {
        return Err(ScpWasmError::Validation {
            message: format!(
                "signature must be 64 bytes (got {})",
                record.signature.len()
            ),
            code: "SCP-VALID-7001".to_owned(),
        }
        .into_js());
    }

    // F4: Validate required structural fields (context_id, mode)
    if let Some(obj) = record.structural.as_object() {
        if !obj.contains_key("context_id") {
            return Err(ScpWasmError::Validation {
                message: "structural metadata must contain 'context_id' field".to_owned(),
                code: "SCP-VALID-7001".to_owned(),
            }
            .into_js());
        }
        if !obj.contains_key("mode") {
            return Err(ScpWasmError::Validation {
                message: "structural metadata must contain 'mode' field".to_owned(),
                code: "SCP-VALID-7001".to_owned(),
            }
            .into_js());
        }
    } else {
        return Err(ScpWasmError::Validation {
            message: "structural metadata must be a JSON object".to_owned(),
            code: "SCP-VALID-7001".to_owned(),
        }
        .into_js());
    }

    // F4: Validate required operational fields (version, capabilities)
    if let Some(obj) = record.operational.as_object() {
        if !obj.contains_key("version") {
            return Err(ScpWasmError::Validation {
                message: "operational metadata must contain 'version' field".to_owned(),
                code: "SCP-VALID-7001".to_owned(),
            }
            .into_js());
        }
        if !obj.contains_key("capabilities") {
            return Err(ScpWasmError::Validation {
                message: "operational metadata must contain 'capabilities' field".to_owned(),
                code: "SCP-VALID-7001".to_owned(),
            }
            .into_js());
        }
    } else {
        return Err(ScpWasmError::Validation {
            message: "operational metadata must be a JSON object".to_owned(),
            code: "SCP-VALID-7001".to_owned(),
        }
        .into_js());
    }

    serde_json::to_string(&record).map_err(|e| {
        ScpWasmError::Validation {
            message: format!("failed to re-serialize MetadataRecord: {e}"),
            code: "SCP-VALID-7001".to_owned(),
        }
        .into_js()
    })
}

// ---------------------------------------------------------------------------
// Template validation (B2 — #614)
// ---------------------------------------------------------------------------

/// Validates context params against the claimed template.
///
/// Delegates to `scp_protocol::context::templates::validate_against_template`.
/// Returns an error message on mismatch, or `Ok(())` if validation passes
/// (or no template is claimed).
fn validate_invitation_template(params: &serde_json::Value) -> Result<(), ScpWasmError> {
    // If no template_id field, nothing to validate.
    let Some(tid) = params.get("template_id") else {
        return Ok(());
    };
    if tid.is_null() {
        return Ok(());
    }

    // Normalize camelCase to snake_case before deserialization into ContextParams.
    let mut normalized = params.clone();
    camel_to_snake_context_params(&mut normalized);

    // Parse the whole params as ContextParams, then delegate to the protocol.
    let ctx_params: scp_protocol::context::params::ContextParams =
        serde_json::from_value(normalized).map_err(|_| {
            // If the params can't be parsed as ContextParams, it's not a valid
            // template — forward-compatible: skip validation for unknown shapes.
            ScpWasmError::Context {
                message: "template validation failed: invalid context params".to_owned(),
                code: "SCP-CTX-2060".to_owned(),
            }
        })?;

    protocol_validate_against_template(&ctx_params).map_err(|e| ScpWasmError::Context {
        message: format!("template spoofing detected: {e}"),
        code: "SCP-CTX-2060".to_owned(),
    })
}

/// Returns `true` if the ceiling array contains any tool-related capability.
fn ceiling_has_tool_caps(ceiling: Option<&serde_json::Value>) -> bool {
    use scp_protocol::context::params::Capability;

    ceiling
        .and_then(|v| serde_json::from_value::<Vec<Capability>>(v.clone()).ok())
        .is_some_and(|caps| {
            caps.iter().any(|cap| {
                matches!(
                    cap,
                    Capability::ToolInvokeAll
                        | Capability::ToolInvoke(_)
                        | Capability::ToolRegister
                )
            })
        })
}

/// Returns `true` if the params JSON has an economic policy requiring payment.
fn params_require_payment(params: &serde_json::Value) -> bool {
    params
        .get("economic_policy")
        .and_then(|ep| ep.get("cost_schedule"))
        .is_some_and(|cs| {
            cs.get("per_message").is_some_and(|v| !v.is_null())
                || cs.get("per_tool_invoke").is_some_and(|v| !v.is_null())
                || cs.get("per_join").is_some_and(|v| !v.is_null())
                || cs.get("per_period").is_some_and(|v| !v.is_null())
                || cs.get("per_byte_stored").is_some_and(|v| !v.is_null())
        })
        || params
            .get("economic_policy")
            .and_then(|ep| ep.get("pricing_formula"))
            .is_some_and(|v| !v.is_null())
}

/// Checks trust requirement against the inviter and trusted DID list.
fn check_trust(
    policy: &serde_json::Value,
    inviter_did: &str,
    trusted_dids_json: Option<&String>,
) -> bool {
    match policy.get("from").and_then(serde_json::Value::as_str) {
        Some("Any") => true,
        Some("SharedContext") => {
            let trusted: Vec<String> = trusted_dids_json.map_or_else(Vec::new, |json| {
                serde_json::from_str(json).unwrap_or_default()
            });
            trusted.contains(&inviter_did.to_owned())
        }
        _ => policy.get("from").is_some_and(|from_obj| {
            from_obj.get("Explicit").is_some_and(|explicit| {
                explicit
                    .as_array()
                    .is_some_and(|arr| arr.iter().any(|d| d.as_str() == Some(inviter_did)))
            })
        }),
    }
}

// ---------------------------------------------------------------------------
// Template inspection — delegates to scp-protocol
// ---------------------------------------------------------------------------

/// Checks economic policy constraints: spending UCAN, adapter compatibility,
/// and balance sufficiency. Returns an error `JsValue` on failure, or
/// `Ok(())` if all checks pass.
fn check_economic_policy(
    params: &serde_json::Value,
    spending_json: Option<&String>,
) -> Result<(), JsValue> {
    let spending: Option<serde_json::Value> =
        spending_json.and_then(|json| serde_json::from_str(json).ok());

    let has_ucan = spending
        .as_ref()
        .and_then(|sp| {
            sp.get("has_spending_ucan")
                .and_then(serde_json::Value::as_bool)
        })
        .unwrap_or(false);

    if !has_ucan {
        return Err(ScpWasmError::Context {
            message: "spending UCAN required: context has economic policy requiring payment"
                .to_owned(),
            code: "SCP-CTX-2060".to_owned(),
        }
        .into_js()
        .into());
    }

    let Some(ref sp) = spending else {
        return Ok(());
    };

    // Check compatible payment adapter.
    let configured_adapters: Vec<String> = sp
        .get("configured_adapters")
        .and_then(serde_json::Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(serde_json::Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();

    if let Some(accepted_adapters) = params
        .get("economic_policy")
        .and_then(|ep| ep.get("payment_adapters"))
        .and_then(serde_json::Value::as_array)
    {
        let has_compatible = accepted_adapters.iter().any(|a| {
            a.as_str()
                .is_some_and(|s| configured_adapters.contains(&s.to_owned()))
        });

        if !has_compatible {
            let accepted: Vec<String> = accepted_adapters
                .iter()
                .filter_map(serde_json::Value::as_str)
                .map(str::to_owned)
                .collect();
            return Err(ScpWasmError::Context {
                message: format!(
                    "no compatible payment adapter: context accepts {accepted:?}, configured {configured_adapters:?}"
                ),
                code: "SCP-CTX-2060".to_owned(),
            }
            .into_js()
            .into());
        }
    }

    // Check balance covers at least per_join cost.
    let available_balance = sp
        .get("available_balance")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);

    if let Some(per_join) = params
        .get("economic_policy")
        .and_then(|ep| ep.get("cost_schedule"))
        .and_then(|cs| cs.get("per_join"))
        .and_then(serde_json::Value::as_u64)
        && available_balance < per_join
    {
        return Err(ScpWasmError::Context {
            message: format!(
                "insufficient balance: estimated cost {per_join}, available {available_balance}"
            ),
            code: "SCP-CTX-2060".to_owned(),
        }
        .into_js()
        .into());
    }

    Ok(())
}

/// Evaluates the auto-accept policy against invitation params.
///
/// Returns `Some("auto_accept")` if the policy matches and all constraints
/// (trust, TTL, rate limit) pass. Returns `None` to fall through to
/// prompt-agent.
fn check_auto_accept(
    params: &serde_json::Value,
    policy_json: Option<&String>,
    inviter_did: &str,
    identity_did: &str,
    trusted_dids_json: Option<&String>,
) -> Result<Option<&'static str>, JsValue> {
    let Some(pjson) = policy_json else {
        return Ok(None);
    };

    let policy: serde_json::Value = serde_json::from_str(pjson).map_err(|e| {
        JsValue::from_str(&format!(
            "[SCP-VALID-7010] failed to parse auto-accept policy JSON: {e}"
        ))
    })?;

    if ceiling_has_tool_caps(params.get("ceiling")) {
        return Ok(None);
    }

    let policy_template = policy.get("template").and_then(serde_json::Value::as_str);
    let params_template = params
        .get("template_id")
        .and_then(serde_json::Value::as_str);

    if policy_template.is_none()
        || policy_template != params_template
        || !check_trust(&policy, inviter_did, trusted_dids_json)
    {
        return Ok(None);
    }

    let ttl_ok = match (
        policy.get("max_ttl").and_then(serde_json::Value::as_f64),
        params.get("ttl").and_then(serde_json::Value::as_f64),
    ) {
        (Some(max), Some(actual)) => actual <= max,
        _ => true,
    };

    if !ttl_ok {
        return Ok(None);
    }

    // Rate limit check.
    let rate_ok = match (
        policy
            .get("rate_limit")
            .and_then(|rl| rl.get("max_count"))
            .and_then(serde_json::Value::as_u64),
        policy
            .get("rate_limit")
            .and_then(|rl| rl.get("window"))
            .and_then(serde_json::Value::as_f64),
    ) {
        (Some(max_count), Some(window_secs)) => {
            let max = u32::try_from(max_count).unwrap_or(u32::MAX);
            with_rate_limit_tracker(identity_did, |tracker| tracker.is_allowed(max, window_secs))
        }
        _ => true,
    };

    if rate_ok {
        with_rate_limit_tracker(identity_did, |tracker| {
            tracker.record_accept();
        });
        return Ok(Some("auto_accept"));
    }

    Ok(None)
}

// ---------------------------------------------------------------------------
// JSON field name normalization (snake_case <-> camelCase)
// ---------------------------------------------------------------------------

/// Renames `snake_case` `ContextParams` fields to camelCase for JS output.
///
/// The scp-protocol `ContextParams` struct serializes with `snake_case` field
/// names (`max_chain_depth`, `max_nesting_depth`, `session_cap`). The WASM
/// bridge API contract exposes these as camelCase to match JS conventions.
fn snake_to_camel_context_params(val: &mut serde_json::Value) {
    if let Some(map) = val.as_object_mut() {
        let renames: &[(&str, &str)] = &[
            ("max_chain_depth", "maxChainDepth"),
            ("max_nesting_depth", "maxNestingDepth"),
            ("session_cap", "sessionCap"),
        ];
        for &(snake, camel) in renames {
            if let Some(v) = map.remove(snake) {
                map.insert(camel.to_owned(), v);
            }
        }
    }
}

/// Renames camelCase `ContextParams` fields to `snake_case` for deserialization
/// into the scp-protocol `ContextParams` struct.
///
/// JS consumers may send `"maxChainDepth"` (camelCase) in params JSON. The
/// scp-protocol `ContextParams` expects `"max_chain_depth"` (`snake_case`).
/// This normalization avoids silent field drops during deserialization.
fn camel_to_snake_context_params(val: &mut serde_json::Value) {
    if let Some(map) = val.as_object_mut() {
        let renames: &[(&str, &str)] = &[
            ("maxChainDepth", "max_chain_depth"),
            ("maxNestingDepth", "max_nesting_depth"),
            ("sessionCap", "session_cap"),
        ];
        for &(camel, snake) in renames {
            if let Some(v) = map.remove(camel) {
                map.insert(snake.to_owned(), v);
            }
        }
    }
}

/// Returns the canonical `ContextParams` for a given template ID as JSON.
///
/// Delegates to `scp_protocol::context::templates::template_params` for the
/// canonical definitions. No WASM-local reimplementation needed.
///
/// Post-processes JSON output to restore camelCase field names
/// (`maxChainDepth`, `maxNestingDepth`, `sessionCap`) expected by JS consumers.
/// The scp-protocol `ContextParams` struct serializes with `snake_case`, but
/// the WASM bridge API contract uses camelCase for these fields.
///
/// # Errors
///
/// Returns `JsError` if the template ID is not recognized or serialization fails.
#[wasm_bindgen(js_name = "templateGetParams")]
pub fn template_get_params(template_id: String) -> Result<String, JsError> {
    let tid: TemplateId = serde_json::from_value(serde_json::Value::String(template_id.clone()))
        .map_err(|_| {
            ScpWasmError::Validation {
                message: format!(
                    "unknown template ID: {template_id:?} -- valid values: BilateralEphemeral, \
                     BilateralPersistent, Coordination, GroupDiscussion, PublicBroadcast, \
                     GatedBroadcast, scp:template/tool-interface, \
                     scp:template/paid-service, scp:template/paid-broadcast, \
                     scp:template/handle-registry (alias: scp:template/discovery-context, \
                     DiscoveryContext)"
                ),
                code: "SCP-VALID-7001".to_owned(),
            }
            .into_js()
        })?;
    let params = protocol_template_params(&tid);
    let mut val = serde_json::to_value(&params).map_err(|e| {
        ScpWasmError::Validation {
            message: format!("failed to serialize template params: {e}"),
            code: "SCP-VALID-7001".to_owned(),
        }
        .into_js()
    })?;

    // Restore camelCase field names expected by JS consumers. The scp-protocol
    // ContextParams struct uses snake_case, but the WASM bridge has always
    // exposed these three fields as camelCase.
    snake_to_camel_context_params(&mut val);

    serde_json::to_string(&val).map_err(|e| {
        ScpWasmError::Validation {
            message: format!("failed to serialize template params: {e}"),
            code: "SCP-VALID-7001".to_owned(),
        }
        .into_js()
    })
}

/// Validates that a `ContextParams` JSON matches its template definition.
///
/// Returns `null` on success, or a string error message on validation failure.
/// Delegates to `scp_protocol::context::templates::validate_against_template`.
///
/// Normalizes camelCase field names (`maxChainDepth`, `maxNestingDepth`,
/// `sessionCap`) to `snake_case` before deserialization, so JS consumers can
/// use either convention.
///
/// # Errors
///
/// Returns `JsError` if the JSON is malformed.
#[wasm_bindgen(js_name = "validateAgainstTemplate")]
pub fn validate_against_template(params_json: String) -> Result<Option<String>, JsError> {
    let mut raw: serde_json::Value = serde_json::from_str(&params_json).map_err(|e| {
        ScpWasmError::Validation {
            message: format!("invalid ContextParams JSON: {e}"),
            code: "SCP-VALID-7001".to_owned(),
        }
        .into_js()
    })?;

    // Normalize camelCase to snake_case before deserialization into ContextParams.
    camel_to_snake_context_params(&mut raw);

    let params: scp_protocol::context::params::ContextParams = serde_json::from_value(raw)
        .map_err(|e| {
            ScpWasmError::Validation {
                message: format!("invalid ContextParams JSON: {e}"),
                code: "SCP-VALID-7001".to_owned(),
            }
            .into_js()
        })?;

    match protocol_validate_against_template(&params) {
        Ok(()) => Ok(None),
        Err(e) => Ok(Some(e.to_string())),
    }
}

/// Evaluates a context invitation through the sequential pipeline.
///
/// WASM-local re-implementation of the 4-step pipeline from `scp-core`.
/// Returns a Promise resolving to JSON: `{"decision": "auto_accept"|"prompt_agent"}`.
///
/// Includes rate limiting (B1), full template validation (B2), and
/// adapter/balance economic checks (B3) per #614 review findings.
#[wasm_bindgen]
pub fn evaluate_invitation(
    params_json: String,
    inviter_did: String,
    identity_did: String,
    policy_json: Option<String>,
    spending_json: Option<String>,
    trusted_dids_json: Option<String>,
) -> Promise {
    future_to_promise(async move {
        validate_did(&inviter_did).map_err(|e| ScpWasmError::from(e).into_js())?;
        validate_did(&identity_did).map_err(|e| ScpWasmError::from(e).into_js())?;

        let params: serde_json::Value = serde_json::from_str(&params_json).map_err(|e| {
            JsValue::from_str(&format!(
                "[SCP-VALID-7010] failed to parse context params JSON: {e}"
            ))
        })?;

        // Step 1: Template validation (B2 — all template types).
        validate_invitation_template(&params).map_err(ScpWasmError::into_js)?;

        // Step 2: Economic policy check (B3 — adapter/balance checks).
        if params_require_payment(&params) {
            check_economic_policy(&params, spending_json.as_ref())?;
            return Ok(JsValue::from_str(r#"{"decision":"prompt_agent"}"#));
        }

        // Step 3: Auto-accept check (B1 — rate limiting).
        if let Some(decision) = check_auto_accept(
            &params,
            policy_json.as_ref(),
            &inviter_did,
            &identity_did,
            trusted_dids_json.as_ref(),
        )? {
            return Ok(JsValue::from_str(&format!(
                r#"{{"decision":"{decision}"}}"#
            )));
        }

        // Step 4: Prompt agent (fallthrough).
        Ok(JsValue::from_str(r#"{"decision":"prompt_agent"}"#))
    })
}

/// Validates cross-field invariants for `ContextParams` regardless of template.
///
/// Returns `null` on success, or a string error message on validation failure.
/// Delegates to `scp_protocol::context::templates::validate_context_params`.
///
/// Normalizes camelCase field names (`maxChainDepth`, `maxNestingDepth`,
/// `sessionCap`) to `snake_case` before deserialization, so JS consumers can
/// use either convention.
///
/// # Errors
///
/// Returns `JsError` if the JSON is malformed.
#[wasm_bindgen(js_name = "validateContextParams")]
pub fn validate_context_params(params_json: String) -> Result<Option<String>, JsError> {
    let mut raw: serde_json::Value = serde_json::from_str(&params_json).map_err(|e| {
        ScpWasmError::Validation {
            message: format!("invalid ContextParams JSON: {e}"),
            code: "SCP-VALID-7001".to_owned(),
        }
        .into_js()
    })?;

    // Normalize camelCase to snake_case before deserialization into ContextParams.
    camel_to_snake_context_params(&mut raw);

    let params: scp_protocol::context::params::ContextParams = serde_json::from_value(raw)
        .map_err(|e| {
            ScpWasmError::Validation {
                message: format!("invalid ContextParams JSON: {e}"),
                code: "SCP-VALID-7001".to_owned(),
            }
            .into_js()
        })?;

    match protocol_validate_context_params(&params) {
        Ok(()) => Ok(None),
        Err(e) => Ok(Some(e.to_string())),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_min_protocol_version_absent() {
        let params = serde_json::json!({});
        assert!(validate_min_protocol_version(&params).is_ok());
    }

    #[test]
    fn validate_min_protocol_version_null() {
        let params = serde_json::json!({ "minProtocolVersion": null });
        assert!(validate_min_protocol_version(&params).is_ok());
    }

    #[test]
    fn validate_min_protocol_version_valid() {
        let params = serde_json::json!({ "minProtocolVersion": [1, 0] });
        assert!(validate_min_protocol_version(&params).is_ok());
    }

    #[test]
    fn validate_min_protocol_version_valid_max_u8() {
        let params = serde_json::json!({ "minProtocolVersion": [255, 255] });
        assert!(validate_min_protocol_version(&params).is_ok());
    }

    #[test]
    fn validate_min_protocol_version_rejects_string() {
        let params = serde_json::json!({ "minProtocolVersion": "1.0" });
        assert!(
            matches!(
                validate_min_protocol_version(&params),
                Err(ScpWasmError::Validation { ref code, .. }) if code == "SCP-VALID-7002"
            ),
            "expected SCP-VALID-7002 validation error"
        );
    }

    #[test]
    fn validate_min_protocol_version_rejects_number() {
        let params = serde_json::json!({ "minProtocolVersion": 42 });
        assert!(
            matches!(
                validate_min_protocol_version(&params),
                Err(ScpWasmError::Validation { ref code, .. }) if code == "SCP-VALID-7002"
            ),
            "expected SCP-VALID-7002 validation error"
        );
    }

    #[test]
    fn validate_min_protocol_version_rejects_short_array() {
        let params = serde_json::json!({ "minProtocolVersion": [1] });
        assert!(
            matches!(
                validate_min_protocol_version(&params),
                Err(ScpWasmError::Validation { ref code, .. }) if code == "SCP-VALID-7002"
            ),
            "expected SCP-VALID-7002 validation error"
        );
    }

    #[test]
    fn validate_min_protocol_version_rejects_empty_array() {
        let params = serde_json::json!({ "minProtocolVersion": [] });
        assert!(
            matches!(
                validate_min_protocol_version(&params),
                Err(ScpWasmError::Validation { ref code, .. }) if code == "SCP-VALID-7002"
            ),
            "expected SCP-VALID-7002 validation error"
        );
    }

    #[test]
    fn validate_min_protocol_version_rejects_string_elements() {
        let params = serde_json::json!({ "minProtocolVersion": ["1", "0"] });
        assert!(
            matches!(
                validate_min_protocol_version(&params),
                Err(ScpWasmError::Validation { ref code, .. }) if code == "SCP-VALID-7002"
            ),
            "expected SCP-VALID-7002 validation error"
        );
    }

    #[test]
    fn validate_min_protocol_version_rejects_string_minor() {
        let params = serde_json::json!({ "minProtocolVersion": [1, "0"] });
        assert!(
            matches!(
                validate_min_protocol_version(&params),
                Err(ScpWasmError::Validation { ref code, .. }) if code == "SCP-VALID-7002"
            ),
            "expected SCP-VALID-7002 validation error"
        );
    }

    #[test]
    fn validate_min_protocol_version_rejects_major_overflow() {
        let params = serde_json::json!({ "minProtocolVersion": [256, 0] });
        assert!(
            matches!(
                validate_min_protocol_version(&params),
                Err(ScpWasmError::Validation { ref code, .. }) if code == "SCP-VALID-7002"
            ),
            "expected SCP-VALID-7002 validation error"
        );
    }

    #[test]
    fn validate_min_protocol_version_rejects_minor_overflow() {
        let params = serde_json::json!({ "minProtocolVersion": [1, 256] });
        assert!(
            matches!(
                validate_min_protocol_version(&params),
                Err(ScpWasmError::Validation { ref code, .. }) if code == "SCP-VALID-7002"
            ),
            "expected SCP-VALID-7002 validation error"
        );
    }

    #[test]
    fn validate_min_protocol_version_rejects_negative() {
        let params = serde_json::json!({ "minProtocolVersion": [-1, 0] });
        assert!(
            matches!(
                validate_min_protocol_version(&params),
                Err(ScpWasmError::Validation { ref code, .. }) if code == "SCP-VALID-7002"
            ),
            "expected SCP-VALID-7002 validation error"
        );
    }
}
