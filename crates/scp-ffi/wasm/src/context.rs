//! `wasm-bindgen` bridge for context lifecycle and messaging.
//!
//! All context operations delegate to [`WasmContextManager`](crate::manager::WasmContextManager)
//! via [`with_manager`](crate::manager::with_manager). No local state management or
//! algorithm re-implementation — the manager owns all context state.
//!
//! See ADR-034 in `.docs/adrs/phase-4.md` and issue #389.

use js_sys::Promise;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::future_to_promise;

use scp_ffi_common::validate::validate_did;

use crate::error::ScpWasmError;
use crate::manager::{WasmGovernanceAction, with_manager};

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
/// * `action_json` — JSON-encoded governance action (see `WasmGovernanceAction`).
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
        let action: WasmGovernanceAction = serde_json::from_str(&action_json).map_err(|e| {
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
        let action: crate::manager::WasmGovernanceAction = serde_json::from_str(&action_json)
            .map_err(|e| {
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

/// Sets the economic policy on a context (§19.3).
///
/// Validates the JSON string before storing. Does not go through
/// governance — this is a direct setter for local state matching the
/// `PyO3` `py_set_economic_policy` pattern.
///
/// # Errors
///
/// Returns a `JsError` if the JSON is invalid.
#[wasm_bindgen]
pub fn context_set_economic_policy(
    handle: &WasmContextHandle,
    policy_json: String,
) -> Result<(), JsError> {
    // Validate JSON is well-formed and parses as a generic JSON value.
    // WASM cannot import scp-core's EconomicPolicy (ADR-034), so we
    // validate that the JSON is syntactically valid. Schema validation
    // is the SDK wrapper's responsibility in the WASM path.
    let _val: serde_json::Value = serde_json::from_str(&policy_json).map_err(|e| {
        ScpWasmError::Validation {
            message: format!("invalid economic policy JSON: {e}"),
            code: "SCP-VALID-7001".to_owned(),
        }
        .into_js()
    })?;

    let context_id = handle.context_id();
    with_manager(|mgr| mgr.set_economic_policy(&context_id, policy_json))
        .map_err(ScpWasmError::into_js)?;
    Ok(())
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
        (_, "invoke", true) => vec![format!("tool:invoke:{category}")],
        // MessagesRead -- core accepts ("messaging"|"members", "read")
        ("messaging" | "members", "read", _) => vec!["messages:read".to_owned()],
        // MessagesWrite -- core accepts ("messaging", "write") only
        ("messaging", "write", _) => vec!["messages:write".to_owned()],
        // MemberInvite -- core accepts ("members", "write"|"admin")
        ("members", "write" | "admin", _) => vec!["member:invite".to_owned()],
        // ToolInvokeAll
        ("tools", "invoke", _) => vec!["tool:invoke:*".to_owned()],
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

    // Structural validation.
    let app_name = decl.get("app_name").and_then(|v| v.as_str()).unwrap_or("");
    if app_name.is_empty() || app_name.len() > 128 {
        let result = serde_json::json!({
            "valid": false,
            "signatureVerified": false,
            "grantedCapabilities": [],
            "error": "invalid app_name: must be 1-128 UTF-8 bytes",
            "appDid": app_did
        });
        return serde_json::to_string(&result)
            .map_err(|e| JsError::new(&format!("serialization failed: {e}")));
    }

    let capabilities = decl
        .get("capabilities")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    if capabilities.is_empty() || capabilities.len() > 64 {
        let result = serde_json::json!({
            "valid": false,
            "signatureVerified": false,
            "grantedCapabilities": [],
            "error": "capabilities must have 1-64 entries",
            "appDid": app_did
        });
        return serde_json::to_string(&result)
            .map_err(|e| JsError::new(&format!("serialization failed: {e}")));
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
            || (cap.starts_with("tool:invoke:") && ceiling_set.contains("tool:invoke:*"));
        let in_role = role_set.contains(cap.as_str())
            || (cap.starts_with("tool:invoke:") && role_set.contains("tool:invoke:*"));

        if !in_ceiling || !in_role {
            let result = serde_json::json!({
                "valid": false,
                "signatureVerified": false,
                "grantedCapabilities": [],
                "error": format!("capability denied: {cap}"),
                "appDid": app_did
            });
            return serde_json::to_string(&result)
                .map_err(|e| JsError::new(&format!("serialization failed: {e}")));
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
    if required_capability.starts_with("tool:invoke:")
        && required_capability != "tool:invoke:*"
        && granted.contains("tool:invoke:*")
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
