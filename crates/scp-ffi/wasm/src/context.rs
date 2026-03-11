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
    #[must_use]
    #[wasm_bindgen(getter, js_name = "contextId")]
    pub fn context_id(&self) -> String {
        self.context_id.clone()
    }

    #[must_use]
    #[wasm_bindgen(getter)]
    pub fn state(&self) -> String {
        self.state.borrow().clone()
    }

    #[must_use]
    #[wasm_bindgen(getter, js_name = "creatorDid")]
    pub fn creator_did(&self) -> String {
        self.creator_did.clone()
    }

    #[must_use]
    #[wasm_bindgen(getter)]
    pub fn mode(&self) -> String {
        self.mode.clone()
    }

    #[must_use]
    #[wasm_bindgen(getter)]
    pub fn ceiling(&self) -> js_sys::Array {
        self.ceiling.iter().map(|s| JsValue::from_str(s)).collect()
    }

    #[must_use]
    #[wasm_bindgen(getter, js_name = "ceilingPolicy")]
    pub fn ceiling_policy(&self) -> String {
        self.ceiling_policy.clone()
    }

    #[must_use]
    #[wasm_bindgen(getter, js_name = "ttlSeconds")]
    pub fn ttl_seconds(&self) -> Option<u64> {
        self.ttl_seconds
    }

    #[must_use]
    #[wasm_bindgen(getter, js_name = "promotionPolicy")]
    pub fn promotion_policy(&self) -> Option<String> {
        self.promotion_policy.clone()
    }

    #[must_use]
    #[wasm_bindgen(getter)]
    pub fn governance(&self) -> String {
        self.governance.clone()
    }

    #[must_use]
    #[wasm_bindgen(getter, js_name = "memberCount")]
    pub fn member_count(&self) -> u64 {
        self.member_count
    }

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
    #[must_use]
    #[wasm_bindgen(getter, js_name = "senderDid")]
    pub fn sender_did(&self) -> String {
        self.sender_did.clone()
    }

    #[must_use]
    #[wasm_bindgen(getter, js_name = "payloadBase64")]
    pub fn payload_base64(&self) -> String {
        self.payload_base64.clone()
    }

    #[must_use]
    #[wasm_bindgen(getter)]
    pub fn timestamp(&self) -> f64 {
        self.timestamp
    }

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
pub fn context_member_count(handle: &WasmContextHandle) -> Option<u64> {
    let context_id = handle.context_id();
    with_manager(|mgr| Ok(mgr.member_count(&context_id).map(|c| c as u64)))
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
pub fn broadcast_block(handle: &WasmContextHandle, subscriber_did: String) -> Promise {
    if let Err(e) = validate_did(&subscriber_did) {
        return future_to_promise(async move { Err(ScpWasmError::from(e).into_js().into()) });
    }
    let context_id = handle.context_id();

    future_to_promise(async move {
        with_manager(|mgr| mgr.block_broadcast_subscriber(&context_id, &subscriber_did))
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
pub fn broadcast_unblock(handle: &WasmContextHandle, subscriber_did: String) -> Promise {
    if let Err(e) = validate_did(&subscriber_did) {
        return future_to_promise(async move { Err(ScpWasmError::from(e).into_js().into()) });
    }
    let context_id = handle.context_id();

    future_to_promise(async move {
        with_manager(|mgr| mgr.unblock_broadcast_subscriber(&context_id, &subscriber_did))
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
pub fn context_ttl_remaining(handle: &WasmContextHandle) -> Option<u64> {
    let context_id = handle.context_id();
    with_manager(|mgr| Ok(mgr.ttl_remaining(&context_id)))
        .ok()
        .flatten()
}

/// Extends the TTL by the given number of seconds.
///
/// Returns `true` if the extension was applied.
#[wasm_bindgen]
pub fn context_extend_ttl(handle: &WasmContextHandle, additional_secs: u64) -> Promise {
    let context_id = handle.context_id();

    future_to_promise(async move {
        let applied = with_manager(|mgr| mgr.extend_ttl(&context_id, additional_secs))
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
    extension_secs: u64,
) -> Promise {
    if let Err(e) = validate_did(&proposer_did) {
        return future_to_promise(async move { Err(ScpWasmError::from(e).into_js().into()) });
    }
    let context_id = handle.context_id();

    future_to_promise(async move {
        let applied = with_manager(|mgr| {
            mgr.propose_ttl_extension(&context_id, &proposer_did, extension_secs)
        })
        .map_err(ScpWasmError::into_js)?;
        Ok(JsValue::from_bool(applied))
    })
}

/// Resets the TTL timer to a new duration.
///
/// Replaces the context's TTL with the given value.
#[wasm_bindgen]
pub fn context_reset_ttl_timer(handle: &WasmContextHandle, new_duration_secs: u64) -> Promise {
    let context_id = handle.context_id();

    future_to_promise(async move {
        with_manager(|mgr| mgr.reset_ttl_timer(&context_id, new_duration_secs))
            .map_err(ScpWasmError::into_js)?;
        Ok(JsValue::UNDEFINED)
    })
}
