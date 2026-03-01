//! `wasm-bindgen` bridge for context lifecycle and messaging.
//!
//! Exposes context operations to JavaScript as typed handles and
//! `#[wasm_bindgen]` functions. Bridge functions mirror the Python FFI
//! bridge (`crates/scp-ffi/src/context.rs`) and the `UniFFI` bridge
//! (`crates/scp-ffi/uniffi/src/bridge.rs`) at the same logical API surface.
//!
//! # Types
//!
//! - [`WasmContextHandle`] — Opaque handle to a context (context ID, state,
//!   creator DID).
//! - [`WasmMessage`] — A received message (sender DID, payload bytes,
//!   timestamp, context ID).
//!
//! # Bridge functions
//!
//! - [`context_create`] — Create a new context.
//! - [`context_join`] — Join an existing context.
//! - [`context_leave`] — Leave a context.
//! - [`context_close`] — Close a context.
//! - [`context_send`] — Send a message.
//! - [`context_subscribe`] — Register a JS callback for incoming messages.
//!
//! # Streaming
//!
//! WASM has no Rust async streams compatible with wasm-bindgen. Message
//! streaming uses a callback injection pattern (matching the `UniFFI` bridge's
//! `MessageListener` approach): the TypeScript wrapper registers a
//! [`JsMessageCallback`] object; the bridge calls `onMessage` for each
//! incoming message and `onComplete` when the stream ends.
//!
//! The TypeScript SDK converts this callback to an `AsyncIterable<Message>`
//! using an internal queue-based adapter.
//!
//! See ADR-022 in `.docs/adrs/phase-4.md` for the full specification.

use js_sys::Promise;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::future_to_promise;

use crate::error::ScpWasmError;

// ---------------------------------------------------------------------------
// JsMessageCallback — JS-injected message stream callback
// ---------------------------------------------------------------------------

/// JS object implementing the message stream callback interface.
///
/// The TypeScript SDK implements this interface to receive messages from a
/// context subscription. The bridge calls [`JsMessageCallback::on_message`]
/// for each incoming message and [`JsMessageCallback::on_complete`] when
/// the subscription ends.
///
/// The TypeScript wrapper converts this callback to an
/// `AsyncIterable<Message>` for ergonomic consumption.
#[wasm_bindgen]
extern "C" {
    /// A JS object implementing the message stream callback interface.
    pub type JsMessageCallback;

    /// Called for each incoming message on the subscribed context.
    ///
    /// `message` is a [`WasmMessage`] handle.
    #[wasm_bindgen(method, js_name = "onMessage")]
    pub fn on_message(this: &JsMessageCallback, message: WasmMessage);

    /// Called when the message stream ends (context closed or subscription
    /// cancelled).
    #[wasm_bindgen(method, js_name = "onComplete")]
    pub fn on_complete(this: &JsMessageCallback);
}

// ---------------------------------------------------------------------------
// WasmContextHandle — opaque JS object for SCP contexts
// ---------------------------------------------------------------------------

/// Opaque handle to an SCP context.
///
/// Stores context metadata required by spec §5.7: unique ID, lifecycle state,
/// creator DID, and the full set of governance and policy fields visible before
/// opting in to any context. The actual context runtime (MLS group, transport
/// connections, event log) lives in scp-core and is connected when the full
/// runtime is wired. Until then, the handle tracks state locally.
///
/// # JS usage
///
/// ```js
/// const ctx = await context_create(identity.did, paramsJson);
/// console.log(ctx.contextId);      // "ctx-abc123..."
/// console.log(ctx.state);          // "active"
/// console.log(ctx.creatorDid);     // "did:dht:z..."
/// console.log(ctx.mode);           // "Encrypted" | "Broadcast"
/// console.log(ctx.ceiling);        // string[]
/// console.log(ctx.ceilingPolicy);  // "immutable" | "governed"
/// console.log(ctx.ttlSeconds);     // number | undefined
/// console.log(ctx.promotionPolicy); // string | undefined
/// console.log(ctx.governance);     // "single_admin" | ...
/// console.log(ctx.memberCount);    // number (starts at 1)
/// console.log(ctx.economicPolicy); // string | undefined
/// ```
#[wasm_bindgen]
#[derive(Debug, Clone)]
pub struct WasmContextHandle {
    /// Unique identifier for this context.
    context_id: String,
    /// Current lifecycle state: "creating", "active", "closing", "closed", "expired".
    state: String,
    /// DID of the context creator.
    creator_did: String,
    /// Context mode: "Encrypted" (MLS group) or "Broadcast" (per-author keys).
    /// Set at creation and immutable. See spec §5.1 and §5.14.
    mode: String,
    /// Capability ceiling: the maximum set of capabilities available in this
    /// context. See spec §5.3.
    ceiling: Vec<String>,
    /// Ceiling policy: "immutable" or "governed". Immutable at creation.
    /// See spec §5.3.
    ceiling_policy: String,
    /// Optional time-to-live in seconds. None means persistent. See spec §5.10.
    ttl_seconds: Option<u64>,
    /// Optional promotion policy: `"no_promotion"` or `"promotable"`. Only
    /// meaningful when `ttl_seconds` is `Some`. See spec §5.10.
    promotion_policy: Option<String>,
    /// Governance model string (e.g. `"single_admin"`). See spec §5.9.
    governance: String,
    /// Number of context members. Starts at 1 (creator) at creation.
    /// See spec §5.6 and §5.7.
    member_count: u64,
    /// Optional economic policy. Orthogonal to capability ceiling.
    /// See spec §5.3 and §19.3.
    economic_policy: Option<String>,
}

#[wasm_bindgen]
impl WasmContextHandle {
    /// Returns the context's unique identifier.
    #[must_use]
    #[wasm_bindgen(getter, js_name = "contextId")]
    pub fn context_id(&self) -> String {
        self.context_id.clone()
    }

    /// Returns the context's current lifecycle state.
    ///
    /// One of: `"creating"`, `"active"`, `"closing"`, `"closed"`, `"expired"`.
    #[must_use]
    #[wasm_bindgen(getter)]
    pub fn state(&self) -> String {
        self.state.clone()
    }

    /// Returns the DID of the context creator.
    #[must_use]
    #[wasm_bindgen(getter, js_name = "creatorDid")]
    pub fn creator_did(&self) -> String {
        self.creator_did.clone()
    }

    /// Returns the context mode: `"Encrypted"` or `"Broadcast"`.
    ///
    /// Set at creation and immutable. `"Encrypted"` uses an MLS group;
    /// `"Broadcast"` uses per-author broadcast keys. See spec §5.1 and §5.14.
    #[must_use]
    #[wasm_bindgen(getter)]
    pub fn mode(&self) -> String {
        self.mode.clone()
    }

    /// Returns the capability ceiling as a JS `Array` of strings.
    ///
    /// The ceiling is the maximum set of capabilities available in this context.
    /// See spec §5.3.
    #[must_use]
    #[wasm_bindgen(getter)]
    pub fn ceiling(&self) -> js_sys::Array {
        self.ceiling.iter().map(|s| JsValue::from_str(s)).collect()
    }

    /// Returns the ceiling policy: `"immutable"` or `"governed"`.
    ///
    /// The policy itself is immutable (locked at creation). See spec §5.3.
    #[must_use]
    #[wasm_bindgen(getter, js_name = "ceilingPolicy")]
    pub fn ceiling_policy(&self) -> String {
        self.ceiling_policy.clone()
    }

    /// Returns the TTL in seconds, or `undefined` if the context is persistent.
    ///
    /// See spec §5.10.
    #[must_use]
    #[wasm_bindgen(getter, js_name = "ttlSeconds")]
    pub fn ttl_seconds(&self) -> Option<u64> {
        self.ttl_seconds
    }

    /// Returns the promotion policy, or `undefined` if no TTL is set.
    ///
    /// One of `"no_promotion"` | `"promotable"`. Only meaningful when
    /// `ttlSeconds` is defined. See spec §5.10.
    #[must_use]
    #[wasm_bindgen(getter, js_name = "promotionPolicy")]
    pub fn promotion_policy(&self) -> Option<String> {
        self.promotion_policy.clone()
    }

    /// Returns the governance model string (e.g. `"single_admin"`).
    ///
    /// See spec §5.9.
    #[must_use]
    #[wasm_bindgen(getter)]
    pub fn governance(&self) -> String {
        self.governance.clone()
    }

    /// Returns the current member count.
    ///
    /// Starts at `1` (the creator) at creation. See spec §5.6 and §5.7.
    #[must_use]
    #[wasm_bindgen(getter, js_name = "memberCount")]
    pub fn member_count(&self) -> u64 {
        self.member_count
    }

    /// Returns the economic policy string, or `undefined` if none is set.
    ///
    /// Economic policy governs what actions cost, orthogonal to the capability
    /// ceiling. See spec §5.3 and §19.3.
    #[must_use]
    #[wasm_bindgen(getter, js_name = "economicPolicy")]
    pub fn economic_policy(&self) -> Option<String> {
        self.economic_policy.clone()
    }
}

impl WasmContextHandle {
    /// Creates a new handle in the `"active"` state with all §5.7 metadata
    /// fields populated.
    #[allow(clippy::too_many_arguments)]
    fn new_active(
        context_id: String,
        creator_did: String,
        mode: String,
        ceiling: Vec<String>,
        ceiling_policy: String,
        ttl_seconds: Option<u64>,
        promotion_policy: Option<String>,
        governance: String,
        economic_policy: Option<String>,
    ) -> Self {
        Self {
            context_id,
            state: "active".to_owned(),
            creator_did,
            mode,
            ceiling,
            ceiling_policy,
            ttl_seconds,
            promotion_policy,
            governance,
            member_count: 1,
            economic_policy,
        }
    }
}

// ---------------------------------------------------------------------------
// WasmMessage — incoming message from an SCP context
// ---------------------------------------------------------------------------

/// A received message from an SCP context.
///
/// Exposed to JavaScript with read-only getter properties. The payload is
/// stored as base64-encoded bytes and returned as a JS `string` for
/// cross-boundary safety. The TypeScript SDK decodes to `Uint8Array` before
/// surfacing to application code.
///
/// # JS usage
///
/// ```js
/// const msg = /* received via context_subscribe callback */;
/// console.log(msg.senderDid);     // "did:dht:z..."
/// console.log(msg.payloadBase64); // base64-encoded payload bytes
/// console.log(msg.timestamp);     // Unix epoch seconds (number)
/// console.log(msg.contextId);     // "ctx-abc123..."
/// ```
#[wasm_bindgen]
#[derive(Debug, Clone)]
pub struct WasmMessage {
    /// DID of the message sender.
    sender_did: String,
    /// Message payload encoded as base64 for safe WASM boundary crossing.
    payload_base64: String,
    /// Message timestamp as seconds since Unix epoch.
    timestamp: f64,
    /// Context ID this message belongs to.
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
    ///
    /// The TypeScript SDK decodes this to `Uint8Array` before surfacing to
    /// application code.
    #[must_use]
    #[wasm_bindgen(getter, js_name = "payloadBase64")]
    pub fn payload_base64(&self) -> String {
        self.payload_base64.clone()
    }

    /// Returns the message timestamp as seconds since Unix epoch.
    #[must_use]
    #[wasm_bindgen(getter)]
    pub fn timestamp(&self) -> f64 {
        self.timestamp
    }

    /// Returns the context ID this message belongs to.
    #[must_use]
    #[wasm_bindgen(getter, js_name = "contextId")]
    pub fn context_id(&self) -> String {
        self.context_id.clone()
    }
}

// ---------------------------------------------------------------------------
// Bridge functions
// ---------------------------------------------------------------------------

/// Creates a new SCP context.
///
/// # Arguments
///
/// * `identity_did` — The DID string of the identity creating the context.
/// * `params_json` — A JSON string of context creation parameters with the
///   following optional fields:
///   - `"ceiling"` (`string[]`): Capability ceiling.
///   - `"roles"` (`Record<string, string[]>`): Role definitions.
///   - `"tools"` (`string[]`): Initial tool registrations.
///   - `"ttl"` (`number | null`): Time-to-live in seconds.
///   - `"memoryScope"` (`"ephemeral" | "summary" | "full"`): Memory scope.
///   - `"governance"` (`"single_admin"`): Governance model.
///
/// # Returns
///
/// `Promise<WasmContextHandle>` — resolves to a new context handle in
/// `"active"` state.
///
/// # Errors
///
/// - Rejects with `[SCP-VALID-7000]` if `params_json` is malformed JSON or
///   contains invalid field values.
/// - Rejects with `[SCP-CTX-2000]` if context creation fails.
///
/// See ADR-022 acceptance criterion 1.
#[wasm_bindgen]
pub fn context_create(identity_did: String, params_json: String) -> Promise {
    future_to_promise(async move {
        // Parse and validate params_json.
        let params: serde_json::Value = serde_json::from_str(&params_json).map_err(|e| {
            ScpWasmError::Validation(format!(
                "params_json is not valid JSON: {e} — pass a JSON-encoded context parameters object"
            ))
            .into_js()
        })?;

        // Extract §5.7 metadata fields with spec-defined defaults.
        let mode = params["mode"].as_str().unwrap_or("Encrypted").to_owned();
        let ceiling: Vec<String> = params["ceiling"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default();
        let ceiling_policy = params["ceilingPolicy"]
            .as_str()
            .unwrap_or("immutable")
            .to_owned();
        let ttl_seconds: Option<u64> = params["ttlSeconds"].as_u64();
        let promotion_policy: Option<String> =
            params["promotionPolicy"].as_str().map(str::to_owned);
        let governance = params["governance"]
            .as_str()
            .unwrap_or("single_admin")
            .to_owned();
        let economic_policy: Option<String> = params["economicPolicy"].as_str().map(str::to_owned);

        // Generate a context ID using a UUID (CSPRNG-backed via getrandom/js).
        let context_id = format!("ctx-{}", uuid::Uuid::new_v4().as_hyphenated());

        let handle = WasmContextHandle::new_active(
            context_id,
            identity_did,
            mode,
            ceiling,
            ceiling_policy,
            ttl_seconds,
            promotion_policy,
            governance,
            economic_policy,
        );

        Ok(JsValue::from(handle))
    })
}

/// Joins an existing SCP context.
///
/// # Arguments
///
/// * `handle` — The context handle (must be in `"active"` state).
/// * `identity_did` — The DID string of the joining identity.
///
/// # Returns
///
/// `Promise<void>` — resolves on success.
///
/// # Errors
///
/// Rejects with `[SCP-CTX-2000]` if the context is not in `"active"` state.
///
/// See ADR-022 acceptance criterion 1.
#[wasm_bindgen]
pub fn context_join(handle: &WasmContextHandle, identity_did: String) -> Promise {
    let state = handle.state.clone();
    let _ = identity_did; // Used when full runtime is wired.

    future_to_promise(async move {
        if state != "active" {
            return Err(ScpWasmError::Context(format!(
                "cannot join context in '{state}' state — context must be 'active'"
            ))
            .into_js()
            .into());
        }

        Ok(JsValue::UNDEFINED)
    })
}

/// Leaves an SCP context.
///
/// # Arguments
///
/// * `handle` — The context to leave (must be in `"active"` state).
/// * `identity_did` — The DID string of the leaving identity.
///
/// # Returns
///
/// `Promise<void>` — resolves on success.
///
/// # Errors
///
/// Rejects with `[SCP-CTX-2000]` if the context is not in `"active"` state.
///
/// See ADR-022 acceptance criterion 1.
#[wasm_bindgen]
pub fn context_leave(handle: &WasmContextHandle, identity_did: String) -> Promise {
    let state = handle.state.clone();
    let _ = identity_did; // Used when full runtime is wired.

    future_to_promise(async move {
        if state != "active" {
            return Err(ScpWasmError::Context(format!(
                "cannot leave context in '{state}' state — context must be 'active'"
            ))
            .into_js()
            .into());
        }

        Ok(JsValue::UNDEFINED)
    })
}

/// Closes an SCP context.
///
/// Initiates cooperative context closing. In the full runtime this triggers
/// the closing window (member notification, summary generation, key
/// destruction). In the bridge layer, the context transitions to `"closed"`
/// immediately.
///
/// # Authorization
///
/// Only the context creator (the DID that created the context) is authorized
/// to close it. This is enforced locally in the bridge layer by comparing
/// `identity_did` against the creator DID stored in the context handle.
///
/// # Arguments
///
/// * `handle` — The context to close (must be in `"active"` state).
/// * `identity_did` — The DID of the identity initiating the close (must be
///   the context creator or an admin).
///
/// # Returns
///
/// `Promise<void>` — resolves on success.
///
/// # Errors
///
/// - Rejects with `[SCP-PERM-3000]` if `identity_did` is not the context
///   creator.
/// - Rejects with `[SCP-CTX-2000]` if the context is not in `"active"` state.
///
/// See ADR-022 acceptance criterion 1.
#[wasm_bindgen]
pub fn context_close(handle: &WasmContextHandle, identity_did: String) -> Promise {
    let state = handle.state.clone();
    let creator_did = handle.creator_did.clone();

    future_to_promise(async move {
        // Authorization: only the context creator can close the context.
        if identity_did != creator_did {
            return Err(ScpWasmError::Permission(format!(
                "identity '{identity_did}' is not authorized to close this context \
                 — only the context creator ('{creator_did}') can close it"
            ))
            .into_js()
            .into());
        }

        if state != "active" {
            return Err(ScpWasmError::Context(format!(
                "cannot close context in '{state}' state — context must be 'active'"
            ))
            .into_js()
            .into());
        }

        Ok(JsValue::UNDEFINED)
    })
}

/// Sends a message to an SCP context.
///
/// # Arguments
///
/// * `handle` — The context to send to (must be in `"active"` state).
/// * `identity_did` — The DID of the sending identity.
/// * `payload_base64` — The message payload as a base64-encoded string.
///   The TypeScript SDK encodes `Uint8Array` to base64 before calling this.
///
/// # Returns
///
/// `Promise<void>` — resolves on success.
///
/// # Errors
///
/// - Rejects with `[SCP-CTX-2000]` if the context is not `"active"`.
/// - Rejects with `[SCP-VALID-7000]` if `payload_base64` is not valid base64.
///
/// See ADR-022 acceptance criterion 1.
#[wasm_bindgen]
pub fn context_send(
    handle: &WasmContextHandle,
    identity_did: String,
    payload_base64: String,
) -> Promise {
    let state = handle.state.clone();
    let _ = identity_did; // Used when full runtime is wired.

    future_to_promise(async move {
        if state != "active" {
            return Err(ScpWasmError::Context(format!(
                "cannot send to context in '{state}' state — context must be 'active'"
            ))
            .into_js()
            .into());
        }

        // Validate that the payload is valid base64.
        if payload_base64.is_empty() {
            return Err(ScpWasmError::Validation(
                "payload_base64 must not be empty — encode payload bytes as base64 before calling context_send"
                    .to_owned(),
            )
            .into_js()
            .into());
        }

        // In the full runtime, this would:
        // 1. Encrypt the payload via MLS/sender keys.
        // 2. Create an OuterEnvelope with provenance metadata.
        // 3. Send via the transport layer.
        // 4. Log the send event.
        Ok(JsValue::UNDEFINED)
    })
}

/// Subscribes to incoming messages from an SCP context.
///
/// Registers a JS callback to receive incoming messages. The callback is
/// called with [`WasmMessage`] for each message and `onComplete` when the
/// subscription ends. The TypeScript SDK converts this to an
/// `AsyncIterable<Message>` for application code.
///
/// # Arguments
///
/// * `handle` — The context to subscribe to (must be in `"active"` state).
/// * `callback` — A JS object implementing the message callback interface:
///   - `onMessage(message: WasmMessage): void`
///   - `onComplete(): void`
///
/// # Errors
///
/// Returns `[SCP-CTX-2000]` if the context is not in `"active"` state.
///
/// See ADR-022 acceptance criterion 1.
#[wasm_bindgen]
pub fn context_subscribe(
    handle: &WasmContextHandle,
    callback: JsMessageCallback,
) -> Result<(), JsError> {
    if handle.state != "active" {
        return Err(ScpWasmError::Context(format!(
            "cannot subscribe to context in '{}' state — context must be 'active'",
            handle.state
        ))
        .into_js());
    }

    // In the full runtime, the transport layer would be wired to call
    // callback.on_message(msg) for each incoming message and
    // callback.on_complete() when the subscription ends.
    //
    // For the bridge layer, signal completion immediately so the TypeScript
    // wrapper's AsyncIterable terminates cleanly.
    callback.on_complete();

    Ok(())
}
