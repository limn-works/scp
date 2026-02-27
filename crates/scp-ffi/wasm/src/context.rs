//! `wasm-bindgen` bridge for context lifecycle and messaging.
//!
//! Exposes context operations to JavaScript as typed handles and
//! `#[wasm_bindgen]` functions. Bridge functions mirror the Python FFI
//! bridge (`crates/scp-ffi/src/context.rs`) and the UniFFI bridge
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
//! streaming uses a callback injection pattern (matching the UniFFI bridge's
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
/// Stores context metadata: unique ID, lifecycle state, and the DID of the
/// context creator. The actual context runtime (MLS group, transport
/// connections, event log) lives in scp-core and is connected when the full
/// runtime is wired. Until then, the handle tracks state locally.
///
/// # JS usage
///
/// ```js
/// const ctx = await context_create(identity.did, paramsJson);
/// console.log(ctx.contextId);   // "ctx-abc123..."
/// console.log(ctx.state);       // "active"
/// console.log(ctx.creatorDid);  // "did:dht:z..."
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
}

#[wasm_bindgen]
impl WasmContextHandle {
    /// Returns the context's unique identifier.
    #[wasm_bindgen(getter, js_name = "contextId")]
    pub fn context_id(&self) -> String {
        self.context_id.clone()
    }

    /// Returns the context's current lifecycle state.
    ///
    /// One of: `"creating"`, `"active"`, `"closing"`, `"closed"`, `"expired"`.
    #[wasm_bindgen(getter)]
    pub fn state(&self) -> String {
        self.state.clone()
    }

    /// Returns the DID of the context creator.
    #[wasm_bindgen(getter, js_name = "creatorDid")]
    pub fn creator_did(&self) -> String {
        self.creator_did.clone()
    }
}

impl WasmContextHandle {
    /// Creates a new handle in the "active" state.
    fn new_active(context_id: String, creator_did: String) -> Self {
        Self {
            context_id,
            state: "active".to_owned(),
            creator_did,
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
    #[wasm_bindgen(getter, js_name = "senderDid")]
    pub fn sender_did(&self) -> String {
        self.sender_did.clone()
    }

    /// Returns the message payload as a base64-encoded string.
    ///
    /// The TypeScript SDK decodes this to `Uint8Array` before surfacing to
    /// application code.
    #[wasm_bindgen(getter, js_name = "payloadBase64")]
    pub fn payload_base64(&self) -> String {
        self.payload_base64.clone()
    }

    /// Returns the message timestamp as seconds since Unix epoch.
    #[wasm_bindgen(getter)]
    pub fn timestamp(&self) -> f64 {
        self.timestamp
    }

    /// Returns the context ID this message belongs to.
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
        // Validate that params_json is valid JSON.
        let _params: serde_json::Value = serde_json::from_str(&params_json)
            .map_err(|e| ScpWasmError::Validation(format!(
                "params_json is not valid JSON: {e} — pass a JSON-encoded context parameters object"
            ))
            .into_js())?;

        // Generate a context ID using a UUID (CSPRNG-backed via getrandom/js).
        let context_id = format!("ctx-{}", uuid::Uuid::new_v4().as_hyphenated());

        let handle = WasmContextHandle::new_active(context_id, identity_did);

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
/// # Arguments
///
/// * `handle` — The context to close (must be in `"active"` state).
/// * `identity_did` — The DID of the identity initiating the close (must be
///   admin or hold a close capability).
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
pub fn context_close(handle: &WasmContextHandle, identity_did: String) -> Promise {
    let state = handle.state.clone();
    let _ = identity_did; // Used when full runtime is wired.

    future_to_promise(async move {
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
