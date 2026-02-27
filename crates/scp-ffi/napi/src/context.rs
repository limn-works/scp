//! napi-rs bridge for context lifecycle and messaging.
//!
//! Exposes context operations to JavaScript:
//!
//! - [`context_create`] — Create a new SCP context.
//! - [`context_join`] — Join an existing context.
//! - [`context_leave`] — Leave a context.
//! - [`context_close`] — Close a context.
//! - [`context_send`] — Send a message to a context.
//! - [`context_subscribe`] — Subscribe to incoming messages via a callback.
//!
//! # Streaming
//!
//! Message streaming uses a callback pattern matching the UniFFI bridge's
//! `MessageListener` approach. The TypeScript SDK converts this callback to
//! an `AsyncIterable<Message>` via an internal queue adapter (see ADR-022).
//!
//! See ADR-022 in `.docs/adrs/phase-4.md`.

use napi::Error as NapiError;
use napi_derive::napi;
use uuid::Uuid;

use crate::error::ScpNapiError;
use crate::{decrement_handle_count, increment_handle_count};

// ---------------------------------------------------------------------------
// NapiContextHandle — opaque JS class for SCP contexts
// ---------------------------------------------------------------------------

/// Opaque handle to an SCP context.
///
/// Stores context metadata: unique ID, lifecycle state, and the DID of the
/// context creator. The actual context runtime (MLS group, transport
/// connections, event log) lives in scp-core and will be wired in full
/// integration stories.
///
/// # JS usage
///
/// ```js
/// const ctx = await contextCreate(identity.did, paramsJson);
/// console.log(ctx.contextId);   // "ctx-..."
/// console.log(ctx.state);       // "active"
/// console.log(ctx.creatorDid);  // "did:dht:z..."
/// ```
#[napi]
pub struct NapiContextHandle {
    /// Unique identifier for this context.
    context_id: String,
    /// Current lifecycle state (guarded by a Mutex for interior mutability).
    state: std::sync::Mutex<ContextState>,
    /// DID of the context creator.
    creator_did: String,
}

#[derive(Debug, Clone, Copy)]
enum ContextState {
    Active,
    Closed,
}

impl ContextState {
    fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Closed => "closed",
        }
    }
}

#[napi]
impl NapiContextHandle {
    /// Returns the context's unique identifier.
    #[napi(getter, js_name = "contextId")]
    pub fn context_id(&self) -> String {
        self.context_id.clone()
    }

    /// Returns the context's current lifecycle state.
    ///
    /// One of: `"active"`, `"closed"`.
    #[napi(getter)]
    pub fn state(&self) -> napi::Result<String> {
        let guard = self.state.lock().map_err(|_| {
            NapiError::from(ScpNapiError::Context {
                message: "context state lock is poisoned".to_owned(),
                code: "SCP-CTX-2012".to_owned(),
            })
        })?;
        Ok(guard.as_str().to_owned())
    }

    /// Returns the DID of the context creator.
    #[napi(getter, js_name = "creatorDid")]
    pub fn creator_did(&self) -> String {
        self.creator_did.clone()
    }
}

impl NapiContextHandle {
    /// Returns the current state string for validation checks.
    pub(crate) fn current_state_str(&self) -> Result<String, ScpNapiError> {
        self.state
            .lock()
            .map(|g| g.as_str().to_owned())
            .map_err(|_| ScpNapiError::Context {
                message: "context state lock is poisoned".to_owned(),
                code: "SCP-CTX-2012".to_owned(),
            })
    }

    /// Sets the state to Closed.
    pub(crate) fn set_closed(&self) -> Result<(), ScpNapiError> {
        let mut guard = self.state.lock().map_err(|_| ScpNapiError::Context {
            message: "context state lock is poisoned".to_owned(),
            code: "SCP-CTX-2012".to_owned(),
        })?;
        *guard = ContextState::Closed;
        Ok(())
    }
}

impl Drop for NapiContextHandle {
    fn drop(&mut self) {
        decrement_handle_count();
    }
}

// ---------------------------------------------------------------------------
// NapiMessage — incoming message from an SCP context
// ---------------------------------------------------------------------------

/// A received message from an SCP context.
#[napi(object)]
pub struct NapiMessage {
    /// DID of the message sender.
    pub sender_did: String,
    /// Raw message payload bytes (decrypted application content).
    pub payload: Vec<u8>,
    /// Unix timestamp (seconds since epoch) when the message was created.
    pub timestamp: f64,
    /// Monotonic sequence number within the context event log.
    pub sequence: f64,
    /// Context ID this message belongs to.
    pub context_id: String,
}

// ---------------------------------------------------------------------------
// Bridge functions
// ---------------------------------------------------------------------------

/// Creates a new SCP context.
///
/// # Arguments
///
/// * `identity_did` — The DID string of the context creator.
/// * `params_json` — Context creation parameters as a JSON string. Optional
///   fields: `ceiling` (string[]), `governance` (string), `memoryScope`
///   (string), `ttlSeconds` (number), `promotable` (boolean).
///
/// # Returns
///
/// A `Promise<NapiContextHandle>` in the `"active"` state.
///
/// # Errors
///
/// - Rejects with `SCP-VAL-7000` if `params_json` is malformed JSON.
/// - Rejects with `SCP-CTX-2000` if context creation fails.
#[napi]
pub async fn context_create(
    identity_did: String,
    params_json: String,
) -> napi::Result<NapiContextHandle> {
    let _params: serde_json::Value =
        serde_json::from_str(&params_json).map_err(|e| {
            NapiError::from(ScpNapiError::Validation {
                message: format!(
                    "params_json is not valid JSON: {e} — pass a JSON-encoded context parameters object"
                ),
                code: "SCP-VAL-7000".to_owned(),
            })
        })?;

    let context_id = format!("ctx-{}", Uuid::new_v4());
    let handle = NapiContextHandle {
        context_id,
        state: std::sync::Mutex::new(ContextState::Active),
        creator_did: identity_did,
    };
    increment_handle_count();
    Ok(handle)
}

/// Joins an existing SCP context.
///
/// # Errors
///
/// Rejects with `SCP-CTX-2013` if the context is not in `"active"` state.
#[napi]
pub async fn context_join(
    handle: &NapiContextHandle,
    identity_did: String,
) -> napi::Result<()> {
    let state_str = handle.current_state_str().map_err(NapiError::from)?;
    if state_str != "active" {
        return Err(ScpNapiError::Context {
            message: format!(
                "cannot join context in {state_str:?} state — context must be active"
            ),
            code: "SCP-CTX-2013".to_owned(),
        }
        .into());
    }
    let _ = identity_did;
    Ok(())
}

/// Leaves an SCP context.
///
/// # Errors
///
/// Rejects with `SCP-CTX-2015` if the context is not in `"active"` state.
#[napi]
pub async fn context_leave(
    handle: &NapiContextHandle,
    identity_did: String,
) -> napi::Result<()> {
    let state_str = handle.current_state_str().map_err(NapiError::from)?;
    if state_str != "active" {
        return Err(ScpNapiError::Context {
            message: format!(
                "cannot leave context in {state_str:?} state — context must be active"
            ),
            code: "SCP-CTX-2015".to_owned(),
        }
        .into());
    }
    let _ = identity_did;
    Ok(())
}

/// Closes an SCP context.
///
/// Transitions the context to `"closed"` state.
///
/// # Errors
///
/// Rejects with `SCP-CTX-2017` if the context is not in `"active"` state.
#[napi]
pub async fn context_close(
    handle: &NapiContextHandle,
    identity_did: String,
) -> napi::Result<()> {
    let state_str = handle.current_state_str().map_err(NapiError::from)?;
    if state_str != "active" {
        return Err(ScpNapiError::Context {
            message: format!(
                "cannot close context in {state_str:?} state — context must be active"
            ),
            code: "SCP-CTX-2017".to_owned(),
        }
        .into());
    }
    handle.set_closed().map_err(NapiError::from)?;
    let _ = identity_did;
    Ok(())
}

/// Sends a message to an SCP context.
///
/// # Errors
///
/// - Rejects with `SCP-CTX-2019` if the context is not `"active"`.
#[napi]
pub async fn context_send(
    handle: &NapiContextHandle,
    identity_did: String,
    payload: Vec<u8>,
) -> napi::Result<()> {
    let state_str = handle.current_state_str().map_err(NapiError::from)?;
    if state_str != "active" {
        return Err(ScpNapiError::Context {
            message: format!(
                "cannot send to context in {state_str:?} state — context must be active"
            ),
            code: "SCP-CTX-2019".to_owned(),
        }
        .into());
    }
    let _ = (identity_did, payload);
    Ok(())
}

/// Subscribes to incoming messages from an SCP context.
///
/// Registers a JS callback to receive incoming messages. The callback is
/// invoked with a [`NapiMessage`] object for each message. When the stream
/// ends (context closed or transport disconnected), the callback is invoked
/// with `null`.
///
/// The TypeScript SDK converts this callback to an `AsyncIterable<Message>`
/// via an internal queue adapter (ADR-022):
///
/// ```typescript
/// function contextReceive(handle: NapiContextHandle): AsyncIterable<NapiMessage> {
///   const queue: NapiMessage[] = [];
///   let resolve: (() => void) | null = null;
///   let done = false;
///
///   contextSubscribe(handle, identity_did, (msg) => {
///     if (msg === null) { done = true; resolve?.(); }
///     else { queue.push(msg); resolve?.(); resolve = null; }
///   });
///
///   return { [Symbol.asyncIterator]() { ... } };
/// }
/// ```
///
/// # Arguments
///
/// * `handle` — The context to subscribe to (must be `"active"`).
/// * `identity_did` — The DID of the subscribing identity.
/// * `on_message` — A JS callback invoked for each message, or `null` for
///   stream termination.
///
/// # Errors
///
/// Rejects with `SCP-CTX-2021` if the context is not in `"active"` state.
#[napi]
pub fn context_subscribe(
    handle: &NapiContextHandle,
    identity_did: String,
    on_message: napi::threadsafe_function::ThreadsafeFunction<Option<NapiMessage>>,
) -> napi::Result<()> {
    let state_str = handle.current_state_str().map_err(NapiError::from)?;
    if state_str != "active" {
        return Err(ScpNapiError::Context {
            message: format!(
                "cannot subscribe to context in {state_str:?} state — context must be active"
            ),
            code: "SCP-CTX-2021".to_owned(),
        }
        .into());
    }

    let _ = identity_did;

    // Signal stream completion — full transport wiring connects this callback
    // to the message pipeline in integration stories.
    on_message.call(
        Ok(None),
        napi::threadsafe_function::ThreadsafeFunctionCallMode::NonBlocking,
    );

    Ok(())
}
