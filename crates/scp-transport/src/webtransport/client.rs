//! WebTransport client adapter for browser/WASM environments.
//!
//! Implements [`TransportAdapter`] using the browser's `WebTransport` API per
//! spec section 10.15.2 and 10.15.3. Automatically falls back to `WebSocket`
//! when `WebTransport` is unavailable (Safari, older browsers) or when the
//! connection fails (relay doesn't support HTTP/3).
//!
//! # Connection model (spec section 10.15.2)
//!
//! 1. Browser opens `new WebTransport("https://<host>/scp/v1")` -- establishes
//!    HTTP/3 + WebTransport session.
//! 2. Same per-operation stream model as section 10.14.1 (QUIC).
//! 3. Server must support HTTP/3 and advertise via `Alt-Svc` header.
//!
//! # Fallback chain (spec section 10.15.3)
//!
//! The fallback is transparent to callers. When `WebTransport` is unavailable
//! or fails to connect, the adapter silently falls back to `WebSocket`. Callers
//! see a single [`TransportAdapter`] regardless of which transport is active.
//!
//! # WASM constraints
//!
//! This module is only compiled for `wasm32` targets. It uses `web-sys` and
//! `js-sys` for browser API access. All async operations use
//! `wasm-bindgen-futures` -- no tokio runtime is required.
//!
//! **`Send` + `Sync` bounds:** `JsValue` (and all web-sys types) is `!Send`
//! and `!Sync` because JavaScript values are confined to a single thread.
//! The [`TransportAdapter`] trait requires `Send + Sync` for use across
//! threads. On WASM, this is safe because the browser's main thread is the
//! only thread -- there is no concurrent access. The `Mutex<JsValue>` wrapper
//! satisfies the compiler without runtime overhead (WASM `Mutex` never
//! contends). If WASM threads (SharedArrayBuffer) are ever adopted, the
//! JS interop layer would need `postMessage`-based marshalling instead.
//!
//! See ADR-037 for the full specification.
//!
//! [`TransportAdapter`]: crate::TransportAdapter

use std::collections::HashMap;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use futures::channel::{mpsc, oneshot};
use futures::{SinkExt, Stream, StreamExt};
use scp_core::envelope::OuterEnvelope;
use wasm_bindgen::JsCast;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;

use super::fallback::{
    FallbackState, TransportKind, is_webtransport_available, relay_url_to_websocket,
    relay_url_to_webtransport,
};
use crate::error::TransportError;
use crate::native::protocol::{ClientMessage, RelayMessage};
use crate::quic::streams::{
    QuicClientFrame, QuicRelayFrame, decode_frame_from_buf, decode_relay_frame, encode_client_frame,
};
use crate::subscription::{
    MAX_TRANSPORT_SUBSCRIPTIONS, SubscriptionError, TransportSubscriptionMap,
};
use crate::traits::{BlobId, RoutingId, SubscriptionStream, TransportAdapter, TransportEvent};

/// A boxed, pinned, `Send`-safe future -- the return type for all
/// [`TransportAdapter`] methods to ensure the trait is dyn-compatible.
type BoxFuture<'a, T> = Pin<Box<dyn std::future::Future<Output = T> + Send + 'a>>;

/// Default blob TTL for PUBLISH operations (1 hour).
const DEFAULT_BLOB_TTL: u32 = 3600;

// ---------------------------------------------------------------------------
// Send+Sync wrapper for JsValue-containing types
// ---------------------------------------------------------------------------

/// Wrapper to make `!Send` JS types satisfy `Send + Sync`.
///
/// # Safety invariant
///
/// This is sound **only** on single-threaded WASM runtimes (the standard
/// `wasm32-unknown-unknown` target without the `atomics` target feature).
/// The wrapped `JsValue`-containing types are never accessed from multiple
/// threads because there is only one thread.
///
/// If WASM gains threading support (SharedArrayBuffer + `atomics` target
/// feature), this wrapper becomes unsound. The compile-time guard below
/// ensures a hard error in that case — the migration path is
/// `postMessage`-based marshalling between workers.
///
/// The wrapper exists solely to satisfy the `Send + Sync` bounds required
/// by [`TransportAdapter`]. On non-WASM targets the struct is not compiled.
#[cfg(all(target_arch = "wasm32", not(target_feature = "atomics")))]
struct SendSyncWrapper<T>(T);

// Fail compilation if someone enables WASM threads — the SendSyncWrapper
// would be unsound with concurrent access to JsValue.
#[cfg(all(target_arch = "wasm32", target_feature = "atomics"))]
compile_error!(
    "SendSyncWrapper is unsound with WASM threads (atomics target feature). \
     Replace with postMessage-based marshalling for cross-worker JsValue access."
);

// SAFETY: WASM without atomics is single-threaded — no concurrent access.
#[cfg(all(target_arch = "wasm32", not(target_feature = "atomics")))]
unsafe impl<T> Send for SendSyncWrapper<T> {}
// SAFETY: WASM without atomics is single-threaded — no concurrent access.
#[cfg(all(target_arch = "wasm32", not(target_feature = "atomics")))]
unsafe impl<T> Sync for SendSyncWrapper<T> {}

#[cfg(all(target_arch = "wasm32", not(target_feature = "atomics")))]
impl<T> SendSyncWrapper<T> {
    fn new(val: T) -> Self {
        Self(val)
    }

    fn inner(&self) -> &T {
        &self.0
    }
}

// ---------------------------------------------------------------------------
// WebTransportAdapter
// ---------------------------------------------------------------------------

/// Browser-side WebTransport adapter with WebSocket fallback.
///
/// Implements [`TransportAdapter`] for WASM targets per spec section 10.15.
/// Attempts `WebTransport` first, falls back to `WebSocket` if unavailable
/// or if the connection fails. The fallback is invisible to callers.
///
/// # Construction
///
/// ```rust,ignore
/// let adapter = WebTransportAdapter::new("wss://relay.example.com/scp/v1")?;
/// adapter.connect().await?;
/// ```
///
/// # Thread safety
///
/// WASM is single-threaded. The adapter uses `Arc<Mutex<FallbackState>>` to
/// satisfy [`TransportAdapter`]'s `Send + Sync` bounds. The mutex never
/// contends on WASM's single-threaded runtime.
pub struct WebTransportAdapter {
    /// The relay URL provided at construction (wss:// or https://).
    relay_url: String,

    /// The computed WebTransport URL (https://<host>/scp/v1).
    webtransport_url: String,

    /// The computed WebSocket fallback URL (wss://<host>/scp/v1).
    websocket_url: String,

    /// Current fallback state -- tracks which transport is active.
    /// Uses `Arc<Mutex<>>` to satisfy `Send + Sync` bounds required by
    /// `TransportAdapter`. On WASM this never contends (single-threaded).
    state: Arc<Mutex<FallbackState>>,

    /// Active WebTransport session handle, wrapped for Send+Sync.
    wt_session: Arc<Mutex<Option<SendSyncWrapper<web_sys::WebTransport>>>>,

    /// Active WebSocket handle, wrapped for Send+Sync.
    ws_handle: Arc<Mutex<Option<SendSyncWrapper<web_sys::WebSocket>>>>,

    /// Active WebTransport (HTTP/3) bidi-stream handles keyed by routing_id.
    /// Used by the WT-HTTP/3 subscribe path; the lifecycle re-architecture
    /// is tracked in a follow-up issue. The minimal cap+duplicate guard in
    /// `subscribe()` uses a check-do-check pattern around this map.
    #[cfg(target_arch = "wasm32")]
    wt_bidi_handles:
        Arc<Mutex<HashMap<[u8; 32], SendSyncWrapper<web_sys::WebTransportBidirectionalStream>>>>,

    /// WebSocket subscription routing: routing_id -> event sender.
    /// The WebSocket onmessage handler dispatches BLOB messages to the
    /// appropriate subscription sender based on the routing_id.
    subscriptions: Arc<TransportSubscriptionMap<mpsc::UnboundedSender<TransportEvent>>>,

    /// Pending request-response correlation for WebSocket path.
    /// Maps ref_id -> oneshot sender for the response.
    pending_requests: Arc<Mutex<HashMap<String, oneshot::Sender<RelayMessage>>>>,

    /// Maps subscribe ref_id -> routing_id so that `backfill_complete` events
    /// (which carry only a ref_id) can be routed to the correct subscription
    /// instead of being broadcast to all subscribers.
    subscribe_ref_ids: Arc<Mutex<HashMap<String, [u8; 32]>>>,

    /// Monotonic counter for WebSocket ref_id correlation.
    next_ref_id: Arc<Mutex<u64>>,

    /// Stored WebSocket event closures. Held here so they are dropped when
    /// the adapter is dropped or when a reconnection replaces the WebSocket,
    /// preventing the memory leak caused by `Closure::forget()`.
    ///
    /// Each entry is a type-erased `Closure<dyn FnMut(...)>` wrapped for
    /// Send+Sync (safe on single-threaded WASM).
    #[cfg(target_arch = "wasm32")]
    ws_closures: Arc<Mutex<Vec<SendSyncWrapper<JsValue>>>>,
}

impl std::fmt::Debug for WebTransportAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let state = self
            .state
            .lock()
            .map_or_else(|_| FallbackState::Disconnected, |g| g.clone());
        f.debug_struct("WebTransportAdapter")
            .field("relay_url", &self.relay_url)
            .field("state", &state)
            .finish()
    }
}

impl WebTransportAdapter {
    /// Creates a new `WebTransportAdapter` for the given relay URL.
    ///
    /// The URL must use `wss://` or `https://` scheme (TLS required per spec
    /// section 9.13). The adapter computes both the WebTransport and WebSocket
    /// endpoint URLs from the relay URL.
    ///
    /// Does not connect immediately -- call [`connect`](Self::connect) to
    /// establish the transport connection with fallback.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::ConnectionFailed`] if the URL scheme is not
    /// `wss://` or `https://`.
    pub fn new(relay_url: &str) -> Result<Self, TransportError> {
        let webtransport_url = relay_url_to_webtransport(relay_url)?;
        let websocket_url = relay_url_to_websocket(relay_url)?;

        Ok(Self {
            relay_url: relay_url.to_owned(),
            webtransport_url,
            websocket_url,
            state: Arc::new(Mutex::new(FallbackState::Disconnected)),
            wt_session: Arc::new(Mutex::new(None)),
            ws_handle: Arc::new(Mutex::new(None)),
            #[cfg(target_arch = "wasm32")]
            wt_bidi_handles: Arc::new(Mutex::new(HashMap::new())),
            subscriptions: Arc::new(TransportSubscriptionMap::new()),
            pending_requests: Arc::new(Mutex::new(HashMap::new())),
            subscribe_ref_ids: Arc::new(Mutex::new(HashMap::new())),
            next_ref_id: Arc::new(Mutex::new(1)),
            #[cfg(target_arch = "wasm32")]
            ws_closures: Arc::new(Mutex::new(Vec::new())),
        })
    }

    /// Returns the current fallback state.
    #[must_use]
    pub fn fallback_state(&self) -> FallbackState {
        self.state
            .lock()
            .map_or_else(|_| FallbackState::Disconnected, |g| g.clone())
    }

    /// Returns which transport is currently active, or `None` if not connected.
    #[must_use]
    pub fn active_transport(&self) -> Option<TransportKind> {
        self.state.lock().ok().and_then(|g| g.transport_kind())
    }

    /// Returns the relay URL this adapter was constructed with.
    #[must_use]
    pub fn relay_url(&self) -> &str {
        &self.relay_url
    }

    /// Sets the fallback state. Silently ignores poisoned mutexes (should
    /// not occur on WASM's single-threaded runtime).
    fn set_state(&self, new_state: FallbackState) {
        if let Ok(mut guard) = self.state.lock() {
            *guard = new_state;
        }
    }

    /// Allocates the next ref_id for WebSocket request correlation.
    fn next_ref_id(&self) -> String {
        let mut guard = self.next_ref_id.lock().unwrap_or_else(|e| e.into_inner());
        let id = *guard;
        *guard = id.wrapping_add(1);
        id.to_string()
    }

    /// Attempts to connect using the fallback chain (spec section 10.15.3).
    ///
    /// 1. If `WebTransport` API is available, attempt WebTransport connection.
    /// 2. If WebTransport fails or is unavailable, fall back to WebSocket.
    /// 3. If both fail, return an error.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::ConnectionFailed`] if both WebTransport and
    /// WebSocket fail to connect.
    pub async fn connect(&self) -> Result<TransportKind, TransportError> {
        // Step 1: Check WebTransport API availability
        if is_webtransport_available() {
            self.set_state(FallbackState::AttemptingWebTransport);

            // Attempt WebTransport connection
            match self.attempt_webtransport().await {
                Ok(()) => {
                    self.set_state(FallbackState::Connected(TransportKind::WebTransport));
                    tracing::info!(
                        relay_url = %self.relay_url,
                        transport = "WebTransport",
                        "connected via WebTransport"
                    );
                    return Ok(TransportKind::WebTransport);
                }
                Err(wt_err) => {
                    tracing::warn!(
                        relay_url = %self.relay_url,
                        error = %wt_err,
                        "WebTransport connection failed, falling back to WebSocket"
                    );
                    // Fall through to WebSocket
                }
            }
        } else {
            tracing::info!(
                relay_url = %self.relay_url,
                "WebTransport API not available, using WebSocket"
            );
        }

        // Step 2: Fall back to WebSocket
        self.set_state(FallbackState::AttemptingWebSocket);

        match self.attempt_websocket().await {
            Ok(()) => {
                self.set_state(FallbackState::Connected(TransportKind::WebSocket));
                tracing::info!(
                    relay_url = %self.relay_url,
                    transport = "WebSocket",
                    "connected via WebSocket (fallback)"
                );
                Ok(TransportKind::WebSocket)
            }
            Err(ws_err) => {
                let msg = format!(
                    "all transports failed for {}: WebSocket error: {ws_err}",
                    self.relay_url
                );
                self.set_state(FallbackState::Failed(msg.clone()));
                Err(TransportError::ConnectionFailed(msg))
            }
        }
    }

    /// Attempts a WebTransport connection to the relay.
    ///
    /// Uses the browser's `WebTransport` API via `web-sys` bindings.
    /// Opens `new WebTransport(url)` and awaits the `.ready` promise.
    /// On success, stores the session handle for stream creation.
    async fn attempt_webtransport(&self) -> Result<(), TransportError> {
        let url = &self.webtransport_url;

        // Create WebTransport options (default -- no custom certificates in
        // browser context; the browser's TLS stack validates the server cert).
        let options = web_sys::WebTransportOptions::new();

        // Construct WebTransport session: `new WebTransport(url, options)`
        let wt = web_sys::WebTransport::new_with_options(url, &options).map_err(|e| {
            TransportError::ConnectionFailed(format!(
                "WebTransport constructor failed: {}",
                js_error_message(&e)
            ))
        })?;

        // Await the `.ready` promise -- resolves when the HTTP/3 session is
        // established with the server.
        JsFuture::from(wt.ready()).await.map_err(|e| {
            TransportError::ConnectionFailed(format!(
                "WebTransport .ready() failed: {}",
                js_error_message(&e)
            ))
        })?;

        // Store the WebTransport session handle for later stream creation.
        if let Ok(mut guard) = self.wt_session.lock() {
            *guard = Some(SendSyncWrapper::new(wt));
        }

        Ok(())
    }

    /// Attempts a WebSocket connection to the relay.
    ///
    /// Uses the browser's `WebSocket` API. Creates `new WebSocket(url)`,
    /// sets binary type to `ArrayBuffer`, and awaits the `onopen` event.
    /// Sets up the `onmessage` handler to dispatch received messages to
    /// pending requests (by ref_id) and subscriptions (by routing_id).
    async fn attempt_websocket(&self) -> Result<(), TransportError> {
        let url = &self.websocket_url;

        // Clear old closures from any previous WebSocket connection to free
        // the leaked JS closures. New closures are stored below.
        if let Ok(mut guard) = self.ws_closures.lock() {
            guard.clear();
        }

        // Create WebSocket: `new WebSocket(url)`
        let ws = web_sys::WebSocket::new(url).map_err(|e| {
            TransportError::ConnectionFailed(format!(
                "WebSocket constructor failed: {}",
                js_error_message(&e)
            ))
        })?;

        // Set binary type to ArrayBuffer for efficient binary frame handling.
        ws.set_binary_type(web_sys::BinaryType::Arraybuffer);

        // Await `onopen` using a oneshot channel.
        let (open_tx, open_rx) = oneshot::channel::<Result<(), String>>();
        let open_tx = Arc::new(Mutex::new(Some(open_tx)));

        // Set up onopen handler.
        let open_tx_clone = Arc::clone(&open_tx);
        let onopen = Closure::wrap(Box::new(move |_: JsValue| {
            if let Ok(mut guard) = open_tx_clone.lock() {
                if let Some(tx) = guard.take() {
                    let _ = tx.send(Ok(()));
                }
            }
        }) as Box<dyn FnMut(JsValue)>);
        ws.set_onopen(Some(onopen.as_ref().unchecked_ref()));

        // Set up onerror handler (fires before onopen if connection fails).
        let open_tx_err = Arc::clone(&open_tx);
        let onerror = Closure::wrap(Box::new(move |e: web_sys::ErrorEvent| {
            let msg = e.message();
            if let Ok(mut guard) = open_tx_err.lock() {
                if let Some(tx) = guard.take() {
                    let _ = tx.send(Err(msg));
                }
            }
        }) as Box<dyn FnMut(web_sys::ErrorEvent)>);
        ws.set_onerror(Some(onerror.as_ref().unchecked_ref()));

        // Set up onmessage handler to dispatch incoming relay messages.
        let subscriptions = Arc::clone(&self.subscriptions);
        let pending_requests = Arc::clone(&self.pending_requests);
        let subscribe_ref_ids = Arc::clone(&self.subscribe_ref_ids);
        let onmessage = Closure::wrap(Box::new(move |e: web_sys::MessageEvent| {
            // Extract binary data from the MessageEvent.
            let data = e.data();
            let bytes = if data.is_instance_of::<js_sys::ArrayBuffer>() {
                let arr = js_sys::Uint8Array::new(&data);
                let mut buf = vec![0u8; arr.length() as usize];
                arr.copy_to(&mut buf);
                buf
            } else {
                // Non-binary messages are unexpected; ignore.
                return;
            };

            // Deserialize as RelayMessage (MessagePack). The relay's bytes
            // are attacker-controlled; deliberately do not surface the
            // serde error in any user-visible string -- it can include
            // byte excerpts in `Display`.
            let relay_msg = match RelayMessage::from_bytes(&bytes) {
                Ok(msg) => msg,
                Err(_) => {
                    tracing::warn!("relay message deserialization failed");
                    return;
                }
            };

            // Dispatch based on message type.
            dispatch_relay_message(
                &relay_msg,
                &subscriptions,
                &pending_requests,
                &subscribe_ref_ids,
            );
        }) as Box<dyn FnMut(web_sys::MessageEvent)>);
        ws.set_onmessage(Some(onmessage.as_ref().unchecked_ref()));

        // Store closures so they are dropped on reconnect instead of leaked
        // via Closure::forget(). The closures must outlive the WebSocket,
        // which is guaranteed because both are stored on the adapter.
        if let Ok(mut guard) = self.ws_closures.lock() {
            // Convert each typed Closure into a JsValue for type-erased storage.
            guard.push(SendSyncWrapper::new(onopen.into_js_value()));
            guard.push(SendSyncWrapper::new(onerror.into_js_value()));
            guard.push(SendSyncWrapper::new(onmessage.into_js_value()));
        }

        // Wait for onopen or onerror.
        let result = open_rx.await.map_err(|_| {
            TransportError::ConnectionFailed("WebSocket open channel cancelled".to_owned())
        })?;

        result.map_err(|e| {
            TransportError::ConnectionFailed(format!("WebSocket connection failed: {e}"))
        })?;

        // Store the WebSocket handle.
        if let Ok(mut guard) = self.ws_handle.lock() {
            *guard = Some(SendSyncWrapper::new(ws));
        }

        Ok(())
    }

    /// Returns the current state, cloned. Returns `Disconnected` if the
    /// mutex is poisoned (should not occur on WASM).
    fn current_state(&self) -> FallbackState {
        self.state
            .lock()
            .map_or_else(|_| FallbackState::Disconnected, |g| g.clone())
    }

    // -----------------------------------------------------------------------
    // WebTransport stream helpers
    // -----------------------------------------------------------------------

    /// Opens a bidirectional WebTransport stream, sends a client frame,
    /// and reads the response frame. Closes the stream after the response.
    ///
    /// This implements the per-operation stream model from section 10.14.1:
    /// open bidi -> send frame -> receive response -> close.
    async fn wt_request_response(
        &self,
        frame: &QuicClientFrame,
    ) -> Result<QuicRelayFrame, TransportError> {
        let wt = {
            let guard = self
                .wt_session
                .lock()
                .map_err(|_| TransportError::NotConnected)?;
            match guard.as_ref() {
                Some(wrapper) => wrapper.inner().clone(),
                None => return Err(TransportError::NotConnected),
            }
        };

        // Open a bidirectional stream.
        let bidi_promise = wt.create_bidirectional_stream();
        let bidi_js = JsFuture::from(bidi_promise).await.map_err(|e| {
            TransportError::SendFailed(format!(
                "failed to open bidi stream: {}",
                js_error_message(&e)
            ))
        })?;
        let bidi: web_sys::WebTransportBidirectionalStream = bidi_js.unchecked_into();

        // Encode the client frame as length-prefixed MessagePack.
        let wire_bytes = encode_client_frame(frame)?;

        // Write to the send stream.
        let writable = bidi.writable();
        let writer = writable.get_writer().map_err(|e| {
            TransportError::SendFailed(format!("failed to get writer: {}", js_error_message(&e)))
        })?;
        let js_data = js_sys::Uint8Array::from(wire_bytes.as_slice());
        JsFuture::from(writer.write_with_chunk(&js_data))
            .await
            .map_err(|e| {
                TransportError::SendFailed(format!("write failed: {}", js_error_message(&e)))
            })?;
        // Close the writer to signal we're done sending.
        JsFuture::from(writer.close()).await.map_err(|e| {
            TransportError::SendFailed(format!("failed to close writer: {}", js_error_message(&e)))
        })?;

        // Read the response from the readable stream.
        // Bound the read buffer to MAX_FRAME_SIZE + LENGTH_PREFIX_SIZE to
        // prevent unbounded memory growth from a malicious relay.
        let max_read_buf = (MAX_FRAME_SIZE as usize) + LENGTH_PREFIX_SIZE;
        let readable = bidi.readable();
        let reader = readable
            .get_reader()
            .unchecked_into::<web_sys::ReadableStreamDefaultReader>();
        let mut buf = Vec::new();

        loop {
            let result = JsFuture::from(reader.read()).await.map_err(|e| {
                TransportError::ProtocolError(format!(
                    "failed to read from stream: {}",
                    js_error_message(&e)
                ))
            })?;

            let done =
                js_sys::Reflect::get(&result, &JsValue::from_str("done")).unwrap_or(JsValue::TRUE);
            let value = js_sys::Reflect::get(&result, &JsValue::from_str("value"))
                .unwrap_or(JsValue::UNDEFINED);

            if !value.is_undefined() && !value.is_null() {
                let chunk = js_sys::Uint8Array::new(&value);
                let chunk_len = chunk.length() as usize;
                if buf.len() + chunk_len > max_read_buf {
                    return Err(TransportError::ProtocolError(format!(
                        "response exceeds maximum frame size ({max_read_buf} bytes)"
                    )));
                }
                let mut chunk_buf = vec![0u8; chunk_len];
                chunk.copy_to(&mut chunk_buf);
                buf.extend_from_slice(&chunk_buf);
            }

            if done.is_truthy() {
                break;
            }
        }

        // Decode the response frame (length-prefixed MessagePack).
        let (_, payload) = decode_frame_from_buf(&buf)?
            .ok_or_else(|| TransportError::ProtocolError("incomplete response frame".to_owned()))?;

        decode_relay_frame(&payload)
    }

    /// Opens a long-lived bidirectional WebTransport stream for subscriptions.
    /// Sends the SUBSCRIBE frame and returns a stream that yields events
    /// from the incoming BLOB/EVENT frames until the stream closes.
    async fn wt_subscribe_stream(
        &self,
        routing_id: [u8; 32],
        since: Option<u64>,
    ) -> Result<
        (
            SubscriptionStream,
            SendSyncWrapper<web_sys::WebTransportBidirectionalStream>,
        ),
        TransportError,
    > {
        let wt = {
            let guard = self
                .wt_session
                .lock()
                .map_err(|_| TransportError::NotConnected)?;
            match guard.as_ref() {
                Some(wrapper) => wrapper.inner().clone(),
                None => return Err(TransportError::NotConnected),
            }
        };

        // Open a bidirectional stream for the subscription.
        let bidi_promise = wt.create_bidirectional_stream();
        let bidi_js = JsFuture::from(bidi_promise).await.map_err(|e| {
            TransportError::SubscriptionFailed(format!(
                "failed to open bidi stream: {}",
                js_error_message(&e)
            ))
        })?;
        let bidi: web_sys::WebTransportBidirectionalStream = bidi_js.unchecked_into();

        // Send the SUBSCRIBE frame.
        let frame = QuicClientFrame::Subscribe { routing_id, since };
        let wire_bytes = encode_client_frame(&frame)?;

        let writable = bidi.writable();
        let writer = writable.get_writer().map_err(|e| {
            TransportError::SubscriptionFailed(format!(
                "failed to get writer: {}",
                js_error_message(&e)
            ))
        })?;
        let js_data = js_sys::Uint8Array::from(wire_bytes.as_slice());
        JsFuture::from(writer.write_with_chunk(&js_data))
            .await
            .map_err(|e| {
                TransportError::SubscriptionFailed(format!(
                    "write failed: {}",
                    js_error_message(&e)
                ))
            })?;
        // Release the writer lock but keep the stream open for sending
        // UNSUBSCRIBE later.
        writer.release_lock();

        // Create a channel to feed events from the readable stream.
        let (tx, rx) = mpsc::unbounded::<TransportEvent>();

        // Spawn a background task to read incoming frames from the
        // subscription stream and push them to the channel.
        let readable = bidi.readable();
        let max_buf = (MAX_FRAME_SIZE as usize) + LENGTH_PREFIX_SIZE;
        wasm_bindgen_futures::spawn_local(async move {
            let reader = readable
                .get_reader()
                .unchecked_into::<web_sys::ReadableStreamDefaultReader>();
            let mut read_buf = Vec::new();
            let mut tx = tx;

            loop {
                let result = match JsFuture::from(reader.read()).await {
                    Ok(r) => r,
                    Err(_) => break,
                };

                let done = js_sys::Reflect::get(&result, &JsValue::from_str("done"))
                    .unwrap_or(JsValue::TRUE);
                let value = js_sys::Reflect::get(&result, &JsValue::from_str("value"))
                    .unwrap_or(JsValue::UNDEFINED);

                if !value.is_undefined() && !value.is_null() {
                    let chunk = js_sys::Uint8Array::new(&value);
                    let chunk_len = chunk.length() as usize;
                    // Cap buffer size to prevent unbounded growth from
                    // a malicious relay. Processed frames are drained
                    // below, so the buffer only grows if a single frame
                    // exceeds MAX_FRAME_SIZE.
                    if read_buf.len() + chunk_len > max_buf {
                        let _ = tx
                            .send(TransportEvent::Error(TransportError::ProtocolError(
                                "subscription frame exceeds maximum size".to_owned(),
                            )))
                            .await;
                        break;
                    }
                    let mut chunk_buf = vec![0u8; chunk_len];
                    chunk.copy_to(&mut chunk_buf);
                    read_buf.extend_from_slice(&chunk_buf);

                    // Process all complete frames in the buffer.
                    while let Ok(Some((consumed, payload))) = decode_frame_from_buf(&read_buf) {
                        let drained: Vec<u8> = read_buf.drain(..consumed).collect();
                        let _ = drained; // consumed bytes
                        if let Ok(relay_frame) = decode_relay_frame(&payload) {
                            let event = relay_frame_to_event(relay_frame);
                            if let Some(ev) = event {
                                if tx.send(ev).await.is_err() {
                                    return; // Receiver dropped
                                }
                            }
                        }
                    }
                }

                if done.is_truthy() {
                    let _ = tx
                        .send(TransportEvent::Terminated {
                            reason: "WebTransport stream closed".to_owned(),
                        })
                        .await;
                    break;
                }
            }
        });

        let stream: SubscriptionStream = Box::pin(rx);
        Ok((stream, SendSyncWrapper::new(bidi)))
    }

    // -----------------------------------------------------------------------
    // WebSocket helpers
    // -----------------------------------------------------------------------

    /// Sends a `ClientMessage` over WebSocket and awaits the correlated
    /// response (matched by ref_id).
    async fn ws_request_response(
        &self,
        msg: ClientMessage,
        ref_id: String,
    ) -> Result<RelayMessage, TransportError> {
        // Register a pending request for this ref_id.
        let (tx, rx) = oneshot::channel::<RelayMessage>();
        {
            let mut guard = self
                .pending_requests
                .lock()
                .map_err(|_| TransportError::NotConnected)?;
            guard.insert(ref_id.clone(), tx);
        }

        // Serialize and send the message.
        let bytes = msg
            .to_bytes()
            .map_err(|e| TransportError::SendFailed(e.to_string()))?;

        {
            let guard = self
                .ws_handle
                .lock()
                .map_err(|_| TransportError::NotConnected)?;
            let ws = guard.as_ref().ok_or(TransportError::NotConnected)?.inner();
            ws.send_with_u8_array(&bytes).map_err(|e| {
                TransportError::SendFailed(format!(
                    "WebSocket send failed: {}",
                    js_error_message(&e)
                ))
            })?;
        }

        // Await the correlated response.
        rx.await.map_err(|_| {
            // Clean up the pending request on cancellation.
            if let Ok(mut guard) = self.pending_requests.lock() {
                guard.remove(&ref_id);
            }
            TransportError::ConnectionFailed("response channel cancelled".to_owned())
        })
    }

    /// Sends a fire-and-forget `ClientMessage` over WebSocket (no response expected).
    fn ws_send_fire_and_forget(&self, msg: &ClientMessage) -> Result<(), TransportError> {
        let bytes = msg
            .to_bytes()
            .map_err(|e| TransportError::SendFailed(e.to_string()))?;

        let guard = self
            .ws_handle
            .lock()
            .map_err(|_| TransportError::NotConnected)?;
        let ws = guard.as_ref().ok_or(TransportError::NotConnected)?.inner();
        ws.send_with_u8_array(&bytes).map_err(|e| {
            TransportError::SendFailed(format!("WebSocket send failed: {}", js_error_message(&e)))
        })
    }
}

// ---------------------------------------------------------------------------
// TransportAdapter implementation
// ---------------------------------------------------------------------------

impl TransportAdapter for WebTransportAdapter {
    /// Sends an outer envelope to the network.
    ///
    /// Routes based on the envelope's `routing_id`. Dispatches to the active
    /// transport (WebTransport or WebSocket). Same wire format (ADR-004
    /// MessagePack) regardless of underlying transport.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::NotConnected`] if no transport is active.
    fn send(&self, envelope: &OuterEnvelope) -> BoxFuture<'_, Result<BlobId, TransportError>> {
        let state = self.current_state();
        let envelope = envelope.clone();

        Box::pin(async move {
            // Serialize envelope to blob bytes.
            let blob = envelope
                .to_bytes()
                .map_err(|e| TransportError::SendFailed(e.to_string()))?;

            let routing_id: [u8; 32] = envelope.routing_id.as_slice().try_into().map_err(|_| {
                TransportError::SendFailed(format!(
                    "invalid routing_id length: expected 32, got {}",
                    envelope.routing_id.len()
                ))
            })?;

            let recipient_hint: Option<[u8; 32]> = envelope
                .recipient_hint
                .as_ref()
                .map(|hint| {
                    hint.as_slice().try_into().map_err(|_| {
                        TransportError::SendFailed(format!(
                            "invalid recipient_hint length: expected 32, got {}",
                            hint.len()
                        ))
                    })
                })
                .transpose()?;

            match state {
                FallbackState::Connected(TransportKind::WebTransport) => {
                    // WebTransport path: open bidi stream, send PUBLISH frame,
                    // await ACK with blob_id, close stream.
                    let frame = QuicClientFrame::Publish {
                        routing_id,
                        recipient_hint,
                        blob_ttl: envelope.blob_ttl,
                        blob,
                    };

                    let response = self.wt_request_response(&frame).await?;

                    match response {
                        QuicRelayFrame::Ok {
                            blob_id: Some(id), ..
                        } => Ok(BlobId::new(id)),
                        QuicRelayFrame::Ok { blob_id: None, .. } => {
                            Ok(BlobId::from_sha256(&envelope.routing_id))
                        }
                        QuicRelayFrame::Err { code, msg } => Err(TransportError::SendFailed(
                            format!("relay error {code}: {msg}"),
                        )),
                        _ => Err(TransportError::ProtocolError(
                            "unexpected response to PUBLISH".to_owned(),
                        )),
                    }
                }
                FallbackState::Connected(TransportKind::WebSocket) => {
                    // WebSocket path: serialize ClientMessage with ref_id,
                    // send over WebSocket, correlate response by ref_id.
                    let ref_id = self.next_ref_id();

                    let msg = ClientMessage::Publish {
                        ref_id: Some(ref_id.clone()),
                        routing_id,
                        recipient_hint,
                        blob_ttl: envelope.blob_ttl,
                        blob,
                    };

                    let response = self.ws_request_response(msg, ref_id).await?;

                    match response {
                        RelayMessage::Ok {
                            blob_id: Some(id), ..
                        } => Ok(BlobId::new(id)),
                        RelayMessage::Ok { blob_id: None, .. } => {
                            Ok(BlobId::from_sha256(&envelope.routing_id))
                        }
                        RelayMessage::Err { code, msg, .. } => Err(TransportError::SendFailed(
                            format!("relay error {code}: {msg}"),
                        )),
                        _ => Err(TransportError::ProtocolError(
                            "unexpected response to PUBLISH".to_owned(),
                        )),
                    }
                }
                _ => Err(TransportError::NotConnected),
            }
        })
    }

    /// Subscribes to envelopes for a given routing ID.
    ///
    /// Returns a stream of [`TransportEvent`]s. If `since` is provided,
    /// backfills with stored envelopes newer than that timestamp. Dispatches
    /// to the active transport.
    ///
    /// For WebTransport: opens a long-lived bidirectional stream (same model
    /// as section 10.14.1 QUIC SUBSCRIBE).
    ///
    /// For WebSocket: sends SUBSCRIBE frame and streams events via the
    /// shared WebSocket connection (same as native relay, ADR-004).
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::NotConnected`] if no transport is active.
    fn subscribe(
        &self,
        routing_id: &RoutingId,
        since: Option<u64>,
    ) -> BoxFuture<'_, Result<SubscriptionStream, TransportError>> {
        let state = self.current_state();
        let routing_id_bytes = *routing_id.as_bytes();
        let since = since;

        Box::pin(async move {
            match state {
                FallbackState::Connected(TransportKind::WebTransport) => {
                    // Check-do-check: race semantics under concurrent
                    // subscribe/unsubscribe interleaving are documented as
                    // known limitations; see the follow-up tracking issue
                    // for the planned uniform lifecycle contract.
                    {
                        let guard = self.wt_bidi_handles.lock().map_err(|_| {
                            TransportError::ProtocolError(
                                "wt_bidi_handles lock poisoned".to_owned(),
                            )
                        })?;
                        if guard.contains_key(&routing_id_bytes) {
                            return Err(TransportError::SubscriptionFailed(
                                "already subscribed to this routing_id".to_owned(),
                            ));
                        }
                        if guard.len() >= MAX_TRANSPORT_SUBSCRIPTIONS {
                            return Err(TransportError::SubscriptionFailed(format!(
                                "subscription map full (max {MAX_TRANSPORT_SUBSCRIPTIONS} entries)"
                            )));
                        }
                    }

                    let (stream, bidi_handle) =
                        self.wt_subscribe_stream(routing_id_bytes, since).await?;

                    {
                        let mut guard = self.wt_bidi_handles.lock().map_err(|_| {
                            TransportError::ProtocolError(
                                "wt_bidi_handles lock poisoned".to_owned(),
                            )
                        })?;
                        if guard.contains_key(&routing_id_bytes) {
                            drop(guard);
                            if let Ok(writer) = bidi_handle.inner().writable().get_writer() {
                                let _ = writer.close();
                            }
                            return Err(TransportError::SubscriptionFailed(
                                "concurrent subscribe completed for this routing_id".to_owned(),
                            ));
                        }
                        if guard.len() >= MAX_TRANSPORT_SUBSCRIPTIONS {
                            drop(guard);
                            if let Ok(writer) = bidi_handle.inner().writable().get_writer() {
                                let _ = writer.close();
                            }
                            return Err(TransportError::SubscriptionFailed(format!(
                                "subscription map full (max {MAX_TRANSPORT_SUBSCRIPTIONS} entries)"
                            )));
                        }
                        guard.insert(routing_id_bytes, bidi_handle);
                    }

                    Ok(stream)
                }
                FallbackState::Connected(TransportKind::WebSocket) => {
                    // WebSocket path: send SUBSCRIBE frame, register a
                    // subscription receiver for this routing_id, return stream.
                    let ref_id = self.next_ref_id();

                    let msg = ClientMessage::Subscribe {
                        ref_id: Some(ref_id.clone()),
                        routing_id: routing_id_bytes,
                        since,
                    };

                    // Create subscription channel.
                    let (tx, rx) = mpsc::unbounded::<TransportEvent>();

                    // Register the subscription before sending so we don't miss
                    // messages between send and registration. If a subscription
                    // already exists for this routing_id, reject the request
                    // to prevent clobbering the existing subscription's sender.
                    self.subscriptions
                        .insert(RoutingId::new(routing_id_bytes), tx)
                        .map_err(|e| match e {
                            SubscriptionError::Duplicate => TransportError::SubscriptionFailed(
                                "already subscribed to this routing_id".to_owned(),
                            ),
                            SubscriptionError::CapacityExceeded(n) => {
                                TransportError::SubscriptionFailed(format!(
                                    "subscription map full ({n} entries)"
                                ))
                            }
                        })?;

                    // Register ref_id -> routing_id mapping so that
                    // backfill_complete events can be routed to this specific
                    // subscription instead of broadcast to all.
                    if let Ok(mut guard) = self.subscribe_ref_ids.lock() {
                        guard.insert(ref_id.clone(), routing_id_bytes);
                    }

                    // Send the SUBSCRIBE frame. We use fire-and-forget here
                    // because the relay responds with OK followed by streaming
                    // BLOBs -- those are handled by the onmessage handler.
                    self.ws_send_fire_and_forget(&msg)?;

                    let stream: SubscriptionStream = Box::pin(rx);
                    Ok(stream)
                }
                _ => Err(TransportError::NotConnected),
            }
        })
    }

    /// Unsubscribes from a routing ID.
    ///
    /// For WebTransport: closes the subscription's bidirectional stream.
    /// For WebSocket: sends UNSUBSCRIBE frame.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::NotConnected`] if no transport is active.
    fn unsubscribe(&self, routing_id: &RoutingId) -> BoxFuture<'_, Result<(), TransportError>> {
        let state = self.current_state();
        let routing_id_bytes = *routing_id.as_bytes();

        Box::pin(async move {
            match state {
                FallbackState::Connected(TransportKind::WebTransport) => {
                    let removed_handle = self
                        .wt_bidi_handles
                        .lock()
                        .ok()
                        .and_then(|mut guard| guard.remove(&routing_id_bytes));

                    // Close the writable stream outside the lock to signal
                    // the relay that this subscription is done. The relay
                    // recognizes closing the writer as an implicit
                    // unsubscribe per the QUIC stream-per-operation model.
                    if let Some(handle) = removed_handle
                        && let Ok(writer) = handle.inner().writable().get_writer()
                    {
                        let _ = writer.close();
                    }

                    // Remove from local subscriptions (the background reader
                    // task will exit when the sender is dropped).
                    self.subscriptions.remove(&RoutingId::new(routing_id_bytes));

                    Ok(())
                }
                FallbackState::Connected(TransportKind::WebSocket) => {
                    // WebSocket path: send UNSUBSCRIBE frame and remove
                    // the subscription from the local map.
                    let ref_id = self.next_ref_id();

                    let msg = ClientMessage::Unsubscribe {
                        ref_id: Some(ref_id),
                        routing_id: routing_id_bytes,
                    };

                    self.ws_send_fire_and_forget(&msg)?;

                    // Remove from local subscriptions.
                    self.subscriptions.remove(&RoutingId::new(routing_id_bytes));

                    Ok(())
                }
                _ => Err(TransportError::NotConnected),
            }
        })
    }

    /// Queries stored envelopes matching a routing ID.
    ///
    /// For WebTransport: opens a bidirectional stream, sends QUERY, collects
    /// results + query_complete, closes stream (same model as section 10.14.1).
    ///
    /// For WebSocket: sends QUERY frame, collects results matched by ref_id.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::NotConnected`] if no transport is active.
    fn query(
        &self,
        routing_id: &RoutingId,
        since: Option<u64>,
    ) -> BoxFuture<'_, Result<Vec<OuterEnvelope>, TransportError>> {
        let state = self.current_state();
        let routing_id_bytes = *routing_id.as_bytes();

        Box::pin(async move {
            match state {
                FallbackState::Connected(TransportKind::WebTransport) => {
                    // WebTransport path: open bidi stream, send QUERY frame,
                    // collect BLOB results until query_complete EVENT, close.
                    let wt = {
                        let guard = self
                            .wt_session
                            .lock()
                            .map_err(|_| TransportError::NotConnected)?;
                        match guard.as_ref() {
                            Some(wrapper) => wrapper.inner().clone(),
                            None => return Err(TransportError::NotConnected),
                        }
                    };

                    // Open a bidirectional stream.
                    let bidi_promise = wt.create_bidirectional_stream();
                    let bidi_js = JsFuture::from(bidi_promise).await.map_err(|e| {
                        TransportError::SendFailed(format!(
                            "failed to open bidi stream: {}",
                            js_error_message(&e)
                        ))
                    })?;
                    let bidi: web_sys::WebTransportBidirectionalStream = bidi_js.unchecked_into();

                    // Send QUERY frame.
                    let frame = QuicClientFrame::Query {
                        routing_id: routing_id_bytes,
                        since,
                        limit: None,
                    };
                    let wire_bytes = encode_client_frame(&frame)?;

                    let writable = bidi.writable();
                    let writer = writable.get_writer().map_err(|e| {
                        TransportError::SendFailed(format!(
                            "failed to get writer: {}",
                            js_error_message(&e)
                        ))
                    })?;
                    let js_data = js_sys::Uint8Array::from(wire_bytes.as_slice());
                    JsFuture::from(writer.write_with_chunk(&js_data))
                        .await
                        .map_err(|e| {
                            TransportError::SendFailed(format!(
                                "write failed: {}",
                                js_error_message(&e)
                            ))
                        })?;
                    JsFuture::from(writer.close()).await.map_err(|e| {
                        TransportError::SendFailed(format!(
                            "failed to close writer: {}",
                            js_error_message(&e)
                        ))
                    })?;

                    // Read all response frames until stream ends or query_complete.
                    let max_buf = (MAX_FRAME_SIZE as usize) + LENGTH_PREFIX_SIZE;
                    let readable = bidi.readable();
                    let reader = readable
                        .get_reader()
                        .unchecked_into::<web_sys::ReadableStreamDefaultReader>();
                    let mut buf = Vec::new();
                    let mut envelopes = Vec::new();

                    'outer: loop {
                        let result = JsFuture::from(reader.read()).await.map_err(|e| {
                            TransportError::ProtocolError(format!(
                                "failed to read: {}",
                                js_error_message(&e)
                            ))
                        })?;

                        let done = js_sys::Reflect::get(&result, &JsValue::from_str("done"))
                            .unwrap_or(JsValue::TRUE);
                        let value = js_sys::Reflect::get(&result, &JsValue::from_str("value"))
                            .unwrap_or(JsValue::UNDEFINED);

                        if !value.is_undefined() && !value.is_null() {
                            let chunk = js_sys::Uint8Array::new(&value);
                            let chunk_len = chunk.length() as usize;
                            if buf.len() + chunk_len > max_buf {
                                return Err(TransportError::ProtocolError(format!(
                                    "query response exceeds maximum frame size ({max_buf} bytes)"
                                )));
                            }
                            let mut chunk_buf = vec![0u8; chunk_len];
                            chunk.copy_to(&mut chunk_buf);
                            buf.extend_from_slice(&chunk_buf);

                            // Process complete frames.
                            while let Ok(Some((consumed, payload))) = decode_frame_from_buf(&buf) {
                                buf.drain(..consumed);
                                if let Ok(relay_frame) = decode_relay_frame(&payload) {
                                    match relay_frame {
                                        QuicRelayFrame::Blob { blob, .. } => {
                                            match OuterEnvelope::from_bytes(&blob) {
                                                Ok(env) => envelopes.push(env),
                                                Err(_) => {
                                                    // Sanitized: do not log the
                                                    // serde error; the byte
                                                    // payload is relay-supplied
                                                    // and some codecs include
                                                    // byte excerpts in `Display`.
                                                    tracing::warn!(
                                                        "envelope deserialization failed"
                                                    );
                                                }
                                            }
                                        }
                                        QuicRelayFrame::Event { event_type }
                                            if event_type == "query_complete" =>
                                        {
                                            break 'outer;
                                        }
                                        QuicRelayFrame::Err { code, msg } => {
                                            return Err(TransportError::ProtocolError(format!(
                                                "query error {code}: {msg}"
                                            )));
                                        }
                                        _ => {}
                                    }
                                }
                            }
                        }

                        if done.is_truthy() {
                            break;
                        }
                    }

                    Ok(envelopes)
                }
                FallbackState::Connected(TransportKind::WebSocket) => {
                    // WebSocket path: send QUERY frame, collect results via a
                    // temporary subscription keyed by routing_id, until
                    // query_complete EVENT arrives (matched by ref_id).
                    let ref_id = self.next_ref_id();

                    // Create a temporary channel for query results.
                    let (tx, mut rx) = mpsc::unbounded::<TransportEvent>();

                    // Register temporarily as a subscription so the onmessage
                    // handler can route BLOB results to us. If a live
                    // subscription already exists for this routing_id, skip
                    // registration to avoid clobbering it -- query results
                    // will still arrive via the pending_request for
                    // query_complete, and we accept potentially fewer results.
                    let registered_temp_sub = !self
                        .subscriptions
                        .contains(&RoutingId::new(routing_id_bytes));
                    if registered_temp_sub {
                        self.subscriptions
                            .insert(RoutingId::new(routing_id_bytes), tx)
                            .map_err(|e| TransportError::SubscriptionFailed(e.to_string()))?;
                    }

                    // Also register a pending request for the query_complete
                    // or OK response.
                    let (complete_tx, complete_rx) = oneshot::channel::<RelayMessage>();
                    {
                        let mut guard = self
                            .pending_requests
                            .lock()
                            .map_err(|_| TransportError::NotConnected)?;
                        guard.insert(ref_id.clone(), complete_tx);
                    }

                    let msg = ClientMessage::Query {
                        ref_id: Some(ref_id.clone()),
                        routing_id: routing_id_bytes,
                        since,
                        limit: None,
                    };

                    self.ws_send_fire_and_forget(&msg)?;

                    // Wait for the query_complete signal.
                    let _ = complete_rx.await;

                    // Collect all buffered envelopes from the subscription channel.
                    let mut envelopes = Vec::new();
                    while let Ok(Some(event)) = rx.try_next() {
                        if let TransportEvent::Envelope(env) = event {
                            envelopes.push(env);
                        }
                    }

                    // Clean up the temporary subscription only if we
                    // registered it (i.e., no pre-existing subscription).
                    if registered_temp_sub {
                        self.subscriptions.remove(&RoutingId::new(routing_id_bytes));
                    }

                    Ok(envelopes)
                }
                _ => Err(TransportError::NotConnected),
            }
        })
    }

    /// Requests deletion of a blob by its ID.
    ///
    /// Best-effort: untrusted transports may ignore this request.
    ///
    /// For WebTransport: opens a bidirectional stream, sends DELETE, awaits
    /// ACK, closes stream.
    ///
    /// For WebSocket: sends DELETE frame, awaits ACK matched by ref_id.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::NotConnected`] if no transport is active.
    fn delete(&self, blob_id: &BlobId) -> BoxFuture<'_, Result<(), TransportError>> {
        let state = self.current_state();
        let blob_id_bytes = *blob_id.as_bytes();

        Box::pin(async move {
            match state {
                FallbackState::Connected(TransportKind::WebTransport) => {
                    // WebTransport path: open bidi stream, send DELETE, await ACK.
                    let frame = QuicClientFrame::Delete {
                        blob_id: blob_id_bytes,
                    };

                    let response = self.wt_request_response(&frame).await?;

                    match response {
                        QuicRelayFrame::Err { code, msg } => Err(TransportError::SendFailed(
                            format!("relay error {code}: {msg}"),
                        )),
                        // Best-effort: treat all non-error responses as success.
                        _ => Ok(()),
                    }
                }
                FallbackState::Connected(TransportKind::WebSocket) => {
                    // WebSocket path: send DELETE frame, await ACK by ref_id.
                    let ref_id = self.next_ref_id();

                    let msg = ClientMessage::Delete {
                        ref_id: Some(ref_id.clone()),
                        blob_id: blob_id_bytes,
                    };

                    let response = self.ws_request_response(msg, ref_id).await?;

                    match response {
                        RelayMessage::Err { code, msg, .. } => Err(TransportError::SendFailed(
                            format!("relay error {code}: {msg}"),
                        )),
                        // Best-effort: treat all non-error responses as success.
                        _ => Ok(()),
                    }
                }
                _ => Err(TransportError::NotConnected),
            }
        })
    }
}

// ---------------------------------------------------------------------------
// Relay message dispatch (WebSocket onmessage handler)
// ---------------------------------------------------------------------------

/// Dispatches a received `RelayMessage` to the appropriate pending request
/// or subscription channel.
///
/// Messages with a `ref_id` that matches a pending request are sent to the
/// oneshot channel. BLOB messages are routed to the subscription channel
/// matching the `routing_id`. `backfill_complete` events are routed to the
/// specific subscription that initiated the backfill via `subscribe_ref_ids`
/// to prevent broadcasting to all subscribers.
fn dispatch_relay_message(
    msg: &RelayMessage,
    subscriptions: &Arc<TransportSubscriptionMap<mpsc::UnboundedSender<TransportEvent>>>,
    pending_requests: &Arc<Mutex<HashMap<String, oneshot::Sender<RelayMessage>>>>,
    subscribe_ref_ids: &Arc<Mutex<HashMap<String, [u8; 32]>>>,
) {
    // Check if this message has a ref_id that matches a pending request.
    let ref_id = match msg {
        RelayMessage::Ok { ref_id, .. }
        | RelayMessage::Err { ref_id, .. }
        | RelayMessage::Event { ref_id, .. } => ref_id.clone(),
        _ => None,
    };

    if let Some(ref ref_id) = ref_id {
        if let Ok(mut guard) = pending_requests.lock() {
            if let Some(tx) = guard.remove(ref_id) {
                let _ = tx.send(msg.clone());
                return;
            }
        }
    }

    // Route BLOB messages to subscriptions by routing_id. Decoding only
    // runs after a presence check so malformed BLOBs at unsolicited
    // routing_ids cannot drive log spam or attacker-controlled bytes
    // toward error surfaces (sanitized regardless on the failure path).
    if let RelayMessage::Blob {
        routing_id, blob, ..
    } = msg
    {
        let rid = RoutingId::new(*routing_id);
        if !subscriptions.contains(&rid) {
            return;
        }
        let event = match OuterEnvelope::from_bytes(blob) {
            Ok(env) => TransportEvent::Envelope(env),
            Err(_) => {
                // The blob is attacker-controlled. Some serde codecs include
                // raw byte excerpts in their `Display`; do not include `e` in
                // the surfaced error message.
                tracing::warn!("envelope deserialization failed");
                TransportEvent::Error(TransportError::ProtocolError(
                    "failed to deserialize envelope from blob".to_owned(),
                ))
            }
        };
        let _ = subscriptions.with(&rid, |tx| tx.unbounded_send(event));
    }

    // Route backfill_complete events to the specific subscription that
    // requested the backfill, identified via the subscribe ref_id -> routing_id
    // mapping. Falls back to broadcast only if no mapping exists (e.g.,
    // events without ref_id from older relays).
    if let RelayMessage::Event { event_type, .. } = msg {
        if event_type == "backfill_complete" {
            // Try to route to the specific subscription via ref_id mapping.
            let target_routing_id = ref_id.as_ref().and_then(|rid| {
                subscribe_ref_ids
                    .lock()
                    .ok()
                    .and_then(|guard| guard.get(rid).copied())
            });

            if let Some(routing_id) = target_routing_id {
                // Scoped delivery: only the subscription that requested backfill.
                let _ = subscriptions.with(&RoutingId::new(routing_id), |tx| {
                    tx.unbounded_send(TransportEvent::BackfillComplete)
                });
            } else {
                // Fallback: no ref_id mapping available. Broadcast to all
                // subscriptions for backwards compatibility with relays that
                // send backfill_complete without a ref_id.
                subscriptions.for_each(|_rid, tx| {
                    let _ = tx.unbounded_send(TransportEvent::BackfillComplete);
                });
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Converts a `QuicRelayFrame` to a `TransportEvent`.
fn relay_frame_to_event(frame: QuicRelayFrame) -> Option<TransportEvent> {
    match frame {
        QuicRelayFrame::Blob { blob, .. } => match OuterEnvelope::from_bytes(&blob) {
            Ok(env) => Some(TransportEvent::Envelope(env)),
            Err(_) => {
                // Sanitized: do not propagate the serde error message into the
                // TransportEvent. The byte payload is relay-supplied and some
                // codecs include byte excerpts in `Display`, which would leak
                // attacker-controlled bytes into SDK error surfaces.
                tracing::warn!("envelope deserialization failed");
                Some(TransportEvent::Error(TransportError::ProtocolError(
                    "failed to deserialize envelope from blob".to_owned(),
                )))
            }
        },
        QuicRelayFrame::Event { event_type } => match event_type.as_str() {
            "backfill_complete" => Some(TransportEvent::BackfillComplete),
            "query_complete" => None, // Handled by query loop
            _ => None,
        },
        QuicRelayFrame::Err { code, msg } => Some(TransportEvent::Error(
            TransportError::ProtocolError(format!("relay error {code}: {msg}")),
        )),
        QuicRelayFrame::Ok { .. } => None,
    }
}

/// Extracts a human-readable error message from a `JsValue`.
fn js_error_message(val: &JsValue) -> String {
    if let Some(err) = val.dyn_ref::<js_sys::Error>() {
        err.message().into()
    } else if let Some(s) = val.as_string() {
        s
    } else {
        format!("{val:?}")
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// Unit tests that do not require a browser environment.
// WASM-specific integration tests would use wasm-bindgen-test.
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    // These tests run on the host (not WASM), so they exercise the
    // non-browser code paths and type-level correctness.

    // Note: WebTransportAdapter::new() is gated behind cfg(target_arch = "wasm32")
    // so we cannot construct it in non-WASM tests. Instead, we test the
    // underlying components (FallbackState, URL conversion) which are
    // exercised in fallback.rs tests.

    // The following tests verify type-level properties.

    #[test]
    fn fallback_state_transitions_are_exhaustive() {
        // Verify all FallbackState variants are constructible and pattern-matchable.
        let states = vec![
            FallbackState::Disconnected,
            FallbackState::AttemptingWebTransport,
            FallbackState::AttemptingWebSocket,
            FallbackState::Connected(TransportKind::WebTransport),
            FallbackState::Connected(TransportKind::WebSocket),
            FallbackState::Failed("test error".to_owned()),
        ];

        for state in &states {
            match state {
                FallbackState::Disconnected => assert!(!state.is_connected()),
                FallbackState::AttemptingWebTransport => assert!(!state.is_connected()),
                FallbackState::AttemptingWebSocket => assert!(!state.is_connected()),
                FallbackState::Connected(kind) => {
                    assert!(state.is_connected());
                    assert_eq!(state.transport_kind(), Some(*kind));
                }
                FallbackState::Failed(_) => assert!(!state.is_connected()),
            }
        }
    }

    #[test]
    fn transport_kind_covers_both_variants() {
        let kinds = [TransportKind::WebTransport, TransportKind::WebSocket];
        assert_eq!(kinds.len(), 2);
        assert_ne!(kinds[0], kinds[1]);
    }

    #[test]
    fn relay_frame_to_event_blob_parses_valid_envelope() {
        // Create a valid envelope.
        let routing_id = [0xAA; 32];
        let env = scp_core::envelope::create_outer_envelope(
            &routing_id,
            None,
            3600,
            vec![0x01, 0x02, 0x03],
        )
        .unwrap();
        let blob_bytes = env.to_bytes().unwrap();
        let blob_id = {
            use sha2::{Digest, Sha256};
            let hash = Sha256::digest(&blob_bytes);
            let mut out = [0u8; 32];
            out.copy_from_slice(&hash);
            out
        };

        let frame = QuicRelayFrame::Blob {
            routing_id,
            blob_id,
            recipient_hint: None,
            blob_ttl: 3600,
            stored_at: 1_700_000_000,
            blob: blob_bytes,
        };

        let event = relay_frame_to_event(frame);
        assert!(matches!(event, Some(TransportEvent::Envelope(_))));
    }

    #[test]
    fn relay_frame_to_event_blob_returns_error_for_invalid_data() {
        let frame = QuicRelayFrame::Blob {
            routing_id: [0xAA; 32],
            blob_id: [0xBB; 32],
            recipient_hint: None,
            blob_ttl: 3600,
            stored_at: 1_700_000_000,
            blob: vec![0xFF, 0xFE, 0xFD],
        };

        let event = relay_frame_to_event(frame);
        assert!(matches!(event, Some(TransportEvent::Error(_))));
    }

    #[test]
    fn relay_frame_to_event_backfill_complete() {
        let frame = QuicRelayFrame::Event {
            event_type: "backfill_complete".to_string(),
        };
        let event = relay_frame_to_event(frame);
        assert!(matches!(event, Some(TransportEvent::BackfillComplete)));
    }

    #[test]
    fn relay_frame_to_event_query_complete_returns_none() {
        let frame = QuicRelayFrame::Event {
            event_type: "query_complete".to_string(),
        };
        let event = relay_frame_to_event(frame);
        assert!(event.is_none());
    }

    #[test]
    fn relay_frame_to_event_err() {
        let frame = QuicRelayFrame::Err {
            code: 4001,
            msg: "invalid".to_string(),
        };
        let event = relay_frame_to_event(frame);
        assert!(matches!(event, Some(TransportEvent::Error(_))));
    }

    #[test]
    fn relay_frame_to_event_ok_returns_none() {
        let frame = QuicRelayFrame::Ok { blob_id: None };
        let event = relay_frame_to_event(frame);
        assert!(event.is_none());
    }

    #[test]
    fn dispatch_blob_routes_to_correct_subscription() {
        // Verify that a BLOB message addressed to one routing_id is delivered
        // only to the matching subscription's sender, not to every subscriber.
        let routing_a = [0xAAu8; 32];
        let routing_b = [0xBBu8; 32];

        let subscriptions: Arc<TransportSubscriptionMap<mpsc::UnboundedSender<TransportEvent>>> =
            Arc::new(TransportSubscriptionMap::new());
        let pending_requests: Arc<Mutex<HashMap<String, oneshot::Sender<RelayMessage>>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let subscribe_ref_ids: Arc<Mutex<HashMap<String, [u8; 32]>>> =
            Arc::new(Mutex::new(HashMap::new()));

        let (tx_a, mut rx_a) = mpsc::unbounded::<TransportEvent>();
        let (tx_b, mut rx_b) = mpsc::unbounded::<TransportEvent>();
        subscriptions
            .insert(RoutingId::new(routing_a), tx_a)
            .unwrap();
        subscriptions
            .insert(RoutingId::new(routing_b), tx_b)
            .unwrap();

        // Build a valid envelope addressed to routing_a so that
        // OuterEnvelope::from_bytes succeeds.
        let envelope = scp_core::envelope::create_outer_envelope(
            &routing_a,
            None,
            3600,
            vec![0x01, 0x02, 0x03],
        )
        .unwrap();
        let blob_bytes = envelope.to_bytes().unwrap();

        let blob_msg = RelayMessage::Blob {
            routing_id: routing_a,
            blob_id: *crate::traits::BlobId::from_sha256(&blob_bytes).as_bytes(),
            recipient_hint: None,
            blob_ttl: 3600,
            stored_at: 1_700_000_000,
            blob: blob_bytes,
        };

        dispatch_relay_message(
            &blob_msg,
            &subscriptions,
            &pending_requests,
            &subscribe_ref_ids,
        );

        // routing_a's subscription must receive the envelope.
        let event_a = rx_a.try_next().expect("rx_a should have an event").unwrap();
        assert!(
            matches!(event_a, TransportEvent::Envelope(_)),
            "expected Envelope on rx_a, got {event_a:?}"
        );

        // routing_b's subscription must NOT receive anything.
        assert!(
            rx_b.try_next().is_err(),
            "rx_b should be empty after dispatch to routing_a"
        );
    }
}
