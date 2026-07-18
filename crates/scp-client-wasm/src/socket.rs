//! JS-injected outbound relay socket, adapted to the driver's
//! [`scp_client::RelaySink`] (ADR-057 transport slice).
//!
//! The browser owns the relay WebSocket; the TypeScript SDK injects a small
//! `JsSocket` object whose one method, `send(frame)`, writes a serialized relay
//! `ClientMessage` frame to that socket. This module adapts it to the driver's
//! synchronous [`scp_client::RelaySink`] outbound port. Inbound relay frames flow
//! the other way: the SDK's WebSocket `onmessage` handler calls
//! [`WasmScpClient::handle_relay_frame`](crate::WasmScpClient::handle_relay_frame),
//! so the socket itself is **outbound-only** — it is never read through.
//!
//! # Embedder contract: re-subscribe on every socket (re)open
//!
//! Entry-time `SUBSCRIBE`s are best-effort and never fail context entry (ADR-057
//! F-API1/R1). If the socket is not yet open when a context is entered — the first
//! connect, a reconnect after a drop, or a tab restored from storage before the
//! socket opens — those `SUBSCRIBE` frames are silently dropped and the client is
//! durably present but receives nothing. The TypeScript SDK's WebSocket `onopen`
//! handler (fired on the initial open AND on every reconnect) MUST therefore call
//! [`WasmScpClient::resubscribe_all`](crate::WasmScpClient::resubscribe_all), which
//! re-drives a `SUBSCRIBE` for every tracked routing id. It is idempotent and
//! best-effort, so calling it on every `onopen` is always safe. Omitting it leaves
//! a reconnected or restored tab deaf — the failure the `resubscribeAll` export
//! (P0) exists to let the embedder prevent.
//!
//! Restores the deleted WASM bridge's JS-injected-extern shape (a JS object the
//! TypeScript wrapper injects), matching [`crate::custody`] and [`crate::storage`].

#[cfg(target_arch = "wasm32")]
pub use wasm_impl::{JsSocket, JsSocketAdapter};

#[cfg(target_arch = "wasm32")]
mod wasm_impl {
    use scp_client::RelaySink;
    use wasm_bindgen::prelude::*;

    #[wasm_bindgen]
    extern "C" {
        /// Opaque JS object wrapping the browser's relay WebSocket.
        ///
        /// Injected by the TypeScript SDK. Its `send` method writes one binary
        /// relay frame to the socket. Uses `catch`, so a thrown JS exception (the
        /// socket is closed, buffering failed) surfaces as `Err(JsValue)`.
        pub type JsSocket;

        /// Writes one serialized relay `ClientMessage` frame to the WebSocket.
        ///
        /// `frame` is passed **by value** (an owned `Vec<u8>`), so wasm-bindgen
        /// marshals it as a JS-owned `Uint8Array` copy detached from wasm linear
        /// memory — NOT a `subarray` view into it (which `&[u8]` would produce).
        /// This is load-bearing for the same reason as
        /// [`JsKeyCustody::sign`](crate::custody): a `WebSocket.send` (or a
        /// buffering/queuing facade) that retains the buffer past the call is sound
        /// with an owned `Vec<u8>`, whereas a `&[u8]` view would alias wasm memory
        /// that later allocations reuse — corrupting the bytes actually sent.
        #[wasm_bindgen(method, catch, js_name = "send")]
        fn send(this: &JsSocket, frame: Vec<u8>) -> Result<(), JsValue>;
    }

    /// Adapts an injected [`JsSocket`] to the driver's [`RelaySink`] trait.
    pub struct JsSocketAdapter {
        inner: JsSocket,
    }

    impl JsSocketAdapter {
        /// Wraps an injected [`JsSocket`].
        #[must_use]
        pub fn new(inner: JsSocket) -> Self {
            Self { inner }
        }
    }

    // SAFETY: identical single-thread justification to `custody::JsSigner` and
    // `storage::JsStorageAdapter` — see those modules' "Single-thread soundness"
    // notes. The wrapped `JsSocket` handle is a JS-heap index that cannot cross a
    // worker-agent boundary; under the single-tab driver model it is never sent to
    // another agent, so the driver's `Send + Sync` bound on `RelaySink` is satisfied.
    // Compiled ONLY for wasm32; does not relax the shared `scp_client::RelaySink`
    // bound. The embedder must keep one client pinned to one agent if it ever wires
    // shared-memory threads.
    unsafe impl Send for JsSocketAdapter {}
    // SAFETY: as above (see storage.rs module docs).
    unsafe impl Sync for JsSocketAdapter {}

    impl RelaySink for JsSocketAdapter {
        fn send(&self, frame: Vec<u8>) -> Result<(), String> {
            self.inner.send(frame).map_err(|e| {
                e.as_string()
                    .unwrap_or_else(|| "JsSocket.send threw a non-string exception".to_owned())
            })
        }
    }
}
