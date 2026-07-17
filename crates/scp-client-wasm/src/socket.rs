//! JS-injected outbound relay socket, adapted to the driver's
//! [`scp_client::Socket`] (ADR-057 transport slice).
//!
//! The browser owns the relay WebSocket; the TypeScript SDK injects a small
//! `JsSocket` object whose one method, `send(frame)`, writes a serialized relay
//! `ClientMessage` frame to that socket. This module adapts it to the driver's
//! synchronous [`scp_client::Socket`] outbound port. Inbound relay frames flow
//! the other way: the SDK's WebSocket `onmessage` handler calls
//! [`WasmScpClient::handle_relay_frame`](crate::WasmScpClient::handle_relay_frame),
//! so the socket itself is **outbound-only** — it is never read through.
//!
//! Restores the deleted WASM bridge's JS-injected-extern shape (a JS object the
//! TypeScript wrapper injects), matching [`crate::custody`] and [`crate::storage`].

#[cfg(target_arch = "wasm32")]
pub use wasm_impl::{JsSocket, JsSocketAdapter};

#[cfg(target_arch = "wasm32")]
mod wasm_impl {
    use scp_client::Socket;
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

    /// Adapts an injected [`JsSocket`] to the driver's [`Socket`] trait.
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
    // another agent, so the driver's `Send + Sync` bound on `Socket` is satisfied.
    // Compiled ONLY for wasm32; does not relax the shared `scp_client::Socket`
    // bound. The embedder must keep one client pinned to one agent if it ever wires
    // shared-memory threads.
    unsafe impl Send for JsSocketAdapter {}
    // SAFETY: as above (see storage.rs module docs).
    unsafe impl Sync for JsSocketAdapter {}

    impl Socket for JsSocketAdapter {
        fn send(&self, frame: Vec<u8>) -> Result<(), String> {
            self.inner.send(frame).map_err(|e| {
                e.as_string()
                    .unwrap_or_else(|| "JsSocket.send threw a non-string exception".to_owned())
            })
        }
    }
}
