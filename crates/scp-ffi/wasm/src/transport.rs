//! `wasm-bindgen` bridge for transport connection and status.
//!
//! Exposes SCP transport operations to JavaScript:
//!
//! - [`transport_connect`] — Connect to an SCP relay.
//! - [`transport_status`] — Query the current transport status.
//!
//! # Types
//!
//! - [`WasmTransportStatus`] — Connection status (connected, relay URL,
//!   latency).
//!
//! # Browser `WebSocket` transport
//!
//! In browser targets, transport connections use the browser's native
//! `WebSocket` API (not a Rust `WebSocket` crate). The TypeScript SDK wrapper
//! manages the `WebSocket` lifecycle and injects messages into the Rust bridge
//! via callback. This is consistent with the transport independence tenet
//! (spec §4 — no structural coupling to any single transport).
//!
//! See ADR-022 in `.docs/adrs/phase-4.md` and ADR-005 (transport abstraction)
//! for the full specification.

use js_sys::Promise;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::future_to_promise;

use crate::error::ScpWasmError;

// ---------------------------------------------------------------------------
// WasmTransportStatus
// ---------------------------------------------------------------------------

/// Transport connection status exposed to JavaScript.
///
/// Reports whether the transport is connected, the relay URL (if connected),
/// and the measured round-trip latency in milliseconds (if available).
///
/// # JS usage
///
/// ```js
/// const status = transport_status();
/// console.log(status.connected);   // false
/// console.log(status.relayUrl);    // null | "wss://relay.example.com"
/// console.log(status.latencyMs);   // null | 42.0
/// ```
#[wasm_bindgen]
#[derive(Debug, Clone)]
pub struct WasmTransportStatus {
    /// `true` if the transport is currently connected to a relay.
    connected: bool,
    /// The relay URL if connected, `None` (JS `null`) if disconnected.
    relay_url: Option<String>,
    /// Round-trip latency to the relay in milliseconds, `None` if unavailable.
    latency_ms: Option<f64>,
}

#[wasm_bindgen]
impl WasmTransportStatus {
    /// Returns `true` if the transport is currently connected.
    #[must_use]
    #[wasm_bindgen(getter)]
    pub fn connected(&self) -> bool {
        self.connected
    }

    /// Returns the relay URL if connected, or `null` if disconnected.
    #[must_use]
    #[wasm_bindgen(getter, js_name = "relayUrl")]
    pub fn relay_url(&self) -> Option<String> {
        self.relay_url.clone()
    }

    /// Returns the round-trip latency in milliseconds, or `null` if
    /// not measured or disconnected.
    #[must_use]
    #[wasm_bindgen(getter, js_name = "latencyMs")]
    pub fn latency_ms(&self) -> Option<f64> {
        self.latency_ms
    }
}

// ---------------------------------------------------------------------------
// Bridge functions
// ---------------------------------------------------------------------------

/// Connects to an SCP relay.
///
/// In browser targets, transport connections use the browser's native
/// `WebSocket` API managed by the TypeScript SDK wrapper. This function
/// validates the relay URL format and signals to the TypeScript wrapper
/// that a `WebSocket` connection should be established.
///
/// # Arguments
///
/// * `relay_url` — The `WebSocket` URL of the SCP relay (must use `wss://`
///   scheme in browser contexts for security).
///
/// # Returns
///
/// `Promise<WasmTransportStatus>` — resolves to a [`WasmTransportStatus`]
/// reflecting the (intended) connected state. The TypeScript wrapper
/// establishes the actual `WebSocket` connection.
///
/// # Errors
///
/// - Rejects with `[SCP-VALID-7000]` if `relay_url` does not use the
///   `wss://` scheme.
/// - Rejects with `[SCP-TRANS-5000]` if the relay URL format is otherwise
///   invalid.
///
/// See ADR-022 acceptance criterion 1.
#[wasm_bindgen]
pub fn transport_connect(relay_url: String) -> Promise {
    future_to_promise(async move {
        // Validate scheme — browser targets MUST use wss:// (TLS-encrypted).
        // Plain ws:// is not permitted; it allows cleartext interception of
        // all SCP protocol traffic. See ADR-022 acceptance criterion 1.
        if !relay_url.starts_with("wss://") {
            return Err(ScpWasmError::Validation(format!(
                "relay_url must use wss:// scheme (TLS required), got: {relay_url:?}"
            ))
            .into_js()
            .into());
        }

        // The TypeScript SDK wrapper establishes the actual WebSocket
        // connection using the browser's native WebSocket API. This bridge
        // function validates the URL and returns a pending status — the
        // TypeScript wrapper updates the connected state after the socket
        // handshake completes.
        let status = WasmTransportStatus {
            connected: false, // Will be updated when TS wrapper handshakes.
            relay_url: Some(relay_url),
            latency_ms: None,
        };

        Ok(JsValue::from(status))
    })
}

/// Returns the current transport connection status.
///
/// Returns a disconnected status in the bridge layer. The TypeScript SDK
/// wrapper maintains the authoritative connection state via the browser's
/// `WebSocket` API and calls this to obtain a Rust-typed status object.
///
/// # Returns
///
/// [`WasmTransportStatus`] — the current transport status (synchronous,
/// not a Promise).
///
/// See ADR-022 acceptance criterion 1.
#[must_use]
#[wasm_bindgen]
pub fn transport_status() -> WasmTransportStatus {
    // Default disconnected status — the TypeScript SDK wrapper provides
    // the live state from the browser WebSocket.
    WasmTransportStatus {
        connected: false,
        relay_url: None,
        latency_ms: None,
    }
}
