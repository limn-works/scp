//! napi-rs bridge for transport operations.
//!
//! Exposes relay connection management to JavaScript:
//!
//! - [`transport_connect`] — Connect to an SCP relay.
//! - [`transport_status`] — Query the current transport connection status.
//! - [`transport_disconnect`] — Disconnect from the relay.
//!
//! # Transport model
//!
//! The napi bridge has full access to the native filesystem and OS networking
//! stack — there are no WASM constraints. The tokio multi-thread runtime
//! drives all async I/O. Full transport wiring (WebSocket, multi-relay
//! routing) is connected in integration stories.
//!
//! See ADR-022 and ADR-005 (Transport Abstraction) in `.docs/adrs/`.

use napi_derive::napi;

use crate::error::ScpNapiError;
use crate::{decrement_handle_count, increment_handle_count};

// ---------------------------------------------------------------------------
// NapiTransportStatus — connection status record
// ---------------------------------------------------------------------------

/// Current transport connection status.
///
/// Returned by [`transport_status`] and accessible on [`NapiTransportManager`].
#[napi(object)]
pub struct NapiTransportStatus {
    /// `true` if the transport is currently connected to a relay.
    pub connected: bool,
    /// The relay URL if connected. `null` if disconnected.
    pub relay_url: Option<String>,
    /// Round-trip latency to the relay in milliseconds. `null` if not measured.
    pub latency_ms: Option<f64>,
}

// ---------------------------------------------------------------------------
// NapiTransportManager — opaque JS class for transport state
// ---------------------------------------------------------------------------

/// Opaque handle to the transport layer.
///
/// Exposes connection status and relay URL. The actual transport (WebSocket,
/// multi-relay routing) is managed internally and will be wired to `scp-core`
/// in integration stories.
///
/// # JS usage
///
/// ```js
/// const transport = await transportConnect("wss://relay.example.com");
/// console.log(transport.isConnected); // true
/// console.log(transport.relayUrl);    // "wss://relay.example.com"
/// ```
#[napi]
pub struct NapiTransportManager {
    /// Current connection state.
    status: std::sync::Mutex<NapiTransportStatus>,
}

#[napi]
impl NapiTransportManager {
    /// Returns the current transport connection status.
    #[napi(getter)]
    #[must_use]
    pub fn status(&self) -> NapiTransportStatus {
        self.status
            .lock()
            .map(|s| NapiTransportStatus {
                connected: s.connected,
                relay_url: s.relay_url.clone(),
                latency_ms: s.latency_ms,
            })
            .unwrap_or(NapiTransportStatus {
                connected: false,
                relay_url: None,
                latency_ms: None,
            })
    }

    /// Returns `true` if the transport is currently connected.
    #[napi(getter, js_name = "isConnected")]
    #[must_use]
    pub fn is_connected(&self) -> bool {
        self.status.lock().map(|s| s.connected).unwrap_or(false)
    }

    /// Returns the relay URL if connected, `null` otherwise.
    #[napi(getter, js_name = "relayUrl")]
    #[must_use]
    pub fn relay_url(&self) -> Option<String> {
        self.status.lock().ok().and_then(|s| s.relay_url.clone())
    }
}

impl Drop for NapiTransportManager {
    fn drop(&mut self) {
        decrement_handle_count();
    }
}

// ---------------------------------------------------------------------------
// Bridge functions
// ---------------------------------------------------------------------------

/// Connects to an SCP relay.
///
/// Establishes a transport connection to the specified relay URL. The relay
/// must use the `wss://` scheme (TLS-secured WebSocket). Plaintext `ws://`
/// connections are rejected to prevent credential exposure.
///
/// # Arguments
///
/// * `relay_url` — The URL of the SCP relay (e.g., `"wss://relay.example.com"`).
///   Must use the `wss://` scheme.
///
/// # Returns
///
/// A `Promise<NapiTransportManager>` resolving to the connection handle.
///
/// # Errors
///
/// - Rejects with `SCP-VALID-7000` if `relay_url` does not start with `wss://`.
/// - Rejects with `SCP-TRANS-5001` if the connection fails (unreachable relay,
///   protocol mismatch, timeout, authentication failure) in the full runtime.
#[napi]
#[allow(clippy::unused_async)] // napi-rs requires async for Promise return
pub async fn transport_connect(relay_url: String) -> napi::Result<NapiTransportManager> {
    if !relay_url.starts_with("wss://") {
        return Err(ScpNapiError::Validation {
            message: format!(
                "relay URL must use wss:// scheme (got {relay_url:?}) — \
                 plaintext ws:// connections are not permitted"
            ),
            code: "SCP-VALID-7000".to_owned(),
        }
        .into());
    }

    let handle = NapiTransportManager {
        status: std::sync::Mutex::new(NapiTransportStatus {
            connected: true,
            relay_url: Some(relay_url),
            latency_ms: None,
        }),
    };
    increment_handle_count();
    Ok(handle)
}

/// Returns the current transport connection status.
///
/// # Arguments
///
/// * `manager` — The transport manager handle.
///
/// # Returns
///
/// A `Promise<NapiTransportStatus>` with the current connection state.
///
/// # Errors
///
/// This function is infallible — the `Result` return type is required by
/// the napi-rs bridge pattern.
#[napi]
#[allow(clippy::unused_async)] // napi-rs requires async for Promise return
pub async fn transport_status(manager: &NapiTransportManager) -> napi::Result<NapiTransportStatus> {
    Ok(manager.status())
}

/// Disconnects from the relay.
///
/// Closes the active transport connection. Any pending sends are dropped.
/// The `NapiTransportManager` handle transitions to a disconnected state and
/// must not be used for new operations after this call.
///
/// # Arguments
///
/// * `manager` — The transport manager handle (must be connected).
///
/// # Errors
///
/// Rejects with `SCP-TRANS-5002` if the manager is not connected.
#[napi]
#[allow(clippy::unused_async)] // napi-rs requires async for Promise return
pub async fn transport_disconnect(manager: &NapiTransportManager) -> napi::Result<()> {
    let mut s = manager.status.lock().map_err(|_| ScpNapiError::Transport {
        message: "transport status lock is poisoned".to_owned(),
        code: "SCP-TRANS-5002".to_owned(),
    })?;

    if !s.connected {
        return Err(ScpNapiError::Transport {
            message: "transport is not connected — call transportConnect first".to_owned(),
            code: "SCP-TRANS-5002".to_owned(),
        }
        .into());
    }

    s.connected = false;
    s.relay_url = None;
    s.latency_ms = None;

    Ok(())
}
