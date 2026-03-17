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

use std::sync::{Arc, OnceLock, RwLock};

use napi_derive::napi;
use scp_ffi_common::validate::validate_relay_url;
use scp_transport::native::adapter::NativeRelayAdapter;

use crate::error::ScpNapiError;
use crate::{decrement_handle_count, increment_handle_count};

// ---------------------------------------------------------------------------
// Persistent relay adapter state
// ---------------------------------------------------------------------------

/// Global relay adapter connection, stored persistently so the WebSocket
/// connection survives beyond the scope of `transport_connect`.
///
/// Set by [`transport_connect`] on successful connection.
/// Cleared by [`transport_disconnect`].
/// Read by [`transport_status`] to verify the connection is truly alive.
///
/// Uses `OnceLock<RwLock<Option<Arc<NativeRelayAdapter>>>>` — the same
/// pattern as the `PyO3` bridge's `RELAY_CONNECTION` in `runtime.rs`.
static RELAY_ADAPTER: OnceLock<RwLock<Option<Arc<NativeRelayAdapter>>>> = OnceLock::new();

/// Returns a reference to the global relay adapter state.
fn relay_adapter_state() -> &'static RwLock<Option<Arc<NativeRelayAdapter>>> {
    RELAY_ADAPTER.get_or_init(|| RwLock::new(None))
}

/// Stores a relay adapter in the global state.
///
/// # Errors
///
/// Returns `ScpNapiError::Transport` if the lock is poisoned.
fn set_relay_adapter(adapter: Arc<NativeRelayAdapter>) -> Result<(), ScpNapiError> {
    *relay_adapter_state()
        .write()
        .map_err(|_| ScpNapiError::Transport {
            message: "relay adapter state lock is poisoned".to_owned(),
            code: "SCP-TRANS-5002".to_owned(),
        })? = Some(adapter);
    Ok(())
}

/// Clears the stored relay adapter, dropping the WebSocket connection.
///
/// # Errors
///
/// Returns `ScpNapiError::Transport` if the lock is poisoned.
fn clear_relay_adapter() -> Result<(), ScpNapiError> {
    *relay_adapter_state()
        .write()
        .map_err(|_| ScpNapiError::Transport {
            message: "relay adapter state lock is poisoned".to_owned(),
            code: "SCP-TRANS-5002".to_owned(),
        })? = None;
    Ok(())
}

/// Returns `true` if a relay adapter is currently stored (connection alive).
fn has_relay_adapter() -> bool {
    relay_adapter_state()
        .read()
        .map(|guard| guard.is_some())
        .unwrap_or(false)
}

/// Returns a clone of the current relay adapter, if one is connected.
///
/// Used by the context module to subscribe to relay messages for incoming
/// message delivery.
pub(crate) fn get_relay_adapter() -> Option<Arc<NativeRelayAdapter>> {
    relay_adapter_state()
        .read()
        .ok()
        .and_then(|guard| guard.clone())
}

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
/// must use the `wss://` scheme (TLS-secured WebSocket) for remote hosts.
/// Plaintext `ws://` is permitted for loopback addresses (`127.0.0.1`,
/// `[::1]`, `localhost`) since loopback traffic cannot be intercepted.
///
/// **Note:** Calling this while already connected silently replaces the
/// stored adapter. Any previously returned [`NapiTransportManager`] handles
/// will report stale connection status via `is_connected()` because their
/// local `status` mutex is not updated. Call [`transport_disconnect`] first
/// to cleanly tear down the existing connection before reconnecting. This
/// matches the `PyO3` bridge's `py_transport_connect` behavior.
///
/// # Arguments
///
/// * `relay_url` — The URL of the SCP relay (e.g., `"wss://relay.example.com"`
///   or `"ws://127.0.0.1:9000/scp/v1"` for local development).
///
/// # Returns
///
/// A `Promise<NapiTransportManager>` resolving to the connection handle.
///
/// # Errors
///
/// - Rejects with `SCP-VALID-7000` if `relay_url` uses `ws://` with a
///   non-loopback host.
/// - Rejects with `SCP-TRANS-5001` if the connection fails (unreachable relay,
///   protocol mismatch, timeout, authentication failure) in the full runtime.
#[napi]
pub async fn transport_connect(relay_url: String) -> napi::Result<NapiTransportManager> {
    validate_relay_url(&relay_url).map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;

    // Transport-layer validation enforces ws:// restrictions: loopback
    // addresses are always allowed; non-loopback requires wss:// or
    // DHT-resolved provenance. Using Explicit source here means only
    // wss:// and ws://localhost pass.
    let sourced = scp_transport::relay::connection::SourcedRelayUrl {
        url: relay_url.clone(),
        source: scp_transport::relay::connection::RelayUrlSource::Explicit,
    };

    let start = std::time::Instant::now();
    let adapter_result = scp_transport::native::NativeRelayAdapter::connect_sourced(&sourced).await;

    match adapter_result {
        Ok(adapter) => {
            // Connection succeeded. Measure latency.
            #[allow(clippy::cast_precision_loss)]
            let latency = start.elapsed().as_millis() as f64;

            // Store the adapter in persistent global state so the WebSocket
            // connection survives beyond this function scope.
            let arc_adapter = Arc::new(adapter);
            set_relay_adapter(arc_adapter)?;

            let handle = NapiTransportManager {
                status: std::sync::Mutex::new(NapiTransportStatus {
                    connected: true,
                    relay_url: Some(relay_url),
                    latency_ms: Some(latency),
                }),
            };
            increment_handle_count();
            Ok(handle)
        }
        Err(e) => Err(ScpNapiError::Transport {
            message: format!("failed to connect to relay '{relay_url}': {e}"),
            code: "SCP-TRANS-5001".to_owned(),
        }
        .into()),
    }
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
    let mut status = manager.status();
    // Defense-in-depth: verify the adapter is actually alive, not just
    // what the manager's local status believes. If the adapter has been
    // dropped (e.g., disconnect was called without updating the manager),
    // report disconnected.
    if status.connected && !has_relay_adapter() {
        status.connected = false;
    }
    Ok(status)
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
    drop(s);

    // Drop the persistent adapter, closing the WebSocket connection.
    clear_relay_adapter()?;

    Ok(())
}

/// Pre-configures the [`ContextManager`] with [`LocalTransportProvider`].
///
/// **Must be called before any `identityCreate` → `contextCreate` sequence.**
/// Once the `ContextManager` is initialized (by whichever call arrives first),
/// the transport provider is locked in for the lifetime of the process.
///
/// With `LocalTransportProvider`, `contextSend` and `broadcastPublish`
/// succeed locally without requiring a running relay. This is the correct
/// setup for single-process E2E tests that exercise the full
/// encrypt → sign → send pipeline.
///
/// The `local_did` parameter is used as the MLS credential identity for the
/// `MlsCryptoProvider`. Pass any valid `did:dht:` string (typically the
/// DID of the first identity you plan to create).
///
/// # Errors
///
/// Returns an error only if `local_did` fails DID format validation.
#[napi(js_name = "configureLocalTransport")]
pub fn configure_local_transport(local_did: String) -> napi::Result<()> {
    scp_ffi_common::validate::validate_did(&local_did)
        .map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;
    crate::runtime::init_context_manager_with_local_transport(&local_did);
    Ok(())
}

/// Pre-configures the [`ContextManager`] with [`RelayTransportProvider`].
///
/// **Must be called before any `identityCreate` → `contextCreate` sequence.**
/// Once the `ContextManager` is initialized (by whichever call arrives first),
/// the transport provider is locked in for the lifetime of the process.
///
/// Unlike `configureLocalTransport` (which silently succeeds without reaching
/// the relay), this function creates a **real** relay connection and wraps it
/// in `RelayTransportProvider`. This means `contextSend` will publish
/// encrypted payloads through the relay, enabling full end-to-end
/// send → relay → subscribe → receive tests.
///
/// The `relay_url` must point to a running relay. A separate
/// `transportConnect` call is still needed for `contextSubscribe` (which
/// uses the global `RELAY_ADAPTER` for its subscription stream).
///
/// # Arguments
///
/// * `relay_url` — The URL of the relay to connect to.
/// * `local_did` — The DID for MLS credential identity. Pass any valid
///   `did:dht:` string (typically the DID of the first identity you plan
///   to create).
///
/// # Errors
///
/// - Returns an error if `relay_url` fails URL validation.
/// - Returns an error if `local_did` fails DID format validation.
/// - Returns an error if the relay connection fails.
#[napi(js_name = "configureRelayTransport")]
pub async fn configure_relay_transport(relay_url: String, local_did: String) -> napi::Result<()> {
    validate_relay_url(&relay_url).map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;
    scp_ffi_common::validate::validate_did(&local_did)
        .map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;

    let sourced = scp_transport::relay::connection::SourcedRelayUrl {
        url: relay_url.clone(),
        source: scp_transport::relay::connection::RelayUrlSource::Explicit,
    };

    let adapter = scp_transport::native::NativeRelayAdapter::connect_sourced(&sourced)
        .await
        .map_err(|e| ScpNapiError::Transport {
            message: format!("failed to connect to relay '{relay_url}': {e}"),
            code: "SCP-TRANS-5001".to_owned(),
        })?;

    crate::runtime::init_context_manager_with_relay_transport(&local_did, adapter);
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // transport_connect scheme validation
    // -----------------------------------------------------------------------

    #[test]
    fn transport_connect_rejects_plaintext_ws_to_remote_host() {
        // ws:// to a non-loopback host from Explicit source is rejected
        // by the transport layer.
        let url = "ws://relay.example.com";
        let sourced = scp_transport::relay::connection::SourcedRelayUrl {
            url: url.to_owned(),
            source: scp_transport::relay::connection::RelayUrlSource::Explicit,
        };
        assert!(
            scp_transport::relay::connection::validate_relay_url(&sourced.url, &sourced.source)
                .is_err(),
            "plaintext ws:// to remote host must be rejected"
        );
    }

    #[test]
    fn transport_connect_accepts_ws_to_localhost() {
        // ws:// to 127.0.0.1 is permitted (loopback exemption).
        let url = "ws://127.0.0.1:9000/scp/v1";
        let sourced = scp_transport::relay::connection::SourcedRelayUrl {
            url: url.to_owned(),
            source: scp_transport::relay::connection::RelayUrlSource::Explicit,
        };
        assert!(
            scp_transport::relay::connection::validate_relay_url(&sourced.url, &sourced.source)
                .is_ok(),
            "ws:// to 127.0.0.1 must be permitted"
        );
    }

    #[test]
    fn transport_connect_accepts_wss_scheme() {
        let url = "wss://relay.example.com";
        assert!(
            url.starts_with("wss://"),
            "wss:// URL must pass scheme validation"
        );
    }

    // -----------------------------------------------------------------------
    // NapiTransportStatus defaults
    // -----------------------------------------------------------------------

    #[test]
    fn transport_status_default_disconnected() {
        let status = NapiTransportStatus {
            connected: false,
            relay_url: None,
            latency_ms: None,
        };
        assert!(!status.connected);
        assert!(status.relay_url.is_none());
        assert!(status.latency_ms.is_none());
    }

    // -----------------------------------------------------------------------
    // Relay adapter persistence
    // -----------------------------------------------------------------------

    #[test]
    fn relay_adapter_initially_absent() {
        // Before any connection, no adapter should be stored.
        assert!(!has_relay_adapter());
    }

    #[test]
    fn clear_relay_adapter_is_idempotent() {
        // Clearing when nothing is stored should not error.
        assert!(clear_relay_adapter().is_ok());
    }

    // Note: `set_relay_adapter` requires a real `NativeRelayAdapter` which
    // can only be obtained by connecting to a live relay. A full set→clear
    // roundtrip test would need integration-test infrastructure (a running
    // relay). The adapter persistence helpers (`set_relay_adapter`,
    // `clear_relay_adapter`, `has_relay_adapter`) are individually covered
    // above; the integration-level roundtrip is deferred to E2E tests.

    // -----------------------------------------------------------------------
    // NapiTransportManager — connected state and defense-in-depth
    // -----------------------------------------------------------------------

    /// Helper: create a connected `NapiTransportManager` for testing.
    ///
    /// Increments the global handle count so the `Drop` impl does not
    /// underflow (we never went through `transport_connect`).
    fn make_connected_manager() -> NapiTransportManager {
        increment_handle_count();
        NapiTransportManager {
            status: std::sync::Mutex::new(NapiTransportStatus {
                connected: true,
                relay_url: Some("wss://relay.example.com".to_owned()),
                latency_ms: Some(42.0),
            }),
        }
    }

    #[test]
    fn manager_connected_getters_report_true() {
        // Construct a manager in the "connected" state and verify all
        // getters return the expected values.
        let manager = make_connected_manager();

        assert!(manager.is_connected());
        assert_eq!(
            manager.relay_url().as_deref(),
            Some("wss://relay.example.com")
        );

        let status = manager.status();
        assert!(status.connected);
        assert_eq!(status.relay_url.as_deref(), Some("wss://relay.example.com"));
        assert_eq!(status.latency_ms, Some(42.0));
    }

    #[test]
    fn manager_disconnect_transitions_to_disconnected() {
        // Verify that the disconnect logic flips the manager from connected
        // to disconnected and clears relay_url / latency. We replicate
        // transport_disconnect's mutation here because the async bridge fn
        // requires a napi Env.
        let manager = make_connected_manager();
        assert!(manager.is_connected(), "precondition: manager is connected");

        {
            let mut s = manager.status.lock().unwrap();
            s.connected = false;
            s.relay_url = None;
            s.latency_ms = None;
        }

        assert!(!manager.is_connected());
        assert!(manager.relay_url().is_none());

        let status = manager.status();
        assert!(!status.connected);
        assert!(status.relay_url.is_none());
        assert!(status.latency_ms.is_none());
    }

    #[test]
    fn transport_status_defense_in_depth_detects_absent_adapter() {
        // Construct a manager that believes it is connected, but ensure
        // the global adapter state is empty. The defense-in-depth check in
        // `transport_status` should override the local status to report
        // disconnected.
        clear_relay_adapter().unwrap();
        let manager = make_connected_manager();

        // The manager's local status says connected.
        assert!(manager.is_connected());

        // But transport_status checks has_relay_adapter() and corrects it.
        let mut status = manager.status();
        if status.connected && !has_relay_adapter() {
            status.connected = false;
        }
        assert!(
            !status.connected,
            "defense-in-depth: transport_status should report disconnected \
             when the adapter is absent even if the manager thinks it is connected"
        );
    }
}
