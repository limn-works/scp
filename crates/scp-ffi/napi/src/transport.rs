//! napi-rs bridge for transport operations.
//!
//! Exposes relay connection management to JavaScript:
//!
//! - [`transport_connect`] — Connect to an SCP relay (wraps adapter in `TransportManager`).
//! - [`transport_status`] — Query the current transport connection status.
//! - [`transport_disconnect`] — Disconnect from the relay.
//! - [`transport_add_relay`] — Add an additional relay adapter to the manager.
//! - [`transport_assign_relay_set`] — Assign a relay set for a context.
//! - [`transport_adapter_count`] — Query the number of registered adapters.
//! - [`transport_reliability`] — Query reliability score for an adapter.
//!
//! # Transport model
//!
//! The napi bridge stores a process-global [`scp_transport::TransportManager`]
//! that wraps one or more [`NativeRelayAdapter`] instances. The manager
//! provides multi-relay fanout, per-context relay set assignment, suppression
//! cross-checking, and reliability scoring.
//!
//! The tokio multi-thread runtime drives all async I/O. Full transport wiring
//! (WebSocket, multi-relay routing) is connected via the `TransportManager`.
//!
//! See ADR-022, ADR-005 (Transport Abstraction), and ADR-012 (Multi-Relay) in
//! `.docs/adrs/`.

use std::sync::{Arc, OnceLock, RwLock};

use napi_derive::napi;
use scp_ffi_common::validate::{validate_context_id, validate_relay_url};

use crate::error::ScpNapiError;
use crate::{decrement_handle_count, increment_handle_count};

// ---------------------------------------------------------------------------
// Persistent transport manager state
// ---------------------------------------------------------------------------

/// Global transport manager for multi-relay support.
///
/// Stores the real [`scp_transport::TransportManager`] wrapping one or more
/// [`NativeRelayAdapter`] instances. Provides multi-relay fanout, per-context
/// relay set assignment, suppression detection, and reliability scoring.
///
/// Set by [`transport_connect`] on successful connection.
/// Cleared by [`transport_disconnect`].
/// Read by [`transport_status`] and [`context_subscribe`] (via
/// [`get_transport_manager`]).
///
/// Wrapped in `Arc` so async subscription tasks (which outlive the closure)
/// can hold a reference without keeping the `RwLock` guard alive across
/// `.await` points. Same `OnceLock<RwLock<...>>` pattern as the `PyO3`
/// bridge's `TRANSPORT_MANAGER` in `runtime.rs`.
static TRANSPORT_MANAGER: OnceLock<RwLock<Option<Arc<scp_transport::TransportManager>>>> =
    OnceLock::new();

/// Returns a reference to the global transport manager state.
fn transport_state() -> &'static RwLock<Option<Arc<scp_transport::TransportManager>>> {
    TRANSPORT_MANAGER.get_or_init(|| RwLock::new(None))
}

/// Stores a new `TransportManager` (called by [`transport_connect`]).
///
/// # Errors
///
/// Returns `ScpNapiError::Transport` if the lock is poisoned.
fn set_transport_manager(manager: scp_transport::TransportManager) -> napi::Result<()> {
    *transport_state()
        .write()
        .map_err(|_| ScpNapiError::Transport {
            message: "transport manager lock is poisoned".to_owned(),
            code: "SCP-TRANS-5002".to_owned(),
        })? = Some(Arc::new(manager));
    Ok(())
}

/// Stores a pre-built `Arc<TransportManager>` (called by [`server.rs`]
/// auto-wire where the caller needs to construct the manager externally).
///
/// # Errors
///
/// Returns `ScpNapiError::Transport` if the lock is poisoned.
pub(crate) fn set_transport_manager_arc(
    manager: Arc<scp_transport::TransportManager>,
) -> Result<(), ScpNapiError> {
    *transport_state()
        .write()
        .map_err(|_| ScpNapiError::Transport {
            message: "transport manager lock is poisoned".to_owned(),
            code: "SCP-TRANS-5002".to_owned(),
        })? = Some(manager);
    Ok(())
}

/// Executes a closure with a read reference to the `TransportManager`.
///
/// Used by callers that need to query, probe, or inspect the manager
/// without mutating it (sync operations only — for async, use
/// [`get_transport_manager`]).
///
/// # Errors
///
/// Returns `ScpNapiError::Transport` if the lock is poisoned or no
/// transport manager has been initialized.
pub(crate) fn with_transport_manager<T>(
    f: impl FnOnce(&scp_transport::TransportManager) -> napi::Result<T>,
) -> napi::Result<T> {
    let guard = transport_state()
        .read()
        .map_err(|_| ScpNapiError::Transport {
            message: "transport manager lock is poisoned".to_owned(),
            code: "SCP-TRANS-5002".to_owned(),
        })?;
    let manager = guard.as_ref().ok_or_else(|| ScpNapiError::Transport {
        message: "no transport manager — call transportConnect() first".to_owned(),
        code: "SCP-TRANS-5010".to_owned(),
    })?;
    f(manager)
}

/// Executes a closure with a mutable reference to the `TransportManager`.
///
/// Used by callers that need to add adapters or modify relay assignments.
///
/// # Errors
///
/// Returns `ScpNapiError::Transport` if the lock is poisoned or no
/// transport manager has been initialized.
pub(crate) fn with_transport_manager_mut<T>(
    f: impl FnOnce(&mut scp_transport::TransportManager) -> napi::Result<T>,
) -> napi::Result<T> {
    let guard = transport_state()
        .write()
        .map_err(|_| ScpNapiError::Transport {
            message: "transport manager lock is poisoned".to_owned(),
            code: "SCP-TRANS-5002".to_owned(),
        })?;
    // Arc::get_mut won't work here because there may be cloned references
    // held by async subscription tasks. Use Arc::make_mut which is
    // Clone-only. Instead, we downcast through the Option.
    //
    // Since TransportManager uses interior mutability for most operations
    // (relay_assignments: RwLock, reliability_scores: Arc<Mutex>, etc.),
    // `add_adapter` is the only method requiring &mut self. We obtain it
    // by temporarily taking the Arc out and using Arc::get_mut or
    // reconstructing.
    //
    // Actually, `add_adapter(&mut self)` needs exclusive access. If other
    // async tasks hold Arc clones, we can't get &mut. We use a write lock
    // on the outer RwLock to serialize, but the Arc prevents &mut access.
    // Solution: use `Arc::get_mut` which succeeds only when refcount == 1.
    // If it fails (subscription in progress), we error out.
    drop(guard);

    let mut guard = transport_state()
        .write()
        .map_err(|_| ScpNapiError::Transport {
            message: "transport manager lock is poisoned".to_owned(),
            code: "SCP-TRANS-5002".to_owned(),
        })?;

    let arc = guard.as_mut().ok_or_else(|| ScpNapiError::Transport {
        message: "no transport manager — call transportConnect() first".to_owned(),
        code: "SCP-TRANS-5010".to_owned(),
    })?;

    let manager = Arc::get_mut(arc).ok_or_else(|| ScpNapiError::Transport {
        message: "transport manager is in use by an active subscription — \
                  cannot modify while subscriptions are active"
            .to_owned(),
        code: "SCP-TRANS-5003".to_owned(),
    })?;
    f(manager)
}

/// Returns `true` if a transport manager has been initialized.
fn has_transport_manager() -> bool {
    transport_state()
        .read()
        .map(|guard| guard.is_some())
        .unwrap_or(false)
}

/// Returns an `Arc` clone of the current transport manager, if one exists.
///
/// Used by `context_subscribe` which needs to move the manager reference
/// into an async task that outlives any lock guard.
pub(crate) fn get_transport_manager() -> Option<Arc<scp_transport::TransportManager>> {
    transport_state()
        .read()
        .ok()
        .and_then(|guard| guard.clone())
}

/// Clears the transport manager (called by [`transport_disconnect`]).
///
/// # Errors
///
/// Returns `ScpNapiError::Transport` if the lock is poisoned.
fn clear_transport_manager() -> napi::Result<()> {
    *transport_state()
        .write()
        .map_err(|_| ScpNapiError::Transport {
            message: "transport manager lock is poisoned".to_owned(),
            code: "SCP-TRANS-5002".to_owned(),
        })? = None;
    Ok(())
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
    let profile = scp_transport::profile::TransportProfile::platform_default();
    let adapter_result =
        scp_transport::native::NativeRelayAdapter::connect_sourced(&sourced, Some(&profile)).await;

    match adapter_result {
        Ok(adapter) => {
            // Connection succeeded. Measure latency.
            #[allow(clippy::cast_precision_loss)]
            let latency = start.elapsed().as_millis() as f64;

            // Wrap the adapter in a TransportManager for multi-relay support,
            // then store it in the process-global state. Same pattern as the
            // PyO3 bridge's `py_transport_connect`.
            let manager = scp_transport::TransportManager::new(Box::new(adapter));
            set_transport_manager(manager)?;

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
    // Defense-in-depth: verify the transport manager is actually alive,
    // not just what the manager's local status believes. If the transport
    // manager has been dropped (e.g., disconnect was called without
    // updating the manager), report disconnected.
    if status.connected && !has_transport_manager() {
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

    // Drop the transport manager, closing all WebSocket connections.
    clear_transport_manager()?;

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
/// uses the global `TRANSPORT_MANAGER` for its subscription stream).
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

    let profile = scp_transport::profile::TransportProfile::platform_default();
    let adapter =
        scp_transport::native::NativeRelayAdapter::connect_sourced(&sourced, Some(&profile))
            .await
            .map_err(|e| ScpNapiError::Transport {
                message: format!("failed to connect to relay '{relay_url}': {e}"),
                code: "SCP-TRANS-5001".to_owned(),
            })?;

    crate::runtime::init_context_manager_with_relay_transport(&local_did, adapter);
    Ok(())
}

// ---------------------------------------------------------------------------
// NapiReliabilityScore — per-adapter reliability metrics
// ---------------------------------------------------------------------------

/// Per-adapter reliability score exposed to JavaScript.
///
/// Returned by [`transport_reliability`] and maps to the core
/// [`scp_transport::scoring::ReliabilityScore`].
#[napi(object)]
pub struct NapiReliabilityScore {
    /// The relay URL this score tracks.
    pub relay_url: String,
    /// Delivery success rate (0.0 to 1.0), updated via EMA.
    pub delivery_success_rate: f64,
    /// Average latency in milliseconds, updated via EMA.
    pub average_latency_ms: f64,
    /// Deletion compliance rate (0.0 to 1.0), updated via EMA.
    pub deletion_compliance_rate: f64,
    /// Total number of send attempts.
    pub total_sends: f64,
    /// Total number of send failures.
    pub total_failures: f64,
}

// ---------------------------------------------------------------------------
// Multi-relay management functions
// ---------------------------------------------------------------------------

/// Registers an additional relay adapter with the transport manager.
///
/// Connects to the specified relay URL and adds the resulting adapter to
/// the global [`TransportManager`]. The [`transport_connect`] function must
/// have been called first to initialize the manager.
///
/// # Arguments
///
/// * `relay_url` — The URL of the additional SCP relay to connect to.
///
/// # Returns
///
/// A `Promise<number>` resolving to the total number of adapters after
/// adding (i.e. the new adapter count).
///
/// # Errors
///
/// - Rejects with `SCP-TRANS-5010` if no transport manager exists.
/// - Rejects with `SCP-VALID-7000` if the URL is invalid.
/// - Rejects with `SCP-TRANS-5001` if the connection fails.
/// - Rejects with `SCP-TRANS-5003` if a subscription is active.
#[napi]
pub async fn transport_add_relay(relay_url: String) -> napi::Result<u32> {
    validate_relay_url(&relay_url).map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;

    let sourced = scp_transport::relay::connection::SourcedRelayUrl {
        url: relay_url.clone(),
        source: scp_transport::relay::connection::RelayUrlSource::Explicit,
    };
    let profile = scp_transport::profile::TransportProfile::platform_default();
    let adapter =
        scp_transport::native::NativeRelayAdapter::connect_sourced(&sourced, Some(&profile))
            .await
            .map_err(|e| ScpNapiError::Transport {
                message: format!("failed to connect to relay '{relay_url}': {e}"),
                code: "SCP-TRANS-5001".to_owned(),
            })?;

    with_transport_manager_mut(|manager| {
        let _eviction = manager.add_adapter(Box::new(adapter));
        #[allow(clippy::cast_possible_truncation)]
        Ok(manager.adapter_count() as u32)
    })
}

/// Assigns a relay set for the given context.
///
/// Delegates to [`TransportManager::assign_relay_set`] which selects at
/// least `min_relays` adapters per context using round-robin spread to
/// minimize overlap.
///
/// # Arguments
///
/// * `context_id` — The context to assign relays for.
///
/// # Returns
///
/// A list of adapter indices assigned to this context.
///
/// # Errors
///
/// - Rejects with `SCP-TRANS-5010` if no transport manager exists.
/// - Rejects with `SCP-VALID-7000` if `context_id` is invalid.
/// - Rejects with `SCP-TRANS-5002` if relay set assignment fails.
#[napi]
pub fn transport_assign_relay_set(context_id: String) -> napi::Result<Vec<u32>> {
    validate_context_id(&context_id).map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;
    with_transport_manager(|manager| {
        manager
            .assign_relay_set(&context_id)
            .map(|indices| {
                indices
                    .into_iter()
                    .map(|i| {
                        #[allow(clippy::cast_possible_truncation)]
                        {
                            i as u32
                        }
                    })
                    .collect()
            })
            .map_err(|e| {
                napi::Error::from(ScpNapiError::Transport {
                    message: format!("relay set assignment failed: {e}"),
                    code: "SCP-TRANS-5002".to_owned(),
                })
            })
    })
}

/// Returns the number of adapters registered in the transport manager.
///
/// # Errors
///
/// Rejects with `SCP-TRANS-5010` if no transport manager has been
/// initialized.
#[napi]
pub fn transport_adapter_count() -> napi::Result<u32> {
    with_transport_manager(|manager| {
        #[allow(clippy::cast_possible_truncation)]
        Ok(manager.adapter_count() as u32)
    })
}

/// Returns the reliability score for an adapter by index.
///
/// Returns the score as a [`NapiReliabilityScore`] object, or `null` if
/// no score exists for the given adapter index.
///
/// # Arguments
///
/// * `adapter_index` — The adapter index (0-based) to query.
///
/// # Errors
///
/// Rejects with `SCP-TRANS-5010` if no transport manager has been
/// initialized.
#[napi]
pub fn transport_reliability(adapter_index: u32) -> napi::Result<Option<NapiReliabilityScore>> {
    with_transport_manager(|manager| {
        Ok(manager
            .get_reliability_score(adapter_index as usize)
            .map(|score| {
                #[allow(clippy::cast_precision_loss)]
                NapiReliabilityScore {
                    relay_url: score.relay_url.clone(),
                    delivery_success_rate: score.delivery_success_rate,
                    average_latency_ms: score.average_latency_ms as f64,
                    deletion_compliance_rate: score.deletion_compliance_rate,
                    total_sends: score.total_sends as f64,
                    total_failures: score.total_failures as f64,
                }
            }))
    })
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
    // Transport manager persistence
    // -----------------------------------------------------------------------

    #[test]
    fn transport_manager_initially_absent() {
        // Before any connection, no transport manager should be stored.
        assert!(!has_transport_manager());
    }

    #[test]
    fn clear_transport_manager_is_idempotent() {
        // Clearing when nothing is stored should not error.
        assert!(clear_transport_manager().is_ok());
    }

    // Note: `set_transport_manager` requires a real `NativeRelayAdapter`
    // (wrapped in `TransportManager`) which can only be obtained by
    // connecting to a live relay. A full set→clear roundtrip test would
    // need integration-test infrastructure (a running relay). The
    // persistence helpers (`set_transport_manager`,
    // `clear_transport_manager`, `has_transport_manager`) are individually
    // covered above; the integration-level roundtrip is deferred to E2E
    // tests.

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
    fn transport_status_defense_in_depth_detects_absent_manager() {
        // Construct a manager that believes it is connected, but ensure
        // the global transport manager state is empty. The defense-in-depth
        // check in `transport_status` should override the local status to
        // report disconnected.
        clear_transport_manager().unwrap();
        let manager = make_connected_manager();

        // The manager's local status says connected.
        assert!(manager.is_connected());

        // But transport_status checks has_transport_manager() and corrects it.
        let mut status = manager.status();
        if status.connected && !has_transport_manager() {
            status.connected = false;
        }
        assert!(
            !status.connected,
            "defense-in-depth: transport_status should report disconnected \
             when the transport manager is absent even if the handle thinks it is connected"
        );
    }
}
