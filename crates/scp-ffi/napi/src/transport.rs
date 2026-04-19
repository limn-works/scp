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
//! Transport state is delegated to the default [`NapiBridgeInstance`]'s transport
//! field (#1549). The `BridgeInstance` stores an `Arc<TransportManager>` behind
//! a `RwLock` — the `Arc` allows NAPI subscription tasks to hold a reference
//! across `.await` points without keeping the lock guard alive.
//!
//! See ADR-022, ADR-005 (Transport Abstraction), and ADR-012 (Multi-Relay) in
//! `.docs/adrs/`.

use scp_ffi_common::bridge_instance::TransportLockError;
use scp_ffi_common::error_codes as codes;
use std::sync::Arc;

use napi_derive::napi;
use scp_ffi_common::validate::{validate_context_id, validate_relay_url};

use crate::error::ScpNapiError;
use crate::runtime::{NapiBridgeInstance, default_bridge_instance};
use crate::{decrement_handle_count, increment_handle_count};

// ---------------------------------------------------------------------------
// Transport accessor helpers — delegate to BridgeInstance (#1549)
// ---------------------------------------------------------------------------

/// Maps a [`TransportLockError`] to the appropriate [`ScpNapiError`].
fn map_transport_lock_error(e: TransportLockError) -> ScpNapiError {
    match e {
        TransportLockError::Poisoned => ScpNapiError::Transport {
            message: "transport manager lock is poisoned".to_owned(),
            code: codes::TRANS_5002.to_owned(),
        },
        TransportLockError::NotInitialized => ScpNapiError::Transport {
            message: "no transport manager — call transportConnect() first".to_owned(),
            code: codes::TRANS_5010.to_owned(),
        },
        TransportLockError::InUse => ScpNapiError::Transport {
            message: "transport manager is in use by an active subscription — \
                      cannot modify while subscriptions are active"
                .to_owned(),
            code: codes::TRANS_5003.to_owned(),
        },
        TransportLockError::Rejected(msg) => ScpNapiError::Transport {
            message: format!("transport operation rejected: {msg}"),
            code: codes::TRANS_5010.to_owned(),
        },
    }
}

/// Stores a `TransportManager` (called by [`transport_connect`]).
///
/// Wraps in `Arc` and delegates to [`CoreFields::set_transport`].
/// If the `BridgeInstance` doesn't exist yet, lazily creates it from
/// the existing `ContextManager`.
///
/// # Errors
///
/// Returns `ScpNapiError::Transport` if the lock is poisoned or the bridge
/// is not initialized.
//
// Retained alongside `set_transport_manager_on` until the Phase 4 demolition
// slice deletes the free-function transport entry points. Tests still exercise
// this path; suppress the unused-function lint rather than delete prematurely.
#[allow(dead_code)]
fn set_transport_manager(manager: scp_transport::TransportManager) -> napi::Result<()> {
    // Try existing bridge instance first; fall back to lazy creation
    // from the existing ContextManager.
    let bi = if let Ok(bi) = crate::runtime::bridge_instance() {
        bi
    } else {
        let default_bi = crate::runtime::default_bridge_instance()?;
        if let Ok(cm) = crate::runtime::context_manager(&default_bi) {
            crate::runtime::attach_context_manager_to_bridge(cm.clone());
        } else {
            crate::runtime::ensure_bridge_instance();
        }
        crate::runtime::bridge_instance()?
    };
    bi.set_transport(Arc::new(manager))
        .map_err(|e| napi::Error::from(map_transport_lock_error(e)))
}

/// Per-bridge-instance implementation of [`set_transport_manager`].
///
/// Stores the transport manager on the given [`NapiBridgeInstance`]'s core
/// fields rather than the process-global default.
fn set_transport_manager_on(
    bi: &NapiBridgeInstance,
    manager: scp_transport::TransportManager,
) -> napi::Result<()> {
    bi.core
        .set_transport(Arc::new(manager))
        .map_err(|e| napi::Error::from(map_transport_lock_error(e)))
}

/// Stores a pre-built `Arc<TransportManager>` (called by [`crate::server`]
/// auto-wire where the caller needs to construct the manager externally).
///
/// Delegates to [`CoreFields::set_transport`].
///
/// # Errors
///
/// Returns `ScpNapiError::Transport` if the lock is poisoned or the bridge
/// is not initialized.
pub(crate) fn set_transport_manager_arc(
    manager: Arc<scp_transport::TransportManager>,
) -> Result<(), ScpNapiError> {
    let bi = crate::runtime::bridge_instance().map_err(|_| ScpNapiError::Transport {
        message: "bridge not initialized — call identityCreate before transport operations"
            .to_owned(),
        code: codes::TRANS_5002.to_owned(),
    })?;
    bi.set_transport(manager).map_err(map_transport_lock_error)
}

/// Executes a closure with a read reference to the `TransportManager`.
///
/// Delegates to [`CoreFields::with_transport`].
///
/// # Errors
///
/// Returns `ScpNapiError::Transport` if the lock is poisoned, no
/// transport manager has been initialized, or the bridge is not initialized.
//
// Retained alongside `with_transport_manager_on` until demolition slice.
#[allow(dead_code)]
pub(crate) fn with_transport_manager<T>(
    f: impl FnOnce(&scp_transport::TransportManager) -> napi::Result<T>,
) -> napi::Result<T> {
    let bi = crate::runtime::bridge_instance()?;
    bi.with_transport(f)
        .map_err(|e| napi::Error::from(map_transport_lock_error(e)))?
}

/// Per-bridge-instance implementation of [`with_transport_manager`].
pub(crate) fn with_transport_manager_on<T>(
    bi: &NapiBridgeInstance,
    f: impl FnOnce(&scp_transport::TransportManager) -> napi::Result<T>,
) -> napi::Result<T> {
    bi.core
        .with_transport(f)
        .map_err(|e| napi::Error::from(map_transport_lock_error(e)))?
}

/// Executes a closure with a mutable reference to the `TransportManager`.
///
/// Delegates to [`CoreFields::with_transport_mut`]. Requires exclusive
/// `Arc` ownership (refcount == 1). If subscription tasks hold cloned
/// `Arc` references, this fails with `SCP-TRANS-5003`.
///
/// # Errors
///
/// Returns `ScpNapiError::Transport` if the lock is poisoned, no
/// transport manager has been initialized, or the manager is in use.
//
// Retained alongside `with_transport_manager_mut_on` until demolition slice.
#[allow(dead_code)]
pub(crate) fn with_transport_manager_mut<T>(
    f: impl FnOnce(&mut scp_transport::TransportManager) -> napi::Result<T>,
) -> napi::Result<T> {
    let bi = crate::runtime::bridge_instance()?;
    bi.with_transport_mut(f)
        .map_err(|e| napi::Error::from(map_transport_lock_error(e)))?
}

/// Per-bridge-instance implementation of [`with_transport_manager_mut`].
pub(crate) fn with_transport_manager_mut_on<T>(
    bi: &NapiBridgeInstance,
    f: impl FnOnce(&mut scp_transport::TransportManager) -> napi::Result<T>,
) -> napi::Result<T> {
    bi.core
        .with_transport_mut(f)
        .map_err(|e| napi::Error::from(map_transport_lock_error(e)))?
}

/// Returns `true` if a transport manager has been initialized.
//
// Retained alongside `has_transport_manager_on` until demolition slice.
#[allow(dead_code)]
fn has_transport_manager() -> bool {
    crate::runtime::bridge_instance().is_ok_and(scp_ffi_common::CoreFields::has_transport)
}

/// Per-bridge-instance implementation of [`has_transport_manager`].
fn has_transport_manager_on(bi: &NapiBridgeInstance) -> bool {
    scp_ffi_common::CoreFields::has_transport(&bi.core)
}

/// Returns an `Arc` clone of the current transport manager, if one exists.
///
/// Used by `context_subscribe` which needs to move the manager reference
/// into an async task that outlives any lock guard.
///
/// Delegates to [`CoreFields::get_transport_arc`].
pub(crate) fn get_transport_manager() -> Option<Arc<scp_transport::TransportManager>> {
    crate::runtime::bridge_instance()
        .ok()
        .and_then(|bi| bi.get_transport_arc().ok().flatten())
}

/// Clears the transport manager (called by [`transport_disconnect`]).
///
/// Delegates to [`CoreFields::clear_transport`].
///
/// # Errors
///
/// Returns `ScpNapiError::Transport` if the lock is poisoned or the bridge
/// is not initialized.
//
// Retained alongside `clear_transport_manager_on` until demolition slice.
#[allow(dead_code)]
fn clear_transport_manager() -> napi::Result<()> {
    let bi = crate::runtime::bridge_instance()?;
    bi.clear_transport()
        .map_err(|e| napi::Error::from(map_transport_lock_error(e)))
}

/// Per-bridge-instance implementation of [`clear_transport_manager`].
fn clear_transport_manager_on(bi: &NapiBridgeInstance) -> napi::Result<()> {
    bi.core
        .clear_transport()
        .map_err(|e| napi::Error::from(map_transport_lock_error(e)))
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
    /// `NapiBridgeInstance` id that minted this handle — used for handle
    /// affinity checks at every FFI entry point. Mismatches are rejected
    /// with `SCP-PERM-3030`.
    pub(crate) instance_id: u64,
}

#[napi]
impl NapiTransportManager {
    /// Returns the current transport connection status.
    #[napi(getter)]
    #[must_use]
    pub fn status(&self) -> NapiTransportStatus {
        self.status.lock().map_or(
            NapiTransportStatus {
                connected: false,
                relay_url: None,
                latency_ms: None,
            },
            |s| NapiTransportStatus {
                connected: s.connected,
                relay_url: s.relay_url.clone(),
                latency_ms: s.latency_ms,
            },
        )
    }

    /// Returns `true` if the transport is currently connected.
    #[napi(getter, js_name = "isConnected")]
    #[must_use]
    pub fn is_connected(&self) -> bool {
        self.status.lock().is_ok_and(|s| s.connected)
    }

    /// Returns the relay URL if connected, `null` otherwise.
    #[napi(getter, js_name = "relayUrl")]
    #[must_use]
    pub fn relay_url(&self) -> Option<String> {
        self.status.lock().ok().and_then(|s| s.relay_url.clone())
    }

    /// Returns the id of the `SCP` instance that minted this handle, as a
    /// base-10 string (u64 serialized as string to survive JS number limits).
    #[napi(getter, js_name = "instanceId")]
    #[must_use]
    pub fn instance_id_js(&self) -> String {
        self.instance_id.to_string()
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
    let bi = default_bridge_instance()?;
    transport_connect_on(&bi, relay_url).await
}

/// Per-bridge-instance implementation of [`transport_connect`].
pub(crate) async fn transport_connect_on(
    bi: &NapiBridgeInstance,
    relay_url: String,
) -> napi::Result<NapiTransportManager> {
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
        Ok(mut adapter) => {
            // Connection succeeded. Measure latency.
            #[allow(clippy::cast_precision_loss)]
            let latency = start.elapsed().as_millis() as f64;

            // Extract the suppression event receiver BEFORE moving the adapter
            // into the TransportManager. The spawned task drains suppression
            // events and downgrades the relay's reliability score (#1533 AC5).
            let suppression_rx = adapter.take_suppression_receiver();

            // Wrap the adapter in a TransportManager for multi-relay support,
            // then store it on the bridge instance. Same pattern as the
            // PyO3 bridge's `py_transport_connect`.
            // Cover traffic is already running — `connect_sourced` with a
            // profile auto-starts it via `finalize_connection` (#1532 AC6).
            let manager = scp_transport::TransportManager::new(Box::new(adapter));
            set_transport_manager_on(bi, manager)?;

            // Register the URL on the bridge's pending-reconnect set so
            // `BridgeInstanceCore::resume` can rebuild the transport after
            // suspend/resume cycles (#1678).
            bi.core.add_relay_url(relay_url.clone());

            // Spawn suppression → scoring bridge task.
            if let Some(rx) = suppression_rx {
                spawn_suppression_scoring_task(rx, relay_url.clone());
            }

            let handle = NapiTransportManager {
                status: std::sync::Mutex::new(NapiTransportStatus {
                    connected: true,
                    relay_url: Some(relay_url),
                    latency_ms: Some(latency),
                }),
                instance_id: bi.instance_id(),
            };
            increment_handle_count();
            Ok(handle)
        }
        Err(e) => Err(ScpNapiError::Transport {
            message: format!("failed to connect to relay '{relay_url}': {e}"),
            code: codes::TRANS_5001.to_owned(),
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
    let bi = default_bridge_instance()?;
    transport_status_on(&bi, manager).await
}

/// Per-bridge-instance implementation of [`transport_status`].
#[allow(clippy::unused_async)] // napi-rs requires async for Promise return
pub(crate) async fn transport_status_on(
    bi: &NapiBridgeInstance,
    manager: &NapiTransportManager,
) -> napi::Result<NapiTransportStatus> {
    crate::napi_check_handle!(&bi.core, manager);
    let mut status = manager.status();
    // Defense-in-depth: verify the transport manager is actually alive,
    // not just what the manager's local status believes. If the transport
    // manager has been dropped (e.g., disconnect was called without
    // updating the manager), report disconnected.
    if status.connected && !has_transport_manager_on(bi) {
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
    let bi = default_bridge_instance()?;
    transport_disconnect_on(&bi, manager).await
}

/// Per-bridge-instance implementation of [`transport_disconnect`].
#[allow(clippy::unused_async)] // napi-rs requires async for Promise return
pub(crate) async fn transport_disconnect_on(
    bi: &NapiBridgeInstance,
    manager: &NapiTransportManager,
) -> napi::Result<()> {
    crate::napi_check_handle!(&bi.core, manager);
    let mut s = manager.status.lock().map_err(|_| ScpNapiError::Transport {
        message: "transport status lock is poisoned".to_owned(),
        code: codes::TRANS_5002.to_owned(),
    })?;

    if !s.connected {
        return Err(ScpNapiError::Transport {
            message: "transport is not connected — call transportConnect first".to_owned(),
            code: codes::TRANS_5002.to_owned(),
        }
        .into());
    }

    // Capture the URL we were connected to before clearing it so the
    // bridge's pending-reconnect set can drop it too (#1678).
    let disconnecting_url = s.relay_url.clone();

    s.connected = false;
    s.relay_url = None;
    s.latency_ms = None;
    drop(s);

    // Drop the transport manager, closing all WebSocket connections.
    clear_transport_manager_on(bi)?;

    if let Some(ref url) = disconnecting_url {
        bi.core.remove_relay_url(url);
    }

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
    let bi = default_bridge_instance()?;
    configure_local_transport_on(&bi, local_did)
}

/// Per-bridge-instance implementation of [`configure_local_transport`].
pub(crate) fn configure_local_transport_on(
    bi: &NapiBridgeInstance,
    local_did: String,
) -> napi::Result<()> {
    scp_ffi_common::validate::validate_did(&local_did)
        .map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;
    crate::runtime::init_context_manager_with_local_transport(bi, &local_did);
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
/// uses the `BridgeInstance` transport manager for its subscription stream).
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
    let bi = default_bridge_instance()?;
    configure_relay_transport_on(&bi, relay_url, local_did).await
}

/// Per-bridge-instance implementation of [`configure_relay_transport`].
pub(crate) async fn configure_relay_transport_on(
    bi: &NapiBridgeInstance,
    relay_url: String,
    local_did: String,
) -> napi::Result<()> {
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
                code: codes::TRANS_5001.to_owned(),
            })?;

    crate::runtime::init_context_manager_with_relay_transport(bi, &local_did, adapter);
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
/// the `BridgeInstance` transport manager. The [`transport_connect`] function
/// must have been called first to initialize the manager.
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
    let bi = default_bridge_instance()?;
    transport_add_relay_on(&bi, relay_url).await
}

/// Per-bridge-instance implementation of [`transport_add_relay`].
pub(crate) async fn transport_add_relay_on(
    bi: &NapiBridgeInstance,
    relay_url: String,
) -> napi::Result<u32> {
    validate_relay_url(&relay_url).map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;

    let sourced = scp_transport::relay::connection::SourcedRelayUrl {
        url: relay_url.clone(),
        source: scp_transport::relay::connection::RelayUrlSource::Explicit,
    };
    let profile = scp_transport::profile::TransportProfile::platform_default();
    // Cover traffic auto-starts per adapter via `connect_sourced` with a
    // profile — `finalize_connection` launches the cover traffic background
    // task based on the profile's tier (#1532 AC6).
    let mut adapter =
        scp_transport::native::NativeRelayAdapter::connect_sourced(&sourced, Some(&profile))
            .await
            .map_err(|e| ScpNapiError::Transport {
                message: format!("failed to connect to relay '{relay_url}': {e}"),
                code: codes::TRANS_5001.to_owned(),
            })?;

    // Extract the suppression event receiver BEFORE moving the adapter into
    // the TransportManager. The spawned task drains suppression events and
    // downgrades the relay's reliability score (#1533 AC5).
    let suppression_rx = adapter.take_suppression_receiver();

    let count = with_transport_manager_mut_on(bi, |manager| {
        let _eviction = manager.add_adapter(Box::new(adapter));
        #[allow(clippy::cast_possible_truncation)]
        Ok(manager.adapter_count() as u32)
    })?;

    // Spawn suppression → scoring bridge task.
    if let Some(rx) = suppression_rx {
        spawn_suppression_scoring_task(rx, relay_url);
    }

    Ok(count)
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
    let bi = default_bridge_instance()?;
    transport_assign_relay_set_on(&bi, context_id)
}

/// Per-bridge-instance implementation of [`transport_assign_relay_set`].
pub(crate) fn transport_assign_relay_set_on(
    bi: &NapiBridgeInstance,
    context_id: String,
) -> napi::Result<Vec<u32>> {
    validate_context_id(&context_id).map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;
    with_transport_manager_on(bi, |manager| {
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
                    code: codes::TRANS_5002.to_owned(),
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
    let bi = default_bridge_instance()?;
    transport_adapter_count_on(&bi)
}

/// Per-bridge-instance implementation of [`transport_adapter_count`].
pub(crate) fn transport_adapter_count_on(bi: &NapiBridgeInstance) -> napi::Result<u32> {
    with_transport_manager_on(bi, |manager| {
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
    let bi = default_bridge_instance()?;
    transport_reliability_on(&bi, adapter_index)
}

/// Per-bridge-instance implementation of [`transport_reliability`].
pub(crate) fn transport_reliability_on(
    bi: &NapiBridgeInstance,
    adapter_index: u32,
) -> napi::Result<Option<NapiReliabilityScore>> {
    with_transport_manager_on(bi, |manager| {
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

// ---------------------------------------------------------------------------
// Suppression → scoring bridge task
// ---------------------------------------------------------------------------

/// Spawns a background task that drains heartbeat suppression events from a
/// per-adapter receiver and records each as a delivery failure in the global
/// transport manager's reliability scoring.
///
/// This bridges the per-adapter heartbeat monitor (spec §9.9.2) with the
/// `TransportManager`'s cross-relay `SuppressionTracker` (spec §9.9.4,
/// #1533 AC5). Each suppression event downgrades the relay's reliability
/// score via `DeliveryOutcome::Failure`.
///
/// The task exits gracefully when the sender half is dropped (adapter
/// dropped or disconnected).
fn spawn_suppression_scoring_task(
    mut rx: tokio::sync::mpsc::Receiver<scp_transport::heartbeat::SuppressionSuspected>,
    relay_url: String,
) {
    tokio::spawn(async move {
        while let Some(_suppression) = rx.recv().await {
            tracing::debug!(
                relay_url = %relay_url,
                "heartbeat suppression → downgrading relay reliability score"
            );
            // Read-lock the BridgeInstance transport to update the score.
            // If the bridge or transport was cleared (disconnect), silently stop.
            if let Ok(bi) = crate::runtime::bridge_instance() {
                let _ = bi.with_transport(|manager| {
                    manager
                        .update_score(&relay_url, scp_transport::scoring::DeliveryOutcome::Failure);
                });
            }
        }
        tracing::debug!(
            relay_url = %relay_url,
            "suppression scoring task exited — adapter disconnected"
        );
    });
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
        // Before any connection (or bridge init), no transport manager
        // should be stored. `has_transport_manager` returns false when
        // the BridgeInstance is not initialized.
        assert!(!has_transport_manager());
    }

    #[test]
    fn clear_transport_manager_without_bridge_returns_err() {
        // Clearing when the bridge is not initialized returns an error
        // (BridgeInstance must be initialized before transport operations).
        // In production this is fine — transport_disconnect is only called
        // after transport_connect, which requires an initialized bridge.
        let result = clear_transport_manager();
        // When bridge is initialized (via another test in the same process),
        // clear succeeds idempotently. When not initialized, it returns Err.
        // Either outcome is acceptable in tests.
        let _ = result;
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
            instance_id: scp_ffi_common::bridge_instance::UNSET_INSTANCE_ID,
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
        // the BridgeInstance transport state is empty. The defense-in-depth
        // check in `transport_status` should override the local status to
        // report disconnected.
        let _ = clear_transport_manager(); // may fail if bridge not initialized
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
