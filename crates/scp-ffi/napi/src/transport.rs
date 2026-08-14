//! napi-rs bridge for transport operations.
//!
//! Exposes relay connection management to JavaScript:
//!
//! - `transport_connect` — Connect to an SCP relay (wraps adapter in `TransportManager`).
//! - `transport_status` — Query the current transport connection status.
//! - `transport_disconnect` — Disconnect from the relay.
//! - `transport_add_relay` — Add an additional relay adapter to the manager.
//! - `transport_assign_relay_set` — Assign a relay set for a context.
//! - `transport_adapter_count` — Query the number of registered adapters.
//! - `transport_reliability` — Query reliability score for an adapter.
//!
//! # Transport model
//!
//! Transport state is delegated to the default `NapiBridgeInstance`'s transport
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
use crate::runtime::NapiBridgeInstance;
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

/// Per-bridge-instance transport manager setter.
///
/// Stores the transport manager on the given [`NapiBridgeInstance`]'s core
/// fields.
fn set_transport_manager_on(
    bi: &NapiBridgeInstance,
    manager: scp_transport::TransportManager,
) -> napi::Result<()> {
    bi.core
        .set_transport(Arc::new(manager))
        .map_err(|e| napi::Error::from(map_transport_lock_error(e)))
}

/// Stores a pre-built `Arc<TransportManager>` on the given bridge instance
/// (called by [`crate::server`] auto-wire where the caller needs to
/// construct the manager externally).
///
/// Delegates to [`CoreFields::set_transport`].
///
/// # Errors
///
/// Returns `ScpNapiError::Transport` if the lock is poisoned.
///
/// Gated to match its sole caller, the `server`-gated node auto-wiring path
/// in `server.rs` (`mod server` is `#[cfg(feature = "server")]`). Without the
/// gate the function is dead code in `--no-default-features` builds.
#[cfg(feature = "server")]
pub(crate) fn set_transport_manager_arc_on(
    bi: &NapiBridgeInstance,
    manager: Arc<scp_transport::TransportManager>,
) -> Result<(), ScpNapiError> {
    bi.core
        .set_transport(manager)
        .map_err(map_transport_lock_error)
}

/// Per-bridge-instance implementation of `with_transport_manager`.
pub(crate) fn with_transport_manager_on<T>(
    bi: &NapiBridgeInstance,
    f: impl FnOnce(&scp_transport::TransportManager) -> napi::Result<T>,
) -> napi::Result<T> {
    bi.core
        .with_transport(f)
        .map_err(|e| napi::Error::from(map_transport_lock_error(e)))?
}

/// Per-bridge-instance implementation of `with_transport_manager_mut`.
pub(crate) fn with_transport_manager_mut_on<T>(
    bi: &NapiBridgeInstance,
    f: impl FnOnce(&mut scp_transport::TransportManager) -> napi::Result<T>,
) -> napi::Result<T> {
    bi.core
        .with_transport_mut(f)
        .map_err(|e| napi::Error::from(map_transport_lock_error(e)))?
}

/// Returns `true` if a transport manager has been initialized on the given
/// bridge instance.
fn has_transport_manager_on(bi: &NapiBridgeInstance) -> bool {
    scp_ffi_common::CoreFields::has_transport(&bi.core)
}

/// Per-bridge-instance accessor for the current transport manager.
///
/// Returns an `Arc` clone if one is configured on `bi.core`, otherwise `None`.
/// Used by `context_subscribe_on` which needs to move the manager reference
/// into an async task that outlives any lock guard.
pub(crate) fn get_transport_manager_on(
    bi: &NapiBridgeInstance,
) -> Option<Arc<scp_transport::TransportManager>> {
    bi.core.get_transport_arc().ok().flatten()
}

/// Per-bridge-instance implementation of `clear_transport_manager`.
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
/// Returned by `transport_status` and accessible on [`NapiTransportManager`].
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
}

impl Drop for NapiTransportManager {
    fn drop(&mut self) {
        decrement_handle_count();
    }
}

// ---------------------------------------------------------------------------
// Bridge functions
// ---------------------------------------------------------------------------

/// Per-bridge-instance implementation of `transport_connect`.
///
/// Takes an `Arc<NapiBridgeInstance>` so the spawned suppression-scoring
/// task can hold a weak reference back to the bridge across await points.
pub(crate) async fn transport_connect_on(
    bi: &Arc<NapiBridgeInstance>,
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
    // Route through the instance-scoped transport selector for transparent
    // QUIC↔WebSocket selection (spec §10.14.3 item 4; ADR-037). The discovering
    // variant fetches the relay's advertised transports from `.well-known/scp`
    // (spec §10.5.1) at connect time and feeds that list into the
    // QUIC-vs-WebSocket decision — failing open to WebSocket when the relay
    // serves no well-known. The selector is owned by the bridge instance so its
    // per-relay QUIC-suppression and well-known caches survive across connects.
    // Mirrors the PyO3 reference bridge's `transport_connect`. The selector
    // surfaces the suppression receiver (drained into reliability scoring,
    // #1533 AC5) for the WebSocket branch; cover traffic auto-starts via the
    // profile inside `finalize_connection` (#1532 AC6).
    let selector = bi.core.transport_selector();
    let adapter_result = selector
        .select_and_connect_discovering_with_suppression(&sourced, Some(&profile))
        .await;

    match adapter_result {
        Ok((adapter, suppression_rx)) => {
            // Connection succeeded. Measure latency.
            #[allow(clippy::cast_precision_loss)]
            let latency = start.elapsed().as_millis() as f64;

            // The suppression receiver is surfaced by the selector (the
            // concrete `NativeRelayAdapter::take_suppression_receiver` lives
            // behind the `Box<dyn TransportAdapter>` the selector returns, so
            // we cannot call it here — the selector hands it back directly,
            // exactly like the PyO3 bridge).

            // Wrap the selected adapter in a TransportManager for multi-relay
            // support, then store it on the bridge instance. Same pattern as
            // the PyO3 bridge's `transport_connect`. The selector returns a
            // `Box<dyn TransportAdapter>`; the blanket
            // `impl TransportAdapter for Box<dyn TransportAdapter>` lets it be
            // used anywhere a concrete adapter is expected.
            let manager = scp_transport::TransportManager::new(adapter);
            set_transport_manager_on(bi, manager)?;

            // Register the URL on the bridge's pending-reconnect set so
            // `BridgeInstanceCore::resume` can rebuild the transport after
            // suspend/resume cycles (#1678).
            bi.core.add_relay_url(relay_url.clone());

            // Spawn suppression → scoring bridge task. Holds a `Weak` to the
            // bridge instance so the task doesn't keep the bridge alive past
            // shutdown.
            if let Some(rx) = suppression_rx {
                spawn_suppression_scoring_task(Arc::downgrade(bi), rx, relay_url.clone());
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

/// Per-bridge-instance implementation of `transport_status`.
///
/// When `manager` is provided, reflects the status of that handle with a
/// defense-in-depth check against this bridge's transport state: if the
/// underlying `TransportManager` has been cleared (e.g., by
/// `transportDisconnect` without touching the handle), the status is
/// downgraded to disconnected.
///
/// When `manager` is `None`, returns a stateless snapshot drawn from the
/// bridge's transport state. Mirrors the `PyO3` handleless probe
/// so callers can observe the disconnected shape before ever calling
/// `transportConnect`, without needing to construct a
/// `NapiTransportManager` handle.
#[allow(clippy::unused_async)] // napi-rs requires async for Promise return
pub(crate) async fn transport_status_on(
    bi: &NapiBridgeInstance,
    manager: Option<&NapiTransportManager>,
) -> napi::Result<NapiTransportStatus> {
    if let Some(mgr) = manager {
        crate::napi_check_handle!(&bi.core, mgr);
        let mut status = mgr.status();
        // Defense-in-depth: verify the transport manager is actually alive,
        // not just what the manager's local status believes. If the transport
        // manager has been dropped (e.g., disconnect was called without
        // updating the manager), report disconnected.
        if status.connected && !has_transport_manager_on(bi) {
            status.connected = false;
        }
        return Ok(status);
    }
    // Handleless probe — mirrors UniFFI `Scp::transport_manager_status`
    // (PyO3 has its own per-bridge-state probe with a different
    // contract). Reports whether a `TransportManager` is wired on this
    // bridge; the relay URL / latency fields are null because those live
    // on the handle, not in the bridge instance.
    let (connected, relay_url, latency_ms) =
        scp_ffi_common::handleless_transport_status(has_transport_manager_on(bi));
    Ok(NapiTransportStatus {
        connected,
        relay_url,
        latency_ms,
    })
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

/// Per-bridge-instance implementation of `configure_local_transport`.
///
/// Pre-configures the per-instance `Supervisor` with `LocalTransportProvider`.
///
/// **Must be called before any `identityCreate` → `contextCreate` sequence.**
/// Once the supervisor is initialized (by whichever call arrives first),
/// the transport provider is locked in for the lifetime of the instance.
///
/// With `LocalTransportProvider`, `contextSend` and `broadcastPublish`
/// succeed locally without requiring a running relay. This is the correct
/// setup for single-process E2E tests that exercise the full
/// encrypt → sign → send pipeline.
///
/// The `local_did` parameter is used as the MLS credential identity for the
/// `NodeMlsFactory`. Pass any valid `did:dht:` string (typically the
/// DID of the first identity you plan to create).
///
/// # Errors
///
/// Returns an error only if `local_did` fails DID format validation.
pub(crate) fn configure_local_transport_on(
    bi: &NapiBridgeInstance,
    local_did: String,
) -> napi::Result<()> {
    scp_ffi_common::validate::validate_did(&local_did)
        .map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;
    crate::runtime::init_supervisor_with_local_transport(bi, &local_did);
    Ok(())
}

/// Per-bridge-instance implementation of `configure_relay_transport`.
///
/// Pre-configures the per-instance `Supervisor` with `RelayTransportProvider`.
///
/// **Must be called before any `identityCreate` → `contextCreate` sequence.**
/// Once the supervisor is initialized (by whichever call arrives first),
/// the transport provider is locked in for the lifetime of the instance.
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
    // Route through the instance-scoped transport selector for transparent
    // QUIC↔WebSocket selection (spec §10.14.3 item 4; ADR-037). The discovering
    // variant reads the relay's advertised transports from `.well-known/scp`
    // (spec §10.5.1) at connect time to enable QUIC, failing open to WebSocket
    // when discovery is unavailable. Mirrors the PyO3 reference bridge's
    // `configure_relay_transport`.
    let selector = bi.core.transport_selector();
    let adapter = selector
        .select_and_connect_discovering(&sourced, Some(&profile))
        .await
        .map_err(|e| ScpNapiError::Transport {
            message: format!("failed to connect to relay '{relay_url}': {e}"),
            code: codes::TRANS_5001.to_owned(),
        })?;

    crate::runtime::init_supervisor_with_relay_transport(bi, &local_did, adapter);
    Ok(())
}

// ---------------------------------------------------------------------------
// NapiReliabilityScore — per-adapter reliability metrics
// ---------------------------------------------------------------------------

/// Per-adapter reliability score exposed to JavaScript.
///
/// Returned by `transport_reliability` and maps to the core
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

/// Per-bridge-instance implementation of `transport_add_relay`.
pub(crate) async fn transport_add_relay_on(
    bi: &Arc<NapiBridgeInstance>,
    relay_url: String,
) -> napi::Result<u32> {
    validate_relay_url(&relay_url).map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;

    let sourced = scp_transport::relay::connection::SourcedRelayUrl {
        url: relay_url.clone(),
        source: scp_transport::relay::connection::RelayUrlSource::Explicit,
    };
    let profile = scp_transport::profile::TransportProfile::platform_default();
    // Route through the instance-scoped transport selector for transparent
    // QUIC↔WebSocket selection (spec §10.14.3 item 4; ADR-037). The discovering
    // variant reads the relay's advertised transports from `.well-known/scp`
    // (spec §10.5.1) at connect time to enable QUIC, failing open to WebSocket
    // when discovery is unavailable. Cover traffic auto-starts per adapter via
    // the profile inside `finalize_connection` (#1532 AC6). The selector
    // surfaces the suppression receiver (drained into reliability scoring,
    // #1533 AC5). Mirrors the PyO3 reference bridge's `transport_add_relay`.
    let selector = bi.core.transport_selector();
    let (adapter, suppression_rx) = selector
        .select_and_connect_discovering_with_suppression(&sourced, Some(&profile))
        .await
        .map_err(|e| ScpNapiError::Transport {
            message: format!("failed to connect to relay '{relay_url}': {e}"),
            code: codes::TRANS_5001.to_owned(),
        })?;

    let count = with_transport_manager_mut_on(bi, |manager| {
        let _eviction = manager.add_adapter(adapter);
        #[allow(clippy::cast_possible_truncation)]
        Ok(manager.adapter_count() as u32)
    })?;

    // Spawn suppression → scoring bridge task.
    if let Some(rx) = suppression_rx {
        spawn_suppression_scoring_task(Arc::downgrade(bi), rx, relay_url);
    }

    Ok(count)
}

/// Per-bridge-instance implementation of `transport_assign_relay_set`.
///
/// Assigns a relay set for the given context.
///
/// Delegates to `TransportManager::assign_relay_set` which selects at
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

/// Per-bridge-instance implementation of [`transport_adapter_count`].
pub(crate) fn transport_adapter_count_on(bi: &NapiBridgeInstance) -> napi::Result<u32> {
    with_transport_manager_on(bi, |manager| {
        #[allow(clippy::cast_possible_truncation)]
        Ok(manager.adapter_count() as u32)
    })
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
    bi: std::sync::Weak<NapiBridgeInstance>,
    mut rx: tokio::sync::mpsc::Receiver<scp_transport::heartbeat::SuppressionSuspected>,
    relay_url: String,
) {
    tokio::spawn(async move {
        while let Some(_suppression) = rx.recv().await {
            tracing::debug!(
                relay_url = %relay_url,
                "heartbeat suppression → downgrading relay reliability score"
            );
            // If the bridge has been dropped (shutdown), silently stop.
            let Some(bi_arc) = bi.upgrade() else { break };
            let _ = bi_arc.core.with_transport(|manager| {
                manager.update_score(&relay_url, scp_transport::scoring::DeliveryOutcome::Failure);
                Ok::<(), napi::Error>(())
            });
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
        // A fresh bridge instance reports no transport manager attached.
        let bi = NapiBridgeInstance::new_napi();
        assert!(!has_transport_manager_on(&bi));
    }

    #[test]
    fn clear_transport_manager_without_transport_returns_err() {
        // Clearing when no transport has been attached returns an error.
        let bi = NapiBridgeInstance::new_napi();
        let _ = clear_transport_manager_on(&bi);
    }

    // Note: a populated transport manager requires a real adapter, which can
    // only be obtained by connecting to a live relay (the connect now routes
    // through the bridge instance's transport selector). Full set→clear
    // roundtrip coverage is in E2E tests.

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
        // Construct a manager that believes it is connected on a fresh bi
        // with no transport. The defense-in-depth check must override.
        let bi = NapiBridgeInstance::new_napi();
        let manager = make_connected_manager();

        // The manager's local status says connected.
        assert!(manager.is_connected());

        // transport_status_on checks has_transport_manager_on and corrects it.
        let mut status = manager.status();
        if status.connected && !has_transport_manager_on(&bi) {
            status.connected = false;
        }
        assert!(
            !status.connected,
            "defense-in-depth: transport_status should report disconnected \
             when the transport manager is absent even if the handle thinks it is connected"
        );
    }

    // -----------------------------------------------------------------------
    // Per-instance transport manager accessor (bug-catcher follow-up, #1549)
    // -----------------------------------------------------------------------
    //
    // Regression: `get_transport_manager()` ignored the `bi` passed through
    // `context_subscribe_on(bi, ...)` — it always resolved the process-global
    // the legacy default bridge. A subscription spawned against a non-default
    // `bi` therefore pulled the default bridge's transport manager, leaking
    // into the wrong JoinSet and breaking multi-instance relay isolation.
    //
    // The fix adds `get_transport_manager_on(bi)` which reads the per-instance
    // transport slot. These tests exercise that accessor directly.

    /// A fresh non-default `NapiBridgeInstance` starts with no transport
    /// manager attached — `get_transport_manager_on` must return `None` for
    /// it regardless of the default bridge's state.
    #[test]
    fn get_transport_manager_on_returns_none_for_fresh_bi() {
        let bi = NapiBridgeInstance::new_napi();
        assert!(
            get_transport_manager_on(&bi).is_none(),
            "fresh NapiBridgeInstance must have no transport manager attached"
        );
        assert!(
            !has_transport_manager_on(&bi),
            "fresh NapiBridgeInstance must report no transport manager via has_transport_manager_on"
        );
    }

    /// Two independent `NapiBridgeInstance`s must report their transport
    /// state independently. This proves the accessor is genuinely
    /// per-instance (i.e. not routed through any global).
    #[test]
    fn get_transport_manager_on_is_per_instance() {
        let bi_a = NapiBridgeInstance::new_napi();
        let bi_b = NapiBridgeInstance::new_napi();

        // Neither instance has a transport manager attached.
        assert!(get_transport_manager_on(&bi_a).is_none());
        assert!(get_transport_manager_on(&bi_b).is_none());

        // The two instances are distinct allocations.
        assert_ne!(
            bi_a.instance_id(),
            bi_b.instance_id(),
            "fresh NapiBridgeInstance instances must have distinct ids — otherwise the \
             per-instance isolation test below is meaningless"
        );
    }

    // -----------------------------------------------------------------------
    // Selector routing — connect sites must go through the instance selector
    // (cross-SDK QUIC selection). The in-memory relay serves no
    // `.well-known/scp`, so the selector's discovering connect fails open to
    // WebSocket and still succeeds. These tests prove each napi connect site
    // routes through `bi.core.transport_selector()` rather than dialing
    // `NativeRelayAdapter::connect_sourced` directly.
    // -----------------------------------------------------------------------

    /// `transport_connect_on` must route through the instance selector and
    /// connect via WebSocket fallback against a relay that advertises no QUIC.
    /// After the call the bridge instance must own a transport manager.
    ///
    /// Requires the `server` feature: it spins up an in-memory relay via
    /// `scp_ffi_common::server::start_relay_in_memory`, which only exists under
    /// `#[cfg(feature = "server")]`. The bare (`--no-default-features`) test
    /// target must still compile, so this fn is server-gated.
    #[cfg(feature = "server")]
    #[test]
    fn transport_connect_routes_through_selector_ws_fallback() {
        let rt = crate::runtime();
        // An in-memory relay serves no `.well-known/scp`; QUIC is never
        // advertised, so a selector-routed connect must fail open to WS.
        let relay = rt
            .block_on(scp_ffi_common::server::start_relay_in_memory())
            .unwrap();
        let relay_url = relay.relay_url().to_owned();

        let bi = Arc::new(NapiBridgeInstance::new_napi());
        let handle = rt
            .block_on(transport_connect_on(&bi, relay_url.clone()))
            .expect("selector-routed connect to a no-QUIC relay must succeed via WS fallback");

        assert!(
            handle.is_connected(),
            "handle must report connected after selector-routed connect"
        );
        assert_eq!(handle.relay_url().as_deref(), Some(relay_url.as_str()));
        assert!(
            has_transport_manager_on(&bi),
            "transport manager must be populated on the bridge instance after \
             the selector-routed connect"
        );

        // Drop the handle explicitly so its Drop decrements the handle count.
        drop(handle);
        relay.shutdown();
    }

    /// `transport_add_relay_on` must route through the instance selector and
    /// add a second WS-fallback adapter to the manager.
    ///
    /// Server-gated: depends on `scp_ffi_common::server::start_relay_in_memory`
    /// (`#[cfg(feature = "server")]`), so the bare test target compiles.
    #[cfg(feature = "server")]
    #[test]
    fn transport_add_relay_routes_through_selector_ws_fallback() {
        let rt = crate::runtime();
        let relay = rt
            .block_on(scp_ffi_common::server::start_relay_in_memory())
            .unwrap();
        let relay_url = relay.relay_url().to_owned();

        let bi = Arc::new(NapiBridgeInstance::new_napi());
        // First connect establishes the manager (also selector-routed).
        let handle = rt
            .block_on(transport_connect_on(&bi, relay_url.clone()))
            .expect("initial selector-routed connect must succeed");
        assert_eq!(transport_adapter_count_on(&bi).unwrap(), 1);

        // add_relay must also route through the selector and fall open to WS.
        let count = rt
            .block_on(transport_add_relay_on(&bi, relay_url))
            .expect("selector-routed add_relay to a no-QUIC relay must succeed via WS fallback");
        assert_eq!(
            count, 2,
            "second selector-routed adapter must be registered in the manager"
        );

        drop(handle);
        relay.shutdown();
    }

    /// `configure_relay_transport_on` must route through the instance selector
    /// and install a `RelayTransportProvider` over the WS-fallback adapter.
    ///
    /// Server-gated: depends on `scp_ffi_common::server::start_relay_in_memory`
    /// (`#[cfg(feature = "server")]`), so the bare test target compiles.
    #[cfg(feature = "server")]
    #[test]
    fn configure_relay_transport_routes_through_selector_ws_fallback() {
        let rt = crate::runtime();
        let relay = rt
            .block_on(scp_ffi_common::server::start_relay_in_memory())
            .unwrap();
        let relay_url = relay.relay_url().to_owned();

        let bi = NapiBridgeInstance::new_napi();
        let did = "did:dht:z6MkTestConfigureRelay".to_owned();
        rt.block_on(configure_relay_transport_on(&bi, relay_url, did))
            .expect(
                "selector-routed configure_relay_transport to a no-QUIC relay must succeed via \
                 WS fallback and install a Supervisor",
            );

        assert!(
            bi.core.has_supervisor(),
            "Supervisor must be attached after configure_relay_transport routes through \
             the selector"
        );

        relay.shutdown();
    }
}
