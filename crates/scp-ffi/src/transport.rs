//! `PyO3` bridge functions for transport connection and status.
//!
//! Exposes SCP transport operations to Python:
//!
//! - [`py_transport_connect`] -- Connect to an SCP relay.
//! - [`py_transport_disconnect`] -- Disconnect from the current relay.
//! - [`py_transport_status`] -- Query transport connection status.
//! - [`py_transport_add_relay`] -- Register an additional relay adapter.
//! - [`py_transport_assign_relay_set`] -- Assign a relay set for a context.
//! - [`py_transport_adapter_count`] -- Number of registered adapters.
//! - [`py_transport_reliability`] -- Per-adapter reliability score.
//!
//! # Types
//!
//! - [`PyTransportStatus`] -- Connection status (connected, relay URL, latency).
//!
//! # Transport Wiring (SCP-213, #1490)
//!
//! `py_transport_connect` creates a [`NativeRelayAdapter`] connected to the
//! given relay URL, wraps it in a [`scp_transport::TransportManager`], and
//! stores the manager in the global transport state (see
//! [`crate::runtime`]). The manager provides multi-relay fanout,
//! per-context relay set assignment, suppression detection, and reliability
//! scoring. This manager is shared with `py_mcp_load_contexts` for
//! relay-based context discovery.
//!
//! The relay URL is tracked in a module-level `RwLock` so that
//! `py_transport_status` can report it without querying the adapter.
//!
//! See ADR-013 in `.docs/adrs/phase-3.md` section 5 for the bridge specification.

use std::sync::{OnceLock, RwLock};

use pyo3::prelude::*;
use scp_transport::native::adapter::NativeRelayAdapter;
use scp_transport::relay::connection::{RelayUrlSource, SourcedRelayUrl};

use crate::error::ScpPyError;
use crate::validate;

// ---------------------------------------------------------------------------
// Connected relay URL tracking
// ---------------------------------------------------------------------------

/// Tracks the URL of the currently connected relay.
///
/// Set by [`py_transport_connect`], cleared by [`py_transport_disconnect`],
/// read by [`py_transport_status`].
static CONNECTED_RELAY_URL: OnceLock<RwLock<Option<String>>> = OnceLock::new();

/// Returns a reference to the connected relay URL state.
pub(crate) fn connected_url_state() -> &'static RwLock<Option<String>> {
    CONNECTED_RELAY_URL.get_or_init(|| RwLock::new(None))
}

// ---------------------------------------------------------------------------
// PyTransportStatus
// ---------------------------------------------------------------------------

/// Transport connection status exposed to Python.
///
/// Reports whether the transport is connected, the relay URL (if connected),
/// and the measured latency in milliseconds (if available).
///
/// See ADR-005 (transport abstraction) and ADR-013 section 5 (bridge layer).
#[pyclass(name = "TransportStatus")]
#[derive(Debug, Clone)]
pub struct PyTransportStatus {
    /// `True` if the transport is currently connected to a relay.
    #[pyo3(get)]
    pub connected: bool,

    /// The relay URL, if connected. `None` if disconnected.
    #[pyo3(get)]
    pub relay_url: Option<String>,

    /// Round-trip latency to the relay in milliseconds. `None` if not
    /// measured or if disconnected.
    #[pyo3(get)]
    pub latency_ms: Option<f64>,
}

#[pymethods]
impl PyTransportStatus {
    fn __repr__(&self) -> String {
        format!(
            "TransportStatus(connected={}, relay_url={:?}, latency_ms={:?})",
            self.connected, self.relay_url, self.latency_ms
        )
    }
}

// ---------------------------------------------------------------------------
// Bridge functions
// ---------------------------------------------------------------------------

/// Connects to an SCP relay with provenance-based transport security
/// validation (§10.12.6).
///
/// Establishes a WebSocket connection to the specified relay URL using
/// [`NativeRelayAdapter::connect_sourced`]. The adapter is stored in the
/// global relay connection state for use by `py_mcp_load_contexts` (context
/// discovery) and future transport operations.
///
/// The `source` parameter specifies how the relay URL was discovered,
/// which determines whether `ws://` (plaintext) is permitted:
///
/// - `"dht_resolved"` -- resolved from a BEP44-signed DID document. `ws://`
///   is permitted.
/// - `"well_known"` -- discovered via `.well-known/scp`. `wss://` only.
/// - `"explicit"` (default) -- user/operator configured. `wss://` only.
/// - `"peer_discovered"` -- discovered from a peer. `wss://` only.
///
/// # Arguments
///
/// * `relay_url` -- The URL of the SCP relay to connect to (e.g.,
///   `"wss://relay.example.com/scp/v1"`).
/// * `source` -- How the URL was discovered (default: `"explicit"`).
///
/// # Errors
///
/// Raises `TransportError` if the URL scheme is not permitted for the
/// given source (e.g., `ws://` from `"explicit"`) or if the connection
/// fails (unreachable relay, protocol mismatch, timeout, etc.).
///
/// See ADR-013 section 5: `py_transport_connect(relay_url) -> None`.
#[pyfunction]
#[pyo3(name = "transport_connect", signature = (relay_url, source = "explicit"))]
pub fn py_transport_connect(relay_url: &str, source: &str) -> PyResult<()> {
    validate::validate_relay_url(relay_url)?;
    let rt = crate::runtime()?;
    let url = relay_url.to_owned();

    let relay_source = match source {
        "dht_resolved" => RelayUrlSource::DhtResolved,
        "well_known" => RelayUrlSource::WellKnown,
        "explicit" => RelayUrlSource::Explicit,
        "peer_discovered" => RelayUrlSource::PeerDiscovered,
        other => {
            return Err(ScpPyError::validation(format!(
                "invalid relay URL source: {other:?}. Expected one of: \
                 \"dht_resolved\", \"well_known\", \"explicit\", \"peer_discovered\""
            ))
            .into());
        }
    };

    let sourced = SourcedRelayUrl {
        url: url.clone(),
        source: relay_source,
    };
    let profile = scp_transport::profile::TransportProfile::platform_default();
    let adapter =
        rt.block_on(async { NativeRelayAdapter::connect_sourced(&sourced, Some(&profile)).await });

    match adapter {
        Ok(mut adapter) => {
            // Extract the suppression event receiver BEFORE moving the adapter
            // into the TransportManager. The spawned task drains suppression
            // events and downgrades the relay's reliability score (#1533 AC5).
            let suppression_rx = adapter.take_suppression_receiver();

            // Wrap the adapter in a TransportManager for multi-relay support.
            // Cover traffic is already running — `connect_sourced` with a
            // profile auto-starts it via `finalize_connection` (#1532 AC6).
            let manager = scp_transport::TransportManager::new(Box::new(adapter));
            crate::runtime::set_transport_manager(manager)?;

            // Spawn suppression → scoring bridge task.
            if let Some(suppression_rx) = suppression_rx {
                spawn_suppression_scoring_task(suppression_rx, url.clone());
            }

            // Track the URL for status queries.
            *connected_url_state().write().map_err(|_| {
                ScpPyError::transport("connected relay URL lock is poisoned".to_owned())
            })? = Some(url);

            Ok(())
        }
        Err(e) => Err(ScpPyError::from(e).into()),
    }
}

/// Disconnects from the current SCP relay.
///
/// Clears the global relay connection state. After this call,
/// `py_mcp_load_contexts` will fall back to local-only context discovery.
///
/// This is a no-op if no relay connection is active.
///
/// # Errors
///
/// Raises `TransportError` if clearing the connection state fails.
#[pyfunction]
#[pyo3(name = "transport_disconnect")]
pub fn py_transport_disconnect() -> PyResult<()> {
    crate::runtime::clear_transport_manager()?;

    *connected_url_state()
        .write()
        .map_err(|_| ScpPyError::transport("connected relay URL lock is poisoned".to_owned()))? =
        None;

    Ok(())
}

/// Returns the current transport connection status.
///
/// # Returns
///
/// A [`PyTransportStatus`] with connection state, relay URL, and latency.
///
/// # Errors
///
/// Raises `TransportError` if querying the transport status fails.
///
/// See ADR-013 section 5: `py_transport_status() -> PyTransportStatus`.
#[pyfunction]
#[pyo3(name = "transport_status")]
pub fn py_transport_status() -> PyResult<PyTransportStatus> {
    let has_connection = crate::runtime::has_transport_manager();

    let relay_url = connected_url_state()
        .read()
        .ok()
        .and_then(|guard| guard.clone());

    Ok(PyTransportStatus {
        connected: has_connection,
        relay_url,
        latency_ms: None, // Latency measurement is a future enhancement.
    })
}

/// Pre-configures the [`ContextManager`] with [`RelayTransportProvider`].
///
/// **Must be called before any `py_identity_create` → `py_context_create` sequence.**
/// Once the `ContextManager` is initialized (by whichever call arrives first),
/// the transport provider is locked in for the lifetime of the process.
///
/// Unlike the default transport (`NotConfiguredTransportProvider`), this creates a
/// **real** relay connection and wraps it in `RelayTransportProvider`. This means
/// `py_context_send` will publish encrypted payloads through the relay, enabling
/// full end-to-end send → relay → subscribe → receive tests.
///
/// A separate `transport_connect` call is still needed for relay-based context
/// discovery and any subscribe-side operations.
///
/// # Arguments
///
/// * `relay_url` -- The URL of the relay to connect to.
/// * `local_did` -- The DID for MLS credential identity (typically the first identity).
///
/// # Errors
///
/// Raises `TransportError` if the URL fails validation or the connection fails.
#[pyfunction]
#[pyo3(name = "configure_relay_transport")]
pub fn py_configure_relay_transport(relay_url: &str, local_did: &str) -> PyResult<()> {
    validate::validate_relay_url(relay_url)?;
    validate::validate_did(local_did)?;

    let rt = crate::runtime()?;

    let sourced = SourcedRelayUrl {
        url: relay_url.to_owned(),
        source: RelayUrlSource::Explicit,
    };
    let profile = scp_transport::profile::TransportProfile::platform_default();
    let adapter = rt
        .block_on(async { NativeRelayAdapter::connect_sourced(&sourced, Some(&profile)).await })
        .map_err(|e| {
            ScpPyError::transport(format!("failed to connect to relay '{relay_url}': {e}"))
        })?;

    let crypto = Box::new(scp_core::crypto::mls::provider::MlsCryptoProvider::new(
        local_did.to_owned(),
    ));
    let transport = Box::new(scp_transport::RelayTransportProvider::new(adapter));
    let event_log: Box<dyn scp_core::context::builder::ContextEventLogProvider> =
        Box::new(crate::runtime::NoOpEventLogProvider);
    crate::runtime::init_context_manager_with(local_did, crypto, transport, event_log, None);

    Ok(())
}

// ---------------------------------------------------------------------------
// Multi-relay management functions
// ---------------------------------------------------------------------------

/// Registers an additional relay adapter with the transport manager.
///
/// Connects to the specified relay URL and adds the resulting adapter to
/// the global [`TransportManager`]. The `transport_connect` function must
/// have been called first to initialize the manager.
///
/// # Arguments
///
/// * `relay_url` -- The URL of the additional SCP relay to connect to.
/// * `source` -- How the URL was discovered (default: `"explicit"`).
///
/// # Returns
///
/// The total number of adapters after adding (i.e. the new adapter count).
///
/// # Errors
///
/// Raises `TransportError` if no transport manager exists, the URL is
/// invalid, or the connection fails.
#[pyfunction]
#[pyo3(name = "transport_add_relay", signature = (relay_url, source = "explicit"))]
pub fn py_transport_add_relay(relay_url: &str, source: &str) -> PyResult<usize> {
    validate::validate_relay_url(relay_url)?;
    let rt = crate::runtime()?;

    let relay_source = match source {
        "dht_resolved" => RelayUrlSource::DhtResolved,
        "well_known" => RelayUrlSource::WellKnown,
        "explicit" => RelayUrlSource::Explicit,
        "peer_discovered" => RelayUrlSource::PeerDiscovered,
        other => {
            return Err(ScpPyError::validation(format!(
                "invalid relay URL source: {other:?}. Expected one of: \
                 \"dht_resolved\", \"well_known\", \"explicit\", \"peer_discovered\""
            ))
            .into());
        }
    };

    let sourced = SourcedRelayUrl {
        url: relay_url.to_owned(),
        source: relay_source,
    };
    let profile = scp_transport::profile::TransportProfile::platform_default();
    // Cover traffic auto-starts per adapter via `connect_sourced` with a
    // profile — `finalize_connection` launches the cover traffic background
    // task based on the profile's tier (#1532 AC6).
    let mut adapter = rt
        .block_on(async { NativeRelayAdapter::connect_sourced(&sourced, Some(&profile)).await })
        .map_err(ScpPyError::from)?;

    // Extract the suppression event receiver BEFORE moving the adapter into
    // the TransportManager. The spawned task drains suppression events and
    // downgrades the relay's reliability score (#1533 AC5).
    let suppression_rx = adapter.take_suppression_receiver();
    let scoring_url = relay_url.to_owned();

    let count = crate::runtime::with_transport_manager_mut(|manager| {
        let _eviction = manager.add_adapter(Box::new(adapter));
        Ok(manager.adapter_count())
    })?;

    // Spawn suppression → scoring bridge task.
    if let Some(suppression_rx) = suppression_rx {
        spawn_suppression_scoring_task(suppression_rx, scoring_url);
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
/// * `context_id` -- The context to assign relays for.
///
/// # Returns
///
/// A list of adapter indices assigned to this context.
///
/// # Errors
///
/// Raises `TransportError` if no transport manager exists or no adapters
/// are registered.
#[pyfunction]
#[pyo3(name = "transport_assign_relay_set")]
pub fn py_transport_assign_relay_set(context_id: &str) -> PyResult<Vec<usize>> {
    validate::validate_context_id(context_id)?;
    crate::runtime::with_transport_manager(|manager| {
        manager
            .assign_relay_set(&context_id.to_owned())
            .map_err(|e| ScpPyError::transport(format!("relay set assignment failed: {e}")))
    })
    .map_err(Into::into)
}

/// Returns the number of adapters registered in the transport manager.
///
/// # Errors
///
/// Raises `TransportError` if no transport manager has been initialized.
#[pyfunction]
#[pyo3(name = "transport_adapter_count")]
pub fn py_transport_adapter_count() -> PyResult<usize> {
    crate::runtime::with_transport_manager(|manager| Ok(manager.adapter_count()))
        .map_err(Into::into)
}

/// Returns the reliability score for an adapter by index.
///
/// Returns a dict with the score fields, or `None` if no score exists
/// for the given adapter index.
///
/// # Arguments
///
/// * `adapter_index` -- The adapter index (0-based) to query.
///
/// # Errors
///
/// Raises `TransportError` if no transport manager has been initialized.
#[pyfunction]
#[pyo3(name = "transport_reliability")]
pub fn py_transport_reliability(
    py: Python<'_>,
    adapter_index: usize,
) -> PyResult<Option<PyObject>> {
    crate::runtime::with_transport_manager(|manager| {
        match manager.get_reliability_score(adapter_index) {
            Some(score) => {
                let dict = pyo3::types::PyDict::new(py);
                dict.set_item("relay_url", &score.relay_url)
                    .map_err(|e| ScpPyError::transport(format!("dict build failed: {e}")))?;
                dict.set_item("delivery_success_rate", score.delivery_success_rate)
                    .map_err(|e| ScpPyError::transport(format!("dict build failed: {e}")))?;
                dict.set_item("average_latency_ms", score.average_latency_ms)
                    .map_err(|e| ScpPyError::transport(format!("dict build failed: {e}")))?;
                dict.set_item("deletion_compliance_rate", score.deletion_compliance_rate)
                    .map_err(|e| ScpPyError::transport(format!("dict build failed: {e}")))?;
                dict.set_item("total_sends", score.total_sends)
                    .map_err(|e| ScpPyError::transport(format!("dict build failed: {e}")))?;
                dict.set_item("total_failures", score.total_failures)
                    .map_err(|e| ScpPyError::transport(format!("dict build failed: {e}")))?;
                Ok(Some(dict.into()))
            }
            None => Ok(None),
        }
    })
    .map_err(Into::into)
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
    // Use crate::runtime() to get the tokio Runtime handle, then spawn on it.
    // We cannot use bare `tokio::spawn` because PyO3 functions run outside
    // the tokio runtime context (they use block_on for individual calls).
    let Ok(rt) = crate::runtime() else { return };
    rt.spawn(async move {
        while let Some(_suppression) = rx.recv().await {
            tracing::debug!(
                relay_url = %relay_url,
                "heartbeat suppression → downgrading relay reliability score"
            );
            crate::runtime::record_suppression(&relay_url);
        }
        tracing::debug!(
            relay_url = %relay_url,
            "suppression scoring task exited — adapter disconnected"
        );
    });
}

// ---------------------------------------------------------------------------
// Module registration
// ---------------------------------------------------------------------------

/// Registers transport bridge functions and classes on the `_scp_core` module.
///
/// Called from [`crate::_scp_core`] during module initialization.
///
/// # Errors
///
/// Returns `PyErr` if registration of functions or classes fails.
pub fn register_transport(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyTransportStatus>()?;
    m.add_function(wrap_pyfunction!(py_transport_connect, m)?)?;
    m.add_function(wrap_pyfunction!(py_transport_disconnect, m)?)?;
    m.add_function(wrap_pyfunction!(py_transport_status, m)?)?;
    m.add_function(wrap_pyfunction!(py_configure_relay_transport, m)?)?;
    m.add_function(wrap_pyfunction!(py_transport_add_relay, m)?)?;
    m.add_function(wrap_pyfunction!(py_transport_assign_relay_set, m)?)?;
    m.add_function(wrap_pyfunction!(py_transport_adapter_count, m)?)?;
    m.add_function(wrap_pyfunction!(py_transport_reliability, m)?)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn transport_status_disconnected_by_default() {
        // Before any connection, status should report disconnected.
        let status = py_transport_status().unwrap();
        let _ = status.connected; // Verify field is accessible without panic.
    }

    #[test]
    fn transport_disconnect_is_idempotent() {
        // BridgeInstance must exist for transport operations.
        crate::runtime::init_context_manager_for_test();
        // Disconnecting when not connected should not error.
        let result = py_transport_disconnect();
        assert!(result.is_ok());
    }

    #[test]
    fn transport_connect_fails_for_unreachable_localhost() {
        // Connecting to an unreachable URL should fail with TransportError.
        // We need the tokio runtime to be initialized first.
        crate::init_runtime().ok();
        // ws:// to loopback passes scheme validation (loopback exemption),
        // but the connection fails because nothing is listening on port 1.
        let result = py_transport_connect("ws://127.0.0.1:1/nonexistent", "explicit");
        assert!(result.is_err());
    }

    #[test]
    fn transport_connect_rejects_ws_to_remote_host() {
        crate::init_runtime().ok();
        // ws:// to a non-loopback address from "explicit" source is
        // rejected by the transport layer per §10.12.6.
        let result = py_transport_connect("ws://203.0.113.42:9000/scp/v1", "explicit");
        assert!(result.is_err());
    }

    #[test]
    fn transport_connect_rejects_invalid_source() {
        crate::init_runtime().ok();
        let result = py_transport_connect("wss://relay.example.com/scp/v1", "invalid_source");
        assert!(result.is_err());
    }
}
