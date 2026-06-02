//! `PyO3` bridge functions for transport connection and status.
//!
//! Exposes SCP transport operations to Python as methods on the `SCP` class:
//!
//! - `PyScp::transport_connect` -- Connect to an SCP relay.
//! - `PyScp::transport_disconnect` -- Disconnect from the current relay.
//! - `PyScp::transport_status` -- Query transport connection status.
//! - `PyScp::configure_relay_transport` -- Pre-configure `ContextManager`
//!   with `RelayTransportProvider`.
//! - `PyScp::transport_add_relay` -- Register an additional relay adapter.
//! - `PyScp::transport_assign_relay_set` -- Assign a relay set for a context.
//! - `PyScp::transport_adapter_count` -- Number of registered adapters.
//! - `PyScp::transport_reliability` -- Per-adapter reliability score.
//!
//! Migrated from flat `#[pyfunction]` exports to `#[pymethods] impl PyScp`
//! methods in Phase 4 PR 4 sub-slice D (#1549).
//!
//! # Types
//!
//! - [`PyTransportStatus`] -- Connection status (connected, relay URL, latency).
//!
//! # Transport Wiring (SCP-213, #1490)
//!
//! `py_transport_connect` connects to the given relay URL via the
//! [`scp_transport::TransportSelector`] (transparent QUIC↔WebSocket selection,
//! spec §10.14.3 item 4; ADR-037), wraps the resulting adapter in a
//! [`scp_transport::TransportManager`], and
//! stores the manager in the global transport state (see
//! [`crate::runtime`]). The manager provides multi-relay fanout,
//! per-context relay set assignment, suppression detection, and reliability
//! scoring. This manager is shared with `py_mcp_load_contexts` for
//! relay-based context discovery.
//!
//! The **currently-connected** relay URL is tracked on the
//! [`PyBridgeInstance`] as
//! `connected_relay_url: RwLock<Option<String>>`. It is written by
//! `py_transport_connect`, cleared by `py_transport_disconnect`, and
//! read by `py_transport_status`. This is **distinct** from
//! `CoreFields::relay_url` (in `scp-ffi-common`), which tracks the
//! **pending** relay URL preserved across suspend/resume so the bridge can
//! reconnect after the caller calls `resume()`. The two fields intentionally
//! diverge: `connected_relay_url` is a live status value (cleared on
//! disconnect); `CoreFields::relay_url` is a reconnection hint (survives
//! disconnect on suspend).
//!
//! See ADR-013 in `.docs/adrs/phase-3.md` section 5 for the bridge specification.

use std::sync::Arc;

use pyo3::prelude::*;
use scp_transport::relay::connection::{RelayUrlSource, SourcedRelayUrl};

use crate::error::ScpPyError;
use crate::runtime::PyBridgeInstance;
use crate::validate;

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
// PyScp methods — migrated from #[pyfunction] exports (Phase 4 PR 4, #1549).
// ---------------------------------------------------------------------------

#[pymethods]
impl crate::scp::PyScp {
    /// Connects to an SCP relay with provenance-based transport security
    /// validation (§10.12.6).
    ///
    /// Establishes a connection to the specified relay URL via the
    /// [`scp_transport::TransportSelector`] (transparent QUIC↔WebSocket
    /// selection, spec §10.14.3 item 4; ADR-037). The adapter is stored in the
    /// bridge instance's relay connection state for use by
    /// `mcp_load_contexts` (context discovery) and future transport
    /// operations.
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
    /// See ADR-013 section 5: `transport_connect(relay_url) -> None`.
    #[pyo3(name = "transport_connect", signature = (relay_url, source = "explicit"))]
    pub fn transport_connect(&self, relay_url: &str, source: &str) -> PyResult<()> {
        let bi = &*self.inner;
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
        // Route through the transport selector for transparent QUIC↔WebSocket
        // selection (spec §10.14.3 item 4; ADR-037). The advertised-transports
        // list from `.well-known/scp` is NOT available at this bridge entry
        // point — `source` is provenance, not the relay's transport binding
        // list — so the selector degrades to the WebSocket baseline here. When
        // a `.well-known/scp` transports list is plumbed to this site in a
        // future change, pass it as the second argument to enable QUIC.
        let selector = scp_transport::TransportSelector::new();
        let result = rt.block_on(async {
            selector
                .select_and_connect_with_suppression(&sourced, None, Some(&profile))
                .await
        });

        match result {
            Ok((adapter, suppression_rx)) => {
                // The suppression event receiver (drained into reliability
                // scoring, #1533 AC5) is surfaced by the selector for the
                // WebSocket branch. Cover traffic is already running —
                // `connect_sourced` with a profile auto-starts it via
                // `finalize_connection` (#1532 AC6).

                // Wrap the adapter in a TransportManager for multi-relay support.
                let manager = scp_transport::TransportManager::new(adapter);
                crate::runtime::set_transport_manager(bi, manager)?;

                // Register the URL on the bridge's pending-reconnect set so
                // `BridgeInstanceCore::resume` can rebuild the transport after
                // suspend/resume cycles (#1678).
                bi.core.add_relay_url(url.clone());

                // Spawn suppression → scoring bridge task.
                //
                // Pass `Weak<PyBridgeInstance>` + the instance's cancel
                // token so the task cannot pin the instance alive. See
                // the `spawn_suppression_scoring_task` doc comment for
                // the Arc-cycle rationale (#1549 round-2 bug-catcher).
                if let Some(suppression_rx) = suppression_rx {
                    spawn_suppression_scoring_task(
                        Arc::downgrade(&self.inner),
                        self.inner.core.cancel_token(),
                        suppression_rx,
                        url.clone(),
                    );
                }

                // Track the URL for status queries on the per-bridge instance.
                // Distinct from `CoreFields::relay_url` (pending URL for resume):
                // this field is cleared on disconnect.
                *bi.connected_relay_url().write().map_err(|_| {
                    ScpPyError::transport("connected relay URL lock is poisoned".to_owned())
                })? = Some(url);

                Ok(())
            }
            Err(e) => Err(ScpPyError::from(e).into()),
        }
    }

    /// Disconnects from the current SCP relay.
    ///
    /// Clears the bridge instance's relay connection state. After this call,
    /// `mcp_load_contexts` will fall back to local-only context discovery.
    ///
    /// This is a no-op if no relay connection is active.
    ///
    /// # Errors
    ///
    /// Raises `TransportError` if clearing the connection state fails.
    #[pyo3(name = "transport_disconnect")]
    pub fn transport_disconnect(&self) -> PyResult<()> {
        let bi = &*self.inner;
        // Read the URL we'll be disconnecting before clearing the state so we
        // can remove it from the bridge's pending-reconnect set (#1678).
        let disconnecting_url = bi
            .connected_relay_url()
            .read()
            .ok()
            .and_then(|guard| guard.clone());

        crate::runtime::clear_transport_manager(bi)?;

        // Drop the URL from the bridge's pending-reconnect set so resume() does
        // not reopen it after an explicit disconnect (#1678).
        if let Some(ref url) = disconnecting_url {
            bi.core.remove_relay_url(url);
        }

        // Clear the currently-connected URL on the per-bridge instance.
        // `CoreFields::relay_url` (pending) is NOT cleared here — it survives
        // disconnect so resume() can reconnect after suspend().
        *bi.connected_relay_url().write().map_err(|_| {
            ScpPyError::transport("connected relay URL lock is poisoned".to_owned())
        })? = None;

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
    /// See ADR-013 section 5: `transport_status() -> PyTransportStatus`.
    #[pyo3(name = "transport_status")]
    pub fn transport_status(&self) -> PyResult<PyTransportStatus> {
        let bi = &*self.inner;
        let has_connection = crate::runtime::has_transport_manager(bi);

        // Read the currently-connected URL off the per-bridge instance. Unlike
        // `CoreFields::relay_url` (which tracks the pending URL for resume),
        // this reflects a live bound connection and is `None` when disconnected.
        let relay_url = bi.connected_relay_url().read().ok().and_then(|g| g.clone());

        Ok(PyTransportStatus {
            connected: has_connection,
            relay_url,
            latency_ms: None, // Latency measurement is a future enhancement.
        })
    }

    /// Pre-configures the `ContextManager` with `RelayTransportProvider`.
    ///
    /// **Must be called before any `identity_create` → `context_create` sequence.**
    /// Once the `ContextManager` is initialized (by whichever call arrives first),
    /// the transport provider is locked in for the lifetime of the process.
    ///
    /// Unlike the default transport (`NotConfiguredTransportProvider`), this creates a
    /// **real** relay connection and wraps it in `RelayTransportProvider`. This means
    /// `context_send` will publish encrypted payloads through the relay, enabling
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
    #[pyo3(name = "configure_relay_transport")]
    pub fn configure_relay_transport(&self, relay_url: &str, local_did: &str) -> PyResult<()> {
        let bi = &*self.inner;
        validate::validate_relay_url(relay_url)?;
        validate::validate_did(local_did)?;

        let rt = crate::runtime()?;

        let sourced = SourcedRelayUrl {
            url: relay_url.to_owned(),
            source: RelayUrlSource::Explicit,
        };
        let profile = scp_transport::profile::TransportProfile::platform_default();
        // Route through the transport selector for transparent QUIC↔WebSocket
        // selection (spec §10.14.3 item 4; ADR-037). No advertised-transports
        // list is available at this site, so the selector uses the WebSocket
        // baseline (see `transport_connect` for the plumbing-gap rationale).
        let selector = scp_transport::TransportSelector::new();
        let adapter = rt
            .block_on(async {
                selector
                    .select_and_connect(&sourced, None, Some(&profile))
                    .await
            })
            .map_err(|e| {
                ScpPyError::transport(format!("failed to connect to relay '{relay_url}': {e}"))
            })?;

        let crypto = Box::new(scp_core::crypto::mls::provider::MlsCryptoProvider::new(
            local_did.to_owned(),
        ));
        let transport = Box::new(scp_transport::RelayTransportProvider::new(adapter));
        let event_log: Box<dyn scp_core::context::builder::ContextEventLogProvider> =
            Box::new(crate::runtime::NoOpEventLogProvider);
        crate::runtime::init_context_manager_with(
            bi, local_did, crypto, transport, event_log, None,
        );

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Multi-relay management methods
    // -----------------------------------------------------------------------

    /// Registers an additional relay adapter with the transport manager.
    ///
    /// Connects to the specified relay URL and adds the resulting adapter to
    /// the bridge instance's `TransportManager`. The `transport_connect`
    /// method must have been called first to initialize the manager.
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
    #[pyo3(name = "transport_add_relay", signature = (relay_url, source = "explicit"))]
    pub fn transport_add_relay(&self, relay_url: &str, source: &str) -> PyResult<usize> {
        let bi = &*self.inner;
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
        // Route through the transport selector for transparent QUIC↔WebSocket
        // selection (spec §10.14.3 item 4; ADR-037). No advertised-transports
        // list is available at this site, so the selector uses the WebSocket
        // baseline (see `transport_connect` for the plumbing-gap rationale).
        // Cover traffic auto-starts per adapter via the profile —
        // `finalize_connection` launches the cover traffic background task
        // based on the profile's tier (#1532 AC6). The selector surfaces the
        // suppression receiver (drained into reliability scoring, #1533 AC5).
        let selector = scp_transport::TransportSelector::new();
        let (adapter, suppression_rx) = rt
            .block_on(async {
                selector
                    .select_and_connect_with_suppression(&sourced, None, Some(&profile))
                    .await
            })
            .map_err(ScpPyError::from)?;
        let scoring_url = relay_url.to_owned();

        let count = crate::runtime::with_transport_manager_mut(bi, |manager| {
            let _eviction = manager.add_adapter(adapter);
            Ok(manager.adapter_count())
        })?;

        // Spawn suppression → scoring bridge task.
        //
        // Pass `Weak<PyBridgeInstance>` + the instance's cancel token so
        // the task cannot pin the instance alive. See the
        // `spawn_suppression_scoring_task` doc comment for the Arc-cycle
        // rationale (#1549 round-2 bug-catcher).
        if let Some(suppression_rx) = suppression_rx {
            spawn_suppression_scoring_task(
                Arc::downgrade(&self.inner),
                self.inner.core.cancel_token(),
                suppression_rx,
                scoring_url,
            );
        }

        Ok(count)
    }

    /// Assigns a relay set for the given context.
    ///
    /// Delegates to `TransportManager::assign_relay_set` which selects at
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
    #[pyo3(name = "transport_assign_relay_set")]
    pub fn transport_assign_relay_set(&self, context_id: &str) -> PyResult<Vec<usize>> {
        let bi = &*self.inner;
        validate::validate_context_id(context_id)?;
        crate::runtime::with_transport_manager(bi, |manager| {
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
    #[pyo3(name = "transport_adapter_count")]
    pub fn transport_adapter_count(&self) -> PyResult<usize> {
        let bi = &*self.inner;
        crate::runtime::with_transport_manager(bi, |manager| Ok(manager.adapter_count()))
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
    #[pyo3(name = "transport_reliability")]
    pub fn transport_reliability(
        &self,
        py: Python<'_>,
        adapter_index: usize,
    ) -> PyResult<Option<PyObject>> {
        let bi = &*self.inner;
        crate::runtime::with_transport_manager(bi, |manager| {
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
}

// ---------------------------------------------------------------------------
// Suppression → scoring bridge task
// ---------------------------------------------------------------------------

/// Spawns a background task that drains heartbeat suppression events from a
/// per-adapter receiver and records each as a delivery failure in the bridge
/// instance's reliability scoring.
///
/// This bridges the per-adapter heartbeat monitor (spec §9.9.2) with the
/// `TransportManager`'s cross-relay `SuppressionTracker` (spec §9.9.4,
/// #1533 AC5). Each suppression event downgrades the relay's reliability
/// score via `DeliveryOutcome::Failure`.
///
/// # Arc-cycle avoidance (#1549 round-2 bug-catcher)
///
/// The bridge instance is captured as a [`std::sync::Weak`], not an `Arc`.
/// Holding an `Arc<PyBridgeInstance>` here would keep the instance alive
/// forever because this task is spawned on the shared tokio runtime
/// (`RUNTIME.spawn(...)`) and is NOT enrolled in the per-instance
/// [`JoinSet`](scp_ffi_common::bridge_instance::CoreFields::task_handle)
/// that `emergency_cancel_tasks` aborts. The cycle would be:
///
///   `PyScp` → `Arc<PyBridgeInstance>` ← task ← `rt.spawn(...)`
///
/// Without a `Weak`, dropping `PyScp` (and with it the last `Arc<PyBridgeInstance>`
/// held by the caller) would not actually drop `PyBridgeInstance` because
/// the task body holds a strong reference. The task never exits on its own
/// (the `recv()` future is awaited until the relay adapter closes its
/// sender), so the `MCP` server, `ContextManager`, identity registry, and
/// relay connection would leak for the remainder of the process.
///
/// With `Weak`, the task upgrades per iteration. Once the caller-side `Arc`
/// is dropped, the next upgrade fails and the task exits cleanly. The
/// `cancel_token` is also wired so `emergency_cancel_tasks()` from
/// `PyBridgeInstance::drop` can wake the task before its next `recv()`.
///
/// The task exits gracefully when:
/// 1. The sender half is dropped (adapter dropped or disconnected), OR
/// 2. The `cancel_token` fires (instance shutdown), OR
/// 3. `Weak::upgrade` returns `None` (the instance has been dropped).
fn spawn_suppression_scoring_task(
    bi: std::sync::Weak<PyBridgeInstance>,
    cancel_token: tokio_util::sync::CancellationToken,
    mut rx: tokio::sync::mpsc::Receiver<scp_transport::heartbeat::SuppressionSuspected>,
    relay_url: String,
) {
    // Use crate::runtime() to get the tokio Runtime handle, then spawn on it.
    // We cannot use bare `tokio::spawn` because PyO3 functions run outside
    // the tokio runtime context (they use block_on for individual calls).
    let Ok(rt) = crate::runtime() else { return };
    rt.spawn(async move {
        loop {
            let suppression = tokio::select! {
                () = cancel_token.cancelled() => {
                    tracing::debug!(
                        relay_url = %relay_url,
                        "suppression scoring task exiting — bridge instance cancelled"
                    );
                    break;
                }
                ev = rx.recv() => ev,
            };
            if suppression.is_none() {
                // Sender dropped (adapter disconnected).
                break;
            }
            tracing::debug!(
                relay_url = %relay_url,
                "heartbeat suppression → downgrading relay reliability score"
            );
            // Upgrade on every event so a dropped instance releases the Arc
            // immediately on the next iteration rather than pinning it alive
            // for the remainder of the relay session.
            let Some(bi_arc) = bi.upgrade() else {
                tracing::debug!(
                    relay_url = %relay_url,
                    "suppression scoring task exiting — bridge instance dropped"
                );
                break;
            };
            crate::runtime::record_suppression(&bi_arc, &relay_url);
            // Drop the Arc before the next `recv().await` so the caller's
            // `Arc::strong_count` can reach zero while this task is parked.
            drop(bi_arc);
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

/// Registers transport bridge classes on the `_scp_core` module.
///
/// Post-migration (Phase 4 PR 4 sub-slice D) transport operations are exposed
/// as methods on `SCP` (see the `#[pymethods]` block above) and registered
/// automatically with the class. Only the opaque [`PyTransportStatus`] class
/// still requires manual registration here.
///
/// Called from [`crate::_scp_core`] during module initialization.
///
/// # Errors
///
/// Returns `PyErr` if registration of the class fails.
pub fn register_transport(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyTransportStatus>()?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {

    fn default_scp() -> crate::scp::PyScp {
        crate::scp::PyScp::new()
    }

    #[test]
    fn transport_status_disconnected_by_default() {
        // Before any connection, status should report disconnected.
        let status = default_scp().transport_status().unwrap();
        let _ = status.connected; // Verify field is accessible without panic.
    }

    #[test]
    fn transport_disconnect_is_idempotent() {
        let scp = default_scp();
        crate::runtime::init_context_manager_for_test(&scp.inner);
        // Disconnecting when not connected should not error.
        let result = scp.transport_disconnect();
        assert!(result.is_ok());
    }

    #[test]
    fn transport_connect_fails_for_unreachable_localhost() {
        // Connecting to an unreachable URL should fail with TransportError.
        // We need the tokio runtime to be initialized first.
        crate::init_runtime().ok();
        // ws:// to loopback passes scheme validation (loopback exemption),
        // but the connection fails because nothing is listening on port 1.
        let result = default_scp().transport_connect("ws://127.0.0.1:1/nonexistent", "explicit");
        assert!(result.is_err());
    }

    #[test]
    fn transport_connect_rejects_ws_to_remote_host() {
        crate::init_runtime().ok();
        // ws:// to a non-loopback address from "explicit" source is
        // rejected by the transport layer per §10.12.6.
        let result = default_scp().transport_connect("ws://203.0.113.42:9000/scp/v1", "explicit");
        assert!(result.is_err());
    }

    #[test]
    fn transport_connect_rejects_invalid_source() {
        crate::init_runtime().ok();
        let result =
            default_scp().transport_connect("wss://relay.example.com/scp/v1", "invalid_source");
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // #1549 round-2 regression: suppression scoring task must not pin
    // `PyBridgeInstance` alive via a strong `Arc` held across `recv().await`.
    //
    // Before the fix, `spawn_suppression_scoring_task` captured
    // `Arc<PyBridgeInstance>` by value. Because the task runs on the
    // shared `RUNTIME.spawn(...)` handle (not the per-instance `JoinSet`
    // aborted by `emergency_cancel_tasks`) and parks indefinitely on
    // `rx.recv().await`, dropping the caller's `Arc` left the instance's
    // strong count at ≥ 1 forever. The ContextManager, identity
    // registry, and relay connection owned by `PyBridgeInstance` leaked.
    //
    // The fix passes a `Weak<PyBridgeInstance>` + the instance's
    // `cancel_token`. These tests prove:
    //
    //   1. While parked on `recv().await`, the task holds no strong
    //      reference (strong_count stays at 1 — the caller's).
    //   2. Dropping the caller's `Arc` fires `emergency_cancel_tasks`
    //      from `PyBridgeInstance::drop`, which cancels `cancel_token`,
    //      which wakes the task via its `select!` arm. The instance is
    //      fully dropped; `Weak::upgrade` returns `None`.
    // -----------------------------------------------------------------------

    /// Suppression task must not hold a strong `Arc<PyBridgeInstance>`
    /// while parked on `recv()`. Proven by observing `Arc::strong_count`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn suppression_scoring_task_does_not_pin_bridge_instance() {
        use std::sync::Arc;
        use std::time::Duration;

        crate::init_runtime().ok();

        let bi = Arc::new(crate::runtime::PyBridgeInstance::new_py());
        let (_tx, rx) = tokio::sync::mpsc::channel(1);

        super::spawn_suppression_scoring_task(
            Arc::downgrade(&bi),
            bi.core.cancel_token(),
            rx,
            "ws://test-suppression".to_owned(),
        );

        // Yield long enough for the task to reach its `select!` and park.
        tokio::time::sleep(Duration::from_millis(50)).await;

        // The only strong reference is ours. The task holds a `Weak` and
        // a cloned `CancellationToken`; neither bumps `strong_count`.
        assert_eq!(
            Arc::strong_count(&bi),
            1,
            "suppression task must not hold a strong Arc<PyBridgeInstance> \
             while parked on recv() — holding one would prevent Drop from \
             ever running when the caller releases their last strong ref"
        );
    }

    /// Dropping the caller's `Arc` fires `PyBridgeInstance::drop` →
    /// `emergency_cancel_tasks` → `cancel_token` fires → task exits.
    /// After the task unparks, the instance is fully dropped.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn dropping_bridge_instance_terminates_suppression_scoring_task() {
        use std::sync::Arc;
        use std::time::Duration;

        crate::init_runtime().ok();

        let bi = Arc::new(crate::runtime::PyBridgeInstance::new_py());
        let weak_observer = Arc::downgrade(&bi);
        let (_tx, rx) = tokio::sync::mpsc::channel(1);

        super::spawn_suppression_scoring_task(
            Arc::downgrade(&bi),
            bi.core.cancel_token(),
            rx,
            "ws://test-drop".to_owned(),
        );

        // Let the task park on `select!`.
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(
            Arc::strong_count(&bi),
            1,
            "precondition: task must not pin the instance"
        );

        // Drop triggers `emergency_cancel_tasks` → `cancel_token.cancel()`.
        drop(bi);

        // Yield so the task wakes on the cancel branch and exits.
        for _ in 0..50 {
            if weak_observer.strong_count() == 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        assert_eq!(
            weak_observer.strong_count(),
            0,
            "after dropping the caller's Arc, PyBridgeInstance must be \
             fully released — if this fails, the suppression task is \
             still holding a strong reference (regressed Arc cycle)"
        );
        assert!(
            weak_observer.upgrade().is_none(),
            "Weak must not upgrade after the last strong reference is gone"
        );
    }

    /// The task also handles the channel-sender-dropped path: when the
    /// relay adapter that owns the suppression `tx` is dropped, the
    /// `rx.recv()` future resolves with `None` and the task exits.
    /// Verifies that after the sender drops, the spawned task stops
    /// pinning (proven via `Arc::strong_count` going back to 1 after the
    /// task was briefly alive holding a temporary upgraded Arc).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn suppression_scoring_task_exits_when_sender_drops() {
        use std::sync::Arc;
        use std::time::Duration;

        crate::init_runtime().ok();

        let bi = Arc::new(crate::runtime::PyBridgeInstance::new_py());
        let (tx, rx) = tokio::sync::mpsc::channel(1);

        super::spawn_suppression_scoring_task(
            Arc::downgrade(&bi),
            bi.core.cancel_token(),
            rx,
            "ws://test-sender-drop".to_owned(),
        );

        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(Arc::strong_count(&bi), 1);

        // Drop the sender — simulates relay adapter shutdown. The task's
        // `recv()` returns `None`, and the task body breaks out of its
        // loop cleanly without touching the `Weak`.
        drop(tx);

        tokio::time::sleep(Duration::from_millis(100)).await;

        // Count remains 1 because we still hold `bi`; the task's exit
        // did not double-drop or leak anything.
        assert_eq!(
            Arc::strong_count(&bi),
            1,
            "after sender drop the task must exit without touching strong count"
        );
    }
}
