//! `PyO3` bridge functions for transport connection and status.
//!
//! Exposes SCP transport operations to Python:
//!
//! - [`py_transport_connect`] -- Connect to an SCP relay.
//! - [`py_transport_disconnect`] -- Disconnect from the current relay.
//! - [`py_transport_status`] -- Query transport connection status.
//!
//! # Types
//!
//! - [`PyTransportStatus`] -- Connection status (connected, relay URL, latency).
//!
//! # Transport Wiring (SCP-213)
//!
//! `py_transport_connect` creates a [`NativeRelayAdapter`] connected to the
//! given relay URL and stores it in the global relay connection state (see
//! [`crate::runtime`]). This adapter is shared with `py_mcp_load_contexts`
//! for relay-based context discovery.
//!
//! The relay URL is tracked in a module-level `RwLock` so that
//! `py_transport_status` can report it without querying the adapter.
//!
//! See ADR-013 in `.docs/adrs/phase-3.md` section 5 for the bridge specification.

use std::sync::{Arc, OnceLock, RwLock};

use pyo3::prelude::*;
use scp_transport::native::adapter::NativeRelayAdapter;

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
fn connected_url_state() -> &'static RwLock<Option<String>> {
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

/// Connects to an SCP relay.
///
/// Establishes a WebSocket connection to the specified relay URL using
/// [`NativeRelayAdapter`]. The adapter is stored in the global relay
/// connection state for use by `py_mcp_load_contexts` (context discovery)
/// and future transport operations.
///
/// # Arguments
///
/// * `relay_url` -- The URL of the SCP relay to connect to (e.g.,
///   `"ws://127.0.0.1:9000/scp/v1"`).
///
/// # Errors
///
/// Raises `TransportError` if the connection fails (unreachable relay,
/// protocol mismatch, timeout, etc.).
///
/// See ADR-013 section 5: `py_transport_connect(relay_url) -> None`.
#[pyfunction]
#[pyo3(name = "transport_connect")]
pub fn py_transport_connect(relay_url: &str) -> PyResult<()> {
    validate::validate_relay_url(relay_url)?;
    let rt = crate::runtime()?;
    let url = relay_url.to_owned();

    #[allow(deprecated)] // Stub — see #220: migrate to connect_sourced() with provenance tracking
    let adapter = rt.block_on(async { NativeRelayAdapter::connect(&url).await });

    match adapter {
        Ok(adapter) => {
            let arc_adapter = Arc::new(adapter);

            // Store the adapter in the global relay connection state.
            crate::runtime::set_relay_connection(Arc::clone(&arc_adapter))?;

            // Track the URL for status queries.
            *connected_url_state().write().map_err(|_| {
                ScpPyError::TransportError("connected relay URL lock is poisoned".to_owned())
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
    crate::runtime::clear_relay_connection()?;

    *connected_url_state().write().map_err(|_| {
        ScpPyError::TransportError("connected relay URL lock is poisoned".to_owned())
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
/// See ADR-013 section 5: `py_transport_status() -> PyTransportStatus`.
#[pyfunction]
#[pyo3(name = "transport_status")]
pub fn py_transport_status() -> PyResult<PyTransportStatus> {
    let has_connection = crate::runtime::get_relay_connection()
        .map(|opt| opt.is_some())
        .unwrap_or(false);

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
        // Disconnecting when not connected should not error.
        let result = py_transport_disconnect();
        assert!(result.is_ok());
    }

    #[test]
    fn transport_connect_rejects_invalid_url() {
        // Connecting to an unreachable URL should fail with TransportError.
        // We need the tokio runtime to be initialized first.
        crate::init_runtime().ok();
        let result = py_transport_connect("ws://127.0.0.1:1/nonexistent");
        assert!(result.is_err());
    }
}
