//! `PyO3` bridge functions for transport connection and status.
//!
//! Exposes SCP transport operations to Python:
//!
//! - [`py_transport_connect`] — Connect to an SCP relay.
//! - [`py_transport_status`] — Query transport connection status.
//!
//! # Types
//!
//! - [`PyTransportStatus`] — Connection status (connected, relay URL, latency).
//!
//! See ADR-013 in `.docs/adrs/phase-3.md` §5 for the bridge specification.

use pyo3::prelude::*;

use crate::error::ScpPyError;

// ---------------------------------------------------------------------------
// PyTransportStatus
// ---------------------------------------------------------------------------

/// Transport connection status exposed to Python.
///
/// Reports whether the transport is connected, the relay URL (if connected),
/// and the measured latency in milliseconds (if available).
///
/// See ADR-005 (transport abstraction) and ADR-013 §5 (bridge layer).
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
/// Establishes a transport connection to the specified relay URL. This is
/// an async operation that completes when the connection is established.
///
/// # Arguments
///
/// * `relay_url` — The URL of the SCP relay to connect to (e.g.,
///   `"wss://relay.example.com"`).
///
/// # Errors
///
/// Raises `TransportError` if the connection fails (unreachable relay,
/// protocol mismatch, timeout, etc.).
///
/// See ADR-013 §5: `py_transport_connect(relay_url) -> None`.
#[pyfunction]
#[pyo3(name = "transport_connect")]
pub fn py_transport_connect(_relay_url: &str) -> PyResult<()> {
    Err(ScpPyError::TransportError(
        "not yet connected to runtime — transport connection requires runtime initialization"
            .to_owned(),
    )
    .into())
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
/// See ADR-013 §5: `py_transport_status() -> PyTransportStatus`.
#[pyfunction]
#[pyo3(name = "transport_status")]
#[allow(clippy::missing_const_for_fn)] // PyO3 #[pyfunction] cannot be const.
pub fn py_transport_status() -> PyResult<PyTransportStatus> {
    // Return a disconnected status as the default placeholder.
    Ok(PyTransportStatus {
        connected: false,
        relay_url: None,
        latency_ms: None,
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
    m.add_function(wrap_pyfunction!(py_transport_status, m)?)?;
    Ok(())
}
