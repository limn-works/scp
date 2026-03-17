//! `PyO3` bridge for relay and application node server startup.
//!
//! Wraps the shared startup code in `scp-ffi-common::server` for consumption
//! from Python via `PyO3` `#[pyfunction]` and `#[pyclass]` definitions.
//!
//! - [`PyRelayHandle`] -- opaque handle to a running relay server.
//! - [`PyNodeHandle`] -- opaque handle to a running application node (wraps
//!   both `InMemoryStorage` and `FilesystemStorage` variants via an internal
//!   enum).
//! - [`py_relay_start_in_memory`] / [`py_relay_start_local`] -- relay startup.
//! - [`py_node_start_in_memory`] / [`py_node_start_local`] -- node startup.
//!
//! Gated behind the `server` feature on `scp-ffi-common`. Not available for
//! WASM (ADR-034).

use pyo3::prelude::*;

use scp_ffi_common::server::{self, RunningRelay, ServerError};
use scp_platform::testing::InMemoryStorage;

// ---------------------------------------------------------------------------
// Error conversion
// ---------------------------------------------------------------------------

fn server_err(e: ServerError) -> PyErr {
    pyo3::exceptions::PyRuntimeError::new_err(e.to_string())
}

// ---------------------------------------------------------------------------
// PyRelayHandle
// ---------------------------------------------------------------------------

/// Opaque handle to a running SCP relay server.
///
/// Created by `relay_start_in_memory()` or `relay_start_local()`. The relay
/// accepts WebSocket connections at `relay_url` and can be gracefully stopped
/// via `shutdown()`.
#[pyclass(name = "RelayHandle")]
pub struct PyRelayHandle {
    inner: RunningRelay,
}

// PyO3 `#[getter]` methods require `&self` and cannot be `const` or `#[must_use]`.
// These are framework constraints, not code quality issues.
#[pymethods]
#[allow(clippy::must_use_candidate, clippy::missing_const_for_fn)]
impl PyRelayHandle {
    /// Returns the WebSocket URL clients should connect to
    /// (e.g., ``ws://127.0.0.1:12345/scp/v1``).
    #[getter]
    fn relay_url(&self) -> String {
        self.inner.relay_url().to_owned()
    }

    /// Returns the port the relay is listening on.
    #[getter]
    fn relay_port(&self) -> u16 {
        self.inner.bound_addr().port()
    }

    /// Returns ``True`` if shutdown has already been signaled.
    #[getter]
    fn is_shutdown(&self) -> bool {
        self.inner.is_shutdown()
    }

    /// Signals the relay server to stop accepting new connections.
    ///
    /// In-flight connection handlers drain naturally after shutdown is
    /// signaled -- they are not cancelled.
    fn shutdown(&self) {
        self.inner.shutdown();
    }

    fn __repr__(&self) -> String {
        format!("RelayHandle(url={})", self.inner.relay_url())
    }
}

impl Drop for PyRelayHandle {
    fn drop(&mut self) {
        self.inner.shutdown();
    }
}

// ---------------------------------------------------------------------------
// PyNodeHandle -- type-erased ApplicationNode wrapper
// ---------------------------------------------------------------------------

/// Internal enum that erases the `ApplicationNode<S>` generic parameter.
///
/// `ApplicationNode<S>` is generic over `S: Storage`. The `Storage` trait uses
/// RPITIT and is not object-safe, so we cannot use `dyn Storage`. Instead we
/// use a closed enum over the two concrete storage backends used by the shared
/// server code: `InMemoryStorage` and `FilesystemStorage`.
enum NodeInner {
    InMemory(scp_node::ApplicationNode<InMemoryStorage>),
    Filesystem(scp_node::ApplicationNode<scp_platform::filesystem::FilesystemStorage>),
}

impl NodeInner {
    fn relay_url(&self) -> &str {
        match self {
            Self::InMemory(n) => n.relay_url(),
            Self::Filesystem(n) => n.relay_url(),
        }
    }

    fn did(&self) -> &str {
        match self {
            Self::InMemory(n) => n.identity().did(),
            Self::Filesystem(n) => n.identity().did(),
        }
    }

    const fn relay_port(&self) -> u16 {
        match self {
            Self::InMemory(n) => n.relay().bound_addr().port(),
            Self::Filesystem(n) => n.relay().bound_addr().port(),
        }
    }

    fn is_shutdown(&self) -> bool {
        match self {
            Self::InMemory(n) => n.relay().shutdown_handle().is_shutdown(),
            Self::Filesystem(n) => n.relay().shutdown_handle().is_shutdown(),
        }
    }

    fn shutdown(&self) {
        match self {
            Self::InMemory(n) => n.shutdown(),
            Self::Filesystem(n) => n.shutdown(),
        }
    }
}

/// Opaque handle to a running SCP application node.
///
/// Created by `node_start_in_memory()` or `node_start_local()`. The node
/// includes a running relay server, a generated DID identity, and (optionally)
/// persistent storage. The HTTP server is **not** started automatically --
/// only the relay is bound.
#[pyclass(name = "NodeHandle")]
pub struct PyNodeHandle {
    inner: NodeInner,
}

// PyO3 `#[getter]` methods require `&self` and cannot be `const` or `#[must_use]`.
// These are framework constraints, not code quality issues.
#[pymethods]
#[allow(clippy::must_use_candidate, clippy::missing_const_for_fn)]
impl PyNodeHandle {
    /// Returns the WebSocket URL clients should connect to for this node's
    /// relay (e.g., ``ws://127.0.0.1:12345/scp/v1``).
    #[getter]
    fn relay_url(&self) -> String {
        self.inner.relay_url().to_owned()
    }

    /// Returns the port the node's relay is listening on.
    #[getter]
    fn relay_port(&self) -> u16 {
        self.inner.relay_port()
    }

    /// Returns the node's DID string (e.g., ``did:dht:z6Mk...``).
    #[getter]
    fn did(&self) -> String {
        self.inner.did().to_owned()
    }

    /// Returns ``True`` if shutdown has already been signaled.
    #[getter]
    fn is_shutdown(&self) -> bool {
        self.inner.is_shutdown()
    }

    /// Signals the node to stop (relay + background tasks).
    fn shutdown(&self) {
        self.inner.shutdown();
    }

    fn __repr__(&self) -> String {
        format!(
            "NodeHandle(relay_url={}, did={})",
            self.inner.relay_url(),
            self.inner.did()
        )
    }
}

impl Drop for PyNodeHandle {
    fn drop(&mut self) {
        self.inner.shutdown();
    }
}

// ---------------------------------------------------------------------------
// Free functions -- relay startup
// ---------------------------------------------------------------------------

/// Starts a relay with in-memory blob storage on an OS-assigned port.
///
/// Returns a :class:`RelayHandle` whose ``relay_url`` property contains the
/// WebSocket URL for clients.
#[pyfunction]
pub fn py_relay_start_in_memory(py: Python<'_>) -> PyResult<PyRelayHandle> {
    let rt = crate::runtime()?;
    py.allow_threads(|| {
        let relay = rt
            .block_on(server::start_relay_in_memory())
            .map_err(server_err)?;
        Ok(PyRelayHandle { inner: relay })
    })
}

/// Starts a relay with redb-backed blob storage on an OS-assigned port.
///
/// Opens (or creates) a redb database at ``<data_dir>/blobs.redb``.
#[pyfunction]
pub fn py_relay_start_local(py: Python<'_>, data_dir: String) -> PyResult<PyRelayHandle> {
    let rt = crate::runtime()?;
    py.allow_threads(|| {
        let relay = rt
            .block_on(server::start_relay_local(std::path::Path::new(&data_dir)))
            .map_err(server_err)?;
        Ok(PyRelayHandle { inner: relay })
    })
}

// ---------------------------------------------------------------------------
// Free functions -- node startup
// ---------------------------------------------------------------------------

/// Starts a full application node with in-memory storage.
///
/// Auto-wires in-memory key custody, in-memory storage, in-memory DHT client,
/// self-signed TLS, and a relay on an OS-assigned port.
#[pyfunction]
pub fn py_node_start_in_memory(py: Python<'_>) -> PyResult<PyNodeHandle> {
    let rt = crate::runtime()?;
    py.allow_threads(|| {
        let node = rt
            .block_on(server::start_node_in_memory())
            .map_err(server_err)?;
        Ok(PyNodeHandle {
            inner: NodeInner::InMemory(node),
        })
    })
}

/// Starts a full application node with file-backed storage.
///
/// Opens (or creates) persistent storage at ``<data_dir>/storage/`` and a redb
/// blob database at ``<data_dir>/blobs.redb``.
#[pyfunction]
pub fn py_node_start_local(py: Python<'_>, data_dir: String) -> PyResult<PyNodeHandle> {
    let rt = crate::runtime()?;
    py.allow_threads(|| {
        let node = rt
            .block_on(server::start_node_local(std::path::Path::new(&data_dir)))
            .map_err(server_err)?;
        Ok(PyNodeHandle {
            inner: NodeInner::Filesystem(node),
        })
    })
}

// ---------------------------------------------------------------------------
// Module registration
// ---------------------------------------------------------------------------

/// Registers the server bridge functions and classes in the Python module.
pub fn register_server(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyRelayHandle>()?;
    m.add_class::<PyNodeHandle>()?;
    m.add_function(wrap_pyfunction!(py_relay_start_in_memory, m)?)?;
    m.add_function(wrap_pyfunction!(py_relay_start_local, m)?)?;
    m.add_function(wrap_pyfunction!(py_node_start_in_memory, m)?)?;
    m.add_function(wrap_pyfunction!(py_node_start_local, m)?)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn rt() -> &'static tokio::runtime::Runtime {
        crate::init_runtime().ok();
        crate::runtime().unwrap()
    }

    #[test]
    fn relay_in_memory_starts_and_returns_url() {
        let relay = rt().block_on(server::start_relay_in_memory()).unwrap();
        assert!(relay.relay_url().starts_with("ws://127.0.0.1:"));
        assert!(relay.relay_url().ends_with("/scp/v1"));
        assert_ne!(relay.bound_addr().port(), 0);
        relay.shutdown();
    }

    #[test]
    fn relay_local_starts_and_returns_url() {
        let tmp = std::env::temp_dir().join(format!("scp-pyo3-relay-test-{}", std::process::id()));
        let relay = rt().block_on(server::start_relay_local(&tmp)).unwrap();
        assert!(relay.relay_url().starts_with("ws://127.0.0.1:"));
        assert_ne!(relay.bound_addr().port(), 0);
        relay.shutdown();
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn node_in_memory_starts_and_returns_did() {
        let node = rt().block_on(server::start_node_in_memory()).unwrap();
        let url = node.relay_url();
        assert!(
            url.starts_with("ws://") || url.starts_with("wss://"),
            "expected ws(s):// URL, got: {url}"
        );
        assert!(node.identity().did().starts_with("did:"));
        assert_ne!(node.relay().bound_addr().port(), 0);
        node.shutdown();
    }

    #[test]
    fn node_local_starts_and_returns_did() {
        let tmp = std::env::temp_dir().join(format!("scp-pyo3-node-test-{}", std::process::id()));
        let node = rt().block_on(server::start_node_local(&tmp)).unwrap();
        let url = node.relay_url();
        assert!(
            url.starts_with("ws://") || url.starts_with("wss://"),
            "expected ws(s):// URL, got: {url}"
        );
        assert!(node.identity().did().starts_with("did:"));
        assert_ne!(node.relay().bound_addr().port(), 0);
        node.shutdown();
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn relay_shutdown_is_idempotent() {
        let relay = rt().block_on(server::start_relay_in_memory()).unwrap();
        relay.shutdown();
        relay.shutdown();
    }
}
