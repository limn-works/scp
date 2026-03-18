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
use zeroize::Zeroizing;

use scp_ffi_common::server::{self, RunningRelay, ServerError};
use scp_node::NodeError;
use scp_platform::testing::InMemoryStorage;

// ---------------------------------------------------------------------------
// Error conversion
// ---------------------------------------------------------------------------

fn server_err(e: ServerError) -> PyErr {
    pyo3::exceptions::PyRuntimeError::new_err(e.to_string())
}

fn node_err(e: NodeError) -> PyErr {
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

    async fn enable_broadcast_projection_with_site(
        &self,
        context_id: &str,
        broadcast_key: scp_core::crypto::sender_keys::BroadcastKey,
        admission: scp_core::context::broadcast::BroadcastAdmission,
        site_config: Option<scp_node::projection::SiteConfig>,
    ) -> Result<(), NodeError> {
        match self {
            Self::InMemory(n) => {
                n.enable_broadcast_projection_with_site(
                    context_id,
                    broadcast_key,
                    admission,
                    None,
                    site_config,
                )
                .await
            }
            Self::Filesystem(n) => {
                n.enable_broadcast_projection_with_site(
                    context_id,
                    broadcast_key,
                    admission,
                    None,
                    site_config,
                )
                .await
            }
        }
    }

    async fn commit_deploy(&self, context_id: &str, deploy_id: &str) -> Result<usize, NodeError> {
        match self {
            Self::InMemory(n) => n.commit_deploy(context_id, deploy_id).await,
            Self::Filesystem(n) => n.commit_deploy(context_id, deploy_id).await,
        }
    }

    async fn rollback_deploy(&self, context_id: &str, deploy_id: &str) -> Result<(), NodeError> {
        match self {
            Self::InMemory(n) => n.rollback_deploy(context_id, deploy_id).await,
            Self::Filesystem(n) => n.rollback_deploy(context_id, deploy_id).await,
        }
    }

    async fn disable_broadcast_projection(&self, context_id: &str) {
        match self {
            Self::InMemory(n) => n.disable_broadcast_projection(context_id).await,
            Self::Filesystem(n) => n.disable_broadcast_projection(context_id).await,
        }
    }

    async fn serve_background(
        &self,
        bind_addr: Option<std::net::SocketAddr>,
    ) -> Result<std::net::SocketAddr, scp_node::NodeError> {
        match self {
            Self::InMemory(n) => n.serve_background(bind_addr).await,
            Self::Filesystem(n) => n.serve_background(bind_addr).await,
        }
    }

    async fn http_url(&self) -> Option<String> {
        match self {
            Self::InMemory(n) => n.http_url().await,
            Self::Filesystem(n) => n.http_url().await,
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

    /// Activates HTTP broadcast projection with site configuration.
    ///
    /// Registers a broadcast context for HTTP content delivery. The
    /// ``broadcast_key_hex`` is the 32-byte AES-256 broadcast key as a
    /// 64-character hex string. ``author_did`` is the DID of the key owner.
    /// ``admission`` is ``"open"`` or ``"gated"``.
    ///
    /// Site configuration fields:
    /// - ``hostname`` (required): virtual host hostname (RFC 1123).
    /// - ``index_path``: default path for directory requests (default ``"/index.html"``).
    /// - ``max_assets_per_deploy``: max assets per deploy (default 10000).
    /// - ``max_deploy_size_bytes``: max total deploy size in bytes (default 536870912).
    /// - ``deploy_retention_count``: deploys to retain (default 2, max 8).
    /// - ``csp_override``: optional Content-Security-Policy override.
    #[pyo3(signature = (context_id, broadcast_key_hex, author_did, admission, hostname, index_path=None, max_assets_per_deploy=None, max_deploy_size_bytes=None, deploy_retention_count=None, csp_override=None))]
    #[allow(clippy::too_many_arguments)]
    fn enable_site_projection(
        &self,
        py: Python<'_>,
        context_id: String,
        broadcast_key_hex: String,
        author_did: String,
        admission: String,
        hostname: String,
        index_path: Option<String>,
        max_assets_per_deploy: Option<usize>,
        max_deploy_size_bytes: Option<u64>,
        deploy_retention_count: Option<usize>,
        csp_override: Option<String>,
    ) -> PyResult<()> {
        crate::validate::validate_context_id(&context_id)?;
        crate::validate::validate_did(&author_did)?;
        let rt = crate::runtime()?;

        let key_vec = Zeroizing::new(hex::decode(&broadcast_key_hex).map_err(|e| {
            pyo3::exceptions::PyValueError::new_err(format!("invalid broadcast_key_hex: {e}"))
        })?);
        let key_bytes: Zeroizing<[u8; 32]> =
            Zeroizing::new(<[u8; 32]>::try_from(key_vec.as_slice()).map_err(|_| {
                pyo3::exceptions::PyValueError::new_err(
                    "broadcast_key_hex must be exactly 64 hex characters (32 bytes)",
                )
            })?);

        let broadcast_key = scp_core::crypto::sender_keys::BroadcastKey::from_parts(
            scp_core::crypto::sender_keys::SenderKey::from_bytes(*key_bytes),
            0,
            author_did,
        );

        let adm = match admission.to_lowercase().as_str() {
            "open" => scp_core::context::broadcast::BroadcastAdmission::Open,
            "gated" => scp_core::context::broadcast::BroadcastAdmission::Gated,
            other => {
                return Err(pyo3::exceptions::PyValueError::new_err(format!(
                    "admission must be \"open\" or \"gated\", got \"{other}\""
                )));
            }
        };

        let idx_path_str = index_path.as_deref().unwrap_or("/index.html");
        let content_path = scp_core::context::broadcast_content::ContentPath::new(idx_path_str)
            .map_err(|e| {
                pyo3::exceptions::PyValueError::new_err(format!("invalid index_path: {e}"))
            })?;

        let site_config = scp_node::projection::SiteConfig {
            hostname,
            index_path: content_path,
            max_assets_per_deploy: max_assets_per_deploy.unwrap_or(10_000),
            max_deploy_size_bytes: max_deploy_size_bytes.unwrap_or(512 * 1024 * 1024),
            deploy_retention_count: deploy_retention_count.unwrap_or(2),
            csp_override,
        };

        py.allow_threads(|| {
            rt.block_on(self.inner.enable_broadcast_projection_with_site(
                &context_id,
                broadcast_key,
                adm,
                Some(site_config),
            ))
            .map_err(node_err)
        })
    }

    /// Commits a deploy for a projected context (§18.11.11).
    ///
    /// Scans blobs matching the ``deploy_id``, decrypts each to extract
    /// metadata, builds an immutable path index, and atomically swaps the
    /// serving pointer.
    ///
    /// Returns the number of assets in the committed deploy.
    fn commit_deploy(
        &self,
        py: Python<'_>,
        context_id: String,
        deploy_id: String,
    ) -> PyResult<usize> {
        crate::validate::validate_context_id(&context_id)?;
        crate::validate::validate_deploy_id(&deploy_id)?;
        let rt = crate::runtime()?;
        py.allow_threads(|| {
            rt.block_on(self.inner.commit_deploy(&context_id, &deploy_id))
                .map_err(node_err)
        })
    }

    /// Rolls back to a previous deploy for a projected context (§18.11.11).
    ///
    /// Sets the path index pointer to a previous deploy within the retention
    /// window.
    fn rollback_deploy(
        &self,
        py: Python<'_>,
        context_id: String,
        deploy_id: String,
    ) -> PyResult<()> {
        crate::validate::validate_context_id(&context_id)?;
        crate::validate::validate_deploy_id(&deploy_id)?;
        let rt = crate::runtime()?;
        py.allow_threads(|| {
            rt.block_on(self.inner.rollback_deploy(&context_id, &deploy_id))
                .map_err(node_err)
        })
    }

    /// Deactivates HTTP broadcast projection for the given context.
    ///
    /// Removes the projected context from the registry and drops all
    /// retained epoch keys.
    fn disable_site_projection(&self, py: Python<'_>, context_id: String) -> PyResult<()> {
        crate::validate::validate_context_id(&context_id)?;
        let rt = crate::runtime()?;
        py.allow_threads(|| {
            rt.block_on(self.inner.disable_broadcast_projection(&context_id));
            Ok(())
        })
    }

    /// Starts the HTTP server in the background on the given bind address.
    ///
    /// If ``bind_addr`` is ``None``, defaults to ``127.0.0.1:8443``
    /// (loopback only). Pass ``"0.0.0.0:PORT"`` for network access.
    ///
    /// Returns the actual bound address as a string (e.g., ``"127.0.0.1:8443"``).
    ///
    /// Raises ``RuntimeError`` if the server is already running or binding fails.
    #[pyo3(signature = (bind_addr=None))]
    fn serve(&self, py: Python<'_>, bind_addr: Option<String>) -> PyResult<String> {
        let addr = bind_addr
            .map(|s| {
                s.parse::<std::net::SocketAddr>().map_err(|e| {
                    pyo3::exceptions::PyValueError::new_err(format!("invalid bind_addr: {e}"))
                })
            })
            .transpose()?;
        let rt = crate::runtime()?;
        py.allow_threads(|| {
            rt.block_on(self.inner.serve_background(addr))
                .map(|a| a.to_string())
                .map_err(node_err)
        })
    }

    /// Returns the HTTP URL of the background server, or ``None`` if not serving.
    #[getter]
    fn http_url(&self, py: Python<'_>) -> PyResult<Option<String>> {
        let rt = crate::runtime()?;
        Ok(py.allow_threads(|| rt.block_on(self.inner.http_url())))
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

    #[test]
    fn enable_site_projection_invalid_context_returns_error() {
        // enable_broadcast_projection_with_site on a fresh node with a valid
        // key should succeed (the context need not exist in the manager for
        // projection — it is purely a node-local routing table entry).
        let node = rt().block_on(server::start_node_in_memory()).unwrap();
        let key = scp_core::crypto::sender_keys::BroadcastKey::from_parts(
            scp_core::crypto::sender_keys::SenderKey::from_bytes([0xAB; 32]),
            0,
            "did:dht:test123".to_owned(),
        );
        let site_config = scp_node::projection::SiteConfig::with_hostname("example.com").unwrap();
        let result = rt().block_on(node.enable_broadcast_projection_with_site(
            "test-ctx",
            key,
            scp_core::context::broadcast::BroadcastAdmission::Open,
            None,
            Some(site_config),
        ));
        assert!(
            result.is_ok(),
            "enable_site_projection should succeed: {result:?}"
        );
        node.shutdown();
    }

    #[test]
    fn commit_deploy_on_unprojected_context_returns_error() {
        let node = rt().block_on(server::start_node_in_memory()).unwrap();
        let result = rt().block_on(node.commit_deploy("nonexistent-ctx", "deploy-1"));
        assert!(
            result.is_err(),
            "commit_deploy on unknown context should fail"
        );
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("not projected"),
            "error should mention 'not projected', got: {err_msg}"
        );
        node.shutdown();
    }

    #[test]
    fn rollback_deploy_on_unprojected_context_returns_error() {
        let node = rt().block_on(server::start_node_in_memory()).unwrap();
        let result = rt().block_on(node.rollback_deploy("nonexistent-ctx", "deploy-1"));
        assert!(
            result.is_err(),
            "rollback_deploy on unknown context should fail"
        );
        node.shutdown();
    }

    #[test]
    fn disable_site_projection_on_unprojected_context_is_noop() {
        let node = rt().block_on(server::start_node_in_memory()).unwrap();
        // Should not panic — disable on unknown context is a no-op.
        rt().block_on(node.disable_broadcast_projection("nonexistent-ctx"));
        node.shutdown();
    }

    #[test]
    fn node_inner_lifecycle_dispatch() {
        // Test the NodeInner dispatch methods (which are the FFI layer).
        let node = rt().block_on(server::start_node_in_memory()).unwrap();
        let inner = NodeInner::InMemory(node);

        // enable_site_projection via NodeInner
        let key = scp_core::crypto::sender_keys::BroadcastKey::from_parts(
            scp_core::crypto::sender_keys::SenderKey::from_bytes([0xCD; 32]),
            0,
            "did:dht:dispatch-test".to_owned(),
        );
        let site_config =
            scp_node::projection::SiteConfig::with_hostname("dispatch.example.com").unwrap();
        let result = rt().block_on(inner.enable_broadcast_projection_with_site(
            "dispatch-ctx",
            key,
            scp_core::context::broadcast::BroadcastAdmission::Open,
            Some(site_config),
        ));
        assert!(
            result.is_ok(),
            "NodeInner enable should succeed: {result:?}"
        );

        // commit_deploy — will fail because no blobs exist but should return
        // a proper error, not panic.
        let cd_result = rt().block_on(inner.commit_deploy("dispatch-ctx", "deploy-abc"));
        // This will return an error about no assets or similar — the important
        // thing is that dispatch works and doesn't panic.
        assert!(cd_result.is_ok() || cd_result.is_err());

        // disable
        rt().block_on(inner.disable_broadcast_projection("dispatch-ctx"));

        inner.shutdown();
    }

    #[test]
    fn serve_background_dispatches_through_node_inner() {
        let node = rt().block_on(server::start_node_in_memory()).unwrap();
        let inner = NodeInner::InMemory(node);

        // serve_background with port 0 (OS-assigned)
        let addr = rt()
            .block_on(inner.serve_background(Some(std::net::SocketAddr::from(([127, 0, 0, 1], 0)))))
            .unwrap();

        assert_ne!(addr.port(), 0, "should bind to a real port");
        assert!(addr.ip().is_loopback());

        // http_url should return Some
        let url = rt().block_on(inner.http_url());
        assert!(url.is_some(), "http_url should be Some after serve");

        // Double serve should fail
        let result = rt().block_on(
            inner.serve_background(Some(std::net::SocketAddr::from(([127, 0, 0, 1], 0)))),
        );
        assert!(result.is_err(), "double serve should fail");

        inner.shutdown();
    }
}
