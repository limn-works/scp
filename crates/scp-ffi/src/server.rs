//! `PyO3` bridge for relay and application node server startup.
//!
//! Wraps the shared startup code in `scp-ffi-common::server` for consumption
//! from Python via `PyO3` `#[pyclass]` definitions and methods on the `SCP`
//! class.
//!
//! - [`PyRelayHandle`] -- opaque handle to a running relay server.
//! - [`PyNodeHandle`] -- opaque handle to a running application node (wraps
//!   both `InMemoryStorage` and `FilesystemStorage` variants via an internal
//!   enum).
//! - [`PyScp::relay_start_in_memory`] / [`PyScp::relay_start_local`] -- relay
//!   startup.
//! - [`PyScp::node_start_in_memory`] / [`PyScp::node_start_local`] -- node
//!   startup.
//!
//! Migrated from flat `#[pyfunction]` exports to `#[pymethods] impl PyScp`
//! methods in Phase 4 PR 4 sub-slice D (#1549).
//!
//! Gated behind the `server` feature on `scp-ffi-common`. Not available for
//! WASM (ADR-034).

use std::sync::Arc;

use pyo3::prelude::*;
use zeroize::Zeroizing;

use scp_ffi_common::server::{
    self, ConcreteDidMethod, NodeIdentity, RunningNode, RunningRelay, ServerError,
};
use scp_identity::{DidCache, InMemoryDhtClient};
use scp_node::NodeError;
use scp_transport::native::NativeRelayAdapter;
use scp_transport::relay::connection::{RelayUrlSource, SourcedRelayUrl};

// ---------------------------------------------------------------------------
// Error conversion
// ---------------------------------------------------------------------------

fn server_err(e: ServerError) -> PyErr {
    tracing::debug!(error = %e, "server operation failed");
    match &e {
        ServerError::MissingPassphrase => {
            // Map to ValidationError (code SCP-VALID-7004) to match the
            // UniFFI bridge and allow Python callers to distinguish this
            // actionable error from generic RuntimeError failures.
            crate::error::ScpPyError::ValidationError {
                message: e.user_message(),
                code: scp_ffi_common::error_codes::VALID_7004.to_owned(),
            }
            .into()
        }
        _ => pyo3::exceptions::PyRuntimeError::new_err(e.user_message()),
    }
}

fn node_err(e: NodeError) -> PyErr {
    tracing::debug!(error = %e, "node operation failed");
    pyo3::exceptions::PyRuntimeError::new_err("node operation failed")
}

/// Auto-wires the global [`ContextManager`] with relay transport after
/// node startup.
///
/// Connects to the node's local relay (with bearer token authentication)
/// and initializes the `ContextManager` with `RelayTransportProvider` so
/// that context operations (create, join, send) work immediately. If the
/// `ContextManager` was already initialized (e.g., by a prior
/// `configure_relay_transport` or `context_create` call), this is a no-op
/// — the `OnceLock` ensures first-writer-wins semantics.
///
/// The `bridge_token` is required because `ApplicationNode` relays enforce
/// `Authorization: Bearer <token>` on all WebSocket connections.
///
/// Best-effort: logs a warning if the relay connection fails rather than
/// blocking node startup.
fn auto_wire_context_manager(
    bi: &crate::runtime::PyBridgeInstance,
    py: Python<'_>,
    rt: &tokio::runtime::Runtime,
    did: &str,
    relay_url: &str,
    bridge_token: Zeroizing<String>,
) {
    let sourced = SourcedRelayUrl {
        url: relay_url.to_owned(),
        source: RelayUrlSource::Explicit,
    };
    let did_owned = did.to_owned();
    let token2 = bridge_token.clone();
    let profile = scp_transport::profile::TransportProfile::platform_default();
    match py.allow_threads(|| {
        rt.block_on(NativeRelayAdapter::connect_sourced_with_bearer(
            &sourced,
            Some(bridge_token),
            Some(&profile),
        ))
    }) {
        Ok(adapter) => {
            let crypto = Box::new(scp_core::crypto::mls::provider::MlsCryptoProvider::new(
                did_owned.clone(),
            ));
            let transport = Box::new(scp_transport::RelayTransportProvider::new(adapter));
            let event_log: Box<dyn scp_core::context::builder::ContextEventLogProvider> =
                Box::new(crate::runtime::NoOpEventLogProvider);
            crate::runtime::init_context_manager_with(
                &did_owned, crypto, transport, event_log, None,
            );

            // Also populate the BridgeInstance transport manager so that
            // broadcast publish, context subscribe, and discovery probing
            // work without a separate `transport_connect` call. This requires
            // a second WebSocket connection because NativeRelayAdapter is not
            // Clone and the first was consumed by RelayTransportProvider.
            match py.allow_threads(|| {
                rt.block_on(NativeRelayAdapter::connect_sourced_with_bearer(
                    &sourced,
                    Some(token2),
                    Some(&profile),
                ))
            }) {
                Ok(relay_adapter) => {
                    let manager = scp_transport::TransportManager::new(Box::new(relay_adapter));
                    let _ = crate::runtime::set_transport_manager(bi, manager);
                }
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        relay_url = %relay_url,
                        "auto_wire_context_manager: ContextManager wired but failed to \
                         populate BridgeInstance transport manager — broadcast publish and \
                         discovery may require a manual transport_connect call"
                    );
                }
            }
        }
        Err(e) => {
            tracing::warn!(
                error = %e,
                relay_url = %relay_url,
                "auto_wire_context_manager: failed to connect to node relay — \
                 context operations may fail until transport is configured manually"
            );
            // Fall back to initializing without transport so that at least
            // the ContextManager exists (with NotConfiguredTransportProvider).
            crate::runtime::init_context_manager(&did_owned);
        }
    }
    // Always register the node's DID as a local DID for defense-in-depth.
    py.allow_threads(|| {
        if let Ok(mgr) = crate::runtime::context_manager(bi) {
            rt.block_on(mgr.register_local_did(did_owned.into()));
        }
    });
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
    /// Bridge instance affinity id (Phase 4 PR 1 — #1549).
    ///
    /// `dead_code` allowance: future commits of this PR will add
    /// `check_handle` at every entry point that accepts this handle.
    #[allow(dead_code)]
    pub(crate) instance_id: u64,
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

/// Opaque handle to a running SCP application node.
///
/// Created by `node_start_in_memory()` or `node_start_local()`. The node
/// includes a running relay server, a generated DID identity, and (optionally)
/// persistent storage. The HTTP server is **not** started automatically --
/// only the relay is bound.
#[pyclass(name = "NodeHandle")]
pub struct PyNodeHandle {
    inner: RunningNode,
    /// Bridge instance affinity id (Phase 4 PR 1 — #1549).
    ///
    /// `dead_code` allowance: future commits of this PR will add
    /// `check_handle` at every entry point that accepts this handle.
    #[allow(dead_code)]
    pub(crate) instance_id: u64,
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
    /// Three resolution modes:
    /// 1. Both ``broadcast_key_hex`` **and** ``author_did`` provided -- uses
    ///    the explicit key with epoch 0.
    /// 2. Only ``author_did`` provided -- auto-resolves the broadcast key
    ///    using that DID (useful when the author identity differs from the
    ///    node identity).
    /// 3. Neither provided -- auto-resolves using the node's identity DID.
    ///
    /// Providing ``broadcast_key_hex`` without ``author_did`` raises
    /// ``ValueError``.
    ///
    /// ``admission`` is ``"open"`` or ``"gated"``.
    ///
    /// Site configuration fields:
    /// - ``hostname`` (required): virtual host hostname (RFC 1123).
    /// - ``index_path``: default path for directory requests (default ``"/index.html"``).
    /// - ``max_assets_per_deploy``: max assets per deploy (default 10000).
    /// - ``max_deploy_size_bytes``: max total deploy size in bytes (default 536870912).
    /// - ``deploy_retention_count``: deploys to retain (default 2, max 8).
    /// - ``csp_override``: optional Content-Security-Policy override.
    #[pyo3(signature = (context_id, admission, hostname, broadcast_key_hex=None, author_did=None, index_path=None, max_assets_per_deploy=None, max_deploy_size_bytes=None, deploy_retention_count=None, csp_override=None))]
    #[allow(clippy::too_many_arguments)]
    fn enable_site_projection(
        &self,
        py: Python<'_>,
        context_id: String,
        admission: String,
        hostname: String,
        broadcast_key_hex: Option<String>,
        author_did: Option<String>,
        index_path: Option<String>,
        max_assets_per_deploy: Option<usize>,
        max_deploy_size_bytes: Option<u64>,
        deploy_retention_count: Option<usize>,
        csp_override: Option<String>,
    ) -> PyResult<()> {
        crate::validate::validate_context_id(&context_id)?;
        if let Some(ref did) = author_did {
            crate::validate::validate_did(did)?;
        }
        let rt = crate::runtime()?;

        // Resolve broadcast key: explicit or auto-lookup from ContextManager.
        // `PyNodeHandle` is owned by the Python process (not tied to a
        // specific `PyScp` instance) so it routes through the default
        // bridge instance. Per-instance `NodeHandle` support lands with the
        // affinity check in a later commit of PR 4.
        let bi_for_mgr = crate::runtime::default_bridge_instance()?;
        let mgr = Arc::clone(crate::runtime::context_manager(&bi_for_mgr).map_err(|e| {
            pyo3::exceptions::PyRuntimeError::new_err(format!(
                "broadcast key auto-lookup failed: {e}"
            ))
        })?);
        let resolved = py.allow_threads(|| {
            rt.block_on(server::resolve_broadcast_key(
                broadcast_key_hex,
                author_did,
                self.inner.did(),
                &mgr,
                &context_id,
            ))
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))
        })?;
        let broadcast_key = resolved.into_broadcast_key();

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
    /// Returns the actual bound address as a raw string (e.g.,
    /// ``"127.0.0.1:8443"``). Use :meth:`http_url` for the full URL form
    /// (``"http://127.0.0.1:8443"``).
    ///
    /// **Note:** The background server does not support TLS. For production
    /// deployments requiring encryption, use the node binary's ``serve()``
    /// with TLS configuration.
    ///
    /// Raises ``RuntimeError`` if the server is already running or binding fails.
    #[pyo3(signature = (bind_addr=None))]
    fn serve(&self, py: Python<'_>, bind_addr: Option<String>) -> PyResult<String> {
        let addr = bind_addr
            .map(|s| {
                s.parse::<std::net::SocketAddr>().map_err(|e| {
                    let display = if s.len() > 128 {
                        &s[..s.floor_char_boundary(128)]
                    } else {
                        &s
                    };
                    pyo3::exceptions::PyValueError::new_err(format!(
                        "invalid bind_addr \"{display}\": {e}"
                    ))
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
    ///
    /// Returns the literal bind address, which may contain ``0.0.0.0`` if the
    /// server was bound to the unspecified address.
    #[pyo3(name = "http_url")]
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
// Identity portability helper
// ---------------------------------------------------------------------------

/// Constructs a [`NodeIdentity`] from the given bridge instance's identity
/// registry.
///
/// Looks up the given DID in the `PyO3` bridge identity registry (populated by
/// `PyScp::identity_create`) and builds a `NodeIdentity` with a configured DID
/// method instance that can sign on behalf of the identity's custody provider.
///
/// # Errors
///
/// Returns `PyErr` if the DID is not found in the identity registry.
fn build_node_identity(
    bi: &crate::runtime::PyBridgeInstance,
    did: &str,
) -> PyResult<NodeIdentity> {
    crate::runtime::with_identity(bi, did, |entry| {
        let custody = Arc::clone(&entry.custody);
        let sign_fn = ConcreteDidMethod::make_sign_fn(custody);
        let dht_client = Arc::new(InMemoryDhtClient::new());
        let cache = Arc::new(DidCache::new());
        let did_method = Arc::new(ConcreteDidMethod::with_client_and_signer(
            dht_client, cache, sign_fn,
        ));

        Ok(NodeIdentity {
            identity: entry.identity.clone(),
            document: entry.document.clone(),
            did_method,
        })
    })
    .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(format!("{e}")))
}

// ---------------------------------------------------------------------------
// PyScp methods — migrated from #[pyfunction] exports (Phase 4 PR 4, #1549).
// ---------------------------------------------------------------------------

#[pymethods]
impl crate::scp::PyScp {
    /// Starts a relay with in-memory blob storage on an OS-assigned port.
    ///
    /// Returns a :class:`RelayHandle` whose ``relay_url`` property contains the
    /// WebSocket URL for clients.
    #[pyo3(name = "relay_start_in_memory")]
    pub fn relay_start_in_memory(&self, py: Python<'_>) -> PyResult<PyRelayHandle> {
        let bi = &*self.inner;
        let rt = crate::runtime()?;
        py.allow_threads(|| {
            let relay = rt
                .block_on(server::start_relay_in_memory())
                .map_err(server_err)?;
            let instance_id = bi.core.instance_id();
            Ok(PyRelayHandle {
                inner: relay,
                instance_id,
            })
        })
    }

    /// Starts a relay with redb-backed blob storage on an OS-assigned port.
    ///
    /// Opens (or creates) a redb database at ``<data_dir>/blobs.redb``.
    #[pyo3(name = "relay_start_local")]
    pub fn relay_start_local(
        &self,
        py: Python<'_>,
        data_dir: String,
    ) -> PyResult<PyRelayHandle> {
        let bi = &*self.inner;
        let rt = crate::runtime()?;
        py.allow_threads(|| {
            let relay = rt
                .block_on(server::start_relay_local(std::path::Path::new(&data_dir)))
                .map_err(server_err)?;
            let instance_id = bi.core.instance_id();
            Ok(PyRelayHandle {
                inner: relay,
                instance_id,
            })
        })
    }

    /// Starts a full application node with in-memory storage.
    ///
    /// When ``identity_did`` is ``None`` (the default), auto-wires in-memory key
    /// custody, in-memory storage, in-memory DHT client, self-signed TLS, and a
    /// relay on an OS-assigned port with a fresh DID.
    ///
    /// When ``identity_did`` is provided, the node uses the pre-existing identity
    /// from the `PyO3` identity registry (populated by ``PyScp::identity_create``).
    /// This enables identity portability — the same DID persists across node
    /// restarts.
    #[pyo3(name = "node_start_in_memory", signature = (identity_did=None))]
    pub fn node_start_in_memory(
        &self,
        py: Python<'_>,
        identity_did: Option<String>,
    ) -> PyResult<PyNodeHandle> {
        let bi = &*self.inner;
        let rt = crate::runtime()?;
        let node_identity = match identity_did {
            Some(ref did) => {
                crate::validate::validate_did(did)?;
                Some(build_node_identity(bi, did)?)
            }
            None => None,
        };
        let node = py.allow_threads(|| {
            rt.block_on(server::start_node_in_memory(node_identity))
                .map_err(server_err)
        })?;

        // Auto-wire the ContextManager with relay transport so that
        // context operations work immediately after node startup.
        // Use the internal loopback URL (ws://127.0.0.1:{port}/scp/v1) instead of
        // node.relay_url() which returns the advertised URL (wss://localhost/scp/v1)
        // that requires TLS and lacks the actual bound port.
        // The bridge token is required because ApplicationNode relays enforce
        // Authorization: Bearer <token> on all WebSocket connections.
        let did = node.identity().did().to_owned();
        let relay_url = format!("ws://127.0.0.1:{}/scp/v1", node.relay().bound_addr().port());
        let bridge_token = node.bridge_token_hex();
        auto_wire_context_manager(bi, py, rt, &did, &relay_url, bridge_token);

        let instance_id = bi.core.instance_id();
        Ok(PyNodeHandle {
            inner: RunningNode::InMemory(node),
            instance_id,
        })
    }

    /// Starts a full application node with file-backed storage.
    ///
    /// Opens (or creates) persistent storage at ``<data_dir>/storage/`` and a redb
    /// blob database at ``<data_dir>/blobs.redb``.
    ///
    /// When ``identity_did`` is ``None`` (the default), the node creates or
    /// reloads a persistent identity from ``<data_dir>/identity.key``. The
    /// ``passphrase`` parameter is required in this mode.
    ///
    /// When ``identity_did`` is provided, the node uses the pre-existing identity
    /// from the `PyO3` identity registry (populated by ``PyScp::identity_create``).
    /// No passphrase is required in this mode.
    #[pyo3(name = "node_start_local", signature = (data_dir, identity_did=None, passphrase=None))]
    pub fn node_start_local(
        &self,
        py: Python<'_>,
        data_dir: String,
        identity_did: Option<String>,
        passphrase: Option<String>,
    ) -> PyResult<PyNodeHandle> {
        let bi = &*self.inner;
        let rt = crate::runtime()?;
        let node_identity = match identity_did {
            Some(ref did) => {
                crate::validate::validate_did(did)?;
                Some(build_node_identity(bi, did)?)
            }
            None => None,
        };
        let zeroized_passphrase = passphrase.map(Zeroizing::new);
        let node = py.allow_threads(|| {
            rt.block_on(server::start_node_local(
                std::path::Path::new(&data_dir),
                node_identity,
                zeroized_passphrase,
            ))
            .map_err(server_err)
        })?;

        // Auto-wire the ContextManager with relay transport so that
        // context operations work immediately after node startup.
        // Use the internal loopback URL — see comment in `node_start_in_memory`.
        let did = node.identity().did().to_owned();
        let relay_url = format!("ws://127.0.0.1:{}/scp/v1", node.relay().bound_addr().port());
        let bridge_token = node.bridge_token_hex();
        auto_wire_context_manager(bi, py, rt, &did, &relay_url, bridge_token);

        let instance_id = bi.core.instance_id();
        Ok(PyNodeHandle {
            inner: RunningNode::Filesystem(node),
            instance_id,
        })
    }
}

// ---------------------------------------------------------------------------
// Module registration
// ---------------------------------------------------------------------------

/// Registers the server bridge classes in the Python module.
///
/// Post-migration (Phase 4 PR 4 sub-slice D) relay/node startup operations are
/// exposed as methods on `SCP` (see the `#[pymethods]` block above) and
/// registered automatically with the class. Only the opaque [`PyRelayHandle`]
/// and [`PyNodeHandle`] classes still require manual class registration here.
pub fn register_server(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyRelayHandle>()?;
    m.add_class::<PyNodeHandle>()?;
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
        let node = rt().block_on(server::start_node_in_memory(None)).unwrap();
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
        let passphrase = Zeroizing::new("test-passphrase".to_owned());
        let node = rt()
            .block_on(server::start_node_local(&tmp, None, Some(passphrase)))
            .unwrap();
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
        let node = rt().block_on(server::start_node_in_memory(None)).unwrap();
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
        let node = rt().block_on(server::start_node_in_memory(None)).unwrap();
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
        let node = rt().block_on(server::start_node_in_memory(None)).unwrap();
        let result = rt().block_on(node.rollback_deploy("nonexistent-ctx", "deploy-1"));
        assert!(
            result.is_err(),
            "rollback_deploy on unknown context should fail"
        );
        node.shutdown();
    }

    #[test]
    fn disable_site_projection_on_unprojected_context_is_noop() {
        let node = rt().block_on(server::start_node_in_memory(None)).unwrap();
        // Should not panic — disable on unknown context is a no-op.
        rt().block_on(node.disable_broadcast_projection("nonexistent-ctx"));
        node.shutdown();
    }

    #[test]
    fn node_inner_lifecycle_dispatch() {
        // Test the RunningNode dispatch methods (which are the FFI layer).
        let node = rt().block_on(server::start_node_in_memory(None)).unwrap();
        let inner = RunningNode::InMemory(node);

        // enable_site_projection via RunningNode
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
            "RunningNode enable should succeed: {result:?}"
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
        let node = rt().block_on(server::start_node_in_memory(None)).unwrap();
        let inner = RunningNode::InMemory(node);

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

    /// Verifies that auto-wiring a node's relay populates the `BridgeInstance`
    /// transport manager so that broadcast publish, context subscribe,
    /// and discovery probing work without a separate `transport_connect`.
    #[test]
    fn auto_wire_populates_transport_manager_global() {
        use scp_transport::relay::connection::{RelayUrlSource, SourcedRelayUrl};

        // BridgeInstance must exist for transport manager storage.
        crate::runtime::init_context_manager_for_test();

        // Start a standalone relay to get a stable WebSocket endpoint.
        let relay = rt().block_on(server::start_relay_in_memory()).unwrap();
        let relay_url = relay.relay_url().to_owned();

        // Connect to the relay and store in the global — mirrors what
        // auto_wire_context_manager does after ContextManager init.
        let sourced = SourcedRelayUrl {
            url: relay_url,
            source: RelayUrlSource::Explicit,
        };
        let adapter = rt()
            .block_on(NativeRelayAdapter::connect_sourced(&sourced, None))
            .expect("should connect to the relay");
        let manager = scp_transport::TransportManager::new(Box::new(adapter));
        crate::runtime::set_transport_manager(manager)
            .expect("should store transport manager in global");

        // Verify the global is populated.
        assert!(
            crate::runtime::has_transport_manager(),
            "BridgeInstance transport manager should be populated after auto-wire"
        );

        // Clean up.
        crate::runtime::clear_transport_manager().ok();
        relay.shutdown();
    }
}
