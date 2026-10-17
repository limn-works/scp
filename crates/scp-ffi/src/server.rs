//! `PyO3` bridge for relay and application node server startup.
//!
//! Wraps the shared startup code in `scp-ffi-common::server` for consumption
//! from Python via `PyO3` `#[pyclass]` definitions and methods on the `SCP`
//! class.
//!
//! - [`PyRelayHandle`] -- opaque handle to a running relay server.
//! - [`PyNodeHandle`] -- opaque handle to a running application node (wraps
//!   encrypted-in-memory and `SQLCipher` variants via an internal enum).
//! - `PyScp::relay_start_in_memory` / `PyScp::relay_start_local` -- relay
//!   startup.
//! - `PyScp::node_start` -- production node start from this instance's
//!   storage under an operator identity (SCP-322).
//! - `PyScp::node_start_in_memory` / `PyScp::node_start_local` -- node
//!   startup.
//!
//! Migrated from flat `#[pyfunction]` exports to `#[pymethods] impl PyScp`
//! methods in Phase 4 PR 4 sub-slice D (#1549).
//!
//! Gated behind the `server` feature on `scp-ffi-common`.

use std::sync::Arc;

use pyo3::prelude::*;
use zeroize::Zeroizing;

use scp_ffi_common::error_codes as codes;
use scp_ffi_common::node_start_config::NodeStartConfig;
use scp_ffi_common::server::{
    self, ConcreteDidMethod, InstanceStorage, NodeIdentity, RunningNode, RunningRelay, ServerError,
};
use scp_identity::DidCache;
use scp_node::NodeError;

use crate::error::ScpPyError;

// ---------------------------------------------------------------------------
// Error conversion
// ---------------------------------------------------------------------------

/// Builds the [`ScpPyError`] for `e` with `message`: the variant from
/// `server_error_class` and the code from `server_error_code`, the one mapping
/// the `PyO3`, napi-rs and `UniFFI` bridges share (sdk-common.md §"Node start
/// error codes").
fn coded(e: &ServerError, message: String) -> ScpPyError {
    let code = codes::server_error_code(e).to_owned();
    match codes::server_error_class(e) {
        codes::ServerErrorClass::Validation => ScpPyError::ValidationError { message, code },
        codes::ServerErrorClass::Identity => ScpPyError::IdentityError { message, code },
        codes::ServerErrorClass::Transport => ScpPyError::TransportError { message, code },
        codes::ServerErrorClass::Context => ScpPyError::ContextError { message, code },
    }
}

/// Maps a [`ServerError`] to its coded [`ScpPyError`] with the sanitized
/// [`ServerError::user_message`]; the full error goes to the debug log only.
fn server_error(e: ServerError) -> ScpPyError {
    tracing::debug!(error = %e, "server operation failed");
    coded(&e, e.user_message())
}

fn server_err(e: ServerError) -> PyErr {
    server_error(e).into()
}

/// A `NodeError` from a running node's operation (projection, deploy, serve)
/// maps as `ServerError::Node` does, with a message that names no path.
fn node_err(e: NodeError) -> PyErr {
    tracing::debug!(error = %e, "node operation failed");
    coded(&ServerError::Node(e), "node operation failed".to_owned()).into()
}

/// Wires `bi`'s `Supervisor` to the started, registered `node` through the
/// relay at `relay_url`, which every production caller sets to
/// `node.internal_relay_url()`.
///
/// Delegates to [`server::wire_supervisor_to_node`], which on any failure
/// shuts `node` down, removes it from the instance's node registry, and
/// returns `ServerError::SupervisorWiring` (`SCP-TRANS-5056`, sdk-common.md
/// §"Node start error codes"). The attach step is
/// [`crate::runtime::init_context_manager`], the same set-once init
/// `context_create` runs, which builds the `Supervisor` with the instance's
/// persistent event-log provider: a `NoOp` event log would drop every
/// governance, role and membership leaf that
/// `Supervisor::participation_record` (§7.3.2) reads.
fn auto_wire_context_manager(
    bi: &crate::runtime::PyBridgeInstance,
    py: Python<'_>,
    rt: &tokio::runtime::Runtime,
    node: &Arc<RunningNode>,
    relay_url: &str,
) -> Result<(), ScpPyError> {
    py.allow_threads(|| {
        rt.block_on(server::wire_supervisor_to_node(
            &bi.core,
            node,
            relay_url,
            |did| crate::runtime::init_context_manager(bi, did),
        ))
    })
    .map_err(server_error)
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
    /// Shared with this instance's borrower registry, which holds a `Weak` to
    /// this same node so `SCP.shutdown()` stops it before releasing storage
    /// (see `scp_ffi_common::bridge_instance::InstanceBorrower`).
    inner: Arc<RunningNode>,
    /// Bridge instance affinity id (Phase 4 PR 1 — #1549).
    ///
    /// `dead_code` allowance: future commits of this PR will add
    /// `check_handle` at every entry point that accepts this handle.
    #[allow(dead_code)]
    pub(crate) instance_id: u64,
    /// The bridge instance that owns this node's `ContextManager`. Stored
    /// so methods on `PyNodeHandle` (e.g. `publish_broadcast`) can resolve
    /// the manager without consulting any process-global default
    /// (Phase D #1695).
    pub(crate) bi: Arc<crate::runtime::PyBridgeInstance>,
}

// PyO3 `#[getter]` methods require `&self` and cannot be `const` or `#[must_use]`.
// These are framework constraints, not code quality issues.
#[pymethods]
#[allow(clippy::must_use_candidate, clippy::missing_const_for_fn)]
impl PyNodeHandle {
    /// Returns the WebSocket URL clients should connect to for this node's
    /// relay (e.g., ``ws://127.0.0.1:12345/scp/v1``).
    ///
    /// Read live per call from the node's relay-URL slot, so it reflects a NAT
    /// tier change that re-pointed the node's endpoint.
    #[getter]
    fn relay_url(&self) -> String {
        self.inner.relay_url()
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

    /// Signals the node to stop (relay + background tasks), and unbinds the
    /// instance's `Supervisor` transport from this node when it holds the
    /// binding.
    fn shutdown(&self) {
        server::stop_node(&self.bi.core, &self.inner);
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

        // Resolve broadcast key: explicit or auto-lookup via Supervisor.
        // `PyNodeHandle` carries a reference to the bridge instance that
        // spawned it, so we resolve the supervisor from there.
        let supervisor = Arc::clone(crate::runtime::supervisor(&self.bi).map_err(|e| {
            pyo3::exceptions::PyRuntimeError::new_err(format!(
                "broadcast key auto-lookup failed: {e}"
            ))
        })?);
        let resolved = py.allow_threads(|| {
            rt.block_on(server::resolve_broadcast_key(
                broadcast_key_hex,
                author_did,
                self.inner.did(),
                &supervisor,
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
        server::stop_node(&self.bi.core, &self.inner);
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
/// - `IdentityError` with `SCP-IDENT-1063` (`OperatorIdentityUnavailable`,
///   sdk-common.md §"Node start error codes") when the DID is not registered
///   on this instance.
/// - `IdentityError` with `SCP-IDENT-1058` when the instance has no DHT client
///   and the production client cannot be built.
fn build_node_identity(
    bi: &crate::runtime::PyBridgeInstance,
    did: &str,
) -> Result<NodeIdentity, ScpPyError> {
    let entry = crate::runtime::identity_registry(bi)
        .get(did)
        .ok_or_else(|| server_error(ServerError::OperatorIdentityUnavailable))?;
    let custody = Arc::clone(&entry.custody);
    let sign_fn = ConcreteDidMethod::make_sign_fn(custody);
    // Publish through the instance's shared DHT client (the one the resolver
    // reads from) so a node serving this identity re-publishes into the same
    // DHT the rest of the bridge resolves against. Fall back to a fail-closed
    // production client if the resolver was never initialized — never an
    // in-memory nullifier on a shipped path (ADR-062 §Decision 1).
    let dht_client = match crate::runtime::resolver_dht_client(bi) {
        Some(client) => client,
        None => Arc::new(crate::identity::build_ffi_dht_client()?),
    };
    let cache = Arc::new(DidCache::new());
    let did_method = Arc::new(ConcreteDidMethod::with_client_and_signer(
        dht_client, cache, sign_fn,
    ));
    Ok(NodeIdentity {
        identity: entry.identity.clone(),
        document: entry.document.clone(),
        did_method,
    })
}

/// Resolves the operator identity a node start config names: a malformed DID
/// is `InvalidConfig` (`SCP-STORAGE-8007`), and a DID not registered on this
/// instance is `OperatorIdentityUnavailable` (`SCP-IDENT-1063`).
fn resolve_operator_identity(
    bi: &crate::runtime::PyBridgeInstance,
    did: &str,
) -> Result<NodeIdentity, ScpPyError> {
    if scp_ffi_common::validate::validate_did(did).is_err() {
        return Err(server_error(ServerError::InvalidConfig(
            "identity must be a DID".to_owned(),
        )));
    }
    build_node_identity(bi, did)
}

/// The instance's own storage handle, which `server::node_start` gives to the
/// node (spec §17.6). Fails closed when the instance was built without a
/// storage selection.
fn instance_storage(bi: &crate::runtime::PyBridgeInstance) -> Result<InstanceStorage, ScpPyError> {
    Ok(match crate::runtime::get_storage(bi)? {
        crate::runtime::StorageProvider::InMemoryEncrypted(s) => {
            InstanceStorage::InMemoryEncrypted(Arc::clone(s))
        }
        crate::runtime::StorageProvider::Sqlite(s) => InstanceStorage::Sqlite(Arc::clone(s)),
    })
}

/// Starts a production node on `bi`'s storage under the operator identity the
/// config names (construction.md §"Node start — `NodeStartConfig`").
///
/// Runs, in order: the config parse, the operator identity resolution, taking
/// the instance storage, `server::node_start`, `server::register_node`,
/// `auto_wire_context_manager` (which shuts the node down and unregisters it
/// on failure), and wrapping the handle.
///
/// # Errors
///
/// The code sdk-common.md §"Node start error codes" gives each failure.
fn node_start_on(
    bi_arc: &Arc<crate::runtime::PyBridgeInstance>,
    py: Python<'_>,
    rt: &tokio::runtime::Runtime,
    config_json: &str,
) -> Result<PyNodeHandle, ScpPyError> {
    let bi = &**bi_arc;
    let cfg = NodeStartConfig::from_json(config_json).map_err(server_error)?;
    let identity = resolve_operator_identity(bi, &cfg.identity)?;
    let storage = instance_storage(bi)?;
    let node = py
        .allow_threads(|| rt.block_on(server::node_start(cfg, identity, storage)))
        .map_err(server_error)?;
    // Registered before anything else can fail, so `SCP.shutdown()` stops
    // this node before it releases the storage the node holds
    // (`scp_ffi_common::bridge_instance::InstanceBorrower`).
    let inner = server::register_node(&bi.core, node);
    auto_wire_context_manager(bi, py, rt, &inner, &inner.internal_relay_url())?;
    Ok(PyNodeHandle {
        instance_id: bi.core.instance_id(),
        inner,
        bi: Arc::clone(bi_arc),
    })
}

// ---------------------------------------------------------------------------
// PyScp methods — migrated from #[pyfunction] exports (Phase 4 PR 4, #1549).
// ---------------------------------------------------------------------------

#[pymethods]
impl crate::scp::PyScp {
    /// Starts a production node from this ``SCP`` instance.
    ///
    /// ``config_json`` is a ``NodeStartConfig`` (construction.md §"Node start
    /// — ``NodeStartConfig``"): its ``identity`` names an operator identity
    /// registered on this instance, and the node runs on this instance's own
    /// storage. Each failure raises with the code sdk-common.md §"Node start
    /// error codes" gives it, such as ``SCP-IDENT-1063`` for an unregistered
    /// operator DID.
    #[pyo3(name = "node_start")]
    pub fn node_start(&self, py: Python<'_>, config_json: &str) -> PyResult<PyNodeHandle> {
        let rt = crate::runtime()?;
        node_start_on(&self.inner, py, rt, config_json).map_err(PyErr::from)
    }

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
    pub fn relay_start_local(&self, py: Python<'_>, data_dir: String) -> PyResult<PyRelayHandle> {
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

    /// Starts a full application node with encrypted in-memory storage.
    ///
    /// Storage is an ephemeral ``InMemoryStorage`` under an ``EncryptingAdapter``
    /// keyed by a fresh `OsRng` AES-256-GCM key, so a node is built through a
    /// production ``Node::start`` constructor and its ``EncryptedStorage`` bound.
    ///
    /// When ``identity_did`` is ``None`` (a default), a build carrying a
    /// test-harness feature auto-wires in-memory key custody, an in-memory DHT
    /// client, self-signed TLS, and a relay on an OS-assigned port with a fresh
    /// DID; a shipped build fails closed instead.
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

        // Register this node as a borrower of this instance's resources, so
        // `SCP.shutdown()` stops it before `bridge_specific_shutdown` releases
        // anything (`scp_ffi_common::bridge_instance::InstanceBorrower`), and
        // so a failed wiring below can remove it again.
        let inner = server::register_node(&bi.core, RunningNode::InMemoryEncrypted(node));
        // Wire the Supervisor through the internal loopback URL: `relay_url()`
        // is the advertised URL, which requires TLS and lacks the bound port.
        auto_wire_context_manager(bi, py, rt, &inner, &inner.internal_relay_url())?;

        let instance_id = bi.core.instance_id();
        Ok(PyNodeHandle {
            inner,
            instance_id,
            bi: Arc::clone(&self.inner),
        })
    }

    /// Starts a full application node on this instance's own storage backend.
    ///
    /// A node inherits whichever storage handle this ``SCP`` instance was
    /// constructed with (``SCP.with_storage({...})``) — encrypted in-memory or
    /// `SQLCipher` — so its context snapshots, Merkle event log, saga journal,
    /// and `OpenMLS` store land in one backend this instance already owns. A
    /// caller wanting a node on a different backend constructs a second ``SCP``
    /// instance; no per-node storage argument exists.
    ///
    /// ``data_dir`` holds a redb blob database at ``<data_dir>/blobs.redb`` and,
    /// under auto-identity mode, a key file at ``<data_dir>/identity.key``.
    /// No protocol store is created there.
    ///
    /// When ``identity_did`` is ``None`` (a default), a node creates or reloads
    /// a persistent identity from ``<data_dir>/identity.key``, and a
    /// ``passphrase`` argument is required in that mode.
    ///
    /// When ``identity_did`` is provided, a node uses that pre-existing identity
    /// from a `PyO3` identity registry (populated by ``PyScp::identity_create``),
    /// and no passphrase is required.
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
        // Clone this instance's chosen backend out (a cheap `Arc` clone) before
        // crossing into `allow_threads`. `get_storage` fails closed when an
        // instance was built without a storage selection, rather than letting a
        // node open a store of its own (SCP-CAPSEL-8000, spec §17.6).
        let storage = crate::runtime::get_storage(bi)?.clone();
        let inner = py.allow_threads(|| {
            let data_dir = std::path::Path::new(&data_dir);
            match storage {
                crate::runtime::StorageProvider::InMemoryEncrypted(s) => rt
                    .block_on(server::start_node_local(
                        data_dir,
                        s,
                        node_identity,
                        zeroized_passphrase,
                    ))
                    .map(RunningNode::InMemoryEncrypted),
                crate::runtime::StorageProvider::Sqlite(s) => rt
                    .block_on(server::start_node_local(
                        data_dir,
                        s,
                        node_identity,
                        zeroized_passphrase,
                    ))
                    .map(RunningNode::Sqlite),
            }
            .map_err(server_err)
        })?;
        // This node holds a clone of this instance's storage `Arc`, so register
        // it before anything else: `SCP.shutdown()` must stop this node before
        // the durable store closer closes that `SQLCipher` handle and drops
        // an advisory `flock(2)`
        // (`scp_ffi_common::bridge_instance::InstanceBorrower`).
        let inner = server::register_node(&bi.core, inner);

        // Wire the Supervisor through the internal loopback URL — see the
        // comment in `node_start_in_memory`.
        auto_wire_context_manager(bi, py, rt, &inner, &inner.internal_relay_url())?;

        let instance_id = bi.core.instance_id();
        Ok(PyNodeHandle {
            inner,
            instance_id,
            bi: Arc::clone(&self.inner),
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

    /// Regression guard on the `PyO3` reference bridge: after node startup the
    /// production `Supervisor` must have its event broadcast channel enabled, so
    /// `subscribe_events()` yields a receiver. This is the runtime counterpart
    /// to the `NAPI`/`UniFFI` `node_startup_enables_context_event_channel`
    /// tests. Before this assertion existed, `PyO3`'s "actually wired" guarantee
    /// rested solely on a `pipeline_wiring.rs` string-match.
    #[test]
    fn node_startup_enables_context_event_channel() {
        // Initialize the process-global tokio runtime the same way `rt()` does;
        // `node_start_in_memory` fetches it via `crate::runtime()`.
        crate::init_runtime().ok();
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|py| {
            // Production callers choose storage before node startup (spec §17.6 —
            // the runtime never defaults storage). Mirror the SDK by selecting
            // in-memory storage, which is the storage source `build_supervisor`
            // derives `mls_storage` from.
            let config = pyo3::types::PyDict::new(py);
            config
                .set_item("type", "in_memory")
                .expect("set storage type");
            let scp = crate::scp::PyScp::with_storage(py, &config)
                .expect("in-memory storage config must construct");
            let node = scp
                .node_start_in_memory(py, None)
                .expect("node startup must succeed");

            let supervisor = crate::runtime::supervisor(&scp.inner)
                .expect("Supervisor must be attached after node startup");
            assert!(
                supervisor.subscribe_events().is_some(),
                "node startup must enable the Supervisor event channel"
            );

            node.shutdown();
        });
    }

    /// `node_start_local` drives a node onto whichever backend an `SCP`
    /// instance already holds, so this test selects in-memory storage through
    /// `PyScp::with_storage`, then asserts a node starts on that same handle.
    #[test]
    fn node_local_starts_on_the_instance_storage_handle() {
        crate::init_runtime().ok();
        pyo3::prepare_freethreaded_python();
        let tmp = std::env::temp_dir().join(format!("scp-pyo3-node-test-{}", std::process::id()));
        Python::with_gil(|py| {
            let config = pyo3::types::PyDict::new(py);
            config
                .set_item("type", "in_memory")
                .expect("set storage type");
            let scp = crate::scp::PyScp::with_storage(py, &config)
                .expect("in-memory storage config must construct");
            let handle = scp
                .node_start_local(
                    py,
                    tmp.display().to_string(),
                    None,
                    Some("test-passphrase".to_owned()),
                )
                .expect("node startup must succeed on an instance storage handle");
            assert!(
                handle.relay_url().starts_with("ws://") || handle.relay_url().starts_with("wss://")
            );
            assert!(handle.did().starts_with("did:"));
            assert!(handle.relay_port() > 0);
            assert!(
                !tmp.join("storage").exists(),
                "node_start_local must open no protocol store under a data directory"
            );
            handle.shutdown();
        });
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
        let inner = RunningNode::InMemoryEncrypted(node);

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

        let cd_result = rt().block_on(inner.commit_deploy("dispatch-ctx", "deploy-abc"));
        // Code above projected this context, which holds no staged blob, so
        // §18.11.11 of `.docs/specs/18-addressability-and-deployment.md` makes
        // this an empty deploy, which fails. Dispatch reached this node, which
        // the error text proves: an unprojected context reports "not
        // projected" instead, as
        // `commit_deploy_on_unprojected_context_returns_error` pins. An
        // earlier assertion read `is_ok() || is_err()`, which every value
        // satisfies.
        let message = cd_result
            .expect_err("an empty deploy fails rather than swapping in an empty path index")
            .to_string();
        assert!(
            message.contains("matched no staged asset"),
            "dispatch must reach the projected context and refuse the empty deploy: {message}"
        );

        // disable
        rt().block_on(inner.disable_broadcast_projection("dispatch-ctx"));

        inner.shutdown();
    }

    #[test]
    fn serve_background_dispatches_through_node_inner() {
        let node = rt().block_on(server::start_node_in_memory(None)).unwrap();
        let inner = RunningNode::InMemoryEncrypted(node);

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

    /// A `NodeStartConfig` JSON naming `identity`, on loopback with plaintext,
    /// in-memory blobs and an OS-assigned relay port, with `edit` applied.
    fn start_json(identity: &str, edit: impl FnOnce(&mut serde_json::Value)) -> String {
        let mut cfg = serde_json::json!({
            "reach": {"kind": "local"},
            "identity": identity,
            "blob_storage": {"kind": "in_memory"},
            "tls": {"kind": "plaintext"},
            "dht": {"kind": "disabled"},
            "cors_origins": {"kind": "any_origin"},
            "bind_addr": "127.0.0.1:0",
        });
        edit(&mut cfg);
        cfg.to_string()
    }

    /// The error's class name and code.
    fn class_and_code(e: &ScpPyError) -> (&'static str, &str) {
        match e {
            ScpPyError::IdentityError { code, .. } => ("identity", code),
            ScpPyError::ContextError { code, .. } => ("context", code),
            ScpPyError::TransportError { code, .. } => ("transport", code),
            ScpPyError::ValidationError { code, .. } => ("validation", code),
            other => panic!("unexpected error class: {other:?}"),
        }
    }

    /// The error a refused `node_start_on` returned.
    fn start_error(result: Result<PyNodeHandle, ScpPyError>, label: &str) -> ScpPyError {
        match result {
            Ok(node) => {
                node.shutdown();
                panic!("{label}: node_start must fail");
            }
            Err(e) => e,
        }
    }

    /// A well-formed operator DID that no identity on this instance holds
    /// returns `SCP-IDENT-1063` on a shipped build as on a `testing` build,
    /// and the Python exception carries the code.
    #[test]
    fn node_start_with_unregistered_operator_did_returns_ident_1063() {
        crate::init_runtime().ok();
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|py| {
            let scp = crate::scp::PyScp::new_in_memory_for_test();
            let json = start_json("did:dht:z6MkNodeStartOperatorProbe", |_| {});
            let err = start_error(
                node_start_on(&scp.inner, py, rt(), &json),
                "unregistered operator",
            );
            assert_eq!(
                class_and_code(&err),
                ("identity", codes::IDENT_1063),
                "{err:?}"
            );

            let raised = match scp.node_start(py, &json) {
                Ok(node) => {
                    node.shutdown();
                    panic!("the pymethod must refuse an unregistered operator");
                }
                Err(e) => e.to_string(),
            };
            assert!(raised.contains(codes::IDENT_1063), "{raised}");
        });
    }

    /// One `ServerError` per class: each bridge error takes its variant from
    /// `server_error_class` and its code from `server_error_code`, and a
    /// running node's `NodeError` names no path in its message.
    #[test]
    fn server_and_node_errors_map_through_the_shared_table() {
        let cases: Vec<(ServerError, &str, &str)> = vec![
            (
                ServerError::InvalidConfig("x".into()),
                "validation",
                codes::STORAGE_8007,
            ),
            (
                ServerError::Io(std::io::Error::other("/secret/path")),
                "validation",
                codes::STORAGE_8008,
            ),
            (
                ServerError::Node(NodeError::Storage("x".into())),
                "validation",
                codes::STORAGE_8009,
            ),
            (
                ServerError::OperatorIdentityUnavailable,
                "identity",
                codes::IDENT_1063,
            ),
            (
                ServerError::Node(NodeError::Serve("x".into())),
                "transport",
                codes::TRANS_5054,
            ),
            (
                ServerError::SupervisorWiring(server::SupervisorWiringError::NodeAlreadyBound),
                "transport",
                codes::TRANS_5056,
            ),
            (
                ServerError::MissingPassphrase,
                "validation",
                codes::VALID_7004,
            ),
            (
                ServerError::Platform(scp_platform::error::PlatformError::StorageError("x".into())),
                "context",
                codes::CTX_2053,
            ),
        ];
        for (e, class, code) in cases {
            let label = format!("{e:?}");
            let err = server_error(e);
            assert_eq!(class_and_code(&err), (class, code), "{label}");
        }

        pyo3::prepare_freethreaded_python();
        Python::with_gil(|py| {
            let err = node_err(NodeError::InvalidConfig("/secret/path/data.db".into()));
            let raised = err.value(py).to_string();
            assert!(raised.contains(codes::STORAGE_8007), "{raised}");
            assert!(raised.contains("node operation failed"), "{raised}");
            assert!(!raised.contains("/secret/path"), "{raised}");
        });
    }

    /// A valid config starts a node under the operator identity, registers it
    /// with the instance, and wires the instance's `Supervisor` to its relay.
    #[test]
    #[cfg(feature = "testing")]
    fn node_start_runs_a_node_under_the_operator_identity() {
        crate::init_runtime().ok();
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|py| {
            let scp = crate::scp::PyScp::new_in_memory_for_test();
            let identity = scp.identity_create(py, "in_memory", None).unwrap();
            let did = identity.did().to_owned();
            let node = scp.node_start(py, &start_json(&did, |_| {})).unwrap();

            assert_eq!(node.did(), did);
            assert!(node.relay_port() > 0);
            assert!(
                server::supervisor_wired_to(&scp.inner.core, &node.inner),
                "node_start must wire the instance's Supervisor to the node's relay"
            );
            node.shutdown();
            assert!(node.is_shutdown());
        });
    }

    /// A relay URL on a loopback port nothing listens on, so a connect to it
    /// fails with a refused connection.
    #[cfg(feature = "testing")]
    fn unreachable_relay_url() -> String {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        format!("ws://127.0.0.1:{port}/scp/v1")
    }

    /// `node_start_on`'s wiring step, run on a real started and registered
    /// node with a relay URL that refuses the connection, returns
    /// `SCP-TRANS-5056`, shuts the node down, unregisters it, and leaves no
    /// fallback `Supervisor`. A second start while a running node holds the
    /// binding also returns `SCP-TRANS-5056`, and a start after that node
    /// stops binds again.
    #[test]
    #[cfg(feature = "testing")]
    fn node_start_wiring_failure_returns_trans_5056_and_unregisters_the_node() {
        crate::init_runtime().ok();
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|py| {
            let scp = crate::scp::PyScp::new_in_memory_for_test();
            let identity = scp.identity_create(py, "in_memory", None).unwrap();
            let did = identity.did().to_owned();
            let bi = &*scp.inner;
            let cfg = NodeStartConfig::from_json(&start_json(&did, |_| {})).unwrap();
            let node_identity = resolve_operator_identity(bi, &cfg.identity).unwrap();
            let storage = instance_storage(bi).unwrap();
            let node = rt()
                .block_on(server::node_start(cfg, node_identity, storage))
                .unwrap();
            let inner = server::register_node(&bi.core, node);

            let err = auto_wire_context_manager(bi, py, rt(), &inner, &unreachable_relay_url())
                .expect_err("a refused relay connect must fail the node start");
            assert_eq!(
                class_and_code(&err),
                ("transport", codes::TRANS_5056),
                "{err:?}"
            );
            assert!(!bi.core.has_borrower(&inner), "the node stays registered");
            assert!(inner.is_shutdown(), "the node keeps running");
            assert!(
                !bi.core.has_supervisor(),
                "a fallback Supervisor was attached"
            );

            let node = scp.node_start(py, &start_json(&did, |_| {})).unwrap();
            assert!(server::supervisor_wired_to(&bi.core, &node.inner));
            let err = start_error(
                node_start_on(&scp.inner, py, rt(), &start_json(&did, |_| {})),
                "second node start",
            );
            assert_eq!(
                class_and_code(&err),
                ("transport", codes::TRANS_5056),
                "{err:?}"
            );
            node.shutdown();
            let restarted = scp
                .node_start(py, &start_json(&did, |_| {}))
                .expect("a start after the bound node stops binds again");
            assert!(server::supervisor_wired_to(&bi.core, &restarted.inner));
            restarted.shutdown();
        });
    }

    /// Every sdk-common.md §"Node start error codes" row a `PyO3` caller can
    /// reach through `node_start` returns its code and class.
    #[test]
    #[cfg(feature = "testing")]
    fn node_start_maps_each_reachable_failure_to_its_sdk_common_code() {
        let tmp = tempfile::tempdir().unwrap();
        let file = tmp.path().join("regular-file");
        std::fs::write(&file, b"x").unwrap();
        let under_file = file.join("sub").join("blobs.redb").display().to_string();
        let dir = tmp.path().join("a-directory");
        std::fs::create_dir(&dir).unwrap();
        let dir = dir.display().to_string();
        let taken = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let taken_addr = taken.local_addr().unwrap().to_string();

        crate::init_runtime().ok();
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|py| {
            let scp = crate::scp::PyScp::new_in_memory_for_test();
            let identity = scp.identity_create(py, "in_memory", None).unwrap();
            let did = identity.did().to_owned();

            let cases: Vec<(&str, String, &str, &str)> = vec![
                (
                    "malformed JSON (InvalidConfig)",
                    "{not json".to_owned(),
                    "validation",
                    codes::STORAGE_8007,
                ),
                (
                    "unknown field (InvalidConfig)",
                    start_json(&did, |c| c["port"] = 1.into()),
                    "validation",
                    codes::STORAGE_8007,
                ),
                (
                    "malformed operator DID (InvalidConfig)",
                    start_json("not-a-did", |_| {}),
                    "validation",
                    codes::STORAGE_8007,
                ),
                (
                    "domain with a scheme (InvalidConfig)",
                    start_json(&did, |c| {
                        c["reach"] = serde_json::json!({
                            "kind": "domain", "domain": "https://node.example.org"
                        });
                        c["tls"] = serde_json::json!({"kind": "self_signed"});
                    }),
                    "validation",
                    codes::STORAGE_8007,
                ),
                (
                    "domain with plaintext (Node(InvalidConfig))",
                    start_json(&did, |c| {
                        c["reach"] =
                            serde_json::json!({"kind": "domain", "domain": "node.example.org"});
                    }),
                    "validation",
                    codes::STORAGE_8007,
                ),
                (
                    "blob parent under a regular file (Io)",
                    start_json(&did, |c| {
                        c["blob_storage"] = serde_json::json!({"kind": "redb", "path": under_file});
                    }),
                    "validation",
                    codes::STORAGE_8008,
                ),
                (
                    "redb path that is a directory (Storage)",
                    start_json(&did, |c| {
                        c["blob_storage"] = serde_json::json!({"kind": "redb", "path": dir});
                    }),
                    "validation",
                    codes::STORAGE_8008,
                ),
                (
                    "relay bind on a taken port (Node(Relay))",
                    start_json(&did, |c| c["bind_addr"] = taken_addr.clone().into()),
                    "transport",
                    codes::TRANS_5051,
                ),
            ];
            for (label, json, class, code) in cases {
                let err = start_error(node_start_on(&scp.inner, py, rt(), &json), label);
                assert_eq!(class_and_code(&err), (class, code), "{label}: {err:?}");
            }
        });
        drop(taken);
    }

    /// Asserts `result` is the `TransportError` carrying `SCP-TRANS-5056` that
    /// a start returns while another node of the instance holds the binding.
    #[cfg(feature = "testing")]
    fn assert_refused_while_bound(py: Python<'_>, result: PyResult<PyNodeHandle>, label: &str) {
        let err = match result {
            Ok(node) => {
                node.shutdown();
                panic!("{label}: a start while a running node holds the binding must fail");
            }
            Err(e) => e,
        };
        assert!(
            err.is_instance_of::<crate::error::TransportError>(py),
            "{label}: {err}"
        );
        let raised = err.value(py).to_string();
        assert!(raised.contains(codes::TRANS_5056), "{label}: {raised}");
    }

    /// `context_create` attaches a `Supervisor` with an unconfigured
    /// transport. `node_start_in_memory` then binds that same `Supervisor` to
    /// the node's relay; a second start while the first node runs fails
    /// closed with `SCP-TRANS-5056` and leaves the first binding and the
    /// borrower registry as they were; dropping the first handle unbinds it,
    /// so a later start binds again.
    #[test]
    #[cfg(feature = "testing")]
    fn node_start_in_memory_binds_after_context_create_and_fails_closed_while_bound() {
        crate::init_runtime().ok();
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|py| {
            let scp = crate::scp::PyScp::new_in_memory_for_test();
            let did = scp
                .identity_create(py, "in_memory", None)
                .unwrap()
                .did()
                .to_owned();
            let params = pyo3::types::PyDict::new(py);
            params.set_item("mode", "encrypted").unwrap();
            params.set_item("ceiling", vec!["messages:read"]).unwrap();
            scp.context_create(&did, &params)
                .expect("context_create must succeed");
            let core = &scp.inner.core;
            let attached = Arc::clone(
                core.try_supervisor()
                    .expect("context_create attaches a Supervisor"),
            );

            let first = scp
                .node_start_in_memory(py, Some(did.clone()))
                .expect("a start after context_create binds the attached Supervisor");
            assert!(
                Arc::ptr_eq(core.try_supervisor().unwrap(), &attached),
                "the start keeps the Supervisor context_create attached"
            );
            assert!(server::supervisor_wired_to(core, &first.inner));

            let borrowers = core.borrower_count();
            assert_refused_while_bound(
                py,
                scp.node_start_in_memory(py, Some(did.clone())),
                "node_start_in_memory",
            );
            assert_eq!(
                core.borrower_count(),
                borrowers,
                "a refused start unregisters its node"
            );
            assert!(server::supervisor_wired_to(core, &first.inner));

            drop(first);
            assert!(
                core.node_binding().is_none(),
                "dropping the handle unbinds its node"
            );
            let second = scp
                .node_start_in_memory(py, Some(did))
                .expect("a start after the bound node's handle drops binds again");
            assert!(Arc::ptr_eq(core.try_supervisor().unwrap(), &attached));
            assert!(server::supervisor_wired_to(core, &second.inner));
            second.shutdown();
        });
    }

    /// `configure_local_transport` attaches a `Supervisor` with a loopback
    /// transport. `node_start_local` then binds that same `Supervisor` to the
    /// node's relay; a second start while the first node runs fails closed
    /// with `SCP-TRANS-5056`; a start after `shutdown` binds again.
    #[test]
    #[cfg(feature = "testing")]
    fn node_start_local_binds_after_configure_local_transport_and_fails_closed_while_bound() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = |name: &str| tmp.path().join(name).display().to_string();
        crate::init_runtime().ok();
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|py| {
            let scp = crate::scp::PyScp::new_in_memory_for_test();
            let did = scp
                .identity_create(py, "in_memory", None)
                .unwrap()
                .did()
                .to_owned();
            scp.configure_local_transport(&did).unwrap();
            let core = &scp.inner.core;
            let attached = Arc::clone(
                core.try_supervisor()
                    .expect("configure_local_transport attaches a Supervisor"),
            );

            let first = scp
                .node_start_local(py, dir("first"), Some(did.clone()), None)
                .expect("a start after configure_local_transport binds the attached Supervisor");
            assert!(Arc::ptr_eq(core.try_supervisor().unwrap(), &attached));
            assert!(server::supervisor_wired_to(core, &first.inner));

            let borrowers = core.borrower_count();
            assert_refused_while_bound(
                py,
                scp.node_start_local(py, dir("second"), Some(did.clone()), None),
                "node_start_local",
            );
            assert_eq!(core.borrower_count(), borrowers);
            assert!(server::supervisor_wired_to(core, &first.inner));

            first.shutdown();
            assert!(!server::supervisor_wired_to(core, &first.inner));
            let third = scp
                .node_start_local(py, dir("third"), Some(did), None)
                .expect("a start after shutdown binds again");
            assert!(server::supervisor_wired_to(core, &third.inner));
            third.shutdown();
        });
    }
}
