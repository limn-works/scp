//! napi-rs bridge for relay and application node server startup.
//!
//! Wraps the shared startup code in `scp-ffi-common::server` for consumption
//! from Node.js/Bun via napi-rs `#[napi]` types and functions.
//!
//! - [`NapiRelayHandle`] — opaque handle to a running relay server.
//! - [`NapiNodeHandle`] — opaque handle to a running application node (wraps
//!   encrypted-in-memory and `SQLCipher` variants via an internal enum).
//! - `relay_start_in_memory` / `relay_start_local` — relay startup.
//! - `node_start` — production node start from this instance's storage under
//!   an operator identity (SCP-322).
//! - `node_start_in_memory` / `node_start_local` — node startup.
//!
//! Gated behind the `server` feature on `scp-ffi-common`.

use std::sync::Arc;

use napi::Error as NapiError;
use napi_derive::napi;

use scp_ffi_common::error_codes as codes;
use scp_ffi_common::node_start_config::NodeStartConfig;
use scp_ffi_common::server::{self, NodeIdentity, RunningNode, RunningRelay, ServerError};
use scp_ffi_common::validate::{validate_context_id, validate_deploy_id, validate_did};
use scp_node::NodeError;

use crate::error::ScpNapiError;
use crate::runtime::NapiBridgeInstance;
use crate::{decrement_handle_count, increment_handle_count};

// ---------------------------------------------------------------------------
// Error conversion
// ---------------------------------------------------------------------------

/// Builds the [`ScpNapiError`] for `e` with `message`: the variant from
/// `server_error_class` and the code from `server_error_code`, the one mapping
/// the `PyO3`, napi-rs and `UniFFI` bridges share (sdk-common.md §"Node start
/// error codes").
fn coded(e: &ServerError, message: String) -> ScpNapiError {
    let code = codes::server_error_code(e).to_owned();
    match codes::server_error_class(e) {
        codes::ServerErrorClass::Validation => ScpNapiError::Validation { message, code },
        codes::ServerErrorClass::Identity => ScpNapiError::Identity { message, code },
        codes::ServerErrorClass::Transport => ScpNapiError::Transport { message, code },
        codes::ServerErrorClass::Context => ScpNapiError::Context { message, code },
    }
}

/// Maps a [`ServerError`] to its coded error with the sanitized
/// [`ServerError::user_message`]; the full error goes to the debug log only.
fn server_err(e: ServerError) -> NapiError {
    tracing::debug!(error = %e, "server operation failed");
    coded(&e, e.user_message()).into()
}

/// A `NodeError` from a running node's operation (projection, deploy, serve)
/// maps as `ServerError::Node` does, with a message that names no path.
fn node_err(e: NodeError) -> NapiError {
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
/// §"Node start error codes"). The attach step is napi's
/// [`crate::runtime::init_supervisor`], the same set-once init
/// `context_create` runs.
async fn auto_wire_context_manager(
    bi: &Arc<NapiBridgeInstance>,
    node: &Arc<RunningNode>,
    relay_url: &str,
) -> napi::Result<()> {
    server::wire_supervisor_to_node(&bi.core, node, relay_url, |did| {
        crate::runtime::init_supervisor(bi, did);
    })
    .await
    .map_err(server_err)
}

// ---------------------------------------------------------------------------
// NapiRelayHandle
// ---------------------------------------------------------------------------

/// Opaque handle to a running SCP relay server.
///
/// Created by `relay_start_in_memory` or `relay_start_local`. The relay
/// accepts WebSocket connections at [`relay_url`](NapiRelayHandle::relay_url)
/// and can be gracefully stopped via [`shutdown`](NapiRelayHandle::shutdown).
#[napi]
pub struct NapiRelayHandle {
    inner: RunningRelay,
    /// `NapiBridgeInstance` id that minted this handle.
    pub(crate) instance_id: u64,
}

// napi-rs `#[napi(getter)]` generates wrappers that cannot be `const` or
// `#[must_use]`. These are framework constraints, not code quality issues.
#[napi]
#[allow(clippy::must_use_candidate, clippy::missing_const_for_fn)]
impl NapiRelayHandle {
    /// Returns the WebSocket URL clients should connect to
    /// (e.g., `ws://127.0.0.1:12345/scp/v1`).
    #[napi(getter)]
    pub fn relay_url(&self) -> String {
        self.inner.relay_url().to_owned()
    }

    /// Returns the port the relay is listening on.
    #[napi(getter)]
    pub fn relay_port(&self) -> u16 {
        self.inner.bound_addr().port()
    }

    /// Returns `true` if shutdown has already been signaled.
    #[napi(getter)]
    pub fn is_shutdown(&self) -> bool {
        self.inner.is_shutdown()
    }

    /// Signals the relay server to stop accepting new connections.
    ///
    /// In-flight connection handlers drain naturally after shutdown is
    /// signaled — they are not cancelled.
    #[napi]
    pub fn shutdown(&self) {
        self.inner.shutdown();
    }
}

impl Drop for NapiRelayHandle {
    fn drop(&mut self) {
        self.inner.shutdown();
        decrement_handle_count();
    }
}

// ---------------------------------------------------------------------------
// NapiNodeHandle — type-erased ApplicationNode wrapper
// ---------------------------------------------------------------------------

/// Opaque handle to a running SCP application node.
///
/// Created by `node_start_in_memory` or `node_start_local`. The node
/// includes a running relay server, a generated DID identity, and (optionally)
/// persistent storage. The HTTP server is **not** started automatically —
/// only the relay is bound.
#[napi]
pub struct NapiNodeHandle {
    /// Shared with this instance's borrower registry, which holds a `Weak` to
    /// this same node so `SCP.shutdown()` stops it before releasing storage
    /// (see `scp_ffi_common::bridge_instance::InstanceBorrower`).
    inner: Arc<RunningNode>,
    /// The `NapiBridgeInstance` that minted this handle.
    ///
    /// Retained so that methods like `enable_site_projection` can resolve
    /// the `ContextManager` for broadcast-key auto-resolution without
    /// depending on the process-global default bridge.
    pub(crate) bi: Arc<NapiBridgeInstance>,
    /// `NapiBridgeInstance` id that minted this handle.
    pub(crate) instance_id: u64,
}

#[napi]
#[allow(clippy::must_use_candidate, clippy::missing_const_for_fn)]
impl NapiNodeHandle {
    /// Returns the WebSocket URL clients should connect to for this node's
    /// relay (e.g., `ws://127.0.0.1:12345/scp/v1`).
    ///
    /// Read live per call from the node's relay-URL slot, so it reflects a NAT
    /// tier change that re-pointed the node's endpoint.
    #[napi(getter)]
    pub fn relay_url(&self) -> String {
        self.inner.relay_url()
    }

    /// Returns the port the node's relay is listening on.
    #[napi(getter)]
    pub fn relay_port(&self) -> u16 {
        self.inner.relay_port()
    }

    /// Returns the node's DID string (e.g., `did:dht:z6Mk...`).
    #[napi(getter)]
    pub fn did(&self) -> String {
        self.inner.did().to_owned()
    }

    /// Returns `true` if shutdown has already been signaled.
    #[napi(getter)]
    pub fn is_shutdown(&self) -> bool {
        self.inner.is_shutdown()
    }

    /// Signals the node to stop (relay + background tasks), and unbinds the
    /// instance's `Supervisor` transport from this node when it holds the
    /// binding.
    ///
    /// In-flight connection handlers drain naturally after shutdown is
    /// signaled — they are not cancelled.
    #[napi]
    pub fn shutdown(&self) {
        server::stop_node(&self.bi.core, &self.inner);
    }

    /// Activates HTTP broadcast projection with site configuration.
    ///
    /// Three resolution modes:
    /// 1. Both `broadcastKeyHex` **and** `authorDid` provided -- uses
    ///    the explicit key with epoch 0.
    /// 2. Only `authorDid` provided -- auto-resolves the broadcast key
    ///    using that DID (useful when the author identity differs from the
    ///    node identity).
    /// 3. Neither provided -- auto-resolves using the node's identity DID.
    ///
    /// Providing `broadcastKeyHex` without `authorDid` raises an error.
    ///
    /// `admission` is `"open"` or `"gated"`.
    ///
    /// Site configuration fields:
    /// - `hostname` (required): virtual host hostname (RFC 1123).
    /// - `indexPath`: default path for directory requests (default `"/index.html"`).
    /// - `maxAssetsPerDeploy`: max assets per deploy (default 10000).
    /// - `maxDeploySizeBytes`: max total deploy size in bytes (default 536870912).
    /// - `deployRetentionCount`: deploys to retain (default 2, max 8).
    /// - `cspOverride`: optional Content-Security-Policy override.
    #[napi]
    #[allow(clippy::too_many_arguments)]
    pub async fn enable_site_projection(
        &self,
        context_id: String,
        admission: String,
        hostname: String,
        broadcast_key_hex: Option<String>,
        author_did: Option<String>,
        index_path: Option<String>,
        max_assets_per_deploy: Option<u32>,
        max_deploy_size_bytes: Option<i64>,
        deploy_retention_count: Option<u32>,
        csp_override: Option<String>,
    ) -> napi::Result<()> {
        validate_context_id(&context_id).map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;
        if let Some(ref did) = author_did {
            validate_did(did).map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;
        }

        // Resolve broadcast key: explicit or auto-lookup via Supervisor.
        let supervisor = crate::runtime::supervisor(&self.bi)?;
        let resolved = server::resolve_broadcast_key(
            broadcast_key_hex,
            author_did,
            self.inner.did(),
            supervisor,
            &context_id,
        )
        .await
        .map_err(|e| NapiError::from_reason(e.to_string()))?;
        let broadcast_key = resolved.into_broadcast_key();

        let adm = match admission.to_lowercase().as_str() {
            "open" => scp_core::context::broadcast::BroadcastAdmission::Open,
            "gated" => scp_core::context::broadcast::BroadcastAdmission::Gated,
            other => {
                return Err(NapiError::from_reason(format!(
                    "admission must be \"open\" or \"gated\", got \"{other}\""
                )));
            }
        };

        let idx_path_str = index_path.as_deref().unwrap_or("/index.html");
        let content_path = scp_core::context::broadcast_content::ContentPath::new(idx_path_str)
            .map_err(|e| NapiError::from_reason(format!("invalid index_path: {e}")))?;

        // JavaScript numbers are signed; validate non-negative before u64 conversion.
        let deploy_size = match max_deploy_size_bytes {
            Some(v) if v < 0 => {
                return Err(NapiError::from_reason(
                    "max_deploy_size_bytes must be non-negative",
                ));
            }
            Some(v) => v.unsigned_abs(),
            None => 512 * 1024 * 1024,
        };

        let site_config = scp_node::projection::SiteConfig {
            hostname,
            index_path: content_path,
            max_assets_per_deploy: max_assets_per_deploy.map_or(10_000, |v| v as usize),
            max_deploy_size_bytes: deploy_size,
            deploy_retention_count: deploy_retention_count.map_or(2, |v| v as usize),
            csp_override,
        };

        self.inner
            .enable_broadcast_projection_with_site(
                &context_id,
                broadcast_key,
                adm,
                Some(site_config),
            )
            .await
            .map_err(node_err)
    }

    /// Commits a deploy for a projected context (section 18.11.11).
    ///
    /// Returns the number of assets in the committed deploy.
    #[napi]
    pub async fn commit_deploy(&self, context_id: String, deploy_id: String) -> napi::Result<u32> {
        validate_context_id(&context_id).map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;
        validate_deploy_id(&deploy_id).map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;
        let count = self
            .inner
            .commit_deploy(&context_id, &deploy_id)
            .await
            .map_err(node_err)?;
        u32::try_from(count)
            .map_err(|_| NapiError::from_reason(format!("asset count {count} exceeds u32::MAX")))
    }

    /// Rolls back to a previous deploy for a projected context (section 18.11.11).
    #[napi]
    pub async fn rollback_deploy(&self, context_id: String, deploy_id: String) -> napi::Result<()> {
        validate_context_id(&context_id).map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;
        validate_deploy_id(&deploy_id).map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;
        self.inner
            .rollback_deploy(&context_id, &deploy_id)
            .await
            .map_err(node_err)
    }

    /// Deactivates HTTP broadcast projection for the given context.
    #[napi]
    pub async fn disable_site_projection(&self, context_id: String) -> napi::Result<()> {
        validate_context_id(&context_id).map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;
        self.inner.disable_broadcast_projection(&context_id).await;
        Ok(())
    }

    /// Starts the HTTP server in the background on the given bind address.
    ///
    /// Defaults to `127.0.0.1:8443` (loopback only) when `bindAddr` is not
    /// provided. Returns the actual bound address as a raw string
    /// (e.g. `"127.0.0.1:8443"`). Use [`http_url`](NapiNodeHandle::http_url)
    /// for the full URL form (`"http://127.0.0.1:8443"`).
    ///
    /// **Note:** The background server does not support TLS. For production
    /// deployments requiring encryption, use the node binary's `serve()`
    /// with TLS configuration.
    ///
    /// Throws if the server is already running or binding fails.
    #[napi]
    pub async fn serve(&self, bind_addr: Option<String>) -> napi::Result<String> {
        let addr = bind_addr
            .map(|s| {
                s.parse::<std::net::SocketAddr>().map_err(|e| {
                    let display = if s.len() > 128 {
                        &s[..s.floor_char_boundary(128)]
                    } else {
                        &s
                    };
                    NapiError::from_reason(format!("invalid bind_addr \"{display}\": {e}"))
                })
            })
            .transpose()?;
        self.inner
            .serve_background(addr)
            .await
            .map(|a| a.to_string())
            .map_err(node_err)
    }

    /// Returns the HTTP URL of the background server, or `null` if not serving.
    ///
    /// Returns the literal bind address, which may contain `0.0.0.0` if the
    /// server was bound to the unspecified address.
    #[napi]
    pub async fn http_url(&self) -> Option<String> {
        self.inner.http_url().await
    }
}

impl Drop for NapiNodeHandle {
    fn drop(&mut self) {
        server::stop_node(&self.bi.core, &self.inner);
        decrement_handle_count();
    }
}

// ---------------------------------------------------------------------------
// build_node_identity — constructs NodeIdentity from identity registry
// ---------------------------------------------------------------------------

/// Builds a [`NodeIdentity`] from the NAPI identity registry for a given DID.
///
/// Looks up the DID in the global identity registry (populated by
/// `identity_create`) and constructs a `NodeIdentity` with a properly
/// configured `DidDht` instance that has signing capability.
///
/// # Errors
///
/// - `SCP-IDENT-1063` (`OperatorIdentityUnavailable`, sdk-common.md §"Node
///   start error codes") when the DID is not registered on this instance.
/// - `SCP-IDENT-1058` when no shared DHT client exists and the production
///   client cannot be built.
///
/// Works for any locally registered identity — in-memory OR a production
/// callback custody (`identityCreateWithCustody`) — since signing dispatches
/// through the enum-typed `NapiKeyCustody`.
#[allow(clippy::type_complexity)]
fn build_node_identity(bi: &NapiBridgeInstance, did: &str) -> napi::Result<NodeIdentity> {
    use std::sync::Arc;

    use scp_identity::DidCache;
    use scp_platform::traits::KeyCustody;

    let entry = crate::runtime::identity_registry(bi)
        .get(did)
        .ok_or_else(|| server_err(ServerError::OperatorIdentityUnavailable))?;
    let custody_clone = Arc::clone(&entry.custody);

    // Hand-rolled sign_fn: `ConcreteDidMethod::make_sign_fn` requires
    // `Arc<K: KeyCustody>`, and `NapiKeyCustody` does implement `KeyCustody`
    // via enum dispatch, so we sign through it directly. Same pattern as
    // `make_dht_with_signer` in identity.rs.
    let sign_fn: Arc<
        dyn Fn(
                u64,
                Vec<u8>,
            ) -> std::pin::Pin<
                Box<
                    dyn std::future::Future<
                            Output = Result<Vec<u8>, scp_identity::dht::IdentityError>,
                        > + Send,
                >,
            > + Send
            + Sync,
    > = Arc::new(move |key_id: u64, data: Vec<u8>| {
        let kc = Arc::clone(&custody_clone);
        Box::pin(async move {
            let handle = scp_platform::traits::KeyHandle::new(key_id);
            let sig = kc
                .sign(&handle, &data)
                .await
                .map_err(scp_identity::dht::IdentityError::Platform)?;
            Ok(sig.into_bytes())
        })
    });

    // Publish through the process-shared DHT client (the one the resolver
    // reads from) so a node serving this identity re-publishes into the same
    // DHT the rest of the bridge resolves against. Fall back to a fail-closed
    // production client if the resolver was never initialized — never an
    // in-memory nullifier on a shipped path (ADR-062 §Decision 1).
    let dht_client = match crate::runtime::shared_dht_client() {
        Some(client) => Arc::clone(client),
        None => Arc::new(crate::identity::build_ffi_dht_client().map_err(napi::Error::from)?),
    };
    let cache = Arc::new(DidCache::new());
    let did_method = Arc::new(
        scp_ffi_common::server::ConcreteDidMethod::with_client_and_signer(
            dht_client, cache, sign_fn,
        ),
    );

    Ok(NodeIdentity {
        identity: entry.identity.clone(),
        document: entry.document.clone(),
        did_method,
    })
}

/// Resolves the operator identity a node start config names: a malformed DID
/// is `InvalidConfig` (`SCP-STORAGE-8007`), and a DID not registered on this
/// instance is `OperatorIdentityUnavailable` (`SCP-IDENT-1063`).
fn resolve_operator_identity(bi: &NapiBridgeInstance, did: &str) -> napi::Result<NodeIdentity> {
    if validate_did(did).is_err() {
        return Err(server_err(ServerError::InvalidConfig(
            "identity must be a DID".to_owned(),
        )));
    }
    build_node_identity(bi, did)
}

/// Per-bridge-instance implementation of `node_start`: starts a production
/// node on `bi`'s storage under the operator identity the config names
/// (construction.md §"Node start — `NodeStartConfig`").
///
/// `operator_did` is the DID of the operator handle the caller passed, on
/// which `Scp::node_start` already ran the ADR-048 handle check.
///
/// Runs, in order: the config parse, the operator identity resolution, the
/// check that the config names `operator_did`, taking the instance storage,
/// `server::node_start`, `server::register_node`,
/// `auto_wire_context_manager`, and wrapping the handle.
///
/// # Errors
///
/// The code sdk-common.md §"Node start error codes" gives each failure.
pub(crate) async fn node_start_on(
    bi: &Arc<NapiBridgeInstance>,
    config_json: String,
    operator_did: &str,
) -> napi::Result<NapiNodeHandle> {
    let cfg = NodeStartConfig::from_json(&config_json).map_err(server_err)?;
    let identity = resolve_operator_identity(bi, &cfg.identity)?;
    // The config names its operator by DID; the caller also passed the
    // operator handle the ADR-048 check ran on. A config naming any other
    // identity would run the node under an operator that check never saw.
    if cfg.identity != operator_did {
        return Err(server_err(ServerError::OperatorIdentityUnavailable));
    }
    let storage = crate::runtime::protocol_repository(bi).instance_storage();
    let node = server::node_start(cfg, identity, storage)
        .await
        .map_err(server_err)?;
    // Registered before anything else can fail, so `SCP.shutdown()` stops
    // this node before it releases the storage the node holds
    // (`scp_ffi_common::bridge_instance::InstanceBorrower`).
    let inner = server::register_node(&bi.core, node);
    auto_wire_context_manager(bi, &inner, &inner.internal_relay_url()).await?;
    increment_handle_count();
    Ok(NapiNodeHandle {
        inner,
        bi: Arc::clone(bi),
        instance_id: bi.instance_id(),
    })
}

// ---------------------------------------------------------------------------
// Free functions — relay startup
// ---------------------------------------------------------------------------

/// Per-bridge-instance implementation of `relay_start_in_memory`.
pub(crate) async fn relay_start_in_memory_on(
    bi: &Arc<NapiBridgeInstance>,
) -> napi::Result<NapiRelayHandle> {
    let relay = server::start_relay_in_memory().await.map_err(server_err)?;
    increment_handle_count();
    Ok(NapiRelayHandle {
        inner: relay,
        instance_id: bi.instance_id(),
    })
}

/// Per-bridge-instance implementation of `relay_start_local`.
pub(crate) async fn relay_start_local_on(
    bi: &Arc<NapiBridgeInstance>,
    data_dir: String,
) -> napi::Result<NapiRelayHandle> {
    let relay = server::start_relay_local(std::path::Path::new(&data_dir))
        .await
        .map_err(server_err)?;
    increment_handle_count();
    Ok(NapiRelayHandle {
        inner: relay,
        instance_id: bi.instance_id(),
    })
}

// ---------------------------------------------------------------------------
// Free functions — node startup
// ---------------------------------------------------------------------------

// The dev pair splits on this crate's own `testing` feature, never on
// `scp-ffi-common`'s: this crate's dev-dependencies turn
// `scp-ffi-common/testing` on for every test build, so a split on the common
// feature would start a node in a test of the shipped configuration. The
// shipped variants are plain `fn`s returning a ready future, so the exported
// `async` methods await either variant unchanged.

/// The shipped `node_start_in_memory`: the dev pair is cut from builds
/// without `testing` (SCP-327), so it rejects with `SCP-TRANS-5055` and starts
/// nothing.
#[cfg(not(feature = "testing"))]
pub(crate) fn node_start_in_memory_on(
    _bi: &Arc<NapiBridgeInstance>,
    _identity_did: Option<String>,
) -> std::future::Ready<napi::Result<NapiNodeHandle>> {
    std::future::ready(Err(server_err(ServerError::DevStartUnavailable)))
}

/// The shipped `node_start_local`: the dev pair is cut from builds without
/// `testing` (SCP-327), so it rejects with `SCP-TRANS-5055` and creates
/// nothing.
#[cfg(not(feature = "testing"))]
pub(crate) fn node_start_local_on(
    _bi: &Arc<NapiBridgeInstance>,
    _data_dir: String,
    _identity_did: Option<String>,
    _passphrase: Option<String>,
) -> std::future::Ready<napi::Result<NapiNodeHandle>> {
    std::future::ready(Err(server_err(ServerError::DevStartUnavailable)))
}

/// Per-bridge-instance implementation of `node_start_in_memory` on a
/// `testing` build.
#[cfg(feature = "testing")]
pub(crate) async fn node_start_in_memory_on(
    bi: &Arc<NapiBridgeInstance>,
    identity_did: Option<String>,
) -> napi::Result<NapiNodeHandle> {
    let node_identity = match identity_did {
        Some(ref did) => {
            validate_did(did).map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;
            Some(build_node_identity(bi, did)?)
        }
        None => None,
    };
    let node = server::start_node_in_memory(node_identity)
        .await
        .map_err(server_err)?;

    // Register this node as a borrower of this instance's resources, so
    // `SCP.shutdown()` stops it before `bridge_specific_shutdown` releases
    // anything (`scp_ffi_common::bridge_instance::InstanceBorrower`), and so a
    // failed wiring below can remove it again.
    let inner = server::register_node(&bi.core, RunningNode::InMemoryEncrypted(node));
    auto_wire_context_manager(bi, &inner, &inner.internal_relay_url()).await?;

    increment_handle_count();
    Ok(NapiNodeHandle {
        inner,
        bi: Arc::clone(bi),
        instance_id: bi.instance_id(),
    })
}

/// Per-bridge-instance implementation of `node_start_local` on a `testing`
/// build.
///
/// A node inherits whichever storage backend an instance was constructed with
/// (`SCP.withStorage({...})`), so it opens no protocol store of its own. A
/// caller wanting a node on a different backend constructs a second `SCP`.
#[cfg(feature = "testing")]
pub(crate) async fn node_start_local_on(
    bi: &Arc<NapiBridgeInstance>,
    data_dir: String,
    identity_did: Option<String>,
    passphrase: Option<String>,
) -> napi::Result<NapiNodeHandle> {
    let node_identity = match identity_did {
        Some(ref did) => {
            validate_did(did).map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;
            Some(build_node_identity(bi, did)?)
        }
        None => None,
    };
    let zeroized_passphrase = passphrase.map(zeroize::Zeroizing::new);
    let data_dir = std::path::Path::new(&data_dir);
    // `ProtocolRepository::storage()` yields this instance's own chosen
    // backend; cloning that `Arc` hands a node one store that an event log, a
    // saga journal, and an `OpenMLS` view already share (spec §17.6).
    let inner = match crate::runtime::protocol_repository(bi) {
        crate::runtime::ProtocolRepoVariant::InMemory(repo) => {
            let storage = Arc::clone(repo.storage());
            server::start_node_local(data_dir, storage, node_identity, zeroized_passphrase)
                .await
                .map(RunningNode::InMemoryEncrypted)
        }
        crate::runtime::ProtocolRepoVariant::Sqlite(repo) => {
            let storage = Arc::clone(repo.storage());
            server::start_node_local(data_dir, storage, node_identity, zeroized_passphrase)
                .await
                .map(RunningNode::Sqlite)
        }
    }
    .map_err(server_err)?;
    // This node holds a clone of this instance's storage `Arc`, so register it
    // before anything else: `SCP.shutdown()` must stop this node before
    // the durable store closer closes that `SQLCipher` handle and drops an
    // advisory `flock(2)`
    // (`scp_ffi_common::bridge_instance::InstanceBorrower`).
    let inner = server::register_node(&bi.core, inner);

    auto_wire_context_manager(bi, &inner, &inner.internal_relay_url()).await?;

    increment_handle_count();
    Ok(NapiNodeHandle {
        inner,
        bi: Arc::clone(bi),
        instance_id: bi.instance_id(),
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn rt() -> &'static tokio::runtime::Runtime {
        crate::runtime()
    }

    #[test]
    fn relay_in_memory_starts_and_returns_url() {
        let relay = rt()
            .block_on(crate::scp::Scp::new_in_memory_for_test().relay_start_in_memory())
            .unwrap();
        assert!(
            relay.relay_url().starts_with("ws://127.0.0.1:"),
            "expected ws:// URL, got: {}",
            relay.relay_url()
        );
        assert!(
            relay.relay_url().ends_with("/scp/v1"),
            "expected /scp/v1 suffix, got: {}",
            relay.relay_url()
        );
        assert!(relay.relay_port() > 0, "port should be assigned");
        assert!(!relay.is_shutdown());
        relay.shutdown();
        assert!(relay.is_shutdown());
    }

    #[test]
    fn relay_local_starts_and_returns_url() {
        let tmp = std::env::temp_dir().join(format!("scp-napi-relay-test-{}", std::process::id()));
        let relay = rt()
            .block_on(
                crate::scp::Scp::new_in_memory_for_test()
                    .relay_start_local(tmp.to_string_lossy().into_owned()),
            )
            .unwrap();
        assert!(
            relay.relay_url().starts_with("ws://127.0.0.1:"),
            "expected ws:// URL, got: {}",
            relay.relay_url()
        );
        assert!(relay.relay_port() > 0);
        relay.shutdown();
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    #[cfg(feature = "testing")]
    fn node_in_memory_starts_and_returns_did() {
        let node = rt()
            .block_on(crate::scp::Scp::new_in_memory_for_test().node_start_in_memory(None))
            .unwrap();
        let url = node.relay_url();
        assert!(
            url.starts_with("ws://") || url.starts_with("wss://"),
            "expected ws(s):// URL, got: {url}",
        );
        assert!(
            node.did().starts_with("did:"),
            "expected did: prefix, got: {}",
            node.did()
        );
        assert!(node.relay_port() > 0);

        assert!(!node.is_shutdown());
        node.shutdown();
        assert!(node.is_shutdown());
    }

    /// Regression guard on Node/Bun: after node startup the production
    /// `Supervisor` must have its event broadcast channel enabled, so
    /// `subscribe_events()` yields a receiver. Before the fix,
    /// `build_supervisor_arc` did not enable the channel on this bridge and the
    /// channel was `None`.
    #[test]
    #[cfg(feature = "testing")]
    fn node_startup_enables_context_event_channel() {
        let scp = crate::scp::Scp::new_in_memory_for_test();
        let node = rt().block_on(scp.node_start_in_memory(None)).unwrap();

        let supervisor = crate::runtime::supervisor(&scp.inner)
            .expect("Supervisor must be attached after node startup");
        assert!(
            supervisor.subscribe_events().is_some(),
            "node startup must enable the Supervisor event channel"
        );

        node.shutdown();
    }

    #[test]
    #[cfg(feature = "testing")]
    fn node_local_starts_and_returns_did() {
        let tmp = std::env::temp_dir().join(format!("scp-napi-node-test-{}", std::process::id()));
        let node = rt()
            .block_on(crate::scp::Scp::new_in_memory_for_test().node_start_local(
                tmp.to_string_lossy().into_owned(),
                None,
                Some("test-passphrase".to_owned()),
            ))
            .unwrap();
        let url = node.relay_url();
        assert!(
            url.starts_with("ws://") || url.starts_with("wss://"),
            "expected ws(s):// URL, got: {url}",
        );
        assert!(
            node.did().starts_with("did:"),
            "expected did: prefix, got: {}",
            node.did()
        );
        assert!(node.relay_port() > 0);

        node.shutdown();
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn relay_shutdown_is_idempotent() {
        let relay = rt()
            .block_on(crate::scp::Scp::new_in_memory_for_test().relay_start_in_memory())
            .unwrap();
        relay.shutdown();
        // Second shutdown should not panic.
        relay.shutdown();
    }

    #[test]
    #[cfg(feature = "testing")]
    fn node_shutdown_is_idempotent() {
        let node = rt()
            .block_on(crate::scp::Scp::new_in_memory_for_test().node_start_in_memory(None))
            .unwrap();
        node.shutdown();
        // Second shutdown should not panic.
        node.shutdown();
    }

    #[test]
    fn enable_site_projection_dispatches_through_node_inner() {
        let node = rt().block_on(server::start_node_in_memory(None)).unwrap();
        let inner = RunningNode::InMemoryEncrypted(node);
        let key = scp_core::crypto::sender_keys::BroadcastKey::from_parts(
            scp_core::crypto::sender_keys::SenderKey::from_bytes([0xAB; 32]),
            0,
            "did:dht:napi-test".to_owned(),
        );
        let site_config =
            scp_node::projection::SiteConfig::with_hostname("napi.example.com").unwrap();
        let result = rt().block_on(inner.enable_broadcast_projection_with_site(
            "napi-ctx",
            key,
            scp_core::context::broadcast::BroadcastAdmission::Open,
            Some(site_config),
        ));
        assert!(result.is_ok(), "enable should succeed: {result:?}");
        inner.shutdown();
    }

    #[test]
    fn commit_deploy_returns_error_for_unprojected_context() {
        let node = rt().block_on(server::start_node_in_memory(None)).unwrap();
        let inner = RunningNode::InMemoryEncrypted(node);
        let result = rt().block_on(inner.commit_deploy("no-such-ctx", "deploy-1"));
        assert!(
            result.is_err(),
            "commit_deploy should fail for unprojected context"
        );
        inner.shutdown();
    }

    #[test]
    fn rollback_deploy_returns_error_for_unprojected_context() {
        let node = rt().block_on(server::start_node_in_memory(None)).unwrap();
        let inner = RunningNode::InMemoryEncrypted(node);
        let result = rt().block_on(inner.rollback_deploy("no-such-ctx", "deploy-1"));
        assert!(
            result.is_err(),
            "rollback_deploy should fail for unprojected context"
        );
        inner.shutdown();
    }

    #[test]
    fn disable_site_projection_is_noop_for_unprojected_context() {
        let node = rt().block_on(server::start_node_in_memory(None)).unwrap();
        let inner = RunningNode::InMemoryEncrypted(node);
        rt().block_on(inner.disable_broadcast_projection("no-such-ctx"));
        // Should not panic.
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

    /// The reason a refused `node_start` returned.
    fn start_error(result: napi::Result<NapiNodeHandle>, label: &str) -> String {
        match result {
            Ok(node) => {
                node.shutdown();
                panic!("{label}: node_start must fail");
            }
            Err(e) => e.reason.clone(),
        }
    }

    /// Asserts `reason` is the `ScpNapiError` rendering with `code` and
    /// `class`, the form the TypeScript SDK parses.
    fn assert_coded(reason: &str, class: &str, code: &str, label: &str) {
        let prefix = format!("[{code}] {class} error: ");
        assert!(
            reason.starts_with(&prefix),
            "{label}: expected {prefix:?}, got {reason:?}"
        );
    }

    /// An operator handle for `did` minted by `scp` that holds no key
    /// material and is not in `scp`'s identity registry, as an externally
    /// loaded identity is; a shipped build can mint it, since it needs no
    /// custody.
    fn external_identity(scp: &crate::scp::Scp, did: &str) -> crate::identity::NapiIdentity {
        // Balances the decrement in `NapiIdentity`'s `Drop`, as every handle
        // constructor does.
        crate::increment_handle_count();
        crate::identity::NapiIdentity {
            inner: Arc::new(crate::identity::NapiIdentityInner {
                did: did.to_owned(),
                custody_type: "external".to_owned(),
                scp_identity: None,
                custody: None,
                document: None,
                bi: Arc::clone(&scp.inner),
                verifying_key_hex: None,
                instance_id: scp.inner.instance_id(),
                rotation_event_json: None,
            }),
        }
    }

    /// A well-formed operator DID that no identity on this instance holds
    /// returns `SCP-IDENT-1063` on a shipped build as on a `testing` build.
    #[test]
    fn node_start_with_unregistered_operator_did_returns_ident_1063() {
        let scp = crate::scp::Scp::new_in_memory_for_test();
        let probe = "did:dht:z6MkNodeStartOperatorProbe";
        let handle = external_identity(&scp, probe);
        let json = start_json(probe, |_| {});
        let reason = start_error(
            rt().block_on(scp.node_start(json, &handle)),
            "unregistered operator",
        );
        assert_coded(
            &reason,
            "identity",
            codes::IDENT_1063,
            "unregistered operator",
        );
    }

    /// The dev pair is cut from a shipped build (SCP-327): the exported
    /// `nodeStartInMemory` rejects with the transport-class `SCP-TRANS-5055`
    /// and starts no node, with and without an identity.
    #[test]
    #[cfg(not(feature = "testing"))]
    fn node_start_in_memory_on_a_shipped_build_returns_trans_5055() {
        let scp = crate::scp::Scp::new_in_memory_for_test();
        for identity in [None, Some("did:dht:z6MkDevStartProbe".to_owned())] {
            let label = format!("node_start_in_memory({identity:?})");
            let reason = start_error(rt().block_on(scp.node_start_in_memory(identity)), &label);
            assert_coded(&reason, "transport", codes::TRANS_5055, &label);
        }
    }

    /// The dev pair is cut from a shipped build (SCP-327): the exported
    /// `nodeStartLocal` rejects with the transport-class `SCP-TRANS-5055` and
    /// writes no key file or blob store under `data_dir`.
    #[test]
    #[cfg(not(feature = "testing"))]
    fn node_start_local_on_a_shipped_build_returns_trans_5055() {
        let tmp =
            std::env::temp_dir().join(format!("scp-napi-shipped-dev-start-{}", std::process::id()));
        let scp = crate::scp::Scp::new_in_memory_for_test();
        let reason = start_error(
            rt().block_on(scp.node_start_local(
                tmp.to_string_lossy().into_owned(),
                None,
                Some("test-passphrase".to_owned()),
            )),
            "node_start_local",
        );
        assert_coded(&reason, "transport", codes::TRANS_5055, "node_start_local");
        assert!(
            !tmp.exists(),
            "a shipped node_start_local must create nothing under data_dir"
        );
    }

    /// An operator handle another `SCP` minted fails the ADR-048 handle check
    /// with `SCP-PERM-3030` before the config is read, so even a config that
    /// cannot parse returns `SCP-PERM-3030`.
    #[test]
    fn node_start_refuses_another_instances_identity_with_perm_3030() {
        let minting = crate::scp::Scp::new_in_memory_for_test();
        let other = crate::scp::Scp::new_in_memory_for_test();
        let did = "did:dht:z6MkNodeStartForeignProbe";
        let foreign = external_identity(&minting, did);
        for json in [start_json(did, |_| {}), "{not json".to_owned()] {
            let reason = start_error(
                rt().block_on(other.node_start(json, &foreign)),
                "foreign operator handle",
            );
            assert_coded(
                &reason,
                "permission",
                codes::PERM_3030,
                "foreign operator handle",
            );
        }
    }

    /// A config naming a DID other than the operator handle's returns
    /// `SCP-IDENT-1063`: the node never runs under an operator the handle
    /// check did not see.
    #[test]
    #[cfg(feature = "testing")]
    fn node_start_refuses_a_config_naming_another_operator_with_ident_1063() {
        let scp = crate::scp::Scp::new_in_memory_for_test();
        let named = rt()
            .block_on(scp.identity_create("in_memory".to_owned(), None))
            .unwrap();
        let passed = rt()
            .block_on(scp.identity_create("in_memory".to_owned(), None))
            .unwrap();
        let reason = start_error(
            rt().block_on(scp.node_start(start_json(&named.did(), |_| {}), &passed)),
            "config names another operator",
        );
        assert_coded(
            &reason,
            "identity",
            codes::IDENT_1063,
            "config names another operator",
        );
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
            assert_coded(&server_err(e).reason, class, code, &label);
        }

        let reason = node_err(NodeError::InvalidConfig("/secret/path/data.db".into()))
            .reason
            .clone();
        assert_eq!(
            reason,
            format!(
                "[{}] validation error: node operation failed",
                codes::STORAGE_8007
            )
        );
    }

    /// A valid config starts a node under the operator identity, registers it
    /// with the instance, and wires the instance's `Supervisor` to its relay.
    #[test]
    #[cfg(feature = "testing")]
    fn node_start_runs_a_node_under_the_operator_identity() {
        let scp = crate::scp::Scp::new_in_memory_for_test();
        let identity = rt()
            .block_on(scp.identity_create("in_memory".to_owned(), None))
            .unwrap();
        let did = identity.did();
        let node = rt()
            .block_on(scp.node_start(start_json(&did, |_| {}), &identity))
            .unwrap();

        assert_eq!(node.did(), did);
        assert!(node.relay_port() > 0);
        assert!(
            server::supervisor_wired_to(&scp.inner.core, &node.inner),
            "node_start must wire the instance's Supervisor to the node's relay"
        );
        node.shutdown();
        assert!(node.is_shutdown());
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
    /// `SCP-TRANS-5056`, shuts the node down, unregisters it, leaves no
    /// fallback `Supervisor`, and leaves the transport manager the instance
    /// held before the start in place. A second start while a running node
    /// holds the binding also returns `SCP-TRANS-5056`, and a start after
    /// that node stops binds again and puts the earlier manager back on its
    /// stop.
    #[test]
    #[cfg(feature = "testing")]
    fn node_start_wiring_failure_returns_trans_5056_and_unregisters_the_node() {
        let scp = crate::scp::Scp::new_in_memory_for_test();
        let relay = rt().block_on(scp.relay_start_in_memory()).unwrap();
        let sourced = scp_transport::relay::connection::SourcedRelayUrl {
            url: relay.relay_url(),
            source: scp_transport::relay::connection::RelayUrlSource::Explicit,
        };
        let adapter = rt()
            .block_on(
                scp_transport::TransportSelector::new()
                    .select_and_connect_with_bearer(&sourced, None, None),
            )
            .unwrap();
        scp.inner
            .core
            .install_transport(Arc::new(scp_transport::TransportManager::new(
                relay.relay_url(),
                adapter,
            )))
            .unwrap();
        let identity = rt()
            .block_on(scp.identity_create("in_memory".to_owned(), None))
            .unwrap();
        let did = identity.did();
        let cfg = NodeStartConfig::from_json(&start_json(&did, |_| {})).unwrap();
        let node_identity = resolve_operator_identity(&scp.inner, &cfg.identity).unwrap();
        let storage = crate::runtime::protocol_repository(&scp.inner).instance_storage();
        let node = rt()
            .block_on(server::node_start(cfg, node_identity, storage))
            .unwrap();
        let inner = server::register_node(&scp.inner.core, node);

        let err = rt()
            .block_on(auto_wire_context_manager(
                &scp.inner,
                &inner,
                &unreachable_relay_url(),
            ))
            .expect_err("a refused relay connect must fail the node start");
        assert_coded(
            &err.reason,
            "transport",
            codes::TRANS_5056,
            "refused connect",
        );
        assert!(
            !scp.inner.core.has_borrower(&inner),
            "the node stays registered"
        );
        assert!(inner.is_shutdown(), "the node keeps running");
        assert!(
            !scp.inner.core.has_supervisor(),
            "a fallback Supervisor was attached"
        );
        assert_eq!(
            scp.inner
                .core
                .with_transport(scp_transport::TransportManager::relay_urls)
                .unwrap(),
            [relay.relay_url()],
            "the failed start must restore the instance's previous transport manager"
        );

        let node = rt()
            .block_on(scp.node_start(start_json(&did, |_| {}), &identity))
            .unwrap();
        assert!(server::supervisor_wired_to(&scp.inner.core, &node.inner));
        let reason = start_error(
            rt().block_on(scp.node_start(start_json(&did, |_| {}), &identity)),
            "second node start",
        );
        assert_coded(&reason, "transport", codes::TRANS_5056, "second node start");
        node.shutdown();
        let restarted = rt()
            .block_on(scp.node_start(start_json(&did, |_| {}), &identity))
            .expect("a start after the bound node stops binds again");
        assert!(server::supervisor_wired_to(
            &scp.inner.core,
            &restarted.inner
        ));
        restarted.shutdown();
        assert_eq!(
            scp.inner
                .core
                .with_transport(scp_transport::TransportManager::relay_urls)
                .unwrap(),
            [relay.relay_url()],
            "a stop puts back the transport manager the first start displaced"
        );
        relay.shutdown();
    }

    /// Every sdk-common.md §"Node start error codes" row a napi-rs caller can
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

        let scp = crate::scp::Scp::new_in_memory_for_test();
        let identity = rt()
            .block_on(scp.identity_create("in_memory".to_owned(), None))
            .unwrap();
        let did = identity.did();

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
            let reason = start_error(rt().block_on(scp.node_start(json, &identity)), label);
            assert_coded(&reason, class, code, label);
        }
        drop(taken);
    }

    /// Asserts `result` is the transport error carrying `SCP-TRANS-5056` that
    /// a start returns while another node of the instance holds the binding,
    /// and that it names the `NodeAlreadyBound` step, so a 5056 from any
    /// other step, such as `RelayConnect`, fails the assertion.
    #[cfg(feature = "testing")]
    fn assert_refused_while_bound(result: napi::Result<NapiNodeHandle>, label: &str) {
        let reason = match result {
            Ok(node) => {
                node.shutdown();
                panic!("{label}: a start while a running node holds the binding must fail");
            }
            Err(e) => e.reason.clone(),
        };
        assert_coded(&reason, "transport", codes::TRANS_5056, label);
        let step = scp_ffi_common::server::SupervisorWiringError::NodeAlreadyBound.user_message();
        assert!(
            reason.contains(step),
            "{label}: the refusal names NodeAlreadyBound: {reason}"
        );
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
        let scp = crate::scp::Scp::new_in_memory_for_test();
        let identity = rt()
            .block_on(scp.identity_create("in_memory".to_owned(), None))
            .unwrap();
        let did = identity.did();
        let params_json = serde_json::json!({
            "ceiling": ["messages:read"],
            "memoryScope": "ephemeral",
            "governance": "single_admin",
        })
        .to_string();
        rt().block_on(crate::context::context_create_on(
            &scp.inner,
            &identity,
            params_json,
        ))
        .expect("context_create must succeed");
        let core = &scp.inner.core;
        let attached = Arc::clone(
            core.try_supervisor()
                .expect("context_create attaches a Supervisor"),
        );

        let first = rt()
            .block_on(scp.node_start_in_memory(Some(did.clone())))
            .expect("a start after context_create binds the attached Supervisor");
        assert!(
            Arc::ptr_eq(core.try_supervisor().unwrap(), &attached),
            "the start keeps the Supervisor context_create attached"
        );
        assert!(server::supervisor_wired_to(core, &first.inner));

        let borrowers = core.borrower_count();
        assert_refused_while_bound(
            rt().block_on(scp.node_start_in_memory(Some(did.clone()))),
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
        let second = rt()
            .block_on(scp.node_start_in_memory(Some(did)))
            .expect("a start after the bound node's handle drops binds again");
        assert!(Arc::ptr_eq(core.try_supervisor().unwrap(), &attached));
        assert!(server::supervisor_wired_to(core, &second.inner));
        second.shutdown();
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
        let scp = crate::scp::Scp::new_in_memory_for_test();
        let identity = rt()
            .block_on(scp.identity_create("in_memory".to_owned(), None))
            .unwrap();
        let did = identity.did();
        scp.configure_local_transport(did.clone()).unwrap();
        let core = &scp.inner.core;
        let attached = Arc::clone(
            core.try_supervisor()
                .expect("configure_local_transport attaches a Supervisor"),
        );

        let first = rt()
            .block_on(scp.node_start_local(dir("first"), Some(did.clone()), None))
            .expect("a start after configure_local_transport binds the attached Supervisor");
        assert!(Arc::ptr_eq(core.try_supervisor().unwrap(), &attached));
        assert!(server::supervisor_wired_to(core, &first.inner));

        let borrowers = core.borrower_count();
        assert_refused_while_bound(
            rt().block_on(scp.node_start_local(dir("second"), Some(did.clone()), None)),
            "node_start_local",
        );
        assert_eq!(core.borrower_count(), borrowers);
        assert!(server::supervisor_wired_to(core, &first.inner));

        first.shutdown();
        assert!(!server::supervisor_wired_to(core, &first.inner));
        let third = rt()
            .block_on(scp.node_start_local(dir("third"), Some(did), None))
            .expect("a start after shutdown binds again");
        assert!(server::supervisor_wired_to(core, &third.inner));
        third.shutdown();
    }
}
