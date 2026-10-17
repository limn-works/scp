//! `UniFFI` bridge for relay and application node server startup.
//!
//! Wraps the shared startup code in `scp-ffi-common::server` for consumption
//! from Swift and Kotlin via `#[uniffi::export]` functions and objects.
//!
//! - [`RelayHandle`] -- opaque handle to a running relay server.
//! - [`NodeHandle`] -- opaque handle to a running application node (wraps
//!   encrypted-in-memory and `SQLCipher` variants via an internal enum).
//! - `relay_start_in_memory` / `relay_start_local` -- relay startup.
//! - `Scp::node_start` -- node startup from a flat [`NodeStartConfig`]
//!   (ADR-052) under the operator identity, through
//!   `scp_ffi_common::server::node_start`.
//! - `node_start_in_memory` / `node_start_local` -- node startup.
//!
//! Gated behind the `server` feature on `scp-ffi-common`.

use scp_ffi_common::error_codes as codes;
use std::sync::Arc;

use zeroize::Zeroizing;

use scp_ffi_common::server::{self, BroadcastKeyError, RunningNode, ServerError};
use scp_ffi_common::validate::{validate_context_id, validate_deploy_id, validate_did};
use scp_node::NodeError;

use crate::bridge::{Identity, ScpError};
use crate::{decrement_handle_count, increment_handle_count};

// ---------------------------------------------------------------------------
// Error conversion
// ---------------------------------------------------------------------------

/// Builds the [`ScpError`] for `e` with `msg`: the variant from
/// `server_error_class` and the code from `server_error_code`, the one mapping
/// the `PyO3`, napi-rs and `UniFFI` bridges share (sdk-common.md §"Node start
/// error codes").
fn coded(e: &ServerError, msg: String) -> ScpError {
    let code = codes::server_error_code(e).to_owned();
    match codes::server_error_class(e) {
        codes::ServerErrorClass::Validation => ScpError::Validation { msg, code },
        codes::ServerErrorClass::Identity => ScpError::Identity { msg, code },
        codes::ServerErrorClass::Transport => ScpError::Transport { msg, code },
        codes::ServerErrorClass::Context => ScpError::Context { msg, code },
    }
}

impl From<ServerError> for ScpError {
    fn from(e: ServerError) -> Self {
        tracing::debug!(error = %e, "server operation failed");
        coded(&e, e.user_message())
    }
}

/// A `NodeError` from a running node's operation (projection, deploy, serve)
/// maps as `ServerError::Node` does, with a message that names no path.
impl From<NodeError> for ScpError {
    fn from(e: NodeError) -> Self {
        tracing::debug!(error = %e, "node operation failed");
        coded(&ServerError::Node(e), "node operation failed".to_owned())
    }
}

impl From<BroadcastKeyError> for ScpError {
    fn from(e: BroadcastKeyError) -> Self {
        match e {
            BroadcastKeyError::InvalidHex(_) | BroadcastKeyError::InvalidKeyLength => {
                Self::Validation {
                    msg: e.to_string(),
                    code: codes::TRANS_5060.to_owned(),
                }
            }
            BroadcastKeyError::KeyWithoutAuthor => Self::Validation {
                msg: e.to_string(),
                code: codes::TRANS_5060.to_owned(),
            },
            BroadcastKeyError::AutoResolveFailed(_) => Self::Context {
                msg: e.to_string(),
                code: codes::CTX_2060.to_owned(),
            },
        }
    }
}

/// Wires `bi`'s `Supervisor` to the started, registered `node` through the
/// relay at `relay_url`, which every production caller sets to
/// `node.internal_relay_url()`.
///
/// Delegates to [`server::wire_supervisor_to_node`], which on any failure
/// shuts `node` down, removes it from the instance's node registry, and
/// returns `ServerError::SupervisorWiring` (`SCP-TRANS-5056`, sdk-common.md
/// §"Node start error codes"). The attach step is
/// `UniffiBridgeInstance::init_context_manager_with_did`, the same set-once
/// init `context_create` runs.
async fn auto_wire_context_manager(
    bi: &Arc<crate::runtime::UniffiBridgeInstance>,
    node: &Arc<RunningNode>,
    relay_url: &str,
) -> Result<(), ScpError> {
    server::wire_supervisor_to_node(&bi.core, node, relay_url, |did| {
        bi.init_context_manager_with_did(did);
    })
    .await
    .map_err(ScpError::from)
}

// ---------------------------------------------------------------------------
// RelayHandle
// ---------------------------------------------------------------------------

/// Opaque handle to a running SCP relay server.
///
/// Created by `relay_start_in_memory` or `relay_start_local`. The relay
/// accepts WebSocket connections at [`relay_url`](Self::relay_url)
/// and can be gracefully stopped via [`shutdown`](Self::shutdown).
#[derive(uniffi::Object)]
pub struct RelayHandle {
    inner: server::RunningRelay,
    /// Monotonic identifier of the bridge instance that minted this handle.
    ///
    /// Affinity substrate: retained so that any future `#[uniffi::export]`
    /// entry accepting a `RelayHandle` can gate on
    /// `CoreFields::check_handle(handle.instance_id())`. No such entry exists
    /// today (`RelayHandle` is only ever returned, never passed back in), so
    /// the field has no live reader — hence `#[allow(dead_code)]`. It is NOT
    /// host-visible (see ADR-048 — per-handle `instanceId` is not exported).
    #[allow(dead_code)]
    pub(crate) instance_id: u64,
}

impl RelayHandle {
    /// Returns the monotonic identifier of the bridge instance that minted
    /// this handle.
    ///
    /// Rust-internal affinity substrate consumed by
    /// `CoreFields::check_handle`. No caller passes a `RelayHandle` back
    /// across the FFI boundary yet, so this has no live caller — hence
    /// `#[allow(dead_code)]`. NOT exposed through `#[uniffi::export]`
    /// (see ADR-048 — per-handle `instanceId` is not host-visible).
    #[allow(dead_code)]
    #[must_use]
    pub(crate) const fn instance_id(&self) -> u64 {
        self.instance_id
    }
}

#[uniffi::export]
impl RelayHandle {
    /// Returns the WebSocket URL clients should connect to
    /// (e.g., `ws://127.0.0.1:12345/scp/v1`).
    #[must_use]
    pub fn relay_url(&self) -> String {
        self.inner.relay_url().to_owned()
    }

    /// Returns the port the relay is listening on.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)] // UniFFI export methods cannot be const.
    pub fn relay_port(&self) -> u16 {
        self.inner.bound_addr().port()
    }

    /// Returns `true` if shutdown has already been signaled.
    #[must_use]
    pub fn is_shutdown(&self) -> bool {
        self.inner.is_shutdown()
    }

    /// Signals the relay server to stop accepting new connections.
    ///
    /// In-flight connection handlers drain naturally after shutdown is
    /// signaled -- they are not cancelled.
    pub fn shutdown(&self) {
        self.inner.shutdown();
    }
}

impl Drop for RelayHandle {
    fn drop(&mut self) {
        self.inner.shutdown();
        decrement_handle_count();
    }
}

// ---------------------------------------------------------------------------
// NodeHandle -- type-erased ApplicationNode wrapper
// ---------------------------------------------------------------------------

/// The site settings of one [`NodeHandle::enable_site_projection`] call
/// (section 18.11).
///
/// They travel as one record so that the export takes five buffer
/// arguments: JNA on darwin-aarch64 corrupts a by-value `RustBuffer`
/// argument of some calls that pass nine or more of them, and the
/// `ffi_buffer_arg_bound` test holds every export to eight.
#[derive(Debug, Clone, uniffi::Record)]
pub struct SiteProjectionSettings {
    /// The virtual host (RFC 1123).
    pub hostname: String,
    /// The path served at `/`; `None` serves `/index.html`.
    pub index_path: Option<String>,
    /// The most assets one deploy may hold; `None` allows 10 000.
    pub max_assets_per_deploy: Option<u32>,
    /// The largest total deploy size in bytes; `None` allows 512 MiB.
    pub max_deploy_size_bytes: Option<u64>,
    /// How many past deploys are kept; `None` keeps 2.
    pub deploy_retention_count: Option<u32>,
    /// A Content-Security-Policy header replacing the default.
    pub csp_override: Option<String>,
}

/// Opaque handle to a running SCP application node.
///
/// Created by [`Scp::node_start_in_memory`](crate::scp::Scp::node_start_in_memory)
/// or [`Scp::node_start_local`](crate::scp::Scp::node_start_local). The
/// node includes a running relay server, a generated DID identity, and
/// (optionally) persistent storage. The HTTP server is **not** started
/// automatically -- only the relay is bound.
#[derive(uniffi::Object)]
pub struct NodeHandle {
    /// Shared with this instance's borrower registry, which holds a `Weak` to
    /// this same node so `Scp::shutdown` stops it before releasing storage
    /// (see `scp_ffi_common::bridge_instance::InstanceBorrower`).
    inner: Arc<RunningNode>,
    /// Owning `UniffiBridgeInstance` — the handle reaches back into its
    /// instance's `ContextManager` for broadcast-key lookup during HTTP
    /// projection. Phase D (#1695) replaced `crate::runtime::context_manager()`
    /// free-function lookup with this Arc affinity.
    pub(crate) bi: Arc<crate::runtime::UniffiBridgeInstance>,
    /// Monotonic identifier of the bridge instance that minted this handle.
    ///
    /// Affinity substrate: retained so that any future `#[uniffi::export]`
    /// entry accepting a `NodeHandle` can gate on
    /// `CoreFields::check_handle(handle.instance_id())`. The existing
    /// `NodeHandle` methods reach back through the owning `bi` Arc and never
    /// re-check the minting instance via this field, so it has no live reader
    /// today — hence `#[allow(dead_code)]`. It is NOT host-visible (see
    /// ADR-048 — per-handle `instanceId` is not exported).
    #[allow(dead_code)]
    pub(crate) instance_id: u64,
}

impl NodeHandle {
    /// Returns the monotonic identifier of the bridge instance that minted
    /// this handle.
    ///
    /// Rust-internal affinity substrate consumed by
    /// `CoreFields::check_handle`. No caller passes a `NodeHandle` back across
    /// the FFI boundary for an affinity check yet, so this has no live caller
    /// — hence `#[allow(dead_code)]`. NOT exposed through `#[uniffi::export]`
    /// (see ADR-048 — per-handle `instanceId` is not host-visible).
    #[allow(dead_code)]
    #[must_use]
    pub(crate) const fn instance_id(&self) -> u64 {
        self.instance_id
    }
}

#[uniffi::export]
impl NodeHandle {
    /// Returns the WebSocket URL clients should connect to for this node's
    /// relay (e.g., `ws://127.0.0.1:12345/scp/v1`).
    ///
    /// Read live per call from the node's relay-URL slot, so it reflects a NAT
    /// tier change that re-pointed the node's endpoint.
    #[must_use]
    pub fn relay_url(&self) -> String {
        self.inner.relay_url()
    }

    /// Returns the port the node's relay is listening on.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)] // UniFFI export methods cannot be const.
    pub fn relay_port(&self) -> u16 {
        self.inner.relay_port()
    }

    /// Returns the node's DID string (e.g., `did:dht:z6Mk...`).
    #[must_use]
    pub fn did(&self) -> String {
        self.inner.did().to_owned()
    }

    /// Returns `true` if shutdown has already been signaled.
    #[must_use]
    pub fn is_shutdown(&self) -> bool {
        self.inner.is_shutdown()
    }

    /// Signals the node to stop (relay + background tasks), and unbinds the
    /// instance's `Supervisor` transport from this node when it holds the
    /// binding.
    pub fn shutdown(&self) {
        server::stop_node(&self.bi.core, &self.inner);
    }

    /// Activates HTTP broadcast projection with site configuration.
    ///
    /// Three resolution modes:
    /// 1. Both `broadcast_key_hex` **and** `author_did` provided — uses the
    ///    explicit key with epoch 0.
    /// 2. Only `author_did` provided — auto-resolves the broadcast key
    ///    using that DID (useful when the author identity differs from the
    ///    node identity).
    /// 3. Neither provided — auto-resolves using the node's identity DID.
    ///
    /// Providing `broadcast_key_hex` without `author_did` is an error.
    ///
    /// `admission` is `"open"` or `"gated"`. `site` carries the virtual
    /// host (RFC 1123) and the serving limits.
    pub async fn enable_site_projection(
        &self,
        context_id: String,
        admission: String,
        broadcast_key_hex: Option<String>,
        author_did: Option<String>,
        site: SiteProjectionSettings,
    ) -> Result<(), ScpError> {
        let SiteProjectionSettings {
            hostname,
            index_path,
            max_assets_per_deploy,
            max_deploy_size_bytes,
            deploy_retention_count,
            csp_override,
        } = site;
        validate_context_id(&context_id)?;
        if let Some(ref did) = author_did {
            validate_did(did)?;
        }

        // Resolve broadcast key: explicit, auto-lookup, or auto with explicit author.
        // Delegates to the shared resolver in scp-ffi-common (same logic as PyO3/NAPI).
        let supervisor = self.bi.context_manager_expect()?;
        let resolved = server::resolve_broadcast_key(
            broadcast_key_hex,
            author_did,
            self.inner.did(),
            supervisor,
            &context_id,
        )
        .await?;
        let broadcast_key = resolved.into_broadcast_key();

        let adm = match admission.to_lowercase().as_str() {
            "open" => scp_core::context::broadcast::BroadcastAdmission::Open,
            "gated" => scp_core::context::broadcast::BroadcastAdmission::Gated,
            other => {
                return Err(ScpError::Validation {
                    msg: format!("admission must be \"open\" or \"gated\", got \"{other}\""),
                    code: codes::TRANS_5061.to_owned(),
                });
            }
        };

        let idx_path_str = index_path.as_deref().unwrap_or("/index.html");
        let content_path = scp_core::context::broadcast_content::ContentPath::new(idx_path_str)
            .map_err(|e| ScpError::Validation {
                msg: format!("invalid index_path: {e}"),
                code: codes::TRANS_5062.to_owned(),
            })?;

        let site_config = scp_node::projection::SiteConfig {
            hostname,
            index_path: content_path,
            max_assets_per_deploy: max_assets_per_deploy.map_or(10_000, |v| v as usize),
            max_deploy_size_bytes: max_deploy_size_bytes.unwrap_or(512 * 1024 * 1024),
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
            .map_err(ScpError::from)
    }

    /// Commits a deploy for a projected context (section 18.11.11).
    ///
    /// Returns the number of assets in the committed deploy.
    pub async fn commit_deploy(
        &self,
        context_id: String,
        deploy_id: String,
    ) -> Result<u32, ScpError> {
        validate_context_id(&context_id)?;
        validate_deploy_id(&deploy_id)?;
        let count = self
            .inner
            .commit_deploy(&context_id, &deploy_id)
            .await
            .map_err(ScpError::from)?;
        u32::try_from(count).map_err(|_| ScpError::Validation {
            msg: format!("asset count {count} exceeds u32::MAX"),
            code: codes::TRANS_5063.to_owned(),
        })
    }

    /// Rolls back to a previous deploy for a projected context (section 18.11.11).
    pub async fn rollback_deploy(
        &self,
        context_id: String,
        deploy_id: String,
    ) -> Result<(), ScpError> {
        validate_context_id(&context_id)?;
        validate_deploy_id(&deploy_id)?;
        self.inner
            .rollback_deploy(&context_id, &deploy_id)
            .await
            .map_err(ScpError::from)
    }

    /// Deactivates HTTP broadcast projection for the given context.
    pub async fn disable_site_projection(&self, context_id: String) -> Result<(), ScpError> {
        validate_context_id(&context_id)?;
        self.inner.disable_broadcast_projection(&context_id).await;
        Ok(())
    }

    /// Starts the HTTP server in the background on the given bind address.
    ///
    /// Defaults to `127.0.0.1:8443` (loopback only) when `bind_addr` is `None`.
    /// Returns the actual bound address as a raw string (e.g., `"127.0.0.1:8443"`).
    /// Use [`http_url`](NodeHandle::http_url) for the full URL form
    /// (`"http://127.0.0.1:8443"`).
    ///
    /// **Note:** The background server does not support TLS. For production
    /// deployments requiring encryption, use the node binary's `serve()`
    /// with TLS configuration.
    ///
    /// Throws if the server is already running or binding fails.
    pub async fn serve(&self, bind_addr: Option<String>) -> Result<String, ScpError> {
        let addr = bind_addr
            .map(|s| {
                s.parse::<std::net::SocketAddr>().map_err(|_| {
                    let display = if s.len() > 128 {
                        &s[..s.floor_char_boundary(128)]
                    } else {
                        &s
                    };
                    ScpError::Validation {
                        msg: format!("invalid bind_addr: {display}"),
                        code: codes::TRANS_5070.to_owned(),
                    }
                })
            })
            .transpose()?;
        self.inner
            .serve_background(addr)
            .await
            .map(|a| a.to_string())
            .map_err(ScpError::from)
    }

    /// Returns the HTTP URL of the background server, or `None` if not serving.
    #[must_use]
    pub async fn http_url(&self) -> Option<String> {
        self.inner.http_url().await
    }
}

impl Drop for NodeHandle {
    fn drop(&mut self) {
        server::stop_node(&self.bi.core, &self.inner);
        decrement_handle_count();
    }
}

// ---------------------------------------------------------------------------
// Free functions -- relay startup
// ---------------------------------------------------------------------------

/// Per-instance helper used by [`crate::Scp::relay_start_in_memory`] on the
/// caller-owned `Scp`. Replaces the deleted `relay_start_in_memory` free
/// function (Phase D, #1695) — relay handles must be stamped against a
/// concrete instance so their `instance_id` can participate in the
/// handle-affinity check.
pub(crate) async fn relay_start_in_memory_on(
    bi: &Arc<crate::runtime::UniffiBridgeInstance>,
) -> Result<Arc<RelayHandle>, ScpError> {
    let relay = server::start_relay_in_memory().await?;
    let instance_id = bi.core.instance_id();
    increment_handle_count();
    Ok(Arc::new(RelayHandle {
        inner: relay,
        instance_id,
    }))
}

/// Per-instance helper used by [`crate::Scp::relay_start_local`] on the
/// caller-owned `Scp`.
pub(crate) async fn relay_start_local_on(
    bi: &Arc<crate::runtime::UniffiBridgeInstance>,
    data_dir: String,
) -> Result<Arc<RelayHandle>, ScpError> {
    let relay = server::start_relay_local(std::path::Path::new(&data_dir)).await?;
    let instance_id = bi.core.instance_id();
    increment_handle_count();
    Ok(Arc::new(RelayHandle {
        inner: relay,
        instance_id,
    }))
}

// ---------------------------------------------------------------------------
// Free functions -- node startup
// ---------------------------------------------------------------------------

/// Builds a [`server::NodeIdentity`] from a `UniFFI` [`Identity`] handle.
///
/// Extracts the `ScpIdentity` and `DidDocument` retained in the identity
/// handle, then constructs a `ConcreteDidMethod` (`DidDht`) with a signing
/// function derived from the identity's custody provider, so the node runs
/// under its operator's identity (construction.md §"Node start —
/// `NodeStartConfig`"). Compiled on every build: a shipped Swift build signs
/// through the host's callback custody.
///
/// # Errors
///
/// - `ScpError::Identity` with `SCP-IDENT-1063` (sdk-common.md §"Node start
///   error codes", `OperatorIdentityUnavailable`) when the handle retains no
///   `ScpIdentity`, no `DidDocument`, or no custody, as a handle from
///   `identity_load` over external custody does.
/// - `ScpError::Identity` with `SCP-IDENT-1058` when the instance holds no DHT
///   client and the production client cannot be built.
#[allow(clippy::type_complexity)]
fn build_node_identity_from_uniffi(id: &Identity) -> Result<server::NodeIdentity, ScpError> {
    use scp_ffi_common::server::ConcreteDidMethod;
    use scp_identity::{DidCache, IdentityError};
    use scp_platform::traits::KeyCustody;

    // Each missing piece names why the identity cannot run a node; all three
    // are `OperatorIdentityUnavailable`, so they share its code and class.
    let unavailable = |why: &str| ScpError::Identity {
        msg: format!("operator identity is not available to the node: {why}"),
        code: codes::server_error_code(&ServerError::OperatorIdentityUnavailable).to_owned(),
    };

    let core_id = id.core_id.clone().ok_or_else(|| {
        unavailable(
            "the handle holds no key handles; only an identity created on this \
             instance (identity_create or identity_create_with_custody) can run a node",
        )
    })?;
    let document = id
        .core_document
        .clone()
        .ok_or_else(|| unavailable("the handle holds no DID document"))?;
    // Every custody backend signs through the enum's `KeyCustody` dispatch, so
    // the node takes whichever custody created the identity. An identity with
    // no custody (one `identity_load` built over external custody) cannot sign.
    let custody = id
        .custody
        .as_ref()
        .ok_or_else(|| unavailable("the handle holds no key custody"))?;

    let custody_clone = Arc::clone(custody);
    let sign_fn: Arc<
        dyn Fn(
                u64,
                Vec<u8>,
            ) -> std::pin::Pin<
                Box<dyn std::future::Future<Output = Result<Vec<u8>, IdentityError>> + Send>,
            > + Send
            + Sync,
    > = Arc::new(move |key_id: u64, data: Vec<u8>| {
        let kc = Arc::clone(&custody_clone);
        Box::pin(async move {
            let handle = scp_platform::traits::KeyHandle::new(key_id);
            let sig = kc
                .sign(&handle, &data)
                .await
                .map_err(IdentityError::Platform)?;
            Ok(sig.into_bytes())
        })
    });

    // Source the shared per-instance DHT client the identity was minted against
    // (the one its DID document was published into by `identity_create`), so the
    // node's DID method resolves against the SAME store — never a throwaway
    // in-memory client. Falls back to the fail-closed production client if the
    // instance somehow has none (ADR-062 §Decision 1). The shipped client is the
    // real Mainline Pkarr client; the in-memory arm exists only under `testing`.
    let dht_client = match id.bi.core.dht_client() {
        Some(client) => Arc::clone(client),
        None => Arc::new(crate::bridge::build_ffi_dht_client()?),
    };
    let cache = Arc::new(DidCache::new());
    let did_method = Arc::new(ConcreteDidMethod::with_client_and_signer(
        dht_client, cache, sign_fn,
    ));

    Ok(server::NodeIdentity {
        identity: core_id,
        document,
        did_method,
    })
}

// ---------------------------------------------------------------------------
// node_start — production node start from this instance (SCP-322)
// ---------------------------------------------------------------------------

/// How the node is reached; mirrors `scp_ffi_common::node_start_config::FfiReach`
/// (construction.md §"Node start — `NodeStartConfig`").
#[derive(Debug, Clone, uniffi::Enum)]
pub enum FfiReach {
    /// A public DNS name the node serves under.
    Domain {
        /// The DNS name, with no scheme, port or path.
        domain: String,
    },
    /// No domain; the node discovers a public address through NAT traversal.
    NatTraversal,
    /// Loopback only.
    Local,
}

/// The node's blob storage backend; mirrors
/// `scp_ffi_common::node_start_config::FfiBlobBackend`.
#[derive(Debug, Clone, uniffi::Enum)]
pub enum FfiBlobBackend {
    /// Blobs in process memory, lost on drop.
    InMemory,
    /// A redb database file at `path`.
    Redb {
        /// The database file path; its parent directory is created.
        path: String,
    },
    /// A `SQLite` database file at `path`.
    Sqlite {
        /// The database file path; its parent directory is created.
        path: String,
    },
}

/// How the node provisions TLS; mirrors
/// `scp_ffi_common::node_start_config::FfiTlsMode`.
#[derive(Debug, Clone, uniffi::Enum)]
pub enum FfiTlsMode {
    /// A self-signed certificate.
    SelfSigned,
    /// An ACME certificate for the `Domain` reach.
    Acme {
        /// The ACME account contact address, if any.
        email: Option<String>,
    },
    /// No TLS.
    Plaintext,
    /// TLS terminated in front of the node.
    Terminated,
}

/// The node's DHT mode; mirrors `scp_ffi_common::node_start_config::FfiDhtMode`.
/// `Disabled` is the one arm (keri's scope ruling of 2026-10-13).
#[derive(Debug, Clone, uniffi::Enum)]
pub enum FfiDhtMode {
    /// The node publishes nothing to a DHT.
    Disabled,
}

/// The HTTP CORS origins the node allows; mirrors
/// `scp_ffi_common::node_start_config::FfiCorsOrigins`.
#[derive(Debug, Clone, uniffi::Enum)]
pub enum FfiCorsOrigins {
    /// Any origin (`*`), selected only by naming it.
    AnyOrigin,
    /// These `scheme://host` origins.
    Allowlist {
        /// The allowed origins; `*` is rejected.
        origins: Vec<String>,
    },
}

/// The node's NAT traversal strategy; mirrors
/// `scp_ffi_common::node_start_config::FfiNat`.
#[derive(Debug, Clone, uniffi::Enum)]
pub enum FfiNat {
    /// The core's automatic strategy.
    Auto,
}

/// The `UniFFI` form of `scp_ffi_common::node_start_config::NodeStartConfig`.
///
/// construction.md §"Node start — `NodeStartConfig`", ADR-052. `identity` is
/// the operator's [`Identity`] handle, minted by the same `Scp`; the socket
/// addresses are `host:port` strings.
#[derive(uniffi::Record)]
pub struct NodeStartConfig {
    /// How the node is reached.
    pub reach: FfiReach,
    /// The operator identity the node runs under.
    pub identity: Arc<Identity>,
    /// The node's blob storage backend.
    pub blob_storage: FfiBlobBackend,
    /// How the node provisions TLS.
    pub tls: FfiTlsMode,
    /// The node's DHT mode.
    pub dht: FfiDhtMode,
    /// The HTTP CORS origins the node allows.
    pub cors_origins: FfiCorsOrigins,
    /// The relay's bind address (`host:port`); the core picks one when `None`.
    pub bind_addr: Option<String>,
    /// The HTTP server's bind address (`host:port`).
    pub http_bind_addr: Option<String>,
    /// The NAT traversal strategy.
    pub nat: Option<FfiNat>,
    /// The projection rate limit, greater than 0.
    pub projection_rate_limit: Option<u32>,
}

/// Parses an optional `host:port` field; a malformed one is
/// `ServerError::InvalidConfig`, naming the field and never echoing the value.
fn parse_addr(
    field: &str,
    addr: Option<String>,
) -> Result<Option<std::net::SocketAddr>, ServerError> {
    addr.map(|a| {
        a.parse().map_err(|_| {
            ServerError::InvalidConfig(format!("{field} must be a host:port socket address"))
        })
    })
    .transpose()
}

/// Lowers the `UniFFI` config to the shared `NodeStartConfig`, naming the
/// operator by the handle's DID. Returns the handle for identity resolution.
fn lower_node_start_config(
    cfg: NodeStartConfig,
) -> Result<
    (
        scp_ffi_common::node_start_config::NodeStartConfig,
        Arc<Identity>,
    ),
    ServerError,
> {
    use scp_ffi_common::node_start_config as common;
    let NodeStartConfig {
        reach,
        identity,
        blob_storage,
        tls,
        dht,
        cors_origins,
        bind_addr,
        http_bind_addr,
        nat,
        projection_rate_limit,
    } = cfg;
    let lowered = common::NodeStartConfig {
        reach: match reach {
            FfiReach::Domain { domain } => common::FfiReach::Domain { domain },
            FfiReach::NatTraversal => common::FfiReach::NatTraversal {},
            FfiReach::Local => common::FfiReach::Local {},
        },
        identity: identity.did.clone(),
        blob_storage: match blob_storage {
            FfiBlobBackend::InMemory => common::FfiBlobBackend::InMemory {},
            FfiBlobBackend::Redb { path } => common::FfiBlobBackend::Redb { path: path.into() },
            FfiBlobBackend::Sqlite { path } => common::FfiBlobBackend::Sqlite { path: path.into() },
        },
        tls: match tls {
            FfiTlsMode::SelfSigned => common::FfiTlsMode::SelfSigned {},
            FfiTlsMode::Acme { email } => common::FfiTlsMode::Acme { email },
            FfiTlsMode::Plaintext => common::FfiTlsMode::Plaintext {},
            FfiTlsMode::Terminated => common::FfiTlsMode::Terminated {},
        },
        dht: match dht {
            FfiDhtMode::Disabled => common::FfiDhtMode::Disabled {},
        },
        cors_origins: match cors_origins {
            FfiCorsOrigins::AnyOrigin => common::FfiCorsOrigins::AnyOrigin {},
            FfiCorsOrigins::Allowlist { origins } => common::FfiCorsOrigins::Allowlist { origins },
        },
        bind_addr: parse_addr("bind_addr", bind_addr)?,
        http_bind_addr: parse_addr("http_bind_addr", http_bind_addr)?,
        nat: nat.map(|n| match n {
            FfiNat::Auto => common::FfiNat::Auto {},
        }),
        projection_rate_limit,
    };
    Ok((lowered, identity))
}

/// Per-instance helper behind [`crate::Scp::node_start`]: starts a production
/// node on this instance's storage under the operator identity `cfg` names.
///
/// Runs, in order: the handle check on `cfg.identity`, the config conversion,
/// the operator identity resolution, taking the instance storage,
/// `server::node_start`, `server::register_node`, `auto_wire_context_manager`,
/// and wrapping the handle.
///
/// # Errors
///
/// `SCP-PERM-3030` when another `Scp` minted `cfg.identity`; otherwise the
/// code sdk-common.md §"Node start error codes" gives the failure.
pub(crate) async fn node_start_on(
    bi: &Arc<crate::runtime::UniffiBridgeInstance>,
    cfg: NodeStartConfig,
) -> Result<Arc<NodeHandle>, ScpError> {
    bi.core
        .check_handle(cfg.identity.instance_id())
        .map_err(ScpError::from)?;
    let (cfg, identity) = lower_node_start_config(cfg)?;
    let node_identity = build_node_identity_from_uniffi(&identity)?;
    let storage = bi.protocol_repository().instance_storage();
    let node = server::node_start(cfg, node_identity, storage).await?;
    // Registered before anything else can fail, so `Scp::shutdown` stops this
    // node before it releases the storage the node holds
    // (`scp_ffi_common::bridge_instance::InstanceBorrower`).
    let inner = server::register_node(&bi.core, node);
    auto_wire_context_manager(bi, &inner, &inner.internal_relay_url()).await?;
    let instance_id = bi.core.instance_id();
    increment_handle_count();
    Ok(Arc::new(NodeHandle {
        inner,
        bi: Arc::clone(bi),
        instance_id,
    }))
}

/// Per-instance helper used by [`crate::Scp::node_start_in_memory`] on the
/// caller-owned `Scp`. Replaces the deleted `node_start_in_memory` free
/// function (Phase D, #1695).
pub(crate) async fn node_start_in_memory_on(
    bi: &Arc<crate::runtime::UniffiBridgeInstance>,
    identity: Option<Arc<Identity>>,
) -> Result<Arc<NodeHandle>, ScpError> {
    // Handle-affinity check moved from `uniffi_check_handle!` macro expansion
    // (which read `DEFAULT_BRIDGE_INSTANCE`) to a direct `CoreFields::check_handle`
    // against the caller's own `bi`. Mirrors `identity_attest_device` etc.
    if let Some(ref id) = identity {
        bi.core
            .check_handle(id.instance_id())
            .map_err(ScpError::from)?;
    }
    let node_identity = match identity {
        Some(ref id) => Some(build_node_identity_from_uniffi(id)?),
        None => None,
    };
    let node = server::start_node_in_memory(node_identity).await?;

    // Register this node as a borrower of this instance's resources, so
    // `Scp::shutdown` stops it before `bridge_specific_shutdown` releases
    // anything (`scp_ffi_common::bridge_instance::InstanceBorrower`), and so a
    // failed wiring below can remove it again.
    let inner = server::register_node(&bi.core, RunningNode::InMemoryEncrypted(node));
    // Wire the Supervisor through the internal loopback URL: `relay_url()` is
    // the advertised URL, which requires TLS and lacks the bound port.
    auto_wire_context_manager(bi, &inner, &inner.internal_relay_url()).await?;

    let instance_id = bi.core.instance_id();
    increment_handle_count();
    Ok(Arc::new(NodeHandle {
        inner,
        bi: Arc::clone(bi),
        instance_id,
    }))
}

/// Per-instance helper used by [`crate::Scp::node_start_local`] on the
/// caller-owned `Scp`.
///
/// A node inherits whichever storage backend an instance was constructed with
/// (`Scp::with_storage`), so it opens no protocol store of its own. A caller
/// wanting a node on a different backend constructs a second `Scp`.
pub(crate) async fn node_start_local_on(
    bi: &Arc<crate::runtime::UniffiBridgeInstance>,
    data_dir: String,
    identity: Option<Arc<Identity>>,
    passphrase: Option<String>,
) -> Result<Arc<NodeHandle>, ScpError> {
    if let Some(ref id) = identity {
        bi.core
            .check_handle(id.instance_id())
            .map_err(ScpError::from)?;
    }
    let node_identity = match identity {
        Some(ref id) => Some(build_node_identity_from_uniffi(id)?),
        None => None,
    };
    let zeroized_passphrase = passphrase.map(Zeroizing::new);
    let data_dir = std::path::Path::new(&data_dir);
    // `ProtocolRepository::storage()` yields this instance's own chosen
    // backend; cloning that `Arc` hands a node one store that an event log, a
    // saga journal, and an `OpenMLS` view already share (spec §17.6).
    let inner = match bi.protocol_repository() {
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
    }?;
    // This node holds a clone of this instance's storage `Arc`, so register it
    // before anything else: `Scp::shutdown` must stop this node before
    // the durable store closer closes that `SQLCipher` handle and drops an
    // advisory `flock(2)`
    // (`scp_ffi_common::bridge_instance::InstanceBorrower`).
    let inner = server::register_node(&bi.core, inner);

    // Wire the Supervisor through the internal loopback URL — see the
    // comment in node_start_in_memory.
    auto_wire_context_manager(bi, &inner, &inner.internal_relay_url()).await?;

    let instance_id = bi.core.instance_id();
    increment_handle_count();
    Ok(Arc::new(NodeHandle {
        inner,
        bi: Arc::clone(bi),
        instance_id,
    }))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use scp_ffi_common::error_codes as codes;

    fn rt() -> &'static tokio::runtime::Runtime {
        crate::runtime()
    }

    #[test]
    fn relay_in_memory_starts_and_returns_url() {
        let scp = crate::scp::Scp::new_in_memory_for_test();
        let relay = rt().block_on(scp.relay_start_in_memory()).unwrap();
        assert!(relay.relay_url().starts_with("ws://127.0.0.1:"));
        assert!(relay.relay_url().ends_with("/scp/v1"));
        assert!(relay.relay_port() > 0);
        assert!(!relay.is_shutdown());
        relay.shutdown();
        assert!(relay.is_shutdown());
    }

    #[test]
    fn relay_local_starts_and_returns_url() {
        let tmp =
            std::env::temp_dir().join(format!("scp-uniffi-relay-test-{}", std::process::id()));
        let scp = crate::scp::Scp::new_in_memory_for_test();
        let relay = rt()
            .block_on(scp.relay_start_local(tmp.to_string_lossy().into_owned()))
            .unwrap();
        assert!(relay.relay_url().starts_with("ws://127.0.0.1:"));
        assert!(relay.relay_port() > 0);
        relay.shutdown();
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn node_in_memory_starts_and_returns_did() {
        let scp = crate::scp::Scp::new_in_memory_for_test();
        let node = rt().block_on(scp.node_start_in_memory(None)).unwrap();
        let url = node.relay_url();
        assert!(
            url.starts_with("ws://") || url.starts_with("wss://"),
            "expected ws(s):// URL, got: {url}"
        );
        assert!(node.did().starts_with("did:"));
        assert!(node.relay_port() > 0);

        assert!(!node.is_shutdown());
        node.shutdown();
        assert!(node.is_shutdown());
    }

    /// Regression guard on Swift/Kotlin: after node startup the production
    /// `Supervisor` must have its event broadcast channel enabled, so
    /// `subscribe_events()` yields a receiver. Before the fix,
    /// `build_supervisor` did not enable the channel on this bridge and it was
    /// `None`.
    #[test]
    fn node_startup_enables_context_event_channel() {
        let scp = crate::scp::Scp::new_in_memory_for_test();
        let node = rt().block_on(scp.node_start_in_memory(None)).unwrap();

        let supervisor = scp
            .inner
            .context_manager_expect()
            .expect("Supervisor must be attached after node startup");
        assert!(
            supervisor.subscribe_events().is_some(),
            "node startup must enable the Supervisor event channel"
        );

        node.shutdown();
    }

    #[test]
    fn node_local_starts_and_returns_did() {
        let tmp = std::env::temp_dir().join(format!("scp-uniffi-node-test-{}", std::process::id()));
        let scp = crate::scp::Scp::new_in_memory_for_test();
        let node = rt()
            .block_on(scp.node_start_local(
                tmp.to_string_lossy().into_owned(),
                None,
                Some("test-passphrase".to_owned()),
            ))
            .unwrap();
        let url = node.relay_url();
        assert!(
            url.starts_with("ws://") || url.starts_with("wss://"),
            "expected ws(s):// URL, got: {url}"
        );
        assert!(node.did().starts_with("did:"));
        assert!(node.relay_port() > 0);

        node.shutdown();
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn relay_shutdown_is_idempotent() {
        let scp = crate::scp::Scp::new_in_memory_for_test();
        let relay = rt().block_on(scp.relay_start_in_memory()).unwrap();
        relay.shutdown();
        relay.shutdown();
    }

    #[test]
    fn node_shutdown_is_idempotent() {
        let scp = crate::scp::Scp::new_in_memory_for_test();
        let node = rt().block_on(scp.node_start_in_memory(None)).unwrap();
        node.shutdown();
        node.shutdown();
    }

    #[test]
    fn enable_site_projection_dispatches_through_node_inner() {
        let node = rt().block_on(server::start_node_in_memory(None)).unwrap();
        let inner = RunningNode::InMemoryEncrypted(node);
        let key = scp_core::crypto::sender_keys::BroadcastKey::from_parts(
            scp_core::crypto::sender_keys::SenderKey::from_bytes([0xAB; 32]),
            0,
            "did:dht:uniffi-test".to_owned(),
        );
        let site_config =
            scp_node::projection::SiteConfig::with_hostname("uniffi.example.com").unwrap();
        let result = rt().block_on(inner.enable_broadcast_projection_with_site(
            "uniffi-ctx",
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

    #[test]
    #[cfg(feature = "testing")]
    fn node_in_memory_with_identity_uses_provided_did() {
        let scp = crate::scp::Scp::new_in_memory_for_test();
        let identity = rt()
            .block_on(scp.identity_create("in_memory".to_owned(), None))
            .unwrap();
        let expected_did = identity.did();

        let node = rt()
            .block_on(scp.node_start_in_memory(Some(identity)))
            .unwrap();

        assert_eq!(
            node.did(),
            expected_did,
            "node should use the pre-existing identity's DID"
        );
        assert!(node.relay_port() > 0);
        let url = node.relay_url();
        assert!(
            url.starts_with("ws://") || url.starts_with("wss://"),
            "expected ws(s):// URL, got: {url}"
        );

        node.shutdown();
    }

    #[test]
    #[cfg(feature = "testing")]
    fn node_local_with_identity_uses_provided_did() {
        let scp = crate::scp::Scp::new_in_memory_for_test();
        let identity = rt()
            .block_on(scp.identity_create("in_memory".to_owned(), None))
            .unwrap();
        let expected_did = identity.did();

        let tmp =
            std::env::temp_dir().join(format!("scp-uniffi-node-id-test-{}", std::process::id()));
        // No passphrase needed when passing a pre-existing identity.
        let node = rt()
            .block_on(scp.node_start_local(
                tmp.to_string_lossy().into_owned(),
                Some(identity),
                None,
            ))
            .unwrap();

        assert_eq!(
            node.did(),
            expected_did,
            "node should use the pre-existing identity's DID"
        );
        assert!(node.relay_port() > 0);

        node.shutdown();
        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// A config whose operator is `identity`, on loopback with plaintext,
    /// in-memory blobs and an OS-assigned relay port.
    fn start_config(identity: Arc<Identity>) -> NodeStartConfig {
        NodeStartConfig {
            reach: FfiReach::Local,
            identity,
            blob_storage: FfiBlobBackend::InMemory,
            tls: FfiTlsMode::Plaintext,
            dht: FfiDhtMode::Disabled,
            cors_origins: FfiCorsOrigins::AnyOrigin,
            bind_addr: Some("127.0.0.1:0".to_owned()),
            http_bind_addr: None,
            nat: None,
            projection_rate_limit: None,
        }
    }

    /// The error a refused `node_start` returned.
    fn start_error(result: Result<Arc<NodeHandle>, ScpError>, label: &str) -> ScpError {
        match result {
            Ok(node) => {
                node.shutdown();
                panic!("{label}: node_start must fail");
            }
            Err(e) => e,
        }
    }

    /// The error's class name and code.
    fn class_and_code(e: &ScpError) -> (&'static str, &str) {
        let class = match e {
            ScpError::Identity { .. } => "identity",
            ScpError::Context { .. } => "context",
            ScpError::Permission { .. } => "permission",
            ScpError::Transport { .. } => "transport",
            ScpError::Validation { .. } => "validation",
            other => panic!("unexpected error class: {other:?}"),
        };
        (class, e.code())
    }

    /// An identity `identity_load` returns holds no key material, so the node
    /// cannot run under it, and `node_start` returns `SCP-IDENT-1063` on a
    /// shipped build as on a `testing` build.
    #[test]
    fn node_start_with_externally_loaded_identity_returns_ident_1063() {
        let scp = crate::scp::Scp::new_in_memory_for_test();
        let identity = rt()
            .block_on(scp.identity_load("did:dht:z6MkNodeStartOperatorProbe".to_owned()))
            .expect("identity_load builds an external handle on every build");
        let err = start_error(
            rt().block_on(scp.node_start(start_config(identity))),
            "loaded identity",
        );
        assert_eq!(
            class_and_code(&err),
            ("identity", codes::IDENT_1063),
            "{err:?}"
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
            let err = ScpError::from(e);
            assert_eq!(class_and_code(&err), (class, code), "{label}");
        }

        let err = ScpError::from(NodeError::InvalidConfig("/secret/path/data.db".into()));
        match err {
            ScpError::Validation { msg, code } => {
                assert_eq!(msg, "node operation failed");
                assert_eq!(code, codes::STORAGE_8007);
            }
            other => panic!("expected Validation, got: {other:?}"),
        }
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
            .block_on(scp.node_start(start_config(identity)))
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
    /// `SCP-TRANS-5056`, shuts the node down, unregisters it, and leaves no
    /// fallback `Supervisor`. A second start while a running node holds the
    /// binding also returns `SCP-TRANS-5056`, and a start after that node
    /// stops binds again.
    #[test]
    #[cfg(feature = "testing")]
    fn node_start_wiring_failure_returns_trans_5056_and_unregisters_the_node() {
        let scp = crate::scp::Scp::new_in_memory_for_test();
        let identity = rt()
            .block_on(scp.identity_create("in_memory".to_owned(), None))
            .unwrap();
        let (cfg, lowered) = lower_node_start_config(start_config(Arc::clone(&identity))).unwrap();
        let node_identity = build_node_identity_from_uniffi(&lowered).unwrap();
        let storage = scp.inner.protocol_repository().instance_storage();
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
        assert_eq!(
            class_and_code(&err),
            ("transport", codes::TRANS_5056),
            "{err:?}"
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

        let node = rt()
            .block_on(scp.node_start(start_config(Arc::clone(&identity))))
            .unwrap();
        assert!(server::supervisor_wired_to(&scp.inner.core, &node.inner));
        let err = start_error(
            rt().block_on(scp.node_start(start_config(Arc::clone(&identity)))),
            "second node start",
        );
        assert_eq!(
            class_and_code(&err),
            ("transport", codes::TRANS_5056),
            "{err:?}"
        );
        node.shutdown();
        let restarted = rt()
            .block_on(scp.node_start(start_config(identity)))
            .expect("a start after the bound node stops binds again");
        assert!(server::supervisor_wired_to(
            &scp.inner.core,
            &restarted.inner
        ));
        restarted.shutdown();
    }

    /// Every sdk-common.md §"Node start error codes" row a `UniFFI` caller can
    /// reach through `node_start` returns its code and class.
    #[test]
    #[cfg(feature = "testing")]
    fn node_start_maps_each_reachable_failure_to_its_sdk_common_code() {
        let tmp = tempfile::tempdir().unwrap();
        let file = tmp.path().join("regular-file");
        std::fs::write(&file, b"x").unwrap();
        let dir = tmp.path().join("a-directory");
        std::fs::create_dir(&dir).unwrap();
        let taken = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let taken_addr = taken.local_addr().unwrap().to_string();

        type Mutate = Box<dyn Fn(&mut NodeStartConfig)>;
        let cases: Vec<(&str, Mutate, &str, &str)> = vec![
            (
                "domain with a scheme (InvalidConfig)",
                Box::new(|c| {
                    c.reach = FfiReach::Domain {
                        domain: "https://node.example.org".to_owned(),
                    };
                    c.tls = FfiTlsMode::SelfSigned;
                }),
                "validation",
                codes::STORAGE_8007,
            ),
            (
                "'*' in the CORS allowlist (InvalidConfig)",
                Box::new(|c| {
                    c.cors_origins = FfiCorsOrigins::Allowlist {
                        origins: vec!["*".to_owned()],
                    };
                }),
                "validation",
                codes::STORAGE_8007,
            ),
            (
                "malformed bind_addr (InvalidConfig)",
                Box::new(|c| c.bind_addr = Some("not-an-address".to_owned())),
                "validation",
                codes::STORAGE_8007,
            ),
            (
                "domain with plaintext (Node(InvalidConfig))",
                Box::new(|c| {
                    c.reach = FfiReach::Domain {
                        domain: "node.example.org".to_owned(),
                    };
                    c.tls = FfiTlsMode::Plaintext;
                }),
                "validation",
                codes::STORAGE_8007,
            ),
            (
                "blob parent under a regular file (Io)",
                Box::new({
                    let path = file.join("sub").join("blobs.redb");
                    move |c| {
                        c.blob_storage = FfiBlobBackend::Redb {
                            path: path.display().to_string(),
                        };
                    }
                }),
                "validation",
                codes::STORAGE_8008,
            ),
            (
                "redb path that is a directory (Storage)",
                Box::new({
                    let path = dir.display().to_string();
                    move |c| c.blob_storage = FfiBlobBackend::Redb { path: path.clone() }
                }),
                "validation",
                codes::STORAGE_8008,
            ),
            (
                "relay bind on a taken port (Node(Relay))",
                Box::new(move |c| c.bind_addr = Some(taken_addr.clone())),
                "transport",
                codes::TRANS_5051,
            ),
        ];

        let scp = crate::scp::Scp::new_in_memory_for_test();
        for (label, mutate, class, code) in cases {
            let identity = rt()
                .block_on(scp.identity_create("in_memory".to_owned(), None))
                .unwrap();
            let mut cfg = start_config(identity);
            mutate(&mut cfg);
            let err = start_error(rt().block_on(scp.node_start(cfg)), label);
            assert_eq!(class_and_code(&err), (class, code), "{label}: {err:?}");
        }
        drop(taken);
    }

    /// An operator identity another `Scp` minted fails the handle check with
    /// `SCP-PERM-3030` before any other step.
    #[test]
    #[cfg(feature = "testing")]
    fn node_start_rejects_another_instances_identity_with_perm_3030() {
        let minting = crate::scp::Scp::new_in_memory_for_test();
        let identity = rt()
            .block_on(minting.identity_create("in_memory".to_owned(), None))
            .unwrap();
        let other = crate::scp::Scp::new_in_memory_for_test();
        let err = start_error(
            rt().block_on(other.node_start(start_config(identity))),
            "foreign identity",
        );
        assert_eq!(
            class_and_code(&err),
            ("permission", codes::PERM_3030),
            "{err:?}"
        );
    }

    /// Asserts `result` is the transport error carrying `SCP-TRANS-5056` that
    /// a start returns while another node of the instance holds the binding,
    /// and that its message is the `NodeAlreadyBound` step's, so a 5056 from
    /// any other step, such as `RelayConnect`, fails the assertion.
    #[cfg(feature = "testing")]
    fn assert_refused_while_bound(result: Result<Arc<NodeHandle>, ScpError>, label: &str) {
        let err = match result {
            Ok(node) => {
                node.shutdown();
                panic!("{label}: a start while a running node holds the binding must fail");
            }
            Err(e) => e,
        };
        assert_eq!(
            class_and_code(&err),
            ("transport", codes::TRANS_5056),
            "{label}: {err:?}"
        );
        let ScpError::Transport { msg, .. } = &err else {
            panic!("{label}: a 5056 refusal is a transport error: {err:?}");
        };
        assert_eq!(
            *msg,
            scp_ffi_common::server::ServerError::SupervisorWiring(
                scp_ffi_common::server::SupervisorWiringError::NodeAlreadyBound,
            )
            .user_message(),
            "{label}: the refusal names NodeAlreadyBound"
        );
    }

    /// The `Supervisor` a lazy call attached to `scp`.
    #[cfg(feature = "testing")]
    fn attached_supervisor(
        scp: &crate::scp::Scp,
        call: &str,
    ) -> Arc<scp_core::context::supervisor::Supervisor> {
        Arc::clone(
            scp.inner
                .core
                .try_supervisor()
                .unwrap_or_else(|| panic!("{call} attaches a Supervisor")),
        )
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
        use crate::bridge::{
            CeilingPolicy, ContextMode, ContextParams, GovernanceModel, MemoryScope,
        };
        let scp = crate::scp::Scp::new_in_memory_for_test();
        let identity = rt()
            .block_on(scp.identity_create("in_memory".to_owned(), None))
            .unwrap();
        let params = ContextParams {
            mode: ContextMode::Encrypted,
            ceiling: vec!["messages:read".to_owned()],
            ceiling_policy: CeilingPolicy::Immutable,
            governance: GovernanceModel::SingleAdmin,
            memory_scope: MemoryScope::Ephemeral,
            ttl_seconds: 0,
            promotable: false,
            min_protocol_version: 0,
            max_chain_depth: None,
            max_nesting_depth: None,
            session_cap: None,
            economic_policy: None,
            consequence_rules_json: None,
            consequence_config_json: None,
            capability_requirements_json: None,
            pseudonym_rotation: None,
        };
        rt().block_on(scp.context_create(Arc::clone(&identity), params))
            .expect("context_create must succeed");
        let attached = attached_supervisor(&scp, "context_create");
        let core = &scp.inner.core;

        let first = rt()
            .block_on(scp.node_start_in_memory(Some(Arc::clone(&identity))))
            .expect("a start after context_create binds the attached Supervisor");
        assert!(
            Arc::ptr_eq(core.try_supervisor().unwrap(), &attached),
            "the start keeps the Supervisor context_create attached"
        );
        assert!(server::supervisor_wired_to(core, &first.inner));

        let borrowers = core.borrower_count();
        assert_refused_while_bound(
            rt().block_on(scp.node_start_in_memory(Some(Arc::clone(&identity)))),
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
            .block_on(scp.node_start_in_memory(Some(identity)))
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
        scp.configure_local_transport(identity.did()).unwrap();
        let attached = attached_supervisor(&scp, "configure_local_transport");
        let core = &scp.inner.core;

        let first = rt()
            .block_on(scp.node_start_local(dir("first"), Some(Arc::clone(&identity)), None))
            .expect("a start after configure_local_transport binds the attached Supervisor");
        assert!(Arc::ptr_eq(core.try_supervisor().unwrap(), &attached));
        assert!(server::supervisor_wired_to(core, &first.inner));

        let borrowers = core.borrower_count();
        assert_refused_while_bound(
            rt().block_on(scp.node_start_local(dir("second"), Some(Arc::clone(&identity)), None)),
            "node_start_local",
        );
        assert_eq!(core.borrower_count(), borrowers);
        assert!(server::supervisor_wired_to(core, &first.inner));

        first.shutdown();
        assert!(!server::supervisor_wired_to(core, &first.inner));
        let third = rt()
            .block_on(scp.node_start_local(dir("third"), Some(identity), None))
            .expect("a start after shutdown binds again");
        assert!(server::supervisor_wired_to(core, &third.inner));
        third.shutdown();
    }

    /// `register_local_did` attaches a `Supervisor` with an unconfigured
    /// transport and registers the DID; `node_start` then binds that same
    /// `Supervisor` to the node's relay.
    #[test]
    #[cfg(feature = "testing")]
    fn node_start_after_register_local_did_binds_the_existing_supervisor() {
        let scp = crate::scp::Scp::new_in_memory_for_test();
        let identity = rt()
            .block_on(scp.identity_create("in_memory".to_owned(), None))
            .unwrap();
        rt().block_on(scp.register_local_did(identity.did()))
            .expect("register_local_did must succeed");
        let attached = attached_supervisor(&scp, "register_local_did");

        let node = rt()
            .block_on(scp.node_start(start_config(identity)))
            .expect("a start after register_local_did binds the attached Supervisor");
        assert!(Arc::ptr_eq(
            scp.inner.core.try_supervisor().unwrap(),
            &attached
        ));
        assert!(server::supervisor_wired_to(&scp.inner.core, &node.inner));
        node.shutdown();
    }
}
