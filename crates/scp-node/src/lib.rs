#![doc = include_str!("../README.md")]
#![warn(missing_docs)]
//! Application node for SCP deployments.
//!
//! `scp-node` provides [`ApplicationNode`], a concrete SDK type that composes
//! an SCP relay, an identity, and storage into a single deployable unit. It is
//! the "one box" deployment pattern -- relay + participant + storage on one
//! machine.
//!
//! See spec section 18.6 and ADR-032 in `.docs/adrs/phase-2.md`.

#![forbid(unsafe_code)]

pub mod config;
pub mod dev_api;
pub mod dns_provider;
pub(crate) mod error;
pub mod http;
pub mod projection;
mod published_state;
mod republish;
pub mod self_host;
pub mod tls;
mod well_known;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use scp_core::store::{CURRENT_STORE_VERSION, ProtocolRepository, StoredValue};
use scp_did::DidDocument;
use scp_identity::{
    DidMethod,
    dht::{IdentityError, ScpIdentity},
};
use scp_platform::traits::{KeyCustody, Storage};
use scp_transport::nat::{NatTierChange, NetworkChangeDetector};
use scp_transport::native::server::{RelayConfig, RelayError, ShutdownHandle};
use scp_transport::native::storage::{BlobStorage as _, BlobStorageBackend};
use sha2::Digest;
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

pub(crate) use published_state::{
    LiveSlot, NodePublishedState, NodePublisher, apply_tier_change, seed_from_startup_publish,
};
// The publish seam's trait and its call-authorization token are needed only by
// test doubles (which implement `DidPublisher`) and the `NodePublisher::from_dyn`
// test constructor. Production never names them — it goes through `NodePublisher`
// and `seed_from_startup_publish` / `apply_tier_change` — so gate the re-export to
// `cfg(test)` to keep the non-test build free of an unused import.
#[cfg(test)]
pub(crate) use published_state::{DidPublisher, PublishAuthorization};

pub use http::{BoundApplicationNode, BroadcastContext};
pub use projection::{
    DeployManifest, DeployManifestEntry, PathEntry, ProjectedContext, SiteConfig,
};
pub use self_host::{
    Asset, DeploySiteParams, HostSiteConfig, HostSiteError, HostSiteReady, SelfHostDeployer,
    SelfHostError, StorageLocationError, colocated_document_vm_key_resolver, content_type_for,
    deploy_site, embedded_assets, host_site, host_site_until, routing_id_hex,
};

// `IdentitySource` / `ExplicitIdentity` now live in `config` (ADR-052 Phase
// B-P1 name reconciliation). They are consumed by `Node::start`'s identity
// lowering in `config`; the `pub use` brings them into crate-root scope for
// both that path and external consumers.
pub use config::{
    DhtMode, ExplicitIdentity, IdentitySource, NatSlot, Node, NodeConfig, PushSlot, Reach, TlsMode,
    validate_reach_and_tls,
};

// ---------------------------------------------------------------------------
// Default HTTP bind address
// ---------------------------------------------------------------------------

/// Default port for the public HTTP server (8443).
///
/// Port 8443 is the standard unprivileged HTTPS alternative port, avoiding
/// the need for root/elevated privileges required by port 443. The node
/// advertises this port, and hands it to NAT tier selection, when
/// [`NodeConfig::http_bind_addr`] is `None`.
pub const DEFAULT_HTTP_PORT: u16 = 8443;

/// Default bind address for the public HTTP server (`0.0.0.0:8443`).
///
/// This binds to **all network interfaces** (`0.0.0.0`), which is
/// appropriate for public-facing deployments where the node must be
/// reachable from external clients. Only [`ApplicationNode::serve`] and
/// [`ApplicationNode::bind`] fall back to it; the background server falls
/// back to [`DEFAULT_BACKGROUND_HTTP_BIND_ADDR`] instead.
///
/// For development or internal-only deployments, use `127.0.0.1` (loopback
/// only) via [`NodeConfig::http_bind_addr`] to avoid exposing
/// the server to the network.
pub const DEFAULT_HTTP_BIND_ADDR: SocketAddr = SocketAddr::new(
    std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
    DEFAULT_HTTP_PORT,
);

/// Default bind address for the background HTTP server (`127.0.0.1:8443`).
///
/// This binds to **loopback only** (`127.0.0.1`), which is the safe default
/// for [`ApplicationNode::serve_background`] since SDK consumers typically
/// run the node in-process and do not need external access. The background
/// server uses it only when neither the call nor
/// [`NodeConfig::http_bind_addr`] names an address, so an unset config never
/// makes it listen on every interface.
///
/// For public-facing deployments, pass a non-loopback address explicitly —
/// a warning is logged when a non-loopback address is used.
pub const DEFAULT_BACKGROUND_HTTP_BIND_ADDR: SocketAddr = SocketAddr::new(
    std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
    DEFAULT_HTTP_PORT,
);

/// Builds the in-process WebSocket URL of a relay bound at `addr`.
///
/// The URL carries the bound address itself, so a relay bound to `::1` or to a
/// LAN address is reached where it listens. An unspecified bind (`0.0.0.0` or
/// `::`) listens on every interface but is not a connectable destination, so it
/// maps to the loopback address of the same family. `SocketAddr`'s `Display`
/// brackets an IPv6 host.
#[must_use]
pub fn bound_relay_ws_url(mut addr: SocketAddr) -> String {
    if addr.ip().is_unspecified() {
        addr.set_ip(match addr.ip() {
            std::net::IpAddr::V4(_) => std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            std::net::IpAddr::V6(_) => std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
        });
    }
    format!("ws://{addr}/scp/v1")
}

/// The public HTTP address a no-domain node advertises and hands to NAT tier
/// selection.
///
/// A configured [`NodeConfig::http_bind_addr`] with port 0 asks the operating
/// system for a port, which exists only once something binds it. So
/// [`AdvertisedHttp::resolve`] binds the public TCP listener first and
/// advertises the port the system assigned, and the node later serves on that
/// listener ([`http::NodeState::take_or_bind_public`]). Any other configured
/// address advertises its own port, and no configured address advertises
/// [`DEFAULT_HTTP_PORT`]. No published URL or NAT mapping therefore names port
/// 0, which has no §9.18.2 canonical form.
struct AdvertisedHttp {
    /// The configured address, with port 0 replaced by the bound port.
    bind_addr: Option<SocketAddr>,
    /// The listener bound for a configured port 0, else `None`.
    listener: Option<tokio::net::TcpListener>,
}

impl AdvertisedHttp {
    /// Binds the public listener when `configured` requests port 0.
    ///
    /// # Errors
    ///
    /// [`NodeError::Serve`] when that bind fails or its address cannot be read.
    async fn resolve(configured: Option<SocketAddr>) -> Result<Self, NodeError> {
        match configured {
            Some(addr) if addr.port() == 0 => {
                let (listener, bound) = http::bind_public_tcp(addr).await?;
                Ok(Self {
                    bind_addr: Some(bound),
                    listener: Some(listener),
                })
            }
            bind_addr => Ok(Self {
                bind_addr,
                listener: None,
            }),
        }
    }

    /// The port the node advertises.
    fn port(&self) -> u16 {
        self.bind_addr.map_or(DEFAULT_HTTP_PORT, |addr| addr.port())
    }
}

/// The address `serve_background*` binds: the caller's `requested` address,
/// else the configured [`NodeConfig::http_bind_addr`], else loopback
/// [`DEFAULT_BACKGROUND_HTTP_BIND_ADDR`] — never `0.0.0.0` by default.
fn background_bind_addr(
    requested: Option<SocketAddr>,
    configured: Option<SocketAddr>,
) -> SocketAddr {
    requested
        .or(configured)
        .unwrap_or(DEFAULT_BACKGROUND_HTTP_BIND_ADDR)
}

// ---------------------------------------------------------------------------
// Resource limits
// ---------------------------------------------------------------------------

/// Maximum number of broadcast contexts that can be registered per node.
///
/// Enforced in both the SDK API ([`ApplicationNode::register_broadcast_context`])
/// and the dev API (`POST /scp/dev/v1/contexts`). Prevents unbounded `HashMap`
/// growth from registration floods.
pub(crate) const MAX_BROADCAST_CONTEXTS: usize = 1024;

/// Default per-IP rate limit for broadcast projection endpoints (requests per second).
///
/// Configurable via `SCP_NODE_PROJECTION_RATE_LIMIT` env var or
/// [`NodeConfig::projection_rate_limit`].
///
/// See spec section 18.11.6.
pub const DEFAULT_PROJECTION_RATE_LIMIT: u32 = 60;

// ---------------------------------------------------------------------------
// Public HTTP surface selection
// ---------------------------------------------------------------------------

/// Selects which routes the public HTTP listener exposes when serving.
///
/// The default run modes (relay-only, persistent, ephemeral) serve the
/// [`Full`](PublicSurface::Full) protocol surface. The `--self-host`
/// website-hosting mode serves the restricted [`SelfHost`](PublicSurface::SelfHost)
/// surface so the public bind exposes only the read-only website projection
/// and never the relay upgrade (§10.12.8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublicSurface {
    /// Full protocol surface: `.well-known/scp`, the `/scp/v1` relay
    /// WebSocket upgrade, broadcast projection (`/scp/broadcast/*`), ACME
    /// challenges, and the virtual-host fallback. Used by every run mode
    /// except `--self-host`.
    Full,
    /// Restricted website surface for `--self-host`: `.well-known/scp`, the
    /// broadcast projection endpoints (`/scp/broadcast/*`, including
    /// `/feed`, `/messages`, and `/site`), and the virtual-host fallback —
    /// and nothing else. The relay upgrade/bridge (`/scp/v1`) is NOT mounted,
    /// so an anonymous internet client cannot reach the node's relay or bridge
    /// through the public bind.
    SelfHost,
}

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// Errors produced by [`ApplicationNode`] construction and operation.
#[derive(Debug, thiserror::Error)]
pub enum NodeError {
    /// The builder is missing a required field.
    #[error("missing required field: {0}")]
    MissingField(&'static str),

    /// An identity operation (create, publish) failed.
    #[error("identity error: {0}")]
    Identity(#[from] IdentityError),

    /// The relay server failed to start.
    #[error("relay error: {0}")]
    Relay(#[from] RelayError),

    /// A storage operation failed.
    #[error("storage error: {0}")]
    Storage(String),

    /// An invalid configuration value was provided.
    #[error("invalid configuration: {0}")]
    InvalidConfig(String),

    /// The HTTP server failed to bind or encountered a fatal I/O error.
    #[error("serve error: {0}")]
    Serve(String),

    /// NAT traversal failed during zero-config deployment.
    #[error("NAT traversal error: {0}")]
    Nat(String),

    /// TLS provisioning failed.
    #[error("TLS error: {0}")]
    Tls(#[from] tls::TlsError),
}

// ---------------------------------------------------------------------------
// RelayHandle
// ---------------------------------------------------------------------------

/// Handle to the running relay server.
///
/// Wraps the bound address, shutdown handle, and provides access to the
/// relay's state. The relay accepts connections from any SCP client (spec
/// section 18.6.4).
#[derive(Debug)]
pub struct RelayHandle {
    /// The local address the relay is bound to.
    bound_addr: SocketAddr,
    /// Handle for gracefully shutting down the relay server.
    shutdown_handle: ShutdownHandle,
}

impl RelayHandle {
    /// Returns the local address the relay server is bound to.
    #[must_use]
    pub const fn bound_addr(&self) -> SocketAddr {
        self.bound_addr
    }

    /// Returns a reference to the relay's shutdown handle.
    #[must_use]
    pub const fn shutdown_handle(&self) -> &ShutdownHandle {
        &self.shutdown_handle
    }
}

/// Holds a started relay's [`ShutdownHandle`] while `Node::start` finishes,
/// and shuts the relay down if the build fails before an [`ApplicationNode`]
/// takes the handle.
///
/// Dropping a bare `ShutdownHandle` leaves the relay serving, so every `?`
/// between starting the relay and returning the node would leak a listener on
/// `bind_addr`. The builder moves the guard through every fallible step and
/// calls [`disarm`](Self::disarm) only when it builds the `ApplicationNode`.
#[derive(Debug)]
pub(crate) struct RelayShutdownGuard {
    handle: ShutdownHandle,
    armed: bool,
}

impl RelayShutdownGuard {
    /// Guards the relay `handle` shuts down.
    pub(crate) const fn new(handle: ShutdownHandle) -> Self {
        Self {
            handle,
            armed: true,
        }
    }

    /// Hands the relay to its owner: the guard no longer shuts it down.
    pub(crate) fn disarm(mut self) -> ShutdownHandle {
        self.armed = false;
        self.handle.clone()
    }
}

impl Drop for RelayShutdownGuard {
    fn drop(&mut self) {
        if self.armed {
            tracing::info!("node start failed after the relay started; shutting the relay down");
            self.handle.shutdown();
        }
    }
}

// ---------------------------------------------------------------------------
// IdentityHandle
// ---------------------------------------------------------------------------

/// Handle to the node's DID identity.
///
/// Provides access to the [`ScpIdentity`] and the published [`DidDocument`].
/// The identity is a full SCP identity -- it can create contexts, join
/// contexts, and send messages (spec section 18.6.4).
#[derive(Debug)]
pub struct IdentityHandle {
    /// The SCP identity containing key handles and DID string.
    identity: ScpIdentity,
    /// The node's live published-state slot, never an independent copy. See
    /// [`LiveSlot`].
    live_state: LiveSlot<NodePublishedState>,
}

impl IdentityHandle {
    /// Binds an identity to the node's live published-state slot.
    pub(crate) const fn new(
        identity: ScpIdentity,
        live_state: LiveSlot<NodePublishedState>,
    ) -> Self {
        Self {
            identity,
            live_state,
        }
    }

    /// Returns a reference to the underlying [`ScpIdentity`].
    #[must_use]
    pub const fn identity(&self) -> &ScpIdentity {
        &self.identity
    }

    /// Returns the DID string for this identity.
    #[must_use]
    pub fn did(&self) -> &str {
        &self.identity.did
    }

    /// Returns the [`DidDocument`] the node currently stands behind.
    ///
    /// By value rather than by reference precisely because it can change: a
    /// `&DidDocument` would either pin the document for the borrow's lifetime or
    /// hand back a build-time copy. (No intra-doc link: the slot type is
    /// crate-private, like the `NodeState` field it lives on.)
    #[must_use]
    pub fn document(&self) -> DidDocument {
        self.live_state.get().document
    }
}

// ---------------------------------------------------------------------------
// ApplicationNode
// ---------------------------------------------------------------------------

/// A complete SCP application node composing relay, identity, and storage.
///
/// Created via [`Node::start`](crate::Node::start) for production use, or via
/// [`ApplicationNode::dev`] for quick development/demo setups (requires the
/// `allow_unencrypted_storage` feature).
///
/// The node starts a relay server, publishes the identity's DID document
/// with `SCPRelay` service entries, and provides accessors for each
/// component.
///
/// The relay accepts connections from any SCP client, not just the local
/// identity. DID publication happens once on `.build()`, not continuously
/// (spec section 18.6.4).
///
/// The type parameter `S` is the platform storage backend (e.g.,
/// `InMemoryStorage` for testing, `SqliteStorage` for production).
///
/// See spec section 18.6 for the full design.
pub struct ApplicationNode<S: Storage> {
    /// The domain this node serves. `None` for zero-config no-domain mode (§10.12.8).
    domain: Option<String>,
    /// Handle to the running relay server.
    relay: RelayHandle,
    /// Handle to the node's identity.
    identity: IdentityHandle,
    /// The protocol repository wrapping the storage backend.
    storage: Arc<ProtocolRepository<S>>,
    /// Shared state for HTTP handlers (`.well-known/scp`, relay bridge).
    state: Arc<http::NodeState>,
    /// Handle to the periodic tier re-evaluation background task (§10.12.1, SCP-243).
    /// `None` in domain mode with successful TLS (Tier 4 doesn't need NAT re-eval).
    tier_reeval: Option<TierReEvalHandle>,
    /// Channel for tier change events (§10.12.1, SCP-243).
    ///
    /// A bounded `mpsc` whose sender uses `try_send` (see `apply_tier_change`),
    /// so it drops the NEWEST event on a full queue rather than the oldest —
    /// technically the wrong end for a latest-value "where am I now" stream, for
    /// which `tokio::sync::watch` would be the semantically-correct primitive.
    /// It is kept as `mpsc` deliberately: no production consumer drains this
    /// stream (the authoritative surfaces — `.well-known/scp`, the DID document,
    /// `relay_url()` — never depend on it), so the drop-newest gap is
    /// inconsequential, and the `try_send` is what keeps the tier task from
    /// wedging on a full queue in the first place (see `apply_tier_change`). A
    /// `watch` swap would wrap the variant-only `NatTierChange` in `Option` for
    /// an initial value and rewrite the send block plus every test, buying
    /// nothing while no consumer exists. Revisit the primitive if a real
    /// draining consumer is ever added.
    tier_change_rx: Option<tokio::sync::mpsc::Receiver<NatTierChange>>,
    /// HTTP/3 configuration for the QUIC-based HTTP/3 endpoint (spec §10.15.1).
    /// `None` if HTTP/3 is not configured. Only available with the `http3` feature.
    #[cfg(feature = "http3")]
    http3_config: Option<scp_transport::http3::Http3Config>,
    /// Whether the background HTTP server is currently running.
    /// Used by [`serve_background`](Self::serve_background) to prevent double-serve.
    /// Wrapped in `Arc` so the spawned background task can clear it on exit.
    serving: Arc<AtomicBool>,
    /// Whether the projection rate-limit cleanup task has been spawned.
    /// Guards against duplicate cleanup tasks on restart.
    rate_limit_cleanup_spawned: Arc<AtomicBool>,
    /// The bound address of the background HTTP server, if running.
    /// Set by [`serve_background`](Self::serve_background) after successful bind.
    /// Wrapped in `Arc` so the spawned background task can clear it on exit.
    serving_addr: Arc<tokio::sync::Mutex<Option<SocketAddr>>>,
    /// The node's self-DID republish cycle (ADR-003 §2, §3.10.5 step 4).
    ///
    /// Not an `Option`: every node has exactly one, because only a builder can
    /// construct an `ApplicationNode` and both builders fill this field. A
    /// Mainline DHT record that nothing re-puts expires, so a node without a
    /// cycle is a node whose DID document stops resolving. The cycle is dormant
    /// (zero arms) while the node has published nothing — which is the permanent
    /// state of a [`DhtMode::Disabled`] node — and it seeds itself the moment the
    /// node publishes. See [`republish`].
    ///
    /// `Arc<dyn RepublishCycle>` erases the DHT client type the builder's
    /// `DidMethod` supplies, which `ApplicationNode<S>` does not carry.
    /// [`shutdown`](Self::shutdown) stops it; dropping the node without calling
    /// `shutdown` reaches the cycle's own `Drop` backstop.
    republish: Arc<dyn republish::RepublishCycle>,
}

impl<S: Storage + std::fmt::Debug> std::fmt::Debug for ApplicationNode<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApplicationNode")
            .field("domain", &self.domain)
            .field("relay", &self.relay)
            .field("identity", &self.identity)
            .field("storage", &"<Storage>")
            .field(
                "tier_reeval",
                &self.tier_reeval.as_ref().map(|_| "<active>"),
            )
            .field("serving", &self.serving.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

impl<S: Storage> ApplicationNode<S> {
    /// Returns the domain this node serves.
    ///
    /// Returns `None` in zero-config no-domain mode (§10.12.8).
    #[must_use]
    pub fn domain(&self) -> Option<&str> {
        self.domain.as_deref()
    }

    /// The signed BEP44 DID record this node has most recently published
    /// (§3.10.5).
    ///
    /// `None` when the node has published nothing — the `DhtMode::Disabled`
    /// fail-safe default. That absence is protocol-supported and detectable;
    /// callers MUST NOT synthesize a record in its place.
    ///
    /// The value is the output of this node's own signing pass, so a caller never
    /// has to reconstruct the `(value, signature, seq)` triple by reading it back
    /// off the network.
    ///
    /// This is a **snapshot**: a NAT tier change re-publishes the document with a
    /// new sequence, after which this returns the newer record. The node's own
    /// republish cycle takes a live view of the slot instead of a snapshot, so
    /// it follows every re-publish (see the crate-private `republish` module).
    #[must_use]
    pub fn published_did_record(&self) -> Option<scp_identity::republish::RepublishEntry> {
        self.state.live_state.get().record
    }

    /// Returns a reference to the relay handle.
    #[must_use]
    pub const fn relay(&self) -> &RelayHandle {
        &self.relay
    }

    /// Returns a reference to the identity handle.
    #[must_use]
    pub const fn identity(&self) -> &IdentityHandle {
        &self.identity
    }

    /// Returns a reference to the protocol repository.
    #[must_use]
    pub fn storage(&self) -> &ProtocolRepository<S> {
        &self.storage
    }

    /// Returns the relay URL the node is currently reachable at — the one it
    /// publishes in its DID document and serves from `.well-known/scp`.
    ///
    /// For domain mode: `wss://<domain>/scp/v1` (spec section 18.5.2).
    /// For no-domain mode: the address of the current reachability tier, which a
    /// NAT tier change (§10.12.1) advances.
    ///
    /// Returned by value rather than as `&str` precisely because it can change:
    /// this reads the node's live state slot per call, and a borrow cannot escape
    /// that slot. (No intra-doc link: the slot type is crate-private, like the
    /// `NodeState` field it lives on.)
    #[must_use]
    pub fn relay_url(&self) -> String {
        self.state.live_state.get().relay.url().to_owned()
    }

    /// Returns the TLS certificate resolver for ACME hot-reload.
    ///
    /// Returns `Some` in domain mode when TLS is active, `None` in
    /// no-domain mode. The ACME renewal loop should call
    /// [`CertResolver::update`](tls::CertResolver::update) on the
    /// returned resolver to hot-swap certificates without restarting
    /// the server.
    ///
    /// See spec section 18.6.3 (auto-renewal).
    #[must_use]
    pub fn cert_resolver(&self) -> Option<&Arc<tls::CertResolver>> {
        self.state.cert_resolver.as_ref()
    }

    /// Registers a broadcast context so it appears in subsequent
    /// `GET /.well-known/scp` responses.
    ///
    /// Only broadcast contexts may be registered (spec section 18.3
    /// privacy constraints). Encrypted context IDs MUST NOT be exposed.
    ///
    /// # Limits
    ///
    /// A maximum of `MAX_BROADCAST_CONTEXTS` simultaneous broadcast
    /// contexts may be registered per node.
    ///
    /// # Errors
    ///
    /// Returns [`NodeError::InvalidConfig`] if the context ID is empty,
    /// exceeds 64 characters, contains non-hex characters, or the broadcast
    /// context limit has been reached.
    pub async fn register_broadcast_context(
        &self,
        id: String,
        name: Option<String>,
    ) -> Result<(), NodeError> {
        // Validate: non-empty, hex-only, max 64 chars (32 bytes hex-encoded).
        if id.is_empty() || id.len() > 64 {
            return Err(NodeError::InvalidConfig(
                "context id must be 1-64 hex characters".into(),
            ));
        }
        if !id.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(NodeError::InvalidConfig(
                "context id must contain only hex characters".into(),
            ));
        }
        let id = id.to_ascii_lowercase();
        let mut contexts = self.state.broadcast_contexts.write().await;
        if !contexts.contains_key(&id) && contexts.len() >= MAX_BROADCAST_CONTEXTS {
            return Err(NodeError::InvalidConfig(format!(
                "broadcast context limit ({MAX_BROADCAST_CONTEXTS}) reached",
            )));
        }
        contexts.insert(id.clone(), BroadcastContext { id, name });
        drop(contexts);
        Ok(())
    }

    /// Returns the hex-encoded bridge secret for the internal relay.
    ///
    /// This is the token that must be included as an
    /// `Authorization: Bearer <hex>` header when connecting directly to
    /// the relay's bound address. Used by tests that bypass the axum
    /// bridge layer.
    ///
    /// **Security:** This value is a secret. Do not log or expose it.
    #[must_use]
    pub fn bridge_token_hex(&self) -> Zeroizing<String> {
        Zeroizing::new(scp_transport::native::server::hex_encode_32(
            &self.state.bridge_secret,
        ))
    }

    /// Returns the dev API bearer token if the dev API is enabled.
    ///
    /// Returns `Some` when [`NodeConfig::local_api`] was called,
    /// `None` otherwise. The token format is `scp_local_token_<32 hex chars>`.
    ///
    /// See spec section 18.10.2.
    #[must_use]
    pub fn dev_token(&self) -> Option<&str> {
        self.state.dev_token.as_deref()
    }

    /// Gracefully shuts down the relay server and the tier re-evaluation
    /// background task (§10.12.1, SCP-243).
    ///
    /// Signals the relay server, the public HTTPS listener, and the dev API
    /// listener (if running) to stop accepting new connections. In-flight
    /// connection handlers drain naturally -- they are not cancelled. A public
    /// listener `Node::start` bound for a port-0 `http_bind_addr` and no serve
    /// took is closed, so the advertised port refuses connections.
    ///
    /// The tier re-evaluation task is stopped. When the node was built on a
    /// multi-thread runtime and the caller is off any runtime or on a
    /// multi-thread worker, this blocks, up to a deadline, on the task's
    /// `JoinHandle`, which tokio completes only after the task's future has been
    /// dropped. When the join completes, the `DidMethod`/`KeyCustody` `Arc`
    /// clones the republish path captured are released before this returns, so
    /// the custody backend's `SqliteStorage` advisory lock is free and a caller
    /// can immediately re-open the same storage path (e.g. a node restart over a
    /// persisted identity) without racing the background task's teardown. At
    /// the deadline the task is aborted instead. If the runtime is shutting
    /// down, the wait can end before the task's future drops; that case is
    /// logged at warn. A caller on a `current_thread` runtime gets only an
    /// abort.
    /// Absent the join the task could still hold the custody
    /// handle for a short, nondeterministic window after `shutdown()` returned,
    /// intermittently failing the next open with an advisory-lock conflict. See
    /// [`TierReEvalHandle::stop_and_wait`].
    ///
    /// See SCP-245: "Ensure graceful shutdown of dev API listener alongside
    /// main server."
    pub fn shutdown(&self) {
        self.relay.shutdown_handle.shutdown();
        self.state.shutdown_token.cancel();
        // After the cancel, so a serve whose bind fails cannot restore it.
        self.state.close_prebound_public();
        if let Some(ref handle) = self.tier_reeval {
            handle.stop_and_wait();
        }
        // Both republish arms stop here. An arm that outlived shutdown would
        // keep re-putting this node's address on the DHT for the life of the
        // process — the §10.12.1 disclosure past shutdown.
        self.republish.stop_and_wait();
    }

    /// How many republish arms this node is running, per layer.
    ///
    /// Crate-internal: the counts exist so the node's own tests can assert that
    /// exactly one cycle runs and that it covers both layers (§3.10.6).
    ///
    /// The `testing` feature gates this method for the same reason it gates the
    /// `ActiveArms` counts it returns: every test that calls it starts its node
    /// in the `Memory` variant of `DhtMode`, which compiles only under that
    /// feature.
    #[cfg(all(test, feature = "testing"))]
    pub(crate) async fn active_republish_arms(&self) -> republish::ActiveArms {
        self.republish.active_arms().await
    }

    /// Returns a clone of the node's graceful-shutdown cancellation token.
    ///
    /// The token is cancelled by [`shutdown`](Self::shutdown) (and when a
    /// [`serve`](Self::serve)/[`serve_background`](Self::serve_background) loop
    /// completes). Background tasks that should stop when the node stops — for
    /// example a self-host site refresh loop — can observe this token to exit
    /// cleanly without racing the listener teardown.
    #[must_use]
    pub fn shutdown_token(&self) -> CancellationToken {
        self.state.shutdown_token.clone()
    }

    /// Builds the merged SCP protocol router for the requested
    /// [`PublicSurface`].
    ///
    /// [`PublicSurface::Full`] exposes the complete protocol surface:
    /// `.well-known/scp`, the `/scp/v1` relay WebSocket upgrade, the broadcast
    /// projection endpoints (`/scp/broadcast/*`), ACME challenges, and the
    /// virtual-host fallback.
    ///
    /// [`PublicSurface::SelfHost`] exposes ONLY the read-only website surface:
    /// `.well-known/scp`, the broadcast projection endpoints, and the
    /// virtual-host fallback. The relay upgrade/bridge (`/scp/v1`) is
    /// deliberately NOT mounted — in
    /// self-host mode the node's loopback relay is reached in-process over
    /// `127.0.0.1` and must never be exposed to anonymous internet clients on
    /// the public bind (§10.12.8; exposing `/scp/v1` would let an anonymous
    /// external client publish/subscribe/query/delete on the node's relay,
    /// carrying the node's own bridge bearer token, with every external client
    /// collapsed to `127.0.0.1` for per-IP limits — a site-takedown and
    /// metadata-exfiltration vector).
    fn build_scp_router_with_surface(
        &self,
        app_router: axum::Router,
        surface: PublicSurface,
    ) -> axum::Router {
        let cors = http::build_cors_layer(&self.state.cors_origins);
        let well_known = http::well_known_router(Arc::clone(&self.state)).layer(cors.clone());
        let projection =
            crate::projection::broadcast_projection_router(Arc::clone(&self.state)).layer(cors);

        match surface {
            PublicSurface::Full => {
                let relay_rt = http::relay_router(Arc::clone(&self.state));
                http::build_merged_router(app_router, well_known, relay_rt, projection, &self.state)
            }
            PublicSurface::SelfHost => {
                http::build_self_host_router(app_router, well_known, projection, &self.state)
            }
        }
    }

    /// Returns the HTTP URL of the background server, if running.
    ///
    /// Returns the literal bind address, which may contain `0.0.0.0` if the
    /// server was bound to the unspecified address. Callers should replace
    /// `0.0.0.0` with the appropriate interface address when constructing
    /// user-facing URLs.
    ///
    /// Returns `Some("http://<addr>")` when [`serve_background`](Self::serve_background)
    /// has been called and the server is actively listening. Returns `None`
    /// if the background server has not been started.
    pub async fn http_url(&self) -> Option<String> {
        let guard = self.serving_addr.lock().await;
        guard.map(|addr| format!("http://{addr}"))
    }

    /// Designates a single projected context as the **default site** served at
    /// the origin root (`--self-host` mode, §10.12.8).
    ///
    /// After this is set, the public listener's virtual-host fallback serves
    /// bare-path requests (`GET /`, `GET /style.css`, `GET /<anything>`) from
    /// this routing ID's projected site whenever the request `Host` header does
    /// not match a registered site hostname — including raw-IP access, where no
    /// `Host` matches. The bare path passes through the same
    /// [`site_handler`](crate::projection::site_handler) the explicit
    /// `/scp/broadcast/<rid>/site/...` route uses, so `ContentPath` traversal
    /// protection, decryption, `ETag`, `Cache-Control`, and CSP all still apply,
    /// and `/` maps to the site's configured `index_path`.
    ///
    /// `routing_id` must be `SHA-256(context_id)` for a context that has been
    /// projected with a site config (e.g. via
    /// [`enable_broadcast_projection_with_site`](Self::enable_broadcast_projection_with_site));
    /// the value is exactly [`projection::compute_routing_id`]. If the
    /// designated context is not (yet) projected, the fallback simply 404s
    /// until it is — no panic, no broken state.
    ///
    /// Intended for the single-site self-host surface. The Full protocol
    /// surface never sets this, so origin-root serving is a self-host-only
    /// behavior.
    pub fn set_default_site_routing_id(&self, routing_id: [u8; 32]) {
        match self.state.default_site_routing_id.write() {
            Ok(mut guard) => *guard = Some(routing_id),
            Err(poisoned) => {
                // A poisoned lock means a prior writer panicked while holding
                // it — recover the guard and overwrite rather than propagate,
                // since the stored value is a plain `Option<[u8; 32]>` with no
                // invariant a panic could have left half-updated.
                *poisoned.into_inner() = Some(routing_id);
            }
        }
    }

    /// Starts serving HTTP traffic in a background tokio task.
    ///
    /// Unlike [`serve`](Self::serve), this method does **not** consume the
    /// node. It clones the shared `NodeState` and the cancellation token,
    /// spawns the full merged router in a background task, and returns the
    /// bound address.
    ///
    /// ## Bind address
    ///
    /// When `bind_addr` is `None`, binds the configured
    /// [`NodeConfig::http_bind_addr`], or `127.0.0.1:8443` (loopback only,
    /// never `0.0.0.0`) when none is configured. A `tracing::warn!` is
    /// emitted when a non-loopback address is used, since exposing the HTTP server to the network may have
    /// security implications.
    ///
    /// ## TLS
    ///
    /// The background server does **not** use TLS — all HTTP traffic is
    /// plaintext. For production deployments requiring encryption, use the
    /// node binary's [`serve`](Self::serve) method with TLS configuration.
    ///
    /// ## Dev API
    ///
    /// The dev API listener (spec §18.10) is intentionally **not** spawned
    /// by this method. It is designed for the node binary's `serve()` flow,
    /// not for SDK consumers using `serve_background()`.
    ///
    /// ## Double-serve prevention
    ///
    /// Calling this method more than once returns an error without starting
    /// a second listener.
    ///
    /// ## Shutdown
    ///
    /// The spawned task observes the node's cancellation token. Calling
    /// [`shutdown`](Self::shutdown) stops both the relay and the background
    /// HTTP server.
    ///
    /// # Errors
    ///
    /// Returns [`NodeError::Serve`] if:
    /// - The node has already been shut down.
    /// - The server is already running (double-serve).
    /// - The TCP listener cannot bind.
    /// - The bound address cannot be retrieved.
    pub async fn serve_background(
        &self,
        bind_addr: Option<SocketAddr>,
    ) -> Result<SocketAddr, NodeError> {
        self.serve_background_with_surface(bind_addr, PublicSurface::Full)
            .await
    }

    /// Like [`serve_background`](Self::serve_background) but restricts the
    /// public HTTP surface to the requested [`PublicSurface`].
    ///
    /// [`PublicSurface::SelfHost`] mounts ONLY the read-only website
    /// projection surface (`.well-known/scp`, `/scp/broadcast/*`, and the
    /// virtual-host fallback) — the relay upgrade (`/scp/v1`) is not exposed
    /// on the background listener
    /// (§10.12.8). All other behavior (no TLS, no dev API, double-serve
    /// prevention, shutdown via the node's cancellation token) is identical to
    /// [`serve_background`](Self::serve_background).
    ///
    /// # Errors
    ///
    /// Returns [`NodeError::Serve`] under the same conditions as
    /// [`serve_background`](Self::serve_background).
    pub async fn serve_background_with_surface(
        &self,
        bind_addr: Option<SocketAddr>,
        surface: PublicSurface,
    ) -> Result<SocketAddr, NodeError> {
        self.serve_background_with_surface_tls(bind_addr, surface, None)
            .await
    }

    /// Like [`serve_background_with_surface`](Self::serve_background_with_surface)
    /// but optionally terminates TLS with a caller-supplied
    /// `rustls::ServerConfig`.
    ///
    /// When `tls_config` is `Some`, the background listener speaks HTTPS/WSS
    /// using [`tls::serve_tls`] (TLS 1.3, HTTP/1.1+HTTP/2 auto-detect, and
    /// per-connection `ConnectInfo` for rate limiting). When `None`, it serves
    /// plaintext HTTP exactly as
    /// [`serve_background_with_surface`](Self::serve_background_with_surface).
    ///
    /// This is the seam the `--self-host` binary uses to serve a self-signed
    /// certificate (the "be your own CA" no-DNS model, §10.12.11): the cert's
    /// SANs depend on the node's external/LAN IP, which is only known after
    /// `build()`, so the config is constructed at serve time and injected here
    /// rather than baked into [`NodeState`](crate::http::NodeState)'s `tls_config` (which stays `None`
    /// in no-domain mode). TLS is purely what is spoken on the bound TCP port;
    /// the NAT/port-mapping behavior is unchanged.
    ///
    /// # Errors
    ///
    /// Returns [`NodeError::Serve`] under the same conditions as
    /// [`serve_background_with_surface`](Self::serve_background_with_surface).
    pub async fn serve_background_with_surface_tls(
        &self,
        bind_addr: Option<SocketAddr>,
        surface: PublicSurface,
        tls_config: Option<Arc<rustls::ServerConfig>>,
    ) -> Result<SocketAddr, NodeError> {
        self.claim_background_serve()?;

        let addr = background_bind_addr(bind_addr, self.state.http_bind_addr);

        // Security: warn when binding a *plaintext* listener to a non-loopback
        // address. When a TLS config is present (self-host self-signed cert),
        // traffic is encrypted, so the "unencrypted" warning would be wrong.
        if !addr.ip().is_loopback() && tls_config.is_none() {
            tracing::warn!(
                bind_addr = %addr,
                "serve_background binding to non-loopback address — \
                 HTTP traffic is unencrypted (no TLS) and will be \
                 accessible from the network"
            );
        }

        // Bind the TCP listener before spawning so we can report errors
        // and the bound address synchronously.
        // A node that advertised the port of a listener it bound at start
        // serves on that listener.
        // Nothing after the take can fail, so a taken pre-bound listener is
        // always served.
        let (listener, local_addr) =
            self.state
                .take_or_bind_public(addr)
                .await
                .inspect_err(|_| {
                    // Reset serving flag on bind failure.
                    self.serving.store(false, Ordering::SeqCst);
                })?;
        self.spawn_background_server(listener, local_addr, surface, tls_config)
            .await
    }

    /// Serves the public surface in the background on a listener the caller
    /// already bound, returning the listener's local address.
    ///
    /// [`crate::self_host::host_site_until`] binds its public listener before it
    /// builds the node, so a `port` of 0 resolves to the OS-assigned port that
    /// the node's configuration, NAT mapping, and ready signal all report.
    ///
    /// # Errors
    ///
    /// The same as [`Self::serve_background_with_surface_tls`], except that no
    /// bind happens here.
    pub(crate) async fn serve_background_on_listener(
        &self,
        listener: tokio::net::TcpListener,
        surface: PublicSurface,
        tls_config: Option<Arc<rustls::ServerConfig>>,
    ) -> Result<SocketAddr, NodeError> {
        self.claim_background_serve()?;
        let local_addr = listener.local_addr().map_err(|e| {
            self.serving.store(false, Ordering::SeqCst);
            NodeError::Serve(format!("failed to get local address: {e}"))
        })?;
        self.spawn_background_server(listener, local_addr, surface, tls_config)
            .await
    }

    /// Rejects a background serve on a shut-down node and claims the
    /// single-serve flag. The caller resets the flag on a later failure.
    fn claim_background_serve(&self) -> Result<(), NodeError> {
        // Reject if the node has already been shut down — the cancellation
        // token is already cancelled so the server would exit immediately.
        if self.state.shutdown_token.is_cancelled() {
            return Err(NodeError::Serve(
                "node has been shut down; cannot start background HTTP server".into(),
            ));
        }

        // Prevent double-serve.
        if self
            .serving
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return Err(NodeError::Serve(
                "background HTTP server is already running".into(),
            ));
        }

        Ok(())
    }

    /// Spawns the background server on a bound listener whose address the
    /// caller read. The caller holds the single-serve flag.
    async fn spawn_background_server(
        &self,
        listener: tokio::net::TcpListener,
        local_addr: SocketAddr,
        surface: PublicSurface,
        tls_config: Option<Arc<rustls::ServerConfig>>,
    ) -> Result<SocketAddr, NodeError> {
        let shutdown_token = self.state.shutdown_token.clone();

        // Build the merged router for the requested public surface.
        let merged = self.build_scp_router_with_surface(axum::Router::new(), surface);

        // Store the bound address.
        {
            let mut guard = self.serving_addr.lock().await;
            *guard = Some(local_addr);
        }

        // Spawn the projection rate limiter cleanup only after a successful
        // bind — avoids leaking a background task on bind failure, and guards
        // against duplicate tasks if serve_background is called more than once.
        if self
            .rate_limit_cleanup_spawned
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            http::spawn_projection_rate_limit_cleanup(
                self.state.projection_rate_limiter.clone(),
                shutdown_token.clone(),
            );
        }

        let serving_flag = Arc::clone(&self.serving);
        let serving_addr_ref = Arc::clone(&self.serving_addr);

        // Spawn the background server task. When a TLS config is supplied
        // (self-host self-signed cert), terminate TLS via `tls::serve_tls`;
        // otherwise serve plaintext HTTP. Both honor the graceful-shutdown
        // token and clear the serving flag/address on exit.
        tokio::spawn(async move {
            let scheme = if tls_config.is_some() {
                "HTTPS"
            } else {
                "HTTP"
            };
            tracing::info!(
                addr = %local_addr,
                scheme,
                "background HTTP server started"
            );

            let result = if let Some(tls_cfg) = tls_config {
                tls::serve_tls(listener, tls_cfg, merged, shutdown_token.clone())
                    .await
                    .map_err(|e| match e {
                        NodeError::Serve(msg) => std::io::Error::other(msg),
                        other => std::io::Error::other(other.to_string()),
                    })
            } else {
                axum::serve(
                    listener,
                    merged.into_make_service_with_connect_info::<std::net::SocketAddr>(),
                )
                .with_graceful_shutdown(shutdown_token.cancelled_owned())
                .await
            };

            if let Err(ref e) = result {
                tracing::error!(error = %e, "background HTTP server exited with error");
            } else {
                tracing::info!("background HTTP server shut down");
            }

            // Clear the serving flag and address on exit.
            serving_flag.store(false, Ordering::SeqCst);
            let mut guard = serving_addr_ref.lock().await;
            *guard = None;
        });

        Ok(local_addr)
    }

    /// Returns a mutable reference to the tier change event receiver
    /// (§10.12.1, SCP-243).
    ///
    /// The receiver yields [`NatTierChange::TierChanged`] events when the
    /// periodic re-evaluation loop detects a tier change. Returns `None`
    /// if the node is in domain mode with successful TLS (Tier 4).
    pub const fn tier_change_rx(
        &mut self,
    ) -> Option<&mut tokio::sync::mpsc::Receiver<NatTierChange>> {
        self.tier_change_rx.as_mut()
    }

    /// Maximum number of simultaneously projected broadcast contexts per node.
    const MAX_PROJECTED_CONTEXTS: usize = 1024;

    /// Activates HTTP broadcast projection for the given context.
    ///
    /// Computes `routing_id = SHA-256(context_id)` per spec section 5.14.6,
    /// then creates or updates a [`ProjectedContext`] in the node's projected
    /// contexts registry. If the context is already projected, the broadcast
    /// key is inserted at its epoch (previous epochs are retained for the
    /// blob TTL window).
    ///
    /// Once enabled, the node's HTTP endpoints serve decrypted broadcast
    /// content at `/scp/broadcast/<routing_id_hex>/feed` and
    /// `/scp/broadcast/<routing_id_hex>/messages/<blob_id_hex>`.
    ///
    /// The `admission` mode and optional `projection_policy` are stored on the
    /// [`ProjectedContext`] so that projection handlers can enforce
    /// authentication requirements per spec section 18.11.2.1. If the context
    /// is already projected, the key is added and `admission`/`projection_policy`
    /// are updated (use this to propagate governance `ModifyCeiling` changes).
    ///
    /// See spec sections 18.11.2 and 18.11.8.
    ///
    /// # Limits
    ///
    /// A maximum of 1024 simultaneous projected contexts may be registered
    /// per node. Returns [`NodeError::InvalidConfig`] if the limit is
    /// exceeded.
    ///
    /// # Errors
    ///
    /// Returns [`NodeError::InvalidConfig`] if:
    /// - The projected context limit (1024) has been reached.
    /// - A gated context has a `Public` default projection rule (violates
    ///   spec section 18.11.2.1: gated contexts cannot have public projection).
    /// - A gated context has a `Public` per-author projection override.
    pub async fn enable_broadcast_projection(
        &self,
        context_id: &str,
        broadcast_key: scp_core::crypto::sender_keys::BroadcastKey,
        admission: scp_core::context::broadcast::BroadcastAdmission,
        projection_policy: Option<scp_core::context::params::ProjectionPolicy>,
    ) -> Result<(), NodeError> {
        self.enable_broadcast_projection_with_site(
            context_id,
            broadcast_key,
            admission,
            projection_policy,
            None,
        )
        .await
    }

    /// Activates HTTP broadcast projection with optional site configuration.
    ///
    /// Like [`enable_broadcast_projection`](Self::enable_broadcast_projection) but
    /// additionally accepts a [`SiteConfig`] for path-based serving (§18.11.12).
    ///
    /// When `site_config` is `Some`, validates the hostname (RFC 1123, not the
    /// node's own hostname, no duplicates) and `deploy_retention_count` (<= 8).
    ///
    /// # Errors
    ///
    /// Returns [`NodeError::InvalidConfig`] if validation fails.
    pub async fn enable_broadcast_projection_with_site(
        &self,
        context_id: &str,
        broadcast_key: scp_core::crypto::sender_keys::BroadcastKey,
        admission: scp_core::context::broadcast::BroadcastAdmission,
        projection_policy: Option<scp_core::context::params::ProjectionPolicy>,
        site_config: Option<projection::SiteConfig>,
    ) -> Result<(), NodeError> {
        // Validate: gated contexts cannot have public projection rules.
        projection::validate_projection_policy(admission, projection_policy.as_ref())
            .map_err(NodeError::InvalidConfig)?;

        let routing_id = projection::compute_routing_id(context_id);

        // Acquire write lock FIRST, then validate hostname uniqueness inside
        // the lock to eliminate the TOCTOU race between read-lock validation
        // and write-lock insertion.
        let mut registry = self.state.projected_contexts.write().await;

        if let Some(ref config) = site_config {
            let existing_hostnames: std::collections::HashSet<String> = registry
                .iter()
                .filter(|(id, _)| **id != routing_id)
                .filter_map(|(_, p)| p.hostname().map(str::to_ascii_lowercase))
                .collect();

            projection::validate_site_config(config, self.domain.as_deref(), &existing_hostnames)
                .map_err(NodeError::InvalidConfig)?;
        }

        // Track the old hostname (if any) so we can remove it from the
        // hostname index when updating to a new hostname.
        let old_hostname = registry
            .get(&routing_id)
            .and_then(|p| p.hostname().map(str::to_ascii_lowercase));

        if let Some(existing) = registry.get_mut(&routing_id) {
            existing.insert_key(broadcast_key);
            existing.admission = admission;
            existing.projection_policy = projection_policy;
            if let Some(config) = site_config {
                existing.set_site_config(config);
            }
        } else {
            if registry.len() >= Self::MAX_PROJECTED_CONTEXTS {
                return Err(NodeError::InvalidConfig(format!(
                    "projected context limit ({}) reached",
                    Self::MAX_PROJECTED_CONTEXTS
                )));
            }
            let mut projected =
                ProjectedContext::new(context_id, broadcast_key, admission, projection_policy);
            if let Some(config) = site_config {
                projected.set_site_config(config);
            }
            registry.insert(routing_id, projected);
        }

        // Extract the new hostname after mutation (if any).
        let new_hostname = registry
            .get(&routing_id)
            .and_then(|p| p.hostname().map(str::to_ascii_lowercase));

        // Update the hostname index while still holding the projected_contexts
        // lock to eliminate the TOCTOU window between registry mutation and
        // index update.
        if old_hostname != new_hostname {
            let mut index = self.state.hostname_index.write().await;
            if let Some(ref old) = old_hostname {
                // Only remove if this routing_id still owns the hostname entry.
                if index.get(old) == Some(&routing_id) {
                    index.remove(old);
                }
            }
            if let Some(ref new) = new_hostname
                && !new.is_empty()
            {
                index.insert(new.clone(), routing_id);
            }
            let index_len = index.len();
            drop(index);
            debug_assert!(
                index_len <= Self::MAX_PROJECTED_CONTEXTS,
                "hostname_index size {index_len} exceeds MAX_PROJECTED_CONTEXTS {}",
                Self::MAX_PROJECTED_CONTEXTS,
            );
        }

        drop(registry);

        Ok(())
    }

    /// Deactivates HTTP broadcast projection for the given context.
    ///
    /// Computes `routing_id = SHA-256(context_id)` per spec section 5.14.6,
    /// then removes the corresponding [`ProjectedContext`] from the registry.
    /// All retained epoch keys are dropped.
    ///
    /// See spec sections 18.11.2 and 18.11.8.
    pub async fn disable_broadcast_projection(&self, context_id: &str) {
        let routing_id = projection::compute_routing_id(context_id);
        let mut registry = self.state.projected_contexts.write().await;
        // Extract hostname before removal so we can clean up the index.
        let hostname = registry
            .get(&routing_id)
            .and_then(|p| p.hostname().map(str::to_ascii_lowercase));

        // Update the hostname index while still holding the projected_contexts
        // lock to eliminate the TOCTOU window between registry removal and
        // index update.
        if let Some(ref hostname) = hostname {
            let mut index = self.state.hostname_index.write().await;
            // Only remove if this routing_id still owns the hostname entry,
            // preventing removal of a hostname re-registered by another context.
            if index.get(hostname) == Some(&routing_id) {
                index.remove(hostname);
            }
        }

        registry.remove(&routing_id);
        drop(registry);
    }

    /// Updates the cached member public keys for a projected context.
    ///
    /// Called when context membership changes (new subscribers, removed
    /// subscribers, key rotations). No-op if the context is not projected.
    /// Also clears the UCAN validation cache since cached validations may
    /// reference stale keys.
    ///
    /// See spec section 18.11.6.
    pub async fn update_projection_member_keys(
        &self,
        context_id: &str,
        member_keys: HashMap<String, [u8; 32]>,
    ) {
        let routing_id = projection::compute_routing_id(context_id);
        {
            let mut registry = self.state.projected_contexts.write().await;
            if let Some(projected) = registry.get_mut(&routing_id) {
                projected.update_member_keys(member_keys);
            }
        }
        // Clear the validation cache and bump the generation counter so
        // in-flight validations started before the rotation are discarded.
        // Use unwrap_or_else to propagate through poisoned locks — key
        // rotations must always reach the cache.
        self.state
            .projection_ucan_cache
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clear_and_bump_generation();
    }

    /// Adds a token CID to the projected context's revocation set.
    ///
    /// Tokens matching this CID will be rejected on subsequent requests.
    /// The CID is `SHA-256(encoded_jwt)` hex-encoded, matching the format
    /// used by `scp_core::crypto::ucan::revoke::compute_revocation_cid`.
    /// `token_exp` is the UCAN's `exp` field, used for pruning stale
    /// revocations. No-op if the context is not projected.
    ///
    /// Also adds the CID to the validation cache's revocation set and
    /// removes any cached validation entry, preventing TOCTOU races where
    /// a revoked token could be re-cached.
    ///
    /// See spec section 18.11.6.
    pub async fn revoke_projection_token(&self, context_id: &str, token_cid: &str, token_exp: u64) {
        let routing_id = projection::compute_routing_id(context_id);
        {
            let mut registry = self.state.projected_contexts.write().await;
            if let Some(projected) = registry.get_mut(&routing_id) {
                projected.revoke_token(token_cid, token_exp);
            }
        }
        // Add to the cache's revocation set AND remove from cached entries.
        // This prevents re-caching of the revoked token (TOCTOU defense).
        // Use unwrap_or_else to propagate through poisoned locks — revocations
        // must always reach the cache.
        self.state
            .projection_ucan_cache
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .revoke(token_cid, token_exp);
    }

    /// Propagates rotated broadcast keys to the projection registry after a
    /// governance ban.
    ///
    /// After `ContextManager::execute_governance_action` returns
    /// `GovernanceActionResult::ReadAccessRevoked`, call this method with
    /// the `context_id` and the `GovernanceBanResult` to ensure the
    /// projection endpoint can decrypt content encrypted under the new
    /// post-rotation keys.
    ///
    /// For each rotated author, inserts the new-epoch key into the
    /// [`ProjectedContext`] key registry. If the context is not projected
    /// (not registered via `enable_broadcast_projection`), this is a no-op.
    ///
    /// When the ban's `AccessScope` is `Both`, old-epoch keys are
    /// purged from the projection registry so historical content encrypted
    /// under pre-ban keys is no longer served. `Read` or `Write` scope
    /// retains old keys (historical content remains accessible).
    pub async fn propagate_ban_keys(
        &self,
        context_id: &str,
        ban_result: &scp_core::context::broadcast::GovernanceBanResult,
    ) {
        use scp_core::context::governance::AccessScope;

        let routing_id = projection::compute_routing_id(context_id);
        let mut registry = self.state.projected_contexts.write().await;
        if let Some(projected) = registry.get_mut(&routing_id) {
            // Insert new post-rotation keys.
            for rotation in &ban_result.rotated_authors {
                projected.insert_key(rotation.new_key.clone());
            }

            // Both scope: retain only the new post-rotation keys, purging
            // all pre-ban keys so historical content is no longer
            // decryptable via projection. Uses retain_only_epochs to
            // correctly handle epoch-divergent multi-author contexts.
            if ban_result.scope == AccessScope::Both {
                let new_epochs: std::collections::HashSet<u64> = ban_result
                    .rotated_authors
                    .iter()
                    .map(|r| r.new_epoch)
                    .collect();
                projected.retain_only_epochs(&new_epochs);
            }
        }
    }

    /// Commits a deploy for a projected context (§18.11.11).
    ///
    /// Scans blobs matching the `deploy_id`, decrypts each to extract
    /// `BroadcastContent` metadata, builds an immutable `PathIndex`, verifies
    /// `ETag`s, stores a deploy manifest blob, and atomically swaps the path
    /// index pointer.
    ///
    /// # Errors
    ///
    /// Returns [`NodeError::InvalidConfig`] if the context is not projected
    /// or has no site config. Returns [`NodeError::InvalidConfig`] when the
    /// blob scan matched no asset under `deploy_id`, which §18.11.11 of
    /// `.docs/specs/18-addressability-and-deployment.md` requires so that an
    /// empty deploy leaves whatever the node currently serves in place.
    /// Returns [`NodeError::Storage`] on storage failures.
    #[allow(clippy::too_many_lines)]
    pub async fn commit_deploy(
        &self,
        context_id: &str,
        deploy_id: &str,
    ) -> Result<usize, NodeError> {
        use scp_core::context::broadcast_content::{
            ContentPath, deserialize_broadcast_content, verify_etag,
        };

        /// Reasonable upper bound for blob queries to prevent unbounded memory
        /// allocation on large routing IDs.
        const MAX_BLOB_QUERY: u32 = 50_000;

        let routing_id = projection::compute_routing_id(context_id);

        // Snapshot keys from the registry.
        let registry = self.state.projected_contexts.read().await;
        let projected = registry
            .get(&routing_id)
            .ok_or_else(|| NodeError::InvalidConfig("context is not projected".into()))?;

        if projected.site_config.is_none() {
            return Err(NodeError::InvalidConfig(
                "context has no site config".into(),
            ));
        }

        let max_assets = projected
            .site_config
            .as_ref()
            .map_or(10_000, |c| c.max_assets_per_deploy);
        let max_deploy_size = projected
            .site_config
            .as_ref()
            .map_or(512 * 1024 * 1024, |c| c.max_deploy_size_bytes);

        let keys: HashMap<u64, scp_core::crypto::sender_keys::BroadcastKey> =
            projected.keys.clone();
        drop(registry);

        // Query all blobs for this routing_id. We scan all and filter by
        // deploy_id after decryption (deploy_id is inside the ciphertext).
        let blobs = self
            .state
            .blob_storage
            .query(&routing_id, None, MAX_BLOB_QUERY)
            .await
            .map_err(|e| NodeError::Storage(e.to_string()))?;

        let mut entries: HashMap<ContentPath, projection::PathEntry> = HashMap::new();
        let mut manifest_entries: Vec<projection::DeployManifestEntry> = Vec::new();
        let mut total_size: u64 = 0;
        // Track per-path sizes so path collisions subtract the old size before
        // adding the new one, preventing double-counting.
        let mut path_sizes: HashMap<ContentPath, u64> = HashMap::new();

        for stored in &blobs {
            // Unwrap OuterEnvelope (transport layer), then deserialize
            // BroadcastEnvelope. Skip blobs that are not valid OuterEnvelopes.
            let inner_bytes = match scp_core::envelope::OuterEnvelope::from_bytes(&stored.blob) {
                Ok(outer) => outer.encrypted_blob,
                Err(e) => {
                    tracing::warn!(
                        "failed to unwrap OuterEnvelope in commit_deploy, skipping blob: {e}"
                    );
                    continue;
                }
            };
            let envelope: scp_core::crypto::sender_keys::BroadcastEnvelope =
                match rmp_serde::from_slice(&inner_bytes) {
                    Ok(env) => env,
                    Err(_) => continue,
                };

            let Some(key) = keys.get(&envelope.key_epoch) else {
                continue;
            };

            let Ok(plaintext) =
                scp_core::crypto::sender_keys::open_broadcast_trusted(key, &envelope)
            else {
                continue;
            };

            let Ok(mut content) = deserialize_broadcast_content(&plaintext) else {
                continue;
            };

            // Filter by deploy_id.
            let matches_deploy = content
                .metadata
                .deploy_id
                .as_deref()
                .is_some_and(|id| id == deploy_id);
            if !matches_deploy {
                continue;
            }

            // Compute ETag if absent, then verify. Fail the entire commit on
            // mismatch rather than silently skipping a corrupted blob.
            if content.metadata.etag.is_none() {
                content.metadata.etag = Some(scp_core::context::broadcast_content::compute_etag(
                    &content.body,
                ));
            }
            if let Err(e) = verify_etag(&content) {
                return Err(NodeError::InvalidConfig(format!(
                    "blob {} etag mismatch: {e}",
                    projection::hex_encode(&stored.blob_id)
                )));
            }

            // Capture the ETag content hash and immutability flag BEFORE
            // moving `path` out of `content.metadata`. The ETag is guaranteed
            // `Some` here (populated/verified just above); the let-else is the
            // clippy-clean way to unwrap it.
            let Some(content_hash) = content.metadata.etag.clone() else {
                continue;
            };
            let immutable = content.metadata.immutable;
            let content_type = content
                .metadata
                .content_type
                .as_ref()
                .map(|m| m.as_str().to_owned());

            // Extract path.
            let Some(path) = content.metadata.path else {
                continue;
            };

            let new_size = content.body.len() as u64;

            // Path collision: subtract old size before adding new, and remove
            // stale manifest entry. Last-writer-wins (blobs are oldest-first).
            if let Some(old_size) = path_sizes.get(&path) {
                total_size -= old_size;
                manifest_entries.retain(|e| e.path != path.as_str());
            }

            total_size += new_size;

            if !entries.contains_key(&path) && entries.len() >= max_assets {
                return Err(NodeError::InvalidConfig(format!(
                    "deploy exceeds max_assets_per_deploy ({max_assets})"
                )));
            }

            if total_size > max_deploy_size {
                return Err(NodeError::InvalidConfig(format!(
                    "deploy exceeds max_deploy_size_bytes ({max_deploy_size})"
                )));
            }

            manifest_entries.push(projection::DeployManifestEntry {
                path: path.as_str().to_owned(),
                blob_id: projection::hex_encode(&stored.blob_id),
                content_hash: content_hash.clone(),
                immutable,
                content_type: content_type.clone(),
            });

            path_sizes.insert(path.clone(), new_size);
            entries.insert(
                path,
                projection::PathEntry {
                    blob_id: stored.blob_id,
                    content_hash,
                    immutable,
                    content_type,
                },
            );
        }

        // §18.11.11 step 2, empty deploy: a scan that matched no blob under
        // this deploy_id proves nothing about operator intent, so this commit
        // fails here — before it writes a manifest and before it swaps the
        // pointer. Swapping an empty PathIndex in would make every path the
        // previous deploy served answer 404, and would push that previous
        // deploy into history behind an index serving nothing.
        if entries.is_empty() {
            return Err(NodeError::InvalidConfig(format!(
                "deploy {deploy_id} matched no staged asset, so the current deploy stands"
            )));
        }

        // Store deploy manifest as a special blob.
        let manifest = projection::DeployManifest {
            deploy_id: deploy_id.to_owned(),
            entries: manifest_entries,
        };
        let manifest_bytes = rmp_serde::to_vec_named(&manifest)
            .map_err(|e| NodeError::Storage(format!("manifest serialization failed: {e}")))?;

        // Compute a deterministic manifest blob_id.
        let manifest_blob_id: [u8; 32] = {
            let mut hasher = sha2::Sha256::new();
            hasher.update(b"scp:deploy-manifest:");
            hasher.update(context_id.as_bytes());
            hasher.update(b":");
            hasher.update(deploy_id.as_bytes());
            hasher.finalize().into()
        };

        let _ = self
            .state
            .blob_storage
            .store(
                routing_id,
                manifest_blob_id,
                None,
                86400 * 30,
                manifest_bytes,
            )
            .await
            .map_err(|e| NodeError::Storage(e.to_string()))?;

        // Commit: swap path index.
        let count = entries.len();
        let mut registry = self.state.projected_contexts.write().await;
        let projected = registry
            .get_mut(&routing_id)
            .ok_or_else(|| NodeError::InvalidConfig("context removed during deploy".into()))?;
        projected.commit_deploy(deploy_id.to_owned(), entries);
        drop(registry);

        tracing::info!(
            context_id = context_id,
            deploy_id = deploy_id,
            asset_count = count,
            "deploy committed"
        );

        Ok(count)
    }

    /// Rolls back to a previous deploy for a projected context (§18.11.11).
    ///
    /// Sets the path index pointer to a previous deploy within the retention
    /// window. Only works if the deploy is in the history buffer (within the
    /// configured `deploy_retention_count`).
    ///
    /// # Errors
    ///
    /// Returns [`NodeError::InvalidConfig`] if the context is not projected
    /// or the `deploy_id` is not in the history buffer.
    #[allow(clippy::significant_drop_tightening)]
    pub async fn rollback_deploy(
        &self,
        context_id: &str,
        deploy_id: &str,
    ) -> Result<(), NodeError> {
        let routing_id = projection::compute_routing_id(context_id);
        let rolled_back = {
            let mut registry = self.state.projected_contexts.write().await;
            let projected = registry
                .get_mut(&routing_id)
                .ok_or_else(|| NodeError::InvalidConfig("context is not projected".into()))?;
            projected.rollback_deploy(deploy_id)
        };

        if !rolled_back {
            return Err(NodeError::InvalidConfig(format!(
                "deploy_id '{deploy_id}' not found in history"
            )));
        }

        // Spot-check one blob from the restored deploy to verify storage
        // freshness. If the blob has expired in storage, the rollback
        // succeeded structurally but content is stale.
        let sample_blob_id = {
            let registry = self.state.projected_contexts.read().await;
            registry.get(&routing_id).and_then(|p| {
                let guard = p.path_index.load();
                guard
                    .as_ref()
                    .as_ref()
                    .and_then(|state| state.index.values().next().map(|e| e.blob_id))
            })
        };
        if let Some(blob_id) = sample_blob_id {
            match self.state.blob_storage.get(&blob_id).await {
                Ok(Some(_)) => {}
                Ok(None) => {
                    tracing::warn!(
                        context_id = context_id,
                        deploy_id = deploy_id,
                        blob_id = projection::hex_encode(&blob_id),
                        "rollback blob spot-check: blob expired in storage"
                    );
                }
                Err(e) => {
                    tracing::warn!(
                        context_id = context_id,
                        deploy_id = deploy_id,
                        error = %e,
                        "rollback blob spot-check: storage error"
                    );
                }
            }
        }

        tracing::info!(
            context_id = context_id,
            deploy_id = deploy_id,
            "deploy rolled back"
        );

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Dev convenience constructor
// ---------------------------------------------------------------------------

/// Dev/demo convenience constructor for [`ApplicationNode`].
///
/// Requires the `testing` feature flag (or `#[cfg(test)]`). **Not for production
/// use.** It wires the `InMemoryDhtClient` (a §17.17.3 resolve nullifier) and
/// publishes its DID document at startup, so it is a test-harness node only —
/// hence the `testing` gate, which keeps the nullifier out of shipped artifacts
/// (ADR-062 §Decision 1). Production callers use [`Node::start`] with a real
/// Pkarr client, or [`DhtMode::Disabled`](crate::DhtMode::Disabled) via
/// `host_site` for a non-publishing node.
#[cfg(any(test, feature = "testing"))]
impl
    ApplicationNode<
        Arc<
            scp_platform::encrypting_adapter::EncryptingAdapter<
                scp_platform::in_memory::InMemoryStorage,
            >,
        >,
    >
{
    /// Creates an `ApplicationNode` with sensible development defaults.
    ///
    /// Auto-wires:
    /// - [`InMemoryKeyCustody`](scp_platform::testing::InMemoryKeyCustody)
    /// - [`InMemoryStorage`](scp_platform::in_memory::InMemoryStorage) wrapped in
    ///   [`EncryptingAdapter`](scp_platform::encrypting_adapter::EncryptingAdapter)
    ///   under a fresh `OsRng` AES-256-GCM key, so this constructor satisfies a
    ///   production [`Node::start`](crate::Node::start) `EncryptedStorage` bound
    ///   (spec §17.5 canonical usage pattern). An `Arc` around that adapter
    ///   matches a handle shape a bridge instance holds, so an FFI caller places
    ///   a `dev` node and a caller-supplied-storage node in one enum variant.
    /// - [`InMemoryDhtClient`](scp_dht::InMemoryDhtClient) (no real DHT network)
    /// - [`SelfSignedTlsProvider`] (self-signed TLS certificate for `localhost`)
    /// - Relay bound to `127.0.0.1:<port>`
    /// - Domain set to `localhost`
    ///
    /// This is the zero-friction path for demos, prototyping, and integration
    /// tests. For production deployments, use [`Node::start`](crate::Node::start) with
    /// real key custody, encrypted storage, and ACME TLS.
    ///
    /// # Example
    ///
    /// ```ignore
    /// # async fn example() -> Result<(), scp_node::NodeError> {
    /// let node = scp_node::ApplicationNode::dev(4000).await?;
    /// println!("Relay at {}", node.relay().bound_addr());
    /// println!("DID: {}", node.identity().did());
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// Returns [`NodeError`] if relay binding, identity generation, or TLS
    /// provisioning fails.
    pub async fn dev(port: u16) -> Result<Self, NodeError> {
        use scp_clock::SystemClock;
        use scp_dht::InMemoryDhtClient;
        use scp_identity::DidCache;
        use scp_identity::dht::DidDht;
        use scp_platform::encrypting_adapter::EncryptingAdapter;
        use scp_platform::in_memory::InMemoryStorage;
        use scp_platform::testing::InMemoryKeyCustody;
        use zeroize::Zeroizing;

        type DevDidDht = DidDht<InMemoryDhtClient, SystemClock>;

        let custody = Arc::new(InMemoryKeyCustody::new());
        let dht_client = Arc::new(InMemoryDhtClient::new());
        let cache = Arc::new(DidCache::new());
        let sign_fn = DevDidDht::make_sign_fn(Arc::clone(&custody));
        let did_method = Arc::new(DevDidDht::with_client_and_signer(
            dht_client, cache, sign_fn,
        ));

        // Migrated to the ADR-052 flat-config front door (Phase B-P2). The
        // dropped `.tls_provider(SelfSignedTlsProvider::new("localhost"))` is
        // reproduced by the default `TlsMode::SelfSigned`, which installs a
        // byte-identical self-signed provider for the `Domain` reach. This
        // node opts into `DhtMode::Production` (M2 accepts `Disabled` for every
        // `Reach`, `Domain` included), which makes `Node::start` publish
        // through `did_method` and fail the start if that publish fails.
        //
        // Storage goes through a production `Node::start` front door: an
        // ephemeral `InMemoryStorage` is wrapped in `EncryptingAdapter` under a
        // fresh `OsRng` AES-256-GCM key, which satisfies a sealed
        // `EncryptedStorage` bound (spec §17.5). `dev` is a *DHT/custody*
        // test-harness affordance, not a storage-encryption one — it has no
        // reason to reach for `start_for_testing`.
        let mut storage_key = Zeroizing::new([0u8; 32]);
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut *storage_key);
        Node::start(NodeConfig {
            bind_addr: Some(SocketAddr::from(([127, 0, 0, 1], port))),
            dht: DhtMode::Production,
            ..NodeConfig::defaults(
                Reach::Domain {
                    domain: "localhost".to_owned(),
                },
                IdentitySource::Generate {
                    custody,
                    did_method,
                },
                Arc::new(EncryptingAdapter::new(InMemoryStorage::new(), storage_key)),
                // Durability-only blob arm, selected explicitly — `dev()` is a
                // documented dev/prototyping affordance (SCP-CAPINJECT-010).
                BlobStorageBackend::in_memory(),
            )
        })
        .await
    }
}

// ---------------------------------------------------------------------------
// Identity persistence
// ---------------------------------------------------------------------------

/// Storage key used by [`IdentitySource::Persisted`](crate::IdentitySource::Persisted) to
/// persist and reload the node's identity across restarts.
///
/// The value stored under this key is a MessagePack-serialized
/// [`StoredValue<PersistedIdentity>`] (spec §17.5).
///
/// Listed in spec §17.3 key convention as a top-level singleton key.
const IDENTITY_STORAGE_KEY: &str = "scp/identity";

/// Serializable snapshot of an [`ScpIdentity`] and its [`DidDocument`].
///
/// Used by [`IdentitySource::Persisted`](crate::IdentitySource::Persisted) to persist a newly
/// created identity so that subsequent restarts produce the same DID.
///
/// # Storage format
///
/// Stored as `MessagePack` (`rmp-serde`) under [`IDENTITY_STORAGE_KEY`], wrapped
/// in a [`StoredValue<PersistedIdentity>`] version envelope per spec §17.5.
/// Uses the `Storage` trait directly (NOT through [`ProtocolRepository`] domain
/// methods) because identity bootstrap persistence is a pre-DID operation:
/// the identity must be loaded before any DID is known, before contexts exist,
/// and before `ProtocolRepository` domain methods can be used (since they are keyed
/// by DID or `context_id`). This is documented as a second legitimate exception
/// in spec §17.4, alongside the MLS bridge (§17.9).
///
/// # Concurrency
///
/// `ApplicationNode` is expected to be a singleton per process. No locking
/// is applied around the retrieve-then-store sequence; concurrent builders
/// against the same storage may race.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct PersistedIdentity {
    identity: ScpIdentity,
    document: DidDocument,
}

// ---------------------------------------------------------------------------
// IdentitySource / ExplicitIdentity
// ---------------------------------------------------------------------------
//
// These now live in `crate::config` (ADR-052 Phase B-P1 name reconciliation)
// and are re-exported at crate root above. `Node::start`'s identity lowering
// in `config` constructs and matches on them by name.

// ---------------------------------------------------------------------------
// NAT strategy (mockable NAT probing for testability)
// ---------------------------------------------------------------------------

/// Result of the NAT tier selection process during zero-config deployment
/// (spec section 10.12.8).
///
/// Determines the relay URL format published in the DID document
/// (spec section 10.12.7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReachabilityTier {
    /// Tier 1: UPnP/NAT-PMP port mapping succeeded.
    /// Relay URL: `ws://<external-ip>:<port>/scp/v1`.
    Upnp {
        /// External address obtained from the gateway.
        external_addr: SocketAddr,
    },
    /// Tier 2: STUN hole punching (non-symmetric NAT).
    /// Relay URL: `ws://<external-ip>:<port>/scp/v1`.
    Stun {
        /// External address discovered by STUN.
        external_addr: SocketAddr,
    },
    /// Tier 3: Bridge relay (symmetric NAT or all lower tiers failed).
    /// Relay entry: `serviceEndpoint` is the bridge relay's own
    /// `wss://<bridge-domain>/scp/v1`, and `bridgeTarget` names the routing ID
    /// the bridge forwards to (§10.12.7, §18.2.1).
    Bridge {
        /// The bridge relay's URL, published as the entry's `serviceEndpoint`.
        bridge_url: scp_did::BridgeEndpoint,
    },
}

/// Strategy for NAT probing and tier selection (spec section 10.12.8).
///
/// Abstracted as a trait to enable mock implementations in tests.
/// Production code uses [`DefaultNatStrategy`]; tests provide
/// pre-computed results.
pub trait NatStrategy: Send + Sync {
    /// Probes NAT type and selects the best reachability tier.
    ///
    /// Steps per §10.12.8:
    /// 1. Probe NAT type via STUN.
    /// 2. Attempt Tier 1 (UPnP/NAT-PMP).
    /// 3. If Tier 1 fails and NAT is non-symmetric, attempt Tier 2 (STUN).
    /// 4. If Tier 2 fails or NAT is symmetric, attempt Tier 3 (bridge).
    fn select_tier(
        &self,
        relay_port: u16,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<ReachabilityTier, NodeError>> + Send + '_>,
    >;
}

/// Default STUN endpoints with pre-resolved IP addresses.
///
/// Two endpoints are required for NAT type classification (the prober
/// compares external addresses reported by different STUN servers to
/// detect symmetric NAT). Addresses are numeric `SocketAddr` values
/// because `str::parse::<SocketAddr>` rejects hostnames.
const DEFAULT_STUN_ENDPOINTS: &[(&str, &str)] = &[
    ("74.125.250.129:19302", "stun1.l.google.com"),
    ("64.233.163.127:19302", "stun2.l.google.com"),
];

/// Default NAT strategy using real STUN probing, `UPnP`, and bridge relay.
///
/// Implements the tier selection algorithm from spec 10.12.8:
/// 1. Probe NAT type via STUN.
/// 2. Attempt Tier 1 (UPnP/NAT-PMP) if a `PortMapper` is configured.
///    Run reachability self-test on the mapped address (spec 10.12.2 step 4).
/// 3. If Tier 1 fails and NAT is non-symmetric, attempt Tier 2 (STUN address).
///    Run reachability self-test on the STUN-discovered address (spec 10.12.3).
/// 4. If Tier 2 fails or NAT is symmetric, attempt Tier 3 (bridge relay).
///
/// The reachability self-test (SCP-242) sends a STUN Binding Request from the
/// SAME socket that holds the NAT mapping to a STUN server intermediary. If
/// the server confirms the expected external address, the mapping is valid.
///
/// Uses [`NatProber`](scp_transport::nat::NatProber) for STUN probing,
/// [`PortMapper`](scp_transport::nat::PortMapper) for `UPnP`, and
/// [`ReachabilityProbe`](scp_transport::nat::ReachabilityProbe) for self-test.
pub struct DefaultNatStrategy {
    /// STUN server URL override (if set via `.stun_server()`).
    stun_server: Option<String>,
    /// Bridge relay override (if set via `.bridge_relay()`).
    bridge_relay: Option<scp_did::BridgeEndpoint>,
    /// Optional primary port mapper for Tier 1 (spec 10.12.2).
    /// Typically UPnP-IGD, tried first.
    port_mapper: Option<Arc<dyn scp_transport::nat::PortMapper>>,
    /// Optional fallback port mapper for Tier 1 (spec 10.12.2).
    /// Typically NAT-PMP/PCP, tried if the primary mapper fails.
    fallback_mapper: Option<Arc<dyn scp_transport::nat::PortMapper>>,
    /// Optional reachability probe for self-test (spec 10.12.2 step 4, SCP-242).
    /// If `None`, a [`DefaultReachabilityProbe`](scp_transport::nat::DefaultReachabilityProbe)
    /// is constructed from the first STUN endpoint.
    reachability_probe: Option<Arc<dyn scp_transport::nat::ReachabilityProbe>>,
}

impl DefaultNatStrategy {
    /// Creates a new default NAT strategy with optional overrides.
    #[must_use]
    pub fn new(stun_server: Option<String>, bridge_relay: Option<scp_did::BridgeEndpoint>) -> Self {
        Self {
            stun_server,
            bridge_relay,
            port_mapper: None,
            fallback_mapper: None,
            reachability_probe: None,
        }
    }

    /// Sets the primary port mapper for Tier 1 (spec 10.12.2).
    #[must_use]
    pub fn with_port_mapper(mut self, mapper: Arc<dyn scp_transport::nat::PortMapper>) -> Self {
        self.port_mapper = Some(mapper);
        self
    }

    /// Sets the fallback port mapper for Tier 1 (spec 10.12.2).
    ///
    /// Tried when the primary mapper fails. Typically NAT-PMP/PCP.
    #[must_use]
    pub fn with_fallback_mapper(mut self, mapper: Arc<dyn scp_transport::nat::PortMapper>) -> Self {
        self.fallback_mapper = Some(mapper);
        self
    }

    /// Sets the reachability probe for self-test verification (SCP-242).
    ///
    /// If not set, a [`DefaultReachabilityProbe`](scp_transport::nat::DefaultReachabilityProbe)
    /// is constructed from the first STUN endpoint at probe time.
    #[must_use]
    pub fn with_reachability_probe(
        mut self,
        probe: Arc<dyn scp_transport::nat::ReachabilityProbe>,
    ) -> Self {
        self.reachability_probe = Some(probe);
        self
    }

    /// Builds the STUN endpoint list from configuration.
    fn build_stun_endpoints(&self) -> Result<Vec<scp_transport::nat::StunEndpoint>, NodeError> {
        use scp_transport::nat::StunEndpoint;
        if let Some(ref override_url) = self.stun_server {
            let addr: SocketAddr = override_url.parse().map_err(|e| {
                NodeError::Nat(format!("invalid STUN server address '{override_url}': {e}"))
            })?;
            Ok(vec![StunEndpoint {
                addr,
                label: override_url.clone(),
            }])
        } else {
            Ok(DEFAULT_STUN_ENDPOINTS
                .iter()
                .map(|(addr_str, label)| {
                    // SAFETY: DEFAULT_STUN_ENDPOINTS are compile-time string literals
                    // verified by the `default_stun_endpoints_parseable` unit test.
                    #[allow(clippy::expect_used)]
                    let addr: SocketAddr = addr_str
                        .parse()
                        .expect("DEFAULT_STUN_ENDPOINTS contains valid SocketAddr literals");
                    StunEndpoint {
                        addr,
                        label: (*label).to_owned(),
                    }
                })
                .collect())
        }
    }

    /// Attempts Tier 1 `UPnP`/NAT-PMP port mapping with reachability self-test.
    ///
    /// Tries the primary mapper first, then the fallback mapper if the primary
    /// fails. Returns `Some(ReachabilityTier::Upnp)` if mapping and self-test
    /// both succeed, `None` if all attempts fail (caller should fall through
    /// to Tier 2).
    async fn try_tier1_upnp(
        &self,
        relay_port: u16,
        socket: &tokio::net::UdpSocket,
        probe: &dyn scp_transport::nat::ReachabilityProbe,
    ) -> Option<ReachabilityTier> {
        // Build the ordered list of mappers to try: primary, then fallback.
        let mappers: Vec<&Arc<dyn scp_transport::nat::PortMapper>> = self
            .port_mapper
            .iter()
            .chain(self.fallback_mapper.iter())
            .collect();

        if mappers.is_empty() {
            return None;
        }

        tracing::info!("attempting Tier 1 UPnP/NAT-PMP port mapping");

        for mapper in &mappers {
            match mapper.map_port(relay_port).await {
                Ok(mapping) => {
                    tracing::info!(
                        protocol = %mapping.protocol,
                        external_addr = %mapping.external_addr,
                        "port mapping acquired, running reachability self-test"
                    );
                    let reachable = probe
                        .probe_reachability(socket, mapping.external_addr)
                        .await
                        .unwrap_or(false);

                    if reachable {
                        tracing::info!(
                            external_addr = %mapping.external_addr,
                            "Tier 1 reachability self-test passed"
                        );
                        return Some(ReachabilityTier::Upnp {
                            external_addr: mapping.external_addr,
                        });
                    }
                    tracing::warn!(
                        "Tier 1 reachability self-test failed for {:?}, trying next mapper",
                        mapping.protocol
                    );
                }
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "port mapping failed, trying next mapper"
                    );
                }
            }
        }

        tracing::warn!("all Tier 1 port mappers exhausted, falling through to Tier 2");
        None
    }
}

impl NatStrategy for DefaultNatStrategy {
    fn select_tier(
        &self,
        relay_port: u16,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<ReachabilityTier, NodeError>> + Send + '_>,
    > {
        Box::pin(async move {
            use scp_transport::nat::{DefaultReachabilityProbe, NatProber, ReachabilityProbe};

            // Step 1: Build STUN endpoint list.
            let endpoints = self.build_stun_endpoints()?;

            // Resolve or construct the reachability probe for self-test.
            // Uses the first STUN endpoint as intermediary if no explicit probe
            // is configured (SCP-242 AC5: self-test via known relay intermediary).
            let probe: Arc<dyn ReachabilityProbe> = if let Some(ref p) = self.reachability_probe {
                Arc::clone(p)
            } else {
                Arc::new(DefaultReachabilityProbe::new(endpoints[0].addr, None))
            };

            // Bind a UDP socket for NAT probing. This socket is reused for
            // the reachability self-test so the NAT mapping is preserved.
            let socket = tokio::net::UdpSocket::bind("0.0.0.0:0")
                .await
                .map_err(|e| {
                    NodeError::Nat(format!("failed to bind UDP socket for NAT probing: {e}"))
                })?;

            let prober = NatProber::new(endpoints, None)
                .map_err(|e| NodeError::Nat(format!("failed to create NAT prober: {e}")))?;

            // Step 2: Probe NAT type using the shared socket.
            let probe_result = prober
                .probe_with_socket(&socket)
                .await
                .map_err(|e| NodeError::Nat(format!("NAT probing failed: {e}")))?;

            tracing::info!(
                nat_type = %probe_result.nat_type,
                external_addr = ?probe_result.external_addr,
                "NAT type probed"
            );

            // Step 3: Attempt Tier 1 (UPnP/NAT-PMP) — spec 10.12.2.
            if let Some(tier) = self.try_tier1_upnp(relay_port, &socket, &*probe).await {
                return Ok(tier);
            }

            // Step 4: For non-symmetric NAT, attempt Tier 2 (STUN address).
            // Run reachability self-test before accepting (spec 10.12.3).
            if probe_result.nat_type.is_hole_punchable()
                && let Some(external_addr) = probe_result.external_addr
            {
                tracing::info!(
                    external_addr = %external_addr,
                    "attempting Tier 2 STUN, running reachability self-test"
                );
                let reachable = probe
                    .probe_reachability(&socket, external_addr)
                    .await
                    .unwrap_or(false);

                if reachable {
                    tracing::info!(
                        external_addr = %external_addr,
                        "Tier 2 reachability self-test passed"
                    );
                    return Ok(ReachabilityTier::Stun { external_addr });
                }

                tracing::warn!("Tier 2 reachability self-test failed, falling through to Tier 3");
            }

            // Step 5: Tier 3 (bridge relay).
            if let Some(ref bridge_url) = self.bridge_relay {
                return Ok(ReachabilityTier::Bridge {
                    bridge_url: bridge_url.clone(),
                });
            }

            Err(NodeError::Nat(
                "all reachability tiers failed: NAT is symmetric and no bridge relay configured"
                    .into(),
            ))
        })
    }
}

// ---------------------------------------------------------------------------
// TLS provider (mockable ACME provisioning for testability)
// ---------------------------------------------------------------------------

/// Strategy for TLS certificate provisioning (spec section 18.6.3).
///
/// Abstracted as a trait to enable mock implementations in tests.
/// Production code uses [`AcmeProvider`](tls::AcmeProvider); tests can inject
/// providers that succeed or fail deterministically.
pub trait TlsProvider: Send + Sync {
    /// Attempt to provision or load a TLS certificate for the domain.
    ///
    /// On success, returns [`CertificateData`](tls::CertificateData) for
    /// configuring the TLS acceptor.
    fn provision(
        &self,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<tls::CertificateData, tls::TlsError>>
                + Send
                + '_,
        >,
    >;

    /// Returns the shared ACME challenge map (token → key authorization).
    ///
    /// The default implementation returns a **new empty map on every call**,
    /// which is correct for mock providers and `SelfSignedTlsProvider` that
    /// never serve HTTP-01 challenges.
    ///
    /// # Important
    ///
    /// Implementors that override [`needs_challenge_listener()`](Self::needs_challenge_listener)
    /// to return `true` **MUST** also override this method to return a
    /// persistent, shared map. Failing to do so means the challenge listener
    /// and the provisioning flow will operate on different maps, and ACME
    /// validation will never succeed.
    fn challenges(&self) -> Arc<tokio::sync::RwLock<std::collections::HashMap<String, String>>> {
        Arc::new(tokio::sync::RwLock::new(std::collections::HashMap::new()))
    }

    /// Whether this provider requires an HTTP-01 challenge listener.
    ///
    /// Returns `true` for real ACME providers that need the CA to probe
    /// `GET /.well-known/acme-challenge/{token}` on port 80 during
    /// provisioning. Returns `false` for mock providers and self-signed
    /// certificate generators. Default: `false`.
    fn needs_challenge_listener(&self) -> bool {
        false
    }
}

/// Blanket [`TlsProvider`] for [`AcmeProvider`](tls::AcmeProvider).
impl<S: Storage + 'static> TlsProvider for tls::AcmeProvider<S> {
    fn provision(
        &self,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<tls::CertificateData, tls::TlsError>>
                + Send
                + '_,
        >,
    > {
        Box::pin(self.load_or_provision())
    }

    fn challenges(&self) -> Arc<tokio::sync::RwLock<std::collections::HashMap<String, String>>> {
        self.challenges()
    }

    fn needs_challenge_listener(&self) -> bool {
        true
    }
}

/// TLS provider that generates a self-signed certificate for development.
///
/// Uses [`tls::generate_self_signed`] to create a certificate valid for the
/// given domain. **Not for production use** — browsers and other TLS clients
/// will reject the certificate unless configured to trust it.
///
/// This provider is used internally by [`ApplicationNode::dev`] and is also
/// available for custom builder configurations during development.
///
/// Requires the `allow_unencrypted_storage` feature flag (or `#[cfg(test)]`).
#[cfg(any(test, feature = "allow_unencrypted_storage"))]
pub struct SelfSignedTlsProvider {
    domain: String,
}

#[cfg(any(test, feature = "allow_unencrypted_storage"))]
impl SelfSignedTlsProvider {
    /// Creates a new self-signed TLS provider for the given domain.
    #[must_use]
    pub fn new(domain: &str) -> Self {
        Self {
            domain: domain.to_owned(),
        }
    }
}

#[cfg(any(test, feature = "allow_unencrypted_storage"))]
impl TlsProvider for SelfSignedTlsProvider {
    fn provision(
        &self,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<tls::CertificateData, tls::TlsError>>
                + Send
                + '_,
        >,
    > {
        let domain = self.domain.clone();
        Box::pin(async move { tls::generate_self_signed(&domain) })
    }
}

// The node's DID-document publish seam — the `DidPublisher` trait, its production
// impl `NodeDidPublisher`, the opaque `NodePublisher` handle, and
// `seed_from_startup_publish` — lives in the private `published_state` module,
// beside the live slot it writes and `apply_tier_change`. Keeping the seam and
// the slot in one module is what makes `publish` uncallable without also seeding
// the slot (SCP-RELAYRES-004 AC-6). See `published_state`.

// ---------------------------------------------------------------------------
// Tier re-evaluation (§10.12.1, SCP-243)
// ---------------------------------------------------------------------------

/// Default re-evaluation interval per §10.12.1 recommendation.
const TIER_REEVALUATION_INTERVAL: Duration = Duration::from_mins(30);

/// Handle to the tier re-evaluation background task (SCP-243).
///
/// The task re-evaluates the reachability tier every 30 minutes and on
/// network change events. When the tier changes, it updates the DID
/// document with the new relay address and logs at INFO level (§10.12.1).
struct TierReEvalHandle {
    /// Tokio completes a `JoinHandle` only after the task's future has been
    /// dropped, on every exit path (normal return, cancellation, panic, abort).
    /// Awaiting it therefore blocks until every `Arc` the future captured,
    /// including the `DidMethod`/`KeyCustody` clones held by the republish path,
    /// has been released.
    ///
    /// A value the future owns is no such witness: a sender moved into a local
    /// of the task body drops when the body returns, before the runtime drops
    /// the future and its captures, so a waiter on it can wake while the custody
    /// handle is still held.
    ///
    /// Behind a `std::sync::Mutex` so it is takeable through the shared `&self`
    /// shutdown path; `None` after the first stop-and-wait or abort, so a second
    /// call is a no-op.
    task: std::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
    /// Cancellation token: send `true` to stop the background task.
    cancel_tx: tokio::sync::watch::Sender<bool>,
    /// The runtime the task was spawned onto, captured at spawn.
    ///
    /// [`stop_and_wait`](Self::stop_and_wait) joins through this handle rather
    /// than through [`Handle::try_current`](tokio::runtime::Handle::try_current),
    /// which describes the CALLER's thread: the FFI bridges call
    /// `ApplicationNode::shutdown` from host threads that never entered the
    /// node's runtime (the reason `SelfDidRepublishing::runtime` in
    /// `republish.rs` gives).
    runtime: tokio::runtime::Handle,
    /// How long [`stop_and_wait`](Self::stop_and_wait) waits for the task to
    /// end before it aborts the task and returns.
    /// [`TIER_TASK_STOP_DEADLINE`] in production.
    stop_deadline: Duration,
}

/// The bound on [`TierReEvalHandle::stop_and_wait`]'s wait for the tier task.
///
/// The task reads its cancel signal only between re-evaluations, so a
/// re-evaluation already in flight at shutdown (NAT probing, then the DID
/// document publish) runs on until it finishes or this deadline passes.
const TIER_TASK_STOP_DEADLINE: Duration = Duration::from_secs(5);

impl TierReEvalHandle {
    /// Signals the background re-evaluation task to stop, WITHOUT waiting for it
    /// to finish.
    ///
    /// Fire-and-forget cancel signal. Used by the unit tests in this module to
    /// tear down a directly-spawned task once their assertions are done; the
    /// production teardown path ([`ApplicationNode::shutdown`]) uses
    /// [`stop_and_wait`](Self::stop_and_wait) instead.
    #[cfg(test)]
    fn stop(&self) {
        let _ = self.cancel_tx.send(true);
    }

    /// Signals the background task to stop.
    ///
    /// The task runs on the stored [`runtime`](Self::runtime). When that runtime
    /// is multi-thread, its workers drive the task while this thread waits up to
    /// [`stop_deadline`](Self::stop_deadline) for the `JoinHandle` to resolve; a
    /// caller on a multi-thread worker waits inside
    /// [`tokio::task::block_in_place`]. At the deadline the task is aborted and
    /// this returns without waiting further, so the task's captures can outlive
    /// the return, e.g. when the task is blocked on a host-language custody
    /// callback that needs the thread this caller holds (the GIL, the JS main
    /// thread). If the runtime is shutting down, the wait can end before the
    /// task's future drops; that case is logged at warn.
    ///
    /// A caller on a `current_thread` runtime gets a best-effort `abort()` +
    /// cancel signal instead: `block_in_place` panics there, and waiting without
    /// it would stall every task that runtime drives. A stored
    /// `current_thread` runtime gets the same abort, because its task advances
    /// only while that runtime's owner thread drives it, and the owner may be the
    /// thread waiting on this call.
    /// Idempotent: the `JoinHandle` is consumed on the first call, so a second
    /// invocation only re-sends the (harmless) cancel signal.
    fn stop_and_wait(&self) {
        let _ = self.cancel_tx.send(true);
        let Some(task) = self.take_task() else {
            return;
        };
        let multi_thread = tokio::runtime::RuntimeFlavor::MultiThread;
        let caller = tokio::runtime::Handle::try_current().ok();
        if self.runtime.runtime_flavor() != multi_thread
            || caller
                .as_ref()
                .is_some_and(|current| current.runtime_flavor() != multi_thread)
        {
            task.abort();
            return;
        }
        // The JoinHandle resolves only after the runtime has dropped the task
        // future, so the future's captured `Arc`s are gone when it resolves. A
        // forwarder on the task's runtime relays the result over a std channel,
        // so the wait needs no timer and no `block_on`. If the runtime has shut
        // down, the forwarder is dropped unrun and `recv_timeout` returns
        // `Disconnected` at once.
        let abort = task.abort_handle();
        let (joined_tx, joined_rx) = std::sync::mpsc::sync_channel(1);
        drop(self.runtime.spawn(async move {
            let _ = joined_tx.send(task.await);
        }));
        let wait = || joined_rx.recv_timeout(self.stop_deadline);
        let joined = if caller.is_some() {
            tokio::task::block_in_place(wait) // ci-allow: block-on: multi-thread worker waits, bounded by stop_deadline, for the tier task's captured custody Arc to drop before shutdown() returns
        } else {
            wait()
        };
        match joined {
            Ok(Err(e)) if e.is_panic() => {
                // The future is dropped either way, but a panic in the task is
                // a defect to surface.
                tracing::error!(error = %e, "tier re-evaluation task panicked");
            }
            // A cancelled join: only runtime shutdown can cancel the task once
            // its handle is taken, and that drops the future too.
            Ok(Ok(()) | Err(_)) => {}
            // The forwarder was dropped without sending, which runtime shutdown
            // can do before it drops the tier task's future.
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                tracing::warn!(
                    "tier re-evaluation task join was not observed: its runtime dropped the join forwarder"
                );
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                abort.abort();
                tracing::warn!(
                    deadline = ?self.stop_deadline,
                    "tier re-evaluation task did not stop by the deadline; aborted it"
                );
            }
        }
    }

    /// Takes the task's `JoinHandle`, leaving `None` so later calls are no-ops.
    fn take_task(&self) -> Option<tokio::task::JoinHandle<()>> {
        self.task
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
    }
}

impl Drop for TierReEvalHandle {
    fn drop(&mut self) {
        // Backstop for a node dropped without an explicit `shutdown()`: dropping
        // a `JoinHandle` detaches the task rather than stopping it, so abort it.
        // After `stop_and_wait()` the handle is already taken and this is a
        // no-op.
        if let Some(task) = self.take_task() {
            task.abort();
        }
    }
}

/// The routing ID a tier 3 node publishes as its entry's `bridgeTarget`.
///
/// Stub — see SCP-315. `10-infrastructure-and-self-hosting.md` §10.12.4.1
/// defines the identity routing ID over the identifier's 32 raw digest bytes.
/// This returns `SHA-256("scp:did:" || did)` over the DID string instead,
/// because that is the routing ID `verify_bridge_registration` admits a
/// `BRIDGE_REGISTER` at today, so a published target matches a registration a
/// bridge relay accepts. The two values differ until the SCP-315 cut-over
/// replaces `did:dht`.
///
/// # Errors
///
/// [`NodeError::Identity`] when the routing ID equals SHA-256(0x00), the
/// value §3.10.13 reserves for "no target" (a SHA-256 preimage collision).
fn node_bridge_target(did: &str) -> Result<scp_did::BridgeTarget, NodeError> {
    scp_did::BridgeTarget::new(scp_identity::resolution::did_routing_id(did))
        .map_err(|e| NodeError::Identity(IdentityError::from(e)))
}

/// The `SCPRelay` entry for a node reachable at `addr`: `ws://<addr>/scp/v1`
/// with no `bridgeTarget`.
///
/// # Errors
///
/// [`NodeError::Identity`] when `ws://<addr>/scp/v1` has no §9.18.2 canonical
/// form, which a STUN or port-mapper answer can produce (port 0, or an IPv6
/// address carrying a zone).
fn address_relay_service(addr: SocketAddr) -> Result<scp_did::RelayService, NodeError> {
    scp_did::RelayEndpoint::new(&format!("ws://{addr}/scp/v1"))
        .map(scp_did::RelayService::direct)
        .map_err(|e| NodeError::Identity(IdentityError::from(e)))
}

/// Converts a [`ReachabilityTier`] to the `SCPRelay` entry the node publishes.
///
/// Tiers 1 and 2 publish the node's own `ws://` address with no
/// `bridgeTarget`. Tier 3 publishes the bridge relay's URL with
/// `bridge_target` (§10.12.7, §18.2.1); its [`scp_did::BridgeEndpoint`] and
/// [`scp_did::BridgeTarget`] already passed §18.2.1, so that arm cannot fail.
///
/// # Errors
///
/// As [`address_relay_service`], for tiers 1 and 2.
fn tier_to_relay_service(
    tier: &ReachabilityTier,
    bridge_target: scp_did::BridgeTarget,
) -> Result<scp_did::RelayService, NodeError> {
    match tier {
        ReachabilityTier::Upnp { external_addr } | ReachabilityTier::Stun { external_addr } => {
            address_relay_service(*external_addr)
        }
        ReachabilityTier::Bridge { bridge_url } => Ok(scp_did::RelayService::bridge(
            bridge_url.clone(),
            bridge_target,
        )),
    }
}

/// The relay URL a domain-mode node publishes in its DID document.
///
/// The node also gives it to its relay server as `RelayConfig.relay_url`, so
/// the relay's reserved push routing ID (§10.7.1 step 2) derives from the URL
/// clients read from the document.
pub(crate) fn domain_relay_url(domain: &str) -> String {
    format!("wss://{domain}/scp/v1")
}

/// Resolves the published relay entry for no-domain mode.
///
/// `Some(tier)` is the probed reachability tier; `None` means the NAT probe was
/// skipped (operator opted out — e.g. behind a tunnel/proxy), in which case the
/// node falls back to a loopback relay URL on the public HTTP port. The loopback
/// fallback keeps the published URL and the self-signed certificate SANs
/// localhost-only, which is the correct posture when external reachability is
/// provided by the proxy/tunnel rather than NAT traversal.
///
/// # Errors
///
/// As [`tier_to_relay_service`].
fn no_domain_relay_service(
    tier: Option<&ReachabilityTier>,
    http_port: u16,
    bridge_target: scp_did::BridgeTarget,
) -> Result<scp_did::RelayService, NodeError> {
    tier.map_or_else(
        || address_relay_service(SocketAddr::from(([127, 0, 0, 1], http_port))),
        |tier| tier_to_relay_service(tier, bridge_target),
    )
}

// ---------------------------------------------------------------------------
// NAT port-mapping lease renewal (spec §10.12.2)
// ---------------------------------------------------------------------------

/// Fraction of the mapping lease TTL at which renewal is attempted.
///
/// Per spec §10.12.2: "`UPnP` mappings have a TTL ... The SDK renews at 50% TTL"
/// and "NAT-PMP/PCP mappings have explicit lifetimes ... The SDK renews at 50%
/// lifetime." Renewing at half the lease leaves a full half-life of headroom to
/// retry on transient failure before the mapping actually expires.
const MAPPING_RENEWAL_FRACTION: f64 = 0.5;

/// Minimum renewal interval, clamping 50%-of-TTL for very short leases so the
/// renewal loop never busy-spins.
const MIN_MAPPING_RENEWAL_INTERVAL: Duration = Duration::from_secs(5);

/// Lease TTL assumed when a mapper reports an unusable lifetime (zero/unknown).
///
/// NAT-PMP/PCP report explicit lifetimes and UPnP-IGD echoes the requested lease,
/// so in practice the real TTL is always used; this is only the fall-back when a
/// gateway returns a degenerate value. 3600s (1h) matches the NAT-PMP default
/// lease requested by `NatPmpPortMapper` in `scp_transport::nat::upnp`, an item that
/// crate compiles only under its `upnp` feature, which this crate does not enable.
const DEFAULT_MAPPING_LEASE: Duration = Duration::from_hours(1);

/// Backoff before retrying after a failed renewal attempt.
///
/// Spec §10.12.2: on renewal failure the host "re-probes" rather than giving up.
/// A short fixed backoff means a transient gateway hiccup costs at most this
/// delay; because it is far shorter than a half-life of headroom, the mapping is
/// not dropped while retries are in flight.
const MAPPING_RENEWAL_RETRY_BACKOFF: Duration = Duration::from_secs(30);

/// Computes the renewal interval as [`MAPPING_RENEWAL_FRACTION`] of the lease
/// TTL, clamped to [`MIN_MAPPING_RENEWAL_INTERVAL`].
///
/// A zero (or sub-floor) TTL maps to the floor, never to zero, so the caller
/// can pass a gateway-reported lease through unconditionally.
fn mapping_renewal_interval(ttl: Duration) -> Duration {
    let half = ttl.mul_f64(MAPPING_RENEWAL_FRACTION);
    if half < MIN_MAPPING_RENEWAL_INTERVAL {
        MIN_MAPPING_RENEWAL_INTERVAL
    } else {
        half
    }
}

/// Re-issues the port mapping once, trying the supplied mappers in order
/// (primary first, fallback second — the same order [`DefaultNatStrategy`] used
/// to acquire it). Returns the result of the first mapper that succeeds.
///
/// NAT-PMP renewal is "re-send the mapping request" (RFC 6886 §3.3) and UPnP-IGD
/// renewal is "re-add the same mapping"; both are idempotent and extend the lease
/// rather than creating a duplicate. Issuing the request in acquisition order
/// keeps the renewal aligned with whichever protocol the gateway actually honors,
/// even if that changes mid-session (e.g. `UPnP` comes back after a router reboot).
async fn renew_mapping_once(
    mappers: &[Arc<dyn scp_transport::nat::PortMapper>],
    port: u16,
) -> Option<scp_transport::nat::PortMappingResult> {
    for mapper in mappers {
        match mapper.map_port(port).await {
            Ok(result) => return Some(result),
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    port,
                    "NAT mapping renewal attempt failed for one mapper, trying next"
                );
            }
        }
    }
    None
}

/// Runs the NAT port-mapping renewal loop until `cancel` is triggered.
///
/// The loop is the single owner of every post-acquisition renewal for the
/// self-host node (spec §10.12.2). On each cycle it re-issues the mapping (which
/// extends the lease and reports the gateway's current TTL), schedules the next
/// cycle at 50% of that TTL, and logs the outcome. On failure it logs a warning
/// and retries after a short backoff — a transient gateway error never
/// permanently drops the mapping; the half-life of headroom absorbs the retry.
///
/// The very first action is an immediate renewal so the loop learns the real
/// lease TTL (the acquiring [`DefaultNatStrategy`] discards it). That first
/// re-issue is idempotent against the mapping `build()` already created.
async fn run_mapping_renewal_loop(
    mappers: Vec<Arc<dyn scp_transport::nat::PortMapper>>,
    port: u16,
    cancel: CancellationToken,
) {
    if mappers.is_empty() {
        return;
    }

    // The granted lease TTL is not observable here: the acquiring
    // `DefaultNatStrategy` discards it (it returns only the external address).
    // A self-host gateway may grant a lease far shorter than an hour (spec
    // §10.12.2 calls 10-60 min typical), so seeding the first interval at 50% of
    // an *assumed* hour could let a short lease expire before the first renewal.
    // Instead, schedule the first renewal at the floor: an early, idempotent
    // re-issue (NAT-PMP re-send / UPnP re-add) extends the mapping `build()`
    // already created and reports the gateway's real TTL, which then drives every
    // subsequent interval at the true 50%. The floor keeps this off the hot path.
    let mut next_interval = MIN_MAPPING_RENEWAL_INTERVAL;

    loop {
        // Wait for the scheduled interval or cancellation, whichever comes first.
        tokio::select! {
            () = cancel.cancelled() => {
                tracing::debug!(port, "NAT mapping renewal loop cancelled");
                return;
            }
            () = tokio::time::sleep(next_interval) => {}
        }

        if let Some(result) = renew_mapping_once(&mappers, port).await {
            let ttl = if result.ttl.is_zero() {
                DEFAULT_MAPPING_LEASE
            } else {
                result.ttl
            };
            next_interval = mapping_renewal_interval(ttl);
            tracing::info!(
                protocol = %result.protocol,
                external_addr = %result.external_addr,
                ttl_secs = ttl.as_secs(),
                next_renewal_secs = next_interval.as_secs(),
                port,
                "NAT port mapping lease renewed (§10.12.2)"
            );
        } else {
            next_interval = MAPPING_RENEWAL_RETRY_BACKOFF;
            tracing::warn!(
                port,
                retry_secs = MAPPING_RENEWAL_RETRY_BACKOFF.as_secs(),
                "NAT port mapping renewal failed on all mappers; retrying after backoff"
            );
        }
    }
}

/// Spawns the NAT port-mapping renewal loop, tied to `cancel` for shutdown.
///
/// Hold the returned [`JoinHandle`](tokio::task::JoinHandle) for the node's lifetime. On shutdown, trigger
/// `cancel` and `await` the handle so the renewal loop fully stops *before* the
/// mapping is released — renewal must never race the teardown `remove()`.
///
/// The `mappers` slice should contain the retained mapper handles in acquisition
/// order (primary, then fallback). An empty slice yields a task that returns
/// immediately, so the default (non-`upnp`) build spawns a harmless no-op exactly
/// like the bare one-shot path.
#[must_use]
pub fn spawn_self_host_mapping_renewal(
    mappers: Vec<Arc<dyn scp_transport::nat::PortMapper>>,
    port: u16,
    cancel: CancellationToken,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(run_mapping_renewal_loop(mappers, port, cancel))
}

/// Spawns the periodic tier re-evaluation background task (§10.12.1, SCP-243).
///
/// The task uses `tokio::select!` to wait for either:
/// - The 30-minute periodic timer
/// - A network change event from the `NetworkChangeDetector`
///
/// On each trigger, it calls `NatStrategy::select_tier()` and compares the
/// result to the current tier. If the tier changed, it updates the DID
/// document and republishes it, logging at INFO level.
///
/// `live_state` is the node's shared state slot, not a copy: this task is its
/// only writer, and it keeps no document and no URL of its own — not even the
/// "current" address it compares against, which it reads back out of the slot.
/// See [`LiveSlot`]. `publisher` is bound to the relay's live URL handle, the
/// one every relay listener reads its reserved push routing IDs from, and
/// [`apply_tier_change`] moves that handle with the advertised address
/// (§10.7.1 step 2).
#[allow(clippy::too_many_arguments)]
fn spawn_tier_reevaluation(
    nat_strategy: Arc<dyn NatStrategy>,
    network_detector: Option<Arc<dyn NetworkChangeDetector>>,
    publisher: NodePublisher,
    bridge_target: scp_did::BridgeTarget,
    identity: ScpIdentity,
    live_state: LiveSlot<NodePublishedState>,
    relay_port: u16,
    event_tx: Option<tokio::sync::mpsc::Sender<NatTierChange>>,
    reevaluation_interval: Duration,
) -> TierReEvalHandle {
    let (cancel_tx, mut cancel_rx) = tokio::sync::watch::channel(false);
    // Teardown joins this task's `JoinHandle`, which completes only after the
    // runtime has dropped the future and the `publisher`/`DidMethod`/custody
    // clones it captured. See `TierReEvalHandle::task`.
    let task = tokio::spawn(async move {
        loop {
            let trigger_reason = tokio::select! {
                () = tokio::time::sleep(reevaluation_interval) => {
                    "periodic 30-minute re-evaluation (§10.12.1)"
                }
                result = async {
                    match network_detector.as_ref() {
                        Some(d) => d.wait_for_change().await,
                        None => std::future::pending().await,
                    }
                } => {
                    match result {
                        Ok(()) => "network change event detected",
                        Err(e) => {
                            tracing::warn!(error = %e, "network change detector error");
                            continue;
                        }
                    }
                }
                result = cancel_rx.changed() => {
                    // Err means the sender was dropped — treat as shutdown.
                    // Ok means value changed — check if it's the cancel signal.
                    if result.is_err() || *cancel_rx.borrow() { return; }
                    continue;
                }
            };
            tracing::debug!(reason = trigger_reason, "tier re-evaluation triggered");
            let new_tier = match nat_strategy.select_tier(relay_port).await {
                Ok(tier) => tier,
                Err(e) => {
                    tracing::warn!(error = %e, "tier re-evaluation failed, keeping current tier");
                    continue;
                }
            };
            // Only a tier 1 or 2 address with no §9.18.2 canonical form fails
            // here; a tier 3 entry is built from validated parts.
            let new_relay = match tier_to_relay_service(&new_tier, bridge_target) {
                Ok(relay) => relay,
                Err(e) => {
                    tracing::warn!(
                        error = %e, tier = ?new_tier,
                        "re-evaluated tier's address has no relay entry, keeping current tier"
                    );
                    continue;
                }
            };
            // A re-publish is owed while EITHER the entry the node advertises
            // or the entry its DID document carries still differs. Both are
            // checked because they are gated differently: the advertised entry
            // advances on every detected change while the document advances
            // only on a successful publish, so a failed publish must keep being
            // retried after the address has already moved. See
            // `NodePublishedState`. Comparing whole entries, not URLs, keeps a
            // `bridgeTarget` change from passing as "no change".
            let current = live_state.get();
            if current.relay == new_relay
                && published_state::document_relay_service(&current.document).as_ref()
                    == Some(&new_relay)
            {
                tracing::debug!(relay_url = %new_relay.url(), "tier re-evaluation: no change");
                continue;
            }
            tracing::info!(
                previous_url = %current.relay.url(), new_url = %new_relay.url(),
                tier = ?new_tier, reason = trigger_reason,
                "reachability tier changed, updating DID document (§10.12.1)"
            );
            apply_tier_change(
                &live_state,
                &new_relay,
                bridge_target,
                &publisher,
                &identity,
                published_state::TierChangeReport {
                    reason: trigger_reason,
                    events: event_tx.as_ref(),
                },
            )
            .await;
        }
    });
    TierReEvalHandle {
        task: std::sync::Mutex::new(Some(task)),
        cancel_tx,
        runtime: tokio::runtime::Handle::current(),
        stop_deadline: TIER_TASK_STOP_DEADLINE,
    }
}

// ---------------------------------------------------------------------------
// Bridge secret generation
// ---------------------------------------------------------------------------

/// Resolves the identity from an [`IdentitySource`], returning the identity,
/// document, and DID method.
///
/// On a shipped build the `Generate` arm fails closed with no `.await`; the
/// `async` signature is kept for the `testing` build and callers' `.await`.
#[cfg_attr(not(feature = "testing"), allow(clippy::unused_async))]
async fn resolve_identity<K: KeyCustody, D: DidMethod>(
    source: IdentitySource<K, D>,
) -> Result<(ScpIdentity, DidDocument, Arc<D>), NodeError> {
    match source {
        IdentitySource::Generate {
            custody,
            did_method,
        } => {
            // Pre-rotation is mandatory at creation (spec §9.7.4.1 item 5(a)), which
            // requires a `PreRotationCustody` backend. The only implementation
            // is the test-harness `InMemoryPreRotationCustody` nullifier.
            #[cfg(feature = "testing")]
            {
                // KNOWN LIMITATION (testing builds): this path drops the
                // `PreRotationKeyHandle` because `ApplicationNode`'s generic
                // parameter list does not yet carry a `P: PreRotationCustody`
                // slot, so identities produced here cannot be migrated later.
                let pre_rotation_custody = scp_platform::testing::InMemoryPreRotationCustody::new();
                let (identity, document, _pre_rotation_handle) =
                    did_method.create(&*custody, &pre_rotation_custody).await?;
                tracing::warn!(
                    did = %identity.did,
                    "identity created without a persistent PreRotationCustody — migration \
                     (Layer-2 DID rotation) will be impossible until the builder API is \
                     widened to accept a real backend. The reveal that spec §9.7.4.1 item 4 \
                     says recovers a root compromise is unreachable for this identity."
                );
                Ok((identity, document, did_method))
            }
            #[cfg(not(feature = "testing"))]
            {
                // FAIL CLOSED (ADR-062 §Decision 6): no real PreRotationCustody
                // backend exists yet (RFC #2130 / #1729). Never mint the in-memory
                // nullifier on a shipped build — return a typed error instead.
                let _ = (custody, did_method);
                Err(NodeError::Identity(IdentityError::NoPreRotationBackend))
            }
        }
        IdentitySource::Explicit(e) => Ok((e.identity, e.document, e.did_method)),
        // `Node::start` normalizes `Persisted` to a `Generate` source with
        // `persist = true` before calling the resolvers, so a `Persisted`
        // variant never reaches `resolve_identity`.
        IdentitySource::Persisted { .. } => unreachable!(
            "IdentitySource::Persisted is normalized to Generate by Node::start \
             and never reaches resolve_identity"
        ),
    }
}

/// Validates that a persisted identity's key handles exist in the provided
/// custody backend and that the derived public keys match the corresponding
/// verification methods in the DID document.
///
/// Checks all three key slots (identity `#0`, active `#active`, and agent
/// `#agent` if present) for both existence in custody and public-key
/// consistency with the document.
async fn validate_persisted_custody<K: KeyCustody>(
    persisted: &PersistedIdentity,
    key_custody: &K,
) -> Result<(), NodeError> {
    // --- #0 Identity Key ---
    let identity_pub = key_custody
        .public_key(&persisted.identity.identity_key)
        .await
        .map_err(|e| {
            NodeError::Storage(format!(
                "persisted identity key handle not found in custody: {e}"
            ))
        })?;
    verify_vm_match(&persisted.document, "#0", &identity_pub, "identity key")?;

    // Re-derive the self-certifying DID from the #0 identity key and confirm it
    // matches the persisted DID string. The did:dht identifier is
    // `did:dht:z<zbase32(#0 public key)>`; a stored DID that does not re-derive
    // from the custody-held key indicates tampering or corruption of the
    // persisted record, so reject the load.
    let id_key_bytes: [u8; 32] = identity_pub.as_bytes().try_into().map_err(|_| {
        NodeError::Storage(format!(
            "persisted #0 identity public key is not 32 bytes (got {})",
            identity_pub.as_bytes().len()
        ))
    })?;
    let derived_did = scp_identity::dht::did_from_ed25519_public_key(&id_key_bytes);
    if derived_did != persisted.identity.did {
        return Err(NodeError::Storage(format!(
            "persisted DID does not match DID re-derived from #0 identity key \
             (stored: {}, derived: {derived_did})",
            persisted.identity.did
        )));
    }

    // --- #active Signing Key ---
    let active_pub = key_custody
        .public_key(&persisted.identity.active_signing_key)
        .await
        .map_err(|e| {
            NodeError::Storage(format!(
                "persisted active signing key handle not found in custody: {e}"
            ))
        })?;
    verify_vm_match(
        &persisted.document,
        "#active",
        &active_pub,
        "active signing key",
    )?;

    // --- #agent Signing Key (optional) ---
    if let Some(ref agent_key) = persisted.identity.agent_signing_key {
        let agent_pub = key_custody.public_key(agent_key).await.map_err(|e| {
            NodeError::Storage(format!(
                "persisted agent signing key handle not found in custody: {e}"
            ))
        })?;
        verify_vm_match(
            &persisted.document,
            "#agent",
            &agent_pub,
            "agent signing key",
        )?;
    }

    Ok(())
}

/// Checks that a custody-derived public key matches the corresponding
/// verification method in the DID document.
///
/// `vm_suffix` is the fragment suffix to search for (e.g. `"#0"`, `"#active"`,
/// `"#agent"`). If the VM is not found in the document, this is a no-op (the
/// VM may not exist for optional keys like `#agent`).
fn verify_vm_match(
    document: &DidDocument,
    vm_suffix: &str,
    public_key: &scp_platform::traits::PublicKey,
    label: &str,
) -> Result<(), NodeError> {
    if let Some(vm) = document
        .verification_method
        .iter()
        .find(|vm| vm.id.ends_with(vm_suffix))
    {
        let expected_multibase = format!("z{}", bs58::encode(public_key.as_bytes()).into_string());
        if vm.public_key_multibase != expected_multibase {
            return Err(NodeError::Storage(format!(
                "custody {label} does not match DID document {vm_suffix} verification method \
                 (custody: {expected_multibase}, document: {})",
                vm.public_key_multibase
            )));
        }
    }
    Ok(())
}

/// Resolves identity with automatic persistence.
///
/// When `persist` is `true` and the identity source is `Generate`:
///   1. Check storage for [`IDENTITY_STORAGE_KEY`].
///   2. If found, deserialize the [`PersistedIdentity`] and return the
///      stored identity + document (skipping generation).
///   3. If not found, generate via `did_method.create()`, serialize to
///      storage, then return the new identity.
///
/// When `persist` is `false`, delegates to [`resolve_identity`].
pub(crate) async fn resolve_identity_persistent<K: KeyCustody, D: DidMethod, S: Storage>(
    source: IdentitySource<K, D>,
    persist: bool,
    storage: &S,
) -> Result<(ScpIdentity, DidDocument, Arc<D>), NodeError> {
    if !persist {
        return resolve_identity(source).await;
    }

    match source {
        IdentitySource::Generate {
            custody,
            did_method,
        } => {
            // 1. Check storage for an existing identity.
            let existing = storage.retrieve(IDENTITY_STORAGE_KEY).await.map_err(|e| {
                NodeError::Storage(format!("failed to read persisted identity: {e}"))
            })?;

            if let Some(bytes) = existing {
                // 2. Deserialize the StoredValue<PersistedIdentity> envelope.
                let envelope: StoredValue<PersistedIdentity> = rmp_serde::from_slice(&bytes)
                    .map_err(|e| {
                        NodeError::Storage(format!("failed to deserialize persisted identity: {e}"))
                    })?;

                // 2a. Reject unknown future versions to prevent silent corruption
                //     from downgraded binaries reading data written by newer code.
                if envelope.version > CURRENT_STORE_VERSION {
                    return Err(NodeError::Storage(format!(
                        "persisted identity version {} is newer than supported version {}; \
                         upgrade the binary or delete the stored identity",
                        envelope.version, CURRENT_STORE_VERSION
                    )));
                }

                let persisted = envelope.data;

                // 2b. Validate custody key handles and DID document consistency.
                validate_persisted_custody(&persisted, &*custody).await?;

                tracing::info!(
                    did = %persisted.identity.did,
                    "reloaded persisted identity from storage"
                );
                Ok((persisted.identity, persisted.document, did_method))
            } else {
                // 3. Generate a new identity and persist it.
                //
                // Pre-rotation is mandatory at creation (spec §9.7.4.1 item 5(a)),
                // which requires a `PreRotationCustody` backend. The only
                // implementation is the test-harness `InMemoryPreRotationCustody`.
                #[cfg(feature = "testing")]
                {
                    // KNOWN LIMITATION (testing builds): the `PreRotationKeyHandle`
                    // is dropped because the builder does not yet carry a
                    // `P: PreRotationCustody` generic slot, so identities produced
                    // via this persistent path cannot migrate.
                    let pre_rotation_custody =
                        scp_platform::testing::InMemoryPreRotationCustody::new();
                    let (identity, document, _pre_rotation_handle) =
                        did_method.create(&*custody, &pre_rotation_custody).await?;
                    tracing::warn!(
                        did = %identity.did,
                        "persisted identity created without a persistent PreRotationCustody — \
                         migration (Layer-2 DID rotation) will be impossible after process \
                         restart. The reveal that spec §9.7.4.1 item 4 says recovers a root \
                         compromise is unreachable for this identity until the builder API is widened to accept a real \
                         backend."
                    );
                    let persisted = PersistedIdentity {
                        identity: identity.clone(),
                        document: document.clone(),
                    };
                    let envelope = StoredValue {
                        version: CURRENT_STORE_VERSION,
                        data: &persisted,
                    };
                    let bytes = rmp_serde::to_vec_named(&envelope).map_err(|e| {
                        NodeError::Storage(format!(
                            "failed to serialize identity for persistence: {e}"
                        ))
                    })?;
                    storage
                        .store(IDENTITY_STORAGE_KEY, &bytes)
                        .await
                        .map_err(|e| {
                            NodeError::Storage(format!(
                                "failed to persist identity to storage: {e}"
                            ))
                        })?;
                    tracing::info!(
                        did = %identity.did,
                        "created and persisted new identity to storage"
                    );
                    Ok((identity, document, did_method))
                }
                #[cfg(not(feature = "testing"))]
                {
                    // FAIL CLOSED (ADR-062 §Decision 6): no real PreRotationCustody
                    // backend exists yet (RFC #2130 / #1729). Never mint the
                    // in-memory nullifier on a shipped build — return a typed error.
                    let _ = (&custody, &did_method, storage);
                    Err(NodeError::Identity(IdentityError::NoPreRotationBackend))
                }
            }
        }
        // Explicit identities are never persisted — caller already manages them.
        IdentitySource::Explicit(e) => Ok((e.identity, e.document, e.did_method)),
        // `Node::start` normalizes `Persisted` to a `Generate` source with
        // `persist = true` before calling this resolver, so a `Persisted`
        // variant never reaches `resolve_identity_persistent`.
        IdentitySource::Persisted { .. } => unreachable!(
            "IdentitySource::Persisted is normalized to Generate by Node::start \
             and never reaches resolve_identity_persistent"
        ),
    }
}

/// Generates a 32-byte bridge secret using `OsRng`.
///
/// Wrapped in `Zeroizing` so the secret is zeroed on drop.
pub(crate) fn generate_bridge_secret() -> Zeroizing<[u8; 32]> {
    let mut bytes = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut bytes);
    Zeroizing::new(bytes)
}

// ---------------------------------------------------------------------------
// Dev API token generation (spec §18.10.2)
// ---------------------------------------------------------------------------

/// Generate a random bearer token for the dev API.
///
/// 16 random bytes from `OsRng` → 32 hex chars (spec §18.10.2).
/// Logs a masked prefix — never the full token.
pub(crate) fn generate_dev_token(addr: SocketAddr) -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    let hex = hex::encode(bytes);
    let token = format!("scp_local_token_{hex}");
    let masked = &token[..("scp_local_token_".len() + 8)];
    tracing::info!(
        token_prefix = %masked,
        dev_bind_addr = ?addr,
        "dev API token generated (use node.dev_token() for full value)"
    );
    token
}

// ---------------------------------------------------------------------------
// TLS provider resolution (§10.12.8 step 4)
// ---------------------------------------------------------------------------

/// Resolves the TLS provider: uses the explicitly provided one, or constructs
/// a default [`AcmeProvider`](tls::AcmeProvider) for the given domain.
pub(crate) fn resolve_tls<S: Storage + 'static>(
    provider: Option<Arc<dyn TlsProvider>>,
    domain: &str,
    storage: &Arc<ProtocolRepository<S>>,
    acme_email: Option<&String>,
) -> Arc<dyn TlsProvider> {
    provider.unwrap_or_else(|| {
        let mut acme = tls::AcmeProvider::new(domain, Arc::clone(storage));
        if let Some(email) = acme_email {
            acme = acme.with_email(email);
        }
        Arc::new(acme)
    })
}

// ---------------------------------------------------------------------------
// ACME challenge listener (§18.6.3, issue #305)
// ---------------------------------------------------------------------------

/// Temporary ACME challenge listener handle.
///
/// Wraps the tokio task and cancellation token for the temporary HTTP-only
/// listener that serves `GET /.well-known/acme-challenge/{token}` during
/// ACME provisioning. Call [`stop`](Self::stop) to shut down the listener
/// after provisioning completes.
struct AcmeChallengeListener {
    /// Cancellation token to signal shutdown.
    shutdown: CancellationToken,
    /// Handle to the spawned listener task.
    task: tokio::task::JoinHandle<Result<(), NodeError>>,
}

impl AcmeChallengeListener {
    /// Stop the temporary listener and wait for it to drain.
    async fn stop(self) {
        self.shutdown.cancel();
        let _ = self.task.await;
        tracing::info!("temporary ACME HTTP-01 challenge listener stopped");
    }
}

/// Starts a temporary HTTP-only listener on port 80 to serve ACME HTTP-01
/// challenges during certificate provisioning (issue #305, spec §18.6.3).
///
/// The listener serves only `GET /.well-known/acme-challenge/{token}` from
/// the provided challenge map. It must be started BEFORE calling
/// `provision()` so the ACME CA has an endpoint to probe.
///
/// # Errors
///
/// Returns [`NodeError::Serve`] if the listener cannot bind to port 80.
async fn start_acme_challenge_listener(
    challenges: Arc<tokio::sync::RwLock<std::collections::HashMap<String, String>>>,
) -> Result<AcmeChallengeListener, NodeError> {
    let router = tls::acme_challenge_router(challenges);
    let shutdown = CancellationToken::new();
    let listener = tokio::net::TcpListener::bind("0.0.0.0:80")
        .await
        .map_err(|e| {
            NodeError::Serve(format!(
                "failed to bind temporary ACME challenge listener on port 80: {e}"
            ))
        })?;
    let local_addr = listener
        .local_addr()
        .map_err(|e| NodeError::Serve(e.to_string()))?;
    tracing::info!(
        addr = %local_addr,
        "temporary ACME HTTP-01 challenge listener started"
    );
    let shutdown_clone = shutdown.clone();
    let task = tokio::spawn(async move {
        axum::serve(listener, router)
            .with_graceful_shutdown(shutdown_clone.cancelled_owned())
            .await
            .map_err(|e| NodeError::Serve(format!("ACME challenge listener error: {e}")))
    });
    Ok(AcmeChallengeListener { shutdown, task })
}

/// Runs TLS provisioning with an optional temporary ACME challenge listener.
///
/// For real ACME providers (`needs_challenge_listener() == true`), starts
/// a temporary HTTP-only listener on port 80, calls `provision()`, then
/// shuts the listener down. For mock providers, calls `provision()` directly.
///
/// Returns the provisioning result and an optional shared challenge map
/// (for mounting in `serve()` to support ACME renewal).
///
/// # Errors
///
/// Returns [`NodeError::Serve`] if the ACME listener cannot bind.
pub(crate) async fn provision_with_challenge_listener(
    provider: &dyn TlsProvider,
) -> Result<
    (
        Result<tls::CertificateData, tls::TlsError>,
        Option<Arc<tokio::sync::RwLock<std::collections::HashMap<String, String>>>>,
    ),
    NodeError,
> {
    let challenges = provider.challenges();
    let acme_listener = if provider.needs_challenge_listener() {
        Some(start_acme_challenge_listener(Arc::clone(&challenges)).await?)
    } else {
        None
    };

    let result = provider.provision().await;

    if let Some(listener) = acme_listener {
        listener.stop().await;
    }

    let acme_challenges = if provider.needs_challenge_listener() {
        Some(challenges)
    } else {
        None
    };

    Ok((result, acme_challenges))
}

// ---------------------------------------------------------------------------
// NAT strategy resolution (§10.12.8 step 5)
// ---------------------------------------------------------------------------

/// Resolves the NAT traversal strategy: uses the explicitly provided one, or
/// constructs a [`DefaultNatStrategy`] from the STUN/bridge/port-mapper configuration.
pub(crate) fn resolve_nat(
    strategy: Option<Arc<dyn NatStrategy>>,
    stun_server: Option<String>,
    bridge_relay: Option<scp_did::BridgeEndpoint>,
    port_mapper: Option<Arc<dyn scp_transport::nat::PortMapper>>,
    reachability_probe: Option<Arc<dyn scp_transport::nat::ReachabilityProbe>>,
) -> Arc<dyn NatStrategy> {
    strategy.unwrap_or_else(|| {
        let mut default = DefaultNatStrategy::new(stun_server, bridge_relay);

        // Wire the port mapper: use the explicitly provided one, or construct
        // a production `UPnP` mapper when the `upnp` feature is enabled.
        // The `UpnpPortMapper` is the primary tier per spec 10.12.2.
        // NOTE: NAT-PMP/PCP fallback (#1154) requires `PortMappingManager`
        // integration which accepts (upnp, natpmp, port, channel) — tracked
        // for follow-up wiring to `DefaultNatStrategy`.
        #[cfg(feature = "upnp")]
        let port_mapper = port_mapper.or_else(|| {
            Some(Arc::new(scp_transport::UpnpPortMapper::new())
                as Arc<dyn scp_transport::nat::PortMapper>)
        });

        if let Some(mapper) = port_mapper {
            default = default.with_port_mapper(mapper);
        }

        // Wire the NAT-PMP fallback mapper per spec 10.12.2:
        // "NAT-PMP/PCP as fallback" after UPnP-IGD.
        #[cfg(feature = "upnp")]
        {
            let natpmp_mapper = Arc::new(scp_transport::NatPmpPortMapper::new())
                as Arc<dyn scp_transport::nat::PortMapper>;
            default = default.with_fallback_mapper(natpmp_mapper);
        }

        if let Some(probe) = reachability_probe {
            default = default.with_reachability_probe(probe);
        }
        Arc::new(default)
    })
}

/// Starts the node's self-DID republish cycle and erases its DHT client type.
///
/// ADR-003 §2 of `.docs/adrs/phase-1.md`: republishing "starts when an identity
/// is loaded". Both builders call this, so every `Node::start` path reaches it —
/// `build_domain_inner` on the `Reach::Domain` TLS-success arm, and
/// [`build_no_domain_inner`] on `Reach::NatTraversal`, `Reach::Tunnel`,
/// `Reach::Local`, and the `Reach::Domain` TLS-failure fall-through.
///
/// Both layers run. The DHT keep-alive is the only thing stopping this node's
/// BEP44 record from expiring off Mainline, and the relay arm fails closed while
/// no relay is bound and self-heals the instant one is; §3.10.6 forbids turning
/// either off without a deliberate opt-out, and an unbound relay is not one.
///
/// The cycle reads a LIVE VIEW of the slot [`seed_from_startup_publish`] just
/// built, never a snapshot: a NAT tier change re-publishes the document with a
/// new `(value, signature, seq)`, and both arms follow it rather than going on
/// asserting a superseded sequence. While `record` is `None` the cycle sits
/// dormant at zero arms — the permanent state of a [`DhtMode::Disabled`] node,
/// which publishes nothing.
///
/// The DHT client comes from the node's own [`DidMethod`], so the client that
/// keeps the record alive is the client that signed the publish.
async fn start_node_republish_cycle<D: DidMethod + 'static>(
    did_method: &Arc<D>,
    live_state: &LiveSlot<NodePublishedState>,
) -> Arc<dyn republish::RepublishCycle> {
    Arc::new(
        republish::start_self_did_republishing(
            did_method.dht_client(),
            Arc::new(scp_transport::native::TransportRelayPublisher::new()),
            live_state.subscribe(),
        )
        .await,
    )
}

// ---------------------------------------------------------------------------
// Shared domain build logic (extracted for clippy::too_many_lines)
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
pub(crate) async fn build_domain_inner<D: DidMethod + 'static, S: Storage + 'static>(
    domain: String,
    identity: ScpIdentity,
    mut document: DidDocument,
    did_method: Arc<D>,
    dht_mode: DhtMode,
    storage: Arc<ProtocolRepository<S>>,
    relay_guard: RelayShutdownGuard,
    bound_addr: SocketAddr,
    bridge_secret: Zeroizing<[u8; 32]>,
    dev_token: Option<String>,
    dev_bind_addr: Option<SocketAddr>,
    blob_storage: Arc<BlobStorageBackend>,
    relay_config: RelayConfig,
    http_bind_addr: Option<SocketAddr>,
    cors_origins: Option<Vec<String>>,
    projection_rate_limit: u32,
    cert_data: tls::CertificateData,
    connection_tracker: scp_transport::relay::rate_limit::ConnectionTracker,
    subscription_registry: scp_transport::relay::subscription::SubscriptionRegistry,
    #[cfg(feature = "quic")]
    publish_rate_limiter: scp_transport::relay::rate_limit::PublishRateLimiter,
    #[cfg(feature = "quic")] did_slot_registry: scp_transport::native::did_slot::DidSlotRegistry,
    acme_challenges: Option<Arc<tokio::sync::RwLock<std::collections::HashMap<String, String>>>>,
    #[cfg(feature = "http3")] http3_config: Option<scp_transport::http3::Http3Config>,
) -> Result<ApplicationNode<S>, NodeError> {
    // Node::start already rejected a domain whose relay URL has no §9.18.2
    // canonical form (config.rs builds the relay's `RelayUrl` from the same
    // string first), so this conversion succeeds on that path; it stays a
    // typed error, never an unwrap, for any other caller.
    let relay = scp_did::RelayService::direct(
        scp_did::RelayEndpoint::new(&domain_relay_url(&domain)).map_err(IdentityError::from)?,
    );
    document.add_relay_service(&relay);
    // The entries the node is about to publish, whose push routing IDs the
    // relay reserves before the publish (§10.7.1 step 2, "Tier 3 relays"): the
    // domain entry, which carries no `bridgeTarget` and so reserves its
    // `"scp-push-registration"` ID, and every tier 3 entry of an
    // `IdentitySource::Explicit` document with the node's `bridgeTarget`.
    // `seed_from_startup_publish` reserves them on the publisher's own handle,
    // `relay_config.relay_url`, before it publishes.
    let bridge_target = node_bridge_target(&identity.did)?;
    let entries = published_state::PublishedEntries::new(&relay, &document, bridge_target);
    // Publish the domain→DID binding per the configured `DhtMode` (NOT
    // unconditionally). `DhtMode::Disabled` — the fail-safe default, and a
    // LEGITIMATE more-private `Domain + Disabled` config per construction.md M2
    // (:63/:194): reachable via the domain, address NOT DHT-published, shared
    // out-of-band — SKIPS the publish, so the node still starts. `Production`
    // (and the test-only `Memory`) publish FATALLY, exactly as this path did
    // before. `Domain + Disabled` is never rejected: erroring on the fail-safe
    // direction would itself violate M2.
    //
    // Published AND seeded through the node's single publish seam as ONE step:
    // `seed_from_startup_publish` performs the publish and builds the live slot
    // that carries the published document and record together, so a startup
    // publish that does not seed the slot is not expressible (SCP-RELAYRES-004
    // AC-6 — the seam's `publish` is uncallable outside `published_state`). The
    // seam is the same one the no-domain builder and the tier-change task use, so
    // the configured `DhtMode` gate is honored identically: `Disabled` publishes
    // nothing (still a start), `Production` / test-only `Memory` publish FATALLY.
    //
    // Domain mode spawns NO tier re-evaluation (`tier_reeval: None`), so nothing
    // writes the slot after construction — it is still a `LiveSlot` so both modes
    // read the same live type and a future update site cannot leave a reader
    // behind. See `LiveSlot`.
    //
    // The publisher is bound to the live URL handle of `relay_config`, the
    // configuration this node stores and runs its relay with, so the
    // reservation `seed_from_startup_publish` makes moves this node's relay.
    // `seed_from_startup_publish` reserves, then bootstraps the publish-sequence
    // counter (Production / Memory) so a restart's startup publish supersedes
    // the live record instead of colliding at `seq = 1` (SCP-RELAYRES-004), then
    // publishes.
    let publisher = NodePublisher::new(Arc::clone(&did_method), dht_mode, &relay_config);
    let live_state = seed_from_startup_publish(&publisher, &identity, &entries).await?;

    // Build the rustls ServerConfig from the provisioned certificate.
    // Uses the reloadable config so that ACME renewal can hot-swap certs
    // without restarting the server (spec section 18.6.3).
    let (tls_server_config, cert_resolver) =
        tls::build_reloadable_tls_config(&cert_data).map_err(NodeError::Tls)?;

    // Build the QUIC server config from the SAME provisioned certificate so the
    // relay cert covers both WebSocket (TCP) and QUIC (UDP) on the public TLS
    // port (spec §10.14.3 item 1). The listener itself is started lazily in
    // `serve()`; here we only prepare the config so `serve()` has everything it
    // needs without re-parsing the certificate.
    #[cfg(feature = "quic")]
    let quic_server_config = {
        let cert_chain = cert_data.certificate_chain_der().map_err(NodeError::Tls)?;
        let private_key = cert_data.private_key_der().map_err(NodeError::Tls)?;
        match scp_transport::quic::listener::build_server_config(cert_chain, private_key) {
            Ok(cfg) => Some(cfg),
            Err(e) => {
                // A malformed cert should not prevent the node from serving
                // WebSocket; degrade to WebSocket-only and log loudly.
                tracing::error!(
                    domain = %domain, error = %e,
                    "failed to build QUIC server config — serving WebSocket only"
                );
                None
            }
        }
    };

    tracing::info!(
        domain = %domain, relay_url = %relay.url(),
        bound_addr = %bound_addr, did = %identity.did,
        "application node started (domain mode, TLS active)"
    );

    // Start this node's self-DID republish cycle (ADR-003 §2). Below every
    // fallible step in this builder, so no `?` leaves arms to tear down.
    let republish = start_node_republish_cycle(&did_method, &live_state).await;

    let state = Arc::new(http::NodeState {
        did: identity.did.clone(),
        live_state: live_state.clone(),
        broadcast_contexts: tokio::sync::RwLock::new(HashMap::new()),
        relay_addr: bound_addr,
        bridge_secret,
        dev_token,
        dev_bind_addr,
        projected_contexts: tokio::sync::RwLock::new(HashMap::new()),
        blob_storage,
        relay_config,
        start_time: std::time::Instant::now(),
        http_bind_addr,
        // A domain node advertises `wss://<domain>/scp/v1`, which names no
        // port, so it binds its public listener only when it serves.
        prebound_public: std::sync::Mutex::new(None),
        shutdown_token: CancellationToken::new(),
        cors_origins,
        projection_rate_limiter: scp_transport::relay::rate_limit::PublishRateLimiter::new(
            projection_rate_limit,
        ),
        projection_ucan_cache: std::sync::RwLock::new(projection::ProjectionUcanCache::new()),
        tls_config: Some(Arc::new(tls_server_config)),
        cert_resolver: Some(cert_resolver),
        connection_tracker,
        subscription_registry,
        acme_challenges,
        hostname_index: tokio::sync::RwLock::new(HashMap::new()),
        default_site_routing_id: std::sync::RwLock::new(None),
        #[cfg(feature = "quic")]
        publish_rate_limiter,
        #[cfg(feature = "quic")]
        did_slot_registry,
        #[cfg(feature = "quic")]
        quic_server_config,
        // Set to `true` by `serve()` once the QUIC listener binds (§10.14.3).
        #[cfg(feature = "quic")]
        quic_listening: std::sync::atomic::AtomicBool::new(false),
    });

    Ok(ApplicationNode {
        domain: Some(domain),
        relay: RelayHandle {
            bound_addr,
            shutdown_handle: relay_guard.disarm(),
        },
        identity: IdentityHandle::new(identity, live_state),
        storage,
        state,
        tier_reeval: None,
        tier_change_rx: None,
        #[cfg(feature = "http3")]
        http3_config,
        serving: Arc::new(AtomicBool::new(false)),
        rate_limit_cleanup_spawned: Arc::new(AtomicBool::new(false)),
        serving_addr: Arc::new(tokio::sync::Mutex::new(None)),
        republish,
    })
}

// ---------------------------------------------------------------------------
// Shared no-domain build logic (used by the non-domain reaches and the
// Reach::Domain ACME-failure fallthrough in config.rs's build engine)
// ---------------------------------------------------------------------------

/// Publishes a node's DID document, discriminating on the configured
/// [`DhtMode`] so the two semantically-opposite outcomes are never conflated.
///
/// The `DhtMode` gate itself. Its ONLY caller is the node's publish seam
/// (`NodeDidPublisher::publish`, in `published_state`), so every publish this
/// node performs — startup and NAT tier change alike — honors the mode.
///
/// It takes a [`PublishAuthorization`](crate::published_state::PublishAuthorization) by value, whose sole constructor is
/// private to `published_state`. So even though it is `pub(crate)`, it is
/// **uncallable outside the publish seam by construction, not by convention**:
/// a would-be in-crate caller that reached the [`DidMethod`] around this gate —
/// publishing a `DhtMode::Disabled` node's address, or publishing WITHOUT
/// seeding the live slot (the served≠published divergence AC-6 forbids) — cannot
/// mint the token, so it does not compile. This completes AC-6's structural
/// guarantee for the real DHT/relay publish itself, matching the guard on
/// [`DidPublisher::publish`](crate::published_state::DidPublisher::publish).
///
/// The asymmetry is deliberate and honest:
///
/// - [`DhtMode::Disabled`]: the DID document is **not published at all** — the
///   publish call is skipped entirely. The node is intentionally not
///   DHT-discoverable (fail-safe by design; no address disclosed), which is a
///   *success*, not a degradation. A single `info` is emitted; no warning/error
///   path is taken, reserving those for genuine degradation. The `host_site`
///   non-publishing node and any local/dev node rely on exactly this.
/// - [`DhtMode::Production`] (and the test-harness-only [`DhtMode::Memory`]):
///   the DID document is published, and a publish failure is **fatal** — it
///   propagates so [`build_no_domain_inner`] fails and `Node::start` fails
///   closed. A stable node's tier does not change, so a genuine startup publish
///   failure (network / timeout / rate-limit) is not something a later periodic
///   republish will heal into correctness; swallowing it would report a healthy
///   start while the DID is NOT on the DHT — a false discoverability guarantee,
///   strictly worse than an honest failure.
///
/// This brings the no-domain publishing reaches (`NatTraversal` / `Tunnel`, and
/// the `Reach::Domain` TLS-provisioning fall-through) into line with the
/// `Reach::Domain` path, which already treats publish as fatal.
///
/// Note the `DhtMode::Disabled` skip is independent of the concrete `D`: even if
/// `D`'s client would error on publish (e.g.
/// [`DisabledDhtClient`](scp_dht::DisabledDhtClient), ADR-062 §Decision 1), no
/// publish is attempted, so a `Disabled` node always starts.
///
/// # Return value: the signed record, or an honest absence
///
/// Returns `Some(entry)` carrying the BEP44 `(public_key, seq, signature,
/// value)` this publish signed, and `None` for `DhtMode::Disabled` — where the
/// absence is the literal truth that nothing was published, not a lookup miss.
/// The record becomes part of the node's [`NodePublishedState`], from which the
/// self-host republish cycle reads it directly, so the triple is never
/// reconstructed by resolving the node's own record back off the network.
pub(crate) async fn publish_did_document_for_mode<D: DidMethod + 'static>(
    _auth: published_state::PublishAuthorization,
    dht_mode: DhtMode,
    did_method: &D,
    identity: &ScpIdentity,
    document: &DidDocument,
) -> Result<Option<scp_identity::republish::RepublishEntry>, NodeError> {
    match dht_mode {
        DhtMode::Disabled => {
            tracing::info!(
                did = %identity.did,
                "DhtMode::Disabled — node is intentionally not DHT-published \
                 (not discoverable by design; no address disclosed)"
            );
            Ok(None)
        }
        // Production publishes to the global Mainline DHT; Memory (test-harness-
        // only) publishes to its in-memory client. Both treat a publish failure
        // as FATAL so the node fails closed instead of advertising a false
        // discoverability guarantee. Gated `feature = "testing"` ONLY (ADR-062 A5)
        // to match the `DhtMode::Memory` variant's single activation path.
        #[cfg(feature = "testing")]
        DhtMode::Memory => did_method
            .publish(identity, document)
            .await
            .map(Some)
            .map_err(NodeError::from),
        DhtMode::Production => did_method
            .publish(identity, document)
            .await
            .map(Some)
            .map_err(NodeError::from),
    }
}

/// Bootstraps the DID method's monotonic publish-sequence counter ahead of the
/// node's STARTUP publish — for the modes that actually publish.
///
/// Mirrors [`publish_did_document_for_mode`]'s gate exactly.
/// [`seed_from_startup_publish`] runs it through
/// [`DidPublisher::initialize_sequence`](crate::published_state::DidPublisher::initialize_sequence)
/// after it reserves the startup
/// document's entries and before it publishes that document:
///
/// - [`DhtMode::Disabled`] publishes nothing, so there is no sequence to
///   bootstrap — a no-op success (and it never touches the disabled DHT arm).
/// - [`DhtMode::Production`] (and the test-only [`DhtMode::Memory`]) publish, so
///   the counter MUST be raised to `max(persisted store, live DHT seq)` here.
///   A fresh [`DidDht`](scp_identity::dht::DidDht) counter starts at
///   `AtomicU64::new(0)`, so the first publish does `fetch_add(1)` → `seq = 1`.
///   On a **restart within the record TTL** that `seq = 1` lands *beneath* the
///   live `seq = N` record the previous run published: the real DHT rejects the
///   lower-seq write (a fatal startup-publish failure) or, worse, the node pins
///   itself at `seq = 1` and its DID document dies at the live record's TTL.
///   Bootstrapping the counter here makes the startup publish emit `seq = N + 1`,
///   correctly superseding the prior record (SCP-RELAYRES-004).
///
/// A failure is **FATAL**, exactly as a startup publish failure is:
/// [`DidMethod::initialize_sequence`] is fail-closed on a DHT resolve error
/// (proceeding at an unknown sequence would republish beneath the live record
/// while the OLD — possibly superseded — document stays authoritative), so the
/// node must not go on to publish.
async fn initialize_sequence_for_mode<D: DidMethod + 'static>(
    dht_mode: DhtMode,
    did_method: &D,
    identity: &ScpIdentity,
) -> Result<(), NodeError> {
    match dht_mode {
        DhtMode::Disabled => Ok(()),
        #[cfg(feature = "testing")]
        DhtMode::Memory => did_method
            .initialize_sequence(&identity.did)
            .await
            .map_err(NodeError::from),
        DhtMode::Production => did_method
            .initialize_sequence(&identity.did)
            .await
            .map_err(NodeError::from),
    }
}

// Node builder internal: all parameters are required for server construction.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub(crate) async fn build_no_domain_inner<D: DidMethod + 'static, S: Storage + 'static>(
    identity: ScpIdentity,
    mut document: DidDocument,
    did_method: Arc<D>,
    dht_mode: DhtMode,
    storage: Arc<ProtocolRepository<S>>,
    relay_guard: RelayShutdownGuard,
    bound_addr: SocketAddr,
    nat_strategy: Arc<dyn NatStrategy>,
    bridge_secret: Zeroizing<[u8; 32]>,
    dev_token: Option<String>,
    dev_bind_addr: Option<SocketAddr>,
    blob_storage: Arc<BlobStorageBackend>,
    relay_config: RelayConfig,
    http_bind_addr: Option<SocketAddr>,
    cors_origins: Option<Vec<String>>,
    projection_rate_limit: u32,
    network_detector: Option<Arc<dyn NetworkChangeDetector>>,
    connection_tracker: scp_transport::relay::rate_limit::ConnectionTracker,
    subscription_registry: scp_transport::relay::subscription::SubscriptionRegistry,
    #[cfg(feature = "quic")]
    publish_rate_limiter: scp_transport::relay::rate_limit::PublishRateLimiter,
    #[cfg(feature = "quic")] did_slot_registry: scp_transport::native::did_slot::DidSlotRegistry,
    skip_nat_probe: bool,
) -> Result<ApplicationNode<S>, NodeError> {
    // NAT strategy needs the public HTTP port, not the internal relay port
    // (#641), and the port the node serves, never a configured port 0.
    let advertised = AdvertisedHttp::resolve(http_bind_addr).await?;
    let http_port = advertised.port();
    let AdvertisedHttp {
        bind_addr: http_bind_addr,
        listener: prebound_public,
    } = advertised;

    // When `skip_nat_probe` is set (operator opted out — e.g. behind a
    // tunnel/proxy that terminates on `localhost`), the STUN/NAT probe is dead
    // weight and adds tens of seconds to startup. Skip `select_tier` entirely
    // and fall back to a loopback relay URL: no external IP is discovered or
    // disclosed to the DHT, and no periodic tier re-evaluation task is spawned
    // (there is no tier to re-evaluate). External reachability is provided by
    // the proxy/tunnel, not by NAT traversal.
    let tier = if skip_nat_probe {
        None
    } else {
        Some(nat_strategy.select_tier(http_port).await?)
    };

    let bridge_target = node_bridge_target(&identity.did)?;
    let relay_url = no_domain_relay_service(tier.as_ref(), http_port, bridge_target)?;

    // Inserted ahead of any relay a caller's `IdentitySource::Explicit`
    // document names, so the first `SCPRelay` entry, which a tier change
    // rewrites through `set_preferred_relay`, is the node's own.
    document.insert_preferred_relay(&relay_url);

    // The entries the node is about to publish, whose push routing IDs the
    // relay reserves before the publish, so no client reads an entry whose
    // routing ID the relay does not yet intercept (§10.7.1 step 2): the node's
    // own entry and every tier 3 entry of `document` with the node's
    // `bridgeTarget`. A tier 3 entry reserves its tier 3 push routing ID,
    // never the bridge relay's own `"scp-push-registration"` ID (§10.7.1
    // "Tier 3 relays"). `seed_from_startup_publish` reserves them on the
    // publisher's own handle, `relay_config.relay_url`, before it publishes.
    let entries = published_state::PublishedEntries::new(&relay_url, &document, bridge_target);

    // 4. Publish the DID document through the node's SINGLE publish seam AND seed
    //    the live slot in ONE step. `seed_from_startup_publish` performs the
    //    publish and constructs the slot carrying the published document and
    //    record together, so a startup publish that does not seed the slot is not
    //    expressible (SCP-RELAYRES-004 AC-6 — the seam's `publish` is uncallable
    //    outside `published_state`). The seam applies the configured DhtMode gate
    //    — skipped for `Disabled` (fail-safe, not discoverable by design), FATAL
    //    on failure for a publishing node (`Production` / test-only `Memory`) so a
    //    genuine startup publish failure fails the node closed rather than
    //    advertising a false discoverability guarantee. The SAME publisher handle
    //    drives the tier-change re-publish below.
    //
    //    Consuming the plain `document` here is deliberate: past this line there
    //    is no copy of it left in scope to hand out, so the tier task, `NodeState`
    //    and the `IdentityHandle` can only receive clones of the slot. See
    //    `LiveSlot`.
    //
    //    The publisher is bound to the live URL handle of `relay_config`, the
    //    configuration this node stores and runs its relay with, so the
    //    reservation `seed_from_startup_publish` makes, and every reservation
    //    the tier task's `apply_tier_change` makes, moves this node's relay.
    //    `seed_from_startup_publish` reserves, then bootstraps the
    //    publish-sequence counter (Production / Memory) so the startup publish
    //    supersedes any live record a prior run left within its TTL instead of
    //    colliding at `seq = 1` (SCP-RELAYRES-004), then publishes.
    let publisher = NodePublisher::new(Arc::clone(&did_method), dht_mode, &relay_config);
    let live_state = seed_from_startup_publish(&publisher, &identity, &entries).await?;

    tracing::info!(
        tier = ?tier,
        relay_url = %relay_url.url(),
        bridge_target = ?relay_url.bridge_target().map(|t| format!("{t:x}")),
        bound_addr = %bound_addr,
        did = %identity.did,
        nat_probe_skipped = skip_nat_probe,
        "application node started (no-domain mode, §10.12.8)"
    );

    // Start this node's self-DID republish cycle (ADR-003 §2). Below every
    // fallible step in this builder, so no `?` leaves arms to tear down.
    let republish = start_node_republish_cycle(&did_method, &live_state).await;

    let (tier_event_tx, tier_event_rx) = tokio::sync::mpsc::channel(16);
    let bg_identity = identity.clone();
    // No tier to re-evaluate when the probe was skipped: the node is reached via
    // a proxy/tunnel, not via a NAT-traversed tier that could change.
    let tier_reeval = if skip_nat_probe {
        None
    } else {
        Some(spawn_tier_reevaluation(
            nat_strategy,
            network_detector,
            publisher,
            bridge_target,
            bg_identity,
            live_state.clone(),
            http_port,
            Some(tier_event_tx),
            TIER_REEVALUATION_INTERVAL,
        ))
    };

    let state = Arc::new(http::NodeState {
        did: identity.did.clone(),
        live_state: live_state.clone(),
        broadcast_contexts: tokio::sync::RwLock::new(HashMap::new()),
        relay_addr: bound_addr,
        bridge_secret,
        dev_token,
        dev_bind_addr,
        projected_contexts: tokio::sync::RwLock::new(HashMap::new()),
        blob_storage,
        relay_config,
        start_time: std::time::Instant::now(),
        http_bind_addr,
        prebound_public: std::sync::Mutex::new(prebound_public),
        shutdown_token: CancellationToken::new(),
        cors_origins,
        projection_rate_limiter: scp_transport::relay::rate_limit::PublishRateLimiter::new(
            projection_rate_limit,
        ),
        projection_ucan_cache: std::sync::RwLock::new(projection::ProjectionUcanCache::new()),
        tls_config: None,
        cert_resolver: None,
        connection_tracker,
        subscription_registry,
        acme_challenges: None,
        hostname_index: tokio::sync::RwLock::new(HashMap::new()),
        default_site_routing_id: std::sync::RwLock::new(None),
        // No-domain mode is plaintext `ws://` (no cert), so QUIC is not served (§10.14.3).
        #[cfg(feature = "quic")]
        publish_rate_limiter,
        #[cfg(feature = "quic")]
        did_slot_registry,
        #[cfg(feature = "quic")]
        quic_server_config: None,
        // No QUIC config means `serve()` never sets this; stays `false`.
        #[cfg(feature = "quic")]
        quic_listening: std::sync::atomic::AtomicBool::new(false),
    });

    Ok(ApplicationNode {
        domain: None,
        relay: RelayHandle {
            bound_addr,
            shutdown_handle: relay_guard.disarm(),
        },
        identity: IdentityHandle::new(identity, live_state),
        storage,
        state,
        // `None` for both when the NAT probe was skipped: there is no
        // re-evaluation task and no tier-change stream to surface.
        tier_change_rx: tier_reeval.as_ref().map(|_| tier_event_rx),
        tier_reeval,
        // HTTP/3 is not supported in no-domain mode (no TLS certificate).
        #[cfg(feature = "http3")]
        http3_config: None,
        serving: Arc::new(AtomicBool::new(false)),
        rate_limit_cleanup_spawned: Arc::new(AtomicBool::new(false)),
        serving_addr: Arc::new(tokio::sync::Mutex::new(None)),
        republish,
    })
}

// ---------------------------------------------------------------------------
// NoOp placeholder types for the default NodeConfig type parameters
// ---------------------------------------------------------------------------

/// Placeholder key custody used as the default type parameter for
/// [`NodeConfig`](crate::NodeConfig). All methods return errors -- callers must
/// provide a real implementation via the config's
/// [`IdentitySource`](crate::IdentitySource).
#[doc(hidden)]
pub struct NoOpCustody;

impl scp_platform::KeyEventSigner for NoOpCustody {
    type Member = scp_platform::KeyHandle;

    fn sign_change(
        &self,
        _member: &scp_platform::KeyHandle,
        _change: &scp_platform::SigningChange,
    ) -> impl std::future::Future<
        Output = Result<scp_platform::IndexedSignature, scp_platform::KeyEventSignError>,
    > + Send {
        std::future::ready(Err(scp_platform::PlatformError::StorageError(
            "NoOpCustody: not configured".to_owned(),
        )
        .into()))
    }

    fn sign_probe(
        &self,
        _member: &scp_platform::KeyHandle,
        _probe: &scp_platform::CustodyProbe,
    ) -> impl std::future::Future<
        Output = Result<scp_platform::ProbeSignature, scp_platform::KeyEventSignError>,
    > + Send {
        std::future::ready(Err(scp_platform::PlatformError::StorageError(
            "NoOpCustody: not configured".to_owned(),
        )
        .into()))
    }
}

impl KeyCustody for NoOpCustody {
    fn generate_key_event_keypair(
        &self,
    ) -> impl std::future::Future<
        Output = Result<scp_platform::KeyHandle, scp_platform::PlatformError>,
    > + Send {
        std::future::ready(Err(scp_platform::PlatformError::StorageError(
            "NoOpCustody: not configured".to_owned(),
        )))
    }

    fn generate_keypair(
        &self,
        _key_type: scp_platform::KeyType,
    ) -> impl std::future::Future<
        Output = Result<scp_platform::KeyHandle, scp_platform::PlatformError>,
    > + Send {
        std::future::ready(Err(scp_platform::PlatformError::StorageError(
            "NoOpCustody: not configured".to_owned(),
        )))
    }

    fn generate_identity_keypair(
        &self,
    ) -> impl std::future::Future<
        Output = Result<scp_platform::KeyHandle, scp_platform::PlatformError>,
    > + Send {
        std::future::ready(Err(scp_platform::PlatformError::StorageError(
            "NoOpCustody: not configured".to_owned(),
        )))
    }

    fn public_key(
        &self,
        _handle: &scp_platform::KeyHandle,
    ) -> impl std::future::Future<
        Output = Result<scp_platform::PublicKey, scp_platform::PlatformError>,
    > + Send {
        std::future::ready(Err(scp_platform::PlatformError::StorageError(
            "NoOpCustody: not configured".to_owned(),
        )))
    }

    fn sign(
        &self,
        _handle: &scp_platform::KeyHandle,
        _data: &[u8],
    ) -> impl std::future::Future<
        Output = Result<scp_platform::Signature, scp_platform::PlatformError>,
    > + Send {
        std::future::ready(Err(scp_platform::PlatformError::StorageError(
            "NoOpCustody: not configured".to_owned(),
        )))
    }

    fn destroy_key(
        &self,
        _handle: &scp_platform::KeyHandle,
    ) -> impl std::future::Future<Output = Result<(), scp_platform::PlatformError>> + Send {
        std::future::ready(Err(scp_platform::PlatformError::StorageError(
            "NoOpCustody: not configured".to_owned(),
        )))
    }

    fn dh_agree(
        &self,
        _handle: &scp_platform::KeyHandle,
        _peer_public: &[u8],
    ) -> impl std::future::Future<
        Output = Result<scp_platform::SharedSecret, scp_platform::PlatformError>,
    > + Send {
        std::future::ready(Err(scp_platform::PlatformError::StorageError(
            "NoOpCustody: not configured".to_owned(),
        )))
    }

    fn derive_pseudonym(
        &self,
        _handle: &scp_platform::KeyHandle,
        _context_id: &[u8],
    ) -> impl std::future::Future<
        Output = Result<scp_platform::Pseudonym, scp_platform::PlatformError>,
    > + Send {
        std::future::ready(Err(scp_platform::PlatformError::StorageError(
            "NoOpCustody: not configured".to_owned(),
        )))
    }

    fn derive_rotatable_pseudonym(
        &self,
        _handle: &scp_platform::KeyHandle,
        _context_id: &[u8],
        _pseudonym_epoch: u64,
    ) -> impl std::future::Future<
        Output = Result<scp_platform::Pseudonym, scp_platform::PlatformError>,
    > + Send {
        std::future::ready(Err(scp_platform::PlatformError::StorageError(
            "NoOpCustody: not configured".to_owned(),
        )))
    }

    fn custody_type(&self, _handle: &scp_platform::KeyHandle) -> scp_platform::CustodyType {
        scp_platform::CustodyType::InMemory
    }
}

/// Placeholder DID method used as the default type parameter for
/// [`NodeConfig`](crate::NodeConfig). All methods return errors -- callers must
/// provide a real implementation.
#[doc(hidden)]
pub struct NoOpDidMethod;

impl DidMethod for NoOpDidMethod {
    /// Every other method here returns an error, so the keep-alive client is the
    /// one that refuses to publish rather than one that would report a false
    /// success: `DisabledDhtClient::publish` returns `DhtError::Disabled`.
    type Dht = scp_dht::DisabledDhtClient;

    fn dht_client(&self) -> Arc<scp_dht::DisabledDhtClient> {
        Arc::new(scp_dht::DisabledDhtClient)
    }

    fn create(
        &self,
        _key_custody: &impl KeyCustody,
        _pre_rotation_custody: &impl scp_platform::PreRotationCustody,
    ) -> impl std::future::Future<
        Output = Result<
            (ScpIdentity, DidDocument, scp_platform::PreRotationKeyHandle),
            IdentityError,
        >,
    > + Send {
        std::future::ready(Err(IdentityError::DhtPublishFailed(
            "NoOpDidMethod: not configured".to_owned(),
        )))
    }

    fn verify(&self, _did_string: &str, _public_key: &[u8]) -> bool {
        false
    }

    fn publish(
        &self,
        _identity: &ScpIdentity,
        _document: &DidDocument,
    ) -> impl std::future::Future<
        Output = Result<scp_identity::republish::RepublishEntry, IdentityError>,
    > + Send {
        // Fails closed with a typed error — never a fabricated signed record.
        std::future::ready(Err(IdentityError::DhtPublishFailed(
            "NoOpDidMethod: not configured".to_owned(),
        )))
    }

    fn resolve(
        &self,
        _did_string: &str,
    ) -> impl std::future::Future<Output = Result<DidDocument, IdentityError>> + Send {
        std::future::ready(Err(IdentityError::DhtResolveFailed(
            "NoOpDidMethod: not configured".to_owned(),
        )))
    }

    fn rotate(
        &self,
        _identity: &ScpIdentity,
        _key_custody: &impl KeyCustody,
    ) -> impl std::future::Future<Output = Result<(ScpIdentity, DidDocument), IdentityError>> + Send
    {
        std::future::ready(Err(IdentityError::KeyRotationFailed(
            "NoOpDidMethod: not configured".to_owned(),
        )))
    }
}

/// Placeholder storage used as the default type parameter for
/// [`NodeConfig`](crate::NodeConfig).
#[doc(hidden)]
#[derive(Debug, Default)]
pub struct NoOpStorage;

impl Storage for NoOpStorage {
    fn store(
        &self,
        _key: &str,
        _data: &[u8],
    ) -> impl std::future::Future<Output = Result<(), scp_platform::PlatformError>> + Send {
        std::future::ready(Ok(()))
    }

    fn retrieve(
        &self,
        _key: &str,
    ) -> impl std::future::Future<Output = Result<Option<Vec<u8>>, scp_platform::PlatformError>> + Send
    {
        std::future::ready(Ok(None))
    }

    fn delete(
        &self,
        _key: &str,
    ) -> impl std::future::Future<Output = Result<(), scp_platform::PlatformError>> + Send {
        std::future::ready(Ok(()))
    }

    fn list_keys(
        &self,
        _prefix: &str,
    ) -> impl std::future::Future<Output = Result<Vec<String>, scp_platform::PlatformError>> + Send
    {
        std::future::ready(Ok(Vec::new()))
    }

    fn delete_prefix(
        &self,
        _prefix: &str,
    ) -> impl std::future::Future<Output = Result<u64, scp_platform::PlatformError>> + Send {
        std::future::ready(Ok(0))
    }

    fn exists(
        &self,
        _key: &str,
    ) -> impl std::future::Future<Output = Result<bool, scp_platform::PlatformError>> + Send {
        std::future::ready(Ok(false))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use scp_transport::relay::push_gate::{LiveRelayUrl, RelayUrl};

    use scp_clock::SystemClock;
    use scp_dht::InMemoryDhtClient;
    use scp_identity::DidCache;
    use scp_identity::dht::DidDht;
    use scp_platform::in_memory::InMemoryStorage;
    use scp_platform::testing::InMemoryKeyCustody;

    /// The concrete `DidDht` type used in tests (with in-memory DHT and system clock).
    type TestDidDht = DidDht<InMemoryDhtClient, SystemClock>;

    /// Creates a `DidDht` instance with signing capability for tests.
    fn make_test_dht(custody: &Arc<InMemoryKeyCustody>) -> TestDidDht {
        let dht_client = Arc::new(InMemoryDhtClient::new());
        let cache = Arc::new(DidCache::new());
        let sign_fn = TestDidDht::make_sign_fn(Arc::clone(custody));
        DidDht::with_client_and_signer(dht_client, cache, sign_fn)
    }

    /// ADR-062 §Decision 6 / SCP-CAPINJECT-006: on a shipped (no-`testing`) build
    /// the production `Node` / self-host identity-generation path has no
    /// pre-rotation custody backend, so it FAILS CLOSED with
    /// [`IdentityError::NoPreRotationBackend`] (surfaced as SCP-IDENT-1059) rather
    /// than minting the in-memory `InMemoryPreRotationCustody` nullifier.
    ///
    /// Gated `#[cfg(not(feature = "testing"))]`: the fail-closed behavior only
    /// holds when the nullifier is severed. `resolve_identity`'s `Generate` arm
    /// mints under `feature = "testing"`; with the feature off (this crate's
    /// standalone `cargo test -p scp-node` build) it returns the typed error. The
    /// test constructs its `Generate` inputs via the dev-dependency in-memory
    /// custody/DHT (available under `test` cfg) — but the fail-closed arm is
    /// selected by the FEATURE, not `test` cfg, so the assertion is real.
    #[cfg(not(feature = "testing"))]
    #[tokio::test]
    async fn pre_rotation_severance_generate_fails_closed() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let did_method = Arc::new(make_test_dht(&custody));
        let source = IdentitySource::Generate {
            custody,
            did_method,
        };
        // The Ok type contains `Arc<DidDht<..>>` which is not `Debug`, so match
        // explicitly rather than `expect_err`.
        match resolve_identity(source).await {
            Err(NodeError::Identity(IdentityError::NoPreRotationBackend)) => {}
            Err(other) => panic!("expected NoPreRotationBackend (SCP-IDENT-1059), got: {other:?}"),
            Ok(_) => panic!(
                "expected fail-closed NoPreRotationBackend, got Ok — the in-memory \
                 pre-rotation nullifier was minted on a shipped-config create path!"
            ),
        }
    }

    /// Companion to the above for the persisting create path
    /// (`resolve_identity_persistent`'s generate branch): it likewise funnels
    /// through the pre-rotation commitment and fails closed on a shipped build.
    #[cfg(not(feature = "testing"))]
    #[tokio::test]
    async fn pre_rotation_severance_persistent_fails_closed() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let did_method = Arc::new(make_test_dht(&custody));
        let source = IdentitySource::Generate {
            custody,
            did_method,
        };
        let storage = InMemoryStorage::new();
        match resolve_identity_persistent(source, true, &storage).await {
            Err(NodeError::Identity(IdentityError::NoPreRotationBackend)) => {}
            Err(other) => panic!("expected NoPreRotationBackend (SCP-IDENT-1059), got: {other:?}"),
            Ok(_) => panic!(
                "expected fail-closed NoPreRotationBackend, got Ok — the in-memory \
                 pre-rotation nullifier was minted on a shipped-config persist create path!"
            ),
        }
    }

    /// Mock TLS provider that succeeds with a self-signed certificate.
    struct SucceedingTlsProvider {
        domain: String,
    }

    impl TlsProvider for SucceedingTlsProvider {
        fn provision(
            &self,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<Output = Result<tls::CertificateData, tls::TlsError>>
                    + Send
                    + '_,
            >,
        > {
            let domain = self.domain.clone();
            Box::pin(async move { tls::generate_self_signed(&domain) })
        }
    }

    /// Mock TLS provider that always fails (simulates ACME failure).
    struct FailingTlsProvider;

    impl TlsProvider for FailingTlsProvider {
        fn provision(
            &self,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<Output = Result<tls::CertificateData, tls::TlsError>>
                    + Send
                    + '_,
            >,
        > {
            Box::pin(async {
                Err(tls::TlsError::Acme(
                    "ACME challenge failed (mock)".to_owned(),
                ))
            })
        }
    }

    /// Builds a domain-mode `NodeConfig` for `test.example.com` with a
    /// succeeding self-signed TLS provider and a fresh generated identity.
    /// The config opts into `DhtMode::Production` (M2 accepts `Disabled` for
    /// every `Reach`, `Reach::Domain` included), so `Node::start` publishes the
    /// identity document to the in-memory `TestDidDht`, which receives it in
    /// process and never reaches live Mainline.
    fn domain_config() -> NodeConfig<InMemoryKeyCustody, TestDidDht, InMemoryStorage> {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let did_method = Arc::new(make_test_dht(&custody));
        NodeConfig {
            bind_addr: Some(SocketAddr::from(([127, 0, 0, 1], 0))),
            dht: DhtMode::Production,
            tls: TlsMode::Custom(Arc::new(SucceedingTlsProvider {
                domain: "test.example.com".to_owned(),
            })),
            ..NodeConfig::defaults(
                Reach::Domain {
                    domain: "test.example.com".to_owned(),
                },
                IdentitySource::Generate {
                    custody,
                    did_method,
                },
                InMemoryStorage::new(),
                BlobStorageBackend::in_memory(),
            )
        }
    }

    /// Helper: creates an identity and document for explicit identity tests.
    async fn create_test_identity() -> (ScpIdentity, DidDocument, Arc<InMemoryKeyCustody>) {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let pre_rotation_custody = scp_platform::testing::InMemoryPreRotationCustody::new();
        let did_dht = make_test_dht(&custody);
        let (identity, document, _pre_rotation_handle) = did_dht
            .create(&*custody, &pre_rotation_custody)
            .await
            .unwrap();
        (identity, document, custody)
    }

    #[tokio::test]
    async fn build_with_generate_identity_creates_new_did() {
        let node = Node::start_for_testing(domain_config()).await.unwrap();

        // Verify the identity was created.
        assert!(
            node.identity().did().starts_with("did:dht:"),
            "DID should start with did:dht:, got: {}",
            node.identity().did()
        );

        // Verify the DID document has an SCPRelay entry.
        let relay_urls = node.identity().document().relay_service_urls();
        assert_eq!(relay_urls.len(), 1);
        assert_eq!(relay_urls[0], "wss://test.example.com/scp/v1");

        // Verify accessors work.
        assert_eq!(node.domain(), Some("test.example.com"));
        assert_eq!(node.relay_url(), "wss://test.example.com/scp/v1");

        // Verify relay is actually bound.
        let addr = node.relay().bound_addr();
        assert_ne!(addr.port(), 0, "relay should be bound to a real port");
    }

    #[tokio::test]
    async fn build_with_explicit_identity_uses_provided_identity() {
        let (identity, document, custody) = create_test_identity().await;
        let original_did = identity.did.clone();
        let did_method = Arc::new(make_test_dht(&custody));

        let node = Node::start_for_testing(NodeConfig {
            bind_addr: Some(SocketAddr::from(([127, 0, 0, 1], 0))),
            dht: DhtMode::Production,
            tls: TlsMode::Custom(Arc::new(SucceedingTlsProvider {
                domain: "explicit.example.com".to_owned(),
            })),
            ..NodeConfig::defaults(
                Reach::Domain {
                    domain: "explicit.example.com".to_owned(),
                },
                IdentitySource::<InMemoryKeyCustody, TestDidDht>::Explicit(Box::new(
                    ExplicitIdentity {
                        identity,
                        document,
                        did_method,
                    },
                )),
                InMemoryStorage::new(),
                BlobStorageBackend::in_memory(),
            )
        })
        .await
        .unwrap();

        // Verify the original DID is preserved.
        assert_eq!(node.identity().did(), original_did);

        // Verify the relay URL is in the document.
        let relay_urls = node.identity().document().relay_service_urls();
        assert!(
            relay_urls.contains(&"wss://explicit.example.com/scp/v1".to_owned()),
            "expected relay URL in document, got: {relay_urls:?}"
        );
    }

    #[tokio::test]
    async fn did_publication_happens_once_on_build() {
        use std::sync::atomic::{AtomicU32, Ordering};

        // Create a DID method that counts publish calls.
        struct CountingDidMethod {
            inner: TestDidDht,
            publish_count: Arc<AtomicU32>,
        }

        impl DidMethod for CountingDidMethod {
            /// These doubles observe what the builders publish; none of them
            /// keeps a record alive, so the keep-alive client is the fail-closed
            /// `DisabledDhtClient` rather than one that would report a false
            /// publish success.
            type Dht = scp_dht::DisabledDhtClient;

            fn dht_client(&self) -> Arc<scp_dht::DisabledDhtClient> {
                Arc::new(scp_dht::DisabledDhtClient)
            }

            fn create(
                &self,
                key_custody: &impl KeyCustody,
                pre_rotation_custody: &impl scp_platform::PreRotationCustody,
            ) -> impl std::future::Future<
                Output = Result<
                    (ScpIdentity, DidDocument, scp_platform::PreRotationKeyHandle),
                    IdentityError,
                >,
            > + Send {
                self.inner.create(key_custody, pre_rotation_custody)
            }

            fn verify(&self, did_string: &str, public_key: &[u8]) -> bool {
                self.inner.verify(did_string, public_key)
            }

            fn publish(
                &self,
                identity: &ScpIdentity,
                document: &DidDocument,
            ) -> impl std::future::Future<
                Output = Result<scp_identity::republish::RepublishEntry, IdentityError>,
            > + Send {
                self.publish_count.fetch_add(1, Ordering::SeqCst);
                self.inner.publish(identity, document)
            }

            fn resolve(
                &self,
                did_string: &str,
            ) -> impl std::future::Future<Output = Result<DidDocument, IdentityError>> + Send
            {
                self.inner.resolve(did_string)
            }

            fn rotate(
                &self,
                identity: &ScpIdentity,
                key_custody: &impl KeyCustody,
            ) -> impl std::future::Future<
                Output = Result<(ScpIdentity, DidDocument), IdentityError>,
            > + Send {
                self.inner.rotate(identity, key_custody)
            }
        }

        let custody = Arc::new(InMemoryKeyCustody::new());
        let publish_count = Arc::new(AtomicU32::new(0));
        let counting_method = Arc::new(CountingDidMethod {
            inner: make_test_dht(&custody),
            publish_count: Arc::clone(&publish_count),
        });

        let _node = Node::start_for_testing(NodeConfig {
            bind_addr: Some(SocketAddr::from(([127, 0, 0, 1], 0))),
            dht: DhtMode::Production,
            tls: TlsMode::Custom(Arc::new(SucceedingTlsProvider {
                domain: "counting.example.com".to_owned(),
            })),
            ..NodeConfig::defaults(
                Reach::Domain {
                    domain: "counting.example.com".to_owned(),
                },
                IdentitySource::Generate {
                    custody,
                    did_method: counting_method,
                },
                InMemoryStorage::new(),
                BlobStorageBackend::in_memory(),
            )
        })
        .await
        .unwrap();

        // Verify publish was called exactly once during build.
        assert_eq!(
            publish_count.load(Ordering::SeqCst),
            1,
            "DID should be published exactly once on build"
        );
    }

    #[tokio::test]
    async fn relay_accepts_connections_with_valid_bridge_token() {
        use tokio_tungstenite::tungstenite::client::IntoClientRequest;

        let node = Node::start_for_testing(domain_config()).await.unwrap();

        let addr = node.relay().bound_addr();
        let token = node.bridge_token_hex();

        // Connect with the bridge token in the Authorization header (#225).
        let url = format!("ws://{addr}/");
        let mut request = url.into_client_request().unwrap();
        request.headers_mut().insert(
            "Authorization",
            format!("Bearer {}", token.as_str()).parse().unwrap(),
        );
        let connect_result = tokio_tungstenite::connect_async(request).await;

        assert!(
            connect_result.is_ok(),
            "relay should accept connections with valid bridge token, got error: {:?}",
            connect_result.err()
        );
    }

    #[tokio::test]
    async fn relay_rejects_connections_without_bridge_token() {
        let node = Node::start_for_testing(domain_config()).await.unwrap();

        let addr = node.relay().bound_addr();

        // Connect without the Authorization header — should be rejected.
        let url = format!("ws://{addr}/");
        let connect_result = tokio_tungstenite::connect_async(&url).await;

        assert!(
            connect_result.is_err(),
            "relay should reject connections without bridge token"
        );
    }

    #[tokio::test]
    async fn relay_binds_before_did_publish() {
        use std::sync::atomic::{AtomicBool, Ordering};

        // A DID method that records whether `publish()` was called.
        struct PublishRecorder {
            inner: TestDidDht,
            published: Arc<AtomicBool>,
        }

        impl DidMethod for PublishRecorder {
            /// These doubles observe what the builders publish; none of them
            /// keeps a record alive, so the keep-alive client is the fail-closed
            /// `DisabledDhtClient` rather than one that would report a false
            /// publish success.
            type Dht = scp_dht::DisabledDhtClient;

            fn dht_client(&self) -> Arc<scp_dht::DisabledDhtClient> {
                Arc::new(scp_dht::DisabledDhtClient)
            }

            fn create(
                &self,
                key_custody: &impl KeyCustody,
                pre_rotation_custody: &impl scp_platform::PreRotationCustody,
            ) -> impl std::future::Future<
                Output = Result<
                    (ScpIdentity, DidDocument, scp_platform::PreRotationKeyHandle),
                    IdentityError,
                >,
            > + Send {
                self.inner.create(key_custody, pre_rotation_custody)
            }

            fn verify(&self, did_string: &str, public_key: &[u8]) -> bool {
                self.inner.verify(did_string, public_key)
            }

            fn publish(
                &self,
                identity: &ScpIdentity,
                document: &DidDocument,
            ) -> impl std::future::Future<
                Output = Result<scp_identity::republish::RepublishEntry, IdentityError>,
            > + Send {
                self.published.store(true, Ordering::SeqCst);
                self.inner.publish(identity, document)
            }

            fn resolve(
                &self,
                did_string: &str,
            ) -> impl std::future::Future<Output = Result<DidDocument, IdentityError>> + Send
            {
                self.inner.resolve(did_string)
            }

            fn rotate(
                &self,
                identity: &ScpIdentity,
                key_custody: &impl KeyCustody,
            ) -> impl std::future::Future<
                Output = Result<(ScpIdentity, DidDocument), IdentityError>,
            > + Send {
                self.inner.rotate(identity, key_custody)
            }
        }

        // Starts a domain node whose relay binds `bind_addr`, publishing through
        // a recorder. Returns the start result and whether `publish()` ran.
        async fn start_recording(bind_addr: SocketAddr) -> (Result<(), NodeError>, bool) {
            let custody = Arc::new(InMemoryKeyCustody::new());
            let published = Arc::new(AtomicBool::new(false));
            let recorder = Arc::new(PublishRecorder {
                inner: make_test_dht(&custody),
                published: Arc::clone(&published),
            });
            let result = Node::start_for_testing(NodeConfig {
                bind_addr: Some(bind_addr),
                dht: DhtMode::Production,
                tls: TlsMode::Custom(Arc::new(SucceedingTlsProvider {
                    domain: "relay-order.example.com".to_owned(),
                })),
                ..NodeConfig::defaults(
                    Reach::Domain {
                        domain: "relay-order.example.com".to_owned(),
                    },
                    IdentitySource::Generate {
                        custody,
                        did_method: recorder,
                    },
                    InMemoryStorage::new(),
                    BlobStorageBackend::in_memory(),
                )
            })
            .await
            .map(drop);
            (result, published.load(Ordering::SeqCst))
        }

        // The ordering proof: hold the relay's address for the whole start, so
        // the relay bind fails. If the start published before binding the
        // relay, `publish()` would already have run when the bind failed.
        // Holding the listener (never dropping it before the start) leaves no
        // window for another socket to take the port.
        let held = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let held_addr = held.local_addr().unwrap();
        let (result, published) = start_recording(held_addr).await;
        assert!(
            result.is_err(),
            "a relay whose address is held must fail the start"
        );
        assert!(
            !published,
            "the relay must bind BEFORE the DID document is published"
        );
        drop(held);

        // Control: with a free relay address the same start publishes, so the
        // recorder observes `publish()` and the assertion above is not vacuous.
        let (result, published) = start_recording(SocketAddr::from(([127, 0, 0, 1], 0))).await;
        result.expect("a node whose relay can bind must start");
        assert!(
            published,
            "a started domain node must publish its DID document"
        );
    }

    #[tokio::test]
    async fn start_for_testing_with_custom_storage() {
        let node = Node::start_for_testing(domain_config()).await.unwrap();

        // Verify the storage handle is accessible.
        let _storage = node.storage();
    }

    // -- No-domain / NAT traversal tests (SCP-235) ---------------------------

    /// Mock NAT strategy that returns a pre-configured tier.
    struct MockNatStrategy {
        tier: ReachabilityTier,
    }

    impl NatStrategy for MockNatStrategy {
        fn select_tier(
            &self,
            _relay_port: u16,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<ReachabilityTier, NodeError>> + Send + '_>,
        > {
            let tier = self.tier.clone();
            Box::pin(async move { Ok(tier) })
        }
    }

    /// Mock NAT strategy that always fails.
    struct FailingNatStrategy;

    impl NatStrategy for FailingNatStrategy {
        fn select_tier(
            &self,
            _relay_port: u16,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<ReachabilityTier, NodeError>> + Send + '_>,
        > {
            Box::pin(async { Err(NodeError::Nat("all tiers failed".into())) })
        }
    }

    /// Builds a no-domain (`Reach::NatTraversal`) `NodeConfig` whose NAT probe
    /// is a `MockNatStrategy` returning `tier` (no real STUN). The config opts
    /// into `DhtMode::Production` (M2 accepts `Disabled` for every `Reach`,
    /// `NatTraversal` included).
    fn no_domain_config(
        tier: ReachabilityTier,
    ) -> NodeConfig<InMemoryKeyCustody, TestDidDht, InMemoryStorage> {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let did_method = Arc::new(make_test_dht(&custody));
        NodeConfig {
            bind_addr: Some(SocketAddr::from(([127, 0, 0, 1], 0))),
            dht: DhtMode::Production,
            nat: NatSlot::Custom(Arc::new(MockNatStrategy { tier })),
            ..NodeConfig::defaults(
                Reach::NatTraversal,
                IdentitySource::Generate {
                    custody,
                    did_method,
                },
                InMemoryStorage::new(),
                BlobStorageBackend::in_memory(),
            )
        }
    }

    #[tokio::test]
    async fn no_domain_build_skips_tls_and_publishes_ws_url() {
        // AC: Reach::NatTraversal build skips TLS and publishes ws:// URL.
        let external_addr = SocketAddr::from(([198, 51, 100, 7], 32891));
        let tier = ReachabilityTier::Stun { external_addr };

        let node = Node::start_for_testing(no_domain_config(tier))
            .await
            .unwrap();

        // Verify no domain is set.
        assert!(
            node.domain().is_none(),
            "no-domain mode should have None domain"
        );

        // Verify the relay URL uses ws:// (not wss://).
        assert!(
            node.relay_url().starts_with("ws://"),
            "no-domain mode should publish ws:// URL, got: {}",
            node.relay_url()
        );
        assert_eq!(node.relay_url(), "ws://198.51.100.7:32891/scp/v1");

        // Verify the DID document has the ws:// relay entry.
        let relay_urls = node.identity().document().relay_service_urls();
        assert_eq!(relay_urls.len(), 1);
        assert_eq!(relay_urls[0], "ws://198.51.100.7:32891/scp/v1");

        // Verify identity was created.
        assert!(
            node.identity().did().starts_with("did:dht:"),
            "DID should start with did:dht:"
        );

        // Verify relay is bound.
        assert_ne!(node.relay().bound_addr().port(), 0);
    }

    /// Tier 3 publishes the bridge relay's own URL as `serviceEndpoint` and the
    /// node's routing ID as `bridgeTarget` (§10.12.7, §18.2.1), and that target
    /// is the routing ID a bridge relay admits this node's `BRIDGE_REGISTER`
    /// at: `verify_bridge_registration` accepts a registration signed by the
    /// node's identity key whose routing ID is the published target.
    ///
    /// The target is `did_routing_id(did)` until SCP-315 moves both the
    /// publisher and `verify_bridge_registration` to §10.12.4.1's value; the
    /// check through the verifier keeps the two in step across that move.
    #[tokio::test]
    async fn no_domain_build_with_bridge_publishes_bridge_target() {
        use scp_platform::KeyCustody as _;
        use scp_transport::relay::bridge::{
            BridgeRegistration, bridge_register_signable, verify_bridge_registration,
        };

        const BRIDGE_URL: &str = "wss://bridge.example.com/scp/v1";
        let tier = ReachabilityTier::Bridge {
            bridge_url: scp_did::BridgeEndpoint::new(BRIDGE_URL).unwrap(),
        };
        let custody = Arc::new(InMemoryKeyCustody::new());
        let did_method = Arc::new(make_test_dht(&custody));
        let config: NodeConfig<InMemoryKeyCustody, TestDidDht, InMemoryStorage> = NodeConfig {
            bind_addr: Some(SocketAddr::from(([127, 0, 0, 1], 0))),
            dht: DhtMode::Production,
            nat: NatSlot::Custom(Arc::new(MockNatStrategy { tier })),
            ..NodeConfig::defaults(
                Reach::NatTraversal,
                IdentitySource::Generate {
                    custody: Arc::clone(&custody),
                    did_method,
                },
                InMemoryStorage::new(),
                BlobStorageBackend::in_memory(),
            )
        };

        let node = Node::start_for_testing(config).await.unwrap();

        assert_eq!(
            node.relay_url(),
            BRIDGE_URL,
            "no query on the published URL"
        );
        let entry = node
            .identity()
            .document()
            .service
            .iter()
            .find(|s| s.service_type == scp_did::SCP_RELAY_SERVICE_TYPE)
            .cloned()
            .expect("the document carries an SCPRelay entry");
        assert_eq!(entry.service_endpoint, BRIDGE_URL);
        let target = entry
            .bridge_target
            .expect("a tier 3 entry carries bridgeTarget");

        // A BRIDGE_REGISTER at the published target, signed by the node's key.
        let key = &node.identity().identity().identity_key;
        let public_key: [u8; 32] = custody
            .public_key(key)
            .await
            .unwrap()
            .as_bytes()
            .try_into()
            .expect("an Ed25519 identity key");
        let timestamp = 1_700_000_000;
        let signature: [u8; 64] = custody
            .sign(key, &bridge_register_signable(&target, timestamp))
            .await
            .unwrap()
            .as_bytes()
            .try_into()
            .expect("an Ed25519 signature");
        let registration = BridgeRegistration {
            routing_id: target,
            public_key,
            signature,
            timestamp,
        };
        verify_bridge_registration(&registration, timestamp)
            .expect("the bridge relay admits the node at its published bridgeTarget");

        // The re-read document reports the same entry.
        assert_eq!(
            node.identity().document().relay_services(),
            [scp_did::RelayService::bridge(
                scp_did::BridgeEndpoint::new(BRIDGE_URL).unwrap(),
                scp_did::BridgeTarget::new(target).unwrap(),
            )]
        );
    }

    /// A domain with no §9.18.2 canonical relay URL fails `Node::start` with a
    /// typed error instead of publishing a relay entry no reader accepts.
    #[tokio::test]
    async fn node_start_rejects_a_non_ascii_domain() {
        const DOMAIN: &str = "bücher.example";
        let custody = Arc::new(InMemoryKeyCustody::new());
        let did_method = Arc::new(make_test_dht(&custody));
        let config: NodeConfig<InMemoryKeyCustody, TestDidDht, InMemoryStorage> = NodeConfig {
            bind_addr: Some(SocketAddr::from(([127, 0, 0, 1], 0))),
            dht: DhtMode::Production,
            tls: TlsMode::Custom(Arc::new(SucceedingTlsProvider {
                domain: DOMAIN.to_owned(),
            })),
            ..NodeConfig::defaults(
                Reach::Domain {
                    domain: DOMAIN.to_owned(),
                },
                IdentitySource::Generate {
                    custody,
                    did_method,
                },
                InMemoryStorage::new(),
                BlobStorageBackend::in_memory(),
            )
        };

        let result = Node::start_for_testing(config).await;

        assert!(
            matches!(
                &result,
                Err(NodeError::InvalidConfig(msg)) if msg.contains(DOMAIN)
            ),
            "a non-ASCII domain must fail Node::start with InvalidConfig naming the domain, got {:?}",
            result.err()
        );
    }

    #[tokio::test]
    async fn no_domain_build_with_upnp_tier_publishes_ws_url() {
        // AC: Tier 1 (UPnP) publishes ws:// URL.
        let external_addr = SocketAddr::from(([203, 0, 113, 42], 8443));
        let tier = ReachabilityTier::Upnp { external_addr };

        let node = Node::start_for_testing(no_domain_config(tier))
            .await
            .unwrap();

        assert_eq!(node.relay_url(), "ws://203.0.113.42:8443/scp/v1");
    }

    // -----------------------------------------------------------------------
    // No-domain publish asymmetry: `DhtMode::Production` fails closed on a
    // genuine publish failure; `DhtMode::Disabled` starts without publishing.
    // (P3 fail-closed fix — a Production node must never report a healthy start
    // while its DID is NOT on the DHT.)
    // -----------------------------------------------------------------------

    /// A `DidMethod` spy whose `publish` **always fails** — simulating a genuine
    /// Pkarr network / timeout / rate-limit error — and records whether publish
    /// was attempted at all. `create` / `verify` / `resolve` / `rotate` delegate
    /// to an inner `TestDidDht` so identity creation still succeeds.
    struct FailingPublishDidMethod {
        inner: TestDidDht,
        publish_attempts: Arc<std::sync::atomic::AtomicU32>,
    }

    impl DidMethod for FailingPublishDidMethod {
        /// These doubles observe what the builders publish; none of them
        /// keeps a record alive, so the keep-alive client is the fail-closed
        /// `DisabledDhtClient` rather than one that would report a false
        /// publish success.
        type Dht = scp_dht::DisabledDhtClient;

        fn dht_client(&self) -> Arc<scp_dht::DisabledDhtClient> {
            Arc::new(scp_dht::DisabledDhtClient)
        }

        fn create(
            &self,
            key_custody: &impl KeyCustody,
            pre_rotation_custody: &impl scp_platform::PreRotationCustody,
        ) -> impl std::future::Future<
            Output = Result<
                (ScpIdentity, DidDocument, scp_platform::PreRotationKeyHandle),
                IdentityError,
            >,
        > + Send {
            self.inner.create(key_custody, pre_rotation_custody)
        }

        fn verify(&self, did_string: &str, public_key: &[u8]) -> bool {
            self.inner.verify(did_string, public_key)
        }

        fn publish(
            &self,
            _identity: &ScpIdentity,
            _document: &DidDocument,
        ) -> impl std::future::Future<
            Output = Result<scp_identity::republish::RepublishEntry, IdentityError>,
        > + Send {
            self.publish_attempts
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            std::future::ready(Err(IdentityError::DhtPublishFailed(
                "simulated Pkarr publish failure (network/timeout/rate-limit)".to_owned(),
            )))
        }

        fn resolve(
            &self,
            did_string: &str,
        ) -> impl std::future::Future<Output = Result<DidDocument, IdentityError>> + Send {
            self.inner.resolve(did_string)
        }

        fn rotate(
            &self,
            identity: &ScpIdentity,
            key_custody: &impl KeyCustody,
        ) -> impl std::future::Future<Output = Result<(ScpIdentity, DidDocument), IdentityError>> + Send
        {
            self.inner.rotate(identity, key_custody)
        }
    }

    /// Builds a no-domain (`Reach::NatTraversal`) config whose DID method's
    /// `publish` always fails, with an explicit `DhtMode`. Returns the config and
    /// the shared publish-attempt counter so tests can assert whether publish was
    /// attempted.
    fn failing_publish_no_domain_config(
        dht: DhtMode,
    ) -> (
        NodeConfig<InMemoryKeyCustody, FailingPublishDidMethod, InMemoryStorage>,
        Arc<std::sync::atomic::AtomicU32>,
    ) {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let publish_attempts = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let did_method = Arc::new(FailingPublishDidMethod {
            inner: make_test_dht(&custody),
            publish_attempts: Arc::clone(&publish_attempts),
        });
        // A resolvable NAT tier so the build reaches the publish step (the NAT
        // probe succeeds; only the DHT publish fails).
        let tier = ReachabilityTier::Stun {
            external_addr: SocketAddr::from(([198, 51, 100, 7], 32891)),
        };
        let config = NodeConfig {
            bind_addr: Some(SocketAddr::from(([127, 0, 0, 1], 0))),
            dht,
            nat: NatSlot::Custom(Arc::new(MockNatStrategy { tier })),
            ..NodeConfig::defaults(
                Reach::NatTraversal,
                IdentitySource::Generate {
                    custody,
                    did_method,
                },
                InMemoryStorage::new(),
                BlobStorageBackend::in_memory(),
            )
        };
        (config, publish_attempts)
    }

    #[tokio::test]
    async fn no_domain_production_publish_failure_fails_closed() {
        // A `DhtMode::Production` no-domain node whose DID publish genuinely
        // FAILS must NOT report a healthy start — it fails closed so it never
        // advertises a false discoverability guarantee.
        let (config, publish_attempts) = failing_publish_no_domain_config(DhtMode::Production);

        let err = Node::start_for_testing(config)
            .await
            .err()
            .expect("Production no-domain start must fail closed when DID publish fails");

        assert!(
            matches!(err, NodeError::Identity(IdentityError::DhtPublishFailed(_))),
            "expected a fatal NodeError::Identity(DhtPublishFailed), got: {err:?}"
        );
        assert_eq!(
            publish_attempts.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "Production must attempt the DID publish exactly once (and fail closed on error)"
        );
    }

    #[tokio::test]
    async fn no_domain_disabled_starts_without_publishing() {
        // A `DhtMode::Disabled` node must start cleanly WITHOUT attempting to
        // publish — even when the underlying DID method's publish would error.
        let (config, publish_attempts) = failing_publish_no_domain_config(DhtMode::Disabled);

        let node = Node::start_for_testing(config)
            .await
            .expect("a Disabled node must start cleanly even when publish would error");

        assert_eq!(
            publish_attempts.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "Disabled must NOT attempt to publish the DID document (not discoverable by design)"
        );
        // The node is genuinely up (relay bound) — just not DHT-published.
        assert!(
            node.domain().is_none(),
            "no-domain mode should have None domain"
        );
        assert_ne!(
            node.relay().bound_addr().port(),
            0,
            "relay should be bound to a real port"
        );
        // B2: the absence is HONEST — the node published nothing, so it carries
        // no signed record. Nothing is fabricated in its place, and the
        // downstream republish cycle reads exactly this to stay dormant.
        assert!(
            node.published_did_record().is_none(),
            "a Disabled node published nothing, so it holds no signed record"
        );
    }

    /// B2: a node that DOES publish carries the signed BEP44 record its own
    /// publish produced — so nothing downstream has to reconstruct the
    /// `(value, signature, seq)` triple by reading it back off the network.
    ///
    /// The returned record is checked against the node's DID-derived key, so a
    /// fabricated or mismatched record cannot pass.
    #[cfg(feature = "testing")]
    #[tokio::test]
    async fn publishing_node_carries_its_own_signed_record() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let did_method = Arc::new(make_test_dht(&custody));
        // A resolvable NAT tier so the build reaches the publish step.
        let tier = ReachabilityTier::Stun {
            external_addr: SocketAddr::from(([198, 51, 100, 9], 32893)),
        };
        let config = NodeConfig {
            bind_addr: Some(SocketAddr::from(([127, 0, 0, 1], 0))),
            dht: DhtMode::Memory,
            nat: NatSlot::Custom(Arc::new(MockNatStrategy { tier })),
            ..NodeConfig::defaults(
                Reach::NatTraversal,
                IdentitySource::Generate {
                    custody,
                    did_method,
                },
                InMemoryStorage::new(),
                BlobStorageBackend::in_memory(),
            )
        };

        let node = Node::start_for_testing(config)
            .await
            .expect("a publishing node starts");

        let record = node
            .published_did_record()
            .expect("a publishing node carries the record it signed");

        // The record is genuinely this node's: its key derives the node's DID,
        // and its (value, seq) BEP44-verify under that key.
        assert_eq!(
            record.did(),
            node.identity().did(),
            "the record's key derives THIS node's DID"
        );
        scp_dht::verify_bep44_signature(
            &record.public_key,
            &record.signature,
            &record.document_bytes,
            record.sequence,
        )
        .expect("the carried record BEP44-verifies against the node's own key");
        assert!(
            record.sequence >= 1,
            "a published record carries the sequence its publish assigned"
        );
    }

    /// SCP-RELAYRES-004: a node RESTART within the record TTL must SUPERSEDE the
    /// live `seq = N` record its prior run published, not collide beneath it at
    /// `seq = 1`.
    ///
    /// `seed_from_startup_publish` bootstraps the publish-sequence counter
    /// (`initialize_sequence_for_mode`) BEFORE the startup publish, so the
    /// restart's `seed_from_startup_publish` emits `seq = N + 1`. Against the
    /// pre-fix code — which bootstrapped the counter only AFTER `Node::start`
    /// (or self-host build) had already published — this fails: a fresh
    /// `AtomicU64::new(0)` published `seq = 1` beneath the live `seq = N`.
    #[cfg(feature = "testing")]
    #[tokio::test]
    async fn restart_startup_publish_supersedes_live_record_not_seq_1() {
        use scp_platform::testing::InMemoryPreRotationCustody;

        // The live record the prior run leaves behind sits at seq = N.
        const N: u64 = 5;

        let custody = Arc::new(InMemoryKeyCustody::new());
        let cache = Arc::new(DidCache::new());
        // ONE shared in-memory DHT client stands in for the live Mainline record
        // that survives a restart within TTL: both the "prior run" and the
        // "restart" DID methods publish into / resolve from it.
        let shared_dht = Arc::new(InMemoryDhtClient::new());

        // Create the node's identity ONCE; the restart reuses it verbatim via
        // `IdentitySource::Explicit` (a restart keeps the same DID).
        let prior_method = Arc::new(DidDht::with_client_and_signer(
            Arc::clone(&shared_dht),
            Arc::clone(&cache),
            TestDidDht::make_sign_fn(Arc::clone(&custody)),
        ));
        let pre_rotation = InMemoryPreRotationCustody::new();
        let (identity, document, _handle) = prior_method
            .create(&*custody, &pre_rotation)
            .await
            .expect("identity creation succeeds");

        // Simulate the prior run: drive the shared live record up to seq = N.
        let mut last_seq = 0;
        for _ in 0..N {
            last_seq = prior_method
                .publish(&identity, &document)
                .await
                .expect("prior-run publish succeeds")
                .sequence;
        }
        assert_eq!(last_seq, N, "prior run left the live record at seq = N");

        // RESTART: a FRESH DID method over the SAME shared DHT client — its
        // sequence counter starts at `AtomicU64::new(0)`, exactly as a restarted
        // process's would.
        let restart_method = Arc::new(DidDht::with_client_and_signer(
            Arc::clone(&shared_dht),
            Arc::clone(&cache),
            TestDidDht::make_sign_fn(Arc::clone(&custody)),
        ));

        let tier = ReachabilityTier::Stun {
            external_addr: SocketAddr::from(([198, 51, 100, 9], 32893)),
        };
        let config: NodeConfig<InMemoryKeyCustody, TestDidDht, InMemoryStorage> = NodeConfig {
            bind_addr: Some(SocketAddr::from(([127, 0, 0, 1], 0))),
            dht: DhtMode::Memory,
            nat: NatSlot::Custom(Arc::new(MockNatStrategy { tier })),
            ..NodeConfig::defaults(
                Reach::NatTraversal,
                IdentitySource::Explicit(Box::new(ExplicitIdentity {
                    identity: identity.clone(),
                    document: document.clone(),
                    did_method: restart_method,
                })),
                InMemoryStorage::new(),
                BlobStorageBackend::in_memory(),
            )
        };

        let node = Node::start_for_testing(config)
            .await
            .expect("the restarted node starts");

        let record = node
            .published_did_record()
            .expect("the restarted node carries the record it signed");

        // The fix: the startup publish superseded the live record at seq = N + 1.
        // Without `initialize_sequence` before the startup publish the fresh counter would
        // have published seq = 1, colliding beneath the live seq = N record.
        assert_eq!(
            record.sequence,
            N + 1,
            "restart must supersede the live record at seq = N+1, not collide at seq = 1"
        );
        assert_eq!(
            record.did(),
            node.identity().did(),
            "the record's key derives THIS (restarted) node's DID"
        );
        scp_dht::verify_bep44_signature(
            &record.public_key,
            &record.signature,
            &record.document_bytes,
            record.sequence,
        )
        .expect("the superseding record BEP44-verifies against the node's own key");
    }

    // -----------------------------------------------------------------------
    // Domain-success publish honors DhtMode (R2-2). `build_domain_inner` (the
    // TLS-provisioning-SUCCESS `Reach::Domain` path) previously published
    // unconditionally + fatally, ignoring `config.dht`; now it routes through
    // `publish_did_document_for_mode`, so `DhtMode::Disabled` — a legitimate
    // more-private `Domain + Disabled` config (construction.md M2 :63/:194) —
    // starts the node WITHOUT publishing, and `Production` still publishes
    // fatally. `Domain + Disabled` is NEVER rejected.
    // -----------------------------------------------------------------------

    /// Builds a `Reach::Domain` config (with a succeeding self-signed TLS
    /// provider so the build reaches `build_domain_inner`) whose DID method's
    /// `publish` always fails, with an explicit `DhtMode`. Returns the config and
    /// the shared publish-attempt counter.
    fn failing_publish_domain_config(
        dht: DhtMode,
    ) -> (
        NodeConfig<InMemoryKeyCustody, FailingPublishDidMethod, InMemoryStorage>,
        Arc<std::sync::atomic::AtomicU32>,
    ) {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let publish_attempts = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let did_method = Arc::new(FailingPublishDidMethod {
            inner: make_test_dht(&custody),
            publish_attempts: Arc::clone(&publish_attempts),
        });
        let config = NodeConfig {
            bind_addr: Some(SocketAddr::from(([127, 0, 0, 1], 0))),
            dht,
            tls: TlsMode::Custom(Arc::new(SucceedingTlsProvider {
                domain: "test.example.com".to_owned(),
            })),
            ..NodeConfig::defaults(
                Reach::Domain {
                    domain: "test.example.com".to_owned(),
                },
                IdentitySource::Generate {
                    custody,
                    did_method,
                },
                InMemoryStorage::new(),
                BlobStorageBackend::in_memory(),
            )
        };
        (config, publish_attempts)
    }

    #[tokio::test]
    async fn domain_disabled_starts_without_publishing() {
        // A `Domain + DhtMode::Disabled` node (TLS provisioned) must start
        // cleanly WITHOUT attempting to publish — even when the DID method's
        // publish would error. This is the legitimate more-private config
        // (reachable via the domain, address NOT DHT-published); M2 forbids
        // rejecting it.
        let (config, publish_attempts) = failing_publish_domain_config(DhtMode::Disabled);

        let node = Node::start_for_testing(config)
            .await
            .expect("a Domain + Disabled node must start cleanly (publish is SKIPPED, not fatal)");

        assert_eq!(
            publish_attempts.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "Domain + Disabled must NOT attempt to publish the DID document"
        );
        // The node is genuinely up in domain mode (TLS active, relay bound).
        assert_eq!(node.domain(), Some("test.example.com"));
        assert_ne!(
            node.relay().bound_addr().port(),
            0,
            "relay should be bound to a real port"
        );
    }

    #[tokio::test]
    async fn domain_production_publish_failure_fails_closed() {
        // A `Domain + DhtMode::Production` node whose DID publish genuinely FAILS
        // must fail closed — the domain-success path publishes fatally, never
        // reporting a healthy start while the DID is NOT on the DHT.
        let (config, publish_attempts) = failing_publish_domain_config(DhtMode::Production);

        let err = Node::start_for_testing(config)
            .await
            .err()
            .expect("Domain + Production start must fail closed when DID publish fails");

        assert!(
            matches!(err, NodeError::Identity(IdentityError::DhtPublishFailed(_))),
            "expected a fatal NodeError::Identity(DhtPublishFailed), got: {err:?}"
        );
        assert_eq!(
            publish_attempts.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "Production must attempt the DID publish exactly once (and fail closed on error)"
        );
    }

    #[tokio::test]
    async fn no_domain_does_not_serve_well_known() {
        // AC: .well-known/scp is NOT served in no-domain mode.
        // The node is created without a domain, so there is nothing
        // to serve .well-known/scp from. The well_known_router still
        // works as an axum router, but conceptually this node should
        // NOT be served on a public HTTP endpoint for .well-known.
        // We verify the domain is None, which is the gate for deciding
        // whether to serve .well-known.
        let tier = ReachabilityTier::Stun {
            external_addr: SocketAddr::from(([198, 51, 100, 7], 32891)),
        };

        let node = Node::start_for_testing(no_domain_config(tier))
            .await
            .unwrap();

        assert!(
            node.domain().is_none(),
            "no-domain mode: domain must be None to prevent .well-known/scp serving"
        );
    }

    #[tokio::test]
    async fn domain_fallthrough_on_acme_failure_probes_nat() {
        // AC9: When Reach::Domain is set and TLS provisioning fails (ACME),
        // automatic fallthrough to Tiers 1-3 (§10.12.8 step 4).
        // AC11: Verify that NAT is probed on fallthrough.
        use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};

        /// Mock NAT strategy that records whether it was called and what port it received.
        struct RecordingNatStrategy {
            called: Arc<AtomicBool>,
            received_port: Arc<AtomicU16>,
            tier: ReachabilityTier,
        }

        impl NatStrategy for RecordingNatStrategy {
            fn select_tier(
                &self,
                relay_port: u16,
            ) -> std::pin::Pin<
                Box<
                    dyn std::future::Future<Output = Result<ReachabilityTier, NodeError>>
                        + Send
                        + '_,
                >,
            > {
                self.called.store(true, Ordering::SeqCst);
                self.received_port.store(relay_port, Ordering::SeqCst);
                let tier = self.tier.clone();
                Box::pin(async move { Ok(tier) })
            }
        }

        let nat_called = Arc::new(AtomicBool::new(false));
        let nat_port = Arc::new(AtomicU16::new(0));
        let external_addr = SocketAddr::from(([198, 51, 100, 7], 32891));

        let custody = Arc::new(InMemoryKeyCustody::new());
        let did_method = Arc::new(make_test_dht(&custody));

        let node = Node::start_for_testing(NodeConfig {
            bind_addr: Some(SocketAddr::from(([127, 0, 0, 1], 0))),
            dht: DhtMode::Production,
            tls: TlsMode::Custom(Arc::new(FailingTlsProvider)),
            nat: NatSlot::Custom(Arc::new(RecordingNatStrategy {
                called: Arc::clone(&nat_called),
                received_port: Arc::clone(&nat_port),
                tier: ReachabilityTier::Stun { external_addr },
            })),
            ..NodeConfig::defaults(
                Reach::Domain {
                    domain: "fail.example.com".to_owned(),
                },
                IdentitySource::Generate {
                    custody,
                    did_method,
                },
                InMemoryStorage::new(),
                BlobStorageBackend::in_memory(),
            )
        })
        .await
        .unwrap();

        // Verify fallthrough happened: domain should be None.
        assert!(
            node.domain().is_none(),
            "domain should be None after TLS fallthrough"
        );

        // Verify NAT was probed (AC11).
        assert!(
            nat_called.load(Ordering::SeqCst),
            "NAT strategy should have been called on ACME failure fallthrough"
        );

        // Verify the HTTP port (not relay port) was passed to NAT strategy.
        assert_eq!(
            nat_port.load(Ordering::SeqCst),
            DEFAULT_HTTP_BIND_ADDR.port(),
            "NAT strategy should receive the HTTP port ({}), not the relay port",
            DEFAULT_HTTP_BIND_ADDR.port()
        );

        // Verify the relay URL uses ws:// (not wss://).
        assert!(
            node.relay_url().starts_with("ws://"),
            "fallthrough should use ws:// URL, got: {}",
            node.relay_url()
        );
        assert_eq!(node.relay_url(), "ws://198.51.100.7:32891/scp/v1");

        // Verify the relay is bound and functioning.
        assert_ne!(
            node.relay().bound_addr().port(),
            0,
            "relay should be bound to a real port after fallthrough"
        );

        // Verify identity was created.
        assert!(
            node.identity().did().starts_with("did:dht:"),
            "DID should start with did:dht:"
        );
    }

    // -- HTTP bind address (SCP-320) ------------------------------------------

    /// Returns a loopback address whose port the OS reports free right now.
    fn free_loopback_addr() -> SocketAddr {
        let probe = std::net::TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).unwrap();
        probe.local_addr().unwrap()
    }

    /// NAT strategy that records the port tier selection received.
    struct PortRecordingNatStrategy {
        received_port: Arc<std::sync::atomic::AtomicU16>,
        tier: ReachabilityTier,
    }

    impl NatStrategy for PortRecordingNatStrategy {
        fn select_tier(
            &self,
            relay_port: u16,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<ReachabilityTier, NodeError>> + Send + '_>,
        > {
            self.received_port
                .store(relay_port, std::sync::atomic::Ordering::SeqCst);
            let tier = self.tier.clone();
            Box::pin(async move { Ok(tier) })
        }
    }

    #[tokio::test]
    async fn serve_background_none_binds_configured_http_bind_addr() {
        let configured = free_loopback_addr();
        let tier = ReachabilityTier::Stun {
            external_addr: SocketAddr::from(([198, 51, 100, 7], 32891)),
        };
        let node = Node::start_for_testing(NodeConfig {
            http_bind_addr: Some(configured),
            ..no_domain_config(tier)
        })
        .await
        .unwrap();

        let bound = node.serve_background(None).await.unwrap();

        assert_eq!(
            bound, configured,
            "serve_background(None) must bind the configured http_bind_addr"
        );
        node.shutdown();
    }

    #[tokio::test]
    async fn serve_background_none_without_config_binds_loopback() {
        let tier = ReachabilityTier::Stun {
            external_addr: SocketAddr::from(([198, 51, 100, 7], 32891)),
        };
        let config = no_domain_config(tier);
        assert!(config.http_bind_addr.is_none());
        let node = Node::start_for_testing(config).await.unwrap();

        let bound = node.serve_background(None).await.unwrap();

        assert_eq!(
            bound,
            SocketAddr::from(([127, 0, 0, 1], 8443)),
            "serve_background(None) with no configured address must bind loopback 127.0.0.1:8443"
        );
        assert!(
            !bound.ip().is_unspecified(),
            "serve_background(None) must never bind 0.0.0.0, got {bound}"
        );
        node.shutdown();
    }

    #[test]
    fn background_bind_addr_prefers_requested_then_configured_then_loopback() {
        let requested = SocketAddr::from(([127, 0, 0, 1], 9001));
        let configured = SocketAddr::from(([0, 0, 0, 0], 9002));
        assert_eq!(
            background_bind_addr(Some(requested), Some(configured)),
            requested
        );
        assert_eq!(background_bind_addr(None, Some(configured)), configured);
        assert_eq!(
            background_bind_addr(None, None),
            SocketAddr::from(([127, 0, 0, 1], 8443))
        );
    }

    #[tokio::test]
    async fn nat_tier_selection_reads_configured_http_port() {
        let received_port = Arc::new(std::sync::atomic::AtomicU16::new(0));
        let tier = ReachabilityTier::Stun {
            external_addr: SocketAddr::from(([198, 51, 100, 7], 32891)),
        };
        let node = Node::start_for_testing(NodeConfig {
            http_bind_addr: Some(SocketAddr::from(([127, 0, 0, 1], 9555))),
            nat: NatSlot::Custom(Arc::new(PortRecordingNatStrategy {
                received_port: Arc::clone(&received_port),
                tier: tier.clone(),
            })),
            ..no_domain_config(tier)
        })
        .await
        .unwrap();

        assert_eq!(
            received_port.load(std::sync::atomic::Ordering::SeqCst),
            9555,
            "NAT tier selection must receive the configured http_bind_addr port"
        );
        node.shutdown();
    }

    #[tokio::test]
    async fn nat_tier_selection_reads_default_http_port_without_config() {
        let received_port = Arc::new(std::sync::atomic::AtomicU16::new(0));
        let tier = ReachabilityTier::Stun {
            external_addr: SocketAddr::from(([198, 51, 100, 7], 32891)),
        };
        let node = Node::start_for_testing(NodeConfig {
            nat: NatSlot::Custom(Arc::new(PortRecordingNatStrategy {
                received_port: Arc::clone(&received_port),
                tier: tier.clone(),
            })),
            ..no_domain_config(tier)
        })
        .await
        .unwrap();

        assert_eq!(
            received_port.load(std::sync::atomic::Ordering::SeqCst),
            DEFAULT_HTTP_PORT
        );
        node.shutdown();
    }

    #[tokio::test]
    async fn advertised_relay_url_reads_configured_http_port() {
        let tier = ReachabilityTier::Stun {
            external_addr: SocketAddr::from(([198, 51, 100, 7], 32891)),
        };
        let configured = Node::start_for_testing(NodeConfig {
            reach: Reach::Local,
            dht: DhtMode::Disabled,
            http_bind_addr: Some(SocketAddr::from(([127, 0, 0, 1], 9556))),
            ..no_domain_config(tier.clone())
        })
        .await
        .unwrap();
        assert_eq!(configured.relay_url(), "ws://127.0.0.1:9556/scp/v1");
        configured.shutdown();

        let unconfigured = Node::start_for_testing(NodeConfig {
            reach: Reach::Local,
            dht: DhtMode::Disabled,
            ..no_domain_config(tier)
        })
        .await
        .unwrap();
        assert_eq!(unconfigured.relay_url(), "ws://127.0.0.1:8443/scp/v1");
        unconfigured.shutdown();
    }

    /// A configured `http_bind_addr` with port 0 publishes the port the node
    /// bound, never port 0, and the background server serves on that port.
    #[tokio::test]
    async fn advertised_relay_url_reads_the_bound_port_for_a_port_zero_bind() {
        let tier = ReachabilityTier::Stun {
            external_addr: SocketAddr::from(([198, 51, 100, 7], 32891)),
        };
        let node = Node::start_for_testing(NodeConfig {
            reach: Reach::Local,
            dht: DhtMode::Disabled,
            http_bind_addr: Some(SocketAddr::from(([127, 0, 0, 1], 0))),
            ..no_domain_config(tier)
        })
        .await
        .expect("a port-0 http_bind_addr starts");

        let url = node.relay_url();
        let port: u16 = url
            .strip_prefix("ws://127.0.0.1:")
            .and_then(|rest| rest.strip_suffix("/scp/v1"))
            .and_then(|p| p.parse().ok())
            .unwrap_or_else(|| panic!("loopback relay URL with a port: {url}"));
        assert_ne!(port, 0);

        let served = node
            .serve_background(None)
            .await
            .expect("serves on the configured address");
        assert_eq!(served.port(), port, "the node serves the port it published");
        node.shutdown();
    }

    /// Starts a node whose `http_bind_addr` is `127.0.0.1:0` and returns it
    /// with the port its relay URL publishes.
    async fn port_zero_node() -> (ApplicationNode<InMemoryStorage>, u16) {
        let tier = ReachabilityTier::Stun {
            external_addr: SocketAddr::from(([198, 51, 100, 7], 32891)),
        };
        let node = Node::start_for_testing(NodeConfig {
            reach: Reach::Local,
            dht: DhtMode::Disabled,
            http_bind_addr: Some(SocketAddr::from(([127, 0, 0, 1], 0))),
            ..no_domain_config(tier)
        })
        .await
        .expect("a port-0 http_bind_addr starts");
        let url = node.relay_url();
        let port: u16 = url
            .strip_prefix("ws://127.0.0.1:")
            .and_then(|rest| rest.strip_suffix("/scp/v1"))
            .and_then(|p| p.parse().ok())
            .unwrap_or_else(|| panic!("loopback relay URL with a port: {url}"));
        assert_ne!(port, 0);
        (node, port)
    }

    /// Whether a TCP connect to `127.0.0.1:port` is refused.
    async fn loopback_port_refuses(port: u16) -> bool {
        tokio::net::TcpStream::connect(SocketAddr::from(([127, 0, 0, 1], port)))
            .await
            .is_err_and(|e| e.kind() == std::io::ErrorKind::ConnectionRefused)
    }

    /// The SDK `serve(bindAddr)` path passes the configured `127.0.0.1:0`; the
    /// node serves the port it published, not a second port.
    #[tokio::test]
    async fn serve_background_on_the_configured_port_zero_serves_the_published_port() {
        let (node, port) = port_zero_node().await;

        let served = node
            .serve_background(Some(SocketAddr::from(([127, 0, 0, 1], 0))))
            .await
            .expect("serves on the configured address");

        assert_eq!(served.port(), port, "the node serves the port it published");
        node.shutdown();
    }

    /// `shutdown` closes a pre-bound listener no serve took.
    #[tokio::test]
    async fn shutdown_closes_the_unserved_prebound_listener() {
        let (node, port) = port_zero_node().await;
        assert!(
            !loopback_port_refuses(port).await,
            "the pre-bound listener accepts before shutdown"
        );

        node.shutdown();

        assert!(
            loopback_port_refuses(port).await,
            "the published port refuses connections after shutdown"
        );
    }

    /// Dropping a node that never served closes its pre-bound listener.
    #[tokio::test]
    async fn dropping_an_unserved_node_closes_the_prebound_listener() {
        let (node, port) = port_zero_node().await;

        drop(node);

        assert!(
            loopback_port_refuses(port).await,
            "the published port refuses connections after the node drops"
        );
    }

    /// A background serve on another address closes the pre-bound listener,
    /// which no serve can take afterwards.
    #[tokio::test]
    async fn serving_elsewhere_closes_the_prebound_listener() {
        let (node, port) = port_zero_node().await;
        let elsewhere = free_loopback_addr();

        let served = node
            .serve_background(Some(elsewhere))
            .await
            .expect("serves on the requested address");

        assert_eq!(served, elsewhere);
        assert!(
            loopback_port_refuses(port).await,
            "the unserved published port refuses connections"
        );
        node.shutdown();
    }

    /// A background serve whose bind fails leaves the pre-bound listener open,
    /// so no other socket can take the published port, and the next serve
    /// takes it.
    #[tokio::test]
    async fn a_failed_serve_keeps_the_prebound_listener() {
        let (node, port) = port_zero_node().await;
        let occupied = std::net::TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .expect("bind a probe listener");
        let occupied_addr = occupied.local_addr().expect("probe address");

        node.serve_background(Some(occupied_addr))
            .await
            .expect_err("binding an occupied address fails");
        assert!(
            !loopback_port_refuses(port).await,
            "the published port stays bound after the failed serve"
        );
        let served = node
            .serve_background(None)
            .await
            .expect("serves on the configured address");

        assert_eq!(served.port(), port, "the retry serves the published port");
        drop(occupied);
        node.shutdown();
    }

    /// NAT tier selection receives the bound port of a port-0 `http_bind_addr`,
    /// and [`ApplicationNode::bind`] binds that same port.
    #[tokio::test]
    async fn nat_tier_selection_reads_the_bound_port_for_a_port_zero_bind() {
        let received_port = Arc::new(std::sync::atomic::AtomicU16::new(0));
        let tier = ReachabilityTier::Stun {
            external_addr: SocketAddr::from(([198, 51, 100, 7], 32891)),
        };
        let node = Node::start_for_testing(NodeConfig {
            http_bind_addr: Some(SocketAddr::from(([127, 0, 0, 1], 0))),
            nat: NatSlot::Custom(Arc::new(PortRecordingNatStrategy {
                received_port: Arc::clone(&received_port),
                tier: tier.clone(),
            })),
            ..no_domain_config(tier)
        })
        .await
        .expect("a port-0 http_bind_addr starts");

        let port = received_port.load(std::sync::atomic::Ordering::SeqCst);
        assert_ne!(port, 0, "tier selection never sees port 0");

        let bound = node.bind().await.expect("binds the advertised port");
        assert_eq!(bound.http_addr().port(), port);
    }

    #[tokio::test]
    async fn no_domain_nat_failure_returns_error() {
        // AC (implied): When all NAT tiers fail, build() returns an error.
        let custody = Arc::new(InMemoryKeyCustody::new());
        let did_method = Arc::new(make_test_dht(&custody));

        let result = Node::start_for_testing(NodeConfig {
            bind_addr: Some(SocketAddr::from(([127, 0, 0, 1], 0))),
            dht: DhtMode::Production,
            nat: NatSlot::Custom(Arc::new(FailingNatStrategy)),
            ..NodeConfig::defaults(
                Reach::NatTraversal,
                IdentitySource::Generate {
                    custody,
                    did_method,
                },
                InMemoryStorage::new(),
                BlobStorageBackend::in_memory(),
            )
        })
        .await;

        let Err(err) = result else {
            panic!("build() should fail when all NAT tiers fail");
        };
        assert!(
            matches!(err, NodeError::Nat(_)),
            "error should be NodeError::Nat, got: {err:?}"
        );
    }

    /// A `Node::start` that fails after its relay started shuts the relay
    /// down: nothing accepts connections on `bind_addr` afterwards. The NAT
    /// probe fails after the relay is listening, so without the shutdown the
    /// listener would outlive the failed start.
    #[tokio::test]
    async fn a_failed_nat_traversal_start_leaves_no_listener() {
        let bind_addr = std::net::TcpListener::bind("127.0.0.1:0")
            .and_then(|l| l.local_addr())
            .unwrap();
        let custody = Arc::new(InMemoryKeyCustody::new());
        let did_method = Arc::new(make_test_dht(&custody));

        let result = Node::start_for_testing(NodeConfig {
            bind_addr: Some(bind_addr),
            dht: DhtMode::Production,
            nat: NatSlot::Custom(Arc::new(FailingNatStrategy)),
            ..NodeConfig::defaults(
                Reach::NatTraversal,
                IdentitySource::Generate {
                    custody,
                    did_method,
                },
                InMemoryStorage::new(),
                BlobStorageBackend::in_memory(),
            )
        })
        .await;
        assert!(
            matches!(result, Err(NodeError::Nat(_))),
            "{:?}",
            result.err()
        );

        // Shutdown is signalled synchronously; the accept loop drops the
        // listener when it next runs, so poll briefly for the refusal.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            match tokio::net::TcpStream::connect(bind_addr).await {
                Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => break,
                outcome => assert!(
                    tokio::time::Instant::now() < deadline,
                    "the relay still listens on {bind_addr} after a failed start: {outcome:?}"
                ),
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    #[tokio::test]
    async fn no_domain_did_publication_happens_once() {
        use std::sync::atomic::{AtomicU32, Ordering};

        struct CountingDidMethod {
            inner: TestDidDht,
            publish_count: Arc<AtomicU32>,
        }

        impl DidMethod for CountingDidMethod {
            /// These doubles observe what the builders publish; none of them
            /// keeps a record alive, so the keep-alive client is the fail-closed
            /// `DisabledDhtClient` rather than one that would report a false
            /// publish success.
            type Dht = scp_dht::DisabledDhtClient;

            fn dht_client(&self) -> Arc<scp_dht::DisabledDhtClient> {
                Arc::new(scp_dht::DisabledDhtClient)
            }

            fn create(
                &self,
                key_custody: &impl KeyCustody,
                pre_rotation_custody: &impl scp_platform::PreRotationCustody,
            ) -> impl std::future::Future<
                Output = Result<
                    (ScpIdentity, DidDocument, scp_platform::PreRotationKeyHandle),
                    IdentityError,
                >,
            > + Send {
                self.inner.create(key_custody, pre_rotation_custody)
            }

            fn verify(&self, did_string: &str, public_key: &[u8]) -> bool {
                self.inner.verify(did_string, public_key)
            }

            fn publish(
                &self,
                identity: &ScpIdentity,
                document: &DidDocument,
            ) -> impl std::future::Future<
                Output = Result<scp_identity::republish::RepublishEntry, IdentityError>,
            > + Send {
                self.publish_count.fetch_add(1, Ordering::SeqCst);
                self.inner.publish(identity, document)
            }

            fn resolve(
                &self,
                did_string: &str,
            ) -> impl std::future::Future<Output = Result<DidDocument, IdentityError>> + Send
            {
                self.inner.resolve(did_string)
            }

            fn rotate(
                &self,
                identity: &ScpIdentity,
                key_custody: &impl KeyCustody,
            ) -> impl std::future::Future<
                Output = Result<(ScpIdentity, DidDocument), IdentityError>,
            > + Send {
                self.inner.rotate(identity, key_custody)
            }
        }

        let custody = Arc::new(InMemoryKeyCustody::new());
        let publish_count = Arc::new(AtomicU32::new(0));
        let counting_method = Arc::new(CountingDidMethod {
            inner: make_test_dht(&custody),
            publish_count: Arc::clone(&publish_count),
        });

        let tier = ReachabilityTier::Stun {
            external_addr: SocketAddr::from(([198, 51, 100, 7], 32891)),
        };

        let _node = Node::start_for_testing(NodeConfig {
            bind_addr: Some(SocketAddr::from(([127, 0, 0, 1], 0))),
            dht: DhtMode::Production,
            nat: NatSlot::Custom(Arc::new(MockNatStrategy { tier })),
            ..NodeConfig::defaults(
                Reach::NatTraversal,
                IdentitySource::Generate {
                    custody,
                    did_method: counting_method,
                },
                InMemoryStorage::new(),
                BlobStorageBackend::in_memory(),
            )
        })
        .await
        .unwrap();

        assert_eq!(
            publish_count.load(Ordering::SeqCst),
            1,
            "DID should be published exactly once on no-domain build"
        );
    }

    #[test]
    fn default_stun_endpoints_parseable() {
        for (addr, _label) in DEFAULT_STUN_ENDPOINTS {
            let parsed: std::net::SocketAddr = addr
                .parse()
                .unwrap_or_else(|e| panic!("STUN endpoint '{addr}' not parseable: {e}"));
            assert_ne!(parsed.port(), 0);
        }
    }

    // -- DefaultNatStrategy self-test integration (SCP-242) -------------------

    /// Builds a minimal STUN Binding Response for test mock servers.
    ///
    /// This is a test-local re-implementation of the logic in
    /// `build_stun_binding_response`,
    /// which is `#[cfg(test)]` and not accessible cross-crate.
    fn build_stun_binding_response(addr: SocketAddr, transaction_id: &[u8; 12]) -> Vec<u8> {
        const MAGIC_COOKIE: u32 = 0x2112_A442;
        const BINDING_RESPONSE: u16 = 0x0101;
        const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;

        // Encode XOR-MAPPED-ADDRESS value.
        let mut attr_data = Vec::new();
        attr_data.push(0x00); // Reserved.
        match addr {
            SocketAddr::V4(v4) => {
                attr_data.push(0x01); // IPv4 family.
                let xor_port = v4.port() ^ (MAGIC_COOKIE >> 16) as u16;
                attr_data.extend_from_slice(&xor_port.to_be_bytes());
                let ip_bits: u32 = (*v4.ip()).into();
                let xor_ip = ip_bits ^ MAGIC_COOKIE;
                attr_data.extend_from_slice(&xor_ip.to_be_bytes());
            }
            SocketAddr::V6(v6) => {
                attr_data.push(0x02); // IPv6 family.
                let xor_port = v6.port() ^ (MAGIC_COOKIE >> 16) as u16;
                attr_data.extend_from_slice(&xor_port.to_be_bytes());
                let ip_bytes = v6.ip().octets();
                let mut xor_key = [0u8; 16];
                xor_key[0..4].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
                xor_key[4..16].copy_from_slice(transaction_id);
                for i in 0..16 {
                    attr_data.push(ip_bytes[i] ^ xor_key[i]);
                }
            }
        }

        #[allow(clippy::cast_possible_truncation)]
        let attr_len = attr_data.len() as u16;
        #[allow(clippy::cast_possible_truncation)]
        let padded_attr_len = ((attr_data.len() + 3) & !3) as u16;
        let msg_len = 4 + padded_attr_len;

        let mut buf = Vec::with_capacity(20 + msg_len as usize);

        // Header.
        buf.extend_from_slice(&BINDING_RESPONSE.to_be_bytes());
        buf.extend_from_slice(&msg_len.to_be_bytes());
        buf.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        buf.extend_from_slice(transaction_id);

        // Attribute header.
        buf.extend_from_slice(&ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
        buf.extend_from_slice(&attr_len.to_be_bytes());
        buf.extend_from_slice(&attr_data);

        // Padding.
        let padding = (4 - (attr_data.len() % 4)) % 4;
        buf.extend(std::iter::repeat_n(0u8, padding));

        buf
    }

    /// Spawns a mock STUN server that responds to `count` requests with the
    /// given external address.
    fn spawn_mock_stun_server(
        socket: tokio::net::UdpSocket,
        external_addr: SocketAddr,
        count: usize,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            for _ in 0..count {
                let mut buf = [0u8; 576];
                let (_, from) = socket.recv_from(&mut buf).await.expect("recv");
                let mut txn_id = [0u8; 12];
                txn_id.copy_from_slice(&buf[8..20]);
                let response = build_stun_binding_response(external_addr, &txn_id);
                socket.send_to(&response, from).await.expect("send");
            }
        })
    }

    /// Mock reachability probe for testing `DefaultNatStrategy` directly.
    struct MockReachabilityProbe {
        /// Whether the probe should succeed (return true) or fail (return false).
        reachable: std::sync::atomic::AtomicBool,
    }

    impl MockReachabilityProbe {
        fn new(reachable: bool) -> Self {
            Self {
                reachable: std::sync::atomic::AtomicBool::new(reachable),
            }
        }
    }

    impl scp_transport::nat::ReachabilityProbe for MockReachabilityProbe {
        fn probe_reachability<'a>(
            &'a self,
            _socket: &'a tokio::net::UdpSocket,
            _external_addr: SocketAddr,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<Output = Result<bool, scp_transport::TransportError>>
                    + Send
                    + 'a,
            >,
        > {
            let reachable = self.reachable.load(std::sync::atomic::Ordering::Relaxed);
            Box::pin(async move { Ok(reachable) })
        }
    }

    /// Mock `PortMapper` for testing `DefaultNatStrategy`'s Tier 1 `UPnP` integration.
    struct MockPortMapper {
        result: tokio::sync::Mutex<
            Option<
                Result<scp_transport::nat::PortMappingResult, scp_transport::nat::PortMappingError>,
            >,
        >,
    }

    impl MockPortMapper {
        fn ok(addr: SocketAddr) -> Self {
            Self {
                result: tokio::sync::Mutex::new(Some(Ok(scp_transport::nat::PortMappingResult {
                    external_addr: addr,
                    ttl: std::time::Duration::from_mins(10),
                    protocol: scp_transport::nat::MappingProtocol::UpnpIgd,
                }))),
            }
        }

        fn fail(msg: &str) -> Self {
            Self {
                result: tokio::sync::Mutex::new(Some(Err(
                    scp_transport::nat::PortMappingError::DiscoveryFailed(msg.to_owned()),
                ))),
            }
        }
    }

    impl scp_transport::nat::PortMapper for MockPortMapper {
        fn map_port(
            &self,
            _internal_port: u16,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<
                        Output = Result<
                            scp_transport::nat::PortMappingResult,
                            scp_transport::nat::PortMappingError,
                        >,
                    > + Send
                    + '_,
            >,
        > {
            Box::pin(async {
                let mut r = self.result.lock().await;
                r.take().unwrap_or_else(|| {
                    Err(scp_transport::nat::PortMappingError::Internal(
                        "no more results".to_owned(),
                    ))
                })
            })
        }

        fn renew(
            &self,
            _internal_port: u16,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<
                        Output = Result<
                            scp_transport::nat::PortMappingResult,
                            scp_transport::nat::PortMappingError,
                        >,
                    > + Send
                    + '_,
            >,
        > {
            Box::pin(async {
                Err(scp_transport::nat::PortMappingError::Internal(
                    "renew not expected".to_owned(),
                ))
            })
        }

        fn remove(
            &self,
            _internal_port: u16,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<Output = Result<(), scp_transport::nat::PortMappingError>>
                    + Send
                    + '_,
            >,
        > {
            Box::pin(async { Ok(()) })
        }
    }

    /// SCP-242 AC3: `DefaultNatStrategy` `UPnP` self-test failure triggers
    /// fallthrough to Tier 2 STUN.
    ///
    /// Uses mock STUN servers and a mock `PortMapper` to exercise
    /// `DefaultNatStrategy` directly (not through a custom mock strategy).
    #[tokio::test]
    async fn default_nat_strategy_upnp_self_test_failure_falls_through_to_bridge() {
        // Single STUN server for NAT probing (single-STUN fallback → AddressRestricted).
        let stun = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let stun_addr = stun.local_addr().expect("addr");
        let stun_external = SocketAddr::from(([203, 0, 113, 42], 32891_u16));

        // NAT probing needs 1 request only (mock reachability probe handles self-test).
        let h = spawn_mock_stun_server(stun, stun_external, 1);

        // UPnP returns a mapping, but self-test probe always returns false.
        let upnp_external = SocketAddr::from(([198, 51, 100, 1], 8443_u16));
        let mapper = Arc::new(MockPortMapper::ok(upnp_external));
        let probe = Arc::new(MockReachabilityProbe::new(false));

        let strategy = DefaultNatStrategy::new(
            Some(stun_addr.to_string()),
            Some(scp_did::BridgeEndpoint::new("wss://bridge.example.com/scp/v1").unwrap()),
        )
        .with_port_mapper(mapper)
        .with_reachability_probe(probe);

        let tier = strategy.select_tier(4000).await.expect("should succeed");

        // UPnP self-test failed, STUN self-test also failed (same probe),
        // so it should fall through to Tier 3 bridge.
        assert!(
            matches!(tier, ReachabilityTier::Bridge { .. }),
            "should fall through to bridge when all self-tests fail, got: {tier:?}"
        );

        h.await.expect("server");
    }

    /// SCP-242 AC1/AC2: `DefaultNatStrategy` `UPnP` self-test success returns Tier 1.
    #[tokio::test]
    async fn default_nat_strategy_upnp_self_test_success_returns_tier1() {
        let stun = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let stun_addr = stun.local_addr().expect("addr");
        let stun_external = SocketAddr::from(([203, 0, 113, 42], 32891_u16));

        // NAT probing: 1 request.
        let h = spawn_mock_stun_server(stun, stun_external, 1);

        // UPnP mapping succeeds and self-test passes.
        let upnp_external = SocketAddr::from(([198, 51, 100, 1], 8443_u16));
        let mapper = Arc::new(MockPortMapper::ok(upnp_external));
        let probe = Arc::new(MockReachabilityProbe::new(true));

        let strategy = DefaultNatStrategy::new(Some(stun_addr.to_string()), None)
            .with_port_mapper(mapper)
            .with_reachability_probe(probe);

        let tier = strategy.select_tier(4000).await.expect("should succeed");

        match tier {
            ReachabilityTier::Upnp { external_addr } => {
                assert_eq!(external_addr, upnp_external);
            }
            other => panic!("expected Tier 1 Upnp, got: {other:?}"),
        }

        h.await.expect("server");
    }

    /// SCP-242 AC3: `DefaultNatStrategy` `UPnP` mapping failure falls through
    /// to Tier 2 STUN, where self-test succeeds.
    #[tokio::test]
    async fn default_nat_strategy_upnp_mapping_failure_falls_through_to_stun() {
        let stun = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let stun_addr = stun.local_addr().expect("addr");
        let stun_external = SocketAddr::from(([203, 0, 113, 42], 32891_u16));

        // NAT probing + Tier 2 self-test: 2 requests total
        // (probe uses DefaultReachabilityProbe which sends to the STUN server).
        // But since we use MockReachabilityProbe, only 1 request (NAT probing).
        let h = spawn_mock_stun_server(stun, stun_external, 1);

        // UPnP mapping FAILS, self-test probe returns true.
        let mapper = Arc::new(MockPortMapper::fail("no UPnP gateway"));
        let probe = Arc::new(MockReachabilityProbe::new(true));

        let strategy = DefaultNatStrategy::new(
            Some(stun_addr.to_string()),
            Some(scp_did::BridgeEndpoint::new("wss://bridge.example.com/scp/v1").unwrap()),
        )
        .with_port_mapper(mapper)
        .with_reachability_probe(probe);

        let tier = strategy.select_tier(4000).await.expect("should succeed");

        match tier {
            ReachabilityTier::Stun { external_addr } => {
                assert_eq!(external_addr, stun_external);
            }
            other => panic!("expected Tier 2 Stun, got: {other:?}"),
        }

        h.await.expect("server");
    }

    /// SCP-242: `DefaultNatStrategy` without `port_mapper` skips Tier 1.
    #[tokio::test]
    async fn default_nat_strategy_no_port_mapper_skips_tier1() {
        let stun = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let stun_addr = stun.local_addr().expect("addr");
        let stun_external = SocketAddr::from(([203, 0, 113, 42], 32891_u16));

        // NAT probing only: 1 request (mock probe handles self-test).
        let h = spawn_mock_stun_server(stun, stun_external, 1);

        let probe = Arc::new(MockReachabilityProbe::new(true));

        let strategy = DefaultNatStrategy::new(Some(stun_addr.to_string()), None)
            .with_reachability_probe(probe);

        let tier = strategy.select_tier(4000).await.expect("should succeed");

        match tier {
            ReachabilityTier::Stun { external_addr } => {
                assert_eq!(external_addr, stun_external);
            }
            other => panic!("expected Tier 2 Stun, got: {other:?}"),
        }

        h.await.expect("server");
    }

    /// SCP-242 AC4: Tier 2 STUN self-test failure triggers fallthrough to Tier 3.
    #[tokio::test]
    async fn default_nat_strategy_stun_self_test_failure_falls_through_to_bridge() {
        let stun = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let stun_addr = stun.local_addr().expect("addr");
        let stun_external = SocketAddr::from(([203, 0, 113, 42], 32891_u16));

        // NAT probing: 1 request.
        let h = spawn_mock_stun_server(stun, stun_external, 1);

        // Self-test probe returns false (fails).
        let probe = Arc::new(MockReachabilityProbe::new(false));

        let strategy = DefaultNatStrategy::new(
            Some(stun_addr.to_string()),
            Some(scp_did::BridgeEndpoint::new("wss://bridge.example.com/scp/v1").unwrap()),
        )
        .with_reachability_probe(probe);

        let tier = strategy.select_tier(4000).await.expect("should succeed");

        match tier {
            ReachabilityTier::Bridge { bridge_url } => {
                assert_eq!(bridge_url.as_str(), "wss://bridge.example.com/scp/v1");
            }
            other => panic!("expected Tier 3 Bridge, got: {other:?}"),
        }

        h.await.expect("server");
    }

    // -- HTTP tests (SCP-147) ------------------------------------------------

    mod http_tests {
        use super::*;
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use scp_core::well_known::WellKnownScp;
        use tower::ServiceExt;

        /// Builds a node and returns it along with the well-known router
        /// for direct testing via `tower::ServiceExt`.
        async fn build_test_node() -> ApplicationNode<InMemoryStorage> {
            Node::start_for_testing(domain_config()).await.unwrap()
        }

        #[tokio::test]
        async fn well_known_returns_valid_json() {
            let node = build_test_node().await;
            let router = node.well_known_router();

            let request = Request::builder()
                .uri("/.well-known/scp")
                .body(Body::empty())
                .unwrap();

            let response = router.oneshot(request).await.unwrap();

            assert_eq!(response.status(), StatusCode::OK);

            // Check Content-Type is application/json.
            let content_type = response
                .headers()
                .get("content-type")
                .expect("should have content-type header")
                .to_str()
                .unwrap();
            assert!(
                content_type.contains("application/json"),
                "Content-Type should be application/json, got: {content_type}"
            );

            // Parse the body as WellKnownScp.
            let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
                .await
                .unwrap();
            let doc: WellKnownScp = serde_json::from_slice(&body).unwrap();

            assert_eq!(doc.version, 1);
            assert!(
                doc.did.starts_with("did:dht:"),
                "DID should be the node's DID, got: {}",
                doc.did
            );
            assert_eq!(doc.relay, "wss://test.example.com/scp/v1");
            assert!(doc.contexts.is_none(), "no contexts registered yet");
        }

        #[tokio::test]
        async fn well_known_includes_registered_broadcast_contexts() {
            let node = build_test_node().await;

            // Register a broadcast context.
            node.register_broadcast_context("abc123".to_owned(), Some("Test Broadcast".to_owned()))
                .await
                .unwrap();

            let router = node.well_known_router();

            let request = Request::builder()
                .uri("/.well-known/scp")
                .body(Body::empty())
                .unwrap();

            let response = router.oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);

            let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
                .await
                .unwrap();
            let doc: WellKnownScp = serde_json::from_slice(&body).unwrap();

            let contexts = doc.contexts.expect("should have contexts");
            assert_eq!(contexts.len(), 1);
            assert_eq!(contexts[0].id, "abc123");
            assert_eq!(contexts[0].name.as_deref(), Some("Test Broadcast"));
            assert_eq!(contexts[0].mode.as_deref(), Some("broadcast"));
            assert!(
                contexts[0]
                    .uri
                    .as_ref()
                    .unwrap()
                    .starts_with("scp://context/abc123"),
                "URI should start with scp://context/abc123, got: {}",
                contexts[0].uri.as_ref().unwrap()
            );
        }

        #[tokio::test]
        async fn well_known_dynamic_updates_on_new_context() {
            let node = build_test_node().await;

            // First request: no contexts.
            let router = node.well_known_router();
            let request = Request::builder()
                .uri("/.well-known/scp")
                .body(Body::empty())
                .unwrap();
            let response = router.oneshot(request).await.unwrap();
            let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
                .await
                .unwrap();
            let doc: WellKnownScp = serde_json::from_slice(&body).unwrap();
            assert!(doc.contexts.is_none());

            // Register a context.
            node.register_broadcast_context("def456".to_owned(), None)
                .await
                .unwrap();

            // Second request: context appears.
            let router = node.well_known_router();
            let request = Request::builder()
                .uri("/.well-known/scp")
                .body(Body::empty())
                .unwrap();
            let response = router.oneshot(request).await.unwrap();
            let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
                .await
                .unwrap();
            let doc: WellKnownScp = serde_json::from_slice(&body).unwrap();

            let contexts = doc.contexts.expect("should now have contexts");
            assert_eq!(contexts.len(), 1);
            assert_eq!(contexts[0].id, "def456");
        }

        #[tokio::test]
        async fn relay_router_upgrades_websocket() {
            let node = build_test_node().await;
            let _relay_addr = node.relay().bound_addr();

            // Start the relay router on a separate port.
            let relay_router = node.relay_router();
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let http_addr = listener.local_addr().unwrap();

            let server_handle = tokio::spawn(async move {
                axum::serve(listener, relay_router).await.unwrap();
            });

            // Connect via WebSocket to the HTTP server's /scp/v1 endpoint.
            let url = format!("ws://{http_addr}/scp/v1");
            let connect_result = tokio_tungstenite::connect_async(&url).await;

            assert!(
                connect_result.is_ok(),
                "WebSocket upgrade at /scp/v1 should succeed, got error: {:?}",
                connect_result.err()
            );

            // Clean up.
            server_handle.abort();
            let _ = server_handle.await;
        }

        #[tokio::test]
        async fn custom_app_routes_merge_with_scp_routes() {
            let node = build_test_node().await;

            // Create a simple app route.
            let app_router =
                axum::Router::new().route("/health", axum::routing::get(|| async { "ok" }));

            // Merge with SCP routes.
            let well_known = node.well_known_router();
            let merged = app_router.merge(well_known);

            // Test the custom route.
            let request = Request::builder()
                .uri("/health")
                .body(Body::empty())
                .unwrap();
            let response = merged.clone().oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);

            let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
                .await
                .unwrap();
            assert_eq!(&body[..], b"ok");

            // Test the .well-known/scp route on the same merged router.
            let request = Request::builder()
                .uri("/.well-known/scp")
                .body(Body::empty())
                .unwrap();
            let response = merged.oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);

            let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
                .await
                .unwrap();
            let doc: WellKnownScp = serde_json::from_slice(&body).unwrap();
            assert_eq!(doc.version, 1);
        }
    }

    // -- Periodic tier re-evaluation tests (SCP-243) ---------------------------

    /// Mock NAT strategy that returns different tiers on successive calls.
    /// Used to test that the re-evaluation loop detects tier changes.
    struct SequenceNatStrategy {
        tiers: std::sync::Mutex<Vec<ReachabilityTier>>,
        call_count: std::sync::atomic::AtomicU32,
    }

    impl SequenceNatStrategy {
        fn new(tiers: Vec<ReachabilityTier>) -> Self {
            Self {
                tiers: std::sync::Mutex::new(tiers),
                call_count: std::sync::atomic::AtomicU32::new(0),
            }
        }
    }

    impl NatStrategy for SequenceNatStrategy {
        fn select_tier(
            &self,
            _relay_port: u16,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<ReachabilityTier, NodeError>> + Send + '_>,
        > {
            let idx = self
                .call_count
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst) as usize;
            let tiers = self.tiers.lock().unwrap();
            // Cycle through the tiers if we exhaust the list.
            let tier = tiers[idx % tiers.len()].clone();
            drop(tiers);
            Box::pin(async move { Ok(tier) })
        }
    }

    /// Mock `DidPublisher` that records publish calls and models the real seam's
    /// monotonically-increasing BEP44 sequence, so a test can tell the record
    /// produced by the Nth publish apart from the previous one.
    struct RecordingPublisher {
        publish_count: std::sync::atomic::AtomicU32,
    }

    impl RecordingPublisher {
        fn new() -> Self {
            Self {
                publish_count: std::sync::atomic::AtomicU32::new(0),
            }
        }

        fn count(&self) -> u32 {
            self.publish_count.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    impl DidPublisher for RecordingPublisher {
        fn publish<'a>(
            &'a self,
            _auth: PublishAuthorization,
            _identity: &'a ScpIdentity,
            document: &'a DidDocument,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<
                        Output = Result<Option<scp_identity::republish::RepublishEntry>, NodeError>,
                    > + Send
                    + 'a,
            >,
        > {
            let sequence = u64::from(
                self.publish_count
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst),
            ) + 1;
            let document_bytes = document
                .to_json()
                .expect("test document serializes")
                .into_bytes();
            Box::pin(async move {
                Ok(Some(scp_identity::republish::RepublishEntry {
                    public_key: [7u8; 32],
                    document_bytes,
                    signature: [0u8; 64],
                    sequence,
                }))
            })
        }

        fn initialize_sequence<'a>(
            &'a self,
            _identity: &'a ScpIdentity,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), NodeError>> + Send + 'a>>
        {
            Box::pin(async { Ok(()) })
        }
    }

    /// Short interval used in tests instead of the production 30-minute interval.
    const TEST_REEVALUATION_INTERVAL: Duration = Duration::from_millis(50);

    /// Timeout for waiting on events in tests (generous to avoid flakiness).
    const TEST_EVENT_TIMEOUT: Duration = Duration::from_secs(5);

    #[tokio::test]
    async fn tier_change_after_30_minutes_triggers_did_republish() {
        // AC: A background task re-evaluates the reachability tier every 30 minutes.
        // AC: Tier change triggers DID document update with the new relay address.
        // AC: Tier change is logged at INFO level (§10.12.1).
        let initial_addr = SocketAddr::from(([198, 51, 100, 7], 32891));
        let new_addr = SocketAddr::from(([203, 0, 113, 42], 8443));

        // First call returns Stun, second returns Upnp (different URL → tier change).
        let strategy = Arc::new(SequenceNatStrategy::new(vec![
            ReachabilityTier::Stun {
                external_addr: initial_addr,
            },
            ReachabilityTier::Upnp {
                external_addr: new_addr,
            },
        ]));

        let publisher = Arc::new(RecordingPublisher::new());
        let (event_tx, mut event_rx) = tokio::sync::mpsc::channel(16);

        let identity = ScpIdentity {
            identity_key: scp_platform::KeyHandle::new(1),
            active_signing_key: scp_platform::KeyHandle::new(2),
            agent_signing_key: None,
            pre_rotation_commitment: [0u8; 32],
            did: "did:dht:test123".to_owned(),
        };

        let document = DidDocument {
            context: vec!["https://www.w3.org/ns/did/v1".to_owned()],
            id: "did:dht:test123".to_owned(),
            verification_method: vec![],
            authentication: vec![],
            assertion_method: vec![],
            also_known_as: vec![],
            service: vec![scp_did::Service {
                id: "did:dht:test123#scp-relay-1".to_owned(),
                service_type: "SCPRelay".to_owned(),
                service_endpoint: "ws://198.51.100.7:32891/scp/v1".to_owned(),
                bridge_target: None,
            }],
        };

        let handle = spawn_tier_reevaluation(
            Arc::clone(&strategy) as Arc<dyn NatStrategy>,
            None,
            NodePublisher::from_dyn(
                Arc::clone(&publisher) as Arc<dyn DidPublisher>,
                LiveRelayUrl::new(RelayUrl::new("ws://198.51.100.7:32891/scp/v1").unwrap()),
            ),
            node_bridge_target(&identity.did).unwrap(),
            identity,
            LiveSlot::new(NodePublishedState {
                document,
                relay: crate::published_state::test_relay("ws://198.51.100.7:32891/scp/v1"),
                record: None,
            }),
            32891,
            Some(event_tx),
            TEST_REEVALUATION_INTERVAL,
        );

        // Wait for the periodic timer to fire (50ms test interval).
        let event = tokio::time::timeout(TEST_EVENT_TIMEOUT, event_rx.recv())
            .await
            .expect("timeout waiting for tier change event")
            .expect("channel closed unexpectedly");

        match event {
            NatTierChange::TierChanged {
                previous_relay_url,
                new_relay_url,
                reason,
            } => {
                assert_eq!(previous_relay_url, "ws://198.51.100.7:32891/scp/v1");
                assert_eq!(new_relay_url, "ws://203.0.113.42:8443/scp/v1");
                assert!(
                    reason.contains("periodic"),
                    "reason should mention periodic: {reason}"
                );
            }
            other => panic!("expected TierChanged, got {other:?}"),
        }

        // Verify the DID document was republished.
        assert_eq!(
            publisher.count(),
            1,
            "DID document should be republished after tier change"
        );

        handle.stop();
    }

    #[tokio::test]
    async fn network_event_triggers_immediate_reevaluation() {
        // AC: Network change events (IP change, interface up/down) trigger
        //     immediate re-evaluation.
        let new_addr = SocketAddr::from(([10, 0, 0, 1], 9999));

        // The first select_tier call is the re-evaluation triggered by the
        // network change — it should return a DIFFERENT address than the
        // current relay URL to trigger a TierChanged event.
        let strategy = Arc::new(SequenceNatStrategy::new(vec![ReachabilityTier::Stun {
            external_addr: new_addr,
        }]));

        let publisher = Arc::new(RecordingPublisher::new());
        let (event_tx, mut event_rx) = tokio::sync::mpsc::channel(16);

        // Create a network change detector with a channel for injecting events.
        let (net_change_tx, net_change_rx) = tokio::sync::mpsc::channel(16);
        let detector = Arc::new(scp_transport::nat::ChannelNetworkChangeDetector::new(
            net_change_rx,
        ));

        let identity = ScpIdentity {
            identity_key: scp_platform::KeyHandle::new(1),
            active_signing_key: scp_platform::KeyHandle::new(2),
            agent_signing_key: None,
            pre_rotation_commitment: [0u8; 32],
            did: "did:dht:testnet123".to_owned(),
        };

        let document = DidDocument {
            context: vec!["https://www.w3.org/ns/did/v1".to_owned()],
            id: "did:dht:testnet123".to_owned(),
            verification_method: vec![],
            authentication: vec![],
            assertion_method: vec![],
            also_known_as: vec![],
            service: vec![scp_did::Service {
                id: "did:dht:testnet123#scp-relay-1".to_owned(),
                service_type: "SCPRelay".to_owned(),
                service_endpoint: "ws://198.51.100.7:32891/scp/v1".to_owned(),
                bridge_target: None,
            }],
        };

        let handle = spawn_tier_reevaluation(
            Arc::clone(&strategy) as Arc<dyn NatStrategy>,
            Some(detector as Arc<dyn NetworkChangeDetector>),
            NodePublisher::from_dyn(
                Arc::clone(&publisher) as Arc<dyn DidPublisher>,
                LiveRelayUrl::new(RelayUrl::new("ws://198.51.100.7:32891/scp/v1").unwrap()),
            ),
            node_bridge_target(&identity.did).unwrap(),
            identity,
            LiveSlot::new(NodePublishedState {
                document,
                relay: crate::published_state::test_relay("ws://198.51.100.7:32891/scp/v1"),
                record: None,
            }),
            32891,
            Some(event_tx),
            // Use a long interval so the periodic timer does NOT fire first.
            Duration::from_hours(1),
        );

        // Give the spawned task a chance to enter the select! and start
        // listening on the network change detector before we send the event.
        tokio::task::yield_now().await;
        tokio::time::sleep(Duration::from_millis(10)).await;

        // Trigger a network change event — should NOT need to wait for the timer.
        net_change_tx.send(()).await.expect("send network change");

        // The network change triggers immediate re-evaluation.
        let event = tokio::time::timeout(TEST_EVENT_TIMEOUT, event_rx.recv())
            .await
            .expect("timeout waiting for tier change event")
            .expect("channel closed unexpectedly");

        match event {
            NatTierChange::TierChanged {
                previous_relay_url,
                new_relay_url,
                reason,
            } => {
                assert_eq!(previous_relay_url, "ws://198.51.100.7:32891/scp/v1");
                assert_eq!(new_relay_url, "ws://10.0.0.1:9999/scp/v1");
                assert!(
                    reason.contains("network change"),
                    "reason should mention network change: {reason}"
                );
            }
            other => panic!("expected TierChanged, got {other:?}"),
        }

        // Verify the DID document was republished immediately.
        assert_eq!(
            publisher.count(),
            1,
            "DID document should be republished after network change"
        );

        handle.stop();
    }

    #[tokio::test]
    async fn no_event_when_tier_unchanged_after_reevaluation() {
        // Verify that no TierChanged event is emitted when the tier stays the same.
        let addr = SocketAddr::from(([198, 51, 100, 7], 32891));

        // Return the same tier every time.
        let strategy = Arc::new(SequenceNatStrategy::new(vec![ReachabilityTier::Stun {
            external_addr: addr,
        }]));

        let publisher = Arc::new(RecordingPublisher::new());
        let (event_tx, mut event_rx) = tokio::sync::mpsc::channel(16);

        let identity = ScpIdentity {
            identity_key: scp_platform::KeyHandle::new(1),
            active_signing_key: scp_platform::KeyHandle::new(2),
            agent_signing_key: None,
            pre_rotation_commitment: [0u8; 32],
            did: "did:dht:unchanged123".to_owned(),
        };

        let document = DidDocument {
            context: vec!["https://www.w3.org/ns/did/v1".to_owned()],
            id: "did:dht:unchanged123".to_owned(),
            verification_method: vec![],
            authentication: vec![],
            assertion_method: vec![],
            also_known_as: vec![],
            service: vec![scp_did::Service {
                id: "did:dht:unchanged123#scp-relay-1".to_owned(),
                service_type: "SCPRelay".to_owned(),
                service_endpoint: "ws://198.51.100.7:32891/scp/v1".to_owned(),
                bridge_target: None,
            }],
        };

        let handle = spawn_tier_reevaluation(
            Arc::clone(&strategy) as Arc<dyn NatStrategy>,
            None,
            NodePublisher::from_dyn(
                Arc::clone(&publisher) as Arc<dyn DidPublisher>,
                LiveRelayUrl::new(RelayUrl::new("ws://198.51.100.7:32891/scp/v1").unwrap()),
            ),
            node_bridge_target(&identity.did).unwrap(),
            identity,
            LiveSlot::new(NodePublishedState {
                document,
                relay: crate::published_state::test_relay("ws://198.51.100.7:32891/scp/v1"),
                record: None,
            }),
            32891,
            Some(event_tx),
            TEST_REEVALUATION_INTERVAL,
        );

        // Wait long enough for the periodic timer to fire and the task to
        // complete its re-evaluation (same tier → no event, no publish).
        tokio::time::sleep(Duration::from_millis(200)).await;

        // No DID republish should happen.
        assert_eq!(
            publisher.count(),
            0,
            "DID document should NOT be republished when tier is unchanged"
        );

        // No event should be emitted.
        let recv_result = event_rx.try_recv();
        assert!(
            recv_result.is_err(),
            "no TierChanged event should be emitted when tier is unchanged"
        );

        handle.stop();
    }

    /// NAT strategy that fails on the first call and succeeds on subsequent calls.
    struct FailThenSucceedStrategy {
        call_count: std::sync::atomic::AtomicU32,
        success_tier: ReachabilityTier,
    }

    impl NatStrategy for FailThenSucceedStrategy {
        fn select_tier(
            &self,
            _relay_port: u16,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<ReachabilityTier, NodeError>> + Send + '_>,
        > {
            let n = self
                .call_count
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let tier = self.success_tier.clone();
            Box::pin(async move {
                if n == 0 {
                    Err(NodeError::Nat("transient STUN failure".into()))
                } else {
                    Ok(tier)
                }
            })
        }
    }

    #[tokio::test]
    async fn reevaluation_loop_survives_nat_probe_failure() {
        // Verify the loop continues when a NAT probe fails.
        let addr = SocketAddr::from(([198, 51, 100, 7], 32891));
        let new_addr = SocketAddr::from(([10, 0, 0, 1], 5000));

        let strategy = Arc::new(FailThenSucceedStrategy {
            call_count: std::sync::atomic::AtomicU32::new(0),
            success_tier: ReachabilityTier::Stun {
                external_addr: new_addr,
            },
        });

        let publisher = Arc::new(RecordingPublisher::new());
        let (event_tx, mut event_rx) = tokio::sync::mpsc::channel(16);

        let identity = ScpIdentity {
            identity_key: scp_platform::KeyHandle::new(1),
            active_signing_key: scp_platform::KeyHandle::new(2),
            agent_signing_key: None,
            pre_rotation_commitment: [0u8; 32],
            did: "did:dht:resilient123".to_owned(),
        };

        let document = DidDocument {
            context: vec!["https://www.w3.org/ns/did/v1".to_owned()],
            id: "did:dht:resilient123".to_owned(),
            verification_method: vec![],
            authentication: vec![],
            assertion_method: vec![],
            also_known_as: vec![],
            service: vec![scp_did::Service {
                id: "did:dht:resilient123#scp-relay-1".to_owned(),
                service_type: "SCPRelay".to_owned(),
                service_endpoint: format!("ws://{addr}/scp/v1"),
                bridge_target: None,
            }],
        };

        let handle = spawn_tier_reevaluation(
            strategy as Arc<dyn NatStrategy>,
            None,
            NodePublisher::from_dyn(
                Arc::clone(&publisher) as Arc<dyn DidPublisher>,
                LiveRelayUrl::new(RelayUrl::new("ws://198.51.100.7:32891/scp/v1").unwrap()),
            ),
            node_bridge_target(&identity.did).unwrap(),
            identity,
            LiveSlot::new(NodePublishedState {
                document,
                relay: crate::published_state::test_relay(&format!("ws://{addr}/scp/v1")),
                record: None,
            }),
            addr.port(),
            Some(event_tx),
            TEST_REEVALUATION_INTERVAL,
        );

        // The first cycle fails (NAT probe error), the second succeeds with
        // a new tier. With a 50ms interval, the event should arrive within
        // a few hundred ms.
        let event = tokio::time::timeout(TEST_EVENT_TIMEOUT, event_rx.recv())
            .await
            .expect("timeout waiting for tier change event after recovery")
            .expect("channel closed unexpectedly");
        assert!(matches!(event, NatTierChange::TierChanged { .. }));

        // The first cycle produced an error (no publish), the second
        // succeeded and triggered a publish — exactly 1 total.
        assert_eq!(
            publisher.count(),
            1,
            "republish after successful re-evaluation"
        );

        handle.stop();
    }

    /// `DidPublisher` double whose `Drop` takes a deliberate delay before
    /// recording that it ran. The tier task's captured `NodePublisher` is the
    /// only owner, so the flag flips only once the task future has been dropped
    /// and that drop has finished — the moment `stop_and_wait` must wait for.
    /// The drop then sends on `drop_tx`, so a test whose task is aborted
    /// rather than joined can wait for the drop without polling the flag.
    struct SlowDropPublisher {
        dropped: Arc<std::sync::atomic::AtomicBool>,
        drop_tx: std::sync::mpsc::Sender<()>,
    }

    /// Long enough that a waiter woken before the task future is dropped
    /// observes the flag still unset.
    const SLOW_DROP_DELAY: Duration = Duration::from_millis(300);

    impl Drop for SlowDropPublisher {
        fn drop(&mut self) {
            std::thread::sleep(SLOW_DROP_DELAY);
            self.dropped
                .store(true, std::sync::atomic::Ordering::SeqCst);
            let _ = self.drop_tx.send(());
        }
    }

    impl DidPublisher for SlowDropPublisher {
        fn publish<'a>(
            &'a self,
            _auth: PublishAuthorization,
            _identity: &'a ScpIdentity,
            _document: &'a DidDocument,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<
                        Output = Result<Option<scp_identity::republish::RepublishEntry>, NodeError>,
                    > + Send
                    + 'a,
            >,
        > {
            Box::pin(async { Ok(None) })
        }

        fn initialize_sequence<'a>(
            &'a self,
            _identity: &'a ScpIdentity,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), NodeError>> + Send + 'a>>
        {
            Box::pin(async { Ok(()) })
        }
    }

    /// NAT strategy that reports it was entered, then panics, so a test can
    /// drive the tier task down its panic path at a known point.
    struct PanickingNatStrategy {
        entered: std::sync::Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
    }

    impl NatStrategy for PanickingNatStrategy {
        fn select_tier(
            &self,
            _relay_port: u16,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<ReachabilityTier, NodeError>> + Send + '_>,
        > {
            let entered = self
                .entered
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take();
            if let Some(tx) = entered {
                let _ = tx.send(());
            }
            panic!("tier re-evaluation test double panics on purpose");
        }
    }

    fn slow_drop_tier_task(
        strategy: Arc<dyn NatStrategy>,
        interval: Duration,
    ) -> (
        TierReEvalHandle,
        Arc<std::sync::atomic::AtomicBool>,
        std::sync::mpsc::Receiver<()>,
    ) {
        let dropped = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (drop_tx, drop_rx) = std::sync::mpsc::channel();
        let publisher = Arc::new(SlowDropPublisher {
            dropped: Arc::clone(&dropped),
            drop_tx,
        });
        let document = DidDocument {
            context: vec!["https://www.w3.org/ns/did/v1".to_owned()],
            id: "did:dht:slowdrop".to_owned(),
            verification_method: vec![],
            authentication: vec![],
            assertion_method: vec![],
            also_known_as: vec![],
            service: vec![],
        };
        let handle = spawn_tier_reevaluation(
            strategy,
            None,
            NodePublisher::from_dyn(
                publisher as Arc<dyn DidPublisher>,
                LiveRelayUrl::new(RelayUrl::new("ws://198.51.100.7:32891/scp/v1").unwrap()),
            ),
            node_bridge_target("did:dht:slowdrop").unwrap(),
            ScpIdentity {
                identity_key: scp_platform::KeyHandle::new(1),
                active_signing_key: scp_platform::KeyHandle::new(2),
                agent_signing_key: None,
                pre_rotation_commitment: [0u8; 32],
                did: "did:dht:slowdrop".to_owned(),
            },
            LiveSlot::new(NodePublishedState {
                document,
                relay: crate::published_state::test_relay("ws://198.51.100.7:32891/scp/v1"),
                record: None,
            }),
            32891,
            None,
            interval,
        );
        (handle, dropped, drop_rx)
    }

    /// `stop_and_wait` returns only after the cancelled task's future, and the
    /// publisher it captured, has been dropped. A waiter woken any earlier lets
    /// a node restart reopen custody storage while the old task still holds it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn stop_and_wait_returns_after_cancelled_task_drops_its_captures() {
        let strategy = Arc::new(SequenceNatStrategy::new(vec![ReachabilityTier::Stun {
            external_addr: SocketAddr::from(([198, 51, 100, 7], 32891)),
        }]));
        let (handle, dropped, _) = slow_drop_tier_task(strategy, Duration::from_hours(1));

        handle.stop_and_wait();

        assert!(
            dropped.load(std::sync::atomic::Ordering::SeqCst),
            "stop_and_wait returned before the tier task's captured publisher was dropped"
        );
    }

    /// The same guarantee on the panic path: a task that panicked has its future
    /// dropped by the runtime, and `stop_and_wait` waits for that drop.
    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn stop_and_wait_returns_after_panicked_task_drops_its_captures() {
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let strategy = Arc::new(PanickingNatStrategy {
            entered: std::sync::Mutex::new(Some(entered_tx)),
        });
        let (handle, dropped, _) = slow_drop_tier_task(strategy, Duration::from_millis(1));

        entered_rx
            .await
            .expect("tier task reaches the panicking strategy");
        handle.stop_and_wait();

        assert!(
            dropped.load(std::sync::atomic::Ordering::SeqCst),
            "stop_and_wait returned before the panicked tier task's captured publisher was dropped"
        );
    }

    /// A caller running in a task on the node's own one-worker runtime holds
    /// that worker, so it must hand the worker off while it waits; otherwise
    /// neither the tier task nor the join forwarder can run before the deadline.
    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn stop_and_wait_on_a_runtime_worker_returns_after_task_drops_its_captures() {
        let strategy = Arc::new(SequenceNatStrategy::new(vec![ReachabilityTier::Stun {
            external_addr: SocketAddr::from(([198, 51, 100, 7], 32891)),
        }]));
        let (handle, dropped, _) = slow_drop_tier_task(strategy, Duration::from_hours(1));

        tokio::spawn(async move { handle.stop_and_wait() })
            .await
            .expect("stop_and_wait does not panic on a runtime worker");

        assert!(
            dropped.load(std::sync::atomic::Ordering::SeqCst),
            "stop_and_wait on a runtime worker returned before the tier task's captured publisher was dropped"
        );
    }

    /// The FFI bridges' shape: the node's task runs on a multi-thread runtime,
    /// and `stop_and_wait` is called from a host thread that never entered any
    /// runtime. It must still return only after the task's captures dropped.
    #[test]
    fn stop_and_wait_off_runtime_returns_after_task_drops_its_captures() {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .expect("multi-thread runtime builds");
        let (handle, dropped, _) = {
            let _entered = runtime.enter();
            let strategy = Arc::new(SequenceNatStrategy::new(vec![ReachabilityTier::Stun {
                external_addr: SocketAddr::from(([198, 51, 100, 7], 32891)),
            }]));
            slow_drop_tier_task(strategy, Duration::from_hours(1))
        };

        let warnings = std::thread::spawn(move || {
            let warnings = Arc::new(WarnCounter::default());
            tracing::subscriber::with_default(Arc::clone(&warnings), || handle.stop_and_wait());
            warnings.count()
        })
        .join()
        .expect("stop_and_wait does not panic off-runtime");

        assert!(
            dropped.load(std::sync::atomic::Ordering::SeqCst),
            "stop_and_wait returned before the tier task's captured publisher was dropped"
        );
        assert_eq!(warnings, 0, "a completed join logged a warning");
    }

    /// Counts the WARN events emitted on the thread it is the default
    /// subscriber for.
    #[derive(Default)]
    struct WarnCounter(std::sync::atomic::AtomicUsize);

    impl WarnCounter {
        fn count(&self) -> usize {
            self.0.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    impl tracing::Subscriber for WarnCounter {
        fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
            true
        }
        fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }
        fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
        fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
        fn event(&self, event: &tracing::Event<'_>) {
            if *event.metadata().level() == tracing::Level::WARN {
                self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
        }
        fn enter(&self, _: &tracing::span::Id) {}
        fn exit(&self, _: &tracing::span::Id) {}
    }

    /// Once the task's runtime has shut down, the join forwarder is dropped
    /// without sending, so `stop_and_wait` never observes a join. It must log
    /// that at warn rather than return as if the join had completed.
    #[test]
    fn stop_and_wait_logs_a_warning_when_its_runtime_has_shut_down() {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .expect("multi-thread runtime builds");
        let (handle, _, _) = {
            let _entered = runtime.enter();
            let strategy = Arc::new(SequenceNatStrategy::new(vec![ReachabilityTier::Stun {
                external_addr: SocketAddr::from(([198, 51, 100, 7], 32891)),
            }]));
            slow_drop_tier_task(strategy, Duration::from_hours(1))
        };
        drop(runtime);
        let warnings = Arc::new(WarnCounter::default());

        tracing::subscriber::with_default(Arc::clone(&warnings), || handle.stop_and_wait());

        assert_eq!(
            warnings.count(),
            1,
            "stop_and_wait did not log the unobserved join"
        );
    }

    /// NAT strategy that reports it was entered, then never completes, so the
    /// tier task sits in an in-flight re-evaluation that never reads its cancel
    /// signal.
    struct StuckNatStrategy {
        entered: std::sync::Mutex<Option<std::sync::mpsc::Sender<()>>>,
    }

    impl NatStrategy for StuckNatStrategy {
        fn select_tier(
            &self,
            _relay_port: u16,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<ReachabilityTier, NodeError>> + Send + '_>,
        > {
            let entered = self
                .entered
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take();
            if let Some(tx) = entered {
                let _ = tx.send(());
            }
            Box::pin(std::future::pending())
        }
    }

    /// A task stuck inside a re-evaluation never sees the cancel signal. An
    /// off-runtime caller (the FFI bridges' shape) must still get control back, not
    /// block forever, and the deadline's abort must drop the task's captures.
    #[test]
    fn stop_and_wait_off_runtime_returns_and_drops_captures_of_a_stuck_task() {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .expect("multi-thread runtime builds");
        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let (mut handle, _, drop_rx) = {
            let _entered = runtime.enter();
            let strategy = Arc::new(StuckNatStrategy {
                entered: std::sync::Mutex::new(Some(entered_tx)),
            });
            slow_drop_tier_task(strategy, Duration::from_millis(1))
        };
        handle.stop_deadline = Duration::from_millis(100);
        entered_rx
            .recv_timeout(Duration::from_secs(30))
            .expect("tier task enters the stuck re-evaluation");
        let (returned_tx, returned_rx) = std::sync::mpsc::channel();

        std::thread::spawn(move || {
            handle.stop_and_wait();
            let _ = returned_tx.send(());
        });

        returned_rx
            .recv_timeout(Duration::from_secs(30))
            .expect("stop_and_wait did not return within 30 s on a stuck task");
        drop_rx
            .recv_timeout(Duration::from_secs(30))
            .expect("the stuck tier task's captured publisher was not dropped after the deadline");
    }

    /// A node dropped without `shutdown()` drops its `TierReEvalHandle`.
    /// Dropping a `JoinHandle` only detaches its task, so `Drop` must abort a
    /// task stuck in a re-evaluation, dropping its captures.
    #[test]
    fn dropping_the_handle_aborts_a_stuck_task() {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .expect("multi-thread runtime builds");
        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let (handle, _, drop_rx) = {
            let _entered = runtime.enter();
            let strategy = Arc::new(StuckNatStrategy {
                entered: std::sync::Mutex::new(Some(entered_tx)),
            });
            slow_drop_tier_task(strategy, Duration::from_millis(1))
        };
        entered_rx
            .recv_timeout(Duration::from_secs(30))
            .expect("tier task enters the stuck re-evaluation");

        drop(handle);

        drop_rx.recv_timeout(Duration::from_secs(30)).expect(
            "the stuck tier task's captured publisher was not dropped after its handle dropped",
        );
    }

    /// A `current_thread` caller cannot block: with the task on a multi-thread
    /// runtime, `stop_and_wait` called inside a `current_thread` runtime must
    /// return instead of panicking in `block_in_place`, and its abort must drop
    /// the captures of a task stuck in a re-evaluation.
    #[test]
    fn stop_and_wait_from_current_thread_caller_aborts_a_stuck_task() {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .expect("multi-thread runtime builds");
        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let (handle, _, drop_rx) = {
            let _entered = runtime.enter();
            let strategy = Arc::new(StuckNatStrategy {
                entered: std::sync::Mutex::new(Some(entered_tx)),
            });
            slow_drop_tier_task(strategy, Duration::from_millis(1))
        };
        entered_rx
            .recv_timeout(Duration::from_secs(30))
            .expect("tier task enters the stuck re-evaluation");
        let caller = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("current-thread runtime builds");

        caller.block_on(async { handle.stop_and_wait() }); // ci-allow: block-on: test enters a current_thread runtime to call stop_and_wait from its context

        drop_rx
            .recv_timeout(Duration::from_secs(30))
            .expect("the stuck tier task's captured publisher was not dropped after the abort");
    }

    /// A task spawned on a `current_thread` runtime advances only while that
    /// runtime's owner drives it. Here the owner is blocked waiting on the
    /// caller thread, so `stop_and_wait` must return rather than block on a join
    /// nothing will drive.
    #[test]
    fn stop_and_wait_on_current_thread_runtime_task_returns() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("current-thread runtime builds");
        let (mut handle, _, _) = {
            let _entered = runtime.enter();
            let strategy = Arc::new(SequenceNatStrategy::new(vec![ReachabilityTier::Stun {
                external_addr: SocketAddr::from(([198, 51, 100, 7], 32891)),
            }]));
            slow_drop_tier_task(strategy, Duration::from_hours(1))
        };
        // Far above the 30 s receive bound below, so a wait on the undriven
        // join cannot end at the deadline in time to pass.
        handle.stop_deadline = Duration::from_hours(1);
        let (returned_tx, returned_rx) = std::sync::mpsc::channel();

        std::thread::spawn(move || {
            handle.stop_and_wait();
            let _ = returned_tx.send(());
        });

        returned_rx
            .recv_timeout(Duration::from_secs(30))
            .expect("stop_and_wait did not return within 30 s; it blocked on an undriven join");
    }

    #[tokio::test]
    async fn no_domain_build_spawns_tier_reevaluation_task() {
        // Verify that the no-domain build path spawns the re-evaluation task.
        let tier = ReachabilityTier::Stun {
            external_addr: SocketAddr::from(([198, 51, 100, 7], 32891)),
        };

        let node = Node::start_for_testing(no_domain_config(tier))
            .await
            .unwrap();

        assert!(
            node.tier_reeval.is_some(),
            "no-domain mode should spawn the tier re-evaluation task"
        );
        assert!(
            node.tier_change_rx.is_some(),
            "no-domain mode should provide a tier change event channel"
        );

        node.shutdown();
    }

    #[tokio::test]
    async fn domain_build_does_not_spawn_tier_reevaluation_task() {
        // Verify that the domain build path does NOT spawn re-evaluation
        // (Tier 4 doesn't need NAT re-eval).
        let node = Node::start_for_testing(domain_config()).await.unwrap();

        assert!(
            node.tier_reeval.is_none(),
            "domain mode should NOT spawn the tier re-evaluation task"
        );
        assert!(
            node.tier_change_rx.is_none(),
            "domain mode should NOT provide a tier change event channel"
        );

        node.shutdown();
    }

    // -----------------------------------------------------------------------
    // The node's published state is a LIVE slot, not a build-time snapshot
    // (SCP-243 §10.12.1 / SCP-RELAYRES-004). See `NodePublishedState`.
    //
    // `apply_tier_change` re-points the node's relay endpoint on a NAT tier
    // change. These tests drive a REAL tier change on a REAL node — real
    // builder, real tier re-evaluation task, real publish seam — and assert
    // against the real handler RESPONSE BODIES and public accessors, never a
    // field: the token-gated `GET /scp/dev/v1/identity` document, the public
    // `IdentityHandle::document`, the PUBLIC UNAUTHENTICATED
    // `GET /.well-known/scp` top-level `relay` field and invite-URI `relay=`
    // parameters, and `ApplicationNode::relay_url`. Every one must advance, and
    // — the actual invariant — they must all AGREE.
    // -----------------------------------------------------------------------

    /// The pre-tier-change relay endpoint these tests start at.
    const TIER_CHANGE_OLD_URL: &str = "ws://198.51.100.7:32891/scp/v1";
    /// The post-tier-change relay endpoint these tests expect to be served.
    const TIER_CHANGE_NEW_URL: &str = "ws://203.0.113.42:8443/scp/v1";
    /// The context ID registered so the discovery document actually contains
    /// `scp://context/…?relay=` URIs to check.
    const WELL_KNOWN_TEST_CONTEXT: &str = "beefcafe";

    /// Builds a no-domain `NodeConfig` whose NAT probe walks a STUN tier then a
    /// `UPnP` tier (`TIER_CHANGE_OLD_URL` then `TIER_CHANGE_NEW_URL`), and whose
    /// network-change detector is driven by the returned sender.
    ///
    /// The build path calls `select_tier` exactly once, so the first tier is the
    /// node's startup tier and the sender triggers the re-evaluation that reaches
    /// the second — a real tier change, without waiting out the 30-minute
    /// production timer or reaching into the task.
    fn tier_change_config(
        dht: DhtMode,
    ) -> (
        NodeConfig<InMemoryKeyCustody, TestDidDht, InMemoryStorage>,
        tokio::sync::mpsc::Sender<()>,
    ) {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let did_method = Arc::new(make_test_dht(&custody));
        let (net_change_tx, net_change_rx) = tokio::sync::mpsc::channel(16);
        let config = NodeConfig {
            bind_addr: Some(SocketAddr::from(([127, 0, 0, 1], 0))),
            dht,
            nat: NatSlot::Custom(Arc::new(SequenceNatStrategy::new(vec![
                ReachabilityTier::Stun {
                    external_addr: SocketAddr::from(([198, 51, 100, 7], 32891)),
                },
                ReachabilityTier::Upnp {
                    external_addr: SocketAddr::from(([203, 0, 113, 42], 8443)),
                },
            ]))),
            network_detector: Some(Arc::new(
                scp_transport::nat::ChannelNetworkChangeDetector::new(net_change_rx),
            )),
            ..NodeConfig::defaults(
                Reach::NatTraversal,
                IdentitySource::Generate {
                    custody,
                    did_method,
                },
                InMemoryStorage::new(),
                BlobStorageBackend::in_memory(),
            )
        };
        (config, net_change_tx)
    }

    /// Every relay endpoint the node exposes, read back through the REAL
    /// surfaces a caller uses:
    /// `(dev-API document, IdentityHandle document, .well-known top-level relay,
    /// .well-known invite-URI relays, ApplicationNode::relay_url)`.
    async fn advertised_relay_surfaces<S: scp_platform::traits::Storage>(
        node: &ApplicationNode<S>,
    ) -> (Vec<String>, Vec<String>, String, Vec<String>, String) {
        use axum::response::IntoResponse as _;

        let state = &node.state;
        let identity_response =
            crate::dev_api::identity_handler(axum::extract::State(Arc::clone(state)))
                .await
                .into_response();
        let identity_body = axum::body::to_bytes(identity_response.into_body(), usize::MAX)
            .await
            .expect("the dev API identity body is readable");
        let identity_json: serde_json::Value =
            serde_json::from_slice(&identity_body).expect("the dev API identity response is JSON");
        let dev_api_document: DidDocument =
            serde_json::from_value(identity_json["document"].clone())
                .expect("the dev API serves a full DID document, not the DID-string fallback");

        let well_known_response =
            crate::well_known::well_known_handler(axum::extract::State(Arc::clone(state)))
                .await
                .into_response();
        let well_known_body = axum::body::to_bytes(well_known_response.into_body(), usize::MAX)
            .await
            .expect("the .well-known/scp body is readable");
        let well_known: scp_core::well_known::WellKnownScp =
            serde_json::from_slice(&well_known_body).expect("the .well-known/scp response is JSON");

        let uri_relays = well_known
            .contexts
            .unwrap_or_default()
            .into_iter()
            .map(|ctx| {
                let uri = ctx
                    .uri
                    .expect("a broadcast context advertises an invite URI");
                let query = uri
                    .split_once('?')
                    .expect("the invite URI carries a query string")
                    .1;
                let encoded = query
                    .split('&')
                    .find_map(|pair| pair.strip_prefix("relay="))
                    .expect("the invite URI carries a relay= parameter");
                percent_encoding::percent_decode_str(encoded)
                    .decode_utf8()
                    .expect("the relay= parameter is UTF-8")
                    .into_owned()
            })
            .collect();

        (
            dev_api_document.relay_service_urls(),
            node.identity().document().relay_service_urls(),
            well_known.relay,
            uri_relays,
            node.relay_url(),
        )
    }

    /// Asserts every advertised surface names `expected`, and therefore agrees
    /// with every other. Nothing else pins the surfaces to EACH OTHER, which is
    /// the invariant the single slot exists to hold.
    async fn assert_all_surfaces_advertise<S: scp_platform::traits::Storage>(
        node: &ApplicationNode<S>,
        expected: &str,
        when: &str,
    ) {
        let (dev_api, handle, well_known_relay, uri_relays, accessor) =
            advertised_relay_surfaces(node).await;
        let expected_one = vec![expected.to_owned()];
        assert_eq!(dev_api, expected_one, "dev-API document, {when}");
        assert_eq!(handle, expected_one, "IdentityHandle::document, {when}");
        assert_eq!(
            well_known_relay, expected,
            "the PUBLIC .well-known/scp top-level relay, {when}"
        );
        assert_eq!(
            uri_relays, expected_one,
            "the PUBLIC .well-known/scp invite-URI relay= parameters, {when}"
        );
        assert_eq!(accessor, expected, "ApplicationNode::relay_url, {when}");
    }

    /// Drives the node through one real tier change and returns once it has been
    /// applied.
    ///
    /// The tier task writes the slot BEFORE emitting `TierChanged`, so awaiting
    /// the event is a happens-before edge for the update — no polling, no sleep.
    async fn drive_tier_change<S: scp_platform::traits::Storage>(
        node: &mut ApplicationNode<S>,
        net_change_tx: &tokio::sync::mpsc::Sender<()>,
    ) {
        net_change_tx
            .send(())
            .await
            .expect("the network-change detector is listening");
        let event = tokio::time::timeout(
            TEST_EVENT_TIMEOUT,
            node.tier_change_rx()
                .expect("a no-domain node streams tier changes")
                .recv(),
        )
        .await
        .expect("timed out waiting for the tier change")
        .expect("the tier-change channel closed unexpectedly");
        match event {
            NatTierChange::TierChanged {
                previous_relay_url,
                new_relay_url,
                ..
            } => {
                assert_eq!(previous_relay_url, TIER_CHANGE_OLD_URL);
                assert_eq!(new_relay_url, TIER_CHANGE_NEW_URL);
            }
            other => panic!("expected TierChanged, got {other:?}"),
        }
    }

    /// THE regression: a NAT tier change re-signs and re-publishes the node's DID
    /// document with a NEW relay endpoint, and EVERY surface that reports the
    /// node's address must report THAT one — the token-gated dev API, the public
    /// identity handle, the public unauthenticated discovery document (top-level
    /// field and invite URIs alike) and the public accessor.
    ///
    /// Against the pre-fix code this fails on every surface: each held its own
    /// build-time copy, so the dev API served a document naming a dead relay and
    /// `.well-known/scp` handed every peer an address the node had moved off.
    #[tokio::test]
    async fn tier_change_advances_every_advertised_surface_in_agreement() {
        let (config, net_change_tx) = tier_change_config(DhtMode::Production);
        let mut node = Node::start_for_testing(config)
            .await
            .expect("the no-domain node starts");
        node.register_broadcast_context(WELL_KNOWN_TEST_CONTEXT.to_owned(), None)
            .await
            .expect("a broadcast context registers");

        assert_all_surfaces_advertise(&node, TIER_CHANGE_OLD_URL, "at startup").await;
        let published_before = node
            .published_did_record()
            .expect("a publishing node signs a record at startup");

        drive_tier_change(&mut node, &net_change_tx).await;

        // The re-publish genuinely happened: a new signed record at a higher
        // BEP44 sequence. Without this the surface assertions could pass on a
        // change that was never published.
        let published_after = node
            .published_did_record()
            .expect("the tier change re-published");
        assert!(
            published_after.sequence > published_before.sequence,
            "the tier-change re-publish assigns a HIGHER sequence ({} -> {})",
            published_before.sequence,
            published_after.sequence
        );
        assert!(
            String::from_utf8_lossy(&published_after.document_bytes).contains(TIER_CHANGE_NEW_URL),
            "the re-published record carries the NEW relay endpoint"
        );

        assert_all_surfaces_advertise(&node, TIER_CHANGE_NEW_URL, "after the tier change").await;

        node.shutdown();
    }

    /// Publishes a one-byte blob over the node's internal WebSocket relay to the
    /// reserved push routing ID that a client derives from `url`,
    /// `SHA-256("scp-push-registration" || canonical url)` (§10.7.1 step 2), and
    /// returns the relay's reply.
    async fn publish_to_reserved_push_id<S: scp_platform::traits::Storage>(
        node: &ApplicationNode<S>,
        url: &str,
    ) -> scp_relay_client::RelayMessage {
        use futures::{SinkExt as _, StreamExt as _};
        use tokio_tungstenite::tungstenite::{Message, client::IntoClientRequest as _};

        let routing_id = scp_transport::relay::push_gate::RelayUrl::new(url)
            .expect("the advertised relay URL has a canonical form")
            .push_routing_id();
        let mut request = format!("ws://{}/scp/v1", node.relay().bound_addr())
            .into_client_request()
            .expect("the relay address forms a request");
        request.headers_mut().insert(
            "Authorization",
            format!("Bearer {}", node.bridge_token_hex().as_str())
                .parse()
                .expect("the bridge token is a valid header value"),
        );
        let (mut ws, _) = tokio_tungstenite::connect_async(request)
            .await
            .expect("the internal relay accepts the bridge token");
        let publish = scp_relay_client::ClientMessage::Publish {
            ref_id: None,
            routing_id,
            recipient_hint: None,
            blob_ttl: 3600,
            blob: vec![1],
        };
        ws.send(Message::Binary(
            publish.to_bytes().expect("PUBLISH encodes"),
        ))
        .await
        .expect("the PUBLISH is sent");
        let frame = tokio::time::timeout(TEST_EVENT_TIMEOUT, ws.next())
            .await
            .expect("the relay answers the PUBLISH in time")
            .expect("the relay keeps the connection open")
            .expect("the relay frame is readable");
        match frame {
            Message::Binary(bytes) => {
                scp_relay_client::RelayMessage::from_bytes(&bytes).expect("the reply decodes")
            }
            other => panic!("expected a binary relay frame, got {other:?}"),
        }
    }

    /// Asserts the relay answered a PUBLISH to its reserved push routing ID as
    /// a relay with no push service must: `4063` and no blob stored (§10.7.1
    /// "No blob storage"). An `OK` carrying a `blob_id` means the relay did not
    /// recognize the routing ID as reserved and stored the message as a blob.
    fn assert_push_not_supported(reply: &scp_relay_client::RelayMessage, when: &str) {
        assert!(
            matches!(
                reply,
                scp_relay_client::RelayMessage::Err {
                    code: scp_relay_client::code::PUSH_NOT_SUPPORTED,
                    ..
                }
            ),
            "{when}: expected ERR 4063 PUSH_NOT_SUPPORTED, got {reply:?}"
        );
    }

    type NodeRelayWs = tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >;

    /// Opens a WebSocket to the node's internal relay with the bridge token.
    async fn connect_node_relay<S: scp_platform::traits::Storage>(
        node: &ApplicationNode<S>,
    ) -> NodeRelayWs {
        use tokio_tungstenite::tungstenite::client::IntoClientRequest as _;
        let mut request = format!("ws://{}/scp/v1", node.relay().bound_addr())
            .into_client_request()
            .expect("the relay address forms a request");
        request.headers_mut().insert(
            "Authorization",
            format!("Bearer {}", node.bridge_token_hex().as_str())
                .parse()
                .expect("the bridge token is a valid header value"),
        );
        tokio_tungstenite::connect_async(request)
            .await
            .expect("the internal relay accepts the bridge token")
            .0
    }

    /// Sends `msg` over `ws` without waiting for a reply.
    async fn send_node_relay(ws: &mut NodeRelayWs, msg: &scp_relay_client::ClientMessage) {
        use futures::SinkExt as _;
        ws.send(tokio_tungstenite::tungstenite::Message::Binary(
            msg.to_bytes().expect("the client message encodes"),
        ))
        .await
        .expect("the client message is sent");
    }

    /// Reads the next relay message from `ws`.
    async fn recv_node_relay(ws: &mut NodeRelayWs) -> scp_relay_client::RelayMessage {
        use futures::StreamExt as _;
        let frame = tokio::time::timeout(TEST_EVENT_TIMEOUT, ws.next())
            .await
            .expect("the relay answers in time")
            .expect("the relay keeps the connection open")
            .expect("the relay frame is readable");
        match frame {
            tokio_tungstenite::tungstenite::Message::Binary(bytes) => {
                scp_relay_client::RelayMessage::from_bytes(&bytes).expect("the reply decodes")
            }
            other => panic!("expected a binary relay frame, got {other:?}"),
        }
    }

    /// Publishes a one-byte blob at `routing_id` on the node's internal relay
    /// and returns the reply.
    async fn publish_at<S: scp_platform::traits::Storage>(
        node: &ApplicationNode<S>,
        routing_id: [u8; 32],
    ) -> scp_relay_client::RelayMessage {
        let mut ws = connect_node_relay(node).await;
        send_node_relay(
            &mut ws,
            &scp_relay_client::ClientMessage::Publish {
                ref_id: None,
                routing_id,
                recipient_hint: None,
                blob_ttl: 3600,
                blob: vec![1],
            },
        )
        .await;
        recv_node_relay(&mut ws).await
    }

    /// The number of BLOBs a QUERY at `routing_id` returns before
    /// `query_complete`.
    async fn query_blob_count<S: scp_platform::traits::Storage>(
        node: &ApplicationNode<S>,
        routing_id: [u8; 32],
    ) -> usize {
        let mut ws = connect_node_relay(node).await;
        send_node_relay(
            &mut ws,
            &scp_relay_client::ClientMessage::Query {
                ref_id: None,
                routing_id,
                since: None,
                limit: None,
            },
        )
        .await;
        let mut blobs = 0;
        loop {
            match recv_node_relay(&mut ws).await {
                scp_relay_client::RelayMessage::Blob { .. } => blobs += 1,
                scp_relay_client::RelayMessage::Event { event_type, .. }
                    if event_type == "query_complete" =>
                {
                    return blobs;
                }
                other => panic!("QUERY answered {other:?}"),
            }
        }
    }

    /// The number of BLOBs a SUBSCRIBE with backfill at `routing_id` returns
    /// before `backfill_complete`.
    async fn subscribe_backfill_count<S: scp_platform::traits::Storage>(
        node: &ApplicationNode<S>,
        routing_id: [u8; 32],
    ) -> usize {
        let mut ws = connect_node_relay(node).await;
        send_node_relay(
            &mut ws,
            &scp_relay_client::ClientMessage::Subscribe {
                ref_id: None,
                routing_id,
                since: Some(0),
            },
        )
        .await;
        let mut blobs = 0;
        loop {
            match recv_node_relay(&mut ws).await {
                scp_relay_client::RelayMessage::Ok { .. } => {}
                scp_relay_client::RelayMessage::Blob { .. } => blobs += 1,
                scp_relay_client::RelayMessage::Event { event_type, .. }
                    if event_type == "backfill_complete" =>
                {
                    return blobs;
                }
                other => panic!("SUBSCRIBE answered {other:?}"),
            }
        }
    }

    /// The node's tier 3 entry for `bridge_url`, as `tier_to_relay_service`
    /// builds it from the node's own DID.
    fn node_tier3_entry<S: scp_platform::traits::Storage>(
        node: &ApplicationNode<S>,
        bridge_url: &str,
    ) -> scp_did::RelayService {
        scp_did::RelayService::bridge(
            scp_did::BridgeEndpoint::new(bridge_url).expect("a wss bridge URL"),
            node_bridge_target(node.identity().did()).expect("not the absent value"),
        )
    }

    /// The `"scp-push-registration"` ID of `url`, which a node relay holding
    /// a tier 3 entry for `url` does not reserve.
    fn registration_id(url: &str) -> [u8; 32] {
        RelayUrl::new(url).expect("canonical URL").push_routing_id()
    }

    /// §10.7.1 "Tier 3 relays" at the node's listener: a PUBLISH at the
    /// entry's tier 3 ID is answered with `4063`, and a QUERY and a SUBSCRIBE
    /// there return nothing; a PUBLISH at the bridge relay's own
    /// `"scp-push-registration"` ID is stored as a blob that a QUERY returns.
    async fn assert_tier3_id_intercepted<S: scp_platform::traits::Storage>(
        node: &ApplicationNode<S>,
        entry: &scp_did::RelayService,
        when: &str,
    ) {
        let tier3 = RelayUrl::from(entry).push_routing_id();
        let bridge_own = registration_id(entry.url());
        assert_ne!(tier3, bridge_own, "{when}: the tier 3 ID is its own");
        assert_push_not_supported(&publish_at(node, tier3).await, when);
        assert_eq!(query_blob_count(node, tier3).await, 0, "{when}: QUERY");
        assert_eq!(
            subscribe_backfill_count(node, tier3).await,
            0,
            "{when}: SUBSCRIBE"
        );
        let reply = publish_at(node, bridge_own).await;
        assert!(
            matches!(
                reply,
                scp_relay_client::RelayMessage::Ok {
                    blob_id: Some(_),
                    ..
                }
            ),
            "{when}: the bridge relay's own ID stores, got {reply:?}"
        );
        assert_eq!(
            query_blob_count(node, bridge_own).await,
            1,
            "{when}: QUERY at the bridge relay's own ID"
        );
    }

    /// Criterion 6 at startup: a no-domain node whose startup tier is a
    /// bridge reserves the tier 3 push routing ID of the entry it publishes,
    /// never the bridge relay's own ID, before its first publish.
    #[tokio::test]
    async fn no_domain_node_reserves_its_tier3_id_at_startup() {
        let (mut config, _net_change_tx) = tier_change_config(DhtMode::Disabled);
        config.nat = NatSlot::Custom(Arc::new(SequenceNatStrategy::new(vec![
            ReachabilityTier::Bridge {
                bridge_url: scp_did::BridgeEndpoint::new(SLOT_BRIDGE_URL).unwrap(),
            },
        ])));
        let node = Node::start_for_testing(config)
            .await
            .expect("the no-domain node starts");
        let entry = node_tier3_entry(&node, SLOT_BRIDGE_URL);
        assert_eq!(
            node.identity().document().relay_services(),
            vec![entry.clone()]
        );
        assert_tier3_id_intercepted(&node, &entry, "at startup").await;
        assert_eq!(
            node.state.relay_config.relay_url.current(),
            scp_transport::relay::push_gate::ReservedRelayUrls::from(RelayUrl::from(&entry))
        );
        node.shutdown();
    }

    /// Criterion 6 for several entries: a node whose `IdentitySource::Explicit`
    /// document carries a second tier 3 entry with the node's `bridgeTarget`
    /// reserves that entry's tier 3 ID beside its own entry's ID at startup,
    /// and again after a tier change moves its own entry to a bridge. An
    /// entry for another target is never reserved.
    #[tokio::test]
    async fn explicit_node_reserves_its_documents_second_tier3_entry_at_startup_and_after_a_tier_change()
     {
        const SECOND_BRIDGE_URL: &str = "wss://bridge-two.example.net/scp/v1";
        let (identity, mut document, custody) = create_test_identity().await;
        let target = node_bridge_target(&identity.did).expect("not the absent value");
        let second = scp_did::RelayService::bridge(
            scp_did::BridgeEndpoint::new(SECOND_BRIDGE_URL).expect("a wss bridge URL"),
            target,
        );
        let foreign = scp_did::RelayService::bridge(
            scp_did::BridgeEndpoint::new("wss://bridge-three.example.org/scp/v1")
                .expect("a wss bridge URL"),
            scp_did::BridgeTarget::new([0x5a; 32]).expect("not the absent value"),
        );
        document.add_relay_service(&second);
        document.add_relay_service(&foreign);

        let (mut config, net_change_tx) = tier_change_config(DhtMode::Disabled);
        config.identity = IdentitySource::Explicit(Box::new(ExplicitIdentity {
            identity,
            document,
            did_method: Arc::new(make_test_dht(&custody)),
        }));
        config.nat = NatSlot::Custom(Arc::new(SequenceNatStrategy::new(vec![
            ReachabilityTier::Stun {
                external_addr: SocketAddr::from(([198, 51, 100, 7], 32891)),
            },
            ReachabilityTier::Bridge {
                bridge_url: scp_did::BridgeEndpoint::new(SLOT_BRIDGE_URL).unwrap(),
            },
        ])));
        let mut node = Node::start_for_testing(config)
            .await
            .expect("the explicit no-domain node starts");
        let relay = node.state.relay_config.relay_url.clone();
        let second_id = RelayUrl::from(&second).push_routing_id();
        let foreign_id = RelayUrl::from(&foreign).push_routing_id();

        assert_eq!(
            relay.current(),
            scp_transport::relay::push_gate::ReservedRelayUrls::new(
                RelayUrl::new(TIER_CHANGE_OLD_URL).unwrap(),
                [RelayUrl::from(&second)],
            ),
            "at startup: the own direct entry and the document's tier 3 entry"
        );
        assert_tier3_id_intercepted(&node, &second, "at startup").await;
        assert!(
            matches!(
                publish_at(&node, foreign_id).await,
                scp_relay_client::RelayMessage::Ok {
                    blob_id: Some(_),
                    ..
                }
            ),
            "another target's tier 3 ID is an ordinary routing ID"
        );

        await_tier_change(
            &mut node,
            &net_change_tx,
            TIER_CHANGE_OLD_URL,
            SLOT_BRIDGE_URL,
        )
        .await;
        let own = node_tier3_entry(&node, SLOT_BRIDGE_URL);
        assert_eq!(
            relay.current(),
            scp_transport::relay::push_gate::ReservedRelayUrls::new(
                RelayUrl::from(&own),
                [RelayUrl::from(&second)],
            ),
            "after the tier change: both tier 3 entries"
        );
        for (label, id) in [
            ("own tier 3 entry", RelayUrl::from(&own).push_routing_id()),
            ("second tier 3 entry", second_id),
        ] {
            assert_push_not_supported(&publish_at(&node, id).await, label);
            assert_eq!(query_blob_count(&node, id).await, 0, "{label}: QUERY");
        }
        node.shutdown();
    }

    /// §10.7.1 "Tier 3 relays" on the domain builder: a domain node whose
    /// `IdentitySource::Explicit` document carries a tier 3 entry with the
    /// node's `bridgeTarget` reserves that entry's tier 3 ID beside the domain
    /// entry's `"scp-push-registration"` ID before its startup publish, so a
    /// plaintext PUBLISH there gets `4063` and a QUERY returns nothing. An
    /// entry for another target stays an ordinary routing ID.
    #[tokio::test]
    async fn domain_node_reserves_its_explicit_documents_tier3_entry_at_startup() {
        let (identity, mut document, custody) = create_test_identity().await;
        let target = node_bridge_target(&identity.did).expect("not the absent value");
        let tier3 = scp_did::RelayService::bridge(
            scp_did::BridgeEndpoint::new(SLOT_BRIDGE_URL).expect("a wss bridge URL"),
            target,
        );
        let foreign = scp_did::RelayService::bridge(
            scp_did::BridgeEndpoint::new("wss://bridge-three.example.org/scp/v1")
                .expect("a wss bridge URL"),
            scp_did::BridgeTarget::new([0x5a; 32]).expect("not the absent value"),
        );
        document.add_relay_service(&tier3);
        document.add_relay_service(&foreign);
        let mut config = domain_config();
        config.identity = IdentitySource::Explicit(Box::new(ExplicitIdentity {
            identity,
            document,
            did_method: Arc::new(make_test_dht(&custody)),
        }));

        let node = Node::start_for_testing(config)
            .await
            .expect("the explicit domain node starts");

        assert!(
            node.identity().document().relay_services().contains(&tier3),
            "the domain node publishes the Explicit document's tier 3 entry"
        );
        assert_eq!(
            node.state.relay_config.relay_url.current(),
            scp_transport::relay::push_gate::ReservedRelayUrls::new(
                RelayUrl::new(&domain_relay_url("test.example.com")).unwrap(),
                [RelayUrl::from(&tier3)],
            ),
            "the domain entry and the document's tier 3 entry with this node's target"
        );
        let tier3_id = RelayUrl::from(&tier3).push_routing_id();
        assert_push_not_supported(&publish_at(&node, tier3_id).await, "tier 3 entry");
        assert_eq!(
            query_blob_count(&node, tier3_id).await,
            0,
            "tier 3 entry: QUERY"
        );
        assert!(
            matches!(
                publish_at(&node, RelayUrl::from(&foreign).push_routing_id()).await,
                scp_relay_client::RelayMessage::Ok {
                    blob_id: Some(_),
                    ..
                }
            ),
            "another target's tier 3 ID is an ordinary routing ID"
        );
        node.shutdown();
    }

    /// Waits for the next `TierChanged` event and checks its URLs.
    async fn await_tier_change<S: scp_platform::traits::Storage>(
        node: &mut ApplicationNode<S>,
        net_change_tx: &tokio::sync::mpsc::Sender<()>,
        previous: &str,
        new: &str,
    ) {
        net_change_tx
            .send(())
            .await
            .expect("the network-change detector is listening");
        let event = tokio::time::timeout(
            TEST_EVENT_TIMEOUT,
            node.tier_change_rx()
                .expect("a no-domain node streams tier changes")
                .recv(),
        )
        .await
        .expect("timed out waiting for the tier change")
        .expect("the tier-change channel closed unexpectedly");
        match event {
            NatTierChange::TierChanged {
                previous_relay_url,
                new_relay_url,
                ..
            } => {
                assert_eq!(previous_relay_url, previous);
                assert_eq!(new_relay_url, new);
            }
            other => panic!("expected TierChanged, got {other:?}"),
        }
    }

    /// Criterion 7 at the node's listener: a tier change to a bridge entry
    /// reserves the entry's tier 3 ID, and a later change to a direct entry
    /// moves the reservation to that entry's `"scp-push-registration"` ID
    /// while the tier 3 ID stays refused.
    #[tokio::test]
    async fn tier_change_to_a_bridge_entry_intercepts_its_tier3_id_at_the_node_listener() {
        let (mut config, net_change_tx) = tier_change_config(DhtMode::Disabled);
        config.nat = NatSlot::Custom(Arc::new(SequenceNatStrategy::new(vec![
            ReachabilityTier::Stun {
                external_addr: SocketAddr::from(([198, 51, 100, 7], 32891)),
            },
            ReachabilityTier::Bridge {
                bridge_url: scp_did::BridgeEndpoint::new(SLOT_BRIDGE_URL).unwrap(),
            },
            ReachabilityTier::Upnp {
                external_addr: SocketAddr::from(([203, 0, 113, 42], 8443)),
            },
        ])));
        let mut node = Node::start_for_testing(config)
            .await
            .expect("the no-domain node starts");
        let entry = node_tier3_entry(&node, SLOT_BRIDGE_URL);

        await_tier_change(
            &mut node,
            &net_change_tx,
            TIER_CHANGE_OLD_URL,
            SLOT_BRIDGE_URL,
        )
        .await;
        assert_tier3_id_intercepted(&node, &entry, "after the change to the bridge entry").await;

        await_tier_change(
            &mut node,
            &net_change_tx,
            SLOT_BRIDGE_URL,
            TIER_CHANGE_NEW_URL,
        )
        .await;
        assert_eq!(
            node.state.relay_config.relay_url.current(),
            scp_transport::relay::push_gate::ReservedRelayUrls::from(
                RelayUrl::new(TIER_CHANGE_NEW_URL).unwrap()
            )
        );
        assert_push_not_supported(
            &publish_at(&node, registration_id(TIER_CHANGE_NEW_URL)).await,
            "the direct entry after the change back",
        );
        let tier3 = RelayUrl::from(&entry).push_routing_id();
        assert_push_not_supported(
            &publish_at(&node, tier3).await,
            "the released tier 3 ID after the change back",
        );
        assert_eq!(query_blob_count(&node, tier3).await, 0);
        node.shutdown();
    }

    /// A node relay given two tier 3 entries with different bridge URLs and
    /// the same target, its own and one its document carries, intercepts both
    /// tier 3 IDs; a later reservation from a document without the second
    /// entry releases it, and the relay keeps refusing its ID.
    #[tokio::test]
    async fn node_relay_reserving_two_bridge_entries_intercepts_both_and_one_entry_releases_the_other()
     {
        let (config, _net_change_tx) = tier_change_config(DhtMode::Disabled);
        let node = Node::start_for_testing(config)
            .await
            .expect("the no-domain node starts");
        let a = node_tier3_entry(&node, SLOT_BRIDGE_URL);
        let b = node_tier3_entry(&node, "wss://bridge-two.example.net/scp/v1");
        let relay = &node.state.relay_config.relay_url;
        let target = node_bridge_target(node.identity().did()).expect("not the absent value");
        let single = node.identity().document();
        let mut both = single.clone();
        both.add_relay_service(&b);
        // A publisher bound to the node relay's own handle, as the builders
        // bind theirs; its scripted publish publishes nothing.
        let publisher = NodePublisher::from_dyn(
            Arc::new(ScriptedPublisher::new(false)) as Arc<dyn DidPublisher>,
            relay.clone(),
        );
        let identity = slot_test_identity();

        seed_from_startup_publish(
            &publisher,
            &identity,
            &published_state::PublishedEntries::new(&a, &both, target),
        )
        .await
        .expect("the scripted publish succeeds");
        for (label, entry) in [("entry A", &a), ("entry B", &b)] {
            assert_tier3_id_intercepted(&node, entry, label).await;
        }

        seed_from_startup_publish(
            &publisher,
            &identity,
            &published_state::PublishedEntries::new(&a, &single, target),
        )
        .await
        .expect("the scripted publish succeeds");
        assert_eq!(
            relay.current(),
            scp_transport::relay::push_gate::ReservedRelayUrls::from(RelayUrl::from(&a))
        );
        let released = RelayUrl::from(&b).push_routing_id();
        assert_push_not_supported(&publish_at(&node, released).await, "released entry B");
        assert_eq!(query_blob_count(&node, released).await, 0);
        node.shutdown();
    }

    /// A no-domain node's relay reserves the push routing ID of the URL the node
    /// advertises at startup, so a PUBLISH there never becomes a stored blob.
    #[tokio::test]
    async fn no_domain_relay_reserves_the_push_routing_id_of_its_advertised_url() {
        let (config, _net_change_tx) = tier_change_config(DhtMode::Disabled);
        let node = Node::start_for_testing(config)
            .await
            .expect("the no-domain node starts");
        assert_eq!(node.relay_url(), TIER_CHANGE_OLD_URL);
        let reply = publish_to_reserved_push_id(&node, TIER_CHANGE_OLD_URL).await;
        assert_push_not_supported(&reply, "at startup");
        node.shutdown();
    }

    /// After a NAT tier change the relay's reserved push routing ID follows the
    /// new advertised URL, which is the URL a client now dials and derives the
    /// routing ID from. A PUBLISH to the previous URL's reserved routing ID is
    /// still refused and never stored.
    #[tokio::test]
    async fn tier_change_moves_the_relay_push_gate_to_the_new_url() {
        let (config, net_change_tx) = tier_change_config(DhtMode::Disabled);
        let mut node = Node::start_for_testing(config)
            .await
            .expect("the no-domain node starts");
        drive_tier_change(&mut node, &net_change_tx).await;
        assert_eq!(node.relay_url(), TIER_CHANGE_NEW_URL);

        let reply = publish_to_reserved_push_id(&node, TIER_CHANGE_NEW_URL).await;
        assert_push_not_supported(&reply, "the new URL after the tier change");
        let reply = publish_to_reserved_push_id(&node, TIER_CHANGE_OLD_URL).await;
        assert_push_not_supported(&reply, "the previous URL after the tier change");
        node.shutdown();
    }

    /// The `DhtMode::Disabled` case: the node publishes NOTHING — its record is
    /// `None` before and after — and every surface must STILL advance, because
    /// its reachability genuinely changed.
    ///
    /// This is why the state is its own slot rather than a projection of the
    /// published record: keying it off the record would leave a
    /// not-discoverable-by-design node advertising the build-time endpoint
    /// forever, or force a synthesized record to paper over it.
    #[tokio::test]
    async fn tier_change_advances_every_surface_on_a_node_that_publishes_nothing() {
        let (config, net_change_tx) = tier_change_config(DhtMode::Disabled);
        let mut node = Node::start_for_testing(config)
            .await
            .expect("a DhtMode::Disabled node starts without publishing");
        node.register_broadcast_context(WELL_KNOWN_TEST_CONTEXT.to_owned(), None)
            .await
            .expect("a broadcast context registers");

        assert!(
            node.published_did_record().is_none(),
            "DhtMode::Disabled publishes nothing — the honest absent state"
        );
        assert_all_surfaces_advertise(&node, TIER_CHANGE_OLD_URL, "at startup").await;

        drive_tier_change(&mut node, &net_change_tx).await;

        assert!(
            node.published_did_record().is_none(),
            "the tier change must not make a non-publishing node publish"
        );
        assert_all_surfaces_advertise(
            &node,
            TIER_CHANGE_NEW_URL,
            "after a tier change that published nothing",
        )
        .await;

        node.shutdown();
    }

    // -----------------------------------------------------------------------
    // `apply_tier_change` unit tests over the slot directly: the two gates, and
    // the document rewrite's unconditional postcondition.
    // -----------------------------------------------------------------------

    /// A `DidPublisher` that records what it was handed and can be made to fail.
    ///
    /// Built with [`ScriptedPublisher::observing`], it also records the value
    /// of a relay handle at each `initialize_sequence` call, so a test can see
    /// whether the reservation moved the handle before the sequence bootstrap,
    /// and can make that bootstrap fail.
    struct ScriptedPublisher {
        fail: bool,
        seen: std::sync::Mutex<Vec<DidDocument>>,
        observed: Option<LiveRelayUrl>,
        fail_initialize: bool,
        relay_at_initialize:
            std::sync::Mutex<Vec<scp_transport::relay::push_gate::ReservedRelayUrls>>,
    }

    impl ScriptedPublisher {
        fn new(fail: bool) -> Self {
            Self {
                fail,
                seen: std::sync::Mutex::new(Vec::new()),
                observed: None,
                fail_initialize: false,
                relay_at_initialize: std::sync::Mutex::new(Vec::new()),
            }
        }

        fn observing(relay: LiveRelayUrl, fail_initialize: bool) -> Self {
            Self {
                observed: Some(relay),
                fail_initialize,
                ..Self::new(false)
            }
        }
    }

    impl DidPublisher for ScriptedPublisher {
        fn publish<'a>(
            &'a self,
            _auth: PublishAuthorization,
            _identity: &'a ScpIdentity,
            document: &'a DidDocument,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<
                        Output = Result<Option<scp_identity::republish::RepublishEntry>, NodeError>,
                    > + Send
                    + 'a,
            >,
        > {
            self.seen
                .lock()
                .expect("scripted publisher lock")
                .push(document.clone());
            let fail = self.fail;
            Box::pin(async move {
                if fail {
                    Err(NodeError::Identity(IdentityError::DhtPublishFailed(
                        "scripted failure".to_owned(),
                    )))
                } else {
                    Ok(None)
                }
            })
        }

        fn initialize_sequence<'a>(
            &'a self,
            _identity: &'a ScpIdentity,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), NodeError>> + Send + 'a>>
        {
            if let Some(relay) = &self.observed {
                self.relay_at_initialize
                    .lock()
                    .expect("scripted publisher lock")
                    .push(relay.current());
            }
            let fail = self.fail_initialize;
            Box::pin(async move {
                if fail {
                    Err(NodeError::Identity(IdentityError::DhtPublishFailed(
                        "scripted sequence bootstrap failure".to_owned(),
                    )))
                } else {
                    Ok(())
                }
            })
        }
    }

    fn slot_test_identity() -> ScpIdentity {
        ScpIdentity {
            identity_key: scp_platform::KeyHandle::new(1),
            active_signing_key: scp_platform::KeyHandle::new(2),
            agent_signing_key: None,
            pre_rotation_commitment: [0u8; 32],
            did: "did:dht:slottest".to_owned(),
        }
    }

    /// The `bridgeTarget` the slot-test node publishes in a tier 3 entry.
    fn slot_test_target() -> scp_did::BridgeTarget {
        node_bridge_target(&slot_test_identity().did).expect("not the absent value")
    }

    fn slot_test_document(relay_endpoints: &[&str]) -> DidDocument {
        DidDocument {
            context: vec!["https://www.w3.org/ns/did/v1".to_owned()],
            id: "did:dht:slottest".to_owned(),
            verification_method: vec![],
            authentication: vec![],
            assertion_method: vec![],
            also_known_as: vec![],
            service: relay_endpoints
                .iter()
                .enumerate()
                .map(|(i, endpoint)| scp_did::Service {
                    id: format!("did:dht:slottest#scp-relay-{}", i + 1),
                    service_type: "SCPRelay".to_owned(),
                    service_endpoint: (*endpoint).to_owned(),
                    bridge_target: None,
                })
                .collect(),
        }
    }

    /// The node's own entry lands FIRST even when the caller's document already
    /// names a relay — the position premise `set_preferred_relay` keys on.
    ///
    /// `IdentitySource::Explicit` hands a caller-supplied document through
    /// verbatim. While the node's installer appended, the node's own entry landed
    /// at position 1 behind the caller's, so `document_relay_service` (position 0)
    /// reported the CALLER's relay while the slot reported the node's. The first
    /// tier tick then saw them disagree, ran a tier change that had not happened,
    /// rewrote the caller's preferred relay, and stranded the node's own entry at
    /// position 1 naming a URL nothing would ever re-point again.
    #[test]
    fn the_nodes_own_relay_entry_is_installed_at_the_preferred_position() {
        const CALLER_RELAY: &str = "wss://caller.example.com/scp/v1";
        let mut document = slot_test_document(&[CALLER_RELAY]);

        document.insert_preferred_relay(&crate::published_state::test_relay(TIER_CHANGE_NEW_URL));

        assert_eq!(
            document.relay_service_urls(),
            vec![TIER_CHANGE_NEW_URL.to_owned(), CALLER_RELAY.to_owned()],
            "the node's own relay is the subject's preferred relay (§18.2.3) and \
             must be first; the caller's additional relay keeps its order after it"
        );
        assert_eq!(
            published_state::document_relay_service(&document)
                .as_ref()
                .map(scp_did::RelayService::url),
            Some(TIER_CHANGE_NEW_URL),
            "so the tier loop's skip condition compares against the node's own \
             endpoint rather than the caller's"
        );
        // The caller's service id is untouched. A DID service `id` is a
        // resolvable URI a third party may already reference, so the node names
        // only the entry it owns rather than renumbering the whole set.
        let ids: Vec<&str> = document
            .service
            .iter()
            .filter(|s| s.service_type == "SCPRelay")
            .map(|s| s.id.as_str())
            .collect();
        assert_eq!(
            ids,
            vec![
                "did:dht:slottest#scp-relay-2",
                "did:dht:slottest#scp-relay-1"
            ],
            "the node takes the next free index and leaves the caller's id alone"
        );
        assert_eq!(
            ids.iter().collect::<std::collections::HashSet<_>>().len(),
            ids.len(),
            "service ids must stay unique within the document"
        );
    }

    /// A document with NO `SCPRelay` entry still ends up naming the address the
    /// node advertises. The predecessor rewrote only entries matching the current
    /// URL while the address advanced regardless, so a document with no match
    /// diverged from the advertised address permanently.
    #[tokio::test]
    async fn tier_change_appends_a_relay_service_when_the_document_carries_none() {
        let live_state = LiveSlot::new(NodePublishedState {
            document: slot_test_document(&[]),
            relay: crate::published_state::test_relay(TIER_CHANGE_OLD_URL),
            record: None,
        });
        let publisher = Arc::new(ScriptedPublisher::new(false));

        apply_tier_change(
            &live_state,
            &crate::published_state::test_relay(TIER_CHANGE_NEW_URL),
            slot_test_target(),
            &NodePublisher::from_dyn(
                Arc::clone(&publisher) as Arc<dyn DidPublisher>,
                LiveRelayUrl::new(RelayUrl::new(TIER_CHANGE_OLD_URL).unwrap()),
            ),
            &slot_test_identity(),
            crate::published_state::TierChangeReport {
                reason: "test",

                events: None,
            },
        )
        .await;

        let state = live_state.get();
        assert_eq!(state.relay.url(), TIER_CHANGE_NEW_URL);
        assert_eq!(
            state.document.relay_service_urls(),
            vec![TIER_CHANGE_NEW_URL.to_owned()],
            "no matching entry to re-point → the document gains one, rather than \
             silently disagreeing with the address the node advertises"
        );
        assert_eq!(
            publisher.seen.lock().expect("lock")[0].relay_service_urls(),
            vec![TIER_CHANGE_NEW_URL.to_owned()],
            "and the document that was PUBLISHED already carried it"
        );
    }

    /// A tier change re-points only the preferred (first) `SCPRelay` entry
    /// (§18.2.3) — the one this node's own reachability owns. Additional relays
    /// are other ways to reach the subject and a NAT tier change does not move
    /// them.
    #[tokio::test]
    async fn tier_change_repoints_only_the_preferred_relay_entry() {
        const OTHER_RELAY: &str = "wss://other.example.com/scp/v1";
        let live_state = LiveSlot::new(NodePublishedState {
            document: slot_test_document(&[TIER_CHANGE_OLD_URL, OTHER_RELAY]),
            relay: crate::published_state::test_relay(TIER_CHANGE_OLD_URL),
            record: None,
        });

        apply_tier_change(
            &live_state,
            &crate::published_state::test_relay(TIER_CHANGE_NEW_URL),
            slot_test_target(),
            &NodePublisher::from_dyn(
                Arc::new(ScriptedPublisher::new(false)) as Arc<dyn DidPublisher>,
                LiveRelayUrl::new(RelayUrl::new(TIER_CHANGE_OLD_URL).unwrap()),
            ),
            &slot_test_identity(),
            crate::published_state::TierChangeReport {
                reason: "test",

                events: None,
            },
        )
        .await;

        assert_eq!(
            live_state.get().document.relay_service_urls(),
            vec![TIER_CHANGE_NEW_URL.to_owned(), OTHER_RELAY.to_owned()],
        );
    }

    const SLOT_BRIDGE_URL: &str = "wss://bridge.example.com/scp/v1";

    /// The tier 3 entry the slot tests' identity publishes.
    fn slot_bridge_entry() -> scp_did::RelayService {
        scp_did::RelayService::bridge(
            scp_did::BridgeEndpoint::new(SLOT_BRIDGE_URL).expect("a wss bridge URL"),
            node_bridge_target(&slot_test_identity().did).expect("not the absent value"),
        )
    }

    /// A tier change to a bridge entry publishes its URL and `bridgeTarget`,
    /// and the relay reserves the entry's tier 3 push routing ID in place of
    /// the previous URL's ID (§10.7.1 "Tier 3 relays").
    #[tokio::test]
    async fn tier_change_to_a_bridge_entry_publishes_it_and_reserves_its_tier3_id() {
        let live_state = LiveSlot::new(NodePublishedState {
            document: slot_test_document(&[TIER_CHANGE_OLD_URL]),
            relay: crate::published_state::test_relay(TIER_CHANGE_OLD_URL),
            record: None,
        });
        let old = RelayUrl::new(TIER_CHANGE_OLD_URL).expect("canonical test URL");
        let relay = LiveRelayUrl::new(old.clone());
        let publisher = Arc::new(ScriptedPublisher::new(false));
        let bridge = slot_bridge_entry();

        apply_tier_change(
            &live_state,
            &bridge,
            slot_test_target(),
            &NodePublisher::from_dyn(
                Arc::clone(&publisher) as Arc<dyn DidPublisher>,
                relay.clone(),
            ),
            &slot_test_identity(),
            crate::published_state::TierChangeReport {
                reason: "test",

                events: None,
            },
        )
        .await;

        let state = live_state.get();
        assert_eq!(state.relay, bridge);
        assert_eq!(state.document.relay_services(), vec![bridge.clone()]);
        assert_eq!(
            publisher.seen.lock().expect("lock")[0].relay_services(),
            vec![bridge.clone()],
            "the published document carries the bridge URL and bridgeTarget"
        );
        assert_eq!(
            relay.current(),
            scp_transport::relay::push_gate::ReservedRelayUrls::from(RelayUrl::from(&bridge)),
            "the relay reserves the entry's tier 3 ID"
        );
        assert_ne!(
            RelayUrl::from(&bridge).push_routing_id(),
            registration_id(SLOT_BRIDGE_URL),
            "never the bridge relay's own ID"
        );
        assert!(matches!(
            scp_transport::relay::push_gate::gate_publish(
                &relay,
                &scp_transport::relay::push_gate::PushRole::Disabled,
                &old.push_routing_id(),
                &[1],
                0,
            )
            .await,
            scp_transport::relay::push_gate::PushPublishGate::Rejected { code: 4063, .. }
        ));
    }

    /// Criterion 6: the reservation `seed_from_startup_publish` makes on the
    /// publisher's own handle maps every entry to its own routing ID, the
    /// tier 3 form for a bridge entry, and a later set of fewer entries
    /// releases the rest into the refused previous IDs.
    #[tokio::test]
    async fn reserve_push_routing_id_reserves_the_tier3_id_of_every_entry() {
        use crate::published_state::PublishedEntries;
        use scp_transport::relay::push_gate::{
            PushPublishGate, PushRole, ReservedRelayUrls, gate_publish,
        };
        async fn gate(relay: &LiveRelayUrl, id: [u8; 32]) -> PushPublishGate {
            gate_publish(relay, &PushRole::Disabled, &id, &[1], 0).await
        }
        let old = RelayUrl::new(TIER_CHANGE_OLD_URL).unwrap();
        let relay = LiveRelayUrl::new(old.clone());
        let scripted = Arc::new(ScriptedPublisher::new(false));
        let publisher = NodePublisher::from_dyn(
            Arc::clone(&scripted) as Arc<dyn DidPublisher>,
            relay.clone(),
        );
        let seed = |entries: PublishedEntries| {
            let publisher = publisher.clone();
            async move {
                seed_from_startup_publish(&publisher, &slot_test_identity(), &entries)
                    .await
                    .expect("the scripted publish succeeds");
            }
        };
        let target = slot_test_target();
        let entry = |url: &str| {
            scp_did::RelayService::bridge(scp_did::BridgeEndpoint::new(url).unwrap(), target)
        };
        let a = entry(SLOT_BRIDGE_URL);
        let b = entry("wss://bridge-two.example.net/scp/v1");
        // An entry for another target, which this node's relay never reserves.
        let foreign = scp_did::RelayService::bridge(
            scp_did::BridgeEndpoint::new("wss://bridge-three.example.org/scp/v1").unwrap(),
            scp_did::BridgeTarget::new([0x5a; 32]).unwrap(),
        );
        let mut document = slot_test_document(&[TIER_CHANGE_OLD_URL]);
        document.add_relay_service(&b);
        document.add_relay_service(&foreign);
        document.insert_preferred_relay(&a);

        seed(PublishedEntries::new(&a, &document, target)).await;
        assert_eq!(
            scripted.seen.lock().expect("lock").as_slice(),
            std::slice::from_ref(&document),
            "the document whose entries were reserved is the one published"
        );
        let current = relay.current();
        assert_eq!(
            current,
            ReservedRelayUrls::new(RelayUrl::from(&a), [RelayUrl::from(&b)]),
            "the own entry and the document's entry with this node's target, \
             never the direct entry or another target's entry"
        );
        for (held, entry) in current.as_slice().iter().zip([&a, &b]) {
            assert_eq!(
                held.canonical(),
                RelayUrl::new(entry.url()).unwrap().canonical()
            );
            assert_eq!(held.bridge_target(), Some(target));
            assert_ne!(held.push_routing_id(), registration_id(entry.url()));
            assert!(
                !matches!(
                    gate(&relay, held.push_routing_id()).await,
                    PushPublishGate::NotPush
                ),
                "{} is reserved",
                entry.url()
            );
        }
        assert!(matches!(
            gate(&relay, old.push_routing_id()).await,
            PushPublishGate::Rejected { code: 4063, .. }
        ));
        for url in [SLOT_BRIDGE_URL, "wss://bridge-two.example.net/scp/v1"] {
            assert_eq!(
                gate(&relay, registration_id(url)).await,
                PushPublishGate::NotPush,
                "the bridge relay's own ID is not this relay's"
            );
        }

        let only_own = slot_test_document(&[]);
        seed(PublishedEntries::new(&a, &only_own, target)).await;
        assert_eq!(relay.current(), ReservedRelayUrls::from(RelayUrl::from(&a)));
        assert!(matches!(
            gate(&relay, RelayUrl::from(&b).push_routing_id()).await,
            PushPublishGate::Rejected { code: 4063, .. }
        ));

        let direct = crate::published_state::test_relay(TIER_CHANGE_NEW_URL);
        seed(PublishedEntries::new(&direct, &only_own, target)).await;
        assert_eq!(
            relay.current(),
            ReservedRelayUrls::from(RelayUrl::new(TIER_CHANGE_NEW_URL).unwrap())
        );
    }

    /// A node's startup publish and its later tier change reserve on the one
    /// handle its publisher is bound to: the tier change moves the handle the
    /// startup publish moved, and the ID the startup reserved is then refused
    /// on that same handle.
    #[tokio::test]
    async fn startup_and_tier_change_reserve_on_the_one_publisher_handle() {
        use crate::published_state::PublishedEntries;
        use scp_transport::relay::push_gate::{
            PushPublishGate, PushRole, ReservedRelayUrls, gate_publish,
        };
        // The handle starts at an URL the node never advertises, so a
        // reservation that missed it would leave this value in place.
        let unrelated = RelayUrl::new("ws://203.0.113.9:4000/scp/v1").unwrap();
        let relay = LiveRelayUrl::new(unrelated);
        let publisher = NodePublisher::from_dyn(
            Arc::new(ScriptedPublisher::new(false)) as Arc<dyn DidPublisher>,
            relay.clone(),
        );
        let old = crate::published_state::test_relay(TIER_CHANGE_OLD_URL);
        let document = slot_test_document(&[TIER_CHANGE_OLD_URL]);

        let live_state = seed_from_startup_publish(
            &publisher,
            &slot_test_identity(),
            &PublishedEntries::new(&old, &document, slot_test_target()),
        )
        .await
        .expect("the scripted publish succeeds");
        assert_eq!(
            relay.current(),
            ReservedRelayUrls::from(RelayUrl::from(&old)),
            "the startup publish reserves on the publisher's handle"
        );

        let bridge = slot_bridge_entry();
        apply_tier_change(
            &live_state,
            &bridge,
            slot_test_target(),
            &publisher,
            &slot_test_identity(),
            crate::published_state::TierChangeReport {
                reason: "test",
                events: None,
            },
        )
        .await;
        assert_eq!(
            relay.current(),
            ReservedRelayUrls::from(RelayUrl::from(&bridge)),
            "the tier change reserves on the same handle"
        );
        assert!(matches!(
            gate_publish(
                &relay,
                &PushRole::Disabled,
                &RelayUrl::from(&old).push_routing_id(),
                &[1],
                0,
            )
            .await,
            PushPublishGate::Rejected { code: 4063, .. }
        ));
    }

    /// The startup publish reserves the entries on the publisher's handle
    /// before it bootstraps the publish-sequence counter: the handle already
    /// holds the published entry when `initialize_sequence` runs.
    #[tokio::test]
    async fn startup_publish_reserves_before_it_initializes_the_sequence() {
        use crate::published_state::PublishedEntries;
        use scp_transport::relay::push_gate::ReservedRelayUrls;
        let unrelated = RelayUrl::new("ws://203.0.113.9:4000/scp/v1").unwrap();
        let relay = LiveRelayUrl::new(unrelated.clone());
        let scripted = Arc::new(ScriptedPublisher::observing(relay.clone(), false));
        let publisher = NodePublisher::from_dyn(
            Arc::clone(&scripted) as Arc<dyn DidPublisher>,
            relay.clone(),
        );
        let old = crate::published_state::test_relay(TIER_CHANGE_OLD_URL);
        let document = slot_test_document(&[TIER_CHANGE_OLD_URL]);

        seed_from_startup_publish(
            &publisher,
            &slot_test_identity(),
            &PublishedEntries::new(&old, &document, slot_test_target()),
        )
        .await
        .expect("the scripted publish succeeds");

        let at_initialize = scripted
            .relay_at_initialize
            .lock()
            .expect("scripted publisher lock")
            .clone();
        assert_eq!(
            at_initialize,
            vec![ReservedRelayUrls::from(RelayUrl::from(&old))],
            "the sequence bootstrap runs once, after the reservation moved the handle \
             off {unrelated:?}"
        );
        assert_eq!(
            scripted.seen.lock().expect("scripted publisher lock").len(),
            1,
            "the startup publish publishes once"
        );
    }

    /// A failed sequence bootstrap stops the startup publish with the typed
    /// error, and nothing is published.
    #[tokio::test]
    async fn failed_sequence_bootstrap_stops_the_startup_publish() {
        use crate::published_state::PublishedEntries;
        let relay = LiveRelayUrl::new(RelayUrl::new("ws://203.0.113.9:4000/scp/v1").unwrap());
        let scripted = Arc::new(ScriptedPublisher::observing(relay.clone(), true));
        let publisher =
            NodePublisher::from_dyn(Arc::clone(&scripted) as Arc<dyn DidPublisher>, relay);
        let old = crate::published_state::test_relay(TIER_CHANGE_OLD_URL);
        let document = slot_test_document(&[TIER_CHANGE_OLD_URL]);

        let result = seed_from_startup_publish(
            &publisher,
            &slot_test_identity(),
            &PublishedEntries::new(&old, &document, slot_test_target()),
        )
        .await;

        assert!(
            matches!(
                result,
                Err(NodeError::Identity(IdentityError::DhtPublishFailed(ref msg)))
                    if msg == "scripted sequence bootstrap failure"
            ),
            "the bootstrap's typed error reaches the caller"
        );
        assert!(
            scripted
                .seen
                .lock()
                .expect("scripted publisher lock")
                .is_empty(),
            "nothing is published after a failed sequence bootstrap"
        );
    }

    /// Moving from tier 3 back to a direct tier clears `bridgeTarget`: the
    /// entry is re-pointed as a whole, never left naming a bridge the node no
    /// longer uses.
    #[tokio::test]
    async fn tier_change_from_bridge_to_stun_clears_bridge_target() {
        let mut document = slot_test_document(&[]);
        document.insert_preferred_relay(&slot_bridge_entry());
        let live_state = LiveSlot::new(NodePublishedState {
            document,
            relay: slot_bridge_entry(),
            record: None,
        });
        let relay = LiveRelayUrl::new(RelayUrl::from(&slot_bridge_entry()));
        let tier3 = RelayUrl::from(&slot_bridge_entry()).push_routing_id();
        let stun = crate::published_state::test_relay(TIER_CHANGE_NEW_URL);

        apply_tier_change(
            &live_state,
            &stun,
            slot_test_target(),
            &NodePublisher::from_dyn(
                Arc::new(ScriptedPublisher::new(false)) as Arc<dyn DidPublisher>,
                relay.clone(),
            ),
            &slot_test_identity(),
            crate::published_state::TierChangeReport {
                reason: "test",

                events: None,
            },
        )
        .await;

        let state = live_state.get();
        assert_eq!(state.relay, stun);
        assert_eq!(state.document.relay_services(), vec![stun]);
        let raw: Vec<_> = state
            .document
            .service
            .iter()
            .filter(|s| s.service_type == "SCPRelay")
            .collect();
        assert_eq!(raw.len(), 1, "the entry is re-pointed, not duplicated");
        assert_eq!(raw[0].bridge_target, None, "the bridgeTarget is cleared");
        assert_eq!(
            relay.current(),
            scp_transport::relay::push_gate::ReservedRelayUrls::from(
                RelayUrl::new(TIER_CHANGE_NEW_URL).unwrap()
            ),
            "a direct tier's URL is this node's, so the relay reserves it"
        );
        assert!(
            matches!(
                scp_transport::relay::push_gate::gate_publish(
                    &relay,
                    &scp_transport::relay::push_gate::PushRole::Disabled,
                    &tier3,
                    &[1],
                    0,
                )
                .await,
                scp_transport::relay::push_gate::PushPublishGate::Rejected { code: 4063, .. }
            ),
            "the released tier 3 ID stays refused"
        );
    }

    /// The re-evaluation loop treats an identical bridge entry as no change: a
    /// node already publishing its tier 3 entry does not re-publish on every
    /// tick. The entry compared includes `bridgeTarget`, so the loop must build
    /// the same target the document carries.
    #[tokio::test]
    async fn tier_reevaluation_sees_no_change_for_an_identical_bridge_entry() {
        let strategy = Arc::new(SequenceNatStrategy::new(vec![ReachabilityTier::Bridge {
            bridge_url: scp_did::BridgeEndpoint::new(SLOT_BRIDGE_URL).unwrap(),
        }]));
        let publisher = Arc::new(RecordingPublisher::new());
        let mut document = slot_test_document(&[]);
        document.insert_preferred_relay(&slot_bridge_entry());

        let handle = spawn_tier_reevaluation(
            Arc::clone(&strategy) as Arc<dyn NatStrategy>,
            None,
            NodePublisher::from_dyn(
                Arc::clone(&publisher) as Arc<dyn DidPublisher>,
                LiveRelayUrl::new(RelayUrl::new(TIER_CHANGE_OLD_URL).unwrap()),
            ),
            node_bridge_target(&slot_test_identity().did).unwrap(),
            slot_test_identity(),
            LiveSlot::new(NodePublishedState {
                document,
                relay: slot_bridge_entry(),
                record: None,
            }),
            32891,
            None,
            TEST_REEVALUATION_INTERVAL,
        );

        let deadline = tokio::time::Instant::now() + TEST_EVENT_TIMEOUT;
        while strategy
            .call_count
            .load(std::sync::atomic::Ordering::SeqCst)
            < 3
        {
            assert!(
                tokio::time::Instant::now() < deadline,
                "the re-evaluation loop did not tick three times"
            );
            tokio::time::sleep(TEST_REEVALUATION_INTERVAL).await;
        }
        handle.stop();

        assert_eq!(
            publisher.count(),
            0,
            "an identical bridge entry is no tier change and publishes nothing"
        );
    }

    /// The persisted identity's named `MessagePack` encoding keeps a bridge
    /// entry's `bridgeTarget`, so a restarted node reloads the entry it
    /// published.
    #[test]
    fn persisted_identity_round_trips_a_bridge_entry() {
        let mut document = slot_test_document(&[TIER_CHANGE_OLD_URL]);
        document.insert_preferred_relay(&slot_bridge_entry());
        let persisted = PersistedIdentity {
            identity: slot_test_identity(),
            document,
        };

        let bytes = scp_platform::store_value::to_stored_value_bytes(&persisted)
            .expect("persisted identity encodes");
        let decoded: PersistedIdentity = scp_platform::store_value::from_stored_value_bytes(&bytes)
            .expect("persisted identity decodes");

        assert_eq!(decoded.document, persisted.document);
        assert_eq!(
            decoded.document.relay_services(),
            vec![
                slot_bridge_entry(),
                crate::published_state::test_relay(TIER_CHANGE_OLD_URL)
            ],
        );
    }

    /// A FAILED re-publish still advances the address the node reports — the
    /// external address has already moved, so the old one is dead either way and
    /// `.well-known/scp` must not keep handing it to peers — while leaving the
    /// document at what was actually published. The next re-evaluation therefore
    /// still owes a re-publish, which the tier loop detects by comparing the
    /// DOCUMENT's endpoint rather than the address.
    #[tokio::test]
    async fn a_failed_republish_advances_the_address_but_not_the_document() {
        let live_state = LiveSlot::new(NodePublishedState {
            document: slot_test_document(&[TIER_CHANGE_OLD_URL]),
            relay: crate::published_state::test_relay(TIER_CHANGE_OLD_URL),
            record: None,
        });
        let (event_tx, mut event_rx) = tokio::sync::mpsc::channel(4);

        apply_tier_change(
            &live_state,
            &crate::published_state::test_relay(TIER_CHANGE_NEW_URL),
            slot_test_target(),
            &NodePublisher::from_dyn(
                Arc::new(ScriptedPublisher::new(true)) as Arc<dyn DidPublisher>,
                LiveRelayUrl::new(RelayUrl::new(TIER_CHANGE_OLD_URL).unwrap()),
            ),
            &slot_test_identity(),
            crate::published_state::TierChangeReport {
                reason: "test",

                events: Some(&event_tx),
            },
        )
        .await;

        let state = live_state.get();
        assert_eq!(
            state.relay.url(),
            TIER_CHANGE_NEW_URL,
            "the node reports where it actually is"
        );
        assert_eq!(
            state.document.relay_service_urls(),
            vec![TIER_CHANGE_OLD_URL.to_owned()],
            "the document is published state: it may only name what was published"
        );
        assert!(
            matches!(event_rx.try_recv(), Ok(NatTierChange::TierChanged { .. })),
            "the reachability change is real, so the event fires even though the \
             re-publish did not land"
        );

        // A re-publish is still OWED: the loop's skip condition must see it.
        assert_ne!(
            published_state::document_relay_service(&state.document)
                .as_ref()
                .map(scp_did::RelayService::url),
            Some(TIER_CHANGE_NEW_URL),
        );

        // The retry succeeds and converges both, and does NOT re-announce an
        // address that did not move.
        apply_tier_change(
            &live_state,
            &crate::published_state::test_relay(TIER_CHANGE_NEW_URL),
            slot_test_target(),
            &NodePublisher::from_dyn(
                Arc::new(ScriptedPublisher::new(false)) as Arc<dyn DidPublisher>,
                LiveRelayUrl::new(RelayUrl::new(TIER_CHANGE_OLD_URL).unwrap()),
            ),
            &slot_test_identity(),
            crate::published_state::TierChangeReport {
                reason: "retry",
                events: Some(&event_tx),
            },
        )
        .await;
        let state = live_state.get();
        assert_eq!(state.relay.url(), TIER_CHANGE_NEW_URL);
        assert_eq!(
            state.document.relay_service_urls(),
            vec![TIER_CHANGE_NEW_URL.to_owned()],
            "the retry re-points the SAME entry rather than appending a duplicate"
        );
        assert!(
            event_rx.try_recv().is_err(),
            "the address did not move on the retry, so no second TierChanged"
        );
    }

    // -----------------------------------------------------------------------
    // identity_with_storage tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn identity_with_storage_creates_and_persists_on_first_run() {
        // First build: no identity in storage → creates new DID and persists it.
        let storage = Arc::new(InMemoryStorage::new());
        let custody = Arc::new(InMemoryKeyCustody::new());
        let did_method = Arc::new(make_test_dht(&custody));

        let node = Node::start_for_testing(NodeConfig {
            bind_addr: Some(SocketAddr::from(([127, 0, 0, 1], 0))),
            dht: DhtMode::Production,
            tls: TlsMode::Custom(Arc::new(SucceedingTlsProvider {
                domain: "persist.example.com".to_owned(),
            })),
            ..NodeConfig::defaults(
                Reach::Domain {
                    domain: "persist.example.com".to_owned(),
                },
                IdentitySource::Persisted {
                    custody,
                    did_method,
                },
                Arc::clone(&storage),
                BlobStorageBackend::in_memory(),
            )
        })
        .await
        .unwrap();

        let did = node.identity().did().to_owned();
        assert!(
            did.starts_with("did:dht:"),
            "DID should start with did:dht:"
        );

        // Verify the identity was persisted to storage.
        let stored = storage
            .retrieve(IDENTITY_STORAGE_KEY)
            .await
            .unwrap()
            .expect("identity should be persisted to storage");
        let envelope: StoredValue<PersistedIdentity> = rmp_serde::from_slice(&stored).unwrap();
        assert_eq!(envelope.version, CURRENT_STORE_VERSION);
        assert_eq!(envelope.data.identity.did, did);
        assert_eq!(envelope.data.document.id, did);

        node.shutdown();
    }

    #[tokio::test]
    async fn persisted_identity_with_tampered_did_is_rejected() {
        // The did:dht identifier is self-certifying: it is derived directly
        // from the `#0` identity key. A stored DID string that no longer
        // re-derives from the custody-held key indicates tampering or
        // corruption of the persisted record, and the load MUST be rejected
        // even though the custody key handles and document verification
        // methods are still internally consistent.

        // First run: create and persist a real identity.
        let storage = Arc::new(InMemoryStorage::new());
        let custody = Arc::new(InMemoryKeyCustody::new());
        let did_method = Arc::new(make_test_dht(&custody));

        let node1 = Node::start_for_testing(NodeConfig {
            bind_addr: Some(SocketAddr::from(([127, 0, 0, 1], 0))),
            dht: DhtMode::Production,
            tls: TlsMode::Custom(Arc::new(SucceedingTlsProvider {
                domain: "tampered-did.example.com".to_owned(),
            })),
            ..NodeConfig::defaults(
                Reach::Domain {
                    domain: "tampered-did.example.com".to_owned(),
                },
                IdentitySource::Persisted {
                    custody: Arc::clone(&custody),
                    did_method: Arc::clone(&did_method),
                },
                Arc::clone(&storage),
                BlobStorageBackend::in_memory(),
            )
        })
        .await
        .unwrap();

        let original_did = node1.identity().did().to_owned();
        node1.shutdown();

        // Tamper: rewrite ONLY the persisted DID string, leaving the custody
        // key handles and DID document verification methods untouched so that
        // `validate_persisted_custody`'s VM-match checks still pass and the
        // DID re-derivation check is the sole gate that can catch the
        // corruption.
        let stored = storage
            .retrieve(IDENTITY_STORAGE_KEY)
            .await
            .unwrap()
            .expect("identity should be persisted after first run");
        let mut envelope: StoredValue<PersistedIdentity> = rmp_serde::from_slice(&stored).unwrap();
        let tampered_did = "did:dht:zyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy".to_owned();
        assert_ne!(
            tampered_did, original_did,
            "tampered DID must differ from the genuine DID"
        );
        envelope.data.identity.did = tampered_did.clone();
        let tampered_bytes = rmp_serde::to_vec_named(&envelope).unwrap();
        storage
            .store(IDENTITY_STORAGE_KEY, &tampered_bytes)
            .await
            .unwrap();

        // Second run: same custody (so VMs still match) but the stored DID no
        // longer re-derives from the `#0` key → load MUST be rejected.
        let result = Node::start_for_testing(NodeConfig {
            bind_addr: Some(SocketAddr::from(([127, 0, 0, 1], 0))),
            dht: DhtMode::Production,
            tls: TlsMode::Custom(Arc::new(SucceedingTlsProvider {
                domain: "tampered-did.example.com".to_owned(),
            })),
            ..NodeConfig::defaults(
                Reach::Domain {
                    domain: "tampered-did.example.com".to_owned(),
                },
                IdentitySource::Persisted {
                    custody,
                    did_method,
                },
                Arc::clone(&storage),
                BlobStorageBackend::in_memory(),
            )
        })
        .await;

        match result {
            Err(err) => {
                let msg = err.to_string();
                assert!(
                    msg.contains("does not match DID re-derived from #0 identity key"),
                    "expected DID re-derivation mismatch error, got: {msg}"
                );
            }
            Ok(node) => {
                node.shutdown();
                panic!("expected tampered-DID rejection, but build succeeded");
            }
        }
    }

    /// Regression: persisted `ScpIdentity` blobs from interim builds
    /// (where `pre_rotation_key: KeyHandle` was briefly a field on the
    /// struct) MUST deserialize cleanly into the post-revert struct,
    /// since msgpack-named ignores unknown fields and the
    /// `PreRotationCustody` workstream replaced that field with a
    /// separate cold-storage substrate. Without this regression test,
    /// a future change adding `#[serde(deny_unknown_fields)]` would
    /// silently break upgrades from interim builds.
    #[tokio::test]
    async fn identity_with_storage_deserialises_blob_with_extra_pre_rotation_key_field() {
        use scp_platform::traits::KeyHandle;

        // Synthesize a `PersistedIdentity` shape that mirrors the
        // interim-build serialization: same fields plus an extra
        // `pre_rotation_key` slot.
        #[derive(serde::Serialize)]
        struct InterimIdentity {
            identity_key: KeyHandle,
            active_signing_key: KeyHandle,
            agent_signing_key: Option<KeyHandle>,
            pre_rotation_commitment: [u8; 32],
            // The extra field that should be silently ignored on read.
            pre_rotation_key: KeyHandle,
            did: String,
        }

        #[derive(serde::Serialize)]
        struct InterimPersistedIdentity {
            identity: InterimIdentity,
            document: DidDocument,
        }

        let interim = InterimPersistedIdentity {
            identity: InterimIdentity {
                identity_key: KeyHandle::new(1),
                active_signing_key: KeyHandle::new(2),
                agent_signing_key: None,
                pre_rotation_commitment: [7u8; 32],
                pre_rotation_key: KeyHandle::new(3),
                did: "did:dht:zinterim".to_owned(),
            },
            document: DidDocument {
                context: vec!["https://www.w3.org/ns/did/v1".to_owned()],
                id: "did:dht:zinterim".to_owned(),
                verification_method: vec![],
                authentication: vec![],
                assertion_method: vec![],
                also_known_as: vec![],
                service: vec![],
            },
        };

        let envelope = StoredValue {
            version: CURRENT_STORE_VERSION,
            data: &interim,
        };
        let bytes = rmp_serde::to_vec_named(&envelope).unwrap();

        // The post-revert struct (no `pre_rotation_key` field) MUST
        // deserialize successfully — the extra field is silently
        // dropped.
        let decoded: StoredValue<PersistedIdentity> = rmp_serde::from_slice(&bytes)
            .expect("interim-build blob with extra pre_rotation_key field MUST deserialize");
        assert_eq!(decoded.version, CURRENT_STORE_VERSION);
        assert_eq!(decoded.data.identity.did, "did:dht:zinterim");
        assert_eq!(decoded.data.identity.pre_rotation_commitment, [7u8; 32]);
    }

    #[tokio::test]
    async fn identity_with_storage_stored_value_envelope_roundtrip() {
        // Verify that a StoredValue<PersistedIdentity> envelope round-trips
        // through MessagePack serialization correctly.
        use scp_platform::traits::KeyHandle;
        let persisted = PersistedIdentity {
            identity: ScpIdentity {
                identity_key: KeyHandle::new(1),
                active_signing_key: KeyHandle::new(2),
                agent_signing_key: None,
                pre_rotation_commitment: [0u8; 32],
                did: "did:dht:zroundtrip".to_owned(),
            },
            document: DidDocument {
                context: vec!["https://www.w3.org/ns/did/v1".to_owned()],
                id: "did:dht:zroundtrip".to_owned(),
                verification_method: vec![],
                authentication: vec![],
                assertion_method: vec![],
                also_known_as: vec![],
                service: vec![],
            },
        };
        let envelope = StoredValue {
            version: CURRENT_STORE_VERSION,
            data: &persisted,
        };
        let bytes = rmp_serde::to_vec_named(&envelope).unwrap();
        let decoded: StoredValue<PersistedIdentity> = rmp_serde::from_slice(&bytes).unwrap();
        assert_eq!(decoded.version, CURRENT_STORE_VERSION);
        assert_eq!(decoded.data.identity.did, "did:dht:zroundtrip");
        assert_eq!(decoded.data.document.id, "did:dht:zroundtrip");
    }

    #[tokio::test]
    async fn identity_with_storage_rejects_future_version() {
        // §17.5: A StoredValue with version > CURRENT_STORE_VERSION must be
        // rejected with a clear error, preventing silent corruption from
        // downgraded binaries reading data written by newer code.
        use scp_platform::traits::KeyHandle;
        let persisted = PersistedIdentity {
            identity: ScpIdentity {
                identity_key: KeyHandle::new(1),
                active_signing_key: KeyHandle::new(2),
                agent_signing_key: None,
                pre_rotation_commitment: [0u8; 32],
                did: "did:dht:zfuture".to_owned(),
            },
            document: DidDocument {
                context: vec!["https://www.w3.org/ns/did/v1".to_owned()],
                id: "did:dht:zfuture".to_owned(),
                verification_method: vec![],
                authentication: vec![],
                assertion_method: vec![],
                also_known_as: vec![],
                service: vec![],
            },
        };
        let future_version = CURRENT_STORE_VERSION + 1;
        let envelope = StoredValue {
            version: future_version,
            data: &persisted,
        };
        let bytes = rmp_serde::to_vec_named(&envelope).unwrap();

        let storage = Arc::new(InMemoryStorage::new());
        storage.store(IDENTITY_STORAGE_KEY, &bytes).await.unwrap();

        let custody = Arc::new(InMemoryKeyCustody::new());
        let did_method = Arc::new(make_test_dht(&custody));

        let result = Node::start_for_testing(NodeConfig {
            bind_addr: Some(SocketAddr::from(([127, 0, 0, 1], 0))),
            dht: DhtMode::Production,
            tls: TlsMode::Custom(Arc::new(SucceedingTlsProvider {
                domain: "future-ver.example.com".to_owned(),
            })),
            ..NodeConfig::defaults(
                Reach::Domain {
                    domain: "future-ver.example.com".to_owned(),
                },
                IdentitySource::Persisted {
                    custody,
                    did_method,
                },
                Arc::clone(&storage),
                BlobStorageBackend::in_memory(),
            )
        })
        .await;

        match result {
            Err(err) => {
                let msg = err.to_string();
                assert!(
                    msg.contains("newer than supported version"),
                    "expected future version rejection error, got: {msg}"
                );
            }
            Ok(node) => {
                node.shutdown();
                panic!("expected future version rejection, but build succeeded");
            }
        }
    }

    #[tokio::test]
    async fn generate_identity_with_does_not_persist() {
        // Verify the original generate_identity_with does NOT persist (backward compat).
        let storage = Arc::new(InMemoryStorage::new());
        let custody = Arc::new(InMemoryKeyCustody::new());
        let did_method = Arc::new(make_test_dht(&custody));

        let node = Node::start_for_testing(NodeConfig {
            bind_addr: Some(SocketAddr::from(([127, 0, 0, 1], 0))),
            dht: DhtMode::Production,
            tls: TlsMode::Custom(Arc::new(SucceedingTlsProvider {
                domain: "nopersist.example.com".to_owned(),
            })),
            ..NodeConfig::defaults(
                Reach::Domain {
                    domain: "nopersist.example.com".to_owned(),
                },
                IdentitySource::Generate {
                    custody,
                    did_method,
                },
                Arc::clone(&storage),
                BlobStorageBackend::in_memory(),
            )
        })
        .await
        .unwrap();

        assert!(node.identity().did().starts_with("did:dht:"));

        // Storage should NOT contain a persisted identity.
        let stored = storage.retrieve(IDENTITY_STORAGE_KEY).await.unwrap();
        assert!(
            stored.is_none(),
            "generate_identity_with should NOT persist identity"
        );

        node.shutdown();
    }

    #[tokio::test]
    async fn identity_with_storage_no_domain_mode() {
        // Verify persistence works in no-domain mode too.
        let storage = Arc::new(InMemoryStorage::new());
        let custody = Arc::new(InMemoryKeyCustody::new());
        let did_method = Arc::new(make_test_dht(&custody));

        let tier = ReachabilityTier::Upnp {
            external_addr: SocketAddr::from(([1, 2, 3, 4], 9090)),
        };
        let node = Node::start_for_testing(NodeConfig {
            bind_addr: Some(SocketAddr::from(([127, 0, 0, 1], 0))),
            dht: DhtMode::Production,
            nat: NatSlot::Custom(Arc::new(MockNatStrategy { tier: tier.clone() })),
            ..NodeConfig::defaults(
                Reach::NatTraversal,
                IdentitySource::Persisted {
                    custody: Arc::clone(&custody),
                    did_method: Arc::clone(&did_method),
                },
                Arc::clone(&storage),
                BlobStorageBackend::in_memory(),
            )
        })
        .await
        .unwrap();

        let first_did = node.identity().did().to_owned();
        node.shutdown();

        // Second run: same storage → same DID.
        let node2 = Node::start_for_testing(NodeConfig {
            bind_addr: Some(SocketAddr::from(([127, 0, 0, 1], 0))),
            dht: DhtMode::Production,
            nat: NatSlot::Custom(Arc::new(MockNatStrategy { tier })),
            ..NodeConfig::defaults(
                Reach::NatTraversal,
                IdentitySource::Persisted {
                    custody,
                    did_method,
                },
                Arc::clone(&storage),
                BlobStorageBackend::in_memory(),
            )
        })
        .await
        .unwrap();

        assert_eq!(
            node2.identity().did(),
            first_did,
            "no-domain mode should also reload persisted identity"
        );

        node2.shutdown();
    }

    // -- NAT port-mapping lease renewal (spec §10.12.2) ----------------------

    mod mapping_renewal {
        use super::super::{
            MAPPING_RENEWAL_RETRY_BACKOFF, MIN_MAPPING_RENEWAL_INTERVAL, mapping_renewal_interval,
            run_mapping_renewal_loop,
        };
        use scp_transport::nat::{
            MappingProtocol, PortMapper, PortMappingError, PortMappingResult,
        };
        use std::future::Future;
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};
        use std::pin::Pin;
        use std::sync::Arc;
        use std::sync::atomic::{AtomicU32, Ordering};
        use std::time::Duration;
        use tokio_util::sync::CancellationToken;

        fn ext_addr() -> SocketAddr {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)), 8443)
        }

        /// A `PortMapper` for renewal tests. Counts `map_port` calls and returns
        /// a programmable sequence of results (cycling on the last entry), so a
        /// renewal loop can be driven across many cycles without exhausting it.
        struct CountingMapper {
            map_calls: AtomicU32,
            results: Vec<Result<PortMappingResult, PortMappingError>>,
        }

        impl CountingMapper {
            fn new(results: Vec<Result<PortMappingResult, PortMappingError>>) -> Self {
                Self {
                    map_calls: AtomicU32::new(0),
                    results,
                }
            }

            /// Always succeeds with the given TTL.
            fn always_ok(ttl: Duration) -> Self {
                Self::new(vec![Ok(PortMappingResult {
                    external_addr: ext_addr(),
                    ttl,
                    protocol: MappingProtocol::NatPmp,
                })])
            }

            fn calls(&self) -> u32 {
                self.map_calls.load(Ordering::SeqCst)
            }
        }

        impl PortMapper for CountingMapper {
            fn map_port(
                &self,
                _internal_port: u16,
            ) -> Pin<
                Box<dyn Future<Output = Result<PortMappingResult, PortMappingError>> + Send + '_>,
            > {
                Box::pin(async move {
                    let idx = self.map_calls.fetch_add(1, Ordering::SeqCst) as usize;
                    let pick = idx.min(self.results.len().saturating_sub(1));
                    self.results[pick].clone()
                })
            }

            fn renew(
                &self,
                internal_port: u16,
            ) -> Pin<
                Box<dyn Future<Output = Result<PortMappingResult, PortMappingError>> + Send + '_>,
            > {
                self.map_port(internal_port)
            }

            fn remove(
                &self,
                _internal_port: u16,
            ) -> Pin<Box<dyn Future<Output = Result<(), PortMappingError>> + Send + '_>>
            {
                Box::pin(async { Ok(()) })
            }
        }

        #[test]
        fn interval_is_50_percent_of_ttl() {
            assert_eq!(
                mapping_renewal_interval(Duration::from_hours(1)),
                Duration::from_mins(30),
            );
            assert_eq!(
                mapping_renewal_interval(Duration::from_mins(10)),
                Duration::from_mins(5),
            );
        }

        #[test]
        fn interval_is_floored_for_short_and_zero_ttls() {
            // 50% of 4s = 2s, below the 5s floor.
            assert_eq!(
                mapping_renewal_interval(Duration::from_secs(4)),
                MIN_MAPPING_RENEWAL_INTERVAL,
            );
            // A zero TTL still yields the floor, never zero.
            assert_eq!(
                mapping_renewal_interval(Duration::ZERO),
                MIN_MAPPING_RENEWAL_INTERVAL,
            );
        }

        /// The loop re-issues the mapping after the renewal interval, and stops
        /// renewing once cancelled. Time is injected via tokio's paused clock so
        /// the test is hermetic (no real 1800s wait).
        #[tokio::test(start_paused = true)]
        async fn renews_after_interval_then_stops_on_cancel() {
            // 100s TTL → second-and-later interval = 50s. The FIRST interval is
            // the floor (5s); after that the loop learns the real reported TTL.
            let mapper = Arc::new(CountingMapper::always_ok(Duration::from_secs(100)));
            let mappers: Vec<Arc<dyn PortMapper>> = vec![mapper.clone()];
            let cancel = CancellationToken::new();

            let handle = tokio::spawn(run_mapping_renewal_loop(mappers, 8443, cancel.clone()));

            // Let the spawned loop reach its first `sleep` and register the timer
            // against the paused clock before we advance it.
            tokio::task::yield_now().await;

            // No renewal before the first interval elapses.
            assert_eq!(
                mapper.calls(),
                0,
                "must not renew before the first interval"
            );

            // The first renewal is seeded at the floor (not 50% of an assumed
            // hour) so a short gateway lease can never expire before the loop
            // learns the real TTL. Advancing just past the floor fires it.
            tokio::time::advance(MIN_MAPPING_RENEWAL_INTERVAL + Duration::from_millis(1)).await;
            tokio::task::yield_now().await;
            assert!(
                mapper.calls() >= 1,
                "expected the first renewal at the floor interval, got {}",
                mapper.calls()
            );

            // Advance past the next interval (now derived from the real 100s TTL
            // = 50s) and confirm a second renewal fires.
            let after_first = mapper.calls();
            tokio::time::advance(Duration::from_secs(50) + Duration::from_millis(1)).await;
            tokio::task::yield_now().await;
            assert!(
                mapper.calls() > after_first,
                "expected a second renewal at 50% of the reported TTL"
            );

            // Cancel and confirm renewals stop: no further map calls after a long
            // advance.
            cancel.cancel();
            let _ = handle.await;
            let at_cancel = mapper.calls();
            tokio::time::advance(Duration::from_secs(10_000)).await;
            tokio::task::yield_now().await;
            assert_eq!(
                mapper.calls(),
                at_cancel,
                "cancellation must stop all further renewals"
            );
        }

        /// A transient renewal failure must NOT permanently drop the mapping: the
        /// loop retries after the backoff and recovers on the next success.
        #[tokio::test(start_paused = true)]
        async fn retries_after_a_failed_renewal() {
            // First renewal fails, second succeeds. The loop must survive the
            // failure and renew successfully afterward.
            let mapper = Arc::new(CountingMapper::new(vec![
                Err(PortMappingError::Timeout),
                Ok(PortMappingResult {
                    external_addr: ext_addr(),
                    ttl: Duration::from_secs(200),
                    protocol: MappingProtocol::NatPmp,
                }),
            ]));
            let mappers: Vec<Arc<dyn PortMapper>> = vec![mapper.clone()];
            let cancel = CancellationToken::new();

            let handle = tokio::spawn(run_mapping_renewal_loop(mappers, 8443, cancel.clone()));

            // Let the loop register its first timer against the paused clock.
            tokio::task::yield_now().await;

            // Trigger the first (failing) renewal. The first interval is the
            // floor (seeded so a short lease cannot expire before the first
            // renewal), so advance just past it.
            tokio::time::advance(MIN_MAPPING_RENEWAL_INTERVAL + Duration::from_millis(1)).await;
            tokio::task::yield_now().await;
            assert_eq!(mapper.calls(), 1, "first renewal attempt should have run");

            // After failure the loop backs off, then retries. Advance past the
            // backoff and confirm a second attempt fires (the loop did not give
            // up).
            tokio::time::advance(MAPPING_RENEWAL_RETRY_BACKOFF + Duration::from_millis(1)).await;
            tokio::task::yield_now().await;
            assert!(
                mapper.calls() >= 2,
                "loop must retry after a failed renewal, not give up; got {} calls",
                mapper.calls()
            );

            cancel.cancel();
            let _ = handle.await;
        }

        /// With no mappers (the default, non-`upnp` build) the loop is a no-op
        /// that returns immediately.
        #[tokio::test(start_paused = true)]
        async fn empty_mappers_is_noop() {
            let cancel = CancellationToken::new();
            // Returns immediately; awaiting must not hang or require cancellation.
            run_mapping_renewal_loop(Vec::new(), 8443, cancel).await;
        }
    }
}
