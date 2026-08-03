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

pub mod bridge_auth;
pub mod bridge_handlers;
pub mod config;
pub mod dev_api;
pub mod dns_provider;
pub(crate) mod error;
pub mod http;
pub mod projection;
pub mod self_host;
pub mod tls;
pub mod webhook;
mod well_known;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use scp_core::store::{CURRENT_STORE_VERSION, ProtocolRepository, StoredValue};
use scp_did::DidDocument;
use scp_identity::{DidMethod, IdentityError, ScpIdentity};
use scp_platform::traits::{KeyCustody, Storage};
use scp_transport::nat::{NatTierChange, NetworkChangeDetector};
use scp_transport::native::server::{RelayConfig, RelayError, ShutdownHandle};
use scp_transport::native::storage::{BlobStorage as _, BlobStorageBackend};
use sha2::Digest;
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

pub use http::BroadcastContext;
pub use projection::{
    DeployManifest, DeployManifestEntry, PathEntry, ProjectedContext, SiteConfig,
};
pub use self_host::{
    Asset, DeploySiteParams, HostSiteConfig, HostSiteError, HostSiteReady, SelfHostDeployer,
    SelfHostError, colocated_document_vm_key_resolver, content_type_for, deploy_site,
    embedded_assets, host_site, host_site_until, routing_id_hex,
};

// `IdentitySource` / `ExplicitIdentity` now live in `config` (ADR-052 Phase
// B-P1 name reconciliation). They are consumed by `Node::start`'s identity
// lowering in `config`; the `pub use` brings them into crate-root scope for
// both that path and external consumers.
pub use config::{
    DhtMode, ExplicitIdentity, IdentitySource, NatSlot, Node, NodeConfig, Reach, TlsMode,
};

// ---------------------------------------------------------------------------
// Default HTTP bind address
// ---------------------------------------------------------------------------

/// Default bind address for the public HTTP server (`0.0.0.0:8443`).
///
/// This binds to **all network interfaces** (`0.0.0.0`), which is
/// appropriate for public-facing deployments where the node must be
/// reachable from external clients.
///
/// Port 8443 is the standard unprivileged HTTPS alternative port, avoiding
/// the need for root/elevated privileges required by port 443.
///
/// For development or internal-only deployments, use `127.0.0.1` (loopback
/// only) via [`NodeConfig::http_bind_addr`] to avoid exposing
/// the server to the network.
pub const DEFAULT_HTTP_BIND_ADDR: SocketAddr =
    SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 8443);

/// Default bind address for the background HTTP server (`127.0.0.1:8443`).
///
/// This binds to **loopback only** (`127.0.0.1`), which is the safe default
/// for [`ApplicationNode::serve_background`] since SDK consumers typically
/// run the node in-process and do not need external access.
///
/// For public-facing deployments, pass a non-loopback address explicitly —
/// a warning is logged when a non-loopback address is used.
pub const DEFAULT_BACKGROUND_HTTP_BIND_ADDR: SocketAddr =
    SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 8443);

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
/// and never the relay upgrade or bridge routes (§10.12.8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublicSurface {
    /// Full protocol surface: `.well-known/scp`, the `/scp/v1` relay
    /// WebSocket upgrade, broadcast projection (`/scp/broadcast/*`), the
    /// bridge routes (`/v1/scp/bridge/*`), ACME challenges, and the
    /// virtual-host fallback. Used by every run mode except `--self-host`.
    Full,
    /// Restricted website surface for `--self-host`: `.well-known/scp`, the
    /// broadcast projection endpoints (`/scp/broadcast/*`, including
    /// `/feed`, `/messages`, and `/site`), and the virtual-host fallback —
    /// and nothing else. The relay upgrade/bridge (`/scp/v1`) and the bridge
    /// routes (`/v1/scp/bridge/*`) are NOT mounted, so an anonymous internet
    /// client cannot reach the node's relay or bridge through the public bind.
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
    /// The published DID document.
    document: DidDocument,
}

impl IdentityHandle {
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

    /// Returns a reference to the published [`DidDocument`].
    #[must_use]
    pub const fn document(&self) -> &DidDocument {
        &self.document
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

    /// Returns the relay URL published in the DID document.
    ///
    /// For domain mode: `wss://<domain>/scp/v1` (spec section 18.5.2).
    /// For no-domain mode: the relay URL is stored in the node state.
    #[must_use]
    pub fn relay_url(&self) -> &str {
        &self.state.relay_url
    }

    /// Returns a clonable handle to this node's outbound webhook dispatcher.
    ///
    /// The dispatcher fans context events out to registered bridge webhook
    /// endpoints (spec §12.2.1, §12.10.5). It is fed by two producers:
    ///
    /// 1. The inbound HTTP relay endpoint (`POST /v1/scp/bridge/webhook`),
    ///    which reconciles platform-originated events.
    /// 2. The local `Supervisor` event channel, wired via
    ///    [`wire_context_events`](Self::wire_context_events).
    #[must_use]
    pub fn webhook_dispatcher(&self) -> Arc<crate::webhook::WebhookDispatcher> {
        self.state.bridge_state.webhook_dispatcher()
    }

    /// Spawns a background task that forwards local `Supervisor` events to
    /// this node's [`WebhookDispatcher`](crate::webhook::WebhookDispatcher).
    ///
    /// This is the production wire for SCP-to-platform webhook delivery
    /// (§12.10.5): when a context the node hosts emits an event (message
    /// received/sent, member joined/left, governance action), the event is
    /// translated and dispatched to every registered webhook target matching
    /// that context.
    ///
    /// The caller supplies a fresh broadcast receiver obtained from
    /// [`Supervisor::subscribe_events`](scp_core::context::supervisor::Supervisor::subscribe_events).
    /// The returned [`JoinHandle`](tokio::task::JoinHandle) owns the consumer
    /// task; the caller MUST retain or supervise it so the task is aborted on
    /// shutdown (otherwise it runs until the `Supervisor` — and therefore the
    /// broadcast sender — is dropped, which closes the channel and stops the
    /// consumer cleanly).
    ///
    /// # Fail-safe
    ///
    /// Webhook delivery is best-effort. A slow or unreachable webhook endpoint
    /// cannot block or crash context operations: the broadcast channel drops
    /// the oldest events for lagging consumers (logged, never panics), and the
    /// dispatcher performs HTTP I/O on its own spawned tasks with bounded
    /// retries.
    #[must_use]
    pub fn wire_context_events(
        &self,
        events: tokio::sync::broadcast::Receiver<(
            String,
            scp_core::context::membership::ContextEvent,
        )>,
    ) -> tokio::task::JoinHandle<()> {
        crate::webhook::spawn_event_consumer(events, self.webhook_dispatcher())
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
    /// connection handlers drain naturally -- they are not cancelled.
    ///
    /// The tier re-evaluation task is stopped **and joined**: on a multi-thread
    /// runtime this blocks until that task's future has been dropped, which
    /// releases the `DidMethod`/`KeyCustody` `Arc` clones the republish path
    /// captured. That makes teardown deterministic — after `shutdown()` returns,
    /// the custody backend's `SqliteStorage` advisory lock is free, so a caller
    /// can immediately re-open the same storage path (e.g. a node restart over a
    /// persisted identity) without racing the background task's teardown. Absent
    /// this join the task could still hold the custody handle for a short,
    /// nondeterministic window after `shutdown()` returned, intermittently
    /// failing the next open with an advisory-lock conflict. See
    /// [`TierReEvalHandle::stop_and_wait`].
    ///
    /// See SCP-245: "Ensure graceful shutdown of dev API listener alongside
    /// main server."
    pub fn shutdown(&self) {
        self.relay.shutdown_handle.shutdown();
        self.state.shutdown_token.cancel();
        if let Some(ref handle) = self.tier_reeval {
            handle.stop_and_wait();
        }
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
    /// projection endpoints (`/scp/broadcast/*`), the bridge routes
    /// (`/v1/scp/bridge/*`), ACME challenges, and the virtual-host fallback.
    ///
    /// [`PublicSurface::SelfHost`] exposes ONLY the read-only website surface:
    /// `.well-known/scp`, the broadcast projection endpoints, and the
    /// virtual-host fallback. The relay upgrade/bridge (`/scp/v1`) and the
    /// bridge routes (`/v1/scp/bridge/*`) are deliberately NOT mounted — in
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
                let (bridge, bridge_webhook) = http::build_bridge_routers(
                    &self.state.bridge_state,
                    self.state.bridge_lookup.as_ref(),
                );
                http::build_merged_router(
                    app_router,
                    well_known,
                    relay_rt,
                    projection,
                    bridge,
                    bridge_webhook,
                    &self.state,
                )
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
    /// Defaults to `127.0.0.1:8443` (loopback only) when `bind_addr` is
    /// `None`. A `tracing::warn!` is emitted when a non-loopback address
    /// is used, since exposing the HTTP server to the network may have
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
    /// virtual-host fallback) — the relay upgrade (`/scp/v1`) and bridge
    /// routes (`/v1/scp/bridge/*`) are not exposed on the background listener
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
    /// rather than baked into [`NodeState`]'s `tls_config` (which stays `None`
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

        let addr = bind_addr.unwrap_or(DEFAULT_BACKGROUND_HTTP_BIND_ADDR);

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

        let shutdown_token = self.state.shutdown_token.clone();

        // Build the merged router for the requested public surface.
        let merged = self.build_scp_router_with_surface(axum::Router::new(), surface);

        // Bind the TCP listener before spawning so we can report errors
        // and the bound address synchronously.
        let listener = tokio::net::TcpListener::bind(addr).await.map_err(|e| {
            // Reset serving flag on bind failure.
            self.serving.store(false, Ordering::SeqCst);
            NodeError::Serve(format!(
                "failed to bind background HTTP server on {addr}: {e}"
            ))
        })?;
        let local_addr = listener.local_addr().map_err(|e| {
            self.serving.store(false, Ordering::SeqCst);
            NodeError::Serve(format!("failed to get local address: {e}"))
        })?;

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
    /// or has no site config. Returns [`NodeError::Storage`] on storage
    /// failures.
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
impl ApplicationNode<scp_platform::in_memory::InMemoryStorage> {
    /// Creates an `ApplicationNode` with sensible development defaults.
    ///
    /// Auto-wires:
    /// - [`InMemoryKeyCustody`](scp_platform::testing::InMemoryKeyCustody)
    /// - [`InMemoryStorage`](scp_platform::in_memory::InMemoryStorage)
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
        use scp_platform::in_memory::InMemoryStorage;
        use scp_platform::testing::InMemoryKeyCustody;

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
        // byte-identical self-signed provider for the `Domain` reach. `Domain`
        // is a publishing reach, so M2 requires `DhtMode::Production`
        // (advisory in P1 — the in-memory DHT client publishes nothing).
        Node::start_for_testing(NodeConfig {
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
                InMemoryStorage::new(),
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
    /// Relay URL: `wss://<bridge-domain>/scp/v1?bridge_target=<hex>`.
    Bridge {
        /// Bridge relay URL to publish in the DID document.
        bridge_url: String,
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
    /// Bridge relay URL override (if set via `.bridge_relay()`).
    bridge_relay: Option<String>,
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
    pub fn new(stun_server: Option<String>, bridge_relay: Option<String>) -> Self {
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

// ---------------------------------------------------------------------------
// DidPublisher — object-safe trait for DID document publishing (SCP-243)
// ---------------------------------------------------------------------------

/// Object-safe trait for publishing DID documents.
///
/// The full [`DidMethod`] trait is not object-safe because it uses `impl Future`
/// in return types. This trait wraps just the `publish` method with a boxed
/// future, enabling the tier re-evaluation background task (SCP-243) to
/// republish the DID document on tier changes without requiring generic
/// parameters.
pub(crate) trait DidPublisher: Send + Sync {
    /// Publishes a DID document to the underlying DID infrastructure.
    fn publish<'a>(
        &'a self,
        identity: &'a ScpIdentity,
        document: &'a DidDocument,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), IdentityError>> + Send + 'a>>;
}

/// Blanket implementation wrapping any [`DidMethod`] into a [`DidPublisher`].
struct DidMethodPublisher<D: DidMethod> {
    inner: Arc<D>,
}

impl<D: DidMethod + 'static> DidPublisher for DidMethodPublisher<D> {
    fn publish<'a>(
        &'a self,
        identity: &'a ScpIdentity,
        document: &'a DidDocument,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), IdentityError>> + Send + 'a>>
    {
        Box::pin(self.inner.publish(identity, document))
    }
}

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
    /// Handle to the background task. Retained so the task is not detached
    /// and can be awaited for clean shutdown if needed.
    task: tokio::task::JoinHandle<()>,
    /// Cancellation token: send `true` to stop the background task.
    cancel_tx: tokio::sync::watch::Sender<bool>,
    /// Completion signal for deterministic teardown.
    ///
    /// The spawned task moves the paired [`oneshot::Sender`](tokio::sync::oneshot::Sender)
    /// into its future; the sender is dropped only when that future is dropped
    /// (i.e. when the task has fully unwound after cancellation). Awaiting this
    /// receiver therefore blocks until the task future — and every `Arc` it
    /// captured, including the `DidMethod`/`KeyCustody` clones held by the
    /// republish path — has been released. This is what makes
    /// [`shutdown`](ApplicationNode::shutdown) deterministically drop the
    /// custody handle (and its `SqliteStorage` advisory lock) before the caller
    /// re-opens the same storage path, e.g. on a node restart. Behind a
    /// `std::sync::Mutex` so it is takeable through the shared `&self` shutdown
    /// path; `None` after the first stop-and-wait so a second call is a no-op.
    done_rx: std::sync::Mutex<Option<tokio::sync::oneshot::Receiver<()>>>,
}

impl TierReEvalHandle {
    /// Signals the background re-evaluation task to stop, WITHOUT waiting for it
    /// to finish.
    ///
    /// Fire-and-forget cancel signal. Used by the unit tests in this module to
    /// tear down a directly-spawned task once their assertions are done; the
    /// production teardown path ([`ApplicationNode::shutdown`]) uses
    /// [`stop_and_wait`](Self::stop_and_wait) instead, which additionally joins
    /// the task so its captured `Arc`s are released deterministically.
    #[cfg(test)]
    fn stop(&self) {
        let _ = self.cancel_tx.send(true);
    }

    /// Signals the background task to stop and blocks until its future — and
    /// every `Arc` it captured — has been dropped.
    ///
    /// On a multi-thread runtime this bridges the sync→async boundary with
    /// [`tokio::task::block_in_place`] + [`Handle::block_on`](tokio::runtime::Handle::block_on),
    /// awaiting the completion oneshot so teardown is deterministic. The cancel
    /// signal makes the task return promptly (it is parked in a `select!` that
    /// includes the cancel watch), so the wait is bounded by the task's current
    /// poll, not by the 30-minute re-evaluation interval.
    ///
    /// `block_in_place` PANICS on a `current_thread` runtime and is unavailable
    /// outside a runtime, so both are handled by falling back to a best-effort
    /// `abort()` + cancel signal — exactly the prior fire-and-forget behaviour,
    /// only reached on runtimes where a synchronous join is impossible.
    /// Idempotent: the completion receiver is consumed on the first call, so a
    /// second invocation only re-sends the (harmless) cancel signal.
    fn stop_and_wait(&self) {
        let _ = self.cancel_tx.send(true);
        let Some(done_rx) = self
            .done_rx
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
        else {
            // Already waited once; the task future has already been awaited to
            // completion (or a prior fallback aborted it). Nothing to join.
            return;
        };
        match tokio::runtime::Handle::try_current() {
            Ok(handle) if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread => {
                // Bridge the sync `shutdown(&self)` surface to the async task
                // join so the custody `Arc` (and its advisory lock) is released
                // before this returns. Multi-thread runtime only — the flavor is
                // checked above; current_thread / no-runtime fall back to abort
                // below instead of panicking.
                tokio::task::block_in_place(|| {
                    // Awaiting the completion oneshot resolves (with `Err` —
                    // the sender was dropped, not sent) exactly when the task
                    // future is dropped. That is the signal we need: the
                    // future's captured `Arc`s are gone.
                    let _ = handle.block_on(done_rx); // ci-allow: block-on: awaits the tier-task completion oneshot so the captured DidMethod/custody Arcs drop before shutdown() returns
                }); // ci-allow: block-on: deterministic node teardown — multi-thread-checked sync→async join releasing the custody Arc before storage re-open
            }
            _ => {
                // A current_thread runtime cannot `block_in_place`, and outside
                // a runtime there is nothing to drive the join. Fall back to a
                // best-effort abort so the task is still torn down (its future
                // is dropped on the next runtime turn), matching the prior
                // fire-and-forget semantics on these runtimes.
                self.task.abort();
            }
        }
    }
}

impl Drop for TierReEvalHandle {
    fn drop(&mut self) {
        // Send the cancel signal so the task exits cleanly. If send fails
        // (already sent), abort as a safety net to prevent busy-spin when the
        // watch sender is dropped without sending `true`. `shutdown()` already
        // calls `stop_and_wait()`, so by the time a node is dropped the task is
        // typically gone; this remains the backstop for nodes dropped without
        // an explicit shutdown.
        if self.cancel_tx.send(true).is_err() {
            self.task.abort();
        }
    }
}

/// Converts a [`ReachabilityTier`] to a relay URL string.
fn tier_to_relay_url(tier: &ReachabilityTier) -> String {
    match tier {
        ReachabilityTier::Upnp { external_addr } | ReachabilityTier::Stun { external_addr } => {
            format!("ws://{external_addr}/scp/v1")
        }
        ReachabilityTier::Bridge { bridge_url } => bridge_url.clone(),
    }
}

/// Resolves the published relay URL for no-domain mode.
///
/// `Some(tier)` is the probed reachability tier; `None` means the NAT probe was
/// skipped (operator opted out — e.g. behind a tunnel/proxy), in which case the
/// node falls back to a loopback relay URL on the public HTTP port. The loopback
/// fallback keeps the published URL and the self-signed certificate SANs
/// localhost-only, which is the correct posture when external reachability is
/// provided by the proxy/tunnel rather than NAT traversal.
fn no_domain_relay_url(tier: Option<&ReachabilityTier>, http_port: u16) -> String {
    tier.map_or_else(
        || format!("ws://127.0.0.1:{http_port}/scp/v1"),
        tier_to_relay_url,
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
/// lease requested by [`scp_transport::nat::NatPmpPortMapper`].
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
/// Hold the returned [`JoinHandle`] for the node's lifetime. On shutdown, trigger
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

/// Handles a detected tier change: updates the DID document, republishes it,
/// and emits the event only after successful publish. Returns the new URL and
/// document on success.
async fn apply_tier_change(
    current_url: &str,
    new_relay_url: &str,
    trigger_reason: &str,
    current_doc: &DidDocument,
    publisher: &dyn DidPublisher,
    identity: &ScpIdentity,
    event_tx: Option<&tokio::sync::mpsc::Sender<NatTierChange>>,
) -> Option<(String, DidDocument)> {
    let mut updated_doc = current_doc.clone();
    for svc in &mut updated_doc.service {
        if svc.service_type == "SCPRelay" && svc.service_endpoint == current_url {
            new_relay_url.clone_into(&mut svc.service_endpoint);
        }
    }
    match publisher.publish(identity, &updated_doc).await {
        Ok(()) => {
            // Emit the tier-change event only after the DID document has been
            // successfully published. This ensures consumers see events that
            // correspond to actual state changes in the DHT.
            if let Some(tx) = event_tx {
                let _ = tx
                    .send(NatTierChange::TierChanged {
                        previous_relay_url: current_url.to_owned(),
                        new_relay_url: new_relay_url.to_owned(),
                        reason: trigger_reason.to_owned(),
                    })
                    .await;
            }
            tracing::info!(new_url = %new_relay_url, did = %identity.did,
                "DID document republished with new relay URL");
            Some((new_relay_url.to_owned(), updated_doc))
        }
        Err(e) => {
            tracing::warn!(error = %e, "DID document republish failed after tier change");
            None
        }
    }
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
#[allow(clippy::too_many_arguments)]
fn spawn_tier_reevaluation(
    nat_strategy: Arc<dyn NatStrategy>,
    network_detector: Option<Arc<dyn NetworkChangeDetector>>,
    publisher: Arc<dyn DidPublisher>,
    identity: ScpIdentity,
    document: DidDocument,
    relay_port: u16,
    current_relay_url: String,
    event_tx: Option<tokio::sync::mpsc::Sender<NatTierChange>>,
    reevaluation_interval: Duration,
) -> TierReEvalHandle {
    let (cancel_tx, mut cancel_rx) = tokio::sync::watch::channel(false);
    // Completion signal: the sender is moved into the task future and never
    // `send`s — it serves purely as a drop witness. When the future is dropped
    // (after cancellation unwinds the loop), `_done_tx` drops too, closing the
    // oneshot. `stop_and_wait` awaits the receiver, which resolves at exactly
    // that moment, guaranteeing every `Arc` the future captured (the
    // `publisher`/`DidMethod`/custody clones) is released before teardown
    // returns. See `TierReEvalHandle::done_rx`.
    let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();
    let task = tokio::spawn(async move {
        // Held for the lifetime of the task future; dropped with it. The `move`
        // closure captures it even though it is never read.
        let _done_tx = done_tx;
        let mut current_url = current_relay_url;
        let mut current_doc = document;
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
            let new_relay_url = tier_to_relay_url(&new_tier);
            if new_relay_url == current_url {
                tracing::debug!(relay_url = %current_url, "tier re-evaluation: no change");
                continue;
            }
            tracing::info!(
                previous_url = %current_url, new_url = %new_relay_url,
                tier = ?new_tier, reason = trigger_reason,
                "reachability tier changed, updating DID document (§10.12.1)"
            );
            if let Some((url, doc)) = apply_tier_change(
                &current_url,
                &new_relay_url,
                trigger_reason,
                &current_doc,
                &*publisher,
                &identity,
                event_tx.as_ref(),
            )
            .await
            {
                current_url = url;
                current_doc = doc;
            }
        }
    });
    TierReEvalHandle {
        task,
        cancel_tx,
        done_rx: std::sync::Mutex::new(Some(done_rx)),
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
            // Pre-rotation is mandatory at creation (spec §9.7.4.1 §3), which
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
                     widened to accept a real backend. Recovery from `#0` compromise via \
                     spec §9.7.4.1 is unreachable for this identity."
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
                // Pre-rotation is mandatory at creation (spec §9.7.4.1 §3),
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
                         restart. Recovery from `#0` compromise via spec §9.7.4.1 is unreachable \
                         for this identity until the builder API is widened to accept a real \
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
    bridge_relay: Option<String>,
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
    shutdown_handle: ShutdownHandle,
    bound_addr: SocketAddr,
    bridge_secret: Zeroizing<[u8; 32]>,
    dev_token: Option<String>,
    dev_bind_addr: Option<SocketAddr>,
    blob_storage: Arc<BlobStorageBackend>,
    relay_config: RelayConfig,
    http_bind_addr: SocketAddr,
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
    let relay_url = format!("wss://{domain}/scp/v1");
    // `add_relay_service` now returns the wasm-safe `DidError`
    // (ADR-057); route it through `IdentityError` so it lands in the
    // existing `NodeError::Identity` variant, preserving prior behavior.
    document
        .add_relay_service(&relay_url)
        .map_err(IdentityError::from)?;
    // Publish the domain→DID binding per the configured `DhtMode` (NOT
    // unconditionally). `DhtMode::Disabled` — the fail-safe default, and a
    // LEGITIMATE more-private `Domain + Disabled` config per construction.md M2
    // (:63/:194): reachable via the domain, address NOT DHT-published, shared
    // out-of-band — SKIPS the publish, so the node still starts. `Production`
    // (and the test-only `Memory`) publish FATALLY, exactly as this path did
    // before. `Domain + Disabled` is never rejected: erroring on the fail-safe
    // direction would itself violate M2.
    publish_did_document_for_mode(dht_mode, did_method.as_ref(), &identity, &document).await?;

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
        domain = %domain, relay_url = %relay_url,
        bound_addr = %bound_addr, did = %identity.did,
        "application node started (domain mode, TLS active)"
    );

    // Build the production bridge auth lookup, hydrating from storage.
    // The audience URL is the HTTPS base URL for this node (spec 12.10.2).
    let audience = format!("https://{domain}");
    let bridge_lookup = Arc::new(bridge_auth::StorageBridgeLookup::new(
        Arc::clone(&storage),
        audience,
    ));
    if let Err(e) = bridge_lookup.load_from_storage().await {
        tracing::warn!(error = %e, "failed to load bridge auth cache from storage — starting with empty cache");
    }

    let state = Arc::new(http::NodeState {
        did: identity.did.clone(),
        relay_url,
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
        shutdown_token: CancellationToken::new(),
        cors_origins,
        projection_rate_limiter: scp_transport::relay::rate_limit::PublishRateLimiter::new(
            projection_rate_limit,
        ),
        projection_ucan_cache: std::sync::RwLock::new(projection::ProjectionUcanCache::new()),
        tls_config: Some(Arc::new(tls_server_config)),
        cert_resolver: Some(cert_resolver),
        did_document: document.clone(),
        connection_tracker,
        subscription_registry,
        acme_challenges,
        hostname_index: tokio::sync::RwLock::new(HashMap::new()),
        default_site_routing_id: std::sync::RwLock::new(None),
        bridge_state: Arc::new(crate::bridge_handlers::BridgeState::new()),
        bridge_lookup: Some(bridge_lookup),
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
            shutdown_handle,
        },
        identity: IdentityHandle { identity, document },
        storage,
        state,
        tier_reeval: None,
        tier_change_rx: None,
        #[cfg(feature = "http3")]
        http3_config,
        serving: Arc::new(AtomicBool::new(false)),
        rate_limit_cleanup_spawned: Arc::new(AtomicBool::new(false)),
        serving_addr: Arc::new(tokio::sync::Mutex::new(None)),
    })
}

// ---------------------------------------------------------------------------
// Shared no-domain build logic (used by the non-domain reaches and the
// Reach::Domain ACME-failure fallthrough in config.rs's build engine)
// ---------------------------------------------------------------------------

/// Appends an `SCPRelay` service entry to the DID document for `relay_url`.
///
/// The service id is suffixed with the next sequential index so multiple relays
/// can coexist on one document (`<did>#scp-relay-<n>`).
fn push_relay_service(document: &mut DidDocument, relay_url: &str) {
    let relay_count = document
        .service
        .iter()
        .filter(|s| s.service_type == "SCPRelay")
        .count();
    document.service.push(scp_did::Service {
        id: format!("{}#scp-relay-{}", document.id, relay_count + 1),
        service_type: "SCPRelay".to_owned(),
        service_endpoint: relay_url.to_owned(),
    });
}

/// Publishes a node's DID document on the no-domain build path, discriminating
/// on the configured [`DhtMode`] so the two semantically-opposite outcomes are
/// never conflated.
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
async fn publish_did_document_for_mode<D: DidMethod + 'static>(
    dht_mode: DhtMode,
    did_method: &D,
    identity: &ScpIdentity,
    document: &DidDocument,
) -> Result<(), NodeError> {
    match dht_mode {
        DhtMode::Disabled => {
            tracing::info!(
                did = %identity.did,
                "DhtMode::Disabled — node is intentionally not DHT-published \
                 (not discoverable by design; no address disclosed)"
            );
            Ok(())
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
            .map_err(NodeError::from),
        DhtMode::Production => did_method
            .publish(identity, document)
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
    shutdown_handle: ShutdownHandle,
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
    // NAT strategy needs the public HTTP port, not the internal relay port (#641).
    let http_bind_addr = http_bind_addr.unwrap_or(DEFAULT_HTTP_BIND_ADDR);

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
        Some(nat_strategy.select_tier(http_bind_addr.port()).await?)
    };

    let relay_url = no_domain_relay_url(tier.as_ref(), http_bind_addr.port());

    push_relay_service(&mut document, &relay_url);

    // 4. Publish the DID document per the configured DhtMode: skipped for
    //    `Disabled` (fail-safe, not discoverable by design), FATAL on failure for
    //    a publishing node (`Production` / test-only `Memory`) so a genuine
    //    startup publish failure fails the node closed rather than advertising a
    //    false discoverability guarantee.
    publish_did_document_for_mode(dht_mode, did_method.as_ref(), &identity, &document).await?;

    tracing::info!(
        tier = ?tier,
        relay_url = %relay_url,
        bound_addr = %bound_addr,
        did = %identity.did,
        nat_probe_skipped = skip_nat_probe,
        "application node started (no-domain mode, §10.12.8)"
    );

    let publisher: Arc<dyn DidPublisher> = Arc::new(DidMethodPublisher {
        inner: Arc::clone(&did_method),
    });
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
            bg_identity,
            document.clone(),
            http_bind_addr.port(),
            relay_url.clone(),
            Some(tier_event_tx),
            TIER_REEVALUATION_INTERVAL,
        ))
    };

    // Bridge auth lookup — audience is relay URL in no-domain mode (spec 12.10.2).
    let bridge_lookup = Arc::new(bridge_auth::StorageBridgeLookup::new(
        Arc::clone(&storage),
        relay_url.clone(),
    ));
    if let Err(e) = bridge_lookup.load_from_storage().await {
        tracing::warn!(error = %e, "failed to load bridge auth cache from storage — starting with empty cache");
    }

    let state = Arc::new(http::NodeState {
        did: identity.did.clone(),
        relay_url,
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
        shutdown_token: CancellationToken::new(),
        cors_origins,
        projection_rate_limiter: scp_transport::relay::rate_limit::PublishRateLimiter::new(
            projection_rate_limit,
        ),
        projection_ucan_cache: std::sync::RwLock::new(projection::ProjectionUcanCache::new()),
        tls_config: None,
        cert_resolver: None,
        did_document: document.clone(),
        connection_tracker,
        subscription_registry,
        acme_challenges: None,
        hostname_index: tokio::sync::RwLock::new(HashMap::new()),
        default_site_routing_id: std::sync::RwLock::new(None),
        bridge_state: Arc::new(crate::bridge_handlers::BridgeState::new()),
        bridge_lookup: Some(bridge_lookup),
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
            shutdown_handle,
        },
        identity: IdentityHandle { identity, document },
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

impl KeyCustody for NoOpCustody {
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
        _peer_public: &[u8; 32],
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
        Output = Result<scp_platform::PseudonymKeypair, scp_platform::PlatformError>,
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
        Output = Result<scp_platform::PseudonymKeypair, scp_platform::PlatformError>,
    > + Send {
        std::future::ready(Err(scp_platform::PlatformError::StorageError(
            "NoOpCustody: not configured".to_owned(),
        )))
    }

    fn ed25519_to_x25519_agree(
        &self,
        _handle: &scp_platform::KeyHandle,
        _peer_x25519_public: &[u8; 32],
    ) -> impl std::future::Future<
        Output = Result<scp_platform::SharedSecret, scp_platform::PlatformError>,
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
    ) -> impl std::future::Future<Output = Result<(), IdentityError>> + Send {
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
    /// `Reach::Domain` is a publishing reach, so `DhtMode::Production` is set
    /// (M2); the in-memory `TestDidDht` publishes nothing offline.
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
            ) -> impl std::future::Future<Output = Result<(), IdentityError>> + Send {
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
    async fn relay_listening_before_did_publish() {
        use std::sync::atomic::{AtomicBool, Ordering};

        // Create a DID method that verifies the relay is listening when
        // publish() is called.
        struct RelayCheckDidMethod {
            inner: TestDidDht,
            relay_was_listening_at_publish: Arc<AtomicBool>,
            bind_addr: SocketAddr,
        }

        impl DidMethod for RelayCheckDidMethod {
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
            ) -> impl std::future::Future<Output = Result<(), IdentityError>> + Send {
                // Probe the relay bind address to see if it's listening.
                let addr = self.bind_addr;
                let flag = Arc::clone(&self.relay_was_listening_at_publish);
                let inner = &self.inner;
                async move {
                    // Attempt a TCP connection to the relay's bound port.
                    if tokio::net::TcpStream::connect(addr).await.is_ok() {
                        flag.store(true, Ordering::SeqCst);
                    }
                    inner.publish(identity, document).await
                }
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

        // We need to know the bind address ahead of time so the DID method
        // can probe it.  Bind to port 0 and let the OS pick a port — but the
        // relay picks the port, so we pre-bind a listener, record its address,
        // then drop it and hand the same address to the config.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let bind_addr = listener.local_addr().unwrap();
        drop(listener); // free the port for the relay

        let custody = Arc::new(InMemoryKeyCustody::new());
        let relay_was_listening = Arc::new(AtomicBool::new(false));

        let check_method = Arc::new(RelayCheckDidMethod {
            inner: make_test_dht(&custody),
            relay_was_listening_at_publish: Arc::clone(&relay_was_listening),
            bind_addr,
        });

        let _node = Node::start_for_testing(NodeConfig {
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
                    did_method: check_method,
                },
                InMemoryStorage::new(),
                BlobStorageBackend::in_memory(),
            )
        })
        .await
        .unwrap();

        assert!(
            relay_was_listening.load(Ordering::SeqCst),
            "relay must be listening BEFORE DID document is published"
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
    /// is a `MockNatStrategy` returning `tier` (no real STUN). `NatTraversal` is a
    /// publishing reach → `DhtMode::Production` (M2).
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

    #[tokio::test]
    async fn no_domain_build_with_bridge_publishes_wss_url() {
        // AC: Tier 3 (bridge) publishes wss:// bridge URL.
        let tier = ReachabilityTier::Bridge {
            bridge_url: "wss://bridge.example.com/scp/v1?bridge_target=deadbeef".to_owned(),
        };

        let node = Node::start_for_testing(no_domain_config(tier))
            .await
            .unwrap();

        // Verify the relay URL uses wss:// (bridge URL).
        assert!(
            node.relay_url().starts_with("wss://"),
            "bridge mode should publish wss:// URL, got: {}",
            node.relay_url()
        );
        assert_eq!(
            node.relay_url(),
            "wss://bridge.example.com/scp/v1?bridge_target=deadbeef"
        );

        // Verify the DID document has the bridge relay entry.
        let relay_urls = node.identity().document().relay_service_urls();
        assert_eq!(relay_urls.len(), 1);
        assert!(relay_urls[0].contains("bridge_target="));
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
        ) -> impl std::future::Future<Output = Result<(), IdentityError>> + Send {
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

    #[tokio::test]
    async fn no_domain_did_publication_happens_once() {
        use std::sync::atomic::{AtomicU32, Ordering};

        struct CountingDidMethod {
            inner: TestDidDht,
            publish_count: Arc<AtomicU32>,
        }

        impl DidMethod for CountingDidMethod {
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
            ) -> impl std::future::Future<Output = Result<(), IdentityError>> + Send {
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
            Some("wss://bridge.example.com/scp/v1".to_owned()),
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
            Some("wss://bridge.example.com/scp/v1".to_owned()),
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
            Some("wss://bridge.example.com/scp/v1".to_owned()),
        )
        .with_reachability_probe(probe);

        let tier = strategy.select_tier(4000).await.expect("should succeed");

        match tier {
            ReachabilityTier::Bridge { bridge_url } => {
                assert_eq!(bridge_url, "wss://bridge.example.com/scp/v1");
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

    /// Mock `DidPublisher` that records publish calls.
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
            _identity: &'a ScpIdentity,
            _document: &'a DidDocument,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<(), IdentityError>> + Send + 'a>,
        > {
            self.publish_count
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
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
            }],
        };

        let handle = spawn_tier_reevaluation(
            Arc::clone(&strategy) as Arc<dyn NatStrategy>,
            None,
            Arc::clone(&publisher) as Arc<dyn DidPublisher>,
            identity,
            document,
            32891,
            "ws://198.51.100.7:32891/scp/v1".to_owned(),
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
            }],
        };

        let handle = spawn_tier_reevaluation(
            Arc::clone(&strategy) as Arc<dyn NatStrategy>,
            Some(detector as Arc<dyn NetworkChangeDetector>),
            Arc::clone(&publisher) as Arc<dyn DidPublisher>,
            identity,
            document,
            32891,
            "ws://198.51.100.7:32891/scp/v1".to_owned(),
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
            }],
        };

        let handle = spawn_tier_reevaluation(
            Arc::clone(&strategy) as Arc<dyn NatStrategy>,
            None,
            Arc::clone(&publisher) as Arc<dyn DidPublisher>,
            identity,
            document,
            32891,
            "ws://198.51.100.7:32891/scp/v1".to_owned(),
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
            }],
        };

        let handle = spawn_tier_reevaluation(
            strategy as Arc<dyn NatStrategy>,
            None,
            Arc::clone(&publisher) as Arc<dyn DidPublisher>,
            identity,
            document,
            addr.port(),
            format!("ws://{addr}/scp/v1"),
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
