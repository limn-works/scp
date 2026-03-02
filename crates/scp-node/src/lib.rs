//! Application node for SCP deployments.
//!
//! `scp-node` provides [`ApplicationNode`], a concrete SDK type that composes
//! an SCP relay, an identity, and storage into a single deployable unit. It is
//! the "one box" deployment pattern -- relay + participant + storage on one
//! machine.
//!
//! See spec section 18.6 and ADR-032 in `.docs/adrs/phase-2.md`.

#![forbid(unsafe_code)]

pub mod dev_api;
pub mod http;
pub mod projection;
pub mod tls;
mod well_known;

use std::collections::HashMap;
use std::marker::PhantomData;
use std::net::SocketAddr;
use std::sync::Arc;

use scp_identity::document::DidDocument;
use scp_identity::{DidMethod, IdentityError, ScpIdentity};
use scp_platform::traits::{KeyCustody, Storage};
use scp_transport::native::server::{RelayConfig, RelayError, RelayServer, ShutdownHandle};
use scp_transport::native::storage::{BlobStorage, InMemoryBlobStorage};

pub use http::BroadcastContext;
pub use projection::ProjectedContext;

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
/// Created via [`ApplicationNodeBuilder`]. The node starts a relay server,
/// publishes the identity's DID document with `SCPRelay` service entries,
/// and provides accessors for each component.
///
/// The relay accepts connections from any SCP client, not just the local
/// identity. DID publication happens once on `.build()`, not continuously
/// (spec section 18.6.4).
///
/// The type parameter `S` is the platform storage backend (e.g.,
/// `InMemoryStorage` for testing, `SqliteStorage` for production).
///
/// See spec section 18.6 for the full design.
pub struct ApplicationNode<S: Storage, B: BlobStorage = InMemoryBlobStorage> {
    /// The domain this node serves. `None` for zero-config no-domain mode (§10.12.8).
    domain: Option<String>,
    /// Handle to the running relay server.
    relay: RelayHandle,
    /// Handle to the node's identity.
    identity: IdentityHandle,
    /// The storage backend.
    storage: Arc<S>,
    /// Shared state for HTTP handlers (`.well-known/scp`, relay bridge).
    state: Arc<http::NodeState<B>>,
}

impl<S: Storage + std::fmt::Debug, B: BlobStorage> std::fmt::Debug for ApplicationNode<S, B> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApplicationNode")
            .field("domain", &self.domain)
            .field("relay", &self.relay)
            .field("identity", &self.identity)
            .field("storage", &"<Storage>")
            .finish_non_exhaustive()
    }
}

impl<S: Storage, B: BlobStorage> ApplicationNode<S, B> {
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

    /// Returns a reference to the storage backend.
    #[must_use]
    pub fn storage(&self) -> &S {
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

    /// Registers a broadcast context so it appears in subsequent
    /// `GET /.well-known/scp` responses.
    ///
    /// Only broadcast contexts may be registered (spec section 18.3
    /// privacy constraints). Encrypted context IDs MUST NOT be exposed.
    pub async fn register_broadcast_context(&self, id: String, name: Option<String>) {
        let mut contexts = self.state.broadcast_contexts.write().await;
        contexts.push(BroadcastContext { id, name });
    }

    /// Returns the hex-encoded bridge secret for the internal relay.
    ///
    /// This is the token that must be included as a `token` query parameter
    /// when connecting directly to the relay's bound address. Used by tests
    /// that bypass the axum bridge layer.
    ///
    /// **Security:** This value is a secret. Do not log or expose it.
    #[must_use]
    pub fn bridge_token_hex(&self) -> String {
        scp_transport::native::server::hex_encode_32(&self.state.bridge_secret)
    }

    /// Returns the dev API bearer token if the dev API is enabled.
    ///
    /// Returns `Some` when [`ApplicationNodeBuilder::local_api`] was called,
    /// `None` otherwise. The token format is `scp_local_token_<32 hex chars>`.
    ///
    /// See spec section 18.10.2.
    #[must_use]
    pub fn dev_token(&self) -> Option<&str> {
        self.state.dev_token.as_deref()
    }

    /// Gracefully shuts down the relay server.
    ///
    /// In-flight connection handlers drain naturally — they are not cancelled.
    pub fn shutdown(&self) {
        self.relay.shutdown_handle.shutdown();
    }

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
    /// See spec sections 18.11.2 and 18.11.8.
    pub async fn enable_broadcast_projection(
        &self,
        context_id: &str,
        broadcast_key: scp_core::crypto::sender_keys::BroadcastKey,
    ) {
        let routing_id = projection::compute_routing_id(context_id);
        let mut registry = self.state.projected_contexts.write().await;
        if let Some(existing) = registry.get_mut(&routing_id) {
            existing.insert_key(broadcast_key);
        } else {
            let projected = ProjectedContext::new(context_id, broadcast_key);
            registry.insert(routing_id, projected);
        }
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
        registry.remove(&routing_id);
    }
}

/// Returns a new [`ApplicationNodeBuilder`].
///
/// Convenience function equivalent to `ApplicationNodeBuilder::new()`.
#[must_use]
pub fn builder() -> ApplicationNodeBuilder {
    ApplicationNodeBuilder::new()
}

// ---------------------------------------------------------------------------
// IdentitySource
// ---------------------------------------------------------------------------

/// Specifies how the builder obtains an identity.
enum IdentitySource<K: KeyCustody, D: DidMethod> {
    /// Generate a new identity using the provided key custody and DID method.
    Generate {
        key_custody: Arc<K>,
        did_method: Arc<D>,
    },
    /// Use a pre-existing identity and document (boxed to avoid large variant
    /// size difference).
    Explicit(Box<ExplicitIdentity<D>>),
}

/// Data for an explicitly provided identity.
struct ExplicitIdentity<D: DidMethod> {
    identity: ScpIdentity,
    document: DidDocument,
    did_method: Arc<D>,
}

// ---------------------------------------------------------------------------
// Builder type-state markers
// ---------------------------------------------------------------------------

/// Marker: domain has not been set on the builder.
pub struct NoDomain;
/// Marker: domain has been set on the builder.
pub struct HasDomain;
/// Marker: zero-config (no domain) mode has been explicitly selected (§10.12.8).
pub struct HasNoDomain;

/// Marker: identity has not been configured on the builder.
pub struct NoIdentity;
/// Marker: identity has been configured on the builder.
pub struct HasIdentity;

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
/// Uses [`NatProber`](scp_transport::nat::NatProber) for STUN probing and
/// [`PortMappingManager`](scp_transport::nat::PortMappingManager) for `UPnP`.
pub struct DefaultNatStrategy {
    /// STUN server URL override (if set via `.stun_server()`).
    stun_server: Option<String>,
    /// Bridge relay URL override (if set via `.bridge_relay()`).
    bridge_relay: Option<String>,
}

impl DefaultNatStrategy {
    /// Creates a new default NAT strategy with optional overrides.
    #[must_use]
    pub const fn new(stun_server: Option<String>, bridge_relay: Option<String>) -> Self {
        Self {
            stun_server,
            bridge_relay,
        }
    }
}

impl NatStrategy for DefaultNatStrategy {
    fn select_tier(
        &self,
        _relay_port: u16,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<ReachabilityTier, NodeError>> + Send + '_>,
    > {
        Box::pin(async move {
            use scp_transport::nat::{NatProber, StunEndpoint};

            // Step 1: Build STUN endpoint list.
            let endpoints: Vec<StunEndpoint> = if let Some(ref override_url) = self.stun_server {
                // User-provided override: single endpoint.
                let addr: SocketAddr = override_url.parse().map_err(|e| {
                    NodeError::Nat(format!("invalid STUN server address '{override_url}': {e}"))
                })?;
                vec![StunEndpoint {
                    addr,
                    label: override_url.clone(),
                }]
            } else {
                // Default: two pre-resolved endpoints for NAT classification.
                DEFAULT_STUN_ENDPOINTS
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
                    .collect()
            };

            let prober = NatProber::new(endpoints, None)
                .map_err(|e| NodeError::Nat(format!("failed to create NAT prober: {e}")))?;

            // Step 2: Probe NAT type.
            let probe_result = prober
                .probe()
                .await
                .map_err(|e| NodeError::Nat(format!("NAT probing failed: {e}")))?;

            tracing::info!(
                nat_type = %probe_result.nat_type,
                external_addr = ?probe_result.external_addr,
                "NAT type probed"
            );

            // Step 3: Attempt Tier 1 (UPnP) — requires real UPnP gateway discovery.
            // UPnP is best-effort; failure falls through to Tier 2.
            // Full UPnP integration requires `PortMappingManager` with real mappers.
            // For now, the DefaultNatStrategy attempts STUN-based tiers.
            // UPnP can be added when production PortMapper impls exist.

            // Step 4: For non-symmetric NAT, use Tier 2 (STUN address).
            if probe_result.nat_type.is_hole_punchable()
                && let Some(external_addr) = probe_result.external_addr
            {
                return Ok(ReachabilityTier::Stun { external_addr });
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
}

// ---------------------------------------------------------------------------
// ApplicationNodeBuilder
// ---------------------------------------------------------------------------

/// Builder for [`ApplicationNode`].
///
/// Uses a type-state pattern to enforce required fields at compile time.
/// The builder starts with `Dom = NoDomain, Id = NoIdentity`. Calling
/// [`domain`](Self::domain) transitions `Dom` to [`HasDomain`], and calling
/// [`generate_identity_with`](Self::generate_identity_with) or
/// [`identity`](Self::identity) transitions `Id` to [`HasIdentity`].
/// [`build`](Self::build) is only available when both are set.
///
/// # Required fields
///
/// - [`domain`](Self::domain) -- the domain this node serves.
/// - Identity -- either [`generate_identity_with`](Self::generate_identity_with)
///   or [`identity`](Self::identity).
///
/// # Optional fields
///
/// - [`storage`](Self::storage), [`blob_storage`](Self::blob_storage),
///   [`bind_addr`](Self::bind_addr), [`acme_email`](Self::acme_email).
pub struct ApplicationNodeBuilder<
    K: KeyCustody = NoOpCustody,
    D: DidMethod = NoOpDidMethod,
    S: Storage = NoOpStorage,
    B: BlobStorage = InMemoryBlobStorage,
    Dom = NoDomain,
    Id = NoIdentity,
> {
    domain: Option<String>,
    identity_source: Option<IdentitySource<K, D>>,
    storage: Option<Arc<S>>,
    blob_storage: Option<B>,
    bind_addr: Option<SocketAddr>,
    acme_email: Option<String>,
    /// Override the STUN endpoint for NAT type probing (§10.12.8).
    stun_server: Option<String>,
    /// Override the bridge relay for Tier 3 fallback (§10.12.8).
    bridge_relay: Option<String>,
    /// Pluggable NAT strategy for testability.
    nat_strategy: Option<Arc<dyn NatStrategy>>,
    /// Pluggable TLS provider for testability (domain mode only).
    tls_provider: Option<Arc<dyn TlsProvider>>,
    /// Bind address for the local dev API server. `None` = dev API disabled.
    local_api_addr: Option<SocketAddr>,
    _domain_state: PhantomData<Dom>,
    _identity_state: PhantomData<Id>,
}

impl ApplicationNodeBuilder {
    /// Creates a new builder with all fields unset.
    ///
    /// The relay uses [`InMemoryBlobStorage`] by default. Call
    /// [`blob_storage`](Self::blob_storage) to use a different backend.
    #[must_use]
    pub fn new() -> Self {
        Self {
            domain: None,
            identity_source: None,
            storage: None,
            blob_storage: Some(InMemoryBlobStorage::new()),
            bind_addr: None,
            acme_email: None,
            stun_server: None,
            bridge_relay: None,
            nat_strategy: None,
            tls_provider: None,
            local_api_addr: None,
            _domain_state: PhantomData,
            _identity_state: PhantomData,
        }
    }
}

impl Default
    for ApplicationNodeBuilder<
        NoOpCustody,
        NoOpDidMethod,
        NoOpStorage,
        InMemoryBlobStorage,
        NoDomain,
        NoIdentity,
    >
{
    fn default() -> Self {
        Self::new()
    }
}

impl<
    K: KeyCustody + 'static,
    D: DidMethod + 'static,
    S: Storage + 'static,
    B: BlobStorage + 'static,
    Id,
> ApplicationNodeBuilder<K, D, S, B, NoDomain, Id>
{
    /// Sets the domain this node serves.
    ///
    /// The relay URL is derived as `wss://<domain>/scp/v1` (spec section
    /// 18.5.2). Either `.domain()` or `.no_domain()` must be called —
    /// the builder cannot be built without one (§10.12.8).
    #[must_use]
    pub fn domain(self, domain: &str) -> ApplicationNodeBuilder<K, D, S, B, HasDomain, Id> {
        ApplicationNodeBuilder {
            domain: Some(domain.to_owned()),
            identity_source: self.identity_source,
            storage: self.storage,
            blob_storage: self.blob_storage,
            bind_addr: self.bind_addr,
            acme_email: self.acme_email,
            stun_server: self.stun_server,
            bridge_relay: self.bridge_relay,
            nat_strategy: self.nat_strategy,
            tls_provider: self.tls_provider,
            local_api_addr: self.local_api_addr,
            _domain_state: PhantomData,
            _identity_state: PhantomData,
        }
    }

    /// Zero-config NAT-traversed mode (§10.12.8).
    ///
    /// When set: skip ACME TLS provisioning, probe NAT type via STUN,
    /// attempt `UPnP` (Tier 1), fallback to STUN address (Tier 2),
    /// register with bridge (Tier 3), publish DID document with `ws://`
    /// relay URL, do NOT serve `.well-known/scp`.
    ///
    /// This is the zero-config deployment path for self-hosted relays
    /// behind residential NAT.
    #[must_use]
    pub fn no_domain(self) -> ApplicationNodeBuilder<K, D, S, B, HasNoDomain, Id> {
        ApplicationNodeBuilder {
            domain: None,
            identity_source: self.identity_source,
            storage: self.storage,
            blob_storage: self.blob_storage,
            bind_addr: self.bind_addr,
            acme_email: self.acme_email,
            stun_server: self.stun_server,
            bridge_relay: self.bridge_relay,
            nat_strategy: self.nat_strategy,
            tls_provider: self.tls_provider,
            local_api_addr: self.local_api_addr,
            _domain_state: PhantomData,
            _identity_state: PhantomData,
        }
    }
}

impl<
    K: KeyCustody + 'static,
    D: DidMethod + 'static,
    S: Storage + 'static,
    B: BlobStorage + 'static,
    Dom,
    Id,
> ApplicationNodeBuilder<K, D, S, B, Dom, Id>
{
    /// Sets the socket address for the relay server to bind to.
    ///
    /// Defaults to `127.0.0.1:0` (OS-assigned port) if not specified.
    #[must_use]
    pub const fn bind_addr(mut self, addr: SocketAddr) -> Self {
        self.bind_addr = Some(addr);
        self
    }

    /// Sets the ACME email for TLS certificate provisioning.
    ///
    /// Used for Let's Encrypt certificate requests (spec section 18.6.3).
    /// Optional -- TLS provisioning is not implemented in this scaffold but
    /// the configuration is captured for future use.
    #[must_use]
    pub fn acme_email(mut self, email: &str) -> Self {
        self.acme_email = Some(email.to_owned());
        self
    }

    /// Override the STUN endpoint used for NAT type probing (§10.12.8).
    ///
    /// Default: bootstrap relay with STUN support. The value should be a
    /// socket address (e.g., `"stun.l.google.com:19302"`).
    #[must_use]
    pub fn stun_server(mut self, url: &str) -> Self {
        self.stun_server = Some(url.to_owned());
        self
    }

    /// Override the bridge relay used for Tier 3 fallback (§10.12.8).
    ///
    /// Default: first bridge-capable relay in the fallback relay list.
    /// The value should be a `wss://` URL.
    #[must_use]
    pub fn bridge_relay(mut self, url: &str) -> Self {
        self.bridge_relay = Some(url.to_owned());
        self
    }

    /// Sets a custom NAT strategy for testability.
    ///
    /// Production code uses [`DefaultNatStrategy`] (created automatically
    /// during `build()`). Tests can inject mock strategies.
    #[must_use]
    pub fn nat_strategy(mut self, strategy: Arc<dyn NatStrategy>) -> Self {
        self.nat_strategy = Some(strategy);
        self
    }

    /// Sets a custom TLS provider for testability.
    ///
    /// Production code uses [`AcmeProvider`](tls::AcmeProvider) (created
    /// automatically during domain `build()`). Tests can inject mock
    /// providers that succeed or fail deterministically.
    #[must_use]
    pub fn tls_provider(mut self, provider: Arc<dyn TlsProvider>) -> Self {
        self.tls_provider = Some(provider);
        self
    }

    /// Enables the local dev API on the specified address.
    ///
    /// When set, a bearer token is generated at build time and logged at
    /// `INFO` level. The dev API listens on a separate port from the public
    /// HTTPS listener, typically bound to `127.0.0.1:<port>`.
    ///
    /// If not called, the dev API is disabled (production default).
    ///
    /// See spec section 18.10.2 and 18.10.5.
    /// # Panics
    ///
    /// Panics if `addr` is not a loopback address (`127.0.0.1` or `::1`).
    /// The dev API must never be exposed on a non-loopback interface.
    #[must_use]
    pub fn local_api(mut self, addr: SocketAddr) -> Self {
        assert!(
            addr.ip().is_loopback(),
            "dev API bind address must be loopback (127.0.0.1 or ::1), got {addr}"
        );
        self.local_api_addr = Some(addr);
        self
    }
}

impl<K: KeyCustody + 'static, D: DidMethod + 'static, B: BlobStorage + 'static, Dom, Id>
    ApplicationNodeBuilder<K, D, NoOpStorage, B, Dom, Id>
{
    /// Sets an explicit storage backend.
    ///
    /// If not called, `.build()` uses a default no-op storage.
    pub fn storage<S2: Storage + 'static>(
        self,
        storage: Arc<S2>,
    ) -> ApplicationNodeBuilder<K, D, S2, B, Dom, Id> {
        ApplicationNodeBuilder {
            domain: self.domain,
            identity_source: self.identity_source,
            storage: Some(storage),
            blob_storage: self.blob_storage,
            bind_addr: self.bind_addr,
            acme_email: self.acme_email,
            stun_server: self.stun_server,
            bridge_relay: self.bridge_relay,
            nat_strategy: self.nat_strategy,
            tls_provider: self.tls_provider,
            local_api_addr: self.local_api_addr,
            _domain_state: PhantomData,
            _identity_state: PhantomData,
        }
    }
}

impl<K: KeyCustody + 'static, D: DidMethod + 'static, S: Storage + 'static, Dom, Id>
    ApplicationNodeBuilder<K, D, S, InMemoryBlobStorage, Dom, Id>
{
    /// Sets a custom blob storage backend for the relay server.
    ///
    /// If not called, the relay uses [`InMemoryBlobStorage`] (all blobs lost on restart).
    /// Accepts any type implementing [`BlobStorage`].
    pub fn blob_storage<B2: BlobStorage + 'static>(
        self,
        blob_storage: B2,
    ) -> ApplicationNodeBuilder<K, D, S, B2, Dom, Id> {
        ApplicationNodeBuilder {
            domain: self.domain,
            identity_source: self.identity_source,
            storage: self.storage,
            blob_storage: Some(blob_storage),
            bind_addr: self.bind_addr,
            acme_email: self.acme_email,
            stun_server: self.stun_server,
            bridge_relay: self.bridge_relay,
            nat_strategy: self.nat_strategy,
            tls_provider: self.tls_provider,
            local_api_addr: self.local_api_addr,
            _domain_state: PhantomData,
            _identity_state: PhantomData,
        }
    }
}

impl<S: Storage + 'static, B: BlobStorage + 'static, Dom>
    ApplicationNodeBuilder<NoOpCustody, NoOpDidMethod, S, B, Dom, NoIdentity>
{
    /// Sets an explicit identity and DID document to use.
    ///
    /// The identity will be published to the DHT with `SCPRelay` entries
    /// pointing to this node's relay URL.
    pub fn identity<D2: DidMethod + 'static>(
        self,
        identity: ScpIdentity,
        document: DidDocument,
        did_method: Arc<D2>,
    ) -> ApplicationNodeBuilder<NoOpCustody, D2, S, B, Dom, HasIdentity> {
        ApplicationNodeBuilder {
            domain: self.domain,
            identity_source: Some(IdentitySource::Explicit(Box::new(ExplicitIdentity {
                identity,
                document,
                did_method,
            }))),
            storage: self.storage,
            blob_storage: self.blob_storage,
            bind_addr: self.bind_addr,
            acme_email: self.acme_email,
            stun_server: self.stun_server,
            bridge_relay: self.bridge_relay,
            nat_strategy: self.nat_strategy,
            tls_provider: self.tls_provider,
            local_api_addr: self.local_api_addr,
            _domain_state: PhantomData,
            _identity_state: PhantomData,
        }
    }

    /// Configures the builder to generate a new DID identity on `.build()`.
    ///
    /// Uses the provided key custody and DID method implementations.
    pub fn generate_identity_with<K2: KeyCustody + 'static, D2: DidMethod + 'static>(
        self,
        key_custody: Arc<K2>,
        did_method: Arc<D2>,
    ) -> ApplicationNodeBuilder<K2, D2, S, B, Dom, HasIdentity> {
        ApplicationNodeBuilder {
            domain: self.domain,
            identity_source: Some(IdentitySource::Generate {
                key_custody,
                did_method,
            }),
            storage: self.storage,
            blob_storage: self.blob_storage,
            bind_addr: self.bind_addr,
            acme_email: self.acme_email,
            stun_server: self.stun_server,
            bridge_relay: self.bridge_relay,
            nat_strategy: self.nat_strategy,
            tls_provider: self.tls_provider,
            local_api_addr: self.local_api_addr,
            _domain_state: PhantomData,
            _identity_state: PhantomData,
        }
    }
}

impl<
    K: KeyCustody + 'static,
    D: DidMethod + 'static,
    S: Storage + Default + 'static,
    B: BlobStorage + 'static,
> ApplicationNodeBuilder<K, D, S, B, HasDomain, HasIdentity>
{
    /// Builds the [`ApplicationNode`].
    ///
    /// This method is only available when both [`domain`](Self::domain) and
    /// identity ([`generate_identity_with`](Self::generate_identity_with) or
    /// [`identity`](Self::identity)) have been set — the type system enforces
    /// this at compile time.
    ///
    /// # Steps
    ///
    /// 1. Initializes storage (uses provided or creates default).
    /// 2. Loads or generates identity.
    /// 3. Adds `SCPRelay` service entry to the DID document.
    /// 4. Starts relay server (must be listening before publication).
    /// 5. Publishes DID document to the DHT.
    ///
    /// DID publication happens once on `.build()`, not continuously
    /// (spec section 18.6.4).
    ///
    /// # Errors
    ///
    /// Returns [`NodeError::Identity`] if identity creation or DID
    /// publication fails. Returns [`NodeError::Relay`] if the relay server
    /// fails to start.
    pub async fn build(self) -> Result<ApplicationNode<S, B>, NodeError> {
        // Type-state guarantees domain and identity_source are set.
        // The runtime check is a defensive fallback — the type system
        // prevents reaching this code without both fields configured.
        let domain = self.domain.ok_or(NodeError::MissingField("domain"))?;
        let identity_source = self
            .identity_source
            .ok_or(NodeError::MissingField("identity"))?;

        // 2. Initialize storage.
        let storage = self.storage.unwrap_or_else(|| Arc::new(S::default()));

        // 3. Obtain identity.
        let (identity, document, did_method) = match identity_source {
            IdentitySource::Generate {
                key_custody,
                did_method,
            } => {
                let (identity, document) = did_method.create(&*key_custody).await?;
                (identity, document, did_method)
            }
            IdentitySource::Explicit(e) => (e.identity, e.document, e.did_method),
        };

        // 4. Bridge secret for internal WebSocket relay connection (#85).
        let bridge_secret: [u8; 32] = rand::random();

        // 6. Start relay server — must be listening before DID publish.
        let bind_addr = self
            .bind_addr
            .unwrap_or_else(|| SocketAddr::from(([127, 0, 0, 1], 0)));
        let relay_config = RelayConfig {
            bind_addr,
            bridge_secret: Some(bridge_secret),
            ..RelayConfig::default()
        };

        let blob_storage = self
            .blob_storage
            .ok_or(NodeError::MissingField("blob_storage"))?;
        let blob_storage = Arc::new(blob_storage);
        let relay_server = RelayServer::new(relay_config.clone(), Arc::clone(&blob_storage));
        let (shutdown_handle, bound_addr) = relay_server.start().await?;

        // 7. Generate dev API token if local_api was configured.
        let dev_token = self.local_api_addr.map(generate_dev_token);

        // 8. Attempt TLS provisioning (§10.12.8 step 4).
        //    Success → domain deployment; failure → NAT-traversed fallthrough.
        let tls_provider = resolve_tls(
            self.tls_provider,
            &domain,
            &storage,
            self.acme_email.as_ref(),
        );

        match tls_provider.provision().await {
            Ok(_cert_data) => {
                // TLS provisioned successfully — proceed with domain deployment.
                let relay_url = format!("wss://{domain}/scp/v1");

                let mut document = document;
                document.add_relay_service(&relay_url)?;

                did_method.publish(&identity, &document).await?;

                tracing::info!(
                    domain = %domain,
                    relay_url = %relay_url,
                    bound_addr = %bound_addr,
                    did = %identity.did,
                    "application node started (domain mode)"
                );

                let state = Arc::new(http::NodeState {
                    did: identity.did.clone(),
                    relay_url: relay_url.clone(),
                    broadcast_contexts: tokio::sync::RwLock::new(Vec::new()),
                    relay_addr: bound_addr,
                    bridge_secret,
                    dev_token,
                    dev_bind_addr: self.local_api_addr,
                    projected_contexts: tokio::sync::RwLock::new(HashMap::new()),
                    blob_storage,
                    relay_config,
                    start_time: std::time::Instant::now(),
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
                })
            }
            Err(tls_err) => {
                tracing::warn!(
                    domain = %domain,
                    error = %tls_err,
                    "domain-based TLS provisioning failed, falling through to NAT-traversed mode (§10.12.8)"
                );

                let strategy = resolve_nat(self.nat_strategy, self.stun_server, self.bridge_relay);

                build_no_domain_inner(
                    identity,
                    document,
                    did_method,
                    storage,
                    shutdown_handle,
                    bound_addr,
                    strategy,
                    bridge_secret,
                    dev_token,
                    self.local_api_addr,
                    blob_storage,
                    relay_config,
                )
                .await
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Dev API token generation (spec §18.10.2)
// ---------------------------------------------------------------------------

/// Generate a random bearer token for the dev API.
///
/// 16 random bytes from `OsRng` → 32 hex chars (spec §18.10.2).
/// Logs a masked prefix — never the full token.
fn generate_dev_token(addr: SocketAddr) -> String {
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
fn resolve_tls<S: Storage + 'static>(
    provider: Option<Arc<dyn TlsProvider>>,
    domain: &str,
    storage: &Arc<S>,
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
// NAT strategy resolution (§10.12.8 step 5)
// ---------------------------------------------------------------------------

/// Resolves the NAT traversal strategy: uses the explicitly provided one, or
/// constructs a [`DefaultNatStrategy`] from the STUN/bridge configuration.
fn resolve_nat(
    strategy: Option<Arc<dyn NatStrategy>>,
    stun_server: Option<String>,
    bridge_relay: Option<String>,
) -> Arc<dyn NatStrategy> {
    strategy.unwrap_or_else(|| Arc::new(DefaultNatStrategy::new(stun_server, bridge_relay)))
}

// ---------------------------------------------------------------------------
// Shared no-domain build logic (used by HasNoDomain::build and domain fallthrough)
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
async fn build_no_domain_inner<
    D: DidMethod + 'static,
    S: Storage + 'static,
    B: BlobStorage + 'static,
>(
    identity: ScpIdentity,
    mut document: DidDocument,
    did_method: Arc<D>,
    storage: Arc<S>,
    shutdown_handle: ShutdownHandle,
    bound_addr: SocketAddr,
    nat_strategy: Arc<dyn NatStrategy>,
    bridge_secret: [u8; 32],
    dev_token: Option<String>,
    dev_bind_addr: Option<SocketAddr>,
    blob_storage: Arc<B>,
    relay_config: RelayConfig,
) -> Result<ApplicationNode<S, B>, NodeError> {
    let tier = nat_strategy.select_tier(bound_addr.port()).await?;

    let relay_url = match &tier {
        ReachabilityTier::Upnp { external_addr } | ReachabilityTier::Stun { external_addr } => {
            format!("ws://{external_addr}/scp/v1")
        }
        ReachabilityTier::Bridge { bridge_url } => bridge_url.clone(),
    };

    let relay_count = document
        .service
        .iter()
        .filter(|s| s.service_type == "SCPRelay")
        .count();

    document.service.push(scp_identity::document::Service {
        id: format!("{}#scp-relay-{}", document.id, relay_count + 1),
        service_type: "SCPRelay".to_owned(),
        service_endpoint: relay_url.clone(),
    });

    // 4. Publish DID document.
    did_method.publish(&identity, &document).await?;

    tracing::info!(
        tier = ?tier,
        relay_url = %relay_url,
        bound_addr = %bound_addr,
        did = %identity.did,
        "application node started (no-domain mode, §10.12.8)"
    );

    let state = Arc::new(http::NodeState {
        did: identity.did.clone(),
        relay_url,
        broadcast_contexts: tokio::sync::RwLock::new(Vec::new()),
        relay_addr: bound_addr,
        bridge_secret,
        dev_token,
        dev_bind_addr,
        projected_contexts: tokio::sync::RwLock::new(HashMap::new()),
        blob_storage,
        relay_config,
        start_time: std::time::Instant::now(),
    });

    // Do NOT serve .well-known/scp — no domain to serve from (§10.12.8).
    Ok(ApplicationNode {
        domain: None,
        relay: RelayHandle {
            bound_addr,
            shutdown_handle,
        },
        identity: IdentityHandle { identity, document },
        storage,
        state,
    })
}

// ---------------------------------------------------------------------------
// Build for HasNoDomain — zero-config NAT-traversed mode (§10.12.8)
// ---------------------------------------------------------------------------

impl<
    K: KeyCustody + 'static,
    D: DidMethod + 'static,
    S: Storage + Default + 'static,
    B: BlobStorage + 'static,
> ApplicationNodeBuilder<K, D, S, B, HasNoDomain, HasIdentity>
{
    /// Builds the [`ApplicationNode`] in zero-config no-domain mode (§10.12.8).
    ///
    /// This method is only available when `.no_domain()` has been called and
    /// identity has been set — the type system enforces this at compile time.
    ///
    /// # Steps
    ///
    /// 1. Initializes storage.
    /// 2. Loads or generates identity.
    /// 3. Starts relay server.
    /// 4. Probes NAT type via STUN and selects reachability tier.
    /// 5. Constructs relay URL based on tier (ws:// for Tiers 1-2, wss:// for Tier 3).
    /// 6. Adds `SCPRelay` service entry to the DID document.
    /// 7. Publishes DID document.
    /// 8. Does NOT serve `.well-known/scp` (no domain to serve from).
    ///
    /// # Errors
    ///
    /// Returns [`NodeError::Nat`] if all reachability tiers fail.
    /// Returns [`NodeError::Identity`] if identity creation or DID
    /// publication fails. Returns [`NodeError::Relay`] if the relay server
    /// fails to start.
    pub async fn build(self) -> Result<ApplicationNode<S, B>, NodeError> {
        let identity_source = self
            .identity_source
            .ok_or(NodeError::MissingField("identity"))?;

        // 1. Initialize storage.
        let storage = self.storage.unwrap_or_else(|| Arc::new(S::default()));

        // 2. Obtain identity.
        let (identity, document, did_method) = match identity_source {
            IdentitySource::Generate {
                key_custody,
                did_method,
            } => {
                let (identity, document) = did_method.create(&*key_custody).await?;
                (identity, document, did_method)
            }
            IdentitySource::Explicit(e) => (e.identity, e.document, e.did_method),
        };

        // 3. Start relay server.
        let bind_addr = self
            .bind_addr
            .unwrap_or_else(|| SocketAddr::from(([127, 0, 0, 1], 0)));

        let bridge_secret: [u8; 32] = rand::random();
        let relay_config = RelayConfig {
            bind_addr,
            bridge_secret: Some(bridge_secret),
            ..RelayConfig::default()
        };

        let blob_storage = Arc::new(
            self.blob_storage
                .ok_or(NodeError::MissingField("blob_storage"))?,
        );
        let relay_server = RelayServer::new(relay_config.clone(), Arc::clone(&blob_storage));
        let (shutdown_handle, bound_addr) = relay_server.start().await?;

        // 4. Generate dev API token if local_api was configured.
        let dev_token = self.local_api_addr.map(generate_dev_token);

        // 5-8. Delegate to shared no-domain logic.
        let strategy: Arc<dyn NatStrategy> = self.nat_strategy.unwrap_or_else(|| {
            Arc::new(DefaultNatStrategy::new(
                self.stun_server.clone(),
                self.bridge_relay.clone(),
            ))
        });

        build_no_domain_inner(
            identity,
            document,
            did_method,
            storage,
            shutdown_handle,
            bound_addr,
            strategy,
            bridge_secret,
            dev_token,
            self.local_api_addr,
            blob_storage,
            relay_config,
        )
        .await
    }
}

// ---------------------------------------------------------------------------
// NoOp placeholder types for the default builder state
// ---------------------------------------------------------------------------

/// Placeholder key custody used as the default type parameter for
/// [`ApplicationNodeBuilder`]. All methods return errors -- callers must
/// provide a real implementation via [`generate_identity_with`] or
/// [`identity`].
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

    fn custody_type(&self, _handle: &scp_platform::KeyHandle) -> scp_platform::CustodyType {
        scp_platform::CustodyType::InMemory
    }
}

/// Placeholder DID method used as the default type parameter for
/// [`ApplicationNodeBuilder`]. All methods return errors -- callers must
/// provide a real implementation.
#[doc(hidden)]
pub struct NoOpDidMethod;

impl DidMethod for NoOpDidMethod {
    fn create(
        &self,
        _key_custody: &impl KeyCustody,
    ) -> impl std::future::Future<Output = Result<(ScpIdentity, DidDocument), IdentityError>> + Send
    {
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
/// [`ApplicationNodeBuilder`].
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

    use scp_identity::DidCache;
    use scp_identity::cache::SystemClock;
    use scp_identity::dht::DidDht;
    use scp_identity::dht_client::InMemoryDhtClient;
    use scp_platform::testing::{InMemoryKeyCustody, InMemoryStorage};

    /// The concrete `DidDht` type used in tests (with in-memory DHT and system clock).
    type TestDidDht = DidDht<InMemoryDhtClient, SystemClock>;

    /// Creates a `DidDht` instance with signing capability for tests.
    fn make_test_dht(custody: &Arc<InMemoryKeyCustody>) -> TestDidDht {
        let dht_client = Arc::new(InMemoryDhtClient::new());
        let cache = Arc::new(DidCache::new());
        let sign_fn = TestDidDht::make_sign_fn(Arc::clone(custody));
        DidDht::with_client_and_signer(dht_client, cache, sign_fn)
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

    /// Helper: creates a builder with domain and `generate_identity` configured.
    ///
    /// Uses a [`SucceedingTlsProvider`] so domain-mode tests proceed without
    /// contacting a real ACME server.
    fn test_builder() -> ApplicationNodeBuilder<
        InMemoryKeyCustody,
        TestDidDht,
        InMemoryStorage,
        InMemoryBlobStorage,
        HasDomain,
        HasIdentity,
    > {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let did_method = Arc::new(make_test_dht(&custody));
        ApplicationNodeBuilder::new()
            .storage(Arc::new(InMemoryStorage::new()))
            .domain("test.example.com")
            .tls_provider(Arc::new(SucceedingTlsProvider {
                domain: "test.example.com".to_owned(),
            }))
            .generate_identity_with(custody, did_method)
    }

    /// Helper: creates an identity and document for explicit identity tests.
    async fn create_test_identity() -> (ScpIdentity, DidDocument, Arc<InMemoryKeyCustody>) {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let did_dht = make_test_dht(&custody);
        let (identity, document) = did_dht.create(&*custody).await.unwrap();
        (identity, document, custody)
    }

    /// Verifies the type-state builder compiles when all required fields
    /// are set. Missing domain or identity would be a compile error:
    ///
    /// ```compile_fail
    /// // Missing domain — NoDomain has no build():
    /// ApplicationNodeBuilder::new()
    ///     .generate_identity_with(custody, did_method)
    ///     .build().await;
    /// ```
    ///
    /// ```compile_fail
    /// // Missing identity — NoIdentity has no build():
    /// ApplicationNodeBuilder::new()
    ///     .domain("example.com")
    ///     .build().await;
    /// ```
    #[tokio::test]
    async fn type_state_builder_compiles_with_all_required_fields() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let did_method = Arc::new(make_test_dht(&custody));

        // This compiles because domain + identity are both set.
        let _builder = ApplicationNodeBuilder::new()
            .domain("test.example.com")
            .generate_identity_with(custody, did_method);

        // build() is available on the result type.
        // We don't call .build().await here to avoid starting a server,
        // but the fact that it compiles proves the type state works.
    }

    #[test]
    fn type_state_optional_fields_at_any_point() {
        // Optional fields (bind_addr, acme_email) can be called at any
        // point in the chain — before or after required fields.
        let _builder = ApplicationNodeBuilder::new()
            .bind_addr(SocketAddr::from(([127, 0, 0, 1], 0)))
            .acme_email("test@example.com");

        // And after setting required fields too.
        let custody = Arc::new(InMemoryKeyCustody::new());
        let did_method = Arc::new(make_test_dht(&custody));
        let _builder = ApplicationNodeBuilder::new()
            .domain("test.example.com")
            .generate_identity_with(custody, did_method)
            .bind_addr(SocketAddr::from(([127, 0, 0, 1], 0)))
            .acme_email("test@example.com");
    }

    #[tokio::test]
    async fn build_with_generate_identity_creates_new_did() {
        let node = test_builder()
            .bind_addr(SocketAddr::from(([127, 0, 0, 1], 0)))
            .build()
            .await
            .unwrap();

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

        let node = ApplicationNodeBuilder::new()
            .domain("explicit.example.com")
            .tls_provider(Arc::new(SucceedingTlsProvider {
                domain: "explicit.example.com".to_owned(),
            }))
            .identity(identity, document, did_method)
            .bind_addr(SocketAddr::from(([127, 0, 0, 1], 0)))
            .build()
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
            ) -> impl std::future::Future<
                Output = Result<(ScpIdentity, DidDocument), IdentityError>,
            > + Send {
                self.inner.create(key_custody)
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

        let _node = ApplicationNodeBuilder::new()
            .domain("counting.example.com")
            .tls_provider(Arc::new(SucceedingTlsProvider {
                domain: "counting.example.com".to_owned(),
            }))
            .generate_identity_with(custody, counting_method)
            .bind_addr(SocketAddr::from(([127, 0, 0, 1], 0)))
            .build()
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
        let node = test_builder()
            .bind_addr(SocketAddr::from(([127, 0, 0, 1], 0)))
            .build()
            .await
            .unwrap();

        let addr = node.relay().bound_addr();
        let token = node.bridge_token_hex();

        // Connect with the bridge token (explicit `/` path before query).
        let url = format!("ws://{addr}/?token={token}");
        let connect_result = tokio_tungstenite::connect_async(&url).await;

        assert!(
            connect_result.is_ok(),
            "relay should accept connections with valid bridge token, got error: {:?}",
            connect_result.err()
        );
    }

    #[tokio::test]
    async fn relay_rejects_connections_without_bridge_token() {
        let node = test_builder()
            .bind_addr(SocketAddr::from(([127, 0, 0, 1], 0)))
            .build()
            .await
            .unwrap();

        let addr = node.relay().bound_addr();

        // Connect without the bridge token — should be rejected.
        let url = format!("ws://{addr}");
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
            ) -> impl std::future::Future<
                Output = Result<(ScpIdentity, DidDocument), IdentityError>,
            > + Send {
                self.inner.create(key_custody)
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
        // then drop it and hand the same address to the builder.
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

        let _node = ApplicationNodeBuilder::new()
            .domain("relay-order.example.com")
            .tls_provider(Arc::new(SucceedingTlsProvider {
                domain: "relay-order.example.com".to_owned(),
            }))
            .generate_identity_with(custody, check_method)
            .bind_addr(bind_addr)
            .build()
            .await
            .unwrap();

        assert!(
            relay_was_listening.load(Ordering::SeqCst),
            "relay must be listening BEFORE DID document is published"
        );
    }

    #[tokio::test]
    async fn builder_domain_sets_relay_url() {
        let node = test_builder()
            .bind_addr(SocketAddr::from(([127, 0, 0, 1], 0)))
            .build()
            .await
            .unwrap();

        assert_eq!(node.relay_url(), "wss://test.example.com/scp/v1");
    }

    #[tokio::test]
    async fn builder_with_custom_storage() {
        let custom_storage = Arc::new(InMemoryStorage::new());
        let custody = Arc::new(InMemoryKeyCustody::new());
        let did_method = Arc::new(make_test_dht(&custody));

        let node = ApplicationNodeBuilder::new()
            .storage(custom_storage)
            .domain("storage.example.com")
            .tls_provider(Arc::new(SucceedingTlsProvider {
                domain: "storage.example.com".to_owned(),
            }))
            .generate_identity_with(custody, did_method)
            .bind_addr(SocketAddr::from(([127, 0, 0, 1], 0)))
            .build()
            .await
            .unwrap();

        // Verify the storage handle is accessible.
        let _storage = node.storage();
    }

    #[tokio::test]
    async fn builder_with_acme_email() {
        // acme_email is accepted and does not affect build.
        let node = test_builder()
            .acme_email("admin@example.com")
            .bind_addr(SocketAddr::from(([127, 0, 0, 1], 0)))
            .build()
            .await
            .unwrap();

        assert!(
            node.identity().did().starts_with("did:dht:"),
            "node should build successfully with acme_email set"
        );
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

    /// Helper: creates a builder with `no_domain` and `generate_identity` configured,
    /// using a mock NAT strategy that returns a STUN tier.
    fn test_no_domain_builder(
        tier: ReachabilityTier,
    ) -> ApplicationNodeBuilder<
        InMemoryKeyCustody,
        TestDidDht,
        InMemoryStorage,
        InMemoryBlobStorage,
        HasNoDomain,
        HasIdentity,
    > {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let did_method = Arc::new(make_test_dht(&custody));
        ApplicationNodeBuilder::new()
            .storage(Arc::new(InMemoryStorage::new()))
            .no_domain()
            .nat_strategy(Arc::new(MockNatStrategy { tier }))
            .generate_identity_with(custody, did_method)
    }

    #[test]
    fn no_domain_method_exists_and_transitions_type_state() {
        // .no_domain() should compile and transition Dom to HasNoDomain.
        let custody = Arc::new(InMemoryKeyCustody::new());
        let did_method = Arc::new(make_test_dht(&custody));

        let _builder = ApplicationNodeBuilder::new()
            .no_domain()
            .generate_identity_with(custody, did_method);

        // The fact that this compiles proves HasNoDomain enables build().
    }

    #[test]
    fn stun_server_method_exists_on_builder() {
        // .stun_server() should compile at any Dom state.
        let _builder = ApplicationNodeBuilder::new().stun_server("stun.example.com:3478");

        // Also after setting domain.
        let custody = Arc::new(InMemoryKeyCustody::new());
        let did_method = Arc::new(make_test_dht(&custody));
        let _builder = ApplicationNodeBuilder::new()
            .stun_server("stun.example.com:3478")
            .no_domain()
            .generate_identity_with(custody, did_method);
    }

    #[test]
    fn bridge_relay_method_exists_on_builder() {
        // .bridge_relay() should compile at any Dom state.
        let _builder =
            ApplicationNodeBuilder::new().bridge_relay("wss://bridge.example.com/scp/v1");
    }

    #[tokio::test]
    async fn no_domain_build_skips_tls_and_publishes_ws_url() {
        // AC: .no_domain() build skips TLS and publishes ws:// URL.
        let external_addr = SocketAddr::from(([198, 51, 100, 7], 32891));
        let tier = ReachabilityTier::Stun { external_addr };

        let node = test_no_domain_builder(tier)
            .bind_addr(SocketAddr::from(([127, 0, 0, 1], 0)))
            .build()
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

        let node = test_no_domain_builder(tier)
            .bind_addr(SocketAddr::from(([127, 0, 0, 1], 0)))
            .build()
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

        let node = test_no_domain_builder(tier)
            .bind_addr(SocketAddr::from(([127, 0, 0, 1], 0)))
            .build()
            .await
            .unwrap();

        assert_eq!(node.relay_url(), "ws://203.0.113.42:8443/scp/v1");
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

        let node = test_no_domain_builder(tier)
            .bind_addr(SocketAddr::from(([127, 0, 0, 1], 0)))
            .build()
            .await
            .unwrap();

        assert!(
            node.domain().is_none(),
            "no-domain mode: domain must be None to prevent .well-known/scp serving"
        );
    }

    #[tokio::test]
    async fn domain_build_uses_wss_no_regression() {
        // AC: When .domain() is set and succeeds, wss:// is used.
        let node = test_builder()
            .bind_addr(SocketAddr::from(([127, 0, 0, 1], 0)))
            .build()
            .await
            .unwrap();

        assert!(
            node.relay_url().starts_with("wss://"),
            "domain mode should use wss://, got: {}",
            node.relay_url()
        );
        assert_eq!(node.relay_url(), "wss://test.example.com/scp/v1");
        assert_eq!(node.domain(), Some("test.example.com"));
    }

    #[tokio::test]
    async fn domain_fallthrough_on_acme_failure_probes_nat() {
        // AC9: When .domain() is set and TLS provisioning fails (ACME),
        // automatic fallthrough to Tiers 1-3 (§10.12.8 step 4).
        // AC11: Verify that NAT is probed on fallthrough.
        use std::sync::atomic::{AtomicBool, Ordering};

        /// Mock NAT strategy that records whether it was called.
        struct RecordingNatStrategy {
            called: Arc<AtomicBool>,
            tier: ReachabilityTier,
        }

        impl NatStrategy for RecordingNatStrategy {
            fn select_tier(
                &self,
                _relay_port: u16,
            ) -> std::pin::Pin<
                Box<
                    dyn std::future::Future<Output = Result<ReachabilityTier, NodeError>>
                        + Send
                        + '_,
                >,
            > {
                self.called.store(true, Ordering::SeqCst);
                let tier = self.tier.clone();
                Box::pin(async move { Ok(tier) })
            }
        }

        let nat_called = Arc::new(AtomicBool::new(false));
        let external_addr = SocketAddr::from(([198, 51, 100, 7], 32891));

        let custody = Arc::new(InMemoryKeyCustody::new());
        let did_method = Arc::new(make_test_dht(&custody));

        let node = ApplicationNodeBuilder::new()
            .storage(Arc::new(InMemoryStorage::new()))
            .domain("fail.example.com")
            .tls_provider(Arc::new(FailingTlsProvider))
            .nat_strategy(Arc::new(RecordingNatStrategy {
                called: Arc::clone(&nat_called),
                tier: ReachabilityTier::Stun { external_addr },
            }))
            .generate_identity_with(custody, did_method)
            .bind_addr(SocketAddr::from(([127, 0, 0, 1], 0)))
            .build()
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

        let result = ApplicationNodeBuilder::new()
            .storage(Arc::new(InMemoryStorage::new()))
            .no_domain()
            .nat_strategy(Arc::new(FailingNatStrategy))
            .generate_identity_with(custody, did_method)
            .bind_addr(SocketAddr::from(([127, 0, 0, 1], 0)))
            .build()
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
            ) -> impl std::future::Future<
                Output = Result<(ScpIdentity, DidDocument), IdentityError>,
            > + Send {
                self.inner.create(key_custody)
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

        let _node = ApplicationNodeBuilder::new()
            .storage(Arc::new(InMemoryStorage::new()))
            .no_domain()
            .nat_strategy(Arc::new(MockNatStrategy { tier }))
            .generate_identity_with(custody, counting_method)
            .bind_addr(SocketAddr::from(([127, 0, 0, 1], 0)))
            .build()
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
            test_builder()
                .bind_addr(SocketAddr::from(([127, 0, 0, 1], 0)))
                .build()
                .await
                .unwrap()
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
                .await;

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
                .await;

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
}
