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
pub mod dev_api;
pub mod dns_provider;
pub(crate) mod error;
pub mod http;
pub mod projection;
pub mod tls;
mod well_known;

use std::collections::HashMap;
use std::marker::PhantomData;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use scp_core::store::{CURRENT_STORE_VERSION, ProtocolRepository, StoredValue};
use scp_identity::document::DidDocument;
use scp_identity::{DidMethod, IdentityError, ScpIdentity};
use scp_platform::EncryptedStorage;
use scp_platform::traits::{KeyCustody, Storage};
use scp_transport::nat::{NatTierChange, NetworkChangeDetector};
use scp_transport::native::server::{RelayConfig, RelayError, RelayServer, ShutdownHandle};
use scp_transport::native::storage::{BlobStorage as _, BlobStorageBackend};
use sha2::Digest;
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

pub use http::BroadcastContext;
pub use projection::{DeployManifest, DeployManifestEntry, ProjectedContext, SiteConfig};

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
/// only) via [`ApplicationNodeBuilder::http_bind_addr`] to avoid exposing
/// the server to the network.
pub const DEFAULT_HTTP_BIND_ADDR: SocketAddr =
    SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 8443);

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
/// [`ApplicationNodeBuilder::projection_rate_limit`].
///
/// See spec section 18.11.6.
pub const DEFAULT_PROJECTION_RATE_LIMIT: u32 = 60;

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
/// Created via [`ApplicationNodeBuilder`] for production use, or via
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

    /// Gracefully shuts down the relay server and the tier re-evaluation
    /// background task (§10.12.1, SCP-243).
    ///
    /// Signals the relay server, the public HTTPS listener, and the dev API
    /// listener (if running) to stop accepting new connections. In-flight
    /// connection handlers drain naturally -- they are not cancelled.
    ///
    /// See SCP-245: "Ensure graceful shutdown of dev API listener alongside
    /// main server."
    pub fn shutdown(&self) {
        self.relay.shutdown_handle.shutdown();
        self.state.shutdown_token.cancel();
        if let Some(ref handle) = self.tier_reeval {
            handle.stop();
        }
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
                .values()
                .filter_map(|p| p.hostname().map(String::from))
                .collect();

            projection::validate_site_config(config, self.domain.as_deref(), &existing_hostnames)
                .map_err(NodeError::InvalidConfig)?;
        }

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
        registry.remove(&routing_id);
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
    /// When the ban's `RevocationScope` is `Full`, old-epoch keys are
    /// purged from the projection registry so historical content encrypted
    /// under pre-ban keys is no longer served. `FutureOnly` retains old
    /// keys (historical content remains accessible).
    pub async fn propagate_ban_keys(
        &self,
        context_id: &str,
        ban_result: &scp_core::context::broadcast::GovernanceBanResult,
    ) {
        use scp_core::context::governance::RevocationScope;

        let routing_id = projection::compute_routing_id(context_id);
        let mut registry = self.state.projected_contexts.write().await;
        if let Some(projected) = registry.get_mut(&routing_id) {
            // Insert new post-rotation keys.
            for rotation in &ban_result.rotated_authors {
                projected.insert_key(rotation.new_key.clone());
            }

            // Full scope: retain only the new post-rotation keys, purging
            // all pre-ban keys so historical content is no longer
            // decryptable via projection. Uses retain_only_epochs to
            // correctly handle epoch-divergent multi-author contexts.
            if ban_result.scope == RevocationScope::Full {
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

        let mut entries: HashMap<ContentPath, [u8; 32]> = HashMap::new();
        let mut manifest_entries: Vec<projection::DeployManifestEntry> = Vec::new();
        let mut total_size: u64 = 0;
        // Track per-path sizes so path collisions subtract the old size before
        // adding the new one, preventing double-counting.
        let mut path_sizes: HashMap<ContentPath, u64> = HashMap::new();

        for stored in &blobs {
            let envelope: scp_core::crypto::sender_keys::BroadcastEnvelope =
                match rmp_serde::from_slice(&stored.blob) {
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
            });

            path_sizes.insert(path.clone(), new_size);
            entries.insert(path, stored.blob_id);
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
                    .and_then(|state| state.index.values().next().copied())
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
/// Requires the `allow_unencrypted_storage` feature flag (or `#[cfg(test)]`).
/// **Not for production use.**
#[cfg(any(test, feature = "allow_unencrypted_storage"))]
impl ApplicationNode<scp_platform::testing::InMemoryStorage> {
    /// Creates an `ApplicationNode` with sensible development defaults.
    ///
    /// Auto-wires:
    /// - [`InMemoryKeyCustody`](scp_platform::testing::InMemoryKeyCustody)
    /// - [`InMemoryStorage`](scp_platform::testing::InMemoryStorage)
    /// - [`InMemoryDhtClient`](scp_identity::InMemoryDhtClient) (no real DHT network)
    /// - [`SelfSignedTlsProvider`] (self-signed TLS certificate for `localhost`)
    /// - Relay bound to `127.0.0.1:<port>`
    /// - Domain set to `localhost`
    ///
    /// This is the zero-friction path for demos, prototyping, and integration
    /// tests. For production deployments, use [`ApplicationNodeBuilder`] with
    /// real key custody, encrypted storage, and ACME TLS.
    ///
    /// # Example
    ///
    /// ```rust,no_run
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
        use scp_identity::DidCache;
        use scp_identity::InMemoryDhtClient;
        use scp_identity::cache::SystemClock;
        use scp_identity::dht::DidDht;
        use scp_platform::testing::{InMemoryKeyCustody, InMemoryStorage};

        type DevDidDht = DidDht<InMemoryDhtClient, SystemClock>;

        let custody = Arc::new(InMemoryKeyCustody::new());
        let dht_client = Arc::new(InMemoryDhtClient::new());
        let cache = Arc::new(DidCache::new());
        let sign_fn = DevDidDht::make_sign_fn(Arc::clone(&custody));
        let did_method = Arc::new(DevDidDht::with_client_and_signer(
            dht_client, cache, sign_fn,
        ));

        ApplicationNodeBuilder::new()
            .storage(InMemoryStorage::new())
            .domain("localhost")
            .bind_addr(std::net::SocketAddr::from(([127, 0, 0, 1], port)))
            .tls_provider(Arc::new(SelfSignedTlsProvider::new("localhost")))
            .generate_identity_with(custody, did_method)
            .build_for_testing()
            .await
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
// Identity persistence
// ---------------------------------------------------------------------------

/// Storage key used by [`ApplicationNodeBuilder::identity_with_storage`] to
/// persist and reload the node's identity across restarts.
///
/// The value stored under this key is a MessagePack-serialized
/// [`StoredValue<PersistedIdentity>`] (spec §17.5).
///
/// Listed in spec §17.3 key convention as a top-level singleton key.
const IDENTITY_STORAGE_KEY: &str = "scp/identity";

/// Serializable snapshot of an [`ScpIdentity`] and its [`DidDocument`].
///
/// Used by [`ApplicationNodeBuilder::identity_with_storage`] to persist a newly
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
const TIER_REEVALUATION_INTERVAL: Duration = Duration::from_secs(30 * 60);

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
}

impl TierReEvalHandle {
    /// Gracefully stops the background re-evaluation task.
    fn stop(&self) {
        let _ = self.cancel_tx.send(true);
    }
}

impl Drop for TierReEvalHandle {
    fn drop(&mut self) {
        // Send the cancel signal so the task exits cleanly. If send fails
        // (already sent), abort as a safety net to prevent busy-spin when the
        // watch sender is dropped without sending `true`.
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
    let task = tokio::spawn(async move {
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
    TierReEvalHandle { task, cancel_tx }
}

// ---------------------------------------------------------------------------
// ApplicationNodeBuilder
// ---------------------------------------------------------------------------

/// Builder for [`ApplicationNode`].
///
/// Uses a type-state pattern to enforce required fields at compile time.
/// The builder starts with `Dom = NoDomain, Id = NoIdentity`. Calling
/// [`domain`](Self::domain) transitions `Dom` to [`HasDomain`], and calling
/// [`generate_identity_with`](Self::generate_identity_with),
/// [`identity`](Self::identity), or
/// [`identity_with_storage`](Self::identity_with_storage) transitions `Id`
/// to [`HasIdentity`]. [`build`](Self::build) is only available when both
/// are set.
///
/// # Required fields
///
/// - [`domain`](Self::domain) -- the domain this node serves.
/// - Identity -- one of [`generate_identity_with`](Self::generate_identity_with),
///   [`identity`](Self::identity), or
///   [`identity_with_storage`](Self::identity_with_storage).
///
/// # Optional fields
///
/// - [`storage`](Self::storage), [`blob_storage`](Self::blob_storage),
///   [`bind_addr`](Self::bind_addr), [`acme_email`](Self::acme_email).
pub struct ApplicationNodeBuilder<
    K: KeyCustody = NoOpCustody,
    D: DidMethod = NoOpDidMethod,
    S: Storage = NoOpStorage,
    Dom = NoDomain,
    Id = NoIdentity,
> {
    domain: Option<String>,
    identity_source: Option<IdentitySource<K, D>>,
    storage: Option<S>,
    blob_storage: Option<BlobStorageBackend>,
    bind_addr: Option<SocketAddr>,
    acme_email: Option<String>,
    /// Override the STUN endpoint for NAT type probing (§10.12.8).
    stun_server: Option<String>,
    /// Override the bridge relay for Tier 3 fallback (§10.12.8).
    bridge_relay: Option<String>,
    /// Pluggable NAT strategy for testability.
    nat_strategy: Option<Arc<dyn NatStrategy>>,
    /// Optional UPnP/NAT-PMP port mapper for Tier 1 (spec 10.12.2).
    port_mapper: Option<Arc<dyn scp_transport::nat::PortMapper>>,
    /// Optional reachability probe for self-test (SCP-242, spec 10.12.2 step 4).
    reachability_probe: Option<Arc<dyn scp_transport::nat::ReachabilityProbe>>,
    /// Pluggable TLS provider for testability (domain mode only).
    tls_provider: Option<Arc<dyn TlsProvider>>,
    /// Network change detector for tier re-evaluation (§10.12.1, SCP-243).
    /// When present, network change events trigger immediate re-evaluation.
    network_detector: Option<Arc<dyn NetworkChangeDetector>>,
    /// Bind address for the local dev API server. `None` = dev API disabled.
    local_api_addr: Option<SocketAddr>,
    /// Bind address for the public HTTP server. Separate from the relay's
    /// internal listener to avoid double-binding (#224). Defaults to
    /// [`DEFAULT_HTTP_BIND_ADDR`] (`0.0.0.0:8443`).
    http_bind_addr: Option<SocketAddr>,
    /// CORS allowed origins for public endpoints. `None` = permissive (`*`).
    /// See issue #231.
    cors_origins: Option<Vec<String>>,
    /// Per-IP rate limit for broadcast projection endpoints (req/s).
    /// `None` uses the default of 60 req/s. Configurable via
    /// `SCP_NODE_PROJECTION_RATE_LIMIT` env var.
    projection_rate_limit: Option<u32>,
    /// HTTP/3 configuration (spec §10.15.1). `None` = HTTP/3 disabled.
    #[cfg(feature = "http3")]
    http3_config: Option<scp_transport::http3::Http3Config>,
    /// When `true`, the builder will check storage for an existing identity
    /// before generating a new one, and persist newly created identities.
    /// Set by [`identity_with_storage`](Self::identity_with_storage).
    persist_identity: bool,
    /// Optional DNS provider configuration for zero-config TLS via DNS
    /// subdomain (issue #642). When set, `build()` overrides the domain
    /// and TLS provider with DNS-derived values after identity resolution.
    dns_provider_config: Option<dns_provider::DnsProviderConfig>,
    _domain_state: PhantomData<Dom>,
    _identity_state: PhantomData<Id>,
}

impl ApplicationNodeBuilder {
    /// Creates a new builder with all fields unset.
    ///
    /// The relay uses [`BlobStorageBackend::default()`] (in-memory) by default. Call
    /// [`blob_storage`](Self::blob_storage) to use a different backend.
    #[must_use]
    pub fn new() -> Self {
        Self {
            domain: None,
            identity_source: None,
            storage: None,
            blob_storage: Some(BlobStorageBackend::default()),
            bind_addr: None,
            acme_email: None,
            stun_server: None,
            bridge_relay: None,
            nat_strategy: None,
            port_mapper: None,
            reachability_probe: None,
            tls_provider: None,
            network_detector: None,
            local_api_addr: None,
            http_bind_addr: None,
            cors_origins: None,
            projection_rate_limit: None,
            #[cfg(feature = "http3")]
            http3_config: None,
            persist_identity: false,
            dns_provider_config: None,
            _domain_state: PhantomData,
            _identity_state: PhantomData,
        }
    }
}

impl Default
    for ApplicationNodeBuilder<NoOpCustody, NoOpDidMethod, NoOpStorage, NoDomain, NoIdentity>
{
    fn default() -> Self {
        Self::new()
    }
}

impl<K: KeyCustody + 'static, D: DidMethod + 'static, S: Storage + 'static, Id>
    ApplicationNodeBuilder<K, D, S, NoDomain, Id>
{
    /// Sets the domain this node serves.
    ///
    /// The relay URL is derived as `wss://<domain>/scp/v1` (spec section
    /// 18.5.2). Either `.domain()` or `.no_domain()` must be called —
    /// the builder cannot be built without one (§10.12.8).
    #[must_use]
    pub fn domain(self, domain: &str) -> ApplicationNodeBuilder<K, D, S, HasDomain, Id> {
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
            port_mapper: self.port_mapper,
            reachability_probe: self.reachability_probe,
            tls_provider: self.tls_provider,
            network_detector: self.network_detector,
            local_api_addr: self.local_api_addr,
            http_bind_addr: self.http_bind_addr,
            cors_origins: self.cors_origins,
            projection_rate_limit: self.projection_rate_limit,
            #[cfg(feature = "http3")]
            http3_config: self.http3_config,
            persist_identity: self.persist_identity,
            dns_provider_config: self.dns_provider_config,
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
    pub fn no_domain(self) -> ApplicationNodeBuilder<K, D, S, HasNoDomain, Id> {
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
            port_mapper: self.port_mapper,
            reachability_probe: self.reachability_probe,
            tls_provider: self.tls_provider,
            network_detector: self.network_detector,
            local_api_addr: self.local_api_addr,
            http_bind_addr: self.http_bind_addr,
            cors_origins: self.cors_origins,
            projection_rate_limit: self.projection_rate_limit,
            #[cfg(feature = "http3")]
            http3_config: self.http3_config,
            persist_identity: self.persist_identity,
            dns_provider_config: self.dns_provider_config,
            _domain_state: PhantomData,
            _identity_state: PhantomData,
        }
    }
}

impl<K: KeyCustody + 'static, D: DidMethod + 'static, S: Storage + 'static, Dom, Id>
    ApplicationNodeBuilder<K, D, S, Dom, Id>
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
    /// When `.domain()` is set, the email is passed to
    /// [`AcmeProvider`](tls::AcmeProvider) during `build()` for ACME account
    /// registration (SCP-246). Optional -- if omitted, the ACME account is
    /// created without a contact email.
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

    /// Sets a UPnP/NAT-PMP port mapper for Tier 1 NAT traversal (spec 10.12.2).
    ///
    /// When set, the [`DefaultNatStrategy`] will attempt `UPnP` port mapping
    /// before falling through to STUN (Tier 2). Has no effect if a custom
    /// [`NatStrategy`] is provided via [`nat_strategy`](Self::nat_strategy).
    #[must_use]
    pub fn port_mapper(mut self, mapper: Arc<dyn scp_transport::nat::PortMapper>) -> Self {
        self.port_mapper = Some(mapper);
        self
    }

    /// Sets a reachability probe for self-test verification (SCP-242).
    ///
    /// The self-test verifies that an external address is actually reachable
    /// before publishing it in the DID document (spec 10.12.2 step 4). When
    /// not set, the [`DefaultNatStrategy`] constructs a
    /// [`DefaultReachabilityProbe`](scp_transport::nat::DefaultReachabilityProbe)
    /// from the first configured STUN endpoint. Has no effect if a custom
    /// [`NatStrategy`] is provided via [`nat_strategy`](Self::nat_strategy).
    #[must_use]
    pub fn reachability_probe(
        mut self,
        probe: Arc<dyn scp_transport::nat::ReachabilityProbe>,
    ) -> Self {
        self.reachability_probe = Some(probe);
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

    /// Configures zero-config TLS via the SCP DNS subdomain service (#642).
    ///
    /// When set, `build()` derives a deterministic subdomain from the node's
    /// DID (after identity resolution) and creates an [`ScpDnsProvider`] that
    /// registers with the Limn DNS API for automatic Let's Encrypt
    /// certificate provisioning.
    ///
    /// The domain set via `.domain()` is **overridden** during `build()` with
    /// the DNS-derived subdomain (e.g., `a3f8b2c1.scp.ctx.network`).
    ///
    /// Falls back to self-signed if the DNS API is unreachable — the protocol
    /// still works because MLS provides real confidentiality.
    ///
    /// [`ScpDnsProvider`]: dns_provider::ScpDnsProvider
    #[must_use]
    pub fn dns_provider(mut self, config: dns_provider::DnsProviderConfig) -> Self {
        self.dns_provider_config = Some(config);
        self
    }

    /// Sets a network change detector for tier re-evaluation (§10.12.1, SCP-243).
    ///
    /// When provided, network change events (IP change, interface up/down)
    /// trigger immediate re-evaluation of the reachability tier. Without a
    /// detector, only the periodic 30-minute timer triggers re-evaluation.
    ///
    /// Use `ChannelNetworkChangeDetector`
    /// for channel-based event injection, or implement
    /// [`NetworkChangeDetector`]
    /// for platform-specific detection.
    #[must_use]
    pub fn network_detector(mut self, detector: Arc<dyn NetworkChangeDetector>) -> Self {
        self.network_detector = Some(detector);
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

    /// Sets the bind address for the public HTTP server.
    ///
    /// This is the address where [`ApplicationNode::serve`] listens for
    /// incoming HTTP/HTTPS connections (`.well-known/scp`, `/scp/v1`
    /// WebSocket upgrade, broadcast projection endpoints, and any
    /// application routes).
    ///
    /// This is distinct from the relay's internal bind address (set via
    /// [`bind_addr`](Self::bind_addr)), which is a localhost-only listener
    /// used for the internal WebSocket bridge.
    ///
    /// Defaults to [`DEFAULT_HTTP_BIND_ADDR`] (`0.0.0.0:8443`) if not specified.
    #[must_use]
    pub const fn http_bind_addr(mut self, addr: SocketAddr) -> Self {
        self.http_bind_addr = Some(addr);
        self
    }

    /// Sets the allowed CORS origins for public endpoints.
    ///
    /// Public endpoints (`.well-known/scp`, broadcast projection feeds and
    /// messages) include `Access-Control-Allow-Origin` headers so that
    /// browser-based JavaScript and WASM clients can read responses
    /// cross-origin.
    ///
    /// - If not called, or called with an empty list: permissive CORS
    ///   (`Access-Control-Allow-Origin: *`). This is the default because
    ///   broadcast content is public by design (spec section 18.11.6).
    /// - If called with a non-empty list: restricts to exactly those
    ///   origins (e.g., `["https://example.com"]`).
    ///
    /// CORS is NOT applied to the WebSocket relay endpoint (`/scp/v1`)
    /// because WebSocket upgrades have their own origin mechanism, nor to
    /// the dev API (localhost-only).
    ///
    /// See issue #231.
    #[must_use]
    pub fn cors_origins(mut self, origins: Vec<String>) -> Self {
        self.cors_origins = if origins.is_empty() {
            None
        } else {
            Some(origins)
        };
        self
    }

    /// Sets the per-IP rate limit for broadcast projection endpoints.
    ///
    /// Controls the maximum number of requests per second from a single IP
    /// address to the `/scp/broadcast/*` endpoints. Exceeding this rate
    /// returns HTTP 429 Too Many Requests.
    ///
    /// Default: 60 req/s. Also configurable via `SCP_NODE_PROJECTION_RATE_LIMIT`.
    ///
    /// See spec section 18.11.6.
    #[must_use]
    pub const fn projection_rate_limit(mut self, rate: u32) -> Self {
        self.projection_rate_limit = Some(rate);
        self
    }

    /// Configures HTTP/3 support for the node (spec §10.15.1).
    ///
    /// When set, the node starts an HTTP/3 listener on a QUIC endpoint
    /// alongside the HTTP/1.1+HTTP/2 listener. All HTTP/1.1 and HTTP/2
    /// responses will include an `Alt-Svc` header advertising the HTTP/3
    /// endpoint.
    ///
    /// Requires the `http3` feature flag.
    #[cfg(feature = "http3")]
    #[must_use]
    pub fn http3(mut self, config: scp_transport::http3::Http3Config) -> Self {
        self.http3_config = Some(config);
        self
    }
}

impl<K: KeyCustody + 'static, D: DidMethod + 'static, Dom, Id>
    ApplicationNodeBuilder<K, D, NoOpStorage, Dom, Id>
{
    /// Sets an explicit storage backend.
    ///
    /// If not called, `.build()` uses a default no-op storage.
    pub fn storage<S2: Storage + 'static>(
        self,
        storage: S2,
    ) -> ApplicationNodeBuilder<K, D, S2, Dom, Id> {
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
            port_mapper: self.port_mapper,
            reachability_probe: self.reachability_probe,
            tls_provider: self.tls_provider,
            network_detector: self.network_detector,
            local_api_addr: self.local_api_addr,
            http_bind_addr: self.http_bind_addr,
            cors_origins: self.cors_origins,
            projection_rate_limit: self.projection_rate_limit,
            #[cfg(feature = "http3")]
            http3_config: self.http3_config,
            persist_identity: self.persist_identity,
            dns_provider_config: self.dns_provider_config,
            _domain_state: PhantomData,
            _identity_state: PhantomData,
        }
    }
}

impl<K: KeyCustody + 'static, D: DidMethod + 'static, S: Storage + 'static, Dom, Id>
    ApplicationNodeBuilder<K, D, S, Dom, Id>
{
    /// Sets a custom blob storage backend for the relay server.
    ///
    /// If not called, the relay uses in-memory storage (all blobs lost on restart).
    /// Accepts any type that converts into [`BlobStorageBackend`].
    #[must_use]
    pub fn blob_storage(mut self, blob_storage: impl Into<BlobStorageBackend>) -> Self {
        self.blob_storage = Some(blob_storage.into());
        self
    }
}

impl<S: Storage + 'static, Dom>
    ApplicationNodeBuilder<NoOpCustody, NoOpDidMethod, S, Dom, NoIdentity>
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
    ) -> ApplicationNodeBuilder<NoOpCustody, D2, S, Dom, HasIdentity> {
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
            port_mapper: self.port_mapper,
            reachability_probe: self.reachability_probe,
            tls_provider: self.tls_provider,
            network_detector: self.network_detector,
            local_api_addr: self.local_api_addr,
            http_bind_addr: self.http_bind_addr,
            cors_origins: self.cors_origins,
            projection_rate_limit: self.projection_rate_limit,
            #[cfg(feature = "http3")]
            http3_config: self.http3_config,
            persist_identity: self.persist_identity,
            dns_provider_config: self.dns_provider_config,
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
    ) -> ApplicationNodeBuilder<K2, D2, S, Dom, HasIdentity> {
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
            port_mapper: self.port_mapper,
            reachability_probe: self.reachability_probe,
            tls_provider: self.tls_provider,
            network_detector: self.network_detector,
            local_api_addr: self.local_api_addr,
            http_bind_addr: self.http_bind_addr,
            cors_origins: self.cors_origins,
            projection_rate_limit: self.projection_rate_limit,
            #[cfg(feature = "http3")]
            http3_config: self.http3_config,
            persist_identity: self.persist_identity,
            dns_provider_config: self.dns_provider_config,
            _domain_state: PhantomData,
            _identity_state: PhantomData,
        }
    }

    /// Configures the builder to automatically persist and reload identity.
    ///
    /// This is the recommended way to manage identity for long-lived
    /// applications. On the first run it behaves like
    /// [`generate_identity_with`](Self::generate_identity_with): it creates a
    /// new DID via the provided `key_custody` and `did_method`, then persists
    /// the resulting [`ScpIdentity`] and [`DidDocument`] to the builder's
    /// storage backend under the key `"scp/identity"`.
    ///
    /// On subsequent runs with the same storage backend, the persisted
    /// identity is deserialized and reused — no new DID is created. This
    /// ensures the node keeps the same DID across restarts.
    ///
    /// # Lifecycle
    ///
    /// 1. At `.build()` time, check storage for key `"scp/identity"`.
    /// 2. **Found:** Deserialize the stored [`ScpIdentity`] and
    ///    [`DidDocument`], use the `.identity()` path internally.
    /// 3. **Not found:** Call `did_method.create(custody)`, persist the
    ///    result to storage, then continue.
    ///
    /// `KeyHandle` indices remain valid across restarts because the custody
    /// backend (e.g., `FileKeyCustody`) reloads the same keyring from disk.
    ///
    /// # Requirements
    ///
    /// A real storage backend must be set via [`.storage()`](Self::storage)
    /// before calling `.build()`. The default no-op storage will not persist
    /// anything.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use std::sync::Arc;
    /// # use scp_node::ApplicationNodeBuilder;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// // let custody = Arc::new(FileKeyCustody::open("keys.db")?);
    /// // let did_method = Arc::new(DidDht::new(...));
    /// // let storage = SqliteStorage::open("node.db")?;
    /// //
    /// // let node = ApplicationNodeBuilder::new()
    /// //     .storage(storage)
    /// //     .domain("example.com")
    /// //     .identity_with_storage(custody, did_method)
    /// //     .build()
    /// //     .await?;
    /// // // First run: creates new DID, persists to storage.
    /// // // Subsequent runs: reloads same DID from storage.
    /// # Ok(())
    /// # }
    /// ```
    pub fn identity_with_storage<K2: KeyCustody + 'static, D2: DidMethod + 'static>(
        self,
        key_custody: Arc<K2>,
        did_method: Arc<D2>,
    ) -> ApplicationNodeBuilder<K2, D2, S, Dom, HasIdentity> {
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
            port_mapper: self.port_mapper,
            reachability_probe: self.reachability_probe,
            tls_provider: self.tls_provider,
            network_detector: self.network_detector,
            local_api_addr: self.local_api_addr,
            http_bind_addr: self.http_bind_addr,
            cors_origins: self.cors_origins,
            projection_rate_limit: self.projection_rate_limit,
            #[cfg(feature = "http3")]
            http3_config: self.http3_config,
            persist_identity: true,
            dns_provider_config: self.dns_provider_config,
            _domain_state: PhantomData,
            _identity_state: PhantomData,
        }
    }
}

impl<K: KeyCustody + 'static, D: DidMethod + 'static, S: EncryptedStorage + 'static>
    ApplicationNodeBuilder<K, D, S, HasDomain, HasIdentity>
{
    /// Builds the [`ApplicationNode`].
    ///
    /// Requires `S: EncryptedStorage` — compile-time enforcement that
    /// the storage backend encrypts data at rest. For testing with
    /// unencrypted backends, use [`build_for_testing`](Self::build_for_testing).
    ///
    /// See issue #695.
    ///
    /// # Errors
    ///
    /// Returns [`NodeError`] if storage, identity, relay, or TLS setup fails.
    pub async fn build(mut self) -> Result<ApplicationNode<S>, NodeError> {
        let storage = self
            .storage
            .take()
            .ok_or(NodeError::MissingField("storage"))?;
        let protocol_repository = Arc::new(ProtocolRepository::new(storage));
        self.build_with_store(protocol_repository).await
    }
}

/// Testing variant of `build()` — accepts any `Storage` backend.
#[cfg(any(test, feature = "allow_unencrypted_storage"))]
impl<K: KeyCustody + 'static, D: DidMethod + 'static, S: Storage + 'static>
    ApplicationNodeBuilder<K, D, S, HasDomain, HasIdentity>
{
    /// Builds the [`ApplicationNode`] without requiring encrypted storage.
    ///
    /// **Testing only.** Production code must use [`build`](Self::build).
    ///
    /// # Errors
    ///
    /// Returns [`NodeError`] if storage, identity, relay, or TLS setup fails.
    pub async fn build_for_testing(mut self) -> Result<ApplicationNode<S>, NodeError> {
        let storage = self
            .storage
            .take()
            .ok_or(NodeError::MissingField("storage"))?;
        let protocol_repository = Arc::new(ProtocolRepository::new_for_testing(storage));
        self.build_with_store(protocol_repository).await
    }
}

impl<K: KeyCustody + 'static, D: DidMethod + 'static, S: Storage + 'static>
    ApplicationNodeBuilder<K, D, S, HasDomain, HasIdentity>
{
    /// Shared build logic after `ProtocolRepository` has been constructed.
    #[allow(clippy::too_many_lines)] // builder with many config steps
    async fn build_with_store(
        self,
        protocol_repository: Arc<ProtocolRepository<S>>,
    ) -> Result<ApplicationNode<S>, NodeError> {
        let mut domain = self.domain.ok_or(NodeError::MissingField("domain"))?;
        let identity_source = self
            .identity_source
            .ok_or(NodeError::MissingField("identity"))?;
        let persist = self.persist_identity;

        let (identity, document, did_method) =
            resolve_identity_persistent(identity_source, persist, protocol_repository.storage())
                .await?;

        // If DNS provider config is set, derive the subdomain from the DID
        // and create the ScpDnsProvider as the TLS provider (#642).
        let tls_provider_override = if let Some(dns_config) = self.dns_provider_config {
            let (provider, dns_domain) = dns_config.build(&identity.did);
            tracing::info!(
                did = %identity.did,
                dns_domain = %dns_domain,
                node_id = %provider.node_id(),
                "using DNS subdomain provider for zero-config TLS"
            );
            domain = dns_domain;
            Some(Arc::new(provider) as Arc<dyn TlsProvider>)
        } else {
            None
        };

        let bridge_secret = generate_bridge_secret();
        let bind_addr = self
            .bind_addr
            .unwrap_or_else(|| SocketAddr::from(([127, 0, 0, 1], 0)));
        let relay_config = RelayConfig {
            bind_addr,
            bridge_secret: Some(*bridge_secret),
            ..RelayConfig::default()
        };

        let blob_storage = Arc::new(
            self.blob_storage
                .ok_or(NodeError::MissingField("blob_storage"))?,
        );
        let relay_server = RelayServer::new(relay_config.clone(), Arc::clone(&blob_storage));
        let connection_tracker = relay_server.connection_tracker();
        let subscription_registry = relay_server.subscriptions();
        let (shutdown_handle, bound_addr) = relay_server.start().await?;
        let dev_token = self.local_api_addr.map(generate_dev_token);
        let http_bind_addr = self.http_bind_addr.unwrap_or(DEFAULT_HTTP_BIND_ADDR);

        let tls_provider = resolve_tls(
            tls_provider_override.or(self.tls_provider),
            &domain,
            &protocol_repository,
            self.acme_email.as_ref(),
        );

        let (provision_result, acme_challenges) =
            provision_with_challenge_listener(&*tls_provider).await?;
        let rate_limit = self
            .projection_rate_limit
            .unwrap_or(DEFAULT_PROJECTION_RATE_LIMIT);

        match provision_result {
            Ok(cert_data) => {
                build_domain_inner(
                    domain,
                    identity,
                    document,
                    did_method,
                    protocol_repository,
                    shutdown_handle,
                    bound_addr,
                    bridge_secret,
                    dev_token,
                    self.local_api_addr,
                    blob_storage,
                    relay_config,
                    http_bind_addr,
                    self.cors_origins.clone(),
                    rate_limit,
                    cert_data,
                    connection_tracker.clone(),
                    subscription_registry.clone(),
                    acme_challenges,
                    #[cfg(feature = "http3")]
                    self.http3_config,
                )
                .await
            }
            Err(tls_err) => {
                tracing::warn!(
                    domain = %domain, error = %tls_err,
                    "TLS provisioning failed, falling through to NAT-traversed mode (§10.12.8)"
                );
                let strategy = resolve_nat(
                    self.nat_strategy,
                    self.stun_server,
                    self.bridge_relay,
                    self.port_mapper,
                    self.reachability_probe,
                );
                build_no_domain_inner(
                    identity,
                    document,
                    did_method,
                    protocol_repository,
                    shutdown_handle,
                    bound_addr,
                    strategy,
                    bridge_secret,
                    dev_token,
                    self.local_api_addr,
                    blob_storage,
                    relay_config,
                    Some(http_bind_addr),
                    self.cors_origins,
                    rate_limit,
                    self.network_detector,
                    connection_tracker,
                    subscription_registry,
                )
                .await
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Bridge secret generation
// ---------------------------------------------------------------------------

/// Resolves the identity from an [`IdentitySource`], returning the identity,
/// document, and DID method.
async fn resolve_identity<K: KeyCustody, D: DidMethod>(
    source: IdentitySource<K, D>,
) -> Result<(ScpIdentity, DidDocument, Arc<D>), NodeError> {
    match source {
        IdentitySource::Generate {
            key_custody,
            did_method,
        } => {
            let (identity, document) = did_method.create(&*key_custody).await?;
            Ok((identity, document, did_method))
        }
        IdentitySource::Explicit(e) => Ok((e.identity, e.document, e.did_method)),
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
async fn resolve_identity_persistent<K: KeyCustody, D: DidMethod, S: Storage>(
    source: IdentitySource<K, D>,
    persist: bool,
    storage: &S,
) -> Result<(ScpIdentity, DidDocument, Arc<D>), NodeError> {
    if !persist {
        return resolve_identity(source).await;
    }

    match source {
        IdentitySource::Generate {
            key_custody,
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
                validate_persisted_custody(&persisted, &*key_custody).await?;

                tracing::info!(
                    did = %persisted.identity.did,
                    "reloaded persisted identity from storage"
                );
                Ok((persisted.identity, persisted.document, did_method))
            } else {
                // 3. Generate a new identity and persist it.
                let (identity, document) = did_method.create(&*key_custody).await?;
                let persisted = PersistedIdentity {
                    identity: identity.clone(),
                    document: document.clone(),
                };
                let envelope = StoredValue {
                    version: CURRENT_STORE_VERSION,
                    data: &persisted,
                };
                let bytes = rmp_serde::to_vec_named(&envelope).map_err(|e| {
                    NodeError::Storage(format!("failed to serialize identity for persistence: {e}"))
                })?;
                storage
                    .store(IDENTITY_STORAGE_KEY, &bytes)
                    .await
                    .map_err(|e| {
                        NodeError::Storage(format!("failed to persist identity to storage: {e}"))
                    })?;
                tracing::info!(
                    did = %identity.did,
                    "created and persisted new identity to storage"
                );
                Ok((identity, document, did_method))
            }
        }
        // Explicit identities are never persisted — caller already manages them.
        IdentitySource::Explicit(e) => Ok((e.identity, e.document, e.did_method)),
    }
}

/// Generates a 32-byte bridge secret using `OsRng`.
///
/// Wrapped in `Zeroizing` so the secret is zeroed on drop.
fn generate_bridge_secret() -> Zeroizing<[u8; 32]> {
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
async fn provision_with_challenge_listener(
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
fn resolve_nat(
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
async fn build_domain_inner<D: DidMethod + 'static, S: Storage + 'static>(
    domain: String,
    identity: ScpIdentity,
    mut document: DidDocument,
    did_method: Arc<D>,
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
    acme_challenges: Option<Arc<tokio::sync::RwLock<std::collections::HashMap<String, String>>>>,
    #[cfg(feature = "http3")] http3_config: Option<scp_transport::http3::Http3Config>,
) -> Result<ApplicationNode<S>, NodeError> {
    let relay_url = format!("wss://{domain}/scp/v1");
    document.add_relay_service(&relay_url)?;
    did_method.publish(&identity, &document).await?;

    // Build the rustls ServerConfig from the provisioned certificate.
    // Uses the reloadable config so that ACME renewal can hot-swap certs
    // without restarting the server (spec section 18.6.3).
    let (tls_server_config, cert_resolver) =
        tls::build_reloadable_tls_config(&cert_data).map_err(NodeError::Tls)?;

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
        bridge_state: Arc::new(crate::bridge_handlers::BridgeState::new()),
        bridge_lookup: Some(bridge_lookup),
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
    })
}

// ---------------------------------------------------------------------------
// Shared no-domain build logic (used by HasNoDomain::build and domain fallthrough)
// ---------------------------------------------------------------------------

// Node builder internal: all parameters are required for server construction.
#[allow(clippy::too_many_arguments)]
async fn build_no_domain_inner<D: DidMethod + 'static, S: Storage + 'static>(
    identity: ScpIdentity,
    mut document: DidDocument,
    did_method: Arc<D>,
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
) -> Result<ApplicationNode<S>, NodeError> {
    // Resolve the HTTP bind address first — NAT strategy needs the public-facing
    // HTTP port, not the internal relay port (which is bound to loopback and
    // unreachable externally). UPnP maps this port on the router and the relay
    // URL uses it. See #641.
    let http_bind_addr = http_bind_addr.unwrap_or(DEFAULT_HTTP_BIND_ADDR);

    let tier = nat_strategy.select_tier(http_bind_addr.port()).await?;

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

    // 5. Spawn periodic tier re-evaluation (§10.12.1, SCP-243).
    let publisher: Arc<dyn DidPublisher> = Arc::new(DidMethodPublisher {
        inner: Arc::clone(&did_method),
    });
    let (tier_event_tx, tier_event_rx) = tokio::sync::mpsc::channel(16);
    // Construct a copy of the identity for the background task (ScpIdentity
    // fields are all Copy/Clone but the struct itself doesn't derive Clone).
    let bg_identity = ScpIdentity {
        identity_key: identity.identity_key,
        active_signing_key: identity.active_signing_key,
        agent_signing_key: identity.agent_signing_key,
        pre_rotation_commitment: identity.pre_rotation_commitment,
        did: identity.did.clone(),
    };
    let tier_reeval = spawn_tier_reevaluation(
        nat_strategy,
        network_detector,
        publisher,
        bg_identity,
        document.clone(),
        http_bind_addr.port(),
        relay_url.clone(),
        Some(tier_event_tx),
        TIER_REEVALUATION_INTERVAL,
    );

    // Build the production bridge auth lookup, hydrating from storage.
    // In no-domain mode the audience is the relay URL itself (spec 12.10.2).
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
        bridge_state: Arc::new(crate::bridge_handlers::BridgeState::new()),
        bridge_lookup: Some(bridge_lookup),
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
        tier_reeval: Some(tier_reeval),
        tier_change_rx: Some(tier_event_rx),
        // HTTP/3 is not supported in no-domain mode (no TLS certificate).
        #[cfg(feature = "http3")]
        http3_config: None,
    })
}

// ---------------------------------------------------------------------------
// Build for HasNoDomain — zero-config NAT-traversed mode (§10.12.8)
// ---------------------------------------------------------------------------

impl<K: KeyCustody + 'static, D: DidMethod + 'static, S: EncryptedStorage + 'static>
    ApplicationNodeBuilder<K, D, S, HasNoDomain, HasIdentity>
{
    /// Builds the [`ApplicationNode`] in zero-config no-domain mode (§10.12.8).
    ///
    /// Requires `S: EncryptedStorage`. For testing, use
    /// [`build_for_testing`](Self::build_for_testing).
    ///
    /// # Errors
    ///
    /// Returns [`NodeError`] if storage, identity, relay, or NAT setup fails.
    pub async fn build(mut self) -> Result<ApplicationNode<S>, NodeError> {
        let storage = self
            .storage
            .take()
            .ok_or(NodeError::MissingField("storage"))?;
        let protocol_repository = Arc::new(ProtocolRepository::new(storage));
        self.build_with_store(protocol_repository).await
    }
}

/// Testing variant of no-domain `build()`.
#[cfg(any(test, feature = "allow_unencrypted_storage"))]
impl<K: KeyCustody + 'static, D: DidMethod + 'static, S: Storage + 'static>
    ApplicationNodeBuilder<K, D, S, HasNoDomain, HasIdentity>
{
    /// Builds the [`ApplicationNode`] in no-domain mode without requiring
    /// encrypted storage. **Testing only.**
    ///
    /// # Errors
    ///
    /// Returns [`NodeError`] if storage, identity, relay, or NAT setup fails.
    pub async fn build_for_testing(mut self) -> Result<ApplicationNode<S>, NodeError> {
        let storage = self
            .storage
            .take()
            .ok_or(NodeError::MissingField("storage"))?;
        let protocol_repository = Arc::new(ProtocolRepository::new_for_testing(storage));
        self.build_with_store(protocol_repository).await
    }
}

impl<K: KeyCustody + 'static, D: DidMethod + 'static, S: Storage + 'static>
    ApplicationNodeBuilder<K, D, S, HasNoDomain, HasIdentity>
{
    /// Shared build logic for no-domain mode after `ProtocolRepository` creation.
    async fn build_with_store(
        self,
        protocol_repository: Arc<ProtocolRepository<S>>,
    ) -> Result<ApplicationNode<S>, NodeError> {
        let identity_source = self
            .identity_source
            .ok_or(NodeError::MissingField("identity"))?;
        let persist = self.persist_identity;

        let (identity, document, did_method) =
            resolve_identity_persistent(identity_source, persist, protocol_repository.storage())
                .await?;

        // 3. Start relay server.
        let bind_addr = self
            .bind_addr
            .unwrap_or_else(|| SocketAddr::from(([127, 0, 0, 1], 0)));
        let bridge_secret = generate_bridge_secret();
        let relay_config = RelayConfig {
            bind_addr,
            bridge_secret: Some(*bridge_secret),
            ..RelayConfig::default()
        };

        let blob_storage = Arc::new(
            self.blob_storage
                .ok_or(NodeError::MissingField("blob_storage"))?,
        );
        let relay_server = RelayServer::new(relay_config.clone(), Arc::clone(&blob_storage));
        let connection_tracker = relay_server.connection_tracker();
        let subscription_registry = relay_server.subscriptions();
        let (shutdown_handle, bound_addr) = relay_server.start().await?;

        // 4. Generate dev API token if local_api was configured.
        let dev_token = self.local_api_addr.map(generate_dev_token);

        // 5-8. Delegate to shared no-domain logic.
        let strategy = resolve_nat(
            self.nat_strategy,
            self.stun_server,
            self.bridge_relay,
            self.port_mapper,
            self.reachability_probe,
        );

        build_no_domain_inner(
            identity,
            document,
            did_method,
            protocol_repository,
            shutdown_handle,
            bound_addr,
            strategy,
            bridge_secret,
            dev_token,
            self.local_api_addr,
            blob_storage,
            relay_config,
            self.http_bind_addr,
            self.cors_origins,
            self.projection_rate_limit
                .unwrap_or(DEFAULT_PROJECTION_RATE_LIMIT),
            self.network_detector,
            connection_tracker,
            subscription_registry,
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
        HasDomain,
        HasIdentity,
    > {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let did_method = Arc::new(make_test_dht(&custody));
        ApplicationNodeBuilder::new()
            .storage(InMemoryStorage::new())
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
            .build_for_testing()
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
            .storage(InMemoryStorage::new())
            .domain("explicit.example.com")
            .tls_provider(Arc::new(SucceedingTlsProvider {
                domain: "explicit.example.com".to_owned(),
            }))
            .identity(identity, document, did_method)
            .bind_addr(SocketAddr::from(([127, 0, 0, 1], 0)))
            .build_for_testing()
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
            .storage(InMemoryStorage::new())
            .domain("counting.example.com")
            .tls_provider(Arc::new(SucceedingTlsProvider {
                domain: "counting.example.com".to_owned(),
            }))
            .generate_identity_with(custody, counting_method)
            .bind_addr(SocketAddr::from(([127, 0, 0, 1], 0)))
            .build_for_testing()
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

        let node = test_builder()
            .bind_addr(SocketAddr::from(([127, 0, 0, 1], 0)))
            .build_for_testing()
            .await
            .unwrap();

        let addr = node.relay().bound_addr();
        let token = node.bridge_token_hex();

        // Connect with the bridge token in the Authorization header (#225).
        let url = format!("ws://{addr}/");
        let mut request = url.into_client_request().unwrap();
        request
            .headers_mut()
            .insert("Authorization", format!("Bearer {token}").parse().unwrap());
        let connect_result = tokio_tungstenite::connect_async(request).await;

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
            .build_for_testing()
            .await
            .unwrap();

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
            .storage(InMemoryStorage::new())
            .domain("relay-order.example.com")
            .tls_provider(Arc::new(SucceedingTlsProvider {
                domain: "relay-order.example.com".to_owned(),
            }))
            .generate_identity_with(custody, check_method)
            .bind_addr(bind_addr)
            .build_for_testing()
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
            .build_for_testing()
            .await
            .unwrap();

        assert_eq!(node.relay_url(), "wss://test.example.com/scp/v1");
    }

    #[tokio::test]
    async fn builder_with_custom_storage() {
        let custom_storage = InMemoryStorage::new();
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
            .build_for_testing()
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
            .build_for_testing()
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
        HasNoDomain,
        HasIdentity,
    > {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let did_method = Arc::new(make_test_dht(&custody));
        ApplicationNodeBuilder::new()
            .storage(InMemoryStorage::new())
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
            .build_for_testing()
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
            .build_for_testing()
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
            .build_for_testing()
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
            .build_for_testing()
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
            .build_for_testing()
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

        let node = ApplicationNodeBuilder::new()
            .storage(InMemoryStorage::new())
            .domain("fail.example.com")
            .tls_provider(Arc::new(FailingTlsProvider))
            .nat_strategy(Arc::new(RecordingNatStrategy {
                called: Arc::clone(&nat_called),
                received_port: Arc::clone(&nat_port),
                tier: ReachabilityTier::Stun { external_addr },
            }))
            .generate_identity_with(custody, did_method)
            .bind_addr(SocketAddr::from(([127, 0, 0, 1], 0)))
            .build_for_testing()
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

        let result = ApplicationNodeBuilder::new()
            .storage(InMemoryStorage::new())
            .no_domain()
            .nat_strategy(Arc::new(FailingNatStrategy))
            .generate_identity_with(custody, did_method)
            .bind_addr(SocketAddr::from(([127, 0, 0, 1], 0)))
            .build_for_testing()
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
            .storage(InMemoryStorage::new())
            .no_domain()
            .nat_strategy(Arc::new(MockNatStrategy { tier }))
            .generate_identity_with(custody, counting_method)
            .bind_addr(SocketAddr::from(([127, 0, 0, 1], 0)))
            .build_for_testing()
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
                    ttl: std::time::Duration::from_secs(600),
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
            test_builder()
                .bind_addr(SocketAddr::from(([127, 0, 0, 1], 0)))
                .build_for_testing()
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
            service: vec![scp_identity::document::Service {
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
            service: vec![scp_identity::document::Service {
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
            Duration::from_secs(60 * 60),
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
            service: vec![scp_identity::document::Service {
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
            service: vec![scp_identity::document::Service {
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

        let node = test_no_domain_builder(tier)
            .bind_addr(SocketAddr::from(([127, 0, 0, 1], 0)))
            .build_for_testing()
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
        let node = test_builder()
            .bind_addr(SocketAddr::from(([127, 0, 0, 1], 0)))
            .build_for_testing()
            .await
            .unwrap();

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

        let node = ApplicationNodeBuilder::new()
            .storage(Arc::clone(&storage))
            .domain("persist.example.com")
            .tls_provider(Arc::new(SucceedingTlsProvider {
                domain: "persist.example.com".to_owned(),
            }))
            .identity_with_storage(custody, did_method)
            .bind_addr(SocketAddr::from(([127, 0, 0, 1], 0)))
            .build_for_testing()
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
    async fn identity_with_storage_reloads_on_subsequent_run() {
        // First run: create identity and persist.
        let storage = Arc::new(InMemoryStorage::new());
        let custody = Arc::new(InMemoryKeyCustody::new());
        let did_method = Arc::new(make_test_dht(&custody));

        let node1 = ApplicationNodeBuilder::new()
            .storage(Arc::clone(&storage))
            .domain("reload.example.com")
            .tls_provider(Arc::new(SucceedingTlsProvider {
                domain: "reload.example.com".to_owned(),
            }))
            .identity_with_storage(Arc::clone(&custody), Arc::clone(&did_method))
            .bind_addr(SocketAddr::from(([127, 0, 0, 1], 0)))
            .build_for_testing()
            .await
            .unwrap();

        let first_did = node1.identity().did().to_owned();
        node1.shutdown();

        // Second run: same storage → should reload the same DID (no new creation).
        let node2 = ApplicationNodeBuilder::new()
            .storage(Arc::clone(&storage))
            .domain("reload.example.com")
            .tls_provider(Arc::new(SucceedingTlsProvider {
                domain: "reload.example.com".to_owned(),
            }))
            .identity_with_storage(custody, did_method)
            .bind_addr(SocketAddr::from(([127, 0, 0, 1], 0)))
            .build_for_testing()
            .await
            .unwrap();

        assert_eq!(
            node2.identity().did(),
            first_did,
            "second run should produce the same DID"
        );

        node2.shutdown();
    }

    #[tokio::test]
    async fn identity_with_storage_rejects_mismatched_custody() {
        // First run: create identity with one custody instance.
        let storage = Arc::new(InMemoryStorage::new());
        let custody1 = Arc::new(InMemoryKeyCustody::new());
        let did_method = Arc::new(make_test_dht(&custody1));

        let node1 = ApplicationNodeBuilder::new()
            .storage(Arc::clone(&storage))
            .domain("mismatch.example.com")
            .tls_provider(Arc::new(SucceedingTlsProvider {
                domain: "mismatch.example.com".to_owned(),
            }))
            .identity_with_storage(custody1, Arc::clone(&did_method))
            .bind_addr(SocketAddr::from(([127, 0, 0, 1], 0)))
            .build_for_testing()
            .await
            .unwrap();

        node1.shutdown();

        // Second run: fresh custody with NO keys → should fail validation.
        let custody2 = Arc::new(InMemoryKeyCustody::new());
        let did_method2 = Arc::new(make_test_dht(&custody2));

        let result = ApplicationNodeBuilder::new()
            .storage(Arc::clone(&storage))
            .domain("mismatch.example.com")
            .tls_provider(Arc::new(SucceedingTlsProvider {
                domain: "mismatch.example.com".to_owned(),
            }))
            .identity_with_storage(custody2, did_method2)
            .bind_addr(SocketAddr::from(([127, 0, 0, 1], 0)))
            .build_for_testing()
            .await;

        let err = result
            .err()
            .expect("build should fail with mismatched custody");
        let msg = err.to_string();
        assert!(
            msg.contains("not found in custody"),
            "expected custody validation error, got: {msg}"
        );
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

        let result = ApplicationNodeBuilder::new()
            .storage(Arc::clone(&storage))
            .domain("future-ver.example.com")
            .tls_provider(Arc::new(SucceedingTlsProvider {
                domain: "future-ver.example.com".to_owned(),
            }))
            .identity_with_storage(custody, did_method)
            .bind_addr(SocketAddr::from(([127, 0, 0, 1], 0)))
            .build_for_testing()
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

        let node = ApplicationNodeBuilder::new()
            .storage(Arc::clone(&storage))
            .domain("nopersist.example.com")
            .tls_provider(Arc::new(SucceedingTlsProvider {
                domain: "nopersist.example.com".to_owned(),
            }))
            .generate_identity_with(custody, did_method)
            .bind_addr(SocketAddr::from(([127, 0, 0, 1], 0)))
            .build_for_testing()
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
        let node = ApplicationNodeBuilder::new()
            .storage(Arc::clone(&storage))
            .no_domain()
            .nat_strategy(Arc::new(MockNatStrategy { tier: tier.clone() }))
            .identity_with_storage(Arc::clone(&custody), Arc::clone(&did_method))
            .bind_addr(SocketAddr::from(([127, 0, 0, 1], 0)))
            .build_for_testing()
            .await
            .unwrap();

        let first_did = node.identity().did().to_owned();
        node.shutdown();

        // Second run: same storage → same DID.
        let node2 = ApplicationNodeBuilder::new()
            .storage(Arc::clone(&storage))
            .no_domain()
            .nat_strategy(Arc::new(MockNatStrategy { tier }))
            .identity_with_storage(custody, did_method)
            .bind_addr(SocketAddr::from(([127, 0, 0, 1], 0)))
            .build_for_testing()
            .await
            .unwrap();

        assert_eq!(
            node2.identity().did(),
            first_did,
            "no-domain mode should also reload persisted identity"
        );

        node2.shutdown();
    }
}
