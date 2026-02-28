//! Application node for SCP deployments.
//!
//! `scp-node` provides [`ApplicationNode`], a concrete SDK type that composes
//! an SCP relay, an identity, and storage into a single deployable unit. It is
//! the "one box" deployment pattern -- relay + participant + storage on one
//! machine.
//!
//! See spec section 18.6 and ADR-032 in `.docs/adrs/phase-2.md`.

#![forbid(unsafe_code)]

pub mod http;
pub mod tls;
mod well_known;

use std::marker::PhantomData;
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::sync::RwLock;

use scp_core::identity::document::DidDocument;
use scp_core::identity::{DidMethod, IdentityError, ScpIdentity};
use scp_platform::traits::{KeyCustody, Storage};
use scp_transport::native::server::{RelayConfig, RelayError, RelayServer, ShutdownHandle};
use scp_transport::native::storage::{BlobStorage, InMemoryBlobStorage};

pub use http::BroadcastContext;

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
pub struct ApplicationNode<S: Storage> {
    /// The domain this node serves.
    domain: String,
    /// Handle to the running relay server.
    relay: RelayHandle,
    /// Handle to the node's identity.
    identity: IdentityHandle,
    /// The storage backend.
    storage: Arc<S>,
    /// Shared state for HTTP handlers (`.well-known/scp`, relay bridge).
    state: Arc<http::NodeState>,
}

impl<S: Storage + std::fmt::Debug> std::fmt::Debug for ApplicationNode<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApplicationNode")
            .field("domain", &self.domain)
            .field("relay", &self.relay)
            .field("identity", &self.identity)
            .field("storage", &"<Storage>")
            .finish_non_exhaustive()
    }
}

impl<S: Storage> ApplicationNode<S> {
    /// Returns the domain this node serves.
    #[must_use]
    pub fn domain(&self) -> &str {
        &self.domain
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

    /// Returns the relay URL derived from the configured domain.
    ///
    /// Format: `wss://<domain>/scp/v1` (spec section 18.5.2).
    #[must_use]
    pub fn relay_url(&self) -> String {
        format!("wss://{}/scp/v1", self.domain)
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

    /// Gracefully shuts down the relay server.
    ///
    /// In-flight connection handlers drain naturally — they are not cancelled.
    pub fn shutdown(&self) {
        self.relay.shutdown_handle.shutdown();
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

/// Marker: identity has not been configured on the builder.
pub struct NoIdentity;
/// Marker: identity has been configured on the builder.
pub struct HasIdentity;

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
    // Intentional dead code: TLS provisioning is not yet implemented (ADR-032 AC 7).
    // This field is part of the builder API surface per SCP-145. It will be consumed
    // when TLS certificate provisioning is added.
    #[allow(dead_code)]
    acme_email: Option<String>,
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
    /// 18.5.2). This field is required — the builder cannot be built without it.
    #[must_use]
    pub fn domain(self, domain: &str) -> ApplicationNodeBuilder<K, D, S, B, HasDomain, Id> {
        ApplicationNodeBuilder {
            domain: Some(domain.to_owned()),
            identity_source: self.identity_source,
            storage: self.storage,
            blob_storage: self.blob_storage,
            bind_addr: self.bind_addr,
            acme_email: self.acme_email,
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
    pub async fn build(self) -> Result<ApplicationNode<S>, NodeError> {
        // Type-state guarantees domain and identity_source are set.
        // The runtime check is a defensive fallback — the type system
        // prevents reaching this code without both fields configured.
        let domain = self.domain.ok_or(NodeError::MissingField("domain"))?;

        let identity_source = self.identity_source.ok_or(NodeError::MissingField(
            "identity (call generate_identity_with() or identity())",
        ))?;

        // 2. Initialize storage.
        let storage = self.storage.unwrap_or_else(|| Arc::new(S::default()));

        // 3. Obtain identity.
        let relay_url = format!("wss://{domain}/scp/v1");

        let (identity, mut document, did_method) = match identity_source {
            IdentitySource::Generate {
                key_custody,
                did_method,
            } => {
                let (identity, document) = did_method.create(&*key_custody).await?;
                (identity, document, did_method)
            }
            IdentitySource::Explicit(explicit) => {
                (explicit.identity, explicit.document, explicit.did_method)
            }
        };

        // 4. Add SCPRelay service entry to the DID document (local-only, no network).
        document.add_relay_service(&relay_url)?;

        // 5. Start relay server — must be listening before we publish the DID
        //    so that clients resolving the DID can immediately connect.
        let bind_addr = self
            .bind_addr
            .unwrap_or_else(|| SocketAddr::from(([127, 0, 0, 1], 0)));

        let relay_config = RelayConfig {
            bind_addr,
            ..RelayConfig::default()
        };

        let blob_storage = self
            .blob_storage
            .ok_or(NodeError::MissingField("blob_storage"))?;
        let relay_server = RelayServer::new(relay_config, blob_storage);
        let (shutdown_handle, bound_addr) = relay_server.start().await?;

        // 6. Publish DID document now that the relay is confirmed listening.
        did_method.publish(&identity, &document).await?;

        tracing::info!(
            domain = %domain,
            relay_url = %relay_url,
            bound_addr = %bound_addr,
            did = %identity.did,
            "application node started"
        );

        let state = Arc::new(http::NodeState {
            did: identity.did.clone(),
            relay_url: relay_url.clone(),
            broadcast_contexts: RwLock::new(Vec::new()),
            relay_addr: bound_addr,
        });

        Ok(ApplicationNode {
            domain,
            relay: RelayHandle {
                bound_addr,
                shutdown_handle,
            },
            identity: IdentityHandle { identity, document },
            storage,
            state,
        })
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

    use scp_core::identity::DidCache;
    use scp_core::identity::cache::SystemClock;
    use scp_core::identity::dht::DidDht;
    use scp_core::identity::dht_client::InMemoryDhtClient;
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

    /// Helper: creates a builder with domain and `generate_identity` configured.
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
        assert_eq!(node.domain(), "test.example.com");
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
    async fn relay_accepts_connections_from_any_client() {
        let node = test_builder()
            .bind_addr(SocketAddr::from(([127, 0, 0, 1], 0)))
            .build()
            .await
            .unwrap();

        let addr = node.relay().bound_addr();

        // Connect as a plain WebSocket client (not the node's identity).
        let url = format!("ws://{addr}");
        let connect_result = tokio_tungstenite::connect_async(&url).await;

        assert!(
            connect_result.is_ok(),
            "relay should accept connections from any SCP client, got error: {:?}",
            connect_result.err()
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
