//! Application node for SCP deployments.
//!
//! `scp-node` provides [`ApplicationNode`], a concrete SDK type that composes
//! an SCP relay, an identity, and storage into a single deployable unit. It is
//! the "one box" deployment pattern -- relay + participant + storage on one
//! machine.
//!
//! See spec section 18.6 and ADR-032 in `.docs/adrs/phase-2.md`.

#![forbid(unsafe_code)]

use std::net::SocketAddr;
use std::sync::Arc;

use scp_core::identity::document::DidDocument;
use scp_core::identity::{DidMethod, IdentityError, ScpIdentity};
use scp_platform::traits::{KeyCustody, Storage};
use scp_transport::native::server::{RelayConfig, RelayError, RelayServer};
use scp_transport::native::storage::InMemoryBlobStorage;

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
}

// ---------------------------------------------------------------------------
// RelayHandle
// ---------------------------------------------------------------------------

/// Handle to the running relay server.
///
/// Wraps the bound address and provides access to the relay's state. The relay
/// accepts connections from any SCP client (spec section 18.6.4).
#[derive(Debug)]
pub struct RelayHandle {
    /// The local address the relay is bound to.
    bound_addr: SocketAddr,
}

impl RelayHandle {
    /// Returns the local address the relay server is bound to.
    #[must_use]
    pub const fn bound_addr(&self) -> SocketAddr {
        self.bound_addr
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
}

impl<S: Storage + std::fmt::Debug> std::fmt::Debug for ApplicationNode<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApplicationNode")
            .field("domain", &self.domain)
            .field("relay", &self.relay)
            .field("identity", &self.identity)
            .field("storage", &"<Storage>")
            .finish()
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
}

/// Returns a new [`ApplicationNodeBuilder`].
///
/// Convenience function equivalent to `ApplicationNodeBuilder::new()`.
#[must_use]
pub const fn builder() -> ApplicationNodeBuilder {
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
// ApplicationNodeBuilder
// ---------------------------------------------------------------------------

/// Builder for [`ApplicationNode`].
///
/// Follows the Rust builder pattern with `Option` fields and validation on
/// `.build()`. The domain is required; all other fields have defaults or are
/// optional.
///
/// # Required fields
///
/// - [`domain`](Self::domain) -- the domain this node serves.
///
/// # Identity
///
/// Either call [`generate_identity_with`](Self::generate_identity_with) to
/// create a new DID with explicit implementations, or
/// [`identity`](ApplicationNodeBuilder::identity) to use an existing one. If
/// neither is called, `.build()` returns [`NodeError::MissingField`].
pub struct ApplicationNodeBuilder<
    K: KeyCustody = NoOpCustody,
    D: DidMethod = NoOpDidMethod,
    S: Storage = NoOpStorage,
> {
    domain: Option<String>,
    identity_source: Option<IdentitySource<K, D>>,
    storage: Option<Arc<S>>,
    bind_addr: Option<SocketAddr>,
    acme_email: Option<String>,
}

impl ApplicationNodeBuilder {
    /// Creates a new builder with all fields unset.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            domain: None,
            identity_source: None,
            storage: None,
            bind_addr: None,
            acme_email: None,
        }
    }
}

impl Default for ApplicationNodeBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl<K: KeyCustody + 'static, D: DidMethod + 'static, S: Storage + 'static>
    ApplicationNodeBuilder<K, D, S>
{
    /// Sets the domain this node serves.
    ///
    /// The relay URL is derived as `wss://<domain>/scp/v1` (spec section
    /// 18.5.2). This field is required.
    #[must_use]
    pub fn domain(mut self, domain: &str) -> Self {
        self.domain = Some(domain.to_owned());
        self
    }

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

impl<K: KeyCustody + 'static, D: DidMethod + 'static> ApplicationNodeBuilder<K, D, NoOpStorage> {
    /// Sets an explicit storage backend.
    ///
    /// If not called, `.build()` uses a default no-op storage.
    pub fn storage<S2: Storage + 'static>(
        self,
        storage: Arc<S2>,
    ) -> ApplicationNodeBuilder<K, D, S2> {
        ApplicationNodeBuilder {
            domain: self.domain,
            identity_source: self.identity_source,
            storage: Some(storage),
            bind_addr: self.bind_addr,
            acme_email: self.acme_email,
        }
    }
}

impl<S: Storage + 'static> ApplicationNodeBuilder<NoOpCustody, NoOpDidMethod, S> {
    /// Sets an explicit identity and DID document to use.
    ///
    /// The identity will be published to the DHT with `SCPRelay` entries
    /// pointing to this node's relay URL.
    pub fn identity<D2: DidMethod + 'static>(
        self,
        identity: ScpIdentity,
        document: DidDocument,
        did_method: Arc<D2>,
    ) -> ApplicationNodeBuilder<NoOpCustody, D2, S> {
        ApplicationNodeBuilder {
            domain: self.domain,
            identity_source: Some(IdentitySource::Explicit(Box::new(ExplicitIdentity {
                identity,
                document,
                did_method,
            }))),
            storage: self.storage,
            bind_addr: self.bind_addr,
            acme_email: self.acme_email,
        }
    }

    /// Configures the builder to generate a new DID identity on `.build()`.
    ///
    /// Uses the provided key custody and DID method implementations.
    pub fn generate_identity_with<K2: KeyCustody + 'static, D2: DidMethod + 'static>(
        self,
        key_custody: Arc<K2>,
        did_method: Arc<D2>,
    ) -> ApplicationNodeBuilder<K2, D2, S> {
        ApplicationNodeBuilder {
            domain: self.domain,
            identity_source: Some(IdentitySource::Generate {
                key_custody,
                did_method,
            }),
            storage: self.storage,
            bind_addr: self.bind_addr,
            acme_email: self.acme_email,
        }
    }
}

impl<K: KeyCustody + 'static, D: DidMethod + 'static, S: Storage + Default + 'static>
    ApplicationNodeBuilder<K, D, S>
{
    /// Builds the [`ApplicationNode`].
    ///
    /// # Steps
    ///
    /// 1. Validates required fields (domain, identity source).
    /// 2. Initializes storage (uses provided or creates default).
    /// 3. Loads or generates identity.
    /// 4. Adds `SCPRelay` service entry to the DID document.
    /// 5. Starts relay server (must be listening before publication).
    /// 6. Publishes DID document to the DHT.
    ///
    /// DID publication happens once on `.build()`, not continuously
    /// (spec section 18.6.4).
    ///
    /// # Errors
    ///
    /// Returns [`NodeError::MissingField`] if domain or identity source is
    /// not configured. Returns [`NodeError::Identity`] if identity creation
    /// or DID publication fails. Returns [`NodeError::Relay`] if the relay
    /// server fails to start.
    pub async fn build(self) -> Result<ApplicationNode<S>, NodeError> {
        // 1. Validate required fields.
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

        let blob_storage = InMemoryBlobStorage::new();
        let relay_server = RelayServer::new(relay_config, blob_storage);
        let bound_addr = relay_server.start().await?;

        // 6. Publish DID document now that the relay is confirmed listening.
        did_method.publish(&identity, &document).await?;

        tracing::info!(
            domain = %domain,
            relay_url = %relay_url,
            bound_addr = %bound_addr,
            did = %identity.did,
            "application node started"
        );

        Ok(ApplicationNode {
            domain,
            relay: RelayHandle { bound_addr },
            identity: IdentityHandle { identity, document },
            storage,
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
    fn test_builder() -> ApplicationNodeBuilder<InMemoryKeyCustody, TestDidDht, InMemoryStorage> {
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

    #[tokio::test]
    async fn build_requires_domain() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let did_method = Arc::new(make_test_dht(&custody));

        let result = ApplicationNodeBuilder::new()
            .generate_identity_with(custody, did_method)
            .build()
            .await;

        let err = result.unwrap_err();
        match &err {
            NodeError::MissingField(field) => assert_eq!(*field, "domain"),
            other => panic!("expected MissingField(\"domain\"), got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn build_requires_identity_source() {
        let result = ApplicationNodeBuilder::new()
            .domain("test.example.com")
            .build()
            .await;

        let err = result.unwrap_err();
        match &err {
            NodeError::MissingField(field) => {
                assert!(
                    field.contains("identity"),
                    "expected identity missing, got: {field}"
                );
            }
            other => panic!("expected MissingField containing 'identity', got: {other:?}"),
        }
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
}
