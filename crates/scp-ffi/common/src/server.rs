//! Shared relay and application node startup code for FFI bridges.
//!
//! Provides [`RunningRelay`] for standalone relay startup and
//! [`start_node_in_memory`] / [`start_node_local`] for full application node
//! startup. Both bind with sensible defaults and expose bound addresses for
//! FFI consumers. All functions bind to `127.0.0.1:0` (OS-assigned port) so
//! tests can run in parallel without port conflicts.
//!
//! Gated behind the `server` feature.

use std::net::SocketAddr;
use std::path::{Component, Path};
use std::sync::Arc;

use scp_clock::SystemClock;
use scp_core::context::supervisor::Supervisor;
use scp_did::DidDocument;
use scp_identity::ScpIdentity;
use scp_identity::dht::DidDht;
use scp_node::{DhtMode, ExplicitIdentity, IdentitySource, Node, NodeConfig, NodeError, Reach};
use scp_platform::file::FileKeyCustody;
use scp_platform::in_memory::InMemoryStorage;

use crate::dht::{DhtInitError, FfiDhtClient};
// `ClientDhtConfig` is only referenced by the production (non-test) fail-closed
// node DHT client in `start_node_local`; the test-harness build uses the
// in-memory double instead, so the import would otherwise be unused.
#[cfg(not(any(test, feature = "testing")))]
use crate::dht::ClientDhtConfig;
use scp_transport::native::server::{RelayConfig, RelayError, RelayServer, ShutdownHandle};
use scp_transport::native::storage::{BlobStorageBackend, StorageError};
use zeroize::Zeroizing;

// ---------------------------------------------------------------------------
// NodeIdentity — pre-existing identity for node startup
// ---------------------------------------------------------------------------

/// Concrete DID method type used by all FFI bridges for node identity.
///
/// Parameterized over the shared [`FfiDhtClient`] — the real Mainline
/// `PkarrDhtClient` in shipped builds (an in-memory arm only under `testing`,
/// ADR-062 §Decision 1) — and `SystemClock` (wall-clock time).
pub type ConcreteDidMethod = DidDht<FfiDhtClient, SystemClock>;

/// Pre-existing identity to use when starting an application node.
///
/// Constructed by FFI bridges from their identity registries. Contains
/// the identity, its DID document, and a configured DID method instance
/// with signing capability.
///
/// When `Some(NodeIdentity)` is passed to [`start_node_in_memory`] or
/// [`start_node_local`], the node uses this identity instead of generating
/// a fresh one. This enables identity portability — the same DID persists
/// across node restarts and can be shared across FFI bridge instances.
pub struct NodeIdentity {
    /// The SCP identity containing key handles and DID string.
    pub identity: ScpIdentity,
    /// The published DID document.
    pub document: DidDocument,
    /// A configured DID method instance with signing capability.
    pub did_method: Arc<ConcreteDidMethod>,
}

// ---------------------------------------------------------------------------
// ServerError
// ---------------------------------------------------------------------------

/// Errors produced by shared server startup functions.
///
/// Wraps the concrete error types from the relay, blob storage, application
/// node, and filesystem layers so callers get structured diagnostics instead
/// of opaque strings.
#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    /// The relay server failed to start (bind failure, accept failure).
    #[error("relay error: {0}")]
    Relay(#[from] RelayError),

    /// The application node failed to build or start.
    #[error("node error: {0}")]
    Node(#[from] NodeError),

    /// The blob storage backend could not be opened.
    #[error("storage error: {0}")]
    Storage(#[from] StorageError),

    /// No passphrase was provided when one is required for persistent node identity.
    #[error("passphrase required for persistent node identity")]
    MissingPassphrase,

    /// A filesystem I/O operation failed (e.g., creating the data directory).
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// The platform storage backend could not be initialized.
    #[error("platform error: {0}")]
    Platform(#[from] scp_platform::error::PlatformError),

    /// The production DHT client could not be built (fail-closed — never an
    /// in-memory substitution; ADR-062 §Decision 1).
    #[error("DHT init error: {0}")]
    DhtInit(#[from] DhtInitError),

    /// A node identity auto-generation was requested on a shipped build, where
    /// the in-memory test-harness node is not compiled (fail-closed; ADR-062).
    #[error("auto-generated in-memory node identity is unavailable in this build")]
    AutoGenerateUnavailable,
}

impl ServerError {
    /// Returns a sanitized message safe to expose to SDK consumers.
    ///
    /// Internal details (filesystem paths, OS error descriptions, permission
    /// info) are stripped. Use `tracing::error!` with the full error for
    /// server-side debugging before converting.
    #[must_use]
    pub fn user_message(&self) -> String {
        match self {
            Self::Relay(_) => "relay startup failed".to_owned(),
            Self::Node(_) => "node startup failed".to_owned(),
            Self::Storage(_) => "storage initialization failed".to_owned(),
            Self::Io(_) => "I/O error during server operation".to_owned(),
            Self::Platform(_) => "platform error during server operation".to_owned(),
            Self::MissingPassphrase => {
                "passphrase required for persistent node identity".to_owned()
            }
            Self::DhtInit(_) => "DHT client initialization failed".to_owned(),
            Self::AutoGenerateUnavailable => {
                "auto-generated in-memory node identity is unavailable in this build".to_owned()
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Data-directory validation
// ---------------------------------------------------------------------------

/// Validates a data directory path before use.
///
/// Rejects paths that:
/// - Are empty
/// - Contain `..` components (path traversal)
/// - Exceed 4096 bytes
/// - Contain null bytes
///
/// # Errors
///
/// Returns [`ServerError::Io`] with a descriptive message on validation failure.
pub fn validate_data_dir(path: &Path) -> Result<(), ServerError> {
    let os_str = path.as_os_str();
    if os_str.is_empty() {
        return Err(ServerError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "data directory path must not be empty",
        )));
    }
    if os_str.len() > 4096 {
        return Err(ServerError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "data directory path exceeds 4096 bytes",
        )));
    }
    // Check for null bytes (encoded_bytes on Unix, to_string_lossy everywhere).
    let lossy = path.to_string_lossy();
    if lossy.contains('\0') {
        return Err(ServerError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "data directory path contains null bytes",
        )));
    }
    // Reject parent-directory components.
    for component in path.components() {
        if matches!(component, Component::ParentDir) {
            return Err(ServerError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "data directory path must not contain '..' components",
            )));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// RunningRelay
// ---------------------------------------------------------------------------

/// A running relay server with its bound address and shutdown handle.
///
/// Created by [`start_relay_in_memory`] or [`start_relay_local`]. The relay
/// accepts WebSocket connections at [`relay_url`](Self::relay_url) and can be
/// gracefully stopped via [`shutdown`](Self::shutdown).
pub struct RunningRelay {
    /// The WebSocket URL clients should connect to (e.g., `ws://127.0.0.1:12345/scp/v1`).
    relay_url: String,
    /// The local address the relay is bound to.
    bound_addr: SocketAddr,
    /// Handle for graceful shutdown.
    shutdown: ShutdownHandle,
}

impl RunningRelay {
    /// Returns the WebSocket URL clients should connect to
    /// (e.g., `ws://127.0.0.1:12345/scp/v1`).
    #[must_use]
    pub fn relay_url(&self) -> &str {
        &self.relay_url
    }

    /// Returns the local address the relay server is bound to.
    #[must_use]
    pub const fn bound_addr(&self) -> SocketAddr {
        self.bound_addr
    }

    /// Signals the relay server to stop accepting new connections.
    ///
    /// In-flight connection handlers drain naturally after shutdown is
    /// signaled — they are not cancelled.
    pub fn shutdown(&self) {
        self.shutdown.shutdown();
    }

    /// Returns `true` if shutdown has already been signaled.
    #[must_use]
    pub fn is_shutdown(&self) -> bool {
        self.shutdown.is_shutdown()
    }
}

/// Builds a [`RelayConfig`] bound to `127.0.0.1:0` with zero delivery jitter
/// (suitable for testing — deterministic timing).
fn test_relay_config() -> RelayConfig {
    RelayConfig {
        bind_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
        delivery_jitter_ms: 0,
        ..RelayConfig::default()
    }
}

/// Starts a relay and returns a [`RunningRelay`] from the given config and storage.
async fn start_relay_with(
    config: RelayConfig,
    storage: BlobStorageBackend,
) -> Result<RunningRelay, ServerError> {
    let server = RelayServer::new(config, Arc::new(storage));
    let (handle, addr) = server.start().await?;
    let relay_url = format!("ws://127.0.0.1:{}/scp/v1", addr.port());
    Ok(RunningRelay {
        relay_url,
        bound_addr: addr,
        shutdown: handle,
    })
}

/// Starts a relay with in-memory blob storage on an OS-assigned port.
///
/// The relay binds to `127.0.0.1:0` and uses zero delivery jitter (suitable
/// for tests and demos). Use [`RunningRelay::relay_url`] to get the WebSocket
/// URL for clients.
///
/// # Errors
///
/// Returns [`ServerError::Relay`] if the relay cannot bind.
pub async fn start_relay_in_memory() -> Result<RunningRelay, ServerError> {
    start_relay_with(test_relay_config(), BlobStorageBackend::in_memory()).await
}

/// Starts a relay with redb-backed blob storage on an OS-assigned port.
///
/// Opens (or creates) a redb database at `<data_dir>/blobs.redb`. The relay
/// binds to `127.0.0.1:0` with zero delivery jitter.
///
/// # Errors
///
/// Returns [`ServerError::Io`] if the data directory cannot be created, or
/// [`ServerError::Storage`] if the database cannot be opened, or
/// [`ServerError::Relay`] if the relay cannot bind.
pub async fn start_relay_local(data_dir: &Path) -> Result<RunningRelay, ServerError> {
    validate_data_dir(data_dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(data_dir)?;
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(data_dir)?;
    }
    let db_path = data_dir.join("blobs.redb");
    let storage = BlobStorageBackend::redb(&db_path)?;
    start_relay_with(test_relay_config(), storage).await
}

// ---------------------------------------------------------------------------
// ApplicationNode startup
// ---------------------------------------------------------------------------

/// Starts a full application node with in-memory storage.
///
/// When `identity` is `None` (auto-generate): available ONLY in a `testing`
/// build via the test-harness `ApplicationNode::dev` (in-memory key custody,
/// [`InMemoryStorage`](scp_platform::in_memory::InMemoryStorage), and the
/// `InMemoryDhtClient` nullifier — no real DHT
/// network). A shipped (no-`testing`) build FAILS CLOSED with
/// [`ServerError::AutoGenerateUnavailable`] rather than run a nullifier-backed
/// node (ADR-062 §Decision 1/6). A production caller cannot supply
/// `Some(NodeIdentity)` from a create call on this crate's surface either, which
/// fails closed the same way. (A Rust consumer of `scp-identity` can still mint
/// one — see issue 2392.) Self-signed TLS (localhost); relay bound to
/// `127.0.0.1:0` (OS-assigned port).
///
/// When `identity` is `Some(NodeIdentity)`, the node uses the pre-existing
/// identity instead of generating a fresh one. This enables identity
/// portability — the same DID persists across node restarts.
///
/// The relay is started during construction. The HTTP server is **not** started;
/// call `ApplicationNode::serve` if HTTP endpoints are needed.
///
/// # Errors
///
/// Returns [`ServerError::AutoGenerateUnavailable`] when `identity` is `None` on a
/// shipped build, where ADR-062 §Decision 6 severed the auto-generate arm, and
/// [`ServerError::Node`] if relay binding, identity generation, or TLS
/// provisioning fails.
pub async fn start_node_in_memory(
    identity: Option<NodeIdentity>,
) -> Result<scp_node::ApplicationNode<InMemoryStorage>, ServerError> {
    let node = match identity {
        // Auto-generate uses the test-harness `ApplicationNode::dev` (in-memory
        // DHT nullifier), compiled only under `testing` (ADR-062 §Decision 1).
        // A shipped build fails closed rather than running a nullifier-backed
        // node. A production caller cannot get one from this crate's create
        // surface either, which fails closed the same way.
        #[cfg(any(test, feature = "testing"))]
        None => scp_node::ApplicationNode::dev(0).await?,
        #[cfg(not(any(test, feature = "testing")))]
        None => return Err(ServerError::AutoGenerateUnavailable),
        Some(id) => {
            // Migrated to the ADR-052 flat-config front door (Phase B-P2).
            // The dropped explicit `SelfSignedTlsProvider::new("localhost")` is
            // reproduced by the default `TlsMode::SelfSigned`. `Domain` is a
            // publishing reach, so M2 requires `DhtMode::Production` (advisory
            // in P1 — the in-memory DHT client publishes nothing).
            Node::start_for_testing(NodeConfig {
                bind_addr: Some(SocketAddr::from(([127, 0, 0, 1], 0))),
                dht: DhtMode::Production,
                ..NodeConfig::defaults(
                    Reach::Domain {
                        domain: "localhost".to_owned(),
                    },
                    // `Explicit` carries no custody, so `K` is unconstrained by
                    // the variant; annotate it to a production custody type
                    // (`FileKeyCustody`) so no test-only nullifier type appears
                    // on this shipped `server`-feature path (ADR-062 §Decision 6).
                    IdentitySource::<FileKeyCustody, ConcreteDidMethod>::Explicit(Box::new(
                        ExplicitIdentity {
                            identity: id.identity,
                            document: id.document,
                            did_method: id.did_method,
                        },
                    )),
                    InMemoryStorage::new(),
                    // Explicit durability-only selection for this in-memory
                    // server front door (SCP-CAPINJECT-010): the blob backend is
                    // a required selection, never a runtime default.
                    BlobStorageBackend::in_memory(),
                )
            })
            .await?
        }
    };

    tracing::info!(
        relay_url = %node.relay_url(),
        relay_addr = %node.relay().bound_addr(),
        did = %node.identity().did(),
        "application node started (in-memory)"
    );
    Ok(node)
}

/// Starts a full application node with file-backed storage for local development.
///
/// Auto-wires:
/// - [`FilesystemStorage`](scp_platform::filesystem::FilesystemStorage) at
///   `<data_dir>/storage/` — persistent key-value storage for protocol state
/// - [`BlobStorageBackend::redb`] at `<data_dir>/blobs.redb` — persistent
///   relay blob storage
/// - When `identity` is `None`: the production Mainline DHT client, built from
///   `ClientDhtConfig::default()`. A `testing` build substitutes the
///   `InMemoryDhtClient` nullifier so tests stay offline; a shipped build never
///   reaches it. When `identity` is `Some`, the DID method comes from the
///   caller's `NodeIdentity` and this function builds no DHT client.
/// - Self-signed TLS (for the localhost domain)
/// - Relay bound to `127.0.0.1:0` (OS-assigned port)
///
/// The relay is started during construction. The HTTP server is **not** started;
/// call `ApplicationNode::serve` if HTTP endpoints are needed.
///
/// # Identity modes
///
/// When `identity` is `Some(NodeIdentity)`, the node uses the pre-existing
/// identity. This enables identity portability — the same DID persists
/// across node restarts and can be shared across FFI bridge instances.
///
/// When `identity` is `None`, the node reloads a persistent identity via
/// [`FileKeyCustody`](scp_platform::file::FileKeyCustody), whose keystore is
/// `<data_dir>/identity.key` (the identity record itself lives under the storage
/// key `scp/identity` in `<data_dir>/storage/`). The `passphrase` parameter is
/// required in this mode — there is no environment variable fallback.
///
/// With no identity in storage, a shipped build fails here on every run, not only
/// the first. Reloading a DID from storage carries no gate and does work; creating
/// one needs a `PreRotationCustody`
/// backend (spec §9.7.4.1 §3) whose only implementation is the test-harness
/// `InMemoryPreRotationCustody`, so `IdentityError::NoPreRotationBackend` comes
/// back instead. This crate's own create surface fails closed the same way, so
/// nothing an FFI caller can invoke puts an identity into `data_dir` and the
/// reload branch fires only against a slot a `testing` build already seeded, with
/// a custody holding the matching handles. (A Rust consumer of `scp-identity` can still mint
/// one: `DidMethod::create` takes a caller-supplied `PreRotationCustody`, and that
/// trait is not sealed — see issue 2392.) `identity` is a different matter — every field of `ScpIdentity` and
/// `DidDocument` is public, so a caller CAN assemble one by hand, and such an
/// identity carries a pre-rotation commitment whose preimage no custody holds,
/// which makes spec §9.7.4.1 Layer-2 recovery permanently impossible for it.
///
/// For fully ephemeral setups use [`start_node_in_memory`].
///
/// # Errors
///
/// Returns [`ServerError`] if:
/// - The data directory cannot be created ([`ServerError::Io`])
/// - The filesystem storage cannot be initialized ([`ServerError::Platform`])
/// - The redb blob database cannot be opened ([`ServerError::Storage`])
/// - No passphrase provided when `identity` is `None` ([`ServerError::MissingPassphrase`])
/// - `identity` is `None` on a shipped build AND `data_dir` holds no identity,
///   because creating one needs a `PreRotationCustody` backend that only a
///   `testing` build has ([`ServerError::Node`], whose `user_message` is "node
///   startup failed"). Against a directory a `testing` build seeded, the reload
///   branch succeeds.
/// - Relay binding, identity generation, or TLS fails ([`ServerError::Node`])
pub async fn start_node_local(
    data_dir: &Path,
    identity: Option<NodeIdentity>,
    passphrase: Option<zeroize::Zeroizing<String>>,
) -> Result<scp_node::ApplicationNode<scp_platform::filesystem::FilesystemStorage>, ServerError> {
    use scp_identity::DidCache;
    use scp_platform::filesystem::FilesystemStorage;

    // Validate and ensure data directory exists.
    validate_data_dir(data_dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(data_dir)?;
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(data_dir)?;
    }

    // Common paths.
    let storage_dir = data_dir.join("storage");
    let blob_path = data_dir.join("blobs.redb");

    // File-backed protocol storage and blob storage (shared across identity modes).
    let storage = FilesystemStorage::new(&storage_dir)?;
    let blob_storage = BlobStorageBackend::redb(&blob_path)?;

    // Build the node via the ADR-052 flat-config front door (Phase B-P2). The
    // two identity arms differ only in their `IdentitySource`; the dropped
    // explicit `SelfSignedTlsProvider::new("localhost")` is reproduced by the
    // default `TlsMode::SelfSigned`. `Domain` is a publishing reach, so M2
    // requires `DhtMode::Production` (advisory in P1 — the in-memory DHT client
    // publishes nothing). The storage values are moved into the config, so the
    // two arms each build their own config.
    let node = if let Some(id) = identity {
        Node::start_for_testing(NodeConfig {
            bind_addr: Some(SocketAddr::from(([127, 0, 0, 1], 0))),
            dht: DhtMode::Production,
            ..NodeConfig::defaults(
                Reach::Domain {
                    domain: "localhost".to_owned(),
                },
                // `Explicit` carries no custody, so `K` is unconstrained by the
                // variant; annotate it to `FileKeyCustody` (matching the
                // persisted arm below), so no test-only nullifier type appears on
                // this shipped `server`-feature path (ADR-062 §Decision 6).
                IdentitySource::<FileKeyCustody, ConcreteDidMethod>::Explicit(Box::new(
                    ExplicitIdentity {
                        identity: id.identity,
                        document: id.document,
                        did_method: id.did_method,
                    },
                )),
                storage,
                // The operator-chosen durable redb blob backend (opened above),
                // passed as the required selection (SCP-CAPINJECT-010).
                blob_storage,
            )
        })
        .await?
    } else {
        // Persistent key custody — keys survive process restarts.
        let passphrase = passphrase.ok_or(ServerError::MissingPassphrase)?;
        let key_path = data_dir.join("identity.key");
        let key_custody = Arc::new(scp_platform::file::FileKeyCustody::new(
            &key_path,
            &passphrase,
        )?);

        // Build the node's DHT client for its DID method. A shipped build uses
        // the real Mainline Pkarr client, fail-closed (never an in-memory
        // substitution; ADR-062 §Decision 1) — the node's dht gateways would
        // thread in here; the local path uses direct Mainline DHT (no gateways).
        // A test-harness build (`testing`) uses the in-memory §17.17.3 double so
        // `Node::start_for_testing`'s mandatory startup publish (a full relay node
        // always publishes; see `scp_node`) stays offline instead of timing out
        // against live Mainline. The client backs both this node's DID
        // publication and its `did:dht` resolution.
        #[cfg(not(any(test, feature = "testing")))]
        let dht_client = Arc::new(ClientDhtConfig::default().into_client()?);
        #[cfg(any(test, feature = "testing"))]
        let dht_client = Arc::new(FfiDhtClient::InMemory(scp_dht::InMemoryDhtClient::new()));
        let cache = Arc::new(DidCache::new());
        let sign_fn = ConcreteDidMethod::make_sign_fn(Arc::clone(&key_custody));
        let did_method = Arc::new(ConcreteDidMethod::with_client_and_signer(
            dht_client, cache, sign_fn,
        ));

        Node::start_for_testing(NodeConfig {
            bind_addr: Some(SocketAddr::from(([127, 0, 0, 1], 0))),
            dht: DhtMode::Production,
            ..NodeConfig::defaults(
                Reach::Domain {
                    domain: "localhost".to_owned(),
                },
                IdentitySource::Persisted {
                    custody: key_custody,
                    did_method,
                },
                storage,
                // The operator-chosen durable redb blob backend (opened above),
                // passed as the required selection (SCP-CAPINJECT-010).
                blob_storage,
            )
        })
        .await?
    };

    tracing::info!(
        relay_url = %node.relay_url(),
        relay_addr = %node.relay().bound_addr(),
        did = %node.identity().did(),
        data_dir = %data_dir.display(),
        "application node started (local file-backed)"
    );
    Ok(node)
}

// ---------------------------------------------------------------------------
// RunningNode — type-erased ApplicationNode wrapper (shared across bridges)
// ---------------------------------------------------------------------------

/// Type-erased wrapper over `ApplicationNode<S>` for the two concrete storage
/// backends used by the shared server code.
///
/// `ApplicationNode<S>` is generic over `S: Storage`. The `Storage` trait uses
/// RPITIT and is not object-safe, so we cannot use `dyn Storage`. Instead we
/// use a closed enum over `InMemoryStorage` and `FilesystemStorage`.
///
/// This mirrors the pattern established by [`RunningRelay`] — shared in
/// `scp-ffi-common` so each FFI bridge wraps this rather than duplicating the
/// enum and its dispatch methods.
pub enum RunningNode {
    /// In-memory storage variant (ephemeral — suitable for tests/demos).
    InMemory(scp_node::ApplicationNode<InMemoryStorage>),
    /// Filesystem-backed storage variant (persistent — suitable for local dev).
    Filesystem(scp_node::ApplicationNode<scp_platform::filesystem::FilesystemStorage>),
}

impl RunningNode {
    /// Returns the WebSocket URL clients should connect to for this node's relay.
    #[must_use]
    pub fn relay_url(&self) -> &str {
        match self {
            Self::InMemory(n) => n.relay_url(),
            Self::Filesystem(n) => n.relay_url(),
        }
    }

    /// Returns the node's DID string.
    #[must_use]
    pub fn did(&self) -> &str {
        match self {
            Self::InMemory(n) => n.identity().did(),
            Self::Filesystem(n) => n.identity().did(),
        }
    }

    /// Returns the port the node's relay is listening on.
    #[must_use]
    pub const fn relay_port(&self) -> u16 {
        match self {
            Self::InMemory(n) => n.relay().bound_addr().port(),
            Self::Filesystem(n) => n.relay().bound_addr().port(),
        }
    }

    /// Returns the internal relay WebSocket URL for in-process connections.
    ///
    /// Unlike [`relay_url`](Self::relay_url) (which returns the advertised URL
    /// for external clients, e.g. `wss://localhost/scp/v1`), this returns
    /// `ws://127.0.0.1:{port}/scp/v1` — suitable for in-process relay
    /// connections that bypass TLS. The port is the actual OS-assigned port
    /// the relay is bound to.
    #[must_use]
    pub fn internal_relay_url(&self) -> String {
        format!("ws://127.0.0.1:{}/scp/v1", self.relay_port())
    }

    /// Returns the hex-encoded bridge token for relay authentication.
    ///
    /// This token must be included as an `Authorization: Bearer <hex>` header
    /// when connecting directly to the relay's bound address. The
    /// `ApplicationNode` relay enforces this for all WebSocket connections.
    ///
    /// **Security:** This value is a secret. Do not log or expose it.
    #[must_use]
    pub fn bridge_token_hex(&self) -> Zeroizing<String> {
        match self {
            Self::InMemory(n) => n.bridge_token_hex(),
            Self::Filesystem(n) => n.bridge_token_hex(),
        }
    }

    /// Returns `true` if shutdown has already been signaled.
    #[must_use]
    pub fn is_shutdown(&self) -> bool {
        match self {
            Self::InMemory(n) => n.relay().shutdown_handle().is_shutdown(),
            Self::Filesystem(n) => n.relay().shutdown_handle().is_shutdown(),
        }
    }

    /// Signals the node to stop (relay + background tasks).
    pub fn shutdown(&self) {
        match self {
            Self::InMemory(n) => n.shutdown(),
            Self::Filesystem(n) => n.shutdown(),
        }
    }

    /// Spawns a background task forwarding local `Supervisor` events to this
    /// node's outbound webhook dispatcher (§12.10.5).
    ///
    /// The `events` receiver is obtained from
    /// [`Supervisor::subscribe_events`](scp_core::context::supervisor::Supervisor::subscribe_events).
    /// The returned [`JoinHandle`](tokio::task::JoinHandle) owns the consumer
    /// task and MUST be retained by a lifecycle owner (e.g. the bridge instance
    /// `JoinSet`) so it is aborted on shutdown rather than leaked.
    ///
    /// See [`ApplicationNode::wire_context_events`](scp_node::ApplicationNode::wire_context_events).
    #[must_use]
    pub fn wire_context_events(
        &self,
        events: tokio::sync::broadcast::Receiver<(
            String,
            scp_core::context::membership::ContextEvent,
        )>,
    ) -> tokio::task::JoinHandle<()> {
        match self {
            Self::InMemory(n) => n.wire_context_events(events),
            Self::Filesystem(n) => n.wire_context_events(events),
        }
    }

    /// Subscribes to the supervisor's event channel, wires the consumer into
    /// this node's webhook dispatcher, and supervises the consumer under the
    /// bridge instance's lifecycle (spec §12.10.5).
    ///
    /// This is the shared seam for all three FFI bridges (`PyO3`, `NAPI`,
    /// `UniFFI`). Each bridge's node-startup path calls it once, after the
    /// `Supervisor` is attached, passing the instance's `JoinSet` guard and
    /// cancellation token. Consolidating the subscribe → wire → supervise block
    /// here prevents per-bridge drift (the regression that reopened the webhook
    /// wiring, where only `PyO3` was wired).
    ///
    /// Behavior:
    /// - If the supervisor has no event channel (`subscribe_events()` returns
    ///   `None`), wiring is skipped with a warning rather than panicking.
    ///   Production supervisors always enable the channel (see each bridge's
    ///   `build_supervisor`), so this is purely defensive against a supervisor
    ///   initialized by some other path.
    /// - The consumer task runs until the broadcast channel closes (supervisor
    ///   dropped) OR the bridge instance's cancellation token fires, at which
    ///   point the consumer is aborted. This makes the consumer deterministically
    ///   bound to the instance lifecycle rather than leaked as a detached task.
    pub fn wire_and_supervise_context_events(
        &self,
        supervisor: &Arc<Supervisor>,
        tasks: &mut tokio::task::JoinSet<()>,
        cancel: tokio_util::sync::CancellationToken,
    ) {
        let Some(events) = supervisor.subscribe_events() else {
            // Defensive: production supervisors always have the channel, but a
            // Supervisor initialized by another path without it would return
            // None. Skip wiring rather than panic.
            tracing::warn!(
                "wire_and_supervise_context_events: Supervisor has no event \
                 channel — local context events will not reach the webhook dispatcher"
            );
            return;
        };
        let consumer = self.wire_context_events(events);
        spawn_supervised_event_consumer(consumer, tasks, cancel);
    }

    /// Activates HTTP broadcast projection with optional site configuration.
    ///
    /// # Errors
    ///
    /// Returns [`NodeError`] if projection activation fails.
    pub async fn enable_broadcast_projection_with_site(
        &self,
        context_id: &str,
        broadcast_key: scp_core::crypto::sender_keys::BroadcastKey,
        admission: scp_core::context::broadcast::BroadcastAdmission,
        site_config: Option<scp_node::projection::SiteConfig>,
    ) -> Result<(), NodeError> {
        match self {
            Self::InMemory(n) => {
                n.enable_broadcast_projection_with_site(
                    context_id,
                    broadcast_key,
                    admission,
                    None,
                    site_config,
                )
                .await
            }
            Self::Filesystem(n) => {
                n.enable_broadcast_projection_with_site(
                    context_id,
                    broadcast_key,
                    admission,
                    None,
                    site_config,
                )
                .await
            }
        }
    }

    /// Commits a deploy for a projected context.
    ///
    /// # Errors
    ///
    /// Returns [`NodeError`] if the context is not projected or commit fails.
    pub async fn commit_deploy(
        &self,
        context_id: &str,
        deploy_id: &str,
    ) -> Result<usize, NodeError> {
        match self {
            Self::InMemory(n) => n.commit_deploy(context_id, deploy_id).await,
            Self::Filesystem(n) => n.commit_deploy(context_id, deploy_id).await,
        }
    }

    /// Rolls back to a previous deploy for a projected context.
    ///
    /// # Errors
    ///
    /// Returns [`NodeError`] if the context is not projected or rollback fails.
    pub async fn rollback_deploy(
        &self,
        context_id: &str,
        deploy_id: &str,
    ) -> Result<(), NodeError> {
        match self {
            Self::InMemory(n) => n.rollback_deploy(context_id, deploy_id).await,
            Self::Filesystem(n) => n.rollback_deploy(context_id, deploy_id).await,
        }
    }

    /// Deactivates HTTP broadcast projection for the given context.
    pub async fn disable_broadcast_projection(&self, context_id: &str) {
        match self {
            Self::InMemory(n) => n.disable_broadcast_projection(context_id).await,
            Self::Filesystem(n) => n.disable_broadcast_projection(context_id).await,
        }
    }

    /// Starts the HTTP server in the background on the given bind address.
    ///
    /// If `bind_addr` is `None`, the node uses its default bind address.
    /// Returns the actual bound address.
    ///
    /// # Errors
    ///
    /// Returns [`NodeError`] if the server is already running or binding fails.
    pub async fn serve_background(
        &self,
        bind_addr: Option<std::net::SocketAddr>,
    ) -> Result<std::net::SocketAddr, NodeError> {
        match self {
            Self::InMemory(n) => n.serve_background(bind_addr).await,
            Self::Filesystem(n) => n.serve_background(bind_addr).await,
        }
    }

    /// Returns the HTTP URL of the background server, or `None` if not serving.
    pub async fn http_url(&self) -> Option<String> {
        match self {
            Self::InMemory(n) => n.http_url().await,
            Self::Filesystem(n) => n.http_url().await,
        }
    }
}

/// Spawns a webhook-event `consumer` (from `ApplicationNode::wire_context_events`
/// or [`RunningNode::wire_context_events`]) under the bridge instance's
/// `JoinSet`, bound to its cancellation token.
///
/// This is the single shared supervision wire for all three FFI bridges
/// (`PyO3` reference, `NAPI`, `UniFFI`). Each bridge subscribes to its
/// `Supervisor` event channel and wires the consumer via its node, then hands
/// the resulting `JoinHandle` here so the supervision policy lives in one place
/// and cannot drift per-bridge (the failure mode that reopened the webhook
/// wiring, where only `PyO3` was wired).
///
/// Lifecycle: the spawned guard task runs until either the consumer completes
/// (the broadcast channel closed because the `Supervisor` was dropped) or
/// `cancel` fires on bridge shutdown, at which point the consumer is aborted so
/// it never outlives the instance as a detached task.
pub fn spawn_supervised_event_consumer(
    mut consumer: tokio::task::JoinHandle<()>,
    tasks: &mut tokio::task::JoinSet<()>,
    cancel: tokio_util::sync::CancellationToken,
) {
    tasks.spawn(async move {
        tokio::select! {
            // The consumer task runs until the broadcast channel closes.
            _ = &mut consumer => {}
            // On bridge shutdown, abort the consumer so it does not
            // outlive the instance as a detached task.
            () = cancel.cancelled() => {
                consumer.abort();
            }
        }
    });
}

// ---------------------------------------------------------------------------
// Broadcast key resolution — shared across PyO3 and NAPI bridges
// ---------------------------------------------------------------------------

/// Error returned by [`resolve_broadcast_key`] when key resolution fails.
///
/// Bridge callers map this to their framework-specific error types
/// (`PyErr`, `napi::Error`, etc.).
#[derive(Debug, thiserror::Error)]
pub enum BroadcastKeyError {
    /// The hex string is not valid hex.
    #[error("invalid broadcast_key_hex: {0}")]
    InvalidHex(#[from] hex::FromHexError),

    /// The decoded key is not exactly 32 bytes.
    #[error("broadcast_key_hex must be exactly 64 hex characters (32 bytes)")]
    InvalidKeyLength,

    /// `broadcast_key_hex` was provided without `author_did`.
    #[error(
        "broadcast_key_hex requires author_did — provide the DID of the \
         broadcast key owner, or omit both for auto-resolve"
    )]
    KeyWithoutAuthor,

    /// Auto-resolve from the `Supervisor` failed.
    #[error("broadcast key auto-resolve failed: {0}")]
    AutoResolveFailed(String),
}

/// Resolved broadcast key components ready for `BroadcastKey::from_parts`.
pub struct ResolvedBroadcastKey {
    /// The 32-byte broadcast key (zeroize-protected).
    pub key_bytes: Zeroizing<[u8; 32]>,
    /// The epoch associated with the key (0 for explicit keys).
    pub epoch: u64,
    /// The DID of the broadcast key author/owner.
    pub author_did: String,
}

/// Resolves broadcast key parameters into a [`ResolvedBroadcastKey`].
///
/// Three resolution modes:
/// 1. Both `broadcast_key_hex` **and** `author_did` provided — uses the
///    explicit key with epoch 0.
/// 2. Only `author_did` provided — auto-resolves the broadcast key from
///    the per-instance `Supervisor` using that DID.
/// 3. Neither provided — auto-resolves using `fallback_did` (typically the
///    node's identity DID).
///
/// Providing `broadcast_key_hex` without `author_did` is an error.
///
/// # Arguments
///
/// * `broadcast_key_hex` — Optional hex-encoded 32-byte key.
/// * `author_did` — Optional DID of the broadcast key owner.
/// * `fallback_did` — DID to use when both `broadcast_key_hex` and
///   `author_did` are `None` (e.g., the node's own DID).
/// * `supervisor` — Reference to the per-instance `Supervisor` for
///   auto-resolve via the
///   [`Supervisor::get_broadcast_key_for_local_author`](scp_core::context::supervisor::Supervisor::get_broadcast_key_for_local_author)
///   passthrough (ADR-049 commit 12c.9g.3).
/// * `context_id` — The context ID to resolve the key for.
///
/// # Errors
///
/// Returns [`BroadcastKeyError`] on invalid hex, wrong key length,
/// missing author DID, or auto-resolve failure.
pub async fn resolve_broadcast_key(
    broadcast_key_hex: Option<String>,
    author_did: Option<String>,
    fallback_did: &str,
    supervisor: &Supervisor,
    context_id: &str,
) -> Result<ResolvedBroadcastKey, BroadcastKeyError> {
    match (broadcast_key_hex, author_did) {
        (Some(key_hex), Some(did)) => {
            let key_hex = Zeroizing::new(key_hex);
            let key_vec = Zeroizing::new(hex::decode(&*key_hex)?);
            let key_bytes = crate::validate::expect_fixed_bytes_zeroized::<32>(
                key_vec.as_slice(),
                "broadcast_key",
            )
            .map_err(|_| BroadcastKeyError::InvalidKeyLength)?;
            // Explicit key path always uses epoch 0. For rotated keys,
            // use auto-resolve (omit both params).
            Ok(ResolvedBroadcastKey {
                key_bytes,
                epoch: 0,
                author_did: did,
            })
        }
        (None, author_opt) => {
            // Auto-resolve: use provided author_did or fall back to node DID.
            let did = author_opt.unwrap_or_else(|| fallback_did.to_owned());
            let result: Result<(Zeroizing<[u8; 32]>, u64), _> = supervisor
                .get_broadcast_key_for_local_author(context_id, &did)
                .await;
            let (key_bytes, epoch) = result.map_err(|e| {
                tracing::debug!(error = %e, "broadcast key auto-resolve failed");
                BroadcastKeyError::AutoResolveFailed("not authorized for this context".to_owned())
            })?;
            Ok(ResolvedBroadcastKey {
                key_bytes,
                epoch,
                author_did: did,
            })
        }
        (Some(_), None) => Err(BroadcastKeyError::KeyWithoutAuthor),
    }
}

/// Convenience: builds a `BroadcastKey` from a [`ResolvedBroadcastKey`].
impl ResolvedBroadcastKey {
    /// Converts the resolved key into a `BroadcastKey` suitable for
    /// passing to `enable_broadcast_projection_with_site`.
    #[must_use]
    pub fn into_broadcast_key(self) -> scp_core::crypto::sender_keys::BroadcastKey {
        scp_core::crypto::sender_keys::BroadcastKey::from_parts(
            scp_core::crypto::sender_keys::SenderKey::from_bytes(*self.key_bytes),
            self.epoch,
            self.author_did,
        )
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// Passphrase used by tests that exercise the `FileKeyCustody` path.
    fn test_passphrase() -> zeroize::Zeroizing<String> {
        zeroize::Zeroizing::new("test-passphrase".to_owned())
    }

    #[tokio::test]
    async fn relay_in_memory_returns_valid_ws_url() {
        let relay = start_relay_in_memory().await.unwrap();
        assert!(
            relay.relay_url().starts_with("ws://127.0.0.1:"),
            "expected ws:// URL, got: {}",
            relay.relay_url()
        );
        assert!(
            relay.relay_url().ends_with("/scp/v1"),
            "expected /scp/v1 path suffix, got: {}",
            relay.relay_url()
        );
        assert_ne!(relay.bound_addr().port(), 0, "port should be assigned");
        relay.shutdown();
    }

    #[tokio::test]
    async fn relay_local_returns_valid_ws_url() {
        let tmp = std::env::temp_dir().join(format!("scp-test-relay-{}", std::process::id()));
        let relay = start_relay_local(&tmp).await.unwrap();
        assert!(
            relay.relay_url().starts_with("ws://127.0.0.1:"),
            "expected ws:// URL, got: {}",
            relay.relay_url()
        );
        assert!(
            relay.relay_url().ends_with("/scp/v1"),
            "expected /scp/v1 path suffix, got: {}",
            relay.relay_url()
        );
        assert_ne!(relay.bound_addr().port(), 0);
        relay.shutdown();
        // Cleanup
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[tokio::test]
    async fn relay_shutdown_is_idempotent() {
        let relay = start_relay_in_memory().await.unwrap();
        assert!(!relay.is_shutdown());
        relay.shutdown();
        assert!(relay.is_shutdown());
        // Second shutdown should not panic.
        relay.shutdown();
        assert!(relay.is_shutdown());
    }

    #[tokio::test]
    async fn node_in_memory_returns_relay_url_and_did() {
        let node = start_node_in_memory(None).await.unwrap();
        // Relay URL should be a valid ws:// or wss:// URL.
        let url = node.relay_url();
        assert!(
            url.starts_with("ws://") || url.starts_with("wss://"),
            "expected ws(s):// URL, got: {url}"
        );
        // DID should be a valid did: string.
        assert!(
            node.identity().did().starts_with("did:"),
            "expected did: prefix, got: {}",
            node.identity().did()
        );
        assert_ne!(node.relay().bound_addr().port(), 0);
        node.shutdown();
    }

    #[tokio::test]
    async fn node_local_returns_relay_url_and_did() {
        let tmp = std::env::temp_dir().join(format!("scp-test-node-local-{}", std::process::id()));
        let node = start_node_local(&tmp, None, Some(test_passphrase()))
            .await
            .unwrap();

        // Relay URL should be a valid ws:// or wss:// URL.
        let url = node.relay_url();
        assert!(
            url.starts_with("ws://") || url.starts_with("wss://"),
            "expected ws(s):// URL, got: {url}"
        );

        // DID should be a valid did: string.
        assert!(
            node.identity().did().starts_with("did:"),
            "expected did: prefix, got: {}",
            node.identity().did()
        );

        assert_ne!(node.relay().bound_addr().port(), 0);

        // Storage directory should have been created.
        assert!(tmp.join("storage").is_dir(), "storage dir should exist");
        // Blob database should have been created.
        assert!(tmp.join("blobs.redb").exists(), "blobs.redb should exist");
        // Key file should have been created.
        assert!(
            tmp.join("identity.key").exists(),
            "identity.key should exist"
        );

        node.shutdown();
        // Cleanup
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[tokio::test]
    async fn node_local_reuses_data_dir_across_restarts() {
        let tmp =
            std::env::temp_dir().join(format!("scp-test-node-persist-{}", std::process::id()));

        let first_did;
        // First run — creates storage directory, blob database, and identity key.
        {
            let node = start_node_local(&tmp, None, Some(test_passphrase()))
                .await
                .unwrap();
            assert!(tmp.join("storage").is_dir());
            assert!(tmp.join("blobs.redb").exists());
            assert!(tmp.join("identity.key").exists());
            first_did = node.identity().did().to_owned();
            node.shutdown();
            // Drop the node so background tasks release the redb file lock.
            drop(node);
            // Yield to let the tokio runtime drain cancelled relay tasks.
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }

        // Second run — should open the same data directory without error.
        // With FileKeyCustody + identity_with_storage, the same DID is
        // reloaded from persistent storage across restarts.
        {
            let node = start_node_local(&tmp, None, Some(test_passphrase()))
                .await
                .unwrap();
            assert_eq!(
                node.identity().did(),
                first_did,
                "second run should produce the same DID (persistent identity)"
            );
            node.shutdown();
        }

        // Cleanup
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[tokio::test]
    async fn server_error_variants_display() {
        // Verify Display impls for all variants produce non-empty messages.
        let io_err = ServerError::Io(std::io::Error::new(std::io::ErrorKind::NotFound, "gone"));
        assert!(io_err.to_string().contains("gone"), "{io_err}");

        let storage_err = ServerError::Storage(StorageError::Internal("bad".into()));
        assert!(storage_err.to_string().contains("bad"), "{storage_err}");

        let relay_err = ServerError::Relay(RelayError::BindFailed("addr in use".into()));
        assert!(relay_err.to_string().contains("addr in use"), "{relay_err}");
    }

    #[test]
    fn user_message_does_not_leak_internal_details() {
        let io_err = ServerError::Io(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "permission denied: /home/user/.secret/data",
        ));
        let msg = io_err.user_message();
        assert_eq!(msg, "I/O error during server operation");
        assert!(
            !msg.contains("/home"),
            "user_message must not contain paths"
        );

        let relay_err = ServerError::Relay(RelayError::BindFailed("0.0.0.0:443".into()));
        assert_eq!(relay_err.user_message(), "relay startup failed");

        let storage_err = ServerError::Storage(StorageError::Internal("redb corruption".into()));
        assert_eq!(storage_err.user_message(), "storage initialization failed");

        let missing_passphrase = ServerError::MissingPassphrase;
        assert_eq!(
            missing_passphrase.user_message(),
            "passphrase required for persistent node identity"
        );
    }

    #[test]
    fn validate_data_dir_rejects_empty() {
        let result = validate_data_dir(Path::new(""));
        assert!(result.is_err(), "empty path should be rejected");
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("empty"), "error: {msg}");
    }

    #[test]
    fn validate_data_dir_rejects_parent_traversal() {
        let result = validate_data_dir(Path::new("/tmp/foo/../bar"));
        assert!(result.is_err(), ".. component should be rejected");
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains(".."), "error: {msg}");
    }

    #[test]
    fn validate_data_dir_rejects_long_path() {
        let long = "a".repeat(4097);
        let result = validate_data_dir(Path::new(&long));
        assert!(result.is_err(), "path >4096 bytes should be rejected");
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("4096"), "error: {msg}");
    }

    #[test]
    fn validate_data_dir_accepts_valid_path() {
        assert!(validate_data_dir(Path::new("/tmp/scp-test")).is_ok());
        assert!(validate_data_dir(Path::new("relative/path")).is_ok());
    }

    #[tokio::test]
    async fn running_node_in_memory_dispatch() {
        let node = start_node_in_memory(None).await.unwrap();
        let running = RunningNode::InMemory(node);
        assert!(
            running.relay_url().starts_with("ws://") || running.relay_url().starts_with("wss://")
        );
        assert!(running.did().starts_with("did:"));
        assert!(running.relay_port() > 0);
        assert!(!running.is_shutdown());
        running.shutdown();
        assert!(running.is_shutdown());
    }

    /// Sends a minimal HTTP/1.1 GET request and returns the status line.
    async fn http_get_status(addr: SocketAddr, path: &str) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let request =
            format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
        stream.write_all(request.as_bytes()).await.unwrap();

        let mut buf = vec![0u8; 4096];
        let n = stream.read(&mut buf).await.unwrap();
        let response = String::from_utf8_lossy(&buf[..n]);
        response.lines().next().unwrap_or("").to_owned()
    }

    #[tokio::test]
    async fn serve_background_binds_and_responds() {
        let node = start_node_in_memory(None).await.unwrap();

        // Serve on an OS-assigned port (port 0) so tests don't conflict.
        let addr = node
            .serve_background(Some(SocketAddr::from(([127, 0, 0, 1], 0))))
            .await
            .unwrap();

        assert_ne!(addr.port(), 0, "should bind to a real port");
        assert!(addr.ip().is_loopback(), "should be loopback");

        // http_url should reflect the bound address.
        let url = node.http_url().await;
        assert!(url.is_some(), "http_url should be Some after serve");
        let url = url.unwrap();
        assert!(
            url.starts_with("http://127.0.0.1:"),
            "expected http:// URL, got: {url}"
        );

        // HTTP GET to .well-known/scp should return HTTP 200.
        let status = http_get_status(addr, "/.well-known/scp").await;
        assert!(
            status.contains("200"),
            "expected 200 in status line, got: {status}"
        );

        node.shutdown();

        // After shutdown, yield briefly for the background task to clear state.
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    #[tokio::test]
    async fn serve_background_double_serve_returns_error() {
        let node = start_node_in_memory(None).await.unwrap();

        // First serve should succeed.
        let _addr = node
            .serve_background(Some(SocketAddr::from(([127, 0, 0, 1], 0))))
            .await
            .unwrap();

        // Second serve should fail.
        let result = node
            .serve_background(Some(SocketAddr::from(([127, 0, 0, 1], 0))))
            .await;
        assert!(result.is_err(), "double serve should fail");
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("already running"),
            "error should mention 'already running', got: {err_msg}"
        );

        node.shutdown();
    }

    #[tokio::test]
    async fn serve_background_shutdown_stops_server() {
        let node = start_node_in_memory(None).await.unwrap();

        let addr = node
            .serve_background(Some(SocketAddr::from(([127, 0, 0, 1], 0))))
            .await
            .unwrap();

        // Verify server is responsive.
        let status = http_get_status(addr, "/.well-known/scp").await;
        assert!(status.contains("200"), "expected 200, got: {status}");

        // Shutdown.
        node.shutdown();

        // Yield for the background task to drain.
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        // After shutdown, connection should fail.
        let result = tokio::time::timeout(
            std::time::Duration::from_millis(500),
            tokio::net::TcpStream::connect(addr),
        )
        .await;
        assert!(
            result.is_err() || result.unwrap().is_err(),
            "connection should fail after shutdown"
        );
    }

    // -----------------------------------------------------------------------
    // NodeIdentity (pre-existing identity) tests
    // -----------------------------------------------------------------------

    /// Helper: creates a test identity over the shared [`ConcreteDidMethod`]
    /// (`DidDht<FfiDhtClient>`) with the in-memory DHT arm (test-harness-only).
    async fn create_test_identity() -> NodeIdentity {
        use scp_dht::InMemoryDhtClient;
        use scp_identity::{DidCache, DidMethod};
        use scp_platform::testing::InMemoryKeyCustody;

        let custody = Arc::new(InMemoryKeyCustody::new());
        let pre_rotation_custody =
            Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());
        // The bridge's concrete DID method is `DidDht<FfiDhtClient>`; construct
        // its `InMemory` arm directly (a test seam, never `ClientDhtConfig`).
        let dht_client = Arc::new(FfiDhtClient::InMemory(InMemoryDhtClient::new()));
        let cache = Arc::new(DidCache::new());
        let sign_fn = ConcreteDidMethod::make_sign_fn(Arc::clone(&custody));
        let did_method = Arc::new(ConcreteDidMethod::with_client_and_signer(
            dht_client, cache, sign_fn,
        ));
        let (identity, document, _pre_rotation_handle) = did_method
            .create(custody.as_ref(), pre_rotation_custody.as_ref())
            .await
            .unwrap();

        NodeIdentity {
            identity,
            document,
            did_method,
        }
    }

    #[tokio::test]
    async fn node_in_memory_with_identity() {
        let test_id = create_test_identity().await;
        let expected_did = test_id.identity.did.clone();

        let node = start_node_in_memory(Some(test_id)).await.unwrap();

        assert_eq!(
            node.identity().did(),
            expected_did,
            "node should use the pre-existing identity's DID"
        );
        assert!(
            node.relay_url().starts_with("ws://") || node.relay_url().starts_with("wss://"),
            "expected ws(s):// URL, got: {}",
            node.relay_url()
        );
        assert_ne!(node.relay().bound_addr().port(), 0);

        node.shutdown();
    }

    #[tokio::test]
    async fn node_local_with_identity() {
        let test_id = create_test_identity().await;
        let expected_did = test_id.identity.did.clone();

        let tmp =
            std::env::temp_dir().join(format!("scp-test-node-local-id-{}", std::process::id()));
        // No passphrase needed when passing a pre-existing identity.
        let node = start_node_local(&tmp, Some(test_id), None).await.unwrap();

        assert_eq!(
            node.identity().did(),
            expected_did,
            "node should use the pre-existing identity's DID"
        );
        assert!(
            node.relay_url().starts_with("ws://") || node.relay_url().starts_with("wss://"),
            "expected ws(s):// URL, got: {}",
            node.relay_url()
        );
        assert_ne!(node.relay().bound_addr().port(), 0);

        // Storage and blob dirs should still be created.
        assert!(tmp.join("storage").is_dir(), "storage dir should exist");
        assert!(tmp.join("blobs.redb").exists(), "blobs.redb should exist");
        // No identity.key file when using pre-existing identity.
        assert!(
            !tmp.join("identity.key").exists(),
            "identity.key should NOT be created for pre-existing identity"
        );

        node.shutdown();
        // Cleanup
        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// Verifies that `start_node_local` without identity and without
    /// passphrase returns the dedicated `MissingPassphrase` variant —
    /// not a generic `Io` error — so the actionable message reaches callers.
    #[tokio::test]
    async fn node_local_without_identity_requires_passphrase() {
        let tmp =
            std::env::temp_dir().join(format!("scp-test-node-no-pass-{}", std::process::id()));
        let result = start_node_local(&tmp, None, None).await;

        let err = result.err().expect("should fail without passphrase");
        assert!(
            matches!(err, ServerError::MissingPassphrase),
            "expected ServerError::MissingPassphrase, got: {err:?}"
        );
        let user_msg = err.user_message();
        assert!(
            user_msg.contains("passphrase required"),
            "user_message should mention passphrase requirement, got: {user_msg}"
        );

        // Cleanup (data_dir may not have been fully created).
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
