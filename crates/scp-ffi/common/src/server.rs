//! Shared relay and application node startup code for FFI bridges.
//!
//! Provides [`RunningRelay`] for standalone relay startup and
//! [`start_node_in_memory`] / [`start_node_local`] for full application node
//! startup. Both bind with sensible defaults and expose bound addresses for
//! FFI consumers. All functions bind to `127.0.0.1:0` (OS-assigned port) so
//! tests can run in parallel without port conflicts.
//!
//! [`start_node_local`] does not select or open a protocol-storage backend.
//! A caller selected one when it constructed its bridge instance
//! (`SCP.with_storage({...})` → `StorageConfig::InMemory` or
//! `StorageConfig::Sqlite`), and passes that same handle here, so a node's
//! event log, saga journal, `OpenMLS` store, and context snapshots all land in
//! one backend that instance already owns (spec §17.6). A caller wanting a node
//! on a different backend constructs a second bridge instance.
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
use scp_platform::EncryptedStorage;
use scp_platform::encrypting_adapter::EncryptingAdapter;
use scp_platform::file::FileKeyCustody;
use scp_platform::in_memory::InMemoryStorage;
use scp_platform::sqlite::SqliteStorage;

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

/// Ephemeral storage backend for [`start_node_in_memory`]: a durability-only
/// [`InMemoryStorage`] wrapped in an [`EncryptingAdapter`] under a per-node
/// `OsRng` AES-256-GCM key.
///
/// That wrap is what makes an ephemeral backend satisfy a sealed
/// `EncryptedStorage` bound, so this shipped `server`-feature front door goes
/// through a production [`Node::start`] constructor rather than
/// `Node::start_for_testing`. Spec §17.5 names this pattern canonical, and
/// it already appears in
/// [`build_event_log_provider`](crate::bridge_runtime::build_event_log_provider).
/// A bridge instance that selected in-memory storage holds
/// `Arc<EncryptedInMemoryStorage>`, so a node built here and a node built by
/// [`start_node_local`] on such an instance carry one `ApplicationNode` type and
/// land in one [`RunningNode`] variant.
///
/// **Do not copy this key lifetime onto a durable backend.** A per-node `OsRng`
/// key dies with its process, which costs nothing here because
/// [`InMemoryStorage`] dies with that same process. Wrapping a durable backend
/// under a per-process key would satisfy `EncryptedStorage` at compile time and
/// then lose every byte on restart, so a durable backend takes `SqliteStorage`
/// (`SQLCipher`, keyed from custody) instead.
pub type EncryptedInMemoryStorage = EncryptingAdapter<InMemoryStorage>;

/// Starts a full application node with encrypted in-memory storage.
///
/// Storage is an ephemeral [`EncryptedInMemoryStorage`] — `InMemoryStorage`
/// under a per-node `OsRng` AES-256-GCM [`EncryptingAdapter`] — so a node is
/// built through a production [`Node::start`] constructor and its
/// `EncryptedStorage` bound. Nothing on this path reaches
/// `Node::start_for_testing`.
///
/// When `identity` is `None` (auto-generate): available ONLY in a `testing`
/// build via a test-harness `ApplicationNode::dev` (in-memory key custody and
/// an [`InMemoryDhtClient`](scp_dht::InMemoryDhtClient) nullifier — no real DHT
/// network; its storage is that same encrypted in-memory backend). A shipped
/// (no-`testing`) build FAILS CLOSED with
/// [`ServerError::AutoGenerateUnavailable`] rather than run a nullifier-backed
/// node (ADR-062 §Decision 1/6); production callers pass an explicit
/// `Some(NodeIdentity)`. Self-signed TLS (localhost); relay bound to
/// `127.0.0.1:0` (OS-assigned port).
///
/// When `identity` is `Some(NodeIdentity)`, the node uses the pre-existing
/// identity instead of generating a fresh one. This enables identity
/// portability — the same DID persists across node restarts.
///
/// **This store is independent of whichever backend a caller's bridge instance
/// selected.** A node built here opens a fresh ephemeral store, so a caller on a
/// `SQLCipher` instance gets node state — identity records, TLS certificate
/// cache, credentials — that its database never receives and that process exit
/// discards, while that instance's supervisor, event log, and saga journal keep
/// writing to `SQLCipher`. A caller wanting one backend for both calls
/// [`start_node_local`] instead; this front door exists for callers who want an
/// ephemeral node whatever their instance holds.
///
/// The relay is started during construction. The HTTP server is **not** started;
/// call `ApplicationNode::serve` if HTTP endpoints are needed.
///
/// # Errors
///
/// Returns [`ServerError::Node`] if relay binding, identity generation, or TLS
/// provisioning fails.
pub async fn start_node_in_memory(
    identity: Option<NodeIdentity>,
) -> Result<scp_node::ApplicationNode<Arc<EncryptedInMemoryStorage>>, ServerError> {
    let node = match identity {
        // Auto-generate uses the test-harness `ApplicationNode::dev` (in-memory
        // DHT nullifier), compiled only under `testing` (ADR-062 §Decision 1).
        // A shipped build fails closed rather than running a nullifier-backed
        // node; callers pass an explicit `Some(NodeIdentity)` in production.
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
            //
            // Constructed via a PRODUCTION `Node::start` (spec §17.5: FFI
            // bridges must not rely on an `allow_unencrypted_storage` escape
            // hatch). An ephemeral `InMemoryStorage` is wrapped in
            // `EncryptingAdapter` under a fresh `OsRng` AES-256-GCM key, which
            // satisfies a sealed `EncryptedStorage` bound — a §17.5 canonical
            // pattern already used by `build_event_log_provider`.
            let mut storage_key = Zeroizing::new([0u8; 32]);
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut *storage_key);
            Node::start(NodeConfig {
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
                    Arc::new(EncryptingAdapter::new(InMemoryStorage::new(), storage_key)),
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
        "application node started (encrypted in-memory)"
    );
    Ok(node)
}

/// Logs a warning when `data_dir` holds a `storage/` subdirectory.
///
/// Earlier revisions of [`start_node_local`] opened a plaintext
/// `FilesystemStorage` there. This revision reads no such directory, so one left
/// behind by an earlier run is plaintext protocol state that no code path opens
/// and no upgrade converts. Silence would make an operator believe their
/// protocol state is encrypted while key-per-file plaintext sits beside it, so
/// this names a path an operator can delete.
///
/// A warning rather than an error: `storage/` is an ordinary directory name, and
/// refusing to start would break a caller who put something unrelated there.
fn warn_on_stale_plaintext_store(data_dir: &Path) {
    let stale = data_dir.join("storage");
    if stale.is_dir() {
        tracing::warn!(
            path = %stale.display(),
            "found a `storage/` directory a previous SCP revision wrote as \
             plaintext protocol state; this node reads whichever storage handle \
             its caller passed instead, so nothing opens, migrates, or deletes \
             that directory — delete it once you have salvaged anything you need"
        );
    }
}

/// Logs a warning when `data_dir` grants group or other any access on Unix.
///
/// [`start_node_local`] creates `data_dir` at mode `0o700`, and that mode
/// applies only to a directory this call creates. When `data_dir` already
/// exists, its existing mode stands, so `blobs.redb` — which carries blob
/// identifiers, sizes, timestamps, and TTLs in plaintext — can land in a
/// directory every local user traverses. `FileKeyCustody` sets `0o600` on
/// `identity.key` itself, so key material stays protected either way.
///
/// A warning rather than a `chmod`: tightening a directory a caller created
/// could break an operator who deliberately shares it with a backup account.
#[cfg(unix)]
fn warn_on_permissive_data_dir(data_dir: &Path) {
    use std::os::unix::fs::PermissionsExt;

    let Ok(metadata) = std::fs::metadata(data_dir) else {
        return;
    };
    let mode = metadata.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        tracing::warn!(
            path = %data_dir.display(),
            mode = format!("{mode:04o}"),
            "node data directory grants group or other access; `blobs.redb` \
             exposes blob identifiers, sizes, timestamps, and TTLs to every \
             local user who can traverse it — `chmod 700` closes that"
        );
    }
}

/// No-op counterpart of a Unix permission warning.
///
/// Windows expresses directory access through ACLs rather than through a mode
/// word, so a mode check has nothing to read there.
#[cfg(not(unix))]
const fn warn_on_permissive_data_dir(_data_dir: &Path) {}

/// Starts a full application node on a caller's own protocol-storage handle.
///
/// A caller chose its storage backend when it constructed its bridge instance
/// (`SCP.with_storage({...})` — encrypted in-memory or `SQLCipher`), and passes
/// that same handle as `storage`. This function opens no protocol store of its
/// own, so a node's context snapshots, Merkle event log, saga journal, and
/// `OpenMLS` store share one backend that instance already owns (spec §17.6).
/// Two consequences follow, and both are deliberate:
/// - A caller wanting a node on a different backend constructs a second bridge
///   instance. No per-node storage parameter exists to reach for.
/// - `SqliteStorage::new` takes a non-blocking exclusive lock on
///   `<dir>/scp.db.lock`, so a node opening its own `SQLCipher` database under a
///   directory its instance already uses would either fail that lock or run a
///   second, silently diverging store. Inheriting one handle removes both
///   failures.
///
/// `storage` is bound by [`EncryptedStorage`], so this function reaches
/// [`Node::start`] — a production constructor — and never
/// `Node::start_for_testing`.
///
/// `data_dir` names two node-local files and no protocol store:
/// - [`BlobStorageBackend::redb`] at `<data_dir>/blobs.redb` — a relay's
///   durable blob database, passed as a required selection (SCP-CAPINJECT-010).
///   redb applies no encryption of its own. Blob payloads are MLS ciphertext, so
///   content stays sealed, and blob identifiers, sizes, timestamps, and TTLs sit
///   in plaintext next to `identity.key`. Blob storage is a separately injected
///   capability, so `storage` being `EncryptedStorage` says nothing about it.
/// - `<data_dir>/identity.key` — a [`FileKeyCustody`] key file, read only
///   when `identity` is `None`. `FileKeyCustody::generate_keypair` appends
///   rather than replaces, so a caller whose instance selected ephemeral storage
///   adds one unreachable entry per process start (see *Identity modes*).
///
/// Also wired: self-signed TLS for a localhost domain, and a relay bound to
/// `127.0.0.1:0` (an OS-assigned port).
///
/// **No migration path (SCP is pre-release).** Earlier revisions of
/// `start_node_local` opened a plaintext `FilesystemStorage` at
/// `<data_dir>/storage/`. This revision never reads that directory. A data
/// directory holding one carries protocol state that no code path opens, and a
/// node starts against whatever `storage` contains instead. Finding one logs a
/// `tracing::warn!` naming its path, because plaintext protocol state that
/// nothing reads is still plaintext protocol state on disk. Delete it; nothing
/// converts it.
///
/// A relay starts during construction. An HTTP server does **not** start;
/// call `ApplicationNode::serve` when HTTP endpoints are needed.
///
/// # Identity modes
///
/// When `identity` is `Some(NodeIdentity)`, a node uses that pre-existing
/// identity. Identity portability follows — one DID persists across node
/// restarts and can be shared across FFI bridge instances.
///
/// When `identity` is `None`, a node creates or reloads a persistent identity
/// via [`FileKeyCustody`] backed by
/// `<data_dir>/identity.key`. A `passphrase` argument is required in this
/// mode, and no environment variable substitutes for it.
///
/// On first run, a new DID is generated and written to `storage`. On a later
/// run against that same `storage` handle, a node reloads that same DID. A
/// caller whose instance selected encrypted in-memory storage therefore gets a
/// fresh DID per process, because that backend keeps nothing across process
/// exit; a caller whose instance selected `SQLCipher` keeps its DID.
///
/// For fully ephemeral setups use [`start_node_in_memory`].
///
/// # Errors
///
/// Returns [`ServerError`] if:
/// - A data directory cannot be created ([`ServerError::Io`])
/// - A redb blob database cannot be opened ([`ServerError::Storage`])
/// - A key custody file cannot be opened ([`ServerError::Platform`])
/// - No passphrase arrived when `identity` is `None` ([`ServerError::MissingPassphrase`])
/// - Relay binding, identity generation, or TLS fails ([`ServerError::Node`])
pub async fn start_node_local<S>(
    data_dir: &Path,
    storage: S,
    identity: Option<NodeIdentity>,
    passphrase: Option<zeroize::Zeroizing<String>>,
) -> Result<scp_node::ApplicationNode<S>, ServerError>
where
    S: EncryptedStorage + 'static,
{
    use scp_identity::DidCache;

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

    warn_on_stale_plaintext_store(data_dir);
    warn_on_permissive_data_dir(data_dir);

    let blob_path = data_dir.join("blobs.redb");
    let blob_storage = BlobStorageBackend::redb(&blob_path)?;

    // Build the node via the ADR-052 flat-config front door (Phase B-P2). The
    // two identity arms differ only in their `IdentitySource`; the dropped
    // explicit `SelfSignedTlsProvider::new("localhost")` is reproduced by the
    // default `TlsMode::SelfSigned`. `Domain` is a publishing reach, so M2
    // requires `DhtMode::Production` (advisory in P1 — the in-memory DHT client
    // publishes nothing). Each arm moves `storage` into its own config, so both
    // arms build a config separately.
    let node = if let Some(id) = identity {
        Node::start(NodeConfig {
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
        // `Node::start`'s mandatory startup publish (a full relay node always
        // publishes; see `scp_node`) stays offline instead of timing out
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

        Node::start(NodeConfig {
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
        "application node started on a caller-supplied storage handle"
    );
    Ok(node)
}

// ---------------------------------------------------------------------------
// RunningNode — type-erased ApplicationNode wrapper (shared across bridges)
// ---------------------------------------------------------------------------

/// Type-erased wrapper over `ApplicationNode<S>` for every concrete storage
/// backend this module produces.
///
/// `ApplicationNode<S>` is generic over `S: Storage`. A `Storage` trait uses
/// RPITIT and is not object-safe, so `dyn Storage` does not compile. A closed
/// enum stands in. Its two variants are exactly two backends a bridge instance
/// can hold: an encrypted in-memory handle and a `SQLCipher` handle. Each
/// mirrors one arm of a bridge's `StorageConfig` selector, so no third arm can
/// appear here without a matching selector arm a caller can choose.
/// [`start_node_in_memory`] builds its own encrypted in-memory handle and lands
/// in that first variant, because both handles carry one type.
///
/// [`RunningRelay`] established this pattern — shared in `scp-ffi-common` so
/// each FFI bridge wraps one enum rather than duplicating it and its dispatch
/// methods.
pub enum RunningNode {
    /// An encrypted in-memory handle: either one [`start_node_in_memory`]
    /// builds for itself, or one [`start_node_local`] receives from a
    /// `StorageConfig::InMemory` bridge instance. Both are ephemeral.
    InMemoryEncrypted(scp_node::ApplicationNode<Arc<EncryptedInMemoryStorage>>),
    /// A caller's `SQLCipher` handle, produced by [`start_node_local`] on a
    /// `StorageConfig::Sqlite` bridge instance.
    Sqlite(scp_node::ApplicationNode<Arc<SqliteStorage>>),
}

/// Rejects, at compile time, a [`RunningNode`] variant whose storage backend
/// does not satisfy a sealed `EncryptedStorage` bound.
///
/// `ApplicationNode<S>` asks only for `S: Storage`, so nothing else stops a
/// future variant from carrying a plaintext backend. A plaintext backend would
/// force whichever front door produced it onto `Node::start_for_testing`, which
/// drops a bound that [`Node::start`] carries, which in turn would put
/// `ProtocolRepository::new_for_testing` back into this crate's shipped graph
/// through a `scp-node/allow_unencrypted_storage` dependency edge. A `match`
/// below is exhaustive, so adding a variant fails to compile here until its
/// backend satisfies `EncryptedStorage`, and an author reads that error instead
/// of a reviewer catching an omission.
///
/// `scripts/check-shipped-feature-graph.sh` proves a second half: no shipped
/// artifact resolves any of three `allow_unencrypted_storage` features, so a
/// shipped build compiles no `new_for_testing` at all.
#[allow(dead_code)]
const fn assert_running_node_backends_are_encrypted(node: &RunningNode) {
    const fn require_encrypted<S: EncryptedStorage>(_node: &scp_node::ApplicationNode<S>) {}
    match node {
        RunningNode::InMemoryEncrypted(n) => require_encrypted(n),
        RunningNode::Sqlite(n) => require_encrypted(n),
    }
}

/// Binds whichever `ApplicationNode<S>` a [`RunningNode`] holds to `$n` and
/// evaluates `$body` against it.
///
/// Every [`RunningNode`] method dispatches over both variants. Written out per
/// method, each body appears twice, and one copy can drift from its sibling —
/// drift of exactly that kind left only a `PyO3` bridge wired for webhook
/// events. One body per method removes that risk.
macro_rules! dispatch_running_node {
    ($self:expr, |$n:ident| $body:expr) => {
        match $self {
            RunningNode::InMemoryEncrypted($n) => $body,
            RunningNode::Sqlite($n) => $body,
        }
    };
}

impl RunningNode {
    /// Returns the WebSocket URL clients should connect to for this node's relay.
    #[must_use]
    pub fn relay_url(&self) -> &str {
        dispatch_running_node!(self, |n| n.relay_url())
    }

    /// Returns the node's DID string.
    #[must_use]
    pub fn did(&self) -> &str {
        dispatch_running_node!(self, |n| n.identity().did())
    }

    /// Returns the port the node's relay is listening on.
    #[must_use]
    pub const fn relay_port(&self) -> u16 {
        dispatch_running_node!(self, |n| n.relay().bound_addr().port())
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
        dispatch_running_node!(self, |n| n.bridge_token_hex())
    }

    /// Returns `true` if shutdown has already been signaled.
    #[must_use]
    pub fn is_shutdown(&self) -> bool {
        dispatch_running_node!(self, |n| n.relay().shutdown_handle().is_shutdown())
    }

    /// Signals the node to stop (relay + background tasks).
    pub fn shutdown(&self) {
        dispatch_running_node!(self, |n| n.shutdown());
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
        dispatch_running_node!(self, |n| n.wire_context_events(events))
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
        dispatch_running_node!(self, |n| n
            .enable_broadcast_projection_with_site(
                context_id,
                broadcast_key,
                admission,
                None,
                site_config,
            )
            .await)
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
        dispatch_running_node!(self, |n| n.commit_deploy(context_id, deploy_id).await)
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
        dispatch_running_node!(self, |n| n.rollback_deploy(context_id, deploy_id).await)
    }

    /// Deactivates HTTP broadcast projection for the given context.
    pub async fn disable_broadcast_projection(&self, context_id: &str) {
        dispatch_running_node!(self, |n| n.disable_broadcast_projection(context_id).await);
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
        dispatch_running_node!(self, |n| n.serve_background(bind_addr).await)
    }

    /// Returns the HTTP URL of the background server, or `None` if not serving.
    pub async fn http_url(&self) -> Option<String> {
        dispatch_running_node!(self, |n| n.http_url().await)
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

    use scp_platform::traits::Storage as _;

    /// Passphrase used by tests that exercise the `FileKeyCustody` path.
    fn test_passphrase() -> zeroize::Zeroizing<String> {
        zeroize::Zeroizing::new("test-passphrase".to_owned())
    }

    /// Builds a handle that a `StorageConfig::InMemory` bridge instance holds:
    /// an `Arc<EncryptingAdapter<InMemoryStorage>>` under a fresh random key.
    ///
    /// `start_node_local` receives this same value a bridge already owns, so
    /// these tests exercise a production call shape rather than a substitute.
    fn instance_in_memory_storage() -> Arc<EncryptingAdapter<InMemoryStorage>> {
        use rand_core::RngCore as _;
        let mut key = Zeroizing::new([0u8; 32]);
        rand_core::OsRng.fill_bytes(&mut *key);
        Arc::new(EncryptingAdapter::new(InMemoryStorage::new(), key))
    }

    /// Opens a handle that a `StorageConfig::Sqlite` bridge instance holds: an
    /// `Arc<SqliteStorage>` over `<dir>/scp.db`, keyed by a fixed test key.
    ///
    /// Each caller closes a returned handle before reopening that directory,
    /// because `SqliteStorage::new` takes a non-blocking exclusive lock on
    /// `<dir>/scp.db.lock`.
    fn instance_sqlite_storage(dir: &Path) -> Arc<SqliteStorage> {
        Arc::new(SqliteStorage::new(dir, &[0x11u8; 32]).expect("SQLCipher open must succeed"))
    }

    /// Returns a unique temp directory path per call, so parallel tests and
    /// repeated runs never share a data directory or a `SQLCipher` lock file.
    fn temp_dir_for(label: &str) -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!("scp-test-{label}-{}-{seq}", std::process::id()))
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
        let tmp = temp_dir_for("node-local");
        let node = start_node_local(
            &tmp,
            instance_in_memory_storage(),
            None,
            Some(test_passphrase()),
        )
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

    /// `start_node_local` opens no protocol store under `data_dir`. A node
    /// writes protocol state into whichever handle a caller passed in, and a
    /// plaintext `<data_dir>/storage/` directory, which earlier revisions
    /// created, never appears.
    #[tokio::test]
    async fn node_local_writes_into_the_callers_storage_and_opens_no_store_of_its_own() {
        let tmp = temp_dir_for("node-local-inherits");
        let storage = instance_in_memory_storage();

        // A caller keeps its own clone — exactly what a bridge instance does.
        let node = start_node_local(&tmp, Arc::clone(&storage), None, Some(test_passphrase()))
            .await
            .unwrap();

        let keys = storage.list_keys("").await.unwrap();
        assert!(
            !keys.is_empty(),
            "a node must persist protocol state into a caller-supplied storage \
             handle, yet that handle held no keys after startup"
        );

        assert!(
            !tmp.join("storage").exists(),
            "start_node_local must create no protocol store under a data \
             directory; found {}",
            tmp.join("storage").display()
        );

        node.shutdown();
        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// A `storage/` directory that an earlier SCP revision wrote neither blocks
    /// startup nor disappears. `start_node_local` warns about it and moves on,
    /// so an operator keeps whatever that directory holds and decides when to
    /// delete it.
    #[tokio::test]
    async fn node_local_leaves_a_stale_plaintext_store_untouched_and_still_starts() {
        let tmp = temp_dir_for("node-local-stale-store");
        let stale = tmp.join("storage");
        std::fs::create_dir_all(&stale).unwrap();
        let marker = stale.join("leftover-key");
        std::fs::write(&marker, b"plaintext protocol state").unwrap();

        let node = start_node_local(
            &tmp,
            instance_in_memory_storage(),
            None,
            Some(test_passphrase()),
        )
        .await
        .expect("a stale plaintext store must not block startup");

        assert!(
            marker.is_file(),
            "start_node_local must not delete a stale plaintext store; \
             {} disappeared",
            marker.display()
        );
        assert_eq!(
            std::fs::read(&marker).unwrap(),
            b"plaintext protocol state",
            "start_node_local must not rewrite a stale plaintext store"
        );

        node.shutdown();
        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// A caller whose instance selected `SQLCipher` keeps its node DID across
    /// restarts, because that DID persists in a caller's database rather than
    /// in a store a node opened for itself.
    #[tokio::test]
    async fn node_local_reuses_the_callers_sqlite_storage_across_restarts() {
        let tmp = temp_dir_for("node-persist");
        let db_dir = tmp.join("db");
        std::fs::create_dir_all(&db_dir).unwrap();

        let first_did;
        // First run — writes an identity into a caller's SQLCipher database.
        {
            let storage = instance_sqlite_storage(&db_dir);
            let node = start_node_local(&tmp, Arc::clone(&storage), None, Some(test_passphrase()))
                .await
                .unwrap();
            assert!(tmp.join("blobs.redb").exists());
            assert!(tmp.join("identity.key").exists());
            first_did = node.identity().did().to_owned();
            node.shutdown();
            // Drop the node so background tasks release the redb file lock.
            drop(node);
            // Release an advisory lock on `<db_dir>/scp.db.lock` before a
            // second open, which `SqliteStorage::new` takes non-blockingly.
            storage.close();
            drop(storage);
            // Yield to let the tokio runtime drain cancelled relay tasks.
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }

        // Second run — reopens that same database and reloads that same DID.
        {
            let storage = instance_sqlite_storage(&db_dir);
            let node = start_node_local(&tmp, Arc::clone(&storage), None, Some(test_passphrase()))
                .await
                .unwrap();
            assert_eq!(
                node.identity().did(),
                first_did,
                "second run against one caller storage handle must reload one DID"
            );
            node.shutdown();
            drop(node);
            storage.close();
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
        let running = RunningNode::InMemoryEncrypted(node);
        assert!(
            running.relay_url().starts_with("ws://") || running.relay_url().starts_with("wss://")
        );
        assert!(running.did().starts_with("did:"));
        assert!(running.relay_port() > 0);
        assert!(!running.is_shutdown());
        running.shutdown();
        assert!(running.is_shutdown());
    }

    /// Two variants that `start_node_local` produces answer every dispatch
    /// method an in-memory variant answers, so a bridge holding either one
    /// reads relay URL, DID, port, and shutdown state through identical calls.
    #[tokio::test]
    async fn running_node_caller_storage_variants_dispatch() {
        let tmp = temp_dir_for("running-node-encrypted");
        let node = start_node_local(
            &tmp,
            instance_in_memory_storage(),
            None,
            Some(test_passphrase()),
        )
        .await
        .unwrap();
        let running = RunningNode::InMemoryEncrypted(node);
        // Calls an exhaustive compile-time bound assertion with a real value,
        // so that assertion runs rather than sitting merely named.
        assert_running_node_backends_are_encrypted(&running);
        assert!(
            running.relay_url().starts_with("ws://") || running.relay_url().starts_with("wss://")
        );
        assert!(running.did().starts_with("did:"));
        assert!(running.relay_port() > 0);
        assert!(running.internal_relay_url().contains("/scp/v1"));
        assert!(!running.bridge_token_hex().is_empty());
        assert!(!running.is_shutdown());
        running.shutdown();
        assert!(running.is_shutdown());
        drop(running);
        let _ = std::fs::remove_dir_all(&tmp);

        let tmp = temp_dir_for("running-node-sqlite");
        let db_dir = tmp.join("db");
        std::fs::create_dir_all(&db_dir).unwrap();
        let storage = instance_sqlite_storage(&db_dir);
        let node = start_node_local(&tmp, Arc::clone(&storage), None, Some(test_passphrase()))
            .await
            .unwrap();
        let running = RunningNode::Sqlite(node);
        assert_running_node_backends_are_encrypted(&running);
        assert!(
            running.relay_url().starts_with("ws://") || running.relay_url().starts_with("wss://")
        );
        assert!(running.did().starts_with("did:"));
        assert!(running.relay_port() > 0);
        assert!(running.internal_relay_url().contains("/scp/v1"));
        assert!(!running.bridge_token_hex().is_empty());
        assert!(!running.is_shutdown());
        running.shutdown();
        assert!(running.is_shutdown());
        drop(running);
        storage.close();
        let _ = std::fs::remove_dir_all(&tmp);
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

        let tmp = temp_dir_for("node-local-id");
        // No passphrase needed when passing a pre-existing identity.
        let node = start_node_local(&tmp, instance_in_memory_storage(), Some(test_id), None)
            .await
            .unwrap();

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

        // A blob database still opens under a data directory; a protocol
        // store does not.
        assert!(tmp.join("blobs.redb").exists(), "blobs.redb should exist");
        assert!(
            !tmp.join("storage").exists(),
            "no protocol store belongs under a data directory"
        );
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
        let tmp = temp_dir_for("node-no-pass");
        let result = start_node_local(&tmp, instance_in_memory_storage(), None, None).await;

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
