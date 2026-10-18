//! Shared relay and application node startup code for FFI bridges.
//!
//! Provides [`RunningRelay`] for standalone relay startup, [`node_start`] for
//! production node startup from an `SCP` instance, and the development pair
//! `start_node_in_memory` / `start_node_local`, which compile only under
//! `test` or `feature = "testing"` (a bridge built without its own `testing`
//! feature returns [`ServerError::DevStartUnavailable`] from its dev-pair
//! exports). The relay and dev-pair starts bind `127.0.0.1:0` (OS-assigned
//! port) so tests can run in parallel without port conflicts.
//!
//! `start_node_local` does not select or open a protocol-storage backend.
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
use scp_node::{
    DhtMode, ExplicitIdentity, IdentitySource, NatSlot, Node, NodeConfig, NodeError, Reach,
    TlsMode, bound_relay_ws_url,
};
use scp_platform::EncryptedStorage;
use scp_platform::encrypting_adapter::EncryptingAdapter;
use scp_platform::file::FileKeyCustody;
use scp_platform::in_memory::InMemoryStorage;
use scp_platform::sqlite::SqliteStorage;

use crate::bridge_instance::{CoreFields, InstanceBorrower, NodeBinding};
use crate::dht::{DhtInitError, FfiDhtClient};
use crate::node_start_config::{
    FfiBlobBackend, FfiCorsOrigins, FfiDhtMode, FfiNat, FfiReach, FfiTlsMode, NodeStartConfig,
};
use scp_transport::native::server::{RelayConfig, RelayError, RelayServer, ShutdownHandle};
use scp_transport::native::storage::{BlobStorageBackend, StorageError};
use scp_transport::relay::push_gate::{LiveRelayUrl, RelayUrl};
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
/// When `Some(NodeIdentity)` is passed to `start_node_in_memory` or
/// `start_node_local`, the node uses this identity instead of generating
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

    /// No passphrase, or an empty one, was provided when one is required for
    /// persistent node identity.
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

    /// A dev-pair constructor (`node_start_in_memory`, `node_start_local`) was
    /// called on a bridge built without its `testing` feature. The dev pair is
    /// for development only, so a shipped bridge keeps the exported symbols and
    /// returns this error from each (sdk-common.md §"Node start error codes",
    /// `SCP-TRANS-5055`); `node_start` is the production entry.
    #[error("development node start is unavailable in this build; use node_start")]
    DevStartUnavailable,

    /// A [`NodeStartConfig`](crate::node_start_config::NodeStartConfig) failed
    /// to parse or failed a field check in [`node_start`]. The message names the
    /// field and the rule it broke; a field check never echoes a path.
    #[error("invalid node start config: {0}")]
    InvalidConfig(String),

    /// The operator identity a node start config names is not the identity
    /// the bridge resolved from this `SCP` instance.
    #[error("operator identity is not available to the node")]
    OperatorIdentityUnavailable,

    /// The node started, but the bridge could not wire the `SCP` instance's
    /// `Supervisor` to it. [`wire_supervisor_to_node`] shut the node down and
    /// removed it from the instance's node registry before returning this
    /// error (sdk-common.md §"Node start error codes", `SCP-TRANS-5056`).
    #[error("supervisor wiring failed: {0}")]
    SupervisorWiring(#[from] SupervisorWiringError),
}

/// The step at which [`wire_supervisor_to_node`] failed to wire an `SCP`
/// instance's `Supervisor` to a node it started.
#[derive(Debug, thiserror::Error)]
pub enum SupervisorWiringError {
    /// Another node of this instance is running and holds the `Supervisor`'s
    /// transport binding. One node at a time binds an instance's transport.
    #[error("another running node holds this instance's Supervisor transport")]
    NodeAlreadyBound,
    /// The connection to the node's relay failed.
    #[error("connecting to the node's relay failed: {0}")]
    RelayConnect(#[from] scp_transport::TransportError),
    /// After the bridge's attach step, the instance holds no `Supervisor`
    /// built with providers: the bridge's `Supervisor` build failed.
    #[error("the bridge could not attach a Supervisor to the instance")]
    SupervisorUnavailable,
    /// The instance refused the transport manager for the node's relay,
    /// because the instance is suspended or its transport lock is poisoned.
    #[error("installing the node's relay transport failed: {0}")]
    TransportInstall(#[from] crate::bridge_instance::TransportLockError),
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
            Self::DevStartUnavailable => {
                "development node start is unavailable in this build; use node_start".to_owned()
            }
            // The message names a field and a rule, never a path or an OS error.
            Self::InvalidConfig(msg) => format!("invalid node start config: {msg}"),
            Self::OperatorIdentityUnavailable => {
                "operator identity is not available to the node".to_owned()
            }
            Self::SupervisorWiring(step) => {
                format!(
                    "wiring the Supervisor to the node failed: {}",
                    step.user_message()
                )
            }
        }
    }
}

impl SupervisorWiringError {
    /// Returns a sanitized message that names the failed wiring step, so a
    /// caller can tell `NodeAlreadyBound` from `RelayConnect` under the one
    /// `SCP-TRANS-5056` code. The message carries no inner transport or lock
    /// error, because a transport error can name a relay address.
    #[must_use]
    pub const fn user_message(&self) -> &'static str {
        match self {
            Self::NodeAlreadyBound => {
                "another running node holds this instance's Supervisor transport"
            }
            Self::RelayConnect(_) => "connecting to the node's relay failed",
            Self::SupervisorUnavailable => {
                "the bridge could not attach a Supervisor to the instance"
            }
            Self::TransportInstall(_) => "installing the node's relay transport failed",
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
    ///
    /// Borrowed, unlike `RunningNode::relay_url`, which must return by value: a
    /// bare relay is bound to a fixed loopback address for its whole life, while
    /// a node's address is a live slot a NAT tier change re-points.
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

/// Starts a test relay on an OS-assigned loopback port, with zero delivery
/// jitter (deterministic timing), and returns a [`RunningRelay`].
///
/// The listener is bound first so the relay's URL names the real port from the
/// relay's first connection: the relay reserves the push routing ID of exactly
/// the URL [`RunningRelay::relay_url`] returns (§10.7.1 step 2), and answers a
/// PUBLISH there with `4063` instead of storing it.
async fn start_relay_with(storage: BlobStorageBackend) -> Result<RunningRelay, ServerError> {
    let listener = tokio::net::TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .map_err(|e| RelayError::BindFailed(e.to_string()))?;
    let relay_url = bound_relay_ws_url(
        listener
            .local_addr()
            .map_err(|e| RelayError::BindFailed(e.to_string()))?,
    );
    let config = RelayConfig {
        delivery_jitter_ms: 0,
        ..RelayConfig::defaults(LiveRelayUrl::new(
            RelayUrl::new(&relay_url).map_err(RelayError::from)?,
        ))
    };
    let server = RelayServer::new(config, Arc::new(storage));
    let (handle, addr) = server.start_with_listener(listener).await?;
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
    start_relay_with(BlobStorageBackend::in_memory()).await
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
    start_relay_with(storage).await
}

// ---------------------------------------------------------------------------
// ApplicationNode startup
// ---------------------------------------------------------------------------

/// Ephemeral storage backend for `start_node_in_memory`: a durability-only
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
/// `start_node_local` on such an instance carry one `ApplicationNode` type and
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
/// **Development only.** Alec ruled on 2026-08-10: "start local/start in mem
/// are for dev. all sdks still expose. we cut them from prod." This body
/// compiles only under `test` or `feature = "testing"`. Each bridge keeps its
/// exported `node_start_in_memory` symbol and, built without its own `testing`
/// feature, returns [`ServerError::DevStartUnavailable`] (`SCP-TRANS-5055`)
/// without calling here. Production callers use [`node_start`].
///
/// When `identity` is `None` (auto-generate), the node is a test-harness
/// `ApplicationNode::dev` (in-memory key custody and an
/// [`InMemoryDhtClient`](scp_dht::InMemoryDhtClient) nullifier — no real DHT
/// network; its storage is that same encrypted in-memory backend).
/// Self-signed TLS (localhost); relay bound to `127.0.0.1:0` (OS-assigned
/// port).
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
/// `start_node_local` instead; this front door exists for callers who want an
/// ephemeral node whatever their instance holds.
///
/// The relay is started during construction. The HTTP server is **not** started;
/// call `ApplicationNode::serve` if HTTP endpoints are needed.
///
/// # Errors
///
/// Returns [`ServerError::Node`] if relay binding, identity generation, or TLS
/// provisioning fails.
#[cfg(any(test, feature = "testing"))]
pub async fn start_node_in_memory(
    identity: Option<NodeIdentity>,
) -> Result<scp_node::ApplicationNode<Arc<EncryptedInMemoryStorage>>, ServerError> {
    let node = match identity {
        // Auto-generate uses the test-harness `ApplicationNode::dev` (in-memory
        // DHT nullifier), compiled only under `testing` (ADR-062 §Decision 1).
        None => scp_node::ApplicationNode::dev(0).await?,
        Some(id) => {
            // Migrated to the ADR-052 flat-config front door (Phase B-P2).
            // The dropped explicit `SelfSignedTlsProvider::new("localhost")` is
            // reproduced by the default `TlsMode::SelfSigned`. This node opts
            // into `DhtMode::Production` (M2 accepts `Disabled` for every
            // `Reach`, `Domain` included), which makes `Node::start` publish
            // through the caller's `did_method` and fail the start if that
            // publish fails.
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
/// Earlier revisions of `start_node_local` opened a plaintext
/// `FilesystemStorage` there. This revision reads no such directory, so one left
/// behind by an earlier run is plaintext protocol state that no code path opens
/// and no upgrade converts. Silence would make an operator believe their
/// protocol state is encrypted while key-per-file plaintext sits beside it, so
/// this names a path an operator can delete.
///
/// A warning rather than an error: `storage/` is an ordinary directory name, and
/// refusing to start would break a caller who put something unrelated there.
#[cfg(any(test, feature = "testing"))]
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
/// `start_node_local` creates `data_dir` at mode `0o700`, and that mode
/// applies only to a directory this call creates. When `data_dir` already
/// exists, its existing mode stands, so `blobs.redb` — which carries blob
/// identifiers, sizes, timestamps, and TTLs in plaintext — can land in a
/// directory every local user traverses. `FileKeyCustody` sets `0o600` on
/// `identity.key` itself, so key material stays protected either way.
///
/// A warning rather than a `chmod`: tightening a directory a caller created
/// could break an operator who deliberately shares it with a backup account.
#[cfg(all(unix, any(test, feature = "testing")))]
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
#[cfg(all(not(unix), any(test, feature = "testing")))]
const fn warn_on_permissive_data_dir(_data_dir: &Path) {}

/// Starts a full application node on a caller's own protocol-storage handle.
///
/// **Development only**, like `start_node_in_memory`: this body, and with it
/// the [`FileKeyCustody`] at `<data_dir>/identity.key` that the no-identity
/// arm builds, compiles only under `test` or `feature = "testing"`. A bridge
/// built without its own `testing` feature returns
/// [`ServerError::DevStartUnavailable`] (`SCP-TRANS-5055`) from its exported
/// `node_start_local` without calling here. Production callers use
/// [`node_start`].
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
/// For fully ephemeral setups use `start_node_in_memory`.
///
/// # Errors
///
/// Returns [`ServerError`] if:
/// - A data directory cannot be created ([`ServerError::Io`])
/// - A redb blob database cannot be opened ([`ServerError::Storage`])
/// - A key custody file cannot be opened ([`ServerError::Platform`])
/// - No passphrase, or an empty one, arrived when `identity` is `None`
///   ([`ServerError::MissingPassphrase`]); this check runs before the data
///   directory or any file in it is created
/// - Relay binding, identity generation, or TLS fails ([`ServerError::Node`])
#[cfg(any(test, feature = "testing"))]
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

    // A persisted identity needs a passphrase, and an empty one counts as
    // absent: Argon2id over "" seals the key file under a key anyone who reads
    // the salt can derive (spec §17.8). Checked before the data directory or
    // the blob database is created, so a refused call leaves nothing on disk.
    let passphrase = match identity {
        Some(_) => None,
        None => Some(
            passphrase
                .filter(|passphrase| !passphrase.is_empty())
                .ok_or(ServerError::MissingPassphrase)?,
        ),
    };

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
    // default `TlsMode::SelfSigned`. This node opts into `DhtMode::Production`
    // (M2 accepts `Disabled` for every `Reach`, `Domain` included), which makes
    // `Node::start` publish through `did_method` and fail the start if that
    // publish fails. Each arm moves
    // `storage` into its own config, so both arms build a config separately.
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
        // Persistent key custody — keys survive process restarts. The
        // passphrase was validated at entry, before any file was created.
        let passphrase = passphrase.ok_or(ServerError::MissingPassphrase)?;
        let key_path = data_dir.join("identity.key");
        // `FileKeyCustody::new` runs an Argon2id derivation (64 MiB, three
        // passes) and can wait up to 10 s on a file another process is
        // creating (spec §17.8), so it runs on the blocking pool rather than
        // on this future's worker thread. A panicked or cancelled task
        // surfaces as `ServerError::Io`.
        let key_custody = Arc::new(
            tokio::task::spawn_blocking(move || {
                scp_platform::file::FileKeyCustody::new(&key_path, &passphrase)
            })
            .await
            .map_err(std::io::Error::from)??,
        );

        // Build the node's DHT client for its DID method: the in-memory
        // §17.17.3 double, because this body compiles only under `testing`, so
        // the startup publish stays offline instead of timing out against live
        // Mainline. `Node::start` publishes, and fails on a failed publish,
        // because this call selects `DhtMode::Production` below. The client
        // backs both this node's DID publication and its `did:dht` resolution.
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
// node_start — production node start from an SCP instance (SCP-321)
// ---------------------------------------------------------------------------

/// The `SCP` instance's own protocol storage handle, which [`node_start`] gives
/// to the node (spec §17.6, first-party storage adapters).
///
/// Each arm mirrors one arm of a bridge's `StorageConfig` selector and one
/// [`RunningNode`] variant. A second store on the instance's directory would
/// fail, because `SqliteStorage::new` takes an exclusive lock on `scp.db.lock`.
pub enum InstanceStorage {
    /// A `StorageConfig::InMemory` instance's encrypted in-memory store. The
    /// node loses all state on drop, and [`node_start`] logs a warning.
    InMemoryEncrypted(Arc<EncryptedInMemoryStorage>),
    /// A `StorageConfig::Sqlite` instance's `SQLCipher` store.
    Sqlite(Arc<SqliteStorage>),
}

/// The longest DNS name `node_start` accepts (RFC 1035 §2.3.4).
const MAX_DOMAIN_LEN: usize = 253;

/// The longest DNS label `node_start` accepts (RFC 1035 §2.3.4).
const MAX_LABEL_LEN: usize = 63;

/// The longest blob storage path `node_start` accepts, matching
/// [`validate_data_dir`].
const MAX_BLOB_PATH_LEN: usize = 4096;

fn invalid(msg: impl Into<String>) -> ServerError {
    ServerError::InvalidConfig(msg.into())
}

/// Checks that `domain` is a DNS name: dot-separated labels of ASCII letters,
/// digits and inner hyphens, with no scheme, port, path or whitespace.
fn check_domain(domain: &str) -> Result<(), ServerError> {
    if domain.is_empty() || domain.len() > MAX_DOMAIN_LEN {
        return Err(invalid("reach.domain must be 1 to 253 bytes"));
    }
    let label_ok = |label: &str| {
        !label.is_empty()
            && label.len() <= MAX_LABEL_LEN
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    };
    if !domain.split('.').all(label_ok) {
        return Err(invalid(
            "reach.domain must be a DNS name of letters, digits, hyphens and dots, \
             with no scheme, port or path",
        ));
    }
    Ok(())
}

/// Checks a blob database path without touching the filesystem.
fn check_blob_path(path: &Path) -> Result<(), ServerError> {
    let os_str = path.as_os_str();
    if os_str.is_empty() || os_str.len() > MAX_BLOB_PATH_LEN {
        return Err(invalid("blob_storage.path must be 1 to 4096 bytes"));
    }
    if path.to_string_lossy().contains('\0') {
        return Err(invalid("blob_storage.path must not contain a NUL byte"));
    }
    if path.components().any(|c| matches!(c, Component::ParentDir)) {
        return Err(invalid(
            "blob_storage.path must not contain '..' components",
        ));
    }
    if path.file_name().is_none() {
        return Err(invalid("blob_storage.path must name a file"));
    }
    Ok(())
}

/// Lowers a [`FfiTlsMode`] after checking its fields.
fn lower_tls(tls: FfiTlsMode) -> Result<TlsMode, ServerError> {
    Ok(match tls {
        FfiTlsMode::SelfSigned {} => TlsMode::SelfSigned,
        FfiTlsMode::Acme { email } => {
            if let Some(email) = &email {
                let well_formed = email
                    .split_once('@')
                    .is_some_and(|(local, host)| !local.is_empty() && !host.is_empty())
                    && !email.chars().any(char::is_whitespace);
                if !well_formed {
                    return Err(invalid(
                        "tls.email must be an address of the form local@host, without whitespace",
                    ));
                }
            }
            TlsMode::Acme { email }
        }
        FfiTlsMode::Plaintext {} => TlsMode::Plaintext,
        FfiTlsMode::Terminated {} => TlsMode::Terminated,
    })
}

/// Lowers a [`FfiCorsOrigins`] after checking each origin. `AnyOrigin` lowers
/// to the core's `None`, which the core reads as `*`.
fn lower_cors(cors: FfiCorsOrigins) -> Result<Option<Vec<String>>, ServerError> {
    match cors {
        FfiCorsOrigins::AnyOrigin {} => Ok(None),
        FfiCorsOrigins::Allowlist { origins } => {
            for origin in &origins {
                if origin == "*" {
                    return Err(invalid(
                        "cors_origins.origins must not contain '*'; select any_origin instead",
                    ));
                }
                let shaped = origin
                    .split_once("://")
                    .is_some_and(|(scheme, host)| !scheme.is_empty() && !host.is_empty())
                    && !origin.chars().any(char::is_whitespace);
                if !shaped {
                    return Err(invalid(
                        "cors_origins.origins entries must be scheme://host origins without whitespace",
                    ));
                }
            }
            Ok(Some(origins))
        }
    }
}

/// Every [`NodeStartConfig`] field lowered to its core type, produced only by
/// [`validate_node_start`] and before any directory or file exists.
struct ValidatedNodeStart {
    reach: Reach,
    tls: TlsMode,
    cors_origins: Option<Vec<String>>,
    blob_storage: FfiBlobBackend,
    bind_addr: Option<SocketAddr>,
    http_bind_addr: Option<SocketAddr>,
    projection_rate_limit: Option<u32>,
}

/// Runs every check `node_start` makes before it touches the filesystem:
/// the field checks, `scp_node::validate_reach_and_tls`, and the operator
/// identity match.
fn validate_node_start(
    cfg: NodeStartConfig,
    operator_did: &str,
) -> Result<ValidatedNodeStart, ServerError> {
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

    let reach = match reach {
        FfiReach::Domain { domain } => {
            check_domain(&domain)?;
            Reach::Domain { domain }
        }
        FfiReach::NatTraversal {} => Reach::NatTraversal,
        FfiReach::Local {} => Reach::Local,
    };
    let tls = lower_tls(tls)?;
    scp_node::validate_reach_and_tls(&reach, &tls)?;
    let cors_origins = lower_cors(cors_origins)?;
    match &blob_storage {
        FfiBlobBackend::InMemory {} => {}
        FfiBlobBackend::Redb { path } | FfiBlobBackend::Sqlite { path } => {
            check_blob_path(path)?;
        }
    }
    if projection_rate_limit == Some(0) {
        return Err(invalid("projection_rate_limit must be greater than 0"));
    }
    // keri's scope ruling of 2026-10-13: the node publishes nothing.
    let FfiDhtMode::Disabled {} = dht;
    // `Auto` is the one arm, and the core's default.
    let (None | Some(FfiNat::Auto {})) = nat;
    if !identity.starts_with("did:") || identity.len() <= "did:".len() {
        return Err(invalid("identity must be a DID"));
    }
    if identity != operator_did {
        return Err(ServerError::OperatorIdentityUnavailable);
    }

    Ok(ValidatedNodeStart {
        reach,
        tls,
        cors_origins,
        blob_storage,
        bind_addr,
        http_bind_addr,
        projection_rate_limit,
    })
}

/// Creates a blob database's parent directory (mode `0o700` on Unix).
fn create_blob_parent(path: &Path) -> Result<(), ServerError> {
    let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) else {
        return Ok(());
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(parent)?;
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(parent)?;
    }
    Ok(())
}

/// Opens the selected blob backend, creating its parent directory first.
fn open_blob_backend(backend: &FfiBlobBackend) -> Result<BlobStorageBackend, ServerError> {
    Ok(match backend {
        FfiBlobBackend::InMemory {} => BlobStorageBackend::in_memory(),
        FfiBlobBackend::Redb { path } => {
            create_blob_parent(path)?;
            BlobStorageBackend::redb(path)?
        }
        FfiBlobBackend::Sqlite { path } => {
            create_blob_parent(path)?;
            BlobStorageBackend::sqlite(path)?
        }
    })
}

/// Builds the core [`NodeConfig`] from validated fields, the operator identity
/// and one storage handle. Generic over the handle, so each [`InstanceStorage`]
/// arm builds its config through one body.
fn node_config<S: EncryptedStorage>(
    v: ValidatedNodeStart,
    identity: NodeIdentity,
    blob_storage: BlobStorageBackend,
    storage: S,
) -> NodeConfig<FileKeyCustody, ConcreteDidMethod, S> {
    NodeConfig {
        tls: v.tls,
        dht: DhtMode::Disabled,
        bind_addr: v.bind_addr,
        http_bind_addr: v.http_bind_addr,
        cors_origins: v.cors_origins,
        projection_rate_limit: v.projection_rate_limit,
        nat: NatSlot::Auto,
        ..NodeConfig::defaults(
            v.reach,
            // `Explicit` carries no custody, so `K` is annotated to the
            // production `FileKeyCustody`, and no test-only nullifier type
            // appears on this shipped path (ADR-062 §Decision 6).
            IdentitySource::<FileKeyCustody, ConcreteDidMethod>::Explicit(Box::new(
                ExplicitIdentity {
                    identity: identity.identity,
                    document: identity.document,
                    did_method: identity.did_method,
                },
            )),
            storage,
            blob_storage,
        )
    }
}

/// Starts a production node from an `SCP` instance (construction.md §"Node
/// start — `NodeStartConfig`").
///
/// `identity` is the operator identity the bridge resolved from its registry
/// for `cfg.identity`, and `storage` is the instance's own store. Every field
/// check, `scp_node::validate_reach_and_tls`, and the identity match run
/// before any directory or file exists. Only then does `node_start` create the
/// blob directory, open the blob backend, and call [`Node::start`] with
/// `IdentitySource::Explicit` and `DhtMode::Disabled`.
///
/// # Errors
///
/// `error_codes::server_error_code` maps each error to its code
/// (sdk-common.md §"Node start error codes"):
/// - [`ServerError::InvalidConfig`] or [`ServerError::Node`] carrying
///   `NodeError::InvalidConfig`: a field check or the reach and TLS check failed
/// - [`ServerError::OperatorIdentityUnavailable`]: `cfg.identity` is not the
///   DID of `identity`
/// - [`ServerError::Io`] or [`ServerError::Storage`]: the blob directory or
///   backend could not be created or opened
/// - [`ServerError::Node`]: the core node failed to start
pub async fn node_start(
    cfg: NodeStartConfig,
    identity: NodeIdentity,
    storage: InstanceStorage,
) -> Result<RunningNode, ServerError> {
    let validated = validate_node_start(cfg, &identity.identity.did)?;
    let blob_storage = open_blob_backend(&validated.blob_storage)?;
    let node = match storage {
        InstanceStorage::InMemoryEncrypted(storage) => {
            tracing::warn!(
                "node_start on an in-memory SCP instance store: the node loses all state on drop"
            );
            RunningNode::InMemoryEncrypted(
                Node::start(node_config(validated, identity, blob_storage, storage)).await?,
            )
        }
        InstanceStorage::Sqlite(storage) => RunningNode::Sqlite(
            Node::start(node_config(validated, identity, blob_storage, storage)).await?,
        ),
    };
    tracing::info!(
        relay_url = %node.relay_url(),
        did = %node.did(),
        "node started on its SCP instance's storage handle"
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
/// `start_node_in_memory` builds its own encrypted in-memory handle and lands
/// in that first variant, because both handles carry one type.
///
/// [`RunningRelay`] established this pattern — shared in `scp-ffi-common` so
/// each FFI bridge wraps one enum rather than duplicating it and its dispatch
/// methods.
pub enum RunningNode {
    /// An encrypted in-memory handle: either one `start_node_in_memory`
    /// builds for itself, or one `start_node_local` receives from a
    /// `StorageConfig::InMemory` bridge instance. Both are ephemeral.
    InMemoryEncrypted(scp_node::ApplicationNode<Arc<EncryptedInMemoryStorage>>),
    /// A caller's `SQLCipher` handle, produced by `start_node_local` on a
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
/// method, each body appears twice, and one copy can drift from its sibling.
/// One body per method removes that risk.
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
    ///
    /// By value, mirroring `ApplicationNode::relay_url`: the node's address lives
    /// in a live slot that a NAT tier change advances, so a borrow cannot escape
    /// it and a `&str` could only be a copy that goes stale.
    #[must_use]
    pub fn relay_url(&self) -> String {
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
    /// `ws://{bound_addr}/scp/v1` from the relay's bound address — suitable
    /// for in-process relay connections that bypass TLS. An unspecified bind
    /// maps to loopback (construction.md §"Node start — `NodeStartConfig`").
    #[must_use]
    pub fn internal_relay_url(&self) -> String {
        bound_relay_ws_url(dispatch_running_node!(self, |n| n.relay().bound_addr()))
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
    /// A deploy whose blob scan matched no asset counts as a failed commit per
    /// §18.11.11 of `.docs/specs/18-addressability-and-deployment.md`, so the
    /// index this context already serves stays in place.
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

impl InstanceBorrower for RunningNode {
    /// Signals this node's relay and background tasks to stop, so a node stops
    /// writing through whatever storage handle it holds.
    fn stop(&self) {
        self.shutdown();
    }

    /// Reports whether a shutdown signal already reached this node.
    fn stopped(&self) -> bool {
        self.is_shutdown()
    }
}

/// Wraps a started node in an [`Arc`] and registers it with `core` as a
/// borrower of that instance's storage.
///
/// Every bridge node-start path (`node_start_on`, `node_start_in_memory_*`,
/// `node_start_local_*`, across `PyO3`, NAPI, and `UniFFI`) routes its node
/// through this one call, so registration is not a step a bridge author can
/// forget while still obtaining an `Arc<RunningNode>` for its handle type.
///
/// Registration is what makes `SCP.shutdown()` stop a node before
/// the durable store closer closes this instance's `SQLCipher` handle and
/// drops an advisory `flock(2)` on `{dir}/scp.db.lock`. See
/// [`InstanceBorrower`] for what that release corrupts when a node outlives
/// it, and [`CoreFields::register_borrower`] for how a registration races a
/// concurrent shutdown.
#[must_use]
pub fn register_node(core: &CoreFields, node: RunningNode) -> Arc<RunningNode> {
    let node = Arc::new(node);
    core.register_borrower(&node);
    node
}

/// Wires `core`'s `Supervisor` to a started, registered `node`, or stops and
/// unregisters `node`.
///
/// On failure this shuts `node` down, removes it from `core`'s node registry,
/// and returns [`ServerError::SupervisorWiring`] (construction.md §"Node
/// start — `NodeStartConfig`").
///
/// Every bridge node-start path (`node_start_on`, `node_start_in_memory_*`,
/// `node_start_local_*` on `PyO3`, napi-rs and `UniFFI`) runs this one wiring
/// step. Each bridge passes `node.internal_relay_url()` as `relay_url`, and
/// passes `ensure_supervisor`, the bridge's set-once `Supervisor` init, which
/// attaches a `Supervisor` with an unconfigured transport when the instance
/// holds none and does nothing when it holds one.
///
/// Steps, in order: refuse when another running node holds the binding;
/// connect twice to the relay with the node's bearer token, one adapter for
/// the `Supervisor`'s transport and one for the instance's transport manager,
/// because an adapter is not `Clone`; call `ensure_supervisor` with the
/// operator DID; then, holding [`CoreFields::node_binding`], check the binding
/// again, install the transport manager, bind the `Supervisor`'s
/// [`TransportSlot`](scp_core::context::supervisor::TransportSlot) to the
/// node's relay, and record the [`NodeBinding`]; last, register the operator
/// DID as a local DID. The binding works whichever call attached the
/// `Supervisor`, and that `Supervisor` keeps the DID its attaching call gave
/// its MLS factory. No step falls back to a `Supervisor` without relay
/// transport, and the function returns `Ok` only after its own bind.
///
/// # Errors
///
/// [`ServerError::SupervisorWiring`] naming the failed step.
pub async fn wire_supervisor_to_node<E>(
    core: &CoreFields,
    node: &Arc<RunningNode>,
    relay_url: &str,
    ensure_supervisor: E,
) -> Result<(), ServerError>
where
    E: FnOnce(&str),
{
    let Err(e) = wire_steps(core, node, relay_url, ensure_supervisor).await else {
        return Ok(());
    };
    tracing::warn!(error = %e, "node start: Supervisor wiring failed; shutting the node down");
    node.shutdown();
    core.unregister_borrower(node);
    Err(ServerError::SupervisorWiring(e))
}

/// Stops `node`, and unbinds `core`'s `Supervisor` transport from it when
/// `node` holds the binding.
///
/// Every bridge node handle's `shutdown` and `Drop` call this. The unbind puts
/// back the transport provider and the transport manager the binding
/// displaced, so a later node start binds again. When another node holds the
/// binding, or none does, only the stop happens.
pub fn stop_node(core: &CoreFields, node: &Arc<RunningNode>) {
    node.shutdown();
    let mut binding = core.node_binding();
    if !binding.as_ref().is_some_and(|b| b.is_for(node)) {
        return;
    }
    if let Some(b) = binding.take() {
        b.slot.replace(b.displaced_provider);
        core.restore_transport(&b.manager, b.displaced_manager);
    }
}

/// Returns whether `core` is wired to `node` as [`wire_supervisor_to_node`]
/// leaves it.
///
/// Wired means `core`'s binding record names `node`, `core`'s `Supervisor`
/// holds the recorded transport slot and that slot holds the recorded
/// relay provider, and `core`'s transport manager holds exactly `node`'s
/// internal relay URL.
#[must_use]
pub fn supervisor_wired_to(core: &CoreFields, node: &Arc<RunningNode>) -> bool {
    let bound = core.node_binding().as_ref().is_some_and(|b| {
        b.is_for(node)
            && b.slot.holds(&b.provider)
            && core
                .try_supervisor()
                .and_then(|s| s.transport_slot())
                .is_some_and(|slot| Arc::ptr_eq(&slot, &b.slot))
    });
    bound
        && core
            .with_transport(scp_transport::TransportManager::relay_urls)
            .is_ok_and(|urls| urls == [node.internal_relay_url()])
}

/// Returns [`SupervisorWiringError::NodeAlreadyBound`] when `binding` names a
/// live node.
fn refuse_live_binding(binding: Option<&NodeBinding>) -> Result<(), SupervisorWiringError> {
    if binding.is_some_and(NodeBinding::is_live) {
        return Err(SupervisorWiringError::NodeAlreadyBound);
    }
    Ok(())
}

/// The fallible steps of [`wire_supervisor_to_node`].
async fn wire_steps<E>(
    core: &CoreFields,
    node: &Arc<RunningNode>,
    relay_url: &str,
    ensure_supervisor: E,
) -> Result<(), SupervisorWiringError>
where
    E: FnOnce(&str),
{
    use scp_transport::relay::connection::{RelayUrlSource, SourcedRelayUrl};
    refuse_live_binding(core.node_binding().as_ref())?;
    let sourced = SourcedRelayUrl {
        url: relay_url.to_owned(),
        source: RelayUrlSource::Explicit,
    };
    let profile = scp_transport::profile::TransportProfile::platform_default();
    // Bearer-authenticated relays are WebSocket-only (spec §10.14.3 item 4);
    // the selector keeps this connect on the shared selection surface (ADR-037).
    let selector = core.transport_selector();
    let supervisor_adapter = selector
        .select_and_connect_with_bearer(&sourced, Some(node.bridge_token_hex()), Some(&profile))
        .await?;
    let manager_adapter = selector
        .select_and_connect_with_bearer(&sourced, Some(node.bridge_token_hex()), Some(&profile))
        .await?;
    ensure_supervisor(node.did());
    let supervisor = Arc::clone(
        core.try_supervisor()
            .ok_or(SupervisorWiringError::SupervisorUnavailable)?,
    );
    let slot = supervisor
        .transport_slot()
        .ok_or(SupervisorWiringError::SupervisorUnavailable)?;
    let provider: Arc<dyn scp_core::context::builder::ContextTransportProvider> = Arc::new(
        scp_transport::RelayTransportProvider::new(supervisor_adapter),
    );
    let manager = Arc::new(scp_transport::TransportManager::new(
        relay_url.to_owned(),
        manager_adapter,
    ));
    {
        // No `.await` in this block: the record, the manager slot and the
        // transport slot change together under the binding lock.
        let mut binding = core.node_binding();
        refuse_live_binding(binding.as_ref())?;
        let replaced_manager = core.swap_transport(Arc::clone(&manager))?;
        let replaced_provider = slot.replace(Arc::clone(&provider));
        // A stale binding's node stopped without unbinding; the transport it
        // displaced is the one a stop of this node puts back. A manager over
        // the stale node's relay URLs is that node's transport, even when a
        // resume rebuilt it as a new `Arc`.
        let (displaced_provider, displaced_manager) = match binding.take() {
            Some(stale) => {
                let manager_before = match replaced_manager {
                    Some(m) if !crate::bridge_instance::same_node_transport(&m, &stale.manager) => {
                        Some(m)
                    }
                    _ => stale.displaced_manager,
                };
                (stale.displaced_provider, manager_before)
            }
            None => (replaced_provider, replaced_manager),
        };
        let node_weak: std::sync::Weak<dyn crate::bridge_instance::InstanceBorrower> =
            Arc::downgrade(node) as _;
        *binding = Some(NodeBinding {
            node: node_weak,
            slot,
            provider,
            manager,
            displaced_provider,
            displaced_manager,
        });
    }
    supervisor
        .register_local_did(node.did().to_owned().into())
        .await;
    Ok(())
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

    /// The test relay reserves the push routing ID of the URL it hands to
    /// clients (§10.7.1 step 2), so a PUBLISH there is answered `4063` and never
    /// stored as a blob.
    #[tokio::test]
    async fn test_relay_reserves_the_push_routing_id_of_its_url() {
        use futures::{SinkExt as _, StreamExt as _};
        use tokio_tungstenite::tungstenite::Message;

        let relay = start_relay_in_memory().await.unwrap();
        let routing_id = scp_transport::relay::push_gate::RelayUrl::new(relay.relay_url())
            .unwrap()
            .push_routing_id();
        let (mut ws, _) = tokio_tungstenite::connect_async(relay.relay_url())
            .await
            .unwrap();
        let publish = scp_relay_client::ClientMessage::Publish {
            ref_id: None,
            routing_id,
            recipient_hint: None,
            blob_ttl: 3600,
            blob: vec![1],
        };
        ws.send(Message::Binary(publish.to_bytes().unwrap()))
            .await
            .unwrap();
        let frame = tokio::time::timeout(std::time::Duration::from_secs(5), ws.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let Message::Binary(bytes) = frame else {
            panic!("expected a binary relay frame, got {frame:?}");
        };
        let reply = scp_relay_client::RelayMessage::from_bytes(&bytes).unwrap();
        assert!(
            matches!(
                reply,
                scp_relay_client::RelayMessage::Err {
                    code: scp_relay_client::code::PUSH_NOT_SUPPORTED,
                    ..
                }
            ),
            "expected ERR 4063 PUSH_NOT_SUPPORTED, got {reply:?}"
        );
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
            storage.close().expect("close releases the lock");
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
            storage.close().expect("close releases the lock");
        }

        // Cleanup
        let _ = std::fs::remove_dir_all(&tmp);
    }

    // -----------------------------------------------------------------
    // Storage-borrower shutdown ordering (red-hat RED-1002)
    // -----------------------------------------------------------------

    /// A bridge instance for shutdown-ordering tests, holding one
    /// `Arc<SqliteStorage>` exactly as `PyBridgeInstance`,
    /// `NapiBridgeInstance`, and `UniffiBridgeInstance` hold theirs.
    ///
    /// Its `durable_store_closer` reproduces what all three shipped bridges
    /// return: a closer that calls [`SqliteStorage::close`], which drops an
    /// advisory `flock(2)` on `{dir}/scp.db.lock`. Before that call the closer
    /// records whether the registered node had already stopped, which is what
    /// makes ordering — not merely eventual shutdown — observable to a test.
    struct StorageOwningInstance {
        core: CoreFields,
        storage: Arc<SqliteStorage>,
        node: Arc<std::sync::Mutex<Option<std::sync::Weak<RunningNode>>>>,
        node_stopped_before_close: Arc<std::sync::atomic::AtomicBool>,
    }

    impl StorageOwningInstance {
        fn new(storage: Arc<SqliteStorage>) -> Self {
            Self {
                core: CoreFields::new(),
                storage,
                node: Arc::new(std::sync::Mutex::new(None)),
                node_stopped_before_close: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            }
        }

        /// Points this instance at `node` for observation only. Registration
        /// for shutdown purposes happens in [`register_node`], which every
        /// shipped bridge calls.
        fn observe(&self, node: &Arc<RunningNode>) {
            *self.node.lock().expect("observation mutex") = Some(Arc::downgrade(node));
        }

        /// Reports what the store closer saw when it ran.
        fn node_stopped_before_close(&self) -> bool {
            self.node_stopped_before_close
                .load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    #[async_trait::async_trait]
    impl crate::bridge_instance::BridgeInstanceCore for StorageOwningInstance {
        fn core(&self) -> &CoreFields {
            &self.core
        }

        fn durable_store_closer(&self) -> Option<crate::bridge_instance::DurableStoreCloser> {
            let node = Arc::clone(&self.node);
            let observed = Arc::clone(&self.node_stopped_before_close);
            let storage = Arc::clone(&self.storage);
            Some(Box::new(move || {
                let stopped = node
                    .lock()
                    .expect("observation mutex")
                    .as_ref()
                    .and_then(std::sync::Weak::upgrade)
                    .is_some_and(|node| InstanceBorrower::stopped(&*node));
                observed.store(stopped, std::sync::atomic::Ordering::SeqCst);
                // What every shipped bridge does here, and what makes
                // ordering load-bearing: releasing an advisory lock that
                // guards one writer per directory.
                storage.close()
            }))
        }
    }

    /// An instance stops a node it started before releasing a `SQLCipher`
    /// handle that node writes through.
    ///
    /// Without a borrower registry, `bridge_specific_shutdown` dropped an
    /// advisory `flock(2)` on `{dir}/scp.db.lock` while a live node kept
    /// writing through its clone of that same `Arc<SqliteStorage>` — a second
    /// process could then open one database alongside a first writer, which
    /// invites split-brain writes and WAL corruption (red-hat RED-1002).
    #[tokio::test]
    async fn instance_shutdown_stops_a_node_before_releasing_its_sqlite_lock() {
        use crate::bridge_instance::BridgeInstanceCore as _;

        let tmp = temp_dir_for("node-borrower-order");
        let db_dir = tmp.join("db");
        std::fs::create_dir_all(&db_dir).unwrap();

        let storage = instance_sqlite_storage(&db_dir);
        let instance = StorageOwningInstance::new(Arc::clone(&storage));

        let node = start_node_local(&tmp, Arc::clone(&storage), None, Some(test_passphrase()))
            .await
            .unwrap();
        let node = register_node(instance.core(), RunningNode::Sqlite(node));
        instance.observe(&node);
        assert!(
            !node.is_shutdown(),
            "a freshly started node must be running before its instance shuts down"
        );

        instance
            .shutdown(std::time::Duration::from_secs(10))
            .await
            .expect("a first shutdown must not report AlreadyShutDown");

        assert!(
            node.is_shutdown(),
            "an instance shutdown must stop a node that borrows its storage"
        );
        assert!(
            instance.node_stopped_before_close(),
            "a node must already be stopped when the durable store closer releases \
             an advisory SQLCipher lock, otherwise a live writer outlives that lock"
        );

        drop(node);
        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// Stopping borrowers first leaves intact what [`SqliteStorage::close`]
    /// exists for: a caller reopens one directory after `shutdown()` even
    /// while still holding its `SCP` handle.
    #[tokio::test]
    async fn a_sqlite_directory_reopens_after_an_instance_shutdown() {
        use crate::bridge_instance::BridgeInstanceCore as _;

        let tmp = temp_dir_for("node-borrower-reopen");
        let db_dir = tmp.join("db");
        std::fs::create_dir_all(&db_dir).unwrap();

        let storage = instance_sqlite_storage(&db_dir);
        let instance = StorageOwningInstance::new(Arc::clone(&storage));

        let node = start_node_local(&tmp, Arc::clone(&storage), None, Some(test_passphrase()))
            .await
            .unwrap();
        let node = register_node(instance.core(), RunningNode::Sqlite(node));
        instance.observe(&node);

        instance
            .shutdown(std::time::Duration::from_secs(10))
            .await
            .expect("a first shutdown must not report AlreadyShutDown");

        // Drop this node so its relay tasks and redb handle release, matching
        // an SDK caller who drops a node handle after `SCP.shutdown()`.
        drop(node);
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // `instance` and `storage` stay alive on purpose: `SqliteStorage::close`
        // exists so a reopen succeeds while a caller still holds its handle.
        let reopened = SqliteStorage::new(&db_dir, &[0x11u8; 32])
            .expect("a second SQLCipher open must succeed after an instance shutdown");
        reopened.close().expect("close releases the lock");

        drop(instance);
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
        storage.close().expect("close releases the lock");
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

    /// An empty passphrase is refused with `MissingPassphrase` before the data
    /// directory exists, so no `identity.key` sealed under "" and no blob
    /// database is left behind.
    #[tokio::test]
    async fn node_local_rejects_an_empty_passphrase_before_touching_disk() {
        let tmp = temp_dir_for("node-empty-pass");
        let result = start_node_local(
            &tmp,
            instance_in_memory_storage(),
            None,
            Some(zeroize::Zeroizing::new(String::new())),
        )
        .await;
        let created = tmp.exists();
        let _ = std::fs::remove_dir_all(&tmp);

        let err = result.err().expect("an empty passphrase must be refused");
        assert!(
            matches!(err, ServerError::MissingPassphrase),
            "expected ServerError::MissingPassphrase, got: {err:?}"
        );
        assert!(
            !created,
            "a refused start must not create the data directory {}",
            tmp.display()
        );
    }

    /// `FileKeyCustody::new` runs its Argon2id derivation on the blocking
    /// pool. With one worker thread, a derivation run inline would stall a
    /// sibling task for the whole derivation; the sibling's longest stall must
    /// stay under half of one derivation measured on this machine and build.
    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn node_local_opens_key_custody_on_the_blocking_pool() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::time::{Duration, Instant};

        let probe = temp_dir_for("custody-cost");
        std::fs::create_dir_all(&probe).expect("probe dir");
        let started = Instant::now();
        let probe_custody = FileKeyCustody::new(&probe.join("identity.key"), "probe-passphrase");
        let derivation = started.elapsed();
        drop(probe_custody.expect("probe custody opens"));
        let _ = std::fs::remove_dir_all(&probe);

        let stop = Arc::new(AtomicBool::new(false));
        let ticker_stop = Arc::clone(&stop);
        let ticker = tokio::spawn(async move {
            let mut last = Instant::now();
            let mut longest = Duration::ZERO;
            while !ticker_stop.load(Ordering::Acquire) {
                tokio::time::sleep(Duration::from_millis(2)).await;
                let now = Instant::now();
                longest = longest.max(now - last);
                last = now;
            }
            longest
        });

        let tmp = temp_dir_for("node-blocking-pool");
        let data_dir = tmp.clone();
        let started = tokio::spawn(async move {
            start_node_local(
                &data_dir,
                instance_in_memory_storage(),
                None,
                Some(zeroize::Zeroizing::new("blocking-pool-pass".to_owned())),
            )
            .await
        })
        .await
        .expect("start task joins");
        stop.store(true, Ordering::Release);
        let longest = ticker.await.expect("ticker joins");
        let node = started.expect("node starts");
        node.shutdown();
        let _ = std::fs::remove_dir_all(&tmp);

        assert!(
            longest < derivation / 2,
            "a sibling task stalled {longest:?}, against {derivation:?} for one derivation; \
             FileKeyCustody::new ran on the worker thread"
        );
    }

    // -----------------------------------------------------------------------
    // node_start (SCP-321)
    // -----------------------------------------------------------------------

    /// A config that starts a node on `Reach::Local` with a redb blob file at
    /// `blob_path`, for the operator `did`.
    fn local_start_config(did: &str, blob_path: &Path) -> NodeStartConfig {
        NodeStartConfig {
            reach: FfiReach::Local {},
            identity: did.to_owned(),
            blob_storage: FfiBlobBackend::Redb {
                path: blob_path.to_path_buf(),
            },
            tls: FfiTlsMode::Plaintext {},
            dht: FfiDhtMode::Disabled {},
            cors_origins: FfiCorsOrigins::Allowlist {
                origins: vec!["https://app.example.org".to_owned()],
            },
            bind_addr: Some(SocketAddr::from(([127, 0, 0, 1], 0))),
            http_bind_addr: Some(SocketAddr::from(([127, 0, 0, 1], 0))),
            nat: Some(FfiNat::Auto {}),
            projection_rate_limit: Some(10),
        }
    }

    /// Every config that fails validation returns its sdk-common code and
    /// leaves no directory or file at its blob path's parent.
    #[tokio::test]
    async fn node_start_rejects_an_invalid_config_before_creating_any_file() {
        use crate::error_codes::{IDENT_1063, STORAGE_8007, server_error_code};

        type Mutate = fn(&mut NodeStartConfig);
        let cases: [(&str, Mutate, &str); 9] = [
            (
                "acme on local reach",
                |c| c.tls = FfiTlsMode::Acme { email: None },
                STORAGE_8007,
            ),
            (
                "plaintext on domain reach",
                |c| {
                    c.reach = FfiReach::Domain {
                        domain: "node.example.org".to_owned(),
                    };
                },
                STORAGE_8007,
            ),
            (
                "domain with a scheme",
                |c| {
                    c.reach = FfiReach::Domain {
                        domain: "https://node.example.org".to_owned(),
                    };
                    c.tls = FfiTlsMode::SelfSigned {};
                },
                STORAGE_8007,
            ),
            (
                "malformed acme email",
                |c| {
                    c.reach = FfiReach::Domain {
                        domain: "node.example.org".to_owned(),
                    };
                    c.tls = FfiTlsMode::Acme {
                        email: Some("no-at-sign".to_owned()),
                    };
                },
                STORAGE_8007,
            ),
            (
                "wildcard cors entry",
                |c| {
                    c.cors_origins = FfiCorsOrigins::Allowlist {
                        origins: vec!["*".to_owned()],
                    };
                },
                STORAGE_8007,
            ),
            (
                "zero rate limit",
                |c| c.projection_rate_limit = Some(0),
                STORAGE_8007,
            ),
            (
                "blob path with a parent component",
                |c| {
                    let FfiBlobBackend::Redb { path } = &mut c.blob_storage else {
                        unreachable!("fixture selects redb");
                    };
                    *path = path.join("..").join("blobs.redb");
                },
                STORAGE_8007,
            ),
            (
                "identity that is not a DID",
                |c| c.identity = "operator".to_owned(),
                STORAGE_8007,
            ),
            (
                "another operator's DID",
                |c| c.identity = "did:dht:someone-else".to_owned(),
                IDENT_1063,
            ),
        ];

        for (label, mutate, code) in cases {
            let identity = create_test_identity().await;
            let tmp = temp_dir_for("node-start-invalid");
            let mut cfg = local_start_config(&identity.identity.did, &tmp.join("blobs.redb"));
            mutate(&mut cfg);

            let result = node_start(
                cfg,
                identity,
                InstanceStorage::InMemoryEncrypted(instance_in_memory_storage()),
            )
            .await;
            let created = tmp.exists();
            let _ = std::fs::remove_dir_all(&tmp);

            let err = result
                .err()
                .unwrap_or_else(|| panic!("{label}: start must fail"));
            assert_eq!(server_error_code(&err), code, "{label}: {err:?}");
            assert!(
                !created,
                "{label}: a refused start created {}",
                tmp.display()
            );
        }
    }

    /// A valid config starts a node on each instance storage arm, under the
    /// operator's DID, with the blob file at the configured path and an
    /// internal relay URL built from the bound address.
    #[tokio::test]
    async fn node_start_runs_a_node_on_each_instance_storage_arm() {
        for sqlite in [false, true] {
            let identity = create_test_identity().await;
            let did = identity.identity.did.clone();
            let tmp = temp_dir_for("node-start-ok");
            let blob_path = tmp.join("blobs").join("blobs.redb");
            let storage = if sqlite {
                std::fs::create_dir_all(&tmp).expect("instance dir");
                InstanceStorage::Sqlite(instance_sqlite_storage(&tmp))
            } else {
                InstanceStorage::InMemoryEncrypted(instance_in_memory_storage())
            };

            let node = node_start(local_start_config(&did, &blob_path), identity, storage)
                .await
                .expect("a valid config starts");

            assert_eq!(node.did(), did);
            assert_eq!(matches!(node, RunningNode::Sqlite(_)), sqlite);
            assert!(blob_path.exists(), "the redb blob file is created");
            assert_eq!(
                node.internal_relay_url(),
                format!("ws://127.0.0.1:{}/scp/v1", node.relay_port())
            );
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                let mode = std::fs::metadata(tmp.join("blobs"))
                    .expect("blob dir")
                    .permissions()
                    .mode();
                assert_eq!(mode & 0o777, 0o700, "blob dir mode {mode:o}");
            }
            node.shutdown();
            drop(node);
            let _ = std::fs::remove_dir_all(&tmp);
        }
    }

    /// The internal relay URL carries the bound host, brackets IPv6, and maps
    /// an unspecified bind to loopback of the same family.
    #[test]
    fn bound_relay_ws_url_uses_the_bound_address() {
        let cases = [
            ("127.0.0.1:4000", "ws://127.0.0.1:4000/scp/v1"),
            ("192.168.1.20:4000", "ws://192.168.1.20:4000/scp/v1"),
            ("0.0.0.0:4000", "ws://127.0.0.1:4000/scp/v1"),
            ("[::1]:4000", "ws://[::1]:4000/scp/v1"),
            ("[::]:4000", "ws://[::1]:4000/scp/v1"),
        ];
        for (addr, url) in cases {
            let addr: SocketAddr = addr.parse().expect("fixture address");
            assert_eq!(bound_relay_ws_url(addr), url);
        }
    }

    /// Starts an in-memory node and registers it on `core`, as every bridge
    /// node-start path does before it wires the `Supervisor`.
    async fn registered_node(core: &CoreFields) -> Arc<RunningNode> {
        let node = start_node_in_memory(None).await.unwrap();
        register_node(core, RunningNode::InMemoryEncrypted(node))
    }

    /// The provider the binding displaced, read from `core`'s record.
    fn displaced_provider(
        core: &CoreFields,
    ) -> Arc<dyn scp_core::context::builder::ContextTransportProvider> {
        Arc::clone(
            &core
                .node_binding()
                .as_ref()
                .expect("a wired node leaves a binding record")
                .displaced_provider,
        )
    }

    fn slot_of(core: &CoreFields) -> Arc<scp_core::context::supervisor::TransportSlot> {
        core.try_supervisor()
            .and_then(|s| s.transport_slot())
            .expect("a Supervisor built with providers holds a transport slot")
    }

    #[tokio::test]
    async fn wire_binds_a_supervisor_attached_before_the_node_start() {
        let core = CoreFields::with_supervisor(crate::bridge_instance::tests::test_supervisor());
        let node = registered_node(&core).await;

        wire_supervisor_to_node(&core, &node, &node.internal_relay_url(), |_| {})
            .await
            .expect("a node start binds a Supervisor that an earlier call attached");

        assert!(supervisor_wired_to(&core, &node));
        assert!(
            !slot_of(&core).holds(&displaced_provider(&core)),
            "the Supervisor's transport now reaches the node's relay"
        );
        stop_node(&core, &node);
    }

    /// A `configure_local_transport` that attaches a `Supervisor` after the
    /// node start's connects and before its attach step wins the set-once
    /// slot; the start still binds that `Supervisor` to the node's relay
    /// before it returns `Ok`.
    #[tokio::test]
    async fn wire_binds_a_supervisor_attached_by_a_racing_local_transport() {
        let core = CoreFields::new();
        let node = registered_node(&core).await;

        wire_supervisor_to_node(&core, &node, &node.internal_relay_url(), |_| {
            core.set_supervisor(crate::bridge_instance::tests::test_supervisor());
        })
        .await
        .expect("a racing attach leaves a Supervisor the start binds");

        assert!(
            supervisor_wired_to(&core, &node),
            "Ok means this start bound the Supervisor's transport to the node's relay"
        );
        assert!(!slot_of(&core).holds(&displaced_provider(&core)));
        stop_node(&core, &node);
    }

    #[tokio::test]
    async fn stop_node_restores_displaced_provider_and_manager_and_restart_binds_again() {
        let core = CoreFields::with_supervisor(crate::bridge_instance::tests::test_supervisor());
        let first = registered_node(&core).await;
        wire_supervisor_to_node(&core, &first, &first.internal_relay_url(), |_| {})
            .await
            .unwrap();
        let displaced = displaced_provider(&core);

        stop_node(&core, &first);

        assert!(first.is_shutdown());
        assert!(core.node_binding().is_none(), "a stop clears the binding");
        assert!(
            slot_of(&core).holds(&displaced),
            "a stop puts back the provider the start displaced"
        );
        assert_eq!(
            core.with_transport(|_| ()),
            Err(crate::bridge_instance::TransportLockError::NotInitialized),
            "a stop puts back the instance's empty transport manager"
        );
        assert!(!supervisor_wired_to(&core, &first));

        let second = registered_node(&core).await;
        wire_supervisor_to_node(&core, &second, &second.internal_relay_url(), |_| {})
            .await
            .expect("a start after a stop binds again");
        assert!(supervisor_wired_to(&core, &second));
        stop_node(&core, &second);
        assert!(slot_of(&core).holds(&displaced));
    }

    #[tokio::test]
    async fn wire_fails_closed_while_a_running_node_holds_the_binding() {
        let core = CoreFields::with_supervisor(crate::bridge_instance::tests::test_supervisor());
        let first = registered_node(&core).await;
        wire_supervisor_to_node(&core, &first, &first.internal_relay_url(), |_| {})
            .await
            .unwrap();
        let second = registered_node(&core).await;

        let err = wire_supervisor_to_node(&core, &second, &second.internal_relay_url(), |_| {})
            .await
            .expect_err("one node at a time binds an instance's transport");

        assert!(
            matches!(
                err,
                ServerError::SupervisorWiring(SupervisorWiringError::NodeAlreadyBound)
            ),
            "{err:?}"
        );
        assert!(second.is_shutdown(), "a refused start stops its node");
        assert!(
            !core.has_borrower(&second),
            "a refused start unregisters its node"
        );
        assert!(
            supervisor_wired_to(&core, &first),
            "a refused start leaves the first node's binding in place"
        );
        stop_node(&core, &first);
    }

    #[tokio::test]
    async fn stale_binding_of_a_shut_down_node_is_reclaimed() {
        let core = CoreFields::with_supervisor(crate::bridge_instance::tests::test_supervisor());
        let first = registered_node(&core).await;
        wire_supervisor_to_node(&core, &first, &first.internal_relay_url(), |_| {})
            .await
            .unwrap();
        let original = displaced_provider(&core);
        // Stopped without `stop_node`, so the record still names it.
        first.shutdown();

        let second = registered_node(&core).await;
        wire_supervisor_to_node(&core, &second, &second.internal_relay_url(), |_| {})
            .await
            .expect("a binding whose node stopped is stale and a start reclaims it");
        assert!(supervisor_wired_to(&core, &second));

        stop_node(&core, &second);
        assert!(
            slot_of(&core).holds(&original),
            "the provider before the stale binding is the one a stop puts back"
        );
        assert_eq!(
            core.with_transport(|_| ()),
            Err(crate::bridge_instance::TransportLockError::NotInitialized)
        );
    }

    /// A resume rebuilds the instance's transport manager over the same
    /// relay URLs as a new `Arc`. A start that reclaims the stale binding
    /// reads the rebuilt manager as the stale node's transport, so a stop of
    /// the new node puts back the manager from before the stale binding and
    /// not the rebuilt manager of the stopped node.
    #[tokio::test]
    async fn stale_binding_reclaim_recognises_a_manager_a_resume_rebuilt() {
        let core = CoreFields::with_supervisor(crate::bridge_instance::tests::test_supervisor());
        let first = registered_node(&core).await;
        wire_supervisor_to_node(&core, &first, &first.internal_relay_url(), |_| {})
            .await
            .unwrap();
        // Stopped without `stop_node`, so the record still names it.
        first.shutdown();
        let recorded = Arc::clone(
            &core
                .node_binding()
                .as_ref()
                .expect("the stale binding stays recorded")
                .manager,
        );
        let rebuilt = Arc::new(crate::bridge_instance::tests::manager_on(
            &first.internal_relay_url(),
        ));
        assert!(!Arc::ptr_eq(&rebuilt, &recorded));
        core.install_transport(rebuilt)
            .expect("a resume installs the rebuilt manager");

        let second = registered_node(&core).await;
        wire_supervisor_to_node(&core, &second, &second.internal_relay_url(), |_| {})
            .await
            .expect("a start reclaims the stale binding");
        assert!(
            core.node_binding()
                .as_ref()
                .is_some_and(|b| b.displaced_manager.is_none()),
            "the reclaim keeps the stale binding's displaced manager, not the rebuilt one"
        );

        stop_node(&core, &second);
        assert_eq!(
            core.with_transport(|_| ()),
            Err(crate::bridge_instance::TransportLockError::NotInitialized),
            "a stop puts back the empty manager from before the stale binding"
        );
    }

    /// Each `SupervisorWiringError` step gives the caller a distinct
    /// message, so a bridge test can tell `NodeAlreadyBound` from
    /// `RelayConnect` under the shared `SCP-TRANS-5056` code.
    #[test]
    fn supervisor_wiring_user_messages_name_distinct_steps() {
        let steps = [
            SupervisorWiringError::NodeAlreadyBound,
            SupervisorWiringError::RelayConnect(scp_transport::TransportError::ConnectionFailed(
                "ws://10.0.0.7:4000/scp/v1".to_owned(),
            )),
            SupervisorWiringError::SupervisorUnavailable,
            SupervisorWiringError::TransportInstall(
                crate::bridge_instance::TransportLockError::Poisoned,
            ),
        ];
        let messages: std::collections::HashSet<String> = steps
            .into_iter()
            .map(|step| ServerError::SupervisorWiring(step).user_message())
            .collect();
        assert_eq!(messages.len(), 4, "{messages:?}");
        assert!(
            messages.iter().all(|m| !m.contains("10.0.0.7")),
            "a step message carries no inner transport error: {messages:?}"
        );
    }

    #[tokio::test]
    async fn wire_fails_closed_when_no_supervisor_attaches() {
        let core = CoreFields::new();
        let node = registered_node(&core).await;

        let err = wire_supervisor_to_node(&core, &node, &node.internal_relay_url(), |_| {})
            .await
            .expect_err("a start whose attach step attached nothing fails closed");

        assert!(
            matches!(
                err,
                ServerError::SupervisorWiring(SupervisorWiringError::SupervisorUnavailable)
            ),
            "{err:?}"
        );
        assert!(node.is_shutdown());
        assert!(!core.has_borrower(&node));
        assert!(core.node_binding().is_none());
    }

    #[tokio::test]
    async fn stop_node_of_an_unbound_node_leaves_the_binding() {
        let core = CoreFields::with_supervisor(crate::bridge_instance::tests::test_supervisor());
        let bound = registered_node(&core).await;
        wire_supervisor_to_node(&core, &bound, &bound.internal_relay_url(), |_| {})
            .await
            .unwrap();
        let other = registered_node(&core).await;

        stop_node(&core, &other);

        assert!(other.is_shutdown());
        assert!(
            supervisor_wired_to(&core, &bound),
            "stopping a node that holds no binding unbinds nothing"
        );
        stop_node(&core, &bound);
    }
}
