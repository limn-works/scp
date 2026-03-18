//! Shared relay and application node startup code for FFI bridges.
//!
//! Provides [`RunningRelay`] for standalone relay startup and
//! [`start_node_in_memory`] / [`start_node_local`] for full application node
//! startup. Both bind with sensible defaults and expose bound addresses for
//! FFI consumers. All functions bind to `127.0.0.1:0` (OS-assigned port) so
//! tests can run in parallel without port conflicts.
//!
//! Gated behind the `server` feature. Not available for WASM (ADR-034).

use std::net::SocketAddr;
use std::path::{Component, Path};
use std::sync::Arc;

use scp_node::NodeError;
use scp_platform::testing::InMemoryStorage;
use scp_transport::native::server::{RelayConfig, RelayError, RelayServer, ShutdownHandle};
use scp_transport::native::storage::{BlobStorageBackend, StorageError};

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

    /// A filesystem I/O operation failed (e.g., creating the data directory).
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// The platform storage backend could not be initialized.
    #[error("platform error: {0}")]
    Platform(#[from] scp_platform::error::PlatformError),
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
    std::fs::create_dir_all(data_dir)?;
    let db_path = data_dir.join("blobs.redb");
    let storage = BlobStorageBackend::redb(&db_path)?;
    start_relay_with(test_relay_config(), storage).await
}

// ---------------------------------------------------------------------------
// ApplicationNode startup
// ---------------------------------------------------------------------------

/// Starts a full application node with in-memory storage.
///
/// Auto-wires:
/// - [`InMemoryKeyCustody`](scp_platform::testing::InMemoryKeyCustody)
/// - [`InMemoryStorage`](scp_platform::testing::InMemoryStorage)
/// - [`InMemoryDhtClient`](scp_identity::InMemoryDhtClient) (no real DHT network)
/// - Self-signed TLS (for the localhost domain)
/// - Relay bound to `127.0.0.1:0` (OS-assigned port)
///
/// The relay is started during construction. The HTTP server is **not** started;
/// call [`ApplicationNode::serve`] if HTTP endpoints are needed.
///
/// # Errors
///
/// Returns [`ServerError::Node`] if relay binding, identity generation, or TLS
/// provisioning fails.
pub async fn start_node_in_memory()
-> Result<scp_node::ApplicationNode<InMemoryStorage>, ServerError> {
    let node = scp_node::ApplicationNode::dev(0).await?;
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
/// - [`InMemoryKeyCustody`](scp_platform::testing::InMemoryKeyCustody)
/// - [`FilesystemStorage`](scp_platform::filesystem::FilesystemStorage) at
///   `<data_dir>/storage/` — persistent key-value storage for protocol state
/// - [`BlobStorageBackend::redb`] at `<data_dir>/blobs.redb` — persistent
///   relay blob storage
/// - [`InMemoryDhtClient`](scp_identity::InMemoryDhtClient) (no real DHT
///   network — suitable for local-only use)
/// - Self-signed TLS (for the localhost domain)
/// - Relay bound to `127.0.0.1:0` (OS-assigned port)
///
/// The relay is started during construction. The HTTP server is **not** started;
/// call [`ApplicationNode::serve`] if HTTP endpoints are needed.
///
/// This is the zero-friction path for local development with durable relay
/// blob storage. The relay's redb database survives restarts, and the
/// protocol repository's filesystem storage is retained on disk — but
/// because a new DID is generated on every invocation (see below), prior
/// protocol state is orphaned under the old DID. Only relay blob storage
/// is DID-independent and genuinely persists across restarts.
///
/// # Identity persistence
///
/// A new DID identity is generated on every invocation because the key
/// custody backend is in-memory — private key material does not survive
/// process restarts. When a file-backed `KeyCustody` implementation is
/// available, this function should be updated to use
/// [`identity_with_storage`](scp_node::ApplicationNodeBuilder::identity_with_storage)
/// for stable DIDs across restarts.
///
/// For fully ephemeral setups use [`start_node_in_memory`].
///
/// # Errors
///
/// Returns [`ServerError`] if:
/// - The data directory cannot be created ([`ServerError::Io`])
/// - The filesystem storage cannot be initialized ([`ServerError::Platform`])
/// - The redb blob database cannot be opened ([`ServerError::Storage`])
/// - Relay binding, identity generation, or TLS fails ([`ServerError::Node`])
pub async fn start_node_local(
    data_dir: &Path,
) -> Result<scp_node::ApplicationNode<scp_platform::filesystem::FilesystemStorage>, ServerError> {
    use scp_identity::cache::SystemClock;
    use scp_identity::dht::DidDht;
    use scp_identity::{DidCache, InMemoryDhtClient};
    use scp_node::{ApplicationNodeBuilder, SelfSignedTlsProvider};
    use scp_platform::filesystem::FilesystemStorage;
    use scp_platform::testing::InMemoryKeyCustody;

    type DevDidDht = DidDht<InMemoryDhtClient, SystemClock>;

    // Validate and ensure data directory exists.
    validate_data_dir(data_dir)?;
    std::fs::create_dir_all(data_dir)?;

    // File-backed protocol storage under <data_dir>/storage/.
    let storage_dir = data_dir.join("storage");
    let storage = FilesystemStorage::new(&storage_dir)?;

    // Redb-backed blob storage for the relay.
    let blob_path = data_dir.join("blobs.redb");
    let blob_storage = BlobStorageBackend::redb(&blob_path)?;

    // In-memory key custody — keys are NOT persisted across restarts.
    // A new DID is generated on every invocation via `generate_identity_with`.
    // See `identity_with_storage` for the persistent alternative (requires
    // file-backed KeyCustody).
    let custody = Arc::new(InMemoryKeyCustody::new());
    let dht_client = Arc::new(InMemoryDhtClient::new());
    let cache = Arc::new(DidCache::new());
    let sign_fn = DevDidDht::make_sign_fn(Arc::clone(&custody));
    let did_method = Arc::new(DevDidDht::with_client_and_signer(
        dht_client, cache, sign_fn,
    ));

    let node = ApplicationNodeBuilder::new()
        .storage(storage)
        .blob_storage(blob_storage)
        .domain("localhost")
        .bind_addr(SocketAddr::from(([127, 0, 0, 1], 0)))
        .tls_provider(Arc::new(SelfSignedTlsProvider::new("localhost")))
        .generate_identity_with(custody, did_method)
        .build_for_testing()
        .await?;

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
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

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
        let node = start_node_in_memory().await.unwrap();
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
        let node = start_node_local(&tmp).await.unwrap();

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

        node.shutdown();
        // Cleanup
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[tokio::test]
    async fn node_local_reuses_data_dir_across_restarts() {
        let tmp =
            std::env::temp_dir().join(format!("scp-test-node-persist-{}", std::process::id()));

        // First run — creates storage directory and blob database.
        {
            let node = start_node_local(&tmp).await.unwrap();
            assert!(tmp.join("storage").is_dir());
            assert!(tmp.join("blobs.redb").exists());
            node.shutdown();
            // Drop the node so background tasks release the redb file lock.
            drop(node);
            // Yield to let the tokio runtime drain cancelled relay tasks.
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }

        // Second run — should open the same data directory without error.
        // Identity will be different (InMemoryKeyCustody generates fresh
        // keys each time), but the storage backends are reused.
        {
            let node = start_node_local(&tmp).await.unwrap();
            assert!(
                node.identity().did().starts_with("did:"),
                "should produce a valid DID"
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
        let node = start_node_in_memory().await.unwrap();
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
}
