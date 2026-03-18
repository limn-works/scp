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
use std::path::Path;
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

    // Ensure data directory exists.
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
        let node = start_node_in_memory().await.unwrap();

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
        let node = start_node_in_memory().await.unwrap();

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
        let node = start_node_in_memory().await.unwrap();

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
}
