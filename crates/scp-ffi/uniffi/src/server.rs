//! `UniFFI` bridge for relay and application node server startup.
//!
//! Wraps the shared startup code in `scp-ffi-common::server` for consumption
//! from Swift and Kotlin via `#[uniffi::export]` functions and objects.
//!
//! - [`RelayHandle`] -- opaque handle to a running relay server.
//! - [`NodeHandle`] -- opaque handle to a running application node (wraps
//!   both `InMemoryStorage` and `FilesystemStorage` variants via an internal
//!   enum).
//! - [`relay_start_in_memory`] / [`relay_start_local`] -- relay startup.
//! - [`node_start_in_memory`] / [`node_start_local`] -- node startup.
//!
//! Gated behind the `server` feature on `scp-ffi-common`. Not available for
//! WASM (ADR-034).

use std::sync::Arc;

use scp_ffi_common::server::{self, ServerError};
use scp_platform::testing::InMemoryStorage;

use crate::bridge::ScpError;
use crate::{decrement_handle_count, increment_handle_count};

// ---------------------------------------------------------------------------
// Error conversion
// ---------------------------------------------------------------------------

impl From<ServerError> for ScpError {
    fn from(e: ServerError) -> Self {
        match e {
            ServerError::Relay(inner) => Self::Transport {
                msg: format!("relay error: {inner}"),
                code: "SCP-TRANS-5050".to_owned(),
            },
            ServerError::Node(inner) => Self::Context {
                msg: format!("node error: {inner}"),
                code: "SCP-CTX-2050".to_owned(),
            },
            ServerError::Storage(inner) => Self::Context {
                msg: format!("storage error: {inner}"),
                code: "SCP-CTX-2051".to_owned(),
            },
            ServerError::Platform(inner) => Self::Context {
                msg: format!("platform error: {inner}"),
                code: "SCP-CTX-2053".to_owned(),
            },
            ServerError::Io(inner) => Self::Context {
                msg: format!("io error: {inner}"),
                code: "SCP-CTX-2052".to_owned(),
            },
        }
    }
}

// ---------------------------------------------------------------------------
// RelayHandle
// ---------------------------------------------------------------------------

/// Opaque handle to a running SCP relay server.
///
/// Created by [`relay_start_in_memory`] or [`relay_start_local`]. The relay
/// accepts WebSocket connections at [`relay_url`](Self::relay_url)
/// and can be gracefully stopped via [`shutdown`](Self::shutdown).
#[derive(uniffi::Object)]
pub struct RelayHandle {
    inner: server::RunningRelay,
}

#[uniffi::export]
impl RelayHandle {
    /// Returns the WebSocket URL clients should connect to
    /// (e.g., `ws://127.0.0.1:12345/scp/v1`).
    #[must_use]
    pub fn relay_url(&self) -> String {
        self.inner.relay_url().to_owned()
    }

    /// Returns the port the relay is listening on.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)] // UniFFI export methods cannot be const.
    pub fn relay_port(&self) -> u16 {
        self.inner.bound_addr().port()
    }

    /// Returns `true` if shutdown has already been signaled.
    #[must_use]
    pub fn is_shutdown(&self) -> bool {
        self.inner.is_shutdown()
    }

    /// Signals the relay server to stop accepting new connections.
    ///
    /// In-flight connection handlers drain naturally after shutdown is
    /// signaled -- they are not cancelled.
    pub fn shutdown(&self) {
        self.inner.shutdown();
    }
}

impl Drop for RelayHandle {
    fn drop(&mut self) {
        self.inner.shutdown();
        decrement_handle_count();
    }
}

// ---------------------------------------------------------------------------
// NodeHandle -- type-erased ApplicationNode wrapper
// ---------------------------------------------------------------------------

/// Internal enum that erases the `ApplicationNode<S>` generic parameter.
///
/// `ApplicationNode<S>` is generic over `S: Storage`. The `Storage` trait uses
/// RPITIT and is not object-safe, so we cannot use `dyn Storage`. Instead we
/// use a closed enum over the two concrete storage backends used by the shared
/// server code: `InMemoryStorage` and `FilesystemStorage`.
enum NodeInner {
    InMemory(scp_node::ApplicationNode<InMemoryStorage>),
    Filesystem(scp_node::ApplicationNode<scp_platform::filesystem::FilesystemStorage>),
}

impl NodeInner {
    fn relay_url(&self) -> &str {
        match self {
            Self::InMemory(n) => n.relay_url(),
            Self::Filesystem(n) => n.relay_url(),
        }
    }

    fn did(&self) -> &str {
        match self {
            Self::InMemory(n) => n.identity().did(),
            Self::Filesystem(n) => n.identity().did(),
        }
    }

    const fn relay_port(&self) -> u16 {
        match self {
            Self::InMemory(n) => n.relay().bound_addr().port(),
            Self::Filesystem(n) => n.relay().bound_addr().port(),
        }
    }

    fn is_shutdown(&self) -> bool {
        match self {
            Self::InMemory(n) => n.relay().shutdown_handle().is_shutdown(),
            Self::Filesystem(n) => n.relay().shutdown_handle().is_shutdown(),
        }
    }

    fn shutdown(&self) {
        match self {
            Self::InMemory(n) => n.shutdown(),
            Self::Filesystem(n) => n.shutdown(),
        }
    }
}

/// Opaque handle to a running SCP application node.
///
/// Created by [`node_start_in_memory`] or [`node_start_local`]. The node
/// includes a running relay server, a generated DID identity, and (optionally)
/// persistent storage. The HTTP server is **not** started automatically --
/// only the relay is bound.
#[derive(uniffi::Object)]
pub struct NodeHandle {
    inner: NodeInner,
}

#[uniffi::export]
impl NodeHandle {
    /// Returns the WebSocket URL clients should connect to for this node's
    /// relay (e.g., `ws://127.0.0.1:12345/scp/v1`).
    #[must_use]
    pub fn relay_url(&self) -> String {
        self.inner.relay_url().to_owned()
    }

    /// Returns the port the node's relay is listening on.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)] // UniFFI export methods cannot be const.
    pub fn relay_port(&self) -> u16 {
        self.inner.relay_port()
    }

    /// Returns the node's DID string (e.g., `did:dht:z6Mk...`).
    #[must_use]
    pub fn did(&self) -> String {
        self.inner.did().to_owned()
    }

    /// Returns `true` if shutdown has already been signaled.
    #[must_use]
    pub fn is_shutdown(&self) -> bool {
        self.inner.is_shutdown()
    }

    /// Signals the node to stop (relay + background tasks).
    pub fn shutdown(&self) {
        self.inner.shutdown();
    }
}

impl Drop for NodeHandle {
    fn drop(&mut self) {
        self.inner.shutdown();
        decrement_handle_count();
    }
}

// ---------------------------------------------------------------------------
// Free functions -- relay startup
// ---------------------------------------------------------------------------

/// Starts a relay with in-memory blob storage on an OS-assigned port.
///
/// Returns a [`RelayHandle`] whose `relay_url()` method returns the
/// WebSocket URL for clients.
///
/// # Swift
///
/// ```swift
/// let relay = try await relayStartInMemory()
/// print(relay.relayUrl()) // "ws://127.0.0.1:PORT/scp/v1"
/// relay.shutdown()
/// ```
#[uniffi::export]
pub async fn relay_start_in_memory() -> Result<Arc<RelayHandle>, ScpError> {
    let relay = server::start_relay_in_memory().await?;
    increment_handle_count();
    Ok(Arc::new(RelayHandle { inner: relay }))
}

/// Starts a relay with redb-backed blob storage on an OS-assigned port.
///
/// Opens (or creates) a redb database at `<data_dir>/blobs.redb`.
#[uniffi::export]
pub async fn relay_start_local(data_dir: String) -> Result<Arc<RelayHandle>, ScpError> {
    let relay = server::start_relay_local(std::path::Path::new(&data_dir)).await?;
    increment_handle_count();
    Ok(Arc::new(RelayHandle { inner: relay }))
}

// ---------------------------------------------------------------------------
// Free functions -- node startup
// ---------------------------------------------------------------------------

/// Starts a full application node with in-memory storage.
///
/// Auto-wires in-memory key custody, in-memory storage, in-memory DHT client,
/// self-signed TLS, and a relay on an OS-assigned port.
///
/// # Swift
///
/// ```swift
/// let node = try await nodeStartInMemory()
/// print(node.relayUrl()) // "ws://127.0.0.1:PORT/scp/v1"
/// print(node.did())      // "did:dht:z6Mk..."
/// node.shutdown()
/// ```
#[uniffi::export]
pub async fn node_start_in_memory() -> Result<Arc<NodeHandle>, ScpError> {
    let node = server::start_node_in_memory().await?;
    increment_handle_count();
    Ok(Arc::new(NodeHandle {
        inner: NodeInner::InMemory(node),
    }))
}

/// Starts a full application node with file-backed storage.
///
/// Opens (or creates) persistent storage at `<data_dir>/storage/` and a redb
/// blob database at `<data_dir>/blobs.redb`.
#[uniffi::export]
pub async fn node_start_local(data_dir: String) -> Result<Arc<NodeHandle>, ScpError> {
    let node = server::start_node_local(std::path::Path::new(&data_dir)).await?;
    increment_handle_count();
    Ok(Arc::new(NodeHandle {
        inner: NodeInner::Filesystem(node),
    }))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn rt() -> &'static tokio::runtime::Runtime {
        crate::runtime()
    }

    #[test]
    fn relay_in_memory_starts_and_returns_url() {
        let relay = rt().block_on(relay_start_in_memory()).unwrap();
        assert!(relay.relay_url().starts_with("ws://127.0.0.1:"));
        assert!(relay.relay_url().ends_with("/scp/v1"));
        assert!(relay.relay_port() > 0);
        assert!(!relay.is_shutdown());
        relay.shutdown();
        assert!(relay.is_shutdown());
    }

    #[test]
    fn relay_local_starts_and_returns_url() {
        let tmp =
            std::env::temp_dir().join(format!("scp-uniffi-relay-test-{}", std::process::id()));
        let relay = rt()
            .block_on(relay_start_local(tmp.to_string_lossy().into_owned()))
            .unwrap();
        assert!(relay.relay_url().starts_with("ws://127.0.0.1:"));
        assert!(relay.relay_port() > 0);
        relay.shutdown();
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn node_in_memory_starts_and_returns_did() {
        let node = rt().block_on(node_start_in_memory()).unwrap();
        let url = node.relay_url();
        assert!(
            url.starts_with("ws://") || url.starts_with("wss://"),
            "expected ws(s):// URL, got: {url}"
        );
        assert!(node.did().starts_with("did:"));
        assert!(node.relay_port() > 0);

        assert!(!node.is_shutdown());
        node.shutdown();
        assert!(node.is_shutdown());
    }

    #[test]
    fn node_local_starts_and_returns_did() {
        let tmp = std::env::temp_dir().join(format!("scp-uniffi-node-test-{}", std::process::id()));
        let node = rt()
            .block_on(node_start_local(tmp.to_string_lossy().into_owned()))
            .unwrap();
        let url = node.relay_url();
        assert!(
            url.starts_with("ws://") || url.starts_with("wss://"),
            "expected ws(s):// URL, got: {url}"
        );
        assert!(node.did().starts_with("did:"));
        assert!(node.relay_port() > 0);

        node.shutdown();
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn relay_shutdown_is_idempotent() {
        let relay = rt().block_on(relay_start_in_memory()).unwrap();
        relay.shutdown();
        relay.shutdown();
    }

    #[test]
    fn node_shutdown_is_idempotent() {
        let node = rt().block_on(node_start_in_memory()).unwrap();
        node.shutdown();
        node.shutdown();
    }
}
