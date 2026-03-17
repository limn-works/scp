//! napi-rs bridge for relay and application node server startup.
//!
//! Wraps the shared startup code in `scp-ffi-common::server` for consumption
//! from Node.js/Bun via napi-rs `#[napi]` types and functions.
//!
//! - [`NapiRelayHandle`] — opaque handle to a running relay server.
//! - [`NapiNodeHandle`] — opaque handle to a running application node (wraps
//!   both `InMemoryStorage` and `FilesystemStorage` variants via an internal
//!   enum).
//! - [`relay_start_in_memory`] / [`relay_start_local`] — relay startup.
//! - [`node_start_in_memory`] / [`node_start_local`] — node startup.
//!
//! Gated behind the `server` feature on `scp-ffi-common`. Not available for
//! WASM (ADR-034).

use napi::Error as NapiError;
use napi_derive::napi;

use scp_ffi_common::server::{self, RunningRelay, ServerError};
use scp_platform::testing::InMemoryStorage;

use crate::{decrement_handle_count, increment_handle_count};

// ---------------------------------------------------------------------------
// Error conversion
// ---------------------------------------------------------------------------

fn server_err(e: ServerError) -> NapiError {
    NapiError::from_reason(e.to_string())
}

// ---------------------------------------------------------------------------
// NapiRelayHandle
// ---------------------------------------------------------------------------

/// Opaque handle to a running SCP relay server.
///
/// Created by [`relay_start_in_memory`] or [`relay_start_local`]. The relay
/// accepts WebSocket connections at [`relay_url`](NapiRelayHandle::relay_url)
/// and can be gracefully stopped via [`shutdown`](NapiRelayHandle::shutdown).
#[napi]
pub struct NapiRelayHandle {
    inner: RunningRelay,
}

// napi-rs `#[napi(getter)]` generates wrappers that cannot be `const` or
// `#[must_use]`. These are framework constraints, not code quality issues.
#[napi]
#[allow(clippy::must_use_candidate, clippy::missing_const_for_fn)]
impl NapiRelayHandle {
    /// Returns the WebSocket URL clients should connect to
    /// (e.g., `ws://127.0.0.1:12345/scp/v1`).
    #[napi(getter)]
    pub fn relay_url(&self) -> String {
        self.inner.relay_url().to_owned()
    }

    /// Returns the port the relay is listening on.
    #[napi(getter)]
    pub fn relay_port(&self) -> u16 {
        self.inner.bound_addr().port()
    }

    /// Returns `true` if shutdown has already been signaled.
    #[napi(getter)]
    pub fn is_shutdown(&self) -> bool {
        self.inner.is_shutdown()
    }

    /// Signals the relay server to stop accepting new connections.
    ///
    /// In-flight connection handlers drain naturally after shutdown is
    /// signaled — they are not cancelled.
    #[napi]
    pub fn shutdown(&self) {
        self.inner.shutdown();
    }
}

impl Drop for NapiRelayHandle {
    fn drop(&mut self) {
        self.inner.shutdown();
        decrement_handle_count();
    }
}

// ---------------------------------------------------------------------------
// NapiNodeHandle — type-erased ApplicationNode wrapper
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
/// persistent storage. The HTTP server is **not** started automatically —
/// only the relay is bound.
#[napi]
pub struct NapiNodeHandle {
    inner: NodeInner,
}

#[napi]
#[allow(clippy::must_use_candidate, clippy::missing_const_for_fn)]
impl NapiNodeHandle {
    /// Returns the WebSocket URL clients should connect to for this node's
    /// relay (e.g., `ws://127.0.0.1:12345/scp/v1`).
    #[napi(getter)]
    pub fn relay_url(&self) -> String {
        self.inner.relay_url().to_owned()
    }

    /// Returns the port the node's relay is listening on.
    #[napi(getter)]
    pub fn relay_port(&self) -> u16 {
        self.inner.relay_port()
    }

    /// Returns the node's DID string (e.g., `did:dht:z6Mk...`).
    #[napi(getter)]
    pub fn did(&self) -> String {
        self.inner.did().to_owned()
    }

    /// Returns `true` if shutdown has already been signaled.
    #[napi(getter)]
    pub fn is_shutdown(&self) -> bool {
        self.inner.is_shutdown()
    }

    /// Signals the node to stop (relay + background tasks).
    ///
    /// In-flight connection handlers drain naturally after shutdown is
    /// signaled — they are not cancelled.
    #[napi]
    pub fn shutdown(&self) {
        self.inner.shutdown();
    }
}

impl Drop for NapiNodeHandle {
    fn drop(&mut self) {
        self.inner.shutdown();
        decrement_handle_count();
    }
}

// ---------------------------------------------------------------------------
// Free functions — relay startup
// ---------------------------------------------------------------------------

/// Starts a relay with in-memory blob storage on an OS-assigned port.
///
/// Returns a `NapiRelayHandle` whose `relayUrl` property contains the
/// WebSocket URL for clients. Suitable for tests and demos.
///
/// ```js
/// const relay = await relayStartInMemory();
/// console.log(relay.relayUrl); // "ws://127.0.0.1:PORT/scp/v1"
/// relay.shutdown();
/// ```
#[napi]
pub async fn relay_start_in_memory() -> napi::Result<NapiRelayHandle> {
    let relay = server::start_relay_in_memory().await.map_err(server_err)?;
    increment_handle_count();
    Ok(NapiRelayHandle { inner: relay })
}

/// Starts a relay with redb-backed blob storage on an OS-assigned port.
///
/// Opens (or creates) a redb database at `<data_dir>/blobs.redb`. Suitable
/// for local development with durable relay blob storage.
///
/// ```js
/// const relay = await relayStartLocal("/tmp/my-relay");
/// console.log(relay.relayUrl); // "ws://127.0.0.1:PORT/scp/v1"
/// relay.shutdown();
/// ```
#[napi]
pub async fn relay_start_local(data_dir: String) -> napi::Result<NapiRelayHandle> {
    let relay = server::start_relay_local(std::path::Path::new(&data_dir))
        .await
        .map_err(server_err)?;
    increment_handle_count();
    Ok(NapiRelayHandle { inner: relay })
}

// ---------------------------------------------------------------------------
// Free functions — node startup
// ---------------------------------------------------------------------------

/// Starts a full application node with in-memory storage.
///
/// Auto-wires in-memory key custody, in-memory storage, in-memory DHT client,
/// self-signed TLS, and a relay on an OS-assigned port.
///
/// ```js
/// const node = await nodeStartInMemory();
/// console.log(node.relayUrl); // "ws://127.0.0.1:PORT/scp/v1"
/// console.log(node.did);      // "did:dht:z6Mk..."
/// node.shutdown();
/// ```
#[napi]
pub async fn node_start_in_memory() -> napi::Result<NapiNodeHandle> {
    let node = server::start_node_in_memory().await.map_err(server_err)?;
    increment_handle_count();
    Ok(NapiNodeHandle {
        inner: NodeInner::InMemory(node),
    })
}

/// Starts a full application node with file-backed storage.
///
/// Opens (or creates) persistent storage at `<data_dir>/storage/` and a redb
/// blob database at `<data_dir>/blobs.redb`. A new DID identity is generated
/// on every invocation (key custody is in-memory — keys do not survive
/// process restarts).
///
/// ```js
/// const node = await nodeStartLocal("/tmp/my-node");
/// console.log(node.relayUrl); // "ws://127.0.0.1:PORT/scp/v1"
/// console.log(node.did);      // "did:dht:z6Mk..."
/// node.shutdown();
/// ```
#[napi]
pub async fn node_start_local(data_dir: String) -> napi::Result<NapiNodeHandle> {
    let node = server::start_node_local(std::path::Path::new(&data_dir))
        .await
        .map_err(server_err)?;
    increment_handle_count();
    Ok(NapiNodeHandle {
        inner: NodeInner::Filesystem(node),
    })
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
        assert!(
            relay.relay_url().starts_with("ws://127.0.0.1:"),
            "expected ws:// URL, got: {}",
            relay.relay_url()
        );
        assert!(
            relay.relay_url().ends_with("/scp/v1"),
            "expected /scp/v1 suffix, got: {}",
            relay.relay_url()
        );
        assert!(relay.relay_port() > 0, "port should be assigned");
        assert!(!relay.is_shutdown());
        relay.shutdown();
        assert!(relay.is_shutdown());
    }

    #[test]
    fn relay_local_starts_and_returns_url() {
        let tmp = std::env::temp_dir().join(format!("scp-napi-relay-test-{}", std::process::id()));
        let relay = rt()
            .block_on(relay_start_local(tmp.to_string_lossy().into_owned()))
            .unwrap();
        assert!(
            relay.relay_url().starts_with("ws://127.0.0.1:"),
            "expected ws:// URL, got: {}",
            relay.relay_url()
        );
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
            "expected ws(s):// URL, got: {url}",
        );
        assert!(
            node.did().starts_with("did:"),
            "expected did: prefix, got: {}",
            node.did()
        );
        assert!(node.relay_port() > 0);

        assert!(!node.is_shutdown());
        node.shutdown();
        assert!(node.is_shutdown());
    }

    #[test]
    fn node_local_starts_and_returns_did() {
        let tmp = std::env::temp_dir().join(format!("scp-napi-node-test-{}", std::process::id()));
        let node = rt()
            .block_on(node_start_local(tmp.to_string_lossy().into_owned()))
            .unwrap();
        let url = node.relay_url();
        assert!(
            url.starts_with("ws://") || url.starts_with("wss://"),
            "expected ws(s):// URL, got: {url}",
        );
        assert!(
            node.did().starts_with("did:"),
            "expected did: prefix, got: {}",
            node.did()
        );
        assert!(node.relay_port() > 0);

        node.shutdown();
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn relay_shutdown_is_idempotent() {
        let relay = rt().block_on(relay_start_in_memory()).unwrap();
        relay.shutdown();
        // Second shutdown should not panic.
        relay.shutdown();
    }

    #[test]
    fn node_shutdown_is_idempotent() {
        let node = rt().block_on(node_start_in_memory()).unwrap();
        node.shutdown();
        // Second shutdown should not panic.
        node.shutdown();
    }
}
