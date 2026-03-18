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

use zeroize::Zeroizing;

use scp_ffi_common::server::{self, ServerError};
use scp_ffi_common::validate::{validate_context_id, validate_deploy_id, validate_did};
use scp_node::NodeError;
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
            ServerError::Node(inner) => Self::from(inner),
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

impl From<NodeError> for ScpError {
    fn from(e: NodeError) -> Self {
        match &e {
            NodeError::MissingField(_) | NodeError::InvalidConfig(_) => Self::Validation {
                msg: e.to_string(),
                code: "SCP-TRANS-5050".to_owned(),
            },
            NodeError::Identity(_) => Self::Identity {
                msg: e.to_string(),
                code: "SCP-TRANS-5051".to_owned(),
            },
            NodeError::Relay(_) => Self::Transport {
                msg: e.to_string(),
                code: "SCP-TRANS-5052".to_owned(),
            },
            NodeError::Storage(_) => Self::Context {
                msg: e.to_string(),
                code: "SCP-TRANS-5053".to_owned(),
            },
            NodeError::Serve(_) | NodeError::Nat(_) | NodeError::Tls(_) => Self::Transport {
                msg: e.to_string(),
                code: "SCP-TRANS-5054".to_owned(),
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

    async fn enable_broadcast_projection_with_site(
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

    async fn commit_deploy(&self, context_id: &str, deploy_id: &str) -> Result<usize, NodeError> {
        match self {
            Self::InMemory(n) => n.commit_deploy(context_id, deploy_id).await,
            Self::Filesystem(n) => n.commit_deploy(context_id, deploy_id).await,
        }
    }

    async fn rollback_deploy(&self, context_id: &str, deploy_id: &str) -> Result<(), NodeError> {
        match self {
            Self::InMemory(n) => n.rollback_deploy(context_id, deploy_id).await,
            Self::Filesystem(n) => n.rollback_deploy(context_id, deploy_id).await,
        }
    }

    async fn disable_broadcast_projection(&self, context_id: &str) {
        match self {
            Self::InMemory(n) => n.disable_broadcast_projection(context_id).await,
            Self::Filesystem(n) => n.disable_broadcast_projection(context_id).await,
        }
    }

    async fn serve_background(
        &self,
        bind_addr: Option<std::net::SocketAddr>,
    ) -> Result<std::net::SocketAddr, scp_node::NodeError> {
        match self {
            Self::InMemory(n) => n.serve_background(bind_addr).await,
            Self::Filesystem(n) => n.serve_background(bind_addr).await,
        }
    }

    async fn http_url(&self) -> Option<String> {
        match self {
            Self::InMemory(n) => n.http_url().await,
            Self::Filesystem(n) => n.http_url().await,
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

    /// Activates HTTP broadcast projection with site configuration.
    ///
    /// `broadcast_key_hex` is the 32-byte AES-256 broadcast key as a 64-char
    /// hex string. `author_did` is the DID of the key owner. `admission` is
    /// `"open"` or `"gated"`. `hostname` is the virtual host (RFC 1123).
    #[allow(clippy::too_many_arguments)]
    pub async fn enable_site_projection(
        &self,
        context_id: String,
        broadcast_key_hex: String,
        author_did: String,
        admission: String,
        hostname: String,
        index_path: Option<String>,
        max_assets_per_deploy: Option<u32>,
        max_deploy_size_bytes: Option<u64>,
        deploy_retention_count: Option<u32>,
        csp_override: Option<String>,
    ) -> Result<(), ScpError> {
        validate_context_id(&context_id)?;
        validate_did(&author_did)?;
        let key_vec =
            Zeroizing::new(
                hex::decode(&broadcast_key_hex).map_err(|e| ScpError::Validation {
                    msg: format!("invalid broadcast_key_hex: {e}"),
                    code: "SCP-TRANS-5060".to_owned(),
                })?,
            );
        let key_bytes: Zeroizing<[u8; 32]> =
            Zeroizing::new(<[u8; 32]>::try_from(key_vec.as_slice()).map_err(|_| {
                ScpError::Validation {
                    msg: "broadcast_key_hex must be exactly 64 hex characters (32 bytes)"
                        .to_owned(),
                    code: "SCP-TRANS-5060".to_owned(),
                }
            })?);

        let broadcast_key = scp_core::crypto::sender_keys::BroadcastKey::from_parts(
            scp_core::crypto::sender_keys::SenderKey::from_bytes(*key_bytes),
            0,
            author_did,
        );

        let adm = match admission.to_lowercase().as_str() {
            "open" => scp_core::context::broadcast::BroadcastAdmission::Open,
            "gated" => scp_core::context::broadcast::BroadcastAdmission::Gated,
            other => {
                return Err(ScpError::Validation {
                    msg: format!("admission must be \"open\" or \"gated\", got \"{other}\""),
                    code: "SCP-TRANS-5061".to_owned(),
                });
            }
        };

        let idx_path_str = index_path.as_deref().unwrap_or("/index.html");
        let content_path = scp_core::context::broadcast_content::ContentPath::new(idx_path_str)
            .map_err(|e| ScpError::Validation {
                msg: format!("invalid index_path: {e}"),
                code: "SCP-TRANS-5062".to_owned(),
            })?;

        let site_config = scp_node::projection::SiteConfig {
            hostname,
            index_path: content_path,
            max_assets_per_deploy: max_assets_per_deploy.map_or(10_000, |v| v as usize),
            max_deploy_size_bytes: max_deploy_size_bytes.unwrap_or(512 * 1024 * 1024),
            deploy_retention_count: deploy_retention_count.map_or(2, |v| v as usize),
            csp_override,
        };

        self.inner
            .enable_broadcast_projection_with_site(
                &context_id,
                broadcast_key,
                adm,
                Some(site_config),
            )
            .await
            .map_err(ScpError::from)
    }

    /// Commits a deploy for a projected context (section 18.11.11).
    ///
    /// Returns the number of assets in the committed deploy.
    pub async fn commit_deploy(
        &self,
        context_id: String,
        deploy_id: String,
    ) -> Result<u32, ScpError> {
        validate_context_id(&context_id)?;
        validate_deploy_id(&deploy_id)?;
        let count = self
            .inner
            .commit_deploy(&context_id, &deploy_id)
            .await
            .map_err(ScpError::from)?;
        u32::try_from(count).map_err(|_| ScpError::Validation {
            msg: format!("asset count {count} exceeds u32::MAX"),
            code: "SCP-TRANS-5063".to_owned(),
        })
    }

    /// Rolls back to a previous deploy for a projected context (section 18.11.11).
    pub async fn rollback_deploy(
        &self,
        context_id: String,
        deploy_id: String,
    ) -> Result<(), ScpError> {
        validate_context_id(&context_id)?;
        validate_deploy_id(&deploy_id)?;
        self.inner
            .rollback_deploy(&context_id, &deploy_id)
            .await
            .map_err(ScpError::from)
    }

    /// Deactivates HTTP broadcast projection for the given context.
    pub async fn disable_site_projection(&self, context_id: String) -> Result<(), ScpError> {
        validate_context_id(&context_id)?;
        self.inner.disable_broadcast_projection(&context_id).await;
        Ok(())
    }

    /// Starts the HTTP server in the background on the given bind address.
    ///
    /// Defaults to `127.0.0.1:8443` (loopback only) when `bind_addr` is `None`.
    /// Returns the actual bound address as a raw string (e.g., `"127.0.0.1:8443"`).
    /// Use [`http_url`](NodeHandle::http_url) for the full URL form
    /// (`"http://127.0.0.1:8443"`).
    ///
    /// **Note:** The background server does not support TLS. For production
    /// deployments requiring encryption, use the node binary's `serve()`
    /// with TLS configuration.
    ///
    /// Throws if the server is already running or binding fails.
    pub async fn serve(&self, bind_addr: Option<String>) -> Result<String, ScpError> {
        let addr = bind_addr
            .map(|s| {
                s.parse::<std::net::SocketAddr>().map_err(|_| {
                    let display = if s.len() > 128 { &s[..128] } else { &s };
                    ScpError::Validation {
                        msg: format!("invalid bind_addr: {display}"),
                        code: "SCP-TRANS-5070".to_owned(),
                    }
                })
            })
            .transpose()?;
        self.inner
            .serve_background(addr)
            .await
            .map(|a| a.to_string())
            .map_err(ScpError::from)
    }

    /// Returns the HTTP URL of the background server, or `None` if not serving.
    #[must_use]
    pub async fn http_url(&self) -> Option<String> {
        self.inner.http_url().await
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

    #[test]
    fn enable_site_projection_dispatches_through_node_inner() {
        let node = rt().block_on(server::start_node_in_memory()).unwrap();
        let inner = NodeInner::InMemory(node);
        let key = scp_core::crypto::sender_keys::BroadcastKey::from_parts(
            scp_core::crypto::sender_keys::SenderKey::from_bytes([0xAB; 32]),
            0,
            "did:dht:uniffi-test".to_owned(),
        );
        let site_config =
            scp_node::projection::SiteConfig::with_hostname("uniffi.example.com").unwrap();
        let result = rt().block_on(inner.enable_broadcast_projection_with_site(
            "uniffi-ctx",
            key,
            scp_core::context::broadcast::BroadcastAdmission::Open,
            Some(site_config),
        ));
        assert!(result.is_ok(), "enable should succeed: {result:?}");
        inner.shutdown();
    }

    #[test]
    fn commit_deploy_returns_error_for_unprojected_context() {
        let node = rt().block_on(server::start_node_in_memory()).unwrap();
        let inner = NodeInner::InMemory(node);
        let result = rt().block_on(inner.commit_deploy("no-such-ctx", "deploy-1"));
        assert!(
            result.is_err(),
            "commit_deploy should fail for unprojected context"
        );
        inner.shutdown();
    }

    #[test]
    fn rollback_deploy_returns_error_for_unprojected_context() {
        let node = rt().block_on(server::start_node_in_memory()).unwrap();
        let inner = NodeInner::InMemory(node);
        let result = rt().block_on(inner.rollback_deploy("no-such-ctx", "deploy-1"));
        assert!(
            result.is_err(),
            "rollback_deploy should fail for unprojected context"
        );
        inner.shutdown();
    }

    #[test]
    fn disable_site_projection_is_noop_for_unprojected_context() {
        let node = rt().block_on(server::start_node_in_memory()).unwrap();
        let inner = NodeInner::InMemory(node);
        rt().block_on(inner.disable_broadcast_projection("no-such-ctx"));
        // Should not panic.
        inner.shutdown();
    }

    #[test]
    fn node_error_maps_to_scp_error() {
        let err = NodeError::InvalidConfig("test config".into());
        let scp_err: ScpError = err.into();
        match scp_err {
            ScpError::Validation { msg, code } => {
                assert!(msg.contains("test config"), "msg={msg}");
                assert_eq!(code, "SCP-TRANS-5050");
            }
            other => panic!("expected Validation, got: {other:?}"),
        }
    }
}
