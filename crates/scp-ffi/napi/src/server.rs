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
use zeroize::Zeroizing;

use scp_ffi_common::server::{self, RunningNode, RunningRelay, ServerError};
use scp_ffi_common::validate::{validate_context_id, validate_deploy_id, validate_did};
use scp_node::NodeError;

use crate::error::ScpNapiError;
use crate::{decrement_handle_count, increment_handle_count};

// ---------------------------------------------------------------------------
// Error conversion
// ---------------------------------------------------------------------------

fn server_err(e: ServerError) -> NapiError {
    tracing::error!(error = %e, "server operation failed");
    NapiError::from_reason(e.user_message())
}

fn node_err(e: NodeError) -> NapiError {
    tracing::error!(error = %e, "node operation failed");
    NapiError::from_reason("node operation failed")
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

/// Opaque handle to a running SCP application node.
///
/// Created by [`node_start_in_memory`] or [`node_start_local`]. The node
/// includes a running relay server, a generated DID identity, and (optionally)
/// persistent storage. The HTTP server is **not** started automatically —
/// only the relay is bound.
#[napi]
pub struct NapiNodeHandle {
    inner: RunningNode,
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

    /// Activates HTTP broadcast projection with site configuration.
    ///
    /// `broadcastKeyHex` is the 32-byte AES-256 broadcast key as a 64-char
    /// hex string. `authorDid` is the DID of the key owner. `admission` is
    /// `"open"` or `"gated"`. `hostname` is the virtual host (RFC 1123).
    #[napi]
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
        max_deploy_size_bytes: Option<i64>,
        deploy_retention_count: Option<u32>,
        csp_override: Option<String>,
    ) -> napi::Result<()> {
        validate_context_id(&context_id).map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;
        validate_did(&author_did).map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;
        let key_vec = Zeroizing::new(
            hex::decode(&broadcast_key_hex)
                .map_err(|e| NapiError::from_reason(format!("invalid broadcast_key_hex: {e}")))?,
        );
        let key_bytes: Zeroizing<[u8; 32]> =
            Zeroizing::new(<[u8; 32]>::try_from(key_vec.as_slice()).map_err(|_| {
                NapiError::from_reason(
                    "broadcast_key_hex must be exactly 64 hex characters (32 bytes)",
                )
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
                return Err(NapiError::from_reason(format!(
                    "admission must be \"open\" or \"gated\", got \"{other}\""
                )));
            }
        };

        let idx_path_str = index_path.as_deref().unwrap_or("/index.html");
        let content_path = scp_core::context::broadcast_content::ContentPath::new(idx_path_str)
            .map_err(|e| NapiError::from_reason(format!("invalid index_path: {e}")))?;

        let deploy_size = match max_deploy_size_bytes {
            Some(v) if v < 0 => {
                return Err(NapiError::from_reason(
                    "max_deploy_size_bytes must be non-negative",
                ));
            }
            Some(v) => v.unsigned_abs(),
            None => 512 * 1024 * 1024,
        };

        let site_config = scp_node::projection::SiteConfig {
            hostname,
            index_path: content_path,
            max_assets_per_deploy: max_assets_per_deploy.map_or(10_000, |v| v as usize),
            max_deploy_size_bytes: deploy_size,
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
            .map_err(node_err)
    }

    /// Commits a deploy for a projected context (section 18.11.11).
    ///
    /// Returns the number of assets in the committed deploy.
    #[napi]
    pub async fn commit_deploy(&self, context_id: String, deploy_id: String) -> napi::Result<u32> {
        validate_context_id(&context_id).map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;
        validate_deploy_id(&deploy_id).map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;
        let count = self
            .inner
            .commit_deploy(&context_id, &deploy_id)
            .await
            .map_err(node_err)?;
        u32::try_from(count)
            .map_err(|_| NapiError::from_reason(format!("asset count {count} exceeds u32::MAX")))
    }

    /// Rolls back to a previous deploy for a projected context (section 18.11.11).
    #[napi]
    pub async fn rollback_deploy(&self, context_id: String, deploy_id: String) -> napi::Result<()> {
        validate_context_id(&context_id).map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;
        validate_deploy_id(&deploy_id).map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;
        self.inner
            .rollback_deploy(&context_id, &deploy_id)
            .await
            .map_err(node_err)
    }

    /// Deactivates HTTP broadcast projection for the given context.
    #[napi]
    pub async fn disable_site_projection(&self, context_id: String) -> napi::Result<()> {
        validate_context_id(&context_id).map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;
        self.inner.disable_broadcast_projection(&context_id).await;
        Ok(())
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
        inner: RunningNode::InMemory(node),
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
        inner: RunningNode::Filesystem(node),
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

    #[test]
    fn enable_site_projection_dispatches_through_node_inner() {
        let node = rt().block_on(server::start_node_in_memory()).unwrap();
        let inner = RunningNode::InMemory(node);
        let key = scp_core::crypto::sender_keys::BroadcastKey::from_parts(
            scp_core::crypto::sender_keys::SenderKey::from_bytes([0xAB; 32]),
            0,
            "did:dht:napi-test".to_owned(),
        );
        let site_config =
            scp_node::projection::SiteConfig::with_hostname("napi.example.com").unwrap();
        let result = rt().block_on(inner.enable_broadcast_projection_with_site(
            "napi-ctx",
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
        let inner = RunningNode::InMemory(node);
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
        let inner = RunningNode::InMemory(node);
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
        let inner = RunningNode::InMemory(node);
        rt().block_on(inner.disable_broadcast_projection("no-such-ctx"));
        // Should not panic.
        inner.shutdown();
    }
}
