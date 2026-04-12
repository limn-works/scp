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

use scp_ffi_common::server::{self, RunningNode, ServerError};
use scp_ffi_common::validate::{validate_context_id, validate_deploy_id, validate_did};
use scp_node::NodeError;
use scp_transport::native::NativeRelayAdapter;
use scp_transport::relay::connection::{RelayUrlSource, SourcedRelayUrl};

use crate::bridge::{Identity, ScpError};
use crate::{decrement_handle_count, increment_handle_count};

// ---------------------------------------------------------------------------
// Error conversion
// ---------------------------------------------------------------------------

impl From<ServerError> for ScpError {
    fn from(e: ServerError) -> Self {
        let user_msg = e.user_message();
        tracing::debug!(error = %e, "server operation failed");
        match e {
            ServerError::Relay(_) => Self::Transport {
                msg: user_msg,
                code: "SCP-TRANS-5050".to_owned(),
            },
            ServerError::Node(inner) => Self::from(inner),
            ServerError::Storage(_) => Self::Context {
                msg: user_msg,
                code: "SCP-CTX-2051".to_owned(),
            },
            ServerError::Platform(_) => Self::Context {
                msg: user_msg,
                code: "SCP-CTX-2053".to_owned(),
            },
            ServerError::Io(_) => Self::Context {
                msg: user_msg,
                code: "SCP-CTX-2052".to_owned(),
            },
        }
    }
}

impl From<NodeError> for ScpError {
    fn from(e: NodeError) -> Self {
        tracing::debug!(error = %e, "node operation failed");
        match e {
            NodeError::MissingField(_) | NodeError::InvalidConfig(_) => Self::Validation {
                msg: "node configuration error".to_owned(),
                code: "SCP-TRANS-5050".to_owned(),
            },
            NodeError::Identity(_) => Self::Identity {
                msg: "node identity operation failed".to_owned(),
                code: "SCP-TRANS-5051".to_owned(),
            },
            NodeError::Relay(_) => Self::Transport {
                msg: "node relay error".to_owned(),
                code: "SCP-TRANS-5052".to_owned(),
            },
            NodeError::Storage(_) => Self::Context {
                msg: "node storage error".to_owned(),
                code: "SCP-TRANS-5053".to_owned(),
            },
            NodeError::Serve(_) | NodeError::Nat(_) | NodeError::Tls(_) => Self::Transport {
                msg: "node network error".to_owned(),
                code: "SCP-TRANS-5054".to_owned(),
            },
        }
    }
}

/// Auto-wires the global [`ContextManager`] with relay transport after
/// node startup.
///
/// Connects to the node's local relay (with bearer token authentication)
/// and initializes the `ContextManager` with `MlsCryptoProvider` and
/// `RelayTransportProvider` so that context operations (create, join, send)
/// work immediately. If the `ContextManager` was already initialized
/// (e.g., by a prior `configure_relay_transport` or `context_create` call),
/// this is a no-op — the `OnceLock` ensures first-writer-wins semantics.
///
/// The `bridge_token` is required because `ApplicationNode` relays enforce
/// `Authorization: Bearer <token>` on all WebSocket connections.
///
/// Also registers the node's DID as a local DID on the `ContextManager`
/// for defense-in-depth.
///
/// Best-effort: logs a warning if the relay connection fails rather than
/// blocking node startup.
async fn auto_wire_context_manager(did: &str, relay_url: &str, bridge_token: Zeroizing<String>) {
    let sourced = SourcedRelayUrl {
        url: relay_url.to_owned(),
        source: RelayUrlSource::Explicit,
    };
    let profile = scp_transport::profile::TransportProfile::platform_default();
    match NativeRelayAdapter::connect_sourced_with_bearer(
        &sourced,
        Some(bridge_token),
        Some(&profile),
    )
    .await
    {
        Ok(adapter) => {
            crate::runtime::init_context_manager_with_relay_transport(did, adapter);
        }
        Err(e) => {
            tracing::warn!(
                error = %e,
                relay_url = %relay_url,
                "auto_wire_context_manager: failed to connect to node relay — \
                 context operations may fail until transport is configured manually"
            );
            // Fall back to initializing with MLS crypto (not FfiBridgeCrypto
            // no-op) so that at least the ContextManager exists with real
            // crypto for the identity's DID, matching PyO3/NAPI behavior.
            crate::runtime::init_context_manager_with_did(did);
        }
    }
    // Always register the node's DID as a local DID for defense-in-depth.
    if let Ok(mgr) = crate::runtime::context_manager() {
        mgr.register_local_did(did.to_owned().into()).await;
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

/// Opaque handle to a running SCP application node.
///
/// Created by [`node_start_in_memory`] or [`node_start_local`]. The node
/// includes a running relay server, a generated DID identity, and (optionally)
/// persistent storage. The HTTP server is **not** started automatically --
/// only the relay is bound.
#[derive(uniffi::Object)]
pub struct NodeHandle {
    inner: RunningNode,
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
    /// Three resolution modes:
    /// 1. Both `broadcast_key_hex` **and** `author_did` provided — uses the
    ///    explicit key with epoch 0.
    /// 2. Only `author_did` provided — auto-resolves the broadcast key
    ///    using that DID (useful when the author identity differs from the
    ///    node identity).
    /// 3. Neither provided — auto-resolves using the node's identity DID.
    ///
    /// Providing `broadcast_key_hex` without `author_did` is an error.
    ///
    /// `admission` is `"open"` or `"gated"`. `hostname` is the virtual
    /// host (RFC 1123).
    #[allow(clippy::too_many_arguments)]
    pub async fn enable_site_projection(
        &self,
        context_id: String,
        admission: String,
        hostname: String,
        broadcast_key_hex: Option<String>,
        author_did: Option<String>,
        index_path: Option<String>,
        max_assets_per_deploy: Option<u32>,
        max_deploy_size_bytes: Option<u64>,
        deploy_retention_count: Option<u32>,
        csp_override: Option<String>,
    ) -> Result<(), ScpError> {
        validate_context_id(&context_id)?;
        if let Some(ref did) = author_did {
            validate_did(did)?;
        }

        // Resolve broadcast key: explicit, auto-lookup, or auto with explicit author.
        let (resolved_key_bytes, resolved_epoch, resolved_author_did) =
            match (broadcast_key_hex, author_did) {
                (Some(key_hex), Some(did)) => {
                    let key_hex = Zeroizing::new(key_hex);
                    let key_vec = Zeroizing::new(hex::decode(&*key_hex).map_err(|e| {
                        ScpError::Validation {
                            msg: format!("invalid broadcast_key_hex: {e}"),
                            code: "SCP-TRANS-5060".to_owned(),
                        }
                    })?);
                    let key_bytes: Zeroizing<[u8; 32]> =
                        Zeroizing::new(<[u8; 32]>::try_from(key_vec.as_slice()).map_err(|_| {
                            ScpError::Validation {
                                msg:
                                    "broadcast_key_hex must be exactly 64 hex characters (32 bytes)"
                                        .to_owned(),
                                code: "SCP-TRANS-5060".to_owned(),
                            }
                        })?);
                    // Explicit key path always uses epoch 0. For rotated keys, use auto-resolve (omit both params).
                    (key_bytes, 0u64, did)
                }
                (None, author_opt) => {
                    // Auto-resolve from ContextManager. Use the explicit author
                    // DID if provided, otherwise fall back to the node's identity
                    // DID. This supports the case where the node hosts content
                    // authored by a different DID (#1405).
                    let did = author_opt.unwrap_or_else(|| self.inner.did().to_owned());
                    let mgr = crate::runtime::context_manager()?;
                    let (key_bytes, epoch) = mgr
                        .get_broadcast_key_for_local_author(&context_id, &did)
                        .await
                        .map_err(|e| {
                            tracing::debug!(error = %e, "broadcast key auto-resolve failed");
                            ScpError::Context {
                            msg:
                                "broadcast key auto-resolve failed: not authorized for this context"
                                    .to_owned(),
                            code: "SCP-CTX-2060".to_owned(),
                        }
                        })?;
                    (key_bytes, epoch, did)
                }
                (Some(_), None) => {
                    return Err(ScpError::Validation {
                        msg: "broadcast_key_hex requires author_did — provide the DID of the \
                         broadcast key owner, or omit both for auto-resolve"
                            .to_owned(),
                        code: "SCP-TRANS-5060".to_owned(),
                    });
                }
            };

        let broadcast_key = scp_core::crypto::sender_keys::BroadcastKey::from_parts(
            scp_core::crypto::sender_keys::SenderKey::from_bytes(*resolved_key_bytes),
            resolved_epoch,
            resolved_author_did,
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
                    let display = if s.len() > 128 {
                        &s[..s.floor_char_boundary(128)]
                    } else {
                        &s
                    };
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

/// Builds a [`server::NodeIdentity`] from a `UniFFI` [`Identity`] handle.
///
/// Extracts the `ScpIdentity` and `DidDocument` retained in the identity
/// handle, then constructs a `ConcreteDidMethod` (`DidDht`) with a signing
/// function derived from the identity's custody provider. This enables
/// node startup with a pre-existing identity instead of generating a fresh
/// one, supporting identity portability across node restarts.
///
/// # Errors
///
/// Returns `ScpError::Identity` if:
/// - The identity does not retain a `ScpIdentity` (external/load-only handles)
/// - The identity does not retain a `DidDocument`
/// - The identity has no custody provider (no signing capability)
#[cfg(feature = "allow_in_memory_custody")]
#[allow(clippy::type_complexity)]
fn build_node_identity_from_uniffi(id: &Identity) -> Result<server::NodeIdentity, ScpError> {
    use scp_ffi_common::server::ConcreteDidMethod;
    use scp_identity::{DidCache, IdentityError, InMemoryDhtClient};
    use scp_platform::traits::KeyCustody;

    let core_id = id.core_id.clone().ok_or_else(|| ScpError::Identity {
        msg: "identity does not contain key handles — only identities created \
              via identity_create (not identity_load with external custody) can \
              be used for node startup"
            .to_owned(),
        code: "SCP-IDENT-1010".to_owned(),
    })?;

    let document = id.core_document.clone().ok_or_else(|| ScpError::Identity {
        msg: "identity does not contain a DID document — identity may have been \
              loaded without document resolution"
            .to_owned(),
        code: "SCP-IDENT-1011".to_owned(),
    })?;

    let custody = id
        .in_memory_custody
        .as_ref()
        .ok_or_else(|| ScpError::Identity {
            msg: "identity does not have in-memory custody — only in-memory custody \
              identities can be used for node startup in this build"
                .to_owned(),
            code: "SCP-IDENT-1012".to_owned(),
        })?;

    // Hand-rolled sign_fn because `OpaqueInMemoryKeyCustody` does not
    // implement `KeyCustody` (it wraps `InMemoryKeyCustody` in `.0`).
    // `ConcreteDidMethod::make_sign_fn` requires `Arc<K: KeyCustody>`,
    // so we delegate to the inner `.0` field directly. Same pattern as
    // `make_dht_with_signer` in bridge.rs.
    let custody_clone = Arc::clone(custody);
    let sign_fn: Arc<
        dyn Fn(
                u64,
                Vec<u8>,
            ) -> std::pin::Pin<
                Box<dyn std::future::Future<Output = Result<Vec<u8>, IdentityError>> + Send>,
            > + Send
            + Sync,
    > = Arc::new(move |key_id: u64, data: Vec<u8>| {
        let kc = Arc::clone(&custody_clone);
        Box::pin(async move {
            let handle = scp_platform::traits::KeyHandle::new(key_id);
            let sig =
                kc.0.sign(&handle, &data)
                    .await
                    .map_err(IdentityError::Platform)?;
            Ok(sig.into_bytes())
        })
    });

    let dht_client = Arc::new(InMemoryDhtClient::new());
    let cache = Arc::new(DidCache::new());
    let did_method = Arc::new(ConcreteDidMethod::with_client_and_signer(
        dht_client, cache, sign_fn,
    ));

    Ok(server::NodeIdentity {
        identity: core_id,
        document,
        did_method,
    })
}

/// Fallback for builds without `allow_in_memory_custody`: always returns an
/// error because node identity portability requires custody access.
#[cfg(not(feature = "allow_in_memory_custody"))]
fn build_node_identity_from_uniffi(_id: &Identity) -> Result<server::NodeIdentity, ScpError> {
    Err(ScpError::Identity {
        msg: "node identity portability requires the \"allow_in_memory_custody\" \
              feature — production mobile builds should use platform custody \
              with identity_with_storage on ApplicationNodeBuilder directly"
            .to_owned(),
        code: "SCP-IDENT-1013".to_owned(),
    })
}

/// Starts a full application node with in-memory storage.
///
/// When `identity` is provided, the node uses the pre-existing identity
/// instead of generating a fresh one. This enables identity portability —
/// the same DID persists across node restarts and can be shared between
/// SDK and node instances.
///
/// Auto-wires in-memory key custody, in-memory storage, in-memory DHT client,
/// self-signed TLS, and a relay on an OS-assigned port.
///
/// # Swift
///
/// ```swift
/// let identity = try await identityCreate(custody: "in_memory")
/// let node = try await nodeStartInMemory(identity: identity)
/// print(node.relayUrl()) // "ws://127.0.0.1:PORT/scp/v1"
/// print(node.did())      // same DID as identity.did()
/// node.shutdown()
/// ```
#[uniffi::export]
pub async fn node_start_in_memory(
    identity: Option<Arc<Identity>>,
) -> Result<Arc<NodeHandle>, ScpError> {
    let node_identity = match identity {
        Some(ref id) => Some(build_node_identity_from_uniffi(id)?),
        None => None,
    };
    let node = server::start_node_in_memory(node_identity).await?;

    // Auto-wire the ContextManager with relay transport so that
    // context operations work immediately after node startup.
    // Use the internal loopback URL (ws://127.0.0.1:{port}/scp/v1) instead of
    // node.relay_url() which returns the advertised URL (wss://localhost/scp/v1)
    // that requires TLS and lacks the actual bound port.
    // The bridge token is required because ApplicationNode relays enforce
    // Authorization: Bearer <token> on all WebSocket connections.
    let did = node.identity().did().to_owned();
    let relay_url = format!("ws://127.0.0.1:{}/scp/v1", node.relay().bound_addr().port());
    let bridge_token = node.bridge_token_hex();
    auto_wire_context_manager(&did, &relay_url, bridge_token).await;

    increment_handle_count();
    Ok(Arc::new(NodeHandle {
        inner: RunningNode::InMemory(node),
    }))
}

/// Starts a full application node with file-backed storage.
///
/// When `identity` is provided, the node uses the pre-existing identity.
/// When `None`, the node creates or reloads a persistent identity via
/// `FileKeyCustody`. The `passphrase` parameter is required in this mode.
///
/// Opens (or creates) persistent storage at `<data_dir>/storage/` and a redb
/// blob database at `<data_dir>/blobs.redb`.
#[uniffi::export]
pub async fn node_start_local(
    data_dir: String,
    identity: Option<Arc<Identity>>,
    passphrase: Option<String>,
) -> Result<Arc<NodeHandle>, ScpError> {
    let node_identity = match identity {
        Some(ref id) => Some(build_node_identity_from_uniffi(id)?),
        None => None,
    };
    let zeroized_passphrase = passphrase.map(Zeroizing::new);
    let node = server::start_node_local(
        std::path::Path::new(&data_dir),
        node_identity,
        zeroized_passphrase,
    )
    .await?;

    // Auto-wire the ContextManager with relay transport.
    // Use the internal loopback URL — see comment in node_start_in_memory.
    let did = node.identity().did().to_owned();
    let relay_url = format!("ws://127.0.0.1:{}/scp/v1", node.relay().bound_addr().port());
    let bridge_token = node.bridge_token_hex();
    auto_wire_context_manager(&did, &relay_url, bridge_token).await;

    increment_handle_count();
    Ok(Arc::new(NodeHandle {
        inner: RunningNode::Filesystem(node),
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
        let node = rt().block_on(node_start_in_memory(None)).unwrap();
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
            .block_on(node_start_local(
                tmp.to_string_lossy().into_owned(),
                None,
                Some("test-passphrase".to_owned()),
            ))
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
        let node = rt().block_on(node_start_in_memory(None)).unwrap();
        node.shutdown();
        node.shutdown();
    }

    #[test]
    fn enable_site_projection_dispatches_through_node_inner() {
        let node = rt().block_on(server::start_node_in_memory(None)).unwrap();
        let inner = RunningNode::InMemory(node);
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
        let node = rt().block_on(server::start_node_in_memory(None)).unwrap();
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
        let node = rt().block_on(server::start_node_in_memory(None)).unwrap();
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
        let node = rt().block_on(server::start_node_in_memory(None)).unwrap();
        let inner = RunningNode::InMemory(node);
        rt().block_on(inner.disable_broadcast_projection("no-such-ctx"));
        // Should not panic.
        inner.shutdown();
    }

    #[test]
    #[cfg(feature = "allow_in_memory_custody")]
    fn node_in_memory_with_identity_uses_provided_did() {
        use crate::bridge::identity_create;

        let identity = rt()
            .block_on(identity_create("in_memory".to_owned()))
            .unwrap();
        let expected_did = identity.did();

        let node = rt().block_on(node_start_in_memory(Some(identity))).unwrap();

        assert_eq!(
            node.did(),
            expected_did,
            "node should use the pre-existing identity's DID"
        );
        assert!(node.relay_port() > 0);
        let url = node.relay_url();
        assert!(
            url.starts_with("ws://") || url.starts_with("wss://"),
            "expected ws(s):// URL, got: {url}"
        );

        node.shutdown();
    }

    #[test]
    #[cfg(feature = "allow_in_memory_custody")]
    fn node_local_with_identity_uses_provided_did() {
        use crate::bridge::identity_create;

        let identity = rt()
            .block_on(identity_create("in_memory".to_owned()))
            .unwrap();
        let expected_did = identity.did();

        let tmp =
            std::env::temp_dir().join(format!("scp-uniffi-node-id-test-{}", std::process::id()));
        // No passphrase needed when passing a pre-existing identity.
        let node = rt()
            .block_on(node_start_local(
                tmp.to_string_lossy().into_owned(),
                Some(identity),
                None,
            ))
            .unwrap();

        assert_eq!(
            node.did(),
            expected_did,
            "node should use the pre-existing identity's DID"
        );
        assert!(node.relay_port() > 0);

        node.shutdown();
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn node_error_maps_to_scp_error_with_sanitized_message() {
        let err = NodeError::InvalidConfig("/secret/path/data.db".into());
        let scp_err: ScpError = err.into();
        match scp_err {
            ScpError::Validation { msg, code } => {
                assert!(
                    !msg.contains("/secret"),
                    "internal path leaked in msg: {msg}"
                );
                assert_eq!(msg, "node configuration error");
                assert_eq!(code, "SCP-TRANS-5050");
            }
            other => panic!("expected Validation, got: {other:?}"),
        }
    }
}
