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

use scp_ffi_common::server::{self, NodeIdentity, RunningNode, RunningRelay, ServerError};
use scp_ffi_common::validate::{validate_context_id, validate_deploy_id, validate_did};
use scp_node::NodeError;

use crate::error::ScpNapiError;
use crate::{decrement_handle_count, increment_handle_count};

// ---------------------------------------------------------------------------
// Error conversion
// ---------------------------------------------------------------------------

fn server_err(e: ServerError) -> NapiError {
    tracing::debug!(error = %e, "server operation failed");
    match &e {
        ServerError::MissingPassphrase => {
            // Map to Validation error (code SCP-VALID-7004) to match the
            // UniFFI bridge and allow TypeScript callers to distinguish this
            // actionable error from generic failures.
            NapiError::from(ScpNapiError::Validation {
                message: e.user_message(),
                code: scp_ffi_common::error_codes::VALID_7004.to_owned(),
            })
        }
        _ => NapiError::from_reason(e.user_message()),
    }
}

fn node_err(e: NodeError) -> NapiError {
    tracing::debug!(error = %e, "node operation failed");
    NapiError::from_reason("node operation failed")
}

/// Auto-wires the global [`ContextManager`] with relay transport after
/// node startup.
///
/// Connects to the node's local relay (with bearer token authentication)
/// and initializes the `ContextManager` with `RelayTransportProvider` so
/// that context operations (create, join, send) work immediately. If the
/// `ContextManager` was already initialized (e.g., by a prior
/// `configureLocalTransport` or `contextCreate` call), this is a no-op —
/// the `OnceLock` ensures first-writer-wins semantics.
///
/// The `bridge_token` is required because `ApplicationNode` relays enforce
/// `Authorization: Bearer <token>` on all WebSocket connections.
///
/// Best-effort: logs a warning if the relay connection fails rather than
/// blocking node startup.
async fn auto_wire_context_manager(did: &str, relay_url: &str, bridge_token: Zeroizing<String>) {
    let sourced = scp_transport::relay::connection::SourcedRelayUrl {
        url: relay_url.to_owned(),
        source: scp_transport::relay::connection::RelayUrlSource::Explicit,
    };
    let token2 = bridge_token.clone();
    let profile = scp_transport::profile::TransportProfile::platform_default();
    match scp_transport::native::NativeRelayAdapter::connect_sourced_with_bearer(
        &sourced,
        Some(bridge_token),
        Some(&profile),
    )
    .await
    {
        Ok(adapter) => {
            crate::runtime::init_supervisor_with_relay_transport(did, adapter);

            // Also populate the BridgeInstance transport manager so that
            // broadcast publish, context subscribe, and discovery probing
            // work without a separate `transportConnect` call. This requires
            // a second WebSocket connection because NativeRelayAdapter is not
            // Clone and the first was consumed by RelayTransportProvider.
            match scp_transport::native::NativeRelayAdapter::connect_sourced_with_bearer(
                &sourced,
                Some(token2),
                Some(&profile),
            )
            .await
            {
                Ok(relay_adapter) => {
                    let manager = scp_transport::TransportManager::new(Box::new(relay_adapter));
                    let _ =
                        crate::transport::set_transport_manager_arc(std::sync::Arc::new(manager));
                }
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        relay_url = %relay_url,
                        "auto_wire_context_manager: ContextManager wired but failed to \
                         populate BridgeInstance transport manager — broadcast publish and \
                         discovery may require a manual transportConnect call"
                    );
                }
            }
        }
        Err(e) => {
            tracing::warn!(
                error = %e,
                relay_url = %relay_url,
                "auto_wire_context_manager: failed to connect to node relay — \
                 context operations may fail until transport is configured manually"
            );
            // Fall back to initializing without transport so that at least
            // the Supervisor exists (with NotConfiguredTransportProvider).
            crate::runtime::init_supervisor(did);
        }
    }
    // Always register the node's DID as a local DID for defense-in-depth.
    if let Ok(supervisor) = crate::runtime::supervisor()
        && let Err(e) = supervisor.register_local_did(did.to_owned().into()).await
    {
        tracing::debug!(
            error = %e,
            "auto_wire_context_manager: register_local_did skipped (supervisor not ready)"
        );
    }
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
    /// `NapiBridgeInstance` id that minted this handle.
    pub(crate) instance_id: u64,
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

    /// Returns the id of the `SCP` instance that minted this handle, as a
    /// base-10 string.
    #[napi(getter, js_name = "instanceId")]
    pub fn instance_id_js(&self) -> String {
        self.instance_id.to_string()
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
    /// `NapiBridgeInstance` id that minted this handle.
    pub(crate) instance_id: u64,
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
    /// Three resolution modes:
    /// 1. Both `broadcastKeyHex` **and** `authorDid` provided -- uses
    ///    the explicit key with epoch 0.
    /// 2. Only `authorDid` provided -- auto-resolves the broadcast key
    ///    using that DID (useful when the author identity differs from the
    ///    node identity).
    /// 3. Neither provided -- auto-resolves using the node's identity DID.
    ///
    /// Providing `broadcastKeyHex` without `authorDid` raises an error.
    ///
    /// `admission` is `"open"` or `"gated"`.
    ///
    /// Site configuration fields:
    /// - `hostname` (required): virtual host hostname (RFC 1123).
    /// - `indexPath`: default path for directory requests (default `"/index.html"`).
    /// - `maxAssetsPerDeploy`: max assets per deploy (default 10000).
    /// - `maxDeploySizeBytes`: max total deploy size in bytes (default 536870912).
    /// - `deployRetentionCount`: deploys to retain (default 2, max 8).
    /// - `cspOverride`: optional Content-Security-Policy override.
    #[napi]
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
        max_deploy_size_bytes: Option<i64>,
        deploy_retention_count: Option<u32>,
        csp_override: Option<String>,
    ) -> napi::Result<()> {
        validate_context_id(&context_id).map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;
        if let Some(ref did) = author_did {
            validate_did(did).map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;
        }

        // Resolve broadcast key: explicit or auto-lookup via Supervisor.
        let supervisor = crate::runtime::supervisor()?;
        let resolved = server::resolve_broadcast_key(
            broadcast_key_hex,
            author_did,
            self.inner.did(),
            supervisor,
            &context_id,
        )
        .await
        .map_err(|e| NapiError::from_reason(e.to_string()))?;
        let broadcast_key = resolved.into_broadcast_key();

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

        // JavaScript numbers are signed; validate non-negative before u64 conversion.
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

    /// Starts the HTTP server in the background on the given bind address.
    ///
    /// Defaults to `127.0.0.1:8443` (loopback only) when `bindAddr` is not
    /// provided. Returns the actual bound address as a raw string
    /// (e.g. `"127.0.0.1:8443"`). Use [`http_url`](NapiNodeHandle::http_url)
    /// for the full URL form (`"http://127.0.0.1:8443"`).
    ///
    /// **Note:** The background server does not support TLS. For production
    /// deployments requiring encryption, use the node binary's `serve()`
    /// with TLS configuration.
    ///
    /// Throws if the server is already running or binding fails.
    #[napi]
    pub async fn serve(&self, bind_addr: Option<String>) -> napi::Result<String> {
        let addr = bind_addr
            .map(|s| {
                s.parse::<std::net::SocketAddr>().map_err(|e| {
                    let display = if s.len() > 128 {
                        &s[..s.floor_char_boundary(128)]
                    } else {
                        &s
                    };
                    NapiError::from_reason(format!("invalid bind_addr \"{display}\": {e}"))
                })
            })
            .transpose()?;
        self.inner
            .serve_background(addr)
            .await
            .map(|a| a.to_string())
            .map_err(node_err)
    }

    /// Returns the HTTP URL of the background server, or `null` if not serving.
    ///
    /// Returns the literal bind address, which may contain `0.0.0.0` if the
    /// server was bound to the unspecified address.
    #[napi]
    pub async fn http_url(&self) -> Option<String> {
        self.inner.http_url().await
    }

    /// Returns the id of the `SCP` instance that minted this handle, as a
    /// base-10 string.
    #[napi(getter, js_name = "instanceId")]
    pub fn instance_id_js(&self) -> String {
        self.instance_id.to_string()
    }
}

impl Drop for NapiNodeHandle {
    fn drop(&mut self) {
        self.inner.shutdown();
        decrement_handle_count();
    }
}

// ---------------------------------------------------------------------------
// build_node_identity — constructs NodeIdentity from identity registry
// ---------------------------------------------------------------------------

/// Builds a [`NodeIdentity`] from the NAPI identity registry for a given DID.
///
/// Looks up the DID in the global identity registry (populated by
/// `identity_create`) and constructs a `NodeIdentity` with a properly
/// configured `DidDht` instance that has signing capability.
///
/// # Errors
///
/// Returns `napi::Error` if:
/// - The `allow_in_memory_custody` feature is not enabled.
/// - The DID is not found in the identity registry.
#[cfg(feature = "allow_in_memory_custody")]
#[allow(clippy::type_complexity)]
fn build_node_identity(did: &str) -> napi::Result<NodeIdentity> {
    use std::sync::Arc;

    use scp_identity::{DidCache, InMemoryDhtClient};
    use scp_platform::traits::KeyCustody;

    crate::runtime::with_identity(did, |entry| {
        let custody_clone = Arc::clone(&entry.custody);

        // Hand-rolled sign_fn because `OpaqueInMemoryKeyCustody` does not
        // implement `KeyCustody` (it wraps `InMemoryKeyCustody` in `.0`).
        // `ConcreteDidMethod::make_sign_fn` requires `Arc<K: KeyCustody>`,
        // so we delegate to the inner `.0` field directly. Same pattern as
        // `make_dht_with_signer` in bridge.rs.
        let sign_fn: Arc<
            dyn Fn(
                    u64,
                    Vec<u8>,
                ) -> std::pin::Pin<
                    Box<
                        dyn std::future::Future<
                                Output = Result<Vec<u8>, scp_identity::IdentityError>,
                            > + Send,
                    >,
                > + Send
                + Sync,
        > = Arc::new(move |key_id: u64, data: Vec<u8>| {
            let kc = Arc::clone(&custody_clone);
            Box::pin(async move {
                let handle = scp_platform::traits::KeyHandle::new(key_id);
                let sig =
                    kc.0.sign(&handle, &data)
                        .await
                        .map_err(scp_identity::IdentityError::Platform)?;
                Ok(sig.into_bytes())
            })
        });

        let dht_client = Arc::new(InMemoryDhtClient::new());
        let cache = Arc::new(DidCache::new());
        let did_method = Arc::new(
            scp_ffi_common::server::ConcreteDidMethod::with_client_and_signer(
                dht_client, cache, sign_fn,
            ),
        );

        Ok(NodeIdentity {
            identity: entry.identity.clone(),
            document: entry.document.clone(),
            did_method,
        })
    })
    .map_err(napi::Error::from)
}

#[cfg(not(feature = "allow_in_memory_custody"))]
fn build_node_identity(_did: &str) -> napi::Result<NodeIdentity> {
    Err(NapiError::from_reason(
        "identity portability requires in-memory custody — enable allow_in_memory_custody",
    ))
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
    Ok(NapiRelayHandle {
        inner: relay,
        instance_id: crate::runtime::default_instance_id()?,
    })
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
    Ok(NapiRelayHandle {
        inner: relay,
        instance_id: crate::runtime::default_instance_id()?,
    })
}

// ---------------------------------------------------------------------------
// Free functions — node startup
// ---------------------------------------------------------------------------

/// Starts a full application node with in-memory storage.
///
/// Auto-wires in-memory key custody, in-memory storage, in-memory DHT client,
/// self-signed TLS, and a relay on an OS-assigned port.
///
/// When `identityDid` is provided, the node uses the pre-existing identity
/// from the identity registry (created via `identityCreate`) instead of
/// generating a fresh one. This enables identity portability — the same
/// DID persists across node restarts. The `ContextManager` is also
/// auto-initialized with the node's relay as transport.
///
/// ```js
/// const node = await nodeStartInMemory();
/// console.log(node.relayUrl); // "ws://127.0.0.1:PORT/scp/v1"
/// console.log(node.did);      // "did:dht:z6Mk..."
/// node.shutdown();
///
/// // With identity portability:
/// const id = await identityCreate("in_memory");
/// const node2 = await nodeStartInMemory(id.did);
/// console.log(node2.did === id.did); // true
/// ```
#[napi]
pub async fn node_start_in_memory(identity_did: Option<String>) -> napi::Result<NapiNodeHandle> {
    let node_identity = match identity_did {
        Some(ref did) => {
            validate_did(did).map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;
            Some(build_node_identity(did)?)
        }
        None => None,
    };
    let node = server::start_node_in_memory(node_identity)
        .await
        .map_err(server_err)?;

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
    Ok(NapiNodeHandle {
        inner: RunningNode::InMemory(node),
        instance_id: crate::runtime::default_instance_id()?,
    })
}

/// Starts a full application node with file-backed storage.
///
/// Opens (or creates) persistent storage at `<data_dir>/storage/` and a redb
/// blob database at `<data_dir>/blobs.redb`.
///
/// When `identityDid` is provided, the node uses the pre-existing identity
/// from the identity registry instead of generating a fresh one. When
/// `identityDid` is `null`, the node creates or reloads a persistent
/// identity via `FileKeyCustody`. The `passphrase` parameter is required
/// in this mode.
///
/// ```js
/// const node = await nodeStartLocal("/tmp/my-node", null, "my-secret");
/// console.log(node.relayUrl); // "ws://127.0.0.1:PORT/scp/v1"
/// console.log(node.did);      // "did:dht:z6Mk..."
/// node.shutdown();
///
/// // With identity portability:
/// const id = await identityCreate("in_memory");
/// const node2 = await nodeStartLocal("/tmp/my-node", id.did);
/// console.log(node2.did === id.did); // true
/// ```
#[napi]
pub async fn node_start_local(
    data_dir: String,
    identity_did: Option<String>,
    passphrase: Option<String>,
) -> napi::Result<NapiNodeHandle> {
    let node_identity = match identity_did {
        Some(ref did) => {
            validate_did(did).map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;
            Some(build_node_identity(did)?)
        }
        None => None,
    };
    let zeroized_passphrase = passphrase.map(Zeroizing::new);
    let node = server::start_node_local(
        std::path::Path::new(&data_dir),
        node_identity,
        zeroized_passphrase,
    )
    .await
    .map_err(server_err)?;

    // Auto-wire the ContextManager with relay transport.
    // Use the internal loopback URL — see comment in node_start_in_memory.
    let did = node.identity().did().to_owned();
    let relay_url = format!("ws://127.0.0.1:{}/scp/v1", node.relay().bound_addr().port());
    let bridge_token = node.bridge_token_hex();
    auto_wire_context_manager(&did, &relay_url, bridge_token).await;

    increment_handle_count();
    Ok(NapiNodeHandle {
        inner: RunningNode::Filesystem(node),
        instance_id: crate::runtime::default_instance_id()?,
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
        let node = rt().block_on(node_start_in_memory(None)).unwrap();
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
            .block_on(node_start_local(
                tmp.to_string_lossy().into_owned(),
                None,
                Some("test-passphrase".to_owned()),
            ))
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
        let node = rt().block_on(node_start_in_memory(None)).unwrap();
        node.shutdown();
        // Second shutdown should not panic.
        node.shutdown();
    }

    #[test]
    fn enable_site_projection_dispatches_through_node_inner() {
        let node = rt().block_on(server::start_node_in_memory(None)).unwrap();
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
}
