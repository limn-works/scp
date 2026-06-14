//! Self-host site deployment core (`--self-host` mode).
//!
//! This module holds the transport-and-binary-independent core of the
//! `scp-node --self-host` flow: building an in-process
//! [`Supervisor`](scp_core::context::supervisor::Supervisor) connected to the
//! node's **own loopback relay**, publishing the static site assets as
//! encrypted [`BroadcastContent`](scp_core::context::BroadcastContent)
//! messages through the real two-phase broadcast publish path, enabling
//! broadcast site projection, and committing the deploy.
//!
//! The binary shell (`main.rs`) handles the binary-only concerns: CLI/env
//! parsing, the loud startup banner, NAT port-mapper construction/teardown,
//! and the long-lived [`serve`](crate::ApplicationNode) call. Everything that
//! is exercised by both the production binary and the integration test lives
//! here so the test runs the **same** code path as production.
//!
//! ## Architecture (per `.docs/guides/self-hosting-a-website-on-scp.md`)
//!
//! The website is only ever served over HTTP from the origin node. The
//! supervisor publishes encrypted envelopes onto the node's loopback relay;
//! [`commit_deploy`](crate::ApplicationNode::commit_deploy) scans that same
//! relay's blob storage, builds an immutable `path -> blob_id` index, and the
//! node's HTTP projection handler decrypts and serves plaintext on request.
//!
//! Provenance: specs §10.12 (Infrastructure & Self-Hosting) + §18
//! (Addressability & Deployment); ADR-032 / ADR-035 / ADR-042.

use std::sync::Arc;

use scp_platform::KeyCustody;
use scp_platform::traits::Storage;

use crate::{ApplicationNode, projection};

/// A single static asset to publish: HTTP path, content type, and body bytes.
///
/// `path` is a site-absolute path such as `/index.html`; `content_type` is the
/// MIME type to serve it with; `body` is the raw (plaintext) bytes.
#[derive(Debug, Clone)]
pub struct Asset {
    /// Site-absolute request path, e.g. `/index.html`.
    pub path: String,
    /// MIME type, e.g. `text/html`.
    pub content_type: String,
    /// Raw plaintext bytes.
    pub body: Vec<u8>,
}

/// Errors produced while deploying a self-hosted site.
#[derive(Debug, thiserror::Error)]
pub enum SelfHostError {
    /// Failed to connect the in-process supervisor to the loopback relay.
    #[error("failed to connect supervisor to loopback relay: {0}")]
    RelayConnect(String),
    /// Failed to register the node DID with the supervisor.
    #[error("failed to register local DID with supervisor: {0}")]
    RegisterDid(String),
    /// Failed to register the broadcast context on the node.
    #[error("failed to register broadcast context on node: {0}")]
    RegisterContext(String),
    /// Failed to create the broadcast context in the supervisor.
    #[error("failed to create broadcast context in supervisor: {0}")]
    CreateContext(String),
    /// An asset path or content type was invalid.
    #[error("invalid asset metadata: {0}")]
    InvalidAsset(String),
    /// Publishing an asset failed.
    #[error("failed to publish asset '{path}': {source_msg}")]
    Publish {
        /// The asset path that failed.
        path: String,
        /// The underlying error message.
        source_msg: String,
    },
    /// Failed to resolve the broadcast key for the local author.
    #[error("failed to resolve broadcast key: {0}")]
    BroadcastKey(String),
    /// Failed to build the site config.
    #[error("failed to build site config: {0}")]
    SiteConfig(String),
    /// Failed to enable broadcast projection.
    #[error("failed to enable broadcast projection: {0}")]
    EnableProjection(String),
    /// Committing the deploy failed.
    #[error("failed to commit deploy: {0}")]
    CommitDeploy(String),
    /// The committed asset count did not match the published count.
    #[error("commit_deploy count mismatch: committed {committed}, expected {expected}")]
    CommitCountMismatch {
        /// Number of assets actually committed.
        committed: usize,
        /// Number of assets that were published.
        expected: usize,
    },
}

/// Parameters for [`deploy_site`].
///
/// Bundled into a struct to keep the function signature small and to make the
/// call sites (production binary + integration test) self-documenting.
pub struct DeploySiteParams<'a, C: KeyCustody> {
    /// The node's DID string. Used as the broadcast author and the
    /// supervisor's local DID. Must equal `node.identity().did()`.
    pub node_did: String,
    /// The deterministic broadcast context id (hex, lowercase, <= 64 chars).
    pub context_id: String,
    /// The deploy id committed across all assets.
    pub deploy_id: String,
    /// RFC-1123 hostname placeholder for the site config. Reachability is via
    /// the routing-id path, not this hostname, but it must be non-empty and
    /// valid, and must not equal the node's own domain.
    pub hostname: String,
    /// The author's signing key handle (from `node.identity().identity()`).
    pub signing_key_handle: scp_platform::KeyHandle,
    /// The caller's key custody backend. Borrowed for the publish dispatch.
    pub custody: &'a C,
    /// The supervisor's `OpenMLS` storage adapter. The caller builds this over
    /// its chosen [`Storage`] backend (a `SQLite` handle distinct from the
    /// node's own storage, in production) via
    /// [`SpawnBlockingStorageAdapter`](scp_core::crypto::mls::storage_adapter::SpawnBlockingStorageAdapter).
    pub mls_storage: Arc<dyn scp_core::crypto::mls::storage_adapter::OpenMlsStorageAdapter>,
    /// The static assets to publish, in deploy order.
    pub assets: &'a [Asset],
}

/// Returns the content type for a path based on its file extension.
///
/// The extension match is case-insensitive. Falls back to
/// `application/octet-stream` for unknown or missing extensions.
#[must_use]
pub fn content_type_for(path: &str) -> &'static str {
    let ext = std::path::Path::new(path)
        .extension()
        .and_then(|e| e.to_str())
        .map(str::to_ascii_lowercase)
        .unwrap_or_default();
    match ext.as_str() {
        "html" | "htm" => "text/html",
        "css" => "text/css",
        "js" | "mjs" => "application/javascript",
        "json" => "application/json",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "ico" => "image/x-icon",
        "txt" => "text/plain",
        "wasm" => "application/wasm",
        _ => "application/octet-stream",
    }
}

/// The embedded default site (`index.html` + `style.css` + `app.js`).
///
/// These are compiled into the binary from
/// `crates/scp-node/assets/selfhost/` so the `--self-host` mode works with no
/// external files. When the operator supplies `--site-dir`, those files are
/// served instead (see `main.rs`).
const EMBEDDED_INDEX_HTML: &str = include_str!("../assets/selfhost/index.html");
const EMBEDDED_STYLE_CSS: &str = include_str!("../assets/selfhost/style.css");
const EMBEDDED_APP_JS: &str = include_str!("../assets/selfhost/app.js");

/// Builds the embedded default asset set.
///
/// When `node_did` is `Some`, a `<meta name="scp-did" content="...">` tag is
/// injected into the `<head>` of `index.html` so the page can surface the
/// node's DID (the bundled `app.js` reads it and degrades gracefully if
/// absent). Injection is a single, well-defined string replacement on the
/// known-good embedded HTML; if the expected `</head>` marker is not present
/// (it always is in the shipped asset), the HTML is served unmodified.
#[must_use]
pub fn embedded_assets(node_did: Option<&str>) -> Vec<Asset> {
    let index_html = node_did.map_or_else(
        || EMBEDDED_INDEX_HTML.to_owned(),
        |did| inject_did_meta(EMBEDDED_INDEX_HTML, did),
    );
    vec![
        Asset {
            path: "/index.html".to_owned(),
            content_type: "text/html".to_owned(),
            body: index_html.into_bytes(),
        },
        Asset {
            path: "/style.css".to_owned(),
            content_type: "text/css".to_owned(),
            body: EMBEDDED_STYLE_CSS.as_bytes().to_vec(),
        },
        Asset {
            path: "/app.js".to_owned(),
            content_type: "application/javascript".to_owned(),
            body: EMBEDDED_APP_JS.as_bytes().to_vec(),
        },
    ]
}

/// Injects a `<meta name="scp-did" ...>` tag immediately before `</head>`.
///
/// HTML-escapes the DID's `&`, `<`, `>`, and `"` so a malformed DID cannot
/// break out of the attribute. Returns the input unchanged if `</head>` is
/// absent.
fn inject_did_meta(html: &str, did: &str) -> String {
    let escaped = did
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;");
    let meta = format!("  <meta name=\"scp-did\" content=\"{escaped}\" />\n");
    html.find("</head>").map_or_else(
        || html.to_owned(),
        |idx| {
            let mut out = String::with_capacity(html.len() + meta.len());
            out.push_str(&html[..idx]);
            out.push_str(&meta);
            out.push_str(&html[idx..]);
            out
        },
    )
}

/// Deploys the site through the full broadcast publish + projection pipeline.
///
/// Builds an in-process supervisor on the node's loopback relay, publishes
/// every asset through the real two-phase broadcast publish path, enables
/// broadcast site projection, and commits the deploy.
///
/// Returns the number of assets committed on success (always equal to
/// `params.assets.len()` — a mismatch is an error).
///
/// This is the shared core run by both the production `--self-host` binary
/// flow and the integration test, so both exercise identical wiring.
///
/// # Errors
///
/// Returns a [`SelfHostError`] if any stage fails: relay connect, DID
/// registration, context creation, asset publish, key resolution, projection
/// enable, or deploy commit.
pub async fn deploy_site<S, C>(
    node: &ApplicationNode<S>,
    params: DeploySiteParams<'_, C>,
) -> Result<usize, SelfHostError>
where
    S: Storage + 'static,
    C: KeyCustody,
{
    let DeploySiteParams {
        node_did,
        context_id,
        deploy_id,
        hostname,
        signing_key_handle,
        custody,
        mls_storage,
        assets,
    } = params;

    let deployer = SelfHostDeployer::start(
        node,
        node_did,
        context_id,
        hostname,
        signing_key_handle,
        mls_storage,
    )
    .await?;

    deployer.deploy(node, &deploy_id, custody, assets).await
}

/// A long-lived self-host site deployer bound to ONE in-process supervisor and
/// its single broadcast group.
///
/// The setup work — building the loopback supervisor, registering the DID and
/// broadcast context, creating the MLS broadcast group, and enabling
/// projection with the group's broadcast key — happens exactly once in
/// [`start`](Self::start). Each call to [`deploy`](Self::deploy) then publishes
/// the supplied assets under a fresh `deploy_id` and commits, reusing the SAME
/// supervisor, group, and broadcast key/epoch.
///
/// Reusing one group across deploys is what makes the self-host refresh loop
/// correct: every published blob (current and prior deploys alike) is sealed
/// under the same epoch key, so a prior deploy's blobs stay decryptable right
/// up to the moment a new deploy's manifest is committed — there is no window
/// where the projected manifest points at blobs the projection can no longer
/// decrypt. (Building a fresh group per deploy would mint a new key at the same
/// initial epoch number, silently overwriting the prior key in the projection
/// registry and breaking decryption of the still-referenced prior blobs until
/// the commit completes.)
pub struct SelfHostDeployer {
    supervisor: Arc<scp_core::context::supervisor::Supervisor>,
    author_did: scp_identity::DID,
    context_id: String,
    signing_key_handle: scp_platform::KeyHandle,
}

impl SelfHostDeployer {
    /// Performs the one-time setup: connects the loopback supervisor, registers
    /// the broadcast context on the node, creates the MLS broadcast group, and
    /// enables broadcast site projection under the group's broadcast key.
    ///
    /// # Errors
    ///
    /// Returns a [`SelfHostError`] if relay connect, DID/context registration,
    /// context creation, key resolution, or projection enable fails.
    pub async fn start<S>(
        node: &ApplicationNode<S>,
        node_did: String,
        context_id: String,
        hostname: String,
        signing_key_handle: scp_platform::KeyHandle,
        mls_storage: Arc<dyn scp_core::crypto::mls::storage_adapter::OpenMlsStorageAdapter>,
    ) -> Result<Self, SelfHostError>
    where
        S: Storage + 'static,
    {
        let author_did: scp_identity::DID = scp_identity::DID::from(node_did.clone());

        // Build the in-process supervisor on the node's OWN loopback relay and
        // register the local DID + the broadcast context.
        let supervisor =
            connect_loopback_supervisor(node, &node_did, &author_did, mls_storage).await?;
        node.register_broadcast_context(context_id.clone(), Some("SCP Self-Host Site".to_owned()))
            .await
            .map_err(|e| SelfHostError::RegisterContext(e.to_string()))?;
        let context_params = scp_core::context::ContextParams {
            mode: scp_core::context::params::ContextMode::Broadcast,
            // Broadcast contexts only support `MemoryScope::Full`; the default
            // scope is `Ephemeral`, which `create_context` rejects for
            // broadcast mode.
            memory_scope: scp_core::context::params::MemoryScope::Full,
            ..Default::default()
        };
        supervisor
            .create_context(context_id.clone(), context_params, author_did.clone(), None)
            .await
            .map_err(|e| SelfHostError::CreateContext(e.to_string()))?;

        // Enable projection ONCE with the group's broadcast key/epoch. Because
        // the group (and thus the key/epoch) is stable for this deployer's
        // lifetime, every later `deploy` publishes under the same key and the
        // registry needs no further key updates.
        enable_projection(&supervisor, node, &context_id, &node_did, hostname).await?;

        Ok(Self {
            supervisor,
            author_did,
            context_id,
            signing_key_handle,
        })
    }

    /// Publishes `assets` under `deploy_id` through the reused supervisor/group
    /// and commits the deploy, returning the number of assets committed.
    ///
    /// Each call should use a fresh, unique `deploy_id` so `commit_deploy`
    /// counts only this deploy's blobs (prior deploys' blobs, still inside
    /// their TTL, carry earlier deploy ids and are ignored).
    ///
    /// # Errors
    ///
    /// Returns a [`SelfHostError`] if any asset publish fails, the commit
    /// fails, or the committed count does not match `assets.len()`.
    pub async fn deploy<S, C>(
        &self,
        node: &ApplicationNode<S>,
        deploy_id: &str,
        custody: &C,
        assets: &[Asset],
    ) -> Result<usize, SelfHostError>
    where
        S: Storage + 'static,
        C: KeyCustody,
    {
        publish_assets(
            &self.supervisor,
            &self.context_id,
            &self.author_did,
            deploy_id,
            self.signing_key_handle,
            custody,
            assets,
        )
        .await?;

        let committed = node
            .commit_deploy(&self.context_id, deploy_id)
            .await
            .map_err(|e| SelfHostError::CommitDeploy(e.to_string()))?;
        if committed != assets.len() {
            return Err(SelfHostError::CommitCountMismatch {
                committed,
                expected: assets.len(),
            });
        }

        Ok(committed)
    }
}

/// Builds an in-process [`Supervisor`](scp_core::context::supervisor::Supervisor)
/// connected to the node's own loopback relay and registers `author_did` as a
/// local DID.
///
/// The supervisor publishes encrypted envelopes onto the same relay whose blob
/// storage the node's [`commit_deploy`](ApplicationNode::commit_deploy) scans,
/// closing the publish -> commit loop in-process.
async fn connect_loopback_supervisor<S>(
    node: &ApplicationNode<S>,
    node_did: &str,
    author_did: &scp_identity::DID,
    mls_storage: Arc<dyn scp_core::crypto::mls::storage_adapter::OpenMlsStorageAdapter>,
) -> Result<Arc<scp_core::context::supervisor::Supervisor>, SelfHostError>
where
    S: Storage + 'static,
{
    let relay_port = node.relay().bound_addr().port();
    let sourced = scp_transport::relay::connection::SourcedRelayUrl {
        url: format!("ws://127.0.0.1:{relay_port}/scp/v1"),
        source: scp_transport::relay::connection::RelayUrlSource::DhtResolved,
    };
    let profile = scp_transport::profile::TransportProfile::platform_default();
    // The loopback relay requires the node's bridge bearer token.
    let bearer = node.bridge_token_hex();
    let adapter = scp_transport::native::adapter::NativeRelayAdapter::connect_sourced_with_bearer(
        &sourced,
        Some(bearer),
        Some(&profile),
    )
    .await
    .map_err(|e| SelfHostError::RelayConnect(e.to_string()))?;

    let transport: Box<dyn scp_core::context::builder::ContextTransportProvider> = Box::new(
        scp_transport::provider::RelayTransportProvider::new(adapter),
    );
    let crypto = Arc::new(scp_core::crypto::mls::provider::MlsCryptoProvider::new(
        node_did.to_owned(),
    ));
    let event_log: Box<dyn scp_core::context::builder::ContextEventLogProvider> =
        Box::new(scp_core::context::providers::MerkleEventLogProvider::new());
    let key_resolver: scp_core::context::governance::KeyResolver = Arc::new(|_| None);
    let (event_tx, _event_rx) = tokio::sync::broadcast::channel(1000);

    let supervisor = scp_core::context::supervisor::Supervisor::with_providers(
        crypto,
        transport,
        event_log,
        key_resolver,
        None,
        None,
        Some(event_tx),
        None,
        mls_storage,
    );

    supervisor
        .register_local_did(author_did.clone())
        .await
        .map_err(|e| SelfHostError::RegisterDid(e.to_string()))?;

    Ok(supervisor)
}

/// Publishes each asset as a sealed [`BroadcastContent`](scp_core::context::BroadcastContent)
/// message through the real two-phase broadcast publish path.
async fn publish_assets<C>(
    supervisor: &scp_core::context::supervisor::Supervisor,
    context_id: &str,
    author_did: &scp_identity::DID,
    deploy_id: &str,
    signing_key_handle: scp_platform::KeyHandle,
    custody: &C,
    assets: &[Asset],
) -> Result<(), SelfHostError>
where
    C: KeyCustody,
{
    use scp_core::context::actor::commands::{BroadcastCommand, PublishBroadcastContentPayload};

    for asset in assets {
        let content_path = scp_core::context::ContentPath::new(asset.path.clone())
            .map_err(|e| SelfHostError::InvalidAsset(format!("path '{}': {e}", asset.path)))?;
        let mime_type =
            scp_core::context::MimeType::new(asset.content_type.clone()).map_err(|e| {
                SelfHostError::InvalidAsset(format!("content_type '{}': {e}", asset.content_type))
            })?;
        let etag = scp_core::context::compute_etag(&asset.body);
        let content = scp_core::context::BroadcastContent {
            version: scp_core::context::BROADCAST_CONTENT_VERSION,
            metadata: scp_core::context::ContentMetadata {
                path: Some(content_path),
                content_type: Some(mime_type),
                deploy_id: Some(deploy_id.to_owned()),
                etag: Some(etag),
                immutable: false,
            },
            body: asset.body.clone(),
        };

        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        let cmd = BroadcastCommand::PublishBroadcastContent {
            payload: Box::new(PublishBroadcastContentPayload {
                context_id: context_id.to_owned(),
                author_did: author_did.clone(),
                content,
                signing_key_handle,
            }),
            reply: reply_tx,
        };
        supervisor
            .dispatch_broadcast_command_with_custody(cmd, custody)
            .await
            .map_err(|e| SelfHostError::Publish {
                path: asset.path.clone(),
                source_msg: format!("dispatch failed: {e}"),
            })?;
        reply_rx
            .await
            .map_err(|e| SelfHostError::Publish {
                path: asset.path.clone(),
                source_msg: format!("actor reply channel closed: {e}"),
            })?
            .map_err(|e| SelfHostError::Publish {
                path: asset.path.clone(),
                source_msg: e.to_string(),
            })?;
    }

    Ok(())
}

/// Resolves the broadcast key for the local author and enables broadcast site
/// projection on the node so its HTTP endpoints can decrypt and serve the deploy.
async fn enable_projection<S>(
    supervisor: &scp_core::context::supervisor::Supervisor,
    node: &ApplicationNode<S>,
    context_id: &str,
    node_did: &str,
    hostname: String,
) -> Result<(), SelfHostError>
where
    S: Storage + 'static,
{
    let (key, epoch) = supervisor
        .get_broadcast_key_for_local_author(context_id, node_did)
        .await
        .map_err(|e| SelfHostError::BroadcastKey(e.to_string()))?;
    let broadcast_key = scp_core::crypto::sender_keys::BroadcastKey::from_parts(
        scp_core::crypto::sender_keys::SenderKey::from_bytes(*key),
        epoch,
        node_did.to_owned(),
    );

    let index_path = scp_core::context::ContentPath::new("/index.html")
        .map_err(|e| SelfHostError::SiteConfig(format!("index path: {e}")))?;
    let site_config = projection::SiteConfig {
        hostname,
        index_path,
        ..projection::SiteConfig::default()
    };

    node.enable_broadcast_projection_with_site(
        context_id,
        broadcast_key,
        scp_core::context::broadcast::BroadcastAdmission::Open,
        None,
        Some(site_config),
    )
    .await
    .map_err(|e| SelfHostError::EnableProjection(e.to_string()))
}

/// Computes the hex-encoded routing id (`SHA-256(context_id)`) used in the
/// node's HTTP serving path `/scp/broadcast/{routing_id}/site/{path}`.
#[must_use]
pub fn routing_id_hex(context_id: &str) -> String {
    hex::encode(projection::compute_routing_id(context_id))
}
