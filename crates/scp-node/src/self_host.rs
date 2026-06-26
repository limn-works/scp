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

use std::future::Future;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use zeroize::Zeroizing;

use scp_identity::cache::SystemClock;
use scp_identity::dht::SequenceStore;
use scp_identity::{DidCache, DidDht, IdentityError, InMemoryDhtClient, PkarrDhtClient};
use scp_platform::KeyCustody;
use scp_platform::sqlite::{SqliteKeyCustody, SqliteStorage};
use scp_platform::traits::Storage;

use crate::config::{DhtMode, IdentitySource, NatSlot, Node, NodeConfig, Reach, TlsMode};
use crate::{ApplicationNode, PublicSurface, projection};

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
    /// The REAL document-derived governance
    /// [`KeyResolver`](scp_core::context::governance::KeyResolver) for the
    /// co-located participant (ADR-053 / spec §10.17). Build it with
    /// [`colocated_document_vm_key_resolver`] over a
    /// [`DualLayerResolver`](scp_identity::DualLayerResolver) that shares the
    /// node's [`DidCache`](scp_identity::DidCache); never the `|_, _| None` stub.
    pub key_resolver: scp_core::context::governance::KeyResolver,
    /// The caller's key custody backend. Borrowed for the publish dispatch.
    pub custody: &'a C,
    /// The supervisor's `OpenMLS` storage adapter. The caller builds this over
    /// its chosen [`Storage`] backend (a `SQLite` handle distinct from the
    /// node's own storage, in production) via
    /// [`SpawnBlockingStorageAdapter`](scp_core::crypto::mls::storage_adapter::SpawnBlockingStorageAdapter).
    pub mls_storage: Arc<dyn scp_core::crypto::mls::storage_adapter::OpenMlsStorageAdapter>,
    /// The durable saga journal for the loopback supervisor (§17.16 / ADR-049).
    /// The caller builds this over the SAME [`Storage`] backend it wraps into
    /// `mls_storage` (a `SQLite` handle distinct from the node's own storage,
    /// in production) via
    /// [`ProtocolRepositorySagaJournal::new`](scp_core::context::supervisor::ProtocolRepositorySagaJournal::new),
    /// so crash-recovery replay and the `OpenMLS` view share one backend.
    pub saga_journal: Arc<dyn scp_core::context::supervisor::SagaJournal>,
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
        key_resolver,
        custody,
        mls_storage,
        saga_journal,
        assets,
    } = params;

    let deployer = SelfHostDeployer::start(
        node,
        node_did,
        context_id,
        hostname,
        signing_key_handle,
        key_resolver,
        mls_storage,
        saga_journal,
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
    // Provider-bootstrap entry: each argument is a distinct, required provider
    // the loopback supervisor needs (node, identity, hostname, signing key,
    // governance resolver, MLS storage, durable saga journal). Bundling them
    // into a struct would only relocate the same fields, so the per-provider
    // signature stays — mirroring the FFI `with_providers_and_journal` bootstrap.
    #[allow(clippy::too_many_arguments)]
    pub async fn start<S>(
        node: &ApplicationNode<S>,
        node_did: String,
        context_id: String,
        hostname: String,
        signing_key_handle: scp_platform::KeyHandle,
        key_resolver: scp_core::context::governance::KeyResolver,
        mls_storage: Arc<dyn scp_core::crypto::mls::storage_adapter::OpenMlsStorageAdapter>,
        saga_journal: Arc<dyn scp_core::context::supervisor::SagaJournal>,
    ) -> Result<Self, SelfHostError>
    where
        S: Storage + 'static,
    {
        let author_did: scp_identity::DID = scp_identity::DID::from(node_did.clone());

        // Build the in-process supervisor on the node's OWN loopback relay and
        // register the local DID + the broadcast context. The supervisor carries
        // the REAL document-derived governance resolver (ADR-053 / spec §10.17)
        // and the durable saga journal over the SAME `Storage` backend as
        // `mls_storage` (§17.16 / ADR-049).
        let supervisor = connect_loopback_supervisor(
            node,
            &node_did,
            &author_did,
            key_resolver,
            mls_storage,
            saga_journal,
        )
        .await?;
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

/// Builds the co-located participant's document-derived governance resolver.
///
/// Wraps a [`DidResolver`](scp_identity::resolver::DidResolver) into the
/// governance [`KeyResolver`](scp_core::context::governance::KeyResolver) shape,
/// per ADR-053 / spec §10.17.
///
/// The returned closure resolves a voter's DID document live (cache-backed —
/// the `resolver` should share the node's [`DidCache`](scp_identity::DidCache),
/// whose sequence check is the load-bearing anti-rollback guard) and extracts
/// the Ed25519 verifying key for the *exact* signing key the caller claims
/// (`#active` or `#agent`) via the hoisted, shared
/// [`scp_identity::resolver::verifying_key_from_document`] (SHB-008) — the SAME
/// helper the FFI bridges' `document_vm_key_resolver` consumes. This makes the
/// bundled self-host participant a REAL participant: governance vote signatures
/// are verified against each voter's document-derived key, never the
/// `|_, _| None` stub the bundled path used to ship.
///
/// The async resolution is bridged to the sync `KeyResolver` signature with a
/// runtime-FLAVOR-aware match, mirroring the repo's other async→sync bridges
/// ([`ApplicationNode`]'s `stop_and_wait` and the supervisor's
/// `try_consume_hard_rate_limit_from_any_context`):
/// - **No ambient runtime** (a bare sync caller / `block_on`-driven entry):
///   `handle.block_on` drives the resolve directly.
/// - **Multi-thread runtime:** [`block_in_place`](tokio::task::block_in_place)
///   re-enters `handle` to await the resolve without starving a worker thread.
/// - **Current-thread runtime:** `block_in_place` is multi-thread-only and would
///   PANIC here, so the resolve is driven on a DEDICATED `std::thread` that
///   builds and `block_on`s its own current-thread runtime (see
///   [`colocated_resolve_vm_on_dedicated_thread`]). A governance vote MUST be
///   verified, never silently rejected by a runtime-bridging panic — so this
///   branch resolves the key rather than returning `None`.
///
/// # Anti-rollback guard (load-bearing vs. defense-in-depth)
///
/// The load-bearing anti-rollback mechanism is the shared
/// [`DidCache`](scp_identity::DidCache) sequence check performed INSIDE the
/// resolver's [`resolve`](scp_identity::resolver::DidResolver::resolve)
/// (operating on the node's shared cache). The FFI bridge's
/// `IdentityBackedDidResolver::verifying_key_for` additionally applies a
/// per-instance `seen_sequences` ratchet as defense-in-depth; that ratchet is
/// intentionally NOT replicated here. It is a non-load-bearing artifact of the
/// bridge's async→sync `IdentityBackedDidResolver` wrapper, and routing through
/// that wrapper is impossible from scp-node — the wrapper lives in
/// `scp-ffi-common`, which depends on scp-node, the dependency cycle this
/// co-located helper exists to avoid. Adding a redundant ratchet here would
/// re-check, in weaker per-instance form, a property the shared cache already
/// enforces soundly.
///
/// Per the `KeyResolver` contract, any resolution failure — unknown DID,
/// missing verification method, network-unavailable, downgrade, or a malformed
/// key — collapses to `None`, which the governance engine treats as a rejected
/// vote (fail closed). `None` here is the per-lookup miss, NOT a global stub.
///
/// This is the canonical builder for a co-located (bundled-shape) participant's
/// governance resolver. The production `host_site` path wires it over the node's
/// shared cache/DHT client (see [`build_shared_cache_key_resolver`]); external
/// callers constructing a [`DeploySiteParams`] (e.g. an integration test) build
/// it the same way over their own
/// [`DualLayerResolver`](scp_identity::DualLayerResolver).
pub fn colocated_document_vm_key_resolver<R: scp_identity::resolver::DidResolver + 'static>(
    resolver: Arc<R>,
    handle: tokio::runtime::Handle,
) -> scp_core::context::governance::KeyResolver {
    Arc::new(
        move |did: &scp_identity::DID, kid: scp_identity::SigningKeyId| {
            let resolver = Arc::clone(&resolver);
            let did_owned = did.as_ref().to_owned();
            let handle = handle.clone();
            // Bridge async -> sync with a runtime-FLAVOR-aware match. `block_in_place`
            // is multi-thread-only and PANICS on a current-thread runtime, so the
            // current-thread regime is driven on a dedicated thread instead.
            match tokio::runtime::Handle::try_current() {
                // No ambient runtime: drive the resolve directly on `handle`.
                Err(_) => {
                    let outcome = handle.block_on(resolver.resolve(&did_owned)); // ci-allow: block-on: co-located KeyResolver async→sync bridge (no-runtime branch)
                    let doc = outcome.ok().flatten()?;
                    scp_identity::resolver::verifying_key_from_document(&doc.document, kid)
                }
                Ok(current) => match current.runtime_flavor() {
                    // Multi-thread runtime: `block_in_place` re-enters `handle`.
                    tokio::runtime::RuntimeFlavor::MultiThread => {
                        let outcome = tokio::task::block_in_place(|| {
                            handle.block_on(resolver.resolve(&did_owned)) // ci-allow: block-on: co-located KeyResolver async→sync bridge (multi-thread branch re-enters handle)
                        }); // ci-allow: block-on: co-located KeyResolver async→sync bridge (multi-thread block_in_place; mirrors stop_and_wait / try_consume_hard_rate_limit_from_any_context)
                        let doc = outcome.ok().flatten()?;
                        scp_identity::resolver::verifying_key_from_document(&doc.document, kid)
                    }
                    // Current-thread runtime: `block_in_place` would panic. Drive the
                    // resolve on a dedicated thread that owns its own runtime, and
                    // return the resolved key (a vote must be verified, not rejected).
                    _ => colocated_resolve_vm_on_dedicated_thread(resolver, did_owned, kid),
                },
            }
        },
    )
}

/// Dedicated-thread escape hatch for the current-thread-runtime regime, where
/// [`block_in_place`](tokio::task::block_in_place) would panic. Spawns a
/// `std::thread`, builds a current-thread tokio runtime there, `block_on`s the
/// resolve, extracts the requested verification-method key via the hoisted
/// [`scp_identity::resolver::verifying_key_from_document`], and returns it over
/// an mpsc channel.
///
/// Fails closed (`None`) on runtime-build failure or a join/recv error (the
/// thread panicked before sending) — the `KeyResolver` per-lookup miss
/// semantics — never panicking the governance caller. Mirrors the supervisor's
/// `run_rate_limit_on_dedicated_thread`.
fn colocated_resolve_vm_on_dedicated_thread<R: scp_identity::resolver::DidResolver + 'static>(
    resolver: Arc<R>,
    did_owned: String,
    kid: scp_identity::SigningKeyId,
) -> Option<ed25519_dalek::VerifyingKey> {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let rt = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(rt) => rt,
            Err(e) => {
                tracing::error!(
                    error = %e,
                    "co-located KeyResolver dedicated runtime build failed; failing closed"
                );
                let _ = tx.send(None);
                return;
            }
        };
        let outcome = rt.block_on(resolver.resolve(&did_owned)); // ci-allow: block-on: co-located KeyResolver async→sync bridge (dedicated current-thread runtime for the current-thread-runtime regime; mirrors run_rate_limit_on_dedicated_thread)
        // Any error or absent document is a per-lookup miss (fail closed).
        let key = outcome.ok().flatten().and_then(|doc| {
            scp_identity::resolver::verifying_key_from_document(&doc.document, kid)
        });
        let _ = tx.send(key);
    });
    // A join/recv error (the thread panicked before sending) fails closed.
    rx.recv().ok().flatten()
}

/// Builds an in-process [`Supervisor`](scp_core::context::supervisor::Supervisor)
/// connected to the node's own loopback relay and registers `author_did` as a
/// local DID.
///
/// The supervisor publishes encrypted envelopes onto the same relay whose blob
/// storage the node's [`commit_deploy`](ApplicationNode::commit_deploy) scans,
/// closing the publish -> commit loop in-process.
///
/// `key_resolver` is the REAL document-derived governance resolver (built via
/// [`colocated_document_vm_key_resolver`] over a [`DualLayerResolver`](scp_identity::DualLayerResolver)
/// that shares the node's [`DidCache`](scp_identity::DidCache)). It is passed
/// straight into [`Supervisor::with_providers`], so the co-located participant
/// verifies governance votes against each voter's published verification method
/// — never the `|_, _| None` stub the bundled path used to ship (ADR-053 / spec
/// §10.17).
async fn connect_loopback_supervisor<S>(
    node: &ApplicationNode<S>,
    node_did: &str,
    author_did: &scp_identity::DID,
    key_resolver: scp_core::context::governance::KeyResolver,
    mls_storage: Arc<dyn scp_core::crypto::mls::storage_adapter::OpenMlsStorageAdapter>,
    saga_journal: Arc<dyn scp_core::context::supervisor::SagaJournal>,
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
    let (event_tx, _event_rx) = tokio::sync::broadcast::channel(1000);

    // The durable saga journal is built over the SAME `Storage` backend as
    // `mls_storage` so crash-recovery replay loads unresolved saga entries from
    // one store on restart (§17.16 / ADR-049).
    let supervisor = scp_core::context::supervisor::Supervisor::with_providers_and_journal(
        crypto,
        transport,
        event_log,
        key_resolver,
        None,
        None,
        Some(event_tx),
        None,
        mls_storage,
        saga_journal,
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

// ===========================================================================
// host_site() library API
//
// The reusable core of the `scp-node --self-host` flow, exposed as a normal
// async Rust library call. The binary (`main.rs`) is a thin wrapper that reads
// env/CLI, prints its banner, and drives this with its own shutdown signal and
// an `on_ready` callback for the live-URL banner.
//
// Helpers that were previously private to `main.rs` (storage path/key
// resolution, the storage-backed sequence store, DID-method construction) live
// here so BOTH the self-host path and the full-node paths in `main.rs` call one
// shared, Result-returning implementation instead of duplicating exit-on-error
// logic. Storage location is read from the same env conventions
// (`XDG_DATA_HOME`, `HOME`, `SCP_STORAGE_KEY`) as before; self-host *policy*
// (port, TLS, reach/NAT, DHT mode) is supplied entirely via [`HostSiteConfig`].
// ===========================================================================

/// Default interval, in seconds, between self-host site re-deploys.
///
/// Site assets are published with a fixed 3600s blob TTL (`DEFAULT_BLOB_TTL` in
/// the transport envelope builder), after which the relay's blob store treats
/// them as expired and the projection 404s. Re-deploying on an interval well
/// under that TTL keeps the site continuously reachable. 1800s (half the TTL)
/// leaves ample margin for a slow or transiently-failing refresh to retry
/// before the previous deploy's blobs expire.
pub(crate) const SELF_HOST_DEPLOY_REFRESH_SECS: u64 = 1800;

/// RFC-1123 hostname placeholder for the self-host site projection.
///
/// Reachability is via the routing-id path (`/scp/broadcast/<rid>/site/...`),
/// which ignores the `Host` header, so this value is a non-empty, valid
/// placeholder only. It must not collide with the node's own domain — in
/// no-domain mode there is none, so any valid hostname is safe.
pub(crate) const SELF_HOST_HOSTNAME: &str = "selfhost.scp.local";

/// An optionally-present NAT port mapper handle, retained for clean teardown.
///
/// `Some` only when built with the `upnp` feature; `None` otherwise (no router
/// mapping is attempted, so there is nothing to release).
type OptionalPortMapper = Option<Arc<dyn scp_transport::nat::PortMapper>>;

/// Boxed callback for BEP44 sequence initialization.
///
/// Invoked with the node's DID string after `build()` completes, before any
/// publish operation, to recover the BEP44 sequence number from the persistent
/// store and/or DHT.
pub type SeqInitFn = Box<
    dyn FnOnce(String) -> Pin<Box<dyn Future<Output = Result<(), IdentityError>> + Send>> + Send,
>;

/// Reports the live site details to the caller once the site is deployed and
/// the public listener is about to open.
///
/// The binary uses this to print its operator-facing "live URL" banner without
/// the library having to print anything itself.
#[derive(Debug, Clone)]
pub struct HostSiteReady {
    /// The deterministic broadcast context id for the site (hex `SHA-256` of
    /// the node DID).
    pub context_id: String,
    /// The node's DID string.
    pub node_did: String,
    /// The port the public listener binds (`0.0.0.0:<port>`).
    pub port: u16,
    /// The number of static assets deployed.
    pub asset_count: usize,
    /// Whether the listener serves plaintext HTTP (`true`) or self-signed HTTPS
    /// (`false`).
    pub plaintext: bool,
    /// The hex-encoded routing id (`SHA-256(context_id)`) used in the canonical
    /// SCP projection path `/scp/broadcast/<routing_id_hex>/site/...`.
    pub routing_id_hex: String,
}

/// Flat configuration object for [`host_site`] / [`host_site_until`] (ADR-052
/// Phase B-P3c).
///
/// This is the construction-pattern shape for the hosted-site entry point,
/// folding the former host-options booleans into the same enums
/// [`NodeConfig`](crate::NodeConfig) uses (M1): `plaintext` → [`tls: TlsMode`](TlsMode),
/// `skip_nat` → [`reach: Reach`](Reach), and the DHT client selection into an
/// explicit [`dht: DhtMode`](DhtMode).
///
/// It takes the name `HostSiteConfig`, not the bare `SiteConfig`, because that
/// name is already the FFI-exported [`crate::SiteConfig`] (virtual-host deploy
/// limits) — a compiler-level constraint, the one legitimate naming deviation
/// (see ADR-052 `§host_site` and `.docs/standards/construction.md`).
///
/// # No whole-struct `Default` (M4)
///
/// [`reach`](Self::reach) is an irreducible required decision (it is non-`Option`),
/// so there is **no** whole-struct `Default`. Use [`HostSiteConfig::defaults`]
/// for the spread idiom over a chosen `reach`.
///
/// # Local demo vs public hosting
///
/// [`HostSiteConfig::defaults`] is fail-safe: [`DhtMode::Memory`] means the DID
/// document is NOT published to the DHT, [`TlsMode::SelfSigned`] serves HTTPS,
/// and the reach is whatever you pass. For a fully local demo, pass
/// [`Reach::Local`] (skips NAT probing) and set `tls: TlsMode::Plaintext` so no
/// router port is opened and the listener serves plain HTTP. For PUBLIC hosting,
/// pass [`Reach::NatTraversal`] and opt into [`DhtMode::Production`]
/// deliberately (it publishes the host's address bound to its DID to the global
/// Mainline DHT — a location disclosure). [`DhtMode::Memory`] (no publish) is
/// the fail-safe direction and is valid for every reach — including
/// [`Reach::NatTraversal`], the "reachable but not DHT-discoverable" config
/// (share the address out-of-band) — never an error.
///
/// See the runnable example at `crates/scp-node/examples/website.rs` and the
/// guide `.docs/guides/self-hosting-a-website-on-scp.md`.
pub struct HostSiteConfig {
    // --- Required (irreducible; no whole-struct Default — M4) ---
    /// How the hosted site is reached from the outside (addressing XOR).
    ///
    /// Folds the former `skip_nat` bool (M1): [`Reach::Local`] skips the
    /// STUN/NAT external-address probe and UPnP/NAT-PMP port mapping entirely
    /// (binding a loopback relay URL — correct behind a tunnel/proxy that
    /// terminates externally), while [`Reach::NatTraversal`] probes NAT and
    /// publishes a routable address.
    pub reach: Reach,

    // --- Enums (M1) ---
    /// How TLS is provisioned for the public listener — the SAME enum as
    /// [`NodeConfig::tls`](crate::NodeConfig).
    ///
    /// Folds the former `plaintext` bool (M1): [`TlsMode::Plaintext`] serves
    /// plain HTTP (the hosted content is public broadcast content anyway, but
    /// HTTPS-Only browsers refuse `http://`); [`TlsMode::SelfSigned`] serves
    /// self-signed HTTPS.
    pub tls: TlsMode,
    /// Which DHT client to use. Defaults to the fail-safe [`DhtMode::Memory`],
    /// which never touches the network. Set [`DhtMode::Production`] to opt into
    /// public hosting — it publishes the host's public address bound to the node
    /// DID to the global Mainline DHT (an IP-to-identity / location disclosure).
    ///
    /// [`DhtMode::Memory`] (no publish) is the fail-safe, non-disclosing
    /// direction and is valid with **any** [`reach`](Self::reach), including the
    /// publishing-capable [`Reach::NatTraversal`]: that pairing is the
    /// reachable-but-unpublished config (share the address out-of-band), never an
    /// error — the same M2 stance as [`NodeConfig`](crate::NodeConfig). Only
    /// [`DhtMode::Production`] discloses, so only it is an explicit opt-in.
    pub dht: DhtMode,

    // --- Defaulted fields ---
    /// Directory of static site files to host. `None` uses the embedded default
    /// site (with the node DID injected into `index.html`). When `Some`, the
    /// directory must contain an `index.html` at its root; every file under it
    /// is served verbatim.
    pub site_dir: Option<PathBuf>,
    /// Port the public listener binds on `0.0.0.0`. Defaults to the port of
    /// [`crate::DEFAULT_HTTP_BIND_ADDR`] (8443).
    pub port: u16,
    /// `SQLite` storage directory. `None` resolves to the XDG default
    /// (`$XDG_DATA_HOME/scp/node`, falling back to `$HOME/.local/share/scp/node`).
    pub storage_path: Option<PathBuf>,
    /// DHT HTTP gateway URLs threaded into the production pkarr client. Empty by
    /// default (Mainline DHT only). Ignored when [`dht`](Self::dht) is
    /// [`DhtMode::Memory`].
    pub dht_gateways: Vec<String>,
    /// Per-IP rate limit for the projection endpoints. Defaults to
    /// [`DEFAULT_PROJECTION_RATE_LIMIT`](crate::DEFAULT_PROJECTION_RATE_LIMIT).
    pub projection_rate_limit: u32,
    /// Interval between site re-deploys (to beat the blob TTL). Defaults to
    /// 1800s.
    pub refresh_interval: Duration,
    /// Optional callback invoked once, right after the initial deploy and TLS
    /// setup, before the public listener opens. Receives the live-site details
    /// so a caller (e.g. the binary) can print an operator banner. The library
    /// itself prints nothing.
    pub on_ready: Option<Box<dyn FnOnce(HostSiteReady) + Send>>,
}

impl HostSiteConfig {
    /// Constructs a [`HostSiteConfig`] from the irreducible required field
    /// (`reach`), filling every other field with its **fail-safe** default
    /// (ADR-052 M4).
    ///
    /// Fail-safe defaults: `tls = TlsMode::SelfSigned`, `dht = DhtMode::Memory`
    /// (no publish), `site_dir = None` (embedded site), `port =
    /// DEFAULT_HTTP_BIND_ADDR.port()`, `storage_path = None` (XDG default),
    /// `dht_gateways = []`, `projection_rate_limit = DEFAULT_PROJECTION_RATE_LIMIT`,
    /// `refresh_interval = 1800s`, `on_ready = None`.
    ///
    /// This enables the spread idiom. Because `reach` is moved into the returned
    /// struct, the caller passes a `reach` value to `defaults(...)` separate
    /// from any field it overrides:
    ///
    /// ```ignore
    /// HostSiteConfig {
    ///     tls: TlsMode::Plaintext,
    ///     ..HostSiteConfig::defaults(Reach::Local)
    /// }
    /// ```
    #[must_use]
    pub fn defaults(reach: Reach) -> Self {
        Self {
            reach,
            tls: TlsMode::SelfSigned,
            dht: DhtMode::Memory,
            site_dir: None,
            port: crate::DEFAULT_HTTP_BIND_ADDR.port(),
            storage_path: None,
            dht_gateways: Vec::new(),
            projection_rate_limit: crate::DEFAULT_PROJECTION_RATE_LIMIT,
            refresh_interval: Duration::from_secs(SELF_HOST_DEPLOY_REFRESH_SECS),
            on_ready: None,
        }
    }
}

impl std::fmt::Debug for HostSiteConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HostSiteConfig")
            .field("reach", &self.reach)
            .field("tls", &tls_mode_label(&self.tls))
            .field("dht", &self.dht)
            .field("site_dir", &self.site_dir)
            .field("port", &self.port)
            .field("storage_path", &self.storage_path)
            .field("dht_gateways", &self.dht_gateways)
            .field("projection_rate_limit", &self.projection_rate_limit)
            .field("refresh_interval", &self.refresh_interval)
            .field("on_ready", &self.on_ready.as_ref().map(|_| "<callback>"))
            .finish()
    }
}

/// A short, non-secret label for a [`TlsMode`] for `Debug` output.
///
/// [`TlsMode`] is not `Debug` (its `Custom` variant carries an
/// `Arc<dyn TlsProvider>`), so [`HostSiteConfig`]'s `Debug` impl renders the
/// mode via this stable label instead.
const fn tls_mode_label(tls: &TlsMode) -> &'static str {
    match tls {
        TlsMode::SelfSigned => "SelfSigned",
        TlsMode::Acme { .. } => "Acme",
        TlsMode::Plaintext => "Plaintext",
        TlsMode::Terminated => "Terminated",
        TlsMode::Custom(_) => "Custom",
    }
}

/// Errors produced by [`host_site`] / [`host_site_until`], granular per stage so
/// a caller can distinguish (e.g.) a storage-permission failure from a deploy
/// failure.
#[derive(Debug, thiserror::Error)]
pub enum HostSiteError {
    /// The [`HostSiteConfig`] names something this deployment driver cannot serve
    /// (ADR-052 M3 — fail loud, never a silent no-op). The cases: a
    /// [`Reach::Domain`] (a hosted site builds a no-domain node, reached via its
    /// routing-id path, not a DNS domain), or a [`TlsMode`] the no-domain
    /// listener does not provision ([`TlsMode::Acme`] — no DNS name to provision
    /// for; [`TlsMode::Terminated`] / [`TlsMode::Custom`] — no upstream
    /// terminator here). The DHT axis is NOT a source of this error:
    /// [`DhtMode::Memory`] (no publish) is the fail-safe direction and valid for
    /// every reach.
    #[error("invalid host-site config: {0}")]
    InvalidConfig(String),
    /// The storage directory could not be resolved, created, or written.
    #[error("storage path error: {0}")]
    StoragePath(String),
    /// The `SQLCipher` encryption key could not be resolved or generated.
    #[error("storage key error: {0}")]
    StorageKey(String),
    /// An encrypted `SQLite` database could not be opened.
    #[error("storage open error: {0}")]
    StorageOpen(String),
    /// The persistent key custody backend failed to initialize.
    #[error("key custody error: {0}")]
    Custody(String),
    /// The persistent blob storage backend failed to open.
    #[error("blob storage error: {0}")]
    BlobStorage(String),
    /// The DID method (DHT client) could not be constructed.
    #[error("DID method error: {0}")]
    DidMethod(String),
    /// The application node failed to build.
    #[error("node build error: {0}")]
    NodeBuild(String),
    /// The site assets could not be loaded from the site directory.
    #[error("load assets error: {0}")]
    LoadAssets(String),
    /// The self-signed TLS configuration could not be built.
    #[error("TLS config error: {0}")]
    Tls(String),
    /// The site deploy (publish + commit) failed.
    #[error("deploy error: {0}")]
    Deploy(#[from] SelfHostError),
    /// The deployer setup (loopback supervisor / broadcast group) failed.
    #[error("deployer setup error: {0}")]
    DeployerSetup(String),
    /// The public listener failed to start.
    #[error("serve error: {0}")]
    Serve(String),
}

/// Validates a [`HostSiteConfig`]'s `reach` / `tls` / `dht` triple and lowers
/// the construction-pattern enums onto the internal `(plaintext, skip_nat)`
/// booleans the no-domain self-host build path threads.
///
/// The fold (ADR-052 M1):
/// - `tls`: [`TlsMode::Plaintext`] ⇒ `plaintext = true` (plain HTTP listener);
///   [`TlsMode::SelfSigned`] ⇒ `plaintext = false` (self-signed HTTPS). The
///   no-domain self-host listener only provisions those two modes
///   ([`build_self_host_tls_config`]); [`TlsMode::Acme`], [`TlsMode::Terminated`],
///   and [`TlsMode::Custom`] are a loud [`HostSiteError::InvalidConfig`] (there
///   is no DNS name to provision for and no upstream terminator in this
///   deployment driver).
/// - `reach`: [`Reach::NatTraversal`] ⇒ `skip_nat = false` (probe NAT, publish a
///   routable address); [`Reach::Local`] ⇒ `skip_nat = true` (loopback relay URL).
///   [`Reach::Tunnel`] ⇒ `skip_nat = true` (loopback relay URL — correct behind a
///   tunnel/proxy) *and* emits a `tracing::warn!` that `public_url` is not yet
///   threaded in `host_site`. [`Reach::Domain`] is a loud error: `host_site` builds
///   a no-domain node, so a domain reach has no meaning here.
///
/// This lowering does NOT validate the DHT axis: [`DhtMode::Memory`] (do not
/// publish the DID document) is the fail-safe, non-disclosing direction and is
/// valid for every [`Reach`], including the publishing-capable
/// [`Reach::NatTraversal`] — the reachable-but-unpublished self-host case
/// ("publicly reachable, address shared out-of-band, not published to the DHT").
/// Only [`DhtMode::Production`] discloses, and it is already a deliberate opt-in
/// (Memory is the default), so there is nothing to reject — the same rule
/// [`NodeConfig`](crate::NodeConfig) enforces. `dht` is therefore not an input
/// here; it selects the DHT client downstream, not validity.
fn lower_host_site_reach_tls(reach: &Reach, tls: &TlsMode) -> Result<(bool, bool), HostSiteError> {
    let plaintext = match tls {
        TlsMode::Plaintext => true,
        TlsMode::SelfSigned => false,
        TlsMode::Acme { .. } => {
            return Err(HostSiteError::InvalidConfig(
                "TlsMode::Acme is not valid for host_site: a hosted site builds a no-domain node \
                 with no DNS name to provision a Let's Encrypt certificate for. Use \
                 TlsMode::SelfSigned or TlsMode::Plaintext."
                    .to_owned(),
            ));
        }
        TlsMode::Terminated => {
            return Err(HostSiteError::InvalidConfig(
                "TlsMode::Terminated is not valid for host_site: this deployment driver has no \
                 upstream TLS terminator. Use TlsMode::SelfSigned (self-signed HTTPS) or \
                 TlsMode::Plaintext (a tunnel/proxy adds TLS in front)."
                    .to_owned(),
            ));
        }
        TlsMode::Custom(_) => {
            return Err(HostSiteError::InvalidConfig(
                "TlsMode::Custom is not valid for host_site: the no-domain self-host listener \
                 provisions only self-signed or plaintext. Use TlsMode::SelfSigned or \
                 TlsMode::Plaintext."
                    .to_owned(),
            ));
        }
    };

    let skip_nat = match reach {
        Reach::NatTraversal => false,
        Reach::Local => true,
        Reach::Tunnel { public_url } => {
            tracing::warn!(
                public_url,
                "Reach::Tunnel.public_url is carried but not yet threaded in host_site; \
                 the node publishes a loopback relay URL. Configure the tunnel to forward \
                 to that loopback listener."
            );
            true
        }
        Reach::Domain { .. } => {
            return Err(HostSiteError::InvalidConfig(
                "Reach::Domain is not valid for host_site: a hosted site builds a no-domain node \
                 reached via its routing-id path, not a DNS domain. Use Reach::NatTraversal \
                 (public), Reach::Local, or Reach::Tunnel."
                    .to_owned(),
            ));
        }
    };

    Ok((plaintext, skip_nat))
}

/// Hosts a static website on SCP, serving until the process receives a Ctrl-C
/// (or platform shutdown) signal.
///
/// This is the library entry point behind `scp-node --self-host`. It builds a
/// no-domain [`ApplicationNode`] over persistent encrypted `SQLite` storage,
/// deploys the site through the real broadcast publish + projection pipeline,
/// opens the restricted public website surface, refreshes the deploy on an
/// interval (to beat the blob TTL), and tears everything down cleanly on
/// shutdown.
///
/// See [`HostSiteConfig`] for configuration (including the local-demo vs
/// public-hosting distinction), the runnable example at
/// `crates/scp-node/examples/website.rs`, and the guide
/// `.docs/guides/self-hosting-a-website-on-scp.md`.
///
/// The default [`DhtMode::Memory`] publishes nothing to the network (fail-safe).
/// To make the site publicly reachable, opt in with [`DhtMode::Production`],
/// which publishes this node's public address bound to its DID to the global
/// Mainline DHT (an IP-to-identity / location disclosure).
///
/// To drive shutdown yourself (e.g. in a test or a custom binary), use
/// [`host_site_until`].
///
/// # Errors
///
/// Returns a [`HostSiteError`] if the config names something this deployment
/// driver cannot serve ([`HostSiteError::InvalidConfig`] — a [`Reach::Domain`]
/// or a non-self-host [`TlsMode`]; the DHT axis is never an error since
/// [`DhtMode::Memory`] is valid for every reach) or any stage fails: storage
/// path/key resolution,
/// storage/custody/blob open, DID method construction, node build, asset load,
/// TLS config, deploy, or serve. Returns `Ok(())` on clean shutdown.
pub async fn host_site(config: HostSiteConfig) -> Result<(), HostSiteError> {
    host_site_until(config, async {
        scp_transport::startup::shutdown_signal().await;
    })
    .await
}

/// Like [`host_site`] but serves until the provided `shutdown` future resolves,
/// instead of installing a Ctrl-C handler.
///
/// This is the seam an example, a custom binary, or an integration test uses to
/// control the lifetime of the hosted site (e.g. a `oneshot`-backed future). The
/// `scp-node --self-host` binary passes its own platform shutdown signal here.
///
/// # Errors
///
/// See [`host_site`].
pub async fn host_site_until<F>(config: HostSiteConfig, shutdown: F) -> Result<(), HostSiteError>
where
    F: Future<Output = ()> + Send + 'static,
{
    let HostSiteConfig {
        reach,
        tls,
        dht: dht_mode,
        site_dir,
        port,
        storage_path,
        dht_gateways,
        projection_rate_limit,
        refresh_interval,
        on_ready,
    } = config;

    // -- Validate (TLS×Reach) and lower the construction-pattern enums onto
    //    the internal `plaintext` / `skip_nat` booleans the build path threads.
    //    `tls` folds `plaintext`; `reach` folds `skip_nat`. `DhtMode::Memory`
    //    (no publish) is the fail-safe direction and valid for every reach, so
    //    the DHT axis needs no validation — `dht_mode` selects the DHT client
    //    downstream (the match below). --
    let (plaintext, skip_nat) = lower_host_site_reach_tls(&reach, &tls)?;

    let http_addr = SocketAddr::from(([0, 0, 0, 0], port));

    // -- Storage path + key (Result-returning; never exits) --
    let storage_dir = resolve_storage_path(storage_path.as_ref())?;
    validate_storage_path(&storage_dir)?;
    let storage_key = resolve_storage_key(&storage_dir)?;

    tracing::info!(
        bind_addr = %http_addr,
        storage_path = %storage_dir.display(),
        mode = "self-host",
        "hosting site (SQLite storage, self-host)"
    );

    // -- Root storage + custody. The single root `SqliteStorage` handle owns the
    //    advisory lock on `{dir}/scp.db.lock`; it is shared via `Arc::clone`
    //    between the BEP44 sequence store and the node builder so there is
    //    exactly one lock holder (a second open would fail with os error 35). --
    let node_storage_arc = Arc::new(open_sqlite(&storage_dir, &storage_key)?);
    let custody_storage = open_sqlite(&storage_dir.join("custody"), &storage_key)?;
    let custody = Arc::new(
        SqliteKeyCustody::new(custody_storage)
            .await
            .map_err(|e| HostSiteError::Custody(e.to_string()))?,
    );

    // -- DID method per the requested DHT mode, then dispatch into the generic
    //    serve path. The two DHT modes produce DIFFERENT concrete DID-method
    //    types (`DidDht<InMemoryDhtClient>` vs `DidDht<PkarrDhtClient>`), so the
    //    rest of the flow is generic over `D` and called from each arm — exactly
    //    the shape the binary used for `run_self_host_with`. `Memory` never
    //    publishes the DID document. --
    let cache = Arc::new(DidCache::new());
    let sequence_store: Arc<dyn SequenceStore> =
        Arc::new(StorageSequenceStore::new(Arc::clone(&node_storage_arc)));

    let common = ServeHostedSite {
        http_addr,
        port,
        plaintext,
        skip_nat,
        projection_rate_limit,
        refresh_interval,
        storage_dir,
        storage_key,
        node_storage: node_storage_arc,
        custody,
        site_dir,
        on_ready,
    };

    // The co-located participant's governance resolver MUST share the node's
    // `DidCache` (consistency + the load-bearing cache-level anti-rollback
    // sequence guard) and resolve via the same DHT client the node uses. Each
    // arm builds a `DualLayerResolver` over the concrete `DidDht`'s shared
    // `cache()`/`dht_client()`, then lowers it to the object-safe governance
    // `KeyResolver` (ADR-053 / spec §10.17, SHB-002). The `DhtMode::Memory` arm
    // wires the in-memory client (the resolver only ever resolves the local
    // participant's own published DID document there).
    let handle = tokio::runtime::Handle::current();
    match dht_mode {
        DhtMode::Memory => {
            tracing::info!(
                "using InMemoryDhtClient — DID document will NOT be published to the network \
                 (the fail-safe default; set DhtMode::Production to host publicly)"
            );
            let (did_method, seq_init) =
                build_memory_did_method(Arc::clone(&common.custody), cache, sequence_store);
            let key_resolver = build_shared_cache_key_resolver(
                Arc::clone(did_method.dht_client()),
                Arc::clone(did_method.cache()),
                handle,
            );
            serve_hosted_site(common, did_method, key_resolver, seq_init, shutdown).await
        }
        DhtMode::Production => {
            tracing::warn!(
                "DhtMode::Production — publishing this node's public address bound to its DID \
                 to the global Mainline DHT (an IP-to-identity disclosure). Use DhtMode::Memory \
                 to keep the DID document local."
            );
            let (did_method, seq_init) = build_production_did_method(
                Arc::clone(&common.custody),
                cache,
                sequence_store,
                &dht_gateways,
            )?;
            let key_resolver = build_shared_cache_key_resolver(
                Arc::clone(did_method.dht_client()),
                Arc::clone(did_method.cache()),
                handle,
            );
            serve_hosted_site(common, did_method, key_resolver, seq_init, shutdown).await
        }
    }
}

/// Builds the co-located participant's document-derived governance
/// [`KeyResolver`](scp_core::context::governance::KeyResolver) over a
/// [`DualLayerResolver`](scp_identity::DualLayerResolver) that SHARES the node's
/// [`DidCache`](scp_identity::DidCache) and resolves via the node's `dht_client`
/// (ADR-053 / spec §10.17, SHB-002).
///
/// Sharing the cache is load-bearing: the cache-level sequence check inside
/// [`resolve`](scp_identity::resolver::DidResolver::resolve) is the authoritative
/// anti-rollback guard, and operating on the node's shared cache keeps the
/// participant's view consistent with the node's. The relay layer is a
/// [`NoOpRelayQuerier`](scp_identity::resolver::NoOpRelayQuerier): the node's own
/// loopback relay is a protocol-unaware blob pipe (§10.4), not a DID-document
/// QUERY source, so DID resolution flows through the DHT layer (and cache).
fn build_shared_cache_key_resolver<D: scp_identity::dht_client::DhtClient + 'static>(
    dht_client: Arc<D>,
    cache: Arc<DidCache>,
    handle: tokio::runtime::Handle,
) -> scp_core::context::governance::KeyResolver {
    let relay = Arc::new(scp_identity::resolver::NoOpRelayQuerier);
    let resolver = Arc::new(scp_identity::DualLayerResolver::new(
        relay,
        dht_client,
        cache,
        Vec::new(),
    ));
    colocated_document_vm_key_resolver(resolver, handle)
}

/// The DHT-mode-independent inputs threaded from [`host_site_until`] into the
/// generic [`serve_hosted_site`] dispatch.
///
/// Bundled into a struct so the two DHT-mode call sites stay terse and the
/// generic function avoids a long positional argument list.
struct ServeHostedSite {
    http_addr: SocketAddr,
    port: u16,
    plaintext: bool,
    skip_nat: bool,
    projection_rate_limit: u32,
    refresh_interval: Duration,
    storage_dir: PathBuf,
    storage_key: Zeroizing<[u8; 32]>,
    node_storage: Arc<SqliteStorage>,
    custody: Arc<SqliteKeyCustody>,
    site_dir: Option<PathBuf>,
    on_ready: Option<Box<dyn FnOnce(HostSiteReady) + Send>>,
}

/// Builds the node over the concrete `did_method`, deploys the site, opens the
/// restricted public surface, and serves until `shutdown` resolves.
///
/// Parameterized over the DID method `D` so both the production-pkarr and
/// in-memory DHT modes share this body (mirrors the binary's
/// `run_self_host_with`).
async fn serve_hosted_site<D, F>(
    common: ServeHostedSite,
    did_method: Arc<D>,
    key_resolver: scp_core::context::governance::KeyResolver,
    seq_init: SeqInitFn,
    shutdown: F,
) -> Result<(), HostSiteError>
where
    D: scp_identity::DidMethod + 'static,
    F: Future<Output = ()> + Send + 'static,
{
    let ServeHostedSite {
        http_addr,
        port,
        plaintext,
        skip_nat,
        projection_rate_limit,
        refresh_interval,
        storage_dir,
        storage_key,
        node_storage,
        custody,
        site_dir,
        on_ready,
    } = common;

    // -- Build the no-domain node (persistent blob storage + retained NAT mapper
    //    handles for clean teardown). On build failure the mappings are released
    //    best-effort before returning. --
    let (node, upnp_mapper, natpmp_mapper) = build_host_site_node(
        http_addr,
        &storage_dir,
        node_storage,
        Arc::clone(&custody),
        did_method,
        projection_rate_limit,
        skip_nat,
    )
    .await?;

    let node_did = node.identity().did().to_owned();
    if let Err(e) = seq_init(node_did.clone()).await {
        tracing::error!(error = %e, "failed to initialize BEP44 sequence — publishing may fail");
    }

    let context_id = self_host_context_id(&node_did);

    // -- Load the site assets once. The embedded default injects the node DID. --
    let assets = match load_self_host_assets(site_dir.as_ref(), &node_did) {
        Ok(a) => Arc::new(a),
        Err(e) => {
            release_self_host_mappings(upnp_mapper, natpmp_mapper, port).await;
            return Err(HostSiteError::LoadAssets(e));
        }
    };
    let asset_count = assets.len();

    // -- Build the deployer ONCE (one supervisor/group/key, reused for the
    //    initial deploy and every refresh). The co-located participant carries
    //    the REAL document-derived governance resolver (ADR-053 / spec §10.17). --
    let deployer = match build_host_site_deployer(
        node.as_ref(),
        &storage_dir,
        &storage_key,
        &node_did,
        &context_id,
        key_resolver,
    )
    .await
    {
        Ok(d) => Arc::new(d),
        Err(e) => {
            release_self_host_mappings(upnp_mapper, natpmp_mapper, port).await;
            return Err(e);
        }
    };

    // -- Initial deploy BEFORE the public port opens. --
    if let Err(e) = deployer
        .deploy(node.as_ref(), &mint_deploy_id(), custody.as_ref(), &assets)
        .await
    {
        release_self_host_mappings(upnp_mapper, natpmp_mapper, port).await;
        return Err(HostSiteError::Deploy(e));
    }
    tracing::info!(committed = asset_count, "self-host site deployed");

    // -- Mount the single deployed site at the ORIGIN ROOT so a browser loading
    //    index.html resolves its root-absolute `/style.css` etc. --
    let default_routing_id = projection::compute_routing_id(&context_id);
    node.set_default_site_routing_id(default_routing_id);

    // -- Notify the caller the site is ready (binary prints the live URL). --
    if let Some(cb) = on_ready {
        cb(HostSiteReady {
            context_id: context_id.clone(),
            node_did: node_did.clone(),
            port,
            asset_count,
            plaintext,
            routing_id_hex: routing_id_hex(&context_id),
        });
    }

    // -- Build the TLS config and open the RESTRICTED public surface in the
    //    background. On either failure the retained NAT mappings are released
    //    best-effort before returning. --
    open_self_host_public_surface(
        node.as_ref(),
        http_addr,
        plaintext,
        port,
        &upnp_mapper,
        &natpmp_mapper,
    )
    .await?;

    // -- Run the refresh + NAT-renewal loops, await shutdown, and tear down. --
    run_refresh_and_serve_until_shutdown(RefreshAndServe {
        deployer,
        node,
        custody,
        assets,
        refresh_interval,
        port,
        upnp_mapper,
        natpmp_mapper,
        shutdown,
    })
    .await;

    tracing::info!("host_site stopped");
    Ok(())
}

/// Builds the self-signed multi-SAN TLS config (unless `plaintext`) and opens the
/// restricted public self-host surface in the background.
///
/// On either the TLS-config or serve failure the retained NAT mappings are
/// released best-effort (via a clone of the handles; the caller keeps ownership
/// for the renewal loop on success) before the error is returned.
async fn open_self_host_public_surface<S>(
    node: &ApplicationNode<S>,
    http_addr: SocketAddr,
    plaintext: bool,
    port: u16,
    upnp_mapper: &OptionalPortMapper,
    natpmp_mapper: &OptionalPortMapper,
) -> Result<(), HostSiteError>
where
    S: scp_platform::EncryptedStorage + 'static,
{
    let tls_config = match build_self_host_tls_config(node.relay_url(), http_addr.ip(), plaintext) {
        Ok(c) => c,
        Err(e) => {
            release_self_host_mappings(upnp_mapper.clone(), natpmp_mapper.clone(), port).await;
            return Err(e);
        }
    };

    if let Err(e) = node
        .serve_background_with_surface_tls(Some(http_addr), PublicSurface::SelfHost, tls_config)
        .await
    {
        release_self_host_mappings(upnp_mapper.clone(), natpmp_mapper.clone(), port).await;
        return Err(HostSiteError::Serve(e.to_string()));
    }

    Ok(())
}

/// Inputs to [`run_refresh_and_serve_until_shutdown`]. Bundled into a struct so
/// the call site stays terse and the function avoids a long argument list.
struct RefreshAndServe<S: scp_platform::EncryptedStorage, F> {
    deployer: Arc<SelfHostDeployer>,
    node: Arc<ApplicationNode<S>>,
    custody: Arc<SqliteKeyCustody>,
    assets: Arc<Vec<Asset>>,
    refresh_interval: Duration,
    port: u16,
    upnp_mapper: OptionalPortMapper,
    natpmp_mapper: OptionalPortMapper,
    shutdown: F,
}

/// Spawns the periodic refresh loop and the NAT-mapping renewal loop, serves
/// until `shutdown` resolves, then tears everything down in the order that
/// avoids a spurious deploy-failure ERROR and a renewal/removal race.
async fn run_refresh_and_serve_until_shutdown<S, F>(args: RefreshAndServe<S, F>)
where
    S: scp_platform::EncryptedStorage + 'static,
    F: Future<Output = ()> + Send + 'static,
{
    let RefreshAndServe {
        deployer,
        node,
        custody,
        assets,
        refresh_interval,
        port,
        upnp_mapper,
        natpmp_mapper,
        shutdown,
    } = args;

    // -- Periodic re-deploy to beat the blob TTL. The loop owns its own
    //    cancellation token so it can drain BEFORE `node.shutdown()`. --
    let refresh_cancel = tokio_util::sync::CancellationToken::new();
    let refresh = spawn_site_refresh_loop(
        deployer,
        Arc::clone(&node),
        custody,
        assets,
        refresh_interval,
        refresh_cancel.clone(),
    );

    // -- Renew the NAT port-mapping lease at 50% TTL. The mapper handles only
    //    exist under the `upnp` feature; otherwise this is a harmless no-op. --
    let renewal_cancel = tokio_util::sync::CancellationToken::new();
    let renewal_mappers: Vec<Arc<dyn scp_transport::nat::PortMapper>> =
        [&upnp_mapper, &natpmp_mapper]
            .into_iter()
            .filter_map(|m| m.as_ref().map(Arc::clone))
            .collect();
    let renewal =
        crate::spawn_self_host_mapping_renewal(renewal_mappers, port, renewal_cancel.clone());

    // -- Serve until the injected shutdown future resolves. --
    shutdown.await;
    tracing::warn!("shutdown signal received — stopping self-host site refresh and listener");

    // Teardown ordering (mirrors the binary):
    //  1. Cancel + AWAIT the refresh loop first so any in-flight deploy drains
    //     before the node is torn down (prevents a spurious deploy-failure ERROR).
    //  2. `node.shutdown()` cancels the node's token.
    //  3. Cancel + AWAIT renewal BEFORE releasing mappings so renewal can never
    //     re-issue a mapping concurrently with its removal.
    refresh_cancel.cancel();
    let _ = refresh.await;
    node.shutdown();
    renewal_cancel.cancel();
    let _ = renewal.await;
    release_self_host_mappings(upnp_mapper, natpmp_mapper, port).await;
}

// ---------------------------------------------------------------------------
// Storage path / key resolution (shared with main.rs full-node paths)
// ---------------------------------------------------------------------------

/// Resolves the storage directory path from an explicit path, env var, or XDG
/// default.
///
/// Priority: `cli_path` > `$XDG_DATA_HOME/scp/node` > `$HOME/.local/share/scp/node`.
/// (The `SCP_STORAGE_PATH` env var is resolved by the binary into `cli_path`.)
///
/// # Errors
///
/// Returns [`HostSiteError::StoragePath`] when no explicit path is given and
/// neither `XDG_DATA_HOME` nor `HOME` is set.
pub fn resolve_storage_path(cli_path: Option<&PathBuf>) -> Result<PathBuf, HostSiteError> {
    if let Some(path) = cli_path {
        return Ok(path.clone());
    }
    // XDG Base Directory Specification: $XDG_DATA_HOME or $HOME/.local/share.
    let data_home = if let Ok(xdg) = std::env::var("XDG_DATA_HOME") {
        PathBuf::from(xdg)
    } else {
        let home = std::env::var("HOME").map_err(|_| {
            HostSiteError::StoragePath(
                "HOME environment variable is not set and no storage path or \
                 XDG_DATA_HOME was provided; set HOME, XDG_DATA_HOME, or pass an \
                 explicit storage path"
                    .to_owned(),
            )
        })?;
        PathBuf::from(home).join(".local").join("share")
    };
    Ok(data_home.join("scp").join("node"))
}

/// Validates that the storage directory can be created and is writable.
///
/// # Errors
///
/// Returns [`HostSiteError::StoragePath`] if the directory cannot be created or
/// is not writable.
pub fn validate_storage_path(dir: &Path) -> Result<(), HostSiteError> {
    std::fs::create_dir_all(dir).map_err(|e| {
        HostSiteError::StoragePath(format!(
            "cannot create storage directory '{}': {e}",
            dir.display()
        ))
    })?;
    // Verify writability with a probe file.
    let probe = dir.join(".scp-write-probe");
    std::fs::write(&probe, b"probe").map_err(|e| {
        HostSiteError::StoragePath(format!(
            "storage directory '{}' is not writable: {e}",
            dir.display()
        ))
    })?;
    let _ = std::fs::remove_file(&probe);
    Ok(())
}

/// Resolves or generates the `SQLCipher` encryption key.
///
/// Reads from `SCP_STORAGE_KEY` (hex-encoded 32 bytes). If unset, generates a
/// random key and writes it to `{storage_dir}/.key` (mode 0600 on Unix); on
/// subsequent runs reads it back. All intermediate buffers are
/// [`Zeroizing`](zeroize::Zeroizing).
///
/// # Errors
///
/// Returns [`HostSiteError::StorageKey`] if the env key is invalid, the key file
/// has the wrong length, or the file cannot be read/created/written.
pub fn resolve_storage_key(storage_dir: &Path) -> Result<Zeroizing<[u8; 32]>, HostSiteError> {
    // Env var first.
    if let Ok(hex_key) = std::env::var("SCP_STORAGE_KEY") {
        let bytes = Zeroizing::new(hex::decode(&hex_key).map_err(|e| {
            HostSiteError::StorageKey(format!("SCP_STORAGE_KEY is not valid hex: {e}"))
        })?);
        if bytes.len() != 32 {
            return Err(HostSiteError::StorageKey(format!(
                "SCP_STORAGE_KEY must be 32 bytes (64 hex chars), got {} bytes",
                bytes.len()
            )));
        }
        let mut key = Zeroizing::new([0u8; 32]);
        key.copy_from_slice(&bytes);
        return Ok(key);
    }

    // Existing key file.
    let key_file = storage_dir.join(".key");
    if key_file.exists() {
        let data = Zeroizing::new(std::fs::read(&key_file).map_err(|e| {
            HostSiteError::StorageKey(format!(
                "failed to read key file {}: {e}",
                key_file.display()
            ))
        })?);
        if data.len() != 32 {
            return Err(HostSiteError::StorageKey(format!(
                "key file {} has invalid length {} (expected 32)",
                key_file.display(),
                data.len()
            )));
        }
        let mut key = Zeroizing::new([0u8; 32]);
        key.copy_from_slice(&data);
        return Ok(key);
    }

    // Generate a new key and persist it.
    std::fs::create_dir_all(storage_dir).map_err(|e| {
        HostSiteError::StorageKey(format!("failed to create storage directory: {e}"))
    })?;
    let mut key = Zeroizing::new([0u8; 32]);
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut *key);

    // On Unix, create the key file with mode 0600 atomically (no TOCTOU window).
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&key_file)
            .map_err(|e| {
                HostSiteError::StorageKey(format!(
                    "failed to create key file {}: {e}",
                    key_file.display()
                ))
            })?;
        file.write_all(&*key).map_err(|e| {
            HostSiteError::StorageKey(format!(
                "failed to write key file {}: {e}",
                key_file.display()
            ))
        })?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(&key_file, &*key).map_err(|e| {
            HostSiteError::StorageKey(format!(
                "failed to write key file {}: {e}",
                key_file.display()
            ))
        })?;
    }

    Ok(key)
}

/// Opens an encrypted `SQLite` database, returning a [`HostSiteError`] on
/// failure (the Result-returning analogue of the binary's `open_sqlite_or_exit`).
///
/// # Errors
///
/// Returns [`HostSiteError::StorageOpen`] if the database cannot be opened.
pub fn open_sqlite(dir: &Path, key: &Zeroizing<[u8; 32]>) -> Result<SqliteStorage, HostSiteError> {
    SqliteStorage::new(dir, key.as_ref()).map_err(|e| {
        HostSiteError::StorageOpen(format!(
            "failed to open SQLite storage at '{}': {e}",
            dir.display()
        ))
    })
}

// ---------------------------------------------------------------------------
// Storage-backed SequenceStore (shared)
// ---------------------------------------------------------------------------

/// [`SequenceStore`] backed by a [`Storage`] implementation.
///
/// Persists BEP44 sequence numbers to the same storage backend as the rest of
/// the node state. Key format: `bep44/seq/{did}`.
pub struct StorageSequenceStore<S: Storage> {
    storage: Arc<S>,
}

impl<S: Storage> StorageSequenceStore<S> {
    /// Wraps `storage` as a BEP44 sequence store.
    #[must_use]
    pub const fn new(storage: Arc<S>) -> Self {
        Self { storage }
    }
}

impl<S: Storage + 'static> SequenceStore for StorageSequenceStore<S> {
    fn load(
        &self,
        did: &str,
    ) -> Pin<Box<dyn Future<Output = Result<Option<u64>, IdentityError>> + Send + '_>> {
        let key = format!("bep44/seq/{did}");
        Box::pin(async move {
            let data = self
                .storage
                .retrieve(&key)
                .await
                .map_err(IdentityError::Platform)?;
            match data {
                Some(bytes) if bytes.len() == 8 => {
                    let mut buf = [0u8; 8];
                    buf.copy_from_slice(&bytes);
                    Ok(Some(u64::from_le_bytes(buf)))
                }
                Some(bytes) => {
                    tracing::warn!(
                        key = %key,
                        len = bytes.len(),
                        "BEP44 sequence data has unexpected length (expected 8), treating as absent"
                    );
                    Ok(None)
                }
                None => Ok(None),
            }
        })
    }

    fn store(
        &self,
        did: &str,
        seq: u64,
    ) -> Pin<Box<dyn Future<Output = Result<(), IdentityError>> + Send + '_>> {
        let key = format!("bep44/seq/{did}");
        let bytes = seq.to_le_bytes();
        Box::pin(async move {
            self.storage
                .store(&key, &bytes)
                .await
                .map_err(IdentityError::Platform)
        })
    }
}

// ---------------------------------------------------------------------------
// DID method construction (shared)
// ---------------------------------------------------------------------------

/// Creates a BEP44 sequence-initialization callback for a `DidDht` method.
#[must_use]
pub fn make_seq_init<D: scp_identity::DhtClient + 'static>(
    did_method: Arc<DidDht<D, SystemClock>>,
) -> SeqInitFn {
    Box::new(move |did| Box::pin(async move { did_method.initialize_sequence(&did).await }))
}

/// Builds the in-memory DID method (offline; DID docs are NOT published).
///
/// The returned method signs with `custody` and persists its BEP44 sequence in
/// `sequence_store`, but its [`InMemoryDhtClient`] never reaches the network.
#[must_use]
pub fn build_memory_did_method(
    custody: Arc<SqliteKeyCustody>,
    cache: Arc<DidCache>,
    sequence_store: Arc<dyn SequenceStore>,
) -> (Arc<DidDht<InMemoryDhtClient, SystemClock>>, SeqInitFn) {
    let dht_client = Arc::new(InMemoryDhtClient::new());
    let sign_fn = DidDht::<InMemoryDhtClient, SystemClock>::make_sign_fn(custody);
    let did_method = Arc::new(DidDht::with_client_signer_and_store(
        dht_client,
        cache,
        sign_fn,
        sequence_store,
    ));
    let seq_init = make_seq_init(Arc::clone(&did_method));
    (did_method, seq_init)
}

/// Builds the production pkarr DID method (publishes DID docs to the DHT).
///
/// The returned method signs with `custody`, persists its BEP44 sequence in
/// `sequence_store`, and publishes via a [`PkarrDhtClient`] built over the
/// Mainline DHT plus any `dht_gateways`.
///
/// # Errors
///
/// Returns [`HostSiteError::DidMethod`] if the pkarr client cannot be built.
pub fn build_production_did_method(
    custody: Arc<SqliteKeyCustody>,
    cache: Arc<DidCache>,
    sequence_store: Arc<dyn SequenceStore>,
    dht_gateways: &[String],
) -> Result<(Arc<DidDht<PkarrDhtClient, SystemClock>>, SeqInitFn), HostSiteError> {
    let dht_client = build_pkarr_client(dht_gateways)?;
    let sign_fn = DidDht::<PkarrDhtClient, SystemClock>::make_sign_fn(custody);
    let did_method = Arc::new(DidDht::with_client_signer_and_store(
        dht_client,
        cache,
        sign_fn,
        sequence_store,
    ));
    let seq_init = make_seq_init(Arc::clone(&did_method));
    Ok((did_method, seq_init))
}

/// Builds a [`PkarrDhtClient`] over the Mainline DHT plus the supplied HTTP
/// gateway URLs (empty for Mainline-only).
///
/// # Errors
///
/// Returns [`HostSiteError::DidMethod`] if the client cannot be built.
pub fn build_pkarr_client(dht_gateways: &[String]) -> Result<Arc<PkarrDhtClient>, HostSiteError> {
    let mut dht_builder = PkarrDhtClient::builder();
    for gateway in dht_gateways {
        let gateway = gateway.trim();
        if !gateway.is_empty() {
            tracing::info!(gateway = %gateway, "adding DHT HTTP gateway");
            dht_builder = dht_builder.gateway_url(gateway);
        }
    }
    dht_builder
        .build()
        .map(Arc::new)
        .map_err(|e| HostSiteError::DidMethod(format!("failed to create PkarrDhtClient: {e}")))
}

// ---------------------------------------------------------------------------
// Self-host context id
// ---------------------------------------------------------------------------

/// Derives a deterministic, hex-encoded broadcast context id for the
/// self-hosted site from the node's DID (`SHA-256(did)`, 64 hex chars).
///
/// `register_broadcast_context` requires 1-64 lowercase hex characters. The id
/// is stable across restarts for a given identity, so the site's routing id
/// (and URL) is stable.
#[must_use]
pub fn self_host_context_id(node_did: &str) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(node_did.as_bytes()))
}

// ---------------------------------------------------------------------------
// Asset loading
// ---------------------------------------------------------------------------

/// Loads the site assets to publish.
///
/// When `site_dir` is `Some`, every file under it is read recursively and
/// mapped to a site-absolute path (`<rel>` -> `/<rel>`), with content type
/// inferred from the extension. An `index.html` at the directory root is
/// required. User-supplied files are served verbatim (no DID injection).
///
/// When `site_dir` is `None`, the embedded default site is used and the node
/// DID is injected into `index.html`.
///
/// # Errors
///
/// Returns an error message if the directory is empty, lacks an `index.html` at
/// its root, or cannot be read.
pub fn load_self_host_assets(
    site_dir: Option<&PathBuf>,
    node_did: &str,
) -> Result<Vec<Asset>, String> {
    match site_dir {
        None => Ok(embedded_assets(Some(node_did))),
        Some(dir) => {
            let mut assets = Vec::new();
            read_site_dir_recursive(dir, dir, &mut assets)?;
            if assets.is_empty() {
                return Err(format!(
                    "site directory '{}' contains no files",
                    dir.display()
                ));
            }
            if !assets.iter().any(|a| a.path == "/index.html") {
                return Err(format!(
                    "site directory '{}' must contain an index.html at its root",
                    dir.display()
                ));
            }
            assets.sort_by(|a, b| a.path.cmp(&b.path));
            Ok(assets)
        }
    }
}

/// Recursively reads every file under `dir`, mapping each to an [`Asset`] whose
/// path is site-absolute relative to `root`.
fn read_site_dir_recursive(root: &Path, dir: &Path, out: &mut Vec<Asset>) -> Result<(), String> {
    let entries = std::fs::read_dir(dir)
        .map_err(|e| format!("failed to read directory '{}': {e}", dir.display()))?;
    for entry in entries {
        let entry =
            entry.map_err(|e| format!("failed to read entry in '{}': {e}", dir.display()))?;
        let path = entry.path();
        let file_type = entry
            .file_type()
            .map_err(|e| format!("failed to stat '{}': {e}", path.display()))?;
        if file_type.is_dir() {
            read_site_dir_recursive(root, &path, out)?;
        } else if file_type.is_file() {
            let rel = path
                .strip_prefix(root)
                .map_err(|e| format!("path '{}' is not under site root: {e}", path.display()))?;
            let rel_str = rel
                .to_str()
                .ok_or_else(|| format!("non-UTF-8 path: '{}'", rel.display()))?;
            let site_path = format!("/{}", rel_str.replace('\\', "/"));
            let body = std::fs::read(&path)
                .map_err(|e| format!("failed to read file '{}': {e}", path.display()))?;
            let content_type = content_type_for(&site_path).to_owned();
            out.push(Asset {
                path: site_path,
                content_type,
                body,
            });
        }
        // Symlinks and other special files are skipped intentionally.
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Node + deployer construction
// ---------------------------------------------------------------------------

/// Builds the no-domain self-host [`ApplicationNode`] over persistent storage,
/// returning it behind an `Arc` alongside the retained NAT port-mapper handles.
///
/// Mirrors the binary's `build_self_host_node` but returns a [`HostSiteError`]
/// (releasing any established mappings best-effort) instead of exiting.
async fn build_host_site_node<D: scp_identity::DidMethod + 'static>(
    http_addr: SocketAddr,
    storage_dir: &Path,
    node_storage: Arc<SqliteStorage>,
    custody: Arc<SqliteKeyCustody>,
    did_method: Arc<D>,
    projection_rate_limit: u32,
    skip_nat: bool,
) -> Result<
    (
        Arc<ApplicationNode<Arc<SqliteStorage>>>,
        OptionalPortMapper,
        OptionalPortMapper,
    ),
    HostSiteError,
> {
    let blob_db = storage_dir.join("blobs");
    let blob_storage = scp_transport::native::storage::BlobStorageBackend::sqlite(&blob_db)
        .map_err(|e| {
            HostSiteError::BlobStorage(format!(
                "failed to open persistent SQLite blob storage at '{}': {e}",
                blob_db.display()
            ))
        })?;

    // -- Reach + DHT from `skip_nat`. A `skip_nat` host reaches only locally
    //    (non-publishing → DhtMode::Memory); otherwise it NAT-traverses and
    //    publishes a routable address (DhtMode::Production, M2). --
    let (reach, dht) = if skip_nat {
        (Reach::Local, DhtMode::Memory)
    } else {
        (Reach::NatTraversal, DhtMode::Production)
    };

    // -- NAT slot with RETAINED mapper handles for clean teardown. When
    //    `skip_nat`, no mapper is constructed and the reach skips the probe;
    //    `NatSlot::Auto` is correct there. When NOT `skip_nat` (upnp build),
    //    `NatSlot::Custom(strategy)` carries the strategy and we KEEP the mapper
    //    handles for teardown — `NatSlot::Auto` would lose them. --
    #[cfg(feature = "upnp")]
    let (nat, upnp_mapper, natpmp_mapper): (NatSlot, OptionalPortMapper, OptionalPortMapper) =
        if skip_nat {
            (NatSlot::Auto, None, None)
        } else {
            let upnp: Arc<dyn scp_transport::nat::PortMapper> =
                Arc::new(scp_transport::nat::UpnpPortMapper::new());
            let natpmp: Arc<dyn scp_transport::nat::PortMapper> =
                Arc::new(scp_transport::nat::NatPmpPortMapper::new());
            let strategy = crate::DefaultNatStrategy::new(None, None)
                .with_port_mapper(Arc::clone(&upnp))
                .with_fallback_mapper(Arc::clone(&natpmp));
            (
                NatSlot::Custom(Arc::new(strategy) as Arc<dyn crate::NatStrategy>),
                Some(upnp),
                Some(natpmp),
            )
        };
    #[cfg(not(feature = "upnp"))]
    let (nat, upnp_mapper, natpmp_mapper): (NatSlot, OptionalPortMapper, OptionalPortMapper) =
        (NatSlot::Auto, None, None);

    // `IdentitySource::Persisted` gives the self-host node a STABLE DID across
    // restarts: it creates+persists the identity on first boot and reloads it
    // thereafter from the root `node_storage`. `tls` defaults to
    // `TlsMode::SelfSigned`, a no-op on a no-domain reach.
    let config = NodeConfig {
        dht,
        nat,
        http_bind_addr: Some(http_addr),
        projection_rate_limit: Some(projection_rate_limit),
        blob_storage: Some(blob_storage),
        ..NodeConfig::defaults(
            reach,
            IdentitySource::Persisted {
                custody,
                did_method,
            },
            node_storage,
        )
    };

    match Node::start(config).await {
        Ok(n) => Ok((Arc::new(n), upnp_mapper, natpmp_mapper)),
        Err(e) => {
            // `Node::start` establishes the inbound port mapping during NAT tier
            // selection and CAN still fail afterward, so release best-effort.
            release_self_host_mappings(upnp_mapper, natpmp_mapper, http_addr.port()).await;
            Err(HostSiteError::NodeBuild(e.to_string()))
        }
    }
}

/// Performs the one-time [`SelfHostDeployer`] setup over a `SQLite` MLS store
/// under `storage_dir/mls`. Mirrors the binary's `build_self_host_deployer`.
async fn build_host_site_deployer<S>(
    node: &ApplicationNode<S>,
    storage_dir: &Path,
    storage_key: &Zeroizing<[u8; 32]>,
    node_did: &str,
    context_id: &str,
    key_resolver: scp_core::context::governance::KeyResolver,
) -> Result<SelfHostDeployer, HostSiteError>
where
    S: scp_platform::EncryptedStorage + 'static,
{
    /// Derives BOTH durable providers — the saga journal and the `OpenMLS`
    /// `mls_storage` view — from a SINGLE `Storage` handle (§17.6 / §17.16 /
    /// ADR-049).
    ///
    /// Folding the two derivations behind one handle parameter makes it
    /// impossible to wire the saga journal to a different backend than
    /// `mls_storage`: a reviewer proved that splitting them into separate
    /// derivations let a single mutated constructor pass a fresh in-memory store
    /// to the journal while leaving every gate/test green — silently disabling
    /// crash-recovery replay. Both providers come from the one
    /// `{storage_dir}/mls` `SQLCipher` handle, so saga replay and the `OpenMLS`
    /// view read and write one store by construction. Kept inside
    /// `build_host_site_deployer` so the single construction site is the only
    /// place either provider is derived.
    fn durable_providers_from_handle<H>(
        handle: Arc<H>,
    ) -> (
        Arc<dyn scp_core::context::supervisor::SagaJournal>,
        Arc<dyn scp_core::crypto::mls::storage_adapter::OpenMlsStorageAdapter>,
    )
    where
        H: Storage + 'static,
    {
        let saga_journal: Arc<dyn scp_core::context::supervisor::SagaJournal> = Arc::new(
            scp_core::context::supervisor::ProtocolRepositorySagaJournal::new(Arc::clone(&handle)),
        );
        let mls_storage: Arc<dyn scp_core::crypto::mls::storage_adapter::OpenMlsStorageAdapter> =
            Arc::new(scp_core::crypto::mls::storage_adapter::SpawnBlockingStorageAdapter::new(
                handle,
            ));
        (saga_journal, mls_storage)
    }

    let mls_inner = Arc::new(
        SqliteStorage::new(&storage_dir.join("mls"), storage_key.as_ref()).map_err(|e| {
            HostSiteError::StorageOpen(format!("failed to open MLS SQLite storage: {e}"))
        })?,
    );
    // The durable saga journal and the `mls_storage` view are derived from the
    // SAME `Arc<SqliteStorage>` in one call so crash-recovery replay and the
    // `OpenMLS` view read and write one `{storage_dir}/mls` SQLCipher store and
    // cannot diverge by construction (§17.6 / §17.16 / ADR-049).
    let (saga_journal, mls_storage) = durable_providers_from_handle(mls_inner);

    let signing_key_handle = node.identity().identity().active_signing_key;
    SelfHostDeployer::start(
        node,
        node_did.to_owned(),
        context_id.to_owned(),
        SELF_HOST_HOSTNAME.to_owned(),
        signing_key_handle,
        key_resolver,
        mls_storage,
        saga_journal,
    )
    .await
    .map_err(|e| HostSiteError::DeployerSetup(e.to_string()))
}

/// Mints a unique deploy id for a single self-host deploy run.
///
/// `commit_deploy` counts blobs whose decrypted `deploy_id` matches the
/// requested one; a constant id would count stale within-TTL blobs from a prior
/// run and trip a count mismatch. The id combines a nanosecond timestamp with OS
/// randomness so it is unique across runs.
fn mint_deploy_id() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0u128, |d| d.as_nanos());
    let mut rand_bytes = [0u8; 8];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut rand_bytes);
    format!("selfhost-{nanos:032x}-{}", hex::encode(rand_bytes))
}

/// Spawns the periodic site refresh loop, re-deploying every `period` (well
/// under the blob TTL) until `shutdown_token` is cancelled.
///
/// Each refresh reuses the deployer's supervisor/group/key, mints a fresh
/// `deploy_id`, and re-points the deploy manifest at fresh, full-TTL blobs.
fn spawn_site_refresh_loop<S>(
    deployer: Arc<SelfHostDeployer>,
    node: Arc<ApplicationNode<S>>,
    custody: Arc<SqliteKeyCustody>,
    assets: Arc<Vec<Asset>>,
    period: Duration,
    shutdown_token: tokio_util::sync::CancellationToken,
) -> tokio::task::JoinHandle<()>
where
    S: scp_platform::EncryptedStorage + 'static,
{
    let period = period.max(Duration::from_secs(1));
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(period);
        // Skip the immediate first tick; the caller already performed the
        // initial deploy before opening the public port.
        interval.tick().await;
        loop {
            tokio::select! {
                () = shutdown_token.cancelled() => {
                    tracing::debug!("self-host refresh loop observed shutdown");
                    break;
                }
                _ = interval.tick() => {
                    match deployer
                        .deploy(node.as_ref(), &mint_deploy_id(), custody.as_ref(), &assets)
                        .await
                    {
                        Ok(committed) => tracing::info!(
                            committed,
                            "self-host site refreshed (TTL renewal)"
                        ),
                        Err(e) => tracing::error!(
                            error = %e,
                            "self-host site refresh failed; will retry next interval"
                        ),
                    }
                }
            }
        }
    })
}

/// Best-effort release of the retained NAT port mappings on BOTH mappers.
///
/// Called on every exit path that occurs after the node (and thus its port
/// mapping) is built. The mapper handles are only ever `Some` under the `upnp`
/// feature; otherwise this is a no-op.
async fn release_self_host_mappings(
    upnp: OptionalPortMapper,
    natpmp: OptionalPortMapper,
    port: u16,
) {
    for (label, mapper) in [("upnp", upnp), ("natpmp", natpmp)] {
        if let Some(mapper) = mapper {
            match mapper.remove(port).await {
                Ok(()) => tracing::info!(mapper = label, port, "released NAT port mapping"),
                Err(e) => tracing::warn!(
                    mapper = label,
                    port,
                    error = %e,
                    "failed to release NAT port mapping; it will persist until lease expiry"
                ),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Self-signed TLS config for the self-host listener
// ---------------------------------------------------------------------------

/// Builds the self-signed multi-SAN TLS config for the self-host listener, or
/// returns `None` when `plaintext` is set.
///
/// The "be your own CA" no-DNS model: the certificate presents a SAN for every
/// address a browser might use (`localhost`, `127.0.0.1`, the bind IP when
/// concrete, and the external IP parsed from the node's relay URL). Browsers
/// show a one-time untrusted-certificate warning because there is no CA.
///
/// # Errors
///
/// Returns [`HostSiteError::Tls`] on certificate-generation or TLS-config
/// failure — there is no safe silent fallback to plaintext once HTTPS was
/// requested.
pub fn build_self_host_tls_config(
    relay_url: &str,
    bind_ip: std::net::IpAddr,
    plaintext: bool,
) -> Result<Option<Arc<rustls::ServerConfig>>, HostSiteError> {
    if plaintext {
        tracing::warn!(
            "plaintext requested — serving plain HTTP (HTTPS-Only browsers will refuse \
             to open the site)"
        );
        return Ok(None);
    }

    let dns_sans = vec!["localhost".to_owned()];
    let mut ip_sans: Vec<std::net::IpAddr> =
        vec![std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)];

    if !bind_ip.is_unspecified() && !bind_ip.is_loopback() {
        ip_sans.push(bind_ip);
    }
    if let Some(external_ip) = external_ip_from_relay_url(relay_url)
        && !ip_sans.contains(&external_ip)
    {
        ip_sans.push(external_ip);
    }

    let cert = crate::tls::generate_self_signed_multi(&dns_sans, &ip_sans)
        .map_err(|e| HostSiteError::Tls(format!("failed to generate self-signed cert: {e}")))?;
    let server_config = crate::tls::build_tls_server_config(&cert)
        .map_err(|e| HostSiteError::Tls(format!("failed to build TLS server config: {e}")))?;
    tracing::info!(
        dns_sans = ?dns_sans,
        ip_sans = ?ip_sans,
        "self-host serving self-signed HTTPS (TLS 1.3, no CA)"
    );
    Ok(Some(Arc::new(server_config)))
}

/// Parses the external IP from a no-domain relay URL of the form
/// `ws://<host>:<port>/scp/v1`, returning it only when `<host>` is a bare IP
/// literal (not a DNS name and not loopback/unspecified).
#[must_use]
pub fn external_ip_from_relay_url(relay_url: &str) -> Option<std::net::IpAddr> {
    let after_scheme = relay_url
        .split_once("://")
        .map_or(relay_url, |(_, rest)| rest);
    let authority = after_scheme.split('/').next().unwrap_or(after_scheme);
    let host = if let Some(rest) = authority.strip_prefix('[') {
        rest.split_once(']').map(|(h, _)| h)?
    } else {
        authority.split(':').next().unwrap_or(authority)
    };
    let ip: std::net::IpAddr = host.parse().ok()?;
    if ip.is_loopback() || ip.is_unspecified() {
        None
    } else {
        Some(ip)
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // HostSiteConfig shape + reach/tls lowering (`lower_host_site_reach_tls`)
    //
    // These cover the ADR-052 P3c folds: `HostSiteConfig::defaults` is fail-safe
    // (M4 — no whole-struct Default, a reach-keyed factory instead), `plaintext`
    // is folded into `TlsMode`, `skip_nat` into `Reach`. `DhtMode::Memory` (no
    // publish) is the fail-safe direction and valid for every reach, so the
    // lowering does not validate the DHT axis (M2: only `Production` discloses,
    // and it is the explicit opt-in).
    // -----------------------------------------------------------------------

    /// `HostSiteConfig::defaults(reach)` fills every non-required field with the
    /// fail-safe value: self-signed TLS, no-publish DHT, embedded site.
    #[test]
    fn defaults_are_fail_safe() {
        let config = HostSiteConfig::defaults(Reach::Local);
        assert!(
            matches!(config.tls, TlsMode::SelfSigned),
            "defaults must serve self-signed HTTPS, not plaintext"
        );
        assert_eq!(
            config.dht,
            DhtMode::Memory,
            "defaults must NOT publish to the DHT (fail-safe, M2)"
        );
        assert!(
            config.site_dir.is_none(),
            "defaults must use the embedded site"
        );
        assert!(
            matches!(config.reach, Reach::Local),
            "defaults must carry the reach it was keyed on"
        );
    }

    /// `TlsMode::Plaintext` folds to `plaintext = true` (the former `plaintext`
    /// bool); `TlsMode::SelfSigned` folds to `plaintext = false`. Both pair with
    /// a non-publishing `Reach::Local`, so neither trips the M2 rule.
    #[test]
    fn tls_mode_folds_plaintext_bool() {
        let (plaintext, _skip_nat) = lower_host_site_reach_tls(&Reach::Local, &TlsMode::Plaintext)
            .expect("Local + Plaintext is a valid local-demo config");
        assert!(
            plaintext,
            "TlsMode::Plaintext must lower to a plaintext listener"
        );

        let (plaintext, _skip_nat) = lower_host_site_reach_tls(&Reach::Local, &TlsMode::SelfSigned)
            .expect("Local + SelfSigned is valid");
        assert!(
            !plaintext,
            "TlsMode::SelfSigned must lower to a (self-signed HTTPS) non-plaintext listener"
        );
    }

    /// `Reach::Local` / `Reach::Tunnel` fold to `skip_nat = true` (the former
    /// `skip_nat` bool); `Reach::NatTraversal` folds to `skip_nat = false`.
    #[test]
    fn reach_folds_skip_nat_bool() {
        let (_p, skip_nat) =
            lower_host_site_reach_tls(&Reach::Local, &TlsMode::Plaintext).expect("Local is valid");
        assert!(skip_nat, "Reach::Local must skip the NAT probe");

        let (_p, skip_nat) = lower_host_site_reach_tls(
            &Reach::Tunnel {
                public_url: "https://tunnel.example".to_owned(),
            },
            &TlsMode::Plaintext,
        )
        .expect("Tunnel lowers to skip_nat");
        assert!(skip_nat, "Reach::Tunnel must skip the NAT probe");

        let (_p, skip_nat) = lower_host_site_reach_tls(&Reach::NatTraversal, &TlsMode::SelfSigned)
            .expect("NatTraversal lowers to probe NAT");
        assert!(!skip_nat, "Reach::NatTraversal must probe NAT");
    }

    /// `Reach::NatTraversal` lowers cleanly regardless of DHT mode: the lowering
    /// validates only the TLS×Reach axis, never the DHT axis. `DhtMode::Memory`
    /// (no publish) is the fail-safe direction and valid for every reach — the
    /// reachable-but-unpublished self-host case (publicly reachable via NAT
    /// traversal, address shared out-of-band, not published to the DHT). It is
    /// never an error; only `DhtMode::Production` discloses, and it is the
    /// explicit opt-in (M2).
    #[test]
    fn nat_traversal_lowers_for_both_dht_modes() {
        // `lower_host_site_reach_tls` no longer takes a `dht` arg — the DHT mode
        // does not affect reach/TLS lowering. The successful lowering is the
        // proof that a publishing-capable reach is accepted with the default
        // (Memory) DHT mode (the old, inverted rule rejected NatTraversal+Memory).
        let (_p, skip_nat) = lower_host_site_reach_tls(&Reach::NatTraversal, &TlsMode::SelfSigned)
            .expect("NatTraversal lowers cleanly; DHT mode does not gate validity");
        assert!(!skip_nat, "Reach::NatTraversal must probe NAT");
    }

    /// `Reach::Domain` has no meaning for the no-domain `host_site` deployment
    /// driver — a loud `InvalidConfig`.
    #[test]
    fn domain_reach_is_rejected_for_host_site() {
        let err = lower_host_site_reach_tls(
            &Reach::Domain {
                domain: "example.com".to_owned(),
            },
            &TlsMode::SelfSigned,
        )
        .expect_err("Reach::Domain is not valid for host_site");
        assert!(
            matches!(err, HostSiteError::InvalidConfig(_)),
            "Reach::Domain must be a loud InvalidConfig for host_site"
        );
    }

    /// `TlsMode::Acme` / `Terminated` / `Custom` are not provisionable by the
    /// no-domain self-host listener — each is a loud `InvalidConfig`.
    #[test]
    fn non_self_host_tls_modes_are_rejected() {
        for tls in [TlsMode::Acme { email: None }, TlsMode::Terminated] {
            let err = lower_host_site_reach_tls(&Reach::Local, &tls)
                .expect_err("Acme/Terminated are not valid for host_site");
            assert!(
                matches!(err, HostSiteError::InvalidConfig(_)),
                "{} must be a loud InvalidConfig",
                tls_mode_label(&tls)
            );
        }
    }

    // -----------------------------------------------------------------------
    // NAT mapping release on shutdown (`release_self_host_mappings`)
    //
    // A mock `PortMapper` records the port passed to `remove` (and that
    // `remove` was called at all). `map_port` / `renew` are never invoked by
    // `release_self_host_mappings`, so their arms return a benign error rather
    // than panicking. Lock-free atomics keep the test free of unwrap/expect,
    // matching the existing main.rs test style.
    // -----------------------------------------------------------------------

    /// A `PortMapper` mock that records the port passed to `remove`.
    struct RecordingMapper {
        /// The port passed to the most recent `remove` call (`0` = never called).
        removed_port: Arc<std::sync::atomic::AtomicU16>,
        /// Set true once `remove` is invoked.
        removed: Arc<std::sync::atomic::AtomicBool>,
    }

    impl RecordingMapper {
        fn new() -> Self {
            Self {
                removed_port: Arc::new(std::sync::atomic::AtomicU16::new(0)),
                removed: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            }
        }
    }

    impl scp_transport::nat::PortMapper for RecordingMapper {
        fn map_port(
            &self,
            _internal_port: u16,
        ) -> Pin<
            Box<
                dyn std::future::Future<
                        Output = Result<
                            scp_transport::nat::PortMappingResult,
                            scp_transport::nat::PortMappingError,
                        >,
                    > + Send
                    + '_,
            >,
        > {
            // Never called by `release_self_host_mappings`; return a benign error.
            Box::pin(async {
                Err(scp_transport::nat::PortMappingError::NotSupported(
                    "map_port is not exercised by release_self_host_mappings".to_owned(),
                ))
            })
        }

        fn renew(
            &self,
            _internal_port: u16,
        ) -> Pin<
            Box<
                dyn std::future::Future<
                        Output = Result<
                            scp_transport::nat::PortMappingResult,
                            scp_transport::nat::PortMappingError,
                        >,
                    > + Send
                    + '_,
            >,
        > {
            // Never called by `release_self_host_mappings`; return a benign error.
            Box::pin(async {
                Err(scp_transport::nat::PortMappingError::NotSupported(
                    "renew is not exercised by release_self_host_mappings".to_owned(),
                ))
            })
        }

        fn remove(
            &self,
            internal_port: u16,
        ) -> Pin<
            Box<
                dyn std::future::Future<Output = Result<(), scp_transport::nat::PortMappingError>>
                    + Send
                    + '_,
            >,
        > {
            let removed_port = Arc::clone(&self.removed_port);
            let removed = Arc::clone(&self.removed);
            Box::pin(async move {
                removed_port.store(internal_port, std::sync::atomic::Ordering::SeqCst);
                removed.store(true, std::sync::atomic::Ordering::SeqCst);
                Ok(())
            })
        }
    }

    /// `release_self_host_mappings` calls `remove(port)` on BOTH mappers when
    /// both are present — the graceful-shutdown teardown path.
    #[tokio::test]
    async fn release_self_host_mappings_removes_mapping_on_both_mappers() {
        const PORT: u16 = 8443;

        let upnp = Arc::new(RecordingMapper::new());
        let natpmp = Arc::new(RecordingMapper::new());
        let upnp_port = Arc::clone(&upnp.removed_port);
        let upnp_flag = Arc::clone(&upnp.removed);
        let natpmp_port = Arc::clone(&natpmp.removed_port);
        let natpmp_flag = Arc::clone(&natpmp.removed);

        release_self_host_mappings(
            Some(upnp as Arc<dyn scp_transport::nat::PortMapper>),
            Some(natpmp as Arc<dyn scp_transport::nat::PortMapper>),
            PORT,
        )
        .await;

        assert!(
            upnp_flag.load(std::sync::atomic::Ordering::SeqCst),
            "the upnp mapper's remove must be called"
        );
        assert_eq!(
            upnp_port.load(std::sync::atomic::Ordering::SeqCst),
            PORT,
            "the upnp mapper must be asked to remove the served port"
        );
        assert!(
            natpmp_flag.load(std::sync::atomic::Ordering::SeqCst),
            "the natpmp mapper's remove must be called"
        );
        assert_eq!(
            natpmp_port.load(std::sync::atomic::Ordering::SeqCst),
            PORT,
            "the natpmp mapper must be asked to remove the served port"
        );
    }

    /// With no mappers present (the non-`upnp` build, where both handles are
    /// `None`), `release_self_host_mappings` is a no-op and does not panic.
    #[tokio::test]
    async fn release_self_host_mappings_noop_when_no_mappers() {
        const PORT: u16 = 8443;
        // No mappers: nothing to remove. This must complete cleanly.
        release_self_host_mappings(None, None, PORT).await;
    }

    // -----------------------------------------------------------------------
    // Co-located participant KeyResolver (ADR-053 / spec §10.17, SHB-002)
    //
    // Proves the bundled self-host participant's governance resolver is the REAL
    // document-derived resolver — it resolves a registered DID's #active key and
    // fails closed (None) for an unknown DID — NOT the `|_, _| None` stub the
    // path used to ship.
    // -----------------------------------------------------------------------

    /// Seeds a self-certifying, BEP44-signed DID document into `dht`, returning
    /// the DID and its `#active` verifying key. The DID is derived from (and the
    /// document signed by) the identity key — the production self-certification
    /// invariant the `DualLayerResolver` enforces.
    async fn seed_self_host_identity(
        dht: &InMemoryDhtClient,
    ) -> (String, ed25519_dalek::VerifyingKey) {
        use ed25519_dalek::{Signer, SigningKey};
        use scp_identity::DhtClient;

        // Distinct identity (#0) and active (#active) keys.
        let identity_signing = SigningKey::from_bytes(&[11u8; 32]);
        let active_signing = SigningKey::from_bytes(&[22u8; 32]);
        let identity_public = identity_signing.verifying_key();
        let active_public = active_signing.verifying_key();

        let did = scp_identity::did_from_ed25519_public_key(identity_public.as_bytes());
        let pre_rotation_commitment: [u8; 32] = {
            use sha2::{Digest, Sha256};
            Sha256::digest(
                SigningKey::from_bytes(&[33u8; 32])
                    .verifying_key()
                    .as_bytes(),
            )
            .into()
        };
        let doc = scp_identity::DidDocument::new(
            &did,
            identity_public.as_bytes(),
            active_public.as_bytes(),
            &pre_rotation_commitment,
        );

        // BEP44-sign the serialized document with the identity key (seq = 1).
        let value = doc.to_json().expect("doc serializes").into_bytes();
        let signable = scp_identity::dht::bep44_signable(&value, 1);
        let signature: [u8; 64] = identity_signing.sign(&signable).to_bytes();
        dht.publish(identity_public.as_bytes(), &signature, &value, 1)
            .await
            .expect("publish to in-memory DHT");

        (did, active_public)
    }

    /// SHB-002: the co-located participant's `KeyResolver`, built via
    /// [`colocated_document_vm_key_resolver`] over a `DualLayerResolver` sharing an
    /// in-memory DHT + cache, resolves a registered DID's `#active` key and
    /// returns `None` for an unknown DID — proving it is the REAL
    /// document-derived resolver, not the constant-`None` stub.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn self_host_supervisor_keyresolver_resolves_active_key() {
        let dht = Arc::new(InMemoryDhtClient::new());
        let cache = Arc::new(DidCache::new());

        // Register a DID document into the shared in-memory DHT.
        let (did, active_public) = seed_self_host_identity(&dht).await;

        // Build the co-located participant resolver over the SHARED cache + DHT,
        // exactly as the production `host_site` path wires it.
        let resolver = Arc::new(scp_identity::DualLayerResolver::new(
            Arc::new(scp_identity::resolver::NoOpRelayQuerier),
            Arc::clone(&dht),
            Arc::clone(&cache),
            Vec::new(),
        ));
        let key_resolver =
            colocated_document_vm_key_resolver(resolver, tokio::runtime::Handle::current());

        // A real resolver returns the document's #active key (NOT the None stub).
        let active_result = tokio::task::spawn_blocking({
            let key_resolver = Arc::clone(&key_resolver);
            let did = did.clone();
            move || {
                key_resolver(
                    &scp_identity::DID::from(did),
                    scp_identity::SigningKeyId::Active,
                )
            }
        })
        .await
        .expect("resolver task joins");
        assert_eq!(
            active_result,
            Some(active_public),
            "the co-located KeyResolver must resolve the registered DID's #active \
             key (proves it is the real document-derived resolver, not |_,_| None)"
        );

        // An unknown DID fails closed (None) — also proving it is not a constant
        // that returns the same key for every input.
        let unknown_pk: [u8; 32] = [0x44; 32];
        let unknown_did = scp_identity::did_from_ed25519_public_key(&unknown_pk);
        let unknown = tokio::task::spawn_blocking({
            let key_resolver = Arc::clone(&key_resolver);
            move || {
                key_resolver(
                    &scp_identity::DID::from(unknown_did),
                    scp_identity::SigningKeyId::Active,
                )
            }
        })
        .await
        .expect("resolver task joins");
        assert!(
            unknown.is_none(),
            "an unknown DID must resolve to None (fail closed)"
        );
    }

    /// FINDING 1 (BLOCKER) regression: the co-located `KeyResolver` must resolve
    /// when invoked on a CURRENT-THREAD tokio runtime — the flavor a bare
    /// `#[tokio::test]` (and a current-thread-driven Supervisor) provides.
    ///
    /// The governance engine invokes the resolver synchronously while the
    /// Supervisor's runtime is ambient. The old bridge gated solely on
    /// `Handle::try_current().is_ok()` and then called `block_in_place`, which is
    /// MULTI-THREAD-ONLY and PANICS on a current-thread runtime — silently
    /// failing the vote instead of verifying it. This test calls the resolver
    /// DIRECTLY on the current-thread runtime's thread (no `spawn_blocking`
    /// hop-off to a multi-thread pool), so it exercises the current-thread
    /// branch: it MUST return `Some(expected_key)` without panicking. Against the
    /// pre-fix code this test panics; with the dedicated-thread bridge it passes.
    #[tokio::test]
    async fn colocated_document_vm_key_resolver_resolves_on_current_thread_runtime() {
        let dht = Arc::new(InMemoryDhtClient::new());
        let cache = Arc::new(DidCache::new());

        // Register a DID document into the shared in-memory DHT.
        let (did, active_public) = seed_self_host_identity(&dht).await;

        // Build the co-located participant resolver over the SHARED cache + DHT,
        // exactly as the production `host_site` path wires it. `Handle::current()`
        // here is the bare-`#[tokio::test]` CURRENT-THREAD runtime handle.
        let resolver = Arc::new(scp_identity::DualLayerResolver::new(
            Arc::new(scp_identity::resolver::NoOpRelayQuerier),
            Arc::clone(&dht),
            Arc::clone(&cache),
            Vec::new(),
        ));
        let key_resolver =
            colocated_document_vm_key_resolver(resolver, tokio::runtime::Handle::current());

        // Invoke DIRECTLY on the current-thread runtime's thread — the path that
        // panicked under the old `block_in_place` gate. Must resolve, not panic.
        let active_result = key_resolver(
            &scp_identity::DID::from(did),
            scp_identity::SigningKeyId::Active,
        );
        assert_eq!(
            active_result,
            Some(active_public),
            "the co-located KeyResolver must resolve the registered DID's #active \
             key when invoked on a current-thread runtime (proves the BLOCKER fix: \
             the current-thread regime drives the resolve on a dedicated thread \
             instead of panicking in block_in_place)"
        );
    }
}
