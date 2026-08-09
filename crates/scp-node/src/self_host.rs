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

use scp_clock::SystemClock;
use scp_dht::{DhtClient, DisabledDhtClient, PkarrDhtClient};
// `InMemoryDhtClient` backs the test-harness-only `build_memory_did_method`
// (`DhtMode::Memory`); it is a §17.17.3 nullifier, gated out of shipped builds.
#[cfg(any(test, feature = "testing"))]
use scp_dht::InMemoryDhtClient;
use scp_identity::dht::SequenceStore;
use scp_identity::republish::{RepublishConfig, RepublishEntry, RepublishManager};
use scp_identity::{DidCache, DidDht, IdentityError};
use scp_platform::KeyCustody;
use scp_platform::sqlite::{SqliteKeyCustody, SqliteStorage};
use scp_platform::traits::Storage;
use scp_transport::native::TransportRelayPublisher;
use tokio::sync::watch;

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
    /// The loopback supervisor's durable providers — the saga journal + the
    /// `OpenMLS` `mls_storage` view bound into one
    /// [`DurableProviders`](scp_core::context::supervisor::DurableProviders)
    /// GUARANTEED to share a single [`Storage`] backend (spec §17.6 / §17.16 /
    /// ADR-049).
    ///
    /// The caller builds this via
    /// [`DurableProviders::from_handle`](scp_core::context::supervisor::DurableProviders::from_handle)
    /// over its chosen `Storage` backend (a `SQLite` handle distinct from the
    /// node's own storage, in production), so crash-recovery replay and the
    /// `OpenMLS` view share one backend by construction — the journal can never
    /// be wired to a divergent store.
    pub durable: scp_core::context::supervisor::DurableProviders,
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
        durable,
        assets,
    } = params;

    let deployer = SelfHostDeployer::start(
        node,
        node_did,
        context_id,
        hostname,
        signing_key_handle,
        key_resolver,
        durable,
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
    author_did: scp_did::DID,
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
    // governance resolver, durable providers). The durable saga journal and the
    // `mls_storage` view arrive bound into one `DurableProviders` so they cannot
    // be wired to divergent backends — mirroring the FFI
    // `with_providers_and_journal` bootstrap.
    #[allow(clippy::too_many_arguments)]
    pub async fn start<S>(
        node: &ApplicationNode<S>,
        node_did: String,
        context_id: String,
        hostname: String,
        signing_key_handle: scp_platform::KeyHandle,
        key_resolver: scp_core::context::governance::KeyResolver,
        durable: scp_core::context::supervisor::DurableProviders,
    ) -> Result<Self, SelfHostError>
    where
        S: Storage + 'static,
    {
        let author_did: scp_did::DID = scp_did::DID::from(node_did.clone());

        // Build the in-process supervisor on the node's OWN loopback relay and
        // register the local DID + the broadcast context. The supervisor carries
        // the REAL document-derived governance resolver (ADR-053 / spec §10.17)
        // and the durable saga journal over the SAME `Storage` backend as
        // `mls_storage` — guaranteed by the `DurableProviders` newtype (§17.16 /
        // ADR-049).
        let supervisor =
            connect_loopback_supervisor(node, &node_did, &author_did, key_resolver, durable)
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
    Arc::new(move |did: &scp_did::DID, kid: scp_did::SigningKeyId| {
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
    })
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
    kid: scp_did::SigningKeyId,
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
    author_did: &scp_did::DID,
    key_resolver: scp_core::context::governance::KeyResolver,
    durable: scp_core::context::supervisor::DurableProviders,
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
    let crypto = Arc::new(scp_core::crypto::mls::provider::NodeMlsFactory::new(
        node_did.to_owned(),
        std::sync::Arc::new(scp_clock::SystemClock),
    ));
    let event_log: Box<dyn scp_core::context::builder::ContextEventLogProvider> =
        Box::new(scp_core::context::providers::MerkleEventLogProvider::new());
    let (event_tx, _event_rx) = tokio::sync::broadcast::channel(1000);

    // Share the provider's exact hardened `Clock` Arc with the supervisor so the
    // "one hardened clock per node" invariant (see the `NodeMlsFactory::clock`
    // field doc, ADR-057 §Prereq-1) holds by construction — the supervisor does
    // not fabricate a second `SystemClock`. Read before `crypto` is moved below.
    let clock = crypto.clock();
    // The durable saga journal is built over the SAME `Storage` backend as
    // `mls_storage` so crash-recovery replay loads unresolved saga entries from
    // one store on restart — guaranteed by the `DurableProviders` newtype
    // (§17.16 / ADR-049).
    let supervisor = scp_core::context::supervisor::Supervisor::with_providers_and_journal(
        crypto,
        transport,
        event_log,
        key_resolver,
        None,
        None,
        Some(event_tx),
        Some(clock),
        durable,
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
    author_did: &scp_did::DID,
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
/// [`HostSiteConfig::defaults`] is fail-safe: [`DhtMode::Disabled`] means the DID
/// document is NOT published to the DHT, [`TlsMode::SelfSigned`] serves HTTPS,
/// and the reach is whatever you pass. For a fully local demo, pass
/// [`Reach::Local`] (skips NAT probing) and set `tls: TlsMode::Plaintext` so no
/// router port is opened and the listener serves plain HTTP. For PUBLIC hosting,
/// pass [`Reach::NatTraversal`] and opt into [`DhtMode::Production`]
/// deliberately (it publishes the host's address bound to its DID to the global
/// Mainline DHT — a location disclosure). [`DhtMode::Disabled`] (no publish) is
/// the fail-safe, non-disclosing direction and is valid for every reach —
/// including [`Reach::NatTraversal`], the "reachable but not DHT-discoverable"
/// config (share the address out-of-band) — never an error. [`DhtMode::Memory`]
/// is the test-harness-only analog and is not a shipped option.
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
    /// Which DHT client to use. Defaults to the fail-safe [`DhtMode::Disabled`],
    /// which never touches the network (`Memory` is test-harness-only). Set
    /// [`DhtMode::Production`] to opt into
    /// public hosting — it publishes the host's public address bound to the node
    /// DID to the global Mainline DHT (an IP-to-identity / location disclosure).
    ///
    /// [`DhtMode::Disabled`] (no publish) is the fail-safe, non-disclosing
    /// direction and is valid with **any** [`reach`](Self::reach), including the
    /// publishing-capable [`Reach::NatTraversal`]: that pairing is the
    /// reachable-but-unpublished config (share the address out-of-band), never an
    /// error — the same M2 stance as [`NodeConfig`](crate::NodeConfig). Only
    /// [`DhtMode::Production`] discloses, so only it is an explicit opt-in.
    ///
    /// This value is **load-bearing**, not advisory: it is threaded into
    /// `NodeConfig.dht` (via `build_host_site_node`) and drives
    /// `publish_did_document_for_mode`, and it also selects the concrete
    /// DID-method client `D` in `dispatch_hosted_site_by_dht_mode`. The two are
    /// kept in agreement on every path (a Pkarr `D` with `dht: Disabled` never
    /// publishes; a `Disabled` `D` never sees a `Production` publish request).
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
    /// DHT HTTP gateway URLs threaded into the production pkarr client (validated
    /// via the shared `scp_dht::validate_gateway_url` contract). Empty by default
    /// (Mainline DHT only). Only consulted when [`dht`](Self::dht) is
    /// [`DhtMode::Production`] (the only publishing mode); a non-publishing
    /// [`DhtMode::Disabled`] node builds no pkarr client, so gateways are unused.
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
    /// Fail-safe defaults: `tls = TlsMode::SelfSigned`, `dht = DhtMode::Disabled`
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
            dht: DhtMode::Disabled,
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
    /// [`DhtMode::Disabled`] (no publish) is the fail-safe direction and valid for
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
/// This lowering does NOT validate the DHT axis: [`DhtMode::Disabled`] (do not
/// publish the DID document) is the fail-safe, non-disclosing direction and is
/// valid for every [`Reach`], including the publishing-capable
/// [`Reach::NatTraversal`] — the reachable-but-unpublished self-host case
/// ("publicly reachable, address shared out-of-band, not published to the DHT").
/// Only [`DhtMode::Production`] discloses, and it is already a deliberate opt-in
/// ([`DhtMode::Disabled`] is the default), so there is nothing to reject — the same rule
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
/// The default [`DhtMode::Disabled`] publishes nothing to the network (fail-safe).
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
/// [`DhtMode::Disabled`] is valid for every reach) or any stage fails: storage
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
    //    `tls` folds `plaintext`; `reach` folds `skip_nat`. `DhtMode::Disabled`
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
        // `DhtMode` is `Copy`; the same value also drives the dispatch below.
        dht_mode,
        projection_rate_limit,
        refresh_interval,
        storage_dir,
        storage_key,
        node_storage: node_storage_arc,
        custody,
        site_dir,
        on_ready,
    };

    dispatch_hosted_site_by_dht_mode(
        dht_mode,
        &dht_gateways,
        common,
        cache,
        sequence_store,
        shutdown,
    )
    .await
}

/// Selects the DID method for the requested [`DhtMode`] and dispatches into the
/// generic [`serve_hosted_site`] path.
///
/// The co-located participant's governance resolver MUST share the node's
/// [`DidCache`] (consistency + the load-bearing cache-level anti-rollback
/// sequence guard) and resolve via the same DHT client the node uses. Each arm
/// builds a `DualLayerResolver` over the concrete `DidDht`'s shared
/// `cache()`/`dht_client()`, then lowers it to the object-safe governance
/// `KeyResolver` (ADR-053 / spec §10.17, SHB-002). The two DHT modes produce
/// DIFFERENT concrete DID-method types (`DidDht<DisabledDhtClient>` /
/// `DidDht<InMemoryDhtClient>` / `DidDht<PkarrDhtClient>`), so the rest of the
/// flow is generic over `D` and called from each arm.
async fn dispatch_hosted_site_by_dht_mode<F>(
    dht_mode: DhtMode,
    dht_gateways: &[String],
    common: ServeHostedSite,
    cache: Arc<DidCache>,
    sequence_store: Arc<dyn SequenceStore>,
    shutdown: F,
) -> Result<(), HostSiteError>
where
    F: Future<Output = ()> + Send + 'static,
{
    let handle = tokio::runtime::Handle::current();
    match dht_mode {
        DhtMode::Disabled => {
            tracing::info!(
                "DhtMode::Disabled — DHT layer off: the DID document is NOT published (no address \
                 disclosed, fail-closed on publish) and the DHT resolution arm returns Ok(None). \
                 DID resolution composes the relay layer around the off DHT arm (the fail-safe \
                 default; set DhtMode::Production to host publicly)"
            );
            let (did_method, seq_init) = build_disabled_did_method(cache);
            let key_resolver = build_shared_cache_key_resolver(
                Arc::clone(did_method.dht_client()),
                Arc::clone(did_method.cache()),
                handle,
            );
            // `sequence_store` is unused for a non-publishing node; drop it
            // explicitly so the move is intentional, not an oversight.
            drop(sequence_store);
            serve_hosted_site(common, did_method, key_resolver, seq_init, shutdown).await
        }
        // Gated `feature = "testing"` ONLY (ADR-062 A5) to match the
        // `DhtMode::Memory` variant's single activation path.
        #[cfg(feature = "testing")]
        DhtMode::Memory => {
            tracing::info!(
                "using InMemoryDhtClient — DID document will NOT be published to the network \
                 (test-harness-only; DhtMode::Disabled is the shipped no-publish value)"
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
                 to the global Mainline DHT (an IP-to-identity disclosure). Use DhtMode::Disabled \
                 to keep the DID document local."
            );
            let (did_method, seq_init) = build_production_did_method(
                Arc::clone(&common.custody),
                cache,
                sequence_store,
                dht_gateways,
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
fn build_shared_cache_key_resolver<D: scp_dht::DhtClient + 'static>(
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

// ---------------------------------------------------------------------------
// Self-DID republishing (SCP-RELAYRES-004, §3.10.2/§3.10.5/§3.10.6)
// ---------------------------------------------------------------------------

/// Constructs the production [`RepublishManager`] (the real `scp-transport`
/// [`TransportRelayPublisher`] is the `R` type parameter, paired with the node's
/// DHT client) and drives the self-host node's own DID-document republishing from
/// a **live view** of the node's published record — or leaves it **fully dormant**
/// (manager present, zero arms) while the node has published nothing.
/// Returns the running cycle for teardown.
///
/// # Both layers, always enabled (§3.10.6 anti-segmentation)
///
/// Neither arm is gated on infrastructure readiness:
///
/// - **DHT (2-hour keep-alive).** Mainline DHT records expire and pkarr performs
///   no internal republish, so this arm is the *only* thing keeping the node's
///   DID record resolvable on the DHT.
/// - **Relay (6-day cycle).** Always enabled, including when no relay is bound
///   yet. [`TransportRelayPublisher::publish`] fails closed with a typed
///   `RelayPublishFailed` while unbound, and the relay republish loop backs off
///   30s → 30min, so an unbound relay costs at most one no-op wakeup per 30
///   minutes — and the arm **self-heals** the instant a relay is bound, with no
///   manager reconstruction and no re-drive.
///
/// Sampling relay readiness once, at construction, to decide whether to enable
/// the arm is what this function used to do, and it was unfixable by
/// construction: the sample necessarily ran before any relay-client connection
/// could exist, so the arm could never be true and — being latched — could never
/// be woken. Turning a layer OFF in [`RepublishConfig`] is reserved for a
/// DELIBERATE user opt-out (§3.10.6, which mandates a warning); an unbound layer
/// is not one, so no production path here ever asks for it.
///
/// # Full dormancy — honest disclosure (do not read as active resilience)
///
/// While the node has published **no signed record** (the slot holds `None`)
/// there is nothing to keep alive on either layer, so no arm is scheduled and the
/// manager sits at zero tasks. `DhtMode::Disabled` — the fail-closed default —
/// publishes nothing, so that is its permanent state. The `None` is produced by
/// the publish seam itself, so the log below is literally true: it fires when, and
/// only when, nothing has been published.
///
/// # Re-seeding: a live view, not a snapshot
///
/// The cycle takes a [`watch::Receiver`](tokio::sync::watch::Receiver) over the
/// node's published-record slot, never a `RepublishEntry` by value. Every publish
/// this node performs writes that slot (see `PublishedDidRecord`), and the
/// re-seed observer re-points both arms at the new record. A NAT tier change
/// re-publishes the document with a NEW `(value, signature, seq)`; against a
/// held snapshot the DHT arm would keep re-putting a superseded `seq` (which
/// BEP44 nodes reject, so the *current* record stops being kept alive and
/// expires) and the relay arm would keep pushing a superseded frame (which a
/// validating relay rejects, miscounted as a publish failure and eventually
/// reported as `RelayPublishDegraded` while the relay is in fact correct).
/// Emits the §3.10.6 mandated warning when a DID-resolution layer is disabled.
///
/// A named function rather than an inline closure so the wiring is a *value*:
/// §3.10.6 requires the SDK to warn whenever a resolution layer is turned off,
/// and a mandate buried in a closure inside a constructor is a mandate no test
/// can reach.
fn layer_disabled_warning(message: &str) {
    tracing::warn!(warning = %message, "§3.10.6 DID resolution layer disabled");
}

/// The self-host [`RepublishConfig`]: both layers enabled, with the §3.10.6
/// layer-disabled warning callback wired.
///
/// The production path never disables a layer, so the callback is not expected
/// to fire. It is wired precisely so that it CANNOT be forgotten: if any future
/// path ever disables one, the mandated warning is emitted mechanically rather
/// than depending on that path remembering to log it.
fn self_host_republish_config() -> RepublishConfig {
    RepublishConfig::default().with_layer_disabled_callback(Arc::new(layer_disabled_warning))
}

async fn start_self_did_republishing<D: DhtClient + 'static>(
    dht_client: Arc<D>,
    relay_publisher: Arc<TransportRelayPublisher>,
    mut records: watch::Receiver<Option<RepublishEntry>>,
) -> SelfDidRepublishing<D> {
    let config = self_host_republish_config();

    // Both degraded callbacks are wired: the DHT keep-alive is this node's only
    // resolvability guarantee, so a keep-alive that has been failing for six
    // consecutive cycles MUST NOT be silent. The relay callback additionally
    // fires on a PARTIAL publish (§3.10.8 suppression), not only total failure.
    let manager = Arc::new(
        RepublishManager::with_relay_publisher_and_warning(
            dht_client,
            relay_publisher,
            config,
            Arc::new(|degraded: scp_identity::republish::DhtPublishDegraded| {
                tracing::warn!(
                    did = %degraded.did,
                    consecutive_failures = degraded.consecutive_failures,
                    "self-DID DHT keep-alive is DEGRADED — this node's DID record \
                     will expire from the Mainline DHT and become unresolvable \
                     (§3.10.2)"
                );
            }),
        )
        .with_relay_warning_callback(Arc::new(
            |degraded: scp_identity::republish::RelayPublishDegraded| {
                tracing::warn!(
                    did = %degraded.did,
                    consecutive_failures = degraded.consecutive_failures,
                    accepted = degraded.last_outcome.map(|o| o.accepted),
                    attempted = degraded.last_outcome.map(|o| o.attempted),
                    "self-DID relay republishing is DEGRADED — some or all relays \
                     are not serving this node's DID record (§3.10.6/§3.10.8)"
                );
            },
        )),
    );

    // Seed synchronously from the CURRENT slot value before returning, so a
    // caller that inspects the manager right after this call (and the teardown
    // path) sees the arms that the node's startup publish already justified —
    // rather than racing the observer task's first poll.
    //
    // `borrow_and_update` (not `borrow`) marks EXACTLY the version just read as
    // seen, so a publish racing this line is either included in `current` or
    // still pending for the observer's first `changed()`. Reading and marking as
    // two steps would drop a publish that landed between them.
    let current = records.borrow_and_update().clone();
    seed_republish_arms(&manager, current).await;

    let reseed_task = tokio::spawn(reseed_republish_arms(Arc::clone(&manager), records));

    SelfDidRepublishing {
        manager,
        reseed_task,
    }
}

/// The running self-DID republish cycle: the [`RepublishManager`] plus the
/// observer that keeps it pointed at the node's CURRENT signed record.
///
/// Held for the serve lifetime and torn down via [`stop`](Self::stop).
struct SelfDidRepublishing<D: DhtClient> {
    manager: Arc<RepublishManager<D, TransportRelayPublisher>>,
    /// The re-seed observer. Aborted BEFORE the manager is stopped — see
    /// [`stop`](Self::stop).
    reseed_task: tokio::task::JoinHandle<()>,
}

impl<D: DhtClient + 'static> SelfDidRepublishing<D> {
    /// Stops the cycle: no arm survives, and none can be started afterwards.
    ///
    /// Ordering is load-bearing. The observer is aborted FIRST: stopping the
    /// manager first would leave a window in which an in-flight `changed()`
    /// wake-up re-starts both arms *after* `stop_all`, leaking two tasks past
    /// shutdown.
    async fn stop(self) {
        self.reseed_task.abort();
        self.manager.stop_all().await;
    }
}

/// Points both republish arms at `entry`, replacing whatever they were asserting.
///
/// # Why a full stop-then-start rather than a bespoke `reseed` method
///
/// "Make these arms publish this entry" is exactly what
/// [`RepublishManager::start_republishing`] already means — it aborts and
/// replaces the tasks under the entry's derived DID. A separate `reseed` method
/// would be a second spelling of one operation, and the two would have to be kept
/// in agreement forever. Replacing the tasks is also the only *possible*
/// semantics: each arm captured its `RepublishEntry` by value when it was
/// spawned, so nothing short of a new task can make it publish new bytes.
///
/// The preceding [`stop_all`](RepublishManager::stop_all) closes the one gap in
/// `start_republishing`'s replace: it replaces only the arms keyed under THIS
/// entry's DID. This manager hosts exactly one identity — the node's own — so any
/// arm under a different key is by definition asserting a record this node no
/// longer stands behind, and would keep doing so forever. Stopping everything
/// first makes "one entry, one pair of arms" unconditional rather than an
/// invariant argued from the node's identity never changing. The two calls are
/// serial on a single observer task, and `start_republishing` publishes
/// immediately, so the replacement window carries no tick.
async fn seed_republish_arms<D: DhtClient + 'static>(
    manager: &RepublishManager<D, TransportRelayPublisher>,
    entry: Option<RepublishEntry>,
) {
    let Some(entry) = entry else {
        // Nothing published (yet): no DHT record to keep alive and nothing to
        // publish to relays. Not an error — the `DhtMode::Disabled` default.
        tracing::info!(
            "self-DID republishing dormant: this node has published no signed \
             record, so there is no DID record to keep alive on either layer \
             (DhtMode::Disabled no-publish default)"
        );
        return;
    };

    tracing::info!(
        did = %entry.did(),
        sequence = entry.sequence,
        "self-DID republishing active on BOTH layers: DHT (2h keep-alive) + \
         relay (6d) (§3.10.6 anti-segmentation). The relay arm publishes on \
         every cycle and fails closed until a relay is bound."
    );
    manager.stop_all().await;
    manager.start_republishing(entry).await;
}

/// Re-seeds the republish arms from the node's published-record slot for as long
/// as the node lives.
///
/// This is what makes re-seeding structural: the observer watches the slot that
/// the publish seam writes, so ANY re-publish — the NAT tier change today, and
/// any publish path added later — re-points the arms at the record it produced.
/// No call site has to remember to re-seed, because no call site is involved.
///
/// # Racing an in-flight tick
///
/// A re-seed can land while an arm is mid-publish. Each arm is aborted and its
/// replacement inserted under the manager's task-map lock, so the two can neither
/// interleave nor both survive. Aborting mid-publish drops that request; the
/// replacement task publishes immediately with a HIGHER sequence, which
/// supersedes the dropped one on both layers. Losing the stale in-flight put is
/// the desired outcome — it was asserting a record the node has already replaced.
async fn reseed_republish_arms<D: DhtClient + 'static>(
    manager: Arc<RepublishManager<D, TransportRelayPublisher>>,
    mut records: watch::Receiver<Option<RepublishEntry>>,
) {
    // The version present at construction was read with `borrow_and_update` by
    // `start_self_did_republishing` and is therefore already marked seen, so the
    // first `changed()` waits for the next *publish* rather than replaying it.
    loop {
        if records.changed().await.is_err() {
            // Every sender is gone: the node has been dropped, so nothing more
            // will ever be published. The arms keep asserting the last record
            // until teardown aborts them.
            tracing::debug!(
                "self-DID re-seed observer stopping: the node's published-record \
                 slot was dropped"
            );
            return;
        }
        let entry = records.borrow_and_update().clone();
        seed_republish_arms(manager.as_ref(), entry).await;
    }
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
    /// The caller-selected publish [`DhtMode`], threaded into
    /// [`build_host_site_node`] so `NodeConfig.dht` agrees with the concrete
    /// DID-method `D` that [`dispatch_hosted_site_by_dht_mode`] selected from the
    /// same value (never a re-derivation from `skip_nat`).
    dht_mode: DhtMode,
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
// A single linear build → deploy → serve orchestration; each step must be
// sequenced with its own error/teardown handling, so it reads as one flat body
// rather than fragmenting into helpers that would obscure the ordering.
#[allow(clippy::too_many_lines)]
async fn serve_hosted_site<DC, F>(
    common: ServeHostedSite,
    did_method: Arc<DidDht<DC, SystemClock>>,
    key_resolver: scp_core::context::governance::KeyResolver,
    seq_init: SeqInitFn,
    shutdown: F,
) -> Result<(), HostSiteError>
where
    DC: DhtClient + 'static,
    F: Future<Output = ()> + Send + 'static,
{
    // The node's DHT client comes from the DID method itself — the SAME client
    // that publishes is the one that keeps the record alive. Taking it as a
    // second parameter alongside a free `D: DidMethod` let the two disagree in
    // principle while every call site passed exactly this.
    let dht_client = Arc::clone(did_method.dht_client());
    let ServeHostedSite {
        http_addr,
        port,
        plaintext,
        skip_nat,
        dht_mode,
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
        dht_mode,
    )
    .await?;

    let node_did = node.identity().did().to_owned();
    if let Err(e) = seq_init(node_did.clone()).await {
        tracing::error!(error = %e, "failed to initialize BEP44 sequence — publishing may fail");
    }

    // -- Self-DID republishing (SCP-RELAYRES-004, §3.10.2/§3.10.5/§3.10.6). The
    //    real TransportRelayPublisher (the `R` type parameter) is constructed
    //    here and both layers are always enabled. The republish source is a LIVE
    //    VIEW of the node's published-record slot — the signed records the node's
    //    OWN publishes produce, never re-derived by resolving the node's record
    //    back off the network, and never a snapshot that a later re-publish (a
    //    NAT tier change) would silently supersede. Driven below, once the site
    //    is deployed and the public surface is open, so an early build/deploy
    //    failure never leaves a republish task running. --
    let relay_publisher = Arc::new(TransportRelayPublisher::new());
    let published_records = node.subscribe_published_did_record();

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

    // -- Drive self-DID republishing now the node is up and the surface is open.
    //    Runs the DHT keep-alive whenever a signed record exists, plus the relay
    //    arm once a relay is bound; dormant (zero arms) while nothing has been
    //    published, and re-seeded automatically on every subsequent publish. The
    //    honest disclosure of why production may be dormant lives in
    //    `start_self_did_republishing`. The returned cycle is held for the serve
    //    lifetime and torn down after shutdown. --
    let republish = start_self_did_republishing(
        Arc::clone(&dht_client),
        Arc::clone(&relay_publisher),
        published_records,
    )
    .await;

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

    // Tear down self-DID republishing: the re-seed observer first, then any
    // running arms (see `SelfDidRepublishing::stop`). A dormant node has no arms
    // to abort, so this is a no-op for it.
    republish.stop().await;

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
    let tls_config = match build_self_host_tls_config(&node.relay_url(), http_addr.ip(), plaintext)
    {
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
pub fn make_seq_init<D: scp_dht::DhtClient + 'static>(
    did_method: Arc<DidDht<D, SystemClock>>,
) -> SeqInitFn {
    Box::new(move |did| Box::pin(async move { did_method.initialize_sequence(&did).await }))
}

/// Builds the **test-harness-only** in-memory DID method (`DhtMode::Memory`).
///
/// The returned method signs with `custody` and persists its BEP44 sequence in
/// `sequence_store`, but its [`InMemoryDhtClient`] is a §17.17.3 resolve
/// nullifier — a publish reaches no peer and a resolve sees no peer's writes.
/// Compiled only under `feature = "testing"` (ADR-062 §Decision 1, D-B); shipped
/// nodes use [`build_disabled_did_method`] (no-publish) or
/// [`build_production_did_method`] (real Pkarr).
#[cfg(any(test, feature = "testing"))]
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

/// Builds the DHT-layer-off DID method (`DhtMode::Disabled` — the shipped
/// no-publish value).
///
/// The DHT arm is a [`DisabledDhtClient`]: publish fails closed (no address is
/// disclosed) and resolve contributes an honest `Ok(None)` — never a fabricated
/// or in-memory answer (ADR-062 §Decision 1, A2). The method shares the node's
/// [`DidCache`] with the co-located resolver but carries no signer (it never
/// publishes). DID resolution still runs: the [`DualLayerResolver`] composes the
/// relay layer around the off DHT arm.
#[must_use]
pub fn build_disabled_did_method(
    cache: Arc<DidCache>,
) -> (Arc<DidDht<DisabledDhtClient, SystemClock>>, SeqInitFn) {
    let did_method = Arc::new(DidDht::with_client_and_cache(
        Arc::new(DisabledDhtClient),
        cache,
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
            // The ONE shared gateway-URL validation contract
            // (`scp_dht::validate_gateway_url`), identical to the FFI-bridge
            // `ClientDhtConfig::into_client` — both fail closed on the same rule
            // (previously this path accepted any non-empty string, diverging from
            // the bridge which rejects malformed URLs).
            scp_dht::validate_gateway_url(gateway).map_err(|e| {
                HostSiteError::DidMethod(format!(
                    "invalid DHT gateway URL {:?}: {}",
                    e.url, e.reason
                ))
            })?;
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

/// Derives the [`NatSlot`] (plus retained port-mapper handles for teardown) for a
/// hosted-site node from `skip_nat` and the build features.
///
/// A `skip_nat` host (or any non-`upnp` build) uses [`NatSlot::Auto`] and
/// constructs no mappers. Otherwise the `upnp` build wires a
/// [`DefaultNatStrategy`](crate::DefaultNatStrategy) with `UPnP` + NAT-PMP mappers
/// and KEEPS the handles so teardown can release them (`NatSlot::Auto` would lose
/// them). Split out of [`build_host_site_node`] as a readability seam so the NAT
/// derivation does not inflate the builder body. `HostSiteConfig` has no `nat`
/// field, so there is no config-level NAT injection point (unlike
/// `NodeConfig.nat`) — see #2162 to add one for parity + hermetic host-site tests.
fn derive_host_site_nat_slot(
    #[cfg_attr(not(feature = "upnp"), allow(unused_variables))] skip_nat: bool,
) -> (NatSlot, OptionalPortMapper, OptionalPortMapper) {
    #[cfg(feature = "upnp")]
    {
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
        }
    }
    #[cfg(not(feature = "upnp"))]
    {
        (NatSlot::Auto, None, None)
    }
}

/// Builds the no-domain self-host [`ApplicationNode`] over persistent storage,
/// returning it behind an `Arc` alongside the retained NAT port-mapper handles.
///
/// Mirrors the binary's `build_self_host_node` but returns a [`HostSiteError`]
/// (releasing any established mappings best-effort) instead of exiting.
// Node builder internal: all parameters are required for server construction
// (the `dht_mode` was threaded in per ADR-062 Slice 1 R2-1 so the publish policy
// agrees with the selected DID-method client `D`).
#[allow(clippy::too_many_arguments)]
async fn build_host_site_node<D: scp_identity::DidMethod + 'static>(
    http_addr: SocketAddr,
    storage_dir: &Path,
    node_storage: Arc<SqliteStorage>,
    custody: Arc<SqliteKeyCustody>,
    did_method: Arc<D>,
    projection_rate_limit: u32,
    skip_nat: bool,
    dht_mode: DhtMode,
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

    // -- Reach from `skip_nat`: a `skip_nat` host reaches only locally, otherwise
    //    it NAT-traverses a routable address. --
    let reach = if skip_nat {
        Reach::Local
    } else {
        Reach::NatTraversal
    };

    // -- Publish `DhtMode` is the caller's selected `dht_mode` — the SAME value
    //    that selected the concrete DID-method `D` in
    //    `dispatch_hosted_site_by_dht_mode`. It is NOT re-derived from `skip_nat`.
    //    Re-deriving (`skip_nat ? Disabled : Production`) discarded `config.dht`,
    //    so a documented-valid `{reach: NatTraversal, dht: Disabled}` site
    //    selected `DisabledDhtClient` (via the dispatch) yet set
    //    `NodeConfig.dht = Production`, making `publish_did_document_for_mode`
    //    call `DisabledDhtClient::publish()` → `Err(DhtError::Disabled)` and fail
    //    `Node::start` on a legitimate non-publishing config. Threading the real
    //    `dht_mode` keeps the selected client `D` and the publish policy in
    //    agreement on every path (a Pkarr `D` with `dht: Disabled` never
    //    publishes; a `Disabled` `D` never sees a `Production` publish request). --
    let dht = dht_mode;

    // -- NAT slot with RETAINED mapper handles for clean teardown, derived from
    //    `skip_nat`/features by `derive_host_site_nat_slot`. `HostSiteConfig` has
    //    no `nat` field, so (unlike `NodeConfig.nat`) there is no injection seam
    //    here — see #2162 to add `nat: NatSlot` for parity + hermetic tests. --
    let (nat, upnp_mapper, natpmp_mapper) = derive_host_site_nat_slot(skip_nat);

    // `IdentitySource::Persisted` gives the self-host node a STABLE DID across
    // restarts: it creates+persists the identity on first boot and reloads it
    // thereafter from the root `node_storage`. `tls` defaults to
    // `TlsMode::SelfSigned`, a no-op on a no-domain reach.
    let config = NodeConfig {
        dht,
        nat,
        http_bind_addr: Some(http_addr),
        projection_rate_limit: Some(projection_rate_limit),
        // The self-host binary's operator-chosen backend: a durable, persistent
        // SQLite blob store (opened above, fail-closed on error). Passed as the
        // required `blob_storage` selection at this construction boundary — the
        // legitimate config default (an explicit caller choice), NOT a runtime
        // manufactured default (SCP-CAPINJECT-010 / spec §17.17.1).
        ..NodeConfig::defaults(
            reach,
            IdentitySource::Persisted {
                custody,
                did_method,
            },
            node_storage,
            blob_storage,
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
    let mls_inner = Arc::new(
        SqliteStorage::new(&storage_dir.join("mls"), storage_key.as_ref()).map_err(|e| {
            HostSiteError::StorageOpen(format!("failed to open MLS SQLite storage: {e}"))
        })?,
    );
    // The durable saga journal and the `mls_storage` view are bound into one
    // `DurableProviders` derived from the SAME `Arc<SqliteStorage>`, so
    // crash-recovery replay and the `OpenMLS` view read and write one
    // `{storage_dir}/mls` SQLCipher store and cannot diverge by construction.
    // `DurableProviders::from_handle` is the only non-test constructor (§17.6 /
    // §17.16 / ADR-049): a reviewer proved that deriving the two providers via
    // separate calls let a single mutated constructor pass a fresh in-memory
    // store to the journal while leaving every gate/test green — binding them
    // into one newtype makes that divergence a compile error.
    let durable = scp_core::context::supervisor::DurableProviders::from_handle(mls_inner);

    let signing_key_handle = node.identity().identity().active_signing_key;
    SelfHostDeployer::start(
        node,
        node_did.to_owned(),
        context_id.to_owned(),
        SELF_HOST_HOSTNAME.to_owned(),
        signing_key_handle,
        key_resolver,
        durable,
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
    // is folded into `TlsMode`, `skip_nat` into `Reach`. `DhtMode::Disabled` (no
    // publish) is the fail-safe direction and valid for every reach, so the
    // lowering does not validate the DHT axis (M2: only `Production` discloses,
    // and it is the explicit opt-in; `Memory` is test-harness-only).
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
            DhtMode::Disabled,
            "defaults must NOT publish to the DHT — `DhtMode::Disabled` is the \
             fail-safe no-publish value (ADR-062 §Decision 1; `Memory` is now \
             test-harness-only)"
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
    /// validates only the TLS×Reach axis, never the DHT axis. `DhtMode::Disabled`
    /// (no publish) is the fail-safe direction and valid for every reach — the
    /// reachable-but-unpublished self-host case (publicly reachable via NAT
    /// traversal, address shared out-of-band, not published to the DHT). It is
    /// never an error; only `DhtMode::Production` discloses, and it is the
    /// explicit opt-in (M2).
    #[test]
    fn nat_traversal_lowers_for_both_dht_modes() {
        // `lower_host_site_reach_tls` no longer takes a `dht` arg — the DHT mode
        // does not affect reach/TLS lowering. The successful lowering is the
        // proof that a publishing-capable reach is accepted with the fail-safe
        // default (`DhtMode::Disabled`) DHT mode (the old, inverted rule rejected
        // a publishing-capable reach paired with a non-publishing DHT mode).
        let (_p, skip_nat) = lower_host_site_reach_tls(&Reach::NatTraversal, &TlsMode::SelfSigned)
            .expect("NatTraversal lowers cleanly; DHT mode does not gate validity");
        assert!(!skip_nat, "Reach::NatTraversal must probe NAT");
    }

    /// Gateway-normalization PARITY with the FFI-bridge
    /// [`ClientDhtConfig::into_client`](scp_ffi_common): [`build_pkarr_client`]
    /// TRIMS each gateway and SKIPS empty entries before validating against the
    /// shared [`scp_dht::validate_gateway_url`] contract. A whitespace-padded
    /// valid gateway is trimmed-then-accepted, a whitespace-only / empty entry is
    /// skipped (not an error), and a malformed gateway still fails closed. Both
    /// callers now accept/reject exactly these inputs — the "identical contract"
    /// the docs claim (companion:
    /// `into_client_trims_and_skips_gateways_like_the_node_path`).
    #[test]
    fn build_pkarr_client_trims_and_accepts_whitespace_padded_gateway() {
        // A whitespace-padded VALID gateway is trimmed then accepted.
        build_pkarr_client(&["  https://dns.example.org  ".to_owned()])
            .expect("a whitespace-padded valid gateway must be trimmed-then-accepted");

        // Whitespace-only / empty entries are skipped (not rejected) — same as an
        // empty gateway list, building the default direct-Mainline client.
        build_pkarr_client(&["   ".to_owned(), String::new()])
            .expect("whitespace-only / empty gateways must be skipped, not rejected");

        // A padded but MALFORMED gateway still fails closed (trim does not rescue).
        let malformed = build_pkarr_client(&["  not-a-valid-url  ".to_owned()]);
        assert!(
            matches!(malformed, Err(HostSiteError::DidMethod(_))),
            "a malformed gateway must still fail closed after trimming, got {malformed:?}"
        );
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
        use scp_dht::DhtClient;

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
        let doc = scp_did::DidDocument::new(
            &did,
            identity_public.as_bytes(),
            active_public.as_bytes(),
            &pre_rotation_commitment,
        );

        // BEP44-sign the serialized document with the identity key (seq = 1).
        let value = doc.to_json().expect("doc serializes").into_bytes();
        let signable = scp_dht::bep44_signable(&value, 1);
        let signature: [u8; 64] = identity_signing.sign(&signable).to_bytes();
        dht.publish(identity_public.as_bytes(), &signature, &value, 1)
            .await
            .expect("publish to in-memory DHT");

        (did, active_public)
    }

    /// The signed BEP44 record a self-host node's own publish produces — the
    /// SHAPE the publish seam files into the node's `PublishedDidRecord` slot,
    /// which `start_self_did_republishing` observes. Built directly from the
    /// signing inputs (no DHT involved), because that is the point: sourcing the
    /// republish entry no longer requires any storage or network read.
    fn self_host_signed_record() -> RepublishEntry {
        use ed25519_dalek::{Signer, SigningKey};

        let identity_signing = SigningKey::from_bytes(&[11u8; 32]);
        let active_signing = SigningKey::from_bytes(&[22u8; 32]);
        let identity_public = identity_signing.verifying_key();

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
        let doc = scp_did::DidDocument::new(
            &did,
            identity_public.as_bytes(),
            active_signing.verifying_key().as_bytes(),
            &pre_rotation_commitment,
        );
        let document_bytes = doc.to_json().expect("doc serializes").into_bytes();
        let signature: [u8; 64] = identity_signing
            .sign(&scp_dht::bep44_signable(&document_bytes, 1))
            .to_bytes();

        RepublishEntry {
            public_key: *identity_public.as_bytes(),
            document_bytes,
            signature,
            sequence: 1,
        }
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
            move || key_resolver(&scp_did::DID::from(did), scp_did::SigningKeyId::Active)
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
                    &scp_did::DID::from(unknown_did),
                    scp_did::SigningKeyId::Active,
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
        let active_result = key_resolver(&scp_did::DID::from(did), scp_did::SigningKeyId::Active);
        assert_eq!(
            active_result,
            Some(active_public),
            "the co-located KeyResolver must resolve the registered DID's #active \
             key when invoked on a current-thread runtime (proves the BLOCKER fix: \
             the current-thread regime drives the resolve on a dedicated thread \
             instead of panicking in block_in_place)"
        );
    }

    // -----------------------------------------------------------------------
    // Self-DID republishing (SCP-RELAYRES-004) — §3.10.2/§3.10.5/§3.10.6
    //
    // The production wiring constructs a RepublishManager over the REAL
    // `TransportRelayPublisher` and, when the node has a published signed record
    // to source, drives BOTH the DHT (2h) and relay (6d) cycles. These tests
    // exercise that wiring end-to-end with a testing-gated identity (a genuinely
    // BEP44-signed record seeded into the in-memory DHT) — proving the wiring
    // activates, publishes the full DID-record frame to relays, and covers both
    // layers.
    // -----------------------------------------------------------------------

    use scp_identity::extract_public_key;

    type AdapterFut<'a, T> = Pin<
        Box<
            dyn std::future::Future<Output = Result<T, scp_transport::error::TransportError>>
                + Send
                + 'a,
        >,
    >;

    /// Minimal recording relay adapter: captures every `publish_raw` blob so a
    /// test can decode the DID-record frame the relay layer received. Every other
    /// method is an honest "not connected" (never a fabricated success).
    #[derive(Default)]
    struct RecordingRelayAdapter {
        published: std::sync::Mutex<Vec<(scp_transport::traits::RoutingId, u64, Vec<u8>)>>,
    }

    impl RecordingRelayAdapter {
        fn recorded(&self) -> Vec<(scp_transport::traits::RoutingId, u64, Vec<u8>)> {
            self.published.lock().expect("published lock").clone()
        }
    }

    impl scp_transport::traits::TransportAdapter for RecordingRelayAdapter {
        fn send(
            &self,
            _envelope: &scp_core::envelope::OuterEnvelope,
        ) -> AdapterFut<'_, scp_transport::traits::BlobId> {
            Box::pin(async { Err(scp_transport::error::TransportError::NotConnected) })
        }

        fn subscribe(
            &self,
            _routing_id: &scp_transport::traits::RoutingId,
            _since: Option<u64>,
        ) -> AdapterFut<'_, scp_transport::traits::SubscriptionStream> {
            Box::pin(async { Err(scp_transport::error::TransportError::NotConnected) })
        }

        fn unsubscribe(
            &self,
            _routing_id: &scp_transport::traits::RoutingId,
        ) -> AdapterFut<'_, ()> {
            Box::pin(async { Ok(()) })
        }

        fn query(
            &self,
            _routing_id: &scp_transport::traits::RoutingId,
            _since: Option<u64>,
        ) -> AdapterFut<'_, Vec<scp_core::envelope::OuterEnvelope>> {
            Box::pin(async { Ok(Vec::new()) })
        }

        fn delete(&self, _blob_id: &scp_transport::traits::BlobId) -> AdapterFut<'_, ()> {
            Box::pin(async { Ok(()) })
        }

        fn publish_raw(
            &self,
            routing_id: &scp_transport::traits::RoutingId,
            blob_ttl: u64,
            blob: Vec<u8>,
        ) -> AdapterFut<'_, ()> {
            self.published
                .lock()
                .expect("published lock")
                .push((*routing_id, blob_ttl, blob));
            Box::pin(async { Ok(()) })
        }
    }

    /// A published-record slot pre-seeded with `entry`.
    ///
    /// Returns the sender alongside the receiver: the sender must outlive the
    /// cycle under test, because dropping every sender is the signal that the
    /// node is gone and stops the re-seed observer.
    fn record_slot(
        entry: Option<RepublishEntry>,
    ) -> (
        watch::Sender<Option<RepublishEntry>>,
        watch::Receiver<Option<RepublishEntry>>,
    ) {
        let tx = watch::Sender::new(entry);
        let rx = tx.subscribe();
        (tx, rx)
    }

    /// Binds a recording relay adapter onto `publisher` and returns the adapter
    /// so the test can inspect what the relay layer received.
    fn bind_recording_relay(publisher: &TransportRelayPublisher) -> Arc<RecordingRelayAdapter> {
        let adapter = Arc::new(RecordingRelayAdapter::default());
        publisher.bind(
            "wss://relay.example/scp/v1",
            Arc::clone(&adapter) as Arc<dyn scp_transport::traits::TransportAdapter>,
        );
        adapter
    }

    /// AC 3 / AC 5: the production entry point schedules BOTH layers — the DHT
    /// (2h) keep-alive AND the relay (6d) cycle — from the node's own signed
    /// record, with neither arm disabled.
    #[tokio::test]
    async fn self_did_republishing_schedules_both_dht_and_relay_layers() {
        let dht = Arc::new(InMemoryDhtClient::new());
        let entry = self_host_signed_record();

        let publisher = Arc::new(TransportRelayPublisher::new());
        let _adapter = bind_recording_relay(publisher.as_ref());
        let (_slot, records) = record_slot(Some(entry));
        let republish =
            start_self_did_republishing(Arc::clone(&dht), Arc::clone(&publisher), records).await;

        assert_eq!(
            republish.manager.active_count().await,
            1,
            "the DHT (2h) republish cycle is scheduled"
        );
        assert_eq!(
            republish.manager.active_relay_count().await,
            1,
            "the relay (6d) republish cycle is scheduled ALONGSIDE the DHT cycle (§3.10.6)"
        );

        republish.stop().await;
    }

    /// AC 5: the production `RepublishManager` publishes to BOTH layers — the DHT
    /// record is present and the relay layer independently receives the frame.
    #[tokio::test]
    async fn production_republish_manager_publishes_both_layers() {
        use scp_dht::DhtClient as _;

        let dht = Arc::new(InMemoryDhtClient::new());
        let entry = self_host_signed_record();
        let public_key = entry.public_key;

        let publisher = Arc::new(TransportRelayPublisher::new());
        let adapter = bind_recording_relay(publisher.as_ref());

        let (_slot, records) = record_slot(Some(entry));
        let republish =
            start_self_did_republishing(Arc::clone(&dht), Arc::clone(&publisher), records).await;
        tokio::time::sleep(Duration::from_millis(150)).await;
        republish.stop().await;

        // DHT layer: the record is present (the DHT arm publishes it too).
        assert!(
            dht.resolve(&public_key)
                .await
                .expect("resolve ok")
                .is_some(),
            "the DHT layer holds the DID record (2h cycle)"
        );
        // Relay layer: the frame reached the bound relay (6d cycle) — additive.
        assert!(
            !adapter.recorded().is_empty(),
            "the relay layer received the DID record (additive to the DHT layer, §3.10.6)"
        );
    }

    /// AC 4: a node's DID record reaches the relay as a valid DID-record FRAME
    /// whose `(value, signature, seq)` verifies against the node's DID-derived
    /// key, stored at `did_routing_id` (§9.10.12 publish contract) — never bare
    /// bytes, never an `OuterEnvelope`.
    #[tokio::test]
    async fn node_did_record_reaches_relay_as_verifiable_frame() {
        let dht = Arc::new(InMemoryDhtClient::new());
        let entry = self_host_signed_record();
        let did = entry.did();

        let publisher = Arc::new(TransportRelayPublisher::new());
        let adapter = bind_recording_relay(publisher.as_ref());

        let (_slot, records) = record_slot(Some(entry));
        let republish =
            start_self_did_republishing(Arc::clone(&dht), Arc::clone(&publisher), records).await;
        tokio::time::sleep(Duration::from_millis(150)).await;
        republish.stop().await;

        let recorded = adapter.recorded();
        assert!(!recorded.is_empty(), "relay received the node's DID record");
        assert_relay_blob_is_node_frame(&recorded[0], &did);
    }

    /// Shared frame oracle for the relay-blob assertions.
    ///
    /// Recomposes the expected `routing_id` from the DID STRING
    /// (`did_routing_id`), independently of the key-derived path
    /// (`did_key_routing_id`) the publisher takes — so a bug in the shared
    /// derivation cannot make both sides of the assertion vacuously agree.
    fn assert_relay_blob_is_node_frame(
        recorded: &(scp_transport::traits::RoutingId, u64, Vec<u8>),
        did: &str,
    ) {
        let (rid, ttl, blob) = recorded;

        assert_eq!(
            rid.as_bytes(),
            &scp_identity::did_routing_id(did),
            "published at SHA-256('scp:did:' || did)"
        );
        assert_eq!(
            *ttl,
            scp_identity::republish::RELAY_BLOB_TTL_SECS,
            "blob_ttl is the 7-day DID-record TTL (§3.10.2)"
        );

        // The blob is a valid DID-record frame (not bare bytes, not an envelope).
        let frame = scp_core::envelope::did_record::DidRecordV1::decode(blob)
            .expect("relay blob decodes as a DID-record frame (§9.10.12)");

        // Its (value, signature, seq) verify against the node's DID-derived key.
        let pk = extract_public_key(did).expect("DID yields a public key");
        scp_dht::verify_bep44_signature(&pk, frame.signature(), frame.value(), frame.seq())
            .expect("the framed record verifies against the node's DID-derived key");
    }

    /// B1 (the one-shot latch is GONE — self-heal on a LATE bind).
    ///
    /// Constructed through the production entry point with ZERO relays bound —
    /// exactly the state the deleted latch sampled and then disabled the relay
    /// arm on, permanently. A relay is bound only AFTER the manager is running,
    /// and the NEXT tick must publish a real frame with no manager
    /// reconstruction and no re-drive.
    ///
    /// Against the pre-fix code this test fails at the first assertion: the
    /// relay arm was never scheduled at all.
    #[tokio::test(start_paused = true)]
    async fn relay_arm_self_heals_when_a_relay_is_bound_after_start() {
        let dht = Arc::new(InMemoryDhtClient::new());
        let entry = self_host_signed_record();
        let did = entry.did();

        // ZERO relays bound at construction.
        let publisher = Arc::new(TransportRelayPublisher::new());
        let (_slot, records) = record_slot(Some(entry));
        let republish =
            start_self_did_republishing(Arc::clone(&dht), Arc::clone(&publisher), records).await;

        assert_eq!(
            republish.manager.active_relay_count().await,
            1,
            "the relay arm is scheduled even with no relay bound — it fails closed \
             per tick rather than being latched off at construction"
        );

        // Let the first tick run: it fails closed (nothing bound) and backs off.
        tokio::task::yield_now().await;
        tokio::task::yield_now().await;

        // NOW bind a relay, on the SAME shared publisher instance, after the
        // manager was constructed AND started.
        let adapter = bind_recording_relay(publisher.as_ref());
        assert!(
            adapter.recorded().is_empty(),
            "nothing can have been published before the bind"
        );

        // Advance past the first backoff (30s). The next tick must publish.
        tokio::time::advance(Duration::from_secs(31)).await;
        tokio::task::yield_now().await;
        tokio::task::yield_now().await;

        let recorded = adapter.recorded();
        assert!(
            !recorded.is_empty(),
            "binding a relay AFTER start must wake the relay arm on its next tick \
             (no reconstruction, no re-drive)"
        );
        assert_relay_blob_is_node_frame(&recorded[0], &did);

        republish.stop().await;
    }

    /// B2 (CRITICAL): republishing no longer depends on reading the node's own
    /// record back off the DHT.
    ///
    /// The DHT here is EMPTY, so a read-back would return `Ok(None)` — the exact
    /// shape a `DhtMode::Production` resolve timeout takes with no gateways
    /// configured. The pre-fix code turned that single miss into a permanently
    /// dormant manager (no retry, DID unresolvable ~2h later). Sourcing the
    /// entry from the publish that created it removes the dependency entirely.
    #[tokio::test]
    async fn republishing_survives_a_dht_read_back_miss_at_startup() {
        use scp_dht::DhtClient as _;

        let dht = Arc::new(InMemoryDhtClient::new());
        let entry = self_host_signed_record();
        let public_key = entry.public_key;

        // Precondition: a read-back WOULD have found nothing.
        assert!(
            dht.resolve(&public_key)
                .await
                .expect("resolve ok")
                .is_none(),
            "the DHT holds no record — a read-back source would yield None"
        );

        let publisher = Arc::new(TransportRelayPublisher::new());
        let _adapter = bind_recording_relay(publisher.as_ref());
        let (_slot, records) = record_slot(Some(entry));
        let republish =
            start_self_did_republishing(Arc::clone(&dht), Arc::clone(&publisher), records).await;

        assert_eq!(
            republish.manager.active_count().await,
            1,
            "DHT keep-alive scheduled"
        );
        assert_eq!(
            republish.manager.active_relay_count().await,
            1,
            "relay arm scheduled"
        );

        republish.stop().await;
    }

    /// No signed record → FULLY dormant: zero DHT tasks, zero relay tasks.
    /// The honest absent state, never a fabricated entry. `None` means "this node
    /// published nothing" (the `DhtMode::Disabled` default), which is what the
    /// dormancy log claims — before, it also covered "the network read failed",
    /// making that log a lie.
    #[tokio::test]
    async fn self_did_republishing_fully_dormant_without_published_record() {
        let dht = Arc::new(InMemoryDhtClient::new());
        let publisher = Arc::new(TransportRelayPublisher::new());
        let adapter = bind_recording_relay(publisher.as_ref());

        let (_slot, records) = record_slot(None);
        let republish =
            start_self_did_republishing(Arc::clone(&dht), Arc::clone(&publisher), records).await;

        assert_eq!(
            republish.manager.active_count().await,
            0,
            "nothing published → no DHT keep-alive arm (no entry fabricated)"
        );
        assert_eq!(
            republish.manager.active_relay_count().await,
            0,
            "nothing published → no relay arm"
        );

        // Dormancy is real, not just an empty task map: nothing reaches a relay.
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            adapter.recorded().is_empty(),
            "a dormant cycle publishes nothing to any layer"
        );

        republish.stop().await;
    }

    // -----------------------------------------------------------------------
    // Re-seeding the running republish arms on a re-publish
    // (SCP-RELAYRES-004 — the frozen-snapshot class, tier-change seam)
    //
    // `apply_tier_change` re-publishes the node's DID document on a NAT tier
    // change, producing a NEW (value, signature, seq). These tests drive the REAL
    // seam — a signing `DidDht`, the real `NodeDidPublisher`, the real
    // `apply_tier_change` — and assert the RUNNING arms follow it.
    // -----------------------------------------------------------------------

    use crate::{
        DidPublisher, NodeDidDocument, NodeDidPublisher, NodeRelayUrl, PublishedDidRecord,
        apply_tier_change,
    };
    use scp_did::DidDocument;
    use scp_identity::{DidMethod as _, ScpIdentity};
    use scp_platform::testing::{InMemoryKeyCustody, InMemoryPreRotationCustody};

    /// The concrete signing `DidDht` used by the re-seed tests: a real BEP44
    /// signer over an in-memory DHT, with the real monotonic sequence counter.
    type SigningDidDht = DidDht<InMemoryDhtClient, SystemClock>;

    /// A real identity + relay-carrying DID document + the signing method that
    /// created them.
    ///
    /// Nothing here is synthesized: the records these tests compare are produced
    /// by the same `DidDht::publish_document` signing pass production uses, so a
    /// re-seed that carried the wrong bytes could not pass.
    async fn signing_identity() -> (Arc<SigningDidDht>, ScpIdentity, DidDocument, String) {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let sign_fn = SigningDidDht::make_sign_fn(Arc::clone(&custody));
        let did_method = Arc::new(DidDht::with_client_and_signer(
            Arc::new(InMemoryDhtClient::new()),
            Arc::new(DidCache::new()),
            sign_fn,
        ));
        let (identity, mut document, _pre_rotation) = did_method
            .create(custody.as_ref(), &InMemoryPreRotationCustody::new())
            .await
            .expect("test identity is created");
        let relay_url = "ws://198.51.100.7:32891/scp/v1".to_owned();
        crate::push_relay_service(&mut document, &relay_url);
        (did_method, identity, document, relay_url)
    }

    /// The node's publish seam over `did_method`, in a publishing `DhtMode`.
    fn publish_seam(
        did_method: &Arc<SigningDidDht>,
        records: &PublishedDidRecord,
    ) -> NodeDidPublisher<SigningDidDht> {
        NodeDidPublisher {
            inner: Arc::clone(did_method),
            dht_mode: DhtMode::Memory,
            records: records.clone(),
        }
    }

    /// Polls `cond` across task hops until it holds, or panics with `label`.
    ///
    /// The re-seed path crosses several tasks (publish → slot → observer →
    /// manager → arm), so a fixed number of yields would be a guess. Bounded, so
    /// a genuine failure to re-seed fails the test rather than hanging.
    async fn settle_until<F>(label: &str, mut cond: F)
    where
        F: AsyncFnMut() -> bool,
    {
        for _ in 0..2_000u32 {
            if cond().await {
                return;
            }
            tokio::task::yield_now().await;
        }
        panic!("timed out waiting for {label}");
    }

    /// THE regression: a NAT tier change re-publishes the DID document with a NEW
    /// `(value, signature, seq)`, and the ALREADY-RUNNING republish arms must
    /// re-assert THAT record — on both layers.
    ///
    /// Against the pre-fix code this fails: `start_self_did_republishing` took the
    /// startup `RepublishEntry` BY VALUE, so nothing re-seeded the manager. The
    /// DHT arm kept re-putting the superseded `seq` (rejected by BEP44 nodes, so
    /// the *current* record stops being kept alive and expires) and the relay arm
    /// kept pushing the superseded frame (rejected by a validating relay, then
    /// miscounted as a publish failure).
    #[tokio::test(start_paused = true)]
    async fn tier_change_reseeds_the_running_republish_arms() {
        let (did_method, identity, document, relay_url) = signing_identity().await;
        let records = PublishedDidRecord::new();
        let publisher = publish_seam(&did_method, &records);

        // Startup publish: the seam files the signed record into the slot.
        publisher
            .publish(&identity, &document)
            .await
            .expect("startup publish succeeds");
        let first = records
            .get()
            .expect("the startup publish records its entry");

        // The keep-alive layers. These are used ONLY by the republish arms (the
        // DID method has its own DHT client), so whatever lands here is exactly
        // what the arms asserted — never leakage from the publish itself.
        let keep_alive_dht = Arc::new(InMemoryDhtClient::new());
        let relay = Arc::new(TransportRelayPublisher::new());
        let adapter = bind_recording_relay(relay.as_ref());

        let republish = start_self_did_republishing(
            Arc::clone(&keep_alive_dht),
            Arc::clone(&relay),
            records.subscribe(),
        )
        .await;

        assert_arms_assert_record(
            &keep_alive_dht,
            &adapter,
            &first,
            "the record the startup publish signed",
        )
        .await;

        // -- A NAT tier change: the node re-publishes with a new relay endpoint,
        //    producing a NEW (value, signature, seq). --
        let new_relay_url = "ws://203.0.113.42:8443/scp/v1";
        let node_document = NodeDidDocument::new(document);
        let node_relay_url = NodeRelayUrl::new(relay_url);
        apply_tier_change(
            &node_relay_url,
            new_relay_url,
            "test tier change",
            &node_document,
            &publisher,
            &identity,
            None,
        )
        .await;
        // `apply_tier_change` returns nothing: success is observable only where
        // the node actually keeps its state. The relay-URL slot advancing is the
        // signal the re-publish succeeded (it is written on the success arm
        // only), which the record assertions below then corroborate.
        assert_eq!(
            node_relay_url.get(),
            new_relay_url,
            "a successful tier change advances the node's relay-URL slot"
        );

        let second = records
            .get()
            .expect("the tier-change publish records its entry");
        assert!(
            second.sequence > first.sequence,
            "the re-publish assigns a HIGHER BEP44 sequence ({} -> {})",
            first.sequence,
            second.sequence
        );
        assert_ne!(
            second.signature, first.signature,
            "the re-publish signs different bytes, so the signature differs"
        );
        assert!(
            String::from_utf8_lossy(&second.document_bytes).contains(new_relay_url),
            "the re-published document carries the NEW relay endpoint"
        );

        // -- The running arms must now assert the NEW record, unprompted. --
        assert_arms_assert_record(
            &keep_alive_dht,
            &adapter,
            &second,
            "the record the TIER-CHANGE re-publish signed",
        )
        .await;

        republish.stop().await;
    }

    /// Asserts BOTH republish arms are asserting exactly `entry`: the DHT
    /// keep-alive holds its `(value, signature, seq)` and the relay has received a
    /// frame carrying them.
    ///
    /// Waits for each arm rather than assuming a fixed number of task hops, and
    /// compares full bytes rather than only the sequence — a stale arm republishing
    /// the previous document would otherwise pass on a coincidental sequence match.
    async fn assert_arms_assert_record(
        keep_alive_dht: &InMemoryDhtClient,
        adapter: &RecordingRelayAdapter,
        entry: &RepublishEntry,
        label: &str,
    ) {
        use scp_dht::DhtClient as _;

        settle_until(&format!("the DHT arm to assert {label}"), async || {
            keep_alive_dht
                .resolve(&entry.public_key)
                .await
                .expect("resolve ok")
                .is_some_and(|record| record.seq == entry.sequence)
        })
        .await;
        let kept_alive = keep_alive_dht
            .resolve(&entry.public_key)
            .await
            .expect("resolve ok")
            .expect("record present");
        assert_eq!(
            kept_alive.value, entry.document_bytes,
            "the DHT keep-alive puts the document bytes of {label}"
        );
        assert_eq!(
            kept_alive.signature, entry.signature,
            "the DHT keep-alive puts the signature of {label}"
        );

        settle_until(&format!("the relay arm to assert {label}"), async || {
            adapter.recorded().iter().any(|recorded| {
                scp_core::envelope::did_record::DidRecordV1::decode(&recorded.2)
                    .is_ok_and(|frame| frame.seq() == entry.sequence)
            })
        })
        .await;
        let frame = adapter
            .recorded()
            .into_iter()
            .filter_map(|recorded| {
                scp_core::envelope::did_record::DidRecordV1::decode(&recorded.2).ok()
            })
            .find(|frame| frame.seq() == entry.sequence)
            .expect("the relay arm published a frame at this sequence");
        assert_eq!(
            frame.value(),
            entry.document_bytes.as_slice(),
            "the relay frame carries the document bytes of {label} — a SUPERSEDED \
             frame is what a validating relay rejects as DID_RECORD_REJECTED, which \
             the loop then miscounts as a publish failure"
        );
        assert_eq!(
            frame.signature(),
            &entry.signature,
            "the relay frame carries the signature of {label}"
        );
    }

    /// Re-seeding replaces the arms 1:1: N re-seeds leave exactly one DHT arm and
    /// one relay arm, no leaked tokio tasks, and exactly ONE publish per interval
    /// (N leaked arms would produce N).
    #[tokio::test(start_paused = true)]
    async fn reseeding_neither_leaks_nor_double_spawns_tasks() {
        const RESEEDS: u32 = 5;

        let (did_method, identity, document, _relay_url) = signing_identity().await;
        let records = PublishedDidRecord::new();
        let publisher = publish_seam(&did_method, &records);
        publisher
            .publish(&identity, &document)
            .await
            .expect("startup publish succeeds");

        let counting_dht = Arc::new(CountingDhtClient::default());
        let relay = Arc::new(TransportRelayPublisher::new());
        let _adapter = bind_recording_relay(relay.as_ref());
        let republish = start_self_did_republishing(
            Arc::clone(&counting_dht),
            Arc::clone(&relay),
            records.subscribe(),
        )
        .await;
        settle_until("the initial DHT arm to publish", async || {
            counting_dht.count() >= 1
        })
        .await;

        let alive_before = tokio::runtime::Handle::current()
            .metrics()
            .num_alive_tasks();

        for n in 0..RESEEDS {
            let expected = counting_dht.count() + 1;
            publisher
                .publish(&identity, &document)
                .await
                .expect("re-publish succeeds");
            // Each re-seed publishes immediately on the replacement arm.
            settle_until("the re-seeded DHT arm to publish", async || {
                counting_dht.count() >= expected
            })
            .await;

            assert_eq!(
                republish.manager.active_count().await,
                1,
                "re-seed {n} must REPLACE the DHT arm, never add a second one"
            );
            assert_eq!(
                republish.manager.active_relay_count().await,
                1,
                "re-seed {n} must REPLACE the relay arm, never add a second one"
            );
        }

        // Aborted arms are reaped as the runtime drops them; settle before
        // comparing so a lagging reap is not read as a leak.
        settle_until("aborted arms to be reaped", async || {
            tokio::runtime::Handle::current()
                .metrics()
                .num_alive_tasks()
                <= alive_before
        })
        .await;
        assert_eq!(
            tokio::runtime::Handle::current()
                .metrics()
                .num_alive_tasks(),
            alive_before,
            "{RESEEDS} re-seeds must leave the live task count unchanged"
        );

        // Behavioural proof, independent of the task map: advance one full DHT
        // republish interval. One arm → exactly one publish. N leaked arms would
        // each fire in the same window.
        let before_window = counting_dht.count();
        tokio::time::advance(Duration::from_secs(
            scp_identity::republish::REPUBLISH_INTERVAL_SECS + 1,
        ))
        .await;
        settle_until("the surviving arm's next tick", async || {
            counting_dht.count() > before_window
        })
        .await;
        assert_eq!(
            counting_dht.count() - before_window,
            1,
            "exactly ONE arm survives {RESEEDS} re-seeds, so exactly one publish \
             lands per republish interval"
        );

        republish.stop().await;
    }

    /// A re-seed that lands while an arm is MID-PUBLISH is safe: the in-flight
    /// tick is replaced, not duplicated, and the stale record it was asserting
    /// never completes.
    #[tokio::test(start_paused = true)]
    async fn reseed_racing_an_in_flight_tick_replaces_it_safely() {
        let (did_method, identity, document, _relay_url) = signing_identity().await;
        let records = PublishedDidRecord::new();
        let publisher = publish_seam(&did_method, &records);
        publisher
            .publish(&identity, &document)
            .await
            .expect("startup publish succeeds");
        let first = records.get().expect("startup record");

        // A DHT client whose publish PARKS until the test releases it — the arm
        // is genuinely mid-tick when the re-seed arrives.
        let gated = Arc::new(GatedDhtClient::default());
        let relay = Arc::new(TransportRelayPublisher::new());
        let _adapter = bind_recording_relay(relay.as_ref());
        let republish = start_self_did_republishing(
            Arc::clone(&gated),
            Arc::clone(&relay),
            records.subscribe(),
        )
        .await;

        settle_until("the first tick to enter publish", async || {
            gated.started() == vec![first.sequence]
        })
        .await;
        assert!(
            gated.completed().is_empty(),
            "the first tick is parked INSIDE publish — that is the race window"
        );

        // Re-seed while the tick is parked.
        publisher
            .publish(&identity, &document)
            .await
            .expect("re-publish succeeds");
        let second = records.get().expect("re-published record");
        settle_until("the replacement tick to enter publish", async || {
            gated.started() == vec![first.sequence, second.sequence]
        })
        .await;

        // Release both parked publishes. Only the replacement can complete: the
        // superseded one was dropped mid-await by the replace, which is the
        // desired outcome — it was asserting a record the node has replaced.
        gated.release();
        settle_until("the replacement tick to complete", async || {
            !gated.completed().is_empty()
        })
        .await;
        assert_eq!(
            gated.completed(),
            vec![second.sequence],
            "only the re-seeded tick completes; the superseded in-flight put is \
             dropped, never resurrected"
        );
        assert_eq!(
            republish.manager.active_count().await,
            1,
            "the race leaves exactly one DHT arm"
        );

        republish.stop().await;
    }

    /// Records every `publish` sequence so a test can count arm ticks.
    #[derive(Default)]
    struct CountingDhtClient {
        publishes: std::sync::Mutex<Vec<u64>>,
    }

    impl CountingDhtClient {
        fn count(&self) -> usize {
            self.publishes.lock().expect("publishes lock").len()
        }
    }

    impl scp_dht::DhtClient for CountingDhtClient {
        fn publish(
            &self,
            _public_key: &[u8; 32],
            _signature: &[u8; 64],
            _value: &[u8],
            seq: u64,
        ) -> impl std::future::Future<Output = Result<(), scp_dht::DhtError>> + Send {
            self.publishes.lock().expect("publishes lock").push(seq);
            async { Ok(()) }
        }

        /// Never used: these doubles exist to observe what the arms PUBLISH.
        /// An honest `Ok(None)` (nothing stored), never a fabricated record.
        async fn resolve(
            &self,
            _public_key: &[u8; 32],
        ) -> Result<Option<scp_dht::DhtRecord>, scp_dht::DhtError> {
            Ok(None)
        }
    }

    /// A DHT client whose `publish` parks until [`release`](Self::release), so a
    /// test can hold an arm mid-tick and re-seed underneath it.
    #[derive(Default)]
    struct GatedDhtClient {
        started: std::sync::Mutex<Vec<u64>>,
        completed: std::sync::Mutex<Vec<u64>>,
        gate: tokio::sync::Notify,
        open: std::sync::atomic::AtomicBool,
    }

    impl GatedDhtClient {
        fn started(&self) -> Vec<u64> {
            self.started.lock().expect("started lock").clone()
        }

        fn completed(&self) -> Vec<u64> {
            self.completed.lock().expect("completed lock").clone()
        }

        fn release(&self) {
            self.open.store(true, std::sync::atomic::Ordering::SeqCst);
            self.gate.notify_waiters();
        }
    }

    impl scp_dht::DhtClient for GatedDhtClient {
        fn publish(
            &self,
            _public_key: &[u8; 32],
            _signature: &[u8; 64],
            _value: &[u8],
            seq: u64,
        ) -> impl std::future::Future<Output = Result<(), scp_dht::DhtError>> + Send {
            self.started.lock().expect("started lock").push(seq);
            async move {
                while !self.open.load(std::sync::atomic::Ordering::SeqCst) {
                    self.gate.notified().await;
                }
                self.completed.lock().expect("completed lock").push(seq);
                Ok(())
            }
        }

        /// Never used: these doubles exist to observe what the arms PUBLISH.
        /// An honest `Ok(None)` (nothing stored), never a fabricated record.
        async fn resolve(
            &self,
            _public_key: &[u8; 32],
        ) -> Result<Option<scp_dht::DhtRecord>, scp_dht::DhtError> {
            Ok(None)
        }
    }

    /// B3 / §3.10.6: the production self-host `RepublishConfig` wires the
    /// layer-disabled warning callback, so a layer can never be turned off
    /// silently. (`scp-identity`'s
    /// `disabling_either_layer_fires_the_mandated_warning` proves the callback
    /// actually fires with the mandated text.)
    #[test]
    fn self_host_republish_config_wires_the_layer_disabled_warning() {
        let config = self_host_republish_config();

        assert!(
            config.has_layer_disabled_callback(),
            "§3.10.6 mandates a warning when a resolution layer is disabled — the \
             production config must carry the callback that emits it"
        );
        assert!(
            config.is_dht_enabled() && config.is_relay_enabled(),
            "the production path enables BOTH layers (§3.10.6 anti-segmentation); \
             an unbound relay is not a user opt-out"
        );
    }
}
