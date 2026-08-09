//! Flat-config-object construction surface for [`ApplicationNode`].
//!
//! This module implements the **ADR-052 Unified Construction Pattern** (Phase
//! B-P1) for the Node entry point. It introduces a single flat config object
//! ([`NodeConfig`]) plus a single zero-sized entry-point namespace ([`Node`])
//! exposing [`Node::start`] / [`Node::start_for_testing`], replacing the
//! LLM-hostile builder-based surface with a shape an agent can author in
//! one pass from the type signature plus one example.
//!
//! See `.docs/standards/construction.md` (the enforced enactment of the
//! Agent-first API design builder tenet) and ADR-052 in
//! `.docs/adrs/phase-2.md`.
//!
//! ## The build engine
//!
//! [`Node::start`] / [`Node::start_for_testing`] are the sole front door for
//! node construction. The build orchestration that formerly lived on the
//! deleted builder (ADR-052 P3a) lives here as
//! the engine over a flat [`NodeConfig`]: validate the config, resolve the
//! identity and TLS/NAT capability slots, then run the domain-vs-no-domain
//! build path (ADR-052 AC-3).

use std::net::SocketAddr;
use std::sync::Arc;

use scp_core::store::ProtocolRepository;
use scp_did::DidDocument;
use scp_identity::{DidMethod, ScpIdentity};
use scp_platform::EncryptedStorage;
use scp_platform::traits::{KeyCustody, Storage};
use scp_transport::nat::NetworkChangeDetector;
use scp_transport::native::server::{RelayConfig, RelayServer};
use scp_transport::native::storage::BlobStorageBackend;

use crate::{
    ApplicationNode, DEFAULT_HTTP_BIND_ADDR, DEFAULT_PROJECTION_RATE_LIMIT, NatStrategy,
    NoOpCustody, NoOpDidMethod, NoOpStorage, NodeError, TlsProvider, build_domain_inner,
    build_no_domain_inner, generate_bridge_secret, generate_dev_token,
    provision_with_challenge_listener, resolve_identity_persistent, resolve_nat, resolve_tls,
};

// ---------------------------------------------------------------------------
// Node — zero-sized entry-point namespace
// ---------------------------------------------------------------------------

/// Zero-sized entry-point namespace for Node construction (ADR-052).
///
/// All node construction flows through [`Node::start`] (production,
/// `where S: EncryptedStorage`) or [`Node::start_for_testing`] (feature-gated,
/// any `Storage`). There is no `NodeBuilder`, no phantom-state generics, no
/// `.build()` terminator — the construction surface is one flat [`NodeConfig`]
/// plus one entry function.
pub struct Node;

// ---------------------------------------------------------------------------
// IdentitySource — how a node obtains its identity (ADR-052 §AC-3)
// ---------------------------------------------------------------------------

/// Specifies how a node obtains its identity.
///
/// This is the public, ADR-052-shaped reconciliation of the formerly private
/// `scp-node` `IdentitySource` enum (see the ADR-052 "Name reconciliation"
/// Dependencies bullet). It carries three variants:
///
/// - [`Generate`](IdentitySource::Generate) — create a fresh DID identity from
///   the supplied custody + DID method on every start (no persistence).
/// - [`Persisted`](IdentitySource::Persisted) — load-or-create the node's
///   identity, persisting it into the Node's **own** [`NodeConfig::storage`]
///   slot. On the first start it generates and stores; on subsequent starts
///   with the same storage it reloads the same DID.
/// - [`Explicit`](IdentitySource::Explicit) — use a pre-existing identity and
///   DID document supplied by the caller.
pub enum IdentitySource<K: KeyCustody, D: DidMethod> {
    /// Generate a new identity using the provided key custody and DID method.
    ///
    /// The identity is **not** persisted; a fresh DID is created on every start.
    Generate {
        /// Key custody backend that holds the node's signing keys.
        custody: Arc<K>,
        /// DID method used to create and publish the identity.
        did_method: Arc<D>,
    },
    /// Load-or-create the node's identity, persisting it into the Node's own
    /// [`NodeConfig::storage`] slot.
    ///
    /// First start: generate via `did_method.create(custody)` and persist.
    /// Subsequent starts with the same storage: reload the same DID.
    Persisted {
        /// Key custody backend that holds the node's signing keys.
        custody: Arc<K>,
        /// DID method used to create (and on first run, publish) the identity.
        did_method: Arc<D>,
    },
    /// Use a pre-existing identity and document (boxed to avoid a large variant
    /// size difference).
    Explicit(Box<ExplicitIdentity<D>>),
}

/// Data for an explicitly provided identity (the payload of
/// [`IdentitySource::Explicit`]).
pub struct ExplicitIdentity<D: DidMethod> {
    /// The pre-existing SCP identity.
    pub identity: ScpIdentity,
    /// The pre-existing DID document for [`identity`](Self::identity).
    pub document: DidDocument,
    /// DID method used to publish the identity to the DHT.
    pub did_method: Arc<D>,
}

// ---------------------------------------------------------------------------
// Reach — the addressing XOR (M1 enum, replaces phantom-state markers + skip_nat bool)
// ---------------------------------------------------------------------------

/// How the node is reached from the outside — the addressing choice, as one
/// required field (ADR-052 M1).
///
/// `Reach` folds the former domain / no-domain phantom-state markers and
/// the `skip_nat_probe` boolean into a single legible enum.
#[derive(Debug, Clone)]
pub enum Reach {
    /// The node serves a public DNS domain. The relay URL is derived as
    /// `wss://<domain>/scp/v1` and TLS is provisioned for the domain.
    Domain {
        /// The DNS domain this node serves.
        domain: String,
    },
    /// Zero-config NAT-traversed mode (§10.12.8): probe NAT type over STUN,
    /// attempt `UPnP`, fall back to a bridge relay, and publish a `ws://` relay
    /// URL. No domain, no ACME TLS.
    NatTraversal,
    /// The node is reached through a tunnel/proxy that terminates on
    /// `localhost` (e.g. a Cloudflare tunnel). NAT discovery is skipped and a
    /// loopback relay URL is published.
    Tunnel {
        /// The public URL the tunnel exposes.
        // P1: public_url not yet threaded; builder publishes loopback
        public_url: String,
    },
    /// The node is reached only on the local machine/network. NAT discovery is
    /// skipped and a loopback relay URL is published.
    Local,
}

// ---------------------------------------------------------------------------
// TlsMode — TLS selection (M1 enum, replaces the `plaintext` bool)
// ---------------------------------------------------------------------------

/// How the node provisions TLS for its public listener (ADR-052 M1).
///
/// `TlsMode` exposes a fixed set of named provisioning strategies plus a single
/// open [`Custom`](TlsMode::Custom) capability slot, exactly mirroring the
/// [`NatSlot`] shape. The named variants cover every production provisioning
/// strategy; `Custom` is the typed slot for a caller-supplied
/// `Arc<dyn TlsProvider>` (testing and advanced wiring — e.g. exercising the
/// §10.12.8 TLS-failure → NAT-fallthrough path with a deterministically failing
/// provider). `TlsProvider` is object-safe (the engine already threads
/// `Option<Arc<dyn TlsProvider>>` through `resolve_tls`), so the slot does not
/// violate the "no `dyn` for Storage/KeyCustody/DidMethod" rule — those traits
/// are RPITIT and genuinely not object-safe, `TlsProvider` is not.
///
/// `Custom` is **Rust-core-only**: the per-FFI-bridge `TlsMode` mirror omits it,
/// because a Rust trait object cannot cross the FFI boundary (the same
/// asymmetry as `StorageSlot::Custom` / `NatSlot::Custom`).
#[derive(Clone)]
pub enum TlsMode {
    /// Generate and serve a self-signed certificate for the reach's domain.
    /// This is the fail-safe production default for [`NodeConfig`] — no network,
    /// no CA, MLS still provides real confidentiality.
    SelfSigned,
    /// Provision a Let's Encrypt certificate via ACME for the reach's domain.
    Acme {
        /// Contact email for the ACME account registration.
        ///
        /// Optional: `None` selects headless ACME (no contact email), the
        /// legacy default for a domain node that sets no TLS options. `Some(e)`
        /// registers the ACME account with the contact address `e`.
        email: Option<String>,
    },
    /// Serve plaintext (no node-side TLS). Only valid on a non-`Domain` reach;
    /// `Reach::Domain` + `TlsMode::Plaintext` is a loud configuration error.
    Plaintext,
    /// TLS is terminated upstream (a tunnel or reverse proxy). The node does no
    /// TLS provisioning of its own.
    Terminated,
    /// Use a caller-supplied [`TlsProvider`] (the open capability slot).
    ///
    /// The provided provider is passed as the `resolve_tls` override, so it is
    /// used in place of the default ACME/self-signed provisioning. This is the
    /// only way to inject a deterministic TLS provider (e.g. one that always
    /// fails, to exercise the §10.12.8 TLS-failure → NAT-fallthrough branch on a
    /// `Domain` reach). Rust-core-only; the FFI `TlsMode` mirror omits it.
    Custom(Arc<dyn TlsProvider>),
}

// ---------------------------------------------------------------------------
// DhtMode — DID-document publication selection (M1 enum, shared by Node + Site)
// ---------------------------------------------------------------------------

/// Which DHT client a node (or hosted site) uses to publish (or not publish) its
/// DID document.
///
/// The default is [`Disabled`](DhtMode::Disabled) (the fail-safe no-publish
/// value): the DHT layer is turned off — the node publishes nothing (so it
/// discloses no address) and its DHT-arm resolution is honestly empty
/// (`Ok(None)`, never a fabricated or in-memory answer). Selecting
/// [`Production`](DhtMode::Production) is a deliberate, explicit opt-in to
/// publishing the node's public address bound to its DID, so the privacy-worst
/// behavior is never the path of least resistance (ADR-052 M2).
///
/// The former default, [`Memory`](DhtMode::Memory), is now **test-harness-only**
/// (compiled only under `feature = "testing"`): its in-memory client is a
/// §17.17.3 resolve nullifier — it publishes to and resolves from a process-local
/// map no peer ever sees, silently emptying the DHT resolution namespace
/// (ADR-062 §Decision 1, D-B). `Disabled` replaces it as the shipped no-publish
/// value: same *disclosure* fail-safe (nothing published), but honest on resolve.
///
/// Promoted here from `self_host.rs` so the Node ([`NodeConfig`]) and the
/// hosted-site ([`crate::HostSiteConfig`]) construction surfaces share **one**
/// definition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DhtMode {
    /// DHT layer disabled: the DID document is NEVER published (no address
    /// disclosed — fail-closed on publish), and the DHT resolution arm
    /// contributes an honest `Ok(None)`. The **fail-safe default** and the
    /// shipped no-publish value; DID resolution composes the relay layer around
    /// the off DHT arm (A2).
    #[default]
    Disabled,
    /// **Test-harness-only** in-memory DHT client (a §17.17.3 resolve nullifier).
    /// Publishes to / resolves from a process-local map — no peer ever sees it.
    /// Compiled only under `feature = "testing"` — the **single** activation path
    /// (ADR-062 §Decision 1 / A5; never a bare `#[cfg(test)]` disjunct, which is a
    /// second path invisible to G1's feature-graph check); never a shipped runtime
    /// option. In-crate tests activate it via the `scp-dht`/self `testing`
    /// dev-dependency. Use [`Disabled`](DhtMode::Disabled) for the shipped
    /// no-publish behavior.
    #[cfg(feature = "testing")]
    Memory,
    /// Production pkarr client: publishes the node's DID document (and thus its
    /// address) to the global Mainline DHT. This is the correct mode for a
    /// publicly reachable node or site.
    ///
    /// Production mode publishes the host's public address bound to the node DID
    /// to the global Mainline DHT — an approximate-location / IP-to-identity
    /// disclosure. Select it only as a deliberate opt-in to public hosting; use
    /// [`Disabled`](DhtMode::Disabled) for local/dev so nothing is published.
    Production,
}

// ---------------------------------------------------------------------------
// NatSlot — NAT strategy selection (typed capability slot, never dyn-erased)
// ---------------------------------------------------------------------------

/// NAT traversal strategy selection (ADR-052 capability slot).
///
/// `NatSlot` carries an `Arc<dyn NatStrategy>` in its [`Custom`](NatSlot::Custom)
/// variant, so it intentionally does **not** derive `Debug`.
pub enum NatSlot {
    /// Use the default NAT strategy (`DefaultNatStrategy`), constructed by the
    /// builder. The fail-safe default.
    Auto,
    /// Use a caller-supplied NAT strategy (primarily for testing).
    Custom(Arc<dyn NatStrategy>),
    /// Use the default NAT strategy, tuned with explicit STUN / bridge / port
    /// mapper / reachability-probe overrides. Each `None` field is left at the
    /// builder default.
    Tuned {
        /// Override the STUN endpoint used for NAT type probing (§10.12.8).
        stun_server: Option<String>,
        /// Override the bridge relay used for Tier 3 fallback (§10.12.8).
        bridge_relay: Option<String>,
        /// Optional UPnP/NAT-PMP port mapper for Tier 1 (spec 10.12.2).
        port_mapper: Option<Arc<dyn scp_transport::nat::PortMapper>>,
        /// Optional reachability probe for self-test (SCP-242).
        reachability_probe: Option<Arc<dyn scp_transport::nat::ReachabilityProbe>>,
    },
}

// ---------------------------------------------------------------------------
// NodeConfig — the one flat config object (ADR-052 §AC-3)
// ---------------------------------------------------------------------------

/// Flat configuration object for constructing an [`ApplicationNode`] (ADR-052).
///
/// Every parameter is a named field. There is **no** whole-struct `Default`
/// (M4) because `reach`, `identity`, and `storage` are irreducible required
/// decisions — they are non-`Option` fields, so omitting them is a compile
/// error, not a silent `None`. Use [`NodeConfig::defaults`] for the spread
/// idiom.
///
/// ## Example: local demo (the happy path)
///
/// `NodeConfig::defaults` fills every non-required field with a fail-safe value
/// that is valid for a **non-publishing** reach. `Reach::Local` is
/// non-publishing, so the defaults alone are a complete, valid config — nothing
/// to override:
///
/// ```ignore
/// let node = Node::start(NodeConfig::defaults(
///     Reach::Local,
///     IdentitySource::Generate { custody, did_method },
///     storage,
///     BlobStorageBackend::in_memory(), // durability-only arm, selected explicitly
/// )).await?;
/// ```
///
/// ## Example: public node on a domain
///
/// A publicly reachable node on a domain should publish its address so peers can
/// discover it via `did:dht`, which means opting into `DhtMode::Production`
/// **explicitly** — publishing your location to the DHT is a deliberate opt-in
/// (M2), never a silent default. (Leaving the default `DhtMode::Disabled` is
/// still valid — it just means "reachable, but not published to the DHT; share
/// the address out-of-band" — the more-private choice, never an error.)
///
/// ```ignore
/// let node = Node::start(NodeConfig {
///     dht: DhtMode::Production,
///     tls: TlsMode::Acme { email: Some("admin@example.com".into()) },
///     ..NodeConfig::defaults(
///         Reach::Domain { domain: "example.com".into() },
///         IdentitySource::Generate { custody, did_method },
///         storage,
///         BlobStorageBackend::sqlite(&blob_db)?, // durable backend for a public node
///     )
/// }).await?;
/// ```
///
/// The `<K, D, S>` generics survive from the former builder, carried
/// by the config and its selectors; the `Dom`/`Id` phantom-state markers are gone.
pub struct NodeConfig<
    K: KeyCustody = NoOpCustody,
    D: DidMethod = NoOpDidMethod,
    S: Storage = NoOpStorage,
> {
    // --- Required (irreducible; no whole-struct Default — M4) ---
    /// How the node is reached from the outside (addressing XOR).
    pub reach: Reach,
    /// How the node obtains its identity.
    pub identity: IdentitySource<K, D>,
    /// The node's storage backend. On the production [`Node::start`] path this
    /// is `EncryptedStorage`-bound (encryption-at-rest, compile-time enforced).
    pub storage: S,

    // --- Enums (M1) ---
    /// How TLS is provisioned for the public listener.
    pub tls: TlsMode,
    /// Whether the node publishes its DID document to the DHT.
    ///
    /// **Load-bearing** (not advisory): this field drives the publish decision.
    /// `Node::start` routes every publishing build path — the no-domain reaches
    /// (`build_no_domain_inner`), the `Reach::Domain` TLS-success path
    /// (`build_domain_inner`), and the TLS-failure fall-through — through
    /// `publish_did_document_for_mode(dht, …)`: [`DhtMode::Disabled`] (the
    /// fail-safe default, M2 — no publish, no address disclosed) SKIPS the
    /// publish and the node still starts; [`DhtMode::Production`] (and the
    /// test-only `Memory`) publish FATALLY (a genuine publish failure fails the
    /// node closed rather than advertising a false discoverability guarantee).
    ///
    /// `dht` and the concrete DID-method client `D` the caller passes are **two
    /// independent knobs** that callers keep consistent: a Pkarr `D` paired with
    /// `dht: Disabled` builds a real client but never publishes (the publish is
    /// skipped); a `DisabledDhtClient` `D` paired with `dht: Production` would
    /// try to publish through a client whose `publish` fails closed — so the two
    /// must agree (the `host_site` path enforces this by threading one `DhtMode`
    /// into both, see `dispatch_hosted_site_by_dht_mode` / `build_host_site_node`).
    pub dht: DhtMode,

    // --- Defaulted optionals (mirror the builder's Option fields) ---
    /// Bind address for the relay server (`None` = `127.0.0.1:0`).
    pub bind_addr: Option<SocketAddr>,
    /// Bind address for the local dev API (`None` = dev API disabled).
    pub local_api: Option<SocketAddr>,
    /// Bind address for the public HTTP server (`None` = default `0.0.0.0:8443`).
    pub http_bind_addr: Option<SocketAddr>,
    /// CORS allowed origins for public endpoints (`None` = permissive `*`).
    pub cors_origins: Option<Vec<String>>,
    /// DHT gateway URLs.
    ///
    /// Paired with [`dht`](Self::dht): carried but **not yet threaded end-to-end**
    /// on the `Node::start` path — it is dropped in `split_config` and the actual
    /// gateway wiring currently lives in the concrete `D` the caller passes (the
    /// `host_site` path threads its own `dht_gateways` into `build_pkarr_client`,
    /// validated via the shared `scp_dht::validate_gateway_url` contract).
    /// End-to-end wiring here + the unified FFI-SDK gateway-config surface are
    /// tracked follow-up work. Defaults to an empty vec.
    // shape-complete per ADR-052; end-to-end wiring tracked in — see #2153
    pub dht_gateways: Vec<String>,
    /// Per-IP rate limit for broadcast projection endpoints (`None` = default).
    pub projection_rate_limit: Option<u32>,
    /// DNS provider configuration for zero-config TLS via DNS subdomain.
    pub dns_provider: Option<crate::dns_provider::DnsProviderConfig>,
    /// HTTP/3 configuration (`None` = HTTP/3 disabled).
    #[cfg(feature = "http3")]
    pub http3: Option<scp_transport::http3::Http3Config>,

    // --- Capability slots (typed, never dyn-erased into config) ---
    /// NAT traversal strategy selection.
    pub nat: NatSlot,
    /// Network change detector for tier re-evaluation (§10.12.1, SCP-243).
    pub network_detector: Option<Arc<dyn NetworkChangeDetector>>,
    /// Blob storage backend for the relay.
    ///
    /// **Required, irreducible selection** (SCP-CAPINJECT-010 / ADR-062
    /// §Decision 5; spec §17.17.1). This is a non-`Option` field for the same
    /// reason `reach`/`identity`/`storage` are (M4): the relay's blob backend is
    /// a provider-capability choice the runtime MUST NOT manufacture
    /// (SCP-CAPSEL-8002), default (SCP-CAPSEL-8000), or fall back to
    /// (SCP-CAPSEL-8001). The caller selects it explicitly at this construction
    /// boundary. [`BlobStorageBackend::in_memory`] is a durability-only
    /// development arm (SCP-CAPSEL-8010/8011) — legitimately selectable here, but
    /// only ever by explicit choice, never by omission. Production nodes select a
    /// durable backend (Sqlite/redb/Postgres/S3; see spec §17.7).
    pub blob_storage: BlobStorageBackend,
}

impl<K: KeyCustody, D: DidMethod, S: Storage> NodeConfig<K, D, S> {
    /// Constructs a [`NodeConfig`] from the irreducible required fields, filling
    /// every other field with its **fail-safe** default (ADR-052 M4).
    ///
    /// Fail-safe defaults: `tls = TlsMode::SelfSigned`, `dht = DhtMode::Disabled`
    /// (no publish), every `Option` = `None`, `dht_gateways = []`,
    /// `nat = NatSlot::Auto`.
    ///
    /// This enables the spread idiom. Because `reach`/`identity`/`storage`/
    /// `blob_storage` are moved into the returned struct, the caller passes
    /// *separate* values to `defaults(...)` than the fields it overrides:
    ///
    /// ```ignore
    /// NodeConfig {
    ///     tls: TlsMode::Acme { email },
    ///     ..NodeConfig::defaults(reach2, identity2, storage2, blob_storage2)
    /// }
    /// ```
    ///
    /// `blob_storage` is a required argument (not defaulted) because the relay's
    /// blob backend is an irreducible provider-capability selection the runtime
    /// must never manufacture (SCP-CAPINJECT-010 / spec §17.17.1). A local demo
    /// selects the durability-only arm explicitly:
    /// `NodeConfig::defaults(reach, identity, storage, BlobStorageBackend::in_memory())`.
    #[must_use]
    pub fn defaults(
        reach: Reach,
        identity: IdentitySource<K, D>,
        storage: S,
        blob_storage: BlobStorageBackend,
    ) -> Self {
        Self {
            reach,
            identity,
            storage,
            tls: TlsMode::SelfSigned,
            dht: DhtMode::Disabled,
            bind_addr: None,
            local_api: None,
            http_bind_addr: None,
            cors_origins: None,
            dht_gateways: Vec::new(),
            projection_rate_limit: None,
            dns_provider: None,
            #[cfg(feature = "http3")]
            http3: None,
            nat: NatSlot::Auto,
            network_detector: None,
            blob_storage,
        }
    }
}

// ---------------------------------------------------------------------------
// SelfSignedTlsProvider — production default for TlsMode::SelfSigned
// ---------------------------------------------------------------------------

/// Production [`TlsProvider`] that serves a self-signed certificate for a
/// domain.
///
/// This is the lowering target for [`TlsMode::SelfSigned`] on a `Domain` reach:
/// it provisions a self-signed certificate via [`crate::tls::generate_self_signed`]
/// with no network and no CA. MLS still provides real confidentiality; browsers
/// show a one-time untrusted-certificate warning, expected for the no-CA model.
struct SelfSignedTlsProvider {
    domain: String,
}

impl TlsProvider for SelfSignedTlsProvider {
    fn provision(
        &self,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = Result<crate::tls::CertificateData, crate::tls::TlsError>,
                > + Send
                + '_,
        >,
    > {
        let domain = self.domain.clone();
        Box::pin(async move { crate::tls::generate_self_signed(&domain) })
    }
}

// ---------------------------------------------------------------------------
// Build engine: NodeConfig -> ApplicationNode
// ---------------------------------------------------------------------------

/// The portion of a [`NodeConfig`] that is **not** identity or storage — the
/// "tail" applied uniformly across all three identity arms.
///
/// Extracting this lets the three identity arms (which produce different
/// concrete builder types) each flow through one generic continuation.
struct ConfigTail {
    reach: Reach,
    tls: TlsMode,
    /// The configured DHT mode, threaded through to the no-domain publish step
    /// so the publish decision is fail-closed for a publishing node and
    /// fail-safe (no publish) for a `Disabled` node. See
    /// [`build_no_domain_inner`](crate::build_no_domain_inner).
    dht: DhtMode,
    bind_addr: Option<SocketAddr>,
    local_api: Option<SocketAddr>,
    http_bind_addr: Option<SocketAddr>,
    cors_origins: Option<Vec<String>>,
    projection_rate_limit: Option<u32>,
    dns_provider: Option<crate::dns_provider::DnsProviderConfig>,
    #[cfg(feature = "http3")]
    http3: Option<scp_transport::http3::Http3Config>,
    nat: NatSlot,
    network_detector: Option<Arc<dyn NetworkChangeDetector>>,
    /// The caller's explicit blob backend selection, threaded verbatim to the
    /// relay build (never defaulted/fallen-back — SCP-CAPINJECT-010).
    blob_storage: BlobStorageBackend,
}

/// Validates the config, returning a loud error for contradictory combinations
/// (ADR-052 M2/M3 — fail loud, never silent).
///
/// # TLS × Reach validity matrix
///
/// The first axis is TLS-vs-Reach; every cell below is decided (never a silent
/// "maybe"). `✓` = valid, `✗` = loud [`NodeError::InvalidConfig`].
///
/// | `TlsMode` \ `Reach` | `Domain` | `NatTraversal` | `Tunnel` | `Local` |
/// |---|---|---|---|---|
/// | `SelfSigned` | ✓ (signs for the domain) | ✓ (no domain to sign; TLS no-op) | ✓ | ✓ |
/// | `Acme`       | ✓ (Let's Encrypt for the domain) | ✗ (no DNS name) | ✗ (no DNS name) | ✗ (no DNS name) |
/// | `Plaintext`  | ✗ (public domain can't serve plaintext) | ✓ | ✓ | ✓ |
/// | `Terminated` | ✓ (TLS upstream) | ✓ | ✓ | ✓ |
///
/// The two `✗` rules:
///
/// 1. **`Domain` cannot serve plaintext:** a public domain reach with
///    `TlsMode::Plaintext` would expose a public listener with no node-side TLS
///    — a loud error.
/// 2. **`Acme` requires a domain:** ACME (Let's Encrypt) provisions a
///    certificate for a DNS name, so `TlsMode::Acme` on any non-`Domain` reach
///    (`NatTraversal` / `Tunnel` / `Local`) has no name to provision for — a
///    loud error.
///
/// Every other cell is genuinely valid and is **not** rejected: `Domain` +
/// {`SelfSigned`, `Acme`, `Terminated`}; non-`Domain` + {`SelfSigned`,
/// `Plaintext`, `Terminated`}.
///
/// There is **no** second (DHT) validity axis. `DhtMode::Disabled` (do not
/// publish the DID document to the DHT) is the fail-safe, non-disclosing
/// direction and is therefore valid for **every** `Reach`, including a
/// publishing-capable reach (`Reach::Domain` / `Reach::NatTraversal`): "publicly
/// reachable, but the address is not published to the DHT; share it
/// out-of-band" is a legitimate, more-private config. Per
/// `.docs/standards/construction.md` M2, the security-critical direction is
/// *disclosure*, and only `DhtMode::Production` discloses — which is already a
/// deliberate, explicit opt-in (`Disabled` is the default). Erroring on
/// `Disabled` would reject the safe direction and nudge callers toward the
/// disclosing one, so it is never rejected here.
fn validate_config(reach: &Reach, tls: &TlsMode) -> Result<(), NodeError> {
    // TLS axis, rule 1: Domain cannot serve plaintext.
    if matches!(reach, Reach::Domain { .. }) && matches!(tls, TlsMode::Plaintext) {
        return Err(NodeError::InvalidConfig(
            "Reach::Domain with TlsMode::Plaintext is contradictory: a public domain reach \
             cannot serve plaintext. Choose TlsMode::SelfSigned or TlsMode::Acme."
                .to_owned(),
        ));
    }
    // TLS axis, rule 2: Acme requires a DNS name, which only Reach::Domain
    // provides. Acme on NatTraversal / Tunnel / Local has no name to provision a
    // Let's Encrypt certificate for — a loud error, never a silent no-op.
    if matches!(tls, TlsMode::Acme { .. }) && !matches!(reach, Reach::Domain { .. }) {
        let reach_name = match reach {
            Reach::Domain { .. } => unreachable!("guarded by the !matches! above"),
            Reach::NatTraversal => "Reach::NatTraversal",
            Reach::Tunnel { .. } => "Reach::Tunnel",
            Reach::Local => "Reach::Local",
        };
        return Err(NodeError::InvalidConfig(format!(
            "TlsMode::Acme with {reach_name} is contradictory: ACME needs a DNS name to \
             provision a Let's Encrypt certificate for, but {reach_name} has no domain. Use a \
             Domain reach or TlsMode::SelfSigned."
        )));
    }
    Ok(())
}

/// Splits a [`NodeConfig`] into its three independently-handled parts: the
/// storage backend, the identity source, and the uniform [`ConfigTail`].
///
/// Shared by both entry points ([`Node::start`] / [`Node::start_for_testing`])
/// so the ~37-line destructure + `ConfigTail` rebuild lives in exactly one place
/// (DRY). The `dht` mode is captured into [`ConfigTail`] and consumed at **every**
/// publish step — the no-domain reaches AND the `Reach::Domain` TLS-success path
/// (`build_domain_inner`) — where it decides fail-closed publish vs fail-safe
/// no-publish. The `dht_gateways` field is still dropped here (not yet threaded
/// end-to-end on the `Node::start` path — see #2153).
///
/// `validate_config` borrows `config.reach` / `config.tls` and so MUST run
/// **before** this function moves `config` — callers keep that ordering.
fn split_config<K: KeyCustody, D: DidMethod, S: Storage>(
    config: NodeConfig<K, D, S>,
) -> (S, IdentitySource<K, D>, ConfigTail) {
    let NodeConfig {
        reach,
        identity,
        storage,
        tls,
        // `dht` is captured into `ConfigTail` and consumed at every publish step
        // (fail-closed publish for a publishing node, fail-safe no-publish for
        // `Disabled`) — the no-domain reaches AND the `Reach::Domain` TLS-success
        // path. `dht_gateways` is not yet threaded end-to-end here — see #2153.
        dht,
        dht_gateways: _,
        bind_addr,
        local_api,
        http_bind_addr,
        cors_origins,
        projection_rate_limit,
        dns_provider,
        #[cfg(feature = "http3")]
        http3,
        nat,
        network_detector,
        blob_storage,
    } = config;

    let tail = ConfigTail {
        reach,
        tls,
        dht,
        bind_addr,
        local_api,
        http_bind_addr,
        cors_origins,
        projection_rate_limit,
        dns_provider,
        #[cfg(feature = "http3")]
        http3,
        nat,
        network_detector,
        blob_storage,
    };

    (storage, identity, tail)
}

/// Resolves a [`NatSlot`] into the concrete `Arc<dyn NatStrategy>` the engine
/// uses, lowering each `Tuned` override onto [`resolve_nat`].
///
/// - `Auto` constructs the default strategy (no overrides).
/// - `Custom(strategy)` uses the caller-supplied strategy verbatim.
/// - `Tuned { .. }` feeds the STUN / bridge / port-mapper / reachability-probe
///   overrides into [`resolve_nat`], which builds a `DefaultNatStrategy`.
fn resolve_nat_slot(nat: NatSlot) -> Arc<dyn NatStrategy> {
    match nat {
        NatSlot::Auto => resolve_nat(None, None, None, None, None),
        NatSlot::Custom(strategy) => resolve_nat(Some(strategy), None, None, None, None),
        NatSlot::Tuned {
            stun_server,
            bridge_relay,
            port_mapper,
            reachability_probe,
        } => resolve_nat(
            None,
            stun_server,
            bridge_relay,
            port_mapper,
            reachability_probe,
        ),
    }
}

/// Resolves a [`TlsMode`] into the optional `Arc<dyn TlsProvider>` override the
/// engine passes to [`resolve_tls`]. `None` means "no override" — the engine's
/// default ACME/self-signed provisioning applies.
///
/// - `SelfSigned` on a `Domain` reach installs a [`SelfSignedTlsProvider`]
///   (non-domain builds skip TLS provisioning entirely — no domain to sign for).
/// - `Acme` returns `None`: the engine's default `resolve_tls` constructs the
///   `AcmeProvider` for the domain (only ever reached on a `Domain` reach —
///   `validate_config` already rejected `Acme` on every non-`Domain` reach). The
///   ACME contact email is threaded separately via the engine's `acme_email`.
/// - `Terminated` (TLS terminated upstream by a tunnel/reverse proxy) on a
///   `Domain` reach installs the **no-network** [`SelfSignedTlsProvider`]: the
///   node still terminates a local TLS connection from the upstream proxy, so it
///   needs a local cert, but it must NOT run ACME. **This is load-bearing:** the
///   engine's default domain provisioning is a real `AcmeProvider` (binds :80,
///   contacts Let's Encrypt). Returning `None` for `Terminated` would silently
///   attempt ACME on a `Terminated` domain node — the exact silent-wrong-default
///   the construction standard forbids. The upstream proxy presents the real CA
///   certificate to the public; the node-side self-signed cert only secures the
///   proxy↔node hop.
/// - `Plaintext` is only valid on a non-`Domain` reach (`validate_config` already
///   rejected `Domain` + `Plaintext`); no-domain mode skips TLS, so it returns
///   `None` (no-op). On a non-`Domain` reach, `Terminated` is likewise `None`
///   (the loopback listener is plaintext; the proxy adds TLS).
/// - `Custom(provider)` returns the caller-supplied provider verbatim (the open
///   capability slot — used to inject a deterministic provider, e.g. a failing
///   one to exercise the §10.12.8 TLS-failure → NAT-fallthrough branch).
fn tls_override(tls: TlsMode, reach: &Reach) -> Option<Arc<dyn TlsProvider>> {
    match tls {
        TlsMode::SelfSigned => {
            if let Reach::Domain { domain } = reach {
                Some(Arc::new(SelfSignedTlsProvider {
                    domain: domain.clone(),
                }))
            } else {
                // Non-domain reach: no domain TLS to provision; self-signed no-op.
                None
            }
        }
        // `Acme` and `Plaintext` both return no override, for distinct reasons:
        //   - `Acme`: the engine's `resolve_tls` constructs the default
        //     `AcmeProvider::new(domain)` and threads `acme_email` itself
        //     (only ever reached on a `Domain` reach — `validate_config` rejects
        //     `Acme` on every non-`Domain` reach).
        //   - `Plaintext`: only valid on a non-`Domain` reach (Domain+Plaintext
        //     errored already); no-domain mode skips TLS, so it is a no-op.
        TlsMode::Acme { .. } | TlsMode::Plaintext => None,
        TlsMode::Terminated => {
            if let Reach::Domain { domain } = reach {
                // Domain + Terminated: install a no-network self-signed provider
                // so the node terminates the proxy↔node hop locally and does NOT
                // fall through to the engine's default AcmeProvider. The public
                // CA cert lives at the upstream proxy.
                Some(Arc::new(SelfSignedTlsProvider {
                    domain: domain.clone(),
                }))
            } else {
                // Non-domain reach: loopback listener is plaintext; proxy adds
                // TLS. No node-side provisioning — a no-op.
                None
            }
        }
        // Custom: the caller-supplied provider is used verbatim as the override.
        TlsMode::Custom(provider) => Some(provider),
    }
}

/// Emits a one-time `tracing::warn!` noting that `Reach::Tunnel`'s `public_url`
/// is carried but not yet threaded in P1 (the node publishes a loopback URL).
///
/// This makes the documented deferral observable instead of a silent drop
/// (addresses the accepted-then-ignored misuse-resistance finding) WITHOUT
/// inventing wiring. Called from the engine's Tunnel arm.
fn warn_tunnel_public_url_deferred(public_url: &str) {
    tracing::warn!(
        public_url,
        "Reach::Tunnel.public_url is carried but not yet threaded in P1; the node \
         publishes a loopback relay URL. Configure the tunnel to forward to that \
         loopback listener."
    );
}

/// The Node construction engine: orchestrates relay startup, TLS provisioning,
/// and the domain-vs-no-domain build, given an already-constructed
/// [`ProtocolRepository`] and a resolved identity.
///
/// This is the real orchestration that formerly lived on the builder's
/// `build_with_store` methods (one per domain state). It is ported verbatim here:
/// the `Reach::Domain` arm reproduces the former domain build path (provision TLS,
/// then either `build_domain_inner` on success or fall through to
/// `build_no_domain_inner` on TLS failure — the §10.12.8 path), and the
/// non-`Domain` arms reproduce the former no-domain build path (skip TLS entirely,
/// go straight to `build_no_domain_inner`).
///
/// The only difference between [`Node::start`] (production) and
/// [`Node::start_for_testing`] is the `ProtocolRepository` constructor each picks
/// (`new` vs `new_for_testing`); both then call this one engine, so the
/// orchestration is not duplicated across the two entry points.
async fn build_node<D, S>(
    protocol_repository: Arc<ProtocolRepository<S>>,
    identity: ScpIdentity,
    document: DidDocument,
    did_method: Arc<D>,
    tail: ConfigTail,
) -> Result<ApplicationNode<S>, NodeError>
where
    D: DidMethod + 'static,
    S: Storage + 'static,
{
    let ConfigTail {
        reach,
        tls,
        dht,
        bind_addr,
        local_api,
        http_bind_addr,
        cors_origins,
        projection_rate_limit,
        dns_provider,
        #[cfg(feature = "http3")]
        http3,
        nat,
        network_detector,
        blob_storage,
    } = tail;

    // The Reach selects the build path. `Domain` reproduces the former
    // domain build_with_store (TLS-provisioning + fall-through); the other
    // reaches reproduce the former no-domain build_with_store (no TLS).
    match reach {
        Reach::Domain { .. } => {
            build_node_domain(
                protocol_repository,
                identity,
                document,
                did_method,
                reach,
                tls,
                dht,
                bind_addr,
                local_api,
                http_bind_addr,
                cors_origins,
                projection_rate_limit,
                dns_provider,
                #[cfg(feature = "http3")]
                http3,
                nat,
                network_detector,
                blob_storage,
            )
            .await
        }
        Reach::NatTraversal | Reach::Tunnel { .. } | Reach::Local => {
            // skip_nat_probe is set for the tunnel/loopback reaches (Tunnel,
            // Local); NatTraversal probes NAT. The Tunnel arm also emits the
            // deferred-public_url warning.
            let skip_nat_probe = match &reach {
                Reach::NatTraversal => false,
                Reach::Tunnel { public_url } => {
                    warn_tunnel_public_url_deferred(public_url);
                    true
                }
                Reach::Local => true,
                Reach::Domain { .. } => unreachable!("guarded by the outer match"),
            };
            build_node_no_domain(
                protocol_repository,
                identity,
                document,
                did_method,
                dht,
                bind_addr,
                local_api,
                http_bind_addr,
                cors_origins,
                projection_rate_limit,
                #[cfg(feature = "http3")]
                http3,
                nat,
                network_detector,
                blob_storage,
                skip_nat_probe,
            )
            .await
        }
    }
}

/// Domain-reach engine path: ported verbatim from the former domain
/// `build_with_store`. Provisions TLS; on success builds
/// the domain node, on TLS failure falls through to the NAT-traversed no-domain
/// build (§10.12.8).
#[allow(clippy::too_many_arguments)]
#[allow(clippy::too_many_lines)]
async fn build_node_domain<D, S>(
    protocol_repository: Arc<ProtocolRepository<S>>,
    identity: ScpIdentity,
    document: DidDocument,
    did_method: Arc<D>,
    reach: Reach,
    tls: TlsMode,
    dht: DhtMode,
    bind_addr: Option<SocketAddr>,
    local_api: Option<SocketAddr>,
    http_bind_addr_opt: Option<SocketAddr>,
    cors_origins: Option<Vec<String>>,
    projection_rate_limit_opt: Option<u32>,
    dns_provider: Option<crate::dns_provider::DnsProviderConfig>,
    #[cfg(feature = "http3")] http3: Option<scp_transport::http3::Http3Config>,
    nat: NatSlot,
    network_detector: Option<Arc<dyn NetworkChangeDetector>>,
    blob_storage: BlobStorageBackend,
) -> Result<ApplicationNode<S>, NodeError>
where
    D: DidMethod + 'static,
    S: Storage + 'static,
{
    let Reach::Domain { domain } = reach else {
        unreachable!("build_node_domain is only called for Reach::Domain");
    };
    let mut domain = domain;

    // The `TlsMode::Acme` contact email is threaded into `resolve_tls`; every
    // other TlsMode returns its provider via `tls_override` (or `None`).
    let acme_email = match &tls {
        TlsMode::Acme { email } => email.clone(),
        _ => None,
    };
    let tls_mode_override = tls_override(
        tls,
        &Reach::Domain {
            domain: domain.clone(),
        },
    );

    // If DNS provider config is set, derive the subdomain from the DID and
    // create the ScpDnsProvider as the TLS provider (#642). This override takes
    // precedence over the TlsMode-derived provider, matching the legacy builder
    // (`tls_provider_override.or(self.tls_provider)`).
    let tls_provider_override = if let Some(dns_config) = dns_provider {
        let (provider, dns_domain) = dns_config.build(&identity.did);
        tracing::info!(
            did = %identity.did,
            dns_domain = %dns_domain,
            node_id = %provider.node_id(),
            "using DNS subdomain provider for zero-config TLS"
        );
        domain = dns_domain;
        Some(Arc::new(provider) as Arc<dyn TlsProvider>)
    } else {
        tls_mode_override
    };

    let bridge_secret = generate_bridge_secret();
    let bind_addr = bind_addr.unwrap_or_else(|| SocketAddr::from(([127, 0, 0, 1], 0)));
    let relay_config = RelayConfig {
        bind_addr,
        bridge_secret: Some(*bridge_secret),
        ..RelayConfig::default()
    };

    // The caller's explicit blob-backend selection, threaded verbatim — never
    // defaulted or fallen-back (SCP-CAPINJECT-010 / SCP-CAPSEL-8002).
    let blob_storage = Arc::new(blob_storage);
    let relay_server = RelayServer::new(relay_config.clone(), Arc::clone(&blob_storage));
    let connection_tracker = relay_server.connection_tracker();
    let subscription_registry = relay_server.subscriptions();
    // Shared PUBLISH rate limiter — the QUIC listener reuses it so PUBLISH
    // budgets are enforced uniformly across WebSocket and QUIC (ADR-037 AC3).
    #[cfg(feature = "quic")]
    let publish_rate_limiter = relay_server.publish_rate_limiter();
    // Shared DID-record slot index — the QUIC listener reuses it so
    // slot-exclusivity holds across WebSocket and QUIC over the shared store
    // (§3.10.2, SCP-RELAYRES-003).
    #[cfg(feature = "quic")]
    let did_slot_registry = relay_server.did_slot_registry();
    let (shutdown_handle, bound_addr) = relay_server.start().await?;
    let dev_token = local_api.map(generate_dev_token);
    let http_bind_addr = http_bind_addr_opt.unwrap_or(DEFAULT_HTTP_BIND_ADDR);

    let tls_provider = resolve_tls(
        tls_provider_override,
        &domain,
        &protocol_repository,
        acme_email.as_ref(),
    );

    let (provision_result, acme_challenges) =
        provision_with_challenge_listener(&*tls_provider).await?;
    let rate_limit = projection_rate_limit_opt.unwrap_or(DEFAULT_PROJECTION_RATE_LIMIT);

    match provision_result {
        Ok(cert_data) => {
            build_domain_inner(
                domain,
                identity,
                document,
                did_method,
                // Thread the configured `DhtMode` so the TLS-success domain path
                // honors it: `Disabled` (the legitimate more-private `Domain +
                // Disabled` config, M2) SKIPS publish and the node still starts;
                // `Production`/`Memory` publish fatally. Previously this path
                // published unconditionally + fatally, ignoring `config.dht`.
                dht,
                protocol_repository,
                shutdown_handle,
                bound_addr,
                bridge_secret,
                dev_token,
                local_api,
                blob_storage,
                relay_config,
                http_bind_addr,
                cors_origins.clone(),
                rate_limit,
                cert_data,
                connection_tracker.clone(),
                subscription_registry.clone(),
                #[cfg(feature = "quic")]
                publish_rate_limiter.clone(),
                #[cfg(feature = "quic")]
                did_slot_registry.clone(),
                acme_challenges,
                #[cfg(feature = "http3")]
                http3,
            )
            .await
        }
        Err(tls_err) => {
            tracing::warn!(
                domain = %domain, error = %tls_err,
                "TLS provisioning failed, falling through to NAT-traversed mode (§10.12.8)"
            );
            let strategy = resolve_nat_slot(nat);
            build_no_domain_inner(
                identity,
                document,
                did_method,
                // A Domain+Production node that falls through here (TLS
                // provisioning failed) still owes a DHT publish; threading `dht`
                // keeps that publish fail-closed instead of silently dropped.
                dht,
                protocol_repository,
                shutdown_handle,
                bound_addr,
                strategy,
                bridge_secret,
                dev_token,
                local_api,
                blob_storage,
                relay_config,
                Some(http_bind_addr),
                cors_origins,
                rate_limit,
                network_detector,
                connection_tracker,
                subscription_registry,
                #[cfg(feature = "quic")]
                publish_rate_limiter,
                #[cfg(feature = "quic")]
                did_slot_registry,
                // The domain reach's TLS-failure fall-through always probes NAT
                // (it is the §10.12.8 zero-config path), so it never skips the
                // probe — matching the legacy `self.skip_nat_probe` which was
                // `false` on every domain build.
                false,
            )
            .await
        }
    }
}

/// No-domain-reach engine path: ported verbatim from the former no-domain
/// `build_with_store`. Skips TLS provisioning entirely
/// and builds the NAT-traversed / loopback node directly.
#[allow(clippy::too_many_arguments)]
async fn build_node_no_domain<D, S>(
    protocol_repository: Arc<ProtocolRepository<S>>,
    identity: ScpIdentity,
    document: DidDocument,
    did_method: Arc<D>,
    dht: DhtMode,
    bind_addr: Option<SocketAddr>,
    local_api: Option<SocketAddr>,
    http_bind_addr: Option<SocketAddr>,
    cors_origins: Option<Vec<String>>,
    projection_rate_limit_opt: Option<u32>,
    #[cfg(feature = "http3")] _http3: Option<scp_transport::http3::Http3Config>,
    nat: NatSlot,
    network_detector: Option<Arc<dyn NetworkChangeDetector>>,
    blob_storage: BlobStorageBackend,
    skip_nat_probe: bool,
) -> Result<ApplicationNode<S>, NodeError>
where
    D: DidMethod + 'static,
    S: Storage + 'static,
{
    // 3. Start relay server.
    let bind_addr = bind_addr.unwrap_or_else(|| SocketAddr::from(([127, 0, 0, 1], 0)));
    let bridge_secret = generate_bridge_secret();
    let relay_config = RelayConfig {
        bind_addr,
        bridge_secret: Some(*bridge_secret),
        ..RelayConfig::default()
    };

    // The caller's explicit blob-backend selection, threaded verbatim — never
    // defaulted or fallen-back (SCP-CAPINJECT-010 / SCP-CAPSEL-8002).
    let blob_storage = Arc::new(blob_storage);
    let relay_server = RelayServer::new(relay_config.clone(), Arc::clone(&blob_storage));
    let connection_tracker = relay_server.connection_tracker();
    let subscription_registry = relay_server.subscriptions();
    // Shared PUBLISH rate limiter (unused in no-domain mode because QUIC is
    // not served without TLS, but kept on NodeState for a uniform struct).
    #[cfg(feature = "quic")]
    let publish_rate_limiter = relay_server.publish_rate_limiter();
    // Shared DID-record slot index (same rationale as publish_rate_limiter:
    // unused in no-domain mode, kept for a uniform NodeState).
    #[cfg(feature = "quic")]
    let did_slot_registry = relay_server.did_slot_registry();
    let (shutdown_handle, bound_addr) = relay_server.start().await?;

    // 4. Generate dev API token if local_api was configured.
    let dev_token = local_api.map(generate_dev_token);

    // 5-8. Delegate to shared no-domain logic.
    let strategy = resolve_nat_slot(nat);

    build_no_domain_inner(
        identity,
        document,
        did_method,
        dht,
        protocol_repository,
        shutdown_handle,
        bound_addr,
        strategy,
        bridge_secret,
        dev_token,
        local_api,
        blob_storage,
        relay_config,
        http_bind_addr,
        cors_origins,
        projection_rate_limit_opt.unwrap_or(DEFAULT_PROJECTION_RATE_LIMIT),
        network_detector,
        connection_tracker,
        subscription_registry,
        #[cfg(feature = "quic")]
        publish_rate_limiter,
        #[cfg(feature = "quic")]
        did_slot_registry,
        skip_nat_probe,
    )
    .await
}

impl Node {
    /// Constructs and starts an [`ApplicationNode`] from a [`NodeConfig`]
    /// (production path).
    ///
    /// Requires `S: EncryptedStorage` — compile-time enforcement that the
    /// storage backend encrypts data at rest (the ADR-052 `EncryptedStorage`
    /// seal). For testing with unencrypted backends, use
    /// [`Node::start_for_testing`].
    ///
    /// # Structural seal test (ADR-052 §AC-9)
    ///
    /// ADR-052 rejected demoting the seal to a runtime check, promising instead
    /// that the bound is "additionally backed by a structural test that the
    /// unencrypted path is unreachable from the production constructor." These
    /// two doctests are that test.
    ///
    /// A plaintext backend (`FilesystemStorage` — key-per-file, no encryption)
    /// **must not compile** against this constructor. `EncryptedStorage` is
    /// sealed inside `scp-platform`, so no downstream crate can vote a
    /// plaintext backend in:
    ///
    /// ```compile_fail,E0277
    /// use scp_identity::DidMethod;
    /// use scp_node::{Node, NodeConfig};
    /// use scp_platform::filesystem::FilesystemStorage;
    /// use scp_platform::traits::KeyCustody;
    ///
    /// // E0277: the trait bound `FilesystemStorage: EncryptedStorage`
    /// // is not satisfied.
    /// fn unsealed<K: KeyCustody + 'static, D: DidMethod + 'static>(
    ///     config: NodeConfig<K, D, FilesystemStorage>,
    /// ) {
    ///     let _fut = Node::start(config);
    /// }
    /// ```
    ///
    /// The **same** call over the **same** backend wrapped in
    /// `EncryptingAdapter` does compile. This pairing is what makes the
    /// assertion above sound: a bare `compile_fail` passes for *any* error, so
    /// the positive control proves the failure is attributable to the storage
    /// type rather than to a typo or an unrelated breakage:
    ///
    /// ```
    /// use scp_identity::DidMethod;
    /// use scp_node::{Node, NodeConfig};
    /// use scp_platform::encrypting_adapter::EncryptingAdapter;
    /// use scp_platform::filesystem::FilesystemStorage;
    /// use scp_platform::traits::KeyCustody;
    ///
    /// fn sealed<K: KeyCustody + 'static, D: DidMethod + 'static>(
    ///     config: NodeConfig<K, D, EncryptingAdapter<FilesystemStorage>>,
    /// ) {
    ///     let _fut = Node::start(config);
    /// }
    /// ```
    ///
    /// These run in CI's `Rust / doc` job (`cargo test --workspace --doc`).
    /// `cargo nextest` does not execute doctests; the compiling half of the
    /// pair is additionally covered by
    /// `crates/scp-node/tests/encrypted_storage_seal.rs`, which every test lane
    /// builds.
    ///
    /// # Errors
    ///
    /// Returns [`NodeError::InvalidConfig`] for contradictory configs (e.g.
    /// `Reach::Domain` + `TlsMode::Plaintext`), or any [`NodeError`] from
    /// storage, identity, relay, or TLS setup.
    pub async fn start<K, D, S>(
        config: NodeConfig<K, D, S>,
    ) -> Result<ApplicationNode<S>, NodeError>
    where
        K: KeyCustody + 'static,
        D: DidMethod + 'static,
        S: EncryptedStorage + 'static,
    {
        // `validate_config` borrows `config.reach` / `config.tls`, so it MUST
        // run before `split_config` moves `config`.
        validate_config(&config.reach, &config.tls)?;
        let (storage, identity, tail) = split_config(config);

        // Production constructor: `ProtocolRepository::new` (the only difference
        // from `start_for_testing`). Identity is resolved against the storage,
        // then the one shared engine orchestrates the build.
        let protocol_repository = Arc::new(ProtocolRepository::new(storage));
        // `Persisted` is the load-or-create-and-persist source. It normalizes to
        // a `Generate` source with `persist = true` (exactly as the legacy
        // builder's `identity_with_storage` did): `resolve_identity_persistent`
        // checks storage first and only generates+persists on a cache miss.
        // `Generate` / `Explicit` resolve with `persist = false`.
        let (resolved_source, persist) = match identity {
            IdentitySource::Persisted {
                custody,
                did_method,
            } => (
                IdentitySource::Generate {
                    custody,
                    did_method,
                },
                true,
            ),
            other => (other, false),
        };
        let (scp_identity, document, did_method) =
            resolve_identity_persistent(resolved_source, persist, protocol_repository.storage())
                .await?;
        build_node(
            protocol_repository,
            scp_identity,
            document,
            did_method,
            tail,
        )
        .await
    }

    /// Constructs and starts an [`ApplicationNode`] from a [`NodeConfig`]
    /// without requiring encrypted storage.
    ///
    /// **Testing only.** Production code must use [`Node::start`]. Feature-gated
    /// so it cannot be reached in a release build (preserving the
    /// `EncryptedStorage` seal).
    ///
    /// # Errors
    ///
    /// Returns [`NodeError::InvalidConfig`] for contradictory configs, or any
    /// [`NodeError`] from storage, identity, relay, or TLS setup.
    #[cfg(any(test, feature = "allow_unencrypted_storage"))]
    pub async fn start_for_testing<K, D, S>(
        config: NodeConfig<K, D, S>,
    ) -> Result<ApplicationNode<S>, NodeError>
    where
        K: KeyCustody + 'static,
        D: DidMethod + 'static,
        S: Storage + 'static,
    {
        // `validate_config` borrows `config.reach` / `config.tls`, so it MUST
        // run before `split_config` moves `config`.
        validate_config(&config.reach, &config.tls)?;
        let (storage, identity, tail) = split_config(config);

        // Testing constructor: `ProtocolRepository::new_for_testing` (the only
        // difference from `start`). The build then flows through the same engine.
        let protocol_repository = Arc::new(ProtocolRepository::new_for_testing(storage));
        // `Persisted` is the load-or-create-and-persist source. It normalizes to
        // a `Generate` source with `persist = true` (exactly as the legacy
        // builder's `identity_with_storage` did): `resolve_identity_persistent`
        // checks storage first and only generates+persists on a cache miss.
        // `Generate` / `Explicit` resolve with `persist = false`.
        let (resolved_source, persist) = match identity {
            IdentitySource::Persisted {
                custody,
                did_method,
            } => (
                IdentitySource::Generate {
                    custody,
                    did_method,
                },
                true,
            ),
            other => (other, false),
        };
        let (scp_identity, document, did_method) =
            resolve_identity_persistent(resolved_source, persist, protocol_repository.storage())
                .await?;
        build_node(
            protocol_repository,
            scp_identity,
            document,
            did_method,
            tail,
        )
        .await
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use scp_clock::SystemClock;
    use scp_dht::InMemoryDhtClient;
    use scp_identity::DidCache;
    use scp_identity::dht::DidDht;
    use scp_platform::in_memory::InMemoryStorage;
    use scp_platform::testing::InMemoryKeyCustody;

    use crate::ReachabilityTier;

    /// The concrete `DidDht` type used in tests (in-memory DHT + system clock).
    type TestDidDht = DidDht<InMemoryDhtClient, SystemClock>;

    /// Creates a `DidDht` instance with signing capability for tests.
    fn make_test_dht(custody: &Arc<InMemoryKeyCustody>) -> TestDidDht {
        let dht_client = Arc::new(InMemoryDhtClient::new());
        let cache = Arc::new(DidCache::new());
        let sign_fn = TestDidDht::make_sign_fn(Arc::clone(custody));
        DidDht::with_client_and_signer(dht_client, cache, sign_fn)
    }

    /// Mock NAT strategy that returns a pre-configured tier (avoids real STUN).
    struct MockNatStrategy {
        tier: ReachabilityTier,
    }

    impl NatStrategy for MockNatStrategy {
        fn select_tier(
            &self,
            _relay_port: u16,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<ReachabilityTier, NodeError>> + Send + '_>,
        > {
            let tier = self.tier.clone();
            Box::pin(async move { Ok(tier) })
        }
    }

    /// Builds a `Generate` identity source over a fresh in-memory custody.
    fn generate_identity() -> IdentitySource<InMemoryKeyCustody, TestDidDht> {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let did_method = Arc::new(make_test_dht(&custody));
        IdentitySource::Generate {
            custody,
            did_method,
        }
    }

    /// Creates an explicit identity + document for `Explicit` tests.
    async fn create_explicit_identity() -> (
        ScpIdentity,
        DidDocument,
        Arc<TestDidDht>,
        Arc<InMemoryKeyCustody>,
    ) {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let did_method = Arc::new(make_test_dht(&custody));
        let pre_rotation_custody = scp_platform::testing::InMemoryPreRotationCustody::new();
        let (identity, document, _handle) = did_method
            .create(&*custody, &pre_rotation_custody)
            .await
            .unwrap();
        (identity, document, did_method, custody)
    }

    // --- Test 1: domain + Generate -------------------------------------------

    #[tokio::test]
    async fn domain_generate_produces_did_dht_identity() {
        let node = Node::start_for_testing(NodeConfig {
            bind_addr: Some(SocketAddr::from(([127, 0, 0, 1], 0))),
            // Domain is publishing-capable; this test opts into Production to
            // exercise the public-hosting path (advisory in P1 — the test's
            // TestDidDht uses an in-memory client, so nothing is published
            // offline). `DhtMode::Memory` would be equally valid (see Test 11).
            dht: DhtMode::Production,
            ..NodeConfig::defaults(
                Reach::Domain {
                    domain: "config-gen.example.com".to_owned(),
                },
                generate_identity(),
                InMemoryStorage::new(),
                BlobStorageBackend::in_memory(),
            )
        })
        .await
        .unwrap();

        assert!(
            node.identity().did().starts_with("did:dht:"),
            "domain + Generate should yield a did:dht: identity"
        );
        // Observable behavior beyond "did not panic": the Domain reach lowered
        // to a domain-mode node with the wss:// relay url the builder derives.
        assert_eq!(
            node.domain(),
            Some("config-gen.example.com"),
            "Domain reach should surface the domain on the built node"
        );
        assert_eq!(
            node.relay_url(),
            "wss://config-gen.example.com/scp/v1",
            "domain mode should publish the wss:// relay url (spec §18.5.2)"
        );
        node.shutdown();
    }

    // --- Test 2: domain + Explicit preserves the supplied DID ----------------

    #[tokio::test]
    async fn domain_explicit_preserves_supplied_did() {
        let (identity, document, did_method, _custody) = create_explicit_identity().await;
        let expected_did = identity.did.clone();

        let node = Node::start_for_testing(NodeConfig {
            bind_addr: Some(SocketAddr::from(([127, 0, 0, 1], 0))),
            // Domain is publishing-capable; this test opts into Production for the
            // public-hosting path (advisory; Memory is equally valid).
            dht: DhtMode::Production,
            ..NodeConfig::defaults(
                Reach::Domain {
                    domain: "config-explicit.example.com".to_owned(),
                },
                IdentitySource::<InMemoryKeyCustody, TestDidDht>::Explicit(Box::new(
                    ExplicitIdentity {
                        identity,
                        document,
                        did_method,
                    },
                )),
                InMemoryStorage::new(),
                BlobStorageBackend::in_memory(),
            )
        })
        .await
        .unwrap();

        assert_eq!(
            node.identity().did(),
            expected_did,
            "Explicit identity should preserve the supplied DID"
        );
        node.shutdown();
    }

    // (The former "Acme lowers without provisioning on a no-domain reach" test
    // is removed: `TlsMode::Acme` on a non-`Domain` reach is now a loud
    // `InvalidConfig` — ACME needs a DNS name (fix 1). Its negative coverage is
    // `acme_with_non_domain_reach_is_invalid_config` and
    // `acme_rejected_on_all_non_domain_reaches` below.)

    // --- Test 4: NatTraversal -> no-domain -----------------------------------

    #[tokio::test]
    async fn nat_traversal_builds_no_domain() {
        let external_addr = SocketAddr::from(([198, 51, 100, 7], 32891));
        let node = Node::start_for_testing(NodeConfig {
            bind_addr: Some(SocketAddr::from(([127, 0, 0, 1], 0))),
            // NatTraversal is publishing-capable; this test opts into Production
            // to exercise the public path (advisory in P1; Memory is equally
            // valid — see Test 12).
            dht: DhtMode::Production,
            nat: NatSlot::Custom(Arc::new(MockNatStrategy {
                tier: ReachabilityTier::Stun { external_addr },
            })),
            ..NodeConfig::defaults(
                Reach::NatTraversal,
                generate_identity(),
                InMemoryStorage::new(),
                BlobStorageBackend::in_memory(),
            )
        })
        .await
        .unwrap();

        assert!(
            node.domain().is_none(),
            "NatTraversal should build a no-domain node"
        );
        assert!(
            node.relay_url().starts_with("ws://"),
            "no-domain mode should publish a ws:// url, got: {}",
            node.relay_url()
        );
        node.shutdown();
    }

    // --- Test 5: Tunnel skips NAT --------------------------------------------

    #[tokio::test]
    async fn tunnel_skips_nat_and_builds() {
        // Tunnel uses skip_nat_probe, so no MockNatStrategy is needed: the build
        // never contacts STUN.
        let node = Node::start_for_testing(NodeConfig {
            bind_addr: Some(SocketAddr::from(([127, 0, 0, 1], 0))),
            ..NodeConfig::defaults(
                Reach::Tunnel {
                    public_url: "https://tunnel.example.com".to_owned(),
                },
                generate_identity(),
                InMemoryStorage::new(),
                BlobStorageBackend::in_memory(),
            )
        })
        .await
        .unwrap();

        assert!(
            node.domain().is_none(),
            "Tunnel should build a no-domain node"
        );
        // Observable: a no-domain node publishes a loopback ws:// relay url
        // (the documented P1 Tunnel behavior — public_url is not yet threaded).
        assert!(
            node.relay_url().starts_with("ws://"),
            "Tunnel (no-domain) should publish a ws:// relay url, got: {}",
            node.relay_url()
        );
        node.shutdown();
    }

    // --- Test 6: Local skips NAT ---------------------------------------------

    #[tokio::test]
    async fn local_skips_nat_and_builds() {
        let node = Node::start_for_testing(NodeConfig {
            bind_addr: Some(SocketAddr::from(([127, 0, 0, 1], 0))),
            ..NodeConfig::defaults(
                Reach::Local,
                generate_identity(),
                InMemoryStorage::new(),
                BlobStorageBackend::in_memory(),
            )
        })
        .await
        .unwrap();

        assert!(
            node.domain().is_none(),
            "Local should build a no-domain node"
        );
        // Observable: Local lowers to a no-domain node with a loopback ws://
        // relay url, same as Tunnel.
        assert!(
            node.relay_url().starts_with("ws://"),
            "Local (no-domain) should publish a ws:// relay url, got: {}",
            node.relay_url()
        );
        node.shutdown();
    }

    // --- Test 7: Persisted identity round-trips the same DID -----------------

    #[tokio::test]
    async fn persisted_identity_round_trips_same_did() {
        let storage = Arc::new(InMemoryStorage::new());
        let custody = Arc::new(InMemoryKeyCustody::new());
        let did_method = Arc::new(make_test_dht(&custody));

        let node1 = Node::start_for_testing(NodeConfig {
            bind_addr: Some(SocketAddr::from(([127, 0, 0, 1], 0))),
            // Domain is publishing-capable; this test opts into Production for the
            // public-hosting path (advisory; Memory is equally valid).
            dht: DhtMode::Production,
            ..NodeConfig::defaults(
                Reach::Domain {
                    domain: "config-persist.example.com".to_owned(),
                },
                IdentitySource::Persisted {
                    custody: Arc::clone(&custody),
                    did_method: Arc::clone(&did_method),
                },
                Arc::clone(&storage),
                BlobStorageBackend::in_memory(),
            )
        })
        .await
        .unwrap();
        let first_did = node1.identity().did().to_owned();
        node1.shutdown();

        let node2 = Node::start_for_testing(NodeConfig {
            bind_addr: Some(SocketAddr::from(([127, 0, 0, 1], 0))),
            // Domain is publishing-capable; this test opts into Production for the
            // public-hosting path (advisory; Memory is equally valid).
            dht: DhtMode::Production,
            ..NodeConfig::defaults(
                Reach::Domain {
                    domain: "config-persist.example.com".to_owned(),
                },
                IdentitySource::Persisted {
                    custody,
                    did_method,
                },
                Arc::clone(&storage),
                BlobStorageBackend::in_memory(),
            )
        })
        .await
        .unwrap();

        assert_eq!(
            node2.identity().did(),
            first_did,
            "Persisted identity should reload the same DID on the second start"
        );
        node2.shutdown();
    }

    // --- Test 8: defaults + spread idiom compiles (M4) -----------------------

    #[tokio::test]
    async fn defaults_spread_idiom_compiles() {
        // M4: override one field while spreading defaults from separate values.
        let config = NodeConfig {
            tls: TlsMode::Acme {
                email: Some("spread@example.com".to_owned()),
            },
            ..NodeConfig::defaults(
                Reach::Local,
                generate_identity(),
                InMemoryStorage::new(),
                BlobStorageBackend::in_memory(),
            )
        };
        // The override took effect.
        assert!(matches!(config.tls, TlsMode::Acme { .. }));
    }

    // --- Test 9: defaults are fail-safe --------------------------------------

    #[test]
    fn defaults_are_fail_safe() {
        let c = NodeConfig::defaults(
            Reach::Local,
            generate_identity(),
            InMemoryStorage::new(),
            BlobStorageBackend::in_memory(),
        );
        assert!(matches!(c.tls, TlsMode::SelfSigned), "tls fail-safe");
        assert!(
            matches!(c.dht, DhtMode::Disabled),
            "dht fail-safe (no publish)"
        );
        assert!(matches!(c.nat, NatSlot::Auto), "nat fail-safe");
        assert!(c.bind_addr.is_none());
        assert!(c.local_api.is_none());
        assert!(c.http_bind_addr.is_none());
        assert!(c.cors_origins.is_none());
        assert!(c.projection_rate_limit.is_none());
        assert!(c.dns_provider.is_none());
        assert!(c.network_detector.is_none());
        // `blob_storage` is now a required, explicit selection (no default) — it
        // holds exactly the arm the caller passed (SCP-CAPINJECT-010).
        assert!(
            matches!(c.blob_storage, BlobStorageBackend::InMemory(_)),
            "blob_storage holds the explicitly-selected in-memory arm"
        );
        assert!(c.dht_gateways.is_empty());
        #[cfg(feature = "http3")]
        assert!(c.http3.is_none());
    }

    // --- Test 10: Domain + Plaintext is a loud config error ------------------

    #[tokio::test]
    async fn domain_plus_plaintext_is_invalid_config() {
        let result = Node::start_for_testing(NodeConfig {
            tls: TlsMode::Plaintext,
            ..NodeConfig::defaults(
                Reach::Domain {
                    domain: "config-plaintext.example.com".to_owned(),
                },
                generate_identity(),
                InMemoryStorage::new(),
                BlobStorageBackend::in_memory(),
            )
        })
        .await;

        assert!(
            matches!(result, Err(NodeError::InvalidConfig(_))),
            "Reach::Domain + TlsMode::Plaintext must be a loud InvalidConfig error"
        );
    }

    // --- Test 11: Domain + DhtMode::Disabled is VALID (the fail-safe direction) --

    #[tokio::test]
    async fn domain_plus_dht_memory_is_valid() {
        // `NodeConfig::defaults` yields `dht: DhtMode::Disabled`. `DhtMode::Disabled`
        // (do not publish the address to the DHT) is the fail-safe, non-disclosing
        // direction and is valid for EVERY reach, including a publishing-capable
        // `Reach::Domain`: "reachable on the domain, but the address is not
        // published to the DHT; share it out-of-band" — the more-private config.
        // Only `DhtMode::Production` discloses, so only it is an explicit opt-in
        // (M2); `Memory` is never an error. This is the positive companion to
        // Test 12 (NatTraversal + Memory).
        let node = Node::start_for_testing(NodeConfig {
            bind_addr: Some(SocketAddr::from(([127, 0, 0, 1], 0))),
            ..NodeConfig::defaults(
                Reach::Domain {
                    domain: "config-m2-domain.example.com".to_owned(),
                },
                generate_identity(),
                InMemoryStorage::new(),
                BlobStorageBackend::in_memory(),
            )
        })
        .await
        .expect("Domain + DhtMode::Disabled is the fail-safe direction and must be valid");

        // The successful build IS the proof that `DhtMode::Disabled` is accepted on
        // a publishing-capable `Reach::Domain` (it would have returned
        // `InvalidConfig` under the old, inverted rule). The domain still lowers.
        assert_eq!(
            node.domain(),
            Some("config-m2-domain.example.com"),
            "Domain reach should still surface the domain on the built node"
        );
        node.shutdown();
    }

    // --- Test 12: NatTraversal + DhtMode::Disabled is VALID --------------------

    #[tokio::test]
    async fn nat_traversal_plus_dht_memory_is_valid() {
        // `Reach::NatTraversal` + `DhtMode::Disabled` is the first-class
        // "reachable-but-not-DHT-discoverable" config: publicly reachable via NAT
        // traversal, but the address is NOT published to the DHT (share it
        // out-of-band). `Memory` is the fail-safe, non-disclosing direction and
        // must never be rejected; only `DhtMode::Production` discloses (M2). This
        // is exactly the `SCP_NODE_DHT_MODE=memory` capability the binary exposes.
        let external_addr = SocketAddr::from(([198, 51, 100, 7], 32891));
        let node = Node::start_for_testing(NodeConfig {
            bind_addr: Some(SocketAddr::from(([127, 0, 0, 1], 0))),
            nat: NatSlot::Custom(Arc::new(MockNatStrategy {
                tier: ReachabilityTier::Stun { external_addr },
            })),
            ..NodeConfig::defaults(
                Reach::NatTraversal,
                generate_identity(),
                InMemoryStorage::new(),
                BlobStorageBackend::in_memory(),
            )
        })
        .await
        .expect("NatTraversal + DhtMode::Disabled is the reachable-but-unpublished config and must be valid");

        // The successful build IS the proof that `DhtMode::Disabled` is accepted on
        // the publishing-capable `Reach::NatTraversal` (the old, inverted rule
        // returned `InvalidConfig` here).
        assert!(
            node.domain().is_none(),
            "NatTraversal should build a no-domain node"
        );
        node.shutdown();
    }

    // --- Test 13: Tunnel / Local + DhtMode::Disabled is VALID -------------------

    #[tokio::test]
    async fn tunnel_and_local_with_dht_memory_are_valid() {
        // `DhtMode::Disabled` (the defaults' dht) is the fail-safe, non-disclosing
        // direction and is valid for every reach. Tunnel and Local publish a
        // loopback URL, so Memory is the natural choice there. Together with
        // Tests 11/12 (Domain / NatTraversal + Memory) this covers Memory across
        // all four reaches; it also guards that Tests 5/6 (default Memory) build.
        let tunnel = Node::start_for_testing(NodeConfig {
            bind_addr: Some(SocketAddr::from(([127, 0, 0, 1], 0))),
            ..NodeConfig::defaults(
                Reach::Tunnel {
                    public_url: "https://tunnel-m2.example.com".to_owned(),
                },
                generate_identity(),
                InMemoryStorage::new(),
                BlobStorageBackend::in_memory(),
            )
        })
        .await
        .expect("Tunnel + DhtMode::Disabled is a non-publishing reach and must be valid");
        assert!(tunnel.domain().is_none());
        tunnel.shutdown();

        let local = Node::start_for_testing(NodeConfig {
            bind_addr: Some(SocketAddr::from(([127, 0, 0, 1], 0))),
            ..NodeConfig::defaults(
                Reach::Local,
                generate_identity(),
                InMemoryStorage::new(),
                BlobStorageBackend::in_memory(),
            )
        })
        .await
        .expect("Local + DhtMode::Disabled is a non-publishing reach and must be valid");
        assert!(local.domain().is_none());
        local.shutdown();
    }

    // --- Test 14: NatSlot::Tuned overrides lower onto the builder -------------

    #[tokio::test]
    async fn nat_tuned_overrides_build() {
        // `NatSlot::Tuned` feeds the DefaultNatStrategy (which probes over STUN),
        // so to stay offline we use `Reach::Local` (skip_nat_probe): the tuned
        // strategy is constructed and its four override setters
        // (stun_server / bridge_relay / port_mapper / reachability_probe) are
        // applied to the builder, but `select_tier` is never called → no STUN.
        // A successful build proves all four `apply_nat` Tuned setters lower
        // without panicking and the builder accepts them. DhtMode::Disabled (the
        // default) is valid for every reach, including Local.
        let node = Node::start_for_testing(NodeConfig {
            bind_addr: Some(SocketAddr::from(([127, 0, 0, 1], 0))),
            nat: NatSlot::Tuned {
                stun_server: Some("127.0.0.1:3478".to_owned()),
                bridge_relay: Some("wss://bridge.example.test/scp/v1".to_owned()),
                port_mapper: None,
                reachability_probe: None,
            },
            ..NodeConfig::defaults(
                Reach::Local,
                generate_identity(),
                InMemoryStorage::new(),
                BlobStorageBackend::in_memory(),
            )
        })
        .await
        .expect("NatSlot::Tuned overrides should lower and build offline on a Local reach");

        assert!(
            node.domain().is_none(),
            "Local should build a no-domain node even with NatSlot::Tuned overrides"
        );
        node.shutdown();
    }

    // --- Test 15: blob_storage is an explicit, required durability-only choice --

    /// SCP-CAPINJECT-010 AC3: `InMemoryBlobStorage` remains a legitimate,
    /// **explicitly-selected** durability-only backend (SCP-CAPSEL-8010/8011). A
    /// node built with an explicit `BlobStorageBackend::in_memory()` selection
    /// still builds and serves — proving the durability-only arm stays reachable
    /// by explicit choice. There is deliberately no "None preserves default" case
    /// anymore: `blob_storage` is a required, non-`Option` field, so there is no
    /// omit-the-field / silent-default shape to test (that shape was the removed
    /// SCP-CAPSEL-8011 violation).
    #[tokio::test]
    async fn blob_storage_in_memory_is_explicitly_selectable() {
        // Build on a Local (non-publishing) reach with an EXPLICIT in-memory blob
        // backend. A successful build + serve is the observable proof that the
        // durability-only arm is still selectable; we do not assert the private
        // backend value — only what is observable.
        let node = Node::start_for_testing(NodeConfig {
            bind_addr: Some(SocketAddr::from(([127, 0, 0, 1], 0))),
            ..NodeConfig::defaults(
                Reach::Local,
                generate_identity(),
                InMemoryStorage::new(),
                // The required, explicit durability-only selection.
                BlobStorageBackend::in_memory(),
            )
        })
        .await
        .expect("an explicit in-memory blob backend should build and serve");
        assert!(node.domain().is_none());
        node.shutdown();
    }

    // --- Test 16: Persisted rejects mismatched custody through Node::start -----

    #[tokio::test]
    async fn persisted_rejects_mismatched_custody_through_node_start() {
        // First start persists the identity under custodyA. The second start
        // over the SAME storage but a fresh custodyB (no keys) must be rejected
        // by the builder's persisted-identity validation, surfaced through the
        // config-level entry point. Domain is publishing-capable; opt into
        // Production to exercise the public path (Memory is equally valid).
        let storage = Arc::new(InMemoryStorage::new());
        let custody_a = Arc::new(InMemoryKeyCustody::new());
        let did_method_a = Arc::new(make_test_dht(&custody_a));

        let node1 = Node::start_for_testing(NodeConfig {
            bind_addr: Some(SocketAddr::from(([127, 0, 0, 1], 0))),
            dht: DhtMode::Production,
            ..NodeConfig::defaults(
                Reach::Domain {
                    domain: "config-mismatch.example.com".to_owned(),
                },
                IdentitySource::Persisted {
                    custody: Arc::clone(&custody_a),
                    did_method: did_method_a,
                },
                Arc::clone(&storage),
                BlobStorageBackend::in_memory(),
            )
        })
        .await
        .expect("first persisted start should succeed and persist the identity");
        node1.shutdown();

        // Fresh custody with NO keys → load-or-create must fail validation.
        let custody_b = Arc::new(InMemoryKeyCustody::new());
        let did_method_b = Arc::new(make_test_dht(&custody_b));

        let result = Node::start_for_testing(NodeConfig {
            bind_addr: Some(SocketAddr::from(([127, 0, 0, 1], 0))),
            dht: DhtMode::Production,
            ..NodeConfig::defaults(
                Reach::Domain {
                    domain: "config-mismatch.example.com".to_owned(),
                },
                IdentitySource::Persisted {
                    custody: custody_b,
                    did_method: did_method_b,
                },
                Arc::clone(&storage),
                BlobStorageBackend::in_memory(),
            )
        })
        .await;

        let err = result
            .err()
            .expect("second persisted start with mismatched custody should fail");
        let msg = err.to_string();
        assert!(
            msg.contains("not found in custody"),
            "expected custody validation error, got: {msg}"
        );
    }

    // --- Test 17: PRODUCTION Node::start over a real EncryptedStorage ----------

    #[tokio::test]
    async fn production_start_with_sqlite_encrypted_storage_builds() {
        use scp_platform::sqlite::SqliteStorage;

        // Exercises the SEAL path — `Node::start` (not `start_for_testing`),
        // which is `where S: EncryptedStorage`. `SqliteStorage` implements
        // `EncryptedStorage` (SQLCipher at-rest), so this monomorphizes the
        // production entry point with a genuinely encrypted backend. The
        // `start_for_testing` tests above all use `InMemoryStorage`, which is
        // NOT `EncryptedStorage` and so could never reach `Node::start`.
        let dir = tempfile::tempdir().expect("tempdir");
        let key = [7u8; 32];
        let storage =
            Arc::new(SqliteStorage::new(dir.path(), &key).expect("open encrypted SqliteStorage"));

        // Domain is publishing-capable; this test opts into Production to exercise
        // the public-hosting path (advisory in P1 — the TestDidDht uses an
        // in-memory client, so nothing is published offline). Domain + default
        // SelfSigned builds offline (no network/CA).
        let node = Node::start(NodeConfig {
            bind_addr: Some(SocketAddr::from(([127, 0, 0, 1], 0))),
            dht: DhtMode::Production,
            ..NodeConfig::defaults(
                Reach::Domain {
                    domain: "config-prod-sqlite.example.com".to_owned(),
                },
                generate_identity(),
                Arc::clone(&storage),
                BlobStorageBackend::in_memory(),
            )
        })
        .await
        .expect("production Node::start over encrypted SqliteStorage should build");

        assert!(
            node.identity().did().starts_with("did:dht:"),
            "production start should yield a did:dht: identity"
        );
        assert_eq!(
            node.domain(),
            Some("config-prod-sqlite.example.com"),
            "production start should surface the configured domain"
        );
        assert_eq!(
            node.relay_url(),
            "wss://config-prod-sqlite.example.com/scp/v1",
            "production domain mode should publish the wss:// relay url"
        );
        node.shutdown();
    }

    // --- Test 18: TlsMode::Terminated + Domain builds with a local cert -------

    #[tokio::test]
    async fn terminated_tls_with_domain_builds() {
        // `TlsMode::Terminated` (TLS terminated upstream by a tunnel/reverse
        // proxy) on a Domain reach must NOT fall through to the builder's default
        // AcmeProvider (which would bind :80 and contact Let's Encrypt). Instead
        // `apply_tls` installs the no-network self-signed provider so the node
        // terminates the proxy↔node hop locally and builds OFFLINE in domain
        // mode. The observable proof: a domain-mode node with the wss:// relay
        // url AND a populated cert resolver (local cert provisioned, no network).
        // This combination was previously unexecuted — and silently ran ACME.
        let node = Node::start_for_testing(NodeConfig {
            bind_addr: Some(SocketAddr::from(([127, 0, 0, 1], 0))),
            dht: DhtMode::Production,
            tls: TlsMode::Terminated,
            ..NodeConfig::defaults(
                Reach::Domain {
                    domain: "config-terminated.example.com".to_owned(),
                },
                generate_identity(),
                InMemoryStorage::new(),
                BlobStorageBackend::in_memory(),
            )
        })
        .await
        .expect("Terminated TLS + Domain should build offline (local self-signed, no ACME)");

        assert_eq!(
            node.domain(),
            Some("config-terminated.example.com"),
            "Terminated + Domain should still be a domain-mode node"
        );
        assert_eq!(
            node.relay_url(),
            "wss://config-terminated.example.com/scp/v1",
            "Terminated + Domain should publish the wss:// relay url"
        );
        assert!(
            node.cert_resolver().is_some(),
            "Terminated + Domain installs a no-network local cert (proxy↔node hop), \
             so the cert resolver is populated — it must NOT silently fall to ACME"
        );
        node.shutdown();
    }

    // --- Test 19: TlsMode::SelfSigned + Domain provisions self-signed TLS -----

    #[tokio::test]
    async fn self_signed_tls_with_domain_provisions_and_builds() {
        // `TlsMode::SelfSigned` on a Domain reach installs `SelfSignedTlsProvider`
        // and provisions a self-signed certificate (no network, no CA). The
        // observable proof that provisioning actually happened — not merely that
        // the build did not panic — is a populated `cert_resolver()`, which is
        // `Some` only when node-side TLS is active in domain mode.
        let node = Node::start_for_testing(NodeConfig {
            bind_addr: Some(SocketAddr::from(([127, 0, 0, 1], 0))),
            dht: DhtMode::Production,
            tls: TlsMode::SelfSigned,
            ..NodeConfig::defaults(
                Reach::Domain {
                    domain: "config-selfsigned.example.com".to_owned(),
                },
                generate_identity(),
                InMemoryStorage::new(),
                BlobStorageBackend::in_memory(),
            )
        })
        .await
        .expect("SelfSigned TLS + Domain should provision and build");

        assert_eq!(
            node.domain(),
            Some("config-selfsigned.example.com"),
            "SelfSigned + Domain should be a domain-mode node"
        );
        assert!(
            node.cert_resolver().is_some(),
            "SelfSigned on a Domain reach must actually provision node-side TLS \
             (a populated cert resolver), not silently skip it"
        );
        node.shutdown();
    }

    // --- Test 20: TlsMode::Acme + non-Domain reach is a loud config error ------

    #[tokio::test]
    async fn acme_with_non_domain_reach_is_invalid_config() {
        // The new TLS-axis rule (fix 1): ACME needs a DNS name, which only a
        // Domain reach provides. `TlsMode::Acme` on Local / Tunnel / NatTraversal
        // must be a loud `InvalidConfig`, not a silent no-op. There is no DHT
        // validity rule to interfere (Memory is valid for every reach), so this
        // cleanly isolates the Acme×Reach rejection. Validation runs before any
        // build, so no NAT
        // strategy is needed.
        let result = Node::start_for_testing(NodeConfig {
            tls: TlsMode::Acme {
                email: Some("admin@example.com".to_owned()),
            },
            ..NodeConfig::defaults(
                Reach::Local,
                generate_identity(),
                InMemoryStorage::new(),
                BlobStorageBackend::in_memory(),
            )
        })
        .await;

        let err = match result {
            Err(NodeError::InvalidConfig(msg)) => msg,
            Err(other) => panic!("expected InvalidConfig for Acme + Local, got: {other}"),
            Ok(node) => {
                node.shutdown();
                panic!("expected InvalidConfig for Acme + Local, got Ok");
            }
        };
        assert!(
            err.contains("TlsMode::Acme") && err.contains("Reach::Local"),
            "Acme×Reach error must name the contradiction, got: {err}"
        );
    }

    // --- Test 21: Acme is rejected on every non-Domain reach ------------------

    #[tokio::test]
    async fn acme_rejected_on_all_non_domain_reaches() {
        // Symmetry guard for fix 1: NatTraversal and Tunnel are also rejected
        // with Acme, exactly like Local (Test 20). Each is the same loud
        // `InvalidConfig`. Validation precedes the build, so no NAT mock is
        // needed even for the NatTraversal arm.
        for (reach, reach_name) in [
            (Reach::NatTraversal, "Reach::NatTraversal"),
            (
                Reach::Tunnel {
                    public_url: "https://tunnel-acme.example.com".to_owned(),
                },
                "Reach::Tunnel",
            ),
        ] {
            let result = Node::start_for_testing(NodeConfig {
                tls: TlsMode::Acme {
                    email: Some("admin@example.com".to_owned()),
                },
                ..NodeConfig::defaults(
                    reach,
                    generate_identity(),
                    InMemoryStorage::new(),
                    BlobStorageBackend::in_memory(),
                )
            })
            .await;

            let err = match result {
                Err(NodeError::InvalidConfig(msg)) => msg,
                Err(other) => {
                    panic!("expected InvalidConfig for Acme + {reach_name}, got: {other}")
                }
                Ok(node) => {
                    node.shutdown();
                    panic!("expected InvalidConfig for Acme + {reach_name}, got Ok");
                }
            };
            assert!(
                err.contains("TlsMode::Acme") && err.contains(reach_name),
                "Acme×{reach_name} error must name the contradiction, got: {err}"
            );
        }
    }

    // --- Test: Acme { email: None } on a Domain reach is accepted (headless) ---

    #[test]
    fn acme_with_none_email_on_domain_is_accepted() {
        // `TlsMode::Acme { email: None }` selects headless ACME — the legacy
        // default for a domain node that sets no TLS options (the builder's
        // domain `build()` falls through to `AcmeProvider::new(domain)` with no
        // contact email). It must be a VALID config on a `Reach::Domain` reach —
        // no loud error (the DHT mode does not affect TLS×Reach validity).
        // We assert at the `validate_config` layer rather than building, because
        // a real ACME provision would contact Let's Encrypt over the network;
        // validation is the observable acceptance gate before any provisioning.
        let reach = Reach::Domain {
            domain: "config-acme-headless.example.com".to_owned(),
        };
        let tls = TlsMode::Acme { email: None };
        validate_config(&reach, &tls)
            .expect("Domain + Acme { email: None } must be a valid config");
    }

    // --- Test 21: Plaintext / Terminated on a non-Domain reach are no-op builds

    #[tokio::test]
    async fn local_plaintext_builds() {
        // `TlsMode::Plaintext` is only valid on a non-`Domain` reach (Domain +
        // Plaintext is the loud error in Test 11). On `Reach::Local` it is a
        // no-op in `apply_tls` (the loopback listener is plaintext; no node-side
        // TLS is provisioned). Pin that contract directly — the existing Local
        // tests all build with the default `TlsMode::SelfSigned`, so this path
        // was only transitively covered. Local skips the NAT probe, so the build
        // stays offline; no NAT mock is needed.
        let node = Node::start_for_testing(NodeConfig {
            bind_addr: Some(SocketAddr::from(([127, 0, 0, 1], 0))),
            tls: TlsMode::Plaintext,
            ..NodeConfig::defaults(
                Reach::Local,
                generate_identity(),
                InMemoryStorage::new(),
                BlobStorageBackend::in_memory(),
            )
        })
        .await
        .expect("Local + Plaintext is a non-Domain no-op TLS build and must succeed");
        assert!(
            node.domain().is_none(),
            "Local builds a no-domain node regardless of TlsMode::Plaintext"
        );
        node.shutdown();
    }

    #[tokio::test]
    async fn local_terminated_builds() {
        // Companion to `local_plaintext_builds`: `TlsMode::Terminated` on a
        // non-`Domain` reach is likewise a no-op in `apply_tls` (the upstream
        // proxy terminates TLS; the loopback listener stays plaintext). The
        // Terminated×Domain path is covered by Test 18; this pins the
        // non-Domain no-op branch, which was only transitively exercised. Offline
        // for the same reason as above (Local skips the NAT probe).
        let node = Node::start_for_testing(NodeConfig {
            bind_addr: Some(SocketAddr::from(([127, 0, 0, 1], 0))),
            tls: TlsMode::Terminated,
            ..NodeConfig::defaults(
                Reach::Local,
                generate_identity(),
                InMemoryStorage::new(),
                BlobStorageBackend::in_memory(),
            )
        })
        .await
        .expect("Local + Terminated is a non-Domain no-op TLS build and must succeed");
        assert!(
            node.domain().is_none(),
            "Local builds a no-domain node regardless of TlsMode::Terminated"
        );
        node.shutdown();
    }
}
