//! Flat-config-object construction surface for [`ApplicationNode`].
//!
//! This module implements the **ADR-052 Unified Construction Pattern** (Phase
//! B-P1) for the Node entry point. It introduces a single flat config object
//! ([`NodeConfig`]) plus a single zero-sized entry-point namespace ([`Node`])
//! exposing [`Node::start`] / [`Node::start_for_testing`], replacing the
//! LLM-hostile typestate builder surface with a shape an agent can author in
//! one pass from the type signature plus one example.
//!
//! See `.docs/standards/construction.md` (the enforced enactment of the
//! Agent-first API design builder tenet) and ADR-052 in
//! `.docs/adrs/phase-2.md`.
//!
//! ## Additive lowering
//!
//! Phase B-P1 is **additive**: [`Node::start`] lowers a [`NodeConfig`] onto the
//! existing [`ApplicationNodeBuilder`]. The typestate kernel and every existing
//! call site are untouched; this surface is the new front door that delegates to
//! the old machinery. Later phases migrate call sites and then delete the
//! typestate kernel (ADR-052 AC-3).

use std::net::SocketAddr;
use std::sync::Arc;

use scp_identity::document::DidDocument;
use scp_identity::{DidMethod, ScpIdentity};
use scp_platform::EncryptedStorage;
use scp_platform::traits::{KeyCustody, Storage};
use scp_transport::nat::NetworkChangeDetector;
use scp_transport::native::storage::BlobStorageBackend;

use crate::{
    ApplicationNode, ApplicationNodeBuilder, DhtMode, NatStrategy, NoOpCustody, NoOpDidMethod,
    NoOpStorage, NodeError, TlsProvider,
};

// ---------------------------------------------------------------------------
// Node — zero-sized entry-point namespace
// ---------------------------------------------------------------------------

/// Zero-sized entry-point namespace for Node construction (ADR-052).
///
/// All node construction flows through [`Node::start`] (production,
/// `where S: EncryptedStorage`) or [`Node::start_for_testing`] (feature-gated,
/// any `Storage`). There is no `NodeBuilder`, no typestate, no `.build()`
/// terminator — the construction surface is one flat [`NodeConfig`] plus one
/// entry function.
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
// Reach — the addressing XOR (M1 enum, replaces typestate + skip_nat bool)
// ---------------------------------------------------------------------------

/// How the node is reached from the outside — the addressing choice, as one
/// required field (ADR-052 M1).
///
/// `Reach` folds the former `HasDomain` / `HasNoDomain` typestate markers and
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
/// `TlsMode` is a **closed** selector: it exposes a fixed set of provisioning
/// strategies and has no variant for injecting an arbitrary
/// `Arc<dyn TlsProvider>`. This asymmetry with [`NatSlot`] — which intentionally
/// offers a [`Custom`](NatSlot::Custom) open slot — is deliberate, per
/// construction.md's "providers stay typed enum-selectors, never `dyn`" rule:
/// TLS provisioning is fully covered by the variants below, so the type itself
/// signals that callers select a strategy rather than supply their own.
#[derive(Debug, Clone)]
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
/// )).await?;
/// ```
///
/// ## Example: public node on a domain
///
/// A publishing reach (`Reach::Domain`) advertises a routable address, so it
/// requires `DhtMode::Production` **explicitly** — publishing your location to
/// the DHT is a deliberate opt-in (M2), never a silent default. Selecting a
/// publishing reach while leaving the default `DhtMode::Memory` is a loud
/// [`NodeError::InvalidConfig`], not a silent publish:
///
/// ```ignore
/// let node = Node::start(NodeConfig {
///     dht: DhtMode::Production,
///     tls: TlsMode::Acme { email: Some("admin@example.com".into()) },
///     ..NodeConfig::defaults(
///         Reach::Domain { domain: "example.com".into() },
///         IdentitySource::Generate { custody, did_method },
///         storage,
///     )
/// }).await?;
/// ```
///
/// The `<K, D, S>` generics survive from the former typestate builder, carried
/// by the config and its selectors; the `Dom`/`Id` typestate markers are gone.
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
    /// Advisory in P1: the actual Memory-vs-Production DHT-client selection
    /// lives in the concrete `D` (DID method) the caller passes. This field
    /// records the intent and defaults to the fail-safe [`DhtMode::Memory`]
    /// (no publish — M2); it is **not** yet wired to a builder setter, because
    /// the existing builder has no DHT setter. It is carried so the config is
    /// shape-complete and forward-compatible.
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
    /// Advisory in P1, paired with [`dht`](Self::dht): the existing builder has
    /// no `dht_gateways` setter, so this field is carried but inert (the actual
    /// gateway wiring lives in the concrete `D` the caller passes). Defaults to
    /// an empty vec.
    // shape-complete per ADR-052; wired to the DHT method in P3
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
    /// Blob storage backend for the relay. `None` preserves the builder's
    /// in-memory default; `Some` overrides it.
    pub blob_storage: Option<BlobStorageBackend>,
}

impl<K: KeyCustody, D: DidMethod, S: Storage> NodeConfig<K, D, S> {
    /// Constructs a [`NodeConfig`] from the irreducible required fields, filling
    /// every other field with its **fail-safe** default (ADR-052 M4).
    ///
    /// Fail-safe defaults: `tls = TlsMode::SelfSigned`, `dht = DhtMode::Memory`
    /// (no publish), every `Option` = `None`, `dht_gateways = []`,
    /// `nat = NatSlot::Auto`.
    ///
    /// This enables the spread idiom. Because `reach`/`identity`/`storage` are
    /// moved into the returned struct, the caller passes *separate* values to
    /// `defaults(...)` than the fields it overrides:
    ///
    /// ```ignore
    /// NodeConfig { tls: TlsMode::Acme { email }, ..NodeConfig::defaults(reach2, identity2, storage2) }
    /// ```
    #[must_use]
    pub fn defaults(reach: Reach, identity: IdentitySource<K, D>, storage: S) -> Self {
        Self {
            reach,
            identity,
            storage,
            tls: TlsMode::SelfSigned,
            dht: DhtMode::Memory,
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
            blob_storage: None,
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
// Lowering: NodeConfig -> ApplicationNodeBuilder
// ---------------------------------------------------------------------------

/// The portion of a [`NodeConfig`] that is **not** identity or storage — the
/// "tail" applied uniformly across all three identity arms.
///
/// Extracting this lets the three identity arms (which produce different
/// concrete builder types) each flow through one generic continuation.
struct ConfigTail {
    reach: Reach,
    tls: TlsMode,
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
    blob_storage: Option<BlobStorageBackend>,
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
/// The second axis is M2 (DHT publish): a *publishing* reach (`Reach::Domain`
/// or `Reach::NatTraversal`, both of which advertise a routable address) with
/// `DhtMode::Memory` (which never publishes to the DHT). Per
/// `.docs/standards/construction.md` M2, this is a precise, loud error — not a
/// silent publish, not a silent no-op. `Reach::Tunnel` / `Reach::Local` publish
/// a loopback URL (non-routable) and are therefore non-publishing reaches,
/// valid with `DhtMode::Memory`.
fn validate_config(reach: &Reach, tls: &TlsMode, dht: DhtMode) -> Result<(), NodeError> {
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
    // M2: a publishing reach advertises a routable address, which only reaches
    // the network when the DID document is actually published to the DHT.
    // `DhtMode::Memory` never publishes, so the routable address would be
    // unreachable — a contradiction. Fail loud with the contradiction and fix.
    if dht == DhtMode::Memory {
        let publishing_reach = match reach {
            Reach::Domain { .. } => Some("Reach::Domain"),
            Reach::NatTraversal => Some("Reach::NatTraversal"),
            Reach::Tunnel { .. } | Reach::Local => None,
        };
        if let Some(reach_name) = publishing_reach {
            return Err(NodeError::InvalidConfig(format!(
                "{reach_name} publishes a routable address but DhtMode::Memory does not publish \
                 to the DHT. Select DhtMode::Production to publish, or a non-publishing Reach \
                 (Tunnel/Local)."
            )));
        }
    }
    Ok(())
}

/// Splits a [`NodeConfig`] into its three independently-handled parts: the
/// storage backend, the identity source, and the uniform [`ConfigTail`].
///
/// Shared by both entry points ([`Node::start`] / [`Node::start_for_testing`])
/// so the ~37-line destructure + `ConfigTail` rebuild lives in exactly one place
/// (DRY). The advisory `dht` / `dht_gateways` fields are dropped here (the
/// concrete `D` selects Memory vs Production; there is no builder setter yet).
///
/// `validate_config` borrows `config.reach` / `config.dht` and so MUST run
/// **before** this function moves `config` — callers keep that ordering.
fn split_config<K: KeyCustody, D: DidMethod, S: Storage>(
    config: NodeConfig<K, D, S>,
) -> (S, IdentitySource<K, D>, ConfigTail) {
    let NodeConfig {
        reach,
        identity,
        storage,
        tls,
        // `dht` and `dht_gateways` are advisory in P1 (the concrete `D`
        // selects Memory vs Production); they have no builder setter yet.
        dht: _,
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

/// Applies the [`NatSlot`] to a builder, lowering each tuning override onto the
/// matching builder setter.
fn apply_nat<K, D, S, Dom, Id>(
    builder: ApplicationNodeBuilder<K, D, S, Dom, Id>,
    nat: NatSlot,
) -> ApplicationNodeBuilder<K, D, S, Dom, Id>
where
    K: KeyCustody + 'static,
    D: DidMethod + 'static,
    S: Storage + 'static,
{
    match nat {
        // Auto: no setters; the builder constructs DefaultNatStrategy internally.
        NatSlot::Auto => builder,
        NatSlot::Custom(strategy) => builder.nat_strategy(strategy),
        NatSlot::Tuned {
            stun_server,
            bridge_relay,
            port_mapper,
            reachability_probe,
        } => {
            let mut b = builder;
            if let Some(s) = stun_server {
                b = b.stun_server(&s);
            }
            if let Some(s) = bridge_relay {
                b = b.bridge_relay(&s);
            }
            if let Some(pm) = port_mapper {
                b = b.port_mapper(pm);
            }
            if let Some(rp) = reachability_probe {
                b = b.reachability_probe(rp);
            }
            b
        }
    }
}

/// Applies the [`TlsMode`] to a builder.
///
/// - `SelfSigned` installs a [`SelfSignedTlsProvider`] on a `Domain` reach
///   (non-domain builds skip TLS provisioning entirely — no domain to sign for).
/// - `Acme` sets the ACME contact email (only ever reaches here on a `Domain`
///   reach — `validate_config` already rejected `Acme` on every non-`Domain`
///   reach).
/// - `Terminated` (TLS terminated upstream by a tunnel/reverse proxy) on a
///   `Domain` reach installs the **no-network** [`SelfSignedTlsProvider`]: the
///   node still terminates a local TLS connection from the upstream proxy, so it
///   needs a local cert, but it must NOT run ACME. **This is load-bearing:** the
///   legacy domain build defaults a missing `tls_provider` to a real
///   `AcmeProvider` (binds :80, contacts Let's Encrypt). Leaving `Terminated` a
///   no-op here would silently attempt ACME on a `Terminated` domain node — the
///   exact silent-wrong-default the construction standard forbids. The upstream
///   proxy presents the real CA certificate to the public; the node-side
///   self-signed cert only secures the proxy↔node hop.
/// - `Plaintext` is only valid on a non-`Domain` reach (`validate_config` already
///   rejected `Domain` + `Plaintext`); no-domain mode skips TLS, so it is a
///   no-op. On a non-`Domain` reach, `Terminated` is likewise a no-op (the
///   loopback listener is plaintext; the proxy adds TLS).
fn apply_tls<K, D, S, Dom, Id>(
    builder: ApplicationNodeBuilder<K, D, S, Dom, Id>,
    tls: TlsMode,
    reach: &Reach,
) -> ApplicationNodeBuilder<K, D, S, Dom, Id>
where
    K: KeyCustody + 'static,
    D: DidMethod + 'static,
    S: Storage + 'static,
{
    match tls {
        TlsMode::SelfSigned => {
            if let Reach::Domain { domain } = reach {
                builder.tls_provider(Arc::new(SelfSignedTlsProvider {
                    domain: domain.clone(),
                }))
            } else {
                // Non-domain reach: no domain TLS to provision; self-signed is a no-op.
                builder
            }
        }
        TlsMode::Acme { email } => match email {
            // `Some(e)` registers the ACME account with contact email `e`.
            Some(e) => builder.acme_email(&e),
            // `None` applies no email setter: the builder's domain `build()`
            // falls through to the default `AcmeProvider::new(domain)` with no
            // contact email — the legacy headless-ACME default, reproduced
            // exactly.
            None => builder,
        },
        TlsMode::Terminated => {
            if let Reach::Domain { domain } = reach {
                // Domain + Terminated: install a no-network self-signed provider
                // so the node terminates the proxy↔node hop locally and does NOT
                // fall through to the builder's default AcmeProvider. The public
                // CA cert lives at the upstream proxy.
                builder.tls_provider(Arc::new(SelfSignedTlsProvider {
                    domain: domain.clone(),
                }))
            } else {
                // Non-domain reach: loopback listener is plaintext; proxy adds
                // TLS. No node-side provisioning — a no-op.
                builder
            }
        }
        // Plaintext: only valid on a non-domain reach (Domain+Plaintext errored
        // already); no-domain mode skips TLS, so this is a no-op.
        TlsMode::Plaintext => builder,
    }
}

/// Applies the config tail (optionals + nat + tls + reach addressing) to a
/// builder that already has storage and identity set, applying the optional
/// setters, NAT slot, and TLS mode — but **not** the reach addressing (which
/// changes the `Dom` typestate and so is applied by the caller's finisher).
///
/// Returns the builder still in `NoDomain` state, ready for addressing. Generic
/// over the builder's `K`/`D` so all three identity arms reuse it.
fn apply_tail<K, D, S>(
    builder: ApplicationNodeBuilder<K, D, S, crate::NoDomain, crate::HasIdentity>,
    tail: ConfigTail,
) -> ApplicationNodeBuilder<K, D, S, crate::NoDomain, crate::HasIdentity>
where
    K: KeyCustody + 'static,
    D: DidMethod + 'static,
    S: Storage + 'static,
{
    // Apply the &mut-self-style optional setters first (they keep Dom generic).
    let mut b = builder;
    if let Some(addr) = tail.bind_addr {
        b = b.bind_addr(addr);
    }
    if let Some(addr) = tail.local_api {
        b = b.local_api(addr);
    }
    if let Some(addr) = tail.http_bind_addr {
        b = b.http_bind_addr(addr);
    }
    if let Some(origins) = tail.cors_origins {
        b = b.cors_origins(origins);
    }
    if let Some(rate) = tail.projection_rate_limit {
        b = b.projection_rate_limit(rate);
    }
    if let Some(cfg) = tail.dns_provider {
        b = b.dns_provider(cfg);
    }
    if let Some(detector) = tail.network_detector {
        b = b.network_detector(detector);
    }
    #[cfg(feature = "http3")]
    if let Some(cfg) = tail.http3 {
        b = b.http3(cfg);
    }
    // blob_storage: only override when Some, so None preserves the builder's
    // `new()` default (`Some(BlobStorageBackend::default())`).
    if let Some(blob) = tail.blob_storage {
        b = b.blob_storage(blob);
    }

    // NatSlot lowering, then TlsMode lowering (both keep Dom = NoDomain).
    let b = apply_nat(b, tail.nat);
    apply_tls(b, tail.tls, &tail.reach)
}

/// Emits a one-time `tracing::warn!` noting that `Reach::Tunnel`'s `public_url`
/// is carried but not yet threaded in P1 (the node publishes a loopback URL).
///
/// This makes the documented deferral observable instead of a silent drop
/// (addresses the accepted-then-ignored misuse-resistance finding) WITHOUT
/// inventing wiring. Called from both finishers' Tunnel arm.
fn warn_tunnel_public_url_deferred(public_url: &str) {
    tracing::warn!(
        public_url,
        "Reach::Tunnel.public_url is carried but not yet threaded in P1; the node \
         publishes a loopback relay URL. Configure the tunnel to forward to that \
         loopback listener."
    );
}

/// Applies the optional tail, addresses the builder per the reach, and finishes
/// with the production `build()` (`where S: EncryptedStorage`). The reach
/// addressing yields either `HasDomain` or `HasNoDomain` — both have `build()`.
///
/// This and its testing twin [`finish_build_for_testing`] are the **one split
/// no generic finisher can collapse** in this module: the reach `match` is
/// byte-for-byte identical, but the terminal call differs by trait bound
/// (`build()` requires `S: EncryptedStorage` — the production seal;
/// `build_for_testing()` accepts any `S: Storage`). A single generic finisher
/// cannot name both terminal methods, because a fn/closure has one fixed `S`
/// bound. The *larger* duplication — the identity `match` that repeats across
/// `Node::start` and `Node::start_for_testing` — is NOT hoisted into a shared
/// inner either; see the comment block below this fn for why a generic finisher
/// cannot absorb it.
async fn finish_build<K, D, S>(
    builder: ApplicationNodeBuilder<K, D, S, crate::NoDomain, crate::HasIdentity>,
    tail: ConfigTail,
) -> Result<ApplicationNode<S>, NodeError>
where
    K: KeyCustody + 'static,
    D: DidMethod + 'static,
    S: EncryptedStorage + 'static,
{
    let reach = tail.reach.clone();
    let b = apply_tail(builder, tail);
    match reach {
        Reach::Domain { domain } => b.domain(&domain).build().await,
        Reach::NatTraversal => b.no_domain().build().await,
        Reach::Tunnel { public_url } => {
            warn_tunnel_public_url_deferred(&public_url);
            b.no_domain().skip_nat_probe().build().await
        }
        Reach::Local => b.no_domain().skip_nat_probe().build().await,
    }
}

/// Testing twin of [`finish_build`]: finishes with `build_for_testing()`
/// (`where S: Storage`).
#[cfg(any(test, feature = "allow_unencrypted_storage"))]
async fn finish_build_for_testing<K, D, S>(
    builder: ApplicationNodeBuilder<K, D, S, crate::NoDomain, crate::HasIdentity>,
    tail: ConfigTail,
) -> Result<ApplicationNode<S>, NodeError>
where
    K: KeyCustody + 'static,
    D: DidMethod + 'static,
    S: Storage + 'static,
{
    let reach = tail.reach.clone();
    let b = apply_tail(builder, tail);
    match reach {
        Reach::Domain { domain } => b.domain(&domain).build_for_testing().await,
        Reach::NatTraversal => b.no_domain().build_for_testing().await,
        Reach::Tunnel { public_url } => {
            warn_tunnel_public_url_deferred(&public_url);
            b.no_domain().skip_nat_probe().build_for_testing().await
        }
        Reach::Local => b.no_domain().skip_nat_probe().build_for_testing().await,
    }
}

// Why the identity `match` is NOT hoisted into one shared inner across
// `Node::start` / `Node::start_for_testing` (the dedup the reviewer asked us to
// attempt). It is not reducible *via a generic finisher / closure*: two
// independent type-system facts block that route.
//
//   1. The `Explicit` arm lowers via `base.identity(...)`, which yields a
//      builder with `K = NoOpCustody`, while `Generate`/`Persisted` lower via
//      `generate_identity_with` / `identity_with_storage`, yielding `K`. Three
//      arms, two distinct `K`s — so the post-identity builder has no single
//      type a generic finisher closure (one fixed `K`) could accept.
//   2. The finisher's terminal call differs by `S` bound — `.build()` needs
//      `S: EncryptedStorage` (the production seal), `.build_for_testing()`
//      needs only `S: Storage`. A trait with a generic `call<K, S>` method
//      could absorb (1), but its method signature fixes one `S` bound, so it
//      cannot serve both terminals.
//
// Either alone might be worked around; together they require a generic-over-`K`
// trait method whose `S` bound varies per impl — not expressible in Rust. So no
// value-level finisher collapses it. A token-level `macro_rules!` *could* paste
// the shared arm bodies (macros expand before type-checking, so they sidestep
// both bounds), but we deliberately do NOT use one here: it would hide the
// control flow and the per-terminal trait bounds behind an expansion, working
// against this module's LLM-legibility goal. So the ~30-line identity `match`
// stays explicitly duplicated, each arm handing its concrete builder straight
// to its finisher. The reach lowering inside the finishers is the same split,
// reducible only by the same macro route, and left explicit for the same reason
// (see `finish_build`).

impl Node {
    /// Constructs and starts an [`ApplicationNode`] from a [`NodeConfig`]
    /// (production path).
    ///
    /// Requires `S: EncryptedStorage` — compile-time enforcement that the
    /// storage backend encrypts data at rest (the ADR-052 `EncryptedStorage`
    /// seal). For testing with unencrypted backends, use
    /// [`Node::start_for_testing`].
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
        // `validate_config` borrows `config.reach` / `config.dht`, so it MUST
        // run before `split_config` moves `config`.
        validate_config(&config.reach, &config.tls, config.dht)?;
        let (storage, identity, tail) = split_config(config);

        // Storage first (requires NoOpStorage state), then identity (consuming
        // custody/did_method), then the tail. Each identity arm yields a
        // different concrete builder type (Explicit drops to NoOpCustody), so
        // each flows through `finish_build` independently — the irreducible
        // split documented on `finish_build`.
        let base = ApplicationNodeBuilder::new().storage(storage);
        match identity {
            IdentitySource::Generate {
                custody,
                did_method,
            } => {
                let builder = base.generate_identity_with(custody, did_method);
                finish_build(builder, tail).await
            }
            IdentitySource::Persisted {
                custody,
                did_method,
            } => {
                let builder = base.identity_with_storage(custody, did_method);
                finish_build(builder, tail).await
            }
            IdentitySource::Explicit(e) => {
                let ExplicitIdentity {
                    identity,
                    document,
                    did_method,
                } = *e;
                let builder = base.identity(identity, document, did_method);
                finish_build(builder, tail).await
            }
        }
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
        // `validate_config` borrows `config.reach` / `config.dht`, so it MUST
        // run before `split_config` moves `config`.
        validate_config(&config.reach, &config.tls, config.dht)?;
        let (storage, identity, tail) = split_config(config);

        let base = ApplicationNodeBuilder::new().storage(storage);
        match identity {
            IdentitySource::Generate {
                custody,
                did_method,
            } => {
                let builder = base.generate_identity_with(custody, did_method);
                finish_build_for_testing(builder, tail).await
            }
            IdentitySource::Persisted {
                custody,
                did_method,
            } => {
                let builder = base.identity_with_storage(custody, did_method);
                finish_build_for_testing(builder, tail).await
            }
            IdentitySource::Explicit(e) => {
                let ExplicitIdentity {
                    identity,
                    document,
                    did_method,
                } = *e;
                let builder = base.identity(identity, document, did_method);
                finish_build_for_testing(builder, tail).await
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use scp_identity::DidCache;
    use scp_identity::cache::SystemClock;
    use scp_identity::dht::DidDht;
    use scp_identity::dht_client::InMemoryDhtClient;
    use scp_platform::testing::{InMemoryKeyCustody, InMemoryStorage};

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
            // Domain is a publishing reach; M2 requires Production (advisory in
            // P1 — the test's TestDidDht uses an in-memory client, so nothing is
            // actually published offline).
            dht: DhtMode::Production,
            ..NodeConfig::defaults(
                Reach::Domain {
                    domain: "config-gen.example.com".to_owned(),
                },
                generate_identity(),
                InMemoryStorage::new(),
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
            // Domain is a publishing reach; M2 requires Production (advisory).
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
            // NatTraversal is a publishing reach; M2 requires Production
            // (advisory in P1).
            dht: DhtMode::Production,
            nat: NatSlot::Custom(Arc::new(MockNatStrategy {
                tier: ReachabilityTier::Stun { external_addr },
            })),
            ..NodeConfig::defaults(
                Reach::NatTraversal,
                generate_identity(),
                InMemoryStorage::new(),
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
            ..NodeConfig::defaults(Reach::Local, generate_identity(), InMemoryStorage::new())
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
            // Domain is a publishing reach; M2 requires Production (advisory).
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
            )
        })
        .await
        .unwrap();
        let first_did = node1.identity().did().to_owned();
        node1.shutdown();

        let node2 = Node::start_for_testing(NodeConfig {
            bind_addr: Some(SocketAddr::from(([127, 0, 0, 1], 0))),
            // Domain is a publishing reach; M2 requires Production (advisory).
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
            ..NodeConfig::defaults(Reach::Local, generate_identity(), InMemoryStorage::new())
        };
        // The override took effect.
        assert!(matches!(config.tls, TlsMode::Acme { .. }));
    }

    // --- Test 9: defaults are fail-safe --------------------------------------

    #[test]
    fn defaults_are_fail_safe() {
        let c = NodeConfig::defaults(Reach::Local, generate_identity(), InMemoryStorage::new());
        assert!(matches!(c.tls, TlsMode::SelfSigned), "tls fail-safe");
        assert!(
            matches!(c.dht, DhtMode::Memory),
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
        assert!(c.blob_storage.is_none());
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
            )
        })
        .await;

        assert!(
            matches!(result, Err(NodeError::InvalidConfig(_))),
            "Reach::Domain + TlsMode::Plaintext must be a loud InvalidConfig error"
        );
    }

    // --- Test 11: Domain + DhtMode::Memory is a loud M2 config error ----------

    #[tokio::test]
    async fn domain_plus_dht_memory_is_invalid_config() {
        // `NodeConfig::defaults` yields `dht: DhtMode::Memory`. A `Reach::Domain`
        // publishes a routable address, so Memory (no publish) is the precise,
        // loud M2 contradiction — not a silent publish, not a silent no-op.
        let result = Node::start_for_testing(NodeConfig::defaults(
            Reach::Domain {
                domain: "config-m2-domain.example.com".to_owned(),
            },
            generate_identity(),
            InMemoryStorage::new(),
        ))
        .await;

        let err = match result {
            Err(NodeError::InvalidConfig(msg)) => msg,
            Err(other) => {
                panic!("expected InvalidConfig for Domain + DhtMode::Memory, got: {other}")
            }
            Ok(node) => {
                node.shutdown();
                panic!("expected InvalidConfig for Domain + DhtMode::Memory, got Ok");
            }
        };
        assert!(
            err.contains("Reach::Domain") && err.contains("DhtMode::Memory"),
            "M2 error must name the contradiction, got: {err}"
        );
    }

    // --- Test 12: NatTraversal + DhtMode::Memory is a loud M2 config error -----

    #[tokio::test]
    async fn nat_traversal_plus_dht_memory_is_invalid_config() {
        // NatTraversal publishes a routable (NAT-traversed) address; Memory (no
        // publish) is the same precise, loud M2 contradiction as Domain.
        let result = Node::start_for_testing(NodeConfig::defaults(
            Reach::NatTraversal,
            generate_identity(),
            InMemoryStorage::new(),
        ))
        .await;

        let err = match result {
            Err(NodeError::InvalidConfig(msg)) => msg,
            Err(other) => {
                panic!("expected InvalidConfig for NatTraversal + DhtMode::Memory, got: {other}")
            }
            Ok(node) => {
                node.shutdown();
                panic!("expected InvalidConfig for NatTraversal + DhtMode::Memory, got Ok");
            }
        };
        assert!(
            err.contains("Reach::NatTraversal") && err.contains("DhtMode::Memory"),
            "M2 error must name the contradiction, got: {err}"
        );
    }

    // --- Test 13: non-publishing reach + DhtMode::Memory is VALID -------------

    #[tokio::test]
    async fn tunnel_and_local_with_dht_memory_are_valid() {
        // Tunnel and Local publish a loopback URL (non-routable), so they are
        // NON-publishing reaches: `DhtMode::Memory` (the defaults' dht) is valid,
        // no M2 error. This is the positive companion to Tests 11/12 and the
        // explicit guard that Tests 5/6 (which use default Memory) keep building.
        let tunnel = Node::start_for_testing(NodeConfig {
            bind_addr: Some(SocketAddr::from(([127, 0, 0, 1], 0))),
            ..NodeConfig::defaults(
                Reach::Tunnel {
                    public_url: "https://tunnel-m2.example.com".to_owned(),
                },
                generate_identity(),
                InMemoryStorage::new(),
            )
        })
        .await
        .expect("Tunnel + DhtMode::Memory is a non-publishing reach and must be valid");
        assert!(tunnel.domain().is_none());
        tunnel.shutdown();

        let local = Node::start_for_testing(NodeConfig {
            bind_addr: Some(SocketAddr::from(([127, 0, 0, 1], 0))),
            ..NodeConfig::defaults(Reach::Local, generate_identity(), InMemoryStorage::new())
        })
        .await
        .expect("Local + DhtMode::Memory is a non-publishing reach and must be valid");
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
        // without panicking and the builder accepts them. Local is a
        // non-publishing reach, so DhtMode::Memory (the default) is valid.
        let node = Node::start_for_testing(NodeConfig {
            bind_addr: Some(SocketAddr::from(([127, 0, 0, 1], 0))),
            nat: NatSlot::Tuned {
                stun_server: Some("127.0.0.1:3478".to_owned()),
                bridge_relay: Some("wss://bridge.example.test/scp/v1".to_owned()),
                port_mapper: None,
                reachability_probe: None,
            },
            ..NodeConfig::defaults(Reach::Local, generate_identity(), InMemoryStorage::new())
        })
        .await
        .expect("NatSlot::Tuned overrides should lower and build offline on a Local reach");

        assert!(
            node.domain().is_none(),
            "Local should build a no-domain node even with NatSlot::Tuned overrides"
        );
        node.shutdown();
    }

    // --- Test 15: blob_storage Some overrides, None preserves the default -----

    #[tokio::test]
    async fn blob_storage_some_overrides_and_none_preserves_default() {
        // Some(...) overrides the builder's in-memory default; None preserves it
        // (the builder's `new()` sets `Some(BlobStorageBackend::default())`, so
        // the None path must NOT clear the relay's blob storage). Both paths
        // build on a Local (non-publishing) reach, which is the observable proof:
        // the None path did not break the build by clearing blob storage. We do
        // not assert the private backend value — only what is observable.
        let with_some = Node::start_for_testing(NodeConfig {
            bind_addr: Some(SocketAddr::from(([127, 0, 0, 1], 0))),
            blob_storage: Some(BlobStorageBackend::default()),
            ..NodeConfig::defaults(Reach::Local, generate_identity(), InMemoryStorage::new())
        })
        .await
        .expect("blob_storage: Some(default) should override and build");
        assert!(with_some.domain().is_none());
        with_some.shutdown();

        let with_none = Node::start_for_testing(NodeConfig {
            bind_addr: Some(SocketAddr::from(([127, 0, 0, 1], 0))),
            blob_storage: None,
            ..NodeConfig::defaults(Reach::Local, generate_identity(), InMemoryStorage::new())
        })
        .await
        .expect("blob_storage: None should preserve the builder default and build");
        assert!(with_none.domain().is_none());
        with_none.shutdown();
    }

    // --- Test 16: Persisted rejects mismatched custody through Node::start -----

    #[tokio::test]
    async fn persisted_rejects_mismatched_custody_through_node_start() {
        // First start persists the identity under custodyA. The second start
        // over the SAME storage but a fresh custodyB (no keys) must be rejected
        // by the builder's persisted-identity validation, surfaced through the
        // config-level entry point. Domain is a publishing reach → Production.
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

        // Domain is a publishing reach; M2 requires Production (advisory in P1 —
        // the TestDidDht uses an in-memory client, so nothing is published
        // offline). Domain + default SelfSigned builds offline (no network/CA).
        let node = Node::start(NodeConfig {
            bind_addr: Some(SocketAddr::from(([127, 0, 0, 1], 0))),
            dht: DhtMode::Production,
            ..NodeConfig::defaults(
                Reach::Domain {
                    domain: "config-prod-sqlite.example.com".to_owned(),
                },
                generate_identity(),
                Arc::clone(&storage),
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
        // must be a loud `InvalidConfig`, not a silent no-op. Local is a
        // non-publishing reach so the M2 DHT rule does NOT fire — this isolates
        // the Acme×Reach rejection. Validation runs before any build, so no NAT
        // strategy is needed.
        let result = Node::start_for_testing(NodeConfig {
            tls: TlsMode::Acme {
                email: Some("admin@example.com".to_owned()),
            },
            ..NodeConfig::defaults(Reach::Local, generate_identity(), InMemoryStorage::new())
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
                ..NodeConfig::defaults(reach, generate_identity(), InMemoryStorage::new())
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
        // contact email). It must be a VALID config on a `Reach::Domain`
        // (publishing) reach paired with `DhtMode::Production` — no loud error.
        // We assert at the `validate_config` layer rather than building, because
        // a real ACME provision would contact Let's Encrypt over the network;
        // validation is the observable acceptance gate before any provisioning.
        let reach = Reach::Domain {
            domain: "config-acme-headless.example.com".to_owned(),
        };
        let tls = TlsMode::Acme { email: None };
        validate_config(&reach, &tls, DhtMode::Production)
            .expect("Domain + Acme { email: None } + Production must be a valid config");
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
            ..NodeConfig::defaults(Reach::Local, generate_identity(), InMemoryStorage::new())
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
            ..NodeConfig::defaults(Reach::Local, generate_identity(), InMemoryStorage::new())
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
