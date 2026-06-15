//! Flat-config-object construction surface for [`ApplicationNode`].
//!
//! This module implements the **ADR-051 Unified Construction Pattern** (Phase
//! B-P1) for the Node entry point. It introduces a single flat config object
//! ([`NodeConfig`]) plus a single zero-sized entry-point namespace ([`Node`])
//! exposing [`Node::start`] / [`Node::start_for_testing`], replacing the
//! LLM-hostile typestate builder surface with a shape an agent can author in
//! one pass from the type signature plus one example.
//!
//! See `.docs/standards/construction.md` (the enforced enactment of the
//! Agent-first API design builder tenet) and ADR-051 in
//! `.docs/adrs/phase-2.md`.
//!
//! ## Additive lowering
//!
//! Phase B-P1 is **additive**: [`Node::start`] lowers a [`NodeConfig`] onto the
//! existing [`ApplicationNodeBuilder`]. The typestate kernel and every existing
//! call site are untouched; this surface is the new front door that delegates to
//! the old machinery. Later phases migrate call sites and then delete the
//! typestate kernel (ADR-051 AC-3).

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

/// Zero-sized entry-point namespace for Node construction (ADR-051).
///
/// All node construction flows through [`Node::start`] (production,
/// `where S: EncryptedStorage`) or [`Node::start_for_testing`] (feature-gated,
/// any `Storage`). There is no `NodeBuilder`, no typestate, no `.build()`
/// terminator — the construction surface is one flat [`NodeConfig`] plus one
/// entry function.
pub struct Node;

// ---------------------------------------------------------------------------
// IdentitySource — how a node obtains its identity (ADR-051 §AC-3)
// ---------------------------------------------------------------------------

/// Specifies how a node obtains its identity.
///
/// This is the public, ADR-051-shaped reconciliation of the formerly private
/// `scp-node` `IdentitySource` enum (see the ADR-051 "Name reconciliation"
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
/// required field (ADR-051 M1).
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

/// How the node provisions TLS for its public listener (ADR-051 M1).
#[derive(Debug, Clone)]
pub enum TlsMode {
    /// Generate and serve a self-signed certificate for the reach's domain.
    /// This is the fail-safe production default for [`NodeConfig`] — no network,
    /// no CA, MLS still provides real confidentiality.
    SelfSigned,
    /// Provision a Let's Encrypt certificate via ACME for the reach's domain.
    Acme {
        /// Contact email for the ACME account registration.
        email: String,
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

/// NAT traversal strategy selection (ADR-051 capability slot).
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
// NodeConfig — the one flat config object (ADR-051 §AC-3)
// ---------------------------------------------------------------------------

/// Flat configuration object for constructing an [`ApplicationNode`] (ADR-051).
///
/// Every parameter is a named field. There is **no** whole-struct `Default`
/// (M4) because `reach`, `identity`, and `storage` are irreducible required
/// decisions — they are non-`Option` fields, so omitting them is a compile
/// error, not a silent `None`. Use [`NodeConfig::defaults`] for the spread
/// idiom:
///
/// ```ignore
/// let node = Node::start(NodeConfig {
///     reach: Reach::Domain { domain: "example.com".into() },
///     identity: IdentitySource::Generate { custody, did_method },
///     storage,
///     tls: TlsMode::Acme { email: "admin@example.com".into() },
///     ..NodeConfig::defaults(reach2, identity2, storage2)
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
    /// every other field with its **fail-safe** default (ADR-051 M4).
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
/// (ADR-051 M3 — fail loud, never silent).
fn validate_config(reach: &Reach, tls: &TlsMode) -> Result<(), NodeError> {
    if matches!(reach, Reach::Domain { .. }) && matches!(tls, TlsMode::Plaintext) {
        return Err(NodeError::InvalidConfig(
            "Reach::Domain with TlsMode::Plaintext is contradictory: a public domain reach \
             cannot serve plaintext. Choose TlsMode::SelfSigned or TlsMode::Acme."
                .to_owned(),
        ));
    }
    Ok(())
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
/// `SelfSigned` installs a [`SelfSignedTlsProvider`] only on a `Domain` reach
/// (non-domain builds skip TLS provisioning entirely). `Acme` sets the ACME
/// contact email. `Plaintext` (non-domain only — `Domain` + `Plaintext` already
/// errored in [`validate_config`]) and `Terminated` (TLS handled upstream) are
/// no-ops for the builder in P1.
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
        TlsMode::Acme { email } => builder.acme_email(&email),
        // Plaintext: only valid on non-domain reach (Domain+Plaintext errored
        // already); no-domain mode skips TLS, so this is a no-op.
        // Terminated: TLS terminated upstream (tunnel/proxy); no node-side TLS.
        // Both are builder no-ops in P1.
        TlsMode::Plaintext | TlsMode::Terminated => builder,
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

/// Applies the optional tail, addresses the builder per the reach, and finishes
/// with the production `build()` (`where S: EncryptedStorage`). The reach
/// addressing yields either `HasDomain` or `HasNoDomain` — both have `build()`.
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
        Reach::Tunnel { .. } | Reach::Local => b.no_domain().skip_nat_probe().build().await,
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
        Reach::Tunnel { .. } | Reach::Local => {
            b.no_domain().skip_nat_probe().build_for_testing().await
        }
    }
}

impl Node {
    /// Constructs and starts an [`ApplicationNode`] from a [`NodeConfig`]
    /// (production path).
    ///
    /// Requires `S: EncryptedStorage` — compile-time enforcement that the
    /// storage backend encrypts data at rest (the ADR-051 `EncryptedStorage`
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
        validate_config(&config.reach, &config.tls)?;
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

        // Storage first (requires NoOpStorage state), then identity (consuming
        // custody/did_method), then the tail. Each identity arm yields a
        // different concrete builder type, so each flows through `apply_tail`
        // independently and finishes with `build()`.
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
        validate_config(&config.reach, &config.tls)?;
        let NodeConfig {
            reach,
            identity,
            storage,
            tls,
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
        node.shutdown();
    }

    // --- Test 2: domain + Explicit preserves the supplied DID ----------------

    #[tokio::test]
    async fn domain_explicit_preserves_supplied_did() {
        let (identity, document, did_method, _custody) = create_explicit_identity().await;
        let expected_did = identity.did.clone();

        let node = Node::start_for_testing(NodeConfig {
            bind_addr: Some(SocketAddr::from(([127, 0, 0, 1], 0))),
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

    // --- Test 3: domain + Acme lowers to acme_email (offline fallthrough) -----

    #[tokio::test]
    async fn domain_acme_lowers_and_falls_through_offline() {
        // Acme has no real ACME server here, so TLS provisioning fails and
        // build_with_store falls through to no-domain mode. A MockNatStrategy
        // keeps that fallthrough offline (no real STUN). The ACME path drives
        // rustls, so install a process-level crypto provider first (matches the
        // pattern in the quic_listener / tls tests).
        let _ = rustls::crypto::ring::default_provider().install_default();
        let external_addr = SocketAddr::from(([198, 51, 100, 9], 41001));
        let node = Node::start_for_testing(NodeConfig {
            bind_addr: Some(SocketAddr::from(([127, 0, 0, 1], 0))),
            tls: TlsMode::Acme {
                email: "admin@example.com".to_owned(),
            },
            nat: NatSlot::Custom(Arc::new(MockNatStrategy {
                tier: ReachabilityTier::Stun { external_addr },
            })),
            ..NodeConfig::defaults(
                Reach::Domain {
                    domain: "config-acme.example.com".to_owned(),
                },
                generate_identity(),
                InMemoryStorage::new(),
            )
        })
        .await
        .unwrap();

        // Fallthrough to no-domain mode publishes a ws:// relay url.
        assert!(
            node.relay_url().starts_with("ws://"),
            "Acme fallthrough should land in no-domain mode (ws:// url), got: {}",
            node.relay_url()
        );
        node.shutdown();
    }

    // --- Test 4: NatTraversal -> no-domain -----------------------------------

    #[tokio::test]
    async fn nat_traversal_builds_no_domain() {
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
                email: "spread@example.com".to_owned(),
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
}
