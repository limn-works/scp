//! Shared test helpers for integration tests.
//!
//! Replicates test doubles that are private to `scp-node`'s `#[cfg(test)]`
//! module, making them available to cross-crate integration tests in
//! `scp-testing`.
//!
//! # Provided helpers
//!
//! - [`SucceedingTlsProvider`] — mock TLS provider returning self-signed certs
//! - [`FailingTlsProvider`] — mock TLS provider that always fails
//! - [`MockNatStrategy`] — returns a pre-configured [`ReachabilityTier`]
//! - [`FailingNatStrategy`] — NAT strategy that always fails
//! - [`make_test_dht`] — creates a `DidDht` with in-memory DHT client
//! - [`test_builder`] — fully-configured domain-mode `ApplicationNodeBuilder`
//! - [`test_no_domain_builder`] — no-domain mode builder with mock NAT
//! - [`create_test_identity`] — creates a test `ScpIdentity` + `DidDocument`

#![forbid(unsafe_code)]

use std::sync::Arc;

use scp_identity::cache::SystemClock;
use scp_identity::dht::DidDht;
use scp_identity::dht_client::InMemoryDhtClient;
use scp_identity::{DidDocument, ScpIdentity};
use scp_node::tls;
use scp_node::{
    ApplicationNodeBuilder, DhtMode, HasDomain, HasIdentity, HasNoDomain, IdentitySource, NatSlot,
    NatStrategy, NodeConfig, NodeError, Reach, ReachabilityTier, TlsProvider,
};
use scp_platform::testing::{InMemoryKeyCustody, InMemoryStorage};

/// The concrete `DidDht` type used in tests (in-memory DHT, system clock).
pub type TestDidDht = DidDht<InMemoryDhtClient, SystemClock>;

/// Creates a [`DidDht`] instance with in-memory DHT and signing capability.
///
/// The signing function is derived from the provided custody, enabling
/// `create()` and `publish()` operations in tests.
pub fn make_test_dht(custody: &Arc<InMemoryKeyCustody>) -> TestDidDht {
    DidDht::with_in_memory_custody(Arc::clone(custody))
}

/// Mock TLS provider that succeeds with a self-signed certificate.
///
/// Use this for domain-mode [`ApplicationNodeBuilder`] tests where actual
/// ACME provisioning is not needed.
pub struct SucceedingTlsProvider {
    /// The domain name for the self-signed certificate.
    pub domain: String,
}

impl TlsProvider for SucceedingTlsProvider {
    fn provision(
        &self,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<tls::CertificateData, tls::TlsError>>
                + Send
                + '_,
        >,
    > {
        let domain = self.domain.clone();
        Box::pin(async move { tls::generate_self_signed(&domain) })
    }
}

/// Mock TLS provider that always fails (simulates ACME failure).
pub struct FailingTlsProvider;

impl TlsProvider for FailingTlsProvider {
    fn provision(
        &self,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<tls::CertificateData, tls::TlsError>>
                + Send
                + '_,
        >,
    > {
        Box::pin(async {
            Err(tls::TlsError::Acme(
                "ACME challenge failed (mock)".to_owned(),
            ))
        })
    }
}

/// Mock NAT strategy that returns a pre-configured [`ReachabilityTier`].
pub struct MockNatStrategy {
    /// The tier to return from [`NatStrategy::select_tier`].
    pub tier: ReachabilityTier,
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

/// Mock NAT strategy that always fails.
pub struct FailingNatStrategy;

impl NatStrategy for FailingNatStrategy {
    fn select_tier(
        &self,
        _relay_port: u16,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<ReachabilityTier, NodeError>> + Send + '_>,
    > {
        Box::pin(async { Err(NodeError::Nat("all tiers failed".into())) })
    }
}

/// Creates a domain-mode [`ApplicationNodeBuilder`] with all required fields set.
///
/// Uses [`SucceedingTlsProvider`] and in-memory backends, suitable for most
/// integration tests that need a running `ApplicationNode`.
#[must_use]
pub fn test_builder()
-> ApplicationNodeBuilder<InMemoryKeyCustody, TestDidDht, InMemoryStorage, HasDomain, HasIdentity> {
    let custody = Arc::new(InMemoryKeyCustody::new());
    let did_method = Arc::new(make_test_dht(&custody));
    ApplicationNodeBuilder::new()
        .storage(InMemoryStorage::new())
        .domain("test.example.com")
        .tls_provider(Arc::new(SucceedingTlsProvider {
            domain: "test.example.com".to_owned(),
        }))
        .generate_identity_with(custody, did_method)
}

/// Creates a no-domain [`ApplicationNodeBuilder`] with mock NAT strategy.
///
/// The provided [`ReachabilityTier`] determines how the node advertises
/// itself (`UPnP`, STUN, or Bridge).
#[must_use]
pub fn test_no_domain_builder(
    tier: ReachabilityTier,
) -> ApplicationNodeBuilder<InMemoryKeyCustody, TestDidDht, InMemoryStorage, HasNoDomain, HasIdentity>
{
    let custody = Arc::new(InMemoryKeyCustody::new());
    let did_method = Arc::new(make_test_dht(&custody));
    ApplicationNodeBuilder::new()
        .storage(InMemoryStorage::new())
        .no_domain()
        .nat_strategy(Arc::new(MockNatStrategy { tier }))
        .generate_identity_with(custody, did_method)
}

/// Creates a domain-mode [`NodeConfig`] with all required fields set
/// (ADR-052 flat-config equivalent of [`test_builder`]).
///
/// Uses in-memory backends and the default `TlsMode::SelfSigned` (the same
/// self-signed certificate [`SucceedingTlsProvider`] produces on a `Domain`
/// reach). `Domain` is a publishing reach, so `DhtMode::Production` satisfies
/// the M2 validator (advisory — nothing is published with the in-memory DHT
/// client). Drive it with `Node::start_for_testing(test_node_config()).await`.
#[must_use]
pub fn test_node_config() -> NodeConfig<InMemoryKeyCustody, TestDidDht, InMemoryStorage> {
    let custody = Arc::new(InMemoryKeyCustody::new());
    let did_method = Arc::new(make_test_dht(&custody));
    NodeConfig {
        dht: DhtMode::Production,
        ..NodeConfig::defaults(
            Reach::Domain {
                domain: "test.example.com".to_owned(),
            },
            IdentitySource::Generate {
                custody,
                did_method,
            },
            InMemoryStorage::new(),
        )
    }
}

/// Creates a no-domain [`NodeConfig`] with a mock NAT strategy (ADR-052
/// flat-config equivalent of [`test_no_domain_builder`]).
///
/// The provided [`ReachabilityTier`] determines how the node advertises itself
/// (`UPnP`, STUN, or Bridge), supplied via `NatSlot::Custom`. `NatTraversal` is
/// a publishing reach, so `DhtMode::Production` satisfies the M2 validator.
/// Drive it with `Node::start_for_testing(test_no_domain_node_config(tier))`.
#[must_use]
pub fn test_no_domain_node_config(
    tier: ReachabilityTier,
) -> NodeConfig<InMemoryKeyCustody, TestDidDht, InMemoryStorage> {
    let custody = Arc::new(InMemoryKeyCustody::new());
    let did_method = Arc::new(make_test_dht(&custody));
    NodeConfig {
        dht: DhtMode::Production,
        nat: NatSlot::Custom(Arc::new(MockNatStrategy { tier })),
        ..NodeConfig::defaults(
            Reach::NatTraversal,
            IdentitySource::Generate {
                custody,
                did_method,
            },
            InMemoryStorage::new(),
        )
    }
}

/// Creates a test [`ScpIdentity`] and [`DidDocument`] using in-memory custody
/// and DHT.
///
/// Returns `(identity, document, custody)` for further test usage.
///
/// # Errors
///
/// Returns an error if identity creation fails (should not happen with
/// in-memory backends).
pub async fn create_test_identity()
-> Result<(ScpIdentity, DidDocument, Arc<InMemoryKeyCustody>), Box<dyn std::error::Error>> {
    let (identity, document, custody, _did_dht) = DidDht::create_in_memory().await?;
    Ok((identity, document, custody))
}
