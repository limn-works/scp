#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! B10: `ApplicationNode` integration tests.
//!
//! Tests `ApplicationNodeBuilder` type-state pattern (domain mode, no-domain mode),
//! `SucceedingTlsProvider`, `FailingTlsProvider`, `MockNatStrategy`, `FailingNatStrategy`,
//! `create_test_identity`, and `ApplicationNode` accessors (relay, identity, storage, shutdown).

use scp_node::ReachabilityTier;
use scp_testing::helpers;

// ---------------------------------------------------------------------------
// Builder — domain mode
// ---------------------------------------------------------------------------

#[tokio::test]
async fn domain_mode_builder() {
    let node = helpers::test_builder()
        .build()
        .await
        .expect("domain-mode build should succeed");

    // Identity DID must be a did:dht identifier.
    assert!(
        node.identity().did().starts_with("did:dht:"),
        "DID should start with did:dht:, got: {}",
        node.identity().did()
    );

    // Relay must be bound to a valid address.
    let addr = node.relay().bound_addr();
    assert_ne!(addr.port(), 0, "relay must bind to a real port");

    node.shutdown();
}

// ---------------------------------------------------------------------------
// Builder — no-domain mode
// ---------------------------------------------------------------------------

#[tokio::test]
async fn no_domain_mode_builder() {
    let tier = ReachabilityTier::Bridge {
        bridge_url: "wss://bridge.example.com/scp/v1".to_owned(),
    };
    let node = helpers::test_no_domain_builder(tier)
        .build()
        .await
        .expect("no-domain-mode build should succeed");

    // No-domain mode nodes have no domain.
    assert!(
        node.domain().is_none(),
        "no-domain node should have domain() == None"
    );

    node.shutdown();
}

// ---------------------------------------------------------------------------
// Builder — failing TLS provider falls through to NAT mode (§10.12.8)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn failing_tls_falls_through_to_nat() {
    use std::sync::Arc;

    use scp_platform::testing::InMemoryStorage;

    let custody = Arc::new(scp_platform::testing::InMemoryKeyCustody::new());
    let did_method = Arc::new(helpers::make_test_dht(&custody));

    // TLS failure + no NAT strategy → build should fail because both paths fail.
    let result = scp_node::ApplicationNodeBuilder::new()
        .storage(InMemoryStorage::new())
        .domain("fail-tls.example.com")
        .tls_provider(Arc::new(helpers::FailingTlsProvider))
        .nat_strategy(Arc::new(helpers::FailingNatStrategy))
        .generate_identity_with(custody, did_method)
        .build()
        .await;

    match result {
        Ok(_) => panic!("build with both failing TLS and failing NAT should fail"),
        Err(err) => {
            let err_msg = err.to_string();
            assert!(
                err_msg.contains("NAT") || err_msg.contains("tier") || err_msg.contains("failed"),
                "error should mention failure, got: {err_msg}"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Builder — failing NAT strategy
// ---------------------------------------------------------------------------

#[tokio::test]
async fn failing_nat_strategy() {
    use std::sync::Arc;

    use scp_platform::testing::InMemoryStorage;

    let custody = Arc::new(scp_platform::testing::InMemoryKeyCustody::new());
    let did_method = Arc::new(helpers::make_test_dht(&custody));

    let result = scp_node::ApplicationNodeBuilder::new()
        .storage(InMemoryStorage::new())
        .no_domain()
        .nat_strategy(Arc::new(helpers::FailingNatStrategy))
        .generate_identity_with(custody, did_method)
        .build()
        .await;

    match result {
        Ok(_) => panic!("build with FailingNatStrategy should fail"),
        Err(err) => {
            let err_msg = err.to_string();
            assert!(
                err_msg.contains("NAT") || err_msg.contains("tier"),
                "error should mention NAT, got: {err_msg}"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// create_test_identity
// ---------------------------------------------------------------------------

#[tokio::test]
async fn create_test_identity() {
    let (identity, document, custody) = helpers::create_test_identity()
        .await
        .expect("create_test_identity should succeed");

    // DID should be a valid did:dht identifier.
    assert!(
        identity.did.starts_with("did:dht:"),
        "identity DID should start with did:dht:, got: {}",
        identity.did
    );

    // Document should contain the identity's DID.
    assert_eq!(
        document.id, identity.did,
        "document.id should match identity.did"
    );

    // Custody should be usable (Arc is not dangling).
    assert!(
        Arc::strong_count(&custody) >= 1,
        "custody Arc should have at least 1 strong reference"
    );
}

// ---------------------------------------------------------------------------
// Node relay URL
// ---------------------------------------------------------------------------

#[tokio::test]
async fn node_relay_url() {
    let node = helpers::test_builder()
        .build()
        .await
        .expect("domain-mode build should succeed");

    let relay_url = node.relay_url();
    assert!(
        relay_url.starts_with("wss://"),
        "domain-mode relay URL should start with wss://, got: {relay_url}"
    );

    node.shutdown();
}

// ---------------------------------------------------------------------------
// Node storage access
// ---------------------------------------------------------------------------

#[tokio::test]
async fn node_storage_access() {
    let node = helpers::test_builder()
        .build()
        .await
        .expect("domain-mode build should succeed");

    // storage() should return a reference without panicking.
    let _storage = node.storage();

    node.shutdown();
}

// ---------------------------------------------------------------------------
// Node shutdown
// ---------------------------------------------------------------------------

#[tokio::test]
async fn node_shutdown() {
    let node = helpers::test_builder()
        .build()
        .await
        .expect("domain-mode build should succeed");

    // shutdown() should complete without panicking or returning an error.
    node.shutdown();
}

// Bring Arc into scope for create_test_identity test.
use std::sync::Arc;
