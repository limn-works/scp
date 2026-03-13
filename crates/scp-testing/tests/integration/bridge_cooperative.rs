#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! B19: Bridge connectors and shadow identities.
//!
//! Integration tests for bridge connector construction, shadow identity
//! management, bridge provenance marking, trust level evaluation, and
//! native-vs-bridged action detection. Exercises the public API surface of
//! `scp_core::bridge` and `scp_core::bridge::provenance`.

use std::time::Duration;

use scp_core::bridge::provenance::{
    BridgeProvenance, BridgeTrustLevel, evaluate_bridge_trust_level, evaluate_trust_level,
    is_native_action, mark_bridge_provenance,
};
use scp_core::bridge::{
    BridgeConnector, BridgeMode, BridgeStatus, ShadowIdentity, ShadowProvenanceStatus,
};
use scp_core::context::MemoryScope;
use scp_core::provenance::{DataProvenance, DiscoveryMethod, SourceType};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_base_provenance() -> DataProvenance {
    DataProvenance {
        source_context: "ctx-bridge-integration".to_string(),
        source_type: SourceType::Persistent,
        counterparties: vec!["did:dht:z6MkAlice".into()],
        purpose: Some("bridged message".to_string()),
        discovery_method: DiscoveryMethod::SharedContext("ctx-shared".to_string()),
        age: Duration::from_secs(30),
        memory_scope: MemoryScope::Full,
        chain_depth: 0,
        chain_path: None,
        payment_amount: None,
        payment_adapter: None,
        payment_receipt_id: None,
    }
}

fn make_connector(platform: &str, mode: BridgeMode) -> BridgeConnector {
    BridgeConnector {
        bridge_id: "bridge-integ-001".to_string(),
        operator_did: "did:dht:z6MkOperator".into(),
        platform: platform.to_string(),
        mode,
        status: BridgeStatus::Active,
        registration_context: "ctx-reg".to_string(),
        registered_at: 1_700_000_000,
    }
}

fn make_shadow(status: ShadowProvenanceStatus) -> ShadowIdentity {
    ShadowIdentity {
        shadow_id: "shadow-integ-001".to_string(),
        platform_handle: "@testuser#1234".to_string(),
        bridge_id: "bridge-integ-001".to_string(),
        attributed_role: "observer".to_string(),
        provenance_status: status,
        created_at: 1_700_000_100,
    }
}

fn make_bridge_provenance(shadow_status: ShadowProvenanceStatus) -> BridgeProvenance {
    let base = make_base_provenance();
    let connector = make_connector("discord", BridgeMode::Relay);
    let shadow = make_shadow(shadow_status);
    mark_bridge_provenance(base, &connector, &shadow)
}

// ---------------------------------------------------------------------------
// 1. BridgeMode serialization roundtrip
// ---------------------------------------------------------------------------

#[tokio::test]
async fn bridge_mode_variants() {
    let modes = [
        BridgeMode::Relay,
        BridgeMode::Puppet,
        BridgeMode::Api,
        BridgeMode::Cooperative,
    ];

    for mode in &modes {
        let json = serde_json::to_string(mode).expect("serialize BridgeMode");
        let restored: BridgeMode = serde_json::from_str(&json).expect("deserialize BridgeMode");
        assert_eq!(&restored, mode, "roundtrip failed for {mode:?}");
    }

    // Verify all four variants are distinct
    for (i, a) in modes.iter().enumerate() {
        for (j, b) in modes.iter().enumerate() {
            if i == j {
                assert_eq!(a, b);
            } else {
                assert_ne!(a, b, "{a:?} should differ from {b:?}");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// 2. BridgeStatus transitions
// ---------------------------------------------------------------------------

#[tokio::test]
async fn bridge_status_transitions() {
    // Active -> Suspended -> Revoked
    let mut connector = make_connector("slack", BridgeMode::Api);
    assert_eq!(connector.status, BridgeStatus::Active);

    connector.status = BridgeStatus::Suspended;
    assert_eq!(connector.status, BridgeStatus::Suspended);

    connector.status = BridgeStatus::Revoked;
    assert_eq!(connector.status, BridgeStatus::Revoked);

    // Active -> Revoked (direct)
    let mut connector2 = make_connector("discord", BridgeMode::Relay);
    assert_eq!(connector2.status, BridgeStatus::Active);
    connector2.status = BridgeStatus::Revoked;
    assert_eq!(connector2.status, BridgeStatus::Revoked);

    // Serialization roundtrip for all status variants
    for status in [
        BridgeStatus::Active,
        BridgeStatus::Suspended,
        BridgeStatus::Revoked,
    ] {
        let json = serde_json::to_string(&status).expect("serialize BridgeStatus");
        let restored: BridgeStatus = serde_json::from_str(&json).expect("deserialize BridgeStatus");
        assert_eq!(restored, status);
    }
}

// ---------------------------------------------------------------------------
// 3. BridgeConnector construction
// ---------------------------------------------------------------------------

#[tokio::test]
async fn bridge_connector_construction() {
    let connector = BridgeConnector {
        bridge_id: "bridge-construct-001".to_string(),
        operator_did: "did:dht:z6MkOp".into(),
        platform: "discord".to_string(),
        mode: BridgeMode::Cooperative,
        status: BridgeStatus::Active,
        registration_context: "ctx-abc123".to_string(),
        registered_at: 1_700_000_000,
    };

    assert_eq!(connector.bridge_id, "bridge-construct-001");
    assert_eq!(connector.operator_did, "did:dht:z6MkOp");
    assert_eq!(connector.platform, "discord");
    assert_eq!(connector.mode, BridgeMode::Cooperative);
    assert_eq!(connector.status, BridgeStatus::Active);
    assert_eq!(connector.registration_context, "ctx-abc123");
    assert_eq!(connector.registered_at, 1_700_000_000);

    // Serialization roundtrip
    let json = serde_json::to_string(&connector).expect("serialize BridgeConnector");
    let restored: BridgeConnector =
        serde_json::from_str(&json).expect("deserialize BridgeConnector");
    assert_eq!(restored.bridge_id, connector.bridge_id);
    assert_eq!(restored.operator_did, connector.operator_did);
    assert_eq!(restored.platform, connector.platform);
    assert_eq!(restored.mode, connector.mode);
    assert_eq!(restored.status, connector.status);
    assert_eq!(
        restored.registration_context,
        connector.registration_context
    );
    assert_eq!(restored.registered_at, connector.registered_at);
}

// ---------------------------------------------------------------------------
// 4. ShadowIdentity construction
// ---------------------------------------------------------------------------

#[tokio::test]
async fn shadow_identity_construction() {
    let shadow = ShadowIdentity {
        shadow_id: "shadow-construct-001".to_string(),
        platform_handle: "@alice#5678".to_string(),
        bridge_id: "bridge-construct-001".to_string(),
        attributed_role: "observer".to_string(),
        provenance_status: ShadowProvenanceStatus::Shadow,
        created_at: 1_700_000_200,
    };

    assert_eq!(shadow.shadow_id, "shadow-construct-001");
    assert_eq!(shadow.platform_handle, "@alice#5678");
    assert_eq!(shadow.bridge_id, "bridge-construct-001");
    assert_eq!(shadow.attributed_role, "observer");
    assert_eq!(shadow.provenance_status, ShadowProvenanceStatus::Shadow);
    assert_eq!(shadow.created_at, 1_700_000_200);

    // Serialization roundtrip
    let json = serde_json::to_string(&shadow).expect("serialize ShadowIdentity");
    let restored: ShadowIdentity = serde_json::from_str(&json).expect("deserialize ShadowIdentity");
    assert_eq!(restored.shadow_id, shadow.shadow_id);
    assert_eq!(restored.platform_handle, shadow.platform_handle);
    assert_eq!(restored.bridge_id, shadow.bridge_id);
    assert_eq!(restored.attributed_role, shadow.attributed_role);
    assert_eq!(restored.provenance_status, shadow.provenance_status);
    assert_eq!(restored.created_at, shadow.created_at);
}

// ---------------------------------------------------------------------------
// 5. ShadowProvenanceStatus
// ---------------------------------------------------------------------------

#[tokio::test]
async fn shadow_provenance_status() {
    // Variants are distinct
    assert_ne!(
        ShadowProvenanceStatus::Shadow,
        ShadowProvenanceStatus::Claimed
    );
    assert_eq!(
        ShadowProvenanceStatus::Shadow,
        ShadowProvenanceStatus::Shadow
    );
    assert_eq!(
        ShadowProvenanceStatus::Claimed,
        ShadowProvenanceStatus::Claimed
    );

    // Serialization roundtrip
    for status in [
        ShadowProvenanceStatus::Shadow,
        ShadowProvenanceStatus::Claimed,
    ] {
        let json = serde_json::to_string(&status).expect("serialize ShadowProvenanceStatus");
        let restored: ShadowProvenanceStatus =
            serde_json::from_str(&json).expect("deserialize ShadowProvenanceStatus");
        assert_eq!(restored, status);
    }
}

// ---------------------------------------------------------------------------
// 6. Bridge provenance marking
// ---------------------------------------------------------------------------

#[tokio::test]
async fn bridge_provenance_marking() {
    let base = make_base_provenance();
    let source_ctx = base.source_context.clone();
    let connector = make_connector("slack", BridgeMode::Puppet);
    let shadow = make_shadow(ShadowProvenanceStatus::Shadow);

    let bp = mark_bridge_provenance(base, &connector, &shadow);

    // Base provenance fields preserved
    assert_eq!(bp.base.source_context, source_ctx);
    assert_eq!(bp.base.source_type, SourceType::Persistent);
    assert_eq!(bp.base.chain_depth, 0);

    // Bridge-specific fields populated from connector
    assert_eq!(bp.originating_platform, "slack");
    assert_eq!(bp.bridge_connector_id, "bridge-integ-001");
    assert_eq!(bp.operator_did, "did:dht:z6MkOperator");
    assert_eq!(bp.bridge_mode, BridgeMode::Puppet);

    // Shadow status populated from shadow identity
    assert_eq!(bp.shadow_status, ShadowProvenanceStatus::Shadow);

    // All four bridge modes produce valid provenance
    for mode in [
        BridgeMode::Relay,
        BridgeMode::Puppet,
        BridgeMode::Api,
        BridgeMode::Cooperative,
    ] {
        let base = make_base_provenance();
        let conn = make_connector("matrix", mode.clone());
        let shad = make_shadow(ShadowProvenanceStatus::Claimed);
        let bp = mark_bridge_provenance(base, &conn, &shad);
        assert_eq!(bp.bridge_mode, mode);
        assert_eq!(bp.shadow_status, ShadowProvenanceStatus::Claimed);
    }

    // Multiple platforms
    for platform in ["discord", "slack", "bluesky", "matrix", "telegram"] {
        let base = make_base_provenance();
        let conn = make_connector(platform, BridgeMode::Api);
        let shad = make_shadow(ShadowProvenanceStatus::Shadow);
        let bp = mark_bridge_provenance(base, &conn, &shad);
        assert_eq!(bp.originating_platform, platform);
    }
}

// ---------------------------------------------------------------------------
// 7. Bridge trust level evaluation
// ---------------------------------------------------------------------------

#[tokio::test]
async fn bridge_trust_level_evaluation() {
    // Unclaimed shadow -> ShadowBridged
    let shadow_bp = make_bridge_provenance(ShadowProvenanceStatus::Shadow);
    assert_eq!(
        evaluate_bridge_trust_level(&shadow_bp),
        BridgeTrustLevel::ShadowBridged
    );

    // Claimed shadow -> ClaimedBridged
    let claimed_bp = make_bridge_provenance(ShadowProvenanceStatus::Claimed);
    assert_eq!(
        evaluate_bridge_trust_level(&claimed_bp),
        BridgeTrustLevel::ClaimedBridged
    );

    // ClaimedBridged strictly higher than ShadowBridged
    assert!(evaluate_bridge_trust_level(&claimed_bp) > evaluate_bridge_trust_level(&shadow_bp));

    // General evaluate_trust_level delegates correctly for bridged content
    assert_eq!(
        evaluate_trust_level(Some(&shadow_bp), true),
        BridgeTrustLevel::ShadowBridged
    );
    assert_eq!(
        evaluate_trust_level(Some(&claimed_bp), false),
        BridgeTrustLevel::ClaimedBridged
    );

    // Native actions via evaluate_trust_level
    assert_eq!(
        evaluate_trust_level(None, true),
        BridgeTrustLevel::NativeNative
    );
    assert_eq!(
        evaluate_trust_level(None, false),
        BridgeTrustLevel::NativeBridged
    );

    // Transport flag ignored when bridge provenance is present
    assert_eq!(
        evaluate_trust_level(Some(&shadow_bp), true),
        evaluate_trust_level(Some(&shadow_bp), false),
    );
}

// ---------------------------------------------------------------------------
// 8. Trust level ordering
// ---------------------------------------------------------------------------

#[tokio::test]
async fn trust_level_ordering() {
    assert!(BridgeTrustLevel::ShadowBridged < BridgeTrustLevel::ClaimedBridged);
    assert!(BridgeTrustLevel::ClaimedBridged < BridgeTrustLevel::NativeBridged);
    assert!(BridgeTrustLevel::NativeBridged < BridgeTrustLevel::NativeNative);

    // Transitive: ShadowBridged < NativeNative
    assert!(BridgeTrustLevel::ShadowBridged < BridgeTrustLevel::NativeNative);

    // Sorting produces the expected order
    let mut levels = vec![
        BridgeTrustLevel::NativeNative,
        BridgeTrustLevel::ShadowBridged,
        BridgeTrustLevel::NativeBridged,
        BridgeTrustLevel::ClaimedBridged,
    ];
    levels.sort();
    assert_eq!(
        levels,
        vec![
            BridgeTrustLevel::ShadowBridged,
            BridgeTrustLevel::ClaimedBridged,
            BridgeTrustLevel::NativeBridged,
            BridgeTrustLevel::NativeNative,
        ]
    );

    // Self-equality
    assert_eq!(
        BridgeTrustLevel::ShadowBridged,
        BridgeTrustLevel::ShadowBridged
    );
    assert_eq!(
        BridgeTrustLevel::NativeNative,
        BridgeTrustLevel::NativeNative
    );

    // Serialization roundtrip for all trust levels
    for level in [
        BridgeTrustLevel::ShadowBridged,
        BridgeTrustLevel::ClaimedBridged,
        BridgeTrustLevel::NativeBridged,
        BridgeTrustLevel::NativeNative,
    ] {
        let json = serde_json::to_string(&level).expect("serialize BridgeTrustLevel");
        let restored: BridgeTrustLevel =
            serde_json::from_str(&json).expect("deserialize BridgeTrustLevel");
        assert_eq!(restored, level);
    }
}

// ---------------------------------------------------------------------------
// 9. Native action detection
// ---------------------------------------------------------------------------

#[tokio::test]
async fn native_action_detection() {
    // No bridge provenance -> native action
    assert!(is_native_action(None));

    // Any bridge provenance -> not native
    let shadow_bp = make_bridge_provenance(ShadowProvenanceStatus::Shadow);
    assert!(!is_native_action(Some(&shadow_bp)));

    let claimed_bp = make_bridge_provenance(ShadowProvenanceStatus::Claimed);
    assert!(!is_native_action(Some(&claimed_bp)));

    // ADR-023 AC 5: no shadow action mistakable for native SCP action
    for status in [
        ShadowProvenanceStatus::Shadow,
        ShadowProvenanceStatus::Claimed,
    ] {
        let bp = make_bridge_provenance(status);
        assert!(
            !is_native_action(Some(&bp)),
            "bridged action must never be mistaken for native"
        );
    }

    // Consistency with trust level: native action on native transport is strongest
    assert!(is_native_action(None));
    let level = evaluate_trust_level(None, true);
    assert_eq!(level, BridgeTrustLevel::NativeNative);

    // Native action on bridged transport is still native but lower trust
    assert!(is_native_action(None));
    let level = evaluate_trust_level(None, false);
    assert_eq!(level, BridgeTrustLevel::NativeBridged);
}

// ---------------------------------------------------------------------------
// 10. DataProvenance construction and roundtrip
// ---------------------------------------------------------------------------

#[tokio::test]
async fn data_provenance_construction() {
    let prov = DataProvenance {
        source_context: "ctx-data-prov".to_string(),
        source_type: SourceType::Persistent,
        counterparties: vec!["did:dht:z6MkAlice".into(), "did:dht:z6MkBob".into()],
        purpose: Some("test data flow".to_string()),
        discovery_method: DiscoveryMethod::SharedContext("ctx-discovery".to_string()),
        age: Duration::from_secs(60),
        memory_scope: MemoryScope::Full,
        chain_depth: 1,
        chain_path: Some(vec!["ctx-hop-1".to_string()]),
        payment_amount: None,
        payment_adapter: None,
        payment_receipt_id: None,
    };

    assert_eq!(prov.source_context, "ctx-data-prov");
    assert_eq!(prov.source_type, SourceType::Persistent);
    assert_eq!(prov.counterparties.len(), 2);
    assert_eq!(prov.purpose.as_deref(), Some("test data flow"));
    assert_eq!(prov.chain_depth, 1);
    assert_eq!(prov.chain_path.as_ref().map(Vec::len), Some(1));

    // Serialization roundtrip
    let json = serde_json::to_string(&prov).expect("serialize DataProvenance");
    let restored: DataProvenance = serde_json::from_str(&json).expect("deserialize DataProvenance");
    assert_eq!(restored.source_context, prov.source_context);
    assert_eq!(restored.source_type, prov.source_type);
    assert_eq!(restored.counterparties, prov.counterparties);
    assert_eq!(restored.purpose, prov.purpose);
    assert_eq!(restored.chain_depth, prov.chain_depth);
    assert_eq!(restored.chain_path, prov.chain_path);
    assert_eq!(restored.memory_scope, prov.memory_scope);
    assert_eq!(restored.age, prov.age);

    // All SourceType variants
    for st in [
        SourceType::Persistent,
        SourceType::Ephemeral,
        SourceType::Summary,
    ] {
        let json = serde_json::to_string(&st).expect("serialize SourceType");
        let restored: SourceType = serde_json::from_str(&json).expect("deserialize SourceType");
        assert_eq!(restored, st);
    }

    // All DiscoveryMethod variants
    let methods = [
        DiscoveryMethod::SharedContext("ctx-1".to_string()),
        DiscoveryMethod::Registry("ctx-reg".to_string()),
        DiscoveryMethod::OutOfBand,
    ];
    for method in &methods {
        let json = serde_json::to_string(method).expect("serialize DiscoveryMethod");
        let restored: DiscoveryMethod =
            serde_json::from_str(&json).expect("deserialize DiscoveryMethod");
        assert_eq!(&restored, method);
    }
}
