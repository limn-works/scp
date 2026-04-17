//! Provenance marking for bridged content.
//!
//! All actions and content attributed to shadow identities carry
//! [`BridgeProvenance`] metadata extending [`DataProvenance`]. This includes
//! the originating platform, bridge connector ID, operator DID, operating
//! mode, and shadow/claimed status. No shadow action is mistakable for a
//! native SCP action.
//!
//! # Trust hierarchy (two axes per spec section 12.5)
//!
//! Trust evaluation considers both identity confidence and transport
//! confidence along two axes:
//!
//! - [`BridgeTrustLevel::NativeNative`] -- Native identity + native transport
//!   (strongest).
//! - [`BridgeTrustLevel::NativeBridged`] -- Native identity + bridged
//!   transport.
//! - [`BridgeTrustLevel::ClaimedBridged`] -- Claimed shadow + historical
//!   bridged.
//! - [`BridgeTrustLevel::ShadowBridged`] -- Shadow + bridged (weakest).
//!
//! See ADR-023 acceptance criteria 5-6 in `.docs/adrs/phase-5.md`.

use serde::{Deserialize, Serialize};

use super::{BridgeConnector, BridgeMode, DID, ShadowIdentity, ShadowProvenanceStatus};
use crate::provenance::DataProvenance;

// ---------------------------------------------------------------------------
// BridgeTrustLevel
// ---------------------------------------------------------------------------

/// Trust level for bridge-related actions (spec section 12.5).
///
/// The trust hierarchy considers two axes -- identity confidence and transport
/// confidence -- producing four ordered tiers from strongest to weakest.
///
/// Ordering: `NativeNative` (strongest) > `NativeBridged` > `ClaimedBridged`
/// > `ShadowBridged` (weakest).
///
/// See ADR-023 acceptance criterion 6.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BridgeTrustLevel {
    /// Shadow identity + bridged transport (weakest).
    ///
    /// The identity is unverified (attributed via bridge) and the transport
    /// is bridged. This is the lowest confidence tier.
    ShadowBridged = 0,

    /// Claimed shadow + historical bridged transport.
    ///
    /// The shadow identity has been claimed (bound to a DID via identity
    /// attestation), but the transport path is still bridged. Historical
    /// actions are retroattributed to the claimant DID.
    ClaimedBridged = 1,

    /// Native SCP identity + bridged transport.
    ///
    /// The actor has a verified SCP identity (DID) but the content was
    /// delivered through a bridge transport rather than a native SCP relay.
    NativeBridged = 2,

    /// Native SCP identity + native SCP transport (strongest).
    ///
    /// Both identity and transport are native to SCP. This is the highest
    /// confidence tier and represents fully native SCP participation.
    NativeNative = 3,
}

impl PartialOrd for BridgeTrustLevel {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for BridgeTrustLevel {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        (*self as u8).cmp(&(*other as u8))
    }
}

// ---------------------------------------------------------------------------
// BridgeProvenance
// ---------------------------------------------------------------------------

/// Extension of [`DataProvenance`] for bridged content (spec section 12,
/// ADR-023 acceptance criterion 5).
///
/// All actions and content attributed to shadow identities carry
/// `BridgeProvenance`. This struct includes the base provenance chain plus
/// bridge-specific fields that make bridged actions distinguishable from
/// native SCP actions.
///
/// # Fields
///
/// - `base` -- The underlying [`DataProvenance`] record.
/// - `originating_platform` -- Name of the external platform (e.g.,
///   `"discord"`, `"slack"`).
/// - `bridge_connector_id` -- Unique identifier of the bridge instance.
/// - `operator_did` -- DID of the human operator accountable for the bridge.
/// - `bridge_mode` -- Operating mode of the bridge at the time of the action.
/// - `shadow_status` -- Whether the shadow identity is unclaimed or claimed.
///
/// See ADR-023 acceptance criterion 5.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeProvenance {
    /// The underlying data provenance record.
    pub base: DataProvenance,

    /// Name of the external platform this content originated from (e.g.,
    /// `"discord"`, `"slack"`, `"bluesky"`).
    pub originating_platform: String,

    /// Unique identifier of the bridge connector instance that produced
    /// this content.
    pub bridge_connector_id: String,

    /// DID of the human operator accountable for the bridge. All bridged
    /// actions trace to this operator (human accountability tenet).
    pub operator_did: DID,

    /// Operating mode of the bridge at the time this content was produced.
    pub bridge_mode: BridgeMode,

    /// Whether the shadow identity was unclaimed or claimed at the time
    /// this content was produced.
    pub shadow_status: ShadowProvenanceStatus,
}

// ---------------------------------------------------------------------------
// mark_bridge_provenance
// ---------------------------------------------------------------------------

/// Creates a [`BridgeProvenance`] record from a bridge action.
///
/// Combines the base [`DataProvenance`] with bridge-specific metadata
/// extracted from the [`BridgeConnector`] and [`ShadowIdentity`] that
/// produced the action. The resulting provenance record makes the bridged
/// action fully distinguishable from native SCP actions.
///
/// # Arguments
///
/// - `base` -- The underlying data provenance record for this action.
/// - `connector` -- The bridge connector that produced this action.
/// - `shadow` -- The shadow identity attributed to this action.
///
/// See ADR-023 acceptance criterion 5.
#[must_use]
pub fn mark_bridge_provenance(
    base: DataProvenance,
    connector: &BridgeConnector,
    shadow: &ShadowIdentity,
) -> BridgeProvenance {
    BridgeProvenance {
        base,
        originating_platform: connector.platform.clone(),
        bridge_connector_id: connector.bridge_id.clone(),
        operator_did: connector.operator_did.clone(),
        bridge_mode: connector.mode.clone(),
        shadow_status: shadow.provenance_status.clone(),
    }
}

// ---------------------------------------------------------------------------
// evaluate_bridge_trust_level
// ---------------------------------------------------------------------------

/// Evaluates the trust level for a bridge-related action based on its
/// provenance.
///
/// The trust hierarchy considers two axes (spec section 12.5):
///
/// 1. **Identity confidence:** Is the actor a native SCP identity, a claimed
///    shadow, or an unclaimed shadow?
/// 2. **Transport confidence:** Was the content delivered via native SCP
///    transport or through a bridge?
///
/// Content with [`BridgeProvenance`] is always bridged transport. The
/// identity axis is determined by the `shadow_status` field.
///
/// # Returns
///
/// - [`BridgeTrustLevel::ClaimedBridged`] if the shadow identity has been
///   claimed (bound to a DID).
/// - [`BridgeTrustLevel::ShadowBridged`] if the shadow identity is
///   unclaimed.
///
/// Note: [`BridgeTrustLevel::NativeNative`] and
/// [`BridgeTrustLevel::NativeBridged`] are not returned by this function
/// because content with `BridgeProvenance` is, by definition, produced by
/// a shadow identity via a bridge. Use [`evaluate_trust_level`] for the
/// general case that handles both native and bridged actions.
///
/// See ADR-023 acceptance criterion 6.
#[must_use]
pub const fn evaluate_bridge_trust_level(provenance: &BridgeProvenance) -> BridgeTrustLevel {
    match provenance.shadow_status {
        ShadowProvenanceStatus::Claimed => BridgeTrustLevel::ClaimedBridged,
        ShadowProvenanceStatus::Shadow => BridgeTrustLevel::ShadowBridged,
    }
}

// ---------------------------------------------------------------------------
// evaluate_trust_level
// ---------------------------------------------------------------------------

/// Evaluates the trust level for any action, distinguishing between native
/// and bridged content.
///
/// This is the general-purpose trust evaluation that handles all four tiers
/// of the trust hierarchy (spec section 12.5). It examines whether bridge
/// provenance is present and, if so, the shadow status.
///
/// # Arguments
///
/// - `bridge_provenance` -- `None` for native SCP actions, `Some` for
///   bridged actions.
/// - `is_native_transport` -- Whether the transport is native SCP (true) or
///   bridged (false). Only meaningful when `bridge_provenance` is `None`.
///
/// # Returns
///
/// The appropriate [`BridgeTrustLevel`] tier based on both identity and
/// transport confidence axes.
///
/// See ADR-023 acceptance criterion 6.
#[must_use]
pub const fn evaluate_trust_level(
    bridge_provenance: Option<&BridgeProvenance>,
    is_native_transport: bool,
) -> BridgeTrustLevel {
    match bridge_provenance {
        Some(bp) => evaluate_bridge_trust_level(bp),
        None => {
            if is_native_transport {
                BridgeTrustLevel::NativeNative
            } else {
                BridgeTrustLevel::NativeBridged
            }
        }
    }
}

// ---------------------------------------------------------------------------
// is_native_action
// ---------------------------------------------------------------------------

/// Returns `true` if the action is a native SCP action (not bridged).
///
/// A native action has no [`BridgeProvenance`] -- it was performed by a
/// native SCP identity through native SCP transport. Any action carrying
/// `BridgeProvenance` is a bridged action, regardless of the shadow's
/// claimed status.
///
/// This function satisfies ADR-023 acceptance criterion 5: "No shadow action
/// mistakable for native SCP action."
///
/// # Arguments
///
/// - `bridge_provenance` -- `None` for native SCP actions, `Some` for
///   bridged actions.
#[must_use]
pub const fn is_native_action(bridge_provenance: Option<&BridgeProvenance>) -> bool {
    bridge_provenance.is_none()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::single_char_pattern
)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::bridge::{BridgeStatus, ContextId};
    use crate::context::MemoryScope;
    use crate::provenance::{DiscoveryMethod, SourceType};

    // -------------------------------------------------------------------
    // Test helpers
    // -------------------------------------------------------------------

    fn make_base_provenance() -> DataProvenance {
        DataProvenance {
            source_context: "ctx-bridge-test".to_string(),
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
            bridge_id: "bridge-test-001".to_string(),
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
            shadow_id: "shadow-test-001".to_string(),
            platform_handle: "@testuser#1234".to_string(),
            bridge_id: "bridge-test-001".to_string(),
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

    // -------------------------------------------------------------------
    // BridgeProvenance construction via mark_bridge_provenance
    // -------------------------------------------------------------------

    #[test]
    fn mark_bridge_provenance_copies_base_provenance_fields() {
        let base = make_base_provenance();
        let source_context = base.source_context.clone();
        let connector = make_connector("discord", BridgeMode::Relay);
        let shadow = make_shadow(ShadowProvenanceStatus::Shadow);

        let bp = mark_bridge_provenance(base, &connector, &shadow);

        assert_eq!(bp.base.source_context, source_context);
        assert_eq!(bp.base.source_type, SourceType::Persistent);
        assert_eq!(bp.base.chain_depth, 0);
    }

    #[test]
    fn mark_bridge_provenance_populates_originating_platform() {
        let bp = make_bridge_provenance(ShadowProvenanceStatus::Shadow);
        assert_eq!(bp.originating_platform, "discord");
    }

    #[test]
    fn mark_bridge_provenance_populates_bridge_connector_id() {
        let bp = make_bridge_provenance(ShadowProvenanceStatus::Shadow);
        assert_eq!(bp.bridge_connector_id, "bridge-test-001");
    }

    #[test]
    fn mark_bridge_provenance_populates_operator_did() {
        let bp = make_bridge_provenance(ShadowProvenanceStatus::Shadow);
        assert_eq!(bp.operator_did, "did:dht:z6MkOperator");
    }

    #[test]
    fn mark_bridge_provenance_populates_bridge_mode() {
        let bp = make_bridge_provenance(ShadowProvenanceStatus::Shadow);
        assert_eq!(bp.bridge_mode, BridgeMode::Relay);
    }

    #[test]
    fn mark_bridge_provenance_populates_shadow_status_unclaimed() {
        let bp = make_bridge_provenance(ShadowProvenanceStatus::Shadow);
        assert_eq!(bp.shadow_status, ShadowProvenanceStatus::Shadow);
    }

    #[test]
    fn mark_bridge_provenance_populates_shadow_status_claimed() {
        let bp = make_bridge_provenance(ShadowProvenanceStatus::Claimed);
        assert_eq!(bp.shadow_status, ShadowProvenanceStatus::Claimed);
    }

    #[test]
    fn mark_bridge_provenance_with_different_platforms() {
        for platform in ["discord", "slack", "bluesky", "matrix"] {
            let base = make_base_provenance();
            let connector = make_connector(platform, BridgeMode::Api);
            let shadow = make_shadow(ShadowProvenanceStatus::Shadow);
            let bp = mark_bridge_provenance(base, &connector, &shadow);
            assert_eq!(bp.originating_platform, platform);
        }
    }

    #[test]
    fn mark_bridge_provenance_with_all_bridge_modes() {
        let modes = [
            BridgeMode::Relay,
            BridgeMode::Puppet,
            BridgeMode::Api,
            BridgeMode::Cooperative,
        ];

        for mode in &modes {
            let base = make_base_provenance();
            let connector = make_connector("discord", mode.clone());
            let shadow = make_shadow(ShadowProvenanceStatus::Shadow);
            let bp = mark_bridge_provenance(base, &connector, &shadow);
            assert_eq!(bp.bridge_mode, *mode);
        }
    }

    // -------------------------------------------------------------------
    // BridgeTrustLevel ordering
    // -------------------------------------------------------------------

    #[test]
    fn trust_level_shadow_bridged_is_weakest() {
        assert!(BridgeTrustLevel::ShadowBridged < BridgeTrustLevel::ClaimedBridged);
        assert!(BridgeTrustLevel::ShadowBridged < BridgeTrustLevel::NativeBridged);
        assert!(BridgeTrustLevel::ShadowBridged < BridgeTrustLevel::NativeNative);
    }

    #[test]
    fn trust_level_claimed_bridged_is_second_weakest() {
        assert!(BridgeTrustLevel::ClaimedBridged > BridgeTrustLevel::ShadowBridged);
        assert!(BridgeTrustLevel::ClaimedBridged < BridgeTrustLevel::NativeBridged);
        assert!(BridgeTrustLevel::ClaimedBridged < BridgeTrustLevel::NativeNative);
    }

    #[test]
    fn trust_level_native_bridged_is_second_strongest() {
        assert!(BridgeTrustLevel::NativeBridged > BridgeTrustLevel::ShadowBridged);
        assert!(BridgeTrustLevel::NativeBridged > BridgeTrustLevel::ClaimedBridged);
        assert!(BridgeTrustLevel::NativeBridged < BridgeTrustLevel::NativeNative);
    }

    #[test]
    fn trust_level_native_native_is_strongest() {
        assert!(BridgeTrustLevel::NativeNative > BridgeTrustLevel::ShadowBridged);
        assert!(BridgeTrustLevel::NativeNative > BridgeTrustLevel::ClaimedBridged);
        assert!(BridgeTrustLevel::NativeNative > BridgeTrustLevel::NativeBridged);
    }

    #[test]
    fn trust_level_full_ordering_via_sort() {
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
    }

    #[test]
    fn trust_level_equality() {
        assert_eq!(
            BridgeTrustLevel::ShadowBridged,
            BridgeTrustLevel::ShadowBridged
        );
        assert_eq!(
            BridgeTrustLevel::ClaimedBridged,
            BridgeTrustLevel::ClaimedBridged
        );
        assert_eq!(
            BridgeTrustLevel::NativeBridged,
            BridgeTrustLevel::NativeBridged
        );
        assert_eq!(
            BridgeTrustLevel::NativeNative,
            BridgeTrustLevel::NativeNative
        );
    }

    // -------------------------------------------------------------------
    // evaluate_bridge_trust_level
    // -------------------------------------------------------------------

    #[test]
    fn evaluate_bridge_trust_level_returns_shadow_bridged_for_unclaimed() {
        let bp = make_bridge_provenance(ShadowProvenanceStatus::Shadow);
        let level = evaluate_bridge_trust_level(&bp);
        assert_eq!(level, BridgeTrustLevel::ShadowBridged);
    }

    #[test]
    fn evaluate_bridge_trust_level_returns_claimed_bridged_for_claimed() {
        let bp = make_bridge_provenance(ShadowProvenanceStatus::Claimed);
        let level = evaluate_bridge_trust_level(&bp);
        assert_eq!(level, BridgeTrustLevel::ClaimedBridged);
    }

    #[test]
    fn evaluate_bridge_trust_level_claimed_is_higher_than_shadow() {
        let shadow_bp = make_bridge_provenance(ShadowProvenanceStatus::Shadow);
        let claimed_bp = make_bridge_provenance(ShadowProvenanceStatus::Claimed);

        let shadow_level = evaluate_bridge_trust_level(&shadow_bp);
        let claimed_level = evaluate_bridge_trust_level(&claimed_bp);

        assert!(claimed_level > shadow_level);
    }

    // -------------------------------------------------------------------
    // evaluate_trust_level (general)
    // -------------------------------------------------------------------

    #[test]
    fn evaluate_trust_level_returns_native_native_for_native_action_native_transport() {
        let level = evaluate_trust_level(None, true);
        assert_eq!(level, BridgeTrustLevel::NativeNative);
    }

    #[test]
    fn evaluate_trust_level_returns_native_bridged_for_native_action_bridged_transport() {
        let level = evaluate_trust_level(None, false);
        assert_eq!(level, BridgeTrustLevel::NativeBridged);
    }

    #[test]
    fn evaluate_trust_level_returns_shadow_bridged_for_bridged_unclaimed() {
        let bp = make_bridge_provenance(ShadowProvenanceStatus::Shadow);
        let level = evaluate_trust_level(Some(&bp), true);
        assert_eq!(level, BridgeTrustLevel::ShadowBridged);
    }

    #[test]
    fn evaluate_trust_level_returns_claimed_bridged_for_bridged_claimed() {
        let bp = make_bridge_provenance(ShadowProvenanceStatus::Claimed);
        let level = evaluate_trust_level(Some(&bp), true);
        assert_eq!(level, BridgeTrustLevel::ClaimedBridged);
    }

    #[test]
    fn evaluate_trust_level_ignores_transport_flag_when_bridge_provenance_present() {
        let bp = make_bridge_provenance(ShadowProvenanceStatus::Shadow);

        // Transport flag should not matter when bridge provenance is present
        let level_native = evaluate_trust_level(Some(&bp), true);
        let level_bridged = evaluate_trust_level(Some(&bp), false);
        assert_eq!(level_native, level_bridged);
        assert_eq!(level_native, BridgeTrustLevel::ShadowBridged);
    }

    #[test]
    fn evaluate_trust_level_all_four_tiers_correctly_ordered() {
        let shadow_bp = make_bridge_provenance(ShadowProvenanceStatus::Shadow);
        let claimed_bp = make_bridge_provenance(ShadowProvenanceStatus::Claimed);

        let shadow_bridged = evaluate_trust_level(Some(&shadow_bp), false);
        let claimed_bridged = evaluate_trust_level(Some(&claimed_bp), false);
        let native_bridged = evaluate_trust_level(None, false);
        let native_native = evaluate_trust_level(None, true);

        assert!(shadow_bridged < claimed_bridged);
        assert!(claimed_bridged < native_bridged);
        assert!(native_bridged < native_native);
    }

    // -------------------------------------------------------------------
    // is_native_action
    // -------------------------------------------------------------------

    #[test]
    fn is_native_action_returns_true_when_no_bridge_provenance() {
        assert!(is_native_action(None));
    }

    #[test]
    fn is_native_action_returns_false_for_bridged_shadow() {
        let bp = make_bridge_provenance(ShadowProvenanceStatus::Shadow);
        assert!(!is_native_action(Some(&bp)));
    }

    #[test]
    fn is_native_action_returns_false_for_bridged_claimed() {
        let bp = make_bridge_provenance(ShadowProvenanceStatus::Claimed);
        assert!(!is_native_action(Some(&bp)));
    }

    #[test]
    fn is_native_action_no_shadow_action_mistakable_for_native() {
        // ADR-023 AC 5: "No shadow action mistakable for native SCP action."
        // Any action with BridgeProvenance must NOT be native.
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
    }

    // -------------------------------------------------------------------
    // Serialization roundtrip
    // -------------------------------------------------------------------

    #[test]
    fn bridge_provenance_serialization_roundtrip() {
        let bp = make_bridge_provenance(ShadowProvenanceStatus::Shadow);

        let json = serde_json::to_string(&bp);
        assert!(json.is_ok(), "serialization should succeed");

        let deserialized: Result<BridgeProvenance, _> =
            serde_json::from_str(json.as_ref().map_or("", String::as_str));
        assert!(deserialized.is_ok(), "deserialization should succeed");

        let restored = deserialized.unwrap();
        assert_eq!(restored.originating_platform, bp.originating_platform);
        assert_eq!(restored.bridge_connector_id, bp.bridge_connector_id);
        assert_eq!(restored.operator_did, bp.operator_did);
        assert_eq!(restored.bridge_mode, bp.bridge_mode);
        assert_eq!(restored.shadow_status, bp.shadow_status);
        assert_eq!(restored.base.source_context, bp.base.source_context);
    }

    #[test]
    fn bridge_trust_level_serialization_roundtrip() {
        let levels = [
            BridgeTrustLevel::ShadowBridged,
            BridgeTrustLevel::ClaimedBridged,
            BridgeTrustLevel::NativeBridged,
            BridgeTrustLevel::NativeNative,
        ];

        for level in &levels {
            let json = serde_json::to_string(level);
            assert!(json.is_ok(), "serialization of {level:?} should succeed");

            let deserialized: Result<BridgeTrustLevel, _> =
                serde_json::from_str(json.as_ref().map_or("", String::as_str));
            assert!(
                deserialized.is_ok(),
                "deserialization of {level:?} should succeed"
            );
            assert_eq!(&deserialized.unwrap(), level);
        }
    }

    // -------------------------------------------------------------------
    // BridgeProvenance clone
    // -------------------------------------------------------------------

    #[test]
    fn bridge_provenance_clone_produces_independent_copy() {
        let original = make_bridge_provenance(ShadowProvenanceStatus::Claimed);
        let cloned = original.clone();

        assert_eq!(cloned.originating_platform, original.originating_platform);
        assert_eq!(cloned.bridge_connector_id, original.bridge_connector_id);
        assert_eq!(cloned.operator_did, original.operator_did);
        assert_eq!(cloned.bridge_mode, original.bridge_mode);
        assert_eq!(cloned.shadow_status, original.shadow_status);
    }

    // -------------------------------------------------------------------
    // Integration: trust level and native action consistency
    // -------------------------------------------------------------------

    #[test]
    fn native_action_has_highest_trust_on_native_transport() {
        // A native action on native transport should be the strongest tier
        assert!(is_native_action(None));
        let level = evaluate_trust_level(None, true);
        assert_eq!(level, BridgeTrustLevel::NativeNative);

        // It should be strictly greater than all bridged levels
        let shadow_bp = make_bridge_provenance(ShadowProvenanceStatus::Shadow);
        let claimed_bp = make_bridge_provenance(ShadowProvenanceStatus::Claimed);
        assert!(level > evaluate_trust_level(Some(&shadow_bp), false));
        assert!(level > evaluate_trust_level(Some(&claimed_bp), false));
        assert!(level > evaluate_trust_level(None, false));
    }

    #[test]
    fn bridged_action_is_never_native() {
        // Verify the invariant: if BridgeProvenance exists, is_native_action is
        // false and the trust level is one of the two bridged tiers
        for status in [
            ShadowProvenanceStatus::Shadow,
            ShadowProvenanceStatus::Claimed,
        ] {
            let bp = make_bridge_provenance(status.clone());
            assert!(!is_native_action(Some(&bp)));

            let level = evaluate_trust_level(Some(&bp), true);
            assert!(
                level == BridgeTrustLevel::ShadowBridged
                    || level == BridgeTrustLevel::ClaimedBridged,
                "bridged action trust level must be ShadowBridged or ClaimedBridged, got {level:?}"
            );
        }
    }

    // -------------------------------------------------------------------
    // Edge case: unused ContextId alias (compile check)
    // -------------------------------------------------------------------

    #[test]
    fn context_id_alias_is_string() {
        let _ctx: ContextId = "ctx-test".to_string();
    }
}
