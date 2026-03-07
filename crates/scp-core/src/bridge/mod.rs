//! Bridge connector protocol for SCP.
//!
//! Bridges are protocol entities (not agents) that translate between external
//! platforms and SCP. Each bridge has an accountable operator DID, operates in
//! one of four modes, and creates shadow identities for external platform
//! participants. All bridged content carries a full provenance chain.
//!
//! # Architecture
//!
//! - [`BridgeConnector`] -- A registered bridge instance bound to a context.
//! - [`BridgeMode`] -- One of four operating modes (Relay, Puppet, Api,
//!   Cooperative) determining integration depth.
//! - [`BridgeStatus`] -- Lifecycle state of a bridge (Active, Suspended,
//!   Revoked).
//! - [`ShadowIdentity`] -- Protocol-level representation of an external
//!   platform participant.
//! - [`ShadowProvenanceStatus`] -- Whether a shadow identity is unclaimed or
//!   has been bound to a DID via identity attestation.
//!
//! # Submodules
//!
//! - [`registration`] -- Bridge registration and governance approval.
//! - [`shadow`] -- Shadow identity creation and role management.
//! - [`claiming`] -- Shadow claiming via identity attestation.
//! - [`provenance`] -- Provenance marking for bridged content.
//! - [`credentials`] -- Bridge credential lifecycle (provision, retrieve,
//!   rotate, revoke, list).
//!
//! See ADR-023 in `.docs/adrs/phase-5.md`.

pub mod claiming;
pub mod credentials;
pub mod provenance;
pub mod registration;
pub mod shadow;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Type aliases for domain clarity
// ---------------------------------------------------------------------------

use scp_identity::DID;

/// A context identifier string.
///
/// Represented as a plain `String`. This matches the type alias pattern used
/// across `scp-core` modules (`event_log`, `discovery`).
pub type ContextId = String;

// ---------------------------------------------------------------------------
// BridgeMode
// ---------------------------------------------------------------------------

/// Operating mode of a bridge connector.
///
/// Each mode represents a different integration depth between the external
/// platform and SCP. The mode determines trust implications and is visible
/// in context metadata before opt-in (legibility tenet).
///
/// See ADR-023 in `.docs/adrs/phase-5.md`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BridgeMode {
    /// Read-only mirroring from external platform.
    ///
    /// The bridge observes external platform content and mirrors it into the
    /// SCP context. No actions flow from SCP back to the external platform.
    Relay,

    /// Bridge acts on behalf of external users.
    ///
    /// The bridge can perform actions in the SCP context as a proxy for
    /// external platform participants. Requires credential delegation.
    Puppet,

    /// Platform API integration.
    ///
    /// The bridge integrates with the external platform's API to provide
    /// bidirectional data flow without direct user impersonation.
    Api,

    /// Native SCP support on external platform.
    ///
    /// The external platform has native SCP integration, enabling the
    /// highest level of interoperability and trust.
    Cooperative,
}

// ---------------------------------------------------------------------------
// BridgeStatus
// ---------------------------------------------------------------------------

/// Lifecycle status of a bridge connector.
///
/// Bridge status is managed through context governance. A bridge starts as
/// [`Active`](BridgeStatus::Active) upon registration approval and can be
/// suspended or permanently revoked by governance action.
///
/// See ADR-023 in `.docs/adrs/phase-5.md`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BridgeStatus {
    /// The bridge is operational and actively translating between platforms.
    Active,

    /// The bridge is temporarily suspended. Shadow identities retain their
    /// attributed actions but cannot send or receive new messages.
    Suspended,

    /// The bridge has been permanently revoked by context governance.
    /// Shadow identities retain their attributed actions but the bridge
    /// is disconnected from the external platform.
    Revoked,
}

// ---------------------------------------------------------------------------
// BridgeConnector
// ---------------------------------------------------------------------------

/// A registered bridge connector bound to a specific SCP context.
///
/// Bridges are protocol entities that translate between external platforms
/// and SCP. Every bridge has an accountable operator whose DID is visible
/// in context metadata (human accountability tenet). A bridge in Context A
/// has zero access to Context B -- same platform bridged into two contexts
/// requires two separate bridge instances (context isolation tenet).
///
/// See ADR-023 in `.docs/adrs/phase-5.md`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeConnector {
    /// Unique identifier for this bridge instance.
    pub bridge_id: String,

    /// DID of the human operator accountable for this bridge.
    ///
    /// All bridged actions trace to this operator DID, satisfying the
    /// human accountability protocol tenet.
    pub operator_did: DID,

    /// Name of the external platform this bridge connects to (e.g.,
    /// `"discord"`, `"slack"`, `"bluesky"`).
    pub platform: String,

    /// Operating mode determining the integration depth.
    pub mode: BridgeMode,

    /// Current lifecycle status of the bridge.
    pub status: BridgeStatus,

    /// The context this bridge is registered in.
    ///
    /// A bridge is scoped to exactly one context. Cross-context bridging
    /// requires separate bridge registrations.
    pub registration_context: ContextId,

    /// Unix timestamp (seconds) when the bridge was registered.
    pub registered_at: u64,
}

// ---------------------------------------------------------------------------
// ShadowProvenanceStatus
// ---------------------------------------------------------------------------

/// Provenance status of a shadow identity.
///
/// Tracks whether an external platform participant's shadow identity has
/// been claimed (bound to a DID via identity attestation). Claiming is
/// one-way and irreversible -- once bound, a shadow cannot be unbound or
/// reassigned.
///
/// See ADR-023 in `.docs/adrs/phase-5.md`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ShadowProvenanceStatus {
    /// Unclaimed -- attributed via bridge. The shadow identity has not been
    /// bound to any DID.
    Shadow,

    /// Claimed -- bound to a DID via identity attestation (Spec section 3.5).
    /// Historical actions are retroattributed to the claimant DID.
    Claimed,
}

// ---------------------------------------------------------------------------
// ShadowIdentity
// ---------------------------------------------------------------------------

/// Protocol-level representation of an external platform participant.
///
/// Shadow identities give external platform participants protocol-level
/// representation with provenance, rather than attributing everything to
/// the bridge operator. Shadows are restricted by default (observer role)
/// to prevent capability escalation through bridges.
///
/// See ADR-023 in `.docs/adrs/phase-5.md`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShadowIdentity {
    /// Unique identifier for this shadow identity.
    pub shadow_id: String,

    /// The external platform handle (e.g., `"@user#1234"` on Discord).
    pub platform_handle: String,

    /// The bridge connector that created this shadow identity.
    pub bridge_id: String,

    /// The role attributed to this shadow identity within the context.
    ///
    /// Defaults to `"observer"` -- a restricted role that cannot exercise
    /// capabilities requiring verified identity. Upgradeable by context
    /// governance.
    pub attributed_role: String,

    /// Whether this shadow identity has been claimed (bound to a DID).
    pub provenance_status: ShadowProvenanceStatus,

    /// Unix timestamp (seconds) when the shadow identity was created.
    pub created_at: u64,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bridge_connector_construction_has_expected_fields() {
        let connector = BridgeConnector {
            bridge_id: "bridge-001".to_owned(),
            operator_did: "did:dht:z6MkTest".into(),
            platform: "discord".to_owned(),
            mode: BridgeMode::Relay,
            status: BridgeStatus::Active,
            registration_context: "ctx-abc123".to_owned(),
            registered_at: 1_700_000_000,
        };

        assert_eq!(connector.bridge_id, "bridge-001");
        assert_eq!(connector.operator_did, "did:dht:z6MkTest");
        assert_eq!(connector.platform, "discord");
        assert_eq!(connector.mode, BridgeMode::Relay);
        assert_eq!(connector.status, BridgeStatus::Active);
        assert_eq!(connector.registration_context, "ctx-abc123");
        assert_eq!(connector.registered_at, 1_700_000_000);
    }

    #[test]
    fn shadow_identity_construction_has_expected_fields() {
        let shadow = ShadowIdentity {
            shadow_id: "shadow-001".to_owned(),
            platform_handle: "@user#1234".to_owned(),
            bridge_id: "bridge-001".to_owned(),
            attributed_role: "observer".to_owned(),
            provenance_status: ShadowProvenanceStatus::Shadow,
            created_at: 1_700_000_000,
        };

        assert_eq!(shadow.shadow_id, "shadow-001");
        assert_eq!(shadow.platform_handle, "@user#1234");
        assert_eq!(shadow.bridge_id, "bridge-001");
        assert_eq!(shadow.attributed_role, "observer");
        assert_eq!(shadow.provenance_status, ShadowProvenanceStatus::Shadow);
        assert_eq!(shadow.created_at, 1_700_000_000);
    }

    #[test]
    fn bridge_mode_variants_are_distinct() {
        assert_ne!(BridgeMode::Relay, BridgeMode::Puppet);
        assert_ne!(BridgeMode::Puppet, BridgeMode::Api);
        assert_ne!(BridgeMode::Api, BridgeMode::Cooperative);
        assert_eq!(BridgeMode::Relay, BridgeMode::Relay);
    }

    #[test]
    fn bridge_status_variants_are_distinct() {
        assert_ne!(BridgeStatus::Active, BridgeStatus::Suspended);
        assert_ne!(BridgeStatus::Suspended, BridgeStatus::Revoked);
        assert_eq!(BridgeStatus::Active, BridgeStatus::Active);
    }

    #[test]
    fn shadow_provenance_status_variants_are_distinct() {
        assert_ne!(
            ShadowProvenanceStatus::Shadow,
            ShadowProvenanceStatus::Claimed
        );
        assert_eq!(
            ShadowProvenanceStatus::Shadow,
            ShadowProvenanceStatus::Shadow
        );
    }

    #[test]
    fn bridge_connector_serialization_roundtrip() {
        let connector = BridgeConnector {
            bridge_id: "bridge-002".to_owned(),
            operator_did: "did:dht:z6MkOp".into(),
            platform: "slack".to_owned(),
            mode: BridgeMode::Puppet,
            status: BridgeStatus::Suspended,
            registration_context: "ctx-def456".to_owned(),
            registered_at: 1_700_100_000,
        };

        let json = serde_json::to_string(&connector);
        assert!(json.is_ok());

        let deserialized: Result<BridgeConnector, _> =
            serde_json::from_str(json.as_deref().unwrap_or_default());
        assert!(deserialized.is_ok());

        let restored = deserialized.unwrap_or_else(|_| connector.clone());
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

    #[test]
    fn shadow_identity_serialization_roundtrip() {
        let shadow = ShadowIdentity {
            shadow_id: "shadow-002".to_owned(),
            platform_handle: "@alice".to_owned(),
            bridge_id: "bridge-002".to_owned(),
            attributed_role: "observer".to_owned(),
            provenance_status: ShadowProvenanceStatus::Claimed,
            created_at: 1_700_200_000,
        };

        let json = serde_json::to_string(&shadow);
        assert!(json.is_ok());

        let deserialized: Result<ShadowIdentity, _> =
            serde_json::from_str(json.as_deref().unwrap_or_default());
        assert!(deserialized.is_ok());

        let restored = deserialized.unwrap_or_else(|_| shadow.clone());
        assert_eq!(restored.shadow_id, shadow.shadow_id);
        assert_eq!(restored.platform_handle, shadow.platform_handle);
        assert_eq!(restored.bridge_id, shadow.bridge_id);
        assert_eq!(restored.attributed_role, shadow.attributed_role);
        assert_eq!(restored.provenance_status, shadow.provenance_status);
        assert_eq!(restored.created_at, shadow.created_at);
    }

    #[test]
    fn bridge_mode_serialization_roundtrip() {
        let modes = [
            BridgeMode::Relay,
            BridgeMode::Puppet,
            BridgeMode::Api,
            BridgeMode::Cooperative,
        ];

        for mode in &modes {
            let json = serde_json::to_string(mode);
            assert!(json.is_ok());

            let deserialized: Result<BridgeMode, _> =
                serde_json::from_str(json.as_deref().unwrap_or_default());
            assert!(deserialized.is_ok());
            assert_eq!(&deserialized.unwrap_or_else(|_| mode.clone()), mode);
        }
    }

    #[test]
    fn bridge_status_serialization_roundtrip() {
        let statuses = [
            BridgeStatus::Active,
            BridgeStatus::Suspended,
            BridgeStatus::Revoked,
        ];

        for status in &statuses {
            let json = serde_json::to_string(status);
            assert!(json.is_ok());

            let deserialized: Result<BridgeStatus, _> =
                serde_json::from_str(json.as_deref().unwrap_or_default());
            assert!(deserialized.is_ok());
            assert_eq!(&deserialized.unwrap_or_else(|_| status.clone()), status);
        }
    }

    #[test]
    fn shadow_provenance_status_serialization_roundtrip() {
        let statuses = [
            ShadowProvenanceStatus::Shadow,
            ShadowProvenanceStatus::Claimed,
        ];

        for status in &statuses {
            let json = serde_json::to_string(status);
            assert!(json.is_ok());

            let deserialized: Result<ShadowProvenanceStatus, _> =
                serde_json::from_str(json.as_deref().unwrap_or_default());
            assert!(deserialized.is_ok());
            assert_eq!(&deserialized.unwrap_or_else(|_| status.clone()), status);
        }
    }

    #[test]
    fn bridge_connector_clone_produces_independent_copy() {
        let original = BridgeConnector {
            bridge_id: "bridge-clone".to_owned(),
            operator_did: "did:dht:z6MkClone".into(),
            platform: "matrix".to_owned(),
            mode: BridgeMode::Cooperative,
            status: BridgeStatus::Active,
            registration_context: "ctx-clone".to_owned(),
            registered_at: 1_700_300_000,
        };

        let cloned = original.clone();
        assert_eq!(cloned.bridge_id, original.bridge_id);
        assert_eq!(cloned.mode, original.mode);
    }

    #[test]
    fn shadow_identity_clone_produces_independent_copy() {
        let original = ShadowIdentity {
            shadow_id: "shadow-clone".to_owned(),
            platform_handle: "@bob".to_owned(),
            bridge_id: "bridge-clone".to_owned(),
            attributed_role: "observer".to_owned(),
            provenance_status: ShadowProvenanceStatus::Shadow,
            created_at: 1_700_400_000,
        };

        let cloned = original.clone();
        assert_eq!(cloned.shadow_id, original.shadow_id);
        assert_eq!(cloned.provenance_status, original.provenance_status);
    }
}
