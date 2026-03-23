//! Context metadata record types for SCP.
//!
//! Implements the `MetadataRecord` wire format per spec §5.7.2. Metadata
//! records are signed snapshots of a context's structural and operational
//! parameters, published to a deterministic routing address for pre-join
//! inspection by prospective members.
//!
//! The two-tier visibility model separates **structural** fields (always
//! visible — required for informed consent) from **operational** fields
//! (governed by `MetadataVisibilityPolicy`). See spec §5.7.

use serde::{Deserialize, Serialize};

use scp_primitives::DID;

use super::params::{
    CeilingPolicy, ContextMode, GovernanceModel, MemoryScope, MetadataVisibilityPolicy,
    PromotionPolicy, TemplateId,
};
use super::roles::{Capability, RoleDefinition};

// ---------------------------------------------------------------------------
// Type aliases (match codebase pattern)
// ---------------------------------------------------------------------------

/// A context identifier string.
pub type ContextId = String;

/// An Ed25519 signature (64 bytes).
pub type Ed25519Signature = Vec<u8>;

// ---------------------------------------------------------------------------
// MetadataRecord (§5.7.2)
// ---------------------------------------------------------------------------

/// A signed context metadata record published for pre-join inspection.
///
/// Metadata records are published to the context's metadata routing address
/// (`SHA-256(context_id || "scp-metadata")`, spec §5.7.1). They carry both
/// structural fields (always visible) and operational fields (filtered by
/// `MetadataVisibilityPolicy`).
///
/// Records are signed by a current context admin's Active Signing Key
/// (`#active`). Agent Signing Keys (`#agent`) MUST NOT sign metadata records.
///
/// The `sequence` field provides ordering: each metadata update increments the
/// sequence number monotonically from 1. Receivers MUST reject records with a
/// sequence number less than or equal to the last accepted record for the same
/// `context_id` to prevent replay.
///
/// See spec §5.7, §5.7.1, §5.7.2.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetadataRecord {
    /// The context this metadata describes.
    pub context_id: ContextId,
    /// Monotonically increasing sequence number, starting at 1.
    /// Used for ordering and replay protection.
    pub sequence: u64,
    /// DID of the admin who signed this metadata record.
    pub signer_did: DID,
    /// Unix timestamp (milliseconds) when this record was created.
    /// Informational — not used for ordering (sequence is authoritative).
    pub timestamp: u64,
    /// Structural metadata — always visible to prospective members.
    pub structural: StructuralMetadata,
    /// Operational metadata — filtered by `MetadataVisibilityPolicy`.
    /// Fields with `MemberOnly` visibility are omitted from public records.
    pub operational: OperationalMetadata,
    /// Ed25519 signature over all fields above, signed by the signer's
    /// Active Signing Key (`#active`).
    #[serde(with = "serde_bytes")]
    pub signature: Ed25519Signature,
}

// ---------------------------------------------------------------------------
// StructuralMetadata (§5.7 — always visible)
// ---------------------------------------------------------------------------

/// Structural metadata fields — always visible before joining.
///
/// These are the parameters a prospective member needs to evaluate whether
/// to join a context. Hiding them would undermine informed consent.
///
/// See spec §5.7.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StructuralMetadata {
    /// Template ID, if created from a well-known template (§5.12).
    pub template_id: Option<TemplateId>,
    /// Capability ceiling — the maximum set of things that can happen in
    /// this context (§5.3).
    pub ceiling: Vec<Capability>,
    /// Ceiling mutability policy: `Immutable` or `Governed` (§5.3).
    pub ceiling_policy: CeilingPolicy,
    /// Available roles and their permission sets (§5.5).
    pub roles: Vec<RoleDefinition>,
    /// Governance model for the context (§5.9).
    pub governance: GovernanceModel,
    /// Time-to-live, if set (§5.10). `None` for contexts without TTL.
    pub ttl: Option<u64>,
    /// Promotion policy — whether an ephemeral context can become
    /// persistent (§5.10). Only meaningful when `ttl` is `Some`.
    pub promotion_policy: PromotionPolicy,
    /// Memory scope — what happens to data on context close (§5.11).
    pub memory_scope: MemoryScope,
    /// Context mode: `Encrypted` or `Broadcast` (§5.14).
    pub mode: ContextMode,
    /// Per-field metadata visibility policy — tells prospective members
    /// which operational fields are hidden (§5.7).
    pub visibility_policy: MetadataVisibilityPolicy,
}

// ---------------------------------------------------------------------------
// OperationalMetadata (§5.7 — governed by visibility policy)
// ---------------------------------------------------------------------------

/// Operational metadata fields — visibility governed by
/// `MetadataVisibilityPolicy`.
///
/// Each field is `Option` because fields with `MemberOnly` visibility are
/// omitted from public metadata records. Members retrieve full operational
/// metadata through internal context state.
///
/// See spec §5.7.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OperationalMetadata {
    /// Current member count. Filtered by `visibility_policy.member_count`.
    pub member_count: Option<u64>,
    /// Context age in seconds since creation.
    /// Filtered by `visibility_policy.context_age`.
    pub context_age_secs: Option<u64>,
    /// DID of the context creator.
    /// Filtered by `visibility_policy.creator_identity`.
    pub creator_did: Option<DID>,
    /// Human-readable context name.
    /// Filtered by `visibility_policy.name`.
    pub name: Option<String>,
    /// Context description.
    /// Filtered by `visibility_policy.description`.
    pub description: Option<String>,
    /// Economic policy summary, if set (§19.3).
    /// Filtered by `visibility_policy.economic_policy`.
    pub economic_policy: Option<String>,
    /// Number of active tool interfaces (inbound + outbound, §6.2).
    /// Filtered by `visibility_policy.tool_interface_count`.
    pub tool_count: Option<u64>,
    /// Child context IDs, if this is a parent context (§5.13).
    /// Filtered by `visibility_policy.child_context_info`.
    pub child_contexts: Option<Vec<ContextId>>,
}

// Default derived — all fields are `Option<_>` and default to `None`.

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn make_structural() -> StructuralMetadata {
        StructuralMetadata {
            template_id: Some(TemplateId::BilateralEphemeral),
            ceiling: vec![Capability::MessagesRead, Capability::MessagesWrite],
            ceiling_policy: CeilingPolicy::Immutable,
            roles: Vec::new(),
            governance: GovernanceModel::SingleAdmin,
            ttl: Some(300),
            promotion_policy: PromotionPolicy::NoPromotion,
            memory_scope: MemoryScope::Ephemeral,
            mode: ContextMode::Encrypted,
            visibility_policy: MetadataVisibilityPolicy::default(),
        }
    }

    fn make_operational() -> OperationalMetadata {
        OperationalMetadata {
            member_count: Some(2),
            context_age_secs: Some(60),
            creator_did: Some(DID::from("did:dht:zAlice")),
            name: Some("Test Context".to_owned()),
            description: Some("A test context".to_owned()),
            economic_policy: None,
            tool_count: Some(0),
            child_contexts: None,
        }
    }

    fn make_record() -> MetadataRecord {
        MetadataRecord {
            context_id: "ctx-001".to_owned(),
            sequence: 1,
            signer_did: DID::from("did:dht:zAlice"),
            timestamp: 1_700_000_000_000,
            structural: make_structural(),
            operational: make_operational(),
            signature: vec![0u8; 64],
        }
    }

    #[test]
    fn metadata_record_serialization_roundtrip() {
        let record = make_record();
        let json = serde_json::to_string(&record).unwrap();
        let deserialized: MetadataRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.context_id, "ctx-001");
        assert_eq!(deserialized.sequence, 1);
        assert_eq!(deserialized.signer_did, DID::from("did:dht:zAlice"));
        assert_eq!(deserialized.timestamp, 1_700_000_000_000);
    }

    #[test]
    fn structural_metadata_serialization_roundtrip() {
        let structural = make_structural();
        let json = serde_json::to_string(&structural).unwrap();
        let deserialized: StructuralMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.ceiling.len(), 2);
        assert_eq!(deserialized.ceiling_policy, CeilingPolicy::Immutable);
        assert_eq!(deserialized.governance, GovernanceModel::SingleAdmin);
        assert_eq!(deserialized.ttl, Some(300));
        assert_eq!(deserialized.mode, ContextMode::Encrypted);
    }

    #[test]
    fn operational_metadata_default_is_all_none() {
        let op = OperationalMetadata::default();
        assert!(op.member_count.is_none());
        assert!(op.context_age_secs.is_none());
        assert!(op.creator_did.is_none());
        assert!(op.name.is_none());
        assert!(op.description.is_none());
        assert!(op.economic_policy.is_none());
        assert!(op.tool_count.is_none());
        assert!(op.child_contexts.is_none());
    }

    #[test]
    fn operational_metadata_serialization_roundtrip() {
        let operational = make_operational();
        let json = serde_json::to_string(&operational).unwrap();
        let deserialized: OperationalMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.member_count, Some(2));
        assert_eq!(deserialized.context_age_secs, Some(60));
        assert_eq!(deserialized.creator_did, Some(DID::from("did:dht:zAlice")));
        assert_eq!(deserialized.name.as_deref(), Some("Test Context"));
        assert_eq!(deserialized.tool_count, Some(0));
    }

    #[test]
    fn metadata_record_with_child_contexts() {
        let mut record = make_record();
        record.operational.child_contexts = Some(vec!["child-1".to_owned(), "child-2".to_owned()]);
        let json = serde_json::to_string(&record).unwrap();
        let deserialized: MetadataRecord = serde_json::from_str(&json).unwrap();
        let children = deserialized.operational.child_contexts.unwrap();
        assert_eq!(children.len(), 2);
        assert_eq!(children[0], "child-1");
    }

    #[test]
    fn metadata_record_sequence_starts_at_one() {
        let record = make_record();
        assert_eq!(record.sequence, 1, "sequence must start at 1 per spec");
    }
}
