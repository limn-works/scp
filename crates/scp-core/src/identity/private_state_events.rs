//! Exhaustive private state event types (spec §3.7.1.1).
//!
//! The identity private state event log is an append-only, encrypted log of
//! all private state mutations for an identity. This module defines the
//! unified [`IdentityPrivateStateEvent`] enum covering all 25 event types
//! across 9 categories:
//!
//! 1. **Block/Mute** (8 events) — global and per-context block/mute/unblock/unmute.
//! 2. **Graph visibility** (3 events) — default visibility, per-DID grants/revokes.
//! 3. **Agent configuration** (2 events) — key-value agent preferences.
//! 4. **Annotation** (2 events) — personal notes on DIDs.
//! 5. **Petname** (2 events) — user-chosen names for DIDs or contexts (§22.4).
//! 6. **Notification** (1 event) — per-scope notification preferences.
//! 7. **Attestation draft** (3 events) — draft attestation lifecycle.
//! 8. **Device registry** (2 events) — device enrollment/unenrollment.
//! 9. **Recovery contact** (2 events) — recovery contact management.
//!
//! Block/unblock events (4 variants) are also defined in
//! [`super::block_list::BlockListEvent`] for the specialized block list state
//! machine. This module provides the unified type used in the private state
//! event log itself — the block list module provides the derived state.
//!
//! **Conflict resolution (§3.7.1.1):** For non-commutative events (same
//! key/target modified from multiple devices), resolution is
//! last-timestamp-wins with tie-breaking by lexicographic comparison of the
//! event hash.
//!
//! See spec §3.7.1.1, §3.7 (private state architecture).

use std::borrow::Cow;

use scp_identity::DID;
use serde::{Deserialize, Serialize};

use super::attestation::IdentityLinkAttestation;

// ---------------------------------------------------------------------------
// Supporting types
// ---------------------------------------------------------------------------

/// Graph visibility level for an identity's social graph (§3.7.1.1).
///
/// Controls who can see the identity's connections (contexts, contacts).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum GraphVisibility {
    /// Graph is visible to anyone who resolves the identity's DID.
    Public,
    /// Graph is visible only to contacts (DIDs the identity has interacted
    /// with in shared contexts).
    Contacts,
    /// Graph is not visible to anyone. The identity's connections are fully
    /// private.
    Private,
}

/// Scope of a graph visibility grant (§3.7.1.1).
///
/// Specifies what portion of the graph is visible to the granted DID.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum VisibilityScope {
    /// Full graph — all contexts and contacts.
    Full,
    /// Contacts only — the list of DIDs the identity has interacted with.
    ContactsOnly,
    /// Contexts only — the list of contexts the identity is a member of.
    ContextsOnly,
}

/// Scope for notification preferences (§3.7.1.1).
///
/// Notifications can be configured globally, per-context, or per-DID.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum NotificationScope {
    /// Global notification preference — applies to all contexts and DIDs
    /// unless overridden by a more specific scope.
    Global,
    /// Per-context notification preference.
    PerContext(String),
    /// Per-DID notification preference.
    PerDID(DID),
}

/// Notification level (§3.7.1.1).
///
/// Controls the verbosity/urgency of notifications for a given scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum NotificationLevel {
    /// All notifications delivered.
    All,
    /// Only mentions and direct messages.
    MentionsOnly,
    /// Only direct messages.
    DirectOnly,
    /// No notifications (fully silenced).
    None,
}

/// Target for petname assignment (§22.4, §3.7.1.1).
///
/// Petnames can be assigned to either DIDs or context IDs.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PetnameTarget {
    /// A DID (person or agent).
    Did(DID),
    /// A context identifier.
    Context(String),
}

// ---------------------------------------------------------------------------
// IdentityPrivateStateEvent (§3.7.1.1)
// ---------------------------------------------------------------------------

/// A unified event in the identity private state event log (§3.7.1.1).
///
/// All 25 event types across 9 categories. This enum is the type stored in
/// the encrypted private state event log. The block/mute variants mirror
/// [`super::block_list::BlockListEvent`] — the block list module provides
/// derived state from replaying these events.
///
/// **Serialization:** `MessagePack` (§17) with serde tagging. All timestamps
/// are Unix milliseconds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum IdentityPrivateStateEvent {
    // -------------------------------------------------------------------
    // Block/Mute events (8)
    // -------------------------------------------------------------------
    /// Block a DID globally (Tier 2, cross-context). See §9.16.3.
    BlockDID {
        /// The DID being blocked.
        target_did: DID,
        /// Unix timestamp (milliseconds).
        timestamp: u64,
    },

    /// Unblock a DID globally. See §9.16.8.
    UnblockDID {
        /// The DID being unblocked.
        target_did: DID,
        /// Unix timestamp (milliseconds).
        timestamp: u64,
    },

    /// Block a DID in a specific context (Tier 1).
    BlockDIDInContext {
        /// The DID being blocked.
        target_did: DID,
        /// The context in which the block applies.
        context_id: String,
        /// Unix timestamp (milliseconds).
        timestamp: u64,
    },

    /// Unblock a DID in a specific context.
    UnblockDIDInContext {
        /// The DID being unblocked.
        target_did: DID,
        /// The context from which the block is removed.
        context_id: String,
        /// Unix timestamp (milliseconds).
        timestamp: u64,
    },

    /// Mute a DID globally (suppresses notifications, does NOT affect access).
    MuteDID {
        /// The DID being muted.
        target_did: DID,
        /// Unix timestamp (milliseconds).
        timestamp: u64,
    },

    /// Unmute a DID globally.
    UnmuteDID {
        /// The DID being unmuted.
        target_did: DID,
        /// Unix timestamp (milliseconds).
        timestamp: u64,
    },

    /// Mute a DID in a specific context.
    MuteDIDInContext {
        /// The DID being muted.
        target_did: DID,
        /// The context in which the mute applies.
        context_id: String,
        /// Unix timestamp (milliseconds).
        timestamp: u64,
    },

    /// Unmute a DID in a specific context.
    UnmuteDIDInContext {
        /// The DID being unmuted.
        target_did: DID,
        /// The context from which the mute is removed.
        context_id: String,
        /// Unix timestamp (milliseconds).
        timestamp: u64,
    },

    // -------------------------------------------------------------------
    // Graph visibility events (3)
    // -------------------------------------------------------------------
    /// Set the default graph visibility for all DIDs.
    ///
    /// Non-commutative for same-scope mutations; resolved by last-timestamp-wins.
    SetDefaultGraphVisibility {
        /// The new default visibility level.
        visibility: GraphVisibility,
        /// Unix timestamp (milliseconds).
        timestamp: u64,
    },

    /// Grant graph visibility to a specific DID (per-DID override).
    ///
    /// Commutative for different targets.
    GrantGraphVisibility {
        /// The DID being granted visibility.
        target_did: DID,
        /// What portion of the graph is visible.
        scope: VisibilityScope,
        /// Unix timestamp (milliseconds).
        timestamp: u64,
    },

    /// Revoke a per-DID graph visibility override.
    ///
    /// After revocation, the default visibility applies to this DID.
    /// Commutative for different targets.
    RevokeGraphVisibility {
        /// The DID whose visibility override is being revoked.
        target_did: DID,
        /// Unix timestamp (milliseconds).
        timestamp: u64,
    },

    // -------------------------------------------------------------------
    // Agent configuration events (2)
    // -------------------------------------------------------------------
    /// Set a key-value agent configuration preference.
    ///
    /// Non-commutative for the same key; resolved by last-timestamp-wins.
    SetAgentConfig {
        /// Configuration key.
        key: String,
        /// Configuration value (MessagePack-encoded arbitrary value).
        #[serde(with = "serde_bytes")]
        value: Vec<u8>,
        /// Unix timestamp (milliseconds).
        timestamp: u64,
    },

    /// Delete an agent configuration preference.
    ///
    /// Non-commutative for the same key; resolved by last-timestamp-wins.
    DeleteAgentConfig {
        /// Configuration key to delete.
        key: String,
        /// Unix timestamp (milliseconds).
        timestamp: u64,
    },

    // -------------------------------------------------------------------
    // Annotation events (2)
    // -------------------------------------------------------------------
    /// Set a personal annotation (note) on a DID.
    ///
    /// Non-commutative for the same (target, key) pair; resolved by
    /// last-timestamp-wins.
    SetAnnotation {
        /// The DID being annotated.
        target_did: DID,
        /// Annotation key (e.g., "note", "`trust_level`", "tags").
        key: String,
        /// Annotation value.
        value: String,
        /// Unix timestamp (milliseconds).
        timestamp: u64,
    },

    /// Delete a personal annotation on a DID.
    ///
    /// Non-commutative for the same (target, key) pair; resolved by
    /// last-timestamp-wins.
    DeleteAnnotation {
        /// The DID whose annotation is being deleted.
        target_did: DID,
        /// Annotation key to delete.
        key: String,
        /// Unix timestamp (milliseconds).
        timestamp: u64,
    },

    // -------------------------------------------------------------------
    // Petname events (2) — §22.4
    // -------------------------------------------------------------------
    /// Set a petname (user-chosen label) for a DID or context.
    ///
    /// Non-commutative for the same target; resolved by last-timestamp-wins.
    SetPetname {
        /// The target being named (DID or context).
        target: PetnameTarget,
        /// The user-chosen name.
        name: String,
        /// Unix timestamp (milliseconds).
        timestamp: u64,
    },

    /// Delete a petname for a DID or context.
    ///
    /// Non-commutative for the same target; resolved by last-timestamp-wins.
    DeletePetname {
        /// The target whose petname is being deleted.
        target: PetnameTarget,
        /// Unix timestamp (milliseconds).
        timestamp: u64,
    },

    // -------------------------------------------------------------------
    // Notification events (1)
    // -------------------------------------------------------------------
    /// Set a notification preference for a given scope.
    ///
    /// Non-commutative for the same scope; resolved by last-timestamp-wins.
    SetNotificationPreference {
        /// The scope this preference applies to.
        scope: NotificationScope,
        /// The notification level.
        level: NotificationLevel,
        /// Unix timestamp (milliseconds).
        timestamp: u64,
    },

    // -------------------------------------------------------------------
    // Attestation draft events (3)
    // -------------------------------------------------------------------
    /// Save a draft identity link attestation (not yet published).
    ///
    /// Commutative for different draft IDs.
    SaveDraftAttestation {
        /// Unique draft identifier.
        draft_id: String,
        /// The draft attestation.
        attestation: Box<IdentityLinkAttestation>,
        /// Unix timestamp (milliseconds).
        timestamp: u64,
    },

    /// Delete a draft attestation.
    ///
    /// Commutative for different draft IDs.
    DeleteDraftAttestation {
        /// Draft identifier to delete.
        draft_id: String,
        /// Unix timestamp (milliseconds).
        timestamp: u64,
    },

    /// Mark a draft attestation as published.
    ///
    /// After publication, the draft is removed from the draft store and
    /// the attestation is published to the identity's DID document or
    /// attestation registry.
    ///
    /// Commutative for different draft IDs.
    PublishDraftAttestation {
        /// Draft identifier being published.
        draft_id: String,
        /// Unix timestamp (milliseconds).
        timestamp: u64,
    },

    // -------------------------------------------------------------------
    // Device registry events (2)
    // -------------------------------------------------------------------
    /// Enroll a new device in the identity's device registry.
    ///
    /// The device's X25519 public key is used for HPKE-wrapped PSK
    /// distribution (§3.7.2).
    ///
    /// Commutative for different device IDs.
    EnrollDevice {
        /// Unique device identifier.
        device_id: String,
        /// Device's X25519 public key (32 bytes) for HPKE key wrapping.
        #[serde(with = "serde_bytes")]
        device_x25519_pubkey: Vec<u8>,
        /// Human-readable device name (e.g., "iPhone 15", "`MacBook` Pro").
        device_name: String,
        /// Unix timestamp (milliseconds) when the device was enrolled.
        enrolled_at: u64,
    },

    /// Remove a device from the identity's device registry.
    ///
    /// After unenrollment, the device no longer receives PSK updates and
    /// cannot decrypt new private state events.
    ///
    /// Commutative for different device IDs.
    UnenrollDevice {
        /// Device identifier to unenroll.
        device_id: String,
        /// Unix timestamp (milliseconds).
        timestamp: u64,
    },

    // -------------------------------------------------------------------
    // Recovery contact events (2)
    // -------------------------------------------------------------------
    /// Designate a DID as a recovery contact.
    ///
    /// Recovery contacts can assist with identity recovery procedures.
    /// Commutative for different contact DIDs.
    AddRecoveryContact {
        /// The DID being designated as a recovery contact.
        contact_did: DID,
        /// Unix timestamp (milliseconds).
        timestamp: u64,
    },

    /// Remove a DID from recovery contacts.
    ///
    /// Commutative for different contact DIDs.
    RemoveRecoveryContact {
        /// The DID being removed from recovery contacts.
        contact_did: DID,
        /// Unix timestamp (milliseconds).
        timestamp: u64,
    },
}

impl IdentityPrivateStateEvent {
    /// Returns a human-readable event type name for logging and diagnostics.
    #[must_use]
    pub const fn event_type_name(&self) -> &'static str {
        match self {
            Self::BlockDID { .. } => "BlockDID",
            Self::UnblockDID { .. } => "UnblockDID",
            Self::BlockDIDInContext { .. } => "BlockDIDInContext",
            Self::UnblockDIDInContext { .. } => "UnblockDIDInContext",
            Self::MuteDID { .. } => "MuteDID",
            Self::UnmuteDID { .. } => "UnmuteDID",
            Self::MuteDIDInContext { .. } => "MuteDIDInContext",
            Self::UnmuteDIDInContext { .. } => "UnmuteDIDInContext",
            Self::SetDefaultGraphVisibility { .. } => "SetDefaultGraphVisibility",
            Self::GrantGraphVisibility { .. } => "GrantGraphVisibility",
            Self::RevokeGraphVisibility { .. } => "RevokeGraphVisibility",
            Self::SetAgentConfig { .. } => "SetAgentConfig",
            Self::DeleteAgentConfig { .. } => "DeleteAgentConfig",
            Self::SetAnnotation { .. } => "SetAnnotation",
            Self::DeleteAnnotation { .. } => "DeleteAnnotation",
            Self::SetPetname { .. } => "SetPetname",
            Self::DeletePetname { .. } => "DeletePetname",
            Self::SetNotificationPreference { .. } => "SetNotificationPreference",
            Self::SaveDraftAttestation { .. } => "SaveDraftAttestation",
            Self::DeleteDraftAttestation { .. } => "DeleteDraftAttestation",
            Self::PublishDraftAttestation { .. } => "PublishDraftAttestation",
            Self::EnrollDevice { .. } => "EnrollDevice",
            Self::UnenrollDevice { .. } => "UnenrollDevice",
            Self::AddRecoveryContact { .. } => "AddRecoveryContact",
            Self::RemoveRecoveryContact { .. } => "RemoveRecoveryContact",
        }
    }

    /// Returns the timestamp of this event in Unix milliseconds.
    #[must_use]
    pub const fn timestamp(&self) -> u64 {
        match self {
            Self::BlockDID { timestamp, .. }
            | Self::UnblockDID { timestamp, .. }
            | Self::BlockDIDInContext { timestamp, .. }
            | Self::UnblockDIDInContext { timestamp, .. }
            | Self::MuteDID { timestamp, .. }
            | Self::UnmuteDID { timestamp, .. }
            | Self::MuteDIDInContext { timestamp, .. }
            | Self::UnmuteDIDInContext { timestamp, .. }
            | Self::SetDefaultGraphVisibility { timestamp, .. }
            | Self::GrantGraphVisibility { timestamp, .. }
            | Self::RevokeGraphVisibility { timestamp, .. }
            | Self::SetAgentConfig { timestamp, .. }
            | Self::DeleteAgentConfig { timestamp, .. }
            | Self::SetAnnotation { timestamp, .. }
            | Self::DeleteAnnotation { timestamp, .. }
            | Self::SetPetname { timestamp, .. }
            | Self::DeletePetname { timestamp, .. }
            | Self::SetNotificationPreference { timestamp, .. }
            | Self::SaveDraftAttestation { timestamp, .. }
            | Self::DeleteDraftAttestation { timestamp, .. }
            | Self::PublishDraftAttestation { timestamp, .. }
            | Self::UnenrollDevice { timestamp, .. }
            | Self::AddRecoveryContact { timestamp, .. }
            | Self::RemoveRecoveryContact { timestamp, .. } => *timestamp,
            Self::EnrollDevice { enrolled_at, .. } => *enrolled_at,
        }
    }

    /// Returns a human-readable category for this event type.
    #[must_use]
    pub const fn category(&self) -> Cow<'static, str> {
        match self {
            Self::BlockDID { .. }
            | Self::UnblockDID { .. }
            | Self::BlockDIDInContext { .. }
            | Self::UnblockDIDInContext { .. }
            | Self::MuteDID { .. }
            | Self::UnmuteDID { .. }
            | Self::MuteDIDInContext { .. }
            | Self::UnmuteDIDInContext { .. } => Cow::Borrowed("block_mute"),
            Self::SetDefaultGraphVisibility { .. }
            | Self::GrantGraphVisibility { .. }
            | Self::RevokeGraphVisibility { .. } => Cow::Borrowed("graph_visibility"),
            Self::SetAgentConfig { .. } | Self::DeleteAgentConfig { .. } => {
                Cow::Borrowed("agent_config")
            }
            Self::SetAnnotation { .. } | Self::DeleteAnnotation { .. } => {
                Cow::Borrowed("annotation")
            }
            Self::SetPetname { .. } | Self::DeletePetname { .. } => Cow::Borrowed("petname"),
            Self::SetNotificationPreference { .. } => Cow::Borrowed("notification"),
            Self::SaveDraftAttestation { .. }
            | Self::DeleteDraftAttestation { .. }
            | Self::PublishDraftAttestation { .. } => Cow::Borrowed("attestation_draft"),
            Self::EnrollDevice { .. } | Self::UnenrollDevice { .. } => {
                Cow::Borrowed("device_registry")
            }
            Self::AddRecoveryContact { .. } | Self::RemoveRecoveryContact { .. } => {
                Cow::Borrowed("recovery_contact")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn did(s: &str) -> DID {
        DID::from(s)
    }

    // -----------------------------------------------------------------------
    // Event type count verification
    // -----------------------------------------------------------------------

    #[test]
    fn all_25_event_types_have_names() {
        // Construct one of each variant and verify event_type_name returns
        // a non-empty string for each.
        let events = make_all_events();
        assert_eq!(events.len(), 25, "expected 25 enum variants");
        for event in &events {
            assert!(
                !event.event_type_name().is_empty(),
                "event_type_name must be non-empty for {event:?}"
            );
        }
    }

    #[test]
    fn all_events_have_timestamps() {
        let events = make_all_events();
        for event in &events {
            assert!(event.timestamp() > 0, "timestamp must be > 0 for {event:?}");
        }
    }

    #[test]
    fn all_events_have_categories() {
        let events = make_all_events();
        let expected_categories: Vec<&str> = vec![
            "block_mute",
            "graph_visibility",
            "agent_config",
            "annotation",
            "petname",
            "notification",
            "attestation_draft",
            "device_registry",
            "recovery_contact",
        ];
        let mut found_categories: Vec<String> =
            events.iter().map(|e| e.category().to_string()).collect();
        found_categories.sort();
        found_categories.dedup();
        for expected in &expected_categories {
            assert!(
                found_categories.iter().any(|c| c == expected),
                "expected category {expected} not found in {found_categories:?}"
            );
        }
    }

    // -----------------------------------------------------------------------
    // Serialization round-trips
    // -----------------------------------------------------------------------

    #[test]
    fn block_mute_events_json_roundtrip() {
        let events = vec![
            IdentityPrivateStateEvent::BlockDID {
                target_did: did("did:dht:z6MkA"),
                timestamp: 1000,
            },
            IdentityPrivateStateEvent::UnblockDID {
                target_did: did("did:dht:z6MkA"),
                timestamp: 2000,
            },
            IdentityPrivateStateEvent::MuteDID {
                target_did: did("did:dht:z6MkB"),
                timestamp: 3000,
            },
            IdentityPrivateStateEvent::UnmuteDID {
                target_did: did("did:dht:z6MkB"),
                timestamp: 4000,
            },
            IdentityPrivateStateEvent::MuteDIDInContext {
                target_did: did("did:dht:z6MkC"),
                context_id: "ctx-1".to_owned(),
                timestamp: 5000,
            },
            IdentityPrivateStateEvent::UnmuteDIDInContext {
                target_did: did("did:dht:z6MkC"),
                context_id: "ctx-1".to_owned(),
                timestamp: 6000,
            },
        ];
        let json = serde_json::to_string(&events).unwrap();
        let decoded: Vec<IdentityPrivateStateEvent> = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, events);
    }

    #[test]
    fn graph_visibility_events_json_roundtrip() {
        let events = vec![
            IdentityPrivateStateEvent::SetDefaultGraphVisibility {
                visibility: GraphVisibility::Contacts,
                timestamp: 1000,
            },
            IdentityPrivateStateEvent::GrantGraphVisibility {
                target_did: did("did:dht:z6MkA"),
                scope: VisibilityScope::Full,
                timestamp: 2000,
            },
            IdentityPrivateStateEvent::RevokeGraphVisibility {
                target_did: did("did:dht:z6MkA"),
                timestamp: 3000,
            },
        ];
        let json = serde_json::to_string(&events).unwrap();
        let decoded: Vec<IdentityPrivateStateEvent> = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, events);
    }

    #[test]
    fn agent_config_events_json_roundtrip() {
        let events = vec![
            IdentityPrivateStateEvent::SetAgentConfig {
                key: "language".to_owned(),
                value: rmp_serde::to_vec("en-US").unwrap(),
                timestamp: 1000,
            },
            IdentityPrivateStateEvent::DeleteAgentConfig {
                key: "language".to_owned(),
                timestamp: 2000,
            },
        ];
        let json = serde_json::to_string(&events).unwrap();
        let decoded: Vec<IdentityPrivateStateEvent> = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, events);
    }

    #[test]
    fn annotation_events_json_roundtrip() {
        let events = vec![
            IdentityPrivateStateEvent::SetAnnotation {
                target_did: did("did:dht:z6MkA"),
                key: "note".to_owned(),
                value: "Trustworthy colleague".to_owned(),
                timestamp: 1000,
            },
            IdentityPrivateStateEvent::DeleteAnnotation {
                target_did: did("did:dht:z6MkA"),
                key: "note".to_owned(),
                timestamp: 2000,
            },
        ];
        let json = serde_json::to_string(&events).unwrap();
        let decoded: Vec<IdentityPrivateStateEvent> = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, events);
    }

    #[test]
    fn petname_events_json_roundtrip() {
        let events = vec![
            IdentityPrivateStateEvent::SetPetname {
                target: PetnameTarget::Did(did("did:dht:z6MkA")),
                name: "Alice".to_owned(),
                timestamp: 1000,
            },
            IdentityPrivateStateEvent::SetPetname {
                target: PetnameTarget::Context("ctx-1".to_owned()),
                name: "Work Chat".to_owned(),
                timestamp: 2000,
            },
            IdentityPrivateStateEvent::DeletePetname {
                target: PetnameTarget::Did(did("did:dht:z6MkA")),
                timestamp: 3000,
            },
        ];
        let json = serde_json::to_string(&events).unwrap();
        let decoded: Vec<IdentityPrivateStateEvent> = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, events);
    }

    #[test]
    fn notification_event_json_roundtrip() {
        let events = vec![
            IdentityPrivateStateEvent::SetNotificationPreference {
                scope: NotificationScope::Global,
                level: NotificationLevel::MentionsOnly,
                timestamp: 1000,
            },
            IdentityPrivateStateEvent::SetNotificationPreference {
                scope: NotificationScope::PerContext("ctx-1".to_owned()),
                level: NotificationLevel::None,
                timestamp: 2000,
            },
            IdentityPrivateStateEvent::SetNotificationPreference {
                scope: NotificationScope::PerDID(did("did:dht:z6MkA")),
                level: NotificationLevel::DirectOnly,
                timestamp: 3000,
            },
        ];
        let json = serde_json::to_string(&events).unwrap();
        let decoded: Vec<IdentityPrivateStateEvent> = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, events);
    }

    #[test]
    fn device_registry_events_json_roundtrip() {
        let events = vec![
            IdentityPrivateStateEvent::EnrollDevice {
                device_id: "dev-001".to_owned(),
                device_x25519_pubkey: vec![0xAA; 32],
                device_name: "iPhone 15".to_owned(),
                enrolled_at: 1_700_000_000_000,
            },
            IdentityPrivateStateEvent::UnenrollDevice {
                device_id: "dev-001".to_owned(),
                timestamp: 1_700_100_000_000,
            },
        ];
        let json = serde_json::to_string(&events).unwrap();
        let decoded: Vec<IdentityPrivateStateEvent> = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, events);
    }

    #[test]
    fn recovery_contact_events_json_roundtrip() {
        let events = vec![
            IdentityPrivateStateEvent::AddRecoveryContact {
                contact_did: did("did:dht:z6MkTrusted"),
                timestamp: 1000,
            },
            IdentityPrivateStateEvent::RemoveRecoveryContact {
                contact_did: did("did:dht:z6MkTrusted"),
                timestamp: 2000,
            },
        ];
        let json = serde_json::to_string(&events).unwrap();
        let decoded: Vec<IdentityPrivateStateEvent> = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, events);
    }

    #[test]
    fn all_events_msgpack_roundtrip() {
        let events = make_all_events();
        let bytes = rmp_serde::to_vec_named(&events).unwrap();
        let decoded: Vec<IdentityPrivateStateEvent> = rmp_serde::from_slice(&bytes).unwrap();
        assert_eq!(decoded, events);
    }

    // -----------------------------------------------------------------------
    // Supporting type tests
    // -----------------------------------------------------------------------

    #[test]
    fn graph_visibility_variants_distinct() {
        assert_ne!(GraphVisibility::Public, GraphVisibility::Contacts);
        assert_ne!(GraphVisibility::Contacts, GraphVisibility::Private);
        assert_ne!(GraphVisibility::Public, GraphVisibility::Private);
    }

    #[test]
    fn visibility_scope_variants_distinct() {
        assert_ne!(VisibilityScope::Full, VisibilityScope::ContactsOnly);
        assert_ne!(VisibilityScope::Full, VisibilityScope::ContextsOnly);
        assert_ne!(VisibilityScope::ContactsOnly, VisibilityScope::ContextsOnly);
    }

    #[test]
    fn notification_level_variants_distinct() {
        let levels = [
            NotificationLevel::All,
            NotificationLevel::MentionsOnly,
            NotificationLevel::DirectOnly,
            NotificationLevel::None,
        ];
        for (i, a) in levels.iter().enumerate() {
            for (j, b) in levels.iter().enumerate() {
                if i == j {
                    assert_eq!(a, b);
                } else {
                    assert_ne!(a, b);
                }
            }
        }
    }

    #[test]
    fn petname_target_did_and_context_distinct() {
        let did_target = PetnameTarget::Did(did("did:dht:z6MkA"));
        let ctx_target = PetnameTarget::Context("ctx-1".to_owned());
        assert_ne!(did_target, ctx_target);
    }

    #[test]
    fn notification_scope_variants_serialization() {
        let scopes = vec![
            NotificationScope::Global,
            NotificationScope::PerContext("ctx-1".to_owned()),
            NotificationScope::PerDID(did("did:dht:z6MkA")),
        ];
        for scope in &scopes {
            let json = serde_json::to_string(scope).unwrap();
            let decoded: NotificationScope = serde_json::from_str(&json).unwrap();
            assert_eq!(&decoded, scope);
        }
    }

    // -----------------------------------------------------------------------
    // Forward compatibility: unknown fields ignored (§13.5.1, #593)
    // -----------------------------------------------------------------------

    /// For unit-variant enums (`GraphVisibility`, `VisibilityScope`,
    /// `NotificationLevel`), forward compatibility means the known variants
    /// still deserialize correctly. Unknown variants are a breaking change
    /// handled by version negotiation, not field tolerance.
    #[test]
    fn graph_visibility_known_variants_deserialize() {
        for (json_str, expected) in [
            ("\"Public\"", GraphVisibility::Public),
            ("\"Contacts\"", GraphVisibility::Contacts),
            ("\"Private\"", GraphVisibility::Private),
        ] {
            let decoded: GraphVisibility = serde_json::from_str(json_str).unwrap();
            assert_eq!(decoded, expected);
        }
    }

    #[test]
    fn visibility_scope_known_variants_deserialize() {
        for (json_str, expected) in [
            ("\"Full\"", VisibilityScope::Full),
            ("\"ContactsOnly\"", VisibilityScope::ContactsOnly),
            ("\"ContextsOnly\"", VisibilityScope::ContextsOnly),
        ] {
            let decoded: VisibilityScope = serde_json::from_str(json_str).unwrap();
            assert_eq!(decoded, expected);
        }
    }

    #[test]
    fn notification_level_known_variants_deserialize() {
        for (json_str, expected) in [
            ("\"All\"", NotificationLevel::All),
            ("\"MentionsOnly\"", NotificationLevel::MentionsOnly),
            ("\"DirectOnly\"", NotificationLevel::DirectOnly),
            ("\"None\"", NotificationLevel::None),
        ] {
            let decoded: NotificationLevel = serde_json::from_str(json_str).unwrap();
            assert_eq!(decoded, expected);
        }
    }

    /// `NotificationScope` has data variants (`PerContext`, `PerDID`). The
    /// inner data of these variants must ignore unknown fields.
    #[test]
    fn notification_scope_per_context_ignores_unknown_fields() {
        let scope = NotificationScope::PerContext("ctx-1".to_owned());
        let json = serde_json::to_value(&scope).unwrap();
        // Externally tagged: {"PerContext": "ctx-1"} — newtype, no inner object to inject into.
        // Test that it still deserializes successfully.
        let decoded: NotificationScope = serde_json::from_value(json).unwrap();
        assert_eq!(decoded, scope);
    }

    /// `PetnameTarget` has data variants (`Did`, `Context`). These are
    /// newtypes wrapping a single value, so there's no inner object to
    /// inject extra fields into. Verify known variants still deserialize.
    #[test]
    fn petname_target_variants_deserialize() {
        let did_target = PetnameTarget::Did(did("did:dht:z6MkA"));
        let ctx_target = PetnameTarget::Context("ctx-1".to_owned());
        for target in [&did_target, &ctx_target] {
            let json = serde_json::to_value(target).unwrap();
            let decoded: PetnameTarget = serde_json::from_value(json).unwrap();
            assert_eq!(&decoded, target);
        }
    }

    /// `IdentityPrivateStateEvent` has struct variants with named fields.
    /// Unknown fields inside the variant's inner object must be ignored.
    #[test]
    fn identity_private_state_event_ignores_unknown_fields_in_variant() {
        // BlockDID variant: {"BlockDID": {"target_did": "...", "timestamp": 1000}}
        let event = IdentityPrivateStateEvent::BlockDID {
            target_did: did("did:dht:z6MkA"),
            timestamp: 1000,
        };
        let mut json = serde_json::to_value(&event).unwrap();
        // Inject unknown field into the variant's inner object.
        json.as_object_mut()
            .unwrap()
            .get_mut("BlockDID")
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert("future_field".into(), serde_json::json!("v2-data"));

        let result = serde_json::from_value::<IdentityPrivateStateEvent>(json);
        assert!(
            result.is_ok(),
            "variant inner data must ignore unknown fields per §13.5.1: {:?}",
            result.unwrap_err()
        );
        let decoded = result.unwrap();
        assert_eq!(decoded.event_type_name(), "BlockDID");
        assert_eq!(decoded.timestamp(), 1000);
    }

    /// Test a second variant (`EnrollDevice`) to confirm the pattern holds
    /// across the enum — different field shapes, same tolerance.
    #[test]
    fn identity_private_state_event_enroll_device_ignores_unknown_fields() {
        let event = IdentityPrivateStateEvent::EnrollDevice {
            device_id: "dev-001".to_owned(),
            device_x25519_pubkey: vec![0xAA; 32],
            device_name: "Test Device".to_owned(),
            enrolled_at: 22000,
        };
        let mut json = serde_json::to_value(&event).unwrap();
        json.as_object_mut()
            .unwrap()
            .get_mut("EnrollDevice")
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert(
                "future_biometric_hash".into(),
                serde_json::json!("sha256:abc"),
            );

        let result = serde_json::from_value::<IdentityPrivateStateEvent>(json);
        assert!(
            result.is_ok(),
            "variant inner data must ignore unknown fields per §13.5.1: {:?}",
            result.unwrap_err()
        );
        let decoded = result.unwrap();
        assert_eq!(decoded.event_type_name(), "EnrollDevice");
        assert_eq!(decoded.timestamp(), 22000);
    }

    // -----------------------------------------------------------------------
    // Event type name coverage
    // -----------------------------------------------------------------------

    #[test]
    fn event_type_names_are_unique() {
        let events = make_all_events();
        let names: Vec<&str> = events
            .iter()
            .map(IdentityPrivateStateEvent::event_type_name)
            .collect();
        let mut deduped = names.clone();
        deduped.sort_unstable();
        deduped.dedup();
        assert_eq!(
            names.len(),
            deduped.len(),
            "all event type names must be unique"
        );
    }

    // -----------------------------------------------------------------------
    // Helper
    // -----------------------------------------------------------------------

    fn make_block_mute_events() -> Vec<IdentityPrivateStateEvent> {
        vec![
            IdentityPrivateStateEvent::BlockDID {
                target_did: did("did:dht:z6MkA"),
                timestamp: 1000,
            },
            IdentityPrivateStateEvent::UnblockDID {
                target_did: did("did:dht:z6MkA"),
                timestamp: 2000,
            },
            IdentityPrivateStateEvent::BlockDIDInContext {
                target_did: did("did:dht:z6MkA"),
                context_id: "ctx-1".to_owned(),
                timestamp: 3000,
            },
            IdentityPrivateStateEvent::UnblockDIDInContext {
                target_did: did("did:dht:z6MkA"),
                context_id: "ctx-1".to_owned(),
                timestamp: 4000,
            },
            IdentityPrivateStateEvent::MuteDID {
                target_did: did("did:dht:z6MkB"),
                timestamp: 5000,
            },
            IdentityPrivateStateEvent::UnmuteDID {
                target_did: did("did:dht:z6MkB"),
                timestamp: 6000,
            },
            IdentityPrivateStateEvent::MuteDIDInContext {
                target_did: did("did:dht:z6MkB"),
                context_id: "ctx-1".to_owned(),
                timestamp: 7000,
            },
            IdentityPrivateStateEvent::UnmuteDIDInContext {
                target_did: did("did:dht:z6MkB"),
                context_id: "ctx-1".to_owned(),
                timestamp: 8000,
            },
        ]
    }

    fn make_graph_config_events() -> Vec<IdentityPrivateStateEvent> {
        vec![
            IdentityPrivateStateEvent::SetDefaultGraphVisibility {
                visibility: GraphVisibility::Contacts,
                timestamp: 9000,
            },
            IdentityPrivateStateEvent::GrantGraphVisibility {
                target_did: did("did:dht:z6MkC"),
                scope: VisibilityScope::Full,
                timestamp: 10000,
            },
            IdentityPrivateStateEvent::RevokeGraphVisibility {
                target_did: did("did:dht:z6MkC"),
                timestamp: 11000,
            },
            IdentityPrivateStateEvent::SetAgentConfig {
                key: "lang".to_owned(),
                value: vec![0x01],
                timestamp: 12000,
            },
            IdentityPrivateStateEvent::DeleteAgentConfig {
                key: "lang".to_owned(),
                timestamp: 13000,
            },
            IdentityPrivateStateEvent::SetAnnotation {
                target_did: did("did:dht:z6MkD"),
                key: "note".to_owned(),
                value: "test".to_owned(),
                timestamp: 14000,
            },
            IdentityPrivateStateEvent::DeleteAnnotation {
                target_did: did("did:dht:z6MkD"),
                key: "note".to_owned(),
                timestamp: 15000,
            },
            IdentityPrivateStateEvent::SetPetname {
                target: PetnameTarget::Did(did("did:dht:z6MkE")),
                name: "Eve".to_owned(),
                timestamp: 16000,
            },
            IdentityPrivateStateEvent::DeletePetname {
                target: PetnameTarget::Context("ctx-2".to_owned()),
                timestamp: 17000,
            },
            IdentityPrivateStateEvent::SetNotificationPreference {
                scope: NotificationScope::Global,
                level: NotificationLevel::All,
                timestamp: 18000,
            },
        ]
    }

    fn make_draft_device_recovery_events() -> Vec<IdentityPrivateStateEvent> {
        use std::borrow::Cow;

        vec![
            IdentityPrivateStateEvent::SaveDraftAttestation {
                draft_id: "draft-1".to_owned(),
                attestation: Box::new(super::super::attestation::IdentityLinkAttestation {
                    id: "test-id".to_owned(),
                    attestation_type: Cow::Borrowed("identity_link"),
                    issuer: did("did:dht:z6MkF"),
                    subject: did("did:dht:z6MkF"),
                    issued_at: 1_700_000_000_000,
                    expires_at: None,
                    claim: super::super::attestation::AttestationClaim::new(
                        "github.com".to_owned(),
                        "alice".to_owned(),
                        None,
                    ),
                    evidence: super::super::attestation::AttestationEvidence {
                        method: super::super::attestation::VerificationMethod::Oauth,
                        proof: super::super::attestation::AttestationProof::OauthVerified {
                            provider: "github.com".to_owned(),
                            subject_id: "12345".to_owned(),
                            verified_at: 1_700_000_000,
                        },
                        verified_at: 1_700_000_000_000,
                        verifier_did: None,
                    },
                    revocation: super::super::attestation::AttestationRevocation::new(
                        "/rev".to_owned(),
                    ),
                    revocation_status: crate::trust::attestation::RevocationStatus::Active,
                    signature: vec![0; 64],
                }),
                timestamp: 19000,
            },
            IdentityPrivateStateEvent::DeleteDraftAttestation {
                draft_id: "draft-1".to_owned(),
                timestamp: 20000,
            },
            IdentityPrivateStateEvent::PublishDraftAttestation {
                draft_id: "draft-1".to_owned(),
                timestamp: 21000,
            },
            IdentityPrivateStateEvent::EnrollDevice {
                device_id: "dev-001".to_owned(),
                device_x25519_pubkey: vec![0xBB; 32],
                device_name: "Test Device".to_owned(),
                enrolled_at: 22000,
            },
            IdentityPrivateStateEvent::UnenrollDevice {
                device_id: "dev-001".to_owned(),
                timestamp: 23000,
            },
            IdentityPrivateStateEvent::AddRecoveryContact {
                contact_did: did("did:dht:z6MkG"),
                timestamp: 24000,
            },
            IdentityPrivateStateEvent::RemoveRecoveryContact {
                contact_did: did("did:dht:z6MkG"),
                timestamp: 25000,
            },
        ]
    }

    fn make_all_events() -> Vec<IdentityPrivateStateEvent> {
        let mut events = make_block_mute_events();
        events.extend(make_graph_config_events());
        events.extend(make_draft_device_recovery_events());
        events
    }
}
