//! Per-variant structured payload encoders for [`EventType`](crate::EventType).
//!
//! # Why this module exists
//!
//! Several runtime call sites historically baked event parameters into the
//! event *name* — either as `format!` strings
//! (`"ContextTombstoned:{dest}:{pid}"`) or as an entire JSON blob used as the
//! type tag (`{"event":"SpendApproved",…}`). The ADR-011 typed-event
//! unification amendment (`.docs/adrs/phase-2.md`) identifies each as a defect:
//! it makes the signed Merkle-leaf preimage non-convergent and un-enumerable.
//! The correct end state is a typed [`EventType`](crate::EventType) variant
//! whose parameters live in [`EventPayload`](crate::EventPayload).
//!
//! This module is the **single source** of the payload bytes for those
//! structured variants. As the emit sites are wired (in later phases of the
//! typed-event unification — Phase 1 establishes the types; production callers
//! land later), every honest member MUST route through these functions so that
//! their Merkle roots match:
//! the leaf preimage is `SHA-256(0x00 ‖ rmp_serde(Event))`, and `Event.payload`
//! is `EventPayload { data: <bytes from this module> }`. If two implementations
//! encoded the same logical payload differently, the leaf hashes would diverge
//! and §9.9.3 equivocation detection would produce false positives.
//!
//! # Encoding
//!
//! Each payload struct derives [`Serialize`]/[`Deserialize`] and is encoded with
//! **positional** [`rmp_serde::to_vec`] (NOT `to_vec_named`). Positional
//! `MessagePack` encodes a struct as a fixed-length array of its fields in
//! declaration order, omitting field-name strings. This is deterministic and
//! compact, and — critically — does not depend on a map-key ordering that could
//! differ across serde versions or implementations. Field order is therefore
//! part of the wire contract: **never reorder fields** in these structs without
//! treating it as a breaking protocol change.

use serde::{Deserialize, Serialize};

use crate::{EventLogError, EventPayload, EventType};

/// Encodes a structured payload struct into [`EventPayload`] bytes using
/// positional `MessagePack`.
///
/// This is the single shared entry point that all callers use
/// to produce the leaf-preimage payload bytes.
///
/// # Errors
///
/// Returns [`EventLogError::SerializationFailed`] if `MessagePack` encoding
/// fails (e.g. an unrepresentable value).
pub fn encode_payload<T: Serialize>(value: &T) -> Result<EventPayload, EventLogError> {
    let data =
        rmp_serde::to_vec(value).map_err(|e| EventLogError::SerializationFailed(e.to_string()))?;
    Ok(EventPayload { data })
}

/// Decodes a structured payload struct from [`EventPayload`] bytes.
///
/// The inverse of [`encode_payload`]. Used by verifiers and the receive path to
/// recover the typed parameters from a logged event.
///
/// # Errors
///
/// Returns [`EventLogError::SerializationFailed`] if the bytes do not decode to
/// `T` under positional `MessagePack`.
pub fn decode_payload<T: for<'de> Deserialize<'de>>(
    payload: &EventPayload,
) -> Result<T, EventLogError> {
    rmp_serde::from_slice(&payload.data)
        .map_err(|e| EventLogError::SerializationFailed(e.to_string()))
}

// ---------------------------------------------------------------------------
// Per-variant payload structs
//
// Field order is the wire contract under positional MessagePack. NEVER reorder.
// Field shapes are governed by the ADR-011 amendment variant comments
// (`.docs/adrs/phase-2.md`) and the existing typed sources they replace.
// ---------------------------------------------------------------------------

/// Payload for [`EventType::ContextTombstoned`](crate::EventType::ContextTombstoned)
/// (§5.11A.5 terminal migration).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContextTombstonedPayload {
    /// The context the migration tombstone points to.
    pub destination_id: String,
    /// The migration proposal that authorized the tombstone.
    pub migration_proposal_id: [u8; 32],
}

/// Payload for
/// [`EventType::ContextMigrationCancelled`](crate::EventType::ContextMigrationCancelled)
/// (§5.11A migration abort).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContextMigrationCancelledPayload {
    /// The migration proposal that was cancelled.
    pub original_proposal_id: [u8; 32],
}

/// Payload for [`EventType::AppBound`](crate::EventType::AppBound) (§8 app bound
/// to context).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppBoundPayload {
    /// The DID of the app being bound.
    pub app_did: String,
    /// The app's declared name.
    pub app_name: String,
    /// The app's declared version.
    pub app_version: String,
    /// The capabilities granted to the app on binding.
    pub capabilities: Vec<String>,
}

/// Payload for [`EventType::AppUnbound`](crate::EventType::AppUnbound) (§8 app
/// unbound from context).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppUnboundPayload {
    /// The DID of the app being unbound.
    pub app_did: String,
}

/// Payload for [`EventType::SpendApproved`](crate::EventType::SpendApproved)
/// (`ApproveSpend` governance action, §19.6.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpendApprovedPayload {
    /// The DID authorized to spend.
    pub spender: String,
    /// The approved spend amount.
    pub amount: u64,
    /// A human-readable description of the approved spend.
    pub purpose: String,
}

/// Payload for [`EventType::TtlExtended`](crate::EventType::TtlExtended) (§5.10
/// unanimous TTL extension).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TtlExtendedPayload {
    /// The previous TTL deadline (Unix seconds).
    pub old_deadline_unix: u64,
    /// The new TTL deadline (Unix seconds).
    pub new_deadline_unix: u64,
    /// The proposal that authorized the extension.
    pub proposal_id: [u8; 32],
    /// The members who consented to the extension.
    pub consenting_members: Vec<String>,
}

/// Payload for
/// [`EventType::TtlExtensionRejected`](crate::EventType::TtlExtensionRejected)
/// (§5.10 TTL extension denied).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TtlExtensionRejectedPayload {
    /// The proposal whose extension was rejected.
    pub proposal_id: [u8; 32],
    /// The members who rejected the extension.
    pub rejecting_members: Vec<String>,
}

/// Payload for
/// [`EventType::RecoveryEpochAdvanced`](crate::EventType::RecoveryEpochAdvanced)
/// (§9.12 step 2 MLS group-epoch advance during trust recovery).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryEpochAdvancedPayload {
    /// The MLS group epoch before the advance.
    pub old_epoch: u64,
    /// The MLS group epoch after the advance.
    pub new_epoch: u64,
}

/// Payload for [`EventType::KeyEpochAdvance`](crate::EventType::KeyEpochAdvance)
/// (ADR-007 §5 sender-key epoch rotation triggered by blocking a subscriber).
///
/// Distinct from [`RecoveryEpochAdvancedPayload`], which covers the MLS group
/// epoch advance during trust recovery (§9.12). This struct tracks the
/// **sender-key** epoch for the ADR-007 Broadcast / Encrypted sender-key modes.
/// Field order is the wire contract under positional `MessagePack` —
/// **never reorder**.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyEpochAdvancePayload {
    /// The sender-key epoch before the advance.
    pub old_epoch: u64,
    /// The sender-key epoch after the advance.
    pub new_epoch: u64,
}

/// Payload for [`EventType::AccessRevoked`](crate::EventType::AccessRevoked)
/// (`RevokeReadAccess` / `RevokeWriteAccess`; ADR-031 §3, §5).
///
/// `target_did` is the member whose access was revoked. The consequence
/// engine's `WarningCount` trigger matches governance actions against this
/// field (see `scp_protocol::trust::consequence::payload_target_is`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessRevokedPayload {
    /// The DID whose read/write access was revoked.
    pub target_did: String,
}

/// Payload for
/// [`EventType::GovernanceActionExecuted`](crate::EventType::GovernanceActionExecuted).
///
/// Sources: ADR-031 §8 and acceptance criterion 7, as ADR-066 amends them;
/// `07-trust-validation-and-capabilities.md` §7.3.1.1 step 1.6, "The action,
/// once".
///
/// Encodes as the four-item array `[target_did, action_type, proposal_id,
/// action_bytes]`, with `proposal_id` and `action_bytes` as `MessagePack`
/// binaries (`serde_bytes`), never arrays of integers.
///
/// `target_did` is the member the action targeted (empty when the action has
/// no target, e.g. a context-wide policy change). `action_type` is the
/// `GovernanceAction` variant name. The consequence engine reads `target_did`
/// for the `WarningCount` trigger and `action_type` for participation records.
/// `action_bytes` is the action's one copy in the executing Commit: the exact
/// RFC 8785 bytes the proposer hashed into `proposal_id`, which every member
/// that applies the leaf decodes the action from, and from which every
/// receiver recomputes `proposal_id` (§7.3.1.1 step 1.3). A member never
/// re-encodes them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernanceActionExecutedPayload {
    /// The DID the executed action targeted (empty if the action is untargeted).
    pub target_did: String,
    /// The `GovernanceAction` variant name (e.g. `"RemoveMember"`).
    pub action_type: String,
    /// The executed proposal's identifier (`09-security-model.md` §9.5.2).
    #[serde(with = "serde_bytes")]
    pub proposal_id: [u8; 32],
    /// The proposal's RFC 8785 action bytes, verbatim.
    #[serde(with = "serde_bytes")]
    pub action_bytes: Vec<u8>,
}

/// Payload for [`EventType::MemberReset`](crate::EventType::MemberReset).
///
/// Sources: ADR-029 §4 group state reset, `23-sync-and-offline-strategy.md` §23.4.1
/// Welcome-based fast-forward, and the `ResetMember` governance action;
/// `07-trust-validation-and-capabilities.md` §7.3.1.1 step 1.6.
///
/// Encodes as the four-item array `[subject_did, last_known_epoch,
/// reset_counter, reason]`. A reset a member requested carries the
/// `last_known_epoch`, `reset_counter`, and `reason` of that member's signed
/// reset-request record (§7.3.1.1 step 1.7), so every value in the leaf is one
/// the member signed. A reset a `ResetMember` action derives carries nil for
/// both integers and an empty `reason`; the action's own reason is in the
/// `GovernanceActionExecuted` leaf's `action_bytes`. `reason` is a `String`,
/// never optional, so a nil `reason` fails to decode.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberResetPayload {
    /// The DID of the member that was reset (the affected member, not the
    /// committer, which is the leaf's `actor_did`).
    pub subject_did: String,
    /// The last epoch the member reported in its reset request; `None` for a
    /// reset a `ResetMember` action derives.
    pub last_known_epoch: Option<u64>,
    /// The member's reset-request counter; `None` for a reset a `ResetMember`
    /// action derives.
    pub reset_counter: Option<u64>,
    /// The request's reason text; empty for a reset a `ResetMember` action
    /// derives.
    pub reason: String,
}

/// Payload for
/// [`EventType::GovernanceDeadlockRecovery`](crate::EventType::GovernanceDeadlockRecovery)
/// (ADR-011 amendment; issue #1847).
///
/// Records the deadlock justification evidence emitted **immediately after**
/// [`EventType::GovernanceReconfigured`](crate::EventType::GovernanceReconfigured)
/// so the recovery evidence is durably anchored in the Merkle log.
/// The two leaves share the same `actor_did` and `timestamp_secs`.
/// Field order is the wire contract under positional `MessagePack` —
/// **never reorder**.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernanceDeadlockRecoveryPayload {
    /// DIDs of signers who were unavailable during deadlock detection.
    pub unavailable_dids: Vec<String>,
    /// Per-signer missed-window evidence: (DID, consecutive missed voting windows).
    ///
    /// Each tuple is the DID of a signer who had evidence of unavailability and
    /// the number of consecutive voting windows they missed. Distinct from
    /// `unavailable_dids` (completely absent — no response at all); these signers
    /// sent some responses but missed enough windows to be declared unavailable.
    pub missed_windows: Vec<(String, u32)>,
    /// Unix timestamp (seconds) when deadlock was detected.
    pub detected_at: u64,
}

/// Payload for [`EventType::RoleAssigned`](crate::EventType::RoleAssigned)
/// (`ChangeRole` governance action, §5; ADR-011 amendment subject-bearing
/// leaves).
///
/// `subject_did` is the member whose role was assigned/changed — the *affected
/// member*, NOT the governance actor who executed the change (for admin-driven
/// assignments the leaf `actor_did` is the admin). The participation-record
/// `role_progression_count` fact (§7.3.2) attributes the role transition to
/// this `subject_did`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoleAssignedPayload {
    /// The DID of the member whose role was assigned/changed.
    pub subject_did: String,
    /// The role name assigned to the subject.
    pub role: String,
}

/// Payload for [`EventType::MemberJoined`](crate::EventType::MemberJoined) and
/// [`EventType::MemberLeft`](crate::EventType::MemberLeft) (§5 membership
/// changes; ADR-011 amendment subject-bearing leaves).
///
/// `subject_did` is the member who joined/left — the *affected member*, NOT the
/// governance actor (for admin-driven joins/removals the leaf `actor_did` is the
/// admin; on self-join/leave and broadcast subscribe/unsubscribe the two
/// coincide, but the payload still carries the member so the leaf shape is
/// uniform). The participation-record `participation_duration_secs` fact
/// (§7.3.2) attributes the join/leave interval to this `subject_did`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MembershipChangePayload {
    /// The DID of the member who joined or left.
    pub subject_did: String,
    /// The role name held by the member at the time of the membership change.
    pub role_name: String,
}

/// Payload for [`EventType::MediaSessionStarted`](crate::EventType::MediaSessionStarted)
/// (ADR-024 AC 8 — session metadata recorded in context event log).
///
/// Captures the session identity and initial configuration at the point the
/// session transitions from `Initiating` to `Active`. Field order is the
/// wire contract under positional `MessagePack` — **never reorder**.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MediaSessionStartedPayload {
    /// The media session identifier (e.g. `"ms-<hex>"`).
    pub session_id: String,
    /// The context hosting the session.
    pub context_id: String,
    /// DIDs of participants at session activation.
    pub participants: Vec<String>,
    /// Ceiling names of active media capabilities (e.g. `"media:voice"`).
    pub capabilities: Vec<String>,
    /// Unix timestamp (seconds) when the session was created.
    pub started_at: u64,
}

/// Payload for [`EventType::MediaSessionEnded`](crate::EventType::MediaSessionEnded)
/// (ADR-024 AC 8 — session metadata recorded in context event log).
///
/// Captures the full session record at teardown: participants, capabilities,
/// and both timestamps, sufficient for participation-record derivation
/// (ADR-017 §7.3.2). Field order is the wire contract under positional
/// `MessagePack` — **never reorder**.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MediaSessionEndedPayload {
    /// The media session identifier.
    pub session_id: String,
    /// The context hosting the session.
    pub context_id: String,
    /// DIDs of participants at session end.
    pub participants: Vec<String>,
    /// Ceiling names of active media capabilities (e.g. `"media:voice"`).
    pub capabilities: Vec<String>,
    /// Unix timestamp (seconds) when the session started.
    pub started_at: u64,
    /// Unix timestamp (seconds) when the session ended.
    pub ended_at: u64,
}

/// Builds the durable Merkle-leaf payload bytes for a consequence-enforcement
/// event.
///
/// The event is one of
/// [`ConsequenceTriggered`](crate::EventType::ConsequenceTriggered),
/// [`ConsequenceEnforced`](crate::EventType::ConsequenceEnforced),
/// [`ConsequenceEnforcementFailed`](crate::EventType::ConsequenceEnforcementFailed),
/// or
/// [`ConsequenceEscalatedToSuspendAll`](crate::EventType::ConsequenceEscalatedToSuspendAll)
/// (ADR-017, ADR-051 §6, H4 / `.docs/adrs/phase-2.md` ADR-011 amendment).
///
/// # Why this is the single source
///
/// The native runtime (`scp-runtime`) mints these leaves for convergent-trigger
/// consequences. The leaf preimage is
/// `SHA-256(0x00 ‖ rmp_serde(Event))`, and `Event.payload` is
/// `EventPayload { data }` — so the `data` bytes MUST be byte-identical across
/// all honest members or §9.9.3 equivocation detection produces false
/// positives. This function is the shared producer of those bytes.
///
/// # Encoding — JSON, NOT positional `MessagePack`
///
/// Unlike the structured payload structs above (which use positional
/// `MessagePack` via [`encode_payload`]), consequence payloads are encoded as a
/// **JSON object**. `serde_json::json!` builds a `BTreeMap` (the workspace does
/// not enable `serde_json`'s `preserve_order` feature), so the keys are emitted in
/// SORTED order — `action_type`, `rule_index`, `target_did`, `trigger_kind`:
///
/// ```json
/// {"action_type":"SuspendCapability","rule_index":3,"target_did":"…","trigger_kind":"WarningCount"}
/// ```
///
/// That sorted order is deterministic and implementation-independent (same
/// `serde_json`, same default features across all members), which is exactly
/// why it converges. The JSON shape is also load-bearing because the consequence
/// engine reads `target_did` back out of these bytes via
/// `scp_protocol::trust::consequence::payload_target_is` to close the recursive
/// `WarningCount` blind spot.
///
/// `target_did` is the affected member (mirrors the `payload_target_is`
/// convention). `trigger_kind` is the `ConsequenceTrigger` label (e.g.
/// `"WarningCount"`, `"Custom:key"`) and `action_type` is the
/// `EnforcementSeverity` / consequence-action label (e.g. `"SuspendCapability"`,
/// `"SuspendAll"`). Both labels are produced by the shared functions in
/// `scp_protocol::trust::consequence` so the two platforms emit identical
/// strings.
#[must_use]
pub fn consequence_event_payload(
    target_did: &str,
    rule_index: usize,
    trigger_kind: &str,
    action_type: &str,
) -> EventPayload {
    let value = serde_json::json!({
        "target_did": target_did,
        "rule_index": rule_index,
        "trigger_kind": trigger_kind,
        "action_type": action_type,
    });
    EventPayload {
        data: serde_json::to_vec(&value).unwrap_or_default(),
    }
}

// ---------------------------------------------------------------------------
// Cross-bridge payload projection
// ---------------------------------------------------------------------------

/// A bridge-agnostic projection of the fields an FFI `event_log_query` consumer
/// needs to read out of a typed [`EventPayload`] without re-implementing the
/// per-variant decode logic in each bridge.
///
/// # Why this exists
///
/// The FFI `event_log_query` projection historically discarded the event
/// payload, emitting only the leaf hash. Layer-2 behavioral records need the
/// `target_did` carried by governance/access-revocation events to compute
/// participation facts (e.g. `governance_actions_against`). This struct is the
/// single shared decode surface so that the three native bridges (`PyO3`,
/// NAPI, `UniFFI`) project byte-identical values for the same event — the
/// cross-bridge parity contract. It lives alongside the payload types in
/// `scp-event-log` (not `scp-ffi-common`), so every bridge shares one decoder
/// by construction.
///
/// Fields default to `None`; only variants that carry the field decode it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EventPayloadProjection {
    /// The target DID for events that carry one (governance actions, access
    /// revocation); `None` otherwise. An empty `target_did` in the underlying
    /// payload (e.g. an untargeted, context-wide governance action) projects to
    /// `None` so consumers do not key participation facts on an empty subject.
    pub target_did: Option<String>,
    /// The subject DID for role/membership events that carry one
    /// (`RoleAssigned`, `MemberJoined`, `MemberLeft`, `MemberReset`) — the
    /// *affected member*, not the governance actor; `None` otherwise. An empty
    /// `subject_did` in the underlying payload (e.g. a historical empty-payload
    /// leaf) projects to `None` so consumers do not key participation facts on
    /// an empty subject.
    ///
    /// This is a separate field from [`target_did`](Self::target_did) by design:
    /// governance/access events project the targeted member into `target_did`,
    /// while role/membership events project the affected member into
    /// `subject_did`. Two precise fields keep participation-fact attribution
    /// (§7.3.2) unambiguous about which leaf class a DID came from.
    pub subject_did: Option<String>,
}

/// Decodes the bridge-facing projection fields from a typed event payload.
///
/// This is the single shared entry point every FFI bridge's `event_log_query`
/// projection calls to expose payload fields. It decodes ONLY the variants that
/// carry a projected field; all other variants return
/// [`EventPayloadProjection::default`] (all fields `None`).
///
/// # Panics
///
/// Never. Malformed payload bytes decode to `None` via [`decode_payload`]'s
/// `Result`, never a panic, so a corrupt leaf cannot crash a query.
#[must_use]
pub fn project_payload(event_type: &EventType, payload: &EventPayload) -> EventPayloadProjection {
    /// Maps an empty string to `None`; a non-empty string to `Some`.
    fn non_empty(value: String) -> Option<String> {
        if value.is_empty() { None } else { Some(value) }
    }

    match event_type {
        EventType::GovernanceActionExecuted => EventPayloadProjection {
            target_did: decode_payload::<GovernanceActionExecutedPayload>(payload)
                .ok()
                .and_then(|p| non_empty(p.target_did)),
            ..EventPayloadProjection::default()
        },
        EventType::AccessRevoked => EventPayloadProjection {
            target_did: decode_payload::<AccessRevokedPayload>(payload)
                .ok()
                .and_then(|p| non_empty(p.target_did)),
            ..EventPayloadProjection::default()
        },
        EventType::RoleAssigned => EventPayloadProjection {
            subject_did: decode_payload::<RoleAssignedPayload>(payload)
                .ok()
                .and_then(|p| non_empty(p.subject_did)),
            ..EventPayloadProjection::default()
        },
        EventType::MemberJoined | EventType::MemberLeft => EventPayloadProjection {
            subject_did: decode_payload::<MembershipChangePayload>(payload)
                .ok()
                .and_then(|p| non_empty(p.subject_did)),
            ..EventPayloadProjection::default()
        },
        EventType::MemberReset => EventPayloadProjection {
            subject_did: decode_payload::<MemberResetPayload>(payload)
                .ok()
                .and_then(|p| non_empty(p.subject_did)),
            ..EventPayloadProjection::default()
        },
        _ => EventPayloadProjection::default(),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// Asserts that positional `MessagePack` encodes the struct as a
    /// fixed-length array (first byte is a fixarray marker `0x9N`), proving we
    /// are NOT emitting a field-name map.
    fn assert_positional_array(bytes: &[u8], expected_len: usize) {
        assert!(!bytes.is_empty(), "encoded payload must be non-empty");
        let marker = bytes[0];
        // MessagePack fixarray: 0x90..=0x9f, low nibble is the element count.
        assert_eq!(
            marker & 0xf0,
            0x90,
            "positional encoding must be a fixarray (got marker {marker:#04x})"
        );
        assert_eq!(
            usize::from(marker & 0x0f),
            expected_len,
            "fixarray element count must equal the struct field count"
        );
    }

    #[test]
    fn context_tombstoned_round_trip() {
        let p = ContextTombstonedPayload {
            destination_id: "ctx-dest-1".to_owned(),
            migration_proposal_id: [7u8; 32],
        };
        let encoded = encode_payload(&p).unwrap();
        assert_positional_array(&encoded.data, 2);
        let decoded: ContextTombstonedPayload = decode_payload(&encoded).unwrap();
        assert_eq!(p, decoded);
    }

    #[test]
    fn context_migration_cancelled_round_trip() {
        let p = ContextMigrationCancelledPayload {
            original_proposal_id: [3u8; 32],
        };
        let encoded = encode_payload(&p).unwrap();
        assert_positional_array(&encoded.data, 1);
        let decoded: ContextMigrationCancelledPayload = decode_payload(&encoded).unwrap();
        assert_eq!(p, decoded);
    }

    #[test]
    fn app_bound_round_trip() {
        let p = AppBoundPayload {
            app_did: "did:key:app".to_owned(),
            app_name: "Scheduler".to_owned(),
            app_version: "1.2.3".to_owned(),
            capabilities: vec!["outlet:call:*".to_owned(), "message:send".to_owned()],
        };
        let encoded = encode_payload(&p).unwrap();
        assert_positional_array(&encoded.data, 4);
        let decoded: AppBoundPayload = decode_payload(&encoded).unwrap();
        assert_eq!(p, decoded);
    }

    #[test]
    fn app_unbound_round_trip() {
        let p = AppUnboundPayload {
            app_did: "did:key:app".to_owned(),
        };
        let encoded = encode_payload(&p).unwrap();
        assert_positional_array(&encoded.data, 1);
        let decoded: AppUnboundPayload = decode_payload(&encoded).unwrap();
        assert_eq!(p, decoded);
    }

    #[test]
    fn spend_approved_round_trip() {
        let p = SpendApprovedPayload {
            spender: "did:key:agent".to_owned(),
            amount: 42_000,
            purpose: "compute budget".to_owned(),
        };
        let encoded = encode_payload(&p).unwrap();
        assert_positional_array(&encoded.data, 3);
        let decoded: SpendApprovedPayload = decode_payload(&encoded).unwrap();
        assert_eq!(p, decoded);
    }

    #[test]
    fn ttl_extended_round_trip() {
        let p = TtlExtendedPayload {
            old_deadline_unix: 1_000_000,
            new_deadline_unix: 2_000_000,
            proposal_id: [9u8; 32],
            consenting_members: vec!["did:key:a".to_owned(), "did:key:b".to_owned()],
        };
        let encoded = encode_payload(&p).unwrap();
        assert_positional_array(&encoded.data, 4);
        let decoded: TtlExtendedPayload = decode_payload(&encoded).unwrap();
        assert_eq!(p, decoded);
    }

    #[test]
    fn ttl_extension_rejected_round_trip() {
        let p = TtlExtensionRejectedPayload {
            proposal_id: [5u8; 32],
            rejecting_members: vec!["did:key:c".to_owned()],
        };
        let encoded = encode_payload(&p).unwrap();
        assert_positional_array(&encoded.data, 2);
        let decoded: TtlExtensionRejectedPayload = decode_payload(&encoded).unwrap();
        assert_eq!(p, decoded);
    }

    #[test]
    fn recovery_epoch_advanced_round_trip() {
        let p = RecoveryEpochAdvancedPayload {
            old_epoch: 11,
            new_epoch: 12,
        };
        let encoded = encode_payload(&p).unwrap();
        assert_positional_array(&encoded.data, 2);
        let decoded: RecoveryEpochAdvancedPayload = decode_payload(&encoded).unwrap();
        assert_eq!(p, decoded);
    }

    #[test]
    fn key_epoch_advance_round_trip() {
        // ADR-007 §5 sender-key epoch advance (distinct from MLS group recovery epoch).
        let p = KeyEpochAdvancePayload {
            old_epoch: 5,
            new_epoch: 6,
        };
        let encoded = encode_payload(&p).unwrap();
        // 2-field struct → fixarray of length 2
        assert_positional_array(&encoded.data, 2);
        let decoded: KeyEpochAdvancePayload = decode_payload(&encoded).unwrap();
        assert_eq!(p, decoded);
    }

    #[test]
    fn access_revoked_round_trip() {
        let p = AccessRevokedPayload {
            target_did: "did:key:alice".to_owned(),
        };
        let encoded = encode_payload(&p).unwrap();
        assert_positional_array(&encoded.data, 1);
        let decoded: AccessRevokedPayload = decode_payload(&encoded).unwrap();
        assert_eq!(p, decoded);
    }

    /// A 56-byte identifier in text form (`03-identity.md` §3.1), the length
    /// the §7.3.1.1 leaf bound assumes for `target_did` and `subject_did`.
    const DID_56: &str = "did:dht:z6MkAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    /// RFC 8785 bytes of a `CloseContext` action whose reason pads the whole
    /// encoding to exactly `len` bytes. The object has one key at each level
    /// and an ASCII string value, so its compact JSON is its RFC 8785 form.
    fn canonical_action_of_len(len: usize) -> Vec<u8> {
        let prefix = br#"{"CloseContext":{"reason":""#;
        let suffix = br#""}}"#;
        let pad = len - prefix.len() - suffix.len();
        let mut bytes = Vec::with_capacity(len);
        bytes.extend_from_slice(prefix);
        bytes.extend(std::iter::repeat_n(b'a', pad));
        bytes.extend_from_slice(suffix);
        bytes
    }

    #[test]
    fn governance_action_executed_encodes_four_items_with_bin_fields() {
        let action_bytes = br#"{"RemoveMember":{"did":"did:key:bob"}}"#.to_vec();
        let p = GovernanceActionExecutedPayload {
            target_did: "did:key:bob".to_owned(),
            action_type: "RemoveMember".to_owned(),
            proposal_id: [9u8; 32],
            action_bytes: action_bytes.clone(),
        };
        let encoded = encode_payload(&p).unwrap();
        assert_positional_array(&encoded.data, 4);

        // [fixarray 4][fixstr 11 "did:key:bob"][fixstr 12 "RemoveMember"]
        // [bin8 32 proposal_id][bin8 N action_bytes] — both byte fields are
        // MessagePack `bin` (0xc4), never an array of integers.
        let mut expected = vec![0x94, 0xa0 | 0x0b];
        expected.extend_from_slice(b"did:key:bob");
        expected.push(0xa0 | 0x0c);
        expected.extend_from_slice(b"RemoveMember");
        expected.extend_from_slice(&[0xc4, 32]);
        expected.extend_from_slice(&[9u8; 32]);
        expected.extend_from_slice(&[0xc4, u8::try_from(action_bytes.len()).unwrap()]);
        expected.extend_from_slice(&action_bytes);
        assert_eq!(encoded.data, expected);

        let decoded: GovernanceActionExecutedPayload = decode_payload(&encoded).unwrap();
        assert_eq!(p, decoded);
    }

    #[test]
    fn governance_action_executed_8192_byte_action_round_trips_verbatim_in_8318_bytes() {
        let action_bytes = canonical_action_of_len(8_192);
        assert_eq!(action_bytes.len(), 8_192);
        // The bytes are RFC 8785: re-serializing the parsed value (serde_json
        // sorts object keys and writes compact output) reproduces them.
        let parsed: serde_json::Value = serde_json::from_slice(&action_bytes).unwrap();
        assert_eq!(serde_json::to_vec(&parsed).unwrap(), action_bytes);
        assert_eq!(DID_56.len(), 56);
        let action_type = "ModifyPseudonymRotationPolicy";
        assert_eq!(action_type.len(), 29);

        let p = GovernanceActionExecutedPayload {
            target_did: DID_56.to_owned(),
            action_type: action_type.to_owned(),
            proposal_id: [0xab; 32],
            action_bytes: action_bytes.clone(),
        };
        let encoded = encode_payload(&p).unwrap();
        // 1 (fixarray) + 58 (str8 56) + 30 (fixstr 29) + 34 (bin8 32)
        // + 8,195 (bin16 8,192) = 8,318 (§7.3.1.1, the leaf bound).
        assert_eq!(encoded.data.len(), 8_318);
        // The action is the encoding's tail, verbatim after its bin16 header.
        let tail_start = encoded.data.len() - 8_192;
        assert_eq!(
            &encoded.data[tail_start - 3..tail_start],
            &[0xc5, 0x20, 0x00]
        );
        assert_eq!(&encoded.data[tail_start..], action_bytes.as_slice());

        let decoded: GovernanceActionExecutedPayload = decode_payload(&encoded).unwrap();
        assert_eq!(
            decoded.action_bytes, action_bytes,
            "byte for byte, no re-encoding"
        );
        assert_eq!(decoded, p);
    }

    #[test]
    fn governance_action_executed_empty_target_round_trip() {
        // Untargeted actions (e.g. context-wide policy changes) carry an empty
        // target_did but must still round-trip as a four-element fixarray.
        let p = GovernanceActionExecutedPayload {
            target_did: String::new(),
            action_type: "LockEconomicPolicy".to_owned(),
            proposal_id: [1u8; 32],
            action_bytes: br#""LockEconomicPolicy""#.to_vec(),
        };
        let encoded = encode_payload(&p).unwrap();
        assert_positional_array(&encoded.data, 4);
        let decoded: GovernanceActionExecutedPayload = decode_payload(&encoded).unwrap();
        assert_eq!(p, decoded);
    }

    #[test]
    fn governance_action_executed_rejects_proposal_id_of_wrong_length() {
        // [fixarray 4]["" ]["X"][bin8 31 …][bin8 0] — a 31-byte proposal_id is
        // not a ProposalId.
        let mut bytes = vec![0x94, 0xa0, 0xa1, b'X', 0xc4, 31];
        bytes.extend_from_slice(&[0u8; 31]);
        bytes.extend_from_slice(&[0xc4, 0]);
        let result =
            decode_payload::<GovernanceActionExecutedPayload>(&EventPayload { data: bytes });
        assert!(matches!(result, Err(EventLogError::SerializationFailed(_))));
    }

    #[test]
    fn member_reset_requested_round_trips_all_four_fields() {
        let p = MemberResetPayload {
            subject_did: DID_56.to_owned(),
            last_known_epoch: Some(41),
            reset_counter: Some(7),
            reason: "extended offline (9 days)".to_owned(),
        };
        let encoded = encode_payload(&p).unwrap();
        assert_positional_array(&encoded.data, 4);
        let decoded: MemberResetPayload = decode_payload(&encoded).unwrap();
        assert_eq!(p, decoded);
    }

    #[test]
    fn member_reset_of_reset_member_action_encodes_nil_integers_and_empty_reason() {
        let p = MemberResetPayload {
            subject_did: "did:key:bob".to_owned(),
            last_known_epoch: None,
            reset_counter: None,
            reason: String::new(),
        };
        let encoded = encode_payload(&p).unwrap();
        // [fixarray 4][fixstr 11 "did:key:bob"][nil][nil][fixstr 0]
        let mut expected = vec![0x94, 0xa0 | 0x0b];
        expected.extend_from_slice(b"did:key:bob");
        expected.extend_from_slice(&[0xc0, 0xc0, 0xa0]);
        assert_eq!(encoded.data, expected);
        let decoded: MemberResetPayload = decode_payload(&encoded).unwrap();
        assert_eq!(p, decoded);
    }

    #[test]
    fn member_reset_rejects_nil_reason() {
        // [fixarray 4][fixstr 1 "x"][nil][nil][nil] — `reason` is a String, so
        // nil is not a value of it.
        let bytes = vec![0x94, 0xa1, b'x', 0xc0, 0xc0, 0xc0];
        let result = decode_payload::<MemberResetPayload>(&EventPayload { data: bytes });
        assert!(matches!(result, Err(EventLogError::SerializationFailed(_))));
    }

    #[test]
    fn project_member_reset_round_trips_subject_did() {
        let p = MemberResetPayload {
            subject_did: "did:key:erin".to_owned(),
            last_known_epoch: None,
            reset_counter: None,
            reason: String::new(),
        };
        let encoded = encode_payload(&p).unwrap();
        let projection = project_payload(&EventType::MemberReset, &encoded);
        assert_eq!(projection.subject_did.as_deref(), Some("did:key:erin"));
        assert_eq!(projection.target_did, None);
    }

    #[test]
    fn governance_deadlock_recovery_round_trip() {
        let p = GovernanceDeadlockRecoveryPayload {
            unavailable_dids: vec!["did:key:carol".to_owned(), "did:key:dave".to_owned()],
            missed_windows: vec![
                ("did:key:carol".to_owned(), 4),
                ("did:key:dave".to_owned(), 3),
            ],
            detected_at: 1_700_000_000,
        };
        let encoded = encode_payload(&p).unwrap();
        // 3 fields: unavailable_dids (Vec<String>), missed_windows (Vec<(String,u32)>),
        // detected_at (u64)
        assert_positional_array(&encoded.data, 3);
        let decoded: GovernanceDeadlockRecoveryPayload = decode_payload(&encoded).unwrap();
        assert_eq!(p, decoded);
    }

    #[test]
    fn governance_deadlock_recovery_missed_windows_only_round_trip() {
        // Boundary: missed_windows evidence only (unavailable_dids empty — signers
        // responded but missed enough windows to trigger the fallback threshold).
        let p = GovernanceDeadlockRecoveryPayload {
            unavailable_dids: Vec::new(),
            missed_windows: vec![("did:key:eve".to_owned(), 5)],
            detected_at: 0,
        };
        let encoded = encode_payload(&p).unwrap();
        assert_positional_array(&encoded.data, 3);
        let decoded: GovernanceDeadlockRecoveryPayload = decode_payload(&encoded).unwrap();
        assert_eq!(p, decoded);
    }

    #[test]
    fn role_assigned_round_trip() {
        let p = RoleAssignedPayload {
            subject_did: "did:key:carol".to_owned(),
            role: "admin".to_owned(),
        };
        let encoded = encode_payload(&p).unwrap();
        assert_positional_array(&encoded.data, 2);
        let decoded: RoleAssignedPayload = decode_payload(&encoded).unwrap();
        assert_eq!(p, decoded);
    }

    #[test]
    fn membership_change_round_trip() {
        let p = MembershipChangePayload {
            subject_did: "did:key:dave".to_owned(),
            role_name: "member".to_owned(),
        };
        let encoded = encode_payload(&p).unwrap();
        assert_positional_array(&encoded.data, 2);
        let decoded: MembershipChangePayload = decode_payload(&encoded).unwrap();
        assert_eq!(p, decoded);
    }

    #[test]
    fn empty_collections_round_trip() {
        // Boundary: empty consenting/rejecting/capability vectors must survive
        // the round trip and still produce a fixarray of the struct's field
        // count (the empty Vec is one element, encoded as an empty array).
        let p = TtlExtendedPayload {
            old_deadline_unix: 0,
            new_deadline_unix: 0,
            proposal_id: [0u8; 32],
            consenting_members: Vec::new(),
        };
        let encoded = encode_payload(&p).unwrap();
        assert_positional_array(&encoded.data, 4);
        let decoded: TtlExtendedPayload = decode_payload(&encoded).unwrap();
        assert_eq!(p, decoded);
    }

    #[test]
    fn project_governance_action_executed_round_trips_target_did() {
        let p = GovernanceActionExecutedPayload {
            target_did: "did:key:bob".to_owned(),
            action_type: "RemoveMember".to_owned(),
            proposal_id: [9u8; 32],
            action_bytes: br#"{"RemoveMember":{}}"#.to_vec(),
        };
        let encoded = encode_payload(&p).unwrap();
        let projection = project_payload(&EventType::GovernanceActionExecuted, &encoded);
        assert_eq!(projection.target_did.as_deref(), Some("did:key:bob"));
    }

    #[test]
    fn project_access_revoked_round_trips_target_did() {
        let p = AccessRevokedPayload {
            target_did: "did:key:alice".to_owned(),
        };
        let encoded = encode_payload(&p).unwrap();
        let projection = project_payload(&EventType::AccessRevoked, &encoded);
        assert_eq!(projection.target_did.as_deref(), Some("did:key:alice"));
    }

    #[test]
    fn project_untargeted_governance_action_yields_none() {
        // An untargeted governance action carries an empty target_did, which
        // must project to None so consumers do not key facts on an empty
        // subject.
        let p = GovernanceActionExecutedPayload {
            target_did: String::new(),
            action_type: "ModifyPolicy".to_owned(),
            proposal_id: [9u8; 32],
            action_bytes: br#"{"RemoveMember":{}}"#.to_vec(),
        };
        let encoded = encode_payload(&p).unwrap();
        let projection = project_payload(&EventType::GovernanceActionExecuted, &encoded);
        assert_eq!(projection.target_did, None);
    }

    #[test]
    fn project_non_target_event_yields_none() {
        // A variant that carries no target_did returns the default projection,
        // even when handed bytes that would decode to a targeted payload.
        let p = GovernanceActionExecutedPayload {
            target_did: "did:key:carol".to_owned(),
            action_type: "RemoveMember".to_owned(),
            proposal_id: [9u8; 32],
            action_bytes: br#"{"RemoveMember":{}}"#.to_vec(),
        };
        let encoded = encode_payload(&p).unwrap();
        let projection = project_payload(&EventType::ContextCreated, &encoded);
        assert_eq!(projection, EventPayloadProjection::default());
        assert_eq!(projection.target_did, None);
    }

    #[test]
    fn project_role_assigned_round_trips_subject_did() {
        let p = RoleAssignedPayload {
            subject_did: "did:key:carol".to_owned(),
            role: "admin".to_owned(),
        };
        let encoded = encode_payload(&p).unwrap();
        let projection = project_payload(&EventType::RoleAssigned, &encoded);
        assert_eq!(projection.subject_did.as_deref(), Some("did:key:carol"));
        // RoleAssigned carries a subject, never a target.
        assert_eq!(projection.target_did, None);
    }

    #[test]
    fn project_member_joined_round_trips_subject_did() {
        let p = MembershipChangePayload {
            subject_did: "did:key:dave".to_owned(),
            role_name: "member".to_owned(),
        };
        let encoded = encode_payload(&p).unwrap();
        let projection = project_payload(&EventType::MemberJoined, &encoded);
        assert_eq!(projection.subject_did.as_deref(), Some("did:key:dave"));
        assert_eq!(projection.target_did, None);
    }

    #[test]
    fn project_member_left_round_trips_subject_did() {
        let p = MembershipChangePayload {
            subject_did: "did:key:erin".to_owned(),
            role_name: "subscriber".to_owned(),
        };
        let encoded = encode_payload(&p).unwrap();
        let projection = project_payload(&EventType::MemberLeft, &encoded);
        assert_eq!(projection.subject_did.as_deref(), Some("did:key:erin"));
        assert_eq!(projection.target_did, None);
    }

    #[test]
    fn project_empty_subject_role_membership_yields_none() {
        // A role/membership leaf with an empty subject_did (e.g. a historical
        // empty-payload leaf reconstructed with a blank subject) must project to
        // None so consumers do not key facts on an empty subject.
        let role = RoleAssignedPayload {
            subject_did: String::new(),
            role: "admin".to_owned(),
        };
        let role_enc = encode_payload(&role).unwrap();
        assert_eq!(
            project_payload(&EventType::RoleAssigned, &role_enc).subject_did,
            None
        );

        let membership = MembershipChangePayload {
            subject_did: String::new(),
            role_name: "member".to_owned(),
        };
        let membership_enc = encode_payload(&membership).unwrap();
        assert_eq!(
            project_payload(&EventType::MemberJoined, &membership_enc).subject_did,
            None
        );
        assert_eq!(
            project_payload(&EventType::MemberLeft, &membership_enc).subject_did,
            None
        );
    }

    #[test]
    fn project_malformed_bytes_yields_none_without_panic() {
        // Garbage bytes for a target-carrying variant must decode to None, not
        // panic — a corrupt leaf cannot crash a query.
        let malformed = EventPayload {
            data: vec![0xff, 0x00, 0x13, 0x37],
        };
        let governance = project_payload(&EventType::GovernanceActionExecuted, &malformed);
        assert_eq!(governance.target_did, None);
        let revoked = project_payload(&EventType::AccessRevoked, &malformed);
        assert_eq!(revoked.target_did, None);
        // Subject-bearing variants must also tolerate garbage without panic.
        assert_eq!(
            project_payload(&EventType::RoleAssigned, &malformed).subject_did,
            None
        );
        assert_eq!(
            project_payload(&EventType::MemberJoined, &malformed).subject_did,
            None
        );
        assert_eq!(
            project_payload(&EventType::MemberLeft, &malformed).subject_did,
            None
        );
    }

    #[test]
    fn project_empty_payload_yields_none_without_panic() {
        let empty = EventPayload::default();
        let governance = project_payload(&EventType::GovernanceActionExecuted, &empty);
        assert_eq!(governance.target_did, None);
        let revoked = project_payload(&EventType::AccessRevoked, &empty);
        assert_eq!(revoked.target_did, None);
        // Subject-bearing variants project None from an empty payload, never panic.
        assert_eq!(
            project_payload(&EventType::RoleAssigned, &empty).subject_did,
            None
        );
        assert_eq!(
            project_payload(&EventType::MemberJoined, &empty).subject_did,
            None
        );
        assert_eq!(
            project_payload(&EventType::MemberLeft, &empty).subject_did,
            None
        );
    }

    #[test]
    fn media_session_started_round_trip() {
        let p = MediaSessionStartedPayload {
            session_id: "ms-abc123".to_owned(),
            context_id: "ctx-test-001".to_owned(),
            participants: vec!["did:dht:zAlice".to_owned(), "did:dht:zBob".to_owned()],
            capabilities: vec!["media:voice".to_owned()],
            started_at: 1_700_000_000,
        };
        let encoded = encode_payload(&p).unwrap();
        // 5-field struct → fixarray of length 5
        assert_positional_array(&encoded.data, 5);
        let decoded: MediaSessionStartedPayload = decode_payload(&encoded).unwrap();
        assert_eq!(p, decoded);
    }

    #[test]
    fn media_session_ended_round_trip() {
        let p = MediaSessionEndedPayload {
            session_id: "ms-abc123".to_owned(),
            context_id: "ctx-test-001".to_owned(),
            participants: vec!["did:dht:zAlice".to_owned()],
            capabilities: vec!["media:voice".to_owned(), "media:video".to_owned()],
            started_at: 1_700_000_000,
            ended_at: 1_700_003_600,
        };
        let encoded = encode_payload(&p).unwrap();
        // 6-field struct → fixarray of length 6
        assert_positional_array(&encoded.data, 6);
        let decoded: MediaSessionEndedPayload = decode_payload(&encoded).unwrap();
        assert_eq!(p, decoded);
    }

    #[test]
    fn media_session_started_empty_participants_round_trip() {
        // Boundary: empty participant/capability vectors survive the round-trip
        // and still produce a 5-element fixarray.
        let p = MediaSessionStartedPayload {
            session_id: "ms-empty".to_owned(),
            context_id: "ctx-x".to_owned(),
            participants: Vec::new(),
            capabilities: Vec::new(),
            started_at: 0,
        };
        let encoded = encode_payload(&p).unwrap();
        assert_positional_array(&encoded.data, 5);
        let decoded: MediaSessionStartedPayload = decode_payload(&encoded).unwrap();
        assert_eq!(p, decoded);
    }
}
