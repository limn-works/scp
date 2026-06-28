//! Per-variant structured payload encoders for [`EventType`](crate::EventType).
//!
//! # Why this module exists
//!
//! Several runtime call sites historically baked event parameters into the
//! event *name* — either as `format!` strings
//! (`"ContextTombstoned:{dest}:{pid}"`) or as an entire JSON blob used as the
//! type tag (`{"event":"SpendApproved",…}`). The ADR-011 native↔WASM
//! unification amendment (`.docs/adrs/phase-2.md`) identifies each as a defect:
//! it makes the signed Merkle-leaf preimage non-convergent and un-enumerable.
//! The correct end state is a typed [`EventType`](crate::EventType) variant
//! whose parameters live in [`EventPayload`](crate::EventPayload).
//!
//! This module is the **single source** of the payload bytes for those
//! structured variants. As the emit sites are wired (in later phases of the
//! native↔WASM unification — Phase 1 establishes the types; production callers
//! land later), both the native runtime (`scp-runtime`) and the WASM bridge
//! MUST route through these functions so that native↔WASM Merkle roots match:
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
/// This is the single shared entry point that both native and WASM callers use
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
/// [`EventType::GovernanceActionExecuted`](crate::EventType::GovernanceActionExecuted)
/// (ADR-031 §8; PRD SCP-269/SCP-270).
///
/// `target_did` is the member the action targeted (empty when the action has
/// no target, e.g. a context-wide policy change). `action_type` is the
/// `GovernanceAction` variant name. The consequence engine reads `target_did`
/// for the `WarningCount` trigger and `action_type` for participation records.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernanceActionExecutedPayload {
    /// The DID the executed action targeted (empty if the action is untargeted).
    pub target_did: String,
    /// The `GovernanceAction` variant name (e.g. `"RemoveMember"`).
    pub action_type: String,
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
/// Both the native runtime (`scp-runtime`) and the WASM bridge (`scp-ffi-wasm`)
/// mint these leaves for convergent-trigger consequences. The leaf preimage is
/// `SHA-256(0x00 ‖ rmp_serde(Event))`, and `Event.payload` is
/// `EventPayload { data }` — so the `data` bytes MUST be byte-identical across
/// platforms or §9.9.3 equivocation detection produces false positives. This
/// function is the shared producer of those bytes.
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
/// `serde_json`, same default features on both native and WASM), which is exactly
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
/// single shared decode surface so that all four bridges (`PyO3`, NAPI,
/// `UniFFI`, WASM) project byte-identical values for the same event — the
/// cross-bridge parity contract. WASM links `scp-event-log` (not
/// `scp-ffi-common`), so this must live here per ADR-034.
///
/// Fields default to `None`; only variants that carry the field decode it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EventPayloadProjection {
    /// The target DID for events that carry one (governance actions, access
    /// revocation); `None` otherwise. An empty `target_did` in the underlying
    /// payload (e.g. an untargeted, context-wide governance action) projects to
    /// `None` so consumers do not key participation facts on an empty subject.
    pub target_did: Option<String>,
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
        },
        EventType::AccessRevoked => EventPayloadProjection {
            target_did: decode_payload::<AccessRevokedPayload>(payload)
                .ok()
                .and_then(|p| non_empty(p.target_did)),
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
            capabilities: vec!["tool:invoke:*".to_owned(), "message:send".to_owned()],
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
    fn access_revoked_round_trip() {
        let p = AccessRevokedPayload {
            target_did: "did:key:alice".to_owned(),
        };
        let encoded = encode_payload(&p).unwrap();
        assert_positional_array(&encoded.data, 1);
        let decoded: AccessRevokedPayload = decode_payload(&encoded).unwrap();
        assert_eq!(p, decoded);
    }

    #[test]
    fn governance_action_executed_round_trip() {
        let p = GovernanceActionExecutedPayload {
            target_did: "did:key:bob".to_owned(),
            action_type: "RemoveMember".to_owned(),
        };
        let encoded = encode_payload(&p).unwrap();
        assert_positional_array(&encoded.data, 2);
        let decoded: GovernanceActionExecutedPayload = decode_payload(&encoded).unwrap();
        assert_eq!(p, decoded);
    }

    #[test]
    fn governance_action_executed_empty_target_round_trip() {
        // Untargeted actions (e.g. context-wide policy changes) carry an empty
        // target_did but must still round-trip and stay a 2-element fixarray.
        let p = GovernanceActionExecutedPayload {
            target_did: String::new(),
            action_type: "ModifyPolicy".to_owned(),
        };
        let encoded = encode_payload(&p).unwrap();
        assert_positional_array(&encoded.data, 2);
        let decoded: GovernanceActionExecutedPayload = decode_payload(&encoded).unwrap();
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
        };
        let encoded = encode_payload(&p).unwrap();
        let projection = project_payload(&EventType::ContextCreated, &encoded);
        assert_eq!(projection, EventPayloadProjection::default());
        assert_eq!(projection.target_did, None);
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
    }

    #[test]
    fn project_empty_payload_yields_none_without_panic() {
        let empty = EventPayload::default();
        let governance = project_payload(&EventType::GovernanceActionExecuted, &empty);
        assert_eq!(governance.target_did, None);
        let revoked = project_payload(&EventType::AccessRevoked, &empty);
        assert_eq!(revoked.target_did, None);
    }
}
