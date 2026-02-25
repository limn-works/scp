//! Behavioral record computation from event logs.
//!
//! Behavioral records are computed locally from event logs -- not stored
//! centrally. Any agent computes from accessible logs. Two agents may compute
//! different records from different event log views; this is correct behavior,
//! not a bug.
//!
//! `compute_behavioral_record` is pure computation -- no side effects, no
//! storage. It takes a slice of events and a Merkle root (captured at
//! computation time for verifiability) and produces a [`BehavioralRecord`].
//!
//! See ADR-017 in `.docs/adrs/phase-4.md`.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::event_log::{ContextId, DID, Event, EventType};

use super::{AttestationReference, GovernanceActionSummary, RoleTransition, ToolId, TrustError};

// ---------------------------------------------------------------------------
// BehavioralRecord
// ---------------------------------------------------------------------------

/// Verifiable facts computed from context event logs.
///
/// Each field is derived from scanning the event log for entries related to the
/// `subject_did`. The `event_log_root` captures the Merkle root at computation
/// time, enabling other agents to verify that the record was computed from a
/// specific log state.
///
/// See ADR-017 acceptance criterion 1.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehavioralRecord {
    /// The DID whose behavior is summarized.
    pub subject_did: DID,

    /// The context this record was computed from.
    pub context_id: ContextId,

    /// Total number of events produced by the subject in this context.
    pub participation_count: u64,

    /// Duration (seconds) between the subject's first and last event.
    pub participation_duration_seconds: u64,

    /// Tool invocations by tool ID. The tool ID is extracted from the event
    /// payload's first bytes when the event type is `ToolInvoked`.
    pub tool_invocations: HashMap<ToolId, u64>,

    /// Governance actions performed by the subject.
    pub governance_actions_by: Vec<GovernanceActionSummary>,

    /// Governance actions targeting the subject.
    pub governance_actions_against: Vec<GovernanceActionSummary>,

    /// Role assignment history for the subject.
    pub role_history: Vec<RoleTransition>,

    /// Attestation events related to the subject.
    pub attestation_history: Vec<AttestationReference>,

    /// Number of `ContextCreated` events by the subject.
    pub context_creation_count: u64,

    /// Unix timestamp (seconds) when this record was computed.
    pub computed_at: u64,

    /// Merkle root of the event log at computation time.
    pub event_log_root: [u8; 32],
}

// ---------------------------------------------------------------------------
// compute_behavioral_record
// ---------------------------------------------------------------------------

/// Computes a behavioral record for a subject DID from a slice of events.
///
/// This function is pure computation -- no side effects, no storage. It scans
/// all events in the provided slice and extracts behavioral facts for the
/// given `subject_did`.
///
/// # Parameters
///
/// - `events` -- The events to scan. Typically obtained from the event log.
///   The function takes `&[Event]` rather than `&EventLog` because `EventLog`
///   stores only leaf hashes, not full events.
/// - `subject_did` -- The DID to compute the record for.
/// - `context_id` -- The context these events belong to.
/// - `merkle_root` -- The Merkle root at computation time, for verifiability.
/// - `computed_at` -- Unix timestamp (seconds) for when the computation occurs.
///
/// # Errors
///
/// Returns [`TrustError::EmptyEventLog`] if `events` is empty.
///
/// See ADR-017 acceptance criterion 2.
pub fn compute_behavioral_record(
    events: &[Event],
    subject_did: &str,
    context_id: &str,
    merkle_root: [u8; 32],
    computed_at: u64,
) -> Result<BehavioralRecord, TrustError> {
    if events.is_empty() {
        return Err(TrustError::EmptyEventLog);
    }

    let mut participation_count: u64 = 0;
    let mut first_timestamp: Option<u64> = None;
    let mut last_timestamp: Option<u64> = None;
    let mut tool_invocations: HashMap<ToolId, u64> = HashMap::new();
    let mut governance_actions_by: Vec<GovernanceActionSummary> = Vec::new();
    let mut governance_actions_against: Vec<GovernanceActionSummary> = Vec::new();
    let mut role_history: Vec<RoleTransition> = Vec::new();
    let mut attestation_history: Vec<AttestationReference> = Vec::new();
    let mut context_creation_count: u64 = 0;

    for event in events {
        let is_subject = event.actor_did == subject_did;

        if is_subject {
            participation_count += 1;

            // Track first and last timestamps for duration.
            match first_timestamp {
                None => {
                    first_timestamp = Some(event.timestamp);
                    last_timestamp = Some(event.timestamp);
                }
                Some(_) => {
                    last_timestamp = Some(event.timestamp);
                }
            }
        }

        match event.event_type {
            EventType::ToolInvoked if is_subject => {
                let tool_id = extract_tool_id_from_payload(&event.payload.data);
                *tool_invocations.entry(tool_id).or_insert(0) += 1;
            }

            EventType::GovernanceAction => {
                if is_subject {
                    // Subject performed a governance action.
                    governance_actions_by.push(GovernanceActionSummary {
                        timestamp: event.timestamp,
                        actor_did: event.actor_did.clone(),
                        target_did: extract_target_did_from_payload(&event.payload.data),
                        event_sequence: event.sequence,
                    });
                } else {
                    // Check if the subject is the target of this governance action.
                    let target = extract_target_did_from_payload(&event.payload.data);
                    if target.as_deref() == Some(subject_did) {
                        governance_actions_against.push(GovernanceActionSummary {
                            timestamp: event.timestamp,
                            actor_did: event.actor_did.clone(),
                            target_did: target,
                            event_sequence: event.sequence,
                        });
                    }
                }
            }

            EventType::RoleAssigned => {
                // Role assignments where the target is the subject.
                let target = extract_target_did_from_payload(&event.payload.data);
                if target.as_deref() == Some(subject_did) {
                    role_history.push(RoleTransition {
                        timestamp: event.timestamp,
                        event_sequence: event.sequence,
                        assigned_by: event.actor_did.clone(),
                    });
                }
            }

            EventType::ContextCreated if is_subject => {
                context_creation_count += 1;
            }

            // Events that could be attestation-related activity by the subject.
            // In the current event model, there is no dedicated attestation event
            // type. We track any ToolVerified events as attestation-adjacent
            // activity for the subject.
            EventType::ToolVerified if is_subject => {
                attestation_history.push(AttestationReference {
                    timestamp: event.timestamp,
                    event_sequence: event.sequence,
                    actor_did: event.actor_did.clone(),
                });
            }

            _ => {}
        }
    }

    let participation_duration_seconds = match (first_timestamp, last_timestamp) {
        (Some(first), Some(last)) => last.saturating_sub(first),
        _ => 0,
    };

    Ok(BehavioralRecord {
        subject_did: subject_did.to_owned(),
        context_id: context_id.to_owned(),
        participation_count,
        participation_duration_seconds,
        tool_invocations,
        governance_actions_by,
        governance_actions_against,
        role_history,
        attestation_history,
        context_creation_count,
        computed_at,
        event_log_root: merkle_root,
    })
}

// ---------------------------------------------------------------------------
// Payload extraction helpers
// ---------------------------------------------------------------------------

/// Extracts a tool ID from a `ToolInvoked` event payload.
///
/// Convention: the payload data starts with a UTF-8 tool ID string, terminated
/// by a null byte or the end of data. If the payload is empty or not valid
/// UTF-8, returns `"unknown"`.
fn extract_tool_id_from_payload(data: &[u8]) -> ToolId {
    let end = data.iter().position(|&b| b == 0).unwrap_or(data.len());
    std::str::from_utf8(&data[..end])
        .unwrap_or("unknown")
        .to_owned()
}

/// Extracts a target DID from a governance action or role assignment payload.
///
/// Convention: the payload data starts with a UTF-8 target DID string,
/// terminated by a null byte or the end of data. Returns `None` if the
/// payload is empty.
fn extract_target_did_from_payload(data: &[u8]) -> Option<DID> {
    if data.is_empty() {
        return None;
    }
    let end = data.iter().position(|&b| b == 0).unwrap_or(data.len());
    let s = std::str::from_utf8(&data[..end]).ok()?;
    if s.is_empty() {
        return None;
    }
    Some(s.to_owned())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::event_log::EventPayload;

    /// Creates a test event with the given parameters. The signature and
    /// `prev_hash` are set to dummy values since `compute_behavioral_record`
    /// does not verify signatures.
    fn make_event(
        event_type: EventType,
        actor_did: &str,
        timestamp: u64,
        sequence: u64,
        payload: Vec<u8>,
    ) -> Event {
        Event {
            event_type,
            actor_did: actor_did.to_owned(),
            timestamp,
            sequence,
            payload: EventPayload { data: payload },
            prev_hash: [0u8; 32],
            signature: vec![0u8; 64],
        }
    }

    #[test]
    fn compute_returns_error_for_empty_events() {
        let result = compute_behavioral_record(&[], "did:key:alice", "ctx-1", [0u8; 32], 100);
        assert!(result.is_err());
        match result {
            Err(TrustError::EmptyEventLog) => {}
            other => panic!("expected EmptyEventLog, got {other:?}"),
        }
    }

    #[test]
    fn compute_counts_participation() {
        let events = vec![
            make_event(EventType::MessageSent, "did:key:alice", 1000, 0, vec![]),
            make_event(EventType::MessageSent, "did:key:alice", 1001, 1, vec![]),
            make_event(EventType::MessageSent, "did:key:bob", 1002, 2, vec![]),
            make_event(EventType::MessageSent, "did:key:alice", 1005, 3, vec![]),
        ];

        let record =
            compute_behavioral_record(&events, "did:key:alice", "ctx-1", [1u8; 32], 2000).unwrap();

        assert_eq!(record.subject_did, "did:key:alice");
        assert_eq!(record.context_id, "ctx-1");
        assert_eq!(record.participation_count, 3);
        assert_eq!(record.participation_duration_seconds, 5); // 1005 - 1000
        assert_eq!(record.computed_at, 2000);
        assert_eq!(record.event_log_root, [1u8; 32]);
    }

    #[test]
    fn compute_tracks_tool_invocations() {
        let events = vec![
            make_event(
                EventType::ToolInvoked,
                "did:key:alice",
                1000,
                0,
                b"tool-search\0extra".to_vec(),
            ),
            make_event(
                EventType::ToolInvoked,
                "did:key:alice",
                1001,
                1,
                b"tool-search".to_vec(),
            ),
            make_event(
                EventType::ToolInvoked,
                "did:key:alice",
                1002,
                2,
                b"tool-execute".to_vec(),
            ),
            make_event(
                EventType::ToolInvoked,
                "did:key:bob",
                1003,
                3,
                b"tool-search".to_vec(),
            ),
        ];

        let record =
            compute_behavioral_record(&events, "did:key:alice", "ctx-1", [0u8; 32], 2000).unwrap();

        assert_eq!(record.tool_invocations.len(), 2);
        assert_eq!(record.tool_invocations.get("tool-search"), Some(&2));
        assert_eq!(record.tool_invocations.get("tool-execute"), Some(&1));
    }

    #[test]
    fn compute_tracks_governance_actions_by_subject() {
        let events = vec![
            make_event(
                EventType::GovernanceAction,
                "did:key:alice",
                1000,
                0,
                b"did:key:bob".to_vec(),
            ),
            make_event(
                EventType::GovernanceAction,
                "did:key:alice",
                1001,
                1,
                vec![],
            ),
        ];

        let record =
            compute_behavioral_record(&events, "did:key:alice", "ctx-1", [0u8; 32], 2000).unwrap();

        assert_eq!(record.governance_actions_by.len(), 2);
        assert_eq!(record.governance_actions_by[0].event_sequence, 0);
        assert_eq!(
            record.governance_actions_by[0].target_did,
            Some("did:key:bob".to_owned())
        );
        // Second action has empty payload -> no target.
        assert_eq!(record.governance_actions_by[1].target_did, None);
    }

    #[test]
    fn compute_tracks_governance_actions_against_subject() {
        let events = vec![
            make_event(
                EventType::GovernanceAction,
                "did:key:admin",
                1000,
                0,
                b"did:key:alice".to_vec(),
            ),
            make_event(
                EventType::GovernanceAction,
                "did:key:admin",
                1001,
                1,
                b"did:key:bob".to_vec(),
            ),
        ];

        let record =
            compute_behavioral_record(&events, "did:key:alice", "ctx-1", [0u8; 32], 2000).unwrap();

        // Only the first governance action targets alice.
        assert_eq!(record.governance_actions_against.len(), 1);
        assert_eq!(
            record.governance_actions_against[0].actor_did,
            "did:key:admin"
        );
        assert_eq!(record.governance_actions_against[0].event_sequence, 0);
    }

    #[test]
    fn compute_tracks_role_history() {
        let events = vec![
            make_event(
                EventType::RoleAssigned,
                "did:key:admin",
                1000,
                0,
                b"did:key:alice".to_vec(),
            ),
            make_event(
                EventType::RoleAssigned,
                "did:key:admin",
                1005,
                1,
                b"did:key:alice".to_vec(),
            ),
            make_event(
                EventType::RoleAssigned,
                "did:key:admin",
                1010,
                2,
                b"did:key:bob".to_vec(),
            ),
        ];

        let record =
            compute_behavioral_record(&events, "did:key:alice", "ctx-1", [0u8; 32], 2000).unwrap();

        assert_eq!(record.role_history.len(), 2);
        assert_eq!(record.role_history[0].timestamp, 1000);
        assert_eq!(record.role_history[0].assigned_by, "did:key:admin");
        assert_eq!(record.role_history[1].timestamp, 1005);
    }

    #[test]
    fn compute_tracks_context_creation() {
        let events = vec![
            make_event(EventType::ContextCreated, "did:key:alice", 1000, 0, vec![]),
            make_event(EventType::ContextCreated, "did:key:bob", 1001, 1, vec![]),
            make_event(EventType::ContextCreated, "did:key:alice", 1002, 2, vec![]),
        ];

        let record =
            compute_behavioral_record(&events, "did:key:alice", "ctx-1", [0u8; 32], 2000).unwrap();

        assert_eq!(record.context_creation_count, 2);
    }

    #[test]
    fn compute_tracks_attestation_history() {
        let events = vec![
            make_event(EventType::ToolVerified, "did:key:alice", 1000, 0, vec![]),
            make_event(EventType::ToolVerified, "did:key:bob", 1001, 1, vec![]),
        ];

        let record =
            compute_behavioral_record(&events, "did:key:alice", "ctx-1", [0u8; 32], 2000).unwrap();

        assert_eq!(record.attestation_history.len(), 1);
        assert_eq!(record.attestation_history[0].timestamp, 1000);
        assert_eq!(record.attestation_history[0].actor_did, "did:key:alice");
    }

    #[test]
    fn compute_returns_zero_duration_for_single_event() {
        let events = vec![make_event(
            EventType::MessageSent,
            "did:key:alice",
            1000,
            0,
            vec![],
        )];

        let record =
            compute_behavioral_record(&events, "did:key:alice", "ctx-1", [0u8; 32], 2000).unwrap();

        assert_eq!(record.participation_count, 1);
        assert_eq!(record.participation_duration_seconds, 0);
    }

    #[test]
    fn compute_handles_subject_with_no_matching_events() {
        let events = vec![
            make_event(EventType::MessageSent, "did:key:bob", 1000, 0, vec![]),
            make_event(EventType::MessageSent, "did:key:bob", 1001, 1, vec![]),
        ];

        let record =
            compute_behavioral_record(&events, "did:key:alice", "ctx-1", [0u8; 32], 2000).unwrap();

        // Record is valid but all counts are zero.
        assert_eq!(record.participation_count, 0);
        assert_eq!(record.participation_duration_seconds, 0);
        assert!(record.tool_invocations.is_empty());
        assert!(record.governance_actions_by.is_empty());
        assert!(record.governance_actions_against.is_empty());
        assert!(record.role_history.is_empty());
        assert!(record.attestation_history.is_empty());
        assert_eq!(record.context_creation_count, 0);
    }

    #[test]
    fn compute_captures_merkle_root() {
        let events = vec![make_event(
            EventType::MessageSent,
            "did:key:alice",
            1000,
            0,
            vec![],
        )];

        let merkle_root = [42u8; 32];
        let record =
            compute_behavioral_record(&events, "did:key:alice", "ctx-1", merkle_root, 2000)
                .unwrap();

        assert_eq!(record.event_log_root, merkle_root);
    }

    #[test]
    fn compute_full_scenario() {
        // Simulate a realistic event sequence.
        let events = vec![
            make_event(EventType::ContextCreated, "did:key:alice", 1000, 0, vec![]),
            make_event(EventType::MemberJoined, "did:key:alice", 1001, 1, vec![]),
            make_event(EventType::MemberJoined, "did:key:bob", 1002, 2, vec![]),
            make_event(
                EventType::RoleAssigned,
                "did:key:alice",
                1003,
                3,
                b"did:key:bob".to_vec(),
            ),
            make_event(
                EventType::MessageSent,
                "did:key:alice",
                1004,
                4,
                b"hello".to_vec(),
            ),
            make_event(
                EventType::MessageSent,
                "did:key:bob",
                1005,
                5,
                b"hi".to_vec(),
            ),
            make_event(
                EventType::ToolInvoked,
                "did:key:alice",
                1006,
                6,
                b"search-tool".to_vec(),
            ),
            make_event(
                EventType::ToolInvoked,
                "did:key:alice",
                1007,
                7,
                b"search-tool".to_vec(),
            ),
            make_event(
                EventType::GovernanceAction,
                "did:key:alice",
                1008,
                8,
                b"did:key:bob".to_vec(),
            ),
            make_event(EventType::ToolVerified, "did:key:alice", 1009, 9, vec![]),
        ];

        let record =
            compute_behavioral_record(&events, "did:key:alice", "ctx-1", [99u8; 32], 5000).unwrap();

        assert_eq!(record.participation_count, 8); // All events except bob's
        assert_eq!(record.participation_duration_seconds, 9); // 1009 - 1000
        assert_eq!(record.tool_invocations.get("search-tool"), Some(&2));
        assert_eq!(record.governance_actions_by.len(), 1);
        assert_eq!(record.governance_actions_against.len(), 0);
        assert_eq!(record.role_history.len(), 0); // Alice assigned bob, not herself
        assert_eq!(record.attestation_history.len(), 1);
        assert_eq!(record.context_creation_count, 1);
        assert_eq!(record.computed_at, 5000);
        assert_eq!(record.event_log_root, [99u8; 32]);
    }

    #[test]
    fn extract_tool_id_handles_null_terminated() {
        assert_eq!(
            extract_tool_id_from_payload(b"my-tool\0extra-data"),
            "my-tool"
        );
    }

    #[test]
    fn extract_tool_id_handles_no_null() {
        assert_eq!(extract_tool_id_from_payload(b"my-tool"), "my-tool");
    }

    #[test]
    fn extract_tool_id_handles_empty() {
        assert_eq!(extract_tool_id_from_payload(b""), "");
    }

    #[test]
    fn extract_target_did_handles_empty_payload() {
        assert_eq!(extract_target_did_from_payload(b""), None);
    }

    #[test]
    fn extract_target_did_handles_valid_did() {
        assert_eq!(
            extract_target_did_from_payload(b"did:key:alice"),
            Some("did:key:alice".to_owned())
        );
    }

    #[test]
    fn extract_target_did_handles_null_terminated() {
        assert_eq!(
            extract_target_did_from_payload(b"did:key:alice\0extra"),
            Some("did:key:alice".to_owned())
        );
    }
}
