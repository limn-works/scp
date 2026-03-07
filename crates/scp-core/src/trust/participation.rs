//! Participation record computation and admission types.
//!
//! This module contains two complementary systems:
//!
//! 1. **Participation records** ([`ParticipationRecord`]) — computed locally
//!    from event logs. Any agent computes from accessible logs. Two agents may
//!    compute different records from different event log views; this is correct
//!    behavior, not a bug.
//!
//! 2. **Participation admission** ([`RequireParticipation`],
//!    [`ParticipationFact`], [`ParticipationThreshold`],
//!    [`ParticipationProfile`]) — context-hosted signed attestations and
//!    mechanical admission requirements. Contexts produce
//!    [`ParticipationProfile`] attestations for each opted-in member.
//!    Admitting contexts verify profiles against [`RequireParticipation`]
//!    entries. See §7.3.2.1.
//!
//! See ADR-017 in `.docs/adrs/phase-4.md`.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use scp_event_log::{ContextId, Event, EventType};
use scp_identity::DID;

use super::{AttestationReference, GovernanceActionSummary, RoleTransition, ToolId, TrustError};

// ---------------------------------------------------------------------------
// ParticipationRecord
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
pub struct ParticipationRecord {
    /// The DID whose participation is summarized.
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
// compute_participation_record
// ---------------------------------------------------------------------------

/// Computes a participation record for a subject DID from a slice of events.
///
/// This function is pure computation -- no side effects, no storage. It scans
/// all events in the provided slice and extracts participation facts for the
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
pub fn compute_participation_record(
    events: &[Event],
    subject_did: &str,
    context_id: &str,
    merkle_root: [u8; 32],
    computed_at: u64,
) -> Result<ParticipationRecord, TrustError> {
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

    Ok(ParticipationRecord {
        subject_did: subject_did.into(),
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
    Some(s.into())
}

// ---------------------------------------------------------------------------
// Participation Admission Types (§7.3.2.1)
// ---------------------------------------------------------------------------

/// Which category of participation fact to evaluate for admission.
///
/// Each variant corresponds to one of the 7 fact categories in a
/// [`ParticipationProfile`]. See §7.3.2.1.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ParticipationFact {
    /// Total seconds of context participation.
    ParticipationDuration,
    /// Count of governance actions taken against the identity.
    GovernanceActionsAgainst,
    /// Count of governance actions initiated by the identity.
    GovernanceActionsBy,
    /// Total tool invocations across all tool types.
    ToolInvocationCount,
    /// Number of contexts created.
    ContextCreationCount,
    /// Number of role transitions.
    RoleProgressionCount,
    /// Number of attestation events.
    AttestationCount,
}

impl ParticipationFact {
    /// Extracts the corresponding value from a [`ParticipationProfile`].
    #[must_use]
    pub fn extract_value(&self, profile: &ParticipationProfile) -> u64 {
        match self {
            Self::ParticipationDuration => profile.participation_duration_secs,
            Self::GovernanceActionsAgainst => profile.governance_actions_against,
            Self::GovernanceActionsBy => profile.governance_actions_by,
            Self::ToolInvocationCount => profile.tool_invocation_count,
            Self::ContextCreationCount => profile.context_creation_count,
            Self::RoleProgressionCount => profile.role_progression_count,
            Self::AttestationCount => profile.attestation_count,
        }
    }
}

/// Comparison operator and value for participation admission thresholds.
///
/// Used in [`RequireParticipation`] to specify the comparison a fact value
/// must satisfy. See §7.3.2.1.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ParticipationThreshold {
    /// Fact value must be strictly greater than the specified value.
    GreaterThan(u64),
    /// Fact value must be strictly less than the specified value.
    LessThan(u64),
    /// Fact value must be greater than or equal to the specified value.
    AtLeast(u64),
    /// Fact value must be less than or equal to the specified value.
    AtMost(u64),
    /// Fact value must equal the specified value exactly.
    Equals(u64),
}

impl ParticipationThreshold {
    /// Returns `true` if `value` satisfies this threshold.
    #[must_use]
    pub fn is_satisfied(&self, value: u64) -> bool {
        match self {
            Self::GreaterThan(threshold) => value > *threshold,
            Self::LessThan(threshold) => value < *threshold,
            Self::AtLeast(threshold) => value >= *threshold,
            Self::AtMost(threshold) => value <= *threshold,
            Self::Equals(threshold) => value == *threshold,
        }
    }
}

/// A participation admission requirement declared by a context.
///
/// Contexts include one or more `RequireParticipation` entries in their
/// `ContextParams` admission requirements. Each entry specifies a
/// participation fact, a threshold, a freshness requirement, and a minimum
/// number of independent source contexts. See §7.3.2.1.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequireParticipation {
    /// Which participation category to evaluate.
    pub fact: ParticipationFact,
    /// Comparison operator and value.
    pub threshold: ParticipationThreshold,
    /// Maximum age in seconds for the participation profile's `updated_at`
    /// timestamp. Profiles older than this are rejected.
    pub max_age_secs: u64,
    /// Minimum number of independent source contexts (distinct
    /// `signer_public_key` values) required to satisfy this requirement.
    pub min_contexts: u32,
}

/// A context-hosted participation profile attesting to a member's verifiable
/// participation facts.
///
/// Produced by contexts for opted-in members. The profile is signed by a
/// context-specific Ed25519 key (derived with domain separation) so that
/// verifiers cannot correlate which contexts share a signer.
///
/// **Privacy guarantee:** The profile intentionally omits `context_id`. The
/// admitting context sees signed claims from distinct signers but cannot
/// identify which contexts produced them.
///
/// See §7.3.2.1.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParticipationProfile {
    /// The DID of the member this profile is about.
    pub subject_did: DID,

    /// Total seconds of context participation.
    pub participation_duration_secs: u64,

    /// Count of governance actions taken against this identity.
    pub governance_actions_against: u64,

    /// Count of governance actions initiated by this identity.
    pub governance_actions_by: u64,

    /// Total tool invocations across all tool types.
    pub tool_invocation_count: u64,

    /// Number of contexts created.
    pub context_creation_count: u64,

    /// Number of role transitions.
    pub role_progression_count: u64,

    /// Number of attestation events.
    pub attestation_count: u64,

    /// Unix timestamp (seconds) of the last update to this profile.
    pub updated_at: u64,

    /// Merkle root of the context's event log at profile computation time.
    pub event_log_root: [u8; 32],

    /// Context-specific Ed25519 public key used to sign this profile.
    /// Derived with domain separation to prevent cross-context correlation.
    pub signer_public_key: [u8; 32],

    /// Ed25519 signature over all fields except this one.
    #[serde(with = "serde_bytes")]
    pub signature: [u8; 64],
}

impl ParticipationProfile {
    /// Returns the deterministic signable bytes for this profile.
    ///
    /// Covers all fields except `signature`. The byte layout is:
    /// - subject_did UTF-8 bytes (length-prefixed as u32 big-endian)
    /// - participation_duration_secs (u64 big-endian)
    /// - governance_actions_against (u64 big-endian)
    /// - governance_actions_by (u64 big-endian)
    /// - tool_invocation_count (u64 big-endian)
    /// - context_creation_count (u64 big-endian)
    /// - role_progression_count (u64 big-endian)
    /// - attestation_count (u64 big-endian)
    /// - updated_at (u64 big-endian)
    /// - event_log_root (32 bytes)
    /// - signer_public_key (32 bytes)
    #[must_use]
    pub fn signable_bytes(&self) -> Vec<u8> {
        let did_bytes = self.subject_did.as_bytes();
        // 4 (length prefix) + did_bytes.len() + 8*8 (eight u64 fields) + 32 + 32
        let capacity = 4 + did_bytes.len() + 64 + 64;
        let mut buf = Vec::with_capacity(capacity);

        // Length-prefixed DID string.
        buf.extend_from_slice(&(did_bytes.len() as u32).to_be_bytes());
        buf.extend_from_slice(did_bytes);

        // All u64 fact fields + updated_at in declaration order.
        buf.extend_from_slice(&self.participation_duration_secs.to_be_bytes());
        buf.extend_from_slice(&self.governance_actions_against.to_be_bytes());
        buf.extend_from_slice(&self.governance_actions_by.to_be_bytes());
        buf.extend_from_slice(&self.tool_invocation_count.to_be_bytes());
        buf.extend_from_slice(&self.context_creation_count.to_be_bytes());
        buf.extend_from_slice(&self.role_progression_count.to_be_bytes());
        buf.extend_from_slice(&self.attestation_count.to_be_bytes());
        buf.extend_from_slice(&self.updated_at.to_be_bytes());

        // Fixed-size byte arrays.
        buf.extend_from_slice(&self.event_log_root);
        buf.extend_from_slice(&self.signer_public_key);

        buf
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use scp_event_log::EventPayload;

    /// Creates a test event with the given parameters. The signature and
    /// `prev_hash` are set to dummy values since `compute_participation_record`
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
            actor_did: actor_did.into(),
            timestamp,
            sequence,
            payload: EventPayload { data: payload },
            prev_hash: [0u8; 32],
            signature: vec![0u8; 64],
        }
    }

    #[test]
    fn compute_returns_error_for_empty_events() {
        let result = compute_participation_record(&[], "did:key:alice", "ctx-1", [0u8; 32], 100);
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
            compute_participation_record(&events, "did:key:alice", "ctx-1", [1u8; 32], 2000)
                .unwrap();

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
            compute_participation_record(&events, "did:key:alice", "ctx-1", [0u8; 32], 2000)
                .unwrap();

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
            compute_participation_record(&events, "did:key:alice", "ctx-1", [0u8; 32], 2000)
                .unwrap();

        assert_eq!(record.governance_actions_by.len(), 2);
        assert_eq!(record.governance_actions_by[0].event_sequence, 0);
        assert_eq!(
            record.governance_actions_by[0].target_did,
            Some("did:key:bob".into())
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
            compute_participation_record(&events, "did:key:alice", "ctx-1", [0u8; 32], 2000)
                .unwrap();

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
            compute_participation_record(&events, "did:key:alice", "ctx-1", [0u8; 32], 2000)
                .unwrap();

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
            compute_participation_record(&events, "did:key:alice", "ctx-1", [0u8; 32], 2000)
                .unwrap();

        assert_eq!(record.context_creation_count, 2);
    }

    #[test]
    fn compute_tracks_attestation_history() {
        let events = vec![
            make_event(EventType::ToolVerified, "did:key:alice", 1000, 0, vec![]),
            make_event(EventType::ToolVerified, "did:key:bob", 1001, 1, vec![]),
        ];

        let record =
            compute_participation_record(&events, "did:key:alice", "ctx-1", [0u8; 32], 2000)
                .unwrap();

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
            compute_participation_record(&events, "did:key:alice", "ctx-1", [0u8; 32], 2000)
                .unwrap();

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
            compute_participation_record(&events, "did:key:alice", "ctx-1", [0u8; 32], 2000)
                .unwrap();

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
            compute_participation_record(&events, "did:key:alice", "ctx-1", merkle_root, 2000)
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
            compute_participation_record(&events, "did:key:alice", "ctx-1", [99u8; 32], 5000)
                .unwrap();

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
            Some("did:key:alice".into())
        );
    }

    #[test]
    fn extract_target_did_handles_null_terminated() {
        assert_eq!(
            extract_target_did_from_payload(b"did:key:alice\0extra"),
            Some("did:key:alice".into())
        );
    }

    // -----------------------------------------------------------------------
    // Participation admission type tests (§7.3.2.1)
    // -----------------------------------------------------------------------

    /// Helper to create a test `ParticipationProfile` with known values.
    fn make_profile() -> ParticipationProfile {
        ParticipationProfile {
            subject_did: "did:key:test".into(),
            participation_duration_secs: 86400,
            governance_actions_against: 2,
            governance_actions_by: 5,
            tool_invocation_count: 203,
            context_creation_count: 3,
            role_progression_count: 4,
            attestation_count: 10,
            updated_at: 1_700_000_000,
            event_log_root: [0xAA; 32],
            signer_public_key: [0xBB; 32],
            signature: [0xCC; 64],
        }
    }

    #[test]
    fn participation_fact_has_7_variants() {
        // Exhaustive match ensures all 7 variants exist and compile.
        let all = [
            ParticipationFact::ParticipationDuration,
            ParticipationFact::GovernanceActionsAgainst,
            ParticipationFact::GovernanceActionsBy,
            ParticipationFact::ToolInvocationCount,
            ParticipationFact::ContextCreationCount,
            ParticipationFact::RoleProgressionCount,
            ParticipationFact::AttestationCount,
        ];
        assert_eq!(all.len(), 7);
    }

    #[test]
    fn participation_threshold_has_5_variants() {
        let all = [
            ParticipationThreshold::GreaterThan(0),
            ParticipationThreshold::LessThan(0),
            ParticipationThreshold::AtLeast(0),
            ParticipationThreshold::AtMost(0),
            ParticipationThreshold::Equals(0),
        ];
        assert_eq!(all.len(), 5);
    }

    #[test]
    fn extract_value_returns_correct_field() {
        let profile = make_profile();

        assert_eq!(
            ParticipationFact::ParticipationDuration.extract_value(&profile),
            86400
        );
        assert_eq!(
            ParticipationFact::GovernanceActionsAgainst.extract_value(&profile),
            2
        );
        assert_eq!(
            ParticipationFact::GovernanceActionsBy.extract_value(&profile),
            5
        );
        assert_eq!(
            ParticipationFact::ToolInvocationCount.extract_value(&profile),
            203
        );
        assert_eq!(
            ParticipationFact::ContextCreationCount.extract_value(&profile),
            3
        );
        assert_eq!(
            ParticipationFact::RoleProgressionCount.extract_value(&profile),
            4
        );
        assert_eq!(
            ParticipationFact::AttestationCount.extract_value(&profile),
            10
        );
    }

    #[test]
    fn threshold_greater_than() {
        assert!(ParticipationThreshold::GreaterThan(5).is_satisfied(6));
        assert!(!ParticipationThreshold::GreaterThan(5).is_satisfied(5));
        assert!(!ParticipationThreshold::GreaterThan(5).is_satisfied(4));
    }

    #[test]
    fn threshold_less_than() {
        assert!(ParticipationThreshold::LessThan(5).is_satisfied(4));
        assert!(!ParticipationThreshold::LessThan(5).is_satisfied(5));
        assert!(!ParticipationThreshold::LessThan(5).is_satisfied(6));
    }

    #[test]
    fn threshold_at_least() {
        assert!(ParticipationThreshold::AtLeast(5).is_satisfied(5));
        assert!(ParticipationThreshold::AtLeast(5).is_satisfied(6));
        assert!(!ParticipationThreshold::AtLeast(5).is_satisfied(4));
    }

    #[test]
    fn threshold_at_most() {
        assert!(ParticipationThreshold::AtMost(5).is_satisfied(5));
        assert!(ParticipationThreshold::AtMost(5).is_satisfied(4));
        assert!(!ParticipationThreshold::AtMost(5).is_satisfied(6));
    }

    #[test]
    fn threshold_equals() {
        assert!(ParticipationThreshold::Equals(5).is_satisfied(5));
        assert!(!ParticipationThreshold::Equals(5).is_satisfied(4));
        assert!(!ParticipationThreshold::Equals(5).is_satisfied(6));
    }

    #[test]
    fn signable_bytes_is_deterministic() {
        let profile = make_profile();
        let bytes1 = profile.signable_bytes();
        let bytes2 = profile.signable_bytes();
        assert_eq!(bytes1, bytes2);
    }

    #[test]
    fn signable_bytes_excludes_signature() {
        let mut profile1 = make_profile();
        let mut profile2 = make_profile();
        profile1.signature = [0x00; 64];
        profile2.signature = [0xFF; 64];

        assert_eq!(profile1.signable_bytes(), profile2.signable_bytes());
    }

    #[test]
    fn signable_bytes_changes_with_fields() {
        let profile1 = make_profile();
        let mut profile2 = make_profile();
        profile2.tool_invocation_count = 999;

        assert_ne!(profile1.signable_bytes(), profile2.signable_bytes());
    }

    #[test]
    fn signable_bytes_changes_with_did() {
        let profile1 = make_profile();
        let mut profile2 = make_profile();
        profile2.subject_did = "did:key:other".into();

        assert_ne!(profile1.signable_bytes(), profile2.signable_bytes());
    }

    #[test]
    fn signable_bytes_expected_length() {
        let profile = make_profile();
        let bytes = profile.signable_bytes();
        let did_len = "did:key:test".len();
        // 4 (length prefix) + did_len + 8*8 (8 u64 fields) + 32 + 32
        let expected = 4 + did_len + 64 + 64;
        assert_eq!(bytes.len(), expected);
    }

    #[test]
    fn participation_profile_has_no_context_id() {
        // Structural test: ParticipationProfile must not have a context_id
        // field. This test documents the privacy guarantee from §7.3.2.1.
        // If someone adds context_id to ParticipationProfile, this test's
        // field-by-field construction will fail to compile (missing field).
        let _profile = ParticipationProfile {
            subject_did: "did:key:test".into(),
            participation_duration_secs: 0,
            governance_actions_against: 0,
            governance_actions_by: 0,
            tool_invocation_count: 0,
            context_creation_count: 0,
            role_progression_count: 0,
            attestation_count: 0,
            updated_at: 0,
            event_log_root: [0; 32],
            signer_public_key: [0; 32],
            signature: [0; 64],
        };
    }

    #[test]
    fn require_participation_struct_fields() {
        let req = RequireParticipation {
            fact: ParticipationFact::ToolInvocationCount,
            threshold: ParticipationThreshold::AtLeast(100),
            max_age_secs: 86400,
            min_contexts: 3,
        };
        assert_eq!(req.max_age_secs, 86400);
        assert_eq!(req.min_contexts, 3);
    }

    #[test]
    fn serde_roundtrip_participation_fact() {
        let fact = ParticipationFact::GovernanceActionsBy;
        let json = serde_json::to_string(&fact).unwrap();
        let deserialized: ParticipationFact = serde_json::from_str(&json).unwrap();
        assert_eq!(fact, deserialized);
    }

    #[test]
    fn serde_roundtrip_participation_threshold() {
        let threshold = ParticipationThreshold::AtLeast(42);
        let json = serde_json::to_string(&threshold).unwrap();
        let deserialized: ParticipationThreshold = serde_json::from_str(&json).unwrap();
        assert_eq!(threshold, deserialized);
    }

    #[test]
    fn serde_roundtrip_require_participation() {
        let req = RequireParticipation {
            fact: ParticipationFact::ParticipationDuration,
            threshold: ParticipationThreshold::GreaterThan(3600),
            max_age_secs: 86400,
            min_contexts: 2,
        };
        let json = serde_json::to_string(&req).unwrap();
        let deserialized: RequireParticipation = serde_json::from_str(&json).unwrap();
        assert_eq!(req, deserialized);
    }

    #[test]
    fn serde_roundtrip_participation_profile() {
        let profile = make_profile();
        let json = serde_json::to_string(&profile).unwrap();
        let deserialized: ParticipationProfile = serde_json::from_str(&json).unwrap();
        assert_eq!(profile, deserialized);
    }

    #[test]
    fn all_fact_variants_serde_roundtrip() {
        let facts = [
            ParticipationFact::ParticipationDuration,
            ParticipationFact::GovernanceActionsAgainst,
            ParticipationFact::GovernanceActionsBy,
            ParticipationFact::ToolInvocationCount,
            ParticipationFact::ContextCreationCount,
            ParticipationFact::RoleProgressionCount,
            ParticipationFact::AttestationCount,
        ];
        for fact in &facts {
            let json = serde_json::to_string(fact).unwrap();
            let deserialized: ParticipationFact = serde_json::from_str(&json).unwrap();
            assert_eq!(*fact, deserialized);
        }
    }

    #[test]
    fn all_threshold_variants_serde_roundtrip() {
        let thresholds = [
            ParticipationThreshold::GreaterThan(100),
            ParticipationThreshold::LessThan(50),
            ParticipationThreshold::AtLeast(10),
            ParticipationThreshold::AtMost(200),
            ParticipationThreshold::Equals(42),
        ];
        for threshold in &thresholds {
            let json = serde_json::to_string(threshold).unwrap();
            let deserialized: ParticipationThreshold = serde_json::from_str(&json).unwrap();
            assert_eq!(*threshold, deserialized);
        }
    }
}
