//! Participation record computation and participation admission types.
//!
//! This module contains two distinct concerns:
//!
//! 1. **Participation records** — computed locally from event logs, not stored
//!    centrally. Any agent computes from accessible logs. Two agents may compute
//!    different records from different event log views; this is correct behavior,
//!    not a bug. See [`ParticipationRecord`] and [`compute_participation_record`].
//!
//! 2. **Participation admission** — types for context admission requirements
//!    and signed participation profiles. Contexts produce [`ParticipationProfile`]
//!    attestations for members, signed with context-specific Ed25519 keys derived
//!    via HKDF with domain separation. Verifiers check these profiles without
//!    learning which contexts produced them. See §7.3.2.1.
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
// ParticipationFact — which participation category to check (§7.3.2.1)
// ---------------------------------------------------------------------------

/// A participation fact category used in admission requirements.
///
/// Each variant corresponds to a field in [`ParticipationProfile`]. Contexts
/// declare which facts to check and what thresholds to require.
///
/// See §7.3.2.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ParticipationFact {
    /// Total seconds of context participation (`participation_duration_secs`).
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
    /// Extracts the value of this fact from a [`ParticipationProfile`].
    #[must_use]
    pub const fn extract_value(&self, profile: &ParticipationProfile) -> u64 {
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

// ---------------------------------------------------------------------------
// ParticipationThreshold — comparison operators for admission (§7.3.2.1)
// ---------------------------------------------------------------------------

/// Comparison operator for participation admission requirements.
///
/// See §7.3.2.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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
    pub const fn is_satisfied(&self, value: u64) -> bool {
        match self {
            Self::GreaterThan(t) => value > *t,
            Self::LessThan(t) => value < *t,
            Self::AtLeast(t) => value >= *t,
            Self::AtMost(t) => value <= *t,
            Self::Equals(t) => value == *t,
        }
    }
}

// ---------------------------------------------------------------------------
// RequireParticipation — admission requirement entry (§7.3.2.1)
// ---------------------------------------------------------------------------

/// A single participation admission requirement declared in `ContextParams`.
///
/// See §7.3.2.1.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequireParticipation {
    /// Which participation category to check.
    pub fact: ParticipationFact,
    /// The comparison and threshold value.
    pub threshold: ParticipationThreshold,
    /// Record freshness requirement (seconds). Statements older than this
    /// (relative to admission time) are rejected.
    pub max_age_secs: u64,
    /// Minimum number of independent contexts (distinct `signer_public_key`
    /// values) that must attest to this fact.
    pub min_contexts: u32,
}

// ---------------------------------------------------------------------------
// ParticipationProfile — signed attestation (§7.3.2.1)
// ---------------------------------------------------------------------------

/// A signed participation profile produced by a context for one of its members.
///
/// Contains all 7 participation fact categories plus metadata. Notably does NOT
/// contain a `context_id` — this is the privacy guarantee. The
/// `signer_public_key` is context-specific (derived with domain separation),
/// preventing verifiers from correlating which contexts share a signer.
///
/// The `signature` covers all fields except itself, computed over
/// [`signable_bytes`](Self::signable_bytes).
///
/// See §7.3.2.1.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParticipationProfile {
    /// The DID whose participation is summarized.
    pub subject_did: DID,
    /// Total seconds of context participation.
    pub participation_duration_secs: u64,
    /// Governance actions taken against this identity.
    pub governance_actions_against: u64,
    /// Governance actions initiated by this identity.
    pub governance_actions_by: u64,
    /// Total tool invocations.
    pub tool_invocation_count: u64,
    /// Contexts created.
    pub context_creation_count: u64,
    /// Role transitions.
    pub role_progression_count: u64,
    /// Attestation events.
    pub attestation_count: u64,
    /// Unix timestamp (seconds) of last update.
    pub updated_at: u64,
    /// Merkle root of the event log at computation time.
    pub event_log_root: [u8; 32],
    /// Context-specific Ed25519 public key (derived with domain separation).
    pub signer_public_key: [u8; 32],
    /// Ed25519 signature over [`signable_bytes`](Self::signable_bytes).
    /// 64 bytes for Ed25519.
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>,
}

impl ParticipationProfile {
    /// Returns a deterministic byte representation of all fields except
    /// `signature`, suitable for signing and verification.
    ///
    /// Field order is fixed and canonical. Each `u64` is encoded as 8 bytes
    /// big-endian. The `subject_did` is encoded as its UTF-8 bytes prefixed
    /// with a 4-byte big-endian length.
    #[must_use]
    pub fn signable_bytes(&self) -> Vec<u8> {
        let did_bytes = self.subject_did.as_bytes();
        // 4 (len) + did_bytes + 7*8 (u64s) + 8 (updated_at) + 32 (root) + 32 (pubkey)
        let capacity = 4 + did_bytes.len() + 8 * 8 + 32 + 32;
        let mut buf = Vec::with_capacity(capacity);

        // Length-prefixed DID.
        #[allow(clippy::cast_possible_truncation)]
        // DID strings are always short (< 256 bytes); u32 is more than enough.
        buf.extend_from_slice(&(did_bytes.len() as u32).to_be_bytes());
        buf.extend_from_slice(did_bytes);

        // 7 fact fields + updated_at, all big-endian u64.
        buf.extend_from_slice(&self.participation_duration_secs.to_be_bytes());
        buf.extend_from_slice(&self.governance_actions_against.to_be_bytes());
        buf.extend_from_slice(&self.governance_actions_by.to_be_bytes());
        buf.extend_from_slice(&self.tool_invocation_count.to_be_bytes());
        buf.extend_from_slice(&self.context_creation_count.to_be_bytes());
        buf.extend_from_slice(&self.role_progression_count.to_be_bytes());
        buf.extend_from_slice(&self.attestation_count.to_be_bytes());
        buf.extend_from_slice(&self.updated_at.to_be_bytes());

        // Fixed-size fields.
        buf.extend_from_slice(&self.event_log_root);
        buf.extend_from_slice(&self.signer_public_key);

        buf
    }
}

// ---------------------------------------------------------------------------
// Context-specific signing key derivation (§7.3.2.1, SCP-BA-005)
// ---------------------------------------------------------------------------

/// Domain separator for participation statement signing key derivation.
///
/// Used as the HKDF info string when deriving a context-specific Ed25519
/// signing key. Different contexts produce different keys from the same seed,
/// preventing verifiers from correlating signers across contexts.
const PARTICIPATION_KEY_DOMAIN: &[u8] = b"scp-participation-statement-v1";

/// Derives a context-specific Ed25519 signing key for participation statements.
///
/// Uses HKDF-SHA256 to derive 32 bytes of key material from the context's
/// seed and the context ID as salt, with the domain separator
/// `scp-participation-statement-v1` as the info string.
///
/// # Parameters
///
/// - `context_seed` — The context's secret key material (e.g., a 32-byte seed
///   held by the context administrator). This is the input keying material.
/// - `context_id` — The context ID, used as the HKDF salt for domain separation.
///
/// # Returns
///
/// An `ed25519_dalek::SigningKey` derived deterministically from the inputs.
/// Two different `context_id` values produce distinct keys from the same seed.
///
/// # Errors
///
/// Returns [`TrustError::InvalidEventData`] if HKDF expansion fails (should
/// not happen with valid inputs and SHA-256).
pub fn derive_participation_signing_key(
    context_seed: &[u8; 32],
    context_id: &str,
) -> Result<ed25519_dalek::SigningKey, TrustError> {
    use hkdf::Hkdf;
    use sha2::Sha256;

    let hk = Hkdf::<Sha256>::new(Some(context_id.as_bytes()), context_seed);
    let mut okm = [0u8; 32];
    hk.expand(PARTICIPATION_KEY_DOMAIN, &mut okm)
        .map_err(|e| TrustError::InvalidEventData {
            sequence: 0,
            reason: format!("HKDF expansion failed for participation key: {e}"),
        })?;

    let signing_key = ed25519_dalek::SigningKey::from_bytes(&okm);

    // Zeroize the intermediate key material.
    okm.fill(0);

    Ok(signing_key)
}

// ---------------------------------------------------------------------------
// ParticipationAdmissionError
// ---------------------------------------------------------------------------

/// Errors from participation admission verification.
#[derive(Debug, thiserror::Error)]
pub enum ParticipationAdmissionError {
    /// A statement's Ed25519 signature did not verify.
    #[error("invalid signature on participation statement for {subject_did}")]
    InvalidSignature {
        /// The subject DID of the statement with the invalid signature.
        subject_did: DID,
    },

    /// A participation fact did not meet the required threshold.
    #[error("threshold not met for {fact:?}: value {value}, required {threshold:?}")]
    ThresholdNotMet {
        /// The fact that failed.
        fact: ParticipationFact,
        /// The actual value.
        value: u64,
        /// The threshold that was not satisfied.
        threshold: ParticipationThreshold,
    },

    /// All statements for a requirement are too stale.
    #[error("all statements too stale for {fact:?}: max_age_secs={max_age_secs}")]
    RecordTooStale {
        /// The fact whose statements were all stale.
        fact: ParticipationFact,
        /// The maximum age allowed.
        max_age_secs: u64,
    },

    /// Fewer than `min_contexts` distinct signers provided for a requirement.
    #[error("insufficient contexts for {fact:?}: need {required}, have {actual}")]
    InsufficientContexts {
        /// The fact that lacks sufficient attestations.
        fact: ParticipationFact,
        /// Number of distinct contexts required.
        required: u32,
        /// Number of distinct contexts provided.
        actual: u32,
    },
}

/// Verifies that a set of participation statements satisfies all requirements.
///
/// Each statement's Ed25519 signature is verified against its
/// `signer_public_key` over `signable_bytes`. Requirements are checked
/// independently — all must pass.
///
/// # Parameters
///
/// - `current_time` — Unix timestamp (seconds) for freshness checks.
/// - `requirements` — The participation requirements to check.
/// - `statements` — The signed participation profiles to verify against.
///
/// # Errors
///
/// Returns the first error encountered (signature, threshold, staleness,
/// or insufficient contexts).
pub fn verify_participation_requirements(
    current_time: u64,
    requirements: &[RequireParticipation],
    statements: &[ParticipationProfile],
) -> Result<(), ParticipationAdmissionError> {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    use std::collections::HashSet;

    // Verify all signatures first.
    for stmt in statements {
        let vk = VerifyingKey::from_bytes(&stmt.signer_public_key).map_err(|_| {
            ParticipationAdmissionError::InvalidSignature {
                subject_did: stmt.subject_did.clone(),
            }
        })?;
        let sig_bytes: [u8; 64] = stmt.signature.as_slice().try_into().map_err(|_| {
            ParticipationAdmissionError::InvalidSignature {
                subject_did: stmt.subject_did.clone(),
            }
        })?;
        let sig = Signature::from_bytes(&sig_bytes);
        vk.verify(&stmt.signable_bytes(), &sig).map_err(|_| {
            ParticipationAdmissionError::InvalidSignature {
                subject_did: stmt.subject_did.clone(),
            }
        })?;
    }

    // Check each requirement independently.
    for req in requirements {
        // Filter to fresh statements.
        let fresh: Vec<&ParticipationProfile> = statements
            .iter()
            .filter(|s| {
                current_time
                    .checked_sub(s.updated_at)
                    .is_some_and(|age| age <= req.max_age_secs)
            })
            .collect();

        if fresh.is_empty() {
            return Err(ParticipationAdmissionError::RecordTooStale {
                fact: req.fact,
                max_age_secs: req.max_age_secs,
            });
        }

        // Count distinct signers. Truncation safe: number of signers
        // bounded by number of statements which fits in u32.
        let distinct_signers: HashSet<[u8; 32]> =
            fresh.iter().map(|s| s.signer_public_key).collect();
        #[allow(clippy::cast_possible_truncation)]
        let distinct_count = distinct_signers.len() as u32;
        if distinct_count < req.min_contexts {
            return Err(ParticipationAdmissionError::InsufficientContexts {
                fact: req.fact,
                required: req.min_contexts,
                actual: distinct_count,
            });
        }

        // Check threshold against each fresh statement.
        let any_satisfies = fresh
            .iter()
            .any(|s| req.threshold.is_satisfied(req.fact.extract_value(s)));
        if !any_satisfies {
            // Report the first value for diagnostic purposes.
            let value = req.fact.extract_value(fresh[0]);
            return Err(ParticipationAdmissionError::ThresholdNotMet {
                fact: req.fact,
                value,
                threshold: req.threshold,
            });
        }
    }

    Ok(())
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
    // ParticipationFact tests
    // -----------------------------------------------------------------------

    fn make_profile() -> ParticipationProfile {
        ParticipationProfile {
            subject_did: "did:key:alice".into(),
            participation_duration_secs: 100,
            governance_actions_against: 2,
            governance_actions_by: 5,
            tool_invocation_count: 42,
            context_creation_count: 3,
            role_progression_count: 7,
            attestation_count: 11,
            updated_at: 1000,
            event_log_root: [1u8; 32],
            signer_public_key: [2u8; 32],
            signature: vec![0u8; 64],
        }
    }

    #[test]
    fn extract_value_returns_correct_field_for_each_fact() {
        let p = make_profile();
        assert_eq!(
            ParticipationFact::ParticipationDuration.extract_value(&p),
            100
        );
        assert_eq!(
            ParticipationFact::GovernanceActionsAgainst.extract_value(&p),
            2
        );
        assert_eq!(ParticipationFact::GovernanceActionsBy.extract_value(&p), 5);
        assert_eq!(ParticipationFact::ToolInvocationCount.extract_value(&p), 42);
        assert_eq!(ParticipationFact::ContextCreationCount.extract_value(&p), 3);
        assert_eq!(ParticipationFact::RoleProgressionCount.extract_value(&p), 7);
        assert_eq!(ParticipationFact::AttestationCount.extract_value(&p), 11);
    }

    // -----------------------------------------------------------------------
    // ParticipationThreshold tests
    // -----------------------------------------------------------------------

    #[test]
    fn threshold_greater_than() {
        let t = ParticipationThreshold::GreaterThan(10);
        assert!(!t.is_satisfied(9));
        assert!(!t.is_satisfied(10));
        assert!(t.is_satisfied(11));
    }

    #[test]
    fn threshold_less_than() {
        let t = ParticipationThreshold::LessThan(10);
        assert!(t.is_satisfied(9));
        assert!(!t.is_satisfied(10));
        assert!(!t.is_satisfied(11));
    }

    #[test]
    fn threshold_at_least() {
        let t = ParticipationThreshold::AtLeast(10);
        assert!(!t.is_satisfied(9));
        assert!(t.is_satisfied(10));
        assert!(t.is_satisfied(11));
    }

    #[test]
    fn threshold_at_most() {
        let t = ParticipationThreshold::AtMost(10);
        assert!(t.is_satisfied(9));
        assert!(t.is_satisfied(10));
        assert!(!t.is_satisfied(11));
    }

    #[test]
    fn threshold_equals() {
        let t = ParticipationThreshold::Equals(10);
        assert!(!t.is_satisfied(9));
        assert!(t.is_satisfied(10));
        assert!(!t.is_satisfied(11));
    }

    // -----------------------------------------------------------------------
    // ParticipationProfile::signable_bytes tests
    // -----------------------------------------------------------------------

    #[test]
    fn signable_bytes_deterministic() {
        let p = make_profile();
        assert_eq!(p.signable_bytes(), p.signable_bytes());
    }

    #[test]
    fn signable_bytes_differs_when_field_changes() {
        let p1 = make_profile();
        let mut p2 = make_profile();
        p2.tool_invocation_count = 999;
        assert_ne!(p1.signable_bytes(), p2.signable_bytes());
    }

    #[test]
    fn signable_bytes_differs_when_did_changes() {
        let p1 = make_profile();
        let mut p2 = make_profile();
        p2.subject_did = "did:key:bob".into();
        assert_ne!(p1.signable_bytes(), p2.signable_bytes());
    }

    // -----------------------------------------------------------------------
    // Key derivation tests
    // -----------------------------------------------------------------------

    #[test]
    fn derive_participation_key_deterministic() {
        let seed = [42u8; 32];
        let k1 = derive_participation_signing_key(&seed, "ctx-1").unwrap();
        let k2 = derive_participation_signing_key(&seed, "ctx-1").unwrap();
        assert_eq!(k1.to_bytes(), k2.to_bytes());
    }

    #[test]
    fn derive_participation_key_different_contexts_produce_different_keys() {
        let seed = [42u8; 32];
        let k1 = derive_participation_signing_key(&seed, "ctx-1").unwrap();
        let k2 = derive_participation_signing_key(&seed, "ctx-2").unwrap();
        assert_ne!(k1.to_bytes(), k2.to_bytes());
    }

    #[test]
    fn derive_participation_key_different_seeds_produce_different_keys() {
        let k1 = derive_participation_signing_key(&[1u8; 32], "ctx-1").unwrap();
        let k2 = derive_participation_signing_key(&[2u8; 32], "ctx-1").unwrap();
        assert_ne!(k1.to_bytes(), k2.to_bytes());
    }

    // -----------------------------------------------------------------------
    // Serde roundtrip tests
    // -----------------------------------------------------------------------

    #[test]
    fn serde_roundtrip_participation_fact() {
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
            let back: ParticipationFact = serde_json::from_str(&json).unwrap();
            assert_eq!(*fact, back);
        }
    }

    #[test]
    fn serde_roundtrip_participation_threshold() {
        let thresholds = [
            ParticipationThreshold::GreaterThan(10),
            ParticipationThreshold::LessThan(5),
            ParticipationThreshold::AtLeast(100),
            ParticipationThreshold::AtMost(0),
            ParticipationThreshold::Equals(42),
        ];
        for t in &thresholds {
            let json = serde_json::to_string(t).unwrap();
            let back: ParticipationThreshold = serde_json::from_str(&json).unwrap();
            assert_eq!(*t, back);
        }
    }

    #[test]
    fn serde_roundtrip_participation_profile() {
        let p = make_profile();
        let json = serde_json::to_string(&p).unwrap();
        let back: ParticipationProfile = serde_json::from_str(&json).unwrap();
        assert_eq!(p, back);
    }

    #[test]
    fn serde_roundtrip_require_participation() {
        let req = RequireParticipation {
            fact: ParticipationFact::ParticipationDuration,
            threshold: ParticipationThreshold::AtLeast(86400),
            max_age_secs: 2_592_000,
            min_contexts: 1,
        };
        let json = serde_json::to_string(&req).unwrap();
        let back: RequireParticipation = serde_json::from_str(&json).unwrap();
        assert_eq!(req, back);
    }

    // -----------------------------------------------------------------------
    // End-to-end: sign + verify participation profile
    // -----------------------------------------------------------------------

    #[test]
    fn sign_and_verify_participation_profile() {
        use ed25519_dalek::Signer;

        let seed = [99u8; 32];
        let key = derive_participation_signing_key(&seed, "ctx-test").unwrap();
        let vk = key.verifying_key();

        let mut profile = make_profile();
        profile.signer_public_key = vk.to_bytes();

        let sig = key.sign(&profile.signable_bytes());
        profile.signature = sig.to_bytes().to_vec();

        // Verify via the public verification function.
        let req = RequireParticipation {
            fact: ParticipationFact::ToolInvocationCount,
            threshold: ParticipationThreshold::AtLeast(1),
            max_age_secs: 10_000,
            min_contexts: 1,
        };
        let result = verify_participation_requirements(1500, &[req], &[profile]);
        assert!(result.is_ok());
    }

    #[test]
    fn verify_rejects_invalid_signature() {
        let mut profile = make_profile();
        // signer_public_key is [2u8; 32] which is not a valid Ed25519 key
        // paired with the zero signature — verification must fail.
        // Use a valid key but wrong signature.
        let seed = [77u8; 32];
        let key = derive_participation_signing_key(&seed, "ctx-bad").unwrap();
        profile.signer_public_key = key.verifying_key().to_bytes();
        profile.signature = vec![0u8; 64]; // wrong signature

        let req = RequireParticipation {
            fact: ParticipationFact::ToolInvocationCount,
            threshold: ParticipationThreshold::AtLeast(1),
            max_age_secs: 10_000,
            min_contexts: 1,
        };
        let result = verify_participation_requirements(1500, &[req], &[profile]);
        assert!(
            matches!(
                result,
                Err(ParticipationAdmissionError::InvalidSignature { .. })
            ),
            "expected InvalidSignature, got {result:?}"
        );
    }

    #[test]
    fn verify_rejects_stale_statement() {
        use ed25519_dalek::Signer;

        let seed = [99u8; 32];
        let key = derive_participation_signing_key(&seed, "ctx-stale").unwrap();

        let mut profile = make_profile();
        profile.updated_at = 100; // very old
        profile.signer_public_key = key.verifying_key().to_bytes();
        let sig = key.sign(&profile.signable_bytes());
        profile.signature = sig.to_bytes().to_vec();

        let req = RequireParticipation {
            fact: ParticipationFact::ParticipationDuration,
            threshold: ParticipationThreshold::AtLeast(1),
            max_age_secs: 60,
            min_contexts: 1,
        };
        // current_time=1000, updated_at=100 → age=900 > max_age=60
        let result = verify_participation_requirements(1000, &[req], &[profile]);
        assert!(
            matches!(
                result,
                Err(ParticipationAdmissionError::RecordTooStale { .. })
            ),
            "expected RecordTooStale, got {result:?}"
        );
    }

    #[test]
    fn verify_rejects_insufficient_contexts() {
        use ed25519_dalek::Signer;

        let seed = [99u8; 32];
        let key = derive_participation_signing_key(&seed, "ctx-1").unwrap();

        let mut profile = make_profile();
        profile.signer_public_key = key.verifying_key().to_bytes();
        let sig = key.sign(&profile.signable_bytes());
        profile.signature = sig.to_bytes().to_vec();

        let req = RequireParticipation {
            fact: ParticipationFact::ParticipationDuration,
            threshold: ParticipationThreshold::AtLeast(1),
            max_age_secs: 10_000,
            min_contexts: 3, // need 3 distinct signers, only have 1
        };
        let result = verify_participation_requirements(1500, &[req], &[profile]);
        assert!(
            matches!(
                result,
                Err(ParticipationAdmissionError::InsufficientContexts { .. })
            ),
            "expected InsufficientContexts, got {result:?}"
        );
    }

    #[test]
    fn verify_rejects_threshold_not_met() {
        use ed25519_dalek::Signer;

        let seed = [99u8; 32];
        let key = derive_participation_signing_key(&seed, "ctx-1").unwrap();

        let mut profile = make_profile();
        profile.tool_invocation_count = 5;
        profile.signer_public_key = key.verifying_key().to_bytes();
        let sig = key.sign(&profile.signable_bytes());
        profile.signature = sig.to_bytes().to_vec();

        let req = RequireParticipation {
            fact: ParticipationFact::ToolInvocationCount,
            threshold: ParticipationThreshold::AtLeast(100), // need 100, have 5
            max_age_secs: 10_000,
            min_contexts: 1,
        };
        let result = verify_participation_requirements(1500, &[req], &[profile]);
        assert!(
            matches!(
                result,
                Err(ParticipationAdmissionError::ThresholdNotMet { .. })
            ),
            "expected ThresholdNotMet, got {result:?}"
        );
    }

    #[test]
    fn verify_multiple_requirements_all_satisfied() {
        use ed25519_dalek::Signer;

        let seed = [99u8; 32];
        let key = derive_participation_signing_key(&seed, "ctx-1").unwrap();

        let mut profile = make_profile();
        profile.signer_public_key = key.verifying_key().to_bytes();
        let sig = key.sign(&profile.signable_bytes());
        profile.signature = sig.to_bytes().to_vec();

        let reqs = vec![
            RequireParticipation {
                fact: ParticipationFact::GovernanceActionsAgainst,
                threshold: ParticipationThreshold::AtMost(5),
                max_age_secs: 10_000,
                min_contexts: 1,
            },
            RequireParticipation {
                fact: ParticipationFact::ParticipationDuration,
                threshold: ParticipationThreshold::AtLeast(50),
                max_age_secs: 10_000,
                min_contexts: 1,
            },
        ];
        let result = verify_participation_requirements(1500, &reqs, &[profile]);
        assert!(result.is_ok());
    }

    #[test]
    fn verify_duplicate_signers_count_as_one() {
        use ed25519_dalek::Signer;

        let seed = [99u8; 32];
        let key = derive_participation_signing_key(&seed, "ctx-1").unwrap();

        // Two profiles with the same signer key.
        let make_signed = |tool_count: u64| {
            let mut p = make_profile();
            p.tool_invocation_count = tool_count;
            p.signer_public_key = key.verifying_key().to_bytes();
            let sig = key.sign(&p.signable_bytes());
            p.signature = sig.to_bytes().to_vec();
            p
        };
        let p1 = make_signed(10);
        let p2 = make_signed(20);

        let req = RequireParticipation {
            fact: ParticipationFact::ToolInvocationCount,
            threshold: ParticipationThreshold::AtLeast(1),
            max_age_secs: 10_000,
            min_contexts: 2, // need 2 distinct, but both use same key
        };
        let result = verify_participation_requirements(1500, &[req], &[p1, p2]);
        assert!(
            matches!(
                result,
                Err(ParticipationAdmissionError::InsufficientContexts { .. })
            ),
            "expected InsufficientContexts, got {result:?}"
        );
    }
}
