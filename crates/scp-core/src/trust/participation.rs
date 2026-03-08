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
// Participation Admission Verification (§7.3.2.1)
// ---------------------------------------------------------------------------

/// Error returned when participation admission verification fails.
///
/// Each variant carries diagnostic fields describing the specific failure.
/// See §7.3.2.1 verification flow.
#[derive(Debug, thiserror::Error)]
pub enum ParticipationAdmissionError {
    /// A statement's Ed25519 signature does not verify against its
    /// `signer_public_key` over `signable_bytes`.
    #[error("invalid signature on statement for {subject_did} (signer {signer_hex}): {reason}")]
    InvalidSignature {
        /// The subject DID of the failing statement.
        subject_did: DID,
        /// Hex-encoded first 8 bytes of the signer public key.
        signer_hex: String,
        /// Human-readable reason for the failure.
        reason: String,
    },

    /// The fact value extracted from the profile does not satisfy the
    /// requirement's threshold.
    #[error("threshold not met for {fact:?}: value {value} does not satisfy {threshold:?}")]
    ThresholdNotMet {
        /// Which fact category failed.
        fact: ParticipationFact,
        /// The threshold that was not met.
        threshold: ParticipationThreshold,
        /// The actual value extracted from the profile.
        value: u64,
    },

    /// All statements for a requirement have `updated_at` older than
    /// `max_age_secs` from the current time.
    #[error(
        "all records too stale for {fact:?}: newest updated_at {newest_updated_at}, \
         current_time {current_time}, max_age_secs {max_age_secs}"
    )]
    RecordTooStale {
        /// Which fact category this applies to.
        fact: ParticipationFact,
        /// The most recent `updated_at` among all statements.
        newest_updated_at: u64,
        /// The current time used for comparison.
        current_time: u64,
        /// The maximum allowed age in seconds.
        max_age_secs: u64,
    },

    /// Statements span fewer than `min_contexts` distinct `signer_public_key`
    /// values for a requirement.
    #[error("insufficient contexts for {fact:?}: need {required} distinct signers, found {found}")]
    InsufficientContexts {
        /// Which fact category this applies to.
        fact: ParticipationFact,
        /// The minimum number of distinct signers required.
        required: u32,
        /// The number of distinct signers found.
        found: u32,
    },
}

/// Verifies a set of [`ParticipationProfile`] statements against a context's
/// participation admission requirements.
///
/// For each requirement, the function:
/// 1. Verifies each statement's Ed25519 signature against its
///    `signer_public_key` over `signable_bytes`.
/// 2. Filters statements to those fresh enough (`updated_at` within
///    `max_age_secs` of `current_time`).
/// 3. Filters to statements where the fact value satisfies the threshold.
/// 4. Checks that qualifying statements span at least `min_contexts` distinct
///    `signer_public_key` values.
///
/// Returns `Ok(())` if all requirements are satisfied, or the first
/// `ParticipationAdmissionError` encountered.
///
/// # Empty requirements
///
/// If `requirements` is empty, returns `Ok(())` immediately (no requirements
/// means no constraints).
///
/// See §7.3.2.1.
pub fn verify_participation_requirements(
    current_time: u64,
    requirements: &[RequireParticipation],
    statements: &[ParticipationProfile],
) -> Result<(), ParticipationAdmissionError> {
    use std::collections::HashSet;

    if requirements.is_empty() {
        return Ok(());
    }

    // Step 1: Verify all signatures up front. Any invalid signature is a
    // hard failure regardless of which requirements use it.
    for statement in statements {
        verify_statement_signature(statement)?;
    }

    // Step 2: Check each requirement independently.
    for req in requirements {
        // Collect qualifying statements: fresh + threshold-satisfying.
        let mut distinct_signers: HashSet<[u8; 32]> = HashSet::new();
        let mut newest_updated_at: u64 = 0;
        let mut any_fresh = false;

        for statement in statements {
            newest_updated_at = newest_updated_at.max(statement.updated_at);

            // Freshness check.
            let age = current_time.saturating_sub(statement.updated_at);
            if age > req.max_age_secs {
                continue;
            }
            any_fresh = true;

            // Threshold check.
            let value = req.fact.extract_value(statement);
            if !req.threshold.is_satisfied(value) {
                continue;
            }

            distinct_signers.insert(statement.signer_public_key);
        }

        // If no statements were fresh enough, report staleness.
        if !any_fresh && !statements.is_empty() {
            return Err(ParticipationAdmissionError::RecordTooStale {
                fact: req.fact.clone(),
                newest_updated_at,
                current_time,
                max_age_secs: req.max_age_secs,
            });
        }

        // If no statements satisfied the threshold (but some were fresh),
        // find the best value to report.
        if distinct_signers.is_empty() {
            // Find the best value among fresh statements for diagnostics.
            let best_value = statements
                .iter()
                .filter(|s| current_time.saturating_sub(s.updated_at) <= req.max_age_secs)
                .map(|s| req.fact.extract_value(s))
                .max()
                .unwrap_or(0);

            return Err(ParticipationAdmissionError::ThresholdNotMet {
                fact: req.fact.clone(),
                threshold: req.threshold.clone(),
                value: best_value,
            });
        }

        // Check min_contexts.
        let found = distinct_signers.len() as u32;
        if found < req.min_contexts {
            return Err(ParticipationAdmissionError::InsufficientContexts {
                fact: req.fact.clone(),
                required: req.min_contexts,
                found,
            });
        }
    }

    Ok(())
}

/// Verifies a single statement's Ed25519 signature.
fn verify_statement_signature(
    statement: &ParticipationProfile,
) -> Result<(), ParticipationAdmissionError> {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    let verifying_key = VerifyingKey::from_bytes(&statement.signer_public_key).map_err(|e| {
        ParticipationAdmissionError::InvalidSignature {
            subject_did: statement.subject_did.clone(),
            signer_hex: hex::encode(&statement.signer_public_key[..8]),
            reason: format!("invalid public key: {e}"),
        }
    })?;

    let signature = Signature::from_bytes(&statement.signature);
    let signable = statement.signable_bytes();

    verifying_key.verify(&signable, &signature).map_err(|e| {
        ParticipationAdmissionError::InvalidSignature {
            subject_did: statement.subject_did.clone(),
            signer_hex: hex::encode(&statement.signer_public_key[..8]),
            reason: format!("signature verification failed: {e}"),
        }
    })?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Context-Hosted ParticipationProfile Production (SCP-BA-005)
// ---------------------------------------------------------------------------

/// Domain separator for deriving context-specific participation signing keys.
///
/// Used with HKDF-SHA256 to derive a deterministic Ed25519 signing key from
/// the context's key material. Each context produces a distinct signer,
/// preventing cross-context correlation.
const PARTICIPATION_KEY_DOMAIN: &[u8] = b"scp-participation-statement-v1";

/// Derives a context-specific Ed25519 signing key for participation profiles.
///
/// Uses HKDF-SHA256 with the context key material as IKM and
/// `"scp-participation-statement-v1"` as the info string. The same context
/// key material always produces the same signing key (deterministic), but
/// different contexts produce different keys (preventing correlation).
fn derive_participation_signing_key(context_key_material: &[u8; 32]) -> ed25519_dalek::SigningKey {
    use hkdf::Hkdf;
    use sha2::Sha256;

    let hk = Hkdf::<Sha256>::new(None, context_key_material);
    let mut okm = [0u8; 32];
    // 32 bytes is well within HKDF-SHA256's output limit (255 * 32 = 8160).
    // The only failure mode is requesting more than 8160 bytes, which cannot
    // happen here, so the match arm is unreachable.
    if hk.expand(PARTICIPATION_KEY_DOMAIN, &mut okm).is_err() {
        unreachable!("HKDF-SHA256 expand for 32 bytes cannot fail");
    }
    ed25519_dalek::SigningKey::from_bytes(&okm)
}

/// Produces a signed [`ParticipationProfile`] for a member from the context's
/// event log.
///
/// This is the core protocol operation where a context produces a profile
/// attesting to a member's verifiable participation facts. Key properties:
///
/// - **Context-controlled:** Only contexts produce profiles; agents cannot
///   write, modify, or delete them.
/// - **Privacy-preserving:** The profile omits `context_id`. The signing key
///   is derived with domain separation so verifiers cannot correlate it to the
///   context identity.
/// - **Replacement semantics:** Calling this again for the same member produces
///   a new profile that replaces (not appends to) the prior one.
///
/// # Parameters
///
/// - `context_key_material` — The context's 32-byte key material, used to
///   derive the context-specific Ed25519 signing key.
/// - `member_did` — The DID of the member to produce the profile for.
/// - `events` — The context's event log entries.
/// - `merkle_root` — Merkle root of the event log at computation time.
/// - `is_member` — Whether `member_did` is a current member of the context.
/// - `is_opted_in` — Whether `member_did` has opted in to profile publication.
/// - `current_time` — Unix timestamp (seconds) for `updated_at`.
///
/// # Errors
///
/// - [`TrustError::NotAMember`] if `is_member` is false.
/// - [`TrustError::NotOptedIn`] if `is_opted_in` is false.
/// - [`TrustError::EmptyEventLog`] if `events` is empty.
///
/// See §7.3.2.1.
pub fn produce_participation_profile(
    context_key_material: &[u8; 32],
    member_did: &str,
    events: &[Event],
    merkle_root: [u8; 32],
    is_member: bool,
    is_opted_in: bool,
    current_time: u64,
) -> Result<ParticipationProfile, TrustError> {
    use ed25519_dalek::Signer;

    if !is_member {
        return Err(TrustError::NotAMember {
            did: member_did.to_owned(),
        });
    }

    if !is_opted_in {
        return Err(TrustError::NotOptedIn {
            did: member_did.to_owned(),
        });
    }

    // Compute participation facts from the event log. We use a dummy
    // context_id since ParticipationProfile intentionally omits it.
    let record =
        compute_participation_record(events, member_did, "_internal", merkle_root, current_time)?;

    // Derive the context-specific signing key.
    let signing_key = derive_participation_signing_key(context_key_material);
    let verifying_key = signing_key.verifying_key();

    // Build the profile with all 7 fact values from the record.
    let total_tool_invocations: u64 = record.tool_invocations.values().sum();

    let mut profile = ParticipationProfile {
        subject_did: member_did.into(),
        participation_duration_secs: record.participation_duration_seconds,
        governance_actions_against: record.governance_actions_against.len() as u64,
        governance_actions_by: record.governance_actions_by.len() as u64,
        tool_invocation_count: total_tool_invocations,
        context_creation_count: record.context_creation_count,
        role_progression_count: record.role_history.len() as u64,
        attestation_count: record.attestation_history.len() as u64,
        updated_at: current_time,
        event_log_root: merkle_root,
        signer_public_key: verifying_key.to_bytes(),
        signature: [0u8; 64], // placeholder, overwritten below
    };

    // Sign the profile.
    let signable = profile.signable_bytes();
    let sig = signing_key.sign(&signable);
    profile.signature = sig.to_bytes();

    Ok(profile)
}

// ---------------------------------------------------------------------------
// ParticipationStatements DID Document Service Endpoint (SCP-BA-006)
// ---------------------------------------------------------------------------

/// The service type string for `ParticipationStatements` entries in DID documents.
pub const PARTICIPATION_STATEMENTS_SERVICE_TYPE: &str = "ScpParticipationStatements";

/// The fragment identifier for participation statements service entries.
const PARTICIPATION_STATEMENTS_FRAGMENT: &str = "participation-statements";

/// Adds a `ScpParticipationStatements` service entry to a DID document.
///
/// The service entry points to the relay endpoint where the agent's signed
/// participation profiles can be fetched by admitting contexts. If a
/// `ScpParticipationStatements` entry already exists, it is replaced.
///
/// # Arguments
///
/// * `document` — The DID document to modify.
/// * `service_endpoint` — The URL where participation profiles are served
///   (e.g., `https://relay.example.com/v1/scp/participation/did:dht:z6Mk...`).
///
/// See §7.3.2.1.
pub fn add_participation_service(
    document: &mut scp_identity::document::DidDocument,
    service_endpoint: &str,
) {
    // Remove any existing participation statements entry.
    document
        .service
        .retain(|s| s.service_type != PARTICIPATION_STATEMENTS_SERVICE_TYPE);

    let service = scp_identity::document::Service {
        id: format!("{}#{PARTICIPATION_STATEMENTS_FRAGMENT}", document.id),
        service_type: PARTICIPATION_STATEMENTS_SERVICE_TYPE.to_owned(),
        service_endpoint: service_endpoint.to_owned(),
    };
    document.service.push(service);
}

/// Removes the `ScpParticipationStatements` service entry from a DID document,
/// if present.
pub fn remove_participation_service(document: &mut scp_identity::document::DidDocument) {
    document
        .service
        .retain(|s| s.service_type != PARTICIPATION_STATEMENTS_SERVICE_TYPE);
}

/// Extracts the `ScpParticipationStatements` service endpoint URL from a
/// resolved DID document.
///
/// Returns `None` if no `ScpParticipationStatements` service entry is found.
///
/// See §7.3.2.1.
#[must_use]
pub fn extract_participation_service_endpoint(
    document: &scp_identity::document::DidDocument,
) -> Option<&str> {
    document
        .service
        .iter()
        .find(|s| s.service_type == PARTICIPATION_STATEMENTS_SERVICE_TYPE)
        .map(|s| s.service_endpoint.as_str())
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

    // -----------------------------------------------------------------------
    // Participation admission verification tests (SCP-BA-003)
    // -----------------------------------------------------------------------

    /// Creates a signed test profile using the given signing key.
    fn make_signed_profile(
        signing_key: &ed25519_dalek::SigningKey,
        subject_did: &str,
        updated_at: u64,
        overrides: Option<ProfileOverrides>,
    ) -> ParticipationProfile {
        use ed25519_dalek::Signer;

        let verifying_key = signing_key.verifying_key();
        let ov = overrides.unwrap_or_default();

        let mut profile = ParticipationProfile {
            subject_did: subject_did.into(),
            participation_duration_secs: ov.participation_duration_secs.unwrap_or(86400),
            governance_actions_against: ov.governance_actions_against.unwrap_or(2),
            governance_actions_by: ov.governance_actions_by.unwrap_or(5),
            tool_invocation_count: ov.tool_invocation_count.unwrap_or(203),
            context_creation_count: ov.context_creation_count.unwrap_or(3),
            role_progression_count: ov.role_progression_count.unwrap_or(4),
            attestation_count: ov.attestation_count.unwrap_or(10),
            updated_at,
            event_log_root: [0xAA; 32],
            signer_public_key: verifying_key.to_bytes(),
            signature: [0u8; 64], // placeholder, will be overwritten
        };

        let signable = profile.signable_bytes();
        let sig = signing_key.sign(&signable);
        profile.signature = sig.to_bytes();

        profile
    }

    #[derive(Default)]
    struct ProfileOverrides {
        participation_duration_secs: Option<u64>,
        governance_actions_against: Option<u64>,
        governance_actions_by: Option<u64>,
        tool_invocation_count: Option<u64>,
        context_creation_count: Option<u64>,
        role_progression_count: Option<u64>,
        attestation_count: Option<u64>,
    }

    fn test_signing_key(seed: u8) -> ed25519_dalek::SigningKey {
        let mut secret = [0u8; 32];
        secret[0] = seed;
        ed25519_dalek::SigningKey::from_bytes(&secret)
    }

    #[test]
    fn verify_empty_requirements_passes() {
        let result = verify_participation_requirements(1_700_000_000, &[], &[]);
        assert!(result.is_ok());
    }

    #[test]
    fn verify_single_requirement_satisfied() {
        let key = test_signing_key(1);
        let statement = make_signed_profile(&key, "did:key:alice", 1_700_000_000, None);

        let req = RequireParticipation {
            fact: ParticipationFact::ToolInvocationCount,
            threshold: ParticipationThreshold::AtLeast(100),
            max_age_secs: 3600,
            min_contexts: 1,
        };

        let result = verify_participation_requirements(1_700_000_100, &[req], &[statement]);
        assert!(result.is_ok());
    }

    #[test]
    fn verify_multiple_requirements_all_satisfied() {
        let key = test_signing_key(1);
        let statement = make_signed_profile(&key, "did:key:alice", 1_700_000_000, None);

        let reqs = vec![
            RequireParticipation {
                fact: ParticipationFact::ToolInvocationCount,
                threshold: ParticipationThreshold::AtLeast(100),
                max_age_secs: 3600,
                min_contexts: 1,
            },
            RequireParticipation {
                fact: ParticipationFact::ParticipationDuration,
                threshold: ParticipationThreshold::GreaterThan(1000),
                max_age_secs: 3600,
                min_contexts: 1,
            },
        ];

        let result = verify_participation_requirements(1_700_000_100, &reqs, &[statement]);
        assert!(result.is_ok());
    }

    #[test]
    fn verify_invalid_signature_returns_error() {
        let key = test_signing_key(1);
        let mut statement = make_signed_profile(&key, "did:key:alice", 1_700_000_000, None);
        // Corrupt the signature.
        statement.signature[0] ^= 0xFF;

        let req = RequireParticipation {
            fact: ParticipationFact::ToolInvocationCount,
            threshold: ParticipationThreshold::AtLeast(100),
            max_age_secs: 3600,
            min_contexts: 1,
        };

        let result = verify_participation_requirements(1_700_000_100, &[req], &[statement]);
        assert!(result.is_err());
        match result {
            Err(ParticipationAdmissionError::InvalidSignature { subject_did, .. }) => {
                assert_eq!(subject_did, "did:key:alice");
            }
            other => panic!("expected InvalidSignature, got {other:?}"),
        }
    }

    #[test]
    fn verify_threshold_not_met_returns_error() {
        let key = test_signing_key(1);
        let statement = make_signed_profile(
            &key,
            "did:key:alice",
            1_700_000_000,
            Some(ProfileOverrides {
                tool_invocation_count: Some(50), // below threshold
                ..Default::default()
            }),
        );

        let req = RequireParticipation {
            fact: ParticipationFact::ToolInvocationCount,
            threshold: ParticipationThreshold::AtLeast(100),
            max_age_secs: 3600,
            min_contexts: 1,
        };

        let result = verify_participation_requirements(1_700_000_100, &[req], &[statement]);
        match result {
            Err(ParticipationAdmissionError::ThresholdNotMet { fact, value, .. }) => {
                assert_eq!(fact, ParticipationFact::ToolInvocationCount);
                assert_eq!(value, 50);
            }
            other => panic!("expected ThresholdNotMet, got {other:?}"),
        }
    }

    #[test]
    fn verify_stale_record_returns_error() {
        let key = test_signing_key(1);
        let statement = make_signed_profile(&key, "did:key:alice", 1_700_000_000, None);

        let req = RequireParticipation {
            fact: ParticipationFact::ToolInvocationCount,
            threshold: ParticipationThreshold::AtLeast(100),
            max_age_secs: 3600,
            min_contexts: 1,
        };

        // current_time is way past max_age_secs
        let result = verify_participation_requirements(1_700_010_000, &[req], &[statement]);
        match result {
            Err(ParticipationAdmissionError::RecordTooStale {
                fact,
                newest_updated_at,
                current_time,
                max_age_secs,
            }) => {
                assert_eq!(fact, ParticipationFact::ToolInvocationCount);
                assert_eq!(newest_updated_at, 1_700_000_000);
                assert_eq!(current_time, 1_700_010_000);
                assert_eq!(max_age_secs, 3600);
            }
            other => panic!("expected RecordTooStale, got {other:?}"),
        }
    }

    #[test]
    fn verify_insufficient_contexts_returns_error() {
        let key = test_signing_key(1);
        let statement = make_signed_profile(&key, "did:key:alice", 1_700_000_000, None);

        let req = RequireParticipation {
            fact: ParticipationFact::ToolInvocationCount,
            threshold: ParticipationThreshold::AtLeast(100),
            max_age_secs: 3600,
            min_contexts: 3, // need 3, only have 1
        };

        let result = verify_participation_requirements(1_700_000_100, &[req], &[statement]);
        match result {
            Err(ParticipationAdmissionError::InsufficientContexts {
                required, found, ..
            }) => {
                assert_eq!(required, 3);
                assert_eq!(found, 1);
            }
            other => panic!("expected InsufficientContexts, got {other:?}"),
        }
    }

    #[test]
    fn verify_duplicate_signers_count_as_one() {
        let key = test_signing_key(1);
        // Two statements from the same signer.
        let s1 = make_signed_profile(&key, "did:key:alice", 1_700_000_000, None);
        let s2 = make_signed_profile(&key, "did:key:alice", 1_700_000_001, None);

        let req = RequireParticipation {
            fact: ParticipationFact::ToolInvocationCount,
            threshold: ParticipationThreshold::AtLeast(100),
            max_age_secs: 3600,
            min_contexts: 2, // need 2 distinct signers
        };

        let result = verify_participation_requirements(1_700_000_100, &[req], &[s1, s2]);
        match result {
            Err(ParticipationAdmissionError::InsufficientContexts {
                required, found, ..
            }) => {
                assert_eq!(required, 2);
                assert_eq!(found, 1);
            }
            other => panic!("expected InsufficientContexts, got {other:?}"),
        }
    }

    #[test]
    fn verify_multiple_distinct_signers_satisfies_min_contexts() {
        let key1 = test_signing_key(1);
        let key2 = test_signing_key(2);
        let key3 = test_signing_key(3);

        let s1 = make_signed_profile(&key1, "did:key:alice", 1_700_000_000, None);
        let s2 = make_signed_profile(&key2, "did:key:alice", 1_700_000_000, None);
        let s3 = make_signed_profile(&key3, "did:key:alice", 1_700_000_000, None);

        let req = RequireParticipation {
            fact: ParticipationFact::ToolInvocationCount,
            threshold: ParticipationThreshold::AtLeast(100),
            max_age_secs: 3600,
            min_contexts: 3,
        };

        let result = verify_participation_requirements(1_700_000_100, &[req], &[s1, s2, s3]);
        assert!(result.is_ok());
    }

    #[test]
    fn verify_empty_statements_with_requirements_fails() {
        let req = RequireParticipation {
            fact: ParticipationFact::ToolInvocationCount,
            threshold: ParticipationThreshold::AtLeast(100),
            max_age_secs: 3600,
            min_contexts: 1,
        };

        let result = verify_participation_requirements(1_700_000_000, &[req], &[]);
        // No statements means threshold can't be met.
        match result {
            Err(ParticipationAdmissionError::ThresholdNotMet { .. }) => {}
            other => panic!("expected ThresholdNotMet, got {other:?}"),
        }
    }

    #[test]
    fn verify_mixed_fresh_and_stale_uses_fresh_only() {
        let key1 = test_signing_key(1);
        let key2 = test_signing_key(2);

        // key1's statement is stale but meets threshold.
        let s1 = make_signed_profile(&key1, "did:key:alice", 1_700_000_000, None);
        // key2's statement is fresh and meets threshold.
        let s2 = make_signed_profile(&key2, "did:key:alice", 1_700_003_500, None);

        let req = RequireParticipation {
            fact: ParticipationFact::ToolInvocationCount,
            threshold: ParticipationThreshold::AtLeast(100),
            max_age_secs: 3600,
            min_contexts: 2, // need 2, but only 1 is fresh
        };

        let result = verify_participation_requirements(1_700_003_700, &[req], &[s1, s2]);
        match result {
            Err(ParticipationAdmissionError::InsufficientContexts {
                required, found, ..
            }) => {
                assert_eq!(required, 2);
                assert_eq!(found, 1);
            }
            other => panic!("expected InsufficientContexts, got {other:?}"),
        }
    }

    #[test]
    fn verify_second_requirement_fails_independently() {
        let key = test_signing_key(1);
        let statement = make_signed_profile(
            &key,
            "did:key:alice",
            1_700_000_000,
            Some(ProfileOverrides {
                tool_invocation_count: Some(200),
                context_creation_count: Some(1), // below threshold for 2nd req
                ..Default::default()
            }),
        );

        let reqs = vec![
            RequireParticipation {
                fact: ParticipationFact::ToolInvocationCount,
                threshold: ParticipationThreshold::AtLeast(100),
                max_age_secs: 3600,
                min_contexts: 1,
            },
            RequireParticipation {
                fact: ParticipationFact::ContextCreationCount,
                threshold: ParticipationThreshold::AtLeast(5),
                max_age_secs: 3600,
                min_contexts: 1,
            },
        ];

        let result = verify_participation_requirements(1_700_000_100, &reqs, &[statement]);
        match result {
            Err(ParticipationAdmissionError::ThresholdNotMet { fact, value, .. }) => {
                assert_eq!(fact, ParticipationFact::ContextCreationCount);
                assert_eq!(value, 1);
            }
            other => panic!("expected ThresholdNotMet, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // produce_participation_profile tests (SCP-BA-005)
    // -----------------------------------------------------------------------

    fn make_member_events(actor_did: &str) -> Vec<Event> {
        vec![
            make_event(EventType::ContextCreated, actor_did, 1000, 0, vec![]),
            make_event(EventType::MemberJoined, actor_did, 1001, 1, vec![]),
            make_event(
                EventType::ToolInvoked,
                actor_did,
                1002,
                2,
                b"tool-a".to_vec(),
            ),
            make_event(
                EventType::ToolInvoked,
                actor_did,
                1003,
                3,
                b"tool-b".to_vec(),
            ),
            make_event(
                EventType::ToolInvoked,
                actor_did,
                1004,
                4,
                b"tool-a".to_vec(),
            ),
            make_event(
                EventType::GovernanceAction,
                actor_did,
                1005,
                5,
                b"did:key:target".to_vec(),
            ),
            make_event(
                EventType::GovernanceAction,
                "did:key:admin",
                1006,
                6,
                actor_did.as_bytes().to_vec(),
            ),
            make_event(
                EventType::RoleAssigned,
                "did:key:admin",
                1007,
                7,
                actor_did.as_bytes().to_vec(),
            ),
            make_event(EventType::ToolVerified, actor_did, 1008, 8, vec![]),
            make_event(EventType::MessageSent, actor_did, 1100, 9, vec![]),
        ]
    }

    #[test]
    fn produce_profile_for_valid_opted_in_member() {
        let key_material = [42u8; 32];
        let events = make_member_events("did:key:alice");
        let merkle_root = [0xAA; 32];

        let profile = produce_participation_profile(
            &key_material,
            "did:key:alice",
            &events,
            merkle_root,
            true,
            true,
            5000,
        )
        .unwrap();

        assert_eq!(profile.subject_did, "did:key:alice");
        assert_eq!(profile.participation_duration_secs, 100); // 1100 - 1000
        assert_eq!(profile.governance_actions_by, 1);
        assert_eq!(profile.governance_actions_against, 1);
        assert_eq!(profile.tool_invocation_count, 3); // tool-a x2 + tool-b x1
        assert_eq!(profile.context_creation_count, 1);
        assert_eq!(profile.role_progression_count, 1);
        assert_eq!(profile.attestation_count, 1);
        assert_eq!(profile.updated_at, 5000);
        assert_eq!(profile.event_log_root, merkle_root);
    }

    #[test]
    fn produce_profile_signature_verifies() {
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};

        let key_material = [42u8; 32];
        let events = make_member_events("did:key:alice");

        let profile = produce_participation_profile(
            &key_material,
            "did:key:alice",
            &events,
            [0; 32],
            true,
            true,
            5000,
        )
        .unwrap();

        let vk = VerifyingKey::from_bytes(&profile.signer_public_key).unwrap();
        let sig = Signature::from_bytes(&profile.signature);
        let signable = profile.signable_bytes();
        assert!(vk.verify(&signable, &sig).is_ok());
    }

    #[test]
    fn produce_profile_non_member_returns_error() {
        let events = make_member_events("did:key:alice");
        let result = produce_participation_profile(
            &[0u8; 32],
            "did:key:alice",
            &events,
            [0; 32],
            false, // not a member
            true,
            5000,
        );
        match result {
            Err(TrustError::NotAMember { did }) => assert_eq!(did, "did:key:alice"),
            other => panic!("expected NotAMember, got {other:?}"),
        }
    }

    #[test]
    fn produce_profile_not_opted_in_returns_error() {
        let events = make_member_events("did:key:alice");
        let result = produce_participation_profile(
            &[0u8; 32],
            "did:key:alice",
            &events,
            [0; 32],
            true,
            false, // not opted in
            5000,
        );
        match result {
            Err(TrustError::NotOptedIn { did }) => assert_eq!(did, "did:key:alice"),
            other => panic!("expected NotOptedIn, got {other:?}"),
        }
    }

    #[test]
    fn produce_profile_different_contexts_produce_different_signers() {
        let events = make_member_events("did:key:alice");

        let profile_a = produce_participation_profile(
            &[1u8; 32],
            "did:key:alice",
            &events,
            [0; 32],
            true,
            true,
            5000,
        )
        .unwrap();

        let profile_b = produce_participation_profile(
            &[2u8; 32],
            "did:key:alice",
            &events,
            [0; 32],
            true,
            true,
            5000,
        )
        .unwrap();

        assert_ne!(
            profile_a.signer_public_key, profile_b.signer_public_key,
            "different context key materials must produce different signer keys"
        );
    }

    #[test]
    fn produce_profile_same_context_produces_same_signer() {
        let key_material = [42u8; 32];
        let events = make_member_events("did:key:alice");

        let profile_a = produce_participation_profile(
            &key_material,
            "did:key:alice",
            &events,
            [0; 32],
            true,
            true,
            5000,
        )
        .unwrap();

        let profile_b = produce_participation_profile(
            &key_material,
            "did:key:alice",
            &events,
            [0; 32],
            true,
            true,
            6000,
        )
        .unwrap();

        assert_eq!(
            profile_a.signer_public_key, profile_b.signer_public_key,
            "same context key material must produce same signer key"
        );
    }

    #[test]
    fn produce_profile_replacement_yields_updated_values() {
        let key_material = [42u8; 32];
        let mut events = make_member_events("did:key:alice");

        let profile_v1 = produce_participation_profile(
            &key_material,
            "did:key:alice",
            &events,
            [0; 32],
            true,
            true,
            5000,
        )
        .unwrap();

        // Add more tool invocations.
        events.push(make_event(
            EventType::ToolInvoked,
            "did:key:alice",
            1200,
            10,
            b"tool-c".to_vec(),
        ));

        let profile_v2 = produce_participation_profile(
            &key_material,
            "did:key:alice",
            &events,
            [1; 32],
            true,
            true,
            6000,
        )
        .unwrap();

        assert_eq!(profile_v1.tool_invocation_count, 3);
        assert_eq!(profile_v2.tool_invocation_count, 4);
        assert_eq!(profile_v2.updated_at, 6000);
        assert_ne!(profile_v1.signature, profile_v2.signature);
        // Signer key stays the same (same context).
        assert_eq!(profile_v1.signer_public_key, profile_v2.signer_public_key);
    }

    #[test]
    fn produce_profile_no_context_id_in_output() {
        // ParticipationProfile has no context_id field — this is a compile-time
        // guarantee via the struct definition. This test documents the intent.
        let key_material = [42u8; 32];
        let events = make_member_events("did:key:alice");

        let profile = produce_participation_profile(
            &key_material,
            "did:key:alice",
            &events,
            [0; 32],
            true,
            true,
            5000,
        )
        .unwrap();

        let json = serde_json::to_string(&profile).unwrap();
        assert!(
            !json.contains("context_id"),
            "serialized profile must not contain context_id"
        );
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

    // -----------------------------------------------------------------------
    // SCP-BA-006: ParticipationStatements service endpoint
    // -----------------------------------------------------------------------

    fn make_test_document(did: &str) -> scp_identity::document::DidDocument {
        scp_identity::document::DidDocument::new(did, &[1u8; 32], &[2u8; 32], &[3u8; 32])
    }

    #[test]
    fn add_participation_service_adds_entry() {
        let did = "did:dht:zTestDid";
        let mut doc = make_test_document(did);
        let endpoint = "https://relay.example.com/v1/scp/participation/did:dht:zTestDid";

        add_participation_service(&mut doc, endpoint);

        let svc = doc
            .service
            .iter()
            .find(|s| s.service_type == PARTICIPATION_STATEMENTS_SERVICE_TYPE)
            .expect("service entry should exist");
        assert_eq!(svc.id, format!("{did}#participation-statements"));
        assert_eq!(svc.service_type, "ScpParticipationStatements");
        assert_eq!(svc.service_endpoint, endpoint);
    }

    #[test]
    fn add_participation_service_replaces_existing() {
        let did = "did:dht:zTestDid";
        let mut doc = make_test_document(did);

        add_participation_service(&mut doc, "https://old.example.com/v1/scp/participation/did");
        add_participation_service(&mut doc, "https://new.example.com/v1/scp/participation/did");

        let matching: Vec<_> = doc
            .service
            .iter()
            .filter(|s| s.service_type == PARTICIPATION_STATEMENTS_SERVICE_TYPE)
            .collect();
        assert_eq!(
            matching.len(),
            1,
            "should have exactly one entry after replacement"
        );
        assert_eq!(
            matching[0].service_endpoint,
            "https://new.example.com/v1/scp/participation/did"
        );
    }

    #[test]
    fn remove_participation_service_removes_entry() {
        let did = "did:dht:zTestDid";
        let mut doc = make_test_document(did);

        add_participation_service(
            &mut doc,
            "https://relay.example.com/v1/scp/participation/did",
        );
        assert!(extract_participation_service_endpoint(&doc).is_some());

        remove_participation_service(&mut doc);
        assert!(extract_participation_service_endpoint(&doc).is_none());
    }

    #[test]
    fn extract_participation_service_endpoint_returns_none_when_absent() {
        let doc = make_test_document("did:dht:zTestDid");
        assert!(extract_participation_service_endpoint(&doc).is_none());
    }

    #[test]
    fn extract_participation_service_endpoint_returns_url_when_present() {
        let mut doc = make_test_document("did:dht:zTestDid");
        let endpoint = "https://relay.example.com/v1/scp/participation/did:dht:zTestDid";
        add_participation_service(&mut doc, endpoint);

        let result = extract_participation_service_endpoint(&doc);
        assert_eq!(result, Some(endpoint));
    }

    #[test]
    fn participation_service_serde_roundtrip() {
        let did = "did:dht:zTestDid";
        let mut doc = make_test_document(did);
        let endpoint = "https://relay.example.com/v1/scp/participation/did:dht:zTestDid";
        add_participation_service(&mut doc, endpoint);

        let json = serde_json::to_string(&doc).unwrap();
        let deserialized: scp_identity::document::DidDocument =
            serde_json::from_str(&json).unwrap();

        let result = extract_participation_service_endpoint(&deserialized);
        assert_eq!(result, Some(endpoint));
    }

    #[test]
    fn participation_service_does_not_affect_other_services() {
        let did = "did:dht:zTestDid";
        let mut doc = make_test_document(did);

        // Document starts with pre-rotation service.
        let initial_count = doc.service.len();

        add_participation_service(
            &mut doc,
            "https://relay.example.com/v1/scp/participation/did",
        );
        assert_eq!(doc.service.len(), initial_count + 1);

        remove_participation_service(&mut doc);
        assert_eq!(doc.service.len(), initial_count);

        // Original services should still be intact.
        assert!(doc.pre_rotation_service().is_some());
    }
}
