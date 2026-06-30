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

use scp_event_log::payload::{GovernanceActionExecutedPayload, decode_payload, project_payload};
use scp_event_log::{ContextId, Event, EventType};
use scp_primitives::DID;

use super::attestation::{Attestation, RevocationStatus};
use super::{AttestationReference, GovernanceActionSummary, RoleTransition, ToolId, TrustError};

// ---------------------------------------------------------------------------
// Anchoring flags — single source of truth
// ---------------------------------------------------------------------------

/// Whether `tool_invocation_count` is anchored in the canonical Merkle log.
///
/// `false` until ADR-051 makes `ToolInvoked` a convergent leaf: the count is
/// computed from per-author local `ContextEvent`s, not the Merkle log (spec
/// §7.3.2; ADR-011 amendment exclusion taxonomy). Defined ONCE so the unsigned
/// [`ParticipationFacts`] view and the signed [`ParticipationProfile`] cannot
/// drift in what they advertise.
pub const TOOL_INVOCATION_COUNT_ANCHORED: bool = false;

/// Whether `attestation_count` is anchored in / verifiable against a context
/// Merkle root.
///
/// Always `false`: `attestation_count` is a credential-layer (§7.4),
/// verifier-relative fact — there is no attestation event type, and each
/// contributing attestation is verified by its own envelope signature and
/// revocation status (§7.4.1, §7.4.4), NOT by inclusion in any context Merkle
/// tree (spec §7.3.2). Distinct from [`TOOL_INVOCATION_COUNT_ANCHORED`], which
/// flips once ADR-051 lands; this one never does.
pub const ATTESTATION_COUNT_ANCHORED: bool = false;

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

    /// Total seconds of context participation, summed over the subject's
    /// `MemberJoined`→`MemberLeft` intervals (§7.3.2). Membership leaves carry
    /// the affected member's `subject_did` (ADR-011), so admin-driven
    /// joins/removals are attributed to the affected member, not the executing
    /// admin. If the member is still joined at the end of the slice, the open
    /// interval runs to the latest event timestamp across all events. Re-joins
    /// sum multiple intervals.
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

    /// Credential-layer attestations for the subject (§7.4), the explicit
    /// exception to the event-log-derived facts: this is populated from the
    /// `accessible_attestations` passed to [`compute_participation_record`]
    /// (the subject's accessible, currently-valid, non-revoked attestations),
    /// NOT from any event-log event. There is no attestation event type; the
    /// count is verifier-relative (§7.3.2) — a caller with no attestation-cache
    /// access honestly passes an empty set, yielding an empty history.
    pub attestation_history: Vec<AttestationReference>,

    /// Number of `ChildContextCreated` events by the subject (§7.3.2).
    pub context_creation_count: u64,

    /// Unix timestamp (seconds) when this record was computed.
    pub computed_at: u64,

    /// Merkle root of the event log at computation time.
    pub event_log_root: [u8; 32],
}

// ---------------------------------------------------------------------------
// ParticipationFacts
// ---------------------------------------------------------------------------

/// The scalar (count-flattened) projection of a [`ParticipationRecord`].
///
/// [`ParticipationRecord`] carries rich collections (`tool_invocations`
/// `HashMap`, `governance_actions_*` / `role_history` / `attestation_history`
/// `Vec`s) that are awkward to convey verbatim across the FFI boundary and that
/// every SDK would otherwise have to re-aggregate into counts — re-introducing
/// the cross-binding divergence this projection exists to eliminate. This struct
/// is the single canonical flattening: it derives ALL counts ONCE in the shared
/// Rust core so the bridges and SDKs RECEIVE the facts rather than recompute
/// them.
///
/// The flattening matches [`produce_participation_profile`]'s fact derivation
/// exactly (the same `.len()` / `.values().sum()` reductions), so a
/// `ParticipationFacts` and a [`ParticipationProfile`] computed from the same
/// record carry identical fact values — the difference is that
/// `ParticipationFacts` is an UNSIGNED, locally-computed view (no context
/// signing key, no `signature` / `signer_public_key`), suitable for an agent
/// reading its own accessible logs (§7.3.2), whereas `ParticipationProfile` is
/// the context-hosted SIGNED attestation (§7.3.2.1).
///
/// See ADR-017 (§7.3.2) and the field docs on [`ParticipationProfile`] for the
/// per-fact semantics.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParticipationFacts {
    /// The DID whose participation is summarized.
    pub subject_did: DID,

    /// Total seconds of context participation, summed over the subject's
    /// `MemberJoined`→`MemberLeft` intervals (§7.3.2).
    pub participation_duration_secs: u64,

    /// Count of governance actions taken against this identity (where the
    /// projected `target_did` is the subject).
    ///
    /// This is a LOWER BOUND of adverse actions: only the unambiguously-adverse
    /// [`ADVERSE_ACTION_TYPES`] are counted. Actions whose adverseness cannot be
    /// determined without the role delta (e.g. `ChangeRole`, `RemoveSigner`) are
    /// deliberately excluded to avoid a hostile admin deflating standing with
    /// beneficial-looking actions (H18), so a genuinely-adverse `ChangeRole` is
    /// undercounted rather than over-counted.
    pub governance_actions_against: u64,

    /// Count of governance actions initiated by this identity.
    pub governance_actions_by: u64,

    /// Total tool invocations across all tool types.
    pub tool_invocation_count: u64,

    /// Whether `tool_invocation_count` is anchored in the canonical Merkle log.
    ///
    /// `false` until ADR-051 makes `ToolInvoked` a convergent leaf: the count is
    /// computed from per-author local `ContextEvent`s, not the Merkle log
    /// (spec §7.3.2; ADR-011 amendment exclusion taxonomy §2). Truth-in-
    /// advertising — consumers MUST NOT treat the count as Merkle-proven while
    /// this is `false`.
    pub tool_invocation_count_anchored: bool,

    /// Number of contexts created by the subject (`ChildContextCreated`).
    pub context_creation_count: u64,

    /// Number of role transitions for the subject.
    pub role_progression_count: u64,

    /// Number of accessible, currently-valid credential-layer attestations
    /// (§7.4) for the subject. Verifier-relative — a caller with no
    /// attestation-cache access honestly yields 0.
    ///
    /// SECURITY (issuer legitimacy): this is a raw count of authentic-but-self-
    /// issuable endorsements. Each contributing attestation's signature is
    /// verified, but authenticity is NOT authorization: an issuer is
    /// self-certifying, so a subject can mint endorsements from issuer DIDs it
    /// controls and inflate this count (a Sybil endorsement ring). It carries NO
    /// issuer-independence / Sybil-resistance guarantee. Consumers MUST NOT use
    /// `attestation_count` as a sole trust or admission factor; an admission gate
    /// needing Sybil resistance must use the independence-scored threshold path
    /// ([`check_threshold_attestation`](super::attestation::check_threshold_attestation)),
    /// not this count (mirrors the §7.4.1 self-certification caveat on challenge
    /// results and the `ParticipationProfile` signer).
    pub attestation_count: u64,

    /// Whether `attestation_count` is anchored in / verifiable against a context
    /// Merkle root.
    ///
    /// Always `false` ([`ATTESTATION_COUNT_ANCHORED`]): `attestation_count` is a
    /// credential-layer (§7.4), verifier-relative fact, NOT a context-event-log
    /// count — there is no attestation event type, and each contributing
    /// attestation is verified by its own envelope signature/revocation, not by
    /// Merkle inclusion (spec §7.3.2). The parallel of
    /// `tool_invocation_count_anchored`, present so the non-anchored,
    /// verifier-relative nature is mechanically visible to consumers rather than
    /// implicit.
    pub attestation_count_anchored: bool,

    /// Unix timestamp (seconds) when the underlying record was computed.
    pub computed_at: u64,

    /// Merkle root of the event log at computation time.
    pub event_log_root: [u8; 32],
}

impl From<&ParticipationRecord> for ParticipationFacts {
    /// Flattens a [`ParticipationRecord`]'s collections into scalar counts.
    ///
    /// This is the SAME reduction [`produce_participation_profile`] applies when
    /// building a signed [`ParticipationProfile`] (`.len()` over the governance /
    /// role / attestation `Vec`s; `.values().sum()` over the `tool_invocations`
    /// `HashMap`); `tool_invocation_count_anchored` is `false` until ADR-051
    /// (spec §7.3.2).
    fn from(record: &ParticipationRecord) -> Self {
        let tool_invocation_count: u64 = record.tool_invocations.values().sum();
        Self {
            subject_did: record.subject_did.clone(),
            participation_duration_secs: record.participation_duration_seconds,
            governance_actions_against: record.governance_actions_against.len() as u64,
            governance_actions_by: record.governance_actions_by.len() as u64,
            tool_invocation_count,
            // `tool_invocation_count` is summed from local `ToolInvoked`
            // `ContextEvent`s, not the Merkle log, until ADR-051 (spec §7.3.2).
            tool_invocation_count_anchored: TOOL_INVOCATION_COUNT_ANCHORED,
            context_creation_count: record.context_creation_count,
            role_progression_count: record.role_history.len() as u64,
            attestation_count: record.attestation_history.len() as u64,
            // Credential-layer / verifier-relative — never Merkle-anchored.
            attestation_count_anchored: ATTESTATION_COUNT_ANCHORED,
            computed_at: record.computed_at,
            event_log_root: record.event_log_root,
        }
    }
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
/// SECURITY (trust boundary): this function does NOT verify anything. It trusts
/// `events` as the authoritative convergent log and trusts
/// `accessible_attestations` as ALREADY-VERIFIED credentials (signature, expiry,
/// revocation). The verification boundary is the FFI ingest path
/// (`verify_and_cache` / `verify_attestation_with_revocation`), which is what
/// sources `accessible_attestations`; passing unverified attestations here would
/// inflate `attestation_count` with forged credentials. Callers MUST supply only
/// verified inputs.
///
/// Facts are keyed on the canonical subject-bearing leaves the runtime emits
/// (ADR-011 amendment, §7.3.2): governance/access facts on the projected
/// `target_did`, role/membership facts on the projected `subject_did`. The
/// `attestation_count` fact is the explicit exception — it is a credential-layer
/// fact (§7.4) sourced from `accessible_attestations`, never the event log.
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
/// - `accessible_attestations` -- The subject's accessible, currently-valid
///   attestations from the credential layer (§7.4). `attestation_history` is
///   populated from these, filtered to the subject and non-revoked entries.
///   Callers without attestation-cache access (e.g. proposer-eligibility /
///   lifecycle paths) honestly pass an empty slice — yielding an
///   `attestation_count` of 0, which is correct and verifier-relative per
///   §7.3.2, NOT a stub.
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
    accessible_attestations: &[Attestation],
) -> Result<ParticipationRecord, TrustError> {
    if events.is_empty() {
        return Err(TrustError::EmptyEventLog);
    }

    let mut participation_count: u64 = 0;
    let mut tool_invocations: HashMap<ToolId, u64> = HashMap::new();
    let mut governance_actions_by: Vec<GovernanceActionSummary> = Vec::new();
    let mut governance_actions_against: Vec<GovernanceActionSummary> = Vec::new();
    let mut role_history: Vec<RoleTransition> = Vec::new();
    let mut context_creation_count: u64 = 0;

    // Membership-interval accounting for participation duration (§7.3.2): walk
    // events in order, keyed on the affected member's projected `subject_did`,
    // tracking the currently-open join timestamp. `MemberLeft` closes the
    // interval; a still-open interval at the end runs to the latest event
    // timestamp across the whole slice. Re-joins sum multiple intervals.
    let mut duration_secs: u64 = 0;
    let mut open_join_ts: Option<u64> = None;
    let mut latest_event_ts: u64 = 0;

    for event in events {
        let is_subject = event.actor_did == subject_did;

        latest_event_ts = latest_event_ts.max(event.timestamp);

        if is_subject {
            participation_count += 1;
        }

        match event.event_type {
            EventType::ToolInvoked if is_subject => {
                let tool_id = extract_tool_id_from_payload(&event.payload.data);
                *tool_invocations.entry(tool_id).or_insert(0) += 1;
            }

            EventType::GovernanceActionExecuted => record_governance_action(
                event,
                is_subject,
                subject_did,
                &mut governance_actions_by,
                &mut governance_actions_against,
            ),

            EventType::RoleAssigned => {
                // Role assignments where the projected subject is the subject.
                // Keyed on `subject_did` (the affected member), NOT the assigning
                // governance actor.
                let projected = project_payload(&event.event_type, &event.payload).subject_did;
                if projected.as_deref() == Some(subject_did) {
                    role_history.push(RoleTransition {
                        timestamp: event.timestamp,
                        event_sequence: event.sequence,
                        assigned_by: event.actor_did.clone(),
                    });
                }
            }

            EventType::ChildContextCreated if is_subject => {
                context_creation_count += 1;
            }

            EventType::MemberJoined => {
                // Open a membership interval for the affected member (projected
                // subject_did), if this leaf concerns the subject.
                let projected = project_payload(&event.event_type, &event.payload).subject_did;
                if projected.as_deref() == Some(subject_did) {
                    // Re-join: a prior open interval that never saw a MemberLeft
                    // is closed at this join's timestamp before opening anew.
                    if let Some(joined) = open_join_ts {
                        duration_secs =
                            duration_secs.saturating_add(event.timestamp.saturating_sub(joined));
                    }
                    open_join_ts = Some(event.timestamp);
                }
            }

            EventType::MemberLeft => {
                // Close the open membership interval for the affected member.
                let projected = project_payload(&event.event_type, &event.payload).subject_did;
                if projected.as_deref() == Some(subject_did)
                    && let Some(joined) = open_join_ts.take()
                {
                    duration_secs =
                        duration_secs.saturating_add(event.timestamp.saturating_sub(joined));
                }
            }

            _ => {}
        }
    }

    // An interval still open at the end of the slice runs to the latest event
    // timestamp across ALL events (§7.3.2).
    if let Some(joined) = open_join_ts {
        duration_secs = duration_secs.saturating_add(latest_event_ts.saturating_sub(joined));
    }

    // Attestation history is a credential-layer fact (§7.4), built from the
    // caller-supplied accessible attestations, NOT the event log.
    let attestation_history = credential_attestation_history(accessible_attestations, subject_did);

    Ok(ParticipationRecord {
        subject_did: subject_did.into(),
        context_id: context_id.to_owned(),
        participation_count,
        participation_duration_seconds: duration_secs,
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

/// Builds the credential-layer attestation history (§7.4) for a subject from a
/// set of accessible attestations.
///
/// SECURITY (issuer legitimacy): the resulting length feeds `attestation_count`,
/// a raw count of authentic-but-self-issuable endorsements. Each attestation's
/// signature is verified upstream, but authenticity is not authorization — an
/// issuer is self-certifying, so the count has NO issuer-independence / Sybil
/// guarantee. See the caveat on [`ParticipationFacts::attestation_count`].
///
/// Defensively filters to attestations whose `subject` matches `subject_did` and
/// whose `revocation_status` is [`RevocationStatus::Active`]
/// (`get_verified_attestations` already drops revoked-on-reverify, but a broader
/// caller-supplied set is handled correctly here). Each kept attestation maps to
/// an [`AttestationReference`] whose `timestamp` is the last renewal if
/// renewable, else issuance; `event_sequence` is `0` because credential-layer
/// attestations carry no context-log sequence (the field is only ever read as
/// part of the history count).
fn credential_attestation_history(
    accessible_attestations: &[Attestation],
    subject_did: &str,
) -> Vec<AttestationReference> {
    accessible_attestations
        .iter()
        .filter(|att| att.subject == subject_did)
        .filter(|att| matches!(att.revocation_status, RevocationStatus::Active))
        .map(|att| AttestationReference {
            timestamp: att.renewed_at.unwrap_or(att.issued_at),
            event_sequence: 0,
            actor_did: att.issuer.clone(),
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Participation threshold check
// ---------------------------------------------------------------------------

/// Returns `true` if the participation record meets the minimum participation
/// threshold required for governance actions (#1530).
///
/// The threshold is based on `participation_count` — a member must have
/// at least one event (i.e., any prior participation) AND must not have
/// more governance actions against them than by them (net-positive governance
/// ratio).
///
/// This is a simple, deterministic check that any agent can reproduce
/// from the same event log data.
#[must_use]
pub const fn meets_threshold(record: &ParticipationRecord) -> bool {
    // Must have at least one participation event.
    if record.participation_count == 0 {
        return false;
    }
    // Net-positive governance ratio: actions by >= actions against.
    record.governance_actions_by.len() >= record.governance_actions_against.len()
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

/// Adverse governance action types counted against the target in
/// `governance_actions_against`.
///
/// Only these action types represent punitive or restrictive measures that
/// should weigh against the target member's standing score. All other action
/// types (e.g., `RestoreAccess`, `AssignRole`, `ApproveSpend`) are beneficial
/// or neutral and MUST NOT be counted, as a hostile admin could otherwise
/// issue many beneficial-looking actions to deflate a member's standing
/// (H18: standing-deflation attack).
///
/// This makes `governance_actions_against` a LOWER BOUND of adverse actions:
/// action types whose adverseness depends on the role delta — notably
/// `ChangeRole` (a demotion is adverse, a promotion is not) and `RemoveSigner` —
/// are intentionally excluded because adverseness is not determinable from the
/// action type alone. A genuinely-adverse such action is therefore undercounted,
/// never over-counted; the conservative direction preferred for H18.
///
/// When `action_type` is absent from the payload (legacy events written before
/// H18), the action is conservatively counted as adverse to preserve the
/// pre-fix behavior.
const ADVERSE_ACTION_TYPES: &[&str] = &[
    "SuspendCapability",
    "SuspendAccess",
    "RevokeAccess",
    "RemoveMember",
    "ResetMember",
];

/// Returns `true` if a governance action's `action_type` is adverse toward its
/// target and should therefore be counted in `governance_actions_against`.
///
/// `action_type` comes from the canonical [`GovernanceActionExecutedPayload`]
/// (positional `MessagePack`, ADR-011 amendment). An action is adverse if its
/// `action_type` matches one of the [`ADVERSE_ACTION_TYPES`]. An empty
/// `action_type` string is conservatively treated as adverse (preserving the
/// pre-H18 behavior for legacy events that decode but carry no `action_type`).
fn is_adverse_action_type(action_type: &str) -> bool {
    // Empty action_type — treat conservatively as adverse.
    action_type.is_empty() || ADVERSE_ACTION_TYPES.contains(&action_type)
}

/// Records a [`EventType::GovernanceActionExecuted`] leaf into the appropriate
/// bucket for `compute_participation_record`.
///
/// The canonical [`GovernanceActionExecutedPayload`] is decoded **at most once**
/// per event; the decoded `target_did` (empty → `None`) is reused by both
/// branches.
///
/// - When the subject is the actor, the action is **always** recorded in
///   `actions_by` keyed on the actor — even when the payload is undecodable, in
///   which case its `target_did` is best-effort `None`.
/// - Otherwise the action is recorded in `actions_against` only when the payload
///   decoded, the subject is the (non-empty) target, AND the action is adverse
///   (H18: beneficial actions such as `RestoreAccess` must not deflate the
///   target's standing score). An undecodable payload yields no target, so it
///   can never match the subject and is never counted here.
fn record_governance_action(
    event: &Event,
    is_subject: bool,
    subject_did: &str,
    actions_by: &mut Vec<GovernanceActionSummary>,
    actions_against: &mut Vec<GovernanceActionSummary>,
) {
    // Decode once; reuse for both buckets. Empty `target_did` → `None`.
    let decoded = decode_payload::<GovernanceActionExecutedPayload>(&event.payload).ok();
    let target = decoded
        .as_ref()
        .and_then(|p| (!p.target_did.is_empty()).then(|| p.target_did.clone()));

    if is_subject {
        // Subject performed a governance action — keyed on actor_did. Recorded
        // unconditionally; `target_did` is best-effort (None if undecodable).
        actions_by.push(GovernanceActionSummary {
            timestamp: event.timestamp,
            actor_did: event.actor_did.clone(),
            target_did: target.map(Into::into),
            event_sequence: event.sequence,
        });
    } else if target.as_deref() == Some(subject_did)
        && decoded
            .as_ref()
            .is_some_and(|p| is_adverse_action_type(&p.action_type))
    {
        // A non-empty `target` implies the payload decoded, so `decoded` is
        // `Some` here; record the adverse action against the subject.
        actions_against.push(GovernanceActionSummary {
            timestamp: event.timestamp,
            actor_did: event.actor_did.clone(),
            target_did: target.map(Into::into),
            event_sequence: event.sequence,
        });
    }
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
    /// Number of accessible, currently-valid credential-layer attestations
    /// (§7.4) — NOT an event-log count (there is no attestation event type).
    ///
    /// SECURITY (issuer legitimacy): a raw count of authentic-but-self-issuable
    /// endorsements with NO issuer-independence / Sybil guarantee — an issuer is
    /// self-certifying, so a subject can mint endorsements from DIDs it controls.
    /// An admission gate needing Sybil resistance MUST use the independence-scored
    /// threshold path
    /// ([`check_threshold_attestation`](super::attestation::check_threshold_attestation)),
    /// not `AttestationCount`. See [`ParticipationFacts::attestation_count`].
    AttestationCount,
}

impl ParticipationFact {
    /// Extracts the corresponding value from a [`ParticipationProfile`].
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
    pub const fn is_satisfied(&self, value: u64) -> bool {
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

    /// Whether `tool_invocation_count` is anchored in the canonical Merkle log.
    ///
    /// `false` until ADR-051 makes `ToolInvoked` a convergent leaf: the count is
    /// computed from per-author local `ContextEvent`s, not the Merkle log
    /// (spec §7.3.2; ADR-011 amendment exclusion taxonomy §2). Truth-in-
    /// advertising — consumers MUST NOT treat the count as Merkle-proven while
    /// this is `false`. The flag is part of the signed preimage so it cannot be
    /// stripped from a signed profile.
    pub tool_invocation_count_anchored: bool,

    /// Number of contexts created.
    pub context_creation_count: u64,

    /// Number of role transitions.
    pub role_progression_count: u64,

    /// Number of accessible, currently-valid credential-layer attestations
    /// (§7.4) — NOT an event-log count (there is no attestation event type;
    /// §7.3.2). Verifier-relative.
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

/// Domain separator for participation profile signing.
///
/// Prepended to `signable_bytes` output to prevent cross-protocol signature
/// confusion. Without this, a valid participation profile signature could
/// potentially be replayed in a different protocol context.
const DOMAIN_PARTICIPATION_V1: &[u8] = b"SCP-PARTICIPATION-V1:";

impl ParticipationProfile {
    /// Returns the deterministic signable bytes for this profile.
    ///
    /// Covers all fields except `signature`. The byte layout is:
    /// - `"SCP-PARTICIPATION-V1:"` domain separator
    /// - `subject_did` UTF-8 bytes (length-prefixed as u32 big-endian)
    /// - `participation_duration_secs` (u64 big-endian)
    /// - `governance_actions_against` (u64 big-endian)
    /// - `governance_actions_by` (u64 big-endian)
    /// - `tool_invocation_count` (u64 big-endian)
    /// - `tool_invocation_count_anchored` (1 byte: 0 or 1)
    /// - `context_creation_count` (u64 big-endian)
    /// - `role_progression_count` (u64 big-endian)
    /// - `attestation_count` (u64 big-endian)
    /// - `updated_at` (u64 big-endian)
    /// - `event_log_root` (32 bytes)
    /// - `signer_public_key` (32 bytes)
    #[must_use]
    pub fn signable_bytes(&self) -> Vec<u8> {
        let did_bytes = self.subject_did.as_bytes();
        // domain separator + 4 (length prefix) + did_bytes.len() + 8*8 (eight
        // u64 fields) + 1 (tool_invocation_count_anchored byte) + 32 + 32
        let capacity = DOMAIN_PARTICIPATION_V1.len() + 4 + did_bytes.len() + 64 + 1 + 64;
        let mut buf = Vec::with_capacity(capacity);

        // Domain separator — prevents cross-protocol signature confusion.
        buf.extend_from_slice(DOMAIN_PARTICIPATION_V1);

        // Length-prefixed DID string.
        #[allow(clippy::cast_possible_truncation)] // DID strings are well under u32::MAX bytes
        buf.extend_from_slice(&(did_bytes.len() as u32).to_be_bytes());
        buf.extend_from_slice(did_bytes);

        // All u64 fact fields + updated_at in declaration order.
        buf.extend_from_slice(&self.participation_duration_secs.to_be_bytes());
        buf.extend_from_slice(&self.governance_actions_against.to_be_bytes());
        buf.extend_from_slice(&self.governance_actions_by.to_be_bytes());
        buf.extend_from_slice(&self.tool_invocation_count.to_be_bytes());
        // Truth-in-advertising flag (spec §7.3.2) — one byte in the signed
        // preimage so a signed profile binds whether the count is Merkle-anchored.
        buf.push(u8::from(self.tool_invocation_count_anchored));
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
    let mut okm = zeroize::Zeroizing::new([0u8; 32]);
    hk.expand(PARTICIPATION_KEY_DOMAIN, okm.as_mut())
        .map_err(|e| TrustError::InvalidEventData {
            sequence: 0,
            reason: format!("HKDF expansion failed for participation key: {e}"),
        })?;

    let signing_key = ed25519_dalek::SigningKey::from_bytes(&okm);

    Ok(signing_key)
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
/// participation admission requirements, binding every statement to the subject
/// being admitted.
///
/// SECURITY (subject binding + authenticity, not signer authorization):
///
/// 1. SUBJECT BINDING. Participation profiles are PUBLIC and signed by the
///    *context's* participation key — NOT by the subject. A statement therefore
///    proves nothing about *who* presented it. Before any statement contributes
///    to a threshold, freshness, or distinct-signer (`min_contexts`) count, its
///    signed `subject_did` MUST equal `expected_subject` (the agent being
///    admitted). Without this, an attacker could present a victim's genuine,
///    high-standing profiles and be admitted on the victim's reputation
///    (cross-subject profile replay). Statements for any other subject are
///    silently skipped — they never contribute (fail-closed). This mirrors the
///    subject binding in [`check_capability_requirements`].
/// 2. AUTHENTICITY. For the subject-matching statements, this verifies the
///    AUTHENTICITY of each — its Ed25519 signature over `signable_bytes` against
///    the `signer_public_key` carried IN the profile. The signer key is
///    self-certifying: a valid signature proves the profile was not tampered
///    with, NOT that the signer is a legitimate context. A subject could present
///    genuinely-signed profiles from signers it controls and inflate
///    `min_contexts`. Consumers MUST still establish signer legitimacy
///    separately (e.g. a trusted-signer set or a context-membership proof). See
///    spec §7.4.
///
/// For each requirement, the function (over subject-matching statements only):
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
///
/// # Errors
///
/// Returns [`ParticipationAdmissionError`] if any requirement is unmet:
/// signature verification failure, insufficient threshold values, expired
/// statements, or too few distinct context attestations.
pub fn verify_participation_requirements(
    current_time: u64,
    expected_subject: &str,
    requirements: &[RequireParticipation],
    statements: &[ParticipationProfile],
) -> Result<(), ParticipationAdmissionError> {
    use std::collections::HashSet;

    if requirements.is_empty() {
        return Ok(());
    }

    // Step 0: Subject binding. Only statements whose signed `subject_did`
    // matches the agent being admitted may contribute to ANY accounting. A
    // statement for a different subject is silently dropped (fail-closed) so a
    // victim's genuine profiles cannot be replayed to admit an attacker.
    let statements: Vec<&ParticipationProfile> = statements
        .iter()
        .filter(|s| s.subject_did == expected_subject)
        .collect();

    // Step 1: Verify all signatures up front. Any invalid signature is a
    // hard failure regardless of which requirements use it.
    for statement in &statements {
        verify_statement_signature(statement)?;
    }

    // Step 2: Check each requirement independently.
    for req in requirements {
        // Collect qualifying statements: fresh + threshold-satisfying.
        let mut distinct_signers: HashSet<[u8; 32]> = HashSet::new();
        let mut newest_updated_at: u64 = 0;
        let mut any_fresh = false;

        for statement in &statements {
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
        #[allow(clippy::cast_possible_truncation)] // signer count bounded by context membership
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
    use ed25519_dalek::{Signature, VerifyingKey};

    let verifying_key = VerifyingKey::from_bytes(&statement.signer_public_key).map_err(|e| {
        ParticipationAdmissionError::InvalidSignature {
            subject_did: statement.subject_did.clone(),
            signer_hex: hex::encode(&statement.signer_public_key[..8]),
            reason: format!("invalid public key: {e}"),
        }
    })?;

    let signature = Signature::from_bytes(&statement.signature);
    let signable = statement.signable_bytes();

    verifying_key
        .verify_strict(&signable, &signature)
        .map_err(|e| ParticipationAdmissionError::InvalidSignature {
            subject_did: statement.subject_did.clone(),
            signer_hex: hex::encode(&statement.signer_public_key[..8]),
            reason: format!("signature verification failed: {e}"),
        })?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Context-Hosted ParticipationProfile Production (SCP-BA-005)
// ---------------------------------------------------------------------------

/// Produces a signed [`ParticipationProfile`] for a member from the context's
/// event log.
///
/// This is the core protocol operation where a context produces a profile
/// attesting to a member's verifiable participation facts. Key properties:
///
/// Inputs for [`produce_participation_profile`].
///
/// Groups the event log snapshot and membership preconditions to keep the
/// function signature under the 7-argument clippy limit.
pub struct ParticipationInput<'a> {
    /// The context's event log entries.
    pub events: &'a [Event],
    /// Merkle root of the event log at computation time.
    pub merkle_root: [u8; 32],
    /// Whether `member_did` is a current member of the context.
    pub is_member: bool,
    /// Whether `member_did` has opted in to profile publication.
    pub is_opted_in: bool,
    /// Unix timestamp (seconds) for `updated_at`.
    pub current_time: u64,
    /// The member's accessible, currently-valid credential-layer attestations
    /// (§7.4). Threaded into [`compute_participation_record`] to populate the
    /// `attestation_count` fact. A producer without attestation-cache access
    /// passes an empty slice (count 0, verifier-relative per §7.3.2).
    pub accessible_attestations: &'a [Attestation],
}

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
/// - `context_id` — The context ID, used as HKDF salt for key derivation.
///   This ensures the same key material produces different signing keys for
///   different contexts, preventing cross-context signer correlation.
/// - `member_did` — The DID of the member to produce the profile for.
/// - `input` — Event log snapshot and membership preconditions.
///
/// # Errors
///
/// - [`TrustError::NotAMember`] if `input.is_member` is false.
/// - [`TrustError::NotOptedIn`] if `input.is_opted_in` is false.
/// - [`TrustError::EmptyEventLog`] if `input.events` is empty.
/// - [`TrustError::InvalidEventData`] if HKDF key derivation fails.
///
/// See §7.3.2.1.
pub fn produce_participation_profile(
    context_key_material: &[u8; 32],
    context_id: &str,
    member_did: &str,
    input: &ParticipationInput<'_>,
) -> Result<ParticipationProfile, TrustError> {
    use ed25519_dalek::Signer;

    if !input.is_member {
        return Err(TrustError::NotAMember {
            did: member_did.to_owned(),
        });
    }

    if !input.is_opted_in {
        return Err(TrustError::NotOptedIn {
            did: member_did.to_owned(),
        });
    }

    // Compute participation facts from the event log. We use a dummy
    // context_id for the record since ParticipationProfile intentionally
    // omits it — the real context_id is only used for key derivation.
    let record = compute_participation_record(
        input.events,
        member_did,
        "_internal",
        input.merkle_root,
        input.current_time,
        input.accessible_attestations,
    )?;

    // Derive the context-specific signing key using the unified public API.
    // This uses HKDF-SHA256 with context_id as salt, ensuring the same
    // construction used by derive_participation_signing_key.
    let signing_key = derive_participation_signing_key(context_key_material, context_id)?;
    let verifying_key = signing_key.verifying_key();

    // Flatten the record's collections into scalar facts via the single
    // canonical reduction (shared with `ParticipationFacts`), so the signed
    // profile and the unsigned facts view can never drift in how they count.
    let facts = ParticipationFacts::from(&record);

    let mut profile = ParticipationProfile {
        subject_did: member_did.into(),
        participation_duration_secs: facts.participation_duration_secs,
        governance_actions_against: facts.governance_actions_against,
        governance_actions_by: facts.governance_actions_by,
        tool_invocation_count: facts.tool_invocation_count,
        // `tool_invocation_count` is summed from local `ToolInvoked`
        // `ContextEvent`s, not the Merkle log, until ADR-051 (spec §7.3.2).
        tool_invocation_count_anchored: facts.tool_invocation_count_anchored,
        context_creation_count: facts.context_creation_count,
        role_progression_count: facts.role_progression_count,
        attestation_count: facts.attestation_count,
        updated_at: input.current_time,
        event_log_root: input.merkle_root,
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

// NOTE: The following functions were moved to scp-runtime::trust::participation_service
// because they depend on `scp_identity::document::DidDocument`, which would pull
// tokio into scp-protocol's dependency tree:
//   - add_participation_service()
//   - remove_participation_service()
//   - extract_participation_service_endpoint()

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
        let result =
            compute_participation_record(&[], "did:key:alice", "ctx-1", [0u8; 32], 100, &[]);
        assert!(result.is_err());
        match result {
            Err(TrustError::EmptyEventLog) => {}
            other => panic!("expected EmptyEventLog, got {other:?}"),
        }
    }

    #[test]
    fn compute_counts_participation() {
        // participation_count counts ALL of the subject's events; duration is
        // membership-interval based (§7.3.2): the open MemberJoined interval runs
        // to the latest event timestamp across the slice.
        let events = vec![
            make_event(
                EventType::MemberJoined,
                "did:key:alice",
                1000,
                0,
                make_membership_payload("did:key:alice", "member"),
            ),
            make_event(EventType::MessageSent, "did:key:alice", 1001, 1, vec![]),
            make_event(EventType::MessageSent, "did:key:bob", 1002, 2, vec![]),
            make_event(EventType::MessageSent, "did:key:alice", 1005, 3, vec![]),
        ];

        let record =
            compute_participation_record(&events, "did:key:alice", "ctx-1", [1u8; 32], 2000, &[])
                .unwrap();

        assert_eq!(record.subject_did, "did:key:alice");
        assert_eq!(record.context_id, "ctx-1");
        // MemberJoined + 2 MessageSent by alice.
        assert_eq!(record.participation_count, 3);
        // Open interval: latest_event_ts (1005) - MemberJoined ts (1000).
        assert_eq!(record.participation_duration_seconds, 5);
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
            compute_participation_record(&events, "did:key:alice", "ctx-1", [0u8; 32], 2000, &[])
                .unwrap();

        assert_eq!(record.tool_invocations.len(), 2);
        assert_eq!(record.tool_invocations.get("tool-search"), Some(&2));
        assert_eq!(record.tool_invocations.get("tool-execute"), Some(&1));
    }

    #[test]
    fn compute_tracks_governance_actions_by_subject() {
        let events = vec![
            make_event(
                EventType::GovernanceActionExecuted,
                "did:key:alice",
                1000,
                0,
                make_gov_payload("did:key:bob", "RemoveMember"),
            ),
            // Untargeted action (empty target_did) — still counts as an action
            // BY the subject, but projects no target.
            make_event(
                EventType::GovernanceActionExecuted,
                "did:key:alice",
                1001,
                1,
                make_gov_payload("", "ModifyPolicy"),
            ),
        ];

        let record =
            compute_participation_record(&events, "did:key:alice", "ctx-1", [0u8; 32], 2000, &[])
                .unwrap();

        assert_eq!(record.governance_actions_by.len(), 2);
        assert_eq!(record.governance_actions_by[0].event_sequence, 0);
        assert_eq!(
            record.governance_actions_by[0].target_did,
            Some("did:key:bob".into())
        );
        // Second action has empty target_did -> projects to no target.
        assert_eq!(record.governance_actions_by[1].target_did, None);
    }

    #[test]
    fn undecodable_governance_payload_by_subject_still_recorded() {
        // `0xff` is a MessagePack negative fixint (-1), not a 2-element array,
        // so `decode_payload::<GovernanceActionExecutedPayload>` returns Err.
        // The subject is the actor of this leaf, so the action MUST still be
        // recorded in `governance_actions_by` with a best-effort `None` target
        // — a naive `let-else` early-return on the decode would wrongly drop it.
        let events = vec![make_event(
            EventType::GovernanceActionExecuted,
            "did:key:alice",
            1000,
            0,
            vec![0xff],
        )];

        let record = compute_participation_record(
            &events,
            "did:key:alice",
            "ctx-undecodable-by",
            [0u8; 32],
            2000,
            &[],
        )
        .unwrap();

        assert_eq!(
            record.governance_actions_by.len(),
            1,
            "subject's governance action is recorded even when the payload is undecodable"
        );
        assert!(
            record.governance_actions_by[0].target_did.is_none(),
            "undecodable governance payload yields no target"
        );
        assert_eq!(
            record.governance_actions_against.len(),
            0,
            "the actor isn't its own non-subject target"
        );
    }

    #[test]
    fn compute_tracks_governance_actions_against_subject() {
        let events = vec![
            make_event(
                EventType::GovernanceActionExecuted,
                "did:key:admin",
                1000,
                0,
                make_gov_payload("did:key:alice", "RemoveMember"),
            ),
            make_event(
                EventType::GovernanceActionExecuted,
                "did:key:admin",
                1001,
                1,
                make_gov_payload("did:key:bob", "RemoveMember"),
            ),
        ];

        let record =
            compute_participation_record(&events, "did:key:alice", "ctx-1", [0u8; 32], 2000, &[])
                .unwrap();

        // Only the first governance action targets alice.
        assert_eq!(record.governance_actions_against.len(), 1);
        assert_eq!(
            record.governance_actions_against[0].actor_did,
            "did:key:admin"
        );
        assert_eq!(record.governance_actions_against[0].event_sequence, 0);
    }

    /// Helper: create a canonical `GovernanceActionExecutedPayload` (positional
    /// `MessagePack`, ADR-011 amendment) carrying both `target_did` and
    /// `action_type`.
    fn make_gov_payload(target_did: &str, action_type: &str) -> Vec<u8> {
        scp_event_log::payload::encode_payload(
            &scp_event_log::payload::GovernanceActionExecutedPayload {
                target_did: target_did.to_owned(),
                action_type: action_type.to_owned(),
            },
        )
        .unwrap()
        .data
    }

    /// Helper: create a canonical `RoleAssignedPayload` carrying the affected
    /// member's `subject_did`.
    fn make_role_payload(subject_did: &str, role: &str) -> Vec<u8> {
        scp_event_log::payload::encode_payload(&scp_event_log::payload::RoleAssignedPayload {
            subject_did: subject_did.to_owned(),
            role: role.to_owned(),
        })
        .unwrap()
        .data
    }

    /// Helper: create a canonical `MembershipChangePayload` (for `MemberJoined`/
    /// `MemberLeft`) carrying the affected member's `subject_did`.
    fn make_membership_payload(subject_did: &str, role_name: &str) -> Vec<u8> {
        scp_event_log::payload::encode_payload(&scp_event_log::payload::MembershipChangePayload {
            subject_did: subject_did.to_owned(),
            role_name: role_name.to_owned(),
        })
        .unwrap()
        .data
    }

    // --- H18: standing-deflation filter tests ---

    #[test]
    fn restore_access_does_not_count_against_victim() {
        // A hostile admin issues 5 RestoreAccess { did: victim } actions.
        // These are beneficial — they MUST NOT inflate governance_actions_against.
        let victim = "did:key:victim";
        let events: Vec<Event> = (0..5)
            .map(|i| {
                make_event(
                    EventType::GovernanceActionExecuted,
                    "did:key:admin",
                    1000 + i,
                    i,
                    make_gov_payload(victim, "RestoreAccess"),
                )
            })
            .collect();

        let record =
            compute_participation_record(&events, victim, "ctx-h18", [0u8; 32], 9000, &[]).unwrap();

        assert_eq!(
            record.governance_actions_against.len(),
            0,
            "RestoreAccess must not count against the victim (H18)"
        );
    }

    #[test]
    fn suspend_capability_counts_against_victim() {
        // A SuspendCapability action targeting the victim IS adverse and must
        // be counted.
        let victim = "did:key:victim";
        let events = vec![make_event(
            EventType::GovernanceActionExecuted,
            "did:key:admin",
            1000,
            0,
            make_gov_payload(victim, "SuspendCapability"),
        )];

        let record =
            compute_participation_record(&events, victim, "ctx-h18", [0u8; 32], 9000, &[]).unwrap();

        assert_eq!(
            record.governance_actions_against.len(),
            1,
            "SuspendCapability must count against the victim"
        );
    }

    #[test]
    fn mixed_actions_only_counts_adverse() {
        // 3 RestoreAccess + 2 SuspendCapability + 1 RemoveMember against victim.
        // Only the 3 adverse ones (2 SuspendCapability + 1 RemoveMember) count.
        let victim = "did:key:victim";
        let events = vec![
            make_event(
                EventType::GovernanceActionExecuted,
                "did:key:admin",
                1000,
                0,
                make_gov_payload(victim, "RestoreAccess"),
            ),
            make_event(
                EventType::GovernanceActionExecuted,
                "did:key:admin",
                1001,
                1,
                make_gov_payload(victim, "RestoreAccess"),
            ),
            make_event(
                EventType::GovernanceActionExecuted,
                "did:key:admin",
                1002,
                2,
                make_gov_payload(victim, "RestoreAccess"),
            ),
            make_event(
                EventType::GovernanceActionExecuted,
                "did:key:admin",
                1003,
                3,
                make_gov_payload(victim, "SuspendCapability"),
            ),
            make_event(
                EventType::GovernanceActionExecuted,
                "did:key:admin",
                1004,
                4,
                make_gov_payload(victim, "SuspendCapability"),
            ),
            make_event(
                EventType::GovernanceActionExecuted,
                "did:key:admin",
                1005,
                5,
                make_gov_payload(victim, "RemoveMember"),
            ),
        ];

        let record =
            compute_participation_record(&events, victim, "ctx-h18", [0u8; 32], 9000, &[]).unwrap();

        assert_eq!(
            record.governance_actions_against.len(),
            3,
            "only adverse actions (2 SuspendCapability + 1 RemoveMember) should count (H18)"
        );
    }

    #[test]
    fn approve_spend_does_not_count_against_beneficiary() {
        // ApproveSpend is beneficial. Even when its target_did is the victim,
        // it must not count against them.
        let victim = "did:key:victim";
        let events = vec![make_event(
            EventType::GovernanceActionExecuted,
            "did:key:admin",
            1000,
            0,
            make_gov_payload(victim, "ApproveSpend"),
        )];

        let record =
            compute_participation_record(&events, victim, "ctx-h18", [0u8; 32], 9000, &[]).unwrap();

        assert_eq!(
            record.governance_actions_against.len(),
            0,
            "ApproveSpend must not count against the beneficiary (H18)"
        );
    }

    #[test]
    fn empty_action_type_governance_action_counts_as_adverse() {
        // A GovernanceActionExecuted leaf whose decoded action_type is empty
        // cannot be classified as beneficial, so the conservative default is to
        // count it against the subject. This pins the documented legacy-compat
        // guarantee: when in doubt, treat a governance action as adverse.
        let victim = "did:key:victim";
        let events = vec![make_event(
            EventType::GovernanceActionExecuted,
            "did:key:admin",
            1000,
            0,
            make_gov_payload(victim, ""),
        )];

        let record =
            compute_participation_record(&events, victim, "ctx-h18", [0u8; 32], 9000, &[]).unwrap();

        assert_eq!(
            record.governance_actions_against.len(),
            1,
            "empty action_type is conservatively adverse (pre-H18 compat)"
        );
    }

    #[test]
    fn compute_tracks_role_history() {
        let events = vec![
            make_event(
                EventType::RoleAssigned,
                "did:key:admin",
                1000,
                0,
                make_role_payload("did:key:alice", "moderator"),
            ),
            make_event(
                EventType::RoleAssigned,
                "did:key:admin",
                1005,
                1,
                make_role_payload("did:key:alice", "admin"),
            ),
            make_event(
                EventType::RoleAssigned,
                "did:key:admin",
                1010,
                2,
                make_role_payload("did:key:bob", "moderator"),
            ),
        ];

        // RoleAssigned keys on the projected subject_did (affected member), not
        // the assigning admin actor.
        let record =
            compute_participation_record(&events, "did:key:alice", "ctx-1", [0u8; 32], 2000, &[])
                .unwrap();

        assert_eq!(record.role_history.len(), 2);
        assert_eq!(record.role_history[0].timestamp, 1000);
        assert_eq!(record.role_history[0].assigned_by, "did:key:admin");
        assert_eq!(record.role_history[1].timestamp, 1005);
    }

    #[test]
    fn compute_tracks_context_creation() {
        let events = vec![
            make_event(
                EventType::ChildContextCreated,
                "did:key:alice",
                1000,
                0,
                vec![],
            ),
            make_event(
                EventType::ChildContextCreated,
                "did:key:bob",
                1001,
                1,
                vec![],
            ),
            make_event(
                EventType::ChildContextCreated,
                "did:key:alice",
                1002,
                2,
                vec![],
            ),
        ];

        // context_creation_count derives from ChildContextCreated (§7.3.2).
        let record =
            compute_participation_record(&events, "did:key:alice", "ctx-1", [0u8; 32], 2000, &[])
                .unwrap();

        assert_eq!(record.context_creation_count, 2);
    }

    /// Builds a credential-layer [`Attestation`] fixture. The signature is a
    /// dummy — `compute_participation_record` does NOT verify signatures; it only
    /// counts/filters by `subject` and `revocation_status`.
    fn make_attestation(
        id: &str,
        issuer: &str,
        subject: &str,
        issued_at: u64,
        revocation_status: RevocationStatus,
    ) -> Attestation {
        Attestation {
            id: id.to_owned(),
            attestation_type: crate::trust::AttestationType::Endorsement,
            issuer: issuer.into(),
            subject: subject.into(),
            claim: serde_json::Value::Null,
            evidence: None,
            issued_at,
            expires_at: None,
            renewal_interval: None,
            renewed_at: None,
            revocation_status,
            signature: vec![0u8; 64],
        }
    }

    #[test]
    fn compute_tracks_attestation_history() {
        // attestation_history is sourced from the credential-layer
        // `accessible_attestations` arg (§7.4), NOT the event log. Filtered to
        // the subject and to non-revoked entries.
        let events = vec![make_event(
            EventType::MessageSent,
            "did:key:alice",
            1000,
            0,
            vec![],
        )];
        let attestations = vec![
            make_attestation(
                "att-alice-1",
                "did:key:issuer",
                "did:key:alice",
                1000,
                RevocationStatus::Active,
            ),
            // Different subject — must NOT count for alice.
            make_attestation(
                "att-bob-1",
                "did:key:issuer",
                "did:key:bob",
                1001,
                RevocationStatus::Active,
            ),
            // Revoked — must NOT count even though subject matches.
            make_attestation(
                "att-alice-revoked",
                "did:key:issuer",
                "did:key:alice",
                1002,
                RevocationStatus::Revoked {
                    revoked_at: 1003,
                    reason: String::new(),
                    revoked_by: "did:key:issuer".into(),
                },
            ),
        ];

        let record = compute_participation_record(
            &events,
            "did:key:alice",
            "ctx-1",
            [0u8; 32],
            2000,
            &attestations,
        )
        .unwrap();

        assert_eq!(record.attestation_history.len(), 1);
        assert_eq!(record.attestation_history[0].timestamp, 1000);
        assert_eq!(record.attestation_history[0].actor_did, "did:key:issuer");
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
            compute_participation_record(&events, "did:key:alice", "ctx-1", [0u8; 32], 2000, &[])
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
            compute_participation_record(&events, "did:key:alice", "ctx-1", [0u8; 32], 2000, &[])
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
            compute_participation_record(&events, "did:key:alice", "ctx-1", merkle_root, 2000, &[])
                .unwrap();

        assert_eq!(record.event_log_root, merkle_root);
    }

    #[test]
    fn compute_full_scenario() {
        // Simulate a realistic event sequence using the canonical subject-bearing
        // leaves. attestation_history is sourced from the credential layer; here
        // a single Active attestation for alice is supplied.
        let events = vec![
            make_event(
                EventType::ChildContextCreated,
                "did:key:alice",
                1000,
                0,
                vec![],
            ),
            make_event(
                EventType::MemberJoined,
                "did:key:alice",
                1001,
                1,
                make_membership_payload("did:key:alice", "admin"),
            ),
            make_event(
                EventType::MemberJoined,
                "did:key:bob",
                1002,
                2,
                make_membership_payload("did:key:bob", "member"),
            ),
            make_event(
                EventType::RoleAssigned,
                "did:key:alice",
                1003,
                3,
                make_role_payload("did:key:bob", "moderator"),
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
                EventType::GovernanceActionExecuted,
                "did:key:alice",
                1008,
                8,
                make_gov_payload("did:key:bob", "RemoveMember"),
            ),
        ];
        let attestations = vec![make_attestation(
            "att-alice",
            "did:key:issuer",
            "did:key:alice",
            900,
            RevocationStatus::Active,
        )];

        let record = compute_participation_record(
            &events,
            "did:key:alice",
            "ctx-1",
            [99u8; 32],
            5000,
            &attestations,
        )
        .unwrap();

        // Alice's events: ChildContextCreated, MemberJoined, RoleAssigned (actor),
        // MessageSent, 2x ToolInvoked, GovernanceActionExecuted = 7.
        assert_eq!(record.participation_count, 7);
        // Open MemberJoined interval (1001) → latest event ts (1008) = 7.
        assert_eq!(record.participation_duration_seconds, 7);
        assert_eq!(record.tool_invocations.get("search-tool"), Some(&2));
        assert_eq!(record.governance_actions_by.len(), 1);
        assert_eq!(record.governance_actions_against.len(), 0);
        // Alice assigned bob's role — subject is bob, not alice.
        assert_eq!(record.role_history.len(), 0);
        // Credential-layer attestation for alice.
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
            tool_invocation_count_anchored: false,
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
        let domain_len = b"SCP-PARTICIPATION-V1:".len();
        // domain separator + 4 (length prefix) + did_len + 8*8 (8 u64 fields)
        // + 1 (tool_invocation_count_anchored byte) + 32 + 32
        let expected = domain_len + 4 + did_len + 64 + 1 + 64;
        assert_eq!(bytes.len(), expected);
    }

    #[test]
    fn signable_bytes_changes_with_tool_invocation_count_anchored() {
        // The truth-in-advertising flag is part of the signed preimage (spec
        // §7.3.2), so two profiles differing ONLY in it produce different
        // `signable_bytes` — a signature cannot be transplanted between an
        // anchored and an unanchored claim.
        let mut profile_false = make_profile();
        profile_false.tool_invocation_count_anchored = false;
        let mut profile_true = make_profile();
        profile_true.tool_invocation_count_anchored = true;

        assert_ne!(
            profile_false.signable_bytes(),
            profile_true.signable_bytes(),
            "flipping tool_invocation_count_anchored MUST change the signed preimage"
        );
    }

    #[test]
    fn signature_binds_tool_invocation_count_anchored() {
        use ed25519_dalek::{Signer, Verifier};

        let signing_key = test_signing_key(7);
        let verifying_key = signing_key.verifying_key();

        let mut profile = make_profile();
        profile.tool_invocation_count_anchored = false;
        profile.signer_public_key = verifying_key.to_bytes();
        let sig = signing_key.sign(&profile.signable_bytes());
        profile.signature = sig.to_bytes();

        // The signature verifies over the unanchored profile.
        assert!(
            verifying_key
                .verify(&profile.signable_bytes(), &sig)
                .is_ok()
        );

        // Flipping the flag (without re-signing) breaks verification — the
        // signature is bound to the anchored bit.
        let mut tampered = profile;
        tampered.tool_invocation_count_anchored = true;
        assert!(
            verifying_key
                .verify(&tampered.signable_bytes(), &sig)
                .is_err(),
            "flipping the anchored bit MUST invalidate the bound signature"
        );
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
            tool_invocation_count_anchored: false,
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
            tool_invocation_count_anchored: ov.tool_invocation_count_anchored.unwrap_or(false),
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
        tool_invocation_count_anchored: Option<bool>,
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
        let result = verify_participation_requirements(1_700_000_000, "did:key:alice", &[], &[]);
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

        let result =
            verify_participation_requirements(1_700_000_100, "did:key:alice", &[req], &[statement]);
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

        let result =
            verify_participation_requirements(1_700_000_100, "did:key:alice", &reqs, &[statement]);
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

        let result =
            verify_participation_requirements(1_700_000_100, "did:key:alice", &[req], &[statement]);
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

        let result =
            verify_participation_requirements(1_700_000_100, "did:key:alice", &[req], &[statement]);
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
        let result =
            verify_participation_requirements(1_700_010_000, "did:key:alice", &[req], &[statement]);
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

        let result =
            verify_participation_requirements(1_700_000_100, "did:key:alice", &[req], &[statement]);
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

        let result =
            verify_participation_requirements(1_700_000_100, "did:key:alice", &[req], &[s1, s2]);
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

        let result = verify_participation_requirements(
            1_700_000_100,
            "did:key:alice",
            &[req],
            &[s1, s2, s3],
        );
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

        let result = verify_participation_requirements(1_700_000_000, "did:key:alice", &[req], &[]);
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

        let result =
            verify_participation_requirements(1_700_003_700, "did:key:alice", &[req], &[s1, s2]);
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

        let result =
            verify_participation_requirements(1_700_000_100, "did:key:alice", &reqs, &[statement]);
        match result {
            Err(ParticipationAdmissionError::ThresholdNotMet { fact, value, .. }) => {
                assert_eq!(fact, ParticipationFact::ContextCreationCount);
                assert_eq!(value, 1);
            }
            other => panic!("expected ThresholdNotMet, got {other:?}"),
        }
    }

    #[test]
    fn verify_rejects_cross_subject_profile_replay() {
        // A victim's GENUINE, context-signed, high-standing profile must NOT
        // satisfy a requirement when the agent being admitted is someone else.
        // This is the cross-subject participation-profile replay attack: the
        // signer key is the context's (self-certifying), so signature validity
        // alone does not bind the standing to the presenter.
        let key = test_signing_key(1);
        let victim_profile = make_signed_profile(&key, "did:key:victim", 1_700_000_000, None);

        let req = RequireParticipation {
            fact: ParticipationFact::ToolInvocationCount,
            threshold: ParticipationThreshold::AtLeast(100),
            max_age_secs: 3600,
            min_contexts: 1,
        };

        // The attacker ("did:key:attacker") presents the victim's profiles.
        let result = verify_participation_requirements(
            1_700_000_100,
            "did:key:attacker",
            &[req],
            &[victim_profile],
        );
        // With no subject-matching statements, the requirement is unmet.
        match result {
            Err(ParticipationAdmissionError::ThresholdNotMet { .. }) => {}
            other => panic!("expected ThresholdNotMet (no matching subject), got {other:?}"),
        }
    }

    #[test]
    fn verify_subject_owned_profile_satisfies_requirement() {
        // The same profile DOES satisfy the requirement when the agent being
        // admitted IS the subject the profile was issued for. This is the
        // positive counterpart to `verify_rejects_cross_subject_profile_replay`.
        let key = test_signing_key(1);
        let victim_profile = make_signed_profile(&key, "did:key:victim", 1_700_000_000, None);

        let req = RequireParticipation {
            fact: ParticipationFact::ToolInvocationCount,
            threshold: ParticipationThreshold::AtLeast(100),
            max_age_secs: 3600,
            min_contexts: 1,
        };

        let result = verify_participation_requirements(
            1_700_000_100,
            "did:key:victim",
            &[req],
            &[victim_profile],
        );
        assert!(result.is_ok());
    }

    #[test]
    fn verify_mixed_subjects_counts_only_matching_subject() {
        // distinct-signer (`min_contexts`) accounting must ignore statements for
        // other subjects: three distinct signers across two subjects must not be
        // pooled to satisfy a `min_contexts: 2` requirement for one subject.
        let key1 = test_signing_key(1);
        let key2 = test_signing_key(2);
        let key3 = test_signing_key(3);

        // Two distinct signers attest the attacker; one attests the victim.
        let attacker_a = make_signed_profile(&key1, "did:key:attacker", 1_700_000_000, None);
        let victim_b = make_signed_profile(&key2, "did:key:victim", 1_700_000_000, None);
        let victim_c = make_signed_profile(&key3, "did:key:victim", 1_700_000_000, None);

        let req = RequireParticipation {
            fact: ParticipationFact::ToolInvocationCount,
            threshold: ParticipationThreshold::AtLeast(100),
            max_age_secs: 3600,
            min_contexts: 2,
        };

        // Admitting the attacker: only `attacker_a` matches → 1 distinct signer,
        // below the required 2. The victim's two signers must NOT be borrowed.
        let result = verify_participation_requirements(
            1_700_000_100,
            "did:key:attacker",
            &[req],
            &[attacker_a, victim_b, victim_c],
        );
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

    // -----------------------------------------------------------------------
    // produce_participation_profile tests (SCP-BA-005)
    // -----------------------------------------------------------------------

    fn make_member_events(actor_did: &str) -> Vec<Event> {
        vec![
            make_event(EventType::ChildContextCreated, actor_did, 1000, 0, vec![]),
            make_event(
                EventType::MemberJoined,
                actor_did,
                1001,
                1,
                make_membership_payload(actor_did, "member"),
            ),
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
            // Governance action BY the member (targets someone else).
            make_event(
                EventType::GovernanceActionExecuted,
                actor_did,
                1005,
                5,
                make_gov_payload("did:key:target", "RemoveMember"),
            ),
            // Adverse governance action AGAINST the member (by an admin).
            make_event(
                EventType::GovernanceActionExecuted,
                "did:key:admin",
                1006,
                6,
                make_gov_payload(actor_did, "RemoveMember"),
            ),
            // Role assignment whose subject is the member.
            make_event(
                EventType::RoleAssigned,
                "did:key:admin",
                1007,
                7,
                make_role_payload(actor_did, "moderator"),
            ),
            make_event(EventType::MessageSent, actor_did, 1100, 9, vec![]),
        ]
    }

    #[test]
    fn produce_profile_for_valid_opted_in_member() {
        let key_material = [42u8; 32];
        let events = make_member_events("did:key:alice");
        let merkle_root = [0xAA; 32];
        // A single Active credential-layer attestation for the member, to
        // exercise the attestation_count path end-to-end.
        let attestations = vec![make_attestation(
            "att-alice",
            "did:key:issuer",
            "did:key:alice",
            900,
            RevocationStatus::Active,
        )];

        let profile = produce_participation_profile(
            &key_material,
            "ctx-test",
            "did:key:alice",
            &ParticipationInput {
                events: &events,
                merkle_root,
                is_member: true,
                is_opted_in: true,
                current_time: 5000,
                accessible_attestations: &attestations,
            },
        )
        .unwrap();

        assert_eq!(profile.subject_did, "did:key:alice");
        // Membership-interval duration: latest event ts (1100) - MemberJoined (1001).
        assert_eq!(profile.participation_duration_secs, 99);
        assert_eq!(profile.governance_actions_by, 1);
        assert_eq!(profile.governance_actions_against, 1);
        assert_eq!(profile.tool_invocation_count, 3); // tool-a x2 + tool-b x1
        assert_eq!(profile.context_creation_count, 1);
        assert_eq!(profile.role_progression_count, 1);
        // attestation_count from the supplied credential-layer attestation set.
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
            "ctx-test",
            "did:key:alice",
            &ParticipationInput {
                events: &events,
                merkle_root: [0; 32],
                is_member: true,
                is_opted_in: true,
                current_time: 5000,
                accessible_attestations: &[],
            },
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
            "ctx-test",
            "did:key:alice",
            &ParticipationInput {
                events: &events,
                merkle_root: [0; 32],
                is_member: false, // not a member
                is_opted_in: true,
                current_time: 5000,
                accessible_attestations: &[],
            },
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
            "ctx-test",
            "did:key:alice",
            &ParticipationInput {
                events: &events,
                merkle_root: [0; 32],
                is_member: true,
                is_opted_in: false, // not opted in
                current_time: 5000,
                accessible_attestations: &[],
            },
        );
        match result {
            Err(TrustError::NotOptedIn { did }) => assert_eq!(did, "did:key:alice"),
            other => panic!("expected NotOptedIn, got {other:?}"),
        }
    }

    #[test]
    fn produce_profile_different_contexts_produce_different_signers() {
        let events = make_member_events("did:key:alice");
        let key_material = [42u8; 32];

        let profile_a = produce_participation_profile(
            &key_material,
            "ctx-alpha",
            "did:key:alice",
            &ParticipationInput {
                events: &events,
                merkle_root: [0; 32],
                is_member: true,
                is_opted_in: true,
                current_time: 5000,
                accessible_attestations: &[],
            },
        )
        .unwrap();

        let profile_b = produce_participation_profile(
            &key_material,
            "ctx-beta",
            "did:key:alice",
            &ParticipationInput {
                events: &events,
                merkle_root: [0; 32],
                is_member: true,
                is_opted_in: true,
                current_time: 5000,
                accessible_attestations: &[],
            },
        )
        .unwrap();

        assert_ne!(
            profile_a.signer_public_key, profile_b.signer_public_key,
            "different context IDs must produce different signer keys"
        );
    }

    #[test]
    fn produce_profile_same_context_produces_same_signer() {
        let key_material = [42u8; 32];
        let events = make_member_events("did:key:alice");

        let profile_a = produce_participation_profile(
            &key_material,
            "ctx-test",
            "did:key:alice",
            &ParticipationInput {
                events: &events,
                merkle_root: [0; 32],
                is_member: true,
                is_opted_in: true,
                current_time: 5000,
                accessible_attestations: &[],
            },
        )
        .unwrap();

        let profile_b = produce_participation_profile(
            &key_material,
            "ctx-test",
            "did:key:alice",
            &ParticipationInput {
                events: &events,
                merkle_root: [0; 32],
                is_member: true,
                is_opted_in: true,
                current_time: 6000,
                accessible_attestations: &[],
            },
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
            "ctx-test",
            "did:key:alice",
            &ParticipationInput {
                events: &events,
                merkle_root: [0; 32],
                is_member: true,
                is_opted_in: true,
                current_time: 5000,
                accessible_attestations: &[],
            },
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
            "ctx-test",
            "did:key:alice",
            &ParticipationInput {
                events: &events,
                merkle_root: [1; 32],
                is_member: true,
                is_opted_in: true,
                current_time: 6000,
                accessible_attestations: &[],
            },
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
            "ctx-test",
            "did:key:alice",
            &ParticipationInput {
                events: &events,
                merkle_root: [0; 32],
                is_member: true,
                is_opted_in: true,
                current_time: 5000,
                accessible_attestations: &[],
            },
        )
        .unwrap();

        let json = serde_json::to_string(&profile).unwrap();
        assert!(
            !json.contains("context_id"),
            "serialized profile must not contain context_id"
        );
    }

    // SCP-BA-006 tests moved to scp-runtime::trust::participation_service (they
    // depend on scp_identity::document::DidDocument).

    // -----------------------------------------------------------------------
    // Canonical subject-bearing payload tests
    // -----------------------------------------------------------------------

    /// `governance_actions_against` is populated when canonical
    /// `GovernanceActionExecuted` leaves carry an adverse `target_did` matching
    /// the subject.
    #[test]
    fn test_participation_actions_against_populated() {
        let payload = make_gov_payload("did:key:alice", "RemoveMember");

        let events = vec![
            make_event(
                EventType::GovernanceActionExecuted,
                "did:key:admin",
                1000,
                0,
                payload.clone(),
            ),
            make_event(
                EventType::GovernanceActionExecuted,
                "did:key:moderator",
                1001,
                1,
                payload,
            ),
            // Action targeting bob — should not count against alice.
            make_event(
                EventType::GovernanceActionExecuted,
                "did:key:admin",
                1002,
                2,
                make_gov_payload("did:key:bob", "RemoveMember"),
            ),
        ];

        let record =
            compute_participation_record(&events, "did:key:alice", "ctx-1", [0u8; 32], 2000, &[])
                .unwrap();

        assert_eq!(
            record.governance_actions_against.len(),
            2,
            "both governance actions targeting alice should be recorded"
        );
        assert_eq!(
            record.governance_actions_against[0].actor_did,
            "did:key:admin"
        );
        assert_eq!(
            record.governance_actions_against[0].target_did,
            Some("did:key:alice".into())
        );
        assert_eq!(
            record.governance_actions_against[1].actor_did,
            "did:key:moderator"
        );
    }

    /// A membership re-join (`MemberJoined` → `MemberLeft` → `MemberJoined`) sums
    /// two intervals, with the final open interval running to the latest event.
    #[test]
    fn compute_sums_membership_rejoin_intervals() {
        let subject = "did:key:alice";
        let events = vec![
            make_event(
                EventType::MemberJoined,
                subject,
                1000,
                0,
                make_membership_payload(subject, "member"),
            ),
            make_event(
                EventType::MemberLeft,
                subject,
                1010,
                1,
                make_membership_payload(subject, "member"),
            ),
            make_event(
                EventType::MemberJoined,
                subject,
                1020,
                2,
                make_membership_payload(subject, "member"),
            ),
            make_event(EventType::MessageSent, subject, 1025, 3, vec![]),
        ];

        let record =
            compute_participation_record(&events, subject, "ctx-1", [0u8; 32], 2000, &[]).unwrap();

        // First interval 1010-1000 = 10; open interval 1025 (latest) - 1020 = 5.
        assert_eq!(record.participation_duration_seconds, 15);
    }

    /// An admin-driven `MemberJoined` leaf attributes the interval to the
    /// affected member (projected `subject_did`), NOT to the executing admin
    /// actor.
    #[test]
    fn compute_attributes_admin_driven_join_to_affected_member() {
        let member = "did:key:alice";
        let events = vec![
            make_event(
                EventType::MemberJoined,
                "did:key:admin", // actor is the admin
                1000,
                0,
                make_membership_payload(member, "member"), // subject is the member
            ),
            make_event(EventType::MessageSent, member, 1050, 1, vec![]),
        ];

        let member_record =
            compute_participation_record(&events, member, "ctx-1", [0u8; 32], 2000, &[]).unwrap();
        // Member's interval: 1050 (latest) - 1000 (join) = 50.
        assert_eq!(member_record.participation_duration_seconds, 50);

        let admin_record =
            compute_participation_record(&events, "did:key:admin", "ctx-1", [0u8; 32], 2000, &[])
                .unwrap();
        // The admin executed the join but is not the affected member — no interval.
        assert_eq!(admin_record.participation_duration_seconds, 0);
    }

    #[test]
    fn participation_facts_flattens_record_collections_to_counts() {
        let member = "did:key:alice";
        let admin = "did:key:admin";
        let events = vec![
            // Membership interval 1000 → 1300 = 300s for the member.
            make_event(
                EventType::MemberJoined,
                admin,
                1000,
                0,
                make_membership_payload(member, "member"),
            ),
            // Role assigned to the member (role_progression).
            make_event(
                EventType::RoleAssigned,
                admin,
                1100,
                1,
                make_role_payload(member, "admin"),
            ),
            // Adverse governance action targeting the member (against).
            make_event(
                EventType::GovernanceActionExecuted,
                admin,
                1150,
                2,
                make_gov_payload(member, "RemoveMember"),
            ),
            // Governance action executed BY the member (by).
            make_event(
                EventType::GovernanceActionExecuted,
                member,
                1200,
                3,
                make_gov_payload(admin, "RemoveMember"),
            ),
            // Child context created by the member.
            make_event(EventType::ChildContextCreated, member, 1250, 4, vec![]),
            make_event(
                EventType::MemberLeft,
                admin,
                1300,
                5,
                make_membership_payload(member, "member"),
            ),
        ];

        let record =
            compute_participation_record(&events, member, "ctx-1", [9u8; 32], 5000, &[]).unwrap();
        let facts = ParticipationFacts::from(&record);

        // Each scalar fact equals the reduction of the corresponding record field.
        assert_eq!(
            facts.governance_actions_against,
            record.governance_actions_against.len() as u64
        );
        assert_eq!(facts.governance_actions_against, 1);
        assert_eq!(
            facts.governance_actions_by,
            record.governance_actions_by.len() as u64
        );
        assert_eq!(facts.governance_actions_by, 1);
        assert_eq!(
            facts.role_progression_count,
            record.role_history.len() as u64
        );
        assert_eq!(facts.role_progression_count, 1);
        assert_eq!(
            facts.tool_invocation_count,
            record.tool_invocations.values().sum::<u64>()
        );
        assert_eq!(
            facts.attestation_count,
            record.attestation_history.len() as u64
        );
        assert_eq!(
            facts.participation_duration_secs,
            record.participation_duration_seconds
        );
        assert_eq!(facts.participation_duration_secs, 300);
        assert_eq!(facts.context_creation_count, record.context_creation_count);
        assert_eq!(facts.context_creation_count, 1);
        assert_eq!(facts.computed_at, record.computed_at);
        assert_eq!(facts.event_log_root, record.event_log_root);
        assert_eq!(facts.subject_did.as_ref(), member);
        // Tool count is never Merkle-anchored until ADR-051.
        assert!(!facts.tool_invocation_count_anchored);
    }

    #[test]
    fn adverse_action_types_pin_governance_variant_names() {
        // Pins the `ADVERSE_ACTION_TYPES` string literals to the actual
        // `GovernanceAction::variant_name()` output. The literals are matched
        // against `variant_name()` at runtime in `is_adverse_action_type`, but
        // nothing else binds the two; a future variant rename would silently
        // make `governance_actions_against` stop counting that action. This test
        // constructs every adverse variant and asserts the correspondence in
        // both directions.
        use crate::context::governance::{AccessScope, GovernanceAction};
        use scp_primitives::DID;

        let target = || DID::from("did:dht:z6MkAdverseTarget");

        let adverse: &[GovernanceAction] = &[
            GovernanceAction::SuspendCapability {
                did: target(),
                capabilities: vec![],
            },
            GovernanceAction::SuspendAccess { did: target() },
            GovernanceAction::RevokeAccess {
                did: target(),
                access: AccessScope::Both,
            },
            GovernanceAction::RemoveMember {
                did: target(),
                reason: None,
            },
            GovernanceAction::ResetMember {
                did: target(),
                reason: String::new(),
            },
        ];

        // Forward: every constructed adverse variant's name is in the set.
        for action in adverse {
            let name = action.variant_name();
            assert!(
                ADVERSE_ACTION_TYPES.contains(&name),
                "GovernanceAction variant_name {name:?} is absent from \
                 ADVERSE_ACTION_TYPES — a rename desynced the adverse-action \
                 set; governance_actions_against would stop counting it",
            );
            // And the runtime classifier agrees.
            assert!(is_adverse_action_type(name));
        }

        // Reverse: every literal in the set is produced by some constructed
        // adverse variant, so a stale literal (renamed/removed variant) is
        // also caught.
        let produced: Vec<&str> = adverse.iter().map(GovernanceAction::variant_name).collect();
        for literal in ADVERSE_ACTION_TYPES {
            assert!(
                produced.contains(literal),
                "ADVERSE_ACTION_TYPES literal {literal:?} is not produced by \
                 any constructed adverse GovernanceAction variant — it is \
                 stale",
            );
        }
    }
}
