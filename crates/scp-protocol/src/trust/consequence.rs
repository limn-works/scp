//! Consequence rule evaluation for SCP contexts.
//!
//! Consequence rules are declared at context creation and protocol-enforced.
//! Consequences are part of the opt-in contract -- visible before joining,
//! protocol-enforced, verifiable. No hidden penalties.
//!
//! The [`evaluate_consequence_rules`] function checks each rule's trigger
//! condition against event log data within the rule's time window and returns
//! a list of triggered consequences with the triggering evidence.
//!
//! See ADR-017 acceptance criterion 6 in `.docs/adrs/phase-4.md`.

use std::time::Duration;

use serde::{Deserialize, Serialize};

use scp_event_log::{Event, EventType};
use scp_primitives::DID;

// ---------------------------------------------------------------------------
// ConsequenceValidationError
// ---------------------------------------------------------------------------

/// Error returned when a [`ConsequenceRule`] fails input validation.
///
/// Used to reject attacker-controlled strings (custom trigger keys, capability
/// names, role names) that contain control characters, HTML-special characters,
/// or exceed length limits. Validation is performed at construction time, not
/// at serialization time.
#[derive(Debug, Clone, thiserror::Error)]
#[error("consequence rule validation failed: {0}")]
pub struct ConsequenceValidationError(String);

/// Maximum length for custom trigger keys.
const MAX_CONSEQUENCE_STRING_LEN: usize = 256;
use crate::context::governance::AccessScope;
use crate::context::roles::{Capability, MAX_ROLE_NAME_LENGTH};
/// Maximum number of capabilities in a `SuspendCapability` severity.
pub const MAX_CAPABILITY_SUSPENSION_COUNT: usize = 32;

/// Characters forbidden in consequence string fields. These prevent
/// HTML injection (`<`, `>`, `&`, `"`, `'`) and are checked alongside
/// control characters.
const FORBIDDEN_CHARS: &str = "<>&\"'";

/// Validates a user-supplied string field in a [`ConsequenceRule`].
///
/// Rejects strings that:
/// - Exceed `max_len` bytes
/// - Contain ASCII control characters (`c.is_control()`)
/// - Contain any of `<`, `>`, `&`, `"`, `'`
fn validate_consequence_string(
    s: &str,
    field: &str,
    max_len: usize,
) -> Result<(), ConsequenceValidationError> {
    if s.len() > max_len {
        return Err(ConsequenceValidationError(format!(
            "{field} exceeds max length {max_len} (got {})",
            s.len()
        )));
    }
    if s.chars()
        .any(|c| c.is_control() || FORBIDDEN_CHARS.contains(c))
    {
        return Err(ConsequenceValidationError(format!(
            "{field} contains forbidden characters (control chars or HTML-special chars)"
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// ConsequenceTrigger
// ---------------------------------------------------------------------------

/// The condition that triggers a consequence rule.
///
/// Each variant corresponds to a specific measurable behavior that can be
/// counted from event log entries within a time window.
///
/// See ADR-017 acceptance criterion 6.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConsequenceTrigger {
    /// The subject sent messages faster than the threshold allows within the
    /// time window. Counted from `EventType::MessageSent` events.
    MessageVelocity,

    /// The subject invoked tools at a rate exceeding the threshold within the
    /// time window. Counted from `EventType::ToolInvoked` events.
    ToolRateExceeded,

    /// The subject accumulated warnings (governance actions against them)
    /// exceeding the threshold within the time window. Counted from
    /// `EventType::GovernanceAction` events targeting the subject.
    WarningCount,

    /// A custom trigger identified by a string key. The event counting logic
    /// matches governance action events whose payload starts with the given
    /// key (null-terminated or end-of-data), allowing context-specific
    /// consequence definitions.
    Custom(String),
}

// ---------------------------------------------------------------------------
// EnforcementSeverity
// ---------------------------------------------------------------------------

/// Unified enforcement severity for consequence rules and governance actions.
///
/// This type collapses the previous split between
/// `ConsequenceAction::{Suspend, SuspendAll}` and
/// `GovernanceAction::{SuspendMember, Revoke, RemoveMember}` into a single typed
/// ladder ordered from least to most severe:
///
/// 1. [`SuspendCapability`](Self::SuspendCapability) — application-level block
///    on a specific capability set. Member keeps keys, remains in the group.
/// 2. [`SuspendAccess`](Self::SuspendAccess) — application-level block on
///    the member's full capability set. Member keeps keys, remains in the
///    group.
/// 3. [`RevokeAccess`](Self::RevokeAccess) — cryptographic revocation: access
///    keys are destroyed, the member is added to an exclusion list. The
///    member remains in MLS for auditability but cannot read or write in the
///    specified [`AccessScope`].
/// 4. [`RemoveMember`](Self::RemoveMember) — MLS group removal. Irreversible.
///
/// # Severity levels and their target DIDs
///
/// The subject DID is carried **outside** this enum (on
/// [`ConsequenceAction`] the subject is the rule-evaluation subject; on
/// `GovernanceAction::Enforce` the subject is an explicit `did` field on the
/// wrapper). This keeps the severity shape consistent across both call
/// paths. Each variant's payload carries only the severity-specific data.
///
/// # Consequence-dispatch eligibility
///
/// Not every severity may be referenced by an automatic consequence rule:
///
/// - `SuspendCapability`, `SuspendAccess` — always allowed. These are pure
///   application-level suspensions with no cryptographic side effects.
/// - `RevokeAccess` — allowed **only** when the context's
///   [`ConsequenceConfig::allow_automatic_access_revocation`] is `true`
///   ([`ContextParams.consequence_config`](crate::context::params::ContextParams::consequence_config)).
///   Defaults to `false`: cryptographic revocation is governance-only unless
///   the context explicitly opts in at creation time.
/// - `RemoveMember` — never allowed in consequence rules. MLS ejection is
///   permanent and must originate from an explicit governance proposal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EnforcementSeverity {
    /// Suspend specific capabilities for the subject (application-level
    /// enforcement). The subject keeps all MLS and content access keys.
    ///
    /// The suspension is enforced at the `send_message` / `deliver_incoming`
    /// gates via `ContextRoleState::suspended_capabilities`. The subject's
    /// access keys are NOT destroyed — restoration is a simple state
    /// mutation.
    SuspendCapability {
        /// The capabilities to suspend, as typed variants.
        ///
        /// Using [`Capability`] rather than `Vec<String>` eliminates the
        /// old string-parsing round-trip (which silently dropped unknown
        /// names). Validation at construction time rejects empty vectors,
        /// duplicates, and sets larger than
        /// [`MAX_CAPABILITY_SUSPENSION_COUNT`].
        capabilities: Vec<Capability>,
    },

    /// Suspend ALL member capabilities (application-level enforcement).
    ///
    /// Equivalent to `SuspendCapability` with the full ceiling, but the
    /// runtime uses a dedicated method
    /// (`ContextRoleState::suspend_all`) that is cheaper and does not need
    /// the ceiling materialized as a vec.
    ///
    /// This blocks read and write at the `send_message` / `deliver_incoming`
    /// gates but does **not** perform cryptographic exclusion. For full
    /// cryptographic exclusion, escalate to [`RevokeAccess`](Self::RevokeAccess).
    SuspendAccess,

    /// Cryptographic revocation — destroy the subject's access keys and add
    /// them to a scope-specific exclusion list.
    ///
    /// Forward-restore only: a future `RestoreAccess` governance action
    /// rotates fresh keys; content encrypted during the revocation period
    /// remains permanently inaccessible. Historical messages the subject
    /// had already decrypted are NOT clawed back — SCP does not perform
    /// retroactive key destruction.
    ///
    /// In broadcast contexts, this also calls `block_author` or
    /// `governance_ban_subscriber` depending on `access`. MLS group
    /// membership is preserved so the member remains addressable for
    /// auditability.
    ///
    /// **Cannot be referenced by a consequence rule** unless the
    /// context's [`ConsequenceConfig::allow_automatic_access_revocation`] is
    /// explicitly set to `true` at context creation time.
    RevokeAccess {
        /// DID of the member whose access is being cryptographically
        /// revoked.
        did: DID,
        /// Scope of the revocation (read, write, or both).
        access: AccessScope,
    },

    /// MLS group ejection — permanent removal from the encrypted group.
    ///
    /// This is the strongest enforcement tier. The subject's leaf is
    /// removed from the MLS group, triggering a commit and epoch
    /// advancement. The removed member cannot decrypt any future group
    /// messages, even with retained historical access keys.
    ///
    /// **Governance-only.** Cannot be referenced by a consequence rule
    /// because MLS ejection is permanent and disruptive.
    RemoveMember {
        /// DID of the member to eject from the MLS group.
        did: DID,
        /// Optional human-readable reason recorded on the event log.
        reason: Option<String>,
    },
}

impl EnforcementSeverity {
    /// Returns a short, static variant name for logging and event emission.
    #[must_use]
    pub const fn variant_name(&self) -> &'static str {
        match self {
            Self::SuspendCapability { .. } => "SuspendCapability",
            Self::SuspendAccess => "SuspendAccess",
            Self::RevokeAccess { .. } => "RevokeAccess",
            Self::RemoveMember { .. } => "RemoveMember",
        }
    }

    /// Returns the target DID for severities that carry one explicitly.
    ///
    /// Consequence-dispatch severities ([`SuspendCapability`](Self::SuspendCapability),
    /// [`SuspendAccess`](Self::SuspendAccess)) do not carry a DID — the subject
    /// is derived from the rule-evaluation context. Governance-targeting
    /// severities ([`RevokeAccess`](Self::RevokeAccess),
    /// [`RemoveMember`](Self::RemoveMember)) carry the explicit target.
    #[must_use]
    pub const fn target_did(&self) -> Option<&DID> {
        match self {
            Self::RevokeAccess { did, .. } | Self::RemoveMember { did, .. } => Some(did),
            Self::SuspendCapability { .. } | Self::SuspendAccess => None,
        }
    }

    /// Returns `true` if this severity may be referenced by an automatic
    /// consequence rule under the given `allow_automatic_access_revocation`
    /// opt-in.
    ///
    /// - `SuspendCapability`, `SuspendAccess` — always allowed.
    /// - `RevokeAccess` — allowed only when `allow_automatic_access_revocation`
    ///   is `true`.
    /// - `RemoveMember` — never allowed in consequence rules; governance-only.
    #[must_use]
    pub const fn is_consequence_eligible(&self, allow_automatic_access_revocation: bool) -> bool {
        match self {
            Self::SuspendCapability { .. } | Self::SuspendAccess => true,
            Self::RevokeAccess { .. } => allow_automatic_access_revocation,
            Self::RemoveMember { .. } => false,
        }
    }
}

// ---------------------------------------------------------------------------
// ConsequenceAction
// ---------------------------------------------------------------------------

/// The action taken when a consequence rule is triggered.
///
/// Two semantic families live here:
///
/// - [`Enforcement`](Self::Enforcement) — the subject's access is restricted
///   via one of the unified [`EnforcementSeverity`] tiers. This is the hot
///   path for automatic rule dispatch and the cold path for governance
///   actions (where the same severity enum is wrapped by
///   `GovernanceAction::Enforce`).
/// - [`AssignRole`](Self::AssignRole) — the subject's role is replaced. This
///   is a permissions change, **not** an enforcement action; it lives on
///   `ConsequenceAction` as a sibling of `Enforcement` rather than as a
///   severity tier because it can both elevate and demote.
///
/// These actions are declared at context creation and are visible to all
/// participants before they join. See ADR-017.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConsequenceAction {
    /// Apply an enforcement severity to the subject.
    ///
    /// The severity's [`is_consequence_eligible`](EnforcementSeverity::is_consequence_eligible)
    /// gate MUST be checked by [`ConsequenceRule::validate`] against the
    /// context's
    /// [`ConsequenceConfig::allow_automatic_access_revocation`](crate::context::params::ConsequenceConfig::allow_automatic_access_revocation)
    /// before the rule is accepted.
    Enforcement(EnforcementSeverity),

    /// Assign a role to the subject (replaces previous role).
    AssignRole {
        /// The role to assign to the subject.
        to_role: String,
    },
}

// ---------------------------------------------------------------------------
// ConsequenceRule
// ---------------------------------------------------------------------------

/// A declared consequence rule (ADR-017).
///
/// Consequences are part of the opt-in contract -- visible before joining,
/// protocol-enforced, verifiable. No hidden penalties. Each rule specifies
/// a trigger condition, the enforcement action, a numeric threshold, and a
/// time window for counting events.
///
/// See ADR-017 acceptance criterion 1.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsequenceRule {
    /// The condition that triggers this consequence.
    pub trigger: ConsequenceTrigger,

    /// The enforcement action to take when triggered.
    pub action: ConsequenceAction,

    /// The numeric threshold. When the count of matching events within the
    /// time window meets or exceeds this value, the consequence is triggered.
    pub threshold: u64,

    /// The time window (in seconds) within which events are counted. Only
    /// events with timestamps in `[now - window, now]` are considered.
    pub window: Duration,
}

impl ConsequenceRule {
    /// Validates all user-supplied string fields and enforcement-severity
    /// constraints in this rule.
    ///
    /// This should be called at the FFI boundary and in `ContextManager` before
    /// storing consequence rules. It rejects:
    ///
    /// - `Custom(key)`: key with control/HTML chars or length > 256
    /// - `Enforcement(SuspendCapability { capabilities })`: empty or
    ///   duplicated capability set, or more than 32 capabilities
    /// - `Enforcement(RevokeAccess { .. })`: unless the context's
    ///   `allow_automatic_access_revocation` flag is `true` (checked via
    ///   [`validate_against_config`](Self::validate_against_config))
    /// - `Enforcement(RemoveMember { .. })`: always rejected — MLS ejection
    ///   is governance-only
    /// - `AssignRole { to_role }`: role name with control/HTML chars or
    ///   length > 64
    ///
    /// Other trigger variants have no user-supplied strings and always pass
    /// validation.
    ///
    /// # Errors
    ///
    /// Returns [`ConsequenceValidationError`] if any string field contains
    /// forbidden characters (control chars, `<`, `>`, `&`, `"`, `'`), exceeds
    /// its maximum length, exceeds capability count limits, or references
    /// `RemoveMember` (which is always rejected regardless of config).
    ///
    /// `RevokeAccess` is accepted here and rejected later by
    /// [`validate_against_config`](Self::validate_against_config) when the
    /// context's opt-in flag is `false`. Callers that do not have access to
    /// a [`ConsequenceConfig`](crate::context::params::ConsequenceConfig) MUST
    /// still call [`validate_against_config`](Self::validate_against_config)
    /// before accepting the rule into an active context.
    pub fn validate(&self) -> Result<(), ConsequenceValidationError> {
        // M5: threshold of 0 would trigger on every evaluation — reject.
        if self.threshold == 0 {
            return Err(ConsequenceValidationError(
                "threshold must be > 0".to_owned(),
            ));
        }

        // Validate trigger.
        if let ConsequenceTrigger::Custom(key) = &self.trigger {
            // M6: empty custom key has no semantic meaning — reject.
            if key.is_empty() {
                return Err(ConsequenceValidationError(
                    "Custom trigger key must not be empty".to_owned(),
                ));
            }
            validate_consequence_string(key, "Custom trigger key", MAX_CONSEQUENCE_STRING_LEN)?;
        }

        // Validate action.
        match &self.action {
            ConsequenceAction::Enforcement(severity) => {
                validate_severity_shape(severity)?;
                // RemoveMember is always rejected at this layer — it is
                // governance-only regardless of per-context opt-in.
                if matches!(severity, EnforcementSeverity::RemoveMember { .. }) {
                    return Err(ConsequenceValidationError(
                        "RemoveMember may not be referenced from a consequence rule; \
                         MLS ejection is governance-only"
                            .to_owned(),
                    ));
                }
            }
            ConsequenceAction::AssignRole { to_role } => {
                validate_consequence_string(to_role, "AssignRole.to_role", MAX_ROLE_NAME_LENGTH)?;
            }
        }

        Ok(())
    }

    /// Validates this rule against the per-context [`ConsequenceConfig`](crate::context::params::ConsequenceConfig).
    ///
    /// Performs all checks of [`validate`](Self::validate) plus:
    ///
    /// - `Enforcement(RevokeAccess { .. })` is rejected unless
    ///   [`ConsequenceConfig::allow_automatic_access_revocation`](crate::context::params::ConsequenceConfig::allow_automatic_access_revocation)
    ///   is `true`.
    ///
    /// Call this in `ContextParams` validation and at any FFI boundary that
    /// accepts a rule against an existing config.
    ///
    /// # Errors
    ///
    /// Returns all errors from [`validate`](Self::validate), plus a
    /// config-rejection error when the rule references a severity that is
    /// not permitted by the config.
    pub fn validate_against_config(
        &self,
        config: &crate::context::params::ConsequenceConfig,
    ) -> Result<(), ConsequenceValidationError> {
        self.validate()?;
        if let ConsequenceAction::Enforcement(severity) = &self.action
            && !severity.is_consequence_eligible(config.allow_automatic_access_revocation)
        {
            return Err(ConsequenceValidationError(format!(
                "{} severity is not eligible for automatic consequence dispatch in this \
                 context; set ContextParams.consequence_config.allow_automatic_access_revocation = \
                 true to permit RevokeAccess in consequence rules, or use a governance \
                 proposal for one-off enforcement",
                severity.variant_name()
            )));
        }
        Ok(())
    }
}

/// Shared shape checks for a [`EnforcementSeverity`] referenced in a
/// [`ConsequenceRule`].
///
/// These checks apply regardless of per-context config:
///
/// - `SuspendCapability`: empty set, duplicates, or > `MAX_CAPABILITY_SUSPENSION_COUNT`
///   capabilities are all rejected.
/// - `SuspendAccess`: no fields, always passes shape validation.
/// - `RevokeAccess`: the embedded DID must be non-empty.
/// - `RemoveMember`: reason length check is performed when present; note
///   that [`ConsequenceRule::validate`] rejects `RemoveMember` outright
///   regardless of shape.
fn validate_severity_shape(
    severity: &EnforcementSeverity,
) -> Result<(), ConsequenceValidationError> {
    match severity {
        EnforcementSeverity::SuspendCapability { capabilities } => {
            if capabilities.is_empty() {
                return Err(ConsequenceValidationError(
                    "SuspendCapability must list at least one capability".to_owned(),
                ));
            }
            if capabilities.len() > MAX_CAPABILITY_SUSPENSION_COUNT {
                return Err(ConsequenceValidationError(format!(
                    "SuspendCapability has {} capabilities, max is \
                     {MAX_CAPABILITY_SUSPENSION_COUNT}",
                    capabilities.len()
                )));
            }
            // Reject duplicates: a rule that lists the same capability
            // twice is almost certainly a mistake, and the runtime's
            // suspension set is idempotent anyway.
            for (i, cap) in capabilities.iter().enumerate() {
                if capabilities[..i].contains(cap) {
                    return Err(ConsequenceValidationError(format!(
                        "SuspendCapability contains duplicate capability {cap:?} at \
                         index {i}",
                    )));
                }
                // Validate Custom(name) / ToolInvoke(id) payload strings.
                if let Capability::Custom(name) = cap {
                    if name.is_empty() {
                        return Err(ConsequenceValidationError(format!(
                            "SuspendCapability[{i}] Custom capability has empty name",
                        )));
                    }
                    validate_consequence_string(
                        name,
                        &format!("SuspendCapability[{i}] Custom"),
                        MAX_CONSEQUENCE_STRING_LEN,
                    )?;
                } else if let Capability::ToolInvoke(tool_id) = cap {
                    if tool_id.is_empty() {
                        return Err(ConsequenceValidationError(format!(
                            "SuspendCapability[{i}] ToolInvoke has empty tool_id",
                        )));
                    }
                    validate_consequence_string(
                        tool_id,
                        &format!("SuspendCapability[{i}] ToolInvoke"),
                        MAX_CONSEQUENCE_STRING_LEN,
                    )?;
                }
            }
        }
        EnforcementSeverity::SuspendAccess => { /* no fields */ }
        EnforcementSeverity::RevokeAccess { did, .. } => {
            if did.0.is_empty() {
                return Err(ConsequenceValidationError(
                    "RevokeAccess.did must not be empty".to_owned(),
                ));
            }
        }
        EnforcementSeverity::RemoveMember { did, reason } => {
            if did.0.is_empty() {
                return Err(ConsequenceValidationError(
                    "RemoveMember.did must not be empty".to_owned(),
                ));
            }
            if let Some(r) = reason {
                validate_consequence_string(r, "RemoveMember.reason", MAX_CONSEQUENCE_STRING_LEN)?;
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// ConsequenceEvidence
// ---------------------------------------------------------------------------

/// A reference to an event that contributed to triggering a consequence.
///
/// Provides traceability from a triggered consequence back to the specific
/// events in the log that caused it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsequenceEvidence {
    /// The sequence number of the event in the log.
    pub event_sequence: u64,

    /// Unix timestamp (seconds) of the event.
    pub timestamp: u64,

    /// The DID of the actor who produced the event.
    pub actor_did: DID,

    /// The event type that matched the trigger.
    pub event_type: EventType,
}

// ---------------------------------------------------------------------------
// TriggeredConsequence
// ---------------------------------------------------------------------------

/// A consequence rule that has been triggered, with evidence.
///
/// Returned by [`evaluate_consequence_rules`] when a rule's trigger condition
/// is met. Contains the index of the rule that fired, the action to take,
/// and the events that constituted the triggering evidence.
#[derive(Debug, Clone)]
pub struct TriggeredConsequence {
    /// Index of the rule in the original rules slice that was triggered.
    pub rule_index: usize,

    /// The enforcement action to take.
    pub action: ConsequenceAction,

    /// The events that contributed to triggering this consequence.
    pub evidence: Vec<ConsequenceEvidence>,
}

// ---------------------------------------------------------------------------
// evaluate_consequence_rules
// ---------------------------------------------------------------------------

/// Evaluates consequence rules against event log data for a subject DID.
///
/// For each rule, counts matching events within the rule's time window. If
/// the count meets or exceeds the threshold, the consequence is triggered and
/// included in the returned list with the triggering evidence.
///
/// # Parameters
///
/// - `rules` -- The consequence rules to evaluate (declared at context creation).
/// - `events` -- The event log entries to evaluate against. The function takes
///   `&[Event]` rather than `&EventLog` because `EventLog` stores only leaf
///   hashes, not full events.
/// - `subject_did` -- The DID of the participant being evaluated.
/// - `now` -- The current time as a Unix timestamp in seconds. Used to compute
///   the time window boundary for each rule.
///
/// # Returns
///
/// A `Vec<TriggeredConsequence>` containing all rules that fired. The vector
/// is empty if no rules were triggered.
///
/// # Design Notes
///
/// - Pure computation -- no side effects, no storage.
/// - The `now` parameter is passed explicitly (rather than using a `Clock`
///   trait) for simplicity and testability, following the pattern established
///   by `compute_participation_record`.
/// - Custom triggers match `GovernanceAction` events whose payload starts
///   with the custom key string.
///
/// See ADR-017 acceptance criterion 6.
#[must_use]
pub fn evaluate_consequence_rules(
    rules: &[ConsequenceRule],
    events: &[Event],
    subject_did: &str,
    now: u64,
) -> Vec<TriggeredConsequence> {
    let mut triggered = Vec::new();

    for (rule_index, rule) in rules.iter().enumerate() {
        let window_start = now.saturating_sub(rule.window.as_secs());

        let evidence: Vec<ConsequenceEvidence> = events
            .iter()
            .filter(|event| {
                // Time window filter.
                event.timestamp >= window_start && event.timestamp <= now
            })
            .filter(|event| matches_trigger(&rule.trigger, event, subject_did))
            .map(|event| ConsequenceEvidence {
                event_sequence: event.sequence,
                timestamp: event.timestamp,
                actor_did: event.actor_did.clone(),
                event_type: event.event_type.clone(),
            })
            .collect();

        let count = u64::try_from(evidence.len()).unwrap_or(u64::MAX);
        if count >= rule.threshold {
            triggered.push(TriggeredConsequence {
                rule_index,
                action: rule.action.clone(),
                evidence,
            });
        }
    }

    triggered
}

// ---------------------------------------------------------------------------
// ConsequenceDispatcher — shared enforcement trait
// ---------------------------------------------------------------------------

/// Abstracts over the mutable context state needed to enforce triggered
/// consequences, enabling a single shared loop body for both the runtime
/// (`scp-runtime`) and WASM (`scp-ffi-wasm`) implementations.
///
/// Each implementation mutates its own per-context state structure:
///
/// - **Runtime**: `ContextManager`'s `PerContextState` (uses `ContextRoleState`
///   for capability suspension, `ReceiveBuffer` for events, and the governance
///   `cooldown_until` map).
/// - **WASM**: `WasmContextManager`'s `PerContextState` (uses a flat
///   `suspended_capabilities` hash map, an in-memory event ring, and a
///   flat `cooldown_until` map).
///
/// The methods use `&str` for DIDs to avoid cross-crate type dependencies,
/// and `ContextEvent` from `scp_protocol::context::membership` (which both
/// implementations already construct).
///
/// See Simp-2, ADR-017.
pub trait ConsequenceDispatcher {
    /// Returns `true` if `subject_did` is currently a member of the context.
    fn is_member_present(&self, subject_did: &str) -> bool;

    /// Suspends the listed capabilities for `subject_did`.
    ///
    /// Returns `true` if at least one capability was successfully applied.
    fn suspend_capabilities(
        &mut self,
        subject_did: &str,
        caps: &[crate::context::roles::Capability],
    ) -> bool;

    /// Suspends ALL capabilities for `subject_did` (full access suspension).
    ///
    /// Returns `true` if the suspension was applied.
    fn suspend_all(&mut self, subject_did: &str) -> bool;

    /// Assigns `to_role` to `subject_did`.
    ///
    /// Returns `true` if the subject is a known member and the role was
    /// updated.
    fn assign_role(&mut self, subject_did: &str, to_role: &str) -> bool;

    /// Pushes a `ContextEvent` to the context's receive buffer (for SDK
    /// observability).
    fn push_event(&mut self, event: crate::context::membership::ContextEvent);

    /// Returns the Unix-second timestamp until which rule `rule_index` is
    /// on cooldown, or `None` if there is no active cooldown.
    fn get_cooldown(&self, rule_index: usize) -> Option<u64>;

    /// Records a cooldown for rule `rule_index` that expires at `until`
    /// (Unix seconds).
    fn set_cooldown(&mut self, rule_index: usize, until: u64);
}

/// Enforces a pre-evaluated set of triggered consequences using a
/// [`ConsequenceDispatcher`].
///
/// This is the shared enforcement loop used by both the runtime and WASM
/// bridges. Callers supply:
///
/// - `dispatcher` — mutable reference to the per-context state (implements
///   [`ConsequenceDispatcher`]).
/// - `context_id` — embedded in emitted `ContextEvent`s.
/// - `subject_did` — the participant being evaluated.
/// - `now_secs` — current Unix second (for cooldown arithmetic).
/// - `triggered` — output of [`evaluate_consequence_rules`].
/// - `rules` — the same slice that was passed to `evaluate_consequence_rules`
///   (used to look up each rule's window for cooldown recording).
///
/// Returns the count of consequences that were dispatched (i.e., passed
/// cooldown and ghost-DID guards).
pub fn enforce_triggered<D: ConsequenceDispatcher>(
    dispatcher: &mut D,
    context_id: &str,
    subject_did: &str,
    now_secs: u64,
    triggered: &[TriggeredConsequence],
    rules: &[ConsequenceRule],
) -> usize {
    let mut count = 0usize;

    for consequence in triggered {
        // Cooldown: skip if this rule fired within its window.
        if let Some(last_fired) = dispatcher.get_cooldown(consequence.rule_index)
            && now_secs < last_fired
        {
            continue;
        }

        // Ghost DID guard: if the subject is absent AND there is no evidence
        // of prior participation, skip entirely.
        let member_present = dispatcher.is_member_present(subject_did);
        if !member_present && consequence.evidence.is_empty() {
            continue;
        }

        let action_type = match &consequence.action {
            ConsequenceAction::Enforcement(sev) => sev.variant_name(),
            ConsequenceAction::AssignRole { .. } => "AssignRole",
        };
        let trigger_type = rules
            .get(consequence.rule_index)
            .map_or_else(|| "Unknown".to_owned(), |r| format!("{:?}", r.trigger));

        dispatcher.push_event(
            crate::context::membership::ContextEvent::ConsequenceTriggered {
                context_id: context_id.to_owned(),
                member_did: DID::from(subject_did.to_owned()),
                rule_index: consequence.rule_index,
                trigger_type,
                action_type: action_type.to_owned(),
            },
        );

        // Emit-and-skip for absent members with evidence.
        if !member_present {
            dispatcher.push_event(
                crate::context::membership::ContextEvent::ConsequenceEnforced {
                    context_id: context_id.to_owned(),
                    member_did: DID::from(subject_did.to_owned()),
                    action_type: action_type.to_owned(),
                    success: false,
                },
            );
            count += 1;
            continue;
        }

        let success = match &consequence.action {
            ConsequenceAction::Enforcement(severity) => match severity {
                EnforcementSeverity::SuspendCapability { capabilities } => {
                    dispatcher.suspend_capabilities(subject_did, capabilities)
                }
                EnforcementSeverity::SuspendAccess => dispatcher.suspend_all(subject_did),
                EnforcementSeverity::RevokeAccess { .. }
                | EnforcementSeverity::RemoveMember { .. } => {
                    // Cryptographic tiers must not reach consequence dispatch
                    // without the opt-in flag. Fail here; escalation to
                    // SuspendAll happens below.
                    false
                }
            },
            ConsequenceAction::AssignRole { to_role } => {
                dispatcher.assign_role(subject_did, to_role)
            }
        };

        if !success {
            // Escalate to SuspendAll on enforcement failure.
            let _ = dispatcher.suspend_all(subject_did);
            dispatcher.push_event(
                crate::context::membership::ContextEvent::ConsequenceEnforced {
                    context_id: context_id.to_owned(),
                    member_did: DID::from(subject_did.to_owned()),
                    action_type: "SuspendAll(escalated)".to_owned(),
                    success: true,
                },
            );
            count += 1;
            continue;
        }

        // Record cooldown.
        if let Some(rule) = rules.get(consequence.rule_index) {
            dispatcher.set_cooldown(
                consequence.rule_index,
                now_secs.saturating_add(rule.window.as_secs()),
            );
        }

        dispatcher.push_event(
            crate::context::membership::ContextEvent::ConsequenceEnforced {
                context_id: context_id.to_owned(),
                member_did: DID::from(subject_did.to_owned()),
                action_type: action_type.to_owned(),
                success,
            },
        );
        count += 1;
    }

    count
}

/// Checks whether an event matches a trigger condition for the given subject.
fn matches_trigger(trigger: &ConsequenceTrigger, event: &Event, subject_did: &str) -> bool {
    match trigger {
        ConsequenceTrigger::MessageVelocity => {
            event.actor_did == subject_did && event.event_type == EventType::MessageSent
        }
        ConsequenceTrigger::ToolRateExceeded => {
            event.actor_did == subject_did && event.event_type == EventType::ToolInvoked
        }
        ConsequenceTrigger::WarningCount => {
            // Governance actions targeting the subject (actor is someone else,
            // target DID in payload matches subject).
            event.event_type == EventType::GovernanceAction
                && event.actor_did != subject_did
                && payload_target_is(&event.payload.data, subject_did)
        }
        ConsequenceTrigger::Custom(key) => {
            // Custom triggers match GovernanceAction events whose payload
            // starts with the custom key string.
            event.event_type == EventType::GovernanceAction
                && payload_starts_with(&event.payload.data, key)
        }
    }
}

/// Checks if the payload data represents a target DID matching the given DID.
///
/// Parses the payload as a JSON object with a `"target_did"` field. Falls
/// back to the legacy null-terminated string convention for backward
/// compatibility.
fn payload_target_is(data: &[u8], target_did: &str) -> bool {
    if data.is_empty() {
        return false;
    }
    // Try structured JSON first.
    if let Ok(val) = serde_json::from_slice::<serde_json::Value>(data) {
        return val
            .get("target_did")
            .and_then(|v| v.as_str())
            .is_some_and(|s| s == target_did);
    }
    // Legacy fallback: null-terminated UTF-8 string.
    let end = data.iter().position(|&b| b == 0).unwrap_or(data.len());
    std::str::from_utf8(&data[..end]) == Ok(target_did)
}

/// Checks if a payload's data starts with the given prefix.
///
/// For structured JSON payloads, checks the `"custom_key"` field. Falls
/// back to the legacy null-terminated string convention.
fn payload_starts_with(data: &[u8], prefix: &str) -> bool {
    if data.is_empty() {
        return false;
    }
    // Try structured JSON first.
    if let Ok(val) = serde_json::from_slice::<serde_json::Value>(data) {
        // Check custom_key field for Custom triggers.
        if let Some(key) = val.get("custom_key").and_then(|v| v.as_str()) {
            return key == prefix || key.starts_with(prefix);
        }
        // Also check target_did for backward compat with custom triggers
        // that might use target DID as key.
        if let Some(did) = val.get("target_did").and_then(|v| v.as_str()) {
            return did == prefix || did.starts_with(prefix);
        }
        return false;
    }
    // Legacy fallback: null-terminated UTF-8 string.
    let end = data.iter().position(|&b| b == 0).unwrap_or(data.len());
    std::str::from_utf8(&data[..end])
        .is_ok_and(|payload_str| payload_str == prefix || payload_str.starts_with(prefix))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::context::params::ConsequenceConfig;
    use scp_event_log::EventPayload;

    /// Creates a test event with the given parameters. Signature and `prev_hash`
    /// are set to dummy values since `evaluate_consequence_rules` does not
    /// verify signatures.
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

    fn suspend_write() -> ConsequenceAction {
        ConsequenceAction::Enforcement(EnforcementSeverity::SuspendCapability {
            capabilities: vec![Capability::MessagesWrite],
        })
    }

    fn suspend_all() -> ConsequenceAction {
        ConsequenceAction::Enforcement(EnforcementSeverity::SuspendAccess)
    }

    // -----------------------------------------------------------------------
    // 1. Message velocity triggers capability suspension
    // -----------------------------------------------------------------------

    #[test]
    fn message_velocity_triggers_capability_suspension() {
        let rules = vec![ConsequenceRule {
            trigger: ConsequenceTrigger::MessageVelocity,
            action: suspend_write(),
            threshold: 3,
            window: Duration::from_mins(1),
        }];

        let events = vec![
            make_event(EventType::MessageSent, "did:key:alice", 940, 0, vec![]),
            make_event(EventType::MessageSent, "did:key:alice", 950, 1, vec![]),
            make_event(EventType::MessageSent, "did:key:alice", 960, 2, vec![]),
        ];

        let result = evaluate_consequence_rules(&rules, &events, "did:key:alice", 1000);

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].rule_index, 0);
        assert_eq!(result[0].action, suspend_write());
        assert_eq!(result[0].evidence.len(), 3);
    }

    // -----------------------------------------------------------------------
    // 2. Tool rate threshold triggers suspension
    // -----------------------------------------------------------------------

    #[test]
    fn tool_rate_triggers_suspend_all() {
        let rules = vec![ConsequenceRule {
            trigger: ConsequenceTrigger::ToolRateExceeded,
            action: suspend_all(),
            threshold: 5,
            window: Duration::from_mins(2),
        }];

        let events: Vec<Event> = (0..5)
            .map(|i| {
                make_event(
                    EventType::ToolInvoked,
                    "did:key:alice",
                    900 + i,
                    i,
                    b"some-tool".to_vec(),
                )
            })
            .collect();

        let result = evaluate_consequence_rules(&rules, &events, "did:key:alice", 1000);

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].action, suspend_all());
        assert_eq!(result[0].evidence.len(), 5);
    }

    // -----------------------------------------------------------------------
    // 3. Warning count triggers role demotion
    // -----------------------------------------------------------------------

    #[test]
    fn warning_count_triggers_assign_role() {
        let rules = vec![ConsequenceRule {
            trigger: ConsequenceTrigger::WarningCount,
            action: ConsequenceAction::AssignRole {
                to_role: "observer".to_owned(),
            },
            threshold: 2,
            window: Duration::from_mins(5),
        }];

        let payload =
            serde_json::to_vec(&serde_json::json!({"target_did": "did:key:alice"})).unwrap();

        let events = vec![
            make_event(
                EventType::GovernanceAction,
                "did:key:admin",
                800,
                0,
                payload.clone(),
            ),
            make_event(
                EventType::GovernanceAction,
                "did:key:moderator",
                900,
                1,
                payload,
            ),
        ];

        let result = evaluate_consequence_rules(&rules, &events, "did:key:alice", 1000);

        assert_eq!(result.len(), 1);
        assert_eq!(
            result[0].action,
            ConsequenceAction::AssignRole {
                to_role: "observer".to_owned()
            }
        );
        assert_eq!(result[0].evidence.len(), 2);
    }

    // -----------------------------------------------------------------------
    // 4. Threshold boundary: exactly at threshold triggers
    // -----------------------------------------------------------------------

    #[test]
    fn threshold_exactly_met_triggers_consequence() {
        let rules = vec![ConsequenceRule {
            trigger: ConsequenceTrigger::MessageVelocity,
            action: suspend_all(),
            threshold: 2,
            window: Duration::from_mins(1),
        }];

        let events = vec![
            make_event(EventType::MessageSent, "did:key:alice", 950, 0, vec![]),
            make_event(EventType::MessageSent, "did:key:alice", 960, 1, vec![]),
        ];

        let result = evaluate_consequence_rules(&rules, &events, "did:key:alice", 1000);

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].evidence.len(), 2);
    }

    // -----------------------------------------------------------------------
    // 5. Threshold boundary: one below threshold does NOT trigger
    // -----------------------------------------------------------------------

    #[test]
    fn threshold_not_met_does_not_trigger() {
        let rules = vec![ConsequenceRule {
            trigger: ConsequenceTrigger::MessageVelocity,
            action: suspend_all(),
            threshold: 3,
            window: Duration::from_mins(1),
        }];

        let events = vec![
            make_event(EventType::MessageSent, "did:key:alice", 950, 0, vec![]),
            make_event(EventType::MessageSent, "did:key:alice", 960, 1, vec![]),
        ];

        let result = evaluate_consequence_rules(&rules, &events, "did:key:alice", 1000);

        assert!(result.is_empty());
    }

    // -----------------------------------------------------------------------
    // 6. Time window filtering: events outside window are excluded
    // -----------------------------------------------------------------------

    #[test]
    fn events_outside_time_window_are_excluded() {
        let rules = vec![ConsequenceRule {
            trigger: ConsequenceTrigger::MessageVelocity,
            action: suspend_all(),
            threshold: 3,
            window: Duration::from_mins(1),
        }];

        let events = vec![
            make_event(EventType::MessageSent, "did:key:alice", 900, 0, vec![]),
            make_event(EventType::MessageSent, "did:key:alice", 930, 1, vec![]),
            make_event(EventType::MessageSent, "did:key:alice", 950, 2, vec![]),
            make_event(EventType::MessageSent, "did:key:alice", 960, 3, vec![]),
        ];

        let result = evaluate_consequence_rules(&rules, &events, "did:key:alice", 1000);
        assert!(result.is_empty());
    }

    // -----------------------------------------------------------------------
    // 7. Events from other actors are not counted for message velocity
    // -----------------------------------------------------------------------

    #[test]
    fn events_from_other_actors_not_counted_for_velocity() {
        let rules = vec![ConsequenceRule {
            trigger: ConsequenceTrigger::MessageVelocity,
            action: suspend_all(),
            threshold: 3,
            window: Duration::from_mins(1),
        }];

        let events = vec![
            make_event(EventType::MessageSent, "did:key:alice", 950, 0, vec![]),
            make_event(EventType::MessageSent, "did:key:bob", 955, 1, vec![]),
            make_event(EventType::MessageSent, "did:key:alice", 960, 2, vec![]),
            make_event(EventType::MessageSent, "did:key:bob", 965, 3, vec![]),
        ];

        let result = evaluate_consequence_rules(&rules, &events, "did:key:alice", 1000);
        assert!(result.is_empty());
    }

    // -----------------------------------------------------------------------
    // 8. Multiple rules can trigger simultaneously
    // -----------------------------------------------------------------------

    #[test]
    fn multiple_rules_trigger_simultaneously() {
        let rules = vec![
            ConsequenceRule {
                trigger: ConsequenceTrigger::MessageVelocity,
                action: suspend_write(),
                threshold: 2,
                window: Duration::from_mins(1),
            },
            ConsequenceRule {
                trigger: ConsequenceTrigger::ToolRateExceeded,
                action: suspend_all(),
                threshold: 1,
                window: Duration::from_mins(1),
            },
        ];

        let events = vec![
            make_event(EventType::MessageSent, "did:key:alice", 950, 0, vec![]),
            make_event(EventType::MessageSent, "did:key:alice", 960, 1, vec![]),
            make_event(
                EventType::ToolInvoked,
                "did:key:alice",
                970,
                2,
                b"tool-x".to_vec(),
            ),
        ];

        let result = evaluate_consequence_rules(&rules, &events, "did:key:alice", 1000);

        assert_eq!(result.len(), 2);
        assert_eq!(result[0].rule_index, 0);
        assert_eq!(result[1].rule_index, 1);
    }

    // -----------------------------------------------------------------------
    // 9. Empty event log / rules
    // -----------------------------------------------------------------------

    #[test]
    fn empty_event_log_triggers_nothing() {
        let rules = vec![ConsequenceRule {
            trigger: ConsequenceTrigger::MessageVelocity,
            action: suspend_all(),
            threshold: 1,
            window: Duration::from_mins(1),
        }];

        let result = evaluate_consequence_rules(&rules, &[], "did:key:alice", 1000);
        assert!(result.is_empty());
    }

    #[test]
    fn empty_rules_list_produces_empty_result() {
        let events = vec![make_event(
            EventType::MessageSent,
            "did:key:alice",
            950,
            0,
            vec![],
        )];

        let result = evaluate_consequence_rules(&[], &events, "did:key:alice", 1000);
        assert!(result.is_empty());
    }

    // -----------------------------------------------------------------------
    // 10. Custom trigger / window / serialization
    // -----------------------------------------------------------------------

    #[test]
    fn consequence_rule_serialization_roundtrip() {
        let rule = ConsequenceRule {
            trigger: ConsequenceTrigger::MessageVelocity,
            action: suspend_write(),
            threshold: 10,
            window: Duration::from_mins(5),
        };

        let json = serde_json::to_string(&rule).unwrap();
        let deserialized: ConsequenceRule = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, rule);
    }

    #[test]
    fn consequence_trigger_custom_serialization_roundtrip() {
        let trigger = ConsequenceTrigger::Custom("my-custom-trigger".to_owned());
        let json = serde_json::to_string(&trigger).unwrap();
        let deserialized: ConsequenceTrigger = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, trigger);
    }

    #[test]
    fn consequence_action_assign_role_serialization_roundtrip() {
        let action = ConsequenceAction::AssignRole {
            to_role: "viewer".to_owned(),
        };
        let json = serde_json::to_string(&action).unwrap();
        let deserialized: ConsequenceAction = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, action);
    }

    #[test]
    fn enforcement_severity_serialization_roundtrip() {
        use crate::context::governance::AccessScope;
        let cases = vec![
            EnforcementSeverity::SuspendCapability {
                capabilities: vec![Capability::MessagesWrite, Capability::GovernanceVote],
            },
            EnforcementSeverity::SuspendAccess,
            EnforcementSeverity::RevokeAccess {
                did: DID("did:key:alice".to_owned()),
                access: AccessScope::Both,
            },
            EnforcementSeverity::RemoveMember {
                did: DID("did:key:bob".to_owned()),
                reason: Some("spam".to_owned()),
            },
        ];
        for sev in cases {
            let json = serde_json::to_string(&sev).unwrap();
            let round: EnforcementSeverity = serde_json::from_str(&json).unwrap();
            assert_eq!(round, sev);
        }
    }

    // -----------------------------------------------------------------------
    // Validation: strings
    // -----------------------------------------------------------------------

    #[test]
    fn validate_rejects_custom_trigger_with_script_tag() {
        let rule = ConsequenceRule {
            trigger: ConsequenceTrigger::Custom("<script>alert(1)</script>".to_owned()),
            action: suspend_all(),
            threshold: 1,
            window: Duration::from_mins(1),
        };
        let err = rule.validate().unwrap_err();
        assert!(
            err.to_string().contains("forbidden characters"),
            "error should mention forbidden characters, got: {err}"
        );
    }

    #[test]
    fn validate_accepts_valid_custom_trigger() {
        let rule = ConsequenceRule {
            trigger: ConsequenceTrigger::Custom("valid_trigger_name".to_owned()),
            action: suspend_all(),
            threshold: 1,
            window: Duration::from_mins(1),
        };
        assert!(rule.validate().is_ok());
    }

    #[test]
    fn validate_accepts_valid_suspend_capability() {
        let rule = ConsequenceRule {
            trigger: ConsequenceTrigger::MessageVelocity,
            action: suspend_write(),
            threshold: 1,
            window: Duration::from_mins(1),
        };
        assert!(rule.validate().is_ok());
    }

    #[test]
    fn validate_accepts_valid_assign_role() {
        let rule = ConsequenceRule {
            trigger: ConsequenceTrigger::MessageVelocity,
            action: ConsequenceAction::AssignRole {
                to_role: "member".to_owned(),
            },
            threshold: 1,
            window: Duration::from_mins(1),
        };
        assert!(rule.validate().is_ok());
    }

    #[test]
    fn validate_rejects_assign_role_with_script_tag() {
        let rule = ConsequenceRule {
            trigger: ConsequenceTrigger::MessageVelocity,
            action: ConsequenceAction::AssignRole {
                to_role: "<script>".to_owned(),
            },
            threshold: 1,
            window: Duration::from_mins(1),
        };
        let err = rule.validate().unwrap_err();
        assert!(
            err.to_string().contains("forbidden characters"),
            "error should mention forbidden characters, got: {err}"
        );
    }

    #[test]
    fn validate_rejects_oversized_custom_trigger_key() {
        let long_key = "a".repeat(300);
        let rule = ConsequenceRule {
            trigger: ConsequenceTrigger::Custom(long_key),
            action: suspend_all(),
            threshold: 1,
            window: Duration::from_mins(1),
        };
        let err = rule.validate().unwrap_err();
        assert!(
            err.to_string().contains("exceeds max length"),
            "error should mention max length, got: {err}"
        );
    }

    #[test]
    fn validate_rejects_control_chars_in_custom_trigger() {
        let rule = ConsequenceRule {
            trigger: ConsequenceTrigger::Custom("trigger\x00key".to_owned()),
            action: suspend_all(),
            threshold: 1,
            window: Duration::from_mins(1),
        };
        let err = rule.validate().unwrap_err();
        assert!(
            err.to_string().contains("forbidden characters"),
            "error should mention forbidden characters, got: {err}"
        );
    }

    // -----------------------------------------------------------------------
    // Validation: suspension severity shape
    // -----------------------------------------------------------------------

    #[test]
    fn validate_rejects_empty_suspend_capability_set() {
        let rule = ConsequenceRule {
            trigger: ConsequenceTrigger::MessageVelocity,
            action: ConsequenceAction::Enforcement(EnforcementSeverity::SuspendCapability {
                capabilities: vec![],
            }),
            threshold: 1,
            window: Duration::from_mins(1),
        };
        let err = rule.validate().unwrap_err();
        assert!(
            err.to_string().contains("at least one"),
            "error should mention empty list, got: {err}"
        );
    }

    #[test]
    fn validate_rejects_too_many_capabilities() {
        let capabilities: Vec<Capability> = (0..33)
            .map(|i| Capability::Custom(format!("c{i}")))
            .collect();
        let rule = ConsequenceRule {
            trigger: ConsequenceTrigger::MessageVelocity,
            action: ConsequenceAction::Enforcement(EnforcementSeverity::SuspendCapability {
                capabilities,
            }),
            threshold: 1,
            window: Duration::from_mins(1),
        };
        let err = rule.validate().unwrap_err();
        assert!(
            err.to_string().contains("33 capabilities"),
            "error should mention capability count, got: {err}"
        );
    }

    #[test]
    fn validate_accepts_max_capabilities() {
        // Exactly 32 distinct Custom capabilities fits the cap.
        let capabilities: Vec<Capability> = (0..32)
            .map(|i| Capability::Custom(format!("c{i}")))
            .collect();
        let rule = ConsequenceRule {
            trigger: ConsequenceTrigger::MessageVelocity,
            action: ConsequenceAction::Enforcement(EnforcementSeverity::SuspendCapability {
                capabilities,
            }),
            threshold: 1,
            window: Duration::from_mins(1),
        };
        assert!(rule.validate().is_ok());
    }

    #[test]
    fn validate_rejects_duplicate_capabilities() {
        let rule = ConsequenceRule {
            trigger: ConsequenceTrigger::MessageVelocity,
            action: ConsequenceAction::Enforcement(EnforcementSeverity::SuspendCapability {
                capabilities: vec![Capability::MessagesWrite, Capability::MessagesWrite],
            }),
            threshold: 1,
            window: Duration::from_mins(1),
        };
        let err = rule.validate().unwrap_err();
        assert!(
            err.to_string().contains("duplicate"),
            "error should mention duplicate, got: {err}"
        );
    }

    #[test]
    fn validate_rejects_empty_tool_invoke_payload() {
        let rule = ConsequenceRule {
            trigger: ConsequenceTrigger::MessageVelocity,
            action: ConsequenceAction::Enforcement(EnforcementSeverity::SuspendCapability {
                capabilities: vec![Capability::ToolInvoke(String::new())],
            }),
            threshold: 1,
            window: Duration::from_mins(1),
        };
        let err = rule.validate().unwrap_err();
        assert!(
            err.to_string().contains("ToolInvoke has empty tool_id"),
            "should reject empty tool_id, got: {err}"
        );
    }

    #[test]
    fn validate_rejects_empty_custom_capability_name() {
        let rule = ConsequenceRule {
            trigger: ConsequenceTrigger::MessageVelocity,
            action: ConsequenceAction::Enforcement(EnforcementSeverity::SuspendCapability {
                capabilities: vec![Capability::Custom(String::new())],
            }),
            threshold: 1,
            window: Duration::from_mins(1),
        };
        let err = rule.validate().unwrap_err();
        assert!(
            err.to_string().contains("empty name"),
            "should reject empty Custom name, got: {err}"
        );
    }

    #[test]
    fn validate_accepts_suspend_access_severity() {
        let rule = ConsequenceRule {
            trigger: ConsequenceTrigger::MessageVelocity,
            action: ConsequenceAction::Enforcement(EnforcementSeverity::SuspendAccess),
            threshold: 1,
            window: Duration::from_mins(1),
        };
        assert!(rule.validate().is_ok());
    }

    #[test]
    fn validate_rejects_oversized_assign_role_name() {
        let long_role = "r".repeat(129);
        let rule = ConsequenceRule {
            trigger: ConsequenceTrigger::MessageVelocity,
            action: ConsequenceAction::AssignRole { to_role: long_role },
            threshold: 1,
            window: Duration::from_mins(1),
        };
        let err = rule.validate().unwrap_err();
        assert!(
            err.to_string().contains("exceeds max length"),
            "error should mention max length, got: {err}"
        );
    }

    #[test]
    fn validate_rejects_each_html_special_char_in_custom_trigger() {
        for ch in ['<', '>', '&', '"', '\''] {
            let key = format!("trigger{ch}key");
            let rule = ConsequenceRule {
                trigger: ConsequenceTrigger::Custom(key),
                action: suspend_all(),
                threshold: 1,
                window: Duration::from_mins(1),
            };
            assert!(
                rule.validate().is_err(),
                "should reject char '{ch}' in custom trigger key"
            );
        }
    }

    #[test]
    fn validate_rejects_threshold_zero() {
        let rule = ConsequenceRule {
            trigger: ConsequenceTrigger::MessageVelocity,
            action: suspend_all(),
            threshold: 0,
            window: Duration::from_mins(1),
        };
        let err = rule.validate().unwrap_err();
        assert!(
            err.to_string().contains("threshold must be > 0"),
            "expected threshold rejection, got: {err}"
        );
    }

    #[test]
    fn validate_rejects_empty_custom_key() {
        let rule = ConsequenceRule {
            trigger: ConsequenceTrigger::Custom(String::new()),
            action: suspend_all(),
            threshold: 1,
            window: Duration::from_mins(1),
        };
        let err = rule.validate().unwrap_err();
        assert!(
            err.to_string().contains("must not be empty"),
            "expected empty key rejection, got: {err}"
        );
    }

    // -----------------------------------------------------------------------
    // EnforcementSeverity helpers
    // -----------------------------------------------------------------------

    #[test]
    fn severity_target_did_is_none_for_consequence_variants() {
        assert!(
            EnforcementSeverity::SuspendCapability {
                capabilities: vec![Capability::MessagesWrite]
            }
            .target_did()
            .is_none()
        );
        assert!(EnforcementSeverity::SuspendAccess.target_did().is_none());
    }

    #[test]
    fn severity_target_did_is_some_for_governance_variants() {
        use crate::context::governance::AccessScope;
        let rev = EnforcementSeverity::RevokeAccess {
            did: DID("did:key:alice".to_owned()),
            access: AccessScope::Write,
        };
        assert_eq!(rev.target_did().unwrap().as_ref(), "did:key:alice");

        let ej = EnforcementSeverity::RemoveMember {
            did: DID("did:key:bob".to_owned()),
            reason: None,
        };
        assert_eq!(ej.target_did().unwrap().as_ref(), "did:key:bob");
    }

    #[test]
    fn severity_variant_names_are_stable() {
        use crate::context::governance::AccessScope;
        assert_eq!(
            EnforcementSeverity::SuspendCapability {
                capabilities: vec![Capability::MessagesWrite]
            }
            .variant_name(),
            "SuspendCapability"
        );
        assert_eq!(
            EnforcementSeverity::SuspendAccess.variant_name(),
            "SuspendAccess"
        );
        assert_eq!(
            EnforcementSeverity::RevokeAccess {
                did: DID("did:key:alice".to_owned()),
                access: AccessScope::Read,
            }
            .variant_name(),
            "RevokeAccess"
        );
        assert_eq!(
            EnforcementSeverity::RemoveMember {
                did: DID("did:key:alice".to_owned()),
                reason: None,
            }
            .variant_name(),
            "RemoveMember"
        );
    }

    // -----------------------------------------------------------------------
    // B3: per-context opt-in for RevokeAccess / always reject RemoveMember
    // -----------------------------------------------------------------------

    #[test]
    fn validate_rejects_remove_member_consequence_unconditionally() {
        let rule = ConsequenceRule {
            trigger: ConsequenceTrigger::MessageVelocity,
            action: ConsequenceAction::Enforcement(EnforcementSeverity::RemoveMember {
                did: DID("did:key:alice".to_owned()),
                reason: None,
            }),
            threshold: 1,
            window: Duration::from_mins(1),
        };
        let err = rule.validate().unwrap_err();
        assert!(
            err.to_string().contains("RemoveMember"),
            "should reject RemoveMember, got: {err}"
        );

        // Also rejected under validate_against_config regardless of opt-in.
        let opt_in = ConsequenceConfig {
            allow_automatic_access_revocation: true,
        };
        assert!(rule.validate_against_config(&opt_in).is_err());
    }

    #[test]
    fn default_config_rejects_revoke_access_consequence() {
        use crate::context::governance::AccessScope;
        let rule = ConsequenceRule {
            trigger: ConsequenceTrigger::MessageVelocity,
            action: ConsequenceAction::Enforcement(EnforcementSeverity::RevokeAccess {
                did: DID("did:key:alice".to_owned()),
                access: AccessScope::Both,
            }),
            threshold: 1,
            window: Duration::from_mins(1),
        };
        // Shape-level validate() passes (RevokeAccess is well-formed).
        assert!(rule.validate().is_ok());
        // But validate_against_config() with default (opt-in false) rejects.
        let default_config = ConsequenceConfig::default();
        assert!(!default_config.allow_automatic_access_revocation);
        let err = rule.validate_against_config(&default_config).unwrap_err();
        assert!(
            err.to_string().contains("RevokeAccess")
                && err
                    .to_string()
                    .contains("allow_automatic_access_revocation"),
            "error should mention the opt-in flag, got: {err}"
        );
    }

    #[test]
    fn opt_in_config_accepts_revoke_access_consequence() {
        use crate::context::governance::AccessScope;
        let rule = ConsequenceRule {
            trigger: ConsequenceTrigger::MessageVelocity,
            action: ConsequenceAction::Enforcement(EnforcementSeverity::RevokeAccess {
                did: DID("did:key:alice".to_owned()),
                access: AccessScope::Write,
            }),
            threshold: 1,
            window: Duration::from_mins(1),
        };
        let opt_in = ConsequenceConfig {
            allow_automatic_access_revocation: true,
        };
        assert!(rule.validate_against_config(&opt_in).is_ok());
    }

    #[test]
    fn opt_in_config_accepts_standard_severities() {
        let opt_in = ConsequenceConfig {
            allow_automatic_access_revocation: true,
        };
        let rule = ConsequenceRule {
            trigger: ConsequenceTrigger::MessageVelocity,
            action: suspend_write(),
            threshold: 1,
            window: Duration::from_mins(1),
        };
        assert!(rule.validate_against_config(&opt_in).is_ok());

        let rule = ConsequenceRule {
            trigger: ConsequenceTrigger::MessageVelocity,
            action: suspend_all(),
            threshold: 1,
            window: Duration::from_mins(1),
        };
        assert!(rule.validate_against_config(&opt_in).is_ok());
    }

    #[test]
    fn is_consequence_eligible_matches_opt_in_table() {
        use crate::context::governance::AccessScope;
        // Always-eligible severities ignore the flag.
        assert!(
            EnforcementSeverity::SuspendCapability {
                capabilities: vec![Capability::MessagesWrite]
            }
            .is_consequence_eligible(false)
        );
        assert!(
            EnforcementSeverity::SuspendCapability {
                capabilities: vec![Capability::MessagesWrite]
            }
            .is_consequence_eligible(true)
        );
        assert!(EnforcementSeverity::SuspendAccess.is_consequence_eligible(false));
        assert!(EnforcementSeverity::SuspendAccess.is_consequence_eligible(true));
        // RevokeAccess gated on the flag.
        let rev = EnforcementSeverity::RevokeAccess {
            did: DID("did:key:alice".to_owned()),
            access: AccessScope::Both,
        };
        assert!(!rev.is_consequence_eligible(false));
        assert!(rev.is_consequence_eligible(true));
        // RemoveMember always ineligible.
        let ej = EnforcementSeverity::RemoveMember {
            did: DID("did:key:alice".to_owned()),
            reason: None,
        };
        assert!(!ej.is_consequence_eligible(false));
        assert!(!ej.is_consequence_eligible(true));
    }

    // -----------------------------------------------------------------------
    // B2 regression: capability-silent-ignore bug is fixed by typed caps
    // -----------------------------------------------------------------------
    //
    // Historical bug: `ConsequenceAction::Enforcement(EnforcementSeverity::SuspendCapability { capabilities: Vec<String> })`
    // silently dropped unknown names. With `Vec<Capability>`, the type system
    // enforces known variants at construction time; the runtime cannot drop a
    // typed variant without knowing what it is.

    #[test]
    fn b2_suspend_governance_vote_is_respected() {
        let rule = ConsequenceRule {
            trigger: ConsequenceTrigger::MessageVelocity,
            action: ConsequenceAction::Enforcement(EnforcementSeverity::SuspendCapability {
                capabilities: vec![Capability::GovernanceVote],
            }),
            threshold: 1,
            window: Duration::from_mins(1),
        };
        rule.validate().expect("well-formed rule");
        // Precise destructure confirms the capability is retained typed.
        let ConsequenceAction::Enforcement(EnforcementSeverity::SuspendCapability { capabilities }) =
            &rule.action
        else {
            panic!("expected SuspendCapability, got {:?}", rule.action);
        };
        assert_eq!(capabilities, &vec![Capability::GovernanceVote]);
    }

    #[test]
    fn b2_suspend_custom_tool_invoke_is_respected() {
        let rule = ConsequenceRule {
            trigger: ConsequenceTrigger::MessageVelocity,
            action: ConsequenceAction::Enforcement(EnforcementSeverity::SuspendCapability {
                capabilities: vec![Capability::ToolInvoke("calculator".to_owned())],
            }),
            threshold: 1,
            window: Duration::from_mins(1),
        };
        rule.validate().expect("well-formed rule");
        let ConsequenceAction::Enforcement(EnforcementSeverity::SuspendCapability { capabilities }) =
            &rule.action
        else {
            panic!("expected SuspendCapability");
        };
        assert_eq!(
            capabilities,
            &vec![Capability::ToolInvoke("calculator".to_owned())]
        );
    }

    #[test]
    fn b2_mixed_standard_and_custom_capabilities_are_respected() {
        let caps = vec![
            Capability::MessagesWrite,
            Capability::GovernanceVote,
            Capability::ToolInvoke("calculator".to_owned()),
            Capability::Custom("rate_limit_bypass".to_owned()),
        ];
        let rule = ConsequenceRule {
            trigger: ConsequenceTrigger::MessageVelocity,
            action: ConsequenceAction::Enforcement(EnforcementSeverity::SuspendCapability {
                capabilities: caps.clone(),
            }),
            threshold: 1,
            window: Duration::from_mins(1),
        };
        rule.validate().expect("well-formed rule");
        let ConsequenceAction::Enforcement(EnforcementSeverity::SuspendCapability { capabilities }) =
            &rule.action
        else {
            panic!("expected SuspendCapability");
        };
        assert_eq!(capabilities, &caps);
    }
}
