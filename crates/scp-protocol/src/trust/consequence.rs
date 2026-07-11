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

use scp_did::DID;
use scp_event_log::{Event, EventType};

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

    /// The subject invoked outlets at a rate exceeding the threshold within the
    /// time window. Counted from `EventType::OutletInvoked` events.
    ///
    /// # Currently dormant / non-functional
    ///
    /// This trigger cannot fire today. It keys on
    /// `EventType::OutletInvoked`, but per-author `OutletInvoked` is no longer
    /// durably logged and there is no corresponding `ContextEvent::OutletInvoked`
    /// variant, so no convergent outlet-invocation signal exists in the interim.
    /// A configured `OutletRateExceeded` rule is therefore a no-op until a
    /// convergent outlet-rate input arrives with the ADR-051 causal-DAG ordering.
    /// The variant is retained (removing it is an API change, out of scope) so
    /// rules remain expressible against the eventual convergent signal. Outlet
    /// flooding remains bounded in the interim by the independent hard rate
    /// limit, which does not depend on this trigger.
    OutletRateExceeded,

    /// The subject accumulated warnings (governance actions against them)
    /// exceeding the threshold within the time window. Counted from
    /// `EventType::GovernanceAction` events targeting the subject.
    WarningCount,

    /// A custom trigger identified by a string key. The event counting logic
    /// matches governance-action events whose payload's `target_did` field
    /// (decoded from the typed positional-`MessagePack` or JSON-object
    /// encoding) starts with the given key, allowing context-specific
    /// consequence definitions.
    Custom(String),
}

/// Whether a consequence triggered by this condition may be recorded as a
/// **durable Merkle leaf** in the canonical event log.
///
/// This is the single source of truth for the consequence-durability gate
/// (keyed on the enum, never on a string). Per ADR-051 §6 and the phase-2.md
/// ADR-011 amendment ("Consequence emission"), a derived record is automatic
/// *and* convergent iff its trigger **input** is convergent:
///
/// - **Convergent triggers** — `WarningCount` (governance-action counts) and
///   `Custom` (matched against convergent governance-action events). These
///   auto-derive identically on every honest member from the convergent log, so
///   their consequence leaf converges and is durable.
/// - **Non-convergent triggers** — `MessageVelocity` and `OutletRateExceeded`. A
///   *rate* (count ÷ time) needs a convergent clock, which the protocol neither
///   has (no operator / transport-independent / offline) nor needs. Rate-limiting
///   is local flow control (§23.16.8), not a recorded consequence; a durable
///   suspension rides governance (ADR-031), where the commit *is* both the
///   execution and the record. Velocity-triggered consequences therefore add no
///   durable leaf — they remain buffer-only `ContextEvent`s while still driving
///   local enforcement.
///
/// A consequence whose rule is missing or whose trigger cannot be resolved is
/// treated as **non-durable** (fail-safe: never mint an unconvergent leaf).
#[must_use]
pub const fn is_convergent_trigger(trigger: &ConsequenceTrigger) -> bool {
    match trigger {
        ConsequenceTrigger::WarningCount | ConsequenceTrigger::Custom(_) => true,
        ConsequenceTrigger::MessageVelocity | ConsequenceTrigger::OutletRateExceeded => false,
    }
}

/// The convergent Merkle-leaf timestamp for a durable consequence leaf.
///
/// This is the `timestamp` of the highest-sequence piece of evidence that
/// triggered the consequence — i.e. the convergent log event that crossed the
/// trigger threshold.
///
/// Because the evidence is drawn from the shared convergent event log, every
/// honest member derives the identical value, keeping the
/// durable leaf byte-identical across members for the §9.9.3
/// equal-count/equal-root equivocation test. Only convergent-trigger
/// consequences reach a durable leaf ([`is_convergent_trigger`]), so the
/// evidence is convergent here; an evidence-less consequence (which never
/// produces a durable leaf) yields 0.
#[must_use]
pub fn convergent_consequence_timestamp(consequence: &TriggeredConsequence) -> u64 {
    consequence
        .evidence
        .iter()
        .max_by_key(|e| e.event_sequence)
        .map_or(0, |e| e.timestamp)
}

/// Stable string label for a [`ConsequenceTrigger`], used as the `trigger_kind`
/// field of a durable consequence Merkle-leaf payload
/// (`scp_event_log::payload::consequence_event_payload`).
///
/// This is the single source of the label so that all honest members
/// produce byte-identical leaf payloads (§9.9.3 convergence). Note
/// the `Custom(key)` arm emits `"Custom:{key}"` — NOT the `{:?}` Debug form
/// `Custom("{key}")` — because the durable leaf preimage must be a stable,
/// implementation-independent string.
#[must_use]
pub fn trigger_kind_str(trigger: &ConsequenceTrigger) -> String {
    match trigger {
        ConsequenceTrigger::MessageVelocity => "MessageVelocity".to_owned(),
        ConsequenceTrigger::OutletRateExceeded => "OutletRateExceeded".to_owned(),
        ConsequenceTrigger::WarningCount => "WarningCount".to_owned(),
        ConsequenceTrigger::Custom(key) => format!("Custom:{key}"),
    }
}

/// Stable string label for a [`ConsequenceAction`], used as the `action_type`
/// field of a durable consequence Merkle-leaf payload
/// (`scp_event_log::payload::consequence_event_payload`).
///
/// Shared so all honest members produce
/// byte-identical leaf payloads (§9.9.3 convergence). For an
/// [`ConsequenceAction::Enforcement`] this delegates to
/// [`EnforcementSeverity::variant_name`]; an [`ConsequenceAction::AssignRole`]
/// is labelled `"AssignRole"`.
#[must_use]
pub const fn consequence_action_type(action: &ConsequenceAction) -> &'static str {
    match action {
        ConsequenceAction::Enforcement(sev) => sev.variant_name(),
        ConsequenceAction::AssignRole { .. } => "AssignRole",
    }
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
///   [`ConsequenceConfig::allow_automatic_access_revocation`](crate::context::params::ConsequenceConfig::allow_automatic_access_revocation) is `true`
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
    /// context's [`ConsequenceConfig::allow_automatic_access_revocation`](crate::context::params::ConsequenceConfig::allow_automatic_access_revocation) is
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
    /// events whose timestamp falls in `[anchor - window, anchor]` are
    /// considered, where `anchor` depends on the trigger's convergence
    /// ([`is_convergent_trigger`]): a **convergent** trigger (`WarningCount`,
    /// `Custom`) anchors on the convergent event-log timestamp so its durable
    /// leaf is byte-identical across skewed members (§9.9.3); a
    /// **non-convergent** trigger (`MessageVelocity`, `OutletRateExceeded`)
    /// anchors on the evaluating member's local clock, as local flow control.
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
                // Validate Custom(name) / OutletQuery(id) / OutletCall(id)
                // payload strings.
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
                } else if let Capability::OutletQuery(outlet_id) = cap {
                    if outlet_id.is_empty() {
                        return Err(ConsequenceValidationError(format!(
                            "SuspendCapability[{i}] OutletQuery has empty outlet_id",
                        )));
                    }
                    validate_consequence_string(
                        outlet_id,
                        &format!("SuspendCapability[{i}] OutletQuery"),
                        MAX_CONSEQUENCE_STRING_LEN,
                    )?;
                } else if let Capability::OutletCall(outlet_id) = cap {
                    if outlet_id.is_empty() {
                        return Err(ConsequenceValidationError(format!(
                            "SuspendCapability[{i}] OutletCall has empty outlet_id",
                        )));
                    }
                    validate_consequence_string(
                        outlet_id,
                        &format!("SuspendCapability[{i}] OutletCall"),
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TriggeredConsequence {
    /// Index of the rule in the original rules slice that was triggered.
    pub rule_index: usize,

    /// The enforcement action to take.
    pub action: ConsequenceAction,

    /// The events that contributed to triggering this consequence.
    pub evidence: Vec<ConsequenceEvidence>,
}

// ---------------------------------------------------------------------------
// merge_consequence_events
// ---------------------------------------------------------------------------

/// Maximum age (in seconds) for receive-buffer events used in consequence
/// evaluation. Events estimated to be older than this are discarded as
/// stale, preventing manipulation via timestamp back-dating.
const MAX_BUFFER_EVENT_AGE_SECS: u64 = 3600; // 1 hour

/// Maximum clock skew tolerance (in seconds) for buffer event timestamps.
/// Events with estimated timestamps more than this far in the future are
/// discarded.
const MAX_FUTURE_TOLERANCE_SECS: u64 = 5;

/// Maximum number of receive-buffer events consumed per consequence evaluation
/// cycle. Caps the cost of evaluation and prevents an attacker from flooding
/// the buffer to drive synthetic high event counts (e.g. inflating a
/// `WarningCount` trigger by queuing thousands of messages before governance
/// runs). Events beyond this cap are simply not fed into the evaluator;
/// the persisted event log (Source 1) covers all durable history.
const MAX_BUFFER_EVENTS_FOR_EVAL: usize = 100;

/// Merges the durable Merkle event log with the recent receive buffer into the
/// single event history that [`evaluate_consequence_rules`] (and participation
/// record computation, ADR-017) reads.
///
/// This is the **single** convergence-critical merge used by the native
/// runtime (`scp-runtime`). The §9.9.3 equivocation-detection guarantee depends
/// on all honest members producing byte-identical merged event sets from
/// identical inputs, so every consumer MUST route through this function rather
/// than re-implementing the projection and buffer-gate logic. Each caller
/// supplies its own already-acquired sources as borrowed slices — native reads
/// Source 1 from its `ContextEventLogProvider` — so this function is agnostic to
/// how the sources were obtained.
///
/// Combines two sources:
/// 1. **Event log history** (`log_entries`) — full persisted history with real
///    timestamps and `actor_did`. Each entry's typed [`EventType`] is projected
///    onto the coarse trigger buckets [`matches_trigger`] understands
///    (governance and consequence-enforcement variants collapse to
///    [`EventType::GovernanceAction`]; operational variants map to their
///    velocity buckets). The canonical payload bytes pass through unchanged.
///    Projecting consequence events into the governance bucket closes the
///    recursive blind spot (white-hat H4): subsequent rule evaluation can see
///    prior consequence enforcement (e.g. "if member has been auto-suspended N
///    times, demote").
/// 2. **Receive buffer events** (`buffer`) — recent in-memory `ContextEvent`s.
///    Buffer events use estimated timestamps (spaced 1 second apart backwards
///    from `now_secs`) and are gated by [`MAX_BUFFER_EVENT_AGE_SECS`],
///    [`MAX_FUTURE_TOLERANCE_SECS`], and [`MAX_BUFFER_EVENTS_FOR_EVAL`].
///
/// The merged set is numbered with a single dense, contiguous `sequence`
/// counter (Source-1 entries first, then accepted Source-2 entries), so every
/// member agrees on every field of every emitted [`Event`]. The `sequence`
/// itself is not consulted by [`matches_trigger`] (which keys on
/// `event_type` / `actor_did` / `timestamp` / `payload`), but pinning it
/// deterministically keeps the merged sets identical across implementations.
///
/// Exposed `pub` (not `pub(crate)`) as an internal cross-crate helper: the
/// native runtime (`scp-runtime`) drives the convergent consequence path and
/// delegates to this shared function across the crate boundary. It is not part
/// of the SDK surface (see the cross-layer exemption registry).
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn merge_consequence_events(
    log_entries: &[Event],
    buffer: &std::collections::VecDeque<crate::context::membership::ContextEvent>,
    now_secs: u64,
) -> Vec<Event> {
    use crate::context::membership::ContextEvent;

    let mut events: Vec<Event> = Vec::new();

    // Source 1: Full event log history (persisted, with real timestamps and
    // actor_did). Project each entry's typed `EventType` onto the bucket
    // `matches_trigger` understands.
    for entry in log_entries {
        let event_type = match entry.event_type {
            // DORMANT: per ADR-051 §6 / the phase-2.md ADR-011 amendment
            // exclusion taxonomy §2, `MessageSent` / `OutletInvoked` are
            // per-author, non-convergent events no longer appended to the
            // durable log — Source 1 will not yield them in the interim.
            // Velocity / outlet-rate evaluation continues to read them from
            // the receive buffer (Source 2, below), which is correct and
            // intended (local, per-receiver flow control needs no
            // convergence). These arms re-activate when ADR-051 §2's causal
            // DAG re-enters application events into the canonical log.
            EventType::MessageSent => EventType::MessageSent,
            EventType::MemberJoined => EventType::MemberJoined,
            EventType::MemberLeft => EventType::MemberLeft,
            EventType::RoleAssigned => EventType::RoleAssigned,
            EventType::OutletRegistered | EventType::OutletRemoved | EventType::OutletInvoked => {
                EventType::OutletInvoked
            }
            EventType::GovernanceAction
            | EventType::GovernanceProposalCreated
            | EventType::GovernanceVoteCast
            | EventType::GovernanceVoteWithdrawn
            | EventType::GovernanceProposalResolved
            | EventType::GovernanceDeadlockRecovery
            | EventType::GovernanceConflictDetected
            | EventType::GovernanceConflictResolved
            | EventType::GovernanceActionExecuted
            | EventType::AccessRevoked
            | EventType::ConsequenceTriggered
            | EventType::ConsequenceEnforced
            | EventType::ConsequenceEnforcementFailed
            | EventType::ConsequenceEscalatedToSuspendAll => EventType::GovernanceAction,
            _ => continue, // Skip event types not relevant to consequence evaluation
        };
        // The event already carries its canonical payload bytes (typed
        // positional MessagePack for promoted variants, JSON for the
        // remaining untyped ones). `payload_target_is` / `payload_starts_with`
        // decode both encodings, so pass the bytes through unchanged.
        events.push(Event {
            event_type,
            actor_did: entry.actor_did.clone(),
            timestamp: entry.timestamp,
            sequence: events.len() as u64,
            payload: entry.payload.clone(),
            prev_hash: [0u8; 32],
            signature: Vec::new(),
        });
    }

    // Source 2: Receive buffer events.
    //
    // CONVERGENCE INVARIANT (ADR-051 §6 / phase-2.md ADR-011 amendment §2 /
    // spec §9.9.3 equivocation detection): the buffer may ONLY contribute
    // per-author / velocity-class event types that are NOT in the durable
    // log — i.e. `MessageSent` alone. `MessageSent` is per-author and is
    // excluded from the canonical Merkle log (Source 1), so the receive
    // buffer is its only source; velocity / rate triggers legitimately need
    // it, and per-member variation is by-design local flow control that
    // never feeds a convergent or durable leaf.
    //
    // Convergent events (membership, governance, consequence) are appended
    // to the durable log BEFORE being pushed to the receive buffer (see
    // `governance_helpers.rs`), so they ALWAYS appear in Source 1 on every
    // honest member identically. Sourcing them ALSO from the per-member
    // buffer here would double-count them on quiet members and skip them on
    // busy ones (the dedup below is keyed on the member-local `buffer_len`),
    // producing divergent `WarningCount` / `Custom` counts and therefore a
    // divergent durable `ConsequenceTriggered` leaf — a false-positive
    // equivocation that defeats the entire convergence guarantee. Those
    // events MUST come exclusively from Source 1, so the match below omits
    // them (they fall through to `_ => continue`).
    //
    // The dedup / age / skew / cap logic below now only ever gates
    // `MessageSent` buffer events. Because `MessageSent` is not in Source 1,
    // the `estimated_ts <= last_log_ts` dedup may still skip some of them;
    // that is acceptable — velocity / rate is non-durable, per-receiver
    // local flow control where per-member variation is by design.
    let last_log_ts = events.last().map_or(0, |e| e.timestamp);
    let buffer_len = buffer.len() as u64;
    let next_seq = events.len() as u64;

    // Track how many buffer-derived events we've accepted so far. Once
    // MAX_BUFFER_EVENTS_FOR_EVAL is reached, stop adding more.
    // This cap prevents an attacker from flooding the buffer to inflate
    // synthetic event counts (e.g. triggering a `WarningCount` consequence
    // prematurely). The persisted event log (Source 1) covers all durable
    // history; the buffer is only a short-term supplement.
    let mut buffer_events_accepted: usize = 0;

    for (idx, ctx_event) in buffer.iter().enumerate() {
        let (event_type, actor_did, payload_data) = match ctx_event {
            // Only per-author / velocity-class events are sourced from the
            // buffer (see the CONVERGENCE INVARIANT comment above).
            // `MessageSent` is excluded from the durable log, so the buffer is
            // its only source. All convergent events (MemberJoined/MemberLeft/
            // GovernanceActionExecuted/consequence) are intentionally NOT
            // matched here — they come exclusively from Source 1 to preserve
            // durable-leaf convergence — and fall through to `_ => continue`.
            ContextEvent::MessageSent { sender_did, .. }
            | ContextEvent::MessageReceived { sender_did, .. } => {
                (EventType::MessageSent, sender_did.clone(), Vec::new())
            }
            _ => continue,
        };
        // Oldest event gets `now - (buffer_len - 1)`, newest gets `now`.
        let estimated_ts =
            now_secs.saturating_sub(buffer_len.saturating_sub(1).saturating_sub(idx as u64));

        // Skip buffer events that are likely already covered by the event log.
        if estimated_ts <= last_log_ts && last_log_ts > 0 {
            continue;
        }

        // Defense in depth: reject buffer events with estimated timestamps too
        // far in the future. Currently the estimation formula guarantees
        // estimated_ts <= now_secs, so this never triggers — but it guards
        // against future changes to the formula.
        if estimated_ts > now_secs.saturating_add(MAX_FUTURE_TOLERANCE_SECS) {
            continue;
        }

        // Reject buffer events with timestamps too far in the past (M18).
        if now_secs.saturating_sub(estimated_ts) > MAX_BUFFER_EVENT_AGE_SECS {
            continue;
        }

        // M-R cap: stop once we've accepted MAX_BUFFER_EVENTS_FOR_EVAL events
        // from the buffer. Additional events are not fed to the evaluator.
        if buffer_events_accepted >= MAX_BUFFER_EVENTS_FOR_EVAL {
            break;
        }

        // Dense, contiguous numbering: key the sequence on the count of
        // ACCEPTED buffer events (`buffer_events_accepted`, pre-increment), NOT
        // the raw enumeration index `idx`. Using `idx` would leave gaps whenever
        // a buffer event is skipped (dedup / age / skew / non-`MessageSent`),
        // contradicting the contiguity the doc promises. The sequence is
        // evidence-only metadata — `matches_trigger` never reads it — so this is
        // behavior-preserving and keeps the merged sets identical across all
        // honest members.
        events.push(Event {
            event_type,
            actor_did,
            timestamp: estimated_ts,
            sequence: next_seq + buffer_events_accepted as u64,
            payload: scp_event_log::EventPayload { data: payload_data },
            prev_hash: [0u8; 32],
            signature: Vec::new(),
        });
        buffer_events_accepted += 1;
    }

    events
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
/// - `now` -- The current time as a Unix timestamp in seconds, read from the
///   evaluating member's **local** clock. Used to compute the evidence window
///   boundary for **non-convergent** triggers ([`is_convergent_trigger`] is
///   `false`: `MessageVelocity`, `OutletRateExceeded`), which are local flow
///   control and never mint a durable leaf, so a local-clock window is sound.
/// - `convergent_now` -- The convergent window anchor (Unix seconds) used for
///   **convergent** triggers ([`is_convergent_trigger`] is `true`: `WarningCount`,
///   `Custom`). It must be the max timestamp of the convergent **Source-1
///   durable log entries** — NOT a local clock, and NOT derived from the
///   post-merge `events` (which include Source-2 buffer events carrying
///   local-clock estimated timestamps). Anchoring convergent triggers to the
///   convergent log makes the evidence window — and hence the durable
///   `ConsequenceTriggered` leaf — byte-identical across honest members with
///   skewed local clocks, eliminating the §9.9.3 equivocation false positive.
///
/// # Returns
///
/// A `Vec<TriggeredConsequence>` containing all rules that fired. The vector
/// is empty if no rules were triggered.
///
/// # Design Notes
///
/// - Pure computation -- no side effects, no storage.
/// - The window anchor splits on the trigger's convergence: convergent triggers
///   use `convergent_now` (window `[convergent_now - window, convergent_now]`),
///   non-convergent triggers use the local `now` (window `[now - window, now]`).
///   Everything downstream (`matches_trigger`, evidence collection, threshold,
///   `convergent_consequence_timestamp`) is unchanged.
/// - The clock parameters are passed explicitly (rather than using a `Clock`
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
    convergent_now: u64,
) -> Vec<TriggeredConsequence> {
    let mut triggered = Vec::new();

    for (rule_index, rule) in rules.iter().enumerate() {
        // Convergent-trigger consequences mint a durable Merkle leaf, so their
        // evidence window must anchor on the convergent log (`convergent_now`),
        // not the evaluating member's skewed local clock. Non-convergent triggers
        // are local flow control and keep the local-clock window.
        let window_anchor = if is_convergent_trigger(&rule.trigger) {
            convergent_now
        } else {
            now
        };
        let window_start = window_anchor.saturating_sub(rule.window.as_secs());

        let evidence: Vec<ConsequenceEvidence> = events
            .iter()
            .filter(|event| {
                // Time window filter.
                event.timestamp >= window_start && event.timestamp <= window_anchor
            })
            .filter(|event| matches_trigger(&rule.trigger, event, subject_did))
            .map(|event| ConsequenceEvidence {
                event_sequence: event.sequence,
                timestamp: event.timestamp,
                actor_did: event.actor_did.clone(),
                event_type: event.event_type,
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

/// Checks whether an event matches a trigger condition for the given subject.
fn matches_trigger(trigger: &ConsequenceTrigger, event: &Event, subject_did: &str) -> bool {
    match trigger {
        ConsequenceTrigger::MessageVelocity => {
            event.actor_did == subject_did && event.event_type == EventType::MessageSent
        }
        ConsequenceTrigger::OutletRateExceeded => {
            event.actor_did == subject_did && event.event_type == EventType::OutletInvoked
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
/// Returns the `target_did` carried by an event-log payload, if any.
///
/// The runtime emits exactly two payload encodings into the durable event log,
/// and this decoder accepts only those two:
///
/// 1. **Positional `MessagePack`** for the typed
///    [`scp_event_log::payload`] structs whose first field is `target_did`
///    (e.g. [`scp_event_log::payload::AccessRevokedPayload`],
///    [`scp_event_log::payload::GovernanceActionExecutedPayload`]). These are
///    fixarrays; the first element is the `target_did` string.
/// 2. **JSON objects** with a `"target_did"` field, for the consequence
///    enforcement records (`ConsequenceTriggered`, …) and other untyped
///    governance payloads that have not (yet) been promoted to a typed struct.
///
/// The positional case allocates a `String` because the bytes are decoded; the
/// JSON case copies the matched field.
fn payload_target_did(data: &[u8]) -> Option<String> {
    if data.is_empty() {
        return None;
    }
    // 1. Typed positional MessagePack: read the fixarray and take element 0.
    if let Some(did) = rmp_array_first_string(data) {
        return Some(did);
    }
    // 2. Structured JSON object.
    serde_json::from_slice::<serde_json::Value>(data)
        .ok()
        .and_then(|val| {
            val.get("target_did")
                .and_then(|v| v.as_str())
                .map(str::to_owned)
        })
}

/// Decodes `data` as a positional `MessagePack` array and returns its first
/// element as a `String`, if `data` is an array whose first element is a
/// string. Returns `None` for any other shape (including JSON-object payloads,
/// which are `MessagePack` maps, not arrays).
///
/// This is the decode counterpart to
/// [`scp_event_log::payload::encode_payload`] for the typed payload structs
/// whose first field is `target_did`. It reads only the first element, so it
/// works uniformly across structs of differing arity (1-field
/// `AccessRevokedPayload`, 2-field `GovernanceActionExecutedPayload`).
fn rmp_array_first_string(data: &[u8]) -> Option<String> {
    let mut cursor = data;
    let value = rmpv::decode::read_value(&mut cursor).ok()?;
    match value {
        rmpv::Value::Array(items) => items
            .into_iter()
            .next()
            .and_then(|v| v.as_str().map(str::to_owned)),
        _ => None,
    }
}

/// Checks whether the event-log payload's `target_did` matches `target_did`.
///
/// See [`payload_target_did`] for the supported payload encodings.
fn payload_target_is(data: &[u8], target_did: &str) -> bool {
    payload_target_did(data).is_some_and(|did| did == target_did)
}

/// Checks whether the event-log payload's identifying string matches (or
/// begins with) `prefix`, used by the `Custom` trigger to match consequence
/// records against its key.
///
/// Decodes the same two live encodings as [`payload_target_did`]:
///
/// 1. **Positional `MessagePack`** — match the first array element
///    (`target_did`) against the prefix.
/// 2. **JSON objects** — match the `"target_did"` field against the prefix.
///
/// The `Custom` trigger's payload is the consequence-record JSON object, whose
/// identifying field is `target_did` (the trigger kind is separately encoded as
/// `"trigger_kind": "Custom:<key>"`), so the JSON branch reads `target_did`.
fn payload_starts_with(data: &[u8], prefix: &str) -> bool {
    if data.is_empty() {
        return false;
    }
    // Typed positional MessagePack: match the first array element (target_did)
    // against the prefix, mirroring the JSON target_did path below.
    if let Some(did) = rmp_array_first_string(data) {
        return did == prefix || did.starts_with(prefix);
    }
    // Structured JSON object: match the target_did field.
    serde_json::from_slice::<serde_json::Value>(data)
        .ok()
        .and_then(|val| {
            val.get("target_did")
                .and_then(|v| v.as_str())
                .map(str::to_owned)
        })
        .is_some_and(|did| did == prefix || did.starts_with(prefix))
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

        let result = evaluate_consequence_rules(&rules, &events, "did:key:alice", 1000, 1000);

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].rule_index, 0);
        assert_eq!(result[0].action, suspend_write());
        assert_eq!(result[0].evidence.len(), 3);
    }

    // -----------------------------------------------------------------------
    // 2. Outlet rate threshold triggers suspension
    // -----------------------------------------------------------------------

    #[test]
    fn outlet_rate_triggers_suspend_all() {
        let rules = vec![ConsequenceRule {
            trigger: ConsequenceTrigger::OutletRateExceeded,
            action: suspend_all(),
            threshold: 5,
            window: Duration::from_mins(2),
        }];

        let events: Vec<Event> = (0..5)
            .map(|i| {
                make_event(
                    EventType::OutletInvoked,
                    "did:key:alice",
                    900 + i,
                    i,
                    b"some-outlet".to_vec(),
                )
            })
            .collect();

        let result = evaluate_consequence_rules(&rules, &events, "did:key:alice", 1000, 1000);

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

        let result = evaluate_consequence_rules(&rules, &events, "did:key:alice", 1000, 1000);

        assert_eq!(result.len(), 1);
        assert_eq!(
            result[0].action,
            ConsequenceAction::AssignRole {
                to_role: "observer".to_owned()
            }
        );
        assert_eq!(result[0].evidence.len(), 2);
    }

    /// Convergence pin (§9.9.3): a convergent-trigger rule (`WarningCount`)
    /// evaluated by two honest members with the SAME convergent `events` but
    /// DIFFERENT local clocks (`now_a` vs `now_b`) MUST produce byte-identical
    /// results — including the same `convergent_consequence_timestamp` — as long
    /// as both anchor on the SAME `convergent_now` (the max timestamp of the
    /// convergent durable log). Before the fix, the evidence window keyed on the
    /// local `now`, so skewed members selected different evidence subsets of the
    /// same convergent events and minted divergent durable leaves.
    #[test]
    fn convergent_window_anchor_converges_under_skewed_local_clocks() {
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

        // Identical convergent governance-action evidence on both members.
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

        // Same convergent anchor (max log timestamp), skewed LOCAL clocks.
        let convergent_now = 1000;
        let now_a = 1000;
        let now_b = 1250;

        let result_a =
            evaluate_consequence_rules(&rules, &events, "did:key:alice", now_a, convergent_now);
        let result_b =
            evaluate_consequence_rules(&rules, &events, "did:key:alice", now_b, convergent_now);

        // Byte-identical triggered set — the durable leaf converges.
        assert_eq!(result_a, result_b);
        assert_eq!(result_a.len(), 1);
        assert_eq!(result_a[0].evidence.len(), 2);
        // The convergent leaf timestamp (highest-sequence evidence) is identical.
        assert_eq!(
            convergent_consequence_timestamp(&result_a[0]),
            convergent_consequence_timestamp(&result_b[0]),
        );
    }

    /// Non-vacuity control for
    /// [`convergent_window_anchor_converges_under_skewed_local_clocks`]: if the
    /// anchor itself were skewed (the pre-fix behaviour, here simulated by
    /// passing each member's LOCAL clock AS `convergent_now`), an event whose
    /// timestamp lies BETWEEN the two anchors falls inside one member's window
    /// and outside the other's — so the results DIVERGE. This proves the
    /// convergence in the positive test comes from the shared anchor, not from
    /// the evidence happening to fall in every window regardless.
    #[test]
    fn convergent_window_skewed_anchor_diverges() {
        let rules = vec![ConsequenceRule {
            trigger: ConsequenceTrigger::WarningCount,
            action: ConsequenceAction::AssignRole {
                to_role: "observer".to_owned(),
            },
            threshold: 1,
            window: Duration::from_mins(5),
        }];

        let payload =
            serde_json::to_vec(&serde_json::json!({"target_did": "did:key:alice"})).unwrap();

        // A single convergent event at ts=1100 — between the two skewed anchors.
        let events = vec![make_event(
            EventType::GovernanceAction,
            "did:key:admin",
            1100,
            0,
            payload,
        )];

        // Pre-fix simulation: anchor == local clock. Window = 300s.
        //   anchor_a = 1000 -> window [700, 1000]  -> 1100 EXCLUDED -> no trigger
        //   anchor_b = 1250 -> window [950, 1250]  -> 1100 INCLUDED -> trigger
        let result_a = evaluate_consequence_rules(&rules, &events, "did:key:alice", 1000, 1000);
        let result_b = evaluate_consequence_rules(&rules, &events, "did:key:alice", 1250, 1250);

        assert_ne!(result_a, result_b);
        assert_eq!(result_a.len(), 0);
        assert_eq!(result_b.len(), 1);
    }

    /// The `WarningCount` trigger must match events whose payload is a typed
    /// positional `MessagePack` struct (the encoding the runtime now emits for
    /// `AccessRevoked` / `GovernanceActionExecuted`), not just JSON objects.
    /// Exercises the `rmp_array_first_string` decode path in
    /// [`payload_target_did`].
    #[test]
    fn warning_count_matches_typed_positional_payload() {
        let rules = vec![ConsequenceRule {
            trigger: ConsequenceTrigger::WarningCount,
            action: ConsequenceAction::AssignRole {
                to_role: "observer".to_owned(),
            },
            threshold: 2,
            window: Duration::from_mins(5),
        }];

        // Encode the same way the runtime producers do: positional rmp of a
        // struct whose first field is `target_did`.
        let revoked =
            scp_event_log::payload::encode_payload(&scp_event_log::payload::AccessRevokedPayload {
                target_did: "did:key:alice".to_owned(),
            })
            .unwrap();
        let executed = scp_event_log::payload::encode_payload(
            &scp_event_log::payload::GovernanceActionExecutedPayload {
                target_did: "did:key:alice".to_owned(),
                action_type: "RemoveMember".to_owned(),
            },
        )
        .unwrap();

        let events = vec![
            make_event(
                EventType::GovernanceAction,
                "did:key:admin",
                800,
                0,
                revoked.data,
            ),
            // A 2-field struct must still decode to its first element.
            make_event(
                EventType::GovernanceAction,
                "did:key:moderator",
                900,
                1,
                executed.data,
            ),
        ];

        let result = evaluate_consequence_rules(&rules, &events, "did:key:alice", 1000, 1000);
        assert_eq!(result.len(), 1, "typed payloads must drive WarningCount");
        assert_eq!(result[0].evidence.len(), 2);

        // A different subject must NOT match.
        let none = evaluate_consequence_rules(&rules, &events, "did:key:bob", 1000, 1000);
        assert!(none.is_empty(), "typed payload target_did must be exact");
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

        let result = evaluate_consequence_rules(&rules, &events, "did:key:alice", 1000, 1000);

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

        let result = evaluate_consequence_rules(&rules, &events, "did:key:alice", 1000, 1000);

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

        let result = evaluate_consequence_rules(&rules, &events, "did:key:alice", 1000, 1000);
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

        let result = evaluate_consequence_rules(&rules, &events, "did:key:alice", 1000, 1000);
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
                trigger: ConsequenceTrigger::OutletRateExceeded,
                action: suspend_all(),
                threshold: 1,
                window: Duration::from_mins(1),
            },
        ];

        let events = vec![
            make_event(EventType::MessageSent, "did:key:alice", 950, 0, vec![]),
            make_event(EventType::MessageSent, "did:key:alice", 960, 1, vec![]),
            make_event(
                EventType::OutletInvoked,
                "did:key:alice",
                970,
                2,
                b"outlet-x".to_vec(),
            ),
        ];

        let result = evaluate_consequence_rules(&rules, &events, "did:key:alice", 1000, 1000);

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

        let result = evaluate_consequence_rules(&rules, &[], "did:key:alice", 1000, 1000);
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

        let result = evaluate_consequence_rules(&[], &events, "did:key:alice", 1000, 1000);
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
    fn validate_rejects_empty_outlet_call_payload() {
        let rule = ConsequenceRule {
            trigger: ConsequenceTrigger::MessageVelocity,
            action: ConsequenceAction::Enforcement(EnforcementSeverity::SuspendCapability {
                capabilities: vec![Capability::OutletCall(String::new())],
            }),
            threshold: 1,
            window: Duration::from_mins(1),
        };
        let err = rule.validate().unwrap_err();
        assert!(
            err.to_string().contains("OutletCall has empty outlet_id"),
            "should reject empty outlet_id, got: {err}"
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
    fn b2_suspend_custom_outlet_call_is_respected() {
        let rule = ConsequenceRule {
            trigger: ConsequenceTrigger::MessageVelocity,
            action: ConsequenceAction::Enforcement(EnforcementSeverity::SuspendCapability {
                capabilities: vec![Capability::OutletCall("calculator".to_owned())],
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
            &vec![Capability::OutletCall("calculator".to_owned())]
        );
    }

    #[test]
    fn b2_mixed_standard_and_custom_capabilities_are_respected() {
        let caps = vec![
            Capability::MessagesWrite,
            Capability::GovernanceVote,
            Capability::OutletCall("calculator".to_owned()),
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
