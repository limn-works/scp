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

/// Maximum length for custom trigger keys and capability names.
const MAX_CONSEQUENCE_STRING_LEN: usize = 256;
use crate::context::roles::{Capability, MAX_ROLE_NAME_LENGTH};
/// Maximum number of capabilities in a `Suspend` action.
const MAX_CAPABILITY_SUSPENSION_COUNT: usize = 32;

/// Characters forbidden in consequence string fields. These prevent
/// HTML injection (`<`, `>`, `&`, `"`, `'`) and are checked alongside
/// control characters.
const FORBIDDEN_CHARS: &str = "<>&\"'";

/// Canonical names + aliases for every unit variant of [`Capability`] that
/// may be listed in a [`ConsequenceAction::Suspend`].
///
/// Parametric variants ([`Capability::ToolInvoke`], [`Capability::Custom`]) are
/// **not** in this slice — they require a non-empty payload and are matched
/// by [`parse_suspension_capability`] via prefix detection.
///
/// The variant coverage of this slice is enforced by
/// [`canonical_suspension_capability_string`], which performs an exhaustive
/// match over [`Capability`] (no `_` arm) so a new variant becomes a compile
/// error here.
///
/// Aliases per variant:
/// - **canonical user-facing name** from [`Capability::name`]
///   (e.g. `"messages:write"`)
/// - **Debug-style identifier** matching the Rust variant
///   (e.g. `"MessagesWrite"`)
/// - For [`Capability::MessagesRead`] / [`Capability::MessagesWrite`], the
///   short forms `"read"` and `"write"` (legacy compatibility — pre-#1601
///   rules in deployed contexts still use these).
pub const VALID_SUSPENSION_CAPABILITIES: &[&str] = &[
    // MessagesRead
    "messages:read",
    "MessagesRead",
    "read",
    // MessagesWrite
    "messages:write",
    "MessagesWrite",
    "write",
    // ToolInvokeAll (the wildcard form of ToolInvoke)
    "tool:invoke:*",
    "ToolInvokeAll",
    // ToolRegister
    "tool:register",
    "ToolRegister",
    // MemberInvite
    "member:invite",
    "MemberInvite",
    // MemberRemove
    "member:remove",
    "MemberRemove",
    // RoleAssign
    "role:assign",
    "RoleAssign",
    // GovernancePropose
    "governance:propose",
    "GovernancePropose",
    // GovernanceVote
    "governance:vote",
    "GovernanceVote",
    // ContextClose
    "context:close",
    "ContextClose",
    // ChildContextCreate
    "context:child:create",
    "ChildContextCreate",
    // ToolInterface
    "tool:interface",
    "ToolInterface",
    // Bridging
    "bridging",
    "Bridging",
    // MediaVoice
    "media:voice",
    "MediaVoice",
    // MediaVideo
    "media:video",
    "MediaVideo",
    // MediaScreenShare
    "media:screen_share",
    "MediaScreenShare",
    // MemberBan
    "member:ban",
    "MemberBan",
    // MetadataEdit
    "metadata:edit",
    "MetadataEdit",
];

/// Returns a representative valid input string for `cap`.
///
/// **Compile-time exhaustiveness anchor.** This function exists solely so the
/// compiler enforces that every variant of [`Capability`] is considered as a
/// suspendable capability. The match has no `_` arm, so adding a new variant
/// fails compilation here, forcing the author to:
///
/// 1. Update [`VALID_SUSPENSION_CAPABILITIES`] (for unit variants), or
/// 2. Update [`parse_suspension_capability`] (for parametric variants), then
/// 3. Add a returned representative string here.
///
/// The string returned for unit variants is the canonical
/// [`Capability::name`] form. For parametric variants, a representative
/// non-empty payload is returned (e.g. `tool:invoke:example_tool`,
/// `custom:rate_limit_bypass`).
#[allow(dead_code)] // Compile-time exhaustiveness anchor; exercised by tests.
fn canonical_suspension_capability_string(cap: &Capability) -> String {
    match cap {
        Capability::MessagesRead => "messages:read".to_owned(),
        Capability::MessagesWrite => "messages:write".to_owned(),
        Capability::ToolInvoke(id) => format!("tool:invoke:{id}"),
        Capability::ToolInvokeAll => "tool:invoke:*".to_owned(),
        Capability::ToolRegister => "tool:register".to_owned(),
        Capability::MemberInvite => "member:invite".to_owned(),
        Capability::MemberRemove => "member:remove".to_owned(),
        Capability::RoleAssign => "role:assign".to_owned(),
        Capability::GovernancePropose => "governance:propose".to_owned(),
        Capability::GovernanceVote => "governance:vote".to_owned(),
        Capability::ContextClose => "context:close".to_owned(),
        Capability::ChildContextCreate => "context:child:create".to_owned(),
        Capability::ToolInterface => "tool:interface".to_owned(),
        Capability::Bridging => "bridging".to_owned(),
        Capability::MediaVoice => "media:voice".to_owned(),
        Capability::MediaVideo => "media:video".to_owned(),
        Capability::MediaScreenShare => "media:screen_share".to_owned(),
        Capability::MemberBan => "member:ban".to_owned(),
        Capability::MetadataEdit => "metadata:edit".to_owned(),
        Capability::Custom(name) => format!("custom:{name}"),
    }
}

/// Parses a suspension capability string into a typed [`Capability`].
///
/// Accepts every form listed in [`VALID_SUSPENSION_CAPABILITIES`] plus the
/// parametric forms:
///
/// - `"tool:invoke:<tool_id>"` — any non-empty `<tool_id>` (excluding `*`,
///   which maps to [`Capability::ToolInvokeAll`])
/// - `"custom:<name>"` — any non-empty `<name>`
///
/// Returns `None` for unrecognized strings, empty parametric payloads, or
/// for parametric strings with no payload (e.g. bare `"tool:invoke:"` or
/// bare `"custom:"`).
///
/// Used by both validation ([`ConsequenceRule::validate`]) and enforcement
/// (the runtime's `enforce_suspend` path) so the two layers cannot drift.
#[must_use]
#[allow(clippy::option_if_let_else)] // Nested if-let chain is clearer than map_or_else here.
pub fn parse_suspension_capability(s: &str) -> Option<Capability> {
    match s {
        "messages:read" | "MessagesRead" | "read" => Some(Capability::MessagesRead),
        "messages:write" | "MessagesWrite" | "write" => Some(Capability::MessagesWrite),
        "tool:invoke:*" | "ToolInvokeAll" => Some(Capability::ToolInvokeAll),
        "tool:register" | "ToolRegister" => Some(Capability::ToolRegister),
        "member:invite" | "MemberInvite" => Some(Capability::MemberInvite),
        "member:remove" | "MemberRemove" => Some(Capability::MemberRemove),
        "role:assign" | "RoleAssign" => Some(Capability::RoleAssign),
        "governance:propose" | "GovernancePropose" => Some(Capability::GovernancePropose),
        "governance:vote" | "GovernanceVote" => Some(Capability::GovernanceVote),
        "context:close" | "ContextClose" => Some(Capability::ContextClose),
        "context:child:create" | "ChildContextCreate" => Some(Capability::ChildContextCreate),
        "tool:interface" | "ToolInterface" => Some(Capability::ToolInterface),
        "bridging" | "Bridging" => Some(Capability::Bridging),
        "media:voice" | "MediaVoice" => Some(Capability::MediaVoice),
        "media:video" | "MediaVideo" => Some(Capability::MediaVideo),
        "media:screen_share" | "MediaScreenShare" => Some(Capability::MediaScreenShare),
        "member:ban" | "MemberBan" => Some(Capability::MemberBan),
        "metadata:edit" | "MetadataEdit" => Some(Capability::MetadataEdit),
        other => {
            if let Some(tail) = other.strip_prefix("tool:invoke:") {
                if tail.is_empty() {
                    None
                } else if tail == "*" {
                    Some(Capability::ToolInvokeAll)
                } else {
                    Some(Capability::ToolInvoke(tail.to_owned()))
                }
            } else if let Some(name) = other.strip_prefix("custom:") {
                if name.is_empty() {
                    None
                } else {
                    Some(Capability::Custom(name.to_owned()))
                }
            } else {
                None
            }
        }
    }
}

/// Returns true if `s` names a suspendable capability.
///
/// Wraps [`parse_suspension_capability`] for callers that need only the
/// boolean answer (e.g. validation paths).
#[must_use]
pub fn is_valid_suspension_capability(s: &str) -> bool {
    parse_suspension_capability(s).is_some()
}

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
// ConsequenceAction
// ---------------------------------------------------------------------------

/// The enforcement action taken when a consequence rule is triggered.
///
/// These actions are declared at context creation and are visible to all
/// participants before they join. See ADR-017.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConsequenceAction {
    /// Suspend specific capabilities for the subject. The suspended
    /// capabilities are identified by their `{resource}:{action}` names
    /// (matching the capability URI format from the UCAN module).
    ///
    /// **Known limitation:** Currently only `write`/`MessagesWrite`/
    /// `messages:write` and `read`/`MessagesRead`/`messages:read` are
    /// enforced. Other capability names are logged as unknown and ignored.
    /// Adding new enforced capabilities requires extending the match arms
    /// in `enforce_capability_suspension` in `governance.rs`.
    Suspend {
        /// The capabilities to suspend, identified by their capability names.
        capabilities: Vec<String>,
    },

    /// Suspend ALL member capabilities (application-level enforcement).
    ///
    /// This blocks read and write at the `send_message`/`deliver_incoming`
    /// gates but does **not** perform cryptographic exclusion (MLS group
    /// removal + sender key rotation). For full cryptographic exclusion,
    /// dispatch an `Eject` governance action instead.
    SuspendAll,

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
    /// Validates all user-supplied string fields in this rule.
    ///
    /// This should be called at the FFI boundary and in `ContextManager` before
    /// storing consequence rules. It rejects:
    ///
    /// - `Custom(key)`: key with control/HTML chars or length > 256
    /// - `Suspend { capabilities }`: individual cap name with control/HTML
    ///   chars or length > 256, or more than 32 capabilities
    /// - `AssignRole { to_role }`: role name with control/HTML chars or
    ///   length > 128
    ///
    /// Other trigger/action variants have no user-supplied strings and always
    /// pass validation.
    ///
    /// # Errors
    ///
    /// Returns [`ConsequenceValidationError`] if any string field contains
    /// forbidden characters (control chars, `<`, `>`, `&`, `"`, `'`), exceeds
    /// its maximum length, or if `Suspend` has more than 32 entries.
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
            ConsequenceAction::Suspend { capabilities } => {
                if capabilities.len() > MAX_CAPABILITY_SUSPENSION_COUNT {
                    return Err(ConsequenceValidationError(format!(
                        "Suspend has {} capabilities, max is {MAX_CAPABILITY_SUSPENSION_COUNT}",
                        capabilities.len()
                    )));
                }
                for (i, cap) in capabilities.iter().enumerate() {
                    validate_consequence_string(
                        cap,
                        &format!("Suspend[{i}]"),
                        MAX_CONSEQUENCE_STRING_LEN,
                    )?;
                    if !is_valid_suspension_capability(cap) {
                        return Err(ConsequenceValidationError(format!(
                            "Suspend[{i}] '{cap}' is not a recognized capability name; \
                             expected one of {VALID_SUSPENSION_CAPABILITIES:?}, \
                             or a parametric form 'tool:invoke:<id>' / 'custom:<name>'",
                        )));
                    }
                }
            }
            ConsequenceAction::AssignRole { to_role } => {
                validate_consequence_string(to_role, "AssignRole.to_role", MAX_ROLE_NAME_LENGTH)?;
            }
            ConsequenceAction::SuspendAll => { /* no user strings */ }
        }

        Ok(())
    }
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

    // -----------------------------------------------------------------------
    // 1. Message velocity triggers capability suspension
    // -----------------------------------------------------------------------

    #[test]
    fn message_velocity_triggers_capability_suspension() {
        let rules = vec![ConsequenceRule {
            trigger: ConsequenceTrigger::MessageVelocity,
            action: ConsequenceAction::Suspend {
                capabilities: vec!["messages:write".to_owned()],
            },
            threshold: 3,
            window: Duration::from_secs(60),
        }];

        let events = vec![
            make_event(EventType::MessageSent, "did:key:alice", 940, 0, vec![]),
            make_event(EventType::MessageSent, "did:key:alice", 950, 1, vec![]),
            make_event(EventType::MessageSent, "did:key:alice", 960, 2, vec![]),
        ];

        let result = evaluate_consequence_rules(&rules, &events, "did:key:alice", 1000);

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].rule_index, 0);
        assert_eq!(
            result[0].action,
            ConsequenceAction::Suspend {
                capabilities: vec!["messages:write".to_owned()]
            }
        );
        assert_eq!(result[0].evidence.len(), 3);
    }

    // -----------------------------------------------------------------------
    // 2. Tool rate threshold triggers access revocation
    // -----------------------------------------------------------------------

    #[test]
    fn tool_rate_triggers_suspend_all() {
        let rules = vec![ConsequenceRule {
            trigger: ConsequenceTrigger::ToolRateExceeded,
            action: ConsequenceAction::SuspendAll,
            threshold: 5,
            window: Duration::from_secs(120),
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
        assert_eq!(result[0].action, ConsequenceAction::SuspendAll);
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
            window: Duration::from_secs(300),
        }];

        let events = vec![
            make_event(
                EventType::GovernanceAction,
                "did:key:admin",
                800,
                0,
                b"did:key:alice".to_vec(),
            ),
            make_event(
                EventType::GovernanceAction,
                "did:key:moderator",
                900,
                1,
                b"did:key:alice".to_vec(),
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
            action: ConsequenceAction::SuspendAll,
            threshold: 2,
            window: Duration::from_secs(60),
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
            action: ConsequenceAction::SuspendAll,
            threshold: 3,
            window: Duration::from_secs(60),
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
            action: ConsequenceAction::SuspendAll,
            threshold: 3,
            window: Duration::from_secs(60),
        }];

        let events = vec![
            // Outside window (before now - 60 = 940)
            make_event(EventType::MessageSent, "did:key:alice", 900, 0, vec![]),
            make_event(EventType::MessageSent, "did:key:alice", 930, 1, vec![]),
            // Inside window
            make_event(EventType::MessageSent, "did:key:alice", 950, 2, vec![]),
            make_event(EventType::MessageSent, "did:key:alice", 960, 3, vec![]),
        ];

        let result = evaluate_consequence_rules(&rules, &events, "did:key:alice", 1000);

        // Only 2 events are within the window, threshold is 3 -> not triggered.
        assert!(result.is_empty());
    }

    // -----------------------------------------------------------------------
    // 7. Events from other actors are not counted for message velocity
    // -----------------------------------------------------------------------

    #[test]
    fn events_from_other_actors_not_counted_for_velocity() {
        let rules = vec![ConsequenceRule {
            trigger: ConsequenceTrigger::MessageVelocity,
            action: ConsequenceAction::SuspendAll,
            threshold: 3,
            window: Duration::from_secs(60),
        }];

        let events = vec![
            make_event(EventType::MessageSent, "did:key:alice", 950, 0, vec![]),
            make_event(EventType::MessageSent, "did:key:bob", 955, 1, vec![]),
            make_event(EventType::MessageSent, "did:key:alice", 960, 2, vec![]),
            make_event(EventType::MessageSent, "did:key:bob", 965, 3, vec![]),
        ];

        let result = evaluate_consequence_rules(&rules, &events, "did:key:alice", 1000);

        // Only 2 events from alice -> threshold 3 not met.
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
                action: ConsequenceAction::Suspend {
                    capabilities: vec!["messages:write".to_owned()],
                },
                threshold: 2,
                window: Duration::from_secs(60),
            },
            ConsequenceRule {
                trigger: ConsequenceTrigger::ToolRateExceeded,
                action: ConsequenceAction::SuspendAll,
                threshold: 1,
                window: Duration::from_secs(60),
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
    // 9. Empty event log triggers nothing
    // -----------------------------------------------------------------------

    #[test]
    fn empty_event_log_triggers_nothing() {
        let rules = vec![ConsequenceRule {
            trigger: ConsequenceTrigger::MessageVelocity,
            action: ConsequenceAction::SuspendAll,
            threshold: 1,
            window: Duration::from_secs(60),
        }];

        let result = evaluate_consequence_rules(&rules, &[], "did:key:alice", 1000);

        assert!(result.is_empty());
    }

    // -----------------------------------------------------------------------
    // 10. Empty rules list produces empty result
    // -----------------------------------------------------------------------

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
    // 11. Custom trigger matches governance events with matching payload
    // -----------------------------------------------------------------------

    #[test]
    fn custom_trigger_matches_governance_events_with_payload() {
        let rules = vec![ConsequenceRule {
            trigger: ConsequenceTrigger::Custom("spam-report".to_owned()),
            action: ConsequenceAction::AssignRole {
                to_role: "restricted".to_owned(),
            },
            threshold: 2,
            window: Duration::from_secs(300),
        }];

        let events = vec![
            make_event(
                EventType::GovernanceAction,
                "did:key:admin",
                800,
                0,
                b"spam-report".to_vec(),
            ),
            make_event(
                EventType::GovernanceAction,
                "did:key:moderator",
                900,
                1,
                b"spam-report".to_vec(),
            ),
            // Different payload -- should not match.
            make_event(
                EventType::GovernanceAction,
                "did:key:admin",
                950,
                2,
                b"other-action".to_vec(),
            ),
        ];

        let result = evaluate_consequence_rules(&rules, &events, "did:key:alice", 1000);

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].evidence.len(), 2);
    }

    // -----------------------------------------------------------------------
    // 12. Warning count ignores self-authored governance events
    // -----------------------------------------------------------------------

    #[test]
    fn warning_count_ignores_self_authored_governance_events() {
        let rules = vec![ConsequenceRule {
            trigger: ConsequenceTrigger::WarningCount,
            action: ConsequenceAction::AssignRole {
                to_role: "observer".to_owned(),
            },
            threshold: 2,
            window: Duration::from_secs(300),
        }];

        // Alice performs governance actions targeting herself -- these should
        // NOT count as warnings (actor == subject).
        let events = vec![
            make_event(
                EventType::GovernanceAction,
                "did:key:alice",
                800,
                0,
                b"did:key:alice".to_vec(),
            ),
            make_event(
                EventType::GovernanceAction,
                "did:key:admin",
                900,
                1,
                b"did:key:alice".to_vec(),
            ),
        ];

        let result = evaluate_consequence_rules(&rules, &events, "did:key:alice", 1000);

        // Only 1 warning from admin, threshold is 2 -> not triggered.
        assert!(result.is_empty());
    }

    // -----------------------------------------------------------------------
    // 13. Evidence contains correct event references
    // -----------------------------------------------------------------------

    #[test]
    fn evidence_contains_correct_event_references() {
        let rules = vec![ConsequenceRule {
            trigger: ConsequenceTrigger::MessageVelocity,
            action: ConsequenceAction::SuspendAll,
            threshold: 2,
            window: Duration::from_secs(60),
        }];

        let events = vec![
            make_event(EventType::MessageSent, "did:key:alice", 950, 7, vec![]),
            make_event(EventType::MessageSent, "did:key:alice", 960, 8, vec![]),
        ];

        let result = evaluate_consequence_rules(&rules, &events, "did:key:alice", 1000);

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].evidence.len(), 2);

        assert_eq!(result[0].evidence[0].event_sequence, 7);
        assert_eq!(result[0].evidence[0].timestamp, 950);
        assert_eq!(result[0].evidence[0].actor_did, "did:key:alice");
        assert_eq!(result[0].evidence[0].event_type, EventType::MessageSent);

        assert_eq!(result[0].evidence[1].event_sequence, 8);
        assert_eq!(result[0].evidence[1].timestamp, 960);
    }

    // -----------------------------------------------------------------------
    // 14. Tool rate excludes non-tool events
    // -----------------------------------------------------------------------

    #[test]
    fn tool_rate_excludes_non_tool_events() {
        let rules = vec![ConsequenceRule {
            trigger: ConsequenceTrigger::ToolRateExceeded,
            action: ConsequenceAction::SuspendAll,
            threshold: 3,
            window: Duration::from_secs(60),
        }];

        let events = vec![
            make_event(
                EventType::ToolInvoked,
                "did:key:alice",
                950,
                0,
                b"tool-a".to_vec(),
            ),
            // MessageSent should not count toward tool rate.
            make_event(EventType::MessageSent, "did:key:alice", 955, 1, vec![]),
            make_event(
                EventType::ToolInvoked,
                "did:key:alice",
                960,
                2,
                b"tool-b".to_vec(),
            ),
        ];

        let result = evaluate_consequence_rules(&rules, &events, "did:key:alice", 1000);

        // Only 2 ToolInvoked events, threshold is 3 -> not triggered.
        assert!(result.is_empty());
    }

    // -----------------------------------------------------------------------
    // 15. Window boundary: event at exact window start is included
    // -----------------------------------------------------------------------

    #[test]
    fn event_at_exact_window_boundary_is_included() {
        let rules = vec![ConsequenceRule {
            trigger: ConsequenceTrigger::MessageVelocity,
            action: ConsequenceAction::SuspendAll,
            threshold: 1,
            window: Duration::from_secs(60),
        }];

        // Event at exactly now - window (1000 - 60 = 940).
        let events = vec![make_event(
            EventType::MessageSent,
            "did:key:alice",
            940,
            0,
            vec![],
        )];

        let result = evaluate_consequence_rules(&rules, &events, "did:key:alice", 1000);

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].evidence.len(), 1);
    }

    // -----------------------------------------------------------------------
    // 16. Event at exact now is included
    // -----------------------------------------------------------------------

    #[test]
    fn event_at_exact_now_is_included() {
        let rules = vec![ConsequenceRule {
            trigger: ConsequenceTrigger::MessageVelocity,
            action: ConsequenceAction::SuspendAll,
            threshold: 1,
            window: Duration::from_secs(60),
        }];

        let events = vec![make_event(
            EventType::MessageSent,
            "did:key:alice",
            1000,
            0,
            vec![],
        )];

        let result = evaluate_consequence_rules(&rules, &events, "did:key:alice", 1000);

        assert_eq!(result.len(), 1);
    }

    // -----------------------------------------------------------------------
    // 17. Different windows per rule are respected
    // -----------------------------------------------------------------------

    #[test]
    fn different_windows_per_rule_are_respected() {
        let rules = vec![
            ConsequenceRule {
                trigger: ConsequenceTrigger::MessageVelocity,
                action: ConsequenceAction::Suspend {
                    capabilities: vec!["messages:write".to_owned()],
                },
                threshold: 2,
                // Short window: only events in [980, 1000]
                window: Duration::from_secs(20),
            },
            ConsequenceRule {
                trigger: ConsequenceTrigger::MessageVelocity,
                action: ConsequenceAction::SuspendAll,
                threshold: 3,
                // Longer window: events in [900, 1000]
                window: Duration::from_secs(100),
            },
        ];

        let events = vec![
            make_event(EventType::MessageSent, "did:key:alice", 920, 0, vec![]),
            make_event(EventType::MessageSent, "did:key:alice", 985, 1, vec![]),
            make_event(EventType::MessageSent, "did:key:alice", 995, 2, vec![]),
        ];

        let result = evaluate_consequence_rules(&rules, &events, "did:key:alice", 1000);

        // Rule 0: short window -> only events at 985, 995 = 2 >= 2 -> triggered
        // Rule 1: long window -> events at 920, 985, 995 = 3 >= 3 -> triggered
        assert_eq!(result.len(), 2);

        assert_eq!(result[0].rule_index, 0);
        assert_eq!(result[0].evidence.len(), 2);

        assert_eq!(result[1].rule_index, 1);
        assert_eq!(result[1].evidence.len(), 3);
    }

    // -----------------------------------------------------------------------
    // 18. Zero threshold triggers on any event count
    // -----------------------------------------------------------------------

    #[test]
    fn zero_threshold_rejected_by_validation() {
        // M5: threshold=0 is rejected at validation time.
        let rule = ConsequenceRule {
            trigger: ConsequenceTrigger::MessageVelocity,
            action: ConsequenceAction::SuspendAll,
            threshold: 0,
            window: Duration::from_secs(60),
        };
        assert!(rule.validate().is_err());
    }

    #[test]
    fn threshold_one_triggers_with_one_event() {
        // Replacement for old threshold=0 behavior: threshold=1 triggers
        // with a single matching event.
        let rules = vec![ConsequenceRule {
            trigger: ConsequenceTrigger::MessageVelocity,
            action: ConsequenceAction::SuspendAll,
            threshold: 1,
            window: Duration::from_secs(60),
        }];

        let events = vec![make_event(
            EventType::MessageSent,
            "did:key:alice",
            990,
            0,
            vec![],
        )];
        let result = evaluate_consequence_rules(&rules, &events, "did:key:alice", 1000);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].evidence.len(), 1);
    }

    // -----------------------------------------------------------------------
    // 19. Serialization roundtrip for consequence types
    // -----------------------------------------------------------------------

    #[test]
    fn consequence_rule_serialization_roundtrip() {
        let rule = ConsequenceRule {
            trigger: ConsequenceTrigger::MessageVelocity,
            action: ConsequenceAction::Suspend {
                capabilities: vec!["messages:write".to_owned()],
            },
            threshold: 10,
            window: Duration::from_secs(300),
        };

        let json = serde_json::to_string(&rule).unwrap();
        let deserialized: ConsequenceRule = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.trigger, ConsequenceTrigger::MessageVelocity);
        assert_eq!(deserialized.threshold, 10);
        assert_eq!(deserialized.window, Duration::from_secs(300));

        match deserialized.action {
            ConsequenceAction::Suspend { capabilities } => {
                assert_eq!(capabilities, vec!["messages:write".to_owned()]);
            }
            other => panic!("expected Suspend, got {other:?}"),
        }
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

    // -----------------------------------------------------------------------
    // 20. Validation: Custom trigger with script tag is rejected
    // -----------------------------------------------------------------------

    #[test]
    fn validate_rejects_custom_trigger_with_script_tag() {
        let rule = ConsequenceRule {
            trigger: ConsequenceTrigger::Custom("<script>alert(1)</script>".to_owned()),
            action: ConsequenceAction::SuspendAll,
            threshold: 1,
            window: Duration::from_secs(60),
        };
        let err = rule.validate().unwrap_err();
        assert!(
            err.to_string().contains("forbidden characters"),
            "error should mention forbidden characters, got: {err}"
        );
    }

    // -----------------------------------------------------------------------
    // 21. Validation: valid Custom trigger key is accepted
    // -----------------------------------------------------------------------

    #[test]
    fn validate_accepts_valid_custom_trigger() {
        let rule = ConsequenceRule {
            trigger: ConsequenceTrigger::Custom("valid_trigger_name".to_owned()),
            action: ConsequenceAction::SuspendAll,
            threshold: 1,
            window: Duration::from_secs(60),
        };
        assert!(rule.validate().is_ok());
    }

    // -----------------------------------------------------------------------
    // 22. Validation: Suspend with HTML in cap name is rejected
    // -----------------------------------------------------------------------

    #[test]
    fn validate_rejects_suspend_with_html() {
        let rule = ConsequenceRule {
            trigger: ConsequenceTrigger::MessageVelocity,
            action: ConsequenceAction::Suspend {
                capabilities: vec!["<img onerror=x>".to_owned()],
            },
            threshold: 1,
            window: Duration::from_secs(60),
        };
        let err = rule.validate().unwrap_err();
        assert!(
            err.to_string().contains("forbidden characters"),
            "error should mention forbidden characters, got: {err}"
        );
    }

    // -----------------------------------------------------------------------
    // 23. Validation: valid Suspend is accepted
    // -----------------------------------------------------------------------

    #[test]
    fn validate_accepts_valid_suspend() {
        let rule = ConsequenceRule {
            trigger: ConsequenceTrigger::MessageVelocity,
            action: ConsequenceAction::Suspend {
                capabilities: vec!["messages:write".to_owned()],
            },
            threshold: 1,
            window: Duration::from_secs(60),
        };
        assert!(rule.validate().is_ok());
    }

    // -----------------------------------------------------------------------
    // 24. Validation: valid AssignRole is accepted
    // -----------------------------------------------------------------------

    #[test]
    fn validate_accepts_valid_assign_role() {
        let rule = ConsequenceRule {
            trigger: ConsequenceTrigger::MessageVelocity,
            action: ConsequenceAction::AssignRole {
                to_role: "member".to_owned(),
            },
            threshold: 1,
            window: Duration::from_secs(60),
        };
        assert!(rule.validate().is_ok());
    }

    // -----------------------------------------------------------------------
    // 25. Validation: AssignRole with script tag is rejected
    // -----------------------------------------------------------------------

    #[test]
    fn validate_rejects_assign_role_with_script_tag() {
        let rule = ConsequenceRule {
            trigger: ConsequenceTrigger::MessageVelocity,
            action: ConsequenceAction::AssignRole {
                to_role: "<script>".to_owned(),
            },
            threshold: 1,
            window: Duration::from_secs(60),
        };
        let err = rule.validate().unwrap_err();
        assert!(
            err.to_string().contains("forbidden characters"),
            "error should mention forbidden characters, got: {err}"
        );
    }

    // -----------------------------------------------------------------------
    // 26. Validation: Custom trigger key exceeding max length is rejected
    // -----------------------------------------------------------------------

    #[test]
    fn validate_rejects_oversized_custom_trigger_key() {
        let long_key = "a".repeat(300);
        let rule = ConsequenceRule {
            trigger: ConsequenceTrigger::Custom(long_key),
            action: ConsequenceAction::SuspendAll,
            threshold: 1,
            window: Duration::from_secs(60),
        };
        let err = rule.validate().unwrap_err();
        assert!(
            err.to_string().contains("exceeds max length"),
            "error should mention max length, got: {err}"
        );
    }

    // -----------------------------------------------------------------------
    // 27. Validation: control characters in trigger key are rejected
    // -----------------------------------------------------------------------

    #[test]
    fn validate_rejects_control_chars_in_custom_trigger() {
        let rule = ConsequenceRule {
            trigger: ConsequenceTrigger::Custom("trigger\x00key".to_owned()),
            action: ConsequenceAction::SuspendAll,
            threshold: 1,
            window: Duration::from_secs(60),
        };
        let err = rule.validate().unwrap_err();
        assert!(
            err.to_string().contains("forbidden characters"),
            "error should mention forbidden characters, got: {err}"
        );
    }

    // -----------------------------------------------------------------------
    // 28. Validation: too many capabilities in Suspend rejected
    // -----------------------------------------------------------------------

    #[test]
    fn validate_rejects_too_many_capabilities() {
        let capabilities: Vec<String> = (0..33).map(|i| format!("cap:{i}")).collect();
        let rule = ConsequenceRule {
            trigger: ConsequenceTrigger::MessageVelocity,
            action: ConsequenceAction::Suspend { capabilities },
            threshold: 1,
            window: Duration::from_secs(60),
        };
        let err = rule.validate().unwrap_err();
        assert!(
            err.to_string().contains("33 capabilities"),
            "error should mention capability count, got: {err}"
        );
    }

    // -----------------------------------------------------------------------
    // 29. Validation: exactly 32 capabilities in Suspend is OK
    // -----------------------------------------------------------------------

    #[test]
    fn validate_accepts_max_capabilities() {
        // Use valid capability names repeated to fill the 32-entry limit.
        let valid_names: Vec<&str> = VALID_SUSPENSION_CAPABILITIES.to_vec();
        let capabilities: Vec<String> = (0..32)
            .map(|i| valid_names[i % valid_names.len()].to_owned())
            .collect();
        let rule = ConsequenceRule {
            trigger: ConsequenceTrigger::MessageVelocity,
            action: ConsequenceAction::Suspend { capabilities },
            threshold: 1,
            window: Duration::from_secs(60),
        };
        assert!(rule.validate().is_ok());
    }

    // -----------------------------------------------------------------------
    // 30. Validation: SuspendAll (no user strings) always passes
    // -----------------------------------------------------------------------

    #[test]
    fn validate_accepts_suspend_all() {
        let rule = ConsequenceRule {
            trigger: ConsequenceTrigger::MessageVelocity,
            action: ConsequenceAction::SuspendAll,
            threshold: 1,
            window: Duration::from_secs(60),
        };
        assert!(rule.validate().is_ok());
    }

    // -----------------------------------------------------------------------
    // 31. Validation: AssignRole exceeding max role name length rejected
    // -----------------------------------------------------------------------

    #[test]
    fn validate_rejects_oversized_assign_role_name() {
        let long_role = "r".repeat(129);
        let rule = ConsequenceRule {
            trigger: ConsequenceTrigger::MessageVelocity,
            action: ConsequenceAction::AssignRole { to_role: long_role },
            threshold: 1,
            window: Duration::from_secs(60),
        };
        let err = rule.validate().unwrap_err();
        assert!(
            err.to_string().contains("exceeds max length"),
            "error should mention max length, got: {err}"
        );
    }

    // -----------------------------------------------------------------------
    // 32. Validation: each HTML-special char is individually rejected
    // -----------------------------------------------------------------------

    #[test]
    fn validate_rejects_each_html_special_char() {
        for ch in ['<', '>', '&', '"', '\''] {
            let key = format!("trigger{ch}key");
            let rule = ConsequenceRule {
                trigger: ConsequenceTrigger::Custom(key),
                action: ConsequenceAction::SuspendAll,
                threshold: 1,
                window: Duration::from_secs(60),
            };
            assert!(
                rule.validate().is_err(),
                "should reject char '{ch}' in custom trigger key"
            );
        }
    }

    // -----------------------------------------------------------------------
    // M5: threshold:0 is rejected
    // -----------------------------------------------------------------------

    #[test]
    fn test_threshold_zero_rejected() {
        let rule = ConsequenceRule {
            trigger: ConsequenceTrigger::MessageVelocity,
            action: ConsequenceAction::SuspendAll,
            threshold: 0,
            window: Duration::from_secs(60),
        };
        let err = rule.validate().unwrap_err();
        assert!(
            err.to_string().contains("threshold must be > 0"),
            "expected threshold rejection, got: {err}"
        );
    }

    // -----------------------------------------------------------------------
    // M6: Custom("") is rejected
    // -----------------------------------------------------------------------

    #[test]
    fn test_empty_custom_key_rejected() {
        let rule = ConsequenceRule {
            trigger: ConsequenceTrigger::Custom(String::new()),
            action: ConsequenceAction::SuspendAll,
            threshold: 1,
            window: Duration::from_secs(60),
        };
        let err = rule.validate().unwrap_err();
        assert!(
            err.to_string().contains("must not be empty"),
            "expected empty key rejection, got: {err}"
        );
    }

    // -----------------------------------------------------------------------
    // Structured JSON payload tests (H11-H12)
    // -----------------------------------------------------------------------

    /// `WarningCount` trigger fires when structured JSON payloads carry
    /// `target_did` that matches the subject.
    #[test]
    fn test_warning_count_trigger_fires() {
        let rules = vec![ConsequenceRule {
            trigger: ConsequenceTrigger::WarningCount,
            action: ConsequenceAction::AssignRole {
                to_role: "observer".to_owned(),
            },
            threshold: 2,
            window: Duration::from_secs(300),
        }];

        // Build structured JSON payloads targeting alice.
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

        assert_eq!(
            result.len(),
            1,
            "WarningCount should fire with JSON payloads"
        );
        assert_eq!(
            result[0].action,
            ConsequenceAction::AssignRole {
                to_role: "observer".to_owned()
            }
        );
        assert_eq!(result[0].evidence.len(), 2);
    }

    /// `WarningCount` does NOT fire when JSON payload targets a different DID.
    #[test]
    fn test_warning_count_wrong_target_no_fire() {
        let rules = vec![ConsequenceRule {
            trigger: ConsequenceTrigger::WarningCount,
            action: ConsequenceAction::SuspendAll,
            threshold: 1,
            window: Duration::from_secs(300),
        }];

        let payload =
            serde_json::to_vec(&serde_json::json!({"target_did": "did:key:bob"})).unwrap();

        let events = vec![make_event(
            EventType::GovernanceAction,
            "did:key:admin",
            800,
            0,
            payload,
        )];

        let result = evaluate_consequence_rules(&rules, &events, "did:key:alice", 1000);
        assert!(
            result.is_empty(),
            "WarningCount should not fire when target_did != subject"
        );
    }

    // -----------------------------------------------------------------------
    // Validation: unrecognized capability name is rejected
    // -----------------------------------------------------------------------

    #[test]
    fn validate_rejects_unknown_capability_name() {
        let rule = ConsequenceRule {
            trigger: ConsequenceTrigger::MessageVelocity,
            action: ConsequenceAction::Suspend {
                capabilities: vec!["fly_to_moon".into()],
            },
            threshold: 1,
            window: Duration::from_secs(60),
        };
        let err = rule.validate().unwrap_err();
        assert!(
            err.to_string().contains("not a recognized capability name"),
            "error should mention unrecognized capability, got: {err}"
        );
    }

    // -----------------------------------------------------------------------
    // Validation: all valid suspension capability names are accepted
    // -----------------------------------------------------------------------

    #[test]
    fn validate_accepts_all_valid_suspension_capabilities() {
        for &cap_name in VALID_SUSPENSION_CAPABILITIES {
            let rule = ConsequenceRule {
                trigger: ConsequenceTrigger::MessageVelocity,
                action: ConsequenceAction::Suspend {
                    capabilities: vec![cap_name.to_owned()],
                },
                threshold: 1,
                window: Duration::from_secs(60),
            };
            assert!(
                rule.validate().is_ok(),
                "valid capability '{cap_name}' should be accepted"
            );
        }
    }

    // -----------------------------------------------------------------------
    // Exhaustive coverage: every Capability variant is suspendable
    // -----------------------------------------------------------------------

    /// Returns one representative of every variant of [`Capability`].
    ///
    /// Mirrors the exhaustive match in
    /// `canonical_suspension_capability_string` so the compiler keeps both
    /// in sync. If a new variant is added to [`Capability`], compilation
    /// fails here, forcing the author to add coverage for the new variant
    /// in the suspension validation paths as well.
    fn capability_variant_examples() -> Vec<Capability> {
        // Exhaustive (no `_` arm) — a new variant of Capability becomes a
        // compile error here.
        #[allow(clippy::no_effect_underscore_binding)]
        let _exhaustiveness_check = |c: &Capability| match c {
            Capability::MessagesRead
            | Capability::MessagesWrite
            | Capability::ToolInvoke(_)
            | Capability::ToolInvokeAll
            | Capability::ToolRegister
            | Capability::MemberInvite
            | Capability::MemberRemove
            | Capability::RoleAssign
            | Capability::GovernancePropose
            | Capability::GovernanceVote
            | Capability::ContextClose
            | Capability::ChildContextCreate
            | Capability::ToolInterface
            | Capability::Bridging
            | Capability::MediaVoice
            | Capability::MediaVideo
            | Capability::MediaScreenShare
            | Capability::MemberBan
            | Capability::MetadataEdit
            | Capability::Custom(_) => (),
        };

        vec![
            Capability::MessagesRead,
            Capability::MessagesWrite,
            Capability::ToolInvoke("example_tool".to_owned()),
            Capability::ToolInvokeAll,
            Capability::ToolRegister,
            Capability::MemberInvite,
            Capability::MemberRemove,
            Capability::RoleAssign,
            Capability::GovernancePropose,
            Capability::GovernanceVote,
            Capability::ContextClose,
            Capability::ChildContextCreate,
            Capability::ToolInterface,
            Capability::Bridging,
            Capability::MediaVoice,
            Capability::MediaVideo,
            Capability::MediaScreenShare,
            Capability::MemberBan,
            Capability::MetadataEdit,
            Capability::Custom("rate_limit_bypass".to_owned()),
        ]
    }

    #[test]
    fn every_capability_variant_is_suspendable() {
        for cap in capability_variant_examples() {
            let canonical = canonical_suspension_capability_string(&cap);
            assert!(
                is_valid_suspension_capability(&canonical),
                "canonical form {canonical:?} for {cap:?} must be a valid suspension capability"
            );
            // The string round-trips back to the same typed Capability.
            assert_eq!(
                parse_suspension_capability(&canonical),
                Some(cap.clone()),
                "{canonical:?} should parse back to {cap:?}"
            );
            // And a Suspend rule with that capability validates.
            let rule = ConsequenceRule {
                trigger: ConsequenceTrigger::MessageVelocity,
                action: ConsequenceAction::Suspend {
                    capabilities: vec![canonical.clone()],
                },
                threshold: 1,
                window: Duration::from_secs(60),
            };
            assert!(
                rule.validate().is_ok(),
                "Suspend rule with {canonical:?} for variant {cap:?} should validate"
            );
        }
    }

    #[test]
    fn parse_suspension_capability_handles_aliases() {
        assert_eq!(
            parse_suspension_capability("read"),
            Some(Capability::MessagesRead)
        );
        assert_eq!(
            parse_suspension_capability("MessagesRead"),
            Some(Capability::MessagesRead)
        );
        assert_eq!(
            parse_suspension_capability("messages:read"),
            Some(Capability::MessagesRead)
        );
        assert_eq!(
            parse_suspension_capability("write"),
            Some(Capability::MessagesWrite)
        );
        assert_eq!(
            parse_suspension_capability("Bridging"),
            Some(Capability::Bridging)
        );
        assert_eq!(
            parse_suspension_capability("bridging"),
            Some(Capability::Bridging)
        );
    }

    #[test]
    fn parse_suspension_capability_handles_parametric_forms() {
        assert_eq!(
            parse_suspension_capability("tool:invoke:my_tool"),
            Some(Capability::ToolInvoke("my_tool".to_owned()))
        );
        assert_eq!(
            parse_suspension_capability("tool:invoke:*"),
            Some(Capability::ToolInvokeAll)
        );
        assert_eq!(
            parse_suspension_capability("custom:rate_limit_bypass"),
            Some(Capability::Custom("rate_limit_bypass".to_owned()))
        );
    }

    #[test]
    fn parse_suspension_capability_rejects_empty_parametric_payload() {
        assert_eq!(parse_suspension_capability("tool:invoke:"), None);
        assert_eq!(parse_suspension_capability("custom:"), None);
    }

    #[test]
    fn parse_suspension_capability_rejects_unknown_strings() {
        assert_eq!(parse_suspension_capability(""), None);
        assert_eq!(parse_suspension_capability("fly_to_moon"), None);
        assert_eq!(parse_suspension_capability("MESSAGES:READ"), None);
    }

    #[test]
    fn validate_accepts_parametric_tool_invoke_capability() {
        let rule = ConsequenceRule {
            trigger: ConsequenceTrigger::MessageVelocity,
            action: ConsequenceAction::Suspend {
                capabilities: vec!["tool:invoke:calculator".to_owned()],
            },
            threshold: 1,
            window: Duration::from_secs(60),
        };
        assert!(rule.validate().is_ok());
    }

    #[test]
    fn validate_accepts_custom_capability() {
        let rule = ConsequenceRule {
            trigger: ConsequenceTrigger::MessageVelocity,
            action: ConsequenceAction::Suspend {
                capabilities: vec!["custom:my_app_action".to_owned()],
            },
            threshold: 1,
            window: Duration::from_secs(60),
        };
        assert!(rule.validate().is_ok());
    }

    #[test]
    fn validate_rejects_empty_tool_invoke_payload() {
        let rule = ConsequenceRule {
            trigger: ConsequenceTrigger::MessageVelocity,
            action: ConsequenceAction::Suspend {
                capabilities: vec!["tool:invoke:".to_owned()],
            },
            threshold: 1,
            window: Duration::from_secs(60),
        };
        let err = rule.validate().unwrap_err();
        assert!(
            err.to_string().contains("not a recognized capability name"),
            "should reject empty tool:invoke payload, got: {err}"
        );
    }
}
