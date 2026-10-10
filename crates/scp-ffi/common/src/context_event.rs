//! One string rendering per `ContextEvent`, shared by every FFI bridge.
//!
//! `PyO3`'s receive pipeline and `context_drain_events`, and napi-rs and
//! `UniFFI` `context_drain_events`, each turn a [`ContextEvent`] into a string
//! for an SDK. Each bridge special-cased a few variants and rendered every
//! other variant with `format!("{event:?}")`, so most events reached an SDK as
//! a Rust `Debug` dump whose shape any derive or field change could alter.
//! Every bridge now calls [`context_event_wire_string`].
//!
//! [`context_event_wire_string`] matches every variant with no wildcard arm,
//! so a variant added in `scp-protocol` stops this crate from compiling until
//! someone renders it.
//!
//! Format: `<name>:<key>=<value>,<key>=<value>,...`, where `<name>` is
//! [`context_event_name`] and each key is the variant's Rust field name.
//! Four variants keep the formats `PyO3` already sent and SDK tests read:
//! `member_joined:<did>:<role>`, `member_left:<did>`, `system_close:<did>`,
//! and the shorter keys of `sequence_gap_detected`, `consequence_triggered`,
//! `consequence_enforced`, and `equivocation_detected`. `Expired` carries no
//! fields and renders as `expired`.
//!
//! Value rules:
//! - Every string, DID, and list item passes through
//!   [`html_escape_event_string`](crate::html_escape_event_string), because a
//!   rule name, reason, or DID can come from another member.
//! - Byte arrays and payloads render as lowercase hex.
//! - Lists join with `|`.
//! - An `Option` field that holds `None` is left out, so an absent value never
//!   reads as a string spelled `none`.
//! - `WelcomeGenerated`'s MLS Welcome and Commit render as byte counts only,
//!   matching `RedactedBytes`'s own `Debug` impl, so key material never
//!   reaches an event string.

use std::fmt::Display;

use scp_protocol::context::membership::ContextEvent;

use crate::html_escape_event_string;

/// Returns a snake-case wire name for `event`, which prefixes its rendering.
///
/// Converts [`ContextEvent::variant_name`], whose match names every variant
/// with no wildcard arm, so one table names each variant: `MemberJoined`
/// becomes `member_joined`.
#[must_use]
pub fn context_event_name(event: &ContextEvent) -> String {
    let variant = event.variant_name();
    let mut out = String::with_capacity(variant.len() + 4);
    for (i, c) in variant.char_indices() {
        if c.is_ascii_uppercase() {
            if i > 0 {
                out.push('_');
            }
            out.push(c.to_ascii_lowercase());
        } else {
            out.push(c);
        }
    }
    out
}

/// Builds one `<name>:<key>=<value>,...` record.
struct Record {
    out: String,
    empty: bool,
}

impl Record {
    fn new(event: &ContextEvent) -> Self {
        let mut out = context_event_name(event);
        out.push(':');
        Self { out, empty: true }
    }

    fn key(&mut self, key: &str) {
        if !self.empty {
            self.out.push(',');
        }
        self.empty = false;
        self.out.push_str(key);
        self.out.push('=');
    }

    fn text(mut self, key: &str, value: &str) -> Self {
        self.key(key);
        self.out.push_str(&html_escape_event_string(value));
        self
    }

    fn num(mut self, key: &str, value: impl Display) -> Self {
        self.key(key);
        self.out.push_str(&value.to_string());
        self
    }

    fn hex(mut self, key: &str, bytes: &[u8]) -> Self {
        self.key(key);
        self.out.push_str(&hex::encode(bytes));
        self
    }

    fn opt_text(self, key: &str, value: Option<&str>) -> Self {
        match value {
            Some(value) => self.text(key, value),
            None => self,
        }
    }

    fn opt_num(self, key: &str, value: Option<u64>) -> Self {
        match value {
            Some(value) => self.num(key, value),
            None => self,
        }
    }

    fn list<T: Display>(mut self, key: &str, items: &[T]) -> Self {
        self.key(key);
        let rendered: Vec<String> = items
            .iter()
            .map(|item| html_escape_event_string(&item.to_string()))
            .collect();
        self.out.push_str(&rendered.join("|"));
        self
    }

    fn finish(self) -> String {
        self.out
    }
}

/// Renders `event` as the string every bridge hands an SDK.
///
/// The module documentation defines the format and value rules.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn context_event_wire_string(event: &ContextEvent) -> String {
    let r = Record::new(event);
    match event {
        ContextEvent::MemberJoined {
            member_did,
            role_name,
        } => format!(
            "member_joined:{}:{}",
            html_escape_event_string(member_did.as_ref()),
            html_escape_event_string(role_name),
        ),
        ContextEvent::MemberLeft { member_did } => format!(
            "member_left:{}",
            html_escape_event_string(member_did.as_ref())
        ),
        ContextEvent::SystemClose { initiator_did } => format!(
            "system_close:{}",
            html_escape_event_string(initiator_did.as_ref())
        ),
        ContextEvent::Expired => context_event_name(event),
        ContextEvent::MessageSent {
            sender_did,
            sequence_number,
            payload,
        } => r
            .text("sender_did", sender_did.as_ref())
            .num("sequence_number", sequence_number)
            .hex("payload", payload)
            .finish(),
        ContextEvent::MessageReceived {
            sender_did,
            payload,
        } => r
            .text("sender_did", sender_did.as_ref())
            .hex("payload", payload)
            .finish(),
        ContextEvent::MemberBlocked {
            blocked_did,
            author_did,
        } => r
            .text("blocked_did", blocked_did.as_ref())
            .text("author_did", author_did.as_ref())
            .finish(),
        ContextEvent::MemberUnblocked {
            unblocked_did,
            author_did,
        } => r
            .text("unblocked_did", unblocked_did.as_ref())
            .text("author_did", author_did.as_ref())
            .finish(),
        ContextEvent::AuthorBlocked { author_did } => {
            r.text("author_did", author_did.as_ref()).finish()
        }
        ContextEvent::ReadAccessRevoked { did }
        | ContextEvent::ReadAccessRestored { did }
        | ContextEvent::WriteAccessRevoked { did }
        | ContextEvent::WriteAccessRestored { did }
        | ContextEvent::AccessKeyRevoked { did } => r.text("did", did.as_ref()).finish(),
        ContextEvent::CapabilitiesSuspended { did, capabilities } => r
            .text("did", did.as_ref())
            .list("capabilities", capabilities)
            .finish(),
        ContextEvent::AccessKeyRestored { did, new_epoch } => r
            .text("did", did.as_ref())
            .num("new_epoch", new_epoch)
            .finish(),
        ContextEvent::ContentKeysRotated { reason } => {
            r.opt_text("reason", reason.as_deref()).finish()
        }
        ContextEvent::GovernanceActionExecuted {
            proposal_id,
            action_summary,
            executor_did,
            resulting_epoch,
            target_did,
        } => r
            .hex("proposal_id", proposal_id)
            .text("action_summary", action_summary)
            .text("executor_did", executor_did.as_ref())
            .opt_num("resulting_epoch", *resulting_epoch)
            .opt_text("target_did", target_did.as_ref().map(AsRef::as_ref))
            .finish(),
        ContextEvent::CeilingChangeNotification {
            new_capabilities,
            notified_at,
            effective_at,
            proposal_id,
        } => r
            .list("new_capabilities", new_capabilities)
            .num("notified_at", notified_at)
            .num("effective_at", effective_at)
            .hex("proposal_id", proposal_id)
            .finish(),
        ContextEvent::EconomicPolicyChangeNotification {
            notified_at,
            effective_at,
            proposal_id,
        } => r
            .num("notified_at", notified_at)
            .num("effective_at", effective_at)
            .hex("proposal_id", proposal_id)
            .finish(),
        ContextEvent::ExpiryFailed {
            reason,
            state_transitioned,
            mls_destroyed,
            sender_key_destroyed,
            event_logged,
        } => r
            .text("reason", reason)
            .num("state_transitioned", state_transitioned)
            .num("mls_destroyed", mls_destroyed)
            .num("sender_key_destroyed", sender_key_destroyed)
            .num("event_logged", event_logged)
            .finish(),
        ContextEvent::VoteWithdrawn {
            proposal_id,
            voter_did,
        } => r
            .hex("proposal_id", proposal_id)
            .text("voter_did", voter_did.as_ref())
            .finish(),
        ContextEvent::ProposalTimedOut {
            proposal_id,
            resolution_summary,
            resulting_epoch,
        } => r
            .hex("proposal_id", proposal_id)
            .text("resolution_summary", resolution_summary)
            .opt_num("resulting_epoch", *resulting_epoch)
            .finish(),
        ContextEvent::DeadlockDetected {
            condition_summary,
            resulting_epoch,
        } => r
            .text("condition_summary", condition_summary)
            .opt_num("resulting_epoch", *resulting_epoch)
            .finish(),
        ContextEvent::AppBound {
            app_did,
            capabilities,
        } => r
            .text("app_did", app_did.as_ref())
            .list("capabilities", capabilities)
            .finish(),
        ContextEvent::AppUnbound { app_did } => r.text("app_did", app_did.as_ref()).finish(),
        ContextEvent::DegradedMode {
            context_id,
            local_version,
            remote_version,
            unsupported_features,
        } => r
            .text("context_id", context_id)
            .num(
                "local_version",
                format_args!("{}.{}", local_version.0, local_version.1),
            )
            .num(
                "remote_version",
                format_args!("{}.{}", remote_version.0, remote_version.1),
            )
            .list("unsupported_features", unsupported_features)
            .finish(),
        ContextEvent::WelcomeGenerated {
            context_id,
            creator_did,
            member_did,
            welcome_bytes,
            commit_bytes,
        } => r
            .text("context_id", context_id)
            .text("creator_did", creator_did.as_ref())
            .text("member_did", member_did.as_ref())
            .num("welcome_bytes_len", welcome_bytes.0.len())
            .num("commit_bytes_len", commit_bytes.0.len())
            .finish(),
        ContextEvent::BufferOverflow { dropped_count } => {
            r.num("dropped_count", dropped_count).finish()
        }
        ContextEvent::SequenceGapDetected {
            sender_did,
            expected_sequence,
            first_delivered_sequence,
            reason,
        } => r
            .text("sender", sender_did.as_ref())
            .num("expected", expected_sequence)
            .num("first_delivered", first_delivered_sequence)
            .text("reason", reason)
            .finish(),
        ContextEvent::CheckpointCosignatureRequired {
            proposal_id,
            required_signers,
            minimum_count,
            at_epoch,
        } => r
            .hex("proposal_id", proposal_id)
            .list("required_signers", required_signers)
            .num("minimum_count", minimum_count)
            .num("at_epoch", at_epoch)
            .finish(),
        ContextEvent::ContextMigrationProposed {
            destination_context_id,
            reason,
            grace_period_secs,
            auto_invite,
            proposal_id,
        } => r
            .text("destination_context_id", destination_context_id)
            .text("reason", reason)
            .num("grace_period_secs", grace_period_secs)
            .num("auto_invite", auto_invite)
            .hex("proposal_id", proposal_id)
            .finish(),
        ContextEvent::ContextMigrationStarted {
            destination_context_id,
            grace_period_end,
        } => r
            .text("destination_context_id", destination_context_id)
            .num("grace_period_end", grace_period_end)
            .finish(),
        ContextEvent::ContextMigrationCancelled {
            original_proposal_id,
        } => r.hex("original_proposal_id", original_proposal_id).finish(),
        ContextEvent::ContextTombstoned {
            destination_context_id,
            migration_proposal_id,
        } => r
            .text("destination_context_id", destination_context_id)
            .hex("migration_proposal_id", migration_proposal_id)
            .finish(),
        ContextEvent::ConsequenceTriggered {
            context_id,
            member_did,
            rule_index,
            trigger_type,
            action_type,
        } => r
            .text("member", member_did.as_ref())
            .num("rule", rule_index)
            .text("trigger", trigger_type)
            .text("action", action_type)
            .text("context", context_id)
            .finish(),
        ContextEvent::ConsequenceEnforced {
            context_id,
            member_did,
            action_type,
            success,
        } => r
            .text("member", member_did.as_ref())
            .text("action", action_type)
            .num("success", success)
            .text("context", context_id)
            .finish(),
        ContextEvent::PaymentCaptureFailed {
            action,
            actor_did,
            error,
            cost,
        } => r
            .text("action", action)
            .text("actor_did", actor_did.as_ref())
            .text("error", error)
            .opt_num("cost", *cost)
            .finish(),
        ContextEvent::PaymentReceived {
            receipt_id,
            payer,
            payee,
            amount,
            action,
            anchored,
        } => r
            .hex("receipt_id", receipt_id)
            .text("payer", payer.as_ref())
            .text("payee", payee.as_ref())
            .num("amount", amount)
            .text("action", action)
            .num("anchored", anchored)
            .finish(),
        ContextEvent::CommitBroadcastPending {
            operation,
            error,
            attempt,
        } => r
            .text("operation", operation)
            .text("error", error)
            .num("attempt", attempt)
            .finish(),
        ContextEvent::CommitBroadcastSucceeded {
            operation,
            attempts,
        } => r
            .text("operation", operation)
            .num("attempts", attempts)
            .finish(),
        ContextEvent::EquivocationDetected {
            context_id,
            remote_sender_did,
            event_count,
            local_merkle_root,
            remote_merkle_root,
        } => r
            .text("context", context_id)
            .text("remote_sender", remote_sender_did.as_ref())
            .num("event_count", event_count)
            .hex("local_merkle_root", local_merkle_root)
            .hex("remote_merkle_root", remote_merkle_root)
            .finish(),
        ContextEvent::CommitBroadcastFailed {
            operation,
            reason,
            attempts,
        } => r
            .text("operation", operation)
            .text("reason", reason)
            .num("attempts", attempts)
            .finish(),
        ContextEvent::PseudonymAnnounced {
            member_did,
            pseudonym,
        } => r
            .text("member_did", member_did.as_ref())
            .hex("pseudonym", pseudonym)
            .finish(),
    }
}

#[cfg(test)]
mod tests {
    use scp_did::DID;
    use scp_protocol::context::membership::RedactedBytes;

    use super::*;

    fn did(s: &str) -> DID {
        DID(s.to_owned())
    }

    /// Every rendering starts with its event's name and carries no `Debug`
    /// punctuation such as `MemberBlocked { blocked_did: DID("…") }`, which
    /// every bridge sent for these variants before.
    #[test]
    fn renderings_carry_no_debug_form() {
        let events = [
            ContextEvent::MemberBlocked {
                blocked_did: did("did:dht:zBob"),
                author_did: did("did:dht:zAlice"),
            },
            ContextEvent::GovernanceActionExecuted {
                proposal_id: [7; 32],
                action_summary: "ban".to_owned(),
                executor_did: did("did:dht:zAlice"),
                resulting_epoch: None,
                target_did: Some(did("did:dht:zBob")),
            },
            ContextEvent::DegradedMode {
                context_id: "ctx".to_owned(),
                local_version: (1, 2),
                remote_version: (1, 3),
                unsupported_features: vec!["a".to_owned(), "b".to_owned()],
            },
            ContextEvent::Expired,
        ];
        for event in &events {
            let wire = context_event_wire_string(event);
            assert!(wire.starts_with(&context_event_name(event)), "got {wire}");
            assert_ne!(wire, format!("{event:?}"));
            assert!(!wire.contains(" {") && !wire.contains("DID("), "got {wire}");
        }
    }

    #[test]
    fn renderings_are_pinned() {
        let cases = [
            (
                ContextEvent::MemberJoined {
                    member_did: did("did:dht:zBob"),
                    role_name: "member".to_owned(),
                },
                "member_joined:did:dht:zBob:member",
            ),
            (
                ContextEvent::MemberBlocked {
                    blocked_did: did("did:dht:zBob"),
                    author_did: did("did:dht:zAlice"),
                },
                "member_blocked:blocked_did=did:dht:zBob,author_did=did:dht:zAlice",
            ),
            (
                ContextEvent::GovernanceActionExecuted {
                    proposal_id: [0xab; 32],
                    action_summary: "ban".to_owned(),
                    executor_did: did("did:dht:zAlice"),
                    resulting_epoch: None,
                    target_did: Some(did("did:dht:zBob")),
                },
                "governance_action_executed:proposal_id=\
                 abababababababababababababababababababababababababababababababab,\
                 action_summary=ban,executor_did=did:dht:zAlice,target_did=did:dht:zBob",
            ),
            (
                ContextEvent::ContentKeysRotated { reason: None },
                "content_keys_rotated:",
            ),
            (
                ContextEvent::ConsequenceTriggered {
                    context_id: "ctx-1".to_owned(),
                    member_did: did("did:dht:zBob"),
                    rule_index: 1,
                    trigger_type: "velocity".to_owned(),
                    action_type: "mute".to_owned(),
                },
                "consequence_triggered:member=did:dht:zBob,rule=1,trigger=velocity,\
                 action=mute,context=ctx-1",
            ),
            (
                ContextEvent::ConsequenceEnforced {
                    context_id: "ctx-2".to_owned(),
                    member_did: did("did:dht:zAlice"),
                    action_type: "restrict_write".to_owned(),
                    success: false,
                },
                "consequence_enforced:member=did:dht:zAlice,action=restrict_write,\
                 success=false,context=ctx-2",
            ),
            (
                ContextEvent::DegradedMode {
                    context_id: "ctx".to_owned(),
                    local_version: (1, 2),
                    remote_version: (1, 3),
                    unsupported_features: vec!["a".to_owned(), "b".to_owned()],
                },
                "degraded_mode:context_id=ctx,local_version=1.2,remote_version=1.3,\
                 unsupported_features=a|b",
            ),
            (ContextEvent::Expired, "expired"),
        ];
        for (event, expected) in cases {
            assert_eq!(context_event_wire_string(&event), expected);
        }
    }

    /// A Welcome and a Commit render as byte counts, so MLS key material never
    /// reaches an event string.
    #[test]
    fn welcome_renders_byte_counts_only() {
        let event = ContextEvent::WelcomeGenerated {
            context_id: "ctx".to_owned(),
            creator_did: did("did:dht:zAlice"),
            member_did: did("did:dht:zBob"),
            welcome_bytes: RedactedBytes(vec![0xee; 5]),
            commit_bytes: RedactedBytes(vec![0xdd; 3]),
        };
        let wire = context_event_wire_string(&event);
        assert!(
            wire.ends_with("welcome_bytes_len=5,commit_bytes_len=3"),
            "got {wire}"
        );
        assert!(!wire.contains("ee") && !wire.contains("dd"), "got {wire}");
    }

    /// A member-supplied string cannot inject markup into an event string.
    #[test]
    fn member_strings_are_escaped() {
        let event = ContextEvent::MemberBlocked {
            blocked_did: did("<script>"),
            author_did: did("did:dht:zAlice"),
        };
        let wire = context_event_wire_string(&event);
        assert!(!wire.contains("<script>"), "got {wire}");
    }
}
