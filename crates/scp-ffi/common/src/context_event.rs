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
//!   rule name, reason, or DID can come from another member. Then `%`, `,`,
//!   `=`, and `|` are percent-encoded as `%25`, `%2C`, `%3D`, and `%7C`, so a
//!   value cannot add a key or a list item; `member_joined`'s role also
//!   encodes `:` as `%3A`, so it cannot add a segment. A reader splits a
//!   record, then percent-decodes each value.
//! - Byte arrays and payloads render as lowercase hex.
//! - Lists join with `|`.
//! - An `Option` field that holds `None` is left out, so an absent value never
//!   reads as a string spelled `none`.
//! - `WelcomeGenerated`'s MLS Welcome and Commit render as byte counts only,
//!   matching `RedactedBytes`'s own `Debug` impl, so key material never
//!   reaches an event string.

use std::fmt::Display;

use scp_protocol::context::membership::{ContextEvent, RedactedBytes};

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

/// Escapes one value: HTML-escapes it, then percent-encodes `%`, `,`, `=`,
/// and `|`, and also `:` when `colon` is set, so a value cannot add a key, a
/// list item, or (with `colon`) a segment to the string it sits in.
fn escape_value(value: &str, colon: bool) -> String {
    let escaped = html_escape_event_string(value);
    let mut out = String::with_capacity(escaped.len());
    for c in escaped.chars() {
        match c {
            '%' => out.push_str("%25"),
            ',' => out.push_str("%2C"),
            '=' => out.push_str("%3D"),
            '|' => out.push_str("%7C"),
            ':' if colon => out.push_str("%3A"),
            _ => out.push(c),
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

    fn text(mut self, key: &str, value: &impl AsRef<str>) -> Self {
        self.key(key);
        self.out.push_str(&escape_value(value.as_ref(), false));
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

    /// Writes `key` only when `value` yields an item, as a `&Option` does
    /// when it holds `Some`.
    fn opt_text<'a, T: AsRef<str> + 'a>(
        self,
        key: &str,
        value: impl IntoIterator<Item = &'a T>,
    ) -> Self {
        match value.into_iter().next() {
            Some(value) => self.text(key, value),
            None => self,
        }
    }

    /// Writes `key` only when `value` yields an item, as a `&Option` does
    /// when it holds `Some`.
    fn opt_num<'a, T: Display + 'a>(
        self,
        key: &str,
        value: impl IntoIterator<Item = &'a T>,
    ) -> Self {
        match value.into_iter().next() {
            Some(value) => self.num(key, value),
            None => self,
        }
    }

    fn list<T: Display>(mut self, key: &str, items: &[T]) -> Self {
        self.key(key);
        let rendered: Vec<String> = items
            .iter()
            .map(|item| escape_value(&item.to_string(), false))
            .collect();
        self.out.push_str(&rendered.join("|"));
        self
    }

    fn version<A: Display, B: Display>(self, key: &str, value: &(A, B)) -> Self {
        self.num(key, format_args!("{}.{}", value.0, value.1))
    }

    fn byte_len(self, key: &str, value: &RedactedBytes) -> Self {
        self.num(key, value.0.len())
    }

    fn finish(self) -> String {
        self.out
    }
}

/// Expands to one `match` over [`ContextEvent`] with no wildcard arm.
///
/// Plain arms come first, then one record arm per variant written as
/// `Variant { field: method, field: method as "key" }`. A record arm binds every
/// listed field, so a field missing from the list fails to compile, and
/// renders the fields in list order through the named [`Record`] method,
/// keyed by the field name or by `"key"` when `as "key"` follows.
macro_rules! render {
    (@key $field:ident) => {
        stringify!($field)
    };
    (@key $field:ident $key:literal) => {
        $key
    };
    (
        $event:expr, $r:ident;
        [$($pat:pat => $body:expr,)*]
        $($variant:ident { $($field:ident: $method:ident $(as $key:literal)?),* $(,)? })*
    ) => {
        match $event {
            $($pat => $body,)*
            $(ContextEvent::$variant { $($field),* } => {
                $r$(.$method(render!(@key $field $($key)?), $field))*.finish()
            })*
        }
    };
}

/// Renders `event` as the string every bridge hands an SDK.
///
/// The module documentation defines the format and value rules.
#[must_use]
pub fn context_event_wire_string(event: &ContextEvent) -> String {
    let r = Record::new(event);
    render! { event, r; [
        ContextEvent::MemberJoined { member_did, role_name } => format!(
            "member_joined:{}:{}",
            escape_value(member_did.as_ref(), false),
            escape_value(role_name, true),
        ),
        ContextEvent::MemberLeft { member_did } => {
            format!("member_left:{}", escape_value(member_did.as_ref(), false))
        },
        ContextEvent::SystemClose { initiator_did } => {
            format!("system_close:{}", escape_value(initiator_did.as_ref(), false))
        },
        ContextEvent::Expired => context_event_name(event),
        ]
        MessageSent { sender_did: text, sequence_number: num, payload: hex }
        MessageReceived { sender_did: text, payload: hex }
        MemberBlocked { blocked_did: text, author_did: text }
        MemberUnblocked { unblocked_did: text, author_did: text }
        AuthorBlocked { author_did: text }
        ReadAccessRevoked { did: text }
        ReadAccessRestored { did: text }
        WriteAccessRevoked { did: text }
        WriteAccessRestored { did: text }
        AccessKeyRevoked { did: text }
        CapabilitiesSuspended { did: text, capabilities: list }
        AccessKeyRestored { did: text, new_epoch: num }
        ContentKeysRotated { reason: opt_text }
        GovernanceActionExecuted {
            proposal_id: hex, action_summary: text, executor_did: text,
            resulting_epoch: opt_num, target_did: opt_text,
        }
        CeilingChangeNotification {
            new_capabilities: list, notified_at: num, effective_at: num, proposal_id: hex,
        }
        EconomicPolicyChangeNotification { notified_at: num, effective_at: num, proposal_id: hex }
        ExpiryFailed {
            reason: text, state_transitioned: num, mls_destroyed: num,
            sender_key_destroyed: num, event_logged: num,
        }
        VoteWithdrawn { proposal_id: hex, voter_did: text }
        ProposalTimedOut { proposal_id: hex, resolution_summary: text, resulting_epoch: opt_num }
        DeadlockDetected { condition_summary: text, resulting_epoch: opt_num }
        AppBound { app_did: text, capabilities: list }
        AppUnbound { app_did: text }
        DegradedMode {
            context_id: text, local_version: version, remote_version: version,
            unsupported_features: list,
        }
        WelcomeGenerated {
            context_id: text, creator_did: text, member_did: text,
            welcome_bytes: byte_len as "welcome_bytes_len", commit_bytes: byte_len as "commit_bytes_len",
        }
        BufferOverflow { dropped_count: num }
        SequenceGapDetected {
            sender_did: text as "sender", expected_sequence: num as "expected",
            first_delivered_sequence: num as "first_delivered", reason: text,
        }
        CheckpointCosignatureRequired {
            proposal_id: hex, required_signers: list, minimum_count: num, at_epoch: num,
        }
        ContextMigrationProposed {
            destination_context_id: text, reason: text, grace_period_secs: num,
            auto_invite: num, proposal_id: hex,
        }
        ContextMigrationStarted { destination_context_id: text, grace_period_end: num }
        ContextMigrationCancelled { original_proposal_id: hex }
        ContextTombstoned { destination_context_id: text, migration_proposal_id: hex }
        ConsequenceTriggered {
            member_did: text as "member", rule_index: num as "rule", trigger_type: text as "trigger",
            action_type: text as "action", context_id: text as "context",
        }
        ConsequenceEnforced {
            member_did: text as "member", action_type: text as "action", success: num,
            context_id: text as "context",
        }
        PaymentCaptureFailed { action: text, actor_did: text, error: text, cost: opt_num }
        PaymentReceived {
            receipt_id: hex, payer: text, payee: text, amount: num, action: text, anchored: num,
        }
        CommitBroadcastPending { operation: text, error: text, attempt: num }
        CommitBroadcastSucceeded { operation: text, attempts: num }
        EquivocationDetected {
            context_id: text as "context", remote_sender_did: text as "remote_sender",
            event_count: num, local_merkle_root: hex, remote_merkle_root: hex,
        }
        CommitBroadcastFailed { operation: text, reason: text, attempts: num }
        PseudonymAnnounced { member_did: text, pseudonym: hex }
    }
}

#[cfg(test)]
mod tests {
    use scp_did::DID;

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

    /// A member-supplied value cannot add a key, a list item, or a segment,
    /// and a value with no delimiter renders unchanged.
    #[test]
    fn member_values_cannot_forge_structure() {
        let event = ContextEvent::ContextMigrationProposed {
            destination_context_id: "real".to_owned(),
            reason: "up%grade,destination_context_id=evil|x".to_owned(),
            grace_period_secs: 60,
            auto_invite: true,
            proposal_id: [0; 32],
        };
        let wire = context_event_wire_string(&event);
        assert_eq!(
            wire.matches("destination_context_id=").count(),
            1,
            "got {wire}"
        );
        assert!(
            wire.contains("reason=up%25grade%2Cdestination_context_id%3Devil%7Cx,"),
            "got {wire}"
        );

        let degraded = ContextEvent::DegradedMode {
            context_id: "ctx".to_owned(),
            local_version: (1, 2),
            remote_version: (1, 3),
            unsupported_features: vec!["a|b".to_owned(), "c".to_owned()],
        };
        let degraded_wire = context_event_wire_string(&degraded);
        assert!(
            degraded_wire.ends_with("unsupported_features=a%7Cb|c"),
            "got {degraded_wire}"
        );

        let joined = ContextEvent::MemberJoined {
            member_did: did("did:dht:zBob"),
            role_name: "member:admin".to_owned(),
        };
        assert_eq!(
            context_event_wire_string(&joined),
            "member_joined:did:dht:zBob:member%3Aadmin"
        );
    }
}
