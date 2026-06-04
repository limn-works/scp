//! Shared event-log filtering used by all FFI bridges.
//!
//! Canonical filter semantics for `ContextManager::event_log_entries`
//! queries live here so PyO3/NAPI/UniFFI stay in lock-step by
//! construction rather than by parity-harness enforcement.
//!
//! The five filter clauses — `after_sequence`, `before_sequence`,
//! `event_type`, `actor_did`, `limit` — were previously open-coded
//! identically in three bridges. The cross-bridge parity harness
//! (`OP_EVENT_LOG_FILTERED`, ADR-046) is the runtime anchor; this
//! helper is the structural anchor.
//!
//! Semantics (`PyO3` reference — see `scp-ffi/src/event_log.rs::query_manager_entries`):
//!
//! 1. `after_sequence`: **exclusive** lower bound (entries with
//!    `seq <= after` are skipped).
//! 2. `before_sequence`: **exclusive** upper bound (entries with
//!    `seq >= before` are skipped).
//! 3. `event_type`: equality match on `EventLogEntry::event`.
//! 4. `actor_did`: equality match on `EventLogEntry::actor_did`.
//! 5. `limit`: applied **after** the entry is accepted (push-then-check);
//!    once `out.len() >= lim`, iteration breaks.
//!
//! Sequence numbers are 0-indexed positions within the input slice
//! (`idx as u64`). Mapping `EventLogEntry` → native bridge struct
//! (`PyEvent` / `NapiEvent` / `UniFFI` `Event`) is the caller's
//! responsibility — the helper only encodes the filter contract.

use scp_core::context::providers::event_log::EventLogEntry;

/// The five canonical filter clauses applied to manager event-log entries.
///
/// Borrowed fields so callers can pass string slices from their own
/// parsed filter JSON without extra allocation. All fields are optional
/// — a default-constructed `EventLogFilter` matches every entry.
#[derive(Debug, Default, Clone, Copy)]
pub struct EventLogFilter<'a> {
    /// Exclusive lower bound on sequence number.
    pub after_sequence: Option<u64>,
    /// Exclusive upper bound on sequence number.
    pub before_sequence: Option<u64>,
    /// Equality match on `EventLogEntry::event`.
    pub event_type: Option<&'a str>,
    /// Equality match on `EventLogEntry::actor_did`.
    pub actor_did: Option<&'a str>,
    /// Maximum number of entries to return. Applied post-push.
    pub limit: Option<usize>,
}

/// Applies the canonical filter contract to a slice of entries.
///
/// Returns `(sequence_number, entry)` pairs. Each bridge maps the pair
/// into its own native `Event`/`NapiEvent`/`PyEvent` struct — this
/// helper does not touch bridge-specific fields (e.g. `payload_json`
/// encoding, hex formatting, timestamp-f64 coercion).
///
/// Iteration order matches the input slice; the returned `Vec` is
/// allocated with capacity equal to `limit` when set (saves one
/// reallocation in the common "limit=N" path).
#[must_use]
pub fn filter_manager_entries<'a>(
    entries: &'a [EventLogEntry],
    filter: &EventLogFilter<'a>,
) -> Vec<(u64, &'a EventLogEntry)> {
    let mut out: Vec<(u64, &'a EventLogEntry)> = filter
        .limit
        .map_or_else(Vec::new, |lim| Vec::with_capacity(lim.min(entries.len())));
    for (idx, entry) in entries.iter().enumerate() {
        let seq = idx as u64;
        if let Some(after) = filter.after_sequence
            && seq <= after
        {
            continue;
        }
        if let Some(before) = filter.before_sequence
            && seq >= before
        {
            continue;
        }
        if let Some(et) = filter.event_type
            && entry.event != et
        {
            continue;
        }
        if let Some(did) = filter.actor_did
            && entry.actor_did != did
        {
            continue;
        }
        out.push((seq, entry));
        if let Some(lim) = filter.limit
            && out.len() >= lim
        {
            break;
        }
    }
    out
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    fn entry(event: &str, actor: &str) -> EventLogEntry {
        EventLogEntry {
            event: event.to_owned(),
            actor_did: actor.to_owned(),
            timestamp: 0,
            prev_hash: [0u8; 32],
            hash: [0u8; 32],
            payload: None,
        }
    }

    fn corpus() -> Vec<EventLogEntry> {
        vec![
            entry("ContextCreated", "did:example:alice"),
            entry("MemberJoined", "did:example:bob"),
            entry("MessageSent", "did:example:alice"),
            entry("MessageSent", "did:example:bob"),
            entry("MemberLeft", "did:example:alice"),
        ]
    }

    #[test]
    fn empty_filter_returns_all() {
        let c = corpus();
        let out = filter_manager_entries(&c, &EventLogFilter::default());
        assert_eq!(out.len(), c.len());
        assert_eq!(out[0].0, 0);
        assert_eq!(out[4].0, 4);
    }

    #[test]
    fn after_sequence_is_exclusive() {
        let c = corpus();
        let out = filter_manager_entries(
            &c,
            &EventLogFilter {
                after_sequence: Some(1),
                ..Default::default()
            },
        );
        // seq 0 and 1 are excluded.
        assert_eq!(out.len(), 3);
        assert_eq!(out[0].0, 2);
    }

    #[test]
    fn before_sequence_is_exclusive() {
        let c = corpus();
        let out = filter_manager_entries(
            &c,
            &EventLogFilter {
                before_sequence: Some(3),
                ..Default::default()
            },
        );
        // seq 3 and 4 are excluded.
        assert_eq!(out.len(), 3);
        assert_eq!(out[2].0, 2);
    }

    #[test]
    fn event_type_equality() {
        let c = corpus();
        let out = filter_manager_entries(
            &c,
            &EventLogFilter {
                event_type: Some("MessageSent"),
                ..Default::default()
            },
        );
        assert_eq!(out.len(), 2);
        assert!(out.iter().all(|(_, e)| e.event == "MessageSent"));
    }

    #[test]
    fn actor_did_equality() {
        let c = corpus();
        let out = filter_manager_entries(
            &c,
            &EventLogFilter {
                actor_did: Some("did:example:alice"),
                ..Default::default()
            },
        );
        assert_eq!(out.len(), 3);
        assert!(out.iter().all(|(_, e)| e.actor_did == "did:example:alice"));
    }

    #[test]
    fn limit_is_post_push() {
        let c = corpus();
        let out = filter_manager_entries(
            &c,
            &EventLogFilter {
                limit: Some(2),
                ..Default::default()
            },
        );
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].0, 0);
        assert_eq!(out[1].0, 1);
    }

    #[test]
    fn all_clauses_compose() {
        let c = corpus();
        let out = filter_manager_entries(
            &c,
            &EventLogFilter {
                after_sequence: Some(0),
                before_sequence: Some(4),
                event_type: Some("MessageSent"),
                actor_did: Some("did:example:bob"),
                limit: Some(10),
            },
        );
        // seq 1..=3, event==MessageSent, actor==bob → seq 3 only.
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].0, 3);
    }

    #[test]
    fn limit_zero_returns_empty() {
        let c = corpus();
        let out = filter_manager_entries(
            &c,
            &EventLogFilter {
                limit: Some(0),
                ..Default::default()
            },
        );
        // limit=0 is post-push: first entry pushes, then len==1 >= 0 breaks.
        // Matches legacy PyO3/NAPI/UniFFI behavior (none of them special-cased zero).
        assert_eq!(out.len(), 1);
    }
}
