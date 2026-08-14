---
name: pr2234-broadcast-kea-counter
description: PR #2234 review — checkpoint_events_since counter tests have zero mutation power; fail-closed KEA loop makes committed governance actions retryable; Merkle sort fixed at symptom sites not root
metadata:
  type: project
---

# PR #2234 (fix/rotate-content-keys-review-followup @ 432691d70) — pass-1 findings

## Verified facts (re-usable)

- **`checkpoint_events_since` is a checkpoint *cadence* trigger only.**
  `queries_helpers.rs:691` `events_due = events_since >= 50`; `time_due = events_since > 0 && now - last >= 600`. The
  checkpoint payload itself reads the REAL count from `event_log_entries(...).len()` in `build_checkpoint`. So an
  off-by-N in the counter shifts *when* a checkpoint fires — it never corrupts a Merkle root. Grade counter drift
  MEDIUM/LOW, not CRITICAL.

- **Mutation-test result (2026-08-03):** deleting all 36 occurrences of
  `*cell.class_c_view().checkpoint_events_since_mut() += 1;` in
  `crates/scp-runtime/src/context/governance_helpers.rs` leaves **all 69 tests in
  `crates/scp-runtime/tests/governance_integration.rs` green**, including the six new
  `*_counter_*` / `*_bumps_checkpoint_counter_*` tests. All 21 mentions of `checkpoint_events_since` in that
  test file are comments/strings — zero code reads it. Any future "counter" test that only counts event-log
  leaves is vacuous; require a `#[cfg(feature = "testing")]` reader (pattern exists:
  `queries_helpers.rs` `remaining_budget_for_test`, `velocity_for_test`).

- **`execute_governance_action` rolls back the `executed_proposals` replay marker on ANY dispatch `Err`**
  (`governance_helpers.rs` ~5685, `token.discharge_with(... .executed_proposals.remove(...))`), explicitly
  "so the proposal can be retried". Consequence: converting any post-Class-S-commit event-log append to
  fail-closed makes an already-durably-committed, NON-idempotent action retryable — retry double-advances
  broadcast epochs and duplicates leaves. Always check this rollback when reviewing best-effort→fail-closed
  conversions in `execute_*` leaf helpers.

- **`BroadcastContext.authors` is `HashMap<String, AuthorState>` with key == `AuthorState.author_did`**
  (guaranteed by `add_author`; NOT structurally guaranteed by `from_snapshot`, which copies key and
  `snap.author_did` independently). `rotate_all_author_keys` sorts on the VALUE field `author.author_did`;
  `governance_ban_subscriber` and `unsubscribe` sort on the map KEY. Only the key form is collision-free by
  construction.

- **`bounded_reply_await`** lives at `crates/scp-runtime/src/context/actor/handle.rs:117`. Mechanics only:
  `tokio::time::timeout(REPLY_TIMEOUT /* 2 min */, rx)` → `Ok/Dropped/Elapsed`. **No rate limiter inside** —
  `hard_rate_limit_allow(&bounded_reply_await(...))` at supervisor.rs:11663 is that one call site's own
  disposition. ~41 call sites; the convention is
  `.map_err(|_| ContextError::TransportFailed("Supervisor::<method> — actor reply channel closed"))?`.
  The "channel closed" wording is inaccurate for the `Elapsed` arm at every site (pre-existing, uniform).

## Still-unfixed instances of the same counter defect class (as of 432691d70)

`.await?` inside a leaf-append loop with the counter bump AFTER the loop → a mid-loop append failure
under-counts every already-durable leaf:
- `governance_helpers.rs:434` `withdraw_governance_vote` (`+= event_count`)
- `governance_helpers.rs:4085` and `:4414` conflict-event loops (`+= conflict_event_count`)

## Doc/comment traps found in this area

- `broadcast/mod.rs` `rotate_all_author_keys` param doc still claims `timestamp_ms` is "used by the caller for
  event-log ordering" while the field doc (changed by this PR) says "Currently unconsumed" and
  `execute_rotate_content_keys` says "not used here". `BroadcastKeyEpochAdvance` is produced only by
  `rotate_all_author_keys` and its `.timestamp` is read by nothing in `crates/`.
- There is **no `GovernanceProposed` EventType** anywhere in `crates/scp-runtime` or `crates/scp-event-log`.
  Tests that subtract "GovernanceProposed (always 1)" are actually subtracting the
  `GovernanceActionExecuted` leaf appended by `finalize_governance_action` (which bumps the counter by 1).
