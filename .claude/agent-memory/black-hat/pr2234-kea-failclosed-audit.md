---
name: pr2234-kea-failclosed-audit
description: Adversarial findings on PR #2234 (broadcast KEA fail-closed + Merkle sort determinism + testing seed seam), commit 432691d70
metadata:
  type: project
---

# PR #2234 (`fix/rotate-content-keys-review-followup`, commit 432691d70) — black-hat pass 1

**Why:** PR converted broadcast `KeyEpochAdvance` (KEA) event-log leaves from best-effort to
fail-closed on the governance-ban / RotateContentKeys paths, added `author_did` sorting for
Merkle determinism, and added a `#[cfg(feature = "testing")]` `SeedBroadcastAuthor` actor command.

**How to apply:** These are structural attack surfaces in `scp-runtime` governance execution.
Re-check them on any future change to `governance_helpers.rs` KEA loops or broadcast key rotation.

## Load-bearing mechanisms discovered

- `execute_governance_action` (`governance_helpers.rs:5557`) **rolls back the
  `executed_proposals` replay marker on ANY dispatch error** and persists the removal
  fail-closed, explicitly "so the proposal can be retried". Its premise is that dispatch
  failures happen BEFORE durable side effects. Any `?` placed AFTER a `commit_class_s_keep`
  or after a durable event-log append violates that premise and makes an already-applied
  governance action re-executable.
- On the dispatch-error path `finalize_governance_action` never runs → no
  `GovernanceActionExecuted` leaf, while the action's effect leaves ARE durable.
- No batch/atomic multi-leaf append exists anywhere (`scp-event-log` has none). A per-leaf
  `?` loop cannot be atomic; partial emission is already durable when the error surfaces.
- `checkpoint_events_since` gates §9.9.3 checkpoints at 50 events
  (`queries_helpers.rs::create_checkpoint_if_due_view`).
- No failure-injecting `ContextEventLogProvider` test double exists in the repo — every
  fail-closed KEA branch is untested.
- `crates/scp-runtime/Cargo.toml` documents the precedent: authority-escalation seams
  (`saga-witness-test-mint`, `outlet-capability-test-grant`) get their OWN feature, NOT
  plain `testing`, because `scp-ffi/testing → dep:scp-testing → scp-core/testing →
  scp-runtime/testing` compiles `testing` into bridge builds.
- `BroadcastContext::add_author` grants `messages:write` (`can_write`) AND implicit read of
  every author's content (`can_read` author short-circuit) with no ceiling/capability check.
- `BroadcastContext::unsubscribe` has NO all-or-nothing epoch pre-validate pass, unlike its
  two siblings `rotate_all_author_keys` and `governance_ban_subscriber`.
- `BroadcastKeyEpochAdvance.timestamp` has zero production consumers (constructed only in
  `rotate_all_author_keys` + one test); `timestamp_ms` is a dead parameter on a public API.
