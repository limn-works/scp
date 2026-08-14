---
name: pr2218-kea-counter-round2
description: PR #2218 fix/rotate-all-author-keys-epoch-advance round-2 review — KEA leaf emit + checkpoint counter + sort determinism
metadata:
  type: project
---

# PR #2218 rotate-all-author-keys / KEA epoch-advance — round-2 black/red-hat

Base ed80eab40 → origin/fix/rotate-all-author-keys-epoch-advance (7 commits). Files: scp-protocol broadcast/mod.rs, scp-runtime governance_helpers.rs, tests/event_log_leaves.rs.

**MEDIUM (test efficacy) — the Round-1 BLOCKER fix (checkpoint counter) has NO regression guard.**
- Tests 5 & 6 in event_log_leaves.rs claim to guard `checkpoint_events_since += 1+kea` (execute_revoke) and `+= 2` (execute_reconfigure_governance) but only assert DURABLE LEAF COUNTS via event_log_entries. The counter bump and the leaf appends are INDEPENDENT statements — reverting `+= 2`→`+= 1` leaves both leaves intact, tests still pass. Counter revert = UNCAUGHT.
- Test comments FALSELY claim "if either leaf is dropped ... or in the counter ... this assertion fails" — phantom test-provenance.
- Counter IS directly observable in UNIT tests: state.rs:915 `pub checkpoint_events_since`; existing precedent messaging_helpers.rs:3791/3878, 4096/4168 (`let before=...; assert > before`) and class_s.rs:6718/6733 (`+= 3` → assert ==3). Fix: add unit test asserting counter delta, not integration leaf-count.

**CLEAN:**
- helper `emit_key_epoch_advance_best_effort` `label` param = structured tracing field only, hardcoded call-sites; no injection.
- `old_epoch = new_epoch.saturating_sub(1)` sound: rotation always +1 from ≥0 so new_epoch≥1; pre-validate rejects overflow.
- sort_unstable_by author_did: unique HashMap keys, deterministic; the ONLY cross-replica-Merkle-relevant ordering. author_dids iteration order irrelevant (per-author state independent; leaves sorted). emit() ContextEvents are in-memory receive_buffer, NOT durable Merkle leaves.
- execute_reconfigure_governance `+= 2` EXACT: both leaves unconditional fail-closed `.await?`.

**LOW (pre-existing, not introduced):**
- reconfigure partial failure (leaf1 GovernanceReconfigured durable, leaf2 DeadlockRecovery append fails → `?` returns Err before counter bump) under-counts by 1. Same behavior old (`+=1`) and new; inherent to sequential fail-closed appends w/o txn.
- best-effort KEA leaves diverge across nodes on Byzantine event-log backend (counter tracks each node's own true count, so no NEW drift). Matches memory eventtype-audit-1847.
