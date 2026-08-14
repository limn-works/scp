---
name: eventlog-unification-phase2-round5
description: Round-5 fidelity review of event-log unification Phase 2 at ccf70dc50 — APPROVE; round-4 latent fix confirmed, two pre-existing non-blocking residues
metadata:
  type: project
---

# Event-Log Unification Phase-2 Round-5 @ `ccf70dc50` (2026-06-18) — APPROVE

Branch `feat/eventlog-unification-phase2-substrate`, base `1c0ccbc7d`. Diff = 24 commits, +2440/-1807 across 48 files (much larger than the `dc18f5899` 6/6-item state in [[eventlog_unification_phase2_substrate]]; branch advanced 18 commits).

**Why:** Migrate scp-runtime off the free-form-string `SCP-EXPORT-ENTRY:` hash-chain onto the canonical RFC 6962 `scp_event_log::tree`. Governed by ADR-011 amendment (phase-2.md:865-899) + ADR-050 + §9.9.3/§23.16.8.

**How to apply:** This is the canonical state for re-reviews. All core fidelity invariants PASS:
- Hash-chain fully removed: `git grep compute_entry_hash|EventLogEntry|SCP-EXPORT-ENTRY -- crates/` = EMPTY.
- Export binding `event_log_merkle_root` = RFC 6962 `tree::root` over ALL leaves (export_import.rs:485,506).
- Typed `EventType` enum (lib.rs:109) — all prior name-string defects (`ContextTombstoned`,`ContextMigrationCancelled`,`TtlExtended`,`TtlExtensionRejected`,`SpendApproved`,`AppBound`,`AppUnbound`) now exist as typed variants.
- The TWO exclusions correct: `MessageReceived` + `EquivocationDetected` are NOT EventType variants; survive only as `ContextEvent` receive-buffer signals + explanatory comments (per ADR:871-887).
- Typed `EventPayload` decode in consequence.rs:973-990.
- No `.docs/` upstream artifact modified.

**Round-4 latent fix CONFIRMED:** `ccf70dc50` removed dead `SCP-EXPORT-ENTRY:` from `domain_separators_are_all_unique()` registry (test_vectors.rs:1197 area); uniqueness assertion retained. `4dd9ed010` corrected the prune inline comment (event_log.rs:489) — now states tail is RE-CHAINED to fresh `GENESIS_PREV_HASH`, leaf hashes + root CHANGE, pre-prune proofs intentionally invalidated per RFC 6962; matches `truncate_log_keeping_tail` (event_log.rs:608-638) and the fn doc-comment.

**Two NON-BLOCKING pre-existing residues (NOT introduced/touched by this branch — both predate base `1c0ccbc7d`):**
1. 13 live `#636` GitHub-issue-refs across 5 scp-runtime/src files (builder.rs, providers/event_log.rs, providers/mod.rs, store/context.rs, store/event_log.rs) violate [[no-issue-refs-in-code]]. Base had 15; branch REDUCED to 13 (commit `63b45c114` stripped `#710` but consciously kept `#636` — rewrote `#636, #710`→`#636` on store/event_log.rs:25,107). Rule makes no #710-vs-#636 distinction. Branch touched two of these exact lines = clean miss to delete entirely.
2. Dead `format_bind_event`/`format_unbind_event` in app_sandbox.rs:854,871 (`pub fn`, NOT test-gated) still emit `AppBound:{...}`/`AppUnbound:{did}` name-strings with doc-comments claiming "suitable for appending to the Merkle event log" — the exact defect ADR:889-896 names. BUT: app_sandbox.rs UNTOUCHED by branch (empty diff stat); only callers are 3 test sites (already dead at base); ZERO production append sites for `EventType::AppBound/AppUnbound` (variants defined but unwired). Live runtime log IS typed-only. Follow-up: delete dead formatters + wire typed AppBound/AppUnbound append OR confirm app-bind is intentionally unlogged.

**Reusable pattern:** when a branch advances many commits past your last memory snapshot, re-derive the full diff stat first — don't trust the prior item-count. Distinguish "introduced by branch" (diff `+` lines) from "pre-existing, branch untouched" (empty file diff stat) — the latter is a follow-up flag, not a fidelity blocker, but per CLAUDE.md still surfaced (never dismissed as "pre-existing").
