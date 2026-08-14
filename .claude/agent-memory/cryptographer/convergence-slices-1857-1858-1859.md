---
name: convergence-slices-1857-1858-1859
description: 2026-06-21 review of 3 convergence-fix branches off 1f1ea7cd2 (PR #1857/1858/1859) — all SOUND
metadata:
  type: project
---

# Convergence slices off 1f1ea7cd2 (Phase-2 substrate base) — ALL SOUND 2026-06-21

Review base = `git diff 1f1ea7cd2..HEAD` per worktree (NOT main; main is behind 1f1ea7cd2). RFC-6962 leaf = SHA-256(0x00‖rmp_serde(Event)); convergence test = two honest skewed-clock members derive identical root.

## Slice 1 (#1857) — remove durable CommitBroadcast* appends — SOUND
- Removed all 4 durable `append_context_event(EventType::CommitBroadcast*)` calls (CommitBroadcasted/Pending/Succeeded/Failed). Zero production durable appends remain (grep-verified). Variants stay in closed EventType set (tree.rs tags 57/58/71/72, pruning.rs marks all `false`=prunable).
- Rationale CORRECT: per-committer transport-retry bookkeeping; only broadcasting committer holds notion, receiver appends nothing → diverge at equal event_count = the §9.9.3 false-positive. No convergent order even under ADR-051 (transport-send is not a causal-DAG app event). Permanent exclusion, phase-2.md taxonomy §3.
- `try_broadcast_commit_or_enqueue` + `apply_commit_retry_outcomes` became infallible (dropped Result); checkpoint_events_since increments removed exactly match dropped leaves → accounting consistent by construction. Events surfaced as local ContextEvent only.
- Tests: positive convergence + non-vacuous negative control (eventlog_convergence.rs).

## Slice 2 (#1858) — ContextSnapshot.creation_timestamp_secs convergent TTL — SOUND
- New `creation_timestamp_secs: u64` `#[serde(default)]` on ContextSnapshot. Inside signed JCS preimage: `canonical_snapshot_hash()` = SHA-256(jcs::to_vec(&snapshot)) (export_import.rs:351-367); verify_strict before consume + exporter_did==creator_did bind (578-595).
- Populated from `ctx.creation_timestamp_secs` at snapshot_context (NOT now()). import/restore consume VERBATIM; both now pass anchor_deadline_to_creation=TRUE.
- Verbatim safety CORRECT: sole consumer = TTL upper bound (creation+ttl); backdating only shortens (fail-safe), future-dating bounded by ttl, no lower-bound/grace consumer. Legacy default 0 → 0+ttl in past → expires immediately (fail-safe).
- WASM: own DTO field, doc explicitly says NOT byte-parity w/ native, keeps own digest (claim c OK). WASM import CLAMPS `.min(now)` while native verbatim — asymmetry is no-op on any validly-signed snapshot (clamp only fires on future-date which requires breaking sig; WASM also verify_strict before import, fail-closed on missing sig). No convergence break.
- No frozen export-digest KAT exists; JCS sorts keys so field order irrelevant. NOTE (non-blocking): field not yet in specs — provenance gap, ADR-051 governs intent.

## Slice 3 (#1859) — convergent consequence evidence-window anchor — SOUND
- `evaluate_consequence_rules` gains `convergent_now` param. window_anchor = convergent_now if is_convergent_trigger else local now.
- `is_convergent_trigger` (const fn, EXHAUSTIVE no wildcard): WarningCount/Custom=true, MessageVelocity/ToolRateExceeded=false. Closed by construction.
- KEY: convergent_now = max(Source-1 durable log entry timestamps) computed BEFORE buffer merge in event_log_entries_for_consequences (governance_logic.rs:639); returns (merged, convergent_now). NEVER from post-merge set (which has Source-2 buffer local-clock estimates). Empty log → now fallback (sound: no convergent evidence to match).
- ALL production callers verified: messaging_helpers (3x), governance.rs:792 periodic, governance_helpers.rs:4334/4348 finalize, tools/invoke.rs:850 via ToolEconomyContext.convergent_now, tools_helpers reserve/settle. Participation-only callers correctly `_convergent_now` discard.
- WASM consequence.rs:97 mirrors native exactly (max event_log_events ts, now_secs fallback, before merged_consequence_events).
- SAFETY PREMISE VERIFIED: non-convergent triggers never mint durable leaf — durability gate `durable: is_convergent_trigger(trigger)` (consequence.rs:1253, governance_logic.rs:230) uses SAME fn as window-anchor decision → cannot drift. Test enforce_triggered_non_convergent_mints_no_leaf pins it.
