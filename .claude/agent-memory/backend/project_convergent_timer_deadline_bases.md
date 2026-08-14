---
name: project-convergent-timer-deadline-bases
description: TTL/freeze/deferred-change timer leaves anchored on convergent bases (not local now); restore/import TTL stays local pending ADR-051 signed-snapshot creation-time
metadata:
  type: project
---

Follow-on to [[project-eventlog-committer-assigned-timestamp]]: timer-DERIVED event-log leaves were stamping non-convergent deadlines (local arm-time `now + duration`). Fixed each to a convergent base. Commit on branch feat/eventlog-unification-phase2-substrate.

**Why:** committer-assigned-timestamp convergence (commit 88c856360) covered commit-ordered leaves but left timer branches local-clock-based → honest members diverge on ContextExpired/ContextClosed/GovernanceFreezeExpired/deferred-change leaves.

**How to apply (the design that landed):**
- **TTL deadline**: NEW `PerContextState::creation_timestamp_secs` (distinct from `created_at`, which is LOCAL ms instantiation time — do NOT repurpose `created_at`, it's set to local now on import/restore + doc says "first actor instantiation"). Populated on create from the same value passed to the `ContextCreated` leaf. Deadline = `creation_timestamp_secs + params.ttl` (both convergent), computed in actor handler `handle_start_ttl_timer` via new pure helper `ttl_close_helpers::convergent_ttl_deadline_secs`. Threaded via `TtlTimerPayload::anchor_deadline_to_creation` bool + `dispatch_start_ttl_timer(..., anchor)` arg. `spawn_ttl_timer`/`start_ttl_timer` take `deadline_override: Option<u64>` (None ⇒ local now+duration fallback).
- **CRITICAL gotcha**: TTL extension path (governance_helpers execute ExtendTtl ~1535) computes the new deadline itself as `old_deadline + additional` (already convergent) — it MUST pass `Some(new_dl)` as override, else start_ttl_timer's creation-base would ERASE the extension. `reset_ttl_timer` passes None (local).
- **restore/import**: pass `anchor=false` (local arming, = prior behavior, NOT a regression). The signed `ContextSnapshot` (the export preimage, SHA-256(domain||tag||JCS(snapshot))) does NOT carry the convergent creation time, and ContextParams has no creation timestamp. Adding a snapshot field balloons into WASM byte-parity + §25 cross-bridge KAT — explicitly OUT of scope (ADR-051 forward step). `creation_timestamp_secs` on those paths = local now, never used as base (anchor=false).
- **Governance freeze** (governance_helpers detect_and_handle_conflicts ~578): `freeze_start = max(new_proposal.created_at, conflicting_proposal.created_at)` (signed, tamper-evident) instead of `clock.now_secs()`. Freeze-expiry leaf = freeze_start + FREEZE_TIMEOUT_SECONDS now convergent.
- **Deferred ceiling / economic policy** (execute_modify_ceiling ~1374, execute_set_economic_policy ~2465): `effective_at = CommitMeta::timestamp_secs (= proposal.created_at) + PERIOD` instead of now+PERIOD. Set notified_at = timestamp_secs too.
- **WASM** (manager.rs execute_governance_action ~2792): native `finalize_governance_action` takes `&GovernanceProposal` — CANNOT mint GovernanceActionExecuted without a real proposal.created_at. WASM `map_or(0,..)` would stamp divergent 0. Fixed: resolve `proposal_created_at` from pending_proposals/resolved_proposals BEFORE dispatch, hard-error `SCP-CTX-2041` (ScpWasmError::Context) if untracked. NOTE: WASM `execute_governance_action` accepts the action+proposal_id directly (no stored-proposal requirement structurally) but the convergent-leaf invariant forces presence.

**Honesty edits (no behavior change):** membership/lifecycle/governance leaf comments no longer claim active cross-member convergence — they are committer-appended-only (the receive-side append branch `run_buffered_post_delivery(event_name=Some)` is DORMANT — `deliver_plaintext_or_announcement` returns None in every branch by design to avoid §9.9.3 false-positives). Annotated the dormant `msg.inner.timestamp/1000` args + ttl.rs legacy `TtlTimer::spawn_with_transport` (test-only now; live path is `ttl_close_helpers::spawn_ttl_timer`). Reference ADR-051 by NAME for cross-member leaf replication.

Tests: `ttl_close_helpers::tests` convergence (alice/bob differing arm-clocks → identical deadline; clippy similar_names forbids member_a/member_b naming). eventlog_convergence 6/0, ttl 37/0, governance 35/0, full clippy + wasm clippy = 0.
