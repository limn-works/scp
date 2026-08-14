---
name: slice2-contextsnapshot-creation-time-e935347b5
description: Slice-2 PR #1858 convergent creation_timestamp_secs on ContextSnapshot — ALIGNED, 0 findings, at HEAD e935347b5
metadata:
  type: project
---

# Slice 2 — ContextSnapshot convergent creation_timestamp_secs (PR #1858) @ e935347b5 — ALIGNED

**Why:** Closes the import/restore TTL-deadline divergence: live create path already stamps the convergent creator-assigned `creation_timestamp_secs` (actor PerContextState, pre-existing, =`created_at` in tests / `ContextCreated` leaf in prod), but import/restore previously re-derived from local `now()` and armed the TTL timer with `anchor_deadline_to_creation=false`. A timer-fired `ContextExpired`/`ContextClosed` leaf then carried a per-member-local timestamp → equal-event-count Merkle roots diverge → false equivocation (§9.9.3). Slice threads the value through the snapshot boundary.

**How to apply:** Governing artifact for timer-triggered leaf-time convergence is §9.8.3 line 821 (09-security-model.md): "For timer-triggered events that carry no commit envelope (TTL expiry/close, governance-freeze expiry, deferred economic-policy application), the convergent value is the pre-computed deadline already in convergent context state, not local now()." Plus §7.3.1, §9.9.3. ADR-051 present at base+head (it disclaims the TIME axis — "convergent order and count, not convergent time" — so the single new ADR-051 cite in state.rs is contextual/program-positioning, not the normative source; defensible, not phantom).

## Correct review base (GOTCHA — cost a full false alarm)
- PR #1858 base=`main`, head=`e935347b5`, branch `feat/contextsnapshot-convergent-creation-time`, 3 commits: 18d8d5a49 (runtime field+thread), 00d7a3be2 (wasm verbatim import), e935347b5 (wasm drop legacy creation==0 guard).
- Correct diff = `origin/main(1f1ea7cd2)..e935347b5` = 14 files +563/-56.
- TRAP: in the worktree, local `main` HEAD = `b321248e1` (an OLDER main-lineage commit; origin/main=1f1ea7cd2 is 6 commits AHEAD of it). `git diff 1f1ea7cd2..HEAD` accidentally diffs against stale local main and dumps a HUGE spurious ADR-051-removal list — NOT slice content. ALWAYS pin refs by SHA (gh pr view --json headRefOid) and diff `origin/main..<headOid>`, never bare `main`/`HEAD` in this worktree.

## Verified ALIGNED (0 findings)
- Field `creation_timestamp_secs: u64` `#[serde(default)]` added to native `ContextSnapshot` (state.rs:556) with thorough security rustdoc (verbatim/never-re-pinned, upper-bound fail-safe, legacy 0 → `0+ttl` distant-past = expires-immediately fail-safe direction).
- All 7 native snapshot builders populate `state.creation_timestamp_secs` (broadcast/trust_recovery/messaging/ttl_close build_snapshot_from_state, manager_methods snapshot_context, export_import strip_snapshot_for_public public-projection carry-through). messaging build_snapshot_for_persist delegates to build_snapshot_from_state → covered.
- import_context (lifecycle_helpers:1818) + restore_context (:2298) now consume verbatim and arm `anchor_deadline_to_creation=true`; ttl_close handler/handle.rs/ttl_close_helpers comments updated to match (no more "false / forward-step-under-ADR-051" stale text).
- DOC-COMMENT ACCURACY (user-flagged): corrected `observed_at` comment (lifecycle_helpers:~1752) now explicitly contrasts the two trust models (creation=verbatim upper-bound vs observed_at=re-pinned window-lower-bound, §5.3.2/§19.3) — accurate. WASM legacy comment now says `0+ttl` not `now()` — accurate; `convergent_ttl_deadline_secs(0,Some(ttl))=Some(0+ttl)` has NO creation==0 guard (ttl_close_helpers:277-280), WASM handle_ttl_expiry mirrors with match `Some(ttl)=>creation.saturating_add(ttl)`, `None=>now()` (now-fallback reserved to genuinely-no-TTL).
- WASM: PerContextState + WasmContextExportSnapshot DTO field (both `#[serde(default)]`, both doc'd as independent DTO, NOT native byte-parity). create_context binds `creation_timestamp_secs` ONCE and reuses for both stored state AND the ContextCreated leaf timestamp. Import (manager:5952) consumes `snap.creation_timestamp_secs` VERBATIM — correctly NO `.min(now_ms_for_clamp)` (the observed_at-style nonce/executed fields at 5882/5895 DO clamp — the intended asymmetry). All 5 WASM DTO construction sites compile (1 prod populated, 2 test builders inherit `0` from make_minimal_valid_snapshot/make_bare_per_context_state).
- SCOPE ACCURATE: fixes the creation-TIMESTAMP axis only; does NOT claim to fix native↔WASM system-leaf `actor_did` divergence (pre-existing #1850, tracked Slice 4). Comments are honest about WASM keeping its own digest.
- Tests: native JCS round-trip + legacy-default-0 + public-strip-carry + skewed-importers-identical-deadline + future-dated-verbatim-matches-wasm; persist→load preserves; WASM convergent-deadline + legacy-zero + DTO-serde + native/wasm future-creation agreement. Good coverage of the convergence property and the legacy/future-date edges.

## Did NOT re-raise (per instruction, already tracked)
- native↔WASM system-leaf `actor_did` divergence (#1850, Slice 4).
- "±5-min" doc inaccuracy (tracked). Slice comments reference ±5-min skew (§9.8.2) but introduce no NEW inaccuracy.
