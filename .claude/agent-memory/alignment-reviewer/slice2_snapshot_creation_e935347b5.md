---
name: slice2-snapshot-creation-e935347b5
description: Slice 2 (ContextSnapshot convergent creation-time, PR #1858) final alignment pass @ e935347b5 — ALIGNED, 0 blocking
metadata:
  type: project
---

# Slice 2 Convergent Creation-Time Final Gate @ `e935347b5` (2026-06-22) — ALIGNED

PR #1858, worktree slice2-snapshot-creation, FROZEN. Review the SLICE-ONLY range `1f1ea7cd2..HEAD` (3 commits: 18d8d5a48/00d7a3be2/e935347b5; ~563 LOC, 14 files), NOT `main..HEAD` (that spans 6 merged PRs incl. event-log substrate #1850, ADR-051, sagas — all separately reviewed).

**Why:** verify the slice matches §9.9.3 / §7.3.1 convergent-deadline intent, doc-comments accurate, scope honest (timestamp axis only).

**How to apply:** if asked to re-review this slice, diff `1f1ea7cd2..HEAD` only. KNOWN/EXCLUDED (do NOT raise): native↔WASM system-leaf `actor_did` divergence = slice 4 (task #203); "±5-min" doc phrasing.

## What it does
Adds `creation_timestamp_secs: u64` (`#[serde(default)]`) to `ContextSnapshot` (state.rs) + WASM `PerContextState`/export DTO. Carried verbatim through snapshot/restore/import so the TTL-fired `ContextExpired` leaf stamps the CONVERGENT deadline `creation + ttl` instead of each member's local `now()`. Native arms `dispatch_start_ttl_timer(..., anchor_deadline_to_creation = true)` on BOTH import + restore (previously `false`); WASM `handle_ttl_expiry` stamps `match ttl { Some(ttl) => creation.saturating_add(ttl), None => now() }` — exact mirror of native `convergent_ttl_deadline_secs` (NO `creation==0` guard on either side). Commit e935347b5 dropped the legacy WASM `creation==0 => now()` guard for parity.

## Verified (0 findings)
1. **Intent match is exact.** §9.9.3 spec literally states: "For timer-triggered events that carry no commit envelope (TTL expiry/close, governance-freeze expiry, deferred economic-policy application), the convergent value is the pre-computed deadline already in convergent context state, not local `now()`." Slice implements precisely this.
2. **Verbatim-consumption security claim is TRUE.** `validate_export_for_import` (export_import.rs:553) runs version → `exporter_did == creator_did` binding → `verify_strict` over `SHA-256(domain||scope-tag||JCS(snapshot))` → Merkle-root check, ALL before the `PerContextState` builder (lifecycle_helpers.rs:1803). Since `creation_timestamp_secs` is now a serialized snapshot field, it is inside the signed preimage = authenticated.
3. **Asymmetry sound.** `creation_timestamp_secs` = TTL UPPER bound (`creation+ttl`); backdate only shortens (fail-safe), future-date bounded by ttl → verbatim. `observed_at` = notification-window LOWER bound → re-pinned to local import `now()`. Matches the codebase's established §5.3.2/§19.3 trust split. Restore path keeps verbatim (correct: self-respawn, re-pin would re-arm window forever).
4. **Legacy `0` semantics honest.** `0` is a TTL base not a sentinel → deadline `0+ttl` (distant past) → TTL-bearing legacy context expires immediately on restore = fail-safe upper-bound direction. Convergent across both bridges.
5. **WASM "NOT byte-parity with native ContextSnapshot" disclaimer honest + correctly scoped.** Convergence-critical surface is the LEAF timestamp (`Event.timestamp`, manager.rs:467), which is identical `creation+ttl` on both bridges; the export DTO bytes are irrelevant to leaf/Merkle convergence.

Tests: 4 native (jcs roundtrip, legacy-default-0, public-strip carry-through, skewed/future-dated importer agreement) + 4 WASM (convergent deadline, legacy-zero, serde roundtrip, native↔WASM future-creation agreement) + persist→load. All spec cites (§7.3.1/§9.9.3) resolve. No `#NNNN` in source.

GOTCHA: `main..HEAD` diffstat is HUGE (~32k LOC) and misleading — it includes the whole event-log unification line. Always isolate the slice's own commit range.
