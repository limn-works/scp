---
name: slice2-snapshot-creation-e935347b5
description: Slice 2 (PR #1858) convergent creation_timestamp_secs in ContextSnapshot — final security pass, CLEAN
metadata:
  type: project
---

# Slice 2 — Convergent creation_timestamp_secs in ContextSnapshot (PR #1858, HEAD e935347b5)

Final confirming security pass 2026-06-22. **ZERO new blocking findings — CLEAN.**

Scope = 3 commits over base 1f1ea7cd2: 18d8d5a49 (add field), 00d7a3be2 (WASM verbatim import), e935347b5 (drop WASM creation==0 guard in handle_ttl_expiry).

New field `ContextSnapshot.creation_timestamp_secs: u64` (`#[serde(default)]`, legacy=0). Mirrors `PerContextState.creation_timestamp_secs` (the value stamped on ContextCreated leaf). Persists creator-assigned creation time through export/persist so restore+import re-arm a CONVERGENT TTL deadline (creation+ttl) instead of importer-local now() — closes the ADR-051 restore/import divergence (create path was already convergent).

## Why CLEAN (verified, not asserted)
- **Sole consumer = TTL upper-bound deadline.** Grepped all non-test usages: only `ttl_close.rs:146` (native `convergent_ttl_deadline_secs`) + `manager.rs:5101` (WASM `creation.saturating_add(ttl)`). NOT used as window lower-bound, grace/notification base, authz gate, or anything else. So backdating only SHORTENS lifetime (fail-safe); future-dating bounded by ttl.
- **Authenticated before consume, both bridges.**
  - Native: `validate_export_for_import` (lifecycle_helpers.rs:1512) runs before builder at :1803 that does `creation_timestamp_secs: export.snapshot.creation_timestamp_secs`.
  - WASM: `deserialize_and_verify_envelope` enforces len-bound → version gate → `exporter_did==creator_did` binding → non-empty sig → `verify_strict` against creator-resolved #active/#agent key → HMAC, then returns envelope; `import_context` binds `snap=&envelope.snapshot` AFTER that. Verbatim `creation_timestamp_secs: snap.creation_timestamp_secs` is post-verification.
- **observed_at asymmetry preserved (the load-bearing invariant from prior reviews).** `pending_*` observed_at is STILL re-pinned to local clock on import (it's the §5.3.2/§19.3 notification-window LOWER bound — backdating would collapse window). creation_timestamp_secs is the OPPOSITE trust model (upper bound) → verbatim is correct. Both documented inline. No regression to the 4cad781e5/f234988bc backdating fixes.
- **WASM guard removal (e935347b5) is convergence-only, not exposure.** Dropping `creation==0 => now()` in handle_ttl_expiry changes ONLY the recorded ContextExpired leaf timestamp (0+ttl vs now()); state still →"expired" unconditionally; no access-control side effect. Matches native `convergent_ttl_deadline_secs` which also has no creation==0 guard. now() fallback retained ONLY for genuinely-no-TTL (ttl_seconds==None) case.

## Mechanical changes (all benign)
Every build_snapshot_from_state / snapshot_context call site (broadcast/messaging/trust_recovery/manager_methods/ttl_close) now copies state.creation_timestamp_secs. restore_context + import_context now arm `anchor_deadline_to_creation = true` (was false). Rest = test fixtures + doc comments. Strong test coverage: JCS round-trip, legacy-default-0, public-strip carry-through, skewed-importer convergence, future-dated verbatim native==WASM, WASM legacy 0+ttl.

KNOWN/EXCLUDED per task (do NOT re-raise): native↔WASM actor_did divergence (slice 4); "±5-min" doc wording.
