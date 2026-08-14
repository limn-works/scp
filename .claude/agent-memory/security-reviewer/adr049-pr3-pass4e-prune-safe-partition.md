---
name: adr049-pr3-pass4e-prune-safe-partition
description: ADR-049 PR-3 pass-4e TTL prune-safe partition (216ebf420) — closes 2 #2102 HIGHs; 2 new MEDIUMs
metadata:
  type: project
---

# ADR-049 PR-3 pass-4e prune-safe partition (216ebf420, 3 commits over 0be1853ce) — 2026-07-11

Reviewed feat/adr049-pr3-live-timers. Redesign: convergent TTL deadline PARTITIONED —
fail-DANGEROUS base (`creation_timestamp_secs + params.ttl`) + promotion (`params.ttl == None`)
from PRUNE-IMMUNE snapshot; fail-SAFE extensions (`TtlExtended.new_deadline_unix`) from prunable log.
`convergent_ttl_deadline(entries, creation_timestamp_secs, params_ttl)` ttl_close_helpers.rs:751.
`GenesisBaseTrust` enum (ImportClamp/OwnLog) FULLY REMOVED.

## Two #2102 HIGHs — BOTH CLOSED
- **Pruning HIGH CLOSED.** Base sourced from snapshot at ALL 5 non-test readers: import (lifecycle_helpers.rs:2513 `export.snapshot.creation_timestamp_secs`), restore (2720 `ctx_snapshot.creation_timestamp_secs`), expiry (ttl_close_helpers.rs:147 `cell.creation_timestamp_secs`), extend (483), finalize_close (840). Genesis leaf never read for base. Promotion = `params.ttl==None` via `promote_params()` (mod.rs ~152, sets memory_scope=Full AND ttl=None); ContextPromoted leaf NO LONGER read for arm. Pruned finite-TTL ctx still expires; pruned promoted ctx stays permanent.
- **Import future-dating HIGH CLOSED durably.** lifecycle_helpers.rs:2152 rejects `creation_timestamp_secs > now + SNAPSHOT_CLOCK_SKEW_TOLERANCE_SECS` fail-closed (Err return). Not pass-4d's reversible in-memory clamp; ctx not imported so snapshot never persisted → no poisoned base. Snapshot persist (step 8, line 2483) is AFTER the check.

## Two NEW findings
- **MEDIUM — future-date check placed AFTER irreversible side effects.** import_context (starts 1891): crypto restore (2038/2052) + `import_event_log_data` (2095) run BEFORE the future-date check (2152). On rejection it `return Err` with NO teardown — leaves resident MLS group + persisted foreign event log orphaned. Sibling binding-mismatch path (2077-2087) DOES `destroy_mls_group`. Potential floor-guard poisoning: rejected future-dated import installs crypto+replay-floor (from its snapshot epoch); a later legit import/restore of same context_id with ≤ epoch could be floor-rejected (DoS/grief). Fix: hoist the pure scalar check to TOP of import_context (needs only `export.snapshot.creation_timestamp_secs` + clock). TTL HIGH itself still closed (base never persisted); this is the residue.
- **MEDIUM — promotion (fail-DANGEROUS signal) persisted BEST-EFFORT, not fail-closed.** `execute_promote_context` (governance_helpers.rs:2688) rides `commit_class_c_best_effort` → `persist_state_best_effort` (class_s.rs:3145) whose failure is logged, NOT surfaced. Durable ContextPromoted leaf (appended `?`) is DELIBERATELY ignored by reader. If best-effort persist fails + crash within ≤50ms coalesce window before run-loop coalesced persist, on-disk snapshot keeps params.ttl=Some → restart re-arms → promoted (permanent) ctx RE-EXPIRES, keys destroyed. Confidentiality-SAFE direction (keys destroyed, never-expire fully closed) so NOT a fail-open — but availability/consent regression + strictly LESS durable than pass-4d (which read durable leaf). ADR classifies promotion-loss as "dangerous"; best-effort is wrong tier for a fail-dangerous signal → internal inconsistency. Fix: fail-closed persist for promotion params (can't re-add leaf read — that reintroduces the prunable-log fail-dangerous dependency they removed).

## Pruned extension — fail-safe CONFIRMED
Result = max(base, max TtlExtended). Pruning a leaf only lowers the max → SHORTENS → earlier key destruction (availability, not confidentiality). Cannot LENGTHEN by pruning. Undecodable leaf DROPPED with warn (shortens, visible). Forged import-extension leaf CAN lengthen beyond consent on untrusted import — acknowledged #2102 residual (leaf-level authz deferred), NOT a pruning issue.
