---
name: adr049-pr3-ttl-live-timers
description: ADR-049 PR-3 live TTL timers — M1/M3 convergence review, reset_ttl_timer leaf-blindness gap, history_complete spoofability
metadata:
  type: project
---

# ADR-049 PR-3 (feat/adr049-pr3-live-timers) TTL convergence review (round-2, HEAD ae3bcc7b1)

**Why:** re-review of pass-4 fixes to TTL-close convergence findings (M1/M2/M3/H2/L1).
**How to apply:** when touching TTL expiry leaf timestamps, import clamp, or the two TTL-extension paths.

## Verified SOUND
- M3 import clamp (lifecycle_helpers.rs ~2478-2525): derives `base_ub=creation+ttl`, `derived_ub=base_ub.max(max TtlExtended.new_deadline_unix)` from ROOT-VERIFIED event_log_data (validate_export_for_import recomputes RFC6962 root, ct_eq vs signed snapshot.event_log_merkle_root, at top of import_context BEFORE clamp). CLAMPS (`d.min(derived_ub)`), doesn't reject. Only on import; restore verbatim (messaging_helpers.rs snapshot copies timer). Decode robust (rmp_serde Result, decode_payload `.ok()` filtered, `.max()` None-safe, empty handled). Telescoping correct: execute_extend_ttl records running `old_dl+additional` (governance_helpers.rs:1941-1955), monotonic → `.max()` = last = correct.
- M1 convergent_expiry_leaf_deadline (ttl_close_helpers.rs ~457): first attempt returns recorded deadline verbatim; retry (field cleared by Phase-1) rebuilds `base.max(max TtlExtended)` = matches recorded for the LOGGED-extension case. Wired in handle_ttl_expiry before Phase-1 clear.
- H2 reset guard (ttl_close_helpers.rs reset_ttl_timer ~355): `if let Some(old_dl)` — None → no-op (was `0+new≈1970` immediate expiry). Harmless, no key destruction on unarmed ctx.
- L1: Phase-2 leaf append gated on `persist_result.is_ok()`; idempotent via terminal_leaf_exists. Doesn't break convergence.
- is_terminal (scp-protocol context/mod.rs): exhaustive match Expired|Closed|Tombstoned, closed-by-construction. Despawn gate actor/mod.rs:851 uses it. Sound.
- M2 backoff (actor/mod.rs:116): shift capped at 32, saturating_mul, min CAP 5min. Sound.

## OPEN GAP (NEW, root cause: two disjoint TTL-extension paths)
Two live extension mechanisms:
1. Governance `ExtendTtl`→execute_extend_ttl → EMITS TtlExtended leaf. M1/M3 see it. ✓
2. FFI `context_propose_ttl_extension`+`context_reset_ttl_timer` (all 4 bridges, ffi_conformance required) → reset_ttl_timer sets `deadline_unix_secs=old+new_duration`, persists, NO leaf. M1/M3 BLIND. ✗

Consequences of #2:
- **M3 (MED):** reset-extended ctx exported+imported → history_complete=true (genesis) but max_extended=None → derived_ub=creation+ttl → clamps away the legit reset extension → importer expires PREMATURELY vs live members (early key destruction, D2 violation for reset path).
- **M1 (MED):** reset-extended ctx hits expiry retry → retry rebuilds creation+ttl but first attempt stamped old+new_duration → divergent ContextExpired leaf timestamp.
Fix: reset path must emit TtlExtended leaf (unify with execute_extend_ttl), OR M1/M3 derive from a source capturing reset extensions.

## history_complete spoofable (LOW-MED, malicious creator)
derive_extension_bound gates verbatim(no-clamp) on `entry[0].event_type==ContextCreated`. But append_unsigned_event only enforces entry[0].sequence==0 && prev_hash==GENESIS (tree.rs:164), NOT event_type. Creator can craft seq-0 non-ContextCreated first leaf → history_complete=false → over-long ttl_deadline_secs honored verbatim (defeats M3's anti-equivocation goal). Pruned logs CANNOT pass root verify (start at non-zero seq), so any non-empty root-verified log provably starts at genesis → the robust predicate is `!entries.is_empty()` (gate verbatim on EMPTY log only). ContextCreated-type check is strictly weaker than the seq-0 guarantee already enforced.
