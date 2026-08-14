---
name: ttl-convergent-deadline-redesign
description: ADR-049 PR3 TTL-deadline single-source redesign (convergent_ttl_deadline) — round-3 review, invariant holds, 1 HIGH restore-path regression
metadata:
  type: project
---

# TTL convergent-deadline redesign (branch feat/adr049-pr3-live-timers, HEAD a847842a1)

Replaced 4-source TTL-deadline periphery with ONE invariant: the event log is the single authoritative source of the convergent TTL deadline. Reader = `convergent_ttl_deadline(&[Event], creation_ts, params_ttl)` (ttl_close_helpers.rs:569).

**Why:** M1/M3/H1 deadline bugs from independent scalar + memory_scope + params heuristics.

**How to apply:** every deadline mutation (create/extend/promote) emits a convergent leaf; every reader derives via the one fn.

## Verdict (round-3): INVARIANT HOLDS. Round-2 findings CLOSED.
- `convergent_ttl_deadline` SOUND + convergent: reads only convergent fields (event_type, sequence, payload.new_deadline_unix) + convergent inputs. Does NOT read Event.timestamp. Promotion-after-create⇒None; base=creation+ttl; ext=max(new_deadline_unix); combine=max. Decode panic-safe (.ok()+filter_map). Pruned genesis + multi-created handled via max(sequence).
- M3 import CLOSED: import derives from Merkle-validated `export.event_log_data` (validate_export_for_import → recompute_event_log_root → ct_eq vs SIGNED root, export_import.rs:590-628) BEFORE derivation. Scalar ignored. `rmp_serde::from_slice(...).unwrap_or_default()` unreachable on validated path (validation decodes same bytes first). Only residual = forging creator (fundamental, caught by cross-member convergence). exporter_did==creator_did enforced.
- H1 CLOSED at source: ContextPromoted leaf⇒None (execute_promote_context emits it, gov_helpers.rs:2759, convergent CommitMeta.timestamp_secs, .await? propagated). memory_scope gate gone. Created Full+ttl w/ no promotion leaf re-arms.
- Reset M1/M3-blind CLOSED: reset_ttl_timer now emits TtlExtended leaf (ttl_close_helpers.rs:406-451).

## OPEN FINDINGS from this review
- **HIGH — restore empty-log fallback re-opens H1 (fail-DANGEROUS).** restore_event_log_best_effort (lifecycle_helpers.rs:2560) swallows hydration failure → init_event_log → EMPTY log, returns () (no signal). restore_context (2672) then derives convergent_ttl_deadline(&[], creation_ts, Some(ttl)) = Some(creation+ttl) for a PROMOTED context (params.ttl stays Some, append-only) because the ContextPromoted leaf is gone → dispatch_start_ttl_timer(past deadline) → sleep(0) → silent destruction of a permanent context. Old memory_scope!=Full gate read the DURABLE persisted scope, robust to log-hydration failure; redesign traded it for sole reliance on best-effort log hydration in the dangerous direction. Persistence + event_log are SEPARATE providers → snapshot can load while log fails. FIX: make restore re-arm fail-CLOSED on hydration failure (propagate success bool; on failure do NOT arm a destructive past deadline / leave disarmed), OR defense-in-depth veto: never arm a PAST sleep(0) when persisted memory_scope==Full. Import path is safe (Merkle-validated, unwrap_or_default unreachable).
- **MEDIUM — reset leaf timestamp non-convergent.** reset_ttl_timer appends TtlExtended with `deps.clock.now_secs()` (LOCAL) vs governance execute_extend_ttl uses convergent CommitMeta.timestamp_secs. Event.timestamp IS in compute_event_canonical_hash (tree.rs:389) → per-member reset (local FFI op context_reset_ttl_timer, each member's app calls it) yields divergent leaf hashes → divergent Merkle roots for the same logical extension. Does NOT affect the DEADLINE (derivation ignores timestamp) so invariant holds; blast radius = cross-member checkpoint/consistency-proof root equality (governance uses convergent ts precisely to preserve this). Doc comment falsely claims "committer-as-timestamp for the leaf's own timestamp" — code passes local now(). Import unaffected (creator exports own self-consistent log).

## Reset-leaf durability verdict
Best-effort append is ACCEPTABLE: fail-SAFE (lost leaf ⇒ shorter derived deadline ⇒ context expires no later than convergent TTL, no key exposure past agreed TTL). Weaker than governance (.await? propagates) but reset is fire-and-forget FFI (`->()`), no observer, so error propagation is moot. Recommend fixing the timestamp (MEDIUM above) for Merkle convergence + optionally retry for liveness.
