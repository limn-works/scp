---
name: class-s-mirror-snapshot
description: ADR-049 §9 PR2a Class-S data split + mirror snapshot/restore (ClassSState/GovernanceClassS) crypto-soundness — replay-state round-trip integrity + §9.4.3 bearer barrier
metadata:
  type: project
---

# Class-S sub-struct mirror snapshot/restore (branch classs-guard, HEAD ebb8314f2)

ADR-049 §9 PR2a: behavior-neutral DATA SPLIT of 9 Class-S fields into nested sub-structs
+ NEW in-memory mirror snapshot/restore methods. VERDICT: CRYPTO-SOUND, no findings.

**Why:** PR2a regroups Class-S state and adds `ClassSState::snapshot/restore` + `GovernanceClassS::snapshot/restore` mirrors (currently `#[allow(dead_code)]`, first prod consumer is the later privatization PR; exercised by one lossless round-trip unit test). Concern was replay-window re-open if a nonce silently un-recorded on round-trip.

**How to apply:** when reviewing later Class-S PRs (privatization / mutator-combinator boundary), the round-trip primitives below are the load-bearing invariants — re-verify they stay wired.

## Two distinct snapshot/restore mechanisms, both lossless via SAME primitives
1. PRODUCTION on-disk ContextSnapshot (messaging_helpers build_snapshot + lifecycle_helpers restore): behavior UNCHANGED, pure repath `state.xctx_nonce_dedup` → `state.class_s.xctx_nonce_dedup`, `governance.spending_nonce_tracker` → `governance.class_s.spending_nonce_tracker`. Restore still applies `SAGA_NONCE_DEDUP_TTL_SECS` explicitly at call site + `debug_assert_saga_dedup_ttl` moves with it. build_snapshot DESTRUCTURES GovernanceState incl nested `class_s {...}` → exhaustiveness guard forces new field into snapshot.
2. NEW in-memory mirror `ClassSState::snapshot/restore` + `GovernanceClassS::snapshot/restore` (state.rs:938/962 actor, state.rs:1235/1248 context). dead_code today, unit test only.

## Replay-state round-trip integrity (concern #1) — PRESERVED EXACTLY
- NonceDedup (key_protocol_verify.rs:691): `entries()` clones full `seen` HashMap<[u8;16],u64>; `from_entries_with_ttl(seen, ttl)` reconstructs verbatim, NO prune at restore (lazy prune on next is_replayed → strictly conservative, can only over-retain, never drop a still-valid nonce). REQUEST_NONCE_SIZE=16 matches mirror field. ttl_secs captured + restored (test asserts == SAGA_NONCE_DEDUP_TTL_SECS=600, strictly > 300 skew).
- NonceTracker (ucan/nonce.rs): `snapshot_entries()` clones full `seen` HashMap<String,(first_seen,token_expiry)>; `from_snapshot()` reconstructs + runs prune(). prune retains while `now <= max(token_expiry+300, first_seen+86400)` → drops an entry ONLY when token EXPIRED past 300s grace AND >24h old. A dropped nonce belongs to an expired spending UCAN = zero replay value. SOUND (does not drop a still-replay-able nonce). from_snapshot_with_capacity truncation path is deterministic (sort by desc token_expiry) + unreachable in normal op.
- Asymmetry NOTED + safe: NonceDedup restore = NO prune (lazy); NonceTracker restore = prune. Both can only remove security-irrelevant entries.

## §9.4.3 bearer barrier (concern #2) — HOLDS structurally
- Live `SagaPreparedState` enum (saga_prepared_state.rs:67): NO Clone/Serialize/Deserialize derive. ClassSState: NO derive. GovernanceClassS: NO derive. Barrier is type-level.
- Snapshot path uses `SagaPreparedStateSnapshot::from_prepared` (saga_prepared_state.rs:512) — the existing public-metadata projection already journaled. Exhaustive match over 3 variants (new variant = compile error). XCTX variant carries `ucan_proof_id` (identifier) NOT UCAN proof bytes. from_prepared/into_prepared field-exhaustive 1:1 for all variants incl recorded_nonce/recorded_timestamp_ms/recorded_chain_depth.
- No new Clone/Serialize introduced on any bearer-capable type.

## Other crypto-state (concern #3) — SOUND
- xctx_committed_outputs / xctx_committed_invocations / xctx_caller_reservations: all derive Clone+Serialize (CommittedToolInvocation is public non-bearer protocol artifact, saga_prepared_state.rs:611), snapshot by `.clone()`, restore by direct move = trivially lossless. Idempotency witnesses preserved.
- GovernanceClassS executed_proposals/threshold_signers/threshold_value: Clone, snapshot by clone, restore via struct LITERAL (keeps `threshold_value=` gate marker out of restore body — gate stays green unedited).

Unit test `class_s_and_governance_class_s_snapshot_restore_is_lossless` (state.rs:1912) covers all 9 fields: populate → snapshot → MUTATE/clear → restore → assert value-stable.
