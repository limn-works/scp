---
name: adr049-recv-sequence-floor
description: recv_sequence_tracker import floor merge (§23.17.3) — unbounded-sequence residual assessment, threat model, and why a MAX_SEQUENCE_ADVANCE is the wrong fix
metadata:
  type: project
---

# recv_sequence anti-replay floor merge (§23.17.3, branch fix/adr049-recv-sequence-floor-maxmerge)

Twin of `validate_and_merge_epoch_floors`. Added by e9fe67678 (merge) + ca8edb253 (2b epoch ceiling). Lives in `crypto/mls/provider.rs`: `export_recv_sequence_floors` + `validate_and_merge_recv_sequence_floors`. Wired via `lifecycle_helpers::restore_crypto_state_with_floor_guard` (calls epoch merge THEN recv merge, both rollback-on-Err). Untrusted path = `PrepareForReplace` (lifecycle_control.rs, trusted_local=false), driven by `import_context` with `export.snapshot.mls_crypto_state`.

## The residual (assessed LOW)
Untrusted-import guards: 2a rejects lexicographic regression (both-present senders only); 2b rejects `imp_epoch > sender_key_store.epoch(ctx,did)+MAX_EPOCH_ADVANCE(=1000)`. **2b bounds ONLY epoch; the sequence tuple `.1` is `_imp_seq`, never inspected.** So `(valid_epoch, u64::MAX)` is accepted (it's an advance, not a regression).

Effect (open path, provider.rs ~2087 H9 ceiling, ~2100 replay `epoch<last || (epoch==last && seq<=last_seq)`): poisoned floor `(E,u64::MAX)` kills sender's entire epoch E (seq<=u64::MAX always true) + all epochs <E. Recovery: sender must rotate sender-key to E+1 (rotations use process_incoming_sender_key, NOT gated by recv floor, so they still land). Modest E → self-heals on next rotation. E=merged+1000 → ~1001 rotations ≈ permanent. But the DURABLE lever is the EPOCH (2b's +1000), already present; sequence gap only adds "current epoch fully dead" which self-heals.

## Spec §23.17.3
Lists recv-side tracker in scope but ALL invariants are anti-replay/regression-only. Invariant 3 literally MANDATES accepting any advance (`imported>=local → max`). Upper-bound/poisoning is UNADDRESSED. 2b itself is already an extra-spec DoS deviation.

## Threat model (narrows severity)
`mls_crypto_state` is INSIDE the signed ContextSnapshot (export_import.rs:154-165; unsigned envelope `mls_state` was removed). Import enforces Ed25519 vs creator_did #active/#agent + exporter_did==creator_did + scope=Full. => attacker MUST be creator or hold creator key, AND craft a non-conformant populated mls_crypto_state (legit portable exports empty it). Pure availability (silent per-third-party message suppression at one importing victim). No key leak / forgery.

## Fix guidance
DO NOT add a static MAX_SEQUENCE_ADVANCE: no independent oracle for per-(sender,epoch) seq high-water (unlike epoch which keys off sender_key_store.epoch); a cap false-positives legitimate high-volume catch-up imports or (if clamped) re-opens a replay window. Only false-positive-free option = intra-epoch clamp on import path (accept epoch advances under 2b; don't advance intra-epoch sequence past victim's live value; seed import-only senders at seq 0). Alternative = document residual (like the legacy_floor residual at provider.rs:2110-2126) and tighten MAX_EPOCH_ADVANCE. Related: [[spec-audit-findings]].
