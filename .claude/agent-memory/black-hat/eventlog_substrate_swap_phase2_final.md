---
name: eventlog-substrate-swap-phase2-final
description: Final adversarial pass on Phase-2 substrate-swap branch (HEAD 16a2cd42b) — export verification now CLOSES truncation; only NEW finding is WASM↔native ~40-leaf parity gap (distinct from #1845)
metadata:
  type: project
---

# Event-log substrate swap (RFC-6962) — final black-hat pass

Branch swaps runtime event log onto `scp_event_log` RFC-6962. HEAD `16a2cd42b`.

## What got STRONGER (verified sound)
- **Export verification truncation now CLOSED, not just detected.** `verify_merkle_chain` →
  `recompute_event_log_root` (export_import.rs:464). Replays every entry through
  `scp_event_log::tree::append_unsigned_event` which enforces STRICT `sequence == running_count`
  (tree.rs:168) + `prev_hash` chain (tree.rs:182), then compares `tree::root` (RFC-6962 over ALL
  leaves) constant-time vs SIGNED `snapshot.event_log_merkle_root`. Prefix-truncation rejected
  outright (non-zero seq on new entry[0]); suffix/reorder/forge → different root → ct compare fails.
- **Removed unsigned `ContextExport.merkle_root` field + step-6: NO new bypass.** grep-confirmed no
  path reads the removed field. Step 5 (signed binding) was always authoritative; step 6 was pure
  defense-in-depth dead weight. Removal is clean.
- **Leaf hash includes signature field; provider + verifier BOTH use empty-sig
  `append_unsigned_event` path** → uniform, no producer/verifier mismatch. Provider assigns
  seq/prev_hash itself (event_log.rs:81) — attacker cannot inject inconsistent values.
- **`to_vec_named` blob vs positional `to_vec` leaf-hash**: different serializations but leaf hash
  is always recomputed positionally on both sides via `leaf_hash()`. No mismatch.

## merge_consequence_events convergence — verified sound
- Durable (convergent-trigger) consequence leaves draw evidence ONLY from Source 1 (durable log):
  WarningCount/Custom match `EventType::GovernanceAction` (consequence.rs:1342/1349), buffer only
  contributes MessageSent (non-durable velocity). `convergent_consequence_timestamp` max_by_key over
  Source-1 evidence → deterministic, dense unique seq, no ties → byte-identical leaf ts on every
  honest member.
- Native (governance_logic.rs emit_*) and WASM (consequence.rs append_durable_consequence_leaf →
  manager.rs append_consequence_leaf) BOTH route the SAME shared `consequence_event_payload` +
  `trigger_kind_str` + `consequence_action_type` + `convergent_consequence_timestamp`. Identical
  preimages. EL01 test pins buffer-side GovernanceActionExecuted is NOT re-projected (Source 1 only)
  to avoid double-count divergence.
- TokenRevoked leaf uses shared `token_revoked_payload` (revoke.rs); native (resolvers.rs) + WASM
  both call it. Byte parity.

## NEW finding (distinct from tracked #1845) — MEDIUM
- **WASM omits ~40 durable governance/lifecycle EventType leaves that native appends.** Honestly
  marked by `#[ignore]`d `wasm_native_full_governance_eventtype_parity_pending` (wasm_conformance.rs:
  2454). RoleAssigned, AccessRevoked, SpendApproved, migration/TTL/threshold/proposal families. A
  native member + a WASM member in the SAME context produce structurally different logs → different
  event_count + root. This is a TRUE divergence (not false-positive), DISTINCT root cause from #1845
  (which is dormant replication). Gated behind same dormant cross-member root comparison, so latent.
  Documented in-tree as intentional known gap. Violates completeness tenet but acknowledged.

## Latent fragility (not a live bug)
- Consequence + TokenRevoked leaf convergence depends on `serde_json` emitting SORTED (BTreeMap) keys
  — i.e. `preserve_order` feature NOT enabled anywhere in workspace. Currently true (grep-confirmed).
  If any future dep enables it (additive feature unification), leaf bytes shift to insertion-order.
  Would NOT break native↔WASM (both shift together) but WOULD break §25 KAT vectors. No structural
  guard prevents accidental enablement. Worth a closed-set assertion.

## Self-amplification (convergent, bounded — minor)
- A Custom consequence's own `ConsequenceTriggered` durable leaf (target_did=subject) is projected to
  GovernanceAction and can re-count as evidence for the SAME Custom rule next eval. Bounded by
  cooldown (rule.window) + window-aging of the leaf ts. Convergent (same on all honest members), so
  not an equivocation break. Inflation only.

## Verdict
Export forgery: CLOSED. Consequence merge convergence: SOUND. Leaf/proof seam: SOUND. Only NEW item
is the documented WASM↔native ~40-leaf parity gap (MEDIUM, latent, distinct from #1845).
