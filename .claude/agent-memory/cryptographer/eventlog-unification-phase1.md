# Event-Log Unification Phase 1 (feat/eventlog-unification-phase1, HEAD 8dc96e253)

Realizes merged ADR-011 amendment. Reviewed 2026-06-17 — APPROVE, no blocking findings.

## What landed
- EventType 36 -> 76 (closed set, no catch-all). Tags 0-35 pinned unchanged; 36-75 ADR declaration order. event_type_tag u16 const fn exhaustive (no `_`).
- payload.rs: per-variant positional rmp_serde encoder. 8 structs. ALL field types deterministic (String/u64/[u8;32]/Vec<String>) — no HashMap/HashSet/f64. Field order = wire contract. assert_positional_array test checks fixarray 0x9N (NOT to_vec_named). ContextTombstonedPayload field renamed destination_id (spec fidelity, consistent).
- is_structural_event (pruning.rs): exhaustive match no `_` — forces compile-time decision on new variants. ADR-030 §2c. ContentKeysRotated/RecoveryEpochAdvanced=structural; KeyEpochAdvance(sender-key)=operational deliberate. Test=full 76-row EXPECTED table.
- §25.8 Vectors 32/33 KAT: typed-leaf SHA-256(0x00||rmp_serde(Event)) + checkpoint root 0x39e50b87...b54d40d. GENUINELY derived (test builds via production tree::append then pins). Seed 0x0102..20, did:dht:z.
- Vector 33: checkpoint.merkle_root==tree::root (RFC 6962 NOT chain head). compute_checkpoint_canonical_hash = SHA-256("SCP-CHECKPOINT-V1:"||len-prefixed ctx/did||event_count_BE||merkle_root||epoch_tag(0x01||epoch_BE|0x00)||ts_BE). Sig verified vs KAT key in test.
- wasm_conformance.rs: asserts tree::event_type_tag is closed 76-distinct bijection over contiguous 0..=75. WASM bridge calls EXACT fn (dropped stale hand-mirror).

## Commit 8dc96e253 (prompt claimed test-only)
- Also touched pruning.rs + payload.rs, BUT pruning.rs = #[test] body rewrite only; payload.rs = doc-comment only. is_structural_event prod fn UNCHANGED. No crypto/prod logic change.

## Signature-preimage dedup
- Runtime tests now call tree::compute_event_canonical_hash directly.
- 2 other copies (pruning.rs:602, tiered_storage.rs:846) BOTH #[cfg(test)] local helpers, byte-identical to canonical. Pre-existing, untouched. No drift.

## Environmental gotcha
- `cargo test -p scp-event-log` (no features) => 116 FAIL "unsupported DID format: did:key:" (gated behind `testing`, issue #128). MUST use --features testing => 197/197 pass. KAT uses did:dht so passes standalone.

## Pre-existing doc staleness (NOT this branch)
- test_vectors.rs:52-63 vector_15 comment says "EventLog returns [0u8;32] for empty logs" — FALSE. Prod tree::root returns SHA-256("") via empty_tree_root() (tree.rs:223). Local const never fed to sig/checkpoint. Harmless but misleading; should correct.
