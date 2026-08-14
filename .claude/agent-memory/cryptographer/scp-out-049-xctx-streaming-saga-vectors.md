---
name: scp-out-049-xctx-streaming-saga-vectors
description: SCP-OUT-049 cross-context streaming-saga conformance vectors — KAT + drain + chunk-sig + manifest crypto verified byte-exact
metadata:
  type: project
---

# SCP-OUT-049 xctx streaming-saga conformance vectors (79de1bbed, feat/outlet-xctx-049-conformance)

VERDICT: KAT + crypto vectors SOUND, byte-exact, tamper-evident. All goldens INDEPENDENTLY reproduced in Python (I reproduced them, not just trusted the round-trip).

Files: tests/conformance/vectors/outlet_streaming_saga_vectors.json + crates/scp-testing/tests/integration/outlet_streaming_saga_conformance.rs (harness) + outlet_stream_vectors_common.rs (SCP-OUT-039 shared oracle) + protocol impl crates/scp-protocol/src/context/outlets/cross_context_saga.rs (receipt) + stream.rs (chunk sig / manifest / caveats_binding).

**Why:** cross-impl KAT stability + no self-consistent-but-wrong values.
**How to apply:** if these vectors or the receipt/manifest primitives change, re-reproduce goldens; the Python repro recipe below is authoritative.

## What I independently reproduced byte-exact
- stream_receipt_kat preimage 34ec3d62… AND signature eaa9813d… — SHA256(domain "SCP-XCTX-STREAM-RECEIPT-V1:" ‖ Fixed32 caller_ctx ‖ Fixed32 target_ctx ‖ VarBytes(u32be-len) caller_did ‖ RawBytes16 nonce (no len prefix) ‖ VarBytes outlet_reg_id ‖ Fixed32 stream_manifest_hash ‖ VarBytes outlet_invoked_event_id ‖ U8 chain_depth ‖ U64be timestamp_ms). Sig = deterministic PureEdDSA over the 32B preimage-as-message (NOT Ed25519ph; "prehashed"=fields-already-hashed). Seed = RFC-8032 §7.1 TV1 (pk d75a9801…, confirmed).
- seal_phase caveats_binding 81e13f23… + manifest root eaa73cad… (3 chunks)
- xctx_10_chunk caveats_binding e0a4c0b3… + root 3da9ea2e… (10 chunks)
- truncated_close full root 512c831c… (10) + prefix root e746e95f… (first 5, chunks[..crash_after_index=5])

## Recipe (for re-repro)
- caveats_binding = SHA256("SCP-OUTLET-CAVEAT-BIND-V1:" ‖ lp(ucan_cid) ‖ request_id(16) ‖ lp(invoker_did) ‖ u32be(estimated_chunk_count) ‖ lp(caveats_jcs)); empty InvocationCaveats JCS = "{}"; lp = u32be-len ‖ bytes.
- chunk sig preimage = SHA256("SCP-OUTLET-CHUNK-SIG-V1:" ‖ lp(context_id) ‖ lp(outlet_id) ‖ request_id(16) ‖ u64be(seq) ‖ caveats_binding(32) ‖ SHA256(payload_jcs)); payload_jcs = {"@type":"data","value":{"n":N}} (JCS sorted).
- leaf = SHA256("SCP-OUTLET-CHUNK-V1:" ‖ 0x00 ‖ chunk_jcs); chunk_jcs commits the SIG (keys sorted payload,request_id,sequence,sig; request_id/sig are serde_bytes → JSON int arrays under jcs). interior = SHA256("SCP-OUTLET-CHUNK-V1:" ‖ 0x01 ‖ L ‖ R).
- root = level-by-level pair-adjacent + PROMOTE odd (not duplicate). I cross-checked levelwise == canonical recursive RFC-6962 MTH (split-at-largest-pow2) for ALL n=1..1024 → identical (immune CVE-2012-2459). Empty → [0u8;32] sentinel.

## Answers to the 5 asks
1. Byte-exact: YES (preimage+sig both reproduce; harness pins hex, not a round-trip; pins derived pk too).
2. Tamper-evidence: all 9 preimage-covered fields mutated + verify() rejects each; signature field not covered (correct). Complete.
3. receive_side_drain_lossy: chunks genuinely operator-signed (signed_data_chunks signs+verifies each under ref key), gap 0,1,3 fires 6131 via ReceiverSequenceTracker (real contiguity check keyed on chunk.sequence — the CORRECT gap key per lesson-gap-detector-key; fires at delivered-index 2). Not mocked. NOTE: SCP-OUTLET-6131 = CODE_EXECUTION_CREDIT, a CONSOLIDATED code shared by stream-gap/credit-exhausted/stream-cap-exhausted (documented).
4. Manifest roots: real compute_chunk_manifest_root over real signed chunks, non-zero, prefix over correct first-N. All reproduced.
5. No prod key pattern: only SigningKey::from_bytes(&public TV1 seed); no OsRng/custody; EXPECTED_OPERATOR_PK pin makes corrupted seed fail loud. Fine.

## Observations (NOT crypto blockers)
- xctx_10_chunk `dual_log_identity` assert is TAUTOLOGICAL: builds two json objects from the SAME root_hex var and asserts a==a. Vacuous as a dual-log join test. Honestly scoped: harness doc says live dual event-log join proven runtime-side by xctx_streaming_saga_paid_drive_ac1_ac3_ac5_ac6 (supervisor.rs). Crypto (root/receipt) sound; the join assertion is test-theater. Test-quality, not crypto.
- Live drive to Committed / escrow / exactly-once exec deliberately NOT in this harness (Class-S spawn_actor_with_state is pub(in crate::context)); proven runtime-side. Honest §25.22 map.
- 10/10 tests pass (ran locally).
