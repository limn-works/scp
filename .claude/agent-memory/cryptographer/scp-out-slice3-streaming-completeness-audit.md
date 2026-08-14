---
name: scp-out-slice3-streaming-completeness-audit
description: SCP-OUT-036/044-049 outlet streaming-saga slice-3 crypto completeness audit — surface COMPLETE + SOUND, all 6 domains reproduced byte-exact
metadata:
  type: project
---

# Outlet streaming-saga slice-3 completeness audit (branch feat/adr062-slice11-relay-querier @04c666220; where 047 #2195 + 049 #2198 merged)

VERDICT: crypto surface COMPLETE + SOUND. All 6 domain separators have compute fn + sign/verify + KAT + golden; I re-reproduced every high-value golden byte-exact in Python (pynacl+hashlib, no scp crates).

## The 6 domains (all in crates/scp-protocol/src/context/outlets/)
1. SCP-OUTLET-CAVEAT-BIND-V1: stream.rs:294 compute_caveats_binding — len-prefixed ucan_cid/invoker_did/caveats_jcs, raw req_id(16)+est(u32be). KAT 1950.
2. SCP-OUTLET-CHUNK-SIG-V1: stream.rs:486 compute_chunk_sig_preimage / sign_chunk 519 / verify_chunk_signature 549 (verify_strict). KAT 1994.
3. SCP-OUTLET-CREDIT-V1: stream.rs:627 / sign_credit_grant 676 / verify_credit_signature 696 (verify_strict, binds stream_epoch). KAT 2133.
4. SCP-OUTLET-CANCEL-V1: stream.rs:770 / sign_cancel 810 / verify_cancel_signature 830 (verify_strict, next_seq runtime-derived). KAT 2219.
5. SCP-OUTLET-CHUNK-V1: stream.rs:1071 leaf(0x00) / 1092 interior(0x01) / 1127 compute_chunk_manifest_root (promote-not-dup) + MerkleFrontier 1221 (incremental, root()==oracle). 
6. SCP-XCTX-STREAM-RECEIPT-V1: cross_context_saga.rs:454 signing_preimage / sign 483 (sign_prehashed_preimage=det PureEdDSA) / verify 533 (verify_strict). KAT 1076.

## Reproduced byte-exact in Python (repro.py in scratchpad)
- seal caveats_binding 81e13f23… ✓; trunc b6cec67c… ✓ (empty InvocationCaveats JCS="{}")
- seal manifest root eaa73cad… ✓ (3 chunks, full chunk-sig+JCS+RFC6962) — proves chunk-sig preimage + JCS int-array encoding of request_id/sig (serde_bytes→JSON int array) + leaf/interior tags + promote-not-dup
- trunc full root 512c831c… ✓ (10) + prefix e746e95f… ✓ (first 5)
- stream_receipt_kat preimage 34ec3d62… ✓ + signature eaa9813d… ✓ (det Ed25519 over 32B prehashed preimage)
- operator/target pk d75a9801… = §25.2 RFC8032 TV1 (seed 9d61…7f60) ✓
- credit + cancel preimage structure ✓
- RFC-6962 CVE-2012-2459 immunity: my levelwise==canonical split-MTH for ALL n=1..1199 → NONE mismatch. Frontier==batch oracle proven by property test frontier_root_and_billed_match_oracle (RAN, passes).

## chunks_billed accounting (COMPLETE, fail-closed)
- runtime/…/stream.rs:1467 compute_chunks_billed_ref (filters chunk.sequence<=ceiling, NOT slice index — matches frontier); verify_chunks_billed 1494 (full equality); verify_outlet_invoked_event_local 1586 (<= backstop, event-only); verify_outlet_invoked_event_manifest 1626 (full re-derive at xctx reassembly). Fail-closed: refuses event at log-insert.
- MerkleFrontier WIRED in prod pump dispatch.rs:2747 (ingest_stream_chunk per emission) → manifest_root:frontier.root() committed at close 3258. RESOLVES old ADR-061 "0 prod callers/hardcoded [0u8;32]" gap.

## Findings (all minor, no blocker)
- OBSERVATION (task-premise drift, not code gap): browser (scp-client-wasm/src/lib.rs, ADR-057) exposes ONLY outlet_stream_compute_caveats_binding + outlet_stream_verify_chunk_signature — NOT credit/cancel SIGNING. Documented lib.rs:777 (control plane is runtime-backed, not wasm-safe). Task's "048 in-tab credit/cancel signing" reflects pre-ADR-057 arch; credit/cancel signing now lives in 3 native bridges (uniffi/napi/pyo3 outlet_stream.rs) with caller_did==invoker_did gate (§5.4.5:549 CRITICAL#1) at 3 sites each. Honest scoping.
- Cross-target consistency: browser wrappers CALL the same scp-protocol core fn (not a fork) → byte-identity by construction. KAT compute_caveats_binding_matches_core_helper is thus wrapper==core (borderline tautological) but that's the STRONGEST guarantee — no divergent impl to drift. Not a defect.
- LOW doc: §5.4.5:563 writes chunks_billed_ref index "i <= cancel_ack_seq"; code uses chunk.sequence (documented intentional — renumbered outer-pump seq). Spec text imprecise, code correct.

Tests: scp-protocol outlets::stream 57 passed/0 failed/0 ignored (207s). Conformance harness recomputes roots from fresh sigs vs pinned hex (real KAT, not round-trip), no #[ignore].
