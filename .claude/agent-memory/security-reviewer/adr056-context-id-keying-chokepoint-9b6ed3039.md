# ADR-056 Canonical Context-ID Keying Chokepoint (PR-A, HEAD 9b6ed3039) -- 2026-06-29 -- ZERO FINDINGS

Branch reviewed in /tmp/scp-prA-rev5 detached @ 9b6ed3039 (5 commits over origin/main).

## The change (ADR-056 Model A)
Canonical context identity = the 32-byte digest; id string = `hex(digest)`. `generate_context_id`
(scp-ffi/common/src/context_id.rs:50) = `hex::encode(OsRng[32])` => exactly 64 LOWERCASE hex,
unit-test-pinned. The bug fixed: raw `scp_protocol::context::context_id_bytes` = `SHA-256(id)` on a
real 64-hex id DOUBLE-HASHES => keys the wrong MLS group/sender key/event-log slot => silent
fail-open.

## Chokepoint
`scp_runtime::context::state::context_id_to_bytes` (state.rs:2068), promoted pub(crate)->pub.
Rule: if id is exactly 64 chars AND all `0-9a-f` => `hex::decode` to the 32-byte digest;
else fall through to raw `context_id_bytes` (SHA-256). Strict lowercase guard keeps uppercase /
non-64 / prefixed ids on the SHA-256 fallback (byte-identical to pre-change). Total fn, no
panic/unwrap (clippy-clean), fallthrough even if hex::decode ever rejected.

## Verification done
- Grepped whole tree for `context_id_bytes(`. Classified EVERY production hit:
  - ALL runtime keying paths now route through state::context_id_to_bytes: builder.rs:766
    (local wrapper now delegates to chokepoint), messaging_helpers (send/deliver/snapshot/buffer/
    timeout x5), key_destruction.rs:81, lifecycle_helpers (create/import/restore/export),
    governance_logic.rs:792, ttl.rs (local wrapper), mls/provider.rs seal+open AAD-consistency guards.
  - TWO production exceptions (both correct):
    * supervisor.rs:3547 synthetic `identity-private-state` -> deliberately RAW primitive
      (never 64-hex, byte-identical, documents intent).
    * state.rs:2088 resolver fallback (the chokepoint's own non-context branch).
  - supervisor.rs:9038 reconnect transport publish: changed RAW->chokepoint (correct).
  - All remaining `context_id_bytes(` hits = `#[cfg(test)]` fixtures or routing
    (context_routing_id/broadcast_routing_id) = OK.
- MLS seal/open guards (provider.rs:1571/1662): compare against context_id_to_bytes(ctx_str),
  not raw. NECESSARY -- caller supplies chokepoint-resolved bytes; using raw would fail-closed-reject
  every real 64-hex context. Still fail-closed on genuine divergence (non-64-hex mismatch test
  retained: open_rejects_context_id_str_that_does_not_resolve_to_context_id).
- FFI: 4 event-log sites (pyo3 event_log.rs, napi event_log.rs x2, uniffi bridge.rs:12776) +
  6 test-harness sites (pyo3/napi testing.rs: join_from_welcome / sync_sender_keys / decrypt) all
  rerouted to scp_core::context::state::context_id_to_bytes. CREATE-vs-JOIN convergence confirmed:
  creator deposits under chokepoint bytes (node.rs:293), joiner addresses via chokepoint
  (FFI wrappers pass &[u8;32] into node.rs:421 join_from_welcome). No divergence.
- pub-surface widening grants NO new capability: scp-core/src/lib.rs:91 already re-exported
  `scp_runtime::context::state` (NOT in this diff); only the fn visibility changed. Output =
  same 32 bytes any caller could compute via raw primitive + hex-decode.
- Gate removal (commit da017d9f0): `scripts/check-context-id-keying.sh` was NET-NEW in THIS PR
  (so removal nets to zero vs origin/main; not in protected enforcement-files list; NOT a CLAUDE.md
  violation). Regex pseudo-lexer can't tokenize Rust test-scope (lifetimes/block-comments/multiline
  strings each fail-open). Matches #1826 precedent (drop unsound gate for compiler enforcement).
  ci.yml deletion removes ONLY that job; adjacent saga-gating + bridge-lifecycle jobs untouched.
- Enforcement now = chokepoint (1 source of truth) + mutation-resistant test
  builder.rs:967 create_context_keys_crypto_under_decoded_digest_not_sha256 (drives real
  create_context, asserts crypto keyed under DECODED digest and NOT under SHA-256(id) via
  export_crypto_state empty/non-empty) + state.rs canonical_context_id_tests (6 tests:
  decode, synthetic fallthrough, standing-prefix, arbitrary, uppercase-hashes, near-64-lengths).
  ContextDigest newtype (compiler-enforced) = planned permanent mechanism, #1931.
- Standing-context digest (standing_helpers.rs:54 derive_standing_context_digest) UNCHANGED by
  ADR-056 (separately-tracked); prefixed id falls through chokepoint to SHA-256.
- WASM untouched (ADR-034, no Supervisor / event-log keying via this resolver). bridge.rs:375
  hasher = bridge_id registration id, not context keying.
- Pre-release => no migration/persisted-state divergence concern (feedback_no_migration_prerelease).

VERDICT: clean across injection/auth/secrets/leakage. Closes a real silent fail-open keying bug.
No residual production keying path addresses a real context under SHA-256.
