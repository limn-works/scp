# #116/PR-6b FFI export of §6.2.4 cross-context tool-invocation saga -- 2026-06-29 -- ZERO FINDINGS

Branch feat/116-ffi-saga-export (HEAD 1f84dd9a9). Native FFI exports (PyO3/NAPI/UniFFI) of
`tool_invoke_cross_context_saga` wrapping merged producer
`Supervisor::start_cross_context_tool_invocation_saga` (supervisor.rs:5478).

## Caller-principal binding (load-bearing, §6.2.4 + ADR-049 §3a) -- SOUND
- `enforce_caller_principal_binding` in all 3 bridges (pyo3 tools.rs:1062, napi tools.rs:797, uniffi bridge.rs:5503): two axes, BOTH fail-closed via `?` BEFORE saga dispatch:
  (a) caller_did ∈ per-instance identity registry (pyo3/napi `identity_registry_contains`; uniffi `identity_custody_registry(bi).contains_key`) -- THE load-bearing addition. Registry is per-instance (`bi.identity_registry` / `bi.*custody*`), NOT process-global -> no cross-tenant leak.
  (b) `supervisor.is_member(caller_context_id, caller_did)` -- duplicates producer gate 1 but membership alone is necessary-not-sufficient.
- Co-resident trust model: "channel-authenticated principal" = identity THIS instance hosts. Holding the bridge instance handle = controlling all its hosted identities. This IS the defined boundary, not a gap. Doc comments state it correctly.
- caller_context_id/target_context_id derived from OWNED instance-affine handles in NAPI (`source_handle.context_id()`) and UniFFI (`source_handle.context_id`, after `check_handle` affinity) -- stronger than PyO3 free strings. PyO3 validates strings + is_member.
- Producer gate 1 (is_member, no-reserve) + gate 2 (has_established_tool_interface, no-reserve, BLACK-624-02) BOTH run BEFORE per-set reservation -> SagaError::Busy.contended_context ∈ {caller_hex,target_hex} only, surfaced only after caller authorized for both -> NO cross-context oracle.

## Other focus areas -- all clean
- (2) nonce/timestamp/chain_depth stay caller-asserted; passed straight through; B owns dedup (`xctx_nonce_dedup` supervisor.rs:12495) + skew + chain_depth+1 at Prepare-B (7081-7100,7496,7918). Correct per §6.2.4 co-resident. NAPI extra: rejects negative/non-lossless BigInt timestamp at boundary (defense-in-depth).
- (3) signing keys: target key from target handle/creator_did, caller key from caller handle/creator_did; passed as named `SagaSigningKeys{target,caller}` (no positional swap). resolve via custody export (uniffi resolve_uniffi_signing_key per-handle; pyo3/napi resolve_context_signing_key via creator_did). NO key confusion. Private key never crosses FFI (custody.sign for export-path).
- (4) error surfaces: all 3 `map_saga_error` read structured data off typed SagaError variants, NO message re-parse; retry_after_ms None never coerced to 0; messages supervisor-authored (only hex ids + dids caller already authorized for). No paths/stack/internal-state leak. Fail-closed.
- (5) chokepoint `context_id_to_bytes` (state.rs:2072, decode-64-lowercase-hex-else-SHA256) used for BOTH ids in all 3 bridges -> no double-hash ContextNotRegistered.
- (6) ucan_proof_id opaque Option<String> passed through; resolved/re-validated target-side Prepare-B (7081-7096) -> confused-deputy foreclosed.

## Tests genuinely exercise (not gamed)
e2e_bridge.rs: unhosted-caller->13050, hosted-non-member->13050, authenticated-reaches-target-gate (asserts msg does NOT contain 13050), malformed-nonce fail-closed, full governance-established-interface commit. Real negative coverage.

CONCLUSION: passed all 4 categories. No injection/auth/secrets/leakage issues introduced by this PR.
