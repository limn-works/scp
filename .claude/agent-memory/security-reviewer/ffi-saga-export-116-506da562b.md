# #116 FFI export of §6.2.4 xctx-tool saga (PyO3/NAPI/UniFFI) — 506da562b — ZERO FINDINGS

Branch feat/116-ffi-saga-export. Re-review of an iteration past ff5a0f725 (prior memory entry).
op `tool_invoke_cross_context_saga` on all 3 native bridges. Producer
Supervisor::start_cross_context_tool_invocation_saga (supervisor.rs:5478) untouched.

## Why sound (verified line-by-line this pass):
- **Caller-principal binding** (enforce_caller_principal_binding, all 3 bridges): axis-a
  identity_registry_contains/identity_custody_registry.contains (hosted on THIS instance) +
  axis-b supervisor.is_member(caller_ctx, caller_did). Runs BEFORE producer. caller_did is
  validate_did'd first. NO TOCTOU benefit: producer re-runs is_member as authoritative gate-1
  (supervisor.rs:5504) under the actor — binding is defense-in-depth + axis-a is the load-bearing
  add. Multi-tenant caveat documented as forward obligation (single-tenant co-resident only).
- **Signing keys** resolved off the context's OWN creator_did (PyO3 with_context rt.creator_did →
  resolve_signing_key custody; NAPI source_handle.creator_did() → with_identity custody export;
  UniFFI resolve_uniffi_signing_key(&handle) off handle.signing_key) — NEVER caller input. No key
  confusion. Receipt signed by target's authorized key by construction. Gate 2
  (has_established_tool_interface, supervisor.rs:5527) forecloses naming a victim target before reserve.
- **Chokepoint** context_id_to_bytes (state.rs:2072): 64-hex → decode (round-trips producer's
  hex::encode, NO double-hash); else SHA-256. Identical in all 3 bridges. Bridge pre-check is_member
  uses raw string vs producer's hex(round-trip) — agree for 64-hex; for non-hex the PRODUCER is
  authoritative so security floor holds (divergence = availability only, pre-existing).
- **retry_after_ms** None never coerced to Some(0) — single home decompose_saga_error
  (common/saga_errors.rs), unit-tested. PyO3 args[2]=None (test), NAPI message-suffix renders literal
  "null", UniFFI Option<u64> structural.
- **Info leak**: contended_context (SagaBusy) is ALWAYS one of caller's OWN requested set members
  (try_reserve_context_set find() over context_set, supervisor.rs:5841) — never a 3rd-party id, no
  cross-saga oracle. Busy oracle only reachable AFTER gate-2 authorizes (already-authorized
  participant). Error msgs echo only caller-supplied ids/dids.
- **Typed-error mapping** forges nothing: SagaResult only saga_id (supervisor-minted, never input)
  + receipt + output. SagaSigningKeys carries borrowed &SigningKey (no bytes copied to output).
  SAGA_13050 reused for not-hosted AND not-member (intentional; both caller-axis reject).
- NAPI BigInt timestamp_ms validated fail-closed (signed||!lossless → reject). NAPI
  with_context...unwrap_or(None) handler → echo fallback is benign (supervisor validates output
  schema at Commit-B; gate-2 already authorized).
- Enforcement files additive only (bridge-aliases new entry). e2e_bridge required-features =
  allow_in_memory_custody gates the TEST not the cdylib (HEAD 3afc30c6c dropped unneeded `testing`).
- e2e tests REAL (not dead refs): unhosted→13050, hosted-non-member→13050 w/ bridge-unique
  "is hosted by this bridge but is not a member" substring (proves axis-b fired), auth-caller reaches
  target gate (!=13050), malformed-nonce fail-closed, full governance-established commit.

GOTCHA: worktree path /Users/alec/Developer/limn/scp/.claude/worktrees/ffi-saga-116 (NOT fuzz-pin).
