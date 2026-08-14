# PR #1867 fix/sdk-coverage-fail-closed-and-parity (c0bee8d22) -- 2026-06-22

Trust Layer-1 fail-closed + PERM-3001 allowlist + Python isinstance guard + check-sdk-coverage fail-closed.

## Findings
- HIGH (doc/claim vs reality): PR summary claims "all ~200 SCP methods wrapped with mapBridgeError()".
  FALSE on this branch. `grep mapBridgeError bindings/typescript/src/scp.ts` = 0 hits. scp.ts methods
  (ucanValidate, ucanMint, eventLogQuery, ...) dispatch via raw `this.#native.X` casts, no try/catch,
  no mapBridgeError. mapBridgeError only used in discovery.ts + internal/wasm.ts. trust.ts AND trust.py
  doc comments both ASSERT "scp.ucanValidate routes through mapBridgeError" -- the comment is wrong.
- NET SECURITY IMPACT = NONE (functional). The trust classification still works because the napi/WASM
  raw Error.message format is IDENTICAL to what mapBridgeError would produce:
  napi `#[error("[{code}] permission error: {message}")]` + `napi::Error::new(GenericFailure, e.to_string())`
  => JS Error.message = "[SCP-PERM-3001] permission error: <UcanError Display> — <advice>".
  validateOneCapUri regex /^\[SCP-PERM-3001\]/ matches raw message; __extractCoreError parses
  "] permission error: ". So fail-closed Layer-1 is intact. But the thrown error is a plain napi Error,
  NOT a typed ScpError -- so the re-thrown PERM-3030/PERM-3000/non-UCAN errors reach callers untyped
  (instanceof ScpError === false). That is the real cost: error TYPING is absent on the trust path,
  contradicting the PR's parity claim. LOW/MEDIUM as a typing-contract bug; doc comment is misleading.

## Verified correct
- PERM-3001 is the SOLE code for ALL UcanError variants (ucan_errors.rs exhaustive match, no _=>;
  napi error.rs:406 + wasm ucan.rs:426 both route through ucan_error_code). Allowlist /^\[SCP-PERM-3001\]/
  is complete -- no UcanError uses PERM-3002+. PERM-3000 = WASM manager/tool authz (NOT UcanError).
  PERM-3030 = handle-affinity (napi error.rs:545). Both correctly re-thrown by closed allowlist.
- Python trust.py catches by `bridge.UcanError` type + explicit startswith("[SCP-PERM-3030]") re-raise.
  TS gates on PERM-3001 prefix (re-throws PERM-3000/3030/non-UCAN). Net behavior equivalent.
- Fail-open inventory: NONE found. __extractAllCapabilityUris null/[] -> all-false (fail-closed).
  Non-object att entry -> entry?.with undefined -> "" -> filtered (TS); isinstance(dict) guard (PY).
  Both fail-closed. evaluateLayer1 starts optimistic but ANY failure narrows + fail-fast; isAllFalse
  collapse correct. Layer-2 eventLogQuery catch only swallows [SCP-CTX-\d+]/ContextError -> behavioralRecord=null
  (not a permissive verdict; behavioral is separate from cap verdict). Non-CTX re-thrown.
- Self-consistency vs authority: evaluateLayer1 validates token against its OWN att[i].with (not a
  caller op). Result is CapabilityValidation booleans returned in TrustEvaluation -- consumed by
  agent judgment, NOT used as an internal authz gate anywhere. Doc comments now correctly say so.

## Gotcha
- The "routes through mapBridgeError" doc comments in trust.ts (validateOneCapUri ~L493, evaluateLayer1
  ~L552, eventLogQuery catch ~L683) and trust.py (~L840) are factually wrong for scp.ts callers but
  harmless because napi/WASM message format already matches. Fix = either wrap scp.ts in mapBridgeError
  (makes claim true + gives typed errors) OR correct the comments to "the raw bridge message preserves
  the [SCP-PERM-NNNN] prefix".
