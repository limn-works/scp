---
name: pr116-ffi-saga-export
description: PR #116 FFI export of §6.2.4 xctx tool-invoke saga — caller-principal binding attack surface across PyO3/NAPI/UniFFI
metadata:
  type: project
---

# PR #116 — FFI saga export (tool_invoke_cross_context_saga)

Branch feat/116-ffi-saga-export @1f84dd9a9. Wraps producer
`start_cross_context_tool_invocation_saga` (supervisor.rs:5478). 3 bridges:
PyO3 (scp-ffi/src/tools.rs:1130/1927), NAPI (napi/src/tools.rs:856 + scp.rs entry),
UniFFI (uniffi/src/bridge.rs:5503 + 12305).

## CORE TRUST ASSUMPTION (co-resident model): hosting == authentication
`enforce_caller_principal_binding` = (a) `identity_registry_contains(caller_did)`
+ (b) `supervisor.is_member(caller_context_id, caller_did)`. Both fail-closed.
NO per-call cryptographic proof of WHICH hosted identity the caller is. The
process holds ALL hosted identities' keys equally → in a multi-tenant host
(server hosting many users' identities via repeated identity_create), the binding
passes for ANY hosted DID. Attacker code hosting victim V's identity can assert
caller_did=V. This is BY DESIGN per ADR-049 §3a forward-obligation
(supervisor.rs:5438-5458): "FFI MUST bind caller_did to authenticated FFI
principal/channel — NOT merely membership." The bridge discharges it as
registry-presence, which IS the co-resident channel-auth. SOUND for the
intended single-tenant SDK process; the multi-tenant server deployment is the
documented out-of-scope threat — flag in threat model, not a code bug.

## CROSS-BRIDGE INCONSISTENCY (real, MEDIUM, pre-existing pattern)
- PyO3: caller_context_id/target_context_id are FREE caller-asserted STRINGS
  (tools.rs:1929-1930). Attack surface = attacker names any caller_ctx they're a
  member of + any target. Gates foreclose abuse (see below) but the id is unbound.
- NAPI + UniFFI: ids DERIVED from owned, instance-affine context HANDLES
  (source_handle.context_id, check_handle/napi_check_handle PERM-3030). STRONGER.
- Only caller_did is a free string in all three.
- Net: PyO3 weaker on context-id binding. Not exploitable past supervisor gates,
  but asymmetric hardening. Worth normalizing PyO3 to require handle-equivalents.

## WHY GATES FORECLOSE THE OBVIOUS ESCALATIONS
- Supervisor gate 1 (5504): caller_did is_member of caller_hex → can't name a
  caller ctx you don't belong to. Runs BEFORE reservation.
- Supervisor gate 2 (5528): has_established_tool_interface(caller→target) §6.2.0.1
  standing consent → can't name arbitrary victim target. Runs BEFORE reservation.
- So Busy.contended_context (attack 4) only EVER surfaces for a caller already
  past gate1+gate2 → only its OWN ctx or a legit interface partner. NO victim leak.
  Matches prior typed-SagaError memory note.

## KEY CONFUSION (attack 2) — bridge-trusted target key, NOT independently resolved
- verify_commit_b_receipt (7260) verifies receipt against ctx.target_signing_key
  = the SAME key the bridge supplied. Code EXPLICITLY admits (7223-7235) it does
  NOT do independent signer-authorization (governance resolution that the key is
  the Active Signing Key for target_context_id) — that's "the DOWNSTREAM receipt
  CONSUMER's burden." Bridge resolve_context_signing_key resolves the TARGET
  context's creator_did key from local custody → requires target creator hosted
  locally (with_identity fails otherwise). Caller can't summon a foreign key.
  Sound within co-resident model; the deferred independent-resolution is a
  documented consumer obligation, not a PR defect.

## REPLAY (attack 3) — nonce/timestamp caller-supplied, B owns dedup
- FFI decodes nonce 16B fail-closed (decode_asserted_nonce), passes through. No
  FFI-side dedup. B's §6.2.4 dedup TTL=600s + skew=300s owns freshness. FFI
  surface enables no replay the co-resident model doesn't already foreclose
  (the 1-tick boundary window is the pre-existing BLACK-XCTX-01 twin, not new).

## CHOKEPOINT (attack 5) — consistent across all 3 bridges
- All use context_id_to_bytes (decode-64-hex-else-SHA256), ADR-056. Verified
  prior: routing(string)/keying(digest) split, no double-hash. Tests assert
  reaching 13062 proves digest keyed right actor (not spurious ContextNotRegistered).

## VERDICT: no break within the stated co-resident threat model. Two items to
raise: (1) cross-bridge id-binding asymmetry (PyO3 free strings vs NAPI/UniFFI
handles); (2) multi-tenant-host caller_did spoofing is a real residual the
binding cannot close (process holds all keys) — must be explicit in threat model.

## SECOND PASS @ff5a0f725 (post-consolidation) — STILL NO BREAK
- HEAD added since 1f84dd9a9: `decompose_saga_error` consolidation (commit dea08b624,
  common/src/saga_errors.rs), `# Trust boundary` rustdoc (5e97e362f), mutation-resistant
  behavioral tests (ff5a0f725). PR does NOT touch scp-runtime — ALL supervisor gates
  unchanged from main; prior gate analysis stands verbatim.
- decompose_saga_error is BEHAVIOR-PRESERVING: byte-identical to the prior inline
  map_saga_error (diffed 1f84dd9a9). Same RateLimited→Option, None-never-0,
  format!("SCP-SAGA-{code}"), same message pass-through, same fixed 13065/13066. NO new
  leak/oracle. SagaAbortReason has exactly 2 variants → match exhaustive, a 3rd = compile
  error. Producer `code` carried STRUCTURALLY, faithful (13050-collapse concern was OTHER
  PR ba3ef1f5a's unwrap_or, NOT this one).
- All 3 bridges route identically (only msg:/message: + napi Display suffix differ). napi
  Display renders retry_after_ms=null for None (error.rs:127-130 unchanged). contended/
  saga_id supervisor-minted (ctx-id/UUIDv4), not attacker free-text → no suffix injection.
  saga_errors gated behind `resolvers` (lib.rs:153); WASM never compiles it → no fallback.
- ff5a0f725 tests GENUINELY mutation-resistant: assert SAGA_13050 AND pin bridge-UNIQUE
  msg substring ("is not an identity hosted by this bridge instance" / "is hosted by this
  bridge but is not a member of") absent from supervisor gate-1 → deleting either bridge
  axis fails the test. axis-a w/ unhosted DID, axis-b w/ hosted non-member = real vectors.
- Floors RAISED: MIN_ACTIVE_PIPELINE_ASSERTIONS 41→44, MIN_PARITY_OPERATIONS 105→106.
  capability-matrix false×4 w/ per-SDK exemptions citing bridge export + #1939 PR-6c.
  No enforcement file weakened.
- Co-resident residual + PyO3-string asymmetry now documented in `# Trust boundary`
  rustdoc on all 3 entry points (tools.rs:1869, napi/scp.rs:2876, uniffi:12256).

## RE-AUDIT @4c4e3171f (HEAD, REBASED onto current main: WASM in-browser backend REMOVED #1942/#1941). isolated wt /private/tmp/scp-116-bh10. NO new break.
- Rebase moved producer: supervisor.rs -> supervisor/supervisor.rs (dir module); validate_ucan_rebind +
  gates moved to actor/handlers/saga.rs. SEMANTICS BYTE-IDENTICAL: gate-1 is_member 13050
  (supervisor.rs:5504), gate-2 has_established_tool_interface 13062 (:5528), both authorize-before-
  reserve; presenting_agent_did=req.caller_did (saga.rs:1130) closes confused-deputy; require_spending_ucan
  && ucan_proof_id.is_none()=>13015 (saga.rs:1197) closes None-proof bypass on gated interface;
  context_id_to_bytes (state.rs:2072) decode-64-lc-hex-else-SHA256 unchanged. decompose_saga_error
  (saga_errors.rs:105) structural-on-enum, None-never-0, format SCP-SAGA-{code} for Aborted only.
- WASM-removal angle CLEAN: saga_errors behind `resolvers` feature (lib.rs:153), never compiled for
  WASM; saga never on WASM (no Supervisor, ADR-034); browser=remote thin client ADR-055 -> no saga
  concern. Matrix exemptions correctly omit browser/wasm.
- EMPIRICAL MUTATION (built+ran, reverted, tree clean):
  * PyO3 axis-a `if false &&` => xctx_saga_member_but_unhosted FAILS (got SCP-IDENT-1001 signing-key
    not-found RuntimeError, != SagaAbortedError); axis-b GREEN. PyO3 INCIDENTAL DiD (signing-key blocks).
  * NAPI axis-a `if false &&` => member-but-unhosted FAILS (got SCP-SAGA-13062 gate-2, != 13050);
    axis-b GREEN. NAPI NO incidental DiD — reaches PRODUCER; axis-a SOLE net for BLACK-116-01 residual
    (would reach commit if caller had own->target interface). axis-a load-bearing; test is real defense.
  * Baseline: PyO3 1/1, NAPI 4/4, UniFFI 5/5 saga tests pass.
- HEAD 4c4e3171f gates UniFFI axis-a test `#[cfg(feature="allow_in_memory_custody")]` + adds
  scp-core/testing to uniffi allow_in_memory_custody (for test_insert_member). NO coverage hole:
  CI ci.yml:430 nextest --workspace --features scp-ffi-uniffi/allow_in_memory_custody => test RUNS.
  Prod ci.yml:543 `cargo build -p scp-ffi-uniffi --features server` (no allow_in_memory_custody) =>
  test+test_insert_member absent from prod cdylib. Edge doesn't widen prod (feature already dev-only).
- pipeline_wiring fn_body_contains gate STILL forgeable (if true{return}); behavioral tests are real net.
VERDICT @4c4e3171f: NO new exploitable gap from WASM-removal rebase. All 5 goals re-verified CLOSED
empirically. Test-gating fix sound, no CI coverage hole. Ship-ready from black-hat perspective.
