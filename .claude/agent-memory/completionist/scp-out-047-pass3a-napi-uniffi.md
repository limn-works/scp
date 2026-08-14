---
name: scp-out-047-pass3a-napi-uniffi
description: SCP-OUT-047 pass 3a verify — NAPI+UniFFI streaming-saga exports land, enforcement coverage-expanding, story correctly still pending
metadata:
  type: project
---

SCP-OUT-047 pass 3a (@fd33fadf2, branch feat/outlet-xctx-047-streaming-saga-ffi, worktree /Users/alec/Developer/limn/scp-wt-047) — VERIFIED COMPLETE for its scope.

**Why:** Mirrors PyO3 reference cross-context streaming-saga FFI (open/poll_next/recover_truncated_close) into NAPI + UniFFI bridges, reusing shared scp_ffi_common::streaming_saga driver so 3 bridges can't drift. Continuation of [[scp-out-047-ac5-ac6-ac8-pass2-signoff]].

**How to apply:** All 6 verify axes PASS.
1. All 3 ops on all 3 native bridges — PyO3 src/outlet_stream.rs, NAPI scp.rs (#[napi]) + outlet_stream.rs (_on helpers), UniFFI outlet_stream.rs inside #[uniffi::export] block 1553-1877.
2. 6 pass-1 exemptions REMOVED from bridge-aliases.json .exemptions; the 3 alias entries' uniffi/napi arrays filled with real export names. check-bridge-symmetry.sh = 0 findings exit 0 (script validates each alias resolves to a real `fn`).
3. MIN_PARITY 106→109 in ffi_conformance.rs w/ SCP-OUT-047 comment. All 6 parity/alias tests PASS (parity_operation_count_never_decreases, cross_bridge_parity_matrix, every_alias_resolves_to_a_real_fn_or_exemption, aliases_json_is_in_sync, etc).
4. Per-bridge tests REAL, no #[ignore]/dead let_=. Each bridge has xctx_streaming_saga_{unhosted_caller_rejected_before_saga (SCP-SAGA-13050), recover_unhosted_caller_rejected, recover_hosted_non_invoker_rejected (SCP-PERM-3001 + asserts entry NOT evicted)}. NAPI gated allow_in_memory_custody (3 PASS); UniFFI gated full triple allow_in_memory_custody+testing+outlet-capability-test-grant (3 PASS).
5. Security ordering mirrors PyO3 recover exactly: validate_did → channel-auth(hosted) → registry lookup → CRITICAL#1 invoker gate BEFORE key resolution → resolve target key → drive → evict-on-success-only. New UniffiKeyCustody::export_ed25519_signing_key dispatches to InMemory(gated)+Callback(PROD) — NOT a test nullifier; resolve_context_active_signing_key_by_id resolves real creator key from custody. No hardcoded None on auth path.
6. Scope correctly bounded: matrix 0 streaming-saga rows (pass 4), TS/Swift/Kotlin SDK 0 (pass 3b), Python SDK present (pass-1 ref). Story status = pending (verified in outlet.json).

Enforcement delta = COVERAGE-EXPANDING (remove exemptions + raise ratchet + fill alias arrays), NOT weakening. Only 2 enforcement files touched, both the legitimate expand kind. LESSON: NAPI test gating (allow_in_memory_custody alone) differs from UniFFI (full triple) — grep the mod cfg before running or nextest silently matches 0. Commit --no-verify justified: pre-existing base-branch scp-testing relay/node build drift, full-feature clippy clean.
