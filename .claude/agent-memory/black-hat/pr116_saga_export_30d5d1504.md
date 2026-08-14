# PR #116 FFI saga export `tool_invoke_cross_context_saga` — REBASED @30d5d1504 (onto main 29b87c8a5, WASM removed)

Native FFI exports of §6.2.4 cross-context tool-invocation saga across PyO3/NAPI/UniFFI.
Calls `Supervisor::start_cross_context_tool_invocation_saga`. **NO PRODUCTION BREAK FOUND** (2 audits).
supervisor.rs now at `crates/scp-runtime/src/context/supervisor/supervisor.rs` (moved into subdir).

## Re-attack @30d5d1504 (post-rebase) — all 6 goals re-verified, code identical to pre-rebase
- Caller forgery RESISTS: bridge axis-a (registry/custody contains caller_did) + axis-b is_member;
  producer gate-1 is_member(caller_hex,did)→13050 (supervisor.rs:5504), gate-2
  has_established_tool_interface→13062 (:5528). All authorize-BEFORE-reserve. Co-resident model sound
  (hosting a DID ⇒ custody-of-secret; can't assert a victim's DID).
- ucan_proof_id: forwarded to PrepareB on TARGET actor mailbox (:7096), validated target-side vs
  caller_did. caller_source_role read SUPERVISOR-side via member_role(caller_hex,did) (:5556), NOT
  envelope-asserted → carried to PrepareB for InboundPolicy.allowed_source_roles. No new confused deputy.
- Chokepoint context_id_to_bytes (state.rs:2072 decode-64hex-else-SHA256) on all 3 bridges; producer
  hex::encode round-trips. is_member/has_interface route by RAW string via dispatch_query (actors keyed
  hex(digest)=canonical 64hex). Non-canonical id → no actor → fail closed both axes. No double-hash.
- retry_after_ms None NEVER→0: decompose_saga_error (common/saga_errors.rs:105) preserves Option
  structurally; all 3 map_saga_error arms (pyo3 tools.rs:968, napi:688, uniffi bridge.rs:5429) carry it
  through; tested (None-never-0 asserts in each). NAPI renders `(retry_after_ms=null)` suffix. Codes:
  NeedsRepair=SAGA_13065, Busy=SAGA_13066 (error_codes.rs:994-997); Aborted sub-code formatted inline
  from producer numeric (13050/13062/13067).
- decode_asserted_nonce hex::decode→try_into [u8;16] fail-closed on all 3 (pyo3:1011/napi:748/uniffi
  bridge.rs:5454). Uppercase-hex accepted (benign).

## EMPIRICAL gate mutation (item 6) — re-confirmed @30d5d1504
- Neutralized BOTH PyO3 axis-a + axis-b (`if false && ...`, tokens preserved) in tools.rs.
  → `cargo test -p scp-testing --test pipeline_wiring saga_export_wires`: ALL 3 STILL PASS.
  Gate is coarse fn_body_contains substring tripwire (BLACK-116-01 accepted). NOT a guarantee.
- e2e CATCHES it: `cargo test -p scp-ffi --features allow_in_memory_custody --test e2e_bridge xctx_saga`
  → 3 FAILED (unhosted_caller, hosted_non_member, member_but_unhosted). Restored clean after.

## KEY INSIGHT from mutation — defense-in-depth layering + e2e coverage GAP (LOW, test-only)
With bridge binding neutralized, an unhosted/non-member caller is STILL rejected — by PRODUCER gate-1
is_member (13050). First 2 e2e tests failed only on asserting the BRIDGE-specific message wording, not
on authz bypass (authz held at producer). The 3rd test (member_but_unhosted) failed via SCP-IDENT-1001
(resolve_context_signing_key needs hosted creator key) — NOT cleanly via axis-a — because that test
uses caller_did = CREATOR of caller_ctx, so signing-resolution ALSO fail-closes.
- The truly axis-a-SOLE-guard scenario is UNCOVERED by any e2e: caller_did = a NON-creator secondary
  member of a context whose creator IS hosted (→ signing resolves the hosted creator OK; producer
  gate-1 is_member passes since caller IS a member; gate-2 interface attacker-controllable via hosted
  creator/admin). ONLY bridge axis-a stands between an unhosted-but-member caller and saga execution
  asserting caller_did = a foreign identity (caller-DID provenance spoof on the §6.2.4 receipt).
- PRODUCTION CODE IS CORRECT (axis-a present on all 3 bridges). This is a TEST-ROBUSTNESS gap only:
  add a dedicated secondary-member e2e case proving axis-a is the sole control there. Same as prior note.

## NAPI divergence (benign, not a break)
- napi tools.rs:941 `with_context(...).unwrap_or(None)` swallows ctx-not-found → echo handler; PyO3 uses
  `?`. Executor only PRODUCES a value, validated vs tool output-schema at Commit-B; authz gated by
  producer. NAPI/UniFFI derive both ctx ids from instance-affine handles (stronger than PyO3 free strings).
