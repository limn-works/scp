---
name: outlet-2196-active-gate
description: #2196 runtime active-state gate on outlet reserve paths + error-masking fix — review verdict (substantially clean, 1 LOW incomplete-fix)
metadata:
  type: project
---

# #2196 outlet active-state gate + error-masking fix (branch fix/outlet-2196-active-gate @68eeadbd1, base fa28f925c)

SUBSTANTIALLY CLEAN. 8 new tests pass (isolated CARGO_TARGET_DIR — shared-target contention silently served STALE binary; `--list` omitted the new tests until isolated). clippy -p scp-runtime clean.

Verified all 6 audit items:
- `ensure_context_active` (outlets_helpers.rs:600) is genuine FIRST predicate in all 3 forward-debit reserves: reserve_outlet_economy (:708 before hard-rate consume :717), reserve_outlet_stream_economy (:1198 before :1205), reserve_stream_grant_escrow (:1436 before zero-cost early-return + debit). Reads handle.state() = shared Arc<ArcSwap<ContextState>> (mod.rs:171) — authoritative, not FFI cache.
- Only forward-debit reserves gated; NO settle/refund/reconcile gated.
- Only ONE InvocationError enum (invoke.rs:57); outlets_helpers imports it. No dual-enum confusion. 6080 marker producer/consumer share const SCP_OUTLET_6080_MARKER; rsplit(": ") state-extraction robust (no ContextState Display variant contains ": "). Arm ordering in reserve_error_to_open_rejection safe (6080 msg can't contain escrow/insufficient slugs & vice-versa).
- invoke_outlet sync surface is EXACTLY 4 permanent variants (ContextNotActive/OutletNotFound/InvokerNotAuthorized/InputValidationFailed, invoke.rs:3462-3478); invocation_error_to_open_rejection maps all → Never. Correct.
- 3 bridge caller-axis guards (OUTLET_6010) intact + primary (FFI diffs comment-only); target-axis (OUTLET_6011) correctly demoted to defense-in-depth since runtime reserve runs on TARGET.
- to_invocation_error new ContextNotActive arm: all callers use result Display-only (supervisor.rs:6559/6765 saga abort msg), no variant-match breakage.

## LOW finding (incomplete fix, pre-existing, same function this PR fixed)
reserve_error_to_open_rejection (outlets_helpers.rs:3044) catch-all `_ => AdmissionRateLimited` still masks the PERMANENT membership denial `SCP-OUTLET-6089` (reserve_outlet_stream_economy :1237, plain PermissionDenied, reachable — open_outlet_stream_phase1 has no membership check before reserve) as CODE_TRANSPORT_FAULT = RetryPolicy::WithBackoff (RETRYABLE). Contradicts the PR's own stated invariant ("a permanent failure must never be reported as a transient, retryable condition") which it fixed only for 6080. Impact: retry-storm UX only — rejection is PRE-DEBIT so no money moves / no security bypass. Persist-failure `return Err(err)` also hits catch-all but retryable is defensible there (genuinely transient). Fix if pursued: add a guarded arm for SCP-OUTLET-6089 (and generally non-economic/non-ratelimit permission denials) → a non-retryable Authorization/Protocol class.

## LOW RESOLVED @ e5bb3d136 (verified 2026-08-02, no new bug)
Fix commit added the guarded arm BEFORE the catch-all: `PermissionDenied(msg) if msg.contains(SCP_OUTLET_6089_MARKER) => CaveatPostInputViolation { slug: SLUG_AUTHORIZATION_DENIED }`. slug=="authorization.denied" (not input-schema) → error_code()=CODE_AUTHORIZATION_DENIED (SCP-OUTLET-6110) → error_code_to_retry_policy=Never (error_codes.rs:564). New const SCP_OUTLET_6089_MARKER shared by producer (:1248 format!) + consumer (:3064) — can't drift (mirrors 6080). Persist-failure DELIBERATELY left on catch-all (genuinely transient, correct). New test `non_member_open_maps_to_non_retryable_authorization` drives REAL non-member reserve (no add_member → membership gate, not active gate), asserts code != CODE_TRANSPORT_FAULT AND == CODE_AUTHORIZATION_DENIED AND retry==Never — discriminating (fails if arm removed → catch-all → TRANSPORT_FAULT). No marker collision (6080/6089 differ in last digit, neither is substring of the other). Complete permanent-error set now non-retryable: 6080(active)/6089(member)/escrow-overflow/insufficient-funds; only transient RateLimited+PersistenceFailed on retryable path. Test passes + clippy clean (isolated CARGO_TARGET_DIR).
