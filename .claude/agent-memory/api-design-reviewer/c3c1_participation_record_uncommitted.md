---
name: c3c1-participation-record-uncommitted
description: C3C-1 typed participation_record op review (branch c3c-ts-work uncommitted) — error-code cross-bridge convergence; latest round NEEDS REVISION on PyO3 CTX_2001-vs-CTX_2000 supervisor-failure divergence
metadata:
  type: project
---

Typed `participation_record` op §7.3.2 across PyO3/NAPI/UniFFI (WASM removed native-only; SDK wrappers = Phase 2C-2 / #1943). Branch c3c-ts-work, worktree agent-a1400c1b005b502a3. Scalar projection of scp-core `ParticipationFacts` (11 fields) via `From<&ParticipationRecord>`.

## Round 2 (2026-06-29) — NEEDS REVISION, 1 BLOCKER
Convergence progress vs Round 1: the two failure modes I flagged before are now FIXED — JSON-parse (PyO3:603/NAPI:437/UniFFI:14829) and attestation-sourcing (PyO3:639/NAPI:470/UniFFI:14864) all use VALID_7059 now. Good.

**BLOCKER — supervisor/compute failure code now diverges.** PyO3 maps it via `ScpPyError::context()` whose ctor HARDCODES **CTX_2001** (error.rs:199-204, "Context operation failed") ≠ NAPI/UniFFI **CTX_2000** ("Generic context error"; napi trust.rs:479, uniffi bridge.rs:14873/14879). Brief required all 3 = CTX_2000. `Supervisor::participation_record` collapses EVERY compute failure (empty log, provider err, TrustError::EmptyEventLog) → one ContextError::InvalidState, so this single mismatch spans the whole supervisor/compute + empty-log surface.
- Fix: PyO3 trust.rs:644 replace `.map_err(ScpPyError::context)` with explicit `ScpPyError::ContextError{ code: CTX_2000 }`. DON'T touch the shared `context()` ctor (other callers legitimately rely on CTX_2001).

## Sound (re-confirmed, don't re-flag)
- 11-field set identical in names+order across all 4 types (core + 3 bridge views), all via From<&ParticipationFacts>. produce_participation_profile derives from the same flattening (no drift).
- Type idiom correct: PyO3/UniFFI u64, NAPI i64 (#[allow cast_possible_wrap], matches NapiTrustScoreResult); event_log_root hex String everywhere.
- tool_invocation_count_anchored = honest first-class required bool (false until ADR-051). Structural truth-in-advertising.
- Full format validation (validate_context_id+validate_did) on all 3 with malformed-DID tests; typed-struct return strictly more type-safe than aggregate_trust_input's JSON String.
- NAPI VALID_7010 @trust.rs:114 is the `validation_error` helper for aggregate_trust_input, NOT this op.
- pipeline_wiring + bridge-aliases (wasm empty, wasm_required false) + ffi-allowlist (__repr__) + capability-matrix (4 SDK cells exempted → #1943) all registered.

## SUGGESTION (carried)
3-way dev-facing record name divergence (PyParticipationRecord→Python `ParticipationRecord` / NapiParticipationRecord / ParticipationRecordView) — converge in #1943 SDK wrappers. Canonical op name uniform (participation_record / participationRecord).

## Recurring lesson
For cross-bridge typed-op reviews: grep the per-bridge error code on EVERY failure path (JSON-parse / domain-source / not-initialized / compute-fail), not just the happy-path field-set. Beware convenience error ctors (ScpPyError::context) that silently stamp a code different from the literal const the sibling bridges use — the divergence hides behind the helper name.
