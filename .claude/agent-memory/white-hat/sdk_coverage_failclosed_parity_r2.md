---
name: sdk-coverage-failclosed-parity-r2
description: Fresh defensive review of fix/sdk-coverage-fail-closed-and-parity @02cf55597 — PERM-3030 re-raise, test-env detection, fail-closed gate, ADR-051. APPROVED.
metadata:
  type: project
---

# fix/sdk-coverage-fail-closed-and-parity @ 02cf55597 (2026-06-20 fresh review)

Verdict: **APPROVED**. No BLOCKER/HIGH/MED. LOW notes only.

## Verified-correct defenses (independently traced this pass)

- **PERM-3030 re-raise reachable on BOTH bridges.** PyO3 `From<HandleAffinityError> for ScpPyError` → `UcanError{code:PERM_3030}` (error.rs:737); Display `[{code}] permission error: {message}` (error.rs:158) ⇒ string starts `[SCP-PERM-3030] permission error:`. Python `except bridge.UcanError` catches it (HandleAffinity maps to UcanError), `startswith("[SCP-PERM-3030]")` re-raises (trust.py:762). NAPI `#[error("[{code}] permission error: {message}")]` (napi/error.rs:69) ⇒ TS regex `/^\[SCP-PERM-3030\]/` matches (trust.ts:461), runs AFTER `/^\[SCP-PERM-\d+\]/` gate so 3030 is classified-then-re-raised, not dropped as genuine fault. **Both produce the bracketed prefix the guards depend on.**
- **Test-env detection = 2 independent layers.** (1) `assertTestEnvironment` throws outside test/dev (test-guard.ts), frozen at module load via IIFE `_ENV_AT_LOAD` + `Object.hasOwn` (anti-prototype-pollution, anti-runtime-mutation). (2) LOAD-BEARING: bridge-swap slot keyed by module-private `NATIVE_OVERRIDE: unique symbol` (scp.ts:486) that never escapes module — unforgeable. Defeating env guard still can't reach the override slot. Env guard correctly = defense-in-depth, not sole control.
- **Coverage gate fail-closed & bounded.** check-sdk-coverage.py: suffix/substring match REMOVED (let ~23 fabricated names pass); only ALIASES (positive whitelist) + exact name-variant. Missing SDK key→ERROR; non-bool/None cell→ERROR; true-but-no-symbol-no-exemption→ERROR; blank exemption reason→ERROR; all-exempted-with-zero-statically-verified→ERROR (op_verified_sdks gate, L1219-1231) closes prose escape hatch. Live: 222 ops/0 errors/1 documented exemption. Self-tests (test_check_sdk_coverage.py) mutation-aware: assert returncode==1 on each fail path. 9/9 pass.
- **behavioralRecord** NOT actually null on success path — both SDKs return a record with `contexts_participated=0` (was fabricated `=1`). Zeros are conservative (can't inflate trust) but verified-zero vs not-computed-zero indistinguishable to relying party (LOW legibility gap). The diff title "honest null" is imprecise; null only on event-log-query failure.

## ADR-051 (Proposed, design-only — verified zero impl symbols)
Separate `PreRotationCustodyProvider` interface structurally enforces spec §9.7.4.1 §3 substrate isolation (vs documentation). `generate()` keeps key in HSM/enclave substrate; `import_seed_bytes` unblocks callback-custody migration; non-recoverability conformance test proposed. Correctly sequenced spec-before-code.

## LOW findings
- LOW-1: "honest null" framing imprecise; success path = zeroed record, not null. Document that 0 = not-computed, not verified-zero.
- LOW-2 (denylist-of-one): PERM-3030 re-raise is a single-code denylist; holds only while PERM-3020-3023 stay producer-less. A future non-UCAN PERM producer in ucan_validate would silently re-classify as trust verdict. Prefer positive allowlist of genuine UCAN-stage codes.
- LOW (alignment): garbled doubled citation in Kotlin IdentityAdvancedBridgeTest.kt:254-255 ("§9.12 / §9.12, ADR-003 §4b").
