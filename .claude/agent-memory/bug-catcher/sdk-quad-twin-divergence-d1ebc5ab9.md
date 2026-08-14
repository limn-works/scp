---
name: sdk-quad-twin-divergence-d1ebc5ab9
description: SDK-quad (py/ts/swift/kotlin) twin-divergence audit at origin/main d1ebc5ab9 — dual TS evaluateTrust (stale twin uses nonce-CONSUMING ucanValidate), TS missing numeric guards its own saga twins have, vacuous TS tests that fake the guard in the mock.
metadata:
  type: project
---

Audit of the four SDK wrappers for the "one path fixed, twin not" defect shape, at `origin/main` d1ebc5ab9.

## Confirmed

1. **Two public `evaluateTrust` in the TS SDK; the free-function twin is the un-migrated one.**
   - Migrated/correct: `SCP.evaluateTrust` — `/Users/alec/Developer/limn/scp/bindings/typescript/src/scp.ts:3529` uses the read-only `ucanEvaluate` diagnostic (matches Python `trust.py:853/965`, Swift `Trust.swift:749/818`, Kotlin `Scp.kt:2135/2159`).
   - Stale twin: `evaluateTrust` exported at `index.ts:102` from `trust.ts:674` → `evaluateLayer1` (`trust.ts:594`) → `validateOneCapUri` (`trust.ts:510`) calls `scp.ucanValidate` at `trust.ts:518`.
   - `ucan_validate` RECORDS the replay nonce; `ucan_evaluate` probes it read-only. Proof: `crates/scp-ffi/napi/src/ucan.rs:200` ("Unlike `ucan_validate`, evaluation records NO state") and `:296`.
   - Consequence: the stale twin BURNS the nonce of every token it inspects; also passes `att[0].with` as a concrete challenge capability (all three siblings pass none, and Python's comment at `trust.py:945-952` says passing a concrete URI is wrong), classifies by error PROSE (ADR-059 says never), and hardcodes `contextsParticipated`/`totalDuration`/`governanceActionsAgainst` to 0 (`trust.ts:701-703`) where the siblings receive core-flattened participation facts.

2. **TS lacks the numeric range guards its own saga siblings have.**
   - `SCP.outletInvokeCrossContext` (`scp.ts:2535`) — no `chainDepth` guard; Python `scp.py:2596` guards 0..255. TS's saga (`scp.ts:2614`) and streaming-saga (`scp.ts:2706`) twins DO guard.
   - `SCP.outletSessionCreate` (`scp.ts:2777`) — no `ttlSeconds` guard; Python `scp.py:2881` guards.
   - napi-rs types these `u8` / `Option<u32>` and coerces rather than rejecting. Swift `UInt8`/Kotlin `UByte` are type-enforced (justified).

3. **Vacuous TS tests — the guard lives in the test's own mock.**
   `bindings/typescript/tests/outlets.test.ts:71-77` (chainDepth) and `:97-103` (ttlSeconds) make the STUB throw `[SCP-VALID-7002]` / `[SCP-VALID-7003]`; tests at `:278`, `:323`, `:341`, `:685`, `:694` then assert rejection. They pass with zero SDK guard. `SCP-VALID-7003` is "JSON schema validation error" in the registry — a fabricated spelling.

4. **Error-code purpose drift.** `SCP-VALID-7002` is normatively "JSON parse error" (`crates/scp-ffi/common/src/error_codes.rs:773`) yet both Python and TS emit it for integer-range failures. `VALID_7005` ("Invalid field value") is the right code. The registry header forbids re-purposing a code from any layer including SDK wrappers.

## Verified CLEAN (do not re-derive)

Outlets streaming is the most symmetric domain in the repo: `StreamGap` receiver monotonicity + best-effort cancel, the single-consumer `draining` guard, `isTerminal` (`end` OR `error` with `terminal:true`), lazy open, `cancel()` never-opened local no-op, `grantCredit` closed-check, `Credit` uniform `InvalidGrant`, and the `OutletError → ProtocolError → {InvalidGrant, StreamAlreadyClosed, StreamGap}` depth rule are all four-way symmetric AND match the browser tier (`bindings/typescript-wasm`). Browser `Credit`/`errors` are a faithful mirror (errors are literally re-exported from `bindings/typescript/src/errors` via the `@scp-core/errors` tsconfig alias).

Also clean: `formatAmount` (ADR-060) — identical currency table and range guards in all four; `scpid_challenge` TTL (Swift guards locally, the others rely on the core, which validates); `identity_create_with_custody` nine-method provider completeness (TS checks in the wrapper, PyO3 checks in the bridge at `custody.rs:235`).

## Method note

The coverage gate is name-existence only — it says so at `scripts/check-sdk-coverage.py:8-16`. A row can be `true` in all four cells with wildly different internals, and Swift cells can be satisfied by the GENERATED `Sources/SCP/Internal/ScpBindings.swift` with no hand-written wrapper (e.g. `mediaVerifySenderAttribution`). Highest-yield technique: `git grep` each SDK for local pre-bridge throw sites, bucket by enclosing method, and diff the buckets — that is what surfaced findings 2 and 3.
