# `InMemoryNonceTracker::check_replay` uses `SystemClock`, not injected clock

**Date:** 2026-04-15
**Source:** Round 1 review of fuzzing infrastructure plan — HIGH severity finding

## The problem

`InMemoryNonceTracker::check_replay` calls `SystemClock::now()` directly rather than accepting
an injected clock. This makes nonce replay detection non-deterministic in:

1. **Fuzz targets.** `fuzz_validate_ucan_deep` (invariant I4 — nonce replay prevention) cannot
   achieve deterministic replay-detection testing because two invocations with the same input
   may produce different results depending on wall time.

2. **Property-based tests.** Proptest strategies that test replay behavior must sleep or
   manipulate wall time, making them slow and flaky.

3. **Simulation tests.** `SimulatedClock` (from `scp-testing`) cannot control the nonce
   tracker's time window, breaking multi-node replay-detection scenarios.

## Why invariant I4 is currently unimplemented in fuzzing

Security invariant I4 — "accepted nonce never re-accepted" — is listed in the invariant
catalog (`fuzz/README.md`) as "Future T20 (blocked: `InMemoryNonceTracker` uses `SystemClock`)".
The target cannot be written until the clock is injectable.

This is a documented architectural limitation, not an oversight. The fuzz target for I4 will
require:

1. Clock injection into `InMemoryNonceTracker` (make it generic over `Clock` trait or accept
   `Arc<dyn Clock>`).
2. A deterministic `FuzzClock` in `fuzz/src/lib.rs` that advances monotonically based on
   fuzzer input bytes.
3. A new fuzz target `fuzz_nonce_replay` (T20) that: accepts a nonce + timestamp pair, submits
   it once (must succeed), submits the same nonce again (must be rejected).

## Broader pattern: always inject clocks at construction

Any component that makes time-dependent decisions must accept a clock at construction time, not
call `SystemClock::now()` (or `std::time::SystemTime::now()`, `Instant::now()`, etc.) directly.

This applies to:
- Nonce trackers (`InMemoryNonceTracker`, `SqliteNonceTracker`)
- Rate limiters (`BudgetTracker`, `RateLimitTracker` — already clock-generic per PR #1578)
- Timestamp validators in UCAN / attestation verification
- Any TTL cache with expiry logic

The `Clock` trait already exists in `scp-runtime` (used by `RateLimitTracker` after PR #1578).
Extend its usage to nonce trackers.

## How to catch this when reviewing

When reviewing a new type with time-dependent behavior:

1. `grep -n "SystemTime::now\|Instant::now\|SystemClock" <file>` — any hit in a
   struct method (not test code) is a candidate for clock injection.
2. If the struct is used in tests, confirm there is a way to control time in the test.
   If tests use `sleep`, that is a sign clock injection is missing.
3. If the struct is referenced in a fuzz target, confirm the target can achieve deterministic
   behavior. Non-deterministic fuzz targets are useless for regression detection.

## Related

- `crates/scp-runtime/src/nonce.rs` — `InMemoryNonceTracker` (clock injection needed)
- `crates/scp-runtime/src/rate_limit.rs` — `RateLimitTracker` (already clock-generic, PR #1578)
- `fuzz/README.md` §Security Invariants — I4 marked as "Future T20"
- `.docs/adrs/phase-6.md` §ADR-045 — Fuzzing Infrastructure (invariant catalog)
- PR #1578 — RateLimitTracker clock-generic refactor (reference implementation)
