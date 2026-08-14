---
name: adr049-d14-perf-baseline-harness
description: Review of crates/scp-runtime/tests/perf_baseline.rs (ADR-049 Decision 14 measurement harness) @23c5f7e7d — real-command-surface audit + handshake doc overclaim
metadata:
  type: project
---

# ADR-049 Decision-14 perf_baseline harness (@23c5f7e7d)

`crates/scp-runtime/tests/perf_baseline.rs` — 6 ops × N{1,4,16} = 18 measurement points, std::time::Instant (no criterion), smoke-asserts only, no committed absolute baseline (same-machine pre/post diff for the >15% rollback gate). Single `#[tokio::test]`.

**Verdict: faithful + non-vacuous EXCEPT one doc overclaim.**

- All 6 ops verified through the REAL command surface: `test_supervisor` (mod.rs:259) = real `Supervisor::with_providers` + concrete `MlsCryptoProvider` + in-memory MLS storage (NOT a mock). `deliver_commit_blob` (supervisor.rs:9590) → `dispatch_command` (2548) → mailbox, `?`-propagates. `join_context` (11770)→`dispatch_lifecycle_command`. broadcast via `dispatch_broadcast_command(_with_custody)` (5159/5207)→mailbox / `publish_broadcast_two_phase`.
- `deliver_incoming` `assert Ok || CryptoFailed(_)` is NON-vacuous: `lookup_miss_error` (4569) returns `ContextNotRegistered`/`ContextPoisoned`/`ActorCrashed` — none is `CryptoFailed` — so a broken command surface fails the assert. Terminal is MLS own-message `CryptoFailed("Cannot decrypt own messages.")` on a self-authored captured blob. Doc HONEST here.
- Setup excluded from timed region for all 6 (Instant::now after setup loops). N = N distinct contexts, sequential, wall-clock summed. Faithful. No hard time-threshold asserts → no timing flake. Fresh supervisor() per op → no cross-op state leak. report() `elapsed/u32(n)` safe (n≥1).

**KEY FINDING (doc honesty, would-mislead-perf-comparison):** handshake proxy OVERCLAIMS. Module doc lines 17 + 69-74 say join_context runs "the local MLS add, Welcome generation, and access-key minting". FALSE: `measure_handshake` passes `mls_key_package_bytes: None`; join_context Phase-3 (lifecycle_helpers.rs:918) calls `crypto.add_member(.., None)` which under cfg(test)/testing SHORT-CIRCUITS to `AddMemberOutput::default()` (provider.rs:1167-1176) — real `group::add_member`, Welcome+Commit TLS serialization all SKIPPED. `distribute_sender_key` (1343) skips the HPKE-seal branch (no member_wrapping_keys entry w/o real KP) — only a local sender_key_store write runs. So the timed handshake covers the NON-crypto join pipeline (version/sybil/rate-limit/economy/membership/event/persist) — the dominant, most-regression-prone MLS handshake crypto is NOT measured. Fix: correct doc; adder-side MLS add_member cost IS single-node-measurable by supplying a real serialized KeyPackage (only the two-node joiner *consumption* genuinely needs scp-testing).
