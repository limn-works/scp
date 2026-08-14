---
name: recovery-failclosed-2240-partA
description: #2240 Part A execute_recovery fail-closed — PRE-MERGE NO-SHIP then POST-MERGE confirming pass (CORE CLEAN) of squash 6c79cdb4f / PR #2252
metadata:
  type: project
---

# POST-MERGE confirming pass (2026-08-03, squash 6c79cdb4f, PR #2252) — CORE CLEAN

Re-attacked the MERGED commit (worktree f1-postmerge-review @ origin/main). Core
fail-closed VERIFIED genuinely closed by construction: all 3 bridge fns (PyO3
identity.rs:2544, NAPI scp.rs:1094, UniFFI bridge.rs:17467) have ZERO `Ok(...)` in
body — only Err returns (validate_did, ownership 1020, tier 1020, fail-closed 1022,
+NAPI 7120/7140). All mock RecoveryBackend impls deleted; zero prod callers of
orchestrator (all 15 remaining in recovery.rs `#[cfg(test)]`); recovery.rs unchanged.
Ownership gate load-bearing (real per-instance registry). **PRE-MERGE NO-SHIP
BLOCKER RESOLVED:** Python test_real_ffi.py + TS integration.test.ts WERE inverted to
expect SCP-IDENT-1022 throw before merge; PyO3 1024-cap docstring lie FIXED.
Part-B length/concurrency deferral HELD under re-attack. Matrix note honest.

Fix-forward (non-blocking, merged): (1) MEDIUM Kotlin has no fail-closed test +
IdentityAdvancedBridgeTest.kt:62 stub STILL fabricates `{"key_rotation_completed":true}`
(removed-nullifier shape) with a delegation test asserting it; Swift has NO recovery
test. Commit msg "inverted on every bridge/SDK" overstates (false for Kotlin/Swift;
both are zero-logic pass-throughs over the tested UniFFI bridge, so not a hole).
(2) LOW error_codes.rs doc comments stale vs use (INHERITED): IDENT_1020="agent key
creation" but=ownership+tier; IDENT_1022="DID document error" but=fail-closed.
(3) LOW IDENT_1020 overloaded ownership vs tier (must parse msg). (4) LOW Part-B
latent: PyO3/NAPI key ownership on identity registry, UniFFI on custody registry —
divergent "recoverable identity" set; harmless in Part A, matrix documents it.
VERDICT: SHIP-equivalent / CLEAN on the security property.

---

# PRE-MERGE audit (2026-08-03) — superseded by the confirming pass above

# #2240 Part A — identity_execute_recovery fail-closed (audit 2026-08-03)

Change: removed the inline always-Ok `RecoveryBackend` (nullifier fabricating
`key_rotation_completed:true`) from all 3 bridges (PyO3 identity.rs, NAPI
napi/scp.rs, UniFFI uniffi/bridge.rs). Bridges now fail closed with SCP-IDENT-1022
BEFORE constructing `CompromiseRecoveryOrchestrator`.

**Why:** `CompromiseRecoveryOrchestrator::execute_recovery` (scp-runtime
recovery.rs:484-590) HARDCODES `key_rotation_completed: true` (line 584) and
swallows per-context Err into `failed_contexts`, returning Ok even with a
fully-failing backend + empty context_ids. So a NotConfigured-backend approach
(custody-migration style) would NOT fail closed for recovery — bridge-boundary
fail-closed is NECESSARY. Verified against source; the change's justifying
comments are accurate.

## Verdict: NO-SHIP (as a unit). Core logic sound; change incomplete + commingled.

- BLOCKER: SDK integration tests still assert the fabricated-success contract and
  were NOT updated — Python `test_real_ffi.py::test_execute_recovery` (~line 272)
  asserts `result` is a dict with `key_rotation_completed`/`tier=="Agent"`/`did`;
  TS `integration.test.ts` "returns a JSON result on the happy path" (~853)
  asserts JSON string with tier+did. Both break against fail-closed bridge, or if
  unrun leave fail-closed untested at SDK layer. Rust unit tests WERE updated.
- HIGH: Python SDK docstring (scp.py identity_execute_recovery) advertises a 1024
  context_ids cap + SCP-VALID-7120 that PyO3 does NOT implement (`let _ =
  context_ids;`, deferred to Part B). Doc promises DoS protection that isn't there.
- MEDIUM: IDENT_1020 overloaded across ownership-rejection AND invalid-tier (and
  its doc-comment says "agent key creation"). Consumer can't distinguish authz vs
  caller-bug. All 3 bridges.
- MEDIUM: capability matrix `execute_recovery:true` — name-existence only; always
  errors. Matches custody-migration/device-attestation precedent; recommend a
  machine-readable status field, not prose notes.

## Attacked and HELD (report as verified-good):
- Fail-closed genuinely closed: no Ok-returning path; zero FFI callers of the
  orchestrator (grep). 
- "length-cap + concurrency = Part B" is LEGITIMATE for the Rust bridge, not scar
  tissue: fail-closed path has no block_on (semaphore bounds nothing) and never
  iterates context_ids (length-cap bounds nothing; marshaling alloc happens at FFI
  boundary before any in-fn gate in NAPI too — no differential). Owned-DID caller
  has no amplification vector on PyO3/UniFFI today.
- Ownership gate is forward-parity + conformance-fix, load-bearing only under Part
  B; on today's path it's protectively inert and adds a minor membership oracle.

## WORKTREE HAZARD (observed 2026-08-03)
f1-recovery-failclosed worktree is UNCOMMITTED and being concurrently mutated by
other agents mid-review (scp.py blob hash changed f2b558011->3696b7ebe between two
diffs; test_real_ffi.py carries unrelated testing->allow_in_memory_custody /
outlets->tools churn). Recovery change is commingled with unrelated in-flight work.
Isolate to its own commit and re-verify final state before ship.
