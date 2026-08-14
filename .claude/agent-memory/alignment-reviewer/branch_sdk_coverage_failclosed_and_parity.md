---
name: branch-sdk-coverage-failclosed-and-parity
description: Review of fix/sdk-coverage-fail-closed-and-parity — TS trust/identity parity, ADR-051, fail-closed coverage gate; pre-existing rotate_key matrix inaccuracy
metadata:
  type: project
---

Branch `fix/sdk-coverage-fail-closed-and-parity` reviewed 2026-06-20 (worktree agent-a0bbc61dae626fa6c).

**Scope is much larger than the 4 named review areas.** The diff (8k ins / 36k del) also DELETES the reconnect/heartbeat subsystem: `crates/scp-ffi/common/src/reconnect.rs` (961 lines), `heartbeat_scheduler.rs`, `SCP.reconnect` (TS + Python), `ContextReconnectResult`/`ReconnectReport` types, reconnect_sync.rs/heartbeat_suppression.rs tests. Saga handler -5248 lines, supervisor.rs -7822. These appear to be a separate rebase/merge of the actor-refactor lane folded in. **Why:** likely branch built off a stale base then rebased; the reconnect deletion ties to [[lesson_actor_boundary_no_key_no_retrieval]] (reconnection driver moving to FFI/SDK boundary, #1540). **How to apply:** if re-reviewing, verify the reconnect deletion is intentional (matches the actor-boundary plan) and not an accidental revert — check two-dot diff vs origin/main per the rebase-before-merge rule.

**Findings:**
- TS `evaluateTrust` (trust.ts) faithfully mirrors Python `evaluate_trust` — same 11-step UCAN classification, `__PASSED_BEFORE` map, optimistic-then-classify. Python lifecycle methods (identity_rotate_key/migrate/add_agent_key/etc.) ALREADY existed on main; this branch adds the TS-side equivalents to reach parity (sound).
- ADR-051 (pre-rotation custody substrate isolation) is well-grounded: accurately quotes spec §9.7.4.1 items 3/4/5 (verified at .docs/specs/09-security-model.md:655-686) and §9.12. Status Proposed; design-only, no code. Good ADR.
- check-sdk-coverage.py hardening is sound: fail-closed, positive coverage_exemptions allowlist, all-exempted guard prevents prose-bypass. Gate passes 0 errors / 221 ops.

**PRE-EXISTING matrix inaccuracy (NOT introduced by this diff):** Identity/`rotate_key` is marked `kotlin:false, swift:false` with exemption "UniFFI bridge does not export rotate_key" — but UniFFI DOES export it (`crates/scp-ffi/uniffi/src/bridge.rs:2116 pub async fn rotate_key`), and Swift surfaces it (`bindings/swift/Sources/SCP/Internal/ScpBindings.swift:1183 open func rotateKey`). The gate doesn't verify truthfulness of `false`-entry exemption reasons (only that a non-empty string exists), so a false-negative entry passes. Worth fixing the matrix to true (or correcting the reason) — but it is pre-existing, untouched by this branch.

Minor: TS `identityMigrate` docstring cites "spec §3.2.1 (Identity Key migration)" for rotation-event distribution; §3.2.1 is "Key Custody Migration Protocol" (same-DID custody move). The new-DID migration + DidRotationEvent flow is spec §3 (line 28) + ADR-003 §4b. Python's docstring has the same §3.2.1 ref. Cosmetic citation drift, not a logic bug.
