---
name: execute-recovery-failclosed-2240A
description: #2240 Part A (PR#2252, merge 6c79cdb4f) execute_recovery nullifier removal — post-merge confirming pass, ZERO blocking findings
metadata:
  type: project
---

# execute_recovery fail-closed (#2240 Part A, PR#2252, commit 6c79cdb4f) — CONFIRMED CLEAN

Post-merge confirming security pass on the 3-bridge fail-closed change. ZERO blocking findings.

**What changed:** `identity_execute_recovery` on PyO3 (scp-ffi/src/identity.rs), NAPI (scp-ffi/napi/src/scp.rs), UniFFI (scp-ffi/uniffi/src/bridge.rs) previously ran an inline always-`Ok` `RecoveryBackend` (all 6 §9.12 steps no-ops) then returned `key_rotation_completed:true` = a nullifier. Now all three DELETE the inline backend + orchestrator call and FAIL CLOSED with typed SCP-IDENT-1022.

**Why bridge-boundary, not orchestrator:** `execute_recovery` in scp-runtime/src/identity/recovery.rs:492 (UNCHANGED) isolates per-context backend failures and ALWAYS returns `Ok(RecoveryResult{ key_rotation_completed: true /*line 104, "step 1 provided as input"*/ })` — never a fatal "backend absent" error. So a no-op backend yields fabricated Ok. Fail-closed MUST be at the bridge.

**4 load-bearing questions — all verified:**
1. Fail-closed closed: no reachable Ok/fabricated-success on any bridge. Only returns = validate_did err / 1020 ownership / 1020 tier / 1022 final. Orchestrator imports fully removed, no callers.
2. Ownership gate sound: per-instance DashMap lookup, no process-wide fallback. PyO3 `identity_registry_contains(&self.inner,did)`, NAPI `identity_registry(&self.inner).contains_key`, UniFFI `identity_custody_registry(&self.inner).contains_key`. Oracle limited to DIDs on caller's OWN instance. No bypass.
3. Cross-bridge symmetry: ownership→1020, invalid-tier→1020, fail-closed→1022 on all 3. All codes exist in scp-ffi/common/src/error_codes.rs. PyO3 uses `identity_with_code` (error.rs:295) fixing prior generic IDENT_1001. NAPI adds 7120 length-cap + 7140 permit.
4. No DoS from Part-B deferral on PyO3/UniFFI: fail-closed path does `let _ = context_ids` — iterates nothing, no block_on, pins no worker. Change strictly REDUCES DoS surface vs prior orchestrator-over-all-contexts. Length-cap/permit unneeded (no bounded work).

**OBSERVATION for Part B (not a Part-A finding):** ownership-gate registry source diverges — PyO3/NAPI use `identity_registry` (create AND load); UniFFI uses `identity_custody_registry` (create + link-attestation, NOT DID-only load). A DID-only-loaded identity → 1020 on UniFFI but reaches 1022 on PyO3/NAPI. Both fail-closed (no security impact for A) but Part B must reconcile which registry defines "recovery ownership" so legitimate loaded identities behave identically per-binding.
