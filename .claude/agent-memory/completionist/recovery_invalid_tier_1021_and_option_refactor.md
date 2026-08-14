---
name: recovery-invalid-tier-1021-and-option-refactor
description: #2240 Part B fail-closed recovery — invalid-tier taxonomy split (1020 ownership vs 1021 tier) + execute_recovery bool→Option refactor; CONFIRMED COMPLETE at fb76ac5b0
metadata:
  type: project
---

Reviewed `fix/2240-recovery-seam-and-taxonomy` HEAD `fb76ac5b0` — CONFIRMED COMPLETE (zero findings).

**Two changes:**
1. Dedicated invalid-tier code `SCP-IDENT-1021`, split from the shared ownership
   code `SCP-IDENT-1020`. Ordering on every bridge: ownership gate (1020) BEFORE
   tier check (1021). So an unowned DID + bad tier yields 1020 (ownership wins).
2. `CompromiseRecoveryOrchestrator::execute_recovery` refactored
   `key_rotation: &KeyRotationOutcome` → `Option<&KeyRotationOutcome>`; `None`
   fails closed with `RecoveryError::KeyRotationFailed`. `key_rotation_completed`
   now derived `= key_rotation.is_some()` (no hardcoded `true`). New fail-closed
   variant `RecoveryError::AllContextsFailed { attempted }` — total per-context
   failure returns typed error instead of an all-failed `RecoveryResult` that
   could read as success.

**1021 verified consistent across ALL surfaces:** error_codes.rs const+doc;
PyO3 identity.rs:2591; NAPI scp.rs:1173 (+unit test); UniFFI bridge.rs:17511
(+unit test asserting `code == IDENT_1021`); Python test_real_ffi.py (asserts
code + message); capability-matrix note; TS scp.ts:1058; Python scp.py; Kotlin
Identity.kt (interface+impl); Swift Scp.swift. Zero surviving "invalid tier →
1020" anywhere (all 1020 doc refs, incl ADR-048:167, are ownership-only).

**Scope stayed clean:** deferred WIRE untouched — no dht.rs, no revoke_ucans
impl, no ProductionRecoveryBackend FFI injection, no pipeline_wiring.rs,
capability-matrix BOOLEANS unchanged (notes text only). Bridges still return
fail-closed 1022 without invoking the orchestrator; orchestrator exercised only
by tests until Part B lands.

**Lesson:** when a shared error code is split into two, the completeness surface
is large — 3 bridge impls + 3 bridge tests + error-code const/doc + 4 SDK
docstrings + capability-matrix note + any error-catalog/spec refs. grep the OLD
code near the concept (`grep 1020 ... | grep -i tier`) to catch stale references
the rename missed.
