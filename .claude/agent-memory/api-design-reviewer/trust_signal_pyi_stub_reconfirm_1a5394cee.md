---
name: trust-signal-pyi-stub-reconfirm-1a5394cee
description: ADR-057/C3c trust-signal .pyi stub re-confirmation @1a5394cee — APPROVED, prior participation_record .pyi gap CLOSED
metadata:
  type: project
---

Focused API re-confirmation @1a5394cee (worktree agent-a1400c1b005b502a3, no WASM bridge). SUPERSEDES [[trust-signal-participation-pyi-9d32bb297]].

**Verdict: APPROVED.** The final commit ("add participation_record + economy_verify_payment_receipts to .pyi stub") closes the sole prior MODERATE.

- `_scp_core.pyi:738` `participation_record(self, context_id, subject_did, cached_attestations_json=...)` EXACT-matches PyO3 `trust.rs:831` `signature=(context_id, subject_did, cached_attestations_json="[]")`.
- `_scp_core.pyi:537` `economy_verify_payment_receipts(self, receipts_json)` matches `economy.rs:470` `(&self, receipts_json:&str)`.
- Free-fn `_scp_core.pyi:853` `verify_participation_requirements(expected_subject, requirements_json, profile_json) -> None` matches `trust.rs:271` 3-arg `PyResult<()>`. `ucan_evaluate` stub present :770.
- **FULL class-method parity**: enumerated every `#[pyo3(name="..")]` across `crates/scp-ffi/src/*.rs` vs `.pyi` def names → ZERO missing. The 9d32bb297 asymmetry (sibling added, this omitted) does not recur.
- All 4 SDK wrappers present ×4 methods: Py trust.py (participation_record:892 / evaluate_trust:624 / verify_participation_requirements:1041), TS scp.ts (ucanEvaluate:2081 / verifyParticipationRequirements:2386 / participationRecord / evaluateTrust), Swift Trust.swift, Kotlin Scp.kt (ucanEvaluate:1689/participationRecord:1731/evaluateTrust:1772/verifyParticipationRequirements:1924).

Disposition-only (NOT re-raised, tracked): #1991 typed-vs-JSON input asymmetry; #1993 presenting_agent_did Option/omittable; ADR-048 free-fn-vs-method split SOUND; #1990 .pyi parity gate. Kotlin BridgeConnector.kt:96/115 evaluateTrust = separate int-tier connector concept (not a gap). Wrong-tree signal `reconcile_to_ceiling` absent from branch diff (confirmed clean tree).
