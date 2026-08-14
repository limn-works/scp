---
name: adr055-c3c-ts-review
description: ADR-055 / SCP-302 / §7.2.4 c3c-ts doc-integrity review — what's consistent and the one durable-capture gap (presenting-agent binding)
metadata:
  type: project
---

Reviewed branch `c3c-ts` (worktree agent-a1400c1b005b502a3) doc integrity for the structured CapabilityValidation FFI work (2026-06-27).

**Decision/state.** ADR-055 in phase-2.md, spec §7.2.4, SCP-302 (gate-audit, status pending), capability matrix, lesson `sdk-consume-structured-ffi-results-not-error-prose.md`. CapabilityValidation = 6 per-stage bools crossing FFI; SDKs consume typed record, never parse error prose. `ucan_validate` = gate (mandatory cap, records nonce). `ucan_evaluate` = diagnostic (Option cap, check_replay only). Decision 2a optional-challenge intrinsic mode SKIPS step-6 grant-match — verified against validate.rs:807-851 (signatures_valid reflects only structural checks when None). All 4 bridges coerce empty cap to no-challenge. ADR-009 dep label corrected to "Role Assignment and Capability Ceiling Enforcement" (NonceTracker foundation), ADR-016 = normative nonce pipeline (commit 747f01403).

**Verified consistent:** core signatures, nonce ops (&mut vs &ctx), bridge coercion, Python prose-parsers all deleted (grep=0), matrix has zero orphan exemptions + zero lingering "C3c", check-sdk-coverage + validate-prd green, gate wiring correct, lesson cross-refs resolve, §9.5 nonce ref matches project convention.

**The one gap (LOW, durability):** the **presenting-agent binding decision** is captured ONLY in per-bridge doc-comments, not in any `.docs/` artifact. PyO3/NAPI/UniFFI default `presenting_agent_did` to token `aud` (tautological self-check / trust-inflation risk); WASM REQUIRES `expected_aud_did` (no defaulting). The prompt listed "presenting-agent binding" as a decision that should be durably captured for a fresh agent; ADR-055/§7.2.4/lesson are silent on it. A fresh agent reading only `.docs/` would not learn why WASM diverges or why omitting the subject is a hazard. Recommended (not done — read-only review): one sentence in ADR-055 Decision/Consequences or §7.2.4.
