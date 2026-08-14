---
name: trust-signal-participation-pyi-9d32bb297
description: Trust-signal freshness/caveat review @9d32bb297 — M1/M2 from prior round RESOLVED, one NEW moderate .pyi stub gap (participation_record)
metadata:
  type: project
---

Review @9d32bb297 (branch tip: "consolidate participation freshness predicate + close review nits"). SUPERSEDES [[trust_signal_freshness_hardening_c35c62703]]. NEEDS REVISION, 1 MODERATE.

**Prior findings RESOLVED this round:**
- M1 (TS verifyParticipationRequirements missing signer-legitimacy caveat): FIXED. Caveat now present + accurate on ALL FOUR SDKs — Python trust.py:1085-1093, TS scp.ts:2378-2384, Swift Scp.swift:1142-1148, Kotlin Scp.kt:1912-1922 — plus core participation.rs:972-980. All cite §7.3.5 threshold/independence path; wording converged.
- M2 (.pyi omits ucan_evaluate + wrong verify_participation_requirements stub): FIXED. .pyi now has `ucan_evaluate(context_id,token,capability=...,presenting_agent_did=...,proof_tokens=...)` (matches raw PyO3 ucan.rs:395 capability-first order), and `verify_participation_requirements` free-fn stub corrected from wrong 2-arg `(profile_json, requirements_json)` to `(expected_subject, requirements_json, profile_json)` matching trust.rs:272.

**NEW MODERATE (only finding):** `SCP.participation_record` (PyScp method, trust.rs:831, `#[pyo3(name="participation_record", signature=(context_id,subject_did,cached_attestations_json="[]"))]`) is MISSING from the `.pyi` SCP class. It is the ONLY new `#[pyo3(name=)]` method in the whole branch (origin/main has 0), it IS consumed (trust.py:870 `instance.participation_record(...)`), and its sibling `ucan_evaluate` was added to the stub in this same commit — so the branch curated the stub for siblings but skipped this one. Slipped through because trust.py calls it via loosely-typed `instance: Any`. Breaks the .pyi's stated purpose (IDE/mypy/pyright): direct `_scp_core.SCP` users get false unknown-attribute errors + no autocomplete. Fix: add the 3-arg stub to the SCP class trust section.

**Assessed sound (no re-file):**
- verifyParticipationRequirements void+throw uniform ×4 SDKs+core.
- capability/presentingAgentDid: all 4 developer-facing SDK `ucanEvaluate` wrappers use presenting-FIRST (Swift Trust.swift:655, TS scp.ts:2081, Py scp.py:1122, Kt Scp.kt:1689) — CONSISTENT; forced by default-arg ordering (presenting required, capability optional). Generated bridges + raw PyO3 use capability-first. Swift Trust.swift:5 (raw-bridge order, capability-first) and :36 (SDK-wrapper DocC symbol, presenting-first) BOTH correct — different symbols. F1 from prior round stays FIXED.
- intra-SDK validate↔evaluate cap/did swap = #1993-adjacent, documented + fail-closed.
- verify_participation_requirements 3 adjacent Strings (requirementsJson/profileJson swap): fail-closed (distinct JSON shapes fail deserialize); typed-list inputs in Py/Swift/Kt mitigate; raw-JSON at TS = facet of #1991. presenting_agent_did omittable (=...) in .pyi faithfully mirrors the Option PyO3 sig (runtime fail-closed) = #1993, not a stub defect.
