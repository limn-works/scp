---
name: adr057-structured-trust-participation-9d32bb297
description: ADR-057 structured trust/capability FFI + §7.3.2 participation facts (SCP-302/303) @ 9d32bb297 — ALIGNED, 0 findings, 2 non-blocking OBS
metadata:
  type: project
---

# ADR-057 Structured Trust/Capability FFI + §7.3.2 Participation Facts @ `9d32bb297` — ALIGNED

Worktree `agent-a1400c1b005b502a3`, diff vs origin/main (102 files, +13967/-2841). NAPI-only (no WASM bridge, correct per ADR-055). This is a further-developed state of the ADR-057 C3c SDK-rebuild thread (see prior `7e0f22894` / `50c7bad60` entries). Adds SCP-302 (structured ucan_evaluate SDK consumption across 4 bindings) + SCP-303 (typed participation_record op across 4 bindings) as NEW PRD stories, status=done.

**Why:** C3c SDK rebuild — retire Python prose-parsing of UCAN error strings; wire typed CapabilityValidation + ParticipationFacts through all 4 SDKs.
**How to apply:** treat SCP-302/303 as the canonical ADR-057 SDK-consumption stories; leaf-derived-vs-credential-layer fact split is settled.

## Verdict: ALIGNED, 0 blocking, 2 non-blocking OBS. All 4 review criteria pass.

- **Freshness future-skew bound** ✓ `MAX_PARTICIPATION_FUTURE_SKEW_SECS = 5*60` (participation.rs:838) == §9.14 5min == challenge.rs:408 `MAX_COMPLETION_FUTURE_SKEW_SECS`. Predicate participation.rs:1059-1063 `current_time.saturating_add(...)` then `continue` on future-dated — rejects, not read-as-age-0. Single-pass consolidation (commit purpose) keeps staleness diagnostic sans duplicate predicate.
- **§7.3.2 spec edit accurate** ✓ Code keys governance on `GovernanceActionExecutedPayload.target_did` (participation.rs:562-565), role/membership on `project_payload(...).subject_did` (RoleAssigned:355/MemberJoined:372/MemberLeft:386). SIGNED `ParticipationProfile` (participation.rs:713-758) carries `tool_invocation_count_anchored` (:732) but OMITS `attestation_count_anchored` — exactly matches §7.3.2.1 spec edit; anchored flag lives on UNSIGNED ParticipationFacts projection (:214), `ATTESTATION_COUNT_ANCHORED=false` const (:53). attestation_count = credential-layer via `credential_attestation_history` (:407,434).
- **ADR-057 Consequences clock bullet accurate** ✓ `SystemClock::now_secs` = `.expect("system clock is unavailable or before Unix epoch")` (scp-primitives/src/time.rs:96) — panics, not 0. 3 `verify_participation_requirements` bridges read via SystemClock (scp-ffi/src/trust.rs:296, napi/src/trust.rs:304, uniffi via common/trust_store.rs). panic=unwind holds — NO profile sets panic=abort (`panic = "deny"` at Cargo.toml:91 is a [workspace.lints.clippy] lint next to unwrap_used/todo, NOT a profile strategy). Placement defensible under ADR-057's broad "every bridge returning a validation outcome" scope.
- **SCP-302/303 done flip justified** ✓ trust.py has 0 prose-classifiers (_classify_ucan_error, *_PREFIXES). `validate_ucan` req_cap `&CapabilityUri` mandatory (validate.rs:547) vs `evaluate_ucan` `Option<&CapabilityUri>` + `if let Some(required)` guard (:782,836); all 3 bridges coerce empty via `trim().is_empty()`. All 4 SDKs define BehavioralRecord + participationRecord wrapper. Matrix flips UCAN.evaluate + Trust.evaluate_trust + Trust.participation_record → all 4 true, exemptions REMOVED. `check-sdk-coverage.py` exits 0 (PASS). ("UCAN","evaluate") alias lists all 4 (check-sdk-coverage.py:404-407).

## Non-blocking OBS
1. panic=abort prohibition is DOCS-ONLY — no gate asserts release/FFI profiles keep unwind. ADR honest ("relies on unwind semantics"). Suggest a `# panic=unwind required (ADR-057)` profile comment as low-cost middle ground; full gate likely disproportionate.
2. My SCP-302/303 verify was TARGETED (matrix/coverage/signatures/field-shape/prose-removal), NOT the addon-backed `bun test`/`pytest` runtime-gate ACs — defer those to completionist/tester.

GOTCHA: sdk-capability-matrix.json structure = `capabilities: [{domain, operations: [{name, python/typescript/swift/kotlin bools, exemptions}]}]` — NOT a flat op list. Parse by domain+name.
