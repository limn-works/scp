---
name: fu1988-check-capability-requirements-8080c4e02
description: API review of check_capability_requirements 4-SDK wiring (#1988, branch fu-1988 @8080c4e02); NEEDS REVISION 1 MODERATE (error-code mapping asymmetry)
metadata:
  type: project
---

# check_capability_requirements 4-SDK wiring review (#1988 @8080c4e02)

Op mirrors `verify_participation_requirements`: verify agent meets a context's
capability admission requirements (§7.3.4.4 / SCP-ACR-008). void+throw. Wires
core → PyO3/NAPI/UniFFI → Python/TS/Swift/Kotlin.

**Verdict: NEEDS REVISION, 1 MODERATE.**

**Placement/shape parity is EXCELLENT** — mirrors the participation sibling
EXACTLY per-SDK: Python free-fn, Swift UniFFI free top-level fn, Kotlin SCP
instance method, TS SCP instance method. Identical param order everywhere
`(context/contextId, subject, requirements, agentCapabilities, challengeVerifications)`.
void+throw uniform ×4+core. `.pyi` stub (lines 856-862) matches the real
`#[pyfunction]` signature EXACTLY (the sibling's prior `.pyi` gap did NOT recur).
Instance-vs-free split is faithfully-applied per-SDK idiom (ADR-048 §1/§7), not drift.

**MODERATE — error-code mapping inconsistent across the 3 bridges.** New codes
VALID_7073 (req json) / 7074 (caps json) / 7075 (challenge json) / 7076
(MissingCapability|VerificationRequired) / 7077 (EmptySubjectDid) were DEFINED in
error_codes.rs with doc comments naming THIS op, but ONLY UniFFI emits them
(exhaustive AdmissionError match). NAPI collapses ALL failures to `validation_error`
= VALID_7010 (bridge/napi/src/trust.rs:118). PyO3 raises raw PyValueError/PyRuntimeError
with NO SCP code (src/trust.rs:356-405); Python SDK calls bridge raw, does NOT run
`_coded_bridge_error`, so callers get builtin ValueError/RuntimeError, no `.code`.
Net: same failure → Swift/Kotlin distinct 7073-7077, TS coarse 7010, Python no code.
Cross-language `.code` branching unreliable; the REFERENCE bridge (PyO3, 100% target)
is the LEAST structured. Note VALID_7077 in UniFFI is effectively unreachable
(FFI validate_did rejects empty subject before core's EmptySubjectDid path).

**LOW/OBS** — Python SDK loses typed-model ergonomics its own sibling has:
`check_capability_requirements` takes `list[dict[str,Any]]` for requirements &
challenge_verifications (no CapabilityRequirement / verification-level-enum /
ChallengeVerification dataclass) vs sibling's typed RequireParticipation/
ParticipationProfile. TS/Swift/Kotlin take pre-serialized JSON strings for both
(so it's Python-internal; sibling TS/Swift/Kotlin also JSON-string).

**OBS** — TS/Swift/Kotlin have THREE adjacent same-typed JSON-string params
(requirementsJson/agentCapabilitiesJson/challengeVerificationsJson) + 2 more strings
= silent-swap footgun (reinforces #1991). context/subject swap mostly caught by validate_did.
