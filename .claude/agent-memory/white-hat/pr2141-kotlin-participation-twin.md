---
name: pr2141-kotlin-participation-twin
description: PR #2141 deleted the insecure Swift verifyParticipationRequirements twin but left the identical insecure pure-Kotlin twin (Participation.kt) in place
metadata:
  type: project
---

# PR #2141 (@23779139f) — Swift twin deleted, Kotlin twin REMAINS (P1)

Commit 23779139f "fix(swift): delete insecure participation-verifier twin" correctly removed
`verifyParticipationRequirements(requirement:profile:)` + 4 types (ParticipationFact,
ParticipationThreshold, ParticipationProfile, RequireParticipation) from Trust.swift (90 lines).
Secure UniFFI path `verifyParticipationRequirements(profileJson:requirementsJson:)` intact at
Internal/ScpBindings.swift:15097 (throws, bridges via rustCallWithError). No dangling refs.

**REMAINING GAP (mirror image, uncaught):** Kotlin has the SAME insecure twin still present:
- `bindings/kotlin/scp-kt/src/main/kotlin/works/limn/scp/Participation.kt:90`
  `fun verifyParticipationRequirements(requirement: RequireParticipation, profile: ParticipationProfile): Boolean`
  — NO visibility modifier => PUBLIC in package works.limn.scp. Bare threshold compare via
  private checkThreshold; ZERO signature/freshness/subject-binding/min_contexts checks. Plus 4
  public data classes (ParticipationFact/Threshold/Profile/RequireParticipation) + private checkThreshold.
- SECURE path exists separately: `Scp.kt:1714` `SCP.verifyParticipationRequirements(profileJson, requirementsJson)`
  routes through `uniffi.scp.verifyParticipationRequirements`.

**Why coverage gate misses it:** check-sdk-coverage.py:591 `"kotlin": ["verifyParticipationRequirements"]`
matches by BARE NAME via tree-sitter (captures public class methods too — see memberCount/isMember).
Secure Scp.kt:1714 method already satisfies the matrix entry, so the twin is NOT needed for coverage
and deleting it keeps the gate green — same rationale as the Swift deletion. Twin has NO consumers,
NO tests (grep clean). Pure dead-but-public dangerous API surface.

FIX: delete Participation.kt free fn + 4 data classes + checkThreshold helper (mirror the Swift commit).

Note: round-25/26 memory claimed Kotlin Participation.kt was DELETED @c9c956739 — that was a DIFFERENT
branch lineage (subject-binding). This PR #2141 branch never received that deletion.
