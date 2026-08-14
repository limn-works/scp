---
name: adr057-c3c-trust-participation-7e0f22894
description: ADR-057 C3c trust/participation SDK rebuild @ 7e0f22894 — ALIGNED, prior Kotlin phantom-provenance twin RESOLVED (deleted)
metadata:
  type: project
---

# ADR-057 C3c Trust/Participation SDK Rebuild @ `7e0f22894` (branch feat/actor-2c-xctx-tool-saga, 2026-06-30) — ALIGNED, 0 blocking

Re-review superseding [[adr057_c3c_trust_sdk_caff1e32d]] (which was NEEDS DISCUSSION on the Kotlin phantom-provenance finding). Diff `origin/main...HEAD` = 102 files +13746/-2780. Bundled branch (also flips unrelated identity/discover/economy matrix cells backed by real wrappers).

**PRIOR FINDING RESOLVED:** The insecure pure-Kotlin/pure-Swift `verifyParticipationRequirements` twins are DELETED. `bindings/kotlin/.../Participation.kt` (127 lines, carried the false "matching the Rust trust module's verify_participation_requirements logic" doc on a no-crypto impl = phantom provenance) is GONE. Both Kotlin (`Scp.kt:1913`) and Swift (`Scp.swift:1135` comment, delegates to `ScpBindings.swift:16052`) now route `verifyParticipationRequirements` through the UniFFI-generated free fn → Rust core `verify_participation_requirements(expected_subject, profile, requirements)`. All 4 SDKs (py bridge, TS native, Kotlin/Swift UniFFI) call the Rust impl w/ `expected_subject` subject binding. No "matching the Rust logic" false docs remain (surviving "matching the Rust" refs are legit wire-format/field-list docs).

**Verified ALIGNED:**
- §7.2.4 gate-vs-diagnostic: `validate_ucan` gate (mandatory cap) vs `evaluate_ucan` diagnostic (`required_capability: Option`); SDK-consumption-normative from structured result NOT prose (ADR-057).
- ADR-057 Decision-5 (phase-2.md): all four bindings expose idiomatic wrapper, existence non-optional, per-SDK idiom = HOW not WHETHER. No deferral residue.
- §7.3.2/§7.3.2.1 twelve fields: core `ParticipationFacts` (participation.rs:146) = 12 fields incl `attestation_count_anchored` on UNSIGNED projection; signed `ParticipationProfile` (~732) OMITS it (has only tool_invocation_count_anchored) — matches spec. `ATTESTATION_COUNT_ANCHORED: bool = false` (permanent, participation.rs:53). All 4 SDK BehavioralRecord = 12 fields (py trust.py:177, TS types.ts:912, Swift Trust.swift, Kotlin Trust.kt).
- committer-local-until-ADR-051 documented; ADR-011 amendment: NO AttestationPublished/AttestationRevoked EventType (grep hits = only `TrustError` variants + test asserts).
- §7.4 caveats present: authenticity≠Sybil (self-issuable count, issuer legitimacy) + authenticity≠authorization; subject binding (expected_subject/subject_did) IS enforced by protocol (both siblings discard subject-mismatched profiles/challenge results — closes cross-subject replay), signer/verifier legitimacy remains consumer's job. §7.3.2.1 step-5(a) subject_did check added.
- Matrix: kotlin/swift/py/ts exemptions REMOVED, replaced with descriptive `notes` (HOW). Phantom-deferral phrases ("lands in SDK-parity PR", "C3c follow-up", "bundled branch") only in DELETED lines + narrative PRD descriptions of the work-done.
- SCP-302/SCP-303 in PRD; SCP-303 AC (main.json:10427) explicitly requires Swift/Kotlin twelve-field BehavioralRecord + participationRecord method. Kotlin wrappers exist (Scp.kt: ucanEvaluate:1689/participationRecord:1731/evaluateTrust:1772); Swift (Trust.swift: 655/699/749).
- TIP commit 7e0f22894 = sound fail-open fix: `canonical_challenge_request/response_bytes` no longer `unwrap_or_default()` (which silently signed EMPTY bytes dropping parameters/result); now propagates `TrustError::ChallengeSigningFailed`, matching sibling `canonical_challenge_verification_bytes`.

**Only observation (LOW, pre-existing):** 3 `#NNNN` refs (#1305/#1324/#501) survive in `crates/scp-ffi/CLAUDE.md:10` — pre-existing on origin/main, carried through a substantive edit to that line (rewrote NoOpEventLogProvider→persistent MerkleEventLogProvider for participation_record readability). Doc file (not source/comment/test), so outside the strict feedback rule; optional scrub since the line was touched.

GOTCHA: awk field-count on py/ts BehavioralRecord under-counts due to interspersed doc-comments/defaults — enumerate explicitly.
