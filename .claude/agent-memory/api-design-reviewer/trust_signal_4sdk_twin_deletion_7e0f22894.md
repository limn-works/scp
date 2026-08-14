---
name: trust-signal-4sdk-twin-deletion-7e0f22894
description: ADR-057 trust-signal 4-SDK review @7e0f22894 — verifyParticipationRequirements twin deletion confirmed single-surface; NEEDS REVISION on Swift doc + vestigial-bool
metadata:
  type: project
---

Branch feat/actor-2c-xctx-tool-saga @7e0f22894 (worktree). ADR-057 trust-signal
4-SDK surface (ucanEvaluate/ucanValidate/participationRecord/evaluateTrust/
verifyParticipationRequirements). Supersedes [[trust_signal_wrappers_4sdk]] and
[[adr057_ucan_evaluate_participation_record]].

VERDICT: NEEDS REVISION (2 findings). Most prior blockers RESOLVED this round.

CONVERGED (PASS): CapabilityValidation exactly 6 bools identical ×4
(tokensValid/signaturesValid/withinCeiling/nonceValid/notRevoked/timeBoundsValid).
BehavioralRecord 12-field identical ×4 (snake Py / camel TS,Swift,Kt).
CachedAttestation casing now per-SDK consistent (Py snake, others camel — the
old 2/2 split is GONE). TrustEvaluation now 5-field identical ×4
(subjectDid/contextId/capabilityValidation/behavioralRecord/attestations:
AttestationSummary) — Python's extra Layer-4 fields + Attestation≠AttestationSummary
FIXED. Python now exposes SCP.evaluate_trust METHOD (not module-only) w/ arg order
(context_id, subject_did) matching siblings. TS evaluateTrust vestigial contextId
param GONE (derives from handle). Python bridge-provenance fn RENAMED
bridge_provenance_tier → evaluate_trust name-collision GONE.
presenting_agent_did REQUIRED (no default) ×4 for both validate+evaluate.

TWIN DELETION CONFIRMED: verifyParticipationRequirements resolves to EXACTLY ONE
secure surface per SDK — Swift ONLY generated free fn ScpBindings.swift:16052
(insecure typed no-crypto twin deleted); Kotlin ONLY Scp.kt:1913 (Participation.kt
DELETED); Python ONLY trust.py:1041 module fn (no SCP method); TS ONLY scp.ts:2372.
expected_subject present+first+required ×4. Scp.swift:1138 comment correctly names
3-arg expectedSubject-first fn.

FINDING 1 (blocker, stale doc — the intended fix MISSED): Trust.swift:5 header
purports to document the GENERATED raw ucanEvaluate export but lists
(handle:token:presentingAgentDid:capability:proofTokens:) = presentingAgentDid
BEFORE capability. Actual generated export (ScpBindings.swift:3285 + bridge.rs:13931)
is capability BEFORE presentingAgentDid. Line 5 shows the WRAPPER order (line 36),
not the generated order. (Wrapper legitimately reorders: SDK wrappers ×4 all put
required presentingAgentDid before optional capability; generated/NAPI/PyO3 put
capability first. Only line-5's DOC label is wrong.)

FINDING 2 (moderate, misuse resistance): verifyParticipationRequirements return
contract asymmetry. Rust uniffi bridge.rs:6362 returns Ok(true) ALWAYS (failure =
Err, never Ok(false)). TS/Swift/Kotlin surface Bool/Boolean that can ONLY be true →
invites `if(!result) reject` control flow that never fires; real rejection THROWS.
Python returns None + raises (honest). Recommend the 3 others drop the vestigial
bool (void + throw) to match Python.

OBSERVATIONS: (a) verifyParticipationRequirements arg-order + shape asymmetry —
Python (expected_subject, requirements, profiles) TYPED lists vs TS/Swift/Kt
(expectedSubject, profileJson, requirementsJson) RAW JSON strings — positions 2/3
reversed Py-vs-rest + two adjacent String params silently swappable in the JSON trio.
(b) ucanValidate vs ucanEvaluate intra-op capability⇄presentingAgentDid positional
swap (required-vs-optional driven, documented) — sibling ops disagree.
