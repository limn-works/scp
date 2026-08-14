---
name: trust-signal-freshness-hardening-c35c62703
description: API review of trust/capability FFI 5-method surface @c35c62703 (freshness-hardening branch, WASM gone / 3 bridges) — NEEDS REVISION, 2 MODERATE
metadata:
  type: project
---

Round @c35c62703 ("fix(trust): harden participation freshness + fail-closed FFI clock + fix stale .pyi arg order"). Worktree agent-a1400c1b005b502a3. WASM REMOVED (3 FFI targets: PyO3/UniFFI/NAPI). Reviewed 5 public methods ×4 SDKs + bridges + .pyi.

VERDICT: NEEDS REVISION, 2 MODERATE.

CONVERGED / RESOLVED since prior rounds:
- F1 FIXED: Swift Trust.swift:5 now correctly documents the GENERATED bridge order (capability-before-presentingAgentDid), matches ScpBindings.swift:3285 generated `ucanEvaluate(handle,token,capability:String?,presentingAgentDid,proofTokens)`.
- F2 FIXED: verifyParticipationRequirements now uniformly void+throw ×4 (no vestigial always-true Bool). Python ->None/raise, TS :void, Swift throws, Kotlin Unit.
- Per-method cross-SDK order IDENTICAL ×4: ucanValidate(h,tok,capability,presentingAgentDid,pt?) cap@3 required; ucanEvaluate(h,tok,presentingAgentDid,capability?,pt?) did@3 required cap@4 opt. SDK wrappers all reorder from the uniform BRIDGE order (capability@3, presenting_agent_did@4 — PyO3 ucan.rs:267/393 both =None runtime-rejected) to did-first-for-evaluate (required-before-optional).

TWO MODERATE FINDINGS (in-scope, inline-fixable):
1. TS verifyParticipationRequirements (scp.ts:2372) MISSING signer-legitimacy caveat — NO docstring at all; bridge.ts:683 only a section header. Python trust.py:1064, Kotlin Scp.kt:1916, Swift Scp.swift:1142 (comment standing in for delegated free fn), core participation.rs/admission.rs ALL carry "authenticity is not authorization / signer_public_key self-certifying / inflates min_contexts / establish legitimacy separately / MUST NOT treat as authorization." Grepped bindings/typescript/src/ for legitimacy|authenticity|self-certif|min_contexts — none attach to this method (existing TS caveats scp.ts:2055/2414/types.ts:852 are UCAN-diagnostic + attestationCount = DIFFERENT method/risk). Review premise "TS already had it" is INACCURATE — TS is the gap.
2. .pyi (_scp_core.pyi) — this commit FIXED the stale verify_participation_requirements stub (old: 2 params wrong order, omitted expected_subject; new: expected_subject,requirements_json,profile_json). BUT same file: (a) ucan_evaluate has NO stub entry at all (shipped PyO3 method ucan.rs:395, called scp.py:1171); (b) ucan_validate stub (line 755) types presenting_agent_did: Any = ... advertising the fail-closed-REQUIRED security param as omittable.

OBSERVATIONS (agreed dispositions):
- verifyParticipationRequirements 2 adjacent same-typed JSON String params (requirementsJson/profileJson) in TS/Swift/Kt = residual footgun, runtime fail-closed (profile JSON won't deserialize as RequireParticipation), named params mitigate. Root = typed(Python list[RequireParticipation]/[ParticipationProfile]) vs JSON-string(others) input asymmetry → #1991 surface-wide ADR = RIGHT disposition. SHARPEN: not a missing-types case — TS ALREADY models ParticipationProfile(types.ts:1159)+RequireParticipation(types.ts:1203) AND already typed-input+internal-serialize for participationRecord cachedAttestations → intra-trust-domain inconsistency; #1991 should scope this method explicitly.
- ucanValidate vs ucanEvaluate capability/presentingAgentDid positional swap = CONSISTENT ×4, principled (optional-cap forces required-before-optional), documented every SDK, fail-closed. Alternative (mandatory null) is worse. Not a change.
- method-vs-free-fn split (free fn Python/Swift, method TS/Kotlin) = SOUND per ADR-048 §1/§7; verifyParticipationRequirements is genuinely STATELESS so free-fn is the honest shape.
- Python evaluate_trust/participation_record (context_id,subject_did) adjacent strings = same footgun class, per-SDK string-keyed model, pre-existing, fail-closed (DID fails ctx_id validation).

SUPERSEDES trust_signal_4sdk_twin_deletion_7e0f22894 (F1 now fixed; new .pyi + TS-caveat findings).
