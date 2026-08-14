---
name: pr2141-r26-swift-twin-delete
description: PR#2141 Round 6 black-hat — deletion of insecure pure-Swift participation-verifier twin (@23779139f)
metadata:
  type: project
---

# PR#2141 Round 6 (restarted) — Swift twin deletion @23779139f

Delta vs Round 5 (14501c98b): ONE commit, `fix(swift): delete insecure participation-verifier twin`.
Pure 90-line deletion of `bindings/swift/Sources/SCP/Trust.swift`:
- Removed `verifyParticipationRequirements(requirement:profile:)` — bare `observed >= minimum`
  threshold math, NO sig verify / freshness / subject-binding / min_contexts.
- Removed its 4 supporting types: `ParticipationFact` (enum), `ParticipationThreshold`,
  `ParticipationProfile` (= `[ParticipationFact: UInt64]`), `RequireParticipation`.

## VERDICT: NO ATTACK VECTOR FOUND

Verified:
- Twin + 4 types have ZERO remaining refs outside generated ScpBindings.swift (word-boundary
  grep clean; the `contextsParticipated`/`governanceActionsAgainst` hits are BehavioralRecord
  fields, unrelated to deleted enum cases). Build integrity intact; no dangling refs.
- Secure path survives: `public func verifyParticipationRequirements(profileJson:requirementsJson:)`
  (UniFFI→Rust) at ScpBindings.swift:15097. Routes to Rust `scp-core` full verification.
- Coverage gate now GENUINELY load-bearing on secure path: matrix Trust/verify_participation_requirements
  swift=true, NO exemption. Swift alias `["verifyParticipationRequirements"]` resolves only to the
  generated free func (top-level public func, captured by _extract_swift_symbols, Internal/ rglob-scanned).
  If the secure func vanished, gate ERRORs (unmatched_true) → fails closed. Commit-msg claim accurate.
- Breaking API removal of the pure-Swift types is the intended fix, not a vector.

The 5 non-Swift target files (trust.py, trust.ts, wasm/ucan.rs, ucan_errors.rs, check-sdk-coverage.py)
are BYTE-IDENTICAL to Round 5 → prior RESISTANT findings stand (see pr2141-r25-batch3.md,
pr2141-sdk-trust-coverage-r25.md). Standing latent-only obs unchanged:
- R25-1: `[SCP-PERM-3001]` closed allowlist couples to "all UcanError→PERM_3001" invariant
  (ucan_errors.rs exhaustive match, currently all→3001, test-enforced). Future 3007/3008 split
  held back deliberately; not currently exploitable.
- R25-3 / BLACK-053 OBS-1: within_ceiling att[0]-only over-report — advisory Layer-1 field,
  documented SCP-302, per-action gate + Cat-A-over-all-caps catch it. Not a bypass.
