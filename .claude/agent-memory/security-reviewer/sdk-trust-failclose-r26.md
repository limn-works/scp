# SDK Layer-1 trust classification fail-closed (fix/sdk-coverage-fail-closed-and-parity) -- 2026-07-15 -- APPROVED

Files: `bindings/python/scp_sdk/trust.py`, `bindings/typescript/src/trust.ts`,
`bindings/typescript/src/scp.ts` (mapBridgeError in errors.ts:259).

Design = optimistic-then-narrow: Layer-1 CapabilityValidation fields start True,
narrowed to False on the first ucan_validate failure by classifying the bridge
error into the 11-step validate.rs pipeline stage (`_PASSED_BEFORE` / `__PASSED_BEFORE`
map stage -> set of fields that PASSED before it). SOUND because every uncertain
path is fail-closed:
- `unknown` classification -> empty set -> all fields False.
- null/malformed att[0].with (no bridge call) -> all False.
- `[SCP-VALID-*]` boundary reject (control/HTML chars in URI) -> all False (absorbed).
- empty/undefined token list -> all False (dataclass default in Py; explicit in TS).
- Only `[SCP-PERM-3001]` (the single code all UcanError variants map to) is absorbed
  into a narrowed verdict. `[SCP-PERM-3030]` (handle-affinity misuse) RE-RAISES
  (Py: startswith guard inside `except bridge.UcanError`; TS: closed regex allowlist)
  so a wrong-SCP-instance programming bug isn't masked as a false all-False verdict.
  PERM-3000 and all future codes propagate.
- Revocation narrowing (commit 8ddce4ab0): `_REVOCATION_PREFIXES = ("token revoked:",)`
  ONLY. Operational "revocation unauthorized:"/"revocation failed:" REMOVED -> now
  classify unknown -> all False (fail-closed). Even if validate.rs ever emitted those
  at step 10, the direction is conservative (not_revoked reported False), no hole.

Injection: extracted att[0].with URI is only ever a bridge arg (validated by
ucan_validate); never used in query/format/eval. Reading unverified JWT payload is
safe by construction (crypto verification happens in the bridge). Malformed parse ->
None/null fail-closed.

Leakage: error text preserved verbatim by mapBridgeError = UCAN diagnostics
("token expired", "signature verification failed"), not keys/paths. logger.debug
logs subject_did/context_id (identifiers, not secrets). OK.

Docstrings correctly warn Layer 1 = token self-consistency, NOT "authorizes op X",
and that aud->subject_did binding is an upstream-issuance obligation. No silent
security default.

Round 26 HEAD ae3a4238f = DOCS-ONLY (ADR-053): corrects overclaim "enforced by the
type system" -> "structurally encouraged; substrate/auth-flow isolation is a
foreign-impl obligation, verified by conformance test where observable"; and DISCLOSES
migration-reveal transit (consume->import_ed25519_signing_key transits 32B pre-rotation
seed through shared bridge memory; Zeroizing narrows not eliminates). Strictly improves
posture (honest residual-leak disclosure, no enforced guarantee weakened).

Verdict: APPROVED, zero blocking findings across all 4 categories.

R6-restarted (HEAD 23779139f) delta = SECURITY FIX. Top commit deletes the
pure-Swift `verifyParticipationRequirements(requirement:profile:)` twin in
Trust.swift (and its co-located insecure types: ParticipationProfile =
`[ParticipationFact: UInt64]` dict, ParticipationThreshold, RequireParticipation).
That twin did a BARE `observed >= threshold.minimum` on a caller-supplied
profile dict — NO Ed25519 signature verify, NO freshness (max_age), NO distinct-
signer count (min_contexts), NO subject binding → forgeable participation-
admission bypass (attacker builds any profile dict to pass a gate). The
name-only SDK coverage gate (check-sdk-coverage.py matches symbol NAME, semantics
= human-review invariant by design) was satisfied on the twin's name, masking
the secure path. Post-delete, the ONLY callable `verifyParticipationRequirements`
in Swift is the UniFFI-generated free func `(profileJson:requirementsJson:)` in
Internal/ScpBindings.swift (still a top-level `public func` → gate still passes,
now unambiguously bound to the Rust-backed scp-core verifier that does full
sig/freshness/min_contexts/threshold checks). Confirmed grep: no residual
pure-Swift threshold-comparison helper reachable. TrustEvaluation Layer-1 fields
still hardcoded false (fail-closed) in the two `init(from:)` paths. Other 5 files
(trust.py, trust.ts, wasm ucan.rs, ucan_errors.rs, check-sdk-coverage.py) byte-
identical to R26/R27 APPROVED state. Verdict: SECURE, zero findings; deletion
strictly improves posture.

R27 (HEAD 22ac39777) delta since R26 ae3a4238f = 3 docs/lessons + clippy-only
Rust refactors, ALL behavior-preserving: uri.rs parse_query_params
`find('=')?` == old `else return None` in filter_map (identical skip of
valueless capability-URI query params); tools.rs extract_cost
`.filter(|v| !v.is_none())` == old and_then PyNone drop; fullstack.rs test
println only. Re-verified current tree: Layer-1 optimistic-True block gated by
`if capability_tokens:` (empty list -> dataclass defaults all-False,
fail-closed); PERM-3030 re-raise present both SDKs (Py startswith guard L877,
TS closed regex allowlist absorbs ONLY `/^\[SCP-PERM-3001\]/`, VALID-* ->
ALL_LAYER1_FIELDS_FALSE, else throw); REVOCATION_PREFIXES == ("token revoked:",)
both SDKs. Prototype-pollution guard (test-guard.ts _evaluateTestEnv) uses
Object.hasOwn so `Object.prototype.NODE_ENV="test"` can't elevate; frozen at
load. Wildcard-URI trap fixed (extract att[0].with, never "*"). ONE standing
OBSERVATION (documented, non-blocking): Layer-1 validates att[0] only per token
(multi-att AND-intersection tried 8909092eb, reverted 205966ced pending a
bridge single-call multi-URI+one-nonce op); signal-incompleteness, NOT an auth
bypass (Layer-1 is self-consistency signal; real enforcement at bridge/runtime
when capability is exercised). R27 re-affirms APPROVED.
