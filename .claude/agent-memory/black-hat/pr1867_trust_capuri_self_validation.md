---
name: pr1867-trust-capuri-self-validation
description: PR #1867 (5e1bf40d2) trust.ts/trust.py extract att[0].with from UNVERIFIED JWT to drive ucanValidate; step6 self-match tautology + advisory-only + no subjectDid binding
metadata:
  type: project
---

# PR #1867 / commit 5e1bf40d2 — trust Layer-1 self-capability validation

Branch fix/sdk-coverage-fail-closed-and-parity. New commit changes both SDKs' `evaluate_trust`/`evaluateTrust` Layer-1:
OLD: validate each cap token against `"*"` → bridge rejects InvalidCapabilityUri → Layer1 ALWAYS all-false (dead).
NEW: `__extractCapabilityUri` reads `att[0].with` from UNVERIFIED base64url JWT payload, passes it as `required_cap` to `ucanValidate`.

## How required_cap is used in validate_ucan (scp-protocol/.../validate.rs:512)
- Step 6 check_capability_match(granted_caps, required_cap): required_cap == att[0].with which IS in granted_caps ⇒ **tautology, always passes** (unless att[0].with unparseable, then MalformedToken → classify ceiling).
- Step 8 verify_ceiling_compliance([required_cap], ceiling): only meaningful use. Ceiling check is `{resource}:{action}` only (capability_name), **context-id-AGNOSTIC** (capability.rs:196 is_within_ceiling uses capability_name not context binding).
- Steps 2 (sig), 3-4 (chain/root issuer == ctx.creator_did), 5 (aud==presenting_agent), 9 (nonce), 10 (revocation), 11 (expiry) are **independent of required_cap** — operate on real token bytes/signature. Tampering att[0].with breaks the signature (step2) unless attacker owns iss key.

## Key findings (all MEDIUM at most; advisory surface)
1. evaluateTrust result is ADVISORY (public TrustEvaluation data; "protocol provides data not verdict"). Runtime authoritative UCAN check is on real action paths (send/tool invoke), NOT this. So a forged Layer-1 verdict misleads an SDK consumer's own authz decision, does NOT bypass MLS/runtime.
2. **No subjectDid binding**: evaluateLayer1(scp, handle, tokens) never receives subjectDid. presenting_agent defaults to token.payload.aud. So ANY validly-signed token (for any aud) yields a Layer1 verdict RECORDED AGAINST the queried subjectDid. A caller passing tokens[] + subjectDid that don't correspond gets a misattributed verdict. Pre-existing in spirit but now newly load-bearing since Layer1 actually runs.
3. **Multi-cap token under-checks ceiling**: only att[0] drives ceiling check. A token granting [in-ceiling-cap, out-of-ceiling-cap] reports withinCeiling=true because only att[0] is ceiling-checked. The real action-path validate_ucan checks the SPECIFIC required cap per action, so runtime safe; but Layer1 advisory withinCeiling is over-optimistic for multi-cap tokens. trust.ts:317/trust.py:779 att[0] only.
4. Step6 tautology means withinCeiling effectively == "att[0].with parses AND is in ceiling". signaturesValid/tokensValid still meaningfully reflect real sig/parse. The classification model still yields useful tokensValid/signaturesValid/timeBoundsValid etc.
5. Coverage gate total_ops==0 floor = clean tightening, no bypass (matches prior memory).

## Cross-lang parity: SOUND
- base64 padding python `4 - len%4` then `%4` correct for all residues.
- att non-list / att[0] non-object: both fail-closed to all-false (TS Array.isArray + ?. ; py broad except).
- both re-raise PERM-3030, both propagate non-UCAN errors.
