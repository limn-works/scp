---
name: adr055-structured-ffi-validation
description: ADR-055 / §7.2.4 — structured CapabilityValidation crosses the FFI as a typed record; SDKs stop parsing error prose. Interrogated 2026-06-27 on branch c3c-ts; verdict SOUND.
metadata:
  type: project
---

# ADR-055 structured capability/trust validation (branch c3c-ts)

Interrogated the four decisions behind ADR-055 / spec §7.2.4. **Verdict: SOUND**
(sunk-cost reversal, not perpetuation). Root cause it fixes: structured truth
(`CapabilityValidation`) was computed at every layer below the SDK, discarded at
the bridge, then reverse-engineered in `trust.py` by string-matching error prose
(`_classify_ucan_error` + `_PASSED_BEFORE`, ~200 lines of prefix denylists). That
prose-parsing was a non-convergent denylist AND masked a multi-attestation nonce
bug (mocks emitted prose without modeling nonce state).

**Why:** records the durable conclusions so a future pass doesn't re-litigate
settled premises and knows which sharp edges remain unguarded.

**How to apply:** if a future change re-introduces prose classification, a `"*"`
challenge sentinel, or a single-enum verdict in place of the six booleans — it is
regressing this decision; flag it.

## Premises that HOLD (verified against current code, not docs)
- `evaluate_ucan(Option<&CapabilityUri>)`, `None`=intrinsic: coherent two-question
  model (gate authorizes FOR a capability=mandatory; trust signal has none to
  challenge). `None` only skips `check_capability_match` (validate.rs ~836); ceiling
  + all-att (step 8) still run → fail-closed. The old `"*"` sentinel was a lie —
  the bridge `validate_capability_uri` REJECTS `*`.
- Six booleans + `all_valid`/`allValid`: granular shape IS the product (lossless);
  an enum verdict would re-create the lossy projection the ADR kills. Conjunction
  centralized in one accessor per binding → consumers can't drift.
- Subject-as-presenting-agent (HIGHEST VALUE): bridge defaults
  `presenting_agent_did.unwrap_or(&parsed_token.payload.aud)` →
  omitting it makes step-5 audience check `aud==aud` (vacuously true for ANY token,
  incl. one addressed elsewhere = trust inflation). Binding presenting_agent=subject
  makes the diagnostic meaningful. Python + TS both pass it identically.
- Single error chokepoint (`wrapBridgeErrors` Proxy): own-fn-only, one map site,
  sync/async preserved, handles NOT deep-proxied (preserves handle-affinity),
  `mapBridgeError` idempotent. Closed allowlist, not expanding denylist.

## Sharp edges still open (QUESTIONs, not blockers)
1. Bridge default `presenting_agent unwrap_or(token.aud)` is UNCHANGED and
   UNGUARDED — current callers pass subject correctly, but a future diagnostic
   caller that omits it silently re-opens the tautology. The new safety depends on
   caller discipline, not construction. Recommend a doc-warning/guard on the bridge
   method. (`crates/scp-ffi/src/ucan.rs`)
2. Empty-string capability coerced to "no challenge" (`filter(|c| !c.trim()...)`)
   — a second spelling of "absent" beyond `None`; un-specced.
3. `allValid==false` for an empty token set is indistinguishable from "all failed"
   — fail-closed + documented, but presupposes callers know allValid implies a
   non-empty set.

## Coherence note
Deleted `test_ucan_conformance.py` (613 lines) was correct: it tested the prose
denylist's sync with Rust strings — machinery serving the retired antipattern, not
lost coverage. `test_real_ffi.py` replaces guessing with the real typed path.
Respects [[one-way artifact flow]] (spec §7.2.4 → ADR-055 → code) and the per-SDK
idiom lesson (identical record shape, per-language wrapper).
