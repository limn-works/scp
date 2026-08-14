---
name: adr055-c3c-prose-parsing-retired
description: C3c branch (ADR-055) deleted ~200-line prose-classification denylist in trust.py for a typed 6-bool CapabilityValidation; the convergent-result fix this agent exists to push toward.
metadata:
  type: project
---

The `c3c-ts` branch (ADR-055, spec §7.2.4) is the textbook positive example of retiring a
non-convergent denylist — the exact class [[project_adr055_structured_capability_validation]]
described as docs-only is here implemented in code.

**What it did:** Deleted from `bindings/python/scp_sdk/trust.py` the entire prose-classification
machinery (`_classify_ucan_error`, `_PASSED_BEFORE`, `_extract_core_error`, and six `*_PREFIXES`
tuples ~200 lines) that string-matched `[SCP-PERM-3001] permission error: …` error text to
reconstruct *which* of 6 UCAN checks failed. Replaced with direct consumption of the typed
`CapabilityValidation` (six per-stage bools) that already existed at every layer below the SDK.

**Why it's the right shape:**
- A typed 6-field record is closed by construction; a prose denylist chased "one more spelling"
  forever and silently mis-classified on any reword. The structured truth was being discarded then
  guessed back from a lossy string projection.
- The prose-parse also MASKED a real nonce bug (mocks emitted prose without modeling nonce state).

**Core change is minimal:** only `evaluate_ucan`'s `required_capability` went mandatory →
`Option<&CapabilityUri>` (intrinsic-validity mode when `None`, skips step-6 grant-match;
fail-closed preserved — omitting grant-match never flips a field to `true`). The enforcing gate
`ucan_validate` keeps a MANDATORY capability. Old SDK passed a `"*"` sentinel the real bridge
rejected; absence is now expressed by omitting the cap, not a wildcard.

**Residual minor findings (not blockers):** `allValid`/`all_valid` accessor defined but its own
`evaluate_trust` fold doesn't use it (per-field AND-reduce, different op — still hand-enumerates
6 fields); six-field remap literal hand-copied (TS ×3, Py ×2) with no shared `toCapabilityValidation`
helper. **Two error-mapping sites** (Proxy `wrapBridgeErrors` over the `Bridge` surface; per-method
`try/catch mapBridgeError` in the `SCP` class) — correct, NOT redundant: the class dispatches the raw
frozen `loadNativeAddon()` addon which can't be Proxy-wrapped without breaking handle affinity.

**How to apply:** When reviewing capability/validation SDK consumption, the convergent answer is
ALWAYS "consume the typed record"; flag any reintroduction of error-prose parsing as a regression.
