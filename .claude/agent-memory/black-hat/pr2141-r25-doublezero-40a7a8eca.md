---
name: pr2141-r25-doublezero-40a7a8eca
description: Black-hat double-zero pass on PR #2141 error-classification path @40a7a8eca — LGTM, prior BLACK-R25-1 dissolved
metadata:
  type: project
---

# PR #2141 error-classification double-zero @40a7a8eca — LGTM, no BLOCKER/SHOULD-FIX

Branch fix/sdk-coverage-fail-closed-and-parity, merge-base bc4464566. Scope: SDK error-classification path.

## Verdict: LGTM. Entire branch-specific change set is fail-closed or strict improvement.

Key structural finding: **prior BLACK-R25-1 is DISSOLVED**. trust.py/trust.ts Layer-1 no
longer does ANY prose classification (no `startsWith("[SCP-PERM-3001]")`, no _EXPIRY/_REVOCATION
prefixes). Layer-1 is fully structured via `structured_to_capability_validation` reading the six
bridge bools (ADR-059). The PERM-3001-split coupling concern is moot — trust eval no longer keys on it.

Only TWO security-relevant `.code` branches remain in the whole SDK (grep-verified):
- trust.py:997 `if exc.code != NO_PARTICIPATION_FACTS_CODE` (SCP-CTX-2076)
- scp.ts:2911 `error instanceof ContextError && error.code === NO_PARTICIPATION_FACTS_CODE`
Both fold NoParticipationFacts → zeroed BehavioralRecord. Both SOUND: to hit the fold you need
BOTH the SDK exc TYPE (from bridge exc class name, ContextError/unknown→ContextError) AND the code
== exactly SCP-CTX-2076 (from the FIRST `[SCP-CAT-NNNN]` bracket at message START via anchored
`^\s*\[(SCP-[A-Z]+-\d+)\]`). Attacker controls NEITHER channel: only Rust sets the code prefix;
attacker input (subject_did/context_id) lands in {detail} AFTER the prefix, anchor rejects embedded
`[SCP-CTX-2076]`. Genuinely-different error → different code or non-ContextError type → propagates.
Fail-closed both directions.

## Change-set analysis
1. check-sdk-coverage.py `not name.startswith("_")` ×5 (extractor side) = fail-closed tightening,
   CLOSES prior BLACK-R25-2 (alias can no longer hide behind private helper → gate FAILS). Bounded
   positive rule ("only public symbols count"), parity w/ TS `export` requirement. `_coded_bridge_error`
   /`_SCP_CODE_RE` private + not in `__all__` = consistent (internal, not public surface).
2. errors.py `_coded_bridge_error`: isinstance-ScpError passthrough + anchored code + BRIDGE_ERROR_MAP
   class select (default ContextError). Anchor prevents masquerade.
3. outlets.py `_translate_bridge_error`→`_coded_bridge_error`: STRICT improvement — adds real code
   extraction + isinstance passthrough FIXES a latent bug (old code re-wrapped a re-caught StreamGap/
   InvalidGrant ScpError into ContextError via BRIDGE_ERROR_MAP.get(...,ContextError), downgrading the
   precise subclass). No saga-terminal regression (single-ctx outlet path never emits saga terminals;
   `_saga_terminal_from_bridge` still handles x-ctx separately, untouched).
4. scp.py 13 methods wrapped `except Exception: raise _coded_bridge_error(exc)` = additive, RE-THROWS
   (no swallow → no fail-open). `except Exception` does NOT catch asyncio.CancelledError/KeyboardInterrupt
   /SystemExit (BaseException) → cancellation propagates correctly. ucan_validate now throws typed
   UcanPermissionError w/ real PERM code (parity fix, still throws on denial).
5. TS scp.ts getBridge routing + try/catch on identityRemove/identityExecuteRecovery/eventLogQuery →
   mapBridgeError re-throw. mapBridgeError already-typed passthrough + anchored regex sound.
6. Swift/Kotlin/TS-identity = doc-comment spec-ref fixes (§3.2.1→§9.12) + rotationEventJson getter
   parity + `__setBridgeForTests` (test-guard'd, DCE'd from prod bundle). Not classification-relevant.

## Tests (test_outlets.py TestCodedBridgeError) — strong
Covers: 6-variant class mapping, unknown→ContextError default, leading-bracket code extraction,
**test_embedded_code_is_not_captured** (the anti-masquerade anchor property protecting the trust fold),
already-typed passthrough.

## CONSIDER (only residual, LOW)
- test_embedded_code_is_not_captured asserts `result.code != "SCP-CTX-2076"` — proves the masquerade
  fails but a `== "SCP-CTX-2000"` (the ContextError default) would be a stronger positive assertion.
  Not a gap; the `!=` already catches the exact attack.
- Persistent documented LOWs unchanged: NODE_ENV=development enables `__setBridgeForTests` (def-in-depth,
  prod bundle DCE is the real boundary); within_ceiling att[0]-only advisory (SCP-302 tracked).
