---
name: pr2141-typederr-parity-28623a226
description: PR #2141 delta bc3d88eef..28623a226 — TS↔Python typed-error wrapping parity across 8 SDK methods + getBridge migration; ALIGNED, 1 CONSIDER (non-convergent per-method wrapping vs #2157)
metadata:
  type: project
---

# PR #2141 delta @ 28623a226 (fix/sdk-coverage-fail-closed-and-parity, /tmp/scp-review-r25, 2026-07-16)

5 commits past my prior FINAL (bc3d88eef, ALIGNED zero findings). VERDICT: ALIGNED, 1 CONSIDER, no BLOCKER/SHOULD-FIX.

**Why:** Extends the PR's Python/TS parity goal to typed-error mapping. **How to apply:** if PR advances further, the CONSIDER below is the only open alignment thread.

Delta commits: 5a4291bf3 (TS regex→SCP-literal), d1b21316a (ruff format), 13aecbbbb (lesson ADR-059 restructure), a20eb5314 (Python 8-method wrap), 28623a226 (TS 5-method getBridge migration).

Verified clean:
- `check-sdk-coverage.py` delta = ONLY a stray blank-line removal (d1b21316a merge-format). NOT a gate weakening. The fail-closed private-symbol `not name.startswith("_")` exclusion was already reviewed/ALIGNED at bc3d88eef — unchanged here.
- errors.ts regex tightened `[A-Z]+-[A-Z]+-\d+`→`SCP-[A-Z]+-\d+`, now byte-matches Python `_SCP_CODE_RE`. Stricter/fail-closed direction, cross-lang consistency.
- errors.py: `_SCP_CODE_RE` + `_coded_bridge_error` MOVED from trust.py (byte-identical logic; idempotent — returns ScpError unchanged if already typed). Underscore-prefixed ⇒ invisible to coverage gate even though added to `__all__`. trust.py now imports it; dropped BRIDGE_ERROR_MAP import (no dangling ref, all imports still used @1295/996/63).
- scp.py: 8 methods wrapped `try/except Exception → raise _coded_bridge_error(exc) from exc` (identity_execute_recovery, identity_remove, context_member_count, context_send, ucan_validate, event_log_query, outlet_invoke, governance_propose). Function-local imports match file's existing `import json` style.
- scp.ts: 5 async methods (contextSend, contextMemberCount, contextGovernancePropose, outletInvoke, ucanValidate) migrated from `#native`+manual try/catch → `getBridge(this)` Proxy (wrapBridgeErrors maps by construction; NOT double-wrapped — try/catch removed). Behaviorally correct: contextSend now passes Uint8Array through bridge; native.ts:300 does `Array.from(payload)` internally for NAPI Vec<u8>. eventLogQuery CORRECTLY EXCLUDED from getBridge (scp.ts passes filterJson:string but Bridge iface declares filter:EventFilter — routing would break at runtime); kept explicit try/catch guard.
- 8-method parity is SYMMETRIC: each Python-wrapped method has a TS counterpart that also maps (5 via getBridge migration, identityExecuteRecovery/identityRemove via getBridge from a3a22a7fd, eventLogQuery via explicit guard).
- test docstring corrected: false universal "Every SCP method wraps" → honest two-path (getBridge Proxy + explicit guard) description; admits "Unmapped methods surface a bare Error; broadening coverage tracked in #2157."
- lesson ucan-validate restructure (280L churn): marks pre-ADR-059 client-side sections (att[0].with extraction, ucanValidate Layer-1, _PASSED_BEFORE, _REVOCATION_PREFIXES) as Historical; adds "Current approach (ADR-059)" intrinsic-mode ucan_evaluate→CapabilityValidation 6-bool. Honest, matches ADR-059 confirmed in prior rounds.

**CONSIDER (non-blocking):** PR adds 8 per-method error wrappers — the *non-convergent* per-method boilerplate CLAUDE.md's over-engineering guidance warns against. The convergent fix (apply wrapBridgeErrors to `this.#native` at construction, ~200 methods, no per-site boilerplate) is deferred to **issue #2157** (VERIFIED real, OPEN, well-framed: "hand-per-method approach is non-convergent... Not a live fail-open — explicit try/catch are functionally correct; convergence/DX improvement"). NOT a No-deferral/completeness violation because unmapped methods are NOT fail-open — they still throw Error carrying `[SCP-CODE]`, just not the typed subclass; nothing masked, no false guarantee (crucial distinction from nullifier/stub tenet). Per-method wrappers are idempotent with the future Proxy (harmless, not conflicting-throwaway). Honest docstring pointing at #2157 is a virtue. Minor asymmetry: #2157 is TS-only; Python has the same ~180-method non-convergence with no analog tracking issue — parity would want a Python convergent fix or twin issue.

OBS (bug-catcher territory, non-alignment): scp.ts contextMemberCount now `(await bridge.contextMemberCount(...)) ?? 0` coerces bridge's `number|null` to 0; prior `#native` path typed it as bare number. Negligible/arguably-more-correct.
