# PR #2141 R25 Pass-1 — error-wrapping/anchored-regex delta (28623a226) — 2026-07-16 — LGTM, 0 BLOCKER/SHOULD-FIX

Branch `fix/sdk-coverage-fail-closed-and-parity`, worktree /tmp/scp-review-r25. Reviewed the branch-specific error-path delta (beyond the 156-commit main merge).

## Verdict: SECURE, fail-closed in every direction. 2 CONSIDER (non-security).

### Anchored code-extraction regex (the core security change)
- TS `mapBridgeError` (errors.ts:366): OLD `/\[([A-Z]+-[A-Z]+-\d+)\]/` (unanchored, any bracketed triple anywhere) → NEW `/^\s*\[(SCP-[A-Z]+-\d+)\]/` (start-anchored + SCP-literal). Python errors.py:`_SCP_CODE_RE` = `r"^\s*\[(SCP-[A-Z]+-\d+)\]"` (was unanchored `\[(SCP-[A-Z]+-\d+)\]` in trust.py, now moved to errors.py + anchored).
- Bridges ALWAYS emit code at position 0: napi error.rs `#[error("[{code}] …")]` (all variants), pyo3 error.rs Display `write!(f, "[{code}] … error: {message}")`. So anchoring loses ZERO legit codes.
- Attack closed: a message whose BODY (not start) contains `[SCP-CTX-2076]` (or any code) can no longer forge classification. Materially matters for trust.py Layer-1: `except ContextError: if exc.code != NO_PARTICIPATION_FACTS_CODE("SCP-CTX-2076")` absorb-vs-propagate. Anchored → body-injected 2076 → code=None → propagates (fail-LOUD). Old `.search` leftmost still preferred the genuine start code for standard PyO3 format, so the exposure was the no-leading-code edge (raw panic / wrapped sub-error string); anchoring is strictly fail-closed there.
- Python `^` w/o MULTILINE + `.search` == match at pos 0 only; `\s*` includes newlines but `^` non-multiline blocks line-2 codes. Correct.

### _coded_bridge_error idempotency / double-wrap
- `if isinstance(exc, ScpError): return exc` short-circuit → idempotent. scp.py 8 sites: `except Exception as exc: raise _coded_bridge_error(exc) from exc` — catches Exception (NOT BaseException, so asyncio.CancelledError propagates), always re-raises (no swallow), preserves cause via `from exc`. Native calls never return pre-wrapped ScpError so no real double-wrap. CLASS chosen by `type(exc).__name__` (native class, not user-controlled), code only populates `.code`.

### TS getBridge migration (5 methods: identityRotate/AddAgent/RotateAgent/RemoveAgent-Key retyped + identityMigrate; contextSend, contextMemberCount, contextGovernancePropose, outletInvoke, ucanValidate)
- getBridge → createNativeBridge → returns `wrapBridgeErrors(bridge)` (native.ts:2127). wrapBridgeErrors Proxy maps every own-function error through mapBridgeError once (sync throw + thenable .catch), does NOT deep-proxy returned handles (handle-affinity preserved). So migration = these methods now get structural typed errors (were raw). No auth change — same native ops, auth still native-side. Methods that KEEP try/catch (identityRemove, identityExecuteRecovery, eventLogQuery) call `this.#native.*` directly + `throw mapBridgeError(error)` once. Single-map everywhere; mapBridgeError ScpError-passthrough makes any accidental re-map safe.

### test-guard / __setBridgeForTests (unchanged posture from prior R25 notes)
- assertTestEnvironment fail-closed, `_IS_TEST_ENVIRONMENT` frozen at module load (Object.hasOwn defeats proto-pollution; false if process absent / NODE_ENV∉{test,development} & BUN_TEST empty). __setBridgeForTests contained 4 layers (not re-exported from index, exports map blocks ./internal/* deep import, files:[dist] only, tsup DCE). Sound defense-in-depth.

### check-sdk-coverage.py private-symbol exclusion (5 sites, `not name.startswith("_")` + `_Private` class skip)
- Shrinks symbol set → monotonic MORE gate failures only (fail-closed). Legit "stricter/parity-with-TS-export" enforcement modification, allowed per CLAUDE.md. `_coded_bridge_error` (now `_`-prefixed public in __all__) correctly excluded — not a matrix capability.

## CONSIDER (non-security)
1. `economy_verify_payment_receipts` (new py, scp.py:2204) is NOT wrapped in `_coded_bridge_error` unlike its 8 siblings — native economy exception `.code` extraction parity gap. No injection/secret. Consistency nit.
2. `contextMemberCount` `(await …) ?? 0` coalesces null→0 (masks null/uninit count as empty ctx). Not an SDK-side auth gate. Minor semantic.

No secrets, no injection surface, no info-leak regression (messages = UCAN/protocol diagnostics, unchanged surfacing). Saga datum extraction (retryAfterMs/sagaId/contendedContext) end-anchored, protocol data not secrets.

---
PASS-2 delta 28623a226->95bf99be4 (2026-07-16): outlets.py deletes inferior `_translate_bridge_error`, 4 sites now `_coded_bridge_error` (strictly stronger: +code extraction, ScpError-idempotent, classify-by-classname not body). 5 identity key-mutation methods (rotate_key/add_agent_key/rotate_agent_key/remove_agent_key/migrate) wrapped try/except->`_coded_bridge_error(exc) from exc` -- never swallow (always re-raise, no fail-open), Identity() construct OUTSIDE try, rotation_event_json is public 9.12 event not secret. `_coded_bridge_error` removed from errors.py __all__ = HYGIENIC (private _-name; all consumers explicit-name-import, unaffected by __all__; zero star-imports of scp_sdk.errors). SECURITY SUBSTANCE=LGTM. ONE SHOULD-FIX: test_outlets.py:36 `from scp_sdk.outlets import _translate_bridge_error` orphaned (fn deleted) -> pytest COLLECTION ImportError fails whole module -> CI breakage; TestTranslateBridgeError tests deleted behavior. Delta under-executed: deletion didn't migrate/remove its test.
