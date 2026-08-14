# PR #2141 fix/sdk-coverage-fail-closed-and-parity (HEAD 28623a226) — bug-catch Pass 1

CLEAN — no BLOCKER/SHOULD-FIX. Verified in worktree /tmp/scp-review-r25.

Branch scope beyond 156-commit main merge:
- check-sdk-coverage.py: `not name.startswith("_")` at 5 sites excludes private/dunder Python
  symbols from the extracted symbol set → FAIL-CLOSED (matrix entry to a private symbol now
  fails "not found", never falsely passes). 23/23 self-tests pass.
- TS scp.ts: 10 methods migrated to `getBridge(this).method(...)` — 5 identity lifecycle
  (identityRotateKey/AddAgentKey/RotateAgentKey/RemoveAgentKey/Migrate, commit a3a22a7fd) +
  5 async (contextSend/contextMemberCount/contextGovernancePropose/outletInvoke/ucanValidate,
  commit 28623a226). Error mapping preserved: createNativeBridge returns via wrapBridgeErrors
  Proxy which applies mapBridgeError on thenable rejection — same fn the old try/catch used.
  Handle-affinity preserved: native.ts identityRotateKey still calls handle.rotateKey() on the
  same instance; proxy does NOT deep-proxy returned handles. contextSend now passes Uint8Array;
  native.ts does Array.from→number[]. contextMemberCount `?? 0` normalizes bridge's number|null.
- eventLogQuery CORRECTLY EXCLUDED: scp.ts passes filterJson (raw string), Bridge iface declares
  EventFilter object that native.ts converts — routing through bridge would mis-shape at runtime.
  Keeps explicit try/catch mapBridgeError. Sound reasoning.
- errors.ts regex tightened `[A-Z]+-[A-Z]+-\d+` → `SCP-[A-Z]+-\d+` (anchored `^\s*`). All real
  codes are SCP-CAT-NNNN; stricter, anti-spoof, matches Python `_SCP_CODE_RE`.
- Python errors.py: `_coded_bridge_error` uses `.search()` (correct — `^\s*` anchor makes it
  equiv to .match; verified embedded code NOT captured, leading-ws tolerated, typed passthrough).
  Added to __all__. trust.py: removed `import re`+BRIDGE_ERROR_MAP, no stale refs remain.
  scp.py: 8 methods wrapped, all `raise _coded_bridge_error(exc) from exc`; `except Exception`
  correctly does NOT swallow CancelledError (BaseException). Lazy imports, no cycle.
- runtime.rs: test gated on allow_in_memory_custody (uses FfiKeyCustody::InMemory) — correct.

Minor CONSIDER (not filed as defect): TS contextMemberCount `?? 0` vs Python returns None —
cross-lang divergence on the null-count case; 0 is defensible/arguably more correct. Non-issue.

LESSON: ContextError(msg, code=None) applies its own class-default code (SCP-CTX-2000), so a
missing-code path still yields a coded error — don't assert `.code is None` after _coded_bridge_error.
