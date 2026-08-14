---
name: pr2141-78b6aae58-second-pass
description: PR #2141 second-pass (78b6aae58) — new Python error classes not exported from __init__; else clean
metadata:
  type: project
---

# PR #2141 second pass @ 78b6aae58 (fix/sdk-coverage-fail-closed-and-parity)

Commits since d2c056ea4: cfa28c9db (5 new Py exc classes + CODE_PREFIX_MAP prefix classification),
f222497bd (wrap discover/discover_contexts/economy_verify_payment_receipts), 32dc46bc1 (TS test rewrites),
+docs/lesson commits.

## MEDIUM (real defect, parity gap) — new Python error classes unreachable from public package
cfa28c9db added EconomyError/GovernanceError/StorageError/AttestationError/McpError to
`scp_sdk/errors.py` (+__all__) and wired CODE_PREFIX_MAP so `_coded_bridge_error` RAISES them on
SCP-ECON/GOV/STORAGE/ATTEST/MCP coded bridge errors. But `bindings/python/scp_sdk/__init__.py` was
NOT updated — the 5 names are absent from both the `from scp_sdk.errors import (...)` block AND
`__all__`. Verified empirically: `import scp_sdk; hasattr(scp_sdk,'EconomyError')` → False for all 5.
So `from scp_sdk import EconomyError` = ImportError; `except scp_sdk.EconomyError` = AttributeError.
Users can only catch base ScpError or reach private `scp_sdk.errors`. TS `src/index.ts` DOES export
all 5 publicly → breaks the PR's explicit TS/Python typed-error PARITY goal.
FIX: add the 5 imports to the errors import block + 5 names to __all__ (alphabetical).
Adjacent PRE-EXISTING (NOT this PR): StreamGap also missing from __init__ (existed at d2c056ea4).

## Verified CLEAN
- `_coded_bridge_error`: bare ValueError (no `[SCP-..]`) → code None → BRIDGE_ERROR_MAP.get(name, ScpError)
  = ScpError(msg, code=None→default SCP-UNKNOWN-0000). Fixes prior d2c056ea4 economy leak. except ScpError catches.
- Default changed ContextError→ScpError for unmapped/uncoded — intentional, non-breaking (base catch broader).
- `_saga_terminal_from_bridge` double-bracket fix: strips leading `[SCP-CAT-N]` from args[0] via _SCP_CODE_RE;
  code STILL read from args[1] (authoritative), datum from args[2]. _SCP_CODE_RE referenced before def-line but
  module-level so fine at call time. SAGA cat matches `[A-Z]+`.
- discover wrapped; discover_contexts delegates to discover (transitively wrapped). CancelledError (BaseException)
  not swallowed by `except Exception`. No double-wrap (economy.py calls native directly, not SCP wrapper).
- TS tests: makeSpyBridge(wrapBridgeErrors(Proxy)) + __setBridgeForTests → getBridge returns it; 5 methods
  (contextSend/GovernancePropose/outletInvoke/ucanValidate/contextMemberCount) dispatch via getBridge. Ran
  `bun test scp-typed-errors.test.ts` = 8 pass. Fallback assertion now constructor===ScpError + code check (non-vacuous).
- Ran `pytest test_outlets.py::TestCodedBridgeError` = 10 pass.
