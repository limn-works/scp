---
name: pr2141-e4cb632b4-final-pass
description: PR #2141 final pass (1009e7925+e4cb632b4) — Py typed-error re-export + economy/mcp raise-site reconcile — CLEAN
metadata:
  type: project
---

PR #2141 `fix/sdk-coverage-fail-closed-and-parity` final verification @e4cb632b4 (worktree /tmp/scp-2141).

**CLEAN — 0 bugs.** Supersedes the earlier MEDIUM (missing __init__ exports) which THIS is the fix for.

- `1009e7925` added AttestationError/EconomyError/GovernanceError/McpError/StorageError/StreamGap to __init__.py imports + __all__. Verified all 6 `from scp_sdk import X` succeed (real `import scp_sdk` runs); no __all__ dups; every __all__ entry is a real attr.
- `e4cb632b4` reconciled preflight raise sites to typed classes: economy.py 4 raises ScpError→EconomyError (all SCP-ECON-12070); mcp.py 5 ValidationError→McpError (SCP-MCP-10002/4/5/6 + allowlist); scp.py 1 (mcp_disable_stdio_allowlist SCP-MCP-10007) ValidationError→McpError.
- Class↔code consistency VERIFIED against errors.py CODE_PREFIX_MAP: SCP-MCP→McpError, SCP-ECON→EconomyError (preflight now matches bridge-error classifier). All new classes subclass ScpError.
- No import cycle: economy.py imports EconomyError from scp_sdk.errors (leaf module, no back-import).
- No dangling ValidationError in mcp.py (0 refs). scp.py:2565/2625/2705 ValidationError refs are UNRELATED functions with local imports — untouched, still valid.
- economy.py:38 left as ScpError (SCP-UNKNOWN-0001 native-missing) — correct, not economy-domain.
- No `except ValidationError` catch anywhere in SDK; validate_client_connect callers (scp.py:1787/1805) don't catch → sibling class swap breaks nothing.
- Tests: 42/42 pure-Python mcp preflight pass; format_amount tests pass (test_economy uses pytest.raises(ScpError), EconomyError is subclass → still catches + .code assert holds).

**ENV note:** 8 test_mcp + 4 test_economy failures are PRE-EXISTING native-missing (`_scp_core` not built in worktree) — all fail inside SCP() ctor / economy `_bridge()` native import, NOT the rename. Not introduced by this PR.
