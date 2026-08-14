---
name: project-python-type-alias-gate-interaction
description: Python SDK single-name type aliases must use `X: TypeAlias = ...` AND ruff UP040 must stay ignored — a two-gate conflict
metadata:
  type: project
---

Declaring a single-name type alias in `bindings/python/scp_sdk/` (e.g. `InviteMemberOutcome = Sealed`) hits a two-gate conflict. Resolved on branch feat/adr049-2j-ffi-slice (commit 152888964).

- `scripts/check-no-mutable-module-globals.py` reads a bare single-name RHS (`X = SomeName`) as a mutable module-global and FAILS it. Its `_is_type_alias` only recognizes `X: TypeAlias = ...` (or `"TypeAlias"`). A `|`-union RHS (`X = A | B | C`, e.g. `StorageConfig`) is exempt because a BinOp RHS reads as a type expression; a bare Name is not. Fix = annotate: `X: TypeAlias = Sealed`.
- But ruff `UP040` (config `target-version = "py312"`, in `bindings/python/pyproject.toml`) then rewrites `X: TypeAlias = ...` to the PEP 695 `type X = ...` statement — which is a **syntax error on Python 3.10/3.11**. The package declares `requires-python = ">=3.10"`, so PEP 695 statement syntax is illegal. `UP047` was already ignored for the same reason; `UP040` must be ignored too (it is now).
- The gate does NOT scan PEP 695 `type X = Y` (an `ast.TypeAlias` node, not `Assign`/`AnnAssign`) — but that form is unusable here because of the 3.10 floor.

**Why:** the mutable-globals gate can't distinguish a type alias from a rebindable global without the annotation; ruff's py312 target mandates 3.12-only syntax the support floor can't parse.
**How to apply:** for any new single-name type alias in the Python SDK, write `X: TypeAlias = ...` (import `TypeAlias` from `typing`) and ensure `UP040` stays in the ruff ignore list. Do NOT use `type X = ...` and do NOT allowlist in the gate. See [[feedback-worktree-absolute-path]].
