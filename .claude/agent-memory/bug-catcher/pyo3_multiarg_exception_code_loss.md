---
name: pyo3-multiarg-exception-code-loss
description: PyO3 `new_err((a, b, ...))` with 2+ args makes `str(exc)` a tuple repr, silently breaking the Python SDK's anchored code-extraction regexes.
metadata:
  type: project
---

# PyO3 multi-arg exceptions silently drop `.code` in the Python SDK

CPython `BaseException.__str__` returns `''` for 0 args, `str(args[0])` for 1 arg,
and **`repr(args)`** for 2+ args. So `SomeExc::new_err((formatted, code, ...))`
makes `str(exc)` start with `(`, not `[`.

Both Python-SDK translators anchor on a leading bracket:

- `bindings/python/scp_sdk/errors.py` — `_SCP_CODE_RE = re.compile(r"^\s*\[(SCP-[A-Z]+-\d+)\]")`, used by `_coded_bridge_error`
- `bindings/python/scp_sdk/outlets.py` — `_LEADING_BRIDGE_CODE = re.compile(r"^\[(SCP-[A-Z]+-\d+)\]")`, used by `_translate_bridge_error`

Neither matches a tuple repr ⇒ `.code is None` and `.message` becomes the raw
Python tuple repr (leaking JSON blobs into user-facing text).

**Why:** The three saga terminals already hit this, which is exactly why
`_saga_terminal_from_bridge` exists — it reads `exc.args` positionally instead
of parsing `str(exc)`.

**How to apply:** Any new PyO3 `create_exception!` class raised with a tuple
payload needs (a) a dedicated `exc.args`-reading translator wired into every
call site that currently uses `_coded_bridge_error` / `_translate_bridge_error`,
or (b) it must keep `args[0]` as the sole arg and carry structure elsewhere.
Rust-side tests that only inspect `e.args` will NOT catch this — assert on
`str(exc)` too.

Found: SCP-OUT-031 PR-2b (`crates/scp-ffi/src/error.rs`, `OutletError::new_err`
with 7 positional args on the live `outlet_invoke` path).
