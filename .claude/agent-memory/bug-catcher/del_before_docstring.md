# Python: `del` before docstring destroys `__doc__`

In Python, a string literal is only a docstring if it is the FIRST statement
in a function body. If any statement (e.g. `del exc_type, exc, tb`) precedes
the string literal, the string becomes a dead no-op expression statement and
`func.__doc__` is `None`.

- Found on branch `fix/sdk-coverage-fail-closed-and-parity` HEAD `44eaf5d05`
  in `bindings/python/scp_sdk/scp.py` `__exit__` / `__aexit__` (commit added
  `del exc_type, exc, tb` ABOVE the docstring).
- Ruff does NOT catch this (B018 useless-expression not enabled; excludes
  string literals). CI stays green while docstrings silently vanish.
- Detect: `ast.get_docstring(node)` returns None, OR scan for a bare
  `ast.Expr`+`ast.Constant(str)` statement at body index > 0.
- Fix: place `del`/unused-arg discards AFTER the docstring.
