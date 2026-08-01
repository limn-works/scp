# Strip the `[SCP-CAT-NNNN]` Prefix Before Constructing ScpError

**Date:** 2026-07-16
**Source:** PR #2141 review+fix session — Python SDK `_coded_bridge_error`

## The Problem

The PyO3 bridge formats native exceptions as a single string:

```
[SCP-CTX-2000] context error: description
```

The Python wrapper `_coded_bridge_error` extracts the code and constructs an
`ScpError`. If it passes the *raw* string through as `message`, the doubled
bracket surfaces to callers, because `ScpError.__str__` prepends the code again:

```python
# bindings/python/scp_sdk/errors.py
def __str__(self) -> str:
    return f"[{self.code}] {self.message}"
```

`ScpError(message="[SCP-CTX-2000] context error...", code="SCP-CTX-2000")` then
stringifies to `"[SCP-CTX-2000] [SCP-CTX-2000] context error..."`.

## The Pattern

Extract the code **first** (so the strip cannot affect classification), then strip
the leading `[SCP-CAT-NNNN] ` prefix so `.message` holds only the human-readable
description:

```python
match = _SCP_CODE_RE.search(raw_msg)     # extract code first
code = match.group(1) if match else None
message = raw_msg[match.end():].lstrip() if match is not None else raw_msg
```

## Why This Is Easy to Miss

`__str__` and the raw bridge string both embed the bracketed code, so each is
correct in isolation — the doubling only appears when they compose. A unit test
that asserts on `.message` alone passes; the defect only shows in `str(err)`.

## How to Catch This

- Any wrapper that both (a) parses a code out of a bridge string and (b) hands the
  string to a type whose `__str__` re-prepends the code must strip the prefix.
- Test `str(err)`, not just `err.message` and `err.code`, for bridge-wrapped errors.

## Related

- `.docs/lessons/test-error-code-fixtures-must-pass-conformance-gate.md`
- `.docs/lessons/wrap-error-sibling-methods-together.md`
