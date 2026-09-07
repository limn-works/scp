# Strip the `[SCP-CAT-NNNN]` Prefix Before Constructing `ScpError`

**Problem**: the PyO3 bridge formats a native exception as one string,
`[SCP-CTX-2000] context error: description`. The Python wrapper extracts the code from that
string and constructs an `ScpError`. When the wrapper passes the raw string through as
`message`, the bracketed code surfaces twice, because `ScpError.__str__` in
`bindings/python/scp_sdk/errors.py` prepends the code again:

```python
def __str__(self) -> str:
    return f"[{self.code}] {self.message}"
```

`ScpError(message="[SCP-CTX-2000] context error...", code="SCP-CTX-2000")` then stringifies
to `"[SCP-CTX-2000] [SCP-CTX-2000] context error..."`.

**Root cause**: `__str__` and the raw bridge string each embed the bracketed code, and each
is correct on its own. The doubling appears only when the two compose, so a unit test that
asserts on `.message` alone passes.

## Rules

- **Any wrapper that parses a code out of a bridge string and hands that string to a type
  whose `__str__` re-prepends the code must strip the prefix.** Extract the code first, so
  the strip cannot affect classification, then strip the leading `[SCP-CAT-NNNN] ` so
  `.message` holds the description alone:

  ```python
  match = _SCP_CODE_RE.search(raw_msg)
  code = match.group(1) if match else None
  message = raw_msg[match.end():].lstrip() if match is not None else raw_msg
  ```
- **Test `str(err)`, not only `err.message` and `err.code`**, for every bridge-wrapped
  error.

## See also

- `.docs/lessons/test-error-code-fixtures-must-pass-conformance-gate.md`
- `.docs/lessons/wrap-error-sibling-methods-together.md`
