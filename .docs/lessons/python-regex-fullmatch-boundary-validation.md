# Python Regex Boundary Validation: Always Use `re.fullmatch`

## Problem

When mirroring Rust validators in Python, a common mistake is using `re.match()` or
`re.match()` with a trailing `$` anchor instead of `re.fullmatch()`. Both are subtly
wrong in ways that pass almost all tests but admit invalid inputs.

### `re.match()` — silently matches a valid prefix of an invalid string

```python
import re

# WRONG: matches a valid PREFIX, not the full string
pattern = re.compile(r"[a-zA-Z0-9_-]{1,256}")

pattern.match("ctx!")   # matches "ctx" (the valid prefix) — should reject
pattern.match("abc\n")  # matches "abc" — should reject
```

`re.match()` anchors to the START of the string but not the end. A string like
`"ctx!"` matches because `"ctx"` is a valid 3-character prefix of the pattern's
charset. The trailing `"!"` is simply ignored. Any string whose prefix satisfies the
pattern will slip through.

### `re.match(pattern + "$")` — better, but `$` admits a trailing newline

```python
# BETTER BUT STILL WRONG: $ in Python matches before \n at end of string
pattern = re.compile(r"[a-zA-Z0-9_-]{1,256}$")

pattern.match("ctx!")   # None — correct
pattern.match("abc\n")  # matches "abc" followed by \n — should reject
```

`$` in Python's default (non-`re.MULTILINE`) mode matches either end-of-string OR
immediately before a trailing `\n`. This admits `"valid-id\n"` when `"valid-id\n"` is
NOT a valid identifier — the newline would be part of the string passed to the bridge
and could cause surprising downstream behavior or bypass a boundary check.

## Fix: `re.fullmatch()` — anchors both ends, no `\n` exception

```python
# CORRECT: fullmatch anchors the entire string, no trailing-newline exception
import re

pattern = re.compile(r"[a-zA-Z0-9_-]{1,256}")

re.fullmatch(pattern, "ctx!")   # None — correct
re.fullmatch(pattern, "abc\n")  # None — correct
re.fullmatch(pattern, "ctx-1")  # match — correct
```

`re.fullmatch()` requires the entire string (from index 0 to the very end, including
any trailing `\n`) to match the pattern. It is equivalent to anchoring with `\A` and
`\Z` (not `$`).

## Why this matters when mirroring Rust validators

Rust validators use `len()` (byte count) and ASCII-only charsets (e.g.
`[a-zA-Z0-9_-]`). For pure ASCII charsets, a Python char count equals a Rust byte
count, so `{1,256}` in Python fullmatch is exact.

The important difference is at the boundary: Rust's `Regex::is_match()` matches the
entire string by default (like `fullmatch`), whereas Python's `re.match()` matches a
prefix. When translating a Rust validator to Python:

| Rust | Python equivalent |
|------|-------------------|
| `Regex::new(r"^[a-zA-Z0-9_-]{1,256}$")?.is_match(s)` | `re.fullmatch(r"[a-zA-Z0-9_-]{1,256}", s)` |
| `Regex::new(r"[a-zA-Z0-9_-]{1,256}")?.is_match(s)` | `re.fullmatch(r"[a-zA-Z0-9_-]{1,256}", s)` |

Both Rust forms above match the full string. Use `re.fullmatch` in Python — never
`re.match` or `re.search`.

## Pre-flight validation pattern

```python
import re

_CONTEXT_ID_RE = re.compile(r"[a-zA-Z0-9_-]{1,256}")


def _validate_context_id(context_id: str) -> None:
    if not re.fullmatch(_CONTEXT_ID_RE, context_id):
        raise ValidationError(
            "[SCP-VALID-7001] invalid context_id: must match [a-zA-Z0-9_-]{1,256}"
        )
```

Note: pass the compiled pattern object to `re.fullmatch()`, not the string. Both work,
but the compiled form avoids re-compiling on every call.

## Rules

- **Always use `re.fullmatch`** for string identity/boundary validation in Python.
- **Never use `re.match` alone** — it only anchors the start.
- **Never use `re.match(pattern + "$")`** — `$` admits a trailing newline.
- **Compile patterns once** at module level; pass the compiled object to `re.fullmatch`.

## See also

- `.docs/lessons/ucan-validate-needs-real-capability-uri.md` — closed allowlist
  pattern for error absorption; the same fail-closed discipline applies here.
