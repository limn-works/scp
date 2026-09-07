# Python Regex Boundary Validation: Always Use `re.fullmatch`

**Problem**: mirroring a Rust validator in Python with `re.match()`, or with
`re.match()` plus a trailing `$`, admits inputs the Rust validator rejects. Rust's
`Regex::is_match` over a `^...$` pattern requires the whole string; Python's `re.match`
anchors only the start, and Python's `$` matches before a trailing newline as well as at
the end of the string.

```python
import re

pattern = re.compile(r"[a-zA-Z0-9_-]{1,256}")

pattern.match("ctx!")               # matches the prefix "ctx" — should reject
pattern.match("abc\n")              # matches "abc" — should reject
re.compile(r"[a-zA-Z0-9_-]{1,256}$").match("abc\n")   # matches — should reject
re.fullmatch(pattern, "ctx!")       # None — correct
re.fullmatch(pattern, "abc\n")      # None — correct
re.fullmatch(pattern, "ctx-1")      # match — correct
```

A trailing newline that `$` admits travels onward as part of the string the caller hands to
the bridge.

## Rules

- **Use `re.fullmatch` for every identity or boundary validation.** It anchors the entire
  string, equivalent to wrapping the pattern in `\A` and `\Z`.
- **Never use `re.match` alone**, which anchors only the start; **never use
  `re.match(pattern + "$")`**, whose `$` admits a trailing newline; and **never use
  `re.search`**, which anchors neither end.
- **Compile the pattern once at module level and pass the compiled object to
  `re.fullmatch`.**
- **A Python character count equals a Rust byte count only for an ASCII-only charset.** For
  a charset such as `[a-zA-Z0-9_-]`, a `{1,256}` bound in Python matches Rust's `len()`
  bound exactly; for any charset admitting non-ASCII, the two count different things.

```python
_CONTEXT_ID_RE = re.compile(r"[a-zA-Z0-9_-]{1,256}")


def _validate_context_id(context_id: str) -> None:
    if not re.fullmatch(_CONTEXT_ID_RE, context_id):
        raise ValidationError(
            "[SCP-VALID-7001] invalid context_id: must match [a-zA-Z0-9_-]{1,256}"
        )
```

## See also

- `.docs/lessons/ucan-validate-needs-real-capability-uri.md` — the same fail-closed
  discipline applied to capability-token validation.
