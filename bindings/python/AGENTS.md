# Python SDK (`bindings/python/`)

Use `python3.12`, never the system `python3`. Follow `.docs/standards/python.md`.

## Validators that mirror a Rust regex use `re.fullmatch`

Rust's `Regex::is_match` over a `^...$` pattern requires the whole string. Python's `re.match` anchors only the start, and Python's `$` also matches before a trailing newline, so a Python mirror written either way admits inputs the Rust validator rejects, and the trailing newline travels on to the bridge.

```python
pattern = re.compile(r"[a-zA-Z0-9_-]{1,256}")
pattern.match("ctx!")  # matches "ctx" — wrong
re.compile(r"[a-zA-Z0-9_-]{1,256}$").match("abc\n")  # matches — wrong
re.fullmatch(pattern, "abc\n")  # None — correct
```

- Use `re.fullmatch` for every identity or boundary validation, with the pattern compiled once at module level. Never use `re.match`, `re.match(pattern + "$")`, or `re.search`.
- A Python `{m,n}` bound counts characters and Rust's `len()` counts bytes, so the two agree only for an ASCII-only character class.
