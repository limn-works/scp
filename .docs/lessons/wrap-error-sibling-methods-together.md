# Wrap Error-Sibling Methods Together

**Problem**: adding `_coded_bridge_error` wrapping to one Python SDK method and missing its
behavioral sibling makes two methods with the same semantics fail through different types.
`identity_remove` and `identity_remove_if_present` in `bindings/python/scp_sdk/scp.py` both
drop retained identity state for a DID. Wrapping only the first makes it raise a typed
`ScpError` subclass while the second raises the raw native exception from the bridge, so
`try`/`except IdentityError` around the unwrapped sibling silently misses the failure. The
inconsistency is invisible at the call site and appears only on the error path.

## Rules

- **When you wrap one method's errors, wrap its entire behavioral family in the same
  change.** Before finishing, list the sibling names — `_if_present`, `_or_default`, paired
  create and remove, get and list variants — and confirm every member routes its errors
  through the same wrapper.
- **A method and its `*_if_present` or `*_or_*` variant should not differ in error type.**
  When they do, state the reason in the code.
- **Where a language allows it, put the check inside a throwing helper every call site must
  use, so the type system enforces the family rather than a reviewer.**

## A second instance (2026-08-17)

Pull request #2363, the ADR-025 App Attest fail-closed change, repeated this in
`bindings/swift/Sources/SCP/Platform/AppleStorage.swift`. A commit titled "read every SQLite
bind result" added a `SQLITE_OK` guard to `set(key:value:)` and left `get`, `delete`,
`listKeys`, `deletePrefix`, and `exists` calling `sqlite3_bind_text` as a bare statement. A
rejected bind there leaves the parameter reading `NULL`, and `DELETE FROM kv WHERE key =
NULL` steps to `SQLITE_DONE`, so `delete` removed no row and returned without throwing. The
family here is not a naming variant — it is every method that binds a parameter on the same
connection. The repair routed all six through one throwing `bindText(_:to:at:)`, so the
compiler now rejects a call site that drops the status.

## See also

- `.docs/lessons/python-bridge-error-message-strip-double-bracket.md`
- `.docs/lessons/test-error-code-fixtures-must-pass-conformance-gate.md`
