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

## See also

- `.docs/lessons/python-bridge-error-message-strip-double-bracket.md`
- `.docs/lessons/test-error-code-fixtures-must-pass-conformance-gate.md`
