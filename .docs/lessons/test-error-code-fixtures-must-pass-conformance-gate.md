# Test Error-Code Fixtures Must Pass the Same Conformance Gate as Production

**Problem**: `scripts/check-error-codes.sh` scans every `.ts`, `.py`, and `.rs` file in the
repository, test files included, and excludes no test path. An error code that falls
outside its category's range, or that uses a prefix the script does not recognize, fails the
gate wherever it lives. A placeholder invented for a test fixture is indistinguishable to
the scanner from a real violation, and turns CI red on an otherwise-correct change.

Two ways a fixture breaks it:

- **An out-of-range number under a real prefix** — `SCP-GOV-6001`, when the governance range
  is 11000-11999.
- **A prefix the script does not recognize** — `SCP-WEIRD-9999`, when the categories are
  `IDENT`, `CTX`, `PERM`, `CRYPTO`, `TRANS`, `OUTLET`, `VALID`, `STORAGE`, `ATTEST`, `MCP`,
  `GOV`, `ECON`, and `SAGA`.

## Rules

- **In a test fixture, use a real in-range code for the category under test, or use the
  `SCP-UNKNOWN-*` or `SCP-TEST-*` sentinel**, which `scripts/check-error-codes.sh`
  allowlists for the unmapped or placeholder case.
- **Never invent a placeholder prefix or an arbitrary number for a test.**
- **Read a repository-wide gate as repository-wide.** "It is only a test fixture" is not a
  category the scanner has.

## See also

- `scripts/check-error-codes.sh` — the gate. It is an enforcement file; do not weaken it.
- `.docs/lessons/python-bridge-error-message-strip-double-bracket.md`
