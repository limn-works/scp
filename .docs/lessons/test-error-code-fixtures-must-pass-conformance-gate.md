# Test Error-Code Fixtures Must Pass the Same Conformance Gate as Production

**Date:** 2026-07-16
**Source:** PR #2141 review+fix session — `scripts/check-error-codes.sh`

## The Problem

`scripts/check-error-codes.sh` scans **all** `.ts`, `.py`, and `.rs` files in the
repo — test files included. It has no test-path exclusion. Any error code that is
out of range or uses a non-canonical prefix fails the gate, regardless of whether
it lives in production code or a test fixture. Two ways a fixture breaks the gate:

- **Out-of-range code for a real prefix** — e.g. `SCP-GOV-6001`, when the GOV range
  is `11000-11999` (see the script's range table and the `SCP-GOV)` case).
- **Non-canonical prefix** — e.g. `SCP-WEIRD-9999`, when `SCP-WEIRD` is not one of
  the recognized categories (`IDENT|CTX|PERM|CRYPTO|TRANS|OUTLET|VALID|STORAGE|ATTEST|MCP|GOV|ECON|SAGA`).

## The Pattern

In test fixtures, either:

1. Use a **real, in-range** code for the category under test, or
2. Use the **`SCP-UNKNOWN-*` or `SCP-TEST-*` sentinel** — both are explicitly
   allowlisted in the script (`SCP-UNKNOWN)  ;; # Sentinel for unmapped bridge
   errors — allowed` and `SCP-TEST)  ;; # Test-only sentinel — allowed`) for the
   "unmapped / placeholder error" case.

Never invent a placeholder prefix or an arbitrary number for a test.

## Why This Matters

The gate is a repo-wide invariant, not a production-only one. A "just a test
fixture" placeholder is indistinguishable to the scanner from a real violation, and
will turn CI red on an otherwise-correct change.

## Related

- `scripts/check-error-codes.sh` — the gate (do not weaken; it is an enforcement file)
- `.docs/lessons/python-bridge-error-message-strip-double-bracket.md`
