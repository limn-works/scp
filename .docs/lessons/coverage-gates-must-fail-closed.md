# Coverage Gates Must Fail Closed and Match Symbols Exactly

`scripts/check-sdk-coverage.py` once warned, and exited 0, when a matrix cell marked `true`
had no implementing symbol, and it matched symbols by suffix. TypeScript identity-lifecycle
and Python economy/discovery gaps shipped under it, and about 23 non-existent operation
names passed by suffix collision with unrelated symbols.

## Rules

- **The default verdict is FAIL.** A `true` cell passes only by producing an exactly named,
  statically verified symbol or an exemption that cites provenance: an ADR, a spec section,
  or a generated-file path plus the command that verifies it.
- **Match exactly.** Suffix or substring matching admits fabricated capability claims.
- **An operation cannot be exempted in every SDK.** At least one SDK per operation must
  verify statically, or the exemption map re-opens the warn-only hole.
- **Give the gate negative self-tests and run them before the gate.**
  `scripts/test_check_sdk_coverage.py` strips an exemption and fabricates a `true` op, and
  both must exit 1.
- **The `ALIASES` table proves a symbol of that name exists, not that it implements the
  capability.** A method that returns `null` unconditionally passes. Whether the symbol does
  the work is a code-review question, and adding an alias asserts only the name.

See `.docs/lessons/a-green-check-that-asserted-nothing.md` for the wider catalogue of checks
that pass over nothing.
