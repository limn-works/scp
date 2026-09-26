# A Mock Test That Inverts Real Behavior Is a Silent Future Blocker

**Problem**: `bindings/typescript/tests/identity-lifecycle.test.ts` asserted
`migrated.did === identity.did` for `identityMigrate`. The bridge does the opposite:
migration produces a new DID, which the Rust `migrate_returns_new_did` test asserts and
§9.12 of the security-model spec requires. The mock stubbed the migrate return value to echo
its input DID, and the assertion then compared the echo against the input, so the test
exercised the mock rather than the bridge. The test passed only because CI skips it when the
native addon is not built. The day the addon ships, that test fails on correct code and
blocks the correct implementation.

**Root cause**: mocking a return value to echo an input, then asserting the echo equals the
input, is a tautology in the shape of a behavioral assertion. Nothing in it exercises the
behavior it claims to check, so it can enshrine inverted semantics. Addon-gating then hides
that from CI until the gate opens.

## Rules

- **Never mock a return value to echo an input and then assert the echoed value equals the
  input.** The assertion is vacuous, and it can record the wrong semantics as the expected
  ones.
- **A mock test's expected value must match what the real implementation produces.** Before
  writing the assertion, find the authoritative behavior — the Rust bridge test, the spec
  section — and assert that.
- **Audit the assertions in addon-gated and CI-skipped tests against real behavior.** A test
  that never runs is exactly where an inverted assertion sits undetected, and "it passes"
  says nothing about it.

## See also

- `.docs/lessons/typescript-sdk-bridge-patterns.md`
- `.docs/lessons/napi-bridge-encoded-field-must-be-set.md`
- `.docs/lessons/fromhandle-must-surface-all-protocol-significant-fields.md` — the same
  migrate path, where the TypeScript wrapper drops a protocol-significant field.
