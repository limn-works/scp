# A Mock Test That Inverts Real Behavior Is a Silent Future Blocker

**Context**: `bindings/typescript/test/identity-lifecycle.test.ts` asserted
`migrated.did === identity.did` for `identityMigrate`. The NAPI bridge's actual behavior is
the **opposite**: migration produces a *new* DID (the Rust `migrate_returns_new_did` test
asserts the two DIDs differ, per spec §9.12). The TS test only passed because it is
addon-gated and CI skips it when the native `.node` addon isn't built.

**Problem**: The mock stubbed the migrate return value to echo its input DID, then asserted
the echoed value equalled the input. That assertion says **nothing** about real behavior —
it tests the mock, not the bridge. Worse, it encodes the *wrong* semantics. The day the
addon ships and the real bridge runs, this test will **fail on correct code** and block the
correct implementation. A test that goes red when the system finally works is an anti-test.

**Root cause**: Mocking a return value to echo the input, then asserting the echo equals the
input, is a tautology dressed as a behavioral assertion. It can lock in inverted semantics
because nothing in the test ever exercised the behavior it claims to check. Addon-gating then
hides the defect from CI until the gate opens.

**Rule**:
- Never mock a return value to echo an input and then assert the echoed value equals the
  input. The assertion is vacuous and can enshrine wrong semantics.
- A mock test's expected value must match what the **real** implementation produces. Before
  writing the assertion, find the authoritative behavior (the Rust bridge test, the spec
  section) and assert *that* — e.g. for migrate, `migrated.did !== identity.did` per §9.12.
- Treat addon-gated / CI-skipped tests with extra suspicion: they are exactly where an
  inverted assertion can sit undetected until it blocks correct work. Audit their assertions
  against real behavior, don't assume "it passes" means "it's right."

Related: `.docs/lessons/typescript-sdk-bridge-patterns.md`,
`.docs/lessons/napi-bridge-encoded-field-must-be-set.md`, and
`.docs/lessons/fromhandle-must-surface-all-protocol-significant-fields.md` (same migrate path,
TS wrapper drops a protocol-significant field).
