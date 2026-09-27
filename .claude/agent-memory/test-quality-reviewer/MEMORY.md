# Test Quality Reviewer Memory

- [Gate self-tests can pass for the wrong reason](gate-selftest-over-determined.md) — isolate the branch under test, assert the error line only that branch prints, and mutation-check the test.
- [Agent-written tests duplicate each other](feedback_test_duplication.md) — batched coder passes copy earlier tests with trivial input changes; count distinct code paths.

## Recurring weak-test shapes in this repository
- An assertion that cannot fail: `>= 0` on an unsigned or empty-default value, or `Ok` asserted on a function that does nothing.
- A test that asserts an event was emitted when the behavior under test is a state change (role demotion asserted by its event, not by the role).
- A mock that returns success for every unstubbed method. The TypeScript `bindings/typescript/tests/mock-bridge.ts` harness throws on any unstubbed method except the documented `SAFE_DEFAULT_METHODS`; hold other mocks to that standard.
- A realistic TypeScript bridge failure is a plain `Error` whose message carries the code (`[SCP-PERM-3001] permission error: …`); a test that rejects with a typed error subclass tests a shape the bridge never produces.
- A browser-path test that deletes `globalThis.Buffer` must assert that `Buffer` is then undefined; if the delete silently fails, the test passes through the Node path.
