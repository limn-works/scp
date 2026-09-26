# A `_fromHandle` Wrapper Must Surface Every Protocol-Significant Field

**Problem**: a shared `_fromHandle` constructor is written against the common shape of an
object, so it drops by omission whatever a specific bridge method returns beyond that shape.
The napi `identityMigrate` returns a handle carrying `rotationEventJson` — the rotation event
the caller must distribute to active context members, per §9.12 of the security-model spec
and §4b of ADR-003, DID creation. The TypeScript SDK re-wrapped that handle through
`Identity._fromHandle`, which captures `did` and `custodyType` alone, so the field existed on
the bridge handle and reached no accessor. The migrate-then-distribute flow was impossible
from TypeScript, and the operation looked wired because it returned an `Identity`.

The loss is silent: the code compiles, the return type is satisfied, and only reading the
bridge handle reveals the missing data.

## Rules

- **When you add or wrap a bridge method that returns protocol-significant fields beyond the
  standard object shape, audit what the shared constructor captures.** Add explicit
  accessors, or a result type specific to that method, for every field the protocol requires
  the caller to act on.
- **Do not assume a generic wrapper round-trips everything.** It round-trips the fields it
  was written to know about.
- **For every field the bridge handle exposes, find the corresponding accessor in the SDK
  wrapper.** An exposed-but-unwrapped field is a half-done binding under the CLAUDE.md
  integration checklist.

## See also

- `.docs/lessons/napi-bridge-encoded-field-must-be-set.md`
- `.docs/lessons/migration-publish-recovery-handle.md`
- `.docs/lessons/typescript-sdk-bridge-patterns.md`
- `.docs/lessons/mock-test-must-not-invert-real-bridge-behavior.md` — the same migrate path.
