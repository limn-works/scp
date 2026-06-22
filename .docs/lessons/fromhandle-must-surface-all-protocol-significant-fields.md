# `_fromHandle` Wrappers Must Surface All Protocol-Significant Fields

**Context**: The NAPI `identityMigrate` returns a handle carrying a `rotationEventJson`
field — the rotation event the caller MUST distribute to active context members
(spec §9.12, ADR-003 §4b) so the migrate→distribute flow can complete. The TS SDK re-wrapped
the handle through `Identity._fromHandle`, a generic constructor that captures only the
standard identity shape (`did`, `custodyType`).

**Problem**: `_fromHandle` silently dropped `rotationEventJson`. The field existed on the
bridge handle but was never copied onto the SDK object, so there was no accessor for it.
From TypeScript, the migrate→distribute flow was **impossible** — callers could migrate but
had no way to obtain the rotation event they're required to broadcast. The operation
*looked* wired (it returned an `Identity`) but was protocol-incomplete.

**Root cause**: A shared `_fromHandle` constructor is written against the *common* identity
shape. When a specific bridge method returns *extra* fields beyond that shape, the generic
wrapper has no knowledge of them and drops them by omission. The loss is silent: the code
compiles, the happy-path return type is satisfied, and only a careful read of the bridge
handle reveals the missing data.

**Rule**: When adding (or wrapping) a bridge method that returns protocol-significant fields
beyond the standard object shape, audit what the shared `_fromHandle` / `fromHandle`
constructor captures. If the handle carries extra fields the protocol requires the caller to
act on, add explicit accessors (or a method-specific result type) that surface them. Do not
assume the generic wrapper round-trips everything — it round-trips only the fields it was
written to know about.

A useful check: for every field the bridge handle exposes, grep the SDK wrapper for a
corresponding accessor. An exposed-but-unwrapped field is a half-done binding (see the
CLAUDE.md Integration checklist — a bridge export without a complete SDK wrapper is half-done).

Related: `.docs/lessons/napi-bridge-encoded-field-must-be-set.md`,
`.docs/lessons/migration-publish-recovery-handle.md`,
`.docs/lessons/typescript-sdk-bridge-patterns.md`, and
`.docs/lessons/mock-test-must-not-invert-real-bridge-behavior.md` (same migrate path).
