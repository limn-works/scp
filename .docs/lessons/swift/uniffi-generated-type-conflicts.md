# UniFFI-generated types conflict with hand-written Swift wrappers

**Date:** 2026-02-27
**Story:** SCP-103
**Severity:** Blocking for `swift build`

## Problem

When UniFFI generates real Swift bindings (`ScpBindings.swift`), they define types
like `UcanToken`, `ScpError`, `ContextState`, `TransportStatus`, `OutletDefinition`,
`OutletVerificationResult`, etc. The existing hand-written Swift wrapper files in
`Sources/SCP/` (`Ucan.swift`, `Errors.swift`, `Context.swift`, `Transport.swift`,
`Outlets.swift`, `Types.swift`) define the same types as placeholder structs/enums.

This causes "invalid redeclaration" and "ambiguous for type lookup" errors during
`swift build`.

## Resolution

The hand-written Swift files must be adapted to either:
1. Remove their duplicate type definitions and use the UniFFI-generated ones directly, or
2. Alias/re-export the UniFFI types with any additional Swift-idiomatic API surface

The key types that conflict:
- `ScpError` (Errors.swift vs ScpBindings.swift)
- `UcanToken` (Ucan.swift vs ScpBindings.swift)
- `ContextState` (Context.swift vs ScpBindings.swift)
- `ContextHandleProtocol` (Context.swift vs ScpBindings.swift)
- `TransportStatus` (Transport.swift vs ScpBindings.swift)
- `OutletDefinition` (Outlets.swift vs ScpBindings.swift)
- `OutletVerificationResult` (Outlets.swift vs ScpBindings.swift)
- `Message`, `Provenance`, `Capability` (Types.swift vs ScpBindings.swift)

## Key detail

`ScpBindings.swift` is tracked in git (not gitignored) so SPM consumers without
a Rust toolchain can use the package. This means the file is always present and
always compiled.
