# `ScpError.Validation` uses `msg:` not `message:`

**Story:** PR #1725 (PR-D MCP allowlist migration)
**Severity:** Blocking for Swift CI build job

## Problem

`ScpError.Validation` is a UniFFI-generated case from a Rust enum where the
field is named `msg`. Swift surfaces the literal Rust field name as the
labeled-argument form. New code that throws a validation error using
`message:` compiles fine **locally without the XCFramework** (because the
generated bindings aren't linked) but fails the macOS `Swift / build + test`
CI job with:

```
error: incorrect argument label in call (have 'message:code:', expected 'msg:code:')
```

## Why this is easy to miss

Every other SDK uses `message`:

| SDK | Field/keyword |
|---|---|
| Python | `message=...` |
| TypeScript | `message: ...` |
| Kotlin | `message = ...` |
| Swift | **`msg: ...`** |

A coder agent (or human) who is fluent in the other SDKs will write
`message:` reflexively. Local `swift build` skips the offending file because
the binary target reports "does not contain a binary artifact" (the
XCFramework isn't built locally), so the bug only surfaces on CI.

## Resolution

Use `msg:` in all `ScpError.Validation` (and any other UniFFI-derived
variant) constructions:

```swift
throw ScpError.Validation(
    msg: "Description of the validation failure",
    code: "SCP-XXX-NNNN"
)
```

## How to apply

Before pushing Swift code that throws `ScpError.Validation`, grep for
`ScpError.Validation(` under `bindings/swift/Sources/SCP/` and confirm
every call uses `msg:`. The same rule applies to any UniFFI-generated
case whose Rust field name differs from the Swift idiom — when in doubt,
read `Sources/SCP/Internal/ScpBindings.swift` for the literal labels.

## How it reaches CI

A throw written with `message:` compiles nowhere, so the Swift CI job reports the
label-mismatch error above rather than shipping the defect. It reached CI once through the
`mcpDisableStdioAllowlist` ceremony throw in `bindings/swift/Sources/SCP/Scp.swift`, which
an author wrote with the Swift-idiomatic label instead of the generated one.
