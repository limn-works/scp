# Cross-SDK timestamp integer coercion — guard NaN, Infinity, and signed/unsigned drift

**Date:** 2026-04-14
**Source:** PRs #1638 and #1642 — `verifiedAt` / `revokedAt` integer enforcement

## The invariant

Rust source uses `u64` for all timestamps. Every SDK must produce a `u64`-compatible value
at the FFI boundary: a finite, non-negative integer. Floats, `NaN`, `Infinity`, negative
numbers, and booleans all violate this invariant and must be rejected explicitly, not
coerced silently.

## What goes wrong per language

| SDK        | Failure mode                                                                 | Fix                                                                 |
| ---------- | ---------------------------------------------------------------------------- | ------------------------------------------------------------------- |
| Swift      | `Int` used where `UInt64` expected — silently narrows and admits negatives   | Use `UInt64` throughout. Do **not** follow the Apple-convention `Date` type; the wire format is integer seconds, not `Date`. |
| Python     | `int(x)` happily accepts `True` (returns `1`), `False` (returns `0`), floats | Wrap with a helper that catches `TypeError`/`ValueError`/`OverflowError` and rejects booleans explicitly if the field is semantically numeric |
| TypeScript | `JSON.parse` returns `number` (f64). `Math.trunc(NaN) === NaN`               | Guard with `Number.isFinite(x)` before `Math.trunc(x)`. Throw `ValidationError` with `SCP-VALID-7005` on failure |
| Kotlin     | `Long` already correct — JVM rejects non-integer JSON at deserialization     | Nothing required if using `kotlinx.serialization` with `Long`       |

## Python's bool-is-int trap

```python
>>> isinstance(True, int)
True
>>> int(True)
1
```

Any `int(value)` call where `value` came from untyped deserialization can smuggle a boolean
through. For timestamp fields this is cosmetically harmless (you get `1`) but semantically
wrong — the source type violated the schema and the SDK pretended it didn't. Either reject
`bool` explicitly, or at least document that it is coerced.

## Math.trunc(NaN) silently poisons timestamps

```js
Math.trunc(NaN)        // NaN  — not a thrown error
Math.trunc(Infinity)   // Infinity
NaN === NaN            // false  — comparisons silently all return false
```

If NaN enters a timestamp comparison (e.g. `verifiedAt < now`), every branch of the comparison
returns `false`, which typically short-circuits to the "not yet valid" or "not yet expired"
code path. The object looks like a valid attestation but is silently unusable. Always guard
with `Number.isFinite()` **before** `Math.trunc()`.

## Error code

Use `SCP-VALID-7005` (invalid field value) for finite-integer failures. **Do not** use
`SCP-VALID-7003` (JSON schema error — the JSON parsed fine) or `SCP-VALID-7004` (missing
required field — the field was present). See `.docs/standards/sdk-common.md` §"Registered
SCP-VALID- codes".

## How to catch this when reviewing

1. Every SDK field that maps to a Rust `u64`: grep for its access point and confirm either the
   language's deserializer rejects non-integers (Kotlin `Long`, Rust `u64`, Swift `UInt64`)
   or there is an explicit finite-integer guard at the FFI boundary.
2. Swift-specific: any `Int` or `Date` in a struct that mirrors a Rust `u64` is wrong. Search
   for `Int\b` in FFI-facing Swift structs.
3. Python-specific: `int(x)` on an untyped field is a yellow flag. Prefer an explicit helper
   that handles `bool`, `NaN`, `Infinity`, and overflow.

## Related

- `bindings/python/scp_sdk/identity.py::_parse_finite_int` — reference implementation
- `bindings/typescript/src/identity.ts` — `Number.isFinite` + `Math.trunc` pattern
- `bindings/swift/Sources/SCP/Identity.swift::RevocationStatus` — `UInt64` throughout
- `.docs/standards/sdk-common.md` — registered `SCP-VALID-` codes including 7005
