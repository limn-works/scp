# Cross-SDK Timestamp Coercion: Reject NaN, Infinity, Booleans, and Negative Values

Rust uses `u64` for every timestamp, so each SDK must hand the FFI a finite, non-negative
integer and reject anything else explicitly rather than coercing it.

| SDK | Trap | Guard |
|---|---|---|
| Swift | `Int` narrows and admits negatives; `Date` is the wrong type, since the wire value is integer seconds | `UInt64` throughout |
| Python | `int(True)` is `1`, and `int()` accepts floats | a helper that rejects `bool` and catches `TypeError`/`ValueError`/`OverflowError` (`_parse_finite_int` in `bindings/python/scp_sdk/identity.py`) |
| TypeScript | `Math.trunc(NaN)` is `NaN`, and every comparison with `NaN` is false, so a poisoned timestamp reads as "not yet valid" or "not yet expired" | `Number.isFinite(x)` before `Math.trunc(x)` |
| Kotlin | none: `kotlinx.serialization` into `Long` rejects non-integers | — |

Report a failure as `SCP-VALID-7005` (invalid field value). `SCP-VALID-7003` means the JSON
failed its schema and `SCP-VALID-7004` means a required field is missing, and neither is true
here.
