# API Design Reviewer Memory

## SCP SDK Standards Review (2026-02-22)
- Reviewed all 10 files in `.docs/standards/` (sdk-common.md + 8 language files + conventions.md)
- Key blocking issues found:
  - Untyped `ceiling` and `custody` params (string instead of enum) across all SDKs
  - Swift code example contains force unwraps despite the file's own safety rules forbidding them
  - Contract says `identity` is a param on context_send/leave/close, but all 6+ language implementations omit it
  - Kotlin `Context.close()` uses `runBlocking` which deadlocks from coroutine contexts
  - Python `PermissionError` shadows `builtins.PermissionError`
- Cross-language naming table in sdk-common.md only covers 6 of 18 operations; needs `receive` row and others
- Java `Flow.Publisher` for streaming is too complex for the SDK's target audience
- Context state tracked as a string, not an enum, in Python examples

## SCP FFI Layer Review (PR #86, 2026-02-26)
- Reviewed WASM, NAPI, UniFFI bridges + Swift SDK bindings + sketch alignment
- 18 findings total, 3 critical, 5 major, 5 moderate, 5 minor
- Critical: WASM tool/UCAN ops use bare context_id (no state check), error code prefixes inconsistent across bridges, WASM identity_create always errors as exported public API
- Major: context state/custody remain stringly-typed in WASM/NAPI (UniFFI has enums), NAPI context_create accepts raw strings not typed structs, WASM payload as base64 instead of Uint8Array, WASM DIDDocument uses JSON strings where Vec<String> works
- Pattern: UniFFI bridge is the most type-safe; WASM is the least. NAPI is in between but could match UniFFI since it has full runtime access.
- Error code ranges: standard says TRANS=5000, TOOL=6000. NAPI swapped them. WASM uses SCP-IDENT- prefix, NAPI uses SCP-IDN- prefix. Must unify.
