# API Design Reviewer Memory

## SCP SDK API Surface Review (2026-02-22)
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
