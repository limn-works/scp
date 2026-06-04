---
name: Swift UniFFI bindings are regenerated in CI from Rust source
description: CI regenerates bindings/swift/Sources/SCP/Internal/ScpBindings.swift during build-xcframework.sh; committed file may be stale and compile locally but not in CI
type: reference
---

Swift CI job "Swift / build + test" runs `bindings/swift/build-xcframework.sh --dev`, which invokes `uniffi-bindgen` against the current Rust source in `crates/scp-ffi/uniffi/src/` and OVERWRITES `bindings/swift/Sources/SCP/Internal/ScpBindings.swift` before the Swift compile step.

Implications for future sessions:
- If a Rust FFI function changes signature (adds `async`, changes `-> T` to `-> Result<T, ScpError>`, etc.), the SDK wrapper code in `bindings/swift/Sources/SCP/*.swift` must match the regenerated signature — not whatever the currently committed `ScpBindings.swift` says.
- Local `swift build` uses the committed `ScpBindings.swift` and may succeed when CI will fail. To preview the CI surface, run `bindings/swift/build-xcframework.sh --dev` locally first.
- Rust signature → UniFFI Swift signature rules that matter:
  - `pub fn foo() -> T` → `func foo() -> T` (sync, non-throwing)
  - `pub fn foo() -> Result<T, ScpError>` → `func foo() throws -> T` (sync, throwing)
  - `pub async fn foo() -> T` → `func foo() async -> T` (async, non-throwing)
  - `pub async fn foo() -> Result<T, ScpError>` → `func foo() async throws -> T` (async, throwing)
- When SDK wrapper default closures call FFI functions, their typealias signatures and default closure bodies must track all four quadrants.

Stale-checksum failure mode (verified Batch 4 round-4): UniFFI embeds a checksum guard per FFI method in `ScpBindings.swift` (`if uniffi_..._checksum_method_X() != <int> { return .apiChecksumMismatch }`, ~line 15000+). If a Rust method changes signature (e.g. infallible → `Result`), the checksum changes. A stale committed value does NOT break compilation — it triggers a runtime `fatalError("UniFFI API checksum mismatch")` on first object init. CI does NOT catch this: both `swift-build-test` and `bridge-parity-swift` run `build-xcframework.sh --dev` which regenerates the bindings, so CI's checksums always match its freshly-built dylib. Only DOWNSTREAM consumers (who build the dylib but use committed `ScpBindings.swift` as-is) hit the crash. To verify a suspected stale checksum: run steps 1-2 of build-xcframework.sh (build host dylib for aarch64-apple-darwin with the dev features `allow_in_memory_custody,testing`, then `uniffi-bindgen generate --library <dylib> --language swift`), grep the generated `scp.swift` for `checksum_method_<name>`, and diff against committed. Expect ONLY the changed methods' checksum lines to differ; bare uppercase acronyms in doc-comments (e.g. `PyO3` → `` `PyO3` ``) may also flip depending on rustdoc/toolchain version — those are benign comment-only diffs.

Files where this bit us during #1549 PR 3:
- `bindings/swift/Sources/SCP/Governance.swift` (defaultRegisterLocalDid)
- `bindings/swift/Sources/SCP/Lifecycle.swift` (defaultResume + ResumeFn + Lifecycle.resume)
- `bindings/swift/Tests/SCPTests/LifecycleTests.swift` (resume test async-awareness)
- `bindings/swift/Tests/SCPTests/RealFFITests.swift` (ffiLocalDidManagement)
- `bindings/swift/Tests/SCPTests/PersistenceTests.swift` (used FFI param name `timeoutSecs:` instead of SDK wrapper `timeout:`)
