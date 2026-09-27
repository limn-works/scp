# Swift SDK (`bindings/swift/`)

Every public method calls exactly one UniFFI bridge function, and no protocol logic lives in Swift (ADR-026, the Swift SDK, in `.docs/adrs/phase-5.md`). Follow `.docs/standards/swift.md`.

## The generated bindings

- `Sources/SCP/Internal/ScpBindings.swift` is UniFFI output. Do not edit it; it runs to thousands of lines, so grep it instead of reading it whole.
- The Swift SDK ships through a separate SPM mirror that the release pipeline publishes, and CI's Swift jobs regenerate `ScpBindings.swift` from the current Rust source (`build-xcframework.sh --dev`) before compiling. A committed `ScpBindings.swift` that lags the Rust UniFFI surface therefore does not break any consumer's build, so do not report the lag as a build failure. The `swift` column of the SDK capability matrix is checked against the Rust UniFFI surface, not against this file.
- The committed file still matters to anyone who builds the dylib and uses it. UniFFI computes each `uniffi_scp_ffi_uniffi_checksum_method_*` constant over a method's FFI signature, and a mismatch makes the whole SDK `fatalError` at first use. Never hand-edit a signature or a checksum integer; regenerate with `build-xcframework.sh`. Because CI regenerates, a local `swift build` on the committed file can pass while CI fails on a changed signature. To detect stale checksums, generate fresh bindings (`cargo run -p scp-ffi-uniffi --bin uniffi-bindgen --release -- generate --library target/release/libscp_ffi_uniffi.dylib --language swift --out-dir <dir>`) and diff the `checksum_method…() != N` lines.
- Swift exposes a Rust field name as the argument label. `ScpError.Validation` comes from a Rust variant whose field is `msg`, so write `ScpError.Validation(msg: "…", code: "SCP-XXX-NNNN")`, not `message:`. Read the literal labels in `ScpBindings.swift` for any generated case.
- Without the XCFramework, `swift build` skips the target that "does not contain a binary artifact", so it type-checks less than CI does; a wrong label compiles locally and fails the macOS `Swift / build + test` job.

## Writing Swift here

- **Never write `@unchecked Sendable`.** Alec: "not cool. we don't like those." When strict concurrency flags a type, drop the `Sendable` conformance if the type never crosses an actor boundary; otherwise change its fields to `Sendable` types.
- Use actors, not locks. The target is macOS 14 and iOS 17, which lack `Synchronization.Mutex`.
- UniFFI async functions are already `async throws`; call them with `try await`, never through `withCheckedThrowingContinuation`.

