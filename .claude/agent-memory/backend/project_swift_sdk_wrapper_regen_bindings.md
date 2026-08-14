---
name: project-swift-sdk-wrapper-regen-bindings
description: Swift SDK wrapper work on a NEW UniFFI bridge op requires regenerating the committed ScpBindings.swift (build-xcframework.sh --dev) — it also builds the dev xcframework enabling local swift build/test = the exact CI flow
metadata:
  type: project
---

Adding a Swift SDK wrapper (`bindings/swift/`) for a newly-exported UniFFI bridge op is NOT source-only: `Sources/SCP/Internal/ScpBindings.swift` is UniFFI-GENERATED but CHECKED IN (~5700+ lines), and it will not contain the new op/record until regenerated. Your wrapper won't compile against the stale bindings.

**Why:** the wrapper calls `inner.<newOp>(...)` and references the generated Record type (e.g. `ReservedKeyPackage`) directly on the concrete UniFFI `Scp` class — these symbols only exist after regeneration.

**How to apply:**
- Run `bindings/swift/build-xcframework.sh --dev` from a Bash tool. It (1) release-builds `scp-ffi-uniffi` for macOS arm64 with `allow_in_memory_custody,testing`, (2) regenerates ScpBindings.swift via uniffi-bindgen, (3) builds the dev ScpFFI.xcframework (gitignored). This is the EXACT thing CI's `swift-build-test` job runs, so it also unblocks local `swift build` + `swift test` (tests link the real binary — they are real integration tests, not mock-only). Slow (~minutes); run it in the background early since it only touches Rust + ScpBindings, independent of your wrapper code.
- CI (`ci.yml`): `swift-lint` = `swiftlint lint --strict` + `swiftformat --lint Sources/ Tests/` (lints the COMMITTED bindings). `swift-build-test` regenerates bindings fresh then `swift build` + `swift test`. Run all four locally before reporting.
- **Commit the faithful regen even if it refreshes unrelated items.** The regen is atomic — it may also update a checksum / doc-comment for an unrelated op that had drifted from the Rust source since the last regen (the committed bindings can be stale). Keep it: the runtime `uniffiCheckApiChecksums` guard would reject a stale checksum against a fresh build. Note the drift in the commit message; do NOT hand-revert those hunks (that would make the committed file NOT match a fresh regen — worse).

**Per-SDK idiom (see [[feedback-per-sdk-idiom]]):** UniFFI maps Rust `Vec<u8>` -> Swift `Data` and generates a clean Record for `uniffi::Record` returns, so Swift surfaces the generated type DIRECTLY — no re-wrapping (unlike TS/Python, which re-type the napi/pyo3 byte return). UniFFI ops take `Identity` objects; Python/TS take DID strings. Match the bridge signature, not the other SDKs' string shape. `ScpError.Validation` uses `msg:` label, not `message:`.

**Idiom for "returns a live Context" ops:** low-level public forwarder on `SCP` returns the raw `ContextHandle`; a static factory on `Context` (e.g. `Context.joinFromWelcome`) wraps it — exactly the `contextCreate`/`Context.create` split. Value-returning ops (e.g. `reserveKeyPackage`) stay as public methods on `SCP`.
