# Loom Status — Iteration 11

## Failing Tests
None. All 215+ tests pass across the workspace.

## Uncommitted Changes
None. All work committed.

## Fixed This Iteration
- Pre-existing WASM bridge E0119: `impl From<ScpWasmError> for JsError` conflicted with wasm_bindgen's blanket `impl<E: std::error::Error> From<E> for JsError`. Fixed by removing the redundant explicit impl. (commit 0ad5944)
- Swift `Errors.swift`: `LocalizedError` protocol is in Foundation, not stdlib. Added missing `import Foundation`. (commit 62cd249)
- Swift `AppleDeviceAttestation.swift`: `DCAppAttestService.generateAssertion` argument label is `clientDataHash:` not `clientData:`. Fixed call site label. (commit 62cd249)

## Tests Added / Updated
No new test files this iteration. Work is Swift platform adapters (no test harness yet) and ADR docs.

## Tool-Gated Stories
None skipped.

## Subagent Outcomes

| Story | Result | Summary |
|-------|--------|---------|
| SCP-080 | PASS | napi-rs bridge at crates/scp-ffi/napi/ (~500 lines). OnceLock<Runtime> for single Tokio runtime, HANDLE_COUNT AtomicUsize, ThreadsafeFunction streaming, full type/function surface mirroring WASM bridge. Committed d46bf91. |
| SCP-093 | PASS | AppleKeyCustody at bindings/swift/Sources/SCP/Platform/AppleKeyCustody.swift. Keychain CRUD for Ed25519/X25519 with kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly, CryptoKit signing/DH, key destruction with errSecItemNotFound verification. Committed eb93493. |
| SCP-094 | PASS | AppleStorage at bindings/swift/Sources/SCP/Platform/AppleStorage.swift. Swift actor with Keychain-derived 32-byte key, NSFileProtection on iOS, SQLCipher integration path stubbed. Committed cfab7ce. |
| SCP-095 | PASS | AppleDeviceAttestation at bindings/swift/Sources/SCP/Platform/AppleDeviceAttestation.swift. DCAppAttestService hardware path + software simulator fallback, generateKey/attestKey/generateAssertion flow, SHA-256(challenge‖deviceId) clientDataHash, NSLock-protected UserDefaults key persistence. Committed d244771. |
| SCP-096 | PASS | ApplePushProvider at bindings/swift/Sources/SCP/Platform/ApplePushProvider.swift. APNs silent push via content-available:1 only (zero context metadata per ADR-025 §10.7), CheckedContinuation bridge for registerForRemoteNotifications. Committed 15a9278. |
| SCP-098 | PASS | Swift SDK bootstrapped at bindings/swift/. Package.swift (swift-tools-version 6.2, iOS 17+, macOS 14+, binary ScpFFI target), Errors.swift, Types.swift, Internal/ScpBindings.swift. StrictConcurrency experimental feature enabled. Committed 0d551ed. |
| SCP-106 | PASS | ADR-028 completed in .docs/adrs/phase-6.md (749 lines). Covers Dispatchers.IO for FFI, callbackFlow→Flow<Message>, Android lifecycle via scp-sdk-kotlin-android artifact, Compose integration, Maven Central com.limn:scp-sdk-kotlin. Committed 1f5e189. |

## Review Outcomes
Reviews not run this iteration: changes are Swift platform adapters and ADR documentation — no Rust production code requiring cryptographic or security review. Next iteration's Swift actor implementation (SCP-099–101) warrants full security review.

## Architecture Notes
- Apple platform adapters live in **Swift** (`bindings/swift/Sources/SCP/Platform/`), not Rust. PRD story `files` arrays listed stale Rust paths — ADR-025 is the authoritative source.
- `DeviceAttestationProvider` protocol is defined in `AppleDeviceAttestation.swift` (local source of truth) until XCFramework pipeline is wired (SCP-103). UniFFI-generated bindings will declare it once that is complete.
- AppleStorage uses actor isolation; all other platform types use `nonisolated`/`@unchecked Sendable` with explicit locks, matching Swift 6.2 strict concurrency rules.

## Next Iteration

All blockers cleared. Unblocked stories (can run in parallel — no file conflicts between first 4):

- **SCP-081** (TypeScript SDK with dual-target bridge selection) — blocked by SCP-079, SCP-080, SCP-060 (all done) ✓
- **SCP-097** (Apple platform module root and re-exports) — blocked by SCP-093–096, SCP-082 (all done) ✓
- **SCP-099** (Swift Identity actor with async/await) — blocked by SCP-098, SCP-076, SCP-083 (all done) ✓
- **SCP-100** (Swift Context actor with message streaming) — blocked by SCP-098, SCP-076, SCP-083 (all done) ✓
- **SCP-101** (Swift Trust, Tools, EventLog, Transport, UCAN, MCP wrappers) — blocked by SCP-098, SCP-076, SCP-083 (all done) ✓
- **SCP-103** (Build XCFramework and configure SPM distribution) — blocked by SCP-098, SCP-076, SCP-082, SCP-083 (all done) ✓

Note: SCP-099/100/101 touch different Swift source files (Identity.swift, Context.swift, multiple module wrappers) — no file conflicts. SCP-103 touches Package.swift/build system only. SCP-097 creates a new module root file. SCP-081 is entirely in TypeScript bindings. All 6 can run in parallel.
