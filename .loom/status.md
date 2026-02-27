# Loom Status — Iteration 10

## Failing Tests
None. All 2,322+ tests pass across the workspace.

## Uncommitted Changes
None. All work committed.

## Fixed This Iteration
- SCP-078 review: `identity_create` discarded key material immediately — `InMemoryKeyCustody` and `ScpIdentity` were dropped, leaving `Identity` handle as a dead DID-string-only shell. Fixed by adding `scp_identity: Option<ScpIdentity>` and `in_memory_custody: Option<Arc<OpaqueInMemoryKeyCustody>>` to the `Identity` struct and retaining both in the `InMemory` branch of `identity_create`.
- SCP-079 review: `transport_connect` accepted `ws://` (plaintext) in addition to `wss://`. Fixed to reject `ws://` — only `wss://` (TLS) is permitted per ADR-022 AC-1.

## Tests Added / Updated
No new test files this iteration. Fixes are structural (key material retention, URL scheme enforcement).

## Tool-Gated Stories
None skipped.

## Subagent Outcomes

| Story | Result | Summary |
|-------|--------|---------|
| SCP-083 | PASS | ADR-026 completed in .docs/adrs/phase-5.md: Swift SDK actor isolation (SCPContext as actor, DTOs as nonisolated), AsyncStream<Message> for messaging, @Observable for SwiftUI, SPM Package.swift at bindings/swift/, deinit+close() resource management. 636 lines added. |
| SCP-105 | PASS | ADR-027 completed in .docs/adrs/phase-6.md: Android Keystore TEE-backed Ed25519 (API 33+), software fallback API 26-32, Play Integrity Standard API, FCM opaque {data:{scp:"1"}} payload, SQLCipher with TEE-derived 32-byte key, PlatformAdapter.make() factory in Kotlin. 434 lines added. |
| SCP-078 | PASS | UniFFI async bridging: HANDLE_COUNT AtomicUsize and scp_shutdown() added to lib.rs, Drop impls on all opaque handles (Identity, ContextHandle, UcanToken, TransportManager), identity_create("in_memory") wired to actual scp-core DidDht + InMemoryKeyCustody. Committed directly to main. |
| SCP-079 | PASS | WASM bridge crate created at crates/scp-ffi/wasm/ (10 source files, ~600 lines). wasm-bindgen, wasm-bindgen-futures, js-sys, web-sys dependencies. No scp-core dependency (tokio rt-multi-thread incompatible with wasm32-unknown-unknown). Full type/function surface mirroring UniFFI bridge. Cargo.toml conflict resolved (both crates/scp-ffi/uniffi and crates/scp-ffi/wasm now in workspace). |

## Review Outcomes

| Story | Result | Issues | Fixes Applied |
|-------|--------|--------|---------------|
| SCP-083 | PASS | No issues — ADR-only work | None needed |
| SCP-105 | PASS | No issues — ADR-only work | None needed |
| SCP-078 | FAIL→FIXED | HIGH: identity_create discarded InMemoryKeyCustody and ScpIdentity immediately, leaving Identity handle as dead DID-string shell — all future signing operations would fail; LOW: UcanToken::drop calls decrement_handle_count() with no matching increment in ucan_mint (latent, not triggerable — ucan_mint always returns Err) | Fixed in cc60abc: Identity struct now retains Option<ScpIdentity> + Option<Arc<OpaqueInMemoryKeyCustody>> for in_memory paths |
| SCP-079 | FAIL→FIXED | HIGH: transport_connect accepted ws:// (cleartext), allowing interception of all SCP traffic; MEDIUM (5): WasmDIDDocument zero validation, context_send base64 gap, panic hook info leakage, missing forbid(unsafe_code), serde_json error leakage — all in stub code, tracked for full integration stories | Fixed in cc60abc: transport_connect now rejects ws:// with TLS-required error per ADR-022 AC-1 |

## Next Iteration

Unblocked stories (can run in parallel — no file conflicts between first 3):

- **SCP-080** (Implement napi-rs bridge for Node.js/Bun) — blocked by SCP-036, SCP-079, SCP-060 (all done) ✓
- **SCP-098** (Bootstrap Swift SDK package structure and UniFFI bridge) — blocked by SCP-076, SCP-082, SCP-083 (all done) ✓
- **SCP-106** (Write ADR-028: Kotlin SDK) — blocked by SCP-105 (done) ✓
- **SCP-093** (Implement Secure Enclave key custody adapter, Rust) — blocked by SCP-076, SCP-082 (all done) ✓
- **SCP-094** (Implement Apple Keychain integration and protection classes, Rust) — blocked by SCP-076, SCP-082 (all done) ✓

Note: SCP-093/SCP-094 are Rust platform adapters (crates/scp-platform/apple/), independent of Swift SDK. SCP-095 (App Attest) and SCP-096 (APNs) also unblocked but may have file conflicts with SCP-093/SCP-094 — schedule in follow-on batch. SCP-080, SCP-098, and SCP-106 have no shared files with the Apple adapter stories.
