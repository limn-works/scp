# Finding 009: UniFFI bridge uses no-op crypto provider for ContextManager

## Severity: major

## Summary

The UniFFI bridge's ContextManager is initialized with `FfiBridgeCrypto` — a no-op crypto provider where all operations succeed silently. MLS encryption, sender key rotation, and group management are all no-ops in the UniFFI path. Actual crypto operations are expected to be handled by platform callbacks.

## Evidence

**File:** `crates/scp-ffi/uniffi/src/runtime.rs`

Line 127: "Uses `FfiBridgeCrypto` (no-op)"
Line 155: "`FfiBridgeCrypto` (no-op crypto for state)"
Line 458: "They succeed by default (no-op)"
Line 470-472:
```rust
/// Stub crypto provider for the FFI bridge `ContextManager`.
///
/// All operations succeed (no-op). Real MLS and sender key operations are
```

Line 319: "Global stub crypto provider shared with the `CloseOrchestrator`."

## Expected Behavior

The ContextManager should use a real crypto provider that either:
1. Delegates to platform crypto (KeyStore/Keychain) for signing, with MLS/sender key operations
2. Uses InMemoryKeyCustody when in-memory mode is enabled

## Root Cause

The UniFFI bridge delegates crypto to platform callbacks (Swift/Kotlin implement `KeyCustodyProvider`). But the ContextManager's `CryptoProvider` trait is different — it handles MLS group operations, not just key custody. The bridge uses no-ops because MLS operations aren't routed through the mobile platform layer.

## Impact

Messages sent through the UniFFI bridge are NOT encrypted by MLS. Sender key rotation on member join/leave/block is a no-op. Forward secrecy is not enforced. This is a significant security gap for the Swift and Kotlin SDKs.

## Suggested Fix

1. Wire the real `MlsCryptoProvider` into the UniFFI ContextManager (same as NAPI uses)
2. Or implement a `PlatformCallbackCryptoProvider` that routes MLS operations to Swift/Kotlin
3. At minimum, document that UniFFI contexts are not encrypted and add a build-time warning
