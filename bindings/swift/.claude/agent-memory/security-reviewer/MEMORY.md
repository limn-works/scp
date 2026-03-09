# Security Reviewer Memory — Swift SDK

## AppleKeyCustody Biometric Gating Review (2026-03-08, #392)

### Critical: Pseudonym HMAC key mismatch (Swift vs Rust)
- Swift `derivePseudonym` uses **private** key bytes as HMAC key (line 731)
- Rust `InMemoryKeyCustody::derive_pseudonym` uses **public** key bytes (ADR-027 amendment)
- This breaks cross-platform determinism — the core requirement of ADR-027
- Golden vector test would catch this but cannot compile (`storePrivateKeyBytes` is `private`, `@testable` only exposes `internal`)

### High: publicKey() triggers biometric under .required policy
- `publicKey()` calls `fetchPrivateKeyBytes` (line 547) which hits biometric-gated Keychain item
- ADR-025 explicitly states publicKey and destroyKey should NOT require biometric auth
- Fix: store public key bytes separately or in metadata, retrieve without biometric gate

### Key patterns in AppleKeyCustody
- Keys stored as `kSecClassGenericPassword` items with JSON metadata in `kSecAttrLabel`
- `.biometryCurrentSet` is the correct choice (ties to enrolled biometric set, triggers rotation on change)
- Protection class: `AfterFirstUnlockThisDeviceOnly` (no bio) vs `WhenUnlockedThisDeviceOnly` (bio)
- Error handling: `errSecUserCanceled` and `errSecAuthFailed` correctly mapped to `biometricAuthenticationFailed`
- No private key material in error messages (verified all PlatformError variants)
- `errSecDuplicateItem` treated as success — safe for UUID handles, questionable for deterministic pseudonym handles

### Missing: Memory zeroing
- Swift `Data` holding private key bytes is never zeroed after use
- Rust equivalent uses `Zeroizing<[u8; 32]>` wrapper
- Swift lacks a stdlib equivalent but manual zeroing is possible

### Positive patterns
- `Sendable` conformance throughout, `@concurrent` for background execution
- Proper `SecAccessControl` creation with error handling
- Destruction verification (re-fetch after delete)
- Clean error type hierarchy, no key material in messages
