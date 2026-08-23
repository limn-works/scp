# Security Reviewer Memory — Swift SDK

## AppleKeyCustody Biometric Gating Review (2026-03-08, #392)

### RESOLVED: Pseudonym HMAC key model (spec §9.10.4.A)
- HMAC key is the private-derived `pseudonym_secret`, NEVER the public key (public-key keying = membership-enumeration oracle).
- Software custody (Swift + Rust + Kotlin): `pseudonym_secret = HKDF-SHA256(ed25519_private_seed, salt="scp-pseudonym-secret-v1")`; all software impls produce IDENTICAL pseudonyms (pinned by KAT §25.19).
- Hardware custody (Secure Enclave / TEE): device-local secret, device-local by design.
- The earlier ADR-027 "use public key bytes" amendment was REJECTED. Do not "fix" correct private-seed code toward the public key.

### FIXED (was a HIGH): publicKey() triggered a biometric prompt
- `publicKey(_:)` (`Sources/SCP/Platform/AppleKeyCustody.swift:593`) reads the cached public key out of Keychain metadata attributes at `:602-606` and returns it. It reaches no key material, so it raises no Face ID or Touch ID prompt.
- `storePrivateKeyBytes` (`:406`) takes a non-optional `publicKeyBytes` and writes it into `KeyMetadata.publicKeyBase64` at `:412-415`, so every key this class stores carries the cached public key.
- One residue: an item stored by a build that predates the metadata cache carries no `publicKeyBase64`, and `publicKey` then falls back to `fetchPrivateKeyBytes` at `:610`, which does prompt. The code comments that fallback as such at `:608-609`.
- The class doc at `:209-211` now states what the code does: `publicKey` and `destroyKey` require no biometric authentication.

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
