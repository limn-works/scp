# Bug Catcher Memory — Swift SDK

## AppleKeyCustody Review (2026-03-08)

### CRITICAL: derivePseudonym uses private key bytes as HMAC key
- Swift `derivePseudonym` at line 731 uses `privateKeyBytes` as HMAC key
- Rust reference (InMemoryKeyCustody line 369) uses `verifying_key()` (public key bytes)
- UniFFI trait doc (line 384) mandates `HMAC-SHA256(public_key_bytes, ...)`
- ADR-027 amendment requires public key bytes for cross-platform determinism
- Golden vector test (line 291) can't compile: calls `private` method via `@testable`

### HIGH: publicKey() triggers biometric prompt
- publicKey calls `fetchPrivateKeyBytes` which does `kSecReturnData = true`
- For biometric-gated items, this WILL trigger Face ID/Touch ID
- Class doc (line 200) falsely claims publicKey does NOT require biometric auth
- Fix: store public key bytes separately in Keychain, or cache at generation time

### Keychain patterns
- `kSecAttrAccessControl` and `kSecAttrAccessible` are mutually exclusive in SecItemAdd
- `SecItemDelete` does NOT require biometric auth (metadata-level operation)
- `kSecReturnAttributes = true` does NOT trigger biometric auth
- `kSecReturnData = true` DOES trigger biometric auth for SecAccessControl-protected items
- `errSecInteractionNotAllowed` returned when biometric item accessed in background
