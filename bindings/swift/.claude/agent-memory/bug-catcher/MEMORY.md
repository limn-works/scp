# Bug Catcher Memory — Swift SDK

## AppleKeyCustody Review (2026-03-08)

### RESOLVED: derivePseudonym HMAC key is the private-derived pseudonym_secret
- UniFFI/WASM trait docs specify the HMAC key is the private-derived `pseudonym_secret` (HKDF-SHA256 over the Ed25519 private seed for software custody; device-local secret for hardware), NEVER the public key — public-key-keyed derivation is a rejected enumeration oracle (§9.10.4.A). Do not "fix" correct private-seed code toward the public key.
- The earlier "ADR-027 amendment requires public key bytes" claim is REJECTED — public keys are publicly derivable, so a public-key-keyed pseudonym is a membership-enumeration oracle.
- Golden vector tests must assert the private-seed-HKDF derivation, not a public-key-based HMAC.

### FIXED (was a HIGH): publicKey() triggered a biometric prompt
- `publicKey(_:)` (`Sources/SCP/Platform/AppleKeyCustody.swift:593`) reads the cached public key out of Keychain metadata attributes at `:602-606` and returns it. It reaches no key material, so it raises no Face ID or Touch ID prompt.
- `storePrivateKeyBytes` (`:406`) takes a non-optional `publicKeyBytes` and writes it into `KeyMetadata.publicKeyBase64` at `:412-415`, so every key this class stores carries the cached public key.
- One residue: an item stored by a build that predates the metadata cache carries no `publicKeyBase64`, and `publicKey` then falls back to `fetchPrivateKeyBytes` at `:610`, which does prompt. The code comments that fallback as such at `:608-609`.
- The class doc at `:209-211` now states what the code does: `publicKey` and `destroyKey` require no biometric authentication.

### Keychain patterns
- `kSecAttrAccessControl` and `kSecAttrAccessible` are mutually exclusive in SecItemAdd
- `SecItemDelete` does NOT require biometric auth (metadata-level operation)
- `kSecReturnAttributes = true` does NOT trigger biometric auth
- `kSecReturnData = true` DOES trigger biometric auth for SecAccessControl-protected items
- `errSecInteractionNotAllowed` returned when biometric item accessed in background
