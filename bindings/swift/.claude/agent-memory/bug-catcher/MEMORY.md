# Bug Catcher Memory — Swift SDK

## AppleKeyCustody Review (2026-03-08)

### RESOLVED: derivePseudonym HMAC key is the private-derived pseudonym_secret
- UniFFI/WASM trait docs specify the HMAC key is the private-derived `pseudonym_secret` (HKDF-SHA256 over the Ed25519 private seed for software custody; device-local secret for hardware), NEVER the public key — public-key-keyed derivation is a rejected enumeration oracle (§9.10.4.A). Do not "fix" correct private-seed code toward the public key.
- The earlier "ADR-027 amendment requires public key bytes" claim is REJECTED — public keys are publicly derivable, so a public-key-keyed pseudonym is a membership-enumeration oracle.
- Golden vector tests must assert the private-seed-HKDF derivation, not a public-key-based HMAC.

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
