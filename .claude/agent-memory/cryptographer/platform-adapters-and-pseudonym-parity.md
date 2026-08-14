---
name: platform-adapters-and-pseudonym-parity
description: Apple (PR #86) and Android (PR #118) key-custody adapter audits, the three-way cross-platform pseudonym incompatibility matrix (SCP-214), and randomness-source policy
metadata:
  type: project
---

# Randomness policy

- Production: `OsRng` (CSPRNG) via the `KeyCustody` trait
- Tests: `thread_rng()` — acceptable for test-only code (rand 0.8 `thread_rng` is ChaCha12 reseeded from OsRng, so it IS a CSPRNG)

# Cross-platform pseudonym compatibility matrix (SCP-214) — THE headline finding

- **Rust (ed25519_dalek)**: HMAC key = private seed bytes; keygen = `SigningKey::from_bytes(hmac_output)` — REFERENCE
- **Kotlin/BouncyCastle**: HMAC key = **PUBLIC key (WRONG)**; keygen = `FixedSecureRandom(hmac)` → `Ed25519KeyPairGenerator` — INCOMPATIBLE
- **Swift/CryptoKit**: HMAC key = private key bytes (correct); keygen = `PrivateKey(rawRepresentation:)` — INCOMPATIBLE (treats input as a clamped scalar, not a seed)
- All three produce DIFFERENT pseudonyms for the same identity+context. Must be unified per SCP-214.
- Seed-handling detail: BouncyCastle Ed25519 = same as ed25519_dalek (seed → SHA-512 → clamp) = COMPATIBLE with each other; CryptoKit `rawRepresentation` is incompatible with BOTH.

# Apple platform adapter (PR #86)

- `AppleKeyCustody`: Ed25519/X25519 via CryptoKit, Keychain software-backed
- CRITICAL: `Curve25519.Signing.PrivateKey(rawRepresentation:)` uses an RFC 8032 clamped scalar while `ed25519_dalek::SigningKey::from_bytes()` treats input as a seed (SHA-512 then clamp) — HMAC-derived pseudonym seeds produce DIFFERENT public keys across platforms
- `AppleDeviceAttestation`: `clientDataHash = SHA-256(challenge || deviceId)`, no length prefix — ambiguous concatenation
- `AppleDeviceAttestation`: TOCTOU in `resolveKeyId()` — concurrent calls can double-generate
- `AppleStorage`: 32-byte key via `SecRandomCopyBytes`, Keychain-protected, in-memory dict placeholder
- `AppleStorage`: `encryptionKey` as `Data` (no zeroization on dealloc). No zeroization anywhere in the Swift layer.
- WASM custody: pure FFI boundary, delegates all crypto to JS WebCrypto
- NAPI identity: `InMemoryKeyCustody` with `OpaqueInMemoryKeyCustody` redacted Debug wrapper

# Android platform adapter (PR #118)

- `AndroidKeyCustody`: Ed25519 via Android Keystore TEE (API 33+), BouncyCastle software fallback (API 26-32). X25519 always software via BC (Keystore has no X25519).
- CRITICAL: `derivePseudonym` uses the PUBLIC key as HMAC key material (line 285-288). Rust/Swift use PRIVATE key bytes. A public HMAC key destroys unlinkability — anyone can compute the pseudonyms.
- `dhAgree` missing key-type validation — accepts Ed25519 keys without error
- No private-key zeroing on `destroySoftwareKey` (only map-entry removal)
- `FixedSecureRandom(seed)` for deterministic keygen works but is fragile; prefer `Ed25519PrivateKeyParameters(seed, 0)`
- AES-GCM storage key: TEE-backed, fixed zero IV, single plaintext — SOUND
- SQLCipher passphrase: `ByteArray` zeroed (line 89), String copy immutable (documented, acceptable)
- `SecureRandom()` used for keygen — correct CSPRNG on Android
