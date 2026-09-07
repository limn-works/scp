---
name: platform-adapters-and-pseudonyms
description: Apple/Android/WASM key-custody adapter reviews, randomness sources, and the cross-platform pseudonym-derivation incompatibility matrix (SCP-214)
metadata:
  type: project
---

# Randomness

- Production: `OsRng` (CSPRNG) via the `KeyCustody` trait.
- Tests: `thread_rng()` — acceptable for test-only code (rand 0.8 `thread_rng` is
  ChaCha12 reseeded from `OsRng`, so still a CSPRNG).

# Cross-platform pseudonym compatibility matrix (must be unified per SCP-214)

All three produce DIFFERENT pseudonyms for the same identity + context:

| Platform | HMAC key material | Keygen from HMAC output |
|---|---|---|
| Rust (`ed25519_dalek`) — REFERENCE | private seed bytes | `SigningKey::from_bytes(hmac)` (seed → SHA-512 → clamp) |
| Kotlin / Bouncy Castle | **PUBLIC key (WRONG)** | `FixedSecureRandom(hmac)` → `Ed25519KeyPairGenerator` |
| Swift / CryptoKit | private key bytes (correct) | `PrivateKey(rawRepresentation:)` — treats input as a **clamped scalar, not a seed** |

- Bouncy Castle Ed25519 seed handling matches `ed25519_dalek` (seed → SHA-512 → clamp) = COMPATIBLE.
- CryptoKit `rawRepresentation:` is INCOMPATIBLE with both BC and dalek.
- Using the PUBLIC key as HMAC key material destroys unlinkability — anyone can
  compute the pseudonyms.

# Apple platform adapter (PR #86 review)

- `AppleKeyCustody`: Ed25519/X25519 via CryptoKit, Keychain software-backed.
- `AppleDeviceAttestation`: `clientDataHash = SHA-256(challenge ‖ deviceId)` — no
  length prefix, ambiguous.
- `AppleDeviceAttestation`: TOCTOU in `resolveKeyId()` — concurrent calls can double-generate.
- `AppleStorage`: 32-byte key via `SecRandomCopyBytes`, Keychain-protected, in-memory
  dict placeholder; `encryptionKey` as `Data` (no zeroization on dealloc).
- No zeroization anywhere in the Swift layer (`Data` is not zeroed on dealloc).

# Android platform adapter (PR #118 review)

- `AndroidKeyCustody`: Ed25519 via Android Keystore TEE (API 33+), Bouncy Castle
  software fallback (API 26–32). X25519 is always software (Keystore has no X25519).
- **CRITICAL**: `derivePseudonym` uses the PUBLIC key as HMAC key material (line 285-288).
- `dhAgree` missing key-type validation — accepts Ed25519 keys without error.
- No private-key zeroing on `destroySoftwareKey` (only map-entry removal).
- `FixedSecureRandom(seed)` for deterministic keygen works but is fragile; prefer
  `Ed25519PrivateKeyParameters(seed, 0)`.
- AES-GCM storage key: TEE-backed, fixed zero IV, single plaintext — SOUND.
- SQLCipher passphrase: `ByteArray` zeroed (line 89); `String` copy immutable
  (documented, acceptable). `SecureRandom()` used for keygen — correct CSPRNG.

# WASM / NAPI

- WASM custody: pure FFI boundary, delegates all crypto to JS WebCrypto.
- NAPI identity: `InMemoryKeyCustody` with an `OpaqueInMemoryKeyCustody` redacted
  `Debug` wrapper.
