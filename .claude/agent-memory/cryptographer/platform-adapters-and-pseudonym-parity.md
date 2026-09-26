---
name: platform-adapters-and-pseudonym-parity
description: Apple and Android key-custody adapter findings, and the three-way cross-platform pseudonym incompatibility matrix (SCP-214)
metadata:
  type: project
---

# Cross-platform pseudonym compatibility matrix

All three implementations produce DIFFERENT pseudonyms for one identity plus one
context. SCP-214 must unify them.

- **Rust (ed25519_dalek) — REFERENCE:** HMAC key = private seed bytes;
  keygen = `SigningKey::from_bytes(hmac_output)`.
- **Kotlin / Bouncy Castle — INCOMPATIBLE:** HMAC key = PUBLIC key (wrong);
  keygen = `FixedSecureRandom(hmac)` → `Ed25519KeyPairGenerator`.
- **Swift / CryptoKit — INCOMPATIBLE:** HMAC key = private key bytes (correct);
  keygen = `PrivateKey(rawRepresentation:)`, which treats input as a clamped
  scalar rather than a seed.

Bouncy Castle Ed25519 seed handling matches ed25519_dalek (seed → SHA-512 →
clamp), so those two are COMPATIBLE on keygen. CryptoKit's `rawRepresentation` is
incompatible with both.

# Apple platform adapter (PR #86 review)

- `AppleKeyCustody`: Ed25519/X25519 via CryptoKit, Keychain software-backed.
- CRITICAL: `Curve25519.Signing.PrivateKey(rawRepresentation:)` takes an RFC 8032
  clamped scalar, whereas `ed25519_dalek::SigningKey::from_bytes()` takes a seed
  (SHA-512 then clamp), so HMAC-derived pseudonym seeds yield different public
  keys across platforms.
- `AppleDeviceAttestation`: `clientDataHash = SHA-256(challenge||deviceId)` with
  no length prefix — ambiguous concatenation.
- `AppleDeviceAttestation`: TOCTOU in `resolveKeyId()` — concurrent calls can
  double-generate.
- `AppleStorage`: 32-byte key via `SecRandomCopyBytes`, Keychain-protected,
  in-memory dict placeholder; `encryptionKey` held as `Data` with no zeroization
  on dealloc.
- No zeroization anywhere in the Swift layer, because `Data` is not zeroed on
  dealloc.
- WASM custody is a pure FFI boundary that delegates all crypto to JS WebCrypto.
- NAPI identity uses `InMemoryKeyCustody` with an `OpaqueInMemoryKeyCustody`
  redacted Debug wrapper.

# Android platform adapter (PR #118 review)

- `AndroidKeyCustody`: Ed25519 via Android Keystore TEE (API 33+), Bouncy Castle
  software fallback (API 26–32). X25519 is always software via Bouncy Castle,
  because Keystore has no X25519.
- CRITICAL: `derivePseudonym` uses the PUBLIC key as HMAC key material
  (line 285–288). Rust and Swift use private key bytes. A public HMAC key also
  destroys unlinkability, because anyone can compute those pseudonyms.
- `dhAgree` performs no key-type validation and accepts Ed25519 keys silently.
- `destroySoftwareKey` removes a map entry without zeroing private key bytes.
- `FixedSecureRandom(seed)` for deterministic keygen works but is fragile;
  prefer `Ed25519PrivateKeyParameters(seed, 0)`.
- AES-GCM storage key: TEE-backed, fixed zero IV, single plaintext — SOUND.
- SQLCipher passphrase: `ByteArray` zeroed (line 89); the `String` copy is
  immutable and documented, which is acceptable.
- `SecureRandom()` used for keygen — correct CSPRNG on Android.
