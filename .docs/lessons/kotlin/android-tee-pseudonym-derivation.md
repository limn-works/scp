# Android TEE Pseudonym Derivation — HMAC Key Material

**Problem**: `derivePseudonym` in `AndroidKeyCustody` uses the public key bytes as the HMAC key
material for hardware-backed Ed25519 keys. This is not because it is correct, but because the
Android Keystore TEE does not allow private key bytes to be exported — they are inaccessible
outside the secure enclave. ADR-006 says `HMAC-SHA256(identity_key_material, ...)` but does not
define what "key material" means when the private key is in a TEE.

**Impact**: If the Apple adapter uses private key bytes as the HMAC key, the Android 13+ adapter
will derive a *different pseudonym* for the same identity in the same context. Cross-platform test
vectors will fail. A user who upgrades from API 26-32 (software key, can use private bytes) to
API 33+ (hardware key, must use public key) will have their pseudonym silently change in every
context they participate in.

**Resolution**: The spec must be amended before any cross-platform test vectors are written.
Options:
1. All adapters use the **public key** as the HMAC key (32 bytes, always accessible). This is the
   only option that works uniformly across TEE and software keys.
2. All adapters use the **private key** as the HMAC key, and Android software fallback (API 26-32)
   does too. This breaks on API 33+ hardware-backed keys.

Option 1 is correct. Update ADR-006 acceptance criterion 6 and the cross-platform test vectors to
read: `seed = HMAC-SHA256(public_key_bytes, contextId || "scp-pseudonym")`.

**Where to fix**: ADR-006 acceptance criterion 6, ADR-027 §Rationale, and the same comment in
`AndroidKeyCustody.kt` at `derivePseudonym`.
