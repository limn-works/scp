# Pseudonym Derivation — HMAC Key Material (Software vs Hardware Custody)

**Decision**: The per-context pseudonym keypair is derived as

```
seed = HMAC-SHA256(pseudonym_secret, context_id || "scp-pseudonym")          // v1 (static)
seed = HMAC-SHA256(pseudonym_secret, context_id || BE64(epoch) || "scp-pseudonym-v2")  // v2 (rotatable)
pseudonym_keypair = Ed25519_keygen(seed[0..32])   // seed is an RFC-8032 Ed25519 seed, not a clamped scalar
```

The HMAC key is the 32-byte `pseudonym_secret`, **never the public key**. How the
`pseudonym_secret` is obtained differs by custody type:

- **Software custody** (Rust `InMemory`/`File`/`SQLite`, Android Bouncy Castle API 26-32,
  Apple software Keychain, WASM/JS WebCrypto):
  `pseudonym_secret = HKDF-SHA256(ikm = ed25519_private_seed, salt = "scp-pseudonym-secret-v1", info = "", len = 32)`.
  This is byte-identical across every platform, so software pseudonyms are **cross-platform
  deterministic**. The canonical implementation is `derive_pseudonym_secret()` /
  `derive_pseudonym_keypair()` in `crates/scp-crypto/src/pseudonym.rs`. Known-answer
  vectors are pinned in `.docs/specs/25-test-vectors.md` §25.19.

- **Hardware custody** (Android Keystore TEE API 33+, Apple Secure Enclave, HSM):
  the private key bytes are **non-exportable** — they never leave the secure boundary. The
  `pseudonym_secret` is therefore a **device-local** value computed inside the boundary.
  Android uses `SHA-256(TEE_sign("scp-pseudonym-secret-v1"))` (Ed25519 signing is deterministic
  per RFC 8032, so this is reproducible on that device). Hardware pseudonyms are
  **device-local by design** and are intentionally NOT identical across devices or to the
  software vectors.

## Why NOT the public key

An earlier proposal used the raw Ed25519 **public key** bytes as the HMAC key, motivated by
the fact that the public key is the only key material accessible for a TEE-backed key, which
would have made all custody types produce identical pseudonyms.

**This was rejected.** The public key is public by definition. If it were the HMAC key, any
party who knows a member's public key and a `context_id` could compute
`HMAC-SHA256(public_key_bytes, context_id || "scp-pseudonym")` and probe relays to detect
whether that pseudonym is an active subscription — a **membership-enumeration oracle**
(spec §9.10.4.A). Using a secret known only to the key holder is what makes the pseudonym
unguessable, which is the entire point of pseudonymous routing.

## Why hardware being device-local is fine

Cross-device pseudonym identity is **not** a protocol requirement. Hardware keys are
non-exportable precisely so the private material cannot be copied — that is the security
property hardware custody exists to provide. A participant moving to a new device uses the
social/device recovery protocol (spec §3.3), which provisions a fresh identity (and thus a
fresh device-local `pseudonym_secret`) at the destination. "The key is the key" — we do not
need deterministic pseudonym generation across devices for hardware-bound keys.

## Where this lives

- Canonical recipe + KAT: `crates/scp-crypto/src/pseudonym.rs`
  (`derive_pseudonym_secret`, `derive_pseudonym_keypair`).
- Software backends: `file.rs`, `sqlite/key_custody.rs`, `testing/key_custody.rs`.
- Android adapter: `bindings/kotlin/scp-kt-android/.../AndroidKeyCustody.kt`
  (`derivePseudonym`, `derivePseudonymSecret`).
- Spec: §9.10.4, §9.10.4.A, §9.10.4.1; vectors in §25.19.
- ADRs: ADR-006 acceptance criterion 6 (phase-1), ADR-027 (phase-6).
