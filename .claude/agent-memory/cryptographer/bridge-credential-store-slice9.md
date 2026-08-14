---
name: bridge-credential-store-slice9
description: SCP-CAPINJECT-009 ADR-062 Slice 9 durable bridge credential store crypto audit — SOUND with one LOW AAD-binding finding
metadata:
  type: project
---

# Bridge Credential Store (SCP-CAPINJECT-009, ADR-062 Slice 9)

Branch feat/adr062-slice9-credentials @619c50604. Files:
scp-runtime/src/bridge/credentials.rs, scp-runtime/src/store/credentials.rs (new),
scp-ffi/common/src/credentials.rs (new).

**Verdict: SOUND, no blocking crypto findings.**

- KDF: HKDF-SHA256. salt=SHA-256("SCP-BRIDGE-CREDENTIAL-V1") (domain sep),
  info="scp-bridge-credential:"||bridge_id (context bind), ikm=per-bridge 32B OsRng key.
  bridge/credentials.rs:399. Single trailing var field so no length-prefix ambiguity. Correct RFC5869.
- AEAD: AES-256-GCM, 12B OsRng nonce per call, [nonce||ct+tag] format. encrypt_credential:437.
  Random 96-bit nonce, admin-path low volume → no reuse risk.
- **LOW finding (defense-in-depth): NO AAD.** encrypt at :451 / decrypt at :491 pass empty AAD.
  Key binds bridge_id (via HKDF info) but NOT credential_type → within one bridge all types
  share one AES key with no ciphertext↔slot binding. An attacker past SQLCipher (DB write) could
  swap OAuthAccessToken ciphertext into ApiKey slot (type confusion) or roll back a rotated cred.
  Cross-BRIDGE swap IS caught (different derived key). Recommend AAD = credential_type (+created_at
  for anti-rollback). Free to add now (new feature, no deployed ciphertext).
- Namespacing: bridge_id→sanitize_key_component (rejects / \ .. \0, store_value.rs:143);
  credential_type→hex(SHA-256(Display)) fixed 64-char, no separator. Custom(arbitrary) can't inject.
  Display injective within Custom + disjoint from builtins → no key collision. SOUND.
- Root key: store_bridge_credential_root_key wraps Vec copy in Zeroizing + store_value_zeroize
  (zeroes serialized envelope after write, store/mod.rs:262). load wraps in Zeroizing<[u8;32]>.
  At-rest via S:EncryptedStorage bound (prod new(); new_for_testing feature-gated). Double-encrypt
  (per-cred AEAD w/ independent key + SQLCipher) not redundant-weakening. SOUND.
- Revoke = crypto-shred: deletes records FIRST then root key (bridge/credentials.rs:1045). Honest
  doc: decryption key is CALLER-supplied not stored root copy, so record deletion (not root-key
  deletion) is what gates retrieve→NotFound. Residual freelist ciphertext encrypted at rest under
  independent DB key. SOUND for KV/SQLCipher. Documented non-atomicity: provision/rotate racing
  revoke can re-materialize (no CAS) — "callers MUST quiesce", acceptable durability-only. Not blocking.
- Restart test bridge_credential_survives_store_drop_and_reopen (store/credentials.rs): real on-disk
  Sqlite, drops store+Arc, reopens same path/key, decrypts end-to-end. Cannot pass without real crypto
  (GCM tag). Proves durable round-trip. SOUND.
- Wrong-key test durable_wrong_key_fails_to_decrypt:1289 + decrypt_with_wrong_key_fails — GCM tag
  rejects wrong key → CryptoError not garbage. SOUND.
- Non-crypto observation: expires_at field always hardcoded None on both provision paths (no expiry
  param); retrieve never checks expiry. Completeness/spec gap, not crypto.
