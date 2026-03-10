# PR #479 Deep Cryptographic Review (2026-03-09)

## Findings Summary

### CRITICAL: WASM event leaf hash incompatible with native
- **Native** (`scp-event-log/src/tree.rs:80-85`): `SHA-256(0x00 || MessagePack(event))` where event includes ALL fields
- **WASM** (`scp-ffi/wasm/src/manager.rs:2315-2324`): `SHA-256(0x00 || event_type_string || context_id || Date.now_bits_le)`
- Completely different construction. Different inputs, different encoding, different field set.
- WASM uses `to_bits().to_le_bytes()` on f64 timestamp -- not even a real timestamp encoding
- Merkle roots from WASM and native are INCOMPATIBLE. Cross-platform proof verification impossible.

### MEDIUM: ChunkEnvelope message_id lacks domain separator and length prefixes
- **File**: `scp-core/src/envelope/chunk.rs:124-131`
- Construction: `SHA-256(payload || sender_did.as_bytes() || timestamp.to_be_bytes())`
- Missing: domain separator, length prefix on `payload` and `sender_did`
- Risk: concatenation ambiguity. A payload ending with the bytes of a DID string is indistinguishable from a different payload/DID combination.
- Not a collision attack in practice (SHA-256 domain), but violates the protocol's own canonical hash standard (§9.5.1)

### MEDIUM: WASM UCAN nonce validation weaker than native
- **Native** (`scp-core/src/crypto/ucan/nonce.rs:201-227`): validates format ({millis}-{32hex}), freshness (+/-5min), uniqueness
- **WASM** (`scp-ffi/wasm/src/ucan.rs:415-418` + `manager.rs:1365-1380`): validates non-empty and uniqueness only
- Missing: format validation and freshness check
- Risk: WASM accepts nonces that native would reject, creating interop inconsistency. An attacker could mint UCAN tokens with predictable nonces in WASM that would be rejected by native validators.

### MEDIUM: Inconsistent Ed25519 verification strictness
- **Strict** (verify_strict, rejects small-order points):
  - Inner envelope (`envelope/inner.rs:335`)
  - UCAN validation (`crypto/ucan/validate.rs:794`)
  - WASM UCAN validation (`wasm/src/ucan.rs:263`)
  - Sender key protocol (local `key_protocol.rs:1394`)
  - Bridge registration (`scp-transport/src/relay/bridge.rs`)
- **Non-strict** (cofactored, accepts small-order points):
  - Trust attestation (`trust/attestation.rs:415`)
  - Event log signature (`scp-event-log/src/tree.rs:299`)
  - Shadow claiming (`bridge/claiming.rs:243,259`)
  - Trust challenge (`trust/challenge.rs:663,683`)
  - Identity link attestation (`identity/attestation.rs:419`)
  - Content access key requests (`crypto/access_keys/wire.rs:223`)
- Risk: small-order point attacks are theoretical for Ed25519, but the inconsistency is a defense-in-depth gap. All signature verification should use strict unless there's a specific reason not to.

### LOW: Migration proof docstring stale
- `scp-identity/src/dht.rs:1184`: comment says `old_did || new_did || rotated_at` without mentioning length prefixes
- Actual code (lines 1194-1204) correctly uses 4-byte BE length prefixes
- Documentation-only issue, implementation is correct

## Constructions Verified SOUND

### Canonical hash framework (`crypto/canonical.rs`)
- Domain separator as raw UTF-8, no length prefix (correct -- domain separator IS the prefix)
- VarBytes: BE32 length prefix + raw bytes
- Fixed32/Fixed64: raw bytes, no prefix (fixed-size, unambiguous)
- U64/U32/U16/U8: big-endian encoding
- Absent sentinel: SHA-256(0x00) (32 bytes, distinguishable from all other field types)
- Excellent test coverage including concatenation ambiguity tests

### Inner envelope (`envelope/inner.rs`)
- Domain separator: SCP-INNER-ENVELOPE-V1:
- Includes version (U16), message_type discriminator byte (U8)
- All variable-length fields length-prefixed
- payload_hash computed BEFORE padding, signature covers pre-padded hash
- verify_inner_signature uses verify_strict
- provenance_hash: SHA-256(MessagePack(provenance)) or SHA-256(0x00) sentinel

### Checkpoint hash (native, `scp-event-log/src/checkpoint.rs:1116-1148`)
- Domain separator: SCP-CHECKPOINT-V1:
- Length-prefixed context_id and sender_did
- epoch_flag byte (0x01/0x00) with conditional epoch encoding
- WASM checkpoint hash (`scp-ffi/wasm/src/event_log.rs:355-368`) NOW MATCHES native (fixed from earlier finding)

### Sender key encrypt/decrypt (`crypto/sender_keys/encrypt.rs`)
- AES-256-GCM with OsRng 12-byte nonces
- AAD: length-prefixed context_id + sender_did + epoch BE + sequence BE
- Wire format: nonce || ciphertext || tag (standard)
- Tests for wrong context, wrong DID, wrong epoch, wrong sequence

### HPKE sender key distribution (`crypto/sender_keys/key_protocol.rs`)
- X25519 ephemeral DH + HKDF-SHA256 -> AES-128-GCM
- Info: "scp-sender-key-v1" || BE32(len(ctx)) || ctx || BE32(len(did)) || did || epoch_BE
- AAD: BE32(len(ctx)) || ctx || BE32(len(did)) || did || epoch_BE
- HKDF salt: None (acceptable with high-entropy IKM from X25519)
- Ephemeral secret via OsRng, Zeroizing wrapper on derived key

### AES-256-KW key wrapping (`crypto/access_keys/wrapping.rs`)
- RFC 3394 implementation with standard IV (0xA6^8)
- 6 rounds, n=4 semiblocks for 256-bit keys
- Unwrap verifies IV integrity check

### Content access layer (`crypto/access_keys/wrapping.rs`)
- Fresh CEK per message via OsRng
- AES-256-GCM with length-prefixed AAD
- CEK wrapped per-recipient via AES-256-KW
- wrapped_ceks sorted by member_id for deterministic serialization

### Pseudonymize DID (`provenance/attach.rs:229-241`)
- Domain separator: SCP-PSEUDONYM-V1:
- All three fields (pseudonym_key, context_id, did) length-prefixed
- Deterministic for same (key, context, DID) triple

### UCAN revocation CID consistency
- Native (`crypto/ucan/revoke.rs:608`): SHA-256(encoded_token_bytes) -> hex
- WASM (`wasm/src/ucan.rs:206`): identical algorithm
- UniFFI (`uniffi/src/bridge.rs:3673`): now correctly uses compute_revocation_cid (FIXED from PR #127)
- PyO3 and NAPI: correct

### Key material zeroization
- SenderKey: Zeroize + ZeroizeOnDrop
- AccessKey: Zeroize + ZeroizeOnDrop
- ContentEncryptionKey: Zeroize + ZeroizeOnDrop, redacted Debug
- HKDF-derived AES key: Zeroizing<[u8; 16]>
- X25519 EphemeralSecret: consumed by DH (no lingering copy)

### Randomness audit
- All production code uses OsRng (CSPRNG)
- FFI types.rs uses thread_rng() (ChaCha12 reseeded from OsRng) for context IDs and handles -- acceptable
- WASM uses OsRng via getrandom/js -> crypto.getRandomValues
- No weak RNG usage found anywhere in production paths
