# Crypto Agent Memory

## Project: SCP Protocol Core

### Merkle Tree (event_log/)
- RFC 6962 domain separation: leaf=SHA-256(0x00||data), interior=SHA-256(0x01||left||right)
- Consistent across tree.rs, proof.rs, checkpoint.rs, metrics.rs, phase2_integration.rs
- Odd-leaf promotion: hash-with-self (not carry-unchanged)
- hash_pair() duplicated in tree.rs and proof.rs -- divergence risk
- compute_event_canonical_hash() + event_type_tag() duplicated in 5 files

### Canonical Hash Weaknesses (open findings)
- No domain separators across hash functions (event, claim, attestation, checkpoint)
- No length prefixes on variable-length fields in concatenated hashes
- Attestation type uses Debug formatting (not stable for canonicalization)
- serde_json::Value::to_string() not canonical across languages/versions
- CRITICAL: claiming.rs:267 uses to_be_bytes + SHA-256 prehash; trust/attestation.rs:431 uses to_le_bytes + raw bytes -- INCOMPATIBLE attestation verification
- See PR #76 review for full details

### Signature Verification
- claim_shadow() verifies attestation sig then claim sig before state transition
- Ed25519 via ed25519_dalek, signatures over SHA-256 canonical hashes (claiming.rs)
- Ed25519 via ed25519_dalek, signatures over raw canonical bytes (trust/attestation.rs)
- TWO different canonical forms exist for attestations -- must consolidate
- DID formats: did:dht:z<z-base-32> (prod), did:key:<hex> (test, non-standard)
- did:key format in claiming.rs does NOT conform to W3C did:key spec (missing multicodec/multibase)

### Deterministic Serialization
- nesting.rs: BTreeSet for requires_approval_for ensures sorted serde_json
- content_hash() returns Result for proper error propagation

### Randomness
- Production: OsRng (CSPRNG) via KeyCustody trait
- Tests: thread_rng() -- acceptable for test-only code

### Apple Platform Adapter (PR #86 review)
- AppleKeyCustody: Ed25519/X25519 via CryptoKit, Keychain software-backed
- CRITICAL: CryptoKit Curve25519.Signing.PrivateKey(rawRepresentation:) uses RFC 8032 clamped scalar
  ed25519_dalek SigningKey::from_bytes() treats input as seed (SHA-512 then clamp)
  HMAC-derived pseudonym seeds will produce DIFFERENT public keys across platforms
- AppleDeviceAttestation: clientDataHash = SHA-256(challenge||deviceId), no length prefix -- ambiguous
- AppleDeviceAttestation: TOCTOU in resolveKeyId() -- concurrent calls can double-generate
- AppleStorage: 32-byte key via SecRandomCopyBytes, Keychain-protected, in-memory dict placeholder
- AppleStorage: encryptionKey as Data (no zeroization on dealloc)
- No zeroization anywhere in Swift layer (Data is not zeroed on dealloc)
- WASM custody: pure FFI boundary, delegates all crypto to JS WebCrypto
- NAPI identity: InMemoryKeyCustody with OpaqueInMemoryKeyCustody redacted Debug wrapper

### Key Files
- `crates/scp-core/src/event_log/tree.rs` -- Merkle tree, leaf/interior hashing
- `crates/scp-core/src/event_log/proof.rs` -- inclusion/absence proofs
- `crates/scp-core/src/event_log/checkpoint.rs` -- consistency checkpoints
- `crates/scp-core/src/bridge/claiming.rs` -- shadow claiming, dual sig verification
- `crates/scp-core/src/context/nesting.rs` -- governance config hashing, BTreeSet
- `crates/scp-core/src/crypto/sender_keys/` -- sender key protocol, HKDF, X25519
- `bindings/swift/Sources/SCP/Platform/` -- Apple platform adapters
- `crates/scp-ffi/wasm/src/custody.rs` -- WASM key custody FFI boundary
- `crates/scp-ffi/napi/src/identity.rs` -- Node/Bun identity bridge
