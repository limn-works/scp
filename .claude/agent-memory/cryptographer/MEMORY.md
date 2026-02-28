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

### Pruning & Proof Compaction (SCP-126)
- CompactProof == PrunedInclusionProof with renamed fields (unnecessary duplication)
- hash_pair() now duplicated in THREE files: tree.rs, proof.rs, pruning.rs -- critical divergence risk
- prune_before_checkpoint does NOT verify checkpoint merkle_root against log state
- prune_before_checkpoint does NOT verify checkpoint signature
- compute_prune_boundary has structural retention logic error: prunes structural events within retention
- TruncatedEventLog always prunes at checkpoint.event_count regardless of compute_prune_boundary result
- ADR-030 invariant 3 (checkpoint events never pruned) NOT enforced
- Size-based pruning (ADR-030 section 2b) NOT implemented
- Test checkpoints use fake signatures (vec![0u8; 64]) -- masks missing verification

### Economy / Dynamic Pricing (SCP-157)
- evaluate_formula: integer-only, Amount(u64) + Coefficient(i64), no f64
- Linear: (coefficient.0 * metric_value) / 1_000_000 via Coefficient::evaluate
- Step: cumulative thresholds, all met thresholds add via saturating_add
- Floor applied before cap -- cap takes precedence in degenerate (cap < floor) case
- Overflow in Coefficient::evaluate returns None, propagated up; verify_cost_sufficiency falls back to Amount(u64::MAX) (fail-closed)
- cast_unsigned() (stabilized Rust 1.87) used for non-negative i64->u64 conversion, guarded by delta >= 0 check
- EIP-1559 relay pricing: stuck price when current_base_price * max_change_per_mille < 1000 (integer truncation to 0 change)
- Step thresholds NOT required to be sorted -- doesn't affect correctness due to saturating_add commutativity

### Adapter Credential Management (SCP-162)
- AdapterCredential stores pre-encrypted credential bytes (caller encrypts before storing)
- Storage key: identity/{did}/adapter_credentials/{adapter_id} per spec 17.3
- No zeroization on encrypted_data Vec<u8> (mitigated by data being encrypted)
- DID key injection risk: DID type has no character validation, used in storage key construction
- configure_adapter overwrites created_at on rotation (loses original creation time)
- validate_adapter checks: non-empty id, safe chars [a-zA-Z0-9_-], >= 1 currency
- 34 tests, all passing; missing proptest for serialization roundtrips
- ProtocolStore<S: Storage> wraps platform Storage trait for domain methods

### scp-ffi Bridge Layer (reviewed 2026-02-28)
- compute_simple_cid: SHA-256 + "bafyrei" prefix is NOT a valid CID v1 -- purely opaque internal ID
- UcanHeader::validate() skips typ field check (alg + ucv only)
- Context ID: as_nanos() only, no randomness -- collision/predictability risk
- rand 0.8 thread_rng() is CSPRNG (ChaCha12 reseeded from OsRng)
- Nonce format: {millis}-{16 random hex bytes} matches UcanPayload.nnc spec
- Base64 URL_SAFE_NO_PAD correct for JWT
- MCP handles: 128-bit CSPRNG randomness, sufficient
- encode_hex: infallible for String, no truncation bugs
- extract_implementation_hash: correct 64-char hex validation, byte-by-byte decode

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
- `crates/scp-core/src/economy/credentials.rs` -- adapter credential management
- `crates/scp-core/src/store/mod.rs` -- ProtocolStore definition
- `crates/scp-core/src/store/economy.rs` -- adapter credential storage impl
