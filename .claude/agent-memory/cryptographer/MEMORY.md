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

### Android Platform Adapter (PR #118 review)
- AndroidKeyCustody: Ed25519 via Android Keystore TEE (API 33+), Bouncy Castle software fallback (API 26-32)
- X25519 always software via Bouncy Castle (Keystore has no X25519)
- CRITICAL: derivePseudonym uses PUBLIC key as HMAC key material (line 285-288)
  Rust/Swift use PRIVATE key bytes -- pseudonyms will differ cross-platform
  Public key as HMAC key destroys unlinkability (anyone can compute pseudonyms)
- dhAgree missing key type validation -- accepts Ed25519 keys without error
- No private key zeroing on destroySoftwareKey (only map entry removal)
- FixedSecureRandom(seed) for deterministic keygen works but fragile; prefer Ed25519PrivateKeyParameters(seed,0)
- Bouncy Castle Ed25519 seed handling: same as ed25519_dalek (seed -> SHA-512 -> clamp) = COMPATIBLE
- CryptoKit rawRepresentation: treats input as clamped scalar, NOT seed = INCOMPATIBLE with both BC and dalek
- AES-GCM storage key: TEE-backed, fixed zero IV, single plaintext -- SOUND
- SQLCipher passphrase: ByteArray zeroed (line 89), String copy immutable (documented, acceptable)
- SecureRandom() used for keygen -- correct CSPRNG on Android

### Cross-Platform Pseudonym Compatibility Matrix
- Rust (ed25519_dalek): HMAC key = private seed bytes, keygen = SigningKey::from_bytes(hmac_output) -- REFERENCE
- Kotlin/BC: HMAC key = PUBLIC key (WRONG), keygen = FixedSecureRandom(hmac) -> Ed25519KeyPairGenerator -- INCOMPATIBLE
- Swift/CryptoKit: HMAC key = private key bytes (correct), keygen = PrivateKey(rawRepresentation:) -- INCOMPATIBLE (scalar vs seed)
- All three produce DIFFERENT pseudonyms for same identity+context. Must be unified per SCP-214.

### PR #127 Crypto Audit (2026-03-01)
- CRITICAL: UniFFI ucan_revoke (bridge.rs:2220) revokes by token_id, NOT content-hash CID
  Validation pipeline (validate.rs:467) checks compute_revocation_cid(&payload) = SHA-256(JSON)
  UniFFI inserts raw token_id string -- revocations are no-ops for mobile/desktop
  PyO3, WASM, NAPI bridges all correctly compute CID before revoking
- HIGH: WASM WasmUcanPayload (wasm/ucan.rs:139-151) duplicates UcanPayload (mod.rs:289)
  Field order must match for CID consistency; no compile-time or test enforcement
- Inner envelope: domain separator SCP-INNER-ENVELOPE-V1, length-prefixed var fields, SOUND
- AES-256-GCM: OsRng nonces throughout, Zeroize+ZeroizeOnDrop on all key types, SOUND
- Broadcast key rotation: fresh random keys (not HKDF), epoch overflow checked, SOUND
- Outer envelope pipeline: MLS->SenderKey->deserialize->verify sender->content integrity->sig, SOUND
- UCAN mint: 24h max expiry, clock error propagation, Ed25519 signing via KeyCustody, SOUND
- Nonce tracker: format validation, freshness +/-5min, capacity 100K, pruning, serialization, SOUND
- Attestation renewal: mandatory re-verification before renewed_at update, SOUND
- MessageType::as_discriminator_byte() exists but NOT used in compute_canonical_hash -- docstring misleading

### Bridge Relay Auth + DID Healing (PR #255, SCP-247/SCP-245)
- Bridge auth: "SCP-BRIDGE-REGISTER-V1:" || routing_id[32] || be-u64(timestamp) = 63B fixed, SOUND
- verify_strict() used, verification order: timestamp->sig->routing_id (fast-reject)
- Routing ID: SHA-256("scp:did:" || did_string) -- domain-separated, golden vector verified
- DID derivation: did:dht:z + zbase32(pubkey) -- deterministic, invertible
- 60s replay window, no nonce tracking -- acceptable (idempotent registration)
- DualLayerResolver: tokio::join!, BEP44 verify_strict on both layers, anti-rollback via cached seq
- Healing: async best-effort republish to stale layer, panic-monitored
- PRE-EXISTING: migration proof hash (dht.rs:607) has var-length concat ambiguity (old_did||new_did)

### Spec-Level Crypto Audit (2026-03-05)
- See [spec-audit-findings.md](spec-audit-findings.md) for full findings
- 9 CRITICAL, 11 HIGH, 8 MEDIUM, 5 LOW findings across 09-security-model.md, 03-identity.md, 07-trust-validation-and-capabilities.md
- Root pattern: migration proof (line 350) correctly uses length prefixes + domain sep, but 8+ other hash constructions don't
- BroadcastEnvelope is the ONLY signature without a domain separator
- "Ed25519_keygen(seed)" undefined = cross-platform breakage (confirmed by impl audit)
- Sender key HPKE, nonce gen, wire format, routing_id (encrypted), participation signing key derivation all MISSING
- Canonical serialization for signed structures (attestations, profiles, checkpoints) MISSING entirely

### Key Files
- `crates/scp-core/src/event_log/tree.rs` -- Merkle tree, leaf/interior hashing
- `crates/scp-core/src/event_log/proof.rs` -- inclusion/absence proofs
- `crates/scp-core/src/event_log/checkpoint.rs` -- consistency checkpoints
- `crates/scp-core/src/bridge/claiming.rs` -- shadow claiming, dual sig verification
- `crates/scp-core/src/context/nesting.rs` -- governance config hashing, BTreeSet
- `crates/scp-core/src/crypto/sender_keys/` -- sender key protocol, HKDF, X25519
- `crates/scp-core/src/envelope/inner.rs` -- inner envelope, canonical hash, domain separator
- `crates/scp-core/src/envelope/outer.rs` -- seal/open pipeline, SCP-177 sender key resolution
- `crates/scp-core/src/crypto/ucan/mint.rs` -- UCAN minting, CID computation
- `crates/scp-core/src/crypto/ucan/nonce.rs` -- nonce generation and NonceTracker
- `crates/scp-core/src/crypto/ucan/revoke.rs` -- revocation CID, RevocationList
- `crates/scp-core/src/crypto/ucan/validate.rs` -- 11-step validation pipeline
- `crates/scp-core/src/trust/renewal.rs` -- attestation renewal with re-verification
- `bindings/swift/Sources/SCP/Platform/` -- Apple platform adapters
- `crates/scp-ffi/wasm/src/ucan.rs` -- WASM UCAN bridge (partial validation)
- `crates/scp-ffi/uniffi/src/bridge.rs` -- UniFFI bridge (CID mismatch bug)
- `crates/scp-ffi/napi/src/ucan.rs` -- NAPI UCAN bridge (correct CID handling)
- `crates/scp-ffi/src/ucan.rs` -- PyO3 UCAN bridge (correct CID handling)
- `crates/scp-ffi/wasm/src/custody.rs` -- WASM key custody FFI boundary
- `crates/scp-ffi/napi/src/identity.rs` -- Node/Bun identity bridge
- `crates/scp-core/src/economy/credentials.rs` -- adapter credential management
- `crates/scp-core/src/store/mod.rs` -- ProtocolStore definition
- `crates/scp-core/src/store/economy.rs` -- adapter credential storage impl
- `bindings/kotlin/scp-sdk-kotlin-android/src/main/kotlin/com/limn/scp/android/platform/` -- Android adapters
- `crates/scp-core/src/envelope/pseudonym.rs` -- pseudonym derivation spec (delegates to KeyCustody)
- `crates/scp-platform/src/testing/key_custody.rs` -- InMemoryKeyCustody reference impl + golden vectors
- `crates/scp-transport/src/relay/bridge.rs` -- bridge auth, SCP-BRIDGE-REGISTER-V1 domain separator
- `crates/scp-identity/src/resolver.rs` -- DualLayerResolver, healing publisher, anti-rollback
- `crates/scp-identity/src/resolution.rs` -- did_routing_id(), relay-based resolution
- `crates/scp-identity/src/dht.rs` -- DidDht, BEP44, did_from_ed25519_public_key, migration proofs
