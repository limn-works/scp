# Crypto Agent Memory

## Project: SCP Protocol Core

- [#1900 PR-2b WASM engine-adoption BLOCKER](pr2b-wasm-engine-adoption-blocker.md) — plan's "transient engine + replay stored votes" NOT implementable: PR-2a added keyless ingest_approve/reject only, NO keyless propose/seed; engine `proposals` map private, only signed `propose` (needs key+resolver WASM lacks) creates entries. Unblock = add `TrustedVoteIngest::ingest_proposal(GovernanceProposal)` to shared engine (PR-2a-bis). Items A/B/C/D/H are WASM-only & unblocked; E/F/G blocked.

- [Event-log unification Phase 2](eventlog-unification-phase2.md) — ADR-011 runtime onto RFC 6962 substrate; export-root migration (truncation forgery CLOSED) + §9.9.3 equivocation dedup (per-sender (count,root) set, no durable receiver-minted leaves); round-4 APPROVE
- Signed context-export (export_import.rs) 16a2cd42b APPROVE: removed unsigned envelope ContextExport.merkle_root field + step-6 self-check. SOUND, strictly stronger. Signed preimage = SHA-256(SCP-CONTEXT-EXPORT-V1: || scope.tag_byte() || JCS(snapshot)); snapshot.event_log_merkle_root is INSIDE JCS(snapshot)=signed. Step 5 (recompute RFC6962 root over event_log_data via recompute_event_log_root [renamed from verify_merkle_chain], ct_eq vs signed root) is sole authoritative binding. Step 6 compared attacker-writable envelope copy vs signed copy — both attacker-visible, trivially satisfiable, gated nothing. Coverage: prefix-trunc rejected in append_unsigned_event (seq/prev_hash); suffix/middle/reorder/sub/forge → root mismatch. exporter_did==creator_did + verify_strict unchanged. Empty log: signed [0u8;32] not unsigned sentinel, no all-zeros bypass. Removed field never in hash → no 2nd-preimage/domain-sep regression.
- PseudonymAnnounced removal (f438acf0f) APPROVE: taxonomy 76->75; tag 59 RETIRED as gap (no renumber) so all other event_type_tag stable -> §25 KAT 32/33 root 39e50b87 byte-unchanged (verified). EventType serializes by NAME-string via rmp_serde (no int repr), so removal can't shift other leaves. Convergence RESTORED: receive path deliver_plaintext_or_announcement returns None for ALL 3 arms; Some-append channel DEAD in prod. 3 non-convergent classes (MessageReceived, EquivocationDetected, PseudonymAnnounced) have NO EventType variant -> type-level un-appendable. All prod append sites sender-authored (MessageSent) or commit/governance-driven. GOTCHA: bare `-p scp-event-log` FAILS 116 (hex did:key gated behind scp-primitives `testing` feature, identity.rs:118) — run with --features testing.
- [HPKE RFC 9180 conformance](hpke-rfc9180-conformance.md) — FIXED the custom-ECIES finding: one hand-impl RFC 9180 core in scp-protocol/src/crypto/hpke.rs (A.1 KAT + hpke-rs oracle), custody Decap variant, 60->48 wire, all 5 paths conformed; C5 platform custody verified OK
- [trust-ucan-classification](trust-ucan-classification.md) — TS evaluateTrust UCAN error→CapabilityValidation classification; fail-closed analysis; faithful port of reviewed Python layer
- [adr-051-prerotation-substrate](adr-051-prerotation-substrate.md) — ADR-051 pre-rotation custody substrate isolation (Proposed); separate-provider model sound per spec §9.7.4.1 §3
- [nonce-dedup-saga-removal](nonce-dedup-saga-removal.md) — fix/sdk-coverage-fail-closed-and-parity: NonceDedup configurable-TTL API removed in lockstep w/ cross-context saga deletion; no replay regression; trust.ts unchanged-sound, Python-parity confirmed

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

### ADR-039 Shared-DID Persona Binding (#active/#agent)
- `signing_key_id` (SigningKeyId enum, #active/#agent) IS in the SIGNED canonical preimage of InnerEnvelope — envelope/inner/mod.rs compute_canonical_hash ~L557, final VarBytes (length-prefixed) field. verify recomputes with inner.signing_key_id (~L370). Persona cannot be flipped post-sign without breaking sig. SOUND.
- KeyResolver widened DID-only → `Fn(&DID, SigningKeyId) -> Option<VerifyingKey>`. verify_and_unwrap (messaging_helpers.rs:309) resolves by inner.signing_key_id. verify-before-unwrap correct; payload_hash via ct_eq.
- SigningKeyId::from_fragment strict: only "#active"/"#agent"; rejects "#0","active","". economy_logic resolve_public_key_by_kid fails CLOSED on unknown kid. No-kid resolve_public_key defaults #active (only on no-kid UCAN path).
- Governance votes all pass SigningKeyId::Active; SignedVote has NO kid field so votes are always #active by construction — no wrong-key-accept. Per-VM votes deferred (documented).
- GAP (not a regression): only prod KeyResolver wiring (scp-node/self_host.rs:453) returns None for ALL (DID,kid); FFI bridges hardcode signing_key_id=Active + not_configured_key_resolver→None. #agent end-to-end still non-functional outside in-crate tests despite "wired into live pipeline" claim. Receive path correct GIVEN real document-derived resolver (only in agent_binding_pipeline_tests.rs).

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
- ProtocolRepository<S: Storage> wraps platform Storage trait for domain methods

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

### SCP-1717 Pre-Rotation Custody (2026-05-10 round-10 final review — SOUND, no blocking findings)
- Round-10 (commit 7ce74e7ca): Added 6 typed FFI error codes SCP-IDENT-1047..1052, one per PreRotationCustodyError variant. Diff confined to PyO3/NAPI/UniFFI From<IdentityError>; zero crypto substrate drift (git diff -- scp-identity scp-platform scp-ffi/wasm empty). Byte-equal const-string mapping across 3 bridges. 7 regression tests pin variants + fallback. WASM intentionally unchanged (own registry, IDENT_1002). LOW followups: parity codes in WASM custody paths; rustdoc warning to backend implementers re: not embedding key material in Storage/Unavailable/InvalidCallbackResponse strings.
- Round-8 review history below:
- Round-8 polish landed: Kotlin Identity.migrate deprecation level=ERROR (Identity.kt:299-308); bind_old_document_to_old_did's 5 error paths uniformly map to MigrationVerificationFailed (dht.rs:1919-1948); step-0 mismatch error carries 12-byte hex prefixes for did-derived + document-derived pubkeys (dht.rs:1940-1946)
- CI clippy clean at full feature set (allow_in_memory_custody on all bridges + scp-core/scp-runtime testing)
- Prior HIGH (verify_migration old_public_key→old_did binding via step 1b) addressed → bind_old_document_to_old_did is now an explicit Step 0 backstop closing the documented LOW from earlier rev. Caller contract explicit at dht.rs:2023-2036 (must use resolve_did / verify_and_deserialize / relay_resolve).
- Prior LOW (PreRotationKeyEntry struct-level Zeroize derive) FIXED at testing/pre_rotation_custody.rs:40 + WASM mirror at wasm/identity.rs:441
- rotated_at bounds at dht.rs:1809-1840: MAX_FUTURE_SKEW_SECS=300, MAX_PAST_WINDOW_SECS=5y, MIGRATION_EPOCH_FLOOR_UNIX_SECS=1_700_000_000 (hard floor closes saturating-clamp loophole on broken-clock verifiers)
- check_rotated_at_window boundary walk: rotated_at=floor passes, floor-1 rejected, u64::MAX rejected (when now is real), now=0 → floor still rejects rotated_at<floor
- Step ordering: probe→reveal→build proofs→generate-new-pre-rot→store-new→destroy-old/import-as-#0→build-doc→publish-NEW→publish-OLD-with-aKa
- Step 0 probe (import_ed25519_signing_key + destroy_key) catches Unsupported pre-flight; FileKeyCustody dedup ensures probe doesn't append duplicate file entries (concurrent dedup test exists)
- LOW (FIXED): probe seed now OsRng-derived (dht.rs:1258-1260) — collision probability ~2^-256 with any pre-existing entry. Was [0u8;32] in earlier rev.
- LOW (FIXED 2026-05-03): retire_operational_keys_for_migration (document.rs:890-913) now uses exact-fragment match via rsplit('#').next(). Test at document.rs:2444 injects #secondary-active and verifies retention.
- LOW (FIXED 2026-05-03): from_did Local-record preservation test landed at wasm/identity.rs:5442. Idempotent re-call preserves IdentityRecord::Local + custody_type + agent_signing_key_bytes.
- LOW (open): WASM zbase32 parity test pinned to 3 vectors (wasm/identity.rs:5950) — replace with proptest over 1000+ random 32-byte inputs. OUT OF SCOPE per current review.
- LOW (NEW 2026-05-03): verify_migration doesn't bind old_document to old_did (no internal check that old_document.id == old_did or that #0 VM derives old_did). Caller-supplied document allows STRONG-bypass attack: an attacker with the compromised #0 private key can supply a forged old_document with no PreRotationCommitment service, defeating the STRONG-when-committed enforcement at step 1c. Mitigated when caller uses resolve_did (which calls verify_self_certification). DOCUMENTATION GAP — caller contract not stated in rustdoc. Recommend: add `let expected_id_pk = extract_public_key(old_did)?; let doc_pk = decode_multibase_key(&old_document.verification_method_by_fragment("0")?.public_key_multibase)?; if doc_pk != expected_id_pk { return Err(...); }` inside verify_migration. Severity HIGH if any production caller skips resolution; MEDIUM with the documented contract.
- MEDIUM open: CallbackKeyCustody.import_ed25519_signing_key returns Unsupported (production iOS/Android migrate fails fast at step 0 — no leak, but feature blocker for #1729)
- MEDIUM open: callback substrate isolation incomplete (OsRng in bridge process holds bytes briefly co-resident with operational keys)
- MEDIUM open: step-7 publish_document(new) failure leaves new identity uninstalled with consumed old pre-rotation key — function returns Err with no recovery handle
- All 4 bridges have SHA-256(revealed_key)==commitment cross-bridge invariant test on REAL bridge output (UniFFI: 15384, NAPI: 1518, PyO3: 2150, WASM: 5072)
- Reverse-parity test (WASM tests/native_emitted_rotation_event_json_matches_wasm_encoding): Value-equality + native-deserialize round-trip + byte-canonicalize compare — strong
- WASM `pre_rotation_commitment` recomputed from revealed_key (= old pre-rot pub); verifier later checks against old_doc service entry — equivalent to native flow
- ADR-046 byte parity preserved (seed[0..32]=identity, [32..64]=active, [64..96]=pre-rotation, [96..128]=agent)
- zbase32 canonicality math: 32 bytes → 52 chars + 4 padding bits in last char → 16 alternates; encode-and-compare rejects all
- ed25519_dalek::SigningKey 2.2.0 impls ZeroizeOnDrop — drops at line 1273 wipe internals
- 268 scp-identity tests pass (1 #[ignore]); 96 scp-platform tests pass

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

### Phase 0/1 Production Readiness Review (2026-03-06)
- Sender key protocol: JSON->MessagePack (to_vec_named) SOUND, all 4 serialization points + 25 test sites
- HPKE domain separator: "scp-sender-key-hpke-v1" -> "scp-sender-key-v1" per spec. Prefix matches but full info param still incomplete (see spec-audit)
- PRE-EXISTING HIGH: hpke_seal/hpke_open pass only domain prefix to HKDF info, NOT context_id||sender_did||epoch_bytes per spec 9.16.2. No AAD on AES-GCM. Tracked in spec-audit.
- InnerEnvelope: deny_unknown_fields added, SOUND. Provenance nested struct lacks it (mitigated by provenance_hash). Sender key wire types also lack it.
- ProtocolRepository: to_vec -> to_vec_named SOUND, backward-compatible deserialization
- Dedup cache TTL: 1h -> 24h per spec 9.8.2(b), SOUND
- Wire format: 10 ref_id -> "ref" renames + event_type -> "type", comprehensive tests, SOUND
- Conflict detection: RemoveMember same-target + RotateContentKeys self-conflict added, SOUND
- [u8;16] nonce fields lack serde_bytes (integer array in msgpack, not binary blob) -- wire format interop risk
- Block notification future-timestamp rejection added but no dedicated test for that code path

### White Paper Crypto Review (2026-03-09)
- Reviewed .docs/white-paper.md against specs. Substantially correct, no construction flaws.
- MEDIUM: Paper omits that MLS ciphersuite uses AES-128-GCM (not 256). System security bounded at 128-bit.
- MEDIUM: Sender keys do NOT provide forward secrecy (intentional, spec 9.16.5) -- paper omits this.
- MEDIUM: HPKE info param has var-length concat ambiguity (pre-existing spec issue).
- LOW: MessagePack listed as "Cryptographic Primitive" (it's a serialization format).
- LOW: X25519, HMAC-SHA256 missing from Appendix A primitives table.
- Composition: MLS epoch vs sender key epoch independence, 3-layer ordering load-bearing, UCAN-MLS gap window.
- All RFC/NIST references correct. Formal analysis call in Section 14.1 is appropriate.

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
- `crates/scp-core/src/store/mod.rs` -- ProtocolRepository definition
- `crates/scp-core/src/store/economy.rs` -- adapter credential storage impl
- `bindings/kotlin/scp-kt-android/src/main/kotlin/works/limn/scp/android/platform/` -- Android adapters
- `crates/scp-core/src/envelope/pseudonym.rs` -- pseudonym derivation spec (delegates to KeyCustody)
- `crates/scp-platform/src/testing/key_custody.rs` -- InMemoryKeyCustody reference impl + golden vectors
- `crates/scp-transport/src/relay/bridge.rs` -- bridge auth, SCP-BRIDGE-REGISTER-V1 domain separator
- `crates/scp-identity/src/resolver.rs` -- DualLayerResolver, healing publisher, anti-rollback
- `crates/scp-identity/src/resolution.rs` -- did_routing_id(), relay-based resolution
- `crates/scp-identity/src/dht.rs` -- DidDht, BEP44, did_from_ed25519_public_key, migration proofs
