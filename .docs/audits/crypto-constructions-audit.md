---

> **Line number shift notice:** References to `05-contexts.md` §5.14 (broadcast) are shifted +47 to +64 after PR #296 merged. All findings remain valid.

# SCP Cryptographic Specification Audit

## Executive Summary

This audit covers all cryptographic constructions specified in `09-security-model.md` (sections 9.3-9.17), `03-identity.md` (key management, DID, rotation), and `07-trust-validation-and-capabilities.md` (UCAN, attestations). I have identified **9 CRITICAL**, **11 HIGH**, **8 MEDIUM**, and **5 LOW** severity findings.

The most serious category of findings involves underspecified constructions where implementers must make choices that affect security and cross-platform interoperability, but the spec provides insufficient guidance to make those choices correctly. Several hash constructions lack length prefixes on variable-length fields, creating concatenation ambiguity. The HPKE usage for sender key wrapping is described at a "roll your own" level rather than pointing to a standard HPKE mode.

---

## Findings

### [CRYPTO-01] InnerEnvelope Signature Hash Lacks Length Prefixes on Variable-Length Fields
- **Construction**: InnerEnvelope canonical hash for Ed25519 signature
- **Location**: 09-security-model.md, line 214 (section 9.5) and line 368 (section 9.8.1)
- **What's missing**: The signature formula is `SHA256("SCP-INNER-ENVELOPE-V1:" || context_id || sender_did || epoch || generation_number || sequence_number || timestamp || payload_hash || provenance_hash)`. The `context_id` and `sender_did` are variable-length strings. No length prefixes are specified. A `context_id` of "abc" with `sender_did` of "def" produces the same hash input as `context_id` "ab" with `sender_did` "cdef". The migration proof formula (line 350) correctly uses `len()` as 4-byte BE prefixes for its variable-length fields -- this same pattern is missing from the envelope signatures.
- **Security impact**: Concatenation ambiguity enables second-preimage attacks where an attacker can construct a different `(context_id, sender_did)` pair that produces the same signature input. This is a forgery vector: a valid signature over one context/sender pair could validate for a different pair. In practice, the exploitation requires finding two valid DID strings whose concatenation matches, which is constrained but not impossible.
- **Severity**: CRITICAL

### [CRYPTO-02] BroadcastEnvelope Signature Hash Lacks Length Prefixes on Variable-Length Fields
- **Construction**: BroadcastEnvelope canonical hash for Ed25519 signature
- **Location**: 09-security-model.md, line 216 (section 9.5)
- **What's missing**: Same as CRYPTO-01. The formula `SHA256(context_id || sender_did || sequence || key_epoch || timestamp || content_hash || provenance_hash)` uses raw concatenation of variable-length `context_id` and `sender_did` without length prefixes. Additionally, this formula lacks the domain separator present in InnerEnvelope (`"SCP-INNER-ENVELOPE-V1:"`). There is no `"SCP-BROADCAST-ENVELOPE-V1:"` prefix.
- **Security impact**: (1) Same concatenation ambiguity as CRYPTO-01. (2) The missing domain separator means the same `(context_id, sender_did, ...)` values produce hash inputs that could collide with other hash constructions in the protocol. A valid broadcast signature could potentially be replayed as an InnerEnvelope signature if the fixed-length fields happen to align. The domain separator on InnerEnvelope prevents InnerEnvelope-to-Broadcast replay, but not the reverse direction.
- **Severity**: CRITICAL

### [CRYPTO-03] Sender Key HPKE Is Not Standard HPKE (RFC 9180) -- Manual Construction Specified
- **Construction**: Sender key wrapping HPKE
- **Location**: 09-security-model.md, line 798 (section 9.16.2)
- **What's missing**: The spec describes "HPKE assembly" as 4 manual steps: (1) generate ephemeral X25519, (2) ECDH, (3) HKDF to derive key, (4) AES-128-GCM encrypt. This is NOT RFC 9180 HPKE. RFC 9180 defines specific modes (Base, PSK, Auth, AuthPSK) with mandatory `info`, `psk`, `psk_id` parameters and a specific `ExtractAndExpand` procedure. The spec says "HKDF to derive encryption key" without specifying: which HKDF mode (Extract only? Expand only? Both?), what the salt is, what the info string is, what the key length is, or what the nonce is for AES-128-GCM. The access key section (line 916) specifies `info = "scp-sender-key-v1" || context_id || member_did || epoch` but the sender key section does not reference this info string -- the info string appears only in the access key context as a contrast example.
- **Security impact**: Without a specified HPKE mode, info string, and nonce derivation, each implementation will make different choices, producing incompatible ciphertext. Worse, a naive implementation might reuse the same derived key with a fixed nonce across multiple key exchanges, which would be catastrophic for AES-GCM. The manual 4-step construction also omits the HPKE KDF's `labeled_extract` and `labeled_expand` steps that provide critical domain separation within RFC 9180.
- **Severity**: CRITICAL

### [CRYPTO-04] Sender Key AES-256-GCM Nonce Generation Unspecified
- **Construction**: Sender-side encryption (AES-256-GCM with sender keys)
- **Location**: 09-security-model.md, line 778-780 (section 9.16.1)
- **What's missing**: Each sender encrypts messages with their AES-256-GCM sender key before MLS encryption. The spec does not specify how the 12-byte nonce/IV is generated for this encryption. Options include: random nonce (requires CSPRNG), counter-based nonce (requires persistent state), nonce derived from MLS generation number, etc. Each has different security properties. A sender key is long-lived (rotates only on block events, per section 9.16.5), so nonce collision probability under random nonce generation must be bounded. With AES-GCM's 96-bit nonce, the birthday bound is approximately 2^48 messages per key -- but the spec does not mandate key rotation before approaching this bound.
- **Security impact**: If two messages under the same sender key reuse a nonce, AES-GCM is catastrophically broken: the authentication tag becomes forgeable and the XOR of plaintexts is revealed. Without specifying the nonce generation strategy, interoperability is impossible and nonce reuse is probable in long-lived contexts.
- **Severity**: CRITICAL

### [CRYPTO-05] Content Access Key CEK Nonce Generation Partially Specified but Randomness Source Unspecified
- **Construction**: Content access key layer AES-256-GCM encryption
- **Location**: 09-security-model.md, line 941-944 (section 9.17.3)
- **What's missing**: The `WrappedContent` struct includes `pub nonce: [u8; 12]` for AES-256-GCM, which is good -- the nonce is in the wire format. However, the spec does not specify how this nonce is generated. Each CEK is per-message (ephemeral), so random nonces are safe from the birthday bound perspective (each key is used exactly once). But the spec must mandate CSPRNG (e.g., `OsRng`) for nonce generation. A predictable nonce combined with a known-plaintext attack could reveal the CEK.
- **Security impact**: If nonces are generated from a non-cryptographic source, combined with the fact that CEKs are ephemeral but access keys are long-lived, this could enable attacks against the key wrapping layer. The risk is moderate because each CEK is single-use.
- **Severity**: MEDIUM

### [CRYPTO-06] Pseudonym Derivation Uses Undefined "Ed25519_keygen" From HMAC Output
- **Construction**: Per-context pseudonym derivation
- **Location**: 09-security-model.md, lines 549-551, 568-570 (section 9.10.4)
- **What's missing**: The derivation is `context_seed = HMAC-SHA256(identity_key_material, context_id || "scp-pseudonym")` then `context_keypair = Ed25519_keygen(context_seed[0..32])`. The function `Ed25519_keygen` is not defined anywhere in the spec. This is the exact cross-platform incompatibility I documented in my memory -- `Ed25519_keygen(seed)` could mean: (a) use the 32 bytes as an Ed25519 seed (RFC 8032: SHA-512 then clamp), which is what `ed25519_dalek::SigningKey::from_bytes()` does, or (b) use the 32 bytes as a clamped scalar directly, which is what CryptoKit `Curve25519.Signing.PrivateKey(rawRepresentation:)` does. These produce DIFFERENT public keys from the same 32-byte input.
- **Security impact**: Pseudonyms are used for message routing. If implementations disagree on the keygen semantics, messages will be routed to wrong pseudonyms and delivery will fail. This is an interoperability-breaking bug, not a security vulnerability per se, but it prevents cross-platform operation.
- **Severity**: HIGH

### [CRYPTO-07] Pseudonym HMAC Key Material Ambiguously Specified
- **Construction**: Per-context pseudonym derivation
- **Location**: 09-security-model.md, lines 549, 554, 560 (section 9.10.4)
- **What's missing**: The HMAC key is `identity_key_material` (line 549), described as "the DID's `#0` key" (line 554). But line 560 contradicts: "For software keys, the HMAC uses the raw Ed25519 public key bytes (ADR-027 amendment)". The HMAC key is the public key, not the private key. For hardware-backed keys, "the HSM computes the HMAC internally using an associated symmetric key derived during `generate_keypair`". So the HMAC key differs by custody type: public key bytes for software, HSM-derived symmetric key for hardware. The spec claims "All implementations produce identical output" but provides no mechanism to ensure the HSM-derived key produces the same HMAC as using the public key.
- **Security impact**: If software and hardware custody implementations use different HMAC keys, the same identity in different custody modes produces different pseudonyms. This breaks routing and creates a fingerprinting oracle: an observer who sees a pseudonym change after a custody migration can infer the custody type changed. More fundamentally, the claim of cross-platform determinism is unverified.
- **Severity**: HIGH

### [CRYPTO-08] Block Notification Signature Lacks Length Prefixes
- **Construction**: Block notification signature in sender key block protocol
- **Location**: 09-security-model.md, line 815 (section 9.16.3)
- **What's missing**: The block notification is signed as `SHA-256(context_id || "block" || alice_did || bob_did || timestamp)`. The `context_id`, `alice_did`, and `bob_did` are all variable-length strings separated by the fixed string `"block"`. However, the boundary between `context_id` and `"block"` is ambiguous: a `context_id` ending in `"block"` concatenated with `""` produces the same bytes as a shorter `context_id` concatenated with `"block"`. Length prefixes on variable-length fields would resolve this. Note: the literal string "block" provides partial domain separation but is not a length prefix.
- **Security impact**: An attacker could construct a valid block notification for a different (context_id, blocker, blocked) triple. Exploitation requires finding specific DID/context_id values whose concatenation collides, which is unlikely but theoretically possible.
- **Severity**: MEDIUM

### [CRYPTO-09] SenderKeyEpochAdvance Signature Lacks Domain Separator
- **Construction**: SenderKeyEpochAdvance signature
- **Location**: 09-security-model.md, line 792 (section 9.16.2)
- **What's missing**: The epoch advance signature covers `context_id || sender_did || "key_epoch" || epoch`. This uses the inline string "key_epoch" as a domain separator, but: (1) `context_id` and `sender_did` are variable-length with no length prefixes; (2) the string "key_epoch" could be part of the `sender_did` suffix; (3) `epoch` is not specified as a fixed-width encoding (big-endian u64? variable-length integer?). The migration proof (line 350) correctly uses 4-byte BE length prefixes and 8-byte BE timestamps -- this same rigor is missing here.
- **Security impact**: Same concatenation ambiguity class as CRYPTO-01. Additionally, the epoch encoding ambiguity means different implementations could produce different signatures over the same logical content.
- **Severity**: HIGH

### [CRYPTO-10] HPKE Suite for Sender Key/Access Key Distribution Not Fully Specified
- **Construction**: HPKE for sender key and access key distribution
- **Location**: 09-security-model.md, line 798 (section 9.16.2) and line 916 (section 9.17.1)
- **What's missing**: Section 9.5 specifies "HPKE (RFC 9180) with suite DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM" for DID-to-DID encryption. It is unclear whether sender key distribution uses this same suite. Section 9.16.2 describes a manual ECDH + HKDF + AES-128-GCM construction. Section 9.17.1 mentions "HPKE info strings" with a domain separator but does not specify the HPKE mode (Base, PSK, Auth, AuthPSK). The sender key HPKE section says nothing about which HPKE mode is used. For sender keys, the recipient's ephemeral wrapping key is used, which maps to HPKE Base mode, but this is not stated.
- **Security impact**: Without specifying the exact HPKE mode and parameters, implementations cannot interoperate. If one implementation uses HPKE Base mode and another uses Auth mode, the ciphertexts are incompatible.
- **Severity**: HIGH

### [CRYPTO-11] HPKE Info String for Sender Key Distribution Not Specified
- **Construction**: HPKE key derivation for sender key wrapping
- **Location**: 09-security-model.md, line 798 (section 9.16.2)
- **What's missing**: The access key section (line 916) specifies info strings: `info = "scp-access-key-v1" || context_id || member_did || epoch` and references `"scp-sender-key-v1"` as the sender key equivalent. But the sender key section (line 798) where the actual HPKE assembly is described does not specify the info string at all. It only says "HKDF to derive encryption key" with no info parameter. The `"scp-sender-key-v1"` string appears only as a parenthetical contrast in the access key section.
- **Security impact**: The HPKE/HKDF info string binds the derived key to its context. Without it, keys derived in one context could be valid in another context (cross-context key confusion). Without specifying the info string structure in the sender key section, implementations will diverge.
- **Severity**: HIGH

### [CRYPTO-12] Attestation Signature Input Not Canonicalized
- **Construction**: Attestation format signature (general attestation envelope)
- **Location**: 07-trust-validation-and-capabilities.md, lines 421-442 (section 7.4.1)
- **What's missing**: The Attestation format includes `signature: issuer's cryptographic signature` but does not specify what bytes the signature is over. Is it over a canonical serialization of all other fields? If so, what serialization format? JSON? MessagePack? CBOR? What is the field ordering? Are optional fields (`evidence`, `expires`, `renewed_at`) included in the signed data when absent? The spec says "verification of the envelope (signature, expiry, revocation) is automated and mechanical" but does not define the canonical form that makes this possible.
- **Security impact**: Without a canonical serialization, different implementations will sign different byte sequences for the same logical attestation. Cross-platform attestation verification will fail. This is a fundamental interoperability blocker for the entire attestation system.
- **Severity**: CRITICAL

### [CRYPTO-13] ParticipationProfile Signature Input Not Canonicalized
- **Construction**: ParticipationProfile Ed25519 signature
- **Location**: 07-trust-validation-and-capabilities.md, lines 144-158 (section 7.3.2.1)
- **What's missing**: The `ParticipationProfile` struct has a `signature: Ed25519Signature` field and the spec says "The signature covers all fields except itself." But it does not specify: (1) the serialization format for the signed bytes; (2) the field ordering in the canonical form; (3) whether field names are included or just values; (4) the encoding of each field type (`DID` as UTF-8? `u64` as big-endian? little-endian? variable-length?); (5) whether a domain separator is used.
- **Security impact**: Same as CRYPTO-12. Different implementations will produce different signatures over the same logical `ParticipationProfile`, breaking admission verification across platforms.
- **Severity**: CRITICAL

### [CRYPTO-14] ParticipationProfile Signing Key Derivation Not Specified
- **Construction**: Context-specific Ed25519 signing key for ParticipationProfile
- **Location**: 07-trust-validation-and-capabilities.md, lines 156-161 (section 7.3.2.1)
- **What's missing**: The spec says `signer_public_key` is "context-specific -- derived from the context's identity with domain separation, not reused across contexts." It does not specify: (1) what "the context's identity" is (does the context have a key? Is it the creator's key? A group key?); (2) the derivation function (HMAC? HKDF? SHA-256?); (3) the domain separation string; (4) the input material; (5) how the derived Ed25519 keypair is generated from the derived material (same `Ed25519_keygen` ambiguity as CRYPTO-06). This is a complete specification gap -- there is no way to implement this construction from the spec alone.
- **Security impact**: Without the derivation specification, the privacy guarantee (contexts cannot be correlated via signer keys) is aspirational but unimplementable. Each implementation will invent its own derivation, and they will not interoperate.
- **Severity**: CRITICAL

### [CRYPTO-15] Pre-Rotation Commitment Is Bare SHA-256 Without Domain Separation
- **Construction**: Pre-rotation commitment scheme
- **Location**: 09-security-model.md, line 334 (section 9.7.4)
- **What's missing**: The pre-rotation commitment is `SHA-256(public_key)` -- a bare hash of the 32-byte Ed25519 public key with no domain separator, no length prefix, and no version tag. If any other construction in the protocol hashes a 32-byte value with SHA-256, the commitments could collide in meaning. The migration proof (line 350) correctly uses `"SCP-MIGRATION-V1:"` as a domain separator. The commitment itself should use something like `SHA-256("SCP-PRE-ROTATION-COMMITMENT-V1:" || public_key)`.
- **Security impact**: In isolation, this is low risk because the commitment is stored in a specific field of the DID document. However, the protocol uses SHA-256 hashes of 32-byte values in multiple places (event hashes, routing IDs, etc.). A commitment value that happens to match another hash could be confused in contexts where the field type is not checked. More importantly, this violates the spec's own domain separation pattern used everywhere else.
- **Severity**: LOW

### [CRYPTO-16] Sender Key AES-256-GCM Nonce Not Included in Sender Key Wire Format
- **Construction**: Sender key encrypted message format
- **Location**: 09-security-model.md, sections 9.16.1-9.16.2
- **What's missing**: When a sender encrypts a message with their AES-256-GCM sender key, the resulting ciphertext must be accompanied by the nonce used for encryption. The spec defines the content access key layer's `WrappedContent` struct with an explicit `nonce: [u8; 12]` field (line 944), but there is no equivalent wire format specification for the sender key encryption layer. The spec says "Sender-first (AES-256-GCM), then MLS" but does not define the data structure that carries the sender-key-encrypted ciphertext and its nonce.
- **Security impact**: Without a wire format, implementations cannot exchange sender-key-encrypted messages interoperably. The nonce must be transmitted alongside the ciphertext for decryption.
- **Severity**: HIGH

### [CRYPTO-17] AES-256-GCM AAD Concatenation Ambiguity in Content Access Key Layer
- **Construction**: Content access key AAD
- **Location**: 09-security-model.md, line 919 (section 9.17.1)
- **What's missing**: The AAD is specified as `AAD = context_id || sender_did || sequence_number`. The `context_id` and `sender_did` are variable-length strings. The `sequence_number` encoding is not specified (u64 BE? u32? varint?). Same concatenation ambiguity class as CRYPTO-01. A shorter `context_id` + longer `sender_did` could produce the same AAD bytes as a longer `context_id` + shorter `sender_did`.
- **Security impact**: AAD mismatch between sender and receiver causes AES-GCM decryption to fail silently (authentication tag verification failure). This is primarily an interoperability issue -- a malicious attack exploiting this ambiguity would require the attacker to be a context member (since the content is inside MLS).
- **Severity**: MEDIUM

### [CRYPTO-18] Broadcast Key Encryption Parameters Unspecified
- **Construction**: Broadcast key AES-256-GCM encryption of content
- **Location**: 05-contexts.md, lines 816-826, 872-896 (section 5.14)
- **What's missing**: The spec says "AES-256-GCM encrypted with author broadcast key" (line 875) and the send path (line 890) says "AES-256-GCM encrypt with author broadcast key." But: (1) Nonce generation for broadcast encryption is not specified. (2) The wire format for the broadcast-encrypted content (ciphertext + nonce + auth tag) is not defined. (3) AAD for broadcast AES-256-GCM encryption is not specified. The content access key layer specifies AAD (line 919), but it is unclear whether broadcast encryption has its own AAD binding. The `BroadcastEnvelope` struct (lines 871-876) has `content: Vec<u8>` described as "AES-256-GCM encrypted" but no nonce field.
- **Security impact**: Same class as CRYPTO-04. Without nonce generation specification and wire format, implementations cannot interoperate and may reuse nonces.
- **Severity**: CRITICAL

### [CRYPTO-19] Identity Private State Encryption Not Specified
- **Construction**: Identity private state encryption
- **Location**: 03-identity.md, lines 97-132 (section 3.7)
- **What's missing**: The spec says "Private state is encrypted to the identity's own keys" and "Only you hold the decryption key." It does not specify: (1) which algorithm encrypts private state (AES-256-GCM? The MLS ciphersuite's AEAD?); (2) what key encrypts it (derived from Identity Key? Active Key? A dedicated symmetric key?); (3) how the key is derived (HKDF? Direct use?); (4) nonce generation; (5) AAD binding; (6) how re-encryption works on key rotation ("re-encrypted to the new key" -- but which key?). This is a complete specification gap for a construction that protects block lists, graph policies, agent configs, and annotations.
- **Security impact**: Without a specified encryption scheme, each platform will implement its own, and identity private state will not be portable across platforms or devices. The security properties (authenticated encryption, forward secrecy on rotation) are aspirational but unverifiable.
- **Severity**: HIGH

### [CRYPTO-20] Cover Traffic Dummy Flag Not Authenticated
- **Construction**: Cover traffic real/dummy discrimination
- **Location**: 09-security-model.md, lines 606-607 (section 9.10.6)
- **What's missing**: "Single-byte flag inside encrypted payload distinguishes real from dummy. `REAL_FLAG = 0x01`, `DUMMY_FLAG = 0x00`." The flag is inside the encrypted payload, which means it is protected by MLS encryption (authenticated). However, for broadcast contexts, the flag would be inside the broadcast-key-encrypted payload. If an attacker obtains the broadcast key (e.g., as a subscriber who was later blocked but retained the key from a non-compliant SDK), they could distinguish real from dummy traffic for that broadcast context.
- **Security impact**: Limited. The real/dummy distinction leaks only whether a broadcast message is real or dummy to a subscriber who retained a key they should have destroyed. The main defense (cover traffic rate masking) still works against the relay because the relay cannot decrypt.
- **Severity**: LOW

### [CRYPTO-21] Merkle Tree Hash Construction Inconsistency with RFC 6962
- **Construction**: Merkle tree event log hash
- **Location**: 09-security-model.md, line 212 (section 9.5)
- **What's missing**: The spec says "Each event entry is `SHA256(previous_hash || event_data)`." This is a hash chain, not a Merkle tree construction. RFC 6962 Merkle trees use domain-separated leaf hashing `SHA-256(0x00 || data)` and interior hashing `SHA-256(0x01 || left || right)`. The spec's description conflates a hash chain (linear, each entry references the previous) with a Merkle tree (binary, leaves and interior nodes hashed differently). The implementation in `event_log/tree.rs` (per my memory) correctly uses RFC 6962 domain separation. The spec description at line 212 is inaccurate relative to the implementation.
- **Security impact**: If an implementer follows the spec text at line 212 literally, they would build a hash chain, not a Merkle tree. Hash chains do not support efficient inclusion proofs or consistency proofs. The security model's references to "Merkle root" and "proof-of-inclusion" (section 7.3.1) would be impossible with the construction described in section 9.5.
- **Severity**: HIGH

### [CRYPTO-22] KeyPackage Signing Key Not Specified
- **Construction**: MLS KeyPackage generation and signing
- **Location**: 09-security-model.md, line 337 (section 9.7.4)
- **What's missing**: The spec says "Pre-generated and published to relays. Each KeyPackage is single-use. Signed by identity key." In MLS (RFC 9420), KeyPackages are signed by the leaf signing key (the credential key), not the identity key. The spec's three-key architecture (section 3.7) has `#0` (Identity Key), `#active` (Active Signing Key), and `#agent` (Agent Signing Key). Which key signs KeyPackages? If the Identity Key (`#0`) signs them, that contradicts ADR-003 which says `#0` is used "ONLY for DID document updates and signing pre-rotation commitments." If the Active Signing Key signs them, the spec text "signed by identity key" is incorrect. The MLS credential must match the signing key.
- **Security impact**: Confusion about which key signs KeyPackages will cause MLS credential validation failures. If `#0` is used (as the spec text says), it violates the principle of minimal key usage for the root of trust. If `#active` is used (as the rest of the spec implies), the spec text is wrong and implementers following it will produce invalid KeyPackages.
- **Severity**: HIGH

### [CRYPTO-23] Routing ID for Encrypted Contexts Not Specified
- **Construction**: Per-context routing_id derivation for encrypted contexts
- **Location**: 09-security-model.md, line 534 (section 9.10.2) and line 561 (section 9.10.4)
- **What's missing**: For broadcast contexts, the `routing_id = SHA-256(context_id)` is clearly specified. For encrypted contexts, line 534 says routing IDs use "HKDF-derived pseudonyms" but the actual HKDF derivation for the `routing_id` is never specified. Section 9.10.4 specifies pseudonym derivation for `context_pseudonym` (used as `recipient_hint`), but the `routing_id` itself -- the key under which blobs are stored on the relay -- is not defined. Is it the pseudonym public key? A hash of it? A separate HKDF derivation? The metadata routing ID is specified as `SHA-256(context_id || "scp-metadata")` (line 561), and the DID routing ID is `SHA-256("scp:did:" || did_string)` (section 3.10.2), but the primary encrypted context routing ID is absent.
- **Security impact**: The routing ID is the fundamental addressing primitive for message delivery. Without its specification, implementations cannot publish or subscribe to the correct relay topics. Messages will not be delivered.
- **Severity**: CRITICAL

### [CRYPTO-24] SenderKeyRequest Signature Input Not Fully Specified
- **Construction**: SenderKeyRequest authentication
- **Location**: 09-security-model.md, line 794 (section 9.16.2)
- **What's missing**: `SenderKeyRequest { requester_did, sender_did, epoch, wrapping_pubkey, signature }`. The `signature` field exists but the spec does not define what bytes are signed. It says "verifies the signature" but does not specify the canonical hash input for the signature. Compare with `SenderKeyEpochAdvance` (line 792) which at least specifies `context_id || sender_did || "key_epoch" || epoch` as the signed content. The `SenderKeyRequest` signature input is completely absent.
- **Security impact**: Without specifying the signed bytes, implementations cannot verify each other's signatures. This breaks the pull-based key distribution protocol across platforms.
- **Severity**: HIGH

### [CRYPTO-25] AccessKeyRequest Signature Not Canonicalized
- **Construction**: AccessKeyRequest signature
- **Location**: 09-security-model.md, line 921 (section 9.17.1)
- **What's missing**: The signed payload is `{ context_id, requester_did, epoch, timestamp }` but the serialization is not specified. Is it JSON? Is it canonical concatenation? What byte encoding for each field? The timestamp format (Unix seconds? milliseconds? big-endian?) is unspecified. Without a canonical form, different implementations will produce different signature inputs.
- **Security impact**: Same interoperability class as CRYPTO-12. Cross-platform access key requests will fail signature verification.
- **Severity**: MEDIUM

### [CRYPTO-26] KeyDestructionAttestation Signature Input Not Specified
- **Construction**: KeyDestructionAttestation Ed25519 signature
- **Location**: 09-security-model.md, lines 750-758 (section 9.15)
- **What's missing**: The `KeyDestructionAttestation` struct includes `signature: Ed25519Signature` and says "signed by `#0` (Identity Key) or `#active` (Active Signing Key)." The spec does not define the canonical bytes that are signed. Is it a hash of all other fields? If so, what serialization? What domain separator?
- **Security impact**: Destruction attestations that cannot be verified across platforms undermine the ephemeral context destruction verification protocol.
- **Severity**: MEDIUM

### [CRYPTO-27] ConsistencyCheckpoint Signature Input Not Specified
- **Construction**: ConsistencyCheckpoint Ed25519 signature
- **Location**: 09-security-model.md, lines 462-471 (section 9.9.3)
- **What's missing**: The `ConsistencyCheckpoint` struct includes `signature: Ed25519Signature` but does not specify what bytes are signed. Same class as CRYPTO-26. The fields include `contextID`, `senderDID` (variable-length), `eventCount`, `merkleRoot`, `epoch`, `timestamp`. No serialization format, no domain separator.
- **Security impact**: Consistency checkpoints that cannot be verified across platforms undermine equivocation detection.
- **Severity**: MEDIUM

### [CRYPTO-28] Provenance Hash Serialization Not Canonical
- **Construction**: Provenance hash in envelope signatures
- **Location**: 09-security-model.md, line 214 (section 9.5)
- **What's missing**: `provenance_hash = SHA256(serialize(provenance))`. The `serialize()` function is not specified. What format? JSON (not canonical across implementations)? MessagePack (not canonical across implementations without sorted keys)? CBOR (has canonical modes but spec does not reference them)? The `DataProvenance` struct (07-trust-validation-and-capabilities.md, lines 512-528) contains nested types (`MemoryScope`, `Amount`, arrays, optional fields) that make canonical serialization non-trivial.
- **Security impact**: If sender and receiver use different serialization for provenance, the provenance hash will not match, and signature verification will fail. This is a hard interoperability blocker.
- **Severity**: HIGH

### [CRYPTO-29] Sender Key Encryption Uses AES-256-GCM but HPKE Wrapping Uses AES-128-GCM -- Inconsistency
- **Construction**: Sender key encryption vs. sender key distribution
- **Location**: 09-security-model.md, line 778 (section 9.16.1) and line 798 (section 9.16.2)
- **What's missing**: The sender key itself is AES-256 (32 bytes, line 778). The HPKE assembly for distributing this key uses AES-128-GCM (line 798). This means the key transport mechanism has 128-bit security while the transported key provides 256-bit security. This is not a vulnerability per se (128-bit security is sufficient), but it is an inconsistency that suggests the spec may have conflated the MLS ciphersuite's AEAD (AES-128-GCM) with the sender key layer's AEAD (AES-256-GCM). If the intent is for the sender key layer to provide AES-256 security, the transport should also be AES-256.
- **Security impact**: The security level of the sender key system is bounded by the weaker 128-bit HPKE transport, not the 256-bit sender key. This may be intentional (matching the MLS ciphersuite) or may be an oversight.
- **Severity**: LOW

### [CRYPTO-30] AES-256-KW Wrapped CEK Size Mismatch
- **Construction**: Content access key AES-256-KW wrapping
- **Location**: 09-security-model.md, lines 949-953 (section 9.17.3)
- **What's missing**: The `WrappedCek` struct specifies `wrapped_key: [u8; 40]` with the comment "32-byte CEK + 8-byte integrity check." RFC 3394 (AES Key Wrap) adds exactly 8 bytes to the input, so wrapping a 32-byte key produces a 40-byte output. This is correct. However, the spec says "AES-256-KW (RFC 3394). Deterministic, no IV needed." RFC 3394 actually uses a default IV (`A6A6A6A6A6A6A6A6`). The statement "no IV needed" is technically correct (the IV is fixed and specified by the RFC) but could mislead an implementer into using a different IV or no IV check during unwrapping.
- **Security impact**: Minimal. Any correct RFC 3394 implementation uses the default IV. But an implementer who reads "no IV needed" might skip the IV verification during unwrapping, which would weaken integrity checking.
- **Severity**: LOW

### [CRYPTO-31] Identity Private State Re-encryption on Key Rotation Lacks Detail
- **Construction**: Identity private state re-encryption
- **Location**: 03-identity.md, line 138 (section 3.7)
- **What's missing**: "On identity key rotation (§9.12), private state is re-encrypted to the new key. Single-owner case requires no group redistribution -- the owner re-encrypts and republishes." The spec does not define: (1) what re-encryption means operationally (decrypt with old key, re-encrypt with new key?); (2) whether forward secrecy is provided (is the old key zeroized after re-encryption?); (3) what happens if the device is offline during rotation (stale encrypted blobs on relays); (4) the atomicity requirements (can a crash during re-encryption leave some events encrypted under the old key and some under the new key?).
- **Security impact**: A crash during re-encryption could leave identity private state in an inconsistent state where some events require the old key (which may have been zeroized) and others require the new key. Data loss of block lists, graph policies, and other identity-critical state.
- **Severity**: MEDIUM

### [CRYPTO-32] UCAN CID Computation Not Specified in Protocol Spec
- **Construction**: UCAN revocation CID computation
- **Location**: 09-security-model.md, line 218 (section 9.5)
- **What's missing**: The spec says revocation uses "token CIDs" in the `RevocationList` but does not define how a CID is computed from a UCAN token. My memory records show the implementation uses `SHA-256(JSON(payload))` with a non-standard "bafyrei" prefix. This is not a valid CID v1 per the IPFS/IPLD specification (which requires multicodec + multihash encoding). The spec should define the exact CID computation to prevent the UniFFI bridge bug I documented (PR #127: UniFFI revokes by raw `token_id` instead of computed CID, making mobile revocations no-ops).
- **Security impact**: Without a specified CID computation, implementations will use different methods to identify tokens for revocation. This is a known bug in production (PR #127). UCAN revocations from mobile/desktop clients silently fail.
- **Severity**: HIGH

### [CRYPTO-33] No Zeroization Requirements in Spec
- **Construction**: Key material lifecycle
- **Location**: 09-security-model.md, sections 9.7.2, 9.7.4, 9.15, 9.16
- **What's missing**: The spec uses the word "destroyed" and "deleted" extensively for key material (old epoch keys, consumed KeyPackages, sender keys on block, access keys on revocation) but never specifies the technical requirement for zeroization. Zeroization means overwriting key material bytes with zeros before deallocation, preventing recovery from memory dumps, swap files, or core dumps. The spec should mandate: (1) all key material types implement zeroize-on-drop; (2) key material must not be copied to non-zeroizing buffers; (3) debug/display implementations must not log key material. Without these requirements, "destroyed" is operationally meaningless -- `drop()` or `free()` does not clear memory.
- **Security impact**: Key material that is "destroyed" by deallocation without zeroization can be recovered from process memory, swap files, crash dumps, or hibernation images. This directly undermines forward secrecy claims.
- **Severity**: LOW

---

## Construction-by-Construction Assessment

### 1. MLS Group Operations
- **Specification**: MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 (RFC 9420 section 17.1)
- **Soundness**: CONDITIONALLY SOUND
- **Issues**: Ciphersuite itself is standard. KeyPackage signing key ambiguity (CRYPTO-22). MLS group_context extensions for nesting are specified. Forward secrecy grace window (30s) is well-defined. PCS Update intervals are specified (24h default).
- **What's solid**: Epoch key deletion requirements, grace window, MLS-to-SCP concept mapping.

### 2. Sender Key HPKE Wrapping
- **Specification**: Manual ECDH + HKDF + AES-128-GCM
- **Soundness**: UNSOUND as specified
- **Issues**: CRYPTO-03 (not standard HPKE), CRYPTO-10 (mode unspecified), CRYPTO-11 (info string missing in sender key section), CRYPTO-29 (128-bit transport for 256-bit key). The construction is described at the level of "do ECDH then HKDF then AEAD" without the specificity needed for interoperable implementation.

### 3. Content Access Key AES-256-KW Wrapping
- **Specification**: AES-256-KW (RFC 3394) wrapping per-message CEKs
- **Soundness**: SOUND
- **Issues**: CRYPTO-30 (minor IV documentation). The construction is well-specified: CEK generation (32-byte random), wrapping (RFC 3394), wire format (WrappedCek struct), member_id derivation (SHA-256 truncation), deterministic ordering (Vec not HashMap). HPKE info string domain separation is specified for access key distribution.

### 4. InnerEnvelope Construction
- **Specification**: Domain-separated SHA-256 hash signed with Ed25519
- **Soundness**: CONDITIONALLY SOUND
- **Issues**: CRYPTO-01 (missing length prefixes). Domain separator `"SCP-INNER-ENVELOPE-V1:"` is present and correct. Field set is comprehensive (context_id, sender_did, epoch, generation, sequence, timestamp, payload_hash, provenance_hash). Processing order is correctly specified.
- **What's solid**: Domain separator, hash-then-sign, payload_hash covers pre-padding plaintext, provenance binding.

### 5. BroadcastEnvelope Construction
- **Specification**: SHA-256 hash signed with Ed25519
- **Soundness**: UNSOUND as specified
- **Issues**: CRYPTO-02 (missing domain separator AND length prefixes). This is the only signature construction in the protocol without a domain separator prefix.

### 6. Metadata Routing ID Derivation
- **Specification**: `SHA-256(context_id || "scp-metadata")` for metadata; `SHA-256("scp:did:" || did_string)` for DID resolution
- **Soundness**: CONDITIONALLY SOUND for the two that are specified
- **Issues**: CRYPTO-23 (encrypted context routing_id derivation unspecified). Broadcast routing_id `SHA-256(context_id)` is specified. The domain separators for metadata and DID routing are good. But the primary encrypted context routing ID -- the one used for actual message delivery -- is missing.

### 7. Pseudonym Derivation
- **Specification**: `HMAC-SHA256(identity_key_material, context_id || "scp-pseudonym")` then `Ed25519_keygen(seed[0..32])`
- **Soundness**: CONDITIONALLY SOUND
- **Issues**: CRYPTO-06 (Ed25519_keygen undefined), CRYPTO-07 (HMAC key material ambiguous). Domain separation between v1 and v2 is good. Epoch-based rotation for v2 is well-designed. HSM compatibility approach is reasonable in principle but the cross-platform determinism claim is unverified.

### 8. Key Destruction Protocol
- **Specification**: Ordered destruction steps for ephemeral contexts
- **Soundness**: CONDITIONALLY SOUND
- **Issues**: CRYPTO-33 (no zeroization requirement). The destruction protocol itself is well-designed: hardware attestation where available, honest about limitations, signed attestations. The gap is the technical mechanism (zeroization) vs. the logical operation (destruction).

### 9. Pre-Rotation Commitment Scheme
- **Specification**: `SHA-256(public_key)` commitment, Ed25519 migration proof
- **Soundness**: CONDITIONALLY SOUND
- **Issues**: CRYPTO-15 (no domain separation on commitment). The migration proof is well-specified: domain separator, length prefixes, fixed-width timestamp. The commitment itself is bare.

---

## Key Material Audit

| Key Type | Generation | Storage | Rotation | Destruction | Zeroization |
|----------|-----------|---------|----------|-------------|-------------|
| Identity Key (#0) | HSM/Secure Enclave | Hardware | migrate_identity (rare) | N/A (hardware) | Hardware-managed |
| Active Signing Key (#active) | KeyCustody | Platform secure storage | rotate_active_key (DID doc update) | On rotation | NOT SPECIFIED |
| Agent Signing Key (#agent) | Software | Software keystore | rotate_agent_key (DID doc update) | On rotation | NOT SPECIFIED |
| Pre-Rotation Key | Ed25519 keygen | Cold/offline storage | Single-use (migration) | After migration | NOT SPECIFIED |
| MLS Epoch Keys | MLS library | Platform secure storage | Every Commit | After grace window (30s) | NOT SPECIFIED |
| Sender Keys (AES-256) | Random 32 bytes | Local key store | On block events | Old keys retained | NOT SPECIFIED |
| Access Keys (AES-256) | Random 32 bytes | Local key store | On revocation | Destroyed on revoke (Full) | NOT SPECIFIED |
| CEKs (AES-256) | Random 32 bytes per message | Ephemeral | N/A (single use) | After wrapping | NOT SPECIFIED |
| Broadcast Keys (AES-256) | Random 32 bytes | Local key store | On block/rotation | On author removal | NOT SPECIFIED |
| X25519 Wrapping Key | Software keygen | KeyCustody | On identity rotation | On rotation | NOT SPECIFIED |

**Randomness sources**: The spec does not explicitly mandate CSPRNG for key generation. The implementation uses `OsRng` (per my memory), which is correct. The spec should mandate this.

---

## Missing Cryptographic Operations

1. **Routing ID derivation for encrypted contexts** -- The fundamental addressing primitive for message delivery is unspecified.
2. **Canonical serialization format** -- No canonical serialization is defined for any signed structure (attestations, participation profiles, consistency checkpoints, key destruction attestations, access key requests, sender key requests).
3. **CSPRNG mandate** -- No explicit requirement for cryptographic randomness in key/nonce generation.
4. **Zeroization mandate** -- No explicit requirement for secure memory erasure of key material.
5. **Sender key encryption wire format** -- No struct definition for sender-key-encrypted message (ciphertext + nonce).
6. **Broadcast key encryption wire format** -- No struct definition for broadcast-key-encrypted content (ciphertext + nonce).
7. **HPKE mode specification** -- No explicit RFC 9180 mode selection for any HPKE usage.
8. **Nonce generation mandate for sender key and broadcast key encryption** -- No specification of how 12-byte nonces are generated for the non-MLS AES-GCM layers.

---

## Recommendations (ordered by severity)

### 1. [CRITICAL] Define canonical serialization format for all signed structures
All signed data structures (InnerEnvelope hash, BroadcastEnvelope hash, Attestation, ParticipationProfile, ConsistencyCheckpoint, KeyDestructionAttestation, SenderKeyRequest, AccessKeyRequest, block notification) MUST use a single, specified canonical serialization. Recommended: length-prefixed concatenation of fixed-width fields with domain separator prefix, matching the pattern already used for the migration proof. Define a `CanonicalHash` trait with a specification-level byte format for each type.

### 2. [CRITICAL] Add length prefixes to all variable-length fields in hash inputs
Every hash or signature input that contains variable-length fields (context_id, DID strings, serialized provenance) MUST use 4-byte big-endian length prefixes. The migration proof already does this correctly -- apply the same pattern to InnerEnvelope, BroadcastEnvelope, block notification, SenderKeyEpochAdvance, AAD, and all other concatenated hash inputs.

### 3. [CRITICAL] Add domain separator to BroadcastEnvelope signature
Add `"SCP-BROADCAST-ENVELOPE-V1:"` prefix to the broadcast envelope signature hash, matching the InnerEnvelope pattern. Without this, broadcast and inner envelope signatures share the same hash domain.

### 4. [CRITICAL] Specify sender key HPKE as RFC 9180 Base mode with explicit parameters
Replace the manual 4-step HPKE description with: "Sender key distribution uses HPKE (RFC 9180) in Base mode with suite DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM. The info parameter is `"scp-sender-key-v1" || context_id_len || context_id || member_did_len || member_did || epoch_be`." This eliminates all ambiguity about the KDF, nonce derivation, and key schedule.

### 5. [CRITICAL] Specify nonce generation for sender key and broadcast key AES-256-GCM
Mandate: "Nonces for sender key and broadcast key AES-256-GCM encryption MUST be 12 bytes generated from a CSPRNG (e.g., OsRng). Random nonces are safe because the birthday bound for 96-bit nonces (2^48 messages per key) will not be approached within a sender key epoch's lifetime."

### 6. [CRITICAL] Define encrypted context routing ID derivation
Specify the routing_id derivation for encrypted contexts, e.g.: `routing_id = SHA-256("scp-routing:" || context_id)` or derive from pseudonym material.

### 7. [CRITICAL] Specify ParticipationProfile signing key derivation
Define: "Context-specific signing key is derived as `signing_seed = HKDF-Expand(HKDF-Extract(salt="scp-participation-signer-v1", ikm=context_secret_key), info=context_id, L=32)`, and the Ed25519 signing key is generated from this seed using RFC 8032 seed-to-keypair."

### 8. [HIGH] Define `Ed25519_keygen(seed)` semantics
Specify: "Ed25519_keygen(seed) uses the 32-byte input as an Ed25519 seed per RFC 8032: the seed is SHA-512 hashed, the lower 32 bytes are scalar-clamped, and the upper 32 bytes form the nonce prefix. This matches `ed25519_dalek::SigningKey::from_bytes()` and `Bouncy Castle Ed25519PrivateKeyParameters(seed, 0)`." This resolves the cross-platform incompatibility with CryptoKit.

### 9. [HIGH] Define sender key encryption wire format
Add a `SenderKeyEncryptedContent { ciphertext: Vec<u8>, nonce: [u8; 12] }` struct to the wire format specification.

### 10. [HIGH] Define UCAN CID computation
Specify: "A UCAN token CID is computed as `SHA-256(canonical_json(payload))` where `canonical_json` produces RFC 8785 JSON Canonicalization Scheme output." Or adopt a proper CID v1 construction.

---

## Relevant File Paths

- `.docs/specs/09-security-model.md` -- Primary security and cryptographic specification
- `.docs/specs/03-identity.md` -- Identity, key custody, DID resolution
- `.docs/specs/07-trust-validation-and-capabilities.md` -- UCAN, attestations, participation profiles
- `.docs/specs/05-contexts.md` -- Broadcast context specifics (lines 801-935)

Now let me update my memory with these findings.
