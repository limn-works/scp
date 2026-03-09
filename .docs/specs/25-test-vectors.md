# 25. Cryptographic Test Vectors

## 25.1 Purpose

This section provides known-answer test vectors for all cryptographic constructions in the SCP protocol. An independent implementer MUST use these vectors to verify that their implementation produces correct output before attempting interoperability testing. Each vector specifies inputs, intermediate values (where applicable), and expected outputs in hexadecimal.

All byte values are lowercase hex with `0x` prefix unless otherwise noted. All integers are big-endian unless otherwise noted.

## 25.2 Reference Key Material

The following Ed25519 keypair is used across all test vectors for consistency. Implementations SHOULD verify they can reproduce the public key from the private key as a sanity check.

**Ed25519 Seed (32 bytes):**
```
0x9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60
```

**Ed25519 Public Key (32 bytes):**
```
0xd75a980182b10ab7d54bfed3c964073a0ee172f3daa3f4a18446b0b8d183f8e3
```

This is the RFC 8032 Section 7.1 Test Vector 1 keypair. Implementations that cannot reproduce this public key from the seed have a broken Ed25519 implementation and MUST NOT proceed with SCP interoperability testing.

**Secondary Ed25519 Seed (for two-party vectors):**
```
0x4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb
```

**Secondary Ed25519 Public Key (32 bytes):**
```
0x3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c
```

This is the RFC 8032 Section 7.1 Test Vector 2 keypair.

**X25519 Key Material (derived from Ed25519 keys for HPKE operations):**

Implementations derive X25519 keys from Ed25519 keys per RFC 8032 and the birational map. The exact X25519 public keys depend on the implementation's Ed25519-to-X25519 conversion. Implementations SHOULD verify round-trip consistency: `x25519_from_ed25519(ed25519_keypair).public == expected_x25519_public`.

## 25.3 Canonical Hash Construction Vectors

All signed structures use the canonical hash construction defined in §9.5.1. These vectors verify the byte-level construction.

### 25.3.1 Domain Separator Encoding

**Vector 1: Domain separator is raw UTF-8 bytes, no length prefix.**

```
Input:
  domain_separator: "SCP-INNER-ENVELOPE-V1:"

Expected bytes:
  0x5343502d494e4e45522d454e56454c4f50452d56313a
  (ASCII encoding of "SCP-INNER-ENVELOPE-V1:")
```

### 25.3.2 Variable-Length Field Encoding

**Vector 2: String field with 4-byte BE length prefix.**

```
Input:
  field_value: "did:dht:z6MkTest"

Expected bytes:
  0x00000010                              (length = 16, 4-byte BE)
  0x6469643a6468743a7a364d6b54657374      (UTF-8 bytes)

Combined: 0x000000106469643a6468743a7a364d6b54657374
```

### 25.3.3 Fixed-Length Field Encoding

**Vector 3: u64 integer as 8-byte BE.**

```
Input:
  value: 1700000000 (Unix timestamp)

Expected bytes:
  0x0000000065554d80
```

### 25.3.4 Optional Absent Field Encoding

**Vector 4: Absent optional field uses SHA-256(0x00) sentinel.**

```
Input:
  field: absent

Expected bytes (32 bytes):
  SHA-256(0x00) = 0x6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d
```

## 25.4 InnerEnvelope Signing Vectors (§9.5.2)

Domain: `"SCP-INNER-ENVELOPE-V1:"`

### Vector 5: Minimal InnerEnvelope

```
Input:
  context_id:       "test-context-01"
  sender_did:       "did:dht:z6MkTest"
  epoch:            1
  generation_number: 0
  sequence_number:  0
  timestamp:        1700000000
  payload_hash:     SHA-256("hello world") = 0xb94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9
  provenance_hash:  absent (use sentinel)
  signing_key_id:   "#active"

Canonical hash input (concatenated bytes):
  "SCP-INNER-ENVELOPE-V1:"                    (22 bytes, no length prefix)
  || BE32(15) || "test-context-01"             (4 + 15 = 19 bytes)
  || BE32(16) || "did:dht:z6MkTest"           (4 + 16 = 20 bytes)
  || BE64(1)                                   (8 bytes — epoch)
  || BE64(0)                                   (8 bytes — generation_number)
  || BE64(0)                                   (8 bytes — sequence_number)
  || BE64(1700000000)                          (8 bytes — timestamp)
  || BE32(32) || payload_hash                  (4 + 32 = 36 bytes)
  || BE32(32) || SHA-256(0x00)                 (4 + 32 = 36 bytes — absent provenance)
  || BE32(7)  || "#active"                     (4 + 7 = 11 bytes)

Total: 22 + 19 + 20 + 8 + 8 + 8 + 8 + 36 + 36 + 11 = 176 bytes

Expected: SHA-256 of the above 176 bytes. Sign this hash with the reference Ed25519 key.
The signature is 64 bytes. Verify with Ed25519-verify(public_key, hash, signature).
```

Implementations MUST produce identical canonical hash bytes. The SHA-256 of those bytes is the value signed by Ed25519.

### Vector 6: InnerEnvelope with Provenance

Same as Vector 5 but with `provenance_hash` present:

```
Input changes:
  provenance_hash: 0xabcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789

Canonical hash input changes:
  Position 8 (provenance_hash): BE32(32) || 0xabcdef...
  (replaces the SHA-256(0x00) sentinel)
```

## 25.5 Vote Signing Vectors (§6.4)

Domain: `"SCP-VOTE-V1:"`

### Vector 7: Approval Vote

```
Input:
  context_id:   "governance-test-ctx"
  proposal_id:  0x0102030405060708091011121314151617181920212223242526272829303132
  voter_did:    "did:dht:z6MkVoter"
  vote_value:   "approve" (tag: 0x01)
  timestamp:    1700000000

Canonical hash input:
  "SCP-VOTE-V1:"                                           (12 bytes)
  || BE32(19)  || "governance-test-ctx"                     (4 + 19 = 23 bytes)
  || proposal_id                                            (32 bytes, fixed-length)
  || BE32(18)  || "did:dht:z6MkVoter"                      (4 + 18 = 22 bytes)
  || 0x01                                                   (1 byte — approve tag)
  || BE64(1700000000)                                       (8 bytes)

Total: 12 + 23 + 32 + 22 + 1 + 8 = 98 bytes

Expected: SHA-256 of the 98 bytes. Sign with Ed25519.
```

## 25.6 Reset Request Signing Vectors (§23.5.2)

Domain: `"SCP-RESET-REQUEST-V1:"`

### Vector 8: Reset Request

```
Input:
  context_id:     "sync-test-context"
  requester_did:  "did:dht:z6MkSync"
  nonce:          0x0102030405060708091011121314151617181920212223242526272829303132 (32 bytes)
  timestamp:      1700000000

Canonical hash input:
  "SCP-RESET-REQUEST-V1:"                     (21 bytes)
  || BE32(17) || "sync-test-context"           (4 + 17 = 21 bytes)
  || BE32(16) || "did:dht:z6MkSync"           (4 + 16 = 20 bytes)
  || nonce                                     (32 bytes, fixed-length)
  || BE64(1700000000)                          (8 bytes)

Total: 21 + 21 + 20 + 32 + 8 = 102 bytes

Expected: SHA-256 of 102 bytes. Sign with Ed25519.
```

## 25.7 Envelope Padding Vectors (§9.10)

Bucket sizes: `[256, 1024, 4096, 16384, 65536, 262144]`.

Format: `[payload][zero padding][4-byte BE original length]`.

### Vector 9: Empty Payload

```
Input:  payload = [] (0 bytes)
Needed: 0 + 4 = 4 bytes
Bucket: 256 (smallest >= 4)

Output: 252 zero bytes || 0x00000000
Total:  256 bytes
```

### Vector 10: Small Payload

```
Input:  payload = 0x68656c6c6f ("hello", 5 bytes)
Needed: 5 + 4 = 9 bytes
Bucket: 256 (smallest >= 9)

Output: 0x68656c6c6f || 247 zero bytes || 0x00000005
Total:  256 bytes
```

### Vector 11: Exact Bucket Boundary

```
Input:  payload = 252 bytes of 0xAB
Needed: 252 + 4 = 256 bytes
Bucket: 256 (exact fit)

Output: 252 bytes of 0xAB || 0 zero bytes || 0x000000FC
Total:  256 bytes
```

### Vector 12: One Byte Over Bucket Boundary

```
Input:  payload = 253 bytes of 0xAB
Needed: 253 + 4 = 257 bytes
Bucket: 1024 (next bucket)

Output: 253 bytes of 0xAB || 767 zero bytes || 0x000000FD
Total:  1024 bytes
```

### Vector 13: Maximum Payload

```
Input:  payload = 262140 bytes of 0x42
Needed: 262140 + 4 = 262144 bytes
Bucket: 262144 (largest bucket, exact fit)

Output: 262140 bytes of 0x42 || 0 zero bytes || 0x0003FFFC
Total:  262144 bytes
```

### Vector 14: Payload Too Large (Error)

```
Input:  payload = 262141 bytes
Needed: 262141 + 4 = 262145 bytes
Bucket: none (exceeds largest bucket)

Expected: Error — PayloadTooLarge
```

## 25.8 Merkle Tree Vectors (§11, RFC 6962)

Construction: Leaf hash = `SHA-256(0x00 || data)`. Interior hash = `SHA-256(0x01 || left || right)`. Empty tree root = `SHA-256("")`.

### Vector 15: Empty Tree

```
Expected root: SHA-256("") = 0xe3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```

### Vector 16: Single Leaf

```
Input: event_data = 0x48656c6c6f ("Hello")

Leaf hash: SHA-256(0x00 || 0x48656c6c6f)
         = SHA-256(0x0048656c6c6f)
         = 0x...  (compute with reference implementation)

Root: leaf_hash (single leaf = root)
```

### Vector 17: Two Leaves

```
Input:
  event_1 = 0x4576656e7431 ("Event1")
  event_2 = 0x4576656e7432 ("Event2")

Leaf 1: SHA-256(0x00 || event_1)
Leaf 2: SHA-256(0x00 || event_2)

Root: SHA-256(0x01 || leaf_1 || leaf_2)
```

### Vector 18: Three Leaves (Unbalanced)

```
Input:
  event_1 = 0x41 ("A")
  event_2 = 0x42 ("B")
  event_3 = 0x43 ("C")

Leaf 1: SHA-256(0x00 || 0x41)
Leaf 2: SHA-256(0x00 || 0x42)
Leaf 3: SHA-256(0x00 || 0x43)

Interior 1: SHA-256(0x01 || leaf_1 || leaf_2)

Root: SHA-256(0x01 || interior_1 || leaf_3)
```

Note: RFC 6962 tree construction with 3 leaves produces an unbalanced tree where the third leaf is promoted to the right child of the root. Implementations MUST follow the RFC 6962 §2 construction algorithm for this case.

### Vector 19: Four Leaves (Balanced)

```
Input:
  event_1 = 0x41 ("A")
  event_2 = 0x42 ("B")
  event_3 = 0x43 ("C")
  event_4 = 0x44 ("D")

Leaf 1-4: SHA-256(0x00 || event_N)

Interior L: SHA-256(0x01 || leaf_1 || leaf_2)
Interior R: SHA-256(0x01 || leaf_3 || leaf_4)

Root: SHA-256(0x01 || interior_L || interior_R)
```

## 25.9 Key Continuity Fingerprint Vectors (§9.11)

Domain: `"SCP-KEY-CONTINUITY-V1:"`

### Vector 20: Full Fingerprint (All Three Keys Present)

```
Input:
  root_key (#0):    0xd75a980182b10ab7d54bfed3c964073a0ee172f3daa3f4a18446b0b8d183f8e3 (32 bytes)
  active_key (#active): 0x3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c (32 bytes)
  agent_key (#agent):   0xfc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025 (32 bytes)

Fingerprint: SHA-256("SCP-KEY-CONTINUITY-V1:" || root_key || active_key || agent_key)
```

### Vector 21: Fingerprint Without Agent Key

```
Input:
  root_key (#0):        (same as Vector 20)
  active_key (#active): (same as Vector 20)
  agent_key (#agent):   absent

Agent key sentinel: SHA-256("SCP-ABSENT-AGENT-KEY")
                  = 0x... (32 bytes)

Fingerprint: SHA-256("SCP-KEY-CONTINUITY-V1:" || root_key || active_key || sentinel)
```

The sentinel value MUST equal `SHA-256(b"SCP-ABSENT-AGENT-KEY")`. This is a domain-derived constant, not a magic number. Implementations MUST precompute this value and verify it matches their SHA-256 implementation.

## 25.10 Claim Validation Vectors (§12.3)

Domain: `"SCP-CLAIM-V1:"`

### Vector 22: Shadow Claim Hash

```
Input:
  shadow_id:    "shadow-alice-x-12345"
  claimant_did: "did:dht:z6MkClaim"
  context_id:   "bridge-test-context"
  timestamp:    1700000000

Canonical hash input:
  "SCP-CLAIM-V1:"                              (14 bytes)
  || BE32(20) || "shadow-alice-x-12345"         (4 + 20 = 24 bytes)
  || BE32(17) || "did:dht:z6MkClaim"           (4 + 17 = 21 bytes)
  || BE32(19) || "bridge-test-context"          (4 + 19 = 23 bytes)
  || BE64(1700000000)                           (8 bytes)

Total: 14 + 24 + 21 + 23 + 8 = 90 bytes
```

## 25.11 Proposal ID Vectors (§6.4)

Domain: `"SCP-PROPOSAL-V1:"`

### Vector 23: Governance Proposal ID

```
Input:
  context_id:   "gov-proposal-context"
  action_hash:  SHA-256 of serialized governance action (32 bytes)
  proposer_did: "did:dht:z6MkProposer"
  timestamp:    1700000000

Canonical hash input:
  "SCP-PROPOSAL-V1:"                           (17 bytes)
  || BE32(20) || "gov-proposal-context"         (4 + 20 = 24 bytes)
  || action_hash                                (32 bytes, fixed-length)
  || BE32(20) || "did:dht:z6MkProposer"        (4 + 20 = 24 bytes)
  || BE64(1700000000)                           (8 bytes)

Total: 17 + 24 + 32 + 24 + 8 = 105 bytes

Proposal ID: SHA-256 of the above 105 bytes.
```

## 25.12 HPKE Key Distribution Vectors

These vectors verify the domain separation between sender key and access key HPKE operations.

### Vector 24: Sender Key HPKE Info String

```
Input:
  context_id: "hpke-test-context"
  sender_did: "did:dht:z6MkSender"
  epoch:      42

Info string (concatenated bytes):
  "scp-sender-key-v1"                     (18 bytes)
  || "hpke-test-context"                   (17 bytes)
  || "did:dht:z6MkSender"                (18 bytes)
  || BE64(42)                              (8 bytes)

Total: 18 + 17 + 18 + 8 = 61 bytes
```

Note: the sender key info string uses flat concatenation (no length prefixes) for the context_id, sender_did, and epoch fields.

### Vector 25: Access Key HPKE Info String

```
Input:
  context_id: "hpke-test-context"
  member_did: "did:dht:z6MkMember"
  epoch:      42

Info string (concatenated bytes):
  "scp-access-key-v1"                     (18 bytes)
  || BE32(17) || "hpke-test-context"       (4 + 17 = 21 bytes)
  || BE32(18) || "did:dht:z6MkMember"     (4 + 18 = 22 bytes)
  || BE64(42)                              (8 bytes)

Total: 18 + 21 + 22 + 8 = 69 bytes
```

Note: the access key info string uses length-prefixed context_id and member_did fields (with 4-byte BE length), unlike the sender key info string. This structural difference ensures the two info strings can never collide even with adversarial inputs.

## 25.13 Attestation Signing Vectors (§9.5.2)

Domain: `"SCP-ATTESTATION-V1:"`

### Vector 26: Identity Link Attestation

```
Input:
  id:                "att-001"
  attestation_type:  IdentityLink (tag: 0x0001)
  issuer:            "did:dht:z6MkIssuer"
  subject:           "did:dht:z6MkSubject"
  claim:             '{"handle":"@alice","platform":"x"}' (compact JSON, no whitespace)
  evidence:          absent (use sentinel)
  issued_at:         1700000000
  expires_at:        0 (no expiry)

Canonical hash input:
  "SCP-ATTESTATION-V1:"                        (20 bytes)
  || BE32(7)  || "att-001"                      (4 + 7 = 11 bytes)
  || BE16(0x0001)                               (2 bytes — attestation type tag)
  || BE32(19) || "did:dht:z6MkIssuer"          (4 + 19 = 23 bytes)
  || BE32(20) || "did:dht:z6MkSubject"         (4 + 20 = 24 bytes)
  || BE32(34) || compact_json_bytes             (4 + 34 = 38 bytes)
  || SHA-256(0x00)                              (32 bytes — absent evidence sentinel)
  || BE64(1700000000)                           (8 bytes)
  || BE64(0)                                    (8 bytes — no expiry)

Total: 20 + 11 + 2 + 23 + 24 + 38 + 32 + 8 + 8 = 166 bytes
```

## 25.14 Verification Procedure

To verify an implementation against these test vectors:

1. **SHA-256 sanity check.** Compute `SHA-256("")` and verify it equals `0xe3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`. If this fails, the SHA-256 implementation is broken.

2. **Ed25519 sanity check.** Load the reference seed (§25.2) and derive the public key. Verify it matches the expected public key. If this fails, the Ed25519 implementation is broken.

3. **Encoding verification.** For each vector, construct the canonical byte sequence from the specified inputs using the encoding rules in §9.5.1. Compare the byte sequence length against the expected total. If lengths differ, the encoding is wrong.

4. **Hash verification.** Compute SHA-256 of each canonical byte sequence. Compare against the expected hash (run against the Rust reference implementation to obtain expected hashes).

5. **Signature verification.** For signed structures, sign the hash with the reference Ed25519 key and verify the signature. Then verify with Ed25519-verify. Both operations must succeed.

6. **Padding verification.** For each padding vector, construct the padded output and verify the total length matches the expected bucket size. Strip the padding and verify the original payload is recovered.

7. **Merkle tree verification.** Construct trees incrementally and verify the root hash matches after each append. Verify inclusion proofs for specific leaves.

## 25.15 Generating Reference Outputs

The Rust reference implementation can generate exact expected outputs for all vectors. Run the test vector generation tool:

```bash
cargo test -p scp-core --test test_vectors -- --nocapture
cargo test -p scp-event-log --test test_vectors -- --nocapture
```

The test vector generation test is defined in `crates/scp-core/tests/test_vectors.rs` and `crates/scp-event-log/tests/test_vectors.rs`. These tests print hex-encoded intermediate and final values for each vector defined above.

Independent implementations SHOULD run these tests against the Rust implementation to obtain the expected outputs, then embed those outputs in their own test suites.
