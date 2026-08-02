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
0xd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a
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
  0x000000006553f100
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
  version:           256 (0x0100 — SCP/1.0)
  message_type:      0x00 (Standard discriminator byte)
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
  || BE16(256)                                  (2 bytes — version, 0x01 0x00)
  || 0x00                                      (1 byte — message_type discriminator)
  || BE32(15) || "test-context-01"             (4 + 15 = 19 bytes)
  || BE32(16) || "did:dht:z6MkTest"           (4 + 16 = 20 bytes)
  || BE64(1)                                   (8 bytes — epoch)
  || BE64(0)                                   (8 bytes — generation_number)
  || BE64(0)                                   (8 bytes — sequence_number)
  || BE64(1700000000)                          (8 bytes — timestamp)
  || BE32(32) || payload_hash                  (4 + 32 = 36 bytes)
  || BE32(32) || SHA-256(0x00)                 (4 + 32 = 36 bytes — absent provenance)
  || BE32(7)  || "#active"                     (4 + 7 = 11 bytes)

Total: 22 + 2 + 1 + 19 + 20 + 8 + 8 + 8 + 8 + 36 + 36 + 11 = 179 bytes

Expected: SHA-256 of the above 179 bytes. Sign this hash with the reference Ed25519 key.
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
  proposal_id:  0x0102030405060708091011121314151617181920212223242526272829303132
  voter_did:    "did:dht:z6MkVoter"
  vote_type:    VoteType::Approve (JSON: "Approve", 9 bytes with quotes)
  timestamp:    1700000000

Canonical hash input (per §9.5.2 SignedVote):
  "SCP-VOTE-V1:"                                           (12 bytes)
  || proposal_id                                            (32 bytes, fixed-length)
  || BE32(17)  || "did:dht:z6MkVoter"                      (4 + 17 = 21 bytes)
  || BE32(9)   || "\"Approve\""                             (4 + 9 = 13 bytes, JSON)
  || BE64(1700000000)                                       (8 bytes)

Total: 12 + 32 + 21 + 13 + 8 = 86 bytes

Expected: SHA-256 of the 86 bytes. Sign with Ed25519.

Note: vote_type is serialized as compact JSON via serde_json (no whitespace).
VoteType::Approve → "\"Approve\"" (9 bytes). VoteType::Reject → "\"Reject\"" (8 bytes).
context_id is NOT included — the vote is bound to a context via the proposal_id hash.
```

## 25.6 Reset Request Signing Vectors (§23.5.2)

Domain: `"SCP-RESET-REQUEST-V1:"`

### Vector 8: Reset Request

```
Input:
  context_id:       "sync-test-context"
  member_did:       "did:dht:z6MkSync"
  last_known_epoch: 42
  reason:           "extended offline (8 days)" (ResetReason::ExtendedOffline { offline_duration_secs: 691200 } → Display string)
  nonce:            0x0102030405060708091011121314151617 (16 bytes)
  timestamp:        1700000000

Canonical hash input (per §23.5.2, field order from code):
  "SCP-RESET-REQUEST-V1:"                     (21 bytes)
  || BE32(17) || "sync-test-context"           (4 + 17 = 21 bytes)
  || BE32(16) || "did:dht:z6MkSync"           (4 + 16 = 20 bytes)
  || BE64(42)                                  (8 bytes — last_known_epoch)
  || BE32(25) || "extended offline (8 days)"   (4 + 25 = 29 bytes — reason)
  || nonce                                     (16 bytes, fixed-length, no length prefix)
  || BE64(1700000000)                          (8 bytes)

Total: 21 + 21 + 20 + 8 + 29 + 16 + 8 = 123 bytes

Expected: SHA-256 of 123 bytes. Sign with Ed25519.
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
         = 0x90b626dbb1e994c962942db2b3b16d97c63f679912a176bb96f4e308c213005b

Root: 0x90b626dbb1e994c962942db2b3b16d97c63f679912a176bb96f4e308c213005b
      (single leaf = root)
```

### Vector 17: Two Leaves

```
Input:
  event_1 = 0x4576656e7431 ("Event1")
  event_2 = 0x4576656e7432 ("Event2")

Leaf 1: SHA-256(0x00 || event_1) = 0x00d9ea40d70522a7d0aa41e2708afd5dc148a4dcc26011d598cbc28cdbde306f
Leaf 2: SHA-256(0x00 || event_2) = 0x7a7b6da2a00d46f75c01d0c5a33cb62e99caa7f0ebbd084a169a00874751e7a3

Root: SHA-256(0x01 || leaf_1 || leaf_2)
    = 0x9f7a0b4b3965ce3eb4dda7c7c56bc9f7fb2c627d5120692d4ff8e531920ebbf9
```

### Vector 18: Three Leaves (Unbalanced)

```
Input:
  event_1 = 0x41 ("A")
  event_2 = 0x42 ("B")
  event_3 = 0x43 ("C")

Leaf 1: SHA-256(0x00 || 0x41) = 0xc00b4d3c929cb5cc316691ed4636f634576f2c9b2954767234c5274e9dde185d
Leaf 2: SHA-256(0x00 || 0x42) = 0x87afe6086fe4571e37657e76281301f189c75ebae1d2eaafb56d578067a1d95e
Leaf 3: SHA-256(0x00 || 0x43) = 0xb563a5e69628743929eddec0ccfeb0745c39577e12a72e84915edd6633cb97f2

Interior 1: SHA-256(0x01 || leaf_1 || leaf_2) = 0xed692f01f7f6c46930d7ad8f9adad3f9f38b7379cf6a8d2f399a0ba1e914fe25

Root: SHA-256(0x01 || interior_1 || leaf_3)
    = 0x961d2e2be20f538ffdf56962a86d1bd165498f222684ee4c5e02c1e9f852adc5
```

Note: RFC 6962 tree construction with 3 leaves produces an unbalanced tree where the third leaf is promoted to the right child of the root. Implementations MUST follow the RFC 6962 §2 construction algorithm for this case.

### Vector 19: Four Leaves (Balanced)

```
Input:
  event_1 = 0x41 ("A")
  event_2 = 0x42 ("B")
  event_3 = 0x43 ("C")
  event_4 = 0x44 ("D")

Leaf 1: SHA-256(0x00 || 0x41) = 0xc00b4d3c929cb5cc316691ed4636f634576f2c9b2954767234c5274e9dde185d
Leaf 2: SHA-256(0x00 || 0x42) = 0x87afe6086fe4571e37657e76281301f189c75ebae1d2eaafb56d578067a1d95e
Leaf 3: SHA-256(0x00 || 0x43) = 0xb563a5e69628743929eddec0ccfeb0745c39577e12a72e84915edd6633cb97f2
Leaf 4: SHA-256(0x00 || 0x44) = 0x08a2afecc9feaef6737f055c177a56a363d28a78d7b259b8c5f66b32174f2e7d

Interior L: SHA-256(0x01 || leaf_1 || leaf_2) = 0xed692f01f7f6c46930d7ad8f9adad3f9f38b7379cf6a8d2f399a0ba1e914fe25
Interior R: SHA-256(0x01 || leaf_3 || leaf_4) = 0xd62c77efa9be96355bb8b07aefc985914377de5aec1287998c9a10f11cd8d075

Root: SHA-256(0x01 || interior_L || interior_R)
    = 0x5c8dc617d287a4297eb2bcb81b37644b5138e57ad461c657db152109e3fc9fca
```

Note: The vectors above use abstract `data` leaves to pin the RFC 6962 tree construction itself (leaf/interior domain prefixes, unbalanced promotion). The typed-leaf and checkpoint vectors below pin the *typed* leaf preimage and the checkpoint root.

### Vector 32: Typed-Leaf KAT (closed `EventType` taxonomy)

Each leaf is `SHA-256(0x00 || rmp_serde(Event))` over a canonical `scp_event_log::Event` whose `event_type` is one of the closed 77-variant `EventType` taxonomy (ADR-011 AC1 + typed-event unification Amendment + the cross-context-saga event model — Amendment §6 added `CrossContextOutletInvoked` (tag 76) and spec §6.2.4 added `CrossContextDivergenceMarker` (tag 77)). The events are signed with a fixed Ed25519 key (RFC 8032 deterministic signatures), so the full-event MessagePack bytes — and therefore the leaf hashes — are reproducible across runs and implementations. Structured payloads are encoded with positional `rmp_serde::to_vec` of the per-variant payload struct (`scp_event_log::payload`); the two opaque payloads carry the documented `key=value;…` bytes shown.

```
Signing key seed (32 bytes): 0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20
Actor DID (did:dht:z<z-base-32(pubkey)>):
  did:dht:zxg4icmwxh3kx1odasrjqtkcmw6eb9bj4h4k57i9yhqeozmer131y
Context ID: "ctx-kat"

Events (append order; each prev_hash = previous leaf hash, genesis = [0u8;32]):

  seq 0  AppBound                 ts 1700000000
         payload = rmp(AppBoundPayload{ app_did:"did:key:app", app_name:"Scheduler",
                       app_version:"1.0.0", capabilities:["outlet:call:*"] })
         leaf = 0xe0c0691d264ca38d086375a0274afb630e9bbb906f2e12e0112adf4d1b4fcd38

  seq 1  SpendApproved            ts 1700000001
         payload = rmp(SpendApprovedPayload{ spender:"did:key:agent", amount:5000,
                       purpose:"inference" })
         leaf = 0xf2f973a4df60ef87abcb99dd1f3afcd537037cbd1aae6297582c52be3bd8e695

  seq 2  TtlExtended              ts 1700000002
         payload = rmp(TtlExtendedPayload{ old_deadline_unix:1700000000,
                       new_deadline_unix:1800000000, proposal_id:[0xAB;32],
                       consenting_members:["did:key:a","did:key:b"] })
         leaf = 0xccdbb8dfa15a7abff3fbd0c08efe45e99d9fc4cb5f042f8f7db5f9e36e3fb0b0

  seq 3  RecoveryEpochAdvanced    ts 1700000003
         payload = rmp(RecoveryEpochAdvancedPayload{ old_epoch:7, new_epoch:8 })
         leaf = 0x7a1a91c33ddaa1a92c02f70a3f567f065bed48b578124a803c07dca2f9a47863

  seq 4  ContextTombstoned        ts 1700000004
         payload = rmp(ContextTombstonedPayload{ destination_id:"ctx-dest",
                       migration_proposal_id:[0xCD;32] })
         leaf = 0x3848718f23aefaba0e47743e72f5ce3bcc3254bc09b4cb38c3f5c263c9c4dd8d

  seq 5  ConsequenceTriggered     ts 1700000005
         payload = b"member_did=did:key:m;rule_index=2;trigger_kind=absence;action_type=suspend"
         leaf = 0x7ea6b6a020d94e0850cb84410af43e69ecd1c945223cbf478356d93503724507

  seq 6  CommitBroadcastSucceeded ts 1700000006
         payload = b"operation=join;attempts=3"
         leaf = 0x87e3cde25168f4af4328f010369313e28fde305dbc6f706be3392fdf7b8e7f3c

  seq 7  RoleAssigned             ts 1700000007
         payload = rmp(RoleAssignedPayload{ subject_did:"did:key:carol", role:"admin" })
         leaf = 0x9455cca66b6528ff7061d27b70ddab795ffff1e790fc1f797f22e21687e5f449

  seq 8  MemberJoined             ts 1700000008
         payload = rmp(MembershipChangePayload{ subject_did:"did:key:dave",
                       role_name:"member" })
         leaf = 0x28860f95688e8b0604db7349fd79deed13d3b9a10198a9623ea288a6eeea58f2

RFC 6962 tree::root over the 9 leaves:
  0x0c6f6a09ecdda29319880ca609060ec15aa8055ee9fbc85099e5f6e8b1ba4117
```

### Vector 33: Checkpoint Root KAT (§23.16.1)

A `ConsistencyCheckpoint` generated over the Vector 32 log MUST carry `merkle_root == tree::root` (the RFC 6962 root above), NOT a hash-chain head. The checkpoint canonical hash is `SHA-256("SCP-CHECKPOINT-V1:" || len(context_id) || context_id || len(sender_did) || sender_did || event_count_BE || merkle_root || epoch_tag || timestamp_BE)` where `epoch_tag = 0x01 || epoch_BE` for `Some(epoch)` (§23.16.1); the checkpoint signature is the actor's Ed25519 signature over that canonical hash. The canonical hash and signature depend on the checkpoint `timestamp` (wall clock) and so are not pinned here; the pinned, timestamp-independent invariant is:

```
checkpoint.merkle_root == tree::root (Vector 32)
  = 0x0c6f6a09ecdda29319880ca609060ec15aa8055ee9fbc85099e5f6e8b1ba4117
checkpoint.event_count == 9
```

Reference implementation and assertions: `crates/scp-event-log/tests/test_vectors.rs` (`vector_32_typed_leaf_and_checkpoint_kat`, `vector_33_checkpoint_root_equals_tree_root_kat`). Regenerate with `cargo test -p scp-event-log --test test_vectors -- --nocapture`.

### Vector 35: `DataProvenance` -> `provenance_hash` KAT (§24.3.3)

Pins the canonical provenance-hash encoding — `SHA-256(rmp_serde::to_vec(DataProvenance))`, positional MessagePack in struct-declaration field order (§24.3.3). This is the single encoding used by the signed BroadcastEnvelope `provenance_hash` (§5.14.5), the inner-envelope provenance hash, and the FFI event-log `ProvenanceAttached` / `ProvenanceReceived` payloads — so this hash is identical whether computed on a signed path or recorded in an event log. `payment_amount` (an `Amount`) encodes as a **native MessagePack integer** (`uint`) here: ADR-060's decimal-string wire form applies only to human-readable encodings (JSON); binary MessagePack keeps the native `u64`, so this KAT is byte-identical to its pre-ADR-060 value.

```
DataProvenance (all fields populated; field order per §24.2.1):
  source_context:     "ctx-kat-provenance"
  source_type:        Persistent
  counterparties:     ["did:key:alice", "did:key:bob"]
  purpose:            Some("kat")
  discovery_method:   SharedContext("ctx-shared")
  age:                300 s
  memory_scope:       Full
  chain_depth:        1
  chain_path:         Some(["ctx-hop-1"])
  payment_amount:     Some(Amount(1000))   # wire: native MessagePack uint 1000 (ADR-060 binary path)
  payment_adapter:    Some("stripe")
  payment_receipt_id: Some([0x11; 32])

provenance_hash = SHA-256(rmp_serde::to_vec(DataProvenance))
  = 0x12ea6cf53e3e2fe1c851214d6c9b1acf1338e835bcb91271c8bcdf04e553ce68

Absent-provenance sentinel (ADR-002):
  provenance_hash = SHA-256(0x00)
  = 0x6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d
```

Reference implementation and assertions: `crates/scp-protocol/src/crypto/sender_keys/broadcast.rs` (`vector_35_data_provenance_hash_kat`). Regenerate with `cargo test -p scp-protocol vector_35_data_provenance_hash_kat -- --nocapture`.

## 25.9 Key Continuity Fingerprint Vectors (§9.11)

Domain: `"SCP-KEY-CONTINUITY-V1:"`

### Vector 20: Full Fingerprint (All Three Keys Present)

```
Input:
  root_key (#0):    0xd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a (32 bytes)
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
  proposer_did: "did:dht:z6MkProposer"
  action_bytes: canonical JSON serialization of GovernanceAction (variable length)
                Example: 0xdeadbeef01020304 (8 bytes, placeholder)
  timestamp:    1700000000

Canonical hash input (per §9.5.2 GovernanceProposal ID):
  "SCP-PROPOSAL-V1:"                           (17 bytes)
  || BE32(20) || "gov-proposal-context"         (4 + 20 = 24 bytes)
  || BE32(20) || "did:dht:z6MkProposer"        (4 + 20 = 24 bytes)
  || BE32(8)  || action_bytes                   (4 + 8 = 12 bytes, length-prefixed)
  || BE64(1700000000)                           (8 bytes)

Total: 17 + 24 + 24 + 12 + 8 = 85 bytes

Proposal ID: SHA-256 of the above 85 bytes.

Note: action_bytes is the canonical JSON serialization of the GovernanceAction
enum (compact, no whitespace — equivalent to serde_json::to_vec in Rust or
json.dumps(separators=(',', ':')) in Python). JSON is used rather than
MessagePack for cross-implementation determinism (see §9.5.2). Field order
matches code: context_id, proposer_did, action_bytes, timestamp. The
action_bytes placeholder above should be replaced with actual JSON output
when generating §25.18 hex outputs.
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
  || BE32(17) || "hpke-test-context"       (4 + 17 = 21 bytes)
  || BE32(18) || "did:dht:z6MkSender"     (4 + 18 = 22 bytes)
  || BE64(42)                              (8 bytes)

Total: 18 + 21 + 22 + 8 = 69 bytes
```

Note: the sender key info string uses 4-byte BE length-prefixed context_id and sender_did fields, matching the access key info string structure. Length prefixes prevent boundary-shift collisions with adversarial inputs.

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

Note: Both the sender key and access key info strings use 4-byte BE length-prefixed context_id and DID fields. Domain separation between the two is provided by distinct prefix strings (`"scp-sender-key-v1"` vs `"scp-access-key-v1"`), which ensures the two info strings can never collide even with adversarial inputs.

## 25.13 Attestation Signing Vectors (§3.5.2, §9.5.1)

Domain: `"SCP-IDENTITY-LINK-ATTESTATION-V1:"`

### Vector 26: Identity Link Attestation Signature

The signing payload uses the canonical hash construction from §9.5.1 with domain separator `"SCP-IDENTITY-LINK-ATTESTATION-V1:"`. Fields are serialized in a fixed order. Sub-structures (`claim`, `evidence`, `revocation_status`) are serialized as MessagePack (`rmp_serde::to_vec_named`, sorted-key encoding) and included as variable-length byte fields.

Note: this is the *signature* construction (used by `verify_signature`). The *attestation ID* uses a different domain separator (`"SCP-ATTESTATION-ID-V1:"`) and different fields — see `compute_id()` in `attestation.rs`.

```
Input:
  id:                "att-001"
  attestation_type:  "identity_link"
  issuer:            "did:dht:z6MkIssuer"
  subject:           "did:dht:z6MkIssuer"  (same as issuer for self-attestation)
  issued_at:         1700000000
  expires_at:        absent (no expiry — use absent sentinel)
  claim:             AttestationClaim { platform: "google.com", platform_handle: "alice@gmail.com",
                       platform_id: None, link_type: "self_attestation" }
  evidence:          AttestationEvidence { method: "oauth", proof: "{\"provider\":\"google.com\",\"subject_id\":\"12345\",\"verified_at\":1700000000}",
                       verified_at: 1700000000, verifier_did: None }
  revocation_status: RevocationStatus::Active

Canonical hash input:
  "SCP-IDENTITY-LINK-ATTESTATION-V1:"         (33 bytes, no length prefix)
  || BE32(7)   || "att-001"                    (4 + 7 = 11 bytes — id)
  || BE32(13)  || "identity_link"              (4 + 13 = 17 bytes — attestation_type)
  || BE32(18)  || "did:dht:z6MkIssuer"        (4 + 18 = 22 bytes — issuer)
  || BE32(18)  || "did:dht:z6MkIssuer"        (4 + 18 = 22 bytes — subject)
  || BE64(1700000000)                          (8 bytes — issued_at)
  || SHA-256(0x00)                              (32 bytes, raw — no length prefix — absent expires_at sentinel)
  || BE32(N_c) || msgpack(claim)               (4 + N_c bytes — claim as MessagePack)
  || BE32(N_e) || msgpack(evidence)            (4 + N_e bytes — evidence as MessagePack)
  || BE32(N_r) || msgpack(revocation_status)    (4 + N_r bytes — revocation_status as MessagePack)

The exact byte count depends on the MessagePack encoding of the sub-structures.
Compute the expected SHA-256 hash using the Rust reference implementation.
```

## 25.14 Pseudonymization Vectors (§24.3.5)

Domain: `"SCP-PSEUDONYM-V1:"`

### Vector 27: DID Pseudonymization

`pseudonymize_did` derives a context-scoped pseudonym from a DID, context ID, and a pseudonym key using the canonical hash construction.

```
Input:
  pseudonym_key:  0x746573742d70736575646f6e796d2d6b6579 ("test-pseudonym-key", 18 bytes)
  context_id:     "test-context-01"
  did:            "did:dht:z6MkTest"

Canonical hash input:
  "SCP-PSEUDONYM-V1:"                           (17 bytes, no length prefix)
  || BE32(18)  || "test-pseudonym-key"           (4 + 18 = 22 bytes)
  || BE32(15)  || "test-context-01"              (4 + 15 = 19 bytes)
  || BE32(16)  || "did:dht:z6MkTest"            (4 + 16 = 20 bytes)

Total: 17 + 22 + 19 + 20 = 78 bytes

Expected SHA-256:
  0xa1545542cd8834cc0599f07e5c730dee3005c01097dde63abf906110f1a8e28d

Result: did:pseudo:a1545542cd8834cc0599f07e5c730dee3005c01097dde63abf906110f1a8e28d
```

The pseudonym is deterministic: the same (key, context, DID) triple always produces the same pseudonym. Different keys or contexts produce unrelated pseudonyms for the same DID.

## 25.15 Outlet Interface Offer ID Vectors (§6.2.0.1)

Domain: `"SCP-OFFER-ID-V1:"`

### Vector 28: Outlet Interface Offer ID

`compute_offer_id` derives a deterministic 32-byte offer ID from the source context, outlet ID, target context, and timestamp.

```
Input:
  source_context:  "source-ctx-01"
  outlet_id:         "outlet-abc123"
  target_context:  "target-ctx-02"
  timestamp:       1700000000

Canonical hash input:
  "SCP-OFFER-ID-V1:"                            (16 bytes, no length prefix)
  || BE32(13) || "source-ctx-01"                 (4 + 13 = 17 bytes)
  || BE32(13) || "outlet-abc123"                 (4 + 13 = 17 bytes)
  || BE32(13) || "target-ctx-02"                 (4 + 13 = 17 bytes)
  || BE64(1700000000)                            (8 bytes)

Total: 16 + 17 + 17 + 17 + 8 = 75 bytes

Expected SHA-256:
  0xea9ce09b497405e8c160c8d0d57067c726092866f6d1ec541e8e6081a5328733
```

## 25.16 Attestation ID Vectors (§3.5.2)

Domain: `"SCP-ATTESTATION-ID-V1:"`

### Vector 29: Attestation ID Computation

`compute_id` derives a deterministic attestation ID from the issuer DID, platform, platform handle, and issuance timestamp. Note: this uses a *different* domain separator from the attestation *signature* construction in §25.13.

```
Input:
  issuer:           "did:dht:z6MkIssuer"
  platform:         "google.com"
  platform_handle:  "alice@gmail.com"
  issued_at:        1700000000

Canonical hash input:
  "SCP-ATTESTATION-ID-V1:"                      (22 bytes, no length prefix)
  || BE32(18)  || "did:dht:z6MkIssuer"          (4 + 18 = 22 bytes)
  || BE32(10)  || "google.com"                   (4 + 10 = 14 bytes)
  || BE32(15)  || "alice@gmail.com"              (4 + 15 = 19 bytes)
  || BE64(1700000000)                            (8 bytes)

Total: 22 + 22 + 14 + 19 + 8 = 85 bytes

Expected SHA-256:
  0x97eedd3adfbd0dc8ee901c9f2baf57c151ddf81e3cf49e7ae3b559f4cd2176e0
```

## 25.17 Verification Procedure

To verify an implementation against these test vectors:

1. **SHA-256 sanity check.** Compute `SHA-256("")` and verify it equals `0xe3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`. If this fails, the SHA-256 implementation is broken.

2. **Ed25519 sanity check.** Load the reference seed (§25.2) and derive the public key. Verify it matches the expected public key. If this fails, the Ed25519 implementation is broken.

3. **Encoding verification.** For each vector, construct the canonical byte sequence from the specified inputs using the encoding rules in §9.5.1. Compare the byte sequence length against the expected total. If lengths differ, the encoding is wrong.

4. **Hash verification.** Compute SHA-256 of each canonical byte sequence. Compare against the expected hash (run against the Rust reference implementation to obtain expected hashes).

5. **Signature verification.** For signed structures, sign the hash with the reference Ed25519 key and verify the signature. Then verify with Ed25519-verify. Both operations must succeed.

6. **Padding verification.** For each padding vector, construct the padded output and verify the total length matches the expected bucket size. Strip the padding and verify the original payload is recovered.

7. **Merkle tree verification.** Construct trees incrementally and verify the root hash matches after each append. Verify inclusion proofs for specific leaves.

## 25.18 Generating Reference Outputs

The Rust reference implementation can generate exact expected outputs for all vectors. Run the test vector generation tool:

```bash
cargo test -p scp-runtime --test test_vectors -- --nocapture
cargo test -p scp-event-log --test test_vectors -- --nocapture
```

The test vector generation test is defined in `crates/scp-runtime/tests/test_vectors.rs` and `crates/scp-event-log/tests/test_vectors.rs`. These tests print hex-encoded intermediate and final values for each vector defined above.

Independent implementations SHOULD run these tests against the Rust implementation to obtain the expected outputs, then embed those outputs in their own test suites.

## 25.19 Per-Context Pseudonym Derivation Vectors (§9.10.4, §9.10.4.A, §9.10.4.1)

These vectors pin the **software-custody** per-context pseudonym keypair derivation. Software custody is cross-platform deterministic: every SDK (Rust, Swift, Kotlin, TypeScript) MUST reproduce the exact public-key bytes below for the same identity seed, `context_id`, and epoch. **Hardware custody** (Secure Enclave, Android Keystore TEE, HSM) is device-local by design — the `pseudonym_secret` is derived inside the hardware boundary from a non-exportable key, so hardware pseudonyms are NOT expected to match these values and are NOT cross-device deterministic (§9.10.4.A).

Derivation recipe (all implementations agree):

```
pseudonym_secret = HKDF-SHA256(
  ikm  = ed25519_private_seed_bytes (32 bytes),
  salt = "scp-pseudonym-secret-v1",
  info = "",                                   (empty)
  len  = 32
)

# v1 (static):
context_seed_v1 = HMAC-SHA256(pseudonym_secret, context_id || "scp-pseudonym")

# v2 (rotatable, BE64 epoch):
context_seed_v2 = HMAC-SHA256(pseudonym_secret, context_id || BE64(epoch) || "scp-pseudonym-v2")

pseudonym_public_key = Ed25519_keygen(context_seed[0..32]).public_key
```

The 32-byte `context_seed` is interpreted as an **RFC-8032 Ed25519 seed** (fed to the standard key expansion: SHA-512 of the seed, then clamp the lower half to form the scalar), NOT as a pre-clamped scalar. The HMAC `data` is plain concatenation with NO length prefixes — these are fixed-format internal inputs, and the domain-separator suffix (`"scp-pseudonym"` vs `"scp-pseudonym-v2"`) plus the fixed 8-byte BE64 epoch make the encoding unambiguous.

### Vector 30: Pseudonym Derivation — identity seed 0x01×32

```
Input:
  ed25519_private_seed:  0x0101010101010101010101010101010101010101010101010101010101010101
  context_id:            "context-alpha"  (0x636f6e746578742d616c706861, 13 bytes)
  epoch (v2):            1

Expected pseudonym_secret:
  0x27456a3dd24ed5813b2645f0ee001f57760c49b9117b93c8fa98e4129d36a643

Expected v1 pseudonym public key:
  0xfddc04882a48aa39888f6dbec622f9c5aa6f06b2e40820a69a2e0e89b5f09ac2

Expected v2 pseudonym public key (epoch = 1):
  0x43e50a947c4b2be44f871e309c7edc64afaf4207b9a589c9b01f61c01158090f
```

### Vector 31: Pseudonym Derivation — identity seed 0x9d,0x01..0x1f

```
Input:
  ed25519_private_seed:  0x9d0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
  context_id:            "context-alpha"  (0x636f6e746578742d616c706861, 13 bytes)
  epoch (v2):            1

Expected pseudonym_secret:
  0xa586191a1ab6cd3efe45697b3510ee1edac8c54a7f27863546b6e0333e20d690

Expected v1 pseudonym public key:
  0xff6e2e909a008318f97bb2c26c1d787ceb9aa2996f746766335e10ba7e2213cc

Expected v2 pseudonym public key (epoch = 1):
  0xedd47319719e2350d1db9488e0189f2405267d7dc243489cfd9aa6f3ac3fc639
```

These vectors are mechanically enforced by the Rust known-answer test `derive_pseudonym_keypair_known_answer_vectors` in `crates/scp-crypto/src/pseudonym.rs` (the wasm-safe home of the derivation, ADR-057 Option A), and cross-checked for native/`wasm32` byte-parity by `pseudonym_derivation_matches_golden_vectors` in `crates/scp-client-wasm/tests/pseudonym_derivation_cross_target_kat.rs`.

### Vector 36: `PseudonymAnnouncement` wire format + classifier decisions (§9.10.4)

These vectors pin the on-the-wire **pseudonym announcement** — the `MessagePack` payload a member broadcasts on the shared bootstrap channel to teach peers their per-context routing ID — and the pure §9.10.4 accept/reject classifier that both the native orchestrator and the in-browser client run over an inbound announcement. Because the announcement type and the classifier live in the wasm-safe `scp-protocol::context::pseudonym` module (ADR-057 T-1), native and `wasm32` MUST produce byte-identical wire bytes and identical accept/reject decisions.

**Wire format.** `PseudonymAnnouncement` is serialized with `rmp_serde::to_vec_named` — a name-keyed `MessagePack` map with three fields, in declaration order: `tag` (string), `member_did` (string), `pseudonym` (32-byte `serde_bytes` binary). No `usize`, no float, no map-iteration order, so a fixed value re-encodes deterministically and target-independently.

```
Input:
  tag:        "\0scp:pseudonym-announce:v1"   (PSEUDONYM_ANNOUNCEMENT_TAG, 26 bytes, NUL-prefixed)
  member_did: "did:dht:z6MkPseudonymKatFixtureMemberAAAAAAAAAAAAAA"  (51 bytes)
  pseudonym:  0x42 × 32

MessagePack layout:
  0x83                                   fixmap, 3 entries
  0xa3 "tag"                             key
  0xba <26 bytes>  "\0scp:pseudonym-announce:v1"   str8 value (NUL-prefixed magic tag)
  0xaa "member_did"                      key
  0xd9 0x33 <51 bytes> "did:dht:z6Mk…AA"  str8 value
  0xa9 "pseudonym"                        key
  0xc4 0x20 <32 bytes> 0x42×32            bin8 value (serde_bytes)

Expected bytes (hex, single continuous string):
  83a3746167ba007363703a70736575646f6e796d2d616e6e6f756e63653a7631aa6d656d6265725f646964d9336469643a6468743a7a364d6b50736575646f6e796d4b6174466978747572654d656d6265724141414141414141414141414141a970736575646f6e796dc4204242424242424242424242424242424242424242424242424242424242424242
```

**Classifier decisions.** `classify_pseudonym_announcement(plaintext, sender_did, context_id, registry)` returns a `PseudonymAnnouncementDecision` over the four-step §9.10.4 validation. The reject `reason` strings are stable `&'static str`s and are part of this vector — a change to any is wire-observable:

| Case | `sender_did` | payload / registry | Decision | `reason` |
|------|--------------|--------------------|----------|----------|
| ordinary app data | member | `b"hello world"` / `Some({})` | `NotAnnouncement` | — |
| legitimate announce | member | golden announce (member, `0x42×32`) / `Some({})` | `Accept { member, 0x42×32 }` | — |
| sender mismatch | member | announce claims `other` / `Some({})` | `Rejected` (carries `claimed_did = other`) | `pseudonym announcement member_did does not match sender` |
| reserved value | member | announce with `[0;32]` **or** `context_routing_id(ctx)` **or** `broadcast_routing_id(ctx)` / `Some({})` | `Rejected` | `pseudonym announcement uses a reserved routing ID` |
| broadcast context | member | golden announce / `None` | `Rejected` | `pseudonym announcement received on broadcast context` |
| cross-DID collision | member | golden announce / `Some({other → 0x42×32})` | `Rejected` | `pseudonym announcement collides with another member's routing ID` |

where `member = "did:dht:z6MkPseudonymKatFixtureMemberAAAAAAAAAAAAAA"`, `other = "did:dht:z6MkPseudonymKatFixtureOtherBBBBBBBBBBBBBBB"`, and `ctx = "ctx-adr057-pseudonym-kat"`.

This vector is mechanically enforced on BOTH native and `wasm32` by `pseudonym_wire_and_classifier_match_golden_vectors` in `crates/scp-client-wasm/tests/pseudonym_cross_target_kat.rs` (native `#[test]` + `#[wasm_bindgen_test]`, run under `wasm-pack test --node`): `native == golden` and `wasm == golden` together prove `native == wasm` (ADR-057 T-1 / Prerequisite 5). The pure predicate + classifier unit tests also live in `crates/scp-protocol/src/context/pseudonym.rs`.

## 25.20 Trust Attestation Signing Vectors (§7.4.1, §9.5.2)

Domain: `"SCP-ATTESTATION-V1:"`

### Vector 34: Trust Attestation Signature

The signing payload for the common attestation envelope (`trust::Attestation`, §7.4.1) uses the canonical hash construction from §9.5.1 with domain separator `"SCP-ATTESTATION-V1:"` and the §9.5.2 Attestation field order. The `claim` field is serialized as RFC 8785 (JCS) canonical JSON — sorted keys, no whitespace — so a claim constructed with any key insertion order yields identical bytes. Per the §9.5.2 I-JSON constraint, claim numeric values MUST be within |n| ≤ 2^53 (this vector's claim uses `42`). `evidence` and `revocation_status` are serialized as MessagePack (`rmp_serde::to_vec_named`). The renewal fields (`renewal_interval`, `renewed_at`) are excluded from the signed preimage (§9.5.2) and do not appear below.

Note: this is the *signature* construction for the generic trust attestation envelope. It is distinct from the IdentityLinkAttestation signature (§25.13, domain `"SCP-IDENTITY-LINK-ATTESTATION-V1:"`, MessagePack claim) and from the attestation *ID* computation (§25.16, domain `"SCP-ATTESTATION-ID-V1:"`).

```
Input:
  id:                "att-trust-001"
  attestation_type:  Endorsement  (type tag 4 per attestation_type_tag())
  issuer:            "did:dht:z6MkIssuer"
  subject:           "did:dht:z6MkSubject"
  claim:             {"level": "gold", "score": 42}
                       JCS: {"level":"gold","score":42}  (27 bytes)
  evidence:          absent (use absent sentinel)
  issued_at:         1700000000
  expires_at:        absent (no expiry — use absent sentinel)
  revocation_status: RevocationStatus::Active
                       msgpack: 0xa6 "Active"  (7 bytes)

Canonical hash input:
  "SCP-ATTESTATION-V1:"                          (19 bytes, no length prefix)
  || BE32(13) || "att-trust-001"                  (4 + 13 = 17 bytes — id)
  || BE16(4)                                      (2 bytes — attestation_type tag)
  || BE32(18) || "did:dht:z6MkIssuer"            (4 + 18 = 22 bytes — issuer)
  || BE32(19) || "did:dht:z6MkSubject"           (4 + 19 = 23 bytes — subject)
  || BE32(27) || {"level":"gold","score":42}      (4 + 27 = 31 bytes — claim as JCS)
  || SHA-256(0x00)                                 (32 bytes, raw — no length prefix — absent evidence sentinel)
  || BE64(1700000000)                              (8 bytes — issued_at)
  || SHA-256(0x00)                                 (32 bytes, raw — no length prefix — absent expires_at sentinel)
  || BE32(7)  || msgpack(Active)                  (4 + 7 = 11 bytes — revocation_status as MessagePack)

Total: 19 + 17 + 2 + 22 + 23 + 31 + 32 + 8 + 32 + 11 = 197 bytes

Expected SHA-256 (= canonical_attestation_bytes output):
  0x6d07c76821a2ae4dd830ca117aa9fd8e30232cca72459a4d129432f56d87a08c
```

The Ed25519 signature is computed over the 32-byte canonical hash. Sign with the reference key (§25.2) and verify per §25.17 step 5; Ed25519 is deterministic, so the reference implementation reproduces the same signature bytes on every run.

This vector is mechanically enforced by `vector_34_trust_attestation_signature` in `crates/scp-runtime/tests/test_vectors.rs`, which pins the expected hash, reconstructs the preimage byte-for-byte, and verifies the signed attestation through the production `verify_attestation` path.

## 25.21 Outlet Streaming Conformance Vectors (§5.4.5)

Progressive-output (streaming) outlet invocation (§5.4.5, ADR-061) is exercised by a shared set of 7 scenario vectors that pin the observable behaviour of a stream end-to-end: the ordered chunk transcript, the credit-grant timing, the cancellation billing boundary, and the terminal status recorded in the `OutletInvokedEvent` (`StreamTerminalStatus`, §5.4.5 "Event log shape"). Unlike the cryptographic known-answer vectors above, these are **behavioural** vectors — they carry payload *descriptors*, not literal signed wire bytes. Every chunk signature (`OutletStreamChunk.sig`) and every `caveats_binding` is **recomputed** by the harness at replay time under the §25.2 reference operator key (RFC 8032 §7.1 Test Vector 1, seed `0x9d61…7f60`), because the operator signature preimage (`SCP-OUTLET-CHUNK-SIG-V1:`, §5.4.5) binds the per-stream `request_id`, `sequence`, and `caveats_binding`, none of which are fixed until the stream is opened.

The canonical vector file is `tests/conformance/vectors/outlet_stream_vectors.json` (top-level `{version, vectors:[7]}`). The four language SDKs consume the **same** JSON so the drain-side chunk decoding, credit granting, cancellation, and terminal-status mapping match the Rust core byte-for-byte across bindings.

### Scenario matrix

| Vector | Outlet kind | Scenario | `expected_end_status` | `expected_error_code` |
|--------|-------------|----------|-----------------------|-----------------------|
| `non_streaming` | action | Degenerate two-chunk stream (`Data` then `End`); the §5.4.5 "Non-streaming invocation" case | `Ok` | — |
| `multi_chunk` | query | Ten `Data` chunks with one interleaved non-billable `Progress` chunk (§5.4.5 `ChunkPayload::Progress`), followed by `End`; ordered multi-chunk transcript (§5.4.5 ordering). The `Progress` chunk is forwarded, consumes a sequence slot (the monotonicity cursor advances across it), and is NOT billed | `Ok` | — |
| `cancellation` | query | Signed `OutletCancel` mid-stream; cancel-ack terminal pins the billing boundary (§5.4.5 "Cancellation and billing boundary") | `Cancelled` | — |
| `error_terminal` | action | Executor emits `Data(seq0)` then a terminal `Error{terminal:true}` at seq1 (§5.4.5 billing: a billable `Data` chunk PRECEDES the terminal here, so escrow is settled for that one delivered chunk — this vector is NOT the "terminal `Error` before any `Data`" full-refund case) | `Error` | `SCP-OUTLET-6130` |
| `error_recoverable` | query | Non-terminal `Error{terminal:false}` is informational; the stream continues and closes `Ok` (§5.4.5 `ChunkPayload::Error` semantics) | `Ok` | — |
| `sequence_gap` | query | Receiver observes a missing `sequence` (0,1,3 — 2 dropped) and MUST cancel (§5.4.5 "Ordering and gaps") | `Cancelled` | `SCP-OUTLET-6131` |
| `credit_stall` | query | Credit window of 1, no grant → the executor stalls past `stream_credit_stall_secs` → framework credit-stall terminal (§5.4.5 "Credit-based backpressure"). NOTE: this vector exercises the credit-**stall** terminal (`SCP-OUTLET-6133` / `execution.credit-stall`) ONLY. The distinct cumulative-ceiling `execution.credit-exhausted` terminal (`SCP-OUTLET-6131`, window driven to its `max_calls` cap) is a SEPARATE condition NOT covered by this 7-vector set (future coverage follow-up) — do not read `credit_stall` as covering it | `Error` | `SCP-OUTLET-6133` |

All rows cite §5.4.5. Sequences are strictly monotonic from `0`; the producer pump renumbers emitted chunks under its own outer cursor, so the runtime-driven replays assert monotonic-from-zero rather than the vector's literal sequence field (which is authoritative only for the receiver-side gap check).

### Two error-code traps (do not conflate)

- **`credit_stall` → `SCP-OUTLET-6133` / `execution.credit-stall`**, NOT `6131`. The round-4 cancel-ack-vs-credit-stall split gave the credit-stall terminal its own dedicated code (`CODE_EXECUTION_CREDIT_STALL`, `crates/scp-protocol/src/context/outlets/error_codes.rs`). A window that reaches zero and is not replenished within `stream_credit_stall_secs` is `CreditStall` (`TerminateReason::CreditStall`), distinct from the cumulative-ceiling `execution.credit-exhausted` (6131). The vector was renamed to `credit_stall` (its earlier name used "exhaustion") so the name matches the terminal it actually drives — an "exhaustion" name misread the retry-policy / error class; the distinct `execution.credit-exhausted` (6131) terminal is not exercised by this set.
- **`sequence_gap` → `SCP-OUTLET-6131` / `execution.stream-gap`** (consolidated). `SLUG_EXECUTION_STREAM_GAP = "execution.stream-gap"` shares `CODE_EXECUTION_CREDIT` (`SCP-OUTLET-6131`) with `execution.credit-exhausted` and `execution.stream-cap-exhausted` — three Execution-class resource/ordering slugs under one code.

### Replay locations

The vectors are replayed at every layer so a regression at any tier is caught:

| Layer | Location | Coverage |
|-------|----------|----------|
| Runtime (direct) | `crates/scp-testing/tests/integration/outlet_stream_conformance.rs` | All 7 through the raw `open_stream_session` dispatch pump; `sequence_gap` via the receiver tracker; `credit_stall` via a real 1-second credit-stall timer. |
| Runtime (through-open-path) | `crates/scp-testing/tests/integration/outlet_stream_vectors_through_open_path.rs` | All 7 through the real `Supervisor::open_outlet_stream` control path with context/outlet/member/UCAN registration and runtime-derived-cursor cancel signing. |
| PyO3 bridge | `crates/scp-ffi/tests/outlet_stream_vectors_real.rs` | `non_streaming`, `cancellation`, `error_terminal` driven live through `outlet_stream_open`→`poll_next`→`grant_credit`/`cancel`; `sequence_gap` via the receiver tracker over a signed transcript; `multi_chunk`/`error_recoverable`/`credit_stall` are covered at the runtime layer (the PyO3 handler seam is single-shot per `BridgeStreamExecutor`). |
| NAPI bridge | `crates/scp-ffi/napi/src/outlet_stream/tests.rs` (`#[cfg(test)]` `mod streaming_vectors` + `mod streaming_vectors_live`) | Same live/runtime split, driven through the NAPI `_on` exports. Internal module, not an external `tests/` target: the napi addon is a `cdylib` whose runtime symbols only link under `#[cfg(test)]`, so an external test target cannot resolve them. `mod streaming_vectors` carries all-7-vector wire integrity + `sequence_gap`; `mod streaming_vectors_live` drives `non_streaming`/`cancellation`/`error_terminal` live. |
| UniFFI bridge | `crates/scp-ffi/uniffi/tests/outlet_stream_vectors_real.rs` (external, all-7 wire integrity + `sequence_gap`) + `crates/scp-ffi/uniffi/src/outlet_stream/tests.rs` (`#[cfg(test)]` `mod streaming_vectors_live`) | The external target verifies wire integrity for all 7; the live open→poll of `non_streaming`/`cancellation`/`error_terminal` needs crate-internal setup seams (`Scp.inner` is `pub(crate)`), so it lives in the internal module. |
| WASM (pure wrappers) | `crates/scp-client-wasm/src/lib.rs` (`#[cfg(test)]`) | For each of the 7 vectors, every chunk is signed under the §25.2 operator key and asserted `true` under `outletStreamVerifyChunkSignature` (and `false` under a wrong key); `outletStreamComputeCaveatsBinding` matches the core helper. WASM has no tokio runtime (ADR-034/057), so it verifies **wire integrity**, not terminal status. |
| SDK drains | Python / TypeScript / Swift / Kotlin SDK smoke tests | Land via the SDK half of SCP-OUT-039, consuming this same vector JSON. |

Because the PyO3/NAPI/UniFFI handler-registration seam produces a single aggregate value (`BridgeStreamExecutor`, `crates/scp-ffi/src/outlet_stream.rs`), the three multi-emission vectors — `multi_chunk` (10 `Data` chunks plus an interleaved `Progress` chunk), `error_recoverable` (`Data` → non-terminal `Error` → `Data`), and `credit_stall` (needs a second billable chunk to park past the window) — cannot be produced by a single-shot handler and are therefore **not faked** at the bridge layer; they are covered at the runtime tiers (every real-bridge test documents this deferral explicitly). `error_terminal` is NOT deferred — a single-shot handler that returns `Err` maps to the framework terminal `Error` `SCP-OUTLET-6130`, so it is driven live at all three bridges. The receiver-side `sequence_gap` check is a Rust-layer receiver *test oracle* at every runtime/bridge tier because a lossless same-context pump cannot produce a gap; the runtime pump is the *producer* in the same-context case and therefore has no gap of its own to detect. The **permanent, transport-agnostic receiver check** is the SDK `InvocationHandle` drain (§5.4.5 "Ordering and gaps" — the receiver locus is the invoker-side SDK framework): it is dormant over the lossless same-context transport and becomes load-bearing when chunks are consumed over a lossy cross-context / relayed transport. The tracker's emitted code is the consolidated `SCP-OUTLET-6131` (`execution.stream-gap`), a test-local reimplementation of the §5.4.5 receiver rule. When slice-3 introduces a cross-context reassembly layer, any additional authoritative gap-detection there is **reconciled with the SDK-drain check as defense-in-depth** (mirroring the revocation dual-locus), NOT as a replacement for it — the SDK-drain receiver check remains the transport-agnostic invariant.

## 25.22 Cross-Context Streaming-Saga Conformance Vectors (§6.2.4 / §6.2.5)

The **transactional-streaming** corner of the outlet taxonomy (ADR-061 *streaming saga*; §6.2.4 cross-context outlet invocation saga; §6.2.5 outlet invocation modes) is exercised by a set of **6 scenario vectors** that pin the observable artifacts of a cross-context stream: the sealed RFC-6962 `stream_manifest_hash` (§5.4.5 chunk manifest; a fixed 32 bytes regardless of stream length, ADR-061), the self-verifying `SCP-XCTX-STREAM-RECEIPT-V1` receipt over that root (`crates/scp-protocol/src/context/outlets/cross_context_saga.rs`), the atomic dual event-log join, the receive-side gap terminal, and the aggregate-schema terminal. This complements the same-context §25.21 set (`§5.4.5` progressive output), which does not exercise the saga's seal/receipt/dual-log artifacts.

The canonical vector file is `tests/conformance/vectors/outlet_streaming_saga_vectors.json` (top-level `{version, vectors:[6]}`, each entry a `{name, spec}` envelope). Every chunk signature and every `caveats_binding` is **recomputed** at replay time under the §25.2 reference operator key (RFC 8032 §7.1 Test Vector 1, seed `0x9d61…7f60`); the receipt round-trip KAT signs under that same §25.2 seed so its preimage and Ed25519 signature are byte-exact and checked in.

### Scenario matrix

| Vector | Scenario | Pinned artifact | Terminal / code |
|--------|----------|-----------------|-----------------|
| `stream_receipt_kat` | Fixed 9-field `SCP-XCTX-STREAM-RECEIPT-V1` input → byte-exact preimage + deterministic Ed25519 signature; `verify()` accepts, every single-field mutation rejects | `expected_preimage_hex` (32 B), `expected_signature_hex` (64 B) | — |
| `seal_phase` | A sealed chunk sequence reaches Committed at seal-close with a non-zero manifest root and a verifiable receipt (§6.2.5) | `expected_stream_manifest_hash` | `Ok` |
| `xctx_10_chunk` | A 10-chunk A→B stream; the target `OutletInvoked` and caller `CrossContextOutletInvoked` dual-log leaves carry the IDENTICAL root (§6.2.4 dual event-log) | `expected_stream_manifest_hash` + `dual_log_identity` | `Ok` |
| `truncated_close` | A mid-stream crash after chunk 5 of 10 seals the durable PREFIX; the receipt is over the truncated (prefix) root, distinct from the full-stream root; escrow settles at the prefix `billed_count`; the outlet exec fn is invoked exactly once (§17.16.4 recovery) | `expected_prefix_manifest_hash` (≠ `expected_full_manifest_hash`), `billed_count`, `exec_invocations` | `Ok` (truncated) |
| `receive_side_drain_lossy` | A lossy A-leg dropping a chunk (delivered sequences 0,1,3) is caught by the invoker-side SDK-drain gap detector (SCP-OUT-037, §5.4.5:515), NOT a runtime bridge detector (SCP-OUT-045) | `expected_caveats_binding` | `Cancelled` / `SCP-OUTLET-6131` |
| `aggregate_schema_violation` | An `End.aggregate` violating the outlet's `aggregate_schema` is an Output-class schema violation | `aggregate_schema` + `violating_aggregate` | `Error` / `SCP-OUTLET-6140` |

### Layered coverage and replay locations (Class-S boundary, honest scope)

The checked-in vectors + the `scp-testing` harness VERIFY the declared cryptographic artifacts through **public protocol primitives only** — `CrossContextOutletStreamReceipt::{signing_preimage, verify}`, `compute_chunk_manifest_root`, dual-hash structural identity, the §25.21 `ReceiverSequenceTracker` oracle, and `validate_value_against_schema` → error-code mapping. Driving a LIVE resident-actor streaming saga to `Committed` (seal-close) or a truncated close requires seeding resident-actor `StreamCapture` state, reachable only via `spawn_actor_with_state`, which is `pub(in crate::context)` — the deliberate **Class-S actor-state isolation boundary** (a security property, NOT a test shortcut; the SAME boundary SCP-OUT-047's AC8 documents). The external `scp-testing` crate does not breach it; the live substance is proven runtime-side.

| Scenario | Verified in-vector (harness, public primitives) | Live substance proven runtime-side |
|----------|--------------------------------------------------|------------------------------------|
| `stream_receipt_kat` | `outlet_streaming_saga_conformance.rs` `stream_receipt_kat_is_byte_exact_and_tamper_evident` — byte-exact preimage + signature, `verify()` accept, 9 single-field mutation rejects | fully covered in-vector (pure known-answer) |
| `receive_side_drain_lossy` | `receive_side_drain_lossy_fires_stream_gap_6131` — per-chunk-signed gapped transcript → `ReceiverSequenceTracker` fires `SCP-OUTLET-6131` | fully covered in-vector (the SDK-drain receiver rule is the permanent invariant, §25.21) |
| `aggregate_schema_violation` | `aggregate_schema_violation_maps_to_6140` — `validate_value_against_schema` Err → `CODE_OUTPUT_VIOLATION` (a conforming aggregate passes) | fully covered in-vector (pure validator) |
| `seal_phase` | `seal_phase_manifest_root_and_receipt_verify` — `compute_chunk_manifest_root` == pinned non-zero hash; reconstructed receipt `verify()`s | the drive to `Committed` at seal-close: `xctx_streaming_saga_paid_drive_ac1_ac3_ac5_ac6` (`crates/scp-runtime/src/context/supervisor/supervisor.rs`) |
| `xctx_10_chunk` | `xctx_10_chunk_dual_log_carries_identical_root` — root == pinned hash; receipt `verify()`s; both dual-log leaf payloads byte-identical | the live 10-chunk drive recording BOTH event logs over the same root: `xctx_streaming_saga_paid_drive_ac1_ac3_ac5_ac6` |
| `truncated_close` | `truncated_close_prefix_root_and_receipt_verify` — prefix root == pinned non-zero hash (≠ full root); prefix `billed_count` == prefix Data count; receipt over the prefix root `verify()`s | the escrow settlement at the prefix `billed_count` + exactly-once outlet-exec (no re-invoke on replayed close): `xctx_streaming_saga_truncated_close_ac7`. (The live drive's `billed_count` may fall in a small range around the pinned prefix count depending on which durable `StreamCaptureAppend` landed before the crash window; the vector pins the deterministic prefix.) |

All rows cite §6.2.4 / §6.2.5 / ADR-061. The harness reuses the SCP-OUT-039 shared oracle (`crates/scp-testing/tests/integration/outlet_stream_vectors_common.rs`) for the §25.2 key, chunk signing, `compute_caveats_binding`, and the `ReceiverSequenceTracker`, so the two streaming vector sets stay byte-consistent.
