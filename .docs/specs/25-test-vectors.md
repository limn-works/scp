# 25. Cryptographic Test Vectors

## 25.1 Purpose

This section provides known-answer test vectors for all cryptographic constructions in the SCP protocol. An independent implementer MUST use these vectors to verify that their implementation produces correct output before attempting interoperability testing. Each vector specifies inputs, intermediate values (where applicable), and expected outputs in hexadecimal.

All byte values are lowercase hex with `0x` prefix unless otherwise noted. All integers are big-endian unless otherwise noted.

**The generator.** `scripts/gen-test-vectors-p256.py` produces every keyed byte this section prints, **except the bytes of §25.21, §25.22 and §25.24**, which come from the checked-in JSON fixtures those three sections name and which no script in this tree regenerates. Run it from the repository root:

```bash
python3.12 scripts/gen-test-vectors-p256.py
```

The script uses nothing outside the Python standard library. It implements P-256 field and point arithmetic, RFC 6979 deterministic ECDSA with SHA-256, low-`s` normalization, SEC1 point encoding, HKDF-SHA256, HMAC-SHA256, unpadded base64url, the §9.5.1 canonical hash construction, the RFC 6962 Merkle construction, the WebAuthn `authenticatorData` and `clientDataJSON` synthesis §25.26 documents, and the MessagePack subset the SCP structures serializes into. Before it prints a byte it checks itself against four published known-answer tests: `SHA-256("")`, the RFC 6979 Appendix A.2.5 P-256 nonce and signature, RFC 5869 Appendix A.1 for HKDF-SHA256, and this section's own curve-independent `DataProvenance` hash (Vector 35). It computes every public key twice, by two scalar multiplications that share no arithmetic, and a third time through the `cryptography` package when that package imports; a mismatch raises before anything prints.

**What a signature covers.** Every SCP signature in this section is an ECDSA signature over a 32-byte canonical hash, so the ECDSA message digest **is** that canonical hash and no second SHA-256 is applied to it. The vectors run RFC 6979 with `h1` set to that same 32-byte digest. §9.5 fixes RFC 6979 with SHA-256 for a software signer and does not state which value plays `h1` for a prehashed digest; these vectors take the digest itself, and an implementation that hashes the digest a second time reproduces none of the signature bytes below.

## 25.2 Reference Key Material

Two P-256 keypairs carry every signature in this section. Both derive from a stated 32-byte seed, so an implementer reproduces the private scalar and the public key from the seed alone.

**Seed-to-scalar rule.** A seed becomes a private scalar by the extra-random-bits method of FIPS 186-5 Appendix A.2.1, which §9.10.4 of the security-model spec states in full: expand the seed to 48 bytes with HKDF-Expand-SHA256 under a label, read those bytes as a big-endian integer, reduce modulo `n − 1`, and add one. The label for these two fixtures is the ASCII string `"SCP-TEST-VECTOR-KEY-V1"`. It labels a test fixture and names no protocol object, so §9.18.2 of the security-model spec registers no separator for it.

**Reference seed (32 bytes):**
```
0x9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60
```

**Reference private scalar (32 bytes):**
```
0x6f0712104c3f61ba04526a822836d3f4a13be12e09a8c3c7586b2da0c795998b
```

**Reference public key, 33-byte SEC1 compressed point (§9.5):**
```
0x033b1cac23f45cf1cdfdf0b32f8f777b99166c1b69649c2295b1517883d47f3027
```

**Reference public key, 65-byte SEC1 uncompressed point (RFC 9420 §5.1.2 and RFC 9180 §7.1 encodings):**
```
0x043b1cac23f45cf1cdfdf0b32f8f777b99166c1b69649c2295b1517883d47f3027471695574e78728df503a0c21dd1da9f7b77252d8398527a1b2177c78224f051
```

**Secondary seed (32 bytes, for two-party vectors):**
```
0x4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb
```

**Secondary private scalar (32 bytes):**
```
0x0fed5549df222a5cf0b537e423fbd60875c6fb2b334b381a0c0a6c89eae9ac6a
```

**Secondary public key, 33-byte SEC1 compressed point:**
```
0x0223702a648232f2d00713de9289753c2fbd4c4efa7e1e33905e3723a412b20aea
```

**Secondary public key, 65-byte SEC1 uncompressed point:**
```
0x0423702a648232f2d00713de9289753c2fbd4c4efa7e1e33905e3723a412b20aead0992a08064d996d9268dc511c7430f3a4e614871d4a888b52a8dbecb56d6da6
```

**Tertiary seed (32 bytes, for three-key vectors):**
```
0xc5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7
```

**Tertiary private scalar (32 bytes):**
```
0x55118deda48fbb900efe9692e644dc5971211c8d3dfcc50f117d842c6056be4f
```

**Tertiary public key, 33-byte SEC1 compressed point:**
```
0x026fc6523b7b1e22ff3fbce8740cfbb7cbc816501864bf40f683db69c860d1a670
```

**Tertiary public key, 65-byte SEC1 uncompressed point:**
```
0x046fc6523b7b1e22ff3fbce8740cfbb7cbc816501864bf40f683db69c860d1a6700192d543b6d5d6b3d7990f4463d2f0692bcb7bdbaf3b1ee8f4465dd888323df0
```

The three seeds are the byte strings RFC 8032 Section 7.1 gives as its first three test-vector seeds. §25.25 is the only section that uses the tertiary key. SCP superseded Ed25519 on 2026-09-10 (§9.5 of the security-model spec), so the seeds no longer name an Ed25519 keypair and are retained only so this corpus's provenance stays legible across the change. An implementation that cannot reproduce any one of the three public keys from its seed has a broken P-256 implementation, a broken HKDF, or a broken reading of the seed-to-scalar rule, and MUST NOT proceed with SCP interoperability testing.

**The same P-256 keys serve ECDH for HPKE.** SCP's HPKE suite is DHKEM(P-256, HKDF-SHA256) (§9.5), so a key-agreement key on this curve is a P-256 key like any other. RFC 9180 §7.1 fixes its encoding as the 65-byte uncompressed SEC1 point, printed above beside the 33-byte compressed form that §9.5 fixes for signature verification. No separate key material stands between the two roles, and no birational map does either.

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

Preimage (hex, 179 bytes):
  5343502d494e4e45522d454e56454c4f50452d56313a0100000000000f746573742d636f6e746578742d3031000000106469643a6468743a7a364d6b54657374000000000000000100000000000000000000000000000000000000006553f10000000020b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9000000206e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d0000000723616374697665

Canonical hash SHA-256(preimage) (32 bytes):
  0xe3fe1d0310b5eb15de46f22afa1995735253ce07b9960acfbdc50901c4c04c32

RFC 6979 signature over the canonical hash, reference key, 64-byte raw r || s:
  0x1e71a01bc73549f3aafd387df0b1efc866fcb008a0af0aba0c714178aab23a073b2448f046955ba5baa61a2d41ff800dee49d03d8671586b0b710282d857e05f

Verification vector:
  public key: 0x033b1cac23f45cf1cdfdf0b32f8f777b99166c1b69649c2295b1517883d47f3027
  digest:     the canonical hash above
  signature:  the 64 bytes above
  verdict:    accept
```

Implementations MUST produce identical canonical hash bytes. The SHA-256 of those bytes is the value the P-256 key signs.

**What an implementation matches.** A software signer that derives its nonce under RFC 6979 with SHA-256 (§9.5) reproduces the signature bytes above exactly, because RFC 6979 removes the nonce as a source of variation. A hardware signer — a Secure Enclave, a passkey authenticator, an HSM, a smartcard — draws a random nonce and therefore produces different `r` and `s` for this same preimage on every call. §9.5 states that such a signer conforms. A conformance check for a hardware signer therefore verifies its signature against the signer's public key and MUST NOT compare bytes against the value printed here. The verification vector above is the check that binds both signer classes.

### Vector 6: InnerEnvelope with Provenance

Same as Vector 5 but with `provenance_hash` present:

```
Input changes:
  provenance_hash: 0xabcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789

Canonical hash input changes:
  Position 8 (provenance_hash): BE32(32) || 0xabcdef...
  (replaces the SHA-256(0x00) sentinel)

Preimage (hex, 179 bytes):
  5343502d494e4e45522d454e56454c4f50452d56313a0100000000000f746573742d636f6e746578742d3031000000106469643a6468743a7a364d6b54657374000000000000000100000000000000000000000000000000000000006553f10000000020b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde900000020abcdef0123456789abcdef0123456789abcdef0123456789abcdef01234567890000000723616374697665

Canonical hash SHA-256(preimage) (32 bytes):
  0x225dae627d1d452ef405c454f5360f3963aa0f7b0aa1e25fcd079c28899a0bac

RFC 6979 signature over the canonical hash, reference key, 64-byte raw r || s:
  0xd367c6babbc1c5f428a28b791b4315d6e48a03364b17d93a5539bc5481eac746226afabede6626a059cbbbf9de31a30d6137b9532cde98fdea84fe1c4ebfd77c

Verification vector:
  public key: 0x033b1cac23f45cf1cdfdf0b32f8f777b99166c1b69649c2295b1517883d47f3027
  digest:     the canonical hash above
  signature:  the 64 bytes above
  verdict:    accept
```

## 25.5 Vote Signing Vectors (§6.4 [no such section])

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

Preimage (hex, 86 bytes):
  5343502d564f54452d56313a0102030405060708091011121314151617181920212223242526272829303132000000116469643a6468743a7a364d6b566f7465720000000922417070726f766522000000006553f100

Canonical hash SHA-256(preimage) (32 bytes):
  0x30a5f33bc023a00c7f2f3deafe20a9097d5e3ab1ac5d3155fecc7196f61a9713

RFC 6979 signature over the canonical hash, reference key, 64-byte raw r || s:
  0x6f6892475ccb7bbeba00223ff906ff4cd9a5d92fa6551b8944561c4f2d36fe296d4a622332cee863aee40b52e38e61a3e88b2fb0ae683770026a23a580777050

Verification vector:
  public key: 0x033b1cac23f45cf1cdfdf0b32f8f777b99166c1b69649c2295b1517883d47f3027
  digest:     the canonical hash above
  signature:  the 64 bytes above
  verdict:    accept

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
  nonce:            0x01020304050607080910111213141516 (16 bytes)
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

Preimage (hex, 123 bytes):
  5343502d52455345542d524551554553542d56313a0000001173796e632d746573742d636f6e74657874000000106469643a6468743a7a364d6b53796e63000000000000002a00000019657874656e646564206f66666c696e6520283820646179732901020304050607080910111213141516000000006553f100

Canonical hash SHA-256(preimage) (32 bytes):
  0xbb28e647cd66832e23e8fa9570f3e05f938bab15c10b03488109d84c75eacefd

RFC 6979 signature over the canonical hash, reference key, 64-byte raw r || s:
  0x31489688422b7e418b1dcd66353b9f689ccdb2128470c57dd2295d59ed28d93f0206cb8496630ae70fd3a04e79ad65d4f53a9582dbd3d31a45a68550d420022c

Verification vector:
  public key: 0x033b1cac23f45cf1cdfdf0b32f8f777b99166c1b69649c2295b1517883d47f3027
  digest:     the canonical hash above
  signature:  the 64 bytes above
  verdict:    accept
```

The `nonce` above carries 16 bytes, which is the width the field list states and the width the 123-byte total assumes. Before 2026-09-10 this vector printed a 17-byte literal beside the label "16 bytes", so an implementer following §25.17 step 3 would have measured 124 bytes against a stated 123 and read a correct encoding as wrong.

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

Each leaf is `SHA-256(0x00 || rmp_serde(Event))` over a canonical `scp_event_log::Event` whose `event_type` is one of the closed 77-variant `EventType` taxonomy (ADR-011 AC1 + typed-event unification Amendment + the cross-context-saga event model — Amendment §6 added `CrossContextOutletInvoked` (tag 76) and spec §6.2.4 added `CrossContextDivergenceMarker` (tag 77)). The events are signed with the §25.2 reference P-256 key under RFC 6979, so the full-event MessagePack bytes — and therefore the leaf hashes — are reproducible across runs and implementations. Structured payloads are encoded with positional `rmp_serde::to_vec` of the per-variant payload struct (`scp_event_log::payload`); the two opaque payloads carry the documented `key=value;…` bytes shown.

**MessagePack layout of a signed `Event`.** The seven fields serialize positionally, so an implementer reproduces the bytes without reading Rust: a 7-element array holding the `EventType` variant **name** as a string, the actor DID as a string, the timestamp as an unsigned integer, the sequence as an unsigned integer, the one-element `EventPayload` array holding the payload as a MessagePack binary, the 32-byte `prev_hash` as a 32-element array of unsigned integers, and the 64-byte signature as a MessagePack binary. The signed value is `SHA-256("SCP-EVENT-V1:" || BE16(event_type_tag) || BE32(len(actor_did)) || actor_did || BE64(timestamp) || BE64(sequence) || BE32(len(payload)) || payload || prev_hash)`.

**The actor DID is an opaque UTF-8 string here.** §9.7.4.2 R13 of the security-model spec fixes the identifier as `SHA-256("SCP-KEL-ID-V1:" || inception_signed_preimage)` and states that a later revision fixes the inception preimage's field order and the identifier's textual form. This vector therefore states its actor DID as a literal fixture string rather than deriving one from the signing key, and pins the typed-leaf preimage and the RFC 6962 root, which is what it exists to pin.

```
Signing key: the §25.2 reference P-256 key (seed 0x9d61b1…7f60)
Actor DID:   "did:dht:z6MkEventLogKat"
Context ID:  "ctx-kat"

Events (append order; each prev_hash = previous leaf hash, genesis = [0u8;32]):

  seq 0  AppBound                 ts 1700000000  tag 74
         payload = rmp(AppBoundPayload{ app_did:"did:key:app", app_name:"Scheduler",
                       app_version:"1.0.0", capabilities:["outlet:call:*"] })
         leaf = 0x1af68450213d8e584be72c8f573aa4ca10dd3a9b9fc465857a751a33a3aaca63

  seq 1  SpendApproved            ts 1700000001  tag 65
         payload = rmp(SpendApprovedPayload{ spender:"did:key:agent", amount:5000,
                       purpose:"inference" })
         leaf = 0xb8654f49e00c329133f562666670b341ac2928d6e260ef7d31385dc60bb79fa1

  seq 2  TtlExtended              ts 1700000002  tag 62
         payload = rmp(TtlExtendedPayload{ old_deadline_unix:1700000000,
                       new_deadline_unix:1800000000, proposal_id:[0xAB;32],
                       consenting_members:["did:key:a","did:key:b"] })
         leaf = 0xe0c4fe4394c6befeaabfd65f829e31402c0cb570da352250204da7b8dd4d2026

  seq 3  RecoveryEpochAdvanced    ts 1700000003  tag 73
         payload = rmp(RecoveryEpochAdvancedPayload{ old_epoch:7, new_epoch:8 })
         leaf = 0x7601b953cbdb0facc67e8d14534d2d867db1d3294ef1ebaf794c36b8387fb5e2

  seq 4  ContextTombstoned        ts 1700000004  tag 60
         payload = rmp(ContextTombstonedPayload{ destination_id:"ctx-dest",
                       migration_proposal_id:[0xCD;32] })
         leaf = 0x3e4c5cb18baeed919c6285ee855f32b465ad8403484d90c5e4e7439e830ef341

  seq 5  ConsequenceTriggered     ts 1700000005  tag 67
         payload = b"member_did=did:key:m;rule_index=2;trigger_kind=absence;action_type=suspend"
         leaf = 0x65a70c03fe2c73563338f2ff54d2407babebede0f04feace8396a6d41165ee06

  seq 6  CommitBroadcastSucceeded ts 1700000006  tag 71
         payload = b"operation=join;attempts=3"
         leaf = 0x1e317e79707690629bd4e34ad028e7afd8b0c1a6d1ecf8c274c8050938522108

  seq 7  RoleAssigned             ts 1700000007  tag 6
         payload = rmp(RoleAssignedPayload{ subject_did:"did:key:carol", role:"admin" })
         leaf = 0xd2fcaa28f52acc06a9baa5dfcbd85cef2e56742eb03a9ec5fc3baf9b7af50426

  seq 8  MemberJoined             ts 1700000008  tag 4
         payload = rmp(MembershipChangePayload{ subject_did:"did:key:dave",
                       role_name:"member" })
         leaf = 0x6bcce39bd338159ac4044e4189d632a606067594c1390e7042cfc4e7b6a7f6e6

RFC 6962 tree::root over the 9 leaves:
  0x0696f04e8cb022c6c33b9fd066bb975da568898588119f94d1846939e3c83c40
```

**Only a software signer reproduces these leaves.** Each leaf hashes the event's signature bytes, so the leaf hash inherits the RFC 6979 determinism of the signature. A hardware signer produces a different signature for the same canonical hash and therefore a different leaf and a different root, which is correct behavior and not a conformance failure. A conformance check for such a signer verifies each event's signature against the signer's public key and compares the root only against a tree it built from its own events.

### Vector 33: Checkpoint Root KAT (§23.16.1)

A `ConsistencyCheckpoint` generated over the Vector 32 log MUST carry `merkle_root == tree::root` (the RFC 6962 root above), NOT a hash-chain head. The checkpoint canonical hash is `SHA-256("SCP-CHECKPOINT-V1:" || len(context_id) || context_id || len(sender_did) || sender_did || event_count_BE || merkle_root || epoch_tag || timestamp_BE)` where `epoch_tag = 0x01 || epoch_BE` for `Some(epoch)` (§23.16.1); the checkpoint signature is the actor's P-256 signature over that canonical hash. The canonical hash and signature depend on the checkpoint `timestamp` (wall clock) and so are not pinned here; the pinned, timestamp-independent invariant is:

```
checkpoint.merkle_root == tree::root (Vector 32)
  = 0x0696f04e8cb022c6c33b9fd066bb975da568898588119f94d1846939e3c83c40
checkpoint.event_count == 9
```

Regenerate both vectors with `python3.12 scripts/gen-test-vectors-p256.py` (§25.1). `crates/scp-event-log/tests/test_vectors.rs` asserts the pre-2026-09-10 Ed25519 values in `vector_32_typed_leaf_and_checkpoint_kat` and `vector_33_checkpoint_root_equals_tree_root_kat`; §25.18 states which artifact governs while that port is outstanding.

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

§9.11 states one construction and it is two-party: the fingerprint covers both parties' 32-byte identifiers, both root sets under the §9.5.1 repeated-field rule, and both `#active` keys. Every key in it is a 33-byte SEC1 compressed P-256 point (§9.5), which is fixed-length and therefore carries no length prefix.

```
fingerprint = SHA-256("SCP-KEY-CONTINUITY-V1:"
                      || id_lo || BE32(count(lo_root)) || lo_root_members || lo_active
                      || id_hi || BE32(count(hi_root)) || hi_root_members || hi_active)
```

`id_lo` is whichever of the two identifiers is lower under unsigned byte comparison, and its whole block comes first.

**The identifiers below are stated constants.** §9.7.4.2 R13 makes an identifier `SHA-256("SCP-KEL-ID-V1:" || inception_signed_preimage)` and states that a later revision of that section fixes the inception preimage's field order. Until it does, no vector can derive an identifier, so these vectors state each one as the SHA-256 of a fixed ASCII string. The fingerprint construction consumes 32 opaque bytes, so a stated constant exercises it exactly as a derived identifier would.

### Vector 20: Two-Party Fingerprint

Party A carries a two-member root set; party B carries a one-member root set, which exercises §9.11's rule that a one-member set still carries its `BE32(1)` count.

```
Input:
  identifier_a = SHA-256("SCP test vector identifier A")
               = 0xbcdcea594dbb12037950ee2d0f356300ea8e37d9dfb01b87c6249033e871095e
  identifier_b = SHA-256("SCP test vector identifier B")
               = 0xf30cbaf928e7bd22a3d2f4aecf6573120a0cdddd8600aa685f61e7f72c78e856

  a_root_set (2 members, in the order the key state carries):
    0x02542c432f5a8f756764e2f18c8125e5338e61ba1540057f8c6ee666b07c7aa8d1
    0x02b945d8e097faded7a70e6c18134caf2a9521bc2b05af0becdf99adc9212789d0
  a_active_key:
    0x02e264c93973b59b7699221aff574dcde04a79347335c4f9c4a643c7525cd9b975

  b_root_set (1 member):
    0x02c4ed969c4a9e294576355bbeb14270e54b51bf6f00b6d1b587676fd0865ee8a8
  b_active_key:
    0x027a3f3aad1b66ab82d3d67a2e3af15f89f304c4b6369accc5715dda72d2800512

Ordering: identifier_a < identifier_b, so party A's block comes first.

Preimage (hex, 259 bytes):
  5343502d4b45592d434f4e54494e554954592d56313abcdcea594dbb12037950ee2d0f356300ea8e37d9dfb01b87c6249033e871095e0000000202542c432f5a8f756764e2f18c8125e5338e61ba1540057f8c6ee666b07c7aa8d102b945d8e097faded7a70e6c18134caf2a9521bc2b05af0becdf99adc9212789d002e264c93973b59b7699221aff574dcde04a79347335c4f9c4a643c7525cd9b975f30cbaf928e7bd22a3d2f4aecf6573120a0cdddd8600aa685f61e7f72c78e8560000000102c4ed969c4a9e294576355bbeb14270e54b51bf6f00b6d1b587676fd0865ee8a8027a3f3aad1b66ab82d3d67a2e3af15f89f304c4b6369accc5715dda72d2800512

Total: 22 + 32 + 4 + 33 + 33 + 33 + 32 + 4 + 33 + 33 = 259 bytes

Fingerprint:
  0xc6cdaa8eeb6d04798e308ee0f7c1ecdc29874f8f4411c7c9df921539ad975466
```

Every key in the preimage is one of the five 33-byte points above, so substituting any single key changes the fingerprint. The five keypairs derive from the seeds `0x41×32`, `0x42×32`, `0x43×32`, `0x44×32`, and `0x45×32` under the §25.2 seed-to-scalar rule and its `"SCP-TEST-VECTOR-KEY-V1"` label.

### Vector 38: Fingerprint Ordering Is Argument-Order Independent

Two parties compute the fingerprint from opposite sides, so each supplies its own block first. §9.11 orders the blocks by the identifiers, never by who is computing, so both parties MUST reach the same value.

```
Input: Vector 20's inputs, with party B supplied first and party A second.

Preimage: byte-identical to Vector 20's 259-byte preimage.

Fingerprint:
  0xc6cdaa8eeb6d04798e308ee0f7c1ecdc29874f8f4411c7c9df921539ad975466
```

An implementation that concatenates the caller's own block first computes two different values for one honest pair and raises §9.11's maximum-severity MITM alert against an honest counterparty.

**Vector 21 was deleted on 2026-09-10.** It pinned a fingerprint over `#0`, `#active`, and an absent `#agent` key standing in as `SHA-256("SCP-ABSENT-AGENT-KEY")`. §9.11's construction carries no `#agent` term and no sentinel of any kind, so the vector covered a construction the spec no longer states. **[Superseded 2026-09-10 — a human identity's key state names one operational role, `#active`, and names no agent key (`09-security-model.md` §9.1 invariant 1); an agent is a separate identity whose establishment events the human's log anchors, and that delegation model is unspecified as of 2026-09-10 (`00-open-questions.md`).]**

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
  "SCP-CLAIM-V1:"                              (13 bytes)
  || BE32(20) || "shadow-alice-x-12345"         (4 + 20 = 24 bytes)
  || BE32(17) || "did:dht:z6MkClaim"           (4 + 17 = 21 bytes)
  || BE32(19) || "bridge-test-context"          (4 + 19 = 23 bytes)
  || BE64(1700000000)                           (8 bytes)

Total: 13 + 24 + 21 + 23 + 8 = 89 bytes

Expected SHA-256:
  0xf3469482bb1d91d18e7167d21666fad9476b0559625257589075df6ebca23642
```

The domain separator is 13 ASCII bytes and the preimage is 89. Before 2026-09-10 this vector stated 14 and 90, so an implementer following §25.17 step 3 would have read a correct encoding as wrong. The claim hash is new here: §25.17 step 4 tells an implementer to compare each canonical byte sequence's SHA-256 against an expected hash, and this vector carried none.

## 25.11 Proposal ID Vectors (§6.4 [no such section])

Domain: `"SCP-PROPOSAL-V1:"`

### Vector 23: Governance Proposal ID

```
Input:
  context_id:   "gov-proposal-context"
  proposer_did: "did:dht:z6MkProposer"
  action_bytes: {"AddMember":{"did":"did:dht:z6MkNewMember","role":"member"}}
                (61 bytes — the compact JSON of GovernanceAction::AddMember)
                hex: 0x7b224164644d656d626572223a7b22646964223a226469643a6468743a7a364d6b4e65774d656d626572222c22726f6c65223a226d656d626572227d7d
  timestamp:    1700000000

Canonical hash input (per §9.5.2 GovernanceProposal ID):
  "SCP-PROPOSAL-V1:"                           (16 bytes)
  || BE32(20) || "gov-proposal-context"         (4 + 20 = 24 bytes)
  || BE32(20) || "did:dht:z6MkProposer"        (4 + 20 = 24 bytes)
  || BE32(61) || action_bytes                   (4 + 61 = 65 bytes, length-prefixed)
  || BE64(1700000000)                           (8 bytes)

Total: 16 + 24 + 24 + 65 + 8 = 137 bytes

Preimage (hex, 137 bytes):
  5343502d50524f504f53414c2d56313a00000014676f762d70726f706f73616c2d636f6e74657874000000146469643a6468743a7a364d6b50726f706f7365720000003d7b224164644d656d626572223a7b22646964223a226469643a6468743a7a364d6b4e65774d656d626572222c22726f6c65223a226d656d626572227d7d000000006553f100

Proposal ID:
  0xcd423e7b6272c9cfd25a6e636922bab94cc3c8df48a50bc649bb856cb5f25d65

Note: action_bytes is the canonical JSON serialization of the GovernanceAction
enum (compact, no whitespace — equivalent to serde_json::to_vec in Rust or
json.dumps(separators=(',', ':')) in Python). JSON is used rather than
MessagePack for cross-implementation determinism (see §9.5.2). Field order
matches code: context_id, proposer_did, action_bytes, timestamp.
```

Before 2026-09-10 this vector carried `0xdeadbeef01020304` labelled a placeholder, together with a note telling a later author to substitute real JSON. Those eight bytes are not a JSON serialization of any `GovernanceAction`, so the vector pinned no proposal ID and its stated 85-byte total measured a preimage no conforming producer builds. The `AddMember` action above is a real variant of the enum §9.5.2 names, stated literally, so this vector now derives from its own printed inputs. The domain separator is 16 ASCII bytes, not the 17 the vector previously stated.

## 25.12 HPKE Key Distribution Vectors

These vectors verify the domain separation between sender key and access key HPKE operations.

### Vector 24: Sender Key HPKE Info String

```
Input:
  context_id: "hpke-test-context"
  sender_did: "did:dht:z6MkSender"
  epoch:      42

Info string (concatenated bytes):
  "scp-sender-key-v1"                     (17 bytes)
  || BE32(17) || "hpke-test-context"       (4 + 17 = 21 bytes)
  || BE32(18) || "did:dht:z6MkSender"     (4 + 18 = 22 bytes)
  || BE64(42)                              (8 bytes)

Total: 17 + 21 + 22 + 8 = 68 bytes

Info string (hex, 68 bytes):
  0x7363702d73656e6465722d6b65792d76310000001168706b652d746573742d636f6e74657874000000126469643a6468743a7a364d6b53656e646572000000000000002a
```

Note: the sender key info string uses 4-byte BE length-prefixed context_id and sender_did fields, matching the access key info string structure. Length prefixes prevent boundary-shift collisions with adversarial inputs.

### Vector 25: Access Key HPKE Info String

```
Input:
  context_id: "hpke-test-context"
  member_did: "did:dht:z6MkMember"
  epoch:      42

Info string (concatenated bytes):
  "scp-access-key-v1"                     (17 bytes)
  || BE32(17) || "hpke-test-context"       (4 + 17 = 21 bytes)
  || BE32(18) || "did:dht:z6MkMember"     (4 + 18 = 22 bytes)
  || BE64(42)                              (8 bytes)

Total: 17 + 21 + 22 + 8 = 68 bytes

Info string (hex, 68 bytes):
  0x7363702d6163636573732d6b65792d76310000001168706b652d746573742d636f6e74657874000000126469643a6468743a7a364d6b4d656d626572000000000000002a
```

Note: Both the sender key and access key info strings use 4-byte BE length-prefixed context_id and DID fields. Domain separation between the two is provided by distinct prefix strings (`"scp-sender-key-v1"` vs `"scp-access-key-v1"`), which ensures the two info strings can never collide even with adversarial inputs.

Both prefixes are 17 ASCII bytes and both info strings are 68. Before 2026-09-10 these two vectors stated 18 and 69, so an implementer following §25.17 step 3 would have read a correct encoding as wrong.

**Neither vector prints a KEM output.** These two vectors pin the `info` strings and the domain separation between them, which is what §9.16.2 and §9.17.1 fix. The KEM itself is DHKEM(P-256, HKDF-SHA256) with the encodings RFC 9180 §7.1 fixes, and RFC 9180 Appendix A.3 already publishes known-answer vectors for it, so no vector here restates them.

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
  || BE32(80)  || msgpack(claim)               (4 + 80 = 84 bytes — claim as MessagePack)
  || BE32(110) || msgpack(evidence)            (4 + 110 = 114 bytes — evidence as MessagePack)
  || BE32(7)   || msgpack(revocation_status)    (4 + 7 = 11 bytes — revocation_status as MessagePack)

Total: 33 + 11 + 17 + 22 + 22 + 8 + 32 + 84 + 114 + 11 = 354 bytes

MessagePack sub-structures (name-keyed maps; a `None` field is omitted, so
`platform_id` and `verifier_did` do not appear):

  msgpack(claim), 80 bytes:
    0x83a8706c6174666f726daa676f6f676c652e636f6daf706c6174666f726d5f68616e646c65af616c69636540676d61696c2e636f6da96c696e6b5f74797065b073656c665f6174746573746174696f6e

  msgpack(evidence), 110 bytes:
    0x83a66d6574686f64a56f61757468a570726f6f66d9477b2270726f7669646572223a22676f6f676c652e636f6d222c227375626a6563745f6964223a223132333435222c2276657269666965645f6174223a313730303030303030307dab76657269666965645f6174ce6553f100

  msgpack(revocation_status), 7 bytes:
    0xa6416374697665

Preimage (hex, 354 bytes):
  5343502d4944454e544954592d4c494e4b2d4154544553544154494f4e2d56313a000000076174742d3030310000000d6964656e746974795f6c696e6b000000126469643a6468743a7a364d6b497373756572000000126469643a6468743a7a364d6b497373756572000000006553f1006e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d0000005083a8706c6174666f726daa676f6f676c652e636f6daf706c6174666f726d5f68616e646c65af616c69636540676d61696c2e636f6da96c696e6b5f74797065b073656c665f6174746573746174696f6e0000006e83a66d6574686f64a56f61757468a570726f6f66d9477b2270726f7669646572223a22676f6f676c652e636f6d222c227375626a6563745f6964223a223132333435222c2276657269666965645f6174223a313730303030303030307dab76657269666965645f6174ce6553f10000000007a6416374697665

Canonical hash SHA-256(preimage) (32 bytes):
  0xf96d0d2c24da118b3e31f20fc082e1b0c23daa0114d9b747eddbc16339924927

RFC 6979 signature over the canonical hash, reference key, 64-byte raw r || s:
  0xe66d1b5884fc5f58ed627e49aac5db247d5c2129e0411e0a2154b9f603ffe94c05a358e3a31b20f28656741a36f90adb500a75261cb9725526f9fe7b2b54550f

Verification vector:
  public key: 0x033b1cac23f45cf1cdfdf0b32f8f777b99166c1b69649c2295b1517883d47f3027
  digest:     the canonical hash above
  signature:  the 64 bytes above
  verdict:    accept
```

A software signer under RFC 6979 reproduces those signature bytes; a hardware signer produces different bytes over the same canonical hash and is checked against the verification vector instead (§25.4 states the rule once and this vector follows it). Before 2026-09-10 this vector printed no hash at all and told the reader to compute one from the Rust reference implementation, so it pinned nothing an independent implementer could check.

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

2. **P-256 sanity check.** Load the reference seed (§25.2), derive the private scalar under the seed-to-scalar rule, and derive the public key. Verify both against the values §25.2 prints. If either fails, the P-256 implementation, the HKDF, or the reading of the seed-to-scalar rule is broken.

3. **Encoding verification.** For each vector, construct the canonical byte sequence from the specified inputs using the encoding rules in §9.5.1. Compare the byte sequence length against the expected total. If lengths differ, the encoding is wrong.

4. **Hash verification.** Compute SHA-256 of each canonical byte sequence. Compare against the expected hash the vector prints.

5. **Signature verification.** For signed structures, verify the printed 64-byte signature against the reference public key and the canonical hash, and confirm the verifier rejects the same signature with `s` replaced by `n − s` (§9.5's low-`s` rule). Then sign the canonical hash with your own signer and **verify the signature your signer produced against the same public key and the same hash**; a hardware signer's conformance check is that verification and never a comparison against the printed bytes. **Confirm as part of it that your signer emitted the low form**, because §9.5 obliges every signer to convert `(r, s)` to `(r, n − s)` when `s` exceeds half the group order and a substrate that returns the high form leaves that conversion to the code around it. A **software** signer MUST additionally reproduce the printed bytes exactly, because §9.5 requires it to derive the nonce under RFC 6979 with SHA-256 over that same digest.

5a. **Point validation.** Confirm your parser rejects a 33-byte encoding whose leading byte is neither `0x02` nor `0x03`, rejects a 65-byte encoding whose leading byte is not `0x04`, rejects an encoding whose decoded point does not satisfy the P-256 curve equation, and rejects the point at infinity — before that point reaches any verification and before it reaches any key agreement (§9.5). §25.2's three reference public keys are the positive cases; negate the y-coordinate of the tertiary key's uncompressed form and flip its final byte to obtain an off-curve negative case.

6. **Padding verification.** For each padding vector, construct the padded output and verify the total length matches the expected bucket size. Strip the padding and verify the original payload is recovered.

7. **Merkle tree verification.** Construct trees incrementally and verify the root hash matches after each append. Verify inclusion proofs for specific leaves.

## 25.18 Generating Reference Outputs

`scripts/gen-test-vectors-p256.py` regenerates every value this section prints outside §25.21, §25.22 and §25.24, whose values live in the checked-in JSON fixtures those sections name:

```bash
python3.12 scripts/gen-test-vectors-p256.py
```

§25.1 states what the script implements and which published known-answer tests it checks itself against. A value printed above that the script does not reproduce is a defect in this section.

**The Rust reference implementation still signs under the superseded curve.** `crates/scp-runtime/tests/test_vectors.rs`, `crates/scp-event-log/tests/test_vectors.rs`, `crates/scp-crypto/src/pseudonym.rs`, and the `vector_38_*` and `vector_39_*` tests of `crates/scp-protocol/src/trust/custody_violation.rs` assert the Ed25519 values these vectors carried before 2026-09-10; §25.25 renumbers that crate's two vectors to 39 and 40, because §25.9 already carries a Vector 38. SCP superseded Ed25519 on that date (§9.5 of the security-model spec) and the artifact flow puts the spec first, so this section is the authority for every byte above until those tests are ported to P-256. An implementer comparing against those Rust tests today reproduces the pre-2026-09-10 values, not the values above.

Independent implementations SHOULD run the generator, compare its output against the values printed above, and then embed those outputs in their own test suites.

## 25.19 Per-Context Pseudonym Derivation Vectors (§9.10.4, §9.10.4.A, §9.10.4.1)

These vectors pin the **software-custody** per-context pseudonym keypair derivation. Software custody is cross-platform deterministic: every SDK (Rust, Swift, Kotlin, TypeScript) MUST reproduce the exact public-key bytes below for the same identity seed, `context_id`, and epoch. **Hardware custody** (Secure Enclave, Android Keystore TEE, HSM) is device-local by design — the `pseudonym_secret` is derived inside the hardware boundary from a non-exportable key, so hardware pseudonyms are NOT expected to match these values and are NOT cross-device deterministic (§9.10.4.A).

Derivation recipe (all implementations agree):

```
identity_scalar = the 32-byte P-256 private scalar (§25.2 states how a seed
                  becomes one; §9.10.4.A names this value as the HKDF input)

pseudonym_secret = HKDF-SHA256(
  ikm  = identity_scalar (32 bytes),
  salt = "scp-pseudonym-secret-v1",
  info = "",                                   (empty)
  len  = 32
)

# v1 (static):
context_seed_v1 = HMAC-SHA256(pseudonym_secret, context_id || "scp-pseudonym")

# v2 (rotatable, BE64 epoch):
context_seed_v2 = HMAC-SHA256(pseudonym_secret, context_id || BE64(epoch) || "scp-pseudonym-v2")

# seed-to-scalar (FIPS 186-5 A.2.1, extra random bits — §9.10.4):
scalar_input = HKDF-Expand-SHA256(context_seed, "SCP-PSEUDONYM-P256-V1", 48)
d            = (int(scalar_input) mod (n - 1)) + 1
pseudonym_public_key = P256_keypair_from_scalar(d).public_key   (33-byte compressed)
```

The 32-byte `context_seed` is the HKDF-Expand input of the seed-to-scalar rule, never a scalar in its own right: §9.10.4 forbids reducing it directly, which biases the low-order scalars, and forbids reject-and-retry, which makes the derivation diverge across implementations that draw retries differently. The HMAC `data` is plain concatenation with NO length prefixes — these are fixed-format internal inputs, and the domain-separator suffix (`"scp-pseudonym"` vs `"scp-pseudonym-v2"`) plus the fixed 8-byte BE64 epoch make the encoding unambiguous.

The two vectors below take a 32-byte identity **seed** as their stated input and turn it into the identity scalar by the §25.2 rule, so each vector derives from bytes it prints.

### Vector 30: Pseudonym Derivation — identity seed 0x01×32

```
Input:
  identity_seed:         0x0101010101010101010101010101010101010101010101010101010101010101
  context_id:            "context-alpha"  (0x636f6e746578742d616c706861, 13 bytes)
  epoch (v2):            1

Identity scalar (§25.2 seed-to-scalar, label "SCP-TEST-VECTOR-KEY-V1"):
  0x32c69e4a096fadd1a8d0a21e0a97f124d5c4c8c5b15b96027beadb91c2f3ec64

Expected pseudonym_secret:
  0xb88e781bb954a6681abc9016f8f69939f0e624311aeaa7e8f1b145857f58de82

Expected context_seed_v1:
  0x47ea801c24e8a4d577f04837eca0674fbbf160127fa2d1a4bb1420150b0a048b

Expected v1 pseudonym public key (33-byte compressed):
  0x0367e9d3809d6f9bc6854132aff27c2a399463bb516db76f844d79a7b0453c8f72

Expected context_seed_v2 (epoch = 1):
  0x6ab63aa150992ff032f6963c31dc9f5a8bd4e9518516f9fbd3bea7bc07f64b38

Expected v2 pseudonym public key (epoch = 1, 33-byte compressed):
  0x0276c50b92dacbe6ae1a3761d007b7fe75016a4c076f214694c95d13162ff24479
```

### Vector 31: Pseudonym Derivation — identity seed 0x9d,0x01..0x1f

```
Input:
  identity_seed:         0x9d0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
  context_id:            "context-alpha"  (0x636f6e746578742d616c706861, 13 bytes)
  epoch (v2):            1

Identity scalar (§25.2 seed-to-scalar, label "SCP-TEST-VECTOR-KEY-V1"):
  0x65d56a863d03d31ea15ade82f677058d5bbe53afedc6ff7d2b8846aa25a1bc2b

Expected pseudonym_secret:
  0x17ef25ad3e5be8adad38c4c5a1c68d3daca80015e81bdcae2ae8940645774739

Expected context_seed_v1:
  0x5157d14a2362044199ba88d66d6a52a4bfbe0598ebe921c5fb9c362d3bebaedd

Expected v1 pseudonym public key (33-byte compressed):
  0x0239f7c3213f3567183fd2fcf7aec6c884bc70e0e694c42053284a4b5ebef4fe2d

Expected context_seed_v2 (epoch = 1):
  0x8133a9d716dcbe729b1f447ac0efccf3795e8bf28da2db4744090d0316ead730

Expected v2 pseudonym public key (epoch = 1, 33-byte compressed):
  0x037967cfe8d3111cdd72288ea3f444c15b710300323162fec63ca9036af73754e3
```

`derive_pseudonym_keypair_known_answer_vectors` in `crates/scp-crypto/src/pseudonym.rs` (the wasm-safe home of the derivation, ADR-057 Option A) and `pseudonym_derivation_matches_golden_vectors` in `crates/scp-client-wasm/tests/pseudonym_derivation_cross_target_kat.rs` assert the pre-2026-09-10 Ed25519 values; §25.18 states which artifact governs while that port is outstanding. The native/`wasm32` byte-parity obligation those two tests carry is unchanged — only the curve and the key width changed.

### Vector 36: `PseudonymAnnouncement` wire format + classifier decisions (§9.10.4)

These vectors pin the on-the-wire **pseudonym announcement** — the `MessagePack` payload a member broadcasts on the shared bootstrap channel to teach peers their per-context routing ID — and the pure §9.10.4 accept/reject classifier that both the native orchestrator and the in-browser client run over an inbound announcement. Because the announcement type and the classifier live in the wasm-safe `scp-protocol::context::pseudonym` module (ADR-057 T-1), native and `wasm32` MUST produce byte-identical wire bytes and identical accept/reject decisions.

**Wire format.** `PseudonymAnnouncement` is serialized with `rmp_serde::to_vec_named` — a name-keyed `MessagePack` map with three fields, in declaration order: `tag` (string), `member_did` (string), `pseudonym` (32-byte `serde_bytes` binary). **The `pseudonym` field carries the 32-byte per-context pseudonym routing id**, `SHA-256("scp-pseudonym-routing-v1:" || context_pseudonym)` over the 33-byte compressed pseudonym public key (§9.10.4 of the security-model spec), and never the point itself; that is why it is 32 bytes and why the reserved-value comparisons below, against `[0;32]` and against the two other routing ids, compare values of one width. The `0x42 × 32` value this vector carries is an opaque fixture routing id and is not derived from Vectors 30 or 31. No `usize`, no float, no map-iteration order, so a fixed value re-encodes deterministically and target-independently.

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

Preimage (hex, 197 bytes):
  5343502d4154544553544154494f4e2d56313a0000000d6174742d74727573742d3030310004000000126469643a6468743a7a364d6b497373756572000000136469643a6468743a7a364d6b5375626a6563740000001b7b226c6576656c223a22676f6c64222c2273636f7265223a34327d6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d000000006553f1006e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d00000007a6416374697665

Expected SHA-256 (= canonical_attestation_bytes output):
  0x6d07c76821a2ae4dd830ca117aa9fd8e30232cca72459a4d129432f56d87a08c

RFC 6979 signature over the canonical hash, reference key, 64-byte raw r || s:
  0x767f500caf5ecbc3e2d9f73376a16a36cb68c5d32c9c4be48cd5aae7b8615174589cb95e07ed2c6027c0a21a260cd90605ab2598f3cc96dce2d437dcfa530647

Verification vector:
  public key: 0x033b1cac23f45cf1cdfdf0b32f8f777b99166c1b69649c2295b1517883d47f3027
  digest:     the canonical hash above
  signature:  the 64 bytes above
  verdict:    accept
```

The P-256 signature is computed over the 32-byte canonical hash. Sign with the reference key (§25.2) and verify per §25.17 step 5. The preimage carries no key material, so the canonical hash above is unchanged from the value this vector pinned before SCP superseded Ed25519 on 2026-09-10; only the signature is new.

`vector_34_trust_attestation_signature` in `crates/scp-runtime/tests/test_vectors.rs` pins the expected hash, reconstructs the preimage byte-for-byte, and verifies a signed attestation through the production `verify_attestation` path. Its hash assertion still holds; its signature path is Ed25519 and §25.18 states which artifact governs while that port is outstanding.

## 25.21 Outlet Streaming Conformance Vectors (§5.4.5)

Progressive-output (streaming) outlet invocation (§5.4.5, ADR-061) is exercised by a shared set of 7 scenario vectors that pin the observable behavior of a stream end-to-end: the ordered chunk transcript, the credit-grant timing, the cancellation billing boundary, and the terminal status recorded in the `OutletInvokedEvent` (`StreamTerminalStatus`, §5.4.5 "Event log shape"). Unlike the cryptographic known-answer vectors above, these are **behavioral** vectors — they carry payload *descriptors*, not literal signed wire bytes. Every chunk signature (`OutletStreamChunk.sig`) and every `caveats_binding` is **recomputed** by the harness at replay time under the §25.2 reference operator key (the P-256 key derived from seed `0x9d61…7f60`), because the operator signature preimage (`SCP-OUTLET-CHUNK-SIG-V1:`, §5.4.5) binds the per-stream `request_id`, `sequence`, and `caveats_binding`, none of which are fixed until the stream is opened.

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
- **`sequence_gap` → `SCP-OUTLET-6131` / `execution.stream-gap`** (consolidated). `SLUG_EXECUTION_STREAM_GAP = "execution.stream-gap"` shares `CODE_EXECUTION_CREDIT` (`SCP-OUTLET-6131`) with `execution.credit-exhausted` — two Execution-class slugs under one code, both `Immediate` (idempotent "retry now"). The node-level `execution.stream-cap-exhausted` was split off to its own code `SCP-OUTLET-6132` (`CODE_EXECUTION_STREAM_CAP`, `WithBackoff`) per #2209 — a node-at-capacity condition needs back-off, not immediate retry, and retry policy is keyed on the code.

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

The canonical vector file is `tests/conformance/vectors/outlet_streaming_saga_vectors.json` (top-level `{version, vectors:[6]}`, each entry a `{name, spec}` envelope). Every chunk signature and every `caveats_binding` is **recomputed** at replay time under the §25.2 reference operator key (the P-256 key derived from seed `0x9d61…7f60`); the receipt round-trip KAT signs under that same §25.2 seed so its preimage and signature are byte-exact and checked in. That fixture was generated before SCP superseded Ed25519 on 2026-09-10 and still carries Ed25519 signature bytes; §25.18 states which artifact governs while that port is outstanding.

### Scenario matrix

| Vector | Scenario | Pinned artifact | Terminal / code |
|--------|----------|-----------------|-----------------|
| `stream_receipt_kat` | Fixed 9-field `SCP-XCTX-STREAM-RECEIPT-V1` input → byte-exact preimage + deterministic signature; `verify()` accepts, every single-field mutation rejects | `expected_preimage_hex` (32 B), `expected_signature_hex` (64 B) | — |
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

## 25.23 KeyPackage Attestation Signing Vectors (§9.7.1, §9.5.2, §9.18.7)

Domain: `"SCP-KEYPACKAGE-ATTESTATION-V1:"`

### Vector 37: KeyPackage Attestation Signature + `0xFF03` Extension Body

The `KeyPackageAttestation` (§9.5.2) binds **all four** of the leaf's public keys — the ephemeral MLS leaf `signature_key`, and three **distinct** DHKEM(P-256) HPKE keys: the LeafNode ratchet-tree `encryption_key`, the KeyPackage `init_key` (the Welcome-seal key), and the `scp_wrapping_key` (`0xFF01`) extension `wrapping_key` — to a DID. It is **context-agnostic** — eight fields, no `context_id`. All four are 65-byte uncompressed SEC1 P-256 points, in the encodings RFC 9420 §5.1.2 and RFC 9180 §7.1 fix and §9.5.2 states in place. The canonical hash uses the §9.5.1 construction; the P-256 signature is computed over the 32-byte hash with the reference key (§25.2). The `scp_keypackage_attestation` (`0xFF03`) LeafNode extension body is the eight fields in preimage order (deterministic length-prefixed binary — NOT MessagePack/JCS) followed by the raw 64-byte signature.

This vector is fully regenerable from the inputs below. `leaf_signature_key` is the §25.2 secondary key in its uncompressed form, standing in for the ephemeral leaf `signature_key` being bound. The three HPKE keys each derive from a **fixed, documented 32-byte seed** under the §25.2 seed-to-scalar rule: `leaf_encryption_key` from `0x33×32`, `init_key` from `0x11×32`, `wrapping_key` from `0x22×32`. These are distinct keys by construction — `init_key != encryption_key` (RFC 9420: the Welcome's `EncryptedGroupSecrets` is HPKE-sealed to the KeyPackage `init_key`, NOT the LeafNode `encryption_key`), and `wrapping_key` is the separate §9.16 sender-key wrapping key.

Before 2026-09-10 the `leaf_encryption_key` seed was the §25.2 secondary seed. On P-256 that seed yields the same scalar as `leaf_signature_key`, which would make two of the four bound keys identical and destroy the distinctness this vector exists to demonstrate, so `leaf_encryption_key` now carries its own seed `0x33×32`.

```
Input:
  signing key:         reference P-256 key (§25.2, seed 0x9d61b1…7f60)
  did:                 "did:dht:z6MkLeafAttest"                (22 bytes)
  leaf_signature_key:  0x0423702a648232f2d00713de9289753c2fbd4c4efa7e1e33905e3723a412b20aead0992a08064d996d9268dc511c7430f3a4e614871d4a888b52a8dbecb56d6da6   (65 bytes, §25.2 secondary public key, uncompressed)
  leaf_encryption_key: 0x04bb9fe4749210aad657fb3937fa97a0d79c976c442c54176ccce88477e1b32f304661cb77defd365843a4d43584afc760fed0d9a889d9cb3dd155986b446f4550   (65 bytes, from fixed seed 0x33×32 — LeafNode ratchet-tree HPKE key)
  init_key:            0x041f75a6a31cc4516a2eb0b28511c45160b976b44e8c31ec377b0c2cb67b05f0ad3195794c4fc38b105bd5f5e1239a3c73feb58bd815cbfd2fe049c084f7f88a8a   (65 bytes, from fixed seed 0x11×32 — KeyPackage Welcome-seal HPKE key)
  wrapping_key:        0x04ff08966117691da4f3f0a3bbc4a63cab7193008d316127821b1e09b9e2aef925eaa5de2932cc294a2cc58f36e31a9a245f67404ad14d142d0e423901aa44cac3   (65 bytes, from fixed seed 0x22×32 — scp_wrapping_key 0xFF01 §9.16 sender-key wrapping key)
  signing_key_id:      "#active"                               (7 bytes)
  issued_at:           1700000000                              (== leaf Lifetime.not_before)
  expires_at:          1700086400                              (== leaf Lifetime.not_after; issued_at + 86400)

Canonical hash input (per §9.5.1 / §9.5.2 KeyPackageAttestation):
  "SCP-KEYPACKAGE-ATTESTATION-V1:"                 (30 bytes, no length prefix)
  || BE32(22) || "did:dht:z6MkLeafAttest"          (4 + 22 = 26 bytes — did)
  || leaf_signature_key                            (65 bytes, fixed-length, no length prefix)
  || leaf_encryption_key                           (65 bytes, fixed-length, no length prefix)
  || init_key                                      (65 bytes, fixed-length, no length prefix)
  || wrapping_key                                  (65 bytes, fixed-length, no length prefix)
  || BE32(7)  || "#active"                         (4 + 7 = 11 bytes — signing_key_id)
  || BE64(1700000000)                              (8 bytes — issued_at)
  || BE64(1700086400)                              (8 bytes — expires_at)

Total preimage: 30 + 26 + 65 + 65 + 65 + 65 + 11 + 8 + 8 = 343 bytes

Preimage (hex, 343 bytes):
  0x5343502d4b45595041434b4147452d4154544553544154494f4e2d56313a000000166469643a6468743a7a364d6b4c6561664174746573740423702a648232f2d00713de9289753c2fbd4c4efa7e1e33905e3723a412b20aead0992a08064d996d9268dc511c7430f3a4e614871d4a888b52a8dbecb56d6da604bb9fe4749210aad657fb3937fa97a0d79c976c442c54176ccce88477e1b32f304661cb77defd365843a4d43584afc760fed0d9a889d9cb3dd155986b446f4550041f75a6a31cc4516a2eb0b28511c45160b976b44e8c31ec377b0c2cb67b05f0ad3195794c4fc38b105bd5f5e1239a3c73feb58bd815cbfd2fe049c084f7f88a8a04ff08966117691da4f3f0a3bbc4a63cab7193008d316127821b1e09b9e2aef925eaa5de2932cc294a2cc58f36e31a9a245f67404ad14d142d0e423901aa44cac30000000723616374697665000000006553f1000000000065554280

Canonical hash SHA-256(preimage) (32 bytes):
  0xb57dafbe5f12cf5d83a0b90e7fd4df9bea53a22e96f80a75a7d844c63041ae71

RFC 6979 signature over the canonical hash, reference key, 64-byte raw r || s:
  0x308c4e5612215e13119b098ac3318a40c0fb393fefea4a65b40c56e38740829e2a94359e5f99476aba4ace58db8fc8c6b39eaf31673d1c81800ce2e972ad69ac

scp_keypackage_attestation (0xFF03) extension body = 8 fields in preimage order
(NO domain separator) || 64-byte signature (313 + 64 = 377 bytes):
  0x000000166469643a6468743a7a364d6b4c6561664174746573740423702a648232f2d00713de9289753c2fbd4c4efa7e1e33905e3723a412b20aead0992a08064d996d9268dc511c7430f3a4e614871d4a888b52a8dbecb56d6da604bb9fe4749210aad657fb3937fa97a0d79c976c442c54176ccce88477e1b32f304661cb77defd365843a4d43584afc760fed0d9a889d9cb3dd155986b446f4550041f75a6a31cc4516a2eb0b28511c45160b976b44e8c31ec377b0c2cb67b05f0ad3195794c4fc38b105bd5f5e1239a3c73feb58bd815cbfd2fe049c084f7f88a8a04ff08966117691da4f3f0a3bbc4a63cab7193008d316127821b1e09b9e2aef925eaa5de2932cc294a2cc58f36e31a9a245f67404ad14d142d0e423901aa44cac30000000723616374697665000000006553f1000000000065554280308c4e5612215e13119b098ac3318a40c0fb393fefea4a65b40c56e38740829e2a94359e5f99476aba4ace58db8fc8c6b39eaf31673d1c81800ce2e972ad69ac

Verification vector:
  public key: 0x033b1cac23f45cf1cdfdf0b32f8f777b99166c1b69649c2295b1517883d47f3027
  digest:     the canonical hash above
  signature:  the 64 bytes above
  verdict:    accept
```

A software signer under RFC 6979 reproduces these exact signature bytes on every run; a hardware signer produces different bytes and is checked against the verification vector instead (§25.4). Note the extension body omits the domain separator (present only in the signed preimage) and shares the eight fields byte-for-byte with the preimage's post-domain portion.

## 25.24 Outlet Registration V2 Vectors (§5.4.1)

Domain: `"SCP-OUTLET-REGISTRATION-V2:"` — supersedes the deleted pre-rename `"SCP-TOOL-REGISTRATION-V1:"` domain (ADR-049 §1, hard-break, no aliases).

The canonical conformance fixture lives at:

```
tests/conformance/vectors/outlet_registration_v2.json
```

The fixture documents **12 known-input / known-output vectors**, each signed under the §25.2 reference keypair. The checked-in fixture was generated before SCP superseded Ed25519 on 2026-09-10 and still carries Ed25519 keys and signatures; §25.18 states which artifact governs while that port is outstanding. Every entry carries:

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | Stable case identifier (e.g., `minimal-query`, `with-100-test-vectors`). |
| `notes` | string | Human-readable description and spec cross-reference. |
| `input` | object | The `OutletRegistration` field set (excluding `signature`). |
| `expected_preimage` | hex string | Raw byte sequence fed into SHA-256, beginning `"SCP-OUTLET-REGISTRATION-V2:"`. |
| `expected_canonical_hash` | hex string | SHA-256 of `expected_preimage` (32 bytes / 64 hex). Equals the output of `compute_outlet_registration_canonical_bytes`. |
| `expected_signature` | hex string | Signature over `expected_canonical_hash` (64 bytes / 128 hex). |
| `operator_did` | string | The signing operator's DID (the same across all vectors for determinism). |
| `operator_public_key` | hex string | The operator's verifying key. §9.5 fixes 33 bytes / 66 hex for a P-256 verification key, and **the checked-in fixture carries 32 bytes**, because it was generated under the superseded Ed25519 curve as the sentence above this table states. A harness reads the width from the fixture it loads until that fixture is regenerated on P-256. |

### 25.24.1 Vector index

| # | Name | Shape |
|---|------|-------|
| 1 | `minimal-query` | Read-only outlet (`kind = query`), `cost = None`. |
| 2 | `minimal-action` | Mutating outlet (`kind = action`), `cost = None`. |
| 3 | `query-cost-none` | Query outlet, explicit `cost = None` (exercises the absent-cost preimage branch, `cost_hash = SHA-256(0x00)`). |
| 4 | `query-cost-zero` | Query outlet with `OutletCost { amount: 0, currency, payee }` (cost-present-but-zero branch). |
| 5 | `action-cost-positive` | Action outlet with `cost.amount > 0`, including `currency` + `payee` fields. |
| 6 | `with-aggregate-schema` | `OutletSchema.aggregate_schema` is `Some(..)`, describing the terminal streamed-aggregate shape (§5.4.5); committed via `schema_hash`. |
| 7 | `max-size-schema` | Input schema approaches the §5.4.1 64 KiB serialized cap. |
| 8 | `with-100-test-vectors` | Carries 100 registration test vectors (the §5.4.1 maximum). |
| 9 | `llm-backed-impl-hash` | `implementation_hash = SHA-256(model_id \|\| ":" \|\| system_prompt_utf8)` per the LLM-backed §5.4.1 rule, with `cost.cost_formula` set for per-token pricing (§19.4). |
| 10 | `remote-service-impl-hash` | `implementation_hash = SHA-256(canonical_jcs(openapi_spec))` per the remote-service §5.4.1 rule, with `cost.cost_formula` set for dynamic per-call pricing (§19.4). |
| 11 | `multi-caveat-invocation-target` | Paid Action outlet whose registered shape is compatible with multi-caveat UCAN invocation (§7.3.8). |
| 12 | `cross-context-invocation-target` | Action outlet exposed via cross-context interface (§6.2.0.1). |

The vectors are signed under the full §5.4.1 V2 preimage produced by `compute_outlet_registration_canonical_bytes`: the real `kind_byte` (`0x00` Query, `0x01` Action), the length-prefixed `outlet_id`/`name`/`operator_did`, and the dedicated 32-byte `description_hash`, `schema_hash`, `implementation_hash`, `test_vectors_hash`, `cost_hash`, and `catalog_hash` terms, closed by the BE64 `registered_at`. The `kind`, `aggregate_schema` (on `OutletSchema`), and `message_catalog` fields specified in §5.4.1 are wired on the current `OutletRegistration` (SCP-OUT-011 / SCP-OUT-013 / SCP-OUT-024 / SCP-OUT-015 have landed); these vectors were regenerated against that full preimage.

### 25.24.2 V1 rejection corpus

The fixture additionally carries 12 paired entries under `v1_rejection_corpus`. Each entry contains:

- `v1_preimage` — the byte sequence under the deleted `SCP-TOOL-REGISTRATION-V1:` domain for the same logical input;
- `v1_canonical_hash` — `SHA-256(v1_preimage)`;
- `v2_canonical_hash` — copy of the matching V2 entry's `expected_canonical_hash`.

Conformance test `CONF-045` enforces that for every entry `v1_canonical_hash != v2_canonical_hash` AND that `v2_canonical_hash` matches the live `compute_outlet_registration_canonical_bytes` output. Pre-migration signatures over the V1 preimage do not validate against any V2 code path — this is the ADR-049 §1 hard break, demonstrated mechanically.

### 25.24.3 Conformance procedure

The conformance suite validates the vectors against the **Rust core only** — `scp_protocol::context::outlets::registry::compute_outlet_registration_canonical_bytes` + `verify_outlet_registration_signature` + direct signature verification. It does **not** exercise the FFI bridges: the live per-bridge registration-signature scheme is currently unwired — `register_outlet` (registry.rs) neither computes nor verifies a registration signature, and the PyO3 / NAPI / UniFFI bridges construct `OutletRegistration { signature: vec![] }`. Wiring the §5.4.1 registration signature through production `register_outlet` and each bridge (so a vector is sign-verifiable via each FFI bridge) is tracked in **#2229**; the WASM bridge is genuinely N/A per ADR-057. The suite:

```bash
cargo test -p scp-testing --test conformance \
  conf_043_outlet_registration_v2_shape \
  conf_044_outlet_registration_v2_sign_verify \
  conf_045_outlet_registration_v1_rejected \
  conf_046_outlet_registration_v2_matches_generator -- --nocapture
```

Independent implementations SHOULD parse `outlet_registration_v2.json`, reconstruct each registration from `input`, recompute the V2 preimage byte-for-byte, verify SHA-256 matches `expected_canonical_hash`, and verify the signature against `operator_public_key`. Implementers MUST also confirm that `v1_preimage` for each rejection-corpus entry produces a hash distinct from the matching `v2_canonical_hash`.

### 25.24.4 Regenerating the fixture

```bash
cargo test -p scp-testing --test conformance \
  conf_outlet_registration_v2_regen -- --ignored --nocapture
```

The regenerator is `#[ignore]` by default so the default `cargo test` run does not write to disk. Fixture drift (live code changes that should but do not invalidate the JSON) is caught by `CONF-046`, which compares the on-disk file byte-for-byte to the generator's current output.

## 25.25 Custody Violation and Counter-Attestation Signing Vectors — deleted 2026-09-10

**These vectors are gone and this heading records why.** The identity-substrate plan's §1 table marks the custody-violation record and the counter-attestation **CUT** — Alec's ruling of 2026-08-25, reconfirmed 2026-08-31 — and Track U4 of that plan owns the teardown of their `09-security-model.md` §9.5.2 preimage tables and of the shipped code that still carries them. Vectors 39 and 40 re-signed those two preimages onto P-256 on this branch, which widened a teardown that was already scoped, so they were deleted rather than carried forward. `scripts/gen-test-vectors-p256.py` builds neither.

## 25.26 Key-Event Preimage and Signature Slot Vectors (§9.7.4.2 definitions, §9.5)

**What these vectors pin.** §9.7.4.2's definitions fix the key-event preimage's field order, so these vectors pin an inception event's own bytes, the digest of those bytes, the identifier that digest derives, and the routing id that identifier derives — then the signature slot each of the two signature forms produces over the same event. **Only the identifier's textual form is still deferred** (R13), and no derivation below consumes one.

**The vector identity.** A 1-of-1 root set whose member is §25.2's reference key, one `#active` key which is §25.2's secondary key, a 1-of-1 next set whose pre-rotation key is §25.2's tertiary key, one designated witness, and a witnessing interval of 3,600 seconds. Every key carries `KeyAlgorithm` `0x01` and custody type `Passkey` (`0x01`). The key-state snapshot is 177 bytes and the preimage is 359 bytes.

```
Pre-rotation public key (33-byte SEC1 compressed):
  026fc6523b7b1e22ff3fbce8740cfbb7cbc816501864bf40f683db69c860d1a6
  70
Pre-rotation commitment, SHA-256("SCP-PREROTATION-COMMITMENT-V1:" || that point):
  421be508c6ed135a9737895007e5ba16f9542e1b3440f6d00a515de80a3e43eb
Designated witness operator identifier:
  9d94df95bc0a13f1963f484414c320354c73c75bb86e96559e97765f5bc2d313
```

### Vector 41: an inception whose one root slot carries the raw form (`form = 0x01`)

```
Preimage (359 bytes), in §9.7.4.2's field order:
  5343502d4b454c2d4556454e542d56313a010000000000000000000000000000
  0000000000000000000000000000000000000000000000000000000000000000
  0000000000000000000000000000000000000000000000000000000000010000
  0000010100000001033b1cac23f45cf1cdfdf0b32f8f777b99166c1b69649c22
  95b1517883d47f3027000000010000000100000002033b1cac23f45cf1cdfdf0
  b32f8f777b99166c1b69649c2295b1517883d47f302701010000000000000000
  01010223702a648232f2d00713de9289753c2fbd4c4efa7e1e33905e3723a412
  b20aea020100000000000000000101000000010101000000019d94df95bc0a13
  f1963f484414c320354c73c75bb86e96559e97765f5bc2d31300000e10020000
  0000000000000000000000000000000000000000000000000000000000000100
  000001421be508c6ed135a9737895007e5ba16f9542e1b3440f6d00a515de80a
  3e43eb00000001

Preimage digest D:
  fcd64b28cde081884543143d77e41161789386b51dc4263e9fc5755f8b17c930
Identifier, SHA-256("SCP-KEL-ID-V1:" || preimage):
  0d230375c05876775265f7a49954a3bba9459ce25d2d5a380c1a9bc14a020b68
Routing id, SHA-256("scp:did:" || identifier):
  73fbe2ada899507f188a7e0f9c47a639e085caae13198f25aae149b08d1afbd0

Root-set member 0, 33-byte SEC1 compressed point:
  033b1cac23f45cf1cdfdf0b32f8f777b99166c1b69649c2295b1517883d47f30
  27

Signature form: 0x01
Slot length: 64 bytes
Slot:
  096207d81369d7f7909329ee2da8b05b0ef30697a49d8a1de668111f972b776a
  48a66d03aa9f7910b51ad732c43a652bcf0b4a48904860e0b8b720f133eb5bdf
```

### Vector 42: an inception whose one root slot carries the WebAuthn assertion form (`form = 0x02`)

**The preimage differs from Vector 41's in one byte**, the signature-form list's entry, so the two events carry different digests and different identifiers. That is the property the form list's presence in the preimage delivers: a relay cannot rewrite a slot's declared form without changing the event.

```
Preimage (359 bytes):
  5343502d4b454c2d4556454e542d56313a010000000000000000000000000000
  0000000000000000000000000000000000000000000000000000000000000000
  0000000000000000000000000000000000000000000000000000000000010000
  0000010200000001033b1cac23f45cf1cdfdf0b32f8f777b99166c1b69649c22
  95b1517883d47f3027000000010000000100000002033b1cac23f45cf1cdfdf0
  b32f8f777b99166c1b69649c2295b1517883d47f302701010000000000000000
  01010223702a648232f2d00713de9289753c2fbd4c4efa7e1e33905e3723a412
  b20aea020100000000000000000101000000010101000000019d94df95bc0a13
  f1963f484414c320354c73c75bb86e96559e97765f5bc2d31300000e10020000
  0000000000000000000000000000000000000000000000000000000000000100
  000001421be508c6ed135a9737895007e5ba16f9542e1b3440f6d00a515de80a
  3e43eb00000001

Preimage digest D:
  cab5a09a8f8841644c2f7d1c64d6a685eddb3272965be01460ecda320616df2e
Identifier:
  8c17ea16acf2dc019003c1e3148d860eadcc2018ef24834fb61c9943d55dcfe9

WebAuthn challenge, "SCP-KEY-EVENT-V1:" || D (49 bytes):
  5343502d4b45592d4556454e542d56313acab5a09a8f8841644c2f7d1c64d6a6
  85eddb3272965be01460ecda320616df2e
Challenge, unpadded base64url, as clientDataJSON carries it:
  U0NQLUtFWS1FVkVOVC1WMTrKtaCaj4hBZEwvfRxk1qaF7dsycpZb4BRg7NoyBhbfLg

rpIdHash, SHA-256("ctx.network"):
  aee39d05bf6e1cbe288aedd7ead156f1d67399382d7a110e8f6c495d11689d76
authenticatorData (37 bytes — the WebAuthn minimum,
which MIN_AUTHENTICATOR_DATA_BYTES fixes):
  aee39d05bf6e1cbe288aedd7ead156f1d67399382d7a110e8f6c495d11689d76
  0500000000
clientDataJSON (155 bytes):
  {"type":"webauthn.get","challenge":"U0NQLUtFWS1FVkVOVC1WMTrKtaCaj4hBZEwvfRxk1qaF7dsycpZb4BRg7NoyBhbfLg","origin":"https://ctx.network","crossOrigin":false}
SHA-256(clientDataJSON):
  6317937fd9151bc5c0b23100340321387e74e638e5c62b311fa6a2f8489c3929
Signed message, authenticatorData || SHA-256(clientDataJSON):
  aee39d05bf6e1cbe288aedd7ead156f1d67399382d7a110e8f6c495d11689d76
  05000000006317937fd9151bc5c0b23100340321387e74e638e5c62b311fa6a2
  f8489c3929
ECDSA digest over that message:
  0d43ff083c4d3cc3be110e51011610e847bfcdab231e805bc100c7d8751d02eb
Signature (64 raw bytes, low-s):
  71489c49d71dd7e7e819190029e49281b495751330c7b9b556d07f79d6a36de3
  1506428e63d842987d258f2e179b1453b05ecdc43c37d522438b84f769cc06cd

Slot length: 264 bytes
Slot:
  00000025aee39d05bf6e1cbe288aedd7ead156f1d67399382d7a110e8f6c495d
  11689d7605000000000000009b7b2274797065223a22776562617574686e2e67
  6574222c226368616c6c656e6765223a2255304e514c55744657533146566b56
  4f564331574d54724b746143616a3468425a4577766652786b31716146376473
  7963705a6234425267374e6f79426862664c67222c226f726967696e223a2268
  747470733a2f2f6374782e6e6574776f726b222c2263726f73734f726967696e
  223a66616c73657d71489c49d71dd7e7e819190029e49281b495751330c7b9b5
  56d07f79d6a36de31506428e63d842987d258f2e179b1453b05ecdc43c37d522
  438b84f769cc06cd
```

**Conformance procedure.** Rebuild the preimage from the field order §9.7.4.2's definitions state and compare it byte for byte; recompute the digest, the identifier and the routing id; then, for the assertion form, parse `clientDataJSON` as RFC 8259 JSON rejecting any duplicate member name, compare the decoded `type` against `"webauthn.get"` and the decoded `challenge` against the base64url above, check that the `authenticatorData` length is at least 37 and that bit 0 of byte 32 is set, reject a high-`s` signature, then verify the trailing 64 bytes over `authenticatorData || SHA-256(clientDataJSON)`.

## 25.27 Witness-Layer and Relay-Proof Vectors (§9.7.4.2 definitions, §9.7.4.3, §9.18.2)

Every object below names Vector 41's identity as its subject and Vector 41's event as the event a witness seeded at.

### Vector 43: a witness's first cosigned head after a seed

`previous_cosigned_digest` names the event the witness seeded at — Vector 41's inception event, which is the latest event whose key state names this witness. **It is never the all-zero placeholder**, which is what stops two first cosignatures of one witness satisfying the fault-proof predicate.

```
witness:                    9d94df95bc0a13f1963f484414c320354c73c75bb86e96559e97765f5bc2d313
witness_key_state_head:     aaac5550de5f09d998e49ae75c5ed63483a43ad77c9252359914a6ce9b7bfe6f
subject:                    0d230375c05876775265f7a49954a3bba9459ce25d2d5a380c1a9bc14a020b68
sequence:                   0
event_digest:               fcd64b28cde081884543143d77e41161789386b51dc4263e9fc5755f8b17c930
previous_cosigned_digest:   fcd64b28cde081884543143d77e41161789386b51dc4263e9fc5755f8b17c930
observed_at:                1700000000

Preimage (197 bytes = 21-byte separator + 176 field bytes):
  5343502d434f5349474e45442d484541442d56313a9d94df95bc0a13f1963f48
  4414c320354c73c75bb86e96559e97765f5bc2d313aaac5550de5f09d998e49a
  e75c5ed63483a43ad77c9252359914a6ce9b7bfe6f0d230375c05876775265f7
  a49954a3bba9459ce25d2d5a380c1a9bc14a020b680000000000000000fcd64b
  28cde081884543143d77e41161789386b51dc4263e9fc5755f8b17c930fcd64b
  28cde081884543143d77e41161789386b51dc4263e9fc5755f8b17c930000000
  006553f100
Canonical hash:
  74cac8bad8ce8c6c35dc96bcc8702f6d9d4dca8c74a4b8bcef68fce9397fb257
Signature, secondary key (240 bytes on the wire):
  0057514053f15625ac9b56cc416fdd0a36d506e12f6b5ee1da18b1b6e87a69d7
  41b69b5f09f8d46e92e1b57515737c43924a202040aca3ee105555438c2a77ed
```

### Vector 45: the conflict statement a witness emits when its one check fails

```
held_sequence:      7
held_digest:        9494a351a50e07b1d806cd1ac9c876fa9090cf31943bc894398d3a285c94e06f
offered_sequence:   7
offered_digest:     d57ac1967c8c6f17313209b43fd8513ac04d66a606f7d591ef65c7308abf0bcf

Preimage (208 bytes = 24-byte separator + 184 field bytes):
  5343502d5749544e4553532d434f4e464c4943542d56313a9d94df95bc0a13f1
  963f484414c320354c73c75bb86e96559e97765f5bc2d313aaac5550de5f09d9
  98e49ae75c5ed63483a43ad77c9252359914a6ce9b7bfe6f0d230375c0587677
  5265f7a49954a3bba9459ce25d2d5a380c1a9bc14a020b680000000000000007
  9494a351a50e07b1d806cd1ac9c876fa9090cf31943bc894398d3a285c94e06f
  0000000000000007d57ac1967c8c6f17313209b43fd8513ac04d66a606f7d591
  ef65c7308abf0bcf000000006553f100
Canonical hash:
  e03427923b8d031ed19bf888c99cc7e5eea3c90248e465a1626587b4ad79722c
Signature, secondary key (248 bytes on the wire):
  f1ac19e91ab2f4581dc05d585d6a8dce0435e745c8639d159732bd50f75cbed2
  7ffa3618fdf012c85b9d059301d8604c4a7b46c571bf58c7a8b0fb8e5de0ff25
```

### Vector 46: the two-heads fault proof

Two cosigned heads of one witness, over one subject, naming one non-zero `previous_cosigned_digest` and two different `event_digest`s. **These two objects together are the fault proof §9.7.4.3 defines**, and a relay keys its cosigned-head slot on (subject, witness, `previous_cosigned_digest`) so that both survive at one address (`03-identity.md` §3.10.2). A conforming implementation assembles the pair, verifies both signatures against the witness operator's key state at the position each names, and reports a valid fault proof.

```
Shared previous_cosigned_digest (non-zero):
  5ec440e45bc301ca80bda9c235036ef19f3fbf833eb5f09960cfac1f1098af54

46a — event_digest: 3dacf98cadc7a299e6f0b25f83aec640c34d5c16a2ba2252d1efcf246aebf0a0
      sequence: 21, observed_at: 1700000000
      preimage (197 bytes):
      5343502d434f5349474e45442d484541442d56313a9d94df95bc0a13f1963f48
      4414c320354c73c75bb86e96559e97765f5bc2d313aaac5550de5f09d998e49a
      e75c5ed63483a43ad77c9252359914a6ce9b7bfe6f0d230375c05876775265f7
      a49954a3bba9459ce25d2d5a380c1a9bc14a020b6800000000000000153dacf9
      8cadc7a299e6f0b25f83aec640c34d5c16a2ba2252d1efcf246aebf0a05ec440
      e45bc301ca80bda9c235036ef19f3fbf833eb5f09960cfac1f1098af54000000
      006553f100
      canonical hash:
  d5c16efd6c3cea57dc1eee12eb38d0aa65f9f28ae8b21368f8627ce0e9369f60
      signature:
  46d4bdf82663f4f011773645f3a7fb72c50e563f5230b6adcd97c38f5676233d
  2b98764217855d4e8c74259b39cc697bf7055a549ea55c7287a8c4d07f3ecec7

46b — event_digest: 53adb5551ff17eb6349a13afc7155a42b0496a7b9889e268eabe6d0c5f60f8a6
      sequence: 21, observed_at: 1700000001
      preimage (197 bytes):
      5343502d434f5349474e45442d484541442d56313a9d94df95bc0a13f1963f48
      4414c320354c73c75bb86e96559e97765f5bc2d313aaac5550de5f09d998e49a
      e75c5ed63483a43ad77c9252359914a6ce9b7bfe6f0d230375c05876775265f7
      a49954a3bba9459ce25d2d5a380c1a9bc14a020b68000000000000001553adb5
      551ff17eb6349a13afc7155a42b0496a7b9889e268eabe6d0c5f60f8a65ec440
      e45bc301ca80bda9c235036ef19f3fbf833eb5f09960cfac1f1098af54000000
      006553f101
      canonical hash:
  0808104f07475614970613efe203d1b809ac639d62574f5c50e5c76214a8fe90
      signature:
  ce016a4c4a12aa432e740fd8854415f57269badd1a95bc190a31bbc05fc0e791
  5d6b4fda2d2922f04c9357bca819ebba41ffc0e220c3bd077eadc45994eed831
```

### Vector 44: a relay proof of control over a served QUERY response

**The object carries no key-state position.** §9.7.1 classifies it in the attestation class, so its signature verifies against the key the operator's latest state-carrying event lists `current` in `#active`, and the operator's own rotation revokes every proof it signed. **`value_digest` is length-prefixed**: a 4-byte blob count, then each blob under §9.5.1's variable-length rule, so one digest names one split of the served bytes into blobs.

```
operator:      c45b32c65d25b3d070929aa68fa4532f69fd5ab56fa15173be77d6c5c6d03c18
nonce:         8c10b9bc0b5acdcfb85432747587fbbd8894bbad69f35de6dff46093513daac8
routing_id:    73fbe2ada899507f188a7e0f9c47a639e085caae13198f25aae149b08d1afbd0   (Vector 41's routing id)
Served blobs, concatenated for display ("scp-25-served-blob-a", "scp-25-served-blob-bb"):
  7363702d32352d7365727665642d626c6f622d617363702d32352d7365727665
  642d626c6f622d6262
value_digest = SHA-256(BE32(2) || BE32(len(A)) || A || BE32(len(B)) || B):
  ebbf1905dedb60f162f2cc5190ae0a8cd0adc66bb34e0ea45469bc4957405115
observed_at:   1700000000

Preimage (155 bytes = 19-byte separator + 136 field bytes):
  5343502d52454c41592d50524f4f462d56313ac45b32c65d25b3d070929aa68f
  a4532f69fd5ab56fa15173be77d6c5c6d03c188c10b9bc0b5acdcfb854327475
  87fbbd8894bbad69f35de6dff46093513daac873fbe2ada899507f188a7e0f9c
  47a639e085caae13198f25aae149b08d1afbd0ebbf1905dedb60f162f2cc5190
  ae0a8cd0adc66bb34e0ea45469bc4957405115000000006553f100
Canonical hash:
  39810614f84be6d793191fad3b05efc990dba59f133fbb88bbcd9b17ac2b1957
Signature, reference key (200 bytes on the wire):
  6ed286373d151c207c584f7cb657de8d9cdd734a0a54272bedc8471243037f0f
  3acf0a59d6c4083085715af8f4e509bd484830ea9c3a779f74bac596343c486d
```

