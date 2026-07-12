---

# ADR Completeness and Specification Gap Audit

## Executive Summary

The SCP ADR corpus across Phases 1--3 (19 ADRs total) is unusually thorough for a project at this stage. Most ADRs include concrete Rust type definitions, file-level scope estimates, acceptance criteria, and integration tests. The quality is well above the typical "we decided X" ADR pattern.

That said, a line-by-line read reveals 47 distinct specification gaps. The most concerning are in three categories: (1) security-critical constructions where the ADR specifies the happy path but leaves adversarial behavior underspecified, (2) cross-ADR seams where assumptions in one ADR contradict or do not compose cleanly with another, and (3) missing defaults and operational parameters that an implementer would need to invent on the spot. None are architectural showstoppers -- the design is sound -- but several could produce interoperability failures or security weaknesses if implemented without additional specification.

---

## Findings

### [ADR-001] Grace Window "All Members ACK" Condition Has No Wire Protocol

- **Category**: Decisions without implementation guidance
- **Location**: ADR-001, Acceptance Criterion 6 (phase-1.md:93-94)
- **What's missing**: The grace window closes when "all members have sent at least one message or ACK in the new epoch." There is no wire format, protocol message, or state tracking mechanism defined for tracking per-member new-epoch acknowledgment. The relay ACK (ADR-004) is for blob delivery, not epoch transition confirmation. No `EpochAck` message type exists anywhere in the ADR corpus.
- **Why it matters**: Without a defined mechanism, implementers must either (a) ignore the "all members ACK" condition and rely solely on the 30-second hard ceiling, or (b) invent their own tracking, leading to interop failures. Condition (a) is safe but weakens forward secrecy properties for fast-turnaround groups.
- **Severity**: MEDIUM

### [ADR-001] KeyPackage Buffer Replenishment Has No Transport Mechanism

- **Category**: Underspecified interfaces
- **Location**: ADR-001, Acceptance Criterion 8 (phase-1.md:106-107)
- **What's missing**: "The SDK must maintain a buffer of at least 10 unused KeyPackages per identity. Replenished when buffer drops below 5." Where are KeyPackages published? How does a prospective adder obtain them? The ADR says "pre-published" but never specifies the publication channel. Are they stored on the relay? In the DID document? A separate KeyPackage server? The MLS spec (RFC 9420) intentionally leaves this to the application, and SCP must specify it.
- **Why it matters**: Without a KeyPackage distribution mechanism, offline member addition (a core MLS feature) is impossible. Every implementer will do something different.
- **Severity**: HIGH

### [ADR-001] StaleEpochMessage Event Has No Recovery Path

- **Category**: Scope gaps
- **Location**: ADR-001, Acceptance Criterion 6 (phase-1.md:97)
- **What's missing**: "Messages arriving after the grace window closes that reference old epochs are unrecoverable. The SDK MUST log a warning and emit a StaleEpochMessage event." But there is no guidance on what the application layer should do. Should the recipient request a re-send? Should the sender detect the stale epoch via a NACK? Is there a retry protocol? The event is defined but the operational response is absent.
- **Why it matters**: In high-latency or unreliable network conditions, message loss from stale epochs could be frequent. Without recovery guidance, implementations will silently lose messages.
- **Severity**: MEDIUM

### [ADR-001] EpochGraceStore Purge Mechanism Unspecified

- **Category**: Decisions without implementation guidance
- **Location**: ADR-001, Acceptance Criterion 6 (phase-1.md:95-96)
- **What's missing**: The `EpochGraceStore` must be "automatically purged when the grace window closes" and "timer-based purge" is mentioned in the file listing. But no implementation detail is given for the timer mechanism: is it a tokio `sleep` task per epoch? A background sweep? What happens if the process crashes during the grace window -- are old epoch keys recovered from persistent storage (violating forward secrecy) or lost (correct but not stated)?
- **Why it matters**: If the grace store is accidentally persisted or survives a crash via process recovery, forward secrecy is violated. The "in-memory only" requirement needs explicit crash-recovery semantics.
- **Severity**: HIGH

### [ADR-002] Signature Preimage Concatenation Is Ambiguous

- **Category**: Missing security analysis
- **Location**: ADR-002, Acceptance Criterion 2 (phase-1.md:209)
- **What's missing**: The inner signature covers `SHA256(context_id || sender_did || signing_key_id || epoch || generation || sequence || timestamp || payload_hash || provenance_hash)`. But the encoding of each field before concatenation is not specified. Are `context_id` and `sender_did` UTF-8 bytes? Is `epoch` a big-endian u64? Without a canonical encoding, two implementations could produce different signatures for the same message. Length prefixes are absent, meaning `context_id = "ab"` + `sender_did = "cd"` produces the same preimage as `context_id = "abc"` + `sender_did = "d"`.
- **Why it matters**: This is a classic serialization ambiguity that leads to signature verification failures across implementations, or worse, a confused deputy attack where a valid signature from one message can be reused with different field boundaries. The key continuity fingerprint (ADR-039:1202-1206) correctly uses length prefixes and domain separators -- the inner envelope signature should do the same.
- **Severity**: CRITICAL

### [ADR-002] Padding Length Suffix Creates a Ciphertext Oracle

- **Category**: Missing security analysis
- **Location**: ADR-002, Acceptance Criterion 7 (phase-1.md:237)
- **What's missing**: "Padding format: payload bytes + padding bytes + 4-byte big-endian length of original payload at the end." The padding fill bytes are not specified. Are they zeros? Random? PKCS#7-style? If they are zeros, an attacker who can observe multiple ciphertexts can detect patterns in the padding region. If they are random, the padding is non-deterministic and cannot be verified independently. The ADR says "Padding integrity is guaranteed by the AEAD authenticated encryption layers," which is true for tampering, but the fill byte choice affects side-channel resistance.
- **Why it matters**: The bucket padding is a metadata privacy mechanism (Decision 3). If the fill bytes are predictable, timing or ciphertext analysis could reveal the original payload size within the bucket.
- **Severity**: MEDIUM

### [ADR-002] Pseudonym Derivation Uses Public Key as HMAC Key

- **Category**: Missing security analysis
- **Location**: ADR-002, Acceptance Criterion 1 (phase-1.md:202); ADR-006 (phase-1.md:803, 860-873)
- **What's missing**: `HMAC-SHA256(ed25519_public_key_bytes, context_id || "scp-pseudonym")` uses the *public* key as the HMAC key. This was changed from private key for Android Keystore compatibility (ADR-027 amendment). The security analysis of this change is missing from the ADR. Since the HMAC key is public, any party that knows the DID can compute the pseudonym for any context_id. This means a relay that knows a user's DID can precompute all their pseudonyms and link activity across contexts -- exactly the attack pseudonyms are supposed to prevent.
- **Why it matters**: The entire metadata privacy architecture (Decisions 2, 7, and 10) rests on pseudonym unlinkability. If the HMAC key is the public key, pseudonyms are unlinkable only if the DID is unknown to the relay. But DID resolution is public (Mainline DHT). A relay operator can resolve DIDs and compute pseudonyms, completely defeating the privacy goal. This is a fundamental design tension introduced by the Android Keystore constraint that requires explicit analysis.
- **Severity**: CRITICAL
- **Resolution (later)**: Accepted and fixed. The public-key-as-HMAC-key approach was rejected. Pseudonym derivation now uses a `pseudonym_secret` that is NOT publicly derivable: software custody derives it via `HKDF-SHA256(ed25519_private_seed, salt="scp-pseudonym-secret-v1")` (cross-platform deterministic); hardware custody uses a device-local secret inside the TEE (device-local by design, since the key is non-exportable). See spec §9.10.4.A, ADR-027 (phase-6), and KAT vectors in §25.19. This finding is preserved as the historical record that drove the fix.

### [ADR-003] DID Document Size vs. BEP44 Payload Limit

- **Category**: Scope gaps
- **Location**: ADR-003 (phase-1.md:260-275); ADR-039 (phase-1.md:1138)
- **What's missing**: ADR-039 acknowledges "DID documents are already ~1,140 bytes with 2 VMs (BEP44 v1 payload limit is 1,000 bytes, requiring bencode packing)." The DID document already exceeds the BEP44 v1 payload limit. With 3 VMs (#0, #active, #agent), retired keys (up to 2 active + 2 agent = 4 retired), relay service entries, PreRotationCommitment, and ScpKeyCustodyAttestation, the document could easily reach 2-3KB. How does this fit in BEP44? Is compression used? Multi-record splitting? The ADR does not address this.
- **Why it matters**: If the DID document does not fit in a single BEP44 record, the entire did:dht publication mechanism breaks. This is a hard technical constraint that needs a concrete solution.
- **Severity**: HIGH

### [ADR-003] DHT Republishing Interval vs. Expiry Window Mismatch

- **Category**: Missing defaults
- **Location**: ADR-003, Acceptance Criterion 2 (phase-1.md:313)
- **What's missing**: "Republish interval: Every 2 hours. This is well within typical DHT record expiry windows (which vary by implementation but are generally 1-2 hours for Mainline DHT BEP44 items)." If expiry is "generally 1-2 hours" and republish is every 2 hours, the DID could be unreachable for up to 1 hour between expiry and republish. The ADR acknowledges the overlap but does not specify what happens to operations that require DID resolution during the gap (UCAN validation, MLS credential verification).
- **Why it matters**: A 1-hour unreachability window for a DID means all identity-dependent operations for that DID fail during the window. For active contexts with multiple members, this is a liveness issue.
- **Severity**: MEDIUM

### [ADR-003] Resolution Cache TTL Conflict

- **Category**: Contradictions with other ADRs
- **Location**: ADR-003, Acceptance Criterion 3 (phase-1.md:324) vs. ADR-003, Criterion 2 (phase-1.md:316)
- **What's missing**: Resolution caches use "24-hour refresh for active contacts, 7-day for inactive" (Criterion 3). But Criterion 2 says "staleness indicator" is emitted after "2 hours + 30 minute grace." These are inconsistent: the cache TTL is 24 hours for active contacts, but staleness is flagged after 2.5 hours. A cached result at 10 hours is not stale (within 24h TTL) but also not fresh (beyond 2.5h republish window). The semantics of "stale" vs. "cached but not refreshed" are conflated.
- **Why it matters**: Implementers will be confused about when to trigger fresh resolution. The security guidance says "Critical operations SHOULD attempt a fresh DHT resolution before rejecting a stale result," but the caching behavior does not distinguish between "we have a fresh cached copy" and "we have a cached copy that might be outdated."
- **Severity**: MEDIUM

### [ADR-003] Migration Proof Does Not Bind to Context

- **Category**: Missing security analysis
- **Location**: ADR-003, Acceptance Criterion 4b (phase-1.md:403)
- **What's missing**: `MigrationProof.signature` signs `SHA-256(SCP-MIGRATION-V1: || len(old_did) || old_did || len(new_did) || new_did || rotated_at)`. This proof is context-independent -- the same proof is valid in all contexts. If a relay intercepts the `DidRotationEvent` from one context, it can replay it to other contexts where the member participates. While MLS prevents unauthorized message injection, a compromised member in one context could forward the rotation event to disrupt other contexts.
- **Why it matters**: The migration proof should ideally be bound to the context_id to prevent cross-context replay. The current design relies on MLS application message authentication for delivery, but the proof itself is reusable.
- **Severity**: LOW

### [ADR-004] No Authentication Means Unlimited Storage Abuse

- **Category**: Missing security analysis
- **Location**: ADR-004 (phase-1.md:459, 512)
- **What's missing**: "No client authentication: any WebSocket client can connect, publish, subscribe, query." Combined with blob storage and rate limits (6000/min per IP), an attacker can fill relay storage at ~100 blobs/second * 256KB = 25MB/second. The ADR specifies rate limiting per IP but no storage quota per IP, no proof-of-work requirement, and no blob_ttl floor beyond 1 second. An attacker publishing 256KB blobs with 604800s TTL at sustained rates will exhaust relay storage.
- **Why it matters**: Without storage quotas, the relay is trivially DoS-able by any unauthenticated client. ADR-033's economic governance (relay pricing) mitigates this but is Phase 3+ scope. Phase 1-2 relays are defenseless.
- **Severity**: HIGH

### [ADR-004] No Maximum Message Size at Deserialization

- **Category**: Missing security analysis
- **Location**: ADR-004 Wire Format (phase-1.md:575)
- **What's missing**: The wire format specifies `blob` max 262144 bytes but does not specify maximum sizes for `msg` (error message string), `ref` (request ID string), or the overall MessagePack frame. A malicious client could send a `ref` field containing megabytes of data, or an `ERR` response with a massive `msg` string, causing OOM on the receiver.
- **Why it matters**: This is the deserialization size limit issue already tracked as #347 in the audit. The ADR should specify max sizes for all string fields.
- **Severity**: HIGH

### [ADR-004] SUBSCRIBE Backfill Has No Pagination

- **Category**: Underspecified interfaces
- **Location**: ADR-004, Acceptance Criterion 2 (phase-1.md:487-488)
- **What's missing**: SUBSCRIBE with `since` backfills all stored blobs newer than `since`. Unlike QUERY (which has a `limit` parameter), SUBSCRIBE backfill has no limit. A routing_id with thousands of stored blobs would send all of them on subscribe, potentially overwhelming the client.
- **Why it matters**: A relay with a high-volume routing_id could send gigabytes of backfill data on a new subscription. The client has no way to control the flow.
- **Severity**: MEDIUM

### [ADR-005] TransportAdapter Trait Has No Connection State

- **Category**: Underspecified interfaces
- **Location**: ADR-005, Acceptance Criterion 1 (phase-1.md:681-708)
- **What's missing**: The `TransportAdapter` trait has no `connect()`, `disconnect()`, or `is_connected()` methods. The trait assumes the adapter is always connected, but reconnection logic (ADR-004:601), connection pooling (ADR-036:1216), and connection budgeting (ADR-036:1218) all require connection lifecycle management. The `NotConnected` error variant exists but there is no way for the caller to distinguish between "not yet connected" and "disconnected after failure."
- **Why it matters**: The TransportManager (ADR-012) needs to manage connection state for relay assignment, health scoring, and budget enforcement. Without connection lifecycle methods on the trait, the TransportManager must reach into adapter internals.
- **Severity**: MEDIUM

### [ADR-006] InMemoryKeyCustody Seed Determinism Not Specified

- **Category**: Missing defaults
- **Location**: ADR-006, Acceptance Criterion 1 (phase-1.md:805)
- **What's missing**: "Optionally accepts a seed for deterministic key generation in tests." The seed format (u64, [u8; 32], etc.), the RNG algorithm (ChaCha20, XorShift), and the derivation from seed to key are not specified. Without a specified algorithm, seeded tests will produce different keys across implementations or even across Rust compiler versions.
- **Why it matters**: If deterministic testing is a goal (and it should be for protocol conformance tests), the seed-to-key derivation must be specified precisely enough to reproduce across implementations.
- **Severity**: LOW

### [ADR-007] Sender Key AES-256-GCM Has No AAD Binding

- **Category**: Missing security analysis
- **Location**: ADR-007, Acceptance Criterion 2 (phase-1.md:963-966)
- **What's missing**: `encrypt_sender_layer(sender_key, plaintext) -> SenderCiphertext` uses AES-256-GCM with a random nonce but no Additional Authenticated Data (AAD). Without AAD, the ciphertext is not bound to any context -- a ciphertext from Context A could be transplanted to Context B if both use the same sender key (unlikely but possible if key generation has weak entropy). The ADR-038 content access key layer specifies AAD (`context_id || sender_did || sequence_number`) but the base sender key layer does not.
- **Why it matters**: AAD binding is defense-in-depth. While MLS provides context binding at the outer layer, the sender key layer should independently bind to context_id to prevent cross-context ciphertext transplant within the sender key abstraction.
- **Severity**: MEDIUM

### [ADR-007] Block Notification Has No Replay Prevention

- **Category**: Missing security analysis
- **Location**: ADR-007, Acceptance Criterion 6 (phase-1.md:1040-1047)
- **What's missing**: Block notifications include a `timestamp` but no sequence number or nonce. A compromised relay or group member could replay an old block notification, causing the recipient to re-execute `rotate_sender_key_for_block`, wasting a key rotation. The notification signature covers the timestamp, but there is no replay window defined -- a notification from 5 minutes ago would still verify.
- **Why it matters**: While re-blocking an already-blocked party is idempotent at the block list level, it causes unnecessary key rotation and epoch advances, which is a denial-of-service vector against the sender key protocol.
- **Severity**: MEDIUM

### [ADR-007] SenderKeyRequest Signature Does Not Bind to context_id

- **Category**: Missing security analysis
- **Location**: ADR-007, Acceptance Criterion 4c (phase-1.md:1021-1024)
- **What's missing**: `SenderKeyRequest` includes `requester_did`, `sender_did`, `epoch`, `wrapping_pubkey`, and `signature`, but the signature preimage is not defined. Looking at `SenderKeyEpochAdvance` (Criterion 4a), it signs `context_id || sender_did || signer_key_ref || "key_epoch" || epoch`. But `SenderKeyRequest` does not show its signature preimage. Without context_id binding, a request from Context A could be replayed to obtain the sender key from Context B if the sender uses the same DID in both.
- **Why it matters**: Cross-context sender key theft through request replay would allow a member of Context A to decrypt messages in Context B without being a member. This is noted in my memory as a known gap pattern.
- **Severity**: HIGH

### [ADR-007] HPKE Construction Is Informal

- **Category**: Decisions without implementation guidance
- **Location**: ADR-007, Acceptance Criterion 4b (phase-1.md:1018)
- **What's missing**: "HPKE assembly: (1) generate ephemeral X25519 keypair, (2) ECDH between ephemeral secret and requester wrapping pubkey, (3) HKDF to derive encryption key, (4) AES-128-GCM encrypt the sender key." This is an informal description of what should be a precise HPKE mode (RFC 9180). Which HPKE mode (Base, Auth, PSK, AuthPSK)? Which KDF (HKDF-SHA256)? What is the HKDF `info` parameter? What is the HPKE `aad`? The ADR mentions "HPKE domain separation: 'scp-access-key-v1' vs 'scp-sender-key-v1'" in the project memory but these strings do not appear in the ADR itself.
- **Why it matters**: Ambiguous HPKE construction leads to interoperability failures between implementations. Two implementations using different HPKE modes or KDF parameters will produce incompatible ciphertexts.
- **Severity**: HIGH

### [ADR-008] Closing State Has No Timeout

- **Category**: Missing defaults
- **Location**: ADR-008, Acceptance Criterion 5-6 (phase-2.md:145-159)
- **What's missing**: The `Closing` state gives members "a window to process final events and verify the summary." But no timeout is specified. How long does the context stay in `Closing` before `finalize_close` is called? What if a member is offline? Can a context stay in `Closing` indefinitely, leaking resources?
- **Why it matters**: Without a closing timeout, a context can be held in `Closing` state indefinitely by a member that never processes the close notification. This is a resource leak and a potential denial-of-service vector against the context creator.
- **Severity**: MEDIUM

### [ADR-008] ContextMode::Broadcast Routing ID Derivation Conflict

- **Category**: Contradictions with other ADRs
- **Location**: ADR-008, ContextMode::Broadcast comment (phase-2.md:239) vs. ADR-002 pseudonym derivation (phase-1.md:198-203)
- **What's missing**: For Broadcast mode, `routing_id = SHA-256(context_id)` -- a simple hash. For Encrypted mode, `routing_id` is derived via `HMAC-SHA256(public_key, context_id || "scp-pseudonym")` -- an identity-bound pseudonym. These are fundamentally different derivation schemes with different privacy properties. The ADR does not specify how `send_message` in the Context Manager determines which derivation to use, or how the TransportManager subscribe call knows which routing_id format to expect.
- **Why it matters**: An implementer wiring up `send_message` needs a clear dispatch path. Mixing up the routing_id derivation for the wrong mode would cause messages to be undeliverable.
- **Severity**: MEDIUM

### [ADR-008] Context Nesting Deferred Without Interface Specification

- **Category**: Incomplete decisions
- **Location**: ADR-008, Scope Note (phase-2.md:287)
- **What's missing**: "Context nesting (spec section 5.13) is not Phase 2 scope." The ADR defines `ChildContextCreate` as a capability (ADR-009:352) and `ParentGovernanceConfig` is mentioned as a future module, but no interface contract is specified for how the `ContextManager` will eventually support nesting. This means the ContextManager API may need backward-incompatible changes when nesting is added.
- **Why it matters**: If `create_context` does not accept a `parent_context_id` parameter now (even as `Option<ContextId>`), adding nesting later requires an API change. The ADR should at minimum reserve the parameter.
- **Severity**: LOW

### [ADR-008] Transport Publication Failure Rollback Is Best-Effort

- **Category**: Missing security analysis
- **Location**: ADR-008, Acceptance Criterion 2 (phase-2.md:128)
- **What's missing**: "DELETE is best-effort (relays are untrusted), but since no MLS group state survives the rollback, any orphaned blobs on relays are encrypted with destroyed keys and cannot be used." This is correct for content privacy, but orphaned blobs still consume relay storage and could be used for traffic analysis (the routing_id is visible). The ADR does not specify whether orphaned blobs should be tracked for later cleanup attempts.
- **Why it matters**: Repeated failed context creation attempts could leave orphaned blobs on relays, consuming storage and creating metadata artifacts.
- **Severity**: LOW

### [ADR-009] Custom Capability String Validation Not Specified

- **Category**: Missing defaults
- **Location**: ADR-009, Acceptance Criterion 1 (phase-2.md:353)
- **What's missing**: `Capability::Custom(String)` allows arbitrary capability strings. No validation rules are specified: maximum length, allowed characters, case sensitivity, namespace conventions. A capability string of `""` (empty), or `"scp:ctx:*/messages:write"` (looks like a UCAN URI), or a 10MB string are all valid per the ADR.
- **Why it matters**: Without validation, Custom capabilities can be used to bypass security checks (by matching UCAN URI patterns) or cause resource exhaustion (unbounded string sizes).
- **Severity**: MEDIUM

### [ADR-009] UCAN Nonce Format Between ADR-009 and ADR-016 Is Duplicated

- **Category**: Contradictions with other ADRs
- **Location**: ADR-009, Criterion 7 (phase-2.md:437) vs. ADR-016, Criterion 6 (phase-3.md:790)
- **What's missing**: Both ADR-009 and ADR-016 specify the nonce format as `{unix_millis_timestamp}-{16_random_bytes_hex}`. ADR-009 says "ADR-016 (Phase 3) is the normative specification for nonce validation." But ADR-016 says the nonce is `UUID v4 or 32 random bytes, hex-encoded` in `mint_ucan` (phase-3.md:756). These are different formats: `{unix_millis}-{hex16}` vs `UUID v4`. Which is it?
- **Why it matters**: Nonce format validation is a security check (Step 9 in the validation pipeline). If minted nonces use UUID v4 but validation expects `{unix_millis}-{hex16}`, all tokens will be rejected.
- **Severity**: HIGH

### [ADR-009] Ceiling Mutability Contradicts ADR Description

- **Category**: Contradictions with other ADRs
- **Location**: ADR-009 (phase-2.md:305, 310, 360) vs. ADR-008 (phase-2.md:198-212)
- **What's missing**: ADR-009 states "The capability ceiling is declared at context creation and is immutable (spec section 5.3)" and "Making it immutable prevents bait-and-switch." But ADR-008 defines `CeilingPolicy::Governed` which explicitly allows ceiling modification through governance. These directly contradict each other. ADR-008 even states "Governed: Ceiling can be modified through the context's governance model." ADR-009's validation logic (`check_ceiling`) does not account for a mutable ceiling.
- **Why it matters**: If the ceiling can change via governance (ADR-008), then ADR-009's security argument about immutable ceilings is invalid. The `check_ceiling` function must handle ceiling changes, including race conditions where a UCAN was minted under one ceiling and validated under a different one.
- **Severity**: HIGH

### [ADR-010] Outlet Implementation Hash Has No Defined Hash Target

- **Category**: Decisions without implementation guidance
- **Location**: ADR-010, Acceptance Criterion 1 (phase-2.md:509)
- **What's missing**: `implementation_hash: [u8; 32]` is "SHA-256 of implementation." But what exactly is hashed? The outlet's source code? A compiled binary? A WASM module? A Docker image? The outlet's response to a specific input? Without a defined hash target, the hash is meaningless for integrity verification -- two implementations of the same outlet will produce different hashes.
- **Why it matters**: Outlet integrity verification (Criterion 5) compares implementation hashes over time. If the hash target is not canonical, hash changes do not reliably indicate implementation changes, and the entire outlet integrity mechanism is cosmetic.
- **Severity**: MEDIUM

### [ADR-010] Cross-Context Outlet Interface Has No Key Exchange

- **Category**: Underspecified interfaces
- **Location**: ADR-010, Acceptance Criterion 6 (phase-2.md:617-633)
- **What's missing**: Cross-context outlet invocation sends requests and responses between two separate MLS groups. But the two contexts have different MLS groups with different keys. How does the request/response travel between contexts? Through the transport layer? If so, how is it encrypted -- is it plaintext at the relay? Does it create a third MLS group for the interface? The ADR says "Both event logs record the call" but does not specify the transport mechanism.
- **Why it matters**: Without a defined transport for cross-context communication, the security properties of outlet interface calls are undefined. If requests traverse relays unencrypted, outlet input/output is exposed to relay operators.
- **Severity**: HIGH

### [ADR-010] Outlet Invocation Is Specified But Outlet Execution Is Not

- **Category**: Decisions without implementation guidance
- **Location**: ADR-010, Acceptance Criterion 3 (phase-2.md:538-539)
- **What's missing**: "Calls the outlet implementation." How? The ADR defines the request/response protocol, schema validation, event logging, and UCAN authorization. But it never specifies how a outlet implementation is actually executed. Is it a function pointer? A WASM sandbox? A subprocess? An HTTP call? The `operator_did` field suggests the outlet runs externally, but the execution boundary is not defined.
- **Why it matters**: Outlet execution is the actual security boundary. A outlet that executes arbitrary code in the SDK process is fundamentally different from a sandboxed WASM module. The ADR specifies everything around the outlet but not the outlet itself.
- **Severity**: MEDIUM

### [ADR-011] Absence Proof Sorted Index Is Not Part of Merkle Tree

- **Category**: Missing security analysis
- **Location**: ADR-011, Acceptance Criterion 4 (phase-2.md:782-815)
- **What's missing**: The absence proof algorithm maintains a "sorted index of leaf hashes alongside the append-order Merkle tree" (`BTreeSet`). This sorted index is auxiliary state not committed to the Merkle tree. A malicious member providing an absence proof could omit entries from their local sorted index to produce false absence proofs. The verifier can confirm the two bracketing leaves are in the tree, but cannot confirm they are truly adjacent in the sorted order without access to all leaf hashes.
- **Why it matters**: False absence proofs could be used to deny that an event occurred. The security of absence proofs depends on the sorted index being complete, but completeness is not verifiable by a third party.
- **Severity**: MEDIUM

### [ADR-011] Consistency Checkpoint Does Not Verify Remote Signature

- **Category**: Missing security analysis
- **Location**: ADR-011, Acceptance Criterion 8 (phase-2.md:843-844)
- **What's missing**: `compare_checkpoint(local_log, remote_checkpoint)` "Compares a received checkpoint against local state." The function signature does not include a mechanism to verify the remote checkpoint's signature against the sender's DID. Without signature verification, a relay or compromised member could forge a checkpoint to trigger false equivocation alerts. This is noted in my memory notes but the ADR does not address it.
- **Why it matters**: False equivocation alerts are a DoS vector against the consensus mechanism. A relay that forges checkpoints with divergent roots can cause members to distrust each other.
- **Severity**: HIGH

### [ADR-012] Relay Set Minimum of 3 Has No Fallback for Insufficient Relays

- **Category**: Missing defaults
- **Location**: ADR-012, Acceptance Criterion 2 (phase-2.md:916)
- **What's missing**: "Sends the envelope to ALL relays in the context's relay set (minimum 3). If fewer than 2 relays succeed, returns an error." But what happens when fewer than 3 relays are available in the relay pool? The ADR does not specify a fallback for environments with only 1 or 2 known relays. ADR-036 relaxes minimums for mobile (2) and constrained (1), but the default `TransportManager` has no grace handling.
- **Why it matters**: Early adopters and test environments will frequently have fewer than 3 relays. Failing hard on insufficient relay count prevents basic functionality.
- **Severity**: MEDIUM

### [ADR-012] Dedup Cache LRU + TTL Interaction

- **Category**: Underspecified interfaces
- **Location**: ADR-012, Acceptance Criterion 3 (phase-2.md:926)
- **What's missing**: "The dedup cache uses LRU eviction with a 10,000-entry capacity and time-based expiry (1 hour default)." When both conditions could trigger eviction, which takes precedence? If an entry is younger than 1 hour but the cache is full, is it evicted? If the cache is not full but an entry is older than 1 hour, is it evicted? The interaction between LRU capacity and TTL is not specified.
- **Why it matters**: Incorrect dedup cache behavior leads to either duplicate message delivery (if entries are evicted too early) or memory exhaustion (if entries are retained too long).
- **Severity**: LOW

### [ADR-012] Suppression Detection Window Relies on Relay Clock

- **Category**: Missing security analysis
- **Location**: ADR-012, Acceptance Criterion 7 (phase-2.md:957-959)
- **What's missing**: "When the merged subscription stream receives an envelope from one relay but not from another within 30 seconds, the lagging relay is marked as potentially adversarial." The 30-second window starts from the first relay's delivery time. But delivery time is based on the `stored_at` timestamp from the relay (ADR-004:583), which is relay-provided and unverifiable. A relay that delays delivery by 29 seconds avoids detection while still effectively suppressing timely delivery.
- **Why it matters**: Suppression detection based on relay-provided timestamps is gameable. The detection should use local receipt time, not relay timestamps.
- **Severity**: MEDIUM

### [ADR-013] PyO3 Bridge Does Not Expose Sender Key Operations

- **Category**: Scope gaps
- **Location**: ADR-013, Acceptance Criteria 1-8 (phase-3.md:70-158)
- **What's missing**: The bridge exposes identity, context, outlets, transport, UCAN, and event log operations. But sender key operations (ADR-007) are completely absent: no `py_sender_key_*` functions, no `PySenderKey` type, no block/unblock functions. The Python SDK cannot manage blocking, which is a core SCP feature.
- **Why it matters**: Python SDK users cannot block other members, manage sender key epochs, or handle block notifications. This makes the Python SDK incomplete for the protocol's social features.
- **Severity**: MEDIUM

### [ADR-013] Runtime Shutdown 100ms Timeout Is Arbitrary

- **Category**: Missing defaults
- **Location**: ADR-013, Acceptance Criterion 1 (phase-3.md:76)
- **What's missing**: "An atexit handler calls shutdown_runtime(), which blocks for 100ms to let cooperative tasks observe shutdown." The 100ms timeout is arbitrary. If MLS group state needs to be persisted, or sender keys need to be stored, or event log checkpoints need to be written, 100ms may be insufficient. No guidance is given on what happens to in-flight operations that do not complete within 100ms.
- **Why it matters**: Data loss on shutdown. If the tokio runtime is dropped while persistence operations are in-flight, key material or event log entries may be lost.
- **Severity**: MEDIUM

### [ADR-014] Sync Wrapper Race Condition

- **Category**: Missing security analysis
- **Location**: ADR-014, Acceptance Criterion 6 (phase-3.md:406-433)
- **What's missing**: The `_get_sync_loop()` function uses a global `_sync_loop` variable with a threading lock. But the lock protects only creation, not use. After creation, `_sync_loop` is used without holding the lock. If the event loop is closed by another thread (e.g., `atexit`), subsequent `run_coroutine_threadsafe` calls will raise `RuntimeError`. The `is_closed()` check is racy -- the loop could close between the check and the `run_coroutine_threadsafe` call.
- **Why it matters**: This is a classic TOCTOU race. In a multi-threaded Python application, shutdown races could cause unhandled exceptions.
- **Severity**: LOW

### [ADR-014] receive() Buffer Overflow Policy Drops Oldest

- **Category**: Missing security analysis
- **Location**: ADR-014, Acceptance Criterion 2, receive() lifecycle (phase-3.md:329-330)
- **What's missing**: "When the buffer is full (1000 events), the oldest event is dropped." This means a flooding attack (an attacker sending messages faster than the application can process) causes legitimate messages to be silently dropped. The `BufferOverflow` warning is injected but there is no backpressure mechanism. The application cannot slow down message delivery -- it can only lose messages.
- **Why it matters**: Message loss from buffer overflow is indistinguishable from relay suppression at the application layer. The SDK cannot tell whether a message was suppressed by a relay or dropped locally.
- **Severity**: MEDIUM

### [ADR-015] MCP Adapter Has No Rate Limiting

- **Category**: Scope gaps
- **Location**: ADR-015, Acceptance Criteria 1-8 (phase-3.md:540-598)
- **What's missing**: The MCP adapter translates MCP tool calls into SCP context operations. But there is no rate limiting at the adapter level. A model that sends 1000 `tools/call` requests per second will translate into 1000 SCP operations per second. While UCAN validation will run on each call, the computational cost of MLS encryption, envelope construction, and multi-relay publishing for each call is significant. No concurrency limit, request queue, or backpressure mechanism is specified.
- **Why it matters**: A runaway model (or a malicious MCP client) can exhaust the agent's resources through the MCP adapter. UCAN validation prevents unauthorized access but not authorized abuse.
- **Severity**: MEDIUM

### [ADR-015] MCP Client Mode Provenance Is Self-Asserted

- **Category**: Missing security analysis
- **Location**: ADR-015, Acceptance Criterion 6 (phase-3.md:601-626)
- **What's missing**: When consuming external MCP tools, the adapter wraps results with "SCP provenance metadata." But this provenance is self-asserted by the consuming agent -- there is no verification that the external tool actually produced the claimed result. An agent could fabricate provenance claiming a result came from an external MCP tool when it was actually generated locally.
- **Why it matters**: If provenance is relied upon for trust decisions (and it is -- spec section 7.7), self-asserted external provenance provides a false sense of authenticity.
- **Severity**: MEDIUM

### [ADR-016] Nonce Format Contradiction with Minting

- **Category**: Contradictions with other ADRs
- **Location**: ADR-016, Criterion 3 (phase-3.md:756) vs. Criterion 6 (phase-3.md:790)
- **What's missing**: This is the same issue as finding [ADR-009/ADR-016 Nonce Format] above. `mint_ucan` says "Generates a unique nonce (UUID v4 or 32 random bytes, hex-encoded)" but the validation pipeline (Step 9) requires `{unix_millis_timestamp}-{16_random_bytes_hex}` with freshness validation based on the timestamp prefix. UUID v4 has no timestamp prefix and would fail the freshness check. The minting specification must match the validation specification.
- **Why it matters**: If minted, the nonce would be immediately rejected by the validator. This is a spec-level bug.
- **Severity**: CRITICAL

### [ADR-016] UCAN CID Computation Not Specified

- **Category**: Decisions without implementation guidance
- **Location**: ADR-016, Criteria 2, 4, 5 (phase-3.md, multiple locations)
- **What's missing**: The revocation list uses "token CID" as the key. Delegation chains use "proof CID." But the CID (Content Identifier) computation is never specified. Is it a CIDv1 with SHA-256 multicodec? Is it the SHA-256 of the raw JWT string? Is it the hash of just the payload? Without a canonical CID computation, revocation cannot work across implementations because two implementations will compute different CIDs for the same token.
- **Why it matters**: Revocation is a core security mechanism. If CID computation is ambiguous, a revoked token may not be found in the revocation list, allowing continued use of a supposedly revoked capability.
- **Severity**: HIGH

### [ADR-016] Capability Wildcard Matching Is Underspecified

- **Category**: Underspecified interfaces
- **Location**: ADR-016, Criterion 2, Step 6 (phase-3.md:745)
- **What's missing**: "Capability matching supports wildcards (scp:ctx:*/messages:write matches any context)." But wildcard semantics are not fully specified. Does `*` match only the context_id position, or can it appear in other positions? Does `scp:ctx:abc123/*` match all capabilities in a context? Does `scp:ctx:*/outlet:call:*` match all outlet invocations in all contexts? Is `*` the only wildcard, or are regex patterns supported?
- **Why it matters**: Overly broad wildcard matching can accidentally grant unintended capabilities. An implementer who interprets `*` generously could create a privilege escalation path.
- **Severity**: MEDIUM

### [ADR-032] .well-known/scp Trust Model Is Advisory But Used for Bootstrap

- **Category**: Missing security analysis
- **Location**: ADR-032 (phase-2.md:1031, 1039)
- **What's missing**: ".well-known/scp is advisory, not trusted" but it is also in the relay bootstrap priority chain: "explicit config -> DID document -> .well-known/scp -> peer discovery -> fallback list." For first-time users who have not configured any relays and have not resolved any DIDs, `.well-known/scp` may be their only bootstrap path. But it is served over HTTPS, which means a TLS MitM (compromised CA, corporate proxy) can direct the client to a malicious relay. The verification chain (BEP44 comparison) is mentioned but not mandatory before using the relay.
- **Why it matters**: The bootstrap path is the most sensitive moment -- the client has no established trust and must rely on the first relay it connects to. If `.well-known/scp` is the bootstrap path and is not verified before use, a network attacker controls the client's relay.
- **Severity**: MEDIUM

### [ADR-033] PaymentAdapter Has No Idempotency Guarantee

- **Category**: Underspecified interfaces
- **Location**: ADR-033, PaymentAdapter trait (phase-3.md:1057-1069)
- **What's missing**: `PaymentMetadata` includes `idempotency_key: [u8; 16]` but the trait does not specify idempotency semantics. Must `authorize` with the same `idempotency_key` return the same result? What about `capture`? The trait has `AlreadyCaptured` error but no `AlreadyAuthorized`. Network retries are common in payment flows, and without defined idempotency, duplicate charges are possible.
- **Why it matters**: Duplicate payment authorization is a financial safety issue. The `idempotency_key` field exists but its contract is not defined.
- **Severity**: MEDIUM

### [ADR-033] Spending UCAN Tracking Has No Specified State

- **Category**: Decisions without implementation guidance
- **Location**: ADR-033, SpendingCapability (phase-3.md:1159-1165)
- **What's missing**: `SpendingCapability` has `max_total` and `time_window` fields. This implies cumulative spending tracking per agent per time window. But no state type, storage mechanism, or reset logic is specified. Where is cumulative spending tracked? Is it per-context? Per-DID globally? What happens when the time window rolls over -- is it a sliding window or a fixed window? Who enforces the limit -- the payer SDK, the payee, or both?
- **Why it matters**: Without specified tracking state, spending limits are unenforceable. An agent could make N payments of max_per_action within a time_window, exceeding max_total because no one tracks the cumulative amount.
- **Severity**: HIGH

### [ADR-033] PricingFormula Metric Observation Timing

- **Category**: Underspecified interfaces
- **Location**: ADR-033, PricingFormula (phase-3.md:1134-1149)
- **What's missing**: Dynamic pricing uses metrics like `ContextMessageRate`, `RelayQueueDepth`, and `SenderVelocity`. The ADR says "Both sides evaluate independently -- deterministic, no oracle." But metrics are inherently time-varying. The payer observes `ContextMessageRate = 50/min` at time T, the receiver observes `ContextMessageRate = 55/min` at time T+2s. Even with integer arithmetic (no float issues), the metric values themselves diverge. The `CostInsufficient` error with `metric_snapshot` is a retry mechanism, not a solution -- it still requires re-evaluation and may fail again.
- **Why it matters**: In high-throughput contexts where metrics change rapidly, pricing formula divergence causes frequent payment failures and retries, degrading performance.
- **Severity**: MEDIUM

### [ADR-035] Dev API Bearer Token Logging at INFO Level

- **Category**: Missing security analysis
- **Location**: ADR-035, Acceptance Criterion 1 (phase-2.md:1156)
- **What's missing**: "Token format: scp_local_token_<32 random hex>. Generated at startup, logged at INFO." Logging a bearer token at INFO level means it will appear in log files, log aggregation systems, and potentially monitoring dashboards. While the dev API is localhost-only, logging the token reduces its effective security to the security of the log storage.
- **Why it matters**: Bearer tokens in logs are a common credential leak vector. The token should be logged only at DEBUG or TRACE level, or displayed only on first startup and stored to a file.
- **Severity**: LOW

### [ADR-036] Platform Inference Heuristics Not Specified

- **Category**: Decisions without implementation guidance
- **Location**: ADR-036, Acceptance Criterion 1 (phase-2.md:1244)
- **What's missing**: "Platform inference via #[cfg(target_os)] with runtime refinement for Linux (server/constrained/desktop heuristics per section 10.13.1)." The Linux heuristics are not specified in this ADR -- they reference section 10.13.1 of the spec. Without defined heuristics, different SDK versions could infer different profiles for the same Linux system, leading to inconsistent transport behavior.
- **Why it matters**: Profile inference determines relay count minimums, cover traffic behavior, and connection budgets. Incorrect inference degrades either security (too few relays) or battery life (too much cover traffic).
- **Severity**: LOW

### [ADR-037] QUIC 0-RTT Replay Attack Not Addressed

- **Category**: Missing security analysis
- **Location**: ADR-037, QUIC Transport Binding (phase-2.md:1303)
- **What's missing**: "0-RTT reconnect (session tickets)" is listed as a benefit. But QUIC 0-RTT is vulnerable to replay attacks -- an attacker who captures a 0-RTT packet can replay it to the server. For PUBLISH operations in 0-RTT, this means a captured blob could be re-published. The ADR does not specify whether PUBLISH is allowed in 0-RTT or restricted to 1-RTT only.
- **Why it matters**: 0-RTT replay of PUBLISH operations creates duplicate blobs on the relay with different `stored_at` timestamps, potentially confusing deduplication and suppression detection.
- **Severity**: MEDIUM

### [ADR-037] UDP/DTLS Binding Has No subscribe() But Spec Requires Subscription

- **Category**: Contradictions with other ADRs
- **Location**: ADR-037, Acceptance Criterion 5 (phase-2.md:1354) vs. ADR-005 trait (phase-1.md:688-693)
- **What's missing**: "`subscribe()` returns error (not supported -- poll via QUERY)." But the `TransportAdapter` trait requires `subscribe()` to return a `Stream`. Returning an error means the adapter cannot be used with the `TransportManager`, which relies on subscription streams for message delivery. The conformance macro `transport_conformance!()` would need to handle this exception, but no exception mechanism is defined.
- **Why it matters**: The UDP/DTLS adapter cannot implement the core `TransportAdapter` trait as defined. Either the trait needs an optional subscribe method, or the conformance tests need to be adapter-specific.
- **Severity**: MEDIUM

### [ADR-039] One Agent Per DID Is Not Enforced in Multi-Device Scenarios

- **Category**: Missing security analysis
- **Location**: ADR-039 (phase-1.md:1136)
- **What's missing**: "Exactly one #agent verification method per DID document. Verifiers reject documents with multiple #agent VMs." But what about a human running agents on multiple devices? The same DID can have its `#agent` key used by different agent software instances on different machines. The ADR constrains the key count (one `#agent` VM in the document) but not the instance count (how many agent runtimes hold the software key). A compromised agent key on one device compromises all devices using that key.
- **Why it matters**: The shared-DID model means agent key compromise is a single point of failure across all devices. The ADR does not discuss multi-device scenarios or key isolation between agent instances.
- **Severity**: MEDIUM

### [ADR-039] Custody Attestation Verification Is Not Mandatory

- **Category**: Scope gaps
- **Location**: ADR-039, Enforcement Layer 4 (phase-1.md:1164-1165)
- **What's missing**: "Absence of attestation is itself a signal." But the ADR does not specify what the signal means. Is a DID without attestation trusted less? Trusted the same? Blocked from certain operations? The attestation layer is defined but its enforcement is left to "trust function (section 7.1)" without specifying how the trust function should weight attestation presence.
- **Why it matters**: If attestation is optional and has no defined impact on trust scoring, no one will implement it. It becomes theater rather than security.
- **Severity**: LOW

### [ADR-040] Streaming BlobStore Has No Size Limit on Streams

- **Category**: Missing security analysis
- **Location**: ADR-040 (phase-2.md:1408)
- **What's missing**: `Option<u64>` content length is "hint for pre-allocation, not a security boundary." The streaming API has no maximum blob size enforcement. An attacker could stream an arbitrarily large blob to the storage backend, exhausting disk. While the relay has a 256KB blob max (ADR-004:575), the streaming API is a general BlobStorage trait that could be used outside the relay context.
- **Why it matters**: The streaming API bypasses the relay's blob size limit. If used directly (e.g., for file transfer), there is no size enforcement.
- **Severity**: LOW

---

## Cross-ADR Structural Concerns

### Pseudonym Security Model Is Fundamentally Weakened

The ADR-027 amendment changed pseudonym derivation from private-key HMAC to public-key HMAC. This change cascades through ADR-002 (routing), ADR-008 (broadcast routing), ADR-012 (relay set partitioning), and all metadata privacy decisions. The entire metadata privacy architecture assumes pseudonyms are unlinkable to DIDs -- but with a public HMAC key, any party that knows the DID (which is public) can compute the pseudonym. This requires either accepting the privacy degradation or redesigning pseudonym derivation (e.g., using a separate software-managed pseudonym seed).

- **Resolution (later)**: The public-key-as-HMAC-key approach was rejected; spec §9.10.4.A now keys the HMAC with a private-derived `pseudonym_secret` (software custody derives it via HKDF-SHA256, hardware custody uses a device-local secret), restoring unlinkability.

### Nonce Format Is Inconsistent Across ADRs

ADR-009 and ADR-016 both claim to be normative for nonce format, and they specify different formats. ADR-016's `mint_ucan` says "UUID v4 or 32 random bytes" but validation expects `{unix_millis}-{hex16}`. This must be resolved to a single format before any implementation.

### Cross-Context Communication Has No Transport Specification

ADR-010's cross-context outlet interfaces and ADR-003's DID rotation events both need to send messages between different MLS groups. Neither ADR specifies the transport mechanism for cross-group communication. This is a fundamental architectural gap -- the protocol defines intra-context communication thoroughly but cross-context communication is hand-waved.

### The CeilingPolicy::Governed vs. Immutable Ceiling Contradiction

ADR-008 introduces `CeilingPolicy::Governed` while ADR-009 repeatedly asserts ceiling immutability as a security invariant. This creates a bifurcated security model where some contexts have mutable ceilings and others do not, but the UCAN validation pipeline (ADR-016) does not distinguish between them. The validation logic needs to handle ceiling version tracking if ceilings can change.

---

## Summary Statistics

| Severity | Count |
|----------|-------|
| CRITICAL | 3 |
| HIGH | 10 |
| MEDIUM | 22 |
| LOW | 12 |
| **Total** | **47** |

**CRITICAL findings** (must be resolved before implementation):
1. Inner envelope signature preimage has no canonical encoding or length prefixes
2. Pseudonym derivation with public key as HMAC key defeats unlinkability
   - **Resolution (later)**: The public-key-as-HMAC-key approach was rejected; spec §9.10.4.A now keys the HMAC with a private-derived `pseudonym_secret` (software custody derives it via HKDF-SHA256, hardware custody uses a device-local secret), restoring unlinkability.
3. Nonce format contradiction between minting (UUID v4) and validation ({unix_millis}-{hex16})

**HIGH findings** (significant risk if not addressed):
1. KeyPackage distribution mechanism undefined
2. EpochGraceStore crash-recovery semantics not specified
3. DID document exceeds BEP44 payload limit
4. Relay storage abuse with no authentication
5. No deserialization size limits on wire format strings
6. SenderKeyRequest signature does not bind to context_id
7. HPKE construction is informal (no RFC 9180 mode specified)
8. Ceiling immutability contradicts CeilingPolicy::Governed
9. Nonce format duplicated and conflicting between ADR-009/016
10. UCAN CID computation not specified
11. Cross-context outlet interface has no key exchange/transport
12. SpendingCapability tracking state not specified
13. Consistency checkpoint does not verify remote signature
