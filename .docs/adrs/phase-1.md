# Phase 1 Architecture Decision Records — Crypto Proof

**Date:** February 22, 2026
**Phase goal:** Prove the crypto stack works. Two Rust processes exchange encrypted messages through the SCP native relay. The relay sees nothing.
**Deliverable:** ~500-800 lines of Rust. Two terminals exchanging encrypted messages.
**Timeline:** Weeks 1-4
**Dependencies between ADRs:**

```
ADR-003 (DID)        ADR-001 (MLS)        ADR-006 (Testing)
     \                  /    \                  |
      \                /      \                 |
       v              v        v                |
      ADR-002 (Envelope) --> ADR-007 (Sender Keys)
             |
             v
      ADR-005 (Transport Trait)
             |
             v
      ADR-004 (Native Relay)
```

Build order: ADR-003 + ADR-001 + ADR-006 (parallel, no deps) --> ADR-002 --> ADR-007 --> ADR-005 --> ADR-004

---

## ADR-001: MLS Wrapper (OpenMLS Integration)

**Status:** Decided

### Context

MLS (Messaging Layer Security, RFC 9420) is the group encryption protocol for SCP. Every SCP context is one MLS group. MLS provides forward secrecy via epoch-based ratcheting, post-compromise security via periodic Updates, and O(log n) member removal via tree-based key management. The MLS wrapper is the most foundational crypto component — envelope encryption, sender keys, and all higher-level features depend on it.

MLS was selected over Sender Keys (Signal protocol) because member removal cost is O(log n) vs O(n), key destruction is clean (destroy tree root), and ephemeral context closure maps directly to MLS group dissolution. See planning-session-04.md Decision 1 for the full comparison.

### Decision

Wrap OpenMLS as `scp-core/crypto/mls/` module. Single ciphersuite: `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`. No ciphersuite negotiation in v1 (spec section 9.5). The wrapper exposes SCP-specific operations and hides OpenMLS internals behind a clean interface.

### Rationale

- **OpenMLS over mls-rs:** OpenMLS is the most mature MLS implementation in Rust (more production usage, more contributors). mls-rs (by Wire) is a viable fallback if OpenMLS proves insufficient.
- **Single ciphersuite:** Eliminates downgrade attacks and simplifies implementation. X25519 for key exchange, AES-128-GCM for encryption, SHA-256 for hashing, Ed25519 for signing. This is MLS's recommended baseline ciphersuite.
- **Wrapper, not fork:** SCP does not modify MLS behavior. The wrapper translates between SCP concepts (context, agent, epoch) and MLS concepts (group, member, epoch) per the mapping in spec section 9.7.1.

### Implementation

- **Language:** Rust
- **Library:** `openmls` crate (latest stable)
- **Crate:** `scp-core`
- **Module:** `scp-core/crypto/mls/`
- **Async runtime:** tokio (for key distribution operations)
- **Storage backend:** OpenMLS requires a `StorageProvider` trait implementation. Phase 1 uses the in-memory provider from ADR-006. Production providers (Keychain, SQLite) come later.

### Dependencies

None. This is foundational. Requires only the `openmls` crate and a storage provider (in-memory for Phase 1).

### Acceptance Criteria

Each function below must be implemented and tested:

1. **`create_group(creator_identity, credential) -> MlsGroup`**
   - Creates a new MLS group with one member (the creator).
   - Sets ciphersuite to `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`.
   - Returns a group handle that wraps the OpenMLS `MlsGroup`.
   - The credential contains the creator's DID and UCAN token (spec section 9.7.1).

2. **`add_member(group, key_package) -> (Welcome, Commit)`**
   - Adds a member to the group using their pre-published KeyPackage.
   - Returns the Welcome message (HPKE-encrypted to the new member's KeyPackage) and the Commit (advances epoch).
   - The Welcome contains all group state the new member needs to decrypt future messages.

3. **`remove_member(group, leaf_index) -> Commit`**
   - Removes a member from the group.
   - Returns a Commit that advances the epoch. All remaining members ratchet to new key material. The removed member cannot derive new epoch keys.
   - Cost is O(log n) via MLS tree structure.

4. **`encrypt(group, plaintext) -> MlsCiphertext`**
   - Encrypts plaintext as an MLS `PrivateMessage` (application message).
   - The ciphertext includes a `membership_tag` HMAC proving the sender is a group member with correct epoch secrets (spec section 9.8.1, inner check).
   - MLS assigns a generation number automatically (spec section 9.8.2, layer a).

5. **`decrypt(group, ciphertext) -> Plaintext`**
   - Decrypts an MLS `PrivateMessage`.
   - Verifies the `membership_tag` — rejects if sender is not a valid group member.
   - Verifies the generation number — rejects if less than or equal to highest seen for this sender in this epoch (replay prevention, spec section 9.8.2).
   - Returns the decrypted plaintext.

6. **`ratchet(group, commit) -> ()`**
   - Processes a Commit message, advancing the group to a new epoch.
   - Old epoch key material enters a **grace window** after the new epoch is established. During the grace window, old epoch keys are retained in memory only (never persisted to disk) and are used exclusively for decrypting in-flight messages that were encrypted under the old epoch.
   - **Grace window duration:** The shorter of (a) all members have sent at least one message or ACK in the new epoch, or (b) 30 seconds from local Commit processing time. The 30-second hard ceiling is not configurable — it bounds the forward secrecy window.
   - **Grace window key isolation:** Old epoch keys held during the grace window MUST be stored in a separate `EpochGraceStore` that is (1) in-memory only, (2) indexed by epoch number, (3) automatically purged when the grace window closes. The grace store MUST NOT be accessible to any code path other than `decrypt()` with a matching epoch number.
   - After the grace window closes, old epoch secrets, application key schedules, and ratchet tree states for past epochs are destroyed and MUST NOT be recoverable. This satisfies forward secrecy (spec section 9.7.2).
   - Messages arriving after the grace window closes that reference old epochs are unrecoverable. The SDK MUST log a warning and emit a `StaleEpochMessage` event to the application layer with the sender DID and epoch number.

7. **`update(group) -> (UpdateProposal, Commit)`**
   - Issues an MLS Update proposal — generates a fresh HPKE key pair and ratchets the sender's path in the tree.
   - Provides post-compromise security (spec section 9.7.3). Recommended interval: every 24 hours for active contexts.
   - After the Update + Commit is processed by all members, any prior compromise of the sender's state becomes useless for future messages.

8. **`generate_key_package(identity) -> KeyPackage`**
   - Generates a single-use KeyPackage for offline member addition.
   - Signed by the credential key (`#active` or `#agent`) matching the `signing_key_id` in the member's `ScpCredential` (ADR-039). This is consistent with standard MLS behavior where the leaf node signature key matches the credential key, and avoids requiring the hardware-backed `#0` for routine background operations (the SDK replenishes KeyPackage buffers automatically).
   - The SDK must maintain a buffer of at least 10 unused KeyPackages per identity (spec section 9.7.4). Replenished when buffer drops below 5.

9. **`destroy_group(group) -> ()`**
   - Destroys all MLS group state: tree secrets, all epoch key schedules, all application key material.
   - This is the operation triggered by ephemeral context closure (spec section 9.7.2).
   - After destruction, all historical messages encrypted under this group are physically unreadable.

### Scope

**Files (~5-8):**

| File | Purpose |
|------|---------|
| `mod.rs` | Module root, re-exports public API |
| `group.rs` | `ScpMlsGroup` wrapper struct, `create_group`, `add_member`, `remove_member`, `destroy_group` |
| `encrypt.rs` | `encrypt`, `decrypt` with generation number tracking |
| `ratchet.rs` | `ratchet` (Commit processing), `update` (PCS), epoch key deletion |
| `key_package.rs` | `generate_key_package`, KeyPackage buffer management |
| `credential.rs` | SCP credential type (DID + UCAN + `signing_key_id`) for MLS LeafNode credential field. The `signing_key_id` field (ADR-039) identifies which verification method (`#active` or `#agent`) signed the credential, enabling verifiers to resolve the correct public key from the DID document. |
| `storage.rs` | `StorageProvider` trait bridge to scp-platform storage adapters |
| `epoch_grace.rs` | `EpochGraceStore` — in-memory old epoch key retention with timer-based purge, per-epoch indexing |
| `error.rs` | MLS-specific error types |

**Estimated functions:** ~15-20 public functions, ~10-15 internal helpers.

---

## ADR-002: Envelope Creation, Signing, and Verification

**Status:** Decided

### Context

The SCP envelope is the wire format for all protocol messages. It has two layers: an outer envelope (visible to relays) and an inner envelope (visible only to group members after MLS decryption). The outer envelope is deliberately minimal to limit metadata exposure (Decision 2: minimal outer envelope). The inner envelope carries the full message with signatures, sequence numbers, timestamps, and payload.

The envelope design implements the metadata privacy architecture from the resolved decisions: per-context pseudonyms replace sender DIDs in the outer layer (Decision 7), the outer envelope contains only routing information (Decision 2), and all sensitive metadata lives inside the encrypted blob.

### Decision

Two-layer envelope format:

**Outer envelope** (what relays and the network see):
- `routing_id` — per-context pseudonym derived via HMAC-SHA256 (Decision 7)
- `recipient_hint` — recipient pseudonym for directed messages, or broadcast marker
- `blob_ttl` — how long the relay should store before deletion (seconds)
- `encrypted_blob` — everything else, MLS-encrypted

**Inner envelope** (inside the encrypted blob, visible only to group members):
- `context_id` — the SCP context identifier
- `sender_did` — the sender's full DID
- `epoch` — MLS epoch number
- `generation` — MLS generation number
- `sequence` — SCP per-sender monotonic sequence number (spec section 9.8.5)
- `timestamp` — creation timestamp
- `payload_hash` — SHA-256 of the original plaintext payload (before padding). Enables content-addressing, deduplication, and integrity verification after decryption. This hash is inside the encrypted blob and invisible to relays.
- `payload` — the actual message content (after bucket padding, Decision 3)
- `provenance` — origin metadata (spec section 7.7)

**Inner signature:** `Ed25519_sign(SHA256(context_id || sender_did || signing_key_id || epoch || generation || sequence || timestamp || payload_hash || provenance_hash))`

The `signing_key_id` field (ADR-039) identifies which verification method signed the envelope (e.g., `"#active"` or `"#agent"`). It is included in the signature preimage to bind the signature to the specific key, and stored as a field on `InnerEnvelope` so verifiers can resolve the correct public key from the sender's DID document.

Where `provenance_hash = SHA256(serialize(provenance))` if provenance is present, or `SHA256(0x00)` (hash of a single zero byte) if provenance is absent. Using a sentinel value for absent provenance ensures the signature unambiguously commits to "no provenance" — stripping provenance from a message that had it, or adding provenance to one that did not, produces an invalid signature.

The inner signature is included inside the encrypted blob. Relays never see it. Group members verify it after MLS decryption. This provides the outer integrity check (spec section 9.8.1) while keeping the signing DID hidden from relays.

### Rationale

- **Minimal outer envelope:** Relays are dumb pipes. They route by `routing_id`, store for `blob_ttl`, and delete. They learn nothing about who sent the message, what context it belongs to (only the pseudonym), or what it contains. This is the core of Decision 2.
- **Per-context pseudonyms:** `routing_id` is derived deterministically from the sender's identity key and context ID via HMAC-SHA256. Same identity + same context = same pseudonym. Different context = different pseudonym. Relays cannot link activity across contexts (Decision 7).
- **Signature inside encryption:** Moving the Ed25519 signature inside the encrypted blob hides the signer's identity from relays. Group members verify after decryption. This is a departure from the original spec (which had an outer Ed25519 signature) — the updated design per Decision 2 eliminates outer sender identity exposure.
- **Bucket padding:** Plaintext is padded to fixed buckets (256B, 1KB, 4KB, 16KB, 64KB, 256KB) before encryption (Decision 3). This prevents relays from correlating message types by size. **Processing order: hash original plaintext -> hash provenance -> sign (covering both hashes) -> pad to bucket boundary -> sender-key encrypt -> MLS encrypt.** Padding occurs after signing so the signature covers the real payload content, not padding bytes. Padding integrity is guaranteed by the AEAD authenticated encryption layers (AES-256-GCM sender key and MLS), not by the inner signature.

### Implementation

- **Language:** Rust
- **Signing:** Ed25519 via the `ed25519-dalek` crate (or via OpenMLS's signing primitives)
- **Hashing:** SHA-256 via the `sha2` crate
- **Pseudonym derivation:** HMAC-SHA256 via the `hmac` and `sha2` crates
- **Serialization:** `serde` with MessagePack via `rmp-serde`
- **Crate:** `scp-core`
- **Module:** `scp-core/envelope/`

### Dependencies

- **ADR-001 (MLS):** Envelope creation calls `mls.encrypt()` on the serialized inner envelope to produce the `encrypted_blob`. Envelope parsing calls `mls.decrypt()` to recover the inner envelope.
- **ADR-003 (DID):** The `sender_did` field references the DID created by the identity module. Pseudonym derivation requires the identity's private key.
- **Decision 7 (per-context pseudonyms):** The `routing_id` and `recipient_hint` are derived via HMAC-SHA256 from identity key + context ID.

### Acceptance Criteria

1. **`derive_pseudonym(key_custody, identity_key_handle, context_id) -> PseudonymKeypair`**
   - Delegates to `key_custody.derive_pseudonym(identity_key_handle, context_id)`.
   - Deterministic: same identity key + same context_id always produces the same pseudonym keypair.
   - Different `context_id` produces a different, unlinkable pseudonym.
   - Uses `HMAC-SHA256(ed25519_public_key_bytes, context_id || "scp-pseudonym")` then `Ed25519_keygen(seed[0..32])`. `identity_key_material` is the raw 32-byte Ed25519 public key for all adapter types — this is the cross-platform canonical definition (see ADR-027 amendment). The resulting PseudonymKeypair is software-managed.
   - The pseudonym keypair's public key is the routing identifier used in outer envelopes.

2. **`create_inner_envelope(context_id, sender_did, epoch, generation, sequence, timestamp, payload, provenance, signing_key, signing_key_id) -> InnerEnvelope`**
   - The `signing_key_id` parameter (ADR-039) identifies which verification method is signing (e.g., `"#active"` or `"#agent"`). Stored on the `InnerEnvelope` for verifier key resolution.
   - Computes `payload_hash = SHA256(payload)` — hash of the original plaintext BEFORE padding. Enables content-addressing and deduplication by recipients.
   - Computes `provenance_hash = SHA256(serialize(provenance))` if present, or `SHA256(0x00)` if absent.
   - Computes `signature = Ed25519_sign(SHA256(context_id || sender_did || signing_key_id || epoch || generation || sequence || timestamp || payload_hash || provenance_hash))`.
   - Pads payload to next bucket boundary (256B, 1KB, 4KB, 16KB, 64KB, 256KB) AFTER signing.
   - Returns the complete inner envelope struct with all fields (including padded payload, `signing_key_id`) + signature.

3. **`create_outer_envelope(routing_id, recipient_hint, blob_ttl, encrypted_blob) -> OuterEnvelope`**
   - Constructs the minimal outer envelope.
   - Serializes to binary format.

4. **`seal_envelope(inner_envelope, mls_group) -> OuterEnvelope`**
   - High-level function that serializes the inner envelope, encrypts via MLS, and wraps in an outer envelope.
   - This is the primary send-path function.

5. **`open_envelope(outer_envelope, mls_group) -> InnerEnvelope`**
   - High-level function that decrypts the outer envelope's blob via MLS, deserializes the inner envelope, and verifies the inner signature.
   - Rejects if inner signature verification fails.
   - After decryption and padding removal, verifies `payload_hash == SHA256(stripped_payload)`. Rejects if the hash does not match (content integrity failure).
   - Rejects if generation number violates replay prevention (delegates to MLS layer).
   - Returns the verified inner envelope.

6. **`verify_inner_signature(inner_envelope, sender_did_document) -> bool`**
   - Resolves the correct public key from the sender's DID document using `inner_envelope.signing_key_id` (ADR-039). For example, `signing_key_id: "#active"` resolves to the `#active` verification method, `"#agent"` resolves to `#agent`.
   - Computes `provenance_hash = SHA256(serialize(provenance))` if provenance is present, or `SHA256(0x00)` if absent.
   - Recomputes `SHA256(context_id || sender_did || signing_key_id || epoch || generation || sequence || timestamp || payload_hash || provenance_hash)`.
   - Verifies the Ed25519 signature against the resolved public key.
   - A mismatch indicates either payload tampering, provenance tampering, or signing key mismatch — all MUST be rejected.

7. **`strip_padding(padded_payload) -> Payload`**
   - Removes bucket padding from decrypted payload.
   - Padding format: payload bytes + padding bytes + 4-byte big-endian length of original payload at the end (so stripping reads the length suffix and truncates).

### Scope

**Files (~3-4):**

| File | Purpose |
|------|---------|
| `mod.rs` | Module root, re-exports |
| `inner.rs` | `InnerEnvelope` struct, `create_inner_envelope`, `verify_inner_signature`, serialization |
| `outer.rs` | `OuterEnvelope` struct, `create_outer_envelope`, serialization, `seal_envelope`, `open_envelope` |
| `padding.rs` | Bucket padding: `pad_to_bucket`, `strip_padding`, bucket size constants |
| `pseudonym.rs` | `derive_pseudonym` — HMAC-SHA256 derivation, pseudonym-to-DID verification cache |

**Estimated functions:** ~10-12 public functions, ~5-8 internal helpers.

---

## ADR-003: DID Creation (did:dht)

**Status:** Decided

### Context

Every SCP participant needs a decentralized identifier (DID) that is self-sovereign, supports key rotation, and requires no centralized infrastructure. did:dht was selected as the primary and only planned DID method (planning-session-06.md section 1.2). did:web exists only as a contingency fallback if did:dht libraries prove unusable — no did:web code is built unless needed.

did:dht uses the BitTorrent Mainline DHT (millions of existing nodes) for resolution. The DID string itself is the z-base-32 encoding of the Ed25519 public key, making it self-certifying: anyone can verify the DID-to-key binding without contacting any server.

### Decision

Implement did:dht as `scp-core/identity/`. The identity module handles DID creation, resolution, key rotation, and DID document management. It abstracts the DID method behind a trait so the contingency did:web fallback could be swapped in without changing any calling code.

### Rationale

- **did:dht over did:web:** No server dependency. Self-certifying (DID = public key). Key rotation via DHT record update with BEP44 signed mutable items. No TLS pinning, TOFU, or key-change alerting infrastructure needed. See planning-session-06.md section 1.2.
- **did:dht over did:key:** did:key cannot rotate keys (the key IS the identity). Key loss = identity loss. Recovery (spec section 3.3) requires key rotation, which did:key cannot do.
- **Self-certifying property:** The DID string `did:dht:z6Mk...` is the z-base-32 encoding of the public key. Verification requires no network call — just decode the DID and compare to the resolved public key. This eliminates DID-to-key MITM attacks at the identifier level.
- **Mainline DHT:** Existing infrastructure with millions of nodes. No blockchain. No token. BEP44 provides signed mutable items with sequence numbers for ordered updates.

### Implementation

- **Language:** Rust
- **Libraries:** `pkarr` (v5.0.3+) as the primary dependency — provides Ed25519 keypair management, BEP44 signed mutable items, DNS packet construction via `simple-dns`, and Mainline DHT publish/resolve via the `mainline` crate (v6.1.1+). `z-base-32` for DID string encoding. SCP implements the did:dht-specific DID Document to DNS resource record encoding (~300 lines) as a thin layer on top of pkarr. No existing Rust crate implements did:dht directly — `did-dht` does not exist on crates.io, `web5-rs` is abandoned (Block/TBD shut down Nov 2024), and `veilid-did` does not exist. The `web5-rs` `document_packet/` module may be referenced for encoding patterns but is not a dependency. `did:web` remains contingency fallback only.
- **Key generation:** Ed25519 via platform adapter (Secure Enclave on iOS, Keystore on Android, software keys for testing).
- **DID document format:** Standard W3C DID Document JSON-LD with Ed25519 verification methods.
- **Crate:** `scp-core`
- **Module:** `scp-core/identity/`

### Dependencies

None. This is foundational. Key generation uses the platform adapter (in-memory for Phase 1, ADR-006), but the DID module itself has no SCP-internal dependencies.

### Acceptance Criteria

1. **`create_identity(key_custody) -> Identity`**
   - Generates three or four keypairs via key_custody:
     - **Identity Key** (Ed25519): derives the DID string. Stored in highest-security custody.
     - **Active Signing Key** (Ed25519): used for MLS, envelopes, UCANs. Rotatable.
     - **Pre-Rotation Key** (Ed25519): stored in cold/offline custody. Generates the pre-rotation commitment `SHA-256(pre_rotation_key.public)`.
     - **Agent Signing Key** (Ed25519, optional): software-held key for autonomous agent operations. Rotatable independently of the Active Signing Key. Generated only when agent delegation is needed. See ADR-039.
   - Derives the did:dht identifier: `did:dht:` + z-base-32 encoding of the Identity Key's public key.
   - Constructs a DID document with:
     - Identity Key as verification method `#0`
     - Active Signing Key as verification method `#active` (referenced by `authentication` and `assertionMethod`)
     - Agent Signing Key as verification method `#agent` (referenced by `authentication` and `assertionMethod`), if present
     - PreRotationCommitment service: `{"type": "PreRotationCommitment", "serviceEndpoint": "sha256:<hex>"}`
   - Returns an `ScpIdentity` handle containing the DID string, all key handles (never raw private keys), pre-rotation commitment, and DID document.

2. **`publish_did_document(identity) -> ()`**
   - Publishes the DID document to the Mainline DHT as a BEP44 signed mutable item.
   - The item is signed by the identity's Ed25519 key.
   - Includes a sequence number (monotonically increasing) for ordered updates.
   - Idempotent: re-publishing with the same sequence number is a no-op on the DHT.

   **DHT republishing strategy:** DIDs published via did:dht require periodic republishing to remain resolvable — Mainline DHT records expire if not refreshed. The SDK handles this automatically for all active identities (identities loaded into memory with an active signing key):

   - **Republish interval:** Every 2 hours. This is well within typical DHT record expiry windows (which vary by implementation but are generally 1-2 hours for Mainline DHT BEP44 items).
   - **Failure handling:** Exponential backoff on publish failure: 30s, 1m, 2m, 4m, 8m, 16m, capped at 30m. Each retry re-resolves DHT bootstrap nodes to handle network topology changes. After 6 consecutive failures, the SDK emits a `DhtPublishDegraded` warning to the application layer.
   - **Automatic lifecycle:** Republishing starts when an identity is loaded (`Identity::load` or `Identity::create`) and stops when the identity is unloaded or the SDK shuts down. The republish task is a background tokio task managed by the identity module — no caller action required.
   - **Stale DID resolution:** When `resolve_did` returns a cached result that has not been refreshed within the expected republish window (2 hours + 30 minute grace), the result includes a `staleness` indicator: `DIDResolutionResult { document, staleness: Staleness::Fresh | Staleness::Stale { last_verified: u64 } }`. Callers SHOULD treat stale results as valid but degraded — the DID document may be outdated (e.g., a key rotation may have occurred). The SDK logs a warning for stale resolutions. Critical operations (UCAN validation, MLS credential verification) SHOULD attempt a fresh DHT resolution before rejecting a stale result.
   - **Startup republish:** On SDK initialization, all persisted active identities are republished immediately (not waiting for the 2-hour interval) to ensure availability after process restarts or network outages.

3. **`resolve_did(did_string) -> DIDDocument`**
   - Resolves a did:dht identifier via Mainline DHT lookup.
   - Verifies self-certification: decoded z-base-32 of DID suffix matches the public key in the resolved document.
   - Verifies BEP44 signature on the DHT record.
   - Returns the DID document with verification methods.
   - Caches results (24-hour refresh for active contacts, 7-day for inactive — Decision 9).

4. **Key Rotation — Three-Layer Architecture**

   did:dht's Identity Key (the key that derives the DID string) is **non-rotatable** per the did:dht specification — the DID string is permanently bound to the initial public key. SCP separates the Identity Key from the Active Signing Key and provides three rotation layers:

   **4a. `rotate_active_key(identity, key_custody) -> Identity`** (Layer 1 — common case)
   - Generates a new Ed25519 keypair as the new Active Signing Key via `key_custody.generate_keypair(KeyType::Ed25519)`.
   - Updates the DID document: adds the new key as a verification method, moves `authentication` and `assertionMethod` references to the new key. Retains the old key as `#retired-{sequence}` for historical verification. Retired key retention is bounded: the document retains at most the 2 most recent retired active keys; older ones are pruned on rotation to prevent unbounded DID document growth within DHT size constraints.
   - Signs the DID document update with the **Identity Key** (NOT the old active key).
   - Publishes to DHT with incremented BEP44 sequence number.
   - Returns updated Identity with the new active key handle.
   - **The DID string does NOT change. The Identity Key does NOT change. No references break.**
   - After rotation, the caller MUST issue MLS Update proposals in all active contexts (PCS, spec §9.7.3) and revoke/reissue UCAN tokens signed by the old active key.

   **4a′. `rotate_agent_key(identity, key_custody) -> Identity`** (Layer 1 — agent key rotation, ADR-039)
   - Generates a new Ed25519 keypair as the new Agent Signing Key via `key_custody.generate_keypair(KeyType::Ed25519)`.
   - Updates the DID document: replaces the `#agent` verification method with the new key. Retains the old agent key as `#retired-agent-{sequence}` for historical verification. Retired key retention is bounded: the document retains at most the 2 most recent retired agent keys; older ones are pruned on rotation (same policy as active key rotation) to prevent unbounded DID document growth within DHT size constraints.
   - Signs the DID document update with the **Identity Key** (`#0`).
   - Publishes to DHT with incremented BEP44 sequence number.
   - Returns updated Identity with the new agent key handle.
   - Also used for initial agent key provisioning: if no `#agent` VM exists, adds one.
   - After rotation, the caller MUST revoke/reissue self-delegated UCANs that grant `#agent` scope.

   **4b. `migrate_identity(identity, pre_rotation_key, key_custody) -> (Identity, DidRotationEvent)`** (Layer 2 — rare, planned migration)
   - Creates a new DID using the pre-rotation key as the new Identity Key.
   - Generates a new Active Signing Key, new pre-rotation commitment, and (if the old identity had one) a new Agent Signing Key for the new DID.
   - Updates the OLD DID document: adds `alsoKnownAs` pointing to the new DID, includes cryptographic linkage (old Identity Key signs new Identity Key public bytes, per did:dht spec).
   - Publishes both old (updated) and new DID documents to the DHT.
   - Returns the new Identity and a `DidRotationEvent` for distribution to all active contexts.
   - Starts a background republish task for the old DID document (forwarding record maintenance, recommended 90 days).
   - **The DID string changes. All per-context references must be migrated via DidRotationEvent.**

   **4c. `verify_migration(old_did, new_did, migration_proof, pre_rotation_proof) -> bool`**
   - Verifies the cryptographic linkage: old Identity Key signed the new Identity Key public bytes.
   - If `pre_rotation_proof` is present: verifies `SHA-256(new_identity_key_public) == commitment` from the old DID document's `PreRotationCommitment` service.
   - Returns true only if all verifications pass. Pre-rotation proof provides STRONG assurance (pre-committed); migration proof alone provides MODERATE assurance.

   **Identity structure at creation:**

   ```rust
   pub struct ScpIdentity {
       /// did:dht Identity Key. Derives the DID string. Stored in highest-security
       /// custody (Secure Enclave, HSM). Used ONLY for DID document updates and
       /// signing pre-rotation commitments. NEVER for MLS, envelopes, or UCANs.
       pub identity_key: KeyHandle,

       /// Current Active Signing Key. A verification method in the DID document.
       /// Used for MLS credentials, inner envelope signatures, UCAN issuance.
       /// Rotatable via rotate_active_key (DID string stays the same).
       pub active_signing_key: KeyHandle,

       /// Optional Agent Signing Key. Verification method `#agent` in the DID doc.
       /// Software-held Ed25519 key for autonomous agent operations. Rotatable
       /// independently via rotate_agent_key. Authorized via self-delegated UCAN
       /// with `fct.scp_key_scope: "#agent"`. See ADR-039.
       pub agent_signing_key: Option<KeyHandle>,

       /// SHA-256 hash of the next Identity Key's public key.
       /// Published in DID document as a PreRotationCommitment service.
       pub pre_rotation_commitment: [u8; 32],

       /// The DID string: did:dht:z<z-base-32(identity_key.public)>
       pub did: String,
   }
   ```

   **DidRotationEvent (sent as MLS application message in each context during migration):**

   ```rust
   pub struct DidRotationEvent {
       pub old_did: String,
       pub new_did: String,
       pub migration_proof: MigrationProof,
       pub pre_rotation_proof: Option<PreRotationProof>,
       pub rotated_at: u64,
   }

   pub struct MigrationProof {
       /// Ed25519 signature of SHA-256(SCP-MIGRATION-V1: || len(old_did) || old_did || len(new_did) || new_did || rotated_at)
       /// where len() is u32 big-endian. Signed by the old Identity Key.
       pub signature: [u8; 64],
       pub old_public_key: [u8; 32],
   }

   pub struct PreRotationProof {
       /// The commitment published in the old DID document.
       pub commitment: [u8; 32],
       /// The new Identity Key public bytes. SHA-256(this) must equal commitment.
       pub revealed_key: [u8; 32],
   }
   ```

5. **`verify_did(did_string, public_key) -> bool`**
   - Self-certification check: decode the z-base-32 suffix of the DID and compare to the provided public key.
   - This is a local operation — no network call required.

6. **`DidMethod` trait**
   - Abstract trait enabling did:web fallback swap without changing calling code.
   - Methods: `create`, `publish`, `resolve`, `rotate`, `verify`.
   - `DidDht` implements this trait. `DidWeb` would implement it if ever needed.

### Scope

**Files (~3-4):**

| File | Purpose |
|------|---------|
| `mod.rs` | Module root, `Identity` struct, `DidMethod` trait, re-exports |
| `dht.rs` | `DidDht` implementation — create, publish, resolve, rotate via Mainline DHT + BEP44 |
| `document.rs` | DID Document construction, serialization (JSON-LD), parsing, verification method management |
| `cache.rs` | Resolution cache — TTL-based, 24h active / 7d inactive refresh, BEP44 sequence number comparison for staleness |

**Estimated functions:** ~10-12 public functions, ~8-10 internal helpers.

---

## ADR-004: SCP Native Relay Protocol

**Status:** Decided

### Context

SCP defines its own native relay as the canonical reference transport (planning-session-06.md section 1.6). The native relay is the simplest possible store-and-forward mechanism purpose-built for SCP envelopes. It is deliberately simple: accept blobs, hold them for a TTL, deliver to subscribers, delete on expiry or request. The relay is a dumb pipe — it cannot read, forge, or modify encrypted content.

The SCP native relay exists because no external transport (Nostr, Matrix, etc.) should be a structural dependency. Other transports are adapters behind the transport abstraction trait (ADR-005), but the native relay is what SCP ships and tests against.

### Decision

Implement a WebSocket-based store-and-forward relay server and its corresponding client adapter. The relay protocol has exactly 6 operations.

### Rationale

- **Purpose-built simplicity:** Nostr relays carry conceptual overhead (event kinds, NIP compliance, signature verification, tag indexing). The SCP native relay stores opaque blobs indexed by `routing_id` with a `blob_ttl`. Nothing else.
- **Transport independence:** By defining and shipping its own relay, SCP proves it works without any external infrastructure dependency. Other transports are optional enhancers.
- **No authentication required:** The relay does not authenticate clients. Encryption-as-access-control (spec section 10.5) means that only group members can read content. The relay cannot even tell if a subscriber is a legitimate group member. This simplifies the relay to a pure storage/routing service.

### Implementation

- **Language:** Rust
- **Server framework:** `tokio` + `tokio-tungstenite` (WebSocket) or `axum` with WebSocket support
- **Client library:** `tokio-tungstenite` (client-side WebSocket)
- **Storage:** In-memory for Phase 1 (HashMap keyed by `routing_id`). Persistent storage (SQLite, redb) for production. See §17.7 for first-party BlobStore adapters.
- **Crate:** `scp-transport`
- **Module:** `scp-transport/native/`

### Dependencies

- **ADR-002 (Envelope):** The relay accepts and delivers `OuterEnvelope` blobs. It uses the `routing_id` for subscription matching and `blob_ttl` for expiry.
- **ADR-005 (Transport Trait):** The native relay client adapter implements the `TransportAdapter` trait.

### Acceptance Criteria

**Relay server operations:**

1. **`PUBLISH { routing_id, recipient_hint, blob_ttl, blob }`**
   - Accept an opaque blob associated with a `routing_id`.
   - `recipient_hint` (optional): a per-context pseudonym (§9.10.4) indicating the intended recipient for directed delivery. If absent, the blob is broadcast to all subscribers of this `routing_id`.
   - Store it for `blob_ttl` seconds.
   - Return a `blob_id` (SHA-256 hash of the blob) as confirmation.
   - Deliver immediately to any active subscribers of this `routing_id`. If `recipient_hint` is present, deliver only to the matching subscriber (optimization — the blob is still encrypted and opaque to non-recipients).

2. **`SUBSCRIBE { routing_id, since? }`**
   - Subscribe to a `routing_id`. The relay pushes all new blobs for this ID to the subscriber via WebSocket.
   - If `since` is provided (unix timestamp), backfill with stored blobs newer than `since`.
   - Multiple routing IDs per connection (multiplexed subscriptions).

3. **`UNSUBSCRIBE { routing_id }`**
   - Stop receiving blobs for this `routing_id` on this connection.

4. **`QUERY { routing_id, since?, limit? }`**
   - One-shot query: return stored blobs for a `routing_id`, optionally filtered by `since` timestamp, with optional `limit`.
   - Does not create a subscription.

5. **`DELETE { blob_id }`**
   - Request deletion of a specific blob by its `blob_id`.
   - Best-effort: the relay SHOULD delete but is not trusted to comply (relays are untrusted, spec section 9.9.1).

6. **`ACK { blob_id }`**
   - Delivery receipt. Client acknowledges receipt of a blob.
   - The relay MAY use ACKs from all known subscribers to garbage-collect blobs before TTL expiry.

**Context metadata retrieval:** Contexts publish their parameters (capability ceiling, governance policy, roles, TTL, memory scope, etc.) to a publicly derivable routing ID: `metadata_routing_id = SHA-256(context_id || "scp-metadata")`. Any participant can SUBSCRIBE or QUERY this routing ID to inspect a context's parameters before joining. The metadata blob is a signed, unencrypted envelope containing the context's `ContextParameters` struct (spec §5.3). This enables the "legibility before opt-in" tenet — informed consent is mechanical, not social.

**Relay server requirements:**

- TTL enforcement: a background task deletes expired blobs.
- No blob inspection: the relay never parses, validates, or inspects blob contents.
- No client authentication: any WebSocket client can connect, publish, subscribe, query.
- Connection multiplexing: one WebSocket connection supports multiple subscriptions.
- Bind address is configurable (supports deployment behind reverse proxies, VPNs, or other network configurations).

**Client adapter:**

- Implements `TransportAdapter` trait (ADR-005).
- Manages WebSocket connection lifecycle (connect, reconnect, keepalive).
- Maps `send(envelope)` to `PUBLISH`.
- Maps `subscribe(routing_id)` to `SUBSCRIBE` + stream of decoded envelopes.
- Maps `query(routing_id, since)` to `QUERY`.
- Maps `delete(blob_id)` to `DELETE`.

### Scope

**Files (~5-8):**

| File | Purpose |
|------|---------|
| `mod.rs` | Module root, re-exports |
| `protocol.rs` | Message types (`ClientMessage`, `RelayMessage`), MessagePack serialization over WebSocket binary frames (see Wire Format section) |
| `server.rs` | Relay server: WebSocket listener, connection handler, subscription registry, blob storage, TTL expiry task |
| `storage.rs` | Blob storage trait + in-memory implementation. Keyed by `(routing_id, blob_id)`. TTL tracking. |
| `client.rs` | WebSocket client: connect, send commands, receive deliveries, reconnection logic |
| `adapter.rs` | `NativeRelayAdapter` implementing `TransportAdapter` trait — translates between SCP transport API and native relay protocol |
| `error.rs` | Protocol-specific error types |

**Estimated functions:** Server ~15-20, Client/Adapter ~10-15, Protocol ~8-10.

### Wire Format

**Serialization:** MessagePack (via `rmp-serde`) over WebSocket binary frames.

**Rationale:** Consistent with the envelope layer (ADR-002 uses `rmp-serde`). Native binary support eliminates Base64 overhead for encrypted blobs (~33% savings). MessagePack has mature libraries in all target languages. JSON text frames rejected — debuggability is solved by tooling, not wire format.

**Backfill ordering:** Oldest-first (ascending relay receipt timestamp). Enables incremental processing, natural stream transition from backfill to real-time, and gets at-risk (expiring) messages to clients first.

**Connection URL:** `wss://<host>/scp/v1`. TLS 1.3 required (§9.13). URL path encodes protocol version — no in-band version negotiation. Relay returns HTTP 404 for unsupported versions.

#### Message Envelope

Every message is a MessagePack map with a required `op` field (string) plus operation-specific fields. Unknown fields MUST be ignored (forward compatibility).

```
{
  "op": <string>,     // operation identifier
  "ref": <string>,    // client-assigned request ID (optional, echoed in response, max 64 bytes)
  ...                 // operation-specific fields
}
```

#### Client-to-Relay Messages

| Op | Fields | Response |
|----|--------|----------|
| `PUBLISH` | `routing_id: bin32`, `recipient_hint: bin32?`, `blob_ttl: u32`, `blob: bin` | OK with `blob_id` |
| `SUBSCRIBE` | `routing_id: bin32`, `since: u64?` | OK, then BLOB stream, then EVENT `backfill_complete` |
| `UNSUBSCRIBE` | `routing_id: bin32` | OK |
| `QUERY` | `routing_id: bin32`, `since: u64?`, `limit: u32?` (default 100, max 1000) | BLOB stream, then EVENT `query_complete` |
| `DELETE` | `blob_id: bin32` | OK (best-effort, does not confirm existence) |
| `ACK` | `blob_id: bin32` | None (fire-and-forget) |
| `PING` | `ts: u64` | PONG |

**Constraints:** `blob_ttl` 1–604800 (7 days). `blob` 1–262144 bytes (256KB). `routing_id`, `recipient_hint`, `blob_id` are exactly 32 bytes, encoded as MessagePack `bin 32` (not hex/base64 strings).

#### Relay-to-Client Messages

| Op | Fields | When |
|----|--------|------|
| `OK` | `ref: string?`, `blob_id: bin32?` | Success response. `blob_id` present only for PUBLISH. |
| `ERR` | `ref: string?`, `code: u16`, `msg: string` | Error response. `msg` is for logging, not parsing. |
| `BLOB` | `routing_id: bin32`, `blob_id: bin32`, `recipient_hint: bin32?`, `blob_ttl: u32`, `stored_at: u64`, `blob: bin` | Blob delivery (subscription, backfill, or query). `blob_id = SHA-256(blob)` — clients SHOULD verify. |
| `EVENT` | `ref: string?`, `type: string`, type-specific fields | Protocol events: `backfill_complete` (with `routing_id`), `query_complete` (with `count`). |
| `PONG` | `ts: u64` | Keepalive response. |

#### Error Codes

**Client errors (4xxx):** `4000` INVALID_MESSAGE, `4001` UNKNOWN_OP, `4002` MISSING_FIELD, `4003` INVALID_FIELD, `4010` BLOB_TOO_LARGE, `4011` TTL_TOO_LONG, `4012` LIMIT_EXCEEDED, `4020` RATE_LIMITED, `4021` TOO_MANY_SUBSCRIPTIONS.

**Server errors (5xxx):** `5000` INTERNAL_ERROR, `5001` STORAGE_FULL, `5002` SHUTTING_DOWN.

Clients MUST handle unknown codes by category: 4xxx = do not retry same request, 5xxx = retry with backoff or switch relay. Codes are extensible within these ranges.

#### Keepalive

Client MUST send PING every 30 seconds. Relay MAY close idle connections after 90 seconds of no messages. WebSocket-level pings (opcode 0x9) are independent and serve as TCP-level liveness checks.

#### Connection Recovery

On abnormal close, client reconnects with exponential backoff (1s, 2s, 4s, 8s, 16s, 30s cap). On reconnect, re-issues SUBSCRIBE for each `routing_id` with `since` = last received `stored_at` minus 5-second overlap. Client deduplicates via `blob_id` per §9.8.2 layer (b). Relay maintains no per-client state across connections — recovery is entirely client-driven.

#### Relay Operator Configuration

Published out-of-band (relay metadata page, DID document service endpoint). Relay MAY impose limits stricter than protocol maximums:

| Parameter | Default | Description |
|-----------|---------|-------------|
| `max_blob_size` | 262144 | Max blob bytes |
| `max_blob_ttl` | 604800 | Max TTL seconds |
| `max_subscriptions_per_connection` | 100 | Concurrent subscriptions per WebSocket |
| `max_query_limit` | 1000 | Max QUERY limit |
| `rate_limit_publish` | 6000/min | PUBLISH rate per IP (100/sec). Per-IP shared across connections; operator-adjustable. Priced relays have economic DDoS resistance (§19.7). |
| `rate_limit_subscribe` | 100 | Max concurrent subscriptions per connection. SUBSCRIBE operation rate is separately enforced at 20/min per connection but not exposed in `.well-known/scp`. |
| `idle_timeout` | 90s | Seconds before idle connection close |

#### Reference Rust Types

```rust
/// Client-to-relay operations (scp-transport/src/native/protocol.rs)
pub enum ClientMessage {
    Publish { ref_id: Option<String>, routing_id: [u8; 32], recipient_hint: Option<[u8; 32]>, blob_ttl: u32, blob: Vec<u8> },
    Subscribe { ref_id: Option<String>, routing_id: [u8; 32], since: Option<u64> },
    Unsubscribe { ref_id: Option<String>, routing_id: [u8; 32] },
    Query { ref_id: Option<String>, routing_id: [u8; 32], since: Option<u64>, limit: Option<u32> },
    Delete { ref_id: Option<String>, blob_id: [u8; 32] },
    Ack { blob_id: [u8; 32] },
    Ping { ts: u64 },
}

/// Relay-to-client operations
pub enum RelayMessage {
    Ok { ref_id: Option<String>, blob_id: Option<[u8; 32]> },
    Err { ref_id: Option<String>, code: u16, msg: String },
    Blob { routing_id: [u8; 32], blob_id: [u8; 32], recipient_hint: Option<[u8; 32]>, blob_ttl: u32, stored_at: u64, blob: Vec<u8> },
    Event { ref_id: Option<String>, event_type: String },
    Pong { ts: u64 },
}
```

Serialized via `serde` with `rmp-serde`. The `op` field is handled by tagged enum representation. All binary fields use MessagePack's native `bin` type.

---

## ADR-005: Transport Abstraction Trait

**Status:** Decided

### Context

SCP is transport-independent. No single transport is "primary" — the protocol functions correctly on any transport that implements the abstraction (planning-session-06.md section 1.6). The transport trait defines the contract that all adapters must fulfill. Phase 1 implements the SCP native relay adapter (ADR-004). Future phases add Nostr, Matrix, Hyperswarm, libp2p, and others.

### Decision

Define a Rust trait `TransportAdapter` that all transport adapters implement. The trait is deliberately thin: 5 core methods covering send, subscribe, unsubscribe, query, and delete. The trait is async (tokio) and returns `Stream` for subscriptions.

### Rationale

- **Thin interface:** The original transport trait from planning-session-04.md had 8 methods including `publish_endpoints` and `discover_endpoints`. These are transport-specific (not all transports have relay/endpoint concepts) and belong in individual adapter implementations, not the shared trait.
- **Envelope-level abstraction:** The trait operates on `OuterEnvelope` objects. It does not know about MLS, DIDs, or inner envelopes. Transport adapters are dumb pipes for outer envelopes.
- **Async with tokio:** All transport operations are inherently async (network I/O). Using tokio's async runtime is consistent with the rest of the Rust ecosystem and OpenMLS's async support.
- **`Stream` for subscriptions:** Subscriptions return a `futures::Stream<OuterEnvelope>`, which integrates with tokio's select, merge, and other stream combinators. This enables multi-transport subscription merging.

### Implementation

- **Language:** Rust
- **Async runtime:** tokio
- **Stream type:** `futures::Stream` (or `tokio_stream::Stream`)
- **Crate:** `scp-transport`
- **Module:** `scp-transport/` (trait.rs at crate root level)

### Dependencies

- **ADR-002 (Envelope):** The trait uses `OuterEnvelope` as its message type.

### Acceptance Criteria

1. **Trait definition:**

```rust
pub trait TransportAdapter: Send + Sync {
    /// Send an outer envelope to the network.
    /// The adapter routes based on the envelope's routing_id.
    async fn send(&self, envelope: &OuterEnvelope) -> Result<BlobId, TransportError>;

    /// Subscribe to envelopes for a given routing_id.
    /// Returns a stream that yields envelopes as they arrive.
    /// If `since` is provided, backfills with stored envelopes newer than that timestamp.
    async fn subscribe(
        &self,
        routing_id: &RoutingId,
        since: Option<u64>,
    ) -> Result<Pin<Box<dyn Stream<Item = TransportEvent> + Send>>, TransportError>;

    /// Unsubscribe from a routing_id.
    async fn unsubscribe(&self, routing_id: &RoutingId) -> Result<(), TransportError>;

    /// One-shot query for stored envelopes matching a routing_id.
    async fn query(
        &self,
        routing_id: &RoutingId,
        since: Option<u64>,
    ) -> Result<Vec<OuterEnvelope>, TransportError>;

    /// Request deletion of a blob by its ID.
    /// Best-effort: untrusted transports may ignore this.
    async fn delete(&self, blob_id: &BlobId) -> Result<(), TransportError>;
}
```

2. **Supporting types:**

```rust
/// Opaque blob identifier (SHA-256 hash of the blob).
pub struct BlobId([u8; 32]);

/// Per-context pseudonym used for routing (from ADR-002).
pub struct RoutingId(pub [u8; 32]);

/// Transport-level errors.
pub enum TransportError {
    ConnectionFailed(String),
    SendFailed(String),
    SubscriptionFailed(String),
    NotConnected,
    Timeout,
    ProtocolError(String),
}

/// Events yielded by a transport subscription stream.
pub enum TransportEvent {
    /// A valid envelope received from the transport.
    Envelope(OuterEnvelope),
    /// Transport-level error on this subscription.
    /// The stream may continue after transient errors (adapter handles reconnection).
    Error(TransportError),
    /// Backfill of stored envelopes is complete (only emitted if `since` was provided).
    BackfillComplete,
    /// The transport reconnected after a disconnection.
    /// Callers should expect possible duplicate envelopes (deduplicate via blob_id).
    Reconnected,
    /// The subscription was terminated by the transport (e.g., relay shutdown).
    Terminated { reason: String },
}
```

3. **`TransportManager` struct:**
   - Holds multiple `Box<dyn TransportAdapter>` instances.
   - `send()` routes through one or more adapters based on policy.
   - `subscribe()` merges streams from multiple adapters into a single stream (deduplication by `blob_id` for `TransportEvent::Envelope` variants; control events like `BackfillComplete` are passed through per-adapter).
   - Phase 1: single adapter (native relay). Multi-adapter routing is Phase 2+.

### Scope

**Files (1-2):**

| File | Purpose |
|------|---------|
| `trait.rs` | `TransportAdapter` trait definition, `BlobId`, `RoutingId`, `TransportError` types |
| `manager.rs` | `TransportManager` — multi-adapter routing, stream merging, deduplication (stub in Phase 1, full in Phase 2) |

**Estimated functions:** ~5 trait methods, ~5 manager methods, ~5-8 type definitions.

---

## ADR-006: Platform Abstraction (In-Memory Testing Adapter)

**Status:** Decided

### Context

SCP's platform adapter layer abstracts device-specific capabilities (key storage, device attestation, push notifications, secure storage) behind traits. Production implementations use hardware security (Secure Enclave, Android Keystore). For Phase 1 testing, all platform traits need in-memory implementations that are fast, deterministic, and require no hardware dependencies.

### Decision

Implement in-memory versions of all four platform traits: `KeyCustody`, `DeviceAttestation`, `Push`, `Storage`. These are used exclusively for testing and development. They provide identical API surfaces to production adapters but store everything in memory.

### Rationale

- **Unblocks all other work:** Every component that touches keys, storage, or attestations depends on platform adapters. In-memory implementations let Phase 1 proceed without iOS/Android platform code.
- **Deterministic testing:** In-memory adapters produce predictable results. Keys can be seeded for reproducible test scenarios.
- **No external dependencies:** No hardware, no OS APIs, no network calls. Pure Rust.

### Implementation

- **Language:** Rust
- **Crate:** `scp-platform`
- **Module:** `scp-platform/testing/`
- **Dependencies:** `ed25519-dalek` for key generation, `rand` for randomness (with seedable RNG for determinism)

### Dependencies

None. This is foundational. The traits it implements are defined in `scp-platform/trait.rs`.

### Acceptance Criteria

1. **`InMemoryKeyCustody`**
   - `generate_keypair(key_type) -> KeyHandle`: Generates an Ed25519 or X25519 keypair in memory. Returns an opaque handle (integer ID). Private key stored in an internal `HashMap<u64, SigningKey>` (Ed25519) or `HashMap<u64, StaticSecret>` (X25519).
   - `sign(key_handle, data) -> Signature`: Signs data with the Ed25519 private key associated with the handle. Returns error for X25519 handles.
   - `public_key(key_handle) -> PublicKey`: Returns the public key for a handle (Ed25519 or X25519).
   - `destroy_key(key_handle) -> ()`: Removes the private key from the internal map. Subsequent operations with this handle fail.
   - `dh_agree(key_handle, peer_public) -> SharedSecret`: Performs X25519 ECDH. Returns error for Ed25519 handles.
   - `derive_pseudonym(key_handle, context_id) -> PseudonymKeypair`: Computes `HMAC-SHA256(ed25519_public_key_bytes, context_id || "scp-pseudonym")`, derives Ed25519 keypair from the first 32 bytes of the HMAC output. Returns error for X25519 handles. **Amendment (ADR-027):** Originally specified as `ed25519_private_key_bytes`, but Android Keystore TEE on API 33+ does not permit private key export. All adapters (InMemory, Apple/Keychain, Android Keystore, Android software) MUST use the raw 32-byte public key as the HMAC key to ensure cross-platform determinism. See `.docs/lessons/kotlin/android-tee-pseudonym-derivation.md`.
   - `custody_type(key_handle) -> CustodyType::InMemory`.
   - Optionally accepts a seed for deterministic key generation in tests.

2. **`InMemoryDeviceAttestation`**
   - `attest() -> DeviceAttestation`: Returns a synthetic attestation (always valid).
   - `verify(attestation) -> bool`: Always returns `true` for attestations produced by this adapter.
   - No actual device verification — this is for testing only.

3. **`InMemoryPush`**
   - `register() -> PushToken`: Returns a synthetic push token (UUID).
   - `handle_notification(payload) -> WakeSignal`: Passes through the payload as a wake signal.
   - For Phase 1 testing, push is not exercised (two processes use direct relay subscriptions). This adapter exists to satisfy the trait requirements.

4. **`InMemoryStorage`**
   - `store(key, data) -> ()`: Stores bytes in an internal `HashMap<String, Vec<u8>>`.
   - `retrieve(key) -> Option<Vec<u8>>`: Returns stored data or None.
   - `delete(key) -> ()`: Removes data from the map.
   - `list_keys(prefix) -> Vec<String>`: Lists keys matching a prefix in lexicographic order (useful for KeyPackage buffer management, event log range queries).
   - `delete_prefix(prefix) -> u64`: Deletes all keys matching a prefix. Returns count deleted. Used for context cleanup (§17.3).
   - `exists(key) -> bool`: Returns true if the key exists. Used for UCAN nonce replay prevention (§17.3).

5. **Platform trait definitions** (in `scp-platform/trait.rs`, not the testing module):

```rust
/// The type of cryptographic key managed by this handle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyType {
    /// Ed25519 signing key (identity key, pseudonym keys).
    Ed25519,
    /// X25519 key agreement key (HPKE wrapping keys).
    X25519,
}

pub trait KeyCustody: Send + Sync {
    /// Generate a new keypair of the specified type.
    /// Ed25519 keys may be hardware-backed. X25519 wrapping keys are
    /// always software-managed but routed through KeyCustody for API consistency.
    async fn generate_keypair(&self, key_type: KeyType) -> Result<KeyHandle, PlatformError>;

    /// Sign data with an Ed25519 key.
    /// Returns an error if the key handle refers to an X25519 key.
    async fn sign(&self, key: &KeyHandle, data: &[u8]) -> Result<Signature, PlatformError>;

    /// Return the public key for a handle.
    async fn public_key(&self, key: &KeyHandle) -> Result<PublicKey, PlatformError>;

    /// Destroy key material. Subsequent operations with this handle fail.
    async fn destroy_key(&self, key: &KeyHandle) -> Result<(), PlatformError>;

    /// Perform X25519 Diffie-Hellman key agreement.
    /// Returns the 32-byte shared secret. The private key never leaves
    /// the custody boundary (scalar multiplication happens inside the adapter).
    /// Returns an error if the key handle refers to an Ed25519 key.
    async fn dh_agree(&self, key: &KeyHandle, peer_public: &[u8; 32]) -> Result<SharedSecret, PlatformError>;

    /// Derive a deterministic, context-scoped pseudonym keypair.
    ///
    /// Algorithm (all implementations MUST produce identical output):
    ///   1. seed = HMAC-SHA256(ed25519_public_key_bytes, context_id || "scp-pseudonym")
    ///   2. pseudonym_keypair = Ed25519_keygen(seed[0..32])
    ///
    /// identity_key_material is defined as the raw 32-byte Ed25519 PUBLIC key for ALL
    /// adapters (hardware-backed and software alike). This is the only definition that
    /// works uniformly: Android Keystore TEE (API 33+) does not permit private key export.
    /// Amendment from ADR-027: original spec said "private key bytes" — corrected to
    /// "public key bytes" to support TEE-backed adapters without cross-platform divergence.
    /// See .docs/lessons/kotlin/android-tee-pseudonym-derivation.md.
    ///
    /// The returned PseudonymKeypair is always software-managed (derived output).
    /// Returns an error if the key handle refers to an X25519 key.
    async fn derive_pseudonym(&self, key: &KeyHandle, context_id: &[u8]) -> Result<PseudonymKeypair, PlatformError>;

    /// The custody type for a given key handle.
    fn custody_type(&self, key: &KeyHandle) -> CustodyType;
}

pub trait DeviceAttestation: Send + Sync {
    async fn attest(&self) -> Result<DeviceAttestationToken, PlatformError>;
    async fn verify(&self, token: &DeviceAttestationToken) -> Result<bool, PlatformError>;
}

pub trait Push: Send + Sync {
    async fn register(&self) -> Result<PushToken, PlatformError>;
    async fn handle_notification(&self, payload: &[u8]) -> Result<WakeSignal, PlatformError>;
}

pub trait Storage: Send + Sync {
    async fn store(&self, key: &str, data: &[u8]) -> Result<(), PlatformError>;
    async fn retrieve(&self, key: &str) -> Result<Option<Vec<u8>>, PlatformError>;
    async fn delete(&self, key: &str) -> Result<(), PlatformError>;
    async fn list_keys(&self, prefix: &str) -> Result<Vec<String>, PlatformError>;
    /// Delete all keys matching a prefix. Returns count deleted. See §17.2.
    async fn delete_prefix(&self, prefix: &str) -> Result<u64, PlatformError>;
    /// Check key existence without reading the value. See §17.2.
    async fn exists(&self, key: &str) -> Result<bool, PlatformError>;
}
```

### Scope

**Files (~3-4):**

| File | Purpose |
|------|---------|
| `scp-platform/trait.rs` | Trait definitions: `KeyCustody`, `DeviceAttestation`, `Push`, `Storage`, error types, handle types |
| `scp-platform/testing/mod.rs` | Module root, re-exports all in-memory adapters |
| `scp-platform/testing/key_custody.rs` | `InMemoryKeyCustody` — keypair generation, signing, storage in HashMap |
| `scp-platform/testing/storage.rs` | `InMemoryStorage` — key-value store in HashMap |
| `scp-platform/testing/attestation.rs` | `InMemoryDeviceAttestation` — synthetic attestations |
| `scp-platform/testing/push.rs` | `InMemoryPush` — synthetic push tokens |

**Estimated functions:** ~4-5 per trait implementation, ~15-20 total.

**Testing harness.** These in-memory adapters are consumed by the `scp-testing` crate (§16), which composes them into a full network simulation harness: `SimulatedIdentity` wraps a real `Identity` with `InMemoryKeyCustody` + `InMemoryStorage` + `InMemoryTransport` instances. Trait conformance macros (`key_custody_conformance!()`, `storage_conformance!()`, `attestation_conformance!()`, `push_conformance!()`) verify that every adapter implementation — in-memory and production — satisfies the same contract.

---

## ADR-007: Sender-Side Key Layer

**Status:** Decided

### Context

Blocking in SCP must be a per-relationship action: Alice blocking Dave affects only Alice's messages to Dave, not Dave's relationship with other context members. MLS group removal is the wrong mechanism for blocking because it excludes the blocked party from ALL messages from ALL members (planning-session-06.md section 1.1).

The sender-side key layer solves this by adding a per-sender symmetric encryption layer on top of MLS. Each sender maintains an AES-256 key that encrypts their messages before MLS encryption. Blocking = rotate the sender key and distribute the new key to everyone except the blocked party (Decision 5).

### Decision

Implement per-sender AES-256 symmetric keys as `scp-core/crypto/sender_keys/`. Messages are double-encrypted: sender key first (AES-256-GCM), then MLS. Blocking rotates the sender key with selective redistribution. The protocol includes mutual block notification.

### Rationale

- **Per-relationship blocking:** MLS removal is all-or-nothing. Sender keys allow surgical blocking: only the blocker's messages become unreadable to the blocked party. The blocked party can still read messages from everyone else in the context.
- **AES-256 symmetric over asymmetric:** Each sender has one key that all recipients share. Storage is 32 bytes per sender key per context member. Symmetric encryption is fast. Distribution happens via MLS application messages (which are already encrypted to the group).
- **Sender-first encryption order:** The plaintext is encrypted with the sender's AES-256 key first, then the result is encrypted with MLS. A blocked party decrypts the MLS layer (they're still a group member) but gets opaque AES-256 ciphertext from the blocker. They know a message exists but cannot read it.
- **Protocol-notified mutual block:** When Alice blocks Dave, the protocol sends a block notification (as an MLS application message: "you have been blocked by DID X"). Dave's client automatically rotates Dave's sender key excluding Alice. Both sides complete within one message round-trip. Neither can read the other's future messages.
- **Sender key rotation only on block, NOT on MLS epoch advances:** Old sender keys are retained for historical message decryption. Blocking is about future messages, not retroactive access. Forward secrecy for sender keys is not a goal — MLS provides forward secrecy at the group level.

### Implementation

- **Language:** Rust
- **Encryption:** AES-256-GCM via the `aes-gcm` crate
- **Key generation:** 32 random bytes via the platform key custody adapter
- **Key distribution:** Via MLS application messages (encrypted to the group)
- **Crate:** `scp-core`
- **Module:** `scp-core/crypto/sender_keys/`

### Dependencies

- **ADR-001 (MLS):** Sender key distribution uses MLS application messages. New members receive a key bundle via MLS. Sender key encryption happens before MLS encryption (double encryption).
- **ADR-002 (Envelope):** The inner envelope payload is first encrypted with the sender key, then the entire inner envelope is encrypted with MLS.

### Acceptance Criteria

1. **`generate_sender_key() -> SenderKey`**
   - Generates a random 32-byte AES-256 key.
   - Returns an opaque `SenderKey` handle.

2. **`encrypt_sender_layer(sender_key, plaintext) -> SenderCiphertext`**
   - Encrypts plaintext with AES-256-GCM using the sender key.
   - Generates a random 12-byte nonce per encryption.
   - Returns `(nonce || ciphertext || auth_tag)`.

3. **`decrypt_sender_layer(sender_key, sender_ciphertext) -> Plaintext`**
   - Decrypts AES-256-GCM ciphertext using the sender key.
   - Verifies the authentication tag. Rejects if verification fails.
   - Returns the plaintext.

4. **Pull-based sender key distribution protocol**

   Sender keys are distributed via a pull-based request/response protocol. When a sender generates or rotates a key, they publish a lightweight epoch advance notification. Members request the actual key material on demand. This replaces the push-based model where the sender HPKE-encrypted the key to every recipient in a single message.

   **Wire types (inside MLS application messages):**

   ```rust
   /// Sender key epoch advanced — author rotated their key.
   /// Published as an MLS application message (broadcast to group).
   pub struct SenderKeyEpochAdvance {
       pub sender_did: DID,
       pub epoch: u64,
       pub signer_key_ref: SigningKeyId,  // Which VM signed: Active or Agent (ADR-039)
       pub signature: Ed25519Signature,  // Signs context_id || sender_did || signer_key_ref || "key_epoch" || epoch
   }

   /// Request for a sender's current key at a specific epoch.
   /// Sent as an MLS application message with recipient_hint to the key holder.
   pub struct SenderKeyRequest {
       pub requester_did: DID,
       pub sender_did: DID,        // Whose key is being requested
       pub epoch: u64,
       pub wrapping_pubkey: X25519PublicKey,
       pub signature: Ed25519Signature,
   }

   /// Response with HPKE-encrypted sender key.
   /// Sent as an MLS application message with recipient_hint to the requester.
   pub struct SenderKeyResponse {
       pub sender_did: DID,
       pub epoch: u64,
       pub hpke_sealed_key: Vec<u8>,   // HPKE(requester_wrapping_pubkey, sender_key)
       pub ephemeral_pubkey: X25519PublicKey,
   }
   ```

   **4a. `publish_sender_key_epoch_advance(key_custody, mls_group, context_id, sender_did, epoch) -> MlsMessage`**
   - Constructs a `SenderKeyEpochAdvance` signed by the sender's Active Signing Key or Agent Signing Key (ADR-039): `Ed25519_sign(signing_key, SHA-256(context_id || sender_did || signer_key_ref || "key_epoch" || epoch))`. The `signer_key_ref` field records which verification method signed (e.g., `"#active"` or `"#agent"`).
   - Sends as an MLS application message (broadcast to all group members). **O(1) cost** regardless of group size.
   - Recipients verify the signature and record the new epoch for this sender.

   **4b. `handle_sender_key_request(key_custody, mls_group, request, block_list) -> Option<MlsMessage>`**
   - Receives a `SenderKeyRequest` from another member.
   - Verifies the request signature against `requester_did`.
   - Checks block list: if `requester_did` is blocked, returns `None` (no response, the requester cannot obtain the key).
   - If not blocked: seals the current sender key to the requester's `wrapping_pubkey` using HPKE Base mode (RFC 9180). Suite: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM. The `info` parameter provides domain separation: `"scp-sender-key-v1" || context_id || sender_did || epoch_bytes`. The `aad` parameter binds context: `context_id || sender_did || epoch_bytes`. The HPKE `enc` (encapsulated key) is transmitted as `ephemeral_pubkey` and `ct` (AEAD ciphertext) as `hpke_sealed_key` in the response. See §9.16.2 for the full HPKE specification.
   - Returns `Some(MlsMessage)` containing the `SenderKeyResponse`, sent with `recipient_hint` to the requester. **O(1) cost per request.**

   **4c. `request_sender_key(key_custody, mls_group, sender_did, epoch) -> MlsMessage`**
   - Constructs a `SenderKeyRequest` with a fresh ephemeral X25519 wrapping keypair.
   - Signs the request with the requester's Active Signing Key or Agent Signing Key (ADR-039).
   - Sends as an MLS application message with `recipient_hint` to the sender. **O(1) cost.**

   **HPKE open (recipient-side decryption):** Calls `SetupBaseR(enc, wrapping_secret_key, info)` where `enc` is `ephemeral_pubkey` from the response, then `recipient_context.Open(aad, ct)` where `ct` is `hpke_sealed_key`. The `wrapping_secret_key` is computed inside the `KeyCustody` boundary via `dh_agree(wrapping_key_handle, enc)` — the wrapping private key never leaves KeyCustody. See §9.16.2 for `info` and `aad` parameter formats.

   **New member join (pull-based):** When a new member joins the group, they observe each existing member's current `sender_key_epoch` from the group state. The new member publishes a `SenderKeyRequest` for each author whose key they need. Each author's SDK responds automatically (checking block list). Same O(N) total work as push-based, but demand-driven and naturally load-balanced — the new member drives the process, not N existing members racing to push.

   **Grace period:** When an epoch advances, the sender SHOULD continue accepting the old key for decryption of in-flight messages for 30 seconds (same grace window as MLS epoch keys, ADR-001 criterion 6). Messages encrypted with the new key and old key coexist briefly.

5. **`rotate_sender_key_for_block(mls_group, blocked_did) -> SenderKey`**
   - Generates a new sender key and increments the sender's `sender_key_epoch`.
   - Publishes a `SenderKeyEpochAdvance` via criterion 4a. **O(1) cost** — no per-recipient HPKE payloads on block.
   - Adds `blocked_did` to the sender's block list.
   - Non-blocked members observe the epoch advance, send `SenderKeyRequest` (criterion 4c), and receive the new key via `handle_sender_key_request` (criterion 4b) which checks the block list.
   - The blocked party can send a `SenderKeyRequest` but receives no response — they cannot obtain the new key.
   - Returns the new sender key.

6. **`send_block_notification(key_custody, mls_group, context_id, blocked_did, blocker_did) -> MlsMessage`**
   - Sends a signed block notification as an MLS application message.
   - The blocker signs the notification with their Active Signing Key or Agent Signing Key (ADR-039) to prevent forgery by other group members (MLS authenticates group membership, not individual identity within application messages).
   - Signature payload: `Ed25519_sign(signing_key, SHA-256(context_id || "block" || blocker_did || blocked_did || signing_key_id || timestamp))`.
   - Message content: `{ "type": "block", "blocker": blocker_did, "blocked": blocked_did, "signing_key_id": signing_key_id, "timestamp": unix_ms, "signature": blocker_signature }`.
   - **Verification on receipt:** The receiver MUST resolve the correct public key from the claimed blocker's DID document using the `signing_key_id` field (ADR-039), then verify the Ed25519 signature. Both `#active` and `#agent` are accepted. Discard without action if verification fails. Log the discarded notification for anomaly detection.
   - On successful verification, the blocked party's client automatically calls `rotate_sender_key_for_block` excluding the blocker.
   - The block event is recorded in the context event log (ADR-011) with `EventType::MemberBlocked { blocker, blocked, signature }`.

7. **`SenderKeyStore` struct**
   - Stores sender keys per (context_id, sender_did).
   - `get(context_id, sender_did) -> Option<SenderKey>`: Retrieve a sender's current key.
   - `set(context_id, sender_did, key)`: Store or update a sender key.
   - `remove(context_id, sender_did)`: Remove a sender key (for leave/removal).
   - `get_all(context_id) -> HashMap<DID, SenderKey>`: Get all sender keys for a context (for key bundle on member join).

### Scope

**Files (~2-3):**

| File | Purpose |
|------|---------|
| `mod.rs` | Module root, `SenderKey` type, `SenderKeyStore` struct, re-exports |
| `encrypt.rs` | `encrypt_sender_layer`, `decrypt_sender_layer` (AES-256-GCM operations) |
| `key_protocol.rs` | `SenderKeyEpochAdvance`, `SenderKeyRequest`, `SenderKeyResponse` types, `publish_sender_key_epoch_advance`, `handle_sender_key_request`, `request_sender_key`, `rotate_sender_key_for_block`, `send_block_notification` |

**Estimated functions:** ~10 public functions, ~5 internal helpers.

---

## Phase 1 Integration Test

The ultimate acceptance criterion for Phase 1 is a single integration test that exercises all 7 ADRs together:

```
1. Alice creates a did:dht identity (ADR-003) using in-memory key custody (ADR-006)
2. Bob creates a did:dht identity (ADR-003) using in-memory key custody (ADR-006)
3. Alice creates an MLS group (ADR-001)
4. Alice generates a sender key (ADR-007) and publishes a SenderKeyEpochAdvance
5. Bob publishes KeyPackages (ADR-001)
6. Alice adds Bob to the group using his KeyPackage (ADR-001)
7. Bob requests and receives Alice's sender key via pull-based protocol (ADR-007)
8. Alice creates a message, encrypts with sender key (ADR-007), wraps in inner envelope (ADR-002), encrypts with MLS (ADR-001), wraps in outer envelope with pseudonym routing (ADR-002)
9. Alice sends the outer envelope via the native relay (ADR-004) using the transport trait (ADR-005)
10. Bob receives the outer envelope via relay subscription (ADR-004, ADR-005)
11. Bob decrypts MLS layer (ADR-001), decrypts sender key layer (ADR-007), verifies inner envelope signature (ADR-002)
12. Bob reads Alice's message
13. The relay never saw: Alice's DID, Bob's DID, the context ID, the message content, or any metadata beyond the routing pseudonym and blob TTL
```

This test proves: identity works, encryption works, the envelope format works, sender keys work, the relay is a dumb pipe, and the transport abstraction is functional.

---

## ADR-039: Shared-DID Human-Agent Identity Model

**Date:** March 4, 2026
**Status:** Decided
**Extends:** ADR-003 (DID Creation)

### Context

SCP spec §4.3 states "one agent per person per context" but calls it "a social constraint, not a computational one." §9.3 admits "provably guaranteeing one-identity-per-human is an unsolved problem." The current implementation uses two separate DIDs — human DID and agent DID — linked by UCAN delegation (`MintSpendingParams { issuer_did, agent_did }`).

This model contradicts the protocol's own tenets:
- §9.1 invariant 1: "every action traces to a human" — but agent DID is unlinkable without UCAN chain resolution.
- §9.1 invariant 4: "one agent per person per context" — zero mechanical enforcement; a human can create N agent DIDs trivially.
- §1 principle 6: "human accountability" — agent has a separate identity the human can disown.
- §4.5: "the human is the root of identity, trust, and accountability" — but agent identity is structurally independent.

The separate-DID model provides human-agent unlinkability, which is not privacy — it is unaccountability. An unlinkable agent is an unaccountable agent.

### Decision

Human and agent share ONE DID with three verification methods:

```
DidDocument.verification_method = [
  #0      — Identity Key (Ed25519, hardware-backed, never rotates, derives DID)
  #active — Human Signing Key (Ed25519, human's operational key)
  #agent  — Agent Signing Key (Ed25519, agent software key, rotatable)
]
```

**Trust chain:** `#0` (root of trust) authorizes `#active` and `#agent` via DID document publication. Adding/removing `#agent` is a DID document update signed by `#0`.

**Key properties:**

| Property | `#0` | `#active` | `#agent` |
|----------|------|-----------|----------|
| Holder | Human | Human | Agent software |
| Backing | Hardware (SE/AKS) | Software | Software |
| Rotatable | No (Layer 2 migration only) | Yes (Layer 1 rotation) | Yes (Layer 1 rotation) |
| Signs DID doc updates | Yes | No | No |
| Signs operational actions | No | Yes | Yes (within permission scope) |

**Structural constraint:** Exactly one `#agent` verification method per DID document. Verifiers reject documents with multiple `#agent` VMs. `#agent` is optional — not every DID needs an agent.

**Agent key scope is global.** One persistent `#agent` key per DID, not per-context. DID documents are already ~1,140 bytes with 2 VMs (BEP44 v1 payload limit is 1,000 bytes, requiring bencode packing). Per-context agent keys would exceed document size constraints at scale. Context-specific restrictions on agent behavior use existing mechanisms: roles, capability ceilings, and context parameters — not separate keys.

### Permission Model

**Category A — Protocol-Immutable (`#0` or `#active` only, agent key MUST NOT sign):** The minimal set that must be human-only for the security model to hold — if the agent can perform these actions, it can bootstrap its own authority or modify its own constraints.
- DID document updates (add/remove keys, change services, alter relays) — requires `#0`
- Pre-rotation commitments — requires `#0`
- Identity migration (Layer 2) — requires `#0`
- Root UCAN issuance — requires `#active`. Root UCANs are the origin of all delegation chains; an agent that can issue root UCANs can grant itself arbitrary capabilities. Sub-delegation (minting scoped UCANs from an existing delegation) is Category B.

**Category B — User-Configurable:** All operational actions. Human sets defaults and limits per agent via UCAN `fct.scp_agent_permissions`.
- Messaging, blocking, context creation/joining, tool invocation, sub-UCAN minting, governance voting, spending — all configurable by the human with protocol defaults (messaging allowed, most other actions denied by default).

**Category C — Context-Configurable:** Per-context restrictions on agent actions via existing governance mechanisms (no new primitives).
- `agent_keys_allowed: false` — no agents in this context
- Agent-specific roles with restricted capabilities
- `agent_rate_limit` — rate limiting for agent actions
- `agent_cosign_required` — agent actions require human co-signature

### Enforcement Stack (5 Layers)

1. **Custody separation.** `#active` in hardware (Secure Enclave / Android Keystore) with session-based biometric unlock. `#agent` in software keychain accessible to agent runtime. Agent physically cannot invoke `#active` on hardware-backed platforms. On software-only platforms, isolation is process-level (different keychains, different access controls).

2. **SDK defaults.** Auto-selects correct key by call context. Developer must deliberately override defaults to misuse keys.

3. **Verifier validation.** Network-level enforcement: all conformant verifiers reject Category A actions (DID document modifications) signed by `#agent`. Non-conformant SDKs can produce these signatures, but they cannot propagate through the network. The attempt is both rejected and logged as a custody violation.

4. **Custody attestation.** At identity creation, the DID document includes a `ScpKeyCustodyAttestation` service entry declaring key custody model (`hardware-biometric` vs `software`) with optional platform attestation proof (Apple App Attest / Android Key Attestation). Unambiguous violations (Category A attempts with `#agent`, attestation mismatches with hardware proof) are permanently logged as `ScpCustodyViolationAttestation` records. DID owners can publish counter-attestations for reputation restoration. Absence of attestation is itself a signal.

5. **Behavioral signals.** Soft trust signal only — feeds into trust function (§7.1), NOT logged as violations. Timing patterns, usage anomalies, and interaction patterns provide supplementary context for trust evaluation. Explicitly excluded from violation records due to false positive risk.

### MLS Impact

`ScpCredential` gains a `signing_key_id: SigningKeyId` field (`Active` or `Agent`, wire-serialized as `"#active"` / `"#agent"`). Verifiers resolve the correct public key from the DID document based on this field. Same DID = same MLS membership entry. Agent key rotation doesn't require MLS re-key — only a credential update via MLS Update proposal.

```rust
pub enum SigningKeyId {
    Active,  // serializes to "#active"
    Agent,   // serializes to "#agent"
}

pub struct ScpCredential {
    pub did: String,
    pub ucan_token: Option<String>,
    pub signing_key_id: SigningKeyId,
}
```

`SigningKeyId` is an enum rather than a `String` to prevent invalid values at construction time — typos, case sensitivity, and unknown values are caught by the type system. The same enum is used for `signer_key_ref` on `SenderKeyEpochAdvance` and `signing_key_id` on `InnerEnvelope`. Wire serialization produces `"#active"`/`"#agent"` strings.

### UCAN Impact

Self-delegation: `iss == aud` (same DID), scoped by a new `fct.scp_key_scope` field. New UCAN JWT header `kid` field per RFC 7515 identifies which verification method signed the token.

New validation step 5b (after existing audience check): if `fct.scp_key_scope` exists, verify the signing key matches the specified scope.

`MintSpendingParams` refactored from `{ issuer_did, agent_did }` to `{ did, key_scope }` — spending UCANs become self-scoped delegations.

### Inner Envelope Impact

`InnerEnvelope` gains a `signing_key_id: SigningKeyId` field. Verifiers use it to resolve the correct public key from the sender's DID document. `SenderKeyEpochAdvance` gains a `signer_key_ref: SigningKeyId` field for the same purpose.

### Key Continuity

Fingerprint computation (§9.11) updated to include all three verification methods with domain separation and length-prefixed DIDs:
```
fingerprint = SHA256("SCP-KEY-CONTINUITY-V1:" || len(did_a) || did_a || len(did_b) || did_b || a_identity_key || a_active_key || a_agent_key || b_identity_key || b_active_key || b_agent_key)
```
Where `len()` is a 4-byte big-endian length prefix preventing concatenation ambiguity. The `"SCP-KEY-CONTINUITY-V1:"` domain separator prevents cross-protocol signature confusion. Agent key absence uses a domain-derived sentinel `SHA-256("SCP-ABSENT-AGENT-KEY")` instead of zero bytes to avoid collision with the Ed25519 identity point.

### Governance

One DID = one governance vote, regardless of which signing key is used. Prevents double-voting via `#active` and `#agent` on the same proposal.

### Compromise Recovery

Agent key compromise (most common case — agent runtime is less secure than device HSM):
1. Human uses `#0` to publish new DID document removing or replacing `#agent`.
2. Revoke all UCANs with `scp_key_scope: "#agent"`.
3. MLS credential updates in all active contexts (Update proposal with new credential).
4. Publish new KeyPackages.

### Rejected Alternative

**Separate DIDs linked by UCAN delegation (current model).** Rejected because:
- Zero mechanical enforcement of one-agent-per-context
- Agent accountability requires UCAN chain traversal (inferential, not structural)
- Agent identity is structurally independent — human can disown
- Human-agent unlinkability contradicts §9.1 invariant 1, §4.5, §1 principle 6
- Higher Sybil cost with shared-DID (every identity needs full human-grade depth signals)

### Acceptance Criteria

1. `DidDocument` supports three verification methods: `#0` (Identity Key), `#active` (Human Signing Key), `#agent` (Agent Signing Key, optional).
2. `ScpIdentity` includes `agent_signing_key: Option<KeyHandle>`.
3. `DidDht::create()` generates an optional fourth keypair for the agent signing key.
4. `add_agent_key()`, `remove_agent_key()`, `rotate_agent_key()` methods on `DidDocument`.
5. `ScpCredential` includes `signing_key_id: SigningKeyId` field; serialization round-trips correctly.
6. `UcanHeader` includes optional `kid: String` field; `MintParams` includes optional `key_scope: String`.
7. UCAN validation step 5b: if `fct.scp_key_scope` exists, verify the presenting key matches.
8. Self-delegation (`iss == aud` with `key_scope`) is explicitly valid.
9. `MintSpendingParams` uses `{ did, key_scope }` instead of `{ issuer_did, agent_did }`.
10. `InnerEnvelope` includes `signing_key_id: SigningKeyId`; verifiers resolve the correct DID document VM.
11. `SenderKeyEpochAdvance` includes `signer_key_ref: SigningKeyId`.
12. Key continuity fingerprint includes all three VMs.
13. One DID = one governance vote regardless of signing key.
14. Verifiers reject DID documents with multiple `#agent` VMs.
15. Verifiers reject Category A actions (DID document modifications) signed by `#agent`.
16. `ScpKeyCustodyAttestation` type published in DID document service entries.
17. `ScpCustodyViolationAttestation` type for permanently recording unambiguous violations.
18. `CounterAttestation` type for reputation restoration.
19. All FFI bridges (PyO3, NAPI, UniFFI, WASM) expose agent key creation, rotation, and status.
20. Integration test: create identity with agent key → mint scoped UCAN → join MLS group with agent credential → send message → verify at recipient → rotate agent key → verify credential update.
