# 3. Identity

## 3.1 Root of Identity

Every identity is rooted in a cryptographic keypair. This is the canonical identifier at the protocol level — not a username, not an email, not an account on someone's server.

Build on **DID (Decentralized Identifiers, W3C standard)**. DIDs provide the right abstraction: a cryptographic root that's method-agnostic, meaning the underlying key custody can vary without changing the identity itself.

## 3.2 Key Custody

Users never see or manage keys directly. Custody is delegated to whatever the user already trusts:

- Device secure enclave (iOS Secure Enclave, Android Keystore)
- Platform accounts (Apple, Google) via passkey infrastructure
- Hardware security keys
- Self-managed keys (power users who want direct control)

The identity layer abstracts custody. The user authenticates however they choose; under the hood it resolves to a protocol-level DID. Migration between custody methods is possible without changing identity.

## 3.3 Recovery

No seed phrases. Recovery uses social and device mechanisms:

- **Trusted device recovery:** Another device you control vouches for a new one.
- **Social recovery:** Trusted contacts confirm your identity.
- **Platform-backed recovery:** If custody is delegated to Apple/Google, their recovery mechanisms apply.

For new users with a single device and no SCP contacts, platform-backed recovery is the practical safety net. Social and device recovery grow in value over time as users add devices and build connections. Apps should prompt for trusted recovery contacts during onboarding — the same pattern Google and Apple use today.

## 3.4 Linking Existing Identities

Existing platform identities (Google, Apple, social accounts) can be linked to a protocol identity but are never the root. They serve as convenience and interop, not as source of truth.

## 3.5 Identity Attestations

A user can publish cryptographic attestations binding their external platform identities to their DID. These attestations are the mechanism that makes bridging trustworthy and social graph import possible.

An attestation says: "The human behind DID `did:key:abc...` is the same human behind `@alice` on X." The attestation is verifiable — the user proves ownership of the external identity (e.g., by signing a challenge, posting a proof, or using OAuth) and the result is a signed statement linking the two.

Properties of identity attestations:

- **Non-fungible.** The attestation binds a specific external identity to a specific DID. It cannot be transferred, forked, or shared. This is the foundation for cross-platform identity attribution.
- **User-initiated.** Only the human creates attestations for their own identities. No third party can assert a link on someone's behalf.
- **Independently verifiable.** Any participant can verify the attestation without relying on a central authority. Verification methods vary by platform (OAuth proof, signed message, DNS record, etc.).
- **Revocable.** Users can revoke attestations at any time, severing the link.
- **Discoverable.** Other SCP participants can look up whether a given external identity maps to a known DID. Attestations are discoverable through discovery contexts (§6.2.2B) and DID document capability entries (§7.4.1). Reverse-lookup (external handle → DID) is provided by the `attestation_lookup` tool in discovery contexts (§22.5).

Identity attestations enable three critical flows:

1. **Social graph import.** A user exports their follower list from X. Their local agent resolves each handle against known attestations. Contacts who have also joined SCP are automatically discoverable.
2. **Shadow identity claiming.** When a bridge connector creates a shadow identity for an external participant (see §12), a user can claim it by presenting a matching attestation. The shadow identity merges with their real DID.
3. **Cross-platform reputation continuity.** Trust judgments about a person can follow them across platforms — not because platforms share data, but because the human has cryptographically proven they're the same person.

## 3.6 Social Graph

There is no global social graph. No "friends list" primitive. No public follower count. No network-wide structure anyone can query.

Social graph data **is context state.** Each context already knows its members — their DIDs, their roles, their participation history. This is protocol state: verifiable against the context's event log, persistent, governed by context permissions. The social graph is not stored separately or owned by any agent. It is the sum of membership across contexts.

A user's view of their own social graph is **assembled from capability-gated queries** against the contexts they participate in. Your agent queries contexts for membership data, computes relationship strength from shared participation (how many contexts, how long, in what roles), and presents the result. The data lives in the contexts. The view is computed. Access is permissioned.

**Social graph sharing is capability-gated.** Sharing your social graph with others — letting someone see which contexts you're in, who you share spaces with — is governed by the same trust and capability model as any other data access. Grants are scoped however you choose:

- **Per-identity.** "Bob can see my connections. Carol cannot."
- **Per-capability scope.** "Bob can see that I'm in this context. Bob cannot see my other contexts."
- **Per-context.** "Everyone in this context can see that I'm a member. Nobody here can see what other contexts I'm in."
- **Per-category.** "Close contacts can see my full context list. Everyone else sees nothing."

This extends to relationship metadata — not just whether a connection exists, but the nature of it. Alice might see that you and Bob are both in the cooking quest. She cannot see that you and Bob also share a private finance context, unless you've granted that visibility.

**Access is through capability-gated protocol interfaces.** Social graph data is accessed through the same permission model as any other protocol data. Queries hit capability-gated interfaces; the protocol checks permissions before responding. No special mechanisms, no local caches treated as source of truth. The protocol provides query APIs for assembling and sharing graph views — these are not static data stores but permission-scoped computations over context membership.

**No new primitives required.** Social graph visibility falls out of the existing trust equation: `trust = f(identity, capability, context, metadata)`. Capability tokens authorize reading specific slices of your graph. The social graph isn't a separate system with its own privacy model — it's just another resource governed by the same model as everything else.

**Block/mute** is stored in identity private state (§3.7) — persistent, portable, encrypted.

**Blocking** operates at three tiers, each enforced through the same three cryptographic layers (§9.16, §9.17):

- **Layer 1 (key distribution denial):** Block list check denies key re-requests to blocked DIDs.
- **Layer 2 (SDK-mandated state destruction):** On block event, the blocker's SDK destroys cached keys and plaintext from the blocked party. This is a protocol requirement for compliant clients.
- **Layer 3 (access key wrapping):** Content keys are wrapped with per-member access keys. Deleting a member's access key = cryptographic revocation of stored content. See §9.17.

**Tier 1: DID-to-DID in-context (per-relationship, unilateral).** Alice blocks Dave in context X. Affects Alice's content in that context only — Dave can still see other members' content. This is the §9.16 sender-side blocking, scoped to a single context. On block: Alice rotates her sender key excluding Dave (Layer 1), Alice's SDK destroys Dave's cached content from Alice (Layer 2), Alice deletes Dave's access key for her content (Layer 3). On unblock: Alice removes Dave from her block list. Forward-only — Dave receives Alice's future content but historical content from before/during the block remains inaccessible (access keys were destroyed, not archived).

**Tier 2: DID-to-DID global (identity-level, cross-context).** Alice blocks Dave everywhere. Stored in identity private state (§3.7). Propagates to all contexts Alice and Dave share — equivalent to Tier 1 applied to every shared context simultaneously. On block: same three layers, applied across all shared contexts. On unblock: same forward-only restoration, across all shared contexts. Blocking is bidirectional: when Alice blocks Dave, both Alice's and Dave's SDKs rotate their sender keys excluding each other (§9.16.3).

**Tier 3: Governance-gated (context-level, all content).** Context governance revokes a member's content access. Goes through GovernanceEngine (propose/approve/reject per §5.9). Affects the target's access to ALL content in the context — not just one member's content. Governance actions: `RevokeReadAccess`, `RevokeWriteAccess`, `RestoreReadAccess`, `RestoreWriteAccess`, `RotateContentKeys` (see ADR-031). Restoration is forward-only.

**Tier stacking:** All three tiers compose. If both Alice (Tier 1) and governance (Tier 3) have revoked Dave's access, both must be independently reversed for full restoration. Each tier's revocation and restoration is independent.

**Key difference between tiers:** Tiers 1-2 are per-relationship (Alice blocks Dave = Dave can't see Alice's content; Dave can still see Bob's content). Tier 3 is per-context (governance revokes Dave = Dave can't see ANY content in the context).

**Mute** is unidirectional. Alice mutes Dave; Alice no longer sees Dave's content. Dave is unaffected and can still see Alice. Muting is a protocol rule enforced in the SDK — apps built on the SDK inherit this behavior. Because the muter is not adversarial against themselves (they chose the mute), SDK-level enforcement is sufficient; cryptographic exclusion is not required.

## 3.7 Identity Private State

A DID has public state (keys, service endpoints, published attestations) and **private state** — encrypted data that only the identity owner can read, replicated for availability and portability.

Context state handles multi-party social data. Identity private state handles single-party personal data. Together they cover every category of protocol-relevant state without requiring anything to live only on a local device.

```
Identity (DID)
├── Public State (DID Document)
│   ├── Public keys
│   ├── Service endpoints / relay list
│   └── Published attestations
│
└── Private State (encrypted, replicated)
    ├── Block / mute list
    ├── Graph visibility policies (default + per-identity grants)
    ├── Agent configuration defaults (cross-context preferences)
    ├── Personal annotations on other DIDs
    ├── Petnames for DIDs and contexts (§22.4)
    ├── Notification preferences
    ├── Draft attestations (not yet published)
    └── (extensible — any identity-level private data)
```

**Encryption model.** Private state is encrypted to the identity's own keys. This is the single-owner case — no group key management, no member add/remove. Only you hold the decryption key. Simpler than context encryption, same confidentiality guarantee.

**Storage model.** Same as context state: encrypted blobs stored on your published relays. Relays see "DID X has encrypted private state." Relays store and serve it. Relays cannot read, modify, or interpret it. This is encryption-as-access-control (§10.5) applied to identity rather than context — the same infrastructure, the same relay behavior, the same trust assumptions.

**Sync model.** Append-only event log, same pattern as context event logs. Each device appends events ("blocked DID Y at timestamp T", "granted Bob graph visibility at scope Z"). Any device reconstructs current state from the log. Multi-device consistency: two phones and a laptop all append to the same log, all converge to the same state.

Most identity private state operations are naturally commutative — "block X" and "block Y" produce the same result regardless of order. Simultaneous updates from multiple devices resolve without conflict in most cases. The event log records all operations; state is derived from the full log.

**Integrity.** The event log is authenticated (Merkle root or equivalent). If a relay tampers with your private state, you detect it on next read. Single-owner verification is simpler than multi-party — you're the only writer — but the integrity guarantee is the same.

**Relationship to context state.** Identity private state is the single-owner degenerate case of context state. Same storage infrastructure. Same integrity model. Same relay interaction. No governance, no roles, no capability ceiling — because it's your data. The protocol doesn't need new infrastructure for this — it's the existing infrastructure with membership count of one and no access control layer (the encryption IS the access control, and only you have the key).

**Protocol-level constants (immutable):**

- **Size constraints.** Less constrained than context state. The single-owner case allows growth (block lists, annotations, agent memory, draft attestations) without imposing storage on other participants. Relays MAY enforce per-DID storage quotas as an operational concern, but the protocol does not mandate minimalism for identity private state.
- **Relay obligations.** Same storage class and retention as context events. No differentiated commitment — relays treat all encrypted blobs uniformly. A relay that stores context events for a DID stores identity private state under the same terms.
- **Key rotation.** On identity key rotation (§9.12), private state is re-encrypted to the new key. Single-owner case requires no group redistribution — the owner re-encrypts and republishes. For large private state, re-encryption is incremental: most recent events first, backfill in background.
- **Discovery pointer.** Explicit. The DID document includes a service endpoint of type `IdentityPrivateState` listing relays that store private state. This cleanly disambiguates context event fetches from private state fetches without relay-side guessing.
- **Relay service endpoints.** The DID document includes service endpoints of type `SCPRelay` listing the identity's transport-layer relay URLs — the endpoints where `TransportManager` routes encrypted blobs for this identity. Multiple entries are recommended for suppression resistance (§9.9.2). Self-certified via BEP44 signature (§9.6.3). See §18.2 for the full specification of DID document service endpoint types.

### 3.7.1 Block List Storage

Identity private state stores block lists at two granularities:

**Global block list.** DIDs blocked across all shared contexts (Tier 2). Stored as an append-only event log within identity private state:

- `BlockDID { target_did, timestamp }` — add DID to global block list.
- `UnblockDID { target_did, timestamp }` — remove DID from global block list.

The current block list is derived by replaying the event log. Both operations are commutative — "block X" and "block Y" produce the same state regardless of order. Multi-device sync is conflict-free: two devices can independently add blocks, and the union is correct.

**Per-context block list.** DIDs blocked in a specific context only (Tier 1). Same event types but scoped:

- `BlockDIDInContext { target_did, context_id, timestamp }`
- `UnblockDIDInContext { target_did, context_id, timestamp }`

**Block list propagation.** When a global block is issued (Tier 2), the SDK propagates to all shared contexts:

1. Enumerate contexts where both the blocker and the target are members.
2. For each shared context, execute the Tier 1 block protocol (§9.16.3) — rotate sender key, destroy cached content, delete access key.
3. Record the block in identity private state.

Propagation is best-effort and idempotent — if the SDK is offline for some contexts, the block executes on next connection. The identity private state event log is the authoritative record; per-context enforcement is the mechanism.

**ProtocolStore methods.** The `Storage` trait (§17) requires these methods for block list persistence:

- `get_global_block_list(did: &DID) -> Result<Vec<DID>>`
- `is_globally_blocked(blocker: &DID, target: &DID) -> Result<bool>`
- `get_context_block_list(did: &DID, context_id: &ContextId) -> Result<Vec<DID>>`
- `is_blocked_in_context(blocker: &DID, target: &DID, context_id: &ContextId) -> Result<bool>`

These methods derive current state from the identity private state event log. Implementations MAY maintain materialized views for query performance.

## 3.8 DID Resolution Security

DID resolution is the trust root for the entire protocol. If resolution can be MITMed, every layer above — encryption, authentication, capability validation — is compromised. The security properties depend on the DID method:

**did:dht (target method):** Self-certifying. The DID string encodes the public key. DID documents are signed via BEP44 and verifiable against the DID without trusting any intermediary. MITM on resolution is impossible given the correct DID. Stale documents are rejected via sequence numbers. See §9.6 for full specification.

**did:web (fallback only):** NOT self-certifying. Security depends on DNS + TLS + server integrity. The SDK MUST use TLS pinning + TOFU (Trust On First Use) + key change alerts to mitigate. did:web exists as a fallback if did:dht libraries prove unusable — not as a planned stepping stone. See §9.6.2 for required mitigations.

**Key Continuity Verification:** Signal-style safety numbers for DIDs, enabling out-of-band verification that two parties have the correct keys for each other. See §9.11.

## 3.9 Key Lifecycle

Identity keys follow a defined lifecycle: generation (in hardware security modules where available), distribution (via DID document publication), rotation (DID document update with authorization chain from old key), and destruction (for ephemeral context keys). The full key lifecycle specification, including compromise recovery, is in §9.7.4 and §9.12.

## 3.10 DID Resolution Layers

DID resolution is the trust root for identity verification (§3.8). The current architecture resolves identities exclusively via Mainline DHT — BEP44 signed mutable items stored on BitTorrent's distributed hash table, a network of millions of nodes with over 20 years of operational history. This works, and it works well. But it routes all identity resolution through infrastructure SCP does not control, cannot improve, and cannot guarantee will continue to operate on terms compatible with the protocol's needs.

SCP introduces a dual-layer resolution architecture:

- **Primary: SCP relay-based resolution.** DID documents stored on SCP relays as standard blobs, resolved via existing relay operations. Grows with the SCP network. Requires no protocol changes — DID documents are just another blob type routed by a deterministic `routing_id`.
- **Fallback: Mainline DHT.** Existing did:dht resolution via BEP44. Works from day one. Transitions from "only path" to "fallback path" as the relay network matures.

Both layers are self-certifying: the BEP44 signature on a DID document is verified against the public key encoded in the DID string itself (§9.6.1). The storage backend — whether an SCP relay or a DHT node — is untrusted. Trust derives from the cryptographic binding between the DID and its document, not from the infrastructure serving it.

### 3.10.1 Resolution Priority

| Layer | Backend | Day-one availability | Latency | SCP dependency |
|-------|---------|---------------------|---------|----------------|
| 1 | SCP relays | Low (few relays exist) | Low (relay QUERY, single hop) | Yes |
| 2 | Mainline DHT | High (millions of nodes) | Higher (DHT traversal, 1-3s typical) | No |

Resolution strategy: query both layers in parallel. The first valid response wins. "Valid" means the BEP44 signature verifies against the public key encoded in the target DID AND the sequence number is greater than or equal to the last known sequence number for that DID. When both layers return valid documents, the document with the highest sequence number is accepted.

Parallel query means resolution latency is `min(relay_latency, dht_latency)`. The slower query is cancelled once the first valid response arrives.

### 3.10.2 Layer 1: SCP Relay-Based Resolution

DID documents are published to SCP relays using the existing relay operations defined in ADR-004. No new wire types, no special relay behavior — a DID document is a blob addressed by a deterministic `routing_id`.

**Routing ID derivation:**

```
did_routing_id = SHA-256("scp:did:" || did_string)
```

The `"scp:did:"` domain separator prevents collision with other routing ID derivation schemes in the protocol: encrypted context routing IDs use HKDF from identity key material (§9.10.4), broadcast context routing IDs use `SHA-256(context_id)` (§5.14), and context metadata routing IDs use `SHA-256(context_id || "scp-metadata")` (§5.7). The domain separator ensures that a DID string can never produce a routing ID that collides with a context ID or metadata address.

**Publication** uses the existing PUBLISH operation (ADR-004):

```
PUBLISH {
    routing_id: did_routing_id,
    blob_ttl: 604800,
    blob: <BEP44-signed DID document>
}
```

**Resolution** uses the existing QUERY operation:

```
QUERY {
    routing_id: did_routing_id,
    since: null,
    limit: 1
}
```

**Properties:**

- **No protocol changes.** PUBLISH and QUERY are existing relay operations. DID documents are stored and retrieved like any other blob. Relays require no awareness that a blob contains a DID document.
- **Relay-agnostic.** A resolver can QUERY any relay that stores the target DID document. Identity owners SHOULD publish to multiple relays — their own relays plus bootstrap relays from the fallback relay list (§18.5.1) — for suppression resistance.
- **Size budget.** DID documents range from 2-30KB depending on attestation count and service endpoint list. The relay blob size limit is 256KB (ADR-004). Well within bounds.
- **TTL and republishing.** The maximum relay blob TTL is 604800 seconds (7 days). Identity owners MUST republish to relays at least every 6 days (1-day safety margin). The RepublishManager already handles periodic DHT republishing on a 2-hour cycle; relay republishing adds a separate 6-day cycle for relay-stored DID documents.

### 3.10.3 Layer 2: Mainline DHT (Fallback)

Existing did:dht resolution via BEP44 signed mutable items on Mainline DHT. The mechanism is unchanged from §3.8 and §9.6.1. What changes is its role: from "only resolution path" to "fallback resolution path."

The DHT layer remains essential for:

- **Day-one operation.** The SCP relay network starts small. Most DID documents will not be available on relays until the network grows. DHT availability is immediate.
- **Resolution of identities not yet publishing to SCP relays.** Older identities or identities using minimal SDK configurations may only publish to DHT. The protocol MUST resolve them.
- **Resilience when all of an identity's relays are down.** DHT provides a resolution path independent of any specific relay's availability.
- **Cross-network interoperability.** Any BEP44-capable client can resolve SCP identities without running SCP software. The DHT layer preserves this property.

### 3.10.4 Resolution Protocol

The full resolution sequence:

```
1. Compute did_routing_id = SHA-256("scp:did:" || did_string)
2. Extract public_key from DID string (z-base-32 decode per did:dht spec)
3. In parallel:
   a. QUERY did_routing_id on known SCP relays
      (identity's published relays if known, else bootstrap relays from §18.5.1)
   b. DhtClient.resolve(public_key) on Mainline DHT
4. For each response:
   a. Verify BEP44 signature against public_key
   b. Verify seq >= last_known_seq for this DID
5. Accept the valid response with highest sequence number
6. Cache result per §9.10.7 caching policy
   (24h refresh for active contacts, 7d for inactive)
```

The relay query in step 3a targets relays in priority order: the identity's own relays (from a previously cached DID document), then bootstrap relays. If the resolver has no prior knowledge of the identity's relays, only bootstrap relays are queried for the relay layer — the DHT layer provides the backup.

### 3.10.5 Publishing Protocol

Identity owners publish to both layers on every DID document create or update:

```
On DID document create or update:
1. Serialize DID document
2. Sign via BEP44 (Ed25519 signature over bencoded value concatenated with
   sequence number, per BEP44 spec)
3. In parallel:
   a. PUBLISH to SCP relays (own relays + bootstrap relays), blob_ttl: 604800
   b. DhtClient.publish(public_key, signature, doc_bytes, seq) to Mainline DHT
4. RepublishManager schedules:
   - Relay republishing: every 6 days (blob_ttl is 7 days, 1-day margin)
   - DHT republishing: every 2 hours (existing cycle, unchanged)
```

Both layers receive identical document bytes and identical BEP44 signatures. The signed payload is the same regardless of storage backend — this is a direct consequence of the self-certification property. A document retrieved from a relay and a document retrieved from the DHT are byte-identical and verify identically.

### 3.10.6 Anti-Segmentation Invariant

**Publishing to both layers is a MUST, not a SHOULD.** Resolution from both layers is a SHOULD (performance optimization — parallel query is faster but not required for correctness).

The risk: if the DHT layer works well enough and relay-based resolution is "just faster," developers may skip DHT publishing as unnecessary overhead. If this becomes widespread, identity resolution fragments — some DIDs resolvable only on relays, others only on DHT. A resolver that checks only one layer misses identities published only on the other. The network splits into two resolution namespaces without anyone intending it.

The SDK prevents this by default. RepublishManager publishes to both layers on every cycle. Disabling either layer requires explicit opt-out (`RepublishConfig::disable_dht()` or `RepublishConfig::disable_relay()`) and the SDK MUST log a warning when either is disabled. The warning states: "DID resolution layer disabled. This identity may not be resolvable by all peers."

### 3.10.7 Version Resolution

The BEP44 sequence number is the sole authority for document freshness. The highest valid sequence number wins, regardless of which layer served it. Split-brain is impossible: the sequence number is monotonically increasing, and only the identity owner (holder of the Ed25519 private key) can increment it.

Stale documents are detected by comparing the received sequence number against the last known sequence number for that DID. A relay or DHT node serving a stale document is not malicious — it simply has not received the latest publish. The stale document is overwritten on the next republish cycle.

When both layers return valid documents with different sequence numbers, the higher sequence number is authoritative. The resolver SHOULD update its cache and MAY re-publish the fresher document to the layer that returned the stale one (protocol-level healing).

### 3.10.8 Security Analysis

The dual-layer architecture preserves all security properties of §9.6.1 (self-certification) while adding relay-layer resilience:

- **Self-certification preserved.** The BEP44 signature is verified against the public key encoded in the DID string. The storage backend (relay or DHT) is untrusted. §9.6.1 properties are unchanged.
- **Relay serves stale document.** Detected by sequence number comparison. The resolver falls through to other relays or DHT. Stale documents do not compromise security — they delay propagation of key rotations, which is bounded by the republish cycle (6 days for relays, 2 hours for DHT).
- **Relay suppresses document.** Parallel query across multiple relays plus DHT. Suppression by one source does not prevent resolution. Multi-relay publishing (§9.9.2) applies to DID documents as it does to context blobs.
- **Relay serves wrong DID's document.** The BEP44 signature does not verify against the target DID's public key. Rejected immediately. The routing ID is derived from the DID string, but verification is against the DID's key — substitution is cryptographically impossible.
- **Dual-layer resilience.** An attacker must suppress a DID document on ALL of an identity's relays AND ALL reachable DHT nodes to prevent resolution. This is a strictly harder attack than suppressing on either layer alone.

### 3.10.9 Privacy Properties

| Layer | What the backend learns |
|-------|------------------------|
| SCP relay | Resolver's IP address queried a specific `routing_id`. The relay can infer which DID is being resolved if the relay knows the DID (it can compute the same `SHA-256("scp:did:" \|\| did_string)` for known DIDs). |
| Mainline DHT | Resolver's IP address queried a public key. DHT routing traffic makes isolation harder (§9.10.7). |

Adding relay-based resolution does not degrade privacy relative to DHT-only resolution. It adds one additional observer (the relay operator) who, for identities hosted on that relay, already sees message traffic for that identity. The DID resolution query does not reveal information the relay operator did not already have.

Caching policy from §9.10.7 applies to both layers: 24-hour refresh for active contacts, 7-day for inactive. The local Mainline DHT node on desktop (§9.10.7) continues to provide resolution privacy for DHT queries.

### 3.10.10 DidResolver Trait

The SDK exposes a unified resolution interface that composes both layers:

```rust
/// Unified DID resolution across SCP relays and Mainline DHT.
/// Implements the parallel dual-layer resolution protocol (§3.10.4).
pub trait DidResolver: Send + Sync {
    fn resolve(&self, did: &str)
        -> impl Future<Output = Result<Option<ResolvedDidDocument>, IdentityError>> + Send;
}

/// A resolved DID document with provenance metadata.
pub struct ResolvedDidDocument {
    /// The verified DID document.
    pub document: DidDocument,
    /// BEP44 sequence number. Monotonically increasing.
    pub seq: u64,
    /// Which resolution layer served this document.
    pub source: ResolutionSource,
}

/// Provenance of a resolved DID document.
pub enum ResolutionSource {
    /// Resolved via QUERY to an SCP relay.
    ScpRelay { relay_url: String },
    /// Resolved via Mainline DHT BEP44 lookup.
    MainlineDht,
    /// Served from local cache (original source recorded at cache time).
    Cache,
}
```

`DidResolver` composes the relay QUERY path with `DhtClient::resolve()` internally. The existing `DidMethod::resolve()` interface continues to work for single-layer DHT resolution — `DidResolver` is an additive layer, not a replacement. Code that only needs DHT resolution (e.g., interoperability tools) can use `DidMethod` directly.

### 3.10.11 Bootstrap and Network Growth

The dual-layer architecture is designed to be self-reinforcing as the SCP network grows:

- **Day one.** DHT dominates. Relay-layer queries mostly fail because few relays exist and few identities have published DID documents to relays. Resolution latency is DHT latency. The protocol works identically to the pre-§3.10 architecture.
- **Growth.** More relays come online. More identities publish to relays. Relay-layer resolution begins succeeding more often, and faster than DHT traversal. DHT queries still run in parallel as backup.
- **Maturity.** Relay-layer resolution is primary for most identities. DHT latency becomes irrelevant because relay responses arrive first. DHT serves as an availability backstop and interoperability bridge for non-SCP clients.
- **DHT is never removed.** The cost of maintaining DHT publishing is one BEP44 put every 2 hours — negligible. The benefit is permanent: a resolution path that works even if every SCP relay is unreachable. Removing it would violate the anti-segmentation invariant (§3.10.6).

### 3.10.12 Phase Integration

| Component | Phase | Crate | Notes |
|-----------|-------|-------|-------|
| `did_routing_id` derivation | Phase 1 patch | `scp-core` | Pure function, no dependencies. SHA-256 of domain-separated DID string. |
| DID document PUBLISH to relays | Phase 2 | `scp-core` | RepublishManager gains relay publishing cycle alongside existing DHT cycle. |
| DID document QUERY from relays | Phase 2 | `scp-core` | Extends existing DID resolution path with relay QUERY before/parallel to DHT. |
| `DidResolver` trait | Phase 2 | `scp-core` | Unified interface composing relay + DHT resolution. |
| Parallel dual-layer resolution | Phase 2 | `scp-core` | Orchestration of parallel queries with first-valid-wins semantics. |
