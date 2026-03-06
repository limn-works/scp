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

- **Trusted device recovery:** Another device you control vouches for a new one. The trusted device enrolls the new device into the identity's device registry and distributes the Private State Key (PSK) via HPKE (§3.7.2). Recovery IS device enrollment — the same cryptographic protocol applies.
- **Social recovery:** Trusted contacts confirm your identity. After social recovery re-establishes key custody, the recovering device is enrolled as a new device (§3.7.2) and receives the PSK from any existing enrolled device. If no enrolled devices remain (all devices lost), PSK recovery requires re-keying: a new PSK is generated, existing private state history encrypted under the old PSK is permanently inaccessible (same forward-only property as §9.17.5), and the identity starts a fresh private state log.
- **Platform-backed recovery:** If custody is delegated to Apple/Google, their recovery mechanisms apply. The PSK is stored in the platform's secure key store (Keychain, Keystore — §17.8) and may be recoverable through platform backup/restore mechanisms (e.g., iCloud Keychain sync, Google Cloud Key Vault). This provides a recovery path for the PSK that does not depend on another SCP device being available.

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
│   ├── Verification methods (ADR-039)
│   │   ├── #0 — Identity Key (Ed25519, root of trust, offline)
│   │   ├── #active — Human Signing Key (Ed25519, hardware-backed)
│   │   └── #agent — Agent Signing Key (Ed25519, optional, software-held, rotatable)
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

**Encryption model.** Private state is encrypted with a dedicated symmetric **Private State Key (PSK)** — an AES-256 key used exclusively for identity private state encryption. The PSK is not derived from any signing key. Ed25519 keys are signing-only — they cannot be used for encryption. The PSK is generated independently and distributed to the identity owner's devices via HPKE (§3.7.2).

**Cryptographic specification:**

- **Algorithm:** AES-256-GCM (RFC 5116).
- **Key:** 32-byte random Private State Key (PSK), generated via CSPRNG (e.g., `OsRng`). The PSK is a raw symmetric key — it is not managed through `KeyCustody` (which handles asymmetric Ed25519/X25519 keys). One PSK per identity, shared across all enrolled devices.
- **Nonce:** 96-bit (12-byte) random nonce, generated per event via CSPRNG. Each event in the private state log gets a unique nonce. The nonce is stored alongside the ciphertext — it is not secret.
- **AAD (Additional Authenticated Data):** `did || "scp-private-state-v1" || sequence_number` where `did` is the identity's DID string encoded as 4-byte big-endian length prefix + UTF-8 bytes (per §9.5.1 encoding rules), `"scp-private-state-v1"` is the domain separator as raw UTF-8 bytes (no length prefix — fixed per version), and `sequence_number` is the event's sequence number as 8-byte big-endian u64. AAD binding prevents: (a) ciphertext from one identity being replayed against another, (b) events being reordered within the log, (c) cross-protocol confusion with other AES-256-GCM uses in SCP.
- **Domain separator:** `"scp-private-state-v1"`. Distinct from `"scp-sender-key-v1"` (§9.16.2), `"scp-access-key-v1"` (§9.17.1), and all other SCP domain separators.

```
Encryption (per event):
  nonce = random(12)
  aad = len(did) || did || "scp-private-state-v1" || sequence_number
  (ciphertext, tag) = AES-256-GCM-Seal(PSK, nonce, plaintext_event, aad)
  stored: { nonce, ciphertext, tag, sequence_number }

Decryption (per event):
  aad = len(did) || did || "scp-private-state-v1" || sequence_number
  plaintext = AES-256-GCM-Open(PSK, nonce, ciphertext, tag, aad)
  if tag verification fails → reject (tampered or wrong key)
```

**Storage model.** Same as context state: encrypted blobs stored on your published relays. Relays see "DID X has encrypted private state." Relays store and serve it. Relays cannot read, modify, or interpret it. This is encryption-as-access-control (§10.5) applied to identity rather than context — the same infrastructure, the same relay behavior, the same trust assumptions.

**Sync model.** Append-only event log, same pattern as context event logs. Each device appends events ("blocked DID Y at timestamp T", "granted Bob graph visibility at scope Z"). Any device that holds the PSK reconstructs current state from the log. Multi-device consistency: two phones and a laptop all hold the same PSK, all append to the same log, all converge to the same state. See §3.7.2 for how the PSK is distributed to devices.

Most identity private state operations are naturally commutative — "block X" and "block Y" produce the same result regardless of order. Simultaneous updates from multiple devices resolve without conflict in most cases. The event log records all operations; state is derived from the full log.

**Integrity.** The event log is authenticated (Merkle root or equivalent). If a relay tampers with your private state, you detect it on next read. Single-owner verification is simpler than multi-party — you're the only writer — but the integrity guarantee is the same. The AES-256-GCM authentication tag provides per-event integrity verification: any modification to ciphertext, nonce, or associated data causes tag verification failure.

**Relationship to context state.** Identity private state is the single-owner degenerate case of context state. Same storage infrastructure. Same integrity model. Same relay interaction. No governance, no roles, no capability ceiling — because it's your data. The protocol doesn't need new infrastructure for this — it's the existing infrastructure with membership count of one and no access control layer (the encryption IS the access control, and only you have the key).

**Protocol-level constants (immutable):**

- **Size constraints.** Less constrained than context state. The single-owner case allows growth (block lists, annotations, agent memory, draft attestations) without imposing storage on other participants. Relays MAY enforce per-DID storage quotas as an operational concern, but the protocol does not mandate minimalism for identity private state.
- **Relay obligations.** Same storage class and retention as context events. No differentiated commitment — relays treat all encrypted blobs uniformly. A relay that stores context events for a DID stores identity private state under the same terms.
- **Key rotation.** On identity key rotation (§9.12), the PSK is rotated: generate a new PSK, re-encrypt private state events, distribute the new PSK to all enrolled devices via HPKE (§3.7.2). The old PSK is destroyed on all devices after re-encryption completes. For large private state, re-encryption is incremental: most recent events first, backfill in background. Each re-encrypted event receives a fresh random nonce.
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

### 3.7.2 Multi-Device Private State Key Distribution

Identity private state is encrypted with a single PSK shared across all of the identity owner's devices. The challenge: each device has its own hardware-backed keys that cannot be exported (§9.7.2), so the PSK must be distributed TO each device rather than derived FROM a shared secret.

**Device enrollment model.** Each device generates a device-specific X25519 keypair via `KeyCustody::generate_keypair(KeyType::X25519)` at device enrollment time. This keypair is used exclusively for receiving HPKE-wrapped key material (PSK distribution, PSK rotation). The X25519 public key is published in the identity's device registry — an encrypted list within identity private state itself (bootstrapped during identity creation, see below).

**Why not derive from the Identity Key (#0)?** The Identity Key is Ed25519 (signing-only) and its private key "never [leaves] the secure element" (§9.7.2). While Ed25519-to-X25519 conversion is mathematically possible (RFC 7748, birational equivalence between Edwards and Montgomery curves), it requires access to the Ed25519 private key bytes — which hardware security modules (Secure Enclave, Android Keystore) do not export. A design that depends on Ed25519-to-X25519 conversion would fail on every hardware-backed key. The PSK is therefore an independent symmetric key, distributed via HPKE to device-specific X25519 keys that are software-managed through `KeyCustody`.

**Identity creation (first device):**

1. Generate the PSK: 32 random bytes via CSPRNG.
2. Generate a device-local X25519 keypair via `KeyCustody`.
3. Store the PSK locally in the device's secure key store.
4. Initialize the device registry in identity private state with this device's X25519 public key. The device registry is the first event in the private state log — it is encrypted with the PSK (which only this device holds at this point).
5. Publish the encrypted private state to relays.

**Adding a new device (device enrollment):**

```
Existing device (Device A) enrolls new device (Device B):

1. Device B generates an X25519 keypair via KeyCustody.
2. Device B presents its X25519 public key to Device A.
   Transport: out-of-band (QR code, local network, NFC) or via
   a standing bilateral context (§5.12.4) between the human's devices.
3. Device A verifies the enrollment request (user confirmation required).
4. Device A wraps the PSK to Device B's X25519 public key via HPKE:
   enc, sealed_psk = HPKE-Seal(
     mode: Base,
     kem: DHKEM(X25519, HKDF-SHA256),
     kdf: HKDF-SHA256,
     aead: AES-128-GCM,
     recipient_pk: device_b_x25519_pubkey,
     info: "scp-private-state-v1" || len(did) || did || "device-enroll",
     plaintext: psk
   )
5. Device A sends (enc, sealed_psk) to Device B via the same channel.
6. Device B opens the HPKE ciphertext using its X25519 private key,
   recovering the PSK.
7. Device A appends a DeviceEnrolled event to the private state log:
   DeviceEnrolled { device_x25519_pubkey, enrolled_at, enrolled_by_device }
   This event is encrypted with the PSK (readable by all enrolled devices).
8. Device B can now decrypt and append to the private state event log.
```

**HPKE suite.** Device enrollment and PSK distribution use DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM — the same HPKE suite as MLS (§9.5) and sender key distribution (§9.16.2). The `info` parameter includes the domain separator `"scp-private-state-v1"` concatenated with the DID and purpose string to prevent cross-protocol confusion with sender key HPKE (`"scp-sender-key-v1"`) or access key HPKE (`"scp-access-key-v1"`).

**Device removal:**

1. An authorized device appends a `DeviceRemoved { device_x25519_pubkey, removed_at }` event to the private state log.
2. The removing device rotates the PSK: generates a new PSK, re-wraps it via HPKE to all remaining enrolled devices' X25519 public keys, and appends a `PskRotated { wrapped_keys: Vec<(device_pubkey, hpke_ciphertext)> }` event.
3. Re-encryption of existing private state events proceeds incrementally under the new PSK (same as key rotation, §3.7 protocol-level constants).
4. The removed device's cached PSK becomes useless for future events. Historical events encrypted under the old PSK are accessible only if the removed device retained the old PSK locally — the protocol cannot force deletion on an untrusted device (same honest limitation as §9.15).

**Device registry.**

The device registry is stored within identity private state as a sequence of `DeviceEnrolled` and `DeviceRemoved` events. The current set of enrolled devices is derived by replaying the log (same pattern as block lists, §3.7.1). Each entry contains:

```
DeviceEnrolled {
    device_x25519_pubkey: [u8; 32],  // X25519 public key for HPKE
    enrolled_at: u64,                 // Unix timestamp (milliseconds)
    enrolled_by_device: [u8; 32],     // X25519 pubkey of the enrolling device
    device_label: String,             // Human-readable label ("iPhone", "Laptop")
}

DeviceRemoved {
    device_x25519_pubkey: [u8; 32],
    removed_at: u64,
}

PskRotated {
    wrapped_keys: Vec<DeviceWrappedPsk>,  // One entry per enrolled device
    rotated_at: u64,
}

DeviceWrappedPsk {
    device_x25519_pubkey: [u8; 32],
    enc: Vec<u8>,           // HPKE encapsulated key
    sealed_psk: Vec<u8>,    // HPKE-sealed PSK
}
```

**Bootstrap paradox resolution.** The device registry is itself encrypted with the PSK — so how does the first device read it? The first device generated the PSK (step 1 of identity creation) and holds it locally before any private state events exist. The first `DeviceEnrolled` event is encrypted with that PSK. Subsequent devices receive the PSK via HPKE before they need to read the log. There is no circular dependency: the PSK is always distributed out-of-band (HPKE to device key) before the device attempts to read PSK-encrypted events.

**Interaction with trusted device recovery (§3.3).** When a user recovers their identity on a new device via trusted device recovery, the recovery flow includes PSK distribution: the trusted device wraps the current PSK to the new device's X25519 public key via the same HPKE enrollment protocol above. This is the same mechanism as adding a new device — recovery IS enrollment. The recovering device generates a fresh X25519 keypair, the trusted device wraps the PSK, and the new device gains access to the full private state history.

**Interaction with key rotation (§9.12).** Step 6 of the compromise recovery protocol specifies "re-encrypt identity private state under the new key." With PSK-based encryption, this means: (a) generate a new PSK, (b) wrap the new PSK to all enrolled devices via HPKE, (c) append a `PskRotated` event, (d) re-encrypt existing events under the new PSK incrementally. If the compromise involved a device (device stolen), that device is removed first (device removal protocol above), and the PSK rotation excludes the compromised device's X25519 public key.

**ProtocolStore methods.** The `Storage` trait (§17) requires these additional methods for PSK and device management:

- `store_private_state_key(did: &DID, psk: &Zeroizing<[u8; 32]>) -> Result<(), StoreError>`
- `load_private_state_key(did: &DID) -> Result<Option<Zeroizing<[u8; 32]>>, StoreError>`
- `store_device_registry_event(did: &DID, seq: u64, event: &[u8]) -> Result<(), StoreError>`
- `load_device_registry(did: &DID) -> Result<Vec<DeviceRegistryEvent>, StoreError>`

The PSK MUST be stored in the platform's secure key store (Keychain on Apple, Keystore on Android, SQLCipher-encrypted storage on desktop/server — per §17.8 platform-specific key custody). The PSK is zeroized on destruction (`Zeroizing<[u8; 32]>`).

## 3.8 DID Resolution Security

DID resolution is the trust root for the entire protocol. If resolution can be MITMed, every layer above — encryption, authentication, capability validation — is compromised. The security properties depend on the DID method:

**did:dht (target method):** Self-certifying. The DID string encodes the public key. DID documents are signed via BEP44 and verifiable against the DID without trusting any intermediary. MITM on resolution is impossible given the correct DID. Stale documents are rejected via sequence numbers. See §9.6 for full specification.

**did:web (fallback only):** NOT self-certifying. Security depends on DNS + TLS + server integrity. The SDK MUST use TLS pinning + TOFU (Trust On First Use) + key change alerts to mitigate. did:web exists as a fallback if did:dht libraries prove unusable — not as a planned stepping stone. See §9.6.2 for required mitigations.

**Key Continuity Verification:** Signal-style safety numbers for DIDs, enabling out-of-band verification that two parties have the correct keys for each other. See §9.11.

## 3.9 Key Lifecycle

Identity keys follow a defined lifecycle: generation (in hardware security modules where available), distribution (via DID document publication), rotation (DID document update with authorization chain from old key), and destruction (for ephemeral context keys). The full key lifecycle specification, including compromise recovery, is in §9.7.4.

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
