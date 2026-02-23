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
- **Discoverable.** Other SCP participants can look up whether a given external identity maps to a known DID. Discovery mechanism TBD — possibilities include a distributed registry, DHT, or attestations published alongside the DID document.

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

**Block** is DID-to-DID and bidirectional. When Alice blocks Dave, neither can see the other — across all shared contexts. Blocking is cryptographically enforced through a **sender-side key layer** (§10.5), which is distinct from MLS group membership. When a block is issued, the blocker rotates their personal sender key and redistributes it to all context members except the blocked party. The blocked party physically cannot decrypt the blocker's future messages. Critically, blocking does NOT remove the blocked party from the MLS group — they remain a context member and can still see other members' messages. Blocking is a unilateral, per-relationship action by the blocker; it does not require group coordination or affect the blocked party's relationship with other context members. This is fundamentally different from member removal, which IS a group action (MLS Remove Commit + epoch advancement). Blocks can optionally be scoped to a specific context, but the default and most common case is DID-to-DID across all shared contexts.

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

## 3.8 DID Resolution Security

DID resolution is the trust root for the entire protocol. If resolution can be MITMed, every layer above — encryption, authentication, capability validation — is compromised. The security properties depend on the DID method:

**did:dht (target method):** Self-certifying. The DID string encodes the public key. DID documents are signed via BEP44 and verifiable against the DID without trusting any intermediary. MITM on resolution is impossible given the correct DID. Stale documents are rejected via sequence numbers. See §9.6 for full specification.

**did:web (fallback only):** NOT self-certifying. Security depends on DNS + TLS + server integrity. The SDK MUST use TLS pinning + TOFU (Trust On First Use) + key change alerts to mitigate. did:web exists as a fallback if did:dht libraries prove unusable — not as a planned stepping stone. See §9.6.2 for required mitigations.

**Key Continuity Verification:** Signal-style safety numbers for DIDs, enabling out-of-band verification that two parties have the correct keys for each other. See §9.11.

## 3.9 Key Lifecycle

Identity keys follow a defined lifecycle: generation (in hardware security modules where available), distribution (via DID document publication), rotation (DID document update with authorization chain from old key), and destruction (for ephemeral context keys). The full key lifecycle specification, including compromise recovery, is in §9.7.4 and §9.12.
