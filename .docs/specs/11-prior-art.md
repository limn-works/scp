# 11. Prior Art

| Component | Existing Standard/Technology | SCP Relationship |
|---|---|---|
| Identity | DID (W3C) | Build on directly |
| Identity resolution | did:dht (BEP44 + Mainline DHT) | Build on directly; extend significantly (§3.10) |
| Capability tokens | UCAN | Build on directly |
| Key custody | Passkeys, WebAuthn, Secure Enclave | Delegate custody to |
| Group encryption | MLS (RFC 9420) | Build on directly |
| Transport | Matrix, libp2p, Nostr | Build on / interop |
| Data sovereignty | Solid, AT Protocol PDS | Informed by, evaluate |
| Federated contexts | ActivityPub, Matrix rooms | Informed by |
| Access control | RBAC (decades old) | Standard application |
| Auth delegation | OAuth, GNAP | Informed by |
| Local AI-tool wiring | MCP (Model Context Protocol) | Agent-level integration |
| P2P transport + NAT traversal | Hyperswarm (Holepunch) | Informed by; architecturally distinct |
| Append-only authenticated logs | Hypercore (Holepunch) | Informed by; structurally parallel, different trust model |

---

## 11.1 Holepunch / Hypercore

**Holepunch** (github.com/holepunchto) builds open-source P2P infrastructure: Hyperswarm (DHT + UDP hole punching), Hypercore (append-only signed logs), Autobase (multi-writer via causal DAG linearization), Keet (production P2P encrypted chat), Pear (P2P app runtime on Bare, a minimal JS runtime). Keet is a shipping product — proof that zero-server P2P chat works at scale.

### 11.1.1 Structural Comparison: Hypercore vs SCP Event Logs

Hypercore and SCP's event logs serve a structurally similar function: tamper-evident append-only history. The comparison is instructive because SCP took a well-understood primitive and embedded it in a richer security model.

| Dimension | Hypercore | SCP Event Logs |
|-----------|-----------|----------------|
| Structure | Append-only log, Merkle tree | Append-only log, Merkle tree |
| Hash function | BLAKE2b-256 | SHA-256 |
| Tree shape | Flat in-order (Ogham tree) | Standard binary Merkle |
| Signing | Ed25519, single writer per log | Ed25519, multi-writer per context (MLS-authenticated) |
| Verification | Sparse — verify any entry without full history | Proof-of-inclusion and proof-of-absence |
| Multi-writer | Autobase (app-layer DAG linearization over single-writer cores) | Native via MLS group membership — the group key proves write authority |
| Encryption | None at log level; transport-level only (Noise XX + XChaCha20-Poly1305) | MLS + sender-side AES-256-GCM at log level |
| Governance | None — data structure has no concept of rules, roles, or permissions | Full governance model: 24 action types, pluggable governance engines (§5.9) |

**The key distinction:** Hypercore is a data structure. SCP event logs are a data structure embedded in a governance and encryption context. Hypercore answers "who appended this?" (signature verification). SCP event logs answer "who appended this, were they authorized to, under what governance, in what role, with what capabilities, and is it encrypted to the right group?"

### 11.1.2 Autobase and Multi-Writer

Hypercore is fundamentally single-writer: one Ed25519 keypair owns one feed, and only that keypair can append. Autobase extends this to multi-writer by having each writer maintain their own Hypercore, then linearizing the causal DAG across all feeds into a single ordered view.

SCP takes the opposite approach: multi-writer is native. MLS group membership defines who can append to a context's event log. There is no per-writer feed to linearize — all members write to the same logical log, and the MLS epoch/generation/sequence triple provides ordering. This is a fundamental architectural choice: Hypercore starts with single-writer and composes multi-writer; SCP starts with multi-writer (MLS groups) and the single-writer case is the degenerate one-member group.

### 11.1.3 Keet and Group Encryption

Keet is the strongest existence proof that P2P encrypted group messaging works without servers. However, Keet's group encryption protocol is not publicly documented. The encryption scheme (presumably built on Hypercore + Noise) is part of the application, not a published specification. This means:

- Keet cannot be independently implemented from a spec.
- Keet's group encryption cannot be formally analyzed by external security researchers.
- No other application can interoperate with Keet's encryption at the protocol level.

SCP's approach is the inverse: MLS (RFC 9420) is a published IETF standard with formal security analysis, multiple independent implementations, and documented security properties (forward secrecy, post-compromise security). The sender-side key layer (§9.16) and content access control layer (§9.17) are specified in the SCP protocol documentation with enough precision for independent implementation.

Publishing the protocol is the differentiator — not the existence of encryption.

### 11.1.4 Architectural Divergences

**Similar:** Zero-server thesis. DHT for discovery. NAT traversal as first-class concern. E2E encryption. Append-only authenticated logs for tamper-evident history.

**Different:**

- **Transport coupling.** Hyperswarm IS the transport — Kademlia DHT discovery, UDP hole punching, Noise XX handshake, all tightly integrated. SCP is transport-agnostic (17 adapters, §10.5). Hyperswarm could be one SCP adapter. SCP's design never depends on it.
- **Trust model.** Holepunch: trust whoever has the public key of a Hypercore feed. No governance, no capabilities, no accountability chains. SCP: DID + UCAN + context governance + behavioral records (§3, §4, §5.3, §7).
- **Group membership.** MLS in SCP enforces membership cryptographically — you cannot read messages without the group key. Hyperswarm: app-level access control.
- **Context isolation.** SCP's security boundary (§5). No Hyperswarm or Hypercore equivalent. There is no concept of bounded, governed interaction spaces with cryptographic boundaries.
- **Offline/async delivery.** Hypercore requires synchronous peer connections (at least intermittently) — if no peer is online, you wait. SCP's relay architecture provides store-and-forward async delivery. You send a message even if the recipient is offline. Relays buffer with three-tier degradation (§23).
- **Provenance.** SCP: protocol-level automatic provenance attachment at cross-context boundaries (§24). Hypercore: data-structure level only (signature proves who appended, nothing about authorization or origin context).
- **Relay vs direct P2P.** SCP: async via relays (store-and-forward), with multi-relay suppression resistance (§9.9.2). Hyperswarm: synchronous direct connections.

**Why not use Hyperswarm directly:** Transport independence tenet. Different trust model. SCP relay architecture enables async delivery, multi-relay suppression resistance (§9.9.2), bridge fallback. Coupling to Hyperswarm would make SCP a Hyperswarm application rather than a transport-independent protocol.

**What SCP borrows conceptually:** DHT-integrated hole punching as a reachability primitive (§10.12.3). Proof that zero-server P2P works at production scale (Keet). The append-only authenticated log as a tamper-evident history primitive — though SCP embeds it in a fundamentally richer trust context.

---

## 11.2 DID DHT and SCP's Identity Layer

### 11.2.1 What did:dht Specifies

did:dht is a DID method that uses BitTorrent's Mainline DHT for decentralized identity resolution. Originally created by TBD (a subsidiary of Block/Square), the specification was transferred to the Decentralized Identity Foundation (DIF) after TBD shut down in November 2024.

Core properties:

- **DID string format:** `did:dht:<z-base-32-encoded-Ed25519-public-key>`. The DID string IS the public key — self-certifying by construction.
- **Storage:** DID documents stored as BEP44 signed mutable items on Mainline DHT (a network of millions of nodes with 20+ years of operational history).
- **Self-certification:** BEP44 signatures are verified against the public key encoded in the DID string. No intermediary is trusted. MITM on resolution is cryptographically impossible given the correct DID.
- **Serialization:** DID documents encoded as DNS packets (TXT records for properties, SRV records for service endpoints) within the BEP44 payload.
- **Payload limit:** 1000 bytes per BEP44 item (Mainline DHT constraint).
- **Expiry:** BEP44 items must be republished approximately every 2 hours to remain resolvable. Items expire if not republished.
- **Sequence numbers:** BEP44 provides monotonically increasing sequence numbers for freshness. Higher sequence number = newer document.
- **Gateways:** Optional HTTP gateways for resolution without a DHT client (did:dht Gateway specification).

### 11.2.2 What SCP Takes from did:dht

SCP adopts the core self-certification property:

- **DID string format:** `did:dht:<z-base-32>` — identical to the did:dht specification.
- **BEP44 self-certification:** DID document signature verification against the key encoded in the DID string. The storage backend is untrusted; trust derives from the cryptographic binding between DID and document.
- **Mainline DHT as resolution backend:** SCP uses Mainline DHT as one resolution layer (§3.10.3).
- **Ed25519 as the identity key algorithm:** Same as did:dht.

### 11.2.3 Where SCP Departs from did:dht

SCP extends did:dht significantly. These extensions are additive — a standard did:dht resolver can still resolve SCP identities via DHT — but they represent a fundamentally different approach to identity resolution resilience and key management.

**1. Dual-layer resolution (§3.10).** did:dht has one resolution path: Mainline DHT. SCP adds a second: SCP relays. DID documents are published as standard relay blobs (routing_id = `SHA-256("scp:did:" || did_string)`). Both layers are queried in parallel, first-valid-wins, BEP44 sequence numbers resolve conflicts. The anti-segmentation invariant (§3.10.6) makes dual-layer publishing a MUST, not a SHOULD.

This means SCP identities are resolvable even if:
- The entire Mainline DHT is unreachable (relay layer serves)
- All of an identity's SCP relays are down (DHT layer serves)
- An attacker suppresses documents on one layer (the other layer serves)

An attacker must suppress a DID document on ALL relays AND ALL reachable DHT nodes to prevent resolution. This is a strictly harder attack than suppressing on either layer alone.

**2. Three-key architecture.** Standard did:dht uses a single Ed25519 keypair (the one encoded in the DID string) for everything — signing documents, authenticating, operating. SCP defines three keys per identity:

- **Identity Key** — the Ed25519 key encoded in the DID string. Long-lived. Used for BEP44 signing and as the root of the identity's trust chain. Never used for day-to-day operations.
- **Active Signing Key** — the operational key used for protocol actions (signing inner envelopes, MLS operations, capability delegation). Rotatable without changing the DID. Published in the DID document, authorized by the Identity Key.
- **Pre-Rotation Key** — a commitment to the next Active Signing Key. The hash of the pre-rotation key is published in the DID document before it's needed. This enables safe key rotation even if the current Active Signing Key is compromised: the pre-rotation commitment was made before compromise, so an attacker who steals the active key cannot forge a valid rotation (they would need the pre-rotation private key, which was generated separately).

This separation of concerns (identity ≠ signing ≠ rotation) is a significant security improvement over single-key DID methods. It provides a recovery path from key compromise that doesn't require changing the DID itself.

**3. Protocol-level healing (§3.10.7).** When both resolution layers return valid documents with different sequence numbers, the resolver accepts the higher one and MAY re-publish the fresher document to the stale layer. The network self-heals — converging on the freshest document without central coordination. This is unique to SCP; standard did:dht has no concept of multi-layer resolution and therefore no healing protocol.

**4. Relay-layer TTL decoupling.** did:dht's ~2 hour DHT expiry requires aggressive republishing. SCP's relay layer uses 7-day TTL with 6-day republish cycles. The two layers have complementary availability characteristics: DHT for immediate availability (millions of nodes, works from day one), relays for longer persistence (7-day TTL, lower republish overhead). The RepublishManager maintains both cycles independently.

**5. JSON-LD DID document serialization.** Standard did:dht specifies DNS packet encoding (TXT/SRV records) within the 1000-byte BEP44 payload. SCP uses JSON-LD serialization for DID documents. On the relay layer, this removes the 1000-byte constraint entirely (relay blobs support 256KB), allowing richer DID documents with more attestations, service endpoints, and key material. On the DHT layer, the DNS packet encoding is still used for BEP44 compatibility — but the relay layer carries the full document.

### 11.2.4 SCP's DID Implementation Independence

SCP's identity layer is fully self-owned. The `scp-identity` crate implements:
- Ed25519 key generation and management
- z-base-32 encoding/decoding
- BEP44 signature creation and verification
- DID document construction and parsing
- Dual-layer resolution via `DualLayerResolver`
- DHT interaction via `DhtClient` trait (abstracted — not coupled to any specific DHT library)

There is no dependency on any did:dht software, library, or infrastructure beyond the Mainline DHT network itself. SCP depends on BEP44 (a BitTorrent standard) and Ed25519 (universal cryptographic primitive), not on did:dht tooling. The DID string format is a convention (z-base-32 encoding of a public key), not a library dependency.

This independence is important because:
- TBD (the original did:dht creator) shut down in November 2024
- The spec was transferred to DIF, where the community working group continues but with reduced momentum
- If did:dht governance at DIF stalls or the spec diverges in an incompatible direction, SCP is unaffected — SCP's resolution is self-contained

### 11.2.5 Why Not did:scp?

Given SCP's significant departures from did:dht, a natural question is whether SCP should define its own DID method (`did:scp`). The answer is: **not yet**, for three reasons:

1. **Interoperability.** The DID string format is identical to did:dht. A standard did:dht resolver can resolve SCP identities via Mainline DHT. They won't get the relay layer, three-key semantics, or protocol-level healing — but they get a valid DID document. Changing to `did:scp` would break this interoperability bridge.

2. **SCP's extensions are additive, not contradictory.** Nothing SCP does violates the did:dht specification. SCP adds capabilities on top (dual resolution, key separation, healing). A did:dht-compliant resolver seeing an SCP identity just sees a standard did:dht identity with some extra service endpoints.

3. **Cost of premature separation.** Defining a new DID method requires registration, documentation, resolver implementation by third parties. The benefit is namespace clarity. The cost is loss of DHT interoperability with the existing did:dht ecosystem. The cost currently outweighs the benefit.

If did:dht governance at DIF collapses entirely, or if a future did:dht spec revision becomes incompatible with SCP's extensions, registering `did:scp` becomes warranted. The cost of method registration at that point is low — the identity layer is already self-contained.

---

## 11.3 What No Existing Standard Covers

Agents as first-class protocol participants with formalized trust semantics, one-agent-per-person-per-context constraints, context-bound agents that cannot cross at the protocol level, trust as identity + capability pairs applied to autonomous agents, non-fungible cross-platform identity attestations with shadow identity claiming, protocol-level bridge connectors with provenance-tracked content attribution, and all of this framed as infrastructure for generated/ephemeral apps.

Additionally: dual-layer DID resolution with protocol-level self-healing, three-key identity architecture with pre-rotation commitments, encryption-as-access-control where MLS group keys ARE membership, sender-side key layers enabling per-sender blocking without group disruption, and context-level economic governance with spending UCANs.

This is the novel contribution of SCP.
