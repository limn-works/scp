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
| Governance | None — data structure has no concept of rules, roles, or permissions | Full governance model: 30 action types, pluggable governance engines (§5.9) |

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
- **Trust model.** Holepunch: trust whoever has the public key of a Hypercore feed. No governance, no capabilities, no accountability chains. SCP: DID + UCAN + context governance + participation records (§3, §4, §5.3, §7).
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

**2. Multi-key verification method architecture (§3.9, ADR-039).** Standard did:dht uses a single Ed25519 keypair (the one encoded in the DID string) for everything — signing documents, authenticating, operating. SCP defines multiple verification methods per DID document:

- **Identity Key (`#0`)** — the Ed25519 key encoded in the DID string. Hardware-backed. Long-lived root of trust. Used for BEP44 signing and DID document modifications only — never for day-to-day operations.
- **Human Signing Key (`#active`)** — the human's operational key for protocol actions (signing inner envelopes, MLS operations, capability delegation). Hardware-backed. Rotatable without changing the DID. Published in the DID document, authorized by the Identity Key.
- **Pre-Rotation Key** — a commitment to the next Human Signing Key. The hash of the pre-rotation key is published in the DID document before it's needed. This enables safe key rotation even if the current signing key is compromised: the pre-rotation commitment was made before compromise, so an attacker who steals the signing key cannot forge a valid rotation (they would need the pre-rotation private key, which was generated separately).
- **Agent Signing Key (`#agent`)** — optional. A software-held Ed25519 key for the human's agent to perform protocol operations autonomously. Published in the DID document, authorized by the human via self-delegation UCAN (`iss == aud`, same DID, with `fct.scp_key_scope: "#agent"`). The agent key is independently rotatable and revocable without affecting the human's keys. When present, protocol messages carry a `signing_key_id` field identifying which verification method produced the signature.

This separation of concerns (identity ≠ human signing ≠ agent signing ≠ rotation) is a significant security improvement over single-key DID methods. It provides: (a) recovery from key compromise without DID change, (b) custody separation between human and agent operations, and (c) structural action provenance — verifiers can determine whether a human or agent performed any given action by inspecting the `signing_key_id`, without trusting self-reported claims.

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

2. **SCP's extensions are additive, not contradictory.** Nothing SCP does violates the did:dht specification. SCP adds capabilities on top (dual resolution, multi-key verification methods, healing, agent signing keys). A did:dht-compliant resolver seeing an SCP identity just sees a standard did:dht identity with additional verification methods and service endpoints — all of which are valid DID document constructs that standard resolvers can parse (and ignore what they don't understand).

3. **Cost of premature separation.** Defining a new DID method requires registration, documentation, resolver implementation by third parties. The benefit is namespace clarity. The cost is loss of DHT interoperability with the existing did:dht ecosystem. The cost currently outweighs the benefit.

If did:dht governance at DIF collapses entirely, or if a future did:dht spec revision becomes incompatible with SCP's extensions, registering `did:scp` becomes warranted. The cost of method registration at that point is low — the identity layer is already self-contained.

---

## 11.3 GNUnet

**GNUnet** (gnunet.org) is a framework for secure peer-to-peer networking, under active development since 2001. It is the longest-running decentralized protocol project that prioritizes anonymity and censorship resistance as architectural fundamentals. The comparison with SCP is instructive precisely because the two protocols start from opposite premises — GNUnet minimizes identity to protect participants; SCP maximizes verifiable identity to establish trust — but converge on shared principles of infrastructure distrust and transport independence.

### 11.3.1 Architectural Overview

GNUnet is a full network stack — an overlay network that replaces conventional transport with its own layers:

| Layer | GNUnet Subsystem | Function |
|-------|-----------------|----------|
| **Transport** | Communicators (TCP, UDP, HTTP/3, UNIX) | Physical connectivity, per-communicator encryption |
| **CORE** | CAKE (CORE Authenticated Key Exchange) | Link-layer peer authentication and encryption |
| **CADET** | Confidential Ad-hoc Decentralized End-to-End Transport | Multi-hop encrypted tunnels, channel multiplexing |
| **Application** | GNS, FS, MESSENGER, etc. | Naming, file sharing, messaging |

Each layer has independent encryption. Transport communicators use Elligator DHKEM + AES-GCM (UDP) or AES-CTR + HMAC-SHA512 (TCP). CORE uses CAKE (KEM-based, inspired by DTLS 1.3/KEMTLS) with XChaCha20-Poly1305. CADET uses ECDHE over Curve25519 with dual AES-256 + Twofish encryption — a defense-in-depth choice against single-cipher compromise.

This triple-layer encryption is GNUnet's most distinctive architectural choice and also its most significant divergence from SCP's model.

### 11.3.2 Identity Model: The Opposite Premise

GNUnet's identity model is built around **anonymity as a fundamental right**:

- **Egos** are standalone Ed25519 or ECDSA keypairs. Users may have many, with no protocol-level linkage between them.
- **GNS (GNU Name System)** provides censorship-resistant naming where each "zone" is controlled by a private key with no hierarchical authority. Record labels are derived via HKDF, making different records within a zone cryptographically unlinkable. Zone enumeration is prevented by construction.
- **Petname system** — names are non-unique and locally assigned (Alice's "bob" is unrelated to Carol's "bob"). No global namespace, no universal resolution.
- **Revocation** requires Argon2id proof-of-work (~4–5 days of compute for 32 unique proofs), preventing revocation flooding.
- **did:gns** — a DID method mapping DIDs to GNS zones (`did:gns:<Base32-encoded-public-zone-key>`), with DID Documents stored as GNS resource records.

**The contrast with SCP is fundamental:**

| Dimension | GNUnet | SCP |
|-----------|--------|-----|
| **Design goal** | Anonymity — knowing who is the threat | Accountability — verifiable provenance is the feature |
| **Identity** | Disposable egos, no cross-context linkage by design | Persistent DIDs, attestation chains to human accountability |
| **Naming** | Petnames (local, non-unique, no authority) | DID documents (global, self-certifying, dual-layer resolution) |
| **Provenance** | Anti-goal (enables surveillance) | Protocol tenet (absence of provenance is a signal) |
| **Agent model** | No concept of AI agents as participants | Agents are first-class, same rules as humans, UCAN-bounded |

Both are internally consistent. GNUnet is correct that identity enables surveillance in adversarial state contexts. SCP is correct that verifiable identity is prerequisite for trust in collaborative and agentic contexts. They optimize for different threat models.

### 11.3.3 R5N DHT

GNUnet's DHT, R5N (Randomized Recursive Routing for Restricted-Route Networks), differs from standard Kademlia in ways relevant to censorship resistance:

- **Hybrid routing:** The first `log₂(N)` hops (where N is estimated network size) use **random peer selection**, then switch to XOR-distance-based closest-peer routing. The random walk phase escapes local minima in fragmented topologies — a problem that purely greedy Kademlia routing cannot solve.
- **Path recording:** When enabled, each hop appends an EdDSA signature over predecessor/successor keys and block hash. The combined put-path + get-path provides a verifiable route audit trail. Invalid signatures trigger path truncation.
- **On-path validation:** Application-specific block validators run at each hop. Expired or malformed data is discarded in transit, preventing DHT pollution.
- **Loop prevention:** 1024-bit Bloom filter (k=16) tracks visited peers per query, with capacity for ~200 entries before significant false-positive rates.
- **Censorship resistance:** Randomized initial routing + repeated queries contacting different network subsets yields ~80% retrieval success even with 50% compromised nodes in small-world topologies.
- **IETF standardization:** draft-schanzen-r5n-01.

**Comparison with Mainline DHT (used by did:dht):** Mainline uses purely greedy Kademlia routing — simpler, faster, but with no path recording, no on-path validation, and no structural censorship resistance. R5N's random walk phase and path validation are meaningful improvements for adversarial environments. SCP's dual-layer resolution (§3.10) — Mainline DHT + SCP relays — mitigates some of these risks through redundancy rather than routing-level resistance.

### 11.3.4 NAT Traversal: GNUnet's Infrastructure-Free Approach

GNUnet's NAT traversal is the most directly relevant subsystem for SCP. It achieves connectivity without any STUN/TURN infrastructure:

**UPnP/NAT-PMP.** Standard port mapping on supporting routers. Same approach as SCP Tier 1 (§10.12.2).

**Autonomous NAT traversal (pwnat).** Published by Mueller, Evans, and Grothoff (2010). Exploits ICMP Echo Request/Reply to trick NATs into accepting connections:

1. Peer behind NAT sends ICMP Echo Request to a non-existent IP
2. NAT creates a mapping expecting an ICMP Echo Reply
3. Connecting peer sends a crafted ICMP packet matching the expected reply format
4. NAT allows the "response" through, establishing initial contact
5. Data channel established over UDP

**Limitations (significant):** Works only when one peer is NATed (virtually never works when both are). Does not work with symmetric NATs. Requires SUID privileges for raw ICMP sockets. Blocked by most corporate firewalls. Impractical for production deployment.

**Probabilistic burst traversal (NGI Assure funded, 2021–2024).** The most novel technique:

1. Peers exchange external IP + port via GNUnet's Distance Vector backchannel (an already-established relay path)
2. Both peers simultaneously transmit connection attempts across **multiple ports** using raw sockets (TCP SYN or UDP datagrams)
3. Statistical probability produces a port collision — both attempts arrive simultaneously, creating a successful connection

This eliminates third-party infrastructure entirely. The backchannel coordination is the key enabler — without an existing communication path (however indirect), peers cannot synchronize the burst.

**Integrated relaying (Distance Vector).** When all direct connection attempts fail, GNUnet routes through intermediate peers using Distance Vector routing. Any GNUnet peer can act as a relay. DV discovers paths via "learn messages" and maintains both unidirectional (circle) and bidirectional (inverse) paths. Relaying is a native transport property, not a separate service.

**Comparison with SCP's reachability tiers (§10.12):**

| Tier | SCP | GNUnet Equivalent |
|------|-----|-------------------|
| **1 — Port mapping** | UPnP-IGD / NAT-PMP/PCP | UPnP (same) |
| **2 — Hole punching** | Multi-STUN probing + hole punch coordination | Probabilistic burst (no STUN) |
| **3 — Relay** | Bridge relay (BRIDGE_REGISTER + BRIDGE_DATA) | Distance Vector through intermediate peers |
| **4 — Domain TLS** | Domain-based TLS fallback | N/A (no domain concept) |

SCP's 4-tier strategy is more structured and production-oriented. GNUnet's probabilistic burst is more ambitious in eliminating infrastructure dependency. The key insight from GNUnet is that **backchannel-coordinated simultaneous connection attempts** can replace STUN for symmetric NAT scenarios — the backchannel being any existing communication path (in SCP's case, the relay itself).

### 11.3.5 Transport Architecture

GNUnet's transport evolved from monolithic plugins to separate **communicator** processes (Transport-NG):

- Each communicator (TCP, UDP, HTTP/3, UNIX, libp2p) runs as an independent process
- Failure isolation: one communicator crash does not affect others
- Standardized queue management with MTU, network type, and reliability declarations
- URL-like addressing with scope awareness (LAN addresses don't leak to WAN)
- Bidirectional flow control with back-pressure

**Comparison with SCP's transport adapter trait (ADR-005):** Both abstract over transport mechanisms. SCP's `TransportAdapter` is a Rust trait with five methods (send, subscribe, unsubscribe, query, delete) — simpler and more focused than GNUnet's communicator protocol, which handles queue management, back-pressure, and path selection. SCP's model is deliberately thinner: transport is a dumb pipe, and all intelligence (encryption, governance, membership) lives above the transport layer.

GNUnet's communicator model offers one lesson SCP has already partially adopted: transport mechanism independence should be structural, not aspirational. SCP's 17 adapter types (§10.5) realize this.

### 11.3.6 What SCP Borrows Conceptually

- **Infrastructure distrust.** Both protocols treat all infrastructure as potentially adversarial. GNUnet encrypts at every layer because any hop might be compromised. SCP encrypts at the message layer (MLS) and treats relays as untrusted dumb pipes. Different mechanisms, same principle.
- **Relay as native transport.** GNUnet's DV routing makes relaying an inherent transport property. SCP's Tier 3 bridge relay serves the same function — when direct connection fails, relay forwarding is a seamless fallback, not an external service.
- **NAT as first-class problem.** Both protocols treat NAT traversal as a core protocol concern, not an application-layer afterthought. GNUnet's multiple traversal mechanisms and SCP's 4-tier reachability strategy both reflect this.
- **DHT for peer discovery.** Both use DHT-based discovery (R5N vs Mainline) as a decentralized alternative to centralized registries.

### 11.3.7 Why SCP Does Not Adopt GNUnet's Approach

**Overlay coupling.** GNUnet IS the network — it replaces conventional transport with its own stack. SCP's transport independence tenet (§10.5) requires running on top of existing transports. Coupling to GNUnet's overlay would make SCP a GNUnet application rather than a transport-independent protocol.

**Triple-layer encryption.** GNUnet encrypts at transport, CORE, and CADET layers because intermediate peers are untrusted routing nodes that handle plaintext routing metadata. SCP's relay model is simpler: relays see only pseudonym-addressed encrypted blobs (§9.10.2). One encryption layer (MLS) plus a sender-side key layer (§9.16) is sufficient when relays perform no routing decisions beyond subscription matching.

**Anonymity vs accountability.** GNUnet's architecture is optimized for a world where state actors surveil communication and identity itself is dangerous. SCP's architecture is optimized for a world where AI agents act autonomously and verifiable provenance is necessary for trust. These are different futures; both are plausible.

**Maturity.** GNUnet has been in development for 25+ years and remains explicitly experimental ("significant bugs and critical design flaws" per project documentation). No production deployments at scale. SCP cannot depend on experimental infrastructure for core protocol functions.

### 11.3.8 Open Questions

GNUnet's **probabilistic burst NAT traversal** technique — backchannel-coordinated simultaneous multi-port connection attempts — could improve SCP's Tier 2 coverage for symmetric NATs without introducing STUN/TURN infrastructure dependency. See discussion #1380 for ongoing evaluation.

R5N's **randomized routing** and **path recording** offer censorship resistance properties that standard Mainline DHT lacks. If state-level DID resolution suppression becomes a practical threat, R5N's techniques could inform a more resilient resolution fallback alongside SCP's existing dual-layer approach (§3.10).

### 11.3.9 References

- Polot & Grothoff, "CADET: Confidential Ad-hoc Decentralized End-to-End Transport," Med-Hoc-Net 2014
- Evans & Grothoff, "R5N: Randomized Recursive Routing for Restricted-Route Networks," NSS 2011
- Mueller, Evans & Grothoff, "Autonomous NAT Traversal," 2010
- Grothoff, "The GNUnet System," Habilitation thesis, Inria
- IETF draft-schanzen-r5n-01 (R5N specification)
- LSD-0001 (GNS specification), LSD-0005 (did:gns), LSD-0007 (Communicators), LSD-0012 (CAKE)

---

## 11.4 What No Existing Standard Covers

Agents as first-class protocol participants with formalized trust semantics, one-agent-per-person-per-context constraints, context-bound agents that cannot cross at the protocol level, trust as identity + capability pairs applied to autonomous agents, non-fungible cross-platform identity attestations with shadow identity claiming, protocol-level bridge connectors with provenance-tracked content attribution, and all of this framed as infrastructure for generated/ephemeral apps.

Additionally: dual-layer DID resolution with protocol-level self-healing, multi-key identity architecture with pre-rotation commitments and optional agent signing keys, shared-DID human-agent pairs with structural action provenance (verifiers know whether a human or agent signed any action from the `signing_key_id` — no trust in self-reported claims), encryption-as-access-control where MLS group keys ARE membership, sender-side key layers enabling per-sender blocking without group disruption, and context-level economic governance with spending UCANs.

This is the novel contribution of SCP.
