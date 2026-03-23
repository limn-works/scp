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

### 11.1.0 Dat Protocol Origins

The Dat Protocol (2013) is the direct ancestor of the Hypercore stack described in the subsections that follow. Understanding the evolution — and the governance dynamics that accompanied it — provides important context for SCP's design tenets.

**Original motivation: scientific data sharing.** Max Ogden created Dat in August 2013 to solve how scientists collaborate on versioned datasets without centralized infrastructure. Funded by the Knight Foundation and Sloan Foundation (2014-2015), stewardship moved to Code for Science and Society (501(c)(3), 2017). The project was published in *Nature Scientific Data* (2018) — an unusual level of academic legitimacy for a P2P protocol.

**Technical primitives.** Dat introduced several ideas that survived into Hypercore. Data archives were append-only logs signed with Ed25519 keypairs, verified via Merkle trees. The on-disk format, SLEEP (Syncable Ledger of Exact Events Protocol), used fixed-size entries with 32-byte headers — a compact representation that Hypercore later refined. Discovery keys — the hash of the archive's public key — allowed peers to find each other on the DHT without exposing the actual read key to the network, a privacy-by-default design. Dat DNS (DEP-0005) mapped human-readable domain names to cryptographic archive addresses via DNS TXT records or `/.well-known/dat` HTTPS endpoints, foreshadowing the kind of DNS-bridged discovery that SCP's DID resolution uses (§3.10).

**The Beaker Browser.** Paul Frazee's Beaker Browser (2016-2022) was Dat's most visible consumer application — an Electron-based browser natively handling `dat://` URLs, enabling one-click website creation and peer-to-peer hosting. Archived in 2022 due to maintainer burnout, it demonstrated both the promise and the sustainability challenges of building a full browser-embedded P2P stack.

**The evolution: Dat to Hypercore to Holepunch.** By 2020, the protocol had outgrown its command-line-tool origins. The core maintainers — led by Mathias Buus, who had been building Hypercore since 2016 — renamed the protocol layer from "Dat Protocol" to "Hypercore Protocol," creating a separate GitHub organization with an open RFC process. "Dat" persisted as a community label for the broader ecosystem (Cabal, Peermaps, Mapeo, Cobox). In 2022, Holepunch launched with funding from Tether and Bitfinex, with Mathias Buus leading development and Paolo Ardoino (Tether CEO) as Chief Strategy Officer. Modules migrated from the Hypercore Protocol GitHub organization to the Holepunch organization. Keet, the flagship P2P encrypted chat app, shipped as proof that the stack worked at production scale.

**The community split.** The transition created a de facto fork in governance. The Dat Ecosystem (dat-ecosystem.org) continued as a self-organized community of independent P2P projects building on the shared technology — mostly self-funded, loosely coordinated, with no corporate patron. Holepunch became a commercially funded entity with a specific product roadmap (Keet, Pear runtime) and corporate stakeholders. The underlying open-source code remained available, but the locus of protocol development shifted to an organization with commercial interests. Community projects that depended on the stack found themselves downstream of decisions driven by product priorities rather than ecosystem needs.

**Why this matters for SCP.** The Dat-to-Holepunch arc is a case study in protocol governance risk — specifically, what happens when a community protocol's core development gets commercialized. The technical artifacts survived the transition (Hypercore, Hyperswarm, the append-only log primitive), but the governance model changed fundamentally. SCP's "protocol requires no operator" tenet is partly informed by observing these dynamics: a protocol's long-term viability depends on the inability of any single entity — including its creators — to capture the development process. SCP achieves this through specification completeness (independent implementation from the spec alone), transport independence (no coupling to any single infrastructure), and self-contained identity resolution (no dependency on any organization's tooling or services — §11.2.4).

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

### 11.1.3.1 MLS vs Signal Protocol vs Megolm

SCP's choice of MLS (RFC 9420) over alternative group encryption protocols is a deliberate architectural decision:

| Dimension | MLS (RFC 9420) | Signal Protocol (sender keys) | Matrix Megolm |
|-----------|---------------|-------------------------------|---------------|
| **Group key agreement** | TreeKEM — binary tree of key pairs, O(log n) update cost | Pairwise + sender keys — each sender distributes a symmetric ratchet to all members | Sender ratchet — each sender maintains a Megolm session, distributed pairwise via Olm |
| **Member add/remove cost** | O(log n) — update single tree path | O(n) — must re-distribute sender keys to all members | O(n) — must create new Megolm session, distribute via n Olm channels |
| **Forward secrecy granularity** | Per-epoch — key ratchets with each commit | Per-message (pairwise), per-sender-key-period (groups) | Per-message (Megolm ratchet advances), but no backward secrecy on ratchet state |
| **Post-compromise security** | Yes — commit after compromise restores confidentiality | Limited — requires new sender key distribution | No — compromised Megolm ratchet decrypts all future messages in session |
| **Formal analysis** | Extensive — multiple published proofs (Alwen et al., Brzuska et al.) | Extensive (pairwise), limited (sender keys in groups) | Limited formal analysis |
| **Standardization** | IETF RFC 9420 | No formal standard (open-source reference implementation) | Matrix spec (not IETF/W3C) |

SCP chose MLS for three reasons: (1) O(log n) scaling makes large contexts viable, (2) post-compromise security means removing a compromised member actually restores confidentiality, and (3) IETF standardization enables independent implementation — aligned with SCP's "protocol requires no operator" tenet. SCP's sender-side key layer (§9.16) is conceptually similar to Signal's sender keys but serves a different purpose: per-sender access control (blocking without group disruption) rather than performance optimization.

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

Each layer has independent encryption. Transport communicators use Elligator DHKEM + AES-GCM (UDP) or AES-CTR + HMAC-SHA512 (TCP). CORE uses CAKE (KEM-based, inspired by DTLS 1.3/KEMTLS) with XChaCha20-Poly1305. CADET uses ECDHE over Curve25519 with cascaded AES-256-CFB and Twofish-CFB encryption (Twofish inner, AES outer) — a defense-in-depth choice against single-cipher compromise.

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
- **Censorship resistance:** Randomized initial routing + repeated queries contacting different network subsets yields high retrieval success rates even with significant fractions of compromised nodes (Evans & Grothoff 2011, simulation results vary by topology and attack model).
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

**Probabilistic burst traversal (NGI Assure funded, 2022–2024).** The most novel technique:

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

### 11.3.5 GNS (GNU Name System)

GNS is GNUnet's censorship-resistant, decentralized naming system — a replacement for DNS that eliminates hierarchical authority and prevents zone enumeration by construction. Standardized as RFC 9498 (November 2023), it is the most formally specified component of the GNUnet ecosystem and the most directly comparable to SCP's DID-based identity resolution.

**Core construction: Zone Key Derivation Function (ZKDF).** Each GNS zone is controlled by a single keypair (Ed25519 or ECDSA). The zone's public key serves as its identifier — analogous to how a did:dht DID string IS the public key. The critical innovation is per-label key blinding via ZKDF (RFC 9498 §7):

For both PKEY (ECDSA) and EDKEY (EdDSA) zones:
1. Extract a pseudo-random key: `PRK_h = HKDF-Extract(salt="key-derivation", ikm=zone_key)` using SHA-512
2. Derive the blinding factor: `h = HKDF-Expand(PRK_h, info=label || "gns", L=64)` using SHA-256
3. Reduce the blinding factor modulo the curve order: `h = h mod L`
4. Compute the derived key via scalar-point multiplication: `derived_key = h * zone_key`
5. DHT queries use `SHA-512(derived_key)` as the lookup key (the storage key)

The salt for HKDF-Extract is the fixed string `"key-derivation"`, NOT the label — the label appears only in the HKDF-Expand info parameter. The reduction `h mod L` (where L is the curve order) is critical: without it, the scalar multiplication is undefined. HKDF-Extract uses SHA-512 while HKDF-Expand uses SHA-256, matching the RFC's split construction.

This means an observer who sees a DHT query for `SHA-512(derived_key)` cannot determine which zone or label it corresponds to without knowing both the zone key and the label. Two records in the same zone produce unrelated DHT keys. Zone enumeration — trivial in DNS via AXFR or NSEC walking — is computationally infeasible in GNS.

**Record encryption at rest.** GNS records stored in the DHT are encrypted, not merely signed:

| Zone key type | Record encryption | Key derivation |
|---------------|-------------------|----------------|
| **PKEY** (ECDSA) | AES-256-CTR | HKDF-SHA256 from ECDH(zone_private_key, derived_public_key) |
| **EDKEY** (EdDSA) | XSalsa20-Poly1305 | HKDF-SHA512 from zone key + label |

A DHT node storing GNS records sees only encrypted blobs keyed by opaque hashes. It cannot read the records, determine the zone they belong to, or enumerate other records in the zone. This is a stronger privacy property than any DID method provides — DID documents are readable by anyone who knows the DID string.

**Petname system and Zooko's triangle.** GNS makes an explicit choice in Zooko's triangle — the observation that naming systems can provide at most two of three properties:

| Property | DNS | GNS | ENS | did:dht (SCP) |
|----------|-----|-----|-----|---------------|
| **Secure** (not spoofable) | Weak (DNSSEC optional, CAs fallible) | Yes (ZKDF + self-certifying zones) | Yes (smart contract finality) | Yes (BEP44 self-certification) |
| **Memorable** (human-readable) | Yes (example.com) | Yes (petnames: "Alice's blog") | Yes (vitalik.eth) | No (did:dht:z6Mk...) |
| **Global** (unique, universal) | Yes (ICANN hierarchy) | No (petnames are local) | Yes (Ethereum global state) | Yes (DHT global key) |

GNS chose secure + memorable, sacrificing global uniqueness. Names are meaningful only within a local trust context — Alice's "bob" is a petname she assigned and has no meaning to Carol. Hierarchical delegation (alice.bob.gnu means "look up 'alice' in the zone that 'bob' points to in the GNU zone") provides path-based navigation but not global resolution.

SCP chose secure + global, sacrificing memorability. did:dht identifiers are cryptographic strings that no human will remember, but they resolve identically for every resolver worldwide. SCP compensates with display names in DID documents and context-level naming — but the identifiers themselves are opaque.

ENS achieved all three by accepting the trade-off of requiring a blockchain (Ethereum) as global state — introducing infrastructure dependency that both GNS and SCP reject.

**GNS2DNS / DNS2GNS interop.** GNS includes bidirectional DNS bridge records:

- **GNS2DNS** records delegate a GNS label to a DNS name, allowing GNS zones to reference DNS infrastructure (`www.alice.gnu → www.example.com via DNS`)
- **DNS2GNS** requires configuring a DNS nameserver to forward queries to a GNS resolver, enabling DNS clients to reach GNS zones

This interoperability layer means GNS can gradually coexist with DNS rather than requiring wholesale replacement. SCP has no equivalent bridge — DID resolution and DNS resolution are entirely separate systems with no cross-protocol delegation mechanism.

**Comparison: GNS vs SCP DID resolution**

| Dimension | GNS (RFC 9498) | SCP DID (§3, §11.2) |
|-----------|----------------|----------------------|
| **Identifier** | Zone public key (Ed25519/ECDSA) | did:dht string (z-base-32 Ed25519) |
| **Naming** | Petnames (local, memorable, non-global) | DID strings (global, unmemorable, unique) |
| **Hierarchical delegation** | Yes (label.zone chains) | No (flat namespace) |
| **Record privacy** | Encrypted at rest (ZKDF + AES/XSalsa20) | Plaintext DID documents (readable by anyone) |
| **Zone enumeration** | Prevented by construction (ZKDF) | Trivial (DID documents are public) |
| **DHT** | R5N (censorship-resistant routing) | Mainline (millions of nodes, simpler routing) |
| **Revocation** | Argon2id proof-of-work (~4 days) | BEP44 sequence number + TTL expiry |
| **Multi-key architecture** | No (one keypair per zone) | Yes (#0, #active, #agent, pre-rotation) |
| **Capability delegation** | No | Yes (UCAN chains) |
| **Attestation chains** | No | Yes (identity attestations to human accountability) |
| **DNS interop** | Yes (GNS2DNS, DNS2GNS) | No |
| **W3C DID compliance** | Via did:gns (LSD-0005) | Native (did:dht is a registered DID method) |
| **Context-scoped identity** | No | Yes (pseudonym derivation per context, §9.10.2) |
| **Standardization** | RFC 9498 (IETF) | did:dht spec (DIF) |

**What GNS solves that SCP's DID layer does not:** Memorable naming through petnames and hierarchical delegation. Record encryption preventing observers from reading identity metadata. Zone enumeration prevention — no equivalent of crawling all DIDs in the DHT. DNS interoperability for gradual adoption. These are real gaps in SCP's identity model, accepted as trade-offs for global uniqueness, multi-key architecture, and W3C DID ecosystem compatibility.

**What SCP's DID layer solves that GNS does not:** Multi-key verification methods with custody separation (identity key, human signing key, agent signing key, pre-rotation). UCAN capability delegation chains. Identity attestation linking agents to humans. Context-scoped pseudonyms preventing cross-context correlation. Dual-layer resolution (DHT + relay) with protocol-level healing. The massive Mainline DHT network (millions of nodes vs GNUnet's hundreds). These reflect SCP's accountability-first design vs GNS's privacy-first design.

### 11.3.6 Protocol Translation (VPN/PT)

GNUnet's VPN and Protocol Translation subsystem is the closest architectural parallel to SCP's transport adapter model. Both solve the same fundamental problem — bridging between heterogeneous protocol worlds — but at different layers: GNUnet at the IP layer, SCP at the message layer.

GNUnet's approach uses three cooperating daemons (VPN service, DNS service, protocol translation daemon) to transparently intercept DNS queries and route application traffic through CADET tunnels via a TUN device. Applications require zero modification — any program using DNS and TCP/UDP transparently routes through the overlay. Exit nodes (any peer running gnunet-daemon-exit) forward tunneled traffic to conventional internet destinations, creating an organic relay network. GNS VPN records unify naming and transport — resolving a GNS name with a VPN record automatically provisions a CADET tunnel.

| Dimension | GNUnet VPN/PT | SCP Transport Adapters (§10.5) |
|-----------|---------------|-------------------------------|
| **Abstraction layer** | IP (packets via TUN device) | Messages (trait with send/subscribe/query) |
| **Application modification** | None required (transparent DNS-ALG) | Required (must use SCP SDK) |
| **Exit/relay model** | Any peer can be exit node (DHT-announced) | Dedicated relay servers (untrusted, store-and-forward) |
| **Naming integration** | GNS VPN records unify naming + transport | Separate concerns: DID resolution independent of transport |
| **Fault isolation** | Per-communicator process isolation | In-process (trait implementations share process) |
| **Scope** | Full network stack replacement | Message delivery only |

**The key architectural parallel:** Both solve protocol bridging without coupling to any single transport. GNUnet answers at the IP layer (zero application changes, but requires TUN device and raw socket privileges). SCP answers at the message layer (requires SDK integration, but runs in browsers via WASM, works on mobile, needs no OS privileges). The trade-off maps to scope: GNUnet aims to be the entire network stack; SCP aims to be the interaction protocol atop any network stack.

### 11.3.7 Transport Architecture

GNUnet's transport evolved from monolithic plugins to separate **communicator** processes (Transport-NG):

- Each communicator (TCP, UDP, HTTP/3, UNIX, libp2p) runs as an independent process
- Failure isolation: one communicator crash does not affect others
- Standardized queue management with MTU, network type, and reliability declarations
- URL-like addressing with scope awareness (LAN addresses don't leak to WAN)
- Bidirectional flow control with back-pressure

**Comparison with SCP's transport adapter trait (ADR-005):** Both abstract over transport mechanisms. SCP's `TransportAdapter` is a Rust trait with five methods (send, subscribe, unsubscribe, query, delete) — simpler and more focused than GNUnet's communicator protocol, which handles queue management, back-pressure, and path selection. SCP's model is deliberately thinner: transport is a dumb pipe, and all intelligence (encryption, governance, membership) lives above the transport layer.

GNUnet's communicator model offers one lesson SCP has already partially adopted: transport mechanism independence should be structural, not aspirational. SCP's 17 adapter types (§10.5) realize this.

### 11.3.8 What SCP Borrows Conceptually

- **Infrastructure distrust.** Both protocols treat all infrastructure as potentially adversarial. GNUnet encrypts at every layer because any hop might be compromised. SCP encrypts at the message layer (MLS) and treats relays as untrusted dumb pipes. Different mechanisms, same principle.
- **Relay as native transport.** GNUnet's DV routing makes relaying an inherent transport property. SCP's Tier 3 bridge relay serves the same function — when direct connection fails, relay forwarding is a seamless fallback, not an external service.
- **NAT as first-class problem.** Both protocols treat NAT traversal as a core protocol concern, not an application-layer afterthought. GNUnet's multiple traversal mechanisms and SCP's 4-tier reachability strategy both reflect this.
- **DHT for peer discovery.** Both use DHT-based discovery (R5N vs Mainline) as a decentralized alternative to centralized registries.

### 11.3.9 Why SCP Does Not Adopt GNUnet's Approach

**Overlay coupling.** GNUnet IS the network — it replaces conventional transport with its own stack. SCP's transport independence tenet (§10.5) requires running on top of existing transports. Coupling to GNUnet's overlay would make SCP a GNUnet application rather than a transport-independent protocol.

**Triple-layer encryption.** GNUnet encrypts at transport, CORE, and CADET layers because intermediate peers are untrusted routing nodes that handle plaintext routing metadata. SCP's relay model is simpler: relays see only pseudonym-addressed encrypted blobs (§9.10.2). One encryption layer (MLS) plus a sender-side key layer (§9.16) is sufficient when relays perform no routing decisions beyond subscription matching.

**Anonymity vs accountability.** GNUnet's architecture is optimized for a world where state actors surveil communication and identity itself is dangerous. SCP's architecture is optimized for a world where AI agents act autonomously and verifiable provenance is necessary for trust. These are different futures; both are plausible.

**Maturity.** GNUnet has been in development for 25+ years and remains explicitly experimental ("significant bugs and critical design flaws" per project documentation). No production deployments at scale. SCP cannot depend on experimental infrastructure for core protocol functions.

### 11.3.10 Open Questions

GNUnet's **probabilistic burst NAT traversal** technique — backchannel-coordinated simultaneous multi-port connection attempts — could improve SCP's Tier 2 coverage for symmetric NATs without introducing STUN/TURN infrastructure dependency. See discussion #1380 for ongoing evaluation.

R5N's **randomized routing** and **path recording** offer censorship resistance properties that standard Mainline DHT lacks. If state-level DID resolution suppression becomes a practical threat, R5N's techniques could inform a more resilient resolution fallback alongside SCP's existing dual-layer approach (§3.10).

### 11.3.11 References

- Polot & Grothoff, "CADET: Confidential Ad-hoc Decentralized End-to-End Transport," Med-Hoc-Net 2014
- Evans & Grothoff, "R5N: Randomized Recursive Routing for Restricted-Route Networks," NSS 2011
- Mueller, Evans & Grothoff, "Autonomous NAT Traversal," 2010
- Grothoff, "The GNUnet System," Habilitation thesis, Inria
- IETF draft-schanzen-r5n-01 (R5N specification)
- Wachs, Schanzenbach & Grothoff, "A Censorship-Resistant, Privacy-Enhancing and Fully Decentralized Name System," CANS 2014
- RFC 9498: The GNU Name System (GNS specification, IETF)
- LSD-0001 (GNS specification), LSD-0005 (did:gns), LSD-0007 (Communicators), LSD-0012 (CAKE)

---

## 11.4 Freenet / Hyphanet

**Freenet** (2000, Ian Clarke) is one of the oldest decentralized infrastructure projects, predating BitTorrent, Tor, and most modern P2P systems. Originally conceived in Clarke's 1999 University of Edinburgh thesis, Freenet is a censorship-resistant distributed data store where content is stored encrypted across participating nodes, retrieved by key, and persists based on demand rather than owner intent. In March 2023, the original Java codebase was spun off as **Hyphanet** under its existing maintainers, while Clarke's ground-up Rust rewrite (internally "Locutus," begun 2019) took the Freenet name as **Freenet 2023**. The comparison with SCP is instructive because both systems implement provider-blind encrypted storage, but optimize for fundamentally different threat models: Freenet for censorship resistance and publisher anonymity; SCP for governance, accountability, and provenance.

### 11.4.1 Architecture

Freenet operates as a distributed hashtable where participating nodes collectively pool storage to hold encrypted data blocks. Unlike Kademlia-based DHTs (used by BitTorrent, IPFS, GNUnet's R5N), Freenet does not use XOR-distance routing. Instead, each node is assigned a **location** — a floating-point value on a ring from 0.0 to 1.0 — and requests are routed greedily toward the node whose location is closest to the target key (also mapped to the 0.0–1.0 space).

The network operates in two modes:

- **Opennet.** Nodes connect to arbitrary peers discovered through the network. Topology optimization occurs via **path folding**: when a request succeeds, the requesting node may form a direct connection to the responding node, progressively organizing the network so that topologically close nodes hold nearby locations.
- **Darknet (friend-to-friend).** Nodes connect only to manually-specified trusted peers. Because the social graph is fixed, topology optimization occurs via **location swapping**: nodes periodically exchange locations using the Metropolis–Hastings algorithm, minimizing the distance between connected peers. This creates a routable small-world network from an arbitrary trust graph — the key insight from Oskar Sandberg's work on distributed routing in small-world networks.

Requests carry a **Hops-to-Live (HTL)** counter, starting at 18, decremented at each hop. Data is cached along the return path, with caching suppressed for the first 2–3 hops (HTL > 15–16) to prevent nodes from identifying their immediate neighbors' requests. Data blocks are fixed-size: 32 KB for content blocks (CHK), 1 KB for signed metadata blocks (SSK).

### 11.4.2 Key Types

Freenet's key system reflects its design as a content-addressed, publisher-anonymous data store:

| Key Type | Full Name | Purpose | Mutability | Size | Integrity |
|----------|-----------|---------|------------|------|-----------|
| **CHK** | Content Hash Key | Static files | Immutable — hash of encrypted content IS the key | 32 KB blocks | SHA-256 self-verifying |
| **SSK** | Signed Subspace Key | Updateable content | Mutable — owner holds signing keypair | 1 KB blocks | RSA-2048 signature + SHA-256 |
| **USK** | Updatable Subspace Key | Versioned sites | SSK with version counter; clients probe for latest | 1 KB blocks | Inherits SSK verification |
| **KSK** | Keyword Signed Key | Human-readable names | Mutable — key derived from passphrase | 1 KB blocks | Weak (anyone with passphrase can overwrite) |

A CHK is `CHK@<SHA-256-hash>,<decryption-key>,<flags>`. The hash covers the encrypted content, so any node along the routing path can verify integrity by re-hashing — a hostile node altering data under a CHK is detected immediately. The decryption key is separate from the routing key: nodes route and cache content they cannot read.

SSKs use an asymmetric keypair (RSA-2048 for signing, 256-bit symmetric for encryption). The public key hash serves as the routing key; only the private key holder can publish updates. Nodes verify signatures but cannot decrypt content (the symmetric key travels only in the URI, not in the routed data). USKs layer a version number atop SSKs, enabling clients to probe incrementally for the latest version — Freenet's mechanism for updateable content in an otherwise content-addressed system.

### 11.4.3 Content Lifecycle — The Sharpest Contrast

This is where Freenet and SCP diverge most fundamentally.

**Freenet: demand-driven persistence, no deletion.**

- Content persists based on popularity. Popular content is replicated across many nodes (each hop caches a copy); unpopular content gradually expires as nodes reclaim storage for more-requested data.
- Once published, the publisher **cannot delete content**. There is no delete operation. The publisher's identity is unknown to the network. The only mechanism for content removal is collective disinterest — if nobody requests it, nodes eventually discard it to free space.
- Content is not permanent in the absolute sense (the network's total storage is finite and least-requested data is evicted), but it is **uncontrollable** — the publisher has no lifecycle authority after insertion.

**SCP: governed lifecycle, explicit deletion.**

- Content lives within contexts (§5). Contexts have governance models (§5.9) that define who can publish, modify, and delete content.
- Content deletion is a governed action. Context administrators can remove content. Members can be removed, and their access revoked — MLS group key rotation ensures removed members cannot read future messages (forward secrecy), and the sender-side key layer (§9.16) enables retroactive per-sender blocking.
- Content access is cryptographically bounded. Without the MLS group key, content is unreadable. Membership revocation is immediate and cryptographic, not dependent on network-wide cooperation.

| Dimension | Freenet / Hyphanet | SCP |
|-----------|-------------------|-----|
| Persistence model | Demand-driven; popular content lives, unpopular expires | Governed; explicit lifecycle within contexts |
| Deletion | Impossible by publisher; only via collective disinterest | Governed action; admin-controlled with cryptographic enforcement |
| Publisher control after insertion | None | Full, within governance rules |
| Access revocation | Impossible — decryption key is in the URI | MLS key rotation + sender-side key denial (§9.16) |
| Content discovery | Global — any node can request any key | Context-scoped — content exists within bounded, encrypted spaces |
| Optimizes for | Censorship resistance | Accountability and governance |

Freenet's model is coherent for its threat model: if content can be deleted by its publisher, a coerced publisher becomes a censorship vector. SCP's model is coherent for its threat model: if content cannot be governed, contexts become ungovernable. Neither is wrong — they address different problems.

### 11.4.4 Identity and Anonymity

Freenet provides **publisher anonymity** by design — content propagates through multiple hops, each caching a copy, so the publishing node is untraceable after insertion. Retrievers are similarly anonymous via HTL counter probabilistic decrement.

The anonymity-vs-accountability trade-off follows the same pattern as GNUnet (§11.3.2), with Freenet-specific mechanisms:

- **HTL-based plausible deniability.** A node forwarding a request is indistinguishable from the node that originated it because the HTL counter may or may not decrement on the first hop.
- **No protocol-level identity.** Nodes have transport-level cryptographic identities (JFki/Diffie-Hellman for link encryption), but nothing that identifies content authors.
- **Web of Trust (WoT) plugin.** An optional application-layer identity and reputation system atop Freenet's storage. Identities are SSK keypairs; trust is numeric scores propagated through a social graph, weighted by distance. WoT functions primarily as a **spam filter** — in an anonymous network, trust scores determine whose content is displayed.
- **Darknet trust.** Friend-to-friend connections encode trust at the network level, but this is connectivity trust, not content-level identity.

### 11.4.5 Routing

Freenet's routing is distinctive among P2P systems. Where Kademlia (used by BitTorrent, IPFS) uses XOR-distance in a 160-bit keyspace with structured k-buckets, and GNUnet's R5N adds a random-walk prefix to handle NAT-restricted topologies, Freenet maps everything to a continuous 0.0–1.0 ring and routes greedily.

**Darknet routing** is based on Kleinberg's small-world model. Sandberg (2006) showed that if a social network has small-world properties (most connections local, a few long-range), then the Metropolis–Hastings location-swapping algorithm can assign locations such that greedy routing achieves O(log^2 n) expected hops. The social graph's topology is fixed (users choose their friends); only the location assignments change. This is a simulated annealing process — nodes periodically propose location swaps to neighbors, accepting swaps that reduce total distance to neighbors (with probabilistic acceptance of worse swaps to escape local minima).

**Opennet routing** uses path folding instead. When a request is answered, the requester may connect directly to the responder, folding the path. Over time, this organizes the network so that nearby locations cluster on nearby nodes. Path folding is less secure than location swapping (an attacker can selectively fold paths to position themselves near targets), but it works without pre-existing trust relationships.

**Comparison with structured DHTs:**

| Property | Kademlia (BitTorrent, IPFS) | R5N (GNUnet) | Freenet |
|----------|-----------------------------|--------------|---------|
| Keyspace | 160-bit, XOR distance | 256-bit, XOR distance | 0.0–1.0 ring, Euclidean distance |
| Routing | Structured (k-buckets, iterative lookup) | Random-walk prefix + XOR routing | Greedy forwarding to nearest location |
| Topology optimization | None (structure is the topology) | None (random walk handles NAT) | Location swapping (darknet) / path folding (opennet) |
| NAT handling | Relay nodes, hole punching | Random-walk bypasses restricted routes | Darknet connections bypass NAT entirely (friend-to-friend) |
| Hop count | O(log n) | O(log n) after random walk | O(log^2 n) theoretical; HTL max 18 in practice |
| Caching | Nodes near key cache data | Path-based caching | Every hop caches (with HTL-based suppression near origin) |

SCP does not implement its own routing algorithm. SCP's relay architecture (§10) is fundamentally different: relays are addressed directly (by URL), not discovered through a DHT. Content is routed by `routing_id` (SHA-256 of context ID), and relays store-and-forward encrypted blobs. Unlike Freenet's tightly integrated routing, SCP's transport-agnostic model (§11.1.4) means it can run atop Freenet, Kademlia, or any other routing substrate without depending on any of them.

### 11.4.6 Storage Model — Provider-Blind Encrypted Storage

Freenet's storage model has a striking structural parallel with SCP's relay model:

**Freenet:** Every participating node contributes disk space to a shared data store. Content is stored encrypted — nodes cannot determine what they are storing. This provides **plausible deniability**: a node operator cannot be held responsible for content they provably cannot inspect. The data store is a fixed-size LRU cache; when full, the least-recently-requested data is evicted. Nodes have no say in what they store — data migrates toward nodes whose locations are near the data's key, driven entirely by request patterns.

**SCP:** Relays store encrypted blobs they cannot read (§10). Relays are explicitly untrusted — they provide store-and-forward delivery but have no access to plaintext. MLS group keys (§9) are the access control mechanism, not relay-level permissions. Relays are, by design, "dumb pipes."

| Dimension | Freenet Data Store | SCP Relay |
|-----------|-------------------|-----------|
| What is stored | Encrypted content blocks (32 KB CHK, 1 KB SSK) | Encrypted MLS messages and relay blobs (up to 256 KB) |
| Who decides storage | Network demand (automatic caching) | Explicit publish by context members |
| Storage duration | Demand-driven LRU; unpopular content expires | TTL-based (7 days for DID documents); context-governed for messages |
| Provider can read content | No (encrypted with key not available to node) | No (MLS-encrypted; relay has no group key) |
| Provider can identify content | Partially (key is visible; content is not) | Partially (routing_id is visible; content is not) |
| Plausible deniability | Yes — design goal | Not a goal — relays are service providers, not anonymous participants |
| Eviction policy | LRU — least requested data evicted first | Governance-controlled — context rules determine retention |

The structural similarity — infrastructure that stores encrypted data it cannot read — is real. The motivation differs: Freenet encrypts for plausible deniability (protecting node operators from legal liability for stored content). SCP encrypts for access control (MLS group keys are membership; encryption is the authorization mechanism).

### 11.4.7 What SCP Borrows Conceptually

1. **Provider-blind storage.** The proof that distributed systems can operate reliably when storage providers cannot inspect what they store. Freenet demonstrated this at scale starting in 2000; SCP's relay model (§10) applies the same principle with different motivation (access control rather than deniability).

2. **Content-addressed integrity verification.** CHKs — where the hash of the content IS the address — established that any intermediary can verify data integrity without being able to read the data. SCP uses content-addressed hashing for event log integrity (Merkle trees), DID document verification (BEP44 self-certification), and blob integrity in relay storage.

3. **Distributed encrypted storage works at scale.** Freenet has operated continuously since 2000 with thousands of nodes, proving that encrypted distributed storage is not merely theoretical. This is an existence proof SCP relies on — not in architecture, but in confidence that the category of "provider-blind storage" is viable at scale.

4. **Small-world self-organization.** Freenet's demonstration that a P2P network can self-organize into an efficient routing topology from arbitrary social graphs (via location swapping) informed the broader understanding of decentralized network design. SCP does not use small-world routing, but the principle that decentralized systems can achieve efficient structure without central coordination is foundational.

### 11.4.8 Why SCP Diverges

The divergences are not incremental — they reflect incompatible design axioms.

**1. Content governance vs. content immortality.** Freenet's core promise is that published content cannot be censored or deleted. SCP's core promise is that content exists within governed contexts where lifecycle management, access revocation, and deletion are first-class operations. These are mutually exclusive design goals. A system that guarantees content cannot be deleted cannot also guarantee content can be governed. SCP chose governance.

**2. Accountability vs. anonymity.** The same fundamental divergence as GNUnet (§11.3.2), with Freenet adding WoT as an optional plugin atop publisher anonymity — whereas SCP makes identity mandatory infrastructure.

**3. Bounded contexts vs. global datastore.** Freenet is a global, flat keyspace — any node can request any key. There is no concept of access boundaries, membership, or scope. SCP's security boundary is the context (§5): a bounded, encrypted, governed space where membership is enforced by MLS group keys. Content in a context is invisible to non-members — not because it is hidden in a global store, but because it does not exist outside the context's cryptographic boundary.

**4. Transport independence vs. integrated network.** Freenet IS a network — routing, storage, and retrieval are tightly coupled into a single P2P overlay. Unlike SCP's transport-agnostic model (§11.1.4), Freenet cannot be used as a transport substrate for other protocols — the coupling goes in one direction. SCP could use Freenet as an adapter; Freenet cannot use SCP as a transport layer.

**5. Async delivery vs. synchronous retrieval.** Freenet retrieval requires at least some path of online nodes between requester and data. SCP's relay architecture provides store-and-forward async delivery — messages are delivered even when recipients are offline, with three-tier degradation (§23). This is a fundamental architectural difference: Freenet is a retrieval system; SCP is a communication system.

### 11.4.9 Freenet 2023 (formerly Locutus)

In 2019, Ian Clarke began a ground-up rewrite of Freenet in Rust. Originally codenamed "Locutus," it was rebranded as Freenet in March 2023 when the original Java codebase was spun off as Hyphanet. Freenet 2023 is architecturally distinct from Hyphanet — backward compatibility was deemed impractical.

**Key architectural changes:**

- **Contract-based computation.** Freenet 2023 is a global key-value store where keys are WebAssembly contracts. Contracts define validity rules, modification permissions, and synchronization logic. This transforms Freenet from a "decentralized hard drive" (Hyphanet) into a "decentralized computer" (Freenet 2023). Contracts implement the `ContractInterface` trait, with state forming a **commutative monoid** — updates can be applied in any order and produce the same final state, achieving eventual consistency without consensus protocols or proof-of-work.
- **Delegates for private state.** Delegates are local WebAssembly components that hold secrets and perform sensitive operations. Applications never see private keys directly — delegates sign and decrypt on behalf of the application. This separation of public state (contracts, replicated) and private state (delegates, local) is structurally parallel to SCP's separation of context state (encrypted, distributed via relays) and key custody (local, hardware-backed, ADR-006).
- **Subscription-based real-time updates.** Clients can subscribe to contracts and receive notifications when state changes. Subscription trees form automatically along routing paths, enabling real-time propagation. This is a departure from Hyphanet's request-response model and moves closer to SCP's relay subscription model (where clients subscribe to routing IDs for real-time message delivery).
- **Synchronization via deltas.** Contracts define `summarize_state`, `get_state_delta`, and `update_state` functions. Peers exchange compact summaries, identify divergences, and transfer only deltas. This is analogous to SCP's MLS epoch-based synchronization, though SCP's approach is protocol-defined rather than application-defined.

**Relevance to SCP's context model:** Freenet 2023's contracts share a conceptual surface area with SCP's contexts — both are bounded computational spaces with defined rules for state mutation. The differences are significant: SCP contexts have cryptographic membership (MLS), governance models (§5.9), capability-based authorization (UCAN, §4, §7), and identity-bound participation. Freenet 2023 contracts have WebAssembly-defined validation logic but no built-in membership, governance, or identity primitives — these must be implemented per-contract by application developers.

Freenet 2023's delegate model — where private keys are held locally and operations are performed through a message-passing interface — parallels SCP's key custody architecture (ADR-006), where custody backends (Secure Enclave, Android Keystore, file-based) hold signing keys and perform operations on behalf of the protocol layer. Both systems recognize that private key material must never leave a trust boundary; they differ in how that boundary is defined (WebAssembly sandbox vs. hardware-backed custody).

As of early 2026, Freenet 2023 has a working peer network, contract execution, and a demonstration chat application (River), but remains in active development with limited production deployment compared to Hyphanet's 25-year operational history.

### 11.4.10 References

1. Clarke, I. (1999). *A Distributed Decentralised Information Storage and Retrieval System.* Unpublished undergraduate thesis, Division of Informatics, University of Edinburgh.
2. Clarke, I., Sandberg, O., Wiley, B., & Hong, T. W. (2001). Freenet: A Distributed Anonymous Information Storage and Retrieval System. In H. Federrath (Ed.), *Designing Privacy Enhancing Technologies*, Lecture Notes in Computer Science, vol. 2009, pp. 46–66. Springer.
3. Clarke, I., Sandberg, O., Toseland, M., & Verendel, V. (2010). Private Communication Through a Network of Trusted Connections: The Dark Freenet. Manuscript, https://www.hyphanet.org/assets/papers/freenet-0.7.5-paper.pdf
4. Sandberg, O. (2006). Distributed Routing in Small-World Networks. In *Proceedings of the 8th Workshop on Algorithm Engineering and Experiments (ALENEX)*, pp. 144–155. SIAM.
5. Kleinberg, J. (2000). The Small-World Phenomenon: An Algorithmic Perspective. In *Proceedings of the 32nd ACM Symposium on Theory of Computing (STOC)*, pp. 163–170.
6. Evans, N. S., & GauthierDickey, C. (2007). Routing in the Dark: Pitch Black. In *Proceedings of the 23rd Annual Computer Security Applications Conference (ACSAC)*, pp. 305–314.
7. Freenet Project. (2026). Freenet Manual: Components. https://freenet.org/resources/manual/components/
8. Hyphanet Project. (2026). Hyphanet Wiki: Security Summary. https://github.com/hyphanet/wiki/wiki/Security-summary

---

## 11.5 Tahoe-LAFS

**Tahoe-LAFS** (Tahoe Least-Authority File Store) is an open-source, decentralized, cryptographically secure distributed file system created by Zooko Wilcox-O'Hearn and Brian Warner. Originally developed at allmydata.com (2006-2009) as a commercial backup service, it was released as open-source software and became the reference implementation of provider-independent, capability-secured storage. The foundational paper was presented at ACM StorageSS 2008 (Wilcox-O'Hearn & Warner, "Tahoe: the least-authority filesystem," Proceedings of the 4th ACM International Workshop on Storage Security and Survivability, 2008, pp. 21-26). Tahoe-LAFS is the most complete real-world application of object-capability security principles to distributed storage, and the intellectual ancestor of the capability-based authorization model that SCP inherits through UCAN.

### 11.5.1 Provider-Independent Security (POLA)

The "LAFS" in the name is literal: the system is designed around the principle of least authority (POLA) — every component has exactly the minimum power required for its function, enforced by cryptography rather than policy. Tahoe coined the term "provider-independent security" to describe a property that goes beyond encryption:

> "The service provider never has the ability to read or modify your data in the first place: never."

This means three guarantees: **confidentiality** (AES encryption, key held only by client), **integrity** (Merkle hash trees, cap-embedded hashes), and **unforgeability** (RSA signatures for mutable files, content-hash binding for immutable). The provider can deny service; it cannot do anything else. Storage servers cannot read data. Clients cannot modify data they only have read access to. Repairers can reconstruct missing shares without decrypting content. The system holds even if every storage server is adversarial.

SCP's relay model applies the same provider-blind principle (see also §11.4.6 for Freenet's parallel) through different mechanisms:

| Property | Tahoe-LAFS Mechanism | SCP Mechanism |
|----------|---------------------|---------------|
| **Confidentiality** | AES-128-CTR, key in client-held capability | MLS group key (AES-128-GCM), distributed via MLS key schedule |
| **Integrity** | Merkle hash trees + SHA-256d, roots embedded in caps | MLS authenticated encryption (AEAD) + event log Merkle trees |
| **Unforgeability** | RSA-2048 signatures (mutable files), content-hash binding (immutable) | Ed25519 signatures on MLS messages + UCAN chain verification |
| **Relay/server access** | Sees encrypted shares + storage index | Sees encrypted blobs + pseudonym-derived routing IDs |
| **Key management** | Embedded in capability URIs (no separate key distribution) | MLS key schedule (ratcheting, forward secrecy, post-compromise security) |

Where SCP extends beyond Tahoe: MLS provides forward secrecy and post-compromise security — properties that Tahoe's static encryption keys cannot provide. Tahoe's AES key for a file is permanent; if it leaks, all past and future access is compromised. MLS ratchets keys with each epoch, so compromise of a current key does not expose past messages, and removal of a compromised member restores confidentiality for future messages.

### 11.5.2 Capability Model

The capability model is the centerpiece of Tahoe-LAFS and the most important comparison with SCP. In Tahoe, a capability (cap) is a cryptographic URI string that simultaneously provides both **location** (where to find the data on the grid) and **identification** (proof that the retrieved data is authentic). Possessing the cap IS the authorization — there is no access control list, no identity check, no server-side permission enforcement. The cap is an unforgeable bearer token.

#### Capability Types

Tahoe defines 13 capability types across two categories (filecaps and dircaps), organized in a derivation hierarchy where stronger capabilities can derive weaker ones (called "diminishing") but never the reverse:

**Immutable files:**

| Cap Type | URI Prefix | Contains | Grants |
|----------|-----------|----------|--------|
| Read-cap | `URI:CHK:` | 16-byte AES read key + SHA-256 hash of URI Extension Block | Decrypt and read file content |
| Verify-cap | `URI:CHK-Verifier:` | Storage index + UEB hash (no read key) | Verify integrity of ciphertext shares without reading plaintext |
| Literal | `URI:LIT:` | File content inline (files <= 55 bytes) | Read (content embedded in cap itself) |

The key design principle is **one-way derivation**: the read key derives the storage index (via SHA-256d), so knowing the read key lets you locate AND decrypt a file, but knowing the storage index only lets you verify share integrity. This chain — `read_key → storage_index → (locate, verify)` — means routing and authorization are unified in a single cryptographic construction.

**Mutable files** (SSK — from Freenet's "Sub-Space Keys") add RSA-2048 for asymmetric signing and extend the hierarchy: `write_key → read_key → storage_index`, each step a one-way hash truncation. A write-cap holder can derive read and verify capabilities; a read-cap holder can derive only the verify-cap. The write key encrypts the RSA private key within shares; the read key encrypts file content — so write authority and read authority are protected by different symmetric keys.

**Directories** are mutable files whose content maps child names to child capabilities. Read-only directory access is transitively read-only — you cannot extract write-caps for children from a read-only directory cap.

**Repaircap: least privilege in action.** A repairer can download shares, verify integrity, reconstruct missing shares via erasure coding, and upload replacements — but cannot decrypt content. The entity responsible for data durability has no access to data confidentiality.

### 11.5.3 Capability Model Comparison: Tahoe-LAFS vs SCP UCAN

Both Tahoe-LAFS and SCP use capability-based authorization where the bearer token (not an identity lookup) determines access. But the capability models differ fundamentally in structure, delegation, lifecycle, and scope.

| Dimension | Tahoe-LAFS Capabilities | SCP UCAN Tokens |
|-----------|------------------------|-----------------|
| **Representation** | Cryptographic URI string (`URI:CHK:...`, `URI:SSK:...`) | Signed JWT (JSON Web Token with `ucv`, `iss`, `aud`, `att`, `exp` fields) |
| **What it encodes** | Encryption key + content hash (location + identification) | Issuer DID + audience DID + capability set + expiration + proofs |
| **Bearer semantics** | Pure bearer — anyone with the URI string has access | Audience-bound — only the `aud` DID can exercise the capability |
| **Identity binding** | None — capabilities are anonymous | DID-bound — issuer and audience are cryptographically identified |
| **Delegation** | None — you share the cap string, granting full access at that level | Native — `prf` (proof) field chains delegations; each link is a signed JWT |
| **Attenuation** | One direction only: write → read → verify (diminishing) | Arbitrary: any capability subset, custom resources, narrower scope |
| **Time-bounding** | None — caps are permanent while the data exists | Native — `exp` (expiration) and `nbf` (not-before) fields |
| **Revocation** | Impossible — the cap is the key, and you cannot un-share a key | Revocation records (§7.3) checked at verification time |
| **Scope** | Single file or directory | Context-scoped: `scp:ctx:{context_id}/{resource}:{action}` |
| **Governance** | None — no concept of rules governing capability exercise | Full governance model: 30 action types, pluggable engines (§5.9) |
| **Accountability** | None — caps are anonymous, no audit trail of who used them | Full — every action signed by a DID, recorded in event logs |
| **Composability** | File-level only | Protocol-wide: identity + capability + context + governance |

**The fundamental divergence:** Tahoe capabilities are static and anonymous. Once you have a read-cap, you have read access forever, and no one can tell who is reading. UCAN tokens are dynamic and identified. They expire, they can be revoked, they chain through identified delegators, and every exercise is attributable to a specific DID.

This reflects the different problem domains. Tahoe secures data at rest — files on a grid. The threat model is the storage provider reading or modifying your files. Anonymity is a feature: the cap proves you are authorized without revealing who you are. SCP secures interaction — communication within governed contexts. The threat model includes unauthorized agents, capability escalation, and unattributable actions. Identity is a feature: the UCAN proves both that you are authorized AND who you are.

Both inherit from the object-capability tradition (Dennis & Van Horn 1966, Mark Miller's E language, erights.org). The intellectual lineage runs: object-capability theory → Tahoe-LAFS (cryptographic capabilities for storage) → UCAN (cryptographic capabilities for authorization delegation) → SCP (capabilities embedded in a governance and identity framework). Tahoe proved that cryptographic capabilities work for decentralized access control without ACLs. UCAN added the delegation, attenuation, and identity-binding that real-world authorization requires. SCP embedded UCANs in a context-governed, MLS-encrypted interaction protocol.

### 11.5.3.1 Why UCAN Over OAuth, GNAP, and Macaroons

SCP's choice of UCAN over established authorization frameworks reflects the protocol's decentralization and identity requirements:

| Dimension | OAuth 2.0 | GNAP | Macaroons | UCAN (SCP) |
|-----------|-----------|------|-----------|------------|
| **Centralization** | Authorization server required | Grant server required | Minting authority required | Fully decentralized — any DID can issue |
| **Bearer semantics** | Token opaque to client; server validates | Token opaque; server validates | Bearer token with embedded caveats | Bearer token with embedded capabilities |
| **Delegation** | No native delegation (requires token exchange extension) | Structured grant lifecycle, server-mediated | Contextual caveats can attenuate; third-party caveats delegate verification | Native chained delegation via `prf` field; each link is a signed JWT |
| **Identity binding** | Client ID (application-level, not user-level) | Instance identity (ephemeral) | None — pure bearer | DID-bound — issuer and audience are cryptographically identified |
| **Offline verification** | No — requires token introspection or server-signed JWT | No — requires grant server | Partial — first-party caveats are offline; third-party caveats require the third party | Full — signature chain is self-contained and verifiable without any server |
| **Revocation** | Server-side (revoke at authorization server) | Server-side (revoke at grant server) | Third-party caveat expiration | Protocol-level revocation records (§7.3), checked at verification time |

OAuth and GNAP require a central authorization server, violating SCP's "protocol requires no operator" tenet. Macaroons offer decentralized attenuation but lack identity binding — a macaroon proves "someone was authorized," not "this DID was authorized." UCAN uniquely combines decentralized issuance, identity binding, offline verification, and chained delegation — the properties SCP needs for DID-to-DID capability delegation across contexts without any central authority.

### 11.5.4 Erasure Coding and Redundancy

Tahoe distributes each file across multiple storage nodes using erasure coding. The default parameters are:

- **k = 3** — minimum shares needed to reconstruct the file
- **N = 10** — total shares created
- **H = 7** — minimum independent servers required for upload success ("servers of happiness")
- **Expansion factor: 3.3x** — each file consumes 3.3x its plaintext size in storage

The pipeline: plaintext → AES-CTR encryption → segmentation (128 KiB default) → erasure coding per segment → one block per segment per share → distribution across servers. Each share gets one block per segment, plus Merkle hash trees for verification.

The erasure coding algorithm (zfec, based on Rizzo's FEC) means any k-of-N shares suffice for reconstruction. Up to (N - k) = 7 servers can fail simultaneously without data loss. The system can tolerate the loss of any 70% of its storage nodes.

**Comparison with SCP's multi-relay architecture (§9.9.2):**

| Dimension | Tahoe-LAFS Erasure Coding | SCP Multi-Relay Publishing |
|-----------|--------------------------|---------------------------|
| **Purpose** | Data durability — survive storage node failure | Message availability — survive relay failure or censorship |
| **Mechanism** | k-of-N erasure coding (zfec) | Full message replication to multiple relays |
| **Redundancy** | Encoded fragments — any k of N suffice | Full copies — any 1 of M relays suffice |
| **Expansion cost** | 3.3x storage (tunable via k/N ratio) | Mx storage and bandwidth (M = number of relays) |
| **Failure tolerance** | (N - k) simultaneous node failures | (M - 1) simultaneous relay failures |
| **Reconstruction** | Client downloads k shares, decodes | Client reads from first available relay |
| **Suppression resistance** | High — attacker must compromise >70% of nodes | High — attacker must compromise all relays (§9.9.2) |
| **What's distributed** | Encoded ciphertext fragments | Complete encrypted messages |

Tahoe's approach is more storage-efficient (3.3x vs Mx). SCP's approach is simpler (no erasure coding, no multi-share reconstruction). The difference reflects their domains: Tahoe must store large files durably for long periods, making encoding efficiency critical. SCP must deliver messages reliably in real time, making simplicity and latency critical. Erasure coding adds reconstruction latency; full replication provides instant availability from any relay.

Tahoe's redundancy model offers one insight relevant to SCP: k-of-N encoding could improve SCP's relay-layer efficiency for large payloads (blob storage, file attachments). Instead of replicating a 100 MB file to 3 relays (300 MB total), erasure coding to 3-of-10 across 10 relays would use 330 MB but survive 7 relay failures instead of 2. This is an optimization opportunity, not a design necessity.

### 11.5.5 Convergent Encryption

Tahoe supports convergent encryption — deriving the encryption key deterministically from file content (`SHA-256d(tag || params || convergence_secret || content)[:16]`) to enable deduplication without servers seeing plaintext. SCP has no equivalent: MLS keys derive from the group key schedule, not message content, and deduplication is irrelevant to a communication protocol where the same text sent twice constitutes two distinct messages.

### 11.5.6 Mutable Files and Versioning

Tahoe's immutable files are write-once: the capability is derived from the content, so changing the content changes the capability. Mutable files (SSK format) add updateability:

- **RSA-2048 keypair** — the private key signs updates, the public key verifies them
- **Sequence numbers** — 64-bit monotonic counter prevents rollback attacks
- **Two formats:** SDMF (Small Distributed Mutable Files, single segment, entire file downloaded for any read) and MDMF (Medium Distributed Mutable Files, 128 KiB segments, partial reads/writes)
- **Write coordination:** The "Prime Coordination Directive" warns that uncoordinated simultaneous writes can corrupt a file if competing versions exceed the erasure coding recovery threshold (S > N/k)
- **Per-server write enablers:** `H(write_enabler_master + server_nodeid)` — each storage server gets a unique authorization token, preventing cross-server impersonation

**Comparison with SCP event logs:**

| Dimension | Tahoe Mutable Files | SCP Event Logs (§7.3.1) |
|-----------|--------------------|--------------------|
| **Mutability model** | Replace-in-place (latest version wins) | Append-only (events accumulate) |
| **Signing** | RSA-2048 (single writer per file) | Ed25519 via MLS (multi-writer per context) |
| **Multi-writer** | Discouraged — "Prime Coordination Directive" warns of corruption | Native — MLS group membership defines write authority |
| **Versioning** | Sequence number (64-bit monotonic counter) | MLS epoch + generation + sequence triple |
| **Conflict resolution** | Last-writer-wins (no CRDT, no merge) | Ordered by MLS epoch (no conflict — append-only) |
| **Forward secrecy** | None — same RSA key for all versions | Yes — MLS key ratcheting per epoch |
| **Rollback prevention** | Sequence number check | Merkle tree inclusion proofs |
| **Write authorization** | Possession of write-cap (anonymous) | MLS membership + UCAN capability + governance check |

Tahoe's mutable files are a storage primitive — they provide a single mutable slot with integrity and confidentiality. SCP's event logs are a richer structure: append-only (no destructive update), multi-writer with cryptographic membership enforcement, embedded in a governance framework that controls who can append what.

### 11.5.7 Grid Architecture

A Tahoe grid consists of three node types:

1. **Introducer** — a coordination node that maintains the server roster. Servers announce themselves to the introducer; clients connect to receive the list of available servers. The introducer is a recoverable single point of failure: it is defined by a hostname and a private key, easily relocated. Once clients have the server roster, they maintain direct connections without the introducer.

2. **Storage servers** — user-space processes that store shares (encrypted, erasure-coded fragments). Servers perform no cryptographic operations — no decryption, no signature verification, no erasure coding. They are deliberately simple: accept shares, serve shares, manage leases. This simplicity is a security feature — the server has no capability that could be exploited to compromise data.

3. **Client nodes (gateways)** — the security-critical component. Clients perform all encryption, erasure coding, share distribution, Merkle tree computation, capability generation, and download reconstruction. Clients connect to every known server in a bi-clique topology. The client is the only component that handles plaintext or encryption keys.

Server selection uses consistent permutation: `HASH(storage_index + nodeid)` sorts servers into a deterministic, per-file order, ensuring even distribution across the grid. Nodes communicate over TCP using Foolscap (the original protocol) or HTTPS (default since v1.19).

**Comparison with SCP's architecture:**

| Dimension | Tahoe-LAFS Grid | SCP Relay + Node Architecture |
|-----------|----------------|------------------------------|
| **Discovery** | Introducer (centralized roster) | DHT + relay layer + DID document service endpoints (§3.10, §18) |
| **Infrastructure role** | Storage servers — store shares, serve shares, nothing else | Relays — receive blobs, deliver blobs, nothing else |
| **Client role** | All crypto + erasure coding + share management | All crypto + MLS + governance + capability validation |
| **Topology** | Bi-clique (every client → every server) | Subscription-based (participants subscribe to routing IDs on relays) |
| **Protocol** | Foolscap / HTTPS | WebSocket (primary) + 17 transport adapters (§10.5) |
| **Server intelligence** | Minimal — store/serve/lease | Minimal — receive/deliver/TTL |
| **Single point of failure** | Introducer (recoverable) | None — DHT + multiple relays + relay fallback list (§18.5.1) |
| **NAT traversal** | Requires Foolscap connection (bi-clique limited by NAT) | 4-tier reachability: port mapping, hole punching, bridge relay, domain TLS (§10.12) |

Both architectures share the principle that infrastructure nodes (storage servers / relays) are deliberately stupid. All security-critical logic lives in the client. The main architectural difference is discovery: Tahoe uses a centralized introducer (simple, but a single point of failure); SCP uses decentralized multi-layer resolution (more complex, but no single point of failure).

### 11.5.8 Zooko's Triangle

Zooko Wilcox-O'Hearn, the co-creator of Tahoe-LAFS, is also the originator of Zooko's triangle (2001). The full analysis of this naming trilemma — with a comparison table across DNS, GNS, ENS, and SCP — appears in §11.3.5. The relevant connection here is biographical: the same person who identified the fundamental naming problem also built Tahoe-LAFS, which sidesteps it entirely. Tahoe capabilities occupy the "secure + decentralized" edge — cryptographic strings that no human will memorize, but unforgeable and authority-free. SCP's DID approach makes the same trade-off, compensating with display names and context-level naming at higher layers.

### 11.5.9 What SCP Borrows Conceptually

Three ideas flow directly from Tahoe-LAFS into SCP's design:

1. **Capability-based authorization without ACLs.** Tahoe proved that distributed systems can enforce access control using cryptographic bearer tokens rather than identity lookups or server-side permission lists. This is the foundation of SCP's UCAN model. The conceptual step from Tahoe caps to UCANs is: add identity binding (issuer/audience DIDs), add delegation chains (proof fields), add time-bounding (expiration), add revocation, add governance. But the core insight — the token IS the authorization, verified by cryptography not by asking a server — originates in this tradition.

2. **Provider-independent security.** The principle that infrastructure operators should have zero access to the data they handle. Tahoe applied this to file storage (servers cannot read files). SCP applies it to message delivery (relays cannot read messages). Same principle, different scope. In both cases, the client/participant performs all encryption and the infrastructure handles only opaque ciphertext.

3. **The math enforces access, not the infrastructure.** Tahoe's entire security model derives from the hardness of AES, SHA-256, and RSA — not from trusting servers to enforce permissions. SCP's security model derives from the hardness of AES-128-GCM (MLS AEAD), SHA-256 (Merkle trees, storage indices), and Ed25519 (signatures, DID binding) — not from trusting relays or governance servers. Both protocols are designed so that a fully adversarial infrastructure cannot compromise confidentiality or integrity. Only availability is at risk.

The intellectual lineage: object-capability theory (Dennis & Van Horn 1966) → E language (Mark Miller 1997) → Tahoe-LAFS (Wilcox-O'Hearn & Warner 2007) → UCAN (Fission/Brooklyn Zelenka 2021) → SCP. Each step adds structure: E added language-level enforcement; Tahoe added cryptographic enforcement for distributed storage; UCAN added delegation, attenuation, and identity binding; SCP added governance, group encryption, and context isolation.

### 11.5.10 Why SCP Diverges

Despite the shared intellectual heritage, Tahoe-LAFS and SCP solve fundamentally different problems. The divergences are not deficiencies in either system — they reflect different domains.

| Dimension | Tahoe-LAFS | SCP | Why Different |
|-----------|------------|-----|---------------|
| **Domain** | File storage (data at rest) | Communication (data in motion within governed contexts) | Storage is static; communication is dynamic with evolving group membership |
| **Capability lifecycle** | Permanent — a cap grants access as long as the data exists | Time-bounded — UCANs expire, can be revoked, are governance-scoped | Communication requires temporal control; file access is typically permanent |
| **Capability delegation** | None — share the URI string, that's it | Native — delegation chains with attenuation at each link | Communication requires scoped, auditable delegation; file sharing is simpler |
| **Identity** | None — capabilities are anonymous bearer tokens | Core — every action traces to a DID, attestation chains to human accountability | Storage can be anonymous; communication in governed contexts requires accountability |
| **Group communication** | None — Tahoe is single-user or share-the-cap | Native — MLS groups with add/remove/update, forward secrecy, post-compromise security | File storage does not require real-time group membership management |
| **Governance** | None — no concept of rules, roles, or permissions beyond read/write/verify | 30 governance action types, pluggable engines, capability ceilings (§5.9) | File storage is ungoverned; collaborative communication requires governance |
| **Forward secrecy** | None — static encryption keys per file | Yes — MLS key ratcheting per epoch | Static files do not benefit from key ratcheting; communication sessions do |
| **Conflict resolution** | Last-writer-wins for mutable files | Append-only event logs — no conflict by construction | File replacement is a valid operation; message history is immutable |
| **Transport** | Grid-specific (Foolscap/HTTPS between Tahoe nodes) | Transport-agnostic (§11.1.4) | File grids are a closed system; communication must bridge protocol worlds |
| **Agent model** | No concept of AI agents | First-class — agents are UCAN-bounded participants with human accountability chains | 2007 design predates the agentic paradigm entirely |
| **Provenance** | None beyond capability possession | Protocol-level — every action carries verifiable origin metadata (§24) | File access does not require provenance; agentic communication does |

**The sharpest difference:** Tahoe capabilities are anonymous and permanent. This is correct for file storage — you want a link to a file to work forever, and you do not need to know who is reading it. SCP's UCAN tokens are identified and ephemeral. This is correct for communication — you need to know who is speaking, you need to bound how long a delegation lasts, and you need to revoke access when group membership changes.

### 11.5.11 Capability Lineage

Zooko Wilcox-O'Hearn went on to found Least Authority Enterprises (2011, security auditing) and co-found Zcash (2016, zk-SNARK privacy-preserving cryptocurrency). The thread connecting Tahoe, Zcash, and SCP is **cryptographic enforcement of minimal authority** — denying the infrastructure layer authority over the data it processes, enforced by mathematics rather than policy. The intellectual lineage from Tahoe to UCAN runs through the object-capability community: Dennis & Van Horn (1966) established capability-based security; Mark Miller's E language (1997) added language-level enforcement; Tahoe proved cryptographic capabilities work for decentralized storage; UCAN (Fission/Brooklyn Zelenka 2021) added delegation, attenuation, and identity binding; SCP embedded UCANs in a governance and encryption framework.

### 11.5.12 References

- Wilcox-O'Hearn, Zooko & Warner, Brian. "Tahoe: the least-authority filesystem." *Proceedings of the 4th ACM International Workshop on Storage Security and Survivability (StorageSS '08)*, October 2008, pp. 21-26. doi:10.1145/1456469.1456474. Also: IACR Cryptology ePrint Archive, Paper 2012/524.
- Tahoe-LAFS project documentation: https://tahoe-lafs.readthedocs.io/
- Tahoe-LAFS source repository: https://github.com/tahoe-lafs/tahoe-lafs
- Tahoe-LAFS capability specification: https://tahoe-lafs.org/trac/tahoe-lafs/wiki/Capabilities
- Tahoe-LAFS file encoding specification: https://tahoe-lafs.readthedocs.io/en/latest/specifications/file-encoding.html
- Tahoe-LAFS mutable file specification: https://tahoe-lafs.readthedocs.io/en/latest/specifications/mutable.html
- Tahoe-LAFS architecture overview: https://tahoe-lafs.readthedocs.io/en/latest/architecture.html
- Tahoe-LAFS convergence secret: https://tahoe-lafs.readthedocs.io/en/latest/convergence-secret.html
- Wilcox-O'Hearn, Zooko. "Names: Distributed, Secure, Human-Readable: Choose Two." 2001. (Origin of Zooko's triangle.)
- Miller, Mark S. "Robust Composition: Towards a Unified Approach to Access Control and Concurrency Control." PhD thesis, Johns Hopkins University, 2006. (Foundation of the object-capability model.)
- Dennis, Jack B. & Van Horn, Earl C. "Programming Semantics for Multiprogrammed Computations." *Communications of the ACM* 9(3), March 1966, pp. 143-155. (Origin of capability-based security.)
- UCAN specification: https://github.com/ucan-wg/spec

---

## 11.6 Cjdns / Yggdrasil

Cjdns (2011, Caleb James DeLisle) and Yggdrasil (2018, Neil Alexander and Arceliar) are encrypted IPv6 overlay networks that share a foundational premise with SCP: your cryptographic key IS your identity. Both are network-layer protocols that replace traditional address allocation with public-key-derived addressing, creating mesh networks where every packet is encrypted and every address is self-certifying.

### 11.6.1 Self-Certifying Addressing

The core parallel with SCP is self-certifying identity. In cjdns, a node's IPv6 address is the first 16 bytes of SHA-512(SHA-512(Curve25519 public key)), constrained to the `fc00::/8` prefix (addresses whose double-hash does not start with `0xFC` are discarded, requiring brute-force key generation). In Yggdrasil, addresses fall within the `0200::/7` range (deprecated IETF space repurposed to avoid collisions with `fc00::/7`), derived from SHA-512 of the node's Ed25519 public key with a compression scheme that encodes the number of leading one-bits as a prefix byte.

SCP's `did:dht:<z-base-32-Ed25519-public-key>` follows the same principle: the identifier IS the public key, no registration authority required, collision-resistant by construction. The difference is representational — cjdns and Yggdrasil encode keys as IPv6 addresses (lossy truncation), SCP encodes them as DID strings (lossless z-base-32). All three systems achieve the same property: verifying an identity requires only the identifier itself.

### 11.6.2 Routing

Cjdns and Yggdrasil take different approaches to the same problem — routing without centralized infrastructure:

- **Cjdns** uses Kademlia-inspired DHT routing with an XOR distance metric over the address space. The switch layer routes packets via path-based labels (bit sequences consumed hop-by-hop) rather than destination addresses, enabling core routers to forward packets without routing table lookups. Routes are discovered through iterative "find node" queries and composed via label splicing.
- **Yggdrasil** builds a cryptographically secured spanning tree (root = lowest Ed25519 public key), then uses tree distance as a metric for greedy routing. Packets are forwarded over whichever link brings them closer to the destination's tree coordinates, with off-tree shortcuts used opportunistically. This reduces to spanning tree routing in the worst case but performs efficiently on internet-like topologies.

SCP takes neither approach. Routing is entirely delegated to transport adapters (§10.5) — the protocol has no routing layer of its own. An SCP relay could run over a cjdns or Yggdrasil mesh (using the overlay's globally-routable IPv6 addresses), over the public internet, over BLE, or over any combination. This is a deliberate architectural choice: SCP is application-layer infrastructure, not network-layer infrastructure.

### 11.6.3 Encryption

Both networks encrypt all traffic by default — a property SCP shares:

- **Cjdns:** CryptoAuth protocol (Curve25519 key exchange, XSalsa20-Poly1305 authenticated encryption). Per-hop encryption means intermediate nodes cannot read transit traffic. End-to-end encryption between source and destination.
- **Yggdrasil:** End-to-end encryption using NaCl/box primitives (Curve25519 + XSalsa20 + Poly1305), with session key ratcheting for forward secrecy (v0.4+). Ed25519 signatures secure the spanning tree construction.

SCP encrypts at a different layer: MLS (RFC 9420) provides group encryption at the message level, with the sender-side key layer (§9.16) adding per-sender confidentiality control. Transport-level encryption is the adapter's concern — an adapter running over cjdns/Yggdrasil would inherit their network-layer encryption as an additional layer, but SCP's security model does not depend on it.

### 11.6.4 What SCP Borrows

**Self-certifying addresses as identity primitive.** The proof that public-key-derived addressing works at scale — cjdns's Hyperboria network operated with hundreds of globally-distributed nodes — validated the core assumption behind `did:dht`. If a mesh network can function with no address authority, a protocol can function with no identity authority.

**Encrypted-by-default as the only mode.** Both cjdns and Yggdrasil made unencrypted communication impossible by construction. SCP follows the same principle with MLS: there is no plaintext mode. Encryption is not a feature to enable; it is the only way the protocol operates.

### 11.6.5 Where SCP Diverges

Cjdns and Yggdrasil are network-layer protocols — they replace IP routing with encrypted mesh routing. SCP is application-layer protocol infrastructure that runs on top of any transport, including theirs. The divergences follow from this:

- **No governance.** Neither protocol has any concept of permissions, roles, capabilities, or governed interaction spaces. Any node that knows a destination address can send to it. SCP: contexts enforce membership, governance engines enforce rules, UCANs enforce capabilities (§5, §7).
- **No group encryption.** Both provide point-to-point encrypted channels. Neither has multi-party group encryption with forward secrecy and post-compromise security. SCP: MLS groups are the fundamental communication primitive.
- **Identity is an address, not a document.** A cjdns/Yggdrasil address proves key ownership. An SCP DID resolves to a document with multiple verification methods, attestation chains, service endpoints, and agent delegation — identity as a rich, evolving structure rather than a static hash (§3, §11.2).
- **Transport substrate, not alternative.** SCP lists Yggdrasil/cjdns as Tier 2 transport adapters (§10.5). Their globally-routable encrypted IPv6 space could serve as infrastructure-independent transport for SCP relays — especially valuable in scenarios where conventional internet routing is unreliable or surveilled. The adapter mapping is thin: SCP relay connections use the mesh network's IPv6 addresses instead of public IPs, inheriting NAT traversal and encryption for free.

---

## 11.7 What No Existing Standard Covers

No existing protocol combines all of the following. This is SCP's novel contribution:

- **Identity:** Dual-layer DID resolution with protocol-level self-healing; multi-key architecture with pre-rotation commitments and optional agent signing keys; shared-DID human-agent pairs with structural action provenance (`signing_key_id` distinguishes human vs agent signatures without trusting self-reported claims)
- **Capability:** UCAN-based authorization with delegation chains, time-bounding, and revocation; context-level economic governance with spending UCANs
- **Encryption:** MLS group keys as the membership mechanism (encryption-as-access-control); sender-side key layers enabling per-sender blocking without group disruption
- **Governance:** 30 governance action types with pluggable engines; context-bound participation rules enforced cryptographically
- **Provenance:** Protocol-level bridge connectors with provenance-tracked content attribution; non-fungible cross-platform identity attestations with shadow identity claiming
- **Agents:** First-class protocol participants with formalized trust semantics; one-agent-per-person-per-context constraints; context-bound agents that cannot cross at the protocol level; trust as identity + capability pairs applied to autonomous agents

All of this framed as infrastructure for generated and ephemeral apps — not a closed application, but an open protocol layer.
