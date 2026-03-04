# SCP White Paper — Detailed Outline

**Type:** Academic design paper (Tor / Kleppmann model, not crypto white paper)
**Target audience:** Protocol designers, security researchers, agent ecosystem builders, standards body reviewers, potential adopters evaluating the architecture
**Tone:** Technical, precise, honest about tradeoffs, no marketing language
**Length estimate:** 25-40 pages

---

## Front Matter

### Title
"Social Context Protocol: Cryptographic Infrastructure for Agent-Native Social Computing"
(or similar — the title signals: this is infrastructure, it's cryptographic, it's for agents)

### Authors
Alec Marcus, Limn

### Abstract (~250 words)
- The problem: software generation is becoming trivial; connectivity is not. As agents generate ephemeral, personal software, every app becomes an island. Identity, trust, and relationships are locked inside platforms or absent entirely.
- The contribution: SCP — an open protocol providing cryptographic identity (DID), governed interaction spaces (contexts), end-to-end encryption as access control (MLS), capability-based authorization (UCAN), and verifiable provenance. All interaction occurs within contexts — bounded, encrypted, governed spaces where membership is enforced by cryptography, not infrastructure.
- Key properties: no operator dependency, transport independence, human accountability for all agents, context isolation as the security boundary.
- Status: complete specification, reference implementation in Rust with bindings for Python, Swift, Kotlin, TypeScript, WASM.

---

## 1. Introduction (~3 pages)

### 1.1 The Ephemeral Software Thesis
- Software generation is becoming trivial (frontier models, agent builders, one-shot app generation)
- The trajectory: personal, disposable, generated-on-demand software
- What remains hard: identity that belongs to you, trust that's earned and portable, relationships that survive when the software that introduced them is gone
- Building software is becoming trivial; connecting it is not. When every person and every agent generates their own software, all of those apps are islands.
- SCP provides the durable connective tissue: identity, trust, relationships, transport, persistence

### 1.2 Agents as Primary Actors
- The agent ecosystem today: MCP (model ↔ local tools), WebMCP (model ↔ web tools), UCP (agent ↔ commerce)
- What's missing: the social layer. How agents relate to each other. Identity, trust, governed interaction, accountability.
- The distinction: tool-level protocols vs. social-level protocols. SCP fills the social gap.
- Agents are the primary actors, not humans operating through clients. The protocol is designed for a world where autonomous software is the norm.

### 1.3 Design Principles (the nine tenets)
State each principle and its load-bearing consequence:
1. **Provenance everywhere.** All non-private data carries verifiable origin metadata. Absence of provenance is itself a signal.
2. **Human accountability.** Every agent traces to a human DID through attestation chains.
3. **Context isolation.** All interaction within bounded contexts. Cross-context data flow is explicit and governed. The security boundary.
4. **Encryption-as-access-control.** MLS group keys enforce membership. Relays are untrusted dumb pipes.
5. **Legibility before opt-in.** Context parameters visible before joining. Informed consent is mechanical.
6. **Protocol requires no operator.** Must work if Limn disappears.
7. **Transport independence.** No structural coupling to any single transport.
8. **Agents are participants, not enforcers.** Same rules as any human-bound participant. Enforcement is cryptographic.
9. **Trust is contextual.** Function of identity, capability, context, and behavior — not binary.

### 1.4 Contribution and Scope
- What SCP provides (protocol specification, reference SDK, conformance infrastructure)
- What SCP does not provide (content moderation policy, specific transport implementation, app-level logic)
- What is novel (context isolation model, agent accountability architecture, provenance as core principle, encryption-as-access-control)
- Paper organization roadmap

---

## 2. Problem Analysis (~3 pages)

### 2.1 The Connectivity Crisis
- Generated apps have no shared identity layer (each app creates its own accounts)
- No portable trust (reputation locked inside platforms)
- No governed interaction across independently generated software
- No verifiable provenance for agent-produced content
- Current solutions (ActivityPub, Matrix, AT Protocol, Nostr) each solve pieces but none address the agent-native case

### 2.2 The Agent Trust Problem
- Agents acting autonomously need accountability mechanisms
- Unaccountable agents enable: fleet attacks, agent slot rental, cross-context infection, identity manufacturing
- Existing agent protocols (MCP, A2A, ACP) are tool-level — they define how agents use things, not how agents relate to each other or how trust is evaluated
- No existing protocol constrains agents to one-per-person-per-context, binds agents to human accountability chains, or provides protocol-level behavioral records

### 2.3 Why Not Existing Protocols?
Honest assessment of each, what they get right and what they miss:

| Protocol | Strengths | Gaps for agent-native social computing |
|----------|-----------|---------------------------------------|
| **Matrix** | Federated rooms, E2E encryption (Megolm), open spec | Identity tied to homeserver (@user:server), no agent accountability model, no capability-based authorization, room state bloat, no context isolation |
| **AT Protocol** | Self-sovereign identity (did:plc), portable data, open spec | Relay dependency (BGS), no E2E encryption, no governed interaction spaces, no agent-specific primitives |
| **Nostr** | Simple relay model, censorship resistance | No group encryption, no governance, no capability model, no accountability, key management burden on users |
| **ActivityPub** | Wide adoption (Mastodon, etc.) | Server-centric identity, no encryption, no capability model, no agent support |
| **Signal Protocol** | Best-in-class encryption (Double Ratchet) | Centralized identity, closed ecosystem, no programmable governance, no agent model |
| **Holepunch (Hypercore)** | Zero-server P2P, append-only logs, production-proven (Keet) | Transport-coupled (Hyperswarm), no governance, no capabilities, single-writer logs, group encryption undocumented, no context isolation |
| **MCP** | Agent ↔ tool protocol, wide adoption | Tool-level only, no social layer, no identity, no trust, no encryption, no contexts |

### 2.4 Requirements
Distill the requirements that emerge from the problem analysis:
1. Self-sovereign identity independent of any infrastructure operator
2. End-to-end encryption as the access control mechanism (not a feature toggle)
3. Bounded, governed interaction spaces with cryptographic isolation
4. Human accountability for all autonomous agents
5. Verifiable provenance on all non-private data
6. Capability-based authorization (not role-based alone)
7. Transport independence (no coupling to a specific delivery mechanism)
8. Verifiable behavioral records that replace trust with evidence
9. Protocol-level discovery without centralized registries
10. Offline-first design (devices are nodes, not thin clients)

---

## 3. Architecture Overview (~4 pages)

### 3.1 Protocol Boundary
- Diagram: local agent orchestration (unconstrained) above the boundary; contexts, identity, encryption below
- Everything that touches the network is protocol-governed
- Above the boundary: agent internals, local coordination, app logic
- The boundary is sharp: agents are separate instances per context at the protocol level, even if the same human coordinates them locally

### 3.2 Layer Model
```
Applications (generated, traditional, or agent scripts)
    |
App Interface Layer (self-documenting, machine-readable API contracts)
    |
Social Context Layer ← the novel contribution
    |
Identity + Capabilities (DID, UCAN)
    |
Crypto Layer (MLS, sender keys, Merkle trees)
    |
Transport + Data (relay-based, transport-agnostic)
```

### 3.3 Context Interior
- What a context contains: capability ceiling, roles, tools, governance model, event log, membership, TTL, memory scope, metadata
- Contexts are spaces, not actors — passive infrastructure that holds rules, keys, and audit trails
- Two context modes: Encrypted (MLS-backed) and Broadcast (per-author keys, no MLS, unlimited subscriber scale)
- Context creation is a runtime operation (~200ms), not infrastructure provisioning

### 3.4 Message Lifecycle
- Outer envelope: routing_id (per-context pseudonym), recipient_hint, TTL, encrypted blob
- Inner envelope: context_id, sender_did, epoch, generation, sequence, timestamp, payload_hash, payload (bucket-padded), provenance, signature
- Security checkpoints at each layer (MLS encryption, sender-side key encryption, signature verification, capability validation, Merkle log append)
- MessagePack serialization for deterministic encoding

### 3.5 Trust Model
- Four layers from hardest to softest: protocol enforcement (zero-trust, UCAN validation on every action) → behavioral validation (Merkle-backed evidence) → attestation authenticity (signature verification) → trust evaluation (agent-level judgment)
- Critical property: trust surface shrinks over time as behavioral evidence accumulates
- Trust = f(identity, capability, context, metadata) — not binary

---

## 4. Identity (~3 pages)

### 4.1 DID-Based Identity
- Cryptographic root: every identity is a keypair, expressed as a DID
- DID method: did:dht primary (self-certifying via BEP44), did:web fallback only
- Self-certification: the DID string encodes the public key; DID documents are signed and verifiable without trusting any intermediary
- Key custody: invisible to users — Secure Enclave, Android Keystore, passkeys, hardware keys, self-managed
- Recovery: social and device mechanisms, no seed phrases

### 4.2 Three-Key Architecture (Novel Contribution)
- Standard DID methods use a single keypair for everything (signing, authenticating, operating). SCP separates concerns:
  - **Identity Key:** Ed25519 key encoded in DID string. Long-lived root of trust. Used for BEP44 signing only — never for day-to-day operations.
  - **Active Signing Key:** Operational key for protocol actions. Rotatable without changing DID. Published in DID document, authorized by Identity Key.
  - **Pre-Rotation Key:** Hash commitment published before needed. Enables safe rotation even under compromise — attacker who steals Active Signing Key cannot forge rotation (needs pre-rotation private key, generated separately).
- Security improvement over single-key DID methods: recovery from key compromise without DID change
- Compare to did:key (no rotation), did:web (server-dependent rotation), did:plc (PLC directory-mediated rotation)

### 4.3 Dual-Layer Resolution (Novel Contribution)
- Layer 1: SCP relay-based (deterministic routing_id = SHA-256("scp:did:" || did_string), uses existing relay PUBLISH/QUERY)
- Layer 2: Mainline DHT via BEP44 (fallback, immediate availability, 20+ year operational history)
- Parallel query, first-valid-wins, BEP44 sequence numbers for freshness
- Anti-segmentation invariant: publishing to both layers is MUST, not SHOULD
- Protocol-level self-healing: when layers disagree on freshness (different sequence numbers), resolver re-publishes the fresher document to the stale layer. Network converges without central coordination.
- Security: attacker must suppress on ALL relays AND ALL DHT nodes — strictly harder than either layer alone
- did:dht governance risk (TBD shutdown Nov 2024, transfer to DIF) — SCP is insulated because the identity layer is fully self-owned, depending only on BEP44 (BitTorrent standard) and Ed25519 (universal primitive), not on did:dht software or governance

### 4.3 The Human-Agent Pair
- Fundamental unit: human + agent. Neither is complete without the other.
- One agent per person per context. Social constraint, not computational.
- Agent capability metadata: self-attested and challenge-verified capabilities
- Agents are protocol consumers, not enforcers. Enforcement is cryptographic.

### 4.4 Identity Attestations
- Cryptographic binding of external platform identities to DIDs
- Properties: non-fungible, user-initiated, independently verifiable, revocable, discoverable
- Enables: social graph import, shadow identity claiming (bridge connectors), cross-platform reputation continuity

### 4.5 Identity Private State
- Encrypted single-owner data: block/mute lists, graph visibility policies, petnames, agent config defaults
- Same storage infrastructure as context state (encrypted blobs on relays), single-owner degenerate case
- Append-only event log, multi-device sync, commutative operations for conflict-free convergence

---

## 5. Contexts (~4 pages)

### 5.1 Context as Security Boundary
- All interaction within contexts. No off-context communication at the protocol level.
- Context isolation is absolute: agents in different contexts are separate instances, even for the same human
- Two explicit, opt-in mechanisms for cross-context data flow: tool interfaces (asymmetric, §5.5) and multi-parent child contexts (symmetric)
- Context = cryptographic entity with its own key material, event log, governance, membership, ceiling

### 5.2 Capability Ceiling and Governance
- Ceiling declared at creation: maximum set of things that can happen in this space
- Ceiling policy: immutable (default) or governed (changeable through governance model)
- Governance models: single-admin, multi-sig, consensus, voting — pluggable interface
- Governance actions: 24 types covering membership, roles, capabilities, content access, economic policy
- All governance actions logged in verifiable event log

### 5.3 Roles, Tools, and Membership
- Roles with specific permission sets within the ceiling, visible before opt-in
- Tools: stateless functions with schema, implementation hash, test vectors, operator DID, optional cost metadata
- One agent per human per context; membership transparent
- Broadcast contexts: two-tier (bounded authors + unbounded subscribers)

### 5.4 Context Templates and Creation
- Well-known templates for common patterns (bilateral ephemeral/persistent, group, broadcast, discovery, tool interface)
- Creation is a runtime operation (~200ms wall clock with network)
- Standing bilateral contexts for persistent low-overhead communication
- Auto-accept policies for autonomous SDK-level join decisions

### 5.5 Cross-Context Communication
- Tool interfaces: asymmetric, structured, request/response across context boundaries
  - Both contexts opt in (bidirectional governance consent)
  - Shared-member bridging (primary transport) or multi-parent child contexts (fallback)
  - Schema constraints (no unbounded string-only interfaces)
  - Chain depth limit (protocol default: 3 hops)
  - Stateful sessions (optional, per-caller cap, optional TTL)
- Multi-parent child contexts: symmetric collaboration
  - Ceiling = intersection of parent ceilings (no capability escalation)
  - Members must be in at least one parent (continuous eligibility)
  - Children cannot outlive parents (lifecycle coupling)
  - Independent MLS groups with their own keys

### 5.6 Context Nesting
- Parent-child relationships for sub-spaces and governed bridges
- Max nesting depth (3)
- Parent governance over child: configurable (can_close_child, can_evict_members, can_restrict_ceiling)
- On-sever policies: evict unique members, cascade close, preserve membership

---

## 6. Encryption and Key Management (~4 pages)

### 6.1 MLS Foundation
- Message Layer Security (RFC 9420) as the group encryption primitive for Encrypted contexts
- One MLS group per context; epoch ratcheting provides forward secrecy and post-compromise security
- MLS public messages for proposals/commits; private messages for content
- OpenMLS as reference implementation (Rust, maintained)

### 6.2 Sender-Side Keys
- Per-sender AES-256-GCM key layer, separate from MLS group membership
- Pull-based distribution: SenderKeyEpochAdvance (O(1) broadcast) + SenderKeyRequest/Response (O(1) each)
- HPKE-wrapped keys with domain separation ("scp-sender-key-v1")
- 30-second grace period for key transition
- Purpose: enables per-sender blocking without MLS group disruption

### 6.3 Content Access Control
- Three-tier blocking: DID-to-DID in-context, DID-to-DID global, governance-gated
- Three enforcement layers: key distribution denial, SDK-mandated state destruction, access key wrapping (AES-256-KW per RFC 3394)
- Per-member AES-256 access keys; CEK wrapping with AES-256-KW
- Forward-only restoration: unblock grants future access, historical gap permanent
- Membership/access decoupling: full, read-only, presence-only, non-member

### 6.4 Broadcast Mode Encryption
- Per-author AES-256-GCM broadcast keys (no MLS)
- Mandatory subscriber registration (DID-authenticated)
- Subscriber key request/response for current epoch key
- BlockSubscriber rotates key excluding blocked subscriber (same pull model)

### 6.5 Metadata Privacy
- Layered architecture: minimal outer envelopes with per-context pseudonyms, fixed bucket padding, persistent connections, cover traffic, relay set partitioning
- Routing ID derivation: HKDF from identity key material (encrypted contexts), SHA-256(context_id) (broadcast), SHA-256("scp:did:" || did) (DID resolution)
- Relay threat model: what relays can and cannot learn (see §9.9.1 of spec)

---

## 7. Capabilities and Authorization (~2 pages)

### 7.1 UCAN-Based Capability Tokens
- Fine-grained, per-agent, per-context, per-capability
- Verifiable delegation chains (trace any token back to root authority)
- Independently revocable (per-capability, per-agent, per-context)
- Nonce-based replay prevention
- AND-composition with spending UCANs for paid actions

### 7.2 Capability Categories
- Standard categories: messaging, toolInvocation, media (voice/video/screenShare), bridging, toolInterface, childContext
- Ceiling enforcement: every action checked against context ceiling + role permissions + token validity
- Economic policy orthogonal to ceiling (ceiling governs what CAN happen; economic policy governs what it COSTS)

---

## 8. Provenance (~2 pages)

### 8.1 Automatic Provenance Attachment
- Protocol attaches provenance at cross-context boundaries (tool interfaces, structured cross-context references)
- DataProvenance record: source_context, source_type, counterparties, purpose, discovery_method, age, memory_scope, chain_depth, chain_path
- Not manual tagging — automatic, protocol-level

### 8.2 Quality Tiers
- Four tiers: NoProvenance < EphemeralKnownParties < SummaryVerified < PersistentVerifiable
- Absence is a signal, not an error
- Quality degrades with indirection (chain depth) — this is the protocol working as designed

### 8.3 Chain Depth Enforcement
- Protocol-enforced maximum (default: 3 hops)
- Prevents accountability laundering through cascading context traversals
- Chain path recorded for full traversal audit

---

## 9. Verifiable Event Logs (~2 pages)

### 9.1 Merkle Tree Structure
- Append-only Merkle tree per context
- Events: messages, tool invocations, membership changes, role assignments, governance actions
- Events signed by acting agent and sequenced
- Proof-of-inclusion and proof-of-absence for arbitrary claims about history

### 9.2 Behavioral Records
- Derived from event logs, not stored centrally
- Facts: participation history, tool invocations by type/frequency, governance actions, role progression, attestation history
- Each fact verifiable against the relevant context's Merkle root
- Replace endorsements as primary trust input for established identities

### 9.3 Relay Consistency Protocol
- Members detect relays showing different event histories to different clients
- Per-sender sequence numbers detect message suppression
- Clients maintain per-relay reliability scores

---

## 10. Transport Architecture (~2 pages)

### 10.1 Relay Model
- Protocol-unaware: relays store and forward encrypted blobs
- Substitutable: switching relays requires no identity or context migration
- Untrusted for content: cannot read, inspect, or interpret payloads
- DID-based identity means relay failure ≠ identity loss (key structural difference from Matrix homeservers)

### 10.2 Native Relay Protocol
- Four operations: PUBLISH, SUBSCRIBE, QUERY, DELETE
- WebSocket + MessagePack binary frames
- Blob-addressed by routing_id with TTL enforcement
- Bridge secret for relay-to-node callback

### 10.3 Transport Abstraction
- Adapter trait: defined interface contract between protocol logic and delivery infrastructure
- Reference binding: SCP native relay (WebSocket + MessagePack)
- Additional bindings possible: Nostr, Matrix, libp2p, etc.
- Transport independence: the protocol works over any transport that can deliver encrypted blobs

### 10.4 Deployment Spectrum
- Phone (full participant when online, needs relay for offline delivery)
- Laptop daemon (more capable, can be always-on, can serve as personal relay)
- Agent workstation (dedicated always-on hardware, natural SCP node)
- Personal server/NAS (power user, persistent relay)
- Managed infrastructure (convenience, high availability)
- All of the above simultaneously

---

## 11. Discovery and Addressing (~2 pages)

### 11.1 Protocol-Level Discovery
- Discovery contexts: standard SCP contexts with open join policies and standardized discovery tools
- Two-tier model: MLS members (bounded writers) + DID-authenticated readers (unbounded)
- Bootstrap: SDK ships with default discovery context IDs (like DNS root servers)
- Anyone can run a discovery context — no central authority

### 11.2 Human-Readable Addressing
- Five resolution mechanisms with graceful degradation:
  1. Petnames (local, zero infrastructure, always work)
  2. Discovery context handles (SCP-native, DNS-free, community-governed)
  3. Attestation-backed handles (external platform identity → DID reverse lookup)
  4. Domain handles (.well-known/scp extension, web compatibility)
  5. Unscoped resolution (try all layers)
- Address format: `<local-part>@<scope>`
- Trust level attached to every resolution result

---

## 12. Economic Governance (~1 page)

### 12.1 Cost Model
- Per-action cost policies set by context governance
- Payment adapter abstraction (Stripe, Lightning, etc.)
- Spending UCANs: capability tokens authorizing expenditure up to a ceiling
- Payment receipt verification via Merkle inclusion proof
- Velocity-based cost escalation (SenderVelocity) as economic rate limiting

---

## 13. Sync and Offline Strategy (~1 page)

### 13.1 Three-Tier Offline Model
- Tier 1 (< 4 hours): relay buffering + sequential MLS catch-up, lossless
- Tier 2 (4 hours — 7 days): state snapshot + delta sync, may lose access to skipped-epoch messages
- Tier 3 (> 7 days): forced re-join via MLS group state reset, identity preserved
- Client-side outbound queue with deferred MLS encryption
- Six-phase reconnection protocol

---

## 14. Platform Bridge Connectors (~1 page)

### 14.1 Bridge Architecture
- Four modes: Relay (mirror external → SCP), Puppet (act as user on external), API (structured endpoints), Cooperative (bidirectional with external platform support)
- Shadow identities for external participants (claimable via attestation)
- Provenance trust hierarchy: native SCP > cooperative bridge > relay bridge > unverified
- Bridge connectors are protocol participants with the same accountability as any agent

---

## 15. Security Analysis (~4 pages)

### 15.1 Threat Model
- Enumerate threat actors: malicious relay operators, compromised agents, sybil attackers, insider threats, context spoofers, governance captors
- What the protocol defends against vs. what it makes legible (some attacks are detectable and attributable but not preventable)

### 15.2 Security Properties
- Confidentiality: MLS + sender-side keys. Relays are untrusted dumb pipes.
- Integrity: Merkle event logs, BEP44 signature verification, UCAN chain validation.
- Accountability: every action traces to a human DID.
- Forward secrecy and post-compromise security: MLS epoch ratcheting.
- Context isolation: no transitive exposure.

### 15.3 Sybil Resistance
- Composable trust signals: social attestation, device attestation, participation history, behavioral records, economic activity, endorsements
- Depth of investment as sybil discriminator (sybil accounts are broad but shallow)
- No single signal is required; contexts set thresholds

### 15.4 Metadata Privacy
- Honest assessment of what's possible and what's hard
- Layered protections: pseudonymous routing IDs, bucket padding, persistent connections, cover traffic, relay set partitioning
- Traffic analysis remains the strongest residual attack surface — acknowledged, not hand-waved

### 15.5 Key Security Invariants
- Every action traces to a human
- Agents are context-bound (no cross-context protocol awareness)
- Tools are stateless and non-agentic
- One agent per person per context
- Role assignment is non-negotiable
- Context metadata is transparent before opt-in

---

## 16. Comparison with Related Work (~2 pages)

Structured comparison on the axes that matter:

| Property | SCP | Matrix | AT Protocol | Nostr | Signal | Holepunch | MCP |
|----------|-----|--------|-------------|-------|--------|-----------|-----|
| Identity model | Self-sovereign DID (three-key) | Server-bound | did:plc (PLC directory) | Keypair | Phone number | Keypair (per-feed) | N/A |
| Identity resolution | Dual-layer (relay + DHT) | Homeserver | PLC directory | Relay + NIP-05 | Phone registry | DHT | N/A |
| Encryption | MLS + sender keys | Megolm | None (relay sees all) | NIP-44 (pairwise) | Double Ratchet | Noise XX (transport) | N/A |
| Group encryption | MLS (RFC 9420) | Megolm (custom) | None | None | Signal Groups | Undocumented | N/A |
| Agent accountability | Protocol-level | None | None | None | None | None | None |
| Context isolation | Cryptographic | Room-based (no isolation) | None | None | N/A | None | N/A |
| Capability model | UCAN (fine-grained) | Power levels | None | None | None | None | Tool permissions |
| Provenance | Protocol-level | None | Repo signatures | Event signatures | None | Signature-level | None |
| Transport | Abstracted (17 adapters) | Federation | BGS relay | Simple relay | Centralized | Coupled (Hyperswarm) | stdio/SSE |
| Multi-writer | Native (MLS groups) | Native (room state) | Native (repo) | Native (relays) | Native | Autobase (app-layer) | N/A |
| Governance | Pluggable per-context | Power levels | Moderation lists | NIP-based | Centralized | None | N/A |
| Self-hosting | Device-as-node | Homeserver required | PDS | Relay | Not possible | Full P2P | Local |
| Offline support | Three-tier model | Server handles | Relay handles | Best-effort | Server handles | Peer-dependent | N/A |

### 16.1 What SCP Borrows
- MLS from IETF (encryption), DID from W3C (identity), UCAN from community working group (capabilities), Merkle trees from distributed systems, relay model informed by Nostr, federation lessons from Matrix
- did:dht self-certification property (BEP44 signature verification against key encoded in DID string) — the genuinely good idea from did:dht, preserved intact
- Append-only authenticated log as tamper-evident history primitive (well-understood in distributed systems, exemplified by Hypercore)
- DHT-integrated hole punching as reachability primitive (Hyperswarm demonstrated this at production scale)
- Zero-server P2P as existence proof (Keet — proof it works, even if the protocol is undocumented)

### 16.2 What Is Novel
- Context isolation as the security boundary for agent interaction
- Human accountability chains for all autonomous agents
- Provenance as a core protocol principle (not a feature)
- Encryption-as-access-control (MLS keys = membership = access)
- Sender-side key layer enabling per-sender blocking without MLS disruption
- Agent capability metadata with challenge-verified capabilities
- Context-level economic governance
- Verifiable behavioral records replacing reputation scores
- **Dual-layer DID resolution with protocol-level self-healing** — no existing DID method provides multi-backend resolution with automatic convergence
- **Three-key identity architecture** (identity/signing/pre-rotation) — safe rotation under compromise without changing DID, a stronger model than any existing DID method
- **Append-only logs embedded in governance and encryption context** — Hypercore proves the data structure; SCP embeds it in MLS groups, UCAN authorization, and context governance

### 16.3 Detailed Comparison: Holepunch / Hypercore

Hypercore is the closest structural parallel to SCP's event logs: both are append-only authenticated logs with Merkle trees. The comparison illuminates what SCP adds beyond the data structure:

| Dimension | Hypercore | SCP Event Logs |
|-----------|-----------|----------------|
| Structure | Append-only log, Merkle tree | Append-only log, Merkle tree |
| Hash | BLAKE2b-256 | SHA-256 |
| Tree shape | Flat in-order (Ogham tree) | Standard binary Merkle |
| Signing | Ed25519, single writer per log | Ed25519, multi-writer per context (MLS-authenticated) |
| Multi-writer | Autobase (app-layer DAG linearization) | Native via MLS group membership |
| Encryption | None at log level; transport-level only | MLS + sender-side AES-256-GCM at log level |
| Governance | None | Full: 24 action types, pluggable engines |
| Transport | Coupled (Hyperswarm) | Abstracted (adapter trait, 17 adapters) |
| Offline | Requires intermittent peer connections | Store-and-forward relay with three-tier degradation |

Key points for the paper:
- Hypercore is a data structure; SCP event logs are a data structure embedded in a governance and encryption context
- Autobase composes multi-writer from single-writer; SCP starts multi-writer (MLS groups) and single-writer is the degenerate case
- Keet's group encryption is undocumented — cannot be independently implemented, formally analyzed, or interoperated with. SCP's encryption is fully specified. Publishing the protocol is the differentiator.
- Hyperswarm could theoretically be one SCP transport adapter, but SCP's design never depends on it

### 16.4 Detailed Comparison: did:dht and SCP's DID Layer

SCP builds on did:dht's self-certification property but extends it significantly:

| Property | did:dht | SCP Identity |
|----------|---------|--------------|
| Self-certification | Yes (BEP44) | Yes (same BEP44) |
| Resolution backends | Mainline DHT only | Dual-layer: SCP relays + Mainline DHT |
| Key architecture | Single Ed25519 keypair | Three keys: identity / signing / pre-rotation |
| Rotation safety | No pre-rotation commitment | Pre-rotation key hash published in advance |
| Document serialization | DNS packet encoding (TXT/SRV) | JSON-LD (relay layer), DNS packets (DHT layer) |
| Payload limit | 1000 bytes (BEP44) | 256KB (relay layer), 1000 bytes (DHT fallback) |
| Self-healing | None | Protocol-level: fresher doc re-published to stale layer |
| TTL management | ~2 hour republish | Dual-cycle: 2h (DHT) + 6d (relay, 7d TTL) |
| Software dependency | did:dht libraries + DHT libraries | Self-owned (scp-identity crate), depends only on BEP44 + Ed25519 |
| Governance risk | TBD shut down 2024, transferred to DIF | Insulated — no dependency on did:dht software or governance |

Key points for the paper:
- SCP takes the genuinely good idea (self-certification) and removes the single-point-of-failure resolution path
- The three-key architecture provides a recovery path from compromise that no existing DID method offers without changing the identifier itself
- SCP identities are simultaneously did:dht-compatible (resolvable by standard did:dht resolvers via DHT) and more resilient (dual-layer with self-healing)
- The identity layer is a novel contribution to the DID space, not just an application of an existing method

---

## 17. Implementation Status (~1 page)

### 17.1 Reference Implementation
- Rust core (scp-core, scp-transport, scp-platform, scp-node)
- Bindings: Python (PyO3), Swift (UniFFI), Kotlin (UniFFI), TypeScript (wasm-bindgen/napi-rs), WASM
- Current status: phases 1-3 complete, phase 4+ in progress

### 17.2 Conformance Infrastructure
- Conformance macros: storage, transport, blob store, key custody, attestation, push, payment adapter
- Integration test suites: phase 1 (crypto), phase 2 (context lifecycle), phase 5 (advanced features)
- Distributed invariant tests: Merkle consistency, delivery guarantees, suppression detection, pseudonym unlinkability, block enforcement

### 17.3 Licensing
- Protocol specification: CC-BY 4.0 (freely implementable)
- Client SDK: Apache 2.0 (zero adoption friction)
- Application node: AGPL v3 (infrastructure protection)

---

## 18. Discussion and Future Work (~2 pages)

### 18.1 Open Questions
- Sybil resistance earned capacity algorithm (P0, security-critical)
- Protocol versioning and capability negotiation (concrete mechanism needed)
- Formal security analysis of the composed cryptographic construction (MLS + sender keys + UCAN + Merkle)
- Multi-device sync edge cases (concurrent key rotation across devices)

### 18.2 Standardization Path
- Current: self-published specification under CC-BY 4.0
- Near-term: formal protocol specification document (implementation-agnostic), language-neutral test vectors, protocol evolution mechanism
- Long-term: IETF submission for core cryptographic subsystems, similar to AT Protocol's trajectory

### 18.3 Limitations
- Metadata privacy against traffic analysis (honest about residual attack surface)
- Sybil resistance without invasive verification (unsolved in decentralized systems)
- MLS scaling limits for large Encrypted contexts (Broadcast mode addresses this for one-to-many)
- Governance model complexity (pluggable but each model has its own tradeoffs)

---

## 19. Conclusion (~0.5 pages)
- Restate the thesis: SCP provides the durable connective tissue for a world of ephemeral, generated software
- Restate the key contribution: context isolation as security boundary, encryption as access control, provenance as core principle, human accountability for agents
- The protocol exists. The specification is complete. Independent implementations are possible.

---

## Appendices

### A. Protocol Constants
- Maximum nesting depth (3)
- Default chain depth limit (3)
- Bucket padding sizes
- Default TTLs
- Rate limit defaults
- Key derivation domain separators

### B. Wire Format Summary
- Outer envelope fields and types
- Inner envelope fields and types
- Broadcast envelope fields and types
- Relay protocol message types (PUBLISH, SUBSCRIBE, QUERY, DELETE)
- Key exchange message types (SenderKeyEpochAdvance, SenderKeyRequest, SenderKeyResponse)

### C. Cryptographic Primitives
- MLS (RFC 9420): group key management
- AES-256-GCM: sender-side encryption, broadcast encryption, content access keys
- AES-256-KW (RFC 3394): content key wrapping
- HPKE: key distribution
- HKDF: key derivation (routing IDs, domain separation)
- Ed25519: signatures (DID documents, inner envelopes, BEP44)
- SHA-256: hashes (Merkle trees, content addressing, routing ID derivation)
- MessagePack: deterministic serialization

### D. Glossary
- Context, DID, UCAN, MLS, Epoch, Sender Key, Routing ID, Capability Ceiling, Governance Model, Event Log, Provenance, Attestation, Discovery Context, etc.

---

## Figures (suggested)

1. Protocol boundary diagram (local orchestration above, protocol-governed below)
2. Context interior (roles, tools, membership, metadata, event log)
3. Cross-context communication (tool interfaces, multi-parent child contexts)
4. Trust evaluation layer model (4 layers, enforcement → trust)
5. Message lifecycle with security checkpoints
6. Dual-layer DID resolution (relay + DHT in parallel, with self-healing)
7. Three-key identity architecture (identity key → active signing key → pre-rotation commitment)
8. Three-tier blocking architecture (enforcement layers × blocking tiers)
9. Deployment spectrum (phone → agent workstation → managed infra)
10. Sender-side key distribution (pull model, SenderKeyEpochAdvance/Request/Response)
11. Provenance chain with depth tracking
12. Hypercore vs SCP event log structural comparison (data structure vs governed encrypted log)

---

## Notes on Positioning

**This paper is NOT:**
- A crypto white paper (no tokenomics, no investment thesis)
- A marketing document (no hype, no growth projections)
- An SDK guide (no code examples beyond pseudocode)

**This paper IS:**
- An academic-style design document (like Tor's USENIX paper or Kleppmann's AT Protocol paper)
- Honest about tradeoffs and limitations
- Precise enough for security researchers to evaluate
- Complete enough for protocol designers to assess
- A companion to (not substitute for) the normative protocol specification

**The paper should be submittable to:** USENIX Security, IEEE S&P, ACM CCS, or equivalent venue. Not required to submit, but the quality bar should match.

---

## Open Questions for the White Paper Itself

1. **Authorship.** Solo (Alec) or with co-authors? If academic submission is a goal, academic co-authors with security/cryptography expertise would strengthen the paper.
2. **Peer review.** Should the paper be submitted for academic peer review before public release? Academic credibility is the strongest validation signal for a crypto-heavy protocol.
3. **Timing.** Before or after the standalone protocol specification is extracted? The paper can reference the spec. Publishing both simultaneously would be ideal.
4. **Formal proofs.** Should the security analysis section include or reference formal proofs of key properties? This is standard for crypto protocol papers and would significantly strengthen the contribution.
