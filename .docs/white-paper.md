# Shared Context Protocol: Cryptographic Infrastructure for Agent-Native Social Computing

**Alec Marcus**
Limn (limn.works)

March 2026 — Preprint v0.1

---

## Abstract

As software generation becomes trivial — frontier language models producing applications from prompts, agent frameworks composing workflows from modular tools — the bottleneck shifts from building software to connecting it. Identity, trust, and relationships remain siloed inside each application, and every independently generated application is an island.

This paper presents the Shared Context Protocol (SCP), an open protocol providing cryptographic identity (DID [10]), governed interaction spaces (contexts), end-to-end encryption as access control (MLS [2]), capability-based authorization (UCAN [12]), and verifiable provenance. All interaction occurs within contexts — bounded, encrypted, governed spaces where membership is enforced by cryptography. The protocol is designed for a world where autonomous agents are the primary actors: every agent traces to a human identity through cryptographic binding, agents are isolated per context at the protocol level, and behavioral records replace reputation scores as the primary trust input.

Key properties: no operator dependency (the protocol functions if its creators disappear), transport independence (17 adapter specifications across 3 tiers), human accountability for all autonomous agents, and context isolation as the security boundary. The protocol is designed to be complementary to existing platforms and tool-level protocols — bridge connectors, transport adapters, and identity attestations enable harmonious interoperation with established distribution networks. The reference implementation is in Rust with bindings for Python, Swift, Kotlin, TypeScript, and WebAssembly. The specification is published under CC-BY 4.0; the SDK is published under Apache 2.0.

---

## 1. Introduction

### 1.1 The Ephemeral Software Thesis

Software generation is undergoing a phase transition. Frontier language models produce functional applications from brief natural-language specifications. Agent frameworks compose sophisticated workflows from modular tools. The cost of producing a working application — from concept to execution — is collapsing toward zero.

The trajectory is clear: personal, disposable, generated-on-demand software. A user describes what they need; an agent builds it. The application serves its purpose and may never be used again. Software ceases to be a durable artifact and becomes an ephemeral means to an end.

What this trajectory does *not* make trivial is the connective tissue between applications: identity that belongs to the user rather than to the application that created it, trust that is earned through interaction and portable across contexts, relationships that persist when the software that introduced them is discarded, and transport that works regardless of which application generated the endpoints. Building software is becoming trivial; connecting it is not. When every person and every agent generates their own software, all of those applications are islands.

SCP provides the durable infrastructure layer beneath ephemeral software: identity, trust, relationships, transport, persistence, and provenance.

If the protocol provides what every connected application needs — identity, encryption, trust, relationships, persistence — and if agents are building most connected applications, then agents have reason to adopt SCP over reimplementing these concerns from scratch for every application.

### 1.2 Agents as Primary Actors

The agent ecosystem is developing rapidly at the tool level. The Model Context Protocol (MCP) [20] defines how language models connect to local tools via JSON-RPC. Emerging protocols like WebMCP extend this to browser-accessible tools, and the Universal Commerce Protocol (UCP) addresses agent-to-commerce interactions. These protocols solve important problems: how agents *use* things.

What is missing is the social layer — how agents *relate to each other*. No existing protocol addresses the questions that arise when autonomous agents interact: How does an agent prove its identity? How is trust established between agents that have never met? How are interactions governed when both participants are software? Who is accountable when an autonomous agent misbehaves? How does an agent in one context safely share information with an agent in another?

SCP fills this gap. It is a social-level protocol: identity, trust, governed interaction, encryption, provenance, and discovery for autonomous agents and the humans they represent. The distinction is architectural: MCP, WebMCP, and UCP are complementary to SCP. An SCP agent can expose itself as an MCP server locally. An SCP agent can consume WebMCP-exposed tools in the browser. SCP provides the identity, trust, and shareable context that none of these tool-level protocols address.

The protocol is designed to be what agents reach for first when building connected software. This is by design: the SDK is organized around approximately ten conceptual operations — identity, context lifecycle, messaging, tools, trust, capabilities, provenance, discovery, transport, and sync — with cryptographic complexity handled invisibly, context creation is a runtime operation (estimated ~5–15 ms local, ~200 ms with network), and the protocol handles everything an agent needs — identity, encryption, trust, relationships, transport — invisibly. An agent that needs to build a collaborative application imports one SDK and calls `Context.create()`. The alternative is reimplementing identity, key management, encryption, authorization, and transport from scratch for every application. The protocol minimizes the barrier to correct-by-construction connected software.

SCP is designed to harmonize with existing platforms rather than replace them. Bridge connectors translate between SCP and external platforms at the protocol level, transport adapters run on any delivery infrastructure, and identity attestations link SCP identities to existing platform accounts. The protocol complements existing distribution networks by providing the open social infrastructure they do not.

### 1.3 Design Principles

SCP is governed by nine design principles. Each has a load-bearing consequence for the protocol's architecture.

1. **Provenance everywhere.** All non-private data carries verifiable origin metadata. The absence of provenance is itself a signal. *Consequence:* the protocol attaches provenance automatically at context boundary crossings (Section 8).

2. **Human accountability.** Every agent traces to a human DID through cryptographic binding. *Consequence:* there are no anonymous autonomous actors; misbehavior is always attributable (Section 4.4).

3. **Context isolation.** All interaction occurs within bounded contexts. Cross-context data flow is explicit and governed. *Consequence:* agents in different contexts are separate instances at the protocol level, even when operated by the same human (Section 5).

4. **Encryption-as-access-control.** MLS group keys enforce membership. No relay or intermediary enforces access — the cryptography does. *Consequence:* relays are untrusted; a compromised relay cannot breach confidentiality (Section 6).

5. **Legibility before opt-in.** Every context's parameters are visible before joining. *Consequence:* informed consent is mechanical, not social.

6. **No operator dependency.** The protocol must function if its creators disappear. *Consequence:* identity is self-sovereign, relays are substitutable, and all cryptographic operations are local.

7. **Transport independence.** No structural coupling to any single transport. *Consequence:* the protocol defines a transport adapter trait with 17 adapter specifications (Section 9).

8. **Agents are participants, not enforcers.** Enforcement is cryptographic, not behavioral. *Consequence:* no security property depends on client cooperation.

9. **Trust is contextual.** Trust is a function of identity, capability, context, and behavioral evidence — not a binary flag. *Consequence:* contexts set their own thresholds from composable trust signals (Section 11.3).

### 1.4 Contribution and Scope

SCP provides a complete protocol specification, a reference SDK (Rust core with language bindings), and conformance infrastructure. It does not provide content moderation policy, specific transport implementations beyond the reference relay, or application-level logic. The protocol is the infrastructure; applications are built on top.

The novel contributions are: context isolation as the security boundary for agent interaction; human accountability chains for all autonomous agents via shared-DID binding; provenance as a core protocol principle with automatic attachment; encryption-as-access-control where MLS keys constitute membership; a multi-key identity architecture with pre-rotation commitments and agent signing keys; dual-layer DID resolution with protocol-level self-healing; and verifiable behavioral records that replace reputation scores with evidence.

The remainder of this paper is organized as follows: Section 2 analyzes the problem space. Section 3 presents the architecture overview. Sections 4–8 detail the core protocol components: identity, contexts, encryption, capabilities, and provenance. Section 9 covers transport. Section 10 addresses discovery. Section 11 provides the security analysis. Section 12 compares with related work. Section 13 discusses implementation status and Section 14 addresses limitations and future work.

---

## 2. Problem Analysis

### 2.1 The Connectivity Crisis

Generated applications have no shared identity layer. Each application creates its own accounts, its own user model, its own notion of "who you are." When two independently generated applications need to know that the same person is using both, there is no mechanism — the identity is locked inside each application.

Trust is not portable. Reputation earned in one application does not transfer to another. A user who has been a reliable participant in one context for months starts as a stranger in the next. The behavioral evidence that could inform trust evaluation is siloed.

Relationships are trapped inside their clients. When an application is replaced — and generated applications are replaced constantly — every connection, conversation, and shared context it mediated is lost. There is no mechanism for a relationship to survive the death of the software that introduced it, or to move between devices, or to function across two applications that have never heard of each other. In a world where agents run on personal hardware — laptops, workstations, phones — connections and their governing state need to be portable across machines, trivial to create and destroy on demand, and independent of any particular client. The infrastructure should impose no more overhead than the agent runtime itself.

There is no governed interaction across independently generated software. When an agent in one application needs to interact with an agent in another, there is no protocol-level mechanism for establishing the rules of engagement — what capabilities are permitted, who is authorized to do what, what happens when rules are violated.

Provenance is absent. When an agent produces content, there is no standard mechanism for verifying where that content came from, who produced it, or through how many intermediaries it has passed. In a world of generated content, the absence of provenance is a structural vulnerability.

### 2.2 The Agent Trust Problem

Autonomous agents create a category of trust problem that existing protocols do not address, because existing protocols were designed for a world where the human is the actor. When agents act autonomously, identity manufacturing is computationally trivial (creating an agent costs nothing), accountability chains are absent (who is responsible when an agent misbehaves?), and the attack surface scales differently (one operator can deploy agents across many contexts, each appearing independent).

The tool-level protocols that exist today — MCP, WebMCP, UCP — define how agents use things. They do not address how agents relate to each other, how trust is established between agents that have never met, or how interactions are governed when both participants are software. No existing protocol constrains agents to one per person per context, binds agents to human accountability chains through cryptographic identity binding, or provides behavioral records as the basis for trust evaluation.

### 2.3 Why Not Existing Protocols?

Existing protocols address pieces of this problem. Matrix [15] provides federated messaging with room-based grouping but ties identity to homeservers (`@user:server`), uses custom group encryption (Megolm) rather than a standardized construction, and has no agent accountability model. AT Protocol [16] provides self-sovereign identity (`did:plc`) with portable data stores but offers no end-to-end encryption and no governance model. Nostr [17] provides censorship-resistant relaying with keypair identity but lacks group encryption, capability-based authorization, and any mechanism for agent accountability. Signal [13] provides strong pairwise encryption (Double Ratchet) but is centralized, phone-number-bound, and has no programmable governance or provenance. Holepunch/Hypercore [18][19] provides zero-server P2P with authenticated append-only logs but lacks encryption at the log level, governance, and multi-writer is an application-layer concern. MCP [20] defines agent-tool integration but provides no identity, trust, or social infrastructure.

None addresses the agent-native case comprehensively: no existing protocol provides cryptographic context isolation, human accountability chains for autonomous agents, capability-based authorization with delegation, and verifiable provenance as a unified architecture. Section 12 provides a detailed structured comparison.

### 2.4 Requirements

The problems above directly motivate the design principles in Section 1.3: identity that is self-sovereign, encryption that constitutes access control, contexts that provide cryptographic isolation, provenance that is automatic, and so on. Beyond those principles, the problem analysis yields three additional concrete requirements:

- **Capability-based authorization with fine-grained delegation.** Agents need to act on behalf of humans with precisely scoped permissions — not all-or-nothing access.
- **Protocol-level discovery without centralized registries.** Contexts and participants must be findable without a directory service that becomes a single point of failure or control.
- **Online-first, deployable from anywhere.** The protocol is designed for always-connected agents, not for offline tolerance as a primary concern. But it must be deployable wherever an agent runtime runs — a laptop, a phone, an always-on workstation — with infrastructure overhead no greater than the agent runtime itself. No server requirement, no cloud dependency, no provisioning step. Contexts and their state are portable across machines and trivial to create and destroy on demand.

---

## 3. Architecture Overview

### 3.1 Protocol Boundary

SCP defines a sharp protocol boundary. Everything that touches the network is protocol-governed: contexts, identity state, encrypted envelopes, relay interactions, and attestations. Above the boundary, local agent orchestration and client behavior are unconstrained — agents share state freely on the user's machine, coordinate across contexts locally, and execute arbitrary logic.

The boundary is architecturally significant because it defines where isolation applies. A human may have agents in many contexts. Locally, those agents coordinate freely. At the protocol level, each agent is a separate instance confined to its context. Cross-context data flow occurs only through governed protocol mechanisms.

```
┌──────────────────────────────────────────────────────────┐
│                   LOCAL (User's Machine)                  │
│                                                          │
│  Agent·A    Agent·B    Agent·C    Agent·D                │
│     │          │          │          │                    │
│  ┌──┴──────────┴──────────┴──────────┴──┐                │
│  │     Local Agent Orchestration         │                │
│  │     (Unconstrained by protocol)       │                │
│  └──┬──────────┬──────────┬──────────┬──┘                │
└─────┼──────────┼──────────┼──────────┼───────────────────┘
══════╪══════════╪══════════╪══════════╪══════ PROTOCOL BOUNDARY
      │          │          │          │
  Context A  Context B  Context C  Context D
```

### 3.2 Layer Model

The protocol is organized in five layers:

**Applications.** Generated, traditional, or agent scripts — thick or thin clients. The protocol does not constrain application architecture.

**App Interface Layer.** Self-documenting, machine-readable capability declarations. Applications declare what protocol capabilities they need; the protocol validates and provides them. This layer makes generated applications safe — the attack surface of a poorly generated client is bounded by its capability declaration, not by its code quality.

**Social Context Layer.** Contexts, agents, tools, roles, governance, trust semantics. Agent-native social infrastructure.

**Identity and Capabilities.** DID-based identity with multi-key verification methods. UCAN-based capability tokens with verifiable delegation chains. Invisible key custody.

**Crypto and Transport.** MLS group encryption, sender-side keys, Merkle event logs. Relay-based store-and-forward delivery with transport abstraction.

### 3.3 Context as the Fundamental Unit

All interaction occurs within contexts — cryptographic entities with their own key material, event log, governance model, membership roster, and capability ceiling. Contexts are passive infrastructure: they hold the rules, the keys, and the audit trail. Agents do the acting within them.

Contexts operate in one of two modes, set at creation and immutable:

- **Encrypted mode.** One MLS group per context. Sender-side keys. MLS provides forward secrecy and post-compromise security; the sender-side key layer provides selective confidentiality. The default for interactive contexts.
- **Broadcast mode.** Per-author encryption keys, no MLS. Mandatory subscriber registration. Designed for one-to-many patterns at unbounded scale.

Context creation is a runtime operation — estimated at 5–15 ms of local computation and 200 ms with network round-trips — not infrastructure provisioning. Contexts are created, used, and destroyed during normal application operation with the fluidity of opening a connection.

### 3.4 Message Lifecycle

Messages in SCP pass through a layered security pipeline:

1. **Construction.** The sender constructs an inner envelope containing: context ID, sender DID, signing key identifier (`#active` or `#agent`), MLS epoch, generation, sequence number, timestamp, payload hash (SHA-256 of the original plaintext, before padding), padded payload, and provenance metadata. The signature commits to the payload hash, not the padded payload, preventing padding manipulation.

2. **Signing.** The inner envelope is signed with the sender's verification method key. The signature preimage includes the signing key identifier, binding the message to a specific key.

3. **Sender-side encryption.** The signed inner envelope is encrypted with the sender's AES-256-GCM sender key.

4. **MLS encryption.** The sender-encrypted payload is encrypted with the MLS group key for the current epoch.

5. **Outer envelope.** The MLS-encrypted blob is wrapped in a minimal outer envelope containing only a routing ID (a per-context pseudonym), recipient hint, TTL, and the encrypted blob. Outer envelopes are padded to fixed bucket sizes.

6. **Transport.** The outer envelope is delivered via the transport layer (relay store-and-forward or direct connection).

At each layer, specific security properties are enforced: MLS provides forward secrecy and post-compromise security; sender-side keys enable per-sender blocking without group disruption; signatures provide non-repudiation and signing key attribution; Merkle log append provides tamper-evident history.

### 3.5 Trust Model

SCP's trust model has four layers, ordered from hardest (pure validation) to softest (pure judgment):

**Layer 1: Protocol Enforcement.** Zero-trust, mandatory. Every action requires a valid UCAN capability token. Signature chains verified. Capability ceilings enforced. Role permissions checked. No action proceeds on reputation or identity alone.

**Layer 2: Behavioral Validation.** Automated, objective. Verifiable event logs provide Merkle-backed evidence of participation history. Participation records — tool invocations by type and frequency, governance actions taken and received, role progression, attestation history — are derived from event logs, not stored centrally. Challenge-response verification tests agent capabilities objectively.

**Layer 3: Attestation Authenticity.** Automated signature verification. Attestations are verified as *real* (genuinely signed by the claimed issuer) but not as *true* (the content may be inaccurate). OAuth proofs, DNS records, and content hashes are verified where objectively checkable.

**Layer 4: Trust Evaluation.** Agent-level judgment for what cannot be mechanized: new identities with no history, non-testable capabilities, novel situations. This layer exists because some evaluation inherently requires judgment.

The design goal: **the trust surface shrinks over time.** New identities are trust-heavy — no participation history, dependent on endorsements. As they participate, behavioral validation accumulates. Trust becomes supplementary, then marginal. The protocol is designed to make this convergence structural, though formal proof of monotonic decrease remains future work (Section 14.1).

### 3.6 Verifiable Event Logs

Every context maintains an append-only Merkle tree recording all protocol events: messages, tool invocations, membership changes, role assignments, governance proposals and votes, economic transactions, and media session lifecycle. The tree uses SHA-256 hashing following the Certificate Transparency structure (RFC 6962 [24]) with domain separation prefixes for leaf and internal nodes.

Events are signed by the acting participant and sequenced. The Merkle root after each append constitutes a commitment to the entire event history — any tampering with a historical event changes the root, detectable by any member who has observed a prior root. Proof-of-inclusion (a specific event occurred) and proof-of-consistency (the log has not been retroactively modified) are both efficiently verifiable with O(log n) hash computations.

Behavioral records are derived from event logs, not stored centrally. A participant's track record — tool invocations by type and frequency, governance actions taken and received, role progression across contexts, attestation history — is computed by any verifier who has access to the relevant context logs. Each behavioral fact is independently verifiable against the source context's Merkle root. This makes behavioral evidence tamper-evident: a participant cannot alter their history without invalidating the Merkle commitments that other members have already observed.

The event log is the foundation for trust Layer 2 (Section 3.5): automated behavioral validation. As a participant accumulates history across contexts, the evidence base for trust evaluation grows, and the reliance on Layer 4 judgment diminishes. The protocol makes this convergence structural — not dependent on any reputation service or centralized database, but on the mathematical properties of the Merkle construction.

Relay consistency is enforced through two mechanisms. First, per-sender sequence numbers in inner envelopes allow recipients to detect message suppression — a gap in sequence indicates a missing message. Second, members can compare Merkle roots received from different relay connections, detecting equivocation (a relay showing different event histories to different clients). Clients maintain per-relay reliability scores that inform relay selection.

---

## 4. Identity

### 4.1 DID-Based Identity

Every identity in SCP is rooted in a cryptographic keypair expressed as a Decentralized Identifier (DID). The DID is the canonical identifier at the protocol level.

SCP uses `did:dht` as the primary DID method. did:dht stores DID documents as BEP44 [11] signed mutable items on BitTorrent's Mainline DHT — a network of millions of nodes with over 20 years of operational history. The DID string (`did:dht:<z-base-32-encoded-Ed25519-public-key>`) encodes the public key directly, making it self-certifying: DID documents are verifiable against the DID without trusting any intermediary. MITM on resolution is cryptographically impossible given the correct DID.

Key custody is invisible to users. Keys are stored in platform-specific secure storage — iOS Keychain (Secure Enclave supports only P-256, not the Ed25519 required by SCP), Android Keystore, passkey infrastructure — without the user managing keys directly. Recovery uses social and device mechanisms rather than seed phrases: trusted device recovery, social recovery via trusted contacts, and platform-backed recovery as the practical safety net for new users.

### 4.2 Multi-Key Verification Method Architecture

Standard DID methods use a single keypair for everything — signing, authenticating, operating. This conflates distinct security concerns. SCP defines multiple verification methods per DID document, each serving a specific purpose:

**Identity Key (`#0`).** The Ed25519 key encoded in the DID string. Hardware-backed. The long-lived root of trust. Used exclusively for BEP44 signing and DID document modifications. Never used for day-to-day protocol operations.

**Human Signing Key (`#active`).** The human's operational key for protocol actions — signing inner envelopes, MLS operations, capability delegation. Hardware-backed. Rotatable without changing the DID. Published in the DID document, authorized by the Identity Key.

**Pre-Rotation Key.** A commitment to the next Human Signing Key. The hash of the pre-rotation key is published in the DID document before it is needed. This enables safe key rotation even under compromise: the pre-rotation commitment was made before the compromise occurred, so an attacker who steals the current signing key cannot forge a valid rotation — they would need the pre-rotation private key, which was generated separately.

**Agent Signing Key (`#agent`).** Optional. A software-held Ed25519 key for the human's autonomous agent. Published in the DID document, authorized by the human via a self-delegation UCAN (`iss == aud`, same DID, with `fct.scp_key_scope: "#agent"`). Independently rotatable and revocable without affecting the human's keys.

All protocol messages carry a `signing_key_id` field identifying which verification method produced the signature. This provides structural action provenance: verifiers can determine whether a human or agent performed any action by inspecting the signing key identifier, without trusting self-reported claims.

The pre-rotation mechanism draws on KERI's [25] key pre-commitment approach, applied here within the multi-key DID architecture.

This separation provides three security improvements over single-key DID methods: (a) recovery from key compromise without changing the DID, via the pre-rotation commitment; (b) custody separation between human and agent operations; (c) graduated permission categories based on signing key type.

### 4.3 Dual-Layer Resolution

did:dht specifies a single resolution path: Mainline DHT. SCP adds a second: SCP relays. DID documents are published to SCP relays as standard blobs, addressed by a deterministic routing ID: `SHA-256("scp:did:" || did_string)`. Both layers are queried in parallel; the first valid response wins. BEP44 sequence numbers resolve conflicts when both layers return valid documents.

The dual-layer architecture provides:

- **Anti-segmentation.** Publishing to both layers is mandatory (MUST, not SHOULD). The SDK enforces this by default to prevent the network from fragmenting into two resolution namespaces.
- **Protocol-level self-healing.** When layers return documents with different sequence numbers, the resolver accepts the fresher one and may re-publish it to the stale layer. The network converges on the freshest document without central coordination.
- **Suppression resistance.** An attacker must suppress a DID document on all of an identity's relays *and* all reachable DHT nodes to prevent resolution — a strictly harder attack than suppressing on either layer alone.

The dual-cycle republishing schedule accommodates the layers' different characteristics: 2-hour cycles for DHT (matching BEP44 expiry), 6-day cycles for relays (within the 7-day blob TTL with a 1-day safety margin).

### 4.4 The Human-Agent Pair

The fundamental unit of participation in SCP is the human-agent pair. Human and agent share a single DID. Neither is a separate identity — they are one participant with two signing keys.

This binding is the foundation of the entire trust model, and the reasoning behind it is worth tracing. The alternative — giving agents their own identities, separate from humans — was considered and rejected because it severs the accountability chain. An agent with its own DID can be created trivially, operated anonymously, and discarded without consequence. The cost of manufacturing agent identities is computational, not social. Without human binding, nothing distinguishes a legitimate agent from a manufactured sybil except behavioral history that is itself cheap to fabricate. The shared-DID model makes agent creation socially expensive: every agent identity is a human identity, and human identities carry the accumulated weight of attestations, participation history, and social relationships.

The design process that led to this model went further. The original architecture included a second class of actors — unbound "anonymous agents" that could exist within contexts without human binding. Through iterative analysis, these were constrained: first to be context-scoped (no protocol existence outside their context), then to be non-initiating (they could respond but not act), then to be stateless (no persistent memory). At each step, the constraints removed attack surface — emergence within contexts, internal swarms, resource exhaustion through feedback loops. The final realization was that a stateless, non-initiating, context-scoped entity with no identity is not an agent at all. It is a function. The "anonymous agent" concept was eliminated entirely and replaced with tools — stateless functions that agents invoke. This simplification reduced the actor model to two clean concepts: agents (always accountable, always human-bound) and tools (stateless, non-agentic functions).

**One agent per human per context.** This is structurally enforced — a DID document contains exactly one `#agent` verification method; verifiers reject documents with multiples. The constraint is on presence, not capability: the agent can be arbitrarily capable internally, but there is one seat per person per table.

The one-per-context constraint emerged from analysis of what happens without it. Even moderate-sized agent fleets create problems that compound with scale: force multiplication (one operator's agents outnumbering other participants), agent slot rental (a trusted identity lending its agent seats to untrusted operators), coordination risks (multiple agents from one identity amplifying each other), and ambiguity in trust evaluation (which of a person's agents do you evaluate?). One-per-context is the simplest constraint that eliminates all of these while preserving the human's power — their single agent can be arbitrarily capable, and they can participate in as many contexts as they have earned capacity for.

Three permission categories govern what each key can do:

- **Category A** (`#0` only): DID document modifications, key rotation. Human-exclusive, never delegable to the agent key. Structurally impossible for agents because the identity key is hardware-backed.
- **Category B** (user-configurable): Operational actions — messaging, tool invocation, governance votes. SDK defaults to human-only; the human can delegate subsets to the agent via UCAN.
- **Category C** (context-configurable): Context governance can further restrict which key types are accepted for specific actions.

The enforcement stack has five layers: custody separation (hardware vs. software keys) → SDK defaults (conservative) → verifier validation (signing key checks) → custody attestation (DID document service entry declaring key custody model) → behavioral signals (participation history by key type).

### 4.5 Identity Attestations

Users can publish cryptographic attestations binding external platform identities to their DID. An attestation says: "The human behind `did:dht:z6Mk...` is the same human behind `@alice` on X." The attestation is non-transferable (bound to a specific DID and external identity), user-initiated, independently verifiable, revocable, and discoverable.

Attestations enable social graph import (resolving existing contacts who have joined SCP), shadow identity claiming (merging bridge-created representations with native identities), and cross-platform reputation continuity.

---

## 5. Contexts

### 5.1 Context as Security Boundary

All interaction occurs within contexts. There is no off-context communication at the protocol level. A context is a cryptographic entity with its own MLS group key material, append-only Merkle event log, governance model, membership roster, and capability ceiling.

Context isolation is absolute. Agents in different contexts are separate instances at the protocol level, even for the same human. Two explicit, opt-in mechanisms exist for crossing context boundaries:

- **Tool interfaces** (asymmetric): One context's tool is invoked by another context's agent. Both contexts' governance mediates — the source context approves the outbound call, the target context approves the inbound call. Data flows through declared schemas with provenance attached. Each call is logged in both event logs.
- **Multi-parent child contexts** (symmetric): A shared space governed by multiple parent contexts. The child's capability ceiling is the intersection of its parents' ceilings (no capability escalation). Members must be in at least one parent. Children cannot outlive parents.

Context nesting supports hierarchies up to three levels deep. Parent contexts exercise configurable governance over their children: the parent may close a child context, evict members from it, or restrict its capability ceiling, depending on the governance configuration declared at child creation. When a parent-child relationship is severed — through parent closure, member eviction from the parent, or governance action — the protocol enforces on-sever policies: evicting members unique to the severed relationship, cascading closure, or preserving membership at the child's discretion. Lifecycle coupling is strict: a child context cannot outlive its parent, and a child's capability ceiling is always bounded by the intersection of its parents' ceilings, preventing capability escalation through nesting.

### 5.2 Capability Ceiling and Governance

Every context declares a capability ceiling at creation: the maximum set of things that can happen within the space. The ceiling is immutable by default; governed ceiling changes are possible under contexts that specify a governed ceiling policy.

Governance models are pluggable. SCP defines a governance interface that accommodates single-admin, multi-signature, consensus, and voting models. 30 governance action types cover membership, roles, capabilities, content access, economic policy, and context lifecycle. All governance actions are logged in the verifiable event log.

### 5.3 Roles, Tools, and Membership

Contexts define roles with specific permission sets within the ceiling, visible before opt-in. Tools are stateless functions registered with schemas, implementation hashes, test vectors, and operator DIDs. Membership is transparent — the roster is protocol state.

The protocol defines nine well-known context templates — bilateral-ephemeral, bilateral-persistent, coordination, group-discussion, public-broadcast, gated-broadcast, tool-interface, paid-service, and paid-broadcast — each specifying default parameters for common interaction patterns. Templates are protocol-level identifiers, not SDK convenience: a joining agent can evaluate a context's template to make informed accept/reject decisions without parsing the full parameter set. This is architecturally significant for autonomous agents, which create and destroy contexts at high frequency — template-based creation reduces both the computational cost of context evaluation and the risk of misconfiguration.

Broadcast contexts support two-tier membership: bounded MLS-group members (writers) and unbounded DID-authenticated subscribers (readers). This enables feed and broadcast patterns at scale without MLS group size limitations.

### 5.4 Cross-Context Communication

A natural question is why the protocol does not provide a direct agent-to-agent communication primitive — a way for agents in different contexts to message each other freely. This was considered extensively and rejected, because it fundamentally undermines context isolation, which is the protocol's security boundary.

The reasoning is specific. Forbidding agents from communicating across contexts does not hinder their functionality. The human coordinates across their own contexts locally — on their machine, agents share state freely, plan across contexts, and carry intelligence between interactions. The protocol governs what touches the network; it does not constrain what happens on the user's device. Network-level agent-to-agent communication would automate something that does not need network-level automation, while opening massive attack surface: runaway agent connections, cross-context infection via agent memory, fleet coordination at the protocol level, and metastatic growth patterns through agent connection graphs.

Empirical support for this threat model came from Moltbook, an agent social network that launched in early 2026 and reportedly reached approximately 1.5 million agents within weeks [1]. Moltbook provided exactly the unbounded agent communication that SCP deliberately avoids, and the failure modes were immediate and severe: an estimated 2.6% of posts contained prompt injection payloads that persisted in agent memory and activated in later interactions (time-shifted attacks), agents leaked credentials through unstructured communication, fleet attacks and astroturfing were trivial with zero identity binding, and there was no mechanism for trust evaluation or accountability. While Moltbook's failures resulted from the combination of absent identity binding, encryption, governance, and capability controls — not solely from ungoverned communication — the case illustrates the compound risks that arise when autonomous agents interact without protocol-level constraints.

The protocol considered adding governed agent-to-agent communication (a propose/accept flow for bilateral context creation) and ultimately removed it. The reasoning: cross-context tool calls with stateful sessions handle all inter-agent interaction where both parties share a context, which covers the governed case. The remaining unique capability — reaching agents you share no context with — is precisely the attack surface that isolation was designed to eliminate. Any mechanism that allows agents to bypass context isolation, even a "governed" one with rate limits and trust evaluation, reintroduces the problems isolation solves. Agents that need new relationships require their humans to arrange them — through human facilitation in shared contexts, not through network-level agent initiative.

What the protocol provides instead is structured tool interfaces. Tool interfaces carry provenance (source context, counterparties, chain depth), are rate-limited, and enforce a chain depth limit — the protocol maximum of 5 hops (context-configurable default: 3) bounds amplification and prevents accountability laundering through cascading context traversals. Both contexts mediate every interaction: the source context's governance approves the outbound call, the target context's governance approves the inbound call, and both log the interaction with full provenance. Tool schemas must satisfy a structural specificity floor: no unbounded string-only interfaces, a minimum of two distinct fields. This raises the cost of using tool interfaces as covert messaging channels.

Stateful tool sessions support multi-step workflows (negotiation, iterative refinement) within the governed framework, with per-caller session caps to prevent resource exhaustion.

---

## 6. Encryption and Key Management

### 6.1 MLS Foundation

Encrypted contexts use Message Layer Security (MLS) [2] as the group encryption primitive. One MLS group per context. Epoch ratcheting provides forward secrecy (past messages unrecoverable after key advancement) and post-compromise security (the group recovers security properties after a compromised member is removed or updates their keys).

MLS was chosen over alternatives for three reasons: it is an IETF standard with formal security analysis, it has multiple independent implementations, and its tree-based key management provides O(log n) complexity for group operations — essential for contexts with more than a few members.

### 6.2 Sender-Side Key Layer

Separate from MLS, each member maintains a per-sender AES-256-GCM key. Messages are double-encrypted: first with the sender's personal key, then with the MLS group key. This layer serves a specific purpose: enabling per-sender blocking without MLS group disruption.

When Alice blocks Dave, Alice rotates her sender key and makes it available to all members except Dave via HPKE Base mode [3] key distribution. Dave can still decrypt the MLS layer (he remains a group member) but encounters ciphertext from Alice that he cannot decrypt. The block is unilateral, per-relationship, and does not require group coordination.

Key distribution uses a pull model. `SenderKeyEpochAdvance` messages notify the group of a key rotation (O(1) broadcast). `SenderKeyRequest` and `SenderKeyResponse` messages handle individual key requests (O(1) each). A 30-second grace period accommodates key transition.

The sender-side key layer provides selective confidentiality but intentionally does not provide forward secrecy or post-compromise security — those properties are provided by the MLS layer underneath. Compromising a sender key reveals only the messages encrypted with that key for that sender; the MLS epoch keys remain protected by MLS's tree-based ratcheting.

### 6.3 Content Access Control

Content access operates at three tiers:

- **Tier 1: DID-to-DID in-context.** Alice blocks Dave in a specific context. Dave loses access to Alice's content in that context only. Other members' content remains accessible.
- **Tier 2: DID-to-DID global.** Alice blocks Dave across all shared contexts. Stored in identity private state, propagated to every shared context.
- **Tier 3: Governance-gated.** Context governance revokes a member's access to all content in the context. Requires governance approval per the context's model.

Each tier is enforced through three layers: sender key distribution denial (cryptographic exclusion), SDK-mandated state destruction (cached keys and plaintext destroyed on block), and access key wrapping (per-member AES-256 keys with AES-256-KW wrapping [4]). Restoration is forward-only — unblocking grants future access; historical content from the blocked period remains inaccessible.

### 6.4 Broadcast Mode Encryption

Broadcast contexts use per-author AES-256-GCM keys without MLS. Subscribers register via DID-authenticated requests and receive the current epoch key through a request-response protocol. Blocking a subscriber rotates the author's key, excluding the blocked subscriber via the same pull model. Broadcast mode provides neither forward secrecy nor post-compromise security — key rotation occurs only on block events, not through automatic ratcheting. An attacker who compromises an author's broadcast key can decrypt all content encrypted under that key epoch. This is an explicit trade-off: broadcast mode prioritizes scalability and simplicity over the stronger security properties that MLS provides for encrypted contexts.

### 6.5 Metadata Privacy

SCP provides layered metadata protections: per-context pseudonymous routing IDs, fixed bucket padding, persistent connections, optional cover traffic (specified but not mandated), and relay set partitioning. Section 11.4 provides the full analysis, including the residual traffic analysis attack surface.

---

## 7. Capabilities and Authorization

### 7.1 UCAN-Based Capability Tokens

SCP uses UCAN (User Controlled Authorization Networks) [12] for capability-based authorization. Capability tokens are fine-grained, per-agent, per-context, per-capability. Every protocol action requires a valid token; no action proceeds on identity or reputation alone.

UCANs provide verifiable delegation chains — any token can be traced back to the root authority that granted it. Tokens are independently revocable: a human can revoke one capability from one agent in one context without affecting anything else.

Under the shared-DID model, intra-DID delegation uses self-delegation UCANs where `iss == aud` (same DID) with `fct.scp_key_scope: "#agent"` — the mechanism by which a human authorizes their agent key to perform specific actions.

### 7.2 Capability Categories

Standard capability categories include messaging, tool invocation, media (voice, video, screen sharing), bridging, tool interfaces, and child context creation. Every action is checked against the context's capability ceiling, the agent's role permissions, and the token's validity. Economic policy (what actions cost) is orthogonal to the ceiling (what actions are permitted).

Spending UCANs authorize expenditure up to a ceiling, composing with action UCANs via AND-composition: both the capability to act and the capability to pay are required for paid actions.

### 7.3 Economic Governance

Contexts may attach economic policies to protocol actions. A context's governance sets per-action cost policies through the `SetEconomicPolicy` governance action, defining what actions cost and under what conditions. Economic policy is orthogonal to the capability ceiling — the ceiling governs what is permitted; economic policy governs what it costs.

The protocol defines a payment adapter abstraction — a trait-based interface analogous to the transport adapter (Section 9.3). Payment adapters handle the specifics of payment processing (Stripe, Lightning Network, or other payment rails) while the protocol handles authorization and verification. This separation means the protocol specifies *that* payment occurs and *how much*, without coupling to any specific payment infrastructure.

Spending UCANs authorize expenditure up to a ceiling amount. For paid actions, both an action UCAN (capability to act) and a spending UCAN (capability to pay) are required — AND-composition ensures that neither capability alone is sufficient. Payment receipts are recorded in the context's Merkle event log, making economic history as verifiable as any other protocol event.

Velocity-based cost escalation provides economic rate limiting. The `SenderVelocity` mechanism adjusts costs based on a participant's recent activity rate — normal participation incurs base costs, while burst activity triggers escalating costs. This makes sustained spam or flooding economically prohibitive without restricting legitimate high-frequency interaction during brief periods.

Economic policy can be locked via governance action, making it immutable once the context reaches a stable economic model. Three levels of economic policy coexist: relay-level (infrastructure costs for storage and bandwidth), context-level (interaction costs within the context), and tool-level (per-invocation costs for specific tools).

---

## 8. Provenance

### 8.1 Automatic Provenance Attachment

Provenance is a foundational property of every protocol action. The protocol attaches provenance records automatically when data crosses context boundaries through protocol mechanisms. No manual tagging is required. The provenance data model is designed for the cross-context agent communication case specifically, complementing general-purpose provenance frameworks such as W3C PROV [26].

A provenance record contains: source context, source type (persistent, ephemeral, or summary — reflecting current verifiability), counterparties present in the source interaction, purpose, discovery method, age, memory scope, chain depth (number of context boundaries crossed), chain path (ordered list of intermediary contexts), and optional economic provenance (what the data cost to produce).

### 8.2 Quality Tiers

Provenance quality forms a total ordering across four tiers:

**NoProvenance.** Data introduced without protocol-level origin tracking. The lowest quality signal — not an error, but a signal that the data has no verified origin.

**EphemeralKnownParties.** Source context was ephemeral and keys destroyed, but counterparties are known. Origin is attested but not independently verifiable.

**SummaryVerified.** Source context closed with a verified summary. Partial verifiability.

**PersistentVerifiable.** Source context is persistent and active. Data can be independently verified against the source context's event log. The highest quality tier.

This ordering enables mechanical quality comparison. Agents set their own thresholds for what quality they require; the protocol provides the signal.

### 8.3 Chain Depth Enforcement

Cross-context tool calls carry a chain depth counter, incremented on each hop. The protocol enforces a hard maximum of 5 hops (contexts may configure a lower limit; the recommended default is 3). Data at the effective maximum depth cannot trigger further cross-context calls. This bounds amplification and prevents accountability laundering — data traversing enough contexts that its origin becomes meaningless.

Provenance degradation with chain depth is intentional. Data from many degrees of separation should be less trusted, the same way a message from a stranger warrants more scrutiny than one from a known contact.

### 8.4 Honest Limitations

The protocol can tag data that flows through protocol mechanisms. It cannot tag data that an agent remembers and reproduces above the protocol boundary — from model memory rather than through a protocol mechanism. The protocol is honest about this: provenanced data is the norm; unprovenanced data is the exception that triggers scrutiny. This limitation is inherent to any system where participants have memory above the protocol layer.

---

## 9. Transport Architecture

### 9.1 Relay Model

Devices that are not always online need relays for message delivery. Relays hold encrypted payloads and deliver them when the recipient comes online. They are the availability layer.

SCP relays are:

- **Protocol-unaware.** Relays store and forward encrypted blobs. They do not interpret protocol semantics. This keeps relay implementation simple and prevents relay operators from gaining protocol-level influence.
- **Substitutable.** Switching relays requires no identity change, no context migration, no social disruption. Identity is DID-based, not relay-based. This is the key structural difference from Matrix homeservers, where the homeserver owns the identity (`@user:server`).
- **Untrusted for content.** Relays see encrypted payloads. They cannot read content, inspect membership, or understand context semantics. A compromised relay can delay or drop messages; it cannot compromise confidentiality or integrity.

### 9.2 Native Relay Protocol

The SCP native relay protocol defines nine operations over WebSocket with MessagePack binary frames, organized in three groups: data operations (PUBLISH, SUBSCRIBE, UNSUBSCRIBE, QUERY, DELETE, ACK), keepalive (PING), and bridge operations (BRIDGE_REGISTER, BRIDGE_DATA for relay-to-relay proxying).

### 9.3 Transport Abstraction

The protocol defines a transport adapter trait — a contract between protocol logic and delivery infrastructure. Transport adapters are organized in three tiers:

**Tier 1 (Fully specified):** SCP native relay, QUIC, WebTransport, UDP/DTLS. Wire format mapping, conformance suite, and fallback behavior documented.

**Tier 2 (Mapping defined):** Nostr, Matrix, libp2p, Hyperswarm, WebRTC, MQTT, NATS, Tor, I2P, BLE, Yggdrasil/cjdns, ZeroMQ. Method-level mapping documented per adapter.

**Tier 3 (Named):** SSB. Feasibility confirmed; specification pending.

The protocol functions correctly on any transport that implements the adapter trait. A deployment using only Nostr relays, or only direct WebSocket connections, or only libp2p, is equally valid.

### 9.4 Deployment Spectrum

SCP is online-first — designed for always-connected agents — but deployable from anywhere. In the tradition of local-first software [14], a user's device is a full protocol participant, not a client that talks to a server. The infrastructure overhead of running the protocol is negligible compared to the agent runtime itself.

The deployment spectrum ranges from phones (full participants when online, relays for offline delivery), through laptops (persistent daemons, potential personal relays), agent workstations (dedicated always-on hardware — natural SCP nodes), personal servers (power users), to managed infrastructure (convenience and high availability). All points on the spectrum are simultaneously valid; a user can operate at multiple points at once.

The agent workstation tier is architecturally significant. As autonomous agents become mainstream, users are acquiring dedicated always-on hardware to run them. SCP infrastructure — relays, context hosting, bridge connectors — is marginal additional load on hardware already running continuously, providing a natural deployment point for personal relay processes. This is why "online-first, deployable from anywhere" is the right framing rather than "offline-first": the protocol assumes agents are running and connected, and optimizes for that case. Offline tolerance exists (Section 9.5) but is the exception, not the design center.

### 9.5 Offline Strategy

SCP defines a three-tier offline strategy:

**Tier 1 (< 4 hours):** Relay buffering with sequential MLS catch-up. Lossless recovery. Covers the vast majority of offline events.

**Tier 2 (4 hours – 7 days):** State snapshot comparison with delta sync and selective epoch reconstruction. May lose access to messages encrypted in skipped epochs (forward secrecy preserved).

**Tier 3 (> 7 days):** Forced re-join via MLS group state reset. The offline member is effectively removed and re-added at the current epoch. Identity, role, and event log history are preserved.

The reconnection protocol proceeds in six phases: relay catch-up, MLS epoch reconciliation, event log sync, sender key re-acquisition, MLS update for post-compromise security, and outbound queue drain.

---

## 10. Discovery and Addressing

### 10.1 Protocol-Level Discovery

Discovery contexts are standard SCP contexts with open join policies and standardized tool schemas (`agent_search`, `agent_register`, `agent_deregister`). They use a two-tier membership model: MLS members (bounded writers who process registrations and maintain governance) and DID-authenticated readers (unbounded, query via tool endpoints without MLS membership).

The SDK ships with default discovery context IDs, analogous to DNS root servers. These are starting points, not privileged authorities — anyone can create and operate a discovery context.

### 10.2 Human-Readable Addressing

SCP provides five resolution mechanisms with graceful degradation:

1. **Petnames.** User-assigned local names stored in identity private state. Zero infrastructure, always functional.
2. **Discovery context handles.** SCP-native, DNS-free, community-governed. `alice@cooking-community` resolves through the cooking-community discovery context.
3. **Attestation-backed handles.** External platform identity → DID reverse lookup via attestation indices in discovery contexts.
4. **Domain handles.** `.well-known/scp` extension for web compatibility.
5. **Unscoped resolution.** Try all layers, return merged results with trust levels.

Each mechanism is independently useful. Remove any layer and the rest continue functioning. Every resolution result carries an explicit trust level so agents can evaluate the resolution path, not just the result.

---

## 11. Security Analysis

### 11.1 Threat Model

SCP's threat model enumerates specific adversaries: malicious relay operators (can delay or drop but not read), compromised agents (damage contained to their context), compromised agent keys (mitigated by Category A restrictions and independent rotation), sybil attackers (expensive to sustain depth), insider threats (granular revocation, cross-context containment), context spoofers (contexts are cryptographic entities, not names), and governance captors (transparent event logs, exit as veto).

The protocol distinguishes between what it defends against (confidentiality breach, capability escalation, unauthorized access) and what it makes legible (insider misbehavior, governance disputes, bridge operator malfeasance). Some attacks are detectable and attributable but not preventable at the protocol level — the protocol makes the attacker identifiable and the damage measurable, enabling governance response.

### 11.2 Security Properties

**Confidentiality.** MLS provides group encryption with forward secrecy and post-compromise security. Sender-side keys provide per-sender encryption. Relays see only encrypted blobs (Section 9.1).

**Integrity.** Merkle event logs provide tamper-evident history. BEP44 signatures verify DID documents. UCAN chain validation ensures authorization. Inner envelope signatures provide non-repudiation.

**Accountability.** Every action traces to a human DID via the shared-DID model. The `signing_key_id` field provides unforgeable human-vs-agent attribution on every signed message.

**Forward secrecy and post-compromise security.** MLS epoch ratcheting. The SDK issues MLS Update proposals after reconnection to restore post-compromise security.

**Context isolation.** No transitive exposure. Cross-context data flow only through governed mechanisms with provenance attached.

### 11.3 Sybil Resistance

Provably guaranteeing one identity per human in a decentralized system without invasive verification is an unsolved problem. SCP's approach: make sybil attacks expensive to sustain through composable trust signals where depth of investment in one identity is the discriminator.

Trust signals include social attestations (cryptographic proof of external platform accounts), device attestations (platform-signed hardware proofs), participation history (duration and breadth across contexts), behavioral records (governance actions, tool invocations), economic activity (real spending recorded in payment receipts), and endorsements from established identities.

The key insight: multiple attestations on one DID is a strength signal. A DID with device attestation from an iPhone, social attestations from multiple platforms, months of participation history, and clean behavioral records is highly expensive to forge. Sybil accounts are broad but shallow — they cannot sustain depth across many identities.

Three layers compose: earned capacity (new identities start limited, earning through participation), social and economic cost (real accounts, real money, real endorsements compound the cost of sybil maintenance), and context-level thresholds (contexts set their own admission requirements from available signals).

### 11.4 Metadata Privacy

SCP provides layered metadata protections but is honest about residual attack surface. Per-context pseudonymous routing IDs prevent trivial cross-context correlation. Fixed bucket padding prevents message size analysis. Persistent connections prevent connection timing analysis. Cover traffic adds noise.

Traffic analysis by a sophisticated adversary with visibility into relay traffic patterns remains the strongest residual attack. The protocol's contribution is raising the cost and making the most common correlation attacks ineffective, not claiming perfect metadata privacy.

### 11.5 Key Security Invariants

1. Agents are context-bound — no protocol-level cross-context awareness.
2. One agent per person per context (DID document cardinality enforcement).
3. Tools are stateless and non-agentic.
4. Category A actions (`#0` only) are structurally impossible for agents (hardware custody separation).
5. `signing_key_id` provides unforgeable human-vs-agent attribution on every signed message.
6. Context metadata is transparent before opt-in.
7. Role assignment is non-negotiable — agents cannot request elevated permissions.

---

## 12. Comparison with Related Work

### 12.1 Structured Comparison

| Property | SCP | Matrix | AT Protocol | Nostr | Signal | Holepunch | MCP |
|----------|-----|--------|-------------|-------|--------|-----------|-----|
| **Identity** | Self-sovereign DID, multi-key, shared human-agent | Server-bound (`@user:server`) | `did:plc` (PLC directory) | Keypair | Phone number | Keypair (per-feed) | N/A |
| **Resolution** | Dual-layer (relay + DHT), self-healing | Homeserver | PLC directory | Relay + NIP-05 | Phone registry | DHT | N/A |
| **Encryption** | MLS + sender keys | Megolm | None | NIP-44 (pairwise) | Double Ratchet [13] | Noise XX (transport) | N/A |
| **Group encryption** | MLS [2] | Megolm (custom) | None | None | Signal Groups | Undocumented | N/A |
| **Agent accountability** | Protocol-level (shared DID) | None | None | None | None | None | None |
| **Context isolation** | Cryptographic | Room-based (application-level) | None | None | N/A | None | N/A |
| **Capabilities** | UCAN (fine-grained delegation) | Power levels | None | None | None | None | Tool permissions |
| **Provenance** | Protocol-level, automatic | Server signatures | Repo signatures | Event signatures | None | Signature-level | None |
| **Transport** | Abstracted (17 adapters) | Federation | BGS relay | Simple relay | Centralized | Coupled (Hyperswarm) | stdio/SSE |
| **Governance** | Pluggable per-context (30 action types) | Power levels | Moderation lists | NIP-based | Centralized | None | N/A |
| **Self-hosting** | Device-as-node | Homeserver required | PDS | Relay | Not possible | Full P2P | Local |
| **Offline** | Three-tier model | Server handles | Relay handles | Best-effort | Server handles | Peer-dependent | N/A |

### 12.2 What SCP Borrows

SCP builds on established standards rather than inventing from scratch where good solutions exist:

- **MLS** [2] from IETF: group key management with formal security analysis.
- **DID** [10] from W3C: the identity abstraction, with did:dht's self-certification property.
- **UCAN** [12] from the community working group: capability-based authorization with delegation chains.
- **Merkle trees** from distributed systems: tamper-evident history.
- **BEP44** [11] from BitTorrent: signed mutable items on Mainline DHT.

The relay model is informed by Nostr's simplicity [17]. Federation lessons are informed by Matrix's experience [15]. The append-only log primitive draws from the same well-understood lineage as Hypercore [19]. DHT-integrated hole punching as a reachability concept is validated by Hyperswarm [18]. Keet [23] provides existence proof that zero-server encrypted group messaging works at production scale.

### 12.3 What Is Novel

- **Context isolation as the security boundary** for agent interaction — cryptographic isolation between interaction spaces with governed boundary crossing.
- **Human accountability chains** for all autonomous agents via shared-DID binding with structural action provenance (`signing_key_id` on every message).
- **Provenance as a core protocol principle** — automatic attachment at context boundaries with ordered quality tiers, not a per-application feature.
- **Multi-key identity architecture** with pre-rotation commitments, agent signing keys, and graduated permission categories — a stronger model than any existing DID method.
- **Dual-layer DID resolution** with protocol-level self-healing across SCP relays and Mainline DHT.
- **Sender-side key layer** enabling per-sender blocking without MLS group disruption — the mechanism that decouples content access from group membership.

### 12.4 Hypercore Comparison

Hypercore is the closest structural parallel to SCP's event logs — both are append-only authenticated logs with Merkle trees. The comparison illuminates what SCP adds beyond the data structure:

| Dimension | Hypercore | SCP Event Logs |
|-----------|-----------|----------------|
| Structure | Append-only log, Merkle tree | Append-only log, Merkle tree |
| Hash function | BLAKE2b-256 | SHA-256 |
| Signing | Ed25519, single writer per log | Ed25519, multi-writer per context (MLS-authenticated) |
| Multi-writer | Autobase (app-layer DAG linearization) | Native via MLS group membership |
| Encryption | None at log level; transport-level only | MLS + sender-side AES-256-GCM at log level |
| Governance | None | Full: 30 action types, pluggable engines |

Hypercore is a data structure; SCP event logs are a data structure embedded in a governance and encryption context. Autobase composes multi-writer from single-writer feeds; SCP starts multi-writer (MLS groups) and single-writer is the degenerate one-member group.

### 12.5 did:dht Comparison

SCP builds on did:dht's self-certification property but extends it significantly. The comparison illuminates what SCP's identity layer adds:

| Property | did:dht | SCP Identity Layer |
|----------|---------|-------------------|
| Self-certification | Yes (BEP44) | Yes (same BEP44) |
| Resolution backends | Mainline DHT only | Dual-layer: SCP relays + Mainline DHT |
| Key architecture | Single Ed25519 keypair | Multi-key: identity (`#0`) / human signing (`#active`) / pre-rotation / agent signing (`#agent`) |
| Rotation safety | No pre-rotation commitment | Pre-rotation key hash published in advance |
| Self-healing | None | Protocol-level: fresher document re-published to stale layer |
| TTL management | ~2 hour republish | Dual-cycle: 2h (DHT) + 6d (relay, 7d TTL) |
| Payload limit | 1000 bytes (BEP44) | 1000 bytes (DHT fallback), 256KB (relay layer) |
| Governance risk | TBD shutdown 2024, transferred to DIF | Insulated — depends only on BEP44 + Ed25519, not on did:dht software |

SCP identities are simultaneously did:dht-compatible (resolvable by standard did:dht resolvers via the DHT layer) and more resilient (dual-layer with self-healing). The multi-key architecture provides key compromise recovery without changing the DID — a capability no existing DID method offers — plus custody separation between human and agent operations.

---

## 13. Implementation Status

### 13.1 Reference Implementation

The reference implementation is in Rust, organized as a cargo workspace:

- **scp-core:** Protocol logic — contexts, agents, trust, capabilities, governance, encryption, provenance, event logs, sync.
- **scp-identity:** DID management, DHT resolution, key rotation, document lifecycle.
- **scp-transport:** Transport abstraction, adapter implementations, relay protocol.
- **scp-platform:** Platform-specific integrations — key custody, push notifications, device attestation.
- **scp-ffi:** FFI bridge layer — PyO3 (Python), UniFFI (Swift, Kotlin), napi-rs (TypeScript), wasm-bindgen (WASM).
- **scp-node:** Full protocol node combining core, transport, and platform.

The workspace includes six additional crates: scp-event-log (Merkle log), scp-media (media key derivation), scp-relay (standalone relay binary), scp-testing (conformance macros), scp-primitives (shared types), and scp-mcp (MCP integration).

Language bindings: Python (PyO3), Swift (UniFFI), Kotlin (UniFFI), TypeScript (wasm-bindgen and napi-rs), WASM (wasm-pack).

### 13.2 Conformance Infrastructure

Conformance is enforced through Rust macros that generate test suites for trait implementations:

- `storage_conformance!()` — Storage trait implementations (state persistence, 13 tests)
- `blob_store_conformance!()` — BlobStore implementations (relay storage backends, 19 tests)
- `payment_adapter_conformance!()` — PaymentAdapter implementations (economic governance, 8 tests)

Additional conformance suites are specified but not yet implemented for transport adapters, key custody, attestation stores, and push providers.

Integration test suites cover cryptographic primitives, context lifecycle, and advanced features. Distributed invariant tests verify Merkle consistency, delivery guarantees, suppression detection, pseudonym unlinkability, and block enforcement.

### 13.3 Licensing

The licensing structure reflects a deliberate strategy:

- **Protocol specification:** CC-BY 4.0. Freely implementable by anyone.
- **Client SDK:** Apache 2.0. Zero adoption friction.
- **Application node:** AGPL v3. Infrastructure protection — anyone running a relay or node must contribute modifications back.

---

## 14. Discussion and Future Work

### 14.1 Open Questions

**Sybil resistance earned capacity algorithm.** The composable trust signal framework is specified; the algorithm that maps signals to earned capacity thresholds is not. This is security-critical and requires empirical tuning against real attack patterns.

**Protocol versioning and capability negotiation.** The concrete mechanism for protocol evolution — how nodes negotiate versions, how features are introduced without breaking existing participants — needs formal specification.

**Formal security analysis of the composed construction.** MLS, sender-side keys, UCAN, and Merkle logs are individually well-understood. Their composition in SCP creates properties that warrant formal analysis, and independent formal verification is actively sought — particularly the interaction between MLS epoch advancement and sender-side key rotation during blocking, the three-layer encryption ordering (sender key → MLS → outer envelope), and the window between UCAN revocation and MLS membership removal.

**Multi-device sync edge cases.** Concurrent key rotation across devices, epoch advancement during device-to-device sync, and the interaction between MLS group state and identity private state sync require additional specification.

### 14.2 Limitations

The security analysis (Section 11) addresses specific residual attack surfaces — traffic analysis, sybil resistance cost models, and MLS group scaling. Beyond those:

**Governance model complexity.** Pluggable governance is powerful but each model has its own tradeoffs. Single-admin is simple but centralized; voting is democratic but slow; consensus is thorough but can deadlock. The protocol provides the interface; choosing the right model for a given context is a social problem, not a protocol problem.

**Bridge fidelity.** Platform bridge connectors (Section 12 of the specification) depend on external platforms' willingness or API availability. Relay-mode and puppet-mode bridges are inherently lower fidelity than native SCP communication, and shadow identities carry weaker trust properties than native identities.

### 14.3 Standardization Path

The current specification is self-published under CC-BY 4.0. The near-term path includes extraction of a standalone protocol specification document (implementation-agnostic, suitable for independent implementation), language-neutral test vectors, and a protocol evolution mechanism. The long-term trajectory follows AT Protocol's [16] model: IETF submission for core cryptographic subsystems once they have sufficient independent review and implementation experience.

---

## 15. Conclusion

SCP provides the durable connective tissue for a world of ephemeral, generated software. When building software is trivial but connecting it is not, the bottleneck shifts from code to social infrastructure.

The protocol's contribution is a coherent architecture that composes established cryptographic primitives — MLS for group encryption, DIDs for identity, UCANs for authorization, Merkle trees for integrity — into a system designed from the ground up for autonomous agents. Context isolation provides the security boundary. Encryption constitutes access control. Provenance is automatic and structural. Every agent traces to a human through cryptographic binding. The trust surface shrinks as behavioral evidence accumulates.

Three observations emerged from the design process and shaped the protocol's architecture. First, that the human must remain the root of trust and accountability even as agents become the primary actors — not because agents are untrustworthy, but because accountability requires a locus that cannot be manufactured computationally. Second, that isolation is a stronger security primitive than governance — a protocol that prevents cross-context infection by construction is fundamentally more secure than one that tries to govern it after the fact. Third, that the protocol that agents reach for first when building connected software will, over time, become the substrate for most connected software — and that this protocol must be open, interoperable with existing platforms, and independent of any single operator.

The specification is complete and published under CC-BY 4.0. The reference implementation spans five binding targets. Independent implementation is possible from the specification alone.

---

## Appendix A: Notation and Cryptographic Primitives

**Notation.** `#0`, `#active`, and `#agent` refer to DID document verification method identifiers. `iss == aud` denotes a UCAN self-delegation where the issuer and audience are the same DID. `fct.scp_key_scope` is a UCAN facts field constraining delegation to a specific key. Category A/B/C refers to the permission categories defined in Section 4.4.

| Primitive | Standard | Usage in SCP |
|-----------|----------|-------------|
| MLS | RFC 9420 [2] | Group key management, forward secrecy, post-compromise security. Ciphersuite uses AES-128-GCM for the MLS AEAD. |
| AES-256-GCM | NIST SP 800-38D [9] | Sender-side encryption, broadcast encryption, content access keys |
| AES-128-GCM | NIST SP 800-38D [9] | MLS ciphersuite AEAD (within the MLS layer only) |
| AES-256-KW | RFC 3394 [4] | Content access key wrapping |
| HPKE (Base mode) | RFC 9180 [3] | Key distribution (sender keys, access keys, broadcast keys, MLS Welcome messages) |
| HKDF | RFC 5869 [5] | Key derivation (pseudonym secrets, routing IDs, within HPKE) |
| HMAC-SHA256 | RFC 2104 [21] | Key derivation within HKDF, pseudonym derivation |
| Ed25519 | RFC 8032 [6] | Signatures (DID documents, inner envelopes, BEP44) |
| X25519 | RFC 7748 [7] | Diffie-Hellman key agreement (HPKE KEM, MLS tree) |
| SHA-256 | FIPS 180-4 [8] | Hashes (Merkle trees, content addressing, routing ID derivation) |

**Serialization:** MessagePack [22] with a canonical encoding profile (most compact representation for each type) is used for deterministic binary serialization of protocol messages. It is not a cryptographic primitive but is security-relevant: deterministic encoding is required for reproducible signature verification.

**Security level note:** The MLS ciphersuite's AES-128-GCM AEAD provides 128-bit security for the group encryption layer. The sender-side and content access layers use AES-256-GCM (256-bit). The effective security level of the composed system is bounded by the weakest layer — 128 bits — which is considered sufficient for current and near-term threat models.

## Appendix B: Protocol Constants

| Constant | Value | Purpose |
|----------|-------|---------|
| Maximum nesting depth | 3 | Bounds context hierarchy |
| Chain depth limit | 5 (protocol max), 3 (default) | Bounds cross-context data flow |
| Bucket padding sizes | 256, 1024, 4096, 16384, 65536, 262144 bytes | Fixed-size outer envelopes |
| Relay blob TTL | 604800 seconds (7 days) | Maximum relay retention |
| DHT republish interval | 7200 seconds (2 hours) | BEP44 expiry |
| Relay republish interval | 518400 seconds (6 days) | 7-day TTL with 1-day margin |
| Sender key grace period | 30 seconds | Key transition overlap |
| Per-caller session cap | 5 | Resource exhaustion prevention |
| MLS catch-up limit | 100 MLS Commit messages | Practical epoch processing bound |
| Reconnection timeout | 120 seconds | Overall sync timeout |
| Sender key acquisition timeout | 60 seconds | Per-sender key recovery |

## Appendix C: Glossary

**Context.** A bounded, governed, encrypted interaction space. The fundamental unit of interaction in SCP. All communication occurs within contexts.

**DID (Decentralized Identifier).** A W3C standard [10] for self-sovereign cryptographic identity. SCP uses `did:dht` as the primary method.

**UCAN (User Controlled Authorization Network).** Capability tokens with verifiable delegation chains. The authorization mechanism for all protocol actions.

**MLS (Message Layer Security).** The group encryption protocol [2] providing forward secrecy and post-compromise security.

**Epoch.** An MLS key generation. Each membership change or key update advances the epoch, ratcheting the key material.

**Sender Key.** A per-member AES-256-GCM key separate from MLS, enabling per-sender blocking without group disruption.

**Routing ID.** A per-context pseudonym derived from identity key material (encrypted contexts) or context ID (broadcast contexts). Used for relay addressing without revealing context identity.

**Capability Ceiling.** The maximum set of permissions a context can ever grant. Declared at creation; immutable by default.

**Governance Model.** The decision-making mechanism for a context (single-admin, multi-sig, consensus, voting). Pluggable via a defined interface.

**Event Log.** An append-only Merkle tree recording all protocol events within a context. The basis for behavioral validation and tamper-evident history.

**Provenance.** Verifiable origin metadata attached to data at protocol level. Includes source context, counterparties, chain depth, and quality tier.

**Attestation.** A signed claim by an identity about something — identity links, capability delegations, endorsements, tool integrity, participation records.

**Discovery Context.** A standard SCP context with open join policies and standardized discovery tools. Provides searchable registries for agents, contexts, and handles.

**Bridge Connector.** A protocol entity that translates between an external platform's protocol and SCP's protocol semantics. Operated by accountable identities.

**Shadow Identity.** A protocol-level representation of an entity from an external platform, created by a bridge connector. Claimable by the real user via identity attestation.

**Signing Key ID.** A field on every signed message identifying which verification method (`#active` or `#agent`) produced the signature. Provides structural action provenance.

---

## References

[1] Moltbook (moltbook.com), agent social network launched January 2026 by M. Schlicht; acquired by Meta, March 2026. Approximately 1.5 million registered agents (17,000 human deployers). Security analyses: Permiso identified bot-to-bot prompt injection and influence operations (SecurityWeek, Feb. 2026); Wiz Research discovered 1.5M exposed API keys (wiz.io/blog, Feb. 2026); Simula Research Laboratory (M. A. Riegler et al.) found prompt injection payloads in 2.6% of sampled content (Feb. 2026).

[2] R. Barnes, B. Beurdouche, R. Robert, J. Millican, E. Omara, and K. Cohn-Gordon, "The Messaging Layer Security (MLS) Protocol," RFC 9420, IETF, July 2023.

[3] R. Barnes, K. Bhargavan, B. Lipp, and C. Wood, "Hybrid Public Key Encryption," RFC 9180, IETF, February 2022.

[4] J. Schaad, "Advanced Encryption Standard (AES) Key Wrap Algorithm," RFC 3394, IETF, September 2002.

[5] H. Krawczyk and P. Eronen, "HMAC-based Extract-and-Expand Key Derivation Function (HKDF)," RFC 5869, IETF, May 2010.

[6] S. Josefsson and I. Liusvaara, "Edwards-Curve Digital Signature Algorithm (EdDSA)," RFC 8032, IETF, January 2017.

[7] A. Langley, M. Hamburg, and S. Turner, "Elliptic Curves for Security," RFC 7748, IETF, January 2016.

[8] National Institute of Standards and Technology, "Secure Hash Standard (SHS)," FIPS 180-4, August 2015.

[9] National Institute of Standards and Technology, "Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC," SP 800-38D, November 2007.

[10] W3C, "Decentralized Identifiers (DIDs) v1.0," W3C Recommendation, July 2022.

[11] S. Siloti, "BEP44: Storing Arbitrary Data in the DHT," BitTorrent Enhancement Proposal 44, 2014.

[12] B. Zelenka and P. Krüger, "UCAN Specification v1.0," UCAN Working Group, 2024.

[13] M. Marlinspike and T. Perrin, "The Double Ratchet Algorithm," Signal Foundation, November 2016.

[14] M. Kleppmann, A. Wiggins, P. van Hardenberg, and M. McGranaghan, "Local-first software: You own your data, in spite of the cloud," in *Proceedings of the ACM SIGPLAN International Symposium on New Ideas, New Paradigms, and Reflections on Programming and Software (Onward!)*, 2019.

[15] The Matrix.org Foundation, "Matrix Specification," matrix.org/docs/spec, 2024.

[16] J. Graber, "AT Protocol Specification," atproto.com/specs, 2024.

[17] Nostr Protocol, "Nostr Implementation Possibilities," github.com/nostr-protocol/nips, 2024.

[18] M. Buus, "Hyperswarm," Holepunch, github.com/holepunchto/hyperswarm, 2023.

[19] M. Buus and Holepunch, "Hypercore Protocol," github.com/holepunchto/hypercore, 2023.

[20] Anthropic, "Model Context Protocol Specification," modelcontextprotocol.io, 2024.

[21] H. Krawczyk, M. Bellare, and R. Canetti, "HMAC: Keyed-Hashing for Message Authentication," RFC 2104, IETF, February 1997.

[22] S. Furuhashi, "MessagePack Specification," msgpack.org, 2013.

[23] Holepunch (Pear Runtime), "Keet: Peer-to-peer encrypted group messaging," keet.io, 2024.

[24] B. Laurie, A. Langley, and E. Kasper, "Certificate Transparency," RFC 6962, IETF, June 2013.

[25] S. Smith, "Key Event Receipt Infrastructure (KERI)," arXiv:1907.02143, 2019. Pre-rotation key commitment mechanism.

[26] L. Moreau and P. Missier, Eds., "PROV-DM: The PROV Data Model," W3C Recommendation, April 2013.
