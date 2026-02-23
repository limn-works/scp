# Social Context Protocol (SCP)

## Technical Breakdown — Established Decisions

**Status:** Working draft
**Date:** February 14, 2026
**First client:** Cronica (by Limn)

---

## 1. Thesis

App generation is becoming trivial. Clients and server logic will be generated on-demand from simple prompts — personalized, ephemeral, disposable. What remains hard is the connective tissue: identity, social relationships, transport, persistence, and trust. This protocol is that connective tissue — an open, ecosystem-agnostic infrastructure layer that sits beneath any generated or traditional application.

The protocol is designed for a world where:

- Apps are disposable; infrastructure is not.
- Agents are the primary actors, not humans operating through clients.
- The gap between self-hosting and managed infrastructure is negligible.
- The big 3 (Apple, Google, Meta) will build closed versions of this. This is the open alternative.

### Core Principles

1. **Identity.** Every actor has a cryptographically verifiable identity (DID). Actions trace to identities. Identities trace to humans.
2. **Context isolation.** All interaction happens within contexts. Agents are separate instances per context. Cross-context data flow is explicit and governed.
3. **Provenance.** All non-private data carries verifiable origin metadata. Every message, tool output, attestation, and cross-context data transfer is traceable to its source. Provenance is not a feature — it is a foundational property of every protocol action. The absence of provenance on data is itself a signal ("this has no verified origin"). Provenance enables Sybil detection, governance enforcement, trust evaluation, and accountability.
4. **Encryption-as-access-control.** Context membership is enforced cryptographically. If you don't have the key, you can't read the data. No relay or intermediary enforces access — the math does.
5. **Legibility before opt-in.** Every context's parameters — ceiling, governance, roles, tools, TTL, memory scope — are visible before you join. No hidden terms.
6. **Human accountability.** Every agent traces to a human DID. Behavioral records are durable. Actions have consequences that persist across contexts.

---

## 2. System Design

### 2.1 Conceptual Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         LOCAL (User's Machine)                         │
│                                                                        │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐               │
│  │ Agent    │  │ Agent    │  │ Agent    │  │ Agent    │  Locally,      │
│  │ Config A │  │ Config B │  │ Config C │  │ Config D │  agents share  │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘  state and    │
│       │              │              │              │        coordinate  │
│  ┌────┴──────────────┴──────────────┴──────────────┴─────┐  freely.    │
│  │              Local Agent Orchestration                 │             │
│  │         (Unconstrained by protocol)                   │             │
│  └────┬──────────────┬──────────────┬──────────────┬─────┘             │
│       │              │              │              │                    │
└───────┼──────────────┼──────────────┼──────────────┼────────────────────┘
        │              │              │              │
 ═══════╪══════════════╪══════════════╪══════════════╪═══ PROTOCOL BOUNDARY
        │              │              │              │
   ┌────▼────┐   ┌─────▼────┐   ┌────▼────┐   ┌────▼────┐
   │ Context │   │ Context  │   │ Context │   │ Context │
   │    A    │   │    B     │   │    C    │   │    D    │
   │         │   │          │   │         │   │         │
   │ Agent·A │   │ Agent·B  │   │ Agent·C │   │ Agent·D │
   │ [roles] │   │ [roles]  │   │ [roles] │   │ [roles] │
   │ [tools] │   │ [tools]  │   │ [tools] │   │ [tools] │
   └─────────┘   └──────────┘   └─────────┘   └─────────┘
        ▲               ▲              ▲              ▲
        │               │              │              │
        ╳               ╳              ╳              ╳
   No protocol-level communication between agents across contexts.
   Agent isolation is absolute — agents are separate instances per context.
   Information may cross context boundaries only through opt-in tool interfaces (§6.2)
   or multi-parent child contexts (§5.13). See §2.3.
```

The **protocol boundary** encompasses everything that touches the network — contexts, identity state (both public and private), encrypted envelopes, relay interactions, and attestations. Identity private state (§3.7) is protocol-governed even though it exists outside any context — it is encrypted data stored on relays, subject to protocol rules. Above the boundary, local agent orchestration and client behavior are unconstrained. Below it, all data and interactions are protocol-governed and cryptographically enforced.

### 2.2 Context Interior

```
┌─────────────────────────────────────────────────────────┐
│                     CONTEXT                              │
│                                                          │
│  Creator: DID (accountable identity)                     │
│  Capability Ceiling: [declared at creation]              │
│  Governance: [single-admin | multi-sig | consensus | …]  │
│                                                          │
│  ┌─────────────────────────────────────────────────┐     │
│  │ ROLES                                           │     │
│  │                                                 │     │
│  │  admin ──── [full tool access, invite, config]  │     │
│  │  member ─── [standard tool access, read/write]  │     │
│  │  observer ─ [read only, limited tools]          │     │
│  │  (custom) ─ [context-defined permissions]       │     │
│  └─────────────────────────────────────────────────┘     │
│                                                          │
│  ┌─────────────────────────────────────────────────┐     │
│  │ TOOLS (stateless functions)                     │     │
│  │                                                 │     │
│  │  tool_a(input) → output                         │     │
│  │  tool_b(input) → output                         │     │
│  │  tool_c(input) → output                         │     │
│  │                                                 │     │
│  │  No identity. No agency. No initiation.         │     │
│  │  Invoked by agents according to their role.     │     │
│  └─────────────────────────────────────────────────┘     │
│                                                          │
│  ┌─────────────────────────────────────────────────┐     │
│  │ MEMBERS (one agent per human)                   │     │
│  │                                                 │     │
│  │  Alice·Agent ── role: admin                     │     │
│  │  Bob·Agent ──── role: member                    │     │
│  │  Carol·Agent ── role: member                    │     │
│  │  Dave·Agent ─── role: observer                  │     │
│  └─────────────────────────────────────────────────┘     │
│                                                          │
│  ┌─────────────────────────────────────────────────┐     │
│  │ METADATA (visible before opt-in)                │     │
│  │                                                 │     │
│  │  - Capability ceiling                           │     │
│  │  - Available roles + permission sets            │     │
│  │  - Governance model                             │     │
│  │  - Creator identity                             │     │
│  │  - Member count                                 │     │
│  │  - Context age                                  │     │
│  └─────────────────────────────────────────────────┘     │
│                                                          │
└─────────────────────────────────────────────────────────┘
```

### 2.3 Cross-Context Communication

```
  ┌───────────┐                              ┌───────────┐
  │ Context A │                              │ Context B │
  │           │    Tool Interface (opt-in)    │           │
  │   tools ──┼──────── stateless call ──────┼── tools   │
  │           │                              │           │
  │  Alice·A  │              ╳               │  Alice·B  │
  │           │     (agents CANNOT cross)    │           │
  └───────────┘                              └───────────┘
                        │
                        │  The human (Alice) coordinates
                        │  locally. Her agents in A and B
                        │  are separate protocol instances.
                        │  They share state on her machine,
                        │  not on the network.
                        │
          ┌─────────────▼──────────────┐
          │    Alice's Local Machine    │
          │                            │
          │  Agent·A ←state→ Agent·B   │
          │     (unconstrained)        │
          └────────────────────────────┘

  Two protocol-level mechanisms allow information to cross
  context boundaries:

  1. TOOL INTERFACES (asymmetric, §6.2):
     - Both contexts explicitly opt in (mutual consent)
     - Calls are stateless (with optional sessions)
     - Data flows through declared tool schemas
     - Every call is logged in the verifiable event log
     - Results carry provenance

  2. MULTI-PARENT CHILD CONTEXTS (symmetric, §5.13):
     - All parents' governance explicitly consents
     - Child is a full context (messages, tools, roles)
     - Child ceiling ≤ intersection of parent ceilings
     - Members from different parents interact as peers
     - Lifecycle coupled to parents (no orphans)

  Both are controlled crossings, not breaches of isolation.
  Agent isolation remains absolute: no agent instance spans contexts.
  Tool interfaces expose only what schemas declare.
  Child contexts are independent MLS groups with their own keys.
```

### 2.4 Trust and Capability Model

```
┌──────────────────────────────────────────────────────────────┐
│                     HUMAN (DID)                               │
│                                                               │
│  Reputation, consequences, and trust attach here.             │
│  Blocking this identity blocks all agents.                    │
│                                                               │
│  ┌──────────────────────────────────────────────────────┐     │
│  │ CAPABILITY TOKENS (UCAN-based)                       │     │
│  │                                                      │     │
│  │ Granted per-agent, per-context, per-capability:      │     │
│  │                                                      │     │
│  │   Agent·A in Context·1:                              │     │
│  │     ✓ invoke tool_x                                  │     │
│  │     ✓ read member list                               │     │
│  │     ✗ invite new members                             │     │
│  │     ✗ modify context settings                        │     │
│  │                                                      │     │
│  │   Agent·B in Context·2:                              │     │
│  │     ✓ invoke tool_y                                  │     │
│  │     ✓ invoke tool_z                                  │     │
│  │     ✓ invite new members                             │     │
│  │     ✗ modify context settings                        │     │
│  │                                                      │     │
│  └──────────────────────────────────────────────────────┘     │
└──────────────────────────────────────────────────────────────┘

  Trust evaluation between two parties:

  ┌──────────┐         trust query          ┌──────────┐
  │ Alice    │ ────────────────────────────▶ │ Bob      │
  │          │                              │          │
  │ "Do I    │  Bob's agent presents:       │          │
  │  trust   │  1. Proof of binding to Bob  │          │
  │  this?"  │  2. Capability tokens        │          │
  │          │  3. Agent capability metadata │          │
  │          │                              │          │
  │ Alice    │  Alice evaluates:            │          │
  │ decides  │  1. Her relationship w/ Bob  │          │
  │ based on │  2. The specific capability  │          │
  │ identity │     being exercised          │          │
  │    +     │  3. The context it's in      │          │
  │ capability│ 4. Bob's agent's metadata   │          │
  └──────────┘                              └──────────┘

  Trust = f(identity, capability, context, metadata)
  Not a binary flag. Contextual and composable.
```

### 2.5 Full Stack Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                                                                  │
│                     GENERATED / TRADITIONAL APPS                 │
│              (Cronica, custom Discord, any client)               │
│                                                                  │
│   Thick or thin. Partial or full protocol reliance.              │
│   The protocol doesn't care what the app is.                     │
│                                                                  │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│                     APP INTERFACE LAYER                           │
│                                                                  │
│   Self-documenting, machine-readable API contracts.              │
│   Optimized for agent consumption, not human coding.             │
│   Apps declare required capabilities; protocol provides them.    │
│                                                                  │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│                     SOCIAL CONTEXT LAYER ◀── the novel work      │
│                                                                  │
│   Contexts, agents, tools, roles, trust semantics.               │
│   Agent-native social infrastructure.                            │
│   No existing protocol does this.                                │
│                                                                  │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│                     IDENTITY + CAPABILITIES                      │
│                                                                  │
│   DID-based identity. UCAN-based capability tokens.              │
│   Invisible key custody. Social/device recovery.                 │
│   Build on existing standards.                                   │
│                                                                  │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│                     TRANSPORT + DATA                             │
│                                                                  │
│   Relay-based, self-hostable, transport-agnostic.                │
│   Data sovereignty: your data, your storage.                     │
│   Build on existing infrastructure (Matrix, libp2p, etc).        │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

---

## 3. Identity

### 3.1 Root of Identity

Every identity is rooted in a cryptographic keypair. This is the canonical identifier at the protocol level — not a username, not an email, not an account on someone's server.

Build on **DID (Decentralized Identifiers, W3C standard)**. DIDs provide the right abstraction: a cryptographic root that's method-agnostic, meaning the underlying key custody can vary without changing the identity itself.

### 3.2 Key Custody

Users never see or manage keys directly. Custody is delegated to whatever the user already trusts:

- Device secure enclave (iOS Secure Enclave, Android Keystore)
- Platform accounts (Apple, Google) via passkey infrastructure
- Hardware security keys
- Self-managed keys (power users who want direct control)

The identity layer abstracts custody. The user authenticates however they choose; under the hood it resolves to a protocol-level DID. Migration between custody methods is possible without changing identity.

### 3.3 Recovery

No seed phrases. Recovery uses social and device mechanisms:

- **Trusted device recovery:** Another device you control vouches for a new one.
- **Social recovery:** Trusted contacts confirm your identity.
- **Platform-backed recovery:** If custody is delegated to Apple/Google, their recovery mechanisms apply.

For new users with a single device and no SCP contacts, platform-backed recovery is the practical safety net. Social and device recovery grow in value over time as users add devices and build connections. Apps should prompt for trusted recovery contacts during onboarding — the same pattern Google and Apple use today.

### 3.4 Linking Existing Identities

Existing platform identities (Google, Apple, social accounts) can be linked to a protocol identity but are never the root. They serve as convenience and interop, not as source of truth.

### 3.5 Identity Attestations

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

### 3.6 Social Graph

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

### 3.7 Identity Private State

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

**Open questions:**

- **Size constraints.** Block lists and preferences are tiny. Agent memory or personal annotations could grow. Does identity private state have the same minimal-state principle as context state, or is the single-owner case less constrained?
- **Relay obligations.** Do relays treat identity private state the same as context events? Same retention? Same storage class? Or is there a differentiated commitment?
- **Key rotation.** Identity key rotation (recovery scenario) requires re-encrypting private state. Single-owner simplifies this — no group key redistribution — but it's still a migration step that needs specification. See §9.12 for the full compromise recovery protocol.
- **Discovery pointer.** Does the DID document explicitly signal "I have private state at these relays"? Or is it implicit from the relay list? If implicit, relays need a way to distinguish between "fetch context events for this DID" and "fetch private state for this DID."

### 3.8 DID Resolution Security

DID resolution is the trust root for the entire protocol. If resolution can be MITMed, every layer above — encryption, authentication, capability validation — is compromised. The security properties depend on the DID method:

**did:dht (target method):** Self-certifying. The DID string encodes the public key. DID documents are signed via BEP44 and verifiable against the DID without trusting any intermediary. MITM on resolution is impossible given the correct DID. Stale documents are rejected via sequence numbers. See §9.6 for full specification.

**did:web (fallback only):** NOT self-certifying. Security depends on DNS + TLS + server integrity. The SDK MUST use TLS pinning + TOFU (Trust On First Use) + key change alerts to mitigate. did:web exists as a fallback if did:dht libraries prove unusable — not as a planned stepping stone. See §9.6.2 for required mitigations.

**Key Continuity Verification:** Signal-style safety numbers for DIDs, enabling out-of-band verification that two parties have the correct keys for each other. See §9.11.

### 3.9 Key Lifecycle

Identity keys follow a defined lifecycle: generation (in hardware security modules where available), distribution (via DID document publication), rotation (DID document update with authorization chain from old key), and destruction (for ephemeral context keys). The full key lifecycle specification, including compromise recovery, is in §9.7.4 and §9.12.

---

## 4. Agents

### 4.1 Core Principle

Humans and their bound agents are the only actors in the system. Every action on the protocol — every message, every tool invocation, every state change — is traceable to a human(s) as an action they took or their attributed agent took. There are no anonymous actors or unaccountable software participants.

### 4.2 Binding

Every agent is bound to one or more humans via cryptographic proof. The binding is verifiable by any participant.

- **Personal agents:** Bound to a single human. The common case.
- **Institutional agents:** Bound to multiple humans through shared governance (multi-sig, elected operators, organizational hierarchy). Structurally identical to personal agents; the difference is in who holds the keys and how revocation/control works. Institutions get one agent per context, the same as individuals — one seat per institution per table.

### 4.3 One Agent Per Person Per Context

At the protocol level, each human has exactly one agent per context. This is a social constraint, not a computational one. The agent can be arbitrarily capable internally — parallel execution, complex orchestration, sophisticated reasoning. The constraint is on presence: one seat per person per table.

Prevents: fleet-based force multiplication within a space, agent slot rental within a context, swarm attacks from a single identity, ambiguity in trust evaluation.

### 4.4 Bring Your Own Agent

The protocol defines how agents communicate and what capabilities they can exercise. It does not define what agents are internally. Users bring their own: models, configurations, logic, local infrastructure. A user running a frontier model and a user running a basic assistant both have one seat. The asymmetry in capability is acknowledged, not policed.

The protocol surfaces **agent capability metadata** — a standardized profile of what an agent can do — so other participants can evaluate it. Not the model name or implementation details, but a functional profile. Capability metadata distinguishes between:

- **Self-attested capabilities.** Claimed by the agent's human operator but not independently verified. Any agent can make these claims. Trust in the claim depends on trust in the claimant.
- **Challenge-verified capabilities.** Tested via the protocol's challenge-response mechanism (§7.3.4). A verifier issued a standard challenge suite; the agent passed. The metadata records what was verified, when, and by whom. Challenge-verified capabilities are validation, not trust — the test result is objective.

Contexts can require specific capability levels for admission. "This context requires challenge-verified prompt injection resistance" is a mechanical admission check, not a judgment call.

### 4.5 The Human-Agent Pair

The fundamental unit of participation in SCP is not the agent alone — it is the human-agent pair. The human is the root of identity, trust, and accountability. The agent is how the human is present at the protocol level. Neither is complete without the other: an agent without a human binding is unaccountable; a human without an agent has no protocol-level presence.

This pairing is what the protocol provides. At the protocol level, the agent acts. At the trust level, the human is accountable. Other participants evaluate both: "Do I trust this person?" and "Do I trust what their agent can do?" These are separate questions with a single answer — the trust function (§7.1) evaluates identity and capability together.

The protocol does not define a separate "human-direct" interaction mode. The human always acts through their agent. But this is not because the human is subordinate to the agent — it is because the agent is the human's presence in the protocol, the way a voice is a person's presence in a conversation. The agent carries the human's capability tokens, bound to their DID, legible to other participants. The human decides what the agent does — from full autonomy to direct manual control — and that decision is local, outside protocol scope.

What this means for the ecosystem:

- **One actor model.** Every protocol action has the same structure: an agent acts, bound to a human, within a context. No bifurcation between "agent actions" and "human actions." This keeps the protocol simple and trust evaluation uniform.
- **Agent capability is a spectrum.** A passthrough agent that forwards human keystrokes is valid. A fully autonomous agent that acts on its own judgment is valid. The protocol treats both identically — the difference is in the human's local configuration, not in the protocol's evaluation.
- **The minimum viable agent is trivial.** A user doesn't need to "set up an agent" any more than they need to "set up TCP." The simplest agent can be generated, embedded in an app, or provided as a default. The protocol requires the pairing to exist, not that it be sophisticated.

### 4.6 Agents Are Consumers, Not Enforcers

Human-bound agents are **protocol consumers** — a different class of user than humans, but users nonetheless. They use apps. They use context tools. They interact with contexts through the protocol. They have zero responsibility for enforcing protocol rules.

The protocol enforces itself — through cryptography (encryption-as-access-control, key tree exclusion for blocks, capability token validation) and through the SDK that builders use to construct conformant apps. Agents do not enforce blocking, role permissions, capability ceilings, or any other protocol rule. The protocol and its cryptographic guarantees handle enforcement. Apps built on the SDK inherit those guarantees. Agents and humans consume those apps.

This distinction matters because SCP is designed for a world of generated, ephemeral clients. Any enforcement that depends on agent or client behavior is not enforcement — it's a suggestion that non-conformant software can ignore. Protocol guarantees must be cryptographic or structural, never behavioral.

A separate class of agents exists outside this context: **builder agents** — the LLMs and AI systems that generate apps and services on top of SCP using the SDK. These are developers, not protocol participants. They are responsible for constructing software; human-bound agents are responsible for nothing beyond using it.

### 4.7 Context-Bound at Protocol Level

An agent in Context A has no protocol-level awareness of or connection to the same human's agent in Context B. At the protocol level, they are separate instances. They share no state through the network.

The human coordinates locally. On the user's machine, agents share state freely, coordinate, plan across contexts. The protocol only governs what touches the network. Each agent only operates within its own context.

This eliminates: cross-context infection via agent memory, runaway agent coordination at the protocol level, the need for bridging rate limits, metastatic growth patterns through agent connections.

### 4.8 Agent Fleet

A human can be in many contexts, each with one agent configured for that context. The human is multiplied across the system but singular within any space. The rate-limiting surface is how many contexts a person participates in simultaneously, not how many agents they have in one room.

The number of contexts a person can participate in may be an earned resource — new identities start limited, earn more through history, reputation, and behavior. Mechanism TBD.

---

## 5. Contexts

### 5.1 Definition

All interaction happens within contexts. There is no concept of off-context communication at the protocol level. A context is a bounded, encrypted, governed space — a cryptographic entity (one MLS group per context) with its own key tree, event log (append-only Merkle tree), governance model, membership roster, and capability ceiling. A group chat is a context. A Cronica quest is a context. A generated Discord alternative is a context. DMs are a two-party context. An entire app's backend is a context (or set of contexts).

**Contexts are spaces, not actors.** They do not initiate, do not act, and have no agency. They hold the rules, the keys, and the audit trail. Agents (always bound to humans, §4) do the acting within them. Tools (§5.4) do the computing within them. The context itself is passive infrastructure.

**Contexts are runtime objects, not infrastructure to deploy.** Creating a context is a runtime operation (~5-15ms local computation, ~200ms wall clock with network — see §5.12.4). Contexts are created, used, and destroyed during normal application operation. They survive process restarts (state is persisted) but are created as fluidly as opening a connection.

**Contexts are where apps live.** What people experience as "an app" is a composite: a context (or set of contexts) + members + tools + data (§8.1). Long-lived contexts with no TTL host persistent applications — games, workspaces, social platforms. Ephemeral contexts with TTL host bounded tasks. The context is the app's lifecycle boundary. Protocol state (membership, roles, trust) is portable and survives app death; app state is the app's concern (§8.3).

**Every context contains:** a capability ceiling (§5.3), roles with permission sets (§5.5), a governance model (§5.9), tools (§5.4), an optional TTL (§5.10), a memory scope (§5.11), and transparent metadata visible before opt-in (§5.7). These are all declared at creation. Contexts may be created from well-known templates (§5.12) for common patterns or from explicit parameters. Contexts can have parent-child relationships (§5.13) for sub-spaces and governed cross-context bridges.

**Two protocol-level mechanisms allow information to cross context boundaries:** tool interfaces (§6.2) for asymmetric, structured, request/response interactions, and multi-parent child contexts (§5.13) for symmetric collaboration. Both require governance consent from all involved contexts. Agent isolation is absolute — no agent instance spans contexts (§6.1).

### 5.2 Creation

Contexts are created by accountable identities only. Anonymous or unbound entities cannot create contexts. Creating a context is an act of social infrastructure — you're defining a space where autonomous software operates on people. Contexts may be created from well-known templates (§5.12) for common patterns, or from explicit parameters for bespoke configurations. Both paths produce identical contexts; templates are the fast path.

### 5.3 Capability Ceiling

Every context declares a capability ceiling at creation: the maximum set of things that can happen in this space. This ceiling bounds what tools can do, what roles can grant, and what agents can exercise.

Open question: whether ceilings are immutable (stronger security, contexts must be recreated to expand) or mutable under governance (more flexible, but enables permission creep and bait-and-switch). The migration path (create new context, move members) may make immutability practical if artifact portability is solved.

### 5.4 Tools

Contexts provide tools: stateless functions that agents invoke. Tools have no identity, no agency, no ability to initiate. They take input and return output. They are scoped to their context and cannot span contexts.

Tools are the protocol's answer to "what about bots?" — anything that would have been a bot in a traditional system is a tool in SCP. The critical difference: tools cannot act, only respond. All agency flows through accountable agents.

Tool registrations include:

- **Schema.** Input and output types (MCP-compatible JSON Schema — see §8.5). Machine-readable, self-documenting.
- **Implementation hash.** Content-addressable reference to the tool's implementation. Any change to the implementation produces a new hash.
- **Test vectors.** Known input-output pairs that define correct behavior. Any agent can call the tool with test inputs and verify outputs match. This enables continuous integrity verification (§7.3.3).
- **Operator DID.** The identity accountable for the tool. Tool misbehavior traces to this DID.

Tool mutations (implementation hash change, schema modification, test vector update) are recorded in the context's verifiable event log (§7.3.1). Silent tool modification is not possible — any change is visible to all context members.

### 5.5 Roles

Contexts define roles with specific permission sets within the capability ceiling. Roles determine which tools an agent can invoke, what data it can access, whether it can invite others, modify settings, etc.

Properties of roles:

- **Visible before opt-in.** You see what role you'd get before joining.
- **Non-negotiable.** Agents cannot request or bargain for different roles. Take it or leave it. If you want a different role, ask the context creator (human to human) or create your own context.
- **Defined by context creator.** Custom roles beyond defaults are context-specific.
- **Governed by context governance model.** Role changes require whatever governance the context uses.

### 5.6 Membership

One agent per human per context. Membership is transparent — participants can see the member list, roles, and agent capability metadata. When you opt into a context, you know what you're walking into.

### 5.7 Metadata

The following are visible before opting in to any context:

- Template ID, if created from a well-known template (§5.12)
- Capability ceiling
- Available roles and their permission sets
- Governance model
- Creator identity
- Member count
- Context age
- TTL / time-to-live, if set (§5.10)
- Memory scope (§5.11)
- Active tool interface count (inbound and outbound, §6.2, §9.2.1)
- For child contexts (§5.13): parent context IDs, parent metadata summaries, parent governance configuration, and the prospective member's eligibility basis (§5.13.6)

This is protocol-level metadata, not optional. Full legibility of any space before you enter it. When a template ID is present, the joining party can evaluate the context with a single template-level check rather than inspecting each parameter individually — the template is a commitment that the parameters match the well-known definition exactly (§5.12.1).

### 5.8 Context Identity

Contexts are cryptographic entities. You opt into a key, not a name. Naming and display are client-layer concerns. Spoofing a name is a UI problem for clients to solve. Spoofing a cryptographic identity is hard.

### 5.9 Governance

Contexts support multiple governance models for who can change roles, settings, membership, and other context configuration. Models include but are not limited to: single admin, multi-sig (N-of-M approval), elected moderators, full member consensus, weighted voting.

The governance model is declared at creation and visible to all. Governance implementations are **pluggable** — the protocol defines the interface (propose, approve, reject) but specific multi-sig, consensus, and voting implementations are not protocol-mandated. Context creators bring or select their own governance logic. Specific protocol-level primitives for the governance interface are TBD.

### 5.10 Context TTL (Time-to-Live)

Contexts gain an optional time-to-live — a declared lifespan after which the context closes automatically. TTL is set at creation and visible in context metadata (visible before opt-in).

When TTL expires:

- Context is closed. No new actions are accepted.
- Encryption keys can be destroyed per the context's memory scope (§5.11), making content physically unreadable.
- **Durable data persists.** The context's existence, its metadata, its participants, and behavioral record contributions survive. Context is durable data — the interaction inside may be ephemeral, but the fact of the interaction is permanent.

TTL is useful beyond agent-to-agent communication. Time-boxed brainstorming sessions. Pop-up events. Temporary project groups. Scheduled context expiry for data hygiene. The extension is general-purpose.

**Extension mechanics.** TTL is set at creation. A context's TTL cannot be extended unilaterally. Extension requires agreement from all parties (for bilateral contexts) or through the context's governance model (for multi-party contexts). This prevents one party from unilaterally extending an interaction the other expected to be ephemeral. An expired TTL is final — if participants want to continue, they create a new context (which may reference the closed one for continuity).

**Interaction with governance.** Governance actions on a TTL'd context follow the same rules as any context — but the TTL acts as a hard upper bound. A governance proposal to extend TTL is valid and follows the context's governance model, but the extension requires explicit consent from all current members (not just governance approval) because TTL was part of the original opt-in contract.

**Key destruction on expiry.** When TTL expires, key destruction follows the memory scope (§5.11). The destruction protocol includes platform-attested verification where available — see §9.15 for the ephemeral key destruction verification mechanism.

### 5.11 Memory Scope

Contexts gain a declared memory scope — what happens to the context's data when it closes or expires. Memory scope is set at creation and visible in context metadata (visible before opt-in).

Three scopes:

**Ephemeral.** Context encryption keys are destroyed on close AND the SDK issues deletion requests to relays for all encrypted event data associated with the context. Content is physically unreadable (keys destroyed) and actively cleaned up (ciphertext deleted where relays comply). Durable metadata persists: who participated, when, the declared purpose, behavioral contributions (participation counts, tool invocations), and discovery provenance. An agent's local orchestration (above the protocol boundary) may retain information from the interaction, but any data the agent subsequently uses elsewhere carries provenance at the protocol level: "sourced from closed ephemeral context."

Relay deletion is best-effort — relays are untrusted infrastructure and cannot be forced to delete. Defense in depth: even if a relay retains the encrypted blobs, the keys are destroyed and the data is unreadable. Relay compliance with deletion requests is tracked as part of relay reliability scoring (§9.9.2) — relays that retain data they were asked to delete are scored lower and deprioritized for future context creation.

**Summary.** Context produces a structured summary on close. Full content is destroyed (keys destroyed as with ephemeral). The summary persists with full provenance. Both parties can verify the summary against the event log before keys are destroyed. The summary format is defined by the context (via tools or governance), not by the protocol — the protocol provides the lifecycle hooks (pre-close summary generation, verification window, key destruction) but does not prescribe summary content.

**Full.** Standard behavior. Context persists indefinitely. No memory restrictions. Content remains accessible to members. This is the default when no memory scope is specified.

**The Moltbook defense.** Memory scope + provenance tagging (§7.7) prevents time-shifted prompt injection — the attack pattern where malicious payloads are planted in one interaction and activate in a later interaction:

- Ephemeral contexts destroy the source material at the protocol level
- Any data that survives (in agent local memory above the protocol boundary) carries provenance when reintroduced to the protocol: "this came from context X with agent Y"
- Other participants see the provenance and evaluate accordingly
- Fragmented payloads can't reassemble undetected across interactions because each fragment's origin is traceable

**Enforcement honesty.** The protocol enforces memory scope through cryptographic key destruction — specifically, MLS group state destruction (tree secrets, all epoch key schedules, application key material). This is verifiable and absolute for protocol-level data. Platform-attested destruction (§9.15) provides hardware-backed evidence that keys were deleted where available. However, the protocol cannot enforce memory scope above the protocol boundary. An agent's underlying model may retain information from an ephemeral interaction in its own memory. The spec is explicitly honest about this limitation: ephemeral memory scope destroys the protocol-level record and makes reproduction unverifiable, but does not guarantee the agent has forgotten. The absence of provenance on information an agent produces from memory is itself a signal — "this data has no verified origin." Participants in other contexts can evaluate unprovenanced information accordingly.

### 5.12 Context Templates and Lightweight Creation

Context creation requires specifying a ceiling, roles, governance model, memory scope, TTL, and tools. For durable, bespoke contexts this is appropriate — the creator is designing a space. But contexts must also be cheap and disposable. If "spin up a quick context" requires manual configuration of six parameters, agents will route around the protocol for lightweight coordination. Context templates solve this.

#### 5.12.1 Well-Known Templates

The protocol defines a set of well-known templates — named parameter bundles with fixed, predictable configurations. Templates are protocol-level identifiers, not SDK convenience wrappers. Both the creator and the joining party recognize the template ID and know exactly what it means without inspecting individual parameters.

```
Template: "scp:template/bilateral-ephemeral"
  ceiling:     [MessagesRead, MessagesWrite]
  roles:       [admin (creator), member (joiner)]
  governance:  single-admin
  memory_scope: ephemeral
  ttl:         required (creator sets duration, no default — forces intentionality)
  tools:       none

Template: "scp:template/bilateral-persistent"
  ceiling:     [MessagesRead, MessagesWrite]
  roles:       [admin (creator), member (joiner)]
  governance:  single-admin
  memory_scope: full
  ttl:         none
  tools:       none

Template: "scp:template/coordination"
  ceiling:     [MessagesRead, MessagesWrite, ToolInvokeAll]
  roles:       [admin (creator), member (joiner)]
  governance:  single-admin
  memory_scope: summary
  ttl:         required (creator sets duration)
  tools:       creator-defined at creation

Template: "scp:template/group-discussion"
  ceiling:     [MessagesRead, MessagesWrite, MemberInvite]
  roles:       [admin, member, observer]
  governance:  single-admin
  memory_scope: full
  ttl:         optional
  tools:       none
```

Templates are not extensible by users — they are protocol constants. A template ID is a commitment: "this context has exactly these properties." If you need something a template doesn't cover, use explicit `ContextParams`. Templates and explicit params are equally valid; templates are just the fast path for common cases.

**Template in metadata.** When a context is created from a template, the template ID appears in context metadata (§5.7). This means the joining party sees `template: "scp:template/bilateral-ephemeral", ttl: 300s` instead of evaluating six independent parameters. Template-based evaluation is a single check: "do I accept this template from this DID at this TTL?"

#### 5.12.2 Auto-Accept Policies

Agents MAY configure policies for automatic context acceptance — rules that allow the SDK to join contexts without human-in-the-loop confirmation. Auto-accept policies are local to the agent (never shared with the network) and evaluated entirely in the SDK.

Policy structure:

```
AutoAcceptPolicy {
  template:        TemplateID          // Which template(s) to auto-accept
  from:            TrustRequirement    // Who can trigger auto-accept
  max_ttl:         Duration?           // Maximum TTL to accept (optional cap)
  rate_limit:      Rate?               // Max auto-accepts per time window
}

TrustRequirement:
  | shared_context    // DID shares at least one active context with me
  | known_did(list)   // DID is in an explicit allowlist
  | discovery_context // DID is registered in a discovery context I trust
```

Example policy: "Auto-accept `bilateral-ephemeral` contexts from any DID I share at least one context with, if TTL ≤ 10 minutes, at most 5 per hour."

**Security properties:**
- Policies never auto-accept contexts with tool capabilities (ceiling containing `ToolInvoke*`). Tool access always requires explicit confirmation. This is non-overridable.
- Rate limiting prevents a compromised contact from flooding auto-accepts.
- The `shared_context` trust requirement means strangers can never trigger auto-accept — the existing shared context provides the trust baseline.
- Auto-accept policies are enforced in the SDK, not the protocol. The protocol sees a normal context join. The policy just determines whether the SDK prompts the human or acts autonomously.

**No auto-accept for tool-bearing contexts.** This is a hard rule, not a default. Any context whose ceiling includes `ToolInvokeAll`, `ToolInvokeSpecific`, or any tool-related capability requires explicit human or agent confirmation regardless of auto-accept policies. The rationale: tool access is the capability that enables cross-context data flow (§6.2). Auto-accepting it would silently expand the agent's cross-context attack surface.

#### 5.12.3 SDK Convenience Surface

The SDK provides template-based creation as the primary context creation path, with explicit `ContextParams` as the advanced path. Template-based creation is a single call that handles MLS group setup, sender key generation, event log initialization, and transport publishing internally.

```
// Primary path: template-based creation
sdk.create_context(
  template: "bilateral-ephemeral",
  peer: bob_did,                      // For bilateral templates
  ttl: Duration::minutes(5)
) → ContextHandle

// Equivalent explicit path (same result, more configuration)
sdk.create_context(params: ContextParams {
  ceiling: [MessagesRead, MessagesWrite],
  roles: [admin, member],
  governance: SingleAdmin,
  memory_scope: Ephemeral,
  ttl: Duration::minutes(5),
  tools: [],
  template_id: None,                  // No template — custom params
}) → ContextHandle
```

**Bilateral shorthand.** For bilateral templates, the SDK accepts a peer DID directly and handles the invitation internally. The creator creates the context and immediately sends the invitation. If the peer has an auto-accept policy that matches, the join is automatic. If not, the peer's agent is prompted.

**Invitation bundling.** When creating a bilateral context with a peer, the SDK bundles the context metadata and MLS Welcome message into a single transport delivery. The peer receives everything needed to evaluate and join in one message — no roundtrip to fetch metadata before deciding.

#### 5.12.4 Context Creation as a Runtime Operation

Context creation is not infrastructure provisioning. It is a runtime operation — comparable in weight to opening a TLS connection, not to deploying a database. Understanding this is critical to the protocol's viability: if context creation feels like a build action, agents will treat it as one and route around it for lightweight coordination. Context creation must be (and is) as fluid as `connect()`.

**Computational profile of context creation:**

```
Operation                              Time          Analogy
─────────────────────────────────────────────────────────────────
Template params lookup                 <1μs          HashMap::get()
MLS group init (2-member)              1-5ms         TLS handshake
Sender key generation (HKDF+Ed25519)   <1ms          Key derivation
Event log init (empty Merkle tree)     <1ms          Allocate a buffer
UCAN token minting (Ed25519 sign)      1-2ms         Sign a JWT
Pseudonym derivation (HKDF)            <1ms          KDF
State persistence (serialize+write)    1-5ms         Write to keychain
─────────────────────────────────────────────────────────────────
Total local computation                ~5-15ms
```

No disk provisioning. No schema migrations. No index building. No connection pooling. The local computation is a handful of key derivations and one signature. The real cost is network: delivering the invitation to the peer and receiving their join response.

**Network profile — first contact:**

```
Creator                        Relay                          Peer
   │                              │                              │
   ├─── create (local, ~10ms) ───►│                              │
   │                              │                              │
   ├─── invitation bundle ───────►├─── deliver to peer ─────────►│
   │    (metadata + MLS Welcome)  │                              │
   │                              │                              ├── evaluate
   │                              │                              │   (local, <1ms
   │                              │                              │    with template)
   │                              │                              │
   │                              │◄── MLS join + sender key ───┤
   │◄── relay forward ───────────┤                              │
   │                              │                              │
   ├── context Active ────────────┼──────────────────────────────┤
   │                              │                              │
   Total: ~10ms local + 2 relay hops (1 roundtrip with bundling)
   Wall clock: 100-500ms depending on transport latency.
   With auto-accept: no human delay. Fully autonomous.
```

With invitation bundling (§5.12.3), the peer receives metadata and MLS Welcome in one delivery. The peer evaluates the template, auto-accepts (or prompts), and joins — sending their MLS join response and sender key in one return delivery. Two relay hops total. With WebSocket transport to a shared relay, this is sub-200ms.

**Network profile — message in standing context (steady state):**

```
Sender                         Relay                          Receiver
   │                              │                              │
   ├── encrypt (local, <1ms) ────►│                              │
   ├── outer envelope ───────────►├── route to receiver ────────►│
   │                              │                              ├── decrypt
   │                              │                              │   (local, <1ms)
   │                              │                              │
   Total: 1 relay hop. Sub-50ms on WebSocket. Sub-100ms cross-relay.
```

Once a context exists, message exchange is one transport hop with sub-millisecond local crypto on each side. This is the steady-state performance for all contexts — standing or ephemeral.

#### 5.12.5 Context Lifecycle in Application Architecture

Contexts are runtime objects. They are created, used, and destroyed during normal application operation — not provisioned ahead of time, not deployed as infrastructure. The SDK manages context lifecycle the same way a network library manages connections.

**Application startup:**

```
1. sdk.init(identity, storage, transport_config)
   ├── Load identity from secure storage
   ├── Load persisted context state (all Active contexts survive restart)
   ├── Reconnect transport for all Active contexts (background, non-blocking)
   └── Begin processing queued invitations

2. Standing channels are immediately available.
   Messages sent before transport reconnects are queued locally.
   Messages received while offline are retrieved from relay on reconnect.
```

**During operation — contexts are created and destroyed fluidly:**

```
Agent lifecycle                              Context operations
──────────────────────────────────────────────────────────────────

Receives task: "coordinate with Bob"
  └── sdk.standing_channel(bob_did)          [get-or-create, ~0ms or ~200ms]
      └── channel.send("sync on project?")   [send, 1 hop]

Receives task: "negotiate contract terms"
  └── sdk.create_context(                    [create, ~200ms]
        template: "bilateral-ephemeral",
        peer: vendor_did,
        ttl: 30.minutes)
      └── ctx.send(proposal)                 [send, 1 hop]
      └── ... negotiate ...
      └── [TTL expires, context auto-closes, keys destroyed]

Receives task: "start team discussion"
  └── sdk.create_context(                    [create, ~200ms]
        template: "group-discussion")
      └── ctx.add_member(alice_did)          [MLS add, 1 roundtrip]
      └── ctx.add_member(carol_did)          [MLS add, 1 roundtrip]
      └── ctx.send("kick off meeting")       [send, 1 hop]

Application shutdown:
  └── sdk.shutdown()
      ├── Persist all Active context state
      ├── Flush pending event log entries
      └── Close transport connections
      // Contexts survive. On next startup, they reconnect.
```

**Key property: contexts survive process restarts.** Context state (MLS group state, sender keys, event log position) is persisted to secure storage on every state transition (ADR-008). When the application restarts, all Active contexts are restored and transport is reconnected. No re-creation, no re-invitation, no re-negotiation. This is why standing channels work — they persist across application sessions, device reboots, and network interruptions.

**Contexts are not connections.** A TCP connection dies when the process exits. A context does not. A context is a durable cryptographic group that happens to use connections for transport. The transport layer is replaceable (§8, ADR-012) and reconnectable. The context is the stable entity; the transport is ephemeral plumbing underneath.

#### 5.12.6 The Contact Graph

Agents that coordinate regularly maintain **standing bilateral contexts** — the agent's contact graph. A standing channel is a `bilateral-persistent` context with no TTL, created once and kept alive for the duration of the relationship.

**Lifecycle of a standing channel:**

```
Relationship stage        Protocol action                Cost
──────────────────────────────────────────────────────────────────
First contact             create_context + invitation    ~200ms (one-time)
Ongoing communication     send/receive in context        <100ms per message
Idle period               nothing (context persists)     0 (no keepalive)
Reconnect after offline   transport reconnect            background, automatic
Relationship ends         close_context                  one-time, keys preserved or destroyed per memory scope
```

**Standing channels have zero idle cost.** No keepalives, no heartbeats, no periodic key rotation (MLS key updates happen on message send, not on a timer). An agent with 500 standing channels and no active conversations uses zero network bandwidth. The only cost is local storage for persisted MLS state — approximately 2-5KB per bilateral context (two-leaf ratchet tree, sender key material, minimal event log metadata).

**Standing channels vs. ephemeral contexts — when to use which:**

| | Standing channel | Ephemeral context |
|---|---|---|
| Template | `bilateral-persistent` | `bilateral-ephemeral` |
| TTL | None (lives indefinitely) | Required (forces intentionality) |
| Memory scope | Full (history preserved) | Ephemeral (keys destroyed on close) |
| Use case | Ongoing relationship, general communication | Bounded task, sensitive negotiation, time-boxed coordination |
| Analogy | Phone contact | Phone call |
| Creation | Once per relationship | Once per interaction |

An agent typically has a standing channel with every peer it communicates with regularly, and creates ephemeral contexts on top of that for specific bounded tasks — especially tasks involving sensitive data that should not persist.

**First-contact optimization.** When two agents already share a context (e.g., both are members of a group), creating a standing channel between them is faster: both agents already have each other's DID documents and MLS key packages cached from the shared context. The SDK SHOULD use this cached key material to skip DID resolution, reducing first-contact setup to a single relay roundtrip.

### 5.13 Context Nesting

Contexts can have parent-child relationships. A child context is a full context — its own MLS group, event log, governance, roles, tools, ceiling, and membership — that is structurally and cryptographically linked to one or more parent contexts. The parent relationship constrains the child (ceiling inheritance, lifecycle coupling, membership eligibility), is visible in metadata, and is bound into the child's MLS group identity so that lineage cannot be forged or rewritten after creation.

Nesting serves two distinct purposes depending on parent count:

- **Single-parent child** — a sub-space within a context. Per-task rooms, per-topic channels, per-match game instances. The parent contains the child; the child narrows the parent's scope.
- **Multi-parent child** — a governed bridge between contexts. A shared collaboration space where members from different parent contexts interact as peers. This is the protocol's structural mechanism for symmetric cross-context communication.

```
Single-parent (sub-space):              Multi-parent (bridge):

  Context A                               Context A ──┐
    │                                                  ├── Child C
    └── Child C                           Context B ──┘
        (sub-space of A)                      (bridge between A and B)


Multi-parent chain:

  Context A ──┐
              ├── Child C ──┐
  Context B ──┘             ├── Grandchild E
                Context D ──┘
```

#### 5.13.1 Ceiling Inheritance

A child's capability ceiling is the intersection of all parent ceilings. This is enforced at creation time and is the hard security boundary that prevents capability escalation through nesting.

```
Parent A ceiling: [MessagesRead, MessagesWrite, ToolInvokeAll, Media]
Parent B ceiling: [MessagesRead, MessagesWrite, ToolInvokeAll]

Child ceiling ≤ intersection = [MessagesRead, MessagesWrite, ToolInvokeAll]
```

The child's ceiling can be equal to or narrower than the intersection — never broader. A child that only needs messaging can declare `[MessagesRead, MessagesWrite]` even if the intersection would allow tools.

If the protocol later adopts mutable ceilings (§5.3), and a parent's ceiling is reduced, the child's ceiling is retrospectively reduced to maintain the intersection invariant. If this makes the child's ceiling empty (no capabilities remain), the child closes automatically. This cascade is logged in both the parent's and child's event logs.

#### 5.13.2 Membership Eligibility

A member of a child context must be a member of **at least one** parent context. This is the eligibility pool — the set of identities that are permitted to join the child. The child's own governance (roles, admission requirements) determines who actually joins from that pool.

```
Parent A members: [Alice, Carol, Eve]
Parent B members: [Bob, Carol, Dave]

Eligible pool for child: [Alice, Bob, Carol, Dave, Eve]
  - Alice can join (via A)
  - Bob can join (via B)
  - Carol can join (via A or B — multi-anchored)
  - Dave can join (via B)
  - Eve can join (via A)
  - Frank cannot join (not in any parent)
```

**Eligibility is continuous, not one-time.** If a member is removed from their only active parent (i.e., the parent is still open but the member is individually removed from it), they lose eligibility in the child. The child's SDK detects the loss of eligibility and evicts the member — MLS remove_member, sender key rotation, event log entry. If the member is in multiple parents and loses one, they retain eligibility through the remaining parent(s).

**Detection mechanism.** Eligibility enforcement operates through the local agent orchestration layer (above the protocol boundary). The SDK maintains awareness of the user's membership across contexts locally — when local state reflects a membership loss in a parent, the SDK evaluates child eligibility and acts. This does not require cross-context protocol communication; it uses the same local state that the SDK already maintains for context management.

**Distinction from parent sever.** Individual member removal from an active parent triggers continuous eligibility enforcement. When a parent itself severs (closes or is disconnected), the outcome is governed by the `on_sever` configuration agreed upon at creation (§5.13.4), which may differ from the continuous eligibility default.

**Joining a child does not grant membership in any parent.** Bob joining child C (via eligibility through parent B) does not make Bob a member of parent A. Parent membership is independent. The child is a meeting point, not a gateway.

**Children do not confer eligibility for other children.** Membership in a child context does not make a member eligible for sibling children of the same parent, or for children of other parents. Eligibility flows downward (parent → child), never upward or sideways.

#### 5.13.3 Creation

Child context creation requires governance approval from every parent context. The creator does not need to be in all parents — they need creation rights in one parent, and governance in each additional parent must independently approve.

**Creation scenarios:**

**A. Single creator with standing in multiple parents.** Alice is a member of both A and B. She has creation rights (via her role) in both. She creates child C with parents [A, B]. Both A and B's governance approve based on Alice's standing.

```
Alice (in A + B) → sdk.create_child_context(
  parents: [context_a, context_b],
  ceiling: [MessagesRead, MessagesWrite],
  ttl: .hours(2)
)
→ A's governance approves (Alice has ContextCreate capability in A)
→ B's governance approves (Alice has ContextCreate capability in B)
→ Child C created
```

**B. Coordinated creation across contexts.** Alice is in A with creation rights. Bob is in B with creation rights. Neither is in the other's context. They coordinate (via a bilateral context, shared context, or out-of-band) to create child C.

Coordination uses an intrinsic tool call available within each context's governance. Alice invokes the child-creation tool in A with the proposed child params and the list of co-parents. A's governance evaluates and, if approved, publishes a **child creation proposal** — a signed, content-addressed record of the approved params. Bob does the same in B. The protocol matches proposals by their content hash: when all proposed parents have published matching proposals (identical child params), the child is created. Proposals expire after a configurable timeout (suggested default: 1 hour).

```
Alice (in A) → invokes child creation tool → A's governance approves
             → A publishes proposal { hash(child_params), parent_list, approval_sig }
Bob (in B)   → invokes child creation tool → B's governance approves
             → B publishes proposal { hash(child_params), parent_list, approval_sig }
Protocol matches proposals by content hash
→ Child C created
→ Both Alice and Bob are initial members
```

This reuses the existing tool call model — no new protocol primitive. The child creation tool is intrinsic to contexts that include the `ChildContextCreate` capability in their ceiling.

**C. Member proposal without creation rights.** Alice is in A but her role doesn't include creation rights. She proposes the child through A's governance (§5.9). A's governance evaluates and either approves or rejects the proposal. If approved, the governance itself authorizes the creation on A's behalf. Same process on B's side.

**Creation protocol:**

1. **Initiator constructs child params:** ceiling (must be ≤ intersection of parent ceilings), governance model, roles, TTL (must be ≤ minimum parent TTL if parents have TTLs), memory scope, tools, and the parent governance configuration (§5.13.4).
2. **Governance proposal sent to each parent.** The proposal includes the full child params plus the list of all proposed parents. Each parent's governance evaluates independently.
3. **All parents approve.** The child context is created. Creation is logged in every parent's event log and in the child's event log.
4. **Any parent rejects.** Creation fails. No child is created. The rejection is not logged (the proposal never materialized).

**Cryptographic binding.** When the child's MLS group is initialized (step 3), the parent context IDs and the content hash of the parent governance configuration are included in the MLS `group_context` extensions field. This makes the parent lineage part of the child's cryptographic group identity — the `group_id` derived from the `group_context` is a function of the parent references. Consequences:

- **Lineage is unforgeable.** Claiming different parents after creation would require creating a new MLS group with a different `group_id`. Any member can verify the parent lineage by inspecting the `group_context` extensions — no trust in metadata required.
- **Two independent verification paths.** The parent relationship is recorded in both the MLS `group_context` (cryptographic, part of the group identity) and the event log (Merkle tree, signed entries). Both would need to be compromised to forge lineage.
- **Governance config is tamper-evident.** The content hash of the `ParentGovernanceConfig` in the `group_context` means any discrepancy between the claimed governance configuration and the cryptographically committed one is detectable.

**Parent awareness.** When Context A's governance receives a child creation proposal that includes Context B as a co-parent, A's governance sees B's context metadata (§5.7) — ceiling, member count, governance model, age, etc. This is the same metadata visible to anyone inspecting a context before joining. A's governance can evaluate whether a relationship with B is acceptable based on this metadata.

#### 5.13.4 Parent Governance Configuration

The governance relationship between parents and child is configurable at creation time — not prescribed by the protocol. The creators (with parent governance approval) configure a set of parent governance permissions that define what authority each parent retains over the child after creation.

**Configurable permissions (per parent):**

```
ParentGovernanceConfig {
  can_close_child:       Bool    // Can this parent unilaterally close the child?
  can_evict_members:     Bool    // Can this parent evict members from the child?
  can_restrict_ceiling:  Bool    // Can this parent further restrict the child's ceiling?
  requires_approval_for: [       // What child operations require this parent's approval?
    | GovernanceChange           // Child governance model changes
    | ToolRegistration           // New tools added to child
    | CeilingChange              // Child ceiling modifications (if mutable)
    | MembershipChange           // Members added/removed
  ]
  on_sever: .evict_unique_members  // When this parent severs: evict members eligible only through this parent
          | .cascade_close          // When this parent severs: close the child entirely
          | .preserve_membership    // When this parent severs: child continues, current members retain membership
                                    // (members lose their eligibility anchor but keep their seat — a deliberate
                                    // governance choice to prioritize continuity over strict eligibility enforcement)
}
```

**Both parents agree on EACH OTHER'S configuration at creation time.** This is mutual consent — A sees what governance authority B will have over the child, and vice versa. The configuration is visible in the child's metadata (§5.7) so members can evaluate the governance structure before joining.

**Examples of common configurations:**

**Symmetric collaboration** (two teams working together):
```
Parent A config: { can_close: false, can_evict: false, can_restrict: false,
                   requires_approval_for: [], on_sever: .evict_unique_members }
Parent B config: { same as A }
// Neither parent can unilaterally control the child. Severing removes that
// parent's unique members. The child governs itself within the ceiling.
```

**Durable joint venture** (relationship outlives either parent):
```
Parent A config: { can_close: false, can_evict: false, can_restrict: false,
                   requires_approval_for: [], on_sever: .preserve_membership }
Parent B config: { same as A }
// If either parent closes, the child continues with all current members.
// Members who were eligible only through the severed parent keep their seat.
// The child's own governance takes over fully. Use when the child's work
// should survive parent reorganization.
```

**Service relationship** (B provides a service to A's members):
```
Parent A config: { can_close: true, can_evict: false, can_restrict: false,
                   requires_approval_for: [], on_sever: .cascade_close }
Parent B config: { can_close: false, can_evict: false, can_restrict: true,
                   requires_approval_for: [ToolRegistration], on_sever: .cascade_close }
// A can shut down the relationship. B controls the tools (it's the service provider).
// If either severs, the child closes entirely.
```

**Supervised sub-space** (single-parent nesting):
```
Parent A config: { can_close: true, can_evict: true, can_restrict: true,
                   requires_approval_for: [GovernanceChange, CeilingChange],
                   on_sever: .cascade_close }
// Full parental authority. The child is a room within A.
```

**The parent governance configuration is immutable after creation.** Changing it would require creating a new child with different configuration. This prevents governance bait-and-switch — members join the child knowing exactly what authority each parent has, and that doesn't change.

#### 5.13.5 Lifecycle Coupling

**Children cannot outlive all parents. No orphans.**

- When a parent context closes (manually or via TTL expiry), the parent-child relationship severs. The `on_sever` action configured for that parent executes.
- If the last parent closes, the child closes regardless of `on_sever` configuration. A child with no parents has no trust anchors and no structural governance authority. It closes. Even `.preserve_membership` cannot prevent this — the option preserves membership through individual parent severances, not through the loss of all parents.
- Children can close independently without affecting any parent. A child closing is logged in every parent's event log.

**TTL inheritance.** A child's TTL cannot exceed the minimum TTL of its parents (among parents that have TTLs). If parent A has TTL = 1 hour and parent B has no TTL, the child's TTL is bounded by 1 hour. If neither parent has a TTL, the child's TTL is unconstrained.

Rationale: TTL is part of the opt-in contract (§5.10). Parent A's members consented to a 1-hour interaction. A child that outlives A would extend the interaction's footprint beyond what A's members expected. Bounding the child's TTL by the parent's prevents this.

**Lifecycle event log entries:**

```
In parent's event log:
  ChildCreated { child_id, co_parents: [contextID], creator: DID, ceiling, config }
  ChildClosed  { child_id, reason: .manual | .ttl_expiry | .parent_sever | .orphaned }

In child's event log:
  Created           { parents: [contextID], ceiling, config }
  ParentSevered     { parent_id, reason: .closed | .manual_sever, action: on_sever }
  MemberEvicted     { did, reason: .parent_sever(parent_id) }
  ClosedByOrphan    { last_parent_id }
```

#### 5.13.6 Metadata and Legibility

Child context metadata (§5.7) includes all standard context metadata plus:

- **Parent context IDs.** The full list of parent contexts.
- **Parent metadata summaries.** For each parent: ceiling, governance model, member count, age. Enough to evaluate the trust basis without joining the parent.
- **Parent governance configuration.** What authority each parent has over the child (§5.13.4).
- **Eligibility basis.** Which parent(s) the prospective member would join through.

This means a member evaluating whether to join a child sees: "This is a child of contexts A and B. A has 30 members, single-admin governance, ceiling [msg, tools]. B has 15 members, multi-sig governance, ceiling [msg]. The child's ceiling is [msg]. Parent A can close the child unilaterally. Parent B cannot. If A severs, members from A only are evicted."

Full legibility before opt-in applies to nesting relationships the same as everything else in the protocol. No hidden parent governance. No undisclosed co-parents.

#### 5.13.7 Interaction with Other Mechanisms

**Templates.** Well-known templates (§5.12.1) can be used for child contexts. The template constrains the child's params as usual; the parent relationship adds the ceiling intersection and lifecycle coupling on top. A child created from `bilateral-ephemeral` with two parents is an ephemeral bridge — TTL'd, keys destroyed on close, ceiling ≤ intersection.

**Standing channels.** A standing channel (§5.12.6) between Alice and Bob can be modeled as a multi-parent child of whatever context(s) Alice and Bob share. This is not required — standing channels remain lightweight bilateral contexts that work without nesting. But if structural governance over the standing channel is desired (a parent context's governance should have authority over the channel), nesting provides that.

**Tool interfaces.** Tool interfaces (§6.2) and multi-parent children serve different purposes and coexist:

| | Tool interface | Multi-parent child |
|---|---|---|
| Relationship | Asymmetric (caller/tool) | Symmetric (peers) |
| Data flow | Structured (schema-declared) | Full context (messages, tools, everything) |
| Governance | Both contexts govern each call | Configured at creation, child self-governs |
| Duration | Per-call (or per-session) | Persistent (until closed or TTL) |
| Use case | Service calls, data queries | Collaboration, negotiation, ongoing A2A |

A context might use both: tool interfaces for structured service queries and a multi-parent child for ongoing collaboration with the same counterpart.

**Provenance.** Data originating in a child context carries provenance (§7.7) that includes the child's parent lineage. When data from a child crosses another context boundary (via tool interface or further nesting), the provenance chain includes the child and its parents. This makes the trust basis structurally legible: "this data came from a child of A and B" tells the receiver more than "this data came from some context."

**Auto-accept policies.** Auto-accept policies (§5.12.2) can be extended to cover child context invitations. A policy might specify: "auto-accept invitations to children of contexts I'm already in, with ceiling ≤ [MessagesRead, MessagesWrite], TTL ≤ 10 minutes." The parent lineage provides a stronger trust signal than a standalone context invitation — the member knows the child is governed by contexts they already participate in.

#### 5.13.8 Nesting Depth

The protocol enforces a maximum nesting depth (suggested default: 3 levels). A child of a child of a child is permitted; a fourth level is rejected. This bounds:

- Governance complexity (each level adds configurable permissions)
- Ceiling reduction (each level can only narrow, so deep nesting converges on empty ceilings)
- Lifecycle cascade depth (closing a grandparent cascades through children and grandchildren)
- Trust evaluation complexity (provenance with deep nesting lineage is harder to evaluate)

The nesting depth limit is a protocol constant, not configurable per context. It applies to the longest path from any root ancestor to the context being created.

---

## 6. Cross-Context Communication

### 6.1 Agent Isolation

Agents cannot cross contexts at the protocol level. This is absolute. An agent in Context A cannot send a message to Context B, read Context B's state, or interact with Context B's tools or members. From the protocol's perspective, the agent in A and the agent in B (even if operated by the same human) are entirely separate instances.

Information may cross context boundaries through two protocol-level mechanisms:

1. **Cross-context tool interfaces (§6.2)** — asymmetric, structured, request/response. One context queries another's tool. Governed by both contexts per call.
2. **Multi-parent child contexts (§5.13)** — symmetric, full context. A shared space governed by multiple parent contexts. Members from different parents interact as peers.

Both mechanisms require explicit consent from all involved contexts. Neither allows agents to directly access another context's state. The first is for service-style interactions; the second is for collaborative ones.

### 6.2 Context-to-Context Tool Interfaces

Contexts can expose tool endpoints to other contexts. **The context governs the tool call, not the agent.** An agent in Context A does not directly contact Context B — the agent requests from Context A, Context A's governance decides whether to permit the outbound call, and Context B's governance decides whether to permit the inbound call and how to respond. Both contexts mediate. The agent never directly touches the other context.

This is the mechanism for all structured inter-agent interaction across context boundaries. It is strictly stronger governance than any agent-to-agent direct channel because both contexts' governance models, capability ceilings, and role permissions gate every interaction.

Properties:

- Both contexts opt in explicitly (bidirectional consent at the context level, not the agent level).
- Data flows through defined function signatures, not through agent memory or discretion.
- Auditable: every call through an interface is logged in both contexts' event logs with full provenance (§7.7).
- Tool interfaces carry provenance: data received through an interface carries its origin context, invoking agent, timestamp, and chain depth (§7.7.1).
- Rate-limited: both contexts can enforce rate limits on interface calls.
- **Chain depth limit.** Cross-context tool calls carry a `chain_depth` counter, incremented on each hop. A tool call at maximum depth (protocol default: 3) cannot trigger further cross-context tool calls. This bounds amplification and makes transitive provenance degradation mechanically enforced (§9.2.1).
- **Schema constraints.** Tool schemas must satisfy a structural specificity floor at registration time — no unbounded string-only interfaces, minimum two distinct fields in input or output. This prevents degenerate broad-schema tools that function as arbitrary message channels (§9.2.1).

#### 6.2.1 Stateful Tool Sessions

Tool interfaces support optional session-based multi-turn interaction. A tool can accept a session identifier and maintain state across sequential invocations. This enables multi-step workflows (negotiation, coordination, iterative refinement) within the governed tool call framework.

```
// First call: initiate a scheduling session
Context A → Context B tool "schedule_meeting":
  input:  { action: "propose", times: ["Tue 3pm", "Thu 2pm"] }
  output: { session_id: "sched:abc123", status: "pending", counter: ["Tue 4pm"] }

// Second call: continue the session
Context A → Context B tool "schedule_meeting":
  input:  { session_id: "sched:abc123", action: "accept", time: "Tue 4pm" }
  output: { session_id: "sched:abc123", status: "confirmed", time: "Tue 4pm" }
```

Session state is maintained by the tool's context (Context B), not by the calling agent. Each call in the session is individually governed — Context A's governance permits each outbound call, Context B's governance permits each inbound call. The session does not create a persistent channel; it is a sequence of governed tool calls that share state via an opaque session identifier.

Sessions have an optional TTL set by the tool's context. When set, expired sessions are garbage-collected automatically. Sessions without a TTL persist for the lifetime of the context — appropriate for app-hosted sessions (games, workspaces, collaborative tools) where the context itself is the session's lifecycle boundary. Contexts enforce a per-caller session cap (suggested default: 5 concurrent sessions per calling context) to prevent session exhaustion attacks regardless of TTL (§9.2.1). Session state is internal to the tool's context and not visible to the calling context beyond the tool's defined output schema.

#### 6.2.2 Protocol-Level Discovery

With no separate discovery primitive (A2A removed), discovery is built from two complementary mechanisms: DID document capabilities (direct lookup) and discovery contexts (searchable registries). Together, these provide 0-setup discovery that makes SCP inherently social.

##### A. DID Document Capabilities

Every agent MAY publish structured capabilities in their DID document's `service` array. These are resolved via did:dht — always available, 0-setup, no context required. Any agent that knows a DID can resolve the document and inspect capabilities directly.

```json
{
  "id": "#scp-capabilities",
  "type": "SCPCapabilities",
  "serviceEndpoint": {
    "capabilities": ["translation", "japanese", "english"],
    "version": "scp/1.0"
  }
}
```

DID document capabilities provide direct lookup for any known DID. They do not provide search or browsing — for that, discovery contexts are needed.

##### B. Discovery Contexts

Discovery contexts are standard SCP contexts with open join policies and standardized discovery tools. Anyone can create one. No central authority, no operator dependency. They inherit all context-governed properties: tool calls are rate-limited and auditable, results carry provenance.

**Standard discovery tool schemas** — minimum interoperable interface:

```
agent_search(query) → results
  input:  { capability: string?, keywords: [string]?, min_history: int? }
  output: { results: [{ did: DID, capabilities: [string], behavioral_summary: object }] }

agent_register(did, capabilities, metadata) → confirmation
  input:  { did: DID, capabilities: [string], metadata: { description: string?, tags: [string]? } }
  output: { registered: bool, entry_id: string }

agent_deregister(did) → removal
  input:  { did: DID }
  output: { removed: bool }
```

These are conventions, not mandates — discovery contexts can add custom tools (e.g., reputation scoring, category browsing, geographic filtering) beyond the standard schema.

**Two-tier membership model.** Discovery contexts use a two-tier architecture to support unbounded scale while maintaining MLS-based governance:

- **Writer tier (MLS members, bounded).** Writers are standard MLS group members. They can register/deregister entries, modify governance, and process registration requests. The MLS group is bounded at ~500 members to maintain practical epoch advance costs (O(N) cost per MLS Update). Writers are typically registry operators, curators, and high-volume registrants.
- **Reader tier (DID-authenticated, unbounded).** Readers query the discovery context's tool endpoints via DID-signed requests without joining the MLS group. They can search (`agent_search`), inspect entries, and request inclusion proofs from the Merkle event log. No MLS membership required, no epoch advance cost. Reader capacity is unbounded.
- **Registration flow.** A reader (non-MLS-member) registers by sending a DID-signed registration request to the context's `agent_register` tool endpoint. A writer processes the request and records it as an MLS application message in the event log. The registrant does NOT become an MLS member — their entry is stored in the context's registry data, and they can update or deregister via subsequent DID-authenticated requests to tool endpoints, processed by writers.
- **Self-service updates.** Registered agents update their entries via DID-authenticated requests to tool endpoints. Writers verify the DID signature matches the entry owner and process the update.
- **Consistency.** All writes are recorded in the Merkle event log. Readers can request inclusion proofs to verify their registration was recorded and to audit the registry's integrity.

**Bootstrap / cold-start.** How agents find their first discovery context:

- SDK ships with default discovery context IDs (configurable, analogous to browser CA lists or DNS root servers). These are not privileged — they are starting points.
- Apps can add domain-specific discovery contexts (e.g., a cooking community registry, a translation services directory).
- On first identity creation, the SDK auto-queries default discovery contexts and optionally self-registers (opt-out via configuration). Registration does not require MLS group membership.
- If all defaults are unavailable, agents fall back to direct DID resolution for known contacts and manual context ID sharing.

**Operation model.** Anyone can run a discovery context:

- Creator sets governance: who can register, metadata requirements, moderation rules (via standard context governance, enforced by writers).
- Storage: structured metadata entries (~100-500 bytes per agent), not conversation history. Scale is limited only by relay storage capacity — the MLS group (writers) stays small regardless of registry size.
- No operator dependency: if one registry disappears, agents use others. DID + capabilities persist in the agent's DID document regardless.

**SDK unification.** The SDK provides a unified discovery API:

- Searches local contact index (cache of previously resolved DID documents — instant)
- Queries each known discovery context (standard tool calls)
- Returns merged, deduplicated results ranked by relevance

**Privacy.** Registration is opt-in per discovery context. Agents control what metadata they publish in each registry. Registration can be withdrawn at any time via `agent_deregister`. An agent can be registered in one discovery context with full capabilities listed and in another with only a subset. DID document capabilities are controlled by the agent via DID document updates.

### 6.3 The Human as Bridge

The human coordinates across their own contexts locally. Their local agent orchestration — unconstrained by the protocol — handles cross-context intelligence. For the human's own agents, the human remains the bridge — local coordination across their own contexts requires no network-level mechanism.

Two protocol-level mechanisms formalize cross-context relationships: tool interfaces (§6.2) for asymmetric service-style interactions, and multi-parent child contexts (§5.13) for symmetric collaboration. Both require governance consent from all involved contexts. The human's local coordination handles everything that doesn't need to be on the network — and when a cross-context relationship should be visible, governed, and persistent, a multi-parent child context makes the bridge structural rather than implicit.

**Two-tier interaction model.** The protocol provides two tiers of cross-agent communication with different overhead appropriate to different risk profiles:

- **Shared contexts** (bilateral or multi-party) for lightweight, symmetric, low-ceremony communication. A message in a shared context is encrypt-send-decrypt with no per-message governance overhead. All the protocol's trust and encryption properties apply. This is the equivalent of a text message.
- **Tool interfaces** for formal, structured, asymmetric cross-context data exchange. Full governance mediation on both sides, schema-declared data flow, audit logging, rate limiting, provenance attachment. This is the equivalent of an API call.

Agents use whichever tier fits the interaction. Lightweight coordination ("are you available?", "quick update") flows through shared contexts. Formal cross-context data queries flow through tool interfaces. Both are governed; the difference is in ceremony and auditability per interaction.

---

## 7. Trust, Validation, and Capabilities

### 7.1 Design Principle: Validate, Minimize Trust

The protocol's security model is not built on trust. It is built on maximizing the surface area of what can be independently verified, so that trust is required only where validation is impossible.

Trust is a vulnerability. Every claim that requires trust to accept is a claim that can be exploited. The protocol's goal is to push claims down from the trust layer into the validation layer — replacing "someone says X" with "the protocol can verify X" at every opportunity.

The system has four layers, from hardest (pure validation) to softest (pure judgment):

```
┌─────────────────────────────────────────────────────────────┐
│  LAYER 1: PROTOCOL ENFORCEMENT (zero-trust, mandatory)       │
│                                                               │
│  Capability tokens verified on every action. Signatures      │
│  checked. UCAN chains validated. Revocations honored.        │
│  Capability ceilings enforced. Role permissions enforced.    │
│                                                               │
│  100% validation. 0% trust. No exceptions.                   │
├─────────────────────────────────────────────────────────────┤
│  LAYER 2: BEHAVIORAL VALIDATION (automated, objective)       │
│                                                               │
│  Verifiable event logs (Merkle trees per context).           │
│  Behavioral records derived from protocol events.            │
│  Tool verification via deterministic testing.                │
│  Challenge-response for testable agent capabilities.         │
│  Threshold attestation counting.                             │
│  Consequence mechanism evaluation.                           │
│  Attestation freshness / time-locked renewal.                │
│                                                               │
│  Mostly validation. Minimal trust.                           │
│  This layer GROWS as the network accumulates history.        │
├─────────────────────────────────────────────────────────────┤
│  LAYER 3: ATTESTATION AUTHENTICITY (automated, signatures)   │
│                                                               │
│  Attestation signatures verified. Evidence checked where     │
│  objectively checkable (OAuth proofs, DNS records, hashes).  │
│  Claims are verified as REAL (really signed by who they      │
│  claim). Not verified as TRUE.                               │
├─────────────────────────────────────────────────────────────┤
│  LAYER 4: TRUST EVALUATION (agent-level, subjective)         │
│                                                               │
│  Endorsement weighting. Judgment calls.                      │
│  Required for: new identities with no history,               │
│  non-testable capabilities, novel situations.                │
│                                                               │
│  This layer SHRINKS as behavioral validation grows.          │
│  Trust is the bootstrap. Validation is the steady state.     │
└─────────────────────────────────────────────────────────────┘
```

The critical property: **the trust surface shrinks over time.** New identities start trust-heavy — no behavioral history, need endorsements, can't be validated beyond their signatures. As they participate, behavioral records accumulate, tool interactions are verified, challenge-responses are completed. The validation layers grow. Trust becomes supplementary, then marginal.

### 7.2 Layer 1: Protocol Enforcement

Every protocol action is zero-trust. An agent presents a UCAN capability token with every action. The protocol validates mechanically:

- Signature chain is valid (cryptographic verification)
- Capability matches the action being performed
- Context capability ceiling permits the action
- Agent's role includes the required permission
- Token hasn't been revoked
- Token hasn't expired

No action proceeds on reputation or identity alone. A trusted DID with an expired token is denied. An unknown DID with a valid token is permitted. This layer is mandatory and non-negotiable.

**Capability tokens** are fine-grained, per-agent, per-context, per-capability. Build on UCAN (User Controlled Authorization Networks). A human grants their agent specific capabilities for specific contexts. Tokens are independently revocable — you can revoke one capability from one agent in one context without affecting anything else. The UCAN chain provides verifiable delegation: the protocol can trace any token back to the root authority that granted it.

### 7.3 Layer 2: Behavioral Validation

This is the layer that replaces trust with evidence. It grows as the network accumulates history, and it is the primary mechanism by which SCP minimizes trust dependencies over time.

#### 7.3.1 Verifiable Event Logs

Every context maintains a verifiable event log — a Merkle tree (or equivalent authenticated data structure) of all protocol events: messages, tool invocations, membership changes, role assignments, governance actions. Events are signed by the acting agent and sequenced.

Any participant can verify claims about context history against the Merkle root:

- "Carol has never had a governance action taken against her in Context A" — verifiable via proof-of-absence against Context A's log.
- "This tool was registered on date X by DID Y" — verifiable via proof-of-inclusion.
- "The context's capability ceiling has not changed since creation" — verifiable via the log's mutation history.

This transforms claims about the past from trust-dependent to validation-dependent. You don't need to trust a context admin's account of what happened — you verify it against a cryptographic data structure.

#### 7.3.2 Behavioral Records

The protocol defines a standard behavioral record format derivable from context event logs. A behavioral record is not a reputation score (opaque, gameable, subjective). It is a set of verifiable facts:

- Number of contexts participated in, with duration
- Tool invocations by type and frequency
- Governance actions taken against this identity (warnings, role demotions, ejections)
- Governance actions taken by this identity (if in a governance role)
- Role progression history (promotions, demotions)
- Attestation history (endorsements issued, endorsements received, endorsement accuracy)
- Context creation history

Each fact is verifiable against the relevant context's Merkle root. The behavioral record is not stored centrally — it is computed by any agent from the set of context logs they can access.

Behavioral records replace endorsements as the primary input to evaluation for established identities. Instead of "Bob says Carol is trustworthy for scheduling," the evaluating agent can see: "Carol has invoked scheduling tools 203 times across 14 contexts over 8 months. Zero governance actions. Three contexts promoted her to admin." These are facts, not opinions. Validated, not trusted.

#### 7.3.3 Tool Verification

SCP tools are stateless functions with broadly deterministic behavior — consistent behavior and output format for a given input, though not necessarily token-for-token identical output. An LLM-backed tool that answers cooking questions in a consistent schema is "stateless" in the protocol's sense. This makes tool integrity **testable** at the behavioral level.

When a tool is registered with a context, the registration includes:

- Schema (input and output types, MCP-compatible JSON Schema)
- Implementation hash (content-addressable reference to the implementation)
- Test vectors (known input-output pairs that define correct behavior)
- Operator DID (who registered the tool and is accountable for it)

Any agent can verify a tool's integrity at any time by:

1. Calling the tool with test vector inputs
2. Comparing outputs against expected values
3. Verifying the implementation hash hasn't changed since registration

Test vectors verify behavioral conformance and schema compliance, not exact string matching. A tool that returns a correct answer in a valid schema passes, even if the phrasing differs between invocations. If outputs diverge from expected behavior: the tool has been modified or compromised. Detectable, attributable to the operator.

Multiple agents verifying independently creates threshold confidence. If 10 agents all get expected outputs, the tool is almost certainly behaving correctly. This is continuous validation, not a one-time trust decision.

Tool mutations (new implementation hash, modified schema, changed test vectors) are context-level events recorded in the Merkle log, visible to all members. An agent can set its own policy: refuse to call tools that have changed since it joined, accept changes from trusted operators, or require N independent verifications after any change.

#### 7.3.4 Challenge-Response Verification

Self-reported agent capabilities can be challenged rather than trusted. The protocol defines standard challenge suites for testable capabilities.

An agent claims "prompt injection filtering: true" in its capability metadata. A context or peer agent can issue a challenge: a set of test cases that exercise the claimed capability. The challenged agent processes the tests and returns results. The challenger verifies the results demonstrate the claimed capability.

Properties:

- **Repeatable.** Challenges can be re-issued at any time. An agent that passed a challenge last month can be re-challenged today.
- **Standardized.** The protocol defines challenge suites for common capabilities (prompt injection resistance, schema validation, rate limit compliance, content formatting). Custom challenges are possible for context-specific capabilities.
- **Distinguishable.** Agent capability metadata distinguishes between self-attested capabilities (claimed but untested) and challenge-verified capabilities (tested and passed, with timestamp of last verification). Other agents can factor this distinction into their evaluation.

Not all capabilities are testable. "Good judgment" is not challengeable. But many defensive and functional capabilities are, and for those, challenge-response replaces trust with validation.

#### 7.3.5 Threshold Attestations

A single attestation requires trust in one party. Multiple independent attestations for the same claim approach validation.

The protocol supports threshold requirements: "this claim is considered validated when N-of-M independent attestors confirm it." Independence is verifiable — the protocol can check whether attestors share context memberships, have mutual endorsement relationships, or exhibit other correlation patterns that would reduce independence.

Threshold attestations are useful for:

- Context admission ("3 independent endorsements required for admin role")
- Tool integrity ("5 agents independently verified this tool's test vectors")
- Identity claims ("2 unrelated parties confirm this identity link")

The threshold count, independence requirements, and verification are all mechanical. The trust component shrinks as the threshold increases.

#### 7.3.6 Time-Locked Attestation Renewal

A claim verified once is a fact about the past. A claim that must be continuously renewed is a fact about the present.

The protocol defines standard renewal intervals by attestation type. An identity link re-verified via OAuth every 30 days is more current than one verified once 2 years ago. A tool integrity check run weekly is more trustworthy than one run at registration.

Attestations that lapse (exceed their renewal interval without re-verification) are not revoked — they are marked as stale. Agents factor staleness into evaluation. Fresh attestation = high validation confidence. Stale attestation = degraded confidence, approaching trust-only.

Renewal is automated where possible. Identity links can be re-verified in the background. Tool integrity checks can run on a schedule. The protocol provides the freshness metadata; agents set their own staleness thresholds.

#### 7.3.7 Consequence Mechanisms

If misbehavior has automatic, protocol-enforced consequences, trust in an individual's character becomes unnecessary. You verify that the consequence structure makes misbehavior irrational.

Contexts can define **automated consequence rules** as part of their governance model:

- Message velocity exceeds threshold → capability suspension for defined period
- Tool invocation rate exceeds threshold → tool access revoked pending governance review
- Multiple governance warnings → automatic role demotion
- Capability ceiling violation attempt → action rejected and logged

These rules are:

- **Declared at context creation.** Visible in context metadata before opt-in.
- **Protocol-enforced.** Not governance-discretion. Triggers are mechanical, consequences are automatic.
- **Verifiable.** Any agent can evaluate the consequence structure and determine whether misbehavior is irrational given the costs.

Consequence mechanisms transform "do I trust this agent to behave?" into "are the consequences of misbehaving sufficient to make it irrational?" The latter is a validation question, not a trust question.

### 7.4 Layer 3: Attestation Authenticity

Attestations are signed claims by identities about something. The protocol verifies their authenticity — that the claim was really made by the stated issuer — but not their truth.

#### 7.4.1 Attestation Format

All attestations use a common envelope format:

```
Attestation {
  id:          unique identifier
  type:        identity_link | capability_delegation | tool_integrity |
               endorsement | role_assignment | agent_capability |
               context_endorsement | behavioral_witness
  issuer:      DID of the entity making the claim
  subject:     what the claim is about (DID, tool_id, context_id, etc.)
  claim:       structured content (type-specific)
  evidence:    supporting proof (type-specific, optional)
  issued_at:   timestamp
  expires:     optional TTL
  renewed_at:  timestamp of last renewal (if renewable)
  revocation:  how to check if revoked
  signature:   issuer's cryptographic signature
}
```

The envelope is the same regardless of attestation type. Verification of the envelope (signature, expiry, revocation) is automated and mechanical. Interpretation of the claim content depends on the type.

#### 7.4.2 Attestation Types

**Identity link.** Issuer attests they control an external platform identity. Evidence: platform-specific proof (OAuth, signed post, DNS record). Verification of the evidence is automated where possible.

**Capability delegation.** UCAN token granting specific capabilities. Evidence: the UCAN delegation chain. Verification: cryptographic chain validation. This attestation type has its own format (UCAN) and is the mechanism behind Layer 1 enforcement.

**Tool integrity.** Tool operator attests their tool's behavior and implementation. Evidence: implementation hash, test vectors. Verification: deterministic testing (Layer 2).

**Agent capability.** Human attests their agent's capabilities and defenses. Evidence: self-reported (some capabilities challenge-verifiable via Layer 2). Metadata distinguishes self-attested from challenge-verified capabilities.

**Endorsement.** One identity vouches for another's competence in a specific capability. No objective evidence — the value comes from the issuer's own behavioral record and the attestation's accuracy history. This is the attestation type that lives primarily in Layer 4 (trust), but endorsement accuracy tracking (did the endorsed identity subsequently misbehave?) pushes it toward Layer 2 over time.

**Role assignment.** Context governance assigns a role to an agent. Evidence: governance action signed by authorized DIDs. Verification: validate against governance model and UCAN chain.

**Context endorsement.** Any identity vouches for a context's legitimacy. Subjective, but endorser's behavioral record provides validation context.

#### 7.4.3 Solicitation and Presentation

Attestations are solicited and presented through several patterns:

- **Self-initiated.** Users create and publish their own attestations (identity links, agent capability metadata). No solicitation required.
- **Context-required.** A context's admission criteria specify required attestations. "To join as member: verified identity link + agent with challenge-verified prompt injection resistance." Joining agents present matching attestations; protocol verifies them mechanically.
- **Peer-requested.** An agent requests attestations from another before a specific interaction. "Present your scheduling endorsements." Responding agent provides matching attestations on demand.
- **Unsolicited.** Endorsements can be offered without request. Published to the discovery layer for anyone to find.
- **Embedded in actions.** UCAN tokens travel with the actions they authorize. Tool integrity attestations travel with tool outputs.

#### 7.4.4 Revocation

All attestations are independently revocable by their issuer. Revocation is published and checkable — the attestation format includes a revocation reference (endpoint, DID document entry, or Merkle log reference) that any verifier can check. Revocation is immediate for new verifications; agents that cached a previous verification should re-check on a defined interval.

### 7.5 Layer 4: Trust Evaluation

After all validation layers have run, some evaluation remains that requires judgment. This is the trust layer — the part that cannot be mechanized.

Trust evaluation is needed for:

- **New identities with no behavioral history.** A brand-new DID has no behavioral records, no tool verification history, no challenge-response results. Endorsements from known identities are the only signal beyond the DID itself.
- **Non-testable capabilities.** "Good judgment," "domain expertise," "social reliability" — capabilities that can't be verified via challenge-response or behavioral records.
- **Novel situations.** First interactions with unfamiliar contexts, tools, or agents where no prior data exists.

Trust evaluation is agent-level. The protocol provides inputs (verified attestations, behavioral records, challenge-response results, consequence structures). The agent decides. Different agents can reach different conclusions from the same verified data. This is by design.

**Transitive trust.** "I trust John's agent for scheduling" is a statement about John's identity + a specific capability. If John's agent misbehaves, that reflects on John via behavioral records. Trust in John's other capabilities is unaffected unless the evaluating agent reassesses. This mirrors how humans already think: "I trust John with my calendar but not my wallet." The protocol provides the data to make this granular evaluation. The agent applies the judgment.

**Trust decay.** As behavioral validation accumulates, trust evaluation becomes less necessary. An identity with 12 months of verified behavioral history across 20 contexts needs fewer endorsements than an identity created yesterday. The protocol doesn't mandate this decay — agents implement their own trust strategies — but the availability of behavioral validation data naturally displaces endorsement-based trust for established identities.

### 7.6 Attestation as Protocol Primitive

Attestation is not a feature of any single section of SCP — it is a primitive used by every layer:

- **Identity (§3):** Identity links are attestations binding external handles to DIDs.
- **Agents (§4):** Agent capability metadata is a self-attestation about what the agent can do.
- **Contexts (§5):** Role assignments are attestations by governance about an agent's permissions. Tool registrations include integrity attestations.
- **Trust (§7):** Capability tokens (UCAN) are delegation attestations. Endorsements are trust attestations. Behavioral records are computed from verified event attestations.
- **Security (§9):** Provenance chains are sequences of attestations about where data came from. Provenance is a core protocol principle (§1) — all non-private data carries verifiable origin.
- **Bridges (§12):** Shadow identity claims are bridge operator attestations. Identity claiming is a self-attestation verified against the shadow.

The common envelope format (§7.4.1) unifies these under a single verifiable structure. The verification mechanics are the same regardless of attestation type: check signature, check evidence, check expiry, check revocation. What varies is the claim content and how it's evaluated.

### 7.7 Data Provenance

Provenance is a core principle of SCP (§1): all non-private data carries verifiable origin metadata. This section specifies how provenance is implemented for data that crosses context boundaries. Provenance applies protocol-wide — messages carry sender provenance (DID + context + timestamp), attestations carry issuer provenance (DID + evidence + expiry), tool outputs carry invocation provenance (tool + invoking agent + context), and cross-context data carries origin provenance (source context + counterparties + discovery method). The absence of provenance on any data is itself a signal that the data has no verified origin.

#### 7.7.1 Provenance Format

Data provenance is a structured record attached to data at the protocol level:

```
DataProvenance {
  sourceContext:     contextID               // where the data originated
  sourceType:        .persistent | .ephemeral | .summary   // source data availability
  counterparties:    [DID]                   // who was in the source interaction
  purpose:           String                  // declared purpose of source context
  discoveryMethod:   .sharedContext(contextID)
                   | .registry(registryContextID)
                   | .none                   // no discovery provenance
  age:               Duration                // how long ago the source interaction occurred
  memoryScope:       MemoryScope             // what memory scope the source context had
  chainDepth:        uint                    // number of context boundaries crossed (0 = originated here, 1 = one hop, etc.)
  chainPath:         [contextID]?            // optional: ordered list of intermediary context IDs in the chain
}
```

Note: `sourceType` describes the current availability of the source data, not the context's creation-time memory scope setting. A context created with `memoryScope: .full` that is still open has `sourceType: .persistent` (data is still accessible and verifiable). A context that used `memoryScope: .ephemeral` has `sourceType: .ephemeral` (keys destroyed, data unrecoverable). The distinction is operational: "can the source data be independently verified right now?"

Provenance is attached automatically by the protocol when data crosses context boundaries through protocol mechanisms: cross-context tool calls (§6.2) and structured messages carrying references to other contexts.

#### 7.7.2 Provenance Evaluation

Other participants in the receiving context see the provenance and use it for trust evaluation. Provenance quality varies:

- Data from a persistent context with known counterparties — **highest provenance quality**. Source material is verifiable against the source context's event log.
- Data from a summary-scope context — **medium provenance quality**. Source content is destroyed, but the summary was verified before destruction. Counterparties are known.
- Data from an ephemeral context — **lower provenance quality**. Source content is destroyed. Counterparties are known, but the data cannot be verified against a source log.
- Data with no provenance — **lowest quality signal**. The data was introduced without protocol-level origin tracking. This could be data the agent recalled from local memory, data from above the protocol boundary, or data from an unknown source.

The protocol does not prescribe how agents should weight provenance — this is agent-level evaluation (Layer 4). The protocol ensures provenance is available for evaluation.

#### 7.7.3 Honest Limitations

The protocol can tag data that flows through protocol mechanisms. It **cannot** tag data that an agent remembers and reproduces above the protocol boundary. An agent that participated in an ephemeral context and later reproduces information from that interaction in a new context — from its own model memory rather than through a protocol mechanism — produces data without provenance.

The protocol is honest about this: provenance tracks what it can, and the **absence of provenance on information is itself a signal.** When an agent presents information with no provenance, other participants can infer: "this data has no verified origin — it may be accurate, but it cannot be independently verified through the protocol." This is analogous to hearsay in legal systems — admissible but weighted accordingly.

This limitation is inherent to any system where participants have memory above the protocol boundary. The protocol's contribution is making provenanced data the norm and unprovenanced data the exception that triggers additional scrutiny.

---

## 8. Products and Apps in the Graph

### 8.1 Apps in the Protocol

An app is not a protocol entity. It has no DID, is not an agent, and is not a context. The protocol has no `App` type.

What people experience as "an app" is a composite: a context (or set of contexts) + its members + its data + the backend, hosting, and relays that support it. The client is just the visible surface. The app's identity is the whole gestalt — the community, the infrastructure, the accumulated state. This is a philosophical identity, not a codified one. The protocol doesn't need to model it because the constituent parts (contexts, members, tools, data, capability declarations) are already first-class. The app emerges from their composition.

What the protocol *does* ensure is that this emergent identity never becomes lock-in: protocol state is portable (§8.3), clients are switchable, and no app owns the social graph.

### 8.2 App Interface

Apps declare what capabilities they need from the protocol. The protocol provides them. The interface is self-documenting and machine-readable, optimized for agent consumption rather than human developers hand-coding against it.

Apps can be any shape: thick clients with minimal protocol reliance, thin shells that are mostly protocol, or anything in between. The protocol doesn't care. It provides identity, social graph, contexts, tools, trust, and transport. The app decides what to use.

### 8.3 Context Portability and State Layering

State in SCP exists at two layers:

**Protocol state** — membership, roles, capability tokens, tool registrations, governance model, content history, trust relationships. This belongs to the protocol and the context, not to any app. It is portable, app-independent, and survives app death. Any app that declares the right capabilities can attach to an existing context and access its protocol state.

**App state** — data structures, configurations, and artifacts specific to a particular app's functionality. A game's world state. A project tracker's task board. A collaborative document's edit history. This belongs to the app. It may live in the context (stored via protocol data primitives) or entirely outside it (in the app's own infrastructure). The protocol doesn't claim ownership of app state, and apps are free to manage it however they choose.

The boundary between the two is the protocol's anti-lock-in mechanism. If you leave an app, you lose its app state (unless the app chooses to make it portable). You never lose your membership, your roles, your trust relationships, your identity, or your social graph. The social infrastructure is not hostage to any app's business decisions.

This means:

- **App switching.** A group can switch apps without losing their context's social infrastructure. Membership, roles, trust relationships persist. App-specific state may or may not transfer — that depends on the apps, not on the protocol.
- **Simultaneous multi-app.** Different members of the same context can use different apps. Alice uses Cronica. Bob uses a custom-generated client. Carol uses a minimal terminal app. They share protocol state. Each has their own app-layer experience.
- **App death is survivable.** If an app stops working, the context's social infrastructure survives. App-specific data may be lost if the app didn't store it durably, but the people, the relationships, and the trust graph remain. Generate a new app and the context continues.
- **Thick apps are welcome.** An app with rich proprietary state (a game, a design tool, a financial instrument) is a first-class participant. The protocol doesn't demand that all state be portable — only that the social layer is. Apps compete on their app-layer value, not on social graph lock-in.

### 8.4 Capability Declaration Contract

Apps interact with the protocol through a **capability declaration** — a structured, machine-readable manifest of what protocol capabilities the app needs. The protocol validates the declaration against the context's capability ceiling and the user's granted permissions, then provides exactly what was requested.

```
App → Protocol:  "I need: messaging, member_list, tool_invoke(tool_a, tool_b)"
Protocol → App:  "Granted. Here are your interfaces."

App → Protocol:  "I need: messaging, member_list, invite_members"
Protocol → App:  "Denied: invite_members exceeds your agent's role in this context."
```

The declaration contract is the boundary that makes generated apps safe. An LLM generating a client doesn't need to understand SCP internals — it declares what it needs, and the protocol handles authorization, scoping, and enforcement. The attack surface of a badly-generated app is bounded by the declaration contract, not by the app's code quality.

Properties:

- **Declarative, not imperative.** Apps say what they need, not how to get it.
- **Validated against ceiling + role.** The protocol never grants more than the context allows and the agent's role permits.
- **Machine-readable and self-documenting.** An agent can read a capability declaration and understand what an app does without running it. This enables trust evaluation of apps themselves.
- **Versionable.** Declarations carry a protocol version. Apps built against older declarations continue to work. Forward compatibility is a protocol constraint.

### 8.5 MCP Compatibility (Model Context Protocol)

MCP (Model Context Protocol) defines how AI models connect to tools and data sources locally — a JSON-RPC protocol where servers expose tool schemas, models discover and call them. MCP and SCP operate at different layers and integrate naturally.

```
┌──────────────────────────────────────────────────────┐
│  AI Model (any model that speaks MCP)                 │
│                                                        │
│  Sees tools. Calls tools. Gets results.               │
│  Has no awareness of SCP.                             │
└────────────────────┬─────────────────────────────────┘
                     │ MCP (JSON-RPC, local)
                     │
┌────────────────────▼─────────────────────────────────┐
│  SCP Agent (local process)                            │
│                                                        │
│  MCP server (local side) ←→ SCP participant (network) │
│                                                        │
│  - Exposes context tools as MCP tool schemas          │
│  - Filters tools by role + capability tokens          │
│  - Signs actions with human's DID                     │
│  - Encrypts/decrypts context envelopes                │
│  - Surfaces context events as MCP resources           │
└────────────────────┬─────────────────────────────────┘
                     │ SCP Protocol (encrypted, over transport)
                     │
┌────────────────────▼─────────────────────────────────┐
│  SCP Context [tools, roles, members, governance]      │
└──────────────────────────────────────────────────────┘
```

The SCP agent is a translation layer: an MCP server from the model's perspective, an SCP protocol participant from the network's perspective. This separation has several consequences:

**Any MCP-compatible model participates in SCP without modification.** The model doesn't need to know about DIDs, capability tokens, encryption, or context governance. It sees tools. "Send a message" is a tool call. "Read recent messages" is a tool call. "Invoke the scheduling tool" is a tool call. The agent handles everything SCP-specific.

**SCP tool schemas should use MCP's format.** If SCP defines its tool interface using MCP-compatible JSON schemas, then SCP context tools are natively MCP-compatible with zero translation. The agent passes tool schemas through directly. This is a concrete design decision: SCP tool definitions should be a superset of MCP tool definitions, adding SCP-specific metadata (context scope, capability requirements, provenance) while keeping the core schema MCP-compatible.

**Capability filtering happens at the agent.** MCP has no concept of access control — configured tools are available. SCP tools are capability-gated by role. The agent resolves this by exposing only the tools the human's role permits. Tools the agent lacks capability for are never surfaced to the model — from the model's perspective, they don't exist.

```
Context tools:             Admin's agent MCP surface:    Member's agent MCP surface:

  tool_a (admin+)            tool_a ✓                      (not exposed)
  tool_b (member+)           tool_b ✓                      tool_b ✓
  tool_c (member+)           tool_c ✓                      tool_c ✓
  tool_d (observer+)         tool_d ✓                      tool_d ✓
```

**Multi-context as namespaced MCP tools.** A human in multiple contexts has their agent expose tools from all contexts, namespaced by context. The model sees `context_a/send_message`, `context_b/schedule_meeting`. The agent routes each call to the right context, with the right tokens, over the right encrypted channel.

**MCP provides the local wiring. SCP provides the social infrastructure.** MCP solves "how does an AI model connect to tools on this machine." SCP solves "how do those tools exist in a multi-party, trust-evaluated, persistent, access-controlled social space." MCP has no identity, trust, multi-party coordination, or persistence. SCP provides all of these. Together, they give any MCP-speaking model access to SCP's social infrastructure without either protocol needing to change.

**BYOA benefit.** "Bring your own agent" (§4.4) means users choose their own AI model. MCP compatibility means any MCP-speaking model works — Claude, GPT, Gemini, open-source local models, or anything future. The SCP agent handles protocol mechanics. The model handles reasoning. The user chooses both independently.

---

## 9. Security Model

### 9.1 Core Invariants

1. **Every action traces to a human.** No anonymous actors. No unaccountable software.
2. **Agents are context-bound.** No protocol-level cross-context awareness or communication for agents.
3. **Tools are stateless and non-agentic.** They compute, they don't act.
4. **One agent per person per context.** No fleet multiplication within a space.
5. **Contexts are isolated by default.** No transitive exposure. Cross-context data flow only through two explicit, opt-in mechanisms: tool interfaces (asymmetric, §6.2) and multi-parent child contexts (symmetric, §5.13).
6. **Role assignment is non-negotiable.** Agents cannot request elevated permissions.
7. **Context metadata is transparent.** Full legibility before opt-in.

### 9.2 Identified Threat Vectors and Mitigations

**Context spoofing.** Creating a context that impersonates a legitimate one. Mitigation: contexts are cryptographic entities; you opt into a key, not a name. Name-based spoofing is a client-layer problem.

**Context poisoning.** Degrading a legitimate context from within. Mitigation: role-based permissions limit what members can do; governance model controls who can change configuration; context creators are accountable identities; automated consequence mechanisms (§7.3.7) enforce behavioral boundaries mechanically; verifiable event logs (§7.3.1) make all actions auditable; tool integrity verification (§7.3.3) detects compromised tools. Note: poisoning by a legitimate member acting within their permissions is attributable but not preventable at the protocol level — the protocol makes the poisoner identifiable and the damage legible, enabling governance response.

**Bait and switch.** Attractive context changes its purpose after gaining members. Mitigation: capability ceilings (potentially immutable) limit what a context can ever do. Expanding capabilities requires a new context with fresh opt-ins (if immutability is adopted).

**Social engineering through trusted agents.** A trusted friend's agent recommends a malicious context. Mitigation: limited — the trust signal is real. Network-level pattern detection (many agents recommending the same context rapidly) can surface suspicious coordinated promotion.

**Permission creep.** Gradual expansion of what a context demands. Mitigation: capability ceilings. If mutable, mutations require governance approval and are visible to all members.

**Metastatic growth (cancer).** Legitimate-looking cascading expansion through the network. Mitigation: agents can't cross contexts (primary defense); context participation rate limits per human; bridging only through governed tool interfaces (§6.2) or multi-parent child contexts (§5.13) — both require explicit governance consent. Nesting depth limits (§5.13.8) bound cascading expansion through child contexts. Ceiling intersection (§5.13.1) means each level of nesting can only narrow capabilities, converging on empty ceilings at depth.

**Betrayer / insider threat.** Compromised accountable identity using legitimate trust to cause damage. Mitigation: granular revocation (per-capability, per-agent, per-context); damage contained to contexts the betrayer is in; agents can't carry damage across context boundaries.

**Context infection.** Poisoned data flowing through legitimate cross-context mechanisms — tool interfaces (§6.2) or multi-parent child contexts (§5.13). Mitigation: content provenance via hash chains (data carries its origin context and chain path, §7.7.1); tool interface validation at receiving context; velocity limits on propagation (content bridged N times in M minutes is flagged); child context ceiling intersection (§5.13.1) limits what capabilities poisoned data can exploit at each nesting level. Protocol makes infection legible and traceable, can't permanently prevent it.

**Agent slot rental.** Someone with a trusted identity operating agents on another's instructions. Mitigation: one agent per context limits the value; earned capacity means new identities can't immediately scale; fleet coherence signals may detect behavior inconsistent with a single human's intent. Partially mitigated, not fully solved.

#### 9.2.1 Tool Interface Abuse Vectors and Mitigations

Information crosses context boundaries through two protocol-level mechanisms: tool interfaces (§6.2) for asymmetric, structured interactions and multi-parent child contexts (§5.13) for symmetric collaboration. With A2A propose/accept removed, all inter-agent coordination flows through these governed mechanisms. Tool interfaces concentrate structured cross-context data flow on a single, auditable surface. The following abuse patterns target that surface specifically. Nesting-related security properties are addressed in §5.13.1 (ceiling inheritance), §5.13.2 (eligibility enforcement), and §5.13.5 (lifecycle coupling).

**1. Broad-schema tools as covert messaging channels.**

*Attack:* A context exposes a tool with a deliberately broad schema — `input: { payload: string }, output: { response: string }` — creating a de facto free-form messaging channel that wears the governance mask of a "tool call." Both contexts opted in, the schema is valid, rate limits pass, provenance is attached, but the semantic constraint that tool calls carry structured, bounded data is gone.

*Mitigation — minimum viable tool schema.* Tool schemas MUST satisfy structural constraints enforced at registration time (§5.4). The protocol rejects tool registrations that violate these constraints:

- **No unbounded string-only interfaces.** A tool schema where both the input and output consist solely of unconstrained string or bytes fields is rejected. At least one input or output field must be a non-string primitive, enum, array with typed elements, or structured object. This prevents the degenerate case of arbitrary message pipes while permitting legitimate tools that accept or return text alongside structured data.
- **Schema specificity floor.** Tool schemas must declare at least two distinct fields in either input or output (or both). A single-field `{ query: string } → { result: string }` interface is the minimum viable message pipe; requiring structural complexity makes it harder to masquerade.
- **Schema is immutable per registration.** Modifying a tool's schema creates a new registration with a new implementation hash (§5.4). Counterparties that connected to the old schema must re-consent to the new one. This prevents gradual schema broadening after trust is established.

These constraints don't prevent a sufficiently creative attacker from encoding arbitrary messages in structured fields (steganography). The defense is not impermeability — it's raising the cost and making the attempt legible. A tool schema that looks suspiciously like a messaging pipe (e.g., `{ message_type: enum, payload: string }`) is a signal that governance tools and behavioral analysis can flag.

**2. Hub contexts as cross-context data aggregators.**

*Attack:* A single context accumulates tool interfaces to many other contexts, becoming a hub that aggregates cross-context information flowing through its interfaces. Each interface is bilateral and governed, but the hub sees data from all of them — a surveillance context masquerading as infrastructure.

*Mitigation — interface count as observable metadata.*

- **Interface count is visible in context metadata (§5.7).** The number of active inbound and outbound tool interfaces is part of a context's legible metadata. Before joining a context or connecting a tool interface to it, agents can see how many other interfaces it maintains. A context with 50 outbound interfaces is visibly different from one with 2 — and that visibility enables informed decisions.
- **Behavioral topology signals.** The systemic defense philosophy (§9.4) applies: monitor structural metadata, not content. A context that rapidly accumulates interfaces, maintains interfaces to contexts in unrelated domains, or exhibits high-volume cross-interface data flow is topologically anomalous. These patterns are detectable by network-level behavioral analysis without inspecting content.
- **Provenance chain depth.** Data flowing through a hub carries provenance (§7.7). If data enters the hub from Context A and exits to Context C, the provenance chain records both hops. Context C sees that data originated in A and passed through the hub. Deep provenance chains — data that has crossed multiple context boundaries — naturally attract additional scrutiny (§7.7.2). This is a feature, not a limitation: trust should degrade with indirection.

*Design note:* This vector is partially inherent to any system that allows cross-boundary data flow. The protocol's contribution is making the aggregation visible and the data flow traceable, not preventing hub formation entirely. Legitimate service contexts (discovery registries, translation services) are hubs by design — the difference is that their interface patterns are consistent with their declared purpose.

**3. Chained tool calls as amplification.**

*Attack:* Context A calls Context B's tool. B's implementation calls Context C's tool. C calls D. A single call from A cascades with potential exponential fanout. Each hop is independently rate-limited, but A's rate limit only constrains the first hop.

*Mitigation — chain depth limit and provenance-based cost attribution.*

- **Protocol-enforced chain depth limit.** Tool calls carry a `chain_depth` counter, incremented on each cross-context hop. The protocol enforces a maximum chain depth (suggested default: 3 hops). A tool call at the depth limit cannot trigger further cross-context tool calls. This is a hard protocol limit, not a governance option — it bounds the worst-case amplification factor.
- **Provenance carries chain depth.** The provenance record (§7.7.1) includes the chain depth at each hop. Receiving contexts see how many boundaries the data has crossed. This enables depth-aware trust evaluation: data at chain depth 1 (direct tool call) carries stronger provenance than data at chain depth 3 (three intermediaries).
- **Per-window rate limiting across chains.** Each context enforces rate limits on both inbound and outbound tool calls within a sliding time window. A context that receives a burst of inbound tool calls (even from different source contexts) throttles proportionally. This prevents amplification where many chains converge on a single target.
- **Provenance degradation as trust signal.** Transitive provenance degradation is not a flaw — it is the protocol working as designed. Data from many degrees of separation away should be less trusted, the same way a message from a stranger deserves more scrutiny than one from a known contact. The chain depth in provenance gives the receiving agent the information to calibrate trust: "this data originated three hops away in a context I have no relationship with" is a meaningful signal. The protocol ensures this signal is always available; the agent decides how to weight it.

**4. Stateful tool session resource exhaustion.**

*Attack:* An attacker opens many stateful tool sessions (§6.2.1) against a target context, never closing them. Session state accumulates, exhausting the target's resources.

*Mitigation — per-caller session cap and optional TTL.*

- **Per-caller session cap.** A context limits the number of concurrent active sessions per calling context (suggested default: 5). Attempts to open additional sessions from the same caller are rejected until existing sessions close or expire. This is the primary resource exhaustion defense — it bounds the damage any single caller can inflict regardless of session duration.
- **Optional TTL for time-bounded sessions.** The tool's context MAY set a TTL on sessions. When set, expired sessions are garbage-collected automatically. When not set, sessions persist for the context's lifetime — appropriate for app-hosted sessions (games, workspaces, collaborative tools) where the context is the lifecycle boundary.
- **Session cost is borne by the tool's context.** Session state is internal to the tool's context. The tool's context chooses to offer stateful sessions, chooses whether to impose TTLs, and accepts the storage cost. This aligns incentives: contexts that offer sessions manage their own resource budget.

**5. Context proliferation for connectivity.**

*Concern:* Without A2A propose/accept, agents that need to coordinate must share a context. This creates pressure to join or create many contexts solely for connectivity, degenerating into thin wrappers around bilateral communication.

*Resolution — standing channels make this a non-problem.*

Standing bilateral contexts (§5.12.4-§5.12.6) are the protocol's answer to this concern. They are designed for exactly this purpose: persistent, low-overhead communication channels between two agents, created once and maintained indefinitely. Context creation is a runtime operation (~200ms, §5.12.4) — not infrastructure provisioning.

The "proliferation" concern assumes context creation is heavy enough to be problematic at scale. It is not. An agent with 100 standing channels has ~200-500KB of local storage overhead and zero network cost when idle. The proliferation is the feature — a rich contact graph of standing channels is the desired state, not a degenerate one.

The distinction that matters is between **meaningful proliferation** (standing channels representing real relationships) and **wasteful proliferation** (ephemeral contexts created and immediately discarded for a single exchange). Templates and TTL address the latter: ephemeral contexts are cheap to create, automatically cleaned up, and their ephemerality is declared upfront. There is no accumulation of dead contexts.

**6. Human coordination bottleneck.**

*Concern:* The human is the bridge for cross-context coordination (§6.3). New agent relationships require human facilitation. An attacker could overload this bottleneck.

*Mitigation — rate limiting and auto-accept absorb the load.*

- **Auto-accept policies (§5.12.2)** handle the common case autonomously. For contexts matching a known template from a known DID with acceptable TTL, the SDK joins without human involvement. The human is only in the loop for novel or high-risk invitations.
- **Invitation rate limiting.** The SDK rate-limits inbound invitations per source DID and globally. An attacker flooding invitations from multiple DIDs is bounded by the global rate limit. Invitations that exceed the rate limit are queued (not dropped) with decreasing priority.
- **The bottleneck is intentional.** For novel relationships (strangers, unusual templates, tool-bearing contexts), human facilitation is the correct behavior — the protocol forces deliberate evaluation where trust hasn't been established. This is the security boundary working as designed, not a flaw. The same way a firewall throttles unknown connections, the human bridge throttles unknown relationships.

**7. Governance capture over interface decisions.**

*Concern:* Context admins unilaterally control which tool interfaces to expose and connect. In single-admin governance, members have no visibility into or veto over interface decisions.

*Mitigation — event log transparency and governance evolution.*

- **All interface operations are logged.** Tool interface creation, connection, disconnection, and modification are protocol events recorded in the verifiable event log (§7.3.1). Members can see every interface decision the admin has made, when, and to which contexts. No silent interface changes.
- **Interface metadata is visible.** Active tool interfaces are part of context metadata (§5.7). Members see what interfaces exist before joining and while participating.
- **Governance evolution.** Single-admin governance is the Phase 2 minimum. The pluggable governance interface (§5.9) supports multi-sig, consensus, and voting models where interface decisions require member approval. Contexts that need member control over interfaces use governance models that provide it. This is not deferred — the governance interface is specified; specific multi-party models beyond single-admin are Phase 2+.
- **Exit as veto.** Any member can leave a context at any time. If the admin connects the context to an interface the member disagrees with, the member leaves. In an environment where context creation is cheap (§5.12), members can create a new context without the objectionable interface and migrate — the social graph is portable (§8.3).

**8. Caller/tool asymmetry in peer interactions.**

*Concern:* Tool calls have inherent caller/tool asymmetry. One side requests, the other responds. This forces symmetric interactions (negotiation, collaboration) into a client/server pattern.

*Resolution — shared contexts provide symmetric interaction; tool calls serve asymmetric use cases.*

This is not a flaw — it is correct role assignment. Tool calls are inherently asymmetric because cross-context data flow should be structured, directional, and governed. Symmetric peer interaction — two agents collaborating as equals — belongs in a shared context where both have equivalent roles and permissions.

The protocol provides both patterns:

- **Symmetric interaction:** Create a shared context (standing channel or ephemeral). Both agents have messaging capability. Both can read and write. No caller/tool asymmetry.
- **Asymmetric interaction:** One context exposes a tool to another. The tool provider is a service; the caller is a consumer. The asymmetry reflects the actual relationship.

Stateful tool sessions (§6.2.1) partially bridge this: a multi-turn session allows both sides to influence the outcome iteratively. The tool provider responds with counterproposals; the caller adjusts. This isn't true symmetry, but it covers negotiation patterns within the governed tool call framework.

If two agents need truly symmetric, ongoing interaction, the answer is unambiguous: share a context. Context creation is a runtime operation (§5.12.4). Standing channels exist for exactly this purpose (§5.12.6).

**9. Shadow channel incentivization.**

*Concern:* The overhead of governed tool interfaces (mutual opt-in, schema declaration, governance approval, rate limits, provenance, audit logging) may be disproportionate for lightweight coordination, pushing agents to communicate through ungoverned channels (HTTP, direct API calls).

*Resolution — the overhead concern dissolves with standing channels.*

Lightweight coordination ("is your agent available?", "can you check something?", "here's a quick update") does not flow through tool interfaces. It flows through standing bilateral contexts — which have no per-message overhead beyond standard context messaging (encrypt, send, decrypt). There is no schema declaration, no governance approval, no tool registration. A message in a standing channel is as lightweight as a message in any context.

The governed tool interface overhead applies to formal cross-context data flow — where one context's tool is invoked by another context's agent. This overhead is appropriate for that use case because cross-context data flow carries real risk (§6.2) and should be auditable, rate-limited, and governed.

The two-tier model:

- **Standing channels** for lightweight, symmetric, low-ceremony communication. All the protocol's trust and encryption properties. No tool interface overhead.
- **Tool interfaces** for formal, structured, asymmetric cross-context data exchange. Full governance, provenance, and auditability.

This is analogous to the distinction between a text message and an API call. Both are communication; they have different overhead appropriate to their different risk profiles. The protocol provides both, and agents use whichever fits the interaction.

### 9.3 Sybil Resistance and Identity Uniqueness

The protocol's security model assumes one identity per human. Sybil attacks — one person creating many identities to gain disproportionate influence — undermine every trust mechanism in the spec: behavioral records become meaningless, one-agent-per-context is circumventable, earned capacity is gameable.

Provably guaranteeing one-identity-per-human in a decentralized system without invasive verification (KYC, biometric databases) is an unsolved problem. The protocol's approach is to make sybil attacks **expensive enough to be manageable** through three layered mechanisms:

**Device attestation.** Modern devices provide hardware-backed attestation (Apple App Attest, Google Play Integrity) that can prove: "this is a real, un-jailbroken device and it has not previously created another DID through this protocol." One physical device = one DID creation. This doesn't prove one human (a person with two phones gets two identities), but it makes identity creation cost the price of a physical device. The SDK integrates device attestation as part of DID creation. Device attestation constrains DID **creation** only — a DID created on one device can authenticate on multiple devices freely. Multi-device usage (§10.2) is unaffected; the restriction is on how many identities can be minted, not how many devices can use one.

**Earned capacity.** New identities start with limited capabilities — restricted context creation, limited context participation slots, constrained tool invocation rates. Capacity grows through participation history, behavioral records, and time. Sybil accounts are cheap to create (one device per identity) but expensive to make useful — each needs real participation history. This is the Reddit model: new accounts can browse, established accounts can post in restricted communities.

**Context-level social verification.** Contexts set their own admission thresholds — how much behavioral history, how many endorsements, what attestations are required for participation at each role level. A casual group chat might require nothing beyond a valid DID. A high-trust financial context might require 6 months of behavioral history, 3 independent endorsements, and challenge-verified agent capabilities. The protocol provides the verification data (behavioral records, attestations, challenge results); contexts define their own thresholds.

These three layers compose: device attestation makes identity creation expensive → earned capacity makes new identities limited → context-level thresholds make meaningful participation require real history. A sybil attacker needs many devices AND time AND social verification to gain influence. Not impossible, but expensive enough that the attack scales poorly. Crucially, consequences for coordinated attacks render sybil accounts single-use — once detected and penalized, the investment in aging and building history is lost. This makes sustained sybil campaigns economically irrational even when individual identity creation is feasible.

Sybil resistance is a **deterrent**, not an enforcement guarantee. The protocol concedes that a sufficiently determined attacker with many devices can create multiple identities. The defense is structural: making the attack expensive to mount, expensive to sustain, and costly when detected.

### 9.4 Systemic Defense Philosophy

Static rules cannot permanently defeat emergent threats. The protocol's role is to maximize the surface area of what can be independently verified, and to make whatever remains legible enough for agents and governance to respond.

Key principles:

**Validate, minimize trust.** Every claim that can be mechanically verified should be. The four-layer trust model (§7.1) prioritizes protocol enforcement and behavioral validation over attestation authenticity and subjective trust. The trust surface shrinks as the network accumulates history.

**Don't inspect content, inspect behavior topology.** Monitor structural metadata — growth rates, bridge activity patterns, context creation velocity, invitation patterns, tool invocation anomalies, governance action frequency — not what's being said. The protocol equivalent of metabolic signals, not thoughts.

**Consequences over character.** Where possible, replace "trust that actors will behave" with "verify that misbehavior is irrational given the consequences." Automated consequence mechanisms (§7.3.7) make behavioral boundaries mechanical rather than discretionary.

**Observability is the immune system.** The protocol provides verifiable event logs, behavioral records, tool verification results, challenge-response outcomes, and attestation freshness data. These are the immune system's sensory apparatus. The actual immune response is an evolving network of agents and governance tools that consume this data and get better over time.

### 9.5 Cryptographic Primitive Specification

The protocol mandates a single ciphersuite for v1. No negotiation, no fallback. This eliminates downgrade attacks and simplifies implementation.

**Signature algorithm:** Ed25519 (RFC 8032). All DID keys, SCP envelope signatures, Nostr event signatures, UCAN token signatures, and MLS leaf node credentials use Ed25519.

**MLS ciphersuite:** MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 (RFC 9420 §17.1). This provides: X25519 for key agreement (HPKE KEM), AES-128-GCM for symmetric encryption (AEAD), SHA-256 for hashing, Ed25519 for signing.

**DID-to-DID encryption:** HPKE (RFC 9180) with suite DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM. Used for MLS Welcome messages. The HPKE suite matches the MLS ciphersuite to minimize the cryptographic surface area.

**Merkle tree hash:** SHA-256. Append-only log tree following Certificate Transparency structure (RFC 6962). Each event entry is `SHA256(previous_hash || event_data)`. The Merkle root provides tamper-evident integrity over the entire event history.

**Envelope signature scope:** The outer envelope is unsigned — it contains only the routing pseudonym, recipient hint, blob TTL, and encrypted blob (§9.10.2). The full signature lives inside the encrypted payload, signed by the sender's identity key: `SHA256(context_id || sender_did || epoch || generation_number || sequence_number || timestamp || payload_hash)`. This binds every field to the signature. Field-swapping attacks (e.g., moving a payload from one context to another) produce invalid signatures. Relay operators cannot verify signatures (they cannot see sender DIDs), which is by design — verification is the responsibility of context members who can decrypt the payload.

**UCAN signing:** EdDSA (Ed25519) per UCAN specification. The nonce field (`nnc`) is mandatory and must be unique per token issuance. This prevents UCAN token replay. UCAN token expiry (`exp`) MUST NOT exceed 24 hours (matching the nonce deduplication cache window in §9.8.2). Tokens with longer expiry could be replayed after nonce cache eviction.

**Why single ciphersuite:** Ciphersuite negotiation adds complexity and introduces downgrade attack vectors. For v1, every implementation uses exactly these algorithms. Future protocol versions may introduce additional ciphersuites with a secure negotiation mechanism, but v1 prioritizes simplicity and auditability.

### 9.6 Identity Verification and MITM Prevention

Identity verification is the trust root for the entire protocol. If an attacker can substitute their public key for another identity's, every layer above — encryption, authentication, capability validation — is compromised. This section specifies how SCP prevents MITM attacks on identity resolution.

#### 9.6.1 did:dht Self-Certification

The did:dht method (target DID method for SCP) is **self-certifying**: the DID string itself is the z-base-32 encoding of the Ed25519 public key. When resolving a did:dht identifier:

1. The client queries the Mainline DHT for the BEP44 signed record associated with the DID.
2. The client verifies the BEP44 record signature against the public key encoded in the DID string.
3. If the signature is valid, the DID document is authentic. No trusted third party is required.

**MITM on did:dht resolution is impossible given the correct DID.** A DHT node cannot serve a fraudulent DID document because the document must be signed by the key embedded in the DID itself. Tampering is detectable without trusting any intermediary.

**Stale document prevention:** BEP44 records include a sequence number. The client MUST reject DID documents with a lower sequence number than previously observed for the same DID. This prevents serving outdated documents.

**The remaining question:** "Is this the right DID?" Self-certification proves the binding between a DID and its key, but cannot prove the binding between a DID and a person. This is an out-of-band verification problem addressed by Key Continuity Verification (§9.11).

#### 9.6.2 did:web Security Properties and Limitations

did:web (fallback only — used only if did:dht libraries prove unusable) resolves via HTTPS to a well-known path on the authority domain. Security depends on DNS integrity, TLS certificate validity, and server integrity.

**did:web is NOT self-certifying.** A compromised server, DNS hijack, or CA compromise can serve a fraudulent DID document indistinguishable from a legitimate one. did:web introduces a server dependency that contradicts SCP's infrastructure-minimal design. It exists as a contingency fallback, not a planned deployment path.

**Required mitigations if did:web is used:**

- The SDK MUST pin the TLS certificate of the did:web resolution server.
- The SDK MUST verify that the DID document's verification method key matches the key used for all prior interactions with this DID (key continuity check / TOFU — Trust On First Use).
- The SDK MUST alert the user on any key change, with maximum severity.
- The SDK SHOULD record the did:web key fingerprint in identity private state (§3.7) for cross-device consistency of TOFU state.

**Migration from did:web to did:dht (if fallback was used):** If a deployment started with did:web as a fallback, migration to did:dht must be signed by the old did:web key, creating a verifiable authorization chain: "the identity formerly at did:web:example.com is now at did:dht:z6Mk...". Both DIDs temporarily resolve to the same public key during the transition. This migration path exists for contingency recovery, not as a planned lifecycle.

#### 9.6.3 Relay List Authentication

A DID's relay list (service endpoints) is published in the DID document and as NIP-65 Nostr events (kind:10002).

**For did:dht:** The relay list in the DID document is self-certified (BEP44 signature). Substituting a relay list requires the identity's private key.

**For Nostr:** The NIP-65 relay list event is signed by the Nostr keypair derived from the DID key. This provides relay list authentication independent of the DID method.

**Attack: relay list substitution.** A compromised DHT node or Nostr relay could serve a stale relay list, directing messages to relays the recipient no longer uses. Defense: sequence numbers in BEP44 records ensure freshness. Clients MUST reject relay lists with lower sequence numbers than previously observed.

#### 9.6.4 First-Contact Trust Bootstrapping

When Alice first encounters Bob's DID (via shared context membership, registry discovery, or referral):

- **For did:dht:** Alice resolves the DID document and verifies it against the DID string. The binding is cryptographically verified. No MITM is possible.
- **For did:web:** Alice resolves over HTTPS and trusts the web PKI. The SDK records Bob's key on first contact (TOFU) and alerts on any subsequent change.

### 9.7 Group Key Management — MLS Integration

MLS (RFC 9420) provides the group encryption layer for SCP. This section specifies how MLS concepts map to SCP and what security properties the SDK must enforce.

#### 9.7.1 MLS-to-SCP Concept Mapping

| MLS Concept | SCP Concept | Notes |
|---|---|---|
| Group | Context | 1:1 mapping. Each SCP context is one MLS group. |
| Member (LeafNode) | Agent (in context) | One MLS leaf node per agent in the context. |
| Epoch | Context epoch | Increments on every membership change or key update. Included in all SCP envelopes. |
| LeafNode credential | DID + UCAN | The MLS credential field contains the member's DID and their context-scoped UCAN token. |
| Welcome message | Context join token | HPKE-encrypted to new member's KeyPackage. Contains the group state needed to decrypt future messages. |
| KeyPackage | Pre-key bundle | Published to relays so others can add the identity to groups even when offline. Signed by identity key. Single-use. |
| Proposal (Add/Remove/Update) | Governance action | MLS membership proposals map to SCP membership changes. |
| Commit | Governance commit | Finalizes pending proposals and advances the epoch. |
| Application message | SCP envelope payload | The encrypted content within an SCP envelope. |
| Delivery Service (DS) | Nostr relay(s) | The untrusted store-and-forward layer. |
| Authentication Service (AS) | DID resolution + UCAN validation | SCP's identity layer serves as MLS's AS. No separate trusted server. |

**Group context extensions for nesting.** Child contexts include parent context IDs and governance configuration hashes in the MLS `group_context` extensions field (§5.13.3). This cryptographically binds the parent lineage to the child's group identity — the derived `group_id` is a function of the parent references. Root contexts (no parents) have empty nesting extensions.

**Authentication Service design:** MLS delegates identity verification to an Authentication Service (AS). In SCP, the AS is fully decentralized: DID resolution provides the public key binding, and UCAN validation provides the capability binding. No centralized AS server exists. Each participant independently verifies credentials by resolving the DID and validating the UCAN chain.

#### 9.7.2 Forward Secrecy

MLS provides forward secrecy through epoch-based key ratcheting. After a Commit message advances the group to a new epoch, key material from old epochs is deleted.

**SDK requirements:**

- The SDK MUST delete old epoch key material immediately after processing a Commit. Old epoch secrets, application key schedules, and ratchet tree states for past epochs MUST NOT be persisted.
- Historical epoch keys MUST be treated as equivalent to ephemeral Diffie-Hellman parameters: used once, then destroyed.
- Members who want to re-read historical messages must retain the decrypted plaintext locally. They cannot re-derive old epoch keys from current state.

**Interaction with memory scope:**

- For `full` memory scope contexts: forward secrecy protects against future key compromise revealing past messages. Members retain plaintext locally if they want to re-read.
- For `ephemeral` memory scope contexts: the MLS group state is destroyed on context close. This is the `destroy_keys` operation — destroy tree root, all epoch secrets, all application key material. All historical messages become physically unreadable.
- For `summary` memory scope contexts: same as ephemeral, but a summary is generated and verified before destruction.

#### 9.7.3 Post-Compromise Security (PCS)

MLS provides PCS through the Update proposal mechanism. After a member sends an Update (generating a fresh HPKE key pair and ratcheting their path in the tree), any previous compromise of that member's state becomes useless for future messages.

**SDK requirements:**

- The SDK MUST periodically issue MLS Update proposals. Recommended interval: every 24 hours for active contexts, or immediately after any suspected compromise.
- The SDK SHOULD issue an Update after re-establishing connectivity following an offline period.
- When a DID's key rotates (recovery scenario, §3.3), the agent MUST issue an MLS Update in every active context. This synchronizes DID-level key rotation with MLS-level post-compromise security.

**PCS Update interval as context parameter:** High-security contexts may configure shorter PCS Update intervals (e.g., 1 hour). The interval is a context-level parameter set at creation, defaulting to 24 hours.

#### 9.7.4 Key Lifecycle

**Key generation:**

- Identity key (Ed25519): Generated in hardware security module where available (Secure Enclave, Android Keystore). Private key never exported from the secure element.
- MLS leaf key (X25519): Generated by the MLS library per the selected ciphersuite. Stored in platform secure storage.
- KeyPackages: Pre-generated and published to relays. Each KeyPackage is single-use. The SDK MUST maintain a buffer of at least 10 unused KeyPackages per identity on relays. Replenished when the buffer drops below 5.
- UCAN signing key: Same as identity key (Ed25519). UCAN tokens are signed by the human's DID key.

**Key distribution:**

- Identity public key: Distributed via DID document (DHT resolution or web resolution).
- KeyPackages: Published to relays as Nostr events. Any party wanting to add this identity to a group fetches a KeyPackage from their relay.
- Context group key: Distributed via MLS Welcome message, encrypted to the new member's KeyPackage. Only the intended recipient can decrypt.

**Key rotation:**

- Identity key: Rotated via DID document update. For did:dht, the new document is signed by the old key (authorization chain) and published with an incremented sequence number. All active MLS groups receive an Update proposal with the new credential.
- MLS epoch keys: Rotated automatically on every Commit (membership change or Update).
- UCAN tokens: Expire per their `exp` field. Re-issued by the human's DID. Revocation published to a revocation list referenced in the UCAN's revocation field.

**Key destruction:**

- Ephemeral context close: Destroy MLS group state — tree secrets, all epoch key schedules, application key material. See §9.15 for destruction verification.
- KeyPackage consumption: After a KeyPackage is used in a Welcome message, the SDK deletes the KeyPackage's private key. One-time use is mandatory.
- Old epoch material: Destroyed after Commit processing (forward secrecy, §9.7.2).

### 9.8 Message Security

This section specifies how SCP prevents message forgery, replay attacks, and ordering manipulation.

#### 9.8.1 Envelope Integrity (Two Independent Checks)

Every SCP message has two independent integrity verifications, both inside the encrypted payload. Neither is verifiable by relays — relays see only opaque blobs.

**Inner check 1 — Ed25519 identity signature.** The sender signs the payload with their DID key: `SHA256(context_id || sender_did || epoch || generation || sequence || timestamp || payload_hash)`. This signature is created before sender-key encryption and MLS encryption, and verified after MLS decryption and sender-key decryption. A failed signature means the envelope was tampered with or forged and MUST be rejected.

**Inner check 2 — MLS membership_tag.** The MLS PrivateMessage format includes an HMAC (membership_tag) that proves the sender is a group member with correct epoch secrets. This is verified during MLS decryption. It provides authentication independent of the identity signature — even if an attacker obtained the DID private key, they cannot produce a valid membership_tag without the MLS epoch secrets.

Both checks MUST pass for a message to be accepted. This defense-in-depth means an attacker must compromise BOTH the identity key AND the MLS group state to forge a message. Both checks are member-only verifiable — the outer envelope is unsigned by design (§9.10.2), ensuring relays learn nothing about message authenticity or sender identity.

#### 9.8.2 Replay Prevention (Three-Layer Defense)

**(a) MLS generation numbers.** MLS assigns each sender a generation counter that increments with every message. Recipients track the highest generation number seen per sender per epoch. A message with a generation number less than or equal to the highest seen is a replay and MUST be rejected. This catches exact replays within a single MLS epoch.

**(b) Hash-based deduplication.** The SDK maintains a deduplication cache keyed by `SHA256(encrypted_blob)` — the hash of the outer envelope's encrypted blob, which is visible without decryption. Any envelope with a previously-seen blob hash is a replay and MUST be dropped silently. Cache size: bounded by a sliding window of the most recent 10,000 envelopes or 24 hours, whichever is larger. This catches replays across MLS epochs.

**(c) Timestamp bounds.** Every SCP envelope includes a `created_at` timestamp. Recipients MUST reject envelopes with timestamps more than 5 minutes in the future (clock skew tolerance). Within a sequence of messages from the same sender in the same context, timestamps must be monotonically non-decreasing within the clock skew tolerance. This catches time-shifted replays.

The past-bound is relative, not absolute, to handle offline delivery: if Bob comes online after 3 hours, he accepts messages from the past 3 hours. But timestamps from a single sender must not regress.

#### 9.8.3 Message Ordering

Within a context, messages are ordered by: `(epoch, sender_generation_number, timestamp)`. This gives a total order per-sender and a causal order across senders — epoch boundaries are synchronization points.

The Merkle event log records events in append order. Each event references the previous event's hash, creating a hash chain. If two events reference the same parent, the log has forked — possible equivocation (see §9.9).

**Interaction with relay ordering:** Nostr relays do not guarantee message ordering. The SDK MUST re-order messages locally using `(epoch, generation, timestamp)` before presenting them to the application layer.

**Authoritative ordering:** The Merkle log order is authoritative, not timestamps. Timestamps are hints for the SDK to reconstruct order in real-time. Once events are committed to the log, the log order is the permanent record.

#### 9.8.4 Forgery Prevention

**Message forgery:** Prevented by Ed25519 inner signature + MLS membership_tag. Both checks are inside the encrypted payload (§9.8.1). An attacker who does not hold a member's private key cannot produce a valid inner envelope, and an attacker without MLS epoch secrets cannot produce a valid membership_tag.

**Attestation forgery:** Attestations (§7.4) are signed by their issuer's DID key. Forgery requires the issuer's private key.

**UCAN forgery:** UCAN tokens contain a delegation chain where each delegation is signed. The mandatory `nnc` (nonce) field prevents token reuse outside the intended scope.

**Provenance forgery:** Data provenance records (§7.7) are attached by the SDK and signed as part of the enclosing envelope. An agent cannot fabricate a provenance claim for data sourced from a context it was never in, because provenance records are verifiable against the source context's Merkle root (for persistent-scope sources).

#### 9.8.5 Sequence Validation

Each sender in a context maintains a monotonically increasing SCP sequence number (distinct from MLS generation numbers, which are MLS-internal). This sequence number is included in the envelope and the Merkle event log entry.

Recipients MUST accept all authenticated messages regardless of sequence order and apply reorder-before-delivery semantics. Multi-relay delivery (§10.4, ADR-012) guarantees that messages may arrive out of order; strict rejection would cause guaranteed message loss.

**Reorder buffer.** Each recipient maintains a per-(context, sender) reorder buffer:

- Messages arriving in order (sequence == expected next) are delivered immediately to the application layer.
- Messages arriving ahead of their predecessors (sequence > expected next) are buffered pending delivery of the missing predecessors.
- When a buffered message's predecessors arrive, the entire contiguous run is delivered in sequence order.
- **Gap timeout:** If a gap persists for more than 30 seconds, the recipient raises a suppression alert (§9.9), delivers all buffered messages (recording the gap in the event log), and advances the expected sequence number past the gap.
- **Buffer bound:** The reorder buffer is bounded at 100 messages per sender per context to prevent resource exhaustion. If the buffer fills, the oldest gap is force-closed (with suppression alert) and buffered messages are delivered.
- A duplicate sequence number indicates replay (caught by §9.8.2).

### 9.9 Relay Threat Model and Mitigations

Relays are untrusted infrastructure (§10.4). This section formally defines the relay threat model and specifies mitigations.

#### 9.9.1 Relay Capabilities and Limitations

A relay CAN:

- **Read metadata:** routing IDs (per-context pseudonyms, §9.10.4), recipient hints (pseudonyms), blob TTLs, padded blob sizes, and connection timing. Context IDs, sender/recipient DIDs, and timestamps are inside the encrypted payload and NOT visible to relays (§9.10.2). Relay CANNOT read encrypted content.
- **Drop messages (suppression):** Silently discard envelopes. The sender believes delivery succeeded; the recipient never sees the message.
- **Delay messages:** Hold envelopes and deliver them later. Architecturally identical to slow network conditions.
- **Replay messages:** Re-deliver previously delivered envelopes. Mitigated by §9.8.2.
- **Equivocate:** Show different message histories to different members of the same context.
- **Correlate traffic:** Link activities across contexts based on timing, DID, and connection patterns.

A relay CANNOT:

- **Forge messages.** Requires the sender's private key (for the inner Ed25519 signature, §9.8.1) and MLS epoch secrets (for the membership_tag).
- **Decrypt content.** Requires MLS group key and sender-side key (§9.16).
- **Modify messages.** Inner signature verification and MLS membership_tag verification fail after decryption.
- **Inject members into contexts.** Requires MLS Welcome message encrypted to the joiner's KeyPackage.

#### 9.9.2 Suppression Detection

**Sequence gap detection:** If a recipient expects sequence #47 from a sender but receives #49, sequences #47 and #48 were suppressed (or delayed). The SDK MUST track expected sequence numbers per (context, sender) pair and alert on gaps.

**Heartbeat messages:** In active contexts, the SDK SHOULD send periodic heartbeat envelopes (recommended interval: 60 seconds when the context has active participants). A heartbeat is a minimal MLS application message with a sequence number but no user content. If heartbeats stop arriving from a participant who was recently active, suppression is suspected.

**Multi-relay cross-check:** Context messages SHOULD be published to at least 2 relays (recommended: 3). Recipients subscribe to all relays in the sender's relay list and merge received envelopes. If relay A delivers an envelope and relay B does not, this is an inconsistency. After a timeout (recommended: 30 seconds), the inconsistent relay is marked as potentially adversarial.

**Response to suspected suppression:** The SDK SHOULD alert the user and attempt delivery via alternative relays. The SDK MUST NOT silently discard the suspicion.

#### 9.9.3 Equivocation Detection — Relay Consistency Protocol

The Relay Consistency Protocol detects relay equivocation — a relay showing different event histories to different members.

**Consistency checkpoints:** At regular intervals (recommended: every 50 events or every 10 minutes, whichever comes first), each member computes a signed checkpoint:

```
ConsistencyCheckpoint {
  contextID:    String
  senderDID:    DID
  eventCount:   UInt64           // number of events in local log
  merkleRoot:   [UInt8; 32]      // root hash of local event log
  epoch:        UInt64           // current MLS epoch
  timestamp:    DateTime
  signature:    Ed25519Signature // signed by sender's DID key
}
```

Checkpoints are sent as regular MLS application messages (encrypted, authenticated).

**Checkpoint comparison:** On receiving a checkpoint from another member, each member compares:

- `eventCount`: Must match (within tolerance for in-flight messages). Divergence of more than 5 events indicates inconsistency.
- `merkleRoot`: Must match for the same `eventCount`. Divergence indicates equivocation or log corruption.
- `epoch`: Must match. Divergence indicates a missed MLS Commit (possible suppression).

**Divergence resolution:** If Merkle roots diverge, members exchange event log proofs to identify the first divergent event. This reveals which relay served which version. The context's governance model handles the response.

**Sybil-amplified equivocation defense:** The Relay Consistency Protocol is NOT a majority vote. ANY divergence between ANY two honest members detects equivocation. An attacker who controls Sybil members and a relay can make the Sybil members confirm the attacker's version, but this is irrelevant — two honest members comparing checkpoints will detect the equivocation regardless of how many Sybils agree with the attacker. The defense requires only two honest members in the context.

#### 9.9.4 Selective Suppression of MLS Commits

A specific relay attack: suppress an MLS Remove Commit to keep an excluded member in the group.

**Analysis:** After an MLS Remove Commit is processed, new messages use the new epoch key. The removed member does NOT have this key — they physically cannot decrypt new-epoch messages. Even if the relay suppresses the Commit from being delivered to the removed member, confidentiality is preserved.

**Actual risk:** Suppressing the Commit from OTHER members. Members who don't receive the Commit stay in the old epoch and cannot decrypt new-epoch messages. This is a denial-of-service attack (group state divergence), not a confidentiality breach.

**Mitigation:** MLS Commits are high-priority messages that SHOULD be published to all relays with delivery confirmation. If any member detects they are behind on epochs (they receive a message for epoch N+1 but are on epoch N), they MUST request the missing Commit from other members or other relays.

### 9.10 Metadata Privacy Architecture

The protocol provides layered metadata privacy protections. This section specifies what the protocol protects, how it protects it, and what residual risks remain.

#### 9.10.1 What Is Confidential

- Message content (MLS encryption)
- Context-internal state: roles, tools, governance actions, event log content (all encrypted within the MLS group)
- Identity private state (encrypted to owner's key, §3.7)
- UCAN token contents (within encrypted envelopes)
- Sender identity, timestamps, sequence numbers, epoch, generation (all inside encrypted payload)

#### 9.10.2 Minimal Outer Envelope

The outer envelope — what relays see — contains only:

1. **Routing identifier** — per-context pseudonym (§9.10.4)
2. **Recipient hint** — recipient pseudonym for directed messages, or broadcast marker
3. **Blob TTL** — how long the relay should store before deletion
4. **Encrypted blob** — everything else

Sender identity, timestamps, sequence numbers, epoch, generation — all reside inside the encrypted payload. The relay is a dumb pipe that holds encrypted blobs for a specified duration and delivers them to subscribers of a routing ID. Relay-side ordering, dedup, and expiry are NOT the relay's job. The SDK handles all of this client-side.

#### 9.10.3 Fixed Bucket Padding

Pad plaintext to the next bucket boundary before encryption to prevent message size analysis.

**Bucket sizes:** 256B, 1KB, 4KB, 16KB, 64KB, 256KB.

Messages larger than 256KB are chunked into 256KB blocks. Padding happens below the application layer and above the transport layer — the SDK handles it transparently. Application developers never see it. Relay operators see uniform bucket-sized blobs.

#### 9.10.4 Per-Context Pseudonyms

Each participant derives a per-context keypair that replaces their DID in all outer-envelope fields:

```
context_seed = HKDF(identity_private_key, context_id, "scp-context-pseudonym")
context_keypair = Ed25519_keygen(context_seed)
context_pseudonym = context_keypair.public_key
```

- **Deterministic:** Same identity + same context = same pseudonym.
- **Unlinkable across contexts:** Different context_id = different pseudonym. Relays cannot correlate activity across contexts.
- **Verification:** Sender includes full DID inside MLS-encrypted payload. Group members verify pseudonym-to-DID mapping on first encounter and cache the association.
- **No ZK proofs** — unnecessary complexity since only group members need to verify the mapping.
- The SDK handles derivation, caching, and verification transparently.
- **HSM compatibility.** The standard derivation uses raw `identity_private_key` bytes, which are not exportable from HSM-backed key storage (Secure Enclave, Android Keystore). For HSM-backed identity keys, pseudonym derivation uses an HSM-internal HMAC operation: `context_seed = HMAC-SHA256(identity_key_handle, context_id || "scp-context-pseudonym")`. The HSM performs the HMAC internally and returns the seed without exporting the private key. If the HSM does not support HMAC, a separate non-HSM pseudonym derivation key is derived during identity creation and stored alongside (but outside) the HSM. This key is used exclusively for pseudonym derivation and does not grant signing or decryption capability.

#### 9.10.5 Connection Privacy

1. **Persistent connections mandatory on desktop/workstation/server.** Constant connection to each relay regardless of activity. Prevents connection-timing correlation.
2. **Mobile: push-wake + burst.** Opaque push wakes device, SDK connects to relays, exchanges messages, disconnects.
3. **TLS 1.3 required for all relay connections** (§9.13). Relay operators see the client's IP address — the same information any web server sees. Combined with per-context pseudonyms (§9.10.4), the relay cannot link the IP to a specific identity or correlate activity across contexts.
4. **No custom mix network, no custom proxy protocol.** The protocol does not mandate IP-layer anonymization. The privacy posture already exceeds any conventional app: relays see only pseudonyms, bucketed blob sizes, and TTLs. Clients concerned about IP-level privacy can route through a VPN or Tor at the transport layer — this is a client configuration choice, not a protocol requirement.

#### 9.10.6 Cover Traffic

Cover traffic is **enabled by default and configurable per-client.** The SDK ships with cover traffic on. Clients or operators may disable it via SDK configuration. Disabling degrades traffic analysis resistance but has no functional impact on message delivery or protocol correctness.

1. **Persistent connections: constant-rate, default on.** One padded message per relay connection per 30 seconds. Real messages replace dummy messages. ~15MB/day for 5 relay connections at 1KB padding.
2. **Push-wake connections: no cover traffic.** Connection is transient and brief.
3. **Dummy message format:** Single-byte flag inside encrypted payload distinguishes real from dummy. Recipients decrypt, check flag, discard dummies.
4. **Rate is per relay connection, not per context.** Prevents relay from correlating traffic rate changes with context activity.

#### 9.10.7 DID Resolution Privacy

1. **Desktop/workstation/server: local Mainline DHT node, mandatory.** DID resolution queries become indistinguishable from DHT routing traffic. The device participates as a full DHT node, routing queries for others as well as itself.
2. **Mobile: DHT queries via standard HTTPS gateway or lightweight DHT client.** Resolution is infrequent (once per first contact, then cached), so latency is acceptable.
3. **Aggressive caching:** 24-hour refresh for active contacts, 7-day for inactive. Stale documents detected via BEP44 sequence number comparison. Key change alerts trigger immediate re-resolution.
4. **No batch/prefetch, no resolution proxy.** Local DHT node on desktop and caching on mobile provide practical privacy without new infrastructure.

#### 9.10.8 Relay Query Privacy

1. **Per-context pseudonyms (§9.10.4) are the foundation.** Relay cannot link subscriptions across contexts.
2. **Relay set partitioning, mandatory.** Each context SHOULD use different relays from the client's other contexts. SDK distributes contexts across relays to minimize overlap.

**Combined effect:** Relay sees pseudonyms (unlinkable to identity) on a relay hosting only a fraction of the client's total context set. Per-context pseudonyms prevent cross-context linkage; relay partitioning limits the fraction of a client's activity visible to any single relay.

#### 9.10.9 Cross-Context Key Isolation

Each SCP context is a separate MLS group with independent key material. Compromising one context's keys reveals nothing about any other context's keys. The identity key (Ed25519) is shared across contexts but signs actions — it never directly encrypts group content. MLS handles group encryption with ephemeral key material derived independently per group. Per-context pseudonyms (§9.10.4) prevent the identity key from being visible outside encrypted payloads.

#### 9.10.10 Residual Risks

Even with all protections in this section, the following metadata leaks remain:

- **IP visibility:** Relay operators see the client's IP address (same as any web service). Per-context pseudonyms prevent linking IPs to identities, but a relay operator with access to IP logs could correlate connection patterns. Clients requiring IP anonymity can use a VPN or Tor at the transport layer.
- **Cover traffic timing analysis:** Sophisticated statistical analysis may distinguish real message patterns within constant-rate cover traffic. The constant rate makes this significantly harder but not provably impossible.
- **Push notification timing:** Apple/Google learn that a device received a notification at a specific time. Content and source remain opaque (§10.7).
- **DHT participation patterns:** On desktop, DHT routing traffic is mixed with resolution queries, but a network observer can see DHT participation.
- **Relay trust:** Relays see blob sizes (bucketed), TTLs, and pseudonyms. A relay colluding with a context member could correlate pseudonyms to identities for that context only.

### 9.11 Key Continuity Verification

Equivalent to Signal's "safety numbers." Allows two parties to verify they have the correct keys for each other, detecting MITM on DID resolution.

**Fingerprint format:**

```
fingerprint = SHA256(sort(alice_did, bob_did) || alice_pubkey || bob_pubkey)
```

Displayed as:
- A 12-word mnemonic (BIP-39 word list, first 128 bits of the hash)
- A 60-digit decimal number (first 200 bits)
- A QR code encoding the full 256-bit hash

**Verification flow:**

1. Alice and Bob each compute the fingerprint using their local knowledge of the other's public key.
2. They compare fingerprints via an out-of-band channel (in person, voice call, trusted messaging app).
3. If fingerprints match, key continuity is verified. The SDK records this verification event in identity private state (§3.7).
4. If fingerprints do not match, a MITM is actively intercepting DID resolution. The SDK MUST alert with maximum severity.

**Key change detection:**

- The SDK records the public key associated with each DID on first encounter (Trust On First Use / TOFU).
- On any subsequent DID resolution that returns a different public key, the SDK MUST: (a) alert the user that the key has changed, (b) invalidate the previous key continuity verification, (c) refuse to send encrypted content to the new key until the user explicitly accepts the change or completes re-verification.
- Legitimate key changes (rotation, recovery) are distinguishable: for did:dht, the new DID document is signed by the old key (authorization chain). For social recovery, trusted contacts independently confirm the rotation.

### 9.12 Compromise Recovery Protocol

When a key is known or suspected to be compromised, the following ordered steps constitute the recovery protocol:

**1. Key rotation on trusted device.** Generate new identity keypair on a trusted device. For did:dht: publish new DID document signed by the old key (if available) or via social recovery. For did:web: update the hosted DID document.

**2. MLS Update in all active contexts.** Issue MLS Update proposals in every context. This provides post-compromise security: new epoch keys are derived from the new key material, making the compromised old key useless for future messages. If the old key is unavailable (device stolen), a trusted co-member with admin role must remove and re-add the member.

**3. UCAN revocation.** Revoke all UCAN tokens issued by the compromised key. Publish revocations to the revocation endpoint. Issue new tokens signed by the new key.

**4. KeyPackage rotation.** Delete all outstanding KeyPackages associated with the old key from relays. Publish new KeyPackages signed by the new key.

**5. Contact notification.** The SDK sends a key-change notification to all known contacts. Contacts who completed Key Continuity Verification (§9.11) are alerted that re-verification is needed.

**6. Identity private state re-encryption.** Re-encrypt identity private state (§3.7) under the new key. Publish re-encrypted state to relays.

**Time-shifted key compromise:** An attacker who extracts MLS state at time T can read messages until the next PCS Update. Forward secrecy protects all messages from before T (old epoch keys already deleted). PCS protects all messages after the next Update. The vulnerability window is bounded by the PCS Update interval (§9.7.3).

### 9.13 Transport Security Requirements

**Relay connections MUST use TLS 1.3** (or higher). TLS 1.2 is acceptable only as a fallback when TLS 1.3 is unavailable.

**Certificate validation:** Standard WebPKI validation. The SDK MUST reject self-signed certificates for relay connections unless the user has explicitly configured a self-hosted relay with a pinned certificate.

**Certificate pinning:** The SDK SHOULD support certificate pinning for known relays. If did:web is used as a fallback, certificate pinning for the resolution server is mandatory.

**Relay authentication:** NIP-42 (Nostr relay authentication) is supported but not required. SCP does not depend on relay authentication — encryption-as-access-control (§10.5) makes it unnecessary for confidentiality. Relay authentication may be useful for relays that want to limit their user base or implement per-user rate limiting.

**Direct connections:** For the direct WebSocket transport adapter, connections between devices MUST use TLS (wss://) unless both devices are on the same local network AND the user has explicitly accepted the risk.

### 9.14 Clock and Ordering Model

**Clock model:** SCP does not require synchronized clocks. Timestamps are best-effort, used for ordering hints and replay detection, not for security-critical decisions.

**Clock skew tolerance:** 5 minutes. Messages with timestamps more than 5 minutes in the future are rejected. This is generous enough to handle devices with poorly-set clocks while tight enough to limit replay windows.

**Authoritative ordering:** The Merkle event log order is authoritative. Timestamps inform real-time ordering in the SDK. Once events are committed to the log, the log order is the permanent record.

**Causal ordering:** MLS epoch boundaries serve as synchronization points. Within an epoch, sender generation numbers provide per-sender total ordering. Cross-sender ordering within an epoch relies on timestamps (best-effort) and the Merkle log (authoritative after the fact).

### 9.15 Ephemeral Key Destruction Verification

**Honest limitation:** Proving that a key has been destroyed on a remote device is impossible in the general case. A compromised device can claim destruction while retaining the key. This mechanism provides the strongest verifiable guarantees the hardware supports.

**Platform-attested destruction:** On platforms with hardware security (Secure Enclave, Android Keystore), the SDK requests a destruction attestation from the hardware after deleting key material.

**Destruction protocol for ephemeral context close:**

1. Context TTL expires or participants trigger close.
2. Each member destroys their MLS group state locally: tree secrets, all epoch key schedules, application key material.
3. Each member generates a destruction attestation:

```
KeyDestructionAttestation {
  contextID:             String
  memberDID:             DID
  destroyedAt:           DateTime
  platformAttestation:   PlatformAttestation?  // hardware-backed if available
  method:                .hardwareBacked | .softwareOnly
  signature:             Ed25519Signature       // signed by identity key, NOT the destroyed key
}
```

4. Attestations are published to relays (outside the now-destroyed context). They are signed by the identity key so they remain verifiable after context keys are destroyed.

**Trust levels for destruction claims:**

- **Hardware-attested** (Secure Enclave / Keystore attestation): High confidence. The hardware claims the key is gone.
- **Software-only** (`memset(0)` on key material in memory): Moderate confidence. Memory dumps, swap files, or crash logs may have retained the key.
- **No attestation** (member went offline before close): No confidence. The member may still have the key.

The protocol provides the strongest guarantees the hardware supports and is explicit about where those guarantees end. This is consistent with the honest limitations acknowledged in §5.11.

### 9.16 Sender-Side Key Layer (Blocking)

The MLS group key provides confidentiality against outsiders but not against other group members. Blocking a participant within a context requires a cryptographic layer below MLS that allows selective readability.

#### 9.16.1 Key Architecture

Each participant in a context holds one AES-256 symmetric sender key. All messages are encrypted with the sender's key before being encrypted with MLS. Blocked parties can decrypt the MLS layer but receive opaque ciphertext from the blocking party.

- **Key type:** AES-256-GCM symmetric. One key per sender per context.
- **Key size:** 32 bytes per sender key per context member. Storage is trivial.
- **Encryption order:** Sender-first (AES-256-GCM), then MLS. Recipients decrypt MLS layer, then decrypt sender layer with the cached sender key.

**Stable wrapping keypair.** Each member maintains a dedicated X25519 keypair per context, used exclusively for HPKE wrapping of sender key distributions (§9.16.2). This keypair is published as an MLS LeafNode extension (`scp_wrapping_key`) and is distinct from the MLS leaf HPKE key used for MLS key agreement. The wrapping keypair does NOT rotate on MLS Updates (epoch advances) — it remains stable across epochs so that sender key distributions can always be unwrapped, even by members who are offline during epoch transitions or who join after an epoch advance. The wrapping keypair rotates only on: (1) identity key rotation (§9.12), or (2) suspected compromise. On rotation, the member publishes the new wrapping public key in their LeafNode extension via an MLS Update and re-distributes their current sender key to all non-blocked members using the new wrapping keys.

#### 9.16.2 Key Distribution

Sender keys are distributed inside MLS application messages (encrypted to the group), but the key payload itself is HPKE-encrypted to each individual recipient's public key. This is necessary because MLS application messages are readable by all group members — without per-recipient HPKE wrapping, a blocked party could decrypt the MLS layer and read the new sender key.

- **Key wrapping:** Each sender key distribution message contains per-recipient HPKE-encrypted payloads: `{recipient_did, HPKE_Seal(recipient_wrapping_pubkey, sender_key)}`. The recipient's wrapping public key is the stable X25519 key from their MLS LeafNode extension `scp_wrapping_key` (§9.16.1) — NOT the MLS leaf HPKE key, which rotates on epoch advances. Using a stable wrapping key ensures that offline members and members who join after an epoch advance can still unwrap sender key distributions. The MLS message is readable by all group members, but only the intended recipient can unwrap the actual sender key.
- **New member join:** Existing members each send their current sender key to the new member as an MLS application message containing a single HPKE-encrypted payload for the new member. The new member accumulates sender keys from each existing member.
- **Normal operation:** Sender key is stable — it does not rotate on MLS epoch advances. This is intentional: old sender keys are retained for historical message decryption. Blocking is about future messages, not retroactive access.

#### 9.16.3 Block Protocol

When Alice blocks Bob:

1. Alice generates a new AES-256-GCM sender key.
2. Alice sends a single MLS application message containing HPKE-encrypted payloads for each non-blocked member: `[{did: "charlie", key: HPKE(charlie_wrapping_pk, new_key)}, {did: "dave", key: HPKE(dave_wrapping_pk, new_key)}, ...]`, using each recipient's stable wrapping public key (§9.16.1). Bob can see this MLS message (it's group-encrypted) and can observe the recipient list, but Bob cannot unwrap any key payload.
3. Alice sends a block notification to Bob as an MLS application message: `{"type": "block", "blocker": "did:dht:alice"}`. This notifies Bob's client that Alice has blocked him.
4. Bob's client, upon receiving the block notification, automatically rotates Bob's sender key, distributing the new key via HPKE-encrypted payloads to each member EXCEPT Alice.

**Block event observability:** Block events are observable to the group. Alice distributed keys excluding Bob — other members can see the recipient list and infer the block. This is an acceptable tradeoff, consistent with how other messaging systems handle blocks (some explicitly announce "Alice blocked Bob," others simply stop showing messages). The protocol prioritizes cryptographic enforcement of the block over concealing the block event.

**Result:** Both Alice and Bob have new sender keys that exclude each other. Neither can read the other's future messages. Other context members can read both. The entire exchange completes within one message round-trip.

#### 9.16.4 Blocking vs. Removal

Blocking and removal are distinct operations with different mechanisms:

- **Blocking** (§9.16): Sender-side key rotation. The blocked party remains in the MLS group. They can see encrypted blobs from the blocker but cannot decrypt them. They retain access to messages from non-blocking members. Blocking is a per-relationship decision, not a group decision.
- **Removal** (§9.7): MLS group epoch advance excluding the removed member. The removed party loses access to all future messages in the context. Removal requires governance authority (admin role or context rules). Removal implies blocking but blocking does not imply removal.

#### 9.16.5 Forward Secrecy Interaction

Sender keys rotate ONLY on block events, not on MLS epoch advances. This is a deliberate design choice:

- MLS provides forward secrecy for group-level encryption via epoch advancement.
- Sender keys provide selective readability within the group.
- Rotating sender keys on every epoch would require O(N) individual key distributions per epoch advance — prohibitive for active contexts.
- Old sender keys are retained for historical message decryption. A member who joins and receives the current sender keys can decrypt all messages encrypted with those keys (forward and backward within the sender key's lifetime). Historical access boundaries are defined by block events and member joins, not by time.

---

## 10. Infrastructure and Self-Hosting

### 10.1 Philosophy

Self-hosting is a first-class deployment model, not an afterthought. But "self-hosting" means different things at different layers, and the protocol should be honest about which layers are easy and which are hard.

What the protocol guarantees: **no infrastructure operator owns your identity, your relationships, or your social graph.** These live on your device, bound to your DID, portable across any infrastructure. This is the non-negotiable.

What the protocol provides but doesn't trivialize: **relay and storage infrastructure.** Running your own relay is simpler than running a Matrix homeserver, but it's still a server. Managed infrastructure exists for this layer — not as a lock-in mechanism, but because reliable message delivery and media hosting have real operational costs. The protocol ensures that managed infrastructure is substitutable, not that it's unnecessary.

### 10.2 Device-as-Node

The protocol is designed so that a user's device can be a full protocol participant — not a client that talks to a server, but a node. The device stores protocol state, performs cryptographic operations, and executes protocol logic locally.

This is an explicit architectural choice to avoid Matrix's adoption failure mode, where "self-hosting" means "run a Synapse instance on a server you maintain." For SCP, the device *is* the node. But this comes with an honest constraint: **a device that's offline is a node that's unavailable.** The protocol handles this through relays (§10.4), which means every non-server deployment depends on relay infrastructure for availability. The protocol's real guarantee is not "no server needed" — it's "no server *owns* you." Your identity, your state, and your relationships live on your device. The relay is delivery infrastructure, not a dependency.

```
Deployment spectrum:

  Phone running SCP app          ← full participant when online.
       │                            Needs relay for offline delivery.
       │                            iOS background limits apply.
       │
  Laptop running SCP daemon      ← more capable. Can be always-on.
       │                            Can serve as personal relay.
       │
  Agent workstation              ← dedicated always-on hardware running
       │                            builder agents. Mac Mini, Mac Studio,
       │                            or equivalent. Non-technical users.
       │                            Already always-on for agent tasks.
       │                            Natural SCP node: relay, hosting,
       │                            bridge connectors as marginal load.
       │                            Likely the most common always-on
       │                            self-hosted node type.
       │
  Personal server / NAS          ← power user. Persistent relay.
       │                            Hosts bridge connectors.
       │                            Not "self-hosting" in the Matrix
       │                            sense — no protocol server, just
       │                            relay + storage.
       │
  Managed infrastructure         ← convenience. High availability.
       │                            Media hosting. Paid service.
       │
  All of the above simultaneously ← the expected state for many users.
```

The **agent workstation** tier is a critical addition to the deployment model. As builder agents (LLMs that generate and manage software) become mainstream, non-technical users are acquiring dedicated always-on hardware to run them. These machines are already always-on, capable, and user-controlled. SCP infrastructure — relays, context hosting, bridge connectors — is marginal additional load on hardware that's already running 24/7. The builder agent that generates an SCP app can also provision the infrastructure: spin up a relay, configure contexts, register tools — developer and ops in one.

This changes relay economics fundamentally. The question is not "who pays for relay infrastructure" but "you already have the hardware, the relay is just another process." Self-hosting stops being an aspirational option for technical users and becomes the natural default for anyone with a builder agent workstation. The gravitational pull toward centralized relays weakens when most users have their own always-on node.

The protocol must function correctly at every point on this spectrum. A phone-only user and a user with dedicated infrastructure are both first-class participants. The protocol cannot assume persistent connectivity, stable IP addresses, or server-grade resources.

The critical difference from Matrix: in Matrix, your homeserver owns your identity (`@user:server`). If it dies, you're in trouble. In SCP, your DID is self-sovereign. If your relay dies, you switch relays. If your device dies, you recover your identity through social/device recovery (§3.3). No infrastructure operator holds your identity hostage. This — not the elimination of servers — is the real structural advantage.

### 10.3 Minimal Protocol State

The protocol's state footprint per context is deliberately minimal: membership list, role assignments, capability tokens, tool registrations, governance model, and content hashes. Not content itself. Not media. Not application state.

This is load-bearing. If protocol state is small, devices can be nodes. If protocol state includes all content, only servers can play. Matrix learned this the hard way — room state accumulates unboundedly and Synapse instances consume gigabytes of RAM for large rooms.

Content storage is outside protocol scope — the protocol does not define where content lives, how it's stored, or how it's replicated. That is a client and app-layer decision (see §10.8). The protocol concerns itself with protocol state (membership, roles, tokens, governance, event logs). Content is whatever the context's participants produce and consume. The protocol delivers it through encrypted envelopes; storage is the app's responsibility.

**Verifiable event logs (§7.3.1) add a storage requirement.** Each context maintains a Merkle tree of its event history. This is protocol state — it must be available for validation queries. The tree itself is append-only and grows with context activity. For active contexts, this could become significant. The protocol must define pruning rules (how old events are archived or summarized), checkpoint mechanisms (periodic Merkle roots that compress history), and availability requirements (does every device store the full tree, or can proofs be fetched on demand from relays or peers?). This is the primary tension between minimal state and verifiable history — the design must resolve it explicitly.

### 10.4 Relay Architecture

Devices that aren't always online need relays for message delivery. Relays hold encrypted payloads and deliver them when the recipient comes online. They are the availability layer — the thing that makes the protocol work when devices are asleep, offline, or behind NAT.

**Design goals:**

- **Protocol-unaware.** Relays don't interpret protocol semantics. They store and forward encrypted blobs. This keeps relay implementation simple and prevents relay operators from gaining protocol-level influence.
- **Substitutable.** Switching relays requires no identity change, no context migration, no social disruption. Identity is DID-based, not relay-based. This is the key structural difference from Matrix homeservers.
- **Untrusted for content.** Relays see encrypted payloads. They cannot read content, inspect membership, or understand context semantics. A malicious relay can delay or drop messages; it cannot compromise confidentiality or integrity.

**Honest constraints:**

- **Metadata exposure.** Traffic analysis is powerful even with encrypted payloads. The protocol provides layered metadata privacy protections: minimal outer envelopes with per-context pseudonyms, fixed bucket padding, persistent connections, constant-rate cover traffic, and relay set partitioning. (See §9.9.1 for the formal relay threat model — what relays CAN and CANNOT do — and §9.10 for the complete metadata privacy architecture.)
- **Relay discovery.** If Alice wants to reach Bob, she needs to know Bob's relay. If Bob switches relays, Alice needs to discover the new one. This requires either a centralized directory (defeats the purpose), a distributed discovery mechanism (adds complexity and latency), or multi-relay registration (Bob publishes to several relays, Alice checks all of them). Nostr's experience: users publish a relay list, clients check multiple relays. Workable but not seamless. Relay list authentication is specified in §9.6.3 — NIP-65 signed events prevent relay list substitution attacks.
- **Operational complexity.** A production relay needs reliable delivery, ordering, deduplication, rate limiting, and abuse prevention. "Simple message queue" undersells this. A reference implementation should exist, but running it reliably is a server operations task — not "install an app" level.
- **Gravitational pull.** In theory relays are commodity. In practice, network effects apply to infrastructure. Nostr shows this: a few popular relays handle most traffic. The protocol can't prevent this concentration, but DID-based identity ensures it doesn't create lock-in — popular relay dies, users switch, identity survives. The agent workstation trend (§10.2) may significantly weaken centralization pressure — if most users run their own always-on node, personal relays become the default rather than the exception.

**Self-hosting:** Running a personal relay is feasible for technical users. It requires a stable address, TLS, and uptime commitment. This is meaningfully simpler than running a Matrix homeserver (no state resolution, no federation protocol, no room DAG) but it is still a server. The protocol should ship a reference relay that minimizes operational burden, but should not claim self-hosting is effortless.

**Multi-relay resilience.** For availability and equivocation resistance, clients SHOULD publish to 3+ relays and maintain per-relay reliability scores (§9.9.2). The Relay Consistency Protocol (§9.9.3) enables members to detect relays that show different event histories to different clients. Combined with per-sender sequence numbers (§9.8.5), clients can detect message suppression and switch to healthier relays automatically.

### 10.5 SDK Transport Architecture

The SCP SDK owns all protocol logic — contexts, agents, trust, capabilities, governance, bridge connectors, provenance. This is the product. Transport is not the product.

The SDK provides a **transport abstraction layer**: a defined interface contract between protocol logic and delivery infrastructure. The abstraction specifies what properties the transport must provide (encrypted envelope delivery, offline store-and-forward, context-scoped subscription, relay discovery) without specifying how the transport implements them.

Below the abstraction, **transport bindings** adapt SCP's requirements to specific delivery infrastructure. The SDK ships at least one reference binding. The binding is responsible for encoding SCP envelopes into the transport's native format, managing transport connections, and mapping SCP identities to transport-native identities (e.g., DID to Nostr npub).

**What SCP specifies for transport:**

- Encrypted envelope format (SCP's responsibility — the payload the transport carries)
- Transport abstraction interface (SCP's responsibility — the contract bindings must implement)
- SCP native relay protocol (SCP specifies this — the simplest possible store-and-forward relay purpose-built for SCP envelopes)
- Reference relay implementation (SCP ships this — a minimal relay for self-hosters)
- Transport adapter implementations for existing infrastructure (Nostr, Matrix, Holepunch/Hyperswarm, libp2p, WebSocket, WebRTC, QUIC, BLE, Tor, I2P, SSB, MQTT, NATS, ZeroMQ, Yggdrasil, cjdns)

The SCP native relay is the canonical reference — the simplest possible thing that satisfies SCP's transport needs: accept encrypted blobs, store them, forward to subscribers by context ID and/or recipient DID, respond with delivery receipts, honor deletion requests. All other adapters map the transport abstraction to their respective protocols.

**What SCP does not specify:**

- Third-party relay protocol internals (that's Nostr's/Matrix's/etc. spec, not SCP's)
- Third-party relay implementation
- Relay operations (that's either self-hosting or managed infrastructure)

**No fundamental dependency on any single transport.** The protocol must function correctly on any transport that implements the abstraction interface. SCP native relays are the default, but the protocol does not assume or require them. A deployment using only Hyperswarm, or only Matrix, or only direct WebSocket, is equally valid.

**Transport security.** All relay connections MUST use TLS 1.3 (TLS 1.2 acceptable as fallback). Certificate pinning is supported for known relays. See §9.13 for the complete transport security specification.

**Encryption-as-access-control.** Context access control is enforced through encryption, not through relay logic. Specifically, each context maps to one MLS group (§9.7.1); the MLS group key material is the access credential. All context events are encrypted with the current MLS epoch secrets before reaching the transport layer. Relays store and forward opaque blobs — they cannot read content, verify membership, or enforce roles. Key distribution is membership. Member removal triggers MLS Remove Commit + epoch advancement — the removed member does not possess the new epoch's key material and physically cannot decrypt subsequent messages. This keeps the relay layer genuinely protocol-unaware and makes any encrypted-blob-capable relay — including existing Nostr relays — usable as SCP transport without modification.

**Blocking uses a separate sender-side key layer, not MLS group membership.** DID-to-DID blocking (§3.6) is a unilateral, per-relationship action — it does not require group coordination and does not affect the blocked party's membership in the context. When Alice blocks Dave, Alice rotates her personal sender key and redistributes it to all context members except Dave. Dave physically cannot decrypt Alice's future messages. Dave remains an MLS group member and can still decrypt messages from other members.

This is architecturally distinct from member removal, which IS a group action: MLS Remove Commit advances the entire group to a new epoch, and the removed member loses access to ALL future messages from ALL members. Blocking and removal serve different purposes and use different cryptographic mechanisms:

- **Blocking** (sender-side key layer): Unilateral. Per-relationship. Blocker writes; no group coordination. Blocked party loses access to blocker's messages only. O(n) key redistribution per block (distribute to n-1 members).
- **Removal** (MLS epoch advancement): Group action. Affects all members. Removed party loses access to all future messages. O(log n) via MLS tree ratcheting.

The sender-side key layer works as follows: each member maintains a personal sender key alongside their MLS leaf key. Messages are double-encrypted — first with the sender's personal key, then with the MLS group key. All members hold all other members' sender keys (distributed via MLS application messages). When a block is issued, the blocker generates a new sender key and distributes it to all members except the blocked party via individual MLS application messages. The blocked party can still decrypt the MLS layer but encounters ciphertext from the blocker that they cannot decrypt.

### 10.6 Content and Data Sovereignty

**Content is agnostic.** The protocol has no opinion on what content is — text, images, video, structured data, binary blobs, real-time streams. Content is whatever contexts produce and whatever frontends need to display. The protocol does not define content types, does not constrain content formats, and does not host content. App builders and their clients decide what content they support and how they store it.

**Storage is the user's responsibility — but the SDK makes it tractable.** SCP is a protocol, not an entity. It does not host anything. The people and organizations who use the protocol host their own content. But "host your own content" means different things at different scales, and the SDK must make all of them first-class:

```
Deployment spectrum for content/data:

  Generated ephemeral client          ← Content lives on the user's device
       │                                or wherever the generated app puts it.
       │                                Possibly transient. Possibly local-only.
       │
  Personal app / home server          ← User controls storage. Small scale.
       │                                Local NAS, personal cloud, phone storage.
       │
  Community app (Cronica, etc.)       ← App developer chooses storage backend.
       │                                Could be managed hosting, could be
       │                                user-contributed, could be hybrid.
       │
  Enterprise app on SCP               ← Enterprise-grade databases, CDNs,
       │                                content lakes. Full infrastructure team.
       │
  All of the above simultaneously     ← Different contexts, different apps,
                                        different storage. Protocol doesn't care.
```

**What the SDK provides:** The SDK handles encrypted envelope delivery, context key management, and protocol state. For content storage, the SDK provides interfaces and guidance for sovereign storage at every scale — but does not mandate a specific backend. A generated client that stores everything locally is valid. An enterprise app with a distributed content lake is equally valid. The protocol transmits content through encrypted envelopes; where that content persists after delivery is an app-layer decision.

**Media is the same story.** Photos, video, audio, large files — these have real costs (bandwidth, transcoding, storage) that the protocol does not absorb because the protocol is not an entity that can absorb costs. Managed infrastructure services can offer media hosting as a paid service. Self-hosters handle their own media. The protocol treats media like any other content — it flows through encrypted envelopes. Heavy content may require out-of-band storage with in-band references, but that's a client implementation pattern, not a protocol requirement.

### 10.7 Notifications and Push

Mobile devices need push notifications. On iOS the only mechanism is APNs (Apple Push Notification service). On Android, FCM (Firebase Cloud Messaging). Both are platform-mediated — Apple and Google are in the delivery path.

**Push notification opacity is mandatory.** Push payloads MUST contain a wake signal and nothing else. No context ID, no sender DID, no message preview, no metadata of any kind. The device wakes, connects to relays, pulls encrypted envelopes, and decrypts locally. Apple/Google learn only that the device received a notification at a specific time.

- **Push payloads are fully opaque.** The push payload contains exactly one piece of information: "wake up." No sender, no context, no count, no preview. The SCP agent on the device connects to its relay set and pulls all pending envelopes.
- **The push service knows timing, not content or source.** Apple/Google learn when a device received a notification. They cannot determine which context, which sender, or even whether the notification corresponds to one message or many.
- **A sovereign push alternative is desirable but not blocking.** If a mechanism emerges that enables push without platform gatekeepers, the protocol should adopt it. For now, this is an accepted constraint with the opacity guarantee limiting metadata exposure to timing only.

### 10.8 Multi-Device

Multi-device coordination — read state, session continuity, notification deduplication, device handoff — is a client-scope concern. The protocol provides the building blocks:

- **Identity private state (§3.7)** syncs personal configuration across devices via encrypted event log on relays.
- **Context state** is the same regardless of which device queries it.
- **Encrypted envelopes** are available on relays for any device that holds the keys.

How a client uses these to implement read markers, notification deduplication, or session handoff is the client's decision. A simple client might treat each device as independent. A sophisticated client might sync UI state through identity private state or through a dedicated coordination mechanism. The protocol delivers the same encrypted envelopes to all devices; the client decides how to present them.

### 10.9 Real-Time and Async

The protocol supports both real-time and asynchronous interaction. This is not a dichotomy — it's a spectrum, and the SDK provides first-class support across it.

- **Async:** Messages are encrypted, delivered to relays, fetched when the recipient's agent comes online. This is the baseline that works for all participants regardless of connectivity.
- **Real-time:** When both parties are online simultaneously, the transport layer can deliver envelopes immediately. WebSocket connections to relays, direct peer-to-peer via libp2p, or any transport binding that supports streaming delivery. Latency depends on the transport binding, not the protocol.
- **Presence, typing indicators, live collaboration:** These are tool-level or context-level capabilities, not protocol primitives. A context that needs presence registers a presence tool. A context that needs typing indicators includes them as ephemeral events. The protocol carries them through the same encrypted envelope system — the content is up to the context.

The SDK provides the transport abstraction and envelope delivery. Whether that delivery is batched-async or streaming-realtime depends on the transport binding and what the client needs. Both are first-class.

### 10.10 Business Model Direction

Managed infrastructure and media/content hosting are the probable revenue surfaces. Heavy content (video, large files, real-time streams) has real storage and bandwidth costs. The protocol works either way — self-hosters shoulder their own costs, managed infrastructure shoulders it for a fee. The point is the choice exists and the protocol doesn't prefer either.

Relay economics are the responsibility of app builders and relay operators. The protocol defines what relays do, not who runs them or how they're funded. Community-operated relays, paid relay services, app-bundled relay infrastructure, and self-hosted relays are all valid. The protocol ensures none of them create lock-in (DID identity, substitutable relays). In practice, app developers who build on SCP are expected to provision relay infrastructure for their users — the same way app developers today provision API servers, databases, and CDNs. There is no assumption of free community relay infrastructure at the protocol level; a protocol foundation may eventually provide shared infrastructure, but this is not a dependency.

**The agent workstation effect.** As builder agents become mainstream and users acquire dedicated always-on hardware to run them (§10.2), the relay economics shift structurally. Relay infrastructure is marginal load on hardware that's already running 24/7. Builder agents can provision SCP infrastructure — relays, context hosting, bridge connectors — as part of generating apps. The "who pays for relays?" question dissolves for users with agent workstations: you already have the hardware, the relay is just another process. Managed infrastructure remains valuable for users without always-on hardware (phone-only users) and for heavy content workloads, but the default self-hosting path becomes significantly more accessible.

### 10.11 Build on Existing Infrastructure

The transport, data sovereignty, and self-hosting layers are the least novel parts of the system. Existing technologies provide strong foundations. The novel work — and the value — is the Social Context Layer that sits on top.

**Nostr** is the closest existing analog to SCP's transport and identity layer. Keypair-based identity, substitutable relays, signed events, client-side intelligence — SCP's lower stack is architecturally near-identical. SCP defines its own transport abstraction with Nostr as one possible binding rather than building directly on Nostr's event model. This preserves transport agnosticism and avoids coupling to Nostr's governance and ecosystem dynamics. SCP's encryption-as-access-control model and MLS-based group encryption requirements (§10.5) go beyond what unmodified Nostr relays provide — the transport binding approach allows SCP to use Nostr relays where they fit while maintaining its own protocol requirements.

**Matrix** provides federated messaging with strong encryption (Megolm/Olm) and a mature room model. SCP contexts could map to Matrix rooms with SCP-specific state events. Matrix's federation model is heavier than Nostr's relay model but provides stronger delivery guarantees.

**libp2p** provides peer-to-peer transport primitives (pubsub, DHT, NAT traversal) that could underpin direct device-to-device communication without relays for devices that are simultaneously online.

The protocol should define its transport requirements abstractly and provide reference bindings for at least one existing transport. The choice of primary transport binding is a design decision with ecosystem implications — it determines which existing community SCP builds alongside.

---

## 11. Prior Art

| Component | Existing Standard/Technology | SCP Relationship |
|---|---|---|
| Identity | DID (W3C) | Build on directly |
| Capability tokens | UCAN | Build on directly |
| Key custody | Passkeys, WebAuthn, Secure Enclave | Delegate custody to |
| Transport | Matrix, libp2p, Nostr | Build on / interop |
| Data sovereignty | Solid, AT Protocol PDS | Informed by, evaluate |
| Federated contexts | ActivityPub, Matrix rooms | Informed by |
| Access control | RBAC (decades old) | Standard application |
| Auth delegation | OAuth, GNAP | Informed by |
| Local AI-tool wiring | MCP (Model Context Protocol) | Agent-level integration |

**What no existing standard covers:** Agents as first-class protocol participants with formalized trust semantics, one-agent-per-person-per-context constraints, context-bound agents that cannot cross at the protocol level, trust as identity + capability pairs applied to autonomous agents, non-fungible cross-platform identity attestations with shadow identity claiming, protocol-level bridge connectors with provenance-tracked content attribution, and all of this framed as infrastructure for generated/ephemeral apps. This is the novel contribution of SCP.

---

## 12. Platform Bridge Connectors

### 12.1 The Problem

The social graph doesn't start empty. Users have relationships, conversations, communities, and history on existing platforms — X, Facebook, Instagram, WhatsApp, Discord, Slack, and whatever comes next. SCP must provide a path to participate alongside these platforms without requiring their cooperation or conformance.

This is not the same as local data import. Local import (scraping your own data, downloading your archive) is a user-level concern handled by local agent orchestration below the protocol boundary. Bridge connectors are a **protocol-level primitive** — a standardized interface through which non-SCP platforms can participate in SCP contexts, and SCP contexts can reach into external platforms.

### 12.2 Bridge Connectors as Protocol Entities

A bridge connector is a registered protocol entity — distinct from agents, tools, and contexts. It translates between an external platform's native protocol and SCP's protocol semantics.

```
┌───────────────────────────────────────────────────────────────────┐
│                         SCP CONTEXT                                │
│                                                                    │
│  Native members:              Shadow identities:                  │
│                                                                    │
│  Alice·Agent (admin)          @dave_x (shadow, via X Bridge)      │
│  Bob·Agent   (member)         @eve_fb (shadow, via FB Bridge)     │
│  Carol·Agent (member)         @frank_wa (shadow, via WA Bridge)   │
│                                                                    │
│                  ┌─────────────────────────┐                      │
│                  │    Bridge Connector      │                      │
│                  │                          │                      │
│                  │  Operator: did:key:...   │ ← Accountable       │
│                  │  Platform: X (Twitter)   │   identity runs      │
│                  │  Mode: relay | puppet    │   the bridge.        │
│                  │  Provenance: marked      │                      │
│                  └────────────┬─────────────┘                      │
│                               │                                    │
└───────────────────────────────┼────────────────────────────────────┘
                                │
                     ┌──────────▼──────────┐
                     │   External Platform  │
                     │   (X, FB, WA, etc.)  │
                     └─────────────────────┘
```

Properties of bridge connectors:

- **Operated by accountable identities.** Every bridge has a human operator bound by DID. Bridge misbehavior traces to a person. This is consistent with SCP's core invariant: every action traces to a human.
- **Registered with contexts.** A bridge connector registers with a specific context. The context's governance model controls whether the bridge is admitted. Context members can see which bridges are active and who operates them.
- **Transparent.** Bridge presence, operator identity, connected platform, and operating mode are visible to all context members and in context metadata (visible before opt-in).
- **Revocable.** Context governance can remove a bridge at any time, severing the connection to the external platform.

### 12.3 Shadow Identities

When a bridge connector brings external platform participants into an SCP context, it creates **shadow identities** — protocol-level representations of entities that exist on the external platform but do not (yet) have native SCP identities.

Shadow identities differ from native SCP identities in critical ways:

- **Attributed but not verified.** A shadow identity for `@dave_x` asserts that this entity is Dave on X. The assertion comes from the bridge operator, not from Dave himself. The trust in this attribution depends on trust in the bridge operator.
- **Restricted by default.** Shadow identities receive a constrained role — typically observer-equivalent. They cannot exercise capabilities that require verified identity. Specific role assignment is up to context governance.
- **Marked as bridged.** All actions and content associated with a shadow identity carry provenance marking indicating the bridge source. No shadow identity can be mistaken for a native SCP participant.
- **Claimable.** If Dave later joins SCP and publishes an identity attestation (§3.5) binding his X handle to his DID, his shadow identity can be claimed and merged with his native identity. Past actions attributed to the shadow are now attributed to Dave's DID. This transition is one-way and irreversible — once claimed, the shadow is retired.

```
  Before claiming:                   After claiming:

  @dave_x (shadow)                   Dave·Agent (did:key:xyz)
  ├─ source: X Bridge                ├─ native SCP identity
  ├─ operator: bridge_did            ├─ attestation: @dave_x on X
  ├─ role: observer                  ├─ role: member (upgraded by governance)
  ├─ trust: depends on bridge        ├─ trust: depends on Dave's DID
  └─ provenance: bridged             └─ provenance: native
                                         └─ historical: bridged (pre-claim)
```

### 12.4 Bridge Operating Modes

Bridge connectors operate in one of several modes, reflecting the practical constraints of interfacing with uncooperative platforms:

**Relay mode.** The bridge operates a single account on the external platform and relays content through it. External participants appear via shadow identities. Attribution depends on the bridge parsing the external platform's messages correctly. This is the most robust mode — it requires no user credentials and works even when platforms actively resist bridging.

**Puppet mode.** The bridge authenticates as the SCP user on the external platform, using credentials the user has delegated. Messages appear to come from the user natively on the external platform. This provides better fidelity but requires the user to trust the bridge operator with their external platform credentials. Self-hosted bridges mitigate this — users run their own bridge and delegate credentials only to software they control.

**API mode.** The bridge uses the external platform's official API (where available). This is the most stable mode but limited by whatever the platform exposes. Some platforms (Bluesky/AT Protocol, Mastodon/ActivityPub) are fully open and make this trivial. Others (X, Facebook) restrict API access to the point of uselessness for social bridging.

**Cooperative mode.** The external platform voluntarily implements the bridge connector interface. This does not require the platform to adopt SCP — only to expose a structured interface that the bridge can consume. This is the aspirational end state: platforms don't conform to SCP, but they interface with a connector to participate. This mode requires no credential delegation, no scraping, no reverse engineering.

The protocol defines the bridge connector interface such that cooperative mode is clean and well-documented, making the ask to platforms minimal: "You don't need to change anything about your system. Just implement this interface and your users can participate in SCP contexts."

### 12.5 Trust and Provenance for Bridged Content

All content entering an SCP context through a bridge carries a **provenance chain** that includes:

- The originating platform
- The bridge connector that carried it
- The bridge operator's DID
- The bridge operating mode
- The shadow identity it's attributed to (or the native DID if claimed)

This provenance is structural, not content-level. It flows through the data provenance system (§7.7) and is available to any agent evaluating trust.

Trust evaluation for bridged content is necessarily weaker than for native content. The hierarchy reflects two independent axes — **identity confidence** (who is the author?) and **transport confidence** (how did the content arrive?):

```
Trust hierarchy:

  IDENTITY                TRANSPORT              COMBINED

  Native SCP identity     Native action          ← strongest
  (DID verified)          (end-to-end SCP)         Both axes at full confidence.

  Native SCP identity     Bridged action          ← strong
  (DID verified)          (via bridge infra)        Identity is verified — an attestation
                                                    links the external handle to the DID.
                                                    But content traveled through bridge
                                                    infrastructure: timestamps are platform-
                                                    reported, content integrity depends on
                                                    bridge operator fidelity.

  Claimed shadow          Historical bridged      ← moderate
  (retroactive DID link)  (pre-claim content)       User joined SCP and claimed an existing
                                                    shadow. Old content gets retroactive
                                                    attribution, but was created before any
                                                    SCP identity existed to verify against.

  Shadow identity         Bridged action          ← weakest
  (no DID claim)          (via bridge infra)        No SCP identity has claimed this shadow.
                                                    Trust depends entirely on the bridge
                                                    operator's DID and reputation.
```

Agents can calibrate their behavior based on provenance. A conservative agent might ignore all shadow-attributed content. A permissive agent might treat claimed shadows equivalently to native identities. The protocol makes the distinction legible; the evaluation is up to the participant.

### 12.6 Bridge Connectors and Context Isolation

Bridge connectors do not violate context isolation. A bridge registered in Context A has no access to Context B. If the same external platform is bridged into two contexts, they are separate bridge instances with separate registrations.

Bridge connectors are not agents — they cannot initiate actions, exercise capabilities, or participate in governance. They are translation infrastructure. All agency flows through the agents and governance of the context they're registered in.

### 12.7 Self-Hosting Bridges

Consistent with SCP's self-hosting philosophy (§10), bridge connectors are self-hostable. A user can run their own bridge to connect their own external platform accounts into SCP contexts they participate in. Self-hosted bridges eliminate the need to trust a third-party bridge operator with credentials or data.

The managed infrastructure layer (§10.5) may offer hosted bridges as a convenience service, but the protocol treats self-hosted and managed bridges identically.

### 12.8 Platform Resistance

Platforms can and will resist bridging. This is expected and acknowledged. Resistance takes forms:

- API restriction or removal
- Rate limiting authenticated sessions
- Protocol changes that break reverse-engineered integrations
- Legal threats (ToS enforcement, cease-and-desist)

The protocol's response is structural, not adversarial:

- **Cooperative mode** gives platforms a reason to participate rather than resist — their users can reach SCP contexts without leaving the platform.
- **Relay and puppet modes** are resilient but fragile. The ecosystem maintains bridge implementations communally, similar to how Matrix bridges are maintained today.
- **Data portability rights** (GDPR, CCPA, EU Digital Markets Act) provide legal backing for users accessing their own data.
- **The aspirational path** is that as SCP's network grows, platforms face economic pressure to offer cooperative mode rather than lose users to a network they can't see into.

### 12.9 Incentive Structure for Cooperative Mode

Cooperative mode should not be aspirational — it should be the path of least resistance for platforms. The protocol achieves this by making non-cooperation expensive and cooperation cheap.

**Why platforms resist bridging (Matrix's experience):** Bridges leak users off the platform. A WhatsApp user who can read WhatsApp messages in Matrix has less reason to open WhatsApp. The platform loses engagement metrics, ad impressions, and data collection surface.

**Why SCP changes the equation:**

- **Shadow identities are second-class.** Bridged content via relay/puppet mode is provenance-marked as weak-trust. Platform users who show up as shadows in SCP contexts are legible but untrusted. If the platform implements cooperative mode, their users get stronger provenance — bridged-cooperative is more trusted than bridged-relay because the platform has vouched for the attribution.
- **Cooperative mode gives the platform a seat.** In cooperative mode, the platform can include metadata about its users that strengthens trust evaluation. This gives the platform influence over how its users are perceived in SCP — influence it doesn't have in relay/puppet mode where a third party is scraping.
- **The bridge happens anyway.** If users want to bridge, relay and puppet modes exist. The platform can't prevent it without hurting its own users' experience. Cooperative mode gives the platform control over a process that will happen regardless.
- **Minimal implementation cost.** The bridge connector interface is deliberately small — a handful of structured endpoints. Not a protocol adoption, not an architecture change. Comparable to implementing an OAuth provider or a webhook receiver.

The design principle: make the protocol's trust model reward cooperation and make non-cooperation a worse experience for the platform's own users, without making it an ultimatum.

---

## 13. Versioning and Protocol Evolution

The protocol will evolve. New capabilities, new attestation types, new transport bindings, refinements to governance primitives. The versioning strategy follows established best practices:

- **Semantic versioning** for the protocol specification. Breaking changes increment the major version.
- **Capability negotiation.** Agents and contexts declare which protocol version they support. Contexts can set minimum version requirements for participation. Agents encountering a context with a higher version than they support can decline to join or participate in a degraded mode.
- **Forward compatibility as a constraint.** New protocol versions must define how old agents interact with new features — graceful degradation, not hard failure. An agent built against v1 encountering a v2 context should understand what it can and can't do.
- **Extension points.** The attestation type system, tool schema format, and capability declaration contract are designed to be extensible without protocol version bumps. New attestation types, new tool capabilities, and new declaration fields can be added as extensions. Breaking changes to existing types require a version bump.

The goal is that protocol evolution feels like capability growth, not migration. Existing contexts and agents continue to work. New features are available to participants that support them.

---

## 14. Protocol Governance

SCP is a protocol, not a product. Its long-term governance follows the foundation model used by successful open protocols:

- **Early stage (current):** Protocol design is driven by the creators (Limn) and informed by the first client (Cronica). Decisions are made by the people building it.
- **Growth stage:** As adoption grows and other builders contribute, governance broadens. Contributions, extensions, and binding implementations come from the community. Decision-making becomes more inclusive.
- **Mature stage:** If the protocol achieves wide adoption, a foundation or equivalent governance body stewards the specification, reference implementations, and ecosystem health. This is the path taken by Matrix (Matrix.org Foundation), MCP (Anthropic stewarding), and W3C standards (consortium governance).

The protocol's design — extensible attestation types, pluggable transport bindings, context-level governance autonomy — is deliberately structured so that protocol-level governance decisions are rare. Most evolution happens at the edges: new transport bindings, new tool types, new context governance models, new challenge suites. The protocol core changes slowly; the ecosystem evolves fast.

---

## 15. Regulatory Compliance

The protocol is designed compliance-first and privacy-first. These are core ethos, not afterthoughts.

**Obligations fall on protocol users.** SCP is an open protocol specification, not a service. The protocol does not process data, host content, or operate infrastructure. Entities that build on SCP — app developers, relay operators, managed infrastructure providers, bridge operators — bear the regulatory obligations appropriate to their role. The protocol provides the tools to meet those obligations.

**Privacy by design:**

- **Encryption-as-access-control (§10.5)** means content is end-to-end encrypted. Relay operators cannot read content. This is a structural privacy guarantee, not a policy.
- **Identity private state (§3.7)** is encrypted to the owner's keys. Personal data (block lists, preferences, graph visibility) is not accessible to any other party.
- **Context metadata transparency (§5.7)** lets users make informed decisions before participating. No dark patterns at the protocol level.
- **DID-based identity (§3.1)** is self-sovereign. No identity provider holds user data.

**GDPR and data portability:**

- **Right to erasure.** A user can revoke their DID, revoke all attestations, and leave all contexts. Their identity private state is encrypted and under their control. Content they authored in contexts remains (attributed to a now-revoked DID) — the protocol does not retroactively delete content from other participants' contexts, as that would be modifying other people's state. Apps and context governance can implement content deletion policies; the protocol provides the identity revocation primitive.
- **Right to data portability.** Protocol state (membership, roles, attestations, behavioral records) is inherently portable — it's bound to the user's DID, not to any service provider. App state portability depends on the app (§8.3).
- **Data minimization.** Protocol state is minimal by design (§10.3). The protocol collects and stores the minimum data needed for its function.

**Content moderation (EU Digital Services Act, etc.):**

- Content moderation is a context governance responsibility, not a protocol responsibility. Contexts define their own rules, enforce them through roles and consequence mechanisms, and are governed by accountable identities.
- The protocol provides the tools for moderation (role-based permissions, consequence mechanisms, governance models, member ejection) but does not mandate specific content policies. Different contexts have different standards — this is by design.
- Managed infrastructure providers (relay operators, hosting services) may have additional obligations under local law. The protocol's encryption model means relay operators have limited ability to moderate content they can't read — this is a feature for privacy and a tension for compliance that operators must navigate based on their jurisdiction.
- **Relay vs. context as regulatory surface.** Relays handle opaque encrypted blobs and are not positioned to be classified as content intermediaries — they are more analogous to encrypted storage or transport providers. Content moderation obligations, if they materialize, are expected to apply at the **context** level, where content is legible and governance structures exist to enforce policies. This legal argument has not been tested in any jurisdiction; the protocol's design assumes it but does not depend on it.

**The boundary:** The protocol is responsible for providing privacy-preserving, sovereignty-respecting infrastructure with the tools needed for compliance. The protocol is not responsible for the compliance decisions of entities that build on it. This is the same boundary that TCP/IP, HTTP, and email operate under — the protocol enables, the users of the protocol are responsible.

---

## 16. Open Questions

### Design Decisions Pending

- **Context capability ceiling mutability.** Leaning toward immutable (stronger security, requires migration to expand — analogous to onchain programs). Mutable under governance is the alternative (more flexible, enables creep). Undecided; depends on solving artifact portability and context migration tooling.
- **~~Context governance primitives.~~** ✅ **Partially resolved.** ADR-008 specifies context lifecycle state machine with single-admin governance. ADR-009 specifies role assignment and capability ceiling enforcement. The pluggable governance interface for multi-sig/consensus models remains unspecified — not blocking for initial implementation (single-admin is sufficient).
- **~~A2A propose/accept.~~** ✅ **Resolved — removed.** Replaced by two complementary mechanisms: standing bilateral contexts (§5.12.6) for lightweight direct communication, and multi-parent child contexts (§5.13) for governed, symmetric cross-context collaboration. Tool interfaces (§6.2) handle asymmetric service-style interactions. No separate A2A negotiation primitive needed.
- **Context-to-context tool interface mechanics.** How do contexts discover, negotiate, and establish interop interfaces? Specifics TBD.
- **Earned capacity mechanisms.** How do new identities earn more agent slots / context participation capacity? What signals are used? Not gamifiable.
- **Agent capability metadata standard.** What's surfaced, how it's structured, how it's verified.
- **~~Content provenance system.~~** ✅ **Resolved.** DataProvenance format specified in §7.7.1. Provenance attached automatically by protocol on context boundary crossings. Provenance evaluation rules in §7.7.2. Absence-as-signal principle established. Cross-context tool calls and structured messages carry provenance.
- **Rate limiting defaults.** Context creation limits, context participation limits per human. Surfaces identified, defaults not set.
- **Identity attestation discovery.** Likely direction: attestations are discoverable through the contexts and platforms where they're relevant. If Alice wants to find Bob's SCP identity from his X handle, she queries through X's context or bridge — platforms store attestation data alongside their own data. This may eliminate the need for separate discovery infrastructure (DHT, registry), but the mechanics need specification.
- **Identity attestation verification methods.** Platform-specific verification flows (OAuth, signed posts, DNS records, etc.) need standardization per platform.
- **Shadow identity role defaults.** What capabilities should shadow identities receive by default? Observer-equivalent is conservative; some contexts may want more permissive defaults.
- **Bridge connector interface specification.** The cooperative mode interface — what a platform implements to participate — needs to be minimal and well-specified. This is the "pitch" to platforms.
- **Bridge credential custody.** In puppet mode, how are user credentials for external platforms delegated to bridges? Needs to be secure, revocable, and ideally zero-knowledge to the bridge operator.
- **Shadow identity claiming mechanics.** How does the merge work when a shadow identity is claimed? What happens to historical actions, roles, trust evaluations?
- **Capability declaration format.** What does the machine-readable app capability manifest look like? JSON schema, protocol buffers, something else? Must be parseable by LLMs generating apps.
- **Context state portability format.** What's the serialization format for context state that enables app switching? Must be complete enough that a new app can render a context without loss.
- **Minimum viable agent specification.** What does the simplest possible agent look like? The "transparent pipe" agent that just forwards human input needs a reference implementation that's trivially embeddable.
- **~~Relay protocol specification.~~** ✅ **Resolved.** ADR-004 specifies the SCP native relay protocol: PUBLISH/SUBSCRIBE/UNSUBSCRIBE operations over WebSocket, blob TTL enforcement, recipient_hint for directed delivery. Minimal outer envelope format specified in §9.10.2.
- **Cooperative mode trust tiers.** How much does cooperative mode actually improve trust provenance for bridged content? Need to define the specific trust differential that incentivizes platforms.
- **~~Primary transport binding.~~** ✅ **Resolved.** SCP native relay protocol is the canonical transport. Transport is fully abstracted — 17 adapter options listed, no structural dependency on any single transport. Transport security requirements specified in §9.13 (TLS 1.3 required). Relay threat model formalized in §9.9.
- **~~Transport abstraction interface.~~** ✅ **Resolved.** ADR-005 specifies the `TransportAdapter` trait: connect, send, subscribe, query, disconnect. Async interface, error types defined. SCP native relay is the canonical implementation.
- **~~Context key management.~~** ✅ **Resolved.** MLS (RFC 9420) selected. One MLS group per context. MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 ciphersuite. Full specification in §9.7 (group key management), §9.5 (cryptographic primitives), §9.8 (message security). MLS tree-based key management provides O(log N) member exclusion. Blocking uses a separate sender-side key layer (§9.16) that operates independently of MLS epoch advancement.
- **~~Metadata privacy.~~** ✅ **Fully resolved.** Comprehensive metadata privacy architecture specified in §9.10: minimal outer envelope (§9.10.2), fixed bucket padding (§9.10.3), per-context pseudonyms (§9.10.4), persistent connections + TLS (§9.10.5), cover traffic configurable default-on (§9.10.6), DID resolution privacy (§9.10.7), relay query privacy via pseudonyms + partitioning (§9.10.8). Push notification opacity mandated in §10.7. Sender-side key layer for blocking specified in §9.16 with HPKE-wrapped per-recipient key distribution.
- **~~Verifiable event log format.~~** ✅ **Resolved.** ADR-011 specifies the event log: append-only Merkle tree per context, SHA-256 hash chain, entry structure (event type, sender DID, sequence number, timestamp, payload hash), inclusion proofs, consistency checkpoints. Efficient enough for device-as-node participation.
- **Behavioral record schema.** §7.3.2 defines what facts are derivable from event logs, but the record format is unspecified. How are behavioral records serialized, exchanged between agents, and verified against source logs? Must be compact enough for inline presentation and rich enough for meaningful evaluation.
- **Challenge suite standards.** §7.3.4 introduces challenge-response verification for agent capabilities but doesn't define the challenge suites themselves. What tests constitute "prompt injection resistance"? Who defines and maintains challenge suites? How are custom challenges validated as fair? Need a registry or discovery mechanism.
- **Consequence mechanism defaults.** §7.3.7 defines automated consequence rules but leaves threshold values and escalation curves to individual contexts. Should the protocol define recommended defaults? Minimum consequence severity for certain violations? How do contexts communicate their consequence structure in a comparable format?
- **Endorsement accuracy tracking.** §7.4.2 mentions that endorsement accuracy history pushes endorsements from Layer 4 toward Layer 2. How is accuracy measured? What constitutes a "bad endorsement" — the endorsed identity being ejected from a context? A governance action? This feedback loop needs design.
- **Attestation storage and discovery.** Where do attestations live? In DID documents? On relays? In a dedicated attestation layer? Agents need to find relevant attestations for identities they interact with. Discovery must be decentralized but practical.
- **Threshold independence verification.** §7.3.5 says the protocol can check attestor independence via shared memberships and mutual endorsements. The specific independence metric and correlation thresholds need definition.
- **Identity private state size constraints.** §3.7 introduces identity-scoped private state for block lists, preferences, and personal annotations. Block lists are small; agent memory or annotations could grow. Does identity private state follow the same minimal-state principle as context state, or is the single-owner case less constrained?
- **Identity private state relay obligations.** Do relays treat identity private state the same as context events? Same retention, storage class, availability guarantees? Or is there a differentiated commitment?
- **Identity key rotation and private state re-encryption.** When an identity key rotates (recovery scenario), private state must be re-encrypted. Single-owner simplifies this (no group redistribution) but the migration step needs specification — especially for large private state. (Key rotation triggers and the compromise recovery flow are specified in §9.7.4 and §9.12.)
- **Identity private state discovery pointer.** Does the DID document explicitly signal where private state is stored, or is it implicit from the relay list? Relays need to distinguish between "context events involving this DID" and "this DID's private state."

### Context Lifecycle and Governance

- **Memory scope enforcement boundary.** Ephemeral key destruction is protocol-enforceable. Local agent memory is not. The spec acknowledges this (§5.11), but the boundary between "protocol can enforce" and "protocol can only signal" needs precise documentation for implementers. (§9.15 specifies the three trust levels for key destruction verification — hardware-attested, software-only, no attestation — which partially addresses this, but the agent-side memory boundary remains unspecified.)
- **Context promotion mechanics.** When an ephemeral context "promotes" to persistent (both parties agree to continue), what happens? Options: (a) new context created, referencing the closed ephemeral one, or (b) same context with TTL removed and keys preserved. Option (a) is cleaner for the security model; option (b) preserves continuity. Needs decision.
- **Summary generation mechanics.** For summary memory scope (§5.11): how is the summary produced? Who generates it — the context's tools, the participants collaboratively, or the protocol? What happens if participants disagree on the summary? What's the verification window before keys are destroyed?

### Uncovered Areas

- **~~Transport layer specifics.~~** ✅ **Largely resolved.** ADR-005 specifies the `TransportAdapter` trait. ADR-004 specifies the SCP native relay protocol. Transport security in §9.13. Relay threat model in §9.9. Remaining: relay discovery protocol (how clients find relays).
- **Cronica as first client.** How quests, the AI Guide, and quest communities map onto SCP.
- **Offline/local-first behavior.** Disconnection handling, sync, conflict resolution mechanics. (Informed by device-as-node §10.2, but mechanics unspecified.)
