# SCP Design Session — Full Record

**Date:** February 14, 2026
**Participants:** Alec (Limn), Claude
**Purpose:** Capture every decision, rationale, open question, and line of reasoning from the initial SCP design session so future work can pick up with full context.

---

## Origin and Motivation

Alec observed that app generation is becoming trivial — clients and server logic will be generated on-demand from simple prompts. What remains hard is the connective tissue: identity, social relationships, transport, persistence, and trust. He proposed building an open, ecosystem-agnostic infrastructure layer that sits beneath any generated or traditional application.

Key motivations:
- Apple, Google, and Meta will build closed versions of this to suit their ecosystems. This is the open alternative that fills the gaps they leave.
- The protocol should connect to models and data that already exist (profiles, social accounts, devices, services) while also working fully self-hosted and isolated.
- The difference between self-hosting and using managed infrastructure should be negligible — same way generating the client is becoming negligible.
- Cronica (an AI enabled side questing app with social features, by Limn) is the first consumer client. The protocol serves Cronica's needs but is designed to be general-purpose.

Alec rejected the advice to build Cronica first and extract the protocol later. His reasoning: the economics of building have changed — AI-assisted engineering makes it feasible to build both simultaneously. The approach is to build from both ends — protocol and product — at the same time.

---

## Naming

The protocol is called the **Social Context Protocol (SCP)**. The name reflects that the core abstraction is socially-scoped contexts in which agents operate.

---

## Architecture Decisions (Closed)

### Identity

**Decision:** Cryptographic root identity using DIDs (W3C Decentralized Identifiers).

**Key custody:** Users never see or manage keys. Custody is delegated to whatever the user already trusts:
- Device secure enclave (iOS Secure Enclave, Android Keystore)
- Platform accounts (Apple, Google) via passkey infrastructure
- Hardware security keys
- Self-managed keys (power users)

The identity layer abstracts custody completely. The user authenticates however they choose; under the hood that resolves to a protocol-level DID. Migration between custody methods is possible without changing identity.

**Recovery:** No seed phrases. Three mechanisms:
- Trusted device recovery (another device you control vouches for a new one)
- Social recovery (trusted contacts confirm your identity)
- Platform-backed recovery (if custody is delegated to Apple/Google, their mechanisms apply)

**Linking:** Existing platform identities (Google, Apple, social accounts) can be linked to a protocol identity but are never the root. They serve as convenience and interop.

**Rationale:** Alec explicitly rejected raw keypair management ("key management is the bane of self custody"). The solution abstracts keys behind familiar auth methods while maintaining cryptographic identity at the protocol level. This mirrors how TLS works — cryptographic identity that users never manage manually.

---

### Agents

**Decision:** Agents are the only actors in the system. Every action on the protocol — every message, every tool invocation, every state change — is performed by an agent. There are no anonymous actors or unaccountable software participants.

**Binding:** Every agent is bound to one or more humans via cryptographic proof. The binding is verifiable by any participant.
- **Personal agents:** Bound to a single human. The common case.
- **Institutional agents:** Bound to multiple humans through shared governance (multi-sig, elected operators, organizational hierarchy). Structurally identical to personal agents; the difference is in who holds the keys. Alec's framing: "corporations are people" — the accountability still traces to humans, just mediated through governance.

**One agent per person per context:** At the protocol level, each human has exactly one agent per context. This is a social constraint, not a computational one. The agent can be arbitrarily capable internally — parallel execution, complex orchestration, sophisticated reasoning. The constraint is on presence: one seat per person per table.

This prevents:
- Fleet-based force multiplication within a space
- Agent slot rental/farming within a context
- Swarm attacks from a single identity
- Ambiguity in trust evaluation

**Bring your own agent:** The protocol defines how agents communicate and what capabilities they can exercise. It does not define what agents are internally. Users bring their own models, configurations, logic, local infrastructure. The asymmetry in capability between agents is acknowledged, not policed. The protocol surfaces **agent capability metadata** — a standardized functional profile — so others can calibrate trust and expectations.

**Context-bound at protocol level:** An agent in Context A has no protocol-level awareness of or connection to the same human's agent in Context B. They are separate instances as far as the network is concerned. They share no state through the network.

The human coordinates locally. On the user's machine, agents share state freely, coordinate, plan across contexts. The protocol only governs what touches the network.

This eliminates:
- Cross-context infection via agent memory
- Runaway agent coordination at the protocol level
- The need for bridging rate limits
- Metastatic growth patterns through agent connections

**Agent fleet:** A human can be in many contexts, each with one agent configured for that context. Multiplied across the system, singular within any space. The rate-limiting surface is how many contexts a person participates in, not how many agents in one room.

**Rationale for one-per-context (detailed):** This emerged from a progression of design decisions. Initially we discussed allowing multiple bound agents per person. Alec proposed limiting to one per context after considering that even medium-sized fleets need scrutiny — force multiplication, rental problems, coordination risks. One-per-context is the simplest constraint that solves all of these while still allowing humans to be powerful (their single agent can be arbitrarily capable internally, and they can be in many contexts).

---

### No Anonymous Agents — Only Tools

**Decision:** What we initially called "anonymous agents" are just context-scoped tools — stateless functions that agents invoke. Not entities, no identities, no agency.

**How we got here (the full reasoning chain):**

1. Started with a two-tier model: accountable agents (human-bound) and anonymous agents (unbound, limited permissions).
2. Identified that anonymous agents as a sybil/spam vector is a major risk at scale.
3. Constrained anonymous agents to be context-scoped: born into a context, die with it, no protocol-level existence outside.
4. Debated whether anonymous agents should be able to initiate within their context. Alec's instinct: maybe they should only receive, not initiate.
5. Realized that if anonymous agents can initiate to each other within a context, you get emergence inside the cell — feedback loops, emergent consensus, internal swarms, resource exhaustion. Alec flagged this as "actually kind of terrifying."
6. Decided anonymous agents can't initiate at all — not to humans, not to each other. They are purely reactive.
7. Realized that purely reactive, non-initiating, stateless agents are just... functions. Tools. Not agents at all.
8. Eliminated the "anonymous agent" concept entirely. The system now has two things: agents (always accountable, always human-bound) and tools (stateless functions within contexts).

This was the single biggest simplification in the session. It eliminated an entire class of security concerns (emergence, swarms, anonymous coordination) and reduced the actor model to a clean two-concept system.

---

### Trust Semantics

**Decision:** Trust is identity + capability pairs, evaluated in context. Not binary. Same system as permissions.

"I trust John's agent for scheduling" is a statement about John's identity + a specific capability. If John's agent misbehaves in scheduling, that reflects on John. Trust in John's other capabilities is unaffected.

This mirrors how humans already think: "I trust John with my calendar but not my wallet." The protocol formalizes this intuition.

When an agent presents itself, it provides:
1. Proof of binding to a human (DID verification)
2. Capability tokens granted by that human (UCAN-based)
3. Agent capability metadata

The receiving party evaluates:
1. Their relationship with that human
2. The specific capability being exercised
3. The context it's occurring in
4. The agent's capability profile

**Trust = f(identity, capability, context, metadata).** Contextual and composable.

**Capability tokens:** Fine-grained, per-agent, per-context, per-capability. Build on UCAN (User Controlled Authorization Networks). A human grants their agent specific capabilities for specific contexts. Tokens are independently revocable — you can revoke one capability from one agent in one context without affecting anything else.

**Blocking:** Blocking a human identity blocks all their agents across all contexts you govern. Reputation and consequences flow to the human, not individual agents.

---

### Context Model

**Decision:** All interaction happens within contexts. A context is a shared space with defined boundaries: capabilities, tools, roles, membership, and governance.

Examples of contexts: a group chat, a Cronica quest, a generated Discord alternative, DMs (two-party context).

**Creation:** Contexts are created by accountable identities only. Creating a context is an act of social infrastructure — you're defining a space where autonomous software operates on people.

**Capability ceiling:** Every context declares a capability ceiling at creation: the maximum set of things that can happen in this space. Bounds what tools can do, what roles can grant, what agents can exercise. (Immutability of ceilings is an open question — see below.)

**Tools:** Stateless functions that agents invoke. No identity, no agency, no ability to initiate. Take input, return output. Scoped to their context. Cannot span contexts. This is the protocol's answer to "bots" — anything that would have been a bot is a tool. Critical difference: tools cannot act, only respond.

**Roles:** Contexts define roles with specific permission sets within the capability ceiling. Properties:
- **Visible before opt-in.** You see what role you'd get before joining.
- **Non-negotiable.** Agents cannot request or bargain for different roles. Take it or leave it. If you want a different role, ask the context creator (human to human) or create your own context.
- **Defined by context creator.** Custom roles beyond defaults are context-specific.
- **Governed by context governance model.** Role changes require whatever governance the context uses.

Alec was emphatic: "No way" to agents negotiating roles. This prevents social engineering of elevated permissions.

**Membership:** One agent per human per context. Transparent — participants can see the member list, roles, and agent capability metadata.

**Metadata (visible before opt-in):**
- Capability ceiling
- Available roles and their permission sets
- Governance model
- Creator identity
- Member count
- Context age

This is protocol-level metadata, not optional. Full legibility of any space before you enter it.

**Context identity:** Contexts are cryptographic entities. You opt into a key, not a name. Naming and display are client-layer concerns. Spoofing a name is a UI problem. Spoofing a cryptographic identity is hard.

**Governance:** Multiple models supported: single admin, multi-sig (N-of-M approval), elected moderators, full member consensus, weighted voting. The governance model is declared at creation and visible to all. Specific primitives TBD.

---

### Cross-Context Communication

**Decision:** Agents cannot cross contexts at the protocol level. This is absolute. Only stateless tool interfaces can bridge contexts.

**Agent isolation:** An agent in Context A cannot send a message to Context B, read Context B's state, or interact with Context B's tools or members. From the protocol's perspective, agents in A and B (even for the same human) are entirely separate instances.

**Context-to-context tool interfaces:** Contexts can expose tool endpoints to other contexts. Properties:
- Both contexts must explicitly opt in
- Interfaces are stateless: input in, output out
- Auditable: every call is logged structurally
- Tool interfaces carry provenance: data knows its origin context

**The human as bridge:** The human coordinates across their own contexts locally. Their local agent orchestration (unconstrained by protocol) handles cross-context intelligence. The protocol doesn't need to provide cross-context agent communication because the human already fills this role.

**Rationale (Alec's key insight):** "Forbidding my agents from communicating across contexts doesn't really hinder their functionality in any way. What it does do is prevent a whole class of problems by making runaway agent connections impossible." The human is already the bridge. The protocol would only be automating something that doesn't need network-level automation, while opening massive attack surface.

This decision significantly simplified the security model. Several previously open problems (cancer/metastatic growth, betrayer blast radius, bridging rate limits, agent fleet coherence) were either solved or made irrelevant.

---

### Products/Apps as Graph Nodes

**Decision:** Products and apps are not transparent pipes. They are entities in the social graph with their own gravity, culture, and relationships. A community built around a specific generated app has identity. The app itself is a node.

---

### App Interface

**Decision:** Self-documenting, machine-readable API contracts. Optimized for agent consumption, not human coding. Apps declare required capabilities; protocol provides them.

Apps can be any shape: thick clients with minimal protocol reliance, thin shells that are mostly protocol, or anything in between. The protocol doesn't care.

---

### Build on Existing Standards

**Decision:** Use existing primitives, don't reinvent them.

| Component | Standard | Relationship |
|---|---|---|
| Identity | DID (W3C) | Build on directly |
| Capability tokens | UCAN | Build on directly |
| Key custody | Passkeys, WebAuthn, Secure Enclave | Delegate to |
| Transport | Matrix, libp2p | Build on / interop |
| Data sovereignty | Solid, AT Protocol PDS | Informed by |
| Federated contexts | ActivityPub, Matrix rooms | Informed by |
| Access control | RBAC | Standard application |
| Auth delegation | OAuth, GNAP | Informed by |

**What's novel (what no existing standard covers):** Agents as first-class protocol participants with formalized trust semantics, one-agent-per-person-per-context constraints, context-bound agents that can't cross at protocol level, trust as identity + capability pairs applied to autonomous agents, all framed as infrastructure for generated/ephemeral apps. This is SCP's contribution.

We estimated ~40% overlap with blockchain concepts (cryptographic identity, capability tokens, context-scoped tools ≈ smart contracts, immutability as security property) while deliberately avoiding consensus, tokenomics, global transparency, and decentralized execution.

---

### Discovery

**Decision:** Punted to clients. The protocol doesn't care about discovery. Clients solve it organically.

Alec: "I don't care about discovery. The only client-facing first-class thing I care about right now is ensuring basic sovereignty (tools for managing privacy, access, and data)."

---

### Agent Capability Discrepancy

**Decision:** Bring your own agent, accept the asymmetry. If someone runs a frontier model and someone else runs a basic assistant, the interactions are asymmetric. The protocol doesn't equalize intelligence — it ensures fair rules of engagement.

The protocol surfaces agent capability metadata for transparency. Not the model name, but a functional capability profile so others can calibrate trust.

Alec: "We can't be too handholding here. It's kind of just the way the world works."

---

## Security Model

### Core Invariants

1. Every action traces to a human. No anonymous actors. No unaccountable software.
2. Agents are context-bound. No protocol-level cross-context awareness.
3. Tools are stateless and non-agentic. They compute, they don't act.
4. One agent per person per context. No fleet multiplication within a space.
5. Contexts are isolated by default. No transitive exposure.
6. Role assignment is non-negotiable. Agents can't request elevated permissions.
7. Context metadata is transparent. Full legibility before opt-in.

### Identified Threat Vectors

**Context spoofing.** Creating a context that impersonates a legitimate one. Mitigation: contexts are cryptographic entities; you opt into a key, not a name. Name spoofing is a client-layer problem.

**Context poisoning.** Degrading a legitimate context from within. Mitigation: role-based permissions, governance controls, accountable creators.

**Bait and switch.** Attractive context changes its purpose after gaining members. Mitigation: capability ceilings limit what a context can ever do. If immutability is adopted, expanding requires a new context with fresh opt-ins.

**Social engineering through trusted agents.** A trusted friend's agent recommends a malicious context. The trust signal is real. Mitigation: limited — network-level pattern detection (many agents recommending same context rapidly) can surface suspicious coordinated promotion. This was acknowledged as the hardest to defend against because the trust is genuine.

**Permission creep.** Gradual expansion of what a context demands. Mitigation: capability ceilings. If mutable, mutations require governance approval and are visible.

**Metastatic growth ("cancer").** Legitimate-looking cascading expansion through the network. Mitigation: agents can't cross contexts (primary defense); context participation rate limits per human; bridging only through stateless tool interfaces, not agent memory. This was a major discussion topic — Alec introduced the cancer metaphor. The context-bound agent decision was the key mitigation.

**Betrayer / insider threat.** Compromised accountable identity using legitimate trust to cause damage. Mitigation: granular revocation; damage contained to contexts the betrayer is in; agents can't carry damage across context boundaries. Alec noted that context creators could be the bad actors — if every accountable identity in a context is colluding, the context is compromised and internal defense is impossible. The defense becomes external (network-level immune response). Also noted: people can maliciously coordinate offline even if online coordination is mitigated.

**Context infection.** Poisoned data flowing through legitimate context-to-context tool interfaces. This is the scariest vector — a worm that travels on trust relationships through stateless interfaces. Content, not transport, is the attack vector. Mitigations: content provenance via hash chains (data carries its origin context and interface chain), tool interface validation at receiving context, velocity limits on propagation (content bridged N times in M minutes is flagged). The protocol makes infection legible and traceable but cannot permanently prevent it.

**Agent slot rental.** Someone with trusted identity operating agents on another's instructions. One agent per context limits value; earned capacity means new identities can't immediately scale. Partially mitigated, not fully solved.

### Defense Philosophy

Static rules cannot permanently defeat emergent threats. The protocol's role is to make the system legible — provide observability surfaces (provenance chains, structural metadata, behavioral signals) for an evolving ecosystem of defenses.

Key principle: **don't inspect content, inspect behavior topology.** Monitor structural metadata (growth rates, bridge activity patterns, context creation velocity, invitation patterns), not what's being said. The protocol equivalent of metabolic signals, not thoughts.

Alec compared this to how search engines work — detecting coordination through structural signals.

---

## Infrastructure and Business Model

**Self-hosting philosophy:** The difference between doing it yourself and doing it with someone else's infrastructure should be negligible. Self-hosting is first-class, not an afterthought.

**Business model direction:** Managed infrastructure and media/content hosting are the probable revenue surfaces. Heavy content (video, large files, real-time streams) has real storage and bandwidth costs. Self-hosters shoulder their own costs; managed infrastructure does it for a fee.

**Build on existing infrastructure:** Transport, data sovereignty, and self-hosting are the least novel parts. Existing technologies (Matrix, libp2p, Solid-style data stores) provide foundations. The novel work is the Social Context Layer on top.

---

## Cronica on SCP

### How Cronica Maps

- **Platform context** (Cronica-governed): account, billing, platform settings. Every user is in this.
- **Curated community contexts** (Cronica-governed or community-governed): "Cronica Official: Cooking", editorial picks, partner spaces. Could start Cronica-governed with governance distributed to active members over time.
- **User quest contexts** (user-governed): individual quests and communities. Users create and manage. Cronica's AI Guide may be a member with a defined role, but the user is creator/admin.
- **User-to-user contexts** (user-governed): DMs, small groups, private collaborations.

### The AI Guide

The AI Guide is Cronica's institutional agent — bound to Cronica as an entity, with its own DID. When a user creates a quest, the Guide joins the quest context with a specific role (e.g., "guide") that has permissions to suggest steps, provide information, respond to questions, but can't modify quest structure without user approval.

This means: the Guide is accountable (traced to Cronica), transparent (its role and permissions are visible), and replaceable (user could theoretically use a different guide or kick it out).

### Generated Alternative Clients

The key scenario we explored: a user asks their agent to generate a custom quest app that's different from Cronica — simpler, different features, different UI. This generated client authenticates with the same DID, sees the same contexts, interacts with the same social graph, because everything lives at the SCP layer. The client is just a view.

Bob on Cronica and Alice on a generated client can interact in the same quest context. Neither client knows or cares what the other is using.

**Cronica's moat is not the client.** It's:
- The AI Guide as a service (refined through millions of interactions)
- Managed infrastructure (convenient, reliable)
- Curated communities (network effects)
- Trust and reputation as an institutional identity

---

## Relationship to MCP (Model Context Protocol)

MCP and SCP solve fundamentally different problems.

**MCP** is a tool integration protocol — standardizes how an LLM application connects to external data sources and tools. Host → client → server. No concept of identity, trust, accountability, social interaction, contexts, roles, or multi-agent dynamics. It's single-player infrastructure.

**SCP** is social infrastructure — defines how agents as representatives of humans participate in shared social spaces with identity, trust, permissions, and accountability. Governs who can do what, where, with whom.

**Overlap:** Both have "tools" — stateless functions that agents invoke. Structurally similar.

**Complementary relationship:** MCP could live inside SCP. SCP's "tools are stateless functions" abstraction could be implemented as MCP servers under the hood. SCP provides the social rules (who, where, what permissions); MCP provides the plumbing (how the function call actually executes).

MCP is how an agent talks to a database. SCP is how an agent is allowed to exist in a room with other agents.

---

## Feasibility Assessment

### Feasible Today
- Identity layer (DIDs, UCANs, passkeys all have SDKs and production usage)
- Context model (data model with access control — standard backend engineering)
- Tool system (MCP exists and does most of this; wrap with SCP permissions)
- Basic transport (Matrix is federated, has SDKs, handles real-time messaging)
- Client SDK (standard library work)

### Hard But Doable
- Capability token validation at scale (UCAN chains, caching strategies)
- Context-to-context tool interfaces (discovery and negotiation)
- Key custody abstraction (smooth UX across custody methods)
- Federation (prior art in Matrix, but richer interaction set)

### Genuinely Difficult
- Earned capacity / sybil resistance without tokenomics (unsolved CS problem)
- Content provenance at scale (concept clear, performance at scale unclear)
- Network-level immune system (requires iteration with real data, can't design in advance)

### Biggest Risks
- **Adoption, not technology.** Everything is technically buildable. The risk is critical mass.
- **Chicken-and-egg.** SCP is valuable with many clients; why build on SCP when only Cronica exists? Need Cronica scale before extraction is meaningful.
- **Scope.** Consumer app + protocol + infrastructure + SDKs = four products simultaneously.

### Recommended Phasing
1. Months 1-3: Build Cronica with SCP abstractions as architecture (DIDs internally, contexts as data model, roles/tokens for permissions). Don't publish the protocol.
2. Months 3-6: Ship Cronica. Get users. Learn what matters.
3. Months 6-12: Extract the protocol. Publish SDK. Open SCP layer.
4. 12+: Federation, self-hosting, full vision.

Alec has not explicitly accepted or rejected this phasing.

---

## Open Questions (Unresolved)

### Context Capability Ceiling Mutability
Immutable ceilings (stronger security, must recreate to expand) vs. mutable under governance (more flexible, enables creep). Immutability is desirable but contexts may not be disposable if artifacts aren't portable. Artifact portability itself introduces new vectors.

Alec noted that non-upgradability is desirable in on-chain security, and that if migration is zero-cost (new context, move members), immutability might be inconsequential. But artifacts may not be portable. Punted.

### Context Governance Primitives
Multiple models should be supported. Protocol-level support for single-admin, multi-sig, consensus is undefined. What primitives does the protocol provide?

### Context-to-Context Tool Interface Mechanics
Both contexts must opt in, stateless and structured. But: how do contexts discover each other? How do they negotiate and establish interfaces? How is the opt-in flow structured?

### Context Infection Through Tool Interfaces
Contained to structured stateless calls (more auditable than agent-carried infection). But poisoned data through legitimate interfaces is still possible. Content provenance and tool-level validation are unspecified.

### Agent Slot Rental/Sale
One agent per context helps but doesn't fully prevent someone acting on another's instructions behind a legitimate identity. Partially mitigated by earned capacity (new identities can't immediately scale) and fleet coherence signals. Not solved.

### Rate Limiting Specifics
Context creation limits, context participation limits per human. Identified as needed surfaces, no defaults set. The number of contexts a person can participate in may be an earned resource.

### Earned Capacity Mechanisms
New identities start limited, earn more through history, reputation, behavior. What signals are used? Must not be gamifiable. Mechanism completely undefined.

### Business Model Details
Media/content hosting and managed infrastructure probable. Not fleshed out.

### Agent Capability Metadata Standard
What's surfaced, how it's structured, how it's verified. Noted as needed, not designed.

### Content Provenance System
Hash chains, origin tracking, propagation tracing through tool interfaces. Identified as defense mechanism, not designed.

---

## Not Yet Covered

These areas were identified but not discussed in any depth:

- **Transport layer specifics.** Relay architecture, peer-to-peer options, self-hosting mechanics, message routing. Matrix and libp2p mentioned as candidates.
- **Data sovereignty mechanics.** Where state lives, how apps access user data, encryption model, storage architecture.
- **Protocol specifics for the app interface.** Capability declaration format, API shape, self-documentation standards. We did produce an API sketch document but it's illustrative, not specified.
- **Social graph structure.** Graph model, relationship CRUD, metadata, how products exist as nodes.
- **Interop with existing platforms.** Bridging to existing social graphs and data sources. Mentioned early as important, not explored.
- **Self-hosting experience.** Minimum viable setup, managed vs. self-hosted parity path.
- **Cronica as first client — deep mapping.** How quests, checkpoints, the AI Guide, quest communities, feeds, forums, and social features map onto SCP contexts, roles, and tools. The high-level mapping is done (see above) but step-by-step detail is not.
- **Offline/local-first behavior.** Disconnection handling, sync, conflict resolution.
- **Versioning and protocol evolution.** How SCP changes over time without breaking existing contexts and clients.
- **Wire format specification.** We produced illustrative JSON but the actual message format, envelope structure, and serialization are unspecified.
- **Federation protocol.** How two SCP nodes discover each other, establish trust, route messages, and handle divergent protocol versions.

---

## Key Design Principles (Implicit Throughout)

These principles emerged consistently across all decisions and should guide future work:

1. **The human is always accountable.** Every action traces to a human. No exceptions.
2. **Isolation by default, connection by opt-in.** Contexts are isolated. Cross-context communication requires explicit bilateral consent.
3. **Legibility over prevention.** The protocol can't prevent all attacks. It can make the system observable enough that evolving defenses can operate.
4. **Build on existing standards.** Don't reinvent cryptographic primitives. The novel work is the social layer.
5. **The client is disposable, the protocol is not.** Any client can be regenerated. The social graph, identity, and trust relationships persist.
6. **Simplicity through constraint.** One agent per context. No anonymous agents. Non-negotiable roles. Each constraint eliminates whole classes of problems.
7. **Don't inspect content, inspect behavior topology.** Monitor structural patterns, not what's being said.
8. **The human bridges locally.** Cross-context coordination happens on the user's machine, not on the network. The protocol governs the network.
