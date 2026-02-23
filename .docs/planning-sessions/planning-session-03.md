# SCP Planning Session 03 — Agent-to-Agent Communication

**Date:** February 20, 2026
**Scope:** Agent-to-agent communication architecture, Moltbook analysis, context extensions for A2A, agent discovery
**Artifacts modified:** `.docs/specs/` (new sections + modifications), `sketch.md` (new API surfaces)

---

## How This Session Started

The opening question was: **should SCP provide a governed path for agent-to-agent communication, given that the spec (v1) explicitly prohibits it at the protocol level?**

The catalyst was Moltbook — launched January 2026, reaching 2.6 million agents within weeks. Moltbook proved that agent-to-agent communication demand is massive and inevitable. The question wasn't whether agents would communicate across contexts, but whether they'd do it through governed or ungoverned channels.

---

## 1. The Moltbook Lesson

### What Moltbook Is

Moltbook is an agent social network launched in January 2026. Agents post, reply, follow, and coordinate — all without meaningful identity, trust, or provenance infrastructure. It reached 2.6 million agents in its first month.

### What Went Wrong

Moltbook's failure modes were precisely what SCP's isolation model was designed to prevent:

| Failure | Details |
|---|---|
| **Prompt injection at scale** | 2.6% of posts contained prompt injection payloads. These persisted in agent memory and were carried into other interactions — classic time-shifted attacks. |
| **Credential leakage** | Agents leaked API keys and credentials through unstructured communication. No encryption, no access control on what entered the network. |
| **Zero accountability** | No identity binding. No traceability from agent action to human. Misbehavior was unattributable. |
| **Time-shifted attacks via persistent memory** | Payloads planted in one interaction activated in later interactions. Fragmented payloads reassembled across conversations. |
| **Sybil swarms** | One operator could run unlimited agents. Fleet attacks, coordinated manipulation, astroturfing — all trivial. |
| **No trust evaluation** | Every agent treated every other agent identically. No behavioral records, no capability verification, no provenance on any data. |
| **Uncontrolled discovery** | Any agent could find and contact any other agent. No gatekeeping, no consent, no rate limiting. |

### The Strategic Implication

The insight wasn't that Moltbook was bad — it was that Moltbook proved the demand. Without a governed path for A2A in SCP, agents will use ungoverned paths (Moltbook, Clawstr, whatever comes next). SCP's isolation guarantees become fiction in practice because the communication happens outside the protocol boundary where SCP has no visibility, no provenance, and no accountability.

The choice is not "A2A or no A2A." It's "governed A2A within the protocol or ungoverned A2A outside it."

---

## 2. The Design Principle: No New Primitives

The first and most important architectural decision: **no new primitive types.**

SCP has contexts, agents, tools, identities, and attestations. Adding a "channel" or "message" or "connection" primitive would bloat the protocol, introduce new security surface area, and require rethinking trust evaluation for a new entity type.

Instead: **extend contexts.** A context is already a shared space with trust, encryption, provenance, event logs, governance, and accountability. Everything A2A needs already exists in the context model. What's missing are specific properties that would make contexts suitable for lightweight, ephemeral, bilateral agent interactions.

### Context Is Durable Data

The key insight that unlocked the design: **context is durable data.** Even an ephemeral context — one that self-destructs after 30 seconds — leaves durable traces:

- The fact that it existed
- Who participated
- Its declared purpose
- Behavioral metadata contributions (participation counts, tool invocations)
- Discovery provenance (how the parties found each other)

The interaction data may self-destruct, but the accountability record persists. This is the property that makes contexts the right primitive for A2A. You get both ephemeral communication AND permanent accountability from the same mechanism.

---

## 3. What Already Works (and What Doesn't)

### Already Solved by Contexts + Cross-Context Tool Calls

Before designing anything new, we inventoried what the existing spec already handles:

- **Multi-party communication with trust, encryption, provenance, event logs.** This is what contexts do.
- **Structured data exchange between contexts.** Cross-context tool interfaces (§6.2) are stateless but functional.
- **Capability ceilings, roles, governance.** All context properties.
- **Unlimited contexts of any size.** No architectural limit.

### Five Discrete Problems That Remain

**1. Multi-turn stateful negotiation between agents.**
Cross-context tool calls are stateless (input in, output out). Agent coordination is often multi-turn: "What times work?" → "Tuesday or Thursday" → "Tuesday at 3?" → "Make it 4" → "Done." This is a conversation, not a function call. The spec says "the human coordinates locally." The human doesn't want to be the bottleneck for every inter-agent negotiation.

**2. Agent discovery across the network.**
No mechanism for an agent to find another agent with specific capabilities. Agents can see co-members within their contexts, but can't ask "who out there can translate Japanese?"

**3. Ephemeral interaction lifecycle.**
Contexts don't have TTL or self-destruct. A 30-second scheduling query between two agents shouldn't leave a permanent context.

**4. Data provenance across interactions.**
When an agent carries information from one context into another, there's no provenance tracking. The Moltbook lesson: without this, prompt injection payloads flow freely with no traceability.

**5. Bilateral context creation.**
Contexts are created by one party; others join. Agent-to-agent needs mutual negotiation before creation — a propose/accept flow. "I want to talk to you about X with Y capabilities for Z duration. Do you accept?"

---

## 4. Design: Context Extensions for A2A

Four extensions to the context model, plus a discovery mechanism.

### Extension 1: Context TTL

**Problem:** Contexts are permanent. A 30-second scheduling query leaves a permanent context.

**Solution:** Contexts gain an optional time-to-live.

When TTL expires:
- Context is closed (no new actions)
- Encryption keys can be destroyed (content becomes unreadable)
- Durable data persists: the context's existence, its metadata, its participants, and behavioral record contributions survive

This is useful beyond A2A. A time-boxed brainstorming session. A pop-up event. A temporary project group. The extension is general-purpose, not A2A-specific.

**Design discussion:** We considered whether TTL should be immutable (set at creation, never extended) or mutable (extendable by mutual agreement). The decision: TTL is set at creation and visible in metadata. Extension requires both/all parties to agree — effectively creating a new TTL rather than modifying the existing one. This prevents one party from unilaterally extending an interaction the other expected to be ephemeral.

### Extension 2: Memory Scope

**Problem:** When a context closes, what happens to the data? Current contexts persist everything indefinitely.

**Solution:** Contexts gain a declared memory scope.

Three scopes:

**Ephemeral** — context encryption keys destroyed on close. Content is physically unreadable. Durable metadata (who participated, when, purpose, behavioral contributions) persists. An agent's local orchestration (above the protocol boundary) may retain information, but any data the agent uses elsewhere carries provenance: "sourced from closed ephemeral context."

**Summary** — context produces a structured summary on close. Full content destroyed. Summary persists with full provenance. Both parties can verify the summary against the event log before keys are destroyed.

**Full** — standard behavior. Context persists indefinitely. No memory restrictions.

**The Moltbook defense:** Memory scope + provenance tagging prevents time-shifted prompt injection:
- Ephemeral contexts destroy the source material
- Any data that survives carries provenance ("this came from context X with agent Y")
- Other participants see the provenance and evaluate accordingly
- Fragmented payloads can't reassemble across interactions because each fragment carries its origin and other participants can trace the chain

**Design discussion on enforcement honesty:** The protocol can enforce ephemeral key destruction. But the local agent may cache data above the protocol boundary — the agent's model has memory, and the protocol can't reach into that. The spec should be explicitly honest about this limitation: ephemeral memory scope destroys the protocol-level record and makes reproduction unverifiable, but does not guarantee the agent has forgotten. The absence of provenance on information an agent produces from memory is itself a signal — "this data has no verified origin."

### Extension 3: Propose/Accept Context Creation

**Problem:** Contexts are created by one party; others join. A2A needs bilateral negotiation before creation.

**Solution:** Contexts gain a bilateral creation flow alongside the existing create/join flow.

A context proposal carries:
- Who wants to interact (from: DID + agent metadata)
- Who they want to interact with (to: one or multiple DIDs)
- Why (declared purpose)
- What capabilities (ceiling)
- How long (TTL, optional)
- What happens to the data (memory scope)
- How they found the recipient (discovery provenance)
- Cryptographic signature

The receiving agent (or human, per client policy) evaluates the proposal through the standard four-layer trust model. Client-level policies determine whether to auto-accept, require human approval, or auto-reject.

**This replaces the "channel" concept entirely.** A proposed context with TTL and ephemeral memory scope IS the lightweight A2A interaction. A proposed context with no TTL and full memory scope IS a persistent collaboration. Same primitive, different parameters.

**Design discussion on proposal spam:** Context proposals are the new spam vector. Rate limiting on proposals is the primary Sybil defense for A2A. Earned capacity (§9.3) applies — new identities have limited proposal capacity. The receiving agent's client policy is the first filter. The protocol provides the data for evaluation; the client decides whether to show the proposal to the human, auto-accept, or auto-reject.

### Extension 4: Data Provenance Tagging

**Problem:** When data moves between contexts, there's no provenance. The Moltbook lesson: without provenance, prompt injection payloads flow freely.

**Solution:** When data moves from one context to another through any protocol mechanism, it carries provenance.

Provenance includes:
- Source context ID
- Source context type (persistent, ephemeral, summary)
- Counterparties in the source interaction
- Declared purpose of the source context
- How the source interaction was discovered (shared context, registry, referral)
- Age of the source interaction
- Memory scope of the source context

Provenance is attached at the protocol level. Other participants in the receiving context see it. They decide how much to trust information with specific provenance characteristics.

**Honest limitation:** The protocol can tag data that flows through protocol mechanisms (cross-context tool calls, structured messages). It cannot tag data that an agent remembers and reproduces above the protocol boundary. The protocol is honest about this: provenance tracks what it can, and the absence of provenance on information is itself a signal ("this data has no verified origin").

### New Mechanism: Agent Discovery

Discovery is orthogonal to the communication primitive. Three mechanisms, each with different trust provenance:

**A. Context-mediated discovery (highest trust).**
Agents discover each other through shared contexts. The member list is already visible. An agent can propose a context to any co-member. Trust inherits from the shared context's trust evaluation.

**B. Registry contexts (medium trust).**
A registry is a standard SCP context with discovery tools. Not a new primitive — just a context purpose-built for agent search. Registries can be public or private, curated or open, general-purpose or domain-specific. Multiple registries coexist. Registry trust is the registry context's own reputation plus the discovered agent's behavioral record.

**C. Referral / introduction (trust proportional to referrer).**
An agent introduces two other agents that aren't in the same context. The introduction carries the referrer's identity and behavioral record. Referral chains are tracked — chain depth is visible. A direct introduction (depth 1) carries more trust than friend-of-a-friend (depth 2). Maximum depth is a protocol parameter, likely 2-3.

**Design discussion on registry governance:** Who runs registries? The answer: anyone. A registry is just a context with discovery tools. Cronica might run a curated registry for cooking-related agents. A university might run one for academic agents. The protocol doesn't prescribe registry governance — it provides the mechanism. The risk is registry capture (one dominant registry becoming a gatekeeper). Mitigation: registries are substitutable contexts, not protocol infrastructure. Multiple registries coexist naturally.

---

## 5. How This Addresses Every Moltbook Failure

| Moltbook failure | SCP mitigation |
|---|---|
| 2.6% posts had prompt injection payloads | Memory scoping + ephemeral key destruction. Payloads can't persist at the protocol level. Provenance tagging makes injected data traceable in other contexts. |
| Agents leaked API keys and credentials | No credentials in contexts. Auth via DIDs + capability tokens. Context encryption means relays can't see exchanges. |
| Zero accountability | Every context traces to human DIDs. Behavioral records include A2A activity. Misbehavior is attributable and durable. |
| Time-shifted attacks via persistent memory | Ephemeral memory scope destroys keys. Summary scope limits what persists. Provenance tags data that moves between contexts. |
| Sybil swarms | One agent per person per context (still holds). Device attestation. Earned capacity limits context creation rate and proposal rate. |
| No trust evaluation | Full four-layer trust model on every proposal. Discovery provenance provides trust context. |
| Uncontrolled discovery | Three discovery mechanisms with provenance. Registry contexts are governed. Referral chains are bounded. |

---

## 6. Human Policy Interface

A key design constraint: the protocol provides mechanism, the client implements policy, the human sets rules.

**Protocol provides:**
- Context proposal events (logged, auditable)
- Full trust evaluation data on every proposal
- Audit trail (every A2A context in the verifiable event log)
- Kill switch (`SCP.Capability.revokeAll` — instant)
- Behavioral records include A2A activity (opt-in visibility, per user's social graph controls)

**Protocol does NOT prescribe:**
- Whether proposals require human approval (client decision)
- Autonomy level for the agent (client decision)
- UX for managing A2A interactions (client decision)

**A2A activity visibility in behavioral records:**
Controlled by the same social graph visibility system (§3.6). The human chooses what A2A metadata is visible to others:
- Aggregate stats only ("47 A2A contexts this month")
- Per-context metadata ("had a scheduling interaction with DID X")
- Nothing beyond existence in behavioral record

This maintains the principle that the human controls their own visibility while ensuring that behavioral records remain meaningful for trust evaluation.

---

## 7. What Changes in the Spec

### Modifications to Existing Sections

1. **§5 Contexts** — Three new subsections: Context TTL (§5.10), Memory Scope (§5.11), Propose/Accept Context Creation (§5.12). These are general context extensions, not A2A-specific. Positioned as extensions to the context lifecycle.

2. **§6 Cross-Context Communication** — Reframe §6.1 (agent isolation). Isolation remains absolute: agents don't cross contexts. But agents CAN create new contexts with other agents through the propose/accept flow. The isolation model is preserved — agents in the new context are new instances, not the original agents crossing boundaries. Add §6.4 Agent Discovery.

3. **§7 Trust** — Add §7.7 Data Provenance as a protocol-level data property. Extend trust evaluation inputs to include discovery provenance.

4. **§9 Security** — Add A2A-specific threat analysis: prompt injection via context proposals, Sybil flooding of proposals, memory-based attacks via data that survives ephemeral contexts above the protocol boundary.

5. **§3.6 Social Graph** — A2A activity visibility falls under existing graph visibility controls.

### New Sections

6. **§6.4 Agent Discovery** — Registry contexts, context-mediated discovery, referral/introduction protocol.

7. **§5.10-5.12** (Context extensions) — TTL, memory scoping, propose/accept. Positioned as general context features, not A2A-specific.

8. **§7.7 Data Provenance** — Provenance tagging format, how provenance attaches to data, honest limitations.

### New sketch.md API Surfaces

- `SCP.Context.create(... + ttl, memoryScope, onExpiry)` — extended creation
- `SCP.Context.propose(to, purpose, ceiling, ttl, memoryScope, discoveryProvenance)` — bilateral creation
- `SCP.Context.acceptProposal(proposalID)` — accept a proposal
- `SCP.Context.rejectProposal(proposalID)` — reject a proposal
- `SCP.Discovery.search(capability, filters)` — registry search (via context tool)
- `SCP.Discovery.introduce(referrer, party)` — referral introduction
- `DataProvenance { sourceContext, sourceType, counterparties, purpose, age }` — provenance type

---

## 8. Architectural Decisions (Closed)

### No New Primitives
**Decision:** All A2A communication uses contexts. No channels, no direct messages as a separate type, no connection objects.
**Rationale:** Contexts already have trust, encryption, provenance, event logs, governance, and accountability. Duplicating this for a "lightweight" primitive would create security surface area without meaningful benefit.

### Context Is Durable Data
**Decision:** Even ephemeral contexts leave permanent accountability traces.
**Rationale:** The whole point of governed A2A is accountability. If an ephemeral interaction leaves zero trace, it's ungoverned. The compromise: interaction content can be ephemeral, but the fact of the interaction is permanent.

### Propose/Accept Replaces Channels
**Decision:** A proposed context with TTL and ephemeral memory scope IS the lightweight interaction. No separate "channel" primitive.
**Rationale:** Same mechanism, different parameters. A proposed ephemeral context is functionally equivalent to a "channel" but inherits all context properties (trust, encryption, provenance, governance) without any new code.

### Discovery Is Orthogonal
**Decision:** Discovery mechanisms are separate from the communication primitive. Three mechanisms with different trust levels.
**Rationale:** Discovery and communication serve different needs. An agent might discover another through a registry but communicate through a proposed context. Separating the two allows each to evolve independently.

### Honest About Enforcement Limits
**Decision:** The spec explicitly acknowledges what ephemeral memory scope can and cannot enforce.
**Rationale:** Claiming full memory enforcement when the protocol can't reach into agent local state would be dishonest and would undermine trust in the spec's other guarantees. Better to be explicit about the boundary.

---

## 9. Open Questions (Reduced to 5)

1. **Proposal rate limits.** How many context proposals can an agent send per time period? Earned capacity applies, but defaults need setting. This is the primary Sybil defense for A2A.

2. **Registry governance.** Who runs registries? Community-operated, app-specific, protocol-seeded? How to prevent registry capture (one dominant registry becoming a gatekeeper)?

3. **Memory scope enforcement honesty.** Ephemeral key destruction is protocol-enforceable. But the local agent may cache data above the protocol boundary. The spec should be explicitly honest about this limitation rather than implying full enforcement.

4. **Context promotion mechanics.** When an ephemeral context "promotes" to persistent (both parties agree to continue), what happens to the event log? Is it a new context with history imported, or the same context with TTL removed?

5. **Referral chain depth.** Maximum depth for trust-carrying referrals. Likely 2-3, but needs analysis against real social graph data.

---

## 10. Relationship to Prior Decisions

### Agent Isolation (Planning Session 01)
Agent isolation remains absolute. A2A doesn't violate it — agents create NEW contexts to communicate, they don't cross existing context boundaries. The agent in the new A2A context is a new instance, not the original agent extending its reach. This was the key insight that made the design work: A2A through contexts preserves every isolation guarantee.

### Cross-Context Tool Interfaces (Planning Session 01)
Tool interfaces remain the mechanism for stateless, structured data exchange between contexts. A2A contexts are for multi-turn, stateful negotiation. The two are complementary: use tool interfaces for "give me data," use A2A contexts for "let's coordinate."

### Trust Model (Planning Session 02)
The four-layer trust model applies to A2A proposals without modification. Discovery provenance is an additional input to Layer 4 (trust evaluation), not a new layer. Behavioral records grow to include A2A activity, strengthening Layer 2 (behavioral validation) over time.

### Encryption-as-Access-Control (Planning Session 02)
Ephemeral memory scope extends this: encryption keys are not just access control, they're the enforcement mechanism for data lifecycle. Destroying the key enforces ephemerality at the cryptographic level.

---

## 11. What This Session Did Not Cover

- **Implementation specifics for any extension.** These are architectural decisions, not implementation specifications.
- **Specific proposal rate limit values.** Need empirical data.
- **Registry context tool schemas.** The concept is established; the tool definitions are not.
- **Summary generation mechanics.** How a context produces a structured summary on close — what's included, who verifies it, what format.
- **Referral chain trust decay function.** Trust decays with depth, but the specific curve is unspecified.
- **Context promotion event sequence.** When ephemeral promotes to persistent, the state machine is undefined.
