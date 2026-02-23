# SCP Planning Session 02 — Full Transcript Summary

**Date:** February 16, 2026
**Scope:** Spec review, gap analysis, platform bridging, transport architecture, Matrix/Nostr positioning
**Artifacts modified:** `spec-01.md` (substantial additions and revisions)

---

## How This Session Started

The opening question was: **how would SCP integrate data and context from existing services like X and Facebook, without needing their cooperation?**

This turned into a much larger conversation that touched platform bridging, the Matrix comparison, the Nostr realization, infrastructure honesty, and a full gap analysis of where the spec stands.

---

## 1. Platform Bridging — The Initial Design

### The Local Bridge Model

The first answer was that SCP's architecture already has a natural home for platform bridging: the **local agent orchestration layer** below the protocol boundary. Since that layer is unconstrained by protocol, a user's local agents can reach into existing platforms (X, Facebook, etc.) and bring data into SCP.

Concrete mechanisms that don't require platform cooperation:

- **User-authenticated scraping.** The user is already authenticated on these platforms. A browser extension or local agent component extracts data from their authenticated sessions. This is accessing your own data through your own session — legally distinct from unauthorized scraping.
- **Data portability exports.** GDPR, CCPA, and the EU Digital Markets Act give users the right to export their data. X, Facebook, and Instagram all offer structured exports (JSON/HTML). Good for initial bootstrap, but snapshots — not live feeds.
- **Public API surface.** Even restricted APIs have some surface. Bluesky/AT Protocol and Mastodon/ActivityPub are fully open and trivial to bridge.
- **Identity linking (§3.4 in the original spec).** The spec already said platform identities can be linked to a protocol identity. When your local agent imports your X social graph, it discovers that some contacts are also SCP participants because they've linked their X handle to their DID.

### Escalating to Protocol-Level Connectors

The user pushed back on bridging as purely a local concern: **"I do think we want a concept of platform bridge connectors, but at the protocol level, not just locally. Facebook doesn't have to conform to SCP, but they could interface with a connector to participate."**

This was the key insight that shaped the rest of the bridging design. The distinction:
- Local bridging = user scrapes their own data, brings it in privately
- Protocol-level connectors = a standardized interface that external platforms *could* implement to participate in SCP contexts

The user also flagged **identity attestation as a keystone feature** — "non-fungible identity attribution."

### What Got Added to the Spec

**§3.5 Identity Attestations.** Cryptographic proofs binding external platform handles to DIDs. Properties: non-fungible, user-initiated, independently verifiable, revocable, discoverable. Enables three flows: social graph import, shadow identity claiming, cross-platform reputation continuity.

**§12 Platform Bridge Connectors** (full new section, 9 subsections):

- Bridge connectors as protocol entities — operated by accountable identities, registered with contexts, transparent, revocable.
- **Shadow identities** — protocol-level representations of external platform users. Attributed but not verified (attribution comes from bridge operator, not from the user themselves). Restricted by default. Marked as bridged. Claimable — if the user later joins SCP and publishes a matching attestation, the shadow merges with their real DID. Past actions get retroactively attributed. The shadow is retired. This transition is one-way and irreversible.
- **Four operating modes:** relay (single bot on external platform, most robust), puppet (bridge authenticates as user on external platform, best fidelity, requires credential delegation), API (official platform API, most stable, most limited), cooperative (platform voluntarily implements the bridge connector interface — the aspirational mode).
- **Trust hierarchy for bridged content:** native SCP action (strongest) → native identity + bridged action → claimed shadow + historical bridged action → unclaimed shadow + bridged action (weakest). Agents calibrate behavior based on provenance.
- Bridge connectors don't violate context isolation. They're translation infrastructure, not agents.
- Self-hostable, consistent with §10.

### Matrix Bridge Analogs — Detailed Analysis

Matrix was discussed extensively as the closest existing analog for protocol-level bridging. The Matrix bridge architecture:

**Matrix Application Services (AS):** Protocol-level entities that register with a homeserver. They can create "ghost users" (virtual users representing external platform users), relay messages bidirectionally, and handle presence/typing/read receipts.

**Three bridge modes in Matrix:**

| Mode | How it works | Trade-offs |
|---|---|---|
| Relay | Single bot on remote platform. All messages flow through it. Attribution via `BridgeBot: <Dave> hey` | Simplest. Worst attribution. Single point of failure. |
| Puppeting | Bridge logs in as user on remote platform using user's credentials. Messages appear native on both sides. | Best UX. Requires credentials. Fragile — platforms actively break this. |
| Double-puppeting | Both sides puppeted. User appears fully native on both platforms simultaneously. | Best fidelity. Most complex. Most fragile. |

**Real Matrix bridges that exist:** mautrix-whatsapp (reverse-engineered WhatsApp Web protocol), mautrix-facebook/instagram (same approach for Meta, constantly broken by Meta, constantly patched), matrix-appservice-slack/discord (use official APIs where available), mautrix-twitter (was working, X API changes made it harder).

**What Matrix gets right:** Protocol-level bridge entity is the right abstraction. Ghost users let bridged participants exist without being Matrix-native. Self-hosting bridges gives user control. Bridge operator is visible and accountable.

**What Matrix gets wrong — and what SCP fixes:**
- Ghost users have no real identity. You can't verify that `@dave_fb` actually is Dave from Facebook. No cryptographic attestation. **SCP fixes this with identity attestations + shadow claiming.**
- Trust is binary — ghost user is in the room or not. No nuanced trust evaluation. **SCP fixes this with provenance-tracked trust hierarchy.**
- Bridge operators are de facto trusted intermediaries — see all traffic. Matrix doesn't mark bridged content structurally. **SCP fixes this with provenance chains on all bridged content.**
- Platform breakage is constant and exhausting. **SCP's cooperative mode is designed to change the incentive structure (see below).**

### Cooperative Mode Incentive Design (§12.9)

The key design question: how do you make cooperative mode the path of least resistance for platforms, rather than just aspirational?

**Why platforms resist bridging (Matrix's experience):** Bridges leak users off the platform. A WhatsApp user who can read messages in Matrix has less reason to open WhatsApp. Platform loses engagement, ad impressions, data surface.

**Why SCP changes the equation:**

- Shadow identities are second-class. Bridged content via relay/puppet is provenance-marked as weak-trust. If the platform implements cooperative mode, their users get *stronger* provenance — cooperative bridge is more trusted because the platform vouched for attribution.
- Cooperative mode gives the platform a seat. The platform can include metadata about its users that strengthens trust evaluation — influence it doesn't have when a third party is scraping.
- The bridge happens anyway. Relay and puppet modes exist. Platform can't prevent it without hurting its own users. Cooperative mode gives control over a process that will happen regardless.
- Minimal implementation cost. The bridge connector interface is deliberately small — a handful of structured endpoints. Not a protocol adoption. Comparable to implementing an OAuth provider.

**Design principle:** Make the protocol's trust model reward cooperation and make non-cooperation a worse experience for the platform's own users, without making it an ultimatum.

---

## 2. "Is SCP Pointless Given Matrix Exists?"

This was asked directly. The full analysis:

### What Matrix Is

Matrix is a **federated communication protocol**. It solves: how do encrypted messages move between decentralized servers, organized into rooms, with permissions? It does this well. It's been doing it since 2014.

### What Matrix Is Not (The Full List)

Matrix has no concept of:

- **Agents as accountable, bounded participants.** Matrix bots are just user accounts. No cryptographic binding to a human, no capability constraints per room, no structured trust evaluation. Nothing distinguishes a bot from a person at the protocol level.
- **One-agent-per-person-per-context.** You can put 500 bots in a Matrix room.
- **Agent isolation across rooms.** A Matrix bot in Room A and Room B shares memory and state freely. No protocol-level isolation. This is SCP's primary security invariant.
- **Trust as f(identity, capability, context, metadata).** Matrix has power levels — a single integer (0–100) per user per room. No per-capability tokens. No UCAN delegation. No agent capability metadata.
- **Capability ceilings.** Matrix rooms have no concept of "this room can never do more than X." Any admin can change any permission at any time.
- **Tools as stateless, non-agentic functions.** Everything in Matrix is a user or a bot pretending to be a user.
- **Self-sovereign identity.** Matrix identities are homeserver-bound: `@alice:matrix.org`. Homeserver dies, identity is in trouble.
- **Context metadata transparency before opt-in.** You join a Matrix room and then discover what you can do.
- **Non-fungible cross-platform identity attestation.** No mechanism exists.
- **Infrastructure for generated apps.** Matrix is messaging infrastructure, not social infrastructure for arbitrary applications.

### The Layer Distinction

```
Matrix answers:    "How do messages move between decentralized servers?"

SCP answers:       "Who is this agent, what can it do, who is it
                    accountable to, what are the boundaries of this
                    social space, and how do we evaluate trust in a
                    world where autonomous software acts on behalf
                    of people?"
```

These are different layers. You could build SCP *on top of* Matrix. Matrix rooms become transport substrate for SCP contexts. Matrix handles message routing and encryption. SCP handles agency, trust, boundaries, social structure. Complementary, not competing.

### Where Matrix's Struggles Are Instructive for SCP

Matrix has been around for 12 years without mainstream adoption. Lessons:

- **Homeserver complexity.** Running Synapse is a sysadmin job. SCP's self-hosting promise needs to be dramatically simpler or it'll repeat this.
- **Federation performance.** Matrix state resolution is computationally expensive and slow.
- **Identity fragility.** Homeserver-bound identity = server operator is single point of failure. SCP's DID-based identity is the right correction.
- **Bridge fragility.** Matrix bridges break monthly. SCP's cooperative mode is the right aspiration but relay/puppet will face the same whack-a-mole.
- **"Protocol for nerds" problem.** Matrix is a good protocol most people will never use directly. SCP needs to be invisible infrastructure used *through* apps (Cronica first), not a protocol people interact with.

### The Honest One-Liner

Matrix is a decentralized messaging transport. SCP is a social infrastructure layer for agent-native applications. If the thesis is right — agents are primary actors and apps are disposable — then Matrix solves the wrong problem at the wrong layer. If the thesis is wrong and the future is "better chat," then yes, Matrix already exists.

---

## 3. Encoding Win Conditions Into Protocol Design

After the Matrix comparison, the question was: **what of this can we build into the protocol's design to make it more aligned with these win conditions?**

Six structural additions were designed, each encoding a constraint architecturally rather than as a social contract:

### Human-Agent Pair (§4.5)

**Win condition:** The agent thesis can't regress.

First draft said "Agent-Native Only" — no raw human interaction mode. The user pushed back: **"The human and human-bound-agent model should be kept."** The framing was muddying the human-agent binding.

Revised to: the fundamental unit is the human-agent pair. Human is root of identity/trust/accountability. Agent is the human's protocol-level presence. No separate "human-direct" mode exists, but this is because the agent IS the human's presence — like a voice is a person's presence in conversation. The human decides what the agent does (full autonomy to direct manual control) and that decision is local, outside protocol scope.

One actor model at protocol level. No bifurcation between "agent actions" and "human actions." Trust evaluation is uniform. Minimum viable agent is trivial — can be generated, embedded in an app, or provided as a default.

### Context Portability and State Layering (§8.3)

**Win condition:** Apps are actually disposable.

First draft said "the protocol refuses to let apps own context state." User pushed back: **"Apps can be first party owners of state specific to them. I like the ethos of it though, it's just too limiting as designed."**

Revised to a two-layer model:
- **Protocol state** (membership, roles, capability tokens, governance, trust) — belongs to the protocol. App-independent. Portable. Survives app death.
- **App state** (game state, task boards, document history) — belongs to the app. The protocol doesn't claim it. Apps manage it however they choose.

The boundary between the two is the anti-lock-in mechanism. Leave an app, you lose app state (unless the app makes it portable). You never lose membership, roles, trust relationships, identity, or social graph. Social infrastructure is not hostage to any app's business decisions.

Key addition: **thick apps are welcome.** A game with rich proprietary state is a first-class participant. The protocol doesn't demand all state be portable — only the social layer. Apps compete on app-layer value, not social graph lock-in.

Analogy: same distinction that made the web work. HTTP/HTML own transport and document structure. Apps own their databases. You can't lock someone in by owning their browser bookmarks. But you own your application data.

### Capability Declaration Contract (§8.4)

**Win condition:** Generated apps are safe by construction.

Apps interact through a declarative manifest: "I need: messaging, member_list, tool_invoke(tool_a, tool_b)". Protocol validates against context ceiling + agent role. Grants exactly what was requested or denies.

This is the boundary that makes generated apps safe. An LLM generating a client doesn't need to understand SCP internals. The attack surface of a badly-generated app is bounded by the declaration contract, not by the app's code quality.

Properties: declarative not imperative, validated against ceiling + role, machine-readable and self-documenting, versionable with forward compatibility.

### Device-as-Node + Infrastructure Honesty (§10.2, revised)

**Win condition:** Self-hosting means "install an app."

This was subjected to a realism check (see section 4 below). Revised to be honest: device is a full participant when online, but offline devices are unavailable nodes. The real guarantee is "no server owns you," not "no server needed." DID-based identity surviving infrastructure death is the structural advantage over Matrix, not the elimination of servers.

### Relay Architecture (§10.4, revised)

**Win condition:** Offline devices don't break the protocol.

Also subjected to realism check. Revised to acknowledge: metadata exposure unsolved at scale, relay discovery is a real problem, "simple message queue" undersells operational complexity, gravitational pull toward popular relays is inevitable (but not lock-in because DID identity). Self-hosting a relay is a server task, not "install an app."

### Cooperative Mode Incentive Structure (§12.9)

**Win condition:** Platforms choose cooperation over resistance.

Trust model structurally rewards cooperation. Non-cooperation is worse for the platform's own users. Detailed above in bridging section.

### The Common Thread

Every addition is a **structural enforcement** that removes a failure mode by making it architecturally impossible, not just socially discouraged:

- You can't build a non-agent-native app (human-agent pair model)
- You can't lock users to your app via context state (state layering)
- You can't ship an overprivileged app past the declaration contract
- You can't require a server to participate (device-as-node)
- You can't gain platform leverage through relay operation (substitutable relays + DID identity)
- You can't ignore bridging without your users paying the trust cost (cooperative mode incentives)

---

## 4. Realism Check on Infrastructure (Device-as-Node + Relays)

The question was asked directly: **"How realistic are 4 and 5?"** (Device-as-node and relay architecture.)

### Device-as-Node: Partially Realistic

**What's genuinely feasible:**
- Storing protocol state on a phone. Membership, roles, tokens — kilobytes per context. Trivial.
- Performing crypto on a phone. Hardware accelerators. Not a bottleneck.
- Being a full protocol participant when online.

**What's not:**
- **Phones can't be always-on nodes.** Sleep, lose signal, iOS kills background processes. A phone is a participant, not a server. The spec acknowledges this by requiring relays, but then the relay IS infrastructure you depend on.
- **NAT traversal.** Phones behind carrier NAT, WiFi NAT. P2P is hard. Solved-ish (STUN/TURN/ICE) but unreliable. Falls back to relaying through a server... which is a server.
- **iOS constraints.** Apple severely restricts background execution. Can't run a persistent daemon. Push notifications exist but they're Apple-mediated — contradicts sovereignty model. An SCP app on iOS that receives messages while closed needs APNs, meaning Apple is in the delivery path.

**Honest framing:** "Device-as-node" is real for protocol participation. Not real for protocol availability. Phone-only user can do everything — but only when looking at their phone.

### Relay Architecture: Conceptually Sound, Operationally Hard

**What the spec undersold:**

- **"Simple, stateless message-forwarding infrastructure" is what everyone says before building a messaging system.** Reliable delivery, ordering, deduplication, backpressure, rate limiting, abuse prevention — this is genuinely hard distributed systems work.
- **"Untrusted" relays still see metadata.** Who talks to whom, when, how much, from what IP. Same problem Tor and Signal wrestle with.
- **"Substitutable" has switching cost.** Alice needs to know Bob's relay. Bob switches, Alice needs to discover the new one. Relay discovery is either centralized (defeats purpose) or distributed (adds complexity).
- **Self-hosting a relay is not "install an app."** Requires stable address, TLS, uptime commitment. It's a server. Simpler than a Matrix homeserver (no state resolution, no federation protocol, no room DAG) but still a server.
- **Relay federation is federation.** Same hard problem Matrix has. Calling it "relay federation" doesn't make it simpler.
- **Spam and abuse.** Open relay = spam target. Need auth, rate limiting, reputation. Solved individually, collectively significant.

### The Nostr Comparison (Pre-Realization)

Nostr was introduced here as the closest real-world analog — attempting almost exactly this model:

| Claim | Nostr's experience |
|---|---|
| Relays are simple | Basic relay is simple. Reliable relay with search, filtering, abuse prevention is not. |
| Relays are substitutable | True in theory. In practice, users cluster on a few popular relays. Network effects apply to infrastructure too. |
| Self-hosting is easy | Possible for technical users. Nobody's grandmother runs a Nostr relay. |
| No server needed | Technically true. Practically, relay goes down, you're invisible. |
| Identity survives relay death | **Yes — this is the real win.** Keypair identity means no server owns you. |

The last point is what actually works and actually matters. DID-based identity is the real structural advantage over Matrix, not the relay architecture.

### What Changed in the Spec

§10.1 Philosophy: reframed from "negligible difference" to honest two-part claim. Protocol *guarantees* no one owns your identity/relationships. Protocol *provides but doesn't trivialize* relay/storage infrastructure.

§10.2 Device-as-Node: honest about offline unavailability. Added: "The protocol's real guarantee is not 'no server needed' — it's 'no server owns you.'"

§10.4 Relay Architecture: acknowledged metadata exposure, discovery complexity, operational burden, gravitational pull. "Self-hosting a relay is feasible for technical users... but it is still a server."

---

## 5. "This Is Really A Lot Like Nostr"

This was the pivotal realization. At the transport and identity layer, SCP is reinventing Nostr.

### The Overlap Is Architectural, Not Superficial

| SCP Concept | Nostr Equivalent |
|---|---|
| DID (keypair-based identity) | npub/nsec (public key IS identity) |
| Substitutable relays | Nostr relays |
| Encrypted payloads, relay doesn't interpret | Nostr events, relays store signed blobs |
| Client-side intelligence | Nostr clients are the smart layer |
| Relay discovery via published list | NIP-65 relay list metadata |
| Social recovery | Not in Nostr (but same problem space) |

### What SCP Adds That Nostr Doesn't Have

Nostr is a signed-event gossip protocol. It has no concept of:

- **Contexts** — bounded social spaces with membership, roles, governance. NIP-29 attempts relay-based groups but it's primitive — no capability ceilings, no governance, no role definitions beyond admin/member.
- **Agents as protocol entities** — Nostr is human-direct. Every event signed by a human's key. NIP-26 (delegated event signing) exists but no formalized agent model, binding, capability constraints, or one-agent-per-context.
- **Trust as f(identity, capability, context, metadata)** — Nostr trust is "do I follow this pubkey." Binary.
- **UCAN-style capability tokens** — fine-grained, per-context, per-capability, revocable.
- **Capability ceilings** on contexts.
- **Tools as protocol primitives** — stateless functions scoped to contexts.
- **Bridge connectors** with shadow identities and provenance.
- **App interface / capability declarations** — the generated-app infrastructure.

This is the Social Context Layer — the actual novel work. **Everything below it in the stack already exists.**

### Should SCP Build on Nostr?

Three options were discussed:

1. **SCP defines a relay protocol.** Specifies exactly how relays behave. What Matrix does (Server-Server API IS the federation protocol).
2. **SCP defines transport requirements and ships bindings.** Specifies properties, provides adapter implementations for existing transports. Like a database ORM — define the interface, ship drivers.
3. **SCP picks one transport and builds tight.** Just uses Nostr directly. Fast to build, hard to change.

**Decision: Option 2.** The user noted that option 3 is just a subset of option 2 — if the abstraction is thin (and it should be — maybe 5-6 methods), designing it first costs almost nothing. Your first binding is just the first implementation of the interface. There's no shortcut to skip.

**Arguments for building on Nostr:**
- Don't reinvent the transport layer. Nostr relays exist, work, have operators. Client libraries exist in every language.
- Identity alignment. Nostr's keypair identity maps nearly trivially to `did:key:`.
- NIP extensibility. SCP's social context layer could be a set of NIPs or a protocol layer consuming Nostr events.
- Existing user base, relays, clients. Not starting from zero.
- Philosophical alignment. Both sovereignty-first, anti-platform-lock-in, keypair-rooted.

**Arguments against:**
- Cultural baggage. Nostr is associated with Bitcoin maximalism. Branding concern, not technical.
- Nostr's simplicity may be a constraint. SCP may need richer primitives (structured capability tokens, context state machines, governance transactions) awkward as Nostr events.
- Relay semantics. SCP contexts need access control. Nostr relays are mostly open. NIP-42 (relay auth) exists but isn't universal. SCP would need SCP-aware relays OR an encryption-based access model (see below).
- Dependency risk on Nostr's ecosystem/governance.
- DID vs npub. Nostr uses raw public keys — can't change key without changing identity. SCP's DID model allows key rotation, important for recovery.

**Middle path (what the spec now says):** Define SCP protocol semantics independently. Provide a Nostr binding as the reference transport. Allow alternative transports (Matrix, libp2p, raw WebSocket). Use DIDs as identity layer with trivial mapping to Nostr npubs for Nostr-transport contexts.

### The Access Control Tension — And Its Resolution

The key technical fork: Nostr relays are open by default, SCP contexts are bounded by default. These are in tension... unless access control is handled entirely through encryption.

**Encryption-as-access-control model:**
- Context created → context encryption key generated → key distributed to members only → all context events encrypted with context key before reaching transport
- Relay sees: encrypted blobs with a context_id tag
- Relay does: store, forward to subscribers of context_id
- Relay knows: which context_ids exist, who subscribes
- Relay can't: read content, verify membership, enforce roles
- Access control: if you have the key, you can read. If you don't, the blobs are opaque. Key distribution IS membership. Member removal = key rotation.

This is essentially how Signal's group encryption works. It means:
- Relays genuinely don't need to be SCP-aware. They're blob stores.
- Any relay that can store and forward tagged encrypted payloads works.
- Nostr relays can do this today without modification.
- Access control is enforced client-side by key possession, not server-side by relay logic.

**This was identified as the key architectural insight of the session.** It's what makes the transport layer genuinely thin and genuinely delegatable.

---

## 6. SDK Transport Architecture — Where Implementation Boundaries Live

The question was asked: **"Where do actual impl details of relay and transport live in the overall protocol design and impl? How much of the relay impl is SCP responsible for vs defining adherence to?"**

### The SDK Layering

```
SCP SDK
├── Core Protocol Logic (100% SCP's responsibility)
│   ├── Context management, agent lifecycle
│   ├── Trust evaluation, capability tokens (UCAN)
│   ├── Identity (DID), role enforcement
│   ├── Governance, provenance tracking
│   └── Bridge connector management, app capability declarations
│
├── Transport Abstraction Layer (SCP defines the interface)
│   ├── send(context_id, encrypted_envelope) → receipt
│   ├── receive(context_id) → stream<encrypted_envelope>
│   ├── publish_relay_list(did, relays) → void
│   ├── discover_relays(did) → relay_addresses
│   └── subscribe(context_id, filter) → stream
│
├── Transport Bindings (SCP ships at least one, community extends)
│   ├── Nostr binding (SCP envelopes as Nostr events, Nostr relays)
│   ├── Matrix binding (SCP events as Matrix room state events)
│   └── WebSocket binding (direct device-to-device, testing/local)
│
└── Reference Relay Config (for self-hosters)
    └── Deployment guide for the primary binding's relay
```

### Responsibility Breakdown

| Layer | SCP's responsibility | NOT SCP's responsibility |
|---|---|---|
| Protocol logic | Full ownership. This is the product. | — |
| Transport abstraction | Define the interface contract. | Implementing the transport itself. |
| Transport bindings | Ship at least one reference binding. | Maintaining every binding. Community extends. |
| Relay behavior | Specify what SCP needs from a relay. | Implementing relay software. Existing relays cover this. |
| Relay operation | Ship reference config/deployment guide. | Running relays for users (managed infra — business layer). |
| Encryption | Full ownership. Envelope format, key management, access control. | — |
| Identity | Full ownership. DID management, custody, attestations. Binding maps DIDs to transport identities. | — |

### Key Clarification

The abstraction is designed before the first binding, not extracted from it after. The user confirmed: option 2 (abstract + bind) is a superset of option 3 (pick one and go). If the abstraction is thin — and it should be, maybe 5-6 methods — there's no shortcut to skip. The Nostr-first part is a binding priority decision, not an architectural compromise.

---

## 7. Where Things Stand — Full Gap Analysis

### Established (Architecture Decided, Spec Language Written)

| Section | What's solid |
|---|---|
| §1 Thesis | Core thesis, design principles, positioning |
| §2 System Design | Conceptual architecture, diagrams, context interior, cross-context communication, trust model, full stack |
| §3 Identity | DID-based, key custody abstracted, social/device recovery, linking existing identities, identity attestations |
| §4 Agents | Core principle, binding, one-per-context, BYOA, human-agent pair, context-bound, fleet model |
| §5 Contexts | Definition, creation, capability ceiling, tools, roles, membership, metadata, context identity, governance (conceptual) |
| §6 Cross-Context | Agent isolation (absolute), context-to-context tool interfaces (stateless, opt-in), human-as-bridge |
| §8 Apps | Apps as entities, app interface, context portability/state layering, capability declaration contract |
| §9 Security | Core invariants (7 listed), threat vectors and mitigations (8 threats analyzed), systemic defense philosophy |
| §10 Infrastructure | Honest philosophy, device-as-node (with caveats), minimal protocol state, relay architecture (with caveats), SDK transport architecture, encryption-as-access-control, business model, build-on-existing |
| §11 Standards | Mapping of what exists vs. what's novel |
| §12 Bridge Connectors | Problem statement, entities, shadow identities, operating modes, trust/provenance, context isolation, self-hosting, platform resistance, cooperative mode incentives |

### Sketched (Direction Set, Needs Work)

- **§7 Trust and Capabilities.** The model is described — "Trust = f(identity, capability, context, metadata)" — but thin. The unified model, capability tokens, and transitive trust sections are conceptual. Not unpacked into protocol mechanics.
- **§10 Infrastructure.** Honest and well-framed but still "how we think about it" not "how it works." The SDK transport architecture gives the right shape but the actual interface isn't designed.

### Tier 1: Blocks Building Anything

These must be resolved before any SDK implementation can begin. They're in dependency order — each cascades into the next.

**1. Context key management / group encryption.**
This is the first domino. Encryption-as-access-control is the linchpin of the whole transport architecture, but the spec doesn't specify which group encryption protocol to use. Options: MLS (Messaging Layer Security, IETF RFC 9420) vs. Signal's Sender Keys vs. something custom. This cascades into everything — how members are added/removed, forward secrecy guarantees, key rotation cost, performance with large groups. Can't build the SDK without this.

**2. Transport abstraction interface.**
The spec says it should exist and roughly what it provides. It doesn't define the actual methods, the envelope format, or the binding contract. This is the SDK's most fundamental interface — everything above it is protocol logic, everything below it is pluggable transport. Needs to be designed and written down.

**3. DID method selection.**
The spec says "build on DID" but DIDs are a family of methods (`did:key`, `did:web`, `did:pkh`, `did:ion`, dozens more). Which one? `did:key` is simplest (just a public key, no resolution infrastructure) and closest to Nostr's model. `did:web` needs a web server. `did:ion` needs Bitcoin. This choice affects identity resolution, recovery, and key rotation. Important nuance: Nostr uses raw public keys — can't change your key without changing your identity. SCP's DID model should allow key rotation, which is important for recovery. This pushes away from `did:key` (which is also just a raw key) and toward something with a document that can be updated.

**4. UCAN capability schema.**
The spec says "UCAN-based capability tokens" throughout but doesn't design the actual capability schema. What capabilities exist? What's the token format? How are they granted, presented, verified, revoked? This is the enforcement mechanism for roles, context ceilings, and trust evaluation. Without it, roles and ceilings are conceptual, not enforceable.

### Tier 2: Blocks the First Useful App

These must be resolved to ship Cronica or any other client on SCP.

**5. Context lifecycle.**
How is a context actually created, configured, and managed at the protocol level? What's the event sequence? What messages are exchanged? What's the minimum viable context? The spec describes contexts conceptually — what they contain, what properties they have — but doesn't specify the state machine.

**6. Minimum viable agent specification.**
What does the passthrough agent look like? What messages does it send/receive? What's the protocol handshake when an agent joins a context? Without this, nobody can build a client. The spec says "the minimum viable agent is trivial" but doesn't define it.

**7. Capability declaration format.**
What does an app's capability manifest actually look like? JSON schema? Protocol buffers? Something else? Must be concrete enough that someone (or an LLM) can write one. The spec describes the concept and the validation flow but not the format.

**8. Cronica mapping.**
The spec lists this as uncovered, and it's the first client. How do quests, the AI Guide, and quest communities map onto contexts, agents, tools, and roles? Working this through will stress-test every abstraction in the spec and reveal which concepts are load-bearing vs. theoretical. This could be a valuable next session — force every SCP concept through a concrete use case.

### Tier 3: Blocks Growth / Network Effects

These don't block building but block the protocol from being useful at scale.

**9. Social graph structure.** ✅ RESOLVED.
Social graph is not a protocol primitive. It is local agent state, computed from context membership, shared via the same capability-gated permission model as any other personal data. No follow/friend primitives. No global graph. No public follower counts. Block/mute is local agent policy. Added to spec as §3.6.

**10. Identity attestation discovery.**
How does Alice find out that `@bob_x` on X maps to `did:key:abc`? This is what makes social graph import and shadow identity claiming work in practice. Without it, bridging is theoretically possible but practically useless. Options: distributed registry, DHT, attestations in DID documents, gossip protocol. Must be decentralized.

**11. Context discovery.**
How do users find contexts to join? Search? Invitations only? Directory? Recommendation? This is the "how does anyone find anything" problem. If contexts are cryptographic entities you opt into by key, there must be a discovery layer that maps human-meaningful information to context keys.

**12. Governance primitives.**
The spec says contexts support multiple governance models. What are the protocol-level primitives? How does voting work? Multi-sig? Consensus? This can be simple for v1 (single-admin only) and extended later, but the primitive set needs to be defined so it's extensible.

### Tier 4: Important But Deferrable

These are real concerns that don't block shipping.

**13. Content provenance system.** Hash chains, origin tracking. Important for trust evaluation and bridge content attribution. Can be designed after core works.

**14. Earned capacity mechanisms.** Rate limiting context creation, preventing sybil attacks. Important for network health but can be tuned empirically after launch.

**15. Metadata privacy.** Traffic analysis resistance. Real concern but unsolved at scale by anyone. Acceptable to acknowledge and defer. Encrypted content + substitutable relays may be sufficient for v1.

**16. Offline/local-first behavior.** Sync, conflict resolution, disconnection handling. Important for mobile UX. Device-as-node framing informs this but mechanics are unspecified.

---

## 8. Context Poisoning — Deep Analysis

The spec (§9.2) mentions context poisoning as a threat vector with a one-line mitigation. The question was asked: **does SCP actually solve context poisoning?**

### Answer: Mitigates, Doesn't Solve. No Protocol Can.

But it's worth being specific about what it catches and what it doesn't, because some vectors have real gaps.

### Attack Patterns and SCP's Coverage

**Data poisoning — member with write access submits garbage, disinfo, or malicious content.**
SCP mechanisms: one-agent-per-person (no sockpuppet flooding), role-based write access, content provenance (who wrote what is traceable). Assessment: **attributable but not preventable.** A legitimate member with write access can still post garbage. Protocol makes the poisoner identifiable, doesn't make poisoning impossible. You have to rely on governance (kick the member) or trust evaluation (other agents downweight that source).

**Social poisoning — trusted member uses invite rights to bring in allies who degrade the space.**
SCP mechanisms: roles limit what invited members can do. Earned capacity (when designed) slows new identity participation. Member list is transparent — everyone sees who invited whom. Assessment: **slowed, not prevented.** Coordinated infiltration by a trusted member is a social problem, not a protocol problem. Transparency helps detect it but doesn't stop it.

**Tool poisoning — a context's tool provider turns malicious or gets compromised, tool starts returning bad data.**
SCP mechanisms: tools are stateless and non-agentic, can't initiate, scoped to context. Assessment: **real gap in the spec.** Nothing addresses tool integrity verification. Who ensures a tool does what it claims? A tool that returns subtly wrong data — financial calculations off by small amounts, schedule suggestions that create conflicts, search results that omit relevant items — is a serious vector. Every agent calling that tool consumes poisoned output. The spec says tools "take input and return output" but has no mechanism for verifying that the output is honest.

**Governance capture — accumulating enough influence to change the rules in a mutable-governance context.**
SCP mechanisms: capability ceilings bound the damage (if immutable, even captured governance can't exceed them). Governance model is transparent. Assessment: **bounded, not prevented.** Within the ceiling, captured governance can change roles, kick members, modify tool registrations. Immutable ceilings are the strong defense, but the mutability question is still open.

**Slow degradation / boiling frog — individual changes each seem fine but collectively transform the context.**
SCP mechanisms: capability ceilings set hard boundary (if immutable). If mutable, mutations require governance approval and are visible. Assessment: **ceilings help. Visibility helps. Neither is enough.** The boiling frog problem is fundamentally about humans not noticing gradual change, which is a perception problem, not a protocol problem.

### AI-Specific Poison Vectors — What the Spec Doesn't Address

In a world where agents are the primary actors, context poisoning has new dimensions the spec hasn't considered:

**Prompt injection through context content.** An agent reads messages in a context. A malicious member crafts a message designed to manipulate the agent's behavior. This isn't a protocol problem — it's an AI safety problem — but the protocol could surface defenses. Content provenance lets an agent know *who* said something and weight trusted sources higher. But the protocol doesn't inspect or sanitize content, by design ("don't inspect content, inspect behavior topology").

**Context-as-trap.** A context designed specifically to manipulate agents that join. Attractive metadata, reasonable-looking capability ceiling, but the tools and content within are designed to exploit agent behavior. Partially covered by bait-and-switch threat vector (capability ceilings bound what can happen) but content within the ceiling can still be adversarial.

**Cascading poisoning through cross-context tool interfaces.** Poisoned data from Context A flows through a tool interface into Context B. The content provenance system (§9.2) is designed to make this traceable — data carries its origin context and interface chain — but that system is in "open questions," not designed yet. Without it, cross-context tool interfaces are a real propagation vector.

### Identified Gaps to Strengthen

Three specific defenses were identified as worth adding to the protocol:

**1. Tool integrity verification.** Tools should have a content-addressable definition or cryptographic signature. When a tool is registered with a context, its behavior is pinned. Agents can verify a tool hasn't been modified since they opted in. If the tool's implementation changes, this is a visible event — not a silent mutation. This would address the tool poisoning vector directly.

**2. Behavioral anomaly surfaces.** The spec says "don't inspect content, inspect behavior topology" but doesn't define what behavioral signals are actually surfaced at the protocol level. Candidates: message velocity per member, role change frequency, tool invocation patterns, invitation velocity, governance action frequency, bridge traffic volume. These are structural metadata — not what's being said, but how the context's behavior topology is changing. Making these signals available as protocol-level observability lets agents and governance tools detect poisoning patterns.

**3. Agent capability metadata for defensive posture.** If an agent has prompt injection protections, content filtering, adversarial input detection, or other hardening, that could be surfaced as part of agent capability metadata. This lets other participants know which agents are hardened against manipulation and calibrate trust accordingly. A context full of unhardened agents is more vulnerable to prompt injection attacks — this should be legible.

### MCP Integration and Context Poisoning

Also discussed: **MCP (Model Context Protocol) integration** as a natural architectural fit. MCP is the local wiring between AI models and tools. SCP is the network social layer. The SCP agent sits between them — MCP server locally, SCP participant on the network. Key detail: the agent filters which tools the model sees based on role/capability, so the model never even knows about tools it can't access. This is relevant to poisoning because the agent is also the natural place to implement defensive filtering — provenance-aware content presentation, trust-weighted message ordering, tool integrity checks.

MCP integration was added to the spec as §8.5. SCP tool schemas should use MCP-compatible JSON format. Any MCP-speaking model can participate in SCP contexts through an SCP agent without knowing SCP exists.

---

## 9. Recommended Next Session

These sections have clear positions and don't need more design work at the spec level (implementation details remain, but the "what" is decided):

- §1 Thesis — solid
- §2 System Design — the diagrams and conceptual architecture are clear
- §3 Identity — DID-based, key custody abstracted, social recovery, identity attestations
- §4 Agents — binding, one-per-context, BYOA, human-agent pair, context-bound, fleet
- §5 Contexts — definition, creation, capability ceiling, tools, roles, membership, metadata, governance (at the conceptual level)
- §6 Cross-Context Communication — agent isolation, tool interfaces, human-as-bridge
- §8 Apps — apps as entities, interface, state layering, capability declarations
- §9 Security Model — core invariants, threat vectors, defense philosophy
- §12 Bridge Connectors — entities, shadow identities, operating modes, provenance, incentives

Sketched — Direction Set, Needs Detail

- §7 Trust and Capabilities — the model is described but thin. "Trust = f(identity, capability, context, metadata)" is stated but not unpacked.
- §10 Infrastructure — philosophy, device-as-node, relay architecture, SDK transport architecture are honest and clear. But these are still "how we think about it" not "how it works."

The Actual Gaps

In priority order — roughly "blocks implementation" to "can figure out later":

Tier 1: Blocks Building Anything

1. Context key management / group encryption. This is now the first implementation decision. Encryption-as-access-control is the linchpin of the whole transport architecture, but the spec
doesn't specify which group encryption protocol to use. MLS (Messaging Layer Security, IETF RFC 9420) vs. Signal's Sender Keys vs. something custom. This cascades into everything — how
members are added/removed, forward secrecy guarantees, key rotation cost, performance with large groups. Can't build the SDK without this.

2. Transport abstraction interface. The spec says it should exist and roughly what it provides. It doesn't define the actual methods, the envelope format, or the binding contract. This is
the SDK's most fundamental interface — everything above it is protocol logic, everything below it is pluggable transport. Needs to be designed and written.

3. DID method selection. The spec says "build on DID" but DIDs are a family of methods (did:key, did:web, did:pkh, did:ion, dozens more). Which one? did:key is simplest (just a public key,
no resolution infrastructure) and closest to Nostr's model. did:web needs a web server. did:ion needs Bitcoin. This choice affects everything about identity resolution, recovery, and key
rotation.

4. UCAN specifics. The spec says "UCAN-based capability tokens" throughout but doesn't design the actual capability schema. What capabilities exist? What's the token format? How are they
granted, presented, verified, revoked? This is the enforcement mechanism for roles, context ceilings, and trust evaluation.

Tier 2: Blocks the First Useful App

5. Context lifecycle. How is a context actually created, configured, and managed at the protocol level? What's the event sequence? What's the minimum viable context? The spec describes
contexts conceptually but doesn't specify the state machine.

6. Minimum viable agent specification. What does the passthrough agent look like? What messages does it send/receive? What's the protocol handshake when an agent joins a context? Without
this, nobody can build a client.

7. Capability declaration format. What does an app's capability manifest actually look like? This is the contract between apps and the protocol. Needs to be concrete enough that someone (or
  an LLM) can write one.

8. Cronica mapping. The spec lists this as uncovered, but it's the first client. How do quests, the AI Guide, and quest communities map onto contexts, agents, tools, and roles? Working this
  through will stress-test every abstraction in the spec.

Tier 3: Blocks Growth / Network Effects

9. Social graph structure. How do relationships exist at the protocol level? Follow/friend semantics? Discovery? The spec mentions "social graph" but doesn't define it as a protocol
concept.

10. Identity attestation discovery. How does Alice find out that @bob_x on X maps to did:key:abc? This is what makes social graph import and shadow identity claiming work. Without it,
bridging is theoretically possible but practically useless.

11. Context discovery. How do users find contexts to join? Search? Invitations only? Directory? This is the "how does anyone find anything" problem.

12. Governance primitives. The spec says contexts support multiple governance models. What are the protocol-level primitives? How does voting work? Multi-sig? This can be simple for v1
(single-admin only) and extended later.

Tier 4: Important But Not Urgent

13. Content provenance system. Hash chains, origin tracking. Important for trust evaluation and bridge content attribution but can be designed after the core works.

14. Earned capacity mechanisms. Rate limiting context creation, preventing sybil attacks. Important for network health but can be tuned after launch.

15. Metadata privacy. Traffic analysis resistance. Real concern but unsolved at scale by anyone. Acceptable to acknowledge and defer.

16. Offline/local-first behavior. Sync, conflict resolution, disconnection handling. Important for mobile UX but can be iterated on.

---
My recommendation for what to work through next: Tier 1 items, in order. Context key management is the first domino — it determines the encryption model, which determines the envelope
format, which determines the transport abstraction, which determines what the SDK looks like. Then UCAN capability schema and DID method, because those are the other two protocol primitives
  everything is built on.
   
Two paths, depending on whether the priority is implementation-readiness or spec validation:

**Path A: Tier 1 deep dive.** Start with context key management (MLS vs. Sender Keys). This is the first domino — it determines the encryption model, which determines the envelope format, which determines the transport abstraction, which determines what the SDK looks like. Then DID method and UCAN capability schema. After this session, you'd have enough to start writing SDK code.

**Path B: Cronica mapping.** Force every SCP abstraction through a concrete use case. What is a Cronica quest as an SCP context? What tools does it expose? What roles exist? How does the AI Guide participate — is it an agent, a tool, both? What capability ceiling does a quest context declare? This will reveal which abstractions are load-bearing and which are theoretical overhead. It may also surface missing concepts the spec hasn't considered.

These aren't mutually exclusive but they pull in different directions — one goes deeper into protocol mechanics, the other stress-tests the conceptual model.

---

## 10. Attestation Deep-Dive — Trust vs. Validation

### The Opening Question

The conversation turned to attestations: **what value do they provide, how are they solicited and provided, and where do they sit technically in the design?**

### Attestation as Protocol Primitive

The key realization: attestation is not a feature of one section — it's a primitive used across the entire protocol. Identity links, UCAN delegation tokens, tool integrity proofs, agent capability metadata, endorsements, role assignments, context endorsements — they're all attestations. Different claim content, same envelope structure, same verification mechanics.

This unification was significant. Before this discussion, attestations appeared in §3.5 (identity) and §7 (trust) as separate concepts. After: a single common envelope format (`Attestation { id, type, issuer, subject, claim, evidence, timestamps, revocation, signature }`) underlies everything. The verification flow is always: check signature → check evidence → check expiry → check revocation. What varies is claim content and how it's evaluated.

### Attestation Types (Full Taxonomy)

Seven attestation types were identified:

1. **Identity link.** User attests they control an external platform identity. Evidence: platform-specific proof (OAuth, signed post, DNS). Automated verification where possible.
2. **Capability delegation.** UCAN token granting specific capabilities. The mechanism behind Layer 1 enforcement. Has its own format (UCAN spec) within the attestation envelope.
3. **Tool integrity.** Operator attests tool behavior and implementation. Evidence: implementation hash + test vectors. Verified via deterministic testing (Layer 2).
4. **Agent capability.** Human attests their agent's capabilities/defenses. Some self-attested, some challenge-verifiable (see below).
5. **Endorsement.** One identity vouches for another's competence in a specific domain. No objective evidence — value derives from the endorser's own behavioral record and endorsement accuracy history.
6. **Role assignment.** Governance assigns a role. Evidence: governance action signed by authorized DIDs.
7. **Context endorsement.** Any identity vouches for a context's legitimacy. Subjective, but endorser's behavioral record provides calibration.

### Solicitation and Presentation Patterns

Five patterns for how attestations move through the system:

- **Self-initiated.** Users create and publish their own (identity links, agent capabilities). No solicitation required.
- **Context-required.** Admission criteria specify required attestations. "To join as admin: verified identity link + challenge-verified prompt injection resistance." Mechanically verified at join time.
- **Peer-requested.** Agent requests attestations before a specific interaction. On-demand presentation.
- **Unsolicited.** Endorsements can be offered and published for anyone to discover.
- **Embedded in actions.** UCAN tokens travel with the actions they authorize. Tool integrity attestations travel with tool outputs.

### The "Validate, Don't Trust" Challenge

The user made a sharp observation: **"'Validate, don't trust' is all the rage lately. This seems to be 'trust, don't validate'. Or is it 'trust and validate (if you want)'?"**

This prompted a careful analysis of what the protocol actually validates vs. what it trusts.

**Three layers were identified:**

**Layer 1 — Protocol enforcement.** Pure zero-trust/validate. You have a valid UCAN token or the action is rejected. No judgment, no discretion. The protocol validates capabilities mechanically. This is "validate, don't trust" in its purest form.

**Layer 2 — Attestation authenticity.** The protocol validates *that Bob really said this* (signature verification), but not *whether what Bob said is true*. "Bob endorses Carol for scheduling" — protocol verifies Bob signed it and it's not revoked. Protocol has no opinion on whether Carol is actually good at scheduling. This is "validate the envelope, trust the content."

**Layer 3 — Trust evaluation.** "Should I take this scheduling recommendation?" Pure judgment. No validation possible. This is where the protocol provides data and agents decide. This IS "trust."

**The honest framing:** The protocol validates everything it can (Layer 1: capabilities, Layer 2: attestation authenticity). What remains is trust — but trust is bounded because the protocol provides rich inputs for evaluation rather than requiring blind faith.

### Codifying More Validation, Less Trust

The user pushed: **"Can we codify more validation and less trust somehow?"**

Seven specific mechanisms were designed to expand the validation surface at the expense of the trust surface:

#### 1. Behavioral Records Instead of Endorsements

Replace "Bob says Carol is trustworthy" (trust) with "Carol has invoked scheduling tools 203 times across 14 contexts with zero governance actions" (verification). Behavioral records are verifiable facts derived from context event logs. They don't eliminate trust for new identities (no history = no facts) but for established identities they substantially replace endorsements as the primary signal.

#### 2. Tool Verification via Deterministic Testing

SCP tools are stateless: same input → same output. This makes integrity testable. Tool registration includes implementation hash + test vectors. Any agent can verify at any time by running the tests. Multiple agents verifying independently creates threshold confidence. Tool mutations are logged in the Merkle tree — visible to all members, attributable to the operator.

#### 3. Threshold Attestations (N-of-M Independent Verification)

A single endorsement requires trust. Multiple independent endorsements approach validation. The protocol supports threshold requirements: "this claim is validated when N-of-M independent attestors confirm it." Independence is verifiable — the protocol checks shared memberships, mutual endorsements, correlation patterns.

#### 4. Challenge-Response Verification

Self-reported capabilities can be challenged. The protocol defines standard challenge suites for testable capabilities. Agent claims "prompt injection filtering: true" → context issues challenge test cases → agent processes → challenger verifies results. Challenge-verified capabilities are structurally distinguished from self-attested ones in agent metadata.

#### 5. Time-Locked Attestation Renewal

A claim verified once is a fact about the past. A claim continuously renewed is a fact about the present. Identity links re-verified via OAuth monthly. Tool integrity checked weekly. Lapsed attestations marked as stale, not revoked — agents factor staleness into evaluation. Renewal automated where possible.

#### 6. Verifiable Context History (Merkle Trees)

Every context maintains a Merkle tree of its event history. Any claim about the past is verifiable: "Carol has never been ejected from this context" → proof-of-absence against the Merkle root. "This capability ceiling has not changed" → proof against mutation history. Transforms past claims from trust-dependent to validation-dependent.

This was identified as architecturally significant — it adds a storage requirement to protocol state (tension with §10.3 device-as-node) and needs careful design for pruning, checkpoints, and availability.

#### 7. Consequence Mechanisms

If misbehavior has automatic protocol-enforced consequences, trust in character becomes unnecessary. Contexts define consequence rules: velocity thresholds → capability suspension, repeated warnings → automatic role demotion. Rules are declared at creation, visible before opt-in, and mechanically enforced. Transforms "do I trust this agent to behave?" into "are the consequences sufficient to make misbehavior irrational?" — a validation question.

### The Four-Layer Trust Stack

The full model that emerged from this discussion:

```
Layer 1: Protocol Enforcement (zero-trust)
  └─ UCAN tokens. Valid or rejected. No judgment.

Layer 2: Behavioral Validation (verify what happened)
  └─ Merkle event logs, behavioral records, tool verification,
     challenge-response, threshold attestations, renewal, consequences.
     This layer GROWS over time as history accumulates.

Layer 3: Attestation Authenticity (verify who said it)
  └─ Signature verification, expiry, revocation checks.
     Mechanical verification of attestation envelopes.

Layer 4: Trust Evaluation (judge what it means)
  └─ Agent-level subjective judgment.
     This layer SHRINKS over time as Layer 2 grows.
```

**The key insight:** trust doesn't disappear — it shrinks. A new identity lives mostly in Layer 4 (endorsements, gut feelings). An established identity lives mostly in Layer 2 (verified behavioral history). The protocol doesn't mandate this transition — it just makes behavioral data available, and rational agents naturally rely on verification over trust when verification data exists.

### What Changed in the Spec

All seven mechanisms were written into §7 (Trust, Validation, and Capabilities), which was rewritten from ~25 lines to 200+ lines with full subsections. Supporting changes:

- §5.4 (Tools) expanded with test vectors, implementation hashes, operator DIDs
- §4.4 (Agent capability metadata) expanded with self-attested vs. challenge-verified distinction
- §9.2 (Context poisoning) expanded with references to consequence mechanisms, verifiable event logs, tool integrity
- §9.3 (Systemic Defense Philosophy) rewritten with four principles: validate minimize trust, inspect behavior topology, consequences over character, observability as immune system
- §10.3 (Minimal Protocol State) updated with Merkle tree storage implications and pruning requirements
- §13 (Open Questions) updated with 7 new items: event log format, behavioral record schema, challenge suite standards, consequence defaults, endorsement accuracy tracking, attestation storage/discovery, threshold independence verification

### New Open Questions Surfaced

The trust/validation work surfaced several questions that need resolution:

- **Event log format.** Merkle tree structure, hash algorithm, leaf schema — must be efficient enough for device-as-node
- **Behavioral record portability.** How do agents exchange and verify behavioral records across contexts?
- **Challenge suite governance.** Who maintains standard challenge suites? How are they updated? Who decides what constitutes "passing"?
- **Consequence mechanism design space.** What rules are reasonable defaults? How do contexts signal comparable consequence structures?
- **Endorsement feedback loop.** How do you measure endorsement accuracy without circular reasoning?
- **Storage vs. verification tension.** Merkle trees per context grow with activity. Device-as-node requires minimal state. These pull in opposite directions. Pruning and checkpoint design is required.

---

## 11. Consumer Assessment and Social Graph Resolution

### Protocol Consumer Reframing

A critical assessment of the spec's adoptability surfaced an important reframing of who the protocol's consumer is.

Initial concern: the spec has ~25 concepts and a developer would need to understand all of them to build on SCP. MCP has 5 concepts and a developer can implement it in an afternoon.

The user's correction: **SCP's consumer is not a human developer. It's an agent generating ephemeral clients.** The thesis is that agents will generate 90% of software on the fly. SCP is designed for the agentic internet, not for human developers hand-coding clients.

This changes the adoptability surface entirely:

- The **capability declaration contract** is the primary (and potentially only) interface generated clients touch
- The **SDK** handles everything else invisibly — identity, encryption, trust evaluation, attestation verification, behavioral records, transport
- The concept count that matters is the **API surface** (declare capabilities, read context metadata, send/receive), not the protocol surface (25+ concepts)
- The trust model's complexity is **SDK complexity, not consumer complexity** — like TCP being complex but web developers never touching it

The design supports this: capability ceilings are protocol-enforced (not app-enforced), trust evaluation is agent-level (not app-level), encryption is below the transport abstraction, tool schemas are MCP-compatible. A generated app is a thin shell over the SDK. The SDK is the product.

### Social Graph — Resolved as "Not a Protocol Primitive"

The question was raised: does SCP need social graph as a first-class protocol structure?

**Answer: No.** Social graph is not a separate data structure. It is context state — each context already knows its members, their roles, their participation. The social graph is the sum of membership across contexts.

**Key correction during discussion:** An initial framing of "social graph as local agent state" was rejected — local state breaks the protocol model (not verifiable, not portable, not consistent across devices). The correct framing: the data lives in contexts as protocol state. A user's view of their graph is assembled from capability-gated queries against those contexts. The data is in the protocol. The view is computed. Access is permissioned.

**How it works:**
- Context membership IS the social graph data (protocol state, verifiable, persistent)
- Your agent queries contexts you participate in, computes relationship strength from shared participation
- Access to "who's in this context" / "what other contexts is this person in" is capability-gated
- Agent-to-agent and human-to-agent queries check permissions before responding
- There is no global graph, no public follower counts, no network-wide social structure to query

**Sharing is capability-gated.** Sharing your social graph with others uses the same trust/capability model as sharing any personal data:
- Per-identity: "Bob can see my connections. Carol cannot."
- Per-capability scope: "Bob can see I'm in this context, not my other contexts."
- Per-context: "Everyone here can see I'm a member. Nobody sees my other contexts."
- Per-category: "Close contacts see my full context list. Everyone else sees nothing."

Relationship metadata (not just existence but nature of the connection) is independently controllable. Alice might see you and Bob share the cooking quest but can't see you also share a private finance context.

**Block/mute** surfaced a follow-up design question: if block lists aren't context state and we want to avoid local-only state, where do they live? This led to the identity private state primitive (see below).

**No new primitives needed for graph visibility.** The existing trust equation and UCAN capability tokens handle graph visibility. Social graph isn't a separate system — it's just another resource governed by the same model as everything else.

This resolved gap item #9 from the Tier 3 analysis and was added to the spec as §3.6.

### Identity Private State — New Primitive (§3.7)

Block/mute exposed a gap: the protocol had context-scoped state (multi-party, shared) and identity public state (DID document, keys, attestations), but no concept of **identity-scoped private state** — data that's personal, cross-context, needs to survive device loss, and must remain invisible to others.

A "personal context" (single-member context as a private state container) was considered and rejected — a context needs to live somewhere, be replicated by someone, and a single-member context with no other members to keep it alive just collapses into "encrypted blob on a relay" with context overhead for no benefit.

**The solution: identity private state as a first-class primitive.** Your DID has public state (keys, endpoints, attestations) and private state (encrypted to your own keys, replicated to your relays, portable with your identity).

Key design properties:
- **Single-owner encryption.** No group key management. Only you hold the decryption key.
- **Same storage model as context state.** Encrypted blobs on relays. Relays can't read it. Encryption-as-access-control applied to identity rather than context.
- **Append-only event log for sync.** Each device appends events. Any device reconstructs current state from the log. Most operations are commutative (block X + block Y = same result regardless of order), so multi-device conflict is rare.
- **Integrity-verified.** Merkle root over the log. Relay tampering is detectable.
- **The single-owner degenerate case of context state.** Same infrastructure, same integrity model, no governance, no roles, no capability ceiling.

Contents: block/mute lists, graph visibility policies, agent configuration defaults, personal annotations on DIDs, notification preferences, draft attestations, and anything else identity-scoped and private.

This is the personal data layer the protocol was missing. Context state handles multi-party social data. Identity private state handles single-party personal data. Together they cover everything without local-only state.

Added to spec as §3.7 with open questions on size constraints, relay obligations, key rotation re-encryption, and discovery pointers.

---

## 12. Surface Area Completion — Full Coverage Pass

### The Assessment

A consumer-perspective assessment of the spec identified 11 topics the protocol needed a position on. The user provided direction on all 11 in a single pass. Key decisions:

### Positions Established

**Content model (§10.6).** Content is agnostic. The protocol has no opinion on content types, formats, or structure. Content is whatever contexts produce and frontends consume. App builders and clients decide. The protocol delivers encrypted envelopes; what's inside is not its concern. The previous "content referenced by hash" language was removed as overly prescriptive.

**Data sovereignty and storage (§10.6).** SCP is a protocol, not an entity. It doesn't host anything. People who use the protocol host their content. The SDK must make sovereign hosting work at every scale — from a generated ephemeral client storing locally, to a home server, to enterprise-grade infrastructure. Media is the same story: protocol users host their content, the protocol carries it through encrypted envelopes.

**Real-time vs async (§10.9).** Not a dichotomy. The SDK supports both as first-class. Async is the baseline (encrypted envelopes on relays, fetched when online). Real-time is supported when transport allows it (WebSocket, direct peer connections). Presence, typing indicators, live collaboration are tool-level or context-level capabilities, not protocol primitives.

**Notifications/push (§10.7).** Platform-dependent for v1 (APNs/FCM). Acknowledged as contradicting the sovereignty model. Pragmatic reality: no mobile app can notify without platform push services. Notification payload is opaque (wake signal only, no content). A sovereign push alternative is desirable but not blocking.

**Multi-device (§10.8).** Client scope. The protocol provides building blocks (identity private state for config sync, same context state on all devices, encrypted envelopes on relays). How clients implement read markers, notification deduplication, or session handoff is their decision.

**Versioning (§13).** Follow established best practices. Semantic versioning for the spec. Capability negotiation between agents and contexts. Forward compatibility as a constraint — old agents encountering new features degrade gracefully.

**Protocol governance (§14).** Foundation model if the protocol achieves wide adoption. Same path as MCP, Matrix, W3C standards. Early stage: creators drive decisions. Growth: community broadens governance. Mature: foundation stewards.

**Relay economics (§10.10).** App builder and operator responsibility. The protocol defines what relays do, not who runs them or why. Community relays, paid services, app-bundled infrastructure, self-hosted — all valid. Protocol ensures none create lock-in.

**Sybil resistance (§9.3).** Three-layer approach: device attestation (one DID per physical device via Apple App Attest / Google Play Integrity) + earned capacity (new identities start limited, grow through participation) + context-level social verification (contexts set their own admission thresholds, like Reddit's karma/age requirements). No biometrics, no KYC. Makes sybil attacks expensive rather than impossible.

**Regulatory compliance (§15).** Obligations fall on protocol users (app developers, relay operators, infrastructure providers). Protocol is built compliance-first and privacy-first: end-to-end encryption, self-sovereign identity, minimal protocol state, context-level content moderation tools. Right to erasure = DID revocation + attestation revocation (content in contexts remains, attributed to revoked DID). Content moderation is context governance responsibility. Same boundary as TCP/IP and HTTP.

### Key Reframing: "Agent as Consumer"

During the assessment, the user corrected the frame: SCP's consumer is not a human developer hand-coding against the spec. It's an agent generating an ephemeral client. This means:
- The capability declaration contract is THE primary interface (not one of many)
- SDK complexity doesn't matter if the SDK API surface is clean
- The trust model's depth is infrastructure, not developer-facing complexity
- MCP compatibility means models participate through the agent without knowing SCP

### What Remains

After this pass, the spec's surface area coverage is substantially complete at the architectural level. What remains is:
- **Tier 1 implementation specifics** (context key management, transport interface, DID method, UCAN schema)
- **Tier 2 application specifics** (context lifecycle, minimum agent, capability declaration format, Cronica mapping)
- **Offline/local-first mechanics** (informed by device-as-node but not specified)
- **Transport layer specifics** (the 5-6 methods, envelope format, binding contract)
