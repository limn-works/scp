# 8. Products and Apps in the Graph

## 8.1 Apps in the Protocol

An app is not a protocol entity. It has no DID, is not an agent, and is not a context. The protocol has no `App` type.

What people experience as "an app" is a composite: a context (or set of contexts) + its members + its data + the backend, hosting, and relays that support it. The client is just the visible surface. The app's identity is the whole gestalt — the community, the infrastructure, the accumulated state. This is a philosophical identity, not a codified one. The protocol doesn't need to model it because the constituent parts (contexts, members, outlets, data, capability declarations) are already first-class. The app emerges from their composition.

What the protocol *does* ensure is that this emergent identity never becomes lock-in: protocol state is portable (§8.3), clients are switchable, and no app owns the social graph.

## 8.2 App Interface

Apps declare what capabilities they need from the protocol. The protocol provides them. The interface is self-documenting and machine-readable, optimized for agent consumption rather than human developers hand-coding against it.

Apps can be any shape: thick clients with minimal protocol reliance, thin shells that are mostly protocol, or anything in between. The protocol doesn't care. It provides identity, social graph, contexts, outlets, trust, and transport. The app decides what to use.

## 8.3 Context Portability and State Layering

State in SCP exists at two layers:

**Protocol state** — membership, roles, capability tokens, outlet registrations, governance model, content history, trust relationships. This belongs to the protocol and the context, not to any app. It is portable, app-independent, and survives app death. Any app that declares the right capabilities can attach to an existing context and access its protocol state.

**App state** — data structures, configurations, and artifacts specific to a particular app's functionality. A game's world state. A project tracker's task board. A collaborative document's edit history. This belongs to the app. It may live in the context (stored via protocol data primitives) or entirely outside it (in the app's own infrastructure). The protocol doesn't claim ownership of app state, and apps are free to manage it however they choose.

The boundary between the two is the protocol's anti-lock-in mechanism. If you leave an app, you lose its app state (unless the app chooses to make it portable). You never lose your membership, your roles, your trust relationships, your identity, or your social graph. The social infrastructure is not hostage to any app's business decisions.

This means:

- **App switching.** A group can switch apps without losing their context's social infrastructure. Membership, roles, trust relationships persist. App-specific state may or may not transfer — that depends on the apps, not on the protocol.
- **Simultaneous multi-app.** Different members of the same context can use different apps. Alice uses a community app. Bob uses a custom-generated client. Carol uses a minimal terminal app. They share protocol state. Each has their own app-layer experience.
- **App death is survivable.** If an app stops working, the context's social infrastructure survives. App-specific data may be lost if the app didn't store it durably, but the people, the relationships, and the trust graph remain. Generate a new app and the context continues.
- **Thick apps are welcome.** An app with rich proprietary state (a game, a design tool, a financial instrument) is a first-class participant. The protocol doesn't demand that all state be portable — only that the social layer is. Apps compete on their app-layer value, not on social graph lock-in.

## 8.4 Capability Declaration Contract

Apps interact with the protocol through a **capability declaration** — a structured, machine-readable manifest of what protocol capabilities the app needs. The protocol validates the declaration against the context's capability ceiling and the user's granted permissions, then provides exactly what was requested.

```
App → Protocol:  "I need: messaging, member_list, outlet_call(outlet_a, outlet_b)"
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

### 8.4.1 Scope Boundary: SDK-Local, Not Protocol State

Capability scoping is enforced locally, by the member's own SDK. It produces no protocol state. An app runs on the member's device, under the member's identity, with the member's keys — so to the protocol, and to every other member of the context, an action taken by an app that a member has bound *is* an action by that member. There is no second principal, and therefore nothing to authenticate: an app has no DID, presents no signature, and is not a party to the context. This follows directly from §8.1 — an app is not a protocol entity.

- **No protocol record.** Binding or unbinding an app produces no event-log entry, no governance action, and no membership change. Which client software a member runs is that member's business, not a fact the context converges on — recording it would leak each member's software inventory to every peer and turn a local permission check into a consensus problem.
- **The member is accountable.** A declaration bounds what a member's own app can reach, never more than the context ceiling and the member's role already allow. It limits the blast radius of a badly generated client; it does not create a separate accountable actor, and a member cannot disclaim what their app did.

## 8.5 MCP Compatibility (Model Context Protocol)

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
│  - Exposes context outlets as MCP tool schemas        │
│  - Filters outlets by role + capability tokens          │
│  - Signs with #active or #agent from human's DID      │
│  - Encrypts/decrypts context envelopes                │
│  - Surfaces context events as MCP resources           │
└────────────────────┬─────────────────────────────────┘
                     │ SCP Protocol (encrypted, over transport)
                     │
┌────────────────────▼─────────────────────────────────┐
│  SCP Context [outlets, roles, members, governance]      │
└──────────────────────────────────────────────────────┘
```

The SCP agent is a translation layer: an MCP server from the model's perspective, an SCP protocol participant from the network's perspective. This separation has several consequences:

**Any MCP-compatible model participates in SCP without modification.** The model doesn't need to know about DIDs, capability tokens, encryption, or context governance. It sees tools. "Send a message" is a tool call. "Read recent messages" is a tool call. "Invoke the scheduling tool" is a tool call. The agent handles everything SCP-specific.

**SCP outlet schemas should use MCP's format.** If SCP defines its outlet interface using MCP-compatible JSON schemas, then SCP context outlets are natively MCP-compatible with zero translation. The agent passes outlet schemas through directly. This is a concrete design decision: SCP outlet definitions should be a superset of MCP tool definitions, adding SCP-specific metadata (context scope, capability requirements, provenance) while keeping the core schema MCP-compatible.

**Capability filtering happens at the agent.** MCP has no concept of access control — configured tools are available. SCP outlets are capability-gated by role. The agent resolves this by exposing only the outlets the human's role permits. Outlets the agent lacks capability for are never surfaced to the model — from the model's perspective, they don't exist.

```
Context outlets:             Admin's agent MCP surface:    Member's agent MCP surface:

  outlet_a (admin+)            outlet_a ✓                      (not exposed)
  outlet_b (member+)           outlet_b ✓                      outlet_b ✓
  outlet_c (member+)           outlet_c ✓                      outlet_c ✓
  outlet_d (observer+)         outlet_d ✓                      outlet_d ✓
```

**Multi-context as namespaced MCP tools.** A human in multiple contexts has their agent expose outlets from all contexts, namespaced by context. The model sees `context_a/send_message`, `context_b/schedule_meeting`. The agent routes each call to the right context, with the right tokens, over the right encrypted channel.

**MCP provides the local wiring. SCP provides the social infrastructure.** MCP solves "how does an AI model connect to tools on this machine." SCP solves "how do those outlets exist in a multi-party, trust-evaluated, persistent, access-controlled social space." MCP has no identity, trust, multi-party coordination, or persistence. SCP provides all of these. Together, they give any MCP-speaking model access to SCP's social infrastructure without either protocol needing to change.

**BYOA benefit.** "Bring your own agent" (§4.4) means users choose their own AI model. MCP compatibility means any MCP-speaking model works — Claude, GPT, Gemini, open-source local models, or anything future. The SCP agent handles protocol mechanics. The model handles reasoning. The user chooses both independently.
