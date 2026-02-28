# 1. Thesis

App generation is becoming trivial. Clients and server logic will be generated on-demand from simple prompts — personalized, ephemeral, disposable. What remains hard is the connective tissue: identity, social relationships, transport, persistence, and trust. This protocol is that connective tissue — an open, ecosystem-agnostic infrastructure layer that sits beneath any generated or traditional application.

The protocol is designed for a world where:

- Apps are disposable; infrastructure is not.
- Agents are the primary actors, not humans operating through clients.
- The gap between self-hosting and managed infrastructure is negligible.
- The big 3 (Apple, Google, Meta) will build closed versions of this. This is the open alternative.

## Core Principles

1. **Identity.** Every actor has a cryptographically verifiable identity (DID). Actions trace to identities. Identities trace to humans.
2. **Context isolation.** All interaction happens within contexts. Agents are separate instances per context. Cross-context data flow is explicit and governed.
3. **Provenance.** All non-private data carries verifiable origin metadata. Every message, tool output, attestation, and cross-context data transfer is traceable to its source. Provenance is not a feature — it is a foundational property of every protocol action. The absence of provenance on data is itself a signal ("this has no verified origin"). Provenance enables Sybil detection, governance enforcement, trust evaluation, and accountability.
4. **Encryption-as-access-control.** Context membership is enforced cryptographically. If you don't have the key, you can't read the data. No relay or intermediary enforces access — the math does.
5. **Legibility before opt-in.** Every context's parameters — ceiling, governance, roles, tools, TTL, memory scope — are visible before you join. No hidden terms.
6. **Human accountability.** Every agent can be traced to a human DID through attestation and delegation chains. The protocol provides the mechanism; contexts decide the requirement. Unattested DIDs are valid protocol participants. Contexts requiring verified-human attestation enforce traceability. Behavioral records attach to DIDs and are durable — actions have consequences that persist across contexts.

## Strategy: SDK-First, Not App-First

### Why SDK-First

The original plan was app-first: build a specific application, extract the protocol. That plan is wrong. The evidence:

- **Moltbook** (Jan 2026): 2.6 million agents in one month. Demand for agent social infrastructure is massive and proven.
- **OpenClaw**: Agents coordinating outside governed channels because no governed path exists.
- **The competitive window**: MCP (Anthropic), WebMCP (Google+Microsoft), and UCP (Google+Shopify) are all tool-level protocols. Nobody is building the social layer. The window is open but closing.

Agents ARE the killer app. The demand exists. Someone will build the killer app on top of SCP if the SDK is available. Apps are built on the SDK simultaneously — they validate the SDK surface and prove the "app on SCP" story, but don't gate SDK release.

### What SDK-First Means

1. **Ship the SDK before shipping any app.** `pip install scp-sdk` and `npm install @scp/sdk` are the first deliverables.
2. **Python bindings are critical.** The agent ecosystem (LangChain, CrewAI, AutoGen, custom agents) is overwhelmingly Python. If agents can't `import scp`, the protocol doesn't exist to them.
3. **Open source everything in months 2-3.** Spec (CC-BY 4.0), SDK (Apache 2.0), relay (AGPL v3). See §20 for full license structure.
4. **Target agent builders, not app builders.** The first users are people building agents that need to interact with other agents. The second users are app developers building agent-native applications.
5. **First-party apps are built on the SDK simultaneously** — they validate the SDK surface and prove the "app on SCP" story, but don't block SDK release.

### The Competitive Landscape

```
┌──────────────────────────────────────────────────────────┐
│                    TOOL LEVEL                             │
│                                                          │
│  MCP         → model ↔ local tools (JSON-RPC, stdio)    │
│  WebMCP      → model ↔ web tools (navigator.modelContext)│
│  UCP         → agent ↔ commerce (checkout, orders)       │
│                                                          │
│  These define how agents USE things.                     │
├──────────────────────────────────────────────────────────┤
│                    SOCIAL LEVEL   ← SCP fills this gap   │
│                                                          │
│  SCP         → agent ↔ agent ↔ human                    │
│               identity, trust, contexts, encryption,     │
│               governance, provenance, discovery          │
│                                                          │
│  This defines how agents RELATE to each other.           │
└──────────────────────────────────────────────────────────┘
```

MCP, WebMCP, and UCP are complementary to SCP, not competitors. An SCP agent exposes itself as an MCP server locally. An SCP agent can use WebMCP-exposed tools in the browser. An SCP agent can transact via UCP. SCP provides the identity, trust, and shareable context that none of these protocols address.
