# Social Context Protocol (SCP)

**The social layer for an agentic web.**

Software is shifting from something crafted by hand into something manufactured on demand. Agents are building production-ready apps in hours, directed by engineers and consumers alike. Soon, most of the content and interactions on the Internet will be delivered via an endlessly rich and diverse range of apps whose source is contained entirely within the device they were generated on. As clients become ephemeral and highly personal, durable infrastructure for communication and persistence will become an increasingly necessary counterweight. And the tools for implementing this infrastructure need to be natively optimized for agents as both builders and first-class consumers alongside humans.

**What’s ready**
App generation, distribution, and hosting models are all falling into place. People are buying computers and renting servers exclusively to operate personal agents. App stores have already solved distribution. Content and social graphs already exist on the social networks of today.

**What’s missing**
Infrastructure that provides state, data, identity, trust, encryption, governance, provenance — the connective tissue between agents, apps, and the humans behind them. Two chat apps, built by different agents for different people on different devices, need to be able to connect.

**What SCP provides**
SCP is an open, ecosystem-agnostic protocol for this infrastructure layer. It provides trusted identity, end-to-end encryption, granular permissioning, governed interactions, and transparent provenance — without depending on any platform, data source, or central operator.

---

## How It Works

- All interaction happens inside **contexts**: encrypted spaces with declared membership, roles, tools, and governance, all visible before you join
- Membership is enforced by MLS group keys, not by whoever runs the server — relays store opaque blobs and can’t read any of it
- Every agent traces to a human DID, and every message carries verifiable provenance
- All agent actions are scoped to contexts, and agents can’t cross context boundaries freely
- No central operator required. The protocol runs over any transport

Contexts are the core primitive. Each one is an encrypted space that declares its governance model, roles, available tools, and capability ceiling upfront — you can inspect all of this before deciding to join. Membership and permissions are enforced by MLS group keys. Relays are untrusted infrastructure; they store and forward encrypted blobs without any ability to read, inspect, or verify the contents.

Each participant operates as a separate agent instance per context. A single human might participate in dozens of contexts, but isolation between them is absolute — information only crosses context boundaries through explicit, opt-in tool interfaces, and every cross-context call is recorded in a verifiable event log.

Identity is DID-based, and authorization uses UCANs — capability tokens that are cryptographically verifiable without a central authority. Together, the protocol can verify who you are and what you’re allowed to do without calling home to any server.

Encryption combines MLS for group forward secrecy with a sender-side AES-256 layer for selective readability within contexts. Each message passes through 14 independent security checkpoints between sender and recipient. Provenance is structural — every message, tool output, and cross-context data transfer carries verifiable origin metadata.

```
┌────────────────────────────────────────────────────────────┐
│  APPLICATIONS                                              │
│  Apps · Agent scripts · LLM-built clients                  │
│                                                            │
│  ════════════════════════════════════════════════════════  │
│                                                            │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  SCP SDK                                             │  │
│  │                                                      │  │
│  │  Public API (~30 methods)                            │  │
│  │  Python · Swift · TypeScript · Kotlin · Rust         │  │
│  │                                                      │  │
│  │  ┌────────────────────────────────────────────────┐  │  │
│  │  │  Protocol Engine (Rust)                        │  │  │
│  │  │  Context · Identity · Trust · Discovery        │  │  │
│  │  │                                                │  │  │
│  │  │  ┌──────────────────────────────────────────┐  │  │  │
│  │  │  │  Crypto: MLS · UCAN · Merkle trees       │  │  │  │
│  │  │  └──────────────────────────────────────────┘  │  │  │
│  │  └────────────────────────────────────────────────┘  │  │
│  │                                                      │  │
│  │  ┌────────────────────────────────────────────────┐  │  │
│  │  │  Adapters                                      │  │  │
│  │  │  Transport: SCP native · Nostr · Matrix ·      │  │  │
│  │  │    libp2p · Hyperswarm · WebSocket · +more     │  │  │
│  │  │  Platform: Keys · Storage · Push               │  │  │
│  │  │  Bridges: X · Bluesky · Discord                │  │  │
│  │  └────────────────────────────────────────────────┘  │  │
│  └──────────────────────────────────────────────────────┘  │
│                                                            │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  Infrastructure (existing, not owned)                │  │
│  │  SCP relays · Nostr relays · DHT · Hyperswarm ·      │  │
│  │  libp2p · Matrix homeservers                         │  │
│  └──────────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────────┘
```

## Why This Works

For decades, distributed networks have remained niche interests that generally don’t scale. The ones that get significant adoption typically end up being single-client anyway, with the creator as the primary operator. Adoption has never become viral mainly because most people — even the technically inclined — simply do not want to set up and manage a server.

As of 2026, the landscape has changed. All the barriers are disappearing. People still have little interest in the work of self-hosting, but they will become interested in the benefits. Choosing and paying hosting-as-a-service providers will become a mainstream headache the way streaming has, and people will question why they have to subscribe to have a computer to run code they already own, when they’ve got a perfectly good one in their own home.

Most importantly, people no longer need to do any of the work. Nearly anyone generating personal apps already has access to everything needed to provide service. As long as their agents can make use of a PC that’s powered on and has network access, the only missing piece is a protocol for social context, and SDKs for implementing it securely.

A whole class of networks that were previously unscalable due to friction are now primed to become the default model for the future of the internet.

## Where SCP Fits

Tool-level protocols like MCP, WebMCP, and UCP define how agents interact with tools and services. SCP operates one layer beneath — it handles identity, trust, and governance. An SCP agent can expose itself as an MCP server, use WebMCP tools in the browser, or transact through UCP, while SCP provides the social context underneath.

```
┌──────────────────────────────────────────────────────┐
│                    TOOL LEVEL                        │
│                                                      │
│  MCP       → model ↔ local tools                     │
│  WebMCP    → model ↔ web tools                       │
│  UCP       → agent ↔ commerce                        │
│                                                      │
│  How agents USE things.                              │
├──────────────────────────────────────────────────────┤
│                    SOCIAL LEVEL    ← SCP             │
│                                                      │
│  SCP       → agent ↔ agent ↔ human                   │
│              identity · trust · contexts ·           │
│              encryption · governance · provenance    │
│                                                      │
│  How agents RELATE to each other.                    │
└──────────────────────────────────────────────────────┘
```

## Principles

1. **Provenance everywhere.** All non-private data carries verifiable origin metadata. The absence of provenance is itself a signal.
2. **Human accountability.** Every agent traces to a human DID. Actions have consequences that persist across contexts.
3. **Context isolation.** All interaction happens within bounded contexts. Cross-context data flow is explicit and governed.
4. **Encryption-as-access-control.** MLS group keys enforce context membership. Relays are untrusted — the math enforces access.
5. **Legibility before opt-in.** Every context’s parameters are visible before joining. Informed consent is mechanical, not social.
6. **No operator required.** Every mechanism works without centralized infrastructure.
7. **Transport independence.** The protocol drives transport choice, not the reverse.
8. **Agents are participants, not enforcers.** The same rules apply whether you’re a sophisticated autonomous agent or a simple passthrough.
9. **Trust is contextual.** A function of identity, capability, context, and behavior — not a binary.

## Architecture

The protocol engine is written in Rust, with bindings targeting the ecosystems where agents and apps are being built:

| Binding | Technology | Target |
|---|---|---|
| Python | PyO3 | Agent ecosystem (LangChain, CrewAI, AutoGen) |
| Swift | UniFFI | iOS / macOS |
| TypeScript | wasm-bindgen | Web / Node |
| Kotlin | UniFFI | Android |
| Rust | Native | Direct |

The SDK ships as two independent halves. The **Client SDK** handles identity management, context participation, encryption, and transport — everything an application needs to join contexts. The **Server SDK** handles relay operation, message routing, and storage — everything needed to run SCP infrastructure. Any client can connect to any conforming relay; relay operators need no knowledge of client implementations.

Transport is fully abstracted behind an adapter trait. The SCP native relay is the canonical reference implementation, with adapters for Nostr, Matrix, libp2p, Hyperswarm, WebSocket/WebRTC, and more.

## Project Structure

```
scp/
└── .docs/
    ├── architecture.md  # Engineering blueprint
    ├── sketch.md        # API surface sketches
    ├── adrs/            # Architecture Decision Records (3 phases)
    ├── specs/           # Protocol specification (including open questions)
    ├── standards/       # Coding and workflow standards
    └── lessons/         # Evergreen learnings
```

## Contributing

SCP is being built in the open. The best way to get oriented:

1. **Start with the spec.** [`.docs/specs/`](.docs/specs/) is the protocol design — what SCP is and how it works. [`.docs/architecture.md`](.docs/architecture.md) is the engineering blueprint.
2. **Read the ADRs.** [`.docs/adrs/`](.docs/adrs/) covers all three build phases with full Architecture Decision Records.
3. **Weigh in on open questions.** [`.docs/specs/00-open-questions.md`](.docs/specs/00-open-questions.md) has design decisions that would benefit from more perspectives.

## License

TBD
