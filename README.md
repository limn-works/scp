# Social Context Protocol (SCP)

**The social layer for an agentic web.**

Software is shifting from something crafted by hand into something manufactured on demand. Agents are building production-ready apps in hours, directed by engineers and consumers alike. Soon, most of the content and interactions on the internet will be delivered via an endlessly rich and diverse range of apps, the code for which will be contained entirely on the device they were generated with. When clients are ephemeral and personal, durable infrastructure for communication and persistence become an necessary counterweight. Tools for implementing this infrastructure need to be natively optimized for agents as both builders and first-class consumers alongside humans.

**What’s already in place**
App generation, distribution, and hosting models. People are buying computers and renting servers exclusively to operate personal agents. App stores have already solved distribution. Content and social graphs already exist on the social networks of today.

**What’s missing**
Infrastructure that provides state, data, identity, trust, transport, encryption, governance, provenance — the connective tissue between agents, apps, and the humans behind them. Two chat apps, built by different agents for different people on different devices, need to be able to connect.

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

Encryption combines MLS for group forward secrecy with a sender-side AES-256 layer for selective readability within contexts. Each message is signed, encrypted twice, padded, pseudonymized on send, then verified, decrypted, checked for replay, validated against capability tokens, and authenticated on receive. Provenance is structural — every message, tool output, and cross-context data transfer carries verifiable origin metadata.

```
  Applications — apps, agent scripts, LLM-built clients
        ↕
  Client SDK — identity, contexts, encryption, transport
  Server SDK — relay operation, message routing, storage
        ↕
  Protocol Engine (Rust) — contexts, identity, trust, discovery
        ↕
  Crypto — MLS · UCAN · Merkle trees
        ↕
  Transport — SCP relay, Nostr, Matrix, libp2p, WebSocket, +more
```

## Why This Works

Distributed network protocols have historically remained niche because most people — even the technically inclined — simply do not want to set up and manage a server.

As of 2026, the landscape has changed. All the barriers are disappearing. People still have little interest in the work of self-hosting, but they will become interested in the benefits. Choosing and paying hosting-as-a-service providers will become a mainstream headache the way streaming has, and people will question why they have to subscribe to have a computer to run code they already own, when they’ve got a perfectly good one in their own home.

Most importantly, people no longer need to do any of the work. Nearly anyone generating personal apps already has access to everything needed to provide service. As long as their agents can make use of a PC that’s powered on and has network access, the only missing piece is a protocol for social context, and SDKs for implementing it securely.

A whole class of networks that were previously unscalable due to friction are now primed to become the default model for the future of the internet.

## Where SCP Fits

Three categories of protocol are relevant to agent infrastructure. SCP is the only one that provides the social layer.

|  | Tool protocols | Relay protocols | SCP |
|---|---|---|---|
| **Examples** | MCP, WebMCP, UCP | Nostr, AT Protocol, Matrix | — |
| **What it does** | Agent ↔ tools and services | Message delivery and storage | Identity, trust, encryption, governance, provenance |
| **Identity** | None | Platform accounts or keypairs | Cryptographic (DID), human-bound, portable |
| **Encryption** | Transport only | Optional or server-side | End-to-end per context (MLS), relays see nothing |
| **Trust** | Implicit | Follow/block, server moderation | Four-layer model: protocol → behavioral → attestation → contextual |
| **Governance** | None | Server operator rules | Per-context, declared upfront, cryptographically enforced |
| **Provenance** | None | None | Structural — every message carries verifiable origin |
| **Transport** | Local or HTTP | Own relay network | Any — SCP relay, Nostr, Matrix, libp2p, WebSocket, +more |

**Tool protocols** define how agents use tools. SCP complements them — an SCP agent can expose itself as an MCP server or transact through UCP while SCP provides the identity and trust underneath.

**Relay protocols** move messages. SCP can use them as transport adapters while adding what they lack: verifiable identity, end-to-end encryption where relays are untrusted, governed interaction spaces, and provenance on every piece of data that crosses a boundary.

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
