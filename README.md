# Shareable Context Protocol (SCP)

**The social layer for an agentic web.**

SCP is an open protocol that gives agents and apps the connective tissue they're missing: identity, encryption, granular authorization, governance, and provenance. No platform dependency, no central operator, all self-hostable and easily adoptable with a reference implementation and full stack SDKs.

## What SCP Provides

| Capability | How |
|---|---|
| **Identity** | DID-based, human-bound, portable across apps and devices |
| **Encryption** | E2E, MLS group keys per context — relays are untrusted and see nothing |
| **Authorization** | UCANs — capability tokens verified without a central authority |
| **Governance** | Per-context rules (roles, tools, capabilities) declared upfront, visible before joining |
| **Provenance** | Every message, tool output, and data transfer carries verifiable origin |
| **Transport** | Any — SCP relay, Nostr, Matrix, libp2p, WebSocket, and more |

## Core Concepts

All interaction happens inside **contexts** — encrypted spaces with declared membership, roles, tools, and governance. Contexts are the security boundary. Information only crosses context boundaries through explicit, governed interfaces.

**Relays are untrusted.** They store and forward encrypted blobs. Membership is enforced by MLS group keys, not by whoever runs the server.

**Every agent can trace to a human.** Identity is cryptographic (DID), and authorization uses capability tokens (UCAN) that are verifiable without calling home to any server. The protocol provides the mechanism for human accountability — contexts decide whether to require it.

**No operator required.** The protocol works without centralized infrastructure. If Limn disappears, SCP works exactly as designed.

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

## Where SCP Fits

Three categories of protocol are relevant to agent infrastructure. SCP provides the social layer.

|  | Tool protocols | Relay protocols | SCP |
|---|---|---|---|
| **Examples** | MCP, WebMCP, UCP | Nostr, AT Protocol, Matrix | — |
| **What it does** | Agent ↔ tools and services | Message delivery and storage | Identity, trust, encryption, governance, provenance |
| **Identity** | None | Platform accounts or keypairs | Cryptographic (DID), human-bound, portable |
| **Encryption** | Transport only | Optional or server-side | End-to-end per context (MLS), relays see nothing |
| **Trust** | Implicit | Follow/block, server moderation | Protocol → behavioral → attestation → contextual |
| **Governance** | None | Server operator rules | Per-context, declared upfront, cryptographically enforced |
| **Provenance** | None | None | Structural — every message carries verifiable origin |
| **Transport** | Local or HTTP | Own relay network | Any — SCP relay, Nostr, Matrix, libp2p, WebSocket, +more |

SCP complements tool protocols — an SCP agent can expose itself as an MCP server while SCP provides identity and trust underneath. SCP can use relay protocols as transport adapters while adding what they lack.

## Architecture

The protocol engine is Rust, with bindings for the ecosystems where agents and apps are being built:

| Binding | Technology | Target |
|---|---|---|
| Python | PyO3 | Agent ecosystem (LangChain, CrewAI, AutoGen) |
| Swift | UniFFI | iOS / macOS |
| TypeScript | wasm-bindgen | Web / Node |
| Kotlin | UniFFI | Android |
| Rust | Native | Direct |

The SDK ships as two independent halves:

- **Client SDK** — identity management, context participation, encryption, transport. Everything an application needs to join and interact within contexts.
- **Server SDK** — relay operation, message routing, storage. Everything needed to run SCP infrastructure.

Any client connects to any conforming relay. Transport is fully abstracted behind an adapter trait.

## Why Now

Software is shifting from something crafted by hand into something manufactured on demand. Agents are building production-ready apps in hours — work that would have taken teams weeks. The trajectory points toward a world where most software is ephemeral, personal, and generated on-device. App generation is becoming trivial. What remains hard is the connective tissue between these clients and the humans and agents using them: identity, trust, relationships, and accountability.

Distributed protocols have historically stayed niche because nobody wants to manage a server. That constraint is dissolving. People generating personal apps already have access to everything needed to provide service — a computer that's powered on with network access. Their agents handle the rest. A whole class of networks that were previously unscalable due to friction are now primed to become the default model.

Without a strong, open protocol for shareable context, the result is fragmented apps saved only by monolithic solutions from established platforms. SCP is the open, functional answer — no opinions, easy adoption, collective contribution, and unlimited integration.

## Development

### Prerequisites

Install these manually first (one-time):

- [Homebrew](https://brew.sh)
- [asdf](https://asdf-vm.com) — `brew install asdf`
- [rustup](https://rustup.rs)
- Xcode Command Line Tools — `xcode-select --install`

### Quick start

```sh
./scripts/setup-toolchain.sh
```

This installs and configures:
- **Java 17** (Zulu), **Bun 1.3**, **Python 3.12**, **Kotlin 2.3** via asdf
- Rust cross-compilation targets (WASM, iOS, Android, macOS universal)
- Cargo tools (nextest, wasm-pack, maturin, cargo-deny)
- Android SDK + NDK 27.2

### Environment

Source the generated env file in your shell profile:

```sh
# Add to ~/.zshrc or ~/.bashrc
source /path/to/scp/scripts/env.sh
```

This sets `ANDROID_HOME`, `ANDROID_NDK_HOME`, `JAVA_HOME`, and Cargo linker vars for Android cross-compilation.

### Verify

```sh
./scripts/setup-toolchain.sh --check
```

## License

SCP uses a split license designed for maximum adoption with infrastructure protection:

- **Protocol specification** — [CC-BY 4.0](https://creativecommons.org/licenses/by/4.0/). Freely implementable by anyone.
- **Client SDK and bindings** — [Apache 2.0](LICENSE-APACHE). Use in open or closed source, commercial or not.
- **Application node** (`scp-node`) — [AGPL v3 only](LICENSE-AGPL). Operators offering relay as a service share source or obtain a [commercial license](https://limn.works/licensing).

If you're building an app or agent, the SDK is Apache 2.0 — no copyleft, no friction. See [LICENSING.md](LICENSING.md) for the full structure, FAQ, and details.

Copyright [Limn](https://limn.works) Works LLC.
