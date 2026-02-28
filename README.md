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

Install these manually (one-time):

1. **Homebrew** — https://brew.sh
2. **asdf** — `brew install asdf` ([asdf-vm.com](https://asdf-vm.com))
3. **rustup** — https://rustup.rs
4. **Xcode Command Line Tools** — `xcode-select --install`

### Setup

```sh
./scripts/setup-toolchain.sh
```

The script is idempotent — safe to re-run at any time. It installs and configures:

| Category | What | Manager |
|---|---|---|
| Languages | Java 17 (Zulu), Bun 1.3, Python 3.12, Kotlin 2.3 | asdf (pinned in `.tool-versions`) |
| Rust targets | WASM, iOS, iOS Simulator, Android (4 arch), macOS universal | rustup |
| Cargo tools | cargo-nextest, wasm-pack, maturin, cargo-deny | cargo |
| Bun globals | @napi-rs/cli | bun |
| Android | SDK command-line tools, NDK 27.2 | sdkmanager (via Homebrew) |

Rust and Swift are **not** managed by asdf — they use their own canonical tooling (rustup and Xcode, respectively).

If Homebrew-installed Kotlin or OpenJDK are detected, the script warns but does not remove them. asdf takes precedence within the repo via `.tool-versions`.

### Environment

Add this to your shell profile (`~/.zshrc` or `~/.bashrc`):

```sh
source /path/to/scp/scripts/env.sh
```

This sets:
- `ANDROID_HOME` — auto-detected from `~/Library/Android/sdk` or `~/Android/Sdk`
- `ANDROID_NDK_HOME` — pinned NDK version under `ANDROID_HOME`
- `JAVA_HOME` — resolved from asdf
- `CARGO_TARGET_*_LINKER` — NDK clang linkers for all 4 Android architectures, so `cargo build --target aarch64-linux-android` works without extra flags

CI (`build-matrix.yml`) pins the same NDK version so local and CI builds match.

### Verify

```sh
./scripts/setup-toolchain.sh --check
```

Reports the state of every tool without making changes. Exit code 0 = all good, 1 = something missing.

## License

SCP uses a split license designed for maximum adoption with infrastructure protection:

- **Protocol specification** — [CC-BY 4.0](https://creativecommons.org/licenses/by/4.0/). Freely implementable by anyone.
- **Client SDK and bindings** — [Apache 2.0](LICENSE-APACHE). Use in open or closed source, commercial or not.
- **Application node** (`scp-node`) — [AGPL v3 only](LICENSE-AGPL). Operators offering relay as a service share source or obtain a [commercial license](https://limn.works/licensing).

If you're building an app or agent, the SDK is Apache 2.0 — no copyleft, no friction. See [LICENSING.md](LICENSING.md) for the full structure, FAQ, and details.

Copyright [Limn](https://limn.works) Works LLC.
