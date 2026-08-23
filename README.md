# Shared Context Protocol (SCP)

**Open infrastructure for the agentic Internet.**

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

Three categories of protocol are relevant to agent infrastructure. SCP provides the connective tissue.

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
| TypeScript | napi-rs | Node / Bun (server, in-process); browser = in-tab wasm client, keys on-device (`@limn-works/scp-ts-wasm`, ADR-057) |
| Kotlin | UniFFI | Android |
| Rust | Native | Direct |

The SDK ships as two independent halves:

- **Client SDK** — identity management, context participation, encryption, transport. Everything an application needs to join and interact within contexts.
- **Server SDK** — relay operation, message routing, storage. Everything needed to run SCP infrastructure.

Any client connects to any conforming relay. Transport is fully abstracted behind an adapter trait.

## Further Reading

- **[White paper](.docs/white-paper.md)** — full protocol design paper (~12,000 words)
- **[Technical overview](.docs/technical-overview.md)** — deep dive on encryption, MLS, contexts, discovery, economics
- **[Thesis and lineage](.docs/thesis.md)** — motivation, intellectual lineage, prior art
- **[Protocol specification](.docs/specs/)** — normative spec files (CC-BY 4.0)
- **[Architecture decision records](.docs/adrs/)** — ADRs for all design decisions

## Development

### Prerequisites

Install these manually (one-time):

1. **Homebrew** — https://brew.sh
2. **mise** — `brew install mise` ([mise.jdx.dev](https://mise.jdx.dev))
3. **Xcode Command Line Tools** — `xcode-select --install`

Then activate mise in `~/.zshenv` (ensures availability in all shells, including non-interactive):

```sh
eval "$(mise activate zsh --shims)"
```

mise automatically manages environment variables (`JAVA_HOME`, `ANDROID_HOME`, `ANDROID_NDK_HOME`, `CARGO_TARGET_*_LINKER`) — no manual sourcing needed.

### Setup

```sh
mise install         # languages, Rust targets, cargo tools, npm globals
./scripts/setup-toolchain.sh   # Android SDK/NDK (the one thing mise can't do)
```

Both commands are idempotent — safe to re-run at any time. Together they install:

| Category | What | Manager |
|---|---|---|
| Languages | Java 17 (Zulu), Bun 1.3, Python 3.12, Kotlin 2.3 | mise (pinned in `.mise.toml`) |
| Rust | Rust 1.98.0 + 10 cross-compilation targets — the version `rust-toolchain.toml` pins, so a local build uses the compiler CI uses | mise (via rustup backend) |
| Cargo tools | cargo-nextest, maturin, cargo-deny | mise (cargo backend) |
| npm globals | @napi-rs/cli | mise (npm backend) |
| Android | SDK command-line tools, NDK 27.2 | sdkmanager (via Homebrew) |

Swift uses Xcode — not managed by mise.

If Homebrew-installed Kotlin or OpenJDK are detected, the setup script warns but does not remove them. mise takes precedence within the repo via `.mise.toml`.

### Verify

```sh
./scripts/setup-toolchain.sh --check
```

Reports the state of every tool without making changes. Exit code 0 = all good, 1 = something missing.

### Running the Relay

SCP provides two binary entrypoints for local development and testing:

| Binary | What | Use case |
|---|---|---|
| `scp-relay` | Bare relay server (dumb pipe) | Integration tests, transport-level testing |
| `scp-node` | Full application node (identity + relay + HTTP) | End-to-end tests, `.well-known/scp` discovery |

#### From source

```sh
# Bare relay — listens on 0.0.0.0:9000
cargo run --release -p scp-relay

# Full application node — requires SCP_NODE_DOMAIN
SCP_NODE_DOMAIN=localhost cargo run --release -p scp-node

# Relay-only mode via scp-node
cargo run --release -p scp-node -- --relay-only
```

#### With Docker

```sh
# Build the image (both binaries)
docker compose build

# Start bare relay (port 9000)
docker compose up relay

# Start full node (port 9001)
docker compose up node

# Or use the convenience script
./scripts/docker.sh relay up
./scripts/docker.sh node up
./scripts/docker.sh down
```

#### Health checks

Both binaries support `--health` for container health probes:

```sh
# From inside the container
scp-relay --health
scp-node --health
```

#### Environment variables

**Relay configuration** (both binaries):

| Variable | Default | Description |
|---|---|---|
| `SCP_RELAY_BIND_ADDR` | `0.0.0.0:9000` | Listen address |
| `SCP_RELAY_MAX_BLOB_SIZE` | `262144` | Max blob size (bytes) |
| `SCP_RELAY_MAX_BLOB_TTL` | `604800` | Max blob TTL (seconds) |
| `SCP_RELAY_MAX_CONNECTIONS` | `1000` | Max total connections |
| `SCP_RELAY_MAX_CONNECTIONS_PER_IP` | `10` | Max connections per IP |
| `SCP_RELAY_RATE_LIMIT` | `100` | Publishes/sec/IP |
| `SCP_RELAY_LOG_FORMAT` | `pretty` | `pretty` or `json` |
| `SCP_RELAY_LOG_LEVEL` | `info` | Default log level (`RUST_LOG` takes precedence) |

**Node-only configuration** (`scp-node` in full mode):

| Variable | Default | Description |
|---|---|---|
| `SCP_NODE_DOMAIN` | *(required)* | Domain for DID document and relay URL |
| `SCP_NODE_BIND_ADDR` | `0.0.0.0:9000` | HTTP listen address |
| `SCP_NODE_PROJECTION_RATE_LIMIT` | `60` | Per-IP rate limit (req/s) for broadcast projection endpoints |

## Fuzzing

SCP uses [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) (libFuzzer) to find parser panics,
serde edge cases, and deserialization vulnerabilities at every protocol trust boundary. Fuzzing runs
nightly in CI and accumulates a persistent corpus over time.

See [`fuzz/README.md`](fuzz/README.md) for the full target inventory, quick-start guide, crash
workflow, and corpus management instructions.

## License

SCP uses a split license designed for maximum adoption with infrastructure protection:

- **Protocol specification** — [CC-BY 4.0](https://creativecommons.org/licenses/by/4.0/). Freely implementable by anyone.
- **Client SDK and bindings** — [Apache 2.0](LICENSE-APACHE). Use in open or closed source, commercial or not.
- **Application node** (`scp-node`) — [AGPL v3 only](LICENSE-AGPL). Operators offering relay as a service share source or obtain a [commercial license](https://limn.works/licensing).

If you're building an app or agent, the SDK is Apache 2.0 — no copyleft, no friction. See [LICENSING.md](LICENSING.md) for the full structure, FAQ, and details.

Copyright [Limn](https://limn.works) Works LLC.
