# Getting Started

## Prerequisites

Install these manually before running setup:

- [Homebrew](https://brew.sh)
- [mise](https://mise.jdx.dev): `brew install mise`
- Xcode Command Line Tools: `xcode-select --install`

## Setup

```bash
git clone https://github.com/limn-works/scp.git
cd scp
./scripts/setup-toolchain.sh
```

This installs all language runtimes, Rust cross-compilation targets, cargo tools, and Android SDK/NDK via mise. Run `./scripts/setup-toolchain.sh --check` to verify without making changes.

After setup, activate mise in your shell:

```bash
eval "$(mise activate zsh --shims)"
```

Add this to `~/.zshenv` for persistence.

## Toolchain

All tools are managed by mise (see `.mise.toml`):

| Tool | Version |
|------|---------|
| Rust | stable (+ 10 cross-compilation targets) |
| Python | 3.12 |
| Bun | 1.3 |
| Kotlin | 2.3 |
| Gradle | 8.14 |
| Java | Zulu 17 |
| cargo-nextest, maturin, cargo-deny | latest |

**Never use npm or npx** -- this project uses bun exclusively for JS/TS.

## Build

```bash
# Rust core (all crates)
cargo build --workspace

# Python binding
cd bindings/python && maturin develop --release

# TypeScript binding
cd bindings/typescript && bun install && bun run build

# Kotlin binding
cd bindings/kotlin && ./gradlew assembleRelease

# Swift binding
cd bindings/swift && swift build
```

## Test

```bash
# All languages
./scripts/test.sh

# Single language
./scripts/test.sh rust
./scripts/test.sh python
./scripts/test.sh typescript
./scripts/test.sh kotlin
```

See [TESTING.md](TESTING.md) for details on per-language test setup, feature flags, and environment variables.

## Docker

Run a local relay and node:

```bash
docker-compose up
```

- Relay: `localhost:9000`
- Node: `localhost:9001`

## Project Structure

```
crates/              # Rust workspace -- the protocol core
  scp-core/          #   Protocol logic (context, crypto, governance, trust, sync)
  scp-identity/      #   DID, DHT, document, key management
  scp-transport/     #   Relay, adapters, blob storage
  scp-ffi/           #   FFI bridges (PyO3, UniFFI, NAPI)
  scp-relay/         #   Standalone relay binary
  scp-node/          #   Application node binary
  scp-testing/       #   Conformance macros, E2E tests
  ...                #   + scp-platform, scp-media, scp-event-log, scp-mcp

bindings/            # Language SDK wrappers
  python/            #   scp_sdk (wraps PyO3 bridge)
  typescript/        #   @limn-works/scp-ts (wraps NAPI bridge; browser = remote thin client)
  swift/             #   SCP Swift package (wraps UniFFI bridge)
  kotlin/            #   scp-kt (wraps UniFFI bridge)

.docs/               # Project knowledge
  specs/             #   Protocol specifications
  adrs/              #   Architecture Decision Records
  standards/         #   Coding and workflow standards
  architecture.md    #   Engineering blueprint
  sketch.md          #   API surface pseudocode
```

## Documentation

- **Protocol specs**: `.docs/specs/` -- modular, one file per topic area. Sufficient for independent implementation.
- **Architecture**: `.docs/architecture.md` -- component map, data flows, build phases.
- **API sketches**: `.docs/sketch.md` -- pseudocode for all protocol operations.
- **Design decisions**: `.docs/adrs/` -- rationale for every architectural choice.
- **Coding standards**: `.docs/standards/` -- per-language conventions (read before writing code).
- **Transport guides**: `docs/guides/` -- transport architecture and custom adapter implementation.
