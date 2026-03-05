# 21. Documentation

## 21.1 Goal

An agent with no prior context should be able to visit the SCP repository, understand the protocol, build the project, use the SDK in any target language, run tests, and implement features or write a conforming implementation — without human guidance.

## 21.2 Status

### Done

- Protocol specification: modular spec files under `.docs/specs/`, covering all protocol areas
- ADRs: phase documents covering all architectural decisions
- Module-level code documentation: nearly all Rust source files have `//!` headers
- Trait contracts: documented with invariants and error conditions
- Standards: all SDK languages, error hierarchy, async patterns, CI tiers
- SDK binding READMEs: all binding directories have README files
- CI workflows: `ci.yml`, `build-matrix.yml`, `docs.yml`, `release.yml`, and supporting workflows
- Architecture reading guide: `docs/guides/architecture.md`
- Transport adapter guide: `docs/guides/transport-adapters.md`
- scp-mcp and scp-node module docs: all source files have `//!` headers
- Runnable Rust examples: relay chat/send/listen in `crates/scp-transport/examples/`
- SDK examples: Python, TypeScript, Swift, and Kotlin each have 4 runnable examples (basic messaging, tool invocation, MCP integration, multi-agent)
- Getting started guide: `GETTING-STARTED.md` at repo root
- Testing guide: `TESTING.md` at repo root

### Gaps
| Inline doc coverage | Struct fields, enum variants, constants under-documented | Field/variant-level `///` docs on public items | P1 |
| Generated API reference | None | Hosted rustdoc, typedoc, pdoc, DocC | P1 |
| Crate/FFI README files | None | README per crate and FFI bridge | P1 |
| Storage backend guide | None | `docs/guides/storage-backends.md` | P2 |
| Relay operator guide | None | `docs/guides/relay-operations.md` | P2 |
| Conformance testing guide | None | `docs/guides/conformance-testing.md` | P2 |
| Integration guides | None | "Add SCP to existing app" | P2 |
| SDK quickstart guide | None | Unified `docs/guides/sdk-quickstart.md` | P2 |
| Compliance documentation | None | Wire format reference, test vectors, conformance suite | P2 |

## 21.3 Documentation Architecture

```
README.md                        # What SCP is, capabilities, architecture, license
LICENSING.md                     # License structure and FAQ
GETTING-STARTED.md               ✓ exists
CONTRIBUTING.md                  # Branch naming, commits, testing, PR process, CLA
TESTING.md                       ✓ exists

docs/                            # Published documentation (agent-facing)
├── guides/
│   ├── architecture.md          ✓ exists
│   ├── sdk-quickstart.md
│   ├── transport-adapters.md    ✓ exists
│   ├── storage-backends.md
│   ├── relay-operations.md
│   └── conformance-testing.md
├── examples/
│   ├── python/
│   ├── typescript/
│   ├── swift/
│   └── rust/
└── api/                         # Generated API reference (rustdoc output, etc.)

scaffolds/                       # Clonable barebones project setups
├── rust-client/
├── python-agent/
├── typescript-web/
├── typescript-node/
├── swift-ios/
├── swift-macos/
├── kotlin-android/
└── relay/

templates/                       # Clonable working applications for common use cases
├── chat/
├── agent-tool-provider/
├── collaborative-workspace/
├── personal-relay/
├── broadcast-feed/
└── cross-context-bridge/

bindings/*/README.md             ✓ all exist
crates/scp-ffi/README.md
crates/scp-ffi/napi/README.md
crates/scp-ffi/wasm/README.md
crates/scp-ffi/uniffi/README.md

.docs/                           # Internal project knowledge (unchanged)
```

### Separation of concerns

- **`docs/`** is for consumers: agents and developers using SCP. Published, navigable, example-rich.
- **`.docs/`** is for contributors: protocol design, ADRs, standards, build blueprints. Internal.
- **Root files** (`GETTING-STARTED.md`, `TESTING.md`, `CONTRIBUTING.md`) are for everyone.
- **Binding READMEs** are the entry point for each language's SDK users.
- **Crate READMEs** are for maintainers of the FFI bridges.

## 21.4 P0: Getting Started

### GETTING-STARTED.md

Must answer in under 15 minutes of reading + doing:

1. **Prerequisites** — Rust toolchain version, platform requirements, optional deps for bindings
2. **Clone and build** — `git clone`, `cargo build`, expected output, expected time
3. **Run tests** — `cargo nextest run --workspace`, what success looks like
4. **Run the Phase 1 proof** — Two processes exchange encrypted messages, step by step
5. **Next steps** — Links to SDK quickstart, architecture guide, contributing guide

### Audience
An agent or developer who has never seen the repo. They should go from zero to "I built it and saw encrypted messages flow" in one sitting.

## 21.5 P0: SDK Binding READMEs

Each binding directory gets a README answering:

1. **What is this** — One sentence (e.g., "Python SDK for SCP, providing identity, contexts, encryption, and transport")
2. **Install** — `pip install scp-sdk` / SPM / npm
3. **Quickstart** — 10-20 lines of working code: create identity, create context, send message
4. **Platform notes** — Language-specific considerations (Python: async, Swift: Keychain/Secure Enclave, TypeScript: WASM vs NAPI)
5. **API overview** — Brief listing of main classes/modules with one-line descriptions
6. **Link to full docs** — Point to `docs/guides/sdk-quickstart.md` and generated API reference

### Template for each:
```markdown
# SCP SDK for {Language}

{One sentence description.}

## Install

{Package manager command.}

## Quickstart

{10-20 lines of working code.}

## Platform Notes

{Language-specific considerations.}

## API Overview

{Main classes/modules with one-line descriptions.}

## Documentation

- [SDK Quickstart Guide](../../docs/guides/sdk-quickstart.md)
- [API Reference](../../docs/api/)
- [Full Protocol Specification](../../.docs/specs/)
```

## 21.6 P0: Example Applications

Minimal, runnable examples in each target language demonstrating:

1. **Identity creation** — Create a DID, inspect it
2. **Context creation** — Create a context with governance parameters
3. **Message exchange** — Two participants send and receive encrypted messages
4. **Tool invocation** — Register and invoke a tool within a context

Each example should be:
- Self-contained (single file or minimal project)
- Runnable with one command
- Commented explaining each step
- Linked from the binding README

## 21.7 P0: Testing Guide

### TESTING.md

1. **Running tests** — Commands for Tier 1, 2, 3. What each tier covers.
2. **Writing unit tests** — Where tests live, naming convention, template
3. **Writing integration tests** — How to use the Phase 1/2/5 tests as templates
4. **Conformance macros** — How `transport_conformance!()`, `payment_adapter_conformance!()` work
5. **Property-based tests** — When required, how to use proptest
6. **Debugging failures** — Common error patterns, how to interpret output
7. **CI** — What runs on PR, merge, nightly. How to reproduce CI locally.

## 21.8 P1: Inline Documentation

### Targets

Public struct fields, enum variants, utility functions, and constants across all crates — especially `scp-core` — need field/variant-level `///` doc comments explaining contracts, valid ranges, and "why this value."

Priority modules (densest undocumented surface area):
1. `scp-core/src/context/` — context lifecycle, TTL, roles
2. `scp-core/src/economy/` — types, policy
3. `scp-core/src/discovery/` — context discovery, addressing

### FFI crate targets

All four FFI crates (`scp-ffi`, `napi`, `wasm`, `uniffi`) need README files explaining build process, architecture, and maintenance patterns.

## 21.9 P1: Architecture Navigation Guide

### docs/guides/architecture.md

Not a replacement for `.docs/architecture.md` — a reading guide for it:

1. **Start here** — The 5 concepts you need (contexts, DIDs, UCANs, MLS, relays)
2. **Crate map** — Which crate does what, dependency graph, where to find things
3. **Reading order** — Suggested path through specs and ADRs
4. **Key flows** — Context creation, message send, tool invocation (simplified, with file references)
5. **Glossary** — Protocol-specific terms with one-line definitions

## 21.10 P1: Generated API Reference

Set up `cargo doc` generation and hosting:

1. Ensure all public items have doc comments (see §21.8)
2. Add `#![doc = include_str!("../README.md")]` to each crate's `lib.rs`
3. Generate with `cargo doc --workspace --no-deps`
4. Host on GitHub Pages or similar
5. For TypeScript: generate with typedoc from WASM/NAPI bindings
6. For Python: generate from type stubs + docstrings
7. For Swift: generate with DocC from UniFFI output. DocC requires the compiled `ScpFFI.xcframework` binary target, so it runs as a post-step of the `swift-xcframework` job in `build-matrix.yml` (not in `docs.yml`). The `docs-swift` artifact is uploaded from that workflow.

## 21.11 P2: Implementation Guides

### Transport adapter guide (docs/guides/transport-adapters.md)
- What the `TransportAdapter` trait requires
- How to implement one (step by step with a concrete example)
- How to test with `transport_conformance!()`
- How to register with `TransportManager`

### Storage backend guide (docs/guides/storage-backends.md)
- What the `Storage` trait and `BlobStore` trait require
- How to implement (step by step)
- How to test with conformance macros
- Performance considerations

### Relay operations guide (docs/guides/relay-operations.md)
- How to build and run `scp-node`
- Configuration options
- Monitoring and health checks
- Upgrading
- TLS setup

### Conformance testing guide (docs/guides/conformance-testing.md)
- What conformance means in SCP
- How to use each conformance macro
- How to write a new conformance suite
- Relationship between conformance and the spec

## 21.12 Guides, Scaffolds, and Templates

Three categories of practical resources for agents and developers building with SCP, in ascending order of specificity:

### Guides (docs/guides/)

Step-by-step instructions for achieving specific outcomes. An agent follows a guide to learn how to do something.

**Examples:**
- "Build a transport adapter" — trait requirements, implementation steps, conformance testing
- "Add SCP to a LangChain agent" — install SDK, create identity, join context, wire to LangChain
- "Run a community relay" — build scp-node, configure TLS, set up monitoring
- "Implement blocking in a context" — sender key rotation, grace periods, verification

Guides are written for the reference implementation and reference specific files, types, and APIs. They are **instructional** — they teach a process.

### Scaffolds (scaffolds/)

Clonable, barebones project setups for generalized use cases. An agent clones a scaffold as a starting point and builds on top of it.

Each scaffold is a minimal, working project structure with:
- Package configuration (Cargo.toml, pyproject.toml, Package.swift, package.json, etc.)
- SCP SDK dependency wired up
- Placeholder identity creation and context joining
- Build and run instructions in a README
- No application logic — just the SCP integration skeleton

**Scaffold matrix:**

| Scaffold | Language | What it provides |
|---|---|---|
| `scaffolds/rust-client/` | Rust | Minimal Rust binary using scp-core directly |
| `scaffolds/python-agent/` | Python | Python agent with scp-sdk, async runtime, identity setup |
| `scaffolds/typescript-web/` | TypeScript | Browser app using WASM binding, identity in IndexedDB |
| `scaffolds/typescript-node/` | TypeScript | Node.js agent using NAPI binding |
| `scaffolds/swift-ios/` | Swift | iOS app with Keychain custody, push notifications |
| `scaffolds/swift-macos/` | Swift | macOS app with Secure Enclave custody |
| `scaffolds/kotlin-android/` | Kotlin | Android app with Keystore custody |
| `scaffolds/relay/` | Rust | Minimal relay setup with scp-node, TLS, monitoring |

Scaffolds are **structural** — they provide the right project shape so agents don't have to figure out package configuration, FFI wiring, or platform integration from scratch.

### Templates (templates/)

Clonable, fully-functional project setups for popular use cases. An agent clones a template and has a working application immediately — then customizes it.

Each template is a complete, running application that demonstrates a real use case:
- All SCP integration working end-to-end
- Application logic for the specific use case
- UI where applicable (or CLI for agent-facing tools)
- Tests covering the integration points
- README explaining what it does and how to customize it

**Template examples:**

| Template | Language(s) | What it is |
|---|---|---|
| `templates/chat/` | Python + TypeScript | Two-party encrypted chat (CLI + web) |
| `templates/agent-tool-provider/` | Python | Agent exposing tools via SCP context with MCP bridge |
| `templates/collaborative-workspace/` | TypeScript | Multi-party context with roles, tools, and governance |
| `templates/personal-relay/` | Rust | Self-hosted relay with automatic TLS and DID publishing |
| `templates/broadcast-feed/` | Python | Broadcast context (§5.14) with subscriber management |
| `templates/cross-context-bridge/` | Rust | Tool interface bridging two contexts (§6.2) |

Templates are **functional** — they solve a real problem out of the box. An agent studying a template understands not just how SCP works mechanically but how it's used to build real things.

### Relationship between the three

```
Guides          → "How do I do X?"          (learn a technique)
Scaffolds       → "Set me up to build X"     (start from the right shape)
Templates       → "Give me a working X"      (start from a working app)
```

An agent building something novel uses a **guide**. An agent building something common in an uncommon way uses a **scaffold**. An agent building something common in a common way uses a **template**.

## 21.13 Documentation Website

For public-facing documentation, a static site generated from `docs/`:

- **Tool:** mdBook, Docusaurus, or similar
- **Content:** Guides, examples, API reference, spec summaries
- **Audience:** Agent builders, relay operators, protocol implementers
- **Hosted at:** docs.limn.works or similar

This is P2 — the content in `docs/` is the priority. The website is presentation.

## 21.14 Compliance Documentation (Agent-Optimized)

For agents implementing SCP from the spec (not using the reference implementation):

1. **Protocol compliance checklist** — Every MUST/SHOULD/MAY from the spec, as a checkable list
2. **Wire format reference** — MessagePack schemas for all envelope types
3. **Cryptographic requirements** — Exact algorithms, parameters, key sizes, derivation paths
4. **Test vectors** — Known-good inputs and outputs for crypto operations
5. **Conformance test suite** — Language-independent test cases that any implementation must pass

This is P2 but important for the protocol's long-term goal of multiple independent implementations.
