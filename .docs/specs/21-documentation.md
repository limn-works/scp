# 21. Documentation

## 21.1 Goal

An agent with no prior context should be able to visit the SCP repository, understand the protocol, build the project, use the SDK in any target language, run tests, and implement features or write a conforming implementation — without human guidance.

## 21.2 Current State as of 12 Mar 2026

### Done

| # | Category | Artifact | Notes |
|---|----------|----------|-------|
| 1 | Protocol specification | 27 spec files, ~15,900 lines | §01–§26 covering all protocol areas |
| 2 | ADRs | 6 phase documents, ADR-001–ADR-039 | All architectural decisions recorded |
| 3 | Module-level Rust docs | 100% of Rust files have `//!` headers | All crates |
| 4 | Trait contracts | ~100% documented | Invariants and error conditions |
| 5 | Standards | `.docs/standards/` | 8 languages, error hierarchy, async patterns, CI tiers |
| 6 | Inline doc coverage | ~82–100% across all crates (lowest: scp-ffi-wasm ~82%) | See §21.8.1 coverage table |
| 7 | SDK binding READMEs | `bindings/{python,typescript,swift,kotlin}/README.md` | Install, quickstart, platform notes |
| 8 | Architecture guide | `docs/guides/architecture.md` | Reading guide with entry points |
| 9 | Transport adapter guide | `docs/guides/transport-adapters.md` | Trait requirements, step-by-step, conformance |
| 10 | Wire format tables | §9.5.2, §12.12, §19.15, §22.11, §23.16 | Signed structures, bridge, economy, discovery, sync |
| 11 | Protocol constants registry | §9.18 (16 subsections, ~100 constants) | Domain separators, key derivation labels, sizes, timeouts |
| 12 | Cryptographic test vectors | §25 (18 subsections) | All crypto operations; hex outputs pending (§25.18) |
| 13 | Conformance suite spec | §26 | Language-independent test case definitions |
| 14 | GovernanceAction table | §9.5.2 | All 28 variants with signed structure fields |
| 15 | ContextParams table | §9.5.2 | All 17 fields tabulated |
| 16 | Domain separators | §9.18.2 | 30 separators registered, code-verified |
| 17 | Key derivation labels | §9.18.3 | HPKE info, HKDF salt/info, HMAC domains, MLS exporter |
| 18 | Provenance system | §24 | Full specification with chain depth limits |
| 19 | README.md | Root | Protocol overview, capabilities, architecture |
| 20 | LICENSING.md | Root | License structure and FAQ |
| 21 | CI workflows | `.github/workflows/` | Build matrix, docs, release, security scanning |
| 22 | Getting started guide | `GETTING-STARTED.md` | Prerequisites, setup, build, test, project structure |
| 23 | Testing guide | `TESTING.md` | Per-language commands, feature flags, lint, conformance, CI matrix |
| 24 | Contributing guide | `CONTRIBUTING.md` | Workflow, commits, code style, artifact flow, PRD process |

### Gaps

| Category | Current | Target | Priority |
|---|---|---|---|
| ~~Getting started guide~~ | ~~None~~ | ~~`GETTING-STARTED.md`~~ | Done |
| ~~Testing guide~~ | ~~Commands in standards only~~ | ~~`TESTING.md`~~ | Done |
| ~~Contributing guide~~ | ~~None~~ | ~~`CONTRIBUTING.md`~~ | Done |
| Example applications | Pseudocode only | Runnable examples per language | P0 |
| FFI crate READMEs | In progress | `crates/scp-ffi/{src,napi,wasm,uniffi}/README.md` | P1 |
| Inline doc coverage | 82% (scp-ffi-wasm lowest) | 100% | P1 |
| Generated API reference | None | Hosted rustdoc, typedoc, Dokka, DocC | P1 |
| Remaining guides | 2 of 5 | Storage backends, relay ops, conformance testing | P2 |
| Test vector hex outputs | Spec complete, outputs pending | Run reference impl to generate §25.18 | P2 |
| Protocol compliance checklist | None | Extracted MUST/SHOULD/MAY from all specs | P2 |
| Scaffolds & templates | None | Clonable project setups per §21.12 | P2 |

## 21.3 Documentation Architecture

```
README.md                      ✓ What SCP is, capabilities, architecture, license
LICENSING.md                   ✓ License structure and FAQ
GETTING-STARTED.md             ✓ Prerequisites, setup, build, test, project structure
CONTRIBUTING.md                ✓ Workflow, commits, code style, artifact flow, PRD process
TESTING.md                     ✓ Per-language commands, feature flags, lint, conformance, CI matrix

docs/                            Published documentation (agent-facing)
├── guides/
│   ├── architecture.md        ✓ Reading guide: where to start, what to focus on
│   ├── sdk-quickstart.md        Unified quickstart (all languages)
│   ├── transport-adapters.md  ✓ How to implement a new transport adapter
│   ├── storage-backends.md      How to implement a new storage backend
│   ├── relay-operations.md      How to run, monitor, and upgrade a relay
│   └── conformance-testing.md   How to use conformance macros
├── examples/
│   ├── python/                  Working Python examples
│   ├── typescript/              Working TypeScript examples
│   ├── swift/                   Working Swift examples
│   └── rust/                    Working Rust examples
└── api/                         Generated API reference (rustdoc output, etc.)

scaffolds/                       Clonable barebones project setups
├── rust-client/                 Minimal Rust binary using scp-core
├── python-agent/                Python agent skeleton with async runtime
├── typescript-web/              Browser app with WASM binding
├── typescript-node/             Node.js agent with NAPI binding
├── swift-ios/                   iOS app with Keychain custody
├── swift-macos/                 macOS app with Secure Enclave custody
├── kotlin-android/              Android app with Keystore custody
└── relay/                       Minimal relay with scp-node, TLS, monitoring

templates/                       Clonable working applications for common use cases
├── chat/                        Two-party encrypted chat (CLI + web)
├── agent-tool-provider/         Agent exposing tools via SCP context + MCP
├── collaborative-workspace/     Multi-party context with roles and tools
├── personal-relay/              Self-hosted relay with auto-TLS
├── broadcast-feed/              Broadcast context with subscriber management
└── cross-context-bridge/        Tool interface bridging two contexts

bindings/python/README.md      ✓ Python SDK: install, quickstart, platform notes
bindings/swift/README.md       ✓ Swift SDK: install, quickstart, platform notes
bindings/typescript/README.md  ✓ TypeScript SDK: install, quickstart, platform notes
bindings/kotlin/README.md      ✓ Kotlin SDK: install, quickstart, platform notes

crates/scp-ffi/README.md        PyO3 bridge: build, architecture, for maintainers
crates/scp-ffi/napi/README.md    NAPI bridge: build, native addon compilation
crates/scp-ffi/wasm/README.md    WASM bridge: build, JS callback injection
crates/scp-ffi/uniffi/README.md  UniFFI bridge: build, XCFramework generation

.docs/                         ✓ Internal project knowledge (27 specs, ADRs, standards)
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
2. **Install** — `pip install scp-python` / SPM / npm
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

### 21.8.1 Enforcement

Every public crate MUST enable `#[warn(missing_docs)]` at the crate root (`lib.rs`). This produces compiler warnings for any public item without a doc comment. The long-term target is `#[deny(missing_docs)]` once coverage reaches 100%.

Crates and their enforcement status:

| Crate | `missing_docs` | Current Coverage | Target |
|---|---|---|---|
| `scp-core` | `warn` | ~98% | 100% |
| `scp-identity` | `warn` | ~97% | 100% |
| `scp-transport` | `warn` | ~98% | 100% |
| `scp-event-log` | `warn` | ~100% | 100% |
| `scp-platform` | `warn` | ~100% | 100% |
| `scp-media` | `warn` | ~100% | 100% |
| `scp-ffi` | not yet | ~99% | 100% |
| `scp-ffi-napi` | not yet | ~100% | 100% |
| `scp-ffi-uniffi` | not yet | ~100% | 100% |
| `scp-ffi-wasm` | not yet | ~82% | 100% |
| `scp-primitives` | `warn` | ~100% | 100% |
| `scp-testing` | not yet | ~90% | 100% |
| `scp-node` | `warn` | ~91% | 100% |
| `scp-mcp` | `warn` | ~100% | 100% |
| `scp-relay` | `warn` | ~100% | 100% |
| `scp-ffi-common` | not yet | ~90% | 100% |

### 21.8.2 Quality Standard

Each public item MUST have:

- **One-line summary** (`///` for items, `//!` for modules). Describes what the item is or does.
- **Parameter descriptions** for functions with non-obvious parameters. Use `# Arguments` section.
- **`# Errors`** section for any function returning `Result`, listing all error variants.
- **`# Panics`** section if the function can panic (even in debug builds).
- **`# Safety`** section for any `unsafe` code (SCP uses `#![forbid(unsafe_code)]` so this should not apply).
- **Spec cross-references** where the item implements a specific spec section. Format: `See §N.M in the SCP specification.`
- **Example usage** for key entry-point functions (identity creation, context operations, messaging, tool invocation). Use `# Examples` with ```` ```rust ```` code blocks that compile under `cargo test --doc`.

### 21.8.3 scp-core Documentation Targets

| Area | Gap | Items | Action |
|---|---|---|---|
| Struct fields | Most public fields undocumented | ~180 structs | Add field-level `///` docs |
| Enum variants | Large enums lack per-variant docs | ~92 enums | Add variant-level `///` docs |
| Utility functions | Helper functions undocumented | ~228 functions | Add `///` docs with contract |
| Constants | Magic numbers unexplained | ~70 constants | Add "why this value" docs referencing §9.18 |

Priority files (most undocumented items):
1. `src/context/mod.rs` (40 items)
2. `src/context/ttl.rs` (37 items)
3. `src/context/roles.rs` (24 items)
4. `src/economy/types.rs` (23 items)
5. `src/discovery/context.rs` (23 items)

### 21.8.4 Supporting Crate Targets

| Crate | Gap | Action |
|---|---|---|
| scp-mcp | `client.rs`, `stdio.rs`, `sse.rs` missing module docs | Add `//!` headers |
| scp-node | `http.rs`, `tls.rs`, `well_known.rs` missing module docs | Add `//!` headers |

### 21.8.5 FFI Crate Targets

All four FFI crates (`scp-ffi`, `napi`, `wasm`, `uniffi`) need README files explaining build process, architecture, and maintenance patterns.

### 21.8.6 Language Binding Documentation

Each language binding MUST have inline documentation equivalent to the Rust source:

| Language | Documentation System | Location | Standard |
|---|---|---|---|
| Python | Docstrings (PEP 257) | `bindings/python/scp_sdk/` | Every class and public method has a docstring. |
| TypeScript | TSDoc comments | `bindings/typescript/src/` | Every exported type and function has `/** */` comments. |
| Swift | Swift doc comments | `bindings/swift/Sources/` | Every public type and method has `///` comments. |
| Kotlin | KDoc comments | `bindings/kotlin/` | Every public class and function has `/** */` comments. |

Binding documentation SHOULD reference the corresponding Rust type/function and spec section where applicable.

## 21.9 P1: Architecture Navigation Guide

### docs/guides/architecture.md

Not a replacement for `.docs/architecture.md` — a reading guide for it:

1. **Start here** — The 5 concepts you need (contexts, DIDs, UCANs, MLS, relays)
2. **Crate map** — Which crate does what, dependency graph, where to find things
3. **Reading order** — Suggested path through specs and ADRs
4. **Key flows** — Context creation, message send, tool invocation (simplified, with file references)
5. **Glossary** — Protocol-specific terms with one-line definitions

## 21.10 P1: Generated API Reference

### 21.10.1 Requirements

1. `cargo doc --workspace --no-deps` MUST produce warning-free output.
2. CI generates docs on each merge to `main` (`.github/workflows/docs.yml`).
3. Docs published to GitHub Pages on each release tag.
4. Cross-crate links resolve correctly in rustdoc output (scp-core -> scp-identity, etc.).
5. Each language binding has generated API reference alongside Rust docs.

### 21.10.2 Rust (rustdoc)

1. Add `#![doc = include_str!("../README.md")]` to each crate's `lib.rs` so the crate-level doc page shows the README.
2. Generate with `cargo doc --workspace --no-deps --document-private-items`.
3. Cross-crate links use `[`item`](crate_name::path::to::item)` syntax.
4. The `docs.yml` CI workflow already builds rustdoc and uploads as artifact.
5. On release tags, docs are deployed to GitHub Pages.

### 21.10.3 Python (Sphinx)

1. Ensure all classes and functions in `bindings/python/scp_sdk/` have PEP 257 docstrings.
2. Generate with Sphinx (autodoc + napoleon) from `bindings/python/docs/`.
3. Requires `conf.py` in `bindings/python/docs/` — create if missing.
4. The `docs.yml` CI workflow already has a Python docs job.

### 21.10.4 TypeScript (TypeDoc)

1. Ensure all exported types and functions in `bindings/typescript/src/` have TSDoc comments.
2. Generate with TypeDoc from `bindings/typescript/`.
3. Requires `typedoc.json` configuration — create if missing.
4. The `docs.yml` CI workflow already has a TypeScript docs job.
5. Note: CI currently uses `npm install` for typedoc — should be updated to use `bun` per project standards.

### 21.10.5 Kotlin (Dokka)

1. Ensure all public classes and functions in `bindings/kotlin/` have KDoc comments.
2. Generate with Dokka via `./gradlew dokkaHtml`.
3. Requires Dokka plugin in `build.gradle.kts` — add if missing.
4. The `docs.yml` CI workflow already has a Kotlin docs job.

### 21.10.6 Swift (DocC)

1. Ensure all public types and methods have `///` Swift doc comments.
2. Generate with DocC from the compiled `ScpFFI.xcframework` binary target.
3. DocC generation runs as a post-step of the `swift-xcframework` job in `build-matrix.yml` (not in `docs.yml`), because it requires the compiled framework binary.
4. The `docs-swift` artifact is uploaded from that workflow.

### 21.10.7 Aggregate Documentation Site

All generated docs are aggregated into a single site deployed to GitHub Pages:

```
site/
├── index.html          # Landing page with links to all language docs
├── docs-rust/          # rustdoc output (scp_core, scp_identity, etc.)
├── docs-python/        # Sphinx HTML output
├── docs-typescript/    # TypeDoc HTML output
├── docs-kotlin/        # Dokka HTML output
└── docs-swift/         # DocC archive (when available)
```

The `publish-docs` job in `docs.yml` handles aggregation and deployment.

### 21.10.8 Local Documentation Generation

Developers and agents can generate docs locally:

```bash
# Rust
cargo doc --workspace --no-deps --open

# Python (requires sphinx, furo, sphinx-autodoc-typehints)
cd bindings/python && sphinx-build -b html docs docs/_build/html

# TypeScript (requires typedoc)
cd bindings/typescript && bun run typedoc

# Kotlin (requires Dokka gradle plugin)
cd bindings/kotlin && ./gradlew dokkaHtml
```

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
| `scaffolds/python-agent/` | Python | Python agent with scp-python, async runtime, identity setup |
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

1. **Protocol compliance checklist** — Every MUST/SHOULD/MAY from the spec, as a checkable list.
2. **Wire format reference** — Field-by-field tables for all types that cross the network. Covered in: §12.12 (bridge), §19.15 (economy), §22.11 (discovery). Envelope types in §9.5.2. Sync in §23.16.
3. **Cryptographic requirements** — Exact algorithms, parameters, key sizes, derivation paths. Covered in §9.5 (primitives) and §9.18 (constants registry, 16 subsections, ~100 constants).
4. **Test vectors** — Known-good inputs and outputs for crypto operations. Covered in §25 (cryptographic test vectors).
5. **Conformance test suite** — Language-independent test cases that any implementation must pass. Covered in §26 (conformance suite).

This documentation set is now substantially complete as of March 2026. The remaining work is:
- Generating exact hex outputs for all test vectors by running the reference implementation (§25.18).
- Creating the protocol compliance checklist (mechanical extraction from spec MUST/SHOULD/MAY statements).

## 21.15 Protocol Spec as Standalone Specification

**Completeness criterion:** an independent team should be able to implement a conforming SCP stack from `.docs/specs/` alone, without reading the Rust reference implementation source code.

This requires that every protocol-level behavior is specified with enough precision for interoperable implementation:

| Area | Spec Coverage | Status |
|------|---------------|--------|
| Identity (DID, keys, migration) | §3, §9.5, §9.11, §9.12 | Complete |
| Contexts (creation, lifecycle, params) | §5 | Complete |
| Cross-context communication | §6 | Complete |
| Trust and capabilities (UCAN, attestations) | §7, §9.8 | Complete |
| Cryptographic constructions | §9.5.1 (canonical hash), §9.5.2 (signed structures) | Complete |
| Envelope wire formats | §9.5.2 (inner/outer/broadcast), §9.10 (padding/chunking) | Complete |
| Sender key layer | §9.16 | Complete |
| Access key layer (content access control) | §9.17 | Complete |
| MLS group management | §9.7 | Complete |
| Protocol constants | §9.18 (16 subsections, ~100 constants) | Complete |
| Relay wire protocol | §10.5 | Complete |
| Bridge connectors | §12 | Complete |
| Governance | §5.6, §9.5.2 (28 GovernanceAction variants) | Complete |
| Sync and offline recovery | §23, §23.16 (wire formats) | Complete |
| Discovery and addressing | §22, §22.11 (wire formats) | Complete |
| Economy | §19, §19.15 (wire formats) | Complete |
| Provenance | §24 | Complete |
| Test vectors | §25 | Spec complete; hex outputs pending (§25.18) |
| Conformance suite | §26 | Complete |
| Versioning and evolution | §13 | Complete |

**Remaining gaps for full standalone implementability:**
1. Test vector hex outputs — §25.18 requires running the reference implementation to generate known-good byte sequences for each cryptographic operation.
2. Protocol compliance checklist — mechanical extraction of all MUST/SHOULD/MAY requirements into a checkable format.
