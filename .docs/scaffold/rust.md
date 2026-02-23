# Rust Scaffold

> Source of truth: .docs/specs/, .docs/sketch.md, .docs/adrs/. This file is downstream of those documents.

Build blueprint for the SCP Rust core crates: workspace layout, dependency map, and error type definitions. See `.docs/standards/rust.md` for coding standards (safety rules, linting, formatting, testing, CI).

## Workspace Layout

```
Cargo.toml                  # Workspace root
crates/
  scp-core/
    Cargo.toml
    src/
      lib.rs
      crypto/
        mod.rs
        mls/                # ADR-001: MLS wrapper
        sender_keys/        # ADR-007: Sender-side key layer
        ucan/               # ADR-009/016: UCAN validation
      identity/             # ADR-003: DID creation
      envelope/             # ADR-002: Envelope format
      context/              # ADR-008: Context lifecycle
        tools/              # ADR-010: Tool registration/invocation
        roles.rs            # ADR-009: Role assignment
      event_log/            # ADR-011: Verifiable Merkle event log
      clock.rs              # Clock trait + SystemClock (§16.3)
  scp-transport/
    Cargo.toml
    src/
      lib.rs
      trait.rs              # ADR-005: TransportAdapter trait
      manager.rs            # ADR-012: Multi-transport routing
      native/               # ADR-004: SCP native relay
        blob_store.rs       # BlobStore trait (§16.4.1) — relay storage abstraction
  scp-testing/              # §16: Network simulation test harness (dev-dependency only)
    Cargo.toml
    src/
      lib.rs
      clock.rs              # SimulatedClock (§16.3)
      relay/                # InMemoryRelay, InMemoryBlobStore, BehaviorMode
        mod.rs
        blob_store.rs       # InMemoryBlobStore (§16.4.2)
        behavior.rs         # BehaviorMode enum, fault injection configs (§16.4.4)
        subscription.rs     # SubscriptionRegistry (§16.4.5)
      transport.rs          # InMemoryTransport — TransportAdapter impl (§16.5)
      simulator/            # NetworkSimulator, topology, fault injection
        mod.rs              # NetworkSimulator (§16.8)
        identity.rs         # SimulatedIdentity (§16.6)
        topology.rs         # NetworkTopology, LinkConfig (§16.7)
      builder.rs            # ScenarioBuilder (§16.9)
      assertions/           # Distributed invariant checks (§16.10)
        mod.rs
        merkle.rs           # assert_consistent_merkle_roots
        delivery.rs         # assert_complete_delivery
        suppression.rs      # assert_suppression_detected
        ordering.rs         # assert_correct_ordering
        privacy.rs          # assert_pseudonym_unlinkability
        blocking.rs         # assert_block_enforced
        epoch.rs            # assert_epoch_consistency
      presets.rs            # Canned scenarios (§16.11)
      conformance/          # Trait conformance test generators (§16.12)
        mod.rs
        transport.rs        # transport_conformance!()
        storage.rs          # storage_conformance!()
        key_custody.rs      # key_custody_conformance!()
        attestation.rs      # attestation_conformance!()
        push.rs             # push_conformance!()
        blob_store.rs       # blob_store_conformance!()
  scp-platform/
    Cargo.toml
    src/
      lib.rs
      trait.rs              # Platform abstraction traits
      testing/              # ADR-006: In-memory testing adapters
  scp-mcp/
    Cargo.toml
    src/
      lib.rs
      server.rs             # ADR-015: MCP server
      client.rs             # ADR-015: MCP client
      protocol.rs           # JSON-RPC types
      stdio.rs              # stdio transport
      sse.rs                # SSE transport
      namespace.rs          # Context namespace parsing
  scp-ffi/
    pyo3/                   # ADR-013: PyO3 bridge
      Cargo.toml
      src/
        lib.rs
        identity.rs
        context.rs
        tools.rs
        transport.rs
        ucan.rs
        event_log.rs
        error.rs
        types.rs
    uniffi/                 # Swift + Kotlin FFI
      Cargo.toml
      src/
        lib.rs
        scp.udl             # UniFFI definition file
    cbindgen/               # C ABI -> Go, C#, Java
      Cargo.toml
      src/
        lib.rs
      cbindgen.toml
    wasm/                   # Browser TypeScript
      Cargo.toml
      src/
        lib.rs
    napi/                   # Node/Bun TypeScript
      Cargo.toml
      src/
        lib.rs
```

## Workspace Cargo.toml

```toml
[workspace]
resolver = "2"
members = [
    "crates/scp-core",
    "crates/scp-transport",
    "crates/scp-platform",
    "crates/scp-mcp",
    "crates/scp-ffi/pyo3",
    "crates/scp-ffi/uniffi",
    "crates/scp-ffi/cbindgen",
    "crates/scp-ffi/wasm",
    "crates/scp-ffi/napi",
    "crates/scp-testing",
]

[workspace.package]
edition = "2024"
license = "MIT OR Apache-2.0"
repository = "https://github.com/limn/scp"

[workspace.dependencies]
openmls = "latest stable"
tokio = { version = "1", features = ["full"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
thiserror = "2"
ed25519-dalek = { version = "2", features = ["rand_core"] }
pkarr = "5"
z-base-32 = "0.1"
sha2 = "0.10"
hkdf = "0.12"
aes-gcm = "0.10"
rand = "0.8"
futures = "0.3"
tracing = "0.1"
tracing-subscriber = "0.3"
```

## Core Dependencies

| Crate | Version | Used in | Purpose |
|-------|---------|---------|---------|
| `openmls` | latest stable | scp-core | MLS implementation (ADR-001) |
| `ed25519-dalek` | 2.x | scp-core, scp-platform | Ed25519 signing/verification |
| `sha2` | 0.10.x | scp-core | SHA-256 hashing (envelopes, event log) |
| `hkdf` | 0.12.x | scp-core | HKDF pseudonym derivation (ADR-002) |
| `aes-gcm` | 0.10.x | scp-core | AES-256-GCM sender key encryption (ADR-007) |
| `tokio` | 1.x | all crates | Async runtime |
| `tokio-tungstenite` | latest | scp-transport | WebSocket (native relay) |
| `serde` | 1.x | all crates | Serialization framework |
| `serde_json` | 1.x | scp-core, scp-mcp | JSON serialization |
| `rmp-serde` | latest | scp-core, scp-transport | MessagePack binary serialization (envelopes, relay protocol) |
| `pkarr` | 5.0.3+ | scp-core | did:dht identity — BEP44 signed mutable items, DNS packets, Mainline DHT publish/resolve (ADR-003) |
| `z-base-32` | latest | scp-core | z-base-32 encoding for did:dht identifiers (ADR-003) |
| `thiserror` | 2.x | all crates | Error type derivation |
| `futures` | 0.3.x | scp-transport | Stream combinators |
| `tracing` | 0.1.x | all crates | Structured logging |
| `axum` | latest | scp-mcp | HTTP server (MCP SSE transport) |
| `jsonschema` | latest | scp-core | JSON Schema validation (tool schemas) |
| `async-trait` | latest | scp-transport, scp-testing | Async trait support (BlobStore, TransportAdapter) |
| `proptest` | 1.x | all crates (dev) | Property-based testing |
| `scp-testing` | path | all crates (dev) | Network simulation harness, trait conformance macros (§16) |
| `pyo3` | 0.23+ | scp-ffi/pyo3 | Python FFI |
| `uniffi` | latest | scp-ffi/uniffi | Swift/Kotlin FFI |
| `cbindgen` | latest | scp-ffi/cbindgen | C header generation |
| `wasm-bindgen` | latest | scp-ffi/wasm | Browser WASM FFI |
| `napi` | latest | scp-ffi/napi | Node/Bun native addon |

## Error Types

Error types follow the hierarchy defined in `sdk-common.md`. Every crate defines errors via `thiserror`. Each variant carries enough context to diagnose the failure.

```rust
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ScpCoreError {
    #[error("MLS operation failed: {0}")]
    Mls(#[from] MlsError),

    #[error("Identity error: {0}")]
    Identity(#[from] IdentityError),

    #[error("Envelope error: {0}")]
    Envelope(#[from] EnvelopeError),

    #[error("Context error: {0}")]
    Context(#[from] ContextError),

    #[error("UCAN validation failed: {0}")]
    Ucan(#[from] UcanError),

    #[error("Transport error: {0}")]
    Transport(#[from] TransportError),
}
```
