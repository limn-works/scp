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
  scp-transport/
    Cargo.toml
    src/
      lib.rs
      trait.rs              # ADR-005: TransportAdapter trait
      manager.rs            # ADR-012: Multi-transport routing
      native/               # ADR-004: SCP native relay
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
sha2 = "0.10"
hkdf = "0.12"
aes-gcm = "0.10"
rand = "0.8"
futures = "0.3"
async-trait = "0.1"
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
| `rmp-serde` | latest | scp-core | MessagePack binary serialization (envelopes) |
| `thiserror` | 2.x | all crates | Error type derivation |
| `futures` | 0.3.x | scp-transport | Stream combinators |
| `async-trait` | 0.1.x | all crates | Async trait support (may be removed — Rust 2024 supports `async fn` in traits natively via RPITIT; keep only if `dyn`-dispatched async traits are needed) |
| `tracing` | 0.1.x | all crates | Structured logging |
| `axum` | latest | scp-mcp | HTTP server (MCP SSE transport) |
| `jsonschema` | latest | scp-core | JSON Schema validation (tool schemas) |
| `proptest` | 1.x | all crates (dev) | Property-based testing |
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
