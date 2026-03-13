# SCP Rust Client Scaffold

Minimal Rust binary using `scp-core` directly. Creates a DID identity, opens an encrypted context, and sends a message.

## Prerequisites

- Rust toolchain (see root `rust-toolchain.toml`)
- Clone the SCP repository (this scaffold uses path dependencies)

## Build and Run

```bash
cd scaffolds/rust-client
cargo run
```

## What This Does

1. Creates a `did:dht` identity with in-memory key custody
2. Publishes the DID document to an in-memory DHT
3. Builds a `ContextManager` with mock providers
4. Creates an encrypted context with messaging capabilities
5. Sends a message and drains events

## Next Steps

- Replace `MockCrypto` with `scp-core::crypto::mls::provider` for real MLS encryption
- Replace `MockTransport` with `scp-transport` for relay connectivity
- Replace `MockEventLog` with `scp-event-log` for Merkle event persistence
- Add a second participant using `join_context` with a real key package
- See `crates/scp-core/examples/` for more detailed examples
