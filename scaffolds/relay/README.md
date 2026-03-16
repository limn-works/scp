# SCP Relay Scaffold

Minimal standalone SCP relay server using `scp-transport`'s `RelayServer`. Accepts WebSocket connections from any SCP client and handles PUBLISH, SUBSCRIBE, QUERY, and DELETE operations with SQLite-backed blob storage.

## Prerequisites

- Rust toolchain (see root `rust-toolchain.toml`)
- Clone the SCP repository (this scaffold uses path dependencies)

## Build and Run

```bash
cd scaffolds/relay
cargo run
```

The relay binds to `0.0.0.0:9000` by default. Override the address in `src/main.rs` or adapt it to read from environment variables.

Set log level via `RUST_LOG`:

```bash
RUST_LOG=debug cargo run
```

## What This Does

1. Configures a `RelayConfig` with connection limits, rate limiting, and blob storage parameters
2. Opens a SQLite blob store at `./scp-relay.db` for persistent message storage
3. Starts a WebSocket relay server on the configured bind address
4. Handles graceful shutdown on Ctrl+C or SIGTERM

## Next Steps

- **TLS termination**: Put the relay behind a reverse proxy (nginx, Caddy) with TLS certificates, or use `scp_node::ApplicationNodeBuilder` which handles ACME provisioning automatically
- **Monitoring**: Add a health check endpoint by probing the bind address with TCP connect
- **Blob backend**: Switch from SQLite to PostgreSQL (`postgres-blob` feature) or S3 (`s3-blob` feature) for distributed deployments
- **systemd**: Deploy as a systemd service with `Type=notify` and `ExecStop=/bin/kill -SIGTERM $MAINPID`
- **Full node**: For relay + DID identity + HTTP endpoints (`.well-known/scp`, broadcast projection), use `scp_node::ApplicationNodeBuilder` -- see `crates/scp-node/src/main.rs` for the full pattern
