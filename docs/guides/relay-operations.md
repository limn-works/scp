# Relay Operations

## Overview

SCP relays are untrusted dumb pipes that store and forward opaque, encrypted blobs. They implement the 6 core relay operations (PUBLISH, SUBSCRIBE, UNSUBSCRIBE, QUERY, DELETE, ACK) plus PING keepalive and BRIDGE operations for NAT traversal. Relays never decrypt content -- context access control is enforced by MLS encryption, not relay logic.

SCP provides two relay deployment options:

1. **`scp-relay`** -- A standalone relay binary. Accepts WebSocket connections, stores blobs, and forwards them to subscribers. No identity, no HTTP server, no DID document.
2. **`scp-node`** -- A full application node that composes a relay, a DID identity, HTTP endpoints (`.well-known/scp`, dev API, broadcast projection), and TLS provisioning into a single deployable unit.

Both binaries are configured via environment variables and CLI flags. Both share the same `RelayServer` core (defined in `crates/scp-transport/src/native/server.rs`).

**Contents:**
1. [Building](#1-building)
2. [Operating Modes](#2-operating-modes)
3. [Configuration](#3-configuration)
4. [Blob Storage Backend Selection](#4-blob-storage-backend-selection)
5. [Running the Relay](#5-running-the-relay)
6. [Running the Full Node](#6-running-the-full-node)
7. [TLS Setup](#7-tls-setup)
8. [Health Checks and Monitoring](#8-health-checks-and-monitoring)
9. [NAT Traversal and Zero-Config](#9-nat-traversal-and-zero-config)
10. [Upgrading](#10-upgrading)

---

## 1. Building

Both binaries are workspace members in the SCP repository. Build with:

```bash
# Build both binaries
cargo build --release -p scp-relay -p scp-node

# Build just the standalone relay
cargo build --release -p scp-relay

# Build just the full node
cargo build --release -p scp-node
```

The resulting binaries are at:
- `target/release/scp-relay`
- `target/release/scp-node`

### Feature flags

`scp-node` supports optional features:

| Feature | What it enables |
|---------|----------------|
| `http3` | HTTP/3 and QUIC-based HTTP endpoint (spec SS10.15.1) |

```bash
cargo build --release -p scp-node --features http3
```

---

## 2. Operating Modes

### scp-relay (standalone)

Runs a bare `RelayServer`. No identity, no HTTP, no TLS. Suitable for infrastructure operators who want a minimal relay that accepts WebSocket connections.

```bash
scp-relay
```

### scp-node modes

`scp-node` supports three modes (defined in `crates/scp-node/src/main.rs`):

| Mode | Flag | Storage | Identity | HTTP | Use case |
|------|------|---------|----------|------|----------|
| **Full node** (default) | none | SQLite (SQLCipher) | Persistent DID | `.well-known/scp` + dev API | Production deployment |
| **Relay-only** | `--relay-only` | Configurable | None | None | Equivalent to `scp-relay` |
| **Ephemeral** | `--ephemeral` | All in-memory | Ephemeral DID | `.well-known/scp` + dev API | Test harness only. A shipped build exits 1: the mode needs in-memory DHT and custody, which compile only under the `testing` feature. |

```bash
# Full node (production)
SCP_NODE_DOMAIN=relay.example.com scp-node

# Relay-only mode
scp-node --relay-only

# Ephemeral mode — test harness only; a shipped build exits 1 on this flag.
# Build with `--features testing` to use it.
SCP_NODE_DOMAIN=localhost scp-node --ephemeral
```

---

## 3. Configuration

### Relay configuration (both binaries)

All relay configuration is via `SCP_RELAY_*` environment variables. These map to `RelayConfig` fields (defined in `crates/scp-transport/src/native/server.rs`):

| Environment Variable | `RelayConfig` Field | Default | Description |
|---------------------|---------------------|---------|-------------|
| `SCP_RELAY_BIND_ADDR` | `bind_addr` | `0.0.0.0:9000` | WebSocket listener bind address |
| `SCP_RELAY_MAX_BLOB_SIZE` | `max_blob_size` | `262144` (256 KB) | Maximum blob size in bytes |
| `SCP_RELAY_MAX_BLOB_TTL` | `max_blob_ttl` | `604800` (7 days) | Maximum blob TTL in seconds |
| `SCP_RELAY_MAX_CONNECTIONS` | `max_total_connections` | `1000` | Maximum total WebSocket connections |
| `SCP_RELAY_MAX_CONNECTIONS_PER_IP` | `max_connections_per_ip` | `10` | Maximum connections per IP address |
| `SCP_RELAY_RATE_LIMIT` | `rate_limit_publishes_per_second` | `100` | PUBLISH operations per second per IP |
| `SCP_RELAY_LOG_LEVEL` | N/A | `info` | Log level (trace, debug, info, warn, error) |
| `SCP_RELAY_LOG_FORMAT` | N/A | `pretty` | Log format: `json` or `pretty` |

Additional `RelayConfig` fields with fixed defaults (not configurable via env var):

| Field | Default | Description |
|-------|---------|-------------|
| `max_subscriptions_per_connection` | `100` | Max concurrent subscriptions per WebSocket |
| `max_query_limit` | `1000` | Max results per QUERY operation |
| `ttl_check_interval` | `10s` | Background purge interval |
| `rate_limit_subscribes_per_minute` | `20` | SUBSCRIBE operations per minute per connection |
| `delivery_jitter_ms` | `50` | Random delivery delay for metadata privacy |
| `bridge_secret` | `None` | Shared secret for internal bridge auth |
| `bridge` | `BridgeRole::Disabled` | Whether BRIDGE operations are accepted |
| `did_record_validation` | `DidRecordValidation::Enabled` | Whether the relay validates stored DID records |

### Node-specific configuration

These only apply to `scp-node` (not `scp-relay`):

| Environment Variable | Default | Description |
|---------------------|---------|-------------|
| `SCP_NODE_DOMAIN` | (required) | Domain for full node mode |
| `SCP_NODE_BIND_ADDR` | `0.0.0.0:9000` | HTTP server bind address |
| `SCP_NODE_TLS_SELF_SIGNED` | `false` | Use self-signed TLS (development only) |
| `SCP_NODE_PROJECTION_RATE_LIMIT` | `60` | Per-IP rate limit for projection endpoints |
| `SCP_NODE_DHT_MODE` | `production` | DHT client mode. `production` publishes the node's DID so peers can discover it. `disabled` turns the DHT layer off and is honoured only by `--self-host`; a full relay node rejects it and exits. |
| `SCP_NODE_DHT_GATEWAYS` | (none) | Comma-separated DHT HTTP gateway URLs |
| `SCP_STORAGE_PATH` | `$XDG_DATA_HOME/scp/node` | SQLite database directory |
| `SCP_STORAGE_KEY` | (auto-generated) | Hex-encoded 32-byte SQLCipher encryption key |

### CLI flags

```
scp-node [OPTIONS]

OPTIONS:
    --relay-only            Run as a bare relay server (no identity, no HTTP)
    --ephemeral             Use in-memory storage for all subsystems (no persistence).
                            A test-harness mode: a shipped build exits 1 on it.
    --storage-path <PATH>   SQLite database directory
    --health                TCP health probe (exit 0/1)
    --help, -h              Show help
```

---

## 4. Blob Storage Backend Selection

Both `scp-relay` and `scp-node` (in relay-only mode) select a blob storage backend via `SCP_RELAY_STORAGE_BACKEND`. The value maps to a `BlobStorageBackend` enum variant:

| Value | Backend | Required env vars | Default path |
|-------|---------|-------------------|-------------|
| `sqlite` (default) | SQLite | `SCP_RELAY_STORAGE_PATH` | `./scp-relay.db` |
| `redb` | redb (embedded) | `SCP_RELAY_STORAGE_PATH` | `./scp-relay.redb` |
| `postgres` | PostgreSQL | `SCP_RELAY_DATABASE_URL` (required) | N/A |
| `s3` | S3-compatible | `SCP_RELAY_S3_BUCKET` (required), `SCP_RELAY_S3_PREFIX` | prefix: `blobs/` |
| `memory` | In-memory | none | N/A (data lost on restart) |

### Examples

```bash
# SQLite (default)
SCP_RELAY_STORAGE_PATH=/var/lib/scp/relay.db scp-relay

# PostgreSQL
SCP_RELAY_STORAGE_BACKEND=postgres \
SCP_RELAY_DATABASE_URL="postgres://user:pass@localhost/scp_relay" \
scp-relay

# S3-compatible (e.g., MinIO)
SCP_RELAY_STORAGE_BACKEND=s3 \
SCP_RELAY_S3_BUCKET=scp-blobs \
SCP_RELAY_S3_PREFIX=production/ \
AWS_ACCESS_KEY_ID=... \
AWS_SECRET_ACCESS_KEY=... \
scp-relay

# In-memory (development only)
SCP_RELAY_STORAGE_BACKEND=memory scp-relay
```

All backends implement the `BlobStorage` trait and pass the `blob_store_conformance!` test suite. See [Storage Backends](storage-backends.md) for details on the trait and conformance testing.

---

## 5. Running the Relay

### Standalone relay

```bash
# Minimal: SQLite storage, bind 0.0.0.0:9000
scp-relay

# Custom bind address and limits
SCP_RELAY_BIND_ADDR=127.0.0.1:8080 \
SCP_RELAY_MAX_CONNECTIONS=5000 \
SCP_RELAY_MAX_BLOB_SIZE=524288 \
SCP_RELAY_RATE_LIMIT=200 \
scp-relay
```

The relay logs to stderr. Control verbosity with `SCP_RELAY_LOG_LEVEL` or `RUST_LOG`:

```bash
# Structured JSON logs for production
SCP_RELAY_LOG_FORMAT=json SCP_RELAY_LOG_LEVEL=info scp-relay

# Debug-level with RUST_LOG (overrides SCP_RELAY_LOG_LEVEL)
RUST_LOG=scp_transport=debug scp-relay
```

### Graceful shutdown

Both binaries handle SIGINT (Ctrl+C) and SIGTERM gracefully. On receiving a signal:

1. The relay stops accepting new WebSocket connections.
2. In-flight connection handlers drain naturally (not cancelled).
3. The process exits after all handlers complete.

```bash
# In a container or systemd service
kill -TERM $(pidof scp-relay)
```

---

## 6. Running the Full Node

The full node (`scp-node` without `--relay-only`) starts an `ApplicationNode` (defined in `crates/scp-node/src/lib.rs`) that composes:

- A relay server (internal, on a random port with bridge secret auth)
- A DID identity (persistent across restarts via SQLite)
- An HTTP server serving `.well-known/scp`, WebSocket upgrade, dev API, and broadcast projection
- Automatic TLS provisioning via ACME (or self-signed for development)

### Production deployment

```bash
# Required: domain and storage path
SCP_NODE_DOMAIN=relay.example.com \
SCP_STORAGE_PATH=/var/lib/scp/node \
scp-node
```

**On a shipped build, the full-node and `--self-host` modes cannot complete a first
run.** Both need to create an identity, which requires a `PreRotationCustody`
backend whose only implementation is the test harness, so each exits 1. The
full-node mode logs `application node failed to build`; `--self-host` logs
`self-host mode failed`. Two tests in `crates/scp-node/src/lib.rs` pin the two
paths: `pre_rotation_severance_generate_fails_closed` covers the full node's
`persist = false` route, and `pre_rotation_severance_persistent_fails_closed`
covers the `--self-host` route, which `Node::start` normalizes to `Generate` with
`persist = true`. The real backend is not implemented yet, and the node fails closed
rather than mint a nullifier-backed identity.

`--relay-only` is unaffected: `run_relay_only` builds a `RelayServer` and no
identity at all, so it starts on a shipped build.

The steps below therefore describe what the binary does once that backend lands,
and what a `testing` build does today:

1. Creates the storage directory and generates a SQLCipher encryption key (stored at `$SCP_STORAGE_PATH/.key`, mode 0600).
2. Generates a new Ed25519 identity and publishes the DID document to the DHT.
3. Starts the internal relay server with bridge secret authentication.
4. Provisions a TLS certificate via ACME (unless `SCP_NODE_TLS_SELF_SIGNED=1`).
5. Starts the HTTP server with `.well-known/scp` endpoint.

The full-node mode fails on **every** run, not only the first. `main.rs` passes
`IdentitySource::Generate`, `Node::start` maps every arm but `Persisted` to
`persist = false`, and the resolver returns before it reads storage. So that mode
never writes an identity either, and the "subsequent runs reload it" case cannot
arise from it. The reload path is real and ungated, but only the `--self-host`
flow and the FFI `start_node_local` surface reach it, because those pass
`IdentitySource::Persisted` — and both still fail closed on a first run, when
there is nothing stored to reload.

### Development deployment

```bash
# Self-signed TLS; the node still publishes its DID so peers can find it.
# `--ephemeral` is omitted: a shipped build exits 1 on it, so this node persists
# its identity and storage to disk.
SCP_NODE_DOMAIN=localhost \
SCP_NODE_TLS_SELF_SIGNED=1 \
scp-node
```

A full relay node has no non-publishing DHT mode, because a relay whose DID
never reaches the DHT cannot be discovered. Run `scp-node --self-host` when you
want a node that publishes nothing.

### Programmatic usage (Rust SDK)

```rust
use std::sync::Arc;
use scp_did::DidDocument;
use scp_dht::PkarrDhtClient;
use scp_identity::{DidDht, ScpIdentity};
use scp_node::{
    DhtMode, ExplicitIdentity, IdentitySource, Node, NodeConfig, Reach, TlsMode,
};
use scp_platform::sqlite::{SqliteKeyCustody, SqliteStorage};
use scp_transport::native::storage::BlobStorageBackend;

// `load_node_identity`, `load_node_did_document`, `build_did_method`, and
// `open_encrypted_storage` are yours to write; this shows the config shape and the
// type annotations it needs, not a runnable program.
//
// `PkarrDhtClient`, `scp_platform::sqlite`, and `BlobStorageBackend::sqlite` each
// sit behind a feature that is off by default in its own crate, and you do not
// need to enable any of them: depending on `scp-node` is enough. Cargo unifies the
// features `scp-node` requests on its own edges into the single build of each
// dependency, for an external consumer exactly as inside this workspace. Drop
// `scp-node` from your dependencies and the `scp_dht` and `scp_platform::sqlite`
// imports stop resolving; `BlobStorageBackend` still imports, and the
// `::sqlite(...)` constructor is what disappears.
//
// A shipped build cannot CREATE an identity: that needs a `PreRotationCustody`
// backend which only a `testing` build has, so `IdentitySource::Generate` and
// `::Persisted` both fail closed on a first run. Load the
// identity you already hold and pass it explicitly.
let identity: ScpIdentity = load_node_identity()?;
let document: DidDocument = load_node_did_document()?;
let did_method: Arc<DidDht<PkarrDhtClient>> = build_did_method()?;
let storage: SqliteStorage = open_encrypted_storage(&storage_dir, &storage_key)?;

// `IdentitySource` is generic over the custody and DID-method types, and the
// `Explicit` arm carries no custody value, so the custody parameter has to be
// named. `crates/scp-ffi/common/src/server.rs` writes the same turbofish.
let node = Node::start(NodeConfig {
    dht: DhtMode::Production,
    tls: TlsMode::Acme { email: Some("admin@example.com".into()) },
    ..NodeConfig::defaults(
        Reach::Domain { domain: "relay.example.com".into() },
        IdentitySource::<SqliteKeyCustody, DidDht<PkarrDhtClient>>::Explicit(
            Box::new(ExplicitIdentity { identity, document, did_method }),
        ),
        storage,
        BlobStorageBackend::sqlite(&blob_db)?, // durable backend for a public node
    )
})
.await?;

println!("DID: {}", node.identity().did());
println!("Relay URL: {}", node.relay_url());
println!("Relay addr: {}", node.relay().bound_addr());

// Serve HTTP and wait for shutdown
node.serve(axum::Router::new(), shutdown_signal()).await?;
```

### `NodeConfig` fields

ADR-052 replaced `ApplicationNodeBuilder` with one flat config struct plus
`Node::start`. There is no builder and no `.build()`; set the fields you need and
take the rest from `NodeConfig::defaults`.

| Field | Description |
|-------|-------------|
| `reach: Reach` | How the node is reached: `Domain`, `NatTraversal`, `Tunnel`, or `Local` |
| `identity: IdentitySource<K, D>` | `Generate`, `Persisted`, or `Explicit` |
| `storage: S` | Platform storage backend; `Node::start` requires `EncryptedStorage` |
| `blob_storage: BlobStorageBackend` | Relay blob backend (required, no default) |
| `tls: TlsMode` | `Acme`, `SelfSigned`, `Plaintext`, `Terminated`, or `Custom` |
| `dht: DhtMode` | `Disabled` (default, no publish) or `Production` |
| `bind_addr: Option<SocketAddr>` | Internal relay bind address |
| `http_bind_addr: Option<SocketAddr>` | Public HTTP server bind address |
| `local_api: Option<SocketAddr>` | Dev API bind address; `None` disables it |
| `cors_origins: Option<Vec<String>>` | Allowed CORS origins |
| `dht_gateways: Vec<String>` | DHT HTTP gateway URLs. Carried but not threaded end-to-end: `split_config` discards it, so setting it has no effect today. |
| `projection_rate_limit: Option<u32>` | Per-IP rate limit for projection endpoints |
| `dns_provider: Option<DnsProviderConfig>` | Registers a DID-derived subdomain and this node's public IP with the Limn DNS API at `dns.ctx.network`, which runs the Let's Encrypt DNS-01 challenge and returns the certificate. Setting it REPLACES the `tls` provider and overrides the domain; it falls back to self-signed when the API is unreachable. |
| `nat: NatSlot` | NAT traversal strategy selection |
| `network_detector: Option<Arc<dyn NetworkChangeDetector>>` | Network change source |
| `http3: Option<Http3Config>` | HTTP/3 listener config. Exists only under the `http3` feature, which `scp-node` does not enable by default, so a default build has no such field. |

---

## 7. TLS Setup

### ACME (production)

By default, `scp-node` uses ACME (RFC 8555) with HTTP-01 challenges for automatic TLS provisioning. The node serves `/.well-known/acme-challenge/<token>` on port 80 during certificate issuance.

Requirements:
- Port 80 accessible from the internet (for HTTP-01 challenge).
- DNS A/AAAA record pointing `SCP_NODE_DOMAIN` to the server's IP.
- The ACME directory defaults to Let's Encrypt production.

Certificates are stored encrypted in the platform `Storage` and auto-renewed 30 days before expiry. The renewal loop runs every 12 hours.

Certificate data is defined in `crates/scp-node/src/tls.rs` as `CertificateData`:

```rust
pub struct CertificateData {
    pub certificate_chain_pem: String,
    pub private_key_pem: Zeroizing<String>,  // Zeroed on drop
}
```

### Self-signed (development)

For development, set `SCP_NODE_TLS_SELF_SIGNED=1`:

```bash
SCP_NODE_DOMAIN=localhost \
SCP_NODE_TLS_SELF_SIGNED=1 \
scp-node
```

This generates a self-signed certificate for the configured domain. Not suitable for production -- clients will reject the certificate unless they disable verification.

### Custom TLS provider

Implement the `TlsProvider` trait (defined in `crates/scp-node/src/lib.rs`) for custom certificate provisioning (e.g., DNS-01 challenges, Vault-managed certificates):

```rust
pub trait TlsProvider: Send + Sync {
    fn provision(&self) -> Pin<Box<dyn Future<Output = Result<CertificateData, TlsError>> + Send + '_>>;
    fn challenges(&self) -> Arc<RwLock<HashMap<String, String>>> { /* default: empty */ }
    fn needs_challenge_listener(&self) -> bool { false }
}
```

### TLS requirements

Per spec section 9.13, all relay connections use TLS 1.3. The `CertResolver` (defined in `crates/scp-node/src/tls.rs`) supports hot-reloading certificates without restarting the server:

```rust
// Hot-swap certificate after ACME renewal
if let Some(resolver) = node.cert_resolver() {
    resolver.update(new_cert_data)?;
}
```

---

## 8. Health Checks and Monitoring

### TCP health probe

Both binaries support `--health` for container and load balancer health checks:

```bash
# Check if the relay is accepting connections
scp-relay --health       # exit 0 = healthy, exit 1 = unhealthy
scp-node --health        # checks SCP_NODE_BIND_ADDR
scp-node --relay-only --health  # checks SCP_RELAY_BIND_ADDR
```

The health probe attempts a TCP connection to the bind address and exits immediately. It does not initialize tracing or start any servers.

### Container health check

```dockerfile
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["scp-relay", "--health"]
```

### Logging

Both binaries use the `tracing` crate with configurable output:

| Format | Env var | Description |
|--------|---------|-------------|
| Pretty | `SCP_RELAY_LOG_FORMAT=pretty` (default) | Human-readable output to stderr |
| JSON | `SCP_RELAY_LOG_FORMAT=json` | Structured JSON output to stderr |

Log levels are controlled by `RUST_LOG` (takes precedence) or `SCP_RELAY_LOG_LEVEL`:

```bash
# Module-level filtering
RUST_LOG=scp_transport::native::server=debug,scp_node=info scp-node

# Simple level override
SCP_RELAY_LOG_LEVEL=warn scp-relay
```

### Dev API (scp-node only)

When enabled by setting `local_api: Some(addr)` on `NodeConfig`, the dev API provides endpoints for inspection and testing:

```bash
# The dev token is printed at startup
curl -H "Authorization: Bearer scp_local_token_<hex>" \
  http://localhost:9000/scp/dev/v1/status
```

The dev API serves endpoints for identity info, context management, relay status, and broadcast projection configuration. See spec section 18.10 for the full endpoint list.

---

## 9. NAT Traversal and Zero-Config

`scp-node` supports zero-config deployment behind NAT (spec section 10.12.8). When `no_domain()` is used instead of `domain()`, the node probes its network environment and selects the best reachability tier:

| Tier | Method | Relay URL format |
|------|--------|-----------------|
| **Tier 1** | UPnP/NAT-PMP port mapping | `ws://<external-ip>:<port>/scp/v1` |
| **Tier 2** | STUN hole punching (non-symmetric NAT) | `ws://<external-ip>:<port>/scp/v1` |
| **Tier 3** | Bridge relay (symmetric NAT fallback) | `wss://<bridge>/scp/v1?bridge_target=<hex>` |
| **Tier 4** | Domain mode with TLS | `wss://<domain>/scp/v1` |

The `DefaultNatStrategy` (defined in `crates/scp-node/src/lib.rs`) implements the tier selection algorithm using STUN probing. Each tier includes a reachability self-test before acceptance.

The node re-evaluates its tier every 30 minutes and on network change events. When the tier changes, the DID document is republished with the new relay URL.

---

## 10. Upgrading

### Binary upgrade

1. Build the new version: `cargo build --release -p scp-relay -p scp-node`
2. Gracefully stop the running relay: `kill -TERM $(pidof scp-relay)`
3. Replace the binary.
4. Start the new version.

In-flight WebSocket connections drain naturally during shutdown. Clients reconnect via the standard exponential backoff (profile-dependent, see [Transport Layer Architecture](architecture.md)).

### Storage migrations

SQLite blob storage (`SqliteBlobStore`) and node storage (`SqliteStorage`) use versioned schemas. The `ProtocolRepository` wraps values in `StoredValue<T>` envelopes (spec SS17.5) for forward compatibility. Schema migrations run automatically on startup.

### Rolling upgrades

For high-availability deployments with multiple relays:

1. Deploy new binaries to a subset of relays.
2. Clients automatically reconnect to updated relays via their relay set (minimum 3 relays for suppression resistance, spec SS9.9.2).
3. Once verified, deploy to remaining relays.

The relay wire format (MessagePack per ADR-004) is versioned. Protocol version is `SCP_PROTOCOL_VERSION = 0x0100` (256). Wire format changes are backward-compatible within a major version.

---

## Architecture Diagram

```
  scp-node (full mode)
  +-----------------------------------------------------+
  |                                                     |
  |  +------------------+     +---------------------+   |
  |  | ApplicationNode  |     | HTTP Server (axum)  |   |
  |  |                  |     |                     |   |
  |  |  - identity      |     | /.well-known/scp    |   |
  |  |  - relay handle  |     | /scp/v1 (WS upgrade)|   |
  |  |  - storage       |     | /scp/dev/v1/*       |   |
  |  |  - state         |     | /scp/broadcast/*    |   |
  |  +--------+---------+     +----------+----------+   |
  |           |                          |              |
  |           |   bridge_secret auth     |              |
  |           v                          v              |
  |  +------------------+     +---------------------+   |
  |  | RelayServer      |<--->| WebSocket clients   |   |
  |  | (internal port)  |     | (via HTTP upgrade)  |   |
  |  +--------+---------+     +---------------------+   |
  |           |                                         |
  |           v                                         |
  |  +------------------+                               |
  |  | BlobStorageBackend                               |
  |  | (sqlite/redb/pg/s3/mem)                          |
  |  +------------------+                               |
  +-----------------------------------------------------+

  scp-relay (standalone)
  +------------------+     +---------------------+
  | RelayServer      |<--->| WebSocket clients   |
  | (direct port)    |     |                     |
  +--------+---------+     +---------------------+
           |
           v
  +------------------+
  | BlobStorageBackend
  +------------------+
```

---

## Spec Cross-References

| Topic | Spec Section |
|-------|-------------|
| Relay wire protocol (MessagePack, operations) | ADR-004 |
| Application node design | SS18.6 |
| Node identity and DID publication | SS18.6.4 |
| TLS provisioning and ACME | SS18.6.3 |
| Dev API endpoints | SS18.10 |
| Broadcast projection | SS18.11 |
| NAT traversal and zero-config deployment | SS10.12 |
| Reachability self-test | SS10.12.2 |
| Bridge relay operation | SS10.12.4 |
| Rate limiting | ADR-004 |
| Connection limits | ADR-004 |
| Blob storage backends | SS10.5 |
