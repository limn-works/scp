# Relay Operations Guide

This guide covers running and operating an SCP relay -- the store-and-forward infrastructure that delivers encrypted messages between participants. Relays are protocol-unaware: they store and forward encrypted blobs without interpreting their contents. A malicious relay can delay or drop messages but cannot compromise confidentiality or integrity.

SCP provides two relay binaries with different scope.

---

## Overview: Two Binaries

### scp-relay (minimal)

A standalone WebSocket relay server. It accepts connections, stores encrypted blobs, and delivers them to subscribers. No identity, no TLS termination, no `.well-known/scp` endpoint. Use this when you want the smallest possible relay process and handle TLS at the reverse proxy layer.

**Crate:** `crates/scp-relay/`

### scp-node (full-featured)

An application node that composes a relay, a DID identity, TLS termination, an HTTP server (`.well-known/scp`, WebSocket upgrade, broadcast projection), and platform storage into a single deployable unit. This is the "one box" deployment pattern described in spec section 18.6.

`scp-node` also supports a `--relay-only` flag that runs a bare relay identical to the standalone `scp-relay` binary.

**Crate:** `crates/scp-node/`

---

## Quick Start

### Minimal relay (scp-relay)

```bash
cargo run -p scp-relay
```

This starts a WebSocket relay on `0.0.0.0:9000` with in-memory blob storage and default limits. The relay logs to stderr and shuts down cleanly on SIGINT or SIGTERM.

### Full node (scp-node)

```bash
SCP_NODE_DOMAIN=relay.example.com cargo run -p scp-node
```

This starts a full application node: generates a DID identity, starts an internal relay, provisions TLS (ACME by default), and serves HTTPS on `0.0.0.0:9000` with `.well-known/scp` and WebSocket upgrade at `/scp/v1`.

### Relay-only mode via scp-node

```bash
cargo run -p scp-node -- --relay-only
```

Identical behavior to the standalone `scp-relay` binary.

### Health check

Both binaries support a `--health` flag that probes the bind address via TCP and exits with code 0 (reachable) or 1 (unreachable). Useful for container orchestration liveness probes:

```bash
# Health check for scp-relay
cargo run -p scp-relay -- --health

# Health check for scp-node
cargo run -p scp-node -- --health

# Health check for scp-node in relay-only mode
cargo run -p scp-node -- --relay-only --health
```

---

## Configuration

All configuration is via environment variables. Invalid values are logged as warnings and replaced with defaults.

### Relay variables (scp-relay and scp-node --relay-only)

| Variable | Default | Description |
|----------|---------|-------------|
| `SCP_RELAY_BIND_ADDR` | `0.0.0.0:9000` | Socket address to bind the WebSocket listener |
| `SCP_RELAY_MAX_BLOB_SIZE` | `262144` (256 KB) | Maximum blob size in bytes |
| `SCP_RELAY_MAX_BLOB_TTL` | `604800` (7 days) | Maximum blob TTL in seconds |
| `SCP_RELAY_MAX_CONNECTIONS` | `1000` | Maximum total concurrent WebSocket connections |
| `SCP_RELAY_MAX_CONNECTIONS_PER_IP` | `10` | Maximum concurrent connections from a single IP |
| `SCP_RELAY_RATE_LIMIT` | `100` | Maximum PUBLISH operations per second per IP |
| `SCP_RELAY_LOG_LEVEL` | `info` | Default log level (overridden by `RUST_LOG`) |
| `SCP_RELAY_LOG_FORMAT` | `pretty` | Log format: `json` for structured JSON, anything else for human-readable |

### Full node variables (scp-node without --relay-only)

| Variable | Default | Description |
|----------|---------|-------------|
| `SCP_NODE_DOMAIN` | *(required)* | Domain this node serves. Relay URL becomes `wss://<domain>/scp/v1` |
| `SCP_NODE_BIND_ADDR` | `0.0.0.0:9000` | Socket address for the public HTTPS server |
| `SCP_NODE_TLS_SELF_SIGNED` | `false` | Set to `1` or `true` for self-signed TLS (development only) |
| `SCP_NODE_PROJECTION_RATE_LIMIT` | `60` | Per-IP rate limit for broadcast projection endpoints (requests/second) |
| `RUST_LOG` | *(unset)* | Standard `tracing` filter directive. Takes precedence over `SCP_RELAY_LOG_LEVEL` |

### Additional RelayConfig defaults (set in code, not currently exposed as env vars)

These values apply via `RelayConfig::default()` and are not overridden by the env-based config constructors:

| Parameter | Default | Description |
|-----------|---------|-------------|
| `max_subscriptions_per_connection` | `100` | Maximum concurrent subscriptions per WebSocket connection |
| `max_query_limit` | `1000` | Maximum QUERY result limit |
| `ttl_check_interval` | `10s` | How often the background task checks for expired blobs |
| `rate_limit_subscribes_per_minute` | `20` | Maximum SUBSCRIBE operations per minute per connection |
| `delivery_jitter_ms` | `50` | Random delivery delay (0 to N ms) to break timing correlation |

---

## TLS Setup

SCP requires TLS 1.3 for all relay connections (spec section 9.13). The full node (`scp-node`) provides two TLS modes.

### Automatic TLS via ACME (production)

When `SCP_NODE_DOMAIN` is set and `SCP_NODE_TLS_SELF_SIGNED` is not enabled, the node provisions a TLS certificate automatically via the ACME protocol (RFC 8555) using Let's Encrypt. The flow:

1. The node starts an HTTP-01 challenge responder at `/.well-known/acme-challenge/<token>`.
2. Let's Encrypt validates domain ownership by hitting this endpoint on port 80.
3. The signed certificate is stored in platform `Storage` (keys: `scp.tls.certificate_chain_pem`, `scp.tls.private_key_pem`), encrypted at rest by the storage backend.
4. A background renewal loop checks every 12 hours and renews 30 days before expiry.
5. Renewed certificates are hot-swapped via `CertResolver` -- no server restart required.

**Requirements:**
- Port 80 must be reachable from the internet for HTTP-01 challenges.
- DNS must resolve `SCP_NODE_DOMAIN` to the server's public IP.

**Optional:** Set `acme_email` on the builder (or expose via env) for Let's Encrypt account registration notifications.

### Self-signed TLS (development)

For local development or testing:

```bash
SCP_NODE_DOMAIN=localhost SCP_NODE_TLS_SELF_SIGNED=1 cargo run -p scp-node
```

This generates a self-signed certificate for the configured domain. Clients must disable certificate verification or trust the generated CA. Not for production use.

### External TLS termination

If running `scp-relay` (or `scp-node --relay-only`) behind a reverse proxy (nginx, Caddy, etc.), terminate TLS at the proxy and forward plain WebSocket connections to the relay's bind address. The relay itself does not perform TLS in this mode.

---

## Well-Known Endpoint

Full node deployments serve `GET /.well-known/scp` -- a JSON document that advertises the node's identity, relay URL, operational limits, and any public broadcast contexts. The document is generated fresh on every request (never cached).

### Response format

```json
{
  "version": 1,
  "did": "did:dht:z6Mk...",
  "relay": "wss://relay.example.com/scp/v1",
  "relay_config": {
    "max_blob_size": 262144,
    "max_blob_ttl": 604800,
    "rate_limit_publish": 6000,
    "rate_limit_subscribe": 100,
    "transports": ["websocket"]
  },
  "contexts": [
    {
      "id": "a1b2c3d4...",
      "name": "Public Feed",
      "mode": "broadcast",
      "uri": "scp://context/a1b2c3d4...?relay=wss%3A//relay.example.com/scp/v1&mode=broadcast&name=Public%20Feed"
    }
  ]
}
```

Key fields:
- **`version`**: Protocol version (currently `1`).
- **`did`**: The operator's DID. Clients verify relay authenticity against this.
- **`relay`**: The WebSocket relay URL for this node.
- **`relay_config`**: Operational limits so clients can choose relays. `rate_limit_publish` is in operations per minute. `transports` lists supported transport protocols (WebSocket is always present; `quic`, `webtransport`, `udp-dtls`, `coap` appear when compiled with the corresponding feature flags).
- **`contexts`**: Only broadcast contexts are listed (privacy constraint -- encrypted context IDs must not be exposed).

### Why it matters

Clients use `.well-known/scp` for relay discovery and selection. The `relay_config` fields let clients compare relay capabilities and choose based on limits, cost, and supported transports. The `did` field provides cryptographic verification that the relay is operated by the expected identity.

---

## Monitoring

### Health checks

Use the `--health` flag for liveness probes. It performs a TCP connect to the configured bind address and exits immediately:

```bash
# In a container healthcheck or systemd ExecStartPre
scp-relay --health
# Exit code 0 = listening, 1 = unreachable
```

### Logging

Both binaries use the `tracing` crate. Control verbosity with:

```bash
# Standard tracing filter (most flexible)
RUST_LOG=scp_transport=debug,scp_node=info cargo run -p scp-node

# Simple level override
SCP_RELAY_LOG_LEVEL=debug cargo run -p scp-relay

# Structured JSON for log aggregation
SCP_RELAY_LOG_FORMAT=json cargo run -p scp-relay
```

Log output includes bind addresses, connection counts, blob operations, rate limit hits, and shutdown events. In JSON mode, all fields are machine-parseable for ingestion into log aggregation systems.

### Key log events to monitor

- `"starting scp-relay"` / `"starting scp-node in full mode"` -- startup with config summary
- `"relay listening"` -- relay bound and accepting connections
- `"shutdown signal received, stopping relay"` -- graceful shutdown initiated
- `"relay failed to start"` -- fatal: bind failure or config error
- Rate limit warnings (per-IP publish limits, subscribe churn limits)

---

## Storage

### What the relay persists

The relay stores encrypted blobs -- opaque byte sequences with a TTL. It does not interpret, decrypt, or index their contents. Blobs expire after their TTL (default 7 days, max configurable via `SCP_RELAY_MAX_BLOB_TTL`) and are cleaned up by a background task running every 10 seconds.

The full node (`scp-node`) additionally stores:
- TLS certificate chain and private key (PEM-encoded, encrypted at rest)
- Protocol state via `ProtocolStore` (wraps the platform `Storage` trait)

### Blob storage backends

The relay's blob storage is configured via `BlobStorageBackend`, an enum dispatch over multiple backends. All backends implement the `BlobStore` trait and pass the `blob_store_conformance!()` test suite.

| Backend | Feature flag | Use case |
|---------|-------------|----------|
| **InMemory** | *(always available)* | Development, testing. Data lost on restart. |
| **SQLite** | `sqlite-blob` | Personal relays, small deployments. Single-file database. |
| **redb** | `redb-blob` | Medium relays. Pure Rust, no C dependencies. |
| **PostgreSQL** | `postgres-blob` | Production / enterprise. Horizontal scaling. |
| **S3** | `s3-blob` | Large-scale / cloud deployments. Any S3-compatible store. |
| **Combined** | `combined` | SQLCipher-backed: protocol state + blobs in one encrypted DB. |
| **Cached** | `local-cache` | Size-limited local cache wrapping another backend. |

The default in both binaries is `InMemory`. For production, use SQLite (simplest persistent option) or redb/PostgreSQL/S3 depending on scale. Backend selection is done programmatically via the `ApplicationNodeBuilder::blob_storage()` method; the standalone `scp-relay` binary currently uses in-memory storage and would need code changes to use a persistent backend.

---

## Upgrading

### Protocol compatibility

SCP relays are protocol-unaware by design. They store and forward encrypted blobs without interpreting protocol semantics. This means:

- **Relay upgrades do not require client coordination.** Clients and relays communicate via a simple publish/subscribe/query protocol over WebSocket. As long as the wire format is preserved, relay upgrades are transparent.
- **The `.well-known/scp` version field** indicates the protocol version. Clients check this for compatibility.
- **Blob format changes** are a client-side concern. The relay treats blobs as opaque bytes; changes to the envelope format inside blobs do not affect relay operation.

### Upgrade procedure

1. Build the new version: `cargo build -p scp-relay --release` or `cargo build -p scp-node --release`.
2. Send SIGTERM to the running process. The relay drains in-flight connections gracefully -- handlers are not cancelled.
3. Start the new binary. If using persistent blob storage, existing blobs remain available.

For zero-downtime upgrades, run multiple relay instances behind a load balancer. SCP clients are designed for multi-relay resilience (spec section 9.9.2 recommends publishing to 3+ relays), so brief relay unavailability during a rolling upgrade is tolerated by the protocol.

### Data migration

In-memory storage is lost on restart. Persistent backends (SQLite, redb, PostgreSQL, S3) retain blobs across restarts. The `BlobStore` trait is stable; switching backends requires draining or accepting the loss of in-flight blobs from the old backend.

TLS certificates stored via `ProtocolStore` survive restarts when using a persistent `Storage` implementation. The ACME renewal loop re-provisions automatically if certificates are missing.

---

## Deployment Patterns

### Personal relay (single user)

```bash
SCP_NODE_DOMAIN=me.example.com cargo run -p scp-node --release
```

SQLite blob storage, ACME TLS, single process. Suitable for a personal server, NAS, or agent workstation.

### Minimal relay behind a reverse proxy

```bash
SCP_RELAY_BIND_ADDR=127.0.0.1:9000 cargo run -p scp-relay --release
```

Terminate TLS at the proxy (nginx, Caddy). Forward WebSocket connections to `127.0.0.1:9000`. The relay does not need a domain or TLS configuration.

### Development / testing

```bash
SCP_NODE_DOMAIN=localhost \
  SCP_NODE_TLS_SELF_SIGNED=1 \
  SCP_NODE_BIND_ADDR=127.0.0.1:9000 \
  RUST_LOG=debug \
  cargo run -p scp-node
```

Self-signed TLS, verbose logging, loopback only. Suitable for local SDK development against a real relay.
