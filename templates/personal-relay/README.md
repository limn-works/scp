# Personal Relay

A self-hosted SCP relay node with automatic TLS and DID publishing.

This template builds a single-binary relay that:

- Creates a persistent identity (DID) on first run, reuses it on subsequent restarts
- Provisions TLS certificates automatically via Let's Encrypt (ACME HTTP-01)
- Publishes the relay's DID to the DHT so other SCP participants can discover it
- Serves WebSocket connections at `/scp/v1` and discovery at `/.well-known/scp`
- Exposes a `/healthz` endpoint for monitoring and container probes
- Handles graceful shutdown on SIGINT/SIGTERM

## Prerequisites

- Rust toolchain (install via [rustup](https://rustup.rs/))
- A domain name pointing to your server (for automatic TLS)
- Port 443 reachable from the internet (for ACME challenges and client connections)
- Port 80 temporarily reachable during initial certificate provisioning (ACME HTTP-01)

**This template does not currently compile against the workspace.** `src/main.rs:25`
imports `scp_node::ApplicationNodeBuilder`, which the ADR-052 node-construction refactor
deleted in favour of `Node::start(NodeConfig { .. })`, so `cargo build` stops at that import
with `error[E0432]`. Issue #2384, the non-workspace crates that no longer compile, tracks the
port. Every recipe below — the quick start, the systemd unit, and the Docker block — is
correct once that lands, and the Docker recipe compiles on the version
`rust-toolchain.toml` names, because it copies that file into the image.

## Quick start

```bash
# Clone the SCP repository (this template references workspace crates by path)
git clone https://github.com/limn-works/scp.git
cd scp/templates/personal-relay

# Build in release mode
cargo build --release

# Run with a domain (automatic Let's Encrypt TLS)
SCP_RELAY_DOMAIN=relay.example.com \
SCP_RELAY_ACME_EMAIL=you@example.com \
  ./target/release/scp-personal-relay
```

On first run, the relay:
1. Generates Ed25519 keypairs — identity and active signing in operational custody, pre-rotation in a separate substrate (§3.9 of the identity spec)
2. Derives a `did:dht` identifier from the identity key
3. Provisions a TLS certificate from Let's Encrypt
4. Starts the relay on `0.0.0.0:443` (configurable)
5. Publishes the DID document with an `SCPRelay` service entry to the DHT
6. Logs the DID and relay URL at INFO level

On subsequent runs with the same storage path, the same DID is reused.

## TLS options

### Automatic (Let's Encrypt) -- recommended

Set `SCP_RELAY_DOMAIN` and optionally `SCP_RELAY_ACME_EMAIL`. The relay provisions
and auto-renews certificates via ACME HTTP-01 challenges. Port 80 must be reachable
during the initial challenge (a temporary listener is started automatically).

```bash
SCP_RELAY_DOMAIN=relay.example.com \
SCP_RELAY_ACME_EMAIL=admin@example.com \
  ./target/release/scp-personal-relay
```

### Manual certificates

If you manage TLS externally (certbot, Caddy, etc.), point to your PEM files:

```bash
SCP_RELAY_DOMAIN=relay.example.com \
SCP_RELAY_TLS_CERT=/etc/letsencrypt/live/relay.example.com/fullchain.pem \
SCP_RELAY_TLS_KEY=/etc/letsencrypt/live/relay.example.com/privkey.pem \
  ./target/release/scp-personal-relay
```

### Self-signed (development only)

For local development without a real domain:

```bash
SCP_RELAY_DOMAIN=localhost \
SCP_RELAY_TLS_SELF_SIGNED=1 \
SCP_RELAY_BIND_ADDR=0.0.0.0:9443 \
  ./target/release/scp-personal-relay
```

### No domain (NAT-traversed mode)

If you don't have a domain, omit `SCP_RELAY_DOMAIN`. The relay will probe your NAT
type, attempt UPnP port mapping, and publish a `ws://` relay URL to the DHT:

```bash
SCP_RELAY_BIND_ADDR=0.0.0.0:9000 \
  ./target/release/scp-personal-relay
```

## Discovery

Once running, your relay is discoverable via its DID. The DID is published to the
BitTorrent Mainline DHT and includes an `SCPRelay` service entry with your relay URL.

Any SCP client can resolve your DID and connect:

```
did:dht:z6Mk...  -->  wss://relay.example.com/scp/v1
```

The `/.well-known/scp` endpoint also serves relay metadata as JSON.

## Environment variables

| Variable | Default | Description |
|---|---|---|
| `SCP_RELAY_DOMAIN` | *(none)* | Domain name. Enables TLS and `wss://` relay URL. |
| `SCP_RELAY_ACME_EMAIL` | *(none)* | Contact email for Let's Encrypt. |
| `SCP_RELAY_BIND_ADDR` | `0.0.0.0:443` (domain) / `0.0.0.0:9000` (no domain) | HTTP/HTTPS bind address. |
| `SCP_RELAY_TLS_SELF_SIGNED` | `false` | Set `1` for self-signed cert (dev only). |
| `SCP_RELAY_TLS_CERT` | *(none)* | Path to PEM certificate chain (manual TLS). |
| `SCP_RELAY_TLS_KEY` | *(none)* | Path to PEM private key (manual TLS). |
| `SCP_RELAY_STORAGE_PATH` | `$XDG_DATA_HOME/scp/personal-relay` | SQLite database directory. |
| `SCP_RELAY_STORAGE_KEY` | *(auto-generated)* | Hex-encoded 32-byte SQLCipher key. |
| `SCP_RELAY_DHT_GATEWAYS` | *(built-in)* | Comma-separated DHT HTTP gateway URLs. |
| `SCP_RELAY_LOG_LEVEL` | `info` | Log level (overridden by `RUST_LOG`). |
| `SCP_RELAY_LOG_FORMAT` | `pretty` | `json` for structured output, `pretty` for human-readable. |

## Health check

```bash
# From the host
curl -f http://localhost:443/healthz

# Or use the built-in TCP probe (for Docker HEALTHCHECK, etc.)
./target/release/scp-personal-relay --health
```

The `--health` flag performs a TCP connect to the configured bind address and exits
with code 0 (reachable) or 1 (unreachable).

## Deployment

### Systemd

```ini
[Unit]
Description=SCP Personal Relay
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=scp
ExecStart=/usr/local/bin/scp-personal-relay
Environment=SCP_RELAY_DOMAIN=relay.example.com
Environment=SCP_RELAY_ACME_EMAIL=admin@example.com
Environment=SCP_RELAY_STORAGE_PATH=/var/lib/scp/personal-relay
Restart=on-failure
RestartSec=5

# Bind to port 443 without running as root
AmbientCapabilities=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
```

### Docker

Save the block below as `templates/personal-relay/Dockerfile`, then build from the repository
root:

```sh
docker build -f templates/personal-relay/Dockerfile -t scp-personal-relay .
```

The root context is not optional. `scp-personal-relay` declares its own `[workspace]`, so
`cargo build -p scp-personal-relay` finds no such package at the root; and its manifest names
six `crates/*` path dependencies, which a context rooted at this directory cannot reach.
Building the manifest by path from a root context satisfies both.

The builder tag names a Debian release and no Rust version. `COPY . .` brings the
repository's `rust-toolchain.toml` into the image, and rustup — which the official `rust`
image ships — reads that file for the `cargo build` below, so the container compiles on the
version that file names and on no other. Keep the builder stage and the runtime stage on the
same Debian release: glibc is backward compatible only, so a binary linked against a newer
release's glibc cannot exec on an older one.

```dockerfile
FROM rust:bookworm AS builder
WORKDIR /build
# `aws-lc-sys` runs cmake from its build script, `ring` runs perl, and `libsqlite3-sys`
# compiles SQLCipher against OpenSSL — the same build-script dependencies the root
# `Dockerfile` installs, because this template depends on the same crates.
RUN apt-get update \
    && apt-get install -y --no-install-recommends cmake perl pkg-config libssl-dev \
    && rm -rf /var/lib/apt/lists/*
COPY . .
# ASSERT-PINNED-RUSTC — every container build of this workspace carries these three lines
# verbatim, and `scripts/check-toolchain-wiring.sh` fails on one that does not. They make
# the image prove which compiler it resolved, so no reading of COPY lines has to.
RUN pin="$(sed -nE 's/^[[:space:]]*channel[[:space:]]*=[[:space:]]*"([^"]+)".*/\1/p' rust-toolchain.toml | head -n 1)"; \
    got="$(rustc --version | cut -d' ' -f2)"; \
    [ -n "$pin" ] && [ "$got" = "$pin" ] || { echo "image resolved rustc '$got'; rust-toolchain.toml names '$pin'" >&2; exit 1; }
RUN cargo build --release --manifest-path templates/personal-relay/Cargo.toml

FROM debian:bookworm-slim
# `libssl3` because the binary links `libcrypto.so.3` that SQLCipher pulls in.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates libssl3 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /build/templates/personal-relay/target/release/scp-personal-relay /usr/local/bin/
EXPOSE 443
VOLUME /data
ENV SCP_RELAY_STORAGE_PATH=/data
HEALTHCHECK CMD ["/usr/local/bin/scp-personal-relay", "--health"]
ENTRYPOINT ["/usr/local/bin/scp-personal-relay"]
```

```bash
docker run -d \
  -p 443:443 -p 80:80 \
  -v scp-relay-data:/data \
  -e SCP_RELAY_DOMAIN=relay.example.com \
  -e SCP_RELAY_ACME_EMAIL=admin@example.com \
  scp-personal-relay
```

### Behind a reverse proxy

If you run behind nginx, Caddy, or similar, use manual TLS certificates or let the
proxy handle TLS termination and forward plain HTTP to the relay:

```bash
SCP_RELAY_DOMAIN=relay.example.com \
SCP_RELAY_TLS_CERT=/path/to/fullchain.pem \
SCP_RELAY_TLS_KEY=/path/to/privkey.pem \
SCP_RELAY_BIND_ADDR=127.0.0.1:8443 \
  ./target/release/scp-personal-relay
```

## Storage

All persistent state is stored in the configured storage directory:

```
$SCP_RELAY_STORAGE_PATH/
  .key            # Auto-generated SQLCipher encryption key (mode 0600)
  custody/        # Ed25519 keypairs (SQLCipher-encrypted)
  blobs.db        # Relay blob storage (message payloads)
  *.db            # Node state (identity, BEP44 sequences, etc.)
```

Back up the entire directory to preserve your relay's identity. The `.key` file is
required to decrypt the databases -- without it, stored data is unrecoverable.
