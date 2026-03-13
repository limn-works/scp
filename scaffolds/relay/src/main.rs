//! Minimal SCP relay server.
//!
//! This scaffold demonstrates running a standalone SCP relay using
//! `scp-transport`'s `RelayServer` directly. This is the relay-only mode:
//! no DID identity, no HTTP endpoints, no `.well-known/scp` -- just a
//! WebSocket relay that accepts PUBLISH, SUBSCRIBE, QUERY, and DELETE
//! operations from any SCP client.
//!
//! For a full application node (relay + identity + HTTP), use
//! `scp_node::ApplicationNodeBuilder` instead. See `scp-node/src/main.rs`
//! for that pattern.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use scp_transport::native::server::{RelayConfig, RelayServer};
use scp_transport::native::storage::BlobStorageBackend;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // ── 1. Initialize tracing ────────────────────────────────────
    //
    // Reads RUST_LOG for filter level (e.g., RUST_LOG=debug).
    // Defaults to "info" if unset.
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .init();

    // ── 2. Configure the relay ───────────────────────────────────
    //
    // All fields have sensible defaults. Override what you need.
    // See `RelayConfig` docs for the full list of tuning knobs.
    let bind_addr: SocketAddr = "0.0.0.0:9000".parse()?;

    let config = RelayConfig {
        bind_addr,
        // Maximum blob payload size (256 KB default).
        max_blob_size: 262_144,
        // Maximum blob TTL in seconds (7 days default).
        max_blob_ttl: 604_800,
        // Connection limits.
        max_total_connections: 1_000,
        max_connections_per_ip: 10,
        // Rate limiting: PUBLISH ops per second per IP.
        rate_limit_publishes_per_second: 100,
        ..RelayConfig::default()
    };

    // ── 3. Choose a blob storage backend ─────────────────────────
    //
    // The relay stores blobs (encrypted message payloads) until they
    // expire or are deleted. Choose one:
    //
    //   In-memory (all data lost on restart):
    //     BlobStorageBackend::in_memory()
    //
    //   SQLite (persistent, single-file):
    //     BlobStorageBackend::sqlite(&PathBuf::from("./scp-relay.db"))?
    //
    //   redb (persistent, embedded):
    //     BlobStorageBackend::redb(&PathBuf::from("./scp-relay.redb"))?
    //     (requires "redb-blob" feature on scp-transport)
    //
    //   PostgreSQL (requires "postgres-blob" feature):
    //     PostgresBlobStore::open("postgres://...").await?
    //
    //   S3-compatible (requires "s3-blob" feature):
    //     S3BlobStore::open("bucket", "blobs/").await?
    let storage = BlobStorageBackend::sqlite(&PathBuf::from("./scp-relay.db"))?;

    // ── 4. Start the relay server ────────────────────────────────
    //
    // `RelayServer::new` takes the config and a blob storage backend.
    // `.start()` binds the WebSocket listener and returns a shutdown
    // handle plus the actual bound address (useful when port is 0).
    let server = RelayServer::new(config, Arc::new(storage));

    let (shutdown_handle, local_addr) = server.start().await?;

    tracing::info!(addr = %local_addr, "relay listening");

    // ── 5. Wait for shutdown signal ──────────────────────────────
    //
    // Gracefully stop on Ctrl+C or SIGTERM.
    shutdown_signal().await;

    tracing::info!("shutdown signal received, stopping relay");
    shutdown_handle.shutdown();
    tracing::info!("relay stopped");

    Ok(())
}

// ── TLS configuration (uncomment when certificates are available) ──
//
// The bare `RelayServer` does not handle TLS itself. For production
// deployments, terminate TLS at a reverse proxy (nginx, Caddy, etc.)
// or use `scp_node::ApplicationNodeBuilder` which provisions TLS
// certificates automatically via ACME (Let's Encrypt).
//
// Example nginx config:
//
//   upstream scp_relay {
//       server 127.0.0.1:9000;
//   }
//   server {
//       listen 443 ssl;
//       server_name relay.example.com;
//       ssl_certificate     /etc/letsencrypt/live/relay.example.com/fullchain.pem;
//       ssl_certificate_key /etc/letsencrypt/live/relay.example.com/privkey.pem;
//
//       location /scp/v1 {
//           proxy_pass http://scp_relay;
//           proxy_http_version 1.1;
//           proxy_set_header Upgrade $http_upgrade;
//           proxy_set_header Connection "upgrade";
//           proxy_set_header Host $host;
//       }
//   }

// ── Health check ─────────────────────────────────────────────────
//
// For container orchestrators (Docker, Kubernetes, systemd), probe
// the relay's bind address with a TCP connect:
//
//   curl -sf http://127.0.0.1:9000/ || exit 1
//
// Or use the `--health` flag in the full scp-relay binary:
//
//   scp-relay --health

/// Waits for Ctrl+C or SIGTERM (Unix).
async fn shutdown_signal() {
    let ctrl_c = tokio::signal::ctrl_c();

    #[cfg(unix)]
    {
        let mut sigterm =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .unwrap_or_else(|_| {
                    tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
                        .unwrap_or_else(|_| std::process::exit(1))
                });
        tokio::select! {
            _ = ctrl_c => {}
            _ = sigterm.recv() => {}
        }
    }

    #[cfg(not(unix))]
    {
        let _ = ctrl_c.await;
    }
}
