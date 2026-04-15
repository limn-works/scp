#![doc = include_str!("../README.md")]
#![warn(missing_docs)]
//! Standalone SCP native relay server.
//!
//! Reads configuration from environment variables, starts the relay, and
//! blocks until SIGINT or SIGTERM is received for graceful shutdown.
//!
//! Supports a `--health` flag that probes the relay's bind address via TCP
//! and exits with code 0 (reachable) or 1 (unreachable).
//!
//! ## Storage backend selection
//!
//! The relay selects a blob storage backend via the `SCP_RELAY_STORAGE_BACKEND`
//! environment variable. Valid values:
//!
//! | Value      | Backend    | Config env vars                              | Default |
//! |------------|------------|----------------------------------------------|---------|
//! | `sqlite`   | `SQLite`     | `SCP_RELAY_STORAGE_PATH` (default `./scp-relay.db`) | **yes** |
//! | `redb`     | redb       | `SCP_RELAY_STORAGE_PATH` (default `./scp-relay.redb`) | |
//! | `postgres` | `PostgreSQL` | `SCP_RELAY_DATABASE_URL` (required)           | |
//! | `s3`       | S3-compat  | `SCP_RELAY_S3_BUCKET` (required) + AWS env    | |
//! | `memory`   | In-memory  | —                                             | |
//!
//! See §10.5 of the SCP infrastructure spec.

use std::net::SocketAddr;

use scp_transport::startup;

#[tokio::main]
async fn main() {
    // Check for --health before initializing tracing (keep probe quiet).
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "--health") {
        let addr: SocketAddr = startup::env_or(
            "SCP_RELAY_BIND_ADDR",
            SocketAddr::from(([127, 0, 0, 1], 9000)),
        );
        startup::health_check(addr).await;
        // health_check always calls process::exit, but satisfy the compiler.
        return;
    }

    startup::init_tracing();

    let (handle, _local_addr, _storage) = startup::start_relay_from_env().await;

    // Start Prometheus metrics HTTP server on a separate port (#1467).
    let metrics_port = startup::env_or("SCP_RELAY_METRICS_PORT", 9001u16);
    let metrics_addr: SocketAddr = SocketAddr::from(([0, 0, 0, 0], metrics_port));
    let metrics_handle = spawn_metrics_server(metrics_addr).await;

    // Wait for shutdown signal (SIGINT / SIGTERM).
    startup::shutdown_signal().await;

    tracing::info!("shutdown signal received, stopping relay");
    if let Some(h) = metrics_handle {
        h.abort();
    }
    handle.shutdown();
    tracing::info!("relay stopped");
}

// ---------------------------------------------------------------------------
// Prometheus metrics (#1467)
// ---------------------------------------------------------------------------

/// Spawns a minimal axum HTTP server serving `/metrics` in Prometheus text
/// format. Returns the task handle so the caller can abort on shutdown.
///
/// Uses `metrics-exporter-prometheus` as the global recorder. If the metrics
/// port cannot be bound, a warning is logged and `None` is returned.
async fn spawn_metrics_server(addr: SocketAddr) -> Option<tokio::task::JoinHandle<()>> {
    use axum::response::IntoResponse;

    let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
    let handle = recorder.handle();
    let _ = metrics::set_global_recorder(recorder);

    let app = axum::Router::new().route(
        "/metrics",
        axum::routing::get(move || {
            let h = handle.clone();
            async move {
                let body = h.render();
                (
                    axum::http::StatusCode::OK,
                    [(
                        axum::http::header::CONTENT_TYPE,
                        "text/plain; version=0.0.4",
                    )],
                    body,
                )
                    .into_response()
            }
        }),
    );

    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            tracing::warn!(
                addr = %addr,
                error = %e,
                "failed to bind metrics server; metrics endpoint unavailable"
            );
            return None;
        }
    };

    let bound_addr = listener.local_addr().unwrap_or(addr);
    tracing::info!(addr = %bound_addr, "metrics server listening");

    Some(tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    }))
}
