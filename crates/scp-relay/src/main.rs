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
//! The operator names a blob storage backend in the `SCP_RELAY_STORAGE_BACKEND`
//! environment variable. That variable has no default: a relay that reads it
//! unset or empty prints an error naming the valid values and exits 1, as
//! persistence spec §17.7 and §17.17.1 (SCP-CAPSEL-8000, selection is
//! mandatory) require. No config variable in this table has a default either.
//!
//! | Value      | Backend    | Config env vars                               |
//! |------------|------------|-----------------------------------------------|
//! | `sqlite`   | `SQLite`     | `SCP_RELAY_STORAGE_PATH` (required, absolute) |
//! | `redb`     | redb       | `SCP_RELAY_STORAGE_PATH` (required, absolute) |
//! | `postgres` | `PostgreSQL` | `SCP_RELAY_DATABASE_URL` (required)           |
//! | `s3`       | S3-compat  | `SCP_RELAY_S3_BUCKET` (required) + AWS env    |
//! | `memory`   | In-memory  | —                                             |
//!
//! The `postgres` row exists only in a binary whose cargo invocation compiled
//! scp-transport's `postgres-blob` feature, and the `s3` row only with its
//! `s3-blob` feature. This crate's `cloud-blobs` feature enables both, and so
//! does `scp-node/cloud-blobs` in an invocation that builds both packages,
//! because Cargo unifies features across one invocation. A binary whose build
//! did not compile the selected backend exits on that value with an error
//! naming the missing feature.
//!
//! See §10.5 of the SCP infrastructure spec.

// Links the one `#[global_allocator]`, which wipes every heap block before
// freeing it (09-security-model.md §9.15, freed heap memory).
use scp_alloc as _;

use std::net::SocketAddr;

use scp_transport::startup;

#[tokio::main]
async fn main() {
    // Check for --health before initializing tracing (keep probe quiet).
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "--health") {
        let addr: SocketAddr = or_exit(startup::env_or(
            "SCP_RELAY_BIND_ADDR",
            SocketAddr::from(([127, 0, 0, 1], 9000)),
        ));
        if startup::health_check(addr).await {
            return;
        }
        std::process::exit(1);
    }

    or_exit(startup::init_tracing());

    let backend = or_exit(startup::backend_choice_from_env("cloud-blobs"));
    let shutdown = or_exit(startup::shutdown_signal());
    let (handle, _local_addr, _storage) = or_exit(startup::start_relay_from_env(backend).await);

    // Start Prometheus metrics HTTP server on a separate port (#1467).
    let metrics_port = or_exit(startup::env_or("SCP_RELAY_METRICS_PORT", 9001u16));
    let metrics_addr: SocketAddr = SocketAddr::from(([0, 0, 0, 0], metrics_port));
    let metrics_handle = spawn_metrics_server(metrics_addr).await;

    // Wait for shutdown signal (SIGINT / SIGTERM).
    shutdown.await;

    tracing::info!("shutdown signal received, stopping relay");
    if let Some(h) = metrics_handle {
        h.abort();
    }
    handle.shutdown();
    tracing::info!("relay stopped");
}

/// Returns the value inside `result`, or prints its [`startup::StartupError`]
/// to stderr and exits 1.
///
/// The `startup` library returns every failure to this binary, and this
/// function is where a failure becomes an exit code. The error goes to stderr
/// because tracing may not be installed yet, or may write elsewhere.
fn or_exit<T>(result: Result<T, startup::StartupError>) -> T {
    result.unwrap_or_else(|e| {
        eprintln!("error: {e}");
        std::process::exit(1);
    })
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
