//! Shared startup utilities for SCP relay and node binaries.
//!
//! Both `scp-relay` and `scp-node` binaries use identical logic for environment
//! variable parsing, relay configuration, blob storage backend selection,
//! tracing initialization, health checks, and graceful shutdown. This module
//! provides the shared implementations so changes need only be made once.
//!
//! Gated behind the `startup` feature. Not used by the library or FFI bridges.
//!
//! See §10.5 of the SCP infrastructure spec.

use std::env;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use tracing_subscriber::EnvFilter;

use crate::native::server::RelayConfig;
use crate::native::storage::BlobStorageBackend;

// ---------------------------------------------------------------------------
// env_or — typed environment variable with fallback
// ---------------------------------------------------------------------------

/// Reads an environment variable and parses it, returning the default on
/// absence or parse failure (with a warning).
pub fn env_or<T: std::str::FromStr>(name: &str, default: T) -> T {
    match env::var(name) {
        Ok(val) => val.parse().unwrap_or_else(|_| {
            tracing::warn!(
                var = name,
                value_len = val.len(),
                "invalid value, using default"
            );
            default
        }),
        Err(_) => default,
    }
}

// ---------------------------------------------------------------------------
// Relay configuration from environment
// ---------------------------------------------------------------------------

/// Builds a [`RelayConfig`] from `SCP_RELAY_*` environment variables.
///
/// | Variable | Default |
/// |---|---|
/// | `SCP_RELAY_BIND_ADDR` | `0.0.0.0:9000` |
/// | `SCP_RELAY_MAX_BLOB_SIZE` | 262,144 (256 KiB) |
/// | `SCP_RELAY_MAX_BLOB_TTL` | 604,800 (7 days) |
/// | `SCP_RELAY_MAX_CONNECTIONS` | 1,000 |
/// | `SCP_RELAY_MAX_CONNECTIONS_PER_IP` | 10 |
/// | `SCP_RELAY_RATE_LIMIT` | 100 |
#[must_use]
pub fn relay_config_from_env() -> RelayConfig {
    let bind_addr: SocketAddr = env_or(
        "SCP_RELAY_BIND_ADDR",
        SocketAddr::from(([0, 0, 0, 0], 9000)),
    );

    RelayConfig {
        bind_addr,
        max_blob_size: env_or("SCP_RELAY_MAX_BLOB_SIZE", 262_144),
        max_blob_ttl: env_or("SCP_RELAY_MAX_BLOB_TTL", 604_800),
        max_total_connections: env_or("SCP_RELAY_MAX_CONNECTIONS", 1_000),
        max_connections_per_ip: env_or("SCP_RELAY_MAX_CONNECTIONS_PER_IP", 10),
        rate_limit_publishes_per_second: env_or("SCP_RELAY_RATE_LIMIT", 100),
        ..RelayConfig::default()
    }
}

// ---------------------------------------------------------------------------
// Blob storage backend from environment
// ---------------------------------------------------------------------------

/// One row of [`BACKENDS`]: a value an operator can write into
/// `SCP_RELAY_STORAGE_BACKEND`, and what it takes to compile the arm of
/// [`storage_from_env`] that constructs it.
struct Backend {
    /// The value an operator writes into `SCP_RELAY_STORAGE_BACKEND`.
    name: &'static str,
    /// The `scp-transport` feature that compiles this backend's arm, or `None`
    /// for an arm no feature gates.
    transport_feature: Option<&'static str>,
    /// Whether this build enabled that feature.
    compiled: bool,
    /// The `scp-node` / `scp-relay` feature an operator enables to get
    /// `transport_feature`, or `None` when no binary feature gates it. This
    /// module compiles only under `startup`, which `scp-node` and `scp-relay`
    /// are the only two crates to enable, so naming their feature here tells a
    /// reader of the diagnostic what to pass to `cargo build`.
    binary_feature: Option<&'static str>,
}

/// Every value [`storage_from_env`] recognizes, paired with whether this build
/// compiled the arm that constructs it.
///
/// A backend's gating feature is written in three places, and this table is one
/// of them:
///
/// 1. The `#[cfg]` attribute on the arm of [`storage_from_env`] that constructs
///    the backend, which decides whether the binary can open it at all.
/// 2. This table, twice per row: `transport_feature`, which
///    `reject_backend_message` prints in its rebuild instruction, and
///    `compiled`, which decides whether that message prints at all or the value
///    reads as a typo instead.
/// 3. The `cfg`-gated macro pair beneath this table that contributes the
///    backend's name to [`VALID_BACKENDS`] — the options list both messages
///    interpolate.
///
/// Nothing in the type system holds the three in agreement, so a fifth backend
/// needs an edit at all three and three tests fail on a missing one.
/// `every_site_names_the_same_feature_for_a_backend` reads the feature name out
/// of each site's source text and fails when any two disagree, whatever
/// features this build enabled. `every_constructor_arm_has_a_table_row` fails
/// on an arm no row names. `the_constant_and_the_table_agree_on_what_is_compiled`
/// fails when the constant offers a name the `compiled` column calls absent.
const BACKENDS: &[Backend] = &[
    Backend {
        name: "sqlite",
        transport_feature: Some("sqlite-blob"),
        compiled: cfg!(feature = "sqlite-blob"),
        binary_feature: None,
    },
    Backend {
        name: "redb",
        transport_feature: Some("redb-blob"),
        compiled: cfg!(feature = "redb-blob"),
        binary_feature: None,
    },
    Backend {
        name: "postgres",
        transport_feature: Some("postgres-blob"),
        compiled: cfg!(feature = "postgres-blob"),
        binary_feature: Some("cloud-blobs"),
    },
    Backend {
        name: "s3",
        transport_feature: Some("s3-blob"),
        compiled: cfg!(feature = "s3-blob"),
        binary_feature: Some("cloud-blobs"),
    },
    Backend {
        name: "memory",
        transport_feature: None,
        compiled: true,
        binary_feature: None,
    },
];

// `VALID_BACKENDS` below stays a `&'static str`, because `scp-transport`
// publishes that name and that type. Selecting one whole literal per feature
// state would need a definition per combination, and four gated backends give
// sixteen; these four macro pairs produce the same string from a list that
// grows by one pair per backend instead. Each pair expands to its backend's
// name and a separator when the `scp-transport` feature that compiles that
// backend's arm of `storage_from_env` is enabled, and to nothing when it is
// not, so every combination comes out exact. `memory` needs no pair: no feature
// gates it, and it closes the list, so it carries no separator.
#[cfg(feature = "sqlite-blob")]
macro_rules! sqlite_entry {
    () => {
        "sqlite, "
    };
}
#[cfg(not(feature = "sqlite-blob"))]
macro_rules! sqlite_entry {
    () => {
        ""
    };
}
#[cfg(feature = "redb-blob")]
macro_rules! redb_entry {
    () => {
        "redb, "
    };
}
#[cfg(not(feature = "redb-blob"))]
macro_rules! redb_entry {
    () => {
        ""
    };
}
#[cfg(feature = "postgres-blob")]
macro_rules! postgres_entry {
    () => {
        "postgres, "
    };
}
#[cfg(not(feature = "postgres-blob"))]
macro_rules! postgres_entry {
    () => {
        ""
    };
}
#[cfg(feature = "s3-blob")]
macro_rules! s3_entry {
    () => {
        "s3, "
    };
}
#[cfg(not(feature = "s3-blob"))]
macro_rules! s3_entry {
    () => {
        ""
    };
}

/// The `SCP_RELAY_STORAGE_BACKEND` values this build can construct, comma
/// separated, for diagnostics and help text.
///
/// A name appears here only when the `scp-transport` feature that compiles its
/// arm of [`storage_from_env`] is enabled, so this constant never offers a
/// backend the binary cannot open. A build with neither cloud feature reads
/// `"sqlite, redb, memory"`; one with both reads
/// `"sqlite, redb, postgres, s3, memory"`.
///
/// This was the hardcoded string `"sqlite, redb, postgres, s3, memory"` until
/// `scp-node` and `scp-relay` stopped enabling `postgres-blob` and `s3-blob` by
/// default, at which point a default build rejected `postgres` and then listed
/// `postgres` among the valid options.
pub const VALID_BACKENDS: &str = concat!(
    sqlite_entry!(),
    redb_entry!(),
    postgres_entry!(),
    s3_entry!(),
    "memory"
);

/// Reports whether this build compiled the arm of [`storage_from_env`] that
/// constructs `name`, for a caller that has to predict which of two outcomes a
/// binary linking this crate will produce.
///
/// This reads the `compiled` column of the private `BACKENDS` table, which is a
/// [`cfg!`] read of the same feature that gates the arm. It deliberately does
/// not parse [`VALID_BACKENDS`]: a test that compared a binary's diagnostic
/// against a prediction parsed out of the very constant that diagnostic is
/// built from would assert a tautology, and would stay green through a revert of
/// `VALID_BACKENDS` to the hardcoded list that named backends a default build
/// cannot construct.
#[must_use]
pub fn backend_is_compiled(name: &str) -> bool {
    BACKENDS.iter().any(|b| b.name == name && b.compiled)
}

/// Writes the message [`storage_from_env`] prints before it exits, for a
/// `SCP_RELAY_STORAGE_BACKEND` value it will not construct.
///
/// The message separates two cases an operator has to tell apart:
///
/// - `requested` names no backend at all, so the operator mistyped a value and
///   the message lists what this build accepts.
/// - `requested` names a backend this build did not compile, so the operator
///   wrote a real value and needs the cargo feature that compiles it.
fn reject_backend_message(requested: &str) -> String {
    let uncompiled = BACKENDS.iter().find(|b| b.name == requested && !b.compiled);

    let Some(backend) = uncompiled else {
        return format!(
            "error: unknown storage backend '{requested}'. Valid options: {VALID_BACKENDS}"
        );
    };

    let rebuild = match (backend.binary_feature, backend.transport_feature) {
        (Some(binary), Some(transport)) => format!(
            "Rebuild the binary with `--features {binary}`, which enables `scp-transport/{transport}`."
        ),
        (None, Some(transport)) => {
            format!("Rebuild with `scp-transport/{transport}` enabled.")
        }
        (_, None) => String::from("Rebuild with that backend's cargo feature enabled."),
    };

    format!(
        "error: storage backend '{requested}' is not compiled into this binary. \
         {rebuild} Compiled-in options: {VALID_BACKENDS}"
    )
}

/// Constructs the blob storage backend from environment configuration.
///
/// Reads `SCP_RELAY_STORAGE_BACKEND` (default: `sqlite`) and delegates to the
/// backend constructor that value names. On a value this build cannot
/// construct, it prints the message the private `reject_backend_message` writes
/// and calls [`std::process::exit`].
///
/// # Storage backend selection
///
/// | Value | Backend | Config env vars | Compiled in by |
/// |---|---|---|---|
/// | `sqlite` | `SQLite` | `SCP_RELAY_STORAGE_PATH` (default `./scp-relay.db`) | always; the default value |
/// | `redb` | redb | `SCP_RELAY_STORAGE_PATH` (default `./scp-relay.redb`) | always |
/// | `postgres` | `PostgreSQL` | `SCP_RELAY_DATABASE_URL` (required) | `cloud-blobs` |
/// | `s3` | S3-compat | `SCP_RELAY_S3_BUCKET` (required) + AWS env | `cloud-blobs` |
/// | `memory` | In-memory | — | always |
///
/// # Exit codes
///
/// Every failure path here exits the process with code 1 rather than returning,
/// because a relay that cannot open its blob store has nothing to serve. The
/// function exits when the requested backend names nothing, when it names a
/// backend this build did not compile, when a required env var is absent, and
/// when the backend constructor fails.
///
/// Each arm compiles only under its `scp-transport` feature (`sqlite-blob`,
/// `redb-blob`, `postgres-blob`, `s3-blob`), and `scp-node` and `scp-relay`
/// leave `postgres-blob` and `s3-blob` off unless a build passes
/// `--features cloud-blobs`. A request for an uncompiled backend prints the
/// feature to rebuild with; it never falls back to another backend.
///
/// The `postgres` and `s3` arms are the only ones that await, so a build that
/// compiles neither leaves this function with nothing to await and
/// `clippy::unused_async` fires. The attribute below silences the lint in
/// exactly that configuration and nowhere else, which keeps the workspace's
/// rule — an async function with no await justifies itself at every
/// free-function site — answered here rather than waived. The signature keeps
/// `async`: a `cloud-blobs` build does await inside it, and
/// [`start_relay_from_env`] awaits the call either way.
#[cfg_attr(
    not(any(feature = "postgres-blob", feature = "s3-blob")),
    expect(
        clippy::unused_async,
        reason = "the only two arms that await are compiled out of this build"
    )
)]
pub async fn storage_from_env() -> BlobStorageBackend {
    let backend = env::var("SCP_RELAY_STORAGE_BACKEND")
        .unwrap_or_else(|_| "sqlite".to_owned())
        .to_lowercase();

    match backend.as_str() {
        #[cfg(feature = "sqlite-blob")]
        "sqlite" => {
            let path =
                env::var("SCP_RELAY_STORAGE_PATH").unwrap_or_else(|_| "./scp-relay.db".to_owned());
            let path = PathBuf::from(path);
            tracing::info!(path = %path.display(), "using sqlite blob storage");
            BlobStorageBackend::sqlite(&path).unwrap_or_else(|e| {
                tracing::error!(error = %e, path = %path.display(), "failed to open sqlite storage");
                std::process::exit(1);
            })
        }
        #[cfg(feature = "redb-blob")]
        "redb" => {
            let path = env::var("SCP_RELAY_STORAGE_PATH")
                .unwrap_or_else(|_| "./scp-relay.redb".to_owned());
            let path = PathBuf::from(path);
            tracing::info!(path = %path.display(), "using redb blob storage");
            BlobStorageBackend::redb(&path).unwrap_or_else(|e| {
                tracing::error!(error = %e, path = %path.display(), "failed to open redb storage");
                std::process::exit(1);
            })
        }
        #[cfg(feature = "postgres-blob")]
        "postgres" => {
            let Ok(url) = env::var("SCP_RELAY_DATABASE_URL") else {
                eprintln!(
                    "error: SCP_RELAY_STORAGE_BACKEND=postgres requires SCP_RELAY_DATABASE_URL to be set"
                );
                std::process::exit(1);
            };
            tracing::info!("using postgres blob storage");
            let store = crate::native::postgres_blob::PostgresBlobStore::open(&url)
                .await
                .unwrap_or_else(|e| {
                    tracing::error!(error = %e, "failed to connect to postgres");
                    std::process::exit(1);
                });
            BlobStorageBackend::Postgres(store)
        }
        #[cfg(feature = "s3-blob")]
        "s3" => {
            let Ok(bucket) = env::var("SCP_RELAY_S3_BUCKET") else {
                eprintln!(
                    "error: SCP_RELAY_STORAGE_BACKEND=s3 requires SCP_RELAY_S3_BUCKET to be set"
                );
                std::process::exit(1);
            };
            let prefix = env::var("SCP_RELAY_S3_PREFIX").unwrap_or_else(|_| "blobs/".to_owned());
            tracing::info!(bucket = %bucket, prefix = %prefix, "using s3 blob storage");
            let store = crate::native::s3_blob::S3BlobStore::open(&bucket, &prefix)
                .await
                .unwrap_or_else(|e| {
                    tracing::error!(error = %e, "failed to initialize s3 storage");
                    std::process::exit(1);
                });
            BlobStorageBackend::S3(store)
        }
        "memory" => {
            tracing::warn!("using in-memory blob storage — all data will be lost on restart");
            BlobStorageBackend::in_memory()
        }
        other => {
            eprintln!("{}", reject_backend_message(other));
            std::process::exit(1);
        }
    }
}

// ---------------------------------------------------------------------------
// Tracing initialization
// ---------------------------------------------------------------------------

/// Initializes the `tracing` subscriber.
///
/// Log level is determined by `RUST_LOG` (takes precedence) or
/// `SCP_RELAY_LOG_LEVEL` (default: `info`). Output format is controlled
/// by `SCP_RELAY_LOG_FORMAT`: `json` for structured JSON, anything else
/// for human-readable pretty output.
pub fn init_tracing() {
    let default_level = env::var("SCP_RELAY_LOG_LEVEL").unwrap_or_else(|_| "info".into());
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        EnvFilter::try_new(&default_level).unwrap_or_else(|_| EnvFilter::new("info"))
    });

    let format = env::var("SCP_RELAY_LOG_FORMAT").unwrap_or_else(|_| "pretty".into());

    if format == "json" {
        tracing_subscriber::fmt()
            .json()
            .with_writer(std::io::stderr)
            .with_env_filter(filter)
            .init();
    } else {
        tracing_subscriber::fmt()
            .with_writer(std::io::stderr)
            .with_env_filter(filter)
            .init();
    }
}

// ---------------------------------------------------------------------------
// Health check
// ---------------------------------------------------------------------------

/// Runs a TCP health probe: attempts a connection to `addr` and exits with
/// code 0 on success, 1 on failure.
///
/// Designed for container health checks (`--health` CLI flag).
pub async fn health_check(addr: SocketAddr) {
    match tokio::net::TcpStream::connect(addr).await {
        Ok(_) => std::process::exit(0),
        Err(_) => std::process::exit(1),
    }
}

// ---------------------------------------------------------------------------
// Shutdown signal
// ---------------------------------------------------------------------------

/// Waits for either SIGINT (`ctrl_c`) or SIGTERM.
///
/// On non-Unix platforms, only `ctrl_c` is supported.
pub async fn shutdown_signal() {
    let ctrl_c = tokio::signal::ctrl_c();

    #[cfg(unix)]
    {
        let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .unwrap_or_else(|_| {
                // If we cannot register SIGTERM, fall back to ctrl_c only.
                // This is unreachable on any standard Unix system but
                // satisfies the no-panic lint without process::exit.
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

// ---------------------------------------------------------------------------
// Relay startup helper
// ---------------------------------------------------------------------------

/// Starts a relay server from environment configuration and returns the
/// server handle, bound address, and storage reference.
///
/// This encapsulates the common pattern of reading config + storage from env,
/// building the relay, starting it, and logging the result.
pub async fn start_relay_from_env() -> (
    crate::native::server::ShutdownHandle,
    SocketAddr,
    Arc<BlobStorageBackend>,
) {
    let config = relay_config_from_env();
    tracing::info!(
        bind_addr = %config.bind_addr,
        max_blob_size = config.max_blob_size,
        max_connections = config.max_total_connections,
        "starting relay"
    );

    let storage = Arc::new(storage_from_env().await);
    let server = crate::native::server::RelayServer::new(config, Arc::clone(&storage));

    let (handle, local_addr) = match server.start().await {
        Ok(pair) => pair,
        Err(e) => {
            tracing::error!(error = %e, "relay failed to start");
            std::process::exit(1);
        }
    };

    tracing::info!(addr = %local_addr, "relay listening");

    (handle, local_addr, storage)
}

#[cfg(test)]
mod tests {
    use super::{BACKENDS, VALID_BACKENDS, backend_is_compiled, reject_backend_message};

    /// A value naming no backend reads as a typo, and the message lists what
    /// this build accepts instead of naming a rebuild.
    #[test]
    fn an_unrecognized_value_is_reported_as_unknown() {
        let message = reject_backend_message("banana");
        assert!(
            message.contains("unknown storage backend 'banana'"),
            "{message}"
        );
        assert!(!message.contains("not compiled"), "{message}");
        assert!(message.contains("memory"), "{message}");
    }

    /// `VALID_BACKENDS` names a backend exactly when this build compiled that
    /// backend's arm. The constant was hardcoded until `postgres-blob` and
    /// `s3-blob` stopped being unconditional, and this test fails on that
    /// hardcoded value for any build leaving a backend feature off.
    #[test]
    fn the_options_list_names_every_compiled_backend_and_no_other() {
        let names: Vec<&str> = VALID_BACKENDS.split(", ").collect();

        for (name, enabled) in [
            ("sqlite", cfg!(feature = "sqlite-blob")),
            ("redb", cfg!(feature = "redb-blob")),
            ("postgres", cfg!(feature = "postgres-blob")),
            ("s3", cfg!(feature = "s3-blob")),
            ("memory", true),
        ] {
            assert_eq!(
                names.contains(&name),
                enabled,
                "'{name}' should appear in VALID_BACKENDS exactly when its \
                 feature is enabled; the constant read '{VALID_BACKENDS}'"
            );
        }
    }

    /// Two places read the same four `cfg` flags: the macro pairs that build
    /// `VALID_BACKENDS`, and the `compiled` column of [`BACKENDS`] that decides
    /// whether a name reads as absent or as a typo. Adding a backend to one and
    /// forgetting the other would let the constant offer a name that
    /// `reject_backend_message` calls uncompiled, so this pins the two together.
    #[test]
    fn the_constant_and_the_table_agree_on_what_is_compiled() {
        let from_table = BACKENDS
            .iter()
            .filter(|b| b.compiled)
            .map(|b| b.name)
            .collect::<Vec<_>>()
            .join(", ");
        assert_eq!(VALID_BACKENDS, from_table);
    }

    /// The text of `storage_from_env`'s dispatch, from the `match` line to the
    /// catch-all arm, read out of this file rather than out of the compiled
    /// match.
    ///
    /// A `cfg` attribute removes an arm from the match this build compiles and
    /// never from the source, so a scan of this text sees all five arms and
    /// their gates whatever features are enabled.
    fn dispatch_body() -> &'static str {
        let source = include_str!("startup.rs");
        let dispatch = source
            .split_once("    match backend.as_str() {")
            .map(|(_, rest)| rest);
        assert!(
            dispatch.is_some(),
            "storage_from_env no longer dispatches on `match backend.as_str()`, \
             so this scan reads nothing"
        );
        let body = dispatch
            .unwrap_or_default()
            .split_once("\n        other =>")
            .map(|(head, _)| head);
        assert!(
            body.is_some(),
            "the dispatch no longer ends in a catch-all `other` arm, so this \
             scan has no end marker"
        );
        body.unwrap_or_default()
    }

    /// The text between two markers, or a failure naming the marker that is
    /// gone.
    fn source_region(open: &str, close: &str) -> &'static str {
        let source = include_str!("startup.rs");
        let after = source.split_once(open).map(|(_, rest)| rest);
        assert!(after.is_some(), "this file no longer contains `{open}`");
        let region = after
            .unwrap_or_default()
            .split_once(close)
            .map(|(head, _)| head);
        assert!(
            region.is_some(),
            "this file no longer contains `{close}` after `{open}`"
        );
        region.unwrap_or_default()
    }

    /// The feature name in a line that reads `#[cfg(feature = "…")]`, and
    /// `None` for any other line — `#[cfg(not(feature = "…"))]` included, since
    /// that prefix does not match.
    fn positive_cfg_feature(line: &str) -> Option<&str> {
        line.trim_start()
            .strip_prefix("#[cfg(feature = \"")
            .and_then(|rest| rest.split_once("\")]"))
            .map(|(feature, _)| feature)
    }

    /// The feature name in a line that reads `#[cfg(not(feature = "…"))]`, and
    /// `None` for any other line — `#[cfg(feature = "…")]` included, since that
    /// prefix does not match.
    fn negative_cfg_feature(line: &str) -> Option<&str> {
        line.trim_start()
            .strip_prefix("#[cfg(not(feature = \"")
            .and_then(|rest| rest.split_once("\"))]"))
            .map(|(feature, _)| feature)
    }

    /// No two rows of the table claim the same name, and the set of rows is the
    /// one this module was written against.
    ///
    /// This compares the table against a literal, so it fails when a row is
    /// added or dropped and says nothing about the arms of
    /// [`storage_from_env`]. `every_constructor_arm_has_a_table_row` below is
    /// what ties the two together.
    #[test]
    fn every_table_row_names_a_distinct_backend() {
        let mut names: Vec<&str> = BACKENDS.iter().map(|b| b.name).collect();
        let count = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), count, "duplicate backend name in BACKENDS");
        assert_eq!(
            names,
            ["memory", "postgres", "redb", "s3", "sqlite"],
            "BACKENDS must name every value storage_from_env matches on"
        );
    }

    /// The arms of [`storage_from_env`] and the rows of [`BACKENDS`] name the
    /// same set of values.
    ///
    /// The test above compares the table against a literal, so it catches a row
    /// added without an arm and cannot catch an arm added without a row. That
    /// second direction reproduces the defect this module exists to remove: a
    /// `match` arm no row names is a backend [`reject_backend_message`] reports
    /// as unknown rather than as uncompiled, so an operator who asked for a real
    /// backend is told the value names nothing and is handed no feature to
    /// rebuild with.
    ///
    /// The scan reads this file's own text, so it sees every arm whatever
    /// features this build enabled: a `cfg` attribute removes an arm from the
    /// compiled match, never from the source.
    #[test]
    fn every_constructor_arm_has_a_table_row() {
        let body = dispatch_body();

        let mut arms: Vec<&str> = body
            .lines()
            .filter_map(|line| line.trim_start().strip_prefix('"'))
            .filter_map(|rest| rest.split_once("\" =>"))
            .map(|(name, _)| name)
            .collect();
        assert!(
            !arms.is_empty(),
            "the scan matched no arm, so it would pass over any drift"
        );

        let mut rows: Vec<&str> = BACKENDS.iter().map(|b| b.name).collect();
        arms.sort_unstable();
        rows.sort_unstable();
        assert_eq!(
            arms, rows,
            "every arm of storage_from_env needs a BACKENDS row and every row \
             needs an arm; an arm with no row reports as an unknown backend"
        );
    }

    /// Every site that names a backend's gating feature names the same one.
    ///
    /// A backend's name and its `scp-transport` feature are written out four
    /// times in this file, and no two of the four are tied together by the type
    /// system:
    ///
    /// 1. `#[cfg(feature = "…")]` on the arm of [`storage_from_env`] that
    ///    constructs the backend — the gate that decides whether the binary can
    ///    open it.
    /// 2. `transport_feature` in the backend's [`BACKENDS`] row — the feature
    ///    name `reject_backend_message` prints in its rebuild instruction.
    /// 3. `compiled: cfg!(feature = "…")` in that same row — what decides
    ///    whether the operator is told the value is unknown or is told to
    ///    rebuild.
    /// 4. The `#[cfg]` on the macro pair that contributes the name to
    ///    [`VALID_BACKENDS`] — the options list both messages interpolate.
    ///
    /// Every other test in this module compares values a `cfg` already
    /// resolved, so each can see a mismatch only in a build whose feature state
    /// distinguishes the two sides it reads. The two states CI compiles — all
    /// four blob features off, and all four on — distinguish none of these: a
    /// row, an arm, or a macro pair gated on a sibling backend's feature reads
    /// identically to a correct one when every sibling is off and when every
    /// sibling is on. So a copy-pasted row that kept `postgres-blob` in its
    /// `compiled` column while its arm reads `gcs-blob` passes both lanes, and
    /// ships a relay that either rejects a backend it can open or offers one it
    /// cannot — the regression `crates/scp-relay/tests/storage_backend.rs`
    /// exists to keep out.
    ///
    /// This scan reads the four literals out of the file's own text, which is
    /// the same text under every feature state, so it fails on the first
    /// compile whatever CI enabled.
    #[test]
    fn every_site_names_the_same_feature_for_a_backend() {
        // The table, as the compiler sees it: `(name, transport_feature)`.
        let mut table: Vec<(&str, Option<&str>)> = BACKENDS
            .iter()
            .map(|b| (b.name, b.transport_feature))
            .collect();

        // Site 1: the `#[cfg]` above each dispatch arm. A `#[cfg]` line sets
        // the pending feature and the arm line immediately below consumes it,
        // so an arm no `#[cfg]` precedes reads `None` — which is what `memory`
        // must read.
        let mut arm_sites: Vec<(&str, Option<&str>)> = Vec::new();
        let mut pending: Option<&str> = None;
        for line in dispatch_body().lines() {
            if let Some(feature) = positive_cfg_feature(line) {
                pending = Some(feature);
                continue;
            }
            if let Some((name, _)) = line
                .trim_start()
                .strip_prefix('"')
                .and_then(|rest| rest.split_once("\" =>"))
            {
                arm_sites.push((name, pending.take()));
            }
        }
        assert!(
            !arm_sites.is_empty(),
            "the dispatch scan matched no arm, so it would pass over any drift"
        );

        // Sites 2 and 3: each row's `name` paired with the feature its
        // `compiled` column reads, taken from the table's source text rather
        // than from the resolved `bool`.
        let mut compiled_sites: Vec<(&str, Option<&str>)> = Vec::new();
        for row in source_region("const BACKENDS: &[Backend] = &[", "\n];")
            .split("Backend {")
            .skip(1)
        {
            let name = row
                .split_once("name: \"")
                .and_then(|(_, rest)| rest.split_once('"'))
                .map(|(name, _)| name);
            assert!(name.is_some(), "a BACKENDS row carries no `name: \"…\"`");
            let feature = row
                .split_once("compiled: cfg!(feature = \"")
                .and_then(|(_, rest)| rest.split_once('"'))
                .map(|(feature, _)| feature);
            assert!(
                feature.is_some() || row.contains("compiled: true,"),
                "a BACKENDS row's `compiled` column is neither \
                 `cfg!(feature = \"…\")` nor the literal `true`, so this scan \
                 cannot read the feature it gates on"
            );
            compiled_sites.push((name.unwrap_or_default(), feature));
        }

        // Site 4: the `#[cfg]` on each positive half of a `*_entry` macro pair,
        // paired with the name that half expands to. The negative halves read
        // `#[cfg(not(feature = "…"))]`, which `positive_cfg_feature` skips, so
        // their empty expansion finds no pending feature and contributes
        // nothing.
        let mut macro_sites: Vec<(&str, Option<&str>)> = Vec::new();
        let mut pending_entry_feature: Option<&str> = None;
        let entry_region = source_region(
            "const BACKENDS: &[Backend] = &[",
            "pub const VALID_BACKENDS",
        );
        for line in entry_region.lines() {
            if let Some(feature) = positive_cfg_feature(line) {
                pending_entry_feature = Some(feature);
                continue;
            }
            // `take()` sits second in the chain, so it runs only on a line that
            // is an expansion: the `macro_rules!` and `() => {` lines sit
            // between a pair's `#[cfg]` and its expansion, and a `take()` on
            // every line would clear the feature before the expansion reads it.
            let expansion = line
                .trim_start()
                .strip_prefix('"')
                .and_then(|rest| rest.strip_suffix('"'))
                .and_then(|entry| entry.strip_suffix(", "));
            if let Some(name) = expansion
                && let Some(feature) = pending_entry_feature.take()
            {
                macro_sites.push((name, Some(feature)));
            }
        }
        assert!(
            !macro_sites.is_empty(),
            "the macro-pair scan matched no entry, so it would pass over any drift"
        );

        // `memory` is gated by nothing and closes `VALID_BACKENDS` with no
        // separator, so it is the one row with no macro pair.
        let mut gated: Vec<(&str, Option<&str>)> = table
            .iter()
            .filter(|(_, feature)| feature.is_some())
            .copied()
            .collect();

        table.sort_unstable();
        arm_sites.sort_unstable();
        compiled_sites.sort_unstable();
        macro_sites.sort_unstable();
        gated.sort_unstable();

        assert_eq!(
            arm_sites, table,
            "each arm of storage_from_env must be gated on the feature its \
             BACKENDS row names in `transport_feature`, which is the feature \
             reject_backend_message tells the operator to rebuild with"
        );
        assert_eq!(
            compiled_sites, table,
            "each row's `compiled` column must read the same feature the row \
             names in `transport_feature`; a row reading a sibling's feature \
             reports a compiled backend as absent"
        );
        assert_eq!(
            macro_sites, gated,
            "each `*_entry` macro pair must be gated on the feature the row it \
             names carries in `transport_feature`; a pair reading a sibling's \
             feature makes VALID_BACKENDS offer a backend this build cannot open"
        );
    }

    /// Both halves of every `*_entry` macro pair read one feature, and the
    /// negative half expands to nothing.
    ///
    /// `every_site_names_the_same_feature_for_a_backend` above holds site 4 —
    /// the `#[cfg]` on the macro pair that contributes a name to
    /// [`VALID_BACKENDS`] — by reading the positive half of each pair. Each
    /// pair carries two `#[cfg]` attributes, `positive_cfg_feature` returns
    /// `None` for the negative one, and the negative half expands to `""`,
    /// which fails that scan's `", "` suffix test, so four of the eight
    /// attributes on the four pairs go unread there.
    ///
    /// The argument that test makes for scanning source text applies to those
    /// four attributes. The two feature states CI compiles are all four blob
    /// features off and all four on. A negative half gated on a sibling
    /// backend's feature reads identically to a correct one in both: with every
    /// blob feature off, the sibling-gated negative half is present and expands
    /// to `""`, which is what the correct half does; with every blob feature
    /// on, it is absent, which is also what the correct half does. The two
    /// states that distinguish them are mixed states no CI command builds. In
    /// one of them both definitions of the macro exist, the second shadows the
    /// first, and `VALID_BACKENDS` drops a backend whose arm this build
    /// compiled, so the relay refuses to offer an option it can open. In the
    /// other neither definition exists and the crate does not compile.
    ///
    /// A negative half expands to `""`, which carries no backend name, so this
    /// test ties a pair's two halves to each other through the macro's own
    /// name. The test above ties the positive half to the [`BACKENDS`] row, so
    /// the two tests together tie both halves to that row.
    #[test]
    fn both_halves_of_a_macro_pair_read_one_feature() {
        let entry_region = source_region(
            "const BACKENDS: &[Backend] = &[",
            "pub const VALID_BACKENDS",
        );

        // Each definition, as `(macro name, feature, negated, expansion)`. A
        // `#[cfg]` line sets the pending feature, the `macro_rules!` line below
        // it consumes that feature and opens a definition, and the expansion
        // line inside the body attaches to the definition most recently opened.
        let mut halves: Vec<(&str, &str, bool, Option<&str>)> = Vec::new();
        let mut pending: Option<(&str, bool)> = None;
        for line in entry_region.lines() {
            if let Some(feature) = positive_cfg_feature(line) {
                pending = Some((feature, false));
                continue;
            }
            if let Some(feature) = negative_cfg_feature(line) {
                pending = Some((feature, true));
                continue;
            }
            if let Some(name) = line
                .trim_start()
                .strip_prefix("macro_rules! ")
                .and_then(|rest| rest.split_once(' '))
                .map(|(name, _)| name)
            {
                assert!(
                    pending.is_some(),
                    "`macro_rules! {name}` carries no `#[cfg(feature = \"…\")]` \
                     and no `#[cfg(not(feature = \"…\"))]` line above it, so \
                     this scan cannot read the feature that definition gates on"
                );
                let (feature, negated) = pending.take().unwrap_or_default();
                halves.push((name, feature, negated, None));
                continue;
            }
            if let Some(expansion) = line
                .trim_start()
                .strip_prefix('"')
                .and_then(|rest| rest.strip_suffix('"'))
                && let Some(half) = halves.last_mut()
            {
                half.3 = Some(expansion);
            }
        }
        assert!(
            !halves.is_empty(),
            "the macro-pair scan matched no definition, so it would pass over \
             any drift"
        );

        let mut positives: Vec<(&str, &str)> = Vec::new();
        let mut negatives: Vec<(&str, &str)> = Vec::new();
        for &(name, feature, negated, expansion) in &halves {
            if negated {
                assert_eq!(
                    expansion,
                    Some(""),
                    "the `#[cfg(not(feature = \"{feature}\"))]` half of \
                     `{name}` must expand to the empty string, so a build \
                     without that feature leaves the backend out of \
                     VALID_BACKENDS"
                );
                negatives.push((name, feature));
            } else {
                positives.push((name, feature));
            }
        }
        positives.sort_unstable();
        negatives.sort_unstable();
        assert_eq!(
            negatives, positives,
            "each `*_entry` macro pair must gate both of its halves on one \
             feature, and must carry exactly one half of each sign; halves \
             naming two features leave one feature state with both definitions, \
             where the second shadows the first and VALID_BACKENDS omits a \
             backend whose arm compiled, and another state with neither, where \
             this crate does not compile"
        );
    }

    /// [`backend_is_compiled`] answers from the `cfg!` reads in [`BACKENDS`],
    /// not from [`VALID_BACKENDS`].
    ///
    /// That is what makes `scp-relay`'s `invalid_backend_exits_with_error` a
    /// comparison between the binary's message and this build's features. A
    /// predicate that parsed `VALID_BACKENDS` would make that test compare the
    /// constant against itself, which stays green through a revert of the
    /// constant to a hardcoded list.
    #[test]
    fn the_compiled_predicate_answers_from_the_features() {
        for (name, enabled) in [
            ("sqlite", cfg!(feature = "sqlite-blob")),
            ("redb", cfg!(feature = "redb-blob")),
            ("postgres", cfg!(feature = "postgres-blob")),
            ("s3", cfg!(feature = "s3-blob")),
            ("memory", true),
        ] {
            assert_eq!(
                backend_is_compiled(name),
                enabled,
                "'{name}' is compiled in exactly when its feature is enabled"
            );
        }
        assert!(
            !backend_is_compiled("banana"),
            "a value naming no backend is not compiled in"
        );
    }

    /// `postgres` is a real backend, so a build without `postgres-blob` must
    /// say the arm is absent and name the feature that compiles it, rather than
    /// calling the value unknown.
    #[cfg(not(feature = "postgres-blob"))]
    #[test]
    fn an_uncompiled_postgres_names_the_feature_to_rebuild_with() {
        let message = reject_backend_message("postgres");
        assert!(
            message.contains("'postgres' is not compiled into this binary"),
            "{message}"
        );
        assert!(message.contains("--features cloud-blobs"), "{message}");
        assert!(message.contains("scp-transport/postgres-blob"), "{message}");
        assert!(!message.contains("unknown storage backend"), "{message}");
        assert!(
            !message.contains("Valid options"),
            "an absent arm is not a typo; {message}"
        );
    }

    /// The `s3` twin of the `postgres` case above.
    #[cfg(not(feature = "s3-blob"))]
    #[test]
    fn an_uncompiled_s3_names_the_feature_to_rebuild_with() {
        let message = reject_backend_message("s3");
        assert!(
            message.contains("'s3' is not compiled into this binary"),
            "{message}"
        );
        assert!(message.contains("--features cloud-blobs"), "{message}");
        assert!(message.contains("scp-transport/s3-blob"), "{message}");
        assert!(!message.contains("unknown storage backend"), "{message}");
    }

    /// [`reject_backend_message`] names a rebuild only for a backend whose
    /// `compiled` column reads false.
    ///
    /// The edit this test catches is the `&& !b.compiled` filter dropping out
    /// of that function's `find`. Without the filter the function matches the
    /// row of a backend this build did compile, and hands an operator who typed
    /// a working value the rebuild instruction written for an absent arm, which
    /// reports a capability as gone from a binary that holds it. No other test
    /// in this module reads that filter:
    /// `an_unrecognized_value_is_reported_as_unknown` passes a name no row
    /// carries, and the two `an_uncompiled_*` tests pass names whose rows
    /// already read false, so removing the filter changes none of those three
    /// results.
    ///
    /// This loop reads the `compiled` column rather than checking it, so it
    /// says nothing about a row whose column reads a sibling backend's feature:
    /// such a row agrees with itself on both sides of the comparison and stays
    /// green here. `the_compiled_predicate_answers_from_the_features` and
    /// `every_site_names_the_same_feature_for_a_backend` fail on that row.
    /// Which values [`storage_from_env`] routes to this function is held
    /// elsewhere too: `every_constructor_arm_has_a_table_row` pairs each arm
    /// with a row, and `every_site_names_the_same_feature_for_a_backend` pins
    /// each arm's `#[cfg]` to the feature its row names, so a value whose arm
    /// this build compiled reaches a constructor and never reaches either
    /// diagnostic.
    #[test]
    fn a_compiled_backend_never_reads_as_absent() {
        for backend in BACKENDS.iter().filter(|b| b.compiled) {
            let message = reject_backend_message(backend.name);
            assert!(
                !message.contains("not compiled into this binary"),
                "'{}' is compiled in; {message}",
                backend.name
            );
        }
    }
}
