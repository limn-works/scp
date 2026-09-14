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
/// [`storage_from_env`] gates each arm on the `transport_feature` named here
/// and `compiled` reads the same feature through [`cfg!`], so a row reads as
/// compiled-in exactly when the arm exists. Both diagnostics derive from this
/// table, which is why neither can name a backend the binary cannot construct.
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
/// This reads the `compiled` column of [`BACKENDS`], which is a [`cfg!`] read
/// of the same feature that gates the arm. It deliberately does not parse
/// [`VALID_BACKENDS`]: a test that compared a binary's diagnostic against a
/// prediction parsed out of the very constant that diagnostic is built from
/// would assert a tautology, and would stay green through a revert of
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
/// construct, it prints the message [`reject_backend_message`] writes and calls
/// [`std::process::exit`].
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
        let body = body.unwrap_or_default();

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

    /// A build that compiled an arm never routes that value to either
    /// diagnostic, so neither message may advertise a rebuild for it.
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
