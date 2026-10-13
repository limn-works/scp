//! Shared startup utilities for SCP relay and node binaries.
//!
//! Both `scp-relay` and `scp-node` binaries use identical logic for environment
//! variable parsing, relay configuration, blob storage backend selection,
//! tracing initialization, health checks, and graceful shutdown. This module
//! provides the shared implementations so changes need only be made once.
//!
//! No function in this module ends the process. Every failure returns a
//! [`StartupError`] to the calling binary, and the binary decides the exit
//! code.
//!
//! Gated behind the `startup` feature. Not used by the library or FFI bridges.
//!
//! See §10.5 of the SCP infrastructure spec.

use std::env;
use std::ffi::OsString;
use std::future::Future;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use tracing_subscriber::EnvFilter;

use crate::native::server::{RelayConfig, RelayError};
use crate::native::storage::{BlobStorageBackend, StorageError};

/// The variable that names the relay's blob storage backend.
const BACKEND_VAR: &str = "SCP_RELAY_STORAGE_BACKEND";

/// The variable that names the file a `sqlite` or `redb` backend opens.
#[cfg(any(feature = "sqlite-blob", feature = "redb-blob"))]
const STORAGE_PATH_VAR: &str = "SCP_RELAY_STORAGE_PATH";

// ---------------------------------------------------------------------------
// StartupError
// ---------------------------------------------------------------------------

/// Why a relay or node binary cannot start from its environment.
///
/// Every function in this module returns this error instead of ending the
/// process, so the calling binary prints it and picks the exit code.
#[derive(Debug, thiserror::Error)]
pub enum StartupError {
    /// `SCP_RELAY_STORAGE_BACKEND` is unset or empty, names no backend, or
    /// names a backend this build did not compile.
    #[error("{}", rejection_message(error, binary_feature))]
    Backend {
        /// Why [`BackendChoice::parse`] refused the value.
        error: BackendSelectionError,
        /// The calling binary's own cargo feature that compiles the `postgres`
        /// and `s3` backends; the message names it for a backend this build
        /// did not compile.
        binary_feature: &'static str,
    },
    /// The selected backend requires `var`, and `var` is unset or empty. None
    /// of these variables has a default.
    #[error(
        "{BACKEND_VAR}={backend} requires {var} to be set to a non-empty value; {var} has no default"
    )]
    MissingVar {
        /// The backend the operator selected.
        backend: &'static str,
        /// The variable the backend requires.
        var: &'static str,
    },
    /// `var` names a relative path. A relative path resolves against the
    /// working directory the process starts in, so two starts from two
    /// directories open two different stores.
    #[error(
        "{var}='{}' is a relative path, which opens a different store for each working \
         directory the process starts in; set an absolute path",
        path.display()
    )]
    RelativePath {
        /// The variable that holds the path.
        var: &'static str,
        /// The relative path the operator set.
        path: PathBuf,
    },
    /// `var` is set to a value this module cannot parse. The message omits the
    /// value itself.
    #[error("{var} is set to a value that does not parse: {reason}")]
    InvalidValue {
        /// The variable that holds the value.
        var: &'static str,
        /// Why the value does not parse.
        reason: String,
    },
    /// The selected backend's store did not open (SCP-CAPSEL-8001, persistence
    /// spec §17.17.1: a failed selection is terminal).
    #[error("failed to open the {backend} blob store: {error}")]
    StoreOpen {
        /// The backend the operator selected.
        backend: &'static str,
        /// The open failure the store returned.
        error: StorageError,
    },
    /// The relay server did not bind its listener.
    #[error("relay failed to start: {0}")]
    Relay(RelayError),
    /// The tracing subscriber did not install, because another global
    /// subscriber was already installed.
    #[error("failed to install the tracing subscriber: {0}")]
    Tracing(String),
    /// The operating system refused a handler for `signal`, so the process
    /// could not learn when to shut down.
    #[error("failed to register a {signal} handler: {error}")]
    SignalHandler {
        /// The signal the handler was for.
        signal: &'static str,
        /// The registration failure.
        error: std::io::Error,
    },
    /// The push selection or push credentials in the environment cannot start
    /// a relay.
    #[error(transparent)]
    Push(#[from] PushStartupError),
}

// ---------------------------------------------------------------------------
// env_or — typed environment variable with a documented default
// ---------------------------------------------------------------------------

/// Reads environment variable `name` and parses it as `T`, returning
/// `default` when the variable is unset.
///
/// Use this only for a tunable whose default the operator documentation
/// states, such as a bind address or a limit. A provider selection, such as
/// the blob storage backend, has no default (persistence spec §17.17.1,
/// SCP-CAPSEL-8000) and never goes through this function.
///
/// # Errors
///
/// [`StartupError::InvalidValue`] when the variable is set and its value is
/// not UTF-8 or does not parse as `T`. An empty value does not parse as any
/// type this module reads, so it is an error as well.
pub fn env_or<T>(name: &'static str, default: T) -> Result<T, StartupError>
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    parse_or(name, env::var_os(name), default)
}

/// Parses `raw`, the value of variable `name`, as `T`, or returns `default`
/// when `raw` is `None`.
fn parse_or<T>(name: &'static str, raw: Option<OsString>, default: T) -> Result<T, StartupError>
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    let Some(raw) = raw else {
        return Ok(default);
    };
    let text = utf8(name, raw)?;
    text.parse()
        .map_err(|e: T::Err| StartupError::InvalidValue {
            var: name,
            reason: e.to_string(),
        })
}

/// Converts `raw`, the value of variable `name`, to a `String`.
fn utf8(name: &'static str, raw: OsString) -> Result<String, StartupError> {
    raw.into_string().map_err(|_| StartupError::InvalidValue {
        var: name,
        reason: "the value is not valid UTF-8".to_owned(),
    })
}

/// Whether `raw` holds nothing but whitespace.
#[cfg(any(
    feature = "sqlite-blob",
    feature = "redb-blob",
    feature = "postgres-blob",
    feature = "s3-blob"
))]
fn is_blank(raw: &std::ffi::OsStr) -> bool {
    raw.to_string_lossy().trim().is_empty()
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
///
/// # Errors
///
/// [`StartupError::InvalidValue`] when one of these variables is set to a
/// value that does not parse.
pub fn relay_config_from_env() -> Result<RelayConfig, StartupError> {
    Ok(RelayConfig {
        bind_addr: env_or(
            "SCP_RELAY_BIND_ADDR",
            SocketAddr::from(([0, 0, 0, 0], 9000)),
        )?,
        max_blob_size: env_or("SCP_RELAY_MAX_BLOB_SIZE", 262_144)?,
        max_blob_ttl: env_or("SCP_RELAY_MAX_BLOB_TTL", scp_relay_client::MAX_BLOB_TTL)?,
        max_total_connections: env_or("SCP_RELAY_MAX_CONNECTIONS", 1_000)?,
        max_connections_per_ip: env_or("SCP_RELAY_MAX_CONNECTIONS_PER_IP", 10)?,
        rate_limit_publishes_per_second: env_or("SCP_RELAY_RATE_LIMIT", 100)?,
        ..RelayConfig::default()
    })
}

// ---------------------------------------------------------------------------
// Blob storage backend from environment
// ---------------------------------------------------------------------------

/// The `SCP_RELAY_STORAGE_BACKEND` values this build can construct, comma
/// separated, derived from the features this build compiled.
#[must_use]
pub fn valid_backends() -> String {
    let mut names: Vec<&str> = Vec::new();
    if cfg!(feature = "sqlite-blob") {
        names.push("sqlite");
    }
    if cfg!(feature = "redb-blob") {
        names.push("redb");
    }
    if cfg!(feature = "postgres-blob") {
        names.push("postgres");
    }
    if cfg!(feature = "s3-blob") {
        names.push("s3");
    }
    names.push("memory");
    names.join(", ")
}

/// A `SCP_RELAY_STORAGE_BACKEND` value [`BackendChoice::parse`] refuses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BackendSelectionError {
    /// The variable is unset, empty, or holds only whitespace. The backend
    /// selection has no default (persistence spec §17.7 and §17.17.1,
    /// SCP-CAPSEL-8000).
    Unset,
    /// The value names `postgres` or `s3`, and this build did not compile that
    /// backend. [`BackendChoice::parse`] returns this variant for those two
    /// names only.
    NotCompiled {
        /// The lowercase name of the backend the operator selected,
        /// `postgres` or `s3`, whatever letter case the operator set.
        backend: &'static str,
        /// The `scp-transport` cargo feature that compiles `backend`:
        /// `postgres-blob` or `s3-blob`. The binary's own feature that
        /// enables it is the `binary_feature` its caller passes to
        /// [`backend_choice_from_env`].
        feature: &'static str,
    },
    /// The value names no backend this build compiled, and is neither
    /// `postgres` nor `s3`.
    Unknown {
        /// The value the operator set, with its case as set.
        value: String,
    },
}

impl BackendSelectionError {
    /// The persistence spec rule (§17.17.1) this refusal enforces.
    ///
    /// An unset or unknown value makes no selection, which SCP-CAPSEL-8000
    /// (selection is mandatory; there is no default) forbids. A value naming a
    /// backend this build did not compile selects an implementation that can
    /// never succeed, which SCP-CAPSEL-8001 (selection fails closed) covers.
    #[must_use]
    pub const fn rule(&self) -> &'static str {
        match self {
            Self::Unset | Self::Unknown { .. } => "SCP-CAPSEL-8000",
            Self::NotCompiled { .. } => "SCP-CAPSEL-8001",
        }
    }
}

impl std::fmt::Display for BackendSelectionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unset => write!(
                f,
                "{BACKEND_VAR} is unset or empty, and it has no default ({}: a relay starts \
                 only on a backend the operator names). Set it to one of: {}",
                self.rule(),
                valid_backends()
            ),
            Self::NotCompiled { backend, feature } => write!(
                f,
                "storage backend '{backend}' is not compiled into this binary, which was \
                 built without scp-transport's `{feature}` feature. Compiled-in options: {}",
                valid_backends()
            ),
            Self::Unknown { value } => write!(
                f,
                "unknown storage backend '{value}'. Valid options: {}",
                valid_backends()
            ),
        }
    }
}

impl std::error::Error for BackendSelectionError {}

/// A blob storage backend this build compiled, parsed from a
/// `SCP_RELAY_STORAGE_BACKEND` value.
///
/// A variant exists only in a build that compiled its backend, so
/// [`storage_from_env`] matches every variant with no rejection arm. A caller
/// that asks whether a value selects a cloud backend matches the result of
/// [`BackendChoice::parse`] instead of listing the backend names again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendChoice {
    /// `sqlite`.
    #[cfg(feature = "sqlite-blob")]
    Sqlite,
    /// `redb`.
    #[cfg(feature = "redb-blob")]
    Redb,
    /// `postgres`.
    #[cfg(feature = "postgres-blob")]
    Postgres,
    /// `s3`.
    #[cfg(feature = "s3-blob")]
    S3,
    /// `memory`.
    Memory,
}

impl BackendChoice {
    /// Parses a `SCP_RELAY_STORAGE_BACKEND` value, ignoring case.
    ///
    /// # Errors
    ///
    /// [`BackendSelectionError::Unset`] when the value is empty or holds only
    /// whitespace, [`BackendSelectionError::NotCompiled`] when the value is
    /// `postgres` or `s3` and this build did not compile that backend, and
    /// [`BackendSelectionError::Unknown`] for every other value this build has
    /// no backend for.
    pub fn parse(value: &str) -> Result<Self, BackendSelectionError> {
        if value.trim().is_empty() {
            return Err(BackendSelectionError::Unset);
        }
        match value.to_lowercase().as_str() {
            #[cfg(feature = "sqlite-blob")]
            "sqlite" => Ok(Self::Sqlite),
            #[cfg(feature = "redb-blob")]
            "redb" => Ok(Self::Redb),
            #[cfg(feature = "postgres-blob")]
            "postgres" => Ok(Self::Postgres),
            #[cfg(not(feature = "postgres-blob"))]
            "postgres" => Err(BackendSelectionError::NotCompiled {
                backend: "postgres",
                feature: "postgres-blob",
            }),
            #[cfg(feature = "s3-blob")]
            "s3" => Ok(Self::S3),
            #[cfg(not(feature = "s3-blob"))]
            "s3" => Err(BackendSelectionError::NotCompiled {
                backend: "s3",
                feature: "s3-blob",
            }),
            "memory" => Ok(Self::Memory),
            _ => Err(BackendSelectionError::Unknown {
                value: value.to_owned(),
            }),
        }
    }

    /// Whether this backend stores blobs in a network service (`PostgreSQL`
    /// or S3) rather than on this machine.
    #[must_use]
    pub const fn is_cloud(self) -> bool {
        match self {
            #[cfg(feature = "sqlite-blob")]
            Self::Sqlite => false,
            #[cfg(feature = "redb-blob")]
            Self::Redb => false,
            #[cfg(feature = "postgres-blob")]
            Self::Postgres => true,
            #[cfg(feature = "s3-blob")]
            Self::S3 => true,
            Self::Memory => false,
        }
    }
}

/// The text a binary prints when [`BackendChoice::parse`] rejects
/// `SCP_RELAY_STORAGE_BACKEND`.
///
/// For [`BackendSelectionError::NotCompiled`] the text also tells the
/// operator to rebuild with `binary_feature`, the binary's own cargo feature
/// that enables the missing `scp-transport` feature.
fn rejection_message(error: &BackendSelectionError, binary_feature: &str) -> String {
    match error {
        BackendSelectionError::NotCompiled { .. } => {
            format!("{error}\nrebuild this binary with `--features {binary_feature}`")
        }
        BackendSelectionError::Unset | BackendSelectionError::Unknown { .. } => error.to_string(),
    }
}

/// Parses `SCP_RELAY_STORAGE_BACKEND`, which has no default.
///
/// A binary calls this before it creates a directory, a key, or a store, so a
/// rejected value leaves nothing behind, and passes the result to
/// [`storage_from_env`]. `binary_feature` names the calling binary's own
/// cargo feature that compiles the `postgres` and `s3` backends; when this
/// build lacks either, the error tells the operator to rebuild with that
/// feature.
///
/// # Storage backend selection
///
/// [`storage_from_env`] reads the config variables of the backend this
/// function chose. No variable in this table has a default.
///
/// | Value | Backend | Config env vars |
/// |---|---|---|
/// | `sqlite` | `SQLite` | `SCP_RELAY_STORAGE_PATH` (required, absolute) |
/// | `redb` | redb | `SCP_RELAY_STORAGE_PATH` (required, absolute) |
/// | `postgres` | `PostgreSQL` | `SCP_RELAY_DATABASE_URL` (required) |
/// | `s3` | S3-compat | `SCP_RELAY_S3_BUCKET` (required) + AWS env |
/// | `memory` | In-memory | — |
///
/// # Errors
///
/// [`StartupError::Backend`] carrying [`BackendSelectionError::Unset`] when the
/// variable is unset, empty, or whitespace, and carrying the other
/// [`BackendSelectionError`] variants for a value this build cannot serve.
pub fn backend_choice_from_env(
    binary_feature: &'static str,
) -> Result<BackendChoice, StartupError> {
    backend_choice_from_value(env::var_os(BACKEND_VAR), binary_feature)
}

/// Parses `raw`, the value of `SCP_RELAY_STORAGE_BACKEND`, where `None` means
/// the variable is unset.
fn backend_choice_from_value(
    raw: Option<OsString>,
    binary_feature: &'static str,
) -> Result<BackendChoice, StartupError> {
    raw.map_or(Err(BackendSelectionError::Unset), |raw| {
        BackendChoice::parse(&raw.to_string_lossy())
    })
    .map_err(|error| StartupError::Backend {
        error,
        binary_feature,
    })
}

/// Reads `raw`, the value of `SCP_RELAY_STORAGE_PATH`, as the file a `backend`
/// store opens.
///
/// The path has no default, so an unset or blank value is an error. A relative
/// path is an error too, because it resolves against the working directory: a
/// relay started once from `/srv` and once from `/` would open two files, and
/// the second start would serve none of the blobs the first one stored.
#[cfg(any(feature = "sqlite-blob", feature = "redb-blob"))]
fn storage_path(backend: &'static str, raw: Option<OsString>) -> Result<PathBuf, StartupError> {
    let Some(raw) = raw.filter(|raw| !is_blank(raw)) else {
        return Err(StartupError::MissingVar {
            backend,
            var: STORAGE_PATH_VAR,
        });
    };
    let path = PathBuf::from(raw);
    if !path.is_absolute() {
        return Err(StartupError::RelativePath {
            var: STORAGE_PATH_VAR,
            path,
        });
    }
    Ok(path)
}

/// Reads `raw`, the value of variable `var` that `backend` requires.
///
/// An unset or blank value is [`StartupError::MissingVar`]; a value that is
/// not UTF-8 is [`StartupError::InvalidValue`].
#[cfg(any(feature = "postgres-blob", feature = "s3-blob"))]
fn required_value(
    backend: &'static str,
    var: &'static str,
    raw: Option<OsString>,
) -> Result<String, StartupError> {
    match raw {
        Some(raw) if !is_blank(&raw) => utf8(var, raw),
        _ => Err(StartupError::MissingVar { backend, var }),
    }
}

/// Reads `raw`, the value of `SCP_RELAY_S3_PREFIX`. Unset is `blobs/`; a set
/// but blank value is [`StartupError::InvalidValue`] rather than an empty
/// prefix.
#[cfg(feature = "s3-blob")]
fn s3_prefix(raw: Option<OsString>) -> Result<String, StartupError> {
    const PREFIX_VAR: &str = "SCP_RELAY_S3_PREFIX";
    match raw {
        None => Ok("blobs/".to_owned()),
        Some(raw) if is_blank(&raw) => Err(StartupError::InvalidValue {
            var: PREFIX_VAR,
            reason: "the value is set but empty; unset it to use blobs/".to_owned(),
        }),
        Some(raw) => utf8(PREFIX_VAR, raw),
    }
}

/// Constructs the blob storage backend `choice` names, reading that
/// backend's configuration from the environment.
///
/// `choice` comes from [`backend_choice_from_env`]. This function applies no
/// default to any variable it reads, except `SCP_RELAY_S3_PREFIX`, whose
/// default is `blobs/` when it is unset. The doc comment of [`backend_choice_from_env`] lists each
/// backend's config variables.
///
/// Each arm logs `using <backend> blob storage` only after its store opens, so
/// a relay that fails to open its store never logs a backend it does not have.
///
/// # Backend availability
///
/// Backend arms are compiled only when the corresponding feature is enabled
/// (`sqlite-blob`, `redb-blob`, `postgres-blob`, `s3-blob`), and a
/// [`BackendChoice`] variant exists only for a compiled arm. `scp-node` and
/// `scp-relay` enable `postgres-blob` and `s3-blob` only under their
/// off-by-default `cloud-blobs` feature. A request for `postgres` or `s3` in
/// a build without it fails in [`backend_choice_from_env`] and never reaches
/// this function, so it never falls back to another backend.
///
/// # Errors
///
/// - [`StartupError::MissingVar`] when the chosen backend's required variable
///   (`SCP_RELAY_STORAGE_PATH`, `SCP_RELAY_DATABASE_URL`, or
///   `SCP_RELAY_S3_BUCKET`) is unset or blank.
/// - [`StartupError::RelativePath`] when `SCP_RELAY_STORAGE_PATH` is relative.
/// - [`StartupError::InvalidValue`] when a variable it reads is not UTF-8, or
///   when `SCP_RELAY_S3_PREFIX` is set but blank.
/// - [`StartupError::StoreOpen`] when the store fails to open.
#[cfg_attr(
    not(any(feature = "postgres-blob", feature = "s3-blob")),
    expect(
        clippy::unused_async,
        reason = "only the postgres and s3 arms await, and this build compiled neither"
    )
)]
pub async fn storage_from_env(choice: BackendChoice) -> Result<BlobStorageBackend, StartupError> {
    match choice {
        #[cfg(feature = "sqlite-blob")]
        BackendChoice::Sqlite => {
            let path = storage_path("sqlite", env::var_os(STORAGE_PATH_VAR))?;
            let store =
                BlobStorageBackend::sqlite(&path).map_err(|error| StartupError::StoreOpen {
                    backend: "sqlite",
                    error,
                })?;
            tracing::info!(path = %path.display(), "using sqlite blob storage");
            Ok(store)
        }
        #[cfg(feature = "redb-blob")]
        BackendChoice::Redb => {
            let path = storage_path("redb", env::var_os(STORAGE_PATH_VAR))?;
            let store =
                BlobStorageBackend::redb(&path).map_err(|error| StartupError::StoreOpen {
                    backend: "redb",
                    error,
                })?;
            tracing::info!(path = %path.display(), "using redb blob storage");
            Ok(store)
        }
        #[cfg(feature = "postgres-blob")]
        BackendChoice::Postgres => {
            const URL_VAR: &str = "SCP_RELAY_DATABASE_URL";
            let url = required_value("postgres", URL_VAR, env::var_os(URL_VAR))?;
            let store = crate::native::postgres_blob::PostgresBlobStore::open(&url)
                .await
                .map_err(|error| StartupError::StoreOpen {
                    backend: "postgres",
                    error,
                })?;
            tracing::info!("using postgres blob storage");
            Ok(BlobStorageBackend::Postgres(store))
        }
        #[cfg(feature = "s3-blob")]
        BackendChoice::S3 => {
            const BUCKET_VAR: &str = "SCP_RELAY_S3_BUCKET";
            let bucket = required_value("s3", BUCKET_VAR, env::var_os(BUCKET_VAR))?;
            let prefix = s3_prefix(env::var_os("SCP_RELAY_S3_PREFIX"))?;
            let store = crate::native::s3_blob::S3BlobStore::open(&bucket, &prefix)
                .await
                .map_err(|error| StartupError::StoreOpen {
                    backend: "s3",
                    error,
                })?;
            tracing::info!(bucket = %bucket, prefix = %prefix, "using s3 blob storage");
            Ok(BlobStorageBackend::S3(store))
        }
        BackendChoice::Memory => {
            tracing::warn!("using in-memory blob storage — all data will be lost on restart");
            Ok(BlobStorageBackend::in_memory())
        }
    }
}

// ---------------------------------------------------------------------------
// Tracing initialization
// ---------------------------------------------------------------------------

/// Builds the log filter from `rust_log`, the value of `RUST_LOG`, which takes
/// precedence, or else from `level`, the value of `SCP_RELAY_LOG_LEVEL`, whose
/// default is `info`.
fn log_filter(
    rust_log: Option<OsString>,
    level: Option<OsString>,
) -> Result<EnvFilter, StartupError> {
    let (var, directives) = match (rust_log, level) {
        (Some(raw), _) => ("RUST_LOG", utf8("RUST_LOG", raw)?),
        (None, Some(raw)) => ("SCP_RELAY_LOG_LEVEL", utf8("SCP_RELAY_LOG_LEVEL", raw)?),
        (None, None) => ("SCP_RELAY_LOG_LEVEL", "info".to_owned()),
    };
    EnvFilter::try_new(&directives).map_err(|e| StartupError::InvalidValue {
        var,
        reason: e.to_string(),
    })
}

/// Whether `raw`, the value of `SCP_RELAY_LOG_FORMAT`, selects JSON output.
/// The default is `pretty`.
fn log_format_is_json(raw: Option<OsString>) -> Result<bool, StartupError> {
    const VAR: &str = "SCP_RELAY_LOG_FORMAT";
    let Some(raw) = raw else {
        return Ok(false);
    };
    match utf8(VAR, raw)?.as_str() {
        "json" => Ok(true),
        "pretty" => Ok(false),
        _ => Err(StartupError::InvalidValue {
            var: VAR,
            reason: "expected `json` or `pretty`".to_owned(),
        }),
    }
}

/// Installs the global `tracing` subscriber.
///
/// Log level is determined by `RUST_LOG` (takes precedence) or
/// `SCP_RELAY_LOG_LEVEL` (default: `info`). Output format is controlled
/// by `SCP_RELAY_LOG_FORMAT`: `json` for structured JSON, `pretty` (the
/// default) for human-readable output.
///
/// # Errors
///
/// [`StartupError::InvalidValue`] when one of those variables holds a value
/// that does not parse, and [`StartupError::Tracing`] when another global
/// subscriber is already installed.
pub fn init_tracing() -> Result<(), StartupError> {
    let filter = log_filter(env::var_os("RUST_LOG"), env::var_os("SCP_RELAY_LOG_LEVEL"))?;
    let installed = if log_format_is_json(env::var_os("SCP_RELAY_LOG_FORMAT"))? {
        tracing_subscriber::fmt()
            .json()
            .with_writer(std::io::stderr)
            .with_env_filter(filter)
            .try_init()
    } else {
        tracing_subscriber::fmt()
            .with_writer(std::io::stderr)
            .with_env_filter(filter)
            .try_init()
    };
    installed.map_err(|e| StartupError::Tracing(e.to_string()))
}

// ---------------------------------------------------------------------------
// Health check
// ---------------------------------------------------------------------------

/// Runs a TCP health probe against `addr` and returns whether the connection
/// succeeded.
///
/// Designed for container health checks (`--health` CLI flag). Each binary
/// turns `false` into exit code 1.
pub async fn health_check(addr: SocketAddr) -> bool {
    tokio::net::TcpStream::connect(addr).await.is_ok()
}

// ---------------------------------------------------------------------------
// Shutdown signal
// ---------------------------------------------------------------------------

/// Registers SIGINT and SIGTERM handlers and returns a future that resolves
/// when either signal arrives.
///
/// The handlers register when this function runs, so a refused registration
/// fails startup instead of leaving a process that cannot learn when to stop.
/// Call it from inside a Tokio runtime.
///
/// # Errors
///
/// [`StartupError::SignalHandler`] when the operating system refuses either
/// handler.
#[cfg(unix)]
pub fn shutdown_signal() -> Result<impl Future<Output = ()> + Send + 'static, StartupError> {
    use tokio::signal::unix::{SignalKind, signal};
    let mut interrupt =
        signal(SignalKind::interrupt()).map_err(|error| StartupError::SignalHandler {
            signal: "SIGINT",
            error,
        })?;
    let mut terminate =
        signal(SignalKind::terminate()).map_err(|error| StartupError::SignalHandler {
            signal: "SIGTERM",
            error,
        })?;
    Ok(async move {
        tokio::select! {
            _ = interrupt.recv() => {}
            _ = terminate.recv() => {}
        }
    })
}

/// Registers a Ctrl-C handler and returns a future that resolves when Ctrl-C
/// arrives.
///
/// The handler registers when this function runs, so a refused registration
/// fails startup instead of leaving a process that cannot learn when to stop.
/// Call it from inside a Tokio runtime.
///
/// # Errors
///
/// [`StartupError::SignalHandler`] when the operating system refuses the
/// handler.
#[cfg(windows)]
pub fn shutdown_signal() -> Result<impl Future<Output = ()> + Send + 'static, StartupError> {
    let mut ctrl_c =
        tokio::signal::windows::ctrl_c().map_err(|error| StartupError::SignalHandler {
            signal: "Ctrl-C",
            error,
        })?;
    Ok(async move {
        ctrl_c.recv().await;
    })
}

// ---------------------------------------------------------------------------
// Push selection and credentials from environment
// ---------------------------------------------------------------------------

/// The variable that lists the push platforms the relay serves.
const PUSH_PLATFORMS_VAR: &str = "SCP_RELAY_PUSH_PLATFORMS";
/// The variable that names the push registration store.
const PUSH_STORE_VAR: &str = "SCP_RELAY_PUSH_STORE";
/// The variable that names the file the `sqlite` push store opens.
const PUSH_STORE_PATH_VAR: &str = "SCP_RELAY_PUSH_STORE_PATH";
/// The variable that names the APNs authentication key (.p8) file.
const APNS_KEY_PATH_VAR: &str = "SCP_RELAY_APNS_KEY_PATH";
/// The variable that holds the APNs key ID.
const APNS_KEY_ID_VAR: &str = "SCP_RELAY_APNS_KEY_ID";
/// The variable that holds the Apple developer team ID.
const APNS_TEAM_ID_VAR: &str = "SCP_RELAY_APNS_TEAM_ID";
/// The variable that holds the app's bundle ID, the APNs topic.
const APNS_TOPIC_VAR: &str = "SCP_RELAY_APNS_TOPIC";
/// The variable that names the APNs environment.
const APNS_ENVIRONMENT_VAR: &str = "SCP_RELAY_APNS_ENVIRONMENT";
/// The variable that names the FCM service-account JSON file.
const FCM_SERVICE_ACCOUNT_PATH_VAR: &str = "SCP_RELAY_FCM_SERVICE_ACCOUNT_PATH";
/// The variable that holds the Firebase project ID.
const FCM_PROJECT_ID_VAR: &str = "SCP_RELAY_FCM_PROJECT_ID";

/// The largest credential file the relay reads. An APNs .p8 key is about 250
/// bytes and a service-account JSON about 2.4 KB; a larger file is not a
/// credential, and the bound keeps a misnamed path from being read whole.
const MAX_CREDENTIAL_FILE_BYTES: u64 = 64 * 1024;

/// Why the push configuration of the environment cannot start a relay.
///
/// Every variant names the variable it is about and carries no byte of any
/// credential, so its `Display` and `Debug` output are safe to log.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PushStartupError {
    /// `SCP_RELAY_PUSH_PLATFORMS` is unset or blank. Push selection has no
    /// default (persistence spec §17.17.1, SCP-CAPSEL-8000).
    #[error(
        "{PUSH_PLATFORMS_VAR} is unset or empty, and it has no default (SCP-CAPSEL-8000: a relay \
         offers push only on platforms the operator names). Set it to one of: none, apns, fcm, \
         apns,fcm"
    )]
    SelectionMissing,
    /// `SCP_RELAY_PUSH_PLATFORMS` lists a value other than `none`, `apns` and
    /// `fcm`, lists one twice, or combines `none` with a platform.
    #[error(
        "{PUSH_PLATFORMS_VAR} is invalid: {reason}. Set it to one of: none, apns, fcm, apns,fcm \
         (SCP-CAPSEL-8000)"
    )]
    SelectionInvalid {
        /// What is wrong with the list.
        reason: &'static str,
    },
    /// The platform list names a platform and `SCP_RELAY_PUSH_STORE` is unset
    /// or blank. The store selection has no default (SCP-CAPSEL-8000).
    #[error(
        "{PUSH_PLATFORMS_VAR} names a push platform, so {PUSH_STORE_VAR} must be set; it has no \
         default (SCP-CAPSEL-8000). Set it to sqlite"
    )]
    StoreMissing,
    /// `SCP_RELAY_PUSH_STORE` names a store a relay cannot open. A relay
    /// accepts only `sqlite`: the in-memory push store compiles only under the
    /// `testing` feature (persistence spec §17.17.5), so selecting it can never
    /// succeed (SCP-CAPSEL-8001).
    #[error(
        "{PUSH_STORE_VAR}='{value}' is not a push store this relay can open; a relay accepts \
         only sqlite, and the in-memory push store compiles only into test builds \
         (SCP-CAPSEL-8001)"
    )]
    StoreUnsupported {
        /// The value the operator set, as set.
        value: String,
    },
    /// `SCP_RELAY_PUSH_STORE=sqlite` and `SCP_RELAY_PUSH_STORE_PATH` is unset
    /// or blank. The path has no default.
    #[error(
        "{PUSH_STORE_VAR}=sqlite requires {PUSH_STORE_PATH_VAR} to be set to an absolute path; it \
         has no default"
    )]
    StorePathMissing,
    /// `SCP_RELAY_PUSH_PLATFORMS` lists `apns` and `SCP_RELAY_APNS_KEY_PATH`
    /// is unset or blank.
    #[error("{PUSH_PLATFORMS_VAR} lists apns, so {APNS_KEY_PATH_VAR} must name the .p8 key file")]
    ApnsKeyPathMissing,
    /// `SCP_RELAY_PUSH_PLATFORMS` lists `apns` and `SCP_RELAY_APNS_KEY_ID` is
    /// unset or blank.
    #[error("{PUSH_PLATFORMS_VAR} lists apns, so {APNS_KEY_ID_VAR} must be set")]
    ApnsKeyIdMissing,
    /// `SCP_RELAY_PUSH_PLATFORMS` lists `apns` and `SCP_RELAY_APNS_TEAM_ID` is
    /// unset or blank.
    #[error("{PUSH_PLATFORMS_VAR} lists apns, so {APNS_TEAM_ID_VAR} must be set")]
    ApnsTeamIdMissing,
    /// `SCP_RELAY_PUSH_PLATFORMS` lists `apns` and `SCP_RELAY_APNS_TOPIC` is
    /// unset or blank.
    #[error("{PUSH_PLATFORMS_VAR} lists apns, so {APNS_TOPIC_VAR} must name the app's bundle ID")]
    ApnsTopicMissing,
    /// `SCP_RELAY_PUSH_PLATFORMS` lists `apns` and
    /// `SCP_RELAY_APNS_ENVIRONMENT` is unset or blank. The environment has no
    /// default (spec §10.7.1 step 5).
    #[error(
        "{PUSH_PLATFORMS_VAR} lists apns, so {APNS_ENVIRONMENT_VAR} must be production or \
         sandbox; it has no default"
    )]
    ApnsEnvironmentMissing,
    /// `SCP_RELAY_APNS_ENVIRONMENT` is neither `production` nor `sandbox`.
    #[error("{APNS_ENVIRONMENT_VAR} must be production or sandbox")]
    ApnsEnvironmentInvalid,
    /// The file `SCP_RELAY_APNS_KEY_PATH` names is not a P-256 private key.
    #[error("{APNS_KEY_PATH_VAR} names a file that is not an APNs .p8 key: {error}")]
    ApnsKeyInvalid {
        /// What is wrong with the file.
        error: crate::relay::push::ApnsKeyError,
    },
    /// `SCP_RELAY_PUSH_PLATFORMS` lists `fcm` and
    /// `SCP_RELAY_FCM_SERVICE_ACCOUNT_PATH` is unset or blank.
    #[error(
        "{PUSH_PLATFORMS_VAR} lists fcm, so {FCM_SERVICE_ACCOUNT_PATH_VAR} must name the \
         service-account JSON file"
    )]
    FcmServiceAccountPathMissing,
    /// The file `SCP_RELAY_FCM_SERVICE_ACCOUNT_PATH` names is not a usable
    /// service-account key.
    #[error("{FCM_SERVICE_ACCOUNT_PATH_VAR} names an unusable service-account file: {error}")]
    FcmServiceAccountInvalid {
        /// What is wrong with the file.
        error: crate::relay::push::FcmCredentialError,
    },
    /// `SCP_RELAY_FCM_PROJECT_ID` is unset or blank and the service-account
    /// JSON names no `project_id`.
    #[error(
        "{FCM_PROJECT_ID_VAR} is unset and the service-account file names no project_id; set {FCM_PROJECT_ID_VAR}"
    )]
    FcmProjectIdMissing,
    /// A credential file cannot be opened or read.
    #[error("{var}='{}' cannot be read: {error}", path.display())]
    CredentialUnreadable {
        /// The variable that names the file.
        var: &'static str,
        /// The path the variable holds.
        path: PathBuf,
        /// The read failure.
        error: std::io::Error,
    },
    /// A credential file grants a permission to its group or to others.
    #[error(
        "{var}='{}' has mode {mode:o}, which grants access to its group or others; restrict it to \
         its owner (chmod 600)",
        path.display()
    )]
    CredentialPermissions {
        /// The variable that names the file.
        var: &'static str,
        /// The path the variable holds.
        path: PathBuf,
        /// The file's permission bits.
        mode: u32,
    },
    /// A credential file is not a regular file, is larger than any credential,
    /// or sits on a platform where the relay cannot check its permissions.
    #[error("{var}='{}' is not usable as a credential file: {reason}", path.display())]
    CredentialFile {
        /// The variable that names the file.
        var: &'static str,
        /// The path the variable holds.
        path: PathBuf,
        /// Why the file is refused.
        reason: &'static str,
    },
    /// A sender refused a configured value (spec §10.7.1 step 5).
    #[error("the {platform} push sender refused its configuration: {error}")]
    Sender {
        /// `apns` or `fcm`.
        platform: &'static str,
        /// The sender's refusal.
        error: crate::relay::push::PushSenderError,
    },
    /// The relay cannot yet serve the push platforms the operator named. The
    /// configuration is valid, but the relay has no push role to hand it to,
    /// so it fails closed instead of starting a relay that ignores push.
    // Stub — see PUSH-012: the relay's push role (`RelayConfig.push`, built by
    // PUSH-007) and the `KelPushVerifier` it wires replace this refusal.
    #[error(
        "{PUSH_PLATFORMS_VAR} names a push platform, and this relay build cannot serve push yet; \
         set {PUSH_PLATFORMS_VAR}=none (SCP-CAPSEL-8001)"
    )]
    NotServed,
}

impl PushStartupError {
    /// The persistence spec rule (§17.17.1) this refusal enforces: an absent
    /// or unknown selection is SCP-CAPSEL-8000, and a selection that cannot be
    /// satisfied is SCP-CAPSEL-8001.
    #[must_use]
    pub const fn rule(&self) -> &'static str {
        match self {
            Self::SelectionMissing | Self::SelectionInvalid { .. } | Self::StoreMissing => {
                "SCP-CAPSEL-8000"
            }
            Self::StoreUnsupported { .. }
            | Self::StorePathMissing
            | Self::ApnsKeyPathMissing
            | Self::ApnsKeyIdMissing
            | Self::ApnsTeamIdMissing
            | Self::ApnsTopicMissing
            | Self::ApnsEnvironmentMissing
            | Self::ApnsEnvironmentInvalid
            | Self::ApnsKeyInvalid { .. }
            | Self::FcmServiceAccountPathMissing
            | Self::FcmServiceAccountInvalid { .. }
            | Self::FcmProjectIdMissing
            | Self::CredentialUnreadable { .. }
            | Self::CredentialPermissions { .. }
            | Self::CredentialFile { .. }
            | Self::Sender { .. }
            | Self::NotServed => "SCP-CAPSEL-8001",
        }
    }
}

/// The push registration store a relay that offers push opens.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PushStoreChoice {
    /// The SQLite store at `path`, an absolute path.
    Sqlite {
        /// The database file.
        path: PathBuf,
    },
}

/// Everything a relay that offers push needs from its environment: the store
/// it keeps registrations in and one sender per platform it serves. At least
/// one sender is present.
///
/// `Debug` prints no credential: each sender's own `Debug` omits its key, its
/// JWT or access token, and every device token.
#[derive(Debug)]
pub struct PushBackends {
    /// The registration store.
    pub store: PushStoreChoice,
    /// The APNs sender, when the platform list names `apns`.
    pub apns: Option<crate::relay::push::ApnsSender>,
    /// The FCM sender, when the platform list names `fcm`.
    pub fcm: Option<crate::relay::push::FcmSender>,
}

/// The push selection `SCP_RELAY_PUSH_PLATFORMS` makes.
#[derive(Debug)]
pub enum PushSelection {
    /// `none`: the relay offers no push.
    Disabled,
    /// One or both platforms, with their store and senders.
    Enabled(Box<PushBackends>),
}

/// Reads the push selection and credentials from the environment.
///
/// | Variable | Required when | Values |
/// |---|---|---|
/// | `SCP_RELAY_PUSH_PLATFORMS` | always | `none`, `apns`, `fcm`, `apns,fcm` |
/// | `SCP_RELAY_PUSH_STORE` | a platform is listed | `sqlite` |
/// | `SCP_RELAY_PUSH_STORE_PATH` | the store is `sqlite` | absolute path |
/// | `SCP_RELAY_APNS_KEY_PATH` | `apns` is listed | absolute path to the .p8 key |
/// | `SCP_RELAY_APNS_KEY_ID` | `apns` is listed | the key's ID |
/// | `SCP_RELAY_APNS_TEAM_ID` | `apns` is listed | the Apple team ID |
/// | `SCP_RELAY_APNS_TOPIC` | `apns` is listed | the app's bundle ID |
/// | `SCP_RELAY_APNS_ENVIRONMENT` | `apns` is listed | `production` or `sandbox` |
/// | `SCP_RELAY_FCM_SERVICE_ACCOUNT_PATH` | `fcm` is listed | absolute path to the JSON |
/// | `SCP_RELAY_FCM_PROJECT_ID` | `fcm` is listed and the JSON names no `project_id` | the project ID |
///
/// No variable has a default. Credentials load only from files, never from
/// inline values, so they stay out of the process environment; each file must
/// be a regular file of at most 64 KiB that grants nothing to its group or to
/// others. Key bytes are read into zeroizing buffers. This function opens no
/// store and makes no network request, so a refusal leaves nothing behind.
///
/// # Errors
///
/// [`StartupError::Push`] carrying the [`PushStartupError`] variant for the
/// first missing or invalid value, and [`StartupError::InvalidValue`] for a
/// value that is not UTF-8.
pub fn push_selection_from_env() -> Result<PushSelection, StartupError> {
    push_selection_from(&|var| env::var_os(var))
}

/// The two platforms a relay can serve.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PushPlatforms {
    apns: bool,
    fcm: bool,
}

/// Parses a `SCP_RELAY_PUSH_PLATFORMS` value: `None` for `none`, otherwise the
/// listed platforms. Items are comma separated, trimmed and matched ignoring
/// case.
fn parse_push_platforms(value: &str) -> Result<Option<PushPlatforms>, PushStartupError> {
    if value.trim().is_empty() {
        return Err(PushStartupError::SelectionMissing);
    }
    let mut platforms = PushPlatforms {
        apns: false,
        fcm: false,
    };
    let mut none = false;
    for item in value.split(',') {
        let slot = match item.trim().to_ascii_lowercase().as_str() {
            "none" => &mut none,
            "apns" => &mut platforms.apns,
            "fcm" => &mut platforms.fcm,
            "" => {
                return Err(PushStartupError::SelectionInvalid {
                    reason: "the list has an empty item",
                });
            }
            _ => {
                return Err(PushStartupError::SelectionInvalid {
                    reason: "the list names an unknown platform",
                });
            }
        };
        if *slot {
            return Err(PushStartupError::SelectionInvalid {
                reason: "the list names a value twice",
            });
        }
        *slot = true;
    }
    match (none, platforms.apns || platforms.fcm) {
        (true, true) => Err(PushStartupError::SelectionInvalid {
            reason: "none cannot be combined with a platform",
        }),
        (true, false) => Ok(None),
        (false, _) => Ok(Some(platforms)),
    }
}

/// Reads the push selection through `lookup`, which returns a variable's raw
/// value or `None` when it is unset.
fn push_selection_from(
    lookup: &dyn Fn(&'static str) -> Option<OsString>,
) -> Result<PushSelection, StartupError> {
    let platforms = match lookup(PUSH_PLATFORMS_VAR) {
        None => return Err(PushStartupError::SelectionMissing.into()),
        Some(raw) => parse_push_platforms(&utf8(PUSH_PLATFORMS_VAR, raw)?)?,
    };
    let Some(platforms) = platforms else {
        return Ok(PushSelection::Disabled);
    };
    let store = push_store_from(lookup)?;
    let apns = if platforms.apns {
        Some(apns_sender_from(lookup)?)
    } else {
        None
    };
    let fcm = if platforms.fcm {
        Some(fcm_sender_from(lookup)?)
    } else {
        None
    };
    Ok(PushSelection::Enabled(Box::new(PushBackends {
        store,
        apns,
        fcm,
    })))
}

/// Reads variable `var` through `lookup` as a required, non-blank value,
/// returning `missing` when it is unset or blank.
fn required_push_value(
    lookup: &dyn Fn(&'static str) -> Option<OsString>,
    var: &'static str,
    missing: PushStartupError,
) -> Result<String, StartupError> {
    match lookup(var) {
        Some(raw) if !raw.to_string_lossy().trim().is_empty() => utf8(var, raw),
        _ => Err(missing.into()),
    }
}

/// Reads variable `var` through `lookup` as a required absolute path,
/// returning `missing` when it is unset or blank.
fn required_push_path(
    lookup: &dyn Fn(&'static str) -> Option<OsString>,
    var: &'static str,
    missing: PushStartupError,
) -> Result<PathBuf, StartupError> {
    let Some(raw) = lookup(var).filter(|raw| !raw.to_string_lossy().trim().is_empty()) else {
        return Err(missing.into());
    };
    let path = PathBuf::from(raw);
    if !path.is_absolute() {
        return Err(StartupError::RelativePath { var, path });
    }
    Ok(path)
}

/// Reads `SCP_RELAY_PUSH_STORE` and the store's path.
fn push_store_from(
    lookup: &dyn Fn(&'static str) -> Option<OsString>,
) -> Result<PushStoreChoice, StartupError> {
    let value = required_push_value(lookup, PUSH_STORE_VAR, PushStartupError::StoreMissing)?;
    if !value.trim().eq_ignore_ascii_case("sqlite") {
        return Err(PushStartupError::StoreUnsupported { value }.into());
    }
    let path = required_push_path(
        lookup,
        PUSH_STORE_PATH_VAR,
        PushStartupError::StorePathMissing,
    )?;
    Ok(PushStoreChoice::Sqlite { path })
}

/// Reads the APNs variables and key file and builds the sender.
fn apns_sender_from(
    lookup: &dyn Fn(&'static str) -> Option<OsString>,
) -> Result<crate::relay::push::ApnsSender, StartupError> {
    use crate::relay::push::{ApnsConfig, ApnsEnvironment, ApnsSender, apns_key_from_p8};

    let key_path = required_push_path(
        lookup,
        APNS_KEY_PATH_VAR,
        PushStartupError::ApnsKeyPathMissing,
    )?;
    let key_id = required_push_value(lookup, APNS_KEY_ID_VAR, PushStartupError::ApnsKeyIdMissing)?;
    let team_id = required_push_value(
        lookup,
        APNS_TEAM_ID_VAR,
        PushStartupError::ApnsTeamIdMissing,
    )?;
    let topic = required_push_value(lookup, APNS_TOPIC_VAR, PushStartupError::ApnsTopicMissing)?;
    let environment = match required_push_value(
        lookup,
        APNS_ENVIRONMENT_VAR,
        PushStartupError::ApnsEnvironmentMissing,
    )?
    .trim()
    .to_ascii_lowercase()
    .as_str()
    {
        "production" => ApnsEnvironment::Production,
        "sandbox" => ApnsEnvironment::Sandbox,
        _ => return Err(PushStartupError::ApnsEnvironmentInvalid.into()),
    };
    let key_file = read_credential_file(APNS_KEY_PATH_VAR, &key_path)?;
    let signing_key =
        apns_key_from_p8(&key_file).map_err(|error| PushStartupError::ApnsKeyInvalid { error })?;
    drop(key_file);
    let sender = ApnsSender::new(ApnsConfig {
        signing_key,
        key_id,
        team_id,
        topic,
        environment,
    })
    .map_err(|error| PushStartupError::Sender {
        platform: "apns",
        error,
    })?;
    tracing::info!(
        environment = ?environment,
        "apns push credentials loaded"
    );
    Ok(sender)
}

/// Reads the FCM variables and service-account file and builds the sender.
fn fcm_sender_from(
    lookup: &dyn Fn(&'static str) -> Option<OsString>,
) -> Result<crate::relay::push::FcmSender, StartupError> {
    use crate::relay::push::{FcmConfig, FcmSender, FcmServiceAccount};

    let account_path = required_push_path(
        lookup,
        FCM_SERVICE_ACCOUNT_PATH_VAR,
        PushStartupError::FcmServiceAccountPathMissing,
    )?;
    let account_file = read_credential_file(FCM_SERVICE_ACCOUNT_PATH_VAR, &account_path)?;
    let service_account = FcmServiceAccount::from_json(&account_file)
        .map_err(|error| PushStartupError::FcmServiceAccountInvalid { error })?;
    drop(account_file);
    let project_id = match lookup(FCM_PROJECT_ID_VAR) {
        Some(raw) if !raw.to_string_lossy().trim().is_empty() => utf8(FCM_PROJECT_ID_VAR, raw)?,
        _ => service_account
            .project_id()
            .map(str::to_owned)
            .ok_or(PushStartupError::FcmProjectIdMissing)?,
    };
    let sender = FcmSender::new(FcmConfig {
        service_account,
        project_id,
    })
    .map_err(|error| PushStartupError::Sender {
        platform: "fcm",
        error,
    })?;
    tracing::info!("fcm push credentials loaded");
    Ok(sender)
}

/// Reads the credential file at `path`, which variable `var` names, into a
/// zeroizing buffer.
///
/// The file is opened once and every check reads the open handle, so a file
/// swapped after the check is never the one read. The file must be a regular
/// file of at most [`MAX_CREDENTIAL_FILE_BYTES`] whose mode grants nothing to
/// its group or to others. A platform without Unix permission bits cannot pass
/// that check, so it refuses every credential file.
fn read_credential_file(
    var: &'static str,
    path: &std::path::Path,
) -> Result<zeroize::Zeroizing<Vec<u8>>, StartupError> {
    use std::io::Read as _;

    let unreadable = |error| PushStartupError::CredentialUnreadable {
        var,
        path: path.to_owned(),
        error,
    };
    let refused = |reason| PushStartupError::CredentialFile {
        var,
        path: path.to_owned(),
        reason,
    };
    // Opening a FIFO or a device can block startup forever, so the path is
    // checked before it is opened; the check on the open handle below is the
    // one that decides.
    if !std::fs::metadata(path).map_err(unreadable)?.is_file() {
        return Err(refused("it is not a regular file").into());
    }
    let file = std::fs::File::open(path).map_err(unreadable)?;
    let metadata = file.metadata().map_err(unreadable)?;
    if !metadata.is_file() {
        return Err(refused("it is not a regular file").into());
    }
    check_owner_only(var, path, &metadata)?;
    if metadata.len() > MAX_CREDENTIAL_FILE_BYTES {
        return Err(refused("it is larger than 64 KiB").into());
    }
    // Sized up front so the buffer never reallocates and leaves an unzeroed
    // copy of key bytes behind; `take` bounds a file that grew after `stat`.
    let capacity = usize::try_from(MAX_CREDENTIAL_FILE_BYTES).unwrap_or(usize::MAX);
    let mut bytes = zeroize::Zeroizing::new(Vec::with_capacity(capacity.saturating_add(1)));
    file.take(MAX_CREDENTIAL_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(unreadable)?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_CREDENTIAL_FILE_BYTES {
        return Err(refused("it is larger than 64 KiB").into());
    }
    Ok(bytes)
}

/// Refuses a credential file whose mode grants any permission to its group or
/// to others.
#[cfg(unix)]
fn check_owner_only(
    var: &'static str,
    path: &std::path::Path,
    metadata: &std::fs::Metadata,
) -> Result<(), PushStartupError> {
    use std::os::unix::fs::PermissionsExt as _;
    let mode = metadata.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(PushStartupError::CredentialPermissions {
            var,
            path: path.to_owned(),
            mode,
        });
    }
    Ok(())
}

/// Refuses every credential file: this platform has no Unix permission bits,
/// so the relay cannot check that only the file's owner can read it.
#[cfg(not(unix))]
fn check_owner_only(
    var: &'static str,
    path: &std::path::Path,
    _metadata: &std::fs::Metadata,
) -> Result<(), PushStartupError> {
    Err(PushStartupError::CredentialFile {
        var,
        path: path.to_owned(),
        reason: "this platform cannot check that only its owner can read it",
    })
}

/// Refuses an enabled push selection, because this relay has no push role to
/// serve it with yet.
///
/// # Errors
///
/// [`PushStartupError::NotServed`] for [`PushSelection::Enabled`].
// Stub — see PUSH-012: once PUSH-007 adds `RelayConfig.push`, an enabled
// selection becomes `PushRole::Enabled` with the opened store, these senders
// and `KelPushVerifier`, and this refusal goes away.
pub fn require_push_servable(selection: &PushSelection) -> Result<(), StartupError> {
    match selection {
        PushSelection::Disabled => Ok(()),
        PushSelection::Enabled(_) => Err(PushStartupError::NotServed.into()),
    }
}

// ---------------------------------------------------------------------------
// Relay startup helper
// ---------------------------------------------------------------------------

/// Starts a relay server from environment configuration and returns the
/// server handle, bound address, and storage reference.
///
/// This encapsulates the common pattern of reading config + storage from env,
/// building the relay, starting it, and logging the result. `backend` comes
/// from [`backend_choice_from_env`].
///
/// # Errors
///
/// Every error [`relay_config_from_env`], [`push_selection_from_env`],
/// [`require_push_servable`] and [`storage_from_env`] return, and
/// [`StartupError::Relay`] when the relay cannot bind its address. The push
/// selection is read before the blob store opens, so a push refusal leaves no
/// store behind.
pub async fn start_relay_from_env(
    backend: BackendChoice,
) -> Result<
    (
        crate::native::server::ShutdownHandle,
        SocketAddr,
        Arc<BlobStorageBackend>,
    ),
    StartupError,
> {
    let config = relay_config_from_env()?;
    tracing::info!(
        bind_addr = %config.bind_addr,
        max_blob_size = config.max_blob_size,
        max_connections = config.max_total_connections,
        "starting relay"
    );

    let push = push_selection_from_env()?;
    require_push_servable(&push)?;
    tracing::info!("push: none (SCP_RELAY_PUSH_PLATFORMS=none)");

    let storage = Arc::new(storage_from_env(backend).await?);
    let server = crate::native::server::RelayServer::new(config, Arc::clone(&storage));
    let (handle, local_addr) = server.start().await.map_err(StartupError::Relay)?;

    tracing::info!(addr = %local_addr, "relay listening");

    Ok((handle, local_addr, storage))
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;

    use super::{
        BackendChoice, BackendSelectionError, StartupError, backend_choice_from_value, log_filter,
        log_format_is_json, parse_or, rejection_message, valid_backends,
    };

    /// `parse` accepts a name in either case exactly when this build compiled
    /// its backend, returns `NotCompiled` naming the backend's own
    /// `scp-transport` feature for a cloud backend this build left out, and
    /// calls every other value unknown.
    #[test]
    fn parse_accepts_exactly_the_compiled_backends() {
        for (name, feature, compiled, cloud) in [
            (
                "sqlite",
                "sqlite-blob",
                cfg!(feature = "sqlite-blob"),
                false,
            ),
            ("redb", "redb-blob", cfg!(feature = "redb-blob"), false),
            (
                "postgres",
                "postgres-blob",
                cfg!(feature = "postgres-blob"),
                true,
            ),
            ("s3", "s3-blob", cfg!(feature = "s3-blob"), true),
            ("memory", "", true, false),
        ] {
            for value in [name.to_owned(), name.to_uppercase()] {
                let parsed = BackendChoice::parse(&value);
                if compiled {
                    assert_eq!(parsed.map(BackendChoice::is_cloud), Ok(cloud), "{value}");
                } else if cloud {
                    assert_eq!(
                        parsed,
                        Err(BackendSelectionError::NotCompiled {
                            backend: name,
                            feature,
                        }),
                        "{value}"
                    );
                } else {
                    assert!(
                        matches!(parsed, Err(BackendSelectionError::Unknown { .. })),
                        "{value}: {parsed:?}"
                    );
                }
            }
        }
        assert_eq!(
            BackendChoice::parse("banana"),
            Err(BackendSelectionError::Unknown {
                value: "banana".to_owned()
            })
        );
        // An unknown value keeps the case the operator set, so the exit
        // message echoes the operator's own value.
        let mixed_case = BackendSelectionError::Unknown {
            value: "Banana".to_owned(),
        };
        assert_eq!(BackendChoice::parse("Banana"), Err(mixed_case.clone()));
        let display = mixed_case.to_string();
        assert!(display.contains("'Banana'"), "{display}");
    }

    /// The options list names a backend exactly when this build compiled it.
    #[test]
    fn the_options_list_names_exactly_the_compiled_backends() {
        let listed = valid_backends();
        let names: Vec<&str> = listed.split(", ").collect();
        for (name, compiled) in [
            ("sqlite", cfg!(feature = "sqlite-blob")),
            ("redb", cfg!(feature = "redb-blob")),
            ("postgres", cfg!(feature = "postgres-blob")),
            ("s3", cfg!(feature = "s3-blob")),
            ("memory", true),
        ] {
            assert_eq!(names.contains(&name), compiled, "{name} in '{listed}'");
        }
    }

    /// The not-compiled error names the backend and scp-transport's own
    /// feature for it, and names no binary's feature; the exit message adds
    /// the feature the calling binary passed, and only for a not-compiled
    /// backend.
    #[test]
    fn a_not_compiled_backend_names_the_feature() {
        let error = BackendSelectionError::NotCompiled {
            backend: "postgres",
            feature: "postgres-blob",
        };
        let display = error.to_string();
        assert!(display.contains("'postgres' is not compiled"), "{display}");
        assert!(display.contains("`postgres-blob`"), "{display}");
        assert!(!display.contains("cloud-blobs"), "{display}");
        assert!(!display.contains("unknown"), "{display}");

        let exit = rejection_message(&error, "some-binary-feature");
        assert!(exit.starts_with(&display), "{exit}");
        assert!(exit.contains("--features some-binary-feature"), "{exit}");

        let unknown = BackendSelectionError::Unknown {
            value: "banana".to_owned(),
        };
        let exit = rejection_message(&unknown, "some-binary-feature");
        assert_eq!(exit, unknown.to_string());
    }

    /// An unset `SCP_RELAY_STORAGE_BACKEND`, an empty one, and a whitespace one
    /// each select nothing: the result is `Unset`, which enforces
    /// SCP-CAPSEL-8000, and the message names the variable, the rule, and the
    /// backends this build compiled. Restoring a `sqlite` default for an unset
    /// variable makes the `None` case return `Ok(Sqlite)` and fail here.
    #[test]
    fn an_unset_or_empty_backend_is_unset_under_capsel_8000() {
        for raw in [None, Some(""), Some("   ")] {
            let result = backend_choice_from_value(raw.map(OsString::from), "cloud-blobs");
            assert!(
                matches!(
                    &result,
                    Err(StartupError::Backend {
                        error: BackendSelectionError::Unset,
                        binary_feature: "cloud-blobs",
                    })
                ),
                "{raw:?} must be rejected as Unset; got {result:?}"
            );
            assert_eq!(BackendSelectionError::Unset.rule(), "SCP-CAPSEL-8000");
            let message = result.err().map(|e| e.to_string()).unwrap_or_default();
            assert!(message.contains("SCP_RELAY_STORAGE_BACKEND"), "{message}");
            assert!(message.contains("SCP-CAPSEL-8000"), "{message}");
            assert!(message.contains(&valid_backends()), "{message}");
            assert!(!message.contains("--features"), "{message}");
        }
        assert_eq!(BackendChoice::parse(""), Err(BackendSelectionError::Unset));
    }

    /// Each refusal maps to the persistence spec rule it enforces.
    #[test]
    fn each_refusal_names_its_capsel_rule() {
        assert_eq!(BackendSelectionError::Unset.rule(), "SCP-CAPSEL-8000");
        assert_eq!(
            BackendSelectionError::Unknown {
                value: "banana".to_owned()
            }
            .rule(),
            "SCP-CAPSEL-8000"
        );
        assert_eq!(
            BackendSelectionError::NotCompiled {
                backend: "s3",
                feature: "s3-blob"
            }
            .rule(),
            "SCP-CAPSEL-8001"
        );
    }

    /// A named backend parses through the same path the binaries read.
    #[test]
    fn an_explicit_backend_parses() {
        assert!(matches!(
            backend_choice_from_value(Some(OsString::from("memory")), "cloud-blobs"),
            Ok(BackendChoice::Memory)
        ));
    }

    /// A tunable returns its default only when unset; a set value that does
    /// not parse, an empty one included, is an error naming the variable and
    /// never the default.
    #[test]
    fn a_malformed_tunable_is_an_error_and_not_its_default() {
        assert_eq!(
            parse_or::<u16>("SCP_TEST_PORT", None, 9001).ok(),
            Some(9001)
        );
        assert_eq!(
            parse_or::<u16>("SCP_TEST_PORT", Some(OsString::from("8080")), 9001).ok(),
            Some(8080)
        );
        for bad in ["", "eighty", "70000"] {
            let result = parse_or::<u16>("SCP_TEST_PORT", Some(OsString::from(bad)), 9001);
            assert!(
                matches!(
                    result,
                    Err(StartupError::InvalidValue {
                        var: "SCP_TEST_PORT",
                        ..
                    })
                ),
                "{bad:?}: {result:?}"
            );
        }
    }

    /// The log filter and format accept their documented values and defaults,
    /// and reject anything else instead of falling back to `info` or `pretty`.
    #[test]
    fn a_malformed_log_setting_is_an_error() {
        assert!(log_filter(None, None).is_ok());
        assert!(log_filter(None, Some(OsString::from("debug"))).is_ok());
        assert!(log_filter(Some(OsString::from("scp_relay=info")), None).is_ok());
        assert!(matches!(
            log_filter(None, Some(OsString::from("info=info=info"))),
            Err(StartupError::InvalidValue {
                var: "SCP_RELAY_LOG_LEVEL",
                ..
            })
        ));
        assert!(matches!(
            log_filter(Some(OsString::from("info=info=info")), None),
            Err(StartupError::InvalidValue {
                var: "RUST_LOG",
                ..
            })
        ));
        assert_eq!(log_format_is_json(None).ok(), Some(false));
        assert_eq!(
            log_format_is_json(Some(OsString::from("json"))).ok(),
            Some(true)
        );
        assert_eq!(
            log_format_is_json(Some(OsString::from("pretty"))).ok(),
            Some(false)
        );
        assert!(matches!(
            log_format_is_json(Some(OsString::from("JSON "))),
            Err(StartupError::InvalidValue {
                var: "SCP_RELAY_LOG_FORMAT",
                ..
            })
        ));
    }

    /// `SCP_RELAY_STORAGE_PATH` has no default: unset, empty, and blank values
    /// are `MissingVar`, a relative path is `RelativePath`, and an absolute
    /// path comes back unchanged. Restoring the `./scp-relay.db` default makes
    /// the `None` case return a path and fail here.
    #[cfg(any(feature = "sqlite-blob", feature = "redb-blob"))]
    #[test]
    fn a_storage_path_must_be_set_and_absolute() {
        use super::storage_path;

        for raw in [None, Some(""), Some("  ")] {
            let result = storage_path("sqlite", raw.map(OsString::from));
            assert!(
                matches!(
                    result,
                    Err(StartupError::MissingVar {
                        backend: "sqlite",
                        var: "SCP_RELAY_STORAGE_PATH"
                    })
                ),
                "{raw:?}: {result:?}"
            );
        }
        for raw in ["./scp-relay.db", "scp-relay.redb", "data/relay.db"] {
            let result = storage_path("redb", Some(OsString::from(raw)));
            assert!(
                matches!(&result, Err(StartupError::RelativePath { .. })),
                "{raw} must be refused as relative; got {result:?}"
            );
            let message = result.err().map(|e| e.to_string()).unwrap_or_default();
            assert!(message.contains("SCP_RELAY_STORAGE_PATH"), "{message}");
            assert!(message.contains("relative"), "{message}");
        }
        let path = std::env::temp_dir().join("relay.db");
        let resolved = storage_path("sqlite", Some(path.clone().into_os_string()));
        assert_eq!(resolved.ok(), Some(path));
    }

    /// A required cloud variable has no default: unset and blank values are
    /// `MissingVar` naming the variable.
    #[cfg(any(feature = "postgres-blob", feature = "s3-blob"))]
    #[test]
    fn a_required_cloud_variable_must_be_set() {
        use super::required_value;

        for raw in [None, Some(""), Some(" ")] {
            let result = required_value("s3", "SCP_RELAY_S3_BUCKET", raw.map(OsString::from));
            assert!(
                matches!(
                    result,
                    Err(StartupError::MissingVar {
                        backend: "s3",
                        var: "SCP_RELAY_S3_BUCKET"
                    })
                ),
                "{raw:?}: {result:?}"
            );
        }
        assert_eq!(
            required_value("s3", "SCP_RELAY_S3_BUCKET", Some(OsString::from("b"))).ok(),
            Some("b".to_owned())
        );
    }

    /// An unset S3 prefix is `blobs/`; a set but blank prefix is refused
    /// rather than becoming an empty key prefix; a set prefix is kept.
    #[cfg(feature = "s3-blob")]
    #[test]
    fn a_set_s3_prefix_must_not_be_blank() {
        use super::s3_prefix;

        assert_eq!(s3_prefix(None).ok(), Some("blobs/".to_owned()));
        for raw in ["", " "] {
            let result = s3_prefix(Some(OsString::from(raw)));
            assert!(
                matches!(
                    result,
                    Err(StartupError::InvalidValue {
                        var: "SCP_RELAY_S3_PREFIX",
                        ..
                    })
                ),
                "{raw:?}: {result:?}"
            );
        }
        assert_eq!(
            s3_prefix(Some(OsString::from("tenant-a"))).ok(),
            Some("tenant-a".to_owned())
        );
    }
}

/// PUSH-012: push selection and credential loading. Unix only: the tests set
/// file permission bits, which the credential check reads.
#[cfg(all(test, unix))]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod push_tests {
    use std::collections::HashMap;
    use std::ffi::OsString;
    use std::path::{Path, PathBuf};

    use super::{
        APNS_ENVIRONMENT_VAR, APNS_KEY_ID_VAR, APNS_KEY_PATH_VAR, APNS_TEAM_ID_VAR, APNS_TOPIC_VAR,
        FCM_PROJECT_ID_VAR, FCM_SERVICE_ACCOUNT_PATH_VAR, MAX_CREDENTIAL_FILE_BYTES,
        PUSH_PLATFORMS_VAR, PUSH_STORE_PATH_VAR, PUSH_STORE_VAR, PushPlatforms, PushSelection,
        PushStartupError, PushStoreChoice, StartupError, parse_push_platforms, push_selection_from,
        require_push_servable,
    };
    use crate::relay::log_capture::LogCapture;

    /// The P-256 `AlgorithmIdentifier` (id-ecPublicKey, prime256v1).
    const P256_ALGORITHM_ID: [u8; 19] = [
        0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce,
        0x3d, 0x03, 0x01, 0x07,
    ];

    fn pem(label: &str, der: &[u8]) -> String {
        use base64::Engine as _;
        let body = base64::engine::general_purpose::STANDARD.encode(der);
        let lines: Vec<&str> = body
            .as_bytes()
            .chunks(64)
            .map(|c| std::str::from_utf8(c).unwrap())
            .collect();
        format!(
            "-----BEGIN {label}-----\n{}\n-----END {label}-----\n",
            lines.join("\n")
        )
    }

    /// A random P-256 scalar and its version-0 PKCS#8 .p8 PEM file.
    fn apns_key() -> ([u8; 32], String) {
        use ring::rand::SecureRandom as _;
        let mut scalar = [0u8; 32];
        ring::rand::SystemRandom::new().fill(&mut scalar).unwrap();
        // A scalar at or above the group order has probability below 2^-32.
        scalar[0] &= 0x7f;
        let mut ec = vec![0x30, 0x25, 0x02, 0x01, 0x01, 0x04, 0x20];
        ec.extend_from_slice(&scalar);
        let mut body = vec![0x02, 0x01, 0x00, 0x30, 0x13];
        body.extend_from_slice(&P256_ALGORITHM_ID);
        body.push(0x04);
        body.push(u8::try_from(ec.len()).unwrap());
        body.extend_from_slice(&ec);
        let mut der = vec![0x30, u8::try_from(body.len()).unwrap()];
        der.extend_from_slice(&body);
        (scalar, pem("PRIVATE KEY", &der))
    }

    /// An RSA-2048 PKCS#8 PEM key, generated once per test process.
    fn rsa_key_pem() -> &'static str {
        use rsa::pkcs8::{EncodePrivateKey as _, LineEnding};
        static PEM: std::sync::OnceLock<String> = std::sync::OnceLock::new();
        PEM.get_or_init(|| {
            rsa::RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 2048)
                .unwrap()
                .to_pkcs8_pem(LineEnding::LF)
                .unwrap()
                .to_string()
        })
    }

    fn service_account(project_id: Option<&str>) -> Vec<u8> {
        let mut value = serde_json::json!({
            "type": "service_account",
            "private_key_id": "0123456789abcdef",
            "private_key": rsa_key_pem(),
            "client_email": "relay@scp-test-project.iam.gserviceaccount.com",
            "token_uri": "https://oauth2.googleapis.com/token",
        });
        if let Some(id) = project_id {
            value["project_id"] = serde_json::Value::from(id);
        }
        value.to_string().into_bytes()
    }

    /// Writes `contents` to `name` in `dir` with permission bits `mode`.
    fn write_file(dir: &Path, name: &str, contents: &[u8], mode: u32) -> PathBuf {
        use std::os::unix::fs::PermissionsExt as _;
        let path = dir.join(name);
        std::fs::write(&path, contents).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        path
    }

    /// A complete `apns,fcm` environment whose credential files live in `dir`.
    struct Env {
        vars: HashMap<&'static str, OsString>,
        apns_scalar: [u8; 32],
        apns_pem: String,
    }

    impl Env {
        fn full(dir: &Path) -> Self {
            let (apns_scalar, apns_pem) = apns_key();
            let p8 = write_file(dir, "AuthKey.p8", apns_pem.as_bytes(), 0o600);
            let sa = write_file(
                dir,
                "service-account.json",
                &service_account(Some("scp-test-project")),
                0o600,
            );
            let mut vars = HashMap::new();
            for (var, value) in [
                (PUSH_PLATFORMS_VAR, OsString::from("apns,fcm")),
                (PUSH_STORE_VAR, OsString::from("sqlite")),
                (
                    PUSH_STORE_PATH_VAR,
                    dir.join("push.sqlite").into_os_string(),
                ),
                (APNS_KEY_PATH_VAR, p8.into_os_string()),
                (APNS_KEY_ID_VAR, OsString::from("ABC123DEFG")),
                (APNS_TEAM_ID_VAR, OsString::from("TEAM123456")),
                (APNS_TOPIC_VAR, OsString::from("works.limn.app")),
                (APNS_ENVIRONMENT_VAR, OsString::from("sandbox")),
                (FCM_SERVICE_ACCOUNT_PATH_VAR, sa.into_os_string()),
            ] {
                vars.insert(var, value);
            }
            Self {
                vars,
                apns_scalar,
                apns_pem,
            }
        }

        fn set(&mut self, var: &'static str, value: impl Into<OsString>) -> &mut Self {
            self.vars.insert(var, value.into());
            self
        }

        fn unset(&mut self, var: &'static str) -> &mut Self {
            self.vars.remove(var);
            self
        }

        fn parse(&self) -> Result<PushSelection, StartupError> {
            push_selection_from(&|var| self.vars.get(var).cloned())
        }

        fn push_error(&self) -> PushStartupError {
            match self.parse() {
                Err(StartupError::Push(error)) => error,
                other => panic!("expected a push refusal, got {other:?}"),
            }
        }
    }

    fn only_platforms(value: &str) -> Result<PushSelection, StartupError> {
        let value = OsString::from(value);
        push_selection_from(&|var| (var == PUSH_PLATFORMS_VAR).then(|| value.clone()))
    }

    /// Criterion 1: push selection is mandatory. An unset or blank
    /// `SCP_RELAY_PUSH_PLATFORMS` is refused under SCP-CAPSEL-8000, and the
    /// message names the variable and its values.
    #[test]
    fn push_platforms_has_no_default() {
        for result in [
            push_selection_from(&|_| None),
            only_platforms(""),
            only_platforms("  "),
        ] {
            let Err(StartupError::Push(error)) = result else {
                panic!("expected a refusal, got {result:?}");
            };
            assert!(matches!(error, PushStartupError::SelectionMissing));
            assert_eq!(error.rule(), "SCP-CAPSEL-8000");
            let message = StartupError::Push(error).to_string();
            assert!(message.contains(PUSH_PLATFORMS_VAR), "{message}");
            assert!(message.contains("none, apns, fcm, apns,fcm"), "{message}");
        }
    }

    /// Criterion 2: `none` selects no push and reads no other variable, so a
    /// relay with `none` and no push store or credentials starts.
    #[test]
    fn none_selects_no_push_and_reads_nothing_else() {
        for value in ["none", "NONE", " None "] {
            let read = std::cell::RefCell::new(Vec::new());
            let value = OsString::from(value);
            let selection = push_selection_from(&|var| {
                read.borrow_mut().push(var);
                (var == PUSH_PLATFORMS_VAR).then(|| value.clone())
            })
            .unwrap();
            assert!(matches!(selection, PushSelection::Disabled));
            assert_eq!(*read.borrow(), vec![PUSH_PLATFORMS_VAR]);
            require_push_servable(&selection).unwrap();
        }
    }

    /// Every valid list parses, in any order and case.
    #[test]
    fn each_valid_platform_list_parses() {
        let both = PushPlatforms {
            apns: true,
            fcm: true,
        };
        for (value, expected) in [
            (
                "apns",
                Some(PushPlatforms {
                    apns: true,
                    fcm: false,
                }),
            ),
            (
                "fcm",
                Some(PushPlatforms {
                    apns: false,
                    fcm: true,
                }),
            ),
            ("apns,fcm", Some(both)),
            ("FCM , Apns", Some(both)),
            ("none", None),
        ] {
            assert_eq!(parse_push_platforms(value).unwrap(), expected, "{value}");
        }
    }

    /// An unknown platform, a repeated value, an empty item, and `none`
    /// combined with a platform are each refused under SCP-CAPSEL-8000.
    #[test]
    fn a_malformed_platform_list_is_refused() {
        for value in [
            "webpush",
            "apns,apns",
            "none,none",
            "apns,",
            ",fcm",
            "none,apns",
            "apns;fcm",
        ] {
            let error = parse_push_platforms(value).unwrap_err();
            assert!(
                matches!(error, PushStartupError::SelectionInvalid { .. }),
                "{value}: {error:?}"
            );
            assert_eq!(error.rule(), "SCP-CAPSEL-8000");
            assert!(error.to_string().contains(PUSH_PLATFORMS_VAR));
        }
    }

    /// A non-UTF-8 platform list is an invalid value naming the variable.
    #[test]
    fn a_non_utf8_platform_list_is_refused() {
        use std::os::unix::ffi::OsStringExt as _;
        let raw = OsString::from_vec(vec![0x61, 0xff]);
        let result = push_selection_from(&|var| (var == PUSH_PLATFORMS_VAR).then(|| raw.clone()));
        assert!(
            matches!(
                result,
                Err(StartupError::InvalidValue { var, .. }) if var == PUSH_PLATFORMS_VAR
            ),
            "{result:?}"
        );
    }

    /// Criterion 3: the store selection has no default, accepts only
    /// `sqlite`, refuses `memory` (the in-memory store compiles only into test
    /// builds), and requires an absolute path.
    #[test]
    fn the_push_store_must_be_sqlite_at_an_absolute_path() {
        let dir = tempfile::tempdir().unwrap();
        let mut env = Env::full(dir.path());

        env.unset(PUSH_STORE_VAR);
        let error = env.push_error();
        assert!(matches!(error, PushStartupError::StoreMissing));
        assert_eq!(error.rule(), "SCP-CAPSEL-8000");
        assert!(error.to_string().contains(PUSH_STORE_VAR));

        for value in ["memory", "in-memory", "redb", " "] {
            env.set(PUSH_STORE_VAR, value);
            let error = env.push_error();
            if value.trim().is_empty() {
                assert!(matches!(error, PushStartupError::StoreMissing));
                continue;
            }
            assert!(
                matches!(&error, PushStartupError::StoreUnsupported { value: v } if v == value),
                "{error:?}"
            );
            assert_eq!(error.rule(), "SCP-CAPSEL-8001");
            assert!(error.to_string().contains(PUSH_STORE_VAR));
        }

        env.set(PUSH_STORE_VAR, "SQLite").unset(PUSH_STORE_PATH_VAR);
        let error = env.push_error();
        assert!(matches!(error, PushStartupError::StorePathMissing));
        assert!(error.to_string().contains(PUSH_STORE_PATH_VAR));

        env.set(PUSH_STORE_PATH_VAR, "push.sqlite");
        assert!(
            matches!(
                env.parse(),
                Err(StartupError::RelativePath { var, .. }) if var == PUSH_STORE_PATH_VAR
            ),
            "{:?}",
            env.parse()
        );
    }

    /// Criterion 4: each APNs variable missing or blank fails startup with a
    /// refusal that names that variable.
    #[test]
    fn each_missing_apns_variable_is_named() {
        let dir = tempfile::tempdir().unwrap();
        for var in [
            APNS_KEY_PATH_VAR,
            APNS_KEY_ID_VAR,
            APNS_TEAM_ID_VAR,
            APNS_TOPIC_VAR,
            APNS_ENVIRONMENT_VAR,
        ] {
            for blank in [None, Some("  ")] {
                let mut env = Env::full(dir.path());
                env.set(PUSH_PLATFORMS_VAR, "apns");
                match blank {
                    None => env.unset(var),
                    Some(value) => env.set(var, value),
                };
                let error = env.push_error();
                assert!(
                    matches!(
                        error,
                        PushStartupError::ApnsKeyPathMissing
                            | PushStartupError::ApnsKeyIdMissing
                            | PushStartupError::ApnsTeamIdMissing
                            | PushStartupError::ApnsTopicMissing
                            | PushStartupError::ApnsEnvironmentMissing
                    ),
                    "{var}: {error:?}"
                );
                assert_eq!(error.rule(), "SCP-CAPSEL-8001");
                let message = error.to_string();
                assert!(message.contains(var), "{var}: {message}");
            }
        }
    }

    /// The APNs environment has no default and accepts only `production` and
    /// `sandbox`.
    #[test]
    fn the_apns_environment_is_production_or_sandbox() {
        let dir = tempfile::tempdir().unwrap();
        let mut env = Env::full(dir.path());
        env.set(PUSH_PLATFORMS_VAR, "apns");
        for value in ["production", "Sandbox"] {
            env.set(APNS_ENVIRONMENT_VAR, value);
            assert!(matches!(env.parse(), Ok(PushSelection::Enabled(_))));
        }
        for value in ["development", "prod", "sandbox,production"] {
            env.set(APNS_ENVIRONMENT_VAR, value);
            let error = env.push_error();
            assert!(matches!(error, PushStartupError::ApnsEnvironmentInvalid));
            assert!(error.to_string().contains(APNS_ENVIRONMENT_VAR));
        }
    }

    /// Criterion 5: FCM needs its service-account path; the project ID comes
    /// from `SCP_RELAY_FCM_PROJECT_ID` or else the JSON's `project_id`, and
    /// neither present is refused naming the variable.
    #[test]
    fn fcm_needs_a_service_account_and_a_project_id() {
        let dir = tempfile::tempdir().unwrap();
        let mut env = Env::full(dir.path());
        env.set(PUSH_PLATFORMS_VAR, "fcm");

        env.unset(FCM_SERVICE_ACCOUNT_PATH_VAR);
        let error = env.push_error();
        assert!(matches!(
            error,
            PushStartupError::FcmServiceAccountPathMissing
        ));
        assert!(error.to_string().contains(FCM_SERVICE_ACCOUNT_PATH_VAR));

        let no_project = write_file(dir.path(), "no-project.json", &service_account(None), 0o600);
        env.set(FCM_SERVICE_ACCOUNT_PATH_VAR, no_project);
        let error = env.push_error();
        assert!(matches!(error, PushStartupError::FcmProjectIdMissing));
        assert!(error.to_string().contains(FCM_PROJECT_ID_VAR));

        env.set(FCM_PROJECT_ID_VAR, "explicit-project");
        let Ok(PushSelection::Enabled(backends)) = env.parse() else {
            panic!("expected fcm to load: {:?}", env.parse());
        };
        assert!(backends.apns.is_none());
        assert!(backends.fcm.is_some());

        env.set(FCM_SERVICE_ACCOUNT_PATH_VAR, "service-account.json");
        assert!(matches!(
            env.parse(),
            Err(StartupError::RelativePath { var, .. }) if var == FCM_SERVICE_ACCOUNT_PATH_VAR
        ));
    }

    /// Criterion 6: a credential file readable or writable by its group or by
    /// others is refused naming the variable and the mode; a missing file, a
    /// directory, and an oversized file are each refused naming the variable.
    #[test]
    fn a_credential_file_must_be_a_small_owner_only_regular_file() {
        let dir = tempfile::tempdir().unwrap();
        let mut env = Env::full(dir.path());
        let (_, apns_pem) = apns_key();
        for mode in [0o644, 0o640, 0o604, 0o620, 0o602, 0o660] {
            let path = write_file(dir.path(), "loose.p8", apns_pem.as_bytes(), mode);
            env.set(APNS_KEY_PATH_VAR, path);
            let error = env.push_error();
            assert!(
                matches!(
                    error,
                    PushStartupError::CredentialPermissions { var, mode: m, .. }
                        if var == APNS_KEY_PATH_VAR && m == mode
                ),
                "{mode:o}: {error:?}"
            );
            assert!(error.to_string().contains(APNS_KEY_PATH_VAR));
        }
        let owner_read_only = write_file(dir.path(), "ro.p8", apns_pem.as_bytes(), 0o400);
        env.set(APNS_KEY_PATH_VAR, owner_read_only);
        assert!(matches!(env.parse(), Ok(PushSelection::Enabled(_))));

        env.set(APNS_KEY_PATH_VAR, dir.path().join("absent.p8"));
        assert!(matches!(
            env.push_error(),
            PushStartupError::CredentialUnreadable { var, .. } if var == APNS_KEY_PATH_VAR
        ));

        let subdir = dir.path().join("keys");
        std::fs::create_dir(&subdir).unwrap();
        env.set(APNS_KEY_PATH_VAR, &subdir);
        assert!(matches!(
            env.push_error(),
            PushStartupError::CredentialFile { var, .. } if var == APNS_KEY_PATH_VAR
        ));

        // A FIFO is refused before it is opened: opening one with no writer
        // blocks, so a startup that opened it first would hang here.
        let fifo = dir.path().join("key.fifo");
        let made = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap();
        assert!(made.success());
        std::fs::set_permissions(&fifo, std::os::unix::fs::PermissionsExt::from_mode(0o600))
            .unwrap();
        env.set(APNS_KEY_PATH_VAR, &fifo);
        assert!(matches!(
            env.push_error(),
            PushStartupError::CredentialFile { var, .. } if var == APNS_KEY_PATH_VAR
        ));

        let big = vec![b'a'; usize::try_from(MAX_CREDENTIAL_FILE_BYTES).unwrap() + 1];
        let big = write_file(dir.path(), "big.json", &big, 0o600);
        env.set(FCM_SERVICE_ACCOUNT_PATH_VAR, big);
        env.set(
            APNS_KEY_PATH_VAR,
            write_file(dir.path(), "ok.p8", apns_pem.as_bytes(), 0o600),
        );
        assert!(matches!(
            env.push_error(),
            PushStartupError::CredentialFile { var, .. } if var == FCM_SERVICE_ACCOUNT_PATH_VAR
        ));
    }

    /// A credential file of the wrong kind is refused with the parser's typed
    /// error.
    #[test]
    fn a_credential_file_of_the_wrong_kind_is_typed() {
        let dir = tempfile::tempdir().unwrap();
        let mut env = Env::full(dir.path());
        let rsa = write_file(dir.path(), "rsa.p8", rsa_key_pem().as_bytes(), 0o600);
        env.set(APNS_KEY_PATH_VAR, rsa);
        assert!(matches!(
            env.push_error(),
            PushStartupError::ApnsKeyInvalid {
                error: crate::relay::push::ApnsKeyError::NotP256Pkcs8
            }
        ));

        let (_, apns_pem) = apns_key();
        env.set(
            APNS_KEY_PATH_VAR,
            write_file(dir.path(), "ok.p8", apns_pem.as_bytes(), 0o600),
        );
        let not_json = write_file(dir.path(), "sa.json", apns_pem.as_bytes(), 0o600);
        env.set(FCM_SERVICE_ACCOUNT_PATH_VAR, not_json);
        assert!(matches!(
            env.push_error(),
            PushStartupError::FcmServiceAccountInvalid {
                error: crate::relay::push::FcmCredentialError::NotJson
            }
        ));
    }

    /// A configured value a sender refuses fails startup naming the platform.
    #[test]
    fn a_value_the_sender_refuses_fails_startup() {
        let dir = tempfile::tempdir().unwrap();
        let mut env = Env::full(dir.path());
        env.set(APNS_TOPIC_VAR, "works.limn.app\nInjected: header");
        assert!(matches!(
            env.push_error(),
            PushStartupError::Sender {
                platform: "apns",
                ..
            }
        ));
    }

    /// Criteria 4 and 5 together: a complete `apns,fcm` environment yields
    /// both production senders and the SQLite store choice, and the relay
    /// refuses to start with it until it can serve push.
    #[test]
    fn a_complete_environment_builds_both_senders() {
        let dir = tempfile::tempdir().unwrap();
        let env = Env::full(dir.path());
        let selection = env.parse().unwrap();
        let PushSelection::Enabled(backends) = &selection else {
            panic!("expected push enabled: {selection:?}");
        };
        assert_eq!(
            backends.store,
            PushStoreChoice::Sqlite {
                path: dir.path().join("push.sqlite")
            }
        );
        assert!(backends.apns.is_some());
        assert!(backends.fcm.is_some());
        // The parse opens no store.
        assert!(!dir.path().join("push.sqlite").exists());

        let Err(StartupError::Push(error)) = require_push_servable(&selection) else {
            panic!("an enabled selection must be refused until the relay serves push");
        };
        assert!(matches!(error, PushStartupError::NotServed));
        assert_eq!(error.rule(), "SCP-CAPSEL-8001");
        assert!(error.to_string().contains(PUSH_PLATFORMS_VAR));
    }

    /// The fragments of a credential that must never appear in a log line or
    /// in `Debug` or `Display` output: each base64 line of each PEM body, the
    /// APNs scalar in hex, and the scalar bytes as `Debug` would print them.
    fn secret_fragments(env: &Env) -> Vec<String> {
        let mut fragments: Vec<String> = [env.apns_pem.as_str(), rsa_key_pem()]
            .iter()
            .flat_map(|pem| pem.lines())
            .filter(|line| !line.starts_with("-----") && line.len() >= 16)
            .map(str::to_owned)
            .collect();
        fragments.push(hex::encode(env.apns_scalar));
        fragments.push(hex::encode_upper(env.apns_scalar));
        fragments.push(
            format!("{:?}", &env.apns_scalar[..8])
                .trim_end_matches(']')
                .to_owned(),
        );
        fragments
    }

    fn assert_no_secret(text: &str, fragments: &[String]) {
        // The message names the fragment's index, never the fragment, so a
        // failure prints no key material either.
        for (index, fragment) in fragments.iter().enumerate() {
            assert!(
                !text.contains(fragment.as_str()),
                "secret fragment #{index} appears in the checked output ({} bytes)",
                text.len()
            );
        }
    }

    /// Criterion 8: loading credentials writes no key byte to any log line,
    /// and neither the loaded selection's `Debug` nor any refusal's `Display`
    /// or `Debug` carries one.
    #[test]
    fn loading_credentials_logs_and_prints_no_key_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let mut env = Env::full(dir.path());
        let fragments = secret_fragments(&env);
        let capture = LogCapture::install();

        let selection = env.parse().unwrap();
        let printed = format!("{selection:?} {selection:#?}");
        let mut refusals = Vec::new();
        // Refusals raised after a credential file was read.
        env.set(APNS_TOPIC_VAR, "bad\ntopic");
        refusals.push(env.parse().unwrap_err());
        env.set(APNS_TOPIC_VAR, "works.limn.app");
        let swapped = write_file(dir.path(), "sa-as-p8.p8", rsa_key_pem().as_bytes(), 0o600);
        env.set(APNS_KEY_PATH_VAR, &swapped);
        refusals.push(env.parse().unwrap_err());
        let loose = write_file(dir.path(), "loose.p8", env.apns_pem.as_bytes(), 0o644);
        env.set(APNS_KEY_PATH_VAR, loose);
        refusals.push(env.parse().unwrap_err());
        let p8_as_sa = write_file(dir.path(), "p8-as-sa.json", env.apns_pem.as_bytes(), 0o600);
        env.set(
            APNS_KEY_PATH_VAR,
            write_file(dir.path(), "k.p8", env.apns_pem.as_bytes(), 0o600),
        );
        env.set(FCM_SERVICE_ACCOUNT_PATH_VAR, p8_as_sa);
        refusals.push(env.parse().unwrap_err());
        let require = require_push_servable(&selection).unwrap_err();
        drop(selection);

        let logs = capture.contents();
        assert!(logs.contains("apns push credentials loaded"), "{logs}");
        assert!(logs.contains("fcm push credentials loaded"), "{logs}");
        assert_no_secret(&logs, &fragments);
        assert_no_secret(&printed, &fragments);
        assert_no_secret(&format!("{require} {require:?}"), &fragments);
        for refusal in &refusals {
            assert_no_secret(&format!("{refusal} {refusal:?}"), &fragments);
        }
    }
}
