//! Configuration for the personal relay.
//!
//! All settings are loaded from environment variables with sensible defaults.
//! See the [`Config`] struct for the full list.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

/// Personal relay configuration, loaded from environment variables.
pub struct Config {
    /// Domain name for TLS and DID document publication (e.g., `relay.example.com`).
    /// When set, ACME (Let's Encrypt) provisions a TLS certificate automatically.
    ///
    /// Env: `SCP_RELAY_DOMAIN`
    pub domain: Option<String>,

    /// Contact email for Let's Encrypt ACME account registration.
    /// Optional but recommended -- Let's Encrypt sends expiry warnings here.
    ///
    /// Env: `SCP_RELAY_ACME_EMAIL`
    pub acme_email: Option<String>,

    /// Public HTTP/HTTPS bind address. Clients connect here.
    /// Default: `0.0.0.0:443` when a domain is set, `0.0.0.0:9000` otherwise.
    ///
    /// Env: `SCP_RELAY_BIND_ADDR`
    pub bind_addr: SocketAddr,

    /// Use a self-signed TLS certificate instead of ACME (development only).
    /// Default: `false`.
    ///
    /// Env: `SCP_RELAY_TLS_SELF_SIGNED` (set to `1` or `true`)
    pub tls_self_signed: bool,

    /// Path to PEM-encoded TLS certificate chain (manual TLS mode).
    /// When both `tls_cert_path` and `tls_key_path` are set, ACME is skipped
    /// and these files are loaded directly.
    ///
    /// Env: `SCP_RELAY_TLS_CERT`
    pub tls_cert_path: Option<PathBuf>,

    /// Path to PEM-encoded TLS private key (manual TLS mode).
    ///
    /// Env: `SCP_RELAY_TLS_KEY`
    pub tls_key_path: Option<PathBuf>,

    /// Directory for SQLite databases (node storage + key custody).
    /// Default: `$XDG_DATA_HOME/scp/personal-relay` or `$HOME/.local/share/scp/personal-relay`.
    /// An empty value counts as unset. With neither an absolute
    /// `XDG_DATA_HOME` nor an absolute `HOME`, [`Config::from_env`] returns an
    /// error instead of choosing a directory.
    ///
    /// Env: `SCP_RELAY_STORAGE_PATH`
    pub storage_path: PathBuf,

    /// Hex-encoded 32-byte encryption key for SQLCipher storage.
    /// If unset, a random key is generated and persisted to `{storage_path}/.key`.
    ///
    /// Env: `SCP_RELAY_STORAGE_KEY`
    pub storage_key_hex: Option<String>,

    /// Comma-separated DHT HTTP gateway URLs for DID publication.
    /// Default: uses the pkarr client's built-in gateways.
    ///
    /// Env: `SCP_RELAY_DHT_GATEWAYS`
    pub dht_gateways: Vec<String>,

    /// Log level filter. Overridden by `RUST_LOG` when set.
    /// Default: `info`.
    ///
    /// Env: `SCP_RELAY_LOG_LEVEL`
    pub log_level: String,

    /// Log output format: `json` for structured output, anything else for
    /// human-readable output.
    /// Default: `pretty`.
    ///
    /// Env: `SCP_RELAY_LOG_FORMAT`
    pub log_format: String,
}

impl Config {
    /// Loads configuration from environment variables.
    ///
    /// Missing variables use the defaults documented on each field.
    ///
    /// # Errors
    ///
    /// Returns a message when `SCP_RELAY_STORAGE_PATH` is unset or empty, no
    /// absolute `XDG_DATA_HOME` is set, and `HOME` is unset, empty, or
    /// relative.
    pub fn from_env() -> Result<Self, String> {
        let domain = non_empty_env("SCP_RELAY_DOMAIN");

        let default_addr = if domain.is_some() {
            SocketAddr::from(([0, 0, 0, 0], 443))
        } else {
            SocketAddr::from(([0, 0, 0, 0], 9000))
        };

        let bind_addr = std::env::var("SCP_RELAY_BIND_ADDR")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(default_addr);

        let tls_self_signed = std::env::var("SCP_RELAY_TLS_SELF_SIGNED")
            .map(|v| v == "1" || v == "true")
            .unwrap_or(false);

        let storage_path = match non_empty_env("SCP_RELAY_STORAGE_PATH") {
            Some(path) => explicit_storage_path(path)?,
            None => default_storage_path(
                std::env::var_os("XDG_DATA_HOME").as_deref(),
                std::env::var_os("HOME").as_deref(),
            )?,
        };

        let dht_gateways = std::env::var("SCP_RELAY_DHT_GATEWAYS")
            .ok()
            .map(|v| {
                v.split(',')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(String::from)
                    .collect()
            })
            .unwrap_or_default();

        Ok(Self {
            domain,
            acme_email: non_empty_env("SCP_RELAY_ACME_EMAIL"),
            bind_addr,
            tls_self_signed,
            tls_cert_path: non_empty_env("SCP_RELAY_TLS_CERT").map(PathBuf::from),
            tls_key_path: non_empty_env("SCP_RELAY_TLS_KEY").map(PathBuf::from),
            storage_path,
            storage_key_hex: non_empty_env("SCP_RELAY_STORAGE_KEY"),
            dht_gateways,
            log_level: std::env::var("SCP_RELAY_LOG_LEVEL").unwrap_or_else(|_| "info".into()),
            log_format: std::env::var("SCP_RELAY_LOG_FORMAT").unwrap_or_else(|_| "pretty".into()),
        })
    }
}

/// Returns `Some(value)` if the env var exists and is non-empty, `None` otherwise.
fn non_empty_env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

/// Accepts an operator-named `SCP_RELAY_STORAGE_PATH` only when it is
/// absolute.
///
/// A relative path resolves against the working directory, so a relay started
/// from two working directories would open two stores and leave the first
/// store's blobs unread without an error. `scp-transport`'s `storage_path`
/// refuses the same variable for the same reason.
fn explicit_storage_path(raw: String) -> Result<PathBuf, String> {
    let path = PathBuf::from(raw);
    if !path.is_absolute() {
        return Err(format!(
            "SCP_RELAY_STORAGE_PATH='{}' is relative, and a relative path opens a different \
             store for every working directory the relay starts in. Name an absolute path.",
            path.display()
        ));
    }
    Ok(path)
}

/// Default storage path following the XDG Base Directory Specification, over
/// explicit `XDG_DATA_HOME` and `HOME` values.
///
/// An empty or relative `XDG_DATA_HOME` is ignored, as that specification
/// directs. An empty or relative `HOME` is rejected, and so is an unset one:
/// a relative base resolves against the working directory, so a relay started
/// from two working directories would open two databases under two storage
/// keys, and a fixed fallback such as `/tmp` is a directory another local
/// user can create first.
fn default_storage_path(
    xdg_data_home: Option<&std::ffi::OsStr>,
    home: Option<&std::ffi::OsStr>,
) -> Result<PathBuf, String> {
    if let Some(xdg) = xdg_data_home.map(Path::new).filter(|xdg| xdg.is_absolute()) {
        return Ok(xdg.join("scp").join("personal-relay"));
    }
    let home = home
        .map(Path::new)
        .filter(|home| home.is_absolute())
        .ok_or_else(|| {
            "HOME is unset, empty, or relative, and neither SCP_RELAY_STORAGE_PATH nor an \
             absolute XDG_DATA_HOME is set; set one of them to an absolute directory"
                .to_owned()
        })?;
    Ok(home
        .join(".local")
        .join("share")
        .join("scp")
        .join("personal-relay"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsStr;

    /// An unset, empty, or relative `HOME` is rejected rather than replaced by
    /// `/tmp` or resolved against the working directory; an empty or relative
    /// `XDG_DATA_HOME` is ignored.
    ///
    /// Restoring the `/tmp` fallback makes the unset-`HOME` case return `Ok`,
    /// and passing `XDG_DATA_HOME` through unfiltered makes the relative
    /// `share` case return `Ok`, so either regression fails this test.
    #[test]
    fn default_storage_path_rejects_a_working_directory_relative_or_fixed_base() {
        for home in [None, Some(""), Some("data")] {
            let home = home.map(OsStr::new);
            for xdg in [None, Some(OsStr::new("")), Some(OsStr::new("share"))] {
                assert!(
                    default_storage_path(xdg, home).is_err(),
                    "HOME={home:?} XDG_DATA_HOME={xdg:?} must be rejected"
                );
            }
        }

        let home = Some(OsStr::new("/home/op"));
        assert_eq!(
            default_storage_path(Some(OsStr::new("")), home),
            Ok(PathBuf::from("/home/op/.local/share/scp/personal-relay"))
        );
        assert_eq!(
            default_storage_path(Some(OsStr::new("share")), home),
            Ok(PathBuf::from("/home/op/.local/share/scp/personal-relay"))
        );
        assert_eq!(
            default_storage_path(Some(OsStr::new("/data")), home),
            Ok(PathBuf::from("/data/scp/personal-relay"))
        );
    }

    /// An operator-named relative `SCP_RELAY_STORAGE_PATH` is rejected and an
    /// absolute one is kept as given.
    ///
    /// Returning `PathBuf::from(raw)` without the `is_absolute` check makes the
    /// relative cases return `Ok`, so that regression fails this test.
    #[test]
    fn explicit_storage_path_rejects_a_relative_path() {
        for relative in ["data/relay", "relay.db", "./relay", "../relay"] {
            let err = explicit_storage_path(relative.to_owned())
                .expect_err("a relative SCP_RELAY_STORAGE_PATH must be rejected");
            assert!(err.contains("SCP_RELAY_STORAGE_PATH"), "{err}");
            assert!(err.contains(relative), "{err}");
        }
        assert_eq!(
            explicit_storage_path("/var/lib/scp/relay".to_owned()),
            Ok(PathBuf::from("/var/lib/scp/relay"))
        );
    }
}
