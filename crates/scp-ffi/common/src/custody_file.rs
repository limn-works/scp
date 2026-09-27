//! Opens the encrypted key file that backs `"file"` custody, for every bridge.
//!
//! `FileKeyCustody` (Argon2id + AES-256-GCM, spec §17.8) is the production key
//! backend on a desktop or a server: the process holds the keys itself, in one
//! encrypted file, with no platform key store and no injected provider. iOS and
//! Android identities instead inject a `KeyCustodyProvider` backed by the
//! Secure Enclave or the Android Keystore (ADR-006), so this backend never
//! replaces that one — it serves the platforms that have no such key store.
//!
//! The `PyO3` and napi-rs bridges each resolve the same two inputs before they
//! construct that custody: a directory under `$HOME` and a passphrase from
//! `SCP_KEY_PASSPHRASE`. This module holds that resolution once so neither
//! bridge reads a different path, and neither phrases a missing passphrase
//! differently. The `UniFFI` bridge has no `"file"` custody: its callers inject
//! a `KeyCustodyProvider`.
//!
//! Resolution ([`resolve_file_custody_inputs`]) reads the environment and
//! touches no file; opening ([`FileCustodyInputs::open`]) creates the directory
//! and the key file. A bridge whose creation path fails closed before it can
//! use the custody resolves the inputs, so a caller still learns about a
//! missing variable, and never opens the file, so that failing call leaves no
//! key file behind.
//!
//! Gated behind the `custody` feature, which pulls in `scp-platform`.
//!
//! See ADR-006, spec §17.8, and §17.17.1 (custody selection is required).

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use scp_platform::file::FileKeyCustody;
use zeroize::Zeroizing;

/// Why a bridge could not open the encrypted key file.
///
/// A bridge maps each variant onto its own error type. The variants stay
/// distinct because a caller acts differently on each: an unset environment
/// variable is something the caller sets, and a rejected key file is something
/// the caller restores.
#[derive(Debug)]
pub enum FileCustodyError {
    /// `$HOME` is unset or empty, so this process cannot place a key file.
    HomeUnset,
    /// `$HOME` names a relative path, which resolves against the working
    /// directory, so two working directories would hold two key files.
    HomeNotAbsolute {
        /// The value `$HOME` carried.
        home: PathBuf,
    },
    /// `SCP_KEY_PASSPHRASE` is unset or empty. An empty passphrase seals the
    /// key file under a key anyone who reads the file can derive.
    PassphraseUnset,
    /// Creating the `$HOME/.scp` directory failed.
    DirectoryCreate {
        /// Directory this bridge tried to create.
        path: PathBuf,
        /// What the filesystem reported.
        message: String,
    },
    /// `FileKeyCustody::new` rejected the key file — a wrong passphrase, a
    /// header this build does not accept, or a failed integrity check.
    Open {
        /// Key file this bridge tried to open.
        path: PathBuf,
        /// What `scp-platform` reported.
        message: String,
    },
}

impl std::fmt::Display for FileCustodyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::HomeUnset => f.write_str(
                "file custody requires a HOME environment variable naming an absolute \
                 directory — it holds an encrypted key file at $HOME/.scp/keys.bin",
            ),
            Self::HomeNotAbsolute { home } => write!(
                f,
                "file custody requires HOME to name an absolute directory, but HOME is {:?} — \
                 a relative HOME puts the encrypted key file $HOME/.scp/keys.bin under \
                 whichever directory the process started in",
                home.display().to_string()
            ),
            Self::PassphraseUnset => f.write_str(
                "file custody requires the SCP_KEY_PASSPHRASE environment variable to be \
                 set to a non-empty value — this passphrase protects the encrypted key file",
            ),
            Self::DirectoryCreate { path, message } => {
                write!(
                    f,
                    "failed to create key directory {}: {message}",
                    path.display()
                )
            }
            Self::Open { path, message } => {
                write!(
                    f,
                    "failed to initialize file-backed key custody at {}: {message}",
                    path.display()
                )
            }
        }
    }
}

impl std::error::Error for FileCustodyError {}

/// Returns the directory that holds this process's key file.
///
/// # Errors
///
/// Returns [`FileCustodyError::HomeUnset`] when `$HOME` is unset or empty, and
/// [`FileCustodyError::HomeNotAbsolute`] when it names a relative path. An
/// earlier version substituted a working directory, so a service started from
/// two working directories wrote two key files and held two identities while
/// reporting nothing unusual; an empty or relative `$HOME` resolves against the
/// working directory in the same way.
pub fn key_directory() -> Result<PathBuf, FileCustodyError> {
    key_directory_from(std::env::var_os("HOME").as_deref())
}

/// [`key_directory`] over an explicit `$HOME` value, so a test exercises every
/// case without mutating the process environment.
fn key_directory_from(home: Option<&OsStr>) -> Result<PathBuf, FileCustodyError> {
    let home = home
        .filter(|home| !home.is_empty())
        .ok_or(FileCustodyError::HomeUnset)?;
    let home = Path::new(home);
    if !home.is_absolute() {
        return Err(FileCustodyError::HomeNotAbsolute {
            home: home.to_path_buf(),
        });
    }
    Ok(home.join(".scp"))
}

/// Returns the key file path this process uses: `$HOME/.scp/keys.bin`.
///
/// # Errors
///
/// Returns the errors [`key_directory`] returns.
pub fn key_file_path() -> Result<PathBuf, FileCustodyError> {
    Ok(key_directory()?.join("keys.bin"))
}

/// The key directory and passphrase `"file"` custody opens, resolved from the
/// environment without touching any file.
pub struct FileCustodyInputs {
    key_dir: PathBuf,
    passphrase: Zeroizing<String>,
}

impl std::fmt::Debug for FileCustodyInputs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileCustodyInputs")
            .field("key_dir", &self.key_dir)
            .field("passphrase", &"[redacted]")
            .finish()
    }
}

/// Reads `SCP_KEY_PASSPHRASE` and `$HOME` and validates both. Creates no
/// directory and no file.
///
/// # Errors
///
/// Returns [`FileCustodyError::PassphraseUnset`] when `SCP_KEY_PASSPHRASE` is
/// unset, empty, or not valid UTF-8, and the errors [`key_directory`] returns.
pub fn resolve_file_custody_inputs() -> Result<FileCustodyInputs, FileCustodyError> {
    resolve_from(
        std::env::var("SCP_KEY_PASSPHRASE").ok().map(Zeroizing::new),
        std::env::var_os("HOME").as_deref(),
    )
}

/// [`resolve_file_custody_inputs`] over explicit values, so a test exercises
/// every case without mutating the process environment.
fn resolve_from(
    passphrase: Option<Zeroizing<String>>,
    home: Option<&OsStr>,
) -> Result<FileCustodyInputs, FileCustodyError> {
    let passphrase = passphrase
        .filter(|passphrase| !passphrase.is_empty())
        .ok_or(FileCustodyError::PassphraseUnset)?;
    let key_dir = key_directory_from(home)?;
    Ok(FileCustodyInputs {
        key_dir,
        passphrase,
    })
}

impl FileCustodyInputs {
    /// Opens (or creates) `keys.bin` in the resolved directory under the
    /// resolved passphrase, creating the directory first.
    ///
    /// # Errors
    ///
    /// Returns [`FileCustodyError::DirectoryCreate`] when the directory cannot
    /// be created and [`FileCustodyError::Open`] when `scp-platform` rejects
    /// the key file.
    pub fn open(self) -> Result<FileKeyCustody, FileCustodyError> {
        std::fs::create_dir_all(&self.key_dir).map_err(|e| FileCustodyError::DirectoryCreate {
            path: self.key_dir.clone(),
            message: e.to_string(),
        })?;

        let key_path = self.key_dir.join("keys.bin");
        FileKeyCustody::new(&key_path, &self.passphrase).map_err(|e| FileCustodyError::Open {
            path: key_path,
            message: e.to_string(),
        })
    }
}

/// Opens (or creates) `$HOME/.scp/keys.bin` under the passphrase that
/// `SCP_KEY_PASSPHRASE` carries: [`resolve_file_custody_inputs`] followed by
/// [`FileCustodyInputs::open`].
///
/// # Errors
///
/// Returns the errors those two functions return.
pub fn open_default_file_custody() -> Result<FileKeyCustody, FileCustodyError> {
    resolve_file_custody_inputs()?.open()
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// A missing `SCP_KEY_PASSPHRASE` names the variable a caller sets, rather
    /// than reporting a generic custody failure.
    #[test]
    fn passphrase_unset_names_the_environment_variable() {
        let message = FileCustodyError::PassphraseUnset.to_string();
        assert!(
            message.contains("SCP_KEY_PASSPHRASE"),
            "the message must name the variable: {message}"
        );
    }

    /// A missing `$HOME` names both the variable and the path it decides.
    #[test]
    fn home_unset_names_the_variable_and_the_path() {
        let message = FileCustodyError::HomeUnset.to_string();
        assert!(message.contains("HOME"), "must name HOME: {message}");
        assert!(
            message.contains("$HOME/.scp/keys.bin"),
            "must name the key file path: {message}"
        );
    }

    /// An empty `$HOME` is an unset one: `PathBuf::from("").join(".scp")` is
    /// the relative path `.scp`, which lands under the working directory.
    #[test]
    fn empty_home_is_rejected_as_unset() {
        assert!(matches!(
            key_directory_from(Some(OsStr::new(""))),
            Err(FileCustodyError::HomeUnset)
        ));
        assert!(matches!(
            key_directory_from(None),
            Err(FileCustodyError::HomeUnset)
        ));
    }

    /// A relative `$HOME` resolves against the working directory, so two
    /// working directories would hold two key files and two identities.
    #[test]
    fn relative_home_is_rejected() {
        match key_directory_from(Some(OsStr::new("data"))) {
            Err(FileCustodyError::HomeNotAbsolute { home }) => {
                assert_eq!(home, PathBuf::from("data"));
            }
            other => panic!("a relative HOME must be rejected, got {other:?}"),
        }
    }

    /// An absolute `$HOME` yields `$HOME/.scp`.
    #[test]
    fn absolute_home_yields_dot_scp() {
        let dir = key_directory_from(Some(OsStr::new("/home/op"))).expect("absolute HOME");
        assert_eq!(dir, PathBuf::from("/home/op/.scp"));
    }

    /// An empty passphrase seals the key file under a key anyone who reads the
    /// file derives, so it is rejected as an unset one.
    #[test]
    fn empty_passphrase_is_rejected_as_unset() {
        let home = Some(OsStr::new("/home/op"));
        assert!(matches!(
            resolve_from(Some(Zeroizing::new(String::new())), home),
            Err(FileCustodyError::PassphraseUnset)
        ));
        assert!(matches!(
            resolve_from(None, home),
            Err(FileCustodyError::PassphraseUnset)
        ));
        let inputs = resolve_from(Some(Zeroizing::new("pw".to_owned())), home)
            .expect("a non-empty passphrase and an absolute HOME resolve");
        assert_eq!(inputs.key_dir, PathBuf::from("/home/op/.scp"));
    }

    /// Resolution touches no file: resolving against a HOME that does not
    /// exist succeeds and creates nothing there.
    #[test]
    fn resolution_creates_no_file() {
        let base =
            std::env::temp_dir().join(format!("scp-custody-file-resolve-{}", std::process::id()));
        let home = base.join("absent-home");
        let inputs = resolve_from(
            Some(Zeroizing::new("pw".to_owned())),
            Some(home.as_os_str()),
        )
        .expect("resolves");
        assert_eq!(inputs.key_dir, home.join(".scp"));
        assert!(
            !home.exists(),
            "resolution must not create {}",
            home.display()
        );
    }

    /// Every bridge reads one path, so a Python caller and a TypeScript caller
    /// on one machine share one key file rather than holding two identities.
    #[test]
    fn key_file_path_is_home_dot_scp_keys_bin() {
        let Ok(home) = std::env::var("HOME") else {
            // A build host without HOME exercises the error path above.
            return;
        };
        let path = key_file_path().expect("HOME is set in this process");
        assert_eq!(path, PathBuf::from(home).join(".scp").join("keys.bin"));
    }
}
