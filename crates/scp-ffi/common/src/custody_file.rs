//! Opens the encrypted key file that backs `"file"` custody, for every bridge.
//!
//! `FileKeyCustody` (Argon2id + AES-256-GCM, spec §17.8) is the production key
//! backend on a desktop or a server: the process holds the keys itself, in one
//! encrypted file, with no platform key store and no injected provider. iOS and
//! Android identities instead inject a `KeyCustodyProvider` backed by the
//! Secure Enclave or the Android Keystore (ADR-006), so this backend never
//! replaces that one — it serves the platforms that have no such key store.
//!
//! The `PyO3`, napi-rs and `UniFFI` bridges each resolve the same two inputs
//! before they construct that custody: a directory under `$HOME` and a
//! passphrase from `SCP_KEY_PASSPHRASE`. This module holds that resolution once
//! so no bridge reads a different path, and no bridge phrases a missing
//! passphrase differently.
//!
//! Gated behind the `custody` feature, which pulls in `scp-platform`.
//!
//! See ADR-006, spec §17.8, and §17.17.1 (custody selection is required).

use std::path::PathBuf;

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
    /// `$HOME` names no directory, so this process cannot place a key file.
    HomeUnset,
    /// `SCP_KEY_PASSPHRASE` is unset, so nothing can decrypt the key file.
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
                "file custody requires a HOME environment variable naming a directory — \
                 it holds an encrypted key file at $HOME/.scp/keys.bin",
            ),
            Self::PassphraseUnset => f.write_str(
                "file custody requires the SCP_KEY_PASSPHRASE environment variable to be \
                 set — this passphrase protects the encrypted key file",
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
/// Returns [`FileCustodyError::HomeUnset`] when `$HOME` names no directory. An
/// earlier version substituted a working directory, so a service started from
/// two working directories wrote two key files and held two identities while
/// reporting nothing unusual.
pub fn key_directory() -> Result<PathBuf, FileCustodyError> {
    std::env::var("HOME")
        .map(|home| PathBuf::from(home).join(".scp"))
        .map_err(|_| FileCustodyError::HomeUnset)
}

/// Returns the key file path this process uses: `$HOME/.scp/keys.bin`.
///
/// # Errors
///
/// Returns [`FileCustodyError::HomeUnset`] when `$HOME` names no directory.
pub fn key_file_path() -> Result<PathBuf, FileCustodyError> {
    Ok(key_directory()?.join("keys.bin"))
}

/// Opens (or creates) `$HOME/.scp/keys.bin` under the passphrase that
/// `SCP_KEY_PASSPHRASE` carries.
///
/// # Errors
///
/// Returns [`FileCustodyError::HomeUnset`] when `$HOME` is unset,
/// [`FileCustodyError::PassphraseUnset`] when `SCP_KEY_PASSPHRASE` is unset,
/// [`FileCustodyError::DirectoryCreate`] when `$HOME/.scp` cannot be created,
/// and [`FileCustodyError::Open`] when `scp-platform` rejects the key file.
pub fn open_default_file_custody() -> Result<FileKeyCustody, FileCustodyError> {
    let passphrase = Zeroizing::new(
        std::env::var("SCP_KEY_PASSPHRASE").map_err(|_| FileCustodyError::PassphraseUnset)?,
    );

    let key_dir = key_directory()?;
    std::fs::create_dir_all(&key_dir).map_err(|e| FileCustodyError::DirectoryCreate {
        path: key_dir.clone(),
        message: e.to_string(),
    })?;

    let key_path = key_dir.join("keys.bin");
    FileKeyCustody::new(&key_path, &passphrase).map_err(|e| FileCustodyError::Open {
        path: key_path,
        message: e.to_string(),
    })
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
