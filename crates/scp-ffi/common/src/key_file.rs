//! The encrypted key file every bridge builds for the custody value
//! `encrypted_file`.
//!
//! §3.2.2 of the identity spec names `encrypted_file` for "the on-disk key
//! store SCP implements, which derives an AES-256 key from a passphrase with
//! Argon2id and encrypts each key entry under AES-256-GCM". The `PyO3`,
//! napi-rs, and `UniFFI` bridges all open that store at the same path from the
//! same environment variable, so this module holds the opening logic once and
//! each bridge maps [`KeyFileError`] onto its own error type.

use scp_platform::file::FileKeyCustody;

/// The environment variable that carries the passphrase protecting the
/// encrypted key file.
pub const KEY_PASSPHRASE_ENV: &str = "SCP_KEY_PASSPHRASE";

/// What stopped a bridge from opening the encrypted key file.
///
/// Each bridge maps these three cases onto its own error type: the first two
/// onto a validation error, and the third onto an identity error.
#[derive(Debug)]
pub enum KeyFileError {
    /// The caller exported no `SCP_KEY_PASSPHRASE`, so no key derives.
    MissingPassphrase,

    /// Creating the `$HOME/.scp` directory failed. The string names the
    /// directory and quotes the operating system's message.
    DirectoryCreate(String),

    /// Opening or decrypting `$HOME/.scp/keys.bin` failed. The string names
    /// the path and quotes the store's message.
    Open(String),
}

impl std::fmt::Display for KeyFileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingPassphrase => write!(
                f,
                "encrypted_file custody requires the {KEY_PASSPHRASE_ENV} environment \
                 variable to be set — this passphrase protects the encrypted key file"
            ),
            Self::DirectoryCreate(detail) | Self::Open(detail) => f.write_str(detail),
        }
    }
}

impl std::error::Error for KeyFileError {}

/// Opens the encrypted key file at `$HOME/.scp/keys.bin` under the passphrase
/// `SCP_KEY_PASSPHRASE` carries, creating `$HOME/.scp` when it does not exist.
///
/// The passphrase lives in a `Zeroizing<String>` from the moment this function
/// reads it until `FileKeyCustody::new` has consumed it, so the process wipes
/// the bytes rather than leaving them on the heap.
///
/// # Errors
///
/// Returns [`KeyFileError::MissingPassphrase`] when the environment variable
/// is unset, [`KeyFileError::DirectoryCreate`] when creating `$HOME/.scp`
/// fails, and [`KeyFileError::Open`] when the store rejects the passphrase or
/// the file is unreadable.
pub fn open_default_key_file() -> Result<FileKeyCustody, KeyFileError> {
    let passphrase = zeroize::Zeroizing::new(
        std::env::var(KEY_PASSPHRASE_ENV).map_err(|_| KeyFileError::MissingPassphrase)?,
    );

    let key_dir = home_dir().join(".scp");
    std::fs::create_dir_all(&key_dir).map_err(|e| {
        KeyFileError::DirectoryCreate(format!(
            "failed to create key directory {}: {e}",
            key_dir.display()
        ))
    })?;

    let key_path = key_dir.join("keys.bin");
    FileKeyCustody::new(&key_path, &passphrase).map_err(|e| {
        KeyFileError::Open(format!(
            "failed to initialize file-backed key custody at {}: {e}",
            key_path.display()
        ))
    })
}

/// Returns the user's home directory, and the current directory when `$HOME`
/// is unset.
fn home_dir() -> std::path::PathBuf {
    std::env::var("HOME").map_or_else(|_| std::path::PathBuf::from("."), std::path::PathBuf::from)
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use super::{KEY_PASSPHRASE_ENV, KeyFileError};

    /// The missing-passphrase message names the environment variable a caller
    /// has to export, so a caller who reads the error knows what to do next.
    #[test]
    fn the_missing_passphrase_message_names_the_environment_variable() {
        let message = KeyFileError::MissingPassphrase.to_string();
        assert!(
            message.contains(KEY_PASSPHRASE_ENV),
            "the message must name the environment variable, got: {message}"
        );
    }

    /// The two failure cases that carry a detail string print that string
    /// unchanged, so a bridge that wraps the error passes the path and the
    /// operating system's message through to the caller.
    #[test]
    fn the_detail_cases_print_their_detail_unchanged() {
        assert_eq!(
            KeyFileError::DirectoryCreate("failed to create key directory /x: denied".to_owned())
                .to_string(),
            "failed to create key directory /x: denied"
        );
        assert_eq!(
            KeyFileError::Open(
                "failed to initialize file-backed key custody at /x: bad".to_owned()
            )
            .to_string(),
            "failed to initialize file-backed key custody at /x: bad"
        );
    }
}
