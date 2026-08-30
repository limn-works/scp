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

use crate::error_codes as codes;

/// The environment variable that carries the passphrase protecting the
/// encrypted key file.
pub const KEY_PASSPHRASE_ENV: &str = "SCP_KEY_PASSPHRASE";

/// Which of a bridge's error categories reports a [`KeyFileError`].
///
/// A bridge's error type is its own — `ScpPyError::ValidationError`,
/// `ScpNapiError::Validation`, `ScpError::Validation` — so each bridge builds
/// its own value. Which category and which code, though, are one answer for all
/// three: [`KeyFileError::category`] and [`KeyFileError::code`] state them, so a
/// caller who switches on the code string reads one value from Python, from
/// Node, and from Swift or Kotlin. The three bridges each chose their own code
/// before §3.2.2 of the identity spec, the custody vocabulary, landed: one
/// missing `SCP_KEY_PASSPHRASE` read `SCP-VALID-7001` on `PyO3` and
/// `SCP-VALID-7005` on the other two, and one unopenable key file read
/// `SCP-IDENT-1001` on `PyO3` and NAPI and `SCP-IDENT-1002` on `UniFFI`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyFileErrorCategory {
    /// The caller supplied something this process cannot use, or left it
    /// unsupplied. Reported as the bridge's validation error.
    Validation,

    /// The key store itself would not open. Reported as the bridge's identity
    /// error.
    Identity,
}

/// What stopped a bridge from opening the encrypted key file.
///
/// Each bridge maps these three cases onto its own error type.
/// [`KeyFileError::category`] states which of that type's variants carries the
/// case, and [`KeyFileError::code`] states the code all three bridges return.
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

impl KeyFileError {
    /// Returns the error code every bridge returns for this condition.
    ///
    /// The match is exhaustive over the variants, so adding a variant makes
    /// this function fail to compile until the new condition is given a code,
    /// which is what keeps the three bridges from drifting again.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::MissingPassphrase | Self::DirectoryCreate(_) => codes::VALID_7005,
            Self::Open(_) => codes::IDENT_1001,
        }
    }

    /// Returns the bridge error category that carries this condition.
    #[must_use]
    pub const fn category(&self) -> KeyFileErrorCategory {
        match self {
            Self::MissingPassphrase | Self::DirectoryCreate(_) => KeyFileErrorCategory::Validation,
            Self::Open(_) => KeyFileErrorCategory::Identity,
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
/// is unset or holds an empty string, [`KeyFileError::DirectoryCreate`] when
/// creating `$HOME/.scp` fails or `$HOME` is unset, and [`KeyFileError::Open`]
/// when the file is unreadable.
///
/// It does NOT report a wrong passphrase. `FileKeyCustody::new` derives the
/// wrapping key and reads the entry headers without decrypting an entry, so a
/// wrong passphrase opens the store and surfaces at the first signing
/// operation. Open question OQ-16 of `.docs/specs/03-identity.md` owns that.
pub fn open_default_key_file() -> Result<FileKeyCustody, KeyFileError> {
    // An exported-but-empty variable reads as `Ok("")`, and Argon2id accepts a
    // zero-length password, so an empty value would derive a wrapping key that
    // anyone holding the file can recompute — the salt sits in its header in
    // the clear. The no-dev-stand-in tenet of `CLAUDE.md` puts a capability
    // that cannot be provided honestly on the failing side, so an empty
    // passphrase reads as no passphrase.
    let passphrase = zeroize::Zeroizing::new(
        std::env::var(KEY_PASSPHRASE_ENV)
            .ok()
            .filter(|value| !value.is_empty())
            .ok_or(KeyFileError::MissingPassphrase)?,
    );

    let key_dir = home_dir()?.join(".scp");
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

/// Returns the user's home directory.
///
/// # Errors
///
/// Returns [`KeyFileError::DirectoryCreate`] when `$HOME` is unset. This read
/// the current directory in that case, which put the key store at
/// `./.scp/keys.bin` under whatever directory the process happened to start
/// in — a daemon, a container entrypoint, and a scheduled job each run with
/// `$HOME` unset. `FileKeyCustody::new` creates a store when the path holds no
/// file, so a restart from a second directory produced a second empty key
/// store and reported success. Failing here states the condition instead.
fn home_dir() -> Result<std::path::PathBuf, KeyFileError> {
    std::env::var("HOME")
        .map(std::path::PathBuf::from)
        .map_err(|_| {
            KeyFileError::DirectoryCreate(
                "HOME is unset, so this process names no key directory. Set HOME, \
                 or reach a key store through a KeyCustodyProvider."
                    .to_owned(),
            )
        })
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use super::{KEY_PASSPHRASE_ENV, KeyFileError, KeyFileErrorCategory, codes};

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

    /// Each condition carries one code and one category, which is what makes
    /// the three bridges agree. A bridge that picked its own code was the
    /// defect: one missing `SCP_KEY_PASSPHRASE` read `SCP-VALID-7001` on `PyO3`
    /// and `SCP-VALID-7005` on the other two, so an application that branched on
    /// the code string to prompt an operator took the branch on Node and fell
    /// through on Python.
    #[test]
    fn every_condition_carries_one_code_and_one_category() {
        for (error, code, category) in [
            (
                KeyFileError::MissingPassphrase,
                codes::VALID_7005,
                KeyFileErrorCategory::Validation,
            ),
            (
                KeyFileError::DirectoryCreate("d".to_owned()),
                codes::VALID_7005,
                KeyFileErrorCategory::Validation,
            ),
            (
                KeyFileError::Open("o".to_owned()),
                codes::IDENT_1001,
                KeyFileErrorCategory::Identity,
            ),
        ] {
            assert_eq!(error.code(), code, "wrong code for {error:?}");
            assert_eq!(error.category(), category, "wrong category for {error:?}");
        }
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
