//! Resolves and opens the encrypted key file that backs `"file"` custody.
//!
//! `FileKeyCustody` (Argon2id + AES-256-GCM, spec §17.8) holds a process's keys
//! in one encrypted file at `$HOME/.scp/keys.bin`, sealed under the passphrase
//! `SCP_KEY_PASSPHRASE` carries. A bridge that offers `"file"` custody resolves
//! those two inputs here, so every bridge reads one path and rejects one set of
//! bad inputs.
//!
//! Resolution ([`resolve_file_custody_inputs`]) reads the environment and
//! touches no file. Opening ([`FileCustodyInputs::open`]) creates the directory
//! and the key file. A creation path that fails closed before it could use the
//! custody (ADR-062 §Decision 6) resolves the inputs, so its caller still
//! learns about a bad variable, and never opens, so the failed call leaves no
//! key file behind.
//!
//! An unset, empty or relative `$HOME` is an error, never a default: an empty
//! or relative `$HOME` resolves against the working directory, so a process
//! started from two working directories would write two key files and hold two
//! identities while reporting nothing unusual.
//!
//! Gated behind the `custody` feature, which compiles `scp-platform/file`.
//! See ADR-006 and spec §17.8 and §17.17.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use scp_platform::file::FileKeyCustody;
use zeroize::Zeroizing;

/// Why a bridge could not resolve or open the encrypted key file.
///
/// The variants stay distinct because a caller acts on each differently: an
/// environment variable is something the caller sets, and a key file this
/// process cannot open is something the caller repairs or restores.
#[derive(Debug)]
pub enum FileCustodyError {
    /// `$HOME` is unset or empty, so this process has no directory to hold a
    /// key file.
    HomeUnset,
    /// `$HOME` names a relative path, which resolves against the working
    /// directory.
    HomeNotAbsolute {
        /// The value `$HOME` carried.
        home: PathBuf,
    },
    /// `SCP_KEY_PASSPHRASE` is unset, empty, or not valid UTF-8. Argon2id over
    /// an empty passphrase yields a key anyone who reads the salt can derive
    /// (spec §17.8).
    PassphraseUnset,
    /// Creating the `$HOME/.scp` directory failed.
    DirectoryCreate {
        /// Directory this process tried to create.
        path: PathBuf,
        /// What the filesystem reported.
        message: String,
    },
    /// `FileKeyCustody::new` rejected the key file: a wrong passphrase, a
    /// version this build rejects, a failed integrity check, or an I/O error.
    Open {
        /// Key file this process tried to open.
        path: PathBuf,
        /// What `scp-platform` reported.
        message: String,
    },
}

impl std::fmt::Display for FileCustodyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::HomeUnset => f.write_str(
                "file custody requires the HOME environment variable to name an absolute \
                 directory; it is unset or empty, and the encrypted key file lives at \
                 $HOME/.scp/keys.bin",
            ),
            Self::HomeNotAbsolute { home } => write!(
                f,
                "file custody requires HOME to name an absolute directory, but HOME is {:?}; \
                 a relative HOME places the encrypted key file $HOME/.scp/keys.bin under \
                 whichever directory the process started in",
                home.display().to_string()
            ),
            Self::PassphraseUnset => f.write_str(
                "file custody requires the SCP_KEY_PASSPHRASE environment variable to be \
                 set to a non-empty value; this passphrase protects the encrypted key file",
            ),
            Self::DirectoryCreate { path, message } => write!(
                f,
                "failed to create key directory {}: {message}",
                path.display()
            ),
            Self::Open { path, message } => write!(
                f,
                "failed to initialize file-backed key custody at {}: {message}",
                path.display()
            ),
        }
    }
}

impl std::error::Error for FileCustodyError {}

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
/// unset, empty, or not valid UTF-8; [`FileCustodyError::HomeUnset`] when
/// `$HOME` is unset or empty; and [`FileCustodyError::HomeNotAbsolute`] when it
/// names a relative path.
pub fn resolve_file_custody_inputs() -> Result<FileCustodyInputs, FileCustodyError> {
    resolve_from(
        std::env::var("SCP_KEY_PASSPHRASE").ok().map(Zeroizing::new),
        std::env::var_os("HOME").as_deref(),
    )
}

/// [`resolve_file_custody_inputs`] over explicit values, so a test covers every
/// case without mutating the process environment.
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

/// Returns `$HOME/.scp` for an absolute, non-empty `home`.
fn key_directory_from(home: Option<&OsStr>) -> Result<PathBuf, FileCustodyError> {
    let home = home
        .filter(|home| !home.is_empty())
        .map(Path::new)
        .ok_or(FileCustodyError::HomeUnset)?;
    if !home.is_absolute() {
        return Err(FileCustodyError::HomeNotAbsolute {
            home: home.to_path_buf(),
        });
    }
    Ok(home.join(".scp"))
}

impl FileCustodyInputs {
    /// Path of the key file these inputs open: `$HOME/.scp/keys.bin`.
    #[must_use]
    pub fn key_path(&self) -> PathBuf {
        self.key_dir.join("keys.bin")
    }

    /// Creates the key directory, then opens (or creates) `keys.bin` in it
    /// under the resolved passphrase.
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
        let key_path = self.key_path();
        FileKeyCustody::new(&key_path, &self.passphrase).map_err(|e| FileCustodyError::Open {
            path: key_path,
            message: e.to_string(),
        })
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    const PASSPHRASE: &str = "custody-file-test-passphrase";

    fn passphrase() -> Zeroizing<String> {
        Zeroizing::new(PASSPHRASE.to_owned())
    }

    /// An unset or empty `$HOME` is rejected: `Path::new("").join(".scp")` is
    /// the relative path `.scp`, which lands under the working directory.
    #[test]
    fn unset_or_empty_home_is_rejected() {
        for home in [None, Some(OsStr::new(""))] {
            match resolve_from(Some(passphrase()), home) {
                Err(FileCustodyError::HomeUnset) => {}
                other => panic!("HOME={home:?} must be rejected as unset, got {other:?}"),
            }
        }
    }

    /// A relative `$HOME` resolves against the working directory, so it is
    /// rejected and the error carries the value.
    #[test]
    fn relative_home_is_rejected() {
        for home in ["data", ".", "./home/op"] {
            match resolve_from(Some(passphrase()), Some(OsStr::new(home))) {
                Err(FileCustodyError::HomeNotAbsolute { home: carried }) => {
                    assert_eq!(carried, PathBuf::from(home));
                }
                other => panic!("HOME={home:?} must be rejected as relative, got {other:?}"),
            }
        }
    }

    /// An unset or empty passphrase is rejected before `$HOME` is read.
    #[test]
    fn unset_or_empty_passphrase_is_rejected() {
        let home = Some(OsStr::new("/home/op"));
        for pass in [None, Some(Zeroizing::new(String::new()))] {
            assert!(matches!(
                resolve_from(pass, home),
                Err(FileCustodyError::PassphraseUnset)
            ));
        }
    }

    /// An absolute `$HOME` and a non-empty passphrase yield
    /// `$HOME/.scp/keys.bin`.
    #[test]
    fn absolute_home_yields_dot_scp_keys_bin() {
        let inputs =
            resolve_from(Some(passphrase()), Some(OsStr::new("/home/op"))).expect("valid inputs");
        assert_eq!(inputs.key_path(), PathBuf::from("/home/op/.scp/keys.bin"));
    }

    /// Resolution touches no file; opening creates the directory and the key
    /// file.
    #[test]
    fn resolution_creates_nothing_and_open_creates_the_key_file() {
        let base =
            std::env::temp_dir().join(format!("scp-test-custody-file-open-{}", std::process::id()));
        let home = base.join("home");
        let inputs =
            resolve_from(Some(passphrase()), Some(home.as_os_str())).expect("valid inputs");
        assert!(
            !home.exists(),
            "resolution must not create {}",
            home.display()
        );

        let key_path = inputs.key_path();
        let opened = inputs.open();
        let created = key_path.is_file();
        let _ = std::fs::remove_dir_all(&base);
        opened.expect("open creates the key file");
        assert!(created, "open must create {}", key_path.display());
    }

    /// Every message names the variable or path its caller acts on.
    #[test]
    fn messages_name_what_the_caller_fixes() {
        assert!(FileCustodyError::HomeUnset.to_string().contains("HOME"));
        assert!(
            FileCustodyError::PassphraseUnset
                .to_string()
                .contains("SCP_KEY_PASSPHRASE")
        );
        let relative = FileCustodyError::HomeNotAbsolute {
            home: PathBuf::from("data"),
        }
        .to_string();
        assert!(relative.contains("\"data\""), "{relative}");
    }

    /// The passphrase never reaches `Debug` output.
    #[test]
    fn debug_redacts_the_passphrase() {
        let inputs =
            resolve_from(Some(passphrase()), Some(OsStr::new("/home/op"))).expect("valid inputs");
        let debug = format!("{inputs:?}");
        assert!(!debug.contains(PASSPHRASE), "{debug}");
    }
}
