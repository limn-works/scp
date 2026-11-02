//! Resolves and opens the encrypted key file that backs custody
//! `"encrypted_file"` (spec `03-identity.md` §3.2.2).
//!
//! `FileKeyCustody` (Argon2id + AES-256-GCM, spec §17.8) holds a process's keys
//! in one encrypted file at `$HOME/.scp/keys.bin`, sealed under the passphrase
//! `SCP_KEY_PASSPHRASE` carries. A bridge that offers `"encrypted_file"` custody resolves
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
    /// `FileKeyCustody::open` rejected the key file: a wrong passphrase, a
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
                "custody \"encrypted_file\" requires the HOME environment variable to name an absolute \
                 directory; it is unset or empty, and the encrypted key file lives at \
                 $HOME/.scp/keys.bin",
            ),
            Self::HomeNotAbsolute { home } => write!(
                f,
                "custody \"encrypted_file\" requires HOME to name an absolute directory, but HOME is {:?}; \
                 a relative HOME places the encrypted key file $HOME/.scp/keys.bin under \
                 whichever directory the process started in",
                home.display().to_string()
            ),
            Self::PassphraseUnset => f.write_str(
                "custody \"encrypted_file\" requires the SCP_KEY_PASSPHRASE environment variable to be \
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

/// The key directory and passphrase `"encrypted_file"` custody opens, resolved from the
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
    resolve_file_custody_inputs_from(
        std::env::var("SCP_KEY_PASSPHRASE").ok().map(Zeroizing::new),
        std::env::var_os("HOME").as_deref(),
    )
}

/// [`resolve_file_custody_inputs`] over explicit values, so a test covers every
/// case without mutating the process environment.
///
/// # Errors
///
/// Returns the errors [`resolve_file_custody_inputs`] returns, for the same
/// inputs.
pub fn resolve_file_custody_inputs_from(
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
    /// Both steps run on `runtime`'s blocking pool: the open runs an Argon2id
    /// derivation that takes seconds in an unoptimized build, and every
    /// bridge calls this function from an async function. The custody this
    /// returns keeps `runtime` for every later key operation, so a bridge
    /// passes the handle of its process-wide runtime. Dropping the returned
    /// future leaves the open running to completion, which leaves either a
    /// complete key file or none (see `FileKeyCustody::open`).
    ///
    /// # Errors
    ///
    /// Returns [`FileCustodyError::DirectoryCreate`] when the directory cannot
    /// be created and [`FileCustodyError::Open`] when `scp-platform` rejects
    /// the key file or a blocking task fails.
    pub async fn open(
        self,
        runtime: tokio::runtime::Handle,
    ) -> Result<FileKeyCustody, FileCustodyError> {
        let key_path = self.key_path();
        let key_dir = self.key_dir.clone();
        runtime
            .spawn_blocking(move || std::fs::create_dir_all(&key_dir))
            .await
            .map_err(|e| FileCustodyError::DirectoryCreate {
                path: self.key_dir.clone(),
                message: format!("the task creating the key directory failed: {e}"),
            })?
            .map_err(|e| FileCustodyError::DirectoryCreate {
                path: self.key_dir.clone(),
                message: e.to_string(),
            })?;
        FileKeyCustody::open(&key_path, &self.passphrase, runtime)
            .await
            .map_err(|e| FileCustodyError::Open {
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
            match resolve_file_custody_inputs_from(Some(passphrase()), home) {
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
            match resolve_file_custody_inputs_from(Some(passphrase()), Some(OsStr::new(home))) {
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
                resolve_file_custody_inputs_from(pass, home),
                Err(FileCustodyError::PassphraseUnset)
            ));
        }
    }

    /// An absolute `$HOME` and a non-empty passphrase yield
    /// `$HOME/.scp/keys.bin`.
    #[test]
    fn absolute_home_yields_dot_scp_keys_bin() {
        let inputs =
            resolve_file_custody_inputs_from(Some(passphrase()), Some(OsStr::new("/home/op")))
                .expect("valid inputs");
        assert_eq!(inputs.key_path(), PathBuf::from("/home/op/.scp/keys.bin"));
    }

    /// Resolution touches no file; opening creates the directory and the key
    /// file, and both run on the blocking pool.
    ///
    /// The open runs under
    /// `scp_platform::testing::blocking_pool::drive_while_the_blocking_pool_is_held`,
    /// whose observer checks the key directory while the pool's only thread is
    /// held. Creating the directory inline, outside the blocking task, makes it
    /// exist then and fails `!observed`; running the whole open inline makes it
    /// finish while the pool is held and fails `!finished_while_held`.
    #[test]
    fn resolution_creates_nothing_and_open_creates_the_key_file_on_the_blocking_pool() {
        use scp_platform::testing::blocking_pool::{
            blocking_pool_of_one, drive_while_the_blocking_pool_is_held,
        };

        let base = tempfile::tempdir().expect("create a temporary directory");
        let home = base.path().join("home");
        let inputs = resolve_file_custody_inputs_from(Some(passphrase()), Some(home.as_os_str()))
            .expect("valid inputs");
        assert!(
            !home.exists(),
            "resolution must not create {}",
            home.display()
        );

        let key_dir = home.join(".scp");
        let key_path = inputs.key_path();
        let runtime = blocking_pool_of_one().expect("build the probe runtime");
        let outcome = runtime
            .block_on(drive_while_the_blocking_pool_is_held(
                inputs.open(runtime.handle().clone()),
                || key_dir.exists(),
            ))
            .expect("run the probe");
        assert!(
            !outcome.finished_while_held,
            "the open ran on the thread polling it"
        );
        assert!(
            !outcome.observed,
            "the key directory was created on the thread polling the open"
        );
        outcome.output.expect("open creates the key file");
        assert!(
            key_path.is_file(),
            "open must create {}",
            key_path.display()
        );
    }

    /// An open waiting on a key file another process reserved runs on the
    /// blocking pool.
    ///
    /// A zero-byte `keys.bin` makes the open poll for up to 10 s while the
    /// process that reserved it finishes writing. With the pool's only thread
    /// held the open cannot start; the observer then writes a one-byte header
    /// of an unknown format version over the reservation, so the released open
    /// reads it and fails at once. Run inline, the open finishes on its first
    /// poll, after the whole 10 s wait, and fails `!finished_while_held`.
    #[test]
    fn an_open_waiting_on_a_reserved_key_file_runs_on_the_blocking_pool() {
        use scp_platform::testing::blocking_pool::{
            blocking_pool_of_one, drive_while_the_blocking_pool_is_held,
        };

        let base = tempfile::tempdir().expect("create a temporary directory");
        let home = base.path().join("home");
        let inputs = resolve_file_custody_inputs_from(Some(passphrase()), Some(home.as_os_str()))
            .expect("valid inputs");
        let key_path = inputs.key_path();
        std::fs::create_dir_all(home.join(".scp")).expect("create the key directory");
        std::fs::write(&key_path, b"").expect("reserve keys.bin");

        let runtime = blocking_pool_of_one().expect("build the probe runtime");
        let outcome = runtime
            .block_on(drive_while_the_blocking_pool_is_held(
                inputs.open(runtime.handle().clone()),
                || std::fs::write(&key_path, [0xFF]).expect("write an unknown header"),
            ))
            .expect("run the probe");
        assert!(
            !outcome.finished_while_held,
            "the open ran on the thread polling it"
        );
        match outcome.output {
            Err(FileCustodyError::Open { message, .. }) => assert!(
                message.contains("unsupported key file version"),
                "the open must read the header written while the pool was held: {message}"
            ),
            other => panic!("expected an Open error naming the version, got {other:?}"),
        }
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
            resolve_file_custody_inputs_from(Some(passphrase()), Some(OsStr::new("/home/op")))
                .expect("valid inputs");
        let debug = format!("{inputs:?}");
        assert!(!debug.contains(PASSPHRASE), "{debug}");
    }
}
