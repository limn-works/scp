//! Atomic, durable writes of small secret files: a key file, a salt, a
//! storage key.
//!
//! Each write goes to a randomly named sibling opened with `O_EXCL` and mode
//! `0o600`, is synced, and only then appears under its final name, after
//! which the parent directory is synced. A crash at any point therefore
//! leaves either the earlier state or the complete new file under the final
//! name, never a missing, empty or partly written one. A secret that keys
//! other durable data (a database key, a salt) must be on disk this way before
//! that data is written under it; otherwise a crash can leave the data with no
//! key that opens it.
//!
//! [`replace`] overwrites whatever the final name holds. [`create`] never
//! does: when another writer published first it reports
//! [`Created::AlreadyPresent`] and leaves the winner's file in place, so two
//! processes generating the same secret at once agree on one.
//!
//! Every secret-file writer in this workspace calls this module, so the
//! guarantee lives in one place.

use std::io::Write as _;
use std::path::{Path, PathBuf};

use rand::RngCore as _;

/// Which step of a durable write failed, the path it acted on, and what the
/// file system reported.
#[derive(Debug)]
pub struct DurableWriteError {
    /// The step that failed, phrased to follow "failed to".
    pub step: &'static str,
    /// The path that step acted on.
    pub path: PathBuf,
    /// What the file system reported.
    pub source: std::io::Error,
}

impl std::fmt::Display for DurableWriteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "failed to {} {}: {}",
            self.step,
            self.path.display(),
            self.source
        )
    }
}

impl std::error::Error for DurableWriteError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

/// What [`create`] found at the final name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Created {
    /// This call published its data.
    Written,
    /// A file already held the final name, so this call wrote nothing there
    /// and the caller reads that file instead.
    AlreadyPresent,
}

/// Writes `data` to `path`, replacing whatever `path` holds, atomically and
/// durably.
///
/// # Errors
///
/// Returns [`DurableWriteError`] naming the step that failed. A failure
/// leaves `path` as it was and removes the temporary file.
pub fn replace(path: &Path, data: &[u8]) -> Result<(), DurableWriteError> {
    let (parent, tmp) = write_temp(path, data)?;
    std::fs::rename(&tmp, path).map_err(|source| {
        let _ = std::fs::remove_file(&tmp);
        DurableWriteError {
            step: "rename a temporary file onto",
            path: path.to_path_buf(),
            source,
        }
    })?;
    sync_dir(parent);
    Ok(())
}

/// Writes `data` to `path` atomically and durably when no file holds `path`
/// yet, and otherwise leaves that file alone.
///
/// The complete, synced temporary file is hard-linked to `path`, which fails
/// when `path` exists, so a concurrent creator that published first wins and
/// this call reports [`Created::AlreadyPresent`].
///
/// # Errors
///
/// Returns [`DurableWriteError`] naming the step that failed. A failure
/// removes the temporary file and leaves `path` as it was.
pub fn create(path: &Path, data: &[u8]) -> Result<Created, DurableWriteError> {
    let (parent, tmp) = write_temp(path, data)?;
    let linked = std::fs::hard_link(&tmp, path);
    let _ = std::fs::remove_file(&tmp);
    let created = match linked {
        Ok(()) => Created::Written,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Created::AlreadyPresent,
        Err(source) => {
            return Err(DurableWriteError {
                step: "link a temporary file to",
                path: path.to_path_buf(),
                source,
            });
        }
    };
    // Persists the new link and the removed temporary name together.
    sync_dir(parent);
    Ok(created)
}

/// Writes `data` to a new, randomly named sibling of `path` with mode `0o600`
/// and syncs it. Returns the parent directory and the temporary path.
///
/// The name carries 128 bits from the OS random source, so no concurrent
/// writer collides with it and nobody can plant a file or symlink there in
/// advance; `O_EXCL` refuses one anyway.
fn write_temp<'a>(path: &'a Path, data: &[u8]) -> Result<(&'a Path, PathBuf), DurableWriteError> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut suffix = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut suffix);
    let file_name = path
        .file_name()
        .map_or_else(|| "secret".into(), |name| name.to_string_lossy());
    let tmp = parent.join(format!(
        "{file_name}.{:032x}.tmp",
        u128::from_le_bytes(suffix)
    ));

    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options.open(&tmp).map_err(|source| DurableWriteError {
        step: "create the temporary file",
        path: tmp.clone(),
        source,
    })?;
    let written = file
        .write_all(data)
        .map_err(|source| ("write the temporary file", source))
        .and_then(|()| {
            file.sync_all()
                .map_err(|source| ("sync the temporary file", source))
        });
    if let Err((step, source)) = written {
        drop(file);
        let _ = std::fs::remove_file(&tmp);
        return Err(DurableWriteError {
            step,
            path: tmp,
            source,
        });
    }
    Ok((parent, tmp))
}

/// Syncs `dir` so a rename or link into it survives a crash. Best effort: a
/// platform or file system without directory sync reports an error, and the
/// write that preceded it has already been synced.
fn sync_dir(dir: &Path) {
    #[cfg(unix)]
    if let Ok(handle) = std::fs::File::open(dir) {
        let _ = handle.sync_all();
    }
    #[cfg(not(unix))]
    let _ = dir;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Lists every name in `dir`.
    fn names(dir: &Path) -> Result<Vec<String>, std::io::Error> {
        std::fs::read_dir(dir)?
            .map(|entry| Ok(entry?.file_name().to_string_lossy().into_owned()))
            .collect()
    }

    /// `create` publishes the complete data at mode `0o600` and leaves no
    /// temporary file behind.
    #[test]
    fn create_publishes_the_whole_file_and_no_temporary() -> Result<(), Box<dyn std::error::Error>>
    {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join(".key");
        assert_eq!(create(&path, &[7; 32])?, Created::Written);
        assert_eq!(std::fs::read(&path)?, vec![7; 32]);
        assert_eq!(names(dir.path())?, vec![".key".to_owned()]);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                std::fs::metadata(&path)?.permissions().mode() & 0o777,
                0o600
            );
        }
        Ok(())
    }

    /// `create` never overwrites: a second creator reads `AlreadyPresent`,
    /// the first creator's bytes stay, and no temporary file remains.
    #[test]
    fn create_leaves_an_existing_file_alone() -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join(".key");
        assert_eq!(create(&path, &[1; 32])?, Created::Written);
        assert_eq!(create(&path, &[2; 32])?, Created::AlreadyPresent);
        assert_eq!(std::fs::read(&path)?, vec![1; 32]);
        assert_eq!(names(dir.path())?, vec![".key".to_owned()]);
        Ok(())
    }

    /// `replace` overwrites the final name and leaves no temporary file.
    #[test]
    fn replace_overwrites_and_leaves_no_temporary() -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("keys.bin");
        replace(&path, b"first")?;
        replace(&path, b"second")?;
        assert_eq!(std::fs::read(&path)?, b"second");
        assert_eq!(names(dir.path())?, vec!["keys.bin".to_owned()]);
        Ok(())
    }

    /// A write into a directory that does not exist fails and names the
    /// temporary file it could not create.
    #[test]
    fn a_failed_write_names_its_step() -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("missing").join(".key");
        let Err(error) = create(&path, &[0; 32]) else {
            return Err("a write under a missing directory must fail".into());
        };
        assert_eq!(error.step, "create the temporary file");
        assert!(
            error
                .to_string()
                .starts_with("failed to create the temporary file")
        );
        Ok(())
    }
}
