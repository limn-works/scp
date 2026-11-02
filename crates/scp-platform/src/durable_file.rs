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
//! processes generating the same secret at once agree on one. `create`
//! publishes with an exclusive rename (`renameat2(RENAME_NOREPLACE)` on Linux
//! and Android, `renameatx_np(RENAME_EXCL)` on Apple platforms) and falls back
//! to a hard link, which also refuses an existing name. A file system that
//! supports neither gets [`DurableWriteErrorKind::ExclusivePublishUnsupported`]
//! and no file: `create` never falls back to a write that could overwrite.
//!
//! # No temporary copy outlives its write
//!
//! A temporary file holds a complete copy of the secret. Its writer holds an
//! exclusive advisory lock on it from just after creating it until it is
//! renamed or removed, and an operating system releases that lock when the
//! writer dies. [`remove_stale_temporaries`] removes every temporary of one
//! final name whose lock it can take, so it removes what a crashed writer left
//! and never the temporary of a writer that is still running. `create` and
//! `replace` call it before they write, and every reader of a secret this
//! module wrote calls it before it reads, so a crash leaves a copy only until
//! the next open of that secret.
//!
//! Every secret-file writer in this workspace calls this module, so the
//! guarantee lives in one place.

use std::fs::{File, TryLockError};
use std::io::Write as _;
use std::path::{Path, PathBuf};

use rand::RngCore as _;

use crate::file_lock::ExclusiveFileLock;

/// Why a durable write failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DurableWriteErrorKind {
    /// A file-system call failed; the error's `source` says how.
    Io,
    /// The file system supports neither an exclusive rename nor a hard link,
    /// so [`create`] had no way to publish without risking an overwrite of a
    /// file another writer published, and wrote nothing under the final name.
    ExclusivePublishUnsupported,
}

/// Which step of a durable write failed, the path it acted on, and what the
/// file system reported.
#[derive(Debug)]
pub struct DurableWriteError {
    /// Why the write failed.
    pub kind: DurableWriteErrorKind,
    /// The step that failed, phrased to follow "failed to".
    pub step: &'static str,
    /// The path that step acted on.
    pub path: PathBuf,
    /// What the file system reported.
    pub source: std::io::Error,
}

impl DurableWriteError {
    fn io(step: &'static str, path: &Path, source: std::io::Error) -> Self {
        Self {
            kind: DurableWriteErrorKind::Io,
            step,
            path: path.to_path_buf(),
            source,
        }
    }
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
    remove_stale_temporaries(path)?;
    let (parent, temp) = write_temp(path, data)?;
    std::fs::rename(&temp.path, path).map_err(|source| {
        let _ = std::fs::remove_file(&temp.path);
        DurableWriteError::io("rename a temporary file onto", path, source)
    })?;
    drop(temp);
    sync_dir(parent);
    Ok(())
}

/// Writes `data` to `path` atomically and durably when no file holds `path`
/// yet, and otherwise leaves that file alone.
///
/// The complete, synced temporary file is published by an exclusive rename,
/// or by a hard link where the file system has no exclusive rename. Both fail
/// when `path` exists, so a concurrent creator that published first wins and
/// this call reports [`Created::AlreadyPresent`].
///
/// # Errors
///
/// Returns [`DurableWriteError`] naming the step that failed, with kind
/// [`DurableWriteErrorKind::ExclusivePublishUnsupported`] on a file system
/// that supports neither publish. A failure removes the temporary file and
/// leaves `path` as it was.
pub fn create(path: &Path, data: &[u8]) -> Result<Created, DurableWriteError> {
    create_with(path, data, PUBLISHERS)
}

/// [`create`] with the publish calls passed in, so a test can stand for a
/// file system that lacks one of them.
fn create_with(
    path: &Path,
    data: &[u8],
    publishers: &[Publisher],
) -> Result<Created, DurableWriteError> {
    remove_stale_temporaries(path)?;
    let (parent, temp) = write_temp(path, data)?;
    let published = publish_new(&temp.path, path, publishers);
    // An exclusive rename consumed the temporary name, and a link, a refusal
    // or a failure left it, so this removal finds it in every case but the
    // first.
    let _ = std::fs::remove_file(&temp.path);
    drop(temp);
    let created = published?;
    // Persists the new name and the removed temporary name together.
    sync_dir(parent);
    Ok(created)
}

/// One way to give a temporary file a final name that fails with
/// `AlreadyExists` when that name is taken.
type Publisher = fn(&Path, &Path) -> std::io::Result<()>;

/// Every exclusive publish this platform offers, in the order [`create`]
/// tries them. The hard link is last, the fallback for a file system without
/// an exclusive rename.
#[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
const PUBLISHERS: &[Publisher] = &[rename_exclusive, link];
#[cfg(not(any(target_os = "linux", target_os = "android", target_vendor = "apple")))]
const PUBLISHERS: &[Publisher] = &[link];

/// Renames `from` to `to` unless `to` exists.
#[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
fn rename_exclusive(from: &Path, to: &Path) -> std::io::Result<()> {
    rustix::fs::renameat_with(
        rustix::fs::CWD,
        from,
        rustix::fs::CWD,
        to,
        rustix::fs::RenameFlags::NOREPLACE,
    )
    .map_err(std::io::Error::from)
}

/// Hard-links `from` to `to`, which fails when `to` exists.
fn link(from: &Path, to: &Path) -> std::io::Result<()> {
    std::fs::hard_link(from, to)
}

/// Whether a publish failed because the file system lacks that call rather
/// than because of this write: `EINVAL` from a `renameat2` flag the file
/// system does not implement, `ENOTSUP` or `ENOSYS`, and `EPERM` from a hard
/// link on a file system without links (FAT, exFAT, some network mounts).
fn unsupported(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::Unsupported
            | std::io::ErrorKind::InvalidInput
            | std::io::ErrorKind::PermissionDenied
    )
}

/// Gives `tmp` the name `path` through the first of `publishers` the file
/// system supports, never overwriting a file at `path`.
fn publish_new(
    tmp: &Path,
    path: &Path,
    publishers: &[Publisher],
) -> Result<Created, DurableWriteError> {
    let mut last_unsupported = None;
    for publish in publishers {
        match publish(tmp, path) {
            Ok(()) => return Ok(Created::Written),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                return Ok(Created::AlreadyPresent);
            }
            Err(e) if unsupported(&e) => last_unsupported = Some(e),
            Err(source) => {
                return Err(DurableWriteError::io(
                    "publish a temporary file without overwriting",
                    path,
                    source,
                ));
            }
        }
    }
    Err(DurableWriteError {
        kind: DurableWriteErrorKind::ExclusivePublishUnsupported,
        step: "publish without overwriting, because this file system supports neither an \
               exclusive rename nor a hard link,",
        path: path.to_path_buf(),
        source: last_unsupported.unwrap_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "no exclusive publish is available on this platform",
            )
        }),
    })
}

/// A temporary file, locked against [`remove_stale_temporaries`] until this
/// value drops.
struct Temp {
    path: PathBuf,
    _lock: ExclusiveFileLock,
}

/// How many times [`write_temp`] draws a new temporary name after a
/// concurrent [`remove_stale_temporaries`] removed the one it had just
/// created and not yet locked. Each sweep removes such a file at most once,
/// so a retry loses only to another sweep starting inside the same few
/// microseconds.
const TEMP_ATTEMPTS: usize = 8;

/// Writes `data` to a new, randomly named sibling of `path` with mode `0o600`,
/// locks it, and syncs it. Returns the parent directory and the locked
/// temporary file.
///
/// The name carries 128 bits from the OS random source, so no concurrent
/// writer collides with it and nobody can plant a file or symlink there in
/// advance; `O_EXCL` refuses one anyway.
fn write_temp<'a>(path: &'a Path, data: &[u8]) -> Result<(&'a Path, Temp), DurableWriteError> {
    let (parent, file_name) = split(path);
    for _ in 0..TEMP_ATTEMPTS {
        let mut suffix = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut suffix);
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
        let mut file = options
            .open(&tmp)
            .map_err(|source| DurableWriteError::io("create the temporary file", &tmp, source))?;
        let lock_handle = file
            .try_clone()
            .map_err(|source| DurableWriteError::io("lock the temporary file", &tmp, source))?;
        let lock = match ExclusiveFileLock::try_acquire(lock_handle, &tmp) {
            Ok(lock) => lock,
            // A sweep holds this file's lock, so it is removing it.
            Err((_, TryLockError::WouldBlock)) => continue,
            Err((_, TryLockError::Error(source))) => {
                drop(file);
                let _ = std::fs::remove_file(&tmp);
                return Err(DurableWriteError::io(
                    "lock the temporary file",
                    &tmp,
                    source,
                ));
            }
        };
        // A sweep that took and released the lock between the create and the
        // lock above removed this name; the locked file is then unnamed.
        if !still_named(&file, &tmp) {
            continue;
        }
        let written = file
            .write_all(data)
            .map_err(|source| ("write the temporary file", source))
            .and_then(|()| {
                file.sync_all()
                    .map_err(|source| ("sync the temporary file", source))
            });
        drop(file);
        if let Err((step, source)) = written {
            let _ = std::fs::remove_file(&tmp);
            return Err(DurableWriteError::io(step, &tmp, source));
        }
        return Ok((
            parent,
            Temp {
                path: tmp,
                _lock: lock,
            },
        ));
    }
    Err(DurableWriteError::io(
        "create a temporary file that no concurrent sweep removed, beside",
        path,
        std::io::Error::new(
            std::io::ErrorKind::Interrupted,
            format!("{TEMP_ATTEMPTS} temporary files were removed before they were locked"),
        ),
    ))
}

/// Whether `tmp` still names the open `file`.
#[cfg(unix)]
fn still_named(file: &File, tmp: &Path) -> bool {
    use std::os::unix::fs::MetadataExt as _;
    match (file.metadata(), std::fs::symlink_metadata(tmp)) {
        (Ok(open), Ok(named)) => open.dev() == named.dev() && open.ino() == named.ino(),
        _ => false,
    }
}

/// Whether `tmp` still names the open `file`. Windows refuses to remove a
/// file while a handle to it is open, so the name a writer just created
/// stays its own.
#[cfg(not(unix))]
fn still_named(_file: &File, tmp: &Path) -> bool {
    tmp.exists()
}

/// Removes every temporary file a crashed write of `path` left beside it.
///
/// A temporary of `path` is a sibling named `{file name}.{32 hex digits}.tmp`.
/// One whose lock this call takes has no running writer, so this call removes
/// it; one whose lock another holder keeps belongs to a write in progress and
/// stays. A name that is not a regular file (a symlink someone planted) is
/// removed without being opened. A directory that does not exist holds no
/// temporaries.
///
/// [`create`] and [`replace`] call this first. A caller that reads a secret
/// written through this module calls it before that read, because a crash
/// after a temporary was published but before it was removed leaves a copy
/// that no later write of an existing secret would reach.
///
/// # Errors
///
/// Returns [`DurableWriteError`] when the directory cannot be listed, or when
/// a stale temporary cannot be opened, locked or removed, because a secret
/// copy would then outlive its write.
pub fn remove_stale_temporaries(path: &Path) -> Result<(), DurableWriteError> {
    let (parent, file_name) = split(path);
    let entries = match std::fs::read_dir(parent) {
        Ok(entries) => entries,
        // A parent that is missing or is not a directory holds no temporaries;
        // the write that follows reports its own error for that path.
        Err(e)
            if matches!(
                e.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
            ) =>
        {
            return Ok(());
        }
        Err(source) => {
            return Err(DurableWriteError::io(
                "list temporary files in",
                parent,
                source,
            ));
        }
    };
    let mut removed = false;
    for entry in entries {
        let entry = entry
            .map_err(|source| DurableWriteError::io("list temporary files in", parent, source))?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if is_temporary_of(name, &file_name) {
            removed |= remove_if_stale(&parent.join(name))?;
        }
    }
    if removed {
        sync_dir(parent);
    }
    Ok(())
}

/// Removes `candidate` unless a running writer holds its lock. Returns
/// whether it removed a name.
fn remove_if_stale(candidate: &Path) -> Result<bool, DurableWriteError> {
    let remove = |path: &Path| match std::fs::remove_file(path) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(source) => Err(DurableWriteError::io(
            "remove a stale temporary file",
            path,
            source,
        )),
    };
    let metadata = match std::fs::symlink_metadata(candidate) {
        Ok(metadata) => metadata,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(source) => {
            return Err(DurableWriteError::io(
                "inspect a temporary file",
                candidate,
                source,
            ));
        }
    };
    if metadata.is_dir() {
        return Ok(false);
    }
    if !metadata.is_file() {
        return remove(candidate);
    }
    let file = match File::open(candidate) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(source) => {
            return Err(DurableWriteError::io(
                "open a stale temporary file",
                candidate,
                source,
            ));
        }
    };
    let lock = match ExclusiveFileLock::try_acquire(file, candidate) {
        Ok(lock) => lock,
        Err((_, TryLockError::WouldBlock)) => return Ok(false),
        Err((_, TryLockError::Error(source))) => {
            return Err(DurableWriteError::io(
                "lock a temporary file",
                candidate,
                source,
            ));
        }
    };
    let removed = remove(candidate);
    drop(lock);
    removed
}

/// Whether `name` is `{file_name}.{32 lowercase hex digits}.tmp`, the name
/// [`write_temp`] gives a temporary of `file_name`.
fn is_temporary_of(name: &str, file_name: &str) -> bool {
    name.strip_prefix(file_name)
        .and_then(|rest| rest.strip_prefix('.'))
        .and_then(|rest| rest.strip_suffix(".tmp"))
        .is_some_and(|hex| {
            hex.len() == 32 && hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
        })
}

/// The directory that holds `path` and `path`'s file name.
fn split(path: &Path) -> (&Path, String) {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let file_name = path.file_name().map_or_else(
        || "secret".to_owned(),
        |name| name.to_string_lossy().into_owned(),
    );
    (parent, file_name)
}

/// Syncs `dir` so a rename or link into it survives a crash. Best effort: a
/// platform or file system without directory sync reports an error, and the
/// write that preceded it has already been synced.
fn sync_dir(dir: &Path) {
    #[cfg(unix)]
    if let Ok(handle) = File::open(dir) {
        let _ = handle.sync_all();
    }
    #[cfg(not(unix))]
    let _ = dir;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Lists every name in `dir`, sorted.
    fn names(dir: &Path) -> Result<Vec<String>, std::io::Error> {
        let mut names = std::fs::read_dir(dir)?
            .map(|entry| Ok(entry?.file_name().to_string_lossy().into_owned()))
            .collect::<Result<Vec<_>, std::io::Error>>()?;
        names.sort();
        Ok(names)
    }

    /// A temporary of `final_name` in `dir`, holding `data`, as a crashed
    /// write leaves it.
    fn stale_temporary(
        dir: &Path,
        final_name: &str,
        data: &[u8],
    ) -> Result<PathBuf, std::io::Error> {
        let tmp = dir.join(format!("{final_name}.{:032x}.tmp", 0x5eed_u128));
        std::fs::write(&tmp, data)?;
        Ok(tmp)
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

    /// Each publish this platform offers refuses an existing final name on
    /// its own, so whichever one `create` reaches never overwrites a secret.
    #[test]
    fn every_publish_refuses_an_existing_file() -> Result<(), Box<dyn std::error::Error>> {
        for publish in PUBLISHERS {
            let dir = tempfile::tempdir()?;
            let path = dir.path().join(".key");
            std::fs::write(&path, [1; 32])?;
            assert_eq!(
                create_with(&path, &[2; 32], &[*publish])?,
                Created::AlreadyPresent
            );
            assert_eq!(std::fs::read(&path)?, vec![1; 32]);
            assert_eq!(names(dir.path())?, vec![".key".to_owned()]);
        }
        Ok(())
    }

    /// A publish that reports the file system lacks it.
    fn refused(_: &Path, _: &Path) -> std::io::Result<()> {
        Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied))
    }

    /// On a file system with no hard links, `create` still publishes: every
    /// publish this platform offers ahead of the hard link (`PUBLISHERS` keeps
    /// the link last) runs, and the link refuses. Publishing through
    /// `hard_link` alone fails here.
    #[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
    #[test]
    fn create_publishes_without_hard_links() -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join(".key");
        let (_link, ahead_of_the_link) = PUBLISHERS
            .split_last()
            .ok_or("this platform offers no publish")?;
        let mut no_links = ahead_of_the_link.to_vec();
        no_links.push(refused);
        let no_links = no_links.as_slice();
        assert_eq!(create_with(&path, &[3; 32], no_links)?, Created::Written);
        assert_eq!(std::fs::read(&path)?, vec![3; 32]);
        assert_eq!(
            create_with(&path, &[4; 32], no_links)?,
            Created::AlreadyPresent
        );
        assert_eq!(std::fs::read(&path)?, vec![3; 32]);
        assert_eq!(names(dir.path())?, vec![".key".to_owned()]);
        Ok(())
    }

    /// A file system that supports no exclusive publish gets a typed error
    /// and no write: an existing secret keeps its bytes, an absent one stays
    /// absent, and no temporary copy remains.
    #[test]
    fn create_fails_closed_when_no_exclusive_publish_exists()
    -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join(".key");
        let Err(error) = create_with(&path, &[5; 32], &[refused, refused]) else {
            return Err("a create with no exclusive publish must fail".into());
        };
        assert_eq!(
            error.kind,
            DurableWriteErrorKind::ExclusivePublishUnsupported
        );
        assert!(names(dir.path())?.is_empty());

        std::fs::write(&path, [6; 32])?;
        let Err(error) = create_with(&path, &[5; 32], &[refused]) else {
            return Err("a create with no exclusive publish must fail".into());
        };
        assert_eq!(
            error.kind,
            DurableWriteErrorKind::ExclusivePublishUnsupported
        );
        assert_eq!(std::fs::read(&path)?, vec![6; 32]);
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

    /// The next `create` or `replace` of a final name removes the secret copy
    /// a crashed write of that name left, and leaves every other name alone.
    #[test]
    fn the_next_write_removes_a_crashed_writes_temporary() -> Result<(), Box<dyn std::error::Error>>
    {
        let dir = tempfile::tempdir()?;
        let key = dir.path().join(".key");
        let unrelated = [
            ".key.lock",
            ".keyx.0000000000000000000000000000000a.tmp",
            ".key.tmp",
        ];
        for name in unrelated {
            std::fs::write(dir.path().join(name), b"keep")?;
        }

        let stale = stale_temporary(dir.path(), ".key", &[9; 32])?;
        assert_eq!(create(&key, &[1; 32])?, Created::Written);
        assert!(!stale.exists(), "create must remove the stale copy");

        let stale = stale_temporary(dir.path(), ".key", &[9; 32])?;
        replace(&key, &[2; 32])?;
        assert!(!stale.exists(), "replace must remove the stale copy");

        let mut expected = vec![".key".to_owned()];
        expected.extend(unrelated.iter().map(|name| (*name).to_owned()));
        expected.sort();
        assert_eq!(names(dir.path())?, expected);
        Ok(())
    }

    /// A reader's sweep removes a stale copy of a secret that exists, which
    /// no later `create` would reach.
    #[test]
    fn a_sweep_removes_a_copy_left_after_the_publish() -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let key = dir.path().join(".key");
        std::fs::write(&key, [1; 32])?;
        let stale = stale_temporary(dir.path(), ".key", &[1; 32])?;
        remove_stale_temporaries(&key)?;
        assert!(!stale.exists());
        assert_eq!(names(dir.path())?, vec![".key".to_owned()]);
        Ok(())
    }

    /// A temporary whose writer still holds its lock is a write in progress,
    /// so a sweep leaves it.
    #[test]
    fn a_sweep_leaves_a_running_writes_temporary() -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let key = dir.path().join(".key");
        let live = stale_temporary(dir.path(), ".key", &[1; 32])?;
        let held = ExclusiveFileLock::try_acquire(File::open(&live)?, &live)
            .map_err(|(_, e)| format!("lock: {e}"))?;
        remove_stale_temporaries(&key)?;
        assert!(
            live.exists(),
            "a locked temporary belongs to a running write"
        );
        drop(held);
        remove_stale_temporaries(&key)?;
        assert!(!live.exists());
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
        assert_eq!(error.kind, DurableWriteErrorKind::Io);
        assert!(
            error
                .to_string()
                .starts_with("failed to create the temporary file")
        );
        Ok(())
    }
}
