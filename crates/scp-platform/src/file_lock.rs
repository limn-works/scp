//! Exclusive advisory file locks that unlock explicitly on every release path.
//!
//! `fs2` maps an exclusive lock onto `flock(2)` on Unix and `LockFileEx` on
//! Windows. A `flock` belongs to the open file description, not to the
//! descriptor: every descriptor that shares the description shares the lock,
//! and closing one descriptor releases nothing while another survives. A child
//! process forked while the lock is held gets a copy of the descriptor, which
//! `O_CLOEXEC` closes only when the child execs; a child spawned concurrently
//! holds it until its exec, and a child forked without exec holds it until it
//! exits. A `File::try_clone` makes the same copy. Closing the holder's `File`
//! then leaves the lock held until that copy closes, and a reopen of the
//! guarded path fails with contention.
//!
//! [`ExclusiveFileLock`] therefore calls unlock (`LOCK_UN`, which releases the
//! lock on the shared description) before it closes the `File`, both in
//! [`ExclusiveFileLock::release`] and in `Drop`. It is the one type in this
//! crate that takes an exclusive file lock (spec §17.6 "One Opener per Durable
//! Directory", §17.8 "One writer at a time").

use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};

/// An exclusive advisory lock on one open file, released by an explicit unlock
/// before the file closes.
///
/// Construct it with [`try_acquire`](Self::try_acquire). Release it with
/// [`release`](Self::release) when the caller must learn whether the unlock
/// succeeded; dropping the value also unlocks, and logs a failed unlock.
#[derive(Debug)]
pub struct ExclusiveFileLock {
    // `Some` until `release` moves the `File` out, so that `Drop` runs no
    // second unlock on a released lock.
    file: Option<File>,
    path: PathBuf,
}

impl ExclusiveFileLock {
    /// Takes an exclusive advisory lock on `file`, which is open at `path`,
    /// without waiting.
    ///
    /// `path` is kept only to name the lock in diagnostics.
    ///
    /// # Errors
    ///
    /// Returns the `File` and the OS error when the lock cannot be taken, so a
    /// caller that waits on contention can retry on the same open file. The
    /// error's OS code equals `fs2::lock_contended_error()`'s when another
    /// holder has the lock.
    pub fn try_acquire(file: File, path: &Path) -> Result<Self, (File, io::Error)> {
        match fs2::FileExt::try_lock_exclusive(&file) {
            Ok(()) => Ok(Self {
                file: Some(file),
                path: path.to_path_buf(),
            }),
            Err(e) => Err((file, e)),
        }
    }

    /// Unlocks the file, then closes it.
    ///
    /// # Errors
    ///
    /// Returns the OS error when the unlock fails. The file is closed either
    /// way; after a failed unlock, the lock stays held until every other
    /// descriptor sharing the open file description closes.
    pub fn release(mut self) -> io::Result<()> {
        // The taken `File` closes when this expression ends, after the unlock.
        self.file
            .take()
            .map_or(Ok(()), |file| fs2::FileExt::unlock(&file))
    }

    /// The locked file, for tests that copy its descriptor.
    #[cfg(test)]
    pub(crate) const fn file(&self) -> Option<&File> {
        self.file.as_ref()
    }
}

impl Drop for ExclusiveFileLock {
    fn drop(&mut self) {
        if let Some(file) = self.file.take()
            && let Err(e) = fs2::FileExt::unlock(&file)
        {
            tracing::warn!(
                path = %self.path.display(),
                error = %e,
                "could not unlock an exclusive file lock; it stays held until every \
                 descriptor sharing its open file description closes"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open(path: &Path) -> io::Result<File> {
        std::fs::OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(path)
    }

    fn contended(result: &Result<ExclusiveFileLock, (File, io::Error)>) -> bool {
        matches!(
            result,
            Err((_, e)) if e.raw_os_error() == fs2::lock_contended_error().raw_os_error()
        )
    }

    /// `release` unlocks the shared open file description, so a copy of the
    /// descriptor that outlives the lock (an inherited or cloned one) does not
    /// keep the path locked.
    #[test]
    fn release_unlocks_while_an_inherited_descriptor_survives() -> io::Result<()> {
        let dir = tempfile::TempDir::new()?;
        let path = dir.path().join("x.lock");
        let lock = ExclusiveFileLock::try_acquire(open(&path)?, &path).map_err(|(_, e)| e)?;
        let inherited = lock.file().map(File::try_clone).transpose()?;
        assert!(inherited.is_some());

        assert!(contended(&ExclusiveFileLock::try_acquire(
            open(&path)?,
            &path
        )));
        lock.release()?;
        let again = ExclusiveFileLock::try_acquire(open(&path)?, &path);
        assert!(again.is_ok(), "release must unlock, not only close");
        drop(inherited);
        Ok(())
    }

    /// Dropping the lock unlocks as `release` does.
    #[test]
    fn drop_unlocks_while_an_inherited_descriptor_survives() -> io::Result<()> {
        let dir = tempfile::TempDir::new()?;
        let path = dir.path().join("x.lock");
        let lock = ExclusiveFileLock::try_acquire(open(&path)?, &path).map_err(|(_, e)| e)?;
        let inherited = lock.file().map(File::try_clone).transpose()?;
        assert!(inherited.is_some());

        drop(lock);
        let again = ExclusiveFileLock::try_acquire(open(&path)?, &path);
        assert!(again.is_ok(), "drop must unlock, not only close");
        drop(inherited);
        Ok(())
    }
}
