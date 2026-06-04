//! `SQLite`-backed [`Storage`] implementation with `SQLCipher` encryption.
//!
//! The production default storage adapter per spec section 17.6. Uses
//! `rusqlite` with `bundled-sqlcipher` for at-rest encryption. WAL mode
//! enables concurrent readers with one writer. Schema is intentionally
//! minimal — all structure lives in the key convention, not the table
//! schema.
//!
//! Prefix queries use B-tree range scans (`key >= prefix AND key <
//! prefix_successor`), not `LIKE`, for O(log n) performance via the
//! clustered index.
//!
//! See spec section 17.6 and ADR-006.

#[cfg(feature = "software_platform")]
pub mod key_custody;

#[cfg(feature = "software_platform")]
pub use key_custody::SqliteKeyCustody;

use std::fs::{File, OpenOptions};
use std::path::Path;
use std::sync::Mutex;

use fs2::FileExt;
use rand::RngCore;
use rusqlite::Connection;

use zeroize::Zeroize;

use crate::error::PlatformError;
use crate::kdf;
use crate::traits::Storage;

/// File name of the `SQLCipher` database within the storage directory.
const DB_FILE_NAME: &str = "scp.db";

/// File name of the Argon2id salt sidecar within the storage directory.
///
/// The salt lives **outside** the encrypted database (`scp.db`) because it is
/// required to derive the key that decrypts the database — storing it inside
/// would be a bootstrap deadlock (spec §17.6 "Salt Persistence").
const SALT_FILE_NAME: &str = "scp.salt";

/// `SQLite`-backed storage adapter with `SQLCipher` encryption.
///
/// Uses a single `WITHOUT ROWID` table with a clustered index on the
/// primary key for optimal KV workloads. Encryption is provided by
/// `SQLCipher` with the following configuration:
///
/// - `cipher_page_size = 4096`
/// - `kdf_iter = 256000`
/// - `cipher_hmac_algorithm = HMAC_SHA512`
/// - `cipher_kdf_algorithm = PBKDF2_HMAC_SHA512`
///
/// See spec section 17.6.
pub struct SqliteStorage {
    // Uses `std::sync::Mutex` deliberately rather than `tokio::sync::Mutex`.
    // All rusqlite operations are sub-millisecond (single-row KV on WAL-mode
    // SQLite with no network I/O), so blocking the async runtime for that
    // duration is preferable to the overhead and complexity of
    // `spawn_blocking` per call. The mutex hold time is bounded by SQLite's
    // single-writer guarantee — only one thread can hold the lock at a time,
    // and each operation completes quickly.
    conn: Mutex<Connection>,
    // Advisory exclusive lock on `{dir}/scp.db.lock`. Held for the lifetime
    // of the `SqliteStorage` — refuses a second process, or a second
    // in-process instance, trying to open the same database directory
    // concurrently. This guards against split-brain writes and SQLite WAL
    // corruption that can occur when two `rusqlite` handles share the same
    // database file without coordinating access. See red-hat RED-1002.
    //
    // Held in `Mutex<Option<File>>` so [`close`](Self::close) can take the
    // `File` out and drop it explicitly — releasing the flock(2) /
    // LockFileEx lock even when outer `Arc<SqliteStorage>` references
    // persist past shutdown (FFI bridge instances hold the storage through
    // several Arc chains: `StorageProvider`, `CoreFields::persistence`,
    // `ContextManager::persistence`, event-log repository). Without an
    // explicit release path, the advisory lock outlived `SCP.shutdown()`
    // in the Python and NAPI bridges, causing "already open by another
    // SCP instance" errors on same-process reopen. Dropping the struct
    // still releases the lock automatically for non-shutdown paths.
    lock_file: Mutex<Option<File>>,
}

impl SqliteStorage {
    /// Opens or creates an encrypted `SQLite` database at `{dir}/scp.db`.
    ///
    /// An advisory exclusive file lock on `{dir}/scp.db.lock` is taken for
    /// the lifetime of the returned `SqliteStorage`. If the lock is already
    /// held by another process or another in-process instance, this
    /// constructor returns [`PlatformError::StorageError`] rather than
    /// opening a second `SQLite` handle against the same database — a
    /// configuration that can produce WAL corruption, split-brain writes,
    /// or silent data loss (red-hat RED-1002).
    ///
    /// The `key` parameter is the raw encryption key material. It is
    /// hex-encoded and passed to `SQLCipher` via `PRAGMA key`. The
    /// hex-encoded key string is zeroized after the PRAGMA is executed,
    /// but `SQLCipher` retains the derived key internally for the lifetime
    /// of the connection — this is inherent to how `SQLCipher` works and
    /// cannot be avoided without closing the connection.
    ///
    /// Callers that hold the raw key in a `Vec<u8>` or similar should
    /// zeroize it after passing it to this constructor.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformError::StorageError`] if the database cannot be
    /// opened, the encryption key is rejected, the schema cannot be
    /// created, or the advisory file lock is already held by another
    /// `SqliteStorage` instance (same process or other).
    pub fn new(dir: &Path, key: &[u8]) -> Result<Self, PlatformError> {
        std::fs::create_dir_all(dir)
            .map_err(|e| PlatformError::StorageError(format!("failed to create directory: {e}")))?;

        // Take the advisory exclusive lock BEFORE opening the database. We
        // use `try_lock_exclusive` (non-blocking) so a second caller gets an
        // actionable error immediately rather than silently blocking — the
        // caller is expected to use a single `SqliteStorage` per database
        // directory. The lock file is persistent (created with OpenOptions
        // so it survives across process restarts) but the lock itself is
        // advisory and released automatically when the File is dropped.
        let lock_path = dir.join("scp.db.lock");
        let lock_file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(&lock_path)
            .map_err(|e| {
                PlatformError::StorageError(format!(
                    "failed to open lock file at {}: {e}",
                    lock_path.display()
                ))
            })?;
        FileExt::try_lock_exclusive(&lock_file).map_err(|e| {
            PlatformError::StorageError(format!(
                "database at {} is already open by another SCP instance \
                 (advisory lock held on {}): {e} — close the existing \
                 SqliteStorage before opening a second handle",
                dir.display(),
                lock_path.display()
            ))
        })?;

        let db_path = dir.join("scp.db");
        let conn = Connection::open(&db_path)
            .map_err(|e| PlatformError::StorageError(format!("failed to open database: {e}")))?;

        // Apply SQLCipher pragmas (spec section 17.6).
        // The hex key format is `PRAGMA key = "x'<hex>'"` — a double-quoted
        // string containing `x'...'`. This tells SQLCipher to interpret the
        // value as raw hex key bytes rather than a passphrase.
        let mut hex_key = hex::encode(key);
        let mut pragma_sql = format!(
            "PRAGMA key = \"x'{hex_key}'\";\n\
             PRAGMA cipher_page_size = 4096;\n\
             PRAGMA kdf_iter = 256000;\n\
             PRAGMA cipher_hmac_algorithm = HMAC_SHA512;\n\
             PRAGMA cipher_kdf_algorithm = PBKDF2_HMAC_SHA512;"
        );
        // Zeroize the hex key immediately — it's now embedded in pragma_sql.
        hex_key.zeroize();
        let result = conn.execute_batch(&pragma_sql);
        // Zeroize the SQL string containing the key material.
        pragma_sql.zeroize();
        result.map_err(|e| {
            PlatformError::StorageError(format!("failed to set SQLCipher pragmas: {e}"))
        })?;

        // Enable WAL mode for concurrent readers.
        conn.pragma_update(None, "journal_mode", "WAL")
            .map_err(|e| PlatformError::StorageError(format!("failed to enable WAL mode: {e}")))?;

        // Create the KV table (spec section 17.6).
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS kv (\
                key TEXT PRIMARY KEY, \
                value BLOB NOT NULL\
            ) WITHOUT ROWID;",
        )
        .map_err(|e| PlatformError::StorageError(format!("failed to create schema: {e}")))?;

        Ok(Self {
            conn: Mutex::new(conn),
            lock_file: Mutex::new(Some(lock_file)),
        })
    }

    /// Opens or creates an encrypted `SQLite` database at `{dir}/scp.db`,
    /// deriving the `SQLCipher` key from a passphrase via Argon2id (spec §17.6
    /// "Passphrase Key-Derivation Mode").
    ///
    /// This is the passphrase mode: instead of supplying raw key material, the
    /// caller supplies a human-chosen passphrase. The `SQLCipher` PRAGMA key is
    /// derived as `argon2id(passphrase, salt)` using the single, canonical
    /// Argon2id parameterization in [`crate::kdf`]. The 16-byte salt is
    /// persisted to a sidecar file `{dir}/scp.salt` outside the encrypted
    /// database so the same passphrase deterministically re-derives the same
    /// key across process restarts.
    ///
    /// # Fail-Closed Semantics (spec §17.6 "Salt Persistence")
    ///
    /// - If `{dir}/scp.db` exists but `{dir}/scp.salt` does not, this returns
    ///   an error and does NOT regenerate the salt — a fresh salt would derive
    ///   a different key and permanently brick the existing database.
    /// - A salt file of the wrong length (not 16 bytes) is a terminal error.
    /// - A wrong passphrase is rejected by `SQLCipher` on the first query inside
    ///   [`SqliteStorage::new`]; that error is propagated. The system never
    ///   silently creates or opens a fresh, empty database.
    ///
    /// The passphrase bytes are borrowed and never copied here; the derived
    /// key is held in [`Zeroizing`](zeroize::Zeroizing) memory and dropped at
    /// the end of this function. `SQLCipher` retains its own derived key
    /// internally for the connection lifetime (same contract as
    /// [`SqliteStorage::new`]).
    ///
    /// # Errors
    ///
    /// Returns [`PlatformError::StorageError`] if the salt sidecar is missing
    /// beside an existing database, has the wrong length, cannot be read or
    /// written, or if the database cannot be opened (including a rejected
    /// passphrase). Returns [`PlatformError::CustodyError`] if Argon2id
    /// derivation itself fails.
    pub fn with_passphrase(dir: &Path, passphrase: &[u8]) -> Result<Self, PlatformError> {
        // Fail-closed ordering: never regenerate a salt beside an existing
        // database. A db with no salt is unrecoverable through this path, and
        // generating a fresh salt would derive a different key and brick it.
        let db_path = dir.join(DB_FILE_NAME);
        let salt_path = dir.join(SALT_FILE_NAME);
        if db_path.exists() && !salt_path.exists() {
            return Err(PlatformError::StorageError(format!(
                "database exists at {} but salt sidecar is missing at {} — \
                 refusing to regenerate salt (would derive a different key \
                 and permanently brick the database)",
                db_path.display(),
                salt_path.display()
            )));
        }

        let salt = load_or_init_salt(dir)?;
        let key = kdf::derive_argon2id_key(passphrase, &salt)?;

        // Delegate to the shared SQLCipher path. A wrong passphrase produces a
        // different derived key; SQLCipher rejects it on the first query inside
        // `new`, and that error propagates here (fail closed) — `new` never
        // silently creates a fresh DB on key rejection.
        Self::new(dir, key.as_ref())
        // `key` (Zeroizing) is dropped here; SQLCipher retains its own derived
        // key internally for the connection lifetime.
    }

    /// Explicitly releases the advisory exclusive lock on `{dir}/scp.db.lock`.
    ///
    /// Idempotent — a second call is a no-op. Safe to call while
    /// outstanding `Arc<SqliteStorage>` references are still alive;
    /// subsequent `Storage` operations continue to work through the
    /// cached `SQLCipher` connection but the lock is no longer held.
    ///
    /// The FFI bridges (`PyBridgeInstance`, `NapiBridgeInstance`,
    /// `UniffiBridgeInstance`) invoke this from their
    /// `bridge_specific_shutdown` so that `SCP.shutdown()` at the SDK
    /// surface releases the advisory lock even when the caller still
    /// holds the `scp` handle. Without this, the lock outlived
    /// `shutdown()` and a subsequent `new SCP({ storage: sqlite })`
    /// against the same directory failed with "already open by another
    /// SCP instance" (observed on Python / TS persistence tests).
    ///
    /// Poisoned mutex → best-effort: recover the guard via
    /// [`PoisonError::into_inner`] and still release the lock. A
    /// poisoned lock-file mutex would otherwise silently skip the
    /// release, leaving the advisory lock held until the
    /// `SqliteStorage` is finally dropped. Since the only other
    /// access point is `new()` (one-shot, via the constructor) and
    /// the mutex is only ever taken to move a `File` out on
    /// shutdown, there is no invariant that poisoning could
    /// violate — recovery is sound.
    pub fn close(&self) {
        let mut guard = match self.lock_file.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        // Taking drops the `File` when the local goes out of scope,
        // which releases the flock(2) / LockFileEx lock.
        let _ = guard.take();
    }
}

/// Loads the 16-byte Argon2id salt from `{dir}/scp.salt`, generating and
/// persisting a fresh one only when none exists (spec §17.6 "Salt
/// Persistence").
///
/// The directory is created if missing (mirrors [`SqliteStorage::new`]).
///
/// Invariants:
/// - No `{dir}/scp.salt`: generate 16 bytes from a CSPRNG, write atomically
///   (temp file + rename), and return them.
/// - `{dir}/scp.salt` exists with exactly 16 bytes: read and return.
/// - `{dir}/scp.salt` exists with the wrong length: fail closed.
/// - `{dir}/scp.salt` exists but is a symlink: fail closed (defense in depth —
///   the salt sidecar must be a regular file, never a redirect to an
///   attacker-chosen path).
///
/// # Brick prevention (spec §17.6 "Salt Persistence")
///
/// This function enforces the "db-present-but-salt-missing" fail-closed case at
/// the single salt-generation point: if `{dir}/scp.db` exists but
/// `{dir}/scp.salt` does not, it returns an error and does NOT regenerate the
/// salt (a fresh salt would derive a different key and permanently brick the
/// existing database). [`SqliteStorage::with_passphrase`] performs the same
/// check before calling this; whichever trips first returns the identical
/// error, so the guard is enforced even if this function is reached by another
/// path.
///
/// Reduced to `pub(crate)` so callers cannot bypass the brick-prevention guard
/// that lives at this generation point.
///
/// # Errors
///
/// Returns [`PlatformError::StorageError`] if the directory cannot be created,
/// a db exists without its salt sidecar, the salt file cannot be read or
/// written, is a symlink, or has the wrong length.
pub(crate) fn load_or_init_salt(dir: &Path) -> Result<[u8; kdf::ARGON2_SALT_LEN], PlatformError> {
    std::fs::create_dir_all(dir)
        .map_err(|e| PlatformError::StorageError(format!("failed to create directory: {e}")))?;

    let db_path = dir.join(DB_FILE_NAME);
    let salt_path = dir.join(SALT_FILE_NAME);

    // Brick prevention: never regenerate a salt beside an existing database.
    // Enforced here at the single salt-generation point so no caller can bypass
    // it. `with_passphrase` performs the same check first; the error is
    // identical, so reaching it here is harmless (no double-error — control
    // returns on the first match).
    if db_path.exists() && !salt_path.exists() {
        return Err(PlatformError::StorageError(format!(
            "database exists at {} but salt sidecar is missing at {} — \
             refusing to regenerate salt (would derive a different key \
             and permanently brick the database)",
            db_path.display(),
            salt_path.display()
        )));
    }

    if salt_path.exists() {
        // Defense in depth: reject a symlinked salt sidecar. `symlink_metadata`
        // does NOT follow the link, so a planted symlink is detected rather
        // than silently followed to an attacker-chosen target.
        let meta = std::fs::symlink_metadata(&salt_path).map_err(|e| {
            PlatformError::StorageError(format!(
                "failed to stat salt file at {}: {e}",
                salt_path.display()
            ))
        })?;
        if meta.file_type().is_symlink() {
            return Err(PlatformError::StorageError(format!(
                "salt file at {} is a symlink — refusing to follow (fail closed)",
                salt_path.display()
            )));
        }

        let bytes = std::fs::read(&salt_path).map_err(|e| {
            PlatformError::StorageError(format!(
                "failed to read salt file at {}: {e}",
                salt_path.display()
            ))
        })?;
        let salt: [u8; kdf::ARGON2_SALT_LEN] = bytes.as_slice().try_into().map_err(|_| {
            PlatformError::StorageError(format!(
                "salt file at {} has invalid length: expected {} bytes, got {}",
                salt_path.display(),
                kdf::ARGON2_SALT_LEN,
                bytes.len()
            ))
        })?;
        return Ok(salt);
    }

    // First initialization: no salt yet. Generate 16 bytes from a CSPRNG and
    // persist atomically.
    let mut salt = [0u8; kdf::ARGON2_SALT_LEN];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    atomic_write_salt(&salt_path, &salt)?;
    Ok(salt)
}

/// Writes `data` to `path` atomically via a randomized `.tmp` sibling file.
///
/// 1. Generates a randomized, unpredictable temp name
///    `scp.salt.{random_hex}.tmp` in the parent directory so concurrent
///    first-inits cannot collide and the name cannot be pre-planted.
/// 2. Opens the temp file with `create_new(true)` (`O_EXCL`): a pre-existing
///    file or symlink at the temp path fails the open rather than being
///    followed/overwritten. On `AlreadyExists` (astronomically unlikely with a
///    16-byte random suffix), it errors fail-closed.
/// 3. Writes `data` with `mode(0o600)` on Unix.
/// 4. Calls `sync_all` to flush the file to durable storage.
/// 5. Renames to `path` (atomic on POSIX).
/// 6. On Unix, fsyncs the PARENT DIRECTORY so the rename is durable — a crash
///    cannot leave the salt missing beside an already-fsynced `scp.db` (which
///    would be an unrecoverable fail-closed brick). Best-effort on platforms
///    without directory fsync.
/// 7. Cleans up the tmp file on any failure after creation.
///
/// Mirrors the crash-safe write pattern used by `FileKeyCustody`.
fn atomic_write_salt(path: &Path, data: &[u8]) -> Result<(), PlatformError> {
    use std::io::Write;

    let parent = path.parent().ok_or_else(|| {
        PlatformError::StorageError(format!(
            "salt path {} has no parent directory",
            path.display()
        ))
    })?;

    // Randomized, unpredictable temp name in the same directory as the target
    // so the final `rename` stays on one filesystem (atomic). 128 bits of
    // CSPRNG entropy rendered as 32 hex chars — collision-free in practice and
    // unguessable, so an attacker cannot pre-plant the temp path.
    let mut rand_bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut rand_bytes);
    let rand_suffix = u128::from_le_bytes(rand_bytes);
    let tmp_path = parent.join(format!("scp.salt.{rand_suffix:032x}.tmp"));

    #[cfg(unix)]
    let open_result = {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp_path)
    };
    #[cfg(not(unix))]
    let open_result = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp_path);

    let mut file = open_result.map_err(|e| {
        PlatformError::StorageError(format!(
            "failed to create temp salt file at {}: {e}",
            tmp_path.display()
        ))
    })?;
    file.write_all(data).map_err(|e| {
        let _ = std::fs::remove_file(&tmp_path);
        PlatformError::StorageError(format!("failed to write temp salt file: {e}"))
    })?;
    file.sync_all().map_err(|e| {
        let _ = std::fs::remove_file(&tmp_path);
        PlatformError::StorageError(format!("failed to sync temp salt file: {e}"))
    })?;
    drop(file);

    std::fs::rename(&tmp_path, path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp_path);
        PlatformError::StorageError(format!("failed to rename temp salt file: {e}"))
    })?;

    // Durably persist the directory entry created by the rename. Without this,
    // a crash after `rename` returns could lose the salt while `scp.db` (whose
    // own write fsynced) survives — an unrecoverable brick. Best-effort:
    // platforms without directory fsync return an error we tolerate.
    sync_parent_dir(parent);

    Ok(())
}

/// Best-effort fsync of a directory so a preceding `rename` into it is durable.
///
/// On Unix, opens the directory and calls `sync_all`. Errors are tolerated
/// (some filesystems/platforms do not support directory fsync); durability is a
/// hardening property, not a correctness precondition for the in-memory result.
/// No-op on non-Unix targets.
fn sync_parent_dir(dir: &Path) {
    #[cfg(unix)]
    {
        if let Ok(handle) = std::fs::File::open(dir) {
            let _ = handle.sync_all();
        }
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
    }
}

/// Computes the exclusive upper bound for a prefix range scan.
///
/// Given a prefix string, returns a string that is the lexicographic
/// successor — the smallest string that is greater than all strings
/// starting with the prefix. This enables efficient B-tree range scans
/// (`key >= prefix AND key < successor`) instead of `LIKE` queries.
///
/// Returns `None` if no successor exists (prefix is all `\xff` bytes or
/// empty), in which case only a `key >= prefix` bound should be used.
fn prefix_successor(prefix: &str) -> Option<String> {
    let mut bytes = prefix.as_bytes().to_vec();
    // Walk backwards, incrementing the last byte that isn't 0xFF.
    while let Some(last) = bytes.last_mut() {
        if *last < 0xFF {
            *last += 1;
            return String::from_utf8(bytes).ok();
        }
        bytes.pop();
    }
    None
}

/// Acquires the connection lock, mapping poison errors to
/// [`PlatformError::StorageError`].
fn lock_conn(
    conn: &Mutex<Connection>,
) -> Result<std::sync::MutexGuard<'_, Connection>, PlatformError> {
    conn.lock()
        .map_err(|e| PlatformError::StorageError(format!("mutex poisoned: {e}")))
}

/// Collects rows from a statement into a `Vec<String>`.
fn collect_keys(
    stmt: &mut rusqlite::CachedStatement<'_>,
    params: &[&dyn rusqlite::types::ToSql],
) -> Result<Vec<String>, PlatformError> {
    stmt.query_map(params, |row| row.get::<_, String>(0))
        .map_err(|e| PlatformError::StorageError(format!("list_keys failed: {e}")))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| PlatformError::StorageError(format!("list_keys row failed: {e}")))
}

#[allow(clippy::manual_async_fn)]
impl Storage for SqliteStorage {
    fn store(
        &self,
        key: &str,
        data: &[u8],
    ) -> impl Future<Output = Result<(), PlatformError>> + Send {
        let key = key.to_owned();
        let data = data.to_vec();
        async move {
            let conn = lock_conn(&self.conn)?;
            conn.execute(
                "INSERT OR REPLACE INTO kv (key, value) VALUES (?1, ?2)",
                rusqlite::params![key, data],
            )
            .map_err(|e| PlatformError::StorageError(format!("store failed: {e}")))?;
            drop(conn);
            Ok(())
        }
    }

    fn retrieve(
        &self,
        key: &str,
    ) -> impl Future<Output = Result<Option<Vec<u8>>, PlatformError>> + Send {
        let key = key.to_owned();
        async move {
            let conn = lock_conn(&self.conn)?;
            let mut stmt = conn
                .prepare_cached("SELECT value FROM kv WHERE key = ?1")
                .map_err(|e| PlatformError::StorageError(format!("prepare failed: {e}")))?;
            let result = stmt
                .query_row(rusqlite::params![key], |row| row.get::<_, Vec<u8>>(0))
                .optional()
                .map_err(|e| PlatformError::StorageError(format!("retrieve failed: {e}")))?;
            drop(stmt);
            drop(conn);
            Ok(result)
        }
    }

    fn delete(&self, key: &str) -> impl Future<Output = Result<(), PlatformError>> + Send {
        let key = key.to_owned();
        async move {
            let conn = lock_conn(&self.conn)?;
            conn.execute("DELETE FROM kv WHERE key = ?1", rusqlite::params![key])
                .map_err(|e| PlatformError::StorageError(format!("delete failed: {e}")))?;
            drop(conn);
            Ok(())
        }
    }

    fn list_keys(
        &self,
        prefix: &str,
    ) -> impl Future<Output = Result<Vec<String>, PlatformError>> + Send {
        let prefix = prefix.to_owned();
        async move {
            let conn = lock_conn(&self.conn)?;

            let keys = if prefix.is_empty() {
                let mut stmt = conn
                    .prepare_cached("SELECT key FROM kv ORDER BY key")
                    .map_err(|e| PlatformError::StorageError(format!("prepare failed: {e}")))?;
                collect_keys(&mut stmt, &[])
            } else {
                prefix_successor(&prefix).map_or_else(
                    || {
                        let mut stmt = conn
                            .prepare_cached("SELECT key FROM kv WHERE key >= ?1 ORDER BY key")
                            .map_err(|e| {
                                PlatformError::StorageError(format!("prepare failed: {e}"))
                            })?;
                        collect_keys(&mut stmt, &[&prefix as &dyn rusqlite::types::ToSql])
                    },
                    |successor| {
                        let mut stmt = conn
                            .prepare_cached(
                                "SELECT key FROM kv \
                                 WHERE key >= ?1 AND key < ?2 ORDER BY key",
                            )
                            .map_err(|e| {
                                PlatformError::StorageError(format!("prepare failed: {e}"))
                            })?;
                        collect_keys(
                            &mut stmt,
                            &[
                                &prefix as &dyn rusqlite::types::ToSql,
                                &successor as &dyn rusqlite::types::ToSql,
                            ],
                        )
                    },
                )
            }?;

            drop(conn);
            Ok(keys)
        }
    }

    fn delete_prefix(
        &self,
        prefix: &str,
    ) -> impl Future<Output = Result<u64, PlatformError>> + Send {
        let prefix = prefix.to_owned();
        async move {
            let conn = lock_conn(&self.conn)?;

            let deleted = prefix_successor(&prefix)
                .map_or_else(
                    || conn.execute("DELETE FROM kv WHERE key >= ?1", rusqlite::params![prefix]),
                    |successor| {
                        conn.execute(
                            "DELETE FROM kv WHERE key >= ?1 AND key < ?2",
                            rusqlite::params![prefix, successor],
                        )
                    },
                )
                .map_err(|e| PlatformError::StorageError(format!("delete_prefix failed: {e}")))?;

            drop(conn);
            Ok(deleted as u64)
        }
    }

    fn exists(&self, key: &str) -> impl Future<Output = Result<bool, PlatformError>> + Send {
        let key = key.to_owned();
        async move {
            let conn = lock_conn(&self.conn)?;
            let mut stmt = conn
                .prepare_cached("SELECT COUNT(*) FROM kv WHERE key = ?1")
                .map_err(|e| PlatformError::StorageError(format!("prepare failed: {e}")))?;
            let count: i64 = stmt
                .query_row(rusqlite::params![key], |row| row.get(0))
                .map_err(|e| PlatformError::StorageError(format!("exists failed: {e}")))?;
            drop(stmt);
            drop(conn);
            Ok(count > 0)
        }
    }
}

/// Extension trait for optional query results.
///
/// Mirrors `rusqlite::OptionalExtension` but works with the method
/// resolution rules needed for `prepare_cached` statements.
trait OptionalResult<T> {
    fn optional(self) -> Result<Option<T>, rusqlite::Error>;
}

impl<T> OptionalResult<T> for Result<T, rusqlite::Error> {
    fn optional(self) -> Result<Option<T>, rusqlite::Error> {
        match self {
            Ok(v) => Ok(Some(v)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn prefix_successor_normal() {
        assert_eq!(prefix_successor("ctx/"), Some("ctx0".to_owned()));
    }

    #[test]
    fn prefix_successor_empty() {
        assert_eq!(prefix_successor(""), None);
    }

    #[test]
    fn prefix_successor_single_char() {
        assert_eq!(prefix_successor("a"), Some("b".to_owned()));
    }

    #[test]
    fn load_or_init_salt_generates_and_persists_16_bytes() {
        let dir = TempDir::new().unwrap();
        let salt_path = dir.path().join(SALT_FILE_NAME);
        assert!(!salt_path.exists(), "salt must not exist before first call");

        let salt = load_or_init_salt(dir.path()).unwrap();
        assert_eq!(salt.len(), kdf::ARGON2_SALT_LEN);
        assert!(salt_path.exists(), "first call must write the salt sidecar");

        let on_disk = std::fs::read(&salt_path).unwrap();
        assert_eq!(on_disk.len(), kdf::ARGON2_SALT_LEN);
        assert_eq!(on_disk.as_slice(), &salt, "persisted bytes must match");
    }

    #[test]
    fn load_or_init_salt_is_stable_across_calls() {
        let dir = TempDir::new().unwrap();
        let first = load_or_init_salt(dir.path()).unwrap();
        let second = load_or_init_salt(dir.path()).unwrap();
        assert_eq!(
            first, second,
            "second call must read back the same salt, not regenerate"
        );
    }

    #[test]
    fn load_or_init_salt_rejects_wrong_length() {
        let dir = TempDir::new().unwrap();
        let salt_path = dir.path().join(SALT_FILE_NAME);
        // Write a salt of the wrong length (15 bytes).
        std::fs::write(&salt_path, [0u8; kdf::ARGON2_SALT_LEN - 1]).unwrap();

        let result = load_or_init_salt(dir.path());
        assert!(result.is_err(), "wrong-length salt must fail closed");
        match result.unwrap_err() {
            PlatformError::StorageError(msg) => {
                assert!(
                    msg.contains("invalid length"),
                    "error must mention invalid length: {msg}"
                );
            }
            other => panic!("expected StorageError, got {other:?}"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn load_or_init_salt_rejects_symlinked_salt() {
        use std::os::unix::fs::symlink;

        let dir = TempDir::new().unwrap();
        // Plant a real 16-byte target elsewhere, then symlink scp.salt to it.
        let target = dir.path().join("real_salt_target");
        std::fs::write(&target, [7u8; kdf::ARGON2_SALT_LEN]).unwrap();
        let salt_path = dir.path().join(SALT_FILE_NAME);
        symlink(&target, &salt_path).unwrap();

        let result = load_or_init_salt(dir.path());
        assert!(result.is_err(), "symlinked salt must fail closed");
        match result.unwrap_err() {
            PlatformError::StorageError(msg) => {
                assert!(msg.contains("symlink"), "error must mention symlink: {msg}");
            }
            other => panic!("expected StorageError, got {other:?}"),
        }
    }

    #[test]
    fn load_or_init_salt_db_present_salt_missing_fails_closed() {
        let dir = TempDir::new().unwrap();
        // Simulate an existing database with no salt sidecar.
        std::fs::write(dir.path().join(DB_FILE_NAME), b"not-a-real-db").unwrap();

        let result = load_or_init_salt(dir.path());
        assert!(
            result.is_err(),
            "db present + salt missing must fail closed at the generation point"
        );
        // The guard must NOT have regenerated a salt.
        assert!(
            !dir.path().join(SALT_FILE_NAME).exists(),
            "salt must not be regenerated beside an existing db"
        );
    }

    #[test]
    fn atomic_write_salt_uses_randomized_temp_and_no_residue() {
        let dir = TempDir::new().unwrap();
        let salt_path = dir.path().join(SALT_FILE_NAME);

        // A fixed-name temp file pre-planted at the OLD predictable path
        // (`scp.salt.tmp`) must NOT interfere — the temp name is now randomized.
        std::fs::write(dir.path().join("scp.salt.tmp"), b"stale").unwrap();

        let salt = [3u8; kdf::ARGON2_SALT_LEN];
        atomic_write_salt(&salt_path, &salt).unwrap();

        // The salt landed correctly.
        let on_disk = std::fs::read(&salt_path).unwrap();
        assert_eq!(on_disk.as_slice(), &salt);

        // No `*.tmp` residue from our randomized write remains in the dir
        // (the stale pre-planted one is ignored, but ours is cleaned/renamed).
        let tmp_residue: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.starts_with("scp.salt.") && n.contains(".tmp"))
            .collect();
        // Only the stale pre-planted fixed-name temp remains; no randomized
        // residue from atomic_write_salt.
        assert_eq!(
            tmp_residue,
            vec!["scp.salt.tmp".to_owned()],
            "randomized temp must be renamed away, leaving no residue"
        );
    }

    #[tokio::test]
    async fn with_passphrase_round_trips_across_reopen() {
        let dir = TempDir::new().unwrap();
        let passphrase = b"correct horse battery staple";

        // First open: creates db + salt, writes a value.
        let storage = SqliteStorage::with_passphrase(dir.path(), passphrase).unwrap();
        storage.store("k", b"v").await.unwrap();
        drop(storage);

        // Reopen with the SAME passphrase + same dir: salt is read back, the
        // key is deterministically re-derived, and the value is readable. This
        // proves the derived key is stable across a simulated restart.
        let reopened = SqliteStorage::with_passphrase(dir.path(), passphrase).unwrap();
        let value = reopened.retrieve("k").await.unwrap();
        assert_eq!(
            value.as_deref(),
            Some(&b"v"[..]),
            "same passphrase must re-read the stored value"
        );
    }

    #[tokio::test]
    async fn with_passphrase_wrong_passphrase_fails_closed() {
        let dir = TempDir::new().unwrap();

        // Create with one passphrase and write a value.
        let storage = SqliteStorage::with_passphrase(dir.path(), b"right-passphrase").unwrap();
        storage.store("k", b"secret").await.unwrap();
        drop(storage);

        // Reopen with a WRONG passphrase. SQLCipher rejects the derived key on
        // the first query during `new` — this must surface as an error, NOT a
        // silent fresh/empty database and NOT the old value.
        let result = SqliteStorage::with_passphrase(dir.path(), b"wrong-passphrase");
        assert!(
            result.is_err(),
            "wrong passphrase must fail closed (no silent fresh DB)"
        );
    }

    #[tokio::test]
    async fn with_passphrase_db_present_salt_missing_fails_closed() {
        let dir = TempDir::new().unwrap();
        let passphrase = b"some-passphrase";

        // Create a db + salt, then delete the salt to simulate a lost sidecar.
        let storage = SqliteStorage::with_passphrase(dir.path(), passphrase).unwrap();
        storage.store("k", b"v").await.unwrap();
        drop(storage);

        let salt_path = dir.path().join(SALT_FILE_NAME);
        std::fs::remove_file(&salt_path).unwrap();
        assert!(
            dir.path().join(DB_FILE_NAME).exists(),
            "db must still exist"
        );

        // db present + salt missing → fail closed. The system MUST NOT
        // regenerate the salt (that would derive a different key and brick the
        // existing database).
        let result = SqliteStorage::with_passphrase(dir.path(), passphrase);
        assert!(
            result.is_err(),
            "missing salt beside existing db must fail closed"
        );
        // The salt sidecar must NOT have been regenerated.
        assert!(
            !salt_path.exists(),
            "salt must not be regenerated beside an existing db"
        );
    }

    /// Red-hat RED-1002: opening a second `SqliteStorage` against the same
    /// database directory while the first is still live must fail fast,
    /// not silently corrupt the `SQLite` WAL by producing two concurrent
    /// `rusqlite` handles on the same file.
    #[test]
    #[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    fn second_open_on_same_dir_fails_while_first_is_live() {
        let tmp = tempfile::TempDir::new().unwrap();
        let key = [0u8; 32];

        let first = SqliteStorage::new(tmp.path(), &key).expect("first open must succeed");

        // Second open while `first` is alive must fail.
        let second = SqliteStorage::new(tmp.path(), &key);
        assert!(
            second.is_err(),
            "second open on the same database directory must fail while the \
             first instance holds the advisory lock"
        );
        match second {
            Err(PlatformError::StorageError(msg)) => {
                assert!(
                    msg.contains("already open"),
                    "error message must mention lock contention: got {msg}"
                );
            }
            Err(other) => panic!("expected StorageError, got {other:?}"),
            Ok(_) => unreachable!("second open must fail — already handled above"),
        }

        // Dropping `first` releases the lock; a fresh open must succeed.
        drop(first);
        SqliteStorage::new(tmp.path(), &key)
            .expect("fresh open after drop of prior instance must succeed");
    }

    /// `close()` must release the advisory lock even while the
    /// `SqliteStorage` value is still alive. The FFI bridges rely on
    /// this to make `SCP.shutdown()` release the `scp.db.lock` flock
    /// without requiring the SDK caller to drop the `SCP` handle: a
    /// `BridgeInstance` holds the storage through multiple Arc chains
    /// (`StorageProvider`, `CoreFields::persistence`, `ContextManager`,
    /// event-log repository), so drop-on-shutdown is not available and
    /// the lock must be released by explicit call.
    #[test]
    #[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    fn close_releases_advisory_lock_while_instance_alive() {
        let tmp = tempfile::TempDir::new().unwrap();
        let key = [0u8; 32];

        let first = SqliteStorage::new(tmp.path(), &key).expect("first open must succeed");

        // Explicit close releases the lock even though `first` is still alive.
        first.close();

        // Re-open while `first` is in scope must now succeed — this is the
        // behavior `SCP.shutdown()` relies on in the Python and NAPI
        // bridges.
        let second =
            SqliteStorage::new(tmp.path(), &key).expect("re-open after close must succeed");

        // `close()` is idempotent — a second call is a no-op.
        first.close();

        drop(second);
        drop(first);
    }
}
