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
    //
    // `None` once [`close`](Self::close) has run: the connection is gone and
    // every operation returns [`PlatformError::StorageClosed`] (spec §17.6
    // "One Writer per Durable Directory": a closed store refuses operations
    // and never reopens its database implicitly). Field order matters for
    // `Drop` as well: the connection drops before the lock file, so the lock
    // is never released while the connection is open.
    conn: Mutex<Option<Connection>>,
    // Advisory exclusive lock on `{dir}/scp.db.lock`. Held for the lifetime
    // of the `SqliteStorage` — refuses a second process, or a second
    // in-process instance, trying to open the same database directory
    // concurrently. This guards against split-brain writes and SQLite WAL
    // corruption that can occur when two `rusqlite` handles share the same
    // database file without coordinating access. See red-hat RED-1002.
    //
    // Held in `Mutex<Option<File>>` so [`close`](Self::close) can take the
    // `File` out and drop it explicitly, after the connection, while outer
    // `Arc<SqliteStorage>` references persist (FFI bridge instances hold the
    // storage through several `Arc` chains: `StorageProvider`,
    // `CoreFields::persistence`, the Supervisor's persistence, the event-log
    // repository). The owner calls `close` only after every writer has
    // exited (spec §17.6, ADR-048 §5 amendment); dropping the struct also
    // releases both, connection first.
    lock_file: Mutex<Option<File>>,
}

impl SqliteStorage {
    /// Opens or creates an encrypted `SQLite` database at `{dir}/scp.db`.
    ///
    /// An advisory exclusive file lock on `{dir}/scp.db.lock` is taken
    /// before the database opens and held until [`close`](Self::close) or
    /// drop releases the connection. If the lock is already held by another
    /// process or another in-process instance, this constructor returns
    /// [`PlatformError::StorageLockHeld`] at once, without waiting and
    /// without opening a second `SQLite` handle against the same database —
    /// a configuration that can produce WAL corruption, split-brain writes,
    /// or silent data loss (red-hat RED-1002; spec §17.6 "One Writer per
    /// Durable Directory").
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
    /// Returns [`PlatformError::StorageLockHeld`] if another `SqliteStorage`
    /// (same process or other) holds the directory's advisory lock, and
    /// [`PlatformError::StorageError`] if the lock file or database cannot
    /// be opened, the encryption key is rejected, or the schema cannot be
    /// created.
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
        FileExt::try_lock_exclusive(&lock_file).map_err(|e| lock_error(&e, dir, &lock_path))?;

        let db_path = dir.join("scp.db");
        // `scp_sqlite_pools::open` refuses, before it opens the file, unless
        // SQLite's page-cache bulk block is absent and no page-cache buffer
        // has held a page, and then unless this connection's lookaside pool is
        // off. While no code in the process reconfigures SQLite, every block
        // holding the key, a statement, a bound value, or a decrypted page is
        // then freed through SQLCipher's allocator (spec section 17.6, which
        // names that limit's forms).
        let conn = scp_sqlite_pools::open(&db_path)
            .map_err(|e| PlatformError::StorageError(e.to_string()))?;

        // `cipher_memory_security` runs alone and is read back before the key
        // statement: SQLCipher allocates with the C library's `malloc`, which
        // the wiping global allocator never sees, and the pragma makes
        // SQLCipher wipe each block its allocator frees from then on. A
        // refusal after the key statement would come after SQLite had freed
        // blocks holding the key's hex text unwiped. While no code in the
        // process reconfigures SQLite, `1` shows memory security is on and that
        // SQLCipher is the linked engine. The key statement's blocks and the
        // decrypted pages reach SQLCipher's allocator only because SQLite's
        // reuse paths are off (checked by the open above), so the connection
        // keeps no freed block unwiped (§17.6, and §9.15 of the security-model
        // spec, freed heap memory).
        conn.execute_batch("PRAGMA cipher_memory_security = ON;")
            .map_err(|e| {
                PlatformError::StorageError(format!("failed to set cipher_memory_security: {e}"))
            })?;
        scp_sqlite_pools::require_memory_security(&conn)
            .map_err(|e| PlatformError::StorageError(e.to_string()))?;

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
            conn: Mutex::new(Some(conn)),
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

    /// Releases the database connection, then the advisory exclusive lock
    /// on `{dir}/scp.db.lock` (spec §17.6 "One Writer per Durable
    /// Directory").
    ///
    /// After `close` returns `Ok`, every [`Storage`] operation on this handle
    /// returns [`PlatformError::StorageClosed`]; the store never reopens its
    /// database implicitly. An open of the same directory then succeeds on
    /// its first attempt. Safe to call while other `Arc<SqliteStorage>`
    /// references are alive, and idempotent: a call on a closed store
    /// returns `Ok` and changes nothing.
    ///
    /// The caller owns the "after the last writer" half of the contract:
    /// call `close` only once every task that can write through this store
    /// has exited. The FFI bridges call it from the shared
    /// `scp_ffi_common::bridge_instance` shutdown only after the
    /// Supervisor's tracked tasks drain (ADR-048 §5 amendment, ADR-049
    /// Decision 16).
    ///
    /// A poisoned mutex is recovered with
    /// [`PoisonError::into_inner`](std::sync::PoisonError::into_inner): a
    /// panic inside an operation leaves the `Option` itself well formed, and
    /// skipping the release would hold the lock until drop.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformError::StorageError`] if `SQLite` refuses to close
    /// the connection. The store then keeps both its connection and its
    /// lock, because releasing the lock while the connection may still be
    /// open would admit a second writer.
    pub fn close(&self) -> Result<(), PlatformError> {
        let mut conn_guard = self
            .conn
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(conn) = conn_guard.take()
            && let Err((conn, e)) = conn.close()
        {
            *conn_guard = Some(conn);
            return Err(PlatformError::StorageError(format!(
                "failed to close database connection: {e} — the store keeps its \
                     connection and advisory lock"
            )));
        }
        // The connection is closed (now or by an earlier call), so releasing
        // the lock cannot admit a second writer. Hold the connection guard
        // across the release so no operation observes a half-closed store.
        let mut lock_guard = self
            .lock_file
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // Dropping the taken `File` releases the flock(2) / LockFileEx lock.
        drop(lock_guard.take());
        drop(lock_guard);
        drop(conn_guard);
        Ok(())
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

/// Classifies a failed `try_lock_exclusive` on `lock_path`. Contention is the
/// typed lock-still-held condition (spec §17.6); any other lock failure is an
/// I/O fault on the lock file and stays a generic storage error. The OS error
/// code is compared, not the `ErrorKind`: std maps the Windows contention code
/// to no specific kind, so a kind comparison also matches unrelated
/// uncategorized failures.
fn lock_error(e: &std::io::Error, dir: &Path, lock_path: &Path) -> PlatformError {
    let contended = fs2::lock_contended_error().raw_os_error();
    if contended.is_some() && e.raw_os_error() == contended {
        PlatformError::StorageLockHeld {
            dir: dir.display().to_string(),
            lock_path: lock_path.display().to_string(),
        }
    } else {
        PlatformError::StorageError(format!("failed to lock {}: {e}", lock_path.display()))
    }
}

/// Acquires the connection lock. A poisoned mutex maps to
/// [`PlatformError::StorageClosed`] once [`SqliteStorage::close`] has taken
/// the connection, and to [`PlatformError::StorageError`] before that.
fn lock_conn(
    conn: &Mutex<Option<Connection>>,
) -> Result<std::sync::MutexGuard<'_, Option<Connection>>, PlatformError> {
    conn.lock().map_err(|e| {
        if e.get_ref().is_none() {
            PlatformError::StorageClosed
        } else {
            PlatformError::StorageError(format!("mutex poisoned: {e}"))
        }
    })
}

/// Returns the open connection behind a held guard, or
/// [`PlatformError::StorageClosed`] once [`SqliteStorage::close`] has run.
fn open_conn<'g>(
    guard: &'g std::sync::MutexGuard<'_, Option<Connection>>,
) -> Result<&'g Connection, PlatformError> {
    guard.as_ref().ok_or(PlatformError::StorageClosed)
}

#[cfg(test)]
impl SqliteStorage {
    /// Runs `f` on the open connection through the same [`lock_conn`] and
    /// [`open_conn`] checks every [`Storage`] operation uses, so tests that
    /// use the connection do not depend on the `conn` field's representation.
    fn with_open_conn<R>(&self, f: impl FnOnce(&Connection) -> R) -> Result<R, PlatformError> {
        let guard = lock_conn(&self.conn)?;
        Ok(f(open_conn(&guard)?))
    }
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
            let guard = lock_conn(&self.conn)?;
            let conn = open_conn(&guard)?;
            conn.execute(
                "INSERT OR REPLACE INTO kv (key, value) VALUES (?1, ?2)",
                rusqlite::params![key, data],
            )
            .map_err(|e| PlatformError::StorageError(format!("store failed: {e}")))?;
            drop(guard);
            Ok(())
        }
    }

    fn retrieve(
        &self,
        key: &str,
    ) -> impl Future<Output = Result<Option<Vec<u8>>, PlatformError>> + Send {
        let key = key.to_owned();
        async move {
            let guard = lock_conn(&self.conn)?;
            let conn = open_conn(&guard)?;
            let mut stmt = conn
                .prepare_cached("SELECT value FROM kv WHERE key = ?1")
                .map_err(|e| PlatformError::StorageError(format!("prepare failed: {e}")))?;
            let result = stmt
                .query_row(rusqlite::params![key], |row| row.get::<_, Vec<u8>>(0))
                .optional()
                .map_err(|e| PlatformError::StorageError(format!("retrieve failed: {e}")))?;
            drop(stmt);
            drop(guard);
            Ok(result)
        }
    }

    fn delete(&self, key: &str) -> impl Future<Output = Result<(), PlatformError>> + Send {
        let key = key.to_owned();
        async move {
            let guard = lock_conn(&self.conn)?;
            let conn = open_conn(&guard)?;
            conn.execute("DELETE FROM kv WHERE key = ?1", rusqlite::params![key])
                .map_err(|e| PlatformError::StorageError(format!("delete failed: {e}")))?;
            drop(guard);
            Ok(())
        }
    }

    fn list_keys(
        &self,
        prefix: &str,
    ) -> impl Future<Output = Result<Vec<String>, PlatformError>> + Send {
        let prefix = prefix.to_owned();
        async move {
            let guard = lock_conn(&self.conn)?;
            let conn = open_conn(&guard)?;

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

            drop(guard);
            Ok(keys)
        }
    }

    fn delete_prefix(
        &self,
        prefix: &str,
    ) -> impl Future<Output = Result<u64, PlatformError>> + Send {
        let prefix = prefix.to_owned();
        async move {
            let guard = lock_conn(&self.conn)?;
            let conn = open_conn(&guard)?;

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

            drop(guard);
            Ok(deleted as u64)
        }
    }

    fn exists(&self, key: &str) -> impl Future<Output = Result<bool, PlatformError>> + Send {
        let key = key.to_owned();
        async move {
            let guard = lock_conn(&self.conn)?;
            let conn = open_conn(&guard)?;
            let mut stmt = conn
                .prepare_cached("SELECT COUNT(*) FROM kv WHERE key = ?1")
                .map_err(|e| PlatformError::StorageError(format!("prepare failed: {e}")))?;
            let count: i64 = stmt
                .query_row(rusqlite::params![key], |row| row.get(0))
                .map_err(|e| PlatformError::StorageError(format!("exists failed: {e}")))?;
            drop(stmt);
            drop(guard);
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

    /// The constructor's own connection serves nothing from `SQLite`'s
    /// lookaside pool after its key statement and an insert with bound values
    /// (spec §17.6, `SQLCipher` configuration).
    #[test]
    fn connection_serves_nothing_from_lookaside() {
        let dir = TempDir::new().expect("tempdir should succeed");
        let storage = SqliteStorage::new(dir.path(), &[0xAB; 32]).expect("new should succeed");
        let used = storage
            .with_open_conn(|conn| {
                conn.execute_batch(
                    "CREATE TABLE lookaside_probe (k TEXT NOT NULL, v BLOB NOT NULL)",
                )
                .expect("probe table should be created");
                conn.execute(
                    "INSERT INTO lookaside_probe (k, v) VALUES (?1, ?2)",
                    rusqlite::params!["a-key", vec![0x5A_u8; 64]],
                )
                .expect("insert should run");
                scp_sqlite_pools::lookaside_use(conn).expect("lookaside status should read")
            })
            .expect("the connection should be open");
        assert_eq!(
            used,
            scp_sqlite_pools::LookasideUse {
                slots_high_water: 0,
                hits: 0
            },
            "no lookaside slot may hold the key statement or the bound values"
        );
    }

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
            Err(PlatformError::StorageLockHeld { dir, lock_path }) => {
                assert_eq!(dir, tmp.path().display().to_string());
                assert_eq!(
                    lock_path,
                    tmp.path().join("scp.db.lock").display().to_string()
                );
            }
            Err(other) => panic!("expected StorageLockHeld, got {other:?}"),
            Ok(_) => unreachable!("second open must fail — already handled above"),
        }

        // Dropping `first` releases the lock; a fresh open must succeed.
        drop(first);
        SqliteStorage::new(tmp.path(), &key)
            .expect("fresh open after drop of prior instance must succeed");
    }

    /// `close()` must release the advisory lock even while the
    /// `SqliteStorage` value is still alive. The FFI bridges hold the storage
    /// through several `Arc` chains (`StorageProvider`,
    /// `CoreFields::persistence`, the Supervisor's persistence, the event-log
    /// repository), so drop-on-shutdown is not available and the owner
    /// releases the store by explicit call once its writers have exited.
    #[test]
    #[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    fn close_releases_advisory_lock_while_instance_alive() {
        let tmp = tempfile::TempDir::new().unwrap();
        let key = [0u8; 32];

        let first = SqliteStorage::new(tmp.path(), &key).expect("first open must succeed");

        // Explicit close releases the lock even though `first` is still alive.
        first.close().expect("close must succeed");

        // Re-open while `first` is in scope must now succeed on the first
        // attempt (spec §17.6).
        let second =
            SqliteStorage::new(tmp.path(), &key).expect("re-open after close must succeed");

        // `close()` is idempotent — a second call is a no-op and must not
        // touch the lock `second` now holds.
        first.close().expect("second close must succeed");
        assert!(
            matches!(
                SqliteStorage::new(tmp.path(), &key),
                Err(PlatformError::StorageLockHeld { .. })
            ),
            "a repeated close on the old handle must not release the new handle's lock"
        );

        drop(second);
        drop(first);
    }

    /// Spec §17.6 "One Writer per Durable Directory": `close()` releases the
    /// database connection as well as the lock, and every later operation on
    /// the handle fails with the typed closed-store error rather than
    /// writing through a connection the lock no longer guards. Each of the
    /// six `Storage` operations is checked, and the reopened store must not
    /// see a write attempted on the closed handle.
    #[tokio::test]
    #[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    async fn close_closes_connection_and_rejects_further_ops() {
        let tmp = tempfile::TempDir::new().unwrap();
        let key = [7u8; 32];

        let store = SqliteStorage::new(tmp.path(), &key).expect("open must succeed");
        store
            .store("k/live", b"v")
            .await
            .expect("store before close");
        store.close().expect("close must succeed");

        assert!(
            matches!(
                store.with_open_conn(|_| ()),
                Err(PlatformError::StorageClosed)
            ),
            "close must drop the connection, not only the lock file"
        );

        assert!(matches!(
            store.store("k/after", b"x").await,
            Err(PlatformError::StorageClosed)
        ));
        assert!(matches!(
            store.retrieve("k/live").await,
            Err(PlatformError::StorageClosed)
        ));
        assert!(matches!(
            store.delete("k/live").await,
            Err(PlatformError::StorageClosed)
        ));
        assert!(matches!(
            store.list_keys("k/").await,
            Err(PlatformError::StorageClosed)
        ));
        assert!(matches!(
            store.delete_prefix("k/").await,
            Err(PlatformError::StorageClosed)
        ));
        assert!(matches!(
            store.exists("k/live").await,
            Err(PlatformError::StorageClosed)
        ));

        // The lock is released: a reopen succeeds on its first attempt and
        // sees the pre-close write, and none of the refused operations.
        let reopened = SqliteStorage::new(tmp.path(), &key).expect("reopen must succeed");
        assert_eq!(
            reopened.retrieve("k/live").await.unwrap().as_deref(),
            Some(&b"v"[..])
        );
        assert!(!reopened.exists("k/after").await.unwrap());

        // The closed handle stays closed while a new store owns the
        // directory: it never reopens its database implicitly.
        assert!(matches!(
            store.retrieve("k/live").await,
            Err(PlatformError::StorageClosed)
        ));
    }

    /// Only the OS contention code is the typed lock-held condition. An error
    /// with the same `ErrorKind` but no OS code, or a different OS code, is a
    /// generic storage error.
    #[test]
    fn lock_error_matches_the_contention_os_code_only() {
        let dir = Path::new("/d");
        let lock_path = Path::new("/d/scp.db.lock");
        let contended = fs2::lock_contended_error();

        assert!(matches!(
            lock_error(&contended, dir, lock_path),
            PlatformError::StorageLockHeld { .. }
        ));
        let same_kind = std::io::Error::new(contended.kind(), "same kind, no OS code");
        assert!(matches!(
            lock_error(&same_kind, dir, lock_path),
            PlatformError::StorageError(_)
        ));
        let other_code = std::io::Error::from_raw_os_error(9);
        assert_ne!(other_code.raw_os_error(), contended.raw_os_error());
        assert!(matches!(
            lock_error(&other_code, dir, lock_path),
            PlatformError::StorageError(_)
        ));
    }

    /// A poisoned connection mutex refuses operations with a generic storage
    /// error while the connection is open, and with the typed closed-store
    /// error once `close()` has taken it.
    #[tokio::test]
    #[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    async fn poisoned_mutex_after_close_reports_storage_closed() {
        let tmp = tempfile::TempDir::new().unwrap();
        let key = [9u8; 32];
        let store = SqliteStorage::new(tmp.path(), &key).expect("open must succeed");

        let poisoner = std::thread::scope(|s| {
            s.spawn(|| {
                let _guard = store.conn.lock().unwrap();
                panic!("poison the connection mutex");
            })
            .join()
        });
        assert!(poisoner.is_err(), "the poisoning thread must panic");
        assert!(store.conn.is_poisoned());

        assert!(matches!(
            store.store("k", b"v").await,
            Err(PlatformError::StorageError(_))
        ));
        store.close().expect("close recovers a poisoned mutex");
        assert!(matches!(
            store.store("k", b"v").await,
            Err(PlatformError::StorageClosed)
        ));
        assert!(matches!(
            store.retrieve("k").await,
            Err(PlatformError::StorageClosed)
        ));
        SqliteStorage::new(tmp.path(), &key).expect("reopen after close must succeed");
    }
}
