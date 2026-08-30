//! Encrypted file-backed [`KeyCustody`] implementation.
//!
//! Provides `FileKeyCustody` — an encrypted-at-rest key store using
//! Argon2id for passphrase-based key derivation and AES-256-GCM for
//! encryption. This is the universal fallback for all non-HSM platforms
//! and the default custody mode for `scp-node`.
//!
//! # Key File Format
//!
//! The key file stores zero or more encrypted key entries, each containing
//! one Ed25519 or X25519 private key. The file begins with a global header
//! and is followed by a sequence of key entries:
//!
//! ```text
//! ┌────────────────────────────────────────────────┐
//! │ version: u8          (1 byte, currently 0x01)  │
//! │ argon2id_salt: [u8]  (16 bytes)                │
//! ├────────────────────────────────────────────────┤
//! │ entry_count: u32 LE  (4 bytes)                 │
//! ├────────────────────────────────────────────────┤
//! │ Entry 0:                                       │
//! │   key_type: u8       (0x01 = Ed25519,          │
//! │                       0x02 = X25519)           │
//! │   nonce: [u8]        (12 bytes, AES-256-GCM)   │
//! │   ciphertext+tag: [u8] (48 bytes = 32 + 16)    │
//! ├────────────────────────────────────────────────┤
//! │ Entry 1: ...                                   │
//! └────────────────────────────────────────────────┘
//! ```
//!
//! The Argon2id salt is generated once when the file is created and reused
//! for all entries. Each entry has a unique AES-256-GCM nonce. The
//! ciphertext is the 32-byte private key encrypted under AES-256-GCM;
//! the tag (16 bytes) is appended by the AEAD.
//!
//! # Security Properties
//!
//! - Private keys are **never** stored in plaintext on disk.
//! - The encryption key is derived from a user-provided passphrase via
//!   Argon2id with minimum parameters per OWASP recommendations (3
//!   iterations, 64 MiB memory).
//! - All in-memory key material is wrapped in [`Zeroizing`] and cleared
//!   on drop.
//! - Each `sign` / `public_key` / `dh_agree` call decrypts the key,
//!   performs the operation, and zeroizes the plaintext immediately.
//! - Every write of a key file runs under an advisory exclusive lock over that
//!   file, so two instances cannot both append entry index N and hand two
//!   identities one private key, and cannot each write a header carrying its
//!   own salt. `FileKeyCustody::lock_for_write` states how, and
//!   `FileKeyCustody::new` takes the same lock around the existence test that
//!   decides whether to write a header at all.
//! - A handle names its entry by that entry's AES-256-GCM nonce, never by the
//!   entry's position, so one instance compacting the file cannot make another
//!   instance's handle name a neighbour's key. §17.8 of the persistence spec,
//!   "`FileKeyCustody` Entry Identity", states the rule and
//!   `FileKeyCustody::locate_entry` applies it.
//!
//! See GitHub issue #391 and ADR-006.

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use fs2::FileExt;

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use rand::RngCore;
use std::sync::Mutex as StdMutex;
use tokio::sync::Mutex;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::Zeroizing;

use scp_did::attestation::{CustodySubstrate, UnlockFactor};

use crate::error::PlatformError;
use crate::traits::{
    CustodyType, KeyCustody, KeyHandle, KeyType, PseudonymKeypair, PublicKey, SharedSecret,
    Signature,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Current file format version.
const FORMAT_VERSION: u8 = 0x01;

/// Argon2id salt length in bytes.
const SALT_LEN: usize = 16;

/// AES-256-GCM nonce length in bytes.
const NONCE_LEN: usize = 12;

/// Private key length in bytes (Ed25519 or X25519).
const KEY_LEN: usize = 32;

/// AES-256-GCM authentication tag length in bytes.
const TAG_LEN: usize = 16;

/// Size of one encrypted entry on disk: `key_type` (1) + nonce (12) + ciphertext (32) + tag (16).
const ENTRY_SIZE: usize = 1 + NONCE_LEN + KEY_LEN + TAG_LEN;

/// Header size: version (1) + salt (16) + `entry_count` (4).
const HEADER_SIZE: usize = 1 + SALT_LEN + 4;

/// Key type byte for Ed25519.
const KEY_TYPE_ED25519: u8 = 0x01;

/// Key type byte for X25519.
const KEY_TYPE_X25519: u8 = 0x02;

// ---------------------------------------------------------------------------
// Internal types
// ---------------------------------------------------------------------------

/// The type of key stored in an entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StoredKeyType {
    Ed25519,
    X25519,
}

impl StoredKeyType {
    const fn to_byte(self) -> u8 {
        match self {
            Self::Ed25519 => KEY_TYPE_ED25519,
            Self::X25519 => KEY_TYPE_X25519,
        }
    }

    /// Names this stored type in the vocabulary [`PlatformError::WrongKeyType`]
    /// reports.
    const fn to_key_type(self) -> KeyType {
        match self {
            Self::Ed25519 => KeyType::Ed25519,
            Self::X25519 => KeyType::X25519,
        }
    }

    fn from_byte(b: u8) -> Result<Self, PlatformError> {
        match b {
            KEY_TYPE_ED25519 => Ok(Self::Ed25519),
            KEY_TYPE_X25519 => Ok(Self::X25519),
            _ => Err(PlatformError::CustodyError(format!(
                "unknown key type byte: {b:#04x}"
            ))),
        }
    }
}

/// Maps handle IDs to the key type and the entry nonce that names an entry.
///
/// §17.8 of the persistence spec, "`FileKeyCustody` Entry Identity", states
/// that a handle names an entry by the entry's AES-256-GCM nonce and never by
/// the entry's position: `destroy_key` compacts the file, every later entry
/// moves one position down, and a second `FileKeyCustody` over the same path
/// keeps the positions it read when it opened the file. The nonce does not
/// move, because compaction copies each surviving entry byte for byte.
///
/// The key type here records what the caller asked for when it created the
/// handle. [`FileKeyCustody::locate_entry`] reads the key type back out of the
/// file and every operation compares against that byte, so this copy selects
/// nothing on its own.
struct HandleMap {
    /// Maps `handle_id` to (`key_type`, `entry_nonce`).
    entries: HashMap<u64, (StoredKeyType, [u8; NONCE_LEN])>,
}

impl HandleMap {
    fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// Atomic write helper
// ---------------------------------------------------------------------------

/// Writes `data` to `path` atomically via a randomized `.tmp` sibling file.
///
/// 1. Generates a randomized, unpredictable temp name `{file}.{random_hex}.tmp`
///    in the parent directory so concurrent writes cannot collide and the name
///    cannot be pre-planted by an attacker.
/// 2. Opens the temp file with `create_new(true)` (`O_EXCL`): a pre-existing file
///    or symlink at the temp path fails the open rather than being
///    followed/overwritten. On `AlreadyExists` it errors fail-closed.
/// 3. Writes `data` with `mode(0o600)` on Unix.
/// 4. Calls `sync_all` to flush the file to durable storage.
/// 5. Renames to `path` (atomic on POSIX).
/// 6. On Unix, fsyncs the PARENT DIRECTORY so the rename is durable across a
///    crash. Best-effort on platforms without directory fsync.
/// 7. Cleans up the tmp file on any failure after creation.
fn atomic_write(path: &Path, data: &[u8]) -> Result<(), PlatformError> {
    let parent = path.parent().ok_or_else(|| {
        PlatformError::CustodyError(format!(
            "key path {} has no parent directory",
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
    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("keys.scp");
    let tmp_path = parent.join(format!("{file_name}.{rand_suffix:032x}.tmp"));

    // Write to temp file with restrictive permissions on Unix.
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp_path)
            .map_err(|e| {
                PlatformError::CustodyError(format!(
                    "failed to create temp key file at {}: {e}",
                    tmp_path.display()
                ))
            })?;
        file.write_all(data).map_err(|e| {
            let _ = std::fs::remove_file(&tmp_path);
            PlatformError::CustodyError(format!("failed to write temp key file: {e}"))
        })?;
        file.sync_all().map_err(|e| {
            let _ = std::fs::remove_file(&tmp_path);
            PlatformError::CustodyError(format!("failed to sync temp key file: {e}"))
        })?;
    }
    #[cfg(not(unix))]
    {
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp_path)
            .map_err(|e| {
                PlatformError::CustodyError(format!(
                    "failed to create temp key file at {}: {e}",
                    tmp_path.display()
                ))
            })?;
        file.write_all(data).map_err(|e| {
            let _ = std::fs::remove_file(&tmp_path);
            PlatformError::CustodyError(format!("failed to write temp key file: {e}"))
        })?;
        file.sync_all().map_err(|e| {
            let _ = std::fs::remove_file(&tmp_path);
            PlatformError::CustodyError(format!("failed to sync temp key file: {e}"))
        })?;
    }

    // Atomic rename: if this fails, the original file is untouched.
    std::fs::rename(&tmp_path, path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp_path);
        PlatformError::CustodyError(format!("failed to rename temp key file: {e}"))
    })?;

    // Durably persist the directory entry created by the rename. Best-effort:
    // platforms without directory fsync tolerate the error.
    sync_parent_dir(parent);

    Ok(())
}

/// Best-effort fsync of a directory so a preceding `rename` into it is durable.
///
/// On Unix, opens the directory and calls `sync_all`. Errors are tolerated
/// (some filesystems/platforms do not support directory fsync). No-op on
/// non-Unix targets.
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

// ---------------------------------------------------------------------------
// FileKeyCustody
// ---------------------------------------------------------------------------

/// Encrypted file-backed implementation of [`KeyCustody`].
///
/// Stores Ed25519 and X25519 private keys encrypted at rest using
/// AES-256-GCM with a key derived from a user-provided passphrase via
/// Argon2id. This is the universal fallback custody for non-HSM platforms.
///
/// # Thread Safety
///
/// All mutable state is protected by `tokio::sync::Mutex`.
///
/// # Two instances over one key file
///
/// The three FFI bridges open a `FileKeyCustody` per identity they create, and
/// every one of them opens `$HOME/.scp/keys.bin`, so several instances hold one
/// key file at a time. Each read-modify-write of the file — `append_entry` and
/// `destroy_key` — runs under an advisory exclusive lock over the sidecar
/// `<path>.lock`, so the writes serialize instead of overwriting each other.
/// [`FileKeyCustody::lock_for_write`] states what that race costs when the lock
/// is absent.
///
/// See GitHub issue #391 and ADR-006.
pub struct FileKeyCustody {
    /// Path to the key file on disk.
    path: PathBuf,
    /// AES-256-GCM encryption key derived from the passphrase.
    derived_key: Zeroizing<[u8; 32]>,
    /// Maps handle IDs to key type and entry index.
    handle_map: Mutex<HandleMap>,
    /// Counter for allocating new handle IDs.
    next_id: AtomicU64,
    /// In-memory store for derived pseudonym keys (not persisted to disk).
    pseudonym_keys: Mutex<HashMap<u64, SigningKey>>,
    /// Serializes file read-modify-write operations to prevent data races
    /// when multiple tasks call `append_entry` concurrently.
    ///
    /// This mutex covers one instance. The advisory lock below covers the file,
    /// and the two together are what make a read-modify-write of the key file
    /// exclusive.
    file_write_lock: StdMutex<()>,
    /// The open handle to the sidecar `<path>.lock`, whose advisory exclusive
    /// lock [`FileKeyCustody::lock_for_write`] takes around every
    /// read-modify-write of the key file.
    lock_file: File,
}

/// Releases the key file's advisory exclusive lock when it drops.
///
/// [`FileKeyCustody::lock_for_write`] returns one of these, and the write that
/// holds it runs to its end — or unwinds — before another instance's write
/// reads the file.
struct KeyFileWriteLock<'a> {
    lock_file: &'a File,
}

impl Drop for KeyFileWriteLock<'_> {
    fn drop(&mut self) {
        if let Err(e) = FileExt::unlock(self.lock_file) {
            tracing::error!(
                error = %e,
                "failed to release the key file write lock — a later write by \
                 this process or another will block on it"
            );
        }
    }
}

impl FileKeyCustody {
    /// Opens an existing key file or creates a new one at `path`.
    ///
    /// The passphrase is used to derive the AES-256-GCM encryption key via
    /// Argon2id. If the file exists, it is read and validated; if the
    /// passphrase is wrong, decryption of existing entries will fail on
    /// access (the derived key will differ).
    ///
    /// Opening runs under the same advisory exclusive lock every write runs
    /// under, and the test for whether the file exists runs inside that lock.
    /// `create_new` writes a header carrying a fresh salt, so two instances
    /// that each found no file would each write a salt and the second write
    /// would replace the first instance's. That first instance keeps the key it
    /// derived from its own salt, appends entries encrypted under that key into
    /// a file whose header now names the other salt, and every later open of
    /// the file decrypts one of the two instances' entries to garbage. Taking
    /// the lock before the existence test makes the second instance read the
    /// file the first one wrote and derive its key from that file's salt.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformError::CustodyError`] if the file exists but has
    /// an invalid format, or if I/O operations fail.
    pub fn new(path: &Path, passphrase: &str) -> Result<Self, PlatformError> {
        let lock_file = Self::open_lock_file(path)?;
        // The lock is taken and released through one handle, rather than
        // through a [`KeyFileWriteLock`] guard: the two constructors below take
        // ownership of `lock_file`, so no guard this function holds can outlive
        // the call that moves the handle. On the success path the instance now
        // owns the handle and the `unlock` below runs against it. On the error
        // path the failing constructor dropped the handle, and closing a file
        // handle releases the advisory lock it holds.
        FileExt::lock_exclusive(&lock_file).map_err(|e| {
            PlatformError::CustodyError(format!(
                "failed to take the write lock for the key file at {}: {e}",
                path.display()
            ))
        })?;

        let custody = if path.exists() {
            Self::open_existing(path, passphrase, lock_file)
        } else {
            Self::create_new(path, passphrase, lock_file)
        }?;

        if let Err(e) = FileExt::unlock(&custody.lock_file) {
            tracing::error!(
                error = %e,
                "failed to release the key file lock this construction took — a \
                 later write by this process or another will block on it"
            );
        }
        Ok(custody)
    }

    /// Opens the sidecar `<path>.lock`, whose advisory exclusive lock every
    /// read-modify-write of the key file is taken under.
    ///
    /// This function only opens the handle. [`FileKeyCustody::lock_for_write`]
    /// takes the lock, and it states what the lock defends.
    ///
    /// The handle is opened once, at construction, so a write does not pay an
    /// `open` and so a caller learns at construction — rather than at the first
    /// `generate_keypair` — that the directory holding the key file rejects the
    /// lock file.
    fn open_lock_file(path: &Path) -> Result<File, PlatformError> {
        let mut lock_name = path.file_name().map_or_else(
            || std::ffi::OsString::from("keys.scp"),
            std::ffi::OsString::from,
        );
        lock_name.push(".lock");
        let lock_path = path.with_file_name(lock_name);

        let lock_file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(&lock_path)
            .map_err(|e| {
                PlatformError::CustodyError(format!(
                    "failed to open the key-file lock at {}: {e}",
                    lock_path.display()
                ))
            })?;

        Ok(lock_file)
    }

    /// Takes the advisory exclusive lock over the key file and returns a guard
    /// that releases it on drop.
    ///
    /// Every write of the key file runs under this lock. `append_entry` and
    /// `destroy_key` each read the whole file, change one entry, and write the
    /// whole file back. [`FileKeyCustody::new`] takes the same lock around the
    /// existence test and the `create_new` that follows it, so two instances
    /// cannot each write a header carrying its own salt.
    ///
    /// Without it, two `FileKeyCustody` instances over one path each hold their
    /// own `file_write_lock`, which is a `StdMutex` one instance owns, so both
    /// read the same entry count, both write entry index N, and the second
    /// `atomic_write` discards the first instance's private key. Neither
    /// `generate_keypair` reports anything: both instances keep a handle naming
    /// index N, and index N decrypts to the winner's key under the same
    /// passphrase-derived AES key, so the loser signs with a key another
    /// identity published. All three FFI bridges open one hardcoded path,
    /// `$HOME/.scp/keys.bin`
    /// (`scp_ffi_common::key_file::open_default_key_file`), so two SCP
    /// processes on one machine reach exactly that state.
    ///
    /// The lock is held for one write rather than for the instance's lifetime,
    /// which is where this departs from `SqliteStorage`
    /// (`crates/scp-platform/src/sqlite/mod.rs`). That type takes its
    /// lock in the constructor and refuses a second instance, because one
    /// database directory is meant to have one open handle. A key file is not:
    /// the three bridges open a `FileKeyCustody` per identity they create, so
    /// refusing the second open would refuse a second identity in one process.
    /// Serializing the writes instead keeps both keys, and each instance's
    /// handle map then names the entry that instance appended.
    ///
    /// `lock_exclusive` blocks rather than failing, because two instances over
    /// one key file is a supported arrangement and a contending writer holds
    /// the lock only for the length of one file rewrite. `file_write_lock` is
    /// already held across the same span, so this adds no blocking a caller did
    /// not already have. POSIX `flock` associates the lock with the open file
    /// description, and each instance opened its own, so two instances inside
    /// one process contend exactly as two processes do.
    ///
    /// One case this lock does not cover, and does not have to:
    /// `destroy_key` compacts the file, so every entry after the destroyed one
    /// moves down by one position, and serializing the writes cannot help
    /// because the two writes are already ordered. A handle names its entry by
    /// the entry's AES-256-GCM nonce instead of by a position, so the move
    /// changes nothing the handle names.
    /// [`FileKeyCustody::locate_entry`] resolves that name against the file as
    /// it stands, and §17.8 of the persistence spec, "`FileKeyCustody` Entry
    /// Identity", states the rule.
    fn lock_for_write(&self) -> Result<KeyFileWriteLock<'_>, PlatformError> {
        FileExt::lock_exclusive(&self.lock_file).map_err(|e| {
            PlatformError::CustodyError(format!(
                "failed to take the write lock for the key file at {}: {e}",
                self.path.display()
            ))
        })?;
        Ok(KeyFileWriteLock {
            lock_file: &self.lock_file,
        })
    }

    /// Creates a new key file at `path` with a fresh salt.
    ///
    /// Uses write-to-tmp + rename for crash-safe atomic writes (#1470).
    fn create_new(path: &Path, passphrase: &str, lock_file: File) -> Result<Self, PlatformError> {
        let mut salt = [0u8; SALT_LEN];
        rand::rngs::OsRng.fill_bytes(&mut salt);

        let derived_key = Self::derive_key(passphrase, &salt)?;

        // Write the initial file: version + salt + entry_count(0).
        let mut data = Vec::with_capacity(HEADER_SIZE);
        data.push(FORMAT_VERSION);
        data.extend_from_slice(&salt);
        data.extend_from_slice(&0u32.to_le_bytes());

        // Write to temp file, sync, then atomic rename (#1470).
        atomic_write(path, &data)?;

        Ok(Self {
            path: path.to_path_buf(),
            derived_key,
            handle_map: Mutex::new(HandleMap::new()),
            next_id: AtomicU64::new(1),
            pseudonym_keys: Mutex::new(HashMap::new()),
            file_write_lock: StdMutex::new(()),
            lock_file,
        })
    }

    /// Opens an existing key file at `path` and loads entry metadata.
    fn open_existing(
        path: &Path,
        passphrase: &str,
        lock_file: File,
    ) -> Result<Self, PlatformError> {
        let data = std::fs::read(path)
            .map_err(|e| PlatformError::CustodyError(format!("failed to read key file: {e}")))?;

        if data.len() < HEADER_SIZE {
            return Err(PlatformError::CustodyError(
                "key file too short for header".into(),
            ));
        }

        if data[0] != FORMAT_VERSION {
            return Err(PlatformError::CustodyError(format!(
                "unsupported key file version: {:#04x}",
                data[0]
            )));
        }

        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(&data[1..=SALT_LEN]);

        let entry_count = Self::entry_count(&data)?;

        let derived_key = Self::derive_key(passphrase, &salt)?;

        // Build the handle map from stored entries.
        let mut handle_map = HandleMap::new();
        let mut next_id = 1u64;
        let mut seen_nonces = std::collections::HashSet::with_capacity(entry_count);

        for i in 0..entry_count {
            let offset = HEADER_SIZE + i * ENTRY_SIZE;
            let key_type_byte = data[offset];
            let key_type = StoredKeyType::from_byte(key_type_byte)?;
            let mut entry_nonce = [0u8; NONCE_LEN];
            entry_nonce.copy_from_slice(&data[offset + 1..offset + 1 + NONCE_LEN]);

            // §17.8 of the persistence spec makes this rejection normative, and
            // makes it happen at the open rather than at the first decryption:
            // a handle names an entry by its nonce, so two entries under one
            // nonce leave that name pointing at two keys. AES-256-GCM already
            // forbids the pair under one derived key, so a file that carries it
            // was written by something other than this type.
            if !seen_nonces.insert(entry_nonce) {
                return Err(PlatformError::CustodyError(format!(
                    "key file carries one AES-256-GCM nonce on two entries, and entry \
                     {i} is the second — a handle names an entry by its nonce, so this \
                     file names one key twice"
                )));
            }

            let handle_id = next_id;
            next_id += 1;
            handle_map
                .entries
                .insert(handle_id, (key_type, entry_nonce));
        }

        Ok(Self {
            path: path.to_path_buf(),
            derived_key,
            handle_map: Mutex::new(handle_map),
            next_id: AtomicU64::new(next_id),
            pseudonym_keys: Mutex::new(HashMap::new()),
            file_write_lock: StdMutex::new(()),
            lock_file,
        })
    }

    /// Derives an AES-256 key from a passphrase and salt using Argon2id.
    ///
    /// Delegates to [`crate::kdf::derive_argon2id_key`] — the single source of
    /// the Argon2id parameterization (spec §17.6 / §17.8). Behavior is
    /// byte-identical to the historical inline derivation.
    fn derive_key(
        passphrase: &str,
        salt: &[u8; SALT_LEN],
    ) -> Result<Zeroizing<[u8; 32]>, PlatformError> {
        crate::kdf::derive_argon2id_key(passphrase.as_bytes(), salt)
    }

    /// Encrypts a 32-byte private key using AES-256-GCM with a fresh nonce.
    fn encrypt_key(
        &self,
        plaintext: &[u8; KEY_LEN],
    ) -> Result<([u8; NONCE_LEN], Vec<u8>), PlatformError> {
        let cipher = Aes256Gcm::new_from_slice(self.derived_key.as_ref())
            .map_err(|e| PlatformError::CustodyError(format!("cipher init failed: {e}")))?;

        let mut nonce_bytes = [0u8; NONCE_LEN];
        rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, plaintext.as_ref())
            .map_err(|e| PlatformError::CustodyError(format!("encryption failed: {e}")))?;

        Ok((nonce_bytes, ciphertext))
    }

    /// Returns the position of the entry `entry_nonce` names, together with the
    /// key type the file records for it.
    ///
    /// §17.8 of the persistence spec, "`FileKeyCustody` Entry Identity", states
    /// that a handle names an entry by its nonce. This function is where that
    /// name resolves to a position, and it resolves against the file as it
    /// stands rather than against a position an instance recorded earlier.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformError::KeyNotFound`] when no entry carries the nonce,
    /// which is the state a handle reaches after another `FileKeyCustody` over
    /// the same path destroys the key it named. Returns
    /// [`PlatformError::CustodyError`] when the header states an entry count
    /// the file is too short for, and when two entries carry one nonce —
    /// AES-256-GCM forbids that pair under one derived key, so the file is
    /// corrupt and this refuses to pick one of the two.
    fn locate_entry(
        data: &[u8],
        entry_nonce: &[u8; NONCE_LEN],
    ) -> Result<(usize, StoredKeyType), PlatformError> {
        let entry_count = Self::entry_count(data)?;

        let mut found: Option<(usize, StoredKeyType)> = None;
        for index in 0..entry_count {
            let offset = HEADER_SIZE + index * ENTRY_SIZE;
            if &data[offset + 1..offset + 1 + NONCE_LEN] != entry_nonce.as_slice() {
                continue;
            }
            // The key type comes off the file, never off the handle map. A
            // second instance's map records the type its own `generate_keypair`
            // asked for, and that record says nothing about the entry the file
            // holds under this nonce today.
            let key_type = StoredKeyType::from_byte(data[offset])?;
            if found.is_some() {
                return Err(PlatformError::CustodyError(
                    "key file carries one AES-256-GCM nonce on two entries, which \
                     AES-256-GCM forbids under one derived key — refusing to choose \
                     between them"
                        .into(),
                ));
            }
            found = Some((offset, key_type));
        }

        found.ok_or(PlatformError::KeyNotFound)
    }

    /// Reads the entry count out of the header and checks the file holds that
    /// many entries.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformError::CustodyError`] when the file is shorter than a
    /// header, and when the count the header states runs past the end of the
    /// file. Every slice this module takes past the header depends on that
    /// check, and slicing without it panics across the `PyO3`, napi, and
    /// `UniFFI` boundaries.
    fn entry_count(data: &[u8]) -> Result<usize, PlatformError> {
        if data.len() < HEADER_SIZE {
            return Err(PlatformError::CustodyError(format!(
                "key file too short for header: {} bytes",
                data.len()
            )));
        }
        let entry_count = u32::from_le_bytes(
            data[1 + SALT_LEN..HEADER_SIZE]
                .try_into()
                .map_err(|_| PlatformError::CustodyError("invalid entry count bytes".into()))?,
        ) as usize;

        let expected_len = HEADER_SIZE + entry_count * ENTRY_SIZE;
        if data.len() < expected_len {
            return Err(PlatformError::CustodyError(format!(
                "key file truncated: its header states {entry_count} entries, which end \
                 at {expected_len} bytes, and the file is {} bytes",
                data.len()
            )));
        }

        Ok(entry_count)
    }

    /// Decrypts the key entry that starts at `offset`.
    ///
    /// [`FileKeyCustody::locate_entry`] returns the offset, so it has already
    /// checked that the file holds a whole entry there.
    fn decrypt_entry(
        &self,
        data: &[u8],
        offset: usize,
    ) -> Result<Zeroizing<[u8; KEY_LEN]>, PlatformError> {
        // Skip key_type byte (1 byte).
        let nonce_start = offset + 1;
        let ct_start = nonce_start + NONCE_LEN;
        let ct_end = ct_start + KEY_LEN + TAG_LEN;

        let nonce = Nonce::from_slice(&data[nonce_start..ct_start]);
        let ciphertext_and_tag = &data[ct_start..ct_end];

        let cipher = Aes256Gcm::new_from_slice(self.derived_key.as_ref())
            .map_err(|e| PlatformError::CustodyError(format!("cipher init failed: {e}")))?;

        let plaintext =
            Zeroizing::new(cipher.decrypt(nonce, ciphertext_and_tag).map_err(|_| {
                PlatformError::CustodyError("decryption failed (wrong passphrase?)".into())
            })?);

        let mut key_bytes = Zeroizing::new([0u8; KEY_LEN]);
        if plaintext.len() != KEY_LEN {
            return Err(PlatformError::CustodyError(format!(
                "decrypted key has wrong length: expected {KEY_LEN}, got {}",
                plaintext.len()
            )));
        }
        key_bytes.copy_from_slice(&plaintext);
        Ok(key_bytes)
    }

    /// Reads the key file from disk.
    fn read_file(&self) -> Result<Vec<u8>, PlatformError> {
        std::fs::read(&self.path)
            .map_err(|e| PlatformError::CustodyError(format!("failed to read key file: {e}")))
    }

    /// Appends an encrypted key entry to the file, updates the entry count, and
    /// returns the AES-256-GCM nonce that names the new entry.
    ///
    /// The caller records that nonce in the handle map. §17.8 of the
    /// persistence spec, "`FileKeyCustody` Entry Identity", states why the
    /// caller records the nonce rather than the position this function appended
    /// at: another instance's `destroy_key` moves the position and leaves the
    /// nonce where it is.
    ///
    /// Uses write-to-tmp + rename for crash-safe atomic writes (#1470).
    fn append_entry(
        &self,
        key_type: StoredKeyType,
        private_key: &[u8; KEY_LEN],
    ) -> Result<[u8; NONCE_LEN], PlatformError> {
        let _lock = self
            .file_write_lock
            .lock()
            .map_err(|_| PlatformError::CustodyError("file write lock poisoned".into()))?;
        // Cross-instance and cross-process exclusion. `file_write_lock` above
        // covers this instance's own tasks; this covers every other holder of
        // the same path. The read below and the write at the end of this
        // function are one read-modify-write, so both run under it.
        let _file_lock = self.lock_for_write()?;
        let mut data = self.read_file()?;

        // Read current entry count. `entry_count` also checks that the file
        // holds every entry its header states, so the append below extends a
        // whole file rather than a truncated one.
        let count_offset = 1 + SALT_LEN;
        let current_count = u32::try_from(Self::entry_count(&data)?).map_err(|_| {
            PlatformError::CustodyError("key file holds more entries than u32 states".into())
        })?;

        // Encrypt the key.
        let (nonce, ciphertext) = self.encrypt_key(private_key)?;

        // Build the entry: key_type + nonce + ciphertext+tag.
        data.push(key_type.to_byte());
        data.extend_from_slice(&nonce);
        data.extend_from_slice(&ciphertext);

        // Update entry count.
        let new_count = current_count + 1;
        data[count_offset..count_offset + 4].copy_from_slice(&new_count.to_le_bytes());

        // Write to temp file with sync_all, then atomic rename (#1470).
        atomic_write(&self.path, &data)?;

        Ok(nonce)
    }

    /// Allocates the next handle ID.
    fn next_handle(&self) -> KeyHandle {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        KeyHandle::new(id)
    }

    /// Reads the entry `entry_nonce` names out of `data` and checks that the
    /// file records `expected` as its key type.
    ///
    /// §17.8 of the persistence spec, "`FileKeyCustody` Entry Identity",
    /// requires the key type to come off the located entry rather than off a
    /// value the instance recorded when it opened the file. An X25519 secret
    /// read through a handle whose map records Ed25519 reaches
    /// `SigningKey::from_bytes` as an Ed25519 seed, which uses one secret
    /// scalar under two signature schemes.
    fn decrypt_entry_of_type(
        &self,
        data: &[u8],
        entry_nonce: &[u8; NONCE_LEN],
        expected: StoredKeyType,
    ) -> Result<Zeroizing<[u8; KEY_LEN]>, PlatformError> {
        let (offset, stored_type) = Self::locate_entry(data, entry_nonce)?;
        if stored_type != expected {
            return Err(PlatformError::WrongKeyType {
                expected: expected.to_key_type(),
                actual: stored_type.to_key_type(),
            });
        }
        self.decrypt_entry(data, offset)
    }

    /// Decrypts an Ed25519 signing key from the file for the given handle.
    ///
    /// Holds the `handle_map` lock across both the lookup and the file read to
    /// prevent a concurrent `destroy_key` from rewriting the file between the
    /// two operations (TOCTOU).
    async fn decrypt_ed25519_key(
        &self,
        handle: &KeyHandle,
    ) -> Result<(Zeroizing<[u8; KEY_LEN]>, SigningKey), PlatformError> {
        let map = self.handle_map.lock().await;
        let (_recorded_type, entry_nonce) = map
            .entries
            .get(&handle.id())
            .copied()
            .ok_or(PlatformError::KeyNotFound)?;
        let data = self.read_file()?;
        drop(map);
        let key_bytes = self.decrypt_entry_of_type(&data, &entry_nonce, StoredKeyType::Ed25519)?;
        let signing_key = SigningKey::from_bytes(&key_bytes);
        Ok((key_bytes, signing_key))
    }

    /// Exports a clone of the Ed25519 signing key for the given handle.
    ///
    /// Required by FFI bridges that need the raw `ed25519_dalek::SigningKey`
    /// for core governance functions (`propose_governance_action`,
    /// `approve_governance_proposal`, etc.) which take `&SigningKey` directly.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformError::KeyNotFound`] if the handle is invalid.
    /// Returns [`PlatformError::WrongKeyType`] if the handle refers to an
    /// X25519 key.
    pub async fn export_ed25519_signing_key(
        &self,
        handle: &KeyHandle,
    ) -> Result<SigningKey, PlatformError> {
        let (_key_bytes, signing_key) = self.decrypt_ed25519_key(handle).await?;
        Ok(signing_key)
    }
}

use scp_crypto::pseudonym::derive_pseudonym_keypair;

// Trait uses RPITIT with explicit `+ Send` bound; async fn in trait
// does not guarantee Send futures, so manual impl Future is required.
#[allow(clippy::manual_async_fn)]
impl KeyCustody for FileKeyCustody {
    fn generate_keypair(
        &self,
        key_type: KeyType,
    ) -> impl Future<Output = Result<KeyHandle, PlatformError>> + Send {
        async move {
            let mut key_bytes = Zeroizing::new([0u8; KEY_LEN]);
            rand::rngs::OsRng.fill_bytes(key_bytes.as_mut());

            let stored_type = match key_type {
                KeyType::Ed25519 => StoredKeyType::Ed25519,
                KeyType::X25519 => StoredKeyType::X25519,
            };

            // Hold `handle_map` across the entire append-and-insert
            // path so a concurrent `destroy_key` on this instance cannot
            // interleave with the insert. `append_entry` takes only
            // `file_write_lock`, never `handle_map`, so there is no
            // lock-ordering inversion. Mirrors the pattern in
            // `import_ed25519_signing_key`.
            let mut map = self.handle_map.lock().await;
            let entry_nonce = self.append_entry(stored_type, &key_bytes)?;
            let handle = self.next_handle();
            map.entries.insert(handle.id(), (stored_type, entry_nonce));
            drop(map);

            Ok(handle)
        }
    }

    fn sign(
        &self,
        key: &KeyHandle,
        data: &[u8],
    ) -> impl Future<Output = Result<Signature, PlatformError>> + Send {
        let key_id = key.id();
        let handle = KeyHandle::new(key_id);
        async move {
            // Check if this is a derived pseudonym key (stored in memory).
            {
                let pseudonyms = self.pseudonym_keys.lock().await;
                if let Some(signing_key) = pseudonyms.get(&key_id) {
                    let signature = signing_key.sign(data);
                    return Ok(Signature::new(signature.to_bytes().to_vec()));
                }
            }

            let (_key_bytes, signing_key) = self.decrypt_ed25519_key(&handle).await?;
            let signature = signing_key.sign(data);
            // signing_key and _key_bytes are dropped here (Zeroizing for _key_bytes).
            Ok(Signature::new(signature.to_bytes().to_vec()))
        }
    }

    fn public_key(
        &self,
        key: &KeyHandle,
    ) -> impl Future<Output = Result<PublicKey, PlatformError>> + Send {
        let key_id = key.id();
        let handle = KeyHandle::new(key_id);
        async move {
            // Check pseudonym keys first.
            {
                let pseudonyms = self.pseudonym_keys.lock().await;
                if let Some(signing_key) = pseudonyms.get(&key_id) {
                    let vk = signing_key.verifying_key();
                    return Ok(PublicKey::new(vk.to_bytes().to_vec()));
                }
            }

            // Hold handle_map lock across lookup and file read to prevent
            // a concurrent destroy_key from rewriting the file (TOCTOU).
            let map = self.handle_map.lock().await;
            let (_recorded_type, entry_nonce) = map
                .entries
                .get(&handle.id())
                .copied()
                .ok_or(PlatformError::KeyNotFound)?;
            let data = self.read_file()?;
            drop(map);
            // This operation serves both key types, so it takes the type off
            // the located entry rather than checking it against one the caller
            // named. §17.8 of the persistence spec requires the file's own byte
            // to decide.
            let (offset, key_type) = Self::locate_entry(&data, &entry_nonce)?;
            let key_bytes = self.decrypt_entry(&data, offset)?;

            match key_type {
                StoredKeyType::Ed25519 => {
                    let signing_key = SigningKey::from_bytes(&key_bytes);
                    let vk: VerifyingKey = signing_key.verifying_key();
                    Ok(PublicKey::new(vk.to_bytes().to_vec()))
                }
                StoredKeyType::X25519 => {
                    let secret = StaticSecret::from(*key_bytes);
                    let public = X25519PublicKey::from(&secret);
                    Ok(PublicKey::new(public.to_bytes().to_vec()))
                }
            }
        }
    }

    fn destroy_key(
        &self,
        key: &KeyHandle,
    ) -> impl Future<Output = Result<(), PlatformError>> + Send {
        let key_id = key.id();
        async move {
            // Standardized lock order: `handle_map` first, then
            // `pseudonym_keys`. Other call sites that touch both
            // (`sign`, `public_key`) release `pseudonym_keys` before
            // acquiring `handle_map`, so they do not hold the locks
            // concurrently and remain compatible with this ordering.
            let mut map = self.handle_map.lock().await;

            // Pseudonym keys are in-memory only — no disk rewrite needed.
            // Check them under the held `handle_map` lock so destroy_key
            // is atomic with concurrent map readers.
            {
                let mut pseudonyms = self.pseudonym_keys.lock().await;
                if pseudonyms.remove(&key_id).is_some() {
                    return Ok(());
                }
            }

            // Look up — do NOT mutate the map yet. Map mutation is
            // deferred until after the file rewrite succeeds, so a
            // failed `read_file` or `atomic_write` cannot orphan
            // encrypted material on disk (the in-memory map would
            // otherwise have lost the only handle pointing at it).
            let Some(&(_, entry_nonce)) = map.entries.get(&key_id) else {
                return Err(PlatformError::KeyNotFound);
            };

            // Rewrite the key file without the destroyed entry.
            // This ensures key material is removed from disk, not just from
            // the in-memory handle map.
            let _lock = self
                .file_write_lock
                .lock()
                .map_err(|_| PlatformError::CustodyError("file write lock poisoned".into()))?;
            // Same exclusion `append_entry` takes, for the same reason: the
            // read below and the `atomic_write` that rewrites the file without
            // the destroyed entry are one read-modify-write.
            let _file_lock = self.lock_for_write()?;

            let data = self.read_file()?;

            // Reconstruct the file: copy header, skip the destroyed entry,
            // decrement the entry count.
            let count_offset = 1 + SALT_LEN;
            let current_count = Self::entry_count(&data)?;

            // Locate the entry in the file as it stands now, rather than at a
            // position this instance recorded earlier. Another instance may
            // have compacted the file since, so the position moved and the
            // nonce did not. `locate_entry` reports `KeyNotFound` when that
            // other instance already destroyed this key, which is the honest
            // answer for a handle whose key is gone.
            let (removed_offset, _removed_type) = Self::locate_entry(&data, &entry_nonce)
                .inspect_err(|e| {
                    tracing::error!(
                        key_id,
                        error = %e,
                        "FileKeyCustody::destroy_key could not locate the entry its handle names"
                    );
                })?;

            let new_count = u32::try_from(current_count - 1).map_err(|_| {
                PlatformError::CustodyError("key file holds more entries than u32 states".into())
            })?;
            let mut new_data = Vec::with_capacity(HEADER_SIZE + (new_count as usize) * ENTRY_SIZE);

            // Copy header (version + salt).
            new_data.extend_from_slice(&data[..count_offset]);
            // Write updated entry count.
            new_data.extend_from_slice(&new_count.to_le_bytes());

            // Copy all entries except the removed one.
            for i in 0..current_count {
                let entry_offset = HEADER_SIZE + i * ENTRY_SIZE;
                if entry_offset == removed_offset {
                    continue;
                }
                new_data.extend_from_slice(&data[entry_offset..entry_offset + ENTRY_SIZE]);
            }

            // Commit to disk BEFORE mutating the in-memory map. If
            // `atomic_write` fails, the map still references the
            // (unmodified) on-disk entry — no orphaned ciphertext.
            atomic_write(&self.path, &new_data)?;

            // Now that disk state is updated, drop the destroyed entry from the
            // in-memory map. No other entry in the map changes: every remaining
            // handle names its entry by a nonce, and this rewrite moved
            // positions without touching a nonce.
            map.entries.remove(&key_id);
            drop(map);

            Ok(())
        }
    }

    fn dh_agree(
        &self,
        key: &KeyHandle,
        peer_public: &[u8; 32],
    ) -> impl Future<Output = Result<SharedSecret, PlatformError>> + Send {
        let key_id = key.id();
        let peer = *peer_public;
        async move {
            let handle = KeyHandle::new(key_id);
            // Hold handle_map lock across lookup and file read to prevent
            // a concurrent destroy_key from rewriting the file (TOCTOU).
            let map = self.handle_map.lock().await;
            let (_recorded_type, entry_nonce) = map
                .entries
                .get(&handle.id())
                .copied()
                .ok_or(PlatformError::KeyNotFound)?;

            let data = self.read_file()?;
            drop(map);
            let key_bytes =
                self.decrypt_entry_of_type(&data, &entry_nonce, StoredKeyType::X25519)?;

            let secret = StaticSecret::from(*key_bytes);
            let peer_key = X25519PublicKey::from(peer);
            let shared = secret.diffie_hellman(&peer_key);
            let shared_bytes = Zeroizing::new(shared.to_bytes());
            Ok(SharedSecret::new(*shared_bytes))
        }
    }

    fn derive_pseudonym(
        &self,
        key: &KeyHandle,
        context_id: &[u8],
    ) -> impl Future<Output = Result<PseudonymKeypair, PlatformError>> + Send {
        let key_id = key.id();
        let context_id = context_id.to_vec();
        async move {
            let handle = KeyHandle::new(key_id);
            let (_key_bytes, signing_key) = self.decrypt_ed25519_key(&handle).await?;

            // Software custody: pseudonym keypair = Ed25519_keygen(HMAC-SHA256(
            //   pseudonym_secret, context_id || "scp-pseudonym")), where the
            // pseudonym_secret is derived from the private seed via HKDF (§9.10.4.A),
            // NOT the public key, to prevent membership enumeration attacks.
            let pseudonym_signing_key = derive_pseudonym_keypair(&signing_key, &context_id, None);
            let pseudonym_verifying_key = pseudonym_signing_key.verifying_key();

            // Store derived key in memory (pseudonyms are software-managed).
            let pseudo_handle = self.next_handle();
            let mut pseudonyms = self.pseudonym_keys.lock().await;
            pseudonyms.insert(pseudo_handle.id(), pseudonym_signing_key);
            drop(pseudonyms);

            Ok(PseudonymKeypair {
                public_key: PublicKey::new(pseudonym_verifying_key.to_bytes().to_vec()),
                key_handle: pseudo_handle,
            })
        }
    }

    fn derive_rotatable_pseudonym(
        &self,
        key: &KeyHandle,
        context_id: &[u8],
        pseudonym_epoch: u64,
    ) -> impl Future<Output = Result<PseudonymKeypair, PlatformError>> + Send {
        let key_id = key.id();
        let context_id = context_id.to_vec();
        async move {
            let handle = KeyHandle::new(key_id);
            let (_key_bytes, signing_key) = self.decrypt_ed25519_key(&handle).await?;

            // Software custody: rotatable pseudonym keypair = Ed25519_keygen(
            //   HMAC-SHA256(pseudonym_secret, context_id || epoch_BE
            //   || "scp-pseudonym-v2")). The pseudonym_secret is derived from the
            // private seed via HKDF (§9.10.4.A), NOT the public key, to prevent
            // membership enumeration attacks. epoch_BE breaks long-term correlation.
            let pseudonym_signing_key =
                derive_pseudonym_keypair(&signing_key, &context_id, Some(pseudonym_epoch));
            let pseudonym_verifying_key = pseudonym_signing_key.verifying_key();

            let pseudo_handle = self.next_handle();
            let mut pseudonyms = self.pseudonym_keys.lock().await;
            pseudonyms.insert(pseudo_handle.id(), pseudonym_signing_key);
            drop(pseudonyms);

            Ok(PseudonymKeypair {
                public_key: PublicKey::new(pseudonym_verifying_key.to_bytes().to_vec()),
                key_handle: pseudo_handle,
            })
        }
    }

    fn ed25519_to_x25519_agree(
        &self,
        ed25519_handle: &KeyHandle,
        peer_x25519_public: &[u8; 32],
    ) -> impl Future<Output = Result<SharedSecret, PlatformError>> + Send {
        let handle = *ed25519_handle;
        let peer = *peer_x25519_public;
        async move {
            let (_key_bytes, signing_key) = self.decrypt_ed25519_key(&handle).await?;
            Ok(crate::traits::x25519_agree_from_ed25519(
                &signing_key,
                &peer,
            ))
        }
    }

    fn custody_type(&self, _key: &KeyHandle) -> CustodyType {
        CustodyType::Software
    }

    fn generate_ephemeral_ed25519_seed(
        &self,
    ) -> impl Future<Output = Result<Zeroizing<[u8; 32]>, PlatformError>> + Send {
        async move {
            // Software custody: draw 32 bytes from OsRng. The bytes are
            // returned to the caller in a Zeroizing wrapper and never
            // persisted in the file-encrypted custody — the caller hands
            // them to a `PreRotationCustody` per spec §9.7.4.1 §1, §5(f).
            let mut seed = Zeroizing::new([0u8; 32]);
            rand::rngs::OsRng.fill_bytes(seed.as_mut());
            Ok(seed)
        }
    }

    fn import_ed25519_signing_key(
        &self,
        seed: &Zeroizing<[u8; 32]>,
    ) -> impl Future<Output = Result<KeyHandle, PlatformError>> + Send {
        async move {
            // Dedup by content: if the seed's verifying key already
            // matches an existing Ed25519 entry, return that handle
            // instead of appending a duplicate. Without this guard a
            // retry of import (e.g. on transient failure higher up the
            // stack) would create a parallel encrypted entry holding the
            // same private key — wasting space and producing a phantom
            // handle on reopen that the registry can no longer reach.
            let signing_key = SigningKey::from_bytes(seed);
            let target_pub = signing_key.verifying_key().to_bytes();

            // Hold `handle_map.lock()` across the entire scan-and-insert
            // path so that two concurrent imports of the same seed
            // cannot both observe a non-matching snapshot and both
            // append. We do NOT call `self.decrypt_ed25519_key` from
            // here (that method re-acquires `handle_map` and would
            // deadlock). Instead, read the file once and decrypt
            // candidate Ed25519 entries directly via `decrypt_entry`.
            // `append_entry` takes the separate `file_write_lock`,
            // never `handle_map`, so there is no inversion.
            let mut map = self.handle_map.lock().await;

            // Scan the file rather than this instance's map. Another
            // `FileKeyCustody` over the same path may have appended this seed
            // or destroyed a key since this instance opened the file, so the
            // map states what this instance did and the file states what the
            // store holds.
            let data = self.read_file()?;
            let entry_count = Self::entry_count(&data)?;
            for index in 0..entry_count {
                let offset = HEADER_SIZE + index * ENTRY_SIZE;
                if data[offset] != KEY_TYPE_ED25519 {
                    continue;
                }
                let mut entry_nonce = [0u8; NONCE_LEN];
                entry_nonce.copy_from_slice(&data[offset + 1..offset + 1 + NONCE_LEN]);

                // Surface decrypt failure rather than silently skipping
                // the entry. A failed decrypt at this point indicates
                // file corruption (mismatched MAC, truncated ciphertext,
                // or wrong passphrase-derived key) — not a "this entry
                // doesn't match"; treating it as the latter would
                // permit a corrupted file to silently re-grow with
                // duplicate entries on every retry.
                let existing_bytes = self.decrypt_entry(&data, offset).map_err(|e| {
                    PlatformError::CustodyError(format!(
                        "import dedup scan: failed to decrypt the entry at position \
                         {index} — file may be corrupted: {e}"
                    ))
                })?;
                let existing = SigningKey::from_bytes(&existing_bytes);
                if existing.verifying_key().to_bytes() != target_pub {
                    continue;
                }

                // The seed is already in the store. Return the handle that
                // already names it when this instance holds one, and mint a
                // handle for it otherwise — another instance wrote the entry,
                // and appending a second copy of one private key is what this
                // scan exists to prevent.
                if let Some((id, _)) = map
                    .entries
                    .iter()
                    .find(|(_, (_, nonce))| *nonce == entry_nonce)
                {
                    return Ok(KeyHandle::new(*id));
                }
                let handle = self.next_handle();
                map.entries
                    .insert(handle.id(), (StoredKeyType::Ed25519, entry_nonce));
                drop(map);
                return Ok(handle);
            }
            drop(data);

            // Persist the seed bytes via the same encrypted append-only
            // log used by `generate_keypair`. After this call the bytes
            // are encrypted-at-rest under the same passphrase-derived key.
            // `append_entry` takes only `file_write_lock` — safe to call
            // while holding `handle_map`.
            let key_bytes = Zeroizing::new(**seed);
            let entry_nonce = self.append_entry(StoredKeyType::Ed25519, &key_bytes)?;

            let handle = self.next_handle();
            map.entries
                .insert(handle.id(), (StoredKeyType::Ed25519, entry_nonce));
            drop(map);

            Ok(handle)
        }
    }
}

impl CustodySubstrate for FileKeyCustody {
    /// Returns `true`: this backend writes each private key into a file the
    /// process can read, and every signing operation decrypts the key into
    /// process memory, so the key leaves the store.
    fn key_is_extractable(&self) -> bool {
        true
    }

    /// Returns [`UnlockFactor::Passphrase`]: Argon2id derives this backend's
    /// AES-256-GCM key from the passphrase the caller supplied to
    /// [`FileKeyCustody::new`], so a holder presents that passphrase to reach
    /// any key in the file.
    fn unlock_factor(&self) -> UnlockFactor {
        UnlockFactor::Passphrase
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    /// Helper: create a `FileKeyCustody` in a temporary directory.
    fn make_custody(dir: &TempDir, passphrase: &str) -> FileKeyCustody {
        let path = dir.path().join("keys.scp");
        FileKeyCustody::new(&path, passphrase).unwrap()
    }

    // --- Two instances over one key file ---
    //
    // `append_entry` and `destroy_key` each read the whole key file, change one
    // entry, and write the file back. `file_write_lock` is a `StdMutex` one
    // instance owns, so two instances over one path would both read the same
    // entry count, both write entry index N, and the second `atomic_write`
    // would discard the first instance's private key while both handle maps
    // kept naming index N. The four tests below pin the advisory exclusive lock
    // every read-modify-write runs under.

    /// Reads the entry count out of the key file's header.
    fn entry_count(path: &std::path::Path) -> u32 {
        let data = std::fs::read(path).unwrap();
        u32::from_le_bytes(data[1 + SALT_LEN..HEADER_SIZE].try_into().unwrap())
    }

    /// An append by one instance cannot start while another instance holds the
    /// key file's write lock, and it completes once that instance releases it.
    ///
    /// This is the deterministic proof of the exclusion. The two stress tests
    /// below depend on the operating system interleaving two threads, which no
    /// test controls; this one holds the lock itself and reads whether the
    /// append got past it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn an_append_waits_for_the_lock_another_instance_holds() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("keys.scp");

        let holder = FileKeyCustody::new(&path, "pw").unwrap();
        let appender = std::sync::Arc::new(FileKeyCustody::new(&path, "pw").unwrap());

        let guard = holder.lock_for_write().unwrap();

        let appending = {
            let appender = std::sync::Arc::clone(&appender);
            tokio::spawn(async move { appender.generate_keypair(KeyType::Ed25519).await })
        };

        // Long enough for the spawned task to reach `append_entry` and block on
        // the lock. Without the lock the append runs to completion in well
        // under a millisecond and this assertion fails.
        tokio::time::sleep(std::time::Duration::from_millis(400)).await;
        assert!(
            !appending.is_finished(),
            "an append must not complete while another instance holds the key file lock"
        );
        assert_eq!(
            entry_count(&path),
            0,
            "no entry may reach the file while another instance holds the lock"
        );

        drop(guard);

        let handle = tokio::time::timeout(std::time::Duration::from_secs(10), appending)
            .await
            .expect("the append must complete once the lock is released")
            .expect("the spawned task must not panic")
            .expect("the append must succeed");
        assert_eq!(
            entry_count(&path),
            1,
            "the released append must reach the file"
        );
        assert_eq!(
            appender.public_key(&handle).await.unwrap().as_bytes().len(),
            32
        );
    }

    /// Two instances that each append a key keep both keys, and each handle
    /// resolves to the key its own instance generated.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn two_instances_appending_to_one_key_file_keep_both_keys() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("keys.scp");

        let first = std::sync::Arc::new(FileKeyCustody::new(&path, "pw").unwrap());
        let second = std::sync::Arc::new(FileKeyCustody::new(&path, "pw").unwrap());

        let handle_a = {
            let first = std::sync::Arc::clone(&first);
            tokio::spawn(async move { first.generate_keypair(KeyType::Ed25519).await })
        };
        let handle_b = {
            let second = std::sync::Arc::clone(&second);
            tokio::spawn(async move { second.generate_keypair(KeyType::Ed25519).await })
        };
        let handle_a = handle_a.await.unwrap().unwrap();
        let handle_b = handle_b.await.unwrap().unwrap();

        assert_eq!(
            entry_count(&path),
            2,
            "each generate_keypair must add one entry, so neither write may \
             overwrite the other"
        );

        let key_a = first.public_key(&handle_a).await.unwrap();
        let key_b = second.public_key(&handle_b).await.unwrap();
        assert_ne!(
            key_a.as_bytes(),
            key_b.as_bytes(),
            "two instances must not resolve their handles to one key"
        );

        let signature = first.sign(&handle_a, b"payload").await.unwrap();
        let verifying_key =
            VerifyingKey::from_bytes(&key_a.as_bytes().try_into().unwrap()).unwrap();
        let parsed =
            ed25519_dalek::Signature::from_bytes(&signature.as_bytes().try_into().unwrap());
        assert!(
            ed25519_dalek::Verifier::verify(&verifying_key, b"payload", &parsed).is_ok(),
            "the first instance must still sign with the key its own handle names"
        );
    }

    /// Twelve rounds of two concurrent appends across two instances produce
    /// twenty-four entries and twenty-four distinct public keys.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_appends_across_two_instances_lose_no_key() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("keys.scp");

        let first = std::sync::Arc::new(FileKeyCustody::new(&path, "pw").unwrap());
        let second = std::sync::Arc::new(FileKeyCustody::new(&path, "pw").unwrap());

        let mut keys = std::collections::HashSet::new();
        for _ in 0..12 {
            let task_a = {
                let first = std::sync::Arc::clone(&first);
                tokio::spawn(async move { first.generate_keypair(KeyType::Ed25519).await })
            };
            let task_b = {
                let second = std::sync::Arc::clone(&second);
                tokio::spawn(async move { second.generate_keypair(KeyType::Ed25519).await })
            };
            let a = task_a.await.unwrap().unwrap();
            let b = task_b.await.unwrap().unwrap();
            keys.insert(first.public_key(&a).await.unwrap().as_bytes().to_vec());
            keys.insert(second.public_key(&b).await.unwrap().as_bytes().to_vec());
        }

        assert_eq!(entry_count(&path), 24, "every append must reach the file");
        assert_eq!(
            keys.len(),
            24,
            "every handle must resolve to the key its own instance generated"
        );
    }

    /// A second instance opens while a first one holds the same key file, so
    /// serializing the writes does not cost a process its second identity. The
    /// three FFI bridges open one `FileKeyCustody` per identity they create
    /// over one hardcoded path, so refusing the second open would refuse the
    /// second identity.
    #[tokio::test]
    async fn a_second_instance_opens_over_a_key_file_a_first_one_holds() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("keys.scp");

        let first = FileKeyCustody::new(&path, "pw").unwrap();
        let handle_a = first.generate_keypair(KeyType::Ed25519).await.unwrap();

        let second = FileKeyCustody::new(&path, "pw")
            .expect("a second instance must open over a key file a first one holds");
        let handle_b = second.generate_keypair(KeyType::Ed25519).await.unwrap();

        assert_ne!(
            first.public_key(&handle_a).await.unwrap().as_bytes(),
            second.public_key(&handle_b).await.unwrap().as_bytes(),
            "the two instances must hold two distinct keys"
        );
    }

    /// Constructing a `FileKeyCustody` over a path holding no key file waits
    /// for the key file's write lock, and writes the header only after it has
    /// the lock.
    ///
    /// `create_new` writes a header carrying a fresh salt. Two constructions
    /// that each tested for the file before either wrote one would each write a
    /// salt, and the second `atomic_write` would replace the first's. The first
    /// instance keeps the AES key it derived from its own salt and appends
    /// entries encrypted under that key into a file whose header names the
    /// other salt, so a later open derives one key and meets entries written
    /// under two. Two concurrent `identity_create("encrypted_file")` calls on a
    /// machine whose `$HOME/.scp/keys.bin` does not exist yet reach exactly
    /// that pair.
    ///
    /// The test holds the lock itself rather than racing two constructions,
    /// because no test controls whether the operating system interleaves two
    /// threads inside the window between the existence test and the write.
    #[test]
    fn constructing_over_an_absent_key_file_waits_for_the_lock() {
        use std::sync::mpsc;
        use std::time::Duration;

        let dir = TempDir::new().unwrap();
        let path = dir.path().join("keys.scp");

        // Take the lock through the same sidecar path `open_lock_file` opens,
        // without constructing an instance — constructing one is the operation
        // under test.
        let holder = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(dir.path().join("keys.scp.lock"))
            .unwrap();
        FileExt::lock_exclusive(&holder).unwrap();

        let (finished_tx, finished_rx) = mpsc::channel();
        let construction_path = path.clone();
        let constructing = std::thread::spawn(move || {
            let custody = FileKeyCustody::new(&construction_path, "pw");
            finished_tx.send(()).unwrap();
            custody
        });

        // Long enough for the spawned thread to reach the lock. Without the
        // lock the construction finishes in well under a millisecond, the
        // channel carries its message, and this assertion fails.
        // `Timeout`, not `is_err()`: a construction thread that panicked would
        // drop the sender and answer `Disconnected`, which would let this
        // assertion pass while proving nothing about the lock.
        assert_eq!(
            finished_rx.recv_timeout(Duration::from_millis(400)),
            Err(mpsc::RecvTimeoutError::Timeout),
            "a construction must not finish while another holder has the key file lock"
        );
        assert!(
            !path.exists(),
            "no key file header may reach the disk while another holder has the lock"
        );

        FileExt::unlock(&holder).unwrap();

        finished_rx
            .recv_timeout(Duration::from_secs(10))
            .expect("the construction must finish once the lock is released");
        constructing
            .join()
            .expect("the construction thread must not panic")
            .expect("the construction must succeed");
        assert!(
            path.exists(),
            "the released construction must write the header"
        );
    }

    /// Two instances constructed over one path share the salt the first one
    /// wrote, so every key either instance appends decrypts after a reopen.
    ///
    /// A second `create_new` would write a second salt, and the entries the
    /// first instance appended under the first salt would then decrypt to
    /// garbage.
    #[tokio::test]
    async fn two_constructions_over_one_path_share_one_salt() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("keys.scp");

        let first = FileKeyCustody::new(&path, "pw").unwrap();
        let second = FileKeyCustody::new(&path, "pw").unwrap();

        let handle_a = first.generate_keypair(KeyType::Ed25519).await.unwrap();
        let handle_b = second.generate_keypair(KeyType::Ed25519).await.unwrap();
        let key_a = first
            .public_key(&handle_a)
            .await
            .unwrap()
            .as_bytes()
            .to_vec();
        let key_b = second
            .public_key(&handle_b)
            .await
            .unwrap()
            .as_bytes()
            .to_vec();

        drop(first);
        drop(second);

        let reopened = FileKeyCustody::new(&path, "pw").unwrap();
        assert_eq!(entry_count(&path), 2, "both appends must survive");
        let recovered_a = reopened
            .public_key(&KeyHandle::new(1))
            .await
            .expect("the first instance's entry must decrypt under the file's salt");
        let recovered_b = reopened
            .public_key(&KeyHandle::new(2))
            .await
            .expect("the second instance's entry must decrypt under the file's salt");
        assert_eq!(recovered_a.as_bytes(), key_a.as_slice());
        assert_eq!(recovered_b.as_bytes(), key_b.as_slice());
    }

    #[tokio::test]
    async fn generate_ed25519_and_sign_verify() {
        let dir = TempDir::new().unwrap();
        let custody = make_custody(&dir, "test-passphrase");

        let handle = custody.generate_keypair(KeyType::Ed25519).await.unwrap();
        let data = b"hello world";
        let sig = custody.sign(&handle, data).await.unwrap();
        assert_eq!(sig.as_bytes().len(), 64);

        // Verify the signature using the public key.
        let pubkey = custody.public_key(&handle).await.unwrap();
        let pk_bytes: [u8; 32] = pubkey.as_bytes().try_into().unwrap();
        let verifying_key = VerifyingKey::from_bytes(&pk_bytes).unwrap();
        let sig_bytes: [u8; 64] = sig.as_bytes().try_into().unwrap();
        let signature = ed25519_dalek::Signature::from_bytes(&sig_bytes);
        assert!(
            ed25519_dalek::Verifier::verify(&verifying_key, data, &signature).is_ok(),
            "signature must verify"
        );
    }

    #[tokio::test]
    async fn generate_x25519_and_dh_agree() {
        let dir = TempDir::new().unwrap();
        let custody = make_custody(&dir, "pw");

        let alice = custody.generate_keypair(KeyType::X25519).await.unwrap();
        let bob = custody.generate_keypair(KeyType::X25519).await.unwrap();

        let alice_pub = custody.public_key(&alice).await.unwrap();
        let bob_pub = custody.public_key(&bob).await.unwrap();

        let a_bytes: [u8; 32] = alice_pub.as_bytes().try_into().unwrap();
        let b_bytes: [u8; 32] = bob_pub.as_bytes().try_into().unwrap();

        let secret_ab = custody.dh_agree(&alice, &b_bytes).await.unwrap();
        let secret_ba = custody.dh_agree(&bob, &a_bytes).await.unwrap();

        assert_eq!(secret_ab.as_bytes(), secret_ba.as_bytes());
    }

    #[tokio::test]
    async fn reopen_with_same_passphrase_succeeds() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("keys.scp");
        let passphrase = "correct-horse-battery-staple";

        // Create and generate a key.
        let custody = FileKeyCustody::new(&path, passphrase).unwrap();
        let handle = custody.generate_keypair(KeyType::Ed25519).await.unwrap();
        let pubkey = custody.public_key(&handle).await.unwrap();
        let sig = custody.sign(&handle, b"test data").await.unwrap();
        drop(custody);

        // Reopen with the same passphrase.
        let custody2 = FileKeyCustody::new(&path, passphrase).unwrap();
        // The handle IDs are reassigned on load; the first key gets handle 1.
        let handle2 = KeyHandle::new(1);
        let pubkey2 = custody2.public_key(&handle2).await.unwrap();
        assert_eq!(
            pubkey.as_bytes(),
            pubkey2.as_bytes(),
            "public key must be the same after reopening"
        );

        // Sign with the reopened custody and verify.
        let sig2 = custody2.sign(&handle2, b"test data").await.unwrap();
        assert_eq!(
            sig.as_bytes(),
            sig2.as_bytes(),
            "deterministic signing must produce same signature"
        );
    }

    #[tokio::test]
    async fn reopen_with_wrong_passphrase_fails() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("keys.scp");

        // Create and generate a key.
        let custody = FileKeyCustody::new(&path, "correct").unwrap();
        custody.generate_keypair(KeyType::Ed25519).await.unwrap();
        drop(custody);

        // Reopen with the wrong passphrase — file opens but operations fail.
        let custody2 = FileKeyCustody::new(&path, "wrong").unwrap();
        let handle = KeyHandle::new(1);
        let result = custody2.sign(&handle, b"data").await;
        assert!(
            result.is_err(),
            "wrong passphrase must cause decryption failure"
        );
        match result.unwrap_err() {
            PlatformError::CustodyError(msg) => {
                assert!(
                    msg.contains("decryption failed"),
                    "error must mention decryption: {msg}"
                );
            }
            other => panic!("expected CustodyError, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn key_file_does_not_contain_raw_private_key() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("keys.scp");
        let custody = FileKeyCustody::new(&path, "passphrase").unwrap();

        let handle = custody.generate_keypair(KeyType::Ed25519).await.unwrap();

        // Get the public key to derive what the private key bytes look like.
        // We cannot directly access the private key, but we can verify the
        // file does not contain ANY 32-byte window that, when interpreted as
        // an Ed25519 signing key, produces the same public key.
        let pubkey = custody.public_key(&handle).await.unwrap();
        let file_data = std::fs::read(&path).unwrap();

        // Scan the file for any 32-byte window that produces the public key.
        let pub_bytes = pubkey.as_bytes();
        let mut found_raw_key = false;
        for window in file_data.windows(32) {
            let candidate = SigningKey::from_bytes(window.try_into().unwrap_or(&[0u8; 32]));
            if candidate.verifying_key().to_bytes() == <[u8; 32]>::try_from(pub_bytes).unwrap() {
                found_raw_key = true;
                break;
            }
        }
        assert!(
            !found_raw_key,
            "key file must not contain the raw private key bytes"
        );
    }

    #[tokio::test]
    async fn destroy_key_makes_operations_fail() {
        let dir = TempDir::new().unwrap();
        let custody = make_custody(&dir, "pw");
        let handle = custody.generate_keypair(KeyType::Ed25519).await.unwrap();

        custody.sign(&handle, b"test").await.unwrap();
        custody.destroy_key(&handle).await.unwrap();

        assert!(custody.sign(&handle, b"test").await.is_err());
        assert!(custody.public_key(&handle).await.is_err());
        assert!(custody.destroy_key(&handle).await.is_err());
    }

    /// `destroy_key` MUST refuse to rewrite the file when the handle map names
    /// a nonce no entry in the file carries.
    ///
    /// A handle reaches that state when another `FileKeyCustody` over the same
    /// path already destroyed the key it named, so `destroy_key` reports
    /// key-not-found and writes nothing. Rewriting the file with one entry
    /// dropped at a guessed position would emit a header count smaller than the
    /// entry payload and corrupt the store. The handle map must survive the
    /// error so the failed call does not orphan material.
    #[tokio::test]
    async fn destroy_key_rejects_a_nonce_the_file_does_not_carry() {
        let dir = TempDir::new().unwrap();
        let custody = make_custody(&dir, "out-of-bounds-passphrase");

        // Populate two real entries so the file is non-empty and the missing
        // nonce is the only thing that can fail.
        let real_a = custody.generate_keypair(KeyType::Ed25519).await.unwrap();
        let real_b = custody.generate_keypair(KeyType::Ed25519).await.unwrap();

        // Inject a desynchronized entry: a handle whose nonce no entry in the
        // file carries.
        let desync_id = custody.next_handle().id();
        {
            let mut map = custody.handle_map.lock().await;
            map.entries
                .insert(desync_id, (StoredKeyType::Ed25519, [0xAB; NONCE_LEN]));
        }
        let desync_handle = KeyHandle::new(desync_id);

        let err = custody
            .destroy_key(&desync_handle)
            .await
            .expect_err("destroy_key MUST refuse a nonce the file does not carry");
        assert!(
            matches!(err, PlatformError::KeyNotFound),
            "expected KeyNotFound, got: {err:?}"
        );

        // The real entries MUST still be usable — the failed call must
        // not have corrupted the on-disk file or shifted any indices.
        custody
            .public_key(&real_a)
            .await
            .expect("real_a must still decrypt after failed destroy");
        custody
            .public_key(&real_b)
            .await
            .expect("real_b must still decrypt after failed destroy");

        // And the desynchronized map entry must still be present
        // (destroy_key returned Err before any map mutation).
        let preserved = {
            let map = custody.handle_map.lock().await;
            map.entries.contains_key(&desync_id)
        };
        assert!(
            preserved,
            "handle map MUST be preserved when destroy_key fails"
        );
    }

    #[tokio::test]
    async fn sign_with_x25519_key_fails() {
        let dir = TempDir::new().unwrap();
        let custody = make_custody(&dir, "pw");
        let handle = custody.generate_keypair(KeyType::X25519).await.unwrap();

        let result = custody.sign(&handle, b"data").await;
        assert!(result.is_err());
        match result.unwrap_err() {
            PlatformError::WrongKeyType { expected, actual } => {
                assert_eq!(expected, KeyType::Ed25519);
                assert_eq!(actual, KeyType::X25519);
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[tokio::test]
    async fn dh_agree_with_ed25519_key_fails() {
        let dir = TempDir::new().unwrap();
        let custody = make_custody(&dir, "pw");
        let handle = custody.generate_keypair(KeyType::Ed25519).await.unwrap();

        let result = custody.dh_agree(&handle, &[0u8; 32]).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            PlatformError::WrongKeyType { expected, actual } => {
                assert_eq!(expected, KeyType::X25519);
                assert_eq!(actual, KeyType::Ed25519);
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[tokio::test]
    async fn custody_type_returns_software() {
        let dir = TempDir::new().unwrap();
        let custody = make_custody(&dir, "pw");
        let handle = custody.generate_keypair(KeyType::Ed25519).await.unwrap();
        assert_eq!(custody.custody_type(&handle), CustodyType::Software);
    }

    #[test]
    fn substrate_reports_an_extractable_key_a_passphrase_unlocks() {
        let dir = TempDir::new().unwrap();
        let custody = make_custody(&dir, "pw");

        assert!(custody.key_is_extractable());
        assert_eq!(custody.unlock_factor(), UnlockFactor::Passphrase);
    }

    /// A participant running an encrypted key file publishes the extractable
    /// value, so that participant cannot publish a non-extractable claim.
    #[test]
    fn derived_published_custody_is_extractable_passphrase() {
        use scp_did::attestation::{KeyCustodyModel, Platform, ScpKeyCustodyAttestation};

        let dir = TempDir::new().unwrap();
        let custody = make_custody(&dir, "pw");

        assert_eq!(
            KeyCustodyModel::from_substrate(&custody).unwrap(),
            KeyCustodyModel::ExtractablePassphrase
        );

        let attestation = ScpKeyCustodyAttestation::derive(
            &custody,
            None,
            Platform::Desktop,
            None,
            1_700_000_000,
        )
        .unwrap();

        assert_eq!(
            attestation.active_key_custody(),
            KeyCustodyModel::ExtractablePassphrase
        );
    }

    #[tokio::test]
    async fn derive_pseudonym_is_deterministic() {
        let dir = TempDir::new().unwrap();
        let custody = make_custody(&dir, "pw");
        let handle = custody.generate_keypair(KeyType::Ed25519).await.unwrap();

        let first = custody.derive_pseudonym(&handle, b"ctx").await.unwrap();
        let second = custody.derive_pseudonym(&handle, b"ctx").await.unwrap();

        assert_eq!(first.public_key.as_bytes(), second.public_key.as_bytes());
    }

    #[tokio::test]
    async fn derive_pseudonym_key_can_sign() {
        let dir = TempDir::new().unwrap();
        let custody = make_custody(&dir, "pw");
        let handle = custody.generate_keypair(KeyType::Ed25519).await.unwrap();

        let pseudo = custody.derive_pseudonym(&handle, b"ctx").await.unwrap();
        let sig = custody.sign(&pseudo.key_handle, b"msg").await.unwrap();
        assert_eq!(sig.as_bytes().len(), 64);

        // Verify.
        let pk_bytes: [u8; 32] = pseudo.public_key.as_bytes().try_into().unwrap();
        let vk = VerifyingKey::from_bytes(&pk_bytes).unwrap();
        let sig_bytes: [u8; 64] = sig.as_bytes().try_into().unwrap();
        let signature = ed25519_dalek::Signature::from_bytes(&sig_bytes);
        assert!(ed25519_dalek::Verifier::verify(&vk, b"msg", &signature).is_ok());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn key_file_has_restrictive_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("keys.scp");
        let _custody = FileKeyCustody::new(&path, "test-perms").unwrap();
        let metadata = std::fs::metadata(&path).unwrap();
        let mode = metadata.permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "key file should be owner-only (0600), got: {mode:o}"
        );
    }

    #[tokio::test]
    async fn atomic_write_ignores_stale_fixed_temp_and_leaves_no_residue() {
        // A pre-planted file at the OLD predictable temp path (`keys.scp.tmp`)
        // must not block writes — the temp name is now randomized — and our
        // randomized temp must be renamed away, leaving no `*.tmp` residue.
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("keys.scp");
        std::fs::write(dir.path().join("keys.scp.tmp"), b"stale").unwrap();

        let custody = FileKeyCustody::new(&path, "pw").unwrap();
        let handle = custody.generate_keypair(KeyType::Ed25519).await.unwrap();
        let pubkey = custody.public_key(&handle).await.unwrap();
        assert_eq!(pubkey.as_bytes().len(), 32);

        // Only the stale fixed-name temp remains; no randomized residue.
        let residue: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.starts_with("keys.scp.") && n.contains(".tmp"))
            .collect();
        assert_eq!(
            residue,
            vec!["keys.scp.tmp".to_owned()],
            "randomized temp must be renamed away, leaving no residue"
        );
    }

    #[tokio::test]
    async fn multiple_keys_roundtrip() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("keys.scp");
        let passphrase = "multi-key";

        let custody = FileKeyCustody::new(&path, passphrase).unwrap();

        let h1 = custody.generate_keypair(KeyType::Ed25519).await.unwrap();
        let h2 = custody.generate_keypair(KeyType::X25519).await.unwrap();
        let h3 = custody.generate_keypair(KeyType::Ed25519).await.unwrap();

        let pk1 = custody.public_key(&h1).await.unwrap();
        let pk2 = custody.public_key(&h2).await.unwrap();
        let pk3 = custody.public_key(&h3).await.unwrap();

        drop(custody);

        // Reopen and verify all keys.
        let custody2 = FileKeyCustody::new(&path, passphrase).unwrap();
        let rh1 = KeyHandle::new(1);
        let rh2 = KeyHandle::new(2);
        let rh3 = KeyHandle::new(3);

        assert_eq!(
            custody2.public_key(&rh1).await.unwrap().as_bytes(),
            pk1.as_bytes()
        );
        assert_eq!(
            custody2.public_key(&rh2).await.unwrap().as_bytes(),
            pk2.as_bytes()
        );
        assert_eq!(
            custody2.public_key(&rh3).await.unwrap().as_bytes(),
            pk3.as_bytes()
        );
    }

    /// Importing the same Ed25519 seed twice must return the existing
    /// handle rather than appending a duplicate encrypted entry. Without
    /// this guard a retry of import would create an orphan entry that
    /// the registry can no longer reach but reload would resurrect as a
    /// phantom handle.
    #[tokio::test]
    async fn import_ed25519_signing_key_dedups_by_content() {
        let dir = TempDir::new().unwrap();
        let custody = make_custody(&dir, "dedup-passphrase");

        let seed = Zeroizing::new([0x42u8; 32]);

        let first = custody.import_ed25519_signing_key(&seed).await.unwrap();
        let second = custody.import_ed25519_signing_key(&seed).await.unwrap();

        // Same content -> same handle.
        assert_eq!(
            first.id(),
            second.id(),
            "second import of identical seed must return the existing handle"
        );

        // Handle map must hold exactly one entry for this seed.
        let map = custody.handle_map.lock().await;
        assert_eq!(
            map.entries.len(),
            1,
            "duplicate import must not add a new handle map entry"
        );
        drop(map);

        // The encrypted file must contain exactly one entry — the
        // header records `entry_count` at offset `1 + SALT_LEN`.
        let bytes = std::fs::read(&custody.path).unwrap();
        let count_offset = 1 + SALT_LEN;
        let count = u32::from_le_bytes(bytes[count_offset..count_offset + 4].try_into().unwrap());
        assert_eq!(count, 1, "duplicate import must not append a file entry");

        // Sanity: the public key must match what the seed derives to.
        let derived = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
        let pk = custody.public_key(&first).await.unwrap();
        assert_eq!(pk.as_bytes(), &derived);
    }

    /// Importing a *different* Ed25519 seed after the first one must
    /// allocate a fresh handle and append a new entry — dedup is
    /// content-keyed, not blanket suppression.
    #[tokio::test]
    async fn import_ed25519_signing_key_distinct_seeds_allocate_distinct_handles() {
        let dir = TempDir::new().unwrap();
        let custody = make_custody(&dir, "distinct-passphrase");

        let seed_a = Zeroizing::new([0x11u8; 32]);
        let seed_b = Zeroizing::new([0x22u8; 32]);

        let h_a = custody.import_ed25519_signing_key(&seed_a).await.unwrap();
        let h_b = custody.import_ed25519_signing_key(&seed_b).await.unwrap();

        assert_ne!(
            h_a.id(),
            h_b.id(),
            "distinct seeds must produce distinct handles"
        );

        let map = custody.handle_map.lock().await;
        assert_eq!(
            map.entries.len(),
            2,
            "distinct seeds must produce two handle map entries"
        );
        drop(map);
    }

    /// Two concurrent imports of the same seed must dedup correctly:
    /// both calls return the same handle and the handle map ends up
    /// with exactly one entry. Without holding `handle_map` across the
    /// scan-and-insert path, both tasks could observe a non-matching
    /// snapshot and both append, yielding two parallel encrypted
    /// entries pointing at the same private key.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn import_ed25519_signing_key_concurrent_dedups_correctly() {
        use std::sync::Arc;

        let dir = TempDir::new().unwrap();
        let custody = Arc::new(make_custody(&dir, "concurrent-dedup-passphrase"));

        // A fixed all-zero seed is used purely to deterministically
        // exercise the concurrent same-content code path of
        // `import_ed25519_signing_key`'s dedup logic — two tasks
        // import IDENTICAL bytes simultaneously and must collapse to
        // a single content-keyed entry. This test does NOT mirror
        // `migrate_identity`'s probe behaviour: that probe draws
        // OS-CSPRNG bytes precisely so it cannot alias any
        // pre-existing entry. The fixed seed here is a test
        // affordance, not a representation of any production caller.
        let seed = Zeroizing::new([0u8; 32]);

        let custody_a = Arc::clone(&custody);
        let seed_a = seed.clone();
        let task_a =
            tokio::spawn(
                async move { custody_a.import_ed25519_signing_key(&seed_a).await.unwrap() },
            );

        let custody_b = Arc::clone(&custody);
        let seed_b = seed.clone();
        let task_b =
            tokio::spawn(
                async move { custody_b.import_ed25519_signing_key(&seed_b).await.unwrap() },
            );

        let h_a = task_a.await.unwrap();
        let h_b = task_b.await.unwrap();

        assert_eq!(
            h_a.id(),
            h_b.id(),
            "concurrent imports of the same seed must return the same handle"
        );

        let map = custody.handle_map.lock().await;
        assert_eq!(
            map.entries.len(),
            1,
            "concurrent dedup must not produce parallel handle map entries"
        );
        drop(map);

        // File-level check: exactly one entry persisted.
        let bytes = std::fs::read(&custody.path).unwrap();
        let count_offset = 1 + SALT_LEN;
        let count = u32::from_le_bytes(bytes[count_offset..count_offset + 4].try_into().unwrap());
        assert_eq!(
            count, 1,
            "concurrent dedup must not append a parallel encrypted entry"
        );
    }

    /// Concurrent `generate_keypair` ↔ `destroy_key` MUST NOT corrupt
    /// the handle map. The test pre-creates a victim key, then races a
    /// `generate_keypair` against `destroy_key` on the victim and asserts that
    /// whatever handle came back from `generate_keypair` decrypts cleanly, so
    /// the nonce it recorded still names its own ciphertext in the file.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn generate_keypair_concurrent_destroy_does_not_corrupt_handle_map() {
        use std::sync::Arc;

        let dir = TempDir::new().unwrap();
        let custody = Arc::new(make_custody(&dir, "concurrent-gen-destroy-passphrase"));

        // Pre-populate the file with enough entries that the victim
        // we destroy isn't always the trailing entry. The bug pattern
        // (index shift after destroy) only manifests when there are
        // entries *after* the destroyed one.
        let mut handles: Vec<KeyHandle> = Vec::new();
        for _ in 0..4 {
            handles.push(custody.generate_keypair(KeyType::Ed25519).await.unwrap());
        }
        // Destroy the middle entry — index shift is most visible here.
        let victim = handles.remove(1);

        let custody_gen = Arc::clone(&custody);
        let task_gen = tokio::spawn(async move {
            custody_gen
                .generate_keypair(KeyType::Ed25519)
                .await
                .unwrap()
        });

        let custody_destroy = Arc::clone(&custody);
        let task_destroy = tokio::spawn(async move {
            custody_destroy.destroy_key(&victim).await.unwrap();
        });

        let new_handle = task_gen.await.unwrap();
        task_destroy.await.unwrap();

        // The new handle MUST decrypt cleanly. A handle naming a position
        // rather than a nonce would name a neighbour's ciphertext after
        // `destroy_key` compacted the file.
        let _public = custody
            .public_key(&new_handle)
            .await
            .expect("new handle must decrypt cleanly after concurrent destroy");
        // And `sign` MUST succeed — confirms the recovered key
        // material is a valid Ed25519 signing key.
        let _sig = custody
            .sign(&new_handle, b"concurrent-test")
            .await
            .expect("new handle must sign after concurrent destroy");

        // All other pre-existing handles MUST still decrypt cleanly. Each one
        // names its entry by a nonce, and the destroy that compacted the file
        // moved positions without touching a nonce.
        for h in &handles {
            let _ = custody
                .public_key(h)
                .await
                .expect("pre-existing handles must decrypt after concurrent generate/destroy");
        }

        // Handle map invariant: every nonce the map holds names an entry the
        // file carries, and the destroyed victim's nonce is gone from both.
        let map = custody.handle_map.lock().await;
        let bytes = std::fs::read(&custody.path).unwrap();
        for (id, (_kt, nonce)) in &map.entries {
            FileKeyCustody::locate_entry(&bytes, nonce)
                .unwrap_or_else(|e| panic!("handle {id} names a nonce the file lost: {e:?}"));
        }
    }

    // --- Entry identity (§17.8 of the persistence spec) ---

    /// Reads the entry nonce this instance's map records for `handle`.
    async fn recorded_nonce(custody: &FileKeyCustody, handle: &KeyHandle) -> [u8; NONCE_LEN] {
        let map = custody.handle_map.lock().await;
        map.entries.get(&handle.id()).copied().unwrap().1
    }

    /// A second `FileKeyCustody` over one key file keeps signing with its own
    /// key after the first instance destroys a key that sits before it.
    ///
    /// This is the case the advisory write lock cannot order away, because the
    /// two writes are already ordered. Addressing an entry by position made the
    /// second instance's handle name its neighbour's ciphertext, which decrypts
    /// under the same passphrase-derived AES key, so AES-256-GCM authenticated
    /// it and `sign` returned a valid signature under a key the handle does not
    /// name. §17.8 of the persistence spec makes the nonce the entry's name for
    /// exactly this reason.
    #[tokio::test]
    async fn a_second_instance_keeps_its_own_key_after_the_first_compacts_the_file() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("keys.scp");

        let first = FileKeyCustody::new(&path, "shared-passphrase").unwrap();
        let doomed = first.generate_keypair(KeyType::Ed25519).await.unwrap();
        let survivor_of_first = first.generate_keypair(KeyType::Ed25519).await.unwrap();

        // A second instance opens the same file and appends two more keys, the
        // arrangement every `identity_create("encrypted_file")` call produces.
        let second = FileKeyCustody::new(&path, "shared-passphrase").unwrap();
        let second_agent = second.generate_keypair(KeyType::Ed25519).await.unwrap();
        let second_active = second.generate_keypair(KeyType::Ed25519).await.unwrap();

        let agent_public = second.public_key(&second_agent).await.unwrap();
        let active_public = second.public_key(&second_active).await.unwrap();

        let agent_nonce = recorded_nonce(&second, &second_agent).await;
        let position_before = {
            let data = std::fs::read(&path).unwrap();
            FileKeyCustody::locate_entry(&data, &agent_nonce).unwrap().0
        };

        // The first instance destroys its earliest entry, which compacts the
        // file and moves every later entry down one position.
        first.destroy_key(&doomed).await.unwrap();

        // The destroy has to move the second instance's entry, or the
        // assertions below hold whether or not a handle names a position.
        let position_after = {
            let data = std::fs::read(&path).unwrap();
            FileKeyCustody::locate_entry(&data, &agent_nonce).unwrap().0
        };
        assert_eq!(
            position_after + ENTRY_SIZE,
            position_before,
            "the destroy must move the second instance's entry down one position, \
             or this test exercises no shift"
        );

        // The second instance's two handles still name their own keys.
        assert_eq!(
            second.public_key(&second_agent).await.unwrap().as_bytes(),
            agent_public.as_bytes(),
            "the second instance's #agent handle must still name its own key"
        );
        assert_eq!(
            second.public_key(&second_active).await.unwrap().as_bytes(),
            active_public.as_bytes(),
            "the second instance's #active handle must still name its own key"
        );

        // And the signature it produces verifies under that same key.
        let signature = second.sign(&second_active, b"payload").await.unwrap();
        let verifying =
            VerifyingKey::from_bytes(&<[u8; 32]>::try_from(active_public.as_bytes()).unwrap())
                .unwrap();
        verifying
            .verify_strict(
                b"payload",
                &ed25519_dalek::Signature::from_slice(signature.as_bytes()).unwrap(),
            )
            .expect("the signature must verify under the key the handle names");

        // The first instance's surviving handle also still names its own key.
        first
            .public_key(&survivor_of_first)
            .await
            .expect("the compacting instance keeps its own surviving handle");
    }

    /// A handle whose key another instance destroyed reports key-not-found
    /// rather than a neighbour's key.
    #[tokio::test]
    async fn a_handle_whose_entry_another_instance_destroyed_reports_key_not_found() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("keys.scp");

        let first = FileKeyCustody::new(&path, "shared-passphrase").unwrap();
        let shared = first.generate_keypair(KeyType::Ed25519).await.unwrap();
        // A trailing entry so the file still holds something after the destroy.
        let _other = first.generate_keypair(KeyType::Ed25519).await.unwrap();

        // A second instance opens the file and inherits a handle for each
        // entry, in file order, so handle 1 names the entry the first instance
        // is about to destroy.
        let second = FileKeyCustody::new(&path, "shared-passphrase").unwrap();
        let inherited = KeyHandle::new(1);
        second
            .public_key(&inherited)
            .await
            .expect("the inherited handle must decrypt before the destroy");

        first.destroy_key(&shared).await.unwrap();

        let err = second
            .sign(&inherited, b"payload")
            .await
            .expect_err("a destroyed key must not yield a signature");
        assert!(
            matches!(err, PlatformError::KeyNotFound),
            "expected KeyNotFound, got: {err:?}"
        );
    }

    /// An operation reads the key type off the entry it located, so a handle
    /// map that records Ed25519 for an entry the file marks X25519 draws
    /// `WrongKeyType` rather than feeding an X25519 secret to
    /// `SigningKey::from_bytes` as an Ed25519 seed.
    #[tokio::test]
    async fn signing_refuses_an_entry_the_file_marks_x25519() {
        let dir = TempDir::new().unwrap();
        let custody = make_custody(&dir, "type-check-passphrase");

        let x_handle = custody.generate_keypair(KeyType::X25519).await.unwrap();
        let x_nonce = recorded_nonce(&custody, &x_handle).await;

        // A handle whose map record claims Ed25519 while the file's own byte
        // says X25519 — the shape a stale map record produces.
        let mislabelled = custody.next_handle();
        {
            let mut map = custody.handle_map.lock().await;
            map.entries
                .insert(mislabelled.id(), (StoredKeyType::Ed25519, x_nonce));
        }

        let err = custody
            .sign(&mislabelled, b"payload")
            .await
            .expect_err("signing must refuse an entry the file marks X25519");
        match err {
            PlatformError::WrongKeyType { expected, actual } => {
                assert_eq!(expected, KeyType::Ed25519);
                assert_eq!(actual, KeyType::X25519);
            }
            other => panic!("expected WrongKeyType, got: {other:?}"),
        }
    }

    /// Opening a key file that carries one nonce on two entries fails at the
    /// open, which is what §17.8 of the persistence spec requires: a handle
    /// names an entry by its nonce, so two entries under one nonce leave that
    /// name pointing at two keys.
    #[tokio::test]
    async fn opening_a_file_with_a_duplicated_nonce_fails() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("keys.scp");

        let custody = FileKeyCustody::new(&path, "duplicate-nonce-passphrase").unwrap();
        custody.generate_keypair(KeyType::Ed25519).await.unwrap();
        drop(custody);

        // Duplicate the single entry, so both copies carry one nonce.
        let mut data = std::fs::read(&path).unwrap();
        let entry = data[HEADER_SIZE..HEADER_SIZE + ENTRY_SIZE].to_vec();
        data.extend_from_slice(&entry);
        let count_offset = 1 + SALT_LEN;
        data[count_offset..count_offset + 4].copy_from_slice(&2u32.to_le_bytes());
        std::fs::write(&path, &data).unwrap();

        let err = FileKeyCustody::new(&path, "duplicate-nonce-passphrase")
            .map(|_| ())
            .expect_err("a file carrying one nonce twice must not open");
        match err {
            PlatformError::CustodyError(msg) => {
                assert!(
                    msg.contains("one AES-256-GCM nonce on two entries"),
                    "the error must name the duplicated nonce, got: {msg}"
                );
            }
            other => panic!("expected CustodyError, got: {other:?}"),
        }
    }

    /// A header stating more entries than the file holds fails at the open
    /// rather than at the first slice, so no read past the end of the file
    /// panics across the `PyO3`, napi, or `UniFFI` boundary.
    #[test]
    fn a_header_counting_more_entries_than_the_file_holds_fails_to_open() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("keys.scp");

        let custody = FileKeyCustody::new(&path, "truncated-passphrase").unwrap();
        drop(custody);

        let mut data = std::fs::read(&path).unwrap();
        let count_offset = 1 + SALT_LEN;
        data[count_offset..count_offset + 4].copy_from_slice(&3u32.to_le_bytes());
        std::fs::write(&path, &data).unwrap();

        let err = FileKeyCustody::new(&path, "truncated-passphrase")
            .map(|_| ())
            .expect_err("a header counting entries the file lacks must not open");
        match err {
            PlatformError::CustodyError(msg) => {
                assert!(
                    msg.contains("truncated"),
                    "the error must name the truncation, got: {msg}"
                );
            }
            other => panic!("expected CustodyError, got: {other:?}"),
        }
    }

    /// `import_ed25519_signing_key` returns a handle for a seed another
    /// instance already wrote, rather than appending a second copy of one
    /// private key.
    #[tokio::test]
    async fn importing_a_seed_another_instance_wrote_appends_no_second_copy() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("keys.scp");

        let first = FileKeyCustody::new(&path, "import-dedup-passphrase").unwrap();
        let second = FileKeyCustody::new(&path, "import-dedup-passphrase").unwrap();

        let seed = Zeroizing::new([7u8; 32]);
        let first_handle = first.import_ed25519_signing_key(&seed).await.unwrap();
        let second_handle = second.import_ed25519_signing_key(&seed).await.unwrap();

        let data = std::fs::read(&path).unwrap();
        assert_eq!(
            FileKeyCustody::entry_count(&data).unwrap(),
            1,
            "the second import must not append a second copy of one private key"
        );

        let expected = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
        assert_eq!(
            first.public_key(&first_handle).await.unwrap().as_bytes(),
            expected.as_slice()
        );
        assert_eq!(
            second.public_key(&second_handle).await.unwrap().as_bytes(),
            expected.as_slice()
        );
    }
}
