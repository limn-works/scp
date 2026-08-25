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
//! │ version: u8          (1 byte, currently 0x02)  │
//! │ argon2id_salt: [u8]  (16 bytes)                │
//! │ commitment: [u8]     (32 bytes, HMAC-SHA-256)  │
//! │ file_hmac: [u8]      (32 bytes, HMAC-SHA-256)  │
//! ├────────────────────────────────────────────────┤
//! │ entry_count: u32 LE  (4 bytes)                 │
//! ├────────────────────────────────────────────────┤
//! │ Entry 0:                                       │
//! │   key_type: u8       (0x01 = Ed25519,          │
//! │                       0x02 = X25519)           │
//! │   entry_id: [u8]     (16 bytes, random)        │
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
//! # Per-entry binding
//!
//! Each entry carries a 16-byte `entry_id` that `FileKeyCustody::append_entry`
//! draws from the operating system's CSPRNG and that no later write changes. A
//! handle map records that identifier, `FileKeyCustody::decrypt_entry` finds an
//! entry by comparing identifiers rather than by indexing on a position, and
//! `FileKeyCustody::encrypt_key` passes `key_type ‖ entry_id` as AES-256-GCM
//! associated data. `decrypt_entry` also compares the stored `key_type` byte
//! against the key type its caller's handle names before it decrypts anything.
//! §17.8 of `.docs/specs/17-persistence-and-storage.md`, under "Per-entry
//! binding", requires all of that.
//!
//! A position identifies no entry for longer than the next write. Every bridge
//! opens `$HOME/.scp/keys.bin`, so two custody objects sit over one file.
//! `destroy_key` on one object moves every entry after the removed one down by
//! one position, and the other object's handles still name the positions those
//! entries left. A stale handle bound to a position therefore reads whichever
//! key slid into that position. The stored `key_type` byte reports nothing when
//! both keys hold one key type, which is what `#0`, `#active`, and `#agent` are.
//! Associated data over a position matches as well, once the rewrite
//! re-encrypts the moved entry there. An identifier the file draws once per
//! entry closes that path, because no entry the file ever held carries another
//! entry's identifier, so a handle either finds the entry it was minted against
//! or finds nothing.
//!
//! Neither the file HMAC nor the handle map supplies what those rules supply. A
//! second custody object rewrites the file under the same passphrase, so the
//! first object's map outlives the entry it names while the file it now reads
//! still carries a valid HMAC. [`SigningKey::from_bytes`] accepts any 32 bytes,
//! so without the stored-byte comparison a stale Ed25519 handle turns an X25519
//! static secret into an Ed25519 signing key and returns a signature. Without
//! the associated data, a writer who moves one entry's ciphertext behind
//! another entry's identifier hands that ciphertext an identity it never
//! committed to.
//!
//! `destroy_key` copies every surviving entry verbatim, because no entry's
//! ciphertext commits to a position.
//!
//! # One writer at a time
//!
//! `append_entry`, `destroy_key`, and `import_ed25519_signing_key` each read
//! this file, change it, and write it back. All three hold an exclusive
//! advisory lock on a `.lock` sibling of the key file across that whole
//! sequence, which §17.8 of `.docs/specs/17-persistence-and-storage.md`
//! requires under "One writer at a time". Every bridge opens
//! `$HOME/.scp/keys.bin` (`scp_ffi_common::custody_file`), and each identity
//! creation constructs a fresh `FileKeyCustody` over that one path, so the
//! contending writers are two custody objects rather than two tasks inside one
//! object. `flock` excludes a second process and a second object in this
//! process alike; the `file_write_lock` mutex below excludes two tasks that
//! share one object without a syscall.
//!
//! Key import reads before it writes: its dedup scan decides whether the file
//! already holds a seed, so that scan runs under the lock that guards the
//! append it decides. Neither lock is reentrant, so import cannot reach
//! `append_entry`, which takes them both again; it takes them itself and
//! appends through `append_entry_holding_the_write_locks`.
//!
//! # Passphrase commitment and file HMAC
//!
//! One Argon2id derivation over a caller's passphrase and a stored salt
//! produces a root secret, and three HMAC-SHA-256 invocations expand that root
//! under three labels: `…/wrap` gives an AES-256-GCM key that wraps each stored
//! private key, `…/mac` gives a key for this file's HMAC, and `…/commit` gives
//! a commitment that this header stores. Each output is a pseudorandom function
//! of that root and of its own label, so publishing a commitment reveals
//! nothing about either key.
//!
//! `open_existing` checks two things before it returns a custody object, and
//! reports them as two different conditions:
//!
//! 1. **A passphrase commitment.** A stored commitment that differs from what
//!    this caller's passphrase produces proves two passphrases differ.
//!    `SCP-CAPSEL-8001` (§17.17.1 of
//!    `.docs/specs/17-persistence-and-storage.md`) lists "a key or credential
//!    is wrong" among conditions a construction boundary MUST reject, and this
//!    check is how construction detects one — including on a file that holds
//!    zero entries, where no stored key exists to test a passphrase against.
//! 2. **A file HMAC**, computed over every byte outside that HMAC field
//!    itself: version, salt, commitment, entry count, and every entry in order.
//!    A matching commitment with a mismatched HMAC proves something modified
//!    this file after custody wrote it — a header transplanted from another
//!    file, a rewritten entry count that hides keys, a reordered entry that
//!    redirects a handle, a flipped `key_type` byte that reads an X25519 secret
//!    as an Ed25519 signing key, or a flipped ciphertext bit. An operator
//!    answers a modified file by restoring a backup, so this condition carries
//!    its own message instead of reading as a wrong passphrase.
//!
//! Every write path (`create_new`, `append_entry`, and a `destroy_key`
//! rewrite) recomputes this HMAC as its last step before an atomic write, so a
//! file on disk always carries an HMAC over whatever bytes sit beside it.
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
//!
//! See GitHub issue #391 and ADR-006.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use rand::RngCore;
use std::sync::Mutex as StdMutex;
use subtle::ConstantTimeEq as _;
use tokio::sync::Mutex;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::error::PlatformError;
use crate::traits::{
    CustodyType, KeyCustody, KeyHandle, KeyType, PseudonymKeypair, PublicKey, SharedSecret,
    Signature,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Current file format version.
///
/// Version `0x02` adds two header fields a `0x01` file does not carry: a
/// passphrase commitment, which decides whether a caller's passphrase created
/// this file, and an HMAC over every other byte in this file, which decides
/// whether anything modified it since custody last wrote it. `open_existing`
/// checks both before it returns a custody object, so it rejects a `0x01` file
/// by version instead of opening a file it can check neither way.
const FORMAT_VERSION: u8 = 0x02;

/// Argon2id salt length in bytes.
const SALT_LEN: usize = 16;

/// AES-256-GCM nonce length in bytes.
const NONCE_LEN: usize = 12;

/// Private key length in bytes (Ed25519 or X25519).
const KEY_LEN: usize = 32;

/// AES-256-GCM authentication tag length in bytes.
const TAG_LEN: usize = 16;

/// Width of the identifier that names one key entry.
///
/// 16 bytes from the operating system's CSPRNG: two entries collide with
/// probability 2⁻¹²⁸, and [`generate_unique_entry_id`] rejects a collision
/// against the entries a file already holds rather than relying on that number.
const ENTRY_ID_LEN: usize = 16;

/// Byte offset of an entry's identifier inside that entry: it follows a 1-byte
/// key type.
const ENTRY_ID_IN_ENTRY: usize = 1;

/// Byte offset of an entry's AES-256-GCM nonce inside that entry.
const ENTRY_NONCE_IN_ENTRY: usize = ENTRY_ID_IN_ENTRY + ENTRY_ID_LEN;

/// Byte offset of an entry's ciphertext and tag inside that entry.
const ENTRY_CIPHERTEXT_IN_ENTRY: usize = ENTRY_NONCE_IN_ENTRY + NONCE_LEN;

/// Size of one encrypted entry on disk: `key_type` (1) + `entry_id` (16) +
/// nonce (12) + ciphertext (32) + tag (16).
const ENTRY_SIZE: usize = ENTRY_CIPHERTEXT_IN_ENTRY + KEY_LEN + TAG_LEN;

/// Label that derives an AES-256-GCM wrapping key from one Argon2id output.
const WRAP_KEY_LABEL: &[u8] = b"scp-file-key-custody/v2/wrap";

/// Label that derives a file HMAC key from one Argon2id output.
const MAC_KEY_LABEL: &[u8] = b"scp-file-key-custody/v2/mac";

/// Label that derives a passphrase commitment from one Argon2id output.
///
/// A commitment derived under its own label is a one-way function of that
/// Argon2id output, so storing it publishes no value that any key on disk is
/// also a function of.
const COMMITMENT_LABEL: &[u8] = b"scp-file-key-custody/v2/commit";

/// Length of a derived key, of a commitment, and of a file HMAC: SHA-256
/// output width.
const DIGEST_LEN: usize = 32;

/// Byte offset of an Argon2id salt: it follows a 1-byte version field.
const SALT_OFFSET: usize = 1;

/// Byte offset of a passphrase commitment: it follows that salt.
const COMMITMENT_OFFSET: usize = SALT_OFFSET + SALT_LEN;

/// Byte offset of a file HMAC: it follows that commitment.
const MAC_OFFSET: usize = COMMITMENT_OFFSET + DIGEST_LEN;

/// Byte offset one past that file HMAC.
const MAC_END: usize = MAC_OFFSET + DIGEST_LEN;

/// Byte offset of a little-endian `u32` entry count: it follows that file
/// HMAC, which covers this field, so an attacker cannot rewrite a count.
const ENTRY_COUNT_OFFSET: usize = MAC_END;

/// Byte width of that entry count.
const ENTRY_COUNT_LEN: usize = 4;

/// Header size: version (1) + salt (16) + commitment (32) + file HMAC (32) +
/// `entry_count` (4).
const HEADER_SIZE: usize = ENTRY_COUNT_OFFSET + ENTRY_COUNT_LEN;

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

    /// Returns the public [`KeyType`] this stored type names, so an error a
    /// caller reads names the same two values the trait's own signatures use.
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

/// Names one key entry for as long as a key file holds that entry.
///
/// A handle map records this value, and every read finds its entry by comparing
/// it. A position identifies nothing for longer than the next `destroy_key`,
/// which is what makes this identifier the value a handle binds to.
type EntryId = [u8; ENTRY_ID_LEN];

/// Builds the AES-256-GCM associated data that binds one entry's ciphertext to
/// its key type and to its identifier: `key_type | entry_id`.
///
/// A fixed 17-byte width makes the encoding unambiguous, so no two
/// (`key_type`, `entry_id`) pairs produce the same associated data. §17.8 of
/// `.docs/specs/17-persistence-and-storage.md` defines this encoding under
/// "Per-entry binding".
fn entry_aad(key_type: StoredKeyType, entry_id: &EntryId) -> [u8; 1 + ENTRY_ID_LEN] {
    let mut aad = [0u8; 1 + ENTRY_ID_LEN];
    aad[0] = key_type.to_byte();
    aad[1..].copy_from_slice(entry_id);
    aad
}

/// Reads the identifier of the entry at `entry_index`.
///
/// Callers pass bytes [`verify_file`] accepted and an index below the entry
/// count that call reported, which puts every byte this function reads inside
/// `data`.
fn read_entry_id(data: &[u8], entry_index: usize) -> EntryId {
    let start = HEADER_SIZE + entry_index * ENTRY_SIZE + ENTRY_ID_IN_ENTRY;
    let mut entry_id = [0u8; ENTRY_ID_LEN];
    entry_id.copy_from_slice(&data[start..start + ENTRY_ID_LEN]);
    entry_id
}

/// Returns the position of the entry `entry_id` names, and `None` when `data`
/// holds no entry carrying that identifier.
///
/// This function reads whole entries only: it derives its entry count from
/// `data.len()`, so it never reads a partial trailing entry and never indexes
/// past a file shorter than a caller's handle map expects.
fn find_entry_index(data: &[u8], entry_id: &EntryId) -> Option<usize> {
    let entry_count = data.len().checked_sub(HEADER_SIZE)? / ENTRY_SIZE;
    (0..entry_count).find(|index| &read_entry_id(data, *index) == entry_id)
}

/// Draws an entry identifier that no entry in `data` already carries.
///
/// Rejecting a collision here makes "one identifier names at most one entry"
/// hold by construction, and every lookup in this module depends on that.
///
/// # Errors
///
/// Returns [`PlatformError::CustodyError`] when eight consecutive draws all
/// repeat an identifier this file already holds. Two 128-bit draws from the
/// operating system's CSPRNG collide with probability 2⁻¹²⁸, so a caller
/// reaches this arm when that CSPRNG repeats itself, and reporting that beats
/// writing an entry two handles could name.
fn generate_unique_entry_id(data: &[u8]) -> Result<EntryId, PlatformError> {
    const DRAWS: usize = 8;

    for _ in 0..DRAWS {
        let mut entry_id = [0u8; ENTRY_ID_LEN];
        rand::rngs::OsRng.fill_bytes(&mut entry_id);
        if find_entry_index(data, &entry_id).is_none() {
            return Ok(entry_id);
        }
    }

    Err(PlatformError::CustodyError(format!(
        "the operating system's random source returned an entry identifier this key file \
         already holds on all {DRAWS} draws"
    )))
}

/// Returns the path of the lock file that serializes writes to `path`:
/// `path` with `.lock` appended.
///
/// The lock lives beside the key file rather than on the key file itself,
/// because every write path replaces the key file through `rename`. A lock
/// taken on the key file's inode would stop excluding a writer that opened the
/// path after that rename, since the two writers would then hold locks on two
/// different inodes. `atomic_write` names its temporary file
/// `{file_name}.{32 hex digits}.tmp`, so no temporary file ever collides with
/// this name.
fn lock_file_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(".lock");
    PathBuf::from(name)
}

/// Holds an exclusive advisory lock on one key file's lock sibling until this
/// value drops.
///
/// `fs2` maps this onto `flock` on Unix and `LockFileEx` on Windows. Both
/// exclude a second process and a second open file description inside this
/// process, which is what makes two `FileKeyCustody` objects over one path
/// serialize.
struct KeyFileWriteLock {
    file: std::fs::File,
    path: PathBuf,
}

impl Drop for KeyFileWriteLock {
    fn drop(&mut self) {
        if let Err(e) = fs2::FileExt::unlock(&self.file) {
            tracing::warn!(
                path = %self.path.display(),
                error = %e,
                "FileKeyCustody could not release its key-file lock explicitly; closing the \
                 file releases it"
            );
        }
    }
}

/// Takes the exclusive advisory lock that guards a read-modify-write of the key
/// file at `key_path`, creating the lock file when it does not exist.
///
/// This call blocks until whichever writer holds that lock releases it, because
/// two identity creations on one machine must both succeed rather than one of
/// them reporting contention. Every holder does bounded work under this lock —
/// one file read, one AEAD operation per entry it writes, and one atomic write
/// — and awaits nothing while it holds the lock, so no holder waits on a caller
/// of this function. A holder that crashes releases the lock, because an
/// operating system drops every advisory lock a dead process held.
///
/// # Errors
///
/// Returns [`PlatformError::CustodyError`] when the lock file cannot be opened
/// and when the lock cannot be taken.
fn lock_key_file_for_write(key_path: &Path) -> Result<KeyFileWriteLock, PlatformError> {
    let path = lock_file_path(key_path);

    let mut options = std::fs::OpenOptions::new();
    options.create(true).read(true).write(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }

    let file = options.open(&path).map_err(|e| {
        PlatformError::CustodyError(format!(
            "failed to open key-file lock at {}: {e}",
            path.display()
        ))
    })?;

    fs2::FileExt::lock_exclusive(&file).map_err(|e| {
        PlatformError::CustodyError(format!(
            "failed to take the key-file lock at {}: {e}",
            path.display()
        ))
    })?;

    Ok(KeyFileWriteLock { file, path })
}

/// Maps handle IDs to their key type and to the identifier of the entry that
/// holds their key.
struct HandleMap {
    /// Maps `handle_id` to (`key_type`, `entry_id`).
    entries: HashMap<u64, (StoredKeyType, EntryId)>,
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

/// Three values a passphrase and salt produce, each under its own label.
///
/// One Argon2id derivation feeds one HMAC-SHA-256 invocation per label, so each
/// output is a pseudorandom function of that Argon2id output and of its own
/// label, and learning one output reveals nothing about another.
struct DerivedMaterial {
    /// AES-256-GCM key that wraps each stored private key.
    wrap_key: Zeroizing<[u8; DIGEST_LEN]>,
    /// HMAC-SHA-256 key over every file byte outside a file's HMAC field.
    mac_key: Zeroizing<[u8; DIGEST_LEN]>,
    /// Value stored in a header that decides whether a caller's passphrase
    /// created a file.
    commitment: [u8; DIGEST_LEN],
}

/// Expands one Argon2id output into a wrapping key, a MAC key, and a
/// passphrase commitment.
fn derive_material(
    passphrase: &str,
    salt: &[u8; SALT_LEN],
) -> Result<DerivedMaterial, PlatformError> {
    let root = crate::kdf::derive_argon2id_key(passphrase.as_bytes(), salt)?;

    Ok(DerivedMaterial {
        wrap_key: Zeroizing::new(hmac_sha256(root.as_ref(), WRAP_KEY_LABEL)?),
        mac_key: Zeroizing::new(hmac_sha256(root.as_ref(), MAC_KEY_LABEL)?),
        commitment: hmac_sha256(root.as_ref(), COMMITMENT_LABEL)?,
    })
}

/// Computes `HMAC-SHA-256(key, message)`.
///
/// # Errors
///
/// Returns [`PlatformError::CustodyError`] when HMAC rejects `key`. HMAC
/// accepts a key of any length, so no call here reaches that arm today; it
/// returns an error rather than a fixed digest because a fixed digest would
/// make a commitment every passphrase produces and a file MAC every file
/// produces, which turns two checks in `open_existing` into two constants.
fn hmac_sha256(key: &[u8], message: &[u8]) -> Result<[u8; DIGEST_LEN], PlatformError> {
    use hmac::Mac as _;

    let mut mac = <hmac::Hmac<sha2::Sha256> as hmac::Mac>::new_from_slice(key)
        .map_err(|e| PlatformError::CustodyError(format!("HMAC rejected its key: {e}")))?;
    mac.update(message);
    Ok(mac.finalize().into_bytes().into())
}

/// Computes a file HMAC over every byte of `data` except its HMAC field.
///
/// Covered bytes are version, salt, commitment, entry count, and every entry,
/// so a reader detects a transplanted header, a rewritten entry count, a
/// reordered entry, and a flipped ciphertext bit alike.
///
/// # Errors
///
/// Returns [`PlatformError::CustodyError`] when `data` is shorter than a
/// header, or when HMAC rejects `mac_key`.
fn compute_file_mac(
    mac_key: &Zeroizing<[u8; DIGEST_LEN]>,
    data: &[u8],
) -> Result<[u8; DIGEST_LEN], PlatformError> {
    use hmac::Mac as _;

    if data.len() < HEADER_SIZE {
        return Err(PlatformError::CustodyError(
            "key file too short for header".into(),
        ));
    }

    let mut mac = <hmac::Hmac<sha2::Sha256> as hmac::Mac>::new_from_slice(mac_key.as_ref())
        .map_err(|e| PlatformError::CustodyError(format!("HMAC rejected its key: {e}")))?;
    mac.update(&data[..MAC_OFFSET]);
    mac.update(&data[MAC_END..]);
    Ok(mac.finalize().into_bytes().into())
}

/// Writes a file HMAC into `data` in place, over `data`'s current contents.
///
/// Every write path calls this as its last step before `atomic_write`, so a
/// file on disk always carries an HMAC over whatever bytes sit beside it.
///
/// # Errors
///
/// Returns whatever [`compute_file_mac`] reports.
fn seal_file_mac(
    mac_key: &Zeroizing<[u8; DIGEST_LEN]>,
    data: &mut [u8],
) -> Result<(), PlatformError> {
    let mac = compute_file_mac(mac_key, data)?;
    data[MAC_OFFSET..MAC_END].copy_from_slice(&mac);
    Ok(())
}

/// Creates an empty file at `path` with `O_EXCL`, so exactly one caller wins
/// when several create a single path at once.
///
/// Returns `true` when this call created that file and `false` when one was
/// already there, which lets `FileKeyCustody::new` branch on a value rather
/// than on error text.
///
/// # Errors
///
/// Returns [`PlatformError::CustodyError`] when a create fails for any reason
/// other than an existing file.
fn create_file_exclusive(path: &Path) -> Result<bool, PlatformError> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }

    match options.open(path) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
        Err(e) => Err(PlatformError::CustodyError(format!(
            "failed to create key file at {}: {e}",
            path.display()
        ))),
    }
}

/// Reads a header's Argon2id salt after checking version and header length.
///
/// # Errors
///
/// Returns [`PlatformError::CustodyError`] when `data` is empty, when its
/// version byte names another format version, or when it is shorter than a
/// header. A version check runs before a length check, because a file an
/// earlier format wrote is shorter than this format's header and its real
/// problem is its version.
fn read_header_salt(data: &[u8]) -> Result<[u8; SALT_LEN], PlatformError> {
    let Some(&version) = data.first() else {
        return Err(PlatformError::CustodyError("key file is empty".into()));
    };

    if version != FORMAT_VERSION {
        return Err(PlatformError::CustodyError(format!(
            "unsupported key file version: {version:#04x}"
        )));
    }

    if data.len() < HEADER_SIZE {
        return Err(PlatformError::CustodyError(
            "key file too short for header".into(),
        ));
    }

    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(&data[SALT_OFFSET..COMMITMENT_OFFSET]);
    Ok(salt)
}

/// Authenticates whole file bytes and reports how many entries they hold.
///
/// Every path that reads this file runs this check, not construction alone. A
/// writer who swaps two entry blocks, truncates a file, or flips a `key_type`
/// byte between construction and a later `sign` gets detected on that read. An
/// earlier version verified once at construction, so a later `sign` decrypted
/// whatever bytes sat on disk and reported success, and a later `append_entry`
/// re-sealed modified bytes with a victim's own MAC key.
///
/// # Errors
///
/// Returns [`PlatformError::CustodyError`] when a version, a header length, an
/// entry count, a total length, or a stored HMAC does not check out.
fn verify_file(data: &[u8], mac_key: &Zeroizing<[u8; DIGEST_LEN]>) -> Result<usize, PlatformError> {
    // A version and header-length check runs first, so every slice below sits
    // inside `data`.
    read_header_salt(data)?;

    let entry_count = u32::from_le_bytes(
        data[ENTRY_COUNT_OFFSET..HEADER_SIZE]
            .try_into()
            .map_err(|_| PlatformError::CustodyError("invalid entry count bytes".into()))?,
    ) as usize;

    let overflow =
        || PlatformError::CustodyError("key file entry count overflows a byte length".into());
    let expected_len = entry_count
        .checked_mul(ENTRY_SIZE)
        .and_then(|entries_len| HEADER_SIZE.checked_add(entries_len))
        .ok_or_else(overflow)?;
    if data.len() != expected_len {
        return Err(PlatformError::CustodyError(format!(
            "key file length does not match its entry count: expected {expected_len} bytes, \
             got {}",
            data.len()
        )));
    }

    let expected_mac = compute_file_mac(mac_key, data)?;
    if !bool::from(expected_mac.ct_eq(&data[MAC_OFFSET..MAC_END])) {
        return Err(PlatformError::CustodyError(
            "key file failed its integrity check — its bytes changed after custody wrote them \
             (restore a backup; retyping a passphrase will not help)"
                .into(),
        ));
    }

    Ok(entry_count)
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
/// See GitHub issue #391 and ADR-006.
pub struct FileKeyCustody {
    /// Path to the key file on disk.
    path: PathBuf,
    /// AES-256-GCM encryption key derived from the passphrase.
    derived_key: Zeroizing<[u8; DIGEST_LEN]>,
    /// HMAC-SHA-256 key, derived from that same passphrase under its own label,
    /// that authenticates every byte of a key file outside its HMAC field.
    mac_key: Zeroizing<[u8; DIGEST_LEN]>,
    /// Maps handle IDs to key type and entry index.
    handle_map: Mutex<HandleMap>,
    /// Counter for allocating new handle IDs.
    next_id: AtomicU64,
    /// In-memory store for derived pseudonym keys (not persisted to disk).
    pseudonym_keys: Mutex<HashMap<u64, SigningKey>>,
    /// Serializes file read-modify-write operations to prevent data races
    /// when multiple tasks call `append_entry` concurrently.
    ///
    /// This mutex covers two tasks that share one `FileKeyCustody` value and
    /// nothing else. Two values over one path hold two mutexes, which is why
    /// every read-modify-write also takes the cross-process advisory lock that
    /// `lock_key_file_for_write` returns.
    file_write_lock: StdMutex<()>,
}

/// Prints the key file's path and nothing else.
///
/// A derived `Debug` would print `derived_key` and `mac_key`, which is why
/// this impl is written by hand: a caller who logs a custody object, or a
/// bridge whose handle type derives `Debug`, must not thereby write key
/// material into a log.
impl std::fmt::Debug for FileKeyCustody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileKeyCustody")
            .field("path", &self.path)
            .field("derived_key", &"[redacted]")
            .field("mac_key", &"[redacted]")
            .finish_non_exhaustive()
    }
}

impl FileKeyCustody {
    /// Opens an existing key file or creates a new one at `path`.
    ///
    /// A passphrase derives an AES-256-GCM encryption key via Argon2id. On an
    /// existing file, this constructor re-opens a header verifier that
    /// `create_new` sealed under whichever passphrase created that file: a
    /// wrong passphrase fails that check, so this constructor returns an error
    /// and produces no custody object. `SCP-CAPSEL-8001` (§17.17.1 of
    /// `.docs/specs/17-persistence-and-storage.md`) requires a construction
    /// boundary to reject a wrong key or credential, so this check runs here
    /// instead of on a later `sign` call.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformError::CustodyError`] when a caller's passphrase does
    /// not match whichever passphrase created an existing file, when a file
    /// exists but carries an invalid format or an unsupported version, or when
    /// an I/O operation fails.
    pub fn new(path: &Path, passphrase: &str) -> Result<Self, PlatformError> {
        // `create_file_exclusive` creates a file with `O_EXCL` and reports
        // `false` when it loses that race, so two processes calling this
        // constructor at once never both create a file and never overwrite each
        // other's keys. A `path.exists()` test ahead of that creation would
        // leave exactly this window open.
        if create_file_exclusive(path)? {
            Self::finish_new(path, passphrase)
        } else {
            Self::open_existing_when_written(path, passphrase)
        }
    }

    /// Opens an existing key file, waiting briefly when another process
    /// reserved that path and has not written it yet.
    ///
    /// A creating process holds a zero-byte reservation across its Argon2id
    /// derivation, which takes hundreds of milliseconds. A second constructor
    /// arriving inside that window reads zero bytes, so it polls rather than
    /// reporting an empty file that a moment later holds a header.
    fn open_existing_when_written(path: &Path, passphrase: &str) -> Result<Self, PlatformError> {
        // Six attempts at 250 ms bound this wait at 1.5 s, which exceeds one
        // Argon2id derivation at this crate's parameters (64 MiB, 3 passes).
        const ATTEMPTS: u32 = 6;
        const PAUSE: std::time::Duration = std::time::Duration::from_millis(250);

        for attempt in 0..ATTEMPTS {
            match std::fs::metadata(path) {
                Ok(metadata) if metadata.len() > 0 => return Self::open_existing(path, passphrase),
                Ok(_) => {}
                Err(e) => {
                    return Err(PlatformError::CustodyError(format!(
                        "failed to read key file metadata at {}: {e}",
                        path.display()
                    )));
                }
            }
            if attempt + 1 < ATTEMPTS {
                std::thread::sleep(PAUSE);
            }
        }

        Err(PlatformError::CustodyError(format!(
            "key file at {} is empty: an earlier creation reserved that path and did not \
             finish writing it. Delete that file and retry.",
            path.display()
        )))
    }

    /// Derives key material, writes an initial header, and returns custody over
    /// a file `create_file_exclusive` just created.
    fn finish_new(path: &Path, passphrase: &str) -> Result<Self, PlatformError> {
        // Every failure from here on removes whichever empty file a caller just
        // reserved, so a failed creation leaves nothing behind for a later
        // `new` to read as a zero-byte key file.
        let material = Self::write_new_file(path, passphrase).inspect_err(|_| {
            let _ = std::fs::remove_file(path);
        })?;

        Ok(Self {
            path: path.to_path_buf(),
            derived_key: material.wrap_key,
            mac_key: material.mac_key,
            handle_map: Mutex::new(HandleMap::new()),
            next_id: AtomicU64::new(1),
            pseudonym_keys: Mutex::new(HashMap::new()),
            file_write_lock: StdMutex::new(()),
        })
    }

    /// Derives key material and writes an initial header into a file
    /// `create_file_exclusive` already reserved.
    fn write_new_file(path: &Path, passphrase: &str) -> Result<DerivedMaterial, PlatformError> {
        let mut salt = [0u8; SALT_LEN];
        rand::rngs::OsRng.fill_bytes(&mut salt);

        let material = derive_material(passphrase, &salt)?;

        // Write an initial file: version + salt + commitment + HMAC +
        // entry_count(0). That commitment lets a later `open_existing` reject a
        // different passphrase; that HMAC lets it reject a modified file.
        let mut data = Vec::with_capacity(HEADER_SIZE);
        data.push(FORMAT_VERSION);
        data.extend_from_slice(&salt);
        data.extend_from_slice(&material.commitment);
        data.extend_from_slice(&[0u8; DIGEST_LEN]);
        data.extend_from_slice(&0u32.to_le_bytes());
        seal_file_mac(&material.mac_key, &mut data)?;

        // Write to a temp file, sync, then atomic rename over whichever file a
        // caller reserved (#1470).
        atomic_write(path, &data)?;

        Ok(material)
    }

    /// Opens an existing key file at `path` and loads entry metadata.
    fn open_existing(path: &Path, passphrase: &str) -> Result<Self, PlatformError> {
        let data = std::fs::read(path)
            .map_err(|e| PlatformError::CustodyError(format!("failed to read key file: {e}")))?;

        let salt = read_header_salt(&data)?;
        let material = derive_material(passphrase, &salt)?;

        // Reject a wrong passphrase HERE, at construction, instead of letting
        // a caller hold a custody object whose every `sign` call fails
        // (`SCP-CAPSEL-8001`, §17.17.1 of
        // `.docs/specs/17-persistence-and-storage.md`). This commitment answers
        // for a file that holds zero entries too, which no stored-entry check
        // could answer for.
        if !bool::from(
            material
                .commitment
                .ct_eq(&data[COMMITMENT_OFFSET..MAC_OFFSET]),
        ) {
            return Err(PlatformError::CustodyError(
                "wrong passphrase for key file (passphrase commitment did not match)".into(),
            ));
        }

        // A passphrase that reached this line is right, so an HMAC mismatch
        // reports a modified file rather than a wrong passphrase.
        let entry_count = verify_file(&data, &material.mac_key)?;

        // Build the handle map from stored entries.
        let mut handle_map = HandleMap::new();
        let mut next_id = 1u64;

        for i in 0..entry_count {
            let offset = HEADER_SIZE + i * ENTRY_SIZE;
            let key_type_byte = data[offset];
            let key_type = StoredKeyType::from_byte(key_type_byte)?;
            let entry_id = read_entry_id(&data, i);

            let handle_id = next_id;
            next_id += 1;
            handle_map.entries.insert(handle_id, (key_type, entry_id));
        }

        Ok(Self {
            path: path.to_path_buf(),
            derived_key: material.wrap_key,
            mac_key: material.mac_key,
            handle_map: Mutex::new(handle_map),
            next_id: AtomicU64::new(next_id),
            pseudonym_keys: Mutex::new(HashMap::new()),
            file_write_lock: StdMutex::new(()),
        })
    }

    /// Encrypts a 32-byte private key using AES-256-GCM with a fresh nonce,
    /// binding `key_type` and `entry_id` as associated data.
    ///
    /// A caller writes the returned ciphertext behind `key_type`'s byte and
    /// `entry_id`, so [`Self::decrypt_entry`] rebuilds the same associated data
    /// from what it reads. Writing the ciphertext behind any other identifier,
    /// or behind any other type byte, makes the AEAD reject it. The ciphertext
    /// commits to no position, so a rewrite moves a whole entry without
    /// touching it.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformError::CustodyError`] when AES-256-GCM rejects this
    /// custody object's wrapping key or the plaintext.
    fn encrypt_key(
        &self,
        plaintext: &[u8; KEY_LEN],
        key_type: StoredKeyType,
        entry_id: &EntryId,
    ) -> Result<([u8; NONCE_LEN], Vec<u8>), PlatformError> {
        let cipher = Aes256Gcm::new_from_slice(self.derived_key.as_ref())
            .map_err(|e| PlatformError::CustodyError(format!("cipher init failed: {e}")))?;

        let mut nonce_bytes = [0u8; NONCE_LEN];
        rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let aad = entry_aad(key_type, entry_id);
        let ciphertext = cipher
            .encrypt(
                nonce,
                aes_gcm::aead::Payload {
                    msg: plaintext.as_ref(),
                    aad: &aad,
                },
            )
            .map_err(|e| PlatformError::CustodyError(format!("encryption failed: {e}")))?;

        Ok((nonce_bytes, ciphertext))
    }

    /// Decrypts the entry `entry_id` names, after checking that the entry's
    /// stored `key_type` byte names `expected_key_type`.
    ///
    /// Finds that entry by comparing identifiers, so no position a caller
    /// recorded earlier reaches a slice. A handle map outlives the entry it
    /// names in two ways, and both land here as "no entry carries this
    /// identifier": a second custody object over the same file destroys that
    /// key, or an operator restores an older copy of the key file, which
    /// carries its own valid HMAC and a smaller entry count that
    /// [`verify_file`] accepts. Both return the error this function builds
    /// rather than reading whichever key now sits where that handle once
    /// pointed.
    ///
    /// `expected_key_type` is what a caller's handle map recorded, and
    /// `data[offset]` is what the file says now. Comparing those two before
    /// decrypting is what stops [`SigningKey::from_bytes`] from turning an
    /// X25519 static secret into an Ed25519 signing key, which it does without
    /// complaint for any 32 bytes. The associated data this function rebuilds —
    /// `key_type | entry_id`, per §17.8 of
    /// `.docs/specs/17-persistence-and-storage.md` — then makes AES-256-GCM
    /// reject a ciphertext that a writer placed behind another identifier or
    /// behind another type byte.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformError::CustodyError`] when no entry in `data` carries
    /// `entry_id`, when the stored `key_type` byte names a type other than
    /// `expected_key_type`, and when AES-256-GCM rejects the entry.
    fn decrypt_entry(
        &self,
        data: &[u8],
        entry_id: &EntryId,
        expected_key_type: StoredKeyType,
    ) -> Result<Zeroizing<[u8; KEY_LEN]>, PlatformError> {
        let entry_index = find_entry_index(data, entry_id).ok_or_else(|| {
            PlatformError::CustodyError(format!(
                "this key file holds no entry with the identifier this handle names: a custody \
                 object over this file destroyed that key, or this file was replaced by a copy \
                 written before that key existed. The file holds {} entries",
                data.len().saturating_sub(HEADER_SIZE) / ENTRY_SIZE
            ))
        })?;

        let offset = HEADER_SIZE + entry_index * ENTRY_SIZE;
        let nonce_start = offset + ENTRY_NONCE_IN_ENTRY;
        let ct_start = offset + ENTRY_CIPHERTEXT_IN_ENTRY;
        let ct_end = ct_start + KEY_LEN + TAG_LEN;

        // Compare the type this file records against the type this caller's
        // handle names, before any decryption runs.
        let stored_key_type = StoredKeyType::from_byte(data[offset])?;
        if stored_key_type != expected_key_type {
            return Err(PlatformError::CustodyError(format!(
                "key entry {entry_index} holds a {:?} key, and the handle naming it expects a \
                 {:?} key: this key file changed after that handle was minted — restore the \
                 key file this handle was minted against",
                stored_key_type.to_key_type(),
                expected_key_type.to_key_type()
            )));
        }

        let nonce = Nonce::from_slice(&data[nonce_start..ct_start]);
        let ciphertext_and_tag = &data[ct_start..ct_end];

        let cipher = Aes256Gcm::new_from_slice(self.derived_key.as_ref())
            .map_err(|e| PlatformError::CustodyError(format!("cipher init failed: {e}")))?;

        let aad = entry_aad(stored_key_type, entry_id);
        let plaintext = Zeroizing::new(
            cipher
                .decrypt(
                    nonce,
                    aes_gcm::aead::Payload {
                        msg: ciphertext_and_tag,
                        aad: &aad,
                    },
                )
                .map_err(|_| {
                    PlatformError::CustodyError("decryption failed (wrong passphrase?)".into())
                })?,
        );

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

    /// Reads a key file from disk and authenticates its bytes before returning
    /// them.
    ///
    /// Every read path — `sign`, `public_key`, `dh_agree`, `destroy_key`,
    /// `append_entry`, and key import — goes through here, so a writer who
    /// modifies a file between construction and a later call gets detected on
    /// that call. A verified length equals `HEADER_SIZE + count * ENTRY_SIZE`
    /// exactly, so every offset below `count` sits inside the returned bytes.
    /// That says nothing about which entries a file holds: an operator who
    /// restores an older copy of the same key file hands this function a
    /// shorter file that still carries a valid HMAC, and a handle minted
    /// against the longer file then names an entry this file does not hold.
    /// [`Self::decrypt_entry`] finds its entry by identifier for that reason,
    /// and reports an error when no entry carries the one it was given.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformError::CustodyError`] when a read fails, or when
    /// [`verify_file`] rejects what it read.
    fn read_file(&self) -> Result<Vec<u8>, PlatformError> {
        let data = std::fs::read(&self.path)
            .map_err(|e| PlatformError::CustodyError(format!("failed to read key file: {e}")))?;
        verify_file(&data, &self.mac_key)?;
        Ok(data)
    }

    /// Appends an encrypted key entry to the file and updates the entry count,
    /// for a caller that holds neither write lock.
    ///
    /// Takes both locks and hands the read-modify-write to
    /// [`Self::append_entry_holding_the_write_locks`], so the cross-process
    /// advisory lock spans that whole sequence — what §17.8 of
    /// `.docs/specs/17-persistence-and-storage.md` requires under "One writer at
    /// a time". Without it, two custody objects over one key file each read one
    /// entry count, each append at that count, and the later `atomic_write`
    /// replaces the earlier one, so one generated private key never reaches
    /// disk while both callers read success.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformError::CustodyError`] when the advisory lock cannot be
    /// taken, when [`Self::read_file`] rejects the file, when AES-256-GCM
    /// rejects the key, and when the write fails.
    fn append_entry(
        &self,
        key_type: StoredKeyType,
        private_key: &[u8; KEY_LEN],
    ) -> Result<EntryId, PlatformError> {
        let _lock = self
            .file_write_lock
            .lock()
            .map_err(|_| PlatformError::CustodyError("file write lock poisoned".into()))?;
        let _file_lock = lock_key_file_for_write(&self.path)?;
        self.append_entry_holding_the_write_locks(key_type, private_key)
    }

    /// Appends an encrypted key entry to the file and updates the entry count,
    /// for a caller that already holds both write locks.
    ///
    /// Uses write-to-tmp + rename for crash-safe atomic writes (#1470).
    ///
    /// `import_ed25519_signing_key` reads the file, scans every Ed25519 entry
    /// for the key it is about to store, and appends when that scan matches
    /// nothing. §17.8 of `.docs/specs/17-persistence-and-storage.md` requires
    /// one advisory lock across that whole read-modify-write, and neither lock
    /// is reentrant — `file_write_lock` is a plain mutex, and a second
    /// `lock_key_file_for_write` in this process opens a second file
    /// description whose `flock` blocks on the first one — so that caller takes
    /// both locks once, before its read, and calls this function to write.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformError::CustodyError`] when [`Self::read_file`] rejects
    /// the file, when AES-256-GCM rejects the key, and when the write fails.
    fn append_entry_holding_the_write_locks(
        &self,
        key_type: StoredKeyType,
        private_key: &[u8; KEY_LEN],
    ) -> Result<EntryId, PlatformError> {
        let mut data = self.read_file()?;

        // Read current entry count.
        let current_count = u32::from_le_bytes(
            data[ENTRY_COUNT_OFFSET..HEADER_SIZE]
                .try_into()
                .map_err(|_| PlatformError::CustodyError("invalid entry count".into()))?,
        );

        // Draw an identifier no entry in this file already carries. The
        // advisory lock above spans this draw and the write below, so no other
        // writer adds an entry between them.
        let entry_id = generate_unique_entry_id(&data)?;

        // Encrypt the key, binding it to the type byte and to that identifier.
        let (nonce, ciphertext) = self.encrypt_key(private_key, key_type, &entry_id)?;

        // Build the entry: key_type + entry_id + nonce + ciphertext+tag.
        data.push(key_type.to_byte());
        data.extend_from_slice(&entry_id);
        data.extend_from_slice(&nonce);
        data.extend_from_slice(&ciphertext);

        // Update entry count.
        let new_count = current_count + 1;
        data[ENTRY_COUNT_OFFSET..HEADER_SIZE].copy_from_slice(&new_count.to_le_bytes());

        // Re-authenticate this whole file: this write changed an entry count
        // and appended an entry, so a stored HMAC no longer covers what sits on
        // disk.
        seal_file_mac(&self.mac_key, &mut data)?;

        // Write to temp file with sync_all, then atomic rename (#1470).
        atomic_write(&self.path, &data)?;

        Ok(entry_id)
    }

    /// Allocates the next handle ID.
    fn next_handle(&self) -> KeyHandle {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        KeyHandle::new(id)
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
        let (key_type, entry_id) = map
            .entries
            .get(&handle.id())
            .copied()
            .ok_or(PlatformError::KeyNotFound)?;
        if key_type != StoredKeyType::Ed25519 {
            return Err(PlatformError::WrongKeyType {
                expected: KeyType::Ed25519,
                actual: KeyType::X25519,
            });
        }
        let data = self.read_file()?;
        drop(map);
        let key_bytes = self.decrypt_entry(&data, &entry_id, StoredKeyType::Ed25519)?;
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

            // Hold `handle_map` across the entire append-and-insert path so
            // no reader observes a handle this object has not recorded yet.
            // `append_entry` takes only `file_write_lock`, never `handle_map`,
            // so there is no lock-ordering inversion. Mirrors the pattern in
            // `import_ed25519_signing_key`.
            let mut map = self.handle_map.lock().await;
            let entry_id = self.append_entry(stored_type, &key_bytes)?;
            let handle = self.next_handle();
            map.entries.insert(handle.id(), (stored_type, entry_id));
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
            let (key_type, entry_id) = map
                .entries
                .get(&handle.id())
                .copied()
                .ok_or(PlatformError::KeyNotFound)?;
            let data = self.read_file()?;
            drop(map);
            let key_bytes = self.decrypt_entry(&data, &entry_id, key_type)?;

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
            let Some(&(handle_key_type, entry_id)) = map.entries.get(&key_id) else {
                return Err(PlatformError::KeyNotFound);
            };

            // Rewrite the key file without the destroyed entry.
            // This ensures key material is removed from disk, not just from
            // the in-memory handle map.
            let _lock = self
                .file_write_lock
                .lock()
                .map_err(|_| PlatformError::CustodyError("file write lock poisoned".into()))?;
            // Hold the cross-process advisory lock from this read through the
            // write below, so a second custody object over the same path cannot
            // append between them and lose its own entry to this rewrite
            // (§17.8 of `.docs/specs/17-persistence-and-storage.md`, "One
            // writer at a time").
            let _file_lock = lock_key_file_for_write(&self.path)?;

            let data = self.read_file()?;

            // Find the entry this handle names. An identifier names one entry
            // for that entry's whole life, so this lookup reaches the key its
            // caller designated and reaches no other key. A file that carries
            // no entry under this identifier is one that another custody
            // object already rewrote, or a copy an operator restored from
            // before this key existed; this call then writes nothing and
            // leaves the handle map alone, so its caller reads an error rather
            // than a report that custody destroyed a key this file never held.
            let Some(removed_index) = find_entry_index(&data, &entry_id) else {
                tracing::warn!(
                    key_id,
                    "FileKeyCustody::destroy_key found no entry carrying the identifier this \
                     handle names — writing nothing"
                );
                return Err(PlatformError::CustodyError(format!(
                    "destroy_key: this key file holds no entry with the identifier handle \
                     {key_id} names — another custody object over this file destroyed that key, \
                     or this file was replaced by a copy written before that key existed"
                )));
            };

            // The type this file records against the type this handle names. A
            // mismatch means these bytes are not the entry this handle was
            // minted against, and destroying a key is irreversible, so this
            // call writes nothing.
            let entry_offset = HEADER_SIZE + removed_index * ENTRY_SIZE;
            let stored_key_type = StoredKeyType::from_byte(data[entry_offset])?;
            if stored_key_type != handle_key_type {
                return Err(PlatformError::CustodyError(format!(
                    "destroy_key: key entry {removed_index} holds a {:?} key, and handle \
                     {key_id} names a {:?} key — refusing to destroy a key this handle does not \
                     name",
                    stored_key_type.to_key_type(),
                    handle_key_type.to_key_type()
                )));
            }

            // Reconstruct the file: copy header, skip the destroyed entry,
            // decrement the entry count.
            let current_count = u32::from_le_bytes(
                data[ENTRY_COUNT_OFFSET..HEADER_SIZE]
                    .try_into()
                    .map_err(|_| PlatformError::CustodyError("invalid entry count".into()))?,
            );

            // `find_entry_index` derived `removed_index` from this file's own
            // length, and `verify_file` matched that length against this count
            // before `read_file` returned these bytes, so this file holds at
            // least one entry and this subtraction stays inside `u32`.
            let new_count = current_count - 1;
            let mut new_data = Vec::with_capacity(HEADER_SIZE + (new_count as usize) * ENTRY_SIZE);

            // Copy header (version + salt + commitment + an HMAC field, which
            // `seal_file_mac` overwrites below).
            new_data.extend_from_slice(&data[..ENTRY_COUNT_OFFSET]);
            // Write updated entry count.
            new_data.extend_from_slice(&new_count.to_le_bytes());

            // Copy every entry except the removed one, byte for byte.
            // `FileKeyCustody::encrypt_key` binds an entry's identifier rather
            // than its position (§17.8 of
            // `.docs/specs/17-persistence-and-storage.md`, "Per-entry
            // binding"), so an entry that moves down one position still
            // decrypts, and this loop needs no key material to move it.
            for i in 0..current_count as usize {
                if i == removed_index {
                    continue;
                }
                let copy_offset = HEADER_SIZE + i * ENTRY_SIZE;
                new_data.extend_from_slice(&data[copy_offset..copy_offset + ENTRY_SIZE]);
            }

            // Re-authenticate this whole file: this rewrite dropped an entry
            // and changed an entry count, so a stored HMAC no longer covers
            // what sits on disk.
            seal_file_mac(&self.mac_key, &mut new_data)?;

            // Commit to disk BEFORE mutating the in-memory map. If
            // `atomic_write` fails, the map still references the
            // (unmodified) on-disk entry — no orphaned ciphertext.
            atomic_write(&self.path, &new_data)?;

            // Now that disk state is updated, drop the destroyed entry from
            // the in-memory map. Every other handle keeps naming its own
            // entry, because an entry's identifier does not change when that
            // entry moves down a position.
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
            let (key_type, entry_id) = map
                .entries
                .get(&handle.id())
                .copied()
                .ok_or(PlatformError::KeyNotFound)?;

            if key_type != StoredKeyType::X25519 {
                return Err(PlatformError::WrongKeyType {
                    expected: KeyType::X25519,
                    actual: KeyType::Ed25519,
                });
            }

            let data = self.read_file()?;
            drop(map);
            let key_bytes = self.decrypt_entry(&data, &entry_id, StoredKeyType::X25519)?;

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
            //
            // The scan walks the file's entries rather than this object's
            // handle map, because a second custody object over the same path
            // writes entries this object minted no handle for. A scan over the
            // map would miss those entries and append a second copy of a key
            // the file already holds.
            //
            // Both write locks are taken here, before that read, and held
            // through the append below, because this scan and that append are
            // one read-modify-write of the key file: §17.8 of
            // `.docs/specs/17-persistence-and-storage.md` requires an
            // exclusive advisory lock across it, and states that an in-process
            // mutex does not satisfy that requirement. `handle_map` excludes
            // only two tasks that share this object, so without the advisory
            // lock two custody objects over one path — the arrangement every
            // bridge produces, since each identity creation constructs a fresh
            // object over `$HOME/.scp/keys.bin` — each scan a file that holds
            // no matching entry, each append, and the file ends up holding two
            // entries wrapping one private key. `destroy_key` then removes the
            // one entry its handle names and leaves the other on disk.
            //
            // Lock order matches `destroy_key`: `handle_map`, then
            // `file_write_lock`, then the advisory lock. Nothing below awaits,
            // so no lock here is held across a suspension point.
            let mut map = self.handle_map.lock().await;
            let _lock = self
                .file_write_lock
                .lock()
                .map_err(|_| PlatformError::CustodyError("file write lock poisoned".into()))?;
            let _file_lock = lock_key_file_for_write(&self.path)?;

            let data = self.read_file()?;
            let entry_count = data.len().saturating_sub(HEADER_SIZE) / ENTRY_SIZE;
            for index in 0..entry_count {
                let entry_offset = HEADER_SIZE + index * ENTRY_SIZE;
                if StoredKeyType::from_byte(data[entry_offset])? != StoredKeyType::Ed25519 {
                    continue;
                }
                let entry_id = read_entry_id(&data, index);
                // Surface decrypt failure rather than silently skipping
                // the entry. A failed decrypt at this point indicates
                // file corruption (mismatched MAC, truncated ciphertext,
                // or wrong passphrase-derived key) — not a "this entry
                // doesn't match"; treating it as the latter would
                // permit a corrupted file to silently re-grow with
                // duplicate entries on every retry.
                let existing_bytes = self
                    .decrypt_entry(&data, &entry_id, StoredKeyType::Ed25519)
                    .map_err(|e| {
                        PlatformError::CustodyError(format!(
                            "import dedup scan: failed to decrypt entry {index} — file may be \
                             corrupted: {e}"
                        ))
                    })?;
                let existing = SigningKey::from_bytes(&existing_bytes);
                if existing.verifying_key().to_bytes() != target_pub {
                    continue;
                }

                // Return the handle this object already holds for that entry.
                // This object holds none when another custody object over this
                // path wrote the entry, so this branch mints one instead of
                // appending a second copy of the same key.
                let existing_handle = map
                    .entries
                    .iter()
                    .find_map(|(handle_id, (_, id))| (*id == entry_id).then_some(*handle_id));
                if let Some(handle_id) = existing_handle {
                    return Ok(KeyHandle::new(handle_id));
                }
                let handle = self.next_handle();
                map.entries
                    .insert(handle.id(), (StoredKeyType::Ed25519, entry_id));
                return Ok(handle);
            }
            drop(data);

            // Persist the seed bytes via the same encrypted append-only
            // log used by `generate_keypair`. After this call the bytes
            // are encrypted-at-rest under the same passphrase-derived key.
            // Both write locks are already held above and neither is
            // reentrant, so this call takes the variant that writes under
            // locks its caller holds.
            let key_bytes = Zeroizing::new(**seed);
            let entry_id =
                self.append_entry_holding_the_write_locks(StoredKeyType::Ed25519, &key_bytes)?;

            let handle = self.next_handle();
            map.entries
                .insert(handle.id(), (StoredKeyType::Ed25519, entry_id));
            drop(map);

            Ok(handle)
        }
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

    /// `SCP-CAPSEL-8001` (§17.17.1 of
    /// `.docs/specs/17-persistence-and-storage.md`): construction rejects a
    /// wrong passphrase and returns no custody object. Deleting a commitment
    /// comparison from `open_existing` makes `FileKeyCustody::new` return `Ok`
    /// here, so this assertion fails.
    #[tokio::test]
    async fn reopen_with_wrong_passphrase_fails_at_construction() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("keys.scp");

        // Create and generate a key.
        let custody = FileKeyCustody::new(&path, "correct").unwrap();
        custody.generate_keypair(KeyType::Ed25519).await.unwrap();
        drop(custody);

        let result = FileKeyCustody::new(&path, "wrong");
        assert!(
            result.is_err(),
            "construction must reject a wrong passphrase"
        );
        match result.err().unwrap() {
            PlatformError::CustodyError(msg) => {
                assert!(
                    msg.contains("wrong passphrase"),
                    "error must name a wrong passphrase: {msg}"
                );
            }
            other => panic!("expected CustodyError, got {other:?}"),
        }
    }

    /// Swapping two entry blocks after construction redirects a handle: each
    /// block carries its own nonce, so both still decrypt, and an entry's
    /// `key_type` comes from an in-memory handle map rather than from a file.
    /// `sign` on a swapped file must report an integrity failure rather than a
    /// signature under a key its caller never designated. Verifying only at
    /// construction — an earlier version of this file — returns that signature.
    #[tokio::test]
    async fn entry_swap_after_construction_fails_a_later_sign() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("keys.scp");

        let custody = FileKeyCustody::new(&path, "passphrase").unwrap();
        let first = custody.generate_keypair(KeyType::Ed25519).await.unwrap();
        custody.generate_keypair(KeyType::Ed25519).await.unwrap();

        // Swap entry 0 with entry 1 while custody stays open.
        let mut bytes = std::fs::read(&path).unwrap();
        let first_start = HEADER_SIZE;
        let second_start = HEADER_SIZE + ENTRY_SIZE;
        let mut swapped = bytes[..first_start].to_vec();
        swapped.extend_from_slice(&bytes[second_start..second_start + ENTRY_SIZE]);
        swapped.extend_from_slice(&bytes[first_start..first_start + ENTRY_SIZE]);
        swapped.extend_from_slice(&bytes[second_start + ENTRY_SIZE..]);
        bytes = swapped;
        std::fs::write(&path, &bytes).unwrap();

        match custody.sign(&first, b"payload").await.err().unwrap() {
            PlatformError::CustodyError(msg) => {
                assert!(
                    msg.contains("integrity check"),
                    "a swapped entry must fail an integrity check on a later read: {msg}"
                );
            }
            other => panic!("expected CustodyError, got {other:?}"),
        }
    }

    /// A write path must not re-seal bytes it never authenticated. Appending a
    /// key after an external swap would otherwise stamp a valid HMAC over an
    /// attacker's ordering, and a later construction would accept that file.
    #[tokio::test]
    async fn a_write_after_tampering_neither_reseals_nor_hides_it() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("keys.scp");

        let custody = FileKeyCustody::new(&path, "passphrase").unwrap();
        custody.generate_keypair(KeyType::Ed25519).await.unwrap();

        // Flip one ciphertext bit while custody stays open.
        let mut bytes = std::fs::read(&path).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        std::fs::write(&path, &bytes).unwrap();

        assert!(
            custody.generate_keypair(KeyType::Ed25519).await.is_err(),
            "a write path must reject a modified file rather than re-seal it"
        );
        assert!(
            FileKeyCustody::new(&path, "passphrase").is_err(),
            "a later construction must still report that modified file"
        );
    }

    /// Truncating a file after construction leaves a length no entry count
    /// explains. A later read reports that rather than indexing past its end.
    #[tokio::test]
    async fn truncation_after_construction_reports_an_error_and_never_panics() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("keys.scp");

        let custody = FileKeyCustody::new(&path, "passphrase").unwrap();
        let handle = custody.generate_keypair(KeyType::Ed25519).await.unwrap();

        std::fs::write(&path, [FORMAT_VERSION; 20]).unwrap();

        assert!(
            custody.public_key(&handle).await.is_err(),
            "a truncated file must produce an error rather than a panic"
        );
    }

    /// Splicing one file's header onto another file's entries produces a file
    /// whose commitment opens under a header owner's passphrase and whose
    /// entries decrypt under nobody's. Without a file HMAC, construction
    /// succeeds and every key operation then fails; with it, construction
    /// reports an integrity failure and hands back no custody object.
    #[tokio::test]
    async fn transplanted_header_is_rejected_at_construction() {
        let dir = TempDir::new().unwrap();
        let victim_path = dir.path().join("victim.scp");
        let attacker_path = dir.path().join("attacker.scp");

        // Victim file: one key under its own passphrase.
        let victim = FileKeyCustody::new(&victim_path, "victim-passphrase").unwrap();
        victim.generate_keypair(KeyType::Ed25519).await.unwrap();
        drop(victim);

        // Attacker file: one key under a passphrase an attacker knows, so its
        // header carries a commitment that same passphrase opens.
        let attacker = FileKeyCustody::new(&attacker_path, "attacker-passphrase").unwrap();
        attacker.generate_keypair(KeyType::Ed25519).await.unwrap();
        drop(attacker);

        let victim_bytes = std::fs::read(&victim_path).unwrap();
        let attacker_bytes = std::fs::read(&attacker_path).unwrap();

        let mut spliced = attacker_bytes[..HEADER_SIZE].to_vec();
        spliced.extend_from_slice(&victim_bytes[HEADER_SIZE..]);
        std::fs::write(&victim_path, &spliced).unwrap();

        match FileKeyCustody::new(&victim_path, "attacker-passphrase")
            .err()
            .unwrap()
        {
            PlatformError::CustodyError(msg) => {
                assert!(
                    msg.contains("integrity check"),
                    "a transplanted header must fail an integrity check: {msg}"
                );
            }
            other => panic!("expected CustodyError, got {other:?}"),
        }
    }

    /// Rewriting an entry count to zero and truncating every entry hides every
    /// stored key. A file HMAC covers both that count and those entries, so
    /// construction rejects such a file instead of returning custody that holds
    /// no keys.
    #[tokio::test]
    async fn rewritten_entry_count_is_rejected_at_construction() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("keys.scp");

        let custody = FileKeyCustody::new(&path, "passphrase").unwrap();
        custody.generate_keypair(KeyType::Ed25519).await.unwrap();
        drop(custody);

        let mut bytes = std::fs::read(&path).unwrap();
        bytes[ENTRY_COUNT_OFFSET..HEADER_SIZE].copy_from_slice(&0u32.to_le_bytes());
        bytes.truncate(HEADER_SIZE);
        std::fs::write(&path, &bytes).unwrap();

        match FileKeyCustody::new(&path, "passphrase").err().unwrap() {
            PlatformError::CustodyError(msg) => {
                assert!(
                    msg.contains("integrity check"),
                    "a rewritten entry count must fail an integrity check: {msg}"
                );
            }
            other => panic!("expected CustodyError, got {other:?}"),
        }
    }

    /// A flipped ciphertext bit is a modified file, not a wrong passphrase, and
    /// construction says so — an operator restores a backup rather than
    /// retyping a passphrase.
    #[tokio::test]
    async fn flipped_entry_bit_reports_an_integrity_failure_not_a_wrong_passphrase() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("keys.scp");

        let custody = FileKeyCustody::new(&path, "passphrase").unwrap();
        custody.generate_keypair(KeyType::Ed25519).await.unwrap();
        drop(custody);

        let mut bytes = std::fs::read(&path).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        std::fs::write(&path, &bytes).unwrap();

        match FileKeyCustody::new(&path, "passphrase").err().unwrap() {
            PlatformError::CustodyError(msg) => {
                assert!(
                    msg.contains("integrity check"),
                    "a flipped bit must report an integrity failure: {msg}"
                );
                assert!(
                    !msg.contains("wrong passphrase"),
                    "a flipped bit must not read as a wrong passphrase: {msg}"
                );
            }
            other => panic!("expected CustodyError, got {other:?}"),
        }
    }

    /// A file an older format version wrote carries neither a commitment nor a
    /// file HMAC, so construction can check neither its passphrase nor its
    /// integrity. `open_existing` rejects it by version and names that version,
    /// rather than reporting a length problem or opening it anyway.
    #[tokio::test]
    async fn reopen_earlier_format_version_is_rejected_by_version() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("v1-keys.scp");

        // A version-0x01 header: version (1) + salt (16) + entry_count (4).
        let mut v1 = Vec::with_capacity(1 + SALT_LEN + ENTRY_COUNT_LEN);
        v1.push(0x01);
        v1.extend_from_slice(&[0x11; SALT_LEN]);
        v1.extend_from_slice(&0u32.to_le_bytes());
        std::fs::write(&path, &v1).unwrap();

        match FileKeyCustody::new(&path, "any").err().unwrap() {
            PlatformError::CustodyError(msg) => {
                assert!(
                    msg.contains("unsupported key file version"),
                    "error must name that version: {msg}"
                );
            }
            other => panic!("expected CustodyError, got {other:?}"),
        }
    }

    /// A key file that holds zero entries carries no stored key to test a
    /// passphrase against, so only a header verifier can reject a wrong
    /// passphrase on it. Construction rejects one here as well.
    #[tokio::test]
    async fn reopen_empty_file_with_wrong_passphrase_fails_at_construction() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("empty-keys.scp");

        // Create a file and store nothing in it.
        let custody = FileKeyCustody::new(&path, "correct").unwrap();
        drop(custody);

        assert!(
            FileKeyCustody::new(&path, "wrong").is_err(),
            "construction must reject a wrong passphrase on a zero-entry file"
        );
        assert!(
            FileKeyCustody::new(&path, "correct").is_ok(),
            "construction must accept an original passphrase on a zero-entry file"
        );
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

    /// `destroy_key` MUST write nothing when no entry in the file carries the
    /// identifier its caller's handle names. Destroying a key is irreversible,
    /// so a call that cannot find the entry it was asked for reports that
    /// rather than removing whichever entry sits somewhere else. The handle map
    /// must be preserved on this error so the failed call does not orphan
    /// material.
    #[tokio::test]
    async fn destroy_key_rejects_a_handle_whose_entry_the_file_does_not_hold() {
        let dir = TempDir::new().unwrap();
        let custody = make_custody(&dir, "out-of-bounds-passphrase");

        // Populate two real entries so the file is non-empty and the
        // identifier lookup is the only thing that can fail.
        let real_a = custody.generate_keypair(KeyType::Ed25519).await.unwrap();
        let real_b = custody.generate_keypair(KeyType::Ed25519).await.unwrap();

        // Inject a desynchronized entry: a handle the map claims names an
        // entry identifier the file does not carry.
        let desync_id = custody.next_handle().id();
        {
            let mut map = custody.handle_map.lock().await;
            map.entries
                .insert(desync_id, (StoredKeyType::Ed25519, [0xAB; ENTRY_ID_LEN]));
        }
        let desync_handle = KeyHandle::new(desync_id);

        let err = custody
            .destroy_key(&desync_handle)
            .await
            .expect_err("destroy_key MUST refuse a handle the file holds no entry for");
        match err {
            PlatformError::CustodyError(msg) => {
                assert!(
                    msg.contains("holds no entry with the identifier"),
                    "expected desync error, got: {msg}"
                );
                assert!(
                    msg.contains(&desync_id.to_string()),
                    "error message must surface the offending handle, got: {msg}"
                );
            }
            other => panic!("expected CustodyError, got: {other:?}"),
        }

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

    /// A handle that outlives the entry it names must produce a typed error,
    /// not a panic and not another key.
    ///
    /// An operator reaches this state by restoring an older copy of the key
    /// file: that copy carries its own valid HMAC and a smaller entry count,
    /// `verify_file` accepts it, and a handle minted against the longer file
    /// then names an entry the restored file does not hold. `decrypt_entry`
    /// looks its entry up by identifier, so the restored file answers that no
    /// entry carries it.
    #[tokio::test]
    async fn read_of_a_handle_beyond_a_restored_shorter_file_errors_rather_than_panics() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("keys.scp");
        let passphrase = "rollback-passphrase";

        // One key, then a snapshot of the file holding exactly that one key.
        let custody = FileKeyCustody::new(&path, passphrase).unwrap();
        let first = custody.generate_keypair(KeyType::Ed25519).await.unwrap();
        let one_entry_snapshot = std::fs::read(&path).unwrap();

        // A second key, whose handle names entry index 1.
        let second = custody.generate_keypair(KeyType::Ed25519).await.unwrap();
        custody
            .public_key(&second)
            .await
            .expect("the second key reads back before the rollback");

        // Restore the snapshot. It authenticates: its HMAC covers its own
        // one-entry body, so `verify_file` accepts it.
        std::fs::write(&path, &one_entry_snapshot).unwrap();

        let error = custody
            .public_key(&second)
            .await
            .expect_err("a handle naming an entry the restored file lacks must error");
        let PlatformError::CustodyError(message) = error else {
            panic!("an out-of-range entry must surface as CustodyError");
        };
        assert!(
            message.contains("holds no entry with the identifier"),
            "the error must name the missing entry: {message}"
        );

        // The entry the restored file does hold still reads back, so the
        // range check rejects one handle rather than the whole file.
        custody
            .public_key(&first)
            .await
            .expect("the surviving entry still decrypts after the rollback");
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
        // header records `entry_count` at offset `ENTRY_COUNT_OFFSET`.
        let bytes = std::fs::read(&custody.path).unwrap();
        let count = u32::from_le_bytes(bytes[ENTRY_COUNT_OFFSET..HEADER_SIZE].try_into().unwrap());
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
        let count = u32::from_le_bytes(bytes[ENTRY_COUNT_OFFSET..HEADER_SIZE].try_into().unwrap());
        assert_eq!(
            count, 1,
            "concurrent dedup must not append a parallel encrypted entry"
        );
    }

    /// Appends one Ed25519 entry to `custody`'s key file without taking either
    /// write lock, which is what lets a test stand in for a second custody
    /// object mid-write while that test holds the advisory lock itself. Every
    /// custody write path would block on that lock instead. Mirrors what
    /// `append_entry_holding_the_write_locks` writes, byte for byte.
    fn append_ed25519_entry_bypassing_the_locks(
        custody: &FileKeyCustody,
        seed: &Zeroizing<[u8; KEY_LEN]>,
    ) {
        let mut data = std::fs::read(&custody.path).unwrap();
        verify_file(&data, &custody.mac_key).unwrap();

        let current_count =
            u32::from_le_bytes(data[ENTRY_COUNT_OFFSET..HEADER_SIZE].try_into().unwrap());
        let entry_id = generate_unique_entry_id(&data).unwrap();
        let (nonce, ciphertext) = custody
            .encrypt_key(seed, StoredKeyType::Ed25519, &entry_id)
            .unwrap();

        data.push(StoredKeyType::Ed25519.to_byte());
        data.extend_from_slice(&entry_id);
        data.extend_from_slice(&nonce);
        data.extend_from_slice(&ciphertext);
        data[ENTRY_COUNT_OFFSET..HEADER_SIZE].copy_from_slice(&(current_count + 1).to_le_bytes());

        seal_file_mac(&custody.mac_key, &mut data).unwrap();
        atomic_write(&custody.path, &data).unwrap();
    }

    /// `import_ed25519_signing_key` reads the key file under the same advisory
    /// lock it writes under, so a key another writer stored while this import
    /// waited is a key this import finds rather than a key it stores a second
    /// time.
    ///
    /// §17.8 of `.docs/specs/17-persistence-and-storage.md` requires that lock
    /// "from the read that starts a read-modify-write of a key file through the
    /// write that ends that sequence", and states that an in-process mutex does
    /// not satisfy it. Key import is such a sequence: its dedup scan reads the
    /// file, and its append writes the file.
    ///
    /// This test holds the advisory lock while the import runs, which is what a
    /// second custody object over one `$HOME/.scp/keys.bin` holds mid-write —
    /// the arrangement every bridge produces, because each identity creation
    /// constructs a fresh `FileKeyCustody` over that one path. It then stores
    /// the very seed the import is about to store, and releases the lock.
    ///
    /// Reading before taking the lock instead makes the import scan an empty
    /// file, miss, wait, and append: the file ends up holding two entries
    /// wrapping one private key, and `destroy_key` on either handle leaves the
    /// other entry — that private key, still encrypted — on disk. Moving the
    /// two lock acquisitions in `import_ed25519_signing_key` below its
    /// `read_file` call turns the entry-count assertion below red.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn import_scans_the_key_file_under_the_advisory_lock() {
        use std::sync::Arc;

        let dir = TempDir::new().unwrap();
        let path = dir.path().join("keys.scp");

        let importer = Arc::new(FileKeyCustody::new(&path, "pw").unwrap());
        let other_writer = FileKeyCustody::new(&path, "pw").unwrap();

        let seed = Zeroizing::new([7u8; KEY_LEN]);
        let expected_public = SigningKey::from_bytes(&seed).verifying_key().to_bytes();

        // Stand in for a second custody object that is mid-write: hold the
        // advisory lock this import has to wait on.
        let held = lock_key_file_for_write(&path).unwrap();

        let import_custody = Arc::clone(&importer);
        let import_seed = seed.clone();
        let import = tokio::spawn(async move {
            import_custody
                .import_ed25519_signing_key(&import_seed)
                .await
                .unwrap()
        });

        // Long enough for the spawned import to reach whichever point it blocks
        // at, on any runner.
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        assert!(
            !import.is_finished(),
            "an import must wait for the advisory lock rather than write beside its holder"
        );

        // What that second custody object writes before it releases the lock.
        append_ed25519_entry_bypassing_the_locks(&other_writer, &seed);
        drop(held);

        let handle = import.await.unwrap();

        let bytes = std::fs::read(&path).unwrap();
        let count = u32::from_le_bytes(bytes[ENTRY_COUNT_OFFSET..HEADER_SIZE].try_into().unwrap());
        assert_eq!(
            count, 1,
            "an import that scanned the file under the lock must find the entry another writer \
             stored, rather than append a second entry wrapping the same private key"
        );

        assert_eq!(
            importer.public_key(&handle).await.unwrap().as_bytes(),
            expected_public,
            "the handle an import returned must name the key it was asked to store"
        );
    }

    /// Concurrent `generate_keypair` ↔ `destroy_key` MUST NOT corrupt the
    /// handle map. `generate_keypair` holds `handle_map` across its whole
    /// append-and-insert path, so no reader observes a handle this object has
    /// not recorded yet, and the identifier `append_entry` returns names the
    /// entry it wrote for that entry's whole life. The test pre-creates a
    /// victim key, races a `generate_keypair` against `destroy_key` on the
    /// victim, and asserts that the handle `generate_keypair` returned reads
    /// back its own key.
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

        // The new handle MUST decrypt cleanly: it names the identifier
        // `append_entry` drew for the entry it wrote, and the concurrent
        // `destroy_key` removed another entry.
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

        // Every other pre-existing handle MUST still decrypt cleanly. The
        // destroy moved two entries down one position each, and no handle
        // names a position.
        for h in &handles {
            let _ = custody
                .public_key(h)
                .await
                .expect("pre-existing handles must decrypt after concurrent generate/destroy");
        }

        // Handle map invariant: every handle names an entry the file still
        // holds. A stale insert would leave an identifier no entry carries,
        // which `decrypt_entry` rejects above.
        let map = custody.handle_map.lock().await;
        let bytes = std::fs::read(&custody.path).unwrap();
        for (id, (_kt, entry_id)) in &map.entries {
            assert!(
                find_entry_index(&bytes, entry_id).is_some(),
                "handle {id} names an entry identifier the file no longer holds"
            );
        }
    }
    // -----------------------------------------------------------------------
    // Two custody objects over one key file (§17.8 of
    // `.docs/specs/17-persistence-and-storage.md`, "One writer at a time").
    // -----------------------------------------------------------------------

    /// Eight `FileKeyCustody` objects over one path each generate one key at
    /// once, and the file ends up holding all eight distinct keys.
    ///
    /// This is the end state the advisory lock exists to produce: eight
    /// appends, eight surviving entries, eight distinct keys, and eight handles
    /// that each read back their own. It does not decide whether
    /// `append_entry` takes that lock, because the interleaving it would
    /// otherwise hit is a few syscalls wide and does not reproduce on every
    /// run. `append_entry_waits_for_a_lock_another_writer_holds` is the
    /// assertion that fails when the lock leaves `append_entry`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn eight_custody_objects_over_one_file_keep_all_eight_keys() {
        use std::sync::Arc;

        const WRITERS: usize = 8;

        let dir = TempDir::new().unwrap();
        let path = dir.path().join("keys.scp");

        // Construct the file once, so no constructor races another constructor
        // and every object below opens the same existing header.
        drop(FileKeyCustody::new(&path, "pw").unwrap());

        let mut tasks = Vec::with_capacity(WRITERS);
        for _ in 0..WRITERS {
            let custody = Arc::new(FileKeyCustody::new(&path, "pw").unwrap());
            tasks.push(tokio::spawn(async move {
                let handle = custody.generate_keypair(KeyType::Ed25519).await.unwrap();
                let public = custody.public_key(&handle).await.unwrap();
                public.as_bytes().to_vec()
            }));
        }

        let mut public_keys = Vec::with_capacity(WRITERS);
        for task in tasks {
            public_keys.push(task.await.unwrap());
        }

        let bytes = std::fs::read(&path).unwrap();
        let on_disk_count =
            u32::from_le_bytes(bytes[ENTRY_COUNT_OFFSET..HEADER_SIZE].try_into().unwrap()) as usize;
        assert_eq!(
            on_disk_count, WRITERS,
            "every generated key must reach disk: {on_disk_count} of {WRITERS} entries survived"
        );
        assert_eq!(
            bytes.len(),
            HEADER_SIZE + WRITERS * ENTRY_SIZE,
            "the file length must match the entry count it declares"
        );

        public_keys.sort_unstable();
        public_keys.dedup();
        assert_eq!(
            public_keys.len(),
            WRITERS,
            "each caller must hold its own key, not a key another caller wrote"
        );

        // Reopening reads all eight entries back, which proves each entry
        // decrypts under the index it sits at.
        let reopened = FileKeyCustody::new(&path, "pw").unwrap();
        let mut reread = Vec::with_capacity(WRITERS);
        for id in 1..=WRITERS as u64 {
            let public = reopened.public_key(&KeyHandle::new(id)).await.unwrap();
            reread.push(public.as_bytes().to_vec());
        }
        reread.sort_unstable();
        assert_eq!(
            public_keys, reread,
            "reopening must recover the same eight keys"
        );
    }

    /// A second custody object over one key file appends without discarding the
    /// entry a first object wrote, and both objects' handles keep working.
    #[tokio::test]
    async fn a_second_custody_object_appends_without_dropping_the_first_key() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("keys.scp");

        let first = FileKeyCustody::new(&path, "pw").unwrap();
        let first_handle = first.generate_keypair(KeyType::Ed25519).await.unwrap();
        let first_public = first.public_key(&first_handle).await.unwrap();

        let second = FileKeyCustody::new(&path, "pw").unwrap();
        let second_handle = second.generate_keypair(KeyType::Ed25519).await.unwrap();
        let second_public = second.public_key(&second_handle).await.unwrap();

        assert_ne!(
            first_public.as_bytes(),
            second_public.as_bytes(),
            "two objects must hold two keys, not one key twice"
        );
        assert_eq!(
            first.public_key(&first_handle).await.unwrap().as_bytes(),
            first_public.as_bytes(),
            "the first object's key must survive the second object's append"
        );
    }

    // -----------------------------------------------------------------------
    // Per-entry binding (§17.8 of
    // `.docs/specs/17-persistence-and-storage.md`, "Per-entry binding").
    // -----------------------------------------------------------------------

    /// A handle whose entry a second custody object destroyed reports an error
    /// instead of signing with whichever key moved into that entry's position.
    ///
    /// Object `a` records (Ed25519, entry 0) and (X25519, entry 1). Object `b`
    /// destroys entry 0, which moves the X25519 secret to position 0 and
    /// re-seals a valid file HMAC under the same passphrase. Object `a`'s
    /// handle names the identifier of the entry `b` removed, so both calls
    /// below report that the file holds no such entry. A handle bound to a
    /// position instead reads the X25519 secret sitting at position 0, and
    /// `SigningKey::from_bytes` accepts any 32 bytes, so it returns an Ed25519
    /// signature computed from an X25519 static secret.
    #[tokio::test]
    async fn a_handle_over_a_destroyed_entry_fails_instead_of_signing() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("keys.scp");

        let a = FileKeyCustody::new(&path, "pw").unwrap();
        let ed = a.generate_keypair(KeyType::Ed25519).await.unwrap();
        a.generate_keypair(KeyType::X25519).await.unwrap();

        // `b` loads the same two entries and mints handles 1 and 2 for them, so
        // handle 1 names entry 0.
        let b = FileKeyCustody::new(&path, "pw").unwrap();
        b.destroy_key(&KeyHandle::new(1)).await.unwrap();

        let sign_error = a
            .sign(&ed, b"payload")
            .await
            .expect_err("signing an entry another object destroyed must fail");
        match sign_error {
            PlatformError::CustodyError(msg) => assert!(
                msg.contains("holds no entry with the identifier"),
                "the error must name the missing entry: {msg}"
            ),
            other => panic!("expected CustodyError, got {other:?}"),
        }

        let public_key_error = a
            .public_key(&ed)
            .await
            .expect_err("reading a public key from a destroyed entry must fail");
        assert!(matches!(public_key_error, PlatformError::CustodyError(_)));
    }

    /// A writer who flips an entry's `key_type` byte and re-seals the file HMAC
    /// gets an error that names the stored type and the expected type.
    ///
    /// The AEAD rejects this entry too, because `encrypt_key` bound the type
    /// byte the writer replaced. The comparison in `decrypt_entry` runs first
    /// so an operator reads which two types disagree instead of reading
    /// "decryption failed (wrong passphrase?)", which sends that operator after
    /// a passphrase that is correct. §17.8 of
    /// `.docs/specs/17-persistence-and-storage.md` requires the comparison
    /// under "Per-entry binding".
    #[tokio::test]
    async fn a_flipped_key_type_byte_names_both_types_rather_than_a_decrypt_failure() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("keys.scp");

        let custody = FileKeyCustody::new(&path, "pw").unwrap();
        let ed = custody.generate_keypair(KeyType::Ed25519).await.unwrap();

        let mut data = custody.read_file().unwrap();
        data[HEADER_SIZE] = KEY_TYPE_X25519;
        seal_file_mac(&custody.mac_key, &mut data).unwrap();
        atomic_write(&path, &data).unwrap();

        // The file passes its HMAC check, so the per-entry rules are the only
        // thing left to reject it.
        assert!(custody.read_file().is_ok());

        let error = custody
            .sign(&ed, b"payload")
            .await
            .expect_err("an entry whose type byte changed must not sign");
        match error {
            PlatformError::CustodyError(msg) => assert!(
                msg.contains("X25519") && msg.contains("Ed25519"),
                "the error must name both the stored type and the expected type: {msg}"
            ),
            other => panic!("expected CustodyError, got {other:?}"),
        }
    }

    /// A writer who moves one entry's ciphertext behind another entry's
    /// identifier, and re-seals the file HMAC under the passphrase-derived MAC
    /// key, produces entries the AEAD rejects.
    ///
    /// The file HMAC cannot catch this rewrite, because the writer recomputes
    /// it — which is exactly what every legitimate `append_entry` and
    /// `destroy_key` does. The associated data `encrypt_key` binds catches it:
    /// each ciphertext committed to the identifier it was written behind.
    /// Removing the `Payload` from `encrypt_key` and `decrypt_entry` makes this
    /// `sign` call return a signature under the other entry's key.
    #[tokio::test]
    async fn a_ciphertext_moved_behind_another_identifier_fails_its_aead_check() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("keys.scp");

        let custody = FileKeyCustody::new(&path, "pw").unwrap();
        let first = custody.generate_keypair(KeyType::Ed25519).await.unwrap();
        let second = custody.generate_keypair(KeyType::Ed25519).await.unwrap();
        let first_public = custody.public_key(&first).await.unwrap();
        let second_public = custody.public_key(&second).await.unwrap();
        assert_ne!(
            first_public.as_bytes(),
            second_public.as_bytes(),
            "this test needs two distinct keys for the swap to be observable"
        );

        // Swap the two entries' nonces and ciphertexts, and leave each key type
        // byte and each identifier where it sits, so both handles still find
        // the identifiers they name.
        let mut data = custody.read_file().unwrap();
        let first_sealed = HEADER_SIZE + ENTRY_NONCE_IN_ENTRY;
        let second_sealed = HEADER_SIZE + ENTRY_SIZE + ENTRY_NONCE_IN_ENTRY;
        let sealed_len = ENTRY_SIZE - ENTRY_NONCE_IN_ENTRY;
        let first_bytes = data[first_sealed..first_sealed + sealed_len].to_vec();
        let second_bytes = data[second_sealed..second_sealed + sealed_len].to_vec();
        data[first_sealed..first_sealed + sealed_len].copy_from_slice(&second_bytes);
        data[second_sealed..second_sealed + sealed_len].copy_from_slice(&first_bytes);
        seal_file_mac(&custody.mac_key, &mut data).unwrap();
        atomic_write(&path, &data).unwrap();

        // The file now passes `verify_file`, so only the per-entry binding is
        // left to reject it.
        assert!(
            custody.read_file().is_ok(),
            "a re-sealed file must pass its HMAC check, which is what makes this test \
             exercise the AEAD binding rather than the HMAC"
        );

        let error = custody
            .sign(&first, b"payload")
            .await
            .expect_err("a ciphertext moved behind another identifier must not decrypt");
        match error {
            PlatformError::CustodyError(msg) => assert!(
                msg.contains("decryption failed"),
                "the AEAD must reject a relocated ciphertext: {msg}"
            ),
            other => panic!("expected CustodyError, got {other:?}"),
        }
    }

    /// Reordering two whole entry blocks changes which key each handle reads
    /// not at all, because a handle names an identifier that travels with its
    /// entry.
    ///
    /// A key file compacts on every `destroy_key`, so entries move by design.
    /// This assertion states the property that makes that safe.
    #[tokio::test]
    async fn reordering_two_whole_entries_leaves_both_handles_on_their_own_keys() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("keys.scp");

        let custody = FileKeyCustody::new(&path, "pw").unwrap();
        let first = custody.generate_keypair(KeyType::Ed25519).await.unwrap();
        let second = custody.generate_keypair(KeyType::Ed25519).await.unwrap();
        let first_public = custody.public_key(&first).await.unwrap();
        let second_public = custody.public_key(&second).await.unwrap();

        let mut data = custody.read_file().unwrap();
        let first_start = HEADER_SIZE;
        let second_start = HEADER_SIZE + ENTRY_SIZE;
        let first_entry = data[first_start..first_start + ENTRY_SIZE].to_vec();
        let second_entry = data[second_start..second_start + ENTRY_SIZE].to_vec();
        data[first_start..first_start + ENTRY_SIZE].copy_from_slice(&second_entry);
        data[second_start..second_start + ENTRY_SIZE].copy_from_slice(&first_entry);
        seal_file_mac(&custody.mac_key, &mut data).unwrap();
        atomic_write(&path, &data).unwrap();

        assert_eq!(
            custody.public_key(&first).await.unwrap().as_bytes(),
            first_public.as_bytes(),
            "the first handle must read its own key after its entry moved"
        );
        assert_eq!(
            custody.public_key(&second).await.unwrap().as_bytes(),
            second_public.as_bytes(),
            "the second handle must read its own key after its entry moved"
        );
    }

    /// `destroy_key` copies every entry it moves byte for byte, and the handles
    /// naming those entries keep working.
    ///
    /// `encrypt_key` binds an entry's identifier and no position, so a moved
    /// entry needs no new ciphertext. Re-encrypting one instead would hand a
    /// stale handle from a second custody object a ciphertext that decrypts
    /// under the position that handle recorded, which is the read this format
    /// exists to refuse.
    #[tokio::test]
    async fn destroy_key_copies_the_entries_it_moves_verbatim() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("keys.scp");

        let custody = FileKeyCustody::new(&path, "pw").unwrap();
        let first = custody.generate_keypair(KeyType::Ed25519).await.unwrap();
        let victim = custody.generate_keypair(KeyType::Ed25519).await.unwrap();
        let third = custody.generate_keypair(KeyType::Ed25519).await.unwrap();
        let fourth = custody.generate_keypair(KeyType::X25519).await.unwrap();

        let first_public = custody.public_key(&first).await.unwrap();
        let third_public = custody.public_key(&third).await.unwrap();
        let fourth_public = custody.public_key(&fourth).await.unwrap();
        let before = std::fs::read(&path).unwrap();

        custody.destroy_key(&victim).await.unwrap();

        assert_eq!(
            custody.public_key(&first).await.unwrap().as_bytes(),
            first_public.as_bytes(),
            "an entry that kept its position must keep its key"
        );
        assert_eq!(
            custody.public_key(&third).await.unwrap().as_bytes(),
            third_public.as_bytes(),
            "an entry that moved down one position must still decrypt to the same key"
        );
        assert_eq!(
            custody.public_key(&fourth).await.unwrap().as_bytes(),
            fourth_public.as_bytes(),
            "a moved X25519 entry must still decrypt to the same key"
        );
        custody
            .sign(&third, b"payload")
            .await
            .expect("a moved Ed25519 entry must still sign");
        let peer = [7u8; 32];
        custody
            .dh_agree(&fourth, &peer)
            .await
            .expect("a moved X25519 entry must still agree");

        // Every surviving entry carries the bytes it carried before, at
        // whatever position it now sits.
        let after = std::fs::read(&path).unwrap();
        assert_eq!(
            after.len(),
            HEADER_SIZE + 3 * ENTRY_SIZE,
            "destroying one of four entries must leave three"
        );
        assert_eq!(
            &after[HEADER_SIZE..HEADER_SIZE + ENTRY_SIZE],
            &before[HEADER_SIZE..HEADER_SIZE + ENTRY_SIZE],
            "an entry that kept its position must keep its bytes"
        );
        for (moved_from, moved_to) in [(2usize, 1usize), (3, 2)] {
            let from = HEADER_SIZE + moved_from * ENTRY_SIZE;
            let to = HEADER_SIZE + moved_to * ENTRY_SIZE;
            assert_eq!(
                &after[to..to + ENTRY_SIZE],
                &before[from..from + ENTRY_SIZE],
                "the entry at position {moved_from} must reach position {moved_to} unchanged"
            );
        }
    }

    /// A handle a second custody object minted keeps reading its own key after
    /// the first object destroys an entry that sits ahead of it.
    ///
    /// Object `a` writes four Ed25519 keys, so the file holds four entries of
    /// one key type. Object `b` opens that file and mints handles 1 through 4
    /// for positions 0 through 3. `a` then destroys the key at position 1,
    /// which moves the other two entries down one position each. Under a handle
    /// bound to a position, `b`'s third handle reads the fourth key, `b`'s
    /// fourth handle reads past the end of the file, and the stored key-type
    /// byte reports nothing, because every entry here holds an Ed25519 key.
    #[tokio::test]
    async fn a_second_objects_handles_keep_their_own_keys_after_a_destroy_shifts_entries() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("keys.scp");

        let a = FileKeyCustody::new(&path, "pw").unwrap();
        let mut a_handles = Vec::new();
        let mut publics = Vec::new();
        for _ in 0..4 {
            let handle = a.generate_keypair(KeyType::Ed25519).await.unwrap();
            publics.push(a.public_key(&handle).await.unwrap().as_bytes().to_vec());
            a_handles.push(handle);
        }

        // `b` loads the same four entries and mints handles 1 through 4 for
        // positions 0 through 3.
        let b = FileKeyCustody::new(&path, "pw").unwrap();
        let before = std::fs::read(&path).unwrap();

        a.destroy_key(&a_handles[1]).await.unwrap();

        // The rewrite really did move two entries down one position each, so
        // the handles `b` minted against positions 2 and 3 now name positions
        // that hold other keys. Every assertion below rests on that.
        let after = std::fs::read(&path).unwrap();
        assert_eq!(
            after.len(),
            HEADER_SIZE + 3 * ENTRY_SIZE,
            "destroying one of four entries must leave three"
        );
        assert_eq!(
            &after[HEADER_SIZE + ENTRY_SIZE..HEADER_SIZE + 2 * ENTRY_SIZE],
            &before[HEADER_SIZE + 2 * ENTRY_SIZE..HEADER_SIZE + 3 * ENTRY_SIZE],
            "the third key must now sit at position 1"
        );

        assert_eq!(
            b.public_key(&KeyHandle::new(1)).await.unwrap().as_bytes(),
            publics[0].as_slice(),
            "the entry ahead of the destroyed one must keep serving its handle"
        );
        let destroyed = b
            .public_key(&KeyHandle::new(2))
            .await
            .expect_err("the handle naming the destroyed entry must fail");
        match destroyed {
            PlatformError::CustodyError(msg) => assert!(
                msg.contains("holds no entry with the identifier"),
                "the error must name the missing entry: {msg}"
            ),
            other => panic!("expected CustodyError, got {other:?}"),
        }
        assert_eq!(
            b.public_key(&KeyHandle::new(3)).await.unwrap().as_bytes(),
            publics[2].as_slice(),
            "the third handle must read the third key, not the key that moved into position 2"
        );
        assert_eq!(
            b.public_key(&KeyHandle::new(4)).await.unwrap().as_bytes(),
            publics[3].as_slice(),
            "the fourth handle must read the fourth key at its new position"
        );

        // Signing goes through the same lookup, so assert it recovers the same
        // key rather than only that it succeeds.
        let signature = b.sign(&KeyHandle::new(3), b"payload").await.unwrap();
        let verifying_key =
            VerifyingKey::from_bytes(&publics[2].as_slice().try_into().unwrap()).unwrap();
        let signature_bytes: [u8; 64] = signature.as_bytes().try_into().unwrap();
        ed25519_dalek::Verifier::verify(
            &verifying_key,
            b"payload",
            &ed25519_dalek::Signature::from_bytes(&signature_bytes),
        )
        .expect("the third handle must sign under the third key");
    }

    /// `destroy_key` removes the key its handle names, and removes no other
    /// key, after a second custody object rewrote the file and refilled the
    /// position that handle was minted against.
    ///
    /// Object `b` destroys the entry at position 0, which moves `a`'s second
    /// key down to position 0, and then writes a new key at position 1. Object
    /// `a`'s handle for its second key still records position 1. Under a handle
    /// bound to a position, `a`'s destroy passes its bounds check, because the
    /// file holds two entries again, and it removes `b`'s freshly written key
    /// while reporting success.
    #[tokio::test]
    async fn destroy_key_removes_only_the_key_its_handle_names_after_a_refill() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("keys.scp");

        let a = FileKeyCustody::new(&path, "pw").unwrap();
        a.generate_keypair(KeyType::Ed25519).await.unwrap();
        let a_second = a.generate_keypair(KeyType::Ed25519).await.unwrap();
        let a_second_public = a.public_key(&a_second).await.unwrap();

        // `b` loads both entries as handles 1 and 2, destroys the first, and
        // writes a third key into the position that rewrite freed.
        let b = FileKeyCustody::new(&path, "pw").unwrap();
        b.destroy_key(&KeyHandle::new(1)).await.unwrap();
        let b_fresh = b.generate_keypair(KeyType::Ed25519).await.unwrap();
        let b_fresh_public = b.public_key(&b_fresh).await.unwrap();

        // The file holds two entries again, so a bounds check on the position
        // `a`'s handle recorded passes, and only the identifier lookup
        // separates `a`'s key from the key `b` just wrote.
        assert_eq!(
            std::fs::read(&path).unwrap().len(),
            HEADER_SIZE + 2 * ENTRY_SIZE,
            "the second object's append must refill the position its destroy freed"
        );

        a.destroy_key(&a_second)
            .await
            .expect("destroying a key that moved to another position must succeed");

        assert_eq!(
            b.public_key(&b_fresh).await.unwrap().as_bytes(),
            b_fresh_public.as_bytes(),
            "the key the second object wrote must survive the first object's destroy"
        );
        assert_ne!(
            b_fresh_public.as_bytes(),
            a_second_public.as_bytes(),
            "this test needs two distinct keys for the destroy to be observable"
        );
        assert!(
            a.public_key(&a_second).await.is_err(),
            "the destroyed handle must stop reading a key"
        );

        let bytes = std::fs::read(&path).unwrap();
        assert_eq!(
            bytes.len(),
            HEADER_SIZE + ENTRY_SIZE,
            "one key must remain on disk"
        );
    }

    /// `entry_aad` gives every (`key_type`, `entry_id`) pair its own 17-byte
    /// encoding, so no two entries share associated data.
    #[test]
    fn entry_aad_separates_every_type_and_identifier_pair() {
        let mut seen = std::collections::HashSet::new();
        for key_type in [StoredKeyType::Ed25519, StoredKeyType::X25519] {
            for index in 0..64u8 {
                let entry_id = [index; ENTRY_ID_LEN];
                assert!(
                    seen.insert(entry_aad(key_type, &entry_id)),
                    "associated data repeated for {key_type:?} at identifier {index}"
                );
            }
        }
        assert_eq!(seen.len(), 128);
    }

    /// `generate_unique_entry_id` never returns an identifier the file already
    /// holds, which is what makes "one identifier names at most one entry" hold
    /// by construction rather than by probability.
    #[tokio::test]
    async fn every_entry_in_one_file_carries_its_own_identifier() {
        let dir = TempDir::new().unwrap();
        let custody = make_custody(&dir, "unique-identifier-passphrase");

        for _ in 0..8 {
            custody.generate_keypair(KeyType::Ed25519).await.unwrap();
        }

        let bytes = std::fs::read(&custody.path).unwrap();
        let entry_count =
            u32::from_le_bytes(bytes[ENTRY_COUNT_OFFSET..HEADER_SIZE].try_into().unwrap()) as usize;
        assert_eq!(entry_count, 8);

        let mut seen = std::collections::HashSet::new();
        for index in 0..entry_count {
            assert!(
                seen.insert(read_entry_id(&bytes, index)),
                "entry {index} repeats an identifier another entry already carries"
            );
        }
    }

    /// The lock file sits beside the key file and carries the key file's name
    /// with `.lock` appended, so `atomic_write`'s `{name}.{32 hex}.tmp`
    /// temporary never collides with it.
    #[test]
    fn the_lock_file_sits_beside_the_key_file() {
        let path = Path::new("/tmp/scp-lock-name-test/keys.bin");
        assert_eq!(
            lock_file_path(path),
            PathBuf::from("/tmp/scp-lock-name-test/keys.bin.lock")
        );
    }
    /// A second caller of `lock_key_file_for_write` waits while a first holds
    /// that lock.
    ///
    /// Two `FileKeyCustody` objects hold two `file_write_lock` mutexes, so this
    /// advisory lock is the only thing that makes them take turns. Replacing
    /// `fs2::FileExt::lock_exclusive` with a call that returns immediately makes
    /// the second thread set its flag inside the wait below, which fails this
    /// assertion.
    #[test]
    fn a_second_writer_waits_for_the_key_file_lock() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};

        let dir = TempDir::new().unwrap();
        let path = dir.path().join("keys.scp");

        let held = lock_key_file_for_write(&path).unwrap();

        let acquired = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&acquired);
        let waiter_path = path;
        let waiter = std::thread::spawn(move || {
            let _second = lock_key_file_for_write(&waiter_path).unwrap();
            flag.store(true, Ordering::SeqCst);
        });

        std::thread::sleep(std::time::Duration::from_millis(300));
        assert!(
            !acquired.load(Ordering::SeqCst),
            "a second writer must wait while a first holds the key-file lock"
        );

        drop(held);
        waiter.join().unwrap();
        assert!(
            acquired.load(Ordering::SeqCst),
            "releasing the lock must let the waiting writer through"
        );
    }

    /// `append_entry` waits for the key-file lock rather than reading and
    /// writing beside whoever holds it.
    ///
    /// The test takes that lock directly, then starts one `generate_keypair`
    /// and checks that it has not finished 300 ms later. Deleting the
    /// `lock_key_file_for_write` call from `append_entry` lets that call finish
    /// in milliseconds, which fails this assertion.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn append_entry_waits_for_a_lock_another_writer_holds() {
        use std::sync::Arc;

        let dir = TempDir::new().unwrap();
        let path = dir.path().join("keys.scp");
        let custody = Arc::new(FileKeyCustody::new(&path, "pw").unwrap());

        let held = lock_key_file_for_write(&path).unwrap();

        let appending = Arc::clone(&custody);
        let task = tokio::spawn(async move { appending.generate_keypair(KeyType::Ed25519).await });

        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        assert!(
            !task.is_finished(),
            "generate_keypair must wait for the key-file lock another writer holds"
        );

        drop(held);
        let handle = task.await.unwrap().unwrap();
        custody
            .public_key(&handle)
            .await
            .expect("the key written after the lock was released must read back");
    }

    /// `destroy_key` waits for the key-file lock the same way `append_entry`
    /// does, so its rewrite never replaces an entry another writer appended
    /// between its own read and its own write.
    ///
    /// Deleting the `lock_key_file_for_write` call from `destroy_key` lets the
    /// call below finish while this test holds that lock, which fails this
    /// assertion.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn destroy_key_waits_for_a_lock_another_writer_holds() {
        use std::sync::Arc;

        let dir = TempDir::new().unwrap();
        let path = dir.path().join("keys.scp");
        let custody = Arc::new(FileKeyCustody::new(&path, "pw").unwrap());
        let victim = custody.generate_keypair(KeyType::Ed25519).await.unwrap();

        let held = lock_key_file_for_write(&path).unwrap();

        let destroying = Arc::clone(&custody);
        let task = tokio::spawn(async move { destroying.destroy_key(&victim).await });

        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        assert!(
            !task.is_finished(),
            "destroy_key must wait for the key-file lock another writer holds"
        );

        drop(held);
        task.await
            .unwrap()
            .expect("destroy_key must succeed once the lock is free");
    }
}
