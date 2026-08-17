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

/// Size of one encrypted entry on disk: `key_type` (1) + nonce (12) + ciphertext (32) + tag (16).
const ENTRY_SIZE: usize = 1 + NONCE_LEN + KEY_LEN + TAG_LEN;

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

/// Maps handle IDs to their key type and position in the file's entry list.
struct HandleMap {
    /// Maps `handle_id` to (`key_type`, `entry_index`).
    entries: HashMap<u64, (StoredKeyType, usize)>,
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

            let handle_id = next_id;
            next_id += 1;
            handle_map.entries.insert(handle_id, (key_type, i));
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

    /// Decrypts a key entry from the file at the given entry index.
    ///
    /// Checks `entry_index` against `data` before it slices. A caller reaches
    /// an out-of-range index whenever the handle map outlives the entry it
    /// names: an operator restores an older copy of the key file, that copy
    /// carries a valid HMAC and a smaller entry count, [`verify_file`] accepts
    /// it, and a handle minted against the longer file then names an entry the
    /// restored file does not hold. Slicing on that index panics, and AES-GCM
    /// authentication cannot prevent it because authentication reads the bytes
    /// the slice already produced.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformError::CustodyError`] when `entry_index` names an
    /// entry outside `data`, and when AES-256-GCM rejects the entry.
    fn decrypt_entry(
        &self,
        data: &[u8],
        entry_index: usize,
    ) -> Result<Zeroizing<[u8; KEY_LEN]>, PlatformError> {
        let out_of_range = || {
            PlatformError::CustodyError(format!(
                "key entry {entry_index} lies outside this key file: the file holds \
                 {} bytes, which is {} entries — restore the key file this handle was \
                 minted against",
                data.len(),
                data.len().saturating_sub(HEADER_SIZE) / ENTRY_SIZE
            ))
        };

        let offset = entry_index
            .checked_mul(ENTRY_SIZE)
            .and_then(|entries_len| HEADER_SIZE.checked_add(entries_len))
            .ok_or_else(out_of_range)?;
        // Skip key_type byte (1 byte).
        let nonce_start = offset + 1;
        let ct_start = nonce_start + NONCE_LEN;
        let ct_end = ct_start + KEY_LEN + TAG_LEN;
        if ct_end > data.len() {
            return Err(out_of_range());
        }

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

    /// Reads a key file from disk and authenticates its bytes before returning
    /// them.
    ///
    /// Every read path — `sign`, `public_key`, `dh_agree`, `destroy_key`,
    /// `append_entry`, and key import — goes through here, so a writer who
    /// modifies a file between construction and a later call gets detected on
    /// that call. A verified length equals `HEADER_SIZE + count * ENTRY_SIZE`
    /// exactly, so every offset below `count` sits inside the returned bytes.
    /// That says nothing about an index at or above `count`: an operator who
    /// restores an older copy of the same key file hands this function a
    /// shorter file that still carries a valid HMAC, and a handle minted
    /// against the longer file then names an entry this file does not hold.
    /// [`Self::decrypt_entry`] range-checks its own index for that reason.
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

    /// Appends an encrypted key entry to the file and updates the entry count.
    ///
    /// Uses write-to-tmp + rename for crash-safe atomic writes (#1470).
    fn append_entry(
        &self,
        key_type: StoredKeyType,
        private_key: &[u8; KEY_LEN],
    ) -> Result<usize, PlatformError> {
        let _lock = self
            .file_write_lock
            .lock()
            .map_err(|_| PlatformError::CustodyError("file write lock poisoned".into()))?;
        let mut data = self.read_file()?;

        // Read current entry count.
        let current_count = u32::from_le_bytes(
            data[ENTRY_COUNT_OFFSET..HEADER_SIZE]
                .try_into()
                .map_err(|_| PlatformError::CustodyError("invalid entry count".into()))?,
        );

        let new_index = current_count as usize;

        // Encrypt the key.
        let (nonce, ciphertext) = self.encrypt_key(private_key)?;

        // Build the entry: key_type + nonce + ciphertext+tag.
        data.push(key_type.to_byte());
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

        Ok(new_index)
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
        let (key_type, entry_index) = map
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
        let key_bytes = self.decrypt_entry(&data, entry_index)?;
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
            // path so a concurrent `destroy_key` cannot rewrite the
            // file and shift `entry_index` between our `append_entry`
            // and the map insert. `append_entry` takes only
            // `file_write_lock`, never `handle_map`, so there is no
            // lock-ordering inversion. Mirrors the pattern in
            // `import_ed25519_signing_key`.
            let mut map = self.handle_map.lock().await;
            let entry_index = self.append_entry(stored_type, &key_bytes)?;
            let handle = self.next_handle();
            map.entries.insert(handle.id(), (stored_type, entry_index));
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
            let (key_type, entry_index) = map
                .entries
                .get(&handle.id())
                .copied()
                .ok_or(PlatformError::KeyNotFound)?;
            let data = self.read_file()?;
            drop(map);
            let key_bytes = self.decrypt_entry(&data, entry_index)?;

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
            let Some(&(_, removed_index)) = map.entries.get(&key_id) else {
                return Err(PlatformError::KeyNotFound);
            };

            // Rewrite the key file without the destroyed entry.
            // This ensures key material is removed from disk, not just from
            // the in-memory handle map.
            let _lock = self
                .file_write_lock
                .lock()
                .map_err(|_| PlatformError::CustodyError("file write lock poisoned".into()))?;

            let data = self.read_file()?;

            // Reconstruct the file: copy header, skip the destroyed entry,
            // decrement the entry count.
            let current_count = u32::from_le_bytes(
                data[ENTRY_COUNT_OFFSET..HEADER_SIZE]
                    .try_into()
                    .map_err(|_| PlatformError::CustodyError("invalid entry count".into()))?,
            );

            // Defend against in-memory/on-disk desynchronization: if the
            // handle map says the entry lives at an index the file
            // doesn't contain, refuse to write rather than emitting a
            // malformed file with a clamped count.
            if removed_index >= current_count as usize {
                tracing::error!(
                    key_id,
                    removed_index,
                    current_count,
                    "FileKeyCustody::destroy_key detected handle map / on-disk file desync — refusing to write corrupt state"
                );
                return Err(PlatformError::CustodyError(format!(
                    "destroy_key: handle map references entry_index {removed_index} but file has {current_count} entries — refusing to write corrupt state"
                )));
            }

            let new_count = current_count - 1;
            let mut new_data = Vec::with_capacity(HEADER_SIZE + (new_count as usize) * ENTRY_SIZE);

            // Copy header (version + salt + commitment + an HMAC field, which
            // `seal_file_mac` overwrites below).
            new_data.extend_from_slice(&data[..ENTRY_COUNT_OFFSET]);
            // Write updated entry count.
            new_data.extend_from_slice(&new_count.to_le_bytes());

            // Copy all entries except the removed one.
            for i in 0..current_count as usize {
                if i == removed_index {
                    continue;
                }
                let entry_offset = HEADER_SIZE + i * ENTRY_SIZE;
                new_data.extend_from_slice(&data[entry_offset..entry_offset + ENTRY_SIZE]);
            }

            // Re-authenticate this whole file: this rewrite dropped an entry
            // and changed an entry count, so a stored HMAC no longer covers
            // what sits on disk.
            seal_file_mac(&self.mac_key, &mut new_data)?;

            // Commit to disk BEFORE mutating the in-memory map. If
            // `atomic_write` fails, the map still references the
            // (unmodified) on-disk entry — no orphaned ciphertext.
            atomic_write(&self.path, &new_data)?;

            // Now that disk state is updated, mutate the in-memory
            // map: drop the destroyed entry and shift indices for
            // entries that lived after it.
            map.entries.remove(&key_id);
            for (_key_type, entry_index) in map.entries.values_mut() {
                if *entry_index > removed_index {
                    *entry_index -= 1;
                }
            }
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
            let (key_type, entry_index) = map
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
            let key_bytes = self.decrypt_entry(&data, entry_index)?;

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

            let data = self.read_file()?;
            for (id, (kt, idx)) in &map.entries {
                if *kt != StoredKeyType::Ed25519 {
                    continue;
                }
                // Surface decrypt failure rather than silently skipping
                // the entry. A failed decrypt at this point indicates
                // file corruption (mismatched MAC, truncated ciphertext,
                // or wrong passphrase-derived key) — not a "this entry
                // doesn't match"; treating it as the latter would
                // permit a corrupted file to silently re-grow with
                // duplicate entries on every retry.
                let existing_bytes = self.decrypt_entry(&data, *idx).map_err(|e| {
                    PlatformError::CustodyError(format!(
                        "import dedup scan: failed to decrypt entry {idx} \
                         (handle {id}) — file may be corrupted: {e}"
                    ))
                })?;
                let existing = SigningKey::from_bytes(&existing_bytes);
                if existing.verifying_key().to_bytes() == target_pub {
                    return Ok(KeyHandle::new(*id));
                }
            }
            drop(data);

            // Persist the seed bytes via the same encrypted append-only
            // log used by `generate_keypair`. After this call the bytes
            // are encrypted-at-rest under the same passphrase-derived key.
            // `append_entry` takes only `file_write_lock` — safe to call
            // while holding `handle_map`.
            let key_bytes = Zeroizing::new(**seed);
            let entry_index = self.append_entry(StoredKeyType::Ed25519, &key_bytes)?;

            let handle = self.next_handle();
            map.entries
                .insert(handle.id(), (StoredKeyType::Ed25519, entry_index));
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

    /// `destroy_key` MUST refuse to rewrite the file when the in-memory
    /// handle map is desynchronized with the on-disk entry count
    /// (i.e. the map points at an entry index that the file does not
    /// contain). Silently clamping with `saturating_sub` would emit a
    /// malformed file whose header count is smaller than the entry
    /// payload — corrupting the custody store. The handle map must be
    /// preserved on this error so the failed call does not orphan
    /// material.
    #[tokio::test]
    async fn destroy_key_rejects_out_of_bounds_entry_index() {
        let dir = TempDir::new().unwrap();
        let custody = make_custody(&dir, "out-of-bounds-passphrase");

        // Populate two real entries so the file is non-empty and the
        // bounds check is the only thing that can fail.
        let real_a = custody.generate_keypair(KeyType::Ed25519).await.unwrap();
        let real_b = custody.generate_keypair(KeyType::Ed25519).await.unwrap();

        // Inject a desynchronized entry: a handle the map claims lives
        // at an out-of-bounds index relative to the on-disk count (2).
        let desync_id = custody.next_handle().id();
        {
            let mut map = custody.handle_map.lock().await;
            map.entries
                .insert(desync_id, (StoredKeyType::Ed25519, 9_999));
        }
        let desync_handle = KeyHandle::new(desync_id);

        let err = custody
            .destroy_key(&desync_handle)
            .await
            .expect_err("destroy_key MUST refuse desynchronized entry index");
        match err {
            PlatformError::CustodyError(msg) => {
                assert!(
                    msg.contains("refusing to write corrupt state"),
                    "expected desync error, got: {msg}"
                );
                assert!(
                    msg.contains("9999"),
                    "error message must surface the offending index, got: {msg}"
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
    /// not a panic.
    ///
    /// An operator reaches this state by restoring an older copy of the key
    /// file: that copy carries its own valid HMAC and a smaller entry count,
    /// `verify_file` accepts it, and a handle minted against the longer file
    /// then names an entry the restored file does not hold. `decrypt_entry`
    /// sliced on that index before it range-checked, so the slice panicked
    /// inside a library call. AES-GCM authentication cannot prevent that,
    /// because authentication reads bytes the slice already produced.
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
            message.contains("lies outside this key file"),
            "the error must name the out-of-range entry: {message}"
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

    /// Concurrent `generate_keypair` ↔ `destroy_key` MUST NOT corrupt
    /// the handle map. Holding `handle_map` across the entire
    /// append-and-insert path is what guarantees this: without it, a
    /// concurrent `destroy_key` could rewrite the file and shift
    /// `entry_index` values between our `append_entry` and the map
    /// insert, leaving the new handle pointing at a stale slot. The
    /// test pre-creates a victim key, then races a `generate_keypair`
    /// against `destroy_key` on the victim and asserts that whatever
    /// handle came back from `generate_keypair` decrypts cleanly (i.e.
    /// the recorded `entry_index` still references its real ciphertext
    /// in the file).
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

        // The new handle MUST decrypt cleanly. If `generate_keypair`
        // had captured a stale `entry_index` from before
        // `destroy_key`'s shift, `public_key` would fail to decrypt
        // (or recover a different key than the one we wrote).
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

        // All other pre-existing handles MUST still decrypt cleanly
        // (the destroy path is responsible for shifting their indices,
        // and `generate_keypair` must not interleave a stale insert).
        for h in &handles {
            let _ = custody
                .public_key(h)
                .await
                .expect("pre-existing handles must decrypt after concurrent generate/destroy");
        }

        // Handle map invariant: every entry's `entry_index` is in
        // bounds for the current file. A stale insert would leave an
        // out-of-bounds index that `decrypt_entry` would reject above.
        let map = custody.handle_map.lock().await;
        let bytes = std::fs::read(&custody.path).unwrap();
        let count =
            u32::from_le_bytes(bytes[ENTRY_COUNT_OFFSET..HEADER_SIZE].try_into().unwrap()) as usize;
        for (id, (_kt, idx)) in &map.entries {
            assert!(
                *idx < count,
                "handle {id} has stale entry_index {idx} ≥ on-disk count {count}"
            );
        }
    }
}
