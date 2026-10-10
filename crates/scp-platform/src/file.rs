//! Encrypted file-backed [`KeyCustody`] implementation.
//!
//! Provides `FileKeyCustody` — an encrypted-at-rest key store using
//! Argon2id for passphrase-based key derivation and AES-256-GCM for
//! encryption. This is the universal fallback for all non-HSM platforms
//! and the default custody mode for `scp-node`.
//!
//! # Key File Format
//!
//! `17-persistence-and-storage.md` §17.8 (`FileKeyCustody` Argon2id Parameters)
//! defines this format: the Argon2id parameters, the HKDF info labels, the
//! header, entry and associated-data layouts, and the file tag. This summary
//! restates it; where the two differ, §17.8 governs.
//!
//! The key file stores zero or more encrypted key entries, each containing
//! one Ed25519, X25519 or P-256 private key. The file begins with a global header
//! and is followed by a sequence of key entries:
//!
//! ```text
//! ┌────────────────────────────────────────────────┐
//! │ version: u8          (1 byte, 0x01)            │
//! │ argon2id_salt: [u8]  (16 bytes)                │
//! ├────────────────────────────────────────────────┤
//! │ entry_count: u32 LE  (4 bytes)                 │
//! ├────────────────────────────────────────────────┤
//! │ Entry 0:                                       │
//! │   key_type: u8       (0x01 = Ed25519,          │
//! │                       0x02 = X25519,           │
//! │                       0x03 = P-256 signing,    │
//! │                       0x04 = P-256 HPKE)       │
//! │   role: u8           (0x00 = operational,      │
//! │                       0x01 = identity)         │
//! │   nonce: [u8]        (12 bytes, AES-256-GCM)   │
//! │   ciphertext+tag: [u8] (48 bytes = 32 + 16)    │
//! ├────────────────────────────────────────────────┤
//! │ Entry 1: ...                                   │
//! ├────────────────────────────────────────────────┤
//! │ file_tag: [u8]       (32 bytes, HMAC-SHA256)   │
//! └────────────────────────────────────────────────┘
//! ```
//!
//! The file is exactly `HEADER_SIZE + entry_count * ENTRY_SIZE + 32` bytes;
//! any other length is refused. `file_tag` is HMAC-SHA256 over every byte
//! before it, so a lowered `entry_count`, a dropped, appended or replayed
//! entry, and trailing bytes all fail on open and on every later read.
//!
//! The Argon2id output is never used as a key directly. HKDF-SHA256 over it
//! derives two independent subkeys under distinct info labels: the
//! AES-256-GCM entry key (`scp/file-key-custody/v1/entry-aead`) and the
//! file-tag HMAC key (`scp/file-key-custody/v1/file-mac`).
//!
//! The Argon2id salt is generated once when the file is created and reused
//! for all entries. Each entry has a unique AES-256-GCM nonce. The
//! ciphertext is the 32-byte private key encrypted under AES-256-GCM;
//! the tag (16 bytes) is appended by the AEAD. The AEAD's associated data is
//! `version || key_type || role || entry_index (u32 BE)`, so flipping an
//! entry's type or role byte or moving an entry to another position fails
//! decryption instead of reinterpreting the key. Only an identity entry may
//! be a pseudonym-derivation source (§9.10.4.A). `destroy_key` re-encrypts every entry whose index
//! shifts. A P-256 entry's 32 bytes are
//! the big-endian scalar; it is rejected when decrypted if it is zero or not
//! below the group order `n`.
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
//! See ADR-006.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use rand::RngCore;
use std::sync::Mutex as StdMutex;
use tokio::sync::Mutex;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::error::PlatformError;
use crate::traits::{
    CustodyType, KeyCustody, KeyHandle, KeyRole, KeyType, Pseudonym, PublicKey, SharedSecret,
    Signature,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// File format version (`17-persistence-and-storage.md` §17.8).
///
/// The file carries a role byte in each entry, binds each entry's version,
/// type byte, role byte and index as associated data, and ends with a
/// whole-file HMAC-SHA256 tag. Every other version byte is refused.
const FORMAT_VERSION: u8 = 0x01;

/// Length of the trailing whole-file HMAC-SHA256 tag.
const FILE_TAG_LEN: usize = 32;

/// HKDF-SHA256 info label for the AES-256-GCM entry-encryption subkey.
const ENTRY_KEY_INFO: &[u8] = b"scp/file-key-custody/v1/entry-aead";

/// HKDF-SHA256 info label for the whole-file HMAC-SHA256 subkey.
const FILE_MAC_INFO: &[u8] = b"scp/file-key-custody/v1/file-mac";

/// The entry-encryption key and the file-MAC key, in that order, that
/// [`FileKeyCustody::derive_keys`] derives from a passphrase.
type KeyFileSubkeys = (Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>);

/// Argon2id salt length in bytes.
const SALT_LEN: usize = 16;

/// AES-256-GCM nonce length in bytes.
const NONCE_LEN: usize = 12;

/// Private key length in bytes (Ed25519 or X25519).
const KEY_LEN: usize = 32;

/// AES-256-GCM authentication tag length in bytes.
const TAG_LEN: usize = 16;

/// Size of one encrypted entry on disk: `key_type` (1) + role (1) + nonce
/// (12) + ciphertext (32) + tag (16).
const ENTRY_SIZE: usize = 2 + NONCE_LEN + KEY_LEN + TAG_LEN;

/// Header size: version (1) + salt (16) + `entry_count` (4).
const HEADER_SIZE: usize = 1 + SALT_LEN + 4;

/// Key type byte for Ed25519.
const KEY_TYPE_ED25519: u8 = 0x01;

/// Key type byte for X25519.
const KEY_TYPE_X25519: u8 = 0x02;

/// Key type byte for a P-256 signing key ([`KeyType::P256Signing`]).
const KEY_TYPE_P256_SIGNING: u8 = 0x03;

/// Key type byte for a P-256 HPKE key ([`KeyType::HpkeP256`]).
const KEY_TYPE_P256_HPKE: u8 = 0x04;

// ---------------------------------------------------------------------------
// Internal types
// ---------------------------------------------------------------------------

/// The type of key stored in an entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StoredKeyType {
    Ed25519,
    X25519,
    P256Signing,
    HpkeP256,
}

impl StoredKeyType {
    const fn to_byte(self) -> u8 {
        match self {
            Self::Ed25519 => KEY_TYPE_ED25519,
            Self::X25519 => KEY_TYPE_X25519,
            Self::P256Signing => KEY_TYPE_P256_SIGNING,
            Self::HpkeP256 => KEY_TYPE_P256_HPKE,
        }
    }

    const fn from_key_type(key_type: KeyType) -> Self {
        match key_type {
            KeyType::Ed25519 => Self::Ed25519,
            KeyType::X25519 => Self::X25519,
            KeyType::P256Signing => Self::P256Signing,
            KeyType::HpkeP256 => Self::HpkeP256,
        }
    }

    fn from_byte(b: u8) -> Result<Self, PlatformError> {
        match b {
            KEY_TYPE_ED25519 => Ok(Self::Ed25519),
            KEY_TYPE_X25519 => Ok(Self::X25519),
            KEY_TYPE_P256_SIGNING => Ok(Self::P256Signing),
            KEY_TYPE_P256_HPKE => Ok(Self::HpkeP256),
            _ => Err(PlatformError::CustodyError(format!(
                "unknown key type byte: {b:#04x}"
            ))),
        }
    }
}

/// One handle's entry: its key type, its role, and its position in the
/// file's entry list.
#[derive(Debug, Clone, Copy)]
struct MappedEntry {
    key_type: StoredKeyType,
    role: KeyRole,
    index: usize,
}

/// Maps handle IDs to their entries.
struct HandleMap {
    entries: HashMap<u64, MappedEntry>,
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
// Whole-file tag
// ---------------------------------------------------------------------------

/// Checks the version byte and that `data` is exactly
/// `HEADER_SIZE + entry_count * ENTRY_SIZE + FILE_TAG_LEN` bytes, and
/// returns `entry_count`. The tag itself is checked by [`open_file`].
fn check_file_shape(data: &[u8]) -> Result<usize, PlatformError> {
    if data.len() < HEADER_SIZE + FILE_TAG_LEN {
        return Err(PlatformError::CustodyError(format!(
            "key file too short: {} bytes",
            data.len()
        )));
    }
    if data[0] != FORMAT_VERSION {
        return Err(PlatformError::CustodyError(format!(
            "unsupported key file version: {:#04x}",
            data[0]
        )));
    }
    let mut count = [0u8; 4];
    count.copy_from_slice(&data[1 + SALT_LEN..HEADER_SIZE]);
    let entry_count = u32::from_le_bytes(count) as usize;
    let expected_len = entry_count
        .checked_mul(ENTRY_SIZE)
        .and_then(|n| n.checked_add(HEADER_SIZE + FILE_TAG_LEN))
        .ok_or_else(|| {
            PlatformError::CustodyError(format!("key file entry count {entry_count} overflows"))
        })?;
    if data.len() != expected_len {
        return Err(PlatformError::CustodyError(format!(
            "key file length mismatch: {entry_count} entries need {expected_len} bytes, got {}",
            data.len()
        )));
    }
    Ok(entry_count)
}

/// A fresh HMAC-SHA256 instance keyed by `mac_key`.
fn file_mac(mac_key: &[u8; 32]) -> Result<hmac::Hmac<sha2::Sha256>, PlatformError> {
    <hmac::Hmac<sha2::Sha256> as hmac::Mac>::new_from_slice(mac_key)
        .map_err(|e| PlatformError::CustodyError(format!("file MAC init failed: {e}")))
}

/// Appends the whole-file tag over `body`.
fn seal_file(mac_key: &[u8; 32], mut body: Vec<u8>) -> Result<Vec<u8>, PlatformError> {
    use hmac::Mac;
    let mut mac = file_mac(mac_key)?;
    mac.update(&body);
    body.extend_from_slice(&mac.finalize().into_bytes());
    Ok(body)
}

/// Verifies the trailing tag over every byte before it (constant time) and
/// returns the bytes without the tag.
fn open_file(mac_key: &[u8; 32], mut data: Vec<u8>) -> Result<Vec<u8>, PlatformError> {
    use hmac::Mac;
    let body_len = data
        .len()
        .checked_sub(FILE_TAG_LEN)
        .ok_or_else(|| PlatformError::CustodyError("key file too short for its tag".into()))?;
    let mut mac = file_mac(mac_key)?;
    mac.update(&data[..body_len]);
    mac.verify_slice(&data[body_len..]).map_err(|_| {
        PlatformError::CustodyError(
            "key file authentication failed (wrong passphrase, or a tampered file)".into(),
        )
    })?;
    data.truncate(body_len);
    Ok(data)
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
    /// AES-256-GCM entry-encryption subkey ([`ENTRY_KEY_INFO`]).
    entry_key: Zeroizing<[u8; 32]>,
    /// Whole-file HMAC-SHA256 subkey ([`FILE_MAC_INFO`]).
    mac_key: Zeroizing<[u8; 32]>,
    /// Maps handle IDs to key type and entry index.
    handle_map: Mutex<HandleMap>,
    /// Counter for allocating new handle IDs.
    next_id: AtomicU64,
    /// Serializes file read-modify-write operations to prevent data races
    /// when multiple tasks call `append_entry` concurrently.
    file_write_lock: StdMutex<()>,
}

impl FileKeyCustody {
    /// Opens an existing key file or creates a new one at `path`.
    ///
    /// The passphrase is used to derive the AES-256-GCM encryption key via
    /// Argon2id. If the file exists, it is read and validated; if the
    /// passphrase is wrong, decryption of existing entries will fail on
    /// access (the derived key will differ).
    ///
    /// # Errors
    ///
    /// Returns [`PlatformError::CustodyError`] if the file exists but has
    /// an invalid format, or if I/O operations fail.
    pub fn new(path: &Path, passphrase: &str) -> Result<Self, PlatformError> {
        if path.exists() {
            Self::open_existing(path, passphrase)
        } else {
            Self::create_new(path, passphrase)
        }
    }

    /// Creates a new key file at `path` with a fresh salt.
    ///
    /// Uses write-to-tmp + rename for crash-safe atomic writes (#1470).
    fn create_new(path: &Path, passphrase: &str) -> Result<Self, PlatformError> {
        let mut salt = [0u8; SALT_LEN];
        rand::rngs::OsRng.fill_bytes(&mut salt);

        let (entry_key, mac_key) = Self::derive_keys(passphrase, &salt)?;

        // Write the initial file: version + salt + entry_count(0) + tag.
        let mut data = Vec::with_capacity(HEADER_SIZE + FILE_TAG_LEN);
        data.push(FORMAT_VERSION);
        data.extend_from_slice(&salt);
        data.extend_from_slice(&0u32.to_le_bytes());
        let data = seal_file(&mac_key, data)?;

        // Write to temp file, sync, then atomic rename (#1470).
        atomic_write(path, &data)?;

        Ok(Self {
            path: path.to_path_buf(),
            entry_key,
            mac_key,
            handle_map: Mutex::new(HandleMap::new()),
            next_id: AtomicU64::new(1),
            file_write_lock: StdMutex::new(()),
        })
    }

    /// Opens an existing key file at `path` and loads entry metadata.
    fn open_existing(path: &Path, passphrase: &str) -> Result<Self, PlatformError> {
        let data = std::fs::read(path)
            .map_err(|e| PlatformError::CustodyError(format!("failed to read key file: {e}")))?;

        let entry_count = check_file_shape(&data)?;
        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(&data[1..=SALT_LEN]);
        let (entry_key, mac_key) = Self::derive_keys(passphrase, &salt)?;
        // A wrong passphrase derives a different MAC key, so it fails here.
        let data = open_file(&mac_key, data)?;

        // Build the handle map from stored entries.
        let mut handle_map = HandleMap::new();
        let mut next_id = 1u64;

        for i in 0..entry_count {
            let offset = HEADER_SIZE + i * ENTRY_SIZE;
            let key_type_byte = data[offset];
            let key_type = StoredKeyType::from_byte(key_type_byte)?;
            let role_byte = data[offset + 1];
            let role = KeyRole::from_byte(role_byte).ok_or_else(|| {
                PlatformError::CustodyError(format!(
                    "unknown key role byte {role_byte:#04x} in entry {i}"
                ))
            })?;

            let handle_id = next_id;
            next_id += 1;
            handle_map.entries.insert(
                handle_id,
                MappedEntry {
                    key_type,
                    role,
                    index: i,
                },
            );
        }

        Ok(Self {
            path: path.to_path_buf(),
            entry_key,
            mac_key,
            handle_map: Mutex::new(handle_map),
            next_id: AtomicU64::new(next_id),
            file_write_lock: StdMutex::new(()),
        })
    }

    /// Derives the entry-encryption and file-MAC subkeys from a passphrase
    /// and salt: Argon2id through [`crate::kdf::derive_argon2id_key`] (the
    /// single source of the Argon2id parameterization, spec §17.6 / §17.8),
    /// then HKDF-SHA256 under [`ENTRY_KEY_INFO`] and [`FILE_MAC_INFO`].
    fn derive_keys(
        passphrase: &str,
        salt: &[u8; SALT_LEN],
    ) -> Result<KeyFileSubkeys, PlatformError> {
        let master = crate::kdf::derive_argon2id_key(passphrase.as_bytes(), salt)?;
        let hk = hkdf::Hkdf::<sha2::Sha256>::new(None, master.as_ref());
        let mut entry_key = Zeroizing::new([0u8; 32]);
        let mut mac_key = Zeroizing::new([0u8; 32]);
        hk.expand(ENTRY_KEY_INFO, entry_key.as_mut())
            .and_then(|()| hk.expand(FILE_MAC_INFO, mac_key.as_mut()))
            .map_err(|e| PlatformError::CustodyError(format!("key file HKDF failed: {e}")))?;
        Ok((entry_key, mac_key))
    }

    /// The AES-256-GCM associated data for an entry:
    /// `FORMAT_VERSION || key_type || role || entry_index (u32 BE)`.
    fn entry_aad(key_type: u8, role: u8, entry_index: usize) -> Result<[u8; 7], PlatformError> {
        let index = u32::try_from(entry_index).map_err(|_| {
            PlatformError::CustodyError(format!("entry index {entry_index} exceeds u32"))
        })?;
        let mut aad = [0u8; 7];
        aad[0] = FORMAT_VERSION;
        aad[1] = key_type;
        aad[2] = role;
        aad[3..].copy_from_slice(&index.to_be_bytes());
        Ok(aad)
    }

    /// Encrypts one on-disk entry (`key_type || role || nonce ||
    /// ciphertext+tag`) with a fresh nonce, binding the type byte, role byte
    /// and index as associated data.
    fn encrypt_entry(
        &self,
        key_type: u8,
        role: u8,
        entry_index: usize,
        plaintext: &[u8; KEY_LEN],
    ) -> Result<Vec<u8>, PlatformError> {
        let (nonce, ciphertext) = self.encrypt_key(key_type, role, entry_index, plaintext)?;
        let mut entry = Vec::with_capacity(ENTRY_SIZE);
        entry.push(key_type);
        entry.push(role);
        entry.extend_from_slice(&nonce);
        entry.extend_from_slice(&ciphertext);
        Ok(entry)
    }

    /// Encrypts a 32-byte private key using AES-256-GCM with a fresh nonce
    /// and the entry's associated data ([`Self::entry_aad`]).
    fn encrypt_key(
        &self,
        key_type: u8,
        role: u8,
        entry_index: usize,
        plaintext: &[u8; KEY_LEN],
    ) -> Result<([u8; NONCE_LEN], Vec<u8>), PlatformError> {
        let aad = Self::entry_aad(key_type, role, entry_index)?;
        let cipher = Aes256Gcm::new_from_slice(self.entry_key.as_ref())
            .map_err(|e| PlatformError::CustodyError(format!("cipher init failed: {e}")))?;

        let mut nonce_bytes = [0u8; NONCE_LEN];
        rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

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

    /// Decrypts the key entry stored at `entry_index`. The entry's type byte,
    /// role byte and `entry_index` are authenticated as associated data, so a
    /// flipped type or role byte or a moved entry fails here.
    fn decrypt_entry(
        &self,
        data: &[u8],
        entry_index: usize,
    ) -> Result<Zeroizing<[u8; KEY_LEN]>, PlatformError> {
        let offset = HEADER_SIZE + entry_index * ENTRY_SIZE;
        if data.len() < offset + ENTRY_SIZE {
            return Err(PlatformError::CustodyError(format!(
                "key file truncated at entry {entry_index}"
            )));
        }
        let aad = Self::entry_aad(data[offset], data[offset + 1], entry_index)?;
        let nonce_start = offset + 2;
        let ct_start = nonce_start + NONCE_LEN;
        let ct_end = ct_start + KEY_LEN + TAG_LEN;

        let nonce = Nonce::from_slice(&data[nonce_start..ct_start]);
        let ciphertext_and_tag = &data[ct_start..ct_end];

        let cipher = Aes256Gcm::new_from_slice(self.entry_key.as_ref())
            .map_err(|e| PlatformError::CustodyError(format!("cipher init failed: {e}")))?;

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
                    PlatformError::CustodyError(
                        "decryption failed (wrong passphrase, or a tampered or moved entry)".into(),
                    )
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

    /// Reads the key file from disk, checks its exact length and its
    /// whole-file tag, and returns the authenticated bytes without the tag.
    fn read_file(&self) -> Result<Vec<u8>, PlatformError> {
        let data = std::fs::read(&self.path)
            .map_err(|e| PlatformError::CustodyError(format!("failed to read key file: {e}")))?;
        check_file_shape(&data)?;
        open_file(&self.mac_key, data)
    }

    /// Appends the whole-file tag to `body` and writes it atomically.
    fn write_file(&self, body: Vec<u8>) -> Result<(), PlatformError> {
        atomic_write(&self.path, &seal_file(&self.mac_key, body)?)
    }

    /// Appends an encrypted key entry to the file and updates the entry count.
    ///
    /// Uses write-to-tmp + rename for crash-safe atomic writes (#1470).
    fn append_entry(
        &self,
        key_type: StoredKeyType,
        role: KeyRole,
        private_key: &[u8; KEY_LEN],
    ) -> Result<usize, PlatformError> {
        let _lock = self
            .file_write_lock
            .lock()
            .map_err(|_| PlatformError::CustodyError("file write lock poisoned".into()))?;
        let mut data = self.read_file()?;

        // Read current entry count.
        let count_offset = 1 + SALT_LEN;
        let current_count = u32::from_le_bytes(
            data[count_offset..count_offset + 4]
                .try_into()
                .map_err(|_| PlatformError::CustodyError("invalid entry count".into()))?,
        );

        let new_index = current_count as usize;

        // Encrypt the key, binding its type byte and index.
        let entry =
            self.encrypt_entry(key_type.to_byte(), role.to_byte(), new_index, private_key)?;
        data.extend_from_slice(&entry);

        // Update entry count.
        let new_count = current_count + 1;
        data[count_offset..count_offset + 4].copy_from_slice(&new_count.to_le_bytes());

        // Write to temp file with sync_all, then atomic rename (#1470).
        self.write_file(data)?;

        Ok(new_index)
    }

    /// Allocates the next handle ID.
    fn next_handle(&self) -> KeyHandle {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        KeyHandle::new(id)
    }

    /// The §9.10.4 P-256 pseudonym of identity `key_id` in `context_id` under
    /// `version`. A pseudonym has no private key, so this reads the identity
    /// seed, derives the point, and stores nothing; a destroyed identity fails
    /// with `KeyNotFound` (§9.10.4.A).
    async fn derive_p256_pseudonym(
        &self,
        key_id: u64,
        context_id: &[u8],
        version: PseudonymVersion,
    ) -> Result<Pseudonym, PlatformError> {
        // Software custody (§9.10.4.A): the ikm is the identity private
        // seed, never the public key. Only an identity key derives, and
        // until the identity key moves to P-256 (SCP-315) it is Ed25519, so
        // its 32-byte seed is the ikm. The `handle_map` lock is held across
        // the lookup and the file read so a concurrent `destroy_key` cannot
        // rewrite the file between them.
        let map = self.handle_map.lock().await;
        let ikm = self.derive_source_locked(&map, key_id)?;
        drop(map);
        Ok(Pseudonym::new(derive_pseudonym(&ikm, context_id, version)))
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
        match self.load_key(handle.id()).await? {
            LoadedKey::Ed25519(key_bytes) => {
                let signing_key = SigningKey::from_bytes(&key_bytes);
                Ok((key_bytes, signing_key))
            }
            other => Err(wrong_type(other.key_type(), KeyType::Ed25519)),
        }
    }

    /// The Ed25519 seed of a pseudonym-derivation source, after the role and
    /// (until SCP-315) curve check, read under a `handle_map` lock the caller
    /// holds.
    fn derive_source_locked(
        &self,
        map: &HandleMap,
        key_id: u64,
    ) -> Result<Zeroizing<[u8; KEY_LEN]>, PlatformError> {
        let role = map
            .entries
            .get(&key_id)
            .ok_or(PlatformError::KeyNotFound)?
            .role;
        let loaded = self.load_key_locked(map, key_id)?;
        crate::traits::require_derive_source(role, loaded.key_type())?;
        match loaded {
            LoadedKey::Ed25519(seed) => Ok(seed),
            other => Err(wrong_type(other.key_type(), KeyType::Ed25519)),
        }
    }

    /// Loads the key material for a handle: its file entry decrypted (and,
    /// for P-256, scalar-checked) under the `handle_map` lock, which is held
    /// across the lookup and the file read so a concurrent `destroy_key`
    /// cannot rewrite the file between them (TOCTOU).
    async fn load_key(&self, key_id: u64) -> Result<LoadedKey, PlatformError> {
        let map = self.handle_map.lock().await;
        self.load_key_locked(&map, key_id)
    }

    /// Decrypts the file entry for `key_id` under a `handle_map` lock the
    /// caller holds.
    fn load_key_locked(&self, map: &HandleMap, key_id: u64) -> Result<LoadedKey, PlatformError> {
        let MappedEntry {
            key_type, index, ..
        } = map
            .entries
            .get(&key_id)
            .copied()
            .ok_or(PlatformError::KeyNotFound)?;
        let data = self.read_file()?;
        let key_bytes = self.decrypt_entry(&data, index)?;
        Ok(match key_type {
            StoredKeyType::Ed25519 => LoadedKey::Ed25519(key_bytes),
            StoredKeyType::X25519 => LoadedKey::X25519(key_bytes),
            StoredKeyType::P256Signing => LoadedKey::P256(
                KeyType::P256Signing,
                crate::traits::p256_key_from_stored(&key_bytes)?,
            ),
            StoredKeyType::HpkeP256 => LoadedKey::P256(
                KeyType::HpkeP256,
                crate::traits::p256_key_from_stored(&key_bytes)?,
            ),
        })
    }

    /// Mints and persists a key of `key_type` in `role`.
    async fn generate(&self, key_type: KeyType, role: KeyRole) -> Result<KeyHandle, PlatformError> {
        let key_bytes = match key_type {
            KeyType::Ed25519 | KeyType::X25519 => {
                let mut key_bytes = Zeroizing::new([0u8; KEY_LEN]);
                rand::rngs::OsRng.fill_bytes(key_bytes.as_mut());
                key_bytes
            }
            KeyType::P256Signing | KeyType::HpkeP256 => {
                crate::traits::generate_p256_os_rng()?.to_scalar_bytes()
            }
        };
        let stored_type = StoredKeyType::from_key_type(key_type);

        // Hold `handle_map` across the entire append-and-insert
        // path so a concurrent `destroy_key` cannot rewrite the
        // file and shift `entry_index` between our `append_entry`
        // and the map insert. `append_entry` takes only
        // `file_write_lock`, never `handle_map`, so there is no
        // lock-ordering inversion. Mirrors the pattern in
        // `import_ed25519_signing_key`.
        let mut map = self.handle_map.lock().await;
        let index = self.append_entry(stored_type, role, &key_bytes)?;
        let handle = self.next_handle();
        map.entries.insert(
            handle.id(),
            MappedEntry {
                key_type: stored_type,
                role,
                index,
            },
        );
        drop(map);

        Ok(handle)
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

use scp_crypto::p256::P256SecretKey;
use scp_crypto::pseudonym::{PseudonymVersion, derive_pseudonym};

/// Decrypted key material for one handle. The byte arrays are zeroized on
/// drop, and `P256SecretKey` zeroizes its scalar on drop.
enum LoadedKey {
    Ed25519(Zeroizing<[u8; KEY_LEN]>),
    X25519(Zeroizing<[u8; KEY_LEN]>),
    /// A P-256 key and its public type (`P256Signing` or `HpkeP256`).
    P256(KeyType, P256SecretKey),
}

impl LoadedKey {
    const fn key_type(&self) -> KeyType {
        match self {
            Self::Ed25519(_) => KeyType::Ed25519,
            Self::X25519(_) => KeyType::X25519,
            Self::P256(key_type, _) => *key_type,
        }
    }
}

/// The error for using a key of type `actual` where `expected` is required.
const fn wrong_type(actual: KeyType, expected: KeyType) -> PlatformError {
    PlatformError::WrongKeyType { expected, actual }
}

// Trait uses RPITIT with explicit `+ Send` bound; async fn in trait
// does not guarantee Send futures, so manual impl Future is required.
#[allow(clippy::manual_async_fn)]
impl KeyCustody for FileKeyCustody {
    fn generate_keypair(
        &self,
        key_type: KeyType,
    ) -> impl Future<Output = Result<KeyHandle, PlatformError>> + Send {
        self.generate(key_type, KeyRole::Operational)
    }

    fn generate_identity_keypair(
        &self,
    ) -> impl Future<Output = Result<KeyHandle, PlatformError>> + Send {
        self.generate(KeyType::Ed25519, KeyRole::Identity)
    }

    fn sign(
        &self,
        key: &KeyHandle,
        data: &[u8],
    ) -> impl Future<Output = Result<Signature, PlatformError>> + Send {
        let key_id = key.id();
        async move {
            match self.load_key(key_id).await? {
                LoadedKey::Ed25519(key_bytes) => {
                    let signing_key = SigningKey::from_bytes(&key_bytes);
                    let signature = signing_key.sign(data);
                    Ok(Signature::new(signature.to_bytes().to_vec()))
                }
                LoadedKey::P256(KeyType::P256Signing, key) => {
                    crate::traits::sign_p256_digest(&key, data)
                }
                LoadedKey::X25519(_) => Err(wrong_type(KeyType::X25519, KeyType::Ed25519)),
                LoadedKey::P256(actual, _) => Err(wrong_type(actual, KeyType::P256Signing)),
            }
        }
    }

    fn public_key(
        &self,
        key: &KeyHandle,
    ) -> impl Future<Output = Result<PublicKey, PlatformError>> + Send {
        let key_id = key.id();
        async move {
            Ok(match self.load_key(key_id).await? {
                LoadedKey::Ed25519(key_bytes) => {
                    let signing_key = SigningKey::from_bytes(&key_bytes);
                    let vk: VerifyingKey = signing_key.verifying_key();
                    PublicKey::new(vk.to_bytes().to_vec())
                }
                LoadedKey::X25519(key_bytes) => {
                    let secret = StaticSecret::from(*key_bytes);
                    let public = X25519PublicKey::from(&secret);
                    PublicKey::new(public.to_bytes().to_vec())
                }
                LoadedKey::P256(KeyType::HpkeP256, key) => {
                    PublicKey::new(key.public_key().to_uncompressed().to_vec())
                }
                LoadedKey::P256(_, key) => {
                    PublicKey::new(key.public_key().to_compressed().to_vec())
                }
            })
        }
    }

    fn destroy_key(
        &self,
        key: &KeyHandle,
    ) -> impl Future<Output = Result<(), PlatformError>> + Send {
        let key_id = key.id();
        async move {
            let mut map = self.handle_map.lock().await;

            // Look up — do NOT mutate the map yet. Map mutation is
            // deferred until after the file rewrite succeeds, so a
            // failed `read_file` or `atomic_write` cannot orphan
            // encrypted material on disk (the in-memory map would
            // otherwise have lost the only handle pointing at it).
            let Some(&MappedEntry {
                index: removed_index,
                ..
            }) = map.entries.get(&key_id)
            else {
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
            let count_offset = 1 + SALT_LEN;
            let current_count = u32::from_le_bytes(
                data[count_offset..count_offset + 4]
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

            // Copy header (version + salt).
            new_data.extend_from_slice(&data[..count_offset]);
            // Write updated entry count.
            new_data.extend_from_slice(&new_count.to_le_bytes());

            // Copy entries before the removed one unchanged. Every entry
            // after it moves down one index, and the index is part of its
            // associated data, so each is decrypted under its old index and
            // re-encrypted (fresh nonce) under its new one.
            for i in 0..current_count as usize {
                if i == removed_index {
                    continue;
                }
                let entry_offset = HEADER_SIZE + i * ENTRY_SIZE;
                if i < removed_index {
                    new_data.extend_from_slice(&data[entry_offset..entry_offset + ENTRY_SIZE]);
                } else {
                    let key_bytes = self.decrypt_entry(&data, i)?;
                    let entry = self.encrypt_entry(
                        data[entry_offset],
                        data[entry_offset + 1],
                        i - 1,
                        &key_bytes,
                    )?;
                    new_data.extend_from_slice(&entry);
                }
            }

            // Commit to disk BEFORE mutating the in-memory map. If
            // `atomic_write` fails, the map still references the
            // (unmodified) on-disk entry — no orphaned ciphertext.
            self.write_file(new_data)?;

            // Now that disk state is updated, mutate the in-memory
            // map: drop the destroyed entry and shift indices for
            // entries that lived after it.
            map.entries.remove(&key_id);
            for entry in map.entries.values_mut() {
                if entry.index > removed_index {
                    entry.index -= 1;
                }
            }
            drop(map);

            Ok(())
        }
    }

    fn dh_agree(
        &self,
        key: &KeyHandle,
        peer_public: &[u8],
    ) -> impl Future<Output = Result<SharedSecret, PlatformError>> + Send {
        let key_id = key.id();
        let peer_public = peer_public.to_vec();
        async move {
            match self.load_key(key_id).await? {
                LoadedKey::X25519(key_bytes) => {
                    let peer = crate::traits::x25519_peer(&peer_public)?;
                    let secret = StaticSecret::from(*key_bytes);
                    let peer_key = X25519PublicKey::from(peer);
                    let shared = secret.diffie_hellman(&peer_key);
                    let shared_bytes = Zeroizing::new(shared.to_bytes());
                    Ok(SharedSecret::new(*shared_bytes))
                }
                LoadedKey::P256(KeyType::HpkeP256, key) => {
                    crate::traits::p256_dh_agree(&key, &peer_public)
                }
                LoadedKey::Ed25519(_) => Err(wrong_type(KeyType::Ed25519, KeyType::X25519)),
                LoadedKey::P256(actual, _) => Err(wrong_type(actual, KeyType::HpkeP256)),
            }
        }
    }

    fn derive_pseudonym(
        &self,
        key: &KeyHandle,
        context_id: &[u8],
    ) -> impl Future<Output = Result<Pseudonym, PlatformError>> + Send {
        let key_id = key.id();
        let context_id = context_id.to_vec();
        async move {
            self.derive_p256_pseudonym(key_id, &context_id, PseudonymVersion::Static)
                .await
        }
    }

    fn derive_rotatable_pseudonym(
        &self,
        key: &KeyHandle,
        context_id: &[u8],
        pseudonym_epoch: u64,
    ) -> impl Future<Output = Result<Pseudonym, PlatformError>> + Send {
        let key_id = key.id();
        let context_id = context_id.to_vec();
        async move {
            self.derive_p256_pseudonym(
                key_id,
                &context_id,
                PseudonymVersion::Rotatable {
                    epoch: pseudonym_epoch,
                },
            )
            .await
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
            // Only identity entries count: the imported key is the migrated
            // identity's new `#0`, and an operational entry never derives.
            for (id, entry) in &map.entries {
                if entry.key_type != StoredKeyType::Ed25519 || entry.role != KeyRole::Identity {
                    continue;
                }
                let idx = entry.index;
                // Surface decrypt failure rather than silently skipping
                // the entry. A failed decrypt at this point indicates
                // file corruption (mismatched MAC, truncated ciphertext,
                // or wrong passphrase-derived key) — not a "this entry
                // doesn't match"; treating it as the latter would
                // permit a corrupted file to silently re-grow with
                // duplicate entries on every retry.
                let existing_bytes = self.decrypt_entry(&data, idx).map_err(|e| {
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
            let index = self.append_entry(StoredKeyType::Ed25519, KeyRole::Identity, &key_bytes)?;

            let handle = self.next_handle();
            map.entries.insert(
                handle.id(),
                MappedEntry {
                    key_type: StoredKeyType::Ed25519,
                    role: KeyRole::Identity,
                    index,
                },
            );
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

    #[tokio::test]
    async fn reopen_with_wrong_passphrase_fails() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("keys.scp");

        // Create and generate a key.
        let custody = FileKeyCustody::new(&path, "correct").unwrap();
        custody.generate_keypair(KeyType::Ed25519).await.unwrap();
        drop(custody);

        // Reopen with the wrong passphrase: the file tag fails on open.
        match FileKeyCustody::new(&path, "wrong") {
            Err(PlatformError::CustodyError(_)) => {}
            Err(other) => panic!("expected CustodyError, got {other:?}"),
            Ok(_) => panic!("a wrong passphrase must not open the key file"),
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
            map.entries.insert(
                desync_id,
                MappedEntry {
                    key_type: StoredKeyType::Ed25519,
                    role: KeyRole::Operational,
                    index: 9_999,
                },
            );
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
        let handle = custody.generate_identity_keypair().await.unwrap();

        let first = custody.derive_pseudonym(&handle, b"ctx").await.unwrap();
        let second = custody.derive_pseudonym(&handle, b"ctx").await.unwrap();

        assert_eq!(
            first.public_key().to_compressed(),
            second.public_key().to_compressed()
        );
    }

    /// §25.19 Vector 30 through production software custody. Until the identity key
    /// moves to P-256 (SCP-315) the §9.10.4.A ikm is the Ed25519 seed, so the vector's identity scalar is
    /// imported as that seed; the v1 and v2 (`epoch` = 1) points and routing
    /// ids on `context-alpha` must equal the spec's literal bytes. Keying the
    /// derivation on the public key, or dropping a recipe step, fails this.
    #[tokio::test]
    async fn derive_pseudonym_reproduces_spec_25_19_vector_30() {
        fn h(s: &str) -> Vec<u8> {
            (0..s.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
                .collect()
        }
        let dir = TempDir::new().unwrap();
        let custody = make_custody(&dir, "pw");
        let scalar: [u8; 32] =
            h("32c69e4a096fadd1a8d0a21e0a97f124d5c4c8c5b15b96027beadb91c2f3ec64")
                .try_into()
                .unwrap();
        let identity = custody
            .import_ed25519_signing_key(&Zeroizing::new(scalar))
            .await
            .unwrap();
        let ctx = b"context-alpha";

        let v1 = custody.derive_pseudonym(&identity, ctx).await.unwrap();
        assert_eq!(
            v1.public_key().to_compressed(),
            h("0367e9d3809d6f9bc6854132aff27c2a399463bb516db76f844d79a7b0453c8f72").as_slice()
        );
        assert_eq!(
            v1.routing_id().as_slice(),
            h("b7faa05dea2cef1b7aff6a48fa5b7b9ffe217b25f3152d78d597bb9078e98307").as_slice()
        );

        let v2 = custody
            .derive_rotatable_pseudonym(&identity, ctx, 1)
            .await
            .unwrap();
        assert_eq!(
            v2.public_key().to_compressed(),
            h("0276c50b92dacbe6ae1a3761d007b7fe75016a4c076f214694c95d13162ff24479").as_slice()
        );
        assert_eq!(
            v2.routing_id().as_slice(),
            h("b19754a5e88c993683f99e48646ba518cba80dec0693f920c5671263650b6ae9").as_slice()
        );
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
        let count_offset = 1 + SALT_LEN;
        let count =
            u32::from_le_bytes(bytes[count_offset..count_offset + 4].try_into().unwrap()) as usize;
        for (id, entry) in &map.entries {
            let idx = entry.index;
            assert!(
                idx < count,
                "handle {id} has stale entry_index {idx} ≥ on-disk count {count}"
            );
        }
    }

    /// The P-256 group order `n`, big-endian: the smallest invalid scalar.
    const P256_ORDER: [u8; 32] = [
        0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84, 0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63,
        0x25, 0x51,
    ];

    #[tokio::test]
    async fn p256_keys_round_trip_with_type_bytes_3_and_4() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("keys.scp");
        let custody = FileKeyCustody::new(&path, "pass").unwrap();
        let sign_handle = custody
            .generate_keypair(KeyType::P256Signing)
            .await
            .unwrap();
        let hpke_handle = custody.generate_keypair(KeyType::HpkeP256).await.unwrap();
        let sign_pub = custody.public_key(&sign_handle).await.unwrap();
        let hpke_pub = custody.public_key(&hpke_handle).await.unwrap();
        assert_eq!(sign_pub.as_bytes().len(), 33);
        assert_eq!(hpke_pub.as_bytes().len(), 65);
        drop(custody);

        let data = std::fs::read(&path).unwrap();
        assert_eq!(data[HEADER_SIZE], KEY_TYPE_P256_SIGNING);
        assert_eq!(data[HEADER_SIZE + ENTRY_SIZE], KEY_TYPE_P256_HPKE);
        assert_eq!((KEY_TYPE_P256_SIGNING, KEY_TYPE_P256_HPKE), (0x03, 0x04));

        // Handles are reassigned in entry order on reopen.
        let custody = FileKeyCustody::new(&path, "pass").unwrap();
        let (sign_handle, hpke_handle) = (KeyHandle::new(1), KeyHandle::new(2));
        assert_eq!(custody.public_key(&sign_handle).await.unwrap(), sign_pub);
        assert_eq!(custody.public_key(&hpke_handle).await.unwrap(), hpke_pub);

        // 64 distinct digests: RFC 6979 gives a high raw s for about half of
        // them, so every one verifying strictly shows low-s normalisation.
        let pk = scp_crypto::p256::P256PublicKey::from_sec1(sign_pub.as_bytes()).unwrap();
        for i in 0..64u8 {
            let digest = [i; 32];
            let sig = custody.sign(&sign_handle, &digest).await.unwrap();
            scp_crypto::p256::verify_prehash_strict(&pk, &digest, sig.as_bytes()).unwrap();
        }
        let digest = [0x22u8; 32];

        let peer = P256SecretKey::from_scalar_bytes(&[6u8; 32]).unwrap();
        let own = scp_crypto::p256::P256PublicKey::from_sec1(hpke_pub.as_bytes()).unwrap();
        // An HPKE P-256 peer is exactly the 65-byte uncompressed point.
        assert!(matches!(
            custody
                .dh_agree(&hpke_handle, &peer.public_key().to_compressed())
                .await,
            Err(PlatformError::CustodyError(_))
        ));
        let shared = custody
            .dh_agree(&hpke_handle, &peer.public_key().to_uncompressed())
            .await
            .unwrap();
        assert_eq!(
            shared.as_bytes(),
            &*scp_crypto::p256::ecdh_p256(&peer, &own)
        );

        // Wrong-type use reports the handle's real type.
        assert!(matches!(
            custody
                .dh_agree(&sign_handle, &peer.public_key().to_uncompressed())
                .await,
            Err(PlatformError::WrongKeyType {
                expected: KeyType::HpkeP256,
                actual: KeyType::P256Signing
            })
        ));
        assert!(matches!(
            custody.sign(&hpke_handle, &digest).await,
            Err(PlatformError::WrongKeyType {
                expected: KeyType::P256Signing,
                actual: KeyType::HpkeP256
            })
        ));
        assert!(matches!(
            custody.export_ed25519_signing_key(&hpke_handle).await,
            Err(PlatformError::WrongKeyType {
                expected: KeyType::Ed25519,
                actual: KeyType::HpkeP256
            })
        ));
    }

    /// The type byte is authenticated. Rewriting an Ed25519 entry's type
    /// byte to X25519 makes it undecryptable instead of reinterpreting it.
    #[tokio::test]
    async fn flipped_entry_type_byte_fails_decryption() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("keys.scp");
        let custody = FileKeyCustody::new(&path, "pass").unwrap();
        custody.generate_keypair(KeyType::Ed25519).await.unwrap();
        drop(custody);

        // Re-tag the file so the entry AEAD, not the file tag, is under test.
        tamper_and_retag(&path, "pass", |data| {
            assert_eq!(data[HEADER_SIZE], KEY_TYPE_ED25519);
            data[HEADER_SIZE] = KEY_TYPE_X25519;
        });

        let custody = FileKeyCustody::new(&path, "pass").unwrap();
        let handle = KeyHandle::new(1);
        assert!(matches!(
            custody.public_key(&handle).await,
            Err(PlatformError::CustodyError(_))
        ));
        assert!(matches!(
            custody.dh_agree(&handle, &[9u8; 32]).await,
            Err(PlatformError::CustodyError(_))
        ));
    }

    /// The entry index is authenticated. Swapping two entries on disk
    /// makes both undecryptable; destroying an earlier entry re-encrypts the
    /// shifted ones so they still decrypt after reopening.
    #[tokio::test]
    async fn swapped_entries_fail_decryption_and_destroy_reencrypts_shifted() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("keys.scp");
        let custody = FileKeyCustody::new(&path, "pass").unwrap();
        let a = custody.generate_keypair(KeyType::Ed25519).await.unwrap();
        let b = custody.generate_keypair(KeyType::Ed25519).await.unwrap();
        let c = custody
            .generate_keypair(KeyType::P256Signing)
            .await
            .unwrap();
        let b_pub = custody.public_key(&b).await.unwrap();
        let c_pub = custody.public_key(&c).await.unwrap();
        custody.destroy_key(&a).await.unwrap();
        // Still readable in-process after the rewrite.
        assert_eq!(custody.public_key(&b).await.unwrap(), b_pub);
        assert_eq!(custody.public_key(&c).await.unwrap(), c_pub);
        drop(custody);

        // Reopened: the shifted entries decrypt under their new indices.
        let custody = FileKeyCustody::new(&path, "pass").unwrap();
        assert_eq!(custody.public_key(&KeyHandle::new(1)).await.unwrap(), b_pub);
        assert_eq!(custody.public_key(&KeyHandle::new(2)).await.unwrap(), c_pub);
        drop(custody);

        // Swap the two remaining entries (the type bytes move with them),
        // re-tagging so the entry AEAD, not the file tag, is under test.
        tamper_and_retag(&path, "pass", |data| {
            let (first, second) =
                data[HEADER_SIZE..HEADER_SIZE + 2 * ENTRY_SIZE].split_at_mut(ENTRY_SIZE);
            first.swap_with_slice(second);
        });

        let custody = FileKeyCustody::new(&path, "pass").unwrap();
        for id in [1, 2] {
            assert!(matches!(
                custody.public_key(&KeyHandle::new(id)).await,
                Err(PlatformError::CustodyError(_))
            ));
        }
    }

    /// Every version byte other than `FORMAT_VERSION` is refused (§17.8).
    /// Each case is a real file holding a key, with only its version byte
    /// rewritten and its file tag recomputed, so the file's length and tag
    /// still verify and the version check is what refuses it.
    #[tokio::test]
    async fn a_key_file_with_another_version_byte_is_refused() {
        for version in [0x00u8, 0x02, 0xFF] {
            let dir = TempDir::new().unwrap();
            let path = dir.path().join("keys.scp");
            let custody = FileKeyCustody::new(&path, "pass").unwrap();
            custody.generate_keypair(KeyType::Ed25519).await.unwrap();
            drop(custody);
            tamper_and_retag(&path, "pass", |data| {
                assert_eq!(data[0], FORMAT_VERSION);
                data[0] = version;
            });
            match FileKeyCustody::new(&path, "pass") {
                Err(PlatformError::CustodyError(m)) => {
                    assert!(m.contains("unsupported key file version"), "{m}");
                }
                Err(other) => {
                    panic!("version {version:#04x}: expected CustodyError, got {other:?}")
                }
                Ok(_) => panic!("version {version:#04x} must be refused"),
            }
        }
    }

    /// Rewrites the key file at `path` through `f`, which sees the bytes
    /// before the tag, and re-tags it under `passphrase`: a stand-in for an
    /// attacker who holds the passphrase, so a test can reach the per-entry
    /// AEAD checks behind the file tag.
    fn tamper_and_retag(path: &Path, passphrase: &str, f: impl FnOnce(&mut Vec<u8>)) {
        let data = std::fs::read(path).unwrap();
        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(&data[1..=SALT_LEN]);
        let (_, mac_key) = FileKeyCustody::derive_keys(passphrase, &salt).unwrap();
        let mut body = open_file(&mac_key, data).unwrap();
        f(&mut body);
        std::fs::write(path, seal_file(&mac_key, body).unwrap()).unwrap();
    }

    /// The role is persisted and authenticated. After a reopen the
    /// identity key derives and the operational Ed25519 key is refused by
    /// its role; the migrated-identity import is an identity. Rewriting the
    /// operational entry's role byte to identity fails its decryption (the
    /// role is associated data), and an unknown role byte fails the open.
    #[tokio::test]
    async fn identity_role_persists_and_is_authenticated() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("keys.scp");
        let custody = FileKeyCustody::new(&path, "pass").unwrap();
        let identity = custody.generate_identity_keypair().await.unwrap();
        let operational = custody.generate_keypair(KeyType::Ed25519).await.unwrap();
        let imported = custody
            .import_ed25519_signing_key(&Zeroizing::new([5u8; 32]))
            .await
            .unwrap();
        let first = custody.derive_pseudonym(&identity, b"ctx").await.unwrap();
        drop(custody);

        let custody = FileKeyCustody::new(&path, "pass").unwrap();
        let again = custody.derive_pseudonym(&identity, b"ctx").await.unwrap();
        assert_eq!(first, again);
        custody
            .derive_rotatable_pseudonym(&imported, b"ctx", 1)
            .await
            .unwrap();
        for result in [
            custody.derive_pseudonym(&operational, b"ctx").await,
            custody
                .derive_rotatable_pseudonym(&operational, b"ctx", 1)
                .await,
        ] {
            assert!(
                matches!(result, Err(PlatformError::NotIdentityKey)),
                "{result:?}"
            );
        }
        // The operational key still signs: the refusal is its role.
        custody.sign(&operational, b"data").await.unwrap();
        drop(custody);

        tamper_and_retag(&path, "pass", |data| {
            let role = HEADER_SIZE + ENTRY_SIZE + 1;
            assert_eq!(data[role], KeyRole::Operational.to_byte());
            data[role] = KeyRole::Identity.to_byte();
        });
        let custody = FileKeyCustody::new(&path, "pass").unwrap();
        assert!(matches!(
            custody.derive_pseudonym(&operational, b"ctx").await,
            Err(PlatformError::CustodyError(_))
        ));
        drop(custody);

        tamper_and_retag(&path, "pass", |data| data[HEADER_SIZE + 1] = 0x02);
        assert_open_fails(&path);
    }

    /// Asserts that opening the key file at `path` fails with `CustodyError`.
    fn assert_open_fails(path: &Path) {
        match FileKeyCustody::new(path, "pass") {
            Err(PlatformError::CustodyError(_)) => {}
            Err(other) => panic!("expected CustodyError, got {other:?}"),
            Ok(_) => panic!("a tampered key file must not open"),
        }
    }

    /// Lowering `entry_count` hides the last entry from the handle map;
    /// the file tag refuses it. Also covers an in-session read: the tag is
    /// checked on every read, not only on open.
    #[tokio::test]
    async fn lowered_entry_count_fails_the_file_tag() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("keys.scp");
        let custody = FileKeyCustody::new(&path, "pass").unwrap();
        let a = custody.generate_keypair(KeyType::Ed25519).await.unwrap();
        custody.generate_keypair(KeyType::Ed25519).await.unwrap();

        let mut data = std::fs::read(&path).unwrap();
        let total = data.len();
        let count_offset = 1 + SALT_LEN;
        data[count_offset..HEADER_SIZE].copy_from_slice(&1u32.to_le_bytes());
        // Drop the second entry so the length matches the lowered count.
        data.drain(HEADER_SIZE + ENTRY_SIZE..HEADER_SIZE + 2 * ENTRY_SIZE);
        assert_eq!(data.len(), total - ENTRY_SIZE);
        std::fs::write(&path, &data).unwrap();

        assert!(matches!(
            custody.public_key(&a).await,
            Err(PlatformError::CustodyError(_))
        ));
        drop(custody);
        assert_open_fails(&path);
    }

    /// A copy of a destroyed last entry appended back (with the count
    /// raised to match) fails the file tag instead of resurrecting the key.
    #[tokio::test]
    async fn replayed_destroyed_last_entry_fails_the_file_tag() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("keys.scp");
        let custody = FileKeyCustody::new(&path, "pass").unwrap();
        custody.generate_keypair(KeyType::Ed25519).await.unwrap();
        let last = custody.generate_keypair(KeyType::Ed25519).await.unwrap();
        let before = std::fs::read(&path).unwrap();
        let destroyed_entry =
            before[HEADER_SIZE + ENTRY_SIZE..HEADER_SIZE + 2 * ENTRY_SIZE].to_vec();
        custody.destroy_key(&last).await.unwrap();
        drop(custody);

        let mut data = std::fs::read(&path).unwrap();
        let tag_at = data.len() - FILE_TAG_LEN;
        let tag = data.split_off(tag_at);
        data[1 + SALT_LEN..HEADER_SIZE].copy_from_slice(&2u32.to_le_bytes());
        data.extend_from_slice(&destroyed_entry);
        data.extend_from_slice(&tag);
        std::fs::write(&path, &data).unwrap();
        assert_open_fails(&path);
        // Out of scope: restoring the whole pre-destroy file (its own tag
        // included) is a rollback, which no MAC under a fixed key detects.
    }

    /// The file must be exactly the expected length; trailing bytes
    /// after the tag are refused on open and on an in-session read.
    #[tokio::test]
    async fn trailing_bytes_fail_the_exact_length_check() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("keys.scp");
        let custody = FileKeyCustody::new(&path, "pass").unwrap();
        let a = custody.generate_keypair(KeyType::Ed25519).await.unwrap();
        let mut data = std::fs::read(&path).unwrap();
        data.push(0);
        std::fs::write(&path, &data).unwrap();

        assert!(matches!(
            custody.public_key(&a).await,
            Err(PlatformError::CustodyError(_))
        ));
        drop(custody);
        assert_open_fails(&path);
    }

    #[tokio::test]
    async fn stored_p256_scalar_zero_or_out_of_range_is_rejected() {
        for stored_type in [StoredKeyType::P256Signing, StoredKeyType::HpkeP256] {
            for scalar in [[0u8; 32], P256_ORDER, [0xFFu8; 32]] {
                let dir = TempDir::new().unwrap();
                let path = dir.path().join("keys.scp");
                let custody = FileKeyCustody::new(&path, "pass").unwrap();
                custody
                    .append_entry(stored_type, KeyRole::Operational, &scalar)
                    .unwrap();
                drop(custody);

                let custody = FileKeyCustody::new(&path, "pass").unwrap();
                let handle = KeyHandle::new(1);
                assert!(matches!(
                    custody.public_key(&handle).await,
                    Err(PlatformError::StorageError(_))
                ));
                assert!(matches!(
                    custody.sign(&handle, &[0u8; 32]).await,
                    Err(PlatformError::StorageError(_))
                ));
                assert!(matches!(
                    custody.dh_agree(&handle, &[4u8; 65]).await,
                    Err(PlatformError::StorageError(_))
                ));
            }
        }
    }
}
