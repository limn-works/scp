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
//!
//! See GitHub issue #391 and ADR-006.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use argon2::Argon2;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha256;
use std::sync::Mutex as StdMutex;
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

/// Argon2id iteration count (OWASP minimum: 3).
const ARGON2_ITERATIONS: u32 = 3;

/// Argon2id memory cost in KiB (OWASP recommendation: 64 MiB = 65536 KiB).
const ARGON2_MEMORY_KIB: u32 = 65_536;

/// Argon2id parallelism.
const ARGON2_PARALLELISM: u32 = 1;

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

/// Writes `data` to `path` atomically via a `.tmp` sibling file.
///
/// 1. Writes to `{path}.tmp` with `mode(0o600)` on Unix.
/// 2. Calls `sync_all` to flush to durable storage.
/// 3. Renames to `path` (atomic on POSIX).
/// 4. Cleans up the tmp file on any failure after creation.
fn atomic_write(path: &Path, data: &[u8]) -> Result<(), PlatformError> {
    let tmp_path = path.with_extension("tmp");

    // Write to temp file with restrictive permissions on Unix.
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp_path)
            .map_err(|e| {
                PlatformError::CustodyError(format!("failed to create temp key file: {e}"))
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
            .create(true)
            .truncate(true)
            .open(&tmp_path)
            .map_err(|e| {
                PlatformError::CustodyError(format!("failed to create temp key file: {e}"))
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

    Ok(())
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
    derived_key: Zeroizing<[u8; 32]>,
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
        })
    }

    /// Opens an existing key file at `path` and loads entry metadata.
    fn open_existing(path: &Path, passphrase: &str) -> Result<Self, PlatformError> {
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

        let entry_count = u32::from_le_bytes(
            data[1 + SALT_LEN..HEADER_SIZE]
                .try_into()
                .map_err(|_| PlatformError::CustodyError("invalid entry count bytes".into()))?,
        ) as usize;

        let expected_len = HEADER_SIZE + entry_count * ENTRY_SIZE;
        if data.len() < expected_len {
            return Err(PlatformError::CustodyError(format!(
                "key file truncated: expected {expected_len} bytes, got {}",
                data.len()
            )));
        }

        let derived_key = Self::derive_key(passphrase, &salt)?;

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
            derived_key,
            handle_map: Mutex::new(handle_map),
            next_id: AtomicU64::new(next_id),
            pseudonym_keys: Mutex::new(HashMap::new()),
            file_write_lock: StdMutex::new(()),
        })
    }

    /// Derives an AES-256 key from a passphrase and salt using Argon2id.
    fn derive_key(
        passphrase: &str,
        salt: &[u8; SALT_LEN],
    ) -> Result<Zeroizing<[u8; 32]>, PlatformError> {
        let params = argon2::Params::new(
            ARGON2_MEMORY_KIB,
            ARGON2_ITERATIONS,
            ARGON2_PARALLELISM,
            Some(32),
        )
        .map_err(|e| PlatformError::CustodyError(format!("argon2 params error: {e}")))?;

        let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);

        let mut key = Zeroizing::new([0u8; 32]);
        argon2
            .hash_password_into(passphrase.as_bytes(), salt, key.as_mut())
            .map_err(|e| {
                PlatformError::CustodyError(format!("argon2 key derivation failed: {e}"))
            })?;

        Ok(key)
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
    fn decrypt_entry(
        &self,
        data: &[u8],
        entry_index: usize,
    ) -> Result<Zeroizing<[u8; KEY_LEN]>, PlatformError> {
        let offset = HEADER_SIZE + entry_index * ENTRY_SIZE;
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
        let count_offset = 1 + SALT_LEN;
        let current_count = u32::from_le_bytes(
            data[count_offset..count_offset + 4]
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
        data[count_offset..count_offset + 4].copy_from_slice(&new_count.to_le_bytes());

        // Write to temp file with sync_all, then atomic rename (#1470).
        atomic_write(&self.path, &data)?;

        Ok(new_index)
    }

    /// Allocates the next handle ID.
    fn next_handle(&self) -> KeyHandle {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        KeyHandle::new(id)
    }

    /// Looks up handle metadata; returns key type and entry index.
    async fn lookup_handle(
        &self,
        handle: &KeyHandle,
    ) -> Result<(StoredKeyType, usize), PlatformError> {
        let map = self.handle_map.lock().await;
        map.entries
            .get(&handle.id())
            .copied()
            .ok_or(PlatformError::KeyNotFound)
    }

    /// Decrypts an Ed25519 signing key from the file for the given handle.
    async fn decrypt_ed25519_key(
        &self,
        handle: &KeyHandle,
    ) -> Result<(Zeroizing<[u8; KEY_LEN]>, SigningKey), PlatformError> {
        let (key_type, entry_index) = self.lookup_handle(handle).await?;
        if key_type != StoredKeyType::Ed25519 {
            return Err(PlatformError::WrongKeyType {
                expected: KeyType::Ed25519,
                actual: KeyType::X25519,
            });
        }
        let data = self.read_file()?;
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

use crate::pseudonym::derive_pseudonym_secret;

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

            let entry_index = self.append_entry(stored_type, &key_bytes)?;

            let handle = self.next_handle();
            let mut map = self.handle_map.lock().await;
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

            let (key_type, entry_index) = self.lookup_handle(&handle).await?;
            let data = self.read_file()?;
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
            // Remove from pseudonym keys if present.
            {
                let mut pseudonyms = self.pseudonym_keys.lock().await;
                if pseudonyms.remove(&key_id).is_some() {
                    return Ok(());
                }
            }

            let mut map = self.handle_map.lock().await;
            if map.entries.remove(&key_id).is_none() {
                return Err(PlatformError::KeyNotFound);
            }
            drop(map);
            // Note: We remove the handle mapping but leave the encrypted entry
            // in the file. The entry is unreachable and encrypted. A compaction
            // step could be added in the future but is not required for
            // correctness or security — the key material remains encrypted and
            // the handle is invalidated.
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
            let (key_type, entry_index) = self.lookup_handle(&handle).await?;

            if key_type != StoredKeyType::X25519 {
                return Err(PlatformError::WrongKeyType {
                    expected: KeyType::X25519,
                    actual: KeyType::Ed25519,
                });
            }

            let data = self.read_file()?;
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

            // HMAC-SHA256(pseudonym_secret, context_id || "scp-pseudonym")
            // Uses a secret derived from the private key via HKDF (§9.10.4A),
            // NOT the public key, to prevent membership enumeration attacks.
            let pseudonym_secret = derive_pseudonym_secret(&signing_key);
            let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(pseudonym_secret.as_slice())
                .map_err(|e| PlatformError::CustodyError(e.to_string()))?;
            mac.update(&context_id);
            mac.update(b"scp-pseudonym");
            let hmac_output = mac.finalize().into_bytes();

            let mut seed = Zeroizing::new([0u8; 32]);
            seed.copy_from_slice(&hmac_output[..32]);
            let pseudonym_signing_key = SigningKey::from_bytes(&seed);
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

            // HMAC-SHA256(pseudonym_secret, context_id || epoch_BE || "scp-pseudonym-v2")
            // Uses a secret derived from the private key via HKDF (§9.10.4A),
            // NOT the public key, to prevent membership enumeration attacks.
            let pseudonym_secret = derive_pseudonym_secret(&signing_key);
            let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(pseudonym_secret.as_slice())
                .map_err(|e| PlatformError::CustodyError(e.to_string()))?;
            mac.update(&context_id);
            mac.update(&pseudonym_epoch.to_be_bytes());
            mac.update(b"scp-pseudonym-v2");
            let hmac_output = mac.finalize().into_bytes();

            let mut seed = Zeroizing::new([0u8; 32]);
            seed.copy_from_slice(&hmac_output[..32]);
            let pseudonym_signing_key = SigningKey::from_bytes(&seed);
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
}
