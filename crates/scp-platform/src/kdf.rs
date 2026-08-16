//! Shared Argon2id passphrase→key derivation.
//!
//! This module is the single source of the Argon2id parameterization for the
//! entire crate (spec §17.6 / §17.8). Both [`FileKeyCustody`] (encrypted file
//! key custody) and the [`SqliteStorage`] passphrase constructor derive their
//! keys through [`derive_argon2id_key`], so there is exactly one Argon2id
//! parameter set in the codebase — never a second, divergent one.
//!
//! The parameters are NORMATIVE per spec §17.8:
//!
//! ```text
//! algorithm  = Argon2id
//! version    = 0x13            // Argon2 v1.3
//! m_cost     = 65536           // 65536 KiB = 64 MiB memory
//! t_cost     = 3               // 3 iterations
//! p_cost     = 1               // parallelism = 1
//! output_len = 32              // 32-byte derived key
//! salt       = per-derivation 16-byte salt
//! ```
//!
//! [`FileKeyCustody`]: crate::file::FileKeyCustody
//! [`SqliteStorage`]: crate::sqlite::SqliteStorage

use argon2::Argon2;
use zeroize::Zeroizing;

use crate::error::PlatformError;

/// Argon2id salt length in bytes (spec §17.6 / §17.8).
pub const ARGON2_SALT_LEN: usize = 16;

/// Argon2id iteration count (`t_cost`). OWASP minimum: 3 (spec §17.8).
pub const ARGON2_ITERATIONS: u32 = 3;

/// Argon2id memory cost in KiB (`m_cost`). 64 MiB = 65536 KiB (spec §17.8).
pub const ARGON2_MEMORY_KIB: u32 = 65_536;

/// Argon2id parallelism (`p_cost`). 1 (spec §17.8).
pub const ARGON2_PARALLELISM: u32 = 1;

/// Derived key length in bytes.
const DERIVED_KEY_LEN: usize = 32;

/// Derives a 32-byte key from a passphrase and salt using Argon2id.
///
/// This is the single, canonical Argon2id derivation for the crate. The
/// parameters (`m_cost = 65536`, `t_cost = 3`, `p_cost = 1`, version `0x13`,
/// 32-byte output) are NORMATIVE per spec §17.8 and MUST NOT be duplicated or
/// diverged from elsewhere.
///
/// The derived key is returned in [`Zeroizing`] memory so it is cleared on
/// drop. Callers MUST NOT log the passphrase, salt, or derived key.
///
/// # Errors
///
/// Returns [`PlatformError::CustodyError`] if the Argon2id parameters are
/// invalid or the derivation itself fails.
pub fn derive_argon2id_key(
    passphrase: &[u8],
    salt: &[u8; ARGON2_SALT_LEN],
) -> Result<Zeroizing<[u8; DERIVED_KEY_LEN]>, PlatformError> {
    let params = argon2::Params::new(
        ARGON2_MEMORY_KIB,
        ARGON2_ITERATIONS,
        ARGON2_PARALLELISM,
        Some(DERIVED_KEY_LEN),
    )
    .map_err(|e| PlatformError::CustodyError(format!("argon2 params error: {e}")))?;

    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);

    let mut key = Zeroizing::new([0u8; DERIVED_KEY_LEN]);
    argon2
        .hash_password_into(passphrase, salt, key.as_mut())
        .map_err(|e| PlatformError::CustodyError(format!("argon2 key derivation failed: {e}")))?;

    Ok(key)
}

/// Domain-separation label for the `SqliteKeyCustody` per-entry wrapping key.
///
/// Hashed to produce the HKDF salt, so the derived key is unrelated to any
/// other key derived from the same root material under a different label.
#[cfg(feature = "sqlite")]
const CUSTODY_ENTRY_KEY_LABEL: &[u8] = b"SCP-CUSTODY-ENTRY-KEY-V1";

/// HKDF `info` parameter for the `SqliteKeyCustody` per-entry wrapping key.
#[cfg(feature = "sqlite")]
const CUSTODY_ENTRY_KEY_INFO: &[u8] = b"scp-custody-entry";

/// Derives the [`SqliteKeyCustody`] per-entry AES-256-GCM wrapping key from a
/// caller's 32-byte root key material using HKDF-SHA-256 (RFC 5869).
///
/// ```text
/// ikm  = root_key                                   // 32 bytes
/// salt = SHA-256("SCP-CUSTODY-ENTRY-KEY-V1")        // 32 bytes
/// info = "scp-custody-entry"
/// okm  = HKDF-Expand(HKDF-Extract(salt, ikm), info, 32)
/// ```
///
/// A caller that already holds one root secret — the `scp-node` storage key
/// file, for example — uses this to obtain a wrapping key that is independent
/// of the `SQLCipher` PRAGMA key it derives from the same root. Without that
/// separation the custody entries and the database that holds them would be
/// sealed under one key, so a leak of the database key would also forge custody
/// entries. This mirrors the HKDF construction spec §17.6 specifies for the
/// `SQLCipher` key itself, with a different label.
///
/// A caller holding two independent secrets should pass the dedicated one
/// directly to `SqliteKeyCustody::new` instead of deriving here.
///
/// # Errors
///
/// Returns [`PlatformError::CustodyError`] if HKDF-Expand rejects the output
/// length. `expand` rejects only lengths above `255 * 32` bytes and this
/// function requests 32, so no input reaches that branch; it returns an error
/// rather than falling back to a fixed key, because a fallback key would be a
/// wrapping key an attacker knows.
///
/// [`SqliteKeyCustody`]: crate::sqlite::SqliteKeyCustody
#[cfg(feature = "sqlite")]
pub fn derive_custody_entry_key(
    root_key: &[u8; DERIVED_KEY_LEN],
) -> Result<Zeroizing<[u8; DERIVED_KEY_LEN]>, PlatformError> {
    use sha2::Digest as _;

    let salt = sha2::Sha256::digest(CUSTODY_ENTRY_KEY_LABEL);
    let hk = hkdf::Hkdf::<sha2::Sha256>::new(Some(salt.as_slice()), root_key);
    let mut okm = Zeroizing::new([0u8; DERIVED_KEY_LEN]);
    hk.expand(CUSTODY_ENTRY_KEY_INFO, okm.as_mut())
        .map_err(|e| PlatformError::CustodyError(format!("hkdf expand failed: {e}")))?;
    Ok(okm)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn same_passphrase_and_salt_derive_identical_key() {
        let salt = [7u8; ARGON2_SALT_LEN];
        let a = derive_argon2id_key(b"correct horse battery staple", &salt).unwrap();
        let b = derive_argon2id_key(b"correct horse battery staple", &salt).unwrap();
        assert_eq!(
            *a, *b,
            "deterministic derivation must produce identical keys"
        );
    }

    #[test]
    fn different_salt_derives_different_key() {
        let salt_a = [1u8; ARGON2_SALT_LEN];
        let salt_b = [2u8; ARGON2_SALT_LEN];
        let a = derive_argon2id_key(b"same passphrase", &salt_a).unwrap();
        let b = derive_argon2id_key(b"same passphrase", &salt_b).unwrap();
        assert_ne!(*a, *b, "different salts must produce different keys");
    }

    #[test]
    fn different_passphrase_derives_different_key() {
        let salt = [9u8; ARGON2_SALT_LEN];
        let a = derive_argon2id_key(b"passphrase one", &salt).unwrap();
        let b = derive_argon2id_key(b"passphrase two", &salt).unwrap();
        assert_ne!(*a, *b, "different passphrases must produce different keys");
    }

    #[test]
    fn parameters_match_normative_spec_values() {
        // Guards against drift from the normative spec §17.8 parameterization.
        // These are the single source of truth; FileKeyCustody and the Sqlite
        // passphrase constructor both derive through this module.
        assert_eq!(ARGON2_SALT_LEN, 16);
        assert_eq!(ARGON2_ITERATIONS, 3);
        assert_eq!(ARGON2_MEMORY_KIB, 65_536);
        assert_eq!(ARGON2_PARALLELISM, 1);
    }

    #[test]
    fn derived_key_is_32_bytes() {
        let salt = [0u8; ARGON2_SALT_LEN];
        let key = derive_argon2id_key(b"pw", &salt).unwrap();
        assert_eq!(key.len(), 32);
    }

    #[cfg(feature = "sqlite")]
    #[test]
    fn custody_entry_key_is_deterministic() {
        let root = [0x31u8; DERIVED_KEY_LEN];
        let first = derive_custody_entry_key(&root).unwrap();
        let second = derive_custody_entry_key(&root).unwrap();
        assert_eq!(
            *first, *second,
            "the same root must re-derive the same wrapping key across restarts"
        );
    }

    #[cfg(feature = "sqlite")]
    #[test]
    fn custody_entry_key_differs_from_its_root() {
        // The caller passes the same root to `SqliteStorage::new` as the
        // SQLCipher PRAGMA key, so the wrapping key must not equal it —
        // otherwise the per-entry seal and the database rest on one secret.
        let root = [0x31u8; DERIVED_KEY_LEN];
        let derived = derive_custody_entry_key(&root).unwrap();
        assert_ne!(
            *derived, root,
            "the wrapping key must be separated from the root it derives from"
        );
    }

    #[cfg(feature = "sqlite")]
    #[test]
    fn different_roots_derive_different_custody_entry_keys() {
        let a = derive_custody_entry_key(&[0x01u8; DERIVED_KEY_LEN]).unwrap();
        let b = derive_custody_entry_key(&[0x02u8; DERIVED_KEY_LEN]).unwrap();
        assert_ne!(
            *a, *b,
            "different roots must produce different wrapping keys"
        );
    }
}
