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
}
