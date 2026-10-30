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

use argon2::{Argon2, Block};
use zeroize::{Zeroize, Zeroizing};

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
/// The 64 MiB of Argon2id block memory is allocated here, not inside the
/// argon2 crate, and zeroed before it is freed (spec §17.8): the last pass's
/// blocks XOR to the value whose BLAKE2b-long hash is the derived key, so an
/// unwiped buffer leaves the key recoverable from freed heap.
///
/// # Errors
///
/// Returns [`PlatformError::CustodyError`] if the Argon2id parameters are
/// invalid or the derivation itself fails.
pub fn derive_argon2id_key(
    passphrase: &[u8],
    salt: &[u8; ARGON2_SALT_LEN],
) -> Result<Zeroizing<[u8; DERIVED_KEY_LEN]>, PlatformError> {
    let argon2 = argon2id()?;
    // Not `Zeroizing<Vec<Block>>`: `derive_into_memory` already wipes every
    // block on every exit, and `Vec`'s `Zeroize` would wipe them a second
    // time and then volatile-zero all 64 MiB byte by byte, which in an
    // unoptimized build outlasts the 10 s a racing `FileKeyCustody::new`
    // waits for the creator's header.
    let mut blocks = vec![Block::new(); argon2.params().block_count()];
    derive_into_memory(&argon2, passphrase, salt, &mut blocks)
}

/// Zeroes the Argon2id block memory it borrows when it drops, so the wipe
/// runs on a normal return, an error return, and an unwind out of argon2.
struct WipeBlocksOnDrop<'a>(&'a mut [Block]);

impl Drop for WipeBlocksOnDrop<'_> {
    fn drop(&mut self) {
        self.0.iter_mut().for_each(Zeroize::zeroize);
    }
}

/// Builds the one Argon2id instance under the normative §17.8 parameters.
fn argon2id() -> Result<Argon2<'static>, PlatformError> {
    let params = argon2::Params::new(
        ARGON2_MEMORY_KIB,
        ARGON2_ITERATIONS,
        ARGON2_PARALLELISM,
        Some(DERIVED_KEY_LEN),
    )
    .map_err(|e| PlatformError::CustodyError(format!("argon2 params error: {e}")))?;
    Ok(Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        params,
    ))
}

/// Runs the derivation over caller-owned block memory and zeroes every block
/// before returning, on the success and the error path alike.
fn derive_into_memory(
    argon2: &Argon2<'_>,
    passphrase: &[u8],
    salt: &[u8; ARGON2_SALT_LEN],
    blocks: &mut [Block],
) -> Result<Zeroizing<[u8; DERIVED_KEY_LEN]>, PlatformError> {
    let blocks = WipeBlocksOnDrop(blocks);
    let mut key = Zeroizing::new([0u8; DERIVED_KEY_LEN]);
    argon2
        .hash_password_into_with_memory(passphrase, salt, key.as_mut(), &mut *blocks.0)
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

    /// Pinned from `derive_argon2id_key` as it stood before the block memory
    /// moved to a caller-owned buffer, so a change to the derivation path
    /// cannot change any key that an existing file or database was sealed
    /// under.
    const KAT_SALT: [u8; ARGON2_SALT_LEN] = *b"scp-kdf-kat-salt";
    const KAT_PASSPHRASE: &[u8] = b"correct horse battery staple";
    const KAT_KEY: [u8; DERIVED_KEY_LEN] = [
        0xc8, 0x89, 0x28, 0xc7, 0xf6, 0xa2, 0x33, 0x0f, 0x14, 0x20, 0x99, 0x0e, 0x82, 0xde, 0x0c,
        0xf8, 0x38, 0x1a, 0xf4, 0xdd, 0x19, 0xce, 0x2b, 0x45, 0x27, 0x61, 0x13, 0x7c, 0x1e, 0xb4,
        0x25, 0x77,
    ];

    fn all_zero(blocks: &[Block]) -> bool {
        blocks.iter().all(|b| b.as_ref().iter().all(|w| *w == 0))
    }

    #[test]
    fn derivation_matches_known_answer() {
        let key = derive_argon2id_key(KAT_PASSPHRASE, &KAT_SALT).unwrap();
        assert_eq!(*key, KAT_KEY);
    }

    #[test]
    fn block_memory_is_zeroed_after_successful_derivation() {
        let argon2 = argon2id().unwrap();
        let mut blocks = vec![Block::new(); argon2.params().block_count()];
        let key = derive_into_memory(&argon2, KAT_PASSPHRASE, &KAT_SALT, &mut blocks).unwrap();
        // The derivation really ran over this buffer: the key matches the KAT.
        assert_eq!(*key, KAT_KEY);
        assert!(
            all_zero(&blocks),
            "Argon2id block memory must be zeroed after derivation"
        );
    }

    #[test]
    fn block_memory_is_zeroed_after_failed_derivation() {
        let argon2 = argon2id().unwrap();
        // One block short: the argon2 crate refuses with `MemoryTooLittle`.
        let mut filled = Block::new();
        filled.as_mut().fill(u64::MAX);
        let mut blocks = vec![filled; argon2.params().block_count() - 1];
        let err = derive_into_memory(&argon2, KAT_PASSPHRASE, &KAT_SALT, &mut blocks).unwrap_err();
        assert!(matches!(err, PlatformError::CustodyError(_)));
        assert!(
            all_zero(&blocks),
            "Argon2id block memory must be zeroed on the error path"
        );
    }

    #[test]
    fn derived_key_is_32_bytes() {
        let salt = [0u8; ARGON2_SALT_LEN];
        let key = derive_argon2id_key(b"pw", &salt).unwrap();
        assert_eq!(key.len(), 32);
    }
}
