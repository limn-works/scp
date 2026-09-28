//! HKDF-SHA-256 (RFC 5869) written out on `Hmac<Sha256>` so that every
//! secret-bearing intermediate wipes on drop.
//!
//! The `hkdf` crate keeps the PRK and each `T(i)` block in plain stack arrays
//! that are never wiped; for the pseudonym secret (§9.10.4.A) the single
//! `T(1)` block IS the secret, and for [`crate::p256::seed_to_scalar`] the
//! blocks are the scalar input. Here the PRK and every `T(i)` live in
//! [`Zeroizing`] buffers, the keyed HMAC state wipes through hmac/sha2's
//! `zeroize` feature, and each MAC output array is wiped after it is copied
//! out. Wiping is best effort: the compiler may still leave copies in
//! registers or spilled stack slots that no Rust code can reach.

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

/// SHA-256 output length (RFC 5869 `HashLen`).
pub const HASH_LEN: usize = 32;

/// `HMAC-SHA256(key, parts[0] || parts[1] || …)` into a wiping buffer.
///
/// # Panics
///
/// Never in practice: HMAC-SHA-256 accepts a key of any length.
pub fn hmac_sha256(key: &[u8], parts: &[&[u8]]) -> Zeroizing<[u8; HASH_LEN]> {
    let mac_result = <Hmac<Sha256> as KeyInit>::new_from_slice(key);
    assert!(mac_result.is_ok(), "HMAC-SHA256 accepts keys of any length");
    let mut out = Zeroizing::new([0u8; HASH_LEN]);
    if let Ok(mut mac) = mac_result {
        for part in parts {
            mac.update(part);
        }
        let mut bytes = mac.finalize().into_bytes();
        out.copy_from_slice(&bytes);
        bytes.as_mut_slice().zeroize();
    }
    out
}

/// RFC 5869 §2.2 `HKDF-Extract(salt, IKM)`. An empty `salt` is the RFC's
/// "string of `HashLen` zeros": HMAC pads both to the same block.
pub fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> Zeroizing<[u8; HASH_LEN]> {
    hmac_sha256(salt, &[ikm])
}

/// RFC 5869 §2.3 `HKDF-Expand(PRK, info, L)` for a compile-time `L`. The
/// `L ≤ 255 · HashLen` bound is checked at compile time, so the expansion has
/// no failure path.
pub fn hkdf_expand<const L: usize>(prk: &[u8; HASH_LEN], info: &[u8]) -> Zeroizing<[u8; L]> {
    const {
        assert!(
            L > 0 && L <= 255 * HASH_LEN,
            "HKDF-Expand length out of range"
        );
    };
    let mut okm = Zeroizing::new([0u8; L]);
    let mut previous: Zeroizing<[u8; HASH_LEN]> = Zeroizing::new([0u8; HASH_LEN]);
    let mut previous_len = 0usize;
    for (index, chunk) in okm.chunks_mut(HASH_LEN).enumerate() {
        // `index < 255` by the compile-time bound, so the counter fits a byte.
        let counter = [u8::try_from(index + 1).unwrap_or(u8::MAX)];
        let block = hmac_sha256(prk, &[&previous[..previous_len], info, &counter]);
        chunk.copy_from_slice(&block[..chunk.len()]);
        previous = block;
        previous_len = HASH_LEN;
    }
    okm
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn run<const L: usize>(ikm: &[u8], salt: &[u8], info: &[u8], prk_hex: &str, okm_hex: &str) {
        let prk = hkdf_extract(salt, ikm);
        assert_eq!(hex::encode(*prk), prk_hex);
        let okm = hkdf_expand::<L>(&prk, info);
        assert_eq!(hex::encode(*okm), okm_hex);

        // Equivalence with the `hkdf` crate (dev-dependency only).
        let salt_opt = if salt.is_empty() { None } else { Some(salt) };
        let (crate_prk, hk) = hkdf::Hkdf::<Sha256>::extract(salt_opt, ikm);
        assert_eq!(crate_prk.as_slice(), prk.as_slice());
        let mut crate_okm = [0u8; L];
        hk.expand(info, &mut crate_okm).unwrap();
        assert_eq!(crate_okm, *okm);
    }

    fn seq(start: u8, len: u8) -> Vec<u8> {
        (0..len).map(|i| start + i).collect()
    }

    /// RFC 5869 Appendix A.1.
    #[test]
    fn rfc5869_a1() {
        run::<42>(
            &[0x0b; 22],
            &seq(0x00, 13),
            &seq(0xf0, 10),
            "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
        );
    }

    /// RFC 5869 Appendix A.2 (longer inputs and outputs; three `T(i)` blocks).
    #[test]
    fn rfc5869_a2() {
        run::<82>(
            &seq(0x00, 80),
            &seq(0x60, 80),
            &seq(0xb0, 80),
            "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244",
            "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c\
             59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71\
             cc30c58179ec3e87c14c01d5c1f3434f1d87",
        );
    }

    /// RFC 5869 Appendix A.3 (zero-length salt and info).
    #[test]
    fn rfc5869_a3() {
        run::<42>(
            &[0x0b; 22],
            &[],
            &[],
            "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04",
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
        );
    }
}
