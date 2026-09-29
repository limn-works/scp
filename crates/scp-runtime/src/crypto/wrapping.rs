//! The DHKEM(P-256) wrapping keypair (spec 09 §9.16.1).
//!
//! One identity has one wrapping keypair, published as the `0xFF01` leaf
//! extension in every context the identity joins and used to open the
//! HPKE-sealed sender keys, access keys and invitations addressed to it. The
//! scalar is the only persisted half: [`WrappingKeyPair::from_secret`] derives
//! the public point once, so a stored public key can never disagree with the
//! stored scalar.

use scp_crypto::p256::{P256Error, P256SigningKey};
use zeroize::Zeroizing;

/// A DHKEM(P-256) wrapping keypair: a scalar in `[1, n − 1]` and the
/// uncompressed point `scalar · G` derived from it.
///
/// The fields are private, so a pair whose halves disagree cannot be built.
/// The scalar is zeroized when the pair drops.
pub struct WrappingKeyPair {
    secret: Zeroizing<[u8; 32]>,
    public: [u8; 65],
}

impl WrappingKeyPair {
    /// Draws a fresh keypair from the OS random source.
    #[must_use]
    pub fn generate() -> Self {
        let (public, secret) = scp_protocol::crypto::sender_keys::generate_wrapping_keypair();
        Self { secret, public }
    }

    /// Rebuilds the keypair from its 32-byte big-endian scalar, deriving the
    /// public point.
    ///
    /// # Errors
    ///
    /// [`P256Error::InvalidScalar`] if the scalar is zero or at least the
    /// group order `n`.
    pub fn from_secret(secret: Zeroizing<[u8; 32]>) -> Result<Self, P256Error> {
        let public = P256SigningKey::from_scalar_bytes(&secret)?
            .public_key()
            .to_uncompressed();
        Ok(Self { secret, public })
    }

    /// The 65-byte uncompressed public point published in `0xFF01`.
    #[must_use]
    pub const fn public(&self) -> &[u8; 65] {
        &self.public
    }

    /// The 32-byte scalar that opens HPKE ciphertexts sealed to [`Self::public`].
    #[must_use]
    pub const fn secret(&self) -> &Zeroizing<[u8; 32]> {
        &self.secret
    }
}

impl std::fmt::Debug for WrappingKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WrappingKeyPair")
            .field("public", &hex::encode(self.public))
            .field("secret", &"[REDACTED]")
            .finish()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn scalar(hex_str: &str) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(hex::decode(hex_str).unwrap().try_into().unwrap())
    }

    /// The P-256 group order `n`.
    const N_HEX: &str = "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551";

    /// `from_secret(X)` yields `X · G` for literal vectors: `1 · G` is the
    /// base point of SEC 2 §2.4.2, `2 · G` its double.
    #[test]
    fn from_secret_derives_the_public_point_times_g() {
        let one = format!("{:0>64}", "1");
        let two = format!("{:0>64}", "2");
        for (x, expected) in [
            (
                one.as_str(),
                "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296\
                 4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
            ),
            (
                two.as_str(),
                "047cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978\
                 07775510db8ed040293d9ac69f7430dbba7dade63ce982299e04b79d227873d1",
            ),
        ] {
            let pair = WrappingKeyPair::from_secret(scalar(x)).unwrap();
            assert_eq!(hex::encode(pair.public()), expected, "scalar {x}");
            assert_eq!(**pair.secret(), *scalar(x), "scalar {x}");
        }
    }

    /// `from_secret` refuses 0 and `n`, the two ends just outside `[1, n − 1]`,
    /// and accepts `n − 1`.
    #[test]
    fn from_secret_rejects_zero_and_the_group_order() {
        for (case, x) in [("zero", "00".repeat(32)), ("n", N_HEX.to_owned())] {
            assert!(
                matches!(
                    WrappingKeyPair::from_secret(scalar(&x)),
                    Err(P256Error::InvalidScalar)
                ),
                "{case}"
            );
        }
        let n_minus_1 = "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550";
        assert!(WrappingKeyPair::from_secret(scalar(n_minus_1)).is_ok());
    }

    /// A generated pair round-trips through its scalar to the same point.
    #[test]
    fn generated_pair_round_trips_through_its_secret() {
        let pair = WrappingKeyPair::generate();
        let again = WrappingKeyPair::from_secret(pair.secret().clone()).unwrap();
        assert_eq!(again.public(), pair.public());
    }

    /// The secret accessor hands out the zeroizing wrapper, never a bare array.
    #[test]
    fn secret_accessor_is_zeroizing() {
        fn zeroizing(k: &WrappingKeyPair) -> &Zeroizing<[u8; 32]> {
            k.secret()
        }
        let pair = WrappingKeyPair::generate();
        assert_eq!(zeroizing(&pair).len(), 32);
        assert!(!format!("{pair:?}").contains(&hex::encode(**pair.secret())));
    }
}
