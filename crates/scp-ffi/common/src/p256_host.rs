//! P-256 pseudonym point helpers every custody host calls so that no host
//! re-implements the §9.10.4 derivation (§9.10.4.A).
//!
//! Each helper returns the 33-byte SEC1 compressed pseudonym point and
//! nothing else: the private scalar exists only inside the derivation and is
//! wiped on drop, so no scalar reaches a host.
//!
//! - [`p256_pseudonym_point`] maps a `context_seed` the host computed (inside
//!   a keystore, say) to the point;
//! - [`p256_software_pseudonym_point`] runs the whole software recipe from the
//!   32-byte identity key material, so no host hand-writes the HKDF and HMAC
//!   steps.
//!
//! The `PyO3`, napi-rs and `UniFFI` exports of the same names are thin
//! wrappers over these functions, so the three bridges share one argument
//! order, one set of checks and one error code: `SCP-VALID-7005` for an input
//! of the wrong length.
//!
//! [`p256_signature_der_to_raw_low_s`] is the signature-format helper a
//! hardware host (Secure Enclave, Android Keystore) calls so that its `sign`
//! returns the 64-byte raw low-`s` `r || s` that ADR-025 criterion 1 and
//! ADR-027 criterion 2 require, with no per-language DER parser (§9.5,
//! §9.5.1).

use scp_crypto::p256::{SIGNATURE_LEN, der_to_raw, normalize_low_s};
use scp_crypto::pseudonym::{PseudonymVersion, derive_pseudonym, pseudonym_from_context_seed};
use zeroize::Zeroizing;

use crate::error_codes as codes;

/// A rejected P-256 host helper call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum P256HostError {
    /// An input had the wrong length (`SCP-VALID-7005`).
    Validation(String),
}

impl P256HostError {
    /// The error code a bridge reports for this error.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Validation(_) => codes::VALID_7005,
        }
    }

    /// The error text, which never carries key material.
    #[must_use]
    pub fn message(&self) -> &str {
        match self {
            Self::Validation(m) => m,
        }
    }
}

impl std::fmt::Display for P256HostError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.message())
    }
}

impl std::error::Error for P256HostError {}

fn exact_32(what: &str, bytes: &[u8]) -> Result<Zeroizing<[u8; 32]>, P256HostError> {
    let array: [u8; 32] = bytes.try_into().map_err(|_| {
        P256HostError::Validation(format!("{what} must be 32 bytes, got {}", bytes.len()))
    })?;
    Ok(Zeroizing::new(array))
}

/// The compressed pseudonym point of a §9.10.4 `context_seed`.
///
/// The 33-byte SEC1 point of a 32-byte `context_seed` (v1 or v2): the scalar
/// `HKDF-Expand(context_seed, "SCP-PSEUDONYM-P256-V1", 48) mod (n − 1) + 1`
/// (FIPS 186-5 A.2.1, with the label fixed inside `scp-crypto`), then `d·G`.
/// The scalar never leaves this function and is wiped on drop.
///
/// # Errors
///
/// [`P256HostError::Validation`] when `context_seed` is not 32 bytes.
pub fn p256_pseudonym_point(context_seed: &[u8]) -> Result<[u8; 33], P256HostError> {
    let seed = exact_32("context_seed", context_seed)?;
    Ok(pseudonym_from_context_seed(&seed).to_compressed())
}

/// The compressed pseudonym point a software custody derives (§9.10.4.A).
///
/// From the 32-byte identity key material `ikm`:
/// `pseudonym_secret = HKDF-SHA256(ikm, "scp-pseudonym-secret-v1")`, the v1
/// `context_seed` for `context_id` when `epoch` is `None` and the v2 seed at
/// `epoch` otherwise (§9.10.4.1), then the point. This function's copy of
/// `ikm` and every intermediate buffer `scp-crypto` owns are wiped on drop;
/// the hash crates' internal state is not, so wiping is best effort.
///
/// # Errors
///
/// [`P256HostError::Validation`] when `ikm` is not 32 bytes.
pub fn p256_software_pseudonym_point(
    ikm: &[u8],
    context_id: &[u8],
    epoch: Option<u64>,
) -> Result<[u8; 33], P256HostError> {
    let ikm = exact_32("ikm", ikm)?;
    let version = epoch.map_or(PseudonymVersion::Static, |epoch| {
        PseudonymVersion::Rotatable { epoch }
    });
    Ok(derive_pseudonym(&ikm, context_id, version).to_compressed())
}

/// The raw 64-byte low-`s` `r || s` of a strict-DER ECDSA P-256 signature.
///
/// A hardware signer (`SecKeyCreateSignature` with
/// `.ecdsaSignatureDigestX962SHA256`, `java.security.Signature` with
/// `NONEwithECDSA`) emits a DER `ECDSA-Sig-Value` whose `s` may be high.
/// §9.5 requires every signer to emit the low form, and ADR-025 criterion 1
/// and ADR-027 criterion 2 require the host's `sign` to return the raw 64
/// bytes. This parses strict DER, left-padding `r` and `s` to 32 bytes each,
/// then replaces `s` with `n − s` when `s > n/2`. It does not verify: the
/// bridge verifies every host signature strictly under the key's registered
/// public key.
///
/// # Errors
///
/// [`P256HostError::Validation`] when `der` is not strict DER, or `r` or `s`
/// is zero or not below the group order.
pub fn p256_signature_der_to_raw_low_s(der: &[u8]) -> Result<[u8; SIGNATURE_LEN], P256HostError> {
    let raw = der_to_raw(der).map_err(|e| {
        P256HostError::Validation(format!("not a strict-DER P-256 ECDSA signature: {e}"))
    })?;
    normalize_low_s(&raw)
        .map_err(|e| P256HostError::Validation(format!("not a valid P-256 ECDSA signature: {e}")))
}

/// DER encoding and `s` negation for P-256 signature fixtures, shared by
/// this module's tests and the callback-custody fake host.
#[cfg(any(test, feature = "testing"))]
pub mod der_fixture {
    /// The P-256 group order `n`, big-endian.
    const N: [u8; 32] = [
        0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84, 0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63,
        0x25, 0x51,
    ];

    /// A DER length byte. Every length here is below 128, the short form.
    fn der_len(len: usize) -> u8 {
        u8::try_from(len).unwrap_or(u8::MAX)
    }

    /// `n - s` for a big-endian `s < n`.
    #[must_use]
    pub fn negate(s: &[u8]) -> [u8; 32] {
        let mut out = [0u8; 32];
        let mut borrow = 0i16;
        for i in (0..32).rev() {
            let mut d = i16::from(N[i]) - i16::from(s[i]) - borrow;
            borrow = i16::from(d < 0);
            if d < 0 {
                d += 256;
            }
            // `d` is in 0..=255 here, so its low byte is its value.
            out[i] = d.to_le_bytes()[0];
        }
        out
    }

    /// Minimal DER encoding of a positive big-endian integer.
    fn der_int(v: &[u8]) -> Vec<u8> {
        let mut v = v;
        while v.len() > 1 && v[0] == 0 && v[1] & 0x80 == 0 {
            v = &v[1..];
        }
        let mut out = vec![0x02];
        if v[0] & 0x80 != 0 {
            out.push(der_len(v.len() + 1));
            out.push(0);
        } else {
            out.push(der_len(v.len()));
        }
        out.extend_from_slice(v);
        out
    }

    /// DER `SEQUENCE { r, s }` of two big-endian integers.
    #[must_use]
    pub fn der(r: &[u8], s: &[u8]) -> Vec<u8> {
        let body = [der_int(r), der_int(s)].concat();
        let mut out = vec![0x30, der_len(body.len())];
        out.extend_from_slice(&body);
        out
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::der_fixture::{der, negate};
    use super::*;

    fn h(s: &str) -> Vec<u8> {
        hex::decode(s).unwrap()
    }

    /// A real signature in DER converts to the raw low-`s` form that
    /// verifies strictly, whichever `s` the DER carried.
    #[test]
    fn der_helper_returns_raw_low_s_that_verifies_strictly() {
        use scp_crypto::p256::{
            P256SecretKey, sign_prehash_rfc6979_unnormalized, verify_prehash_strict,
        };
        let key = P256SecretKey::from_scalar_bytes(&[7u8; 32]).unwrap();
        let mut saw_high = false;
        for i in 0u8..32 {
            let digest = [i; 32];
            let sig = sign_prehash_rfc6979_unnormalized(&key, &digest).unwrap();
            let r: [u8; 32] = sig[..32].try_into().unwrap();
            let s: [u8; 32] = sig[32..].try_into().unwrap();
            for s_form in [s, negate(&s)] {
                saw_high |= s_form[0] & 0x80 != 0;
                let raw = p256_signature_der_to_raw_low_s(&der(&r, &s_form)).unwrap();
                verify_prehash_strict(&key.public_key(), &digest, &raw).unwrap();
            }
        }
        assert!(saw_high, "no high-s form was presented");
    }

    /// A high `s` comes back as exactly `n − s`, a low `s` unchanged, and a
    /// one-byte `r` left-padded to 32 bytes.
    #[test]
    fn der_helper_negates_exactly_a_high_s_and_left_pads() {
        let mut r = [0u8; 32];
        r[31] = 1;
        let low = [0x33u8; 32];
        let high = negate(&low);
        assert!(high[0] & 0x80 != 0);
        let out = p256_signature_der_to_raw_low_s(&der(&r, &high)).unwrap();
        assert_eq!(&out[..32], &r);
        assert_eq!(&out[32..], &low);
        let out = p256_signature_der_to_raw_low_s(&der(&r, &low)).unwrap();
        assert_eq!(&out[32..], &low);
    }

    /// Raw bytes, an empty input, trailing bytes, a zero `s` and an `s` of
    /// `n` (`negate` of zero) are `SCP-VALID-7005`.
    #[test]
    fn der_helper_rejects_non_der_and_out_of_range_input() {
        let r = [0x22u8; 32];
        let s = [0x33u8; 32];
        let mut trailing = der(&r, &s);
        trailing.push(0);
        let mut raw64 = r.to_vec();
        raw64.extend(s);
        for bad in [
            Vec::new(),
            raw64,
            trailing,
            der(&r, &[0u8; 32]),
            der(&r, &negate(&[0u8; 32])),
        ] {
            let err = p256_signature_der_to_raw_low_s(&bad).expect_err("rejected input");
            assert!(matches!(err, P256HostError::Validation(_)), "{err:?}");
            assert_eq!(err.code(), "SCP-VALID-7005");
        }
    }

    /// §25.19 Vectors 30 and 31: the identity scalar (the software `ikm`)
    /// with `context_id` "context-alpha" gives the spec's v1 point, and at
    /// epoch 1 the spec's v2 point; the spec's `context_seed_v1` gives the v1
    /// point through [`p256_pseudonym_point`].
    #[test]
    fn point_helpers_reproduce_spec_25_19_vectors_30_and_31() {
        for (ikm, seed_v1, v1, v2) in [
            (
                "32c69e4a096fadd1a8d0a21e0a97f124d5c4c8c5b15b96027beadb91c2f3ec64",
                "47ea801c24e8a4d577f04837eca0674fbbf160127fa2d1a4bb1420150b0a048b",
                "0367e9d3809d6f9bc6854132aff27c2a399463bb516db76f844d79a7b0453c8f72",
                "0276c50b92dacbe6ae1a3761d007b7fe75016a4c076f214694c95d13162ff24479",
            ),
            (
                "65d56a863d03d31ea15ade82f677058d5bbe53afedc6ff7d2b8846aa25a1bc2b",
                "5157d14a2362044199ba88d66d6a52a4bfbe0598ebe921c5fb9c362d3bebaedd",
                "0239f7c3213f3567183fd2fcf7aec6c884bc70e0e694c42053284a4b5ebef4fe2d",
                "037967cfe8d3111cdd72288ea3f444c15b710300323162fec63ca9036af73754e3",
            ),
        ] {
            let ctx = b"context-alpha";
            assert_eq!(
                hex::encode(p256_software_pseudonym_point(&h(ikm), ctx, None).unwrap()),
                v1
            );
            assert_eq!(
                hex::encode(p256_software_pseudonym_point(&h(ikm), ctx, Some(1)).unwrap()),
                v2
            );
            assert_eq!(hex::encode(p256_pseudonym_point(&h(seed_v1)).unwrap()), v1);
        }
    }

    /// A seed or `ikm` of any length but 32 is `SCP-VALID-7005`.
    #[test]
    fn point_helpers_reject_a_wrong_length_input() {
        for len in [0, 31, 33] {
            let err = p256_pseudonym_point(&vec![1; len]).expect_err("wrong-length seed");
            assert!(matches!(err, P256HostError::Validation(_)), "{err:?}");
            assert_eq!(err.code(), "SCP-VALID-7005");
            let err = p256_software_pseudonym_point(&vec![1; len], b"ctx", None)
                .expect_err("wrong-length ikm");
            assert!(matches!(err, P256HostError::Validation(_)), "{err:?}");
            assert_eq!(err.code(), "SCP-VALID-7005");
        }
    }
}
