//! Shared byte/string parsing helpers for the callback-custody adapters.
//!
//! The `PyO3`, napi-rs, and `UniFFI` bridges each adapt a caller-supplied
//! `KeyCustodyProvider` (a Python object / JS callback record / `UniFFI`
//! callback interface) to scp-platform's [`KeyCustody`](scp_platform::KeyCustody) trait. The provider
//! protocol speaks in raw byte arrays and opaque key-id strings; the adapters
//! must translate those into the typed [`KeyHandle`] / [`PseudonymKeypair`] /
//! `[u8; 32]` surface. That translation — and the error messages it produces on
//! malformed provider returns — is mechanism-independent: it is identical
//! across all three bridges.
//!
//! These free functions hold that shared logic so the three bridges cannot
//! drift on either the parsing rules or the error-message text. The
//! `method: &str` parameter names the originating custody operation in error
//! messages (e.g. `"KeyCustodyProvider.derive_pseudonym returned ..."`),
//! preserving the format the `PyO3` reference bridge established.
//!
//! Pure byte/string operations — no crypto, no I/O. Gated behind the `custody`
//! feature (which pulls in `scp-platform` for the typed return values) rather
//! than folded into `resolvers`, since the resolver stack is far heavier.
//!
//! See ADR-006 and the per-bridge `CallbackKeyCustody` adapters.

use scp_crypto::p256::P256PublicKey;
use scp_platform::error::PlatformError;
use scp_platform::traits::{KeyHandle, PseudonymKeypair};

/// Parses a numeric key-id string (as returned by a `KeyCustodyProvider`) into
/// a [`KeyHandle`].
///
/// Only the canonical decimal form is accepted (the form `u64::to_string`
/// writes, which is what every bridge sends back to the host), so one host key
/// has exactly one spelling: `"007"`, `"+7"` and `" 7"` are rejected rather
/// than aliased to handle 7.
///
/// # Errors
///
/// Returns [`PlatformError::CustodyError`] if `key_id` does not parse as a
/// `u64`, or parses but is not in canonical decimal form.
pub fn parse_handle(method: &str, key_id: &str) -> Result<KeyHandle, PlatformError> {
    let id = key_id.parse::<u64>().map_err(|_| {
        PlatformError::CustodyError(format!(
            "KeyCustodyProvider.{method} returned a non-numeric key_id: {key_id}"
        ))
    })?;
    if id.to_string() != key_id {
        return Err(PlatformError::CustodyError(format!(
            "KeyCustodyProvider.{method} returned a non-canonical key_id: {key_id:?}"
        )));
    }
    Ok(KeyHandle::new(id))
}

/// Coerces a 32-byte custody return into a fixed array.
///
/// # Errors
///
/// Returns [`PlatformError::CustodyError`] if `bytes` is not exactly 32 bytes.
pub fn expect_32(method: &str, bytes: &[u8]) -> Result<[u8; 32], PlatformError> {
    bytes.try_into().map_err(|_| {
        PlatformError::CustodyError(format!(
            "KeyCustodyProvider.{method} returned {} bytes, expected 32",
            bytes.len()
        ))
    })
}

/// Length of the pseudonym public key a provider returns: a SEC1 compressed
/// P-256 point (§9.10.4).
pub const PSEUDONYM_PUBLIC_KEY_LEN: usize = scp_crypto::p256::COMPRESSED_POINT_LEN;

/// Validates a structured `derive_pseudonym`-style return (`public_key`,
/// `key_id`) into a [`PseudonymKeypair`].
///
/// The host returns the two fields separately; no byte-splitting happens here,
/// so a key id can never be read as part of the point or the reverse.
///
/// # Errors
///
/// Returns [`PlatformError::CustodyError`] if `key_id` is not numeric or
/// `public_key` is not a 33-byte SEC1 compressed point on P-256 (a provider
/// still returning a 32-byte Ed25519 pseudonym fails here).
pub fn parse_pseudonym(
    method: &str,
    public_key: &[u8],
    key_id: &str,
) -> Result<PseudonymKeypair, PlatformError> {
    let handle = parse_handle(method, key_id)?;
    PseudonymKeypair::new(public_key, handle)
        .map_err(|e| PlatformError::CustodyError(format!("KeyCustodyProvider.{method}: {e}")))
}

/// The pseudonym handles a callback custody adapter has derived, each bound to
/// the P-256 point the host returned for it.
///
/// A bridge [`bind`](Self::bind)s a handle after checking that the host's own
/// `public_key(key_id)` reports the same point, and routes every `sign` through
/// [`check_sign_input`](Self::check_sign_input) and
/// [`check_signature`](Self::check_signature) so a pseudonym signature is a
/// strict §9.5 signature under the bound point. A host that returns a high-`s`
/// or otherwise invalid signature fails closed; the bridge never normalizes it.
#[derive(Debug, Default)]
pub struct PseudonymBindings {
    points: dashmap::DashMap<u64, P256PublicKey>,
}

impl PseudonymBindings {
    /// Binds `pseudonym`'s handle to its point once the host's
    /// `public_key(key_id)` return (`host_public_key`) matches it byte for byte.
    /// Re-binding the same point to the same handle is a no-op.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformError::CustodyError`] if `host_public_key` differs from
    /// the derived point, or if the handle is already bound to a different
    /// point (a host that reuses one key id for two pseudonyms).
    pub fn bind(
        &self,
        method: &str,
        pseudonym: &PseudonymKeypair,
        host_public_key: &[u8],
    ) -> Result<(), PlatformError> {
        let derived = pseudonym.public_key().as_bytes();
        if host_public_key != derived {
            return Err(PlatformError::CustodyError(format!(
                "KeyCustodyProvider.{method}: public_key(key_id) does not match the derived \
                 pseudonym point"
            )));
        }
        let point = P256PublicKey::from_sec1(derived).map_err(|e| {
            PlatformError::CustodyError(format!("KeyCustodyProvider.{method}: {e}"))
        })?;
        match self.points.entry(pseudonym.key_handle().id()) {
            dashmap::Entry::Occupied(existing) if *existing.get() != point => {
                Err(PlatformError::CustodyError(format!(
                    "KeyCustodyProvider.{method}: key_id {} is already bound to a different \
                     pseudonym point",
                    pseudonym.key_handle().id()
                )))
            }
            dashmap::Entry::Occupied(_) => Ok(()),
            dashmap::Entry::Vacant(slot) => {
                slot.insert(point);
                Ok(())
            }
        }
    }

    /// Destroys `key` through `host_destroy` with its binding removed first.
    ///
    /// The binding is removed before the host call, so a concurrent re-derive
    /// of the same handle that binds while the host destroys lands after the
    /// removal and survives it. When `host_destroy` fails, the removed point is
    /// bound again unless a concurrent re-derive has already bound one.
    ///
    /// # Errors
    ///
    /// Returns the error of `host_destroy`.
    pub async fn destroy_unbound(
        &self,
        key: &KeyHandle,
        host_destroy: impl core::future::Future<Output = Result<(), PlatformError>>,
    ) -> Result<(), PlatformError> {
        let removed = self.points.remove(&key.id()).map(|(_, point)| point);
        let result = host_destroy.await;
        if let (Err(_), Some(point)) = (&result, removed) {
            self.points.entry(key.id()).or_insert(point);
        }
        result
    }

    /// Whether `key` is bound to a pseudonym point. Tests read it from inside
    /// a host `destroy_key` to prove the bridge unbinds before calling the host.
    #[cfg(any(test, feature = "testing"))]
    #[must_use]
    pub fn is_bound(&self, key: &KeyHandle) -> bool {
        self.points.contains_key(&key.id())
    }

    /// Checks the input to a `sign` call. Returns the bound point and the
    /// digest when `key` is a pseudonym handle, and `None` for any other handle.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformError::CustodyError`] if `key` is a pseudonym handle
    /// and `data` is not a 32-byte digest (§9.5 prehash).
    pub fn check_sign_input(
        &self,
        key: &KeyHandle,
        data: &[u8],
    ) -> Result<Option<(P256PublicKey, [u8; 32])>, PlatformError> {
        let Some(point) = self.points.get(&key.id()).map(|p| *p) else {
            return Ok(None);
        };
        let digest: [u8; 32] = data.try_into().map_err(|_| {
            PlatformError::CustodyError(format!(
                "pseudonym key {} signs only a 32-byte digest, got {} bytes",
                key.id(),
                data.len()
            ))
        })?;
        Ok(Some((point, digest)))
    }

    /// Verifies a host signature from a pseudonym handle under its bound point.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformError::CustodyError`] unless `signature` is a 64-byte
    /// low-`s` `r ‖ s` that verifies strictly over `digest`.
    pub fn check_signature(
        point: &P256PublicKey,
        digest: &[u8; 32],
        signature: &[u8],
    ) -> Result<(), PlatformError> {
        scp_crypto::p256::verify_prehash_strict(point, digest, signature).map_err(|e| {
            PlatformError::CustodyError(format!(
                "KeyCustodyProvider.sign returned an invalid pseudonym signature: {e}"
            ))
        })
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// Drives a future to completion on a current-thread runtime.
    fn block_on<F: core::future::Future>(future: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("runtime")
            .block_on(future)
    }

    /// The binding is gone during the host destroy, so a re-derive binding in
    /// that window survives a successful destroy; a failed destroy restores
    /// the removed binding.
    #[test]
    fn destroy_unbound_unbinds_before_the_host_call() {
        let bindings = PseudonymBindings::default();
        let pseudo = parse_pseudonym("derive_pseudonym", &REFERENCE_POINT, "9").expect("valid");
        let handle = pseudo.key_handle();
        bindings
            .bind("derive_pseudonym", &pseudo, &REFERENCE_POINT)
            .expect("bind");

        // A re-derive that binds while the host destroys survives the destroy.
        block_on(bindings.destroy_unbound(handle, async {
            assert!(
                bindings
                    .check_sign_input(handle, &[0u8; 32])
                    .expect("unbound during the host call")
                    .is_none(),
                "the binding is removed before the host call"
            );
            bindings
                .bind("derive_pseudonym", &pseudo, &REFERENCE_POINT)
                .expect("concurrent re-derive binds");
            Ok(())
        }))
        .expect("destroy");
        assert!(
            bindings
                .check_sign_input(handle, &[0u8; 32])
                .expect("bound")
                .is_some(),
            "the re-derive's binding survives"
        );

        // A failed host destroy keeps the key, so its binding comes back.
        let msg = custody_msg(
            block_on(bindings.destroy_unbound(handle, async {
                Err(PlatformError::CustodyError("host refused".to_owned()))
            }))
            .expect_err("host failure propagates"),
        );
        assert_eq!(msg, "host refused");
        assert!(
            bindings
                .check_sign_input(handle, &[0u8; 32])
                .expect("bound")
                .is_some(),
            "a failed destroy restores the binding"
        );

        // A successful destroy leaves it unbound.
        block_on(bindings.destroy_unbound(handle, async { Ok(()) })).expect("destroy");
        assert!(
            bindings
                .check_sign_input(handle, &[0u8; 32])
                .expect("unbound")
                .is_none()
        );
    }

    /// §25.2 reference key, compressed:
    /// `033b1cac23f45cf1cdfdf0b32f8f777b99166c1b69649c2295b1517883d47f3027`.
    const REFERENCE_POINT: [u8; 33] = [
        0x03, 0x3b, 0x1c, 0xac, 0x23, 0xf4, 0x5c, 0xf1, 0xcd, 0xfd, 0xf0, 0xb3, 0x2f, 0x8f, 0x77,
        0x7b, 0x99, 0x16, 0x6c, 0x1b, 0x69, 0x64, 0x9c, 0x22, 0x95, 0xb1, 0x51, 0x78, 0x83, 0xd4,
        0x7f, 0x30, 0x27,
    ];

    #[test]
    fn parse_handle_accepts_numeric() {
        let handle = parse_handle("generate_keypair", "42").expect("numeric key_id parses");
        assert_eq!(handle.id(), 42);
    }

    #[test]
    fn parse_handle_rejects_non_numeric() {
        let err = parse_handle("generate_keypair", "not-a-number")
            .expect_err("non-numeric key_id is rejected");
        match err {
            PlatformError::CustodyError(msg) => {
                assert_eq!(
                    msg,
                    "KeyCustodyProvider.generate_keypair returned a non-numeric key_id: not-a-number"
                );
            }
            other => panic!("expected CustodyError, got {other:?}"),
        }
    }

    #[test]
    fn expect_32_accepts_exactly_32() {
        let bytes = [7u8; 32];
        let arr = expect_32("dh_agree", &bytes).expect("32 bytes coerces");
        assert_eq!(arr, bytes);
    }

    #[test]
    fn expect_32_rejects_wrong_length_with_exact_message() {
        let bytes = [0u8; 31];
        let err = expect_32("dh_agree", &bytes).expect_err("31 bytes is rejected");
        match err {
            PlatformError::CustodyError(msg) => {
                assert_eq!(
                    msg,
                    "KeyCustodyProvider.dh_agree returned 31 bytes, expected 32"
                );
            }
            other => panic!("expected CustodyError, got {other:?}"),
        }
    }

    fn custody_msg(err: PlatformError) -> String {
        match err {
            PlatformError::CustodyError(msg) => msg,
            other => panic!("expected CustodyError, got {other:?}"),
        }
    }

    #[test]
    fn parse_pseudonym_accepts_point_and_key_id() {
        let pseudo = parse_pseudonym("derive_pseudonym", &REFERENCE_POINT, "123")
            .expect("valid pseudonym parses");
        assert_eq!(pseudo.public_key().as_bytes(), &REFERENCE_POINT);
        assert_eq!(pseudo.key_handle().id(), 123);
    }

    /// Every malformed point reaches a distinct rejection path in
    /// `P256PublicKey::from_sec1` (length, prefix, curve equation).
    #[test]
    fn parse_pseudonym_rejects_invalid_points() {
        let reject = |bytes: &[u8]| {
            custody_msg(
                parse_pseudonym("derive_pseudonym", bytes, "7")
                    .expect_err("invalid point rejected"),
            )
        };
        // Wrong lengths: 32 (a legacy Ed25519 key) and 34.
        assert_eq!(
            reject(&REFERENCE_POINT[1..]),
            "KeyCustodyProvider.derive_pseudonym: custody error: pseudonym public key must be a \
             33-byte compressed P-256 point, got 32 bytes"
        );
        let mut long = REFERENCE_POINT.to_vec();
        long.push(0x00);
        assert!(reject(&long).contains("got 34 bytes"));
        // Bad prefix: 33 bytes led by 0x04 (the uncompressed tag).
        let mut bad_prefix = REFERENCE_POINT;
        bad_prefix[0] = 0x04;
        assert!(reject(&bad_prefix).contains("invalid leading byte 0x04"));
        // Off-curve x: x = 1 is a field element, but 1 - 3 + b is a quadratic
        // non-residue mod p, so no y exists.
        let mut off_curve = [0u8; 33];
        off_curve[0] = 0x02;
        off_curve[32] = 0x01;
        assert!(reject(&off_curve).contains("not on the curve"));
        // x = 2^256 - 1 is not a field element at all.
        let mut not_field = [0xFFu8; 33];
        not_field[0] = 0x02;
        assert!(reject(&not_field).contains("not on the curve"));
    }

    /// The fail-open counterexample against the old concatenated return: a
    /// 32-byte Ed25519 key `K` with key id `"22"` concatenated to `K || "22"`,
    /// whose first 33 bytes `K || 0x32` happen to be a valid P-256 point, so the
    /// split parse accepted it as a pseudonym with handle 2. With separate fields
    /// the 32-byte key is rejected on length, and a host that forwards the
    /// concatenated point anyway fails the `public_key(key_id)` binding.
    #[test]
    fn legacy_concatenation_counterexample_is_rejected() {
        let legacy_key: [u8; 32] = [
            0x02, 0x6e, 0x34, 0x0b, 0x9c, 0xff, 0xb3, 0x7a, 0x98, 0x9c, 0xa5, 0x44, 0xe6, 0xbb,
            0x78, 0x0a, 0x2c, 0x78, 0x90, 0x1d, 0x3f, 0xb3, 0x37, 0x38, 0x76, 0x85, 0x11, 0xa3,
            0x06, 0x17, 0xaf, 0xa0,
        ];
        let msg = custody_msg(
            parse_pseudonym("derive_pseudonym", &legacy_key, "22").expect_err("32 bytes rejected"),
        );
        assert!(msg.contains("got 32 bytes"), "{msg}");

        let mut old_split_point = legacy_key.to_vec();
        old_split_point.push(b'2');
        let pseudo = parse_pseudonym("derive_pseudonym", &old_split_point, "2")
            .expect("the old split's first 33 bytes are a valid point");
        let bindings = PseudonymBindings::default();
        let msg = custody_msg(
            bindings
                .bind("derive_pseudonym", &pseudo, &legacy_key)
                .expect_err("host key 2 is not that point"),
        );
        assert!(
            msg.contains("does not match the derived pseudonym point"),
            "{msg}"
        );
        assert!(
            bindings
                .check_sign_input(pseudo.key_handle(), &[0u8; 32])
                .expect("unbound handle")
                .is_none(),
            "a failed bind leaves the handle unbound"
        );
    }

    #[test]
    fn parse_pseudonym_rejects_non_numeric_key_id() {
        let msg = custody_msg(
            parse_pseudonym("derive_rotatable_pseudonym", &REFERENCE_POINT, "xyz")
                .expect_err("non-numeric key_id is rejected"),
        );
        assert_eq!(
            msg,
            "KeyCustodyProvider.derive_rotatable_pseudonym returned a non-numeric key_id: xyz"
        );
    }

    #[test]
    fn bind_rejects_rebinding_a_key_id_to_another_point() {
        let bindings = PseudonymBindings::default();
        let first = parse_pseudonym("derive_pseudonym", &REFERENCE_POINT, "5").expect("valid");
        bindings
            .bind("derive_pseudonym", &first, &REFERENCE_POINT)
            .expect("bind");
        let other = signing_key().public_key().to_compressed();
        let second = parse_pseudonym("derive_pseudonym", &other, "5").expect("valid");
        let msg = custody_msg(
            bindings
                .bind("derive_pseudonym", &second, &other)
                .expect_err("rebinding is rejected"),
        );
        assert!(
            msg.contains("already bound to a different pseudonym point"),
            "{msg}"
        );
        block_on(bindings.destroy_unbound(first.key_handle(), async { Ok(()) })).expect("destroy");
        bindings
            .bind("derive_pseudonym", &second, &other)
            .expect("bind after destroy");
    }

    const N: [u8; 32] = [
        0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63,
        0x25, 0x51,
    ];

    fn signing_key() -> scp_crypto::p256::P256SigningKey {
        scp_crypto::p256::P256SigningKey::from_seed(b"SCP-FFI-COMMON-TEST", &[9u8; 32])
            .expect("seed maps to a scalar")
    }

    /// `n - s` for a big-endian 32-byte `s < n`.
    fn negate_s(s: &[u8]) -> [u8; 32] {
        let mut out = [0u8; 32];
        let mut borrow = 0i16;
        for i in (0..32).rev() {
            let mut d = i16::from(N[i]) - i16::from(s[i]) - borrow;
            borrow = i16::from(d < 0);
            if d < 0 {
                d += 256;
            }
            out[i] = u8::try_from(d).expect("byte");
        }
        out
    }

    #[test]
    fn pseudonym_sign_is_checked_strictly_against_the_bound_point() {
        let key = signing_key();
        let point = key.public_key().to_compressed();
        let pseudo = parse_pseudonym("derive_pseudonym", &point, "9").expect("valid");
        let bindings = PseudonymBindings::default();
        bindings
            .bind("derive_pseudonym", &pseudo, &point)
            .expect("bind");
        let handle = pseudo.key_handle();

        // Non-pseudonym handles pass through unchecked.
        assert!(
            bindings
                .check_sign_input(&KeyHandle::new(10), b"any length")
                .expect("identity handle")
                .is_none()
        );
        // A pseudonym handle signs only a 32-byte digest.
        let msg = custody_msg(
            bindings
                .check_sign_input(handle, &[0u8; 12])
                .expect_err("12-byte input rejected"),
        );
        assert_eq!(
            msg,
            "pseudonym key 9 signs only a 32-byte digest, got 12 bytes"
        );

        let digest = [0x5au8; 32];
        let (bound, checked) = bindings
            .check_sign_input(handle, &digest)
            .expect("32-byte digest")
            .expect("pseudonym handle is bound");
        assert_eq!(checked, digest);
        let good = scp_crypto::p256::sign_prehash_rfc6979(&key, &digest).expect("sign");
        PseudonymBindings::check_signature(&bound, &digest, &good).expect("low-s verifies");

        // High-s form of the same signature: valid ECDSA, rejected, not normalized.
        let mut high = good;
        high[32..].copy_from_slice(&negate_s(&good[32..]));
        let msg = custody_msg(
            PseudonymBindings::check_signature(&bound, &digest, &high).expect_err("high-s"),
        );
        assert!(msg.contains("high-s"), "{msg}");
        assert!(
            scp_crypto::p256::verify_prehash_lenient(&bound, &digest, &high).is_ok(),
            "the high-s mutant is otherwise a valid signature"
        );

        // Wrong length and wrong key.
        let msg = custody_msg(
            PseudonymBindings::check_signature(&bound, &digest, &good[..63]).expect_err("63"),
        );
        assert!(msg.contains("must be 64 bytes, got 63"), "{msg}");
        let other = scp_crypto::p256::P256PublicKey::from_sec1(&REFERENCE_POINT).expect("point");
        let msg = custody_msg(
            PseudonymBindings::check_signature(&other, &digest, &good).expect_err("wrong key"),
        );
        assert!(msg.contains("does not verify"), "{msg}");

        block_on(bindings.destroy_unbound(handle, async { Ok(()) })).expect("destroy");
        assert!(
            bindings
                .check_sign_input(handle, &[0u8; 12])
                .expect("unbound")
                .is_none()
        );
    }

    #[test]
    fn parse_handle_rejects_non_canonical_ids() {
        for id in ["007", "+7", "00"] {
            let msg = custody_msg(
                parse_handle("derive_pseudonym", id).expect_err("non-canonical id rejected"),
            );
            assert_eq!(
                msg,
                format!(
                    "KeyCustodyProvider.derive_pseudonym returned a non-canonical key_id: {id:?}"
                )
            );
        }
        // `u64::from_str` already refuses surrounding whitespace.
        for id in [" 7", "7 "] {
            let msg = custody_msg(parse_handle("derive_pseudonym", id).expect_err("rejected"));
            assert!(msg.contains("non-numeric key_id"), "{msg}");
        }
        assert_eq!(parse_handle("m", "0").expect("canonical zero").id(), 0);
        assert_eq!(
            parse_handle("m", "18446744073709551615")
                .expect("u64::MAX")
                .id(),
            u64::MAX
        );
    }

    /// B1: a host that returns the same key id for the same pseudonym (the
    /// §9.10.4 determinism the provider interfaces require) re-binds cleanly.
    #[test]
    fn rebinding_the_same_point_under_the_same_id_is_ok() {
        let bindings = PseudonymBindings::default();
        let pseudo = parse_pseudonym("derive_pseudonym", &REFERENCE_POINT, "5").expect("valid");
        bindings
            .bind("derive_pseudonym", &pseudo, &REFERENCE_POINT)
            .expect("first bind");
        bindings
            .bind("derive_pseudonym", &pseudo, &REFERENCE_POINT)
            .expect("same point re-binds");
        let (point, _) = bindings
            .check_sign_input(pseudo.key_handle(), &[0u8; 32])
            .expect("32-byte digest")
            .expect("still bound");
        assert_eq!(point.to_compressed(), REFERENCE_POINT);
    }
}
