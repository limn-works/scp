//! Shared key-type registry and P-256 validation for the callback-custody
//! adapters.
//!
//! The `PyO3`, napi-rs, and `UniFFI` bridges adapt a host `KeyCustodyProvider`
//! to [`KeyCustody`](scp_platform::KeyCustody). The host speaks in key-type
//! strings and raw bytes, so each adapter must remember what type every handle
//! it minted is (the host protocol has no "what type is this key" call) and
//! must not trust host-returned P-256 material. This module holds that logic
//! once, so the three bridges apply identical rules:
//!
//! - [`key_type_str`] maps a [`KeyType`] to the host protocol string.
//! - [`CallbackKeyRegistry`] records the [`KeyType`] of every handle the
//!   adapter minted, and for P-256 keys the public key the host reported at
//!   generation. A handle the adapter did not mint (a pseudonym handle, or one
//!   minted by another adapter instance) is unregistered and follows the
//!   32-byte family rules below.
//! - [`p256_public_key`] requires the exact SEC1 length per type and a valid
//!   curve point.
//! - [`p256_host_signature`] accepts a host signature as raw `r ‖ s` or DER,
//!   converts DER, normalises to low-`s`, and accepts it only when it verifies
//!   strictly against the registered public key. Any failure is an error,
//!   never a value.
//!
//! See ADR-006 and the per-bridge `CallbackKeyCustody` adapters.

use std::collections::HashMap;
use std::sync::Mutex;

use scp_crypto::p256::{
    COMPRESSED_POINT_LEN, P256PublicKey, SIGNATURE_LEN, UNCOMPRESSED_POINT_LEN, der_to_raw,
    normalize_low_s, verify_prehash_strict,
};
use scp_platform::error::PlatformError;
use scp_platform::traits::{KeyHandle, KeyType, PublicKey, SharedSecret, Signature};

/// The host-protocol string for a key type, passed to the provider's
/// `generate_keypair`.
#[must_use]
pub const fn key_type_str(key_type: KeyType) -> &'static str {
    match key_type {
        KeyType::Ed25519 => "ed25519",
        KeyType::X25519 => "x25519",
        KeyType::P256Signing => "p256",
        KeyType::HpkeP256 => "hpke-p256",
    }
}

/// What the adapter knows about a handle it minted.
#[derive(Debug, Clone)]
pub enum RegisteredKey {
    /// An Ed25519 key.
    Ed25519,
    /// An X25519 key.
    X25519,
    /// A P-256 signing key and the public key the host reported for it.
    P256Signing(P256PublicKey),
    /// A P-256 HPKE key and the public key the host reported for it.
    HpkeP256(P256PublicKey),
}

impl RegisteredKey {
    /// The key's [`KeyType`].
    #[must_use]
    pub const fn key_type(&self) -> KeyType {
        match self {
            Self::Ed25519 => KeyType::Ed25519,
            Self::X25519 => KeyType::X25519,
            Self::P256Signing(_) => KeyType::P256Signing,
            Self::HpkeP256(_) => KeyType::HpkeP256,
        }
    }

    /// The typed error for using this key where `expected` is required.
    #[must_use]
    pub const fn wrong_type(&self, expected: KeyType) -> PlatformError {
        PlatformError::WrongKeyType {
            expected,
            actual: self.key_type(),
        }
    }
}

/// Handle → [`RegisteredKey`] for the handles one adapter instance minted.
#[derive(Debug, Default)]
pub struct CallbackKeyRegistry {
    keys: Mutex<HashMap<u64, RegisteredKey>>,
}

impl CallbackKeyRegistry {
    /// An empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(
        &self,
    ) -> Result<std::sync::MutexGuard<'_, HashMap<u64, RegisteredKey>>, PlatformError> {
        self.keys.lock().map_err(|_| {
            PlatformError::CustodyError("callback custody key registry lock poisoned".into())
        })
    }

    /// Records a minted handle.
    ///
    /// # Errors
    ///
    /// [`PlatformError::CustodyError`] if the registry lock is poisoned, or if
    /// the host reused a key id this adapter already holds.
    pub fn register(&self, handle: KeyHandle, key: RegisteredKey) -> Result<(), PlatformError> {
        match self.lock()?.entry(handle.id()) {
            std::collections::hash_map::Entry::Occupied(_) => {
                Err(PlatformError::CustodyError(format!(
                    "KeyCustodyProvider.generate_keypair returned key_id {} that is already live",
                    handle.id()
                )))
            }
            std::collections::hash_map::Entry::Vacant(slot) => {
                slot.insert(key);
                Ok(())
            }
        }
    }

    /// The registered key for a handle, or `None` if this adapter did not
    /// mint it.
    ///
    /// # Errors
    ///
    /// [`PlatformError::CustodyError`] if the registry lock is poisoned.
    pub fn get(&self, handle: &KeyHandle) -> Result<Option<RegisteredKey>, PlatformError> {
        Ok(self.lock()?.get(&handle.id()).cloned())
    }

    /// Forgets a handle after the host destroyed its key.
    ///
    /// # Errors
    ///
    /// [`PlatformError::CustodyError`] if the registry lock is poisoned.
    pub fn remove(&self, handle: &KeyHandle) -> Result<(), PlatformError> {
        self.lock()?.remove(&handle.id());
        Ok(())
    }
}

/// Validates a host-reported P-256 public key.
///
/// It must be exactly 33 bytes (compressed) for [`KeyType::P256Signing`],
/// exactly 65 bytes (uncompressed) for [`KeyType::HpkeP256`], and a point on
/// the curve that is not the identity.
///
/// # Errors
///
/// [`PlatformError::CustodyError`] on a wrong length, a bad point, or a
/// non-P-256 `key_type`.
pub fn p256_public_key(
    method: &str,
    key_type: KeyType,
    bytes: &[u8],
) -> Result<P256PublicKey, PlatformError> {
    let expected_len = match key_type {
        KeyType::P256Signing => COMPRESSED_POINT_LEN,
        KeyType::HpkeP256 => UNCOMPRESSED_POINT_LEN,
        KeyType::Ed25519 | KeyType::X25519 => {
            return Err(PlatformError::CustodyError(format!(
                "{key_type:?} is not a P-256 key type"
            )));
        }
    };
    if bytes.len() != expected_len {
        return Err(PlatformError::CustodyError(format!(
            "KeyCustodyProvider.{method} returned {} bytes for a {} key, expected {expected_len}",
            bytes.len(),
            key_type_str(key_type)
        )));
    }
    P256PublicKey::from_sec1(bytes).map_err(|e| {
        PlatformError::CustodyError(format!(
            "KeyCustodyProvider.{method} returned an invalid P-256 public key: {e}"
        ))
    })
}

/// The adapter's public key for a registered P-256 key: the host's current
/// answer, which must be well formed and equal to the key reported at
/// generation.
///
/// # Errors
///
/// [`PlatformError::CustodyError`] when the host's bytes are malformed or the
/// key changed.
pub fn p256_registered_public_key(
    key_type: KeyType,
    registered: &P256PublicKey,
    host_bytes: &[u8],
) -> Result<PublicKey, PlatformError> {
    let current = p256_public_key("get_public_key", key_type, host_bytes)?;
    if &current != registered {
        return Err(PlatformError::CustodyError(
            "KeyCustodyProvider.get_public_key returned a different key than at generation".into(),
        ));
    }
    Ok(PublicKey::new(host_bytes.to_vec()))
}

/// Requires the 32-byte digest a P-256 signing key signs.
///
/// # Errors
///
/// [`PlatformError::CustodyError`] when `data` is not 32 bytes.
pub fn p256_digest(data: &[u8]) -> Result<[u8; 32], PlatformError> {
    data.try_into().map_err(|_| {
        PlatformError::CustodyError(format!(
            "a P-256 signing key signs a 32-byte digest, got {} bytes",
            data.len()
        ))
    })
}

/// Turns a host signature into the raw 64-byte low-`s` `r ‖ s` that verifies
/// strictly under `public_key` over `digest`.
///
/// A host (Secure Enclave, Android Keystore, `WebCrypto`) may return raw
/// `r ‖ s` or DER, with either `s`. Each reading of the bytes — raw when it is
/// 64 bytes, DER when it parses as strict DER — is normalised to low-`s` and
/// verified; the first that verifies is returned.
///
/// # Errors
///
/// [`PlatformError::CustodyError`] when no reading verifies.
pub fn p256_host_signature(
    public_key: &P256PublicKey,
    digest: &[u8; 32],
    host_signature: &[u8],
) -> Result<Signature, PlatformError> {
    let raw: Option<[u8; SIGNATURE_LEN]> = host_signature.try_into().ok();
    let der = der_to_raw(host_signature).ok();
    for candidate in raw.iter().chain(der.iter()) {
        let Ok(low_s) = normalize_low_s(candidate) else {
            continue;
        };
        if verify_prehash_strict(public_key, digest, &low_s).is_ok() {
            return Ok(Signature::new(low_s.to_vec()));
        }
    }
    Err(PlatformError::CustodyError(format!(
        "KeyCustodyProvider.sign returned {} bytes that are not a valid P-256 signature \
         (raw r||s or DER) over the digest under the key's public key",
        host_signature.len()
    )))
}

/// Parses a P-256 peer public key for [`KeyType::HpkeP256`] key agreement
/// and returns the 65-byte uncompressed encoding the host receives.
///
/// # Errors
///
/// [`PlatformError::CustodyError`] when `peer_public` is not a valid SEC1
/// P-256 point.
pub fn p256_peer_for_host(
    peer_public: &[u8],
) -> Result<[u8; UNCOMPRESSED_POINT_LEN], PlatformError> {
    P256PublicKey::from_sec1(peer_public)
        .map(|pk| pk.to_uncompressed())
        .map_err(|e| PlatformError::CustodyError(format!("P-256 peer public key: {e}")))
}

/// Requires a 32-byte X25519 peer public key.
///
/// # Errors
///
/// [`PlatformError::CustodyError`] when `peer_public` is not 32 bytes.
pub fn x25519_peer(peer_public: &[u8]) -> Result<[u8; 32], PlatformError> {
    peer_public.try_into().map_err(|_| {
        PlatformError::CustodyError(format!(
            "an X25519 peer public key is 32 bytes, got {}",
            peer_public.len()
        ))
    })
}

/// Checks a host signature for an Ed25519 key, or an unregistered handle
/// (such as a pseudonym): both sign with a 64-byte signature.
///
/// # Errors
///
/// [`PlatformError::CustodyError`] when the host returned another length.
pub fn legacy_signature(host_signature: Vec<u8>) -> Result<Signature, PlatformError> {
    if host_signature.len() != SIGNATURE_LEN {
        return Err(PlatformError::CustodyError(format!(
            "KeyCustodyProvider.sign returned {} bytes, expected {SIGNATURE_LEN}",
            host_signature.len()
        )));
    }
    Ok(Signature::new(host_signature))
}

/// Checks a host public key for an Ed25519 or X25519 key (32 bytes), or for
/// an unregistered handle (32 bytes, or a 33-byte compressed P-256 point for
/// a pseudonym handle).
///
/// # Errors
///
/// [`PlatformError::CustodyError`] on any other length or an invalid point.
pub fn legacy_public_key(
    registered: Option<KeyType>,
    host_bytes: Vec<u8>,
) -> Result<PublicKey, PlatformError> {
    let ok = match (registered, host_bytes.len()) {
        (_, 32) => true,
        (None, COMPRESSED_POINT_LEN) => P256PublicKey::from_sec1(&host_bytes).is_ok(),
        _ => false,
    };
    if !ok {
        return Err(PlatformError::CustodyError(format!(
            "KeyCustodyProvider.get_public_key returned {} bytes that are not a valid public key",
            host_bytes.len()
        )));
    }
    Ok(PublicKey::new(host_bytes))
}

// ---------------------------------------------------------------------------
// Adapter flows
//
// Each bridge supplies its host calls as closures; these functions hold every
// decision (key-type strings, registry, lengths, P-256 validation) so the
// bridges cannot drift. The closures take the key id as the host's string.
// ---------------------------------------------------------------------------

/// `KeyCustody::generate_keypair` over a host provider.
///
/// Asks the host for a key of `key_type`, and for a P-256 type fetches and
/// validates its public key before registering the handle. When that
/// validation fails the host key is destroyed, so no unusable key is left
/// behind; the validation error is returned either way (with the destroy
/// failure appended when the destroy also fails).
///
/// # Errors
///
/// Any host error; [`PlatformError::CustodyError`] for a non-numeric key id,
/// a reused key id, or an invalid P-256 public key.
pub async fn generate_keypair<G, GF, P, PF, D, DF>(
    registry: &CallbackKeyRegistry,
    key_type: KeyType,
    host_generate: G,
    host_get_public_key: P,
    host_destroy: D,
) -> Result<KeyHandle, PlatformError>
where
    G: FnOnce(&'static str) -> GF,
    GF: Future<Output = Result<String, PlatformError>>,
    P: FnOnce(String) -> PF,
    PF: Future<Output = Result<Vec<u8>, PlatformError>>,
    D: FnOnce(String) -> DF,
    DF: Future<Output = Result<(), PlatformError>>,
{
    let key_id = host_generate(key_type_str(key_type)).await?;
    let handle = crate::custody_parse::parse_handle("generate_keypair", &key_id)?;
    let registered = match key_type {
        KeyType::Ed25519 => RegisteredKey::Ed25519,
        KeyType::X25519 => RegisteredKey::X25519,
        KeyType::P256Signing | KeyType::HpkeP256 => {
            let validated = match host_get_public_key(key_id.clone()).await {
                Ok(bytes) => p256_public_key("get_public_key", key_type, &bytes),
                Err(e) => Err(e),
            };
            match validated {
                Ok(pk) if key_type == KeyType::P256Signing => RegisteredKey::P256Signing(pk),
                Ok(pk) => RegisteredKey::HpkeP256(pk),
                Err(e) => {
                    return Err(match host_destroy(key_id).await {
                        Ok(()) => e,
                        Err(destroy_err) => PlatformError::CustodyError(format!(
                            "{e}; destroying the rejected host key also failed: {destroy_err}"
                        )),
                    });
                }
            }
        }
    };
    registry.register(handle, registered)?;
    Ok(handle)
}

/// `KeyCustody::sign` over a host provider.
///
/// A registered P-256 signing key signs a 32-byte digest and its host result
/// passes [`p256_host_signature`]. An Ed25519 key or an unregistered handle
/// passes `data` through and must get 64 bytes back. A key-agreement key is
/// [`PlatformError::WrongKeyType`] without a host call.
///
/// # Errors
///
/// Any host error; [`PlatformError::WrongKeyType`] or
/// [`PlatformError::CustodyError`] as above.
pub async fn sign<S, SF>(
    registry: &CallbackKeyRegistry,
    key: &KeyHandle,
    data: &[u8],
    host_sign: S,
) -> Result<Signature, PlatformError>
where
    S: FnOnce(String, Vec<u8>) -> SF,
    SF: Future<Output = Result<Vec<u8>, PlatformError>>,
{
    let key_id = key.id().to_string();
    match registry.get(key)? {
        Some(RegisteredKey::P256Signing(pk)) => {
            let digest = p256_digest(data)?;
            let host_sig = host_sign(key_id, digest.to_vec()).await?;
            p256_host_signature(&pk, &digest, &host_sig)
        }
        Some(k @ RegisteredKey::X25519) => Err(k.wrong_type(KeyType::Ed25519)),
        Some(k @ RegisteredKey::HpkeP256(_)) => Err(k.wrong_type(KeyType::P256Signing)),
        Some(RegisteredKey::Ed25519) | None => {
            legacy_signature(host_sign(key_id, data.to_vec()).await?)
        }
    }
}

/// `KeyCustody::public_key` over a host provider, with exact lengths per
/// registered type (see [`p256_registered_public_key`] and
/// [`legacy_public_key`]).
///
/// # Errors
///
/// Any host error; [`PlatformError::CustodyError`] for a malformed or
/// changed key.
pub async fn public_key<P, PF>(
    registry: &CallbackKeyRegistry,
    key: &KeyHandle,
    host_get_public_key: P,
) -> Result<PublicKey, PlatformError>
where
    P: FnOnce(String) -> PF,
    PF: Future<Output = Result<Vec<u8>, PlatformError>>,
{
    let registered = registry.get(key)?;
    let bytes = host_get_public_key(key.id().to_string()).await?;
    match registered {
        Some(RegisteredKey::P256Signing(pk)) => {
            p256_registered_public_key(KeyType::P256Signing, &pk, &bytes)
        }
        Some(RegisteredKey::HpkeP256(pk)) => {
            p256_registered_public_key(KeyType::HpkeP256, &pk, &bytes)
        }
        other => legacy_public_key(other.map(|k| k.key_type()), bytes),
    }
}

/// `KeyCustody::dh_agree` over a host provider.
///
/// A registered HPKE P-256 key requires a valid SEC1 peer point and sends
/// the host its 65-byte uncompressed form. An X25519 key or an unregistered
/// handle requires a 32-byte peer. A signing key is
/// [`PlatformError::WrongKeyType`] without a host call. The host must return
/// exactly 32 bytes, which are zeroized once copied.
///
/// # Errors
///
/// Any host error; [`PlatformError::WrongKeyType`] or
/// [`PlatformError::CustodyError`] as above.
pub async fn dh_agree<H, HF>(
    registry: &CallbackKeyRegistry,
    key: &KeyHandle,
    peer_public: &[u8],
    host_dh_agree: H,
) -> Result<SharedSecret, PlatformError>
where
    H: FnOnce(String, Vec<u8>) -> HF,
    HF: Future<Output = Result<Vec<u8>, PlatformError>>,
{
    let peer = match registry.get(key)? {
        Some(RegisteredKey::HpkeP256(_)) => p256_peer_for_host(peer_public)?.to_vec(),
        Some(k @ RegisteredKey::Ed25519) => return Err(k.wrong_type(KeyType::X25519)),
        Some(k @ RegisteredKey::P256Signing(_)) => return Err(k.wrong_type(KeyType::HpkeP256)),
        Some(RegisteredKey::X25519) | None => x25519_peer(peer_public)?.to_vec(),
    };
    let shared = zeroize::Zeroizing::new(host_dh_agree(key.id().to_string(), peer).await?);
    Ok(SharedSecret::new(crate::custody_parse::expect_32(
        "dh_agree", &shared,
    )?))
}

/// `KeyCustody::destroy_key` over a host provider: the registry forgets the
/// handle only after the host destroyed the key.
///
/// # Errors
///
/// Any host error, or a poisoned registry.
pub async fn destroy_key<D, DF>(
    registry: &CallbackKeyRegistry,
    key: &KeyHandle,
    host_destroy: D,
) -> Result<(), PlatformError>
where
    D: FnOnce(String) -> DF,
    DF: Future<Output = Result<(), PlatformError>>,
{
    host_destroy(key.id().to_string()).await?;
    registry.remove(key)
}

/// Refuses an Ed25519-only operation (`ed25519_to_x25519_agree`,
/// `export_ed25519_signing_key`) on a handle this adapter minted as another
/// type. Unregistered handles pass, and the host decides.
///
/// # Errors
///
/// [`PlatformError::WrongKeyType`], or a poisoned registry.
pub fn require_ed25519(
    registry: &CallbackKeyRegistry,
    key: &KeyHandle,
) -> Result<(), PlatformError> {
    match registry.get(key)? {
        Some(RegisteredKey::Ed25519) | None => Ok(()),
        Some(k) => Err(k.wrong_type(KeyType::Ed25519)),
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use scp_crypto::p256::{P256SigningKey, sign_prehash_rfc6979};

    /// The P-256 group order `n`, big-endian.
    const N: [u8; 32] = [
        0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84, 0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63,
        0x25, 0x51,
    ];

    /// `n - s` for a big-endian `s < n`.
    fn negate(s: &[u8]) -> [u8; 32] {
        let mut out = [0u8; 32];
        let mut borrow = 0i16;
        for i in (0..32).rev() {
            let mut d = i16::from(N[i]) - i16::from(s[i]) - borrow;
            borrow = i16::from(d < 0);
            if d < 0 {
                d += 256;
            }
            out[i] = u8::try_from(d).unwrap();
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
            out.push(u8::try_from(v.len() + 1).unwrap());
            out.push(0);
        } else {
            out.push(u8::try_from(v.len()).unwrap());
        }
        out.extend_from_slice(v);
        out
    }

    fn der(r: &[u8], s: &[u8]) -> Vec<u8> {
        let body = [der_int(r), der_int(s)].concat();
        let mut out = vec![0x30, u8::try_from(body.len()).unwrap()];
        out.extend_from_slice(&body);
        out
    }

    fn key_and_sig() -> (P256SigningKey, [u8; 32], [u8; 64]) {
        let key = P256SigningKey::from_scalar_bytes(&[0x11u8; 32]).unwrap();
        let digest = [0x22u8; 32];
        let sig = sign_prehash_rfc6979(&key, &digest).unwrap();
        (key, digest, sig)
    }

    #[test]
    fn key_type_strings() {
        assert_eq!(key_type_str(KeyType::Ed25519), "ed25519");
        assert_eq!(key_type_str(KeyType::X25519), "x25519");
        assert_eq!(key_type_str(KeyType::P256Signing), "p256");
        assert_eq!(key_type_str(KeyType::HpkeP256), "hpke-p256");
    }

    #[test]
    fn host_signature_raw_low_s_is_accepted_unchanged() {
        let (key, digest, sig) = key_and_sig();
        let out = p256_host_signature(&key.public_key(), &digest, &sig).unwrap();
        assert_eq!(out.as_bytes(), &sig);
    }

    #[test]
    fn host_signature_der_high_s_normalises_to_raw_low_s() {
        let (key, digest, sig) = key_and_sig();
        let high_s = negate(&sig[32..]);
        let der_high = der(&sig[..32], &high_s);
        let out = p256_host_signature(&key.public_key(), &digest, &der_high).unwrap();
        assert_eq!(
            out.as_bytes(),
            &sig,
            "DER high-s must become the raw low-s form"
        );

        let der_low = der(&sig[..32], &sig[32..]);
        let out = p256_host_signature(&key.public_key(), &digest, &der_low).unwrap();
        assert_eq!(out.as_bytes(), &sig);

        let mut raw_high = sig;
        raw_high[32..].copy_from_slice(&high_s);
        let out = p256_host_signature(&key.public_key(), &digest, &raw_high).unwrap();
        assert_eq!(out.as_bytes(), &sig);
    }

    #[test]
    fn host_signature_that_does_not_verify_is_an_error() {
        let (key, digest, sig) = key_and_sig();
        let other = P256SigningKey::from_scalar_bytes(&[0x33u8; 32]).unwrap();
        for bad in [
            sig.to_vec(),
            vec![],
            vec![0u8; 64],
            vec![0x30, 0x00],
            sig[..63].to_vec(),
        ] {
            let pk = if bad == sig.to_vec() {
                other.public_key()
            } else {
                key.public_key()
            };
            assert!(matches!(
                p256_host_signature(&pk, &digest, &bad),
                Err(PlatformError::CustodyError(_))
            ));
        }
        let mut wrong_digest = digest;
        wrong_digest[0] ^= 1;
        assert!(p256_host_signature(&key.public_key(), &wrong_digest, &sig).is_err());
    }

    #[test]
    fn public_key_requires_exact_length_per_type() {
        let pk = P256SigningKey::from_scalar_bytes(&[0x11u8; 32])
            .unwrap()
            .public_key();
        let compressed = pk.to_compressed();
        let uncompressed = pk.to_uncompressed();
        assert!(p256_public_key("m", KeyType::P256Signing, &compressed).is_ok());
        assert!(p256_public_key("m", KeyType::HpkeP256, &uncompressed).is_ok());
        assert!(p256_public_key("m", KeyType::P256Signing, &uncompressed).is_err());
        assert!(p256_public_key("m", KeyType::HpkeP256, &compressed).is_err());
        assert!(p256_public_key("m", KeyType::Ed25519, &[0u8; 32]).is_err());
        let mut off = uncompressed;
        off[64] ^= 1;
        assert!(p256_public_key("m", KeyType::HpkeP256, &off).is_err());
    }

    #[test]
    fn registered_public_key_must_not_change() {
        let a = P256SigningKey::from_scalar_bytes(&[1u8; 32])
            .unwrap()
            .public_key();
        let b = P256SigningKey::from_scalar_bytes(&[2u8; 32])
            .unwrap()
            .public_key();
        assert!(p256_registered_public_key(KeyType::P256Signing, &a, &a.to_compressed()).is_ok());
        assert!(p256_registered_public_key(KeyType::P256Signing, &a, &b.to_compressed()).is_err());
    }

    #[test]
    fn peer_parsing() {
        let pk = P256SigningKey::from_scalar_bytes(&[1u8; 32])
            .unwrap()
            .public_key();
        assert_eq!(
            p256_peer_for_host(&pk.to_compressed()).unwrap(),
            pk.to_uncompressed()
        );
        assert!(p256_peer_for_host(&[4u8; 65]).is_err());
        assert!(p256_peer_for_host(&[]).is_err());
        assert!(x25519_peer(&[0u8; 32]).is_ok());
        assert!(x25519_peer(&[0u8; 65]).is_err());
    }

    #[test]
    fn legacy_lengths() {
        assert!(legacy_signature(vec![0u8; 64]).is_ok());
        assert!(legacy_signature(vec![0u8; 72]).is_err());
        assert!(legacy_public_key(Some(KeyType::Ed25519), vec![0u8; 32]).is_ok());
        assert!(legacy_public_key(Some(KeyType::Ed25519), vec![0u8; 33]).is_err());
        let pk = P256SigningKey::from_scalar_bytes(&[1u8; 32])
            .unwrap()
            .public_key();
        assert!(legacy_public_key(None, pk.to_compressed().to_vec()).is_ok());
        assert!(legacy_public_key(None, vec![0xABu8; 33]).is_err());
    }

    #[test]
    fn registry_round_trip_and_duplicate_rejection() {
        let registry = CallbackKeyRegistry::new();
        let h = KeyHandle::new(9);
        assert!(registry.get(&h).unwrap().is_none());
        registry.register(h, RegisteredKey::Ed25519).unwrap();
        assert!(matches!(
            registry.get(&h).unwrap(),
            Some(RegisteredKey::Ed25519)
        ));
        assert!(registry.register(h, RegisteredKey::X25519).is_err());
        registry.remove(&h).unwrap();
        assert!(registry.get(&h).unwrap().is_none());
    }
}
