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
//!   generation, and every pseudonym handle it derived as a P-256 signing key
//!   bound to the host's point ([`derive_pseudonym`]). A handle the adapter
//!   neither minted nor derived (a host key from an earlier session) is
//!   resolved for `sign`, `public_key` and pseudonym derivation through the
//!   host's `get_public_key` ([`resolve`]): 33 bytes bind a P-256 signing key
//!   at that point, 32 bytes an Ed25519 key, and a host that has no such key
//!   fails the operation. Every other operation on an unregistered handle is
//!   [`PlatformError::KeyNotFound`] with no host call.
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
use scp_platform::traits::{
    KeyHandle, KeyType, PseudonymKeypair, PublicKey, SharedSecret, Signature,
};

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

    /// Whether two entries name the same key (P-256 entries by point).
    fn same_key(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Ed25519, Self::Ed25519) | (Self::X25519, Self::X25519) => true,
            (Self::P256Signing(a), Self::P256Signing(b))
            | (Self::HpkeP256(a), Self::HpkeP256(b)) => a == b,
            _ => false,
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

    /// Binds a handle the adapter learned after the fact: a derived pseudonym
    /// or a host key resolved through `get_public_key` ([`resolve`]).
    ///
    /// Both are deterministic lookups a host may answer twice (a repeated
    /// derivation, or two concurrent resolutions), so an id already bound to
    /// the same key is accepted and the existing entry returned. Any other
    /// occupant of the id is an error.
    ///
    /// # Errors
    ///
    /// [`PlatformError::CustodyError`] if the id is held by another key or a
    /// different point, or the registry lock is poisoned.
    pub fn bind(
        &self,
        method: &str,
        handle: KeyHandle,
        key: RegisteredKey,
    ) -> Result<RegisteredKey, PlatformError> {
        match self.lock()?.entry(handle.id()) {
            std::collections::hash_map::Entry::Occupied(slot) if slot.get().same_key(&key) => {
                Ok(slot.get().clone())
            }
            std::collections::hash_map::Entry::Occupied(_) => {
                Err(PlatformError::CustodyError(format!(
                    "KeyCustodyProvider.{method}: key_id {} is already bound to another key",
                    handle.id()
                )))
            }
            std::collections::hash_map::Entry::Vacant(slot) => Ok(slot.insert(key).clone()),
        }
    }

    /// The registered key for a handle, or `None` if this adapter neither
    /// minted nor derived it.
    ///
    /// # Errors
    ///
    /// [`PlatformError::CustodyError`] if the registry lock is poisoned.
    pub fn get(&self, handle: &KeyHandle) -> Result<Option<RegisteredKey>, PlatformError> {
        Ok(self.lock()?.get(&handle.id()).cloned())
    }

    /// Removes and returns a handle's entry before the host destroys its
    /// key, so a host that reuses the id for a concurrent generation cannot
    /// have its new registration removed afterwards.
    ///
    /// # Errors
    ///
    /// [`PlatformError::CustodyError`] if the registry lock is poisoned.
    pub fn take(&self, handle: &KeyHandle) -> Result<Option<RegisteredKey>, PlatformError> {
        Ok(self.lock()?.remove(&handle.id()))
    }

    /// Puts back an entry [`Self::take`] removed, after the host failed to
    /// destroy the key. An entry registered for the id in the meantime is
    /// kept.
    ///
    /// # Errors
    ///
    /// [`PlatformError::CustodyError`] if the registry lock is poisoned.
    pub fn restore(&self, handle: &KeyHandle, key: RegisteredKey) -> Result<(), PlatformError> {
        self.lock()?.entry(handle.id()).or_insert(key);
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

/// Validates an [`KeyType::HpkeP256`] peer and returns the bytes the host
/// receives.
///
/// The check is [`scp_platform::traits::hpke_p256_peer`]: exactly the 65-byte
/// uncompressed point (RFC 9180 §7.1.1).
///
/// # Errors
///
/// [`PlatformError::CustodyError`] when `peer_public` is not a valid 65-byte
/// uncompressed P-256 point.
pub fn p256_peer_for_host(
    peer_public: &[u8],
) -> Result<[u8; UNCOMPRESSED_POINT_LEN], PlatformError> {
    scp_platform::traits::hpke_p256_peer(peer_public).map(|pk| pk.to_uncompressed())
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

/// Checks a host signature for an Ed25519 key: exactly 64 bytes.
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

/// Checks a host public key for an Ed25519 or X25519 key: exactly 32 bytes.
///
/// # Errors
///
/// [`PlatformError::CustodyError`] on any other length.
pub fn legacy_public_key(host_bytes: Vec<u8>) -> Result<PublicKey, PlatformError> {
    if host_bytes.len() != 32 {
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
/// validates its public key before registering the handle. When the key id
/// is not numeric or the P-256 public key fails validation, the host key is
/// destroyed, so no unusable key is left behind; the rejection error is
/// returned either way (with the destroy failure appended when the destroy
/// also fails). A key id the registry already holds is rejected without a
/// destroy, because destroying that id would destroy the live key this
/// adapter already registered under it.
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
    let validated = async {
        let handle = crate::custody_parse::parse_handle("generate_keypair", &key_id)?;
        let registered = match key_type {
            KeyType::Ed25519 => RegisteredKey::Ed25519,
            KeyType::X25519 => RegisteredKey::X25519,
            KeyType::P256Signing => RegisteredKey::P256Signing(p256_public_key(
                "get_public_key",
                key_type,
                &host_get_public_key(key_id.clone()).await?,
            )?),
            KeyType::HpkeP256 => RegisteredKey::HpkeP256(p256_public_key(
                "get_public_key",
                key_type,
                &host_get_public_key(key_id.clone()).await?,
            )?),
        };
        Ok::<_, PlatformError>((handle, registered))
    }
    .await;
    match validated {
        Ok((handle, registered)) => {
            registry.register(handle, registered)?;
            Ok(handle)
        }
        Err(e) => Err(match host_destroy(key_id).await {
            Ok(()) => e,
            Err(destroy_err) => PlatformError::CustodyError(format!(
                "{e}; destroying the rejected host key also failed: {destroy_err}"
            )),
        }),
    }
}

/// The registered key for `key`, resolving a handle this adapter neither
/// minted nor derived through the host's `get_public_key`.
///
/// A host keeps its keys across adapter instances, so a handle from an earlier
/// session is still the host's key. The host protocol has no key-type call,
/// so the type comes from the public-key length: 33 bytes (a compressed
/// point) bind a P-256 signing key at that point, so its signatures are
/// verified strictly; 32 bytes bind an Ed25519 key. Agreement keys are never
/// resolved: an X25519 key is also 32 bytes, and binding it as Ed25519 only
/// lets it reach Ed25519 operations the host then refuses. Returns the entry
/// and the host's bytes, or `None` for the bytes when the handle was already
/// registered.
///
/// # Errors
///
/// The host's own error when it has no such key (a conforming host reports
/// [`PlatformError::KeyNotFound`]); [`PlatformError::CustodyError`] for any
/// other length, an invalid point, or an id bound concurrently to another
/// key; or a poisoned registry.
pub async fn resolve<P, PF>(
    registry: &CallbackKeyRegistry,
    key: &KeyHandle,
    host_get_public_key: P,
) -> Result<(RegisteredKey, Option<Vec<u8>>), PlatformError>
where
    P: FnOnce(String) -> PF,
    PF: Future<Output = Result<Vec<u8>, PlatformError>>,
{
    if let Some(registered) = registry.get(key)? {
        return Ok((registered, None));
    }
    let bytes = host_get_public_key(key.id().to_string()).await?;
    let found = match bytes.len() {
        COMPRESSED_POINT_LEN => RegisteredKey::P256Signing(p256_public_key(
            "get_public_key",
            KeyType::P256Signing,
            &bytes,
        )?),
        32 => RegisteredKey::Ed25519,
        n => {
            return Err(PlatformError::CustodyError(format!(
                "KeyCustodyProvider.get_public_key returned {n} bytes for unregistered key_id \
                 {}, expected 33 (p256) or 32 (ed25519)",
                key.id()
            )));
        }
    };
    Ok((registry.bind("get_public_key", *key, found)?, Some(bytes)))
}

/// `KeyCustody::sign` over a host provider.
///
/// A registered P-256 signing key (generated or a derived pseudonym) signs a
/// 32-byte digest and its host result passes [`p256_host_signature`]. An
/// Ed25519 key passes `data` through and must get 64 bytes back. A
/// key-agreement key is [`PlatformError::WrongKeyType`] without a host sign
/// call. An unregistered handle is first [`resolve`]d.
///
/// # Errors
///
/// Any host error; [`PlatformError::WrongKeyType`] or
/// [`PlatformError::CustodyError`] as above and in [`resolve`].
pub async fn sign<S, SF, P, PF>(
    registry: &CallbackKeyRegistry,
    key: &KeyHandle,
    data: &[u8],
    host_sign: S,
    host_get_public_key: P,
) -> Result<Signature, PlatformError>
where
    S: FnOnce(String, Vec<u8>) -> SF,
    SF: Future<Output = Result<Vec<u8>, PlatformError>>,
    P: FnOnce(String) -> PF,
    PF: Future<Output = Result<Vec<u8>, PlatformError>>,
{
    let key_id = key.id().to_string();
    match resolve(registry, key, host_get_public_key).await?.0 {
        RegisteredKey::P256Signing(pk) => {
            let digest = p256_digest(data)?;
            let host_sig = host_sign(key_id, digest.to_vec()).await?;
            p256_host_signature(&pk, &digest, &host_sig)
        }
        k @ RegisteredKey::X25519 => Err(k.wrong_type(KeyType::Ed25519)),
        k @ RegisteredKey::HpkeP256(_) => Err(k.wrong_type(KeyType::P256Signing)),
        RegisteredKey::Ed25519 => legacy_signature(host_sign(key_id, data.to_vec()).await?),
    }
}

/// `KeyCustody::public_key` over a host provider.
///
/// Lengths are exact per registered type (see [`p256_registered_public_key`]
/// and [`legacy_public_key`]). An unregistered handle is [`resolve`]d, and
/// the host is asked once.
///
/// # Errors
///
/// Any host error; or [`PlatformError::CustodyError`] for a malformed or
/// changed key, and as in [`resolve`].
pub async fn public_key<P, PF>(
    registry: &CallbackKeyRegistry,
    key: &KeyHandle,
    host_get_public_key: P,
) -> Result<PublicKey, PlatformError>
where
    // `Sync` so the borrow held across `resolve` keeps the future `Send`.
    P: Fn(String) -> PF + Sync,
    PF: Future<Output = Result<Vec<u8>, PlatformError>>,
{
    let (registered, bytes) = match resolve(registry, key, &host_get_public_key).await? {
        (registered, Some(bytes)) => (registered, bytes),
        (registered, None) => (registered, host_get_public_key(key.id().to_string()).await?),
    };
    match registered {
        RegisteredKey::P256Signing(pk) => {
            p256_registered_public_key(KeyType::P256Signing, &pk, &bytes)
        }
        RegisteredKey::HpkeP256(pk) => p256_registered_public_key(KeyType::HpkeP256, &pk, &bytes),
        RegisteredKey::Ed25519 | RegisteredKey::X25519 => legacy_public_key(bytes),
    }
}

/// `KeyCustody::dh_agree` over a host provider.
///
/// A registered HPKE P-256 key requires a valid SEC1 peer point and sends
/// the host its 65-byte uncompressed form. An X25519 key requires a 32-byte
/// peer. A signing key (a pseudonym included) is
/// [`PlatformError::WrongKeyType`] and an unknown handle
/// [`PlatformError::KeyNotFound`], both without a host call. The host must
/// return exactly 32 bytes, which are zeroized once copied.
///
/// # Errors
///
/// Any host error; [`PlatformError::KeyNotFound`],
/// [`PlatformError::WrongKeyType`] or [`PlatformError::CustodyError`] as
/// above.
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
        Some(RegisteredKey::X25519) => x25519_peer(peer_public)?.to_vec(),
        None => return Err(PlatformError::KeyNotFound),
    };
    let shared = zeroize::Zeroizing::new(host_dh_agree(key.id().to_string(), peer).await?);
    Ok(SharedSecret::new(crate::custody_parse::expect_32(
        "dh_agree", &shared,
    )?))
}

/// `KeyCustody::destroy_key` over a host provider.
///
/// The registry entry is taken before the host call, so a host that reuses
/// the id for a concurrent generation keeps its new registration; if the
/// host fails to destroy the key, the entry is restored and the host error
/// returned.
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
    let taken = registry.take(key)?;
    match host_destroy(key.id().to_string()).await {
        Ok(()) => Ok(()),
        Err(e) => {
            if let Some(entry) = taken {
                registry.restore(key, entry)?;
            }
            Err(e)
        }
    }
}

/// Refuses an Ed25519-only operation (`ed25519_to_x25519_agree`,
/// `export_ed25519_signing_key`) on a handle that is not a registered Ed25519
/// key. Pseudonym derivation checks the same through [`resolve`].
///
/// # Errors
///
/// [`PlatformError::KeyNotFound`] for an unknown handle,
/// [`PlatformError::WrongKeyType`] for another type, or a poisoned registry.
pub fn require_ed25519(
    registry: &CallbackKeyRegistry,
    key: &KeyHandle,
) -> Result<(), PlatformError> {
    match registry.get(key)? {
        Some(RegisteredKey::Ed25519) => Ok(()),
        Some(k) => Err(k.wrong_type(KeyType::Ed25519)),
        None => Err(PlatformError::KeyNotFound),
    }
}

/// `KeyCustody::derive_pseudonym` and `derive_rotatable_pseudonym` over a
/// host provider.
///
/// `key` must be an Ed25519 identity key, registered or [`resolve`]d. The host returns the
/// pseudonym as separate `(public_key, key_id)` fields; the point must be a
/// 33-byte compressed P-256 point, the key id numeric, and the host's own
/// `get_public_key(key_id)` must return the same bytes. The handle is then
/// registered as a P-256 signing key bound to that point, so its `sign`
/// goes through [`p256_host_signature`] and its `dh_agree` is
/// [`PlatformError::WrongKeyType`].
///
/// # Errors
///
/// [`PlatformError::WrongKeyType`] for `key`, or as in [`resolve`]; any host
/// error; [`PlatformError::CustodyError`] for a malformed
/// return, a point the host's `get_public_key` does not confirm, or a key id
/// already bound to another key.
pub async fn derive_pseudonym<H, HF, P, PF>(
    registry: &CallbackKeyRegistry,
    method: &str,
    key: &KeyHandle,
    host_derive: H,
    host_get_public_key: P,
) -> Result<PseudonymKeypair, PlatformError>
where
    H: FnOnce(String) -> HF,
    HF: Future<Output = Result<(Vec<u8>, String), PlatformError>>,
    // `Sync` so the borrow held across `resolve` keeps the future `Send`.
    P: Fn(String) -> PF + Sync,
    PF: Future<Output = Result<Vec<u8>, PlatformError>>,
{
    match resolve(registry, key, &host_get_public_key).await?.0 {
        RegisteredKey::Ed25519 => {}
        other => return Err(other.wrong_type(KeyType::Ed25519)),
    }
    let (public_key, key_id) = host_derive(key.id().to_string()).await?;
    let pseudonym = crate::custody_parse::parse_pseudonym(method, &public_key, &key_id)?;
    let host_public_key = host_get_public_key(key_id).await?;
    if host_public_key.as_slice() != pseudonym.public_key().as_bytes() {
        return Err(PlatformError::CustodyError(format!(
            "KeyCustodyProvider.{method}: get_public_key(key_id) does not match the derived \
             pseudonym point"
        )));
    }
    let point = P256PublicKey::from_sec1(&public_key)
        .map_err(|e| PlatformError::CustodyError(format!("KeyCustodyProvider.{method}: {e}")))?;
    registry.bind(
        method,
        *pseudonym.key_handle(),
        RegisteredKey::P256Signing(point),
    )?;
    Ok(pseudonym)
}

/// A software P-256 host for bridge tests.
///
/// It answers the host callbacks the way a conforming platform keystore does,
/// and signs with a high `s` in DER, so a test proves the adapter normalises
/// what a real host may return.
#[cfg(any(test, feature = "testing"))]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::missing_panics_doc)]
pub mod fake_host {
    use std::collections::HashMap;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use scp_crypto::p256::{P256PublicKey, P256SigningKey, ecdh_p256, sign_prehash_rfc6979};
    use scp_platform::error::PlatformError;

    /// The P-256 group order `n`, big-endian.
    const N: [u8; 32] = [
        0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84, 0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63,
        0x25, 0x51,
    ];

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

    /// DER `SEQUENCE { r, s }` of two big-endian integers.
    #[must_use]
    pub fn der(r: &[u8], s: &[u8]) -> Vec<u8> {
        let body = [der_int(r), der_int(s)].concat();
        let mut out = vec![0x30, u8::try_from(body.len()).unwrap()];
        out.extend_from_slice(&body);
        out
    }

    /// Host state: every key it holds by id, and the last peer it was sent.
    #[derive(Default)]
    pub struct FakeP256Host {
        keys: Mutex<HashMap<String, P256SigningKey>>,
        hpke: Mutex<std::collections::HashSet<String>>,
        next: AtomicUsize,
        /// The peer bytes of the most recent `dh_agree` call.
        pub last_peer: Mutex<Option<Vec<u8>>>,
        /// How many `sign` calls reached the host.
        pub sign_calls: AtomicUsize,
    }

    impl FakeP256Host {
        fn key(&self, key_id: &str) -> Result<P256SigningKey, PlatformError> {
            let scalar = self
                .keys
                .lock()
                .unwrap()
                .get(key_id)
                .ok_or(PlatformError::KeyNotFound)?
                .to_scalar_bytes();
            P256SigningKey::from_scalar_bytes(&scalar)
                .map_err(|e| PlatformError::CustodyError(e.to_string()))
        }

        /// `generate_keypair`: P-256 types only; numeric ids from 1.
        ///
        /// # Errors
        ///
        /// A key type other than `p256` or `hpke-p256`.
        pub fn generate_keypair(&self, key_type: &str) -> Result<String, PlatformError> {
            if key_type != "p256" && key_type != "hpke-p256" {
                return Err(PlatformError::CustodyError(format!(
                    "fake host holds P-256 keys only, not {key_type}"
                )));
            }
            // Ids never repeat, even after a destroy.
            let id = self.next.fetch_add(1, Ordering::Relaxed) + 1;
            let key = P256SigningKey::from_scalar_bytes(&[u8::try_from(id).unwrap() + 0x40; 32])
                .expect("a repeated byte below n is a valid scalar");
            self.keys.lock().unwrap().insert(id.to_string(), key);
            if key_type == "hpke-p256" {
                self.hpke.lock().unwrap().insert(id.to_string());
            }
            Ok(id.to_string())
        }

        /// `get_public_key`: the SEC1 point the host contract names, compressed
        /// for `p256` and uncompressed for `hpke-p256`.
        ///
        /// # Errors
        ///
        /// An unknown key id.
        pub fn get_public_key(&self, key_id: &str) -> Result<Vec<u8>, PlatformError> {
            let public = self.key(key_id)?.public_key();
            if self.hpke.lock().unwrap().contains(key_id) {
                Ok(public.to_uncompressed().to_vec())
            } else {
                Ok(public.to_compressed().to_vec())
            }
        }

        /// `sign`: RFC 6979 over the 32-byte digest, returned as DER with the
        /// high `s` (`n - s`).
        ///
        /// # Errors
        ///
        /// An unknown key id, or a message that is not 32 bytes.
        pub fn sign(&self, key_id: &str, message: &[u8]) -> Result<Vec<u8>, PlatformError> {
            self.sign_calls.fetch_add(1, Ordering::Relaxed);
            let digest: [u8; 32] = message
                .try_into()
                .map_err(|_| PlatformError::CustodyError("digest must be 32 bytes".into()))?;
            let raw = sign_prehash_rfc6979(&self.key(key_id)?, &digest)
                .map_err(|e| PlatformError::CustodyError(e.to_string()))?;
            Ok(der(&raw[..32], &negate(&raw[32..])))
        }

        /// `dh_agree`: the ECDH x-coordinate with the peer, which the host
        /// parses as any SEC1 point, so the adapter alone enforces the
        /// uncompressed form.
        ///
        /// # Errors
        ///
        /// An unknown key id, or a peer that is not a curve point.
        pub fn dh_agree(&self, key_id: &str, peer: &[u8]) -> Result<Vec<u8>, PlatformError> {
            *self.last_peer.lock().unwrap() = Some(peer.to_vec());
            let peer = P256PublicKey::from_sec1(peer)
                .map_err(|e| PlatformError::CustodyError(e.to_string()))?;
            Ok(ecdh_p256(&self.key(key_id)?, &peer).to_vec())
        }

        /// `destroy_key`.
        ///
        /// # Errors
        ///
        /// An unknown key id.
        pub fn destroy_key(&self, key_id: &str) -> Result<(), PlatformError> {
            self.keys
                .lock()
                .unwrap()
                .remove(key_id)
                .map(|_| ())
                .ok_or(PlatformError::KeyNotFound)
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::fake_host::{der, negate};
    use super::*;
    use scp_crypto::p256::{P256SigningKey, sign_prehash_rfc6979};

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
            p256_peer_for_host(&pk.to_uncompressed()).unwrap(),
            pk.to_uncompressed()
        );
        // RFC 9180 §7.1.1: only the 65-byte uncompressed point.
        assert!(p256_peer_for_host(&pk.to_compressed()).is_err());
        let mut bad_prefix = pk.to_uncompressed();
        bad_prefix[0] = 0x05;
        assert!(p256_peer_for_host(&bad_prefix).is_err());
        assert!(p256_peer_for_host(&[4u8; 65]).is_err());
        assert!(p256_peer_for_host(&[]).is_err());
        assert!(x25519_peer(&[0u8; 32]).is_ok());
        assert!(x25519_peer(&[0u8; 65]).is_err());
    }

    #[test]
    fn legacy_lengths() {
        assert!(legacy_signature(vec![0u8; 64]).is_ok());
        assert!(legacy_signature(vec![0u8; 72]).is_err());
        assert!(legacy_public_key(vec![0u8; 32]).is_ok());
        let pk = P256SigningKey::from_scalar_bytes(&[1u8; 32])
            .unwrap()
            .public_key();
        assert!(
            legacy_public_key(pk.to_compressed().to_vec()).is_err(),
            "a P-256 point is never an Ed25519 or X25519 key"
        );
    }

    /// A registry holding identity key 1 (Ed25519) and pseudonym 7, derived
    /// through the shared flow from a host whose pseudonym key is `key`.
    async fn registry_with_pseudonym(key: &P256SigningKey) -> CallbackKeyRegistry {
        let registry = CallbackKeyRegistry::new();
        registry
            .register(KeyHandle::new(1), RegisteredKey::Ed25519)
            .unwrap();
        let point = key.public_key().to_compressed().to_vec();
        let p2 = point.clone();
        let derived = derive_pseudonym(
            &registry,
            "derive_pseudonym",
            &KeyHandle::new(1),
            |id| async move {
                assert_eq!(id, "1");
                Ok((point, "7".to_owned()))
            },
            move |id| {
                let p2 = p2.clone();
                async move {
                    assert_eq!(id, "7");
                    Ok(p2)
                }
            },
        )
        .await
        .unwrap();
        assert_eq!(derived.key_handle().id(), 7);
        registry
    }

    /// B4: a pseudonym handle is a registered P-256 signing key. Its host's
    /// DER high-s signature comes out raw low-s and strictly verifies; a junk
    /// 64-byte signature is rejected; `dh_agree` is `WrongKeyType`. A
    /// registered handle never asks the host for its public key before
    /// signing.
    #[tokio::test]
    async fn pseudonym_handles_use_the_registry_path() {
        let key = P256SigningKey::from_scalar_bytes(&[0x21u8; 32]).unwrap();
        let registry = registry_with_pseudonym(&key).await;
        let handle = KeyHandle::new(7);
        let digest = [0x5au8; 32];

        let raw = sign_prehash_rfc6979(&key, &digest).unwrap();
        let high_der = der(&raw[..32], &negate(&raw[32..]));
        let sig = sign(
            &registry,
            &handle,
            &digest,
            |id, data| async move {
                assert_eq!((id.as_str(), data.as_slice()), ("7", digest.as_slice()));
                Ok(high_der)
            },
            no_lookup,
        )
        .await
        .expect("a high-s DER host signature is accepted");
        assert_eq!(sig.as_bytes(), &raw, "raw low-s out");
        let sig64: [u8; 64] = sig.as_bytes().try_into().unwrap();
        verify_prehash_strict(&key.public_key(), &digest, &sig64).unwrap();

        assert!(matches!(
            sign(
                &registry,
                &handle,
                &digest,
                |_, _| async { Ok(vec![0x11u8; 64]) },
                no_lookup
            )
            .await,
            Err(PlatformError::CustodyError(_))
        ));
        assert!(matches!(
            sign(
                &registry,
                &handle,
                b"not a digest",
                |_, _| async { panic!("no host call for a non-digest") },
                no_lookup
            )
            .await,
            Err(PlatformError::CustodyError(_))
        ));
        assert!(matches!(
            dh_agree(&registry, &handle, &[9u8; 32], |_, _| async {
                panic!("no host call for a signing key")
            })
            .await,
            Err(PlatformError::WrongKeyType {
                expected: KeyType::HpkeP256,
                actual: KeyType::P256Signing
            })
        ));
        let point = key.public_key().to_compressed().to_vec();
        assert_eq!(
            public_key(&registry, &handle, |_| {
                let p = point.clone();
                async move { Ok(p) }
            })
            .await
            .unwrap()
            .as_bytes(),
            point.as_slice()
        );
    }

    /// A lookup a test expects never to happen.
    #[allow(clippy::unused_async)]
    async fn no_lookup(_: String) -> Result<Vec<u8>, PlatformError> {
        panic!("no get_public_key lookup for a registered handle")
    }

    /// A handle this adapter never minted or derived (a host key from an
    /// earlier session) is resolved through `get_public_key`: a 33-byte point
    /// binds a P-256 signing key whose signatures are verified strictly, 32
    /// bytes an Ed25519 key, and a host without the key fails the operation
    /// with no sign call. Any other length is refused and binds nothing.
    /// `dh_agree` and the Ed25519-only operations never resolve.
    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn unregistered_handles_resolve_through_get_public_key() {
        let key = P256SigningKey::from_scalar_bytes(&[0x21u8; 32]).unwrap();
        let point = key.public_key().to_compressed().to_vec();
        let digest = [0x5au8; 32];
        let raw = sign_prehash_rfc6979(&key, &digest).unwrap();
        let lookup = |bytes: Vec<u8>| {
            move |id: String| {
                let bytes = bytes.clone();
                async move {
                    assert_eq!(id, "42");
                    Ok(bytes)
                }
            }
        };
        let n = KeyHandle::new(42);

        // A fresh adapter still verifies strictly: junk is refused, and a
        // high-s DER signature comes out raw low-s.
        let registry = CallbackKeyRegistry::new();
        assert!(matches!(
            sign(
                &registry,
                &n,
                &digest,
                |_, _| async { Ok(vec![0x11u8; 64]) },
                lookup(point.clone())
            )
            .await,
            Err(PlatformError::CustodyError(_))
        ));
        let high_der = der(&raw[..32], &negate(&raw[32..]));
        let fresh = CallbackKeyRegistry::new();
        let sig = sign(
            &fresh,
            &n,
            &digest,
            |_, _| async move { Ok(high_der) },
            lookup(point.clone()),
        )
        .await
        .expect("a resolved P-256 key signs");
        assert_eq!(sig.as_bytes(), &raw);
        assert!(matches!(
            fresh.get(&n).unwrap(),
            Some(RegisteredKey::P256Signing(pk)) if pk == key.public_key()
        ));
        assert!(matches!(
            sign(
                &fresh,
                &n,
                b"not a digest",
                |_, _| async { panic!("no host call for a non-digest") },
                no_lookup
            )
            .await,
            Err(PlatformError::CustodyError(_))
        ));

        // 32 bytes: an Ed25519 key, signed by pass-through.
        let registry = CallbackKeyRegistry::new();
        let sig = sign(
            &registry,
            &n,
            b"message",
            |_, data| async move {
                assert_eq!(data, b"message");
                Ok(vec![3u8; 64])
            },
            lookup(vec![7u8; 32]),
        )
        .await
        .unwrap();
        assert_eq!(sig.as_bytes(), &[3u8; 64]);
        assert!(matches!(
            registry.get(&n).unwrap(),
            Some(RegisteredKey::Ed25519)
        ));

        // The host has no such key: its error, no sign call, nothing bound.
        let registry = CallbackKeyRegistry::new();
        assert!(matches!(
            sign(
                &registry,
                &n,
                &digest,
                |_, _| async { panic!("no sign call for a key the host lacks") },
                |_| async { Err(PlatformError::KeyNotFound) }
            )
            .await,
            Err(PlatformError::KeyNotFound)
        ));
        assert!(matches!(
            public_key(&registry, &n, |_| async { Err(PlatformError::KeyNotFound) }).await,
            Err(PlatformError::KeyNotFound)
        ));
        // Another length (here an HPKE point) binds nothing.
        let hpke = key.public_key().to_uncompressed().to_vec();
        assert!(matches!(
            public_key(&registry, &n, lookup(hpke)).await,
            Err(PlatformError::CustodyError(_))
        ));
        assert!(registry.get(&n).unwrap().is_none());
        // public_key resolves with one host call.
        let calls = std::sync::atomic::AtomicUsize::new(0);
        let p = point.clone();
        let got = public_key(&registry, &n, |_| {
            calls.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let p = p.clone();
            async move { Ok(p) }
        })
        .await
        .unwrap();
        assert_eq!(got.as_bytes(), point.as_slice());
        assert_eq!(calls.load(std::sync::atomic::Ordering::Relaxed), 1);

        let unknown = KeyHandle::new(99);
        assert!(matches!(
            dh_agree(&registry, &unknown, &[9u8; 32], |_, _| async {
                panic!("no host call for an unknown handle")
            })
            .await,
            Err(PlatformError::KeyNotFound)
        ));
        assert!(matches!(
            require_ed25519(&registry, &unknown),
            Err(PlatformError::KeyNotFound)
        ));
    }

    /// B2/B3: derivation needs an Ed25519 key, registered or resolved; the host's
    /// `get_public_key(key_id)` must confirm the point; a repeated derivation
    /// may return the same id for the same point, but an id held by another
    /// key or point is rejected. A rejected derivation registers nothing.
    #[tokio::test]
    async fn derive_pseudonym_binds_and_rejects() {
        let key = P256SigningKey::from_scalar_bytes(&[0x21u8; 32]).unwrap();
        let other = P256SigningKey::from_scalar_bytes(&[0x22u8; 32]).unwrap();
        let point = key.public_key().to_compressed().to_vec();
        let other_point = other.public_key().to_compressed().to_vec();
        let registry = registry_with_pseudonym(&key).await;
        registry
            .register(KeyHandle::new(2), RegisteredKey::X25519)
            .unwrap();
        let derive = |from: u64, pk: Vec<u8>, id: &'static str, host_pk: Vec<u8>| {
            let registry = &registry;
            async move {
                derive_pseudonym(
                    registry,
                    "derive_rotatable_pseudonym",
                    &KeyHandle::new(from),
                    |_| async move { Ok((pk, id.to_owned())) },
                    move |_| {
                        let host_pk = host_pk.clone();
                        async move { Ok(host_pk) }
                    },
                )
                .await
            }
        };

        // Same id, same point: accepted.
        derive(1, point.clone(), "7", point.clone()).await.unwrap();
        // Same id, another point; an id held by an identity key.
        for (id, pk) in [("7", &other_point), ("1", &other_point)] {
            let msg = derive(1, pk.clone(), id, pk.clone()).await.unwrap_err();
            assert!(msg.to_string().contains("already bound"), "{msg}");
        }
        // The host's own public key disagrees: nothing is registered.
        let msg = derive(1, other_point.clone(), "8", point.clone())
            .await
            .unwrap_err();
        assert!(msg.to_string().contains("does not match"), "{msg}");
        assert!(registry.get(&KeyHandle::new(8)).unwrap().is_none());
        // A 32-byte (Ed25519-era) pseudonym.
        assert!(matches!(
            derive(1, vec![2u8; 32], "8", vec![2u8; 32]).await,
            Err(PlatformError::CustodyError(_))
        ));
        // The source key must be a registered Ed25519 key.
        assert!(matches!(
            derive(2, point.clone(), "8", point.clone()).await,
            Err(PlatformError::WrongKeyType { .. })
        ));
        assert!(matches!(
            derive(7, point.clone(), "8", point.clone()).await,
            Err(PlatformError::WrongKeyType { .. })
        ));
        // An unregistered source resolves through get_public_key: the
        // host lacks it, it is a P-256 key, or it is an Ed25519 key.
        assert!(matches!(
            derive_pseudonym(
                &registry,
                "derive_pseudonym",
                &KeyHandle::new(99),
                |_| async { panic!("no derivation from a key the host lacks") },
                |_| async { Err(PlatformError::KeyNotFound) },
            )
            .await,
            Err(PlatformError::KeyNotFound)
        ));
        assert!(matches!(
            derive(98, point.clone(), "8", point.clone()).await,
            Err(PlatformError::WrongKeyType { .. })
        ));
        let p = point.clone();
        let derived = derive_pseudonym(
            &registry,
            "derive_pseudonym",
            &KeyHandle::new(97),
            |_| async move { Ok((p, "9".to_owned())) },
            |id| {
                let bytes = if id == "97" {
                    vec![5u8; 32]
                } else {
                    point.clone()
                };
                async move { Ok(bytes) }
            },
        )
        .await
        .expect("a resolved Ed25519 identity derives");
        assert_eq!(derived.key_handle().id(), 9);
        assert!(matches!(
            registry.get(&KeyHandle::new(97)).unwrap(),
            Some(RegisteredKey::Ed25519)
        ));
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
        registry.take(&h).unwrap();
        assert!(registry.get(&h).unwrap().is_none());
    }

    type Log = std::sync::Mutex<Vec<String>>;

    async fn generate_with(
        registry: &CallbackKeyRegistry,
        key_type: KeyType,
        key_id: &str,
        public_key: Result<Vec<u8>, PlatformError>,
        destroyed: &Log,
    ) -> Result<KeyHandle, PlatformError> {
        let key_id = key_id.to_owned();
        generate_keypair(
            registry,
            key_type,
            |_| async move { Ok(key_id) },
            |_| async move { public_key },
            |id| async move {
                destroyed.lock().unwrap().push(id);
                Ok(())
            },
        )
        .await
    }

    /// A7: every generation the adapter rejects destroys the host key it was
    /// handed: a non-canonical id (for each key type), a malformed P-256 public
    /// key, and a failing public-key fetch. An accepted key is not destroyed.
    #[tokio::test]
    async fn rejected_generation_destroys_the_host_key() {
        type Case = (KeyType, &'static str, Result<Vec<u8>, PlatformError>);
        let valid = P256SigningKey::from_scalar_bytes(&[5u8; 32])
            .unwrap()
            .public_key();
        let cases: Vec<Case> = vec![
            (KeyType::Ed25519, "not-a-number", Ok(vec![])),
            (KeyType::X25519, "", Ok(vec![])),
            (
                KeyType::P256Signing,
                "-1",
                Ok(valid.to_compressed().to_vec()),
            ),
            (
                KeyType::HpkeP256,
                "0x10",
                Ok(valid.to_uncompressed().to_vec()),
            ),
            (
                KeyType::P256Signing,
                "11",
                Ok(valid.to_uncompressed().to_vec()),
            ),
            (KeyType::HpkeP256, "12", Ok(valid.to_compressed().to_vec())),
            // x = 2^256 - 1 is not a field element.
            (
                KeyType::P256Signing,
                "13",
                Ok([&[0x02][..], &[0xFF; 32]].concat()),
            ),
            (
                KeyType::HpkeP256,
                "14",
                Err(PlatformError::CustodyError("host get failed".into())),
            ),
        ];
        for (key_type, key_id, public_key) in cases {
            let registry = CallbackKeyRegistry::new();
            let destroyed = Log::default();
            let result = generate_with(&registry, key_type, key_id, public_key, &destroyed).await;
            assert!(
                matches!(result, Err(PlatformError::CustodyError(_))),
                "{key_type:?} {key_id:?}: {result:?}"
            );
            assert_eq!(
                *destroyed.lock().unwrap(),
                vec![key_id.to_owned()],
                "{key_type:?} {key_id:?} must be destroyed"
            );
        }

        let registry = CallbackKeyRegistry::new();
        let destroyed = Log::default();
        let handle = generate_with(
            &registry,
            KeyType::P256Signing,
            "15",
            Ok(valid.to_compressed().to_vec()),
            &destroyed,
        )
        .await
        .unwrap();
        assert_eq!(handle.id(), 15);
        assert!(destroyed.lock().unwrap().is_empty());

        // A reused id is rejected without destroying the live key under it.
        let again = generate_with(&registry, KeyType::Ed25519, "15", Ok(vec![]), &destroyed).await;
        assert!(matches!(again, Err(PlatformError::CustodyError(_))));
        assert!(destroyed.lock().unwrap().is_empty());
        assert!(matches!(
            registry.get(&handle).unwrap(),
            Some(RegisteredKey::P256Signing(_))
        ));
    }

    /// A6: the entry is taken before the host destroy, so a generation that
    /// reuses the id while the destroy is in flight keeps its registration;
    /// a failed destroy restores the entry.
    #[tokio::test]
    async fn destroy_takes_before_the_host_call_and_restores_on_failure() {
        let registry = CallbackKeyRegistry::new();
        let h = KeyHandle::new(21);
        registry.register(h, RegisteredKey::X25519).unwrap();

        // The host fails: the entry comes back.
        let failed = destroy_key(&registry, &h, |_| async {
            Err(PlatformError::CustodyError("host destroy failed".into()))
        })
        .await;
        assert!(matches!(failed, Err(PlatformError::CustodyError(_))));
        assert!(matches!(
            registry.get(&h).unwrap(),
            Some(RegisteredKey::X25519)
        ));

        // During the host call the id is already free, and a concurrent
        // generation that reuses it survives the destroy's completion.
        destroy_key(&registry, &h, |_| {
            assert!(registry.get(&h).unwrap().is_none());
            registry.register(h, RegisteredKey::Ed25519).unwrap();
            async { Ok(()) }
        })
        .await
        .unwrap();
        assert!(matches!(
            registry.get(&h).unwrap(),
            Some(RegisteredKey::Ed25519)
        ));

        // A failed destroy never overwrites an entry registered meanwhile.
        destroy_key(&registry, &h, |_| {
            registry.register(h, RegisteredKey::X25519).unwrap();
            async { Err(PlatformError::CustodyError("host destroy failed".into())) }
        })
        .await
        .unwrap_err();
        assert!(matches!(
            registry.get(&h).unwrap(),
            Some(RegisteredKey::X25519)
        ));
    }
}
