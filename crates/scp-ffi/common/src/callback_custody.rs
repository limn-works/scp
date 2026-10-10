//! Shared key cache, host-answer validation and adapter flows for the
//! callback-custody bridges.
//!
//! The `PyO3`, napi-rs, and `UniFFI` bridges adapt a host `KeyCustodyProvider`
//! to [`KeyCustody`](scp_platform::KeyCustody). The host returns raw bytes, so
//! this module holds every rule for trusting what it returns, once, and the
//! three bridges only supply one closure per host call:
//!
//! - The host's `get_public_key` answers with a typed [`HostPublicKey`]: the
//!   key's [`KeyType`], its public key, and the [`KeyRole`] the host minted it
//!   in. [`registered_key`] requires the exact length for the stated type
//!   (Ed25519 32, X25519 32, P-256 signing 33, HPKE P-256 65) and a valid key.
//!   The bridge never infers a type from a length.
//! - [`CallbackKeyRegistry`] caches the type, public key and role of each
//!   handle this adapter minted or resolved. The host owns whether a key
//!   exists: a handle the cache lacks (a host key from an earlier session, or
//!   one destroyed in this session) is resolved through `get_public_key` the
//!   same way in every entry point, and a host that no longer holds the key
//!   answers key-not-found. A destroy drops the cache entry when the host
//!   confirms it or reports the key absent. A resolution that awaits the
//!   host while a destroy of the same id completes caches the destroyed key;
//!   no operation succeeds from that entry alone, because each one either
//!   calls the host, which answers key-not-found, or fails a type or role
//!   check first.
//! - Every host signature is verified: an Ed25519 signature strictly over the
//!   data under the cached verifying key, a P-256 signature through
//!   [`p256_host_signature`]. An exported Ed25519 seed must produce the cached
//!   verifying key ([`export_ed25519_signing_key`]).
//! - Pseudonym derivation requires an Ed25519 [`KeyRole::Identity`] source
//!   ([`scp_platform::require_derive_source`]). A pseudonym has no private key
//!   (§9.10.4): the host returns only the 33-byte compressed point, which
//!   becomes a [`Pseudonym`], and the cache records nothing for it.
//!
//! See ADR-006 and the per-bridge `CallbackKeyCustody` adapters.

use std::collections::HashMap;
use std::sync::Mutex;

use ed25519_dalek::VerifyingKey;
use scp_crypto::p256::{
    COMPRESSED_POINT_LEN, P256PublicKey, SIGNATURE_LEN, UNCOMPRESSED_POINT_LEN, der_to_raw,
    normalize_low_s, verify_prehash_strict,
};
use scp_platform::error::PlatformError;
use scp_platform::traits::{
    KeyHandle, KeyRole, KeyType, Pseudonym, PublicKey, SharedSecret, Signature,
};

/// A host's `get_public_key` answer: the key's type, its public key, and the
/// role the host recorded when it minted the key.
///
/// The host records the role `generate_keypair` named and reports it for
/// the key's lifetime, across adapter instances, so a new adapter resolves
/// an identity key from an earlier session as an identity. Rust cannot check
/// the host's word: a host that reports [`KeyRole::Identity`] for a key it
/// minted as operational lets that key derive pseudonyms, and that is outside
/// the bridge's control.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostPublicKey {
    /// The key's type.
    pub key_type: KeyType,
    /// The public key: 32 bytes (Ed25519, X25519), the 33-byte compressed
    /// SEC1 point ([`KeyType::P256Signing`]), or the 65-byte uncompressed SEC1
    /// point ([`KeyType::HpkeP256`]).
    pub public_key: Vec<u8>,
    /// The role the key was minted in.
    pub role: KeyRole,
}

impl HostPublicKey {
    /// Builds an answer from a host that names the type and role as strings
    /// ([`KeyType::as_str`], [`KeyRole::as_str`]), as the Python host does.
    ///
    /// # Errors
    ///
    /// [`PlatformError::CustodyError`] for a type or role name the host
    /// contract does not define.
    pub fn from_names(
        method: &str,
        key_type: &str,
        public_key: Vec<u8>,
        role: &str,
    ) -> Result<Self, PlatformError> {
        let key_type = KeyType::parse(key_type).ok_or_else(|| {
            PlatformError::CustodyError(format!(
                "KeyCustodyProvider.{method} returned unknown key type {key_type:?}"
            ))
        })?;
        let role = KeyRole::parse(role).ok_or_else(|| {
            PlatformError::CustodyError(format!(
                "KeyCustodyProvider.{method} returned unknown key role {role:?}"
            ))
        })?;
        Ok(Self {
            key_type,
            public_key,
            role,
        })
    }
}

/// A key the adapter holds, with its public key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegisteredKey {
    /// An Ed25519 key and its verifying key.
    Ed25519(VerifyingKey),
    /// An X25519 key and its public key.
    X25519([u8; 32]),
    /// A P-256 signing key and its public key.
    P256Signing(P256PublicKey),
    /// A P-256 HPKE key and its public key.
    HpkeP256(P256PublicKey),
}

impl RegisteredKey {
    /// The key's [`KeyType`].
    #[must_use]
    pub const fn key_type(&self) -> KeyType {
        match self {
            Self::Ed25519(_) => KeyType::Ed25519,
            Self::X25519(_) => KeyType::X25519,
            Self::P256Signing(_) => KeyType::P256Signing,
            Self::HpkeP256(_) => KeyType::HpkeP256,
        }
    }

    /// The public key in the form [`KeyCustody::public_key`] returns.
    ///
    /// [`KeyCustody::public_key`]: scp_platform::KeyCustody::public_key
    #[must_use]
    pub fn public_bytes(&self) -> Vec<u8> {
        match self {
            Self::Ed25519(vk) => vk.to_bytes().to_vec(),
            Self::X25519(pk) => pk.to_vec(),
            Self::P256Signing(pk) => pk.to_compressed().to_vec(),
            Self::HpkeP256(pk) => pk.to_uncompressed().to_vec(),
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

/// A cached key: its type and public key, and its role.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisteredEntry {
    /// The key and its public key.
    pub key: RegisteredKey,
    /// What it is for.
    pub role: KeyRole,
}

/// Handle → cached entry for the handles one adapter instance minted or
/// resolved.
///
/// The cache is not the authority on whether a key exists; the host is. A
/// handle the cache lacks is resolved through the host, and a destroy removes
/// the entry when the host confirms the key is gone. An entry can outlive
/// its key: a [`resolve`] that awaits the host's `get_public_key` while a
/// [`destroy_key`] of the same id completes binds the destroyed key
/// afterwards. Every operation on that entry still calls the host (which
/// answers key-not-found) or fails a type or role check, and a later
/// [`destroy_key`] drops it. The map holds at most one entry per key the
/// caller minted or used.
#[derive(Debug, Default)]
pub struct CallbackKeyRegistry {
    entries: Mutex<HashMap<u64, RegisteredEntry>>,
}

impl CallbackKeyRegistry {
    /// An empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(
        &self,
    ) -> Result<std::sync::MutexGuard<'_, HashMap<u64, RegisteredEntry>>, PlatformError> {
        self.entries.lock().map_err(|_| {
            PlatformError::CustodyError("callback custody key registry lock poisoned".into())
        })
    }

    /// Caches a key `generate_keypair` minted.
    ///
    /// # Errors
    ///
    /// [`PlatformError::CustodyError`] if the id is already cached (the host
    /// contract forbids reusing a key id), or the registry lock is poisoned.
    pub fn register(&self, handle: KeyHandle, entry: RegisteredEntry) -> Result<(), PlatformError> {
        let mut entries = self.lock()?;
        if entries.contains_key(&handle.id()) {
            return Err(PlatformError::CustodyError(format!(
                "KeyCustodyProvider.generate_keypair returned key_id {} that names a key \
                 this adapter already holds",
                handle.id()
            )));
        }
        entries.insert(handle.id(), entry);
        drop(entries);
        Ok(())
    }

    /// Caches a host key resolved through `get_public_key`, in the role the
    /// host reported. Resolution is a lookup a host may answer twice (two
    /// concurrent resolutions), so an id already cached with the same key
    /// returns the cached entry, role and all.
    ///
    /// # Errors
    ///
    /// [`PlatformError::CustodyError`] if the id is cached with another key,
    /// or the registry lock is poisoned.
    pub fn bind_resolved(
        &self,
        handle: KeyHandle,
        key: RegisteredKey,
        role: KeyRole,
    ) -> Result<RegisteredEntry, PlatformError> {
        let mut entries = self.lock()?;
        let bound = match entries.get(&handle.id()) {
            Some(existing) if existing.key == key => Ok(existing.clone()),
            Some(_) => Err(PlatformError::CustodyError(format!(
                "KeyCustodyProvider.get_public_key: key_id {} is already bound to another key",
                handle.id()
            ))),
            None => {
                let entry = RegisteredEntry { key, role };
                entries.insert(handle.id(), entry.clone());
                Ok(entry)
            }
        };
        drop(entries);
        bound
    }

    /// The cached entry for a handle, or `None` if the cache lacks it.
    ///
    /// # Errors
    ///
    /// [`PlatformError::CustodyError`] if the registry lock is poisoned.
    pub fn get(&self, handle: &KeyHandle) -> Result<Option<RegisteredEntry>, PlatformError> {
        Ok(self.lock()?.get(&handle.id()).cloned())
    }

    /// Drops a handle's entry, once the host has confirmed the key is gone.
    ///
    /// # Errors
    ///
    /// [`PlatformError::CustodyError`] if the registry lock is poisoned.
    fn remove(&self, handle: KeyHandle) -> Result<(), PlatformError> {
        self.lock()?.remove(&handle.id());
        Ok(())
    }

    /// Whether host key id `key_id` names a cached key. An id
    /// [`parse_handle`](crate::custody_parse::parse_handle) refuses
    /// (non-numeric, or a non-canonical form such as `"07"`) names none: the
    /// cache holds only ids that parse, each under its one canonical spelling.
    fn names_cached(&self, key_id: &str) -> Result<bool, PlatformError> {
        let Ok(handle) = crate::custody_parse::parse_handle("generate_keypair", key_id) else {
            return Ok(false);
        };
        Ok(self.lock()?.contains_key(&handle.id()))
    }
}

/// Validates a host's `get_public_key` answer.
///
/// The public key must have exactly the stated type's length (Ed25519 32,
/// X25519 32, P-256 signing 33, HPKE P-256 65) and be a valid key: a non-weak
/// Ed25519 point, or a P-256 point on the curve that is not the identity.
///
/// # Errors
///
/// [`PlatformError::CustodyError`] for a wrong length or an invalid key.
pub fn registered_key(
    method: &str,
    answer: &HostPublicKey,
) -> Result<RegisteredKey, PlatformError> {
    let key_type = answer.key_type;
    let bytes = answer.public_key.as_slice();
    match key_type {
        KeyType::P256Signing => Ok(RegisteredKey::P256Signing(p256_public_key(
            method, key_type, bytes,
        )?)),
        KeyType::HpkeP256 => Ok(RegisteredKey::HpkeP256(p256_public_key(
            method, key_type, bytes,
        )?)),
        KeyType::Ed25519 | KeyType::X25519 => {
            let raw: [u8; 32] = bytes.try_into().map_err(|_| {
                PlatformError::CustodyError(format!(
                    "KeyCustodyProvider.{method} returned {} bytes for a {} key, expected 32",
                    bytes.len(),
                    key_type.as_str()
                ))
            })?;
            if key_type == KeyType::X25519 {
                return Ok(RegisteredKey::X25519(raw));
            }
            match VerifyingKey::from_bytes(&raw) {
                Ok(vk) if !vk.is_weak() => Ok(RegisteredKey::Ed25519(vk)),
                _ => Err(PlatformError::CustodyError(format!(
                    "KeyCustodyProvider.{method} returned an invalid Ed25519 public key"
                ))),
            }
        }
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
            key_type.as_str()
        )));
    }
    P256PublicKey::from_sec1(bytes).map_err(|e| {
        PlatformError::CustodyError(format!(
            "KeyCustodyProvider.{method} returned an invalid P-256 public key: {e}"
        ))
    })
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

/// Accepts a host Ed25519 signature only when it is 64 bytes and verifies
/// strictly over `data` under `verifying_key`.
///
/// # Errors
///
/// [`PlatformError::CustodyError`] otherwise.
pub fn ed25519_host_signature(
    verifying_key: &VerifyingKey,
    data: &[u8],
    host_signature: Vec<u8>,
) -> Result<Signature, PlatformError> {
    let bytes: [u8; SIGNATURE_LEN] = host_signature.as_slice().try_into().map_err(|_| {
        PlatformError::CustodyError(format!(
            "KeyCustodyProvider.sign returned {} bytes, expected {SIGNATURE_LEN}",
            host_signature.len()
        ))
    })?;
    verifying_key
        .verify_strict(data, &ed25519_dalek::Signature::from_bytes(&bytes))
        .map_err(|_| {
            PlatformError::CustodyError(
                "KeyCustodyProvider.sign returned an Ed25519 signature that does not verify \
                 over the data under the key's public key"
                    .into(),
            )
        })?;
    Ok(Signature::new(host_signature))
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

// ---------------------------------------------------------------------------
// Adapter flows
//
// Each bridge supplies its host calls as closures; these functions hold every
// decision (key types, roles, cache, lengths, signature and seed checks) so
// the bridges cannot drift. The closures take the key id as the host's
// string.
// ---------------------------------------------------------------------------

/// `KeyCustody::generate_keypair` over a host: mints a key of `key_type` in
/// [`KeyRole::Operational`]. See [`generate_identity`] for the identity key.
///
/// # Errors
///
/// As in [`generate_identity`].
pub async fn generate_operational<G, GF, P, PF, D, DF>(
    registry: &CallbackKeyRegistry,
    key_type: KeyType,
    host_generate: G,
    host_get_public_key: P,
    host_destroy: D,
) -> Result<KeyHandle, PlatformError>
where
    G: FnOnce(KeyType, KeyRole) -> GF,
    GF: Future<Output = Result<String, PlatformError>>,
    P: FnOnce(String) -> PF,
    PF: Future<Output = Result<HostPublicKey, PlatformError>>,
    D: FnOnce(String) -> DF,
    DF: Future<Output = Result<(), PlatformError>>,
{
    generate(
        registry,
        key_type,
        KeyRole::Operational,
        host_generate,
        host_get_public_key,
        host_destroy,
    )
    .await
}

/// `KeyCustody::generate_identity_keypair` over a host: mints an Ed25519 key
/// in [`KeyRole::Identity`], the only pseudonym-derivation source.
///
/// Asks the host for the key and for its public key, which must state the
/// requested type and role and pass [`registered_key`], and caches it. When
/// the key id is not numeric, the host's `get_public_key` fails, or the
/// host's answer is refused, the flow destroys the new host key before it
/// returns the error, and appends a destroy failure other than key-not-found
/// to the error. The flow leaves the host key in place in two cases. When the
/// cache already holds the id, the id names a key this adapter holds, so the
/// flow returns the refusal alone. When the registry lock is poisoned, the
/// cache cannot say whether the id names a held key, so the flow appends that
/// the key was not destroyed. When the host's `generate_keypair` fails, no key
/// id exists and nothing is destroyed.
///
/// A caller that drops this future between the host's mint and the cache
/// write leaves the minted key on the host, unnamed by any handle.
///
/// # Errors
///
/// Any host error; [`PlatformError::CustodyError`] for a non-numeric key id,
/// a refused public key, another stated type or role, or a cached key id.
pub async fn generate_identity<G, GF, P, PF, D, DF>(
    registry: &CallbackKeyRegistry,
    host_generate: G,
    host_get_public_key: P,
    host_destroy: D,
) -> Result<KeyHandle, PlatformError>
where
    G: FnOnce(KeyType, KeyRole) -> GF,
    GF: Future<Output = Result<String, PlatformError>>,
    P: FnOnce(String) -> PF,
    PF: Future<Output = Result<HostPublicKey, PlatformError>>,
    D: FnOnce(String) -> DF,
    DF: Future<Output = Result<(), PlatformError>>,
{
    generate(
        registry,
        KeyType::Ed25519,
        KeyRole::Identity,
        host_generate,
        host_get_public_key,
        host_destroy,
    )
    .await
}

/// The one generation flow; [`generate_operational`] and
/// [`generate_identity`] fix the role.
async fn generate<G, GF, P, PF, D, DF>(
    registry: &CallbackKeyRegistry,
    key_type: KeyType,
    role: KeyRole,
    host_generate: G,
    host_get_public_key: P,
    host_destroy: D,
) -> Result<KeyHandle, PlatformError>
where
    G: FnOnce(KeyType, KeyRole) -> GF,
    GF: Future<Output = Result<String, PlatformError>>,
    P: FnOnce(String) -> PF,
    PF: Future<Output = Result<HostPublicKey, PlatformError>>,
    D: FnOnce(String) -> DF,
    DF: Future<Output = Result<(), PlatformError>>,
{
    let key_id = host_generate(key_type, role).await?;
    let registered = async {
        let handle = crate::custody_parse::parse_handle("generate_keypair", &key_id)?;
        let answer = host_get_public_key(key_id.clone()).await?;
        let key = registered_key("get_public_key", &answer)?;
        if key.key_type() != key_type {
            return Err(PlatformError::CustodyError(format!(
                "KeyCustodyProvider.generate_keypair({}) produced a {} key",
                key_type.as_str(),
                key.key_type().as_str()
            )));
        }
        if answer.role != role {
            return Err(PlatformError::CustodyError(format!(
                "KeyCustodyProvider.generate_keypair asked for a {} key, and get_public_key \
                 reports it as {}",
                role.as_str(),
                answer.role.as_str()
            )));
        }
        registry.register(handle, RegisteredEntry { key, role })?;
        Ok(handle)
    }
    .await;
    let Err(refused) = registered else {
        return registered;
    };
    match registry.names_cached(&key_id) {
        // The id names a key this adapter holds: destroy nothing.
        Ok(true) => Err(refused),
        Err(poisoned) => Err(PlatformError::CustodyError(format!(
            "{refused}; the rejected host key {key_id} was not destroyed: {poisoned}"
        ))),
        Ok(false) => match host_destroy(key_id.clone()).await {
            Ok(()) | Err(PlatformError::KeyNotFound) => Err(refused),
            Err(destroy_err) => Err(PlatformError::CustodyError(format!(
                "{refused}; destroying the rejected host key {key_id} also failed: {destroy_err}"
            ))),
        },
    }
}

/// The cached entry for `key`, resolving a handle the cache lacks through
/// the host's `get_public_key`. Every entry point calls this, so no result
/// depends on which ran first.
///
/// A host keeps its keys, and the role it minted each with, across adapter
/// instances, so a handle from an earlier session is still the host's key.
/// Its answer passes [`registered_key`] and binds the handle in the role the
/// host reports ([`CallbackKeyRegistry::bind_resolved`]): an identity minted
/// in an earlier session resolves as an identity. Returns the entry and
/// whether this call asked the host.
///
/// # Errors
///
/// The host's own error for a key it lacks (a conforming host reports
/// [`PlatformError::KeyNotFound`]); as in [`registered_key`] and
/// [`CallbackKeyRegistry::bind_resolved`].
pub async fn resolve<P, PF>(
    registry: &CallbackKeyRegistry,
    key: &KeyHandle,
    host_get_public_key: &P,
) -> Result<(RegisteredEntry, bool), PlatformError>
where
    P: Fn(String) -> PF + Sync,
    PF: Future<Output = Result<HostPublicKey, PlatformError>>,
{
    if let Some(entry) = registry.get(key)? {
        return Ok((entry, false));
    }
    let answer = host_get_public_key(key.id().to_string()).await?;
    let found = registered_key("get_public_key", &answer)?;
    Ok((registry.bind_resolved(*key, found, answer.role)?, true))
}

/// `KeyCustody::sign` over a host provider.
///
/// A P-256 signing key (generated or resolved) signs a 32-byte
/// digest and its host result passes [`p256_host_signature`]. An Ed25519 key
/// signs `data` and its host result passes [`ed25519_host_signature`]. A
/// key-agreement key is [`PlatformError::WrongKeyType`] without a host sign
/// call.
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
    P: Fn(String) -> PF + Sync,
    PF: Future<Output = Result<HostPublicKey, PlatformError>>,
{
    let key_id = key.id().to_string();
    match resolve(registry, key, &host_get_public_key).await?.0.key {
        RegisteredKey::P256Signing(pk) => {
            let digest = p256_digest(data)?;
            let host_sig = host_sign(key_id, digest.to_vec()).await?;
            p256_host_signature(&pk, &digest, &host_sig)
        }
        RegisteredKey::Ed25519(vk) => {
            ed25519_host_signature(&vk, data, host_sign(key_id, data.to_vec()).await?)
        }
        k @ RegisteredKey::X25519(_) => Err(k.wrong_type(KeyType::Ed25519)),
        k @ RegisteredKey::HpkeP256(_) => Err(k.wrong_type(KeyType::P256Signing)),
    }
}

/// `KeyCustody::public_key` over a host provider.
///
/// Returns the cached public key. For a handle already cached, the host's
/// current answer must still pass [`registered_key`] and name the same key in
/// the same role; a resolution asks the host once.
///
/// # Errors
///
/// Any host error; [`PlatformError::CustodyError`] for a refused or changed
/// key or role, and as in [`resolve`].
pub async fn public_key<P, PF>(
    registry: &CallbackKeyRegistry,
    key: &KeyHandle,
    host_get_public_key: P,
) -> Result<PublicKey, PlatformError>
where
    P: Fn(String) -> PF + Sync,
    PF: Future<Output = Result<HostPublicKey, PlatformError>>,
{
    let (entry, asked) = resolve(registry, key, &host_get_public_key).await?;
    if !asked {
        let answer = host_get_public_key(key.id().to_string()).await?;
        let current = registered_key("get_public_key", &answer)?;
        if answer.role != entry.role {
            return Err(PlatformError::CustodyError(
                "KeyCustodyProvider.get_public_key reports another role than the one \
                 registered for this key_id"
                    .into(),
            ));
        }
        if current != entry.key {
            return Err(PlatformError::CustodyError(
                "KeyCustodyProvider.get_public_key returned a different key than the one \
                 registered for this key_id"
                    .into(),
            ));
        }
    }
    Ok(PublicKey::new(entry.key.public_bytes()))
}

/// `KeyCustody::dh_agree` over a host provider.
///
/// An HPKE P-256 key requires a valid 65-byte uncompressed peer point, an
/// X25519 key a 32-byte peer, both checked before the host call. A signing
/// key is [`PlatformError::WrongKeyType`] without a host call. The host must
/// return exactly 32 bytes, which are zeroized once copied.
///
/// # Errors
///
/// Any host error; [`PlatformError::WrongKeyType`] or
/// [`PlatformError::CustodyError`] as above and in [`resolve`].
pub async fn dh_agree<H, HF, P, PF>(
    registry: &CallbackKeyRegistry,
    key: &KeyHandle,
    peer_public: &[u8],
    host_dh_agree: H,
    host_get_public_key: P,
) -> Result<SharedSecret, PlatformError>
where
    H: FnOnce(String, Vec<u8>) -> HF,
    HF: Future<Output = Result<Vec<u8>, PlatformError>>,
    P: Fn(String) -> PF + Sync,
    PF: Future<Output = Result<HostPublicKey, PlatformError>>,
{
    let peer = match resolve(registry, key, &host_get_public_key).await?.0.key {
        RegisteredKey::HpkeP256(_) => p256_peer_for_host(peer_public)?.to_vec(),
        RegisteredKey::X25519(_) => x25519_peer(peer_public)?.to_vec(),
        k @ RegisteredKey::Ed25519(_) => return Err(k.wrong_type(KeyType::X25519)),
        k @ RegisteredKey::P256Signing(_) => return Err(k.wrong_type(KeyType::HpkeP256)),
    };
    let shared = zeroize::Zeroizing::new(host_dh_agree(key.id().to_string(), peer).await?);
    Ok(SharedSecret::new(crate::custody_parse::expect_32(
        "dh_agree", &shared,
    )?))
}

/// `KeyCustody::destroy_key` over a host provider.
///
/// The host destroys the key; the cache entry is dropped when the host
/// confirms the key is gone, by success or by key-not-found. A host failure
/// leaves the entry, so the handle still names the key the host still holds.
/// A [`resolve`] of the same id that was awaiting the host when this call
/// dropped the entry binds the destroyed key again; the host stays the
/// authority, so every later operation on the handle reaches it and fails
/// key-not-found (or fails a type or role check first).
///
/// # Errors
///
/// [`PlatformError::KeyNotFound`] when the host does not hold the key; any
/// other host error; a poisoned registry.
pub async fn destroy_key<D, DF>(
    registry: &CallbackKeyRegistry,
    key: &KeyHandle,
    host_destroy: D,
) -> Result<(), PlatformError>
where
    D: FnOnce(String) -> DF,
    DF: Future<Output = Result<(), PlatformError>>,
{
    match host_destroy(key.id().to_string()).await {
        Ok(()) => registry.remove(*key),
        Err(PlatformError::KeyNotFound) => {
            registry.remove(*key)?;
            Err(PlatformError::KeyNotFound)
        }
        Err(e) => Err(e),
    }
}

/// The verifying key of an Ed25519 handle, resolving a handle the cache
/// lacks like every other entry point.
///
/// # Errors
///
/// [`PlatformError::WrongKeyType`] for another type, or as in [`resolve`].
async fn require_ed25519<P, PF>(
    registry: &CallbackKeyRegistry,
    key: &KeyHandle,
    host_get_public_key: &P,
) -> Result<VerifyingKey, PlatformError>
where
    P: Fn(String) -> PF + Sync,
    PF: Future<Output = Result<HostPublicKey, PlatformError>>,
{
    match resolve(registry, key, host_get_public_key).await?.0.key {
        RegisteredKey::Ed25519(vk) => Ok(vk),
        k => Err(k.wrong_type(KeyType::Ed25519)),
    }
}

/// `KeyCustody::ed25519_to_x25519_agree` over a host provider. The host
/// protocol has no separate birational conversion, so the host's `dh_agree`
/// runs on the Ed25519 key with the 32-byte X25519 peer.
///
/// # Errors
///
/// [`PlatformError::WrongKeyType`] for a handle that is not Ed25519, with no
/// agreement call; any host error; [`PlatformError::CustodyError`] when the
/// host returns other than 32 bytes; as in [`resolve`].
pub async fn ed25519_to_x25519_agree<H, HF, P, PF>(
    registry: &CallbackKeyRegistry,
    key: &KeyHandle,
    peer_x25519_public: &[u8; 32],
    host_dh_agree: H,
    host_get_public_key: P,
) -> Result<SharedSecret, PlatformError>
where
    H: FnOnce(String, Vec<u8>) -> HF,
    HF: Future<Output = Result<Vec<u8>, PlatformError>>,
    P: Fn(String) -> PF + Sync,
    PF: Future<Output = Result<HostPublicKey, PlatformError>>,
{
    require_ed25519(registry, key, &host_get_public_key).await?;
    let shared = zeroize::Zeroizing::new(
        host_dh_agree(key.id().to_string(), peer_x25519_public.to_vec()).await?,
    );
    Ok(SharedSecret::new(crate::custody_parse::expect_32(
        "ed25519_to_x25519_agree",
        &shared,
    )?))
}

/// Exports the Ed25519 signing key of `key` through the host's
/// `export_signing_key_bytes`.
///
/// The host's 32-byte seed must produce the verifying key cached (or
/// resolved) for the handle; a seed for any other key is refused, so a host
/// cannot hand the caller a key that signs under another identity. The
/// host's buffer and the parsed seed are wiped on drop.
///
/// # Errors
///
/// [`PlatformError::WrongKeyType`] for a handle that is not Ed25519, with no
/// export call; any host error; [`PlatformError::CustodyError`] for a seed
/// that is not 32 bytes or whose public key is not the handle's; as in
/// [`resolve`].
pub async fn export_ed25519_signing_key<E, EF, P, PF>(
    registry: &CallbackKeyRegistry,
    key: &KeyHandle,
    host_export: E,
    host_get_public_key: P,
) -> Result<ed25519_dalek::SigningKey, PlatformError>
where
    E: FnOnce(String) -> EF,
    EF: Future<Output = Result<Vec<u8>, PlatformError>>,
    P: Fn(String) -> PF + Sync,
    PF: Future<Output = Result<HostPublicKey, PlatformError>>,
{
    let expected = require_ed25519(registry, key, &host_get_public_key).await?;
    let bytes = zeroize::Zeroizing::new(host_export(key.id().to_string()).await?);
    let seed = zeroize::Zeroizing::new(crate::custody_parse::expect_32(
        "export_signing_key_bytes",
        &bytes,
    )?);
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
    if signing_key.verifying_key() != expected {
        return Err(PlatformError::CustodyError(
            "KeyCustodyProvider.export_signing_key_bytes returned a seed whose public key is \
             not the one registered for this key_id"
                .into(),
        ));
    }
    Ok(signing_key)
}

/// `KeyCustody::derive_pseudonym` (`epoch` `None`) and
/// `derive_rotatable_pseudonym` over a host provider.
///
/// `key` must be an Ed25519 [`KeyRole::Identity`] key
/// ([`scp_platform::require_derive_source`]): an operational key is
/// [`PlatformError::NotIdentityKey`] and an identity of another type
/// [`PlatformError::WrongKeyType`], each with no derive call. A key the host
/// no longer holds is the host's key-not-found (§9.10.4.A). A pseudonym has
/// no private key, so the host returns only the point; [`parse_pseudonym`]
/// requires a 33-byte compressed P-256 point, and nothing is cached.
///
/// [`parse_pseudonym`]: crate::custody_parse::parse_pseudonym
///
/// # Errors
///
/// As above and in [`resolve`]; any `host_derive` error;
/// [`PlatformError::PseudonymRejected`] (reported as `SCP-IDENT-1055`) for
/// bytes that are not a compressed P-256 point.
pub async fn derive_pseudonym<H, HF, P, PF>(
    registry: &CallbackKeyRegistry,
    key: &KeyHandle,
    epoch: Option<u64>,
    host_derive: H,
    host_get_public_key: P,
) -> Result<Pseudonym, PlatformError>
where
    H: FnOnce(String) -> HF,
    HF: Future<Output = Result<Vec<u8>, PlatformError>>,
    P: Fn(String) -> PF + Sync,
    PF: Future<Output = Result<HostPublicKey, PlatformError>>,
{
    let method = if epoch.is_some() {
        "derive_rotatable_pseudonym"
    } else {
        "derive_pseudonym"
    };
    let source = resolve(registry, key, &host_get_public_key).await?.0;
    scp_platform::require_derive_source(source.role, source.key.key_type())?;
    let point = host_derive(key.id().to_string()).await?;
    crate::custody_parse::parse_pseudonym(method, &point)
}

/// A software host for bridge tests: Ed25519, P-256 signing and HPKE P-256
/// keys, answering the host callbacks the way a conforming platform keystore
/// does.
///
/// It signs P-256 digests with a high `s` in DER, so a test proves the
/// adapter normalises what a real host may return; reports an unknown key id
/// as [`PlatformError::KeyNotFound`], which each bridge's test provider turns
/// into that bridge's typed not-found; and counts every call by method.
#[cfg(any(test, feature = "testing"))]
pub mod fake_host {
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Mutex, MutexGuard};

    use ed25519_dalek::Signer;
    use scp_crypto::p256::{P256PublicKey, P256SecretKey, ecdh_p256, sign_prehash_rfc6979};
    use scp_crypto::pseudonym::{PseudonymVersion, derive_pseudonym};
    use scp_platform::error::PlatformError;

    use scp_platform::traits::{KeyRole, KeyType};

    use super::HostPublicKey;

    /// The P-256 group order `n`, big-endian.
    const N: [u8; 32] = [
        0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84, 0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63,
        0x25, 0x51,
    ];

    /// Locks `m`, reporting a poisoned lock as a custody error.
    fn locked<T>(m: &Mutex<T>) -> Result<MutexGuard<'_, T>, PlatformError> {
        m.lock()
            .map_err(|_| PlatformError::CustodyError("fake host lock poisoned".into()))
    }

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

    /// A key the host holds, with the role it was minted in.
    enum HostKey {
        Ed25519(ed25519_dalek::SigningKey),
        P256(P256SecretKey),
        HpkeP256(P256SecretKey),
    }

    fn p256_copy(key: &P256SecretKey) -> Result<P256SecretKey, PlatformError> {
        P256SecretKey::from_scalar_bytes(&key.to_scalar_bytes())
            .map_err(|e| PlatformError::CustodyError(e.to_string()))
    }

    /// Host state: every key by id, call counts, and the last peer it was
    /// sent.
    #[derive(Default)]
    pub struct FakeHost {
        keys: Mutex<HashMap<String, HostKey>>,
        /// The role each key id was minted in.
        roles: Mutex<HashMap<String, KeyRole>>,
        next: AtomicUsize,
        calls: Mutex<HashMap<&'static str, usize>>,
        /// The peer bytes of the most recent `dh_agree` call.
        pub last_peer: Mutex<Option<Vec<u8>>>,
    }

    impl FakeHost {
        /// Whether the host still holds `key_id`.
        pub fn holds(&self, key_id: &str) -> bool {
            locked(&self.keys).is_ok_and(|keys| keys.contains_key(key_id))
        }

        /// How many calls to `method` reached the host.
        pub fn calls(&self, method: &str) -> usize {
            locked(&self.calls).map_or(0, |calls| calls.get(method).copied().unwrap_or(0))
        }

        fn count(&self, method: &'static str) {
            if let Ok(mut calls) = locked(&self.calls) {
                *calls.entry(method).or_default() += 1;
            }
        }

        fn next_id(&self) -> usize {
            // Ids never repeat, even after a destroy.
            self.next.fetch_add(1, Ordering::Relaxed) + 1
        }

        fn with_key<T>(
            &self,
            key_id: &str,
            f: impl FnOnce(&HostKey) -> Result<T, PlatformError>,
        ) -> Result<T, PlatformError> {
            f(locked(&self.keys)?
                .get(key_id)
                .ok_or(PlatformError::KeyNotFound)?)
        }

        /// `generate_keypair`: Ed25519, P-256 signing or HPKE P-256,
        /// recording `role` for `get_public_key`; numeric ids from 1.
        ///
        /// # Errors
        ///
        /// An X25519 key type.
        pub fn generate_keypair(
            &self,
            key_type: KeyType,
            role: KeyRole,
        ) -> Result<String, PlatformError> {
            self.count("generate_keypair");
            let id = self.next_id();
            let scalar = [u8::try_from(id % 64).unwrap_or(0) + 0x40; 32];
            let p256 = || {
                P256SecretKey::from_scalar_bytes(&scalar)
                    .map_err(|e| PlatformError::CustodyError(e.to_string()))
            };
            let key = match key_type {
                KeyType::Ed25519 => {
                    HostKey::Ed25519(ed25519_dalek::SigningKey::from_bytes(&scalar))
                }
                KeyType::P256Signing => HostKey::P256(p256()?),
                KeyType::HpkeP256 => HostKey::HpkeP256(p256()?),
                KeyType::X25519 => {
                    return Err(PlatformError::CustodyError(
                        "fake host does not hold x25519 keys".into(),
                    ));
                }
            };
            locked(&self.roles)?.insert(id.to_string(), role);
            locked(&self.keys)?.insert(id.to_string(), key);
            Ok(id.to_string())
        }

        /// `get_public_key`: the structured answer the host contract names.
        ///
        /// # Errors
        ///
        /// An unknown key id.
        pub fn get_public_key(&self, key_id: &str) -> Result<HostPublicKey, PlatformError> {
            self.count("get_public_key");
            let role = locked(&self.roles)?.get(key_id).copied();
            self.with_key(key_id, |key| {
                // Every key this host holds has a recorded role; a held key
                // without one is a fake-host defect, reported, never defaulted.
                let role = role.ok_or_else(|| {
                    PlatformError::CustodyError(format!(
                        "fake host recorded no role for key {key_id}"
                    ))
                })?;
                let (key_type, public_key) = match key {
                    HostKey::Ed25519(sk) => {
                        (KeyType::Ed25519, sk.verifying_key().to_bytes().to_vec())
                    }
                    HostKey::P256(sk) => (
                        KeyType::P256Signing,
                        sk.public_key().to_compressed().to_vec(),
                    ),
                    HostKey::HpkeP256(sk) => (
                        KeyType::HpkeP256,
                        sk.public_key().to_uncompressed().to_vec(),
                    ),
                };
                Ok(HostPublicKey {
                    key_type,
                    public_key,
                    role,
                })
            })
        }

        /// `sign`: Ed25519 over the message; P-256 RFC 6979 over the 32-byte
        /// digest, returned as DER with the high `s` (`n - s`).
        ///
        /// # Errors
        ///
        /// An unknown key id, an HPKE key, or a P-256 message that is not 32
        /// bytes.
        pub fn sign(&self, key_id: &str, message: &[u8]) -> Result<Vec<u8>, PlatformError> {
            self.count("sign");
            self.with_key(key_id, |key| match key {
                HostKey::Ed25519(sk) => Ok(sk.sign(message).to_bytes().to_vec()),
                HostKey::P256(sk) => {
                    let digest: [u8; 32] = message.try_into().map_err(|_| {
                        PlatformError::CustodyError("digest must be 32 bytes".into())
                    })?;
                    let raw = sign_prehash_rfc6979(sk, &digest)
                        .map_err(|e| PlatformError::CustodyError(e.to_string()))?;
                    Ok(der(&raw[..32], &negate(&raw[32..])))
                }
                HostKey::HpkeP256(_) => Err(PlatformError::CustodyError(
                    "an HPKE key does not sign".into(),
                )),
            })
        }

        /// `dh_agree`: the ECDH x-coordinate with the peer, for an HPKE key.
        /// The host parses the peer as any SEC1 point, so the adapter alone
        /// enforces the uncompressed form.
        ///
        /// # Errors
        ///
        /// An unknown key id, a key that is not HPKE, or a peer that is not a
        /// curve point.
        pub fn dh_agree(&self, key_id: &str, peer: &[u8]) -> Result<Vec<u8>, PlatformError> {
            self.count("dh_agree");
            *locked(&self.last_peer)? = Some(peer.to_vec());
            let key = self.with_key(key_id, |key| match key {
                HostKey::HpkeP256(sk) => p256_copy(sk),
                _ => Err(PlatformError::CustodyError(
                    "fake host agrees with HPKE keys only".into(),
                )),
            })?;
            let peer = P256PublicKey::from_sec1(peer)
                .map_err(|e| PlatformError::CustodyError(e.to_string()))?;
            Ok(ecdh_p256(&key, &peer).to_vec())
        }

        /// `derive_pseudonym` / `derive_rotatable_pseudonym`: the §9.10.4.A
        /// compressed P-256 pseudonym point of an Ed25519 key's seed. The
        /// host stores nothing for it.
        ///
        /// # Errors
        ///
        /// An unknown key id, or a key that is not Ed25519.
        pub fn derive_pseudonym(
            &self,
            key_id: &str,
            context_id: &[u8],
            epoch: Option<u64>,
        ) -> Result<Vec<u8>, PlatformError> {
            self.count(if epoch.is_some() {
                "derive_rotatable_pseudonym"
            } else {
                "derive_pseudonym"
            });
            let seed = self.with_key(key_id, |key| match key {
                HostKey::Ed25519(sk) => Ok(zeroize::Zeroizing::new(sk.to_bytes())),
                _ => Err(PlatformError::CustodyError(
                    "a pseudonym derives from an Ed25519 key".into(),
                )),
            })?;
            let version = epoch.map_or(PseudonymVersion::Static, |epoch| {
                PseudonymVersion::Rotatable { epoch }
            });
            Ok(derive_pseudonym(&seed, context_id, version)
                .to_compressed()
                .to_vec())
        }

        /// `export_signing_key_bytes`: an Ed25519 key's 32-byte seed.
        ///
        /// # Errors
        ///
        /// An unknown key id, or a key that is not Ed25519.
        pub fn export_signing_key_bytes(&self, key_id: &str) -> Result<Vec<u8>, PlatformError> {
            self.count("export_signing_key_bytes");
            self.with_key(key_id, |key| match key {
                HostKey::Ed25519(sk) => Ok(sk.to_bytes().to_vec()),
                _ => Err(PlatformError::CustodyError(
                    "only an Ed25519 key exports".into(),
                )),
            })
        }

        /// `destroy_key`.
        ///
        /// # Errors
        ///
        /// An unknown key id.
        pub fn destroy_key(&self, key_id: &str) -> Result<(), PlatformError> {
            self.count("destroy_key");
            locked(&self.roles)?.remove(key_id);
            locked(&self.keys)?
                .remove(key_id)
                .map(|_| ())
                .ok_or(PlatformError::KeyNotFound)
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::fake_host::{der, negate};
    use super::*;
    use ed25519_dalek::Signer;
    use scp_crypto::p256::{P256SecretKey, sign_prehash_rfc6979};

    fn key_and_sig() -> (P256SecretKey, [u8; 32], [u8; 64]) {
        let key = P256SecretKey::from_scalar_bytes(&[0x11u8; 32]).unwrap();
        let digest = [0x22u8; 32];
        let sig = sign_prehash_rfc6979(&key, &digest).unwrap();
        (key, digest, sig)
    }

    fn p256(seed: u8) -> P256SecretKey {
        P256SecretKey::from_scalar_bytes(&[seed; 32]).unwrap()
    }

    fn ed(seed: u8) -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[seed; 32])
    }

    fn answer(key_type: KeyType, public_key: &[u8]) -> HostPublicKey {
        HostPublicKey {
            key_type,
            public_key: public_key.to_vec(),
            role: KeyRole::Operational,
        }
    }

    fn as_identity(mut a: HostPublicKey) -> HostPublicKey {
        a.role = KeyRole::Identity;
        a
    }

    fn ed_answer(key: &ed25519_dalek::SigningKey) -> HostPublicKey {
        answer(KeyType::Ed25519, &key.verifying_key().to_bytes())
    }

    fn p256_answer(key: &P256SecretKey) -> HostPublicKey {
        answer(KeyType::P256Signing, &key.public_key().to_compressed())
    }

    fn hpke_answer(key: &P256SecretKey) -> HostPublicKey {
        answer(KeyType::HpkeP256, &key.public_key().to_uncompressed())
    }

    /// A `get_public_key` closure that answers `a` for every id and counts
    /// its calls.
    fn lookup<'a>(
        a: &HostPublicKey,
        calls: &'a AtomicUsize,
    ) -> impl Fn(String) -> std::future::Ready<Result<HostPublicKey, PlatformError>> + Sync + 'a
    {
        let a = a.clone();
        move |_| {
            calls.fetch_add(1, Ordering::Relaxed);
            std::future::ready(Ok(a.clone()))
        }
    }

    /// A lookup a test expects never to happen.
    fn no_lookup(_: String) -> std::future::Ready<Result<HostPublicKey, PlatformError>> {
        panic!("no get_public_key lookup expected")
    }

    fn live(registry: &CallbackKeyRegistry, id: u64, key: RegisteredKey, role: KeyRole) {
        registry
            .register(KeyHandle::new(id), RegisteredEntry { key, role })
            .unwrap();
    }

    fn cached(registry: &CallbackKeyRegistry) -> usize {
        registry.entries.lock().expect("registry lock").len()
    }

    /// A host that names a type or role outside the contract is refused;
    /// every contract name builds the typed answer.
    #[test]
    fn host_names_outside_the_contract_are_refused() {
        let ok = HostPublicKey::from_names("m", "hpke-p256", vec![4; 65], "identity").unwrap();
        assert_eq!(
            (ok.key_type, ok.role),
            (KeyType::HpkeP256, KeyRole::Identity)
        );
        for (key_type, role) in [
            ("P256", "operational"),
            ("", "operational"),
            ("secp256k1", "operational"),
            ("ed25519", "admin"),
            ("ed25519", "Identity"),
            ("ed25519", ""),
        ] {
            assert!(
                matches!(
                    HostPublicKey::from_names("m", key_type, vec![1; 32], role),
                    Err(PlatformError::CustodyError(_))
                ),
                "{key_type:?} {role:?}"
            );
        }
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
        let other = p256(0x33);
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
        assert!(matches!(
            p256_host_signature(&key.public_key(), &wrong_digest, &sig),
            Err(PlatformError::CustodyError(_))
        ));
    }

    #[test]
    fn p256_public_key_requires_exact_length_per_type() {
        let pk = p256(0x11).public_key();
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

    /// The host's stated type decides the key, and the key must have
    /// exactly that type's length and be valid. Every other answer is a
    /// custody error: a length that fits another type, an invalid or weak
    /// Ed25519 point, an off-curve P-256 point.
    #[test]
    fn host_answers_bind_by_stated_type_and_exact_length() {
        let p = p256(0x21).public_key();
        let e = ed(0x31).verifying_key();
        let x = [9u8; 32];
        assert_eq!(
            registered_key("m", &answer(KeyType::Ed25519, &e.to_bytes())).unwrap(),
            RegisteredKey::Ed25519(e)
        );
        assert_eq!(
            registered_key("m", &answer(KeyType::X25519, &x)).unwrap(),
            RegisteredKey::X25519(x)
        );
        assert_eq!(
            registered_key("m", &answer(KeyType::P256Signing, &p.to_compressed())).unwrap(),
            RegisteredKey::P256Signing(p)
        );
        assert_eq!(
            registered_key("m", &answer(KeyType::HpkeP256, &p.to_uncompressed())).unwrap(),
            RegisteredKey::HpkeP256(p)
        );

        // The Ed25519 identity point: a weak (small-order) key.
        let mut identity = [0u8; 32];
        identity[0] = 1;
        let refused: Vec<HostPublicKey> = vec![
            answer(KeyType::Ed25519, &p.to_compressed()),
            answer(KeyType::X25519, &p.to_compressed()),
            answer(KeyType::P256Signing, &e.to_bytes()),
            answer(KeyType::P256Signing, &p.to_uncompressed()),
            answer(KeyType::HpkeP256, &p.to_compressed()),
            answer(KeyType::Ed25519, &[0u8; 31]),
            answer(KeyType::X25519, &[0u8; 33]),
            answer(KeyType::Ed25519, &identity),
            answer(KeyType::P256Signing, &[&[0x02][..], &[0xFF; 32]].concat()),
        ];
        for a in refused {
            assert!(
                matches!(registered_key("m", &a), Err(PlatformError::CustodyError(_))),
                "{a:?}"
            );
        }
    }

    /// An Ed25519 host signature is accepted only when it verifies
    /// strictly over the data; 64 junk bytes, a signature over other data and
    /// a wrong length are refused.
    #[test]
    fn ed25519_host_signatures_verify_strictly() {
        let key = ed(0x41);
        let vk = key.verifying_key();
        let sig = key.sign(b"message").to_bytes().to_vec();
        assert_eq!(
            ed25519_host_signature(&vk, b"message", sig.clone())
                .unwrap()
                .as_bytes(),
            sig.as_slice()
        );
        for (data, bad) in [
            (&b"message"[..], vec![0x11u8; 64]),
            (&b"another"[..], sig.clone()),
            (&b"message"[..], sig[..63].to_vec()),
            (&b"message"[..], [sig.as_slice(), &[0]].concat()),
        ] {
            assert!(matches!(
                ed25519_host_signature(&vk, data, bad),
                Err(PlatformError::CustodyError(_))
            ));
        }
    }

    #[test]
    fn peer_parsing() {
        let pk = p256(1).public_key();
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

    /// An Ed25519 handle, minted or resolved, rejects a host that returns
    /// 64 junk bytes, and accepts its real signature.
    #[tokio::test]
    async fn ed25519_sign_rejects_junk_from_the_host() {
        let key = ed(0x51);
        let calls = AtomicUsize::new(0);
        for registry in [
            {
                let r = CallbackKeyRegistry::new();
                live(
                    &r,
                    5,
                    RegisteredKey::Ed25519(key.verifying_key()),
                    KeyRole::Operational,
                );
                r
            },
            CallbackKeyRegistry::new(),
        ] {
            let h = KeyHandle::new(5);
            assert!(matches!(
                sign(
                    &registry,
                    &h,
                    b"data",
                    |_, _| async { Ok(vec![0x11u8; 64]) },
                    lookup(&ed_answer(&key), &calls)
                )
                .await,
                Err(PlatformError::CustodyError(_))
            ));
            let good = key.sign(b"data").to_bytes().to_vec();
            let expected = good.clone();
            let sig = sign(
                &registry,
                &h,
                b"data",
                |id, data| async move {
                    assert_eq!((id.as_str(), data.as_slice()), ("5", &b"data"[..]));
                    Ok(good)
                },
                no_lookup,
            )
            .await
            .unwrap();
            assert_eq!(sig.as_bytes(), expected.as_slice());
        }
        assert_eq!(
            calls.load(Ordering::Relaxed),
            1,
            "only the fresh registry resolves"
        );
    }

    /// A registry holding identity key 1 (Ed25519) and operational P-256
    /// signing key 7 (`key`).
    fn registry_with_p256(
        identity: &ed25519_dalek::SigningKey,
        key: &P256SecretKey,
    ) -> CallbackKeyRegistry {
        let registry = CallbackKeyRegistry::new();
        live(
            &registry,
            1,
            RegisteredKey::Ed25519(identity.verifying_key()),
            KeyRole::Identity,
        );
        live(
            &registry,
            7,
            RegisteredKey::P256Signing(key.public_key()),
            KeyRole::Operational,
        );
        registry
    }

    /// A registered P-256 signing key. Its host's DER high-s signature comes
    /// out raw low-s and strictly verifies; a junk 64-byte signature is
    /// refused; a non-digest input never reaches the host; `dh_agree` is
    /// `WrongKeyType`; a registered handle never asks the host for its public
    /// key to sign.
    #[tokio::test]
    async fn p256_signing_handles_use_the_registry_path() {
        let key = p256(0x21);
        let registry = registry_with_p256(&ed(0x61), &key);
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
            dh_agree(
                &registry,
                &handle,
                &[9u8; 65],
                |_, _| async { panic!("no host call for a signing key") },
                no_lookup
            )
            .await,
            Err(PlatformError::WrongKeyType {
                expected: KeyType::HpkeP256,
                actual: KeyType::P256Signing
            })
        ));
        let calls = AtomicUsize::new(0);
        assert_eq!(
            public_key(&registry, &handle, lookup(&p256_answer(&key), &calls))
                .await
                .unwrap()
                .as_bytes(),
            key.public_key().to_compressed().as_slice()
        );
    }

    /// Every entry point resolves an unregistered handle the same way,
    /// with one host lookup, and binds the same operational entry, whichever
    /// runs first. Before this, `dh_agree` and the Ed25519-only operations
    /// returned `KeyNotFound` for a handle `sign` would have resolved.
    #[tokio::test]
    async fn every_entry_point_resolves_an_unregistered_handle() {
        let e = ed(0x71);
        let p = p256(0x72);
        let x25519 = [0x73u8; 32];
        let h = KeyHandle::new(42);
        let peer_x = [5u8; 32];
        let peer_p = p256(0x74).public_key().to_uncompressed();

        // (answer, the entry point run first); each must resolve and bind.
        let ed_a = ed_answer(&e);
        let x_a = answer(KeyType::X25519, &x25519);
        let hpke_a = hpke_answer(&p);
        let cases: Vec<(&HostPublicKey, &str)> = vec![
            (&ed_a, "sign"),
            (&ed_a, "public_key"),
            (&ed_a, "require_ed25519"),
            (&ed_a, "dh_agree"),
            (&x_a, "dh_agree"),
            (&x_a, "public_key"),
            (&x_a, "require_ed25519"),
            (&x_a, "sign"),
            (&hpke_a, "dh_agree"),
            (&hpke_a, "sign"),
        ];
        for (host_answer, first) in cases {
            let registry = CallbackKeyRegistry::new();
            let calls = AtomicUsize::new(0);
            let l = lookup(host_answer, &calls);
            let expected = registered_key("m", host_answer).unwrap();
            let agree = |peer: &[u8]| peer.to_vec();
            let result = match first {
                "sign" => sign(
                    &registry,
                    &h,
                    b"data",
                    |_, data| {
                        let sig = e.sign(&data).to_bytes().to_vec();
                        async move { Ok(sig) }
                    },
                    &l,
                )
                .await
                .map(|_| ()),
                "public_key" => public_key(&registry, &h, &l).await.map(|pk| {
                    assert_eq!(pk.as_bytes(), expected.public_bytes().as_slice());
                }),
                "require_ed25519" => require_ed25519(&registry, &h, &l).await.map(|_| ()),
                "dh_agree" => {
                    let peer = if host_answer.key_type == KeyType::HpkeP256 {
                        peer_p.to_vec()
                    } else {
                        agree(&peer_x)
                    };
                    dh_agree(&registry, &h, &peer, |_, _| async { Ok(vec![1u8; 32]) }, &l)
                        .await
                        .map(|_| ())
                }
                other => unreachable!("{other}"),
            };
            // The type decides the outcome, never the order: signing and
            // Ed25519-only operations need Ed25519, agreement needs an
            // agreement key.
            let fits = !matches!(
                (host_answer.key_type.as_str(), first),
                ("ed25519", "dh_agree") | ("x25519" | "hpke-p256", "sign" | "require_ed25519")
            );
            assert_eq!(
                result.is_ok(),
                fits,
                "{:?} {first}: {result:?}",
                host_answer.key_type
            );
            if !fits {
                assert!(
                    matches!(result, Err(PlatformError::WrongKeyType { .. })),
                    "{result:?}"
                );
            }
            assert_eq!(
                calls.load(Ordering::Relaxed),
                1,
                "{:?} {first}",
                host_answer.key_type
            );
            let entry = registry.get(&h).unwrap().expect("bound");
            assert_eq!(entry.key, expected);
            assert_eq!(entry.role, KeyRole::Operational);
        }
    }

    /// A host without the key answers its not-found to every entry
    /// point, with no other host call and nothing bound.
    #[tokio::test]
    async fn every_entry_point_reports_a_key_the_host_lacks() {
        let h = KeyHandle::new(42);
        let peer_x = [5u8; 32];
        let registry = CallbackKeyRegistry::new();
        let missing = |_: String| async { Err::<HostPublicKey, _>(PlatformError::KeyNotFound) };
        assert!(matches!(
            sign(
                &registry,
                &h,
                b"data",
                |_, _| async { panic!("no sign call for a key the host lacks") },
                missing
            )
            .await,
            Err(PlatformError::KeyNotFound)
        ));
        assert!(matches!(
            dh_agree(
                &registry,
                &h,
                &peer_x,
                |_, _| async { panic!("no agree call for a key the host lacks") },
                missing
            )
            .await,
            Err(PlatformError::KeyNotFound)
        ));
        assert!(matches!(
            require_ed25519(&registry, &h, &missing).await,
            Err(PlatformError::KeyNotFound)
        ));
        assert!(matches!(
            public_key(&registry, &h, missing).await,
            Err(PlatformError::KeyNotFound)
        ));
        assert!(registry.get(&h).unwrap().is_none());
    }

    /// A resolution whose answer has the wrong length for its stated
    /// type is a custody error and binds nothing, with
    /// no host sign call.
    #[tokio::test]
    async fn a_refused_resolution_binds_nothing() {
        let p = p256(0x81);
        let h = KeyHandle::new(8);
        for a in [
            answer(KeyType::Ed25519, &p.public_key().to_compressed()),
            answer(KeyType::P256Signing, &p.public_key().to_uncompressed()),
            answer(KeyType::HpkeP256, &p.public_key().to_compressed()),
            answer(KeyType::X25519, &[1u8; 31]),
        ] {
            let registry = CallbackKeyRegistry::new();
            let calls = AtomicUsize::new(0);
            let result = sign(
                &registry,
                &h,
                &[0u8; 32],
                |_, _| async { panic!("no sign call after a refused answer") },
                lookup(&a, &calls),
            )
            .await;
            assert!(
                matches!(result, Err(PlatformError::CustodyError(_))),
                "{a:?}"
            );
            assert!(registry.get(&h).unwrap().is_none(), "{a:?}");
            assert_eq!(calls.load(Ordering::Relaxed), 1);
        }
    }

    /// Two resolutions of one handle that both asked the host (the
    /// second completes inside the first's host call) both succeed and bind
    /// one entry; a handle already bound resolves to its entry, role kept.
    #[tokio::test]
    async fn concurrent_and_repeated_resolutions_agree() {
        let p = p256(0x91);
        let a = p256_answer(&p);
        let registry = CallbackKeyRegistry::new();
        let h = KeyHandle::new(9);
        let inner_calls = AtomicUsize::new(0);
        let outer = |_: String| {
            let a = a.clone();
            let registry = &registry;
            let inner_calls = &inner_calls;
            async move {
                // Another entry point resolves the same handle while this
                // host call is in flight.
                let (entry, asked) = resolve(registry, &h, &lookup(&a, inner_calls))
                    .await
                    .expect("the inner resolution binds");
                assert!(asked);
                assert_eq!(entry.role, KeyRole::Operational);
                Ok(a)
            }
        };
        let (entry, asked) = resolve(&registry, &h, &outer)
            .await
            .expect("the outer resolution finds the same key bound");
        assert!(asked);
        assert_eq!(entry.key, RegisteredKey::P256Signing(p.public_key()));
        assert_eq!(inner_calls.load(Ordering::Relaxed), 1);

        assert_eq!(cached(&registry), 1);

        // Resolving again asks nothing and writes nothing: the one entry holds
        // the same entry.
        assert_eq!(
            resolve(&registry, &h, &no_lookup).await.unwrap(),
            (entry.clone(), false)
        );
        assert_eq!(cached(&registry), 1);
        assert_eq!(registry.get(&h).unwrap(), Some(entry));
    }

    /// `require_ed25519` refuses a P-256, an HPKE and an X25519 entry
    /// with `WrongKeyType`, and returns an Ed25519 one's verifying key.
    #[tokio::test]
    async fn require_ed25519_refuses_every_other_type() {
        let registry = CallbackKeyRegistry::new();
        let p = p256(0xA1).public_key();
        live(
            &registry,
            1,
            RegisteredKey::P256Signing(p),
            KeyRole::Operational,
        );
        live(
            &registry,
            2,
            RegisteredKey::HpkeP256(p),
            KeyRole::Operational,
        );
        live(
            &registry,
            3,
            RegisteredKey::X25519([1; 32]),
            KeyRole::Operational,
        );
        live(
            &registry,
            4,
            RegisteredKey::Ed25519(ed(0xA2).verifying_key()),
            KeyRole::Operational,
        );
        for (id, actual) in [
            (1, KeyType::P256Signing),
            (2, KeyType::HpkeP256),
            (3, KeyType::X25519),
        ] {
            assert!(matches!(
                require_ed25519(&registry, &KeyHandle::new(id), &no_lookup).await,
                Err(PlatformError::WrongKeyType { expected: KeyType::Ed25519, actual: a })
                    if a == actual
            ));
        }
        assert_eq!(
            require_ed25519(&registry, &KeyHandle::new(4), &no_lookup)
                .await
                .unwrap(),
            ed(0xA2).verifying_key()
        );
    }

    /// A registered HPKE key whose host point changes after generation
    /// is a custody error from `public_key`; so is one whose host now states
    /// another type for the same bytes, or another role for the same key.
    #[tokio::test]
    async fn public_key_refuses_a_changed_host_key() {
        let registry = CallbackKeyRegistry::new();
        let host = std::sync::Mutex::new(hpke_answer(&p256(0xB1)));
        let h = generate_operational(
            &registry,
            KeyType::HpkeP256,
            |_, _| async { Ok("11".to_owned()) },
            |_| {
                let a = host.lock().unwrap().clone();
                async move { Ok(a) }
            },
            |_| async { panic!("an accepted key is not destroyed") },
        )
        .await
        .unwrap();
        let current = |_: String| {
            let a = host.lock().unwrap().clone();
            async move { Ok(a) }
        };
        assert_eq!(
            public_key(&registry, &h, current).await.unwrap().as_bytes(),
            p256(0xB1).public_key().to_uncompressed().as_slice()
        );
        *host.lock().unwrap() = hpke_answer(&p256(0xB2));
        assert!(matches!(
            public_key(&registry, &h, current).await,
            Err(PlatformError::CustodyError(_))
        ));
        *host.lock().unwrap() = answer(
            KeyType::P256Signing,
            &p256(0xB1).public_key().to_compressed(),
        );
        assert!(matches!(
            public_key(&registry, &h, current).await,
            Err(PlatformError::CustodyError(_))
        ));
        // The same key, now reported as an identity.
        *host.lock().unwrap() = as_identity(hpke_answer(&p256(0xB1)));
        assert!(matches!(
            public_key(&registry, &h, current).await,
            Err(PlatformError::CustodyError(_))
        ));
        // The registration is unchanged.
        assert_eq!(
            registry.get(&h).unwrap().unwrap().key,
            RegisteredKey::HpkeP256(p256(0xB1).public_key())
        );
    }

    /// An X25519 handle given a 33-byte peer is a custody error with no
    /// host call; a 32-byte peer reaches the host.
    #[tokio::test]
    async fn x25519_agree_checks_the_peer_before_the_host() {
        let registry = CallbackKeyRegistry::new();
        live(
            &registry,
            3,
            RegisteredKey::X25519([2; 32]),
            KeyRole::Operational,
        );
        let h = KeyHandle::new(3);
        let agreed = AtomicUsize::new(0);
        let host = |_: String, peer: Vec<u8>| {
            agreed.fetch_add(1, Ordering::Relaxed);
            async move {
                assert_eq!(peer.len(), 32);
                Ok(vec![7u8; 32])
            }
        };
        assert!(matches!(
            dh_agree(&registry, &h, &[4u8; 33], host, no_lookup).await,
            Err(PlatformError::CustodyError(_))
        ));
        assert_eq!(agreed.load(Ordering::Relaxed), 0);
        let shared = dh_agree(&registry, &h, &[4u8; 32], host, no_lookup)
            .await
            .unwrap();
        assert_eq!(shared.as_bytes(), &[7u8; 32]);
        assert_eq!(agreed.load(Ordering::Relaxed), 1);
    }

    /// Runs `derive_pseudonym` from `source` with a host that returns
    /// `point`, counting derive calls.
    async fn derive_from(
        registry: &CallbackKeyRegistry,
        source: u64,
        epoch: Option<u64>,
        point: Vec<u8>,
        derives: &AtomicUsize,
    ) -> Result<Pseudonym, PlatformError> {
        derive_pseudonym(
            registry,
            &KeyHandle::new(source),
            epoch,
            |_| {
                derives.fetch_add(1, Ordering::Relaxed);
                async move { Ok(point) }
            },
            no_lookup,
        )
        .await
    }

    /// A derive source must be an Ed25519 identity key. An operational
    /// Ed25519 key (minted by `generate_operational`, or resolved as
    /// operational) is `NotIdentityKey`: it is Ed25519, so the curve check
    /// alone would pass it. A P-256 identity key is `WrongKeyType` from the
    /// interim curve check. None reaches the host's derive, and a derive
    /// caches nothing.
    #[tokio::test]
    async fn derivation_needs_an_identity_source() {
        let point = p256(0xC1).public_key().to_compressed().to_vec();
        let registry = CallbackKeyRegistry::new();
        let e = ed(0xC2).verifying_key();
        live(&registry, 1, RegisteredKey::Ed25519(e), KeyRole::Identity);
        live(
            &registry,
            2,
            RegisteredKey::Ed25519(e),
            KeyRole::Operational,
        );
        live(
            &registry,
            4,
            RegisteredKey::P256Signing(p256(0xC1).public_key()),
            KeyRole::Identity,
        );
        let host_derives = AtomicUsize::new(0);
        let operational = derive_from(&registry, 2, Some(0), point.clone(), &host_derives).await;
        assert!(
            matches!(operational, Err(PlatformError::NotIdentityKey)),
            "{operational:?}"
        );
        let p256_identity = derive_from(&registry, 4, Some(0), point.clone(), &host_derives).await;
        assert!(
            matches!(
                p256_identity,
                Err(PlatformError::WrongKeyType {
                    expected: KeyType::Ed25519,
                    actual: KeyType::P256Signing
                })
            ),
            "{p256_identity:?}"
        );
        // A host key resolved as operational never derives.
        let calls = AtomicUsize::new(0);
        let resolved = derive_pseudonym(
            &registry,
            &KeyHandle::new(5),
            None,
            |_| async { panic!("no derivation from an operational key") },
            lookup(&answer(KeyType::Ed25519, &e.to_bytes()), &calls),
        )
        .await;
        assert!(
            matches!(resolved, Err(PlatformError::NotIdentityKey)),
            "{resolved:?}"
        );
        assert_eq!(host_derives.load(Ordering::Relaxed), 0);

        let before = cached(&registry);
        let derived = derive_from(&registry, 1, Some(0), point.clone(), &host_derives)
            .await
            .expect("an identity source derives");
        assert_eq!(
            derived.public_key().to_compressed().as_slice(),
            point.as_slice()
        );
        assert_eq!(host_derives.load(Ordering::Relaxed), 1);
        assert_eq!(cached(&registry), before, "a pseudonym caches nothing");
    }

    /// The host's derive answer must be a 33-byte compressed P-256 point: an
    /// uncompressed point, a 32-byte (Ed25519-era) value and an off-curve
    /// prefix are each `PseudonymRejected`.
    #[tokio::test]
    async fn a_derive_answer_must_be_a_compressed_point() {
        let registry = CallbackKeyRegistry::new();
        live(
            &registry,
            1,
            RegisteredKey::Ed25519(ed(0xC3).verifying_key()),
            KeyRole::Identity,
        );
        let key = p256(0xC4).public_key();
        let mut bad_prefix = key.to_compressed().to_vec();
        bad_prefix[0] = 0x05;
        let derives = AtomicUsize::new(0);
        for point in [key.to_uncompressed().to_vec(), vec![2u8; 32], bad_prefix] {
            let result = derive_from(&registry, 1, None, point, &derives).await;
            assert!(
                matches!(result, Err(PlatformError::PseudonymRejected(_))),
                "{result:?}"
            );
        }
    }

    /// An identity the host has destroyed derives nothing: the cache entry
    /// is gone once the host confirmed the destroy, the handle resolves
    /// through the host, and the host's key-not-found is returned with no
    /// derive call.
    #[tokio::test]
    async fn destroyed_identity_derive_is_key_not_found_through_the_host() {
        let host = fake_host::FakeHost::default();
        let host = &host;
        let registry = CallbackKeyRegistry::new();
        let identity = generate_identity(
            &registry,
            |t, r| async move { host.generate_keypair(t, r) },
            |id: String| async move { host.get_public_key(&id) },
            |id| async move { host.destroy_key(&id) },
        )
        .await
        .unwrap();
        destroy_key(
            &registry,
            &identity,
            |id| async move { host.destroy_key(&id) },
        )
        .await
        .unwrap();
        assert_eq!(registry.get(&identity).unwrap(), None);
        let result = derive_pseudonym(
            &registry,
            &identity,
            None,
            |id| async move { host.derive_pseudonym(&id, b"ctx", None) },
            |id: String| async move { host.get_public_key(&id) },
        )
        .await;
        assert!(
            matches!(result, Err(PlatformError::KeyNotFound)),
            "{result:?}"
        );
        assert_eq!(host.calls("derive_pseudonym"), 0);
    }

    type Log = std::sync::Mutex<Vec<String>>;

    async fn generate_with(
        registry: &CallbackKeyRegistry,
        key_type: KeyType,
        key_id: &str,
        public_key: Result<HostPublicKey, PlatformError>,
        destroyed: &Log,
    ) -> Result<KeyHandle, PlatformError> {
        let key_id = key_id.to_owned();
        generate_operational(
            registry,
            key_type,
            |_, _| async move { Ok(key_id) },
            |_| async move { public_key },
            |id| async move {
                destroyed.lock().unwrap().push(id);
                Ok(())
            },
        )
        .await
    }

    /// Every generation the adapter refuses destroys the host key it was
    /// handed: a non-numeric or non-canonical id, a malformed public key, a
    /// failing fetch, an answer stating another type or role.
    #[tokio::test]
    async fn refused_generation_destroys_the_host_key() {
        type Case = (KeyType, &'static str, Result<HostPublicKey, PlatformError>);
        let valid = p256(5);
        let e = ed(6);
        let cases: Vec<Case> = vec![
            (KeyType::Ed25519, "not-a-number", Ok(ed_answer(&e))),
            (KeyType::X25519, "", Ok(answer(KeyType::X25519, &[1; 32]))),
            (KeyType::P256Signing, "-1", Ok(p256_answer(&valid))),
            (KeyType::HpkeP256, "0x10", Ok(hpke_answer(&valid))),
            (KeyType::P256Signing, "07", Ok(p256_answer(&valid))),
            (
                KeyType::P256Signing,
                "11",
                Ok(answer(
                    KeyType::P256Signing,
                    &valid.public_key().to_uncompressed(),
                )),
            ),
            (
                KeyType::HpkeP256,
                "12",
                Ok(answer(
                    KeyType::HpkeP256,
                    &valid.public_key().to_compressed(),
                )),
            ),
            (
                KeyType::P256Signing,
                "13",
                Ok(answer(
                    KeyType::P256Signing,
                    &[&[0x02][..], &[0xFF; 32]].concat(),
                )),
            ),
            (
                KeyType::HpkeP256,
                "14",
                Err(PlatformError::CustodyError("host get failed".into())),
            ),
            // The host states another type than the one requested.
            (KeyType::P256Signing, "15", Ok(hpke_answer(&valid))),
            (
                KeyType::Ed25519,
                "16",
                Ok(answer(KeyType::X25519, &e.verifying_key().to_bytes())),
            ),
            (KeyType::X25519, "17", Ok(ed_answer(&e))),
            // The host reports another role than the one requested.
            (KeyType::Ed25519, "18", Ok(as_identity(ed_answer(&e)))),
            (
                KeyType::P256Signing,
                "19",
                Ok(as_identity(p256_answer(&valid))),
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
            assert_eq!(*destroyed.lock().unwrap(), vec![key_id.to_owned()]);
            assert_eq!(cached(&registry), 0, "{key_id}");
        }
    }

    /// A refused key whose host destroy also fails reports both failures,
    /// and a host that no longer holds the key counts as destroyed.
    #[tokio::test]
    async fn a_refused_generation_reports_a_failed_destroy() {
        let registry = CallbackKeyRegistry::new();
        let refused = generate_operational(
            &registry,
            KeyType::P256Signing,
            |_, _| async { Ok("x".to_owned()) },
            |_| async { Ok(p256_answer(&p256(5))) },
            |_| async { Err(PlatformError::CustodyError("host destroy failed".into())) },
        )
        .await;
        let Err(PlatformError::CustodyError(msg)) = refused else {
            panic!("{refused:?}");
        };
        assert!(msg.contains("host destroy failed"), "{msg}");
        let gone = generate_operational(
            &registry,
            KeyType::P256Signing,
            |_, _| async { Ok("x".to_owned()) },
            |_| async { Ok(p256_answer(&p256(5))) },
            |_| async { Err(PlatformError::KeyNotFound) },
        )
        .await;
        let Err(PlatformError::CustodyError(msg)) = gone else {
            panic!("{gone:?}");
        };
        assert!(!msg.contains("destroy"), "{msg}");
    }

    /// A generation handed an id the cache holds is refused, and the host
    /// key that id names is not destroyed: it is the key this adapter holds.
    /// The non-canonical spelling `"07"` of a cached 7 names no cached key,
    /// so that refused key is destroyed.
    #[tokio::test]
    async fn a_refused_generation_spares_a_cached_id() {
        let valid = p256(5);
        let e = ed(6);
        let registry = CallbackKeyRegistry::new();
        let destroyed = Log::default();
        let handle = generate_with(
            &registry,
            KeyType::P256Signing,
            "7",
            Ok(p256_answer(&valid)),
            &destroyed,
        )
        .await
        .unwrap();
        assert_eq!(handle.id(), 7);

        let again = generate_with(
            &registry,
            KeyType::Ed25519,
            "7",
            Ok(ed_answer(&e)),
            &destroyed,
        )
        .await;
        assert!(matches!(again, Err(PlatformError::CustodyError(_))));
        assert!(destroyed.lock().unwrap().is_empty(), "the held key is kept");
        assert_eq!(
            registry.get(&handle).unwrap().unwrap().key,
            RegisteredKey::P256Signing(valid.public_key())
        );

        let padded = generate_with(
            &registry,
            KeyType::Ed25519,
            "07",
            Ok(ed_answer(&e)),
            &destroyed,
        )
        .await;
        assert!(matches!(padded, Err(PlatformError::CustodyError(_))));
        assert_eq!(*destroyed.lock().unwrap(), vec!["07".to_owned()]);
        assert_eq!(
            registry.get(&handle).unwrap().unwrap().key,
            RegisteredKey::P256Signing(valid.public_key())
        );
    }

    /// `register` refuses an id the cache holds and keeps the cached entry.
    #[test]
    fn register_refuses_a_cached_id() {
        let registry = CallbackKeyRegistry::new();
        let held = RegisteredKey::P256Signing(p256(0x31).public_key());
        live(&registry, 9, held.clone(), KeyRole::Operational);
        let other = RegisteredEntry {
            key: RegisteredKey::Ed25519(ed(0x32).verifying_key()),
            role: KeyRole::Identity,
        };
        assert!(matches!(
            registry.register(KeyHandle::new(9), other),
            Err(PlatformError::CustodyError(_))
        ));
        assert_eq!(
            registry.get(&KeyHandle::new(9)).unwrap(),
            Some(RegisteredEntry {
                key: held,
                role: KeyRole::Operational
            })
        );
    }

    /// A destroy the host fails keeps the cache entry, so the handle still
    /// names the key the host still holds; a host destroy that succeeds or
    /// reports key-not-found drops it.
    #[tokio::test]
    async fn a_failed_host_destroy_keeps_the_entry() {
        let registry = CallbackKeyRegistry::new();
        let h = KeyHandle::new(3);
        let entry = RegisteredEntry {
            key: RegisteredKey::Ed25519(ed(0x33).verifying_key()),
            role: KeyRole::Identity,
        };
        registry.register(h, entry.clone()).unwrap();
        let failed = destroy_key(&registry, &h, |_| async {
            Err(PlatformError::CustodyError("host destroy failed".into()))
        })
        .await;
        assert!(matches!(failed, Err(PlatformError::CustodyError(_))));
        assert_eq!(registry.get(&h).unwrap(), Some(entry.clone()));

        let missing =
            destroy_key(&registry, &h, |_| async { Err(PlatformError::KeyNotFound) }).await;
        assert!(matches!(missing, Err(PlatformError::KeyNotFound)));
        assert_eq!(registry.get(&h).unwrap(), None);

        registry.register(h, entry).unwrap();
        destroy_key(&registry, &h, |_| async { Ok(()) })
            .await
            .unwrap();
        assert_eq!(registry.get(&h).unwrap(), None);
    }

    /// An exported seed must produce the handle's verifying key. The host's
    /// own seed is accepted; a seed for another key, or a buffer that is not
    /// 32 bytes, is a custody error; a non-Ed25519 handle is `WrongKeyType`
    /// with no export call.
    #[tokio::test]
    async fn export_refuses_a_seed_for_another_key() {
        let registry = CallbackKeyRegistry::new();
        let held = ed(0x51);
        live(
            &registry,
            1,
            RegisteredKey::Ed25519(held.verifying_key()),
            KeyRole::Identity,
        );
        live(
            &registry,
            2,
            RegisteredKey::P256Signing(p256(0x52).public_key()),
            KeyRole::Operational,
        );
        let h = KeyHandle::new(1);
        let exported =
            export_ed25519_signing_key(&registry, &h, |_| async { Ok(vec![0x51; 32]) }, no_lookup)
                .await
                .unwrap();
        assert_eq!(exported.verifying_key(), held.verifying_key());

        for seed in [vec![0x53; 32], vec![0x51; 31], vec![0x51; 33]] {
            let len = seed.len();
            let refused =
                export_ed25519_signing_key(&registry, &h, |_| async move { Ok(seed) }, no_lookup)
                    .await;
            assert!(
                matches!(refused, Err(PlatformError::CustodyError(_))),
                "{len}: {refused:?}"
            );
        }
        let wrong = export_ed25519_signing_key(
            &registry,
            &KeyHandle::new(2),
            |_| async { panic!("no export from a P-256 key") },
            no_lookup,
        )
        .await;
        assert!(matches!(
            wrong,
            Err(PlatformError::WrongKeyType {
                expected: KeyType::Ed25519,
                actual: KeyType::P256Signing
            })
        ));
    }

    /// `generate_operational` asks the host for an operational key and
    /// `generate_identity` for an Ed25519 identity, and each caches the
    /// requested role.
    #[tokio::test]
    async fn generate_operational_asks_the_host_for_operational() {
        let host = fake_host::FakeHost::default();
        let host = &host;
        let registry = CallbackKeyRegistry::new();
        let asked = std::sync::Mutex::new(Vec::new());
        let asked = &asked;
        let gpk = |id: String| async move { host.get_public_key(&id) };
        let operational = generate_operational(
            &registry,
            KeyType::Ed25519,
            |t, r| {
                asked.lock().unwrap().push((t, r));
                async move { host.generate_keypair(t, r) }
            },
            gpk,
            |id| async move { host.destroy_key(&id) },
        )
        .await
        .unwrap();
        let identity = generate_identity(
            &registry,
            |t, r| {
                asked.lock().unwrap().push((t, r));
                async move { host.generate_keypair(t, r) }
            },
            gpk,
            |id| async move { host.destroy_key(&id) },
        )
        .await
        .unwrap();
        assert_eq!(
            *asked.lock().unwrap(),
            vec![
                (KeyType::Ed25519, KeyRole::Operational),
                (KeyType::Ed25519, KeyRole::Identity)
            ]
        );
        assert_eq!(
            registry.get(&operational).unwrap().unwrap().role,
            KeyRole::Operational
        );
        assert_eq!(
            registry.get(&identity).unwrap().unwrap().role,
            KeyRole::Identity
        );
    }

    /// The software host through the flows: an identity generates, signs,
    /// derives a pseudonym that is the §9.10.4.A derivation of its exported
    /// seed, and once destroyed is gone on both sides.
    #[tokio::test]
    async fn fake_host_round_trip() {
        let host = fake_host::FakeHost::default();
        let host = &host;
        let registry = CallbackKeyRegistry::new();
        let gpk = |id: String| async move { host.get_public_key(&id) };
        let identity = generate_identity(
            &registry,
            |t, r| async move { host.generate_keypair(t, r) },
            gpk,
            |id| async move { host.destroy_key(&id) },
        )
        .await
        .unwrap();
        let sig = sign(
            &registry,
            &identity,
            b"hello",
            |id, data| async move { host.sign(&id, &data) },
            gpk,
        )
        .await
        .unwrap();
        assert_eq!(sig.as_bytes().len(), 64);
        let pseudonym = derive_pseudonym(
            &registry,
            &identity,
            Some(2),
            |id| async move { host.derive_pseudonym(&id, b"ctx", Some(2)) },
            gpk,
        )
        .await
        .unwrap();
        let seed = export_ed25519_signing_key(
            &registry,
            &identity,
            |id| async move { host.export_signing_key_bytes(&id) },
            gpk,
        )
        .await
        .unwrap()
        .to_bytes();
        assert_eq!(
            pseudonym.public_key(),
            &scp_crypto::pseudonym::derive_pseudonym(
                &seed,
                b"ctx",
                scp_crypto::pseudonym::PseudonymVersion::Rotatable { epoch: 2 }
            ),
            "the host's point is the §9.10.4.A derivation"
        );
        assert_eq!(host.calls("derive_rotatable_pseudonym"), 1);
        assert_eq!(host.calls("derive_pseudonym"), 0);

        destroy_key(
            &registry,
            &identity,
            |id| async move { host.destroy_key(&id) },
        )
        .await
        .unwrap();
        assert!(matches!(
            host.get_public_key(&identity.id().to_string()),
            Err(PlatformError::KeyNotFound)
        ));
        assert!(matches!(
            public_key(&registry, &identity, gpk).await,
            Err(PlatformError::KeyNotFound)
        ));
    }

    /// Mints an Ed25519 key in `role` on `host` through a first registry.
    async fn mint_on(host: &fake_host::FakeHost, role: KeyRole) -> KeyHandle {
        let first = CallbackKeyRegistry::new();
        let gpk = |id: String| async move { host.get_public_key(&id) };
        let destroy = |id: String| async move { host.destroy_key(&id) };
        let mint = |t, r| async move { host.generate_keypair(t, r) };
        match role {
            KeyRole::Identity => generate_identity(&first, mint, gpk, destroy).await,
            KeyRole::Operational => {
                generate_operational(&first, KeyType::Ed25519, mint, gpk, destroy).await
            }
        }
        .unwrap()
    }

    /// An identity a host minted in an earlier session resolves as an
    /// identity in a new registry, and derives a pseudonym there.
    #[tokio::test]
    async fn an_earlier_sessions_identity_derives_in_a_new_registry() {
        let host = fake_host::FakeHost::default();
        let host = &host;
        let identity = mint_on(host, KeyRole::Identity).await;

        let registry = CallbackKeyRegistry::new();
        let gpk = |id: String| async move { host.get_public_key(&id) };
        derive_pseudonym(
            &registry,
            &identity,
            None,
            |id| async move { host.derive_pseudonym(&id, b"ctx", None) },
            gpk,
        )
        .await
        .unwrap();
        assert_eq!(
            registry.get(&identity).unwrap().unwrap().role,
            KeyRole::Identity
        );
        assert_eq!(host.calls("derive_pseudonym"), 1);
    }

    /// An operational key a host minted in an earlier session resolves as
    /// operational in a new registry, and its derive is `NotIdentityKey`
    /// before any host derive call.
    #[tokio::test]
    async fn an_earlier_sessions_operational_key_cannot_derive() {
        let host = fake_host::FakeHost::default();
        let host = &host;
        let operational = mint_on(host, KeyRole::Operational).await;

        let registry = CallbackKeyRegistry::new();
        let result = derive_pseudonym(
            &registry,
            &operational,
            None,
            |id| async move { host.derive_pseudonym(&id, b"ctx", None) },
            |id: String| async move { host.get_public_key(&id) },
        )
        .await;
        assert!(
            matches!(result, Err(PlatformError::NotIdentityKey)),
            "{result:?}"
        );
        assert_eq!(
            registry.get(&operational).unwrap().unwrap().role,
            KeyRole::Operational
        );
        assert_eq!(host.calls("derive_pseudonym"), 0);
    }
}
