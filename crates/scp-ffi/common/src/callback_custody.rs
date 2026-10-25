//! Shared key cache, custody records, host-answer validation and adapter
//! flows for the callback-custody bridges.
//!
//! The `PyO3`, napi-rs, and `UniFFI` bridges adapt a host `KeyCustodyProvider`
//! to [`KeyCustody`](scp_platform::KeyCustody). The host returns raw bytes, so
//! this module holds every rule for trusting what it returns, once, and the
//! three bridges only supply one closure per host call:
//!
//! - The host's `get_public_key` answers with a typed [`HostPublicKey`]: the
//!   key's [`KeyType`], its public key, and the [`KeyRole`] the host minted it
//!   in. [`registered_key`] requires the exact length for the stated type
//!   (Ed25519 32, P-256 signing and P-256 key event 33, HPKE P-256 65) and a
//!   valid key. The bridge never infers a type from a length.
//! - A [`CustodyRecordStore`] fixes the type and role each key was minted
//!   with (ADR-021, spec §17.3 `custody/record/{namespace}/{key_id}`). Every
//!   mint writes its record before it returns. An unrecorded handle is
//!   [`PlatformError::KeyNotFound`] with no host call, in every entry point,
//!   and a host answer that disagrees with the record is refused, so the host
//!   never decides a key's type or role. A production registry always has a
//!   store ([`CustodyRecords`]), opened over the namespace its identity entry
//!   keeps ([`crate::callback_identity`]).
//! - [`CallbackKeyRegistry`] caches the public key of each recorded handle
//!   this adapter minted or resolved. A destroy drops the cache entry and the
//!   record when the host confirms the key is gone or reports it absent.
//! - Every host signature is verified: an Ed25519 signature strictly over the
//!   data under the cached verifying key, a P-256 signature through
//!   [`p256_host_signature`].
//! - A key-event key ([`KeyType::P256KeyEvent`]) signs only a key-event
//!   change digest or a custody probe digest ([`sign_change`],
//!   [`sign_probe`]). Its record refuses [`sign`] before any host call
//!   (spec 09 §9.7.4.2 R10).
//! - Pseudonym derivation requires an Ed25519 [`KeyRole::Identity`] source
//!   ([`scp_platform::require_derive_source`]). A pseudonym has no private key
//!   (§9.10.4): the host returns only the 33-byte compressed point, which
//!   becomes a [`Pseudonym`], and the cache records nothing for it.
//!
//! See ADR-006, ADR-021 and the per-bridge `CallbackKeyCustody` adapters.

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex};

use ed25519_dalek::VerifyingKey;
use rand_core::RngCore;
use scp_crypto::p256::{
    COMPRESSED_POINT_LEN, P256PublicKey, SIGNATURE_LEN, UNCOMPRESSED_POINT_LEN, der_to_raw,
    normalize_low_s, verify_prehash_strict,
};
use scp_platform::error::PlatformError;
use scp_platform::traits::{
    KeyHandle, KeyRole, KeyType, Pseudonym, PublicKey, SharedSecret, Signature, Storage,
};
use scp_platform::{
    CustodyProbe, CustodyRecord, CustodyRecordStore, IndexedSignature, KeyEventSignError,
    ProbeSignature, SigningChange, refuse_key_event_mint,
};

use crate::custody_namespace::{CustodyNamespace, CustodyNamespaces, NamespaceLive};

/// A host's `get_public_key` answer: the key's type, its public key, and the
/// role the host recorded when it minted the key.
///
/// A recorded handle's answer must state the type and role its custody
/// record holds, so a host that reports another type or role for a key is
/// refused rather than believed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostPublicKey {
    /// The key's type.
    pub key_type: KeyType,
    /// The public key: 32 bytes (Ed25519), the 33-byte compressed SEC1 point
    /// ([`KeyType::P256Signing`], [`KeyType::P256KeyEvent`]), or the 65-byte
    /// uncompressed SEC1 point ([`KeyType::HpkeP256`]).
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
    /// A P-256 signing key and its public key.
    P256Signing(P256PublicKey),
    /// A P-256 HPKE key and its public key.
    HpkeP256(P256PublicKey),
    /// A P-256 key-event key and its public key.
    P256KeyEvent(P256PublicKey),
}

impl RegisteredKey {
    /// The key's [`KeyType`].
    #[must_use]
    pub const fn key_type(&self) -> KeyType {
        match self {
            Self::Ed25519(_) => KeyType::Ed25519,
            Self::P256Signing(_) => KeyType::P256Signing,
            Self::HpkeP256(_) => KeyType::HpkeP256,
            Self::P256KeyEvent(_) => KeyType::P256KeyEvent,
        }
    }

    /// The public key in the form [`KeyCustody::public_key`] returns.
    ///
    /// [`KeyCustody::public_key`]: scp_platform::KeyCustody::public_key
    #[must_use]
    pub fn public_bytes(&self) -> Vec<u8> {
        match self {
            Self::Ed25519(vk) => vk.to_bytes().to_vec(),
            Self::P256Signing(pk) | Self::P256KeyEvent(pk) => pk.to_compressed().to_vec(),
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

/// Why a callback adapter's custody records could not be opened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CustodyLoadError {
    /// Another live callback adapter of this instance holds the identity's
    /// custody namespace. Two adapters over one namespace would each check
    /// and write its records under their own lock, so the second is refused
    /// until the first drops.
    NamespaceLive,
    /// The operating system's random source failed while drawing a new
    /// namespace; no namespace is drawn from a fallback.
    RandomSource(String),
}

impl fmt::Display for CustodyLoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NamespaceLive => f.write_str(
                "another live callback custody adapter holds this identity's custody namespace",
            ),
            Self::RandomSource(detail) => write!(
                f,
                "the operating system's random source failed drawing a custody namespace: {detail}"
            ),
        }
    }
}

impl std::error::Error for CustodyLoadError {}

impl From<CustodyLoadError> for PlatformError {
    fn from(e: CustodyLoadError) -> Self {
        Self::CustodyError(e.to_string())
    }
}

impl From<NamespaceLive> for CustodyLoadError {
    fn from(NamespaceLive: NamespaceLive) -> Self {
        Self::NamespaceLive
    }
}

/// One callback adapter's custody records (spec §17.3).
///
/// The store is scoped to its identity's namespace and opened through the
/// instance's [`CustodyNamespaces`] table, which holds the namespace live
/// until the records drop.
pub struct CustodyRecords {
    store: Arc<dyn CustodyRecordStore>,
    namespace: [u8; 16],
}

impl fmt::Debug for CustodyRecords {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CustodyRecords")
            .field("namespace", &CustodyNamespace::from_bytes(self.namespace))
            .finish_non_exhaustive()
    }
}

impl CustodyRecords {
    /// Opens the records of `namespace` over `storage`, the instance
    /// storage the operator selected (spec §17.6), through `table`.
    ///
    /// # Errors
    ///
    /// [`CustodyLoadError::NamespaceLive`] while another adapter opened from
    /// `table` holds `namespace`.
    pub(crate) fn open<S>(
        table: &CustodyNamespaces,
        storage: S,
        namespace: CustodyNamespace,
    ) -> Result<Self, CustodyLoadError>
    where
        S: Storage + Send + Sync + 'static,
    {
        let namespace_bytes = *namespace.as_bytes();
        let store = table.open(storage, namespace)?;
        Ok(Self {
            store: Arc::new(store),
            namespace: namespace_bytes,
        })
    }

    /// Opens the records of a new identity under a namespace drawn from the
    /// operating system's random source. Only the create path of an
    /// identity draws a namespace; every later adapter reopens the one its
    /// identity entry stores ([`crate::callback_identity`]).
    ///
    /// # Errors
    ///
    /// [`CustodyLoadError::RandomSource`] when the random source fails, and
    /// [`CustodyLoadError::NamespaceLive`] as in [`open`](Self::open).
    pub(crate) fn create<S>(table: &CustodyNamespaces, storage: S) -> Result<Self, CustodyLoadError>
    where
        S: Storage + Send + Sync + 'static,
    {
        let mut bytes = [0u8; 16];
        rand_core::OsRng
            .try_fill_bytes(&mut bytes)
            .map_err(|e| CustodyLoadError::RandomSource(e.to_string()))?;
        Self::open(table, storage, CustodyNamespace::from_bytes(bytes))
    }

    /// The namespace these records live under.
    #[must_use]
    pub const fn namespace(&self) -> [u8; 16] {
        self.namespace
    }

    /// A new namespace table and the records of `namespace` over `storage`
    /// it holds, for a test adapter that needs records but no instance; see
    /// [`CustodyNamespaces::open_alone`].
    #[cfg(any(test, feature = "testing"))]
    #[must_use]
    pub fn open_alone<S>(storage: S, namespace: [u8; 16]) -> (CustodyNamespaces, Self)
    where
        S: Storage + Send + Sync + 'static,
    {
        let namespace_bytes = namespace;
        let (table, store) =
            CustodyNamespaces::open_alone(storage, CustodyNamespace::from_bytes(namespace));
        (
            table,
            Self {
                store: Arc::new(store),
                namespace: namespace_bytes,
            },
        )
    }

    /// Reopens `namespace` over `storage` through `table`, for a test
    /// fixture that drops an adapter and rebuilds it over the table
    /// [`open_alone`](Self::open_alone) returned, as a restarted process
    /// reopens its identity's records.
    ///
    /// # Errors
    ///
    /// [`CustodyLoadError::NamespaceLive`] while a live adapter from `table`
    /// holds `namespace`.
    #[cfg(any(test, feature = "testing"))]
    pub fn reopen<S>(
        table: &CustodyNamespaces,
        storage: S,
        namespace: [u8; 16],
    ) -> Result<Self, CustodyLoadError>
    where
        S: Storage + Send + Sync + 'static,
    {
        Self::open(table, storage, CustodyNamespace::from_bytes(namespace))
    }

    /// Records over a store a unit test built and keeps a handle to, with no
    /// namespace table: a store that fails on demand, or one the test reads
    /// beside the adapter.
    #[cfg(test)]
    pub(crate) fn unleased(store: Arc<dyn CustodyRecordStore>) -> Self {
        Self {
            store,
            namespace: [0; 16],
        }
    }
}

mod sealed {
    pub trait Sealed {}
}

/// Where a [`CallbackKeyRegistry`] reads the records of its keys.
///
/// Sealed: [`CustodyRecords`] is the one source a production adapter has,
/// and it always holds a store; the record-less source is a unit-test type.
pub trait RecordSource: sealed::Sealed + fmt::Debug + Send + Sync {
    /// The record store, or `None` for a source whose records are the
    /// entries its registry minted.
    fn store(&self) -> Option<&dyn CustodyRecordStore>;
}

impl sealed::Sealed for CustodyRecords {}

impl RecordSource for CustodyRecords {
    fn store(&self) -> Option<&dyn CustodyRecordStore> {
        Some(self.store.as_ref())
    }
}

/// The record source of a unit-test registry with no record store: only the
/// keys its registry minted are usable, and it mints no key-event key.
#[cfg(test)]
#[derive(Debug)]
pub(crate) struct NoRecords;

#[cfg(test)]
impl sealed::Sealed for NoRecords {}

#[cfg(test)]
impl RecordSource for NoRecords {
    fn store(&self) -> Option<&dyn CustodyRecordStore> {
        None
    }
}

/// The custody records and public-key cache of one callback adapter.
///
/// A handle is usable only when it has a record in the adapter's
/// [`CustodyRecordStore`]. [`resolve`] refuses a handle with no record
/// before any host call. (A unit-test registry with no store treats the
/// entries it minted as its records.)
///
/// The cache is not the authority on whether a key exists; the host is. A
/// recorded handle the cache lacks is resolved through the host, and a
/// destroy removes the entry and the record when the host confirms the key
/// is gone. The map holds at most one entry per key the caller minted or
/// used.
pub struct CallbackKeyRegistry<R: RecordSource = CustodyRecords> {
    entries: Mutex<HashMap<u64, RegisteredEntry>>,
    records: R,
}

impl<R: RecordSource> fmt::Debug for CallbackKeyRegistry<R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CallbackKeyRegistry")
            .field("records", &self.records)
            .finish_non_exhaustive()
    }
}

impl CallbackKeyRegistry {
    /// A registry whose keys' types and roles live in `records`.
    #[must_use]
    pub fn recorded(records: CustodyRecords) -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            records,
        }
    }

    /// The custody namespace this registry's records live under, which the
    /// identity's callback custody entry stores (spec §17.3).
    #[must_use]
    pub const fn namespace(&self) -> [u8; 16] {
        self.records.namespace()
    }

    /// A registry over a fresh in-memory record store with its own namespace
    /// table, for a test adapter that needs records but no instance storage.
    #[cfg(any(test, feature = "testing"))]
    #[must_use]
    pub fn recorded_in_memory() -> Self {
        Self::recorded(Self::in_memory_records())
    }

    /// Records over fresh in-memory storage and a table of their own.
    #[cfg(any(test, feature = "testing"))]
    fn in_memory_records() -> CustodyRecords {
        CustodyRecords::open_alone(scp_platform::in_memory::InMemoryStorage::new(), [0; 16]).1
    }

    /// [`recorded_in_memory`](Self::recorded_in_memory) already holding a
    /// record for each `(handle, key type, role)` in `records`, for a test
    /// that installs an adapter over keys another custody minted.
    ///
    /// # Errors
    ///
    /// Any record-store error.
    #[cfg(any(test, feature = "testing"))]
    pub async fn recorded_in_memory_holding(
        records: &[(KeyHandle, KeyType, KeyRole)],
    ) -> Result<Self, PlatformError> {
        let opened = Self::in_memory_records();
        for &(handle, key_type, role) in records {
            opened.store.put(handle, key_type, role).await?;
        }
        Ok(Self::recorded(opened))
    }
}

#[cfg(test)]
impl CallbackKeyRegistry<NoRecords> {
    /// A registry with no record store. It mints no key-event key, and only
    /// the keys it minted itself are usable; every other handle is
    /// [`PlatformError::KeyNotFound`] with no host call.
    pub(crate) fn unrecorded() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            records: NoRecords,
        }
    }
}

impl<R: RecordSource> CallbackKeyRegistry<R> {
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

    /// Caches a recorded host key resolved through `get_public_key`, in its
    /// recorded role. Resolution is a lookup a host may answer twice (two
    /// concurrent resolutions), so an id already cached with the same key
    /// returns the cached entry.
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

    /// Drops a handle's entry.
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

    /// The record store, when this registry's source has one.
    fn store(&self) -> Option<&dyn CustodyRecordStore> {
        self.records.store()
    }
}

/// The record of `key`: the type and role it was minted with.
///
/// A [`recorded`](CallbackKeyRegistry::recorded) registry reads its store,
/// a local storage read and never a host call. An
/// unrecorded registry (one with no record store) reads only the entries
/// it minted.
///
/// # Errors
///
/// Any store error, including an undecodable record; a poisoned registry.
pub async fn record_of<R: RecordSource>(
    registry: &CallbackKeyRegistry<R>,
    key: &KeyHandle,
) -> Result<Option<CustodyRecord>, PlatformError> {
    match registry.store() {
        Some(store) => store.get(*key).await,
        None => Ok(registry.get(key)?.map(|entry| CustodyRecord {
            key_type: entry.key.key_type(),
            role: entry.role,
        })),
    }
}

/// The record of `key`, or [`PlatformError::KeyNotFound`] when it has none.
async fn required_record<R: RecordSource>(
    registry: &CallbackKeyRegistry<R>,
    key: &KeyHandle,
) -> Result<CustodyRecord, PlatformError> {
    record_of(registry, key)
        .await?
        .ok_or(PlatformError::KeyNotFound)
}

/// Validates a host's `get_public_key` answer.
///
/// The public key must have exactly the stated type's length (Ed25519 32,
/// P-256 signing and key event 33, HPKE P-256 65) and be a valid key: a
/// non-weak Ed25519 point, or a P-256 point on the curve that is not the
/// identity.
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
        KeyType::P256KeyEvent => Ok(RegisteredKey::P256KeyEvent(p256_public_key(
            method, key_type, bytes,
        )?)),
        KeyType::Ed25519 => {
            let raw: [u8; 32] = bytes.try_into().map_err(|_| {
                PlatformError::CustodyError(format!(
                    "KeyCustodyProvider.{method} returned {} bytes for a {} key, expected 32",
                    bytes.len(),
                    key_type.as_str()
                ))
            })?;
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
/// It must be exactly 33 bytes (compressed) for [`KeyType::P256Signing`] and
/// [`KeyType::P256KeyEvent`], exactly 65 bytes (uncompressed) for
/// [`KeyType::HpkeP256`], and a point on the curve that is not the identity.
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
        KeyType::P256Signing | KeyType::P256KeyEvent => COMPRESSED_POINT_LEN,
        KeyType::HpkeP256 => UNCOMPRESSED_POINT_LEN,
        KeyType::Ed25519 => {
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
    p256_host_raw(public_key, digest, host_signature).map(|raw| Signature::new(raw.to_vec()))
}

/// [`p256_host_signature`] as the fixed-size raw signature.
fn p256_host_raw(
    public_key: &P256PublicKey,
    digest: &[u8; 32],
    host_signature: &[u8],
) -> Result<[u8; SIGNATURE_LEN], PlatformError> {
    let raw: Option<[u8; SIGNATURE_LEN]> = host_signature.try_into().ok();
    let der = der_to_raw(host_signature).ok();
    for candidate in raw.iter().chain(der.iter()) {
        let Ok(low_s) = normalize_low_s(candidate) else {
            continue;
        };
        if verify_prehash_strict(public_key, digest, &low_s).is_ok() {
            return Ok(low_s);
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

/// Refuses a key-event key's record where `expected` is required, before
/// any host call (spec 09 §9.7.4.2 R10).
const fn refuse_key_event_record(
    record: CustodyRecord,
    expected: KeyType,
) -> Result<(), PlatformError> {
    if matches!(record.key_type, KeyType::P256KeyEvent) {
        return Err(PlatformError::WrongKeyType {
            expected,
            actual: KeyType::P256KeyEvent,
        });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Adapter flows
//
// Each bridge supplies its host calls as closures; these functions hold every
// decision (key types, roles, records, cache, lengths, signature and seed
// checks) so the bridges cannot drift. The closures take the key id as the
// host's string.
// ---------------------------------------------------------------------------

/// `KeyCustody::generate_keypair` over a host: mints a key of `key_type` in
/// [`KeyRole::Operational`].
///
/// See [`generate_identity`] for the identity key and [`generate_key_event`]
/// for the key-event key, which this refuses.
///
/// # Errors
///
/// [`PlatformError::WrongKeyType`] for [`KeyType::P256KeyEvent`], with no
/// host call ([`refuse_key_event_mint`]); otherwise as in
/// [`generate_identity`].
pub async fn generate_operational<R: RecordSource, G, GF, P, PF, D, DF>(
    registry: &CallbackKeyRegistry<R>,
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
    refuse_key_event_mint(key_type)?;
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

/// `KeyCustody::generate_key_event_keypair` over a host: mints a
/// [`KeyType::P256KeyEvent`] key in [`KeyRole::Operational`].
///
/// The flow records the key before it returns, so a later adapter over the
/// same records refuses its raw signing whatever the host then reports
/// (ADR-021).
///
/// # Errors
///
/// [`PlatformError::Unsupported`] for an
/// unrecorded registry (one with no record store), with no host
/// call; otherwise as in [`generate_identity`].
pub async fn generate_key_event<R: RecordSource, G, GF, P, PF, D, DF>(
    registry: &CallbackKeyRegistry<R>,
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
    if registry.store().is_none() {
        return Err(PlatformError::Unsupported(
            "callback custody without a record store cannot mint a key-event key",
        ));
    }
    generate(
        registry,
        KeyType::P256KeyEvent,
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
/// requested type and role and pass [`registered_key`], caches it, and
/// writes its custody record before it returns. When the key id is not
/// numeric, the host's `get_public_key` fails, the host's answer is refused,
/// or the record write fails, the flow destroys the new host key before it
/// returns the error, and appends a destroy failure other than key-not-found
/// to the error. The flow leaves the host key in place in three cases. When
/// the cache already holds the id, the id names a key this adapter holds, so
/// the flow returns the refusal alone. When the registry lock is poisoned, the
/// cache cannot say whether the id names a held key, so the flow appends that
/// the key was not destroyed. When the host's `generate_keypair` fails, no key
/// id exists and nothing is destroyed.
///
/// A caller that drops this future between the host's mint and the record
/// write leaves the minted key on the host with no record. No SCP operation
/// reads, signs with or destroys an unrecorded key (spec §17.3).
///
/// # Errors
///
/// Any host or record-store error; [`PlatformError::CustodyError`] for a
/// non-numeric key id, a refused public key, another stated type or role, a
/// cached key id, or a different record already stored under the id.
pub async fn generate_identity<R: RecordSource, G, GF, P, PF, D, DF>(
    registry: &CallbackKeyRegistry<R>,
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

/// The one generation flow; [`generate_operational`], [`generate_identity`]
/// and [`generate_key_event`] fix the type and role.
async fn generate<R: RecordSource, G, GF, P, PF, D, DF>(
    registry: &CallbackKeyRegistry<R>,
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
        if let Some(store) = registry.store()
            && let Err(refused) = store.put(handle, key_type, role).await
        {
            // The key is unrecorded, so this adapter does not hold it: drop
            // the cache entry so the refusal below destroys the host key.
            registry.remove(handle)?;
            return Err(refused);
        }
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

/// The cached entry for `key`, resolving a recorded handle the cache lacks
/// through the host's `get_public_key`. Every entry point calls this, so no
/// result depends on which ran first.
///
/// A handle with no record ([`record_of`]) is
/// [`PlatformError::KeyNotFound`] with no host call: the host never decides
/// a key's type or role. A recorded handle's host answer must pass
/// [`registered_key`] and state the recorded type and role, and binds the
/// handle in that role ([`CallbackKeyRegistry::bind_resolved`]). Returns the
/// entry and whether this call asked the host.
///
/// # Errors
///
/// [`PlatformError::KeyNotFound`] for an unrecorded handle; the host's own
/// error for a key it lacks; [`PlatformError::CustodyError`] for an answer
/// that disagrees with the custody record; as in [`registered_key`] and
/// [`CallbackKeyRegistry::bind_resolved`].
pub async fn resolve<R: RecordSource, P, PF>(
    registry: &CallbackKeyRegistry<R>,
    key: &KeyHandle,
    host_get_public_key: &P,
) -> Result<(RegisteredEntry, bool), PlatformError>
where
    P: Fn(String) -> PF + Sync,
    PF: Future<Output = Result<HostPublicKey, PlatformError>>,
{
    let record = required_record(registry, key).await?;
    resolve_recorded(registry, key, record, host_get_public_key).await
}

/// [`resolve`] for a handle whose `record` the caller already read.
async fn resolve_recorded<R: RecordSource, P, PF>(
    registry: &CallbackKeyRegistry<R>,
    key: &KeyHandle,
    record: CustodyRecord,
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
    if found.key_type() != record.key_type || answer.role != record.role {
        return Err(PlatformError::CustodyError(format!(
            "KeyCustodyProvider.get_public_key reports key_id {} as a {} {} key, which \
             disagrees with the custody record ({} {})",
            key.id(),
            found.key_type().as_str(),
            answer.role.as_str(),
            record.key_type.as_str(),
            record.role.as_str()
        )));
    }
    Ok((registry.bind_resolved(*key, found, record.role)?, true))
}

/// `KeyCustody::sign` over a host provider.
///
/// The record is read first: an unrecorded handle is
/// [`PlatformError::KeyNotFound`] and a key-event key
/// [`PlatformError::WrongKeyType`], each with no host call of any kind
/// (spec 09 §9.7.4.2 R10). A P-256 signing key then signs a 32-byte digest
/// and its host result passes [`p256_host_signature`]. An Ed25519 key signs
/// `data` and its host result passes [`ed25519_host_signature`]. A
/// key-agreement key is [`PlatformError::WrongKeyType`] without a host sign
/// call.
///
/// # Errors
///
/// Any host or record-store error; [`PlatformError::KeyNotFound`],
/// [`PlatformError::WrongKeyType`] or [`PlatformError::CustodyError`] as
/// above and in [`resolve`].
pub async fn sign<R: RecordSource, S, SF, P, PF>(
    registry: &CallbackKeyRegistry<R>,
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
    let record = required_record(registry, key).await?;
    refuse_key_event_record(record, KeyType::P256Signing)?;
    let key_id = key.id().to_string();
    match resolve_recorded(registry, key, record, &host_get_public_key)
        .await?
        .0
        .key
    {
        RegisteredKey::P256Signing(pk) => {
            let digest = p256_digest(data)?;
            let host_sig = host_sign(key_id, digest.to_vec()).await?;
            p256_host_signature(&pk, &digest, &host_sig)
        }
        RegisteredKey::Ed25519(vk) => {
            ed25519_host_signature(&vk, data, host_sign(key_id, data.to_vec()).await?)
        }
        k @ (RegisteredKey::HpkeP256(_) | RegisteredKey::P256KeyEvent(_)) => {
            Err(k.wrong_type(KeyType::P256Signing))
        }
    }
}

/// `KeyEventSigner::sign_change` over a host provider: the key-event key
/// `key` signs the 32-byte change digest `D` (spec 09 §9.7.4.2 R10).
///
/// The host's `sign` receives exactly `change.digest()`, and its signature
/// passes [`p256_host_signature`] under the key's public key and becomes the
/// raw low-`s` [`IndexedSignature::Raw`].
///
/// # Errors
///
/// [`KeyEventSignError::MemberNotFound`] for an unrecorded handle or a key
/// the host lacks; [`KeyEventSignError::WrongKeyType`] for a handle whose
/// record is not a key-event key; [`KeyEventSignError::Substrate`] for a host
/// error, a store error, an answer that disagrees with the record, or a
/// signature that does not verify.
pub async fn sign_change<R: RecordSource, S, SF, P, PF>(
    registry: &CallbackKeyRegistry<R>,
    key: &KeyHandle,
    change: &SigningChange,
    host_sign: S,
    host_get_public_key: P,
) -> Result<IndexedSignature, KeyEventSignError>
where
    S: FnOnce(String, Vec<u8>) -> SF,
    SF: Future<Output = Result<Vec<u8>, PlatformError>>,
    P: Fn(String) -> PF + Sync,
    PF: Future<Output = Result<HostPublicKey, PlatformError>>,
{
    let signature = key_event_signature(
        registry,
        key,
        change.digest(),
        host_sign,
        host_get_public_key,
    )
    .await?;
    Ok(IndexedSignature::Raw { signature })
}

/// `KeyEventSigner::sign_probe` over a host provider: the key-event key
/// `key` signs the custody probe's raw digest (§9.7.4.1 item 5, step d).
///
/// The host's `sign` receives exactly `probe.raw_digest()`.
///
/// # Errors
///
/// As in [`sign_change`].
pub async fn sign_probe<R: RecordSource, S, SF, P, PF>(
    registry: &CallbackKeyRegistry<R>,
    key: &KeyHandle,
    probe: &CustodyProbe,
    host_sign: S,
    host_get_public_key: P,
) -> Result<ProbeSignature, KeyEventSignError>
where
    S: FnOnce(String, Vec<u8>) -> SF,
    SF: Future<Output = Result<Vec<u8>, PlatformError>>,
    P: Fn(String) -> PF + Sync,
    PF: Future<Output = Result<HostPublicKey, PlatformError>>,
{
    let signature = key_event_signature(
        registry,
        key,
        probe.raw_digest(),
        host_sign,
        host_get_public_key,
    )
    .await?;
    Ok(ProbeSignature::raw(signature))
}

/// The raw low-`s` signature of the key-event key `key` over `digest`.
async fn key_event_signature<R: RecordSource, S, SF, P, PF>(
    registry: &CallbackKeyRegistry<R>,
    key: &KeyHandle,
    digest: [u8; 32],
    host_sign: S,
    host_get_public_key: P,
) -> Result<[u8; SIGNATURE_LEN], PlatformError>
where
    S: FnOnce(String, Vec<u8>) -> SF,
    SF: Future<Output = Result<Vec<u8>, PlatformError>>,
    P: Fn(String) -> PF + Sync,
    PF: Future<Output = Result<HostPublicKey, PlatformError>>,
{
    let record = required_record(registry, key).await?;
    if record.key_type != KeyType::P256KeyEvent {
        return Err(PlatformError::WrongKeyType {
            expected: KeyType::P256KeyEvent,
            actual: record.key_type,
        });
    }
    let public_key = match resolve_recorded(registry, key, record, &host_get_public_key)
        .await?
        .0
        .key
    {
        RegisteredKey::P256KeyEvent(pk) => pk,
        other => return Err(other.wrong_type(KeyType::P256KeyEvent)),
    };
    let host_sig = host_sign(key.id().to_string(), digest.to_vec()).await?;
    p256_host_raw(&public_key, &digest, &host_sig)
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
pub async fn public_key<R: RecordSource, P, PF>(
    registry: &CallbackKeyRegistry<R>,
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
/// A key-event key's record is [`PlatformError::WrongKeyType`] with no host
/// call. An HPKE P-256 key requires a valid 65-byte uncompressed peer point,
/// checked before the host call. A signing key is
/// [`PlatformError::WrongKeyType`] without a host agreement call. The host
/// must return exactly 32 bytes, which are zeroized once copied.
///
/// # Errors
///
/// Any host error; [`PlatformError::WrongKeyType`] or
/// [`PlatformError::CustodyError`] as above and in [`resolve`].
pub async fn dh_agree<R: RecordSource, H, HF, P, PF>(
    registry: &CallbackKeyRegistry<R>,
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
    let record = required_record(registry, key).await?;
    refuse_key_event_record(record, KeyType::HpkeP256)?;
    let peer = match resolve_recorded(registry, key, record, &host_get_public_key)
        .await?
        .0
        .key
    {
        RegisteredKey::HpkeP256(_) => p256_peer_for_host(peer_public)?.to_vec(),
        k @ (RegisteredKey::Ed25519(_)
        | RegisteredKey::P256Signing(_)
        | RegisteredKey::P256KeyEvent(_)) => {
            return Err(k.wrong_type(KeyType::HpkeP256));
        }
    };
    let shared = zeroize::Zeroizing::new(host_dh_agree(key.id().to_string(), peer).await?);
    Ok(SharedSecret::new(crate::custody_parse::expect_32(
        "dh_agree", &shared,
    )?))
}

/// `KeyCustody::destroy_key` over a host provider.
///
/// An unrecorded handle is [`PlatformError::KeyNotFound`] with no host call.
/// Otherwise the host destroys the key, and the cache entry and the custody
/// record are dropped when the host confirms the key is gone, by success or
/// by key-not-found. A host failure leaves both, so the handle still names
/// the key the host still holds.
///
/// # Errors
///
/// [`PlatformError::KeyNotFound`] for an unrecorded handle or a key the host
/// does not hold; any other host error; [`PlatformError::CustodyError`] when
/// the record could not be removed after the host's destroy; a poisoned
/// registry.
pub async fn destroy_key<R: RecordSource, D, DF>(
    registry: &CallbackKeyRegistry<R>,
    key: &KeyHandle,
    host_destroy: D,
) -> Result<(), PlatformError>
where
    D: FnOnce(String) -> DF,
    DF: Future<Output = Result<(), PlatformError>>,
{
    required_record(registry, key).await?;
    match host_destroy(key.id().to_string()).await {
        Ok(()) => forget(registry, key).await,
        Err(PlatformError::KeyNotFound) => {
            forget(registry, key).await?;
            Err(PlatformError::KeyNotFound)
        }
        Err(e) => Err(e),
    }
}

/// Drops `key`'s cache entry and custody record once the host no longer
/// holds it.
async fn forget<R: RecordSource>(
    registry: &CallbackKeyRegistry<R>,
    key: &KeyHandle,
) -> Result<(), PlatformError> {
    registry.remove(*key)?;
    if let Some(store) = registry.store() {
        store.remove(*key).await.map_err(|e| {
            PlatformError::CustodyError(format!(
                "the host no longer holds key_id {}, and its custody record was not \
                 removed: {e}",
                key.id()
            ))
        })?;
    }
    Ok(())
}

/// `KeyCustody::derive_pseudonym` (`epoch` `None`) and
/// `derive_rotatable_pseudonym` over a host provider.
///
/// `key`'s record must be an Ed25519 [`KeyRole::Identity`] key
/// ([`scp_platform::require_derive_source`]): an operational key, the
/// key-event key included, is [`PlatformError::NotIdentityKey`] and an
/// identity of another type [`PlatformError::WrongKeyType`], each with no
/// host call. A key the host no longer holds is the host's key-not-found
/// (§9.10.4.A). A pseudonym has no private key, so the host returns only the
/// point; [`parse_pseudonym`] requires a 33-byte compressed P-256 point, and
/// nothing is cached.
///
/// [`parse_pseudonym`]: crate::custody_parse::parse_pseudonym
///
/// # Errors
///
/// As above and in [`resolve`]; any `host_derive` error;
/// [`PlatformError::PseudonymRejected`] (reported as `SCP-IDENT-1055`) for
/// bytes that are not a compressed P-256 point.
pub async fn derive_pseudonym<R: RecordSource, H, HF, P, PF>(
    registry: &CallbackKeyRegistry<R>,
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
    let record = required_record(registry, key).await?;
    scp_platform::require_derive_source(record.role, record.key_type)?;
    resolve_recorded(registry, key, record, &host_get_public_key).await?;
    let point = host_derive(key.id().to_string()).await?;
    crate::custody_parse::parse_pseudonym(method, &point)
}

/// The host contract's key-id rule, run against a host (spec §17.3): a host
/// never reuses a key id within one namespace, so a destroyed key's id is
/// never handed out again.
///
/// Mints `rounds` keys of every [`KeyType`] the host serves, destroying each
/// before the next mint, and requires every id to differ.
///
/// # Errors
///
/// A description of the first id the host handed out twice, or of a host
/// call that failed.
#[cfg(any(test, feature = "testing"))]
pub async fn check_host_never_reuses_key_ids<G, GF, D, DF>(
    rounds: usize,
    host_generate: G,
    host_destroy: D,
) -> Result<(), String>
where
    G: Fn(KeyType, KeyRole) -> GF,
    GF: Future<Output = Result<String, PlatformError>>,
    D: Fn(String) -> DF,
    DF: Future<Output = Result<(), PlatformError>>,
{
    let mints = [
        (KeyType::Ed25519, KeyRole::Identity),
        (KeyType::Ed25519, KeyRole::Operational),
        (KeyType::P256Signing, KeyRole::Operational),
        (KeyType::HpkeP256, KeyRole::Operational),
        (KeyType::P256KeyEvent, KeyRole::Operational),
    ];
    let mut seen = std::collections::HashSet::new();
    for _ in 0..rounds {
        for (key_type, role) in mints {
            let id = host_generate(key_type, role)
                .await
                .map_err(|e| format!("generate_keypair({}) failed: {e}", key_type.as_str()))?;
            if !seen.insert(id.clone()) {
                return Err(format!(
                    "the host handed out key id {id} again after destroying the key it named"
                ));
            }
            host_destroy(id.clone())
                .await
                .map_err(|e| format!("destroy_key({id}) failed: {e}"))?;
        }
    }
    Ok(())
}

/// Why a test fixture's `reopen` left its adapter as it was.
#[cfg(any(test, feature = "testing"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReopenRefusal {
    /// An earlier `reopen` already closed the adapter.
    Closed,
    /// A call still holds the adapter, and with it the namespace, so a new
    /// adapter could not open the records; the adapter stays open.
    InFlight,
}

#[cfg(any(test, feature = "testing"))]
impl fmt::Display for ReopenRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Closed => "this testing adapter was closed by reopen",
            Self::InFlight => {
                "a call on this testing adapter is still in flight and holds its custody \
                 records; the adapter stays open, so reopen it after the call settles"
            }
        })
    }
}

/// Closes the adapter in a test fixture's `slot` for a reopen over the same
/// records, only when no call holds it.
///
/// The namespace is released when the adapter drops, so an adapter a call
/// still holds would make the reopen's open refuse the namespace while the
/// fixture had already given its adapter up. A refused close leaves `slot`
/// as it was.
///
/// # Errors
///
/// [`ReopenRefusal::Closed`] for an empty slot, and
/// [`ReopenRefusal::InFlight`] while another reference to the adapter lives.
#[cfg(any(test, feature = "testing"))]
pub fn close_for_reopen<T>(slot: &mut Option<Arc<T>>) -> Result<(), ReopenRefusal> {
    let adapter = slot.take().ok_or(ReopenRefusal::Closed)?;
    match Arc::try_unwrap(adapter) {
        Ok(adapter) => {
            drop(adapter);
            Ok(())
        }
        Err(shared) => {
            *slot = Some(shared);
            Err(ReopenRefusal::InFlight)
        }
    }
}

/// A software host for bridge tests: Ed25519, P-256 signing, HPKE P-256
/// and P-256 key-event keys, answering the host callbacks the way a conforming platform keystore
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

    /// A key the host holds. A P-256 signing key and a P-256 key-event key
    /// are both [`HostKey::P256`]; the reported-type map tells them apart.
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
        /// The type `get_public_key` reports for each key id: the minted
        /// type, unless a test replaced it ([`FakeHost::report_as`]).
        types: Mutex<HashMap<String, KeyType>>,
        next: AtomicUsize,
        calls: Mutex<HashMap<&'static str, usize>>,
        /// The peer bytes of the most recent `dh_agree` call.
        pub last_peer: Mutex<Option<Vec<u8>>>,
    }

    /// The secret scalar the fake host mints for key id `id`: one byte
    /// repeated, so a test recomputes a key's seed from its handle id instead
    /// of asking the host to export it.
    #[must_use]
    pub fn scalar_for(id: u64) -> [u8; 32] {
        [u8::try_from(id % 64).unwrap_or(0) + 0x40; 32]
    }

    impl FakeHost {
        /// Whether the host still holds `key_id`.
        pub fn holds(&self, key_id: &str) -> bool {
            locked(&self.keys).is_ok_and(|keys| keys.contains_key(key_id))
        }

        /// Makes `get_public_key` report `key_id` as `key_type`, as a host
        /// that misreports a key would.
        ///
        /// # Errors
        ///
        /// A poisoned type map.
        pub fn report_as(&self, key_id: &str, key_type: KeyType) -> Result<(), PlatformError> {
            locked(&self.types)?.insert(key_id.to_owned(), key_type);
            Ok(())
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

        /// `generate_keypair`: Ed25519, P-256 signing, HPKE P-256 or P-256
        /// key event, recording `role` and the type for `get_public_key`;
        /// numeric ids from 1, never reused.
        ///
        /// # Errors
        ///
        /// A poisoned key or role map.
        pub fn generate_keypair(
            &self,
            key_type: KeyType,
            role: KeyRole,
        ) -> Result<String, PlatformError> {
            self.count("generate_keypair");
            let id = self.next_id();
            let scalar = scalar_for(id as u64);
            let p256 = || {
                P256SecretKey::from_scalar_bytes(&scalar)
                    .map_err(|e| PlatformError::CustodyError(e.to_string()))
            };
            let key = match key_type {
                KeyType::Ed25519 => {
                    HostKey::Ed25519(ed25519_dalek::SigningKey::from_bytes(&scalar))
                }
                KeyType::P256Signing | KeyType::P256KeyEvent => HostKey::P256(p256()?),
                KeyType::HpkeP256 => HostKey::HpkeP256(p256()?),
            };
            locked(&self.roles)?.insert(id.to_string(), role);
            locked(&self.types)?.insert(id.to_string(), key_type);
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
            let reported = locked(&self.types)?.get(key_id).copied();
            self.with_key(key_id, |key| {
                // Every key this host holds has a recorded role; a held key
                // without one is a fake-host defect, reported, never defaulted.
                let role = role.ok_or_else(|| {
                    PlatformError::CustodyError(format!(
                        "fake host recorded no role for key {key_id}"
                    ))
                })?;
                let key_type = reported.ok_or_else(|| {
                    PlatformError::CustodyError(format!(
                        "fake host recorded no type for key {key_id}"
                    ))
                })?;
                let public_key = match key {
                    HostKey::Ed25519(sk) => sk.verifying_key().to_bytes().to_vec(),
                    HostKey::P256(sk) => sk.public_key().to_compressed().to_vec(),
                    HostKey::HpkeP256(sk) => sk.public_key().to_uncompressed().to_vec(),
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

        /// `destroy_key`.
        ///
        /// # Errors
        ///
        /// An unknown key id.
        pub fn destroy_key(&self, key_id: &str) -> Result<(), PlatformError> {
            self.count("destroy_key");
            locked(&self.roles)?.remove(key_id);
            locked(&self.types)?.remove(key_id);
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

    fn live<R: RecordSource>(
        registry: &CallbackKeyRegistry<R>,
        id: u64,
        key: RegisteredKey,
        role: KeyRole,
    ) {
        registry
            .register(KeyHandle::new(id), RegisteredEntry { key, role })
            .unwrap();
    }

    fn cached<R: RecordSource>(registry: &CallbackKeyRegistry<R>) -> usize {
        registry.entries.lock().expect("registry lock").len()
    }

    /// A record store over fresh in-memory storage, in namespace `ns`.
    fn store_in(ns: u8) -> Arc<dyn CustodyRecordStore> {
        Arc::new(
            CustodyNamespaces::new()
                .open(
                    scp_platform::in_memory::InMemoryStorage::new(),
                    CustodyNamespace::from_bytes([ns; 16]),
                )
                .unwrap(),
        )
    }

    /// A recorded registry over `store`.
    fn over(store: &Arc<dyn CustodyRecordStore>) -> CallbackKeyRegistry {
        CallbackKeyRegistry::recorded(CustodyRecords::unleased(Arc::clone(store)))
    }

    /// A recorded registry whose store holds `records`, and the store.
    async fn seeded(
        records: &[(u64, KeyType, KeyRole)],
    ) -> (CallbackKeyRegistry, Arc<dyn CustodyRecordStore>) {
        let store = store_in(7);
        for &(id, key_type, role) in records {
            store.put(KeyHandle::new(id), key_type, role).await.unwrap();
        }
        (over(&store), store)
    }

    /// A host call a test expects never to happen.
    fn no_host<A, T>(_: A) -> std::future::Ready<Result<T, PlatformError>> {
        panic!("no host call expected")
    }

    /// A two-argument host call a test expects never to happen.
    fn no_host2<A, B, T>(_: A, _: B) -> std::future::Ready<Result<T, PlatformError>> {
        panic!("no host call expected")
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
        assert_eq!(
            registered_key("m", &answer(KeyType::Ed25519, &e.to_bytes())).unwrap(),
            RegisteredKey::Ed25519(e)
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
            answer(KeyType::P256Signing, &e.to_bytes()),
            answer(KeyType::P256Signing, &p.to_uncompressed()),
            answer(KeyType::HpkeP256, &p.to_compressed()),
            answer(KeyType::Ed25519, &[0u8; 31]),
            answer(KeyType::Ed25519, &[0u8; 33]),
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
    }

    /// Handle 5 of `registry`, an Ed25519 `key`, refuses a host's 64 junk
    /// bytes and accepts its real signature.
    async fn junk_then_real<R: RecordSource>(
        registry: &CallbackKeyRegistry<R>,
        key: &ed25519_dalek::SigningKey,
        calls: &AtomicUsize,
    ) {
        let h = KeyHandle::new(5);
        assert!(matches!(
            sign(
                registry,
                &h,
                b"data",
                |_, _| async { Ok(vec![0x11u8; 64]) },
                lookup(&ed_answer(key), calls)
            )
            .await,
            Err(PlatformError::CustodyError(_))
        ));
        let good = key.sign(b"data").to_bytes().to_vec();
        let expected = good.clone();
        let sig = sign(
            registry,
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

    /// An Ed25519 handle, minted or resolved, rejects a host that returns
    /// 64 junk bytes, and accepts its real signature.
    #[tokio::test]
    async fn ed25519_sign_rejects_junk_from_the_host() {
        let key = ed(0x51);
        let calls = AtomicUsize::new(0);
        let minted = CallbackKeyRegistry::unrecorded();
        live(
            &minted,
            5,
            RegisteredKey::Ed25519(key.verifying_key()),
            KeyRole::Operational,
        );
        junk_then_real(&minted, &key, &calls).await;
        let (resolving, _store) = seeded(&[(5, KeyType::Ed25519, KeyRole::Operational)]).await;
        junk_then_real(&resolving, &key, &calls).await;
        assert_eq!(
            calls.load(Ordering::Relaxed),
            1,
            "only the recorded registry with an empty cache resolves"
        );
    }

    /// A registry holding identity key 1 (Ed25519) and operational P-256
    /// signing key 7 (`key`).
    fn registry_with_p256(
        identity: &ed25519_dalek::SigningKey,
        key: &P256SecretKey,
    ) -> CallbackKeyRegistry<NoRecords> {
        let registry = CallbackKeyRegistry::unrecorded();
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

    /// An HPKE P-256 agreement hands the host exactly the 65-byte
    /// uncompressed peer point and returns the host's ECDH x-coordinate,
    /// which equals `ecdh_p256` from the pinned vector's scalar. A peer of the
    /// wrong length (32, 33, 64, 66 bytes), off the curve, or `0x00`-led is
    /// rejected with no `dh_agree` call reaching the host.
    #[tokio::test]
    async fn hpke_p256_dh_agree_passes_exactly_the_65_byte_point_to_the_host() {
        use scp_crypto::p256::{P256PublicKey, ecdh_p256, testing};

        let host = super::fake_host::FakeHost::default();
        let key_id = host
            .generate_keypair(KeyType::HpkeP256, KeyRole::Operational)
            .unwrap();
        let handle = KeyHandle::new(key_id.parse().unwrap());
        let (registry, _store) =
            seeded(&[(handle.id(), KeyType::HpkeP256, KeyRole::Operational)]).await;
        let host_dh = |id: String, peer: Vec<u8>| {
            let answer = host.dh_agree(&id, &peer);
            async move { answer }
        };
        let host_lookup = |id: String| {
            let answer = host.get_public_key(&id);
            async move { answer }
        };

        let fixed = P256SecretKey::from_scalar_bytes(
            &hex::decode(testing::ECDH_VECTOR_SCALAR_I)
                .unwrap()
                .try_into()
                .unwrap(),
        )
        .unwrap();
        let peer = fixed.public_key().to_uncompressed();
        let shared = dh_agree(&registry, &handle, &peer, host_dh, &host_lookup)
            .await
            .unwrap();
        assert_eq!(host.calls("dh_agree"), 1);
        assert_eq!(
            host.last_peer.lock().unwrap().as_deref(),
            Some(peer.as_slice()),
            "the host saw exactly the 65-byte point"
        );
        let own = P256PublicKey::from_uncompressed(
            host.get_public_key(&key_id).unwrap().public_key.as_slice(),
        )
        .unwrap();
        assert_eq!(shared.as_bytes(), ecdh_p256(&fixed, &own).as_slice());

        let mut off_curve = peer;
        off_curve[64] ^= 1;
        let infinity = [0u8; 65];
        let rejected: [(&str, Vec<u8>); 6] = [
            ("32 bytes", peer[1..33].to_vec()),
            ("33 bytes", fixed.public_key().to_compressed().to_vec()),
            ("64 bytes", peer[1..].to_vec()),
            ("66 bytes", [&peer[..], &[0u8][..]].concat()),
            ("off curve", off_curve.to_vec()),
            ("0x00-led", infinity.to_vec()),
        ];
        for (case, bad) in rejected {
            let host_dh = |id: String, peer: Vec<u8>| {
                let answer = host.dh_agree(&id, &peer);
                async move { answer }
            };
            assert!(
                matches!(
                    dh_agree(&registry, &handle, &bad, host_dh, &host_lookup).await,
                    Err(PlatformError::CustodyError(_))
                ),
                "{case}"
            );
            assert_eq!(host.calls("dh_agree"), 1, "{case} reached the host");
        }
    }

    /// Every entry point resolves a recorded handle the cache lacks the same
    /// way, with one host lookup, and binds the same operational entry,
    /// whichever runs first.
    #[tokio::test]
    async fn every_entry_point_resolves_an_unregistered_handle() {
        let e = ed(0x71);
        let p = p256(0x72);
        let h = KeyHandle::new(42);
        let peer_x = [5u8; 32];
        let peer_p = p256(0x74).public_key().to_uncompressed();

        // (answer, the entry point run first); each must resolve and bind.
        let ed_a = ed_answer(&e);
        let hpke_a = hpke_answer(&p);
        let cases: Vec<(&HostPublicKey, &str)> = vec![
            (&ed_a, "sign"),
            (&ed_a, "public_key"),
            (&ed_a, "dh_agree"),
            (&hpke_a, "public_key"),
            (&hpke_a, "dh_agree"),
            (&hpke_a, "sign"),
        ];
        for (host_answer, first) in cases {
            let (registry, _store) =
                seeded(&[(42, host_answer.key_type, KeyRole::Operational)]).await;
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
            // The type decides the outcome, never the order: signing needs
            // Ed25519, agreement needs an agreement key.
            let fits = !matches!(
                (host_answer.key_type.as_str(), first),
                ("ed25519", "dh_agree") | ("hpke-p256", "sign")
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

    /// A host without a recorded key answers its not-found to every entry
    /// point, with no other host call and nothing bound.
    #[tokio::test]
    async fn every_entry_point_reports_a_key_the_host_lacks() {
        let h = KeyHandle::new(42);
        let peer_x = [5u8; 32];
        let (registry, _store) = seeded(&[(42, KeyType::Ed25519, KeyRole::Operational)]).await;
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
            answer(KeyType::HpkeP256, &[4u8; 64]),
        ] {
            let (registry, _store) = seeded(&[(8, a.key_type, KeyRole::Operational)]).await;
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
        let (registry, _store) = seeded(&[(9, KeyType::P256Signing, KeyRole::Operational)]).await;
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

    /// A registered HPKE key whose host point changes after generation
    /// is a custody error from `public_key`; so is one whose host now states
    /// another type for the same bytes, or another role for the same key.
    #[tokio::test]
    async fn public_key_refuses_a_changed_host_key() {
        let registry = CallbackKeyRegistry::unrecorded();
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

    /// An HPKE P-256 handle given a compressed peer point is a custody error
    /// with no host call; a 65-byte uncompressed point reaches the host.
    #[tokio::test]
    async fn hpke_agree_checks_the_peer_before_the_host() {
        let registry = CallbackKeyRegistry::unrecorded();
        live(
            &registry,
            3,
            RegisteredKey::HpkeP256(p256(0x93).public_key()),
            KeyRole::Operational,
        );
        let h = KeyHandle::new(3);
        let peer = p256(0x94).public_key();
        let agreed = AtomicUsize::new(0);
        let host = |_: String, peer: Vec<u8>| {
            agreed.fetch_add(1, Ordering::Relaxed);
            async move {
                assert_eq!(peer.len(), 65);
                Ok(vec![7u8; 32])
            }
        };
        assert!(matches!(
            dh_agree(&registry, &h, &peer.to_compressed(), host, no_lookup).await,
            Err(PlatformError::CustodyError(_))
        ));
        assert_eq!(agreed.load(Ordering::Relaxed), 0);
        let shared = dh_agree(&registry, &h, &peer.to_uncompressed(), host, no_lookup)
            .await
            .unwrap();
        assert_eq!(shared.as_bytes(), &[7u8; 32]);
        assert_eq!(agreed.load(Ordering::Relaxed), 1);
    }

    /// Runs `derive_pseudonym` from `source` with a host that returns
    /// `point`, counting derive calls.
    async fn derive_from<R: RecordSource>(
        registry: &CallbackKeyRegistry<R>,
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
    /// Ed25519 key (minted by `generate_operational`, or recorded as
    /// operational) is `NotIdentityKey`: it is Ed25519, so the curve check
    /// alone would pass it. A P-256 identity key is `WrongKeyType` from the
    /// interim curve check. None reaches the host's derive, and a derive
    /// caches nothing.
    #[tokio::test]
    async fn derivation_needs_an_identity_source() {
        let point = p256(0xC1).public_key().to_compressed().to_vec();
        let registry = CallbackKeyRegistry::unrecorded();
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
        // A key recorded as operational never derives, and its record
        // refuses it before any host call.
        let (recorded, _store) = seeded(&[(5, KeyType::Ed25519, KeyRole::Operational)]).await;
        let resolved = derive_pseudonym(
            &recorded,
            &KeyHandle::new(5),
            None,
            |_| async { panic!("no derivation from an operational key") },
            no_lookup,
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
        let registry = CallbackKeyRegistry::unrecorded();
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
    /// and the custody record are gone once the host confirmed the destroy,
    /// so the handle is key-not-found with no host call of any kind.
    #[tokio::test]
    async fn destroyed_identity_derive_is_key_not_found() {
        let host = fake_host::FakeHost::default();
        let host = &host;
        let (registry, store) = seeded(&[]).await;
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
        assert_eq!(store.get(identity).await.unwrap(), None);
        let lookups = host.calls("get_public_key");
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
        assert_eq!(host.calls("get_public_key"), lookups);
    }

    type Log = std::sync::Mutex<Vec<String>>;

    async fn generate_with<R: RecordSource>(
        registry: &CallbackKeyRegistry<R>,
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
            (KeyType::HpkeP256, "", Ok(hpke_answer(&valid))),
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
            (KeyType::Ed25519, "16", Ok(p256_answer(&valid))),
            (KeyType::HpkeP256, "17", Ok(ed_answer(&e))),
            // The host reports another role than the one requested.
            (KeyType::Ed25519, "18", Ok(as_identity(ed_answer(&e)))),
            (
                KeyType::P256Signing,
                "19",
                Ok(as_identity(p256_answer(&valid))),
            ),
        ];
        for (key_type, key_id, public_key) in cases {
            let registry = CallbackKeyRegistry::unrecorded();
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
        let registry = CallbackKeyRegistry::unrecorded();
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
        let registry = CallbackKeyRegistry::unrecorded();
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
        let registry = CallbackKeyRegistry::unrecorded();
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
        let registry = CallbackKeyRegistry::unrecorded();
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

    /// `generate_operational` asks the host for an operational key and
    /// `generate_identity` for an Ed25519 identity, and each caches the
    /// requested role.
    #[tokio::test]
    async fn generate_operational_asks_the_host_for_operational() {
        let host = fake_host::FakeHost::default();
        let host = &host;
        let registry = CallbackKeyRegistry::unrecorded();
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
    /// derives a pseudonym that is the §9.10.4.A derivation of its seed, and
    /// once destroyed is gone on both sides.
    #[tokio::test]
    async fn fake_host_round_trip() {
        let host = fake_host::FakeHost::default();
        let host = &host;
        let registry = CallbackKeyRegistry::unrecorded();
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
        // The seed is recomputed from the handle id and pinned to the key the
        // host reports, so the derivation check below reads the host's key.
        let seed = fake_host::scalar_for(identity.id());
        assert_eq!(
            public_key(&registry, &identity, gpk)
                .await
                .unwrap()
                .as_bytes(),
            ed25519_dalek::SigningKey::from_bytes(&seed)
                .verifying_key()
                .as_bytes()
        );
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

    /// Mints an Ed25519 key in `role` on `host` through a first registry
    /// over `store`.
    async fn mint_on(
        host: &fake_host::FakeHost,
        role: KeyRole,
        store: &Arc<dyn CustodyRecordStore>,
    ) -> KeyHandle {
        let first = over(store);
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
    /// identity in a new registry over the same records, and derives a
    /// pseudonym there.
    #[tokio::test]
    async fn an_earlier_sessions_identity_derives_in_a_new_registry() {
        let host = fake_host::FakeHost::default();
        let host = &host;
        let store = store_in(9);
        let identity = mint_on(host, KeyRole::Identity, &store).await;

        let registry = over(&store);
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

    /// An operational key a host minted in an earlier session is recorded
    /// as operational, so its derive in a new registry over the same records
    /// is `NotIdentityKey` before any host call.
    #[tokio::test]
    async fn an_earlier_sessions_operational_key_cannot_derive() {
        let host = fake_host::FakeHost::default();
        let host = &host;
        let store = store_in(9);
        let operational = mint_on(host, KeyRole::Operational, &store).await;
        let lookups = host.calls("get_public_key");

        let registry = over(&store);
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
        assert_eq!(registry.get(&operational).unwrap(), None);
        assert_eq!(host.calls("derive_pseudonym"), 0);
        assert_eq!(host.calls("get_public_key"), lookups);
    }

    /// A record store whose `get` answers `record` and whose writes fail on
    /// request.
    struct FaultyStore {
        record: Option<CustodyRecord>,
        fail_put: bool,
        fail_remove: bool,
    }

    type StoreFuture<'a, T> =
        std::pin::Pin<Box<dyn Future<Output = Result<T, PlatformError>> + Send + 'a>>;

    impl CustodyRecordStore for FaultyStore {
        fn put(&self, _: KeyHandle, _: KeyType, _: KeyRole) -> StoreFuture<'_, ()> {
            let fail = self.fail_put;
            Box::pin(async move {
                if fail {
                    Err(PlatformError::StorageError("record write failed".into()))
                } else {
                    Ok(())
                }
            })
        }

        fn get(&self, _: KeyHandle) -> StoreFuture<'_, Option<CustodyRecord>> {
            let record = self.record;
            Box::pin(async move { Ok(record) })
        }

        fn remove(&self, _: KeyHandle) -> StoreFuture<'_, ()> {
            let fail = self.fail_remove;
            Box::pin(async move {
                if fail {
                    Err(PlatformError::StorageError("record remove failed".into()))
                } else {
                    Ok(())
                }
            })
        }
    }

    fn faulty(store: FaultyStore) -> CallbackKeyRegistry {
        CallbackKeyRegistry::recorded(CustodyRecords::unleased(Arc::new(store)))
    }

    const KEY_EVENT: CustodyRecord = CustodyRecord {
        key_type: KeyType::P256KeyEvent,
        role: KeyRole::Operational,
    };

    /// A registry with no record store mints no key-event key, and asks
    /// the host nothing.
    #[tokio::test]
    async fn unrecorded_registry_refuses_key_event_mint() {
        let registry = CallbackKeyRegistry::unrecorded();
        let result = generate_key_event(&registry, no_host2, no_host, no_host).await;
        assert!(
            matches!(result, Err(PlatformError::Unsupported(_))),
            "{result:?}"
        );
        assert_eq!(cached(&registry), 0);
    }

    /// `generate_operational` refuses the key-event type with no host call,
    /// in a recorded registry too: the key-event key's one mint is
    /// `generate_key_event`.
    #[tokio::test]
    async fn generate_operational_refuses_the_key_event_type() {
        let (registry, store) = seeded(&[]).await;
        let result =
            generate_operational(&registry, KeyType::P256KeyEvent, no_host2, no_host, no_host)
                .await;
        assert!(
            matches!(
                result,
                Err(PlatformError::WrongKeyType {
                    expected: KeyType::P256Signing,
                    actual: KeyType::P256KeyEvent
                })
            ),
            "{result:?}"
        );
        assert_eq!(cached(&registry), 0);
        assert_eq!(store.get(KeyHandle::new(1)).await.unwrap(), None);
    }

    /// A handle with no record is key-not-found from every entry point with
    /// no host call, in an unrecorded registry and in a recorded one whose
    /// store lacks it: the host never decides that a key exists, or its type
    /// or role.
    #[tokio::test]
    async fn unrecorded_registry_refuses_sign_of_unminted_handle() {
        let (recorded, _store) = seeded(&[(41, KeyType::Ed25519, KeyRole::Identity)]).await;
        refuses_every_entry_point_for_an_unminted_handle(&CallbackKeyRegistry::unrecorded()).await;
        refuses_every_entry_point_for_an_unminted_handle(&recorded).await;
    }

    async fn refuses_every_entry_point_for_an_unminted_handle<R: RecordSource>(
        registry: &CallbackKeyRegistry<R>,
    ) {
        let change = scp_testing::conformance::key_custody::v41_signing_change();
        let probe = CustodyProbe::fresh().unwrap();
        let h = KeyHandle::new(42);
        {
            let signed = sign(registry, &h, &[0u8; 32], no_host2, no_host).await;
            assert!(
                matches!(signed, Err(PlatformError::KeyNotFound)),
                "{signed:?}"
            );
            let public = public_key(registry, &h, no_host).await;
            assert!(
                matches!(public, Err(PlatformError::KeyNotFound)),
                "{public:?}"
            );
            let agreed = dh_agree(registry, &h, &[4u8; 65], no_host2, no_host).await;
            assert!(
                matches!(agreed, Err(PlatformError::KeyNotFound)),
                "{agreed:?}"
            );
            let derived = derive_pseudonym(registry, &h, None, no_host, no_host).await;
            assert!(
                matches!(derived, Err(PlatformError::KeyNotFound)),
                "{derived:?}"
            );
            let destroyed = destroy_key(registry, &h, no_host).await;
            assert!(
                matches!(destroyed, Err(PlatformError::KeyNotFound)),
                "{destroyed:?}"
            );
            let changed = sign_change(registry, &h, &change, no_host2, no_host).await;
            assert_eq!(changed, Err(KeyEventSignError::MemberNotFound));
            let probed = sign_probe(registry, &h, &probe, no_host2, no_host).await;
            assert!(
                matches!(probed, Err(KeyEventSignError::MemberNotFound)),
                "{probed:?}"
            );
            assert_eq!(cached(registry), 0);
        }
    }

    /// A key-event mint writes its record before it returns, so a new
    /// registry over the same records with an empty cache refuses the key's
    /// raw signing with no host call, even after the host starts reporting
    /// it as a P-256 signing key; the misreported answer disagrees with the
    /// record, so the key-event path refuses it too.
    #[tokio::test]
    async fn key_event_mint_records_before_return() {
        let host = fake_host::FakeHost::default();
        let host = &host;
        let store = store_in(3);
        let minted = over(&store);
        let gpk = |id: String| async move { host.get_public_key(&id) };
        let handle = generate_key_event(
            &minted,
            |t, r| async move { host.generate_keypair(t, r) },
            gpk,
            |id| async move { host.destroy_key(&id) },
        )
        .await
        .unwrap();
        assert_eq!(store.get(handle).await.unwrap(), Some(KEY_EVENT));
        assert_eq!(
            public_key(&minted, &handle, gpk)
                .await
                .unwrap()
                .as_bytes()
                .len(),
            33
        );
        drop(minted);

        host.report_as(&handle.id().to_string(), KeyType::P256Signing)
            .unwrap();
        let rebuilt = over(&store);
        let (signs, lookups) = (host.calls("sign"), host.calls("get_public_key"));
        let refused = sign(
            &rebuilt,
            &handle,
            &[0x5a; 32],
            |id, data| async move { host.sign(&id, &data) },
            gpk,
        )
        .await;
        assert!(
            matches!(
                refused,
                Err(PlatformError::WrongKeyType {
                    expected: KeyType::P256Signing,
                    actual: KeyType::P256KeyEvent
                })
            ),
            "{refused:?}"
        );
        assert_eq!(
            (host.calls("sign"), host.calls("get_public_key")),
            (signs, lookups)
        );

        let change = scp_testing::conformance::key_custody::v41_signing_change();
        let disagreeing = sign_change(
            &rebuilt,
            &handle,
            &change,
            |id, data| async move { host.sign(&id, &data) },
            gpk,
        )
        .await;
        assert!(
            matches!(disagreeing, Err(KeyEventSignError::Substrate(_))),
            "{disagreeing:?}"
        );
        assert_eq!(host.calls("sign"), signs);
        assert_eq!(cached(&rebuilt), 0);
    }

    /// A key whose record write fails is destroyed on the host and not
    /// cached, so no unrecorded key stays usable or held.
    #[tokio::test]
    async fn a_failed_record_write_destroys_the_minted_key() {
        let host = fake_host::FakeHost::default();
        let host = &host;
        let registry = faulty(FaultyStore {
            record: None,
            fail_put: true,
            fail_remove: false,
        });
        let result = generate_key_event(
            &registry,
            |t, r| async move { host.generate_keypair(t, r) },
            |id: String| async move { host.get_public_key(&id) },
            |id| async move { host.destroy_key(&id) },
        )
        .await;
        assert!(
            matches!(result, Err(PlatformError::StorageError(_))),
            "{result:?}"
        );
        assert_eq!(host.calls("destroy_key"), 1);
        assert!(!host.holds("1"));
        assert_eq!(cached(&registry), 0);
    }

    /// A host answer whose type or role differs from the custody record is
    /// refused and binds nothing; an agreeing answer binds in the recorded
    /// role.
    #[tokio::test]
    async fn resolve_refuses_host_answer_disagreeing_with_record() {
        let k = p256(0x95);
        let e = ed(0x96);
        let (registry, _store) = seeded(&[
            (5, KeyType::P256KeyEvent, KeyRole::Operational),
            (6, KeyType::Ed25519, KeyRole::Identity),
            (7, KeyType::HpkeP256, KeyRole::Operational),
        ])
        .await;
        for (id, a) in [
            (5, p256_answer(&k)),
            (6, ed_answer(&e)),
            (7, as_identity(hpke_answer(&k))),
        ] {
            let calls = AtomicUsize::new(0);
            let h = KeyHandle::new(id);
            let result = public_key(&registry, &h, lookup(&a, &calls)).await;
            assert!(
                matches!(&result, Err(PlatformError::CustodyError(m)) if m.contains("custody record")),
                "{id}: {result:?}"
            );
            assert_eq!(calls.load(Ordering::Relaxed), 1, "{id}");
            assert_eq!(registry.get(&h).unwrap(), None, "{id}");
        }
        let calls = AtomicUsize::new(0);
        let h = KeyHandle::new(6);
        public_key(&registry, &h, lookup(&as_identity(ed_answer(&e)), &calls))
            .await
            .unwrap();
        assert_eq!(registry.get(&h).unwrap().unwrap().role, KeyRole::Identity);
    }

    /// A key-event record refuses `sign`, `dh_agree` and both derivations
    /// before any host call (spec 09 §9.7.4.2 R10).
    #[tokio::test]
    async fn sign_refuses_key_event_record_without_host_call() {
        let (registry, _store) = seeded(&[(5, KeyType::P256KeyEvent, KeyRole::Operational)]).await;
        let h = KeyHandle::new(5);
        let signed = sign(&registry, &h, &[0u8; 32], no_host2, no_host).await;
        assert!(
            matches!(
                signed,
                Err(PlatformError::WrongKeyType {
                    expected: KeyType::P256Signing,
                    actual: KeyType::P256KeyEvent
                })
            ),
            "{signed:?}"
        );
        let agreed = dh_agree(&registry, &h, &[4u8; 65], no_host2, no_host).await;
        assert!(
            matches!(
                agreed,
                Err(PlatformError::WrongKeyType {
                    expected: KeyType::HpkeP256,
                    actual: KeyType::P256KeyEvent
                })
            ),
            "{agreed:?}"
        );
        for epoch in [None, Some(3)] {
            let derived = derive_pseudonym(&registry, &h, epoch, no_host, no_host).await;
            assert!(
                matches!(derived, Err(PlatformError::NotIdentityKey)),
                "{derived:?}"
            );
        }
        assert_eq!(cached(&registry), 0);
    }

    /// Only a key-event record signs a change or a probe; every other
    /// record is refused with no host call.
    #[tokio::test]
    async fn key_event_signing_refuses_other_records_without_host_call() {
        let (registry, _store) = seeded(&[
            (5, KeyType::P256Signing, KeyRole::Operational),
            (6, KeyType::Ed25519, KeyRole::Identity),
            (7, KeyType::HpkeP256, KeyRole::Operational),
        ])
        .await;
        let change = scp_testing::conformance::key_custody::v41_signing_change();
        let probe = CustodyProbe::fresh().unwrap();
        for id in [5, 6, 7] {
            let h = KeyHandle::new(id);
            let changed = sign_change(&registry, &h, &change, no_host2, no_host).await;
            assert_eq!(changed, Err(KeyEventSignError::WrongKeyType), "{id}");
            let probed = sign_probe(&registry, &h, &probe, no_host2, no_host).await;
            assert!(
                matches!(probed, Err(KeyEventSignError::WrongKeyType)),
                "{id}: {probed:?}"
            );
        }
        assert_eq!(cached(&registry), 0);
    }

    /// `sign_change` hands the host exactly the change digest and
    /// `sign_probe` exactly the probe's raw digest; each host DER high-`s`
    /// answer comes back as a raw low-`s` signature that verifies under the
    /// key, and a host signature that does not verify is refused.
    #[tokio::test]
    async fn key_event_signing_hands_the_host_the_digest() {
        let host = fake_host::FakeHost::default();
        let host = &host;
        let (registry, _store) = seeded(&[]).await;
        let gpk = |id: String| async move { host.get_public_key(&id) };
        let handle = generate_key_event(
            &registry,
            |t, r| async move { host.generate_keypair(t, r) },
            gpk,
            |id| async move { host.destroy_key(&id) },
        )
        .await
        .unwrap();
        let key: [u8; 33] = public_key(&registry, &handle, gpk)
            .await
            .unwrap()
            .as_bytes()
            .try_into()
            .unwrap();
        let point = scp_crypto::p256::P256PublicKey::from_sec1(&key).unwrap();
        let seen = std::sync::Mutex::new(Vec::new());
        let seen = &seen;
        let recording = |id: String, data: Vec<u8>| {
            seen.lock().unwrap().push(data.clone());
            async move { host.sign(&id, &data) }
        };

        let change = scp_testing::conformance::key_custody::v41_signing_change();
        let IndexedSignature::Raw { signature } =
            sign_change(&registry, &handle, &change, recording, gpk)
                .await
                .unwrap()
        else {
            panic!("a callback custody signs the raw form");
        };
        scp_crypto::p256::verify_prehash_strict(&point, &change.digest(), &signature).unwrap();
        let probe = CustodyProbe::fresh().unwrap();
        sign_probe(&registry, &handle, &probe, recording, gpk)
            .await
            .unwrap()
            .verify(&probe, &key)
            .unwrap();
        assert_eq!(
            *seen.lock().unwrap(),
            vec![change.digest().to_vec(), probe.raw_digest().to_vec()]
        );
        let host_sig = host
            .sign(&handle.id().to_string(), &change.digest())
            .unwrap();
        assert_ne!(host_sig.as_slice(), signature.as_slice());

        let junk = sign_change(
            &registry,
            &handle,
            &change,
            |_, _| async { Ok(vec![0x11u8; 64]) },
            gpk,
        )
        .await;
        assert!(
            matches!(junk, Err(KeyEventSignError::Substrate(_))),
            "{junk:?}"
        );
    }

    /// Two providers that hand out the same key id keep separate records
    /// in one storage: destroying one provider's key leaves the other's
    /// record.
    #[tokio::test]
    async fn providers_with_one_key_id_keep_separate_records() {
        let storage = Arc::new(scp_platform::in_memory::InMemoryStorage::new());
        let table = CustodyNamespaces::new();
        let a = CallbackKeyRegistry::recorded(
            CustodyRecords::create(&table, Arc::clone(&storage)).unwrap(),
        );
        let b = CallbackKeyRegistry::recorded(
            CustodyRecords::create(&table, Arc::clone(&storage)).unwrap(),
        );
        let h = KeyHandle::new(5);
        a.store()
            .unwrap()
            .put(h, KeyType::P256KeyEvent, KeyRole::Operational)
            .await
            .unwrap();
        b.store()
            .unwrap()
            .put(h, KeyType::Ed25519, KeyRole::Identity)
            .await
            .unwrap();
        destroy_key(&b, &h, |_| async { Ok(()) }).await.unwrap();
        assert_eq!(record_of(&b, &h).await.unwrap(), None);
        assert_eq!(record_of(&a, &h).await.unwrap(), Some(KEY_EVENT));
    }

    /// A destroy the host reports as key-not-found drops the record, as a
    /// confirmed destroy does; a failed host destroy keeps it; a recorded
    /// key that is gone is key-not-found with no host call.
    #[tokio::test]
    async fn host_absent_destroy_drops_the_record() {
        let (registry, store) = seeded(&[
            (5, KeyType::Ed25519, KeyRole::Operational),
            (6, KeyType::P256KeyEvent, KeyRole::Operational),
            (7, KeyType::Ed25519, KeyRole::Operational),
        ])
        .await;
        let failed = destroy_key(&registry, &KeyHandle::new(5), |_| async {
            Err(PlatformError::CustodyError("host destroy failed".into()))
        })
        .await;
        assert!(matches!(failed, Err(PlatformError::CustodyError(_))));
        assert!(store.get(KeyHandle::new(5)).await.unwrap().is_some());

        let absent = destroy_key(&registry, &KeyHandle::new(5), |_| async {
            Err(PlatformError::KeyNotFound)
        })
        .await;
        assert!(matches!(absent, Err(PlatformError::KeyNotFound)));
        assert_eq!(store.get(KeyHandle::new(5)).await.unwrap(), None);

        destroy_key(&registry, &KeyHandle::new(6), |_| async { Ok(()) })
            .await
            .unwrap();
        assert_eq!(store.get(KeyHandle::new(6)).await.unwrap(), None);
        let again = destroy_key(&registry, &KeyHandle::new(6), no_host).await;
        assert!(matches!(again, Err(PlatformError::KeyNotFound)));
        assert!(store.get(KeyHandle::new(7)).await.unwrap().is_some());
    }

    /// A record the store fails to remove after the host's destroy is
    /// reported, whether the host confirmed the destroy or reported the key
    /// absent.
    #[tokio::test]
    async fn a_failed_record_removal_is_reported() {
        for host_answer in [Ok(()), Err(PlatformError::KeyNotFound)] {
            let registry = faulty(FaultyStore {
                record: Some(KEY_EVENT),
                fail_put: false,
                fail_remove: true,
            });
            let result = destroy_key(
                &registry,
                &KeyHandle::new(5),
                |_| async move { host_answer },
            )
            .await;
            assert!(
                matches!(&result, Err(PlatformError::CustodyError(m)) if m.contains("not removed")),
                "{result:?}"
            );
        }
    }

    /// One instance's table refuses a second live adapter for one namespace
    /// while the first lives, and opens it again, over the same records, once
    /// the first drops.
    #[tokio::test]
    async fn a_second_live_adapter_for_one_namespace_is_refused() {
        let storage = Arc::new(scp_platform::in_memory::InMemoryStorage::new());
        let table = CustodyNamespaces::new();
        let h = KeyHandle::new(3);
        let first = CallbackKeyRegistry::recorded(
            CustodyRecords::create(&table, Arc::clone(&storage)).expect("the first open"),
        );
        let namespace = first.records.namespace();
        first
            .store()
            .unwrap()
            .put(h, KeyType::P256KeyEvent, KeyRole::Operational)
            .await
            .unwrap();

        let second = CustodyRecords::open(
            &table.clone(),
            Arc::clone(&storage),
            CustodyNamespace::from_bytes(namespace),
        );
        assert!(
            matches!(second, Err(CustodyLoadError::NamespaceLive)),
            "{second:?}"
        );
        assert!(matches!(
            PlatformError::from(CustodyLoadError::NamespaceLive),
            PlatformError::CustodyError(_)
        ));

        drop(first);
        let third = CallbackKeyRegistry::recorded(
            CustodyRecords::open(
                &table,
                Arc::clone(&storage),
                CustodyNamespace::from_bytes(namespace),
            )
            .expect("the namespace is free again"),
        );
        assert_eq!(record_of(&third, &h).await.unwrap(), Some(KEY_EVENT));
    }

    /// A reopen closes the fixture's adapter only when no call holds it; a
    /// held adapter stays in the slot, and the namespace it holds stays
    /// live until the holder drops, after which the close succeeds and the
    /// namespace opens again. An empty slot is `Closed`.
    #[tokio::test]
    async fn close_for_reopen_waits_for_the_last_holder() {
        let storage = Arc::new(scp_platform::in_memory::InMemoryStorage::new());
        let (table, records) = CustodyRecords::open_alone(Arc::clone(&storage), [0x7e; 16]);
        let mut slot = Some(Arc::new(CallbackKeyRegistry::recorded(records)));
        let in_flight = slot.as_ref().map(Arc::clone);

        assert_eq!(close_for_reopen(&mut slot), Err(ReopenRefusal::InFlight));
        assert!(slot.is_some(), "a refused close leaves the adapter open");
        assert!(matches!(
            CustodyRecords::reopen(&table, Arc::clone(&storage), [0x7e; 16]),
            Err(CustodyLoadError::NamespaceLive)
        ));

        drop(in_flight);
        assert_eq!(close_for_reopen(&mut slot), Ok(()));
        assert!(slot.is_none());
        CustodyRecords::reopen(&table, Arc::clone(&storage), [0x7e; 16])
            .expect("the namespace is free once the adapter dropped");
        assert_eq!(close_for_reopen(&mut slot), Err(ReopenRefusal::Closed));
        assert!(ReopenRefusal::InFlight.to_string().contains("in flight"));
    }

    /// The fake host meets the host contract's key-id rule, and the check
    /// fails a host that hands out a destroyed key's id again.
    #[tokio::test]
    async fn fake_host_never_reuses_key_ids() {
        let host = fake_host::FakeHost::default();
        let host = &host;
        check_host_never_reuses_key_ids(
            3,
            |t, r| async move { host.generate_keypair(t, r) },
            |id: String| async move { host.destroy_key(&id) },
        )
        .await
        .unwrap();

        let next = std::sync::Mutex::new(0u64);
        let recycling = check_host_never_reuses_key_ids(
            2,
            |_, _| {
                let id = {
                    let mut n = next.lock().unwrap();
                    *n = (*n % 3) + 1;
                    *n
                };
                async move { Ok(id.to_string()) }
            },
            |_: String| async { Ok(()) },
        )
        .await;
        assert!(
            recycling.as_ref().is_err_and(|e| e.contains("again")),
            "{recycling:?}"
        );
    }
}
