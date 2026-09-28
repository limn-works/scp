//! Shared key registry, host-answer validation and adapter flows for the
//! callback-custody bridges.
//!
//! The `PyO3`, napi-rs, and `UniFFI` bridges adapt a host `KeyCustodyProvider`
//! to [`KeyCustody`](scp_platform::KeyCustody). The host speaks in key-type
//! strings and raw bytes, so this module holds every rule for trusting what
//! it returns, once, and the three bridges only supply one closure per host
//! call:
//!
//! - The host's `get_public_key` answers with a structured
//!   [`HostPublicKey`]: the key's type as a protocol string and its public
//!   key. [`registered_key`] requires a known type and the exact length for
//!   it (Ed25519 32, X25519 32, P-256 signing 33, HPKE P-256 65) and a valid
//!   key. The bridge never infers a type from a length.
//! - [`CallbackKeyRegistry`] holds one slot per handle: `Live` (the key, its
//!   public key and its [`KeyRole`]), `Destroying` while a host destroy is in
//!   flight, `Abandoned` when the caller dropped that destroy before the host
//!   answered, and `Destroyed`, a tombstone. A handle this adapter has not seen
//!   (a host key from an earlier session) is resolved through
//!   `get_public_key` the same way in every entry point, and binds in the role
//!   the host's answer states: [`KeyRole::Identity`] when the host reports
//!   `"identity"`, [`KeyRole::Operational`] when it reports `"operational"`.
//! - A host key minted by a `generate_keypair` future the caller dropped
//!   before the handle was registered is queued, and the next generation
//!   destroys it on the host first ([`sweep_orphans`]). The queue lives in
//!   this registry, so a process that exits before its next generation
//!   leaves the queued key on the host.
//! - Every host signature is verified: an Ed25519 signature strictly over the
//!   data under the registered verifying key, a P-256 signature through
//!   [`p256_host_signature`].
//! - Pseudonym derivation requires an [`KeyRole::Identity`] source, and binds
//!   the result as a [`KeyRole::Pseudonym`] tied to its source, context and
//!   epoch.
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
    KeyHandle, KeyType, PseudonymKeypair, PublicKey, SharedSecret, Signature,
};

/// The host-protocol string for a key type: the argument of the provider's
/// `generate_keypair` and the `key_type` of its `get_public_key` answer.
#[must_use]
pub const fn key_type_str(key_type: KeyType) -> &'static str {
    match key_type {
        KeyType::Ed25519 => "ed25519",
        KeyType::X25519 => "x25519",
        KeyType::P256Signing => "p256",
        KeyType::HpkeP256 => "hpke-p256",
    }
}

/// The key type a host-protocol string names, or `None` for any other string.
#[must_use]
pub fn parse_key_type(key_type: &str) -> Option<KeyType> {
    match key_type {
        "ed25519" => Some(KeyType::Ed25519),
        "x25519" => Some(KeyType::X25519),
        "p256" => Some(KeyType::P256Signing),
        "hpke-p256" => Some(KeyType::HpkeP256),
        _ => None,
    }
}

/// The role a host records for a key it minted: the second argument of the
/// provider's `generate_keypair` and the `role` of its `get_public_key`
/// answer.
///
/// The host records the role `generate_keypair` named and reports it for
/// the key's lifetime, across adapter instances, so a new adapter resolves
/// an identity key from an earlier session as an identity. A pseudonym key a
/// derivation minted is `"operational"`. Rust cannot check the host's word:
/// a host that reports `"identity"` for a key it minted as operational lets
/// that key derive pseudonyms, and that is outside the bridge's control.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostRole {
    /// `"identity"`: minted by `generate_identity_keypair`, the only role a
    /// pseudonym may be derived from.
    Identity,
    /// `"operational"`: every other key, pseudonym keys included.
    Operational,
}

impl HostRole {
    /// The host-protocol string for this role.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Identity => "identity",
            Self::Operational => "operational",
        }
    }

    /// The role a host-protocol string names, or `None` for any other string.
    #[must_use]
    pub fn parse(role: &str) -> Option<Self> {
        match role {
            "identity" => Some(Self::Identity),
            "operational" => Some(Self::Operational),
            _ => None,
        }
    }

    /// The host role a registry role is minted or reported as: `Identity`
    /// for [`KeyRole::Identity`], `Operational` for every other role.
    #[must_use]
    pub const fn of(role: &KeyRole) -> Self {
        match role {
            KeyRole::Identity => Self::Identity,
            KeyRole::Pseudonym { .. } | KeyRole::Operational => Self::Operational,
        }
    }
}

/// A host's `get_public_key` answer: the key's type, as the protocol string
/// [`key_type_str`] names, its public key, and the role the host recorded
/// when it minted the key ([`HostRole`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostPublicKey {
    /// `"ed25519"`, `"x25519"`, `"p256"` or `"hpke-p256"`.
    pub key_type: String,
    /// The public key: 32 bytes (Ed25519, X25519), the 33-byte compressed
    /// SEC1 point (`"p256"`), or the 65-byte uncompressed SEC1 point
    /// (`"hpke-p256"`).
    pub public_key: Vec<u8>,
    /// `"identity"` or `"operational"` ([`HostRole`]).
    pub role: String,
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

/// What a key is for, which decides what may be derived from it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyRole {
    /// An identity key (`#0`), minted by `generate_identity_keypair` or
    /// resolved from a host that reports `"identity"`: the only role a
    /// pseudonym may be derived from.
    Identity,
    /// A pseudonym derived from identity key `source` for `context_id` at
    /// `epoch` (`None` for the v1 derivation).
    Pseudonym {
        /// The id of the identity key it was derived from.
        source: u64,
        /// The context it is scoped to.
        context_id: Vec<u8>,
        /// The rotation epoch, `None` for the v1 derivation.
        epoch: Option<u64>,
    },
    /// Any other key: minted by `generate_keypair`, or a host key resolved
    /// through `get_public_key` whose host role is `"operational"`.
    Operational,
}

/// How an entry reached the registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Origin {
    /// Minted by this adapter (`generate_keypair`).
    Minted,
    /// Resolved from the host's `get_public_key`.
    Resolved,
    /// Bound by a pseudonym derivation.
    Derived,
}

/// A live registry entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisteredEntry {
    /// The key and its public key.
    pub key: RegisteredKey,
    /// What it is for.
    pub role: KeyRole,
    origin: Origin,
}

impl RegisteredEntry {
    /// An entry for a key this adapter minted.
    #[must_use]
    pub const fn minted(key: RegisteredKey, role: KeyRole) -> Self {
        Self {
            key,
            role,
            origin: Origin::Minted,
        }
    }
}

/// One handle's state.
#[derive(Debug, Clone)]
enum Slot {
    Live(RegisteredEntry),
    /// A host destroy is in flight. `prior` is the entry to restore if it
    /// fails (`None` when the handle was unknown); `token` names the destroy
    /// that owns the slot; `abandoned` is set when the destroy retries an
    /// `Abandoned` slot, which a failure returns to `Abandoned`.
    Destroying {
        prior: Option<RegisteredEntry>,
        token: u64,
        abandoned: bool,
    },
    /// The caller dropped a destroy before the host answered, so the host
    /// may or may not hold the key. Every lookup fails as for `Destroyed`,
    /// and a pseudonym of an abandoned identity is retired; a new
    /// `destroy_key` retries the host destroy.
    Abandoned {
        prior: Option<RegisteredEntry>,
    },
    /// Destroyed in this session.
    Destroyed,
}

impl Slot {
    /// Whether this slot held an identity when a destroy, in flight or
    /// abandoned, began.
    fn identity_mid_destroy(&self) -> bool {
        matches!(
            self,
            Self::Destroying { prior: Some(e), .. } | Self::Abandoned { prior: Some(e) }
                if e.role == KeyRole::Identity
        )
    }
}

#[derive(Debug, Default)]
struct Slots {
    map: HashMap<u64, Slot>,
    next_token: u64,
    /// Host key ids minted by a generation whose future was dropped, or
    /// whose rejection destroy failed, before the key was registered or
    /// destroyed. [`sweep_orphans`] destroys them.
    orphans: Vec<String>,
}

/// Handle → slot for the handles one adapter instance has seen.
///
/// Every destroyed id stays as a tombstone for the adapter's lifetime, so
/// the map grows with the number of keys destroyed in a session: one small
/// entry per destroy the caller asked for, never per host input.
#[derive(Debug, Default)]
pub struct CallbackKeyRegistry {
    slots: Mutex<Slots>,
}

impl CallbackKeyRegistry {
    /// An empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, Slots>, PlatformError> {
        self.slots.lock().map_err(|_| {
            PlatformError::CustodyError("callback custody key registry lock poisoned".into())
        })
    }

    /// Records a key `generate_keypair` minted. It may replace a
    /// `Destroying`, `Abandoned` or `Destroyed` slot, because a host may hand
    /// a freed id to a new key; the destroy in flight then leaves the new
    /// entry alone. When the replaced slot is an identity mid-destroy, its
    /// pseudonyms are retired first (§9.15), because the destroy that would
    /// retire them no longer owns the slot and the new key must own none of
    /// them.
    ///
    /// # Errors
    ///
    /// [`PlatformError::CustodyError`] if the id is live, or the registry
    /// lock is poisoned.
    pub fn register(&self, handle: KeyHandle, entry: RegisteredEntry) -> Result<(), PlatformError> {
        let mut slots = self.lock()?;
        if matches!(slots.map.get(&handle.id()), Some(Slot::Live(_))) {
            return Err(PlatformError::CustodyError(format!(
                "KeyCustodyProvider.generate_keypair returned key_id {} that is already live",
                handle.id()
            )));
        }
        if slots
            .map
            .get(&handle.id())
            .is_some_and(Slot::identity_mid_destroy)
        {
            retire_pseudonyms_of(&mut slots.map, handle.id());
        }
        slots.map.insert(handle.id(), Slot::Live(entry));
        drop(slots);
        Ok(())
    }

    /// Binds a host key resolved through `get_public_key` in the role the
    /// host reported: [`KeyRole::Identity`] for [`HostRole::Identity`],
    /// [`KeyRole::Operational`] otherwise. Resolution is a lookup a host may
    /// answer twice (two concurrent resolutions), so an id already live with
    /// the same key returns the existing entry, role and all.
    ///
    /// # Errors
    ///
    /// [`PlatformError::KeyNotFound`] if the id is being or was destroyed;
    /// [`PlatformError::CustodyError`] if it is live with another key, or the
    /// registry lock is poisoned.
    pub fn bind_resolved(
        &self,
        handle: KeyHandle,
        key: RegisteredKey,
        role: HostRole,
    ) -> Result<RegisteredEntry, PlatformError> {
        let mut slots = self.lock()?;
        let bound = match slots.map.get(&handle.id()) {
            Some(Slot::Live(existing)) if existing.key == key => Ok(existing.clone()),
            Some(Slot::Live(_)) => Err(PlatformError::CustodyError(format!(
                "KeyCustodyProvider.get_public_key: key_id {} is already bound to another key",
                handle.id()
            ))),
            Some(Slot::Destroying { .. } | Slot::Abandoned { .. } | Slot::Destroyed) => {
                Err(PlatformError::KeyNotFound)
            }
            None => {
                let entry = RegisteredEntry {
                    key,
                    role: match role {
                        HostRole::Identity => KeyRole::Identity,
                        HostRole::Operational => KeyRole::Operational,
                    },
                    origin: Origin::Resolved,
                };
                slots.map.insert(handle.id(), Slot::Live(entry.clone()));
                Ok(entry)
            }
        };
        drop(slots);
        bound
    }

    /// Binds a derived pseudonym. A repeat derivation may return the same id,
    /// so an id already bound to the same key for the same `role` (source,
    /// context and epoch) is accepted; so is an id this adapter resolved as
    /// an operational key with the same public key, which the derivation now
    /// identifies, and a `Destroyed` id, which the host has handed to the
    /// new pseudonym (as [`Self::register`] accepts for a minted key). Any
    /// other occupant is rejected: a minted key, an identity, another key, or
    /// the same key for another source, context or epoch.
    ///
    /// The source slot must still be a live identity holding `source_key`,
    /// the key the derive resolved, under the same lock: a derive whose host
    /// call raced the identity's destroy binds nothing, and neither does one
    /// whose source id the host meanwhile handed to another identity key.
    ///
    /// # Errors
    ///
    /// [`PlatformError::KeyNotFound`] if the id is being destroyed, or the
    /// source is not a live identity holding `source_key`;
    /// [`PlatformError::PseudonymRejected`] for any rejected occupant;
    /// [`PlatformError::CustodyError`] for a poisoned registry lock.
    pub fn bind_pseudonym(
        &self,
        method: &str,
        handle: KeyHandle,
        key: RegisteredKey,
        role: KeyRole,
        source_key: &RegisteredKey,
    ) -> Result<(), PlatformError> {
        let mut slots = self.lock()?;
        if let KeyRole::Pseudonym { source, .. } = &role {
            match slots.map.get(source) {
                Some(Slot::Live(identity))
                    if identity.role == KeyRole::Identity && identity.key == *source_key => {}
                _ => return Err(PlatformError::KeyNotFound),
            }
        }
        match slots.map.get(&handle.id()) {
            Some(Slot::Live(existing)) if existing.key == key && existing.role == role => {
                return Ok(());
            }
            // A host key resolved earlier as operational, now identified.
            Some(Slot::Live(existing))
                if existing.key == key
                    && existing.origin == Origin::Resolved
                    && existing.role == KeyRole::Operational => {}
            Some(Slot::Live(_)) => {
                return Err(PlatformError::PseudonymRejected(format!(
                    "KeyCustodyProvider.{method}: key_id {} is already bound to another key \
                     or derivation",
                    handle.id()
                )));
            }
            Some(Slot::Destroying { .. }) => return Err(PlatformError::KeyNotFound),
            Some(Slot::Abandoned { .. } | Slot::Destroyed) | None => {}
        }
        slots.map.insert(
            handle.id(),
            Slot::Live(RegisteredEntry {
                key,
                role,
                origin: Origin::Derived,
            }),
        );
        drop(slots);
        Ok(())
    }

    /// The live entry for a handle, or `None` if this adapter has not seen it.
    ///
    /// # Errors
    ///
    /// [`PlatformError::KeyNotFound`] if the handle is being or was destroyed,
    /// or its destroy was abandoned; [`PlatformError::CustodyError`] if the
    /// registry lock is poisoned.
    pub fn get(&self, handle: &KeyHandle) -> Result<Option<RegisteredEntry>, PlatformError> {
        match self.lock()?.map.get(&handle.id()) {
            Some(Slot::Live(entry)) => Ok(Some(entry.clone())),
            Some(Slot::Destroying { .. } | Slot::Abandoned { .. } | Slot::Destroyed) => {
                Err(PlatformError::KeyNotFound)
            }
            None => Ok(None),
        }
    }

    /// Whether `handle` is live: bound, and neither being nor destroyed. A
    /// test host's `destroy_key` reads it to prove an adapter retires the
    /// handle before the host call.
    #[cfg(any(test, feature = "testing"))]
    #[must_use]
    pub fn is_live(&self, handle: &KeyHandle) -> bool {
        self.lock()
            .is_ok_and(|slots| matches!(slots.map.get(&handle.id()), Some(Slot::Live(_))))
    }

    /// Marks a handle `Destroying` before the host destroy, known or not, so
    /// no lookup can resolve it while the host call is in flight. An
    /// `Abandoned` slot is accepted like a live one, so a cancelled destroy
    /// can be retried. Returns the token [`Self::end_destroy`] takes.
    ///
    /// # Errors
    ///
    /// [`PlatformError::KeyNotFound`] if the handle is already being or was
    /// destroyed; [`PlatformError::CustodyError`] if the lock is poisoned.
    pub fn begin_destroy(&self, handle: &KeyHandle) -> Result<u64, PlatformError> {
        let mut slots = self.lock()?;
        let (prior, abandoned) = match slots.map.get(&handle.id()) {
            Some(Slot::Live(entry)) => (Some(entry.clone()), false),
            Some(Slot::Abandoned { prior }) => (prior.clone(), true),
            Some(Slot::Destroying { .. } | Slot::Destroyed) => {
                return Err(PlatformError::KeyNotFound);
            }
            None => (None, false),
        };
        slots.next_token += 1;
        let token = slots.next_token;
        slots.map.insert(
            handle.id(),
            Slot::Destroying {
                prior,
                token,
                abandoned,
            },
        );
        drop(slots);
        Ok(token)
    }

    /// Ends the destroy `token` began: the slot becomes `Destroyed` when the
    /// host destroyed the key, and otherwise returns to its prior entry (or
    /// is removed when the handle was unknown). A retry of an `Abandoned`
    /// destroy that fails returns to `Abandoned`, because the cancelled host
    /// call may have destroyed the key. A slot a generation took over in the
    /// meantime is left alone.
    ///
    /// Destroying an [`KeyRole::Identity`] key destroys every pseudonym
    /// derived from it (§9.15): in the same critical section, each slot whose
    /// entry, live or mid-destroy, is a [`KeyRole::Pseudonym`] of that
    /// identity becomes `Destroyed`, and a destroy in flight on one of them
    /// then finds its slot taken over and leaves it alone.
    ///
    /// # Errors
    ///
    /// [`PlatformError::CustodyError`] if the registry lock is poisoned.
    pub fn end_destroy(
        &self,
        handle: &KeyHandle,
        token: u64,
        destroyed: bool,
    ) -> Result<(), PlatformError> {
        let mut slots = self.lock()?;
        let Some(Slot::Destroying {
            prior,
            token: owner,
            abandoned,
        }) = slots.map.get(&handle.id())
        else {
            return Ok(());
        };
        if *owner != token {
            return Ok(());
        }
        match (destroyed, prior.clone(), *abandoned) {
            (true, prior, _) => {
                slots.map.insert(handle.id(), Slot::Destroyed);
                if prior.is_some_and(|entry| entry.role == KeyRole::Identity) {
                    retire_pseudonyms_of(&mut slots.map, handle.id());
                }
            }
            (false, prior, true) => {
                slots.map.insert(handle.id(), Slot::Abandoned { prior });
            }
            (false, Some(entry), false) => {
                slots.map.insert(handle.id(), Slot::Live(entry));
            }
            (false, None, false) => {
                slots.map.remove(&handle.id());
            }
        }
        drop(slots);
        Ok(())
    }

    /// Records that the destroy `token` began was dropped before the host
    /// answered: the slot becomes `Abandoned`, and an identity's pseudonyms
    /// are retired (§9.15), since the host may already have destroyed it. A
    /// slot a generation took over in the meantime is left alone.
    ///
    /// # Errors
    ///
    /// [`PlatformError::CustodyError`] if the registry lock is poisoned; the
    /// slot then stays `Destroying`, which every lookup refuses.
    fn abandon_destroy(&self, handle: KeyHandle, token: u64) -> Result<(), PlatformError> {
        let mut slots = self.lock()?;
        let prior = match slots.map.get(&handle.id()) {
            Some(Slot::Destroying {
                prior,
                token: owner,
                ..
            }) if *owner == token => prior.clone(),
            _ => return Ok(()),
        };
        let identity = prior
            .as_ref()
            .is_some_and(|entry| entry.role == KeyRole::Identity);
        slots.map.insert(handle.id(), Slot::Abandoned { prior });
        if identity {
            retire_pseudonyms_of(&mut slots.map, handle.id());
        }
        drop(slots);
        Ok(())
    }

    /// Queues host key `key_id` for [`sweep_orphans`] to destroy.
    ///
    /// It cannot fail, because [`OrphanGuard`] calls it from `Drop`, which has
    /// no caller to report to. A poisoned lock still guards a well-formed
    /// queue: pushing an id breaks no invariant of the slot map, and every
    /// other registry call still fails closed on the poison.
    fn queue_orphan(&self, key_id: String) {
        self.slots
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .orphans
            .push(key_id);
    }

    /// Takes one queued orphan host key id.
    fn pop_orphan(&self) -> Result<Option<String>, PlatformError> {
        Ok(self.lock()?.orphans.pop())
    }

    /// The host key ids queued for [`sweep_orphans`].
    #[cfg(any(test, feature = "testing"))]
    #[must_use]
    pub fn orphans(&self) -> Vec<String> {
        self.lock()
            .map_or_else(|_| Vec::new(), |slots| slots.orphans.clone())
    }
}

/// Queues a host key id for [`sweep_orphans`] when dropped armed: the key
/// was minted, or its sweep began, and the key is neither registered nor
/// destroyed on the host.
struct OrphanGuard<'a> {
    registry: &'a CallbackKeyRegistry,
    key_id: Option<String>,
}

impl OrphanGuard<'_> {
    /// The key is registered or destroyed: nothing to queue.
    fn disarm(&mut self) {
        self.key_id = None;
    }
}

impl Drop for OrphanGuard<'_> {
    fn drop(&mut self) {
        if let Some(key_id) = self.key_id.take() {
            self.registry.queue_orphan(key_id);
        }
    }
}

/// Moves a destroy's slot to `Abandoned` when the `destroy_key` future is
/// dropped between `begin_destroy` and `end_destroy`.
struct DestroyGuard<'a> {
    registry: &'a CallbackKeyRegistry,
    handle: KeyHandle,
    token: u64,
    armed: bool,
}

impl Drop for DestroyGuard<'_> {
    fn drop(&mut self) {
        if self.armed {
            // `Drop` has no caller to return an error to. The only error is a
            // poisoned lock, which leaves the slot `Destroying` and makes
            // every registry call fail, so nothing resolves the handle or its
            // pseudonyms either way.
            let _ = self.registry.abandon_destroy(self.handle, self.token);
        }
    }
}

/// Marks `Destroyed` every slot whose entry (live, or the prior of a destroy
/// in flight or abandoned) is a pseudonym derived from identity `source`.
fn retire_pseudonyms_of(map: &mut HashMap<u64, Slot>, source: u64) {
    let derived_from = |entry: &RegisteredEntry| matches!(&entry.role, KeyRole::Pseudonym { source: s, .. } if *s == source);
    for slot in map.values_mut() {
        let owned = match slot {
            Slot::Live(entry)
            | Slot::Destroying {
                prior: Some(entry), ..
            }
            | Slot::Abandoned { prior: Some(entry) } => derived_from(entry),
            Slot::Destroying { prior: None, .. }
            | Slot::Abandoned { prior: None }
            | Slot::Destroyed => false,
        };
        if owned {
            *slot = Slot::Destroyed;
        }
    }
}

/// The role a host's `get_public_key` answer states.
///
/// # Errors
///
/// [`PlatformError::CustodyError`] for a role string other than
/// `"identity"` or `"operational"`.
pub fn host_role(method: &str, answer: &HostPublicKey) -> Result<HostRole, PlatformError> {
    HostRole::parse(&answer.role).ok_or_else(|| {
        PlatformError::CustodyError(format!(
            "KeyCustodyProvider.{method} returned unknown key role {:?}",
            answer.role
        ))
    })
}

/// Validates a host's structured `get_public_key` answer.
///
/// The stated `role` must be a [`HostRole`] string, the stated `key_type` a
/// protocol string, and the public key must have exactly that type's length
/// (Ed25519 32, X25519 32, P-256 signing 33, HPKE P-256 65) and be a valid
/// key: a non-weak Ed25519 point, or a P-256 point on the curve that is not
/// the identity.
///
/// # Errors
///
/// [`PlatformError::CustodyError`] for an unknown role or type, a wrong
/// length or an invalid key.
pub fn registered_key(
    method: &str,
    answer: &HostPublicKey,
) -> Result<RegisteredKey, PlatformError> {
    host_role(method, answer)?;
    let key_type = parse_key_type(&answer.key_type).ok_or_else(|| {
        PlatformError::CustodyError(format!(
            "KeyCustodyProvider.{method} returned unknown key type {:?}",
            answer.key_type
        ))
    })?;
    let bytes = answer.public_key.as_slice();
    match key_type {
        KeyType::P256Signing | KeyType::HpkeP256 => {
            let pk = p256_public_key(method, key_type, bytes)?;
            Ok(if key_type == KeyType::P256Signing {
                RegisteredKey::P256Signing(pk)
            } else {
                RegisteredKey::HpkeP256(pk)
            })
        }
        KeyType::Ed25519 | KeyType::X25519 => {
            let raw: [u8; 32] = bytes.try_into().map_err(|_| {
                PlatformError::CustodyError(format!(
                    "KeyCustodyProvider.{method} returned {} bytes for a {} key, expected 32",
                    bytes.len(),
                    key_type_str(key_type)
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
            key_type_str(key_type)
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
// decision (key-type strings, registry, lengths, signature checks, roles) so
// the bridges cannot drift. The closures take the key id as the host's
// string.
// ---------------------------------------------------------------------------

/// `KeyCustody::generate_keypair` (role [`KeyRole::Operational`]) and
/// `generate_identity_keypair` (role [`KeyRole::Identity`]) over a host.
///
/// First destroys any orphaned host key ([`sweep_orphans`]). Then asks the
/// host for a key of `key_type` in the [`HostRole`] of `role`, and for its
/// public key, which must state the requested type and role and pass
/// [`registered_key`], and registers the handle. When the key id is not
/// numeric, the host's answer is refused, or the registry refuses the id (it
/// is live), the new host key is destroyed before the error is returned; a
/// destroy that also fails is appended to the error, and the key id is
/// queued for the next sweep.
///
/// From the moment the host returns a key id until the handle is registered
/// or the host key destroyed, an armed guard holds the id: a caller that
/// drops this future at any await in between leaves the id queued, and the
/// adapter's next generation destroys it on the host. A key queued when the
/// adapter itself is dropped stays on the host, because a new adapter has no
/// record of it.
///
/// # Errors
///
/// An orphan destroy that fails (see [`sweep_orphans`]); any host error;
/// [`PlatformError::CustodyError`] for a non-numeric key id, a refused public
/// key, another stated type or role, or a live key id.
pub async fn generate_keypair<G, GF, P, PF, D, DF>(
    registry: &CallbackKeyRegistry,
    key_type: KeyType,
    role: KeyRole,
    host_generate: G,
    host_get_public_key: P,
    host_destroy: D,
) -> Result<KeyHandle, PlatformError>
where
    G: FnOnce(&'static str, &'static str) -> GF,
    GF: Future<Output = Result<String, PlatformError>>,
    P: FnOnce(String) -> PF,
    PF: Future<Output = Result<HostPublicKey, PlatformError>>,
    D: Fn(String) -> DF + Sync,
    DF: Future<Output = Result<(), PlatformError>>,
{
    sweep_orphans(registry, &host_destroy).await?;
    let host_role_wanted = HostRole::of(&role);
    let key_id = host_generate(key_type_str(key_type), host_role_wanted.as_str()).await?;
    let mut orphan = OrphanGuard {
        registry,
        key_id: Some(key_id.clone()),
    };
    let registered = async {
        let handle = crate::custody_parse::parse_handle("generate_keypair", &key_id)?;
        let answer = host_get_public_key(key_id.clone()).await?;
        let key = registered_key("get_public_key", &answer)?;
        if key.key_type() != key_type {
            return Err(PlatformError::CustodyError(format!(
                "KeyCustodyProvider.generate_keypair({}) produced a {} key",
                key_type_str(key_type),
                key_type_str(key.key_type())
            )));
        }
        let reported = host_role("get_public_key", &answer)?;
        if reported != host_role_wanted {
            return Err(PlatformError::CustodyError(format!(
                "KeyCustodyProvider.generate_keypair asked for a {} key, and get_public_key \
                 reports it as {}",
                host_role_wanted.as_str(),
                reported.as_str()
            )));
        }
        registry.register(handle, RegisteredEntry::minted(key, role))?;
        Ok(handle)
    }
    .await;
    match registered {
        Ok(handle) => {
            orphan.disarm();
            Ok(handle)
        }
        Err(e) => match host_destroy(key_id).await {
            Ok(()) => {
                orphan.disarm();
                Err(e)
            }
            // The guard stays armed: the id is queued for the next sweep.
            Err(destroy_err) => Err(PlatformError::CustodyError(format!(
                "{e}; destroying the rejected host key also failed, and it is queued for \
                 the next generation to destroy: {destroy_err}"
            ))),
        },
    }
}

/// Destroys every host key queued as an orphan ([`OrphanGuard`]).
///
/// A key the host reports as [`PlatformError::KeyNotFound`] is already gone.
/// Each id leaves the queue only under an armed guard, so a sweep dropped
/// mid-destroy re-queues the id it was destroying and leaves the rest queued.
///
/// # Errors
///
/// [`PlatformError::CustodyError`] naming the first key whose destroy failed
/// with any other error; that key and every key not yet reached stay queued.
pub async fn sweep_orphans<D, DF>(
    registry: &CallbackKeyRegistry,
    host_destroy: &D,
) -> Result<(), PlatformError>
where
    D: Fn(String) -> DF + Sync,
    DF: Future<Output = Result<(), PlatformError>>,
{
    while let Some(key_id) = registry.pop_orphan()? {
        let mut guard = OrphanGuard {
            registry,
            key_id: Some(key_id.clone()),
        };
        match host_destroy(key_id.clone()).await {
            Ok(()) | Err(PlatformError::KeyNotFound) => guard.disarm(),
            Err(e) => {
                return Err(PlatformError::CustodyError(format!(
                    "destroying orphaned host key {key_id} failed: {e}"
                )));
            }
        }
    }
    Ok(())
}

/// The live entry for `key`, resolving a handle this adapter has not seen
/// through the host's `get_public_key`. Every entry point calls this, so no
/// result depends on which ran first.
///
/// A host keeps its keys, and the role it minted each with, across adapter
/// instances, so a handle from an earlier session is still the host's key.
/// Its structured answer passes [`registered_key`] and binds the handle in
/// the role the host reports ([`CallbackKeyRegistry::bind_resolved`]): an
/// identity minted in an earlier session resolves as an identity. Returns
/// the entry and whether this call asked the host.
///
/// # Errors
///
/// [`PlatformError::KeyNotFound`] for a handle being or already destroyed
/// (no host call), and the host's own error for a key it lacks (a conforming
/// host reports [`PlatformError::KeyNotFound`]); as in [`registered_key`] and
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
    let role = host_role("get_public_key", &answer)?;
    Ok((registry.bind_resolved(*key, found, role)?, true))
}

/// `KeyCustody::sign` over a host provider.
///
/// A P-256 signing key (generated, resolved or a pseudonym) signs a 32-byte
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
/// Returns the registered public key. For a handle already registered, the
/// host's current answer must still pass [`registered_key`] and name the
/// same key in the same role; a resolution asks the host once.
///
/// # Errors
///
/// Any host error; [`PlatformError::CustodyError`] for a refused or changed
/// key, and as in [`resolve`].
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
        if host_role("get_public_key", &answer)? != HostRole::of(&entry.role) {
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
/// key (a pseudonym included) is [`PlatformError::WrongKeyType`] without a
/// host call. The host must return exactly 32 bytes, which are zeroized once
/// copied.
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
/// The slot is `Destroying` for the whole host call, so no entry point can
/// resolve or bind the handle meanwhile. A host success leaves a `Destroyed`
/// tombstone; a host failure restores the prior entry (or clears the marker
/// for a handle that was unknown) and returns the host error. When the
/// caller drops this future before the host answers, the slot becomes
/// `Abandoned` and an identity's pseudonyms are retired; a later
/// `destroy_key` on the handle retries the host destroy, and a failed retry
/// leaves it `Abandoned`.
///
/// # Errors
///
/// [`PlatformError::KeyNotFound`] for a handle already being or destroyed
/// (no host call); any host error; a poisoned registry.
pub async fn destroy_key<D, DF>(
    registry: &CallbackKeyRegistry,
    key: &KeyHandle,
    host_destroy: D,
) -> Result<(), PlatformError>
where
    D: FnOnce(String) -> DF,
    DF: Future<Output = Result<(), PlatformError>>,
{
    let token = registry.begin_destroy(key)?;
    let mut guard = DestroyGuard {
        registry,
        handle: *key,
        token,
        armed: true,
    };
    let host = host_destroy(key.id().to_string()).await;
    let ended = registry.end_destroy(key, token, host.is_ok());
    guard.armed = false;
    host?;
    ended
}

/// Requires an Ed25519 key for an Ed25519-only operation
/// (`ed25519_to_x25519_agree`, `export_ed25519_signing_key`), resolving an
/// unregistered handle like every other entry point.
///
/// # Errors
///
/// [`PlatformError::WrongKeyType`] for another type, or as in [`resolve`].
pub async fn require_ed25519<P, PF>(
    registry: &CallbackKeyRegistry,
    key: &KeyHandle,
    host_get_public_key: P,
) -> Result<(), PlatformError>
where
    P: Fn(String) -> PF + Sync,
    PF: Future<Output = Result<HostPublicKey, PlatformError>>,
{
    match resolve(registry, key, &host_get_public_key).await?.0.key {
        RegisteredKey::Ed25519(_) => Ok(()),
        k => Err(k.wrong_type(KeyType::Ed25519)),
    }
}

/// `KeyCustody::derive_pseudonym` (`epoch` `None`) and
/// `derive_rotatable_pseudonym` over a host provider.
///
/// `key` must be an [`KeyRole::Identity`] key: an operational key, a
/// resolved host key or a pseudonym is [`PlatformError::WrongKeyType`], with
/// no derive call. The host returns the pseudonym as separate
/// `(public_key, key_id)` fields; the point must be a 33-byte compressed
/// P-256 point, the key id numeric, and the host's own
/// `get_public_key(key_id)` must answer `"p256"` with the same point in the
/// `"operational"` role. The
/// handle is then bound as a [`KeyRole::Pseudonym`] of `(key, context_id,
/// epoch)` ([`CallbackKeyRegistry::bind_pseudonym`]).
///
/// # Errors
///
/// [`PlatformError::WrongKeyType`] for `key`, or as in [`resolve`]; any host
/// error; [`PlatformError::PseudonymRejected`] (reported as `SCP-IDENT-1055`)
/// for a malformed pseudonym, a malformed `get_public_key(key_id)` answer, a
/// point or role that answer does not confirm, or a refused bind.
pub async fn derive_pseudonym<H, HF, P, PF>(
    registry: &CallbackKeyRegistry,
    method: &str,
    key: &KeyHandle,
    context_id: &[u8],
    epoch: Option<u64>,
    host_derive: H,
    host_get_public_key: P,
) -> Result<PseudonymKeypair, PlatformError>
where
    H: FnOnce(String) -> HF,
    HF: Future<Output = Result<(Vec<u8>, String), PlatformError>>,
    P: Fn(String) -> PF + Sync,
    PF: Future<Output = Result<HostPublicKey, PlatformError>>,
{
    let source = resolve(registry, key, &host_get_public_key).await?.0;
    let source_key = source.key.clone();
    if source.role != KeyRole::Identity {
        return Err(source.key.wrong_type(KeyType::Ed25519));
    }
    // Until S12 (§9.10.4.A native interim): the host derives from an Ed25519
    // identity seed, so the source must also be an Ed25519 key.
    if !matches!(source.key, RegisteredKey::Ed25519(_)) {
        return Err(source.key.wrong_type(KeyType::Ed25519));
    }
    let (public_key, key_id) = host_derive(key.id().to_string()).await?;
    let pseudonym = crate::custody_parse::parse_pseudonym(method, &public_key, &key_id)?;
    let derived =
        RegisteredKey::P256Signing(P256PublicKey::from_sec1(&public_key).map_err(|e| {
            PlatformError::PseudonymRejected(format!("KeyCustodyProvider.{method}: {e}"))
        })?);
    let answer = host_get_public_key(key_id).await?;
    // A malformed answer about the pseudonym key refuses the pseudonym.
    let rejected = |e| match e {
        PlatformError::CustodyError(msg) => PlatformError::PseudonymRejected(msg),
        other => other,
    };
    let confirmed = registered_key("get_public_key", &answer).map_err(rejected)?;
    if host_role("get_public_key", &answer).map_err(rejected)? != HostRole::Operational {
        return Err(PlatformError::PseudonymRejected(format!(
            "KeyCustodyProvider.{method}: get_public_key(key_id) reports the pseudonym key as \
             an identity"
        )));
    }
    if confirmed != derived {
        return Err(PlatformError::PseudonymRejected(format!(
            "KeyCustodyProvider.{method}: get_public_key(key_id) does not match the derived \
             pseudonym point"
        )));
    }
    registry.bind_pseudonym(
        method,
        *pseudonym.key_handle(),
        derived,
        KeyRole::Pseudonym {
            source: key.id(),
            context_id: context_id.to_vec(),
            epoch,
        },
        &source_key,
    )?;
    Ok(pseudonym)
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
    use scp_crypto::p256::{P256PublicKey, P256SigningKey, ecdh_p256, sign_prehash_rfc6979};
    use scp_platform::error::PlatformError;

    use super::{HostPublicKey, HostRole};

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
        P256(P256SigningKey),
        HpkeP256(P256SigningKey),
    }

    fn p256_copy(key: &P256SigningKey) -> Result<P256SigningKey, PlatformError> {
        P256SigningKey::from_scalar_bytes(&key.to_scalar_bytes())
            .map_err(|e| PlatformError::CustodyError(e.to_string()))
    }

    /// A derivation's source key id, context id and epoch.
    type Derivation = (String, Vec<u8>, Option<u64>);

    /// Host state: every key by id, pseudonym ids by derivation, call counts,
    /// and the last peer it was sent.
    #[derive(Default)]
    pub struct FakeHost {
        keys: Mutex<HashMap<String, HostKey>>,
        /// The role each key id was minted in; a pseudonym is operational.
        roles: Mutex<HashMap<String, HostRole>>,
        derived: Mutex<HashMap<Derivation, String>>,
        next: AtomicUsize,
        calls: Mutex<HashMap<&'static str, usize>>,
        /// The peer bytes of the most recent `dh_agree` call.
        pub last_peer: Mutex<Option<Vec<u8>>>,
    }

    impl FakeHost {
        /// How many calls to `method` reached the host.
        /// Whether the host still holds `key_id`.
        pub fn holds(&self, key_id: &str) -> bool {
            locked(&self.keys).is_ok_and(|keys| keys.contains_key(key_id))
        }

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

        /// `generate_keypair`: `ed25519`, `p256` or `hpke-p256`, recording
        /// `role` for `get_public_key`; numeric ids from 1.
        ///
        /// # Errors
        ///
        /// Any other key type or role.
        pub fn generate_keypair(
            &self,
            key_type: &str,
            role: &str,
        ) -> Result<String, PlatformError> {
            self.count("generate_keypair");
            let id = self.next_id();
            let scalar = [u8::try_from(id % 64).unwrap_or(0) + 0x40; 32];
            let p256 = || {
                P256SigningKey::from_scalar_bytes(&scalar)
                    .map_err(|e| PlatformError::CustodyError(e.to_string()))
            };
            let key = match key_type {
                "ed25519" => HostKey::Ed25519(ed25519_dalek::SigningKey::from_bytes(&scalar)),
                "p256" => HostKey::P256(p256()?),
                "hpke-p256" => HostKey::HpkeP256(p256()?),
                other => {
                    return Err(PlatformError::CustodyError(format!(
                        "fake host does not hold {other} keys"
                    )));
                }
            };
            let role = HostRole::parse(role).ok_or_else(|| {
                PlatformError::CustodyError(format!("fake host does not mint {role} keys"))
            })?;
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
            let role = locked(&self.roles)?
                .get(key_id)
                .copied()
                .unwrap_or(HostRole::Operational)
                .as_str()
                .to_owned();
            self.with_key(key_id, |key| {
                let (key_type, public_key) = match key {
                    HostKey::Ed25519(sk) => ("ed25519", sk.verifying_key().to_bytes().to_vec()),
                    HostKey::P256(sk) => ("p256", sk.public_key().to_compressed().to_vec()),
                    HostKey::HpkeP256(sk) => {
                        ("hpke-p256", sk.public_key().to_uncompressed().to_vec())
                    }
                };
                Ok(HostPublicKey {
                    key_type: key_type.into(),
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
        /// P-256 pseudonym of an Ed25519 key's seed, registered as a `p256`
        /// key. A repeated derivation returns the same key id.
        ///
        /// # Errors
        ///
        /// An unknown key id, or a key that is not Ed25519.
        pub fn derive_pseudonym(
            &self,
            key_id: &str,
            context_id: &[u8],
            epoch: Option<u64>,
        ) -> Result<(Vec<u8>, String), PlatformError> {
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
            let pseudonym =
                scp_crypto::pseudonym::derive_pseudonym_keypair(&seed, context_id, epoch)
                    .map_err(|e| PlatformError::CustodyError(e.to_string()))?;
            let point = pseudonym.public_key().to_compressed().to_vec();
            let tuple = (key_id.to_owned(), context_id.to_vec(), epoch);
            let mut derived = locked(&self.derived)?;
            if let Some(id) = derived.get(&tuple) {
                return Ok((point, id.clone()));
            }
            let id = self.next_id().to_string();
            locked(&self.keys)?.insert(id.clone(), HostKey::P256(pseudonym));
            derived.insert(tuple, id.clone());
            drop(derived);
            Ok((point, id))
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
    use scp_crypto::p256::{P256SigningKey, sign_prehash_rfc6979};

    fn key_and_sig() -> (P256SigningKey, [u8; 32], [u8; 64]) {
        let key = P256SigningKey::from_scalar_bytes(&[0x11u8; 32]).unwrap();
        let digest = [0x22u8; 32];
        let sig = sign_prehash_rfc6979(&key, &digest).unwrap();
        (key, digest, sig)
    }

    fn p256(seed: u8) -> P256SigningKey {
        P256SigningKey::from_scalar_bytes(&[seed; 32]).unwrap()
    }

    fn ed(seed: u8) -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[seed; 32])
    }

    fn answer(key_type: &str, public_key: &[u8]) -> HostPublicKey {
        HostPublicKey {
            key_type: key_type.to_owned(),
            public_key: public_key.to_vec(),
            role: "operational".to_owned(),
        }
    }

    fn as_identity(mut a: HostPublicKey) -> HostPublicKey {
        a.role = "identity".to_owned();
        a
    }

    fn ed_answer(key: &ed25519_dalek::SigningKey) -> HostPublicKey {
        answer("ed25519", &key.verifying_key().to_bytes())
    }

    fn p256_answer(key: &P256SigningKey) -> HostPublicKey {
        answer("p256", &key.public_key().to_compressed())
    }

    fn hpke_answer(key: &P256SigningKey) -> HostPublicKey {
        answer("hpke-p256", &key.public_key().to_uncompressed())
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
            .register(KeyHandle::new(id), RegisteredEntry::minted(key, role))
            .unwrap();
    }

    fn slot(registry: &CallbackKeyRegistry, id: u64) -> Option<Slot> {
        registry.slots.lock().unwrap().map.get(&id).cloned()
    }

    #[test]
    fn key_type_strings_round_trip() {
        for t in [
            KeyType::Ed25519,
            KeyType::X25519,
            KeyType::P256Signing,
            KeyType::HpkeP256,
        ] {
            assert_eq!(parse_key_type(key_type_str(t)), Some(t));
        }
        assert_eq!(key_type_str(KeyType::P256Signing), "p256");
        assert_eq!(key_type_str(KeyType::HpkeP256), "hpke-p256");
        assert_eq!(parse_key_type("P256"), None);
        assert_eq!(parse_key_type(""), None);
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

    /// A1/F3: the host's stated type decides the key, and the key must have
    /// exactly that type's length and be valid. Every other answer is a
    /// custody error: a length that fits another type, an unknown type
    /// string, an invalid or weak Ed25519 point, an off-curve P-256 point.
    #[test]
    fn host_answers_bind_by_stated_type_and_exact_length() {
        let p = p256(0x21).public_key();
        let e = ed(0x31).verifying_key();
        let x = [9u8; 32];
        assert_eq!(
            registered_key("m", &answer("ed25519", &e.to_bytes())).unwrap(),
            RegisteredKey::Ed25519(e)
        );
        assert_eq!(
            registered_key("m", &answer("x25519", &x)).unwrap(),
            RegisteredKey::X25519(x)
        );
        assert_eq!(
            registered_key("m", &answer("p256", &p.to_compressed())).unwrap(),
            RegisteredKey::P256Signing(p)
        );
        assert_eq!(
            registered_key("m", &answer("hpke-p256", &p.to_uncompressed())).unwrap(),
            RegisteredKey::HpkeP256(p)
        );

        // The Ed25519 identity point: a weak (small-order) key.
        let mut identity = [0u8; 32];
        identity[0] = 1;
        let refused: Vec<HostPublicKey> = vec![
            answer("ed25519", &p.to_compressed()),
            answer("x25519", &p.to_compressed()),
            answer("p256", &e.to_bytes()),
            answer("p256", &p.to_uncompressed()),
            answer("hpke-p256", &p.to_compressed()),
            answer("ed25519", &[0u8; 31]),
            answer("x25519", &[0u8; 33]),
            answer("ed25519", &identity),
            answer("p256", &[&[0x02][..], &[0xFF; 32]].concat()),
            answer("P256", &p.to_compressed()),
            answer("", &e.to_bytes()),
            answer("secp256k1", &p.to_compressed()),
        ];
        for a in refused {
            assert!(
                matches!(registered_key("m", &a), Err(PlatformError::CustodyError(_))),
                "{a:?}"
            );
        }
    }

    /// A3: an Ed25519 host signature is accepted only when it verifies
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

    /// A3: an Ed25519 handle, minted or resolved, rejects a host that returns
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

    /// A registry holding identity key 1 (Ed25519) and pseudonym 7 of
    /// (1, "ctx", None), derived through the shared flow from a host whose
    /// pseudonym key is `key`.
    async fn registry_with_pseudonym(
        identity: &ed25519_dalek::SigningKey,
        key: &P256SigningKey,
    ) -> CallbackKeyRegistry {
        let registry = CallbackKeyRegistry::new();
        live(
            &registry,
            1,
            RegisteredKey::Ed25519(identity.verifying_key()),
            KeyRole::Identity,
        );
        let point = key.public_key().to_compressed().to_vec();
        let confirm = p256_answer(key);
        let derived = derive_pseudonym(
            &registry,
            "derive_pseudonym",
            &KeyHandle::new(1),
            b"ctx",
            None,
            |id| async move {
                assert_eq!(id, "1");
                Ok((point, "7".to_owned()))
            },
            move |id| {
                let confirm = confirm.clone();
                async move {
                    assert_eq!(id, "7");
                    Ok(confirm)
                }
            },
        )
        .await
        .unwrap();
        assert_eq!(derived.key_handle().id(), 7);
        registry
    }

    fn pseudonym_role(source: u64, context: &[u8], epoch: Option<u64>) -> KeyRole {
        KeyRole::Pseudonym {
            source,
            context_id: context.to_vec(),
            epoch,
        }
    }

    /// A pseudonym handle is a registered P-256 signing key. Its host's DER
    /// high-s signature comes out raw low-s and strictly verifies; a junk
    /// 64-byte signature is refused; `dh_agree` is `WrongKeyType`; a
    /// registered handle never asks the host for its public key to sign.
    #[tokio::test]
    async fn pseudonym_handles_use_the_registry_path() {
        let key = p256(0x21);
        let registry = registry_with_pseudonym(&ed(0x61), &key).await;
        let handle = KeyHandle::new(7);
        let digest = [0x5au8; 32];
        assert_eq!(
            registry.get(&handle).unwrap().unwrap().role,
            pseudonym_role(1, b"ctx", None)
        );

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

    /// A2: every entry point resolves an unregistered handle the same way,
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
        let x_a = answer("x25519", &x25519);
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
                "require_ed25519" => require_ed25519(&registry, &h, &l).await,
                "dh_agree" => {
                    let peer = if host_answer.key_type == "hpke-p256" {
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
                "{} {first}: {result:?}",
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
                "{} {first}",
                host_answer.key_type
            );
            let entry = registry.get(&h).unwrap().expect("bound");
            assert_eq!(entry.key, expected);
            assert_eq!(entry.role, KeyRole::Operational);
        }
    }

    /// A2: a host without the key answers its not-found to every entry
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
            require_ed25519(&registry, &h, missing).await,
            Err(PlatformError::KeyNotFound)
        ));
        assert!(matches!(
            public_key(&registry, &h, missing).await,
            Err(PlatformError::KeyNotFound)
        ));
        assert!(registry.get(&h).unwrap().is_none());
    }

    /// F3: a resolution whose answer has the wrong length for its stated
    /// type, or an unknown type, is a custody error and binds nothing, with
    /// no host sign call.
    #[tokio::test]
    async fn a_refused_resolution_binds_nothing() {
        let p = p256(0x81);
        let h = KeyHandle::new(8);
        for a in [
            answer("ed25519", &p.public_key().to_compressed()),
            answer("p256", &p.public_key().to_uncompressed()),
            answer("hpke-p256", &p.public_key().to_compressed()),
            answer("x25519", &[1u8; 31]),
            answer("rsa", &[1u8; 32]),
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

    /// F6: two resolutions of one handle that both asked the host (the
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

        let slot_count = || registry.slots.lock().expect("registry lock").map.len();
        assert_eq!(slot_count(), 1);

        // Resolving again asks nothing and writes nothing: the one slot holds
        // the same entry. A bound pseudonym keeps its role.
        assert_eq!(
            resolve(&registry, &h, &no_lookup).await.unwrap(),
            (entry.clone(), false)
        );
        assert_eq!(slot_count(), 1);
        assert_eq!(registry.get(&h).unwrap(), Some(entry));
        let pseudo = registry_with_pseudonym(&ed(0x92), &p).await;
        let (entry, asked) = resolve(&pseudo, &KeyHandle::new(7), &no_lookup)
            .await
            .unwrap();
        assert!(!asked);
        assert_eq!(entry.role, pseudonym_role(1, b"ctx", None));
    }

    /// F2: `require_ed25519` refuses a P-256, an HPKE and an X25519 entry
    /// with `WrongKeyType`, and accepts an Ed25519 one.
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
                require_ed25519(&registry, &KeyHandle::new(id), no_lookup).await,
                Err(PlatformError::WrongKeyType { expected: KeyType::Ed25519, actual: a })
                    if a == actual
            ));
        }
        require_ed25519(&registry, &KeyHandle::new(4), no_lookup)
            .await
            .unwrap();
    }

    /// F4: a registered HPKE key whose host point changes after generation
    /// is a custody error from `public_key`; so is one whose host now states
    /// another type for the same bytes.
    #[tokio::test]
    async fn public_key_refuses_a_changed_host_key() {
        let registry = CallbackKeyRegistry::new();
        let host = std::sync::Mutex::new(hpke_answer(&p256(0xB1)));
        let h = generate_keypair(
            &registry,
            KeyType::HpkeP256,
            KeyRole::Operational,
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
        *host.lock().unwrap() = answer("p256", &p256(0xB1).public_key().to_compressed());
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

    /// F5: an X25519 handle given a 33-byte peer is a custody error with no
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
    /// `(point, id)` and confirms `confirm`, counting derive calls.
    async fn derive_from(
        registry: &CallbackKeyRegistry,
        source: u64,
        context: &[u8],
        epoch: Option<u64>,
        returned: (Vec<u8>, &str),
        confirm: HostPublicKey,
        derives: &AtomicUsize,
    ) -> Result<PseudonymKeypair, PlatformError> {
        let (point, id) = (returned.0, returned.1.to_owned());
        derive_pseudonym(
            registry,
            "derive_rotatable_pseudonym",
            &KeyHandle::new(source),
            context,
            epoch,
            |_| {
                derives.fetch_add(1, Ordering::Relaxed);
                async move { Ok((point, id)) }
            },
            move |_| {
                let confirm = confirm.clone();
                async move { Ok(confirm) }
            },
        )
        .await
    }

    /// C2: a derive source must be an identity key. An operational Ed25519
    /// key (minted by `generate_keypair`, or resolved), and an Ed25519 key in
    /// the pseudonym role, are refused because of their role: they are
    /// Ed25519, so the curve check alone would pass them. A P-256 identity
    /// key is refused by the interim curve check. None reaches the host's
    /// derive.
    #[tokio::test]
    async fn derivation_needs_an_identity_source() {
        let pseudo = p256(0xC1);
        let point = pseudo.public_key().to_compressed().to_vec();
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
            3,
            RegisteredKey::Ed25519(e),
            pseudonym_role(1, b"ctx", None),
        );
        live(
            &registry,
            4,
            RegisteredKey::P256Signing(pseudo.public_key()),
            KeyRole::Identity,
        );
        let derives = AtomicUsize::new(0);
        for source in [2, 3, 4] {
            let result = derive_from(
                &registry,
                source,
                b"ctx",
                Some(0),
                (point.clone(), "20"),
                p256_answer(&pseudo),
                &derives,
            )
            .await;
            assert!(
                matches!(
                    result,
                    Err(PlatformError::WrongKeyType {
                        expected: KeyType::Ed25519,
                        ..
                    })
                ),
                "source {source}: {result:?}"
            );
        }
        // A resolved host key is operational, so it never derives.
        let calls = AtomicUsize::new(0);
        let resolved = derive_pseudonym(
            &registry,
            "derive_pseudonym",
            &KeyHandle::new(5),
            b"ctx",
            None,
            |_| async { panic!("no derivation from a resolved key") },
            lookup(&answer("ed25519", &e.to_bytes()), &calls),
        )
        .await;
        assert!(matches!(
            resolved,
            Err(PlatformError::WrongKeyType {
                expected: KeyType::Ed25519,
                actual: KeyType::Ed25519
            })
        ));
        assert_eq!(derives.load(Ordering::Relaxed), 0);
        assert!(registry.get(&KeyHandle::new(20)).unwrap().is_none());

        derive_from(
            &registry,
            1,
            b"ctx",
            Some(0),
            (point, "20"),
            p256_answer(&pseudo),
            &derives,
        )
        .await
        .expect("an identity source derives");
        assert_eq!(
            registry.get(&KeyHandle::new(20)).unwrap().unwrap().role,
            pseudonym_role(1, b"ctx", Some(0))
        );
    }

    /// C3: the same pseudonym id is accepted again only for the same key
    /// and the same (source, context, epoch). An id that collides with a
    /// minted key or an identity, an id returned for another derivation, a
    /// point the host's `get_public_key` does not confirm, and a 32-byte
    /// pseudonym are refused, and each leaves the registry as it was.
    #[tokio::test]
    async fn pseudonym_rebinding_rules() {
        let pseudo = p256(0xD1);
        let other = p256(0xD2);
        let point = pseudo.public_key().to_compressed().to_vec();
        let registry = CallbackKeyRegistry::new();
        let e = ed(0xD3).verifying_key();
        live(&registry, 1, RegisteredKey::Ed25519(e), KeyRole::Identity);
        live(
            &registry,
            2,
            RegisteredKey::Ed25519(ed(0xD4).verifying_key()),
            KeyRole::Identity,
        );
        live(
            &registry,
            30,
            RegisteredKey::P256Signing(pseudo.public_key()),
            KeyRole::Operational,
        );
        let derives = AtomicUsize::new(0);
        let d = |source: u64,
                 context: &'static [u8],
                 epoch: Option<u64>,
                 ret: (Vec<u8>, &'static str),
                 confirm: HostPublicKey| {
            derive_from(&registry, source, context, epoch, ret, confirm, &derives)
        };

        d(
            1,
            b"ctx",
            Some(3),
            (point.clone(), "20"),
            p256_answer(&pseudo),
        )
        .await
        .unwrap();
        let bound = registry.get(&KeyHandle::new(20)).unwrap();
        // A repeat derivation: accepted.
        d(
            1,
            b"ctx",
            Some(3),
            (point.clone(), "20"),
            p256_answer(&pseudo),
        )
        .await
        .unwrap();
        assert_eq!(registry.get(&KeyHandle::new(20)).unwrap(), bound);

        // The same id for another context, epoch or source, or another
        // point: refused, and entry 20 is unchanged.
        for (source, context, epoch, key) in [
            (1, &b"other"[..], Some(3), &pseudo),
            (1, &b"ctx"[..], Some(4), &pseudo),
            (1, &b"ctx"[..], None, &pseudo),
            (2, &b"ctx"[..], Some(3), &pseudo),
            (1, &b"ctx"[..], Some(3), &other),
        ] {
            let ret = (key.public_key().to_compressed().to_vec(), "20");
            let result = d(source, context, epoch, ret, p256_answer(key)).await;
            assert!(
                matches!(result, Err(PlatformError::PseudonymRejected(_))),
                "{result:?}"
            );
            assert_eq!(registry.get(&KeyHandle::new(20)).unwrap(), bound);
        }
        // An id held by a minted operational key or by an identity: refused,
        // the occupant unchanged.
        for id in ["30", "1"] {
            let before = registry.get(&KeyHandle::new(id.parse().unwrap())).unwrap();
            let result = d(1, b"x", None, (point.clone(), id), p256_answer(&pseudo)).await;
            assert!(
                matches!(result, Err(PlatformError::PseudonymRejected(_))),
                "{id}: {result:?}"
            );
            assert_eq!(
                registry.get(&KeyHandle::new(id.parse().unwrap())).unwrap(),
                before
            );
        }
        // The host's own public key disagrees, or states another type:
        // nothing is bound.
        for confirm in [
            p256_answer(&other),
            hpke_answer(&pseudo),
            answer("p256", &[0u8; 33]),
        ] {
            let result = d(1, b"y", None, (point.clone(), "21"), confirm).await;
            assert!(
                matches!(result, Err(PlatformError::PseudonymRejected(_))),
                "{result:?}"
            );
            assert!(registry.get(&KeyHandle::new(21)).unwrap().is_none());
        }
        // A 32-byte (Ed25519-era) pseudonym.
        let result = d(
            1,
            b"y",
            None,
            (vec![2u8; 32], "21"),
            answer("p256", &[2u8; 32]),
        )
        .await;
        assert!(matches!(result, Err(PlatformError::PseudonymRejected(_))));
        assert!(registry.get(&KeyHandle::new(21)).unwrap().is_none());
    }

    /// C3: a host key resolved earlier as operational is identified by the
    /// derivation of its own point. Once destroyed, its id stays unusable
    /// until a derivation the host answers with that id binds it afresh, as
    /// a host with deterministic pseudonym ids does on a re-derive.
    #[tokio::test]
    async fn a_resolved_key_is_identified_by_its_derivation() {
        let other = p256(0xD2);
        let registry = CallbackKeyRegistry::new();
        live(
            &registry,
            1,
            RegisteredKey::Ed25519(ed(0xD3).verifying_key()),
            KeyRole::Identity,
        );
        let derives = AtomicUsize::new(0);
        let d = |source: u64,
                 context: &'static [u8],
                 epoch: Option<u64>,
                 ret: (Vec<u8>, &'static str),
                 confirm: HostPublicKey| {
            derive_from(&registry, source, context, epoch, ret, confirm, &derives)
        };
        let calls = AtomicUsize::new(0);
        resolve(
            &registry,
            &KeyHandle::new(22),
            &lookup(&p256_answer(&other), &calls),
        )
        .await
        .unwrap();
        d(
            1,
            b"z",
            None,
            (other.public_key().to_compressed().to_vec(), "22"),
            p256_answer(&other),
        )
        .await
        .unwrap();
        assert_eq!(
            registry.get(&KeyHandle::new(22)).unwrap().unwrap().role,
            pseudonym_role(1, b"z", None)
        );
        destroy_key(&registry, &KeyHandle::new(22), |_| async { Ok(()) })
            .await
            .unwrap();
        assert!(matches!(
            registry.get(&KeyHandle::new(22)),
            Err(PlatformError::KeyNotFound)
        ));
        d(
            1,
            b"z",
            None,
            (other.public_key().to_compressed().to_vec(), "22"),
            p256_answer(&other),
        )
        .await
        .unwrap();
        assert_eq!(
            registry.get(&KeyHandle::new(22)).unwrap().unwrap().role,
            pseudonym_role(1, b"z", None)
        );
    }

    /// §9.15: destroying an identity destroys every pseudonym derived from
    /// it, live or mid-destroy, in the same step, and no other key. A host
    /// that then reuses a retired id binds it afresh: as a minted key (an
    /// operational entry, with no pseudonym's digest-only signing) or as
    /// another identity's pseudonym.
    #[tokio::test]
    async fn identity_destroy_retires_its_pseudonyms() {
        let registry = CallbackKeyRegistry::new();
        live(
            &registry,
            1,
            RegisteredKey::Ed25519(ed(0xE1).verifying_key()),
            KeyRole::Identity,
        );
        live(
            &registry,
            2,
            RegisteredKey::Ed25519(ed(0xE2).verifying_key()),
            KeyRole::Identity,
        );
        let derives = AtomicUsize::new(0);
        let (a, b, c) = (p256(0xE3), p256(0xE4), p256(0xE5));
        for (source, epoch, key, id) in [
            (1, None, &a, "10"),
            (1, Some(3), &b, "11"),
            (2, None, &c, "12"),
        ] {
            derive_from(
                &registry,
                source,
                b"ctx",
                epoch,
                (key.public_key().to_compressed().to_vec(), id),
                p256_answer(key),
                &derives,
            )
            .await
            .unwrap();
        }
        // A destroy of pseudonym 11 is in flight when its identity goes.
        let in_flight = registry.begin_destroy(&KeyHandle::new(11)).unwrap();

        destroy_key(&registry, &KeyHandle::new(1), |_| async { Ok(()) })
            .await
            .unwrap();
        for id in [1, 10, 11] {
            assert!(
                matches!(
                    registry.get(&KeyHandle::new(id)),
                    Err(PlatformError::KeyNotFound)
                ),
                "handle {id} must be retired with its identity"
            );
        }
        assert_eq!(
            registry.get(&KeyHandle::new(12)).unwrap().unwrap().role,
            pseudonym_role(2, b"ctx", None)
        );
        // The in-flight destroy failing does not bring pseudonym 11 back.
        registry
            .end_destroy(&KeyHandle::new(11), in_flight, false)
            .unwrap();
        assert!(matches!(
            registry.get(&KeyHandle::new(11)),
            Err(PlatformError::KeyNotFound)
        ));
        // A derive from the destroyed identity binds nothing.
        assert!(matches!(
            derive_from(
                &registry,
                1,
                b"ctx",
                None,
                (a.public_key().to_compressed().to_vec(), "10"),
                p256_answer(&a),
                &derives,
            )
            .await,
            Err(PlatformError::KeyNotFound)
        ));

        // The host reuses id 10 for a minted key and id 11 for another
        // identity's pseudonym.
        let minted = RegisteredKey::P256Signing(p256(0xE6).public_key());
        registry
            .register(
                KeyHandle::new(10),
                RegisteredEntry::minted(minted.clone(), KeyRole::Operational),
            )
            .unwrap();
        let entry = registry.get(&KeyHandle::new(10)).unwrap().unwrap();
        assert_eq!((entry.key, entry.role), (minted, KeyRole::Operational));
        let d = p256(0xE7);
        derive_from(
            &registry,
            2,
            b"other",
            None,
            (d.public_key().to_compressed().to_vec(), "11"),
            p256_answer(&d),
            &derives,
        )
        .await
        .unwrap();
        assert_eq!(
            registry.get(&KeyHandle::new(11)).unwrap().unwrap().role,
            pseudonym_role(2, b"other", None)
        );
    }

    /// A derive whose host call returns after its identity was destroyed
    /// binds nothing: the source check is repeated under the bind's lock.
    #[tokio::test]
    async fn a_derive_racing_its_identity_destroy_binds_nothing() {
        let registry = CallbackKeyRegistry::new();
        live(
            &registry,
            1,
            RegisteredKey::Ed25519(ed(0xE8).verifying_key()),
            KeyRole::Identity,
        );
        let key = p256(0xE9);
        let point = key.public_key().to_compressed().to_vec();
        let result = derive_pseudonym(
            &registry,
            "derive_pseudonym",
            &KeyHandle::new(1),
            b"ctx",
            None,
            |_| {
                let token = registry.begin_destroy(&KeyHandle::new(1));
                let ended = token.and_then(|t| registry.end_destroy(&KeyHandle::new(1), t, true));
                async move {
                    ended?;
                    Ok((point, "20".to_owned()))
                }
            },
            |_| {
                let answer = p256_answer(&key);
                async move { Ok(answer) }
            },
        )
        .await;
        assert!(matches!(result, Err(PlatformError::KeyNotFound)));
        assert!(registry.get(&KeyHandle::new(20)).unwrap().is_none());
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
        generate_keypair(
            registry,
            key_type,
            KeyRole::Operational,
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
    /// handed: a non-numeric id, a malformed public key, a failing fetch, an
    /// answer stating another type (F3), and (B2) an id the registry holds
    /// live. An accepted key is not destroyed, and may take over a
    /// destroyed id.
    #[tokio::test]
    async fn refused_generation_destroys_the_host_key() {
        type Case = (KeyType, &'static str, Result<HostPublicKey, PlatformError>);
        let valid = p256(5);
        let e = ed(6);
        let cases: Vec<Case> = vec![
            (KeyType::Ed25519, "not-a-number", Ok(ed_answer(&e))),
            (KeyType::X25519, "", Ok(answer("x25519", &[1; 32]))),
            (KeyType::P256Signing, "-1", Ok(p256_answer(&valid))),
            (KeyType::HpkeP256, "0x10", Ok(hpke_answer(&valid))),
            (
                KeyType::P256Signing,
                "11",
                Ok(answer("p256", &valid.public_key().to_uncompressed())),
            ),
            (
                KeyType::HpkeP256,
                "12",
                Ok(answer("hpke-p256", &valid.public_key().to_compressed())),
            ),
            (
                KeyType::P256Signing,
                "13",
                Ok(answer("p256", &[&[0x02][..], &[0xFF; 32]].concat())),
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
                Ok(answer("x25519", &e.verifying_key().to_bytes())),
            ),
            (KeyType::X25519, "17", Ok(ed_answer(&e))),
            // M2: the host reports another role than the one requested, or
            // no known role.
            (KeyType::Ed25519, "18", Ok(as_identity(ed_answer(&e)))),
            (
                KeyType::P256Signing,
                "19",
                Ok(HostPublicKey {
                    role: "admin".to_owned(),
                    ..p256_answer(&valid)
                }),
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
            assert!(registry.slots.lock().unwrap().map.is_empty(), "{key_id}");
        }

        let registry = CallbackKeyRegistry::new();
        let destroyed = Log::default();
        let handle = generate_with(
            &registry,
            KeyType::P256Signing,
            "21",
            Ok(p256_answer(&valid)),
            &destroyed,
        )
        .await
        .unwrap();
        assert_eq!(handle.id(), 21);
        assert!(destroyed.lock().unwrap().is_empty());

        // B2: a live id is refused, and the host key destroyed.
        let again = generate_with(
            &registry,
            KeyType::Ed25519,
            "21",
            Ok(ed_answer(&e)),
            &destroyed,
        )
        .await;
        assert!(matches!(again, Err(PlatformError::CustodyError(_))));
        assert_eq!(*destroyed.lock().unwrap(), vec!["21".to_owned()]);
        assert_eq!(
            registry.get(&handle).unwrap().unwrap().key,
            RegisteredKey::P256Signing(valid.public_key())
        );

        // A destroyed id may be handed to a new key.
        destroy_key(&registry, &handle, |_| async { Ok(()) })
            .await
            .unwrap();
        generate_with(
            &registry,
            KeyType::Ed25519,
            "21",
            Ok(ed_answer(&e)),
            &destroyed,
        )
        .await
        .unwrap();
        assert_eq!(
            registry.get(&handle).unwrap().unwrap().key,
            RegisteredKey::Ed25519(e.verifying_key())
        );
    }

    /// B1/B2: the slot life cycle. A destroyed handle is `KeyNotFound` for
    /// every lookup and for a second destroy, with no host call; a generation
    /// may take over a destroyed or destroying id, and the destroy in flight
    /// then leaves that new entry alone, whether it succeeds or fails.
    #[tokio::test]
    async fn slot_life_cycle() {
        let registry = CallbackKeyRegistry::new();
        let h = KeyHandle::new(21);
        let x = RegisteredKey::X25519([3; 32]);
        live(&registry, 21, x.clone(), KeyRole::Operational);

        destroy_key(&registry, &h, |_| async { Ok(()) })
            .await
            .unwrap();
        assert!(matches!(slot(&registry, 21), Some(Slot::Destroyed)));
        assert!(matches!(registry.get(&h), Err(PlatformError::KeyNotFound)));
        assert!(matches!(
            destroy_key(&registry, &h, |_| async {
                panic!("no second host destroy")
            })
            .await,
            Err(PlatformError::KeyNotFound)
        ));
        assert!(matches!(
            sign(
                &registry,
                &h,
                b"d",
                |_, _| async { panic!("no sign") },
                no_lookup
            )
            .await,
            Err(PlatformError::KeyNotFound)
        ));
        assert!(matches!(
            registry.bind_resolved(h, x.clone(), HostRole::Operational),
            Err(PlatformError::KeyNotFound)
        ));

        // A generation takes over the id during a destroy that then
        // succeeds, and during one that then fails.
        for host_ok in [true, false] {
            let registry = CallbackKeyRegistry::new();
            live(&registry, 21, x.clone(), KeyRole::Operational);
            let e = RegisteredKey::Ed25519(ed(0xE1).verifying_key());
            let result = destroy_key(&registry, &h, |_| {
                registry
                    .register(h, RegisteredEntry::minted(e.clone(), KeyRole::Operational))
                    .unwrap();
                async move {
                    if host_ok {
                        Ok(())
                    } else {
                        Err(PlatformError::CustodyError("host destroy failed".into()))
                    }
                }
            })
            .await;
            assert_eq!(result.is_ok(), host_ok);
            assert_eq!(registry.get(&h).unwrap().unwrap().key, e);
        }
    }

    /// B3: the host destroy closure calls `public_key` on the same handle
    /// before it returns. The handle is `KeyNotFound` with no host lookup,
    /// and nothing is written back; afterwards a failed destroy restores the
    /// entry (or clears the marker of an unknown handle) and a successful one
    /// leaves the tombstone. Both a registered and an unknown handle.
    #[tokio::test]
    async fn destroy_and_resolve_race() {
        for registered in [true, false] {
            for host_ok in [true, false] {
                let registry = CallbackKeyRegistry::new();
                let h = KeyHandle::new(33);
                let key = RegisteredKey::P256Signing(p256(0xF1).public_key());
                if registered {
                    live(&registry, 33, key.clone(), KeyRole::Operational);
                }
                let result = destroy_key(&registry, &h, |_| async {
                    assert!(matches!(
                        public_key(&registry, &h, no_lookup).await,
                        Err(PlatformError::KeyNotFound)
                    ));
                    assert!(matches!(slot(&registry, 33), Some(Slot::Destroying { .. })));
                    if host_ok {
                        Ok(())
                    } else {
                        Err(PlatformError::CustodyError("host destroy failed".into()))
                    }
                })
                .await;
                assert_eq!(result.is_ok(), host_ok, "{registered} {host_ok}");
                match (host_ok, registered) {
                    (true, _) => {
                        assert!(matches!(slot(&registry, 33), Some(Slot::Destroyed)));
                        assert!(matches!(
                            public_key(&registry, &h, no_lookup).await,
                            Err(PlatformError::KeyNotFound)
                        ));
                    }
                    (false, true) => {
                        assert_eq!(registry.get(&h).unwrap().unwrap().key, key);
                    }
                    (false, false) => assert!(slot(&registry, 33).is_none()),
                }
            }
        }
    }

    /// G1: a `destroy_key` future dropped while the host destroy is pending
    /// leaves the pseudonym handle `Abandoned`. A later `sign` is
    /// `KeyNotFound` without calling the host, so no unverified host
    /// signature can pass through an unbound handle. A retry whose host
    /// destroy fails leaves it `Abandoned`, not live, because the cancelled
    /// host call may have destroyed the key.
    #[tokio::test]
    async fn cancelled_destroy_leaves_the_handle_fail_closed() {
        let p = p256(0xF2);
        let registry = registry_with_pseudonym(&ed(0xF3), &p).await;
        let h = KeyHandle::new(7);
        let polled = AtomicUsize::new(0);
        {
            let destroy = destroy_key(&registry, &h, |_| async {
                polled.fetch_add(1, Ordering::Relaxed);
                std::future::pending::<Result<(), PlatformError>>().await
            });
            assert!(
                tokio::time::timeout(std::time::Duration::from_millis(10), destroy)
                    .await
                    .is_err(),
                "the host destroy never returns"
            );
        }
        assert_eq!(polled.load(Ordering::Relaxed), 1, "the host call started");
        assert!(matches!(slot(&registry, 7), Some(Slot::Abandoned { .. })));

        let host_signs = AtomicUsize::new(0);
        let junk = |_: String, _: Vec<u8>| {
            host_signs.fetch_add(1, Ordering::Relaxed);
            async { Ok(vec![0x55u8; 64]) }
        };
        let answer = p256_answer(&p);
        let lookup = |_: String| {
            let answer = answer.clone();
            async move { Ok(answer) }
        };
        assert!(matches!(
            sign(&registry, &h, &[0x11u8; 32], junk, lookup).await,
            Err(PlatformError::KeyNotFound)
        ));
        assert_eq!(host_signs.load(Ordering::Relaxed), 0);
        assert!(matches!(slot(&registry, 7), Some(Slot::Abandoned { .. })));

        assert!(matches!(
            destroy_key(&registry, &h, |_| async {
                Err(PlatformError::CustodyError("host destroy failed".into()))
            })
            .await,
            Err(PlatformError::CustodyError(_))
        ));
        assert!(matches!(slot(&registry, 7), Some(Slot::Abandoned { .. })));
        assert!(matches!(registry.get(&h), Err(PlatformError::KeyNotFound)));
    }

    /// J1: a cancelled identity destroy retires the identity and every
    /// pseudonym derived from it through the adapter, with no host call, and
    /// a retried destroy calls the host exactly once and completes.
    #[tokio::test]
    async fn cancelled_identity_destroy_retires_its_pseudonyms() {
        let p = p256(0xF4);
        let registry = registry_with_pseudonym(&ed(0xF5), &p).await;
        let identity = KeyHandle::new(1);
        {
            let destroy = destroy_key(&registry, &identity, |_| {
                std::future::pending::<Result<(), PlatformError>>()
            });
            assert!(
                tokio::time::timeout(std::time::Duration::from_millis(10), destroy)
                    .await
                    .is_err(),
                "the host destroy never returns"
            );
        }
        let no_sign = |_: String, _: Vec<u8>| async { panic!("no host sign call") };
        for (id, data) in [(1, &b"message"[..]), (7, &[0x11u8; 32][..])] {
            assert!(
                matches!(
                    sign(&registry, &KeyHandle::new(id), data, no_sign, no_lookup).await,
                    Err(PlatformError::KeyNotFound)
                ),
                "handle {id} must fail after the cancelled identity destroy"
            );
            assert!(matches!(
                public_key(&registry, &KeyHandle::new(id), no_lookup).await,
                Err(PlatformError::KeyNotFound)
            ));
        }

        let host_destroys = AtomicUsize::new(0);
        destroy_key(&registry, &identity, |id| {
            assert_eq!(id, "1");
            host_destroys.fetch_add(1, Ordering::Relaxed);
            async { Ok(()) }
        })
        .await
        .unwrap();
        assert_eq!(host_destroys.load(Ordering::Relaxed), 1);
        assert!(matches!(slot(&registry, 1), Some(Slot::Destroyed)));
        assert!(matches!(slot(&registry, 7), Some(Slot::Destroyed)));
    }

    /// J2: the host reuses an identity's id for a new identity key while
    /// that identity's destroy is in flight. The old identity's pseudonym is
    /// retired, the new key owns none, and the new key stays live.
    #[tokio::test]
    async fn register_over_a_destroying_identity_retires_its_pseudonyms() {
        let p = p256(0xF6);
        let registry = registry_with_pseudonym(&ed(0xF7), &p).await;
        let identity = KeyHandle::new(1);
        let replacement = RegisteredKey::Ed25519(ed(0xF8).verifying_key());
        destroy_key(&registry, &identity, |_| {
            registry
                .register(
                    identity,
                    RegisteredEntry::minted(replacement.clone(), KeyRole::Identity),
                )
                .unwrap();
            async { Ok(()) }
        })
        .await
        .unwrap();
        assert!(
            matches!(
                registry.get(&KeyHandle::new(7)),
                Err(PlatformError::KeyNotFound)
            ),
            "the old identity's pseudonym must be retired"
        );
        let entry = registry.get(&identity).unwrap().unwrap();
        assert_eq!((entry.key, entry.role), (replacement, KeyRole::Identity));
    }

    /// J3: a derive from identity 1 (key A) whose host call returns after id
    /// 1 was destroyed and handed to identity key B fails with
    /// `KeyNotFound`, and the id it returned is not bound.
    #[tokio::test]
    async fn a_derive_racing_an_identity_id_reuse_binds_nothing() {
        let registry = CallbackKeyRegistry::new();
        let identity = KeyHandle::new(1);
        live(
            &registry,
            1,
            RegisteredKey::Ed25519(ed(0xF9).verifying_key()),
            KeyRole::Identity,
        );
        let replacement = RegisteredKey::Ed25519(ed(0xFA).verifying_key());
        let key = p256(0xFB);
        let point = key.public_key().to_compressed().to_vec();
        let result = derive_pseudonym(
            &registry,
            "derive_pseudonym",
            &identity,
            b"ctx",
            None,
            |_| {
                let (registry, replacement) = (&registry, replacement.clone());
                async move {
                    destroy_key(registry, &identity, |_| async { Ok(()) }).await?;
                    registry.register(
                        identity,
                        RegisteredEntry::minted(replacement, KeyRole::Identity),
                    )?;
                    Ok((point, "20".to_owned()))
                }
            },
            |_| {
                let answer = p256_answer(&key);
                async move { Ok(answer) }
            },
        )
        .await;
        assert!(
            matches!(result, Err(PlatformError::KeyNotFound)),
            "{result:?}"
        );
        assert!(registry.get(&KeyHandle::new(20)).unwrap().is_none());
        assert_eq!(registry.get(&identity).unwrap().unwrap().key, replacement);
    }

    /// The software host through the flows: every type generates with the
    /// host's stated type, an Ed25519 identity derives a pseudonym whose
    /// signatures verify, and a destroyed key is gone on both sides.
    #[tokio::test]
    async fn fake_host_round_trip() {
        let host = fake_host::FakeHost::default();
        let host = &host;
        let registry = CallbackKeyRegistry::new();
        let gpk = |id: String| async move { host.get_public_key(&id) };
        let identity = generate_keypair(
            &registry,
            KeyType::Ed25519,
            KeyRole::Identity,
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
            "derive_rotatable_pseudonym",
            &identity,
            b"ctx",
            Some(2),
            |id| async move { host.derive_pseudonym(&id, b"ctx", Some(2)) },
            gpk,
        )
        .await
        .unwrap();
        let digest = [9u8; 32];
        let psig: [u8; 64] = sign(
            &registry,
            pseudonym.key_handle(),
            &digest,
            |id, data| async move { host.sign(&id, &data) },
            gpk,
        )
        .await
        .unwrap()
        .as_bytes()
        .try_into()
        .unwrap();
        let point = P256PublicKey::from_sec1(pseudonym.public_key().as_bytes()).unwrap();
        verify_prehash_strict(&point, &digest, &psig).unwrap();
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
        generate_keypair(
            &first,
            KeyType::Ed25519,
            role,
            |t, r| async move { host.generate_keypair(t, r) },
            |id: String| async move { host.get_public_key(&id) },
            |id| async move { host.destroy_key(&id) },
        )
        .await
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
        let pseudonym = derive_pseudonym(
            &registry,
            "derive_pseudonym",
            &identity,
            b"ctx",
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
        assert_eq!(
            registry.get(pseudonym.key_handle()).unwrap().unwrap().role,
            pseudonym_role(identity.id(), b"ctx", None)
        );
        assert_eq!(host.calls("derive_pseudonym"), 1);
    }

    /// An operational key a host minted in an earlier session resolves as
    /// operational in a new registry, and its derive is refused before any
    /// host derive call.
    #[tokio::test]
    async fn an_earlier_sessions_operational_key_cannot_derive() {
        let host = fake_host::FakeHost::default();
        let host = &host;
        let operational = mint_on(host, KeyRole::Operational).await;

        let registry = CallbackKeyRegistry::new();
        let result = derive_pseudonym(
            &registry,
            "derive_pseudonym",
            &operational,
            b"ctx",
            None,
            |id| async move { host.derive_pseudonym(&id, b"ctx", None) },
            |id: String| async move { host.get_public_key(&id) },
        )
        .await;
        assert!(
            matches!(result, Err(PlatformError::WrongKeyType { .. })),
            "{result:?}"
        );
        assert_eq!(
            registry.get(&operational).unwrap().unwrap().role,
            KeyRole::Operational
        );
        assert_eq!(host.calls("derive_pseudonym"), 0);
    }

    /// A host whose answer changes a registered key's role, or reports a
    /// derived pseudonym as an identity, is refused.
    #[tokio::test]
    async fn a_changed_or_identity_pseudonym_role_is_refused() {
        let host = fake_host::FakeHost::default();
        let host = &host;
        let registry = CallbackKeyRegistry::new();
        let identity = generate_keypair(
            &registry,
            KeyType::Ed25519,
            KeyRole::Identity,
            |t, r| async move { host.generate_keypair(t, r) },
            |id: String| async move { host.get_public_key(&id) },
            |id| async move { host.destroy_key(&id) },
        )
        .await
        .unwrap();
        let demoted = |id: String| async move {
            host.get_public_key(&id).map(|a| HostPublicKey {
                role: "operational".to_owned(),
                ..a
            })
        };
        assert!(matches!(
            public_key(&registry, &identity, demoted).await,
            Err(PlatformError::CustodyError(_))
        ));

        let identity_id = identity.id().to_string();
        let promoting = |id: String| {
            let promote = id != identity_id;
            async move {
                host.get_public_key(&id)
                    .map(|a| if promote { as_identity(a) } else { a })
            }
        };
        let result = derive_pseudonym(
            &registry,
            "derive_pseudonym",
            &identity,
            b"ctx",
            None,
            |id| async move { host.derive_pseudonym(&id, b"ctx", None) },
            promoting,
        )
        .await;
        assert!(
            matches!(result, Err(PlatformError::PseudonymRejected(_))),
            "{result:?}"
        );
    }

    /// A caller that drops `generate_keypair` between the host's mint
    /// and its `get_public_key` leaves the minted id queued, and the next
    /// generation destroys it on the host before minting.
    #[tokio::test]
    async fn a_dropped_generation_is_swept_by_the_next() {
        use std::pin::pin;
        use std::task::{Context, Poll, Waker};

        let host = fake_host::FakeHost::default();
        let host = &host;
        let registry = CallbackKeyRegistry::new();
        {
            let mut fut = pin!(generate_keypair(
                &registry,
                KeyType::Ed25519,
                KeyRole::Identity,
                |t, r| async move { host.generate_keypair(t, r) },
                |_: String| std::future::pending::<Result<HostPublicKey, PlatformError>>(),
                |id| async move { host.destroy_key(&id) },
            ));
            let mut cx = Context::from_waker(Waker::noop());
            assert!(matches!(fut.as_mut().poll(&mut cx), Poll::Pending));
        }
        assert!(host.holds("1"), "the host minted key 1");
        assert_eq!(registry.orphans(), vec!["1".to_owned()]);
        assert!(registry.get(&KeyHandle::new(1)).unwrap().is_none());

        generate_keypair(
            &registry,
            KeyType::Ed25519,
            KeyRole::Operational,
            |t, r| async move { host.generate_keypair(t, r) },
            |id: String| async move { host.get_public_key(&id) },
            |id| async move { host.destroy_key(&id) },
        )
        .await
        .unwrap();
        assert!(!host.holds("1"), "the sweep destroyed the orphan");
        assert!(registry.orphans().is_empty());
    }

    /// A registry whose lock a panic poisoned still queues an orphan, so an
    /// orphan guard dropped then loses no host key id, and every other
    /// registry call still fails closed.
    #[test]
    fn a_poisoned_registry_still_queues_an_orphan() {
        let registry = CallbackKeyRegistry::new();
        let poisoner = std::thread::scope(|s| {
            s.spawn(|| {
                let _held = registry.slots.lock();
                std::panic::resume_unwind(Box::new("poison the registry lock"));
            })
            .join()
        });
        assert!(poisoner.is_err());
        assert!(registry.slots.is_poisoned());
        registry.queue_orphan("9".to_owned());
        let queued = registry
            .slots
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .orphans
            .clone();
        assert_eq!(queued, vec!["9".to_owned()]);
        assert!(matches!(
            registry.pop_orphan(),
            Err(PlatformError::CustodyError(_))
        ));
    }

    /// A sweep whose host destroy fails keeps the orphan queued and
    /// fails the generation before any mint; a host that no longer holds the
    /// key counts as destroyed.
    #[tokio::test]
    async fn a_failed_sweep_keeps_the_orphan_and_mints_nothing() {
        let registry = CallbackKeyRegistry::new();
        registry.queue_orphan("7".to_owned());
        registry.queue_orphan("8".to_owned());
        let result = generate_keypair(
            &registry,
            KeyType::Ed25519,
            KeyRole::Operational,
            |_, _| async { panic!("no mint while an orphan is undestroyed") },
            |_: String| async { panic!("no lookup") },
            |id| async move {
                if id == "8" {
                    Err(PlatformError::CustodyError("host busy".into()))
                } else {
                    Err(PlatformError::KeyNotFound)
                }
            },
        )
        .await;
        assert!(
            matches!(result, Err(PlatformError::CustodyError(_))),
            "{result:?}"
        );
        assert_eq!(registry.orphans(), vec!["7".to_owned(), "8".to_owned()]);

        sweep_orphans(&registry, &|id: String| async move {
            if id == "8" {
                Ok(())
            } else {
                Err(PlatformError::KeyNotFound)
            }
        })
        .await
        .unwrap();
        assert!(registry.orphans().is_empty());
    }

    /// A rejected key whose destroy fails is queued for the next sweep.
    #[tokio::test]
    async fn a_rejected_key_whose_destroy_fails_is_queued() {
        let registry = CallbackKeyRegistry::new();
        let result = generate_keypair(
            &registry,
            KeyType::Ed25519,
            KeyRole::Operational,
            |_, _| async { Ok("not-a-number".to_owned()) },
            |_: String| async { panic!("no lookup for a non-numeric id") },
            |_| async { Err(PlatformError::CustodyError("host busy".into())) },
        )
        .await;
        assert!(matches!(result, Err(PlatformError::CustodyError(_))));
        assert_eq!(registry.orphans(), vec!["not-a-number".to_owned()]);
    }
}
