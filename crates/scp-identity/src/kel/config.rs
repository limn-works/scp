//! What `Identity::create` and `Identity::abandon_pending` take
//! (`03-identity.md` §3.10.10; `.docs/standards/construction.md`).

use std::sync::Arc;

use scp_did::CustodyProfile;
use scp_platform::EncryptedStorage;

use super::slot::{KeyCustodySlot, NextSetCustodySlot};
use super::witness::WitnessChoice;

/// The config the KERI identity operations take.
///
/// [`Identity::create`](super::Identity::create),
/// [`Identity::abandon_pending`](super::Identity::abandon_pending),
/// [`Identity::unfinished`](super::Identity::unfinished) and
/// [`Identity::abandon_unfinished`](super::Identity::abandon_unfinished)
/// take it.
///
/// Every field is required, and none has a default
/// (`.docs/standards/construction.md`).
///
/// A config without its next-set custody does not compile
/// (`09-security-model.md` §9.7.4.1 item 3):
///
/// ```compile_fail,E0063
/// use scp_did::CustodyProfile;
/// use scp_identity::{IdentityConfig, KeyCustodySlot, RecordLock, WitnessChoice};
/// use scp_platform::EncryptedStorage;
///
/// fn config<S: EncryptedStorage + Clone>(
///     custody: KeyCustodySlot,
///     persistence: S,
/// ) -> IdentityConfig<S> {
///     IdentityConfig {
///         custody,
///         persistence,
///         profile: CustodyProfile::Desktop,
///         witnesses: WitnessChoice::NoWitness,
///         record_lock: RecordLock::new(),
///     }
/// }
/// ```
///
/// Nor does one without its witness choice, which has no default
/// (`09-security-model.md` §9.7.4.3):
///
/// ```compile_fail,E0063
/// use scp_did::CustodyProfile;
/// use scp_identity::{IdentityConfig, KeyCustodySlot, NextSetCustodySlot, RecordLock};
/// use scp_platform::EncryptedStorage;
///
/// fn config<S: EncryptedStorage + Clone>(
///     custody: KeyCustodySlot,
///     next_set_custody: NextSetCustodySlot,
///     persistence: S,
/// ) -> IdentityConfig<S> {
///     IdentityConfig {
///         custody,
///         next_set_custody,
///         persistence,
///         profile: CustodyProfile::Desktop,
///         record_lock: RecordLock::new(),
///     }
/// }
/// ```
///
/// The positive control:
///
/// ```
/// use scp_did::CustodyProfile;
/// use scp_identity::{IdentityConfig, KeyCustodySlot, NextSetCustodySlot, RecordLock, WitnessChoice};
/// use scp_platform::EncryptedStorage;
///
/// fn config<S: EncryptedStorage + Clone>(
///     custody: KeyCustodySlot,
///     next_set_custody: NextSetCustodySlot,
///     persistence: S,
/// ) -> IdentityConfig<S> {
///     IdentityConfig {
///         custody,
///         next_set_custody,
///         persistence,
///         profile: CustodyProfile::Desktop,
///         witnesses: WitnessChoice::NoWitness,
///         record_lock: RecordLock::new(),
///     }
/// }
/// ```
#[derive(Clone)]
pub struct IdentityConfig<S: EncryptedStorage + Clone> {
    /// Holds the root members and `#active`.
    pub custody: KeyCustodySlot,
    /// Holds each next-set member, apart from `custody`
    /// (`09-security-model.md` §9.7.4.1 item 3).
    pub next_set_custody: NextSetCustodySlot,
    /// The device's encrypted store, which holds its device record
    /// (`17-persistence-and-storage.md` §17.3). Required, because `create`
    /// persists the `KeptComposition` before it returns (R10).
    pub persistence: S,
    /// The `CustodyProfile` `09-security-model.md` §9.7.4.1 states, against
    /// which `create` checks the next-set custody's method.
    pub profile: CustodyProfile,
    /// The witness set `create` installs in the inception
    /// (`09-security-model.md` §9.7.4.3).
    pub witnesses: WitnessChoice,
    /// Serializes this process's read-modify-writes of the device and
    /// creation records (`17-persistence-and-storage.md` §17.3). Two configs
    /// over one store share it by copying it.
    pub record_lock: RecordLock,
}

/// The lock every read-modify-write of a device or creation record holds.
///
/// `17-persistence-and-storage.md` §17.3, "Record lock". Clones
/// share one lock. `Storage` offers no compare-and-swap, so it serializes
/// the writers of one process and no others.
#[derive(Debug, Clone)]
pub struct RecordLock(Arc<tokio::sync::Mutex<()>>);

impl RecordLock {
    /// A lock no other config shares yet.
    #[must_use]
    pub fn new() -> Self {
        Self(Arc::new(tokio::sync::Mutex::new(())))
    }

    /// Waits for the lock.
    pub(super) async fn hold(&self) -> tokio::sync::MutexGuard<'_, ()> {
        self.0.lock().await
    }
}

impl Default for RecordLock {
    /// [`RecordLock::new`]: a lock no other config shares yet.
    fn default() -> Self {
        Self::new()
    }
}
