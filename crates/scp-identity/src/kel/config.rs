//! What `Identity::create` and `Identity::abandon_pending` take
//! (`03-identity.md` §3.10.10; `.docs/standards/construction.md`).

use scp_did::CustodyProfile;
use scp_platform::EncryptedStorage;

use super::slot::{KeyCustodySlot, NextSetCustodySlot};

/// What [`Identity::create`](super::Identity::create) and
/// [`Identity::abandon_pending`](super::Identity::abandon_pending) take.
///
/// Every field is required, and none has a default
/// (`.docs/standards/construction.md`).
///
/// A config without its next-set custody does not compile
/// (`09-security-model.md` §9.7.4.1 item 3):
///
/// ```compile_fail,E0063
/// use scp_did::CustodyProfile;
/// use scp_identity::{IdentityConfig, KeyCustodySlot};
/// use scp_platform::EncryptedStorage;
///
/// fn config<S: EncryptedStorage + Clone>(
///     custody: KeyCustodySlot,
///     persistence: S,
/// ) -> IdentityConfig<S> {
///     IdentityConfig { custody, persistence, profile: CustodyProfile::Desktop }
/// }
/// ```
///
/// The positive control:
///
/// ```
/// use scp_did::CustodyProfile;
/// use scp_identity::{IdentityConfig, KeyCustodySlot, NextSetCustodySlot};
/// use scp_platform::EncryptedStorage;
///
/// fn config<S: EncryptedStorage + Clone>(
///     custody: KeyCustodySlot,
///     next_set_custody: NextSetCustodySlot,
///     persistence: S,
/// ) -> IdentityConfig<S> {
///     IdentityConfig { custody, next_set_custody, persistence, profile: CustodyProfile::Desktop }
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
}
