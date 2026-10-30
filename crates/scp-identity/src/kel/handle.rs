//! The identity handle `Identity::create` returns (`03-identity.md`
//! §3.10.10) and the key references it carries.

use std::fmt;

use scp_did::{FixedCommitment, Identifier};
use scp_platform::{EncryptedStorage, KeyHandle};

use super::IdentityConfig;

/// The key references of one key-event-log identity this device holds
/// (`03-identity.md` §3.10.10; `09-security-model.md` §9.7.4.2).
///
/// It carries handles and public values only. The standing commitment is
/// the commitment list and next threshold (`09-security-model.md` §9.7.4.2
/// definitions), never a single digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScpIdentity {
    /// The root member `#0`, a key-event key.
    pub identity_key: KeyHandle,
    /// The `#active` key, a P-256 signing key.
    pub active_signing_key: KeyHandle,
    /// The commitment list and next threshold the identity's latest event
    /// fixed.
    pub pre_rotation_commitment: FixedCommitment,
    /// The inception-derived identifier (`03-identity.md` §3.1).
    pub identifier: Identifier,
}

/// One key-event-log identity this device holds, with the config it was
/// built from (`03-identity.md` §3.10.10).
///
/// No accessor returns key material: the handle names keys its custody
/// holds.
///
/// ```compile_fail,E0599
/// fn secret<S: scp_platform::EncryptedStorage + Clone>(
///     identity: &scp_identity::Identity<S>,
/// ) -> Vec<u8> {
///     identity.identity_key_bytes()
/// }
/// ```
///
/// The positive control:
///
/// ```
/// fn handle<S: scp_platform::EncryptedStorage + Clone>(
///     identity: &scp_identity::Identity<S>,
/// ) -> scp_platform::KeyHandle {
///     identity.scp_identity().identity_key
/// }
/// ```
pub struct Identity<S: EncryptedStorage + Clone> {
    pub(super) config: IdentityConfig<S>,
    pub(super) keys: ScpIdentity,
}

impl<S: EncryptedStorage + Clone> Identity<S> {
    /// The inception-derived identifier (`03-identity.md` §3.1).
    #[must_use]
    pub const fn identifier(&self) -> &Identifier {
        &self.keys.identifier
    }

    /// The key references this device holds for the identity.
    #[must_use]
    pub const fn scp_identity(&self) -> &ScpIdentity {
        &self.keys
    }

    /// The config the handle was built from.
    #[must_use]
    pub const fn config(&self) -> &IdentityConfig<S> {
        &self.config
    }
}

impl<S: EncryptedStorage + Clone> fmt::Debug for Identity<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Identity")
            .field("keys", &self.keys)
            .field("profile", &self.config.profile)
            .finish_non_exhaustive()
    }
}
