//! [`ValidatedChange`]: an unsigned candidate that passed R3's check order
//! through step 8 against the chain it extends, or R2 for an inception
//! (§9.7.4.2 R10).

use scp_did::{Identifier, KeyEntry};

use super::check::Accepted;
use crate::signature::KEY_EVENT_CHALLENGE_LEN;
use crate::{Continuation, EventKind, InstalledRootSet, SignerGroupRole, key_event_challenge};

/// One member of a signer group's key set: the index a signer names and
/// the key it verifies against.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NamedKey {
    /// The index.
    pub index: u8,
    /// The compressed P-256 key at that index.
    pub key: [u8; 33],
}

/// One signer group of a validated change: the key set it verifies against
/// (§9.7.4.2, *The key set each signer group verifies against*), its
/// threshold, and the indices its signer index list names.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SignerGroupSpec {
    /// The group's role.
    pub role: SignerGroupRole,
    /// The count of verifying signatures the group needs.
    pub threshold: u32,
    /// The key set, by index.
    pub key_set: Vec<NamedKey>,
    /// The indices the signer index list names, in its order.
    pub indices: Vec<u8>,
}

/// What a change does, for a signing device's display (§9.7.4.2 R10).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ChangeEffect {
    /// The event's kind.
    pub kind: EventKind,
    /// The event's sequence.
    pub sequence: u64,
    /// Every key the event installs, as its snapshot lists it.
    pub installed_keys: Vec<KeyEntry>,
    /// Every key the event drops, with the condition it drops it in.
    pub dropped_keys: Vec<KeyEntry>,
    /// The commitment the event fixes, or its abandonment; `None` on a
    /// `KeyState`.
    pub continuation: Option<Continuation>,
    /// The root standing at the predecessor; `None` at the inception.
    pub root_before: Option<InstalledRootSet>,
    /// The root standing after the event.
    pub root_after: InstalledRootSet,
    /// The witness set at the predecessor; `None` at the inception.
    pub witnesses_before: Option<Vec<Identifier>>,
    /// The witness set after the event.
    pub witnesses_after: Vec<Identifier>,
}

/// An unsigned key-event candidate that passed R3's check order through
/// step 8 (§9.7.4.2 R10).
///
/// It passed against the valid chain it extends, or R2 and step 3 for an
/// inception, with sub-check 7a and without the walk, 7b and step 9, which
/// read signatures the candidate does not carry yet.
///
/// Its fields are private, and only
/// [`ValidatedChain::validate_change`](super::ValidatedChain::validate_change)
/// and [`validate_inception`](super::validate_inception) construct it.
///
/// ```compile_fail,E0451
/// # use scp_kel::ValidatedChange;
/// let change = ValidatedChange { digest: [0; 32] };
/// ```
///
/// ```compile_fail,E0599
/// # use scp_kel::ValidatedChange;
/// let change = ValidatedChange::new();
/// ```
///
/// ```compile_fail,E0599
/// # use scp_kel::ValidatedChange;
/// let change = ValidatedChange::default();
/// ```
///
/// The positive control: [`validate_inception`](super::validate_inception)
/// returns one or refuses.
///
/// ```
/// # use scp_kel::{ValidatedChange, validate_inception};
/// let change: Option<ValidatedChange> = validate_inception(b"SCP-KEL-EVENT-V1:").ok();
/// assert!(change.is_none());
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedChange {
    preimage: Vec<u8>,
    digest: [u8; 32],
    signers: Vec<SignerGroupSpec>,
    effect: ChangeEffect,
}

impl ValidatedChange {
    pub(super) fn from_accepted(accepted: Accepted) -> Self {
        Self {
            preimage: accepted.preimage,
            digest: accepted.event.digest,
            signers: accepted.signers,
            effect: accepted.effect,
        }
    }

    /// The signed preimage, separator included, exactly as checked.
    #[must_use]
    pub fn preimage(&self) -> &[u8] {
        &self.preimage
    }

    /// The event digest, `SHA-256` of the signed preimage.
    #[must_use]
    pub const fn digest(&self) -> [u8; 32] {
        self.digest
    }

    /// The `WebAuthn` challenge a passkey signs: `"SCP-KEY-EVENT-V1:" ‖ D`.
    #[must_use]
    pub const fn key_event_challenge(&self) -> [u8; KEY_EVENT_CHALLENGE_LEN] {
        key_event_challenge(&self.digest)
    }

    /// Each signer group's key set, threshold and named indices, in the
    /// header's group order.
    #[must_use]
    pub fn signers(&self) -> &[SignerGroupSpec] {
        &self.signers
    }

    /// What the change does.
    #[must_use]
    pub const fn effect(&self) -> &ChangeEffect {
        &self.effect
    }
}
