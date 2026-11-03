//! The four storage quota classes (`09-security-model.md` §9.18.B, §9.10.12
//! "The quota classes").
//!
//! Each class is keyed on routing id and keeps no stored value: a node
//! counts the blobs of the class it holds at the routing id from its blob
//! store when a write arrives, so no counter can drift from what is stored.
//! A quota applies to the validated selection and never to raw writes
//! (§9.10.12): the retained class is charged with what the selection keeps
//! after the write, the record the write adds included.

use scp_relay_client::code;
use scp_transport::native::public_records::PublicRecordRefusal;
use scp_transport::native::storage::{StoredBlob, StoredLifetime};

/// One of the four quota classes (§9.18.B).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum QuotaClass {
    /// The five retained kinds: `scp:did:`, `scp:svc:`, `scp:wit:`,
    /// `scp:wcf:` and `scp:nls:` records.
    RetainedPublicRecords,
    /// `KeyPackage` sets (§9.7.4).
    KeyPackageSets,
    /// Identity private state (`03-identity.md` §3.7).
    IdentityPrivateState,
    /// Blobs under the shared TTL, the only class that carries a TTL.
    TtlBlobs,
}

impl QuotaClass {
    /// Every class, in §9.18.B's order.
    pub const ALL: [Self; 4] = [
        Self::RetainedPublicRecords,
        Self::KeyPackageSets,
        Self::IdentityPrivateState,
        Self::TtlBlobs,
    ];

    /// The class a stored blob is charged to.
    ///
    /// A node stores `KeyPackage` sets and identity private state through no
    /// path yet, so every stored blob is a retained record or a TTL blob.
    // Stub — see SCP-374 (KeyPackage sets) and SCP-373 (identity private
    // state): each charges its own class once it stores through this store.
    #[must_use]
    pub const fn of(stored: &StoredBlob) -> Self {
        match stored.lifetime {
            StoredLifetime::Retained => Self::RetainedPublicRecords,
            StoredLifetime::Ttl(_) => Self::TtlBlobs,
        }
    }
}

/// The bound one class puts on the blobs one routing id holds.
///
/// §9.18.B sets no default value: a class is [`Unbounded`](Self::Unbounded)
/// until the operator declares a bound.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum QuotaLimit {
    /// The operator declared no bound.
    Unbounded,
    /// At most this many blobs of the class at one routing id.
    Blobs(u32),
}

impl QuotaLimit {
    /// Whether `held` blobs fit under the bound.
    #[must_use]
    pub fn holds(self, held: usize) -> bool {
        match self {
            Self::Unbounded => true,
            Self::Blobs(limit) => usize::try_from(limit).is_ok_and(|limit| held <= limit),
        }
    }
}

/// The operator's bound for each class, per routing id (§9.18.B).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct QuotaLimits {
    /// Retained public records per routing id.
    pub retained_public_records: QuotaLimit,
    /// `KeyPackage` sets per routing id.
    pub key_package_sets: QuotaLimit,
    /// Identity private-state blobs per routing id.
    pub identity_private_state: QuotaLimit,
    /// TTL-bearing blobs per routing id.
    pub ttl_blobs: QuotaLimit,
}

impl QuotaLimits {
    /// Every class [`QuotaLimit::Unbounded`], §9.18.B's "No value set".
    pub const UNBOUNDED: Self = Self {
        retained_public_records: QuotaLimit::Unbounded,
        key_package_sets: QuotaLimit::Unbounded,
        identity_private_state: QuotaLimit::Unbounded,
        ttl_blobs: QuotaLimit::Unbounded,
    };

    /// The bound on `class`.
    #[must_use]
    pub const fn limit(&self, class: QuotaClass) -> QuotaLimit {
        match class {
            QuotaClass::RetainedPublicRecords => self.retained_public_records,
            QuotaClass::KeyPackageSets => self.key_package_sets,
            QuotaClass::IdentityPrivateState => self.identity_private_state,
            QuotaClass::TtlBlobs => self.ttl_blobs,
        }
    }

    /// Charges a write that leaves `held_after` blobs of `class` at one
    /// routing id.
    ///
    /// # Errors
    ///
    /// ADR-004's `5001` when the class's bound cannot hold them; the caller
    /// then writes nothing, so no class's count moves.
    pub fn charge(&self, class: QuotaClass, held_after: usize) -> Result<(), PublicRecordRefusal> {
        if self.limit(class).holds(held_after) {
            Ok(())
        } else {
            Err(PublicRecordRefusal::new(
                code::STORAGE_FULL,
                format!("the {class:?} quota of this routing id is full"),
            ))
        }
    }
}

impl Default for QuotaLimits {
    fn default() -> Self {
        Self::UNBOUNDED
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits_with(class: QuotaClass, limit: QuotaLimit) -> QuotaLimits {
        let mut limits = QuotaLimits::UNBOUNDED;
        match class {
            QuotaClass::RetainedPublicRecords => limits.retained_public_records = limit,
            QuotaClass::KeyPackageSets => limits.key_package_sets = limit,
            QuotaClass::IdentityPrivateState => limits.identity_private_state = limit,
            QuotaClass::TtlBlobs => limits.ttl_blobs = limit,
        }
        limits
    }

    /// One bounded class refuses the write past its bound with `5001` and
    /// still admits a write at its bound, while every other class stays
    /// unbounded: the bound of one class reads only that class.
    fn a_full_class_refuses_and_leaves_the_others(class: QuotaClass) {
        let limits = limits_with(class, QuotaLimit::Blobs(2));
        assert_eq!(limits.charge(class, 2), Ok(()), "{class:?} holds two");
        assert_eq!(
            limits.charge(class, 3).map_err(|refused| refused.code()),
            Err(code::STORAGE_FULL),
            "{class:?} refuses a third",
        );
        for other in QuotaClass::ALL.into_iter().filter(|other| *other != class) {
            assert_eq!(limits.limit(other), QuotaLimit::Unbounded, "{other:?}");
            assert_eq!(limits.charge(other, 1_000), Ok(()), "{other:?}");
        }
    }

    #[test]
    fn the_retained_public_record_class_refuses_past_its_bound() {
        a_full_class_refuses_and_leaves_the_others(QuotaClass::RetainedPublicRecords);
    }

    // Stub — see SCP-374: no write charges this class until KeyPackage sets
    // are stored, so this test reaches the class's bound directly.
    #[test]
    fn the_key_package_set_class_refuses_past_its_bound() {
        a_full_class_refuses_and_leaves_the_others(QuotaClass::KeyPackageSets);
    }

    // Stub — see SCP-373: no write charges this class until identity
    // private state is stored, so this test reaches the class's bound
    // directly.
    #[test]
    fn the_identity_private_state_class_refuses_past_its_bound() {
        a_full_class_refuses_and_leaves_the_others(QuotaClass::IdentityPrivateState);
    }

    #[test]
    fn the_ttl_blob_class_refuses_past_its_bound() {
        a_full_class_refuses_and_leaves_the_others(QuotaClass::TtlBlobs);
    }

    #[test]
    fn a_zero_bound_refuses_the_first_blob() {
        assert!(QuotaLimit::Blobs(0).holds(0));
        assert!(!QuotaLimit::Blobs(0).holds(1));
        assert!(QuotaLimit::Unbounded.holds(usize::MAX));
    }
}
