//! The identity error of the key-event-log identity model
//! (`03-identity.md` §3.10.10).
//!
//! The type carries twenty-two variants and no others. Their codes take
//! `SCP-IDENT-1100` through `SCP-IDENT-1122`; `SCP-IDENT-1105` is reserved and
//! names no variant. The superseded `did:dht` model's error is
//! [`crate::dht::IdentityError`], whose codes sit in `SCP-IDENT-1000` through
//! `SCP-IDENT-1099` (`.docs/standards/sdk-common.md` §Error code format).

use scp_did::IdentifierError;
use scp_kel::{CheckStep, InceptionRefusal};
use scp_platform::{KeyHandle, NextSetKeyHandle};

use super::creation_record::CreationId;
use super::unfinished::KeptComposition;

/// The error half of `IdentityBackend`'s six methods, of `Identity`'s write
/// API, and of the three recovery entry points `09-security-model.md`
/// §9.7.4.2 R10 declares (`03-identity.md` §3.10.10).
///
/// A refusal the protocol mandates carries one of these variants, so the
/// four bindings mint one code rather than four, and a caller tells a custody
/// choice from a network condition. [`IdentityError::code`] returns each
/// variant's registered code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum IdentityError {
    /// SCP-IDENT-1100. No substrate satisfies the independent-residence
    /// requirement of `09-security-model.md` §9.7.4.1 item 3a, so identity
    /// creation and every later reveal fail closed.
    #[error(
        "no substrate satisfies the independent-residence requirement for next-set keys \
         (security model 9.7.4.1 item 3a), so identity creation fails closed"
    )]
    NoIndependentSubstrate,

    /// SCP-IDENT-1101. The SDK holds a threshold of the standing root, so it
    /// refuses to sign `standing_root: Lost` (§9.7.4.2 R3).
    #[error(
        "this SDK holds a threshold of the standing root, so it refuses to sign standing_root Lost"
    )]
    RootThresholdHeld,

    /// SCP-IDENT-1102. The SDK can reach no source in the fallback set, so it
    /// refuses to compose a reveal-authorized event (§9.7.4.2 R10).
    #[error(
        "no source in the fallback set is reachable, so no reveal-authorized event is composed"
    )]
    NoFallbackSourceReachable,

    /// SCP-IDENT-1103. The SDK can observe, in a member of the store set, an
    /// unpublished reveal-authorized event or a pending `RecoveryHandle` for
    /// this identity; or its adopted log already reveals the commitment the
    /// event would reveal; or its handle vanished or changed digest before it
    /// signed or published; or, as a cosigner, it recorded a commitment the
    /// event reveals (`09-security-model.md` §9.7.4.2 R10).
    #[error("a reveal-authorized event for this identity is already pending or already adopted")]
    RevealAlreadyPending,

    /// SCP-IDENT-1104. The verifier could not persist a contested verdict, its
    /// retained suffixes, or the accepted-head baseline (§9.7.4.2 R14), or a
    /// device could not read or write its device record
    /// (`17-persistence-and-storage.md` §17.3).
    #[error(
        "a verdict, retained suffix, accepted-head baseline or device record could not be persisted"
    )]
    PersistFailed,

    /// SCP-IDENT-1106. A string reached an admission gate that is not the
    /// canonical form of an inception-derived identifier (§3.1).
    #[error("the string is not the canonical form of an inception-derived identifier")]
    NonCanonicalIdentifier,

    /// SCP-IDENT-1107. `abort_recovery` found the signed event in the device's
    /// own store, so it refused to clear the handle; `resume_recovery`
    /// completes the ceremony (`09-security-model.md` §9.7.4.2 R10).
    #[error("the signed reveal-authorized event is unpublished; resume_recovery completes it")]
    SignedRevealUnpublished,

    /// SCP-IDENT-1108. The SDK did not reach every member of a non-empty store
    /// set, whether it reached some members or none, so it refused to compose
    /// a reveal-authorized event (`09-security-model.md` §9.7.4.2 R10).
    #[error("a member of the store set is unreadable, so no reveal-authorized event is composed")]
    StorePartiallyUnreadable,

    /// SCP-IDENT-1109. A passkey gesture was cancelled or failed while the SDK
    /// signed a key event (`09-security-model.md` §9.7.4.2 R10).
    #[error("the user-verification gesture was cancelled or failed while signing a key event")]
    UserVerificationDeclined,

    /// SCP-IDENT-1110. `resume_recovery` found a handle past `Composed` and no
    /// signed event in any store it reaches (`09-security-model.md` §9.7.4.2 R10).
    #[error("the recovery handle is past Composed and no store holds its signed event")]
    RecoveryPreimageMissing,

    /// SCP-IDENT-1111. The custody backend returned an error while the SDK
    /// generated, signed with or destroyed a key-event key, or a next-set
    /// custody's probe signature did not verify (`09-security-model.md`
    /// §9.7.4.1 item 5, §9.7.4.2 R10).
    #[error(
        "the custody backend failed while generating, signing with or destroying a key-event key"
    )]
    CustodySigningFailed,

    /// SCP-IDENT-1112. `Identity::attach` received signatures that fall short
    /// of a group the event's `SignerPlan` names (§3.10.10).
    #[error("the signatures fall short of a signer group the event's SignerPlan names")]
    SignatureSetIncomplete,

    /// SCP-IDENT-1113. The adopted log does not hold the event the store
    /// set's last-reveal marker names, and no entry of the publication set
    /// served it (`09-security-model.md` §9.7.4.2 R10).
    #[error(
        "the last-reveal event at sequence {sequence} (digest {}) is not adopted and no entry served it",
        hex::encode(.event_digest)
    )]
    LastRevealUnadopted {
        /// The sequence the store set's last-reveal marker names.
        sequence: u64,
        /// The event digest the store set's last-reveal marker names.
        event_digest: [u8; 32],
    },

    /// SCP-IDENT-1114. A `PendingEvent`'s `event_digest` differs from the
    /// SHA-256 of its `preimage` (§3.10.10).
    #[error("the pending event's digest differs from the SHA-256 of its preimage")]
    PendingDigestMismatch,

    /// SCP-IDENT-1115. A root set or next set of more than one member carries
    /// a threshold at or below half its size (`09-security-model.md` §9.7.4.1).
    #[error("a key set of more than one member carries a threshold at or below half its size")]
    ThresholdAdmitsDisjointQuorums,

    /// SCP-IDENT-1116. An SDK entry point that creates an identity received no
    /// custody argument. The Python and TypeScript SDKs raise it before any
    /// bridge call; the Swift and Kotlin SDKs require the argument at compile
    /// time.
    #[error("an identity-creating entry point received no custody argument")]
    CustodyRequired,

    /// SCP-IDENT-1117. The candidate key event fails R3's check order, or R2
    /// for an inception, at `stage`, so no device signs it; or the recovery
    /// ceremony's confirm check found the signed event's copy failing with a
    /// failure that is not an illegality failure (R3), so the ceremony
    /// destroyed nothing (`09-security-model.md` §9.7.4.2 R10).
    #[error("the candidate key event fails the check order at stage {stage:?}")]
    IllegalKeyEvent {
        /// The step of R3's check order at which the event failed.
        stage: CheckStep,
    },

    /// SCP-IDENT-1118. The chain a signing device was handed ends at
    /// `handed_head`, and the head that device holds is `held_head`, so a
    /// signature would fork the identity's own chain
    /// (`09-security-model.md` §9.7.4.2 R10).
    #[error(
        "the handed chain ends at {} but this device holds {}, so a signature would fork the chain",
        hex::encode(.handed_head),
        hex::encode(.held_head)
    )]
    SigningBaseStale {
        /// The head of the chain the signing device was handed.
        handed_head: [u8; 32],
        /// The head the signing device holds.
        held_head: [u8; 32],
    },

    /// SCP-IDENT-1119. The device holds a `PendingSignatureRecord` naming
    /// `event_digest` at `sequence`, and the candidate is a different event at
    /// that sequence, so a signature would fork the identity's own chain until
    /// the record clears (`09-security-model.md` §9.7.4.2 R10).
    #[error(
        "this device holds a pending signature for event {} at sequence {sequence}",
        hex::encode(.event_digest)
    )]
    SignaturePending {
        /// The sequence the device's `PendingSignatureRecord` names.
        sequence: u64,
        /// The event digest the device's `PendingSignatureRecord` names.
        event_digest: [u8; 32],
    },

    /// SCP-IDENT-1120. `abandon_pending` named an event for which this
    /// device holds neither a `PendingSignatureRecord` nor a `KeptComposition`,
    /// so nothing cleared, or `attach` was handed an event that is not
    /// reveal-authorized and whose `KeptComposition` this device does not
    /// hold, so nothing was published (`09-security-model.md` §9.7.4.2 R10).
    #[error(
        "this device holds no pending signature or kept composition for event {}",
        hex::encode(.event_digest)
    )]
    NoPendingSignature {
        /// The event digest the call named.
        event_digest: [u8; 32],
    },

    /// SCP-IDENT-1121. The method of the next-set custody `create` was handed
    /// does not conform on the config's `CustodyProfile`, while another
    /// method is offered on that profile, so `create` generated no key
    /// (`09-security-model.md` §9.7.4.1 item 4). Where no method is offered
    /// on the profile, `create` returns
    /// [`NoIndependentSubstrate`](Self::NoIndependentSubstrate) instead.
    #[error(
        "the next-set custody's method does not conform on this custody profile, \
         and another method is offered there"
    )]
    MethodNotOfferedOnProfile,

    /// SCP-IDENT-1122. `abandon_unfinished` named a creation for which the
    /// store holds no creation record (`17-persistence-and-storage.md`
    /// §17.3), so nothing was destroyed.
    #[error("the store holds no creation record for the named creation")]
    NoUnfinishedCreation,
}

/// Why [`Identity::create`](super::Identity::create) failed
/// (`03-identity.md` §3.10.10).
///
/// `error` is the failing step's own error. `cleanup` is `Some` where the
/// cleanup after that failure left a key live or the creation record in
/// place; the creation then stays listed by
/// [`Identity::unfinished`](super::Identity::unfinished), and
/// [`Identity::abandon_unfinished`](super::Identity::abandon_unfinished)
/// finishes the cleanup.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("identity creation failed: {error}")]
pub struct CreateError {
    /// The error of the step that failed.
    #[source]
    pub error: IdentityError,
    /// The cleanup that did not complete, if any, boxed so the error stays
    /// small on the success path.
    pub cleanup: Option<Box<CleanupFailure>>,
}

impl From<IdentityError> for CreateError {
    /// A failure before any key exists, which leaves nothing to clean up.
    fn from(error: IdentityError) -> Self {
        Self {
            error,
            cleanup: None,
        }
    }
}

/// A cleanup after a failed `create` that did not complete
/// (`17-persistence-and-storage.md` §17.3; `03-identity.md` §3.10.10).
/// [`Identity::unfinished`](super::Identity::unfinished) lists what it names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CleanupFailure {
    /// The cleanup ran, and left keys live or the creation record in place.
    Incomplete {
        /// The creation whose record still names every key in `undestroyed`.
        creation: CreationId,
        /// Every key the cleanup failed to destroy. Empty where every key
        /// was destroyed and only the record's removal failed.
        undestroyed: Vec<UndestroyedKey>,
    },
    /// The runtime cancelled `create`'s task, so no cleanup ran, and every
    /// key in `minted` may be live.
    NotAttempted {
        /// The creation whose record names each key it had recorded, unless
        /// the device record superseded it.
        creation: CreationId,
        /// The inception's composition where the device record was written;
        /// that record then names every key.
        composition: Option<KeptComposition>,
        /// Every key the composition minted.
        minted: Vec<UndestroyedKey>,
    },
}

/// One key a destroy pass failed to destroy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UndestroyedKey {
    /// A next-set member, held by the config's `next_set_custody`.
    NextSetMember(NextSetKeyHandle),
    /// A root member or `#active`, held by the config's `custody`.
    Key(KeyHandle),
}

impl From<IdentifierError> for IdentityError {
    /// A string that is not the canonical identifier form is
    /// [`NonCanonicalIdentifier`](Self::NonCanonicalIdentifier), SCP-IDENT-1106
    /// (`03-identity.md` §3.1).
    fn from(error: IdentifierError) -> Self {
        match error {
            IdentifierError::NonCanonicalIdentifier { .. } => Self::NonCanonicalIdentifier,
        }
    }
}

impl From<InceptionRefusal> for IdentityError {
    /// An inception that fails R2 or R3's check order is
    /// [`IllegalKeyEvent`](Self::IllegalKeyEvent) at the failing step,
    /// SCP-IDENT-1117 (`09-security-model.md` §9.7.4.2 R10).
    fn from(refusal: InceptionRefusal) -> Self {
        Self::IllegalKeyEvent {
            stage: refusal.stage(),
        }
    }
}

impl IdentityError {
    /// The registered `SCP-IDENT-` code of this variant
    /// (`03-identity.md` §3.10.10). `SCP-IDENT-1105` is reserved and no
    /// variant returns it.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::NoIndependentSubstrate => "SCP-IDENT-1100",
            Self::RootThresholdHeld => "SCP-IDENT-1101",
            Self::NoFallbackSourceReachable => "SCP-IDENT-1102",
            Self::RevealAlreadyPending => "SCP-IDENT-1103",
            Self::PersistFailed => "SCP-IDENT-1104",
            Self::NonCanonicalIdentifier => "SCP-IDENT-1106",
            Self::SignedRevealUnpublished => "SCP-IDENT-1107",
            Self::StorePartiallyUnreadable => "SCP-IDENT-1108",
            Self::UserVerificationDeclined => "SCP-IDENT-1109",
            Self::RecoveryPreimageMissing => "SCP-IDENT-1110",
            Self::CustodySigningFailed => "SCP-IDENT-1111",
            Self::SignatureSetIncomplete => "SCP-IDENT-1112",
            Self::LastRevealUnadopted { .. } => "SCP-IDENT-1113",
            Self::PendingDigestMismatch => "SCP-IDENT-1114",
            Self::ThresholdAdmitsDisjointQuorums => "SCP-IDENT-1115",
            Self::CustodyRequired => "SCP-IDENT-1116",
            Self::IllegalKeyEvent { .. } => "SCP-IDENT-1117",
            Self::SigningBaseStale { .. } => "SCP-IDENT-1118",
            Self::SignaturePending { .. } => "SCP-IDENT-1119",
            Self::NoPendingSignature { .. } => "SCP-IDENT-1120",
            Self::MethodNotOfferedOnProfile => "SCP-IDENT-1121",
            Self::NoUnfinishedCreation => "SCP-IDENT-1122",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One value of every variant. The exhaustive match in `variant_count`
    /// fails to compile when a variant is added without a row here.
    fn every_variant() -> Vec<IdentityError> {
        vec![
            IdentityError::NoIndependentSubstrate,
            IdentityError::RootThresholdHeld,
            IdentityError::NoFallbackSourceReachable,
            IdentityError::RevealAlreadyPending,
            IdentityError::PersistFailed,
            IdentityError::NonCanonicalIdentifier,
            IdentityError::SignedRevealUnpublished,
            IdentityError::StorePartiallyUnreadable,
            IdentityError::UserVerificationDeclined,
            IdentityError::RecoveryPreimageMissing,
            IdentityError::CustodySigningFailed,
            IdentityError::SignatureSetIncomplete,
            IdentityError::LastRevealUnadopted {
                sequence: 3,
                event_digest: [7; 32],
            },
            IdentityError::PendingDigestMismatch,
            IdentityError::ThresholdAdmitsDisjointQuorums,
            IdentityError::CustodyRequired,
            IdentityError::IllegalKeyEvent {
                stage: CheckStep::Content,
            },
            IdentityError::SigningBaseStale {
                handed_head: [1; 32],
                held_head: [2; 32],
            },
            IdentityError::SignaturePending {
                sequence: 4,
                event_digest: [3; 32],
            },
            IdentityError::NoPendingSignature {
                event_digest: [5; 32],
            },
            IdentityError::MethodNotOfferedOnProfile,
            IdentityError::NoUnfinishedCreation,
        ]
    }

    const fn variant_count(e: &IdentityError) -> usize {
        match e {
            IdentityError::NoIndependentSubstrate
            | IdentityError::RootThresholdHeld
            | IdentityError::NoFallbackSourceReachable
            | IdentityError::RevealAlreadyPending
            | IdentityError::PersistFailed
            | IdentityError::NonCanonicalIdentifier
            | IdentityError::SignedRevealUnpublished
            | IdentityError::StorePartiallyUnreadable
            | IdentityError::UserVerificationDeclined
            | IdentityError::RecoveryPreimageMissing
            | IdentityError::CustodySigningFailed
            | IdentityError::SignatureSetIncomplete
            | IdentityError::LastRevealUnadopted { .. }
            | IdentityError::PendingDigestMismatch
            | IdentityError::ThresholdAdmitsDisjointQuorums
            | IdentityError::CustodyRequired
            | IdentityError::IllegalKeyEvent { .. }
            | IdentityError::SigningBaseStale { .. }
            | IdentityError::SignaturePending { .. }
            | IdentityError::NoPendingSignature { .. }
            | IdentityError::MethodNotOfferedOnProfile
            | IdentityError::NoUnfinishedCreation => 22,
        }
    }

    #[test]
    fn codes_cover_1100_through_1122_without_1105() {
        let variants = every_variant();
        assert_eq!(variants.len(), variant_count(&IdentityError::PersistFailed));
        let mut codes: Vec<&str> = variants.iter().map(IdentityError::code).collect();
        codes.sort_unstable();
        let expected: Vec<String> = (1100..=1122)
            .filter(|n| *n != 1105)
            .map(|n| format!("SCP-IDENT-{n}"))
            .collect();
        assert_eq!(codes, expected);
    }

    #[test]
    fn no_independent_substrate_is_ident_1100() {
        assert_eq!(
            IdentityError::NoIndependentSubstrate.code(),
            "SCP-IDENT-1100"
        );
        assert_ne!(
            IdentityError::NoIndependentSubstrate.code(),
            "SCP-IDENT-1059"
        );
    }

    #[test]
    fn display_names_the_digest_in_hex() {
        let e = IdentityError::NoPendingSignature {
            event_digest: [0xab; 32],
        };
        assert!(e.to_string().contains(&"ab".repeat(32)), "{e}");
    }
}
