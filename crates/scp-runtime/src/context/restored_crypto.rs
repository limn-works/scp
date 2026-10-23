//! A snapshot's MLS crypto on its way back into a member, and the proof that
//! its committed `scp_context_params` (`0xFF02`) binding was verified (spec 05
//! §5.13.3) before anything else used it.
//!
//! Import (`import_context`) and restore (`restore_context`) run four steps
//! after rebuilding the crypto: the `PrepareForReplace` floor gate on a prior
//! actor (import only), the replay-floor merge into the Supervisor-owned
//! registry, the event-log hydrate, and the seed of the owned group onto the
//! fresh actor state. The types below make the order the only one that
//! compiles:
//!
//! 1. [`build_restored_crypto`] yields an opaque [`RestoredCrypto`]. Nothing
//!    reads its group or floors except the verifier.
//! 2. [`VerifiedRestoredCrypto::verify_scp_context_binding`] consumes it and
//!    returns a [`VerifiedRestoredCrypto`] only when the group's `0xFF02`
//!    extension binds the snapshot's identity and parameters. It is the only
//!    constructor of that type.
//! 3. The `PrepareForReplace` gate takes [`VerifiedFloors`], which only
//!    [`VerifiedRestoredCrypto::replace_floors`] yields.
//! 4. [`VerifiedRestoredCrypto::merge_floors`] consumes the verified value,
//!    runs the floor merge, and returns a [`FloorGuardedCrypto`]. The hydrate
//!    step takes `&FloorGuardedCrypto`, and the seed takes the owned group from
//!    [`FloorGuardedCrypto::into_owned`].
//!
//! Every field here is private and no type derives `Default`, `Clone`, or a
//! `From` conversion, so code outside this module cannot construct any of
//! them by struct literal. `#![deny(non_local_definitions)]` turns a second
//! constructor written as an `impl` nested in a function body into a compile
//! error; a top-level second constructor in this file is left to review, as
//! for `supervisor/identity_capability.rs`.
//!
//! [`VerifiedFloors`] is `pub` because it travels in the public
//! `LifecycleControlCommand::PrepareForReplace` variant; its field is private,
//! so being nameable outside the crate does not make it constructible there.

#![deny(non_local_definitions)]

use scp_protocol::context::{ContextError, ContextParams};

use crate::context::actor::deps::ActorDeps;
use crate::crypto::mls::provider::{OwnedMlsCryptoState, RestoredFloors};

/// A snapshot's MLS crypto rebuilt as OWNED material, with the Class-M floors
/// it carried, before its `0xFF02` binding is verified.
///
/// [`build_restored_crypto`] is the only constructor and
/// [`VerifiedRestoredCrypto::verify_scp_context_binding`] the only consumer:
/// an unverified group cannot reach the floor registry, a prior actor, the
/// event log, or an actor state.
pub(in crate::context) struct RestoredCrypto {
    owned: Option<OwnedMlsCryptoState>,
    floors: RestoredFloors,
}

/// Rebuilds `mls_state` as OWNED crypto material plus the Class-M floors it
/// carried. A pure function of its inputs: it touches no provider state, no
/// floor registry, and no wrapping key. An empty `mls_state` yields no owned
/// crypto and empty floors (cold path / keyless needs-reconnect snapshot).
///
/// # Errors
///
/// Returns `ContextError::PersistenceFailed`, prefixed with `site`, if the
/// crypto rebuild fails.
pub(in crate::context) fn build_restored_crypto(
    ctx_id_bytes: &[u8; 32],
    mls_state: &[u8],
    site: &str,
) -> Result<RestoredCrypto, ContextError> {
    if mls_state.is_empty() {
        return Ok(RestoredCrypto {
            owned: None,
            floors: RestoredFloors::default(),
        });
    }
    let (owned, floors) =
        crate::crypto::mls::provider::NodeMlsFactory::build_restored_owned(ctx_id_bytes, mls_state)
            .map_err(|e| {
                ContextError::PersistenceFailed(format!("{site}: crypto state restore failed: {e}"))
            })?;
    Ok(RestoredCrypto {
        owned: Some(owned),
        floors,
    })
}

/// What the verified group committed about its creation (spec 05 §5.13.3
/// rule 9).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::context) enum RestoredBinding {
    /// The group's `0xFF02` extension committed creation timestamp `t0`, which
    /// equals the snapshot's recorded `creation_timestamp_secs`.
    Committed {
        /// The committed creation timestamp, in seconds.
        t0: u64,
    },
    /// The snapshot carried no MLS group (keyless / needs-reconnect), so there
    /// is no extension to bind and no committed value.
    Keyless,
}

/// Restored crypto whose `0xFF02` binding was verified against the snapshot's
/// context id, creator DID, parameters, and creation timestamp.
///
/// [`VerifiedRestoredCrypto::verify_scp_context_binding`] is the only
/// constructor. The floor merge, the `PrepareForReplace` gate, the event-log
/// hydrate, and the actor seed all take this value or data only it yields, so
/// none of them can run on a group whose binding was not verified.
///
/// The fields are private and the type derives nothing, so a struct literal or
/// a `Default` outside this module does not compile. The doctests below mirror
/// that shape on a stand-in, because the real type is not nameable from a
/// doctest crate: a struct literal from outside the defining module fails with
/// E0451, a `default()` call fails with E0599, and the defining module's own
/// constructor compiles.
///
/// ```compile_fail,E0451
/// mod restored_crypto {
///     pub struct VerifiedRestoredCrypto {
///         committed_t0: Option<u64>,
///     }
/// }
///
/// fn main() {
///     // Forging a verified value by struct literal outside the module.
///     let _forged = restored_crypto::VerifiedRestoredCrypto { committed_t0: None };
/// }
/// ```
///
/// ```compile_fail,E0599
/// mod restored_crypto {
///     pub struct VerifiedRestoredCrypto {
///         committed_t0: Option<u64>,
///     }
/// }
///
/// fn main() {
///     // Forging a verified value through a `Default` the type does not derive.
///     let _forged = restored_crypto::VerifiedRestoredCrypto::default();
/// }
/// ```
///
/// ```
/// mod restored_crypto {
///     pub struct VerifiedRestoredCrypto {
///         committed_t0: Option<u64>,
///     }
///
///     impl VerifiedRestoredCrypto {
///         pub(crate) fn verify_scp_context_binding(committed_t0: Option<u64>) -> Self {
///             Self { committed_t0 }
///         }
///
///         pub(crate) fn committed_t0(&self) -> Option<u64> {
///             self.committed_t0
///         }
///     }
/// }
///
/// fn main() {
///     // Positive control: the module's own verifier constructs one.
///     let verified = restored_crypto::VerifiedRestoredCrypto::verify_scp_context_binding(Some(7));
///     assert_eq!(verified.committed_t0(), Some(7));
/// }
/// ```
pub(in crate::context) struct VerifiedRestoredCrypto {
    owned: Option<OwnedMlsCryptoState>,
    floors: VerifiedFloors,
    binding: RestoredBinding,
}

impl VerifiedRestoredCrypto {
    /// Consumes `restored` and verifies its group's committed
    /// `scp_context_params` (`0xFF02`) extension through the shared binding
    /// check [`verify_scp_context_binding`](crate::context::lifecycle_helpers::verify_scp_context_binding)
    /// (spec 05 §5.13.3 rules 1-9), with `snapshot_creation_timestamp_secs`
    /// as the recorded creation timestamp the committed `T0` must equal.
    ///
    /// A keyless `restored` (no MLS group) has nothing to bind and verifies as
    /// [`RestoredBinding::Keyless`].
    ///
    /// # Errors
    ///
    /// Returns the binding check's refusal, prefixed with `site`, when the
    /// group carries no `0xFF02` extension, the extension is unreadable, or any
    /// binding rule fails. The owned material is dropped on refusal (the
    /// `SenderKey` and the group's signer zeroize on drop).
    pub(in crate::context) fn verify_scp_context_binding(
        restored: RestoredCrypto,
        context_id: &str,
        creator_did: &str,
        params: &ContextParams,
        now_secs: u64,
        snapshot_creation_timestamp_secs: u64,
        site: &str,
    ) -> Result<Self, String> {
        let RestoredCrypto { owned, floors } = restored;
        let binding = match owned.as_ref() {
            None => RestoredBinding::Keyless,
            Some(group) => RestoredBinding::Committed {
                t0: crate::context::lifecycle_helpers::verify_scp_context_binding(
                    group
                        .mls_group
                        .group_context_extension()
                        .map_err(|e| e.to_string()),
                    context_id,
                    creator_did,
                    params,
                    now_secs,
                    Some(snapshot_creation_timestamp_secs),
                    site,
                )?,
            },
        };
        Ok(Self {
            owned,
            floors: VerifiedFloors(floors),
            binding,
        })
    }

    /// What the verified group committed about its creation.
    pub(in crate::context) const fn binding(&self) -> RestoredBinding {
        self.binding
    }

    /// A copy of the verified floors for the `PrepareForReplace` gate on a
    /// prior actor.
    pub(in crate::context) fn replace_floors(&self) -> VerifiedFloors {
        VerifiedFloors(RestoredFloors {
            sender_epochs: self.floors.0.sender_epochs.clone(),
            recv_sequence: self.floors.0.recv_sequence.clone(),
        })
    }

    /// Merges the verified floors into the Supervisor-owned registry through
    /// [`restore_crypto_state_with_floor_guard`](crate::context::lifecycle_helpers::restore_crypto_state_with_floor_guard)
    /// and returns the owned crypto, now floor-guarded, for the hydrate and
    /// seed steps.
    ///
    /// # Errors
    ///
    /// The floor guard's `ContextError::CryptoFailed` on a regression or an
    /// overshoot; the owned material is dropped on rejection.
    pub(in crate::context) fn merge_floors(
        self,
        deps: &ActorDeps,
        ctx_id_bytes: &[u8; 32],
        trusted_local: bool,
    ) -> Result<FloorGuardedCrypto, ContextError> {
        crate::context::lifecycle_helpers::restore_crypto_state_with_floor_guard(
            deps,
            ctx_id_bytes,
            &self.floors,
            trusted_local,
        )?;
        Ok(FloorGuardedCrypto { owned: self.owned })
    }
}

/// The Class-M floors of a [`VerifiedRestoredCrypto`], the only input the
/// floor merge accepts.
///
/// Yielded only by [`VerifiedRestoredCrypto`]; the field is private.
#[derive(Debug)]
pub struct VerifiedFloors(RestoredFloors);

impl VerifiedFloors {
    /// `(sender_did, epoch)` high-water floors.
    pub(in crate::context) fn sender_epochs(&self) -> &[(String, u64)] {
        &self.0.sender_epochs
    }

    /// `(sender_did, ReceiveFloor)` intra-epoch anti-replay floors.
    pub(in crate::context) fn recv_sequence(
        &self,
    ) -> &[(String, scp_protocol::context::builder::ReceiveFloor)] {
        &self.0.recv_sequence
    }
}

/// Verified restored crypto whose floors were merged into the registry.
///
/// Only [`VerifiedRestoredCrypto::merge_floors`] constructs one. The event-log
/// hydrate takes `&FloorGuardedCrypto`, and [`Self::into_owned`] hands the
/// group to the actor seed.
pub(in crate::context) struct FloorGuardedCrypto {
    owned: Option<OwnedMlsCryptoState>,
}

impl FloorGuardedCrypto {
    /// The rebuilt group and sender-key material for the fresh actor state, or
    /// `None` for a keyless snapshot.
    pub(in crate::context) fn into_owned(self) -> Option<OwnedMlsCryptoState> {
        self.owned
    }
}
