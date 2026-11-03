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
pub struct RestoredCrypto {
    owned: Option<OwnedMlsCryptoState>,
    floors: RestoredFloors,
}

/// Rebuilds `mls_state` as OWNED crypto material plus the Class-M floors it carried.
///
/// A pure function of its inputs: it touches no provider state, no floor registry, and no wrapping
/// key. An empty `mls_state` yields no owned crypto and empty floors (cold path / keyless
/// needs-reconnect snapshot).
///
/// # Errors
///
/// Returns `ContextError::PersistenceFailed`, prefixed with `site`, if the
/// crypto rebuild fails.
pub fn build_restored_crypto(
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
pub enum RestoredBinding {
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
pub struct VerifiedRestoredCrypto {
    owned: Option<OwnedMlsCryptoState>,
    floors: VerifiedFloors,
    binding: RestoredBinding,
}

impl VerifiedRestoredCrypto {
    /// Consumes `restored` and verifies its group's committed
    /// `scp_context_params` (`0xFF02`) extension through the shared binding
    /// check [`verify_scp_context_binding`]
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
    pub fn verify_scp_context_binding(
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
                t0: verify_scp_context_binding(
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
    pub const fn binding(&self) -> RestoredBinding {
        self.binding
    }

    /// A copy of the verified floors for the `PrepareForReplace` gate on a
    /// prior actor.
    pub fn replace_floors(&self) -> VerifiedFloors {
        VerifiedFloors(RestoredFloors {
            sender_epochs: self.floors.0.sender_epochs.clone(),
            recv_sequence: self.floors.0.recv_sequence.clone(),
        })
    }

    /// Merges the verified floors into the Supervisor-owned registry through
    /// [`restore_crypto_state_with_floor_guard`]
    /// and returns the owned crypto, now floor-guarded, for the hydrate and
    /// seed steps.
    ///
    /// # Errors
    ///
    /// The floor guard's `ContextError::CryptoFailed` on a regression or an
    /// overshoot; the owned material is dropped on rejection.
    pub fn merge_floors(
        self,
        deps: &ActorDeps,
        ctx_id_bytes: &[u8; 32],
        trusted_local: bool,
    ) -> Result<FloorGuardedCrypto, ContextError> {
        restore_crypto_state_with_floor_guard(deps, ctx_id_bytes, &self.floors, trusted_local)?;
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
pub struct FloorGuardedCrypto {
    owned: Option<OwnedMlsCryptoState>,
}

impl FloorGuardedCrypto {
    /// The rebuilt group and sender-key material for the fresh actor state, or
    /// `None` for a keyless snapshot.
    pub fn into_owned(self) -> Option<OwnedMlsCryptoState> {
        self.owned
    }
}

/// §23.17 Invariant 2/3/4 — the SINGLE floor-guarded crypto-restore path for
/// import, `PrepareForReplace`, respawn, and restore.
///
/// Merges the floors of a
/// [`VerifiedRestoredCrypto`]
/// INTO the authoritative Supervisor-owned Class-M registry (ADR-049 PR-6).
/// EVERY crypto-restore site — the actor-side `PrepareForReplace` handler,
/// `import_context`, and `restore_context` — routes through here so the replay
/// (floor-regression) guard cannot be bypassed.
///
/// The input is [`VerifiedFloors`],
/// which only a `VerifiedRestoredCrypto` yields, so floors from a group whose
/// `0xFF02` binding (spec 05 §5.13.3) was not verified cannot reach the
/// registry.
///
/// The registry is the authoritative live floor home and is NOT torn down here,
/// so there is no pre-teardown "capture" step: the snapshot floors are the merge
/// INPUT (`incoming`) and the live registry floors are the merge target. The
/// registry merge guards on `incoming.is_empty()` (NOT the live floors), so a
/// COLD restart (empty live registry, non-empty snapshot) still POPULATES the
/// registry — closing the cold-restart replay window (D2).
///
/// Import and restore reach it through
/// [`VerifiedRestoredCrypto::merge_floors`](crate::context::restored_crypto::VerifiedRestoredCrypto::merge_floors),
/// which returns the owned group for the seed only after this merge succeeds.
/// The terminating `PrepareForReplace` actor calls it with the floors alone
/// and seeds nothing (ADR-049 PR-7 C3 seed-vs-terminal resolution).
///
/// `trusted_local` selects the spec §23.17.2 merge semantics:
///
/// - `true` — restoring the node's OWN snapshot (Invariant 2): crash recovery,
///   actor respawn (`Supervisor::respawn_from_snapshot`), process restart
///   (`restore_all_contexts`). A lower restored floor is the expected
///   coalesce-lag case and is MAX-merged with the live registry floor; the
///   restore PROCEEDS (never rejected for a regression). Only an overshoot
///   beyond `MAX_EPOCH_ADVANCE` (corrupt/garbage snapshot) is rejected.
/// - `false` — importing an UNTRUSTED peer snapshot (Invariant 3): any
///   per-sender floor regression is rejected (snapshot-mediated replay guard).
///
/// # Errors
///
/// Returns `ContextError::CryptoFailed` (from `From<FloorAdvanceError>`, the
/// §23.17 replay-protection rejection the registry's `validate_and_merge_*`
/// sink returns) if a per-sender floor regresses (import path) or overshoots
/// (both paths), and the registry is left unchanged (validate-before-apply
/// across both axes).
pub fn restore_crypto_state_with_floor_guard(
    deps: &ActorDeps,
    ctx_id_bytes: &[u8; 32],
    floors: &crate::context::restored_crypto::VerifiedFloors,
    trusted_local: bool,
) -> Result<(), ContextError> {
    // #2148 (ADR-049 birth-into-actor): the crypto is ACTOR-owned end to end —
    // the provider holds NO per-context state, so there is no provider-resident
    // crypto to tear down first.

    // Map the restore's `trusted_local` bool to the registry merge's §23.17.2
    // `MergePolicy`: a trusted-local respawn max-merges and tolerates the
    // coalesce-lag regression (Inv-2); an untrusted import rejects any
    // regression (Inv-3). BOTH enforce the epoch-poisoning overshoot ceiling.
    let policy = if trusted_local {
        scp_protocol::crypto::sender_keys::MergePolicy::MaxMergeTrustedLocal
    } else {
        scp_protocol::crypto::sender_keys::MergePolicy::RejectRegression
    };

    // THE D2 sink: merge the snapshot floors (`incoming`) INTO the authoritative
    // registry (`local` = the live, non-torn-down registry). ONE cross-axis
    // validating merge — BOTH the epoch AND the recv-sequence floors are
    // validated before EITHER is applied, so a rejection on either axis leaves
    // the WHOLE registry entry UNCHANGED. The merge guards on
    // `incoming.is_empty()` — NOT on the live floors — so on a COLD restart
    // (empty live registry, NON-empty snapshot) it RUNS and POPULATES the
    // registry, closing D2. FAIL-CLOSED via `?`; `From<FloorAdvanceError>` maps
    // a rejection to `ContextError::CryptoFailed`. On rejection
    // `VerifiedRestoredCrypto::merge_floors` drops the owned group at its `?`
    // return (zeroizing on drop), so a rejected restore is never seeded onto an
    // actor and writes no durable snapshot.
    deps.supervisor.validate_and_merge_all_floors(
        ctx_id_bytes,
        floors.sender_epochs().to_vec(),
        floors.recv_sequence().to_vec(),
        scp_protocol::crypto::sender_keys::MAX_EPOCH_ADVANCE,
        policy,
    )?;

    Ok(())
}

/// Verifies a joined or rehydrated MLS group's committed `scp_context_params`
/// (`0xFF02`) group-context extension against the context's declared identity
/// and parameters (spec §5.13.3, finding FFI-02).
///
/// This is the single binding check shared by every point where an SCP context
/// group enters the live provider from a *caller-supplied* description of its
/// parameters:
///
/// - **join** (`Supervisor::spawn_actor_from_welcome`) — the joiner reads the
///   just-joined group's extension (before install) and verifies it against the
///   `WelcomeJoinRequest.params` the (untrusted) inviter supplied;
/// - **import** (`import_context`) and **restore / respawn** (`restore_context`)
///   — the layer reads the *rehydrated* group's extension and verifies it
///   against the snapshot's `context_params`.
///
/// It enforces validation **rule 1** (every SCP context group MUST carry the
/// `0xFF02` extension) plus **rules 2–6** (`context_id`, governance / ceiling
/// hashes, ceiling policy, mode, parent structure) and **rule 8** (the committed
/// genesis `creator_did` MUST equal the presented `creator_did`) via
/// [`ScpContextExtension::verify_against`](scp_protocol::context::ScpContextExtension::verify_against).
/// The extension is folded into the MLS key schedule at group creation, so it
/// is the group's cryptographic attestation of its own parameters: a malicious
/// inviter (or a forged / internally-inconsistent snapshot) that presents
/// benign `params` while the real group commits divergent
/// governance / ceiling / mode / `context_id` is refused here, *before* any
/// authority (governance engine, ceiling, admin set) is built from those
/// params.
///
/// `creator_did` is the genesis creator/admin the caller presents — the
/// (untrusted) bundle's `creator_did` on a Welcome-based join, or the snapshot's
/// `role_state.creator_did` on import/restore. Rule 8 refuses the group unless
/// it equals the `creator_did` the group cryptographically committed at
/// creation, so no authority is ever built for a substituted admin (the sole
/// anchor for DID-less governance models such as `SingleAdmin`).
///
/// It also enforces **rule 9**: the committed `creation_timestamp_secs` must
/// not exceed 2^53 − 1, must not lie later than `now_secs` plus the 5-minute
/// future bound of `09-security-model.md` §9.8.2
/// ([`CREATION_TIMESTAMP_FUTURE_BOUND_SECS`](scp_protocol::context::CREATION_TIMESTAMP_FUTURE_BOUND_SECS)),
/// and, on import and restore, must equal the creation timestamp the snapshot
/// recorded (`snapshot_creation_timestamp_secs`; `None` on a Welcome join,
/// which presents no snapshot). An extension that omits the field fails to
/// decode, so it arrives here as an unreadable `read`.
///
/// `read` is the group-context-extension read outcome: `Ok(Some(ext))` =
/// present, `Ok(None)` = absent (a rule-1 violation — not an SCP context),
/// `Err(msg)` = the group is unreadable / the `0xFF02` payload is malformed.
/// On rejection the returned reason is prefixed with `site` so each caller can
/// wrap it in its site-idiomatic [`ContextError`] variant while sharing this
/// one check. Returns the committed `T0`, which the caller installs as the
/// pseudonym-rotation base and the TTL base, only when the extension is
/// present AND every binding rule holds.
///
/// # Errors
///
/// Returns the `site`-prefixed rejection reason when the extension is absent
/// or unreadable, or when any binding rule fails.
pub fn verify_scp_context_binding(
    read: Result<Option<scp_protocol::context::ScpContextExtension>, String>,
    context_id: &str,
    creator_did: &str,
    params: &scp_protocol::context::ContextParams,
    now_secs: u64,
    snapshot_creation_timestamp_secs: Option<u64>,
    site: &str,
) -> Result<u64, String> {
    match read {
        Ok(Some(ext)) => {
            ext.verify_against(
                &context_id.to_owned(),
                &scp_did::DID::from(creator_did.to_owned()),
                params,
            )
            .map_err(|e| {
                format!(
                    "{site} refused: scp_context_params (0xFF02) binding mismatch \
                     (§5.13.3 rules 2-6, 8): {e}"
                )
            })?;
            let t0 = ext.committed_creation_timestamp(now_secs).map_err(|e| {
                format!(
                    "{site} refused: scp_context_params (0xFF02) creation timestamp \
                     rejected (§5.13.3 rule 9): {e}"
                )
            })?;
            match snapshot_creation_timestamp_secs {
                Some(recorded) if recorded != t0 => Err(format!(
                    "{site} refused: the snapshot records creation timestamp {recorded}, \
                     the scp_context_params (0xFF02) extension commits {t0} \
                     (§5.13.3 rules 7, 9)"
                )),
                _ => Ok(t0),
            }
        }
        Ok(None) => Err(format!(
            "{site} refused: the MLS group carries no scp_context_params (0xFF02) \
             group-context extension — not an SCP context (§5.13.3 rule 1)"
        )),
        Err(e) => Err(format!(
            "{site} refused: scp_context_params (0xFF02) group-context extension \
             unreadable (§5.13.3): {e}"
        )),
    }
}
