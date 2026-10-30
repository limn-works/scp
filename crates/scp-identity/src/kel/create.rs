//! `Identity::create`: the inception under the collection flow
//! (`03-identity.md` §3.10.10; `09-security-model.md` §9.7.4.1 items 3 to 5,
//! §9.7.4.2 R10).
//!
//! `create` runs every refusal that needs no key synchronously, then hands
//! the rest to a spawned task, because no order avoids holding a key across
//! an await: generation is itself an await, and the device record carries
//! the event digest, which needs the keys. Until that record exists, a
//! creation record (`17-persistence-and-storage.md` §17.3) names each key
//! before the next is generated, so `Identity::unfinished` reaches every key
//! a crash leaves. The task runs from the first key through the device-record
//! write, so a caller that drops `create` cancels nothing, and its result
//! owns an abandonment guard that destroys every key the composition minted
//! when nobody takes the pending event out of it.

use std::future::Future;
use std::sync::{Arc, Mutex, PoisonError};

use scp_did::{
    CommitmentEntry, CustodyOffer, CustodyProfile, CustodyType, FixedCommitment, Identifier,
    KeyAlgorithm, KeyCondition, KeyEntry, KeyRole,
};
use scp_kel::constants::DEFAULT_WITNESSING_INTERVAL;
use scp_kel::{
    CheckStep, Continuation, CustodyProbe, EncodedPreimage, EventPreimage, InceptionFields,
    KeyStateSnapshot, SignatureForm, SignerGroup, SigningChange, derive_identifier,
    encode_preimage, prerotation_commitment,
};
use scp_platform::{
    EncryptedStorage, KeyHandle, KeyType, NextSetKeyHandle, PreRotationCustodyKind, PublicKey,
};

use super::abandon::{abandon_composition, destroy_keys};
use super::creation_record::{
    CreationId, CreationRecord, delete_creation_record, read_creation_record, write_creation_record,
};
use super::device_record::{DeviceRecord, EventRef, read_device_record, write_device_record};
use super::error::{CleanupFailure, CreateError, UndestroyedKey};
use super::slot::KeyCustodySlot;
use super::unfinished::KeptComposition;
use super::witness::{WitnessWarning, resolve_witnesses};
use super::{Identity, IdentityConfig, IdentityError, ScpIdentity};

/// The members that sign one group, each by root-set or next-set index and
/// by signature form (`09-security-model.md` §9.7.4.2 definitions).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupSigners {
    /// Each member's index and the form its signature takes.
    pub members: Vec<(u8, SignatureForm)>,
}

/// Who signs an event that needs a root threshold (`03-identity.md`
/// §3.10.10).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignerPlan {
    /// This SDK signs every group with its own members and publishes.
    ThisSdk,
    /// The preimage binds each group's signer index list and form list, and
    /// the composing method returns the event awaiting signatures.
    Groups {
        /// The reveal group of a reveal-authorized event.
        reveal: GroupSigners,
        /// The group of the root set the event installs; an inception's one
        /// group.
        installed_root: GroupSigners,
        /// The group of the standing root set.
        standing_root: GroupSigners,
    },
}

/// What a composing method returns under the collection flow
/// (`03-identity.md` §3.10.10).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EventOutcome {
    /// The composed event, awaiting the signatures its plan names.
    AwaitingSignatures(PendingEvent),
}

/// A composed event awaiting its signatures (`03-identity.md` §3.10.10).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingEvent {
    /// The identity the event creates or extends.
    pub identifier: Identifier,
    /// The event's signed preimage.
    pub preimage: Vec<u8>,
    /// SHA-256 of `preimage`.
    pub event_digest: [u8; 32],
    /// The encoded event units from the inception through the predecessor,
    /// which each signing device checks the event against at the head it
    /// holds (`09-security-model.md` §9.7.4.2 R10). Empty for an inception.
    pub chain: Vec<Vec<u8>>,
}

/// What `create` returns once the device record holds the composition
/// (`03-identity.md` §3.10.10).
pub struct Created<S: EncryptedStorage + Clone> {
    /// The handle.
    pub identity: Identity<S>,
    /// The inception, awaiting its signatures.
    pub outcome: EventOutcome,
    /// `Some` where the installed witness set is empty or names an unlisted
    /// operator (`09-security-model.md` §9.7.4.3).
    pub witness_warning: Option<WitnessWarning>,
}

/// What the synchronous checks hand the spawned task.
#[derive(Debug, Clone)]
pub(super) struct CheckedPlan {
    /// The form the root member's signature takes.
    pub(super) root_form: SignatureForm,
    /// The method the next-set custody runs, as the commitment entry
    /// declares it.
    pub(super) next_custody_type: CustodyType,
    /// The witness set the inception installs.
    pub(super) witnesses: Vec<Identifier>,
}

impl<S: EncryptedStorage + Clone + 'static> Identity<S> {
    /// Composes the inception event under the collection flow, and writes its
    /// `KeptComposition` into this device's record
    /// (`17-persistence-and-storage.md` §17.3) before it returns
    /// (`09-security-model.md` §9.7.4.2 R10).
    ///
    /// Before any key exists, `create` refuses a next-set custody whose
    /// method the config's profile does not admit as the next set's one
    /// member (§9.7.4.1 item 4), then a plan other than one `installed_root`
    /// member at root index 0, then a designated witness set R3 refuses. It
    /// then generates the next-set member, confirms the member signs
    /// (§9.7.4.1 item 5(d)), mints `#0` and `#active`, composes the
    /// inception, and writes the device record. A creation record names each
    /// key before the next is generated, and `create` deletes it once the
    /// device record names every key.
    ///
    /// On a failure or a panic after the first key, `create` destroys every
    /// key it minted, removes its records, and then returns the error or
    /// resumes the panic. A key it fails to destroy stays named in the
    /// creation record, which [`unfinished`](Self::unfinished) lists.
    ///
    /// Must be awaited inside a Tokio runtime: everything from the first key
    /// through the record write runs in a spawned task, which dropping the
    /// returned future does not cancel. A task whose caller left destroys
    /// every key it minted and removes its record. A runtime shutdown
    /// cancels the task as a process stop does, and the creation or device
    /// record then names every key, for
    /// [`abandon_unfinished`](Self::abandon_unfinished).
    ///
    /// # Errors
    ///
    /// [`CreateError::error`] is:
    /// - [`IdentityError::MethodNotOfferedOnProfile`] where the next-set
    ///   custody's method is not admitted on `config.profile` and another
    ///   method is offered there; [`IdentityError::NoIndependentSubstrate`]
    ///   where no method is offered there.
    /// - [`IdentityError::SignatureSetIncomplete`] for a plan other than one
    ///   `installed_root` member at index 0, and for `SignerPlan::ThisSdk`.
    /// - [`IdentityError::ThresholdAdmitsDisjointQuorums`] for an
    ///   `installed_root` group of more than one member, which the inception's
    ///   threshold of 1 cannot cover by a majority.
    /// - [`IdentityError::IllegalKeyEvent`] where a designated witness set
    ///   repeats an operator or exceeds `MAX_WITNESS_SET_SIZE`, or the
    ///   composed inception fails R2 or R3's check order.
    /// - [`IdentityError::CustodySigningFailed`] where a custody fails to
    ///   generate, reveal or probe a key, or the probe signature does not
    ///   verify.
    /// - [`IdentityError::PersistFailed`] where a record cannot be written,
    ///   the creation record is gone because `abandon_unfinished` abandoned
    ///   the creation, a device record already exists for the identifier,
    ///   or the runtime cancelled the task.
    ///
    /// [`CreateError::cleanup`] is `Some` where the cleanup after that
    /// failure left a key live or the creation record in place
    /// ([`CleanupFailure::Incomplete`]), or where the runtime cancelled the
    /// task before any cleanup ran ([`CleanupFailure::NotAttempted`]).
    pub fn create(
        config: IdentityConfig<S>,
        signers: SignerPlan,
    ) -> impl Future<Output = Result<Created<S>, CreateError>> + Send {
        let checked = check_create(&config, signers);
        async move {
            let (plan, witness_warning) = checked?;
            let creation = CreationId::fresh()?;
            let shared = SharedMinted::default();
            let task = tokio::spawn(compose_inception(
                config,
                plan,
                creation,
                Arc::clone(&shared),
            ));
            match task.await {
                Ok(Ok(mut result)) => {
                    let (identity, outcome) = result.take().ok_or(IdentityError::PersistFailed)?;
                    Ok(Created {
                        identity,
                        outcome,
                        witness_warning,
                    })
                }
                Ok(Err(error)) => Err(error),
                Err(join) if join.is_panic() => std::panic::resume_unwind(join.into_panic()),
                Err(join) => {
                    tracing::error!(%join, %creation, "the runtime cancelled identity creation");
                    // The cancelled task attempted no cleanup, so every key
                    // it minted may be live.
                    let minted = minted_now(&shared);
                    Err(CreateError {
                        error: IdentityError::PersistFailed,
                        cleanup: Some(Box::new(CleanupFailure::NotAttempted {
                            creation,
                            composition: minted.recorded.map(|(identifier, event_digest)| {
                                KeptComposition {
                                    identifier,
                                    sequence: 0,
                                    event_digest,
                                }
                            }),
                            minted: minted.all(),
                        })),
                    })
                }
            }
        }
    }
}

/// The refusals `create` runs before any key exists, in order: the
/// method-by-profile check (§9.7.4.1 item 4), the plan's shape and the
/// threshold rule (item 3), and the witness set (§9.7.4.3). Returns the
/// checked plan and the witness warning.
pub(super) fn check_create<S: EncryptedStorage + Clone>(
    config: &IdentityConfig<S>,
    signers: SignerPlan,
) -> Result<(CheckedPlan, Option<WitnessWarning>), IdentityError> {
    let next_custody_type = check_offer(config.next_set_custody.custody_kind(), &config.profile)?;
    let root_form = check_plan(signers)?;
    let (witnesses, warning) = resolve_witnesses(&config.witnesses)?;
    Ok((
        CheckedPlan {
            root_form,
            next_custody_type,
            witnesses,
        },
        warning,
    ))
}

/// An inception has one group, `installed_root`, and this SDK mints one root
/// member at index 0 under threshold 1 (§3.10.10; §9.7.4.1 quorum overlap).
fn check_plan(signers: SignerPlan) -> Result<SignatureForm, IdentityError> {
    let SignerPlan::Groups {
        reveal,
        installed_root,
        standing_root,
    } = signers
    else {
        // Stub — see SCP-006: `ThisSdk` signs and publishes through the
        // `IdentityBackend` the publish half adds (03-identity.md §3.10.10).
        return Err(IdentityError::SignatureSetIncomplete);
    };
    if !reveal.members.is_empty() || !standing_root.members.is_empty() {
        return Err(IdentityError::SignatureSetIncomplete);
    }
    match installed_root.members.as_slice() {
        [(0, form)] => Ok(*form),
        [] | [_] => Err(IdentityError::SignatureSetIncomplete),
        [_, _, ..] => Err(IdentityError::ThresholdAdmitsDisjointQuorums),
    }
}

/// The method-by-profile check (§9.7.4.1 item 4): the custody's declared
/// method must be admitted on `profile` as the next set's one member, which
/// is the floor on `Headless`. Returns the method the commitment entry
/// declares. `CustodyType::ALL` is the type's own variant list, so a method
/// added to the type is weighed here.
fn check_offer(
    kind: PreRotationCustodyKind,
    profile: &CustodyProfile,
) -> Result<CustodyType, IdentityError> {
    if let Some(custody_type) = kind.declared_custody_type()
        && admitted_as_sole_member(custody_type, profile)
    {
        return Ok(custody_type);
    }
    let offered_elsewhere = CustodyType::ALL
        .iter()
        .any(|other| other.offered_on(profile) == CustodyOffer::Offered);
    Err(if offered_elsewhere {
        IdentityError::MethodNotOfferedOnProfile
    } else {
        IdentityError::NoIndependentSubstrate
    })
}

/// Whether `custody_type` may hold the next set's one member on `profile`.
///
/// A method that does not conform there is refused, and so is a copyable
/// method this build ships no custody for. A conforming `Fido2Token` or
/// `Hsm` is admitted while this build ships none, because the caller
/// supplied the custody. On `Headless` the one member is the floor, and only
/// `Hsm` there is a method the table admits as the floor (§9.7.4.1 item 4,
/// "never as the floor").
fn admitted_as_sole_member(custody_type: CustodyType, profile: &CustodyProfile) -> bool {
    let meets_floor =
        !matches!(profile, CustodyProfile::Headless) || custody_type == CustodyType::Hsm;
    meets_floor
        && match custody_type.offered_on(profile) {
            CustodyOffer::Offered | CustodyOffer::HardwareCustodyAwaitingRuling => true,
            CustodyOffer::NotConforming | CustodyOffer::ServerFloorAwaitingRuling => false,
        }
}

/// The keys a composition minted so far, shared with the cleanup so a
/// panic in the composition loses none of them.
#[derive(Debug, Default, Clone)]
pub(super) struct Minted {
    /// The next-set member.
    next: Option<NextSetKeyHandle>,
    /// `#0`, then `#active`.
    keys: Vec<KeyHandle>,
    /// The inception whose device record names every key, once written.
    recorded: Option<(Identifier, [u8; 32])>,
}

impl Minted {
    /// The creation record naming every key minted so far.
    fn record(&self) -> CreationRecord {
        CreationRecord {
            next: self.next,
            keys: self.keys.clone(),
        }
    }

    /// Every key minted so far, as undestroyed keys.
    fn all(&self) -> Vec<UndestroyedKey> {
        self.next
            .map(UndestroyedKey::NextSetMember)
            .into_iter()
            .chain(self.keys.iter().copied().map(UndestroyedKey::Key))
            .collect()
    }
}

/// The minted keys, shared between the composition and its cleanup.
type SharedMinted = Arc<Mutex<Minted>>;

/// A copy of the minted keys. A poisoned lock still holds every key the
/// composition recorded before it panicked.
fn minted_now(shared: &SharedMinted) -> Minted {
    shared
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clone()
}

/// The spawned half of `create`: runs the composition in its own task, so a
/// panic there is caught, and on a failure or a panic destroys every key the
/// composition minted before it returns the error or resumes the panic
/// (§17.3).
pub(super) async fn compose_inception<S: EncryptedStorage + Clone + 'static>(
    config: IdentityConfig<S>,
    plan: CheckedPlan,
    creation: CreationId,
    shared: SharedMinted,
) -> Result<CreateResult<S>, CreateError> {
    let composing = tokio::spawn(compose_keys_and_record(
        config.clone(),
        plan,
        creation,
        Arc::clone(&shared),
    ));
    let (error, panic) = match composing.await {
        Ok(Ok((keys, pending))) => {
            return Ok(CreateResult {
                inner: Some((Identity { config, keys }, pending)),
                runtime: tokio::runtime::Handle::current(),
            });
        }
        Ok(Err(error)) => (error, None),
        Err(join) if join.is_panic() => (IdentityError::PersistFailed, Some(join.into_panic())),
        Err(join) => {
            tracing::error!(%join, "the runtime cancelled the composition");
            (IdentityError::PersistFailed, None)
        }
    };

    let minted = minted_now(&shared);
    // Name every minted key first, including one whose own rewrite failed,
    // so a key this cleanup fails to destroy stays listed.
    let named = {
        let _held = config.record_lock.hold().await;
        write_creation_record(&config.persistence, creation, &minted.record()).await
    };
    let next: Vec<NextSetKeyHandle> = minted.next.into_iter().collect();
    let (undestroyed, records_clean) = match minted.recorded {
        Some((identifier, event_digest)) => {
            match abandon_composition(&config, &identifier, &event_digest).await {
                Ok(undestroyed) => (undestroyed, true),
                Err(abandon) => {
                    tracing::error!(code = abandon.code(), "removing the device record failed");
                    (destroy_keys(&config, &next, &minted.keys).await, false)
                }
            }
        }
        None => (destroy_keys(&config, &next, &minted.keys).await, true),
    };
    let removed = undestroyed.is_empty() && records_clean && {
        let _held = config.record_lock.hold().await;
        delete_creation_record(&config.persistence, creation)
            .await
            .is_ok()
    };
    let cleanup = (!removed).then(|| {
        tracing::error!(
            code = error.code(),
            %creation,
            undestroyed = undestroyed.len(),
            named = named.is_ok(),
            "identity creation failed, and its cleanup did not complete"
        );
        CleanupFailure::Incomplete {
            creation,
            // Where the record could not be rewritten, it may not name the
            // last key, so the caller gets every key minted.
            undestroyed: if named.is_ok() || undestroyed.is_empty() {
                undestroyed
            } else {
                minted.all()
            },
        }
    });
    if let Some(panic) = panic {
        std::panic::resume_unwind(panic);
    }
    Err(CreateError {
        error,
        cleanup: cleanup.map(Box::new),
    })
}

/// Adds a key to the shared list, then rewrites the creation record to name
/// it, refusing where the record is gone because `abandon_unfinished`
/// abandoned this creation (§17.3).
async fn note_minted<S: EncryptedStorage + Clone>(
    config: &IdentityConfig<S>,
    creation: CreationId,
    shared: &SharedMinted,
    add: impl FnOnce(&mut Minted),
) -> Result<(), IdentityError> {
    let record = {
        let mut minted = shared.lock().unwrap_or_else(PoisonError::into_inner);
        add(&mut minted);
        minted.record()
    };
    let _held = config.record_lock.hold().await;
    require_creation_record(config, creation).await?;
    write_creation_record(&config.persistence, creation, &record).await
}

/// Refuses where `creation`'s record is gone.
async fn require_creation_record<S: EncryptedStorage + Clone>(
    config: &IdentityConfig<S>,
    creation: CreationId,
) -> Result<(), IdentityError> {
    if read_creation_record(&config.persistence, creation)
        .await?
        .is_none()
    {
        tracing::error!(%creation, "the creation record is gone: abandon_unfinished abandoned it");
        return Err(IdentityError::PersistFailed);
    }
    Ok(())
}

/// Step 5 of §2.6: the inception preimage over `#0`, `#active` and the
/// next-set member's commitment, each entry declaring its own key's custody
/// type. Returns the preimage and the commitment it binds.
async fn compose_preimage(
    custody: &KeyCustodySlot,
    plan: CheckedPlan,
    root: KeyHandle,
    active: KeyHandle,
    next_point: &[u8; 33],
) -> Result<(EncodedPreimage, FixedCommitment), IdentityError> {
    let root_point = compressed_point(custody.public_key(&root).await, "#0")?;
    let active_point = compressed_point(custody.public_key(&active).await, "#active")?;
    let commitment = FixedCommitment {
        commitments: vec![CommitmentEntry {
            commitment: prerotation_commitment(next_point),
            custody_type: plan.next_custody_type,
            key_algorithm: KeyAlgorithm::EcdsaP256Sha256,
        }],
        next_threshold: 1,
    };
    let encoded = inception_preimage(&InceptionDraft {
        root: current_entry(
            root_point,
            KeyRole::RootMember,
            custody.custody_type(root).key_entry_custody_type(),
        ),
        active: current_entry(
            active_point,
            KeyRole::Active,
            custody.custody_type(active).key_entry_custody_type(),
        ),
        root_form: plan.root_form,
        commitment: commitment.clone(),
        witnesses: plan.witnesses,
        witnessing_interval: DEFAULT_WITNESSING_INTERVAL,
    })?;
    Ok((encoded, commitment))
}

/// Steps 1 to 6 of §2.6: the creation record, the next-set member and its
/// probe, `#0` and `#active`, the inception, and the device-record write
/// that supersedes the creation record.
async fn compose_keys_and_record<S: EncryptedStorage + Clone>(
    config: IdentityConfig<S>,
    plan: CheckedPlan,
    creation: CreationId,
    shared: SharedMinted,
) -> Result<(ScpIdentity, PendingEvent), IdentityError> {
    // The record exists before the first key, so `unfinished` lists every
    // creation that reached a generation (§17.3).
    write_creation_record(&config.persistence, creation, &CreationRecord::default()).await?;

    let next_set = &config.next_set_custody;
    let next = next_set
        .generate()
        .await
        .map_err(|error| custody_failed("generating the next-set member", &error))?;
    note_minted(&config, creation, &shared, |minted| {
        minted.next = Some(next);
    })
    .await?;
    let next_point = next_set
        .reveal_public_key(&next)
        .await
        .map_err(|error| custody_failed("revealing the next-set member", &error))?;
    let probe =
        CustodyProbe::fresh().map_err(|error| custody_failed("drawing the probe nonce", &error))?;
    next_set
        .sign_probe(&next, &probe)
        .await
        .map_err(|error| custody_failed("signing the reachability probe", &error))?
        .verify(&probe, &next_point)
        .map_err(|error| custody_failed("verifying the reachability probe", &error))?;

    let custody = &config.custody;
    let root = custody
        .generate_key_event_keypair()
        .await
        .map_err(|error| custody_failed("generating #0", &error))?;
    note_minted(&config, creation, &shared, |minted| minted.keys.push(root)).await?;
    let active = custody
        .generate_keypair(KeyType::P256Signing)
        .await
        .map_err(|error| custody_failed("generating #active", &error))?;
    note_minted(&config, creation, &shared, |minted| {
        minted.keys.push(active);
    })
    .await?;
    let (encoded, commitment) = compose_preimage(custody, plan, root, active, &next_point).await?;
    let preimage = encoded.signed_preimage();
    SigningChange::inception(&preimage)?;
    let identifier = derive_identifier(encoded.preimage()).map_err(|error| {
        tracing::error!(%error, "the composed inception derives no identifier");
        IdentityError::IllegalKeyEvent {
            stage: CheckStep::InceptionBinding,
        }
    })?;
    let event_digest = encoded.event_digest();

    let record = DeviceRecord {
        root: vec![(0, root)],
        active: Some(active),
        next: vec![next],
        kept: vec![EventRef {
            identifier,
            sequence: 0,
            event_digest,
        }],
        pending: vec![],
    };
    {
        let _held = config.record_lock.hold().await;
        require_creation_record(&config, creation).await?;
        // A fresh inception derives an identifier no record names; a record
        // already there is never overwritten, because its keys would be lost.
        if read_device_record(&config.persistence, &identifier)
            .await?
            .is_some()
        {
            tracing::error!(%identifier, "a device record already exists for a fresh inception");
            return Err(IdentityError::PersistFailed);
        }
        write_device_record(&config.persistence, &identifier, &record).await?;
        shared
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .recorded = Some((identifier, event_digest));
        // The device record now names every key, and supersedes the
        // creation record.
        delete_creation_record(&config.persistence, creation).await?;
    }
    let pending = PendingEvent {
        identifier,
        preimage,
        event_digest,
        chain: vec![],
    };
    // The records are settled; from here the `CreateResult` guard owns
    // abandonment.
    Ok((
        ScpIdentity {
            identity_key: root,
            active_signing_key: active,
            pre_rotation_commitment: commitment,
            identifier,
        },
        pending,
    ))
}

/// The inputs of an inception preimage.
#[derive(Debug, Clone)]
pub(super) struct InceptionDraft {
    pub(super) root: KeyEntry,
    pub(super) active: KeyEntry,
    pub(super) root_form: SignatureForm,
    pub(super) commitment: FixedCommitment,
    pub(super) witnesses: Vec<Identifier>,
    pub(super) witnessing_interval: u32,
}

/// A `Current` key entry, which carries no compromise position.
const fn current_entry(key: [u8; 33], role: KeyRole, custody_type: CustodyType) -> KeyEntry {
    KeyEntry {
        key,
        role,
        condition: KeyCondition::Current,
        compromised_from: 0,
        custody_type,
        key_algorithm: KeyAlgorithm::EcdsaP256Sha256,
    }
}

/// Encodes the inception the draft describes (§9.7.4.2): one root member
/// at threshold 1, `#active`, the witness set, no delegator, and the
/// commitment list.
pub(super) fn inception_preimage(draft: &InceptionDraft) -> Result<EncodedPreimage, IdentityError> {
    let preimage = EventPreimage::inception(InceptionFields {
        root_group: SignerGroup {
            indices: vec![0],
            forms: vec![draft.root_form],
        },
        key_state: KeyStateSnapshot {
            root_threshold: 1,
            keys: vec![draft.root, draft.active],
            witnesses: draft.witnesses.clone(),
            witnessing_interval: draft.witnessing_interval,
            service_key_role: KeyRole::Active,
            delegator: Identifier::ZERO,
        },
        continuation: Continuation::FixesCommitment(draft.commitment.clone()),
    });
    encode_preimage(&preimage).map_err(|error| {
        // The decoder refuses at step 4 every value the encoder refuses.
        tracing::error!(%error, "the composed inception does not encode");
        IdentityError::IllegalKeyEvent {
            stage: CheckStep::Header,
        }
    })
}

/// A key-event public key, which is the 33-byte compressed SEC1 point.
fn compressed_point(
    key: Result<PublicKey, scp_platform::PlatformError>,
    which: &str,
) -> Result<[u8; 33], IdentityError> {
    let key = key.map_err(|error| custody_failed(which, &error))?;
    <[u8; 33]>::try_from(key.as_bytes()).map_err(|_| {
        tracing::error!(
            which,
            len = key.as_bytes().len(),
            "a custody returned a public key that is not a compressed point"
        );
        IdentityError::CustodySigningFailed
    })
}

/// Logs a custody failure and returns SCP-IDENT-1111.
pub(super) fn custody_failed(step: &str, error: &dyn std::fmt::Display) -> IdentityError {
    tracing::error!(step, %error, "a custody operation failed during identity creation");
    IdentityError::CustodySigningFailed
}

/// What the spawned task hands `create`: the handle and the pending event,
/// with a guard that abandons the composition when the value is dropped
/// before `create` takes them out (`03-identity.md` §3.10.10).
pub(super) struct CreateResult<S: EncryptedStorage + Clone + 'static> {
    inner: Option<(Identity<S>, PendingEvent)>,
    runtime: tokio::runtime::Handle,
}

impl<S: EncryptedStorage + Clone + 'static> CreateResult<S> {
    /// Takes the handle and the outcome, disarming the guard.
    pub(super) fn take(&mut self) -> Option<(Identity<S>, EventOutcome)> {
        self.inner
            .take()
            .map(|(identity, pending)| (identity, EventOutcome::AwaitingSignatures(pending)))
    }
}

impl<S: EncryptedStorage + Clone + 'static> Drop for CreateResult<S> {
    fn drop(&mut self) {
        let Some((identity, pending)) = self.inner.take() else {
            return;
        };
        let config = identity.config;
        self.runtime.spawn(async move {
            match abandon_composition(&config, &pending.identifier, &pending.event_digest).await {
                Ok(undestroyed) if undestroyed.is_empty() => {}
                Ok(undestroyed) => tracing::error!(
                    undestroyed = undestroyed.len(),
                    identifier = %pending.identifier,
                    "abandoning an inception nobody took left keys live; its device record stays for abandon_unfinished"
                ),
                Err(error) => tracing::error!(
                    code = error.code(),
                    identifier = %pending.identifier,
                    "abandoning an inception nobody took failed; its device record stays for abandon_unfinished"
                ),
            }
        });
    }
}

#[cfg(test)]
#[path = "create_tests.rs"]
mod tests;
