//! `Identity::create`: the inception under the collection flow
//! (`03-identity.md` §3.10.10; `09-security-model.md` §9.7.4.1 items 3 to 5,
//! §9.7.4.2 R10).
//!
//! `create` runs every refusal that needs no key synchronously, then hands
//! the rest to a spawned task, because no order avoids holding a key across
//! an await: generation is itself an await, and the record that makes the
//! keys reachable carries the event digest, which needs the keys. The task
//! runs from the first key through the device-record write, so a caller that
//! drops `create` cancels nothing, and its result owns an abandonment guard
//! that destroys every key the composition minted when nobody takes the
//! pending event out of it.

use std::future::Future;

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
use scp_platform::{EncryptedStorage, KeyHandle, KeyType, PreRotationCustodyKind, PublicKey};

use super::abandon::{abandon_composition, destroy_keys};
use super::device_record::{DeviceRecord, EventRef, read_device_record, write_device_record};
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

/// What the synchronous checks hand the spawned task.
#[derive(Debug, Clone, Copy)]
pub(super) struct CheckedPlan {
    /// The form the root member's signature takes.
    pub(super) root_form: SignatureForm,
    /// The method the next-set custody runs, as the commitment entry
    /// declares it.
    pub(super) next_custody_type: CustodyType,
}

/// Every `CustodyType`, for the offer check's second question. The
/// exhaustive match below fails to compile when the type gains a variant
/// this list lacks.
const ALL_CUSTODY_TYPES: [CustodyType; 9] = [
    CustodyType::Passkey,
    CustodyType::Fido2Token,
    CustodyType::Hsm,
    CustodyType::SecureEnclave,
    CustodyType::AndroidKeystore,
    CustodyType::EncryptedOfflineBackup,
    CustodyType::ShamirShares,
    CustodyType::PaperBackup,
    CustodyType::Software,
];

const _: () = {
    const fn listed(custody_type: CustodyType) -> bool {
        match custody_type {
            CustodyType::Passkey
            | CustodyType::Fido2Token
            | CustodyType::Hsm
            | CustodyType::SecureEnclave
            | CustodyType::AndroidKeystore
            | CustodyType::EncryptedOfflineBackup
            | CustodyType::ShamirShares
            | CustodyType::PaperBackup
            | CustodyType::Software => true,
        }
    }
    assert!(listed(CustodyType::Passkey));
};

impl<S: EncryptedStorage + Clone + 'static> Identity<S> {
    /// Composes the inception event under the collection flow, and writes its
    /// `KeptComposition` into this device's record
    /// (`17-persistence-and-storage.md` §17.3) before it returns
    /// (`09-security-model.md` §9.7.4.2 R10).
    ///
    /// Before any key exists, `create` refuses a plan other than one
    /// `installed_root` member at root index 0, and a next-set custody whose
    /// method the config's profile does not admit as the next set's one
    /// member (§9.7.4.1 item 4). It then generates the next-set member,
    /// confirms the member signs (§9.7.4.1 item 5(d)), mints `#0` and
    /// `#active`, composes the inception, and writes the device record.
    ///
    /// Must be awaited inside a Tokio runtime: everything from the first key
    /// through the record write runs in a spawned task, which dropping the
    /// returned future does not cancel. A task whose caller left destroys
    /// every key it minted and removes its record. A runtime shutdown
    /// cancels the task as a process stop does, and the record then names
    /// every key it wrote, for [`abandon_pending`](Self::abandon_pending).
    ///
    /// # Errors
    ///
    /// - [`IdentityError::SignatureSetIncomplete`] for a plan other than one
    ///   `installed_root` member at index 0, and for `SignerPlan::ThisSdk`.
    /// - [`IdentityError::ThresholdAdmitsDisjointQuorums`] for an
    ///   `installed_root` group of more than one member, which the inception's
    ///   threshold of 1 cannot cover by a majority.
    /// - [`IdentityError::MethodNotOfferedOnProfile`] where the next-set
    ///   custody's method is not admitted on `config.profile` and another
    ///   method is offered there; [`IdentityError::NoIndependentSubstrate`]
    ///   where no method is offered there.
    /// - [`IdentityError::CustodySigningFailed`] where a custody fails to
    ///   generate, reveal, probe or destroy a key, or the probe signature does
    ///   not verify.
    /// - [`IdentityError::IllegalKeyEvent`] where the composed inception fails
    ///   R2 or R3's check order.
    /// - [`IdentityError::PersistFailed`] where the device record cannot be
    ///   written, or the runtime cancelled the task.
    pub fn create(
        config: IdentityConfig<S>,
        signers: SignerPlan,
    ) -> impl Future<Output = Result<(Self, EventOutcome), IdentityError>> + Send {
        let checked = check_create(&config, signers);
        async move {
            let plan = checked?;
            let task = tokio::spawn(compose_inception(config, plan));
            match task.await {
                Ok(Ok(mut result)) => result.take().ok_or(IdentityError::PersistFailed),
                Ok(Err(error)) => Err(error),
                Err(join) if join.is_panic() => std::panic::resume_unwind(join.into_panic()),
                Err(join) => {
                    tracing::error!(%join, "the runtime cancelled identity creation");
                    Err(IdentityError::PersistFailed)
                }
            }
        }
    }
}

/// The refusals `create` runs before any key exists: the plan's shape, the
/// threshold rule, and the method-by-profile check (§9.7.4.1 items 3 and 4).
pub(super) fn check_create<S: EncryptedStorage + Clone>(
    config: &IdentityConfig<S>,
    signers: SignerPlan,
) -> Result<CheckedPlan, IdentityError> {
    let root_form = check_plan(signers)?;
    let next_custody_type = check_offer(config.next_set_custody.custody_kind(), &config.profile)?;
    Ok(CheckedPlan {
        root_form,
        next_custody_type,
    })
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
/// declares.
fn check_offer(
    kind: PreRotationCustodyKind,
    profile: &CustodyProfile,
) -> Result<CustodyType, IdentityError> {
    if let Some(custody_type) = kind.declared_custody_type()
        && admitted_as_sole_member(custody_type, profile)
    {
        return Ok(custody_type);
    }
    let offered_elsewhere = ALL_CUSTODY_TYPES
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

/// The keys a composition minted so far, destroyed when it fails before its
/// record is written.
#[derive(Debug, Default)]
struct Minted {
    next: Option<scp_platform::NextSetKeyHandle>,
    root: Option<KeyHandle>,
    active: Option<KeyHandle>,
}

/// The spawned half of `create`: composes, then on a failure before the
/// record write destroys every key it minted.
pub(super) async fn compose_inception<S: EncryptedStorage + Clone + 'static>(
    config: IdentityConfig<S>,
    plan: CheckedPlan,
) -> Result<CreateResult<S>, IdentityError> {
    let mut minted = Minted::default();
    match compose_keys_and_record(&config, plan, &mut minted).await {
        Ok((keys, pending)) => Ok(CreateResult {
            inner: Some((Identity { config, keys }, pending)),
            runtime: tokio::runtime::Handle::current(),
        }),
        Err(error) => {
            let next: Vec<_> = minted.next.into_iter().collect();
            let keys: Vec<_> = minted.root.into_iter().chain(minted.active).collect();
            if let Err(cleanup) = destroy_keys(&config, &next, &keys).await {
                tracing::error!(
                    code = error.code(),
                    "identity creation failed, and destroying its minted keys failed too"
                );
                return Err(cleanup);
            }
            Err(error)
        }
    }
}

/// Steps 1 to 6 of §2.6: the next-set member and its probe, `#0` and
/// `#active`, the inception, and the one record write.
async fn compose_keys_and_record<S: EncryptedStorage + Clone>(
    config: &IdentityConfig<S>,
    plan: CheckedPlan,
    minted: &mut Minted,
) -> Result<(ScpIdentity, PendingEvent), IdentityError> {
    let next_set = &config.next_set_custody;
    let next = next_set
        .generate()
        .await
        .map_err(|error| custody_failed("generating the next-set member", &error))?;
    minted.next = Some(next);
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
    minted.root = Some(root);
    let active = custody
        .generate_keypair(KeyType::P256Signing)
        .await
        .map_err(|error| custody_failed("generating #active", &error))?;
    minted.active = Some(active);
    let root_point = compressed_point(custody.public_key(&root).await, "#0")?;
    let active_point = compressed_point(custody.public_key(&active).await, "#active")?;

    let commitment = FixedCommitment {
        commitments: vec![CommitmentEntry {
            commitment: prerotation_commitment(&next_point),
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
        witnessing_interval: DEFAULT_WITNESSING_INTERVAL,
    })?;
    let preimage = encoded.signed_preimage();
    SigningChange::inception(&preimage)?;
    let identifier = derive_identifier(encoded.preimage()).map_err(|error| {
        tracing::error!(%error, "the composed inception derives no identifier");
        IdentityError::IllegalKeyEvent {
            stage: CheckStep::InceptionBinding,
        }
    })?;
    let event_digest = encoded.event_digest();

    // A fresh inception derives an identifier no record names; a record
    // already there is never overwritten, because its keys would be lost.
    if read_device_record(&config.persistence, &identifier)
        .await?
        .is_some()
    {
        tracing::error!(%identifier, "a device record already exists for a fresh inception");
        return Err(IdentityError::PersistFailed);
    }
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
    write_device_record(&config.persistence, &identifier, &record).await?;
    let pending = PendingEvent {
        identifier,
        preimage,
        event_digest,
        chain: vec![],
    };
    // The record is written; from here the `CreateResult` guard owns
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
/// at threshold 1, `#active`, no witnesses, no delegator, and the
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
            witnesses: vec![],
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
            if let Err(error) = abandon_composition(&config, &pending).await {
                tracing::error!(
                    code = error.code(),
                    identifier = %pending.identifier,
                    "abandoning an inception nobody took failed; its device record stays for abandon_pending"
                );
            }
        });
    }
}

#[cfg(test)]
#[path = "create_tests.rs"]
mod tests;
