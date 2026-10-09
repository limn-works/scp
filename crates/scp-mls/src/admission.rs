//! Leaf admission: the checks every leaf must pass before a Commit that adds
//! or replaces it is merged (spec 09 §9.16.1, spec 10 §10.8.1(7)).
//!
//! openmls validates signatures, capabilities and its own `Lifetime` view.
//! SCP adds the rules openmls cannot know:
//!
//! - **Added leaf** ([`admit_added_leaf`]), in order:
//!   1. the `KeyPackage` `Lifetime` holds against the injected hardened clock;
//!   2. the leaf credential parses to an SCP DID;
//!   3. the leaf carries a valid `0xFF01` wrapping key;
//!   4. every leaf the DID already holds, in the tree or earlier in the same
//!      Commit, carries the same `0xFF01`, and the DID holds at most
//!      [`MAX_LEAVES_PER_DID`] leaves after the add.
//! - **Replaced leaf** (an Update proposal's leaf or the Commit's `UpdatePath`
//!   leaf): it carries a valid `0xFF01` and names the same DID as the leaf it
//!   replaces. A changed key is reported in
//!   [`CommitAdmission::wrapping_key_updates`] so the member directory can
//!   follow a rotation.
//!
//! An Add never overwrites a recorded key: a second leaf for a DID must carry
//! the key the DID already published. A key changes only through that DID's
//! own Update.
//!
//! openmls 0.8.1 gives no public accessor for a remote leaf's extensions
//! (`MlsGroup::public_group` is crate-private and `Member` carries none), so
//! [`tree_leaves`] reads them from the exported ratchet tree, whose node list
//! is a public serde type.

use openmls::prelude::*;
use scp_clock::Clock;

use crate::credential::ScpCredential;
use crate::error::MlsError;
use crate::lifetime::validate_key_package_lifetime;
use crate::wrapping_extension::extract_wrapping_key;
use scp_protocol::crypto::hpke::p256::P256Point;

/// The most leaves one DID may hold in a group: one per device
/// (spec 10 §10.8.1(7)).
pub const MAX_LEAVES_PER_DID: usize = 10;

/// A leaf that passed admission: the DID its credential names and the
/// `0xFF01` wrapping key it publishes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdmittedLeaf {
    /// The SCP DID from the leaf credential.
    pub did: String,
    /// The leaf's 65-byte uncompressed P-256 wrapping public key.
    pub wrapping_key: P256Point,
}

/// Why a leaf that openmls accepted was refused by SCP admission.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LeafAdmissionRejection {
    /// The leaf carries no `0xFF01` wrapping key, so no peer could HPKE-seal a
    /// sender key to it.
    MissingWrappingKey,
    /// The added leaf's `0xFF01` differs from the key the DID already
    /// publishes in another leaf.
    WrappingKeyMismatch,
    /// The add would give the DID more than [`MAX_LEAVES_PER_DID`] leaves.
    TooManyLeaves,
    /// A replacing leaf names a different DID than the leaf it replaces.
    IdentityChanged,
}

impl std::fmt::Display for LeafAdmissionRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::MissingWrappingKey => "the leaf carries no wrapping key",
            Self::WrappingKeyMismatch => {
                "the leaf's wrapping key differs from the key the DID already publishes"
            }
            Self::TooManyLeaves => "the DID would hold more than 10 leaves",
            Self::IdentityChanged => "the replacing leaf names a different DID",
        })
    }
}

/// One occupied leaf of the current tree.
#[derive(Clone, Debug)]
pub(crate) struct TreeLeaf {
    index: u32,
    did: String,
    wrapping_key: Option<P256Point>,
}

/// What a staged Commit changes about members' identities, once every added
/// and replaced leaf passed admission.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct CommitAdmission {
    /// The admitted Add leaves, in proposal order.
    pub(crate) added: Vec<AdmittedLeaf>,
    /// `(did, key)` for each replaced leaf whose `0xFF01` differs from the
    /// leaf it replaces, in the order the Commit applies them.
    pub(crate) wrapping_key_updates: Vec<(String, P256Point)>,
}

fn leaf_did(leaf: &LeafNode) -> Result<String, MlsError> {
    let basic = BasicCredential::try_from(leaf.credential().clone())
        .map_err(|e| MlsError::InvalidCredential(format!("leaf credential: {e}")))?;
    ScpCredential::from_bytes(basic.identity())
        .map(|c| c.did)
        .map_err(|e| MlsError::InvalidCredential(format!("leaf SCP credential: {e}")))
}

/// The leaf's `0xFF01` key. A member no peer can HPKE-seal a sender key to
/// must not be admitted (spec 09 §9.16.1).
fn required_wrapping_key(leaf: &LeafNode, did: &str) -> Result<P256Point, MlsError> {
    extract_wrapping_key(leaf.extensions())?.ok_or_else(|| MlsError::LeafAdmissionRejected {
        did: did.to_owned(),
        reason: LeafAdmissionRejection::MissingWrappingKey,
    })
}

/// Reads every occupied leaf of `group`'s current tree with its DID and
/// `0xFF01` key.
///
/// # Errors
///
/// [`MlsError::DeserializationFailed`] if the exported tree does not
/// round-trip into its node list, [`MlsError::InvalidCredential`] if a leaf
/// credential is not an SCP credential, or [`MlsError::ExtensionError`] if a
/// leaf's `0xFF01` payload is malformed.
pub(crate) fn tree_leaves(group: &MlsGroup) -> Result<Vec<TreeLeaf>, MlsError> {
    let bytes = rmp_serde::to_vec(&group.export_ratchet_tree())
        .map_err(|e| MlsError::DeserializationFailed(format!("exporting ratchet tree: {e}")))?;
    let nodes: Vec<Option<Node>> = rmp_serde::from_slice(&bytes)
        .map_err(|e| MlsError::DeserializationFailed(format!("reading ratchet tree: {e}")))?;
    let mut leaves = Vec::new();
    // Leaf `i` sits at node index `2i` (RFC 9420 §4.1).
    for (leaf_index, node) in nodes.iter().step_by(2).enumerate() {
        let Some(Node::LeafNode(leaf)) = node else {
            continue;
        };
        let index = u32::try_from(leaf_index)
            .map_err(|_| MlsError::DeserializationFailed("tree leaf index overflow".into()))?;
        leaves.push(TreeLeaf {
            index,
            did: leaf_did(leaf)?,
            wrapping_key: extract_wrapping_key(leaf.extensions())?,
        });
    }
    Ok(leaves)
}

/// Admits the leaf a validated `KeyPackage` adds, against the current tree
/// and the leaves the same Commit admitted before it.
///
/// # Errors
///
/// In check order: [`MlsError::KeyPackageLifetimeInvalid`],
/// [`MlsError::InvalidCredential`], [`MlsError::ExtensionError`] (a
/// malformed `0xFF01`), then [`MlsError::LeafAdmissionRejected`] with
/// [`LeafAdmissionRejection::MissingWrappingKey`],
/// [`LeafAdmissionRejection::WrappingKeyMismatch`] or
/// [`LeafAdmissionRejection::TooManyLeaves`].
pub(crate) fn admit_added_leaf(
    key_package: &KeyPackage,
    tree: &[TreeLeaf],
    admitted_in_this_commit: &[AdmittedLeaf],
    clock: &dyn Clock,
) -> Result<AdmittedLeaf, MlsError> {
    validate_key_package_lifetime(key_package.life_time(), clock)?;
    let leaf = key_package.leaf_node();
    let did = leaf_did(leaf)?;
    let wrapping_key = required_wrapping_key(leaf, &did)?;

    let mut held = 0usize;
    let existing = tree
        .iter()
        .filter(|l| l.did == did)
        .map(|l| l.wrapping_key)
        .chain(
            admitted_in_this_commit
                .iter()
                .filter(|l| l.did == did)
                .map(|l| Some(l.wrapping_key)),
        );
    for key in existing {
        held += 1;
        if key != Some(wrapping_key) {
            return Err(MlsError::LeafAdmissionRejected {
                did,
                reason: LeafAdmissionRejection::WrappingKeyMismatch,
            });
        }
    }
    if held >= MAX_LEAVES_PER_DID {
        return Err(MlsError::LeafAdmissionRejected {
            did,
            reason: LeafAdmissionRejection::TooManyLeaves,
        });
    }
    Ok(AdmittedLeaf { did, wrapping_key })
}

/// Admits `leaf` as the replacement of the tree leaf at `replaced_index`.
/// Returns the new key when it differs from the replaced leaf's.
fn admit_replacing_leaf(
    leaf: &LeafNode,
    replaced_index: LeafNodeIndex,
    tree: &[TreeLeaf],
) -> Result<Option<(String, P256Point)>, MlsError> {
    let replaced = tree
        .iter()
        .find(|l| l.index == replaced_index.u32())
        .ok_or_else(|| MlsError::MemberNotFound(replaced_index.u32()))?;
    let did = leaf_did(leaf)?;
    let wrapping_key = required_wrapping_key(leaf, &did)?;
    if did != replaced.did {
        return Err(MlsError::LeafAdmissionRejected {
            did,
            reason: LeafAdmissionRejection::IdentityChanged,
        });
    }
    Ok((replaced.wrapping_key != Some(wrapping_key)).then_some((did, wrapping_key)))
}

/// Admits every leaf a staged Commit adds or replaces, before it is merged.
///
/// `committer` is the Commit sender's leaf, which the `UpdatePath` leaf (when
/// present) replaces.
///
/// # Errors
///
/// Any error of [`admit_added_leaf`], the same errors for a replacing leaf
/// (with [`LeafAdmissionRejection::IdentityChanged`] for a DID change), or
/// [`MlsError::CommitProcessingFailed`] if an Update proposal was not sent by
/// a member. The caller drops the staged commit unmerged on any error.
pub(crate) fn admit_staged_commit(
    group: &MlsGroup,
    staged_commit: &StagedCommit,
    committer: LeafNodeIndex,
    clock: &dyn Clock,
) -> Result<CommitAdmission, MlsError> {
    let tree = tree_leaves(group)?;
    let mut admission = CommitAdmission::default();
    for add in staged_commit.add_proposals() {
        let admitted = admit_added_leaf(
            add.add_proposal().key_package(),
            &tree,
            &admission.added,
            clock,
        )?;
        admission.added.push(admitted);
    }
    for update in staged_commit.update_proposals() {
        let Sender::Member(sender) = update.sender() else {
            return Err(MlsError::CommitProcessingFailed(
                "Update proposal not sent by a member".to_owned(),
            ));
        };
        if let Some(change) =
            admit_replacing_leaf(update.update_proposal().leaf_node(), *sender, &tree)?
        {
            admission.wrapping_key_updates.push(change);
        }
    }
    if let Some(leaf) = staged_commit.update_path_leaf_node()
        && let Some(change) = admit_replacing_leaf(leaf, committer, &tree)?
    {
        admission.wrapping_key_updates.push(change);
    }
    Ok(admission)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use openmls::prelude::tls_codec::Serialize as _;
    use scp_clock::SystemClock;
    use scp_crypto::p256::testing::{uncompressed_point_for, valid_uncompressed_point};

    use super::*;
    use crate::encrypt::{
        DecryptedContent, InboundChange, decrypt_with_membership_changes, decrypt_with_sender_did,
    };
    use crate::group::{
        ScpMlsGroup, add_member, add_member_with_convergent_timestamp, create_group,
        generate_key_package, generate_key_package_without_wrapping_key, join_group,
    };

    fn cred(name: &str) -> ScpCredential {
        ScpCredential::new(
            format!("did:dht:z6Mk{name}"),
            None,
            scp_did::SigningKeyId::Active,
        )
        .unwrap()
    }

    fn did(name: &str) -> String {
        cred(name).did
    }

    /// A `KeyPackage` for `name` publishing `key`.
    fn kp(name: &str, key: &[u8; 65]) -> KeyPackage {
        generate_key_package(&cred(name), key, &SystemClock)
            .unwrap()
            .0
            .key_package()
            .clone()
    }

    /// A `KeyPackage` for `name` whose leaf carries no `0xFF01`.
    fn keyless_kp(name: &str) -> KeyPackage {
        generate_key_package_without_wrapping_key(&cred(name), &SystemClock)
            .unwrap()
            .0
            .key_package()
            .clone()
    }

    /// Alice created the group; Bob and Dave joined through honest adds, and
    /// Bob processed the add of Dave, so all three sit at epoch 2.
    struct Fixture {
        alice: ScpMlsGroup,
        bob: ScpMlsGroup,
        dave: ScpMlsGroup,
    }

    fn fixture() -> Fixture {
        let mut alice = create_group(
            &cred("alice"),
            &uncompressed_point_for(&did("alice")),
            &SystemClock,
        )
        .unwrap();
        let join = |alice: &mut ScpMlsGroup, name: &str| {
            let (bundle, signer, provider) = generate_key_package(
                &cred(name),
                &uncompressed_point_for(&did(name)),
                &SystemClock,
            )
            .unwrap();
            let add = add_member(alice, bundle.key_package().clone().into(), &SystemClock).unwrap();
            let joined = join_group(&add.welcome, provider, signer).unwrap();
            (add.commit, joined)
        };
        let (_, bob) = join(&mut alice, "bob");
        let (add_dave, dave) = join(&mut alice, "dave");
        let mut f = Fixture { alice, bob, dave };
        let bytes = add_dave.tls_serialize_detached().unwrap();
        decrypt_with_sender_did(&mut f.bob, &bytes, &SystemClock).unwrap();
        assert_eq!(f.bob.epoch().unwrap(), 2);
        f
    }

    /// A hostile committer: calls openmls `add_members` on the inner group,
    /// skipping SCP admission, merges its own commit, and returns the Commit
    /// bytes a bystander receives.
    fn hostile_add(group: &mut ScpMlsGroup, key_packages: &[KeyPackage]) -> Vec<u8> {
        let signer = group.signer.as_ref().unwrap();
        let g = group.group.as_mut().unwrap();
        let (commit, _welcome, _info) = g
            .add_members(&group.provider, signer, key_packages)
            .expect("openmls itself accepts the add");
        g.merge_pending_commit(&group.provider).unwrap();
        commit.tls_serialize_detached().unwrap()
    }

    /// A self-update commit whose new leaf carries `params`; the committer
    /// does not merge it.
    fn self_update(group: &mut ScpMlsGroup, params: LeafNodeParameters) -> Vec<u8> {
        let signer = group.signer.as_ref().unwrap();
        let g = group.group.as_mut().unwrap();
        let bundle = g
            .self_update(&group.provider, signer, params)
            .expect("openmls itself accepts the update");
        bundle.commit().tls_serialize_detached().unwrap()
    }

    fn with_wrapping_key(key: &[u8; 65]) -> LeafNodeParameters {
        LeafNodeParameters::builder()
            .with_extensions(
                Extensions::single(crate::wrapping_extension::make_wrapping_key_extension(key))
                    .unwrap(),
            )
            .build()
    }

    fn rejection(err: &MlsError) -> Option<LeafAdmissionRejection> {
        match err {
            MlsError::LeafAdmissionRejected { reason, .. } => Some(*reason),
            _ => None,
        }
    }

    /// A leaf with no `0xFF01` is refused by an honest adder and, when a
    /// hostile adder commits it anyway, by bystanders on both receive paths;
    /// no refusal moves an epoch.
    #[test]
    fn add_without_wrapping_key_is_rejected_by_adder_and_bystanders() {
        let mut f = fixture();

        let err = add_member(&mut f.alice, keyless_kp("carol").into(), &SystemClock)
            .err()
            .expect("admission refuses the add");
        assert_eq!(
            rejection(&err),
            Some(LeafAdmissionRejection::MissingWrappingKey)
        );
        assert_eq!(f.alice.epoch().unwrap(), 2);

        let commit = hostile_add(&mut f.alice, &[keyless_kp("carol")]);
        let err = decrypt_with_sender_did(&mut f.bob, &commit, &SystemClock).unwrap_err();
        assert_eq!(
            rejection(&err),
            Some(LeafAdmissionRejection::MissingWrappingKey)
        );
        assert_eq!(f.bob.epoch().unwrap(), 2);
        let err = decrypt_with_membership_changes(&mut f.dave, &commit, &SystemClock).unwrap_err();
        assert_eq!(
            rejection(&err),
            Some(LeafAdmissionRejection::MissingWrappingKey)
        );
        assert_eq!(f.dave.epoch().unwrap(), 2);
    }

    /// An Add for a DID already in the tree with a different `0xFF01` is
    /// refused: an Add never overwrites a recorded key.
    #[test]
    fn add_of_existing_did_with_a_different_key_is_rejected() {
        let mut f = fixture();
        let other = valid_uncompressed_point(0x77);
        assert_ne!(other, uncompressed_point_for(&did("bob")));

        let err = add_member(&mut f.alice, kp("bob", &other).into(), &SystemClock)
            .err()
            .expect("admission refuses the add");
        assert_eq!(
            rejection(&err),
            Some(LeafAdmissionRejection::WrappingKeyMismatch)
        );
        assert_eq!(f.alice.epoch().unwrap(), 2);

        let commit = hostile_add(&mut f.alice, &[kp("bob", &other)]);
        let err = decrypt_with_membership_changes(&mut f.dave, &commit, &SystemClock).unwrap_err();
        assert_eq!(
            rejection(&err),
            Some(LeafAdmissionRejection::WrappingKeyMismatch)
        );
        assert_eq!(f.dave.epoch().unwrap(), 2);
    }

    /// Two Adds for one new DID in one Commit with different keys are refused.
    #[test]
    fn two_adds_of_one_did_with_different_keys_in_one_commit_are_rejected() {
        let mut f = fixture();
        let commit = hostile_add(
            &mut f.alice,
            &[
                kp("erin", &valid_uncompressed_point(0x11)),
                kp("erin", &valid_uncompressed_point(0x22)),
            ],
        );
        let err = decrypt_with_sender_did(&mut f.dave, &commit, &SystemClock).unwrap_err();
        assert_eq!(
            rejection(&err),
            Some(LeafAdmissionRejection::WrappingKeyMismatch)
        );
        assert_eq!(f.dave.epoch().unwrap(), 2);
    }

    /// A second device of a member, publishing the member's key, is admitted
    /// by the adder and a bystander.
    #[test]
    fn second_device_with_the_same_key_is_admitted() {
        let mut f = fixture();
        let bob_key = uncompressed_point_for(&did("bob"));
        let add = add_member_with_convergent_timestamp(
            &mut f.alice,
            kp("bob", &bob_key).into(),
            &SystemClock,
            SystemClock.now_secs(),
        )
        .unwrap();
        assert_eq!(add.admitted_did, did("bob"));
        assert_eq!(
            add.admitted_wrapping_key,
            scp_protocol::crypto::hpke::p256::P256Point::try_from(bob_key).unwrap()
        );

        let bytes = add.commit.tls_serialize_detached().unwrap();
        match decrypt_with_membership_changes(&mut f.dave, &bytes, &SystemClock).unwrap() {
            InboundChange::Commit {
                added_dids,
                added_wrapping_keys,
                ..
            } => {
                assert_eq!(added_dids, vec![did("bob")]);
                assert_eq!(
                    added_wrapping_keys,
                    vec![scp_protocol::crypto::hpke::p256::P256Point::try_from(bob_key).unwrap()]
                );
            }
            other => panic!("expected a Commit, got {other:?}"),
        }
        assert_eq!(f.dave.epoch().unwrap(), 3);
        assert_eq!(f.dave.members().unwrap().len(), 4);
    }

    /// A DID holds at most ten leaves: ten are admitted, an eleventh is
    /// refused by the adder and by a bystander.
    #[test]
    fn eleventh_leaf_of_one_did_is_rejected() {
        let mut f = fixture();
        let key = uncompressed_point_for(&did("frank"));
        let ten: Vec<_> = (0..MAX_LEAVES_PER_DID).map(|_| kp("frank", &key)).collect();
        let commit = hostile_add(&mut f.alice, &ten);
        decrypt_with_sender_did(&mut f.dave, &commit, &SystemClock).unwrap();
        assert_eq!(f.dave.epoch().unwrap(), 3);

        let err = add_member(&mut f.alice, kp("frank", &key).into(), &SystemClock)
            .err()
            .expect("admission refuses the add");
        assert_eq!(rejection(&err), Some(LeafAdmissionRejection::TooManyLeaves));

        let commit = hostile_add(&mut f.alice, &[kp("frank", &key)]);
        let err = decrypt_with_sender_did(&mut f.dave, &commit, &SystemClock).unwrap_err();
        assert_eq!(rejection(&err), Some(LeafAdmissionRejection::TooManyLeaves));
        assert_eq!(f.dave.epoch().unwrap(), 3);
    }

    /// An update whose new leaf drops `0xFF01` is refused before merge.
    #[test]
    fn update_dropping_the_wrapping_key_is_rejected() {
        let mut f = fixture();
        let commit = self_update(
            &mut f.bob,
            LeafNodeParameters::builder()
                .with_extensions(Extensions::empty())
                .build(),
        );
        let err = decrypt_with_sender_did(&mut f.dave, &commit, &SystemClock).unwrap_err();
        assert_eq!(
            rejection(&err),
            Some(LeafAdmissionRejection::MissingWrappingKey)
        );
        assert_eq!(f.dave.epoch().unwrap(), 2);
        let err = decrypt_with_membership_changes(&mut f.alice, &commit, &SystemClock).unwrap_err();
        assert_eq!(
            rejection(&err),
            Some(LeafAdmissionRejection::MissingWrappingKey)
        );
        assert_eq!(f.alice.epoch().unwrap(), 2);
    }

    /// An update that carries a new valid key is merged and reports the
    /// member's new key on both receive paths; one that keeps the key reports
    /// nothing.
    #[test]
    fn update_with_a_new_key_surfaces_the_change() {
        let mut f = fixture();
        let new_key = valid_uncompressed_point(0x42);
        let commit = self_update(&mut f.bob, with_wrapping_key(&new_key));

        match decrypt_with_sender_did(&mut f.dave, &commit, &SystemClock).unwrap() {
            DecryptedContent::Commit {
                sender_did,
                wrapping_key_updates,
            } => {
                assert_eq!(sender_did, did("bob"));
                assert_eq!(
                    wrapping_key_updates,
                    vec![(
                        did("bob"),
                        scp_protocol::crypto::hpke::p256::P256Point::try_from(new_key).unwrap()
                    )]
                );
            }
            other => panic!("expected a Commit, got {other:?}"),
        }
        match decrypt_with_membership_changes(&mut f.alice, &commit, &SystemClock).unwrap() {
            InboundChange::Commit {
                wrapping_key_updates,
                ..
            } => assert_eq!(
                wrapping_key_updates,
                vec![(
                    did("bob"),
                    scp_protocol::crypto::hpke::p256::P256Point::try_from(new_key).unwrap()
                )]
            ),
            other => panic!("expected a Commit, got {other:?}"),
        }
        assert_eq!(f.dave.epoch().unwrap(), 3);

        // Dave's own update keeping his key changes nothing recorded.
        let commit = self_update(&mut f.dave, LeafNodeParameters::builder().build());
        match decrypt_with_sender_did(&mut f.alice, &commit, &SystemClock).unwrap() {
            DecryptedContent::Commit {
                wrapping_key_updates,
                ..
            } => assert!(wrapping_key_updates.is_empty()),
            other => panic!("expected a Commit, got {other:?}"),
        }
    }

    /// An update whose new leaf names a different DID is refused.
    #[test]
    fn update_changing_the_identity_is_rejected() {
        let mut f = fixture();
        let signer = f.bob.signer.as_ref().unwrap();
        let mallory = CredentialWithKey {
            credential: BasicCredential::new(cred("mallory").to_bytes().unwrap()).into(),
            signature_key: signer.to_public_vec().into(),
        };
        let commit = self_update(
            &mut f.bob,
            LeafNodeParameters::builder()
                .with_credential_with_key(mallory)
                .with_extensions(
                    Extensions::single(crate::wrapping_extension::make_wrapping_key_extension(
                        &uncompressed_point_for(&did("bob")),
                    ))
                    .unwrap(),
                )
                .build(),
        );
        let err = decrypt_with_sender_did(&mut f.dave, &commit, &SystemClock).unwrap_err();
        assert_eq!(
            rejection(&err),
            Some(LeafAdmissionRejection::IdentityChanged)
        );
        assert_eq!(f.dave.epoch().unwrap(), 2);
    }

    /// Every SCP group requires `0xFF01` support of every leaf through its
    /// group context's `RequiredCapabilities`, so openmls refuses a leaf that
    /// does not declare it (`valn0103`).
    #[test]
    fn group_context_requires_the_wrapping_key_capability() {
        let f = fixture();
        for group in [&f.alice, &f.bob, &f.dave] {
            let required = group
                .inner()
                .unwrap()
                .extensions()
                .required_capabilities()
                .expect("RequiredCapabilities is present")
                .extension_types()
                .to_vec();
            assert!(
                required.contains(&ExtensionType::Unknown(
                    crate::wrapping_extension::SCP_WRAPPING_KEY_EXTENSION_TYPE
                )),
                "{required:?}"
            );
        }
    }
}
