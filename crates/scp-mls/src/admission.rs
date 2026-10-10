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
//!   4. on the tree **after** the Commit ([`admit_staged_commit`]), every leaf
//!      the DID holds carries the same `0xFF01`, and the DID holds at most
//!      [`MAX_LEAVES_PER_DID`] leaves. The Commit's Removes, Update proposals
//!      and `UpdatePath` are applied first, so a Remove frees a DID's key and
//!      count in the same Commit and a rotation is checked against the Adds it
//!      travels with.
//! - **Replaced leaf** (an Update proposal's leaf or the Commit's `UpdatePath`
//!   leaf): it carries a valid `0xFF01` and names the same DID as the leaf it
//!   replaces. A changed key is reported in [`MemberLeaves::rotated`] so
//!   the member directory can follow a rotation.
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
    /// The tree's leaves after the Commit, from which every holder of a
    /// wrapping-key directory rebuilds it without a fallible step after the
    /// merge.
    pub(crate) members: MemberLeaves,
}

/// The occupied leaves of a group's tree, each with its DID and `0xFF01`
/// key, plus the key rotations the Commit that produced the tree carried.
///
/// A Commit's admission computes this for the tree **after** the Commit,
/// before the merge, so a caller replaces its wrapping-key directory with
/// [`Self::wrapping_key_directory`] after the merge without any step that can
/// fail. The directory therefore never disagrees with the tree: a Remove drops
/// the DID's last leaf from it, an Add records the admitted key, and an
/// Update records the rotation.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MemberLeaves {
    leaves: Vec<AdmittedLeaf>,
    rotated: Vec<(String, P256Point)>,
}

impl MemberLeaves {
    /// Reads the current tree of `group`, for a group no Commit produced
    /// (a created group or a joined one).
    ///
    /// # Errors
    ///
    /// [`MlsError::GroupDestroyed`] for a destroyed group, or any error of
    /// reading the tree's leaves (a malformed tree, a non-SCP credential, or
    /// a malformed `0xFF01`).
    pub fn of_group(group: &crate::group::ScpMlsGroup) -> Result<Self, MlsError> {
        let g = group.inner()?;
        Ok(Self {
            leaves: tree_leaves(g)?
                .into_iter()
                .filter_map(|l| {
                    l.wrapping_key.map(|wrapping_key| AdmittedLeaf {
                        did: l.did,
                        wrapping_key,
                    })
                })
                .collect(),
            rotated: Vec::new(),
        })
    }

    /// The `did → 0xFF01` directory of these leaves.
    ///
    /// A DID whose leaves all publish one key maps to that key. A DID whose
    /// devices publish different keys (one device rotated through its own
    /// Update and the others have not yet, spec 09 §9.16.1) maps to the key
    /// this Commit rotated it to, else to `previous`'s key while a leaf still
    /// publishes it, else to the key of its lowest-index leaf. A DID with no
    /// leaf is absent.
    #[must_use]
    pub fn wrapping_key_directory(
        &self,
        previous: &std::collections::HashMap<String, P256Point>,
    ) -> std::collections::HashMap<String, P256Point> {
        let mut directory: std::collections::HashMap<String, P256Point> =
            std::collections::HashMap::new();
        for leaf in &self.leaves {
            let Some(&recorded) = directory.get(&leaf.did) else {
                directory.insert(leaf.did.clone(), leaf.wrapping_key);
                continue;
            };
            if recorded == leaf.wrapping_key {
                continue;
            }
            let published = |key: &P256Point| {
                self.leaves
                    .iter()
                    .any(|l| l.did == leaf.did && l.wrapping_key == *key)
            };
            let rotated = self
                .rotated
                .iter()
                .rev()
                .find(|(did, key)| *did == leaf.did && published(key))
                .map(|(_, key)| *key);
            let kept = previous.get(&leaf.did).copied().filter(|k| published(k));
            if let Some(key) = rotated.or(kept) {
                directory.insert(leaf.did.clone(), key);
            }
        }
        directory
    }

    /// `previous` carried across the Commit that produced these leaves: every
    /// DID in `previous` or in `added`, mapped to its
    /// [`Self::wrapping_key_directory`] key; a DID left with no leaf is
    /// dropped. A caller that caches only some members' keys keeps the same
    /// set of members, and every cached key equals the tree's.
    #[must_use]
    pub fn follow_directory(
        &self,
        previous: &std::collections::HashMap<String, P256Point>,
        added: &[&str],
    ) -> std::collections::HashMap<String, P256Point> {
        let mut directory = self.wrapping_key_directory(previous);
        directory.retain(|did, _| previous.contains_key(did) || added.contains(&did.as_str()));
        directory
    }

    /// The leaves, in tree order with added leaves last.
    #[must_use]
    pub fn leaves(&self) -> &[AdmittedLeaf] {
        &self.leaves
    }

    /// `(did, key)` for each replaced leaf whose `0xFF01` changed in the
    /// Commit that produced these leaves, in the order it applied them.
    #[must_use]
    pub fn rotated(&self) -> &[(String, P256Point)] {
        &self.rotated
    }
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

/// The checks an added leaf passes on its own, before the Commit-wide rules:
/// the `KeyPackage` `Lifetime` against the hardened clock, an SCP credential,
/// and a present, valid `0xFF01`.
///
/// # Errors
///
/// In check order: [`MlsError::KeyPackageLifetimeInvalid`],
/// [`MlsError::InvalidCredential`], [`MlsError::ExtensionError`] (a
/// malformed `0xFF01`), then [`MlsError::LeafAdmissionRejected`] with
/// [`LeafAdmissionRejection::MissingWrappingKey`].
pub(crate) fn admit_added_leaf(
    key_package: &KeyPackage,
    clock: &dyn Clock,
) -> Result<AdmittedLeaf, MlsError> {
    validate_key_package_lifetime(key_package.life_time(), clock)?;
    let leaf = key_package.leaf_node();
    let did = leaf_did(leaf)?;
    let wrapping_key = required_wrapping_key(leaf, &did)?;
    Ok(AdmittedLeaf { did, wrapping_key })
}

/// Admits `leaf` as the replacement of the tree leaf at `replaced_index`.
/// Returns the new key when it differs from the replaced leaf's.
fn admit_replacing_leaf(
    leaf: &LeafNode,
    replaced_index: LeafNodeIndex,
    tree: &[TreeLeaf],
) -> Result<(AdmittedLeaf, Option<(String, P256Point)>), MlsError> {
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
    let change = (replaced.wrapping_key != Some(wrapping_key)).then(|| (did.clone(), wrapping_key));
    Ok((AdmittedLeaf { did, wrapping_key }, change))
}

/// Replaces the leaf at `index` in the post-commit model.
fn replace_leaf(
    after: &mut [TreeLeaf],
    index: LeafNodeIndex,
    leaf: AdmittedLeaf,
) -> Result<(), MlsError> {
    let slot = after
        .iter_mut()
        .find(|l| l.index == index.u32())
        .ok_or_else(|| MlsError::MemberNotFound(index.u32()))?;
    slot.did = leaf.did;
    slot.wrapping_key = Some(leaf.wrapping_key);
    Ok(())
}

/// Admits a staged Commit, before it is merged, by the verdict the rules give
/// on the tree **after** the Commit (spec 09 §9.16.1, spec 10 §10.8.1(7)).
///
/// The post-commit tree is the current tree with the Commit applied in RFC
/// 9420 §12.3 order: Update proposals replace their senders' leaves, Removes
/// blank leaves, Adds insert leaves, and the `UpdatePath` leaf replaces the
/// committer's leaf. Every replacing leaf keeps its DID and carries a valid
/// `0xFF01`; every added leaf passes [`admit_added_leaf`]. Then, for every
/// added leaf, every leaf its DID holds in the post-commit tree carries the
/// added leaf's `0xFF01`, and the DID holds at most [`MAX_LEAVES_PER_DID`]
/// leaves. A Remove therefore frees its DID's key and leaf count within the
/// same Commit, and an `UpdatePath` rotation is checked against the Adds it
/// travels with.
///
/// `committer` is the Commit sender's leaf, which the `UpdatePath` leaf (when
/// present) replaces.
///
/// # Errors
///
/// Any error of [`admit_added_leaf`]; for a replacing leaf the same credential
/// and `0xFF01` errors or [`LeafAdmissionRejection::IdentityChanged`];
/// [`LeafAdmissionRejection::WrappingKeyMismatch`] or
/// [`LeafAdmissionRejection::TooManyLeaves`] from the post-commit rules; or
/// [`MlsError::CommitProcessingFailed`] if an Update proposal was not sent by
/// a member. The caller drops the staged commit unmerged on any error.
pub(crate) fn admit_staged_commit(
    group: &MlsGroup,
    staged_commit: &StagedCommit,
    committer: LeafNodeIndex,
    clock: &dyn Clock,
) -> Result<CommitAdmission, MlsError> {
    let tree = tree_leaves(group)?;
    let mut after = tree.clone();
    let mut admission = CommitAdmission::default();

    for update in staged_commit.update_proposals() {
        let Sender::Member(sender) = update.sender() else {
            return Err(MlsError::CommitProcessingFailed(
                "Update proposal not sent by a member".to_owned(),
            ));
        };
        let (leaf, change) =
            admit_replacing_leaf(update.update_proposal().leaf_node(), *sender, &tree)?;
        replace_leaf(&mut after, *sender, leaf)?;
        admission.wrapping_key_updates.extend(change);
    }
    for remove in staged_commit.remove_proposals() {
        let removed = remove.remove_proposal().removed().u32();
        after.retain(|l| l.index != removed);
    }
    if let Some(leaf) = staged_commit.update_path_leaf_node() {
        let (leaf, change) = admit_replacing_leaf(leaf, committer, &tree)?;
        replace_leaf(&mut after, committer, leaf)?;
        admission.wrapping_key_updates.extend(change);
    }
    for add in staged_commit.add_proposals() {
        admission
            .added
            .push(admit_added_leaf(add.add_proposal().key_package(), clock)?);
    }

    let post_commit: Vec<(&str, Option<P256Point>)> = after
        .iter()
        .map(|l| (l.did.as_str(), l.wrapping_key))
        .chain(
            admission
                .added
                .iter()
                .map(|l| (l.did.as_str(), Some(l.wrapping_key))),
        )
        .collect();
    for added in &admission.added {
        let mut held = 0usize;
        for (_, key) in post_commit.iter().filter(|(did, _)| *did == added.did) {
            held += 1;
            if *key != Some(added.wrapping_key) {
                return Err(MlsError::LeafAdmissionRejected {
                    did: added.did.clone(),
                    reason: LeafAdmissionRejection::WrappingKeyMismatch,
                });
            }
        }
        if held > MAX_LEAVES_PER_DID {
            return Err(MlsError::LeafAdmissionRejected {
                did: added.did.clone(),
                reason: LeafAdmissionRejection::TooManyLeaves,
            });
        }
    }

    admission.members = MemberLeaves {
        leaves: after
            .into_iter()
            .filter_map(|l| {
                l.wrapping_key.map(|wrapping_key| AdmittedLeaf {
                    did: l.did,
                    wrapping_key,
                })
            })
            .chain(admission.added.iter().cloned())
            .collect(),
        rotated: admission.wrapping_key_updates.clone(),
    };
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
        let rotated = vec![(
            did("bob"),
            scp_protocol::crypto::hpke::p256::P256Point::try_from(new_key).unwrap(),
        )];
        let commit = self_update(&mut f.bob, with_wrapping_key(&new_key));

        match decrypt_with_sender_did(&mut f.dave, &commit, &SystemClock).unwrap() {
            DecryptedContent::Commit {
                sender_did,
                members,
            } => {
                assert_eq!(sender_did, did("bob"));
                assert_eq!(members.rotated(), rotated.as_slice());
                assert_eq!(
                    members
                        .wrapping_key_directory(&std::collections::HashMap::new())
                        .get(&did("bob")),
                    Some(&rotated[0].1)
                );
            }
            other => panic!("expected a Commit, got {other:?}"),
        }
        match decrypt_with_membership_changes(&mut f.alice, &commit, &SystemClock).unwrap() {
            InboundChange::Commit { members, .. } => {
                assert_eq!(members.rotated(), rotated.as_slice());
            }
            other => panic!("expected a Commit, got {other:?}"),
        }
        assert_eq!(f.dave.epoch().unwrap(), 3);

        // Dave's own update keeping his key changes nothing recorded.
        let commit = self_update(&mut f.dave, LeafNodeParameters::builder().build());
        match decrypt_with_sender_did(&mut f.alice, &commit, &SystemClock).unwrap() {
            DecryptedContent::Commit { members, .. } => assert!(members.rotated().is_empty()),
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

    /// Processes a peer's proposal on `group` and stores it, as an openmls
    /// client that accepts proposals by reference does. SCP's own receive path
    /// does not store proposals, so these tests store them directly.
    fn cache_proposal(group: &mut ScpMlsGroup, out: &MlsMessageOut) {
        use openmls::prelude::tls_codec::Deserialize as _;
        use openmls::prelude::{MlsMessageIn, OpenMlsProvider as _, ProcessedMessageContent};
        let bytes = out.tls_serialize_detached().unwrap();
        let message = MlsMessageIn::tls_deserialize_exact(bytes.as_slice()).unwrap();
        let g = group.group.as_mut().unwrap();
        let processed = g
            .process_message(
                &group.provider,
                message.try_into_protocol_message().unwrap(),
            )
            .unwrap();
        let ProcessedMessageContent::ProposalMessage(proposal) = processed.into_content() else {
            panic!("expected a proposal");
        };
        g.store_pending_proposal(group.provider.storage(), *proposal)
            .unwrap();
    }

    fn leaf_of(group: &ScpMlsGroup, name: &str) -> LeafNodeIndex {
        group
            .inner()
            .unwrap()
            .members()
            .find(|m| {
                BasicCredential::try_from(m.credential.clone())
                    .ok()
                    .and_then(|b| ScpCredential::from_bytes(b.identity()).ok())
                    .is_some_and(|c| c.did == did(name))
            })
            .map(|m| m.index)
            .unwrap()
    }

    /// Alice proposes removing `index` and Dave caches the proposal.
    fn propose_remove(f: &mut Fixture, index: LeafNodeIndex) {
        let signer = f.alice.signer.as_ref().unwrap();
        let g = f.alice.group.as_mut().unwrap();
        let (out, _) = g
            .propose_remove_member(&f.alice.provider, signer, index)
            .unwrap();
        cache_proposal(&mut f.dave, &out);
    }

    /// One Commit that removes Bob's leaf and adds Bob back under a new key is
    /// admitted by the adder and by a bystander: the Remove leaves Bob no leaf
    /// whose key the Add would contradict.
    #[test]
    fn remove_and_re_add_with_a_new_key_in_one_commit_is_admitted() {
        let mut f = fixture();
        let new_key = valid_uncompressed_point(0x5a);
        let bob = leaf_of(&f.alice, "bob");
        propose_remove(&mut f, bob);

        let add = add_member(&mut f.alice, kp("bob", &new_key).into(), &SystemClock)
            .expect("the post-commit tree holds one Bob leaf, under the new key");
        let new_key = scp_protocol::crypto::hpke::p256::P256Point::try_from(new_key).unwrap();
        let empty = std::collections::HashMap::new();
        assert_eq!(
            add.members.wrapping_key_directory(&empty).get(&did("bob")),
            Some(&new_key)
        );
        assert_eq!(f.alice.epoch().unwrap(), 3);

        let bytes = add.commit.tls_serialize_detached().unwrap();
        match decrypt_with_sender_did(&mut f.dave, &bytes, &SystemClock).unwrap() {
            DecryptedContent::Commit { members, .. } => {
                let directory = members.wrapping_key_directory(&empty);
                assert_eq!(directory.get(&did("bob")), Some(&new_key));
                assert_eq!(directory.len(), 3);
            }
            other => panic!("expected a Commit, got {other:?}"),
        }
        assert_eq!(f.dave.epoch().unwrap(), 3);
    }

    /// A DID at the cap may swap one leaf: a Commit that removes one of its ten
    /// leaves and adds another is admitted, because the removed leaf no longer
    /// counts.
    #[test]
    fn removed_leaves_do_not_count_toward_the_cap() {
        let mut f = fixture();
        let key = uncompressed_point_for(&did("frank"));
        let ten: Vec<_> = (0..MAX_LEAVES_PER_DID).map(|_| kp("frank", &key)).collect();
        let commit = hostile_add(&mut f.alice, &ten);
        decrypt_with_sender_did(&mut f.dave, &commit, &SystemClock).unwrap();
        assert_eq!(f.dave.epoch().unwrap(), 3);

        let frank = leaf_of(&f.alice, "frank");
        propose_remove(&mut f, frank);
        let add = add_member(&mut f.alice, kp("frank", &key).into(), &SystemClock)
            .expect("ten leaves after the commit");
        let bytes = add.commit.tls_serialize_detached().unwrap();
        decrypt_with_sender_did(&mut f.dave, &bytes, &SystemClock)
            .expect("the bystander counts the post-commit tree");
        assert_eq!(f.dave.epoch().unwrap(), 4);
        assert_eq!(f.dave.members().unwrap().len(), 3 + MAX_LEAVES_PER_DID);
    }

    /// Bob's `UpdatePath` rotates his key to K2 while the same Commit adds a
    /// second Bob device under the old key K1: after the Commit Bob would
    /// publish two keys, so the Commit is refused by the committer's own
    /// admission and by a bystander, and neither merges.
    #[test]
    fn update_path_rotation_with_an_add_under_the_old_key_is_rejected() {
        let mut f = fixture();
        let old_key = uncompressed_point_for(&did("bob"));
        let new_key = valid_uncompressed_point(0x6b);

        // Bob proposes adding his second device under K1, then commits with an
        // UpdatePath to K2 (openmls folds the held proposal into the Commit).
        let signer = f.bob.signer.as_ref().unwrap();
        let g = f.bob.group.as_mut().unwrap();
        let (proposal, _) = g
            .propose_add_member(&f.bob.provider, signer, &kp("bob", &old_key))
            .unwrap();
        cache_proposal(&mut f.dave, &proposal);

        // The committer's own admission refuses and clears the Commit.
        let err =
            crate::ratchet::propose_update_with_wrapping_key(&mut f.bob, &new_key, &SystemClock)
                .err()
                .expect("the committer refuses its own commit");
        assert_eq!(
            rejection(&err),
            Some(LeafAdmissionRejection::WrappingKeyMismatch)
        );
        assert_eq!(f.bob.epoch().unwrap(), 2);
        assert!(f.bob.inner().unwrap().pending_commit().is_none());

        // A committer skipping admission sends it anyway; the bystander refuses.
        let commit = self_update(&mut f.bob, with_wrapping_key(&new_key));
        let err = decrypt_with_sender_did(&mut f.dave, &commit, &SystemClock).unwrap_err();
        assert_eq!(
            rejection(&err),
            Some(LeafAdmissionRejection::WrappingKeyMismatch)
        );
        assert_eq!(f.dave.epoch().unwrap(), 2);
        assert_eq!(f.dave.members().unwrap().len(), 3);
    }

    /// A DID whose devices publish different keys after a rotation maps to
    /// the rotated key, keeps the previous key while a leaf still publishes
    /// it, and otherwise maps to its lowest-index leaf's key.
    #[test]
    fn directory_resolves_a_mid_rotation_did() {
        let k = |b| {
            scp_protocol::crypto::hpke::p256::P256Point::try_from(valid_uncompressed_point(b))
                .unwrap()
        };
        let leaf = |key| AdmittedLeaf {
            did: did("bob"),
            wrapping_key: key,
        };
        let mut members = MemberLeaves {
            leaves: vec![leaf(k(1)), leaf(k(2))],
            rotated: vec![(did("bob"), k(2))],
        };
        let empty = std::collections::HashMap::new();
        assert_eq!(members.wrapping_key_directory(&empty)[&did("bob")], k(2));
        members.rotated.clear();
        let previous = std::collections::HashMap::from([(did("bob"), k(2))]);
        assert_eq!(members.wrapping_key_directory(&previous)[&did("bob")], k(2));
        assert_eq!(members.wrapping_key_directory(&empty)[&did("bob")], k(1));
        let stale = std::collections::HashMap::from([(did("bob"), k(3))]);
        assert_eq!(members.wrapping_key_directory(&stale)[&did("bob")], k(1));
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
