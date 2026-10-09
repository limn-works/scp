//! `InMemoryMlsStorage` writes and deletes exactly what openmls's own
//! `MemoryStorage` writes and deletes.
//!
//! `InMemoryMlsStorage` forwards every `StorageProvider` method but
//! `write_signature_key_pair` to a wrapped `MemoryStorage` through a
//! hand-written body, and a body that drops the call or forwards it to the
//! wrong method still compiles. This test drives one MLS sequence twice, once
//! over `InMemoryMlsProvider` and once over `openmls_rust_crypto`'s
//! `OpenMlsRustCrypto`, whose storage is `MemoryStorage` itself, and after each
//! step compares, for every member, how many storage keys each label holds. A
//! no-op or misrouted forward leaves an entry the reference run deleted, or
//! misses one it wrote, so a label count differs. Neither run stores a signer,
//! so the one method `InMemoryMlsStorage` does not forward is never called.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;

use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use scp_mls::InMemoryMlsProvider;
use scp_mls::group::SCP_CIPHERSUITE;
use tls_codec::{Deserialize as TlsDeserializeTrait, Serialize as TlsSerializeTrait};

/// Every label `openmls_memory_storage` 0.6.0 (`src/lib.rs`) prefixes to a
/// storage key with no draft feature enabled. A key is `label ||
/// serde_json(key) || u16 BE version`, so the label is the key's prefix.
const LABELS: [&str; 19] = [
    "KeyPackage",
    "Psk",
    "EncryptionKeyPair",
    "SignatureKeyPair",
    "EpochKeyPairs",
    "Tree",
    "GroupContext",
    "InterimTranscriptHash",
    "ConfirmationTag",
    "MlsGroupJoinConfig",
    "OwnLeafNodes",
    "GroupState",
    "QueuedProposal",
    "ProposalQueueRefs",
    "OwnLeafNodeIndex",
    "EpochSecrets",
    "ResumptionPsk",
    "MessageSecrets",
    // Not a 0.6.0 label: collects any key no label above prefixes, so an
    // unexpected key still changes a count.
    "<unlabelled>",
];

/// Storage key count per label.
type Histogram = BTreeMap<&'static str, usize>;

/// A provider whose storage keys the test can list.
trait ListKeys: OpenMlsProvider {
    fn storage_keys(&self) -> Vec<Vec<u8>>;
}

impl ListKeys for InMemoryMlsProvider {
    fn storage_keys(&self) -> Vec<Vec<u8>> {
        self.storage()
            .values()
            .read()
            .unwrap()
            .keys()
            .cloned()
            .collect()
    }
}

impl ListKeys for OpenMlsRustCrypto {
    fn storage_keys(&self) -> Vec<Vec<u8>> {
        self.storage()
            .values
            .read()
            .unwrap()
            .keys()
            .cloned()
            .collect()
    }
}

/// The label a storage key starts with; the longest match wins, and a key
/// no label prefixes counts as `<unlabelled>`.
fn label_of(key: &[u8]) -> &'static str {
    LABELS[..LABELS.len() - 1]
        .iter()
        .filter(|label| key.starts_with(label.as_bytes()))
        .max_by_key(|label| label.len())
        .copied()
        .unwrap_or("<unlabelled>")
}

fn histogram<P: ListKeys>(provider: &P) -> Histogram {
    let mut counts = Histogram::new();
    for key in provider.storage_keys() {
        *counts.entry(label_of(&key)).or_default() += 1;
    }
    counts
}

/// Decodes the wire bytes of `message` as a received message.
fn received(message: &MlsMessageOut) -> MlsMessageIn {
    let bytes = message.tls_serialize_detached().unwrap();
    MlsMessageIn::tls_deserialize(&mut bytes.as_slice()).unwrap()
}

struct Member<P> {
    name: &'static str,
    provider: P,
    signer: SignatureKeyPair,
    group: Option<MlsGroup>,
}

impl<P: ListKeys> Member<P> {
    fn new(name: &'static str, provider: P) -> Self {
        let signer = SignatureKeyPair::new(SCP_CIPHERSUITE.signature_algorithm()).unwrap();
        Self {
            name,
            provider,
            signer,
            group: None,
        }
    }

    fn credential(&self) -> CredentialWithKey {
        CredentialWithKey {
            credential: BasicCredential::new(self.name.as_bytes().to_vec()).into(),
            signature_key: self.signer.to_public_vec().into(),
        }
    }

    /// Generates a `KeyPackage`; openmls stores its private keys.
    fn key_package(&self) -> KeyPackage {
        KeyPackage::builder()
            .build(
                SCP_CIPHERSUITE,
                &self.provider,
                &self.signer,
                self.credential(),
            )
            .unwrap()
            .key_package()
            .clone()
    }

    /// Creates a group whose only member is this member.
    fn create_group(&mut self) {
        let config = MlsGroupCreateConfig::builder()
            .ciphersuite(SCP_CIPHERSUITE)
            .use_ratchet_tree_extension(true)
            .build();
        let group = MlsGroup::new(&self.provider, &self.signer, &config, self.credential());
        self.group = Some(group.unwrap());
    }

    /// Joins the group the Welcome in `welcome` admits this member to.
    fn join(&mut self, welcome: &MlsMessageOut) {
        let MlsMessageBodyIn::Welcome(welcome) = received(welcome).extract() else {
            panic!("{} expected a Welcome", self.name);
        };
        let config = MlsGroupJoinConfig::builder()
            .use_ratchet_tree_extension(true)
            .build();
        let staged = StagedWelcome::new_from_welcome(&self.provider, &config, welcome, None);
        self.group = Some(staged.unwrap().into_group(&self.provider).unwrap());
    }

    /// Adds the owners of `key_packages`, merges the Commit, and returns the
    /// Welcome.
    fn add(&mut self, key_packages: &[KeyPackage]) -> MlsMessageOut {
        let group = self.group.as_mut().unwrap();
        let (_commit, welcome, _group_info) = group
            .add_members(&self.provider, &self.signer, key_packages)
            .unwrap();
        group.merge_pending_commit(&self.provider).unwrap();
        welcome
    }

    /// Commits an update of this member's own leaf, merges it, and returns
    /// the Commit.
    fn self_update(&mut self) -> MlsMessageOut {
        let group = self.group.as_mut().unwrap();
        let commit = group
            .self_update(&self.provider, &self.signer, LeafNodeParameters::default())
            .unwrap()
            .into_commit();
        group.merge_pending_commit(&self.provider).unwrap();
        commit
    }

    /// Proposes an update of this member's own leaf and returns the Proposal.
    fn propose_update(&mut self) -> MlsMessageOut {
        let group = self.group.as_mut().unwrap();
        let (proposal, _proposal_ref) = group
            .propose_self_update(&self.provider, &self.signer, LeafNodeParameters::default())
            .unwrap();
        proposal
    }

    /// Commits every queued proposal, merges the Commit, and returns it.
    fn commit_queued(&mut self) -> MlsMessageOut {
        let group = self.group.as_mut().unwrap();
        let (commit, _welcome, _group_info) = group
            .commit_to_pending_proposals(&self.provider, &self.signer)
            .unwrap();
        group.merge_pending_commit(&self.provider).unwrap();
        commit
    }

    /// Removes the member at `leaf`, merges the Commit, and returns it.
    fn remove(&mut self, leaf: LeafNodeIndex) -> MlsMessageOut {
        let group = self.group.as_mut().unwrap();
        let (commit, _welcome, _group_info) = group
            .remove_members(&self.provider, &self.signer, &[leaf])
            .unwrap();
        group.merge_pending_commit(&self.provider).unwrap();
        commit
    }

    fn leaf_index(&self) -> LeafNodeIndex {
        self.group.as_ref().unwrap().own_leaf_index()
    }

    /// Deletes the group's state from storage.
    fn delete_group(&mut self) {
        let group = self.group.as_mut().unwrap();
        group.delete(self.provider.storage()).unwrap();
    }

    /// Processes `message` from another member and returns its content.
    fn process(&mut self, message: &MlsMessageOut) -> ProcessedMessageContent {
        let message = received(message).try_into_protocol_message().unwrap();
        let group = self.group.as_mut().unwrap();
        group
            .process_message(&self.provider, message)
            .unwrap()
            .into_content()
    }

    /// Processes `commit` from another member and merges it.
    fn receive_commit(&mut self, commit: &MlsMessageOut) {
        let ProcessedMessageContent::StagedCommitMessage(staged) = self.process(commit) else {
            panic!("{} expected a Commit", self.name);
        };
        let group = self.group.as_mut().unwrap();
        group.merge_staged_commit(&self.provider, *staged).unwrap();
    }

    /// Processes `proposal` from another member and queues it.
    fn receive_proposal(&mut self, proposal: &MlsMessageOut) {
        let ProcessedMessageContent::ProposalMessage(queued) = self.process(proposal) else {
            panic!("{} expected a Proposal", self.name);
        };
        let group = self.group.as_mut().unwrap();
        group
            .store_pending_proposal(self.provider.storage(), *queued)
            .unwrap();
    }
}

/// Per step, the step's name and each member's histogram.
type Trace = Vec<(&'static str, Vec<(&'static str, Histogram)>)>;

fn record<P: ListKeys>(trace: &mut Trace, step: &'static str, members: [&Member<P>; 3]) {
    trace.push((
        step,
        members
            .iter()
            .map(|m| (m.name, histogram(&m.provider)))
            .collect(),
    ));
}

/// Runs the sequence over providers `new_provider` builds and returns the
/// histograms after each step: Bob and Carol generate a `KeyPackage`; Alice
/// creates a group and adds both; Bob and Carol join from the Welcome; Alice
/// commits a self-update that Bob and Carol merge; Bob proposes an update of
/// his own leaf, Alice and Carol queue it, and Alice commits it, which makes
/// Bob delete the leaf's encryption key pair (the only path in openmls 0.9.0
/// that calls `delete_encryption_key_pair`); Alice removes Carol, and Bob and
/// Carol merge the removal; each member deletes its group (the only path that
/// calls `delete_message_secrets`).
fn run<P: ListKeys>(new_provider: fn() -> P) -> Trace {
    let mut trace = Trace::new();
    let mut alice = Member::new("alice", new_provider());
    let mut bob = Member::new("bob", new_provider());
    let mut carol = Member::new("carol", new_provider());

    let key_packages = [bob.key_package(), carol.key_package()];
    record(&mut trace, "key_packages", [&alice, &bob, &carol]);

    alice.create_group();
    record(&mut trace, "create", [&alice, &bob, &carol]);

    let welcome = alice.add(&key_packages);
    record(&mut trace, "add", [&alice, &bob, &carol]);

    bob.join(&welcome);
    carol.join(&welcome);
    record(&mut trace, "join", [&alice, &bob, &carol]);

    let commit = alice.self_update();
    bob.receive_commit(&commit);
    carol.receive_commit(&commit);
    record(&mut trace, "self_update", [&alice, &bob, &carol]);

    let proposal = bob.propose_update();
    alice.receive_proposal(&proposal);
    carol.receive_proposal(&proposal);
    record(&mut trace, "update_proposal", [&alice, &bob, &carol]);

    let commit = alice.commit_queued();
    bob.receive_commit(&commit);
    carol.receive_commit(&commit);
    record(&mut trace, "update_commit", [&alice, &bob, &carol]);

    let commit = alice.remove(carol.leaf_index());
    bob.receive_commit(&commit);
    carol.receive_commit(&commit);
    record(&mut trace, "remove", [&alice, &bob, &carol]);

    alice.delete_group();
    bob.delete_group();
    carol.delete_group();
    record(&mut trace, "delete", [&alice, &bob, &carol]);

    trace
}

#[test]
fn storage_label_counts_match_memory_storage_after_every_step() {
    let scp = run(InMemoryMlsProvider::default);
    let reference = run(OpenMlsRustCrypto::default);

    // Controls: the reference run observes the writes and deletes the
    // mutants target, so an equal trace is not equal by being empty.
    let count = |trace: &Trace, step: &str, member: &str, label: &str| -> usize {
        let (_, members) = trace.iter().find(|(s, _)| *s == step).unwrap();
        let (_, h) = members.iter().find(|(m, _)| *m == member).unwrap();
        h.get(label).copied().unwrap_or(0)
    };
    assert_eq!(count(&reference, "key_packages", "bob", "KeyPackage"), 1);
    assert_eq!(count(&reference, "join", "bob", "KeyPackage"), 0);
    assert!(count(&reference, "join", "bob", "MessageSecrets") > 0);
    assert_eq!(
        count(&reference, "update_proposal", "bob", "EncryptionKeyPair"),
        1
    );
    assert_eq!(
        count(&reference, "update_commit", "bob", "EncryptionKeyPair"),
        0
    );
    assert_eq!(count(&reference, "delete", "bob", "MessageSecrets"), 0);
    assert_eq!(count(&reference, "delete", "bob", "<unlabelled>"), 0);

    assert_eq!(scp.len(), reference.len());
    for ((step, scp_members), (_, reference_members)) in scp.iter().zip(&reference) {
        assert_eq!(
            scp_members, reference_members,
            "after step `{step}`, InMemoryMlsStorage's per-label key counts must equal MemoryStorage's"
        );
    }
}
