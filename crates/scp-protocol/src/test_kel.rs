//! Key-event logs for the crate's tests: an identity whose one root key
//! signs each event, with spec 25's seed-to-scalar rule for every key, and
//! the chain `validate_entry` accepts over its log.

use scp_crypto::p256::{P256SecretKey, SeedLabel, sign_prehash_rfc6979};
use scp_did::{
    CommitmentEntry, CustodyType, FixedCommitment, Identifier, KeyAlgorithm, KeyCondition,
    KeyEntry, KeyRole,
};
use scp_kel::{
    Continuation, EncodedPreimage, EntryVerdict, EventPreimage, InceptionFields, KeyStateFields,
    KeyStateSnapshot, ReplayedState, SignatureForm, SignerGroup, ValidatedChain, encode_preimage,
    prerotation_commitment, replay, validate_entry,
};
use sha2::{Digest, Sha256};

pub type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// The P-256 key spec 25 derives from 32 bytes of `seed`.
pub fn key(seed: u8) -> P256SecretKey {
    P256SecretKey::from_seed(SeedLabel::TestVectorKey, &[seed; 32])
}

/// The compressed point of [`key`].
pub fn point(seed: u8) -> [u8; 33] {
    key(seed).public_key().to_compressed()
}

/// One identity: its root key, its log, and the digest and snapshot of the
/// log's last event.
pub struct Identity {
    root: P256SecretKey,
    pub identifier: Identifier,
    units: Vec<Vec<u8>>,
    /// The preimage digest of the log's last event, the identity's
    /// `key_state_head` after it.
    pub head: [u8; 32],
    snapshot: KeyStateSnapshot,
}

const fn entry(key: [u8; 33], role: KeyRole, condition: KeyCondition) -> KeyEntry {
    KeyEntry {
        key,
        role,
        condition,
        compromised_from: 0,
        custody_type: CustodyType::Software,
        key_algorithm: KeyAlgorithm::EcdsaP256Sha256,
    }
}

fn root_group() -> SignerGroup {
    SignerGroup {
        indices: vec![0],
        forms: vec![SignatureForm::Raw],
    }
}

/// `BE32(len) ‖ signed preimage ‖ the root key's raw signature`.
fn unit(encoded: &EncodedPreimage, root: &P256SecretKey) -> TestResult<Vec<u8>> {
    let signed = encoded.signed_preimage();
    let signature = sign_prehash_rfc6979(root, &Sha256::digest(&signed).into())?;
    let mut unit = u32::try_from(signed.len())?.to_be_bytes().to_vec();
    unit.extend_from_slice(&signed);
    unit.extend_from_slice(&signature);
    Ok(unit)
}

/// An inception with one root member at threshold 1, one `#active` key and
/// a commitment to one next key.
pub fn incept(root_seed: u8, active_seed: u8, next_seed: u8) -> TestResult<Identity> {
    let root = key(root_seed);
    let snapshot = KeyStateSnapshot {
        root_threshold: 1,
        keys: vec![
            entry(point(root_seed), KeyRole::RootMember, KeyCondition::Current),
            entry(point(active_seed), KeyRole::Active, KeyCondition::Current),
        ],
        witnesses: vec![Identifier::from_bytes([0x77; 32])],
        witnessing_interval: 3600,
        service_key_role: KeyRole::Active,
        delegator: Identifier::ZERO,
    };
    let encoded = encode_preimage(&EventPreimage::inception(InceptionFields {
        root_group: root_group(),
        key_state: snapshot.clone(),
        continuation: Continuation::FixesCommitment(FixedCommitment {
            commitments: vec![CommitmentEntry {
                commitment: prerotation_commitment(&point(next_seed)),
                custody_type: CustodyType::Software,
                key_algorithm: KeyAlgorithm::EcdsaP256Sha256,
            }],
            next_threshold: 1,
        }),
    }))?;
    let identifier = encoded
        .inception_identifier()
        .ok_or("an inception derives its identifier")?;
    Ok(Identity {
        units: vec![unit(&encoded, &root)?],
        head: encoded.event_digest(),
        root,
        identifier,
        snapshot,
    })
}

impl Identity {
    /// The log extended by a `KeyState` that installs `active_seed`'s key and
    /// drops every earlier `#active` key `Superseded`, in R3's snapshot
    /// order: kept entries, the installed key, the dropped entries.
    pub fn rotate(mut self, active_seed: u8) -> TestResult<Self> {
        let (dropped, kept): (Vec<KeyEntry>, Vec<KeyEntry>) = self
            .snapshot
            .keys
            .iter()
            .copied()
            .partition(|entry| entry.role == KeyRole::Active);
        let mut snapshot = self.snapshot.clone();
        snapshot.keys = kept;
        snapshot.keys.push(entry(
            point(active_seed),
            KeyRole::Active,
            KeyCondition::Current,
        ));
        snapshot
            .keys
            .extend(dropped.into_iter().map(|entry| KeyEntry {
                condition: KeyCondition::Superseded,
                ..entry
            }));
        let encoded = encode_preimage(&EventPreimage::key_state(KeyStateFields {
            identifier: self.identifier,
            sequence: u64::try_from(self.units.len())?,
            predecessor_digest: self.head,
            root_group: root_group(),
            key_state: snapshot.clone(),
            seals: Vec::new(),
        }))?;
        self.units.push(unit(&encoded, &self.root)?);
        self.head = encoded.event_digest();
        self.snapshot = snapshot;
        Ok(self)
    }

    /// The one chain of the unforked log `validate_entry` accepts.
    pub fn chain(&self) -> TestResult<ValidatedChain> {
        let units: Vec<&[u8]> = self.units.iter().map(Vec::as_slice).collect();
        let validation = validate_entry(&self.identifier, &units);
        if !validation.discarded.is_empty() {
            return Err(format!("discarded {:?}", validation.discarded).into());
        }
        match validation.verdict {
            EntryVerdict::Valid { chains } => chains
                .single()
                .cloned()
                .ok_or_else(|| format!("expected one chain, got {chains:?}").into()),
            other => Err(format!("expected a valid chain, got {other:?}").into()),
        }
    }

    /// The replay of [`Self::chain`] at its head.
    pub fn replayed(&self) -> TestResult<ReplayedState> {
        Ok(replay(&self.chain()?))
    }
}
