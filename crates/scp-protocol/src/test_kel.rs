//! Key-event logs for the crate's tests: an identity whose one root key
//! signs each event, with spec 25's seed-to-scalar rule for every key, and
//! the key state the verdict classifier accepts over its log.

use scp_crypto::p256::{P256SecretKey, SeedLabel, sign_prehash_rfc6979};
use scp_did::{
    CommitmentEntry, CustodyType, FixedCommitment, Identifier, KeyAlgorithm, KeyCondition,
    KeyEntry, KeyRole,
};
use std::time::SystemTime;

use scp_kel::{
    AcceptedChainHolder, Continuation, EncodedPreimage, EntryVerdict, EventPreimage,
    InceptionFields, KeyStateFields, KeyStateSnapshot, OperatorProof, ReplayedState,
    ResolutionInput, ResolutionVerdict, ResolvedState, RetainedChain, SignatureForm, SignerGroup,
    SourceExhaustion, SourceRead, ValidatedChain, classify, encode_preimage,
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
    fn chain(&self) -> TestResult<ValidatedChain> {
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

    /// The key state a first-contact resolution of the log accepts, through
    /// the verdict classifier, the one constructor of a `ResolvedState`
    /// (`03-identity.md` §3.10.10): two sources, read to the end under two
    /// distinct proven operator keys, serve the log (§9.7.4.2 R11's floor).
    pub fn resolved(&self) -> TestResult<ResolvedState> {
        let source = |name: &str, operator: u8| SourceRead {
            name: name.to_owned(),
            units: self.units.clone(),
            exhaustion: SourceExhaustion::Exhausted,
            proof: OperatorProof::Verified {
                operator_key: [operator; 33],
            },
        };
        let classification = classify(ResolutionInput {
            identifier: self.identifier,
            held: None,
            reads: &[source("relay-a", 0x02), source("relay-b", 0x03)],
            now: SystemTime::now(),
        })?;
        match classification.verdict {
            ResolutionVerdict::Adopted { .. } | ResolutionVerdict::Confirmed => {}
            other => return Err(format!("expected Adopted, got {other:?}").into()),
        }
        classification
            .key_state
            .ok_or_else(|| "an Adopted verdict carries a key state".into())
    }

    /// The log as a validating store holds it: [`Self::chain`] held by an
    /// `AcceptedChainHolder`, the one constructor of a `RetainedChain`
    /// (`03-identity.md` §3.10.10).
    pub fn retained(&self) -> TestResult<RetainedChain> {
        let mut holder = AcceptedChainHolder::new();
        let _: scp_kel::HoldOutcome = holder.hold(self.chain()?)?;
        let [retained] = <[RetainedChain; 1]>::try_from(holder.retained())
            .map_err(|held| format!("expected one retained chain, got {}", held.len()))?;
        Ok(retained)
    }

    /// The replay of [`Self::chain`] at its head.
    pub fn replayed(&self) -> TestResult<ReplayedState> {
        Ok(replay(&self.chain()?))
    }
}
