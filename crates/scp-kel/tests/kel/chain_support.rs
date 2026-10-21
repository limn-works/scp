//! Support for the `validate_chain` tests (`09-security-model.md` §9.7.4.2
//! R3): keys from spec 25's seeds and from test labels, a field writer that
//! applies none of the encoder's refusals, units signed slot by slot, and
//! the base chains the fixtures extend.
//!
//! Every expected identifier and digest a test compares against is computed
//! here with `sha2` over bytes the test assembled itself, or is a spec 25
//! constant; none is a value scp-kel returns.

use scp_crypto::p256::{P256SecretKey, SeedLabel, sign_prehash_rfc6979};
use scp_did::{
    CommitmentEntry, CustodyType, Identifier, KeyAlgorithm, KeyCondition, KeyEntry, KeyRole,
    StandingCommitment,
};
use scp_kel::{
    Continuation, EventKind, EventPreimage, InstalledRootSet, KeyStateFields, KeyStateSnapshot,
    SignatureForm, SignerGroup, SignerGroupRole, StandingRootDeclaration, decode_preimage,
    prerotation_commitment,
};
use sha2::{Digest, Sha256};

use super::fixtures::{
    V41_ACTIVE, V41_DIGEST, V41_IDENTIFIER, V41_PREIMAGE, V41_ROOT, V41_SIGNATURE, V41_WITNESS,
    V42_IDENTIFIER, V42_INDEXED_SIGNATURE, V42_PREIMAGE, V47A_POINT, V50_PREIMAGE, V50_SIGNATURE,
    V53_PREIMAGE, V53_SIGNATURE_FIELD, V54_PREIMAGE, V54_SIGNATURE_FIELD, V55_PREIMAGE,
    V55_SIGNATURE_FIELD, V68_PREIMAGE, V68_REVEAL_SIGNATURE, V68_ROOT_SIGNATURE, V69_PREIMAGE,
    V69_ROOT_SIGNATURE, array, bytes, event_unit, fields, identifier,
};

pub type Error = Box<dyn std::error::Error>;

/// `SCP-KEL-EVENT-V1:`, spec 09 §9.7.4.2's event separator.
pub const SEPARATOR: &[u8] = b"SCP-KEL-EVENT-V1:";
/// `SCP-KEL-ID-V1:`, the identifier derivation's separator (`03-identity.md`
/// §3.1).
const ID_SEPARATOR: &[u8] = b"SCP-KEL-ID-V1:";

/// Spec 25 §25.2's reference seed: Vector 41's root member.
const REFERENCE_SEED: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
/// Spec 25 §25.2's secondary seed: Vector 41's `#active` key.
const SECONDARY_SEED: &str = "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb";
/// Spec 25 §25.2's tertiary seed: the next-set member Vector 41 commits to.
const TERTIARY_SEED: &str = "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7";

/// Spec 25 §25.29's labelled seeds, each `SHA-256(label)`, and the labels
/// these tests add. Each test label names one fixture key.
const LABELS: &[&str] = &[
    "scp-25-rollover-next",
    "scp-25-recovery-cosigns-root",
    "scp-25-recovery-cosigns-active",
    "scp-25-recovery-cosigns-next",
    "scp-25-recovery-lost-root",
    "scp-25-recovery-lost-active",
    "scp-25-recovery-lost-next",
    "scp-25-compromise-active",
    "pr3-active-2",
    "pr3-active-3",
    "pr3-stranger",
    "pr3-kprime-2",
    "pr3-next-0",
    "pr3-next-1",
    "pr3-f2-root-a",
    "pr3-f2-root-b",
    "pr3-f2-active",
    "pr3-f2-next-0",
    "pr3-f2-next-1",
    "pr3-f3-root-a",
    "pr3-f3-root-b",
    "pr3-f3-root-c",
    "pr3-f3-active",
    "pr3-f3-next-0",
    "pr3-f3-next-1",
    "pr3-fx-root",
    "pr3-fx-active",
    "pr3-f1-root",
    "pr3-f1-active",
    "pr3-f1-z",
    "pr3-f2-kprime",
    "pr3-f2-new-active",
];

pub fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

/// One P-256 key pair under the spec 25 seed-to-scalar rule.
pub struct Key {
    secret: P256SecretKey,
    pub point: [u8; 33],
}

impl Key {
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let secret = P256SecretKey::from_seed(SeedLabel::TestVectorKey, seed);
        let point = secret.public_key().to_compressed();
        Self { secret, point }
    }

    /// The key whose seed is `SHA-256(label)`.
    pub fn labelled(label: &str) -> Self {
        Self::from_seed(&sha256(&[label.as_bytes()]))
    }

    /// The raw signature over `SHA-256(signed)`.
    pub fn sign(&self, signed: &[u8]) -> Result<[u8; 64], Error> {
        Ok(sign_prehash_rfc6979(&self.secret, &sha256(&[signed]))?)
    }
}

pub fn reference() -> Result<Key, Error> {
    Ok(Key::from_seed(&array(REFERENCE_SEED)?))
}

pub fn secondary() -> Result<Key, Error> {
    Ok(Key::from_seed(&array(SECONDARY_SEED)?))
}

pub fn tertiary() -> Result<Key, Error> {
    Ok(Key::from_seed(&array(TERTIARY_SEED)?))
}

/// The point of the key `SHA-256(label)` seeds.
pub fn point(label: &str) -> [u8; 33] {
    Key::labelled(label).point
}

/// Every key a fixture signs with, so a signer slot resolves its key from
/// the point the preimage names.
pub struct Ring {
    keys: Vec<Key>,
}

impl Ring {
    pub fn new() -> Result<Self, Error> {
        let mut keys = vec![reference()?, secondary()?, tertiary()?];
        keys.extend(LABELS.iter().map(|label| Key::labelled(label)));
        Ok(Self { keys })
    }

    pub fn key(&self, point: &[u8; 33]) -> Option<&Key> {
        self.keys.iter().find(|key| key.point == *point)
    }
}

/// The signed preimage, `SCP-KEL-EVENT-V1: ‖ fields`.
pub fn signed(fields: &[u8]) -> Vec<u8> {
    [SEPARATOR, fields].concat()
}

/// `SHA-256("SCP-KEL-ID-V1:" ‖ signed preimage)`.
pub fn identifier_of(signed: &[u8]) -> Identifier {
    Identifier::from_bytes(sha256(&[ID_SEPARATOR, signed]))
}

/// `SHA-256(signed preimage)`.
pub fn digest_of(signed: &[u8]) -> [u8; 32] {
    sha256(&[signed])
}

/// The signed preimage a unit carries, read with the test's own length
/// prefix reader.
pub fn signed_of(unit: &[u8]) -> Result<&[u8], Error> {
    let (prefix, rest) = unit.split_first_chunk::<4>().ok_or("unit under 4 bytes")?;
    let len = usize::try_from(u32::from_be_bytes(*prefix))?;
    Ok(rest.get(..len).ok_or("length prefix past the unit")?)
}

/// `BE32(len) ‖ signed ‖ signature field`.
pub fn unit_of(signed: &[u8], signature_field: &[u8]) -> Result<Vec<u8>, Error> {
    let mut unit = u32::try_from(signed.len())?.to_be_bytes().to_vec();
    unit.extend_from_slice(signed);
    unit.extend_from_slice(signature_field);
    Ok(unit)
}

/// A unit over `fields` whose signature field holds one raw signature per
/// slot, in group order then index-list order: each slot's key signs, and a
/// slot no key fills carries 64 zero bytes.
pub fn unit(fields: &[u8], slots: &[Option<&Key>]) -> Result<Vec<u8>, Error> {
    let signed = signed(fields);
    let mut signature_field = Vec::new();
    for slot in slots {
        let signature = match slot {
            Some(key) => key.sign(&signed)?,
            None => [0; 64],
        };
        signature_field.extend_from_slice(&signature);
    }
    unit_of(&signed, &signature_field)
}

/// The key each signature slot names: a reveal index's key is the revealed
/// key at its position, a K′ or inception root index's is field 9's member,
/// and a root or standing-root index past the inception is `standing`'s
/// member. A slot whose point no key in `ring` holds is `None`.
pub fn slots<'r>(
    ring: &'r Ring,
    preimage: &EventPreimage,
    standing: &[[u8; 33]],
) -> Vec<Option<&'r Key>> {
    let roles = preimage.signer_group_roles().unwrap_or(&[]);
    let installed: &[[u8; 33]] = preimage
        .installed_root_set
        .as_ref()
        .map_or(&[], |root| root.members.as_slice());
    let mut out = Vec::new();
    for (group, role) in preimage.signer_groups.iter().zip(roles) {
        for (position, index) in group.indices.iter().enumerate() {
            let point = match role {
                SignerGroupRole::Reveal => preimage.revealed_keys.get(position),
                SignerGroupRole::ReplacementRoot => installed.get(usize::from(*index)),
                SignerGroupRole::Root if preimage.kind == EventKind::Inception => {
                    installed.get(usize::from(*index))
                }
                SignerGroupRole::Root | SignerGroupRole::StandingRoot => {
                    standing.get(usize::from(*index))
                }
            };
            out.push(point.and_then(|point| ring.key(point)));
        }
    }
    out
}

/// A preimage's twelve fields, segment by segment, written with none of the
/// encoder's refusals, so a fixture carries any value its types hold and a
/// test patches a segment's bytes for a value they cannot.
#[derive(Clone)]
pub struct Wire {
    /// Fields 1 to 5.
    pub head: Vec<u8>,
    /// Field 6, every group's count and indices.
    pub indices: Vec<u8>,
    /// Field 7, every group's count and forms.
    pub forms: Vec<u8>,
    pub revealed: Vec<u8>,
    pub installed: Vec<u8>,
    pub snapshot: Vec<u8>,
    pub seals: Vec<u8>,
    pub continuation: Vec<u8>,
}

/// Field 1's offset in [`Wire::head`].
pub const KIND_AT: usize = 0;
/// Field 5's offset in [`Wire::head`].
pub const STANDING_ROOT_AT: usize = 73;
/// One snapshot entry's length, and the offsets of its discriminators.
pub const ENTRY_LEN: usize = 45;
pub const ENTRY_ROLE: usize = 33;
pub const ENTRY_CONDITION: usize = 34;
pub const ENTRY_CUSTODY: usize = 43;
pub const ENTRY_ALGORITHM: usize = 44;

fn be32(len: usize) -> [u8; 4] {
    u32::try_from(len).unwrap_or(u32::MAX).to_be_bytes()
}

const fn form_byte(form: SignatureForm) -> u8 {
    match form {
        SignatureForm::Raw => 0x01,
        SignatureForm::WebAuthnAssertion => 0x02,
    }
}

const fn kind_byte(kind: EventKind) -> u8 {
    match kind {
        EventKind::Inception => 0x01,
        EventKind::KeyState => 0x02,
        EventKind::CommitmentRollover => 0x03,
        EventKind::RootRecovery => 0x04,
    }
}

impl Wire {
    pub fn of(preimage: &EventPreimage) -> Self {
        let mut head = vec![kind_byte(preimage.kind)];
        head.extend_from_slice(preimage.identifier.as_bytes());
        head.extend_from_slice(&preimage.sequence.to_be_bytes());
        head.extend_from_slice(&preimage.predecessor_digest);
        head.push(match preimage.standing_root {
            None => 0x00,
            Some(StandingRootDeclaration::CoSigns) => 0x01,
            Some(StandingRootDeclaration::Lost) => 0x02,
        });
        let mut indices = Vec::new();
        let mut forms = Vec::new();
        for group in &preimage.signer_groups {
            indices.extend_from_slice(&be32(group.indices.len()));
            indices.extend_from_slice(&group.indices);
        }
        for group in &preimage.signer_groups {
            forms.extend_from_slice(&be32(group.forms.len()));
            forms.extend(group.forms.iter().map(|form| form_byte(*form)));
        }
        let mut revealed = be32(preimage.revealed_keys.len()).to_vec();
        for key in &preimage.revealed_keys {
            revealed.extend_from_slice(key);
        }
        let installed = preimage
            .installed_root_set
            .as_ref()
            .map_or_else(|| vec![0; 4], installed_bytes);
        let snapshot = preimage
            .key_state
            .as_ref()
            .map_or_else(|| vec![0; 4], snapshot_bytes);
        let mut seals = be32(preimage.seals.len()).to_vec();
        for seal in &preimage.seals {
            seals.extend_from_slice(seal);
        }
        let continuation = match &preimage.continuation {
            None => vec![0; 4],
            Some(Continuation::Abandons) => vec![0x00],
            Some(Continuation::FixesCommitment(commitment)) => {
                let mut out = vec![0x01];
                out.extend_from_slice(&be32(commitment.commitments.len()));
                for entry in &commitment.commitments {
                    out.extend_from_slice(&entry.commitment);
                    out.push(entry.custody_type.to_byte());
                    out.push(entry.key_algorithm.to_byte());
                }
                out.extend_from_slice(&commitment.next_threshold.to_be_bytes());
                out
            }
        };
        Self {
            head,
            indices,
            forms,
            revealed,
            installed,
            snapshot,
            seals,
            continuation,
        }
    }

    pub fn fields(&self) -> Vec<u8> {
        [
            self.head.as_slice(),
            &self.indices,
            &self.forms,
            &self.revealed,
            &self.installed,
            &self.snapshot,
            &self.seals,
            &self.continuation,
        ]
        .concat()
    }

    /// Sets the byte at `offset` of a segment.
    pub fn set(segment: &mut [u8], offset: usize, value: u8) -> Result<(), Error> {
        *segment.get_mut(offset).ok_or("offset past the segment")? = value;
        Ok(())
    }
}

fn installed_bytes(root: &InstalledRootSet) -> Vec<u8> {
    let mut out = be32(root.members.len()).to_vec();
    for member in &root.members {
        out.extend_from_slice(member);
    }
    out.extend_from_slice(&root.threshold.to_be_bytes());
    out
}

fn snapshot_bytes(snapshot: &KeyStateSnapshot) -> Vec<u8> {
    let mut out = snapshot.root_threshold.to_be_bytes().to_vec();
    out.extend_from_slice(&be32(snapshot.keys.len()));
    for entry in &snapshot.keys {
        out.extend_from_slice(&entry.key);
        out.push(entry.role.to_byte());
        out.push(entry.condition.to_byte());
        out.extend_from_slice(&entry.compromised_from.to_be_bytes());
        out.push(entry.custody_type.to_byte());
        out.push(entry.key_algorithm.to_byte());
    }
    out.extend_from_slice(&be32(snapshot.witnesses.len()));
    for witness in &snapshot.witnesses {
        out.extend_from_slice(witness.as_bytes());
    }
    out.extend_from_slice(&snapshot.witnessing_interval.to_be_bytes());
    out.push(snapshot.service_key_role.to_byte());
    out.extend_from_slice(snapshot.delegator.as_bytes());
    out
}

/// The offset of entry `entry`'s byte `at` in a snapshot segment.
pub const fn entry_at(entry: usize, at: usize) -> usize {
    8 + entry * ENTRY_LEN + at
}

/// The offset of the service-key role in a snapshot segment.
pub const fn service_role_at(snapshot: &KeyStateSnapshot) -> usize {
    8 + snapshot.keys.len() * ENTRY_LEN + 4 + snapshot.witnesses.len() * 32 + 4
}

pub const fn entry(key: [u8; 33], role: KeyRole, condition: KeyCondition) -> KeyEntry {
    KeyEntry {
        key,
        role,
        condition,
        compromised_from: 0,
        custody_type: CustodyType::Passkey,
        key_algorithm: KeyAlgorithm::EcdsaP256Sha256,
    }
}

pub const fn current(key: [u8; 33], role: KeyRole) -> KeyEntry {
    entry(key, role, KeyCondition::Current)
}

/// A snapshot over `keys` with Vector 41's witness set, an interval of
/// 3600, the `Active` service role and no delegator.
pub fn snapshot(keys: Vec<KeyEntry>, root_threshold: u32) -> Result<KeyStateSnapshot, Error> {
    Ok(KeyStateSnapshot {
        root_threshold,
        keys,
        witnesses: vec![identifier(V41_WITNESS)?],
        witnessing_interval: 3600,
        service_key_role: KeyRole::Active,
        delegator: Identifier::ZERO,
    })
}

/// A commitment list over `points` at `next_threshold`.
pub fn fixes(points: &[[u8; 33]], next_threshold: u32) -> Continuation {
    Continuation::FixesCommitment(StandingCommitment {
        commitments: points
            .iter()
            .map(|point| CommitmentEntry {
                commitment: prerotation_commitment(point),
                custody_type: CustodyType::Passkey,
                key_algorithm: KeyAlgorithm::EcdsaP256Sha256,
            })
            .collect(),
        next_threshold,
    })
}

/// A raw-form group naming `indices`.
pub fn group(indices: &[u8]) -> SignerGroup {
    SignerGroup {
        indices: indices.to_vec(),
        forms: vec![SignatureForm::Raw; indices.len()],
    }
}

/// A spec 25 vector's preimage, decoded from its printed bytes.
pub fn vector(preimage_hex: &str) -> Result<EventPreimage, Error> {
    Ok(decode_preimage(&fields(preimage_hex)?)?.preimage().clone())
}

/// A served chain: the identifier, the units in served order, and the root
/// standing at its head.
#[derive(Clone)]
pub struct Base {
    pub name: &'static str,
    pub identifier: Identifier,
    pub units: Vec<Vec<u8>>,
    /// The head's digest, computed here.
    pub head: [u8; 32],
    /// The root standing at the head, which a successor's root or
    /// standing-root group indexes.
    pub root: Vec<[u8; 33]>,
}

impl Base {
    pub fn refs(&self) -> Vec<&[u8]> {
        self.units.iter().map(Vec::as_slice).collect()
    }

    /// The served units followed by `unit`.
    pub fn with<'a>(&'a self, unit: &'a [u8]) -> Vec<&'a [u8]> {
        let mut units = self.refs();
        units.push(unit);
        units
    }

    pub fn len(&self) -> u64 {
        u64::try_from(self.units.len()).unwrap_or(u64::MAX)
    }

    /// The chain extended by a unit over `fields`.
    pub fn then(&self, fields: &[u8], unit: Vec<u8>, root: Vec<[u8; 33]>) -> Self {
        let mut next = self.clone();
        next.units.push(unit);
        next.head = digest_of(&signed(fields));
        next.root = root;
        next
    }
}

/// [Vector 41].
pub fn v41() -> Result<Base, Error> {
    Ok(Base {
        name: "V41",
        identifier: identifier(V41_IDENTIFIER)?,
        units: vec![event_unit(V41_PREIMAGE, V41_SIGNATURE)?],
        head: digest_of(&bytes(V41_PREIMAGE)?),
        root: vec![array(V41_ROOT)?],
    })
}

/// [Vector 42], served under Vector 42's identifier.
pub fn v42() -> Result<Base, Error> {
    Ok(Base {
        name: "V42",
        identifier: identifier(V42_IDENTIFIER)?,
        units: vec![event_unit(V42_PREIMAGE, V42_INDEXED_SIGNATURE)?],
        head: digest_of(&bytes(V42_PREIMAGE)?),
        root: vec![array(V41_ROOT)?],
    })
}

fn v41_then(
    name: &'static str,
    preimage_hex: &str,
    signature_hex: &str,
    root: Vec<[u8; 33]>,
) -> Result<Base, Error> {
    let mut base = v41()?;
    base.name = name;
    base.units.push(event_unit(preimage_hex, signature_hex)?);
    base.head = digest_of(&bytes(preimage_hex)?);
    base.root = root;
    Ok(base)
}

/// [Vector 41, Vector 50].
pub fn v41_v50() -> Result<Base, Error> {
    v41_then(
        "V41,V50",
        V50_PREIMAGE,
        V50_SIGNATURE,
        vec![array(V41_ROOT)?],
    )
}

/// [Vector 41, Vector 53].
pub fn v41_v53() -> Result<Base, Error> {
    v41_then(
        "V41,V53",
        V53_PREIMAGE,
        V53_SIGNATURE_FIELD,
        vec![array(V41_ROOT)?],
    )
}

/// [Vector 41, Vector 54]: the root standing after it is K′.
pub fn v41_v54() -> Result<Base, Error> {
    v41_then(
        "V41,V54",
        V54_PREIMAGE,
        V54_SIGNATURE_FIELD,
        vec![point("scp-25-recovery-cosigns-root")],
    )
}

/// [Vector 41, Vector 55].
pub fn v41_v55() -> Result<Base, Error> {
    v41_then(
        "V41,V55",
        V55_PREIMAGE,
        V55_SIGNATURE_FIELD,
        vec![point("scp-25-recovery-lost-root")],
    )
}

/// [Vector 41, Vector 68].
pub fn v41_v68() -> Result<Base, Error> {
    let signature = format!("{V68_REVEAL_SIGNATURE}{V68_ROOT_SIGNATURE}");
    v41_then("V41,V68", V68_PREIMAGE, &signature, vec![array(V41_ROOT)?])
}

/// [Vector 41, Vector 69].
pub fn v41_v69() -> Result<Base, Error> {
    v41_then(
        "V41,V69",
        V69_PREIMAGE,
        V69_ROOT_SIGNATURE,
        vec![array(V41_ROOT)?],
    )
}

/// A fixture inception, signed by every root index its group names.
pub fn inception_base(
    name: &'static str,
    ring: &Ring,
    preimage: &EventPreimage,
) -> Result<Base, Error> {
    let fields = Wire::of(preimage).fields();
    let unit = unit(&fields, &slots(ring, preimage, &[]))?;
    let signed = signed(&fields);
    Ok(Base {
        name,
        identifier: identifier_of(&signed),
        units: vec![unit],
        head: digest_of(&signed),
        root: preimage
            .installed_root_set
            .as_ref()
            .map(|root| root.members.clone())
            .unwrap_or_default(),
    })
}

pub fn inception(
    roots: &[[u8; 33]],
    root_threshold: u32,
    signers: &[u8],
    active: [u8; 33],
    continuation: Continuation,
) -> Result<EventPreimage, Error> {
    let mut keys: Vec<KeyEntry> = roots
        .iter()
        .map(|root| current(*root, KeyRole::RootMember))
        .collect();
    keys.push(current(active, KeyRole::Active));
    Ok(EventPreimage::inception(scp_kel::InceptionFields {
        root_group: group(signers),
        key_state: snapshot(keys, root_threshold)?,
        continuation,
    }))
}

/// F2: a 1-of-2 root, committing to two next keys at next threshold 2.
pub fn f2_inception() -> Result<EventPreimage, Error> {
    inception(
        &[point("pr3-f2-root-a"), point("pr3-f2-root-b")],
        1,
        &[0],
        point("pr3-f2-active"),
        fixes(&[point("pr3-f2-next-0"), point("pr3-f2-next-1")], 2),
    )
}

/// F3: a 2-of-3 root, committing to two next keys at next threshold 2.
pub fn f3_inception() -> Result<EventPreimage, Error> {
    inception(
        &[
            point("pr3-f3-root-a"),
            point("pr3-f3-root-b"),
            point("pr3-f3-root-c"),
        ],
        2,
        &[0, 1],
        point("pr3-f3-active"),
        fixes(&[point("pr3-f3-next-0"), point("pr3-f3-next-1")], 2),
    )
}

/// A byte string no P-256 point encodes: its leading byte is neither `0x02`
/// nor `0x03`.
pub const NOT_A_POINT: [u8; 33] = [0x05; 33];

/// FX: a 1-of-1 root committing to [`NOT_A_POINT`], so a reveal of that
/// string matches the standing commitment and fails only point validation.
pub fn fx_inception() -> Result<EventPreimage, Error> {
    inception(
        &[point("pr3-fx-root")],
        1,
        &[0],
        point("pr3-fx-active"),
        fixes(&[NOT_A_POINT], 1),
    )
}

/// F1: a 1-of-1 root committing to two next keys at next threshold 1, so
/// one reveal leaves the other member unrevealed.
pub fn f1_inception() -> Result<EventPreimage, Error> {
    inception(
        &[point("pr3-f1-root")],
        1,
        &[0],
        point("pr3-f1-active"),
        fixes(&[point("pr3-next-0"), point("pr3-next-1")], 1),
    )
}

pub fn f1(ring: &Ring) -> Result<Base, Error> {
    inception_base("F1", ring, &f1_inception()?)
}

pub fn f2(ring: &Ring) -> Result<Base, Error> {
    inception_base("F2", ring, &f2_inception()?)
}

pub fn f3(ring: &Ring) -> Result<Base, Error> {
    inception_base("F3", ring, &f3_inception()?)
}

pub fn fx(ring: &Ring) -> Result<Base, Error> {
    inception_base("FX", ring, &fx_inception()?)
}

/// A `KeyState` at the position after `base`'s head, naming root index 0,
/// carrying `snapshot`.
pub fn key_state_on(base: &Base, snapshot: KeyStateSnapshot) -> EventPreimage {
    EventPreimage::key_state(KeyStateFields {
        identifier: base.identifier,
        sequence: base.len(),
        predecessor_digest: base.head,
        root_group: group(&[0]),
        key_state: snapshot,
        seals: Vec::new(),
    })
}

/// Vector 41's snapshot with Vector 50's interval: the legal change every
/// `KeyState` fixture on Vector 41 starts from.
pub fn v41_changed() -> Result<KeyStateSnapshot, Error> {
    let mut changed = snapshot(
        vec![
            current(array(V41_ROOT)?, KeyRole::RootMember),
            current(array(V41_ACTIVE)?, KeyRole::Active),
        ],
        1,
    )?;
    changed.witnessing_interval = 7200;
    Ok(changed)
}

/// Vector 53 with `edit` applied: a `CommitmentRollover` on Vector 41 that
/// reveals the tertiary key.
pub fn v53_with(edit: impl FnOnce(&mut EventPreimage)) -> Result<EventPreimage, Error> {
    let mut preimage = vector(V53_PREIMAGE)?;
    edit(&mut preimage);
    Ok(preimage)
}

/// Vector 54 with `edit` applied: a `RootRecovery{CoSigns}` on Vector 41.
pub fn v54_with(edit: impl FnOnce(&mut EventPreimage)) -> Result<EventPreimage, Error> {
    let mut preimage = vector(V54_PREIMAGE)?;
    edit(&mut preimage);
    Ok(preimage)
}

/// Vector 55 with `edit` applied: a `RootRecovery{Lost}` on Vector 41.
pub fn v55_with(edit: impl FnOnce(&mut EventPreimage)) -> Result<EventPreimage, Error> {
    let mut preimage = vector(V55_PREIMAGE)?;
    edit(&mut preimage);
    Ok(preimage)
}

/// Sets field 10 and, for a kind that installs a root, field 9 to the
/// snapshot's root set, as the constructors do.
pub fn set_snapshot(preimage: &mut EventPreimage, snapshot: KeyStateSnapshot) {
    if preimage.installed_root_set.is_some() {
        preimage.installed_root_set = Some(snapshot.root_set());
    }
    preimage.key_state = Some(snapshot);
}

/// The tertiary key, which Vector 41 commits to.
pub fn v41_next() -> Result<[u8; 33], Error> {
    array(V47A_POINT)
}

/// Vector 41's digest, a §25 constant.
pub fn v41_digest() -> Result<[u8; 32], Error> {
    array(V41_DIGEST)
}

/// Flips the low bit of `unit[offset]`.
pub fn flip(unit: &[u8], offset: usize) -> Result<Vec<u8>, Error> {
    let mut out = unit.to_vec();
    let byte = out.get_mut(offset).ok_or("offset past the unit")?;
    *byte ^= 0x01;
    Ok(out)
}

/// The offset of a unit's signature field.
pub fn signature_field_at(unit: &[u8]) -> Result<usize, Error> {
    Ok(4 + signed_of(unit)?.len())
}

/// The keys every test fixture signs with.
pub const fn root_member(key: [u8; 33]) -> KeyEntry {
    current(key, KeyRole::RootMember)
}

/// A `KeyRole` byte no registered role takes.
pub const UNKNOWN_BYTE: u8 = 0x7F;

/// A unit over `preimage`'s fields, each signature slot signed by the key
/// it names past `base`'s head.
pub fn sign_on(ring: &Ring, base: &Base, preimage: &EventPreimage) -> Result<Vec<u8>, Error> {
    sign_wire(ring, base, preimage, &Wire::of(preimage))
}

/// A unit over `wire`'s fields, with the slots `preimage` names.
pub fn sign_wire(
    ring: &Ring,
    base: &Base,
    preimage: &EventPreimage,
    wire: &Wire,
) -> Result<Vec<u8>, Error> {
    unit(&wire.fields(), &slots(ring, preimage, &base.root))
}

/// An inception unit, signed by the root members its field 9 installs.
pub fn sign_inception(ring: &Ring, preimage: &EventPreimage) -> Result<Vec<u8>, Error> {
    sign_inception_wire(ring, preimage, &Wire::of(preimage))
}

pub fn sign_inception_wire(
    ring: &Ring,
    preimage: &EventPreimage,
    wire: &Wire,
) -> Result<Vec<u8>, Error> {
    unit(&wire.fields(), &slots(ring, preimage, &[]))
}

/// A `RootRecovery` after `base`'s head: it reveals `revealed` under
/// `reveal`, installs `k_prime` at `k_threshold` with `active`, drops every
/// key `Current` in `previous` as `Superseded`, and continues with
/// `continuation`.
pub struct Recovery<'a> {
    pub base: &'a Base,
    pub previous: &'a KeyStateSnapshot,
    pub signing: scp_kel::StandingRootSigning,
    pub reveal: &'a [u8],
    pub revealed: Vec<[u8; 33]>,
    pub k_prime: &'a [[u8; 33]],
    pub k_threshold: u32,
    pub active: [u8; 33],
    pub continuation: Continuation,
}

impl Recovery<'_> {
    pub fn preimage(self) -> Result<EventPreimage, Error> {
        let mut keys: Vec<KeyEntry> = self
            .k_prime
            .iter()
            .map(|member| current(*member, KeyRole::RootMember))
            .collect();
        keys.push(current(self.active, KeyRole::Active));
        keys.extend(
            self.previous
                .keys
                .iter()
                .filter(|entry| entry.condition == KeyCondition::Current)
                .map(|entry| KeyEntry {
                    condition: KeyCondition::Superseded,
                    ..*entry
                }),
        );
        let indices: Vec<u8> = (0..self.k_prime.len())
            .map(u8::try_from)
            .collect::<Result<_, _>>()?;
        Ok(EventPreimage::root_recovery(scp_kel::RootRecoveryFields {
            identifier: self.base.identifier,
            sequence: self.base.len(),
            predecessor_digest: self.base.head,
            standing_root_signing: self.signing,
            reveal_group: group(self.reveal),
            replacement_root_group: group(&indices),
            revealed_keys: self.revealed,
            key_state: snapshot(keys, self.k_threshold)?,
            continuation: self.continuation,
        }))
    }
}

/// A row that holds a field the kind requires to be its sentinel.
pub type SentinelCase = (&'static str, u8, fn(&mut EventPreimage));
