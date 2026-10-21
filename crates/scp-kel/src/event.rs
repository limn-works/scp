//! The key-event preimage's twelve fields as types (`09-security-model.md`
//! §9.7.4.2, "The key-event preimage binds twelve fields in this order").
//!
//! [`EventPreimage`] is a faithful twelve-field value: each `Option` is `None`
//! exactly where the field carries its absent-field sentinel. It represents
//! every preimage a well-formed byte string decodes to, including a defective
//! one R3 discards (a `CommitmentRollover` carrying a key state, a form list
//! whose length differs from its index list), because classifying those
//! defects is the verifier's job and the decoder must hand them over
//! intact. A writer
//! builds a preimage through the per-kind constructors, which place every
//! sentinel the kind carries.

use scp_did::{Identifier, KeyCondition, KeyEntry, KeyRole, KeyState, StandingCommitment};

/// A key event's kind, the preimage's first field (§9.7.4.2 field 1).
///
/// The byte each kind encodes as lives in one place, the preimage module, as
/// ADR-063's implementation constraints require.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EventKind {
    /// The event that creates the identity and fixes its identifier.
    Inception,
    /// An event the standing root signs that installs a new key state.
    KeyState,
    /// A reveal-authorized event that fixes the next commitment list.
    CommitmentRollover,
    /// A reveal-authorized event that replaces the root set.
    RootRecovery,
}

/// What a `RootRecovery` declares about the standing root (§9.7.4.2 field 5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StandingRootDeclaration {
    /// The standing root co-signs the recovery, as a third signer group.
    CoSigns,
    /// The standing root is lost and signs nothing.
    Lost,
}

/// Which indexed set a signer group signs for, by its position in the kind's
/// group order (§9.7.4.2, "Which fields each kind carries in substance").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SignerGroupRole {
    /// The standing root's group of an `Inception` or a `KeyState`, indexing
    /// the root set.
    Root,
    /// The reveal group, indexing the standing commitment list.
    Reveal,
    /// A `RootRecovery`'s K′ group, indexing the root set it installs.
    ReplacementRoot,
    /// The standing root's group of a `CommitmentRollover`, or of a
    /// `RootRecovery` whose standing root co-signs.
    StandingRoot,
}

/// The signer groups a preimage of `kind` names, in its group order.
///
/// `None` for a `RootRecovery` with no standing-root declaration, whose group
/// count is undefined (§9.7.4.2, "Which fields each kind carries in
/// substance"). The one table of group order the encoder and decoder read.
#[must_use]
pub const fn signer_group_roles(
    kind: EventKind,
    standing_root: Option<StandingRootDeclaration>,
) -> Option<&'static [SignerGroupRole]> {
    match (kind, standing_root) {
        (EventKind::Inception | EventKind::KeyState, _) => Some(&[SignerGroupRole::Root]),
        (EventKind::CommitmentRollover, _) => {
            Some(&[SignerGroupRole::Reveal, SignerGroupRole::StandingRoot])
        }
        (EventKind::RootRecovery, Some(StandingRootDeclaration::CoSigns)) => Some(&[
            SignerGroupRole::Reveal,
            SignerGroupRole::ReplacementRoot,
            SignerGroupRole::StandingRoot,
        ]),
        (EventKind::RootRecovery, Some(StandingRootDeclaration::Lost)) => {
            Some(&[SignerGroupRole::Reveal, SignerGroupRole::ReplacementRoot])
        }
        (EventKind::RootRecovery, None) => None,
    }
}

/// The form one indexed signature takes (§9.7.4.2 field 7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SignatureForm {
    /// A raw 64-byte ECDSA signature over the preimage digest.
    Raw,
    /// A `WebAuthn` assertion whose challenge carries the preimage digest.
    WebAuthnAssertion,
}

/// One indexed signer group: the indices it names into its indexed set, and
/// one declared form per signature (§9.7.4.2 fields 6 and 7).
///
/// This is the writer's input, two lists because fields 6 and 7 are two
/// lists on the wire. A group whose form list differs in length from its
/// index list has no encoded length (§9.18.17), so the encoder refuses it
/// with [`EncodeError::FormListLength`](crate::EncodeError::FormListLength)
/// and the decoder fails it at step 4 (§9.7.4.2); every decoded group pairs
/// each index with its form.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SignerGroup {
    /// The member indices the group's signatures are by, in signature order.
    pub indices: Vec<u8>,
    /// The form of each signature, in the same order.
    pub forms: Vec<SignatureForm>,
}

/// The root set an event installs and its signing threshold (§9.7.4.2
/// field 9).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct InstalledRootSet {
    /// The members' 33-byte SEC1 compressed points, in root-set order.
    pub members: Vec<[u8; 33]>,
    /// The signing threshold t.
    pub threshold: u32,
}

/// The key-state snapshot an event carries in field 10 (§9.7.4.2, "The
/// key-state snapshot's own order").
///
/// It is the key state minus the standing commitment: the commitment list
/// travels in the continuation field of the event that fixes it (field 12),
/// and the snapshot carries no next-set list. [`into_key_state`](Self::into_key_state)
/// composes it with the latest continuation's commitment into
/// `scp_did::KeyState`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct KeyStateSnapshot {
    /// The signing threshold t of the root set.
    pub root_threshold: u32,
    /// The keys the snapshot names: the entries kept `Current` in their
    /// existing order, then the keys the event installs in the order the
    /// snapshot itself lists them, then the entries the event drops.
    pub keys: Vec<KeyEntry>,
    /// The designated witnesses' operator identifiers.
    pub witnesses: Vec<Identifier>,
    /// The cadence in seconds at which each witness cosigns the head.
    pub witnessing_interval: u32,
    /// The role whose `Current` key signs the service record.
    pub service_key_role: KeyRole,
    /// The delegating identity, [`Identifier::ZERO`] where undelegated.
    pub delegator: Identifier,
}

impl KeyStateSnapshot {
    /// The root set this snapshot names: its `Current` `RootMember` keys in
    /// snapshot order, which is the root set's own list order, with the
    /// snapshot's root threshold (§9.7.4.2, the key-state snapshot's order:
    /// "root members in the root set's own list order", and "A snapshot lists
    /// the entries it keeps `Current` in their existing order, followed by the
    /// keys the event installs in the order the snapshot itself lists them,
    /// followed by the entries the event drops, in their existing order").
    #[must_use]
    pub fn root_set(&self) -> InstalledRootSet {
        InstalledRootSet {
            members: self
                .keys
                .iter()
                .filter(|entry| {
                    entry.role == KeyRole::RootMember && entry.condition == KeyCondition::Current
                })
                .map(|entry| entry.key)
                .collect(),
            threshold: self.root_threshold,
        }
    }

    /// The key state this snapshot and a standing commitment compose
    /// (§9.7.4.2: "A snapshot carries every component of the key state except
    /// the standing commitment").
    ///
    /// Both types are destructured field by field, so a field added to either
    /// fails to compile here until it is placed.
    #[must_use]
    pub fn into_key_state(self, standing_commitment: StandingCommitment) -> KeyState {
        let Self {
            root_threshold,
            keys,
            witnesses,
            witnessing_interval,
            service_key_role,
            delegator,
        } = self;
        let StandingCommitment {
            commitments,
            next_threshold,
        } = standing_commitment;
        KeyState {
            root_threshold,
            keys,
            witnesses,
            witnessing_interval,
            service_key_role,
            delegator,
            standing_commitment: StandingCommitment {
                commitments,
                next_threshold,
            },
        }
    }
}

/// What a commitment-fixing event says about the next set (§9.7.4.2
/// field 12).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Continuation {
    /// The event fixes a commitment list and its next threshold.
    FixesCommitment(StandingCommitment),
    /// The identity declares itself terminal: no next set exists.
    Abandons,
}

/// A key event's twelve-field preimage (§9.7.4.2).
///
/// Fields 6 and 7 both come from [`signer_groups`](Self::signer_groups): field
/// 6 is each group's index list and field 7 each group's form list, in the
/// kind's group order.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EventPreimage {
    /// Field 1.
    pub kind: EventKind,
    /// Field 2, [`Identifier::ZERO`] in the inception event.
    pub identifier: Identifier,
    /// Field 3.
    pub sequence: u64,
    /// Field 4, all-zero in the inception event.
    pub predecessor_digest: [u8; 32],
    /// Field 5, carried by a `RootRecovery` alone.
    pub standing_root: Option<StandingRootDeclaration>,
    /// Fields 6 and 7, in the kind's group order.
    pub signer_groups: Vec<SignerGroup>,
    /// Field 8, one point per named reveal index.
    pub revealed_keys: Vec<[u8; 33]>,
    /// Field 9.
    pub installed_root_set: Option<InstalledRootSet>,
    /// Field 10.
    pub key_state: Option<KeyStateSnapshot>,
    /// Field 11, carried by a `KeyState` alone.
    pub seals: Vec<[u8; 32]>,
    /// Field 12.
    pub continuation: Option<Continuation>,
}

/// The fields an inception event carries in substance (§9.7.4.2): one root
/// group, the key state and the continuation.
///
/// The installed root set (field 9) is the key state's
/// [`root_set`](KeyStateSnapshot::root_set), so the root members and
/// threshold are written once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InceptionFields {
    /// The root group, indexing the key state's root set.
    pub root_group: SignerGroup,
    /// The identity's first key state, whose root members and threshold are
    /// the root set the inception installs.
    pub key_state: KeyStateSnapshot,
    /// The first commitment list, or abandonment.
    pub continuation: Continuation,
}

/// The fields a `KeyState` event carries in substance (§9.7.4.2): one root
/// group, the key state and the seals.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyStateFields {
    /// The identity the event extends.
    pub identifier: Identifier,
    /// The event's position.
    pub sequence: u64,
    /// The predecessor event's digest.
    pub predecessor_digest: [u8; 32],
    /// The standing root's group.
    pub root_group: SignerGroup,
    /// The key state the event installs.
    pub key_state: KeyStateSnapshot,
    /// The key-event seals, each `key_event_seal` of a sealed event digest.
    pub seals: Vec<[u8; 32]>,
}

/// The fields a `CommitmentRollover` carries in substance (§9.7.4.2): the
/// reveal group then the standing-root group, the revealed keys and the
/// continuation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitmentRolloverFields {
    /// The identity the event extends.
    pub identifier: Identifier,
    /// The event's position.
    pub sequence: u64,
    /// The predecessor event's digest.
    pub predecessor_digest: [u8; 32],
    /// The group indexing the standing commitment list.
    pub reveal_group: SignerGroup,
    /// The standing root's group.
    pub standing_root_group: SignerGroup,
    /// One point per index the reveal group names.
    pub revealed_keys: Vec<[u8; 33]>,
    /// The next commitment list, or abandonment.
    pub continuation: Continuation,
}

/// The standing root's signing part in a `RootRecovery` (§9.7.4.2 fields 5
/// to 7).
///
/// It carries the standing root's signer group where the root co-signs, and
/// nothing where it is lost. The constructor writes the field 5
/// [`StandingRootDeclaration`] each variant implies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StandingRootSigning {
    /// The standing root co-signs with this group, the third group.
    CoSigns {
        /// The standing root's group.
        standing_root_group: SignerGroup,
    },
    /// The standing root is lost and signs nothing.
    Lost,
}

/// The fields a `RootRecovery` carries in substance (§9.7.4.2).
///
/// They are the standing root's signing part, the reveal group, the K′ group,
/// the revealed keys, the key state and the continuation. The installed root
/// set (field 9) is the key state's [`root_set`](KeyStateSnapshot::root_set),
/// so the replacement root members and threshold are written once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootRecoveryFields {
    /// The identity the event extends.
    pub identifier: Identifier,
    /// The event's position.
    pub sequence: u64,
    /// The predecessor event's digest.
    pub predecessor_digest: [u8; 32],
    /// The standing root's signing part in the recovery.
    pub standing_root_signing: StandingRootSigning,
    /// The group indexing the standing commitment list.
    pub reveal_group: SignerGroup,
    /// The K′ group, indexing the installed root set.
    pub replacement_root_group: SignerGroup,
    /// One point per index the reveal group names.
    pub revealed_keys: Vec<[u8; 33]>,
    /// The key state the recovery installs, whose `Current` root members and
    /// threshold are the root set it installs.
    pub key_state: KeyStateSnapshot,
    /// The next commitment list, or abandonment.
    pub continuation: Continuation,
}

impl EventPreimage {
    /// An inception preimage: identifier, sequence and predecessor all zero,
    /// fields 5, 8 and 11 at their sentinels, and field 9 the key state's
    /// root set (§9.7.4.2).
    #[must_use]
    pub fn inception(fields: InceptionFields) -> Self {
        let installed_root_set = fields.key_state.root_set();
        Self {
            kind: EventKind::Inception,
            identifier: Identifier::ZERO,
            sequence: 0,
            predecessor_digest: [0; 32],
            standing_root: None,
            signer_groups: vec![fields.root_group],
            revealed_keys: Vec::new(),
            installed_root_set: Some(installed_root_set),
            key_state: Some(fields.key_state),
            seals: Vec::new(),
            continuation: Some(fields.continuation),
        }
    }

    /// A `KeyState` preimage: fields 5, 8, 9 and 12 at their sentinels
    /// (§9.7.4.2).
    #[must_use]
    pub fn key_state(fields: KeyStateFields) -> Self {
        Self {
            kind: EventKind::KeyState,
            identifier: fields.identifier,
            sequence: fields.sequence,
            predecessor_digest: fields.predecessor_digest,
            standing_root: None,
            signer_groups: vec![fields.root_group],
            revealed_keys: Vec::new(),
            installed_root_set: None,
            key_state: Some(fields.key_state),
            seals: fields.seals,
            continuation: None,
        }
    }

    /// A `CommitmentRollover` preimage: fields 5, 9, 10 and 11 at their
    /// sentinels (§9.7.4.2).
    #[must_use]
    pub fn commitment_rollover(fields: CommitmentRolloverFields) -> Self {
        Self {
            kind: EventKind::CommitmentRollover,
            identifier: fields.identifier,
            sequence: fields.sequence,
            predecessor_digest: fields.predecessor_digest,
            standing_root: None,
            signer_groups: vec![fields.reveal_group, fields.standing_root_group],
            revealed_keys: fields.revealed_keys,
            installed_root_set: None,
            key_state: None,
            seals: Vec::new(),
            continuation: Some(fields.continuation),
        }
    }

    /// A `RootRecovery` preimage: field 11 at its sentinel, field 9 the key
    /// state's root set, and the groups in the order reveal, K′, then
    /// standing root where it co-signs (§9.7.4.2).
    #[must_use]
    pub fn root_recovery(fields: RootRecoveryFields) -> Self {
        let installed_root_set = fields.key_state.root_set();
        let (declaration, signer_groups) = match fields.standing_root_signing {
            StandingRootSigning::CoSigns {
                standing_root_group,
            } => (
                StandingRootDeclaration::CoSigns,
                vec![
                    fields.reveal_group,
                    fields.replacement_root_group,
                    standing_root_group,
                ],
            ),
            StandingRootSigning::Lost => (
                StandingRootDeclaration::Lost,
                vec![fields.reveal_group, fields.replacement_root_group],
            ),
        };
        Self {
            kind: EventKind::RootRecovery,
            identifier: fields.identifier,
            sequence: fields.sequence,
            predecessor_digest: fields.predecessor_digest,
            standing_root: Some(declaration),
            signer_groups,
            revealed_keys: fields.revealed_keys,
            installed_root_set: Some(installed_root_set),
            key_state: Some(fields.key_state),
            seals: Vec::new(),
            continuation: Some(fields.continuation),
        }
    }

    /// The signer groups this preimage's kind names, in group order
    /// ([`signer_group_roles`]).
    #[must_use]
    pub const fn signer_group_roles(&self) -> Option<&'static [SignerGroupRole]> {
        signer_group_roles(self.kind, self.standing_root)
    }
}
