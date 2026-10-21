//! The key-continuity fingerprint (`09-security-model.md` §9.11).
//!
//! Two parties compare the fingerprint out of band to confirm that each holds
//! the other's current root set and `#active` key. §9.11 states one two-party
//! construction:
//!
//! ```text
//! SHA-256("SCP-KEY-CONTINUITY-V1:"
//!         ‖ id_lo ‖ BE32(count(lo_root)) ‖ lo_root_members ‖ lo_active
//!         ‖ id_hi ‖ BE32(count(hi_root)) ‖ hi_root_members ‖ hi_active)
//! ```
//!
//! `id_lo` is the identifier lower under unsigned byte comparison, and its
//! whole block comes first. A party's root set is its key state's `Current`
//! `RootMember` entries in the key state's own list order, and its `#active`
//! key is the key state's one `Current` `Active` entry. Every key is a raw
//! 33-byte SEC1 compressed point and carries no length prefix; the root-set
//! count follows §9.5.1's repeated-field rule. `25-test-vectors.md` §25.9
//! Vectors 20 and 38 pin the bytes.
//!
//! Each party is a [`ReplayedState`]: the key state its validated key event
//! log replays to (§9.7.4.2 R8), carrying the identifier that log's
//! inception derives, so no caller pairs an identifier with a key state of
//! another identity or with a hand-built one. R3 resolved the state's one
//! `Current` `#active` key and bounded its root count, and the state carries
//! both, so the one input §9.11 cannot fingerprint is a pair that names one
//! identifier twice.

use std::cmp::Ordering;

use scp_did::Identifier;
use scp_kel::ReplayedState;
use sha2::{Digest, Sha256};

/// The §9.11 domain separator, registered in §9.18.2.
const KEY_CONTINUITY_SEPARATOR: &[u8] = b"SCP-KEY-CONTINUITY-V1:";

/// Both parties carry one identifier.
///
/// §9.11 orders the two blocks by identifier, so equal identifiers leave the
/// order to the caller and two parties could compute two values for one
/// pair; the fingerprint is also the comparison one person cannot perform
/// against themselves.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("both parties carry identifier {identifier}")]
pub struct SameIdentifier {
    /// The identifier both parties carry.
    pub identifier: Identifier,
}

/// One party's block of the §9.11 preimage: identifier, `BE32` root count,
/// the `Current` root members in key-state order, the `#active` key.
struct PartyBlock<'a> {
    identifier: Identifier,
    root_count: u32,
    root_members: Vec<&'a [u8; 33]>,
    active: &'a [u8; 33],
}

impl<'a> PartyBlock<'a> {
    /// The block of a replayed state, read from what R3 resolved in it.
    fn replayed(state: &'a ReplayedState) -> Self {
        Self {
            identifier: state.identifier(),
            root_count: state.root_count(),
            root_members: state.root_members().collect(),
            active: state.active_key(),
        }
    }

    fn feed(&self, hasher: &mut Sha256) {
        hasher.update(self.identifier.as_bytes());
        hasher.update(self.root_count.to_be_bytes());
        for member in &self.root_members {
            hasher.update(member);
        }
        hasher.update(self.active);
    }
}

/// The §9.11 construction over two parties' blocks: the separator, then the
/// block of the identifier lower under unsigned byte comparison, then the
/// other.
///
/// # Errors
///
/// [`SameIdentifier`] when both blocks carry one identifier.
fn construction(a: &PartyBlock<'_>, b: &PartyBlock<'_>) -> Result<[u8; 32], SameIdentifier> {
    let (lower, higher) = match a.identifier.cmp(&b.identifier) {
        Ordering::Less => (a, b),
        Ordering::Greater => (b, a),
        Ordering::Equal => {
            return Err(SameIdentifier {
                identifier: a.identifier,
            });
        }
    };
    let mut hasher = Sha256::new();
    hasher.update(KEY_CONTINUITY_SEPARATOR);
    lower.feed(&mut hasher);
    higher.feed(&mut hasher);
    Ok(hasher.finalize().into())
}

/// Computes the §9.11 key-continuity fingerprint of two parties' replayed
/// key states.
///
/// The fingerprint is a display value two people compare out of band
/// (§9.11). It is never a gate: nothing is granted or refused on it. That is
/// why it reads a [`ReplayedState`] and not a resolved one, since one party
/// is the device's own identity, whose state comes from its adopted log.
///
/// The result does not depend on which party is supplied first
/// (`25-test-vectors.md` §25.9 Vector 38), because the block of the
/// identifier lower under unsigned byte comparison always comes first.
///
/// # Errors
///
/// [`SameIdentifier`] when both states replay one identity's log. No other
/// input fails: R3 accepts no key state without exactly one `Current`
/// `#active` key or with a root set past `MAX_ROOT_SET_SIZE`.
pub fn compute_key_continuity_fingerprint(
    a: &ReplayedState,
    b: &ReplayedState,
) -> Result<[u8; 32], SameIdentifier> {
    construction(&PartyBlock::replayed(a), &PartyBlock::replayed(b))
}

#[cfg(test)]
mod tests {
    use scp_crypto::p256::{P256SecretKey, SeedLabel};
    use scp_did::{
        CustodyType, FixedCommitment, KeyAlgorithm, KeyCondition, KeyEntry, KeyRole, KeyState,
        StandingCommitment,
    };

    use super::*;

    /// Why the known-answer path cannot read a hand-built key state. A
    /// [`ReplayedState`] reaches none of these but [`SameIdentifier`],
    /// because R3 refuses each of the others; §25's vectors are bare key
    /// states, so their reader checks what R3 would.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum KeyStateFault {
        SameIdentifier(SameIdentifier),
        NoActiveKey {
            identifier: Identifier,
        },
        MultipleActiveKeys {
            identifier: Identifier,
            count: usize,
        },
        EmptyRootSet {
            identifier: Identifier,
        },
        RootSetCountOverflow {
            identifier: Identifier,
            count: usize,
        },
    }

    /// The block of a bare key state: its `Current` root members in list
    /// order and its one `Current` `#active` key.
    fn read<'a>(
        (identifier, key_state): (&Identifier, &'a KeyState),
    ) -> Result<PartyBlock<'a>, KeyStateFault> {
        let identifier = *identifier;
        let root_members: Vec<&[u8; 33]> = key_state
            .keys
            .iter()
            .filter(|entry| {
                entry.role == KeyRole::RootMember && entry.condition == KeyCondition::Current
            })
            .map(|entry| &entry.key)
            .collect();
        let active: Vec<&[u8; 33]> = key_state
            .keys
            .iter()
            .filter(|entry| {
                entry.role == KeyRole::Active && entry.condition == KeyCondition::Current
            })
            .map(|entry| &entry.key)
            .collect();
        let active = match active.as_slice() {
            [key] => *key,
            [] => return Err(KeyStateFault::NoActiveKey { identifier }),
            many => {
                return Err(KeyStateFault::MultipleActiveKeys {
                    identifier,
                    count: many.len(),
                });
            }
        };
        if root_members.is_empty() {
            return Err(KeyStateFault::EmptyRootSet { identifier });
        }
        let root_count =
            u32::try_from(root_members.len()).map_err(|_| KeyStateFault::RootSetCountOverflow {
                identifier,
                count: root_members.len(),
            })?;
        Ok(PartyBlock {
            identifier,
            root_count,
            root_members,
            active,
        })
    }

    /// The §9.11 construction over one bare key state per party, the bytes
    /// Vectors 20 and 38 pin; the same [`construction`] the public function
    /// runs.
    fn fingerprint_of(
        a: (&Identifier, &KeyState),
        b: (&Identifier, &KeyState),
    ) -> Result<[u8; 32], KeyStateFault> {
        if a.0 == b.0 {
            return Err(KeyStateFault::SameIdentifier(SameIdentifier {
                identifier: *a.0,
            }));
        }
        construction(&read(a)?, &read(b)?).map_err(KeyStateFault::SameIdentifier)
    }

    const ID_LOW: Identifier = Identifier::from_bytes([0x10; 32]);
    const ID_HIGH: Identifier = Identifier::from_bytes([0xe0; 32]);

    const fn point(tag: u8) -> [u8; 33] {
        let mut key = [tag; 33];
        key[0] = 0x02;
        key
    }

    fn entry(key: [u8; 33], role: KeyRole, condition: KeyCondition) -> KeyEntry {
        KeyEntry {
            key,
            role,
            condition,
            compromised_from: 0,
            custody_type: CustodyType::Software,
            key_algorithm: KeyAlgorithm::EcdsaP256Sha256,
        }
    }

    fn key_state(keys: Vec<KeyEntry>) -> KeyState {
        KeyState {
            root_threshold: 1,
            keys,
            witnesses: Vec::new(),
            witnessing_interval: 3600,
            service_key_role: KeyRole::Active,
            delegator: Identifier::ZERO,
            standing_commitment: StandingCommitment::Fixed(FixedCommitment {
                commitments: Vec::new(),
                next_threshold: 1,
            }),
        }
    }

    /// A key state with the given `Current` root members and `Current`
    /// `#active` key.
    fn current(root: &[[u8; 33]], active: [u8; 33]) -> KeyState {
        let mut keys: Vec<KeyEntry> = root
            .iter()
            .map(|&key| entry(key, KeyRole::RootMember, KeyCondition::Current))
            .collect();
        keys.push(entry(active, KeyRole::Active, KeyCondition::Current));
        key_state(keys)
    }

    /// One party's block as the preimage writes it: identifier, root members,
    /// `#active` key.
    type Block<'a> = (&'a Identifier, &'a [[u8; 33]], [u8; 33]);

    fn expected(blocks: [Block<'_>; 2]) -> [u8; 32] {
        let mut preimage = KEY_CONTINUITY_SEPARATOR.to_vec();
        for (identifier, root, active) in blocks {
            preimage.extend_from_slice(identifier.as_bytes());
            preimage
                .extend_from_slice(&u32::try_from(root.len()).unwrap_or(u32::MAX).to_be_bytes());
            for member in root {
                preimage.extend_from_slice(member);
            }
            preimage.extend_from_slice(&active);
        }
        Sha256::digest(&preimage).into()
    }

    #[test]
    fn fingerprint_orders_blocks_by_identifier_not_argument_order() {
        let low = current(&[point(1), point(2)], point(3));
        let high = current(&[point(4)], point(5));
        let want = expected([
            (&ID_LOW, &[point(1), point(2)], point(3)),
            (&ID_HIGH, &[point(4)], point(5)),
        ]);
        assert_eq!(fingerprint_of((&ID_LOW, &low), (&ID_HIGH, &high)), Ok(want));
        assert_eq!(fingerprint_of((&ID_HIGH, &high), (&ID_LOW, &low)), Ok(want));
    }

    #[test]
    fn fingerprint_reads_only_current_entries() {
        let plain = current(&[point(1)], point(3));
        let mut with_history = plain.clone();
        with_history.keys.insert(
            0,
            entry(point(7), KeyRole::Active, KeyCondition::Superseded),
        );
        with_history
            .keys
            .push(entry(point(8), KeyRole::RootMember, KeyCondition::Retired));
        with_history.keys.push(KeyEntry {
            compromised_from: 4,
            ..entry(point(9), KeyRole::Active, KeyCondition::Compromised)
        });
        let other = current(&[point(4)], point(5));
        assert_eq!(
            fingerprint_of((&ID_LOW, &with_history), (&ID_HIGH, &other)),
            fingerprint_of((&ID_LOW, &plain), (&ID_HIGH, &other)),
        );
    }

    #[test]
    fn fingerprint_takes_root_members_in_key_state_order() {
        let other = current(&[point(4)], point(5));
        let forward = current(&[point(1), point(2)], point(3));
        let backward = current(&[point(2), point(1)], point(3));
        let forward_fp = fingerprint_of((&ID_LOW, &forward), (&ID_HIGH, &other));
        let backward_fp = fingerprint_of((&ID_LOW, &backward), (&ID_HIGH, &other));
        assert!(forward_fp.is_ok());
        assert_ne!(forward_fp, backward_fp);
    }

    #[test]
    fn fingerprint_changes_when_active_key_rotates() {
        let other = current(&[point(4)], point(5));
        let before = current(&[point(1)], point(3));
        let after = current(&[point(1)], point(6));
        let before_fp = fingerprint_of((&ID_LOW, &before), (&ID_HIGH, &other));
        assert!(before_fp.is_ok());
        assert_ne!(
            before_fp,
            fingerprint_of((&ID_LOW, &after), (&ID_HIGH, &other))
        );
    }

    #[test]
    fn fingerprint_rejects_one_identifier_on_both_sides() {
        let state = current(&[point(1)], point(3));
        assert_eq!(
            fingerprint_of((&ID_LOW, &state), (&ID_LOW, &state)),
            Err(KeyStateFault::SameIdentifier(SameIdentifier {
                identifier: ID_LOW
            }))
        );
    }

    #[test]
    fn fingerprint_rejects_key_state_without_current_active_key() {
        let other = current(&[point(4)], point(5));
        let no_active = key_state(vec![
            entry(point(1), KeyRole::RootMember, KeyCondition::Current),
            entry(point(3), KeyRole::Active, KeyCondition::Superseded),
        ]);
        assert_eq!(
            fingerprint_of((&ID_HIGH, &other), (&ID_LOW, &no_active)),
            Err(KeyStateFault::NoActiveKey { identifier: ID_LOW })
        );
    }

    #[test]
    fn fingerprint_rejects_key_state_with_two_current_active_keys() {
        let other = current(&[point(4)], point(5));
        let mut two_active = current(&[point(1)], point(3));
        two_active
            .keys
            .push(entry(point(6), KeyRole::Active, KeyCondition::Current));
        assert_eq!(
            fingerprint_of((&ID_LOW, &other), (&ID_HIGH, &two_active)),
            Err(KeyStateFault::MultipleActiveKeys {
                identifier: ID_HIGH,
                count: 2
            })
        );
    }

    #[test]
    fn fingerprint_rejects_key_state_without_current_root_member() {
        let other = current(&[point(4)], point(5));
        let no_root = key_state(vec![
            entry(point(1), KeyRole::RootMember, KeyCondition::Retired),
            entry(point(3), KeyRole::Active, KeyCondition::Current),
        ]);
        assert_eq!(
            fingerprint_of((&ID_LOW, &no_root), (&ID_HIGH, &other)),
            Err(KeyStateFault::EmptyRootSet { identifier: ID_LOW })
        );
    }

    /// `SHA-256("SCP test vector identifier " ‖ role)`, spec 25's fixture
    /// identifier rule.
    fn fixture_identifier(role: &str) -> Identifier {
        Identifier::from_bytes(Sha256::digest(format!("SCP test vector identifier {role}")).into())
    }

    fn vector_key(seed: u8) -> [u8; 33] {
        P256SecretKey::from_seed(SeedLabel::TestVectorKey, &[seed; 32])
            .public_key()
            .to_compressed()
    }

    /// §25.9 Vector 20's printed preimage (259 bytes).
    const VECTOR_20_PREIMAGE: &str = concat!(
        "5343502d4b45592d434f4e54494e554954592d56313abcdcea594dbb12037950",
        "ee2d0f356300ea8e37d9dfb01b87c6249033e871095e0000000202542c432f5a",
        "8f756764e2f18c8125e5338e61ba1540057f8c6ee666b07c7aa8d102b945d8e0",
        "97faded7a70e6c18134caf2a9521bc2b05af0becdf99adc9212789d002e264c9",
        "3973b59b7699221aff574dcde04a79347335c4f9c4a643c7525cd9b975f30cba",
        "f928e7bd22a3d2f4aecf6573120a0cdddd8600aa685f61e7f72c78e856000000",
        "0102c4ed969c4a9e294576355bbeb14270e54b51bf6f00b6d1b587676fd0865e",
        "e8a8027a3f3aad1b66ab82d3d67a2e3af15f89f304c4b6369accc5715dda72d2",
        "800512",
    );

    /// §25.9 Vector 20's fingerprint, and Vector 38's.
    const VECTOR_20_FINGERPRINT: &str =
        "c6cdaa8eeb6d04798e308ee0f7c1ecdc29874f8f4411c7c9df921539ad975466";

    /// §25.9 Vectors 20 and 38. Party A's two-member root set at threshold 1
    /// fails a count read from the threshold, and the printed preimage hashes
    /// to the printed fingerprint, so the construction's bytes are the
    /// spec's.
    #[test]
    fn vectors_20_and_38() -> Result<(), Box<dyn std::error::Error>> {
        let id_a = fixture_identifier("A");
        let id_b = fixture_identifier("B");
        let state_a = current(&[vector_key(0x41), vector_key(0x42)], vector_key(0x43));
        let state_b = current(&[vector_key(0x44)], vector_key(0x45));
        let want: [u8; 32] = hex::decode(VECTOR_20_FINGERPRINT)?
            .try_into()
            .map_err(|_| "32 bytes")?;
        let preimage = hex::decode(VECTOR_20_PREIMAGE)?;
        assert_eq!(preimage.len(), 259);
        assert_eq!(<[u8; 32]>::from(Sha256::digest(&preimage)), want);
        assert_eq!(
            fingerprint_of((&id_a, &state_a), (&id_b, &state_b)),
            Ok(want)
        );
        // Vector 38: party B supplied first.
        assert_eq!(
            fingerprint_of((&id_b, &state_b), (&id_a, &state_a)),
            Ok(want)
        );
        Ok(())
    }

    /// The public entry through replayed states: two identities whose logs
    /// the tests sign with spec 25's seed-to-scalar rule, one of them
    /// rotating its `#active` key by a `KeyState` its root signs.
    mod replayed {
        use scp_crypto::p256::{P256SecretKey, SeedLabel, sign_prehash_rfc6979};
        use scp_did::{
            CommitmentEntry, CustodyType, FixedCommitment, Identifier, KeyAlgorithm, KeyCondition,
            KeyEntry, KeyRole,
        };
        use scp_kel::{
            Continuation, EncodedPreimage, EntryVerdict, EventPreimage, InceptionFields,
            KeyStateFields, KeyStateSnapshot, ReplayedState, SignatureForm, SignerGroup,
            encode_preimage, prerotation_commitment, replay, validate_entry,
        };
        use sha2::{Digest, Sha256};

        use super::super::{SameIdentifier, compute_key_continuity_fingerprint};
        use super::fingerprint_of;

        type Error = Box<dyn std::error::Error>;

        /// One identity: its root key, its `#active` key, and its log.
        struct Identity {
            root: P256SecretKey,
            identifier: Identifier,
            units: Vec<Vec<u8>>,
            head: [u8; 32],
            snapshot: KeyStateSnapshot,
        }

        fn key(seed: u8) -> P256SecretKey {
            P256SecretKey::from_seed(SeedLabel::TestVectorKey, &[seed; 32])
        }

        fn point(seed: u8) -> [u8; 33] {
            key(seed).public_key().to_compressed()
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
        fn unit(encoded: &EncodedPreimage, root: &P256SecretKey) -> Result<Vec<u8>, Error> {
            let signed = encoded.signed_preimage();
            let signature = sign_prehash_rfc6979(root, &Sha256::digest(&signed).into())?;
            let mut unit = u32::try_from(signed.len())?.to_be_bytes().to_vec();
            unit.extend_from_slice(&signed);
            unit.extend_from_slice(&signature);
            Ok(unit)
        }

        /// An inception with one root member at threshold 1, one `#active`
        /// key and a commitment to one next key.
        fn incept(root_seed: u8, active_seed: u8, next_seed: u8) -> Result<Identity, Error> {
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
            /// The log extended by a `KeyState` that installs `active_seed`'s
            /// key and drops every earlier `#active` key `Superseded`, in R3's
            /// snapshot order: kept entries, the installed key, the dropped
            /// entries.
            fn rotate(mut self, active_seed: u8) -> Result<Self, Error> {
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

            /// The replay of the one chain of the unforked log
            /// `validate_entry` accepts.
            fn replayed(&self) -> Result<ReplayedState, Error> {
                let units: Vec<&[u8]> = self.units.iter().map(Vec::as_slice).collect();
                let validation = validate_entry(&self.identifier, &units);
                if !validation.discarded.is_empty() {
                    return Err(format!("discarded {:?}", validation.discarded).into());
                }
                match validation.verdict {
                    EntryVerdict::Valid { chains } => chains
                        .single()
                        .map(replay)
                        .ok_or_else(|| format!("expected one chain, got {chains:?}").into()),
                    other => Err(format!("expected a valid chain, got {other:?}").into()),
                }
            }
        }

        /// The public entry is the construction over each state's own
        /// identifier and key state, in either argument order.
        #[test]
        fn fingerprint_reads_each_replayed_identity() -> Result<(), Error> {
            let alice = incept(0x51, 0x52, 0x53)?.replayed()?;
            let bob = incept(0x61, 0x62, 0x63)?.replayed()?;
            let want = fingerprint_of(
                (&alice.identifier(), alice.key_state()),
                (&bob.identifier(), bob.key_state()),
            )
            .map_err(|fault| format!("{fault:?}"))?;
            assert_eq!(compute_key_continuity_fingerprint(&alice, &bob), Ok(want));
            assert_eq!(compute_key_continuity_fingerprint(&bob, &alice), Ok(want));
            Ok(())
        }

        /// A rotation of `#active` on one side changes the fingerprint both
        /// parties compute (§9.11: re-verify after a rotation).
        #[test]
        fn rotation_changes_the_fingerprint() -> Result<(), Error> {
            let alice = incept(0x51, 0x52, 0x53)?;
            let bob = incept(0x61, 0x62, 0x63)?.replayed()?;
            let before = alice.replayed()?;
            let after = alice.rotate(0x54)?.replayed()?;
            assert_eq!(after.head_sequence(), 1);
            // The rotation supersedes the old `#active` key and leaves the
            // new one the state's one `Current` `#active` key (R8).
            let old = after
                .key_state()
                .keys
                .iter()
                .find(|entry| entry.key == point(0x52))
                .ok_or("the old #active key is listed after the rotation")?;
            assert_eq!(
                (old.role, old.condition),
                (KeyRole::Active, KeyCondition::Superseded)
            );
            assert_eq!(before.active_key(), &point(0x52));
            assert_eq!(after.active_key(), &point(0x54));
            let before_fp = compute_key_continuity_fingerprint(&before, &bob)?;
            let after_fp = compute_key_continuity_fingerprint(&after, &bob)?;
            assert_ne!(before_fp, after_fp);
            assert_eq!(
                compute_key_continuity_fingerprint(&bob, &after),
                Ok(after_fp)
            );
            Ok(())
        }

        /// Two states replayed from one identity's log are one party.
        #[test]
        fn one_identity_on_both_sides_is_refused() -> Result<(), Error> {
            let alice = incept(0x51, 0x52, 0x53)?;
            let before = alice.replayed()?;
            let after = alice.rotate(0x54)?.replayed()?;
            assert_eq!(
                compute_key_continuity_fingerprint(&before, &after),
                Err(SameIdentifier {
                    identifier: before.identifier()
                })
            );
            Ok(())
        }
    }
}
