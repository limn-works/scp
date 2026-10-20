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

use std::cmp::Ordering;

use scp_did::{Identifier, KeyCondition, KeyRole, KeyState};
use sha2::{Digest, Sha256};

use self::count::RootCount;

/// The §9.11 domain separator, registered in §9.18.2.
const KEY_CONTINUITY_SEPARATOR: &[u8] = b"SCP-KEY-CONTINUITY-V1:";

/// A pair of inputs §9.11 cannot fingerprint.
///
/// Each variant names the identifier whose key state, or whose pairing, the
/// construction cannot read; none falls back to a sentinel, because §9.11
/// states that "no sentinel stands in for an absent operational key".
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum KeyContinuityError {
    /// Both parties carry one identifier. §9.11 orders the two blocks by
    /// identifier, so equal identifiers leave the order to the caller and two
    /// parties could compute two values for one pair; the fingerprint is also
    /// the comparison one person cannot perform against themselves.
    #[error("both parties carry identifier {identifier}")]
    SameIdentifier {
        /// The identifier both parties carry.
        identifier: Identifier,
    },
    /// The key state names no `Current` `#active` key, which §9.7.4.2 R3
    /// rejects and §9.11 fills with no sentinel.
    #[error("key state of {identifier} names no Current #active key")]
    NoActiveKey {
        /// The party whose key state is missing the key.
        identifier: Identifier,
    },
    /// The key state names more than one `Current` `#active` key, which
    /// §9.7.4.2 R3 rejects ("more than one key `Current` in any operational
    /// role"), so the construction has no one key to take.
    #[error("key state of {identifier} names {count} Current #active keys")]
    MultipleActiveKeys {
        /// The party whose key state names several keys.
        identifier: Identifier,
        /// How many `Current` `#active` entries the key state names.
        count: usize,
    },
    /// The key state names no `Current` root member. §9.7.4.2 R3 rejects a
    /// threshold outside one to the size of its set, so no accepted key state
    /// has an empty root set, and §9.11's re-verification reads the current
    /// root set.
    #[error("key state of {identifier} names no Current root member")]
    EmptyRootSet {
        /// The party whose key state has no root.
        identifier: Identifier,
    },
    /// The root set has more members than `BE32` can count (§9.5.1).
    #[error("root set of {identifier} has {count} members, more than BE32 counts")]
    RootSetCountOverflow {
        /// The party whose root set overflows the count.
        identifier: Identifier,
        /// The member count.
        count: usize,
    },
}

/// One party's block of the §9.11 preimage, read from its key state.
struct PartyBlock<'a> {
    identifier: &'a Identifier,
    root_count: RootCount,
    root_members: Vec<&'a [u8; 33]>,
    active: &'a [u8; 33],
}

impl<'a> PartyBlock<'a> {
    /// Reads the `Current` root members in list order and the one `Current`
    /// `#active` key.
    fn read(
        (identifier, key_state): (&'a Identifier, &'a KeyState),
    ) -> Result<Self, KeyContinuityError> {
        let mut root_members = Vec::new();
        let mut active = None;
        let mut active_count = 0usize;
        for entry in &key_state.keys {
            if entry.condition != KeyCondition::Current {
                continue;
            }
            match entry.role {
                KeyRole::RootMember => root_members.push(&entry.key),
                KeyRole::Active => {
                    active_count += 1;
                    active = Some(&entry.key);
                }
            }
        }
        let active = match (active, active_count) {
            (Some(key), 1) => key,
            (None, _) => {
                return Err(KeyContinuityError::NoActiveKey {
                    identifier: *identifier,
                });
            }
            (Some(_), count) => {
                return Err(KeyContinuityError::MultipleActiveKeys {
                    identifier: *identifier,
                    count,
                });
            }
        };
        if root_members.is_empty() {
            return Err(KeyContinuityError::EmptyRootSet {
                identifier: *identifier,
            });
        }
        let root_count = RootCount::encode(identifier, root_members.len())?;
        Ok(Self {
            identifier,
            root_count,
            root_members,
            active,
        })
    }

    fn feed(&self, hasher: &mut Sha256) {
        hasher.update(self.identifier.as_bytes());
        hasher.update(self.root_count.bytes());
        for member in &self.root_members {
            hasher.update(member);
        }
        hasher.update(self.active);
    }
}

/// The root-set count field, sealed in its own module so the one checked
/// encoder is the only way the preimage gets a count.
mod count {
    use scp_did::Identifier;

    use super::KeyContinuityError;

    /// `BE32(count)` of a root set under §9.5.1's repeated-field rule. The
    /// field is private to this module, so no caller writes an unchecked
    /// (truncated) count into the preimage.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(super) struct RootCount([u8; 4]);

    impl RootCount {
        /// Encodes `count`, refusing one past `u32::MAX` with
        /// [`KeyContinuityError::RootSetCountOverflow`] naming `identifier`.
        pub(super) fn encode(
            identifier: &Identifier,
            count: usize,
        ) -> Result<Self, KeyContinuityError> {
            u32::try_from(count)
                .map(|n| Self(n.to_be_bytes()))
                .map_err(|_| KeyContinuityError::RootSetCountOverflow {
                    identifier: *identifier,
                    count,
                })
        }

        /// The four big-endian bytes the preimage carries.
        pub(super) const fn bytes(self) -> [u8; 4] {
            self.0
        }
    }
}

/// Computes the §9.11 key-continuity fingerprint of two parties.
///
/// Each argument is one party's identifier and key state. The result does not
/// depend on which party is supplied first (`25-test-vectors.md` §25.9
/// Vector 38), because the block of the identifier lower under unsigned byte
/// comparison always comes first.
///
/// # Errors
///
/// [`KeyContinuityError::SameIdentifier`] when both parties carry one
/// identifier, and, naming the party, [`KeyContinuityError::NoActiveKey`],
/// [`KeyContinuityError::MultipleActiveKeys`],
/// [`KeyContinuityError::EmptyRootSet`] or
/// [`KeyContinuityError::RootSetCountOverflow`] when its key state does not
/// name exactly one `Current` `#active` key and a countable, non-empty set of
/// `Current` root members.
pub fn compute_key_continuity_fingerprint(
    a: (&Identifier, &KeyState),
    b: (&Identifier, &KeyState),
) -> Result<[u8; 32], KeyContinuityError> {
    let (lower, higher) = match a.0.cmp(b.0) {
        Ordering::Less => (a, b),
        Ordering::Greater => (b, a),
        Ordering::Equal => return Err(KeyContinuityError::SameIdentifier { identifier: *a.0 }),
    };
    let lower = PartyBlock::read(lower)?;
    let higher = PartyBlock::read(higher)?;
    let mut hasher = Sha256::new();
    hasher.update(KEY_CONTINUITY_SEPARATOR);
    lower.feed(&mut hasher);
    higher.feed(&mut hasher);
    Ok(hasher.finalize().into())
}

#[cfg(test)]
mod tests {
    use scp_did::{CustodyType, KeyAlgorithm, KeyEntry, StandingCommitment};

    use super::*;

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
            standing_commitment: StandingCommitment {
                commitments: Vec::new(),
                next_threshold: 1,
            },
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
        assert_eq!(
            compute_key_continuity_fingerprint((&ID_LOW, &low), (&ID_HIGH, &high)),
            Ok(want)
        );
        assert_eq!(
            compute_key_continuity_fingerprint((&ID_HIGH, &high), (&ID_LOW, &low)),
            Ok(want)
        );
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
            compute_key_continuity_fingerprint((&ID_LOW, &with_history), (&ID_HIGH, &other)),
            compute_key_continuity_fingerprint((&ID_LOW, &plain), (&ID_HIGH, &other)),
        );
    }

    #[test]
    fn fingerprint_takes_root_members_in_key_state_order() {
        let other = current(&[point(4)], point(5));
        let forward = current(&[point(1), point(2)], point(3));
        let backward = current(&[point(2), point(1)], point(3));
        let forward_fp =
            compute_key_continuity_fingerprint((&ID_LOW, &forward), (&ID_HIGH, &other));
        let backward_fp =
            compute_key_continuity_fingerprint((&ID_LOW, &backward), (&ID_HIGH, &other));
        assert!(forward_fp.is_ok());
        assert_ne!(forward_fp, backward_fp);
    }

    #[test]
    fn fingerprint_changes_when_active_key_rotates() {
        let other = current(&[point(4)], point(5));
        let before = current(&[point(1)], point(3));
        let after = current(&[point(1)], point(6));
        let before_fp = compute_key_continuity_fingerprint((&ID_LOW, &before), (&ID_HIGH, &other));
        assert!(before_fp.is_ok());
        assert_ne!(
            before_fp,
            compute_key_continuity_fingerprint((&ID_LOW, &after), (&ID_HIGH, &other))
        );
    }

    #[test]
    fn fingerprint_rejects_one_identifier_on_both_sides() {
        let state = current(&[point(1)], point(3));
        assert_eq!(
            compute_key_continuity_fingerprint((&ID_LOW, &state), (&ID_LOW, &state)),
            Err(KeyContinuityError::SameIdentifier { identifier: ID_LOW })
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
            compute_key_continuity_fingerprint((&ID_HIGH, &other), (&ID_LOW, &no_active)),
            Err(KeyContinuityError::NoActiveKey { identifier: ID_LOW })
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
            compute_key_continuity_fingerprint((&ID_LOW, &other), (&ID_HIGH, &two_active)),
            Err(KeyContinuityError::MultipleActiveKeys {
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
            compute_key_continuity_fingerprint((&ID_LOW, &no_root), (&ID_HIGH, &other)),
            Err(KeyContinuityError::EmptyRootSet { identifier: ID_LOW })
        );
    }

    /// A root set past `u32::MAX` members cannot be built in a test, so the
    /// count encoder is checked at the boundary directly. `RootCount` has no
    /// other constructor, so this check covers every count the preimage
    /// carries.
    #[cfg(target_pointer_width = "64")]
    #[test]
    fn root_count_rejects_count_past_be32() {
        let past = usize::try_from(u64::from(u32::MAX) + 1).unwrap_or(usize::MAX);
        assert_eq!(
            RootCount::encode(&ID_LOW, past),
            Err(KeyContinuityError::RootSetCountOverflow {
                identifier: ID_LOW,
                count: past
            })
        );
        assert_eq!(
            RootCount::encode(&ID_LOW, usize::try_from(u32::MAX).unwrap_or(0))
                .map(RootCount::bytes),
            Ok(u32::MAX.to_be_bytes())
        );
    }
}
