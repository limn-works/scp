//! The witness set `Identity::create` installs in the inception
//! (`03-identity.md` §3.10.10; `09-security-model.md` §9.7.4.3).
//!
//! The community list is read by the caller's transport, not by this crate,
//! so the caller hands its entries in; no list is built in.

use std::fmt;

use scp_did::Identifier;
use scp_kel::CheckStep;
use scp_kel::constants::MAX_WITNESS_SET_SIZE;

use super::IdentityError;

/// One community-list entry: the operator identifier and the P-256 key the
/// entry declares (`09-security-model.md` §9.7.4.2 definitions).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListedOperator {
    /// The operator identifier the entry declares.
    pub operator: Identifier,
    /// The 33-byte compressed operator key the entry carries.
    pub key: [u8; 33],
}

/// One designated witness: the operator identifier its community-list entry
/// declares (`09-security-model.md` §9.7.4.2 definitions).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WitnessDesignation {
    /// The witness's operator identifier.
    pub operator: Identifier,
}

/// Which witnesses `create` installs. No variant is a default
/// (`.docs/standards/construction.md`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WitnessChoice {
    /// The default set [`default_witness_set`] computes from `listed`.
    CommunityDefault {
        /// The community-list entries the caller's transport read.
        listed: Vec<ListedOperator>,
    },
    /// The operators the controller designates, checked against `listed`.
    Designated {
        /// The designated witnesses, in the order the inception lists them.
        witnesses: Vec<WitnessDesignation>,
        /// The community-list entries the caller's transport read.
        listed: Vec<ListedOperator>,
    },
    /// No witness.
    NoWitness,
}

/// The warning `09-security-model.md` §9.7.4.3 requires of an SDK whose
/// controller designates no witness or replaces the default set with
/// unlisted operators.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WitnessWarning {
    /// The installed set is empty.
    NoWitness,
    /// The installed set names these operators, which no handed entry lists.
    UnlistedOperators(Vec<Identifier>),
}

impl WitnessWarning {
    /// The consequence in the terms §9.7.4.3 requires.
    #[must_use]
    pub const fn consequence(&self) -> &'static str {
        "the identity's freshness then rests on that peer's own relay reads"
    }
}

impl fmt::Display for WitnessWarning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoWitness => write!(f, "the identity designates no witness; ")?,
            Self::UnlistedOperators(operators) => {
                write!(
                    f,
                    "the witness set names operators the community list does not list ("
                )?;
                for (position, operator) in operators.iter().enumerate() {
                    if position > 0 {
                        f.write_str(", ")?;
                    }
                    write!(f, "{operator}")?;
                }
                f.write_str("); ")?;
            }
        }
        f.write_str(self.consequence())
    }
}

/// The SDK's default witness set (`09-security-model.md` §9.7.4.3).
///
/// The entries in list order under distinct operator keys, skipping every entry
/// of an operator that two entries declare under different keys, capped at
/// `MAX_WITNESS_SET_SIZE`. It counts keys and never declared names, so one
/// operator key is one witness. Pure.
#[must_use]
pub fn default_witness_set(listed: &[ListedOperator]) -> Vec<Identifier> {
    let cap = MAX_WITNESS_SET_SIZE as usize;
    let mut set: Vec<Identifier> = Vec::new();
    let mut keys: Vec<[u8; 33]> = Vec::new();
    for entry in listed {
        if set.len() == cap {
            break;
        }
        let conflicting = listed
            .iter()
            .any(|other| other.operator == entry.operator && other.key != entry.key);
        if conflicting || keys.contains(&entry.key) || set.contains(&entry.operator) {
            continue;
        }
        keys.push(entry.key);
        set.push(entry.operator);
    }
    set
}

/// The set the inception installs, and the warning §9.7.4.3 requires where
/// it is empty or names an unlisted operator.
///
/// # Errors
///
/// [`IdentityError::IllegalKeyEvent`] at `CheckStep::Content` where a
/// designated set names one operator twice or exceeds
/// `MAX_WITNESS_SET_SIZE` (R3's defect list), before any key exists.
pub(super) fn resolve_witnesses(
    choice: &WitnessChoice,
) -> Result<(Vec<Identifier>, Option<WitnessWarning>), IdentityError> {
    let set = match choice {
        WitnessChoice::NoWitness => return Ok((vec![], Some(WitnessWarning::NoWitness))),
        WitnessChoice::CommunityDefault { listed } => default_witness_set(listed),
        WitnessChoice::Designated { witnesses, listed } => {
            let illegal = IdentityError::IllegalKeyEvent {
                stage: CheckStep::Content,
            };
            if witnesses.len() > MAX_WITNESS_SET_SIZE as usize {
                return Err(illegal);
            }
            let set: Vec<Identifier> = witnesses.iter().map(|w| w.operator).collect();
            for (position, operator) in set.iter().enumerate() {
                if set.iter().skip(position + 1).any(|other| other == operator) {
                    return Err(illegal);
                }
            }
            let unlisted: Vec<Identifier> = set
                .iter()
                .filter(|operator| !listed.iter().any(|entry| entry.operator == **operator))
                .copied()
                .collect();
            if !unlisted.is_empty() {
                return Ok((set, Some(WitnessWarning::UnlistedOperators(unlisted))));
            }
            set
        }
    };
    let warning = set.is_empty().then_some(WitnessWarning::NoWitness);
    Ok((set, warning))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn op(byte: u8) -> Identifier {
        Identifier::from_bytes([byte; 32])
    }

    fn entry(operator: u8, key: u8) -> ListedOperator {
        ListedOperator {
            operator: op(operator),
            key: [key; 33],
        }
    }

    // AC22: one operator key is one witness.
    #[test]
    fn the_default_counts_distinct_keys() {
        let listed = [entry(1, 10), entry(2, 10), entry(3, 11), entry(1, 10)];
        assert_eq!(default_witness_set(&listed), [op(1), op(3)]);
    }

    // AC22: an operator declared under two keys is dropped.
    #[test]
    fn the_default_drops_an_operator_under_two_keys() {
        let listed = [entry(1, 10), entry(2, 11), entry(1, 12)];
        assert_eq!(default_witness_set(&listed), [op(2)]);
    }

    // AC22: the cap.
    #[test]
    fn the_default_stops_at_the_cap() {
        let listed: Vec<ListedOperator> = (0..40).map(|n| entry(n, n)).collect();
        let set = default_witness_set(&listed);
        assert_eq!(set.len(), MAX_WITNESS_SET_SIZE as usize);
        assert_eq!(set.first(), Some(&op(0)));
        assert_eq!(set.last(), Some(&op(31)));
    }

    // AC22: the warnings.
    #[test]
    fn an_empty_or_unlisted_set_warns() -> Result<(), IdentityError> {
        assert_eq!(
            resolve_witnesses(&WitnessChoice::NoWitness)?,
            (vec![], Some(WitnessWarning::NoWitness))
        );
        assert_eq!(
            resolve_witnesses(&WitnessChoice::CommunityDefault { listed: vec![] })?,
            (vec![], Some(WitnessWarning::NoWitness))
        );
        assert_eq!(
            resolve_witnesses(&WitnessChoice::CommunityDefault {
                listed: vec![entry(1, 1)]
            })?,
            (vec![op(1)], None)
        );
        let designated = |ops: &[u8]| WitnessChoice::Designated {
            witnesses: ops
                .iter()
                .map(|n| WitnessDesignation { operator: op(*n) })
                .collect(),
            listed: vec![entry(1, 1)],
        };
        assert_eq!(resolve_witnesses(&designated(&[1]))?, (vec![op(1)], None));
        assert_eq!(
            resolve_witnesses(&designated(&[1, 2]))?,
            (
                vec![op(1), op(2)],
                Some(WitnessWarning::UnlistedOperators(vec![op(2)]))
            )
        );
        assert_eq!(
            resolve_witnesses(&designated(&[]))?,
            (vec![], Some(WitnessWarning::NoWitness))
        );
        Ok(())
    }

    #[test]
    fn a_repeated_or_oversize_designation_is_illegal() {
        let illegal = Err(IdentityError::IllegalKeyEvent {
            stage: CheckStep::Content,
        });
        let designated = |ops: Vec<u8>| WitnessChoice::Designated {
            witnesses: ops
                .into_iter()
                .map(|n| WitnessDesignation { operator: op(n) })
                .collect(),
            listed: vec![],
        };
        assert_eq!(resolve_witnesses(&designated(vec![1, 2, 1])), illegal);
        assert_eq!(resolve_witnesses(&designated((0..33).collect())), illegal);
        assert!(resolve_witnesses(&designated((0..32).collect())).is_ok());
    }

    #[test]
    fn the_warning_states_the_required_consequence_and_nothing_forbidden() {
        for warning in [
            WitnessWarning::NoWitness,
            WitnessWarning::UnlistedOperators(vec![op(2)]),
        ] {
            let text = warning.to_string();
            assert!(
                text.ends_with(
                    "the identity's freshness then rests on that peer's own relay reads"
                ),
                "{text}"
            );
            for forbidden in ["unresolvable", "unadmittable", "Unresolved"] {
                assert!(!text.contains(forbidden), "{text}");
            }
        }
    }
}
