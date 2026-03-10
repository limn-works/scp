//! Epoch consistency assertions.
//!
//! In MLS-based protocols, all group members should converge to the same
//! epoch. This module checks that no member lags too far behind.

#![forbid(unsafe_code)]

use super::AssertionError;

/// Assert that all members' epochs are within `max_behind` of the group
/// maximum.
///
/// Each entry is `(member_id, epoch)`. The function finds the maximum epoch
/// and verifies that every member's epoch is at least `max_epoch - max_behind`.
///
/// A `max_behind` of 0 requires strict equality.
///
/// # Errors
///
/// Returns [`AssertionError::EpochInconsistency`] for the first member whose
/// epoch is too far behind.
pub fn assert_epoch_consistency(
    epochs: &[(&str, u64)],
    max_behind: u64,
) -> Result<(), AssertionError> {
    if epochs.is_empty() {
        return Ok(());
    }

    let max_epoch = epochs.iter().map(|(_, e)| *e).max().unwrap_or(0);
    let min_acceptable = max_epoch.saturating_sub(max_behind);

    for (member, epoch) in epochs {
        if *epoch < min_acceptable {
            return Err(AssertionError::EpochInconsistency {
                member: (*member).to_owned(),
                expected_min: min_acceptable,
                actual: *epoch,
            });
        }
    }

    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn all_same_epoch_passes() {
        assert_epoch_consistency(&[("a", 5), ("b", 5), ("c", 5)], 0).unwrap();
    }

    #[test]
    fn within_tolerance_passes() {
        assert_epoch_consistency(&[("a", 5), ("b", 4), ("c", 3)], 2).unwrap();
    }

    #[test]
    fn exceeds_tolerance_fails() {
        let err = assert_epoch_consistency(&[("a", 10), ("b", 5)], 2).unwrap_err();
        if let AssertionError::EpochInconsistency {
            member,
            expected_min,
            actual,
        } = err
        {
            assert_eq!(member, "b");
            assert_eq!(expected_min, 8);
            assert_eq!(actual, 5);
        } else {
            panic!("expected EpochInconsistency");
        }
    }

    #[test]
    fn empty_passes() {
        assert_epoch_consistency(&[], 0).unwrap();
    }

    #[test]
    fn single_member_passes() {
        assert_epoch_consistency(&[("a", 42)], 0).unwrap();
    }
}
