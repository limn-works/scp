//! Message ordering assertions.

#![forbid(unsafe_code)]

use super::AssertionError;

/// Assert that sequence numbers are monotonically increasing.
///
/// Each element must be strictly greater than the previous one.
///
/// # Errors
///
/// Returns [`AssertionError::OrderingViolation`] at the first position where
/// the monotonicity invariant breaks.
pub fn assert_correct_ordering(sequences: &[u64]) -> Result<(), AssertionError> {
    for window in sequences.windows(2) {
        let (a, b) = (window[0], window[1]);
        if b <= a {
            return Err(AssertionError::OrderingViolation {
                details: format!("sequence {b} at position is not greater than previous {a}"),
            });
        }
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn strictly_increasing_passes() {
        assert_correct_ordering(&[1, 2, 3, 4, 5]).unwrap();
    }

    #[test]
    fn duplicate_fails() {
        let err = assert_correct_ordering(&[1, 2, 2, 3]).unwrap_err();
        assert!(matches!(err, AssertionError::OrderingViolation { .. }));
    }

    #[test]
    fn decreasing_fails() {
        let err = assert_correct_ordering(&[3, 2, 1]).unwrap_err();
        assert!(matches!(err, AssertionError::OrderingViolation { .. }));
    }

    #[test]
    fn empty_passes() {
        assert_correct_ordering(&[]).unwrap();
    }

    #[test]
    fn single_element_passes() {
        assert_correct_ordering(&[42]).unwrap();
    }

    #[test]
    fn non_contiguous_but_increasing_passes() {
        assert_correct_ordering(&[1, 5, 100, 200]).unwrap();
    }
}
