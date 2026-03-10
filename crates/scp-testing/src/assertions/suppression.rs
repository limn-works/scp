//! Relay message-suppression detection assertions.
//!
//! Suppression is detected by gaps in a monotonically-increasing sequence of
//! message sequence numbers. A missing number indicates that the relay
//! dropped or withheld a message.

#![forbid(unsafe_code)]

use super::AssertionError;

/// Assert that the sequence numbers contain at least one gap, indicating
/// message suppression by the relay.
///
/// The input slice should contain sequence numbers in the order they were
/// received. The function sorts a copy internally, so the caller does not
/// need to pre-sort.
///
/// # Errors
///
/// Returns [`AssertionError::SuppressionNotDetected`] if the sequence is
/// contiguous (no gaps).
pub fn assert_suppression_detected(sequences: &[u64]) -> Result<(), AssertionError> {
    let gaps = find_gaps(sequences);
    if gaps.is_empty() {
        Err(AssertionError::SuppressionNotDetected)
    } else {
        Ok(())
    }
}

/// Assert that the sequence numbers are contiguous -- no suppression.
///
/// The input does not need to be sorted.
///
/// # Errors
///
/// Returns [`AssertionError::SuppressionDetected`] if any gap is found,
/// with evidence describing which sequence numbers are missing.
pub fn assert_no_suppression(sequences: &[u64]) -> Result<(), AssertionError> {
    let gaps = find_gaps(sequences);
    if gaps.is_empty() {
        Ok(())
    } else {
        let evidence = gaps
            .iter()
            .map(|(start, end)| {
                if *start == *end {
                    format!("missing seq {start}")
                } else {
                    format!("missing seqs {start}..={end}")
                }
            })
            .collect::<Vec<_>>()
            .join("; ");
        Err(AssertionError::SuppressionDetected { evidence })
    }
}

/// Find contiguous ranges of missing sequence numbers.
///
/// Returns a vec of `(gap_start, gap_end)` inclusive ranges.
fn find_gaps(sequences: &[u64]) -> Vec<(u64, u64)> {
    if sequences.len() < 2 {
        return Vec::new();
    }

    let mut sorted = sequences.to_vec();
    sorted.sort_unstable();
    sorted.dedup();

    let mut gaps = Vec::new();
    for window in sorted.windows(2) {
        let (a, b) = (window[0], window[1]);
        if b.saturating_sub(a) > 1 {
            gaps.push((a + 1, b - 1));
        }
    }
    gaps
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn contiguous_sequence_no_suppression() {
        assert_no_suppression(&[1, 2, 3, 4, 5]).unwrap();
    }

    #[test]
    fn gap_detected_as_suppression() {
        let err = assert_no_suppression(&[1, 2, 5, 6]).unwrap_err();
        assert!(matches!(err, AssertionError::SuppressionDetected { .. }));
    }

    #[test]
    fn suppression_detected_with_gap() {
        assert_suppression_detected(&[1, 2, 5]).unwrap();
    }

    #[test]
    fn suppression_not_detected_contiguous() {
        let err = assert_suppression_detected(&[1, 2, 3]).unwrap_err();
        assert!(matches!(err, AssertionError::SuppressionNotDetected));
    }

    #[test]
    fn unsorted_input_handled() {
        assert_no_suppression(&[3, 1, 2]).unwrap();
    }

    #[test]
    fn single_element_passes() {
        assert_no_suppression(&[42]).unwrap();
    }

    #[test]
    fn empty_passes() {
        assert_no_suppression(&[]).unwrap();
    }

    #[test]
    fn duplicate_sequence_numbers_ignored() {
        assert_no_suppression(&[1, 1, 2, 2, 3]).unwrap();
    }

    #[test]
    fn gap_evidence_is_readable() {
        let err = assert_no_suppression(&[1, 5]).unwrap_err();
        if let AssertionError::SuppressionDetected { evidence } = err {
            assert!(evidence.contains("2..=4"), "evidence was: {evidence}");
        }
    }
}
