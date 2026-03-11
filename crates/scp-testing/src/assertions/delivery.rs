//! Message delivery completeness assertions.

#![forbid(unsafe_code)]

use super::AssertionError;

/// Assert that every sent message was delivered.
///
/// # Errors
///
/// Returns [`AssertionError::IncompleteDelivery`] if `received_count` does
/// not equal `sent_count`.
pub const fn assert_complete_delivery(
    sent_count: usize,
    received_count: usize,
) -> Result<(), AssertionError> {
    if sent_count == received_count {
        Ok(())
    } else {
        Err(AssertionError::IncompleteDelivery {
            expected: sent_count,
            actual: received_count,
        })
    }
}

/// Assert that the delivery ratio meets a minimum threshold.
///
/// `min_ratio` is a value in `[0.0, 1.0]` representing the minimum
/// acceptable fraction of delivered messages. A ratio of `1.0` is equivalent
/// to [`assert_complete_delivery`].
///
/// If `sent` is 0 and `received` is 0, the assertion passes (vacuous truth).
///
/// # Errors
///
/// Returns [`AssertionError::IncompleteDelivery`] if the actual ratio is
/// below `min_ratio`.
pub fn assert_delivery_ratio(
    sent: usize,
    received: usize,
    min_ratio: f64,
) -> Result<(), AssertionError> {
    if sent == 0 {
        return Ok(());
    }

    #[allow(clippy::cast_precision_loss)] // counts are small in tests
    let ratio = received as f64 / sent as f64;

    if ratio >= min_ratio {
        Ok(())
    } else {
        Err(AssertionError::IncompleteDelivery {
            expected: sent,
            actual: received,
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn complete_delivery_passes() {
        assert_complete_delivery(10, 10).unwrap();
    }

    #[test]
    fn incomplete_delivery_fails() {
        let err = assert_complete_delivery(10, 8).unwrap_err();
        assert!(matches!(
            err,
            AssertionError::IncompleteDelivery {
                expected: 10,
                actual: 8,
            }
        ));
    }

    #[test]
    fn zero_sent_zero_received_passes() {
        assert_complete_delivery(0, 0).unwrap();
    }

    #[test]
    fn ratio_above_threshold_passes() {
        assert_delivery_ratio(100, 95, 0.9).unwrap();
    }

    #[test]
    fn ratio_below_threshold_fails() {
        let err = assert_delivery_ratio(100, 50, 0.9).unwrap_err();
        assert!(matches!(err, AssertionError::IncompleteDelivery { .. }));
    }

    #[test]
    fn ratio_zero_sent_passes() {
        assert_delivery_ratio(0, 0, 1.0).unwrap();
    }

    #[test]
    fn ratio_exact_threshold_passes() {
        assert_delivery_ratio(10, 9, 0.9).unwrap();
    }
}
