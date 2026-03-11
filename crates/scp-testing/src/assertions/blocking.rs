//! Content-access-control (blocking) assertions.
//!
//! When a member blocks another, the blocked member must not be able to
//! decrypt the blocker's content. This module verifies that decryption
//! fails as expected.

#![forbid(unsafe_code)]

use std::fmt::Debug;

use super::AssertionError;

/// Assert that a decrypt operation failed, confirming that the block is
/// enforced.
///
/// The caller passes the `Result` of the target member's decrypt attempt.
/// If the result is `Ok(())` the block was not enforced and the assertion
/// fails.
///
/// - `initiator` -- the member who initiated the block.
/// - `target` -- the member who should have been blocked.
///
/// # Errors
///
/// Returns [`AssertionError::BlockNotEnforced`] if `decrypt_result` is
/// `Ok(())`.
#[allow(clippy::needless_pass_by_value)] // Result is small and consumed
pub fn assert_block_enforced<E: Debug>(
    decrypt_result: Result<(), E>,
    initiator: &str,
    target: &str,
) -> Result<(), AssertionError> {
    match decrypt_result {
        Ok(()) => Err(AssertionError::BlockNotEnforced {
            blocker: initiator.to_owned(),
            blocked: target.to_owned(),
        }),
        Err(_) => Ok(()),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn decrypt_failure_means_block_enforced() {
        let result: Result<(), &str> = Err("access denied");
        assert_block_enforced(result, "alice", "bob").unwrap();
    }

    #[test]
    fn decrypt_success_means_block_not_enforced() {
        let result: Result<(), &str> = Ok(());
        let err = assert_block_enforced(result, "alice", "bob").unwrap_err();
        assert!(matches!(err, AssertionError::BlockNotEnforced { .. }));
    }
}
