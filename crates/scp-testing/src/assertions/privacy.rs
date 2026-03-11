//! Pseudonym unlinkability assertions.
//!
//! SCP derives a unique routing ID per context so that an observer cannot
//! correlate a participant's activity across contexts. This module verifies
//! that property.

#![forbid(unsafe_code)]

use super::AssertionError;

/// Assert that all provided routing IDs are distinct.
///
/// Each element represents the routing ID used by the *same* participant in a
/// different context. If any two are equal, the participant can be linked
/// across those contexts.
///
/// # Errors
///
/// Returns [`AssertionError::PseudonymLinkable`] with the indices of the
/// first colliding pair.
pub fn assert_pseudonym_unlinkability(routing_ids: &[&[u8; 32]]) -> Result<(), AssertionError> {
    for i in 0..routing_ids.len() {
        for j in (i + 1)..routing_ids.len() {
            if routing_ids[i] == routing_ids[j] {
                return Err(AssertionError::PseudonymLinkable {
                    context_a: i,
                    context_b: j,
                });
            }
        }
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn distinct_ids_pass() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        let c = [3u8; 32];
        assert_pseudonym_unlinkability(&[&a, &b, &c]).unwrap();
    }

    #[test]
    fn duplicate_ids_fail() {
        let a = [1u8; 32];
        let b = [1u8; 32];
        let err = assert_pseudonym_unlinkability(&[&a, &b]).unwrap_err();
        assert!(matches!(
            err,
            AssertionError::PseudonymLinkable {
                context_a: 0,
                context_b: 1,
            }
        ));
    }

    #[test]
    fn single_id_passes() {
        let a = [1u8; 32];
        assert_pseudonym_unlinkability(&[&a]).unwrap();
    }

    #[test]
    fn empty_passes() {
        assert_pseudonym_unlinkability(&[]).unwrap();
    }
}
