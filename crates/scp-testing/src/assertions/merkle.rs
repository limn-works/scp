//! Merkle root consistency assertions.

#![forbid(unsafe_code)]

use super::AssertionError;

/// Verify that all provided Merkle roots agree within a drift tolerance.
///
/// Each entry is `(member_id, root_hash)`. Two roots are consistent if they
/// are byte-equal. The `max_drift` parameter allows a window: roots are
/// compared pairwise and if more than `max_drift` pairs disagree, the
/// assertion fails.
///
/// A `max_drift` of 0 requires strict unanimity. A non-zero value tolerates
/// transient propagation delay where some members have not yet received the
/// latest epoch.
///
/// # Errors
///
/// Returns [`AssertionError::MerkleInconsistency`] when the number of
/// mismatched root pairs exceeds `max_drift`.
pub fn assert_consistent_merkle_roots(
    roots: &[(&str, &[u8])],
    max_drift: u64,
) -> Result<(), AssertionError> {
    if roots.len() < 2 {
        return Ok(());
    }

    let mut mismatches: u64 = 0;
    let mut first_mismatch: Option<(usize, usize)> = None;

    for i in 0..roots.len() {
        for j in (i + 1)..roots.len() {
            if roots[i].1 != roots[j].1 {
                mismatches = mismatches.saturating_add(1);
                if first_mismatch.is_none() {
                    first_mismatch = Some((i, j));
                }
            }
        }
    }

    if mismatches > max_drift {
        let (a, b) = first_mismatch.unwrap_or((0, 1));
        return Err(AssertionError::MerkleInconsistency {
            details: format!(
                "{mismatches} mismatched pair(s) exceed max_drift={max_drift}; \
                 first mismatch between '{}' and '{}'",
                roots[a].0, roots[b].0,
            ),
        });
    }

    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn identical_roots_pass() {
        let root = [1u8; 32];
        let roots = vec![("a", root.as_slice()), ("b", root.as_slice())];
        assert_consistent_merkle_roots(&roots, 0).unwrap();
    }

    #[test]
    fn different_roots_fail_with_zero_drift() {
        let r1 = [1u8; 32];
        let r2 = [2u8; 32];
        let roots = vec![("a", r1.as_slice()), ("b", r2.as_slice())];
        let err = assert_consistent_merkle_roots(&roots, 0).unwrap_err();
        assert!(matches!(err, AssertionError::MerkleInconsistency { .. }));
    }

    #[test]
    fn different_roots_pass_within_drift() {
        let r1 = [1u8; 32];
        let r2 = [2u8; 32];
        let roots = vec![("a", r1.as_slice()), ("b", r2.as_slice())];
        assert_consistent_merkle_roots(&roots, 1).unwrap();
    }

    #[test]
    fn single_root_always_passes() {
        let root = [0u8; 32];
        assert_consistent_merkle_roots(&[("a", root.as_slice())], 0).unwrap();
    }

    #[test]
    fn empty_input_passes() {
        assert_consistent_merkle_roots(&[], 0).unwrap();
    }
}
