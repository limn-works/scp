//! Signature verification for sub-check 7b and step 9 of §9.7.4.2 R3's
//! check order, at most once per distinct index of each group.
//!
//! "Across 7b and step 9 a verifier verifies at most one signature per
//! distinct index of each group's key set, the first signature the group's
//! signer index list names at that index, and none at an index outside that
//! key set." The bound is the shape of [`GroupVerdicts`]: it keeps the first
//! signature per index in a map keyed by index, so a later signature under
//! the same index is never stored, and the one call to [`Verify::verify`]
//! sits in the vacant arm of a second map keyed by index, so an index is
//! verified at most once whichever step asks first.

use std::collections::BTreeMap;
use std::collections::btree_map::Entry;

use crate::{IndexedSignature, IndexedSignatureError, SignatureForm, verify_indexed};

/// The one operation that verifies an indexed signature. The production
/// implementation is [`Strict`]; a counting implementation in this module's
/// tests checks the per-index bound.
pub(super) trait Verify {
    /// Verifies `signature` under `key` over `digest` in the declared form.
    fn verify(
        &mut self,
        key: &[u8; 33],
        digest: &[u8; 32],
        declared: SignatureForm,
        signature: &IndexedSignature,
    ) -> Result<(), IndexedSignatureError>;
}

/// [`verify_indexed`], §9.7.4.2's indexed-signature check.
pub(super) struct Strict;

impl Verify for Strict {
    fn verify(
        &mut self,
        key: &[u8; 33],
        digest: &[u8; 32],
        declared: SignatureForm,
        signature: &IndexedSignature,
    ) -> Result<(), IndexedSignatureError> {
        verify_indexed(key, digest, declared, signature)
    }
}

/// The key set one signer group verifies against (§9.7.4.2, *The key set
/// each signer group verifies against*), by index, with its threshold.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct KeySet {
    pub(super) keys: BTreeMap<u8, [u8; 33]>,
    pub(super) threshold: u32,
}

impl KeySet {
    /// Whether `indices` name at least the threshold of distinct indices of
    /// this key set: sub-check 7a for one group.
    pub(super) fn named(&self, indices: impl IntoIterator<Item = u8>) -> bool {
        let mut seen = [false; 256];
        let mut count = 0_usize;
        for index in indices {
            if let Some(seen) = seen.get_mut(usize::from(index))
                && !*seen
                && self.keys.contains_key(&index)
            {
                *seen = true;
                count = count.saturating_add(1);
            }
        }
        reaches(count, self.threshold)
    }
}

/// Whether `count` reaches `threshold`, read without a lossy cast.
pub(super) fn reaches(count: usize, threshold: u32) -> bool {
    u32::try_from(count).map_or(true, |count| count >= threshold)
}

/// One walked signer group's signatures, the key set they verify against,
/// and the verdicts reached on them. The key set is fixed when the group is
/// built, so 7b and step 9 read every verdict against the same key.
pub(super) struct GroupVerdicts<'u> {
    keys: KeySet,
    /// The distinct indices the group names, in the order the signer index
    /// list first names each.
    order: Vec<u8>,
    /// The first signature the signer index list names at each index, with
    /// the form field 7 declares for it. A later signature under an index
    /// already present is never stored.
    first: BTreeMap<u8, (SignatureForm, &'u IndexedSignature)>,
    /// The verdict at each index verified so far.
    verdicts: BTreeMap<u8, Result<(), IndexedSignatureError>>,
}

impl<'u> GroupVerdicts<'u> {
    /// The group whose named signers, in signer-list order, carry
    /// `signatures`, verifying against `keys`.
    pub(super) fn new(
        keys: KeySet,
        signers: impl IntoIterator<Item = (u8, SignatureForm, &'u IndexedSignature)>,
    ) -> Self {
        let mut order = Vec::new();
        let mut first = BTreeMap::new();
        for (index, form, signature) in signers {
            if let Entry::Vacant(slot) = first.entry(index) {
                slot.insert((form, signature));
                order.push(index);
            }
        }
        Self {
            keys,
            order,
            first,
            verdicts: BTreeMap::new(),
        }
    }

    /// The verdict at `index`, verifying the first signature named there
    /// only where no step has verified it yet. `None` where the index names
    /// no member of the key set, which is never verified.
    fn verdict(
        &mut self,
        verifier: &mut impl Verify,
        digest: &[u8; 32],
        index: u8,
    ) -> Option<&Result<(), IndexedSignatureError>> {
        let key = self.keys.keys.get(&index)?;
        let &(form, signature) = self.first.get(&index)?;
        Some(match self.verdicts.entry(index) {
            Entry::Occupied(verdict) => verdict.into_mut(),
            Entry::Vacant(slot) => slot.insert(verifier.verify(key, digest, form, signature)),
        })
    }

    /// Sub-check 7b for one group: whether the signatures that verify at
    /// distinct indices of its key set reach its threshold. It stops at the
    /// threshold, and step 9 verifies the rest.
    pub(super) fn verified(&mut self, verifier: &mut impl Verify, digest: &[u8; 32]) -> bool {
        let threshold = self.keys.threshold;
        let mut count = 0usize;
        for position in 0..self.order.len() {
            if reaches(count, threshold) {
                return true;
            }
            let Some(&index) = self.order.get(position) else {
                break;
            };
            if matches!(self.verdict(verifier, digest, index), Some(Ok(()))) {
                count = count.saturating_add(1);
            }
        }
        reaches(count, threshold)
    }

    /// Step 9 for one group: the first named index, in signer-list order,
    /// whose signature does not verify against `keys`.
    pub(super) fn all_verify(
        &mut self,
        verifier: &mut impl Verify,
        digest: &[u8; 32],
    ) -> Result<(), Unverified> {
        for position in 0..self.order.len() {
            let Some(&index) = self.order.get(position) else {
                break;
            };
            match self.verdict(verifier, digest, index) {
                Some(Ok(())) => {}
                Some(Err(error)) => {
                    return Err(Unverified::Failed {
                        index,
                        error: error.clone(),
                    });
                }
                None => return Err(Unverified::OutsideKeySet { index }),
            }
        }
        Ok(())
    }
}

/// The first named index step 9 finds unverified in one group.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Unverified {
    /// The signature under `index` does not verify.
    Failed {
        index: u8,
        error: IndexedSignatureError,
    },
    /// `index` lies outside the key set, which step 8 discards before step
    /// 9 runs.
    OutsideKeySet { index: u8 },
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Counts calls and accepts every signature.
    struct Counting(usize);

    impl Verify for Counting {
        fn verify(
            &mut self,
            _: &[u8; 33],
            _: &[u8; 32],
            _: SignatureForm,
            _: &IndexedSignature,
        ) -> Result<(), IndexedSignatureError> {
            self.0 = self.0.saturating_add(1);
            Ok(())
        }
    }

    fn keys() -> KeySet {
        KeySet {
            keys: BTreeMap::from([(0, [2; 33])]),
            threshold: 1,
        }
    }

    fn raw() -> IndexedSignature {
        IndexedSignature::Raw { signature: [7; 64] }
    }

    #[test]
    fn a_repeated_index_costs_one_verification_across_7b_and_step_9() {
        let signature = raw();
        let mut group = GroupVerdicts::new(
            keys(),
            (0..500).map(|_| (0u8, SignatureForm::Raw, &signature)),
        );
        let mut counting = Counting(0);
        assert!(group.verified(&mut counting, &[0; 32]));
        assert_eq!(group.all_verify(&mut counting, &[0; 32]), Ok(()));
        assert_eq!(counting.0, 1);
    }

    #[test]
    fn no_index_outside_the_key_set_is_verified() {
        let signature = raw();
        let mut group = GroupVerdicts::new(
            keys(),
            [
                (5u8, SignatureForm::Raw, &signature),
                (0u8, SignatureForm::Raw, &signature),
            ],
        );
        let mut counting = Counting(0);
        assert!(group.verified(&mut counting, &[0; 32]));
        assert_eq!(counting.0, 1);
        assert_eq!(
            group.all_verify(&mut counting, &[0; 32]),
            Err(Unverified::OutsideKeySet { index: 5 })
        );
        assert_eq!(counting.0, 1);
    }
}
