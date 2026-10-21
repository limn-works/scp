//! §9.7.4.2 R3's check order over one unit, at chain position zero
//! ([`check_inception`]) or past it ([`check_successor`]). Each step is one
//! call, in the order the check order lists them, and each failure is
//! classified from the [`EventUnit`] variant the decoder returned.
//!
//! A signed unit runs every step. An unsigned candidate (R10) runs the same
//! calls over the same decode, without the walk, sub-check 7b and step 9,
//! which read the signature field it does not carry yet.

use scp_did::{Identifier, KeyRole};

use super::chain::{ChainEvent, ValidatedChain};
use super::change::{ChangeEffect, SignerGroupSpec};
use super::content::{Applied, Position, chain_event, check_content, reveal_key_set, root_key_set};
use super::defect::{ContentDefect, EventDefect, InceptionDefect};
use super::verdicts::{GroupVerdicts, KeySet, Unverified, Verify};
use crate::event_codec::decode_candidate;
use crate::preimage::read_revealed_keys;
use crate::{
    EventHeader, EventPreimage, EventUnit, NamedSigner, RawSignedPreimage, ReadUnit,
    SignerGroupRole, SignerGroupSignatures, decode_event,
};

/// Whether the bytes are a signed event unit, `BE32(len) ‖ signed preimage ‖
/// signature field`, or an unsigned candidate's signed preimage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Signing {
    /// A signed event unit: every step runs.
    Signed,
    /// An unsigned candidate: the walk, 7b and step 9 do not run.
    Unsigned,
}

/// A unit that passed every step it runs, with what it adds to the chain.
pub(super) struct Accepted {
    pub(super) event: ChainEvent,
    pub(super) installed: Vec<([u8; 33], KeyRole)>,
    pub(super) fixed: Vec<[u8; 32]>,
    pub(super) revealed: Vec<[u8; 33]>,
    /// The signed preimage, separator included, as received.
    pub(super) preimage: Vec<u8>,
    pub(super) signers: Vec<SignerGroupSpec>,
    pub(super) effect: ChangeEffect,
}

impl Accepted {
    fn new(
        applied: Applied,
        raw: &RawSignedPreimage,
        digest: [u8; 32],
        preimage: &EventPreimage,
    ) -> Self {
        Self {
            event: chain_event(&applied, digest, preimage),
            installed: applied.installed,
            fixed: applied.fixed,
            revealed: applied.revealed,
            preimage: raw.signed_preimage(),
            signers: applied.signers,
            effect: applied.effect,
        }
    }
}

/// Why a unit offered at position zero is not the chain's inception.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum InceptionFailure {
    /// Step 3's second half: the unit recomputes to the served identifier
    /// and its preimage fails R2 or an R3 indicator, so the identifier names
    /// no valid chain.
    Invalid(InceptionDefect),
    /// Any other step: the position stays open.
    Discard(EventDefect),
}

fn decode(bytes: &[u8], signing: Signing) -> EventUnit {
    match signing {
        Signing::Signed => decode_event(bytes, 0),
        Signing::Unsigned => decode_candidate(bytes),
    }
}

/// Step 3's first half and R3's inception header checks: the identifier the
/// raw signed preimage recomputes to (through
/// [`RawSignedPreimage::identifier`], which reads no field), against the
/// served identifier where one was served.
fn bind_inception(
    raw: &RawSignedPreimage,
    served: Option<Identifier>,
) -> Result<Identifier, InceptionFailure> {
    let recomputed = raw.identifier();
    if served.is_some_and(|served| served != recomputed) {
        return Err(InceptionFailure::Discard(EventDefect::IdentifierMismatch {
            recomputed,
        }));
    }
    raw.inception_zero_checks()
        .map_err(|defect| InceptionFailure::Invalid(InceptionDefect::ZeroCheck(defect)))?;
    Ok(recomputed)
}

/// Runs the check order at position zero: steps 1, 2 and 3, then 5, 6, 7
/// and 9 (§9.7.4.2, the p = 0 paragraph).
pub(super) fn check_inception(
    bytes: &[u8],
    served: Option<Identifier>,
    signing: Signing,
    verifier: &mut impl Verify,
) -> Result<Accepted, InceptionFailure> {
    let read = match decode(bytes, signing) {
        EventUnit::Unframed => return Err(InceptionFailure::Discard(EventDefect::Unframed)),
        EventUnit::NoSeparator => return Err(InceptionFailure::Discard(EventDefect::NoSeparator)),
        EventUnit::HeaderFailed(failed) => {
            bind_inception(failed.raw(), served)?;
            return Err(InceptionFailure::Invalid(InceptionDefect::Header(
                failed.error().clone(),
            )));
        }
        EventUnit::Read(read) => read,
    };
    let identifier = bind_inception(read.raw(), served)?;
    let digest = read.raw().event_digest();
    let preimage = read.preimage().map_err(|error| {
        InceptionFailure::Invalid(InceptionDefect::Content(ContentDefect::Body(error.clone())))
    })?;
    let applied = check_content(
        Position::Inception { identifier },
        read.header(),
        preimage,
        digest,
    )
    .map_err(|defect| InceptionFailure::Invalid(InceptionDefect::Content(defect)))?;

    // Steps 7 and 9 verify the root group against the set the inception's
    // own field 9 installs. Step 3's second half already ran.
    let key_sets: Vec<Option<KeySet>> = applied.key_sets.iter().cloned().map(Some).collect();
    let (applied, preimage) = signatures(
        &read,
        bytes.len(),
        signing,
        key_sets,
        digest,
        verifier,
        |_| Ok((applied, preimage)),
    )
    .map_err(InceptionFailure::Discard)?;
    Ok(Accepted::new(applied, read.raw(), digest, preimage))
}

/// Runs the check order at the position after `chain`'s head: steps 1, 2
/// and 4 through 9.
pub(super) fn check_successor(
    chain: &ValidatedChain,
    bytes: &[u8],
    signing: Signing,
    verifier: &mut impl Verify,
) -> Result<Accepted, EventDefect> {
    let read = match decode(bytes, signing) {
        EventUnit::Unframed => return Err(EventDefect::Unframed),
        EventUnit::NoSeparator => return Err(EventDefect::NoSeparator),
        EventUnit::HeaderFailed(failed) => return Err(EventDefect::Header(failed.error().clone())),
        EventUnit::Read(read) => read,
    };
    let named = *read.header().predecessor_digest();
    if named != chain.head_digest() {
        return Err(EventDefect::PredecessorMismatch { named });
    }
    let digest = read.raw().event_digest();
    let key_sets = anchoring_key_sets(chain, &read);

    let (applied, preimage) = signatures(
        &read,
        bytes.len(),
        signing,
        key_sets,
        digest,
        verifier,
        |read| {
            // Step 8, between 7b and step 9.
            let preimage = read.preimage().map_err(|error| EventDefect::Content {
                digest,
                defect: ContentDefect::Body(error.clone()),
            })?;
            let applied = check_content(Position::Next(chain), read.header(), preimage, digest)
                .map_err(|defect| EventDefect::Content { digest, defect })?;
            Ok((applied, preimage))
        },
    )?;
    Ok(Accepted::new(applied, read.raw(), digest, preimage))
}

/// The key set each group counts toward sub-check 7a and 7b against, past
/// the inception: the standing root for a root or standing-root group, the
/// matching reveals at the standing next threshold for the reveal group, and
/// none for K′, which never counts.
fn anchoring_key_sets(chain: &ValidatedChain, read: &ReadUnit) -> Vec<Option<KeySet>> {
    let head = chain.head();
    read.header()
        .groups()
        .iter()
        .map(|group| match group.role() {
            SignerGroupRole::Root | SignerGroupRole::StandingRoot => Some(root_key_set(&head.root)),
            SignerGroupRole::Reveal => {
                // 7a decodes field 8 alone; one that does not decode yields
                // no matching reveal.
                let keys = read_revealed_keys(read.raw().fields(), read.raw().signed_len())?;
                reveal_key_set(&head.commitment, group, &keys)
            }
            SignerGroupRole::ReplacementRoot => None,
        })
        .collect()
}

/// Steps 5, 7a, 7b, `content` (step 8 past the inception; at it, the
/// content step 3 already applied) and step 9, in that order. Step 9 reads
/// the content's key set for a group 7a gave none.
fn signatures<'u>(
    read: &'u ReadUnit,
    unit_len: usize,
    signing: Signing,
    key_sets: Vec<Option<KeySet>>,
    digest: [u8; 32],
    verifier: &mut impl Verify,
    content: impl FnOnce(&'u ReadUnit) -> Result<(Applied, &'u EventPreimage), EventDefect>,
) -> Result<(Applied, &'u EventPreimage), EventDefect> {
    let header = read.header();
    if signing == Signing::Signed {
        walk(read, unit_len)?;
    }
    let anchored = named_count(header, &key_sets);
    if !anchored.iter().any(|anchored| *anchored) {
        return Err(EventDefect::NamedCountShort { digest });
    }
    let mut verdicts = match signing {
        Signing::Signed => Some(verified_count(read, key_sets, &anchored, digest, verifier)?),
        Signing::Unsigned => None,
    };
    let (applied, preimage) = content(read)?;
    if let Some(verdicts) = verdicts.as_mut() {
        remaining(read, verdicts, &applied.key_sets, digest, verifier)?;
    }
    Ok((applied, preimage))
}

/// Step 5: the signature field walks, and the walk ends at the unit's end.
fn walk(read: &ReadUnit, unit_len: usize) -> Result<(), EventDefect> {
    let field = read
        .signature_field()
        .map_err(|error| EventDefect::Walk(error.clone()))?;
    let trailing = unit_len.saturating_sub(field.consumed());
    if trailing == 0 {
        Ok(())
    } else {
        Err(EventDefect::UnconsumedBytes { trailing })
    }
}

/// Sub-check 7a: which groups name at least their threshold of distinct
/// indices of their key set. No signature is read.
fn named_count(header: &EventHeader, key_sets: &[Option<KeySet>]) -> Vec<bool> {
    header
        .groups()
        .iter()
        .zip(key_sets)
        .map(|(group, keys)| {
            keys.as_ref()
                .is_some_and(|keys| keys.named(group.signers().iter().map(NamedSigner::index)))
        })
        .collect()
}

fn group_verdicts<'u>(walked: &SignerGroupSignatures<'u>, keys: KeySet) -> GroupVerdicts<'u> {
    GroupVerdicts::new(
        keys,
        walked
            .group()
            .signers()
            .iter()
            .zip(walked.signatures())
            .map(|(signer, named)| (signer.index(), signer.form(), named.signature())),
    )
}

/// Sub-check 7b: some group that passed 7a reaches its threshold counting
/// only signatures that verify. Returns every group's verdicts, built once
/// against the group's 7a key set, for step 9 to reuse.
fn verified_count<'u>(
    read: &'u ReadUnit,
    key_sets: Vec<Option<KeySet>>,
    anchored: &[bool],
    digest: [u8; 32],
    verifier: &mut impl Verify,
) -> Result<Vec<Option<GroupVerdicts<'u>>>, EventDefect> {
    let walked = read
        .walked_groups()
        .map_err(|error| EventDefect::Walk(error.clone()))?;
    let mut verdicts: Vec<Option<GroupVerdicts<'u>>> = walked
        .zip(key_sets)
        .map(|(walked, keys)| keys.map(|keys| group_verdicts(&walked, keys)))
        .collect();
    for (group, anchored) in verdicts.iter_mut().zip(anchored) {
        if let Some(group) = group
            && *anchored
            && group.verified(verifier, &digest)
        {
            return Ok(verdicts);
        }
    }
    Err(EventDefect::VerifiedCountShort { digest })
}

/// Step 9: every named index of every group verifies, reusing each verdict
/// 7b reached. A group 7a gave no key set verifies against the key set step
/// 8 assigned it.
fn remaining<'u>(
    read: &'u ReadUnit,
    verdicts: &mut [Option<GroupVerdicts<'u>>],
    key_sets: &[KeySet],
    digest: [u8; 32],
    verifier: &mut impl Verify,
) -> Result<(), EventDefect> {
    let walked = read
        .walked_groups()
        .map_err(|error| EventDefect::Walk(error.clone()))?;
    for ((slot, walked), keys) in verdicts.iter_mut().zip(walked).zip(key_sets) {
        let role = walked.role();
        let group = slot.get_or_insert_with(|| group_verdicts(&walked, keys.clone()));
        group
            .all_verify(verifier, &digest)
            .map_err(|unverified| match unverified {
                Unverified::Failed { index, error } => EventDefect::Signature {
                    digest,
                    role,
                    index,
                    error,
                },
                // Step 8 discards an index outside its group's key set, so
                // step 9 reaches none; were one reached, it is that defect.
                Unverified::OutsideKeySet { index } => EventDefect::Content {
                    digest,
                    defect: ContentDefect::IndexOutOfRange { role, index },
                },
            })?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use scp_crypto::p256::{P256SecretKey, SeedLabel};
    use scp_did::{
        CommitmentEntry, CustodyType, KeyAlgorithm, KeyCondition, KeyEntry, StandingCommitment,
    };

    use super::*;
    use crate::constants::KEL_EVENT_SEPARATOR;
    use crate::preimage::identifier_of;
    use crate::{
        Continuation, InceptionFields, IndexedSignature, IndexedSignatureError, KeyStateFields,
        KeyStateSnapshot, SignatureForm, SignerGroup, encode_preimage, prerotation_commitment,
    };

    type TestResult = Result<(), Box<dyn std::error::Error>>;

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

    fn point(seed: u8) -> [u8; 33] {
        P256SecretKey::from_seed(SeedLabel::TestVectorKey, &[seed; 32])
            .public_key()
            .to_compressed()
    }

    const fn current(key: [u8; 33], role: KeyRole) -> KeyEntry {
        KeyEntry {
            key,
            role,
            condition: KeyCondition::Current,
            compromised_from: 0,
            custody_type: CustodyType::Passkey,
            key_algorithm: KeyAlgorithm::EcdsaP256Sha256,
        }
    }

    fn snapshot(witnessing_interval: u32) -> KeyStateSnapshot {
        KeyStateSnapshot {
            root_threshold: 1,
            keys: vec![
                current(point(1), KeyRole::RootMember),
                current(point(2), KeyRole::Active),
            ],
            witnesses: vec![Identifier::from_bytes([9; 32])],
            witnessing_interval,
            service_key_role: KeyRole::Active,
            delegator: Identifier::ZERO,
        }
    }

    fn root_group() -> SignerGroup {
        SignerGroup {
            indices: vec![0],
            forms: vec![SignatureForm::Raw],
        }
    }

    /// `BE32(len) ‖ separator ‖ fields ‖ one zeroed raw signature`, which
    /// [`Counting`] accepts.
    fn unit(fields: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let signed = [KEL_EVENT_SEPARATOR, fields].concat();
        let mut unit = u32::try_from(signed.len())?.to_be_bytes().to_vec();
        unit.extend_from_slice(&signed);
        unit.extend_from_slice(&[0; 64]);
        Ok(unit)
    }

    /// The bound §9.7.4.2 states for 7b and step 9 together: "Across 7b and
    /// step 9 a verifier verifies at most one signature per distinct index
    /// of each group's key set". Run through `check_successor`, so step 9
    /// must reuse the verdict 7b reached rather than verify again.
    #[test]
    fn step_9_reuses_every_verdict_7b_reached() -> TestResult {
        let inception = encode_preimage(&EventPreimage::inception(InceptionFields {
            root_group: root_group(),
            key_state: snapshot(3600),
            continuation: Continuation::FixesCommitment(StandingCommitment {
                commitments: vec![CommitmentEntry {
                    commitment: prerotation_commitment(&point(3)),
                    custody_type: CustodyType::Passkey,
                    key_algorithm: KeyAlgorithm::EcdsaP256Sha256,
                }],
                next_threshold: 1,
            }),
        }))?;
        let identifier = identifier_of(inception.fields());
        let mut counting = Counting(0);
        let accepted = check_inception(
            &unit(inception.fields())?,
            Some(identifier),
            Signing::Signed,
            &mut counting,
        )
        .map_err(|failure| format!("{failure:?}"))?;
        assert_eq!(counting.0, 1);
        let chain = ValidatedChain::from_inception(identifier, &accepted);

        let key_state = encode_preimage(&EventPreimage::key_state(KeyStateFields {
            identifier,
            sequence: 1,
            predecessor_digest: chain.head_digest(),
            root_group: root_group(),
            key_state: snapshot(7200),
            seals: Vec::new(),
        }))?;
        let mut counting = Counting(0);
        check_successor(
            &chain,
            &unit(key_state.fields())?,
            Signing::Signed,
            &mut counting,
        )
        .map_err(|defect| format!("{defect:?}"))?;
        assert_eq!(counting.0, 1);
        Ok(())
    }
}
