//! `validate_chain` on chains R3 accepts (`09-security-model.md` §9.7.4.2
//! R3): spec 25's chains, a key state signed by the root a recovery
//! installed, the unit-by-unit equivalence of `extend`, and `prefix`.

use scp_did::{Identifier, KeyRole};
use scp_kel::{ChainValidation, Discarded, ValidatedChain, validate_chain};

use super::chain_support::{
    Base, Error, Ring, Wire, current, digest_of, key_state_on, point, signed, slots, unit, v41,
    v41_v50, v41_v53, v41_v54, v41_v55, v41_v68, v41_v69, v42,
};
use super::fixtures::{
    TestResult, V41_DIGEST, V42_DIGEST, V50_DIGEST, V51_DIGEST, V51_IDENTIFIER,
    V51_INCEPTION_PREIMAGE, V51_INCEPTION_SIGNATURE, V51_PREIMAGE, V51_SIGNATURE, V53_DIGEST,
    V54_DIGEST, V55_DIGEST, V68_DIGEST, V69_DIGEST, array, event_unit, identifier,
};

/// The chain and discards of a `Valid` verdict, or the verdict as an error.
pub fn valid(
    identifier: &Identifier,
    units: &[&[u8]],
) -> Result<(ValidatedChain, Vec<Discarded>), Error> {
    match validate_chain(identifier, units) {
        ChainValidation::Valid { chain, discarded } => Ok((chain, discarded)),
        other => Err(format!("expected Valid, got {other:?}").into()),
    }
}

/// The base chain, validated with no discard.
pub fn chain_of(base: &Base) -> Result<ValidatedChain, Error> {
    let (chain, discarded) = valid(&base.identifier, &base.refs())?;
    if !discarded.is_empty() {
        return Err(format!("{}: discards {discarded:?}", base.name).into());
    }
    Ok(chain)
}

fn assert_head(base: &Base, digest_hex: &str) -> TestResult {
    let chain = chain_of(base)?;
    let digest: [u8; 32] = array(digest_hex)?;
    assert_eq!(chain.head_digest(), digest, "{}", base.name);
    assert_eq!(chain.head_digest(), base.head, "{}", base.name);
    assert_eq!(chain.head_sequence(), base.len() - 1, "{}", base.name);
    assert_eq!(chain.identifier(), base.identifier, "{}", base.name);
    Ok(())
}

#[test]
fn spec_25_chains_are_valid() -> TestResult {
    assert_head(&v41()?, V41_DIGEST)?;
    assert_head(&v42()?, V42_DIGEST)?;
    assert_head(&v41_v50()?, V50_DIGEST)?;
    assert_head(&v41_v53()?, V53_DIGEST)?;
    assert_head(&v41_v54()?, V54_DIGEST)?;
    assert_head(&v41_v55()?, V55_DIGEST)?;
    assert_head(&v41_v68()?, V68_DIGEST)?;
    assert_head(&v41_v69()?, V69_DIGEST)?;
    Ok(())
}

#[test]
fn vector_51_chain_is_valid() -> TestResult {
    let inception = event_unit(V51_INCEPTION_PREIMAGE, V51_INCEPTION_SIGNATURE)?;
    let key_state = event_unit(V51_PREIMAGE, V51_SIGNATURE)?;
    let (chain, discarded) = valid(
        &identifier(V51_IDENTIFIER)?,
        &[inception.as_slice(), key_state.as_slice()],
    )?;
    assert!(discarded.is_empty());
    assert_eq!(chain.head_digest(), array::<32>(V51_DIGEST)?);
    assert_eq!(chain.head_sequence(), 1);
    Ok(())
}

/// The root a `RootRecovery` installs anchors the next event: K′ signs a
/// key state after Vector 54, and Vector 41's root signs nothing there.
#[test]
fn recovery_root_anchors_the_next_event() -> TestResult {
    let ring = Ring::new()?;
    let base = v41_v54()?;
    let k_prime = point("scp-25-recovery-cosigns-root");
    let active = point("scp-25-recovery-cosigns-active");
    let mut snapshot = super::chain_support::snapshot(
        vec![
            current(k_prime, KeyRole::RootMember),
            current(active, KeyRole::Active),
        ],
        1,
    )?;
    snapshot.witnessing_interval = 7200;
    let preimage = key_state_on(&base, snapshot);
    let fields = Wire::of(&preimage).fields();
    let signed_by_k_prime = unit(&fields, &slots(&ring, &preimage, &base.root))?;
    let (chain, discarded) = valid(&base.identifier, &base.with(&signed_by_k_prime))?;
    assert!(discarded.is_empty(), "{discarded:?}");
    assert_eq!(chain.head_digest(), digest_of(&signed(&fields)));
    assert_eq!(chain.head_sequence(), 2);

    let old_root = super::chain_support::reference()?;
    let signed_by_old_root = unit(&fields, &[Some(&old_root)])?;
    let (chain, discarded) = valid(&base.identifier, &base.with(&signed_by_old_root))?;
    assert_eq!(chain.head_digest(), base.head);
    assert_eq!(discarded.len(), 1);
    assert_eq!(
        discarded.first().map(Discarded::stage),
        Some(scp_kel::CheckStep::VerifiedCount)
    );
    Ok(())
}

/// `extend` unit by unit reaches the chain `validate_chain` returns, and
/// `prefix` returns each earlier chain.
#[test]
fn extend_and_prefix_agree_with_validate_chain() -> TestResult {
    for base in [v41_v50()?, v41_v53()?, v41_v54()?, v41_v68()?, v41_v69()?] {
        let whole = chain_of(&base)?;
        let first = base.units.first().ok_or("no inception")?;
        let mut chain = chain_of(&Base {
            units: vec![first.clone()],
            ..v41()?
        })?;
        for unit in base.units.iter().skip(1) {
            chain = chain
                .extend(unit)
                .map_err(|(_, discarded)| format!("{discarded:?}"))?;
        }
        assert_eq!(chain, whole, "{}", base.name);
        let inception = whole.prefix(0).ok_or("no prefix 0")?;
        assert_eq!(inception.head_digest(), array::<32>(V41_DIGEST)?);
        assert_eq!(whole.prefix(1).as_ref(), Some(&whole), "{}", base.name);
        assert_eq!(whole.prefix(2), None, "{}", base.name);
    }
    Ok(())
}
