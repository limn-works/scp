//! R10's five relations through `classify_relation`, each against the
//! controller's own retained log, over spec 25's chains, and the one
//! adoption an entry makes (`09-security-model.md` §9.7.4.2 R10, *The
//! prefix a relation reads*, *The five relations, each naming an act* and
//! *One entry adopts at most one chain*).
//!
//! Every expected relation is the test's own reading of R10 from the
//! vectors' kinds: Vector 50 is a root-signed `KeyState`, Vector 53 a
//! root-cosigned `CommitmentRollover` (rank 1 at the fork after Vector 41),
//! Vector 54 a `RootRecovery{CoSigns}` (rank 1 there) and Vector 55 a
//! `RootRecovery{Lost}` (rank 2 there).

use scp_did::KeyCondition;
use scp_kel::{
    ChainRelation, EntryAdoption, EntryRelations, ExtendingAct, ServedChainReading, TieClass,
    ValidatedChain, WithheldEvent, classify_relation,
};

use super::chain_support::{
    Base, Error, Ring, Wire, flip, key_state_on, sign_on, signature_field_at, v41, v41_v50,
    v41_v53, v41_v54, v41_v55, v55_with, vector,
};
use super::chain_valid::chain_of;
use super::fixtures::{
    TestResult, V41_DIGEST, V50_DIGEST, V53_DIGEST, V54_DIGEST, V55_DIGEST, V55_PREIMAGE, array,
};

/// Bytes no unit frames: a length prefix that runs past the bytes.
const JUNK: &[u8] = &[0xff, 0xff, 0xff];

/// The relations of `served` to `own`'s chain, with `authored` digests.
fn relate(
    own: &ValidatedChain,
    served: &[&[u8]],
    authored: &[[u8; 32]],
) -> Result<EntryRelations, Error> {
    Ok(classify_relation(own, served, authored)?)
}

/// The one reading of an entry that served one chain.
fn single(relations: &EntryRelations) -> Result<&ServedChainReading, Error> {
    match relations.readings() {
        [reading] => Ok(reading),
        other => Err(format!("expected one reading, got {other:?}").into()),
    }
}

fn head_of(chain: Option<&ValidatedChain>) -> Option<[u8; 32]> {
    chain.map(ValidatedChain::head_digest)
}

fn own(base: &Base) -> Result<ValidatedChain, Error> {
    chain_of(base)
}

/// The head the entry adopts, or `None` under `Keep`.
fn adopted_head(relations: &EntryRelations) -> Result<Option<[u8; 32]>, Error> {
    match &relations.adoption() {
        EntryAdoption::Keep => Ok(None),
        EntryAdoption::Adopt(chain) => Ok(Some(chain.head_digest())),
        contested @ EntryAdoption::Contested { .. } => {
            Err(format!("expected no contest, got {contested:?}").into())
        }
    }
}

/// The last unit of `base`.
fn last_unit(base: &Base) -> Result<&[u8], Error> {
    Ok(base.units.last().ok_or("a chain holds a unit")?)
}

/// `base` extended by a `KeyState` naming root index 0 that keeps the
/// current keys of `source`'s snapshot, `base`'s head, with a new
/// witnessing interval.
fn key_state_after(ring: &Ring, base: &Base, source: &str) -> Result<Base, Error> {
    let mut snapshot = vector(source)?
        .key_state
        .ok_or("the source carries a snapshot")?;
    snapshot.witnessing_interval = 10_800;
    snapshot
        .keys
        .retain(|entry| entry.condition == KeyCondition::Current);
    let preimage = key_state_on(base, snapshot);
    let unit = sign_on(ring, base, &preimage)?;
    let extended = base.then(&Wire::of(&preimage).fields(), unit, base.root.clone());
    chain_of(&extended)?;
    Ok(extended)
}

/// [Vector 41, Vector 50, a `RootRecovery{Lost}`]: Vector 55's reveal moved
/// onto Vector 50, which leaves Vector 41's commitment standing.
fn v41_v50_lost(ring: &Ring) -> Result<Base, Error> {
    let v50 = v41_v50()?;
    let lost = v55_with(|preimage| {
        preimage.sequence = 2;
        preimage.predecessor_digest = v50.head;
    })?;
    let unit = sign_on(ring, &v50, &lost)?;
    let extended = v50.then(&Wire::of(&lost).fields(), unit, v41_v55()?.root);
    chain_of(&extended)?;
    Ok(extended)
}

#[test]
fn relation_absent() -> TestResult {
    let own = own(&v41_v50()?)?;

    let empty = relate(&own, &[], &[])?;
    let reading = single(&empty)?;
    assert_eq!(reading.relation(), ChainRelation::Absent);
    assert_eq!(reading.head(), None);
    assert_eq!(reading.served(), None);
    assert_eq!(reading.candidate(), None);
    assert!(!reading.served_outranks_own());
    assert!(!empty.served_any_unit(), "an empty entry served no unit");
    assert!(empty.discarded().is_empty());
    assert_eq!(*empty.adoption(), EntryAdoption::Keep);

    // Frames that chain to nothing: the relation reads the valid prefix,
    // which is empty, and never the bytes served.
    let junk = relate(&own, &[JUNK], &[])?;
    let reading = single(&junk)?;
    assert_eq!(reading.relation(), ChainRelation::Absent);
    assert_eq!(reading.head(), None);
    assert!(junk.served_any_unit(), "the entry served a unit");
    assert_eq!(junk.discarded().len(), 1);
    Ok(())
}

#[test]
fn relation_identical() -> TestResult {
    let base = v41_v50()?;
    let own = own(&base)?;
    let relations = relate(&own, &base.refs(), &[])?;
    let reading = single(&relations)?;
    assert_eq!(reading.relation(), ChainRelation::Identical);
    assert_eq!(reading.head(), Some(array(V50_DIGEST)?));
    assert_eq!(reading.candidate(), None);
    assert!(!reading.served_outranks_own());
    assert!(relations.served_any_unit());
    assert!(relations.discarded().is_empty());
    assert_eq!(*relations.adoption(), EntryAdoption::Keep);
    Ok(())
}

#[test]
fn relation_superseded() -> TestResult {
    let own = own(&v41_v50()?)?;
    let relations = relate(&own, &v41()?.refs(), &[])?;
    let reading = single(&relations)?;
    assert_eq!(reading.relation(), ChainRelation::Superseded);
    assert_eq!(reading.head(), Some(array(V41_DIGEST)?));
    assert_eq!(reading.candidate(), None);
    assert!(!reading.served_outranks_own());
    assert_eq!(*relations.adoption(), EntryAdoption::Keep);
    Ok(())
}

/// A served unit whose signature is damaged is discarded and its position
/// unserved, so the relation reads the prefix before it and never the
/// bytes the entry served.
#[test]
fn relation_reads_prefix_before_damaged_unit() -> TestResult {
    let base = v41_v50()?;
    let own = own(&base)?;
    let v50_unit = last_unit(&base)?;
    let damaged = flip(v50_unit, signature_field_at(v50_unit)?)?;
    let v41_base = v41()?;
    let served = v41_base.with(&damaged);
    let relations = relate(&own, &served, &[])?;
    let reading = single(&relations)?;
    assert_eq!(reading.relation(), ChainRelation::Superseded);
    assert_eq!(reading.head(), Some(array(V41_DIGEST)?));
    let [discarded] = relations.discarded() else {
        return Err(format!("expected one discard, got {:?}", relations.discarded()).into());
    };
    assert_eq!(discarded.served_index(), 1);
    assert_eq!(discarded.read_for(), Some(1));
    Ok(())
}

#[test]
fn relation_extending_adopted() -> TestResult {
    let own = own(&v41()?)?;
    let relations = relate(&own, &v41_v50()?.refs(), &[])?;
    let reading = single(&relations)?;
    assert_eq!(
        reading.relation(),
        ChainRelation::Extending(ExtendingAct::Adopted)
    );
    assert_eq!(reading.head(), Some(array(V50_DIGEST)?));
    assert_eq!(head_of(reading.candidate()), Some(array(V50_DIGEST)?));
    assert_eq!(reading.withheld(), None);
    assert!(!reading.served_outranks_own());
    assert_eq!(adopted_head(&relations)?, Some(array(V50_DIGEST)?));
    Ok(())
}

#[test]
fn relation_extending_withheld() -> TestResult {
    let own = own(&v41()?)?;
    let served = v41_v55()?;

    // A `RootRecovery{Lost}` the SDK did not author is withheld, and the
    // adopted prefix ends before it.
    let relations = relate(&own, &served.refs(), &[])?;
    let reading = single(&relations)?;
    assert_eq!(
        reading.relation(),
        ChainRelation::Extending(ExtendingAct::Withheld)
    );
    assert_eq!(reading.head(), Some(array(V55_DIGEST)?));
    assert_eq!(head_of(reading.candidate()), Some(array(V41_DIGEST)?));
    assert_eq!(
        adopted_head(&relations)?,
        None,
        "the candidate is own's head"
    );

    // The same `{Lost}`, authored by the SDK, is adopted.
    let relations = relate(&own, &served.refs(), &[array(V55_DIGEST)?])?;
    let reading = single(&relations)?;
    assert_eq!(
        reading.relation(),
        ChainRelation::Extending(ExtendingAct::Adopted)
    );
    assert_eq!(head_of(reading.candidate()), Some(array(V55_DIGEST)?));

    // An unauthored `RootRecovery{CoSigns}` carries the standing root's
    // signature and is adopted.
    let relations = relate(&own, &v41_v54()?.refs(), &[])?;
    let reading = single(&relations)?;
    assert_eq!(
        reading.relation(),
        ChainRelation::Extending(ExtendingAct::Adopted)
    );
    assert_eq!(head_of(reading.candidate()), Some(array(V54_DIGEST)?));
    Ok(())
}

/// The withheld reading keeps the served chain whole, so the confirm-as-own
/// decision, the alert and R9's retention read the withheld `{Lost}` and
/// its suffix from it, and the adopted prefix ends at the event before it,
/// past `own`'s head.
#[test]
fn relation_withheld_exposes_withheld_suffix() -> TestResult {
    let ring = Ring::new()?;
    let own = own(&v41()?)?;
    let served = v41_v50_lost(&ring)?;
    let relations = relate(&own, &served.refs(), &[])?;
    let reading = single(&relations)?;
    assert_eq!(
        reading.relation(),
        ChainRelation::Extending(ExtendingAct::Withheld)
    );
    let withheld = WithheldEvent {
        sequence: 2,
        digest: served.head,
    };
    assert_eq!(reading.withheld(), Some(withheld));
    let chain = reading
        .served()
        .ok_or("a withheld reading keeps its chain")?;
    assert_eq!(chain.head_digest(), served.head);
    assert_eq!(chain.head_sequence(), withheld.sequence);
    assert_eq!(
        head_of(chain.prefix(withheld.sequence).as_ref()),
        Some(withheld.digest)
    );
    // The adopted prefix ends at Vector 50, past `own`'s head at Vector 41.
    assert_eq!(head_of(reading.candidate()), Some(array(V50_DIGEST)?));
    assert_eq!(adopted_head(&relations)?, Some(array(V50_DIGEST)?));
    Ok(())
}

/// An own log that already holds an adopted unauthored `{Lost}` withholds
/// nothing at or before its head: only events past it are read.
#[test]
fn relation_extending_reads_past_own_head() -> TestResult {
    let ring = Ring::new()?;
    let own_base = v41_v55()?;
    let own = own(&own_base)?;
    let served = key_state_after(&ring, &own_base, V55_PREIMAGE)?;
    let relations = relate(&own, &served.refs(), &[])?;
    let reading = single(&relations)?;
    assert_eq!(
        reading.relation(),
        ChainRelation::Extending(ExtendingAct::Adopted)
    );
    assert_eq!(reading.withheld(), None);
    assert_eq!(head_of(reading.candidate()), Some(served.head));
    assert_eq!(adopted_head(&relations)?, Some(served.head));
    Ok(())
}

#[test]
fn relation_diverged() -> TestResult {
    // Own Vector 50 (a `KeyState`, rank 3 at the fork) against served Vector
    // 54 (`{CoSigns}`, rank 1): R6 ranks the served prefix above the own
    // log, which the entry adopts.
    let own_v50 = own(&v41_v50()?)?;
    let relations = relate(&own_v50, &v41_v54()?.refs(), &[])?;
    let reading = single(&relations)?;
    assert_eq!(reading.relation(), ChainRelation::Diverged);
    assert_eq!(reading.head(), Some(array(V54_DIGEST)?));
    assert!(reading.served_outranks_own());
    assert_eq!(head_of(reading.candidate()), Some(array(V54_DIGEST)?));
    assert_eq!(adopted_head(&relations)?, Some(array(V54_DIGEST)?));

    // Own Vector 54 (rank 1) against served Vector 55 (`{Lost}`, rank 2):
    // the own log outranks it, and the entry adopts nothing. The reading
    // keeps the divergence and the served chain the re-publication and the
    // alert read.
    let own_v54 = own(&v41_v54()?)?;
    let relations = relate(&own_v54, &v41_v55()?.refs(), &[])?;
    let reading = single(&relations)?;
    assert_eq!(reading.relation(), ChainRelation::Diverged);
    assert_eq!(reading.head(), Some(array(V55_DIGEST)?));
    assert!(!reading.served_outranks_own());
    assert_eq!(reading.candidate(), None);
    let divergence = reading.divergence().ok_or("a diverged reading")?;
    assert_eq!(divergence.shared_prefix_head, array(V41_DIGEST)?);
    assert_eq!(divergence.fork_position, 1);
    let chain = reading
        .served()
        .ok_or("a diverged reading keeps its chain")?;
    assert_eq!(chain.head_digest(), array(V55_DIGEST)?);
    assert_eq!(
        head_of(chain.prefix(0).as_ref()),
        Some(divergence.shared_prefix_head)
    );
    assert_eq!(*relations.adoption(), EntryAdoption::Keep);
    Ok(())
}

#[test]
fn relation_passes_discarded_through() -> TestResult {
    let base = v41_v50()?;
    let own = own(&base)?;
    let units = base.refs();
    let (v41_unit, v50_unit) = match units.as_slice() {
        [first, second] => (*first, *second),
        other => return Err(format!("expected two units, got {}", other.len()).into()),
    };
    let relations = relate(&own, &[v41_unit, JUNK, v50_unit], &[])?;
    let reading = single(&relations)?;
    assert_eq!(reading.relation(), ChainRelation::Identical);
    assert_eq!(reading.head(), Some(array(V50_DIGEST)?));
    let [discarded] = relations.discarded() else {
        return Err(format!("expected one discard, got {:?}", relations.discarded()).into());
    };
    assert_eq!(discarded.served_index(), 1);
    assert_eq!(discarded.read_for(), None);
    Ok(())
}

#[test]
fn relation_reads_every_served_chain() -> TestResult {
    // One entry serving a fork: one reading per chain, in served order.
    let own = own(&v41_v50()?)?;
    let v54 = v41_v54()?;
    let base = v41_v50()?;
    let served = base.with(last_unit(&v54)?);
    let relations = relate(&own, &served, &[])?;
    let kinds: Vec<(ChainRelation, Option<[u8; 32]>)> = relations
        .readings()
        .iter()
        .map(|reading| (reading.relation(), reading.head()))
        .collect();
    assert_eq!(
        kinds,
        vec![
            (ChainRelation::Identical, Some(array(V50_DIGEST)?)),
            (ChainRelation::Diverged, Some(array(V54_DIGEST)?)),
        ]
    );
    assert!(relations.discarded().is_empty());
    Ok(())
}

/// Two chains whose arms each name a chain to adopt: R6 over the set picks
/// one, whatever order the entry served them in.
#[test]
fn relation_adoption_is_order_free() -> TestResult {
    // Own Vector 41; served Vector 50 (rank 3) and Vector 54 (rank 1), both
    // extending: Vector 54 wins.
    let own_v41 = own(&v41()?)?;
    let v41_base = v41()?;
    let v50 = v41_v50()?;
    let v54 = v41_v54()?;
    for order in [
        [last_unit(&v50)?, last_unit(&v54)?],
        [last_unit(&v54)?, last_unit(&v50)?],
    ] {
        let served: Vec<&[u8]> = v41_base.refs().into_iter().chain(order).collect();
        let relations = relate(&own_v41, &served, &[])?;
        assert_eq!(relations.readings().len(), 2);
        assert!(relations.readings().iter().all(|reading| {
            reading.relation() == ChainRelation::Extending(ExtendingAct::Adopted)
        }));
        assert_eq!(adopted_head(&relations)?, Some(array(V54_DIGEST)?));
    }

    // Own Vector 50; served an extension of it (rank 3 at the fork after
    // Vector 41) beside Vector 54, a diverged chain that outranks own:
    // Vector 54 wins.
    let ring = Ring::new()?;
    let own_v50 = own(&v50)?;
    let extended = key_state_after(&ring, &v50, super::fixtures::V50_PREIMAGE)?;
    let extension = last_unit(&extended)?;
    for order in [[extension, last_unit(&v54)?], [last_unit(&v54)?, extension]] {
        let served: Vec<&[u8]> = v50.refs().into_iter().chain(order).collect();
        let relations = relate(&own_v50, &served, &[])?;
        let mut relations_seen: Vec<ChainRelation> = relations
            .readings()
            .iter()
            .map(ServedChainReading::relation)
            .collect();
        relations_seen.sort_by_key(|relation| format!("{relation:?}"));
        assert_eq!(
            relations_seen,
            vec![
                ChainRelation::Diverged,
                ChainRelation::Extending(ExtendingAct::Adopted)
            ]
        );
        assert_eq!(adopted_head(&relations)?, Some(array(V54_DIGEST)?));
    }
    Ok(())
}

/// Two adopting chains that tie under R7: the entry adopts neither and
/// names both tied heads.
#[test]
fn relation_adoption_contested_on_tie() -> TestResult {
    // Own Vector 41; served Vector 53 and Vector 54, each root-cosigned at
    // the fork after Vector 41: rank 1 on both sides.
    let own_v41 = own(&v41()?)?;
    let v41_base = v41()?;
    let v53 = v41_v53()?;
    let v54 = v41_v54()?;
    let mut expected = vec![array(V53_DIGEST)?, array(V54_DIGEST)?];
    expected.sort_unstable();
    for order in [
        [last_unit(&v53)?, last_unit(&v54)?],
        [last_unit(&v54)?, last_unit(&v53)?],
    ] {
        let served: Vec<&[u8]> = v41_base.refs().into_iter().chain(order).collect();
        let relations = relate(&own_v41, &served, &[])?;
        let EntryAdoption::Contested {
            class,
            tied,
            shared_prefix_head,
            fork_position,
        } = &relations.adoption()
        else {
            return Err(format!("expected a contest, got {:?}", relations.adoption()).into());
        };
        assert_eq!(*class, TieClass::Rank1Terminal);
        let heads: Vec<[u8; 32]> = tied.iter().map(ValidatedChain::head_digest).collect();
        assert_eq!(heads, expected);
        assert_eq!(*shared_prefix_head, array(V41_DIGEST)?);
        assert_eq!(*fork_position, 1);
    }
    Ok(())
}
