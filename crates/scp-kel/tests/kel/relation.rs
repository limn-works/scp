//! R10's five relations through `classify_relation`, each against the
//! controller's own retained log, over spec 25's chains
//! (`09-security-model.md` §9.7.4.2 R10, *The prefix a relation reads* and
//! *The five relations, each naming an act*).
//!
//! Every expected relation is the test's own reading of R10 from the
//! vectors' kinds: Vector 50 is a root-signed `KeyState`, Vector 54 a
//! `RootRecovery{CoSigns}` (rank 1 at the fork after Vector 41) and Vector
//! 55 a `RootRecovery{Lost}` (rank 2 there).

use scp_kel::{
    ChainRelation, EntryRelations, ExtendingAct, ServedChainReading, ValidatedChain,
    classify_relation,
};

use super::chain_support::{Base, Error, v41, v41_v50, v41_v54, v41_v55};
use super::chain_valid::chain_of;
use super::fixtures::{TestResult, V41_DIGEST, V50_DIGEST, V54_DIGEST, V55_DIGEST, array};

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
    match relations.readings.as_slice() {
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

#[test]
fn relation_absent() -> TestResult {
    let own = own(&v41_v50()?)?;

    let empty = relate(&own, &[], &[])?;
    let reading = single(&empty)?;
    assert_eq!(reading.relation, ChainRelation::Absent);
    assert_eq!(reading.head, None);
    assert_eq!(reading.adopt, None);
    assert!(!reading.served_outranks_own);
    assert!(!empty.served_any_unit, "an empty entry served no unit");
    assert!(empty.discarded.is_empty());

    // Frames that chain to nothing: the relation reads the valid prefix,
    // which is empty, and never the bytes served.
    let junk = relate(&own, &[JUNK], &[])?;
    let reading = single(&junk)?;
    assert_eq!(reading.relation, ChainRelation::Absent);
    assert_eq!(reading.head, None);
    assert!(junk.served_any_unit, "the entry served a unit");
    assert_eq!(junk.discarded.len(), 1);
    Ok(())
}

#[test]
fn relation_identical() -> TestResult {
    let base = v41_v50()?;
    let own = own(&base)?;
    let relations = relate(&own, &base.refs(), &[])?;
    let reading = single(&relations)?;
    assert_eq!(reading.relation, ChainRelation::Identical);
    assert_eq!(reading.head, Some(array(V50_DIGEST)?));
    assert_eq!(reading.adopt, None);
    assert!(!reading.served_outranks_own);
    assert!(relations.served_any_unit);
    assert!(relations.discarded.is_empty());
    Ok(())
}

#[test]
fn relation_superseded() -> TestResult {
    let own = own(&v41_v50()?)?;
    let relations = relate(&own, &v41()?.refs(), &[])?;
    let reading = single(&relations)?;
    assert_eq!(reading.relation, ChainRelation::Superseded);
    assert_eq!(reading.head, Some(array(V41_DIGEST)?));
    assert_eq!(reading.adopt, None);
    assert!(!reading.served_outranks_own);
    Ok(())
}

#[test]
fn relation_extending_adopted() -> TestResult {
    let own = own(&v41()?)?;
    let relations = relate(&own, &v41_v50()?.refs(), &[])?;
    let reading = single(&relations)?;
    assert_eq!(
        reading.relation,
        ChainRelation::Extending(ExtendingAct::Adopted)
    );
    assert_eq!(reading.head, Some(array(V50_DIGEST)?));
    assert_eq!(head_of(reading.adopt.as_ref()), Some(array(V50_DIGEST)?));
    assert!(!reading.served_outranks_own);
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
        reading.relation,
        ChainRelation::Extending(ExtendingAct::Withheld)
    );
    assert_eq!(reading.head, Some(array(V55_DIGEST)?));
    assert_eq!(head_of(reading.adopt.as_ref()), Some(array(V41_DIGEST)?));

    // The same `{Lost}`, authored by the SDK, is adopted.
    let relations = relate(&own, &served.refs(), &[array(V55_DIGEST)?])?;
    let reading = single(&relations)?;
    assert_eq!(
        reading.relation,
        ChainRelation::Extending(ExtendingAct::Adopted)
    );
    assert_eq!(head_of(reading.adopt.as_ref()), Some(array(V55_DIGEST)?));

    // An unauthored `RootRecovery{CoSigns}` carries the standing root's
    // signature and is adopted.
    let relations = relate(&own, &v41_v54()?.refs(), &[])?;
    let reading = single(&relations)?;
    assert_eq!(
        reading.relation,
        ChainRelation::Extending(ExtendingAct::Adopted)
    );
    assert_eq!(head_of(reading.adopt.as_ref()), Some(array(V54_DIGEST)?));
    Ok(())
}

#[test]
fn relation_diverged() -> TestResult {
    // Own Vector 50 (a `KeyState`, rank 3 at the fork) against served Vector
    // 54 (`{CoSigns}`, rank 1): R6 ranks the served prefix above the own
    // log, which the arm adopts.
    let own_v50 = own(&v41_v50()?)?;
    let relations = relate(&own_v50, &v41_v54()?.refs(), &[])?;
    let reading = single(&relations)?;
    assert_eq!(reading.relation, ChainRelation::Diverged);
    assert_eq!(reading.head, Some(array(V54_DIGEST)?));
    assert!(reading.served_outranks_own);
    assert_eq!(head_of(reading.adopt.as_ref()), Some(array(V54_DIGEST)?));

    // Own Vector 54 (rank 1) against served Vector 55 (`{Lost}`, rank 2):
    // the own log outranks it, and the arm adopts nothing.
    let own_v54 = own(&v41_v54()?)?;
    let relations = relate(&own_v54, &v41_v55()?.refs(), &[])?;
    let reading = single(&relations)?;
    assert_eq!(reading.relation, ChainRelation::Diverged);
    assert_eq!(reading.head, Some(array(V55_DIGEST)?));
    assert!(!reading.served_outranks_own);
    assert_eq!(reading.adopt, None);
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
    assert_eq!(reading.relation, ChainRelation::Identical);
    assert_eq!(reading.head, Some(array(V50_DIGEST)?));
    let [discarded] = relations.discarded.as_slice() else {
        return Err(format!("expected one discard, got {:?}", relations.discarded).into());
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
    let v54_unit = v54.units.last().ok_or("Vector 54's unit")?;
    let base = v41_v50()?;
    let served = base.with(v54_unit);
    let relations = relate(&own, &served, &[])?;
    let kinds: Vec<(ChainRelation, Option<[u8; 32]>)> = relations
        .readings
        .iter()
        .map(|reading| (reading.relation, reading.head))
        .collect();
    assert_eq!(
        kinds,
        vec![
            (ChainRelation::Identical, Some(array(V50_DIGEST)?)),
            (ChainRelation::Diverged, Some(array(V54_DIGEST)?)),
        ]
    );
    assert!(relations.discarded.is_empty());
    Ok(())
}
