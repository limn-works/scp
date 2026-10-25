//! Fork rank, set resolution and the accepted-chain holder
//! (`09-security-model.md` §9.7.4.2 R6, R7, R9) over chains that fork from
//! Vector 41, each suffix signed here.
//!
//! These tests sit in the crate because `AcceptedChainHolder` stays
//! crate-private until S5 (SCP-007 part) wires it into a validating store,
//! and because the retention tests drive `RetentionSet` and the holder with
//! bounds small enough to reach. They compile the integration tests' spec 25 fixtures by path.
//!
//! Every expected rank and resolution is the test's own model of R6, read
//! from the kinds of the events a test built: a suffix ranks by its first
//! `CommitmentRollover` or `RootRecovery` past the fork, rank 1 for a
//! rollover or a `{CoSigns}` recovery (both carry a standing-root group),
//! rank 2 for a `{Lost}` recovery, and rank 3 where it holds none.

use proptest::prelude::*;
use scp_did::KeyCondition;

use self::chain_support::{
    Base, Error, Key, Recovery, Ring, Wire, fixes, group, key_state_on, sha256, signed, unit,
    unit_of, v41, v41_changed, v41_next, v41_v54, v41_v55, v42,
};
use self::fixtures::{TestResult, V41_DIGEST, V42_AUTHENTICATOR_DATA, V54_DIGEST, V55_DIGEST};
use super::holder::{AcceptedChainHolder, HoldError, HoldOutcome};
use super::{
    Admission, ChainPairing, Divergence, ForkRank, Rerank, ResolveError, SetResolution, TieClass,
    UnrelatedChains, pair_chains, resolve_set,
};
use crate::{
    AssertionSignature, CommitmentRolloverFields, EntryVerdict, EventPreimage, IndexedSignature,
    KeyStateSnapshot, SignatureForm, SignerGroupRole, StandingRootSigning, ValidatedChain,
    key_event_challenge, validate_entry,
};

#[expect(
    dead_code,
    reason = "the integration tests' fixtures; these tests read a subset"
)]
#[path = "../../tests/kel/fixtures.rs"]
mod fixtures;

#[expect(
    dead_code,
    reason = "the integration tests' chain support; these tests read a subset"
)]
#[path = "../../tests/kel/chain_support.rs"]
mod chain_support;

/// The kind of one event a test builds past Vector 41.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    /// A `KeyState` signed by the standing root, changing the interval.
    KeyState,
    /// A `CommitmentRollover` revealing the standing commitment, signed by
    /// the standing root.
    Reveal,
    /// A `RootRecovery{CoSigns}` revealing the standing commitment.
    CoSigns,
    /// A `RootRecovery{Lost}` revealing the standing commitment.
    Lost,
}

impl Kind {
    /// The rank the model gives a suffix whose first reveal is this event.
    const fn rank(self) -> Option<ForkRank> {
        match self {
            Self::KeyState => None,
            Self::Reveal | Self::CoSigns => Some(ForkRank::Rank1),
            Self::Lost => Some(ForkRank::Rank2),
        }
    }
}

/// The model's tie class: R7's mapping, written here.
const fn model_class(rank: ForkRank) -> TieClass {
    match rank {
        ForkRank::Rank1 => TieClass::Rank1Terminal,
        ForkRank::Rank2 => TieClass::Rank2Terminal,
        ForkRank::Rank3 => TieClass::Rank3Pending,
    }
}

/// The keys these tests sign with: the fixtures' ring and every key a
/// label names.
struct Keys {
    ring: Ring,
    labelled: Vec<Key>,
}

impl Keys {
    fn new() -> Result<Self, Error> {
        Ok(Self {
            ring: Ring::new()?,
            labelled: Vec::new(),
        })
    }

    /// The point of the key `SHA-256(label)`, which this set then signs
    /// with.
    fn point(&mut self, label: &str) -> [u8; 33] {
        let key = Key::labelled(label);
        let point = key.point;
        if self.key(&point).is_none() {
            self.labelled.push(key);
        }
        point
    }

    fn key(&self, point: &[u8; 33]) -> Option<&Key> {
        self.ring
            .key(point)
            .or_else(|| self.labelled.iter().find(|key| key.point == *point))
    }

    /// A unit over `preimage`, each slot signed by the key it names past
    /// `base`'s head: the revealed key for a reveal index, field 9's member
    /// for a replacement-root index, the standing root's otherwise.
    fn sign(&self, base: &Base, preimage: &EventPreimage) -> Result<Vec<u8>, Error> {
        let roles = preimage.signer_group_roles().unwrap_or(&[]);
        let installed: &[[u8; 33]] = preimage
            .installed_root_set
            .as_ref()
            .map_or(&[], |root| root.members.as_slice());
        let mut slots = Vec::new();
        for (group, role) in preimage.signer_groups.iter().zip(roles) {
            for (position, index) in group.indices.iter().enumerate() {
                let point = match role {
                    SignerGroupRole::Reveal => preimage.revealed_keys.get(position),
                    SignerGroupRole::ReplacementRoot => installed.get(usize::from(*index)),
                    SignerGroupRole::Root | SignerGroupRole::StandingRoot => {
                        base.root.get(usize::from(*index))
                    }
                };
                slots.push(point.and_then(|point| self.key(point)));
            }
        }
        unit(&Wire::of(preimage).fields(), &slots)
    }
}

/// A chain under construction past Vector 41, with the model's view of it:
/// each event's kind and identity, and each position's digest as computed
/// here.
#[derive(Clone)]
struct Branch {
    base: Base,
    chain: ValidatedChain,
    /// The standing snapshot.
    snapshot: KeyStateSnapshot,
    /// The key the standing commitment names.
    next: [u8; 33],
    /// The kind of the event at each position past Vector 41.
    kinds: Vec<Kind>,
    /// Who built the event at each position past Vector 41, and where: two
    /// branches hold one event where they hold one identity.
    ids: Vec<(u32, u32)>,
    /// The head digest at each position, Vector 41's first.
    digests: Vec<[u8; 32]>,
    /// The length of the unit at each position, Vector 41's first.
    unit_lens: Vec<u64>,
}

/// A snapshot naming only the `Current` keys of `snapshot`.
fn current_only(snapshot: &KeyStateSnapshot) -> KeyStateSnapshot {
    let mut out = snapshot.clone();
    out.keys
        .retain(|entry| entry.condition == KeyCondition::Current);
    out
}

impl Branch {
    /// Vector 41 alone.
    fn v41() -> Result<Self, Error> {
        let base = v41()?;
        let chain = chain_of(&base)?;
        let unit_len = base.units.first().map_or(0, Vec::len);
        Ok(Self {
            digests: vec![base.head],
            unit_lens: vec![u64::try_from(unit_len)?],
            chain,
            base,
            snapshot: v41_changed()?,
            next: v41_next()?,
            kinds: Vec::new(),
            ids: Vec::new(),
        })
    }

    /// The branch's head digest.
    fn head(&self) -> [u8; 32] {
        self.base.head
    }

    /// Appends the signed unit over `preimage`, after which `root` stands.
    fn append(
        &mut self,
        preimage: &EventPreimage,
        unit: Vec<u8>,
        root: Vec<[u8; 33]>,
    ) -> TestResult {
        self.chain = self
            .chain
            .clone()
            .extend(&unit)
            .map_err(|(_, discarded)| format!("{discarded:?}"))?;
        self.unit_lens.push(u64::try_from(unit.len())?);
        self.base = self.base.then(&Wire::of(preimage).fields(), unit, root);
        self.digests.push(self.base.head);
        assert_eq!(self.chain.head_digest(), self.base.head);
        Ok(())
    }

    /// Appends one event of `kind`, built by `owner`: every label and
    /// interval names the owner and the position, so two owners never build
    /// one event.
    fn push(&mut self, keys: &mut Keys, kind: Kind, owner: u32) -> TestResult {
        let position = u32::try_from(self.ids.len())? + 1;
        let label = |role: &str| format!("rank-{owner}-{position}-{role}");
        match kind {
            Kind::KeyState => {
                let mut snapshot = self.snapshot.clone();
                snapshot.witnessing_interval = 10_000 + 100 * owner + position;
                let preimage = key_state_on(&self.base, snapshot.clone());
                let unit = keys.sign(&self.base, &preimage)?;
                self.append(&preimage, unit, self.base.root.clone())?;
                self.snapshot = snapshot;
            }
            Kind::Reveal => {
                let fresh = keys.point(&label("next"));
                let preimage = EventPreimage::commitment_rollover(CommitmentRolloverFields {
                    identifier: self.base.identifier,
                    sequence: self.base.len(),
                    predecessor_digest: self.base.head,
                    reveal_group: group(&[0]),
                    standing_root_group: group(&[0]),
                    revealed_keys: vec![self.next],
                    continuation: fixes(&[fresh], 1),
                });
                let unit = keys.sign(&self.base, &preimage)?;
                self.append(&preimage, unit, self.base.root.clone())?;
                self.next = fresh;
            }
            Kind::CoSigns | Kind::Lost => {
                let root = keys.point(&label("root"));
                let fresh = keys.point(&label("next"));
                let preimage = Recovery {
                    base: &self.base,
                    previous: &self.snapshot,
                    signing: if kind == Kind::CoSigns {
                        StandingRootSigning::CoSigns {
                            standing_root_group: group(&[0]),
                        }
                    } else {
                        StandingRootSigning::Lost
                    },
                    reveal: &[0],
                    revealed: vec![self.next],
                    k_prime: &[root],
                    k_threshold: 1,
                    active: keys.point(&label("active")),
                    continuation: fixes(&[fresh], 1),
                }
                .preimage()?;
                let unit = keys.sign(&self.base, &preimage)?;
                self.append(&preimage, unit, vec![root])?;
                self.snapshot =
                    current_only(preimage.key_state.as_ref().ok_or("a recovery's snapshot")?);
                self.next = fresh;
            }
        }
        self.kinds.push(kind);
        self.ids.push((owner, position));
        Ok(())
    }

    /// Vector 41 followed by `kinds`, all built by `owner`.
    fn of(keys: &mut Keys, kinds: &[Kind], owner: u32) -> Result<Self, Error> {
        let mut branch = Self::v41()?;
        for kind in kinds {
            branch.push(keys, *kind, owner)?;
        }
        Ok(branch)
    }

    /// The model's fork with `other`: the count of events both hold, the
    /// fork position past them, and the digest of the last.
    fn fork(&self, other: &Self) -> (usize, u64, [u8; 32]) {
        let past_v41 = self
            .ids
            .iter()
            .zip(&other.ids)
            .take_while(|(left, right)| left == right)
            .count();
        let digest = self.digests.get(past_v41).copied().unwrap_or_default();
        (
            past_v41,
            u64::try_from(past_v41).unwrap_or(u64::MAX) + 1,
            digest,
        )
    }

    /// The model's rank of this branch's suffix past its first `past_v41`
    /// events after Vector 41.
    fn rank_past(&self, past_v41: usize) -> ForkRank {
        self.kinds
            .iter()
            .skip(past_v41)
            .find_map(|kind| kind.rank())
            .unwrap_or(ForkRank::Rank3)
    }

    /// Whether this branch's events lead `other`'s.
    fn is_prefix_of(&self, other: &Self) -> bool {
        other.ids.starts_with(&self.ids)
    }
}

/// The base chain, validated with no discard.
fn chain_of(base: &Base) -> Result<ValidatedChain, Error> {
    let validation = validate_entry(&base.identifier, &base.refs());
    if !validation.discarded.is_empty() {
        return Err(format!("{}: discards {:?}", base.name, validation.discarded).into());
    }
    match &validation.verdict {
        EntryVerdict::Valid { chains } => Ok(chains.single().cloned().ok_or("one chain")?),
        other => Err(format!("{}: {other:?}", base.name).into()),
    }
}

/// The model's resolution of branches none of which leads another: R6's
/// winner, else every unbeaten branch and the strictest pair among them.
fn model(branches: &[&Branch]) -> Result<SetResolution, Error> {
    let compare = |i: usize, j: usize| -> Option<(ForkRank, ForkRank, u64, [u8; 32])> {
        let (left, right) = (branches.get(i)?, branches.get(j)?);
        let (past_v41, fork_position, digest) = left.fork(right);
        Some((
            left.rank_past(past_v41),
            right.rank_past(past_v41),
            fork_position,
            digest,
        ))
    };
    let beats = |i: usize, j: usize| {
        i != j && compare(i, j).is_some_and(|(left, right, ..)| left.number() < right.number())
    };
    let n = branches.len();
    if let Some(winner) = (0..n).find(|&i| (0..n).all(|j| i == j || beats(i, j))) {
        let head = branches.get(winner).ok_or("winner")?.head();
        return Ok(SetResolution::Winner { head });
    }
    let unbeaten: Vec<usize> = (0..n).filter(|&i| (0..n).all(|j| !beats(j, i))).collect();
    let mut strictest: Option<(u8, u64, [u8; 32], ForkRank)> = None;
    for &i in &unbeaten {
        for &j in &unbeaten {
            let Some((left, right, fork_position, digest)) = compare(i, j).filter(|_| i < j) else {
                continue;
            };
            assert_eq!(left, right, "two unbeaten branches tie");
            let key = (left.number(), fork_position, digest, left);
            if strictest.is_none_or(|best| (key.0, key.1, key.2) < (best.0, best.1, best.2)) {
                strictest = Some(key);
            }
        }
    }
    let (_, fork_position, shared_prefix_head, rank) =
        strictest.ok_or("no winner and fewer than two unbeaten branches")?;
    let mut heads: Vec<[u8; 32]> = unbeaten
        .iter()
        .filter_map(|&i| branches.get(i).map(|branch| branch.head()))
        .collect();
    heads.sort_unstable();
    Ok(SetResolution::Tie {
        class: model_class(rank),
        heads,
        shared_prefix_head,
        fork_position,
    })
}

fn arb_kind() -> impl Strategy<Value = Kind> {
    prop_oneof![
        Just(Kind::KeyState),
        Just(Kind::Reveal),
        Just(Kind::CoSigns),
        Just(Kind::Lost),
    ]
}

/// A trunk past Vector 41 and two to four suffixes, each forking from the
/// trunk at positions 1 to 4 with one to three events of its own.
#[derive(Debug, Clone)]
struct ForkTree {
    trunk: Vec<Kind>,
    suffixes: Vec<(usize, Vec<Kind>)>,
}

fn arb_fork_tree() -> impl Strategy<Value = ForkTree> {
    proptest::collection::vec(arb_kind(), 0..=3).prop_flat_map(|trunk| {
        let forks = trunk.len();
        let suffixes = proptest::collection::vec(
            (0..=forks, proptest::collection::vec(arb_kind(), 1..=3)),
            2..=4,
        );
        (Just(trunk), suffixes).prop_map(|(trunk, suffixes)| ForkTree { trunk, suffixes })
    })
}

impl ForkTree {
    /// Every frame of each suffix, the trunk's first: the suffix's chain
    /// through each position past Vector 41.
    fn frames(&self, keys: &mut Keys) -> Result<Vec<Vec<Branch>>, Error> {
        let mut trunk = vec![Branch::v41()?];
        for kind in &self.trunk {
            let mut next = trunk.last().ok_or("the trunk")?.clone();
            next.push(keys, *kind, 0)?;
            trunk.push(next);
        }
        let mut out = Vec::new();
        for (owner, (fork_at, own)) in (1_u32..).zip(&self.suffixes) {
            let mut frames: Vec<Branch> = trunk.iter().skip(1).take(*fork_at).cloned().collect();
            let mut branch = trunk.get(*fork_at).ok_or("a fork point")?.clone();
            for kind in own {
                branch.push(keys, *kind, owner)?;
                frames.push(branch.clone());
            }
            out.push(frames);
        }
        Ok(out)
    }
}

/// A rank-3 suffix on Vector 41 that no generated suffix equals.
fn comparator(keys: &mut Keys) -> Result<ValidatedChain, Error> {
    Ok(Branch::of(keys, &[Kind::KeyState], 99)?.chain)
}

fn diverged(pairing: ChainPairing) -> Result<Divergence, Error> {
    match pairing {
        ChainPairing::Diverged(divergence) => Ok(divergence),
        other => Err(format!("expected a divergence, got {other:?}").into()),
    }
}

fn fail(error: &Error) -> TestCaseError {
    TestCaseError::fail(error.to_string())
}

fn v41_digest() -> [u8; 32] {
    let mut digest = [0; 32];
    if let Ok(bytes) = hex::decode(V41_DIGEST) {
        digest.copy_from_slice(&bytes);
    }
    digest
}

/// AC1: once a suffix reveals C, extending it never changes its rank, and
/// every prefix carries the rank the model gives.
fn rank_is_fixed(kinds: &[Kind]) -> TestResult {
    let mut keys = Keys::new()?;
    let other = comparator(&mut keys)?;
    let mut branch = Branch::v41()?;
    let mut fixed = None;
    for kind in kinds {
        branch.push(&mut keys, *kind, 1)?;
        let divergence = diverged(pair_chains(&branch.chain, &other)?)?;
        let rank = divergence.ranks[0];
        assert_eq!(
            rank,
            branch.rank_past(0),
            "{kinds:?} at {}",
            branch.ids.len()
        );
        assert_eq!(divergence.ranks[1], ForkRank::Rank3);
        assert_eq!(divergence.fork_position, 1);
        assert_eq!(divergence.shared_prefix_head, v41_digest());
        match fixed {
            Some(fixed) => assert_eq!(rank, fixed, "{kinds:?} changed rank"),
            None if rank != ForkRank::Rank3 => fixed = Some(rank),
            None => {}
        }
    }
    Ok(())
}

/// AC1's must-fail input: Vector 55's `{Lost}` then a root-signed rollover
/// of the commitment the `{Lost}` itself fixed stays rank 2.
#[test]
fn lost_recovery_then_its_own_rollover_stays_rank_2() -> TestResult {
    rank_is_fixed(&[Kind::Lost, Kind::Reveal, Kind::KeyState])
}

/// The other side: a rollover then a `{Lost}` stays rank 1.
#[test]
fn rollover_then_lost_recovery_stays_rank_1() -> TestResult {
    rank_is_fixed(&[Kind::Reveal, Kind::Lost, Kind::CoSigns])
}

/// A rank-3 suffix ranks 1 once it reveals Vector 41's commitment under
/// Vector 41's root.
#[test]
fn key_state_then_root_signed_reveal_ranks_1() -> TestResult {
    rank_is_fixed(&[Kind::KeyState, Kind::KeyState, Kind::Reveal, Kind::KeyState])
}

/// Every ordering of `items`.
fn permutations<T: Clone>(items: &[T]) -> Vec<Vec<T>> {
    if items.len() <= 1 {
        return vec![items.to_vec()];
    }
    let mut out = Vec::new();
    for index in 0..items.len() {
        let mut rest = items.to_vec();
        let item = rest.remove(index);
        for mut tail in permutations(&rest) {
            tail.insert(0, item.clone());
            out.push(tail);
        }
    }
    out
}

/// AC2: `resolve_set` over a fork tree's leaves is the model's resolution,
/// in every input order.
fn resolves_as_the_model(tree: &ForkTree) -> TestResult {
    let mut keys = Keys::new()?;
    let frames = tree.frames(&mut keys)?;
    let leaves: Vec<&Branch> = frames
        .iter()
        .map(|frames| frames.last().ok_or("a suffix has an event"))
        .collect::<Result<_, _>>()?;
    let expected = model(&leaves)?;
    let chains: Vec<ValidatedChain> = leaves.iter().map(|leaf| leaf.chain.clone()).collect();
    for order in permutations(&chains) {
        assert_eq!(resolve_set(&order)?, expected, "{tree:?}");
    }
    Ok(())
}

/// What holding the first chain returns.
fn first_held() -> HoldOutcome {
    HoldOutcome::AcceptedExtended {
        rerank: Rerank::default(),
    }
}

/// A rerank report naming only `heads` as already held.
fn already_held(heads: &[[u8; 32]]) -> Rerank {
    Rerank {
        already_held: heads.to_vec(),
        ..Rerank::default()
    }
}

/// AC3: after every frame, the holder's accepted chain is the model's: R6's
/// winner among the chains held so far, otherwise the unbeaten chain
/// received first. A chain is received with its first frame no held chain
/// holds, and a frame extending a held chain keeps that chain's place.
fn accepted_follows_every_frame(tree: &ForkTree, choices: &[u8]) -> TestResult {
    let mut keys = Keys::new()?;
    let frames = tree.frames(&mut keys)?;
    let v41 = Branch::v41()?;
    let mut holder = AcceptedChainHolder::new();
    assert_eq!(holder.hold(v41.chain.clone())?, first_held());
    let mut held: Vec<Branch> = vec![v41];
    let mut delivered = vec![0_usize; frames.len()];
    let mut choices = choices.iter().cycle();
    loop {
        let open: Vec<usize> = (0..frames.len())
            .filter(|&suffix| delivered.get(suffix) < frames.get(suffix).map(Vec::len).as_ref())
            .collect();
        if open.is_empty() {
            return Ok(());
        }
        let pick = usize::from(*choices.next().ok_or("choices")?) % open.len();
        let suffix = *open.get(pick).ok_or("an open suffix")?;
        let at = delivered.get_mut(suffix).ok_or("a suffix")?;
        let frame = frames
            .get(suffix)
            .and_then(|frames| frames.get(*at))
            .ok_or("a frame")?;
        *at += 1;

        let outcome = holder.hold(frame.chain.clone())?;
        if held.iter().any(|chain| frame.is_prefix_of(chain)) {
            assert_eq!(outcome, HoldOutcome::AlreadyHeld, "{tree:?}");
        } else if let Some(slot) = held.iter_mut().find(|chain| chain.is_prefix_of(frame)) {
            *slot = frame.clone();
        } else {
            held.push(frame.clone());
        }

        let refs: Vec<&Branch> = held.iter().collect();
        let expected = match model(&refs)? {
            SetResolution::Winner { head } => head,
            SetResolution::Tie { heads, .. } => held
                .iter()
                .map(Branch::head)
                .find(|head| heads.contains(head))
                .ok_or("a tie names a held head")?,
            SetResolution::Empty => return Err("the holder holds a chain".into()),
        };
        let accepted = holder.accepted().ok_or("the holder holds a chain")?;
        assert_eq!(accepted.head_digest(), expected, "{tree:?} {delivered:?}");
        let held_heads: Vec<[u8; 32]> = holder.held().map(ValidatedChain::head_digest).collect();
        let model_heads: Vec<[u8; 32]> = held.iter().map(Branch::head).collect();
        assert_eq!(held_heads, model_heads, "{tree:?} {delivered:?}");
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn rank_is_fixed_once_suffix_reveals(
        kinds in proptest::collection::vec(arb_kind(), 1..=6),
    ) {
        rank_is_fixed(&kinds).map_err(|error| fail(&error))?;
    }

    #[test]
    fn resolve_set_ignores_input_order(tree in arb_fork_tree()) {
        resolves_as_the_model(&tree).map_err(|error| fail(&error))?;
    }

    #[test]
    fn accepted_chain_ignores_arrival_order_except_first_held_tie(
        tree in arb_fork_tree(),
        choices in proptest::collection::vec(any::<u8>(), 1..32),
    ) {
        accepted_follows_every_frame(&tree, &choices).map_err(|error| fail(&error))?;
    }
}

/// AC3's must-fail inputs, fixed: two rank-1 suffixes tie terminally, and
/// the one whose first frame arrived first stays accepted while the other
/// extends before and after it.
#[test]
fn held_first_tie_survives_extensions_in_any_frame_order() -> TestResult {
    let tree = ForkTree {
        trunk: Vec::new(),
        suffixes: vec![
            (0, vec![Kind::Reveal, Kind::KeyState, Kind::KeyState]),
            (0, vec![Kind::CoSigns, Kind::KeyState]),
        ],
    };
    // A first, then B, then A's extensions last: under head-digest identity
    // A's extensions would count as received after B.
    accepted_follows_every_frame(&tree, &[0, 1, 1, 0, 0])?;
    // B first, then A and its extensions: B stays.
    accepted_follows_every_frame(&tree, &[1, 0, 0, 0, 0])
}

/// R6's composite tie takes the strictest pair: A and B tie at rank 1 at
/// position 2, and each ties D at rank 1 at position 1, so the tie names
/// position 1 and Vector 41 even though A and B come first.
#[test]
fn composite_tie_takes_the_earliest_fork() -> TestResult {
    let mut keys = Keys::new()?;
    let tree = ForkTree {
        trunk: vec![Kind::KeyState],
        suffixes: vec![
            (1, vec![Kind::Reveal]),
            (1, vec![Kind::KeyState, Kind::Reveal]),
            (0, vec![Kind::Reveal]),
        ],
    };
    let frames = tree.frames(&mut keys)?;
    let chains: Vec<ValidatedChain> = frames
        .iter()
        .map(|frames| frames.last().map(|leaf| leaf.chain.clone()))
        .collect::<Option<_>>()
        .ok_or("leaves")?;
    let SetResolution::Tie {
        class,
        heads,
        shared_prefix_head,
        fork_position,
    } = resolve_set(&chains)?
    else {
        return Err("three rank-1 suffixes tie".into());
    };
    assert_eq!(class, TieClass::Rank1Terminal);
    assert_eq!(heads.len(), 3);
    assert_eq!(fork_position, 1);
    assert_eq!(shared_prefix_head, v41_digest());
    Ok(())
}

/// R7: two `{Lost}` recoveries tie terminally at rank 2.
#[test]
fn two_lost_recoveries_tie_at_rank_2_terminally() -> TestResult {
    let mut keys = Keys::new()?;
    let left = Branch::of(&mut keys, &[Kind::Lost], 1)?;
    let right = Branch::of(&mut keys, &[Kind::Lost], 2)?;
    let mut heads = vec![left.head(), right.head()];
    heads.sort_unstable();
    assert_eq!(
        resolve_set(&[left.chain, right.chain])?,
        SetResolution::Tie {
            class: TieClass::Rank2Terminal,
            heads,
            shared_prefix_head: v41_digest(),
            fork_position: 1,
        }
    );
    Ok(())
}

/// R7: two rank-3 suffixes tie pending, two rank-1 suffixes tie terminally,
/// and a rank-3 suffix beside them is beaten.
#[test]
fn tie_class_is_the_strictest_pairs() -> TestResult {
    let mut keys = Keys::new()?;
    let key_state = |keys: &mut Keys, owner| Branch::of(keys, &[Kind::KeyState], owner);
    let pending = resolve_set(&[
        key_state(&mut keys, 1)?.chain,
        key_state(&mut keys, 2)?.chain,
    ])?;
    let SetResolution::Tie {
        class,
        heads,
        fork_position,
        ..
    } = pending
    else {
        return Err(format!("expected a tie, got {pending:?}").into());
    };
    assert_eq!(class, TieClass::Rank3Pending);
    assert_eq!(heads.len(), 2);
    assert_eq!(fork_position, 1);

    let terminal = resolve_set(&[
        Branch::of(&mut keys, &[Kind::Reveal], 3)?.chain,
        Branch::of(&mut keys, &[Kind::CoSigns], 4)?.chain,
        key_state(&mut keys, 1)?.chain,
    ])?;
    let SetResolution::Tie { class, heads, .. } = terminal else {
        return Err(format!("expected a tie, got {terminal:?}").into());
    };
    assert_eq!(class, TieClass::Rank1Terminal);
    assert_eq!(heads.len(), 2, "the rank-3 suffix is beaten");
    Ok(())
}

/// AC7: Vector 54 (rank 1) beats Vector 55 (rank 2) at fork position 1, in
/// either argument order and either input order.
#[test]
fn vector_54_beats_vector_55_in_either_order() -> TestResult {
    let v54 = chain_of(&v41_v54()?)?;
    let v55 = chain_of(&v41_v55()?)?;
    let v54_digest: [u8; 32] = fixtures::array(V54_DIGEST)?;
    assert_eq!(
        pair_chains(&v54, &v55)?,
        ChainPairing::Diverged(Divergence {
            shared_prefix_head: v41_digest(),
            fork_position: 1,
            ranks: [ForkRank::Rank1, ForkRank::Rank2],
        })
    );
    assert_eq!(
        pair_chains(&v55, &v54)?,
        ChainPairing::Diverged(Divergence {
            shared_prefix_head: v41_digest(),
            fork_position: 1,
            ranks: [ForkRank::Rank2, ForkRank::Rank1],
        })
    );
    for chains in [[v54.clone(), v55.clone()], [v55, v54]] {
        assert_eq!(
            resolve_set(&chains)?,
            SetResolution::Winner { head: v54_digest }
        );
    }
    Ok(())
}

/// R9 at a store: Vector 54 displaces an earlier-held Vector 55, and a later
/// Vector 55 is held as a rank-2 divergent suffix.
#[test]
fn holder_accepts_vector_54_in_either_arrival_order() -> TestResult {
    let v41 = chain_of(&v41()?)?;
    let v54 = chain_of(&v41_v54()?)?;
    let v55_base = v41_v55()?;
    let v55 = chain_of(&v55_base)?;
    let v54_digest: [u8; 32] = fixtures::array(V54_DIGEST)?;
    let v55_digest: [u8; 32] = fixtures::array(V55_DIGEST)?;

    let mut holder = AcceptedChainHolder::new();
    assert_eq!(holder.accepted(), None);
    assert_eq!(holder.hold(v55.clone())?, first_held());
    assert_eq!(holder.hold(v41.clone())?, HoldOutcome::AlreadyHeld);
    assert_eq!(holder.hold(v55.clone())?, HoldOutcome::AlreadyHeld);
    assert_eq!(
        holder.hold(v54.clone())?,
        HoldOutcome::AcceptedReplaced {
            displaced: v55_digest,
            admission: Some(Admission::Retained {
                rank: ForkRank::Rank1,
                evicted: Vec::new(),
            }),
            rerank: already_held(&[v54_digest]),
        }
    );
    let set = holder.retention().ok_or("a retention set")?;
    let [suffix] = set.suffixes() else {
        return Err("Vector 55 is the one retained suffix".into());
    };
    assert_eq!(
        (
            suffix.head(),
            suffix.rank(),
            suffix.fork_position(),
            suffix.observed()
        ),
        (v55_digest, ForkRank::Rank2, 1, 0)
    );
    let v55_unit_len = v55_base.units.last().map(Vec::len).ok_or("V55's unit")?;
    assert_eq!(set.retained_bytes(), u64::try_from(v55_unit_len)?);
    assert_eq!(set.basis_observed(), 1);
    assert_eq!(
        holder.accepted().map(ValidatedChain::head_digest),
        Some(v54_digest)
    );

    let mut holder = AcceptedChainHolder::new();
    assert_eq!(holder.hold(v41)?, first_held());
    assert_eq!(
        holder.hold(v54)?,
        HoldOutcome::AcceptedExtended {
            rerank: already_held(&[v41_digest()]),
        }
    );
    assert_eq!(
        holder.hold(v55)?,
        HoldOutcome::HeldDivergent {
            admission: Admission::Retained {
                rank: ForkRank::Rank2,
                evicted: Vec::new(),
            }
        }
    );
    assert_eq!(
        holder.accepted().map(ValidatedChain::head_digest),
        Some(v54_digest)
    );
    Ok(())
}

/// R9's held-first rule moves acceptance: B0 (rank 3) is held first, A
/// (rank 1) displaces it, and B0's extension B1 reveals under the root and
/// ties A at rank 1. B is held earlier, so A becomes a divergent suffix
/// carrying the tie's rank, 1.
#[test]
fn held_first_tie_displaces_a_rank_1_chain() -> TestResult {
    let mut keys = Keys::new()?;
    let b0 = Branch::of(&mut keys, &[Kind::KeyState], 2)?;
    let a = Branch::of(&mut keys, &[Kind::Reveal], 1)?;
    let mut b1 = b0.clone();
    b1.push(&mut keys, Kind::Reveal, 2)?;

    let mut holder = AcceptedChainHolder::new();
    assert_eq!(holder.hold(b0.chain.clone())?, first_held());
    assert_eq!(
        holder.hold(a.chain.clone())?,
        HoldOutcome::AcceptedReplaced {
            displaced: b0.head(),
            admission: Some(Admission::Retained {
                rank: ForkRank::Rank1,
                evicted: Vec::new(),
            }),
            rerank: already_held(&[a.head()]),
        }
    );
    let set = holder.retention().ok_or("a retention set")?;
    let [suffix] = set.suffixes() else {
        return Err("B0 is the one retained suffix".into());
    };
    assert_eq!((suffix.head(), suffix.rank()), (b0.head(), ForkRank::Rank3));
    assert_eq!(
        holder.hold(b1.chain.clone())?,
        HoldOutcome::AcceptedReplaced {
            displaced: a.head(),
            admission: Some(Admission::Extended {
                rank: ForkRank::Rank1,
                replaced: b0.head(),
                evicted: Vec::new(),
            }),
            rerank: already_held(&[b1.head()]),
        },
        "B1 extends B0 and keeps its moment, so it ties A and was held first"
    );
    let set = holder.retention().ok_or("a retention set")?;
    let [suffix] = set.suffixes() else {
        return Err("A is the one retained suffix".into());
    };
    assert_eq!(
        (
            suffix.head(),
            suffix.rank(),
            suffix.fork_position(),
            suffix.observed()
        ),
        (a.head(), ForkRank::Rank1, 1, 1)
    );
    assert_eq!(Some(set.retained_bytes()), a.unit_lens.last().copied());
    assert_eq!(set.basis_observed(), 0);
    assert_eq!(
        holder.accepted().map(ValidatedChain::head_digest),
        Some(b1.head())
    );
    Ok(())
}

/// Unpadded base64url, the encoding of a `clientDataJSON` challenge.
fn base64url(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let mut word = [0_u8; 3];
        word[..chunk.len()].copy_from_slice(chunk);
        let bits = u32::from(word[0]) << 16 | u32::from(word[1]) << 8 | u32::from(word[2]);
        for at in 0..=chunk.len() {
            let index = (bits >> (18 - 6 * at)) & 0x3f;
            out.push(char::from(ALPHABET[index as usize]));
        }
    }
    out
}

/// A `KeyState` on Vector 41 whose root signs in the assertion form, as
/// two units of one preimage: the assertions differ in `clientDataJSON`'s
/// origin, so the units differ in bytes and length and share the digest.
fn assertion_copies(keys: &Keys) -> Result<(EventPreimage, Vec<u8>, Vec<u8>), Error> {
    let base = v41()?;
    let mut snapshot = v41_changed()?;
    snapshot.witnessing_interval = 7_300;
    let mut preimage = key_state_on(&base, snapshot);
    let root = preimage.signer_groups.first_mut().ok_or("a root group")?;
    root.forms = vec![SignatureForm::WebAuthnAssertion];
    let signed = signed(&Wire::of(&preimage).fields());
    let challenge = base64url(&key_event_challenge(&sha256(&[&signed])));
    let root_key = base
        .root
        .first()
        .and_then(|point| keys.key(point))
        .ok_or("the root key")?;
    let authenticator = hex::decode(V42_AUTHENTICATOR_DATA)?;
    let copy = |origin: &str| -> Result<Vec<u8>, Error> {
        let client_data = format!(
            r#"{{"type":"webauthn.get","challenge":"{challenge}","origin":"{origin}","crossOrigin":false}}"#
        )
        .into_bytes();
        let message = [authenticator.as_slice(), &sha256(&[&client_data])].concat();
        let signature = root_key.sign(&message)?;
        let assertion = AssertionSignature::new(authenticator.clone(), client_data, signature)?;
        unit_of(
            &signed,
            &IndexedSignature::WebAuthnAssertion(assertion).to_bytes(),
        )
    };
    Ok((
        preimage,
        copy("https://ctx.network")?,
        copy("https://a-longer-origin.ctx.network")?,
    ))
}

/// R9's copy identity: an extension carrying a byte-different copy of a held
/// event keeps the held copy, so the byte bound counts the copy held first.
#[test]
fn extension_keeps_the_held_copy_of_a_shared_event() -> TestResult {
    let mut keys = Keys::new()?;
    let (preimage, first, second) = assertion_copies(&keys)?;
    assert_ne!(first.len(), second.len());
    let v41 = v41()?;
    let fields = Wire::of(&preimage).fields();
    let held = v41.then(&fields, first.clone(), v41.root.clone());
    let copied = v41.then(&fields, second, v41.root.clone());
    let mut later = v41_changed()?;
    later.witnessing_interval = 7_400;
    let next = key_state_on(&copied, later);
    let next_unit = keys.sign(&copied, &next)?;
    let next_len = next_unit.len();
    let extension = copied.then(&Wire::of(&next).fields(), next_unit, v41.root);

    let mut holder = AcceptedChainHolder::new();
    assert_eq!(holder.hold(chain_of(&held)?)?, first_held());
    assert_eq!(
        holder.hold(chain_of(&extension)?)?,
        HoldOutcome::AcceptedExtended {
            rerank: already_held(&[held.head]),
        }
    );
    let accepted = holder.accepted().ok_or("an accepted chain")?;
    assert_eq!(accepted.head_digest(), extension.head);
    let shared = accepted.events().nth(1).ok_or("the shared event")?;
    assert_eq!(shared.unit, first.as_slice());

    let rollover = Branch::of(&mut keys, &[Kind::Reveal], 1)?;
    let HoldOutcome::AcceptedReplaced { displaced, .. } = holder.hold(rollover.chain)? else {
        return Err("a rollover beats a key state".into());
    };
    assert_eq!(displaced, extension.head);
    let set = holder.retention().ok_or("a retention set")?;
    assert_eq!(set.retained_bytes(), u64::try_from(first.len() + next_len)?);
    Ok(())
}

/// Chains of two identifiers share no prefix: every entry point refuses
/// them with a typed error and the holder keeps what it held.
#[test]
fn chains_of_two_identifiers_are_refused() -> TestResult {
    let v41 = chain_of(&v41()?)?;
    let v42 = chain_of(&v42()?)?;
    let unrelated = UnrelatedChains {
        left: v41.identifier(),
        right: v42.identifier(),
    };
    assert_eq!(pair_chains(&v41, &v42), Err(unrelated));
    assert_eq!(
        resolve_set(&[v41.clone(), v42.clone()]),
        Err(ResolveError::Unrelated(UnrelatedChains {
            left: v42.identifier(),
            right: v41.identifier(),
        }))
    );
    let mut holder = AcceptedChainHolder::new();
    assert_eq!(holder.hold(v41.clone())?, first_held());
    assert_eq!(
        holder.hold(v42.clone()),
        Err(HoldError::Resolve(ResolveError::Unrelated(
            UnrelatedChains {
                left: v42.identifier(),
                right: v41.identifier(),
            }
        )))
    );
    assert_eq!(holder.held().count(), 1);
    assert_eq!(holder.accepted(), Some(&v41));
    assert_eq!(resolve_set(&[])?, SetResolution::Empty);
    Ok(())
}

mod retention;

mod verdict;
