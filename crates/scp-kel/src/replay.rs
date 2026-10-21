//! Key-state replay over a validated chain (`09-security-model.md` §9.7.4.2
//! R8).
//!
//! The derived key state at a position is that position's latest snapshot
//! together with the standing commitment at that position. No other earlier
//! event contributes: nothing is diffed or merged across state-carrying
//! events, a `RootRecovery`'s snapshot replaces the whole state, and a
//! `CommitmentRollover` replaces the commitment alone. The validator already
//! holds both components at every position, because R3's check order reads
//! them; replay composes them and never re-reads an event.

use scp_did::{Identifier, KeyState, StandingCommitment};

use crate::validate::{StandingState, ValidatedChain};

/// The key state a validated chain derives at one of its positions
/// (§9.7.4.2 R8), with the identifier and the position it was read at.
///
/// Its fields are private, and it has no `new`, `Default`, `From` or
/// deserializer: [`replay`] and [`key_state_at`] are the only ways to hold
/// one, and each reads a [`ValidatedChain`], so every `ReplayedState` comes
/// from a chain that passed R3's check order.
///
/// ```compile_fail,E0451
/// # use scp_kel::ReplayedState;
/// let state = ReplayedState { identifier: todo!(), head_digest: [0; 32], head_sequence: 0, key_state: todo!() };
/// ```
///
/// ```compile_fail,E0599
/// # use scp_kel::ReplayedState;
/// let state = ReplayedState::new();
/// ```
///
/// ```compile_fail,E0599
/// # use scp_kel::ReplayedState;
/// let state = ReplayedState::default();
/// ```
///
/// The positive control: [`replay`] over a chain
/// [`validate_entry`](crate::validate_entry) holds yields one.
///
/// ```
/// # use scp_kel::{EntryVerdict, ReplayedState, replay, validate_entry};
/// fn replayed(verdict: EntryVerdict) -> Option<ReplayedState> {
///     match verdict {
///         EntryVerdict::Valid { chains } => Some(replay(chains.first())),
///         EntryVerdict::InceptionInvalid { .. } | EntryVerdict::NoInception => None,
///     }
/// }
/// let units: [&[u8]; 0] = [];
/// assert_eq!(replayed(validate_entry(&scp_did::Identifier::ZERO, &units).verdict), None);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayedState {
    identifier: Identifier,
    head_digest: [u8; 32],
    head_sequence: u64,
    /// Carries the standing commitment as its own field, so the state and
    /// its commitment cannot disagree.
    key_state: KeyState,
}

impl ReplayedState {
    fn compose(identifier: Identifier, standing: &StandingState<'_>) -> Self {
        Self {
            identifier,
            head_digest: standing.digest,
            head_sequence: standing.sequence,
            key_state: standing
                .snapshot
                .clone()
                .into_key_state(standing.commitment.clone()),
        }
    }

    /// The identifier the chain's inception recomputes to.
    #[must_use]
    pub const fn identifier(&self) -> Identifier {
        self.identifier
    }

    /// The preimage digest of the event the state was read at.
    #[must_use]
    pub const fn head_digest(&self) -> [u8; 32] {
        self.head_digest
    }

    /// The sequence of the event the state was read at.
    #[must_use]
    pub const fn head_sequence(&self) -> u64 {
        self.head_sequence
    }

    /// The derived key state (§9.7.4.2, the key state's fields).
    #[must_use]
    pub const fn key_state(&self) -> &KeyState {
        &self.key_state
    }

    /// The standing commitment: `Fixed` until an abandoning
    /// `CommitmentRollover`, `Abandoned` from that position on (R4, R8).
    #[must_use]
    pub const fn standing_commitment(&self) -> &StandingCommitment {
        &self.key_state.standing_commitment
    }
}

/// The digest [`key_state_at`] was handed names no event of the chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("no event of the chain has the digest key_state_at was handed")]
pub struct NotOnChain {
    /// The digest handed in.
    pub digest: [u8; 32],
}

/// The key state at the chain's head (§9.7.4.2 R8): the head's latest
/// snapshot with the standing commitment at the head.
#[must_use]
pub fn replay(chain: &ValidatedChain) -> ReplayedState {
    ReplayedState::compose(chain.identifier(), &chain.head_state())
}

/// The key state at the chain's event whose preimage digest is `digest`
/// (§9.7.4.2 R8): that position's latest snapshot with the standing
/// commitment at that position, whatever events follow it.
///
/// # Errors
///
/// [`NotOnChain`] where no event of the chain has that digest.
pub fn key_state_at(
    chain: &ValidatedChain,
    digest: &[u8; 32],
) -> Result<ReplayedState, NotOnChain> {
    chain
        .state_at(digest)
        .map(|standing| ReplayedState::compose(chain.identifier(), &standing))
        .ok_or(NotOnChain { digest: *digest })
}
