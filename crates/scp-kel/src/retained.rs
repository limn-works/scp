//! The key state a validating store reads: one chain it retains under R9.
//!
//! Sources: `03-identity.md` §3.10.10 `ResolvedState` and `RetainedChain`;
//! `09-security-model.md` §9.7.4.2 R9, §9.7.1 log-anchored and current-key
//! rows, §9.10.12.
//!
//! A party's verification decision reads a [`ResolvedState`], which only the
//! verdict classifier constructs. A validating store (a node's public-record
//! store, §9.10.12) is not a party: it holds every chain it retains under R9,
//! accepted or suffix, and admits and selects per chain, for availability
//! only. [`RetainedChain`] is that store-held key state. Only
//! [`AcceptedChainHolder::retained`] constructs one, so a store reads a chain
//! its own holder retains and never a chain a caller hands in.
//!
//! [`KeyStateSource`] is the one input a log-anchored or current-key verifier
//! takes. It is sealed with exactly two implementors, [`ResolvedState`] and
//! [`RetainedChain`], so the identity check and the head-on-chain refusal a
//! verifier applies are the same for both.

use scp_did::{Identifier, KeyState};

use crate::rank::AcceptedChainHolder;
use crate::validate::{NotOnChain, ReplayedState, ValidatedChain, key_state_at, replay};
use crate::verdict::ResolvedState;

/// One chain a validating store retains under `09-security-model.md`
/// §9.7.4.2 R9, accepted or suffix, with the key state replaying it derives
/// (`03-identity.md` §3.10.10).
///
/// Only [`AcceptedChainHolder::retained`] constructs it. Its fields are
/// private, it has no `Deserialize`, and no conversion from a
/// [`ValidatedChain`] exists, so no caller can present a chain the holder does
/// not retain:
///
/// ```compile_fail,E0277
/// fn build(chain: scp_kel::ValidatedChain) -> scp_kel::RetainedChain {
///     chain.into()
/// }
/// ```
///
/// ```compile_fail,E0451
/// fn build(chain: scp_kel::ValidatedChain) -> scp_kel::RetainedChain {
///     scp_kel::RetainedChain {
///         identifier: chain.identifier(),
///         replayed: scp_kel::replay(&chain),
///         chain,
///     }
/// }
/// ```
///
/// The positive control reads one from a holder:
///
/// ```
/// fn heads(holder: &scp_kel::AcceptedChainHolder) -> Vec<[u8; 32]> {
///     holder.retained().iter().map(scp_kel::RetainedChain::head_digest).collect()
/// }
/// ```
///
/// It carries no verdict and no resolution instant: a store admits a record
/// for availability, and no party's trust decision reads a `RetainedChain`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetainedChain {
    chain: ValidatedChain,
    replayed: ReplayedState,
    identifier: Identifier,
}

impl RetainedChain {
    /// The key state `chain` replays to. Private to this module: its one
    /// caller is [`AcceptedChainHolder::retained`].
    fn of(chain: &ValidatedChain) -> Self {
        Self {
            chain: chain.clone(),
            replayed: replay(chain),
            identifier: chain.identifier(),
        }
    }

    /// The identifier the retained chain's inception recomputes to.
    #[must_use]
    pub const fn identifier(&self) -> &Identifier {
        &self.identifier
    }

    /// The preimage digest of the retained chain's head event.
    #[must_use]
    pub fn head_digest(&self) -> [u8; 32] {
        self.chain.head_digest()
    }

    /// The key state at the retained chain's head.
    #[must_use]
    pub const fn key_state(&self) -> &KeyState {
        self.replayed.key_state()
    }

    /// The key state at the retained chain's event whose preimage digest
    /// (`09-security-model.md` §9.5.1) is `digest`, read as
    /// [`ResolvedState::key_state_at`] reads it.
    ///
    /// # Errors
    ///
    /// [`NotOnChain`] where no event of the retained chain has that digest.
    pub fn key_state_at(&self, digest: &[u8; 32]) -> Result<KeyState, NotOnChain> {
        key_state_at(&self.chain, digest).map(|state| state.key_state().clone())
    }
}

impl AcceptedChainHolder {
    /// Every chain the holder retains under R9, the accepted chain included,
    /// in the order of the moment the holder first held each, as the key state
    /// a validating store's admission and selection read
    /// (`03-identity.md` §3.10.10, `09-security-model.md` §9.10.12).
    #[must_use]
    pub fn retained(&self) -> Vec<RetainedChain> {
        self.held().map(RetainedChain::of).collect()
    }
}

mod sealed {
    /// Closes [`super::KeyStateSource`] to its two implementors.
    pub trait Sealed {}
    impl Sealed for super::ResolvedState {}
    impl Sealed for super::RetainedChain {}
}

/// The key state a log-anchored or current-key verifier reads a signer's key
/// from.
///
/// A [`ResolvedState`] serves a party's verification decision, and a
/// [`RetainedChain`] serves a validating store's admission and selection
/// (`03-identity.md` §3.10.10, `09-security-model.md` §9.7.1). The trait is
/// sealed, with exactly those two implementors.
pub trait KeyStateSource: sealed::Sealed {
    /// The identifier the chain's inception recomputes to.
    fn identifier(&self) -> &Identifier;

    /// The key state at the chain's head.
    fn key_state(&self) -> &KeyState;

    /// The key state at the chain's event whose preimage digest is `digest`.
    ///
    /// # Errors
    ///
    /// [`NotOnChain`] where no event of the chain has that digest.
    fn key_state_at(&self, digest: &[u8; 32]) -> Result<KeyState, NotOnChain>;
}

impl KeyStateSource for ResolvedState {
    fn identifier(&self) -> &Identifier {
        Self::identifier(self)
    }

    fn key_state(&self) -> &KeyState {
        Self::key_state(self)
    }

    fn key_state_at(&self, digest: &[u8; 32]) -> Result<KeyState, NotOnChain> {
        Self::key_state_at(self, digest)
    }
}

impl KeyStateSource for RetainedChain {
    fn identifier(&self) -> &Identifier {
        Self::identifier(self)
    }

    fn key_state(&self) -> &KeyState {
        Self::key_state(self)
    }

    fn key_state_at(&self, digest: &[u8; 32]) -> Result<KeyState, NotOnChain> {
        Self::key_state_at(self, digest)
    }
}
