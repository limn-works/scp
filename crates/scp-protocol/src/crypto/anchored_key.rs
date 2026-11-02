//! The signer keys §9.7.1's log-anchored and current-key classes name, read
//! from the signer's validated key-event log.
//!
//! Sources: `09-security-model.md` §9.7.1 log-anchored and current-key rows;
//! §9.7.4.2 R8; §9.5.2 **`ContextOperatorBinding`** "Class"; §9.6.3 "The
//! binding" and "The record".
//!
//! A verifier that takes a bare key trusts its caller to have read the key
//! at the right position of the right identity's log. These functions take
//! the log itself and read the key there, so a caller cannot hand in the
//! signer's current key for a log-anchored signature, another identity's
//! key, or a key from a position the signed object does not name.

use scp_crypto::p256::P256PublicKey;
use scp_did::Identifier;
use scp_kel::{ReplayedState, ValidatedChain, key_state_at, replay};

/// Why a signer's key could not be read from the key-event log handed in.
///
/// No variant carries bytes from the input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AnchoredKeyError {
    /// The log's inception derives another identifier than the signer the
    /// object names.
    #[error("the key-event log is another identity's")]
    IdentityMismatch,
    /// The object's key-state head names no event of the signer's chain.
    #[error("key_state_head names no event of the signer's chain")]
    HeadNotOnChain,
    /// The key state's `#active` key does not decode as a P-256 point.
    #[error("the signer's #active key is not a point on P-256")]
    ActiveKey,
}

/// The log-anchored class: the `#active` key `Current` at the event of
/// `chain` whose preimage digest is `key_state_head`, when `chain` is
/// `signer`'s.
///
/// `chain` is the chain the verifier adopted for `signer` (§9.7.4.2 R6).
/// §9.7.1's first-seen rule for a later `Compromised` marking stays the
/// caller's, because it reads when the verifier first saw the object.
pub(crate) fn active_at(
    chain: &ValidatedChain,
    signer: &Identifier,
    key_state_head: &[u8; 32],
) -> Result<P256PublicKey, AnchoredKeyError> {
    if chain.identifier() != *signer {
        return Err(AnchoredKeyError::IdentityMismatch);
    }
    let state =
        key_state_at(chain, key_state_head).map_err(|_| AnchoredKeyError::HeadNotOnChain)?;
    active_of(&state)
}

/// The current-key class: the `#active` key `Current` at the head of
/// `chain`, when `chain` is `signer`'s.
pub(crate) fn current_active(
    chain: &ValidatedChain,
    signer: &Identifier,
) -> Result<P256PublicKey, AnchoredKeyError> {
    if chain.identifier() != *signer {
        return Err(AnchoredKeyError::IdentityMismatch);
    }
    active_of(&replay(chain))
}

fn active_of(state: &ReplayedState) -> Result<P256PublicKey, AnchoredKeyError> {
    P256PublicKey::from_sec1(state.active_key()).map_err(|_| AnchoredKeyError::ActiveKey)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_kel::{TestResult, incept, key};

    /// After a rotation, the key at the inception's digest is the first
    /// `#active` and the head's is the second; another identity's log and a
    /// digest off the chain are refused.
    #[test]
    fn reads_the_key_at_the_named_position_of_the_signers_log() -> TestResult {
        let alice = incept(0x51, 0x52, 0x53)?;
        let first_head = alice.head;
        let alice = alice.rotate(0x54)?;
        let chain = alice.chain()?;
        assert_eq!(
            active_at(&chain, &alice.identifier, &first_head)?,
            key(0x52).public_key()
        );
        assert_eq!(
            active_at(&chain, &alice.identifier, &alice.head)?,
            key(0x54).public_key()
        );
        assert_eq!(
            current_active(&chain, &alice.identifier)?,
            key(0x54).public_key()
        );
        let bob = incept(0x61, 0x62, 0x63)?;
        assert_eq!(
            active_at(&chain, &bob.identifier, &first_head),
            Err(AnchoredKeyError::IdentityMismatch)
        );
        assert_eq!(
            current_active(&chain, &bob.identifier),
            Err(AnchoredKeyError::IdentityMismatch)
        );
        assert_eq!(
            active_at(&chain, &alice.identifier, &[0x22; 32]),
            Err(AnchoredKeyError::HeadNotOnChain)
        );
        Ok(())
    }
}
