//! The signer keys §9.7.1's log-anchored and current-key classes name, read
//! from the key state a resolution of the signer's key-event log accepted.
//!
//! Sources: `09-security-model.md` §9.7.1 log-anchored and current-key rows;
//! §9.7.4.2 R8; §9.5.2 **`ContextOperatorBinding`** "Class"; §9.6.3 "The
//! binding" and "The record"; `03-identity.md` §3.10.10 `ResolvedState`.
//!
//! A verifier that takes a bare key trusts its caller to have read the key
//! at the right position of the right identity's log. These functions take
//! the [`ResolvedState`] only the verdict classifier constructs, and read the
//! key there, so a caller cannot hand in the signer's current key for a
//! log-anchored signature, another identity's key, a key from a position the
//! signed object does not name, or a chain no resolution adopted.

use scp_crypto::p256::P256PublicKey;
use scp_did::{Identifier, KeyCondition, KeyEntry, KeyRole};
use scp_kel::ResolvedState;

/// Why a signer's key could not be read from the resolved key state handed
/// in.
///
/// No variant carries bytes from the input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AnchoredKeyError {
    /// The resolved log's inception derives another identifier than the
    /// signer the object names.
    #[error("the resolved key state is another identity's")]
    IdentityMismatch,
    /// The object's key-state head names no event of the signer's resolved
    /// chain.
    #[error("key_state_head names no event of the signer's chain")]
    HeadNotOnChain,
    /// The key state lists no single `Current` `#active` key, or that key
    /// does not decode as a P-256 point.
    #[error("the signer's #active key is not one point on P-256")]
    ActiveKey,
}

/// The log-anchored class: the `#active` key `Current` at the event of the
/// resolved chain whose §9.5.1 preimage digest is `key_state_head`, when
/// `resolved` is `signer`'s.
///
/// `resolved` is the key state the verifier's resolution of `signer`
/// accepted (§9.7.4.2 R14), read at a past position through
/// [`ResolvedState::key_state_at`]. §9.7.1's first-seen rule for a later
/// `Compromised` marking stays the caller's, because it reads when the
/// verifier first saw the object.
pub(crate) fn active_at(
    resolved: &ResolvedState,
    signer: &Identifier,
    key_state_head: &[u8; 32],
) -> Result<P256PublicKey, AnchoredKeyError> {
    if resolved.identifier() != signer {
        return Err(AnchoredKeyError::IdentityMismatch);
    }
    let state = resolved
        .key_state_at(key_state_head)
        .map_err(|_| AnchoredKeyError::HeadNotOnChain)?;
    active_of(&state.keys)
}

/// The current-key class: the `#active` key `Current` at the head of the
/// resolved chain, when `resolved` is `signer`'s.
pub(crate) fn current_active(
    resolved: &ResolvedState,
    signer: &Identifier,
) -> Result<P256PublicKey, AnchoredKeyError> {
    if resolved.identifier() != signer {
        return Err(AnchoredKeyError::IdentityMismatch);
    }
    active_of(&resolved.key_state().keys)
}

/// The one key `keys` lists `Current` in `#active`. R3 accepts no snapshot
/// with none or with two, so a resolved state always has one; a second or a
/// missing one fails closed all the same.
fn active_of(keys: &[KeyEntry]) -> Result<P256PublicKey, AnchoredKeyError> {
    let mut current = keys
        .iter()
        .filter(|entry| entry.role == KeyRole::Active && entry.condition == KeyCondition::Current);
    let (Some(entry), None) = (current.next(), current.next()) else {
        return Err(AnchoredKeyError::ActiveKey);
    };
    P256PublicKey::from_sec1(&entry.key).map_err(|_| AnchoredKeyError::ActiveKey)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_kel::{TestResult, incept, key};

    /// After a rotation, the key at the inception's digest is the first
    /// `#active` and the head's is the second; another identity's resolved
    /// state and a digest off the chain are refused.
    #[test]
    fn reads_the_key_at_the_named_position_of_the_signers_log() -> TestResult {
        let alice = incept(0x51, 0x52, 0x53)?;
        let first_head = alice.head;
        let alice = alice.rotate(0x54)?;
        let resolved = alice.resolved()?;
        assert_eq!(
            active_at(&resolved, &alice.identifier, &first_head)?,
            key(0x52).public_key()
        );
        assert_eq!(
            active_at(&resolved, &alice.identifier, &alice.head)?,
            key(0x54).public_key()
        );
        assert_eq!(
            current_active(&resolved, &alice.identifier)?,
            key(0x54).public_key()
        );
        let bob = incept(0x61, 0x62, 0x63)?;
        assert_eq!(
            active_at(&resolved, &bob.identifier, &first_head),
            Err(AnchoredKeyError::IdentityMismatch)
        );
        assert_eq!(
            current_active(&resolved, &bob.identifier),
            Err(AnchoredKeyError::IdentityMismatch)
        );
        assert_eq!(
            active_at(&resolved, &alice.identifier, &[0x22; 32]),
            Err(AnchoredKeyError::HeadNotOnChain)
        );
        Ok(())
    }
}
