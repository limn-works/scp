//! The `NodeBinding` (`09-security-model.md` §9.6.3 "The binding"; §9.18.2
//! `"SCP-NODE-BIND-V1:"`; spec 25 §25.27 Vector 91).
//!
//! A binding binds one node key to one operator identity. Both the operator's
//! `#active` key and the node key sign
//!
//! ```text
//! P = SHA-256("SCP-NODE-BIND-V1:" ‖ operator ‖ node_key ‖ url_hash ‖ key_state_head)
//! ```
//!
//! Every field is fixed width (32, 33, 32 and 32 bytes), so §9.5.1 writes
//! each raw with no length prefix and the 17-byte separator makes a 146-byte
//! preimage. Each field's offset is fixed, so no two field tuples share a
//! preimage.

use scp_crypto::p256::{P256Error, P256PublicKey, SIGNATURE_LEN, verify_prehash_strict};
use scp_did::{Identifier, NodeId, NodeUrl};
use scp_kel::{NodeKeyError, ResolvedState, derive_node_id, parse_node_key};
use sha2::{Digest, Sha256};

use crate::crypto::anchored_key::{AnchoredKeyError, active_at};

/// The §9.18.2 separator of the binding preimage.
pub const NODE_BINDING_SEPARATOR: &str = "SCP-NODE-BIND-V1:";

/// The length of a node key: a compressed SEC1 P-256 point.
pub const NODE_KEY_LEN: usize = 33;

/// One node key bound to one operator identity (§9.6.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeBinding {
    /// The operator identity that runs the node.
    pub operator: Identifier,
    /// The node key, a 33-byte compressed SEC1 point on P-256.
    pub node_key: [u8; NODE_KEY_LEN],
    /// SHA-256 of the node's canonical URL (§9.18.2 "Canonical node URL").
    pub url_hash: [u8; 32],
    /// The operator's key-state position when it signed (§9.7.1 log-anchored
    /// row): the §9.5.1 preimage digest of its latest state-carrying event.
    pub key_state_head: [u8; 32],
    /// The operator's `#active` signature over `P`.
    pub operator_sig: [u8; SIGNATURE_LEN],
    /// The node key's signature over `P`, proving the operator holds the
    /// node key's private half.
    pub possession_sig: [u8; SIGNATURE_LEN],
}

/// Why a binding fails verification. A party treats the entry that carries it
/// as void (§9.6.3 acceptance step 3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum NodeBindingError {
    /// `node_key` is not a compressed SEC1 point on P-256.
    #[error("binding node key: {0}")]
    NodeKey(#[from] NodeKeyError),
    /// The operator's `#active` at `key_state_head` could not be read from
    /// the key-event log handed in.
    #[error("binding operator key: {0}")]
    OperatorKey(AnchoredKeyError),
    /// `operator_sig` does not verify under the operator's `#active` key at
    /// `key_state_head`.
    #[error("binding operator signature: {0}")]
    OperatorSignature(P256Error),
    /// `possession_sig` does not verify under `node_key`.
    #[error("binding possession signature: {0}")]
    PossessionSignature(P256Error),
}

/// `SHA-256` of a node's canonical URL, the value `url_hash` carries.
#[must_use]
pub fn node_url_hash(url: &NodeUrl) -> [u8; 32] {
    Sha256::digest(url.as_str().as_bytes()).into()
}

impl NodeBinding {
    /// `P`, the digest both signatures cover.
    #[must_use]
    pub fn signing_digest(
        operator: &Identifier,
        node_key: &[u8; NODE_KEY_LEN],
        url_hash: &[u8; 32],
        key_state_head: &[u8; 32],
    ) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(NODE_BINDING_SEPARATOR.as_bytes());
        hasher.update(operator.as_bytes());
        hasher.update(node_key);
        hasher.update(url_hash);
        hasher.update(key_state_head);
        hasher.finalize().into()
    }

    /// `P` over this binding's four signed fields.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        Self::signing_digest(
            &self.operator,
            &self.node_key,
            &self.url_hash,
            &self.key_state_head,
        )
    }

    /// The `NodeId` of `node_key`, the name of the entry that carries this
    /// binding (§9.6.3 "The entry").
    ///
    /// # Errors
    ///
    /// [`NodeKeyError`] when `node_key` is not a point on P-256.
    pub fn node_id(&self) -> Result<NodeId, NodeKeyError> {
        derive_node_id(&self.node_key)
    }
}

/// A [`NodeBinding`] whose two signatures verified (§9.6.3 "The binding").
///
/// [`Self::verify`] is the only constructor, so a function that takes this
/// type cannot be handed a binding no party checked, and the type has no
/// `Deserialize`. Holding one establishes the operator's signature and
/// possession of the node key, not attribution: a binding is attributed only
/// when a verified `NodeListRecord` carries it (§9.6.3 "Attribution and
/// standing").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedNodeBinding {
    binding: NodeBinding,
    node_key: P256PublicKey,
    node_id: NodeId,
}

impl VerifiedNodeBinding {
    /// The two checks of §9.6.3: `operator_sig` under the operator's
    /// `#active` at `key_state_head`, and `possession_sig` under `node_key`,
    /// both over `P` and both strict (low-`s`, no second hash).
    ///
    /// `operator` is the key state the verifier's resolution of
    /// `binding.operator` accepted. The operator's key is read from it at `binding.key_state_head`, the
    /// log-anchored class of §9.7.1, so a key from another identity or
    /// another position never verifies the binding. §9.7.1's first-seen rule
    /// for a later `Compromised` marking stays the caller's.
    ///
    /// # Errors
    ///
    /// [`NodeBindingError`] names the first check that failed, in the order
    /// node key, operator key, operator signature, possession signature.
    pub fn verify(
        binding: NodeBinding,
        operator: &ResolvedState,
    ) -> Result<Self, NodeBindingError> {
        let node_key = parse_node_key(&binding.node_key)?;
        let operator_active = active_at(operator, &binding.operator, &binding.key_state_head)
            .map_err(NodeBindingError::OperatorKey)?;
        let digest = binding.digest();
        verify_prehash_strict(&operator_active, &digest, &binding.operator_sig)
            .map_err(NodeBindingError::OperatorSignature)?;
        verify_prehash_strict(&node_key, &digest, &binding.possession_sig)
            .map_err(NodeBindingError::PossessionSignature)?;
        let node_id = derive_node_id(&binding.node_key)?;
        Ok(Self {
            binding,
            node_key,
            node_id,
        })
    }

    /// Borrows the binding this value verified.
    #[must_use]
    pub const fn binding(&self) -> &NodeBinding {
        &self.binding
    }

    /// The node key, decoded and checked.
    #[must_use]
    pub const fn node_key(&self) -> &P256PublicKey {
        &self.node_key
    }

    /// The `NodeId` of the node key.
    #[must_use]
    pub const fn node_id(&self) -> &NodeId {
        &self.node_id
    }

    /// Returns the binding this value verified, dropping the verified marker.
    #[must_use]
    pub const fn into_binding(self) -> NodeBinding {
        self.binding
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use scp_crypto::p256::{P256SecretKey, sign_prehash_rfc6979};

    use super::*;
    pub use crate::test_kel::{Identity, TestResult, incept, key};

    /// The operator identity of these tests: root `key(0x31)`, `#active`
    /// `key(1)`.
    pub fn operator() -> TestResult<Identity> {
        incept(0x31, 1, 0x33)
    }

    /// A binding for `operator` at its current head, signed by `signer` as
    /// the operator's `#active` and by `node_key`.
    pub fn signed_binding(
        operator: &Identity,
        signer: &P256SecretKey,
        node_key: &P256SecretKey,
        url: &NodeUrl,
    ) -> TestResult<NodeBinding> {
        let node_key_bytes = node_key.public_key().to_compressed();
        let url_hash = node_url_hash(url);
        let digest = NodeBinding::signing_digest(
            &operator.identifier,
            &node_key_bytes,
            &url_hash,
            &operator.head,
        );
        Ok(NodeBinding {
            operator: operator.identifier,
            node_key: node_key_bytes,
            url_hash,
            key_state_head: operator.head,
            operator_sig: sign_prehash_rfc6979(signer, &digest)?,
            possession_sig: sign_prehash_rfc6979(node_key, &digest)?,
        })
    }

    pub fn url() -> TestResult<NodeUrl> {
        Ok(NodeUrl::new("wss://node.example.com/scp/v1")?)
    }

    /// The verdict on a copy of `binding`, without the verified value.
    fn check(binding: &NodeBinding, operator: &ResolvedState) -> Result<(), NodeBindingError> {
        VerifiedNodeBinding::verify(binding.clone(), operator).map(|_| ())
    }

    #[test]
    fn a_signed_binding_verifies() -> TestResult {
        let op = operator()?;
        let binding = signed_binding(&op, &key(1), &key(2), &url()?)?;
        let verified = VerifiedNodeBinding::verify(binding, &op.resolved()?)?;
        assert_eq!(verified.node_key(), &key(2).public_key());
        Ok(())
    }

    /// The operator rotates `#active` after signing. The binding still
    /// verifies, under the key at its `key_state_head` and not the head's;
    /// the head's key signing at the old position is refused.
    #[test]
    fn the_operator_key_is_the_one_at_key_state_head() -> TestResult {
        let op = operator()?;
        let old = signed_binding(&op, &key(1), &key(2), &url()?)?;
        let rotated = op.rotate(4)?;
        let resolved = rotated.resolved()?;
        assert!(VerifiedNodeBinding::verify(old.clone(), &resolved).is_ok());
        let mut by_head_key = old;
        by_head_key.operator_sig = sign_prehash_rfc6979(&key(4), &by_head_key.digest())?;
        assert_eq!(
            check(&by_head_key, &resolved),
            Err(NodeBindingError::OperatorSignature(
                P256Error::VerificationFailed
            ))
        );
        let current = signed_binding(&rotated, &key(4), &key(2), &url()?)?;
        assert!(VerifiedNodeBinding::verify(current, &resolved).is_ok());
        Ok(())
    }

    /// Another identity's log, and a head off the operator's chain, are
    /// refused before any signature is read.
    #[test]
    fn another_identity_or_an_unknown_head_is_refused() -> TestResult {
        let op = operator()?;
        let binding = signed_binding(&op, &key(1), &key(2), &url()?)?;
        let other = incept(0x41, 1, 0x43)?.resolved()?;
        assert_eq!(
            check(&binding, &other),
            Err(NodeBindingError::OperatorKey(
                AnchoredKeyError::IdentityMismatch
            ))
        );
        let mut b = binding;
        b.key_state_head[0] ^= 1;
        assert_eq!(
            check(&b, &op.resolved()?),
            Err(NodeBindingError::OperatorKey(
                AnchoredKeyError::HeadNotOnChain
            ))
        );
        Ok(())
    }

    #[test]
    fn the_preimage_is_the_separator_and_the_four_raw_fields() -> TestResult {
        let binding = signed_binding(&operator()?, &key(1), &key(2), &url()?)?;
        let mut preimage = b"SCP-NODE-BIND-V1:".to_vec();
        preimage.extend_from_slice(binding.operator.as_bytes());
        preimage.extend_from_slice(&binding.node_key);
        preimage.extend_from_slice(&binding.url_hash);
        preimage.extend_from_slice(&binding.key_state_head);
        assert_eq!(preimage.len(), 146);
        assert_eq!(
            binding.digest(),
            <[u8; 32]>::from(Sha256::digest(&preimage))
        );
        Ok(())
    }

    /// Flipping one bit of the node key, `url_hash` or either signature makes
    /// the binding refused; `operator` and `key_state_head` are refused by
    /// [`another_identity_or_an_unknown_head_is_refused`].
    #[test]
    fn a_flip_in_each_field_is_refused() -> TestResult {
        let op = operator()?;
        let resolved = op.resolved()?;
        let good = signed_binding(&op, &key(1), &key(2), &url()?)?;

        // The flip lands in x, so the key is off the curve or another point;
        // either way the binding is refused.
        let mut b = good.clone();
        b.node_key[32] ^= 1;
        assert!(check(&b, &resolved).is_err());

        let mut b = good.clone();
        b.url_hash[0] ^= 1;
        assert!(matches!(
            check(&b, &resolved),
            Err(NodeBindingError::OperatorSignature(_))
        ));

        let mut b = good.clone();
        b.operator_sig[5] ^= 1;
        assert!(matches!(
            check(&b, &resolved),
            Err(NodeBindingError::OperatorSignature(_))
        ));

        let mut b = good;
        b.possession_sig[5] ^= 1;
        assert!(matches!(
            check(&b, &resolved),
            Err(NodeBindingError::PossessionSignature(_))
        ));
        Ok(())
    }

    #[test]
    fn an_operator_signature_under_another_key_is_refused() -> TestResult {
        let op = operator()?;
        let binding = signed_binding(&op, &key(3), &key(2), &url()?)?;
        assert_eq!(
            check(&binding, &op.resolved()?),
            Err(NodeBindingError::OperatorSignature(
                P256Error::VerificationFailed
            ))
        );
        Ok(())
    }

    /// A binding whose possession signature is the operator's own signature
    /// proves nothing about the node key's private half.
    #[test]
    fn a_possession_signature_by_the_operator_is_refused() -> TestResult {
        let op = operator()?;
        let mut binding = signed_binding(&op, &key(1), &key(2), &url()?)?;
        binding.possession_sig = binding.operator_sig;
        assert!(matches!(
            check(&binding, &op.resolved()?),
            Err(NodeBindingError::PossessionSignature(_))
        ));
        Ok(())
    }
}
