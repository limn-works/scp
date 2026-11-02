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
use scp_kel::{NodeKeyError, derive_node_id, parse_node_key};
use sha2::{Digest, Sha256};

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
    /// The two checks of §9.6.3: `operator_sig` under `operator_active`, and
    /// `possession_sig` under `node_key`, both over `P` and both strict
    /// (low-`s`, no second hash).
    ///
    /// `operator_active` is the key the operator's `#active` held at
    /// `key_state_head` on the caller's adopted chain for `operator`, the
    /// log-anchored class of §9.7.1. The caller resolves it, because that
    /// class and §9.7.1's first-seen rule read key state this type does not
    /// hold.
    ///
    /// # Errors
    ///
    /// [`NodeBindingError`] names the first check that failed, in the order
    /// node key, operator signature, possession signature.
    pub fn verify(
        binding: NodeBinding,
        operator_active: &P256PublicKey,
    ) -> Result<Self, NodeBindingError> {
        let node_key = parse_node_key(&binding.node_key)?;
        let digest = binding.digest();
        verify_prehash_strict(operator_active, &digest, &binding.operator_sig)
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
    use scp_crypto::p256::{P256SecretKey, SeedLabel, sign_prehash_rfc6979};

    use super::*;

    pub type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

    pub fn key(seed: u8) -> P256SecretKey {
        P256SecretKey::from_seed(SeedLabel::TestVectorKey, &[seed; 32])
    }

    /// A binding signed by `operator_key` and `node_key`.
    pub fn signed_binding(
        operator_key: &P256SecretKey,
        node_key: &P256SecretKey,
        url: &NodeUrl,
    ) -> TestResult<NodeBinding> {
        let operator = Identifier::from_bytes([0x11; 32]);
        let node_key_bytes = node_key.public_key().to_compressed();
        let url_hash = node_url_hash(url);
        let key_state_head = [0x22; 32];
        let digest =
            NodeBinding::signing_digest(&operator, &node_key_bytes, &url_hash, &key_state_head);
        Ok(NodeBinding {
            operator,
            node_key: node_key_bytes,
            url_hash,
            key_state_head,
            operator_sig: sign_prehash_rfc6979(operator_key, &digest)?,
            possession_sig: sign_prehash_rfc6979(node_key, &digest)?,
        })
    }

    pub fn url() -> TestResult<NodeUrl> {
        Ok(NodeUrl::new("wss://node.example.com/scp/v1")?)
    }

    /// The verdict on a copy of `binding`, without the verified value.
    fn check(
        binding: &NodeBinding,
        operator_active: &P256PublicKey,
    ) -> Result<(), NodeBindingError> {
        VerifiedNodeBinding::verify(binding.clone(), operator_active).map(|_| ())
    }

    #[test]
    fn a_signed_binding_verifies() -> TestResult {
        let operator = key(1);
        let binding = signed_binding(&operator, &key(2), &url()?)?;
        assert!(VerifiedNodeBinding::verify(binding, &operator.public_key()).is_ok());
        Ok(())
    }

    #[test]
    fn the_preimage_is_the_separator_and_the_four_raw_fields() -> TestResult {
        let binding = signed_binding(&key(1), &key(2), &url()?)?;
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

    /// Flipping one bit of any of the six fields makes the binding refused.
    #[test]
    fn a_flip_in_each_field_is_refused() -> TestResult {
        let operator = key(1);
        let active = operator.public_key();
        let good = signed_binding(&operator, &key(2), &url()?)?;

        let mut b = good.clone();
        let mut op = *b.operator.as_bytes();
        op[0] ^= 1;
        b.operator = Identifier::from_bytes(op);
        assert!(matches!(
            check(&b, &active),
            Err(NodeBindingError::OperatorSignature(_))
        ));

        // The flip lands in x, so the key is off the curve or another point;
        // either way the binding is refused.
        let mut b = good.clone();
        b.node_key[32] ^= 1;
        assert!(check(&b, &active).is_err());

        let mut b = good.clone();
        b.url_hash[0] ^= 1;
        assert!(matches!(
            check(&b, &active),
            Err(NodeBindingError::OperatorSignature(_))
        ));

        let mut b = good.clone();
        b.key_state_head[0] ^= 1;
        assert!(matches!(
            check(&b, &active),
            Err(NodeBindingError::OperatorSignature(_))
        ));

        let mut b = good.clone();
        b.operator_sig[5] ^= 1;
        assert!(matches!(
            check(&b, &active),
            Err(NodeBindingError::OperatorSignature(_))
        ));

        let mut b = good;
        b.possession_sig[5] ^= 1;
        assert!(matches!(
            check(&b, &active),
            Err(NodeBindingError::PossessionSignature(_))
        ));
        Ok(())
    }

    #[test]
    fn an_operator_signature_under_another_key_is_refused() -> TestResult {
        let binding = signed_binding(&key(1), &key(2), &url()?)?;
        assert!(matches!(
            check(&binding, &key(3).public_key()),
            Err(NodeBindingError::OperatorSignature(
                P256Error::VerificationFailed
            ))
        ));
        Ok(())
    }

    /// A binding whose possession signature is the operator's own signature
    /// proves nothing about the node key's private half.
    #[test]
    fn a_possession_signature_by_the_operator_is_refused() -> TestResult {
        let operator = key(1);
        let mut binding = signed_binding(&operator, &key(2), &url()?)?;
        binding.possession_sig = binding.operator_sig;
        assert!(matches!(
            check(&binding, &operator.public_key()),
            Err(NodeBindingError::PossessionSignature(_))
        ));
        Ok(())
    }
}
