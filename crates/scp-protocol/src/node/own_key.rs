//! A node's own node key and its installed binding (`09-security-model.md`
//! §9.6.3 "How a node gets its key and its binding"; §9.7.4.2 "The node
//! proof of control").
//!
//! - [`NodeSigningKey`] is the private half a node draws on its first start
//!   and keeps in its instance storage. It signs a binding's
//!   `possession_sig` only over a `P` that carries its own `node_key`
//!   ([`NodeSigningKey::sign_possession`]), and the node reaches that
//!   function only through a local operator command.
//! - [`BoundNodeKey`] is that key together with the `NodeBinding` its
//!   operator installed. [`NodeSigningKey::install`] is its only
//!   constructor, and it refuses a binding for another key, a
//!   `possession_sig` that fails under the key, and a `url_hash` other than
//!   the configured canonical URL's. A `BoundNodeKey` signs node proofs.

use scp_crypto::p256::{P256Error, P256SecretKey, SIGNATURE_LEN, sign_prehash_rfc6979};
use scp_did::{Identifier, NodeId, NodeUrl};
use scp_kel::{NodeKeyError, derive_node_id};
use zeroize::Zeroizing;

use super::binding::{NODE_KEY_LEN, NodeBinding, node_url_hash};
use super::proof::{NodeProof, NodeProofError, SentQuery};

/// Why a node key cannot be loaded or cannot sign.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum NodeSigningKeyError {
    /// The stored scalar is zero or not below the P-256 group order.
    #[error("node key scalar: {0}")]
    Scalar(P256Error),
    /// The public half does not name a `NodeId`.
    #[error("node key: {0}")]
    NodeId(#[from] NodeKeyError),
    /// Signing failed.
    #[error("node key signature: {0}")]
    Sign(P256Error),
}

/// Why a node refuses to start with an installed binding (§9.6.3,
/// installation step).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NodeBindingInstallError {
    /// `binding.node_key` is not this node's key.
    #[error("the installed binding binds another node key, not this node's")]
    ForeignNodeKey,
    /// `possession_sig` does not verify under this node's key over `P`.
    #[error("the installed binding's possession signature: {0}")]
    PossessionSignature(P256Error),
    /// `url_hash` is not the SHA-256 of the configured canonical URL.
    #[error("the installed binding's url_hash is not the SHA-256 of the configured URL {}", .0.as_str())]
    UrlMismatch(NodeUrl),
}

/// The private half of a node's node key (§9.6.3 step 1). The scalar is
/// wiped when the value drops; the type has no `Clone` and no serializer.
#[derive(Debug)]
pub struct NodeSigningKey {
    secret: P256SecretKey,
    node_key: [u8; NODE_KEY_LEN],
    node_id: NodeId,
}

impl NodeSigningKey {
    /// Draws a fresh node key from `rng`.
    ///
    /// # Errors
    ///
    /// [`NodeSigningKeyError::NodeId`] when the drawn point names no
    /// `NodeId`.
    pub fn generate(
        rng: &mut (impl rand::RngCore + rand::CryptoRng),
    ) -> Result<Self, NodeSigningKeyError> {
        Self::from_secret(P256SecretKey::random(rng))
    }

    /// Loads the node key from its stored 32-byte scalar.
    ///
    /// # Errors
    ///
    /// [`NodeSigningKeyError::Scalar`] for a scalar that is no P-256 key.
    pub fn from_scalar_bytes(scalar: &[u8; 32]) -> Result<Self, NodeSigningKeyError> {
        Self::from_secret(
            P256SecretKey::from_scalar_bytes(scalar).map_err(NodeSigningKeyError::Scalar)?,
        )
    }

    fn from_secret(secret: P256SecretKey) -> Result<Self, NodeSigningKeyError> {
        let node_key = secret.public_key().to_compressed();
        let node_id = derive_node_id(&node_key)?;
        Ok(Self {
            secret,
            node_key,
            node_id,
        })
    }

    /// The 32-byte scalar, for the node's own storage only.
    #[must_use]
    pub fn to_scalar_bytes(&self) -> Zeroizing<[u8; 32]> {
        self.secret.to_scalar_bytes()
    }

    /// The public node key, 33-byte compressed SEC1.
    #[must_use]
    pub const fn node_key(&self) -> &[u8; NODE_KEY_LEN] {
        &self.node_key
    }

    /// The `NodeId` of the node key.
    #[must_use]
    pub const fn node_id(&self) -> &NodeId {
        &self.node_id
    }

    /// `possession_sig` over `P` for `operator`, `url_hash` and
    /// `key_state_head`, with this key's own `node_key` in `P`, so the key
    /// signs no binding of another key (§9.6.3 step 2).
    ///
    /// # Errors
    ///
    /// [`NodeSigningKeyError::Sign`] when signing fails.
    pub fn sign_possession(
        &self,
        operator: &Identifier,
        url_hash: &[u8; 32],
        key_state_head: &[u8; 32],
    ) -> Result<[u8; SIGNATURE_LEN], NodeSigningKeyError> {
        let digest =
            NodeBinding::signing_digest(operator, &self.node_key, url_hash, key_state_head);
        sign_prehash_rfc6979(&self.secret, &digest).map_err(NodeSigningKeyError::Sign)
    }

    /// Signs a node proof's digest. [`NodeProof::sign`] is the caller.
    pub(crate) fn sign_digest(&self, digest: &[u8; 32]) -> Result<[u8; SIGNATURE_LEN], P256Error> {
        sign_prehash_rfc6979(&self.secret, digest)
    }

    /// The installation checks of §9.6.3 step 4: `binding.node_key` is this
    /// key, `possession_sig` verifies under it over `P`, and `url_hash` is
    /// the SHA-256 of `url`. The node does not check `operator_sig`, which a
    /// party checks against the operator's key-event log.
    ///
    /// # Errors
    ///
    /// [`NodeBindingInstallError`] names the first check that failed, in
    /// that order.
    pub fn install(
        self,
        binding: NodeBinding,
        url: &NodeUrl,
    ) -> Result<BoundNodeKey, NodeBindingInstallError> {
        if binding.node_key != self.node_key {
            return Err(NodeBindingInstallError::ForeignNodeKey);
        }
        scp_crypto::p256::verify_prehash_strict(
            &self.secret.public_key(),
            &binding.digest(),
            &binding.possession_sig,
        )
        .map_err(NodeBindingInstallError::PossessionSignature)?;
        if binding.url_hash != node_url_hash(url) {
            return Err(NodeBindingInstallError::UrlMismatch(url.clone()));
        }
        Ok(BoundNodeKey { key: self, binding })
    }
}

/// A node key with the binding its operator installed (§9.6.3 step 4).
/// [`NodeSigningKey::install`] is the only constructor.
///
/// This is the only form of the node key a transport holds, and it signs node
/// proofs and nothing else: it cannot sign a binding's P, so no wire message
/// can make a node sign `possession_sig` (§9.6.3 step 2).
///
/// ```compile_fail,E0599
/// fn sign(bound: &scp_protocol::node::BoundNodeKey) {
///     let operator = scp_did::Identifier::from_bytes([0; 32]);
///     let _ = bound.sign_possession(&operator, &[0; 32], &[0; 32]);
/// }
/// ```
///
/// The same call on a [`NodeSigningKey`] compiles:
///
/// ```
/// fn sign(key: &scp_protocol::node::NodeSigningKey) {
///     let operator = scp_did::Identifier::from_bytes([0; 32]);
///     let _ = key.sign_possession(&operator, &[0; 32], &[0; 32]);
/// }
/// ```
#[derive(Debug)]
pub struct BoundNodeKey {
    key: NodeSigningKey,
    binding: NodeBinding,
}

impl BoundNodeKey {
    /// The installed binding.
    #[must_use]
    pub const fn binding(&self) -> &NodeBinding {
        &self.binding
    }

    /// The `NodeId` every proof names.
    #[must_use]
    pub const fn node_id(&self) -> &NodeId {
        self.key.node_id()
    }

    /// The node proof over one QUERY response (§9.7.4.2): `query` the
    /// QUERY as received, whose nonce the proof echoes and whose fields it
    /// digests, `value_digest` from [`super::response_value_digest`] over
    /// the blobs returned, and the node's clock `observed_at` in seconds.
    ///
    /// This is the only signer of a node proof outside this crate:
    ///
    /// ```
    /// fn prove(
    ///     bound: &scp_protocol::node::BoundNodeKey,
    ///     query: &scp_protocol::node::SentQuery,
    /// ) {
    ///     let _ = bound.prove(query, [0; 32], 0);
    /// }
    /// ```
    ///
    /// # Errors
    ///
    /// [`NodeProofError::Sign`] when signing fails.
    pub fn prove(
        &self,
        query: &SentQuery,
        value_digest: [u8; 32],
        observed_at: u64,
    ) -> Result<NodeProof, NodeProofError> {
        NodeProof::sign(&self.key, query, value_digest, observed_at)
    }
}

#[cfg(test)]
mod tests {
    use scp_crypto::p256::P256SecretKey;

    use super::super::binding::VerifiedNodeBinding;
    use super::super::binding::tests::{TestResult, key, operator, signed_binding, url};
    use super::super::response_value_digest;
    use super::*;

    fn own(seed: u8) -> TestResult<(NodeSigningKey, P256SecretKey)> {
        let secret = key(seed);
        Ok((
            NodeSigningKey::from_scalar_bytes(&secret.to_scalar_bytes())?,
            secret,
        ))
    }

    /// The operator's half: the node's `node_key` and `possession_sig` from
    /// the local command, then `operator_sig` from the operator's key.
    fn operator_binding(node: &NodeSigningKey, url: &NodeUrl) -> TestResult<NodeBinding> {
        let op = operator()?;
        let url_hash = node_url_hash(url);
        let possession_sig = node.sign_possession(&op.identifier, &url_hash, &op.head)?;
        let mut binding = NodeBinding {
            operator: op.identifier,
            node_key: *node.node_key(),
            url_hash,
            key_state_head: op.head,
            operator_sig: [0; SIGNATURE_LEN],
            possession_sig,
        };
        binding.operator_sig = sign_prehash_rfc6979(&key(1), &binding.digest())?;
        Ok(binding)
    }

    fn query() -> SentQuery {
        SentQuery {
            nonce: [9; 32],
            routing_id: [3; 32],
            since: None,
            after_blob: None,
            limit: Some(10),
        }
    }

    /// The possession signature the local command returns makes a binding a
    /// party verifies, and the proof the bound key signs verifies under it
    /// against the QUERY it answered.
    #[test]
    fn the_proof_verifies_under_the_binding_key() -> TestResult {
        let (node, _) = own(7)?;
        let binding = operator_binding(&node, &url()?)?;
        let verified = VerifiedNodeBinding::verify(binding.clone(), &operator()?.resolved()?)?;
        let bound = node.install(binding, &url()?)?;
        let blobs = [b"a".as_slice()];
        let digest = response_value_digest(&blobs)?;
        let proof = bound.prove(&query(), digest, 1_700_000_000)?;
        assert_eq!(
            proof.verify(&verified, &query(), &blobs, 1_700_000_000, 0),
            Ok(())
        );
        assert_eq!(&proof.node_id, verified.node_id());
        Ok(())
    }

    /// A proof whose echoed nonce is altered fails the nonce check, and a
    /// proof whose nonce was altered and re-matched fails the signature.
    #[test]
    fn a_wrong_nonce_fails() -> TestResult {
        let (node, _) = own(7)?;
        let binding = operator_binding(&node, &url()?)?;
        let verified = VerifiedNodeBinding::verify(binding.clone(), &operator()?.resolved()?)?;
        let bound = node.install(binding, &url()?)?;
        let blobs: [&[u8]; 0] = [];
        let mut proof = bound.prove(&query(), response_value_digest(&blobs)?, 5)?;
        proof.nonce = [8; 32];
        assert_eq!(
            proof.verify(&verified, &query(), &blobs, 5, 0),
            Err(NodeProofError::NonceMismatch)
        );
        let resent = SentQuery {
            nonce: [8; 32],
            ..query()
        };
        proof.query_digest = resent.digest();
        assert_eq!(
            proof.verify(&verified, &resent, &blobs, 5, 0),
            Err(NodeProofError::Signature(P256Error::VerificationFailed))
        );
        Ok(())
    }

    #[test]
    fn a_binding_for_another_key_is_refused() -> TestResult {
        let (node, _) = own(7)?;
        let op = operator()?;
        let foreign = signed_binding(&op, &key(1), &key(8), &url()?)?;
        assert_eq!(
            node.install(foreign, &url()?).map(|_| ()),
            Err(NodeBindingInstallError::ForeignNodeKey)
        );
        Ok(())
    }

    #[test]
    fn a_bad_possession_signature_is_refused() -> TestResult {
        let (node, _) = own(7)?;
        let mut binding = operator_binding(&node, &url()?)?;
        binding.possession_sig = binding.operator_sig;
        assert!(matches!(
            node.install(binding, &url()?),
            Err(NodeBindingInstallError::PossessionSignature(_))
        ));
        Ok(())
    }

    #[test]
    fn a_binding_for_another_url_is_refused() -> TestResult {
        let (node, _) = own(7)?;
        let binding = operator_binding(&node, &url()?)?;
        let other = NodeUrl::new("wss://other.example.com/scp/v1")?;
        assert_eq!(
            node.install(binding, &other).map(|_| ()),
            Err(NodeBindingInstallError::UrlMismatch(other))
        );
        Ok(())
    }

    /// The stored scalar loads the same key: same `node_key`, same
    /// `NodeId`.
    #[test]
    fn the_scalar_round_trips() -> TestResult {
        let (node, secret) = own(7)?;
        let back = NodeSigningKey::from_scalar_bytes(&node.to_scalar_bytes())?;
        assert_eq!(back.node_key(), &secret.public_key().to_compressed());
        assert_eq!(back.node_id(), node.node_id());
        assert_eq!(
            NodeSigningKey::from_scalar_bytes(&[0; 32]).map(|_| ()),
            Err(NodeSigningKeyError::Scalar(P256Error::InvalidScalar))
        );
        Ok(())
    }
}
