//! The node proof of control (`09-security-model.md` §9.7.4.2 definitions,
//! "The node proof of control"; §9.18.2 `"SCP-NODE-PROOF-V1:"`; spec 25
//! §25.27 Vector 44 and §25.23 Vector 80).
//!
//! A listed node signs, under its node key, that it served one QUERY
//! response:
//!
//! ```text
//! SHA-256("SCP-NODE-PROOF-V1:" ‖ node_id ‖ nonce ‖ routing_id ‖ value_digest ‖ observed_at)
//! ```
//!
//! The five fields are fixed width, 136 bytes in all, so §9.5.1 writes each
//! raw and the 18-byte separator makes a 154-byte preimage. The object on the
//! wire is the 136 field bytes followed by the 64-byte signature, 200 bytes.

use scp_crypto::p256::{P256Error, SIGNATURE_LEN, verify_prehash_strict};
use scp_did::NodeId;
use sha2::{Digest, Sha256};

use super::binding::VerifiedNodeBinding;
use crate::crypto::canonical::{CanonicalError, CanonicalField, canonical_hash};

/// The §9.18.2 separator of the node-proof preimage.
pub const NODE_PROOF_SEPARATOR: &str = "SCP-NODE-PROOF-V1:";

/// The five fields' width: 32 + 32 + 32 + 32 + 8.
pub const NODE_PROOF_FIELDS_LEN: usize = 136;

/// The object's width on the wire: the fields and one signature.
pub const NODE_PROOF_LEN: usize = NODE_PROOF_FIELDS_LEN + SIGNATURE_LEN;

/// One node's signed statement that it served a QUERY response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeProof {
    /// The `NodeId` of the serving node's key.
    pub node_id: NodeId,
    /// The requester's nonce, echoed verbatim from the QUERY.
    pub nonce: [u8; 32],
    /// The routing id served.
    pub routing_id: [u8; 32],
    /// [`response_value_digest`] over the blobs in the order the node
    /// returned them.
    pub value_digest: [u8; 32],
    /// The node's own clock, seconds.
    pub observed_at: u64,
    /// The node key's signature over the preimage.
    pub signature: [u8; SIGNATURE_LEN],
}

/// Why a node proof is refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NodeProofError {
    /// The bytes are not exactly [`NODE_PROOF_LEN`] long.
    #[error("node proof is {0} bytes, expected 200")]
    WrongLength(usize),
    /// The proof names a `NodeId` other than the binding's.
    #[error("node proof names another node")]
    NodeIdMismatch,
    /// The signature does not verify under the supplied key.
    #[error("node proof signature: {0}")]
    Signature(P256Error),
    /// The response carries more blobs, or a longer blob, than §9.5.1's
    /// 4-byte counts encode.
    #[error("node proof response: {0}")]
    Response(#[from] CanonicalError),
    /// The response carries more than `u32::MAX` blobs.
    #[error("node proof response holds {0} blobs, more than a 4-byte count encodes")]
    TooManyBlobs(usize),
}

/// `value_digest` over a QUERY response.
///
/// It is `SHA-256(BE32(count) ‖ (BE32(len) ‖ blob)*)`, §9.5.1's repeated-field rule over the blobs in the order the
/// node returned them, so one digest names one split of the bytes into blobs.
///
/// # Errors
///
/// [`NodeProofError::TooManyBlobs`] or [`NodeProofError::Response`] when a
/// count or a length exceeds 4 bytes.
pub fn response_value_digest<B: AsRef<[u8]>>(blobs: &[B]) -> Result<[u8; 32], NodeProofError> {
    let count =
        u32::try_from(blobs.len()).map_err(|_| NodeProofError::TooManyBlobs(blobs.len()))?;
    let mut fields = Vec::with_capacity(blobs.len() + 1);
    fields.push(CanonicalField::U32(count));
    fields.extend(blobs.iter().map(|b| CanonicalField::VarBytes(b.as_ref())));
    Ok(canonical_hash("", &fields)?)
}

impl NodeProof {
    /// The digest the node key signs.
    #[must_use]
    pub fn signing_digest(
        node_id: &NodeId,
        nonce: &[u8; 32],
        routing_id: &[u8; 32],
        value_digest: &[u8; 32],
        observed_at: u64,
    ) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(NODE_PROOF_SEPARATOR.as_bytes());
        hasher.update(node_id.as_bytes());
        hasher.update(nonce);
        hasher.update(routing_id);
        hasher.update(value_digest);
        hasher.update(observed_at.to_be_bytes());
        hasher.finalize().into()
    }

    /// The digest over this proof's five fields.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        Self::signing_digest(
            &self.node_id,
            &self.nonce,
            &self.routing_id,
            &self.value_digest,
            self.observed_at,
        )
    }

    /// The 200 wire bytes: the five fields in preimage order, then the
    /// signature.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; NODE_PROOF_LEN] {
        let mut out = [0u8; NODE_PROOF_LEN];
        out[..32].copy_from_slice(self.node_id.as_bytes());
        out[32..64].copy_from_slice(&self.nonce);
        out[64..96].copy_from_slice(&self.routing_id);
        out[96..128].copy_from_slice(&self.value_digest);
        out[128..136].copy_from_slice(&self.observed_at.to_be_bytes());
        out[136..].copy_from_slice(&self.signature);
        out
    }

    /// Reads exactly 200 bytes.
    ///
    /// # Errors
    ///
    /// [`NodeProofError::WrongLength`] for any other length.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, NodeProofError> {
        let bytes: &[u8; NODE_PROOF_LEN] = bytes
            .try_into()
            .map_err(|_| NodeProofError::WrongLength(bytes.len()))?;
        let (fields, signature) = bytes.split_at(NODE_PROOF_FIELDS_LEN);
        let mut node_id = [0u8; 32];
        let mut nonce = [0u8; 32];
        let mut routing_id = [0u8; 32];
        let mut value_digest = [0u8; 32];
        let mut observed_at = [0u8; 8];
        let mut sig = [0u8; SIGNATURE_LEN];
        node_id.copy_from_slice(&fields[..32]);
        nonce.copy_from_slice(&fields[32..64]);
        routing_id.copy_from_slice(&fields[64..96]);
        value_digest.copy_from_slice(&fields[96..128]);
        observed_at.copy_from_slice(&fields[128..136]);
        sig.copy_from_slice(signature);
        Ok(Self {
            node_id: NodeId::from_bytes(node_id),
            nonce,
            routing_id,
            value_digest,
            observed_at: u64::from_be_bytes(observed_at),
            signature: sig,
        })
    }

    /// Checks that `binding`'s `NodeId` is the proof's `node_id`, and that the
    /// signature verifies strictly under `binding`'s node key.
    ///
    /// `binding` is the verified `NodeBinding` whose `NodeId` the proof names
    /// (§9.7.1 bound-node-key class); the caller holds it attributed by a
    /// verified node-list record (§9.6.3). The resolver's other checks
    /// (standing, the echoed nonce, the queried routing id, the value digest
    /// over the bytes received, and `observed_at` within the clock-skew
    /// tolerance) read state this type does not hold, so the caller makes
    /// them.
    ///
    /// # Errors
    ///
    /// [`NodeProofError::NodeIdMismatch`] or [`NodeProofError::Signature`].
    pub fn verify_signature(&self, binding: &VerifiedNodeBinding) -> Result<(), NodeProofError> {
        if *binding.node_id() != self.node_id {
            return Err(NodeProofError::NodeIdMismatch);
        }
        verify_prehash_strict(binding.node_key(), &self.digest(), &self.signature)
            .map_err(NodeProofError::Signature)
    }
}

#[cfg(test)]
mod tests {
    use scp_crypto::p256::{P256SecretKey, sign_prehash_rfc6979};
    use scp_kel::derive_node_id;

    use super::super::binding::tests::{TestResult, key, operator, signed_binding, url};
    use super::*;

    /// The verified binding of `node` under the test operator.
    fn bound(node: &P256SecretKey) -> TestResult<VerifiedNodeBinding> {
        let operator = operator()?;
        Ok(VerifiedNodeBinding::verify(
            signed_binding(&operator, &key(1), node, &url()?)?,
            &operator.chain()?,
        )?)
    }

    fn signed_proof(node: &P256SecretKey) -> TestResult<NodeProof> {
        let node_id = derive_node_id(&node.public_key().to_compressed())?;
        let value_digest = response_value_digest(&[b"a".as_slice(), b"bb"])?;
        let digest = NodeProof::signing_digest(&node_id, &[1; 32], &[2; 32], &value_digest, 7);
        Ok(NodeProof {
            node_id,
            nonce: [1; 32],
            routing_id: [2; 32],
            value_digest,
            observed_at: 7,
            signature: sign_prehash_rfc6979(node, &digest)?,
        })
    }

    #[test]
    fn the_preimage_is_154_bytes_and_the_object_200() -> TestResult {
        let proof = signed_proof(&key(1))?;
        let mut preimage = b"SCP-NODE-PROOF-V1:".to_vec();
        preimage.extend_from_slice(&proof.to_bytes()[..NODE_PROOF_FIELDS_LEN]);
        assert_eq!(preimage.len(), 154);
        assert_eq!(proof.digest(), <[u8; 32]>::from(Sha256::digest(&preimage)));
        assert_eq!(proof.to_bytes().len(), 200);
        Ok(())
    }

    #[test]
    fn a_proof_round_trips_and_verifies() -> TestResult {
        let node = key(1);
        let proof = signed_proof(&node)?;
        let back = NodeProof::from_bytes(&proof.to_bytes())?;
        assert_eq!(back, proof);
        assert_eq!(back.verify_signature(&bound(&node)?), Ok(()));
        Ok(())
    }

    #[test]
    fn from_bytes_refuses_any_other_length() -> TestResult {
        let bytes = signed_proof(&key(1))?.to_bytes();
        assert_eq!(
            NodeProof::from_bytes(&bytes[..199]),
            Err(NodeProofError::WrongLength(199))
        );
        let mut long = bytes.to_vec();
        long.push(0);
        assert_eq!(
            NodeProof::from_bytes(&long),
            Err(NodeProofError::WrongLength(201))
        );
        Ok(())
    }

    /// A flip in any of the 200 bytes makes the proof refused.
    #[test]
    fn a_flip_in_any_byte_is_refused() -> TestResult {
        let node = key(1);
        let binding = bound(&node)?;
        let bytes = signed_proof(&node)?.to_bytes();
        for i in 0..NODE_PROOF_LEN {
            let mut flipped = bytes;
            flipped[i] ^= 1;
            let proof = NodeProof::from_bytes(&flipped)?;
            assert!(proof.verify_signature(&binding).is_err(), "byte {i}");
        }
        Ok(())
    }

    #[test]
    fn a_proof_checked_under_another_node_key_is_refused() -> TestResult {
        let proof = signed_proof(&key(1))?;
        assert_eq!(
            proof.verify_signature(&bound(&key(2))?),
            Err(NodeProofError::NodeIdMismatch)
        );
        Ok(())
    }

    #[test]
    fn the_value_digest_separates_blob_boundaries() -> TestResult {
        let one = response_value_digest(&[b"ab".as_slice(), b"c"])?;
        let two = response_value_digest(&[b"a".as_slice(), b"bc"])?;
        let joined = response_value_digest(&[b"abc".as_slice()])?;
        assert_ne!(one, two);
        assert_ne!(one, joined);
        let mut expected = Vec::new();
        expected.extend_from_slice(&2u32.to_be_bytes());
        expected.extend_from_slice(&2u32.to_be_bytes());
        expected.extend_from_slice(b"ab");
        expected.extend_from_slice(&1u32.to_be_bytes());
        expected.extend_from_slice(b"c");
        assert_eq!(one, <[u8; 32]>::from(Sha256::digest(&expected)));
        Ok(())
    }
}
