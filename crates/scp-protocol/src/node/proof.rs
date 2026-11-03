//! The node proof of control.
//!
//! Sources: `09-security-model.md` §9.7.4.2 definitions, "The node proof of
//! control" and "The query digest"; §9.10.12; §9.18.2 `"SCP-NODE-PROOF-V1:"`
//! and `"SCP-NODE-QUERY-V1:"`; spec 25 §25.27 Vector 44 and §25.23 Vector 80.
//!
//! A listed node signs, under its node key, that it served one QUERY
//! response:
//!
//! ```text
//! SHA-256("SCP-NODE-PROOF-V1:" ‖ node_id ‖ nonce ‖ routing_id ‖ query_digest ‖ value_digest ‖ observed_at)
//! ```
//!
//! The six fields are fixed width, 168 bytes in all, so §9.5.1 writes each
//! raw and the 18-byte separator makes a 186-byte preimage. The object on the
//! wire is the 168 field bytes followed by the 64-byte signature, 232 bytes.
//!
//! `query_digest` binds the proof to the page the resolver asked for
//! ([`SentQuery::digest`]), so a proof over the empty page a rewritten
//! `since` returns does not verify against the QUERY the resolver sent.
//!
//! [`NodeProof::verify`] is the only public check, and makes all six of the
//! resolver's checks (§9.7.4.2 definitions). Only
//! [`BoundNodeKey::prove`](super::BoundNodeKey::prove) signs a proof:
//!
//! ```compile_fail,E0624
//! fn forge(key: &scp_protocol::node::NodeSigningKey, query: &scp_protocol::node::SentQuery) {
//!     let _ = scp_protocol::node::NodeProof::sign(key, query, [0; 32], 0);
//! }
//! ```

use scp_crypto::p256::{P256Error, SIGNATURE_LEN, verify_prehash_strict};
use scp_did::NodeId;
use serde::de::{self, Deserializer, Visitor};
use serde::{Deserialize, Serialize, Serializer};
use sha2::{Digest, Sha256};

use super::binding::VerifiedNodeBinding;
use super::own_key::NodeSigningKey;
use crate::crypto::canonical::{CanonicalError, CanonicalField, canonical_hash};

/// The §9.18.2 separator of the node-proof preimage.
pub const NODE_PROOF_SEPARATOR: &str = "SCP-NODE-PROOF-V1:";

/// The §9.18.2 domain of the query digest a node proof carries.
pub const NODE_QUERY_SEPARATOR: &str = "SCP-NODE-QUERY-V1:";

/// The six fields' width: 32 + 32 + 32 + 32 + 32 + 8.
pub const NODE_PROOF_FIELDS_LEN: usize = 168;

/// The object's width on the wire: the fields and one signature.
pub const NODE_PROOF_LEN: usize = NODE_PROOF_FIELDS_LEN + SIGNATURE_LEN;

/// The QUERY a resolver sent and a node answered: the fields a node proof
/// echoes or digests (§9.7.4.2 definitions; ADR-004 operation 4).
///
/// A resolver builds it from the QUERY it sent and passes it to
/// [`NodeProof::verify`]; a node builds it from the QUERY it received and
/// signs over it. Each optional field is as the QUERY carried it: an omitted
/// `limit` is `None`, never the node's default of 100.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SentQuery {
    /// The QUERY's `proof_nonce`.
    pub nonce: [u8; 32],
    /// The QUERY's `routing_id`.
    pub routing_id: [u8; 32],
    /// The QUERY's `since`.
    pub since: Option<u64>,
    /// The QUERY's `after_blob` cursor.
    pub after_blob: Option<[u8; 32]>,
    /// The QUERY's `limit`.
    pub limit: Option<u32>,
}

impl SentQuery {
    /// The query digest (§9.7.4.2 definitions):
    /// `SHA-256("SCP-NODE-QUERY-V1:" ‖ routing_id ‖ since ‖ after_blob ‖
    /// limit)`, each optional field `0x00` where absent, or `0x01` followed
    /// by `BE64(since)`, the 32 bytes of `after_blob`, or `BE32(limit)`.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(NODE_QUERY_SEPARATOR.as_bytes());
        hasher.update(self.routing_id);
        match self.since {
            None => hasher.update([0x00]),
            Some(since) => {
                hasher.update([0x01]);
                hasher.update(since.to_be_bytes());
            }
        }
        match self.after_blob {
            None => hasher.update([0x00]),
            Some(after_blob) => {
                hasher.update([0x01]);
                hasher.update(after_blob);
            }
        }
        match self.limit {
            None => hasher.update([0x00]),
            Some(limit) => {
                hasher.update([0x01]);
                hasher.update(limit.to_be_bytes());
            }
        }
        hasher.finalize().into()
    }
}

/// One node's signed statement that it served a QUERY response.
///
/// On the wire it is one `MessagePack` `bin` of exactly [`NODE_PROOF_LEN`]
/// bytes (ADR-004 `EVENT`, `node_proof: bin232?`); its `Deserialize` refuses
/// any other width, so a decoded proof is always a whole one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeProof {
    /// The `NodeId` of the serving node's key.
    pub node_id: NodeId,
    /// The requester's nonce, echoed verbatim from the QUERY.
    pub nonce: [u8; 32],
    /// The routing id served.
    pub routing_id: [u8; 32],
    /// [`SentQuery::digest`] of the QUERY the node answered.
    pub query_digest: [u8; 32],
    /// [`response_value_digest`] over the blobs in the order the node
    /// returned them.
    pub value_digest: [u8; 32],
    /// The node's own clock, seconds.
    pub observed_at: u64,
    /// The node key's signature over the preimage.
    pub signature: [u8; SIGNATURE_LEN],
}

/// Why a node proof is refused, one variant per check of §9.7.4.2's
/// definitions, or why one could not be built.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NodeProofError {
    /// The proof names a `NodeId` other than the binding's.
    #[error("node proof names another node")]
    NodeIdMismatch,
    /// The echoed nonce is not the one the resolver sent.
    #[error("node proof echoes another nonce")]
    NonceMismatch,
    /// The routing id is not the one the resolver queried.
    #[error("node proof covers another routing id")]
    RoutingIdMismatch,
    /// The query digest is not the digest of the QUERY the resolver sent.
    #[error("node proof answers another query")]
    QueryDigestMismatch,
    /// The value digest is not the digest of the blobs received.
    #[error("node proof covers other bytes than those received")]
    ValueDigestMismatch,
    /// `observed_at` is outside the clock-skew tolerance of the resolver's
    /// clock.
    #[error("node proof observed at {observed_at}, outside {skew}s of {now}")]
    ObservedAtOutOfSkew {
        /// The proof's `observed_at`.
        observed_at: u64,
        /// The resolver's clock.
        now: u64,
        /// The tolerance applied, seconds.
        skew: u64,
    },
    /// The signature does not verify under the binding's node key.
    #[error("node proof signature: {0}")]
    Signature(P256Error),
    /// The response carries more blobs, or a longer blob, than §9.5.1's
    /// 4-byte counts encode.
    #[error("node proof response: {0}")]
    Response(#[from] CanonicalError),
    /// The node key could not sign the proof.
    #[error("node proof signing: {0}")]
    Sign(P256Error),
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
    /// Signs the proof of one QUERY response under the node's own key
    /// (§9.7.4.2): `node_id` is `key`'s, `nonce` and `routing_id` the
    /// QUERY's, `query_digest` [`SentQuery::digest`] of the QUERY received,
    /// `value_digest` from [`response_value_digest`] over the blobs in the
    /// order the node returned them, and `observed_at` the node's clock in
    /// seconds.
    ///
    /// Crate-private: a node signs only through
    /// [`BoundNodeKey::prove`](super::BoundNodeKey::prove), which holds the
    /// key together with the binding its operator installed.
    ///
    /// # Errors
    ///
    /// [`NodeProofError::Sign`] when signing fails.
    pub(crate) fn sign(
        key: &NodeSigningKey,
        query: &SentQuery,
        value_digest: [u8; 32],
        observed_at: u64,
    ) -> Result<Self, NodeProofError> {
        let mut proof = Self {
            node_id: *key.node_id(),
            nonce: query.nonce,
            routing_id: query.routing_id,
            query_digest: query.digest(),
            value_digest,
            observed_at,
            signature: [0; SIGNATURE_LEN],
        };
        proof.signature = key
            .sign_digest(&proof.digest())
            .map_err(NodeProofError::Sign)?;
        Ok(proof)
    }

    /// The digest the node key signs, over this proof's six fields.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(NODE_PROOF_SEPARATOR.as_bytes());
        hasher.update(self.node_id.as_bytes());
        hasher.update(self.nonce);
        hasher.update(self.routing_id);
        hasher.update(self.query_digest);
        hasher.update(self.value_digest);
        hasher.update(self.observed_at.to_be_bytes());
        hasher.finalize().into()
    }

    /// The 232 wire bytes: the six fields in preimage order, then the
    /// signature.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; NODE_PROOF_LEN] {
        let mut out = [0u8; NODE_PROOF_LEN];
        out[..32].copy_from_slice(self.node_id.as_bytes());
        out[32..64].copy_from_slice(&self.nonce);
        out[64..96].copy_from_slice(&self.routing_id);
        out[96..128].copy_from_slice(&self.query_digest);
        out[128..160].copy_from_slice(&self.value_digest);
        out[160..168].copy_from_slice(&self.observed_at.to_be_bytes());
        out[168..].copy_from_slice(&self.signature);
        out
    }

    /// Reads the 232 wire bytes. Every split of the fixed width is a proof,
    /// so the read cannot fail; [`Self::verify`] decides whether it holds.
    #[must_use]
    pub fn from_bytes(bytes: &[u8; NODE_PROOF_LEN]) -> Self {
        let field = |at: usize| -> [u8; 32] {
            let mut out = [0u8; 32];
            out.copy_from_slice(&bytes[at..at + 32]);
            out
        };
        let mut observed_at = [0u8; 8];
        observed_at.copy_from_slice(&bytes[160..168]);
        let mut signature = [0u8; SIGNATURE_LEN];
        signature.copy_from_slice(&bytes[NODE_PROOF_FIELDS_LEN..]);
        Self {
            node_id: NodeId::from_bytes(field(0)),
            nonce: field(32),
            routing_id: field(64),
            query_digest: field(96),
            value_digest: field(128),
            observed_at: u64::from_be_bytes(observed_at),
            signature,
        }
    }

    /// The resolver's checks (§9.7.4.2 definitions), in this order: the
    /// proof names `binding`'s `NodeId`; it echoes `sent`'s nonce; it covers
    /// `sent`'s routing id; its query digest is `sent`'s; its value digest
    /// is [`response_value_digest`] over `blobs`, the blobs received in the
    /// order received; `observed_at` is within `skew` seconds of `now`; and
    /// the signature verifies strictly under `binding`'s node key.
    ///
    /// `binding` is the verified `NodeBinding` of the node the resolver
    /// queried (§9.7.1 bound-node-key class), attributed by a verified
    /// node-list record (§9.6.3). Standing, whether that entry stands in the
    /// resolver's accepted list, is the one check this type cannot make,
    /// because it reads the resolver's list.
    ///
    /// # Errors
    ///
    /// The [`NodeProofError`] variant of the first check that fails, or
    /// [`NodeProofError::TooManyBlobs`] / [`NodeProofError::Response`] when
    /// `blobs` exceeds §9.5.1's counts.
    pub fn verify<B: AsRef<[u8]>>(
        &self,
        binding: &VerifiedNodeBinding,
        sent: &SentQuery,
        blobs: &[B],
        now: u64,
        skew: u64,
    ) -> Result<(), NodeProofError> {
        if *binding.node_id() != self.node_id {
            return Err(NodeProofError::NodeIdMismatch);
        }
        if self.nonce != sent.nonce {
            return Err(NodeProofError::NonceMismatch);
        }
        if self.routing_id != sent.routing_id {
            return Err(NodeProofError::RoutingIdMismatch);
        }
        if self.query_digest != sent.digest() {
            return Err(NodeProofError::QueryDigestMismatch);
        }
        if self.value_digest != response_value_digest(blobs)? {
            return Err(NodeProofError::ValueDigestMismatch);
        }
        if self.observed_at.abs_diff(now) > skew {
            return Err(NodeProofError::ObservedAtOutOfSkew {
                observed_at: self.observed_at,
                now,
                skew,
            });
        }
        self.verify_signature(binding)
    }

    /// The signature check alone, which [`Self::verify`] makes last.
    fn verify_signature(&self, binding: &VerifiedNodeBinding) -> Result<(), NodeProofError> {
        verify_prehash_strict(binding.node_key(), &self.digest(), &self.signature)
            .map_err(NodeProofError::Signature)
    }
}

impl Serialize for NodeProof {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(&self.to_bytes())
    }
}

impl<'de> Deserialize<'de> for NodeProof {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct ProofBytes;

        impl Visitor<'_> for ProofBytes {
            type Value = NodeProof;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "a {NODE_PROOF_LEN}-byte node proof")
            }

            fn visit_bytes<E: de::Error>(self, bytes: &[u8]) -> Result<NodeProof, E> {
                let bytes: &[u8; NODE_PROOF_LEN] = bytes
                    .try_into()
                    .map_err(|_| E::invalid_length(bytes.len(), &self))?;
                Ok(NodeProof::from_bytes(bytes))
            }
        }

        deserializer.deserialize_bytes(ProofBytes)
    }
}

#[cfg(test)]
mod tests {
    use scp_crypto::p256::P256SecretKey;

    use super::super::binding::tests::{TestResult, key, operator, signed_binding, url};
    use super::*;

    const NOW: u64 = 1_700_000_000;
    const SKEW: u64 = 300;

    /// The verified binding of `node` under the test operator.
    fn bound(node: &P256SecretKey) -> TestResult<VerifiedNodeBinding> {
        let operator = operator()?;
        Ok(VerifiedNodeBinding::verify(
            signed_binding(&operator, &key(1), node, &url()?)?,
            &operator.resolved()?,
        )?)
    }

    fn sent() -> SentQuery {
        SentQuery {
            nonce: [1; 32],
            routing_id: [2; 32],
            since: Some(5),
            after_blob: Some([3; 32]),
            limit: Some(16),
        }
    }

    const BLOBS: [&[u8]; 2] = [b"a", b"bb"];

    fn signed_proof(node: &P256SecretKey, query: &SentQuery) -> TestResult<NodeProof> {
        let own = NodeSigningKey::from_scalar_bytes(&node.to_scalar_bytes())?;
        Ok(NodeProof::sign(
            &own,
            query,
            response_value_digest(&BLOBS)?,
            NOW,
        )?)
    }

    #[test]
    fn the_preimage_is_186_bytes_and_the_object_232() -> TestResult {
        let proof = signed_proof(&key(1), &sent())?;
        let mut preimage = b"SCP-NODE-PROOF-V1:".to_vec();
        preimage.extend_from_slice(&proof.to_bytes()[..NODE_PROOF_FIELDS_LEN]);
        assert_eq!(preimage.len(), 186);
        assert_eq!(proof.digest(), <[u8; 32]>::from(Sha256::digest(&preimage)));
        assert_eq!(proof.to_bytes().len(), 232);
        assert_eq!(proof.query_digest, sent().digest());
        Ok(())
    }

    /// §9.7.4.2's query digest: a presence byte per optional field, then
    /// the fixed-width value; an absent field is the one byte `0x00`.
    #[test]
    fn the_query_digest_takes_a_presence_byte_per_field() {
        let mut present = b"SCP-NODE-QUERY-V1:".to_vec();
        present.extend_from_slice(&[2; 32]);
        present.push(1);
        present.extend_from_slice(&5u64.to_be_bytes());
        present.push(1);
        present.extend_from_slice(&[3; 32]);
        present.push(1);
        present.extend_from_slice(&16u32.to_be_bytes());
        assert_eq!(sent().digest(), <[u8; 32]>::from(Sha256::digest(&present)));

        let absent = SentQuery {
            since: None,
            after_blob: None,
            limit: None,
            ..sent()
        };
        let mut preimage = b"SCP-NODE-QUERY-V1:".to_vec();
        preimage.extend_from_slice(&[2; 32]);
        preimage.extend_from_slice(&[0, 0, 0]);
        assert_eq!(absent.digest(), <[u8; 32]>::from(Sha256::digest(&preimage)));
        // An omitted limit is not the node's default of 100.
        assert_ne!(
            absent.digest(),
            SentQuery {
                limit: Some(100),
                ..absent
            }
            .digest()
        );
    }

    #[test]
    fn a_proof_round_trips_and_verifies() -> TestResult {
        let node = key(1);
        let proof = signed_proof(&node, &sent())?;
        let back = NodeProof::from_bytes(&proof.to_bytes());
        assert_eq!(back, proof);
        assert_eq!(
            back.verify(&bound(&node)?, &sent(), &BLOBS, NOW, SKEW),
            Ok(())
        );
        Ok(())
    }

    /// The finding the query digest closes: a proof over one page does not
    /// verify against a QUERY that asked for another, in any of `since`,
    /// `after_blob` or `limit`, present or absent.
    #[test]
    fn a_proof_for_one_page_fails_against_another_query() -> TestResult {
        let node = key(1);
        let binding = bound(&node)?;
        let proof = signed_proof(&node, &sent())?;
        let others = [
            SentQuery {
                since: Some(u64::MAX),
                ..sent()
            },
            SentQuery {
                since: None,
                after_blob: None,
                ..sent()
            },
            SentQuery {
                after_blob: Some([4; 32]),
                ..sent()
            },
            SentQuery {
                after_blob: None,
                ..sent()
            },
            SentQuery {
                limit: Some(1),
                ..sent()
            },
            SentQuery {
                limit: None,
                ..sent()
            },
        ];
        for other in others {
            assert_eq!(
                proof.verify(&binding, &other, &BLOBS, NOW, SKEW),
                Err(NodeProofError::QueryDigestMismatch),
                "{other:?}"
            );
        }
        Ok(())
    }

    #[test]
    fn each_check_refuses_with_its_own_error() -> TestResult {
        let node = key(1);
        let binding = bound(&node)?;
        let proof = signed_proof(&node, &sent())?;
        let check = |p: &NodeProof, q: &SentQuery, blobs: &[&[u8]], now: u64| {
            p.verify(&binding, q, blobs, now, SKEW)
        };
        assert_eq!(
            signed_proof(&key(2), &sent())?.verify(&binding, &sent(), &BLOBS, NOW, SKEW),
            Err(NodeProofError::NodeIdMismatch)
        );
        assert_eq!(
            check(
                &proof,
                &SentQuery {
                    nonce: [9; 32],
                    ..sent()
                },
                &BLOBS,
                NOW
            ),
            Err(NodeProofError::NonceMismatch)
        );
        assert_eq!(
            check(
                &proof,
                &SentQuery {
                    routing_id: [9; 32],
                    ..sent()
                },
                &BLOBS,
                NOW
            ),
            Err(NodeProofError::RoutingIdMismatch)
        );
        assert_eq!(
            check(&proof, &sent(), &[b"ab".as_slice(), b"b"], NOW),
            Err(NodeProofError::ValueDigestMismatch)
        );
        assert_eq!(
            check(&proof, &sent(), &[], NOW),
            Err(NodeProofError::ValueDigestMismatch)
        );
        assert_eq!(check(&proof, &sent(), &BLOBS, NOW + SKEW), Ok(()));
        assert_eq!(check(&proof, &sent(), &BLOBS, NOW - SKEW), Ok(()));
        assert_eq!(
            check(&proof, &sent(), &BLOBS, NOW + SKEW + 1),
            Err(NodeProofError::ObservedAtOutOfSkew {
                observed_at: NOW,
                now: NOW + SKEW + 1,
                skew: SKEW
            })
        );
        assert_eq!(
            check(&proof, &sent(), &BLOBS, NOW - SKEW - 1),
            Err(NodeProofError::ObservedAtOutOfSkew {
                observed_at: NOW,
                now: NOW - SKEW - 1,
                skew: SKEW
            })
        );
        let mut forged = proof;
        forged.signature[0] ^= 1;
        assert!(matches!(
            check(&forged, &sent(), &BLOBS, NOW),
            Err(NodeProofError::Signature(_))
        ));
        Ok(())
    }

    /// A flip in any of the 232 bytes makes the proof refused, by the
    /// signature where no earlier check catches it.
    #[test]
    fn a_flip_in_any_byte_is_refused() -> TestResult {
        let node = key(1);
        let binding = bound(&node)?;
        let bytes = signed_proof(&node, &sent())?.to_bytes();
        for i in 0..NODE_PROOF_LEN {
            let mut flipped = bytes;
            flipped[i] ^= 1;
            let proof = NodeProof::from_bytes(&flipped);
            assert!(proof.verify_signature(&binding).is_err(), "byte {i}");
        }
        Ok(())
    }

    /// The proof rides as one `bin` of exactly 232 bytes, and any other
    /// width is a decode error, never a proof.
    #[test]
    fn the_wire_form_is_one_bin_of_232_bytes() -> TestResult {
        let proof = signed_proof(&key(1), &sent())?;
        let encoded = rmp_serde::to_vec(&proof)?;
        let value: rmpv::Value = rmp_serde::from_slice(&encoded)?;
        assert_eq!(value, rmpv::Value::Binary(proof.to_bytes().to_vec()));
        assert_eq!(rmp_serde::from_slice::<NodeProof>(&encoded)?, proof);
        for len in [0, 231, 233] {
            let bin = rmp_serde::to_vec(&serde_bytes::ByteBuf::from(vec![0u8; len]))?;
            assert!(rmp_serde::from_slice::<NodeProof>(&bin).is_err(), "{len}");
        }
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
