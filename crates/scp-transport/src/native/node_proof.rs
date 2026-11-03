//! The node proof of control on `EVENT query_complete`
//! (`09-security-model.md` §9.7.4.2 "The node proof of control", §9.10.12;
//! `10-infrastructure-and-self-hosting.md` §10.4 "Node key and binding").
//!
//! Every transport that answers QUERY (WebSocket, QUIC, UDP/DTLS,
//! WebTransport) ends the response with [`query_complete`], so one function
//! decides for all four whether the response carries a `node_proof` and what
//! it signs.
//!
//! - A server built with [`NodeProofs::Sign`] holds the node key its
//!   operator's installed binding binds, and answers a QUERY that carries a
//!   `proof_nonce` with a proof over the QUERY as received and over exactly
//!   the blobs it returned, in the order it returned them, zero blobs
//!   included.
//! - A server built with [`NodeProofs::Unbound`] holds no binding, which is
//!   the absent state §9.10.12 permits: it returns no `node_proof`, never a
//!   proof under a placeholder key.
//! - A QUERY without a `proof_nonce` gets no proof.

use std::fmt;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use scp_protocol::node::{
    BoundNodeKey, NodeProof, NodeProofError, SentQuery, response_value_digest,
};
use scp_relay_client::{RelayMessage, code};

use super::storage::StoredBlob;

/// Whether a server signs node proofs, and under which bound key.
#[derive(Clone, Default)]
pub enum NodeProofs {
    /// The node's key with the binding its operator installed.
    Sign(Arc<BoundNodeKey>),
    /// No binding is installed, so no response carries a `node_proof`. The
    /// default, because only a node holds a node key.
    #[default]
    Unbound,
}

impl fmt::Debug for NodeProofs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sign(key) => write!(f, "NodeProofs::Sign({})", key.node_id()),
            Self::Unbound => f.write_str("NodeProofs::Unbound"),
        }
    }
}

/// The fields of a received QUERY a node proof covers.
///
/// It exists where the QUERY carried a `proof_nonce`: `None` for a QUERY
/// without one, which gets no proof. Each optional field is as the QUERY carried it, never the
/// effective default the node applied (§9.7.4.2 "The query digest").
#[must_use]
pub const fn proof_query(
    proof_nonce: Option<[u8; 32]>,
    routing_id: [u8; 32],
    since: Option<u64>,
    after_blob: Option<[u8; 32]>,
    limit: Option<u32>,
) -> Option<SentQuery> {
    match proof_nonce {
        Some(nonce) => Some(SentQuery {
            nonce,
            routing_id,
            since,
            after_blob,
            limit,
        }),
        None => None,
    }
}

/// The `EVENT query_complete` that ends a QUERY response whose blobs were
/// `blobs`, in the order the transport sent them.
///
/// It carries a `node_proof` when `proofs` is [`NodeProofs::Sign`] and
/// `query` is the QUERY's [`proof_query`]; the proof echoes the nonce,
/// digests the QUERY's routing id, `since`, `after_blob` and `limit`, covers
/// the blobs' bytes, and names the node's clock in seconds. When the proof
/// cannot be built the response ends with `ERR` `5000` instead, so a
/// requester never reads a response the node meant to prove as one it chose
/// not to.
#[must_use]
pub fn query_complete(
    proofs: &NodeProofs,
    ref_id: Option<String>,
    query: Option<&SentQuery>,
    blobs: &[StoredBlob],
) -> RelayMessage {
    let node_proof = match (proofs, query) {
        (NodeProofs::Sign(key), Some(query)) => match sign(key, query, blobs) {
            Ok(proof) => Some(Box::new(proof)),
            Err(e) => {
                tracing::error!(error = %e, "node proof could not be signed");
                return RelayMessage::Err {
                    ref_id,
                    code: code::INTERNAL_ERROR,
                    msg: "node proof could not be signed".to_owned(),
                };
            }
        },
        (NodeProofs::Sign(_) | NodeProofs::Unbound, _) => None,
    };
    RelayMessage::Event {
        node_proof,
        ref_id,
        event_type: "query_complete".to_owned(),
    }
}

fn sign(
    key: &BoundNodeKey,
    query: &SentQuery,
    blobs: &[StoredBlob],
) -> Result<NodeProof, NodeProofError> {
    let bytes: Vec<&[u8]> = blobs.iter().map(|b| b.blob.as_slice()).collect();
    let value_digest = response_value_digest(&bytes)?;
    // A clock before 1970 reads as 0, which the requester's clock-skew check
    // then refuses; the node never invents a time.
    let observed_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    key.prove(query, value_digest, observed_at)
}

#[cfg(test)]
pub(crate) mod tests {
    use scp_crypto::p256::{
        P256PublicKey, P256SecretKey, sign_prehash_rfc6979, verify_prehash_strict,
    };
    use scp_did::{Identifier, NodeUrl};
    use scp_protocol::node::{NodeBinding, NodeProof, NodeSigningKey, node_url_hash};

    use super::*;
    use crate::native::storage::StoredLifetime;

    pub type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

    /// A node key at `seed` with a binding to a fixed operator. The node
    /// checks the possession signature and the URL at install, not the
    /// operator signature, so the operator key here is arbitrary.
    pub fn bound_key(seed: u8) -> TestResult<Arc<BoundNodeKey>> {
        let node = NodeSigningKey::from_scalar_bytes(&[seed; 32])?;
        let url = NodeUrl::new("wss://node.example.com/scp/v1")?;
        let operator = Identifier::from_bytes([0x0a; 32]);
        let url_hash = node_url_hash(&url);
        let possession_sig = node.sign_possession(&operator, &url_hash, &[0x0b; 32])?;
        let mut binding = NodeBinding {
            operator,
            node_key: *node.node_key(),
            url_hash,
            key_state_head: [0x0b; 32],
            operator_sig: [0; 64],
            possession_sig,
        };
        let operator_key = P256SecretKey::from_scalar_bytes(&[0x0c; 32])?;
        binding.operator_sig = sign_prehash_rfc6979(&operator_key, &binding.digest())?;
        Ok(Arc::new(node.install(binding, &url)?))
    }

    /// The proof a `query_complete` carries, with its signature checked
    /// under the binding's node key and its `node_id` the key's.
    pub fn proof_of(key: &BoundNodeKey, msg: &RelayMessage) -> TestResult<NodeProof> {
        let RelayMessage::Event {
            node_proof: Some(proof),
            event_type,
            ..
        } = msg
        else {
            return Err(format!("expected a proved query_complete, got {msg:?}").into());
        };
        assert_eq!(event_type, "query_complete");
        let node_key = P256PublicKey::from_sec1(&key.binding().node_key)?;
        verify_prehash_strict(&node_key, &proof.digest(), &proof.signature)?;
        assert_eq!(&proof.node_id, key.node_id());
        Ok((**proof).clone())
    }

    /// The seconds clock a test brackets a signing with.
    pub fn now_secs() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs())
    }

    fn blob(bytes: &[u8]) -> StoredBlob {
        StoredBlob {
            routing_id: [1; 32],
            blob_id: [2; 32],
            recipient_hint: None,
            lifetime: StoredLifetime::Ttl(60),
            stored_at: 0,
            blob: bytes.to_vec(),
        }
    }

    fn query() -> SentQuery {
        SentQuery {
            nonce: [9; 32],
            routing_id: [1; 32],
            since: Some(4),
            after_blob: Some([5; 32]),
            limit: Some(2),
        }
    }

    #[test]
    fn a_bound_server_proves_the_query_and_the_blobs_it_returned() -> TestResult {
        let key = bound_key(7)?;
        let blobs = [blob(b"one"), blob(b"two")];
        let before = now_secs();
        let msg = query_complete(
            &NodeProofs::Sign(Arc::clone(&key)),
            None,
            Some(&query()),
            &blobs,
        );
        let after = now_secs();
        let proof = proof_of(&key, &msg)?;
        assert_eq!(proof.nonce, [9; 32]);
        assert_eq!(proof.routing_id, [1; 32]);
        assert_eq!(proof.query_digest, query().digest());
        assert_eq!(
            proof.value_digest,
            response_value_digest(&[b"one".as_slice(), b"two"])?
        );
        assert!(
            (before..=after).contains(&proof.observed_at),
            "observed_at {} outside [{before}, {after}]",
            proof.observed_at
        );
        Ok(())
    }

    /// `proof_query` carries each optional field as the QUERY carried it,
    /// so an omitted `limit` is digested as omitted, not as 100.
    #[test]
    fn the_proof_query_keeps_omitted_fields_omitted() {
        assert_eq!(proof_query(None, [1; 32], Some(4), None, Some(2)), None);
        let sent = proof_query(Some([9; 32]), [1; 32], None, None, None);
        assert_eq!(
            sent,
            Some(SentQuery {
                nonce: [9; 32],
                routing_id: [1; 32],
                since: None,
                after_blob: None,
                limit: None,
            })
        );
        assert_eq!(
            proof_query(Some([9; 32]), [1; 32], Some(4), Some([5; 32]), Some(2)),
            Some(query())
        );
    }

    #[test]
    fn an_empty_response_is_proved_too() -> TestResult {
        let key = bound_key(7)?;
        let msg = query_complete(
            &NodeProofs::Sign(Arc::clone(&key)),
            None,
            Some(&query()),
            &[],
        );
        let proof = proof_of(&key, &msg)?;
        assert_eq!(proof.value_digest, response_value_digest::<&[u8]>(&[])?);
        Ok(())
    }

    #[test]
    fn no_binding_means_no_proof() {
        let msg = query_complete(&NodeProofs::Unbound, None, Some(&query()), &[blob(b"x")]);
        assert!(matches!(
            msg,
            RelayMessage::Event {
                node_proof: None,
                ..
            }
        ));
    }

    #[test]
    fn no_nonce_means_no_proof() -> TestResult {
        let msg = query_complete(&NodeProofs::Sign(bound_key(7)?), None, None, &[]);
        assert!(matches!(
            msg,
            RelayMessage::Event {
                node_proof: None,
                ..
            }
        ));
        Ok(())
    }
}
