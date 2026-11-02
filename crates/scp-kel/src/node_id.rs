//! The node-key check and the [`NodeId`] derivation (`09-security-model.md`
//! §9.7.4.2 definitions, "A node key"; §9.18.2 `"SCP-NODE-ID-V1:"`; spec 25
//! §25.27 Vector 90).
//!
//! A node key is a 33-byte compressed SEC1 point that MUST decode to a point
//! on P-256, and `NodeId = SHA-256("SCP-NODE-ID-V1:" ‖ node_key)`. The
//! separator is an identifier-derivation prefix, not a §9.5.1 signature
//! preimage separator, and the key follows it raw: it is fixed width, so it
//! takes no length prefix.

use scp_crypto::p256::{COMPRESSED_POINT_LEN, P256Error, P256PublicKey};
use scp_did::NodeId;
use sha2::{Digest, Sha256};

use crate::constants::NODE_ID_SEPARATOR;

/// Why a byte string is not a node key (§9.7.4.2 definitions).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum NodeKeyError {
    /// The key is not 33 bytes.
    #[error("node key is {0} bytes, expected 33")]
    WrongLength(usize),
    /// The first byte is not `0x02` or `0x03`, so the key is not a compressed
    /// SEC1 point; an uncompressed point (`0x04`) lands here.
    #[error("node key prefix 0x{0:02x} is not a compressed SEC1 point")]
    NotCompressed(u8),
    /// The 33 bytes decode to no point on P-256.
    #[error("node key is not a point on P-256")]
    NotOnCurve,
}

/// Checks that `node_key` is a 33-byte compressed SEC1 point on P-256.
///
/// Returns the decoded point. Every reader of a node key goes through this
/// one check, so no reader accepts the uncompressed form `from_sec1` admits.
///
/// # Errors
///
/// [`NodeKeyError`] names the first rule the bytes break, in the order
/// length, prefix, curve.
pub fn parse_node_key(node_key: &[u8]) -> Result<P256PublicKey, NodeKeyError> {
    if node_key.len() != COMPRESSED_POINT_LEN {
        return Err(NodeKeyError::WrongLength(node_key.len()));
    }
    match node_key.first() {
        Some(0x02 | 0x03) => {}
        Some(&prefix) => return Err(NodeKeyError::NotCompressed(prefix)),
        None => return Err(NodeKeyError::WrongLength(0)),
    }
    P256PublicKey::from_sec1(node_key).map_err(|e| match e {
        P256Error::InvalidPointLength(len) => NodeKeyError::WrongLength(len),
        P256Error::InvalidPointPrefix { prefix, .. } => NodeKeyError::NotCompressed(prefix),
        _ => NodeKeyError::NotOnCurve,
    })
}

/// `SHA-256("SCP-NODE-ID-V1:" ‖ node_key)` over a checked node key.
///
/// The peer of [`derive_identifier`](crate::derive_identifier). It lives here
/// because `scp-did`, which holds [`NodeId`], carries no P-256 or SHA-256
/// dependency.
///
/// # Errors
///
/// [`NodeKeyError`] when `node_key` is not a 33-byte compressed SEC1 point
/// on P-256; no digest is computed over such bytes.
pub fn derive_node_id(node_key: &[u8]) -> Result<NodeId, NodeKeyError> {
    parse_node_key(node_key)?;
    let mut hasher = Sha256::new();
    hasher.update(NODE_ID_SEPARATOR);
    hasher.update(node_key);
    Ok(NodeId::from_bytes(hasher.finalize().into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// §25.2's reference public key, compressed.
    const REFERENCE_KEY: [u8; 33] = [
        0x03, 0x3b, 0x1c, 0xac, 0x23, 0xf4, 0x5c, 0xf1, 0xcd, 0xfd, 0xf0, 0xb3, 0x2f, 0x8f, 0x77,
        0x7b, 0x99, 0x16, 0x6c, 0x1b, 0x69, 0x64, 0x9c, 0x22, 0x95, 0xb1, 0x51, 0x78, 0x83, 0xd4,
        0x7f, 0x30, 0x27,
    ];

    fn reference_key() -> Vec<u8> {
        REFERENCE_KEY.to_vec()
    }

    #[test]
    fn derive_refuses_a_key_of_the_wrong_length() {
        let key = reference_key();
        assert_eq!(
            derive_node_id(&key[..32]),
            Err(NodeKeyError::WrongLength(32))
        );
        let mut long = key;
        long.push(0);
        assert_eq!(derive_node_id(&long), Err(NodeKeyError::WrongLength(34)));
        assert_eq!(derive_node_id(&[]), Err(NodeKeyError::WrongLength(0)));
    }

    #[test]
    fn derive_refuses_an_uncompressed_prefix() {
        let mut key = reference_key();
        key[0] = 0x04;
        assert_eq!(derive_node_id(&key), Err(NodeKeyError::NotCompressed(0x04)));
        key[0] = 0x00;
        assert_eq!(derive_node_id(&key), Err(NodeKeyError::NotCompressed(0x00)));
    }

    #[test]
    fn derive_refuses_an_off_curve_point() {
        // x = 1: 1 − 3 + b is not a square mod p, so no y exists.
        let mut key = [0u8; 33];
        key[0] = 0x02;
        key[32] = 0x01;
        assert_eq!(derive_node_id(&key), Err(NodeKeyError::NotOnCurve));
        // x ≥ p is not a field element.
        let mut key = [0xffu8; 33];
        key[0] = 0x03;
        assert_eq!(derive_node_id(&key), Err(NodeKeyError::NotOnCurve));
    }

    #[test]
    fn derive_hashes_the_separator_and_the_raw_key() -> Result<(), NodeKeyError> {
        let key = reference_key();
        let mut hasher = Sha256::new();
        hasher.update(b"SCP-NODE-ID-V1:");
        hasher.update(&key);
        let expected: [u8; 32] = hasher.finalize().into();
        assert_eq!(derive_node_id(&key)?.as_bytes(), &expected);
        Ok(())
    }

    /// §25.27 Vector 90: the `NodeId` of §25.2's reference key.
    #[test]
    fn derive_matches_vector_90() -> Result<(), NodeKeyError> {
        let node_id = derive_node_id(&REFERENCE_KEY)?;
        assert_eq!(
            hex::encode(node_id.as_bytes()),
            "e77d53354271e4c1c3c319cf7b5cfcc23be431c2ec795d5b6ecf549355f15610"
        );
        Ok(())
    }
}
