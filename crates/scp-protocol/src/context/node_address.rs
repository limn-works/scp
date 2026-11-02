//! The `NodeAddress` and the sequenced `ContextNodeAddress`.
//!
//! Sources: `09-security-model.md` §9.5.2 **`NodeAddress`** and
//! **`ContextNodeAddress`**; §9.18.2 `"SCP-CONTEXT-NODE-ADDRESS-V1:"`; spec
//! 25 §25.36 Vector 93.
//!
//! A `NodeAddress` names where a context's members reach its node. It encodes
//! as two §9.5.1 fields:
//!
//! ```text
//! BE32(len(url)) ‖ url ‖ BE32(len(body)) ‖ body
//! body = via (32) ‖ bridge_target (32) ‖ wrapping_key (33)   when bridge is present
//! body = SHA-256(0x00)                                       when bridge is absent
//! ```
//!
//! The node signs, under the `context_key` its operator bound,
//!
//! ```text
//! SHA-256("SCP-CONTEXT-NODE-ADDRESS-V1:" ‖ binding_hash ‖ BE64(sequence) ‖ node)
//! ```
//!
//! and the address travels as those fields after the separator followed by
//! the 64-byte signature. The decode rules of §9.5.2 give every valid address
//! one encoding: a canonical URL, a 97-byte or sentinel body, a target other
//! than the sentinel, a wrapping key on P-256, and `wss` beside a bridge.

use std::num::NonZeroU64;

use scp_crypto::p256::{P256Error, P256PublicKey, SIGNATURE_LEN, verify_prehash_strict};
use scp_did::{BridgeEndpoint, BridgeTarget, DidError, NodeEntryUrlError, NodeId, NodeUrl};

use super::operator_binding::{VerifiedContextOperatorBinding, compressed_point};
use crate::crypto::canonical::{
    ABSENT_SENTINEL, CanonicalError, CanonicalField, canonical_hash, canonical_hash_bytes,
};

/// The §9.18.2 separator of the context node-address preimage.
pub const CONTEXT_NODE_ADDRESS_SEPARATOR: &str = "SCP-CONTEXT-NODE-ADDRESS-V1:";

/// The length of a present `bridge` body: `via` (32), `bridge_target` (32)
/// and `wrapping_key` (33).
pub const NODE_BRIDGE_LEN: usize = 97;

/// The bridge through which peers reach a node that has no URL of its own
/// (`10-infrastructure-and-self-hosting.md` §10.12.4).
///
/// Each field is a checked type, so a value holds a target other than the
/// sentinel and a wrapping key on P-256.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeBridge {
    /// The `NodeId` of the listed node that forwards session frames.
    pub via: NodeId,
    /// The identity routing ID the node registered at `via`.
    pub bridge_target: BridgeTarget,
    /// The stable wrapping key (§9.16) of the operator's device that runs the
    /// node. A party checks it against the operator's key state at each use
    /// (§9.5.2 "A party checks `wrapping_key` at each use"); this type checks
    /// only that it is a point.
    pub wrapping_key: P256PublicKey,
}

impl NodeBridge {
    /// The 97 body bytes: `via ‖ bridge_target ‖ wrapping_key`.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; NODE_BRIDGE_LEN] {
        let mut out = [0u8; NODE_BRIDGE_LEN];
        out[..32].copy_from_slice(self.via.as_bytes());
        out[32..64].copy_from_slice(&self.bridge_target.to_bytes());
        out[64..].copy_from_slice(&self.wrapping_key.to_compressed());
        out
    }
}

/// Where a context's members reach its node (§9.5.2 **`NodeAddress`**).
///
/// [`Self::direct`], [`Self::bridged`] and [`Self::from_bytes`] are the
/// constructors, so a value with a bridge always has a `wss` URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeAddress {
    url: NodeUrl,
    bridge: Option<NodeBridge>,
}

/// Why bytes are not a `NodeAddress` or a `ContextNodeAddress`, or why an
/// address is refused.
///
/// No variant carries text or bytes from the input, so an error never echoes
/// what a peer sent.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NodeAddressError {
    /// The bytes end before the encoding does.
    #[error("node address bytes end early")]
    Truncated,
    /// Bytes follow the encoding's last field.
    #[error("node address carries {0} bytes after its last field")]
    TrailingBytes(usize),
    /// `url` is not UTF-8.
    #[error("node address url is not UTF-8")]
    UrlNotUtf8,
    /// `url` has no canonical form ending in `/scp/v1`; the reason, where the
    /// URL check named one.
    #[error("node address url is not a node URL: {0:?}")]
    BadUrl(Option<NodeEntryUrlError>),
    /// `url` is a node URL but not in its canonical spelling.
    #[error("node address url is not in canonical form")]
    UrlNotCanonical,
    /// The `bridge` length is neither 97 nor 32.
    #[error("node address bridge is {0} bytes, expected 97 or 32")]
    BridgeLength(u32),
    /// A 32-byte `bridge` body that is not `SHA-256(0x00)`.
    #[error("node address absent bridge is not SHA-256(0x00)")]
    AbsentBridgeNotSentinel,
    /// A present bridge's `bridge_target` is `SHA-256(0x00)`.
    #[error("node address bridge_target is the absent sentinel")]
    SentinelBridgeTarget,
    /// A present bridge's `wrapping_key` is not a compressed SEC1 point on
    /// P-256 (§9.5 point validation).
    #[error("node address wrapping_key is not a compressed point on P-256")]
    WrappingKey,
    /// A bridge beside a `ws` URL; a node behind a bridge is reached over TLS.
    #[error("node address bridge needs a wss url")]
    PlaintextBridge,
    /// The encoding could not be length-prefixed.
    #[error("node address encoding: {0}")]
    Encoding(#[from] CanonicalError),
    /// `sequence` is 0; the first address carries 1.
    #[error("context node address sequence is 0")]
    ZeroSequence,
    /// The address carries a `binding_hash` other than the binding's.
    #[error("context node address names another binding")]
    BindingMismatch,
    /// The signature does not verify under `context_key`.
    #[error("context node address signature: {0}")]
    Signature(P256Error),
    /// The offered address's sequence is at or below the held one's.
    #[error("context node address sequence {offered} is not above held sequence {held}")]
    NotNewer {
        /// The sequence the reader holds.
        held: u64,
        /// The sequence it was offered.
        offered: u64,
    },
}

/// A cursor over bytes a peer sent. Every read fails closed at the end.
pub(crate) struct Reader<'a> {
    bytes: &'a [u8],
}

impl<'a> Reader<'a> {
    pub(crate) const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }

    /// The next `n` bytes, or `None` when fewer remain.
    pub(crate) const fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.bytes.len() < n {
            return None;
        }
        let (head, rest) = self.bytes.split_at(n);
        self.bytes = rest;
        Some(head)
    }

    /// The next `N` bytes as an array.
    pub(crate) fn array<const N: usize>(&mut self) -> Option<[u8; N]> {
        self.take(N).and_then(|s| s.try_into().ok())
    }

    /// A BE32 length followed by that many bytes.
    pub(crate) fn var(&mut self) -> Option<&'a [u8]> {
        let len = u32::from_be_bytes(self.array::<4>()?);
        self.take(usize::try_from(len).ok()?)
    }

    /// The bytes not yet read.
    pub(crate) const fn remaining(&self) -> usize {
        self.bytes.len()
    }
}

fn node_url(url: &str) -> Result<NodeUrl, NodeAddressError> {
    NodeUrl::new(url).map_err(|e| match e {
        DidError::InvalidNodeUrl { reason, .. } => NodeAddressError::BadUrl(Some(reason)),
        _ => NodeAddressError::BadUrl(None),
    })
}

impl NodeAddress {
    /// A node reached at its own URL.
    #[must_use]
    pub const fn direct(url: NodeUrl) -> Self {
        Self { url, bridge: None }
    }

    /// A node reached through the bridge node at `url`.
    #[must_use]
    pub fn bridged(url: BridgeEndpoint, bridge: NodeBridge) -> Self {
        Self {
            url: url.into_endpoint(),
            bridge: Some(bridge),
        }
    }

    /// The canonical URL a member dials: the node's own, or the bridge
    /// node's when [`Self::bridge`] is present.
    #[must_use]
    pub const fn url(&self) -> &NodeUrl {
        &self.url
    }

    /// The bridge, present only for a node reached through one.
    #[must_use]
    pub const fn bridge(&self) -> Option<&NodeBridge> {
        self.bridge.as_ref()
    }

    /// The §9.5.1 encoding: `BE32(len(url)) ‖ url ‖ BE32(len(body)) ‖ body`.
    ///
    /// # Errors
    ///
    /// [`NodeAddressError::Encoding`] when `url` exceeds a BE32 length.
    pub fn to_bytes(&self) -> Result<Vec<u8>, NodeAddressError> {
        let body = self.bridge.as_ref().map(NodeBridge::to_bytes);
        let body: &[u8] = body.as_ref().map_or(&ABSENT_SENTINEL, |b| b.as_slice());
        Ok(canonical_hash_bytes(
            b"",
            &[
                CanonicalField::VarBytes(self.url.as_str().as_bytes()),
                CanonicalField::VarBytes(body),
            ],
        )?)
    }

    /// Reads one address from the cursor by the §9.5.2 decode rules.
    pub(crate) fn read(reader: &mut Reader<'_>) -> Result<Self, NodeAddressError> {
        let url_bytes = reader.var().ok_or(NodeAddressError::Truncated)?;
        let url_str = std::str::from_utf8(url_bytes).map_err(|_| NodeAddressError::UrlNotUtf8)?;
        let url = node_url(url_str)?;
        if url.as_str() != url_str {
            return Err(NodeAddressError::UrlNotCanonical);
        }
        let len = u32::from_be_bytes(reader.array::<4>().ok_or(NodeAddressError::Truncated)?);
        match usize::try_from(len) {
            Ok(NODE_BRIDGE_LEN) => {
                let via = NodeId::from_bytes(reader.array().ok_or(NodeAddressError::Truncated)?);
                let target = reader.array().ok_or(NodeAddressError::Truncated)?;
                let bridge_target = BridgeTarget::new(target)
                    .map_err(|_| NodeAddressError::SentinelBridgeTarget)?;
                let key = reader.array().ok_or(NodeAddressError::Truncated)?;
                let wrapping_key = compressed_point(&key).ok_or(NodeAddressError::WrappingKey)?;
                let url = BridgeEndpoint::new(url.as_str()).map_err(|e| match e {
                    DidError::InvalidNodeUrl {
                        reason: NodeEntryUrlError::PlaintextBridge,
                        ..
                    } => NodeAddressError::PlaintextBridge,
                    _ => NodeAddressError::BadUrl(None),
                })?;
                Ok(Self::bridged(
                    url,
                    NodeBridge {
                        via,
                        bridge_target,
                        wrapping_key,
                    },
                ))
            }
            Ok(32) => {
                let body: [u8; 32] = reader.array().ok_or(NodeAddressError::Truncated)?;
                if body != ABSENT_SENTINEL {
                    return Err(NodeAddressError::AbsentBridgeNotSentinel);
                }
                Ok(Self::direct(url))
            }
            _ => Err(NodeAddressError::BridgeLength(len)),
        }
    }

    /// Decodes exactly one address.
    ///
    /// # Errors
    ///
    /// The [`NodeAddressError`] of the first §9.5.2 decode rule the bytes
    /// break, or [`NodeAddressError::TrailingBytes`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, NodeAddressError> {
        let mut reader = Reader::new(bytes);
        let address = Self::read(&mut reader)?;
        match reader.remaining() {
            0 => Ok(address),
            n => Err(NodeAddressError::TrailingBytes(n)),
        }
    }
}

/// One node address the node signed under `context_key`
/// (§9.5.2 **`ContextNodeAddress`**).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextNodeAddress {
    /// The `binding_hash` of the context's `ContextOperatorBinding`.
    pub binding_hash: [u8; 32],
    /// 1 at instantiation, one higher on each later address. The type holds
    /// no 0, so the encoder never emits a sequence the decoder refuses.
    pub sequence: NonZeroU64,
    /// Where members reach the node.
    pub node: NodeAddress,
    /// The `context_key` signature over the preimage.
    pub signature: [u8; SIGNATURE_LEN],
}

impl ContextNodeAddress {
    /// The digest `context_key` signs.
    ///
    /// # Errors
    ///
    /// [`NodeAddressError::Encoding`] when `node`'s URL exceeds a BE32
    /// length.
    pub fn signing_digest(
        binding_hash: &[u8; 32],
        sequence: NonZeroU64,
        node: &NodeAddress,
    ) -> Result<[u8; 32], NodeAddressError> {
        let node = node.to_bytes()?;
        Ok(canonical_hash(
            CONTEXT_NODE_ADDRESS_SEPARATOR,
            &[
                CanonicalField::Fixed32(binding_hash),
                CanonicalField::U64(sequence.get()),
                CanonicalField::RawBytes(&node),
            ],
        )?)
    }

    /// The digest over this address's three fields.
    ///
    /// # Errors
    ///
    /// As [`Self::signing_digest`].
    pub fn digest(&self) -> Result<[u8; 32], NodeAddressError> {
        Self::signing_digest(&self.binding_hash, self.sequence, &self.node)
    }

    /// The wire bytes: `binding_hash ‖ BE64(sequence) ‖ node ‖ signature`.
    ///
    /// # Errors
    ///
    /// [`NodeAddressError::Encoding`] when `node`'s URL exceeds a BE32
    /// length.
    pub fn to_bytes(&self) -> Result<Vec<u8>, NodeAddressError> {
        let node = self.node.to_bytes()?;
        let mut out = Vec::with_capacity(32 + 8 + node.len() + SIGNATURE_LEN);
        out.extend_from_slice(&self.binding_hash);
        out.extend_from_slice(&self.sequence.get().to_be_bytes());
        out.extend_from_slice(&node);
        out.extend_from_slice(&self.signature);
        Ok(out)
    }

    /// Decodes exactly one address.
    ///
    /// # Errors
    ///
    /// [`NodeAddressError::Truncated`], [`NodeAddressError::TrailingBytes`],
    /// [`NodeAddressError::ZeroSequence`], or the error of the `node` decode
    /// rule the bytes break.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, NodeAddressError> {
        let mut reader = Reader::new(bytes);
        let binding_hash = reader.array().ok_or(NodeAddressError::Truncated)?;
        let sequence = NonZeroU64::new(u64::from_be_bytes(
            reader.array().ok_or(NodeAddressError::Truncated)?,
        ))
        .ok_or(NodeAddressError::ZeroSequence)?;
        let node = NodeAddress::read(&mut reader)?;
        let signature = reader.array().ok_or(NodeAddressError::Truncated)?;
        match reader.remaining() {
            0 => Ok(Self {
                binding_hash,
                sequence,
                node,
                signature,
            }),
            n => Err(NodeAddressError::TrailingBytes(n)),
        }
    }
}

/// A [`ContextNodeAddress`] the reader adopted: its signature verified under
/// the `context_key` of the binding it names, and its sequence is above the
/// one the reader held.
///
/// [`Self::adopt`] is the only constructor, and the type has no
/// `Deserialize`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedContextNodeAddress {
    address: ContextNodeAddress,
}

impl VerifiedContextNodeAddress {
    /// The §9.5.2 verification and sequence rule in one step.
    ///
    /// `binding` is the binding the reader accepted against the
    /// `binding_hash` its group state or its invitation holds, so an address
    /// that names any other binding is refused. `held` is the address the
    /// reader holds for that binding, or `None` before its first; the reader
    /// adopts `address` only when its sequence is above `held`'s (§9.5.2 "The
    /// highest sequence wins"). Keeping `held` across restarts is the
    /// caller's.
    ///
    /// # Errors
    ///
    /// [`NodeAddressError::BindingMismatch`] when `address` or `held` names
    /// another binding than `binding`, [`NodeAddressError::Encoding`],
    /// [`NodeAddressError::Signature`] (including a high-`s` signature) or
    /// [`NodeAddressError::NotNewer`].
    pub fn adopt(
        address: ContextNodeAddress,
        binding: &VerifiedContextOperatorBinding,
        held: Option<&Self>,
    ) -> Result<Self, NodeAddressError> {
        let offered = Self::verify(address, binding)?;
        let Some(held) = held else {
            return Ok(offered);
        };
        if held.address.binding_hash != *binding.binding_hash() {
            return Err(NodeAddressError::BindingMismatch);
        }
        if offered.address.sequence <= held.address.sequence {
            return Err(NodeAddressError::NotNewer {
                held: held.address.sequence.get(),
                offered: offered.address.sequence.get(),
            });
        }
        Ok(offered)
    }

    /// `binding_hash` is the binding's, and the signature verifies strictly
    /// (low-`s`, no second hash) under the binding's `context_key`.
    fn verify(
        address: ContextNodeAddress,
        binding: &VerifiedContextOperatorBinding,
    ) -> Result<Self, NodeAddressError> {
        if address.binding_hash != *binding.binding_hash() {
            return Err(NodeAddressError::BindingMismatch);
        }
        verify_prehash_strict(
            binding.context_key(),
            &address.digest()?,
            &address.signature,
        )
        .map_err(NodeAddressError::Signature)?;
        Ok(Self { address })
    }

    /// The address this value verified.
    #[must_use]
    pub const fn address(&self) -> &ContextNodeAddress {
        &self.address
    }

    /// Where members reach the node.
    #[must_use]
    pub const fn node(&self) -> &NodeAddress {
        &self.address.node
    }

    /// The address's sequence.
    #[must_use]
    pub const fn sequence(&self) -> NonZeroU64 {
        self.address.sequence
    }
}

#[cfg(test)]
mod tests {
    use scp_crypto::p256::sign_prehash_rfc6979;
    use sha2::{Digest, Sha256};

    use super::super::operator_binding::tests::{
        TestResult, binding_by, held as held_hash, incept, key, verified_binding,
    };
    use super::*;

    fn direct() -> TestResult<NodeAddress> {
        Ok(NodeAddress::direct(NodeUrl::new(
            "wss://context-node.example.com/scp/v1",
        )?))
    }

    fn bridged() -> TestResult<NodeAddress> {
        Ok(NodeAddress::bridged(
            BridgeEndpoint::new("wss://bridge.example.com/scp/v1")?,
            NodeBridge {
                via: NodeId::from_bytes([0x44; 32]),
                bridge_target: BridgeTarget::new([0x55; 32])?,
                wrapping_key: key(7).public_key(),
            },
        ))
    }

    fn signed(
        binding: &VerifiedContextOperatorBinding,
        sequence: u64,
        node: NodeAddress,
        context_key_seed: u8,
    ) -> TestResult<ContextNodeAddress> {
        let sequence = NonZeroU64::new(sequence).ok_or("sequence 0")?;
        let digest = ContextNodeAddress::signing_digest(binding.binding_hash(), sequence, &node)?;
        Ok(ContextNodeAddress {
            binding_hash: *binding.binding_hash(),
            sequence,
            node,
            signature: sign_prehash_rfc6979(&key(context_key_seed), &digest)?,
        })
    }

    /// The verdict on a first address, with no held one.
    fn first(
        address: ContextNodeAddress,
        binding: &VerifiedContextOperatorBinding,
    ) -> Result<VerifiedContextNodeAddress, NodeAddressError> {
        VerifiedContextNodeAddress::adopt(address, binding, None)
    }

    #[test]
    fn a_direct_address_round_trips_with_the_sentinel_body() -> TestResult {
        let node = direct()?;
        let bytes = node.to_bytes()?;
        let url = b"wss://context-node.example.com/scp/v1";
        let mut expected = u32::try_from(url.len())?.to_be_bytes().to_vec();
        expected.extend_from_slice(url);
        expected.extend_from_slice(&32u32.to_be_bytes());
        expected.extend_from_slice(&Sha256::digest([0u8]));
        assert_eq!(bytes, expected);
        assert_eq!(NodeAddress::from_bytes(&bytes)?, node);
        Ok(())
    }

    #[test]
    fn a_bridged_address_round_trips_with_a_97_byte_body() -> TestResult {
        let node = bridged()?;
        let bytes = node.to_bytes()?;
        let url = b"wss://bridge.example.com/scp/v1";
        let body_at = 4 + url.len();
        assert_eq!(&bytes[body_at..body_at + 4], &97u32.to_be_bytes());
        assert_eq!(bytes.len(), body_at + 4 + 97);
        assert_eq!(&bytes[body_at + 4..body_at + 36], &[0x44; 32]);
        assert_eq!(&bytes[body_at + 36..body_at + 68], &[0x55; 32]);
        assert_eq!(&bytes[body_at + 68..], &key(7).public_key().to_compressed());
        assert_eq!(NodeAddress::from_bytes(&bytes)?, node);
        Ok(())
    }

    #[test]
    fn decode_refuses_each_broken_rule() -> TestResult {
        let encode = |url: &[u8], body: &[u8]| {
            let mut out = u32::try_from(url.len()).unwrap_or(0).to_be_bytes().to_vec();
            out.extend_from_slice(url);
            out.extend_from_slice(&u32::try_from(body.len()).unwrap_or(0).to_be_bytes());
            out.extend_from_slice(body);
            out
        };
        let good_body = bridged()?
            .bridge()
            .map(NodeBridge::to_bytes)
            .ok_or("bridge")?;

        // A non-canonical spelling of a valid URL.
        assert_eq!(
            NodeAddress::from_bytes(&encode(b"WSS://Bridge.example.com/scp/v1", &good_body)),
            Err(NodeAddressError::UrlNotCanonical)
        );
        // A URL whose path does not end in /scp/v1.
        assert!(matches!(
            NodeAddress::from_bytes(&encode(b"wss://bridge.example.com/x", &ABSENT_SENTINEL)),
            Err(NodeAddressError::BadUrl(_))
        ));
        assert_eq!(
            NodeAddress::from_bytes(&encode(&[0xff, 0xfe], &ABSENT_SENTINEL)),
            Err(NodeAddressError::UrlNotUtf8)
        );
        // A bridge beside a ws URL.
        assert_eq!(
            NodeAddress::from_bytes(&encode(b"ws://bridge.example.com/scp/v1", &good_body)),
            Err(NodeAddressError::PlaintextBridge)
        );
        let url = b"wss://bridge.example.com/scp/v1";
        // A body of another length.
        assert_eq!(
            NodeAddress::from_bytes(&encode(url, &good_body[..96])),
            Err(NodeAddressError::BridgeLength(96))
        );
        // A 32-byte body other than the sentinel.
        assert_eq!(
            NodeAddress::from_bytes(&encode(url, &[0u8; 32])),
            Err(NodeAddressError::AbsentBridgeNotSentinel)
        );
        // The sentinel as a present target.
        let mut body = good_body;
        body[32..64].copy_from_slice(&ABSENT_SENTINEL);
        assert_eq!(
            NodeAddress::from_bytes(&encode(url, &body)),
            Err(NodeAddressError::SentinelBridgeTarget)
        );
        // A wrapping key with the uncompressed tag.
        let mut body = good_body;
        body[64] = 0x04;
        assert!(matches!(
            NodeAddress::from_bytes(&encode(url, &body)),
            Err(NodeAddressError::WrappingKey)
        ));
        // Truncation and trailing bytes.
        let full = encode(url, &good_body);
        assert_eq!(
            NodeAddress::from_bytes(&full[..full.len() - 1]),
            Err(NodeAddressError::Truncated)
        );
        let mut long = full;
        long.push(0);
        assert_eq!(
            NodeAddress::from_bytes(&long),
            Err(NodeAddressError::TrailingBytes(1))
        );
        Ok(())
    }

    /// The signed address's own decoder refuses one byte after the
    /// signature, and a cut inside it.
    #[test]
    fn a_context_node_address_refuses_a_trailing_byte() -> TestResult {
        let bytes = signed(&verified_binding()?, 1, direct()?, 2)?.to_bytes()?;
        let mut long = bytes.clone();
        long.push(0);
        assert_eq!(
            ContextNodeAddress::from_bytes(&long),
            Err(NodeAddressError::TrailingBytes(1))
        );
        assert_eq!(
            ContextNodeAddress::from_bytes(&bytes[..bytes.len() - 1]),
            Err(NodeAddressError::Truncated)
        );
        Ok(())
    }

    #[test]
    fn a_signed_address_round_trips_and_verifies() -> TestResult {
        let binding = verified_binding()?;
        for node in [direct()?, bridged()?] {
            let address = signed(&binding, 1, node, 2)?;
            let bytes = address.to_bytes()?;
            let back = ContextNodeAddress::from_bytes(&bytes)?;
            assert_eq!(back, address);
            let verified = first(back, &binding)?;
            assert_eq!(verified.address(), &address);
        }
        Ok(())
    }

    #[test]
    fn the_preimage_is_the_separator_the_hash_the_sequence_and_the_node() -> TestResult {
        let binding = verified_binding()?;
        let address = signed(&binding, 3, bridged()?, 2)?;
        let mut preimage = CONTEXT_NODE_ADDRESS_SEPARATOR.as_bytes().to_vec();
        preimage.extend_from_slice(binding.binding_hash());
        preimage.extend_from_slice(&3u64.to_be_bytes());
        preimage.extend_from_slice(&address.node.to_bytes()?);
        assert_eq!(
            address.digest()?,
            <[u8; 32]>::from(Sha256::digest(&preimage))
        );
        Ok(())
    }

    /// A flip in any byte of the wire form outside the URL makes the address
    /// refused, at decode or at verification.
    #[test]
    fn a_flip_in_any_byte_is_refused() -> TestResult {
        let binding = verified_binding()?;
        let bytes = signed(&binding, 1, bridged()?, 2)?.to_bytes()?;
        for i in 0..bytes.len() {
            let mut flipped = bytes.clone();
            flipped[i] ^= 1;
            let refused = ContextNodeAddress::from_bytes(&flipped)
                .and_then(|a| first(a, &binding))
                .is_err();
            assert!(refused, "byte {i}");
        }
        Ok(())
    }

    #[test]
    fn an_address_under_another_key_or_binding_is_refused() -> TestResult {
        let binding = verified_binding()?;
        let address = signed(&binding, 1, direct()?, 3)?;
        assert!(matches!(
            first(address, &binding),
            Err(NodeAddressError::Signature(P256Error::VerificationFailed))
        ));
        let mut address = signed(&binding, 1, direct()?, 2)?;
        address.binding_hash[0] ^= 1;
        assert_eq!(
            first(address, &binding),
            Err(NodeAddressError::BindingMismatch)
        );
        Ok(())
    }

    /// The wire value 0 is refused at decode; the type cannot hold it, so no
    /// value reaches verification with it.
    #[test]
    fn sequence_zero_is_refused_at_decode() -> TestResult {
        let mut bytes = signed(&verified_binding()?, 1, direct()?, 2)?.to_bytes()?;
        bytes[32..40].fill(0);
        assert_eq!(
            ContextNodeAddress::from_bytes(&bytes),
            Err(NodeAddressError::ZeroSequence)
        );
        Ok(())
    }

    /// A reader holding sequence n refuses n and every lower sequence and
    /// adopts n + 1 (§9.5.2 "The highest sequence wins").
    #[test]
    fn the_highest_sequence_wins() -> TestResult {
        let binding = verified_binding()?;
        let address = |sequence: u64| signed(&binding, sequence, direct()?, 2);
        let held = first(address(5)?, &binding)?;
        assert_eq!(
            VerifiedContextNodeAddress::adopt(address(5)?, &binding, Some(&held)),
            Err(NodeAddressError::NotNewer {
                held: 5,
                offered: 5
            })
        );
        for lower in 1..5 {
            assert_eq!(
                VerifiedContextNodeAddress::adopt(address(lower)?, &binding, Some(&held)),
                Err(NodeAddressError::NotNewer {
                    held: 5,
                    offered: lower
                })
            );
        }
        let adopted = VerifiedContextNodeAddress::adopt(address(6)?, &binding, Some(&held))?;
        assert_eq!(adopted.sequence().get(), 6);
        Ok(())
    }

    /// An address at sequence 6 under another binding, offered to a reader
    /// that holds sequence 5 under the first, is refused even though it
    /// verifies under its own binding, which shares the `context_key`.
    #[test]
    fn an_address_under_another_binding_never_supersedes_the_held_one() -> TestResult {
        let binding = verified_binding()?;
        let held = first(signed(&binding, 5, direct()?, 2)?, &binding)?;

        let other_operator = incept(0x41, 1, 0x43)?;
        let other = VerifiedContextOperatorBinding::verify(
            binding_by(&other_operator, &key(1))?,
            &held_hash(&other_operator)?,
            &other_operator.chain()?,
        )?;
        assert_ne!(other.binding_hash(), binding.binding_hash());
        assert_eq!(other.context_key(), binding.context_key());
        let offered = signed(&other, 6, direct()?, 2)?;
        assert!(first(offered.clone(), &other).is_ok());
        assert_eq!(
            VerifiedContextNodeAddress::adopt(offered.clone(), &other, Some(&held)),
            Err(NodeAddressError::BindingMismatch)
        );
        assert_eq!(
            VerifiedContextNodeAddress::adopt(offered, &binding, Some(&held)),
            Err(NodeAddressError::BindingMismatch)
        );
        Ok(())
    }
}
