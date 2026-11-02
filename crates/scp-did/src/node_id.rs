//! The node identifier (`09-security-model.md` §9.7.4.2 definitions, "A node
//! key"; §9.18.2 `"SCP-NODE-ID-V1:"`).
//!
//! A node is named by `NodeId = SHA-256("SCP-NODE-ID-V1:" ‖ node_key)` over
//! its 33-byte compressed SEC1 P-256 key. This crate holds only the 32-byte
//! newtype, because it carries no P-256 or SHA-256 dependency;
//! `scp_kel::derive_node_id` checks the key and computes the digest.
//!
//! A `NodeId` and an [`Identifier`](crate::Identifier) are both 32 bytes, and
//! §9.7.4.2 forbids accepting one where the other is expected. They are two
//! types with no conversion between them, so the compiler enforces that rule.

use std::fmt;

/// The 32-byte identifier of one node key (`09-security-model.md` §9.7.4.2
/// definitions). `Debug` and `Display` write lowercase hexadecimal, the form
/// every byte field of the node list takes (§9.6.3).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NodeId([u8; 32]);

impl NodeId {
    /// Wraps 32 bytes read from a field that carries a `NodeId` (a node
    /// proof's `node_id`, a witness set entry). It checks nothing, because a
    /// `NodeId` is a digest and every 32-byte value is one; a caller compares
    /// it with the `NodeId` it derived from a bound node key.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The 32 raw bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}

impl fmt::Debug for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NodeId({self})")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_and_debug_write_lowercase_hex() {
        let id = NodeId::from_bytes([0xAB; 32]);
        assert_eq!(id.to_string(), "ab".repeat(32));
        assert_eq!(format!("{id:?}"), format!("NodeId({})", "ab".repeat(32)));
        assert_eq!(id.as_bytes(), &[0xAB; 32]);
    }
}
