//! Items the standing domain shares with core and with other domains.
//!
//! It holds code that reads or writes only core state and calls no domain
//! function, and the types and constants more than one crate names (ADR-070
//! Appendix).
use scp_did::DID;
use sha2::Digest;
use sha2::Sha256;

/// Derives the **raw 32-byte digest** for a standing context between two DIDs.
///
/// This is the canonical wire form of the standing-pair identity (spec §5.15.8:
/// "the 32-byte `derived_context_id` is the raw digest before prefix and hex").
/// The digest is computed over both DIDs sorted lexicographically, so it is
/// symmetric: `derive(A, B) == derive(B, A)`.
///
/// [`generate_standing_context_id`] wraps this digest with the `"standing-"`
/// display prefix + hex for the actor-registry key; the saga concurrency
/// gating (ADR-049 §3a, spec §5.15.4) reserves the RAW-digest hex
/// (`hex::encode(derive_standing_context_digest(..))`) so a cross-context
/// saga that shares the same standing context reserves the SAME
/// canonical key and therefore overlaps. Keeping the prefixed id and the raw
/// digest derived from one shared body guarantees they cannot drift apart.
#[must_use]
pub fn derive_standing_context_digest(local_did: &DID, peer_did: &DID) -> [u8; 32] {
    let (a, b) = if local_did.as_ref() <= peer_did.as_ref() {
        (local_did.as_ref(), peer_did.as_ref())
    } else {
        (peer_did.as_ref(), local_did.as_ref())
    };
    let mut hasher = Sha256::new();
    hasher.update(b"standing:");
    hasher.update(a.as_bytes());
    hasher.update(b":");
    hasher.update(b.as_bytes());
    hasher.finalize().into()
}

/// Generates a deterministic context ID for a standing context between two DIDs.
///
/// The ID is derived from both DIDs sorted lexicographically, ensuring the same
/// context ID is generated regardless of which peer initiates. Uses a
/// `standing-` prefix for namespace isolation and the lowercase hex of the
/// 32-byte SHA-256 digest ([`derive_standing_context_digest`]) of the sorted
/// DID pair for the unique portion. The prefixed string is the actor-registry
/// key; the unprefixed raw digest is the gating form (spec §5.15.8).
#[must_use]
pub fn generate_standing_context_id(local_did: &DID, peer_did: &DID) -> String {
    format!(
        "standing-{}",
        hex::encode(derive_standing_context_digest(local_did, peer_did))
    )
}
