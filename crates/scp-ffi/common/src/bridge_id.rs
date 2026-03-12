//! Shared bridge ID generation for all FFI bridges.
//!
//! Bridge ID per spec section 12.2.1: `SHA-256(context_id || operator_did || platform || timestamp)`.
//! Uses length-prefixed fields to prevent domain ambiguity.

use sha2::{Digest, Sha256};

/// Generates a deterministic bridge ID per spec section 12.2.1.
///
/// Computes `SHA-256(len(context_id) || context_id || len(operator_did) ||
/// operator_did || len(platform) || platform || timestamp)` where lengths
/// are encoded as little-endian `u64` bytes for unambiguous domain separation.
///
/// Returns `(bridge_id_hex, timestamp_secs)` so callers can use the same
/// timestamp for `BridgeRegistrationRequest::requested_at`.
#[must_use]
pub fn generate_bridge_id(context_id: &str, operator_did: &str, platform: &str) -> (String, u64) {
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let mut hasher = Sha256::new();

    // Length-prefixed fields for domain separation (prevents
    // "abcdef" vs "ab""cdef" ambiguity).
    let ctx_bytes = context_id.as_bytes();
    hasher.update((ctx_bytes.len() as u64).to_le_bytes());
    hasher.update(ctx_bytes);

    let op_bytes = operator_did.as_bytes();
    hasher.update((op_bytes.len() as u64).to_le_bytes());
    hasher.update(op_bytes);

    let plat_bytes = platform.as_bytes();
    hasher.update((plat_bytes.len() as u64).to_le_bytes());
    hasher.update(plat_bytes);

    hasher.update(now_secs.to_be_bytes());

    (hex::encode(hasher.finalize()), now_secs)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn bridge_id_format() {
        let (id, ts) = generate_bridge_id("ctx-test", "did:key:operator", "discord");
        // SHA-256 output is 64 hex chars.
        assert_eq!(id.len(), 64);
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
        assert!(ts > 0);
    }

    #[test]
    fn bridge_id_deterministic_for_same_inputs() {
        // Two calls with the same inputs in the same second produce the same ID.
        // (This is inherently racy if the test spans a second boundary, but
        // extremely unlikely in practice.)
        let (id1, ts1) = generate_bridge_id("ctx-a", "did:key:op", "slack");
        let (id2, ts2) = generate_bridge_id("ctx-a", "did:key:op", "slack");
        if ts1 == ts2 {
            assert_eq!(id1, id2);
        }
    }

    #[test]
    fn bridge_id_different_for_different_inputs() {
        let (id1, _) = generate_bridge_id("ctx-a", "did:key:op", "slack");
        let (id2, _) = generate_bridge_id("ctx-b", "did:key:op", "slack");
        // Different context_id must produce different bridge_id (same second).
        assert_ne!(id1, id2);
    }

    #[test]
    fn domain_separation_prevents_ambiguity() {
        // Without length prefixes, "ab" + "cdef" would hash the same as
        // "abcd" + "ef" (if platform/timestamp were identical). Length
        // prefixes prevent this.
        let (id1, ts1) = generate_bridge_id("ab", "cdef", "p");
        let (id2, ts2) = generate_bridge_id("abcd", "ef", "p");
        if ts1 == ts2 {
            assert_ne!(id1, id2);
        }
    }
}
