//! Shared bridge ID generation for all FFI bridges.
//!
//! Bridge ID per spec section 12.2.1: `SHA-256(context_id || operator_did || platform || timestamp)`.

use scp_clock::Clock;

/// Generates a bridge ID per spec section 12.2.1.
///
/// Computes `SHA-256(context_id || operator_did || platform || timestamp)`
/// where timestamp is the current Unix epoch seconds as big-endian `u64` bytes.
///
/// # Non-determinism by design
///
/// The timestamp component means the same `(context_id, operator_did, platform)`
/// inputs produce a **different** bridge ID on each call. This is intentional
/// per spec section 12.2.1: the timestamp makes each registration unique, so the same
/// operator can register multiple bridges for the same context and platform
/// at different times without ID collisions.
///
/// Returns `(bridge_id_hex, timestamp_secs)` so callers can use the same
/// timestamp for `BridgeRegistrationRequest::requested_at`.
#[must_use]
pub fn generate_bridge_id(context_id: &str, operator_did: &str, platform: &str) -> (String, u64) {
    let now_secs = scp_clock::SystemClock.now_secs();

    // One derivation lives in scp-protocol, because `register_bridge` rejects
    // a request whose `bridge_id` differs from what it derives. Computing a
    // second copy here would let these two drift and reject every request.
    let bridge_id = scp_protocol::bridge::registration::derive_bridge_id(
        context_id,
        operator_did,
        platform,
        now_secs,
    );

    (bridge_id, now_secs)
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

    /// This bridge derives an id exactly as spec §12.2.1 step 3 does.
    ///
    /// Step 3 hashes a length-prefixed concatenation, so a request built here
    /// passes the derivation check `scp_protocol` `register_bridge` applies.
    /// This test recomputes that preimage by hand rather than calling
    /// `derive_bridge_id`, so a change to that function shows up here.
    #[test]
    fn matches_the_spec_length_prefixed_derivation() {
        use sha2::{Digest, Sha256};

        let ctx = "ctx-test";
        let op = "did:key:operator";
        let plat = "discord";
        let (id, ts) = generate_bridge_id(ctx, op, plat);

        let mut hasher = Sha256::new();
        for segment in [ctx, op, plat] {
            hasher.update((segment.len() as u64).to_be_bytes());
            hasher.update(segment.as_bytes());
        }
        hasher.update(ts.to_be_bytes());

        assert_eq!(id, hex::encode(hasher.finalize()));
    }

    /// A shifted boundary between two inputs derives a different id.
    ///
    /// Raw concatenation would flatten these two into one preimage, and a
    /// bridge id decides which context a request acts inside.
    #[test]
    fn a_shifted_boundary_between_inputs_derives_a_different_id() {
        use sha2::{Digest, Sha256};

        let derive = |ctx: &str, op: &str, ts: u64| {
            let mut hasher = Sha256::new();
            for segment in [ctx, op, "discord"] {
                hasher.update((segment.len() as u64).to_be_bytes());
                hasher.update(segment.as_bytes());
            }
            hasher.update(ts.to_be_bytes());
            hex::encode(hasher.finalize())
        };

        assert_ne!(
            derive("ctx-a", "bc", 1_700_000_000),
            derive("ctx-ab", "c", 1_700_000_000)
        );
    }
}
