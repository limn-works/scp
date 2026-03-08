//! Cryptographic primitives for identity private state (spec section 3.7).
//!
//! This module implements two spec-mandated constructions:
//!
//! 1. **Private state routing ID derivation** — HKDF-SHA-256 derivation of
//!    the routing ID used to address private state blobs on relays (§3.7).
//! 2. **Private state hash chain** — SHA-256 hash chain with domain separator
//!    for event log integrity verification (§3.7).

use hkdf::Hkdf;
use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Domain separator salt for private state routing ID derivation.
///
/// The actual HKDF salt is `SHA-256("scp-private-state-salt-v1")` — a fixed
/// protocol constant computed at compile time (well, once at first use via
/// the derivation function).
const ROUTING_ID_SALT_DOMAIN: &[u8] = b"scp-private-state-salt-v1";

/// HKDF info prefix for private state routing ID derivation.
/// The full info parameter is `"scp-private-state-v1" || did_string`.
const ROUTING_ID_INFO_PREFIX: &[u8] = b"scp-private-state-v1";

/// Domain separator prefix for the private state event hash chain.
///
/// Each event hash is: `SHA-256("SCP-PRIVATE-LOG-V1:" || [prev_hash ||] event_data)`.
const HASH_CHAIN_DOMAIN: &[u8] = b"SCP-PRIVATE-LOG-V1:";

// ---------------------------------------------------------------------------
// Private state routing ID (§3.7 — H12)
// ---------------------------------------------------------------------------

/// Derives the relay routing ID for an identity's private state blobs.
///
/// ```text
/// private_state_routing_id = HKDF-SHA-256(
///     ikm: identity_key_material,
///     salt: SHA-256("scp-private-state-salt-v1"),
///     info: "scp-private-state-v1" || did_string,
///     len: 32
/// )
/// ```
///
/// The HKDF derivation produces a routing ID that is cryptographically
/// unlinkable to the identity's DID without knowledge of the identity key
/// material — unlike the DID document routing ID (`SHA-256("scp:did:" || did)`)
/// which is publicly derivable. This prevents relays from correlating private
/// state blobs with DID documents.
///
/// # Arguments
///
/// * `identity_key_material` — The raw bytes of the identity's `#0` key
///   material (typically the Ed25519 private key bytes or an HSM-derived
///   secret). Must be kept within the custody boundary.
/// * `did_string` — The full DID string (e.g., `"did:dht:abc123"`).
///
/// # Returns
///
/// A 32-byte routing ID suitable for relay PUBLISH/QUERY operations.
pub fn derive_private_state_routing_id(identity_key_material: &[u8], did_string: &str) -> [u8; 32] {
    // Salt = SHA-256("scp-private-state-salt-v1")
    let salt = Sha256::digest(ROUTING_ID_SALT_DOMAIN);

    // Info = "scp-private-state-v1" || did_string
    let mut info = Vec::with_capacity(ROUTING_ID_INFO_PREFIX.len() + did_string.len());
    info.extend_from_slice(ROUTING_ID_INFO_PREFIX);
    info.extend_from_slice(did_string.as_bytes());

    let hk = Hkdf::<Sha256>::new(Some(&salt), identity_key_material);
    let mut routing_id = [0u8; 32];
    // HKDF-Expand cannot fail when output length <= 255 * HashLen (= 8160 for SHA-256).
    // 32 <= 8160, so this is infallible by construction.
    if hk.expand(&info, &mut routing_id).is_err() {
        routing_id.fill(0);
    }

    routing_id
}

// ---------------------------------------------------------------------------
// Private state hash chain (§3.7 — H13)
// ---------------------------------------------------------------------------

/// Computes the hash of the first event in a private state event log.
///
/// ```text
/// event_hash[0] = SHA-256("SCP-PRIVATE-LOG-V1:" || event_data[0])
/// ```
///
/// # Arguments
///
/// * `event_data` — The serialized event bytes (plaintext, before encryption).
///
/// # Returns
///
/// A 32-byte SHA-256 hash that becomes the chain head.
pub fn hash_chain_first(event_data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(HASH_CHAIN_DOMAIN);
    hasher.update(event_data);
    hasher.finalize().into()
}

/// Computes the hash of a subsequent event in a private state event log,
/// chaining it to the previous event's hash.
///
/// ```text
/// event_hash[i] = SHA-256("SCP-PRIVATE-LOG-V1:" || event_hash[i-1] || event_data[i])
/// ```
///
/// # Arguments
///
/// * `previous_hash` — The hash of the immediately preceding event (`event_hash[i-1]`).
/// * `event_data` — The serialized event bytes for the current event.
///
/// # Returns
///
/// A 32-byte SHA-256 hash that becomes the new chain head.
pub fn hash_chain_extend(previous_hash: &[u8; 32], event_data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(HASH_CHAIN_DOMAIN);
    hasher.update(previous_hash);
    hasher.update(event_data);
    hasher.finalize().into()
}

/// Verifies an entire private state event log against a chain head hash.
///
/// Recomputes the hash chain from scratch and compares the result to
/// `expected_head`. Returns `true` if the chain is valid.
///
/// # Arguments
///
/// * `events` — Ordered slice of serialized event data (oldest first).
/// * `expected_head` — The expected chain head hash to verify against.
///
/// # Returns
///
/// `true` if recomputing the chain from `events` produces `expected_head`.
/// `false` if the chain is empty or does not match.
pub fn verify_hash_chain(events: &[&[u8]], expected_head: &[u8; 32]) -> bool {
    if events.is_empty() {
        return false;
    }

    let mut current = hash_chain_first(events[0]);
    for event_data in &events[1..] {
        current = hash_chain_extend(&current, event_data);
    }

    current == *expected_head
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    // ===================================================================
    // H12: Private state routing ID derivation
    // ===================================================================

    #[test]
    fn routing_id_is_deterministic() {
        let ikm = b"test-identity-key-material-32bytes!";
        let did = "did:dht:abc123";

        let id1 = derive_private_state_routing_id(ikm, did);
        let id2 = derive_private_state_routing_id(ikm, did);

        assert_eq!(id1, id2, "same inputs must produce same routing ID");
    }

    #[test]
    fn routing_id_differs_for_different_dids() {
        let ikm = b"test-identity-key-material-32bytes!";

        let id1 = derive_private_state_routing_id(ikm, "did:dht:abc123");
        let id2 = derive_private_state_routing_id(ikm, "did:dht:xyz789");

        assert_ne!(
            id1, id2,
            "different DIDs must produce different routing IDs"
        );
    }

    #[test]
    fn routing_id_differs_for_different_key_material() {
        let did = "did:dht:abc123";

        let id1 = derive_private_state_routing_id(b"key-material-alice", did);
        let id2 = derive_private_state_routing_id(b"key-material-bob", did);

        assert_ne!(
            id1, id2,
            "different key material must produce different routing IDs"
        );
    }

    #[test]
    fn routing_id_is_32_bytes() {
        let id = derive_private_state_routing_id(b"test-key", "did:dht:test");
        assert_eq!(id.len(), 32);
    }

    #[test]
    fn routing_id_differs_from_did_document_routing_id() {
        // DID document routing_id = SHA-256("scp:did:" || did_string)
        // Private state routing_id = HKDF-SHA-256(ikm, ...)
        // These must never collide for the same DID.
        let did = "did:dht:abc123";
        let ikm = b"test-identity-key-material-32bytes!";

        let private_state_id = derive_private_state_routing_id(ikm, did);

        let mut did_doc_hasher = Sha256::new();
        did_doc_hasher.update(b"scp:did:");
        did_doc_hasher.update(did.as_bytes());
        let did_doc_id: [u8; 32] = did_doc_hasher.finalize().into();

        assert_ne!(
            private_state_id, did_doc_id,
            "private state routing ID must differ from DID document routing ID"
        );
    }

    #[test]
    fn routing_id_golden_vector() {
        // Known inputs for cross-platform verification.
        let ikm: [u8; 32] = {
            let mut k = [0u8; 32];
            k[31] = 1;
            k
        };
        let did = "did:dht:test";

        let id = derive_private_state_routing_id(&ikm, did);

        // Recompute expected value from reference algorithm.
        let salt = Sha256::digest(b"scp-private-state-salt-v1");
        let mut info = Vec::new();
        info.extend_from_slice(b"scp-private-state-v1");
        info.extend_from_slice(b"did:dht:test");
        let hk = Hkdf::<Sha256>::new(Some(&salt), &ikm);
        let mut expected = [0u8; 32];
        hk.expand(&info, &mut expected).unwrap();

        assert_eq!(
            id, expected,
            "routing ID must match reference HKDF-SHA-256 computation"
        );
    }

    // ===================================================================
    // H13: Private state hash chain
    // ===================================================================

    #[test]
    fn hash_chain_first_is_deterministic() {
        let event = b"block DID xyz at time T";

        let h1 = hash_chain_first(event);
        let h2 = hash_chain_first(event);

        assert_eq!(h1, h2, "same event data must produce same hash");
    }

    #[test]
    fn hash_chain_first_uses_domain_separator() {
        let event = b"test event";

        let with_domain = hash_chain_first(event);

        // Raw SHA-256 without domain separator must differ.
        let raw = Sha256::digest(event);
        let raw_bytes: [u8; 32] = raw.into();

        assert_ne!(
            with_domain, raw_bytes,
            "hash chain must include domain separator"
        );
    }

    #[test]
    fn hash_chain_extend_includes_previous_hash() {
        let event1 = b"event one";
        let event2 = b"event two";

        let h1 = hash_chain_first(event1);
        let h2 = hash_chain_extend(&h1, event2);

        // If we compute hash_chain_first for event2, it should differ
        // from the chained version (because the chain includes h1).
        let h2_unchained = hash_chain_first(event2);

        assert_ne!(
            h2, h2_unchained,
            "chained hash must differ from unchained hash"
        );
    }

    #[test]
    fn hash_chain_detects_reordering() {
        let event_a = b"block Alice";
        let event_b = b"block Bob";

        // Chain: A then B
        let h1 = hash_chain_first(event_a);
        let head_ab = hash_chain_extend(&h1, event_b);

        // Chain: B then A
        let h1_rev = hash_chain_first(event_b);
        let head_ba = hash_chain_extend(&h1_rev, event_a);

        assert_ne!(
            head_ab, head_ba,
            "different event ordering must produce different chain heads"
        );
    }

    #[test]
    fn hash_chain_detects_insertion() {
        let event_a = b"event A";
        let event_b = b"event B";
        let event_c = b"event C";

        // Original chain: A, C
        let h_a = hash_chain_first(event_a);
        let head_ac = hash_chain_extend(&h_a, event_c);

        // Tampered chain: A, B, C
        let h_a2 = hash_chain_first(event_a);
        let h_ab = hash_chain_extend(&h_a2, event_b);
        let head_abc = hash_chain_extend(&h_ab, event_c);

        assert_ne!(
            head_ac, head_abc,
            "inserting an event must change the chain head"
        );
    }

    #[test]
    fn verify_hash_chain_accepts_valid_chain() {
        let events: Vec<&[u8]> = vec![b"event 0", b"event 1", b"event 2"];

        // Build the expected head.
        let h0 = hash_chain_first(events[0]);
        let h1 = hash_chain_extend(&h0, events[1]);
        let head = hash_chain_extend(&h1, events[2]);

        assert!(verify_hash_chain(&events, &head), "valid chain must verify");
    }

    #[test]
    fn verify_hash_chain_rejects_tampered_event() {
        let events: Vec<&[u8]> = vec![b"event 0", b"event 1", b"event 2"];

        let h0 = hash_chain_first(events[0]);
        let h1 = hash_chain_extend(&h0, events[1]);
        let head = hash_chain_extend(&h1, events[2]);

        // Tamper with middle event.
        let tampered: Vec<&[u8]> = vec![b"event 0", b"TAMPERED", b"event 2"];

        assert!(
            !verify_hash_chain(&tampered, &head),
            "tampered chain must not verify"
        );
    }

    #[test]
    fn verify_hash_chain_rejects_empty() {
        let head = [0u8; 32];
        assert!(
            !verify_hash_chain(&[], &head),
            "empty event list must not verify"
        );
    }

    #[test]
    fn verify_hash_chain_single_event() {
        let event: &[u8] = b"only event";
        let head = hash_chain_first(event);

        assert!(
            verify_hash_chain(&[event], &head),
            "single-event chain must verify"
        );
    }

    #[test]
    fn hash_chain_golden_vector() {
        // Known inputs for cross-platform verification.
        let event0 = b"genesis";
        let event1 = b"second";

        // Reference computation:
        // h0 = SHA-256("SCP-PRIVATE-LOG-V1:" || "genesis")
        let mut hasher = Sha256::new();
        hasher.update(b"SCP-PRIVATE-LOG-V1:");
        hasher.update(b"genesis");
        let expected_h0: [u8; 32] = hasher.finalize().into();

        // h1 = SHA-256("SCP-PRIVATE-LOG-V1:" || h0 || "second")
        let mut hasher = Sha256::new();
        hasher.update(b"SCP-PRIVATE-LOG-V1:");
        hasher.update(expected_h0);
        hasher.update(b"second");
        let expected_h1: [u8; 32] = hasher.finalize().into();

        let h0 = hash_chain_first(event0);
        let h1 = hash_chain_extend(&h0, event1);

        assert_eq!(h0, expected_h0, "first event hash must match reference");
        assert_eq!(h1, expected_h1, "chained hash must match reference");
    }
}
