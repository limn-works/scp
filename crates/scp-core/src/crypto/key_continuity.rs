//! Key continuity fingerprint computation for SCP (spec section 9.11).
//!
//! Equivalent to Signal's "safety numbers." Allows two parties to verify they
//! have the correct keys for each other, detecting MITM on DID resolution.
//!
//! The fingerprint includes all three verification methods (`#0`, `#active`,
//! `#agent`) from each party's DID document. If a DID has no `#agent`
//! verification method, a domain-derived sentinel (`SHA-256("SCP-ABSENT-AGENT-KEY")`)
//! is used as a placeholder to maintain a fixed-length input and avoid
//! collision with the Ed25519 identity point (ADR-039).
//!
//! See spec section 9.11 for the full specification.

use sha2::{Digest, Sha256};

/// Domain-derived sentinel for absent `#agent` keys. Uses `SHA-256("SCP-ABSENT-AGENT-KEY")`
/// instead of zero bytes to avoid collision with the Ed25519 identity point
/// and to be self-documenting. Ensures fixed-length fingerprint input
/// regardless of agent binding state (spec section 9.11, ADR-039).
///
/// Precomputed: `SHA-256("SCP-ABSENT-AGENT-KEY")`.
const ABSENT_AGENT_KEY: [u8; 32] = {
    // SHA-256("SCP-ABSENT-AGENT-KEY") precomputed at compile time.
    // Verified in test `absent_agent_key_sentinel_is_correct`.
    [
        0x57, 0xb4, 0xf5, 0xf2, 0xd1, 0x61, 0x53, 0xbc, 0x6c, 0xa4, 0xef, 0x97, 0x19, 0x86, 0x8e,
        0x59, 0x53, 0xa4, 0xc5, 0xeb, 0x52, 0x7a, 0x66, 0xe7, 0x01, 0xb8, 0x44, 0xfa, 0x89, 0x2c,
        0xea, 0x58,
    ]
};

/// One party's key material for the key continuity fingerprint computation.
///
/// Contains the DID string and all three verification method public keys
/// (`#0` Identity Key, `#active` Active Signing Key, `#agent` Agent Signing
/// Key). Agent key absence is represented as `None`.
pub struct KeyContinuityParty<'a> {
    /// The party's DID string.
    pub did: &'a str,
    /// The party's `#0` Identity Key (32-byte Ed25519 public key).
    pub identity_key: &'a [u8; 32],
    /// The party's `#active` Active Signing Key (32-byte Ed25519 public key).
    pub active_key: &'a [u8; 32],
    /// The party's `#agent` Agent Signing Key, or `None` if no agent is bound.
    /// Absence uses `SHA-256("SCP-ABSENT-AGENT-KEY")` sentinel in the fingerprint
    /// computation (ADR-039).
    pub agent_key: Option<&'a [u8; 32]>,
}

/// Computes the key continuity fingerprint between two parties per spec
/// section 9.11.
///
/// The fingerprint is computed as:
/// ```text
/// SHA256(sort(alice_did, bob_did)
///     || first_identity_key || first_active_key || first_agent_key
///     || second_identity_key || second_active_key || second_agent_key)
/// ```
///
/// Where the DID blocks are ordered by lexicographic sort of the DID strings,
/// and agent key absence uses a domain-derived sentinel.
///
/// # Returns
///
/// The 32-byte SHA-256 fingerprint.
#[must_use]
pub fn compute_key_continuity_fingerprint(
    alice: &KeyContinuityParty<'_>,
    bob: &KeyContinuityParty<'_>,
) -> [u8; 32] {
    // Determine ordering: the two DID blocks are ordered by lexicographic sort
    // of the DID strings (spec section 9.11).
    let (first, second) = if alice.did <= bob.did {
        (alice, bob)
    } else {
        (bob, alice)
    };

    let mut hasher = Sha256::new();

    // Domain separator prevents cross-protocol signature confusion.
    hasher.update(b"SCP-KEY-CONTINUITY-V1:");

    // Length-prefix variable-length DID strings (prevents concatenation ambiguity).
    let len_prefix = |h: &mut Sha256, data: &[u8]| {
        h.update((data.len() as u32).to_be_bytes());
        h.update(data);
    };
    len_prefix(&mut hasher, first.did.as_bytes());
    len_prefix(&mut hasher, second.did.as_bytes());

    // Fixed-length 32-byte keys (no length prefix needed).
    hasher.update(first.identity_key);
    hasher.update(first.active_key);
    hasher.update(first.agent_key.unwrap_or(&ABSENT_AGENT_KEY));
    hasher.update(second.identity_key);
    hasher.update(second.active_key);
    hasher.update(second.agent_key.unwrap_or(&ABSENT_AGENT_KEY));

    hasher.finalize().into()
}

/// Formats a fingerprint as a 60-digit decimal number (first 200 bits) for
/// human display (spec section 9.11).
///
/// The fingerprint is interpreted as a big-endian unsigned integer and the
/// first 200 bits (25 bytes) are converted to a decimal string, left-padded
/// to exactly 60 digits.
#[must_use]
pub fn fingerprint_to_decimal(fingerprint: &[u8; 32]) -> String {
    // Take first 25 bytes (200 bits) per spec.
    let bytes = &fingerprint[..25];

    // Convert to a big-endian unsigned integer.
    // We use a simple manual base-10 conversion since we need arbitrary precision.
    let mut digits: Vec<u8> = vec![0]; // Start with 0

    for &byte in bytes {
        // Multiply current number by 256 and add the new byte.
        let mut carry: u16 = u16::from(byte);
        for d in digits.iter_mut().rev() {
            let val = u16::from(*d) * 256 + carry;
            *d = (val % 10) as u8;
            carry = val / 10;
        }
        while carry > 0 {
            digits.insert(0, (carry % 10) as u8);
            carry /= 10;
        }
    }

    let num_str: String = digits.iter().map(|d| char::from(b'0' + d)).collect();

    // Left-pad to exactly 60 digits.
    if num_str.len() >= 60 {
        num_str[..60].to_owned()
    } else {
        format!("{num_str:0>60}")
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn party<'a>(
        did: &'a str,
        identity_key: &'a [u8; 32],
        active_key: &'a [u8; 32],
        agent_key: Option<&'a [u8; 32]>,
    ) -> KeyContinuityParty<'a> {
        KeyContinuityParty {
            did,
            identity_key,
            active_key,
            agent_key,
        }
    }

    #[test]
    fn fingerprint_without_agent_keys_is_deterministic() {
        let alice_id = [1u8; 32];
        let alice_active = [2u8; 32];
        let bob_id = [3u8; 32];
        let bob_active = [4u8; 32];

        let alice = party("did:dht:z6MkAlice", &alice_id, &alice_active, None);
        let bob = party("did:dht:z6MkBob", &bob_id, &bob_active, None);

        let fp1 = compute_key_continuity_fingerprint(&alice, &bob);
        let fp2 = compute_key_continuity_fingerprint(&alice, &bob);
        assert_eq!(fp1, fp2, "same inputs must produce same fingerprint");
    }

    #[test]
    fn fingerprint_with_agent_keys_is_deterministic() {
        let alice_id = [1u8; 32];
        let alice_active = [2u8; 32];
        let alice_agent = [5u8; 32];
        let bob_id = [3u8; 32];
        let bob_active = [4u8; 32];
        let bob_agent = [6u8; 32];

        let alice = party(
            "did:dht:z6MkAlice",
            &alice_id,
            &alice_active,
            Some(&alice_agent),
        );
        let bob = party("did:dht:z6MkBob", &bob_id, &bob_active, Some(&bob_agent));

        let fp1 = compute_key_continuity_fingerprint(&alice, &bob);
        let fp2 = compute_key_continuity_fingerprint(&alice, &bob);
        assert_eq!(fp1, fp2, "same inputs must produce same fingerprint");
    }

    #[test]
    fn adding_agent_key_changes_fingerprint() {
        let alice_id = [1u8; 32];
        let alice_active = [2u8; 32];
        let alice_agent = [5u8; 32];
        let bob_id = [3u8; 32];
        let bob_active = [4u8; 32];

        let alice_no_agent = party("did:dht:z6MkAlice", &alice_id, &alice_active, None);
        let alice_with_agent = party(
            "did:dht:z6MkAlice",
            &alice_id,
            &alice_active,
            Some(&alice_agent),
        );
        let bob = party("did:dht:z6MkBob", &bob_id, &bob_active, None);

        let fp_without = compute_key_continuity_fingerprint(&alice_no_agent, &bob);
        let fp_with = compute_key_continuity_fingerprint(&alice_with_agent, &bob);
        assert_ne!(
            fp_without, fp_with,
            "adding an agent key must change the fingerprint"
        );
    }

    #[test]
    fn absent_agent_key_sentinel_is_correct() {
        // Verify the precomputed ABSENT_AGENT_KEY matches SHA-256("SCP-ABSENT-AGENT-KEY").
        let expected = Sha256::digest(b"SCP-ABSENT-AGENT-KEY");
        assert_eq!(
            ABSENT_AGENT_KEY,
            <[u8; 32]>::from(expected),
            "ABSENT_AGENT_KEY must equal SHA-256(\"SCP-ABSENT-AGENT-KEY\")"
        );
    }

    #[test]
    fn agent_key_absence_uses_domain_derived_sentinel() {
        let alice_id = [1u8; 32];
        let alice_active = [2u8; 32];
        let bob_id = [3u8; 32];
        let bob_active = [4u8; 32];

        let alice_none = party("did:dht:z6MkAlice", &alice_id, &alice_active, None);
        let alice_sentinel = party(
            "did:dht:z6MkAlice",
            &alice_id,
            &alice_active,
            Some(&ABSENT_AGENT_KEY),
        );
        let bob_none = party("did:dht:z6MkBob", &bob_id, &bob_active, None);
        let bob_sentinel = party(
            "did:dht:z6MkBob",
            &bob_id,
            &bob_active,
            Some(&ABSENT_AGENT_KEY),
        );

        let fp_none = compute_key_continuity_fingerprint(&alice_none, &bob_none);
        let fp_sentinel = compute_key_continuity_fingerprint(&alice_sentinel, &bob_sentinel);
        assert_eq!(
            fp_none, fp_sentinel,
            "None agent key must produce the same fingerprint as the sentinel value"
        );
    }

    #[test]
    fn agent_key_absence_differs_from_zero_bytes() {
        let alice_id = [1u8; 32];
        let alice_active = [2u8; 32];
        let bob_id = [3u8; 32];
        let bob_active = [4u8; 32];
        let zero_key = [0u8; 32];

        let alice_none = party("did:dht:z6MkAlice", &alice_id, &alice_active, None);
        let alice_zero = party(
            "did:dht:z6MkAlice",
            &alice_id,
            &alice_active,
            Some(&zero_key),
        );
        let bob_none = party("did:dht:z6MkBob", &bob_id, &bob_active, None);
        let bob_zero = party("did:dht:z6MkBob", &bob_id, &bob_active, Some(&zero_key));

        let fp_none = compute_key_continuity_fingerprint(&alice_none, &bob_none);
        let fp_zero = compute_key_continuity_fingerprint(&alice_zero, &bob_zero);
        assert_ne!(
            fp_none, fp_zero,
            "None agent key (sentinel) must differ from explicit zero bytes"
        );
    }

    #[test]
    fn fingerprint_is_symmetric_in_did_order() {
        let alice_id = [1u8; 32];
        let alice_active = [2u8; 32];
        let alice_agent = [5u8; 32];
        let bob_id = [3u8; 32];
        let bob_active = [4u8; 32];
        let bob_agent = [6u8; 32];

        let alice = party(
            "did:dht:z6MkAlice",
            &alice_id,
            &alice_active,
            Some(&alice_agent),
        );
        let bob = party("did:dht:z6MkBob", &bob_id, &bob_active, Some(&bob_agent));

        let fp_alice_first = compute_key_continuity_fingerprint(&alice, &bob);
        let fp_bob_first = compute_key_continuity_fingerprint(&bob, &alice);
        assert_eq!(
            fp_alice_first, fp_bob_first,
            "fingerprint must be the same regardless of argument order"
        );
    }

    #[test]
    fn different_keys_produce_different_fingerprints() {
        let alice_id = [1u8; 32];
        let alice_active = [2u8; 32];
        let bob_id = [3u8; 32];
        let bob_active = [4u8; 32];
        let bob_active_changed = [44u8; 32];

        let alice = party("did:dht:z6MkAlice", &alice_id, &alice_active, None);
        let bob = party("did:dht:z6MkBob", &bob_id, &bob_active, None);
        let bob_changed = party("did:dht:z6MkBob", &bob_id, &bob_active_changed, None);

        let fp1 = compute_key_continuity_fingerprint(&alice, &bob);
        let fp2 = compute_key_continuity_fingerprint(&alice, &bob_changed);
        assert_ne!(fp1, fp2, "different active key must change fingerprint");
    }

    #[test]
    fn fingerprint_to_decimal_produces_60_digits() {
        let fp = [0xABu8; 32];
        let decimal = fingerprint_to_decimal(&fp);
        assert_eq!(
            decimal.len(),
            60,
            "decimal representation must be exactly 60 digits"
        );
        assert!(
            decimal.chars().all(|c| c.is_ascii_digit()),
            "must be all digits"
        );
    }

    #[test]
    fn fingerprint_to_decimal_is_deterministic() {
        let fp = [0x42u8; 32];
        let d1 = fingerprint_to_decimal(&fp);
        let d2 = fingerprint_to_decimal(&fp);
        assert_eq!(d1, d2);
    }

    #[test]
    fn fingerprint_to_decimal_zero_input() {
        let fp = [0u8; 32];
        let decimal = fingerprint_to_decimal(&fp);
        assert_eq!(decimal.len(), 60);
        assert_eq!(
            decimal,
            "000000000000000000000000000000000000000000000000000000000000"
        );
    }
}
