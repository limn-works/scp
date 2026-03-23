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

use super::bip39_wordlist::BIP39_ENGLISH;
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
    // DID strings are validated to ≤512 bytes at the FFI boundary, so the u32
    // conversion is always safe. `unwrap_or(u32::MAX)` is unreachable
    // defense-in-depth to satisfy clippy's `cast_possible_truncation` lint.
    let len_prefix = |h: &mut Sha256, data: &[u8]| {
        let len = u32::try_from(data.len()).unwrap_or(u32::MAX);
        h.update(len.to_be_bytes());
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

/// Converts a fingerprint to a 12-word BIP-39 mnemonic (spec section 9.11).
///
/// Uses the first 128 bits (16 bytes) of the fingerprint hash, appends a
/// 4-bit SHA-256 checksum (per BIP-39), producing 132 bits split into 12
/// groups of 11 bits. Each 11-bit value indexes into the 2048-word BIP-39
/// English word list.
///
/// # Returns
///
/// A string of 12 space-separated English words.
#[must_use]
pub fn fingerprint_to_mnemonic(fingerprint: &[u8; 32]) -> String {
    // Take first 16 bytes (128 bits) per spec.
    let entropy = &fingerprint[..16];

    // BIP-39 checksum: SHA-256 of entropy, take first CS bits.
    // For 128-bit entropy, CS = 128 / 32 = 4 bits.
    let checksum_hash = Sha256::digest(entropy);
    let checksum_byte = checksum_hash[0]; // First byte; we need top 4 bits.

    // Build a 132-bit buffer: 128 bits of entropy + 4 bits of checksum.
    // We work with the 16 entropy bytes plus one extra byte whose top 4 bits
    // are the checksum.
    let mut bits = [0u8; 17];
    bits[..16].copy_from_slice(entropy);
    bits[16] = checksum_byte & 0xF0; // Only top 4 bits matter.

    // Extract 12 groups of 11 bits each from the 132-bit buffer.
    // We read a 24-bit window (3 bytes) to avoid overflow when bit_idx > 5.
    let mut words: Vec<&str> = Vec::with_capacity(12);
    for i in 0..12 {
        let bit_offset = i * 11;
        let byte_idx = bit_offset / 8;
        let bit_idx = bit_offset % 8;

        // Read a 3-byte window starting at byte_idx. For 17-byte buffer,
        // byte_idx ranges 0..15. byte_idx+2 is at most 17, but bits has
        // exactly 17 elements, so use 0 for any out-of-bounds byte.
        let b0 = u32::from(bits[byte_idx]);
        let b1 = u32::from(if byte_idx + 1 < bits.len() {
            bits[byte_idx + 1]
        } else {
            0
        });
        let b2 = u32::from(if byte_idx + 2 < bits.len() {
            bits[byte_idx + 2]
        } else {
            0
        });
        let window = (b0 << 16) | (b1 << 8) | b2;
        // The 11 bits start at position `bit_idx` from the top of the 24-bit window.
        let val = (window >> (24 - 11 - bit_idx)) & 0x07FF;

        words.push(BIP39_ENGLISH[val as usize]);
    }

    words.join(" ")
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

    // -----------------------------------------------------------------------
    // Agent key rotation and removal tests (SCP-AB-022 AC5-6)
    // -----------------------------------------------------------------------

    #[test]
    fn agent_key_rotation_changes_fingerprint() {
        let alice_id = [1u8; 32];
        let alice_active = [2u8; 32];
        let alice_agent_a = [10u8; 32];
        let alice_agent_b = [20u8; 32];
        let bob_id = [3u8; 32];
        let bob_active = [4u8; 32];

        let alice_a = party(
            "did:dht:z6MkAlice",
            &alice_id,
            &alice_active,
            Some(&alice_agent_a),
        );
        let bob = party("did:dht:z6MkBob", &bob_id, &bob_active, None);

        let fp_before = compute_key_continuity_fingerprint(&alice_a, &bob);

        // Rotate Alice's agent key.
        let alice_b = party(
            "did:dht:z6MkAlice",
            &alice_id,
            &alice_active,
            Some(&alice_agent_b),
        );
        let fp_after = compute_key_continuity_fingerprint(&alice_b, &bob);

        assert_ne!(
            fp_before, fp_after,
            "rotating an agent key must change the fingerprint"
        );
    }

    #[test]
    fn agent_key_removal_changes_fingerprint() {
        let alice_id = [1u8; 32];
        let alice_active = [2u8; 32];
        let alice_agent = [10u8; 32];
        let bob_id = [3u8; 32];
        let bob_active = [4u8; 32];

        let alice_with = party(
            "did:dht:z6MkAlice",
            &alice_id,
            &alice_active,
            Some(&alice_agent),
        );
        let bob = party("did:dht:z6MkBob", &bob_id, &bob_active, None);

        let fp_with = compute_key_continuity_fingerprint(&alice_with, &bob);

        // Remove Alice's agent key.
        let alice_without = party("did:dht:z6MkAlice", &alice_id, &alice_active, None);
        let fp_without = compute_key_continuity_fingerprint(&alice_without, &bob);

        assert_ne!(
            fp_with, fp_without,
            "removing an agent key must change the fingerprint (None uses sentinel)"
        );
    }

    #[test]
    fn different_agent_keys_produce_different_fingerprints() {
        let alice_id = [1u8; 32];
        let alice_active = [2u8; 32];
        let alice_agent = [10u8; 32];
        let bob_id = [3u8; 32];
        let bob_active = [4u8; 32];
        let bob_agent_a = [20u8; 32];
        let bob_agent_b = [30u8; 32];

        let alice = party(
            "did:dht:z6MkAlice",
            &alice_id,
            &alice_active,
            Some(&alice_agent),
        );
        let bob_a = party("did:dht:z6MkBob", &bob_id, &bob_active, Some(&bob_agent_a));

        let fp1 = compute_key_continuity_fingerprint(&alice, &bob_a);

        // Change Bob's agent key.
        let bob_b = party("did:dht:z6MkBob", &bob_id, &bob_active, Some(&bob_agent_b));
        let fp2 = compute_key_continuity_fingerprint(&alice, &bob_b);

        assert_ne!(
            fp1, fp2,
            "different agent keys must produce different fingerprints"
        );
    }

    #[test]
    fn agent_key_rotation_one_side_only() {
        let alice_id = [1u8; 32];
        let alice_active = [2u8; 32];
        let alice_agent_v1 = [10u8; 32];
        let alice_agent_v2 = [11u8; 32];
        let bob_id = [3u8; 32];
        let bob_active = [4u8; 32];
        let bob_agent = [20u8; 32];

        let alice_v1 = party(
            "did:dht:z6MkAlice",
            &alice_id,
            &alice_active,
            Some(&alice_agent_v1),
        );
        let bob = party("did:dht:z6MkBob", &bob_id, &bob_active, Some(&bob_agent));

        let fp_before = compute_key_continuity_fingerprint(&alice_v1, &bob);

        // Alice rotates her agent key.
        let alice_v2 = party(
            "did:dht:z6MkAlice",
            &alice_id,
            &alice_active,
            Some(&alice_agent_v2),
        );
        let fp_after = compute_key_continuity_fingerprint(&alice_v2, &bob);

        assert_ne!(
            fp_before, fp_after,
            "one-sided agent key rotation must change the fingerprint"
        );
    }

    #[test]
    fn fingerprint_stability_across_agent_key_re_addition() {
        let alice_id = [1u8; 32];
        let alice_active = [2u8; 32];
        let alice_agent = [10u8; 32];
        let bob_id = [3u8; 32];
        let bob_active = [4u8; 32];

        let alice_with = party(
            "did:dht:z6MkAlice",
            &alice_id,
            &alice_active,
            Some(&alice_agent),
        );
        let bob = party("did:dht:z6MkBob", &bob_id, &bob_active, None);

        let fp_original = compute_key_continuity_fingerprint(&alice_with, &bob);

        // Remove agent key.
        let alice_none = party("did:dht:z6MkAlice", &alice_id, &alice_active, None);
        let fp_removed = compute_key_continuity_fingerprint(&alice_none, &bob);
        assert_ne!(fp_original, fp_removed, "removal must change fingerprint");

        // Re-add the same agent key.
        let alice_re_added = party(
            "did:dht:z6MkAlice",
            &alice_id,
            &alice_active,
            Some(&alice_agent),
        );
        let fp_re_added = compute_key_continuity_fingerprint(&alice_re_added, &bob);

        assert_eq!(
            fp_original, fp_re_added,
            "re-adding the same agent key must restore the original fingerprint"
        );
    }

    // -----------------------------------------------------------------------
    // BIP-39 mnemonic tests (spec section 9.11)
    // -----------------------------------------------------------------------

    #[test]
    fn mnemonic_produces_12_words() {
        let fp = [0xABu8; 32];
        let mnemonic = fingerprint_to_mnemonic(&fp);
        assert_eq!(
            mnemonic.split(' ').count(),
            12,
            "mnemonic must be exactly 12 words"
        );
    }

    #[test]
    fn mnemonic_is_deterministic() {
        let fp = [0x42u8; 32];
        let m1 = fingerprint_to_mnemonic(&fp);
        let m2 = fingerprint_to_mnemonic(&fp);
        assert_eq!(m1, m2, "same fingerprint must produce same mnemonic");
    }

    #[test]
    fn mnemonic_stability_same_keys_same_words() {
        let alice_id = [1u8; 32];
        let alice_active = [2u8; 32];
        let bob_id = [3u8; 32];
        let bob_active = [4u8; 32];

        let alice = party("did:dht:z6MkAlice", &alice_id, &alice_active, None);
        let bob = party("did:dht:z6MkBob", &bob_id, &bob_active, None);

        let fp1 = compute_key_continuity_fingerprint(&alice, &bob);
        let fp2 = compute_key_continuity_fingerprint(&alice, &bob);

        let m1 = fingerprint_to_mnemonic(&fp1);
        let m2 = fingerprint_to_mnemonic(&fp2);
        assert_eq!(
            m1, m2,
            "same keys must always produce the same mnemonic words"
        );
    }

    #[test]
    fn mnemonic_changes_with_different_keys() {
        let alice_id = [1u8; 32];
        let alice_active = [2u8; 32];
        let bob_id = [3u8; 32];
        let bob_active_a = [4u8; 32];
        let bob_active_b = [44u8; 32];

        let alice = party("did:dht:z6MkAlice", &alice_id, &alice_active, None);
        let bob_a = party("did:dht:z6MkBob", &bob_id, &bob_active_a, None);
        let bob_b = party("did:dht:z6MkBob", &bob_id, &bob_active_b, None);

        let fp_a = compute_key_continuity_fingerprint(&alice, &bob_a);
        let fp_b = compute_key_continuity_fingerprint(&alice, &bob_b);

        let m_a = fingerprint_to_mnemonic(&fp_a);
        let m_b = fingerprint_to_mnemonic(&fp_b);
        assert_ne!(m_a, m_b, "different keys must produce different mnemonics");
    }

    #[test]
    fn mnemonic_all_words_are_in_bip39_list() {
        use super::BIP39_ENGLISH;

        let fp = [0x73u8; 32];
        let mnemonic = fingerprint_to_mnemonic(&fp);
        for word in mnemonic.split(' ') {
            assert!(
                BIP39_ENGLISH.contains(&word),
                "word '{word}' must be in the BIP-39 word list"
            );
        }
    }

    #[test]
    fn mnemonic_zero_fingerprint() {
        // All-zero entropy: each 11-bit group is 0 → "abandon" (index 0).
        // But the checksum of 16 zero bytes changes the last word.
        let fp = [0u8; 32];
        let mnemonic = fingerprint_to_mnemonic(&fp);
        let words: Vec<&str> = mnemonic.split(' ').collect();
        assert_eq!(words.len(), 12);
        // First 11 words should be "abandon" (all zero bits in entropy portion).
        for word in &words[..11] {
            assert_eq!(
                *word, "abandon",
                "zero entropy bits must map to 'abandon' (index 0)"
            );
        }
        // 12th word includes 4 checksum bits, so it differs from "abandon".
        // SHA-256(16 zero bytes) starts with 0x37 → top 4 bits = 0011 = 3
        // Last word's 11 bits: 0000000_0011 = 3 → "about"
        assert_eq!(
            words[11], "about",
            "checksum bits must produce the correct final word"
        );
    }

    #[test]
    fn bip39_wordlist_has_2048_entries() {
        use super::BIP39_ENGLISH;
        assert_eq!(
            BIP39_ENGLISH.len(),
            2048,
            "BIP-39 word list must have exactly 2048 entries"
        );
    }

    #[test]
    fn bip39_wordlist_is_sorted() {
        use super::BIP39_ENGLISH;
        for i in 1..BIP39_ENGLISH.len() {
            assert!(
                BIP39_ENGLISH[i - 1] < BIP39_ENGLISH[i],
                "BIP-39 word list must be sorted: '{}' >= '{}'",
                BIP39_ENGLISH[i - 1],
                BIP39_ENGLISH[i]
            );
        }
    }
}
