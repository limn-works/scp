//! Canonical context-ID generation shared across all FFI bridges.
//!
//! Spec §18.4.1 requires context IDs to be 64-character lowercase hex
//! strings so they can be embedded directly in
//! `scp://context/<context_id_hex>` URIs. Every `Scp::context_create`
//! implementation (`PyO3`, napi-rs, `UniFFI`) MUST
//! produce a value that satisfies this invariant. Hand-rolled
//! per-bridge implementations have twice regressed during
//! cross-cutting merges — most recently the `UniFFI` regression to
//! `ctx-<uuid>` called out in ADR-048 §7a. Centralising the helper
//! here makes the regression surface a type-check failure instead of
//! a test-run failure.
//!
//! # Implementation
//!
//! 32 cryptographically random bytes are drawn from [`rand_core::OsRng`]
//! (the operating-system CSPRNG — `getrandom(2)` on Linux, `BCrypt`
//! on Windows, `SecRandomCopyBytes` on Apple platforms). The bytes are
//! encoded via `hex::encode`, yielding a lowercase 64-character hex
//! string with no separators.
//!
//! `rand_core::OsRng` is used directly rather than `rand::thread_rng()`
//! so the helper needs only the minimal `rand_core` dependency.

use rand_core::RngCore;

/// Generates a spec-compliant context ID: 32 CSPRNG bytes, lowercase
/// hex-encoded to exactly 64 characters.
///
/// Per §18.4.1, context IDs MUST be valid lowercase hexadecimal so they
/// embed directly in `scp://context/<context_id_hex>` URIs.
///
/// # Determinism
///
/// The function is **non-deterministic** by design. Each call produces
/// a fresh ID. Callers that need reproducibility in tests must inject
/// the ID at a higher layer.
///
/// # Panics
///
/// Panics if the OS CSPRNG fails to produce randomness. That condition
/// indicates a fundamentally broken runtime (no kernel entropy, no
/// `getrandom` syscall, no `WebCrypto`); every bridge already treats
/// it as fatal because every downstream cryptographic operation
/// depends on the same RNG.
#[must_use]
pub fn generate_context_id() -> String {
    let mut bytes = [0u8; 32];
    rand_core::OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn generated_context_id_is_64_char_lowercase_hex() {
        let id = generate_context_id();
        assert_eq!(id.len(), 64, "context ID must be exactly 64 chars");
        assert!(
            id.chars()
                .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)),
            "context ID must contain only lowercase hex digits; got {id:?}"
        );
    }

    #[test]
    fn distinct_calls_produce_distinct_ids() {
        // Collision probability across 128 samples of 256-bit IDs is
        // negligible — so any duplicate indicates a broken RNG, not a
        // statistical fluke.
        let mut ids: std::collections::HashSet<String> = std::collections::HashSet::new();
        for _ in 0..128 {
            assert!(
                ids.insert(generate_context_id()),
                "duplicate context ID — RNG broken"
            );
        }
    }

    #[test]
    fn encoding_matches_hex_encode_of_32_byte_slice() {
        // The output must be indistinguishable from `hex::encode` over a
        // 32-byte slice. Confirm by re-decoding and checking length.
        let id = generate_context_id();
        let decoded = hex::decode(&id).expect("generated ID must be valid hex");
        assert_eq!(decoded.len(), 32, "decoded bytes must be exactly 32");
    }
}
