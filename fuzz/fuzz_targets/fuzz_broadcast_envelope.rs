#![no_main]
#![allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]

//! BroadcastEnvelope deserialization fuzz target (Tier 2 — covers #1654).
//!
//! Target: `scp_protocol::crypto::sender_keys::BroadcastEnvelope` — the outer
//! container for AES-256-GCM encrypted broadcast content (spec §5.14).
//!
//! # Distinction from fuzz_broadcast_content
//!
//! `fuzz_broadcast_content` targets the *inner* `BroadcastContent` struct
//! (plaintext after decryption). This target fuzzes the *outer*
//! `BroadcastEnvelope` that arrives over the wire — before any decryption
//! occurs. Relays and receivers deserialize `BroadcastEnvelope` from
//! untrusted network bytes; a panic here is a P0 crash bug.
//!
//! # Structure
//!
//! `BroadcastEnvelope` uses `rmp_serde` named encoding (field-name map).
//! Key fields with fixed-size serde constraints:
//! - `signature`: exactly 64 bytes via `serde_signature_64`; wrong length → `Err`.
//! - `nonce`: exactly 12 bytes via `serde_nonce`; wrong length → `Err`.
//! - `encrypted_content`: bounded to 512 KiB via `serde_bounded_bytes`.
//!
//! All of these must return `Err` rather than panic on malformed input.
//!
//! # Security invariants
//! - I1: Must never panic on any byte sequence.
//! - I2: `encrypted_content` allocation bounded to 512 KiB (protocol constant).
//!
//! # Trust boundary
//!
//! B2: Post-MLS channel (authenticated but untrusted plaintext). In broadcast
//! contexts, `BroadcastEnvelope` bytes arrive as the `encrypted_blob` field
//! inside an `OuterEnvelope` after relay delivery.

use libfuzzer_sys::fuzz_target;
use scp_protocol::crypto::sender_keys::BroadcastEnvelope;

fuzz_target!(|data: &[u8]| {
    // Deserialize BroadcastEnvelope from raw MessagePack bytes.
    // Must never panic — all field-length violations, type mismatches,
    // and truncation must return Err.
    let _ = rmp_serde::from_slice::<BroadcastEnvelope>(data);
});
