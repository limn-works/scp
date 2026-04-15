#![no_main]
#![allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]

//! Redb SerializedBlob deserialization fuzz target (Tier 2 — covers #1653).
//!
//! Target: the `MessagePack` deserialization path for `SerializedBlob` —
//! the internal struct that `RedbBlobStore` reads from its redb `blobs` table.
//!
//! # Why SerializedBlob matters
//!
//! An adversary who can write to the redb database (e.g., via filesystem
//! access or a corrupt redb file) feeds bytes directly into
//! `rmp_serde::from_slice::<SerializedBlob>`. If this panics, the relay
//! crashes. This is trust boundary B1 for the relay persistence layer.
//!
//! # Strategy
//!
//! `SerializedBlob` is a private type in `scp-transport::native::redb_blob`.
//! The fuzz target cannot instantiate it directly. Instead, the target
//! mirrors the struct layout as a local `MirrorBlob` with the same field
//! names and serde attributes, then deserializes input bytes into it.
//! `rmp_serde` uses field-name matching for named encoding (the format
//! `RedbBlobStore` uses), so the mirror faithfully exercises the same
//! `rmpv` parsing paths.
//!
//! A second pass using `rmpv::Value` exercises the raw MessagePack tree
//! parser independently of serde.
//!
//! # Security invariants
//! - I1: Must never panic on any byte sequence.
//! - I2: `blob` field bounded — `rmp-serde` enforces allocation limits
//!   through `serde(with = "serde_bytes")` which reads a length prefix.

use libfuzzer_sys::fuzz_target;
use rmpv::Value;
use serde::{Deserialize, Serialize};

/// Mirror of `scp_transport::native::redb_blob::SerializedBlob`.
///
/// Field names, order, and serde attributes intentionally match the
/// production type so that fuzz inputs developed for this target are
/// also valid corpus seeds for the production deserialization path.
#[derive(Debug, Deserialize, Serialize)]
#[allow(dead_code)]
struct MirrorBlob {
    routing_id: [u8; 32],
    blob_id: [u8; 32],
    recipient_hint: Option<[u8; 32]>,
    blob_ttl: u32,
    stored_at: u64,
    expires_at: u64,
    #[serde(with = "serde_bytes")]
    blob: Vec<u8>,
}

fuzz_target!(|data: &[u8]| {
    // Path 1: mirror struct deserialization — mirrors RedbBlobStore::get/query.
    let _ = rmp_serde::from_slice::<MirrorBlob>(data);

    // Path 2: raw Value parse — exercises the rmpv tree parser independently.
    let _ = rmp_serde::from_slice::<Value>(data);

    // I1: neither call above may panic.
});
