//! `SCP-OUTLET-REGISTRATION-V2:` canonical preimage and digest construction
//! (SCP-OUT-040, spec §5.4.1).
//!
//! The [`OutletRegistration`] operator signs `SHA-256(preimage)` where
//! `preimage` is a strict byte concatenation pinned by §5.4.1. This module
//! is the single canonical builder; every bridge, conformance fixture, and
//! verifier funnels through [`compute_outlet_registration_canonical_bytes`]
//! and [`outlet_registration_v2_preimage`] so the bytes never diverge across
//! implementations.
//!
//! # Preimage layout (§5.4.1)
//!
//! ```text
//! SHA-256(
//!   "SCP-OUTLET-REGISTRATION-V2:"
//!   || BE32(len(outlet_id)) || outlet_id
//!   || kind_byte                       // 0x00 Query, 0x01 Action
//!   || BE32(len(name)) || name
//!   || description_hash                // SHA-256(description_utf8_bytes), 32 bytes
//!   || BE32(len(operator_did)) || operator_did
//!   || schema_hash                     // SHA-256(MessagePack(schema)), 32 bytes
//!   || implementation_hash             // 32 bytes, fixed width
//!   || test_vectors_hash               // SHA-256(MessagePack(test_vectors)), 32 bytes
//!   || cost_hash                       // SHA-256(MessagePack(cost)) or SHA-256(0x00), 32 bytes
//!   || catalog_hash                    // SHA-256(MessagePack(message_catalog)), 32 bytes
//!   || registered_at_be                // BE64
//! )
//! ```
//!
//! Every variable-length field is BE32-length-prefixed, closing the
//! "split-shift" preimage-collision class that the unprefixed pre-rename
//! concatenation admitted (§5.4.1 closing paragraph). Every operator-authored
//! string field (`description`, `message_catalog`) is committed via a
//! dedicated 32-byte hash term so silent edits cannot escape the signature.
//!
//! # `MessagePack` encoding rules
//!
//! - `schema_hash` covers the `MessagePack` encoding of [`OutletSchema`] —
//!   `input_schema`, `output_schema`, and any future aggregate-schema slot.
//! - `test_vectors_hash` covers the `MessagePack` encoding of
//!   `Vec<OutletTestVector>` — the array preserves operator-authored
//!   insertion order; each element serializes its declared fields in source
//!   order.
//! - `cost_hash` covers the `MessagePack` encoding of `Some(OutletCost)`
//!   when present; when absent, it is `SHA-256(0x00)` (1-byte sentinel)
//!   per §5.4.1.
//! - `catalog_hash` covers
//!   [`canonical_catalog_messagepack`](super::message_catalog::canonical_catalog_messagepack);
//!   an empty catalog hashes to `SHA-256(0x90)` deterministically.

use sha2::{Digest, Sha256};

use super::message_catalog::canonical_catalog_messagepack;
use super::registration::OutletRegistration;
use super::registry::{OutletCost, OutletSchema, OutletTestVector};

/// Domain separator for the V2 outlet-registration signature preimage
/// (§5.4.1).
///
/// The pre-rename `SCP-TOOL-REGISTRATION-V1:` separator is structurally
/// invalid post-ADR-049: pre-migration signatures are explicitly not honored.
pub const OUTLET_REGISTRATION_V2_DOMAIN: &[u8] = b"SCP-OUTLET-REGISTRATION-V2:";

/// 1-byte sentinel hashed (via SHA-256) to produce `cost_hash` when the
/// registration declares `cost: None` (§5.4.1).
const COST_ABSENT_SENTINEL: u8 = 0x00;

/// Returns the raw V2 preimage byte sequence whose SHA-256 is the canonical
/// signing target (§5.4.1).
///
/// This is the byte sequence the operator's Ed25519 key signs over (after
/// SHA-256). Conformance fixtures expose this hex-encoded so independent
/// implementers can byte-compare without first agreeing on a hashing rule.
/// Pathological inputs (variable-length field > 4 GiB) saturate the
/// length prefix to `u32::MAX` — see [`push_length_prefixed`] — which
/// produces a non-matching signature rather than panicking.
#[must_use]
pub fn outlet_registration_v2_preimage(registration: &OutletRegistration) -> Vec<u8> {
    let mut buf = Vec::with_capacity(256);
    buf.extend_from_slice(OUTLET_REGISTRATION_V2_DOMAIN);

    push_length_prefixed(&mut buf, registration.outlet_id.as_bytes());
    buf.push(registration.kind.canonical_byte());
    push_length_prefixed(&mut buf, registration.name.as_bytes());
    buf.extend_from_slice(&description_hash(&registration.description));
    push_length_prefixed(&mut buf, registration.operator_did.as_bytes());
    buf.extend_from_slice(&schema_hash(&registration.schema));
    buf.extend_from_slice(&registration.implementation_hash);
    buf.extend_from_slice(&test_vectors_hash(&registration.test_vectors));
    buf.extend_from_slice(&cost_hash(registration.cost.as_ref()));
    buf.extend_from_slice(&catalog_hash(&registration.message_catalog));
    buf.extend_from_slice(&registration.registered_at.to_be_bytes());
    buf
}

/// Returns `SHA-256` of the V2 canonical preimage (§5.4.1).
///
/// This is the message Ed25519 signs and verifies. Equivalent to
/// `Sha256::digest(outlet_registration_v2_preimage(reg))`.
#[must_use]
pub fn compute_outlet_registration_canonical_bytes(registration: &OutletRegistration) -> [u8; 32] {
    Sha256::digest(outlet_registration_v2_preimage(registration)).into()
}

/// `description_hash = SHA-256(description.as_bytes())` (§5.4.1).
///
/// The `description` field is up to 4 KiB of operator-authored prose
/// displayed to prospective invokers; committing it via a dedicated 32-byte
/// term closes the operator-authored-prose covert-channel surface symmetric
/// to `catalog_hash` (round-5 ADR-049).
#[must_use]
pub fn description_hash(description: &str) -> [u8; 32] {
    Sha256::digest(description.as_bytes()).into()
}

/// `schema_hash = SHA-256(MessagePack(schema))` (§5.4.1).
///
/// Covers only the `schema` body — `input_schema`, `output_schema`, and any
/// future aggregate-schema slot — so the catalog and description require
/// separate terms. `MessagePack` encoding of the owned-string [`OutletSchema`]
/// is infallible in practice; encoder failure (e.g., a custom serde
/// implementation that returns an error) produces an empty buffer rather
/// than panicking, matching the upstream `unwrap_or_default` convention used
/// by the V1 builder this replaced.
#[must_use]
pub fn schema_hash(schema: &OutletSchema) -> [u8; 32] {
    let bytes = rmp_serde::to_vec(schema).unwrap_or_default();
    Sha256::digest(bytes).into()
}

/// `test_vectors_hash = SHA-256(MessagePack(test_vectors))` (§5.4.1).
///
/// `MessagePack` of a `Vec<OutletTestVector>` of owned strings and JSON
/// values is infallible in practice; encoder failure produces an empty
/// buffer rather than panicking.
#[must_use]
pub fn test_vectors_hash(test_vectors: &[OutletTestVector]) -> [u8; 32] {
    let bytes = rmp_serde::to_vec(test_vectors).unwrap_or_default();
    Sha256::digest(bytes).into()
}

/// `cost_hash = SHA-256(MessagePack(cost))` when `Some`, else
/// `SHA-256(0x00)` (§5.4.1).
///
/// The 1-byte absent-sentinel preserves fixed 32-byte width across both
/// branches so the V2 preimage layout has no length-conditional terms.
#[must_use]
pub fn cost_hash(cost: Option<&OutletCost>) -> [u8; 32] {
    cost.map_or_else(
        || Sha256::digest([COST_ABSENT_SENTINEL]).into(),
        |c| {
            let bytes = rmp_serde::to_vec(c).unwrap_or_default();
            Sha256::digest(bytes).into()
        },
    )
}

/// `catalog_hash = SHA-256(MessagePack(message_catalog))` (§5.4.1).
///
/// Empty catalogs hash to `SHA-256(0x90)` (the 1-byte `MessagePack` fixarray
/// header for length 0); see
/// [`canonical_catalog_messagepack`](super::message_catalog::canonical_catalog_messagepack)
/// for the canonical encoding rule.
#[must_use]
pub fn catalog_hash(catalog: &[super::message_catalog::MessageTemplate]) -> [u8; 32] {
    Sha256::digest(canonical_catalog_messagepack(catalog)).into()
}

/// Pushes `BE32(len(bytes)) || bytes` onto `buf`.
///
/// `u32` is the §5.4.1 length-prefix width; the §5.4.1 per-field caps
/// (≤ 4 KiB description, ≤ 64 KiB schema, etc.) keep the conversion
/// well below `u32::MAX` for protocol-conformant inputs. If a caller does
/// pass an input that exceeds 4 GiB the `len` is saturated to `u32::MAX`
/// rather than panicking — the resulting preimage will simply not match
/// any operator's signature, which is the desired failure mode.
fn push_length_prefixed(buf: &mut Vec<u8>, bytes: &[u8]) {
    let len = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(bytes);
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::context::outlets::message_catalog::{MessageTemplate, empty_catalog_messagepack};

    #[test]
    fn description_hash_is_sha256_of_utf8_bytes() {
        let want: [u8; 32] = Sha256::digest(b"hello").into();
        assert_eq!(description_hash("hello"), want);
    }

    #[test]
    fn description_hash_distinct_for_one_byte_change() {
        let h1 = description_hash("policy v1");
        let h2 = description_hash("policy v2");
        assert_ne!(h1, h2);
    }

    #[test]
    fn cost_hash_absent_branch_is_sha256_of_0x00() {
        let want: [u8; 32] = Sha256::digest([0x00u8]).into();
        assert_eq!(cost_hash(None), want);
    }

    #[test]
    fn catalog_hash_empty_is_sha256_of_0x90() {
        let want: [u8; 32] = Sha256::digest(empty_catalog_messagepack()).into();
        let got = catalog_hash(&[]);
        assert_eq!(got, want);
        // Sanity: the constant byte is the MessagePack fixarray-len-0 byte.
        assert_eq!(empty_catalog_messagepack(), &[0x90][..]);
    }

    #[test]
    fn catalog_hash_distinct_for_one_byte_template_change() {
        let a = vec![MessageTemplate::try_new("k", "old").unwrap()];
        let b = vec![MessageTemplate::try_new("k", "ole").unwrap()];
        assert_ne!(catalog_hash(&a), catalog_hash(&b));
    }
}
