//! Forward compatibility conformance tests per spec §13.5.1 and §13.9 items 3/5.
//!
//! §13.5.1 requires that unknown fields in `MessagePack` maps are handled
//! according to the type:
//! - **`OuterEnvelope` / `InnerEnvelope`:** unknown fields MUST be preserved for
//!   forward-compatible roundtripping (via their `extensions` `HashMap`).
//! - **All other wire types:** unknown fields MUST be ignored.
//!
//! §13.9 item 3: "Ignore unknown fields in all deserialized structures."
//! §13.9 item 5: "Preserve unknown fields when forwarding (relays only)."

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::cast_possible_truncation
)]

use std::borrow::Cow;

// ---------------------------------------------------------------------------
// Helper: inject unknown fields into a MessagePack named map
// ---------------------------------------------------------------------------

/// Takes `MessagePack` bytes encoding a named map (`rmp_serde::to_vec_named`
/// output), appends extra string→string key-value pairs, and returns new
/// valid msgpack bytes. This simulates a message from a newer protocol
/// version containing fields the current version doesn't define.
///
/// Works by:
/// 1. Parsing the map header to get the current entry count and body offset
/// 2. Building a new map header with count + N
/// 3. Appending N new fixstr key → fixstr value pairs to the map body
///
/// This approach operates at the raw msgpack level, avoiding JSON
/// intermediate representations that can't handle `serde_bytes` binary data.
fn inject_unknown_msgpack_fields(original: &[u8], extras: &[(&str, &str)]) -> Vec<u8> {
    assert!(!original.is_empty(), "original bytes must not be empty");

    // Parse the map header.
    let first = original[0];
    let (old_count, body_offset) = if first & 0b1111_0000 == 0x80 {
        // fixmap: 0x80..0x8f, lower 4 bits = count
        (u32::from(first & 0x0F), 1)
    } else if first == 0xDE {
        // map16: 0xDE, followed by 2-byte big-endian count
        let count = u32::from(u16::from_be_bytes([original[1], original[2]]));
        (count, 3)
    } else if first == 0xDF {
        // map32: 0xDF, followed by 4-byte big-endian count
        let count = u32::from_be_bytes([original[1], original[2], original[3], original[4]]);
        (count, 5)
    } else {
        panic!("expected msgpack map header, got 0x{first:02X}");
    };

    let new_count = old_count + extras.len() as u32;

    // Build the new header.
    let mut result = Vec::with_capacity(original.len() + extras.len() * 40);
    if new_count <= 15 {
        result.push(0x80 | (new_count as u8));
    } else if new_count <= 0xFFFF {
        result.push(0xDE);
        result.extend_from_slice(&(new_count as u16).to_be_bytes());
    } else {
        result.push(0xDF);
        result.extend_from_slice(&new_count.to_be_bytes());
    }

    // Copy the original map body (everything after the old header).
    result.extend_from_slice(&original[body_offset..]);

    // Append extra key-value pairs as fixstr entries.
    for (key, value) in extras {
        encode_msgpack_str(&mut result, key);
        encode_msgpack_str(&mut result, value);
    }

    result
}

/// Encodes a string in msgpack format (fixstr, str8, str16, or str32).
fn encode_msgpack_str(buf: &mut Vec<u8>, s: &str) {
    let len = s.len();
    if len <= 31 {
        buf.push(0xA0 | (len as u8));
    } else if len <= 0xFF {
        buf.push(0xD9);
        buf.push(len as u8);
    } else if len <= 0xFFFF {
        buf.push(0xDA);
        buf.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        buf.push(0xDB);
        buf.extend_from_slice(&(len as u32).to_be_bytes());
    }
    buf.extend_from_slice(s.as_bytes());
}

/// Same as `inject_unknown_msgpack_fields` but for JSON strings.
fn inject_unknown_json_fields(
    original_json: &str,
    extra_fields: &[(&str, serde_json::Value)],
) -> String {
    let mut val: serde_json::Value =
        serde_json::from_str(original_json).expect("original must be valid JSON");
    let map = val.as_object_mut().expect("wire types are JSON objects");
    for (key, value) in extra_fields {
        map.insert((*key).to_string(), value.clone());
    }
    serde_json::to_string(&val).expect("re-encode to JSON")
}

/// Standard set of unknown string-valued fields simulating a future SCP/1.2
/// protocol version. Used by types that only need to verify ignore-on-deser.
fn future_msgpack_fields() -> Vec<(&'static str, &'static str)> {
    vec![
        ("v2_routing_priority", "42"),
        ("future_capability_flags", "extended"),
        ("scp_1_2_metadata", "nested_value"),
    ]
}

/// Injects unknown fields with diverse `MessagePack` value types (integer,
/// boolean, nested map, array) into a named-map msgpack blob. This exercises
/// the `#[serde(flatten)]` `extensions` `HashMap<String, rmpv::Value>`
/// path more thoroughly than string-only injection.
fn inject_diverse_unknown_msgpack_fields(original: &[u8]) -> Vec<u8> {
    assert!(!original.is_empty(), "original bytes must not be empty");

    let extras: &[(&str, &[u8])] = &[
        // string value
        ("v2_routing_priority", &{
            let mut buf = Vec::new();
            encode_msgpack_str(&mut buf, "high");
            buf
        }),
        // positive fixint (42)
        ("future_int_field", &[0x2A]),
        // boolean true (0xC3)
        ("future_bool_field", &[0xC3]),
        // nested fixmap {\"nested_key\": true} — fixmap(1) + fixstr(10) + true
        ("future_nested_obj", &{
            let mut buf = Vec::new();
            // fixmap with 1 entry
            buf.push(0x81);
            encode_msgpack_str(&mut buf, "nested_key");
            buf.push(0xC3); // true
            buf
        }),
        // fixarray [1, 2, 3] — fixarray(3) + fixint(1) + fixint(2) + fixint(3)
        ("future_array_field", &[0x93, 0x01, 0x02, 0x03]),
    ];

    // Parse the map header.
    let first = original[0];
    let (old_count, body_offset) = if first & 0b1111_0000 == 0x80 {
        (u32::from(first & 0x0F), 1)
    } else if first == 0xDE {
        let count = u32::from(u16::from_be_bytes([original[1], original[2]]));
        (count, 3)
    } else if first == 0xDF {
        let count = u32::from_be_bytes([original[1], original[2], original[3], original[4]]);
        (count, 5)
    } else {
        panic!("expected msgpack map header, got 0x{first:02X}");
    };

    let new_count = old_count + extras.len() as u32;

    let mut result = Vec::with_capacity(original.len() + extras.len() * 40);
    if new_count <= 15 {
        result.push(0x80 | (new_count as u8));
    } else if new_count <= 0xFFFF {
        result.push(0xDE);
        result.extend_from_slice(&(new_count as u16).to_be_bytes());
    } else {
        result.push(0xDF);
        result.extend_from_slice(&new_count.to_be_bytes());
    }

    // Copy the original map body (everything after the old header).
    result.extend_from_slice(&original[body_offset..]);

    // Append extra key-value pairs with diverse value types.
    for (key, value_bytes) in extras {
        encode_msgpack_str(&mut result, key);
        result.extend_from_slice(value_bytes);
    }

    result
}

/// Injects a single Binary-typed extension field into a named-map msgpack blob.
/// This simulates a future protocol version adding a binary field (e.g., a
/// cryptographic digest, certificate, or raw binary payload). The Binary
/// type (0xC4/0xC5/0xC6 headers) is distinct from Array in `MsgPack` — this
/// test proves `rmpv::Value` preserves the distinction.
fn inject_binary_extension_field(original: &[u8], key: &str, binary_data: &[u8]) -> Vec<u8> {
    assert!(!original.is_empty(), "original bytes must not be empty");

    // Parse the map header.
    let first = original[0];
    let (old_count, body_offset) = if first & 0b1111_0000 == 0x80 {
        (u32::from(first & 0x0F), 1)
    } else if first == 0xDE {
        let count = u32::from(u16::from_be_bytes([original[1], original[2]]));
        (count, 3)
    } else if first == 0xDF {
        let count = u32::from_be_bytes([original[1], original[2], original[3], original[4]]);
        (count, 5)
    } else {
        panic!("expected msgpack map header, got 0x{first:02X}");
    };

    let new_count = old_count + 1;

    let mut result = Vec::with_capacity(original.len() + key.len() + binary_data.len() + 16);
    if new_count <= 15 {
        result.push(0x80 | (new_count as u8));
    } else if new_count <= 0xFFFF {
        result.push(0xDE);
        result.extend_from_slice(&(new_count as u16).to_be_bytes());
    } else {
        result.push(0xDF);
        result.extend_from_slice(&new_count.to_be_bytes());
    }

    // Copy the original map body.
    result.extend_from_slice(&original[body_offset..]);

    // Append the key as a string.
    encode_msgpack_str(&mut result, key);

    // Append the value as msgpack Binary (bin8/bin16/bin32).
    let len = binary_data.len();
    if len <= 0xFF {
        result.push(0xC4); // bin8
        result.push(len as u8);
    } else if len <= 0xFFFF {
        result.push(0xC5); // bin16
        result.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        result.push(0xC6); // bin32
        result.extend_from_slice(&(len as u32).to_be_bytes());
    }
    result.extend_from_slice(binary_data);

    result
}

fn future_json_fields() -> Vec<(&'static str, serde_json::Value)> {
    vec![
        ("v2_routing_priority", serde_json::json!(42)),
        ("future_capability_flags", serde_json::json!("extended")),
        ("scp_1_2_metadata", serde_json::json!({"nested": true})),
    ]
}

// ===========================================================================
// §13.5.1 — OuterEnvelope: unknown fields MUST be preserved
// ===========================================================================

mod outer_envelope {
    use super::*;
    use scp_core::envelope::outer::{
        OuterEnvelope, SCP_OUTER_ENVELOPE_VERSION, create_outer_envelope,
    };

    fn make_outer() -> OuterEnvelope {
        create_outer_envelope(&[0xAA; 32], None, 3600, vec![0x01, 0x02, 0x03]).unwrap()
    }

    /// §13.5.1: Unknown fields in `OuterEnvelope` are preserved via `extensions`.
    #[test]
    fn unknown_fields_are_preserved_msgpack() {
        let envelope = make_outer();
        let bytes = envelope.to_bytes().unwrap();
        let with_extras = inject_unknown_msgpack_fields(&bytes, &future_msgpack_fields());

        let result = OuterEnvelope::from_bytes(&with_extras);
        assert!(
            result.is_ok(),
            "OuterEnvelope must accept unknown fields per §13.5.1, got: {:?}",
            result.unwrap_err()
        );
        let decoded = result.unwrap();
        // Known fields preserved
        assert_eq!(decoded.version, SCP_OUTER_ENVELOPE_VERSION);
        assert_eq!(decoded.routing_id, vec![0xAA; 32]);
        assert_eq!(decoded.blob_ttl, 3600);
        // Unknown fields preserved in extensions
        assert!(
            decoded.extensions.contains_key("v2_routing_priority"),
            "extensions must contain v2_routing_priority"
        );
        assert!(
            decoded.extensions.contains_key("future_capability_flags"),
            "extensions must contain future_capability_flags"
        );
        assert!(
            decoded.extensions.contains_key("scp_1_2_metadata"),
            "extensions must contain scp_1_2_metadata"
        );
    }

    /// §13.9 item 5: Relays MUST preserve unknown fields when forwarding.
    /// Verify that serialize -> deserialize round-trip preserves unknown fields.
    #[test]
    fn unknown_fields_survive_roundtrip() {
        let envelope = make_outer();
        let bytes = envelope.to_bytes().unwrap();
        let with_extras = inject_unknown_msgpack_fields(&bytes, &future_msgpack_fields());
        let decoded = OuterEnvelope::from_bytes(&with_extras).unwrap();

        // Re-serialize and re-deserialize -- extensions must survive
        let re_bytes = decoded.to_bytes().unwrap();
        let re_decoded = OuterEnvelope::from_bytes(&re_bytes).unwrap();
        assert_eq!(
            re_decoded.extensions.len(),
            decoded.extensions.len(),
            "unknown fields must survive roundtrip"
        );
        for key in decoded.extensions.keys() {
            assert!(
                re_decoded.extensions.contains_key(key),
                "extension key '{key}' lost during roundtrip"
            );
        }
    }
}

// ===========================================================================
// §13.5.1 — InnerEnvelope: unknown fields MUST be preserved for roundtripping
// ===========================================================================

mod inner_envelope {
    use super::*;
    use scp_core::envelope::inner::InnerEnvelope;

    /// §13.5.1: `InnerEnvelope` MUST preserve unknown fields for
    /// forward-compatible roundtripping.
    #[test]
    fn unknown_fields_are_preserved_msgpack() {
        // Build a valid InnerEnvelope, serialize to msgpack, inject extra fields.
        let inner = InnerEnvelope {
            version: 256,
            context_id: "ctx-test".to_string(),
            sender_did: "did:dht:test".to_string(),
            epoch: 1,
            generation: 0,
            sequence: 1,
            timestamp: 1_700_000_000,
            message_type: scp_core::envelope::inner::MessageType::Content,
            payload_hash: [0xAA; 32],
            payload: vec![0x01, 0x02],
            provenance: None,
            provenance_hash: [0xBB; 32],
            signing_key_id: scp_identity::SigningKeyId::Active,
            signature: [0xCC; 64],
            extensions: std::collections::HashMap::new(),
        };
        let bytes = rmp_serde::to_vec_named(&inner).unwrap();
        let with_extras = inject_unknown_msgpack_fields(&bytes, &future_msgpack_fields());

        let result: Result<InnerEnvelope, _> = rmp_serde::from_slice(&with_extras);
        assert!(
            result.is_ok(),
            "InnerEnvelope must accept unknown fields per §13.5.1, got: {:?}",
            result.unwrap_err()
        );
        let decoded = result.unwrap();
        assert_eq!(decoded.context_id, "ctx-test");
        assert_eq!(decoded.sender_did, "did:dht:test");
        assert_eq!(decoded.epoch, 1);
        assert_eq!(decoded.signature, [0xCC; 64]);

        // Unknown fields must be preserved in extensions (#863).
        assert!(
            decoded.extensions.contains_key("v2_routing_priority"),
            "extensions must contain v2_routing_priority"
        );
        assert!(
            decoded.extensions.contains_key("future_capability_flags"),
            "extensions must contain future_capability_flags"
        );
        assert!(
            decoded.extensions.contains_key("scp_1_2_metadata"),
            "extensions must contain scp_1_2_metadata"
        );
    }

    /// §13.5.1: Unknown fields in `InnerEnvelope` MUST survive roundtrip
    /// for forward-compatible preservation. Verify serialize -> deserialize ->
    /// serialize -> deserialize preserves extensions.
    #[test]
    fn unknown_fields_survive_roundtrip() {
        let inner = InnerEnvelope {
            version: 256,
            context_id: "ctx-roundtrip".to_string(),
            sender_did: "did:dht:roundtrip".to_string(),
            epoch: 1,
            generation: 0,
            sequence: 1,
            timestamp: 1_700_000_000,
            message_type: scp_core::envelope::inner::MessageType::Content,
            payload_hash: [0xAA; 32],
            payload: vec![0x01, 0x02],
            provenance: None,
            provenance_hash: [0xBB; 32],
            signing_key_id: scp_identity::SigningKeyId::Active,
            signature: [0xCC; 64],
            extensions: std::collections::HashMap::new(),
        };
        let bytes = rmp_serde::to_vec_named(&inner).unwrap();
        let with_extras = inject_unknown_msgpack_fields(&bytes, &future_msgpack_fields());
        let decoded: InnerEnvelope = rmp_serde::from_slice(&with_extras).unwrap();

        // Re-serialize and re-deserialize -- extensions must survive
        let re_bytes = rmp_serde::to_vec_named(&decoded).unwrap();
        let re_decoded: InnerEnvelope = rmp_serde::from_slice(&re_bytes).unwrap();
        assert_eq!(
            re_decoded.extensions.len(),
            decoded.extensions.len(),
            "unknown fields must survive roundtrip"
        );
        for key in decoded.extensions.keys() {
            assert!(
                re_decoded.extensions.contains_key(key),
                "extension key '{key}' lost during roundtrip"
            );
        }
    }

    /// §13.5.1: Diverse value types (integer, boolean, nested object, array)
    /// must be preserved, not just strings.
    #[test]
    fn diverse_value_types_are_preserved() {
        let inner = InnerEnvelope {
            version: 256,
            context_id: "ctx-diverse".to_string(),
            sender_did: "did:dht:diverse".to_string(),
            epoch: 1,
            generation: 0,
            sequence: 1,
            timestamp: 1_700_000_000,
            message_type: scp_core::envelope::inner::MessageType::Content,
            payload_hash: [0xAA; 32],
            payload: vec![0x01, 0x02],
            provenance: None,
            provenance_hash: [0xBB; 32],
            signing_key_id: scp_identity::SigningKeyId::Active,
            signature: [0xCC; 64],
            extensions: std::collections::HashMap::new(),
        };
        let bytes = rmp_serde::to_vec_named(&inner).unwrap();
        let with_extras = inject_diverse_unknown_msgpack_fields(&bytes);

        let decoded: InnerEnvelope = rmp_serde::from_slice(&with_extras)
            .expect("InnerEnvelope must accept diverse value types");

        // String value
        assert_eq!(
            decoded.extensions.get("v2_routing_priority"),
            Some(&rmpv::Value::from("high")),
            "string extension value must be preserved"
        );
        // Integer value
        assert_eq!(
            decoded.extensions.get("future_int_field"),
            Some(&rmpv::Value::from(42)),
            "integer extension value must be preserved"
        );
        // Boolean value
        assert_eq!(
            decoded.extensions.get("future_bool_field"),
            Some(&rmpv::Value::Boolean(true)),
            "boolean extension value must be preserved"
        );
        // Nested object — rmpv::Value::Map with (String, Boolean) pair
        let expected_nested = rmpv::Value::Map(vec![(
            rmpv::Value::from("nested_key"),
            rmpv::Value::Boolean(true),
        )]);
        assert_eq!(
            decoded.extensions.get("future_nested_obj"),
            Some(&expected_nested),
            "nested object extension value must be preserved"
        );
        // Array value
        let expected_array = rmpv::Value::Array(vec![
            rmpv::Value::from(1),
            rmpv::Value::from(2),
            rmpv::Value::from(3),
        ]);
        assert_eq!(
            decoded.extensions.get("future_array_field"),
            Some(&expected_array),
            "array extension value must be preserved"
        );

        // Roundtrip: re-serialize and re-deserialize must preserve all types
        let re_bytes = rmp_serde::to_vec_named(&decoded).unwrap();
        let re_decoded: InnerEnvelope = rmp_serde::from_slice(&re_bytes).unwrap();
        assert_eq!(
            re_decoded.extensions, decoded.extensions,
            "diverse extension values must survive roundtrip"
        );
    }

    /// §13.5.1 / F7: A `MessagePack` Binary extension field MUST roundtrip as
    /// Binary, not degrade to Array. This is the key motivation for using
    /// `rmpv::Value` instead of `serde_json::Value` in `InnerEnvelope` extensions.
    #[test]
    fn binary_extension_survives_roundtrip_as_binary() {
        let inner = InnerEnvelope {
            version: 256,
            context_id: "ctx-binary".to_string(),
            sender_did: "did:dht:binary".to_string(),
            epoch: 1,
            generation: 0,
            sequence: 1,
            timestamp: 1_700_000_000,
            message_type: scp_core::envelope::inner::MessageType::Content,
            payload_hash: [0xAA; 32],
            payload: vec![0x01, 0x02],
            provenance: None,
            provenance_hash: [0xBB; 32],
            signing_key_id: scp_identity::SigningKeyId::Active,
            signature: [0xCC; 64],
            extensions: std::collections::HashMap::new(),
        };
        let bytes = rmp_serde::to_vec_named(&inner).unwrap();

        // Inject a Binary-typed extension field at the raw msgpack level.
        // This simulates a future protocol version that adds a binary field.
        let binary_data: &[u8] = &[0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE];
        let with_binary = inject_binary_extension_field(&bytes, "future_binary_field", binary_data);

        // First deserialization: binary must land in extensions as Binary.
        let decoded: InnerEnvelope = rmp_serde::from_slice(&with_binary)
            .expect("InnerEnvelope must accept binary extension fields");

        let ext = decoded
            .extensions
            .get("future_binary_field")
            .expect("extensions must contain future_binary_field");

        // CRITICAL: The value must be Binary, not Array.
        assert!(
            matches!(ext, rmpv::Value::Binary(_)),
            "binary extension field must be rmpv::Value::Binary, got: {ext:?}"
        );
        assert_eq!(
            ext,
            &rmpv::Value::Binary(binary_data.to_vec()),
            "binary content must be preserved exactly"
        );

        // Roundtrip: re-serialize and re-deserialize — must stay Binary.
        let re_bytes = rmp_serde::to_vec_named(&decoded).unwrap();
        let re_decoded: InnerEnvelope = rmp_serde::from_slice(&re_bytes).unwrap();
        let re_ext = re_decoded
            .extensions
            .get("future_binary_field")
            .expect("binary extension must survive roundtrip");
        assert!(
            matches!(re_ext, rmpv::Value::Binary(_)),
            "binary extension must remain Binary after roundtrip, got: {re_ext:?}"
        );
        assert_eq!(
            re_ext,
            &rmpv::Value::Binary(binary_data.to_vec()),
            "binary content must survive roundtrip exactly"
        );
    }
}

// ===========================================================================
// §13.5.1 — ChunkEnvelope: unknown fields MUST be ignored
// ===========================================================================

mod chunk_envelope {
    use super::*;
    use scp_core::envelope::chunk::ChunkEnvelope;

    /// §13.5.1, §13.9 item 3: `ChunkEnvelope` MUST ignore unknown fields.
    #[test]
    fn unknown_fields_are_ignored_msgpack() {
        let chunk = ChunkEnvelope {
            message_id: [0xAA; 32],
            chunk_index: 0,
            total_chunks: 3,
            payload_hash: [0xBB; 32],
            data: vec![0x01, 0x02, 0x03],
        };
        let bytes = rmp_serde::to_vec_named(&chunk).unwrap();
        let with_extras = inject_unknown_msgpack_fields(&bytes, &future_msgpack_fields());

        let result: Result<ChunkEnvelope, _> = rmp_serde::from_slice(&with_extras);
        assert!(
            result.is_ok(),
            "ChunkEnvelope must ignore unknown fields per §13.5.1, got: {:?}",
            result.unwrap_err()
        );
        let decoded = result.unwrap();
        assert_eq!(decoded.message_id, [0xAA; 32]);
        assert_eq!(decoded.chunk_index, 0);
        assert_eq!(decoded.total_chunks, 3);
        assert_eq!(decoded.payload_hash, [0xBB; 32]);
        assert_eq!(decoded.data, vec![0x01, 0x02, 0x03]);
    }
}

// ===========================================================================
// §13.5.1 — BroadcastEnvelope: unknown fields MUST be ignored
// ===========================================================================

mod broadcast_envelope {
    use super::*;
    use scp_core::crypto::sender_keys::broadcast::BroadcastEnvelope;

    /// §13.5.1, §13.9 item 3: `BroadcastEnvelope` MUST ignore unknown fields.
    #[test]
    fn unknown_fields_are_ignored_msgpack() {
        let env = BroadcastEnvelope {
            version: 256,
            context_id: "ctx-broadcast".to_string(),
            author_did: "did:dht:broadcaster".to_string(),
            sequence: 1,
            timestamp: 1_700_000_000,
            key_epoch: 1,
            provenance: None,
            signature: [0xDD; 64],
            nonce: [0xEE; 12],
            encrypted_content: vec![0x01, 0x02],
        };
        let bytes = rmp_serde::to_vec_named(&env).unwrap();
        let with_extras = inject_unknown_msgpack_fields(&bytes, &future_msgpack_fields());

        let result: Result<BroadcastEnvelope, _> = rmp_serde::from_slice(&with_extras);
        assert!(
            result.is_ok(),
            "BroadcastEnvelope must ignore unknown fields per §13.5.1, got: {:?}",
            result.unwrap_err()
        );
        let decoded = result.unwrap();
        assert_eq!(decoded.context_id, "ctx-broadcast");
        assert_eq!(decoded.author_did, "did:dht:broadcaster");
        assert_eq!(decoded.sequence, 1);
    }
}

// ===========================================================================
// §13.5.1 — Sender key wire types: unknown fields MUST be ignored
// ===========================================================================

mod sender_key_types {
    use super::*;
    use scp_core::crypto::sender_keys::key_protocol::{
        BlockNotification, SenderKeyEpochAdvance, SenderKeyRequest, SenderKeyResponse,
    };

    /// §13.9 item 3: `SenderKeyEpochAdvance` MUST ignore unknown fields.
    #[test]
    fn epoch_advance_ignores_unknown_fields() {
        let advance = SenderKeyEpochAdvance {
            sender_did: "did:dht:sender".to_string(),
            epoch: 5,
            signer_key_ref: scp_identity::SigningKeyId::Active,
            signature: [0xAA; 64],
        };
        let bytes = rmp_serde::to_vec_named(&advance).unwrap();
        let with_extras = inject_unknown_msgpack_fields(&bytes, &future_msgpack_fields());

        let result: Result<SenderKeyEpochAdvance, _> = rmp_serde::from_slice(&with_extras);
        assert!(
            result.is_ok(),
            "SenderKeyEpochAdvance must ignore unknown fields, got: {:?}",
            result.unwrap_err()
        );
        let decoded = result.unwrap();
        assert_eq!(decoded.sender_did, "did:dht:sender");
        assert_eq!(decoded.epoch, 5);
    }

    /// §13.9 item 3: `SenderKeyRequest` MUST ignore unknown fields.
    #[test]
    fn request_ignores_unknown_fields() {
        let request = SenderKeyRequest {
            requester_did: "did:dht:requester".to_string(),
            sender_did: "did:dht:sender".to_string(),
            epoch: 3,
            wrapping_pubkey: [0xBB; 32],
            nonce: [0xCC; 16],
            timestamp: 1_700_000_000,
            signature: [0xDD; 64],
        };
        let bytes = rmp_serde::to_vec_named(&request).unwrap();
        let with_extras = inject_unknown_msgpack_fields(&bytes, &future_msgpack_fields());

        let result: Result<SenderKeyRequest, _> = rmp_serde::from_slice(&with_extras);
        assert!(
            result.is_ok(),
            "SenderKeyRequest must ignore unknown fields, got: {:?}",
            result.unwrap_err()
        );
        let decoded = result.unwrap();
        assert_eq!(decoded.requester_did, "did:dht:requester");
        assert_eq!(decoded.epoch, 3);
    }

    /// §13.9 item 3: `SenderKeyResponse` MUST ignore unknown fields.
    #[test]
    fn response_ignores_unknown_fields() {
        let response = SenderKeyResponse {
            sender_did: "did:dht:sender".to_string(),
            epoch: 3,
            hpke_sealed_key: [0xEE; 60],
            ephemeral_pubkey: [0xFF; 32],
            request_nonce: [0xAA; 16],
        };
        let bytes = rmp_serde::to_vec_named(&response).unwrap();
        let with_extras = inject_unknown_msgpack_fields(&bytes, &future_msgpack_fields());

        let result: Result<SenderKeyResponse, _> = rmp_serde::from_slice(&with_extras);
        assert!(
            result.is_ok(),
            "SenderKeyResponse must ignore unknown fields, got: {:?}",
            result.unwrap_err()
        );
        let decoded = result.unwrap();
        assert_eq!(decoded.sender_did, "did:dht:sender");
        assert_eq!(decoded.epoch, 3);
    }

    /// §13.9 item 3: `BlockNotification` MUST ignore unknown fields.
    #[test]
    fn block_notification_ignores_unknown_fields() {
        let notification = BlockNotification {
            notification_type: "block".to_string(),
            blocker: "did:dht:blocker".to_string(),
            blocked: "did:dht:blocked".to_string(),
            signing_key_id: scp_identity::SigningKeyId::Active,
            timestamp: 1_700_000_000,
            signature: [0xBB; 64],
        };
        let bytes = rmp_serde::to_vec_named(&notification).unwrap();
        let with_extras = inject_unknown_msgpack_fields(&bytes, &future_msgpack_fields());

        let result: Result<BlockNotification, _> = rmp_serde::from_slice(&with_extras);
        assert!(
            result.is_ok(),
            "BlockNotification must ignore unknown fields, got: {:?}",
            result.unwrap_err()
        );
        let decoded = result.unwrap();
        assert_eq!(decoded.blocker, "did:dht:blocker");
        assert_eq!(decoded.blocked, "did:dht:blocked");
    }
}

// ===========================================================================
// §13.5.1 — Attestation wire types: unknown fields MUST be ignored
// ===========================================================================

mod attestation_types {
    use super::*;
    use scp_core::identity::attestation::{
        AttestationClaim, AttestationEvidence, AttestationProof, AttestationRevocation,
        IdentityLinkAttestation, VerificationMethod,
    };

    /// §13.9 item 3: `AttestationClaim` MUST ignore unknown fields (JSON).
    #[test]
    fn claim_ignores_unknown_fields_json() {
        let claim = AttestationClaim::new(
            "github.com".to_string(),
            "alice".to_string(),
            Some("12345".to_string()),
        );
        let json = serde_json::to_string(&claim).unwrap();
        let with_extras = inject_unknown_json_fields(&json, &future_json_fields());

        let result: Result<AttestationClaim, _> = serde_json::from_str(&with_extras);
        assert!(
            result.is_ok(),
            "AttestationClaim must ignore unknown JSON fields, got: {:?}",
            result.unwrap_err()
        );
        let decoded = result.unwrap();
        assert_eq!(decoded.platform, "github.com");
        assert_eq!(decoded.platform_handle, "alice");
    }

    /// §13.9 item 3: `AttestationClaim` MUST ignore unknown fields (msgpack).
    #[test]
    fn claim_ignores_unknown_fields_msgpack() {
        let claim = AttestationClaim::new(
            "github.com".to_string(),
            "alice".to_string(),
            Some("12345".to_string()),
        );
        let bytes = rmp_serde::to_vec_named(&claim).unwrap();
        let with_extras = inject_unknown_msgpack_fields(&bytes, &future_msgpack_fields());

        let result: Result<AttestationClaim, _> = rmp_serde::from_slice(&with_extras);
        assert!(
            result.is_ok(),
            "AttestationClaim must ignore unknown msgpack fields, got: {:?}",
            result.unwrap_err()
        );
        let decoded = result.unwrap();
        assert_eq!(decoded.platform, "github.com");
    }

    /// §13.9 item 3: `AttestationEvidence` MUST ignore unknown fields (JSON).
    #[test]
    fn evidence_ignores_unknown_fields_json() {
        let evidence = AttestationEvidence {
            method: VerificationMethod::Oauth,
            proof: AttestationProof::OauthVerified {
                provider: "github.com".to_string(),
                subject_id: "token123".to_string(),
                verified_at: 1_700_000_000,
            },
            verified_at: 1_700_000_000,
            verifier_did: None,
        };
        let json = serde_json::to_string(&evidence).unwrap();
        let with_extras = inject_unknown_json_fields(&json, &future_json_fields());

        let result: Result<AttestationEvidence, _> = serde_json::from_str(&with_extras);
        assert!(
            result.is_ok(),
            "AttestationEvidence must ignore unknown JSON fields, got: {:?}",
            result.unwrap_err()
        );
        let decoded = result.unwrap();
        assert_eq!(decoded.method, VerificationMethod::Oauth);
    }

    /// §13.9 item 3: `AttestationEvidence` MUST ignore unknown fields (msgpack).
    #[test]
    fn evidence_ignores_unknown_fields_msgpack() {
        let evidence = AttestationEvidence {
            method: VerificationMethod::Oauth,
            proof: AttestationProof::OauthVerified {
                provider: "github.com".to_string(),
                subject_id: "token123".to_string(),
                verified_at: 1_700_000_000,
            },
            verified_at: 1_700_000_000,
            verifier_did: None,
        };
        let bytes = rmp_serde::to_vec_named(&evidence).unwrap();
        let with_extras = inject_unknown_msgpack_fields(&bytes, &future_msgpack_fields());

        let result: Result<AttestationEvidence, _> = rmp_serde::from_slice(&with_extras);
        assert!(
            result.is_ok(),
            "AttestationEvidence must ignore unknown msgpack fields, got: {:?}",
            result.unwrap_err()
        );
        let decoded = result.unwrap();
        assert_eq!(decoded.method, VerificationMethod::Oauth);
    }

    /// §13.9 item 3: `AttestationRevocation` MUST ignore unknown fields (JSON).
    #[test]
    fn revocation_ignores_unknown_fields_json() {
        let rev = AttestationRevocation::new("#scp-revocations".to_string());
        let json = serde_json::to_string(&rev).unwrap();
        let with_extras = inject_unknown_json_fields(&json, &future_json_fields());

        let result: Result<AttestationRevocation, _> = serde_json::from_str(&with_extras);
        assert!(
            result.is_ok(),
            "AttestationRevocation must ignore unknown JSON fields, got: {:?}",
            result.unwrap_err()
        );
        let decoded = result.unwrap();
        assert_eq!(&*decoded.method, "did_document");
    }

    /// §13.9 item 3: `AttestationRevocation` MUST ignore unknown fields (msgpack).
    #[test]
    fn revocation_ignores_unknown_fields_msgpack() {
        let rev = AttestationRevocation::new("#scp-revocations".to_string());
        let bytes = rmp_serde::to_vec_named(&rev).unwrap();
        let with_extras = inject_unknown_msgpack_fields(&bytes, &future_msgpack_fields());

        let result: Result<AttestationRevocation, _> = rmp_serde::from_slice(&with_extras);
        assert!(
            result.is_ok(),
            "AttestationRevocation must ignore unknown msgpack fields, got: {:?}",
            result.unwrap_err()
        );
        let decoded = result.unwrap();
        assert_eq!(&*decoded.method, "did_document");
    }

    /// §13.9 item 3: `IdentityLinkAttestation` MUST ignore unknown fields (JSON).
    #[test]
    fn identity_link_attestation_ignores_unknown_fields_json() {
        let attestation = IdentityLinkAttestation {
            id: "test-id-001".to_string(),
            attestation_type: Cow::Borrowed("identity_link"),
            issuer: "did:dht:alice".into(),
            subject: "did:dht:alice".into(),
            issued_at: 1_700_000_000,
            expires_at: None,
            claim: AttestationClaim::new("github.com".to_string(), "alice".to_string(), None),
            evidence: AttestationEvidence {
                method: VerificationMethod::Oauth,
                proof: AttestationProof::OauthVerified {
                    provider: "github.com".to_string(),
                    subject_id: "token".to_string(),
                    verified_at: 1_700_000_000,
                },
                verified_at: 1_700_000_000,
                verifier_did: None,
            },
            revocation: AttestationRevocation::new("#scp-revocations".to_string()),
            signature: vec![0xAA; 64],
        };
        let json = serde_json::to_string(&attestation).unwrap();
        let with_extras = inject_unknown_json_fields(&json, &future_json_fields());

        let result: Result<IdentityLinkAttestation, _> = serde_json::from_str(&with_extras);
        assert!(
            result.is_ok(),
            "IdentityLinkAttestation must ignore unknown JSON fields, got: {:?}",
            result.unwrap_err()
        );
        let decoded = result.unwrap();
        assert_eq!(decoded.id, "test-id-001");
        assert_eq!(&*decoded.issuer, "did:dht:alice");
    }

    /// §13.9 item 3: `IdentityLinkAttestation` MUST ignore unknown fields (msgpack).
    #[test]
    fn identity_link_attestation_ignores_unknown_fields_msgpack() {
        let attestation = IdentityLinkAttestation {
            id: "test-id-001".to_string(),
            attestation_type: Cow::Borrowed("identity_link"),
            issuer: "did:dht:alice".into(),
            subject: "did:dht:alice".into(),
            issued_at: 1_700_000_000,
            expires_at: None,
            claim: AttestationClaim::new("github.com".to_string(), "alice".to_string(), None),
            evidence: AttestationEvidence {
                method: VerificationMethod::Oauth,
                proof: AttestationProof::OauthVerified {
                    provider: "github.com".to_string(),
                    subject_id: "token".to_string(),
                    verified_at: 1_700_000_000,
                },
                verified_at: 1_700_000_000,
                verifier_did: None,
            },
            revocation: AttestationRevocation::new("#scp-revocations".to_string()),
            signature: vec![0xAA; 64],
        };
        let bytes = rmp_serde::to_vec_named(&attestation).unwrap();
        let with_extras = inject_unknown_msgpack_fields(&bytes, &future_msgpack_fields());

        let result: Result<IdentityLinkAttestation, _> = rmp_serde::from_slice(&with_extras);
        assert!(
            result.is_ok(),
            "IdentityLinkAttestation must ignore unknown msgpack fields, got: {:?}",
            result.unwrap_err()
        );
        let decoded = result.unwrap();
        assert_eq!(decoded.id, "test-id-001");
    }
}

// ===========================================================================
// §13.5.1 — ContextParams: unknown fields MUST be ignored
// ===========================================================================

mod context_params {
    use super::*;
    use scp_core::context::params::ContextParams;

    /// §13.5.1: `ContextParams` is explicitly named as a type that MUST ignore
    /// unknown fields. Verify msgpack deserialization with extra fields succeeds.
    #[test]
    fn unknown_fields_are_ignored_msgpack() {
        let params = ContextParams::default();
        let bytes = rmp_serde::to_vec_named(&params).unwrap();
        let with_extras = inject_unknown_msgpack_fields(&bytes, &future_msgpack_fields());

        let result: Result<ContextParams, _> = rmp_serde::from_slice(&with_extras);
        assert!(
            result.is_ok(),
            "ContextParams must ignore unknown fields per §13.5.1, got: {:?}",
            result.unwrap_err()
        );
        let decoded = result.unwrap();
        // Verify known fields are preserved at their defaults
        assert!(!decoded.discoverable);
        assert!(decoded.ttl.is_none());
        assert!(decoded.economic_policy.is_none());
        assert!(decoded.template_id.is_none());
        assert!(decoded.min_protocol_version.is_none());
    }

    /// §13.5.1: `ContextParams` MUST ignore unknown fields in JSON as well.
    #[test]
    fn unknown_fields_are_ignored_json() {
        let params = ContextParams::default();
        let json = serde_json::to_string(&params).unwrap();
        let with_extras = inject_unknown_json_fields(&json, &future_json_fields());

        let result: Result<ContextParams, _> = serde_json::from_str(&with_extras);
        assert!(
            result.is_ok(),
            "ContextParams must ignore unknown JSON fields per §13.5.1, got: {:?}",
            result.unwrap_err()
        );
        let decoded = result.unwrap();
        assert!(!decoded.discoverable);
        assert!(decoded.ttl.is_none());
    }
}

// ===========================================================================
// §13.5.1 — Access key wire types: unknown fields MUST be ignored
// ===========================================================================

mod access_key_types {
    use super::*;
    use scp_core::crypto::access_keys::wire::{AccessKeyRequest, AccessKeyResponse};

    /// §13.9 item 3: `AccessKeyRequest` MUST ignore unknown fields.
    #[test]
    fn request_ignores_unknown_fields_msgpack() {
        let request = AccessKeyRequest {
            requester_did: "did:dht:requester".to_string(),
            context_id: "ctx-access-test".to_string(),
            wrapping_pubkey: vec![0xBB; 32],
            nonce: [0xCC; 16],
            timestamp: 1_700_000_000,
            signature: vec![0xDD; 64],
        };
        let bytes = rmp_serde::to_vec_named(&request).unwrap();
        let with_extras = inject_unknown_msgpack_fields(&bytes, &future_msgpack_fields());

        let result: Result<AccessKeyRequest, _> = rmp_serde::from_slice(&with_extras);
        assert!(
            result.is_ok(),
            "AccessKeyRequest must ignore unknown fields per §13.5.1, got: {:?}",
            result.unwrap_err()
        );
        let decoded = result.unwrap();
        assert_eq!(decoded.requester_did, "did:dht:requester");
        assert_eq!(decoded.context_id, "ctx-access-test");
        assert_eq!(decoded.wrapping_pubkey, vec![0xBB; 32]);
        assert_eq!(decoded.nonce, [0xCC; 16]);
        assert_eq!(decoded.timestamp, 1_700_000_000);
        assert_eq!(decoded.signature, vec![0xDD; 64]);
    }

    /// §13.9 item 3: `AccessKeyResponse` MUST ignore unknown fields.
    #[test]
    fn response_ignores_unknown_fields_msgpack() {
        let response = AccessKeyResponse {
            context_id: "ctx-access-test".to_string(),
            member_did: "did:dht:member".to_string(),
            epoch: 5,
            hpke_sealed_key: vec![0xEE; 60],
            ephemeral_pubkey: vec![0xFF; 32],
        };
        let bytes = rmp_serde::to_vec_named(&response).unwrap();
        let with_extras = inject_unknown_msgpack_fields(&bytes, &future_msgpack_fields());

        let result: Result<AccessKeyResponse, _> = rmp_serde::from_slice(&with_extras);
        assert!(
            result.is_ok(),
            "AccessKeyResponse must ignore unknown fields per §13.5.1, got: {:?}",
            result.unwrap_err()
        );
        let decoded = result.unwrap();
        assert_eq!(decoded.context_id, "ctx-access-test");
        assert_eq!(decoded.member_did, "did:dht:member");
        assert_eq!(decoded.epoch, 5);
        assert_eq!(decoded.hpke_sealed_key, vec![0xEE; 60]);
        assert_eq!(decoded.ephemeral_pubkey, vec![0xFF; 32]);
    }
}
