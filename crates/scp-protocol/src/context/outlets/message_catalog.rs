//! Outlet `message_catalog` types and validators (SCP-OUT-040, spec §5.4.1, §5.4.4).
//!
//! Every [`OutletRegistration`](super::registration::OutletRegistration) carries a
//! `message_catalog: Vec<MessageTemplate>` of at most 256 entries. The catalog
//! defines the bounded set of human-readable strings the outlet may surface
//! through the `OutletError.message` HMAC channel (§5.4.4 "Message structural
//! rule — registered catalog, per-outlet-HMAC'd on wire"). Runtime substitution
//! is forbidden: each template is a pure UTF-8 string with no interpolation
//! slots so the on-wire catalog selection remains a bounded discrete channel.
//!
//! Catalog contents are committed to the registration signature via
//! `catalog_hash = SHA-256(MessagePack(message_catalog))` — a dedicated term
//! of the `SCP-OUTLET-REGISTRATION-V2:` preimage (§5.4.1). The catalog is NOT
//! covered by `schema_hash`: the `schema` preimage hashes only `input`,
//! `output`, and `aggregate_schema`, so a separate term is required to bring
//! the catalog under the operator signature.
//!
//! # Bounds (§5.4.1)
//!
//! - At most [`CATALOG_MAX_ENTRIES`] = `256` entries per catalog.
//! - Each [`MessageTemplate::template`] at most [`TEMPLATE_MAX_BYTES`] = `1024`
//!   UTF-8 bytes.
//! - Each [`MessageTemplate::key`] matches the regex
//!   `^[a-z][a-z0-9-]{0,63}(\.[a-z][a-z0-9-]{0,63})*$` (dotted-segment slugs;
//!   each segment lowercase ASCII alphanumeric plus hyphens; up to 64 chars per
//!   segment). The grammar matches the §5.4.4 `OutletError.slug` grammar so
//!   catalog keys and slugs share a vocabulary.
//! - Keys are unique within a catalog (uniqueness is enforced by
//!   [`OutletRegistration::try_new`](super::registration::OutletRegistration::try_new)).
//!
//! # Canonical `MessagePack` encoding rule
//!
//! `catalog_hash` is byte-stable across SDKs because the catalog serializes
//! through a canonical `MessagePack` form:
//!
//! 1. The outer `Vec<MessageTemplate>` serializes as a `MessagePack` array
//!    with entries in **insertion order** — the order the operator
//!    registered them. Re-ordering the catalog produces a different
//!    `catalog_hash` and therefore a different signature.
//! 2. Each [`MessageTemplate`] serializes as a `MessagePack` map with keys
//!    in **alphabetical order**: `key` first, then `template`. Both are
//!    serialized as `MessagePack` `str` (UTF-8). The `#[serde]` field order
//!    in the [`MessageTemplate`] declaration is alphabetical by design —
//!    this crate's `rmp-serde` encoder honors struct-field declaration
//!    order, so the canonical layout is enforced by the type definition
//!    itself.
//! 3. An empty catalog (`Vec::new()`) serializes to the single `MessagePack`
//!    byte `0x90` (fixarray, length 0); `catalog_hash = SHA-256(0x90)` is
//!    therefore a fixed deterministic value.
//!
//! Consumers MUST use the helpers in [`super::hash`] to compute
//! `catalog_hash` rather than reimplementing the encoding — those helpers
//! call [`canonical_catalog_messagepack`] below and the [`MessageTemplate`]
//! `Serialize` impl, both of which are pinned to the canonical rule.

use serde::{Deserialize, Serialize};

/// Maximum number of entries permitted in an outlet `message_catalog`
/// (spec §5.4.1).
///
/// Catalogs at or under this bound serialize, hash, and lookup-via-HMAC
/// deterministically; the receiver-side per-outlet LRU sizing in §5.4.4
/// assumes this ceiling.
pub const CATALOG_MAX_ENTRIES: usize = 256;

/// Maximum byte length of a single [`MessageTemplate::template`] (spec
/// §5.4.1).
///
/// Per-template length is measured in **UTF-8 bytes**, not Unicode scalar
/// values. The bound caps the wire size of any individual template the
/// operator can surface.
pub const TEMPLATE_MAX_BYTES: usize = 1024;

/// Maximum byte length of a single segment of [`MessageTemplate::key`] (spec
/// §5.4.1).
///
/// Each dotted segment in `^[a-z][a-z0-9-]{0,63}(\.[a-z][a-z0-9-]{0,63})*$`
/// is at most 64 ASCII bytes (1 leading letter + up to 63 trailing
/// alphanumeric/hyphen chars).
const KEY_SEGMENT_MAX_LEN: usize = 64;

/// Errors produced when constructing a [`MessageTemplate`] via
/// [`MessageTemplate::try_new`].
///
/// Variants align with the §5.4.1 catalog bounds — a catalog whose templates
/// individually exceed these bounds cannot be assembled in the first place.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MessageTemplateError {
    /// The supplied `key` does not match the §5.4.1 catalog-key grammar
    /// `^[a-z][a-z0-9-]{0,63}(\.[a-z][a-z0-9-]{0,63})*$`.
    ///
    /// The grammar admits dotted segments of lowercase ASCII alphanumerics
    /// plus hyphens, each segment up to 64 bytes, with at least one segment
    /// required. Keys with uppercase letters, leading hyphens, empty
    /// segments, or non-ASCII characters are rejected here.
    #[error(
        "catalog key {key:?} is malformed (regex \
         ^[a-z][a-z0-9-]{{0,63}}(\\.[a-z][a-z0-9-]{{0,63}})*$)"
    )]
    MalformedKey {
        /// The rejected key bytes (echoed verbatim for diagnostics).
        key: String,
    },

    /// The supplied `template` exceeds [`TEMPLATE_MAX_BYTES`] (1024 UTF-8
    /// bytes) per §5.4.1.
    ///
    /// Length is measured in raw UTF-8 bytes, not characters.
    #[error(
        "catalog template exceeds {max} UTF-8 bytes (got {actual} bytes)",
        max = TEMPLATE_MAX_BYTES,
    )]
    TemplateTooLarge {
        /// The offending template's UTF-8 byte length.
        actual: usize,
    },
}

/// A single registered message template inside an outlet `message_catalog`
/// (spec §5.4.1).
///
/// Each `(key, template)` pair is operator-authored at registration time. The
/// `template` is a pure UTF-8 string with no interpolation slots — the
/// runtime never substitutes input bytes into the template, so the catalog
/// remains a bounded discrete channel from the wire's perspective.
///
/// # Field order is canonical
///
/// Fields are declared in alphabetical order (`key` before `template`) so
/// the canonical `MessagePack` encoding produces alphabetical keys without
/// further post-processing. See module-level docs for the full
/// canonicalization rule.
///
/// # Validation
///
/// Use [`MessageTemplate::try_new`] to construct a validated template.
/// Direct field assignment (e.g. `MessageTemplate { key, template }`) bypasses
/// validation and is reserved for deserialization paths where the upstream
/// signature already covers the bytes.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MessageTemplate {
    /// Catalog key — dotted-segment slug per §5.4.1.
    ///
    /// Format: `^[a-z][a-z0-9-]{0,63}(\.[a-z][a-z0-9-]{0,63})*$`. Used both
    /// as the lookup key in the catalog and as the input to
    /// `HMAC-SHA-256(outlet_message_key, key.as_bytes())[..32]` for the
    /// §5.4.4 wire-time `OutletError.message` field.
    pub key: String,

    /// Template body — operator-authored prose, ≤ 1024 UTF-8 bytes.
    ///
    /// Templates are pure strings — runtime substitution is forbidden
    /// (§5.4.4). The on-wire HMAC keys lookup against the registered catalog
    /// keys; receivers retrieve the raw template byte-for-byte from the
    /// signed registration.
    pub template: String,
}

impl MessageTemplate {
    /// Constructs a [`MessageTemplate`] after validating both the key
    /// grammar and the template byte length per §5.4.1.
    ///
    /// # Errors
    ///
    /// - [`MessageTemplateError::MalformedKey`] when `key` does not match
    ///   `^[a-z][a-z0-9-]{0,63}(\.[a-z][a-z0-9-]{0,63})*$`.
    /// - [`MessageTemplateError::TemplateTooLarge`] when
    ///   `template.len() > 1024` (UTF-8 bytes).
    pub fn try_new(
        key: impl Into<String>,
        template: impl Into<String>,
    ) -> Result<Self, MessageTemplateError> {
        let key = key.into();
        let template = template.into();
        validate_key(&key)?;
        validate_template(&template)?;
        Ok(Self { key, template })
    }
}

/// Returns `Ok(())` if `key` matches the §5.4.1 catalog-key grammar, else
/// [`MessageTemplateError::MalformedKey`].
///
/// Implemented as a hand-rolled byte scanner rather than pulling in a regex
/// dependency: the grammar is regular and small, and the validator is on the
/// registration hot path. The behavior is byte-for-byte equivalent to
/// `^[a-z][a-z0-9-]{0,63}(\.[a-z][a-z0-9-]{0,63})*$`.
pub(crate) fn validate_key(key: &str) -> Result<(), MessageTemplateError> {
    // Empty keys never match the grammar (the leading-letter clause requires
    // at least one byte).
    if key.is_empty() {
        return Err(MessageTemplateError::MalformedKey {
            key: key.to_owned(),
        });
    }
    // Must be ASCII (the grammar contains no non-ASCII codepoints).
    if !key.is_ascii() {
        return Err(MessageTemplateError::MalformedKey {
            key: key.to_owned(),
        });
    }

    let bytes = key.as_bytes();
    let mut i = 0;
    let mut segment_len = 0;
    let mut at_segment_start = true;

    while i < bytes.len() {
        let b = bytes[i];
        if at_segment_start {
            // Each segment must lead with [a-z]: lowercase ASCII letter.
            if !b.is_ascii_lowercase() {
                return Err(MessageTemplateError::MalformedKey {
                    key: key.to_owned(),
                });
            }
            at_segment_start = false;
            segment_len = 1;
        } else if b == b'.' {
            // Segment boundary; a fresh segment must follow.
            at_segment_start = true;
            segment_len = 0;
        } else if b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' {
            segment_len += 1;
            if segment_len > KEY_SEGMENT_MAX_LEN {
                return Err(MessageTemplateError::MalformedKey {
                    key: key.to_owned(),
                });
            }
        } else {
            return Err(MessageTemplateError::MalformedKey {
                key: key.to_owned(),
            });
        }
        i += 1;
    }

    // Trailing dot or empty trailing segment is invalid.
    if at_segment_start {
        return Err(MessageTemplateError::MalformedKey {
            key: key.to_owned(),
        });
    }
    Ok(())
}

/// Returns `Ok(())` if `template` does not exceed
/// [`TEMPLATE_MAX_BYTES`] (1024 UTF-8 bytes), else
/// [`MessageTemplateError::TemplateTooLarge`].
pub(crate) const fn validate_template(template: &str) -> Result<(), MessageTemplateError> {
    if template.len() > TEMPLATE_MAX_BYTES {
        return Err(MessageTemplateError::TemplateTooLarge {
            actual: template.len(),
        });
    }
    Ok(())
}

/// The canonical `MessagePack` encoding of an empty
/// `Vec<MessageTemplate>`.
///
/// The `MessagePack` `fixarray` tag for length-0 is the single byte `0x90`.
/// `catalog_hash = SHA-256([0x90])` is therefore a deterministic constant —
/// exposing the constant lets empty-catalog assertions in tests cite a
/// fixed hex value rather than reconstructing the computation on every
/// assert.
pub const EMPTY_CATALOG_MESSAGEPACK: [u8; 1] = [0x90];

/// Returns the canonical `MessagePack` encoding of an empty catalog.
///
/// Convenience accessor over [`EMPTY_CATALOG_MESSAGEPACK`] for callers that
/// prefer a slice. Equivalent to `&EMPTY_CATALOG_MESSAGEPACK[..]`.
#[must_use]
pub const fn empty_catalog_messagepack() -> &'static [u8] {
    &EMPTY_CATALOG_MESSAGEPACK
}

/// Encodes a `Vec<MessageTemplate>` to its canonical `MessagePack` byte
/// sequence.
///
/// Defers to `rmp-serde` with the type's [`Serialize`] impl. The
/// canonicalization rule (insertion-order array; alphabetical-key map per
/// entry) is enforced by:
///
/// 1. The slice is iterated in the caller's insertion order.
/// 2. The [`MessageTemplate`] field declaration is alphabetical (`key` then
///    `template`); `rmp-serde` emits struct fields in declaration order, so
///    the encoded map keys are alphabetical without an explicit sort.
///
/// Any future field addition to [`MessageTemplate`] MUST preserve
/// alphabetical declaration order to avoid silently changing every
/// `catalog_hash` in the universe.
///
/// `rmp-serde` encoding of owned `String`s in this struct is infallible in
/// practice; encoder error returns an empty buffer rather than panicking,
/// matching the upstream `unwrap_or_default` convention used by the rest of
/// the V2 preimage builder. Empty bytes still hash deterministically — but
/// because the type only contains `String` + `String`, this branch is
/// unreachable for any well-formed input.
#[must_use]
pub fn canonical_catalog_messagepack(catalog: &[MessageTemplate]) -> Vec<u8> {
    rmp_serde::to_vec(catalog).unwrap_or_default()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn try_new_accepts_minimal_valid_inputs() {
        let t = MessageTemplate::try_new("ok", "hello").unwrap();
        assert_eq!(t.key, "ok");
        assert_eq!(t.template, "hello");
    }

    #[test]
    fn try_new_accepts_dotted_multi_segment_key() {
        let t = MessageTemplate::try_new(
            "authorization.expired-token.detail-3",
            "authorization expired",
        )
        .unwrap();
        assert_eq!(t.key, "authorization.expired-token.detail-3");
    }

    #[test]
    fn try_new_accepts_max_segment_length() {
        // 64 chars: 1 leading [a-z] + 63 trailing [a-z0-9-].
        let segment: String = std::iter::once('a')
            .chain(std::iter::repeat_n('z', 63))
            .collect();
        assert_eq!(segment.len(), 64);
        MessageTemplate::try_new(segment.clone(), "x").unwrap();
        // Same segment repeated across 4 dotted parts is also valid.
        let key = format!("{segment}.{segment}.{segment}.{segment}");
        MessageTemplate::try_new(key, "x").unwrap();
    }

    #[test]
    fn try_new_accepts_template_at_exact_limit() {
        let template = "x".repeat(TEMPLATE_MAX_BYTES);
        assert_eq!(template.len(), TEMPLATE_MAX_BYTES);
        MessageTemplate::try_new("ok", template).unwrap();
    }

    #[test]
    fn try_new_rejects_template_one_byte_over_limit() {
        let template = "x".repeat(TEMPLATE_MAX_BYTES + 1);
        let err = MessageTemplate::try_new("ok", template).unwrap_err();
        assert!(matches!(
            err,
            MessageTemplateError::TemplateTooLarge { actual } if actual == TEMPLATE_MAX_BYTES + 1
        ));
    }

    #[test]
    fn try_new_rejects_empty_key() {
        let err = MessageTemplate::try_new("", "x").unwrap_err();
        assert!(matches!(err, MessageTemplateError::MalformedKey { .. }));
    }

    #[test]
    fn try_new_rejects_uppercase_letter_in_key() {
        let err = MessageTemplate::try_new("Bad", "x").unwrap_err();
        assert!(matches!(err, MessageTemplateError::MalformedKey { .. }));
    }

    #[test]
    fn try_new_rejects_leading_digit() {
        let err = MessageTemplate::try_new("0bad", "x").unwrap_err();
        assert!(matches!(err, MessageTemplateError::MalformedKey { .. }));
    }

    #[test]
    fn try_new_rejects_leading_hyphen() {
        let err = MessageTemplate::try_new("-bad", "x").unwrap_err();
        assert!(matches!(err, MessageTemplateError::MalformedKey { .. }));
    }

    #[test]
    fn try_new_rejects_double_dot() {
        let err = MessageTemplate::try_new("a..b", "x").unwrap_err();
        assert!(matches!(err, MessageTemplateError::MalformedKey { .. }));
    }

    #[test]
    fn try_new_rejects_trailing_dot() {
        let err = MessageTemplate::try_new("a.", "x").unwrap_err();
        assert!(matches!(err, MessageTemplateError::MalformedKey { .. }));
    }

    #[test]
    fn try_new_rejects_segment_over_64_bytes() {
        // 65 chars: too long for a single segment (max 1+63 = 64).
        let bad: String = std::iter::once('a')
            .chain(std::iter::repeat_n('a', 64))
            .collect();
        assert_eq!(bad.len(), 65);
        let err = MessageTemplate::try_new(bad, "x").unwrap_err();
        assert!(matches!(err, MessageTemplateError::MalformedKey { .. }));
    }

    #[test]
    fn try_new_rejects_non_ascii_unicode_in_key() {
        let err = MessageTemplate::try_new("café", "x").unwrap_err();
        assert!(matches!(err, MessageTemplateError::MalformedKey { .. }));
    }

    #[test]
    fn empty_catalog_messagepack_is_single_byte_0x90() {
        assert_eq!(empty_catalog_messagepack(), &[0x90][..]);
    }

    #[test]
    fn canonical_messagepack_of_empty_vec_is_0x90() {
        let catalog: Vec<MessageTemplate> = Vec::new();
        let bytes = canonical_catalog_messagepack(&catalog);
        assert_eq!(bytes, vec![0x90]);
    }

    #[test]
    fn canonical_messagepack_round_trips_through_rmp_serde() {
        let catalog = vec![
            MessageTemplate::try_new("a", "alpha").unwrap(),
            MessageTemplate::try_new("b.bb", "bravo").unwrap(),
        ];
        let bytes = canonical_catalog_messagepack(&catalog);
        let decoded: Vec<MessageTemplate> = rmp_serde::from_slice(&bytes).unwrap();
        assert_eq!(decoded, catalog);
    }

    #[test]
    fn canonical_messagepack_preserves_insertion_order() {
        let catalog_ab = vec![
            MessageTemplate::try_new("alpha", "A").unwrap(),
            MessageTemplate::try_new("bravo", "B").unwrap(),
        ];
        let catalog_ba = vec![
            MessageTemplate::try_new("bravo", "B").unwrap(),
            MessageTemplate::try_new("alpha", "A").unwrap(),
        ];
        let bytes_ab = canonical_catalog_messagepack(&catalog_ab);
        let bytes_ba = canonical_catalog_messagepack(&catalog_ba);
        assert_ne!(
            bytes_ab, bytes_ba,
            "insertion-order MUST be observable in canonical encoding"
        );
    }

    #[test]
    fn validate_key_accepts_all_grammar_classes() {
        for k in [
            "a",
            "a-b",
            "a0",
            "a0-b",
            "a.b",
            "a.b.c",
            "abc-def-ghi",
            "v1.event-log.commit",
        ] {
            validate_key(k).unwrap_or_else(|_| panic!("expected valid: {k}"));
        }
    }

    #[test]
    fn validate_key_rejects_each_negative_class() {
        // Note: `bad-.x` is VALID under the §5.4.1 grammar because a segment
        // can end with a hyphen (`[a-z0-9-]`); only the segment-leading char
        // is constrained. So we don't test that case here.
        for bad in [
            "",       // empty
            "A",      // uppercase leading
            "a.B",    // uppercase mid
            "0bad",   // digit leading
            "-bad",   // hyphen leading
            "bad..x", // double dot
            "bad.",   // trailing dot
            ".bad",   // leading dot
            "bad/x",  // slash
            "bad x",  // whitespace
            "bad\nx", // control
            "a.0",    // segment leading with digit
            "a.-",    // segment leading with hyphen
        ] {
            assert!(validate_key(bad).is_err(), "expected invalid key: {bad:?}");
        }
    }
}
