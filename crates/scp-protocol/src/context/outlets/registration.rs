//! `OutletRegistration` struct and validation (SCP-OUT-040, spec §5.4.1).
//!
//! `OutletRegistration` is the wire-format type that an outlet operator signs
//! and that members of a hosting context store as the source of truth for
//! every outlet exposed in that context. The struct definition lives here so
//! the V2 preimage construction in [`super::hash`] and the
//! `register_outlet`/`update_outlet` flows in [`super::registry`] consume the
//! same canonical type.
//!
//! # V2 preimage and `try_new`
//!
//! Round 5 of ADR-049 finalized the V2 preimage layout (§5.4.1) by adding
//! dedicated `description_hash` and `catalog_hash` terms — the former closes
//! the operator-prose covert-channel surface, the latter binds the
//! `message_catalog` per the §5.4.4 HMAC-keyed catalog rule. SCP-OUT-040
//! lands the `message_catalog: Vec<MessageTemplate>` field, the
//! [`OutletRegistration::try_new`] constructor that enforces §5.4.1
//! catalog-bound validation up front, and the
//! [`OutletRegistration::hash_preimage`] accessor that returns the V2
//! preimage byte sequence the operator's Ed25519 key signs over (after
//! SHA-256).
//!
//! Direct field assignment (e.g. `OutletRegistration { ..fields }`) remains
//! supported so existing callers that already validate elsewhere — most
//! importantly the `register_outlet` / `update_outlet` flows that re-run
//! [`OutletRegistration::validate`] before persisting — keep working without
//! a forced API churn. New code SHOULD prefer `try_new`, which composes the
//! catalog-bound check, the §5.4.2 cost-floor check, and the
//! [`crate::context::outlets::message_catalog::MessageTemplate`] sanity
//! checks into one boundary.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use scp_did::DID;

use super::message_catalog::{
    CATALOG_MAX_ENTRIES, MessageTemplate, MessageTemplateError, validate_key, validate_template,
};
use super::registry::{OutletCost, OutletSchema, OutletTestVector};
use super::{OutletError, OutletId, OutletKind};

/// Errors produced by the [`OutletRegistration::try_new`] constructor when
/// catalog-bound invariants are violated up front.
///
/// `try_new` is the validating entry point; field-by-field assignment skips
/// these checks and is intended only for paths where validation runs at a
/// downstream boundary (e.g. fixture deserialization that re-validates after
/// load).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RegistrationError {
    /// The supplied `message_catalog` exceeds [`CATALOG_MAX_ENTRIES`] (256
    /// per §5.4.1).
    ///
    /// The bound is structural: the §5.4.4 HMAC-keyed catalog rule treats
    /// the catalog as a bounded discrete channel of at most 256 keys.
    /// Catalogs larger than the bound are rejected before they reach the
    /// preimage builder.
    #[error(
        "message_catalog has {actual} entries (max {max} per §5.4.1)",
        max = CATALOG_MAX_ENTRIES,
    )]
    CatalogTooLarge {
        /// The offending catalog's entry count.
        actual: usize,
    },

    /// Two or more entries in `message_catalog` share the same key.
    ///
    /// Catalog keys MUST be unique within a catalog (§5.4.1). Duplicate
    /// keys would create an ambiguous reverse-HMAC lookup at the receiver
    /// and admit a covert-signal mechanism via key-collision selection.
    #[error("message_catalog contains duplicate key {key:?}")]
    DuplicateCatalogKey {
        /// The first duplicated key encountered.
        key: String,
    },

    /// A [`MessageTemplate`] inside `message_catalog` failed its own
    /// validation (key grammar or template byte length).
    #[error("invalid message_catalog entry: {0}")]
    InvalidCatalogEntry(#[from] MessageTemplateError),

    /// The §5.4.2 Query structural cost floor was violated. Re-uses the
    /// crate-wide [`OutletError::QueryCostViolation`] payload so callers
    /// that already match on `OutletError` upstream do not need to map
    /// errors twice.
    #[error("Query outlet cost violation: {reason}")]
    QueryCostViolation {
        /// Human-readable reason — which sub-rule was violated.
        reason: String,
    },
}

impl From<RegistrationError> for OutletError {
    /// Maps `try_new`-time failures back onto the crate-wide [`OutletError`]
    /// taxonomy so existing pipelines that surface `OutletError` continue to
    /// receive structured errors.
    ///
    /// `RegistrationError::InvalidCatalogEntry`, `CatalogTooLarge`, and
    /// `DuplicateCatalogKey` map onto
    /// [`OutletError::InputValidationFailed`] with a precise `message`
    /// because the §5.4.4 typed error envelope (the
    /// `OutletErrorClass::Input` mapping) is owned by SCP-OUT-038. The
    /// `message` body cites the exact sub-rule so SDKs can still surface
    /// the precise reason.
    fn from(err: RegistrationError) -> Self {
        match err {
            RegistrationError::QueryCostViolation { reason } => Self::QueryCostViolation { reason },
            other => Self::InputValidationFailed {
                message: other.to_string(),
            },
        }
    }
}

/// Full outlet registration entry for an SCP context (§5.4.1).
///
/// Contains every metadata field required for outlet integrity verification:
/// kind, name, description, schema, implementation hash, test vectors,
/// operator identity, optional cost, and the §5.4.4 wire-time message
/// catalog. The §5.4.1 V2 signature preimage commits a 32-byte hash of every
/// operator-controlled string field (`description_hash`, `catalog_hash`)
/// alongside MessagePack-derived hashes of the structured fields
/// (`schema_hash`, `test_vectors_hash`, `cost_hash`).
///
/// # `signature`
///
/// `signature` is the operator's Ed25519 signature over
/// `SHA-256(reg.hash_preimage())` — i.e., over the canonical V2 digest
/// produced by [`OutletRegistration::hash_preimage`]. Empty `signature` is
/// a backward-compatible sentinel for legacy registrations created before
/// SCP-OUT-002 introduced the V2 domain; bridges and SDKs in this crate
/// produce non-empty signatures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutletRegistration {
    /// Unique identifier for this outlet within the context.
    pub outlet_id: OutletId,
    /// Structural classification of the outlet (§5.4.2).
    ///
    /// `OutletKind::Query` for read-only, idempotent, cacheable outlets;
    /// `OutletKind::Action` for outlets that may mutate context state. The
    /// `kind` is committed to the §5.4.1 V2 canonical preimage as a fixed
    /// `kind_byte` (`0x00` Query, `0x01` Action) between `outlet_id` and
    /// `name`. Wire form: `"kind": "query"` or `"kind": "action"`. Absence
    /// defaults to `Action` (fail-safe per §5.4.2).
    #[serde(default)]
    pub kind: OutletKind,
    /// Human-readable name of the outlet (≤ 256 UTF-8 bytes per §5.4.1).
    pub name: String,
    /// Outlet description (≤ 4096 UTF-8 bytes per §5.4.1).
    ///
    /// Operator-authored prose displayed to prospective invokers. The V2
    /// preimage commits `description_hash = SHA-256(description.as_bytes())`
    /// (§5.4.1 round-5 ADR adjustment) so silent description edits cannot
    /// escape the registration signature.
    pub description: String,
    /// `MCP`-compatible JSON Schema for input and output (§5.4.1, §8.5).
    pub schema: OutletSchema,
    /// SHA-256 hash of the outlet's implementation artifact (§5.4.1).
    ///
    /// The hash target type (binary, source archive, `OpenAPI` spec, LLM
    /// system prompt) is operator-chosen and not stored in the registration.
    pub implementation_hash: [u8; 32],
    /// Known input-output pairs for continuous verification (≤ 100 per
    /// §5.4.1).
    pub test_vectors: Vec<OutletTestVector>,
    /// The DID of the operator accountable for this outlet.
    pub operator_did: DID,
    /// Optional per-invocation cost metadata (§5.4.1, §19.3).
    pub cost: Option<OutletCost>,
    /// Wire-time message catalog (§5.4.1, §5.4.4).
    ///
    /// At most [`CATALOG_MAX_ENTRIES`] entries; each
    /// [`MessageTemplate`] has a key matching the §5.4.1 grammar and a
    /// template ≤ 1024 UTF-8 bytes. The catalog is committed to the V2
    /// preimage via `catalog_hash = SHA-256(MessagePack(message_catalog))`
    /// (§5.4.1 round-5 ADR adjustment) — a dedicated term, NOT via
    /// `schema_hash`. The empty case (`Vec::new()`) `MessagePack`-encodes
    /// to `0x90` (fixarray length-0); `catalog_hash` for an empty catalog
    /// is therefore the well-defined constant `SHA-256(0x90)`.
    ///
    /// `#[serde(default)]` so legacy fixtures that pre-date SCP-OUT-040
    /// deserialize with an empty catalog. New registrations populate this
    /// field explicitly through [`OutletRegistration::try_new`].
    #[serde(default)]
    pub message_catalog: Vec<MessageTemplate>,
    /// Unix timestamp (seconds) when the outlet was registered.
    ///
    /// Operator-declared, NOT used for catalog-rotation dwell-time
    /// enforcement — the §5.4.4 dwell rule consults the event-log append
    /// time instead so an operator cannot back-date a registration to bypass
    /// the floor.
    #[serde(default)]
    pub registered_at: u64,
    /// Ed25519 signature over the §5.4.1 V2 canonical digest produced by
    /// [`OutletRegistration::hash_preimage`].
    ///
    /// Empty for legacy registrations (pre-SCP-OUT-002). Non-empty
    /// signatures MUST be 64 bytes per Ed25519.
    #[serde(default)]
    pub signature: Vec<u8>,
}

impl OutletRegistration {
    /// Constructs an [`OutletRegistration`] after validating every §5.4.1
    /// catalog-bound invariant up front.
    ///
    /// Validates, in this order, so the most-specific failure surfaces
    /// first:
    ///
    /// 1. Each [`MessageTemplate`] in `message_catalog` matches the §5.4.1
    ///    key grammar and template byte-length cap.
    ///    ([`MessageTemplateError::MalformedKey`] and
    ///    [`MessageTemplateError::TemplateTooLarge`] surface as
    ///    [`RegistrationError::InvalidCatalogEntry`].)
    /// 2. `message_catalog.len() <= 256`. Larger catalogs are rejected with
    ///    [`RegistrationError::CatalogTooLarge`].
    /// 3. Catalog keys are unique within the catalog. Duplicates are
    ///    rejected with [`RegistrationError::DuplicateCatalogKey`].
    /// 4. The §5.4.2 Query structural cost floor — Query outlets MUST NOT
    ///    declare a positive `cost.amount` or a `cost.cost_formula`. Surfaces
    ///    as [`RegistrationError::QueryCostViolation`].
    ///
    /// `try_new` does NOT validate the schemas (`input_schema`,
    /// `output_schema`) — those are checked at the
    /// [`super::registry::register_outlet`] boundary against the JSON Schema
    /// validator since they require the full schema lib. `try_new` is the
    /// catalog-bound and cost-floor entry point; it does not duplicate
    /// schema validation.
    ///
    /// # Errors
    ///
    /// Returns [`RegistrationError`] on the first violated invariant.
    #[allow(clippy::too_many_arguments)]
    pub fn try_new(
        outlet_id: impl Into<OutletId>,
        kind: OutletKind,
        name: impl Into<String>,
        description: impl Into<String>,
        schema: OutletSchema,
        implementation_hash: [u8; 32],
        test_vectors: Vec<OutletTestVector>,
        operator_did: impl Into<DID>,
        cost: Option<OutletCost>,
        message_catalog: Vec<MessageTemplate>,
        registered_at: u64,
    ) -> Result<Self, RegistrationError> {
        // 1. Per-template validation (key grammar + template byte length).
        for entry in &message_catalog {
            validate_key(&entry.key)?;
            validate_template(&entry.template)?;
        }
        // 2. Catalog-size cap (§5.4.1 ≤ 256 entries).
        if message_catalog.len() > CATALOG_MAX_ENTRIES {
            return Err(RegistrationError::CatalogTooLarge {
                actual: message_catalog.len(),
            });
        }
        // 3. Catalog-key uniqueness — first-duplicate-wins reporting.
        let mut seen = HashSet::with_capacity(message_catalog.len());
        for entry in &message_catalog {
            if !seen.insert(entry.key.as_str()) {
                return Err(RegistrationError::DuplicateCatalogKey {
                    key: entry.key.clone(),
                });
            }
        }

        let registration = Self {
            outlet_id: outlet_id.into(),
            kind,
            name: name.into(),
            description: description.into(),
            schema,
            implementation_hash,
            test_vectors,
            operator_did: operator_did.into(),
            cost,
            message_catalog,
            registered_at,
            signature: Vec::new(),
        };

        // 4. §5.4.2 Query cost floor. Translate the OutletError variant into
        //    the RegistrationError equivalent so try_new produces a single
        //    error type for all up-front failures.
        if let Err(OutletError::QueryCostViolation { reason }) = registration.validate() {
            return Err(RegistrationError::QueryCostViolation { reason });
        }

        Ok(registration)
    }

    /// Validates structural invariants on the registration that do not
    /// require any context state — pure on-the-payload checks suitable for
    /// invocation at registration time and at the runtime event-log commit
    /// boundary.
    ///
    /// This method is the §5.4.2 Query structural cost-floor gate (SCP-OUT-012).
    /// It is intentionally narrow — schema validation, capability checks,
    /// and DID resolvability are layered on top by
    /// [`super::registry::register_outlet`] and
    /// [`super::registry::update_outlet`]. Catalog-bound checks are gated
    /// at [`OutletRegistration::try_new`].
    ///
    /// # Errors
    ///
    /// Returns [`OutletError::QueryCostViolation`] when `kind == Query` AND
    /// any of:
    /// - `cost.is_some() && cost.amount > 0`
    /// - `cost.is_some() && cost.cost_formula.is_some()`
    pub fn validate(&self) -> Result<(), OutletError> {
        if matches!(self.kind, OutletKind::Query)
            && let Some(cost) = self.cost.as_ref()
        {
            if cost.amount.0 > 0 {
                return Err(OutletError::QueryCostViolation {
                    reason: format!(
                        "Query outlet \"{}\" declares positive cost.amount = {} \
                         (§5.4.2 requires cost == None || cost.amount == 0)",
                        self.outlet_id, cost.amount
                    ),
                });
            }
            if cost.cost_formula.is_some() {
                return Err(OutletError::QueryCostViolation {
                    reason: format!(
                        "Query outlet \"{}\" declares cost.cost_formula \
                         (§5.4.2 forbids dynamic pricing on Query outlets)",
                        self.outlet_id
                    ),
                });
            }
        }
        Ok(())
    }

    /// Returns the §5.4.1 V2 canonical preimage byte sequence for this
    /// registration.
    ///
    /// Layout (§5.4.1):
    ///
    /// ```text
    /// "SCP-OUTLET-REGISTRATION-V2:"
    ///   || BE32(len(outlet_id)) || outlet_id
    ///   || kind_byte
    ///   || BE32(len(name)) || name
    ///   || description_hash
    ///   || BE32(len(operator_did)) || operator_did
    ///   || schema_hash
    ///   || implementation_hash
    ///   || test_vectors_hash
    ///   || cost_hash
    ///   || catalog_hash
    ///   || registered_at_be
    /// ```
    ///
    /// The Ed25519 signing target is `SHA-256(hash_preimage)`. See
    /// [`super::hash::compute_outlet_registration_canonical_bytes`].
    #[must_use]
    pub fn hash_preimage(&self) -> Vec<u8> {
        super::hash::outlet_registration_v2_preimage(self)
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines
)]
mod tests {
    use super::*;
    use crate::context::outlets::hash::{catalog_hash, description_hash, schema_hash};
    use crate::economy::types::Amount;
    use crate::context::outlets::message_catalog::{
        CATALOG_MAX_ENTRIES, MessageTemplate, empty_catalog_messagepack,
    };
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::json;
    use sha2::{Digest, Sha256};

    /// Reusable schema for the tests. Matches the §5.4.1 specificity floor.
    fn test_schema() -> OutletSchema {
        OutletSchema {
            input_schema: json!({"type": "object", "properties": {"a": {"type": "string"}, "b": {"type": "string"}}}),
            output_schema: json!({"type": "object", "properties": {"r": {"type": "string"}}}),
            aggregate_schema: None,
        }
    }

    fn fixture_registration(message_catalog: Vec<MessageTemplate>) -> OutletRegistration {
        OutletRegistration::try_new(
            "outlet-fixture",
            OutletKind::Action,
            "Fixture",
            "an outlet under test",
            test_schema(),
            [0xAB; 32],
            Vec::new(),
            "did:dht:z6MkOperator",
            None,
            message_catalog,
            1_700_000_000,
        )
        .unwrap()
    }

    // ----------- AC1/AC2: MessageTemplate fundamentals are covered in
    //             the message_catalog module. The tests below exercise the
    //             integration between OutletRegistration::try_new and the
    //             §5.4.1 catalog bounds.

    /// AC: `message_catalog: Vec<MessageTemplate>` field exists on
    /// `OutletRegistration` (struct-level assertion via type system).
    #[test]
    fn registration_has_message_catalog_field() {
        let reg = fixture_registration(Vec::new());
        // The field is named `message_catalog` and is `Vec<MessageTemplate>` —
        // the assertion is the move below; if either drifts, this test
        // stops compiling.
        let _: &Vec<MessageTemplate> = &reg.message_catalog;
    }

    // ----------- AC: OutletRegistration::try_new validates catalog bounds.

    #[test]
    fn try_new_accepts_empty_catalog() {
        let reg = fixture_registration(Vec::new());
        assert!(reg.message_catalog.is_empty());
    }

    #[test]
    fn try_new_accepts_full_256_entry_catalog() {
        let mut catalog = Vec::with_capacity(CATALOG_MAX_ENTRIES);
        for i in 0..CATALOG_MAX_ENTRIES {
            catalog.push(MessageTemplate::try_new(format!("k{i:04}"), format!("t{i}")).unwrap());
        }
        let reg = fixture_registration(catalog);
        assert_eq!(reg.message_catalog.len(), CATALOG_MAX_ENTRIES);
    }

    #[test]
    fn try_new_rejects_257_entry_catalog() {
        let mut catalog = Vec::with_capacity(CATALOG_MAX_ENTRIES + 1);
        for i in 0..=CATALOG_MAX_ENTRIES {
            catalog.push(MessageTemplate::try_new(format!("k{i:04}"), "t").unwrap());
        }
        let err = OutletRegistration::try_new(
            "outlet",
            OutletKind::Action,
            "n",
            "d",
            test_schema(),
            [0; 32],
            Vec::new(),
            "did:dht:z6MkOperator",
            None,
            catalog,
            0,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            RegistrationError::CatalogTooLarge { actual } if actual == CATALOG_MAX_ENTRIES + 1
        ));
    }

    #[test]
    fn try_new_rejects_duplicate_catalog_keys() {
        let catalog = vec![
            MessageTemplate::try_new("dup", "first").unwrap(),
            MessageTemplate::try_new("dup", "second").unwrap(),
        ];
        let err = OutletRegistration::try_new(
            "outlet",
            OutletKind::Action,
            "n",
            "d",
            test_schema(),
            [0; 32],
            Vec::new(),
            "did:dht:z6MkOperator",
            None,
            catalog,
            0,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            RegistrationError::DuplicateCatalogKey { ref key } if key == "dup"
        ));
    }

    #[test]
    fn try_new_propagates_invalid_template_error() {
        // Build a catalog with an oversized template to surface
        // InvalidCatalogEntry directly. We bypass MessageTemplate::try_new's
        // own check (which would reject before the catalog ever forms) by
        // constructing the struct via direct field assignment, which is
        // permitted on this type but caught at try_new's per-entry pass.
        let big_template = "x".repeat(2000);
        let bad_entry = MessageTemplate {
            key: "ok".to_owned(),
            template: big_template,
        };
        let err = OutletRegistration::try_new(
            "outlet",
            OutletKind::Action,
            "n",
            "d",
            test_schema(),
            [0; 32],
            Vec::new(),
            "did:dht:z6MkOperator",
            None,
            vec![bad_entry],
            0,
        )
        .unwrap_err();
        assert!(matches!(err, RegistrationError::InvalidCatalogEntry(_)));
    }

    // ----------- AC: hash_preimage matches the §5.4.1 byte layout.

    #[test]
    fn hash_preimage_matches_v2_layout() {
        let reg = fixture_registration(Vec::new());
        let preimage = reg.hash_preimage();

        // Domain separator is the very first thing in the preimage.
        assert!(preimage.starts_with(b"SCP-OUTLET-REGISTRATION-V2:"));

        // Walk the preimage and re-derive each field offset, asserting the
        // expected layout is preserved exactly.
        let mut cursor = b"SCP-OUTLET-REGISTRATION-V2:".len();
        // BE32(len(outlet_id)) || outlet_id
        let len_outlet =
            u32::from_be_bytes(preimage[cursor..cursor + 4].try_into().unwrap()) as usize;
        cursor += 4;
        assert_eq!(len_outlet, reg.outlet_id.len());
        assert_eq!(
            &preimage[cursor..cursor + len_outlet],
            reg.outlet_id.as_bytes()
        );
        cursor += len_outlet;
        // kind_byte
        assert_eq!(preimage[cursor], reg.kind.canonical_byte());
        cursor += 1;
        // BE32(len(name)) || name
        let len_name =
            u32::from_be_bytes(preimage[cursor..cursor + 4].try_into().unwrap()) as usize;
        cursor += 4;
        assert_eq!(len_name, reg.name.len());
        assert_eq!(&preimage[cursor..cursor + len_name], reg.name.as_bytes());
        cursor += len_name;
        // description_hash (32 bytes)
        assert_eq!(
            &preimage[cursor..cursor + 32],
            &description_hash(&reg.description)[..]
        );
        cursor += 32;
        // BE32(len(operator_did)) || operator_did
        let len_op = u32::from_be_bytes(preimage[cursor..cursor + 4].try_into().unwrap()) as usize;
        cursor += 4;
        let op_did_bytes = reg.operator_did.0.as_bytes();
        assert_eq!(len_op, op_did_bytes.len());
        assert_eq!(&preimage[cursor..cursor + len_op], op_did_bytes);
        cursor += len_op;
        // schema_hash (32 bytes)
        assert_eq!(
            &preimage[cursor..cursor + 32],
            &schema_hash(&reg.schema)[..]
        );
        cursor += 32;
        // implementation_hash (32 bytes, fixed)
        assert_eq!(&preimage[cursor..cursor + 32], &reg.implementation_hash[..]);
        cursor += 32;
        // test_vectors_hash (32 bytes)
        let want_tv: [u8; 32] =
            Sha256::digest(rmp_serde::to_vec(&reg.test_vectors).unwrap()).into();
        assert_eq!(&preimage[cursor..cursor + 32], &want_tv[..]);
        cursor += 32;
        // cost_hash (32 bytes; absent = SHA-256(0x00))
        let want_cost: [u8; 32] = Sha256::digest([0x00u8]).into();
        assert_eq!(&preimage[cursor..cursor + 32], &want_cost[..]);
        cursor += 32;
        // catalog_hash (32 bytes; empty catalog = SHA-256(0x90))
        let want_catalog: [u8; 32] = Sha256::digest(empty_catalog_messagepack()).into();
        assert_eq!(&preimage[cursor..cursor + 32], &want_catalog[..]);
        cursor += 32;
        // registered_at_be (BE64)
        assert_eq!(
            &preimage[cursor..cursor + 8],
            &reg.registered_at.to_be_bytes()
        );
        cursor += 8;
        assert_eq!(
            cursor,
            preimage.len(),
            "preimage layout must consume every byte exactly"
        );
    }

    /// AC: changing a single catalog entry's template byte produces a
    /// different `catalog_hash`, a different V2 preimage, and a different
    /// signature. Silent catalog edits MUST NOT survive the signature.
    #[test]
    fn catalog_template_one_byte_change_invalidates_signature() {
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);

        let cat_a = vec![MessageTemplate::try_new("k", "old").unwrap()];
        let cat_b = vec![MessageTemplate::try_new("k", "ole").unwrap()];

        let reg_a = fixture_registration(cat_a.clone());
        let reg_b = fixture_registration(cat_b.clone());

        // Catalog hashes differ.
        assert_ne!(catalog_hash(&cat_a), catalog_hash(&cat_b));

        // Preimages differ.
        let pre_a = reg_a.hash_preimage();
        let pre_b = reg_b.hash_preimage();
        assert_ne!(pre_a, pre_b);

        // Signatures differ.
        let digest_a: [u8; 32] = Sha256::digest(&pre_a).into();
        let digest_b: [u8; 32] = Sha256::digest(&pre_b).into();
        let sig_a = signing_key.sign(&digest_a).to_bytes();
        let sig_b = signing_key.sign(&digest_b).to_bytes();
        assert_ne!(sig_a, sig_b);
    }

    /// AC: changing a single byte of `description` produces a different
    /// `description_hash`, a different preimage, and a different signature.
    #[test]
    fn description_one_byte_change_invalidates_signature() {
        let signing_key = SigningKey::from_bytes(&[9u8; 32]);

        let mut reg_a = fixture_registration(Vec::new());
        let mut reg_b = reg_a.clone();
        reg_a.description = "policy v1".to_owned();
        reg_b.description = "policy v2".to_owned();

        assert_ne!(
            description_hash(&reg_a.description),
            description_hash(&reg_b.description)
        );
        let pre_a = reg_a.hash_preimage();
        let pre_b = reg_b.hash_preimage();
        assert_ne!(pre_a, pre_b);
        let digest_a: [u8; 32] = Sha256::digest(&pre_a).into();
        let digest_b: [u8; 32] = Sha256::digest(&pre_b).into();
        assert_ne!(
            signing_key.sign(&digest_a).to_bytes(),
            signing_key.sign(&digest_b).to_bytes()
        );
    }

    /// AC (regression): the round-4 claim that `message_catalog` was
    /// "covered via `schema_hash`" was false. Holding the schema fixed and
    /// varying the catalog produces the same `schema_hash` but different
    /// `catalog_hash` and a different preimage.
    #[test]
    fn schema_hash_does_not_cover_catalog() {
        let cat_a = vec![MessageTemplate::try_new("k", "old").unwrap()];
        let cat_b = vec![MessageTemplate::try_new("k", "new").unwrap()];

        let reg_a = fixture_registration(cat_a.clone());
        let reg_b = fixture_registration(cat_b.clone());

        // Schemas are identical (same fixture).
        assert_eq!(schema_hash(&reg_a.schema), schema_hash(&reg_b.schema));
        // Catalog hashes differ.
        assert_ne!(catalog_hash(&cat_a), catalog_hash(&cat_b));
        // V2 preimages therefore differ.
        assert_ne!(reg_a.hash_preimage(), reg_b.hash_preimage());
    }

    /// AC: a 10-entry catalog round-trips through `MessagePack` serialization
    /// preserving insertion order, template bytes, and every other
    /// registration field. Description is also round-tripped because the
    /// V2 preimage commits to it.
    #[test]
    fn ten_entry_catalog_round_trips_through_messagepack() {
        let mut catalog = Vec::with_capacity(10);
        for i in 0..10 {
            catalog.push(
                MessageTemplate::try_new(
                    format!("entry-{i}.detail"),
                    format!("template number {i}"),
                )
                .unwrap(),
            );
        }
        let reg = OutletRegistration::try_new(
            "rt-outlet",
            OutletKind::Action,
            "round-trip",
            "round-trip catalog and description fixture",
            test_schema(),
            [1; 32],
            Vec::new(),
            "did:dht:z6MkOperator",
            None,
            catalog.clone(),
            1_700_000_000,
        )
        .unwrap();

        let bytes = rmp_serde::to_vec(&reg).unwrap();
        let decoded: OutletRegistration = rmp_serde::from_slice(&bytes).unwrap();
        assert_eq!(decoded, reg);
        assert_eq!(decoded.message_catalog.len(), 10);
        for (i, entry) in decoded.message_catalog.iter().enumerate() {
            assert_eq!(entry.key, format!("entry-{i}.detail"));
            assert_eq!(entry.template, format!("template number {i}"));
        }
        assert_eq!(
            decoded.description,
            "round-trip catalog and description fixture"
        );
        assert_eq!(decoded.hash_preimage(), reg.hash_preimage());
    }

    /// AC: empty-catalog hash is the well-defined constant `SHA-256(0x90)`.
    #[test]
    fn empty_catalog_hash_is_well_defined_and_deterministic() {
        let reg = fixture_registration(Vec::new());
        let want: [u8; 32] = Sha256::digest([0x90u8]).into();
        assert_eq!(catalog_hash(&reg.message_catalog), want);
        // Determinism across runs: the second computation MUST equal the first.
        assert_eq!(
            catalog_hash(&reg.message_catalog),
            catalog_hash(&reg.message_catalog)
        );
    }

    /// AC: a full V2 [`OutletRegistration`] (catalog, description, schema,
    /// every other field populated) round-trips through canonical JCS
    /// preserving every field and producing a stable `hash_preimage`
    /// byte-for-byte across two independent rebuilds.
    #[test]
    fn full_v2_registration_round_trips_through_jcs_with_stable_preimage() {
        use crate::jcs;

        let catalog = vec![
            MessageTemplate::try_new("authorization.expired", "auth expired").unwrap(),
            MessageTemplate::try_new("input.invalid-shape", "bad input shape").unwrap(),
        ];
        let cost = OutletCost {
            amount: Amount(250),
            currency: "USD".to_owned(),
            payee: "did:dht:z6MkPayee".into(),
            cost_formula: None,
        };
        let test_vectors = vec![OutletTestVector {
            input: json!({"a": "1", "b": "2"}),
            expected_output: json!({"r": "3"}),
            description: "1+2=3".to_owned(),
        }];
        let reg = OutletRegistration::try_new(
            "full-fixture",
            OutletKind::Action,
            "Full Fixture",
            "every field populated to exercise the round-trip path",
            test_schema(),
            [0xAB; 32],
            test_vectors,
            "did:dht:z6MkOperator",
            Some(cost),
            catalog,
            1_700_000_000,
        )
        .unwrap();

        // Serialize through JCS canonical JSON.
        let jcs_bytes = jcs::to_vec(&reg).unwrap();
        let decoded_via_jcs: OutletRegistration = serde_json::from_slice(&jcs_bytes).unwrap();
        assert_eq!(decoded_via_jcs, reg);
        // Stable preimage across two independent rebuilds.
        assert_eq!(decoded_via_jcs.hash_preimage(), reg.hash_preimage());
    }

    /// `OutletRegistration::validate()` continues to enforce the §5.4.2
    /// Query cost floor on already-constructed registrations (not just on
    /// `try_new`).
    #[test]
    fn validate_rejects_query_with_positive_cost() {
        let mut reg = fixture_registration(Vec::new());
        reg.kind = OutletKind::Query;
        reg.cost = Some(OutletCost {
            amount: Amount(1),
            currency: "USD".to_owned(),
            payee: "did:dht:z6MkPayee".into(),
            cost_formula: None,
        });
        let err = reg.validate().unwrap_err();
        assert!(matches!(err, OutletError::QueryCostViolation { .. }));
    }

    /// `try_new` rejects Query+positive cost with the same precision.
    #[test]
    fn try_new_rejects_query_with_positive_cost() {
        let err = OutletRegistration::try_new(
            "outlet",
            OutletKind::Query,
            "n",
            "d",
            test_schema(),
            [0; 32],
            Vec::new(),
            "did:dht:z6MkOperator",
            Some(OutletCost {
                amount: Amount(1),
                currency: "USD".to_owned(),
                payee: "did:dht:z6MkPayee".into(),
                cost_formula: None,
            }),
            Vec::new(),
            0,
        )
        .unwrap_err();
        assert!(matches!(err, RegistrationError::QueryCostViolation { .. }));
    }
}
