//! Invocation caveats for UCAN delegations targeting outlet capabilities
//! (§7.3.8).
//!
//! Caveats are a fixed set of typed fields — explicitly NOT a DSL — that
//! travel inside the UCAN `nb` ("not-before"/attestation) field and attenuate
//! the delegated `outlet_query:*` / `outlet_call:*` capability with
//! call-site-specific limits. The design constraint is parser-stability:
//! every constraint is a typed field, every field has a single conservative
//! interpretation, and every SDK can implement the verifier from a small
//! schema rather than a parser.
//!
//! This module owns:
//!
//! - [`InvocationCaveats`] — the 12-field record (11 typed caveats +
//!   `origin_kind`).
//! - [`RateWindow`] — sliding-window rate cap helper.
//! - [`HoursOfDayMask`] / [`DaysOfWeekMask`] — typed bitmask newtypes whose
//!   `from_bits` constructor is the only way to build them, making malformed
//!   masks structurally impossible across SDK boundaries.
//! - [`assert_mask_widths`] — the single shared mask-width assertion site
//!   invoked from both the mint constructor and the (SCP-OUT-019) `narrow()`
//!   path so the two call sites cannot diverge.
//! - [`CaveatMintError`] — typed errors returned by [`InvocationCaveats::try_new`]
//!   and [`InvocationCaveats::try_new_for_root`] (mint-time enforcement of
//!   §7.3.8 limits).
//! - [`AttenuationViolation`] — typed errors returned by the (SCP-OUT-019)
//!   `narrow()` path. This story declares the variants only; the narrow
//!   enforcement lands in SCP-OUT-019.
//! - [`MaskWidthError`] — internal error returned by
//!   [`assert_mask_widths`] (composed into both [`CaveatMintError`] and
//!   [`AttenuationViolation`]).
//!
//! See `.docs/specs/07-trust-validation-and-capabilities.md` §7.3.8 and
//! `.docs/adrs/ADR-049-outlet-redesign.md` §3.

use serde::{Deserialize, Serialize};

use crate::context::outlets::OutletKind;
use crate::economy::types::{Amount, PaymentAdapterRef};
use scp_primitives::DID;

// ---------------------------------------------------------------------------
// Mint-time structural limits (§7.3.8 mint-limits table)
// ---------------------------------------------------------------------------

/// Maximum number of populated non-`origin_kind` caveats in a single record.
///
/// See §7.3.8 mint-limits table. `origin_kind` is a structural attenuation
/// invariant and does NOT count against this cap.
pub const MAX_POPULATED_CAVEATS: usize = 8;

/// Maximum serialized size, in bytes, of the JSON Schema attached as
/// `input_schema` (§7.3.8 mint-limits table).
pub const MAX_INPUT_SCHEMA_BYTES: usize = 4 * 1024;

/// Maximum nesting depth (objects + arrays) for the JSON Schema attached as
/// `input_schema` (§7.3.8 mint-limits table).
pub const MAX_INPUT_SCHEMA_DEPTH: usize = 8;

/// Maximum number of entries allowed in any list-typed caveat field
/// (§7.3.8 mint-limits table). Applies to `allowed_adapters` and
/// `allowed_target_dids`.
pub const MAX_LIST_ENTRIES: usize = 16;

/// Sliding-window upper bound. §7.3.8 specifies `[1, 86400]` seconds
/// (one day).
pub const MAX_RATE_WINDOW_SECS: u32 = 86_400;

/// Numeric error code for mint-time and mask-width caveat failures (§7.3.8).
/// Allocated within the SCP-TOOL-6100..6199 sub-block.
pub const CAVEAT_MINT_LIMIT_EXCEEDED_CODE: &str = "SCP-TOOL-6114";

// ---------------------------------------------------------------------------
// HoursOfDayMask
// ---------------------------------------------------------------------------

/// 24-bit UTC-hour mask newtype over `u32` (§7.3.8 mask-width newtypes).
///
/// Each bit `n` (where `0 <= n < 24`) represents UTC hour `n` of the day.
/// Bit 0 is hour 0 (midnight UTC), bit 23 is hour 23. Bits 24..=31 are
/// reserved and MUST be zero — the only public constructor
/// [`HoursOfDayMask::from_bits`] rejects any input whose high bits are set,
/// making malformed masks structurally impossible to build across any SDK
/// boundary.
///
/// Serialization is transparent: the wire encoding is the inner `u32`, so
/// `MessagePack` and JSON treat the mask exactly like a plain unsigned 32-bit
/// integer. Round-trips through `from_bits` re-validate the width invariant.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize,
)]
#[serde(transparent)]
pub struct HoursOfDayMask(u32);

impl HoursOfDayMask {
    /// Bit-mask for the legal value space (`bits 0..=23`).
    pub const VALID_BITS: u32 = 0x00FF_FFFF;

    /// Constructs a mask from raw bits. Returns `None` if any bit outside
    /// the low 24 is set, otherwise wraps the value in the newtype.
    ///
    /// This is the **only** public constructor.
    #[must_use]
    pub const fn from_bits(bits: u32) -> Option<Self> {
        if bits & !Self::VALID_BITS != 0 {
            None
        } else {
            Some(Self(bits))
        }
    }

    /// Returns the inner bit pattern.
    #[must_use]
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// Tests whether a specific UTC hour is present in the mask. `hour`
    /// outside `[0, 23]` always returns `false`.
    #[must_use]
    pub const fn contains_hour(self, hour: u8) -> bool {
        if hour >= 24 {
            return false;
        }
        (self.0 & (1u32 << hour)) != 0
    }

    /// Test-only constructor that bypasses the width check. Used exclusively
    /// to fabricate corrupted-state values for the round-trip test that
    /// asserts [`assert_mask_widths`] is invoked from `narrow()` (SCP-OUT-019)
    /// and from `try_new` (this story). NEVER use in production code.
    #[cfg(test)]
    pub(crate) const fn from_bits_unchecked_for_tests(bits: u32) -> Self {
        Self(bits)
    }
}

// ---------------------------------------------------------------------------
// DaysOfWeekMask
// ---------------------------------------------------------------------------

/// 7-bit weekday mask newtype over `u8` (§7.3.8 mask-width newtypes).
///
/// Bit 0 is Sunday, bit 6 is Saturday. Bit 7 is reserved and MUST be zero —
/// the only public constructor [`DaysOfWeekMask::from_bits`] rejects any
/// input whose high bit is set, making malformed masks structurally
/// impossible across any SDK boundary.
///
/// Serialization is transparent: the wire encoding is the inner `u8`, so
/// `MessagePack` and JSON treat the mask exactly like a plain unsigned 8-bit
/// integer. Round-trips through `from_bits` re-validate the width invariant.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize,
)]
#[serde(transparent)]
pub struct DaysOfWeekMask(u8);

impl DaysOfWeekMask {
    /// Bit-mask for the legal value space (`bits 0..=6`).
    pub const VALID_BITS: u8 = 0x7F;

    /// Constructs a mask from raw bits. Returns `None` if the high bit
    /// (bit 7) is set, otherwise wraps the value in the newtype.
    ///
    /// This is the **only** public constructor.
    #[must_use]
    pub const fn from_bits(bits: u8) -> Option<Self> {
        if bits & !Self::VALID_BITS != 0 {
            None
        } else {
            Some(Self(bits))
        }
    }

    /// Returns the inner bit pattern.
    #[must_use]
    pub const fn bits(self) -> u8 {
        self.0
    }

    /// Tests whether a specific UTC weekday is present in the mask. `day`
    /// outside `[0, 6]` always returns `false`.
    #[must_use]
    pub const fn contains_day(self, day: u8) -> bool {
        if day >= 7 {
            return false;
        }
        (self.0 & (1u8 << day)) != 0
    }

    /// Test-only constructor that bypasses the width check. See
    /// [`HoursOfDayMask::from_bits_unchecked_for_tests`] for rationale.
    #[cfg(test)]
    pub(crate) const fn from_bits_unchecked_for_tests(bits: u8) -> Self {
        Self(bits)
    }
}

// ---------------------------------------------------------------------------
// RateWindow
// ---------------------------------------------------------------------------

/// Sliding-window rate cap (§7.3.8 caveat fields).
///
/// `window_secs` MUST be in `[1, 86400]` seconds; values outside that range
/// are rejected by [`InvocationCaveats::try_new`] with
/// [`CaveatMintError::RateWindowSecsOutOfRange`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RateWindow {
    /// Maximum calls within the window.
    pub max: u32,
    /// Sliding window length in seconds; range `[1, 86400]` (§7.3.8).
    #[serde(rename = "windowSecs")]
    pub window_secs: u32,
}

// ---------------------------------------------------------------------------
// InvocationCaveats
// ---------------------------------------------------------------------------

/// Typed UCAN invocation caveats (§7.3.8). Fixed-field design — explicitly
/// not a DSL — so every SDK runs the same conservative verifier and the
/// caveat surface is finite enough to fuzz to saturation.
///
/// Field naming on the wire matches the §7.3.8 vocabulary verbatim. JSON,
/// `MessagePack`, and JCS all use the same camelCase string keys (`amountMaxPerCall`,
/// `validFrom`, etc.) so a UCAN library that emits the `nb` block as JSON for
/// signing and as `MessagePack` for transport produces field-by-field identical
/// caveats.
///
/// All fields are `Option`; `None` means "parent's setting applies"
/// (§7.3.8 absent-field rule). The caveat verifier (SCP-OUT-019) attenuates
/// by transitioning `None → Some` or by tightening a present bound — widening
/// is rejected.
///
/// **Mint-time invariants** are enforced by [`Self::try_new`]:
///
/// 1. At most [`MAX_POPULATED_CAVEATS`] non-`origin_kind` fields populated
///    (`origin_kind` is a structural attenuation invariant and exempt).
/// 2. `input_schema` serializes to at most [`MAX_INPUT_SCHEMA_BYTES`] bytes
///    of canonical JCS.
/// 3. `input_schema` nesting depth (objects + arrays) at most
///    [`MAX_INPUT_SCHEMA_DEPTH`].
/// 4. `allowed_adapters` and `allowed_target_dids` each contain at most
///    [`MAX_LIST_ENTRIES`] entries.
/// 5. Both bitmask fields are well-formed by construction (the newtype
///    constructors guarantee width). [`assert_mask_widths`] re-asserts the
///    invariant defensively at every mint and every narrow step so the two
///    call sites share a single helper.
///
/// **Root-token invariants** are enforced by [`Self::try_new_for_root`]:
///
/// - The capability set MUST be single-kind (no token may carry both
///   `outlet_query:*` and `outlet_call:*` stems).
/// - When `origin_kind` is `Some`, it MUST equal the inferred kind from the
///   stem family (`outlet_query:*` → Query, `outlet_call:*` → Action).
///
/// See `.docs/specs/07-trust-validation-and-capabilities.md` §7.3.8.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InvocationCaveats {
    /// Per-invocation economic ceiling (§19).
    #[serde(rename = "amountMaxPerCall", skip_serializing_if = "Option::is_none", default)]
    pub amount_max_per_call: Option<Amount>,

    /// Cumulative ceiling across invocations.
    #[serde(rename = "amountMaxCumulative", skip_serializing_if = "Option::is_none", default)]
    pub amount_max_cumulative: Option<Amount>,

    /// Unix seconds; tighter than UCAN `nbf`.
    #[serde(rename = "validFrom", skip_serializing_if = "Option::is_none", default)]
    pub valid_from: Option<u64>,

    /// Unix seconds; tighter than UCAN `exp`.
    #[serde(rename = "validUntil", skip_serializing_if = "Option::is_none", default)]
    pub valid_until: Option<u64>,

    /// 24-bit UTC-hour mask. See [`HoursOfDayMask`].
    #[serde(rename = "hoursOfDay", skip_serializing_if = "Option::is_none", default)]
    pub hours_of_day: Option<HoursOfDayMask>,

    /// 7-bit weekday mask. See [`DaysOfWeekMask`].
    #[serde(rename = "daysOfWeek", skip_serializing_if = "Option::is_none", default)]
    pub days_of_week: Option<DaysOfWeekMask>,

    /// Absolute invocation cap.
    #[serde(rename = "maxCalls", skip_serializing_if = "Option::is_none", default)]
    pub max_calls: Option<u64>,

    /// Sliding-window rate cap.
    #[serde(rename = "rateWindow", skip_serializing_if = "Option::is_none", default)]
    pub rate_window: Option<RateWindow>,

    /// Partial JSON Schema narrowing the parent's `input_schema`.
    /// Restricted by [`MAX_INPUT_SCHEMA_BYTES`] and
    /// [`MAX_INPUT_SCHEMA_DEPTH`]. Conservative narrowing keywords only
    /// (§7.3.8 conservative JSON Schema narrowing).
    #[serde(rename = "inputSchema", skip_serializing_if = "Option::is_none", default)]
    pub input_schema: Option<serde_json::Value>,

    /// Restrict invocations to a subset of payment adapters (§19.2).
    #[serde(rename = "allowedAdapters", skip_serializing_if = "Option::is_none", default)]
    pub allowed_adapters: Option<Vec<PaymentAdapterRef>>,

    /// Restrict cross-context invocations to a subset of peer DIDs (§6.2).
    #[serde(rename = "allowedTargetDids", skip_serializing_if = "Option::is_none", default)]
    pub allowed_target_dids: Option<Vec<DID>>,

    /// §6.2.0.3 amplification — MUST equal the parent's `origin_kind` at
    /// every `narrow()` step (no widening, no narrowing, no reset).
    /// Permitted to be absent only at root-token mint, and only because
    /// [`Self::try_new_for_root`] guarantees the stem set is single-kind so
    /// inference is unambiguous. EVERY non-root delegation MUST materialize
    /// an explicit value — a non-root with `origin_kind = None` fails
    /// `narrow()` (SCP-OUT-019) with [`AttenuationViolation::OriginKindUnspecified`].
    #[serde(rename = "originKind", skip_serializing_if = "Option::is_none", default)]
    pub origin_kind: Option<OutletKind>,
}

impl InvocationCaveats {
    /// Constructs an [`InvocationCaveats`] with all fields absent (the
    /// "no constraints" / fully-permissive set). Useful as a starting point
    /// for builder-style construction.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            amount_max_per_call: None,
            amount_max_cumulative: None,
            valid_from: None,
            valid_until: None,
            hours_of_day: None,
            days_of_week: None,
            max_calls: None,
            rate_window: None,
            input_schema: None,
            allowed_adapters: None,
            allowed_target_dids: None,
            origin_kind: None,
        }
    }

    /// Counts populated non-`origin_kind` fields. Helper for the
    /// [`MAX_POPULATED_CAVEATS`] cap; `origin_kind` is exempt per §7.3.8
    /// mint-limits.
    #[must_use]
    pub const fn populated_non_origin_kind_count(&self) -> usize {
        let mut count = 0;
        if self.amount_max_per_call.is_some() {
            count += 1;
        }
        if self.amount_max_cumulative.is_some() {
            count += 1;
        }
        if self.valid_from.is_some() {
            count += 1;
        }
        if self.valid_until.is_some() {
            count += 1;
        }
        if self.hours_of_day.is_some() {
            count += 1;
        }
        if self.days_of_week.is_some() {
            count += 1;
        }
        if self.max_calls.is_some() {
            count += 1;
        }
        if self.rate_window.is_some() {
            count += 1;
        }
        if self.input_schema.is_some() {
            count += 1;
        }
        if self.allowed_adapters.is_some() {
            count += 1;
        }
        if self.allowed_target_dids.is_some() {
            count += 1;
        }
        count
    }

    /// Validates and constructs an [`InvocationCaveats`] enforcing the
    /// §7.3.8 mint-limits table:
    ///
    /// - At most [`MAX_POPULATED_CAVEATS`] non-`origin_kind` fields populated.
    /// - `input_schema` JCS-serialized size at most [`MAX_INPUT_SCHEMA_BYTES`]
    ///   bytes.
    /// - `input_schema` nesting depth at most [`MAX_INPUT_SCHEMA_DEPTH`].
    /// - `allowed_adapters`, `allowed_target_dids` at most
    ///   [`MAX_LIST_ENTRIES`] entries each.
    /// - `rate_window.window_secs` in `[1, 86400]`.
    /// - Mask widths are well-formed (defensive — newtype constructors
    ///   already enforce this; the helper protects against corrupted
    ///   transport bytes that bypass `from_bits`).
    ///
    /// # Errors
    ///
    /// See [`CaveatMintError`] for the full variant set.
    pub fn try_new(caveats: Self) -> Result<Self, CaveatMintError> {
        let populated = caveats.populated_non_origin_kind_count();
        if populated > MAX_POPULATED_CAVEATS {
            return Err(CaveatMintError::TooManyCaveats {
                populated,
                cap: MAX_POPULATED_CAVEATS,
            });
        }

        if let Some(window) = &caveats.rate_window
            && (window.window_secs == 0 || window.window_secs > MAX_RATE_WINDOW_SECS) {
                return Err(CaveatMintError::RateWindowSecsOutOfRange {
                    window_secs: window.window_secs,
                });
            }

        if let Some(adapters) = &caveats.allowed_adapters
            && adapters.len() > MAX_LIST_ENTRIES {
                return Err(CaveatMintError::ListTooLong {
                    field: "allowedAdapters",
                    len: adapters.len(),
                    cap: MAX_LIST_ENTRIES,
                });
            }
        if let Some(dids) = &caveats.allowed_target_dids
            && dids.len() > MAX_LIST_ENTRIES {
                return Err(CaveatMintError::ListTooLong {
                    field: "allowedTargetDids",
                    len: dids.len(),
                    cap: MAX_LIST_ENTRIES,
                });
            }

        if let Some(schema) = &caveats.input_schema {
            check_input_schema_size_and_depth(schema)?;
        }

        // Mask-width re-assertion. Newtype constructors enforce width on
        // entry; this helper is the single shared mint+narrow assertion
        // site so future fields joining the mask family are covered without
        // patching two places.
        assert_mask_widths(&caveats).map_err(CaveatMintError::from_mask_width)?;

        Ok(caveats)
    }

    /// Validates and constructs an [`InvocationCaveats`] for a **root**
    /// (no-parent) UCAN delegation, enforcing the §7.3.8 root-UCAN
    /// `origin_kind` consistency check:
    ///
    /// 1. The capability set MUST be single-kind (no token may carry both
    ///    `outlet_query:*` and `outlet_call:*` stems). Mixed-stem roots are
    ///    rejected with [`CaveatMintError::OriginKindMixedStemRoot`].
    /// 2. With the set guaranteed single-kind, the inferred kind is
    ///    determined by the stem family: `outlet_query:*` → `Query`,
    ///    `outlet_call:*` → `Action`.
    /// 3. If `caveats.origin_kind` is `Some`, it MUST equal the inferred
    ///    kind. Mismatches are rejected with
    ///    [`CaveatMintError::OriginKindStemMismatch`].
    /// 4. `caveats.origin_kind == None` is permitted ONLY because rule (1)
    ///    has guaranteed a single-kind set; the first non-root delegation
    ///    MUST materialize the inferred value explicitly (enforced by the
    ///    `narrow()` path in SCP-OUT-019).
    ///
    /// Stems whose kind cannot be derived (i.e., capabilities that are
    /// neither `outlet_query:*` nor `outlet_call:*`) are ignored when
    /// inferring the root's outlet kind — they belong to other parts of the
    /// trust surface and are independently checked elsewhere.
    ///
    /// This call also runs the full [`Self::try_new`] mint-limit check.
    ///
    /// # Errors
    ///
    /// See [`CaveatMintError`] for the full variant set.
    pub fn try_new_for_root(
        caveats: Self,
        stems: &[crate::context::roles::Capability],
    ) -> Result<Self, CaveatMintError> {
        // Step 1: enumerate the kinds of the outlet stems. We do not error
        // on non-outlet stems — they are out of scope for this check.
        let mut has_query = false;
        let mut has_action = false;
        for stem in stems {
            match stem {
                crate::context::roles::Capability::OutletQuery(_)
                | crate::context::roles::Capability::OutletQueryAll => {
                    has_query = true;
                }
                crate::context::roles::Capability::OutletCall(_)
                | crate::context::roles::Capability::OutletCallAll => {
                    has_action = true;
                }
                _ => {}
            }
        }

        // Mixed-stem root: reject unconditionally per §7.3.8 round-3
        // (the "inference fails on first ambiguous delegation" escape
        // hatch was unsound).
        if has_query && has_action {
            return Err(CaveatMintError::OriginKindMixedStemRoot);
        }

        // Step 2 + 3: with a single-kind stem set, derive the kind and
        // (if origin_kind is explicitly declared) verify it matches.
        let inferred_kind = if has_query {
            Some(OutletKind::Query)
        } else if has_action {
            Some(OutletKind::Action)
        } else {
            // No outlet stems present — nothing to infer. The caveats can
            // still be minted; downstream attenuation rules govern.
            None
        };

        if let (Some(declared), Some(inferred)) = (caveats.origin_kind, inferred_kind)
            && declared != inferred {
                return Err(CaveatMintError::OriginKindStemMismatch {
                    declared,
                    inferred,
                });
            }

        // Run the structural mint check.
        Self::try_new(caveats)
    }

    /// Returns the canonical JCS (RFC 8785) byte serialization of this
    /// caveat record. Used for hashing/signing across SDKs — every party
    /// that observes the same logical caveats produces byte-identical
    /// canonical bytes.
    ///
    /// `MessagePack` is the wire format for transport (`rmp_serde`); JCS is
    /// the format for hashing.
    ///
    /// # Errors
    ///
    /// Returns [`CaveatSerError::Json`] if `serde_json` cannot encode the
    /// value tree (e.g., embedded non-finite floats — JSON has no IEEE 754
    /// special-value encoding).
    pub fn to_canonical_json_bytes(&self) -> Result<Vec<u8>, CaveatSerError> {
        let value =
            serde_json::to_value(self).map_err(|e| CaveatSerError::Json(e.to_string()))?;
        serde_json_canonicalizer::to_string(&value)
            .map(String::into_bytes)
            .map_err(|e| CaveatSerError::Json(e.to_string()))
    }
}

// ---------------------------------------------------------------------------
// Mask-width assertion
// ---------------------------------------------------------------------------

/// Defensively re-asserts the bit-width invariant for the two mask fields.
///
/// The newtype constructors ([`HoursOfDayMask::from_bits`],
/// [`DaysOfWeekMask::from_bits`]) already enforce width on entry, so on the
/// happy path this helper is a no-op. Its purpose is to be the **single**
/// call site for both mint (this story, [`InvocationCaveats::try_new`]) and
/// narrow (SCP-OUT-019), so future mask-style fields are covered without
/// patching two places. A round-trip test at the narrow site fabricates a
/// corrupted-state mask via the test-only constructor and asserts the
/// helper rejects.
///
/// # Errors
///
/// Returns [`MaskWidthError::HoursOfDayHighBitsSet`] or
/// [`MaskWidthError::DaysOfWeekHighBitSet`] if either mask carries bits
/// outside its legal range.
pub const fn assert_mask_widths(caveats: &InvocationCaveats) -> Result<(), MaskWidthError> {
    if let Some(mask) = caveats.hours_of_day
        && mask.bits() & !HoursOfDayMask::VALID_BITS != 0 {
            return Err(MaskWidthError::HoursOfDayHighBitsSet { bits: mask.bits() });
        }
    if let Some(mask) = caveats.days_of_week
        && mask.bits() & !DaysOfWeekMask::VALID_BITS != 0 {
            return Err(MaskWidthError::DaysOfWeekHighBitSet { bits: mask.bits() });
        }
    Ok(())
}

// ---------------------------------------------------------------------------
// JSON Schema size + depth
// ---------------------------------------------------------------------------

/// Walks a `serde_json::Value` and returns the structural nesting depth.
/// An object or array contributes 1 to the depth of its children. A primitive
/// (null/bool/number/string) has depth 0.
fn schema_nesting_depth(value: &serde_json::Value) -> usize {
    match value {
        serde_json::Value::Object(map) => {
            1 + map
                .values()
                .map(schema_nesting_depth)
                .max()
                .unwrap_or(0)
        }
        serde_json::Value::Array(items) => {
            1 + items
                .iter()
                .map(schema_nesting_depth)
                .max()
                .unwrap_or(0)
        }
        _ => 0,
    }
}

/// Validates the `input_schema` size and depth caps. The size check uses the
/// canonical (JCS) byte length so the limit is reproducible across SDKs.
fn check_input_schema_size_and_depth(value: &serde_json::Value) -> Result<(), CaveatMintError> {
    let canonical = serde_json_canonicalizer::to_string(value)
        .map_err(|e| CaveatMintError::SchemaSerializationFailed { reason: e.to_string() })?;
    let size = canonical.len();
    if size > MAX_INPUT_SCHEMA_BYTES {
        return Err(CaveatMintError::SchemaTooLarge {
            size,
            cap: MAX_INPUT_SCHEMA_BYTES,
        });
    }
    let depth = schema_nesting_depth(value);
    if depth > MAX_INPUT_SCHEMA_DEPTH {
        return Err(CaveatMintError::SchemaTooDeep {
            depth,
            cap: MAX_INPUT_SCHEMA_DEPTH,
        });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors returned when constructing an [`InvocationCaveats`] via
/// [`InvocationCaveats::try_new`] or [`InvocationCaveats::try_new_for_root`].
///
/// All variants surface as protocol error code
/// [`CAVEAT_MINT_LIMIT_EXCEEDED_CODE`] (`SCP-TOOL-6114`); the variant
/// determines the slug.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CaveatMintError {
    /// More than [`MAX_POPULATED_CAVEATS`] non-`origin_kind` caveats are
    /// populated. `origin_kind` is exempt per §7.3.8 mint-limits.
    /// Slug: `caveat-mint-limit-exceeded`.
    #[error("caveat-mint-limit-exceeded: {populated} populated non-origin_kind caveats exceeds cap {cap}")]
    TooManyCaveats {
        /// The actual populated count.
        populated: usize,
        /// The cap (always [`MAX_POPULATED_CAVEATS`]).
        cap: usize,
    },

    /// `input_schema` JCS-serialized size exceeds [`MAX_INPUT_SCHEMA_BYTES`].
    /// Slug: `caveat-mint-limit-exceeded`.
    #[error("caveat-mint-limit-exceeded: input_schema canonical size {size}B exceeds cap {cap}B")]
    SchemaTooLarge {
        /// The actual canonical-byte size.
        size: usize,
        /// The cap (always [`MAX_INPUT_SCHEMA_BYTES`]).
        cap: usize,
    },

    /// `input_schema` nesting depth exceeds [`MAX_INPUT_SCHEMA_DEPTH`].
    /// Slug: `caveat-mint-limit-exceeded`.
    #[error("caveat-mint-limit-exceeded: input_schema nesting depth {depth} exceeds cap {cap}")]
    SchemaTooDeep {
        /// The actual nesting depth.
        depth: usize,
        /// The cap (always [`MAX_INPUT_SCHEMA_DEPTH`]).
        cap: usize,
    },

    /// A list-typed caveat field carries more than [`MAX_LIST_ENTRIES`]
    /// entries. Slug: `caveat-mint-limit-exceeded`.
    #[error("caveat-mint-limit-exceeded: list field {field} length {len} exceeds cap {cap}")]
    ListTooLong {
        /// The wire field name.
        field: &'static str,
        /// The actual list length.
        len: usize,
        /// The cap (always [`MAX_LIST_ENTRIES`]).
        cap: usize,
    },

    /// `rate_window.window_secs` is outside `[1, 86400]`. Slug:
    /// `caveat-mint-limit-exceeded`.
    #[error("caveat-mint-limit-exceeded: rate_window.window_secs {window_secs} outside [1, 86400]")]
    RateWindowSecsOutOfRange {
        /// The actual window.
        window_secs: u32,
    },

    /// JCS canonical encoding of `input_schema` failed. Slug:
    /// `caveat-mint-limit-exceeded`.
    #[error("caveat-mint-limit-exceeded: input_schema canonical encoding failed: {reason}")]
    SchemaSerializationFailed {
        /// Reason returned from the JCS encoder.
        reason: String,
    },

    /// `hours_of_day` newtype carries bits outside the legal `0x00FF_FFFF`
    /// range. Slug: `hours-of-day-high-bits-set`. Reachable only if the
    /// newtype constructor was bypassed (e.g., a corrupted wire value or
    /// a test harness using the `_unchecked_for_tests` constructor) since
    /// `from_bits` rejects the same input.
    #[error("hours-of-day-high-bits-set: HoursOfDayMask carries bits outside 0..=23 (raw 0x{bits:08x})")]
    HoursOfDayHighBitsSet {
        /// The actual raw bit pattern.
        bits: u32,
    },

    /// `days_of_week` newtype carries bits outside the legal `0x7F` range.
    /// Slug: `days-of-week-high-bit-set`. See [`Self::HoursOfDayHighBitsSet`]
    /// for reachability notes.
    #[error("days-of-week-high-bit-set: DaysOfWeekMask carries bits outside 0..=6 (raw 0x{bits:02x})")]
    DaysOfWeekHighBitSet {
        /// The actual raw bit pattern.
        bits: u8,
    },

    /// On a root token, `origin_kind` was explicitly declared but disagrees
    /// with the inferred kind from the stem family. Slug:
    /// `origin-kind-stem-mismatch`.
    #[error("origin-kind-stem-mismatch: caveats.origin_kind = {declared:?} disagrees with inferred kind {inferred:?}")]
    OriginKindStemMismatch {
        /// The declared `origin_kind` value.
        declared: OutletKind,
        /// The kind inferred from the stem family.
        inferred: OutletKind,
    },

    /// On a root token, the capability set carries BOTH
    /// `outlet_query:*` and `outlet_call:*` stems. Slug:
    /// `origin-kind-mixed-stem-root`. Mixed-stem roots are rejected
    /// unconditionally per §7.3.8 round-3 because a mixed-stem root with
    /// `origin_kind = None` could be exercised at one hop under one kind
    /// and at a downstream hop under the other.
    #[error("origin-kind-mixed-stem-root: root token capability set contains both outlet_query and outlet_call stems")]
    OriginKindMixedStemRoot,
}

impl CaveatMintError {
    /// Returns the SCP error code (always [`CAVEAT_MINT_LIMIT_EXCEEDED_CODE`]).
    #[must_use]
    pub const fn code(&self) -> &'static str {
        CAVEAT_MINT_LIMIT_EXCEEDED_CODE
    }

    /// Returns the kebab-case slug per §7.3.8.
    #[must_use]
    pub const fn slug(&self) -> &'static str {
        match self {
            Self::TooManyCaveats { .. }
            | Self::SchemaTooLarge { .. }
            | Self::SchemaTooDeep { .. }
            | Self::ListTooLong { .. }
            | Self::RateWindowSecsOutOfRange { .. }
            | Self::SchemaSerializationFailed { .. } => "caveat-mint-limit-exceeded",
            Self::HoursOfDayHighBitsSet { .. } => "hours-of-day-high-bits-set",
            Self::DaysOfWeekHighBitSet { .. } => "days-of-week-high-bit-set",
            Self::OriginKindStemMismatch { .. } => "origin-kind-stem-mismatch",
            Self::OriginKindMixedStemRoot => "origin-kind-mixed-stem-root",
        }
    }

    /// Promotes a [`MaskWidthError`] into the matching [`CaveatMintError`]
    /// variant. Used by [`InvocationCaveats::try_new`] so the mint-side and
    /// narrow-side error surfaces share a single helper.
    #[must_use]
    pub const fn from_mask_width(err: MaskWidthError) -> Self {
        match err {
            MaskWidthError::HoursOfDayHighBitsSet { bits } => Self::HoursOfDayHighBitsSet { bits },
            MaskWidthError::DaysOfWeekHighBitSet { bits } => Self::DaysOfWeekHighBitSet { bits },
        }
    }
}

/// Errors returned by [`assert_mask_widths`].
///
/// Composed into both [`CaveatMintError`] (mint side) and
/// [`AttenuationViolation`] (narrow side — SCP-OUT-019) so the two call sites
/// share a single assertion helper.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum MaskWidthError {
    /// `hours_of_day` carries bits outside `0..=23`.
    #[error("HoursOfDayMask carries bits outside 0..=23 (raw 0x{bits:08x})")]
    HoursOfDayHighBitsSet {
        /// The actual raw bit pattern.
        bits: u32,
    },
    /// `days_of_week` carries bits outside `0..=6`.
    #[error("DaysOfWeekMask carries bits outside 0..=6 (raw 0x{bits:02x})")]
    DaysOfWeekHighBitSet {
        /// The actual raw bit pattern.
        bits: u8,
    },
}

/// Errors returned by `narrow()` (SCP-OUT-019).
///
/// This story (SCP-OUT-018) declares the variants only; the narrow-layer
/// enforcement lives in SCP-OUT-019. The variants are surfaced here so the
/// [`assert_mask_widths`] helper and downstream callers can construct the
/// `MaskWidth` variant from a [`MaskWidthError`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AttenuationViolation {
    /// Child `origin_kind` differs from parent's. §6.2.0.3 forbids
    /// widening or narrowing across Query/Action — the field is equality-
    /// only.
    #[error("origin_kind mismatch: parent {parent:?}, child {child:?}")]
    OriginKindMismatch {
        /// The parent's declared `origin_kind`.
        parent: OutletKind,
        /// The child's declared `origin_kind`.
        child: OutletKind,
    },

    /// A non-root delegation's `origin_kind` is `None`. §7.3.8 rule (4)
    /// requires every non-root delegation to materialize an explicit
    /// value — inheritance is explicit, not ambient.
    #[error("origin_kind unspecified on non-root delegation (parent {parent:?}); rule §7.3.8 (4) requires explicit materialization")]
    OriginKindUnspecified {
        /// The parent's declared `origin_kind` (informational; the rule
        /// fires regardless of parent value).
        parent: Option<OutletKind>,
    },

    /// One of the parent or child caveat sets carries a malformed mask.
    /// Surfaced from [`assert_mask_widths`] when invoked at the narrow
    /// entry point (SCP-OUT-019).
    #[error("mask-width: {0}")]
    MaskWidth(MaskWidthError),
}

impl From<MaskWidthError> for AttenuationViolation {
    fn from(err: MaskWidthError) -> Self {
        Self::MaskWidth(err)
    }
}

/// Errors returned by [`InvocationCaveats::to_canonical_json_bytes`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CaveatSerError {
    /// JCS / `serde_json` encoding failed.
    #[error("JCS encoding failed: {0}")]
    Json(String),
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]
mod tests {
    use super::*;
    use crate::context::roles::Capability;
    use serde_json::json;

    // ----- HoursOfDayMask -----------------------------------------------

    #[test]
    fn hours_mask_from_bits_rejects_high_bit_24() {
        // Bit 24 set → reject.
        assert!(HoursOfDayMask::from_bits(0x0100_0000).is_none());
        // Specific spec example.
        assert!(HoursOfDayMask::from_bits(0x01FF_FFFF).is_none());
    }

    #[test]
    fn hours_mask_from_bits_accepts_low_24_bits() {
        let mask = HoursOfDayMask::from_bits(0x00FF_FFFF).expect("low 24 bits accepted");
        assert_eq!(mask.bits(), 0x00FF_FFFF);
    }

    #[test]
    fn hours_mask_round_trip_preserves_inner_bits() {
        let original = HoursOfDayMask::from_bits(0b1010_1010_1010_1010_1010_1010).unwrap();
        let bytes = rmp_serde::to_vec_named(&original).unwrap();
        let decoded: HoursOfDayMask = rmp_serde::from_slice(&bytes).unwrap();
        assert_eq!(original.bits(), decoded.bits());
    }

    #[test]
    fn hours_mask_contains_hour() {
        let mask = HoursOfDayMask::from_bits(0b1).unwrap();
        assert!(mask.contains_hour(0));
        assert!(!mask.contains_hour(1));
        assert!(!mask.contains_hour(24));
    }

    // ----- DaysOfWeekMask ------------------------------------------------

    #[test]
    fn days_mask_from_bits_rejects_high_bit_7() {
        assert!(DaysOfWeekMask::from_bits(0x80).is_none());
    }

    #[test]
    fn days_mask_from_bits_accepts_low_7_bits() {
        let mask = DaysOfWeekMask::from_bits(0x7F).expect("low 7 bits accepted");
        assert_eq!(mask.bits(), 0x7F);
    }

    #[test]
    fn days_mask_round_trip_preserves_inner_bits() {
        let original = DaysOfWeekMask::from_bits(0b0101_0101).unwrap();
        let bytes = rmp_serde::to_vec_named(&original).unwrap();
        let decoded: DaysOfWeekMask = rmp_serde::from_slice(&bytes).unwrap();
        assert_eq!(original.bits(), decoded.bits());
    }

    // ----- assert_mask_widths -------------------------------------------

    #[test]
    fn assert_mask_widths_accepts_absent_masks() {
        let caveats = InvocationCaveats::empty();
        assert!(assert_mask_widths(&caveats).is_ok());
    }

    #[test]
    fn assert_mask_widths_accepts_well_formed_masks() {
        let caveats = InvocationCaveats {
            hours_of_day: Some(HoursOfDayMask::from_bits(0x00FF_FFFF).unwrap()),
            days_of_week: Some(DaysOfWeekMask::from_bits(0x7F).unwrap()),
            ..InvocationCaveats::empty()
        };
        assert!(assert_mask_widths(&caveats).is_ok());
    }

    #[test]
    fn assert_mask_widths_rejects_corrupted_hours_mask() {
        // Use the test-only constructor to fabricate a corrupted-state
        // mask that would otherwise be impossible. This proves the helper
        // catches the case where bytes bypass `from_bits` (e.g., a
        // memory-pinning attacker or test harness).
        let caveats = InvocationCaveats {
            hours_of_day: Some(HoursOfDayMask::from_bits_unchecked_for_tests(0x0100_0000)),
            ..InvocationCaveats::empty()
        };
        let err = assert_mask_widths(&caveats).unwrap_err();
        assert!(matches!(err, MaskWidthError::HoursOfDayHighBitsSet { .. }));
    }

    #[test]
    fn assert_mask_widths_rejects_corrupted_days_mask() {
        let caveats = InvocationCaveats {
            days_of_week: Some(DaysOfWeekMask::from_bits_unchecked_for_tests(0x80)),
            ..InvocationCaveats::empty()
        };
        let err = assert_mask_widths(&caveats).unwrap_err();
        assert!(matches!(err, MaskWidthError::DaysOfWeekHighBitSet { .. }));
    }

    #[test]
    fn try_new_rejects_corrupted_hours_mask() {
        // try_new shares the same helper as the (SCP-OUT-019) narrow path.
        // This test asserts the helper is actually invoked from try_new.
        let caveats = InvocationCaveats {
            hours_of_day: Some(HoursOfDayMask::from_bits_unchecked_for_tests(0x0100_0000)),
            ..InvocationCaveats::empty()
        };
        let err = InvocationCaveats::try_new(caveats).unwrap_err();
        assert!(matches!(err, CaveatMintError::HoursOfDayHighBitsSet { .. }));
        assert_eq!(err.slug(), "hours-of-day-high-bits-set");
    }

    // ----- try_new mint limits ------------------------------------------

    fn caveats_with_eight_non_origin_fields() -> InvocationCaveats {
        InvocationCaveats {
            amount_max_per_call: Some(Amount::new(100)),
            amount_max_cumulative: Some(Amount::new(1_000)),
            valid_from: Some(0),
            valid_until: Some(2_000_000_000),
            hours_of_day: Some(HoursOfDayMask::from_bits(0x00FF_FFFF).unwrap()),
            days_of_week: Some(DaysOfWeekMask::from_bits(0x7F).unwrap()),
            max_calls: Some(10_000),
            rate_window: Some(RateWindow { max: 60, window_secs: 60 }),
            input_schema: None,
            allowed_adapters: None,
            allowed_target_dids: None,
            origin_kind: None,
        }
    }

    #[test]
    fn try_new_accepts_eight_non_origin_fields_with_origin_kind_some() {
        // origin_kind does NOT count toward the 8-field cap.
        let mut caveats = caveats_with_eight_non_origin_fields();
        caveats.origin_kind = Some(OutletKind::Query);
        let ok = InvocationCaveats::try_new(caveats).expect("8 + origin_kind permitted");
        assert_eq!(ok.populated_non_origin_kind_count(), 8);
        assert_eq!(ok.origin_kind, Some(OutletKind::Query));
    }

    #[test]
    fn try_new_rejects_nine_non_origin_fields() {
        // Nine fields populated regardless of origin_kind value.
        let mut caveats = caveats_with_eight_non_origin_fields();
        caveats.input_schema = Some(json!({"type": "string"}));
        let err = InvocationCaveats::try_new(caveats.clone()).unwrap_err();
        assert!(matches!(err, CaveatMintError::TooManyCaveats { populated: 9, cap: 8 }));
        // Setting origin_kind to a value does not save it.
        caveats.origin_kind = Some(OutletKind::Action);
        let err = InvocationCaveats::try_new(caveats).unwrap_err();
        assert!(matches!(err, CaveatMintError::TooManyCaveats { populated: 9, cap: 8 }));
    }

    #[test]
    fn try_new_rejects_oversize_input_schema() {
        // Build a schema whose JCS encoding exceeds 4 KiB. We use a single
        // string property whose content alone overflows the cap.
        let big = "x".repeat(5_000);
        let schema = json!({"const": big});
        let caveats = InvocationCaveats {
            input_schema: Some(schema),
            ..InvocationCaveats::empty()
        };
        let err = InvocationCaveats::try_new(caveats).unwrap_err();
        assert!(matches!(err, CaveatMintError::SchemaTooLarge { .. }));
    }

    #[test]
    fn try_new_rejects_overdeep_input_schema_objects() {
        // 9-deep object — depth = 9 > 8.
        let mut value = json!({"type": "string"});
        for _ in 0..9 {
            value = json!({"properties": {"x": value}});
        }
        let caveats = InvocationCaveats {
            input_schema: Some(value),
            ..InvocationCaveats::empty()
        };
        let err = InvocationCaveats::try_new(caveats).unwrap_err();
        assert!(matches!(err, CaveatMintError::SchemaTooDeep { .. }));
    }

    #[test]
    fn try_new_rejects_overdeep_input_schema_arrays() {
        // Array nesting must also count.
        let mut value = json!(0);
        for _ in 0..10 {
            value = json!([value]);
        }
        let caveats = InvocationCaveats {
            input_schema: Some(value),
            ..InvocationCaveats::empty()
        };
        let err = InvocationCaveats::try_new(caveats).unwrap_err();
        assert!(matches!(err, CaveatMintError::SchemaTooDeep { .. }));
    }

    #[test]
    fn try_new_rejects_overlong_allowed_adapters() {
        let caveats = InvocationCaveats {
            allowed_adapters: Some((0..17).map(|i| format!("a{i}")).collect()),
            ..InvocationCaveats::empty()
        };
        let err = InvocationCaveats::try_new(caveats).unwrap_err();
        match err {
            CaveatMintError::ListTooLong { field, len, cap } => {
                assert_eq!(field, "allowedAdapters");
                assert_eq!(len, 17);
                assert_eq!(cap, MAX_LIST_ENTRIES);
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn try_new_rejects_overlong_allowed_target_dids() {
        let caveats = InvocationCaveats {
            allowed_target_dids: Some(
                (0..20)
                    .map(|i| DID(format!("did:dht:z6Mk{i}")))
                    .collect(),
            ),
            ..InvocationCaveats::empty()
        };
        let err = InvocationCaveats::try_new(caveats).unwrap_err();
        match err {
            CaveatMintError::ListTooLong { field, len, cap } => {
                assert_eq!(field, "allowedTargetDids");
                assert_eq!(len, 20);
                assert_eq!(cap, MAX_LIST_ENTRIES);
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn try_new_rejects_rate_window_secs_zero_or_too_large() {
        let caveats = InvocationCaveats {
            rate_window: Some(RateWindow { max: 1, window_secs: 0 }),
            ..InvocationCaveats::empty()
        };
        assert!(matches!(
            InvocationCaveats::try_new(caveats).unwrap_err(),
            CaveatMintError::RateWindowSecsOutOfRange { window_secs: 0 }
        ));
        let caveats = InvocationCaveats {
            rate_window: Some(RateWindow {
                max: 1,
                window_secs: MAX_RATE_WINDOW_SECS + 1,
            }),
            ..InvocationCaveats::empty()
        };
        assert!(matches!(
            InvocationCaveats::try_new(caveats).unwrap_err(),
            CaveatMintError::RateWindowSecsOutOfRange { .. }
        ));
    }

    #[test]
    fn try_new_error_codes_and_slugs() {
        // SCP-TOOL-6114 / 'caveat-mint-limit-exceeded' wired.
        let many = caveats_with_eight_non_origin_fields();
        let mut nine = many;
        nine.input_schema = Some(json!({"type": "string"}));
        let err = InvocationCaveats::try_new(nine).unwrap_err();
        assert_eq!(err.code(), CAVEAT_MINT_LIMIT_EXCEEDED_CODE);
        assert_eq!(err.code(), "SCP-TOOL-6114");
        assert_eq!(err.slug(), "caveat-mint-limit-exceeded");
    }

    // ----- Round-trip / camelCase serde --------------------------------

    #[test]
    fn round_trip_messagepack_and_jcs_field_equal() {
        let original = InvocationCaveats {
            amount_max_per_call: Some(Amount::new(42)),
            valid_from: Some(123),
            valid_until: Some(456),
            hours_of_day: Some(HoursOfDayMask::from_bits(0x0000_FFFF).unwrap()),
            days_of_week: Some(DaysOfWeekMask::from_bits(0x3F).unwrap()),
            input_schema: Some(json!({"type": "string"})),
            allowed_adapters: Some(vec!["x402".to_owned(), "lightning".to_owned()]),
            allowed_target_dids: Some(vec![DID("did:dht:z6MkA".to_owned())]),
            origin_kind: Some(OutletKind::Action),
            ..InvocationCaveats::empty()
        };

        // MessagePack round-trip. Use the named-map encoder so the wire
        // form keys are the camelCase strings (matching the JCS form).
        let mp = rmp_serde::to_vec_named(&original).unwrap();
        let back: InvocationCaveats = rmp_serde::from_slice(&mp).unwrap();
        assert_eq!(original, back);

        // JCS round-trip via `to_canonical_json_bytes` + serde_json.
        let jcs = original.to_canonical_json_bytes().unwrap();
        let back2: InvocationCaveats = serde_json::from_slice(&jcs).unwrap();
        assert_eq!(original, back2);
    }

    #[test]
    fn round_trip_canonical_jcs_is_deterministic() {
        // Two equal logical values produce byte-identical JCS bytes
        // regardless of insertion order.
        let mut a = InvocationCaveats::empty();
        a.amount_max_per_call = Some(Amount::new(1));
        a.valid_from = Some(0);

        let mut b = InvocationCaveats::empty();
        b.valid_from = Some(0);
        b.amount_max_per_call = Some(Amount::new(1));

        assert_eq!(
            a.to_canonical_json_bytes().unwrap(),
            b.to_canonical_json_bytes().unwrap()
        );
    }

    #[test]
    fn deserialization_rejects_snake_case_field_names() {
        // The wire vocabulary is camelCase. snake_case must fail to
        // deserialize because of `deny_unknown_fields`.
        let snake = r#"{"amount_max_per_call": 1}"#;
        let err = serde_json::from_str::<InvocationCaveats>(snake).unwrap_err();
        // serde reports the unknown field; our test just asserts it errored.
        assert!(err.to_string().contains("unknown field"), "{err}");
    }

    #[test]
    fn deserialization_camel_case_succeeds() {
        let camel = r#"{"amountMaxPerCall": 1}"#;
        let parsed: InvocationCaveats = serde_json::from_str(camel).unwrap();
        assert_eq!(parsed.amount_max_per_call, Some(Amount::new(1)));
    }

    // ----- try_new_for_root --------------------------------------------

    #[test]
    fn root_mint_rejects_mixed_kind_stems() {
        let stems = vec![
            Capability::OutletQuery("foo".to_owned()),
            Capability::OutletCall("bar".to_owned()),
        ];
        let err = InvocationCaveats::try_new_for_root(InvocationCaveats::empty(), &stems)
            .unwrap_err();
        assert!(matches!(err, CaveatMintError::OriginKindMixedStemRoot));
        assert_eq!(err.slug(), "origin-kind-mixed-stem-root");

        // Mixed-kind rejection happens regardless of explicit origin_kind.
        let mut caveats = InvocationCaveats::empty();
        caveats.origin_kind = Some(OutletKind::Query);
        let err = InvocationCaveats::try_new_for_root(caveats, &stems).unwrap_err();
        assert!(matches!(err, CaveatMintError::OriginKindMixedStemRoot));
    }

    #[test]
    fn root_mint_rejects_origin_kind_disagreeing_with_single_kind_stems() {
        let stems = vec![Capability::OutletQuery("foo".to_owned())];
        let mut caveats = InvocationCaveats::empty();
        caveats.origin_kind = Some(OutletKind::Action);
        let err = InvocationCaveats::try_new_for_root(caveats, &stems).unwrap_err();
        match err {
            CaveatMintError::OriginKindStemMismatch { declared, inferred } => {
                assert_eq!(declared, OutletKind::Action);
                assert_eq!(inferred, OutletKind::Query);
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn root_mint_accepts_origin_kind_none_with_single_kind_stems() {
        // origin_kind = None is permitted because rule (1) has guaranteed
        // a single-kind set; first non-root delegation will materialize.
        let stems = vec![Capability::OutletQuery("foo".to_owned())];
        let ok = InvocationCaveats::try_new_for_root(InvocationCaveats::empty(), &stems)
            .expect("None permitted");
        assert_eq!(ok.origin_kind, None);
    }

    #[test]
    fn root_mint_accepts_origin_kind_query_with_query_stem() {
        let stems = vec![Capability::OutletQuery("foo".to_owned())];
        let mut caveats = InvocationCaveats::empty();
        caveats.origin_kind = Some(OutletKind::Query);
        let ok = InvocationCaveats::try_new_for_root(caveats, &stems).unwrap();
        assert_eq!(ok.origin_kind, Some(OutletKind::Query));
    }

    #[test]
    fn root_mint_accepts_origin_kind_action_with_call_stem() {
        let stems = vec![Capability::OutletCallAll];
        let mut caveats = InvocationCaveats::empty();
        caveats.origin_kind = Some(OutletKind::Action);
        let ok = InvocationCaveats::try_new_for_root(caveats, &stems).unwrap();
        assert_eq!(ok.origin_kind, Some(OutletKind::Action));
    }

    #[test]
    fn root_mint_runs_structural_mint_check() {
        // try_new_for_root composes try_new — overflow surfaces here too.
        let stems = vec![Capability::OutletQueryAll];
        let mut caveats = caveats_with_eight_non_origin_fields();
        caveats.input_schema = Some(json!({}));
        caveats.origin_kind = Some(OutletKind::Query);
        let err = InvocationCaveats::try_new_for_root(caveats, &stems).unwrap_err();
        assert!(matches!(err, CaveatMintError::TooManyCaveats { .. }));
    }

    // ----- Error variants present (compile-time + AC enumeration) -------

    #[test]
    fn caveat_mint_error_has_all_required_variants() {
        // Compile-time check that each variant exists. A missing variant
        // makes the test fail to compile.
        let _ = CaveatMintError::TooManyCaveats { populated: 0, cap: 0 };
        let _ = CaveatMintError::SchemaTooLarge { size: 0, cap: 0 };
        let _ = CaveatMintError::SchemaTooDeep { depth: 0, cap: 0 };
        let _ = CaveatMintError::ListTooLong { field: "x", len: 0, cap: 0 };
        let _ = CaveatMintError::HoursOfDayHighBitsSet { bits: 0 };
        let _ = CaveatMintError::DaysOfWeekHighBitSet { bits: 0 };
        let _ = CaveatMintError::OriginKindStemMismatch {
            declared: OutletKind::Query,
            inferred: OutletKind::Action,
        };
        let _ = CaveatMintError::OriginKindMixedStemRoot;
    }

    #[test]
    fn attenuation_violation_has_all_required_variants() {
        let _ = AttenuationViolation::OriginKindMismatch {
            parent: OutletKind::Query,
            child: OutletKind::Action,
        };
        let _ = AttenuationViolation::OriginKindUnspecified {
            parent: Some(OutletKind::Query),
        };
        let _ =
            AttenuationViolation::MaskWidth(MaskWidthError::HoursOfDayHighBitsSet { bits: 0 });
    }

    #[test]
    fn attenuation_violation_from_mask_width() {
        let mw = MaskWidthError::DaysOfWeekHighBitSet { bits: 0x80 };
        let av: AttenuationViolation = mw.into();
        assert!(matches!(av, AttenuationViolation::MaskWidth(_)));
    }
}
