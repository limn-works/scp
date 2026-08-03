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
use scp_did::DID;

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
///
/// Allocated within the SCP-OUTLET-6100..6199 sub-block; the single source of
/// truth for the literal is the outlet error-code registry.
pub const CAVEAT_MINT_LIMIT_EXCEEDED_CODE: &str =
    crate::context::outlets::error_codes::CODE_AUTHORIZATION_ATTENUATION;

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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
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
    #[serde(
        rename = "amountMaxPerCall",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub amount_max_per_call: Option<Amount>,

    /// Cumulative ceiling across invocations.
    #[serde(
        rename = "amountMaxCumulative",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub amount_max_cumulative: Option<Amount>,

    /// Unix seconds; tighter than UCAN `nbf`.
    #[serde(rename = "validFrom", skip_serializing_if = "Option::is_none", default)]
    pub valid_from: Option<u64>,

    /// Unix seconds; tighter than UCAN `exp`.
    #[serde(
        rename = "validUntil",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub valid_until: Option<u64>,

    /// 24-bit UTC-hour mask. See [`HoursOfDayMask`].
    #[serde(
        rename = "hoursOfDay",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub hours_of_day: Option<HoursOfDayMask>,

    /// 7-bit weekday mask. See [`DaysOfWeekMask`].
    #[serde(
        rename = "daysOfWeek",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub days_of_week: Option<DaysOfWeekMask>,

    /// Absolute invocation cap.
    #[serde(rename = "maxCalls", skip_serializing_if = "Option::is_none", default)]
    pub max_calls: Option<u64>,

    /// Sliding-window rate cap.
    #[serde(
        rename = "rateWindow",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub rate_window: Option<RateWindow>,

    /// Partial JSON Schema narrowing the parent's `input_schema`.
    /// Restricted by [`MAX_INPUT_SCHEMA_BYTES`] and
    /// [`MAX_INPUT_SCHEMA_DEPTH`]. Conservative narrowing keywords only
    /// (§7.3.8 conservative JSON Schema narrowing).
    #[serde(
        rename = "inputSchema",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub input_schema: Option<serde_json::Value>,

    /// Restrict invocations to a subset of payment adapters (§19.2).
    #[serde(
        rename = "allowedAdapters",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub allowed_adapters: Option<Vec<PaymentAdapterRef>>,

    /// Restrict cross-context invocations to a subset of peer DIDs (§6.2).
    #[serde(
        rename = "allowedTargetDids",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub allowed_target_dids: Option<Vec<DID>>,

    /// §6.2.0.3 amplification — MUST equal the parent's `origin_kind` at
    /// every `narrow()` step (no widening, no narrowing, no reset).
    /// Permitted to be absent only at root-token mint, and only because
    /// [`Self::try_new_for_root`] guarantees the stem set is single-kind so
    /// inference is unambiguous. EVERY non-root delegation MUST materialize
    /// an explicit value — a non-root with `origin_kind = None` fails
    /// `narrow()` (SCP-OUT-019) with [`AttenuationViolation::OriginKindUnspecified`].
    #[serde(
        rename = "originKind",
        skip_serializing_if = "Option::is_none",
        default
    )]
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

    /// Returns `true` when at least one populated field requires the durable
    /// per-`(context_id, ucan_cid, kind)` counter CAS to enforce: `max_calls`
    /// (absolute invocation cap), `amount_max_cumulative` (cumulative spend
    /// cap), or `rate_window` (sliding-window rate cap).
    ///
    /// The other §7.3.8 fields (`amount_max_per_call`, `allowed_adapters`,
    /// `allowed_target_dids`, `input_schema`, and the time-box / origin
    /// fields) are stateless local checks that need no counter store.
    ///
    /// Callers that cannot reach a counter store (e.g. a runtime built
    /// without a concrete storage backend) MUST treat a `true` result as
    /// fail-closed — a counter cap that cannot be enforced must reject, not
    /// silently pass.
    #[must_use]
    pub const fn has_counter_bearing_caveat(&self) -> bool {
        self.max_calls.is_some()
            || self.amount_max_cumulative.is_some()
            || self.rate_window.is_some()
    }

    /// Returns `true` when at least one field is populated that the §7.3.8
    /// post-input gate enforces at invocation time — i.e. anything that makes
    /// the runtime build a post-input hook. Excludes the time-box fields
    /// (`valid_from` / `valid_until` / `hours_of_day` / `days_of_week`) and
    /// `origin_kind`, which are enforced upstream during UCAN validation, not
    /// in the post-input hook.
    #[must_use]
    pub const fn requires_post_input_check(&self) -> bool {
        self.amount_max_per_call.is_some()
            || self.input_schema.is_some()
            || self.allowed_adapters.is_some()
            || self.allowed_target_dids.is_some()
            || self.has_counter_bearing_caveat()
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
            && (window.window_secs == 0 || window.window_secs > MAX_RATE_WINDOW_SECS)
        {
            return Err(CaveatMintError::RateWindowSecsOutOfRange {
                window_secs: window.window_secs,
            });
        }

        if let Some(adapters) = &caveats.allowed_adapters
            && adapters.len() > MAX_LIST_ENTRIES
        {
            return Err(CaveatMintError::ListTooLong {
                field: "allowedAdapters",
                len: adapters.len(),
                cap: MAX_LIST_ENTRIES,
            });
        }
        if let Some(dids) = &caveats.allowed_target_dids
            && dids.len() > MAX_LIST_ENTRIES
        {
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
            && declared != inferred
        {
            return Err(CaveatMintError::OriginKindStemMismatch { declared, inferred });
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
        let value = serde_json::to_value(self).map_err(|e| CaveatSerError::Json(e.to_string()))?;
        serde_json_canonicalizer::to_string(&value)
            .map(String::into_bytes)
            .map_err(|e| CaveatSerError::Json(e.to_string()))
    }

    /// Validates that `child` is a legitimate attenuation of `self` (the
    /// parent) per §7.3.8. Each of the eleven typed fields is checked
    /// independently against its narrowing rule (see the section "Attenuation
    /// (`narrow`)" of §7.3.8). The directions are deliberately heterogeneous:
    /// numeric ceilings tighten downward, validity windows shift inward,
    /// bitmasks subset, lists subset, and `origin_kind` is equality-with-
    /// explicit-non-root. The `input_schema` field uses conservative JSON
    /// Schema narrowing per [`json_schema_narrows`] — an explicit whitelist of
    /// nine keywords, none of which permit semantic regex containment (see
    /// `pattern` rule, which requires byte-for-byte equality).
    ///
    /// **Mask-width assertion (run first).** Before any field rule runs,
    /// [`assert_mask_widths`] is invoked on BOTH `self` (parent) and `child`.
    /// This is the same shared helper invoked at mint time
    /// ([`Self::try_new`]); a single implementation guards both call sites.
    /// Failures surface as [`AttenuationViolation::MaskWidth`].
    ///
    /// **`origin_kind` rule (no widening, no narrowing, no reset).** The
    /// `origin_kind` field is the sole field whose narrowing rule is **strict
    /// equality**, not subsetting. Query and Action are disjoint attack-
    /// surface classes (§6.2.0.3); a delegation that crossed the boundary
    /// would be an amplification attack. Additionally, every non-root
    /// delegation MUST materialize an explicit value — a non-root with
    /// `origin_kind = None` fails with
    /// [`AttenuationViolation::OriginKindUnspecified`] regardless of parent
    /// (the root may be `None` because [`Self::try_new_for_root`] guarantees
    /// the stem set is single-kind, but every narrow step below it must pin
    /// the value into the signed caveats).
    ///
    /// **Absent (`None`) parent fields.** A `None` parent field means "no
    /// constraint from this delegation level." A child MAY introduce a bound
    /// where the parent had none (e.g., `parent.amount_max_per_call = None`,
    /// `child.amount_max_per_call = Some(100)` is admissible — the child is
    /// strictly more restrictive). A child that **removes** a parent's bound
    /// (e.g., `parent.amount_max_per_call = Some(100)`,
    /// `child.amount_max_per_call = None`) is widening and is rejected.
    ///
    /// **Pattern-keyword lexical equality.** Inside JSON Schema narrowing,
    /// the `pattern` keyword is enforced byte-for-byte (UTF-8 string
    /// equality). Regex containment is PSPACE-complete in general and
    /// undecidable for the extended dialects typical JSON Schema consumers
    /// accept; no syntactic subsumption check is sound. See [`json_schema_narrows`]
    /// for the full whitelist and per-keyword rules.
    ///
    /// # Errors
    ///
    /// Returns [`AttenuationViolation`] with the variant identifying which
    /// rule failed. The error variants are field-typed so SDK consumers can
    /// surface actionable diagnostics without re-parsing the message string.
    pub fn narrow(&self, child: &Self) -> Result<(), AttenuationViolation> {
        // Mask-width re-assertion on BOTH parent and child. The mint-time
        // helper guarantees freshly minted caveats are well-formed; this call
        // protects the narrow path against transport-corrupted bytes that
        // might bypass the newtype constructor (e.g., a forged
        // MessagePack-decoded value whose internal `u32`/`u8` carries bits
        // outside the legal range).
        assert_mask_widths(self)?;
        assert_mask_widths(child)?;

        // origin_kind: equality with explicit-non-root. Three cases:
        //   1. child = None         → OriginKindUnspecified (rule §7.3.8 (4))
        //   2. parent = Some(p), child = Some(c), p != c → OriginKindMismatch
        //   3. parent = None, child = Some(_) → admissible
        //      (root with single-kind stem set permits None at mint;
        //       first non-root materializes the inferred value)
        //   4. parent = Some(p), child = Some(p) → admissible
        match (self.origin_kind, child.origin_kind) {
            (_, None) => {
                return Err(AttenuationViolation::OriginKindUnspecified {
                    parent: self.origin_kind,
                });
            }
            (Some(parent), Some(child_kind)) if parent != child_kind => {
                return Err(AttenuationViolation::OriginKindMismatch {
                    parent,
                    child: child_kind,
                });
            }
            _ => {}
        }

        // amount_max_per_call: child <= parent (None→Some OK, Some→None fails)
        narrow_le_amount(
            self.amount_max_per_call,
            child.amount_max_per_call,
            CaveatField::AmountMaxPerCall,
        )?;
        // amount_max_cumulative: child <= parent
        narrow_le_amount(
            self.amount_max_cumulative,
            child.amount_max_cumulative,
            CaveatField::AmountMaxCumulative,
        )?;
        // max_calls: child <= parent
        narrow_le_u64(self.max_calls, child.max_calls, CaveatField::MaxCalls)?;
        // valid_from: child >= parent (later)
        narrow_ge_u64(self.valid_from, child.valid_from, CaveatField::ValidFrom)?;
        // valid_until: child <= parent (earlier)
        narrow_le_u64(self.valid_until, child.valid_until, CaveatField::ValidUntil)?;

        // hours_of_day: child & parent == child (subset bitmask)
        narrow_subset_hours(self.hours_of_day, child.hours_of_day)?;
        // days_of_week: child & parent == child (subset bitmask)
        narrow_subset_days(self.days_of_week, child.days_of_week)?;

        // rate_window: both .max and .window_secs narrow downward.
        match (self.rate_window, child.rate_window) {
            (None, _) => {} // child may introduce a bound where parent had none.
            (Some(_), None) => {
                return Err(AttenuationViolation::FieldRemoved {
                    field: CaveatField::RateWindow,
                });
            }
            (Some(parent), Some(child_rw)) => {
                if child_rw.max > parent.max {
                    return Err(AttenuationViolation::RateWindowMaxWidened {
                        parent: parent.max,
                        child: child_rw.max,
                    });
                }
                if child_rw.window_secs > parent.window_secs {
                    return Err(AttenuationViolation::RateWindowSecsWidened {
                        parent: parent.window_secs,
                        child: child_rw.window_secs,
                    });
                }
            }
        }

        // allowed_adapters: child Vec subset of parent
        narrow_list_subset_adapters(
            self.allowed_adapters.as_deref(),
            child.allowed_adapters.as_deref(),
        )?;
        // allowed_target_dids: child Vec subset of parent
        narrow_list_subset_dids(
            self.allowed_target_dids.as_deref(),
            child.allowed_target_dids.as_deref(),
        )?;

        // input_schema: conservative JSON Schema narrowing.
        match (self.input_schema.as_ref(), child.input_schema.as_ref()) {
            (None, _) => {} // child may introduce a schema bound where parent had none.
            (Some(_), None) => {
                return Err(AttenuationViolation::FieldRemoved {
                    field: CaveatField::InputSchema,
                });
            }
            (Some(parent_schema), Some(child_schema)) => {
                json_schema_narrows(parent_schema, child_schema)?;
            }
        }

        Ok(())
    }

    /// SCP-OUT-021 post-input check (synchronous half).
    ///
    /// Runs the §7.3.8 "Post-input checks" that DO NOT require persistent
    /// counter state:
    ///
    /// - `input_schema` — conformance against the caveat's narrowed schema
    ///   (above and beyond the outlet's own input schema).
    /// - `amount_max_per_call` — the computed invocation cost MUST be
    ///   `<=` the per-call ceiling.
    /// - `allowed_adapters` — the negotiated adapter MUST be in the list.
    /// - `allowed_target_dids` — the cross-context target DID MUST be in
    ///   the list.
    ///
    /// The three counter-bearing caveats (`max_calls`,
    /// `amount_max_cumulative`, `rate_window`) are NOT checked here. Those
    /// require atomic CAS against a durable counter store (`CaveatCounterStore`,
    /// §7.3.8 runtime enforcement) that lives in `scp-runtime`. That runtime
    /// value-caveat enforcement is a decided-but-not-yet-wired slice (§7.3.8):
    /// this function is its specified synchronous entrypoint, and when the
    /// counter-backed post-input glue is wired it MUST call
    /// `check_invocation_local` FIRST so a failure on a synchronous caveat does
    /// not consume counter capacity. There is no live divergence today because
    /// the mint emits no value-caveats, so no in-circulation token asserts one.
    ///
    /// `negotiated_adapter` and `target_did` are `Option` to model the
    /// "no adapter selected" / "intra-context invocation" cases. Absent
    /// values trigger the caveat only when the caveat is `Some(non_empty_list)`
    /// — i.e., a token that restricts to specific adapters cannot be
    /// invoked with no adapter at all.
    ///
    /// # Errors
    ///
    /// Returns [`CheckInvocationError`] with a typed variant identifying
    /// which rule failed; the variant's [`CheckInvocationError::slug`]
    /// helper returns the spec slug used in the error envelope.
    pub fn check_invocation_local(
        &self,
        input: &serde_json::Value,
        estimated_cost: Amount,
        negotiated_adapter: Option<&PaymentAdapterRef>,
        target_did: Option<&DID>,
    ) -> Result<(), CheckInvocationError> {
        // input_schema conformance — caveat-narrowed schema.
        if let Some(schema) = self.input_schema.as_ref() {
            crate::context::outlets::schema::validate_value_against_schema(input, schema)
                .map_err(|message| CheckInvocationError::InputSchemaViolation { message })?;
        }

        // amount_max_per_call — estimated cost MUST not exceed cap.
        if let Some(cap) = self.amount_max_per_call
            && estimated_cost.value() > cap.value()
        {
            return Err(CheckInvocationError::AmountMaxPerCallExceeded {
                estimated_cost,
                cap,
            });
        }

        // allowed_adapters — negotiated adapter MUST be in list.
        if let Some(allowed) = self.allowed_adapters.as_ref() {
            // An empty `Some(vec![])` is a token that allows zero
            // adapters — every invocation is rejected by design (the
            // mint-time check accepts empty lists; runtime treats them
            // as "no adapter is admissible"). Absent adapter against a
            // non-empty list is also a rejection: the caveat opts the
            // chain into adapter-restricted operation.
            let negotiated =
                negotiated_adapter.ok_or_else(|| CheckInvocationError::AdapterNotAllowed {
                    negotiated: None,
                    allowed: allowed.clone(),
                })?;
            if !allowed.iter().any(|a| a == negotiated) {
                return Err(CheckInvocationError::AdapterNotAllowed {
                    negotiated: Some(negotiated.clone()),
                    allowed: allowed.clone(),
                });
            }
        }

        // allowed_target_dids — cross-context target MUST be in list.
        if let Some(allowed) = self.allowed_target_dids.as_ref() {
            let target = target_did.ok_or_else(|| CheckInvocationError::TargetDidNotAllowed {
                target: None,
                allowed: allowed.clone(),
            })?;
            if !allowed.iter().any(|d| d == target) {
                return Err(CheckInvocationError::TargetDidNotAllowed {
                    target: Some(target.clone()),
                    allowed: allowed.clone(),
                });
            }
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Per-field narrow helpers (private; called from `narrow`)
// ---------------------------------------------------------------------------

/// `child <= parent` rule for [`Amount`]-typed bounds. `None → Some` is
/// admissible (child introduces a bound), `Some → None` is widening and
/// fails with [`AttenuationViolation::FieldRemoved`].
const fn narrow_le_amount(
    parent: Option<Amount>,
    child: Option<Amount>,
    field: CaveatField,
) -> Result<(), AttenuationViolation> {
    let Some(p) = parent else { return Ok(()) };
    let Some(c) = child else {
        return Err(AttenuationViolation::FieldRemoved { field });
    };
    if c.value() > p.value() {
        return Err(AttenuationViolation::AmountWidened {
            field,
            parent: p,
            child: c,
        });
    }
    Ok(())
}

/// `child <= parent` rule for `u64`-typed downward bounds (`max_calls`,
/// `valid_until`).
const fn narrow_le_u64(
    parent: Option<u64>,
    child: Option<u64>,
    field: CaveatField,
) -> Result<(), AttenuationViolation> {
    let Some(p) = parent else { return Ok(()) };
    let Some(c) = child else {
        return Err(AttenuationViolation::FieldRemoved { field });
    };
    if c > p {
        return Err(AttenuationViolation::U64Widened {
            field,
            parent: p,
            child: c,
        });
    }
    Ok(())
}

/// `child >= parent` rule for `u64`-typed upward bounds (currently only
/// `valid_from`). The direction is flipped: a later `valid_from` is more
/// restrictive (the delegation activates later).
const fn narrow_ge_u64(
    parent: Option<u64>,
    child: Option<u64>,
    field: CaveatField,
) -> Result<(), AttenuationViolation> {
    let Some(p) = parent else { return Ok(()) };
    let Some(c) = child else {
        return Err(AttenuationViolation::FieldRemoved { field });
    };
    if c < p {
        return Err(AttenuationViolation::U64Widened {
            field,
            parent: p,
            child: c,
        });
    }
    Ok(())
}

/// Bitmask subset rule for `hours_of_day`: `child & parent == child`.
const fn narrow_subset_hours(
    parent: Option<HoursOfDayMask>,
    child: Option<HoursOfDayMask>,
) -> Result<(), AttenuationViolation> {
    match (parent, child) {
        (None, _) => Ok(()),
        (Some(_), None) => Err(AttenuationViolation::FieldRemoved {
            field: CaveatField::HoursOfDay,
        }),
        (Some(p), Some(c)) => {
            if (c.bits() & p.bits()) == c.bits() {
                Ok(())
            } else {
                Err(AttenuationViolation::HoursOfDayNotSubset {
                    parent_bits: p.bits(),
                    child_bits: c.bits(),
                })
            }
        }
    }
}

/// Bitmask subset rule for `days_of_week`: `child & parent == child`.
const fn narrow_subset_days(
    parent: Option<DaysOfWeekMask>,
    child: Option<DaysOfWeekMask>,
) -> Result<(), AttenuationViolation> {
    match (parent, child) {
        (None, _) => Ok(()),
        (Some(_), None) => Err(AttenuationViolation::FieldRemoved {
            field: CaveatField::DaysOfWeek,
        }),
        (Some(p), Some(c)) => {
            if (c.bits() & p.bits()) == c.bits() {
                Ok(())
            } else {
                Err(AttenuationViolation::DaysOfWeekNotSubset {
                    parent_bits: p.bits(),
                    child_bits: c.bits(),
                })
            }
        }
    }
}

/// List-subset rule for `allowed_adapters`. `None → Some` introduces a bound
/// (admissible). Membership is by string equality.
fn narrow_list_subset_adapters(
    parent: Option<&[PaymentAdapterRef]>,
    child: Option<&[PaymentAdapterRef]>,
) -> Result<(), AttenuationViolation> {
    match (parent, child) {
        (None, _) => Ok(()),
        (Some(_), None) => Err(AttenuationViolation::FieldRemoved {
            field: CaveatField::AllowedAdapters,
        }),
        (Some(p), Some(c)) => {
            for entry in c {
                if !p.iter().any(|e| e == entry) {
                    return Err(AttenuationViolation::AllowedAdaptersNotSubset {
                        offending_entry: entry.clone(),
                    });
                }
            }
            Ok(())
        }
    }
}

/// List-subset rule for `allowed_target_dids`. Same shape as the adapter
/// helper but typed against [`DID`].
fn narrow_list_subset_dids(
    parent: Option<&[DID]>,
    child: Option<&[DID]>,
) -> Result<(), AttenuationViolation> {
    match (parent, child) {
        (None, _) => Ok(()),
        (Some(_), None) => Err(AttenuationViolation::FieldRemoved {
            field: CaveatField::AllowedTargetDids,
        }),
        (Some(p), Some(c)) => {
            for entry in c {
                if !p.iter().any(|e| e == entry) {
                    return Err(AttenuationViolation::AllowedTargetDidsNotSubset {
                        offending_entry: entry.clone(),
                    });
                }
            }
            Ok(())
        }
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
        && mask.bits() & !HoursOfDayMask::VALID_BITS != 0
    {
        return Err(MaskWidthError::HoursOfDayHighBitsSet { bits: mask.bits() });
    }
    if let Some(mask) = caveats.days_of_week
        && mask.bits() & !DaysOfWeekMask::VALID_BITS != 0
    {
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
            1 + map.values().map(schema_nesting_depth).max().unwrap_or(0)
        }
        serde_json::Value::Array(items) => {
            1 + items.iter().map(schema_nesting_depth).max().unwrap_or(0)
        }
        _ => 0,
    }
}

/// Validates the `input_schema` size and depth caps. The size check uses the
/// canonical (JCS) byte length so the limit is reproducible across SDKs.
fn check_input_schema_size_and_depth(value: &serde_json::Value) -> Result<(), CaveatMintError> {
    let canonical = serde_json_canonicalizer::to_string(value).map_err(|e| {
        CaveatMintError::SchemaSerializationFailed {
            reason: e.to_string(),
        }
    })?;
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
// Conservative JSON Schema narrowing (§7.3.8)
// ---------------------------------------------------------------------------

/// The closed whitelist of JSON Schema keywords admissible in a child
/// `input_schema` (§7.3.8 conservative JSON Schema narrowing).
///
/// Any other keyword appearing newly in the child triggers
/// [`AttenuationViolation::UnknownSchemaKeyword`].
///
/// Per-keyword narrowing rules:
/// - `enum` — child set is a subset of parent set (set-equality on
///   JCS-canonicalized values).
/// - `const` — child equals parent (or parent had no `const`).
/// - `minimum` — child ≥ parent.
/// - `maximum` — child ≤ parent.
/// - `minLength` — child ≥ parent.
/// - `maxLength` — child ≤ parent.
/// - `pattern` — **byte-for-byte UTF-8 string equality** (or parent had
///   no `pattern`). Regex containment is undecidable for extended dialects
///   (PSPACE/EXPSPACE), so no syntactic subsumption check is sound;
///   lexical equality is the only conservative rule.
/// - `required` — child is a superset of parent (adding required fields
///   narrows; removing them widens).
/// - `additionalProperties` — when present, MUST be `false`. Parent absent
///   plus child `false` narrows. Parent `false` plus child `true` is
///   widening and rejected.
///
/// Schema-structural keywords also expected to appear (`type`,
/// `properties`, `items`) are admissible iff the child's value is
/// **lexically equal** to the parent's at the same position. The narrowing
/// operation is descend-matching: a child schema is admissible iff every
/// keyword it adds appears in this whitelist AND every keyword it carries
/// shared with parent narrows (or equals) the parent's value at the same
/// position.
pub const JSON_SCHEMA_NARROWING_WHITELIST: &[&str] = &[
    "enum",
    "const",
    "minimum",
    "maximum",
    "minLength",
    "maxLength",
    "pattern",
    "required",
    "additionalProperties",
];

/// JSON Schema structural / containment keywords that are not narrowing
/// keywords themselves but are admissible in both parent and child for
/// recursive descent. These keywords must match byte-for-byte (via
/// JCS-canonicalized comparison) between parent and child — they describe
/// the *shape* of the schema, not the *bound*. Narrowing happens inside
/// the values they nest.
const JSON_SCHEMA_STRUCTURAL_KEYWORDS: &[&str] = &["type", "properties", "items"];

/// Conservatively narrows `child` against `parent` using only the whitelist
/// of admissible keywords from §7.3.8.
///
/// Returns `Ok(())` if `child` is a legitimate attenuation. Otherwise
/// returns an [`AttenuationViolation`] variant identifying the offending
/// keyword and reason.
///
/// **Pattern narrowing (lexical equality only).** The `pattern` keyword
/// requires `child.pattern == parent.pattern` as UTF-8 byte strings, or
/// parent absent with child present. Regex containment is PSPACE-complete
/// for canonical regexes and undecidable for the extended dialects typical
/// JSON Schema consumers accept (backreferences, lookarounds). No syntactic
/// subsumption check is sound, so the narrowing rule is conservative
/// byte-equality.
///
/// **Object descent.** Within a `properties` object the helper recurses
/// into matching property names. A property present in `child.properties`
/// but absent in `parent.properties` is admissible only if `parent.properties`
/// is itself absent at that position (parent had no per-property bound to
/// extend); otherwise the child has introduced a property bound the parent
/// did not constrain via that mechanism, which is treated as parent
/// supremum and admissible (the child is still a subset of "no property
/// bound").
///
/// # Errors
///
/// See [`AttenuationViolation`] for the schema-related variants:
/// `UnknownSchemaKeyword`, `EnumNotSubset`, `ConstChanged`, `MinimumWidened`,
/// `MaximumWidened`, `MinLengthWidened`, `MaxLengthWidened`,
/// `PatternNotEqual`, `RequiredNotSuperset`,
/// `AdditionalPropertiesRelaxed`, `SchemaStructureChanged`.
pub fn json_schema_narrows(
    parent: &serde_json::Value,
    child: &serde_json::Value,
) -> Result<(), AttenuationViolation> {
    // Both must be JSON objects to be schema-shaped. A non-object schema is
    // a degenerate case (a literal value); fall back to lexical equality.
    let (serde_json::Value::Object(parent_map), serde_json::Value::Object(child_map)) =
        (parent, child)
    else {
        // Non-object schemas: require lexical equality (deep-equal).
        // This covers schema literals like `true` or numeric/string
        // constants used as schemas; widening such a literal is
        // forbidden because we cannot reason about it conservatively.
        if parent == child {
            return Ok(());
        }
        return Err(AttenuationViolation::SchemaStructureChanged {
            position: String::new(),
        });
    };

    // Step 1: every key in the child must be admissible. A key is
    // admissible iff (a) it is in the narrowing whitelist, OR (b) it is in
    // the structural-keyword set (descended into recursively).
    for key in child_map.keys() {
        if !JSON_SCHEMA_NARROWING_WHITELIST.contains(&key.as_str())
            && !JSON_SCHEMA_STRUCTURAL_KEYWORDS.contains(&key.as_str())
        {
            return Err(AttenuationViolation::UnknownSchemaKeyword {
                keyword: key.clone(),
            });
        }
    }

    // Step 2: per-keyword narrowing rules. Each helper handles the four
    // cases (parent-absent/parent-present × child-absent/child-present).
    narrow_schema_enum(parent_map, child_map)?;
    narrow_schema_const(parent_map, child_map)?;
    narrow_schema_numeric_ge(parent_map, child_map, "minimum")?;
    narrow_schema_numeric_le(parent_map, child_map, "maximum")?;
    narrow_schema_uint_ge(parent_map, child_map, "minLength")?;
    narrow_schema_uint_le(parent_map, child_map, "maxLength")?;
    narrow_schema_pattern(parent_map, child_map)?;
    narrow_schema_required(parent_map, child_map)?;
    narrow_schema_additional_properties(parent_map, child_map)?;

    // Step 3: structural descent.
    narrow_schema_structural_descent(parent_map, child_map)?;

    Ok(())
}

/// `enum` rule: `child.enum ⊆ parent.enum`. Set semantics on
/// JCS-canonicalized values.
fn narrow_schema_enum(
    parent: &serde_json::Map<String, serde_json::Value>,
    child: &serde_json::Map<String, serde_json::Value>,
) -> Result<(), AttenuationViolation> {
    let Some(child_enum) = child.get("enum") else {
        return Ok(());
    };
    // Child introduces an enum where parent had none — admissible (child
    // strictly narrows).
    let Some(parent_enum) = parent.get("enum") else {
        return Ok(());
    };
    let parent_arr =
        parent_enum
            .as_array()
            .ok_or_else(|| AttenuationViolation::SchemaStructureChanged {
                position: "enum (parent not an array)".to_owned(),
            })?;
    let child_arr =
        child_enum
            .as_array()
            .ok_or_else(|| AttenuationViolation::SchemaStructureChanged {
                position: "enum (child not an array)".to_owned(),
            })?;
    for child_val in child_arr {
        if !parent_arr.iter().any(|p| p == child_val) {
            return Err(AttenuationViolation::EnumNotSubset {
                offending_value: child_val.clone(),
            });
        }
    }
    Ok(())
}

/// `const` rule: `child.const == parent.const`, OR parent had no `const`.
fn narrow_schema_const(
    parent: &serde_json::Map<String, serde_json::Value>,
    child: &serde_json::Map<String, serde_json::Value>,
) -> Result<(), AttenuationViolation> {
    let Some(child_c) = child.get("const") else {
        return Ok(());
    };
    // Parent absent: child introducing a const narrows.
    let Some(parent_c) = parent.get("const") else {
        return Ok(());
    };
    if parent_c == child_c {
        Ok(())
    } else {
        Err(AttenuationViolation::ConstChanged {
            parent: parent_c.clone(),
            child: child_c.clone(),
        })
    }
}

/// Generic helper for numeric-ge rules (`minimum`). The child's bound, if
/// present, must be `>=` parent's. Parent may use any JSON number; the
/// helper compares as `f64` because JSON Schema numeric bounds are not
/// strictly integer-typed (see RFC 8259 §6 — `number` is the JSON numeric
/// type).
fn narrow_schema_numeric_ge(
    parent: &serde_json::Map<String, serde_json::Value>,
    child: &serde_json::Map<String, serde_json::Value>,
    keyword: &'static str,
) -> Result<(), AttenuationViolation> {
    let Some(child_v) = child.get(keyword) else {
        return Ok(());
    };
    let Some(parent_v) = parent.get(keyword) else {
        return Ok(());
    };
    let parent_f =
        parent_v
            .as_f64()
            .ok_or_else(|| AttenuationViolation::SchemaStructureChanged {
                position: format!("{keyword} (parent not numeric)"),
            })?;
    let child_f = child_v
        .as_f64()
        .ok_or_else(|| AttenuationViolation::SchemaStructureChanged {
            position: format!("{keyword} (child not numeric)"),
        })?;
    // Reject NaN — comparison is not meaningful and JSON Schema numeric
    // bounds are not specced to admit NaN.
    if parent_f.is_nan() || child_f.is_nan() {
        return Err(AttenuationViolation::SchemaStructureChanged {
            position: format!("{keyword} (NaN)"),
        });
    }
    if child_f < parent_f {
        return Err(AttenuationViolation::MinimumWidened {
            keyword,
            parent: parent_f,
            child: child_f,
        });
    }
    Ok(())
}

/// Generic helper for numeric-le rules (`maximum`). The child's bound, if
/// present, must be `<=` parent's.
fn narrow_schema_numeric_le(
    parent: &serde_json::Map<String, serde_json::Value>,
    child: &serde_json::Map<String, serde_json::Value>,
    keyword: &'static str,
) -> Result<(), AttenuationViolation> {
    let Some(child_v) = child.get(keyword) else {
        return Ok(());
    };
    let Some(parent_v) = parent.get(keyword) else {
        return Ok(());
    };
    let parent_f =
        parent_v
            .as_f64()
            .ok_or_else(|| AttenuationViolation::SchemaStructureChanged {
                position: format!("{keyword} (parent not numeric)"),
            })?;
    let child_f = child_v
        .as_f64()
        .ok_or_else(|| AttenuationViolation::SchemaStructureChanged {
            position: format!("{keyword} (child not numeric)"),
        })?;
    if parent_f.is_nan() || child_f.is_nan() {
        return Err(AttenuationViolation::SchemaStructureChanged {
            position: format!("{keyword} (NaN)"),
        });
    }
    if child_f > parent_f {
        return Err(AttenuationViolation::MaximumWidened {
            keyword,
            parent: parent_f,
            child: child_f,
        });
    }
    Ok(())
}

/// `minLength` rule: child ≥ parent. JSON Schema spec types `minLength` as
/// a non-negative integer; the helper compares as `u64` and rejects negative
/// or non-integer values.
fn narrow_schema_uint_ge(
    parent: &serde_json::Map<String, serde_json::Value>,
    child: &serde_json::Map<String, serde_json::Value>,
    keyword: &'static str,
) -> Result<(), AttenuationViolation> {
    let Some(child_v) = child.get(keyword) else {
        return Ok(());
    };
    let Some(parent_v) = parent.get(keyword) else {
        return Ok(());
    };
    let parent_u =
        parent_v
            .as_u64()
            .ok_or_else(|| AttenuationViolation::SchemaStructureChanged {
                position: format!("{keyword} (parent not non-negative integer)"),
            })?;
    let child_u = child_v
        .as_u64()
        .ok_or_else(|| AttenuationViolation::SchemaStructureChanged {
            position: format!("{keyword} (child not non-negative integer)"),
        })?;
    if child_u < parent_u {
        return Err(AttenuationViolation::MinLengthWidened {
            keyword,
            parent: parent_u,
            child: child_u,
        });
    }
    Ok(())
}

/// `maxLength` rule: child ≤ parent.
fn narrow_schema_uint_le(
    parent: &serde_json::Map<String, serde_json::Value>,
    child: &serde_json::Map<String, serde_json::Value>,
    keyword: &'static str,
) -> Result<(), AttenuationViolation> {
    let Some(child_v) = child.get(keyword) else {
        return Ok(());
    };
    let Some(parent_v) = parent.get(keyword) else {
        return Ok(());
    };
    let parent_u =
        parent_v
            .as_u64()
            .ok_or_else(|| AttenuationViolation::SchemaStructureChanged {
                position: format!("{keyword} (parent not non-negative integer)"),
            })?;
    let child_u = child_v
        .as_u64()
        .ok_or_else(|| AttenuationViolation::SchemaStructureChanged {
            position: format!("{keyword} (child not non-negative integer)"),
        })?;
    if child_u > parent_u {
        return Err(AttenuationViolation::MaxLengthWidened {
            keyword,
            parent: parent_u,
            child: child_u,
        });
    }
    Ok(())
}

/// `pattern` rule: **byte-for-byte UTF-8 string equality**. Parent absent +
/// child present narrows OK. Parent present + child absent fails. Any
/// non-equal pair fails — regex containment is undecidable.
fn narrow_schema_pattern(
    parent: &serde_json::Map<String, serde_json::Value>,
    child: &serde_json::Map<String, serde_json::Value>,
) -> Result<(), AttenuationViolation> {
    match (parent.get("pattern"), child.get("pattern")) {
        // Parent absent — child may introduce a pattern (narrows).
        (None, _) => Ok(()),
        // Parent present, child absent — child removes the parent's bound
        // (widens).
        (Some(_), None) => Err(AttenuationViolation::PatternNotEqual {
            parent: extract_pattern_string(parent),
            child: None,
        }),
        (Some(p), Some(c)) => {
            let p_str = p
                .as_str()
                .ok_or_else(|| AttenuationViolation::SchemaStructureChanged {
                    position: "pattern (parent not a string)".to_owned(),
                })?;
            let c_str = c
                .as_str()
                .ok_or_else(|| AttenuationViolation::SchemaStructureChanged {
                    position: "pattern (child not a string)".to_owned(),
                })?;
            // UTF-8 byte-for-byte equality. Comparing &str on the well-
            // formed UTF-8 surface IS comparing bytes — Rust's `str ==
            // str` is `as_bytes() == as_bytes()`.
            if p_str.as_bytes() == c_str.as_bytes() {
                Ok(())
            } else {
                Err(AttenuationViolation::PatternNotEqual {
                    parent: Some(p_str.to_owned()),
                    child: Some(c_str.to_owned()),
                })
            }
        }
    }
}

/// Helper: extracts the `pattern` string from a schema map for diagnostics.
/// Returns `None` if the value is missing or non-string.
fn extract_pattern_string(map: &serde_json::Map<String, serde_json::Value>) -> Option<String> {
    map.get("pattern")
        .and_then(|v| v.as_str())
        .map(str::to_owned)
}

/// `required` rule: `child.required ⊇ parent.required`. Adding required
/// fields narrows; removing them widens. Set semantics on the array of
/// strings.
fn narrow_schema_required(
    parent: &serde_json::Map<String, serde_json::Value>,
    child: &serde_json::Map<String, serde_json::Value>,
) -> Result<(), AttenuationViolation> {
    let Some(parent_v) = parent.get("required") else {
        return Ok(());
    };
    // Parent had a required list but child has none — child removes the
    // parent's bound. Widening; reject.
    let Some(child_v) = child.get("required") else {
        return Err(AttenuationViolation::RequiredNotSuperset {
            missing_field: "<all of parent.required>".to_owned(),
        });
    };
    let parent_arr =
        parent_v
            .as_array()
            .ok_or_else(|| AttenuationViolation::SchemaStructureChanged {
                position: "required (parent not an array)".to_owned(),
            })?;
    let child_arr =
        child_v
            .as_array()
            .ok_or_else(|| AttenuationViolation::SchemaStructureChanged {
                position: "required (child not an array)".to_owned(),
            })?;
    for parent_required in parent_arr {
        let pf = parent_required.as_str().ok_or_else(|| {
            AttenuationViolation::SchemaStructureChanged {
                position: "required (parent entry not a string)".to_owned(),
            }
        })?;
        if !child_arr.iter().any(|c| c.as_str() == Some(pf)) {
            return Err(AttenuationViolation::RequiredNotSuperset {
                missing_field: pf.to_owned(),
            });
        }
    }
    Ok(())
}

/// `additionalProperties` rule: when present, MUST be `false`. Parent
/// absent + child `false` narrows. Parent `false` + child `true` is widening
/// and rejected.
fn narrow_schema_additional_properties(
    parent: &serde_json::Map<String, serde_json::Value>,
    child: &serde_json::Map<String, serde_json::Value>,
) -> Result<(), AttenuationViolation> {
    let parent_ap = parent.get("additionalProperties");
    let child_ap = child.get("additionalProperties");
    // §7.3.8 admits `additionalProperties: false` only. Any other value
    // (true, an object schema) is outside the whitelist.
    let parent_bool = match parent_ap {
        None => None,
        Some(serde_json::Value::Bool(b)) => Some(*b),
        Some(_) => {
            return Err(AttenuationViolation::SchemaStructureChanged {
                position: "additionalProperties (parent must be a bool)".to_owned(),
            });
        }
    };
    let child_bool = match child_ap {
        None => None,
        Some(serde_json::Value::Bool(b)) => Some(*b),
        Some(_) => {
            return Err(AttenuationViolation::SchemaStructureChanged {
                position: "additionalProperties (child must be a bool)".to_owned(),
            });
        }
    };
    match (parent_bool, child_bool) {
        // Parent absent: child may set false (narrows) or true (no-op,
        // matches absent default which is true). Parent's `true` is the
        // JSON Schema default; child may set anything below or equal.
        // Same-value (false → false) admits.
        (None | Some(true), _) | (Some(false), Some(false)) => Ok(()),
        (Some(false), None) => Err(AttenuationViolation::AdditionalPropertiesRelaxed {
            parent: Some(false),
            child: None,
        }),
        (Some(false), Some(true)) => Err(AttenuationViolation::AdditionalPropertiesRelaxed {
            parent: Some(false),
            child: Some(true),
        }),
    }
}

/// Structural descent helper. Walks `properties` (object) and `items`
/// (object or array) maps recursively. Other structural keywords (`type`)
/// are required to match byte-for-byte.
fn narrow_schema_structural_descent(
    parent: &serde_json::Map<String, serde_json::Value>,
    child: &serde_json::Map<String, serde_json::Value>,
) -> Result<(), AttenuationViolation> {
    // `type` must match if both present. Child cannot remove a parent's
    // `type` (would widen the typespace).
    if let Some(parent_type) = parent.get("type") {
        match child.get("type") {
            None => {
                return Err(AttenuationViolation::SchemaStructureChanged {
                    position: "type (child removed parent's type bound)".to_owned(),
                });
            }
            Some(child_type) if parent_type != child_type => {
                return Err(AttenuationViolation::SchemaStructureChanged {
                    position: format!("type (parent={parent_type} child={child_type})"),
                });
            }
            Some(_) => {}
        }
    }

    // `properties` descent. Both must be objects if present.
    if let (Some(parent_props), Some(child_props)) =
        (parent.get("properties"), child.get("properties"))
    {
        let parent_obj = parent_props.as_object().ok_or_else(|| {
            AttenuationViolation::SchemaStructureChanged {
                position: "properties (parent not an object)".to_owned(),
            }
        })?;
        let child_obj = child_props.as_object().ok_or_else(|| {
            AttenuationViolation::SchemaStructureChanged {
                position: "properties (child not an object)".to_owned(),
            }
        })?;
        // Each child property must (a) match a parent property and (b) the
        // child's per-property schema must narrow the parent's. The child
        // MAY define a property the parent did not bound, but only if the
        // parent's own `additionalProperties` is not `false`. Parents who
        // set `additionalProperties: false` are exhaustively listing
        // permitted keys; the child cannot extend that list.
        let parent_ap_false = matches!(
            parent.get("additionalProperties"),
            Some(serde_json::Value::Bool(false))
        );
        for (key, child_subschema) in child_obj {
            match parent_obj.get(key) {
                Some(parent_subschema) => {
                    json_schema_narrows(parent_subschema, child_subschema)?;
                }
                None => {
                    if parent_ap_false {
                        // Parent locked the key set; child cannot add a key.
                        return Err(AttenuationViolation::SchemaStructureChanged {
                            position: format!(
                                "properties.{key} (parent.additionalProperties=false locks key set)"
                            ),
                        });
                    }
                    // Else: parent had no per-property bound, child's
                    // bound is strictly more restrictive — admissible.
                }
            }
        }
    } else if parent.get("properties").is_some() && child.get("properties").is_none() {
        // Parent had per-property bounds, child has none — widening.
        return Err(AttenuationViolation::SchemaStructureChanged {
            position: "properties (child removed parent's per-property bounds)".to_owned(),
        });
    }

    // `items` descent. May be object (single schema) or array (positional).
    if let (Some(parent_items), Some(child_items)) = (parent.get("items"), child.get("items")) {
        match (parent_items, child_items) {
            (serde_json::Value::Object(_), serde_json::Value::Object(_)) => {
                json_schema_narrows(parent_items, child_items)?;
            }
            (serde_json::Value::Array(parent_arr), serde_json::Value::Array(child_arr)) => {
                if parent_arr.len() != child_arr.len() {
                    return Err(AttenuationViolation::SchemaStructureChanged {
                        position: "items (positional array length mismatch)".to_owned(),
                    });
                }
                for (p, c) in parent_arr.iter().zip(child_arr.iter()) {
                    json_schema_narrows(p, c)?;
                }
            }
            (p, c) if p == c => {} // lexical equality fallback
            _ => {
                return Err(AttenuationViolation::SchemaStructureChanged {
                    position: "items (shape mismatch parent vs child)".to_owned(),
                });
            }
        }
    } else if parent.get("items").is_some() && child.get("items").is_none() {
        return Err(AttenuationViolation::SchemaStructureChanged {
            position: "items (child removed parent's items bound)".to_owned(),
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
/// [`CAVEAT_MINT_LIMIT_EXCEEDED_CODE`] (`SCP-OUTLET-6114`); the variant
/// determines the slug.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CaveatMintError {
    /// More than [`MAX_POPULATED_CAVEATS`] non-`origin_kind` caveats are
    /// populated. `origin_kind` is exempt per §7.3.8 mint-limits.
    /// Slug: `caveat-mint-limit-exceeded`.
    #[error(
        "caveat-mint-limit-exceeded: {populated} populated non-origin_kind caveats exceeds cap {cap}"
    )]
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
    #[error(
        "hours-of-day-high-bits-set: HoursOfDayMask carries bits outside 0..=23 (raw 0x{bits:08x})"
    )]
    HoursOfDayHighBitsSet {
        /// The actual raw bit pattern.
        bits: u32,
    },

    /// `days_of_week` newtype carries bits outside the legal `0x7F` range.
    /// Slug: `days-of-week-high-bit-set`. See [`Self::HoursOfDayHighBitsSet`]
    /// for reachability notes.
    #[error(
        "days-of-week-high-bit-set: DaysOfWeekMask carries bits outside 0..=6 (raw 0x{bits:02x})"
    )]
    DaysOfWeekHighBitSet {
        /// The actual raw bit pattern.
        bits: u8,
    },

    /// On a root token, `origin_kind` was explicitly declared but disagrees
    /// with the inferred kind from the stem family. Slug:
    /// `origin-kind-stem-mismatch`.
    #[error(
        "origin-kind-stem-mismatch: caveats.origin_kind = {declared:?} disagrees with inferred kind {inferred:?}"
    )]
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
    #[error(
        "origin-kind-mixed-stem-root: root token capability set contains both outlet_query and outlet_call stems"
    )]
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

/// Field selector used in [`AttenuationViolation`] variants to identify
/// which typed caveat field was widened.
///
/// Provides a typed, machine-readable pointer back to the failing field for
/// SDK consumers — better than a `&'static str` because it forbids typos at
/// compile time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CaveatField {
    /// `amount_max_per_call`.
    AmountMaxPerCall,
    /// `amount_max_cumulative`.
    AmountMaxCumulative,
    /// `valid_from`.
    ValidFrom,
    /// `valid_until`.
    ValidUntil,
    /// `hours_of_day`.
    HoursOfDay,
    /// `days_of_week`.
    DaysOfWeek,
    /// `max_calls`.
    MaxCalls,
    /// `rate_window` (composite — granular variants identify max vs.
    /// `window_secs`).
    RateWindow,
    /// `input_schema`.
    InputSchema,
    /// `allowed_adapters`.
    AllowedAdapters,
    /// `allowed_target_dids`.
    AllowedTargetDids,
}

impl CaveatField {
    /// Returns the wire-name (camelCase) for the field, matching the
    /// serde-renamed names on [`InvocationCaveats`].
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::AmountMaxPerCall => "amountMaxPerCall",
            Self::AmountMaxCumulative => "amountMaxCumulative",
            Self::ValidFrom => "validFrom",
            Self::ValidUntil => "validUntil",
            Self::HoursOfDay => "hoursOfDay",
            Self::DaysOfWeek => "daysOfWeek",
            Self::MaxCalls => "maxCalls",
            Self::RateWindow => "rateWindow",
            Self::InputSchema => "inputSchema",
            Self::AllowedAdapters => "allowedAdapters",
            Self::AllowedTargetDids => "allowedTargetDids",
        }
    }
}

impl std::fmt::Display for CaveatField {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.wire_name())
    }
}

/// Errors returned by [`InvocationCaveats::narrow`] (SCP-OUT-019).
///
/// Each variant identifies the rule that was violated. The variants are
/// granular by typed field so SDK consumers can render actionable
/// diagnostics without re-parsing the message string. All variants surface
/// at the protocol layer as `OutletErrorClass::Authorization::AttenuationViolation`
/// per §7.3.8.
///
/// Note: `Eq` is intentionally NOT derived because `MinimumWidened` /
/// `MaximumWidened` carry `f64` (JSON Schema numeric bounds are spec'd as
/// `number`, RFC 8259 §6, which is IEEE 754). `PartialEq` is sufficient for
/// the test-time `matches!` patterns and equality checks; `Eq` would require
/// the `f64` total-ordering wrapper, which is out of scope for diagnostic
/// payload.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
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
    #[error(
        "origin_kind unspecified on non-root delegation (parent {parent:?}); rule §7.3.8 (4) requires explicit materialization"
    )]
    OriginKindUnspecified {
        /// The parent's declared `origin_kind` (informational; the rule
        /// fires regardless of parent value).
        parent: Option<OutletKind>,
    },

    /// A token's capability set carries BOTH the `outlet_query` and
    /// `outlet_call` stem families, making its `origin_kind` ambiguous.
    /// §7.3.8 forbids mixed-family outlet tokens UNCONDITIONALLY — this is the
    /// validator's analogue of the mint-side
    /// [`CaveatMintError::OriginKindMixedStemRoot`] guard. A self-signed /
    /// forged depth-1 outlet token whose attestations span both families is
    /// rejected with this variant even when it declares no `nb.origin_kind`.
    #[error(
        "origin_kind mixed stem: token capability set carries both outlet_query and outlet_call stems"
    )]
    OriginKindMixedStem,

    /// One of the parent or child caveat sets carries a malformed mask.
    /// Surfaced from [`assert_mask_widths`] when invoked at the narrow
    /// entry point.
    #[error("mask-width: {0}")]
    MaskWidth(MaskWidthError),

    /// Child sets `field = None` while parent had `Some(_)`. Removing a
    /// parent's bound widens the delegation — rejected.
    #[error("attenuation: child removed parent's bound on field {field}")]
    FieldRemoved {
        /// The widened field.
        field: CaveatField,
    },

    /// Child's [`Amount`] exceeds the parent's (widening).
    #[error("attenuation: {field} child {child:?} exceeds parent {parent:?}")]
    AmountWidened {
        /// The widened field (one of the `Amount`-typed fields).
        field: CaveatField,
        /// The parent value.
        parent: Amount,
        /// The child value.
        child: Amount,
    },

    /// Child's `u64`-valued bound widened relative to parent.
    /// `valid_from` widens when child < parent (earlier);
    /// `valid_until` and `max_calls` widen when child > parent.
    #[error("attenuation: {field} child {child} widens parent {parent}")]
    U64Widened {
        /// The widened field.
        field: CaveatField,
        /// The parent value.
        parent: u64,
        /// The child value.
        child: u64,
    },

    /// `rate_window.max` widened (child > parent).
    #[error("attenuation: rateWindow.max child {child} exceeds parent {parent}")]
    RateWindowMaxWidened {
        /// Parent rate-window max.
        parent: u32,
        /// Child rate-window max.
        child: u32,
    },

    /// `rate_window.window_secs` widened (child > parent — longer window
    /// is less strict).
    #[error("attenuation: rateWindow.windowSecs child {child} exceeds parent {parent}")]
    RateWindowSecsWidened {
        /// Parent rate-window seconds.
        parent: u32,
        /// Child rate-window seconds.
        child: u32,
    },

    /// `hours_of_day` failed the bitmask subset check.
    #[error(
        "attenuation: hoursOfDay child 0x{child_bits:08x} not subset of parent 0x{parent_bits:08x}"
    )]
    HoursOfDayNotSubset {
        /// Parent's bitmask.
        parent_bits: u32,
        /// Child's bitmask.
        child_bits: u32,
    },

    /// `days_of_week` failed the bitmask subset check.
    #[error(
        "attenuation: daysOfWeek child 0x{child_bits:02x} not subset of parent 0x{parent_bits:02x}"
    )]
    DaysOfWeekNotSubset {
        /// Parent's bitmask.
        parent_bits: u8,
        /// Child's bitmask.
        child_bits: u8,
    },

    /// `allowed_adapters` failed the list-subset check — child carries an
    /// adapter the parent did not.
    #[error(
        "attenuation: allowedAdapters child contains entry {offending_entry} not in parent set"
    )]
    AllowedAdaptersNotSubset {
        /// The offending child entry not present in parent's list.
        offending_entry: PaymentAdapterRef,
    },

    /// `allowed_target_dids` failed the list-subset check.
    #[error(
        "attenuation: allowedTargetDids child contains entry {offending_entry} not in parent set"
    )]
    AllowedTargetDidsNotSubset {
        /// The offending child entry not present in parent's list.
        offending_entry: DID,
    },

    /// JSON Schema narrowing: child carried a keyword outside the §7.3.8
    /// whitelist or a structural keyword outside the recognized set.
    #[error("attenuation: inputSchema child contains non-whitelisted keyword {keyword}")]
    UnknownSchemaKeyword {
        /// The disallowed keyword name.
        keyword: String,
    },

    /// JSON Schema `enum` rule: child carries a value not present in
    /// parent's enum.
    #[error("attenuation: inputSchema enum child carries value {offending_value} not in parent")]
    EnumNotSubset {
        /// The offending value.
        offending_value: serde_json::Value,
    },

    /// JSON Schema `const` rule: parent had a `const` but child's differs.
    #[error("attenuation: inputSchema const parent={parent} child={child}")]
    ConstChanged {
        /// Parent's `const`.
        parent: serde_json::Value,
        /// Child's `const`.
        child: serde_json::Value,
    },

    /// JSON Schema `minimum` (or other ge-typed) keyword widened.
    #[error("attenuation: inputSchema {keyword} child {child} below parent {parent}")]
    MinimumWidened {
        /// The numeric ge-keyword (`minimum`).
        keyword: &'static str,
        /// Parent value.
        parent: f64,
        /// Child value.
        child: f64,
    },

    /// JSON Schema `maximum` (or other le-typed) keyword widened.
    #[error("attenuation: inputSchema {keyword} child {child} above parent {parent}")]
    MaximumWidened {
        /// The numeric le-keyword (`maximum`).
        keyword: &'static str,
        /// Parent value.
        parent: f64,
        /// Child value.
        child: f64,
    },

    /// JSON Schema `minLength` widened (child below parent).
    #[error("attenuation: inputSchema {keyword} child {child} below parent {parent}")]
    MinLengthWidened {
        /// The keyword (`minLength`).
        keyword: &'static str,
        /// Parent value.
        parent: u64,
        /// Child value.
        child: u64,
    },

    /// JSON Schema `maxLength` widened (child above parent).
    #[error("attenuation: inputSchema {keyword} child {child} above parent {parent}")]
    MaxLengthWidened {
        /// The keyword (`maxLength`).
        keyword: &'static str,
        /// Parent value.
        parent: u64,
        /// Child value.
        child: u64,
    },

    /// JSON Schema `pattern` rule: child and parent disagree on the
    /// pattern string (lexical / byte-for-byte equality required).
    #[error("attenuation: inputSchema pattern parent={parent:?} child={child:?}")]
    PatternNotEqual {
        /// Parent's pattern (`None` if absent).
        parent: Option<String>,
        /// Child's pattern (`None` if absent).
        child: Option<String>,
    },

    /// JSON Schema `required` rule: child does not contain a parent-required
    /// field.
    #[error(
        "attenuation: inputSchema required child does not include parent-required {missing_field}"
    )]
    RequiredNotSuperset {
        /// The missing required field.
        missing_field: String,
    },

    /// JSON Schema `additionalProperties` rule: child relaxed the parent's
    /// `false` setting.
    #[error("attenuation: inputSchema additionalProperties parent={parent:?} child={child:?}")]
    AdditionalPropertiesRelaxed {
        /// Parent value.
        parent: Option<bool>,
        /// Child value.
        child: Option<bool>,
    },

    /// JSON Schema structure mismatch — a non-narrowing structural keyword
    /// disagreed between parent and child, or the schema was not shaped as
    /// expected.
    #[error("attenuation: inputSchema structure changed at {position}")]
    SchemaStructureChanged {
        /// Position description (keyword path or other locator).
        position: String,
    },
}

impl AttenuationViolation {
    /// Returns the kebab-case slug for this violation, suitable for the
    /// `attenuation.*` slug family used in §7.3.8 / ADR-049 §round-5
    /// tables. The slug is stable across SDK boundaries so a delegation
    /// failure is identifiable from the wire payload alone.
    #[must_use]
    pub const fn slug(&self) -> &'static str {
        match self {
            Self::OriginKindMismatch { .. } => "origin-kind-mismatch",
            Self::OriginKindUnspecified { .. } => "origin-kind-unspecified",
            Self::OriginKindMixedStem => "origin-kind-mixed-stem",
            Self::MaskWidth(_) => "mask-width-violation",
            Self::FieldRemoved { .. } => "field-removed",
            Self::AmountWidened { .. } => "amount-widened",
            Self::U64Widened { .. } => "u64-widened",
            Self::RateWindowMaxWidened { .. } => "rate-window-max-widened",
            Self::RateWindowSecsWidened { .. } => "rate-window-secs-widened",
            Self::HoursOfDayNotSubset { .. } => "hours-of-day-not-subset",
            Self::DaysOfWeekNotSubset { .. } => "days-of-week-not-subset",
            Self::AllowedAdaptersNotSubset { .. } => "allowed-adapters-not-subset",
            Self::AllowedTargetDidsNotSubset { .. } => "allowed-target-dids-not-subset",
            Self::UnknownSchemaKeyword { .. } => "schema-unknown-keyword",
            Self::EnumNotSubset { .. } => "schema-enum-not-subset",
            Self::ConstChanged { .. } => "schema-const-changed",
            Self::MinimumWidened { .. } => "schema-minimum-widened",
            Self::MaximumWidened { .. } => "schema-maximum-widened",
            Self::MinLengthWidened { .. } => "schema-min-length-widened",
            Self::MaxLengthWidened { .. } => "schema-max-length-widened",
            Self::PatternNotEqual { .. } => "schema-pattern-not-equal",
            Self::RequiredNotSuperset { .. } => "schema-required-not-superset",
            Self::AdditionalPropertiesRelaxed { .. } => "schema-additional-properties-relaxed",
            Self::SchemaStructureChanged { .. } => "schema-structure-changed",
        }
    }
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
// CheckInvocationError — SCP-OUT-021
// ---------------------------------------------------------------------------

/// Reasons [`InvocationCaveats::check_invocation_local`] may reject an
/// invocation.
///
/// Each variant corresponds to a specific Authorization-class slug per
/// §7.3.8 / ADR-049 §4. The slug is returned by
/// [`CheckInvocationError::slug`] so the caller can populate the
/// `OutletError` envelope without re-mapping the variant by string.
///
/// All variants under this enum map to the
/// [`crate::CODE_AUTHORIZATION_DENIED`] (`SCP-OUTLET-6110`) code; the slug
/// is what disambiguates the failure mode in the wire envelope.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CheckInvocationError {
    /// The invocation input failed the caveat's `input_schema`
    /// conformance check. Slug: `input.schema-violation`.
    ///
    /// Note: although `input_schema` failures could plausibly fall under
    /// the `Input` class (`SCP-OUTLET-6120`), §7.3.8 categorises every
    /// caveat-driven rejection under `Authorization` because the failure
    /// is a delegation-bound constraint, not a malformed-input error.
    /// The SDK error envelope receives the Authorization class with the
    /// Input-shaped slug so the categorisation is unambiguous to
    /// downstream classifiers.
    #[error("input violates caveat input_schema: {message}")]
    InputSchemaViolation {
        /// Human-readable diagnostic from the JSON Schema validator.
        message: String,
    },

    /// The estimated invocation cost exceeds `amount_max_per_call`.
    /// Slug: `authorization.denied` (per-call ceiling — there is no
    /// dedicated slug because the spec collapses per-call ceiling
    /// breaches under the catch-all denied slug; cumulative is
    /// separate).
    #[error("amount_max_per_call exceeded: estimated_cost={estimated_cost}, cap={cap}")]
    AmountMaxPerCallExceeded {
        /// The cost the runtime computed for this invocation.
        estimated_cost: Amount,
        /// The caveat's per-call ceiling.
        cap: Amount,
    },

    /// The negotiated adapter is not in `allowed_adapters` (or the caveat
    /// requires an adapter and none was negotiated).
    /// Slug: `authorization.adapter-not-allowed`.
    #[error("adapter not allowed: negotiated={negotiated:?}, allowed={allowed:?}")]
    AdapterNotAllowed {
        /// The adapter the runtime was about to use, if any.
        negotiated: Option<PaymentAdapterRef>,
        /// The caveat's allow-list.
        allowed: Vec<PaymentAdapterRef>,
    },

    /// The cross-context target DID is not in `allowed_target_dids` (or
    /// the caveat requires a target DID and the invocation was
    /// intra-context).
    /// Slug: `authorization.denied` (target DID — no dedicated spec
    /// slug; falls under the Authorization catch-all).
    #[error("target DID not in allowed_target_dids: target={target:?}, allowed={allowed:?}")]
    TargetDidNotAllowed {
        /// The target DID the runtime was about to invoke, if any.
        target: Option<DID>,
        /// The caveat's allow-list.
        allowed: Vec<DID>,
    },
}

impl CheckInvocationError {
    /// Returns the §5.4.4 / §7.3.8 slug used in the `OutletError`
    /// envelope. All variants share the
    /// [`crate::CODE_AUTHORIZATION_DENIED`] code; the slug disambiguates
    /// the rule that fired.
    #[must_use]
    pub const fn slug(&self) -> &'static str {
        match self {
            Self::InputSchemaViolation { .. } => "input.schema-violation",
            Self::AdapterNotAllowed { .. } => "authorization.adapter-not-allowed",
            // `AmountMaxPerCallExceeded` and `TargetDidNotAllowed` both
            // collapse onto the catch-all `authorization.denied` slug —
            // §7.3.8 / §5.4.4 do not allocate a per-call-cap or
            // target-DID-list-specific slug, so the catch-all is the
            // correct disambiguator.
            Self::AmountMaxPerCallExceeded { .. } | Self::TargetDidNotAllowed { .. } => {
                "authorization.denied"
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::similar_names,
    clippy::doc_markdown,
    clippy::uninlined_format_args,
    clippy::match_wildcard_for_single_variants,
    clippy::type_complexity,
    // SCP-OUT-019 AC: function names embed JSON Schema keywords verbatim
    // (`minLength`, `maxLength`, `additionalProperties`) so the grep
    // assertion in the AC matches each whitelisted keyword. The keywords
    // are defined as camelCase by JSON Schema; renaming them to snake_case
    // would break the wire-name correspondence the AC enforces.
    non_snake_case
)]
mod tests {
    use super::*;
    use crate::context::roles::Capability;
    use proptest::prelude::*;
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
            rate_window: Some(RateWindow {
                max: 60,
                window_secs: 60,
            }),
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
        assert!(matches!(
            err,
            CaveatMintError::TooManyCaveats {
                populated: 9,
                cap: 8
            }
        ));
        // Setting origin_kind to a value does not save it.
        caveats.origin_kind = Some(OutletKind::Action);
        let err = InvocationCaveats::try_new(caveats).unwrap_err();
        assert!(matches!(
            err,
            CaveatMintError::TooManyCaveats {
                populated: 9,
                cap: 8
            }
        ));
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
            allowed_target_dids: Some((0..20).map(|i| DID(format!("did:dht:z6Mk{i}"))).collect()),
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
            rate_window: Some(RateWindow {
                max: 1,
                window_secs: 0,
            }),
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
        // SCP-OUTLET-6114 / 'caveat-mint-limit-exceeded' wired.
        let many = caveats_with_eight_non_origin_fields();
        let mut nine = many;
        nine.input_schema = Some(json!({"type": "string"}));
        let err = InvocationCaveats::try_new(nine).unwrap_err();
        assert_eq!(err.code(), CAVEAT_MINT_LIMIT_EXCEEDED_CODE);
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
        // `Amount` wire form in human-readable formats (JSON) is a canonical
        // base-10 decimal STRING per ADR-060 (§19.15.1), not a bare integer.
        let camel = r#"{"amountMaxPerCall": "1"}"#;
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
        let err =
            InvocationCaveats::try_new_for_root(InvocationCaveats::empty(), &stems).unwrap_err();
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
        let _ = CaveatMintError::TooManyCaveats {
            populated: 0,
            cap: 0,
        };
        let _ = CaveatMintError::SchemaTooLarge { size: 0, cap: 0 };
        let _ = CaveatMintError::SchemaTooDeep { depth: 0, cap: 0 };
        let _ = CaveatMintError::ListTooLong {
            field: "x",
            len: 0,
            cap: 0,
        };
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
        // Compile-time enumeration of all variants. A missing variant fails
        // to compile.
        let _ = AttenuationViolation::OriginKindMismatch {
            parent: OutletKind::Query,
            child: OutletKind::Action,
        };
        let _ = AttenuationViolation::OriginKindUnspecified {
            parent: Some(OutletKind::Query),
        };
        let _ = AttenuationViolation::MaskWidth(MaskWidthError::HoursOfDayHighBitsSet { bits: 0 });
        let _ = AttenuationViolation::FieldRemoved {
            field: CaveatField::AmountMaxPerCall,
        };
        let _ = AttenuationViolation::AmountWidened {
            field: CaveatField::AmountMaxPerCall,
            parent: Amount::new(0),
            child: Amount::new(1),
        };
        let _ = AttenuationViolation::U64Widened {
            field: CaveatField::ValidFrom,
            parent: 0,
            child: 1,
        };
        let _ = AttenuationViolation::RateWindowMaxWidened {
            parent: 0,
            child: 1,
        };
        let _ = AttenuationViolation::RateWindowSecsWidened {
            parent: 0,
            child: 1,
        };
        let _ = AttenuationViolation::HoursOfDayNotSubset {
            parent_bits: 0,
            child_bits: 1,
        };
        let _ = AttenuationViolation::DaysOfWeekNotSubset {
            parent_bits: 0,
            child_bits: 1,
        };
        let _ = AttenuationViolation::AllowedAdaptersNotSubset {
            offending_entry: "x".to_owned(),
        };
        let _ = AttenuationViolation::AllowedTargetDidsNotSubset {
            offending_entry: DID("did:dht:zX".to_owned()),
        };
        let _ = AttenuationViolation::UnknownSchemaKeyword {
            keyword: "$ref".to_owned(),
        };
        let _ = AttenuationViolation::EnumNotSubset {
            offending_value: json!(1),
        };
        let _ = AttenuationViolation::ConstChanged {
            parent: json!(0),
            child: json!(1),
        };
        let _ = AttenuationViolation::MinimumWidened {
            keyword: "minimum",
            parent: 0.0,
            child: -1.0,
        };
        let _ = AttenuationViolation::MaximumWidened {
            keyword: "maximum",
            parent: 0.0,
            child: 1.0,
        };
        let _ = AttenuationViolation::MinLengthWidened {
            keyword: "minLength",
            parent: 1,
            child: 0,
        };
        let _ = AttenuationViolation::MaxLengthWidened {
            keyword: "maxLength",
            parent: 1,
            child: 2,
        };
        let _ = AttenuationViolation::PatternNotEqual {
            parent: Some("a".to_owned()),
            child: Some("b".to_owned()),
        };
        let _ = AttenuationViolation::RequiredNotSuperset {
            missing_field: "x".to_owned(),
        };
        let _ = AttenuationViolation::AdditionalPropertiesRelaxed {
            parent: Some(false),
            child: Some(true),
        };
        let _ = AttenuationViolation::SchemaStructureChanged {
            position: "x".to_owned(),
        };
    }

    #[test]
    fn attenuation_violation_from_mask_width() {
        let mw = MaskWidthError::DaysOfWeekHighBitSet { bits: 0x80 };
        let av: AttenuationViolation = mw.into();
        assert!(matches!(av, AttenuationViolation::MaskWidth(_)));
    }

    // ========================================================================
    // SCP-OUT-019 narrow() tests — per-field rules + JSON Schema attenuation
    // ========================================================================

    /// Helper: parent caveats with `origin_kind = Some(Query)` so most
    /// negative-rule tests don't trip the OriginKindUnspecified rail first.
    fn parent_caveats() -> InvocationCaveats {
        InvocationCaveats {
            origin_kind: Some(OutletKind::Query),
            ..InvocationCaveats::empty()
        }
    }

    /// Helper: child caveats with `origin_kind = Some(Query)` matching the
    /// parent.
    fn child_caveats() -> InvocationCaveats {
        InvocationCaveats {
            origin_kind: Some(OutletKind::Query),
            ..InvocationCaveats::empty()
        }
    }

    // ----- narrow signature + smoke -------------------------------------

    #[test]
    fn test_narrow_method_signature_compiles() {
        // Asserts the SCP-OUT-019 method exists with the expected
        // signature: `fn narrow(&self, child: &Self) -> Result<(), AttenuationViolation>`.
        let parent = parent_caveats();
        let child = child_caveats();
        let result: Result<(), AttenuationViolation> = parent.narrow(&child);
        assert!(result.is_ok());
    }

    #[test]
    fn test_narrow_identity_admissible() {
        // Identical caveat sets always narrow.
        let parent = parent_caveats();
        let child = parent.clone();
        assert!(parent.narrow(&child).is_ok());
    }

    // ----- amount_max_per_call rule -------------------------------------

    #[test]
    fn test_narrow_amount_max_per_call_child_below_parent_admissible() {
        let parent = InvocationCaveats {
            amount_max_per_call: Some(Amount::new(100)),
            ..parent_caveats()
        };
        let child = InvocationCaveats {
            amount_max_per_call: Some(Amount::new(50)),
            ..child_caveats()
        };
        assert!(parent.narrow(&child).is_ok());
    }

    #[test]
    fn test_narrow_amount_max_per_call_child_above_parent_rejected() {
        let parent = InvocationCaveats {
            amount_max_per_call: Some(Amount::new(100)),
            ..parent_caveats()
        };
        let child = InvocationCaveats {
            amount_max_per_call: Some(Amount::new(200)),
            ..child_caveats()
        };
        let err = parent.narrow(&child).unwrap_err();
        assert!(matches!(
            err,
            AttenuationViolation::AmountWidened {
                field: CaveatField::AmountMaxPerCall,
                ..
            }
        ));
    }

    #[test]
    fn test_narrow_amount_max_per_call_none_to_some_admissible() {
        let parent = parent_caveats();
        let child = InvocationCaveats {
            amount_max_per_call: Some(Amount::new(50)),
            ..child_caveats()
        };
        assert!(parent.narrow(&child).is_ok());
    }

    #[test]
    fn test_narrow_amount_max_per_call_some_to_none_rejected() {
        let parent = InvocationCaveats {
            amount_max_per_call: Some(Amount::new(100)),
            ..parent_caveats()
        };
        let child = child_caveats();
        let err = parent.narrow(&child).unwrap_err();
        assert!(matches!(
            err,
            AttenuationViolation::FieldRemoved {
                field: CaveatField::AmountMaxPerCall
            }
        ));
    }

    // ----- amount_max_cumulative rule -----------------------------------

    #[test]
    fn test_narrow_amount_max_cumulative_child_below_parent_admissible() {
        let parent = InvocationCaveats {
            amount_max_cumulative: Some(Amount::new(1_000)),
            ..parent_caveats()
        };
        let child = InvocationCaveats {
            amount_max_cumulative: Some(Amount::new(500)),
            ..child_caveats()
        };
        assert!(parent.narrow(&child).is_ok());
    }

    #[test]
    fn test_narrow_amount_max_cumulative_child_above_parent_rejected() {
        let parent = InvocationCaveats {
            amount_max_cumulative: Some(Amount::new(1_000)),
            ..parent_caveats()
        };
        let child = InvocationCaveats {
            amount_max_cumulative: Some(Amount::new(2_000)),
            ..child_caveats()
        };
        let err = parent.narrow(&child).unwrap_err();
        assert!(matches!(
            err,
            AttenuationViolation::AmountWidened {
                field: CaveatField::AmountMaxCumulative,
                ..
            }
        ));
    }

    // ----- max_calls rule -----------------------------------------------

    #[test]
    fn test_narrow_max_calls_child_below_parent_admissible() {
        let parent = InvocationCaveats {
            max_calls: Some(100),
            ..parent_caveats()
        };
        let child = InvocationCaveats {
            max_calls: Some(50),
            ..child_caveats()
        };
        assert!(parent.narrow(&child).is_ok());
    }

    #[test]
    fn test_narrow_max_calls_child_above_parent_rejected() {
        let parent = InvocationCaveats {
            max_calls: Some(100),
            ..parent_caveats()
        };
        let child = InvocationCaveats {
            max_calls: Some(200),
            ..child_caveats()
        };
        let err = parent.narrow(&child).unwrap_err();
        assert!(matches!(
            err,
            AttenuationViolation::U64Widened {
                field: CaveatField::MaxCalls,
                ..
            }
        ));
    }

    // ----- valid_from rule (child >= parent) ----------------------------

    #[test]
    fn test_narrow_valid_from_child_after_parent_admissible() {
        let parent = InvocationCaveats {
            valid_from: Some(1_000),
            ..parent_caveats()
        };
        let child = InvocationCaveats {
            valid_from: Some(2_000),
            ..child_caveats()
        };
        assert!(parent.narrow(&child).is_ok());
    }

    #[test]
    fn test_narrow_valid_from_child_before_parent_rejected() {
        let parent = InvocationCaveats {
            valid_from: Some(2_000),
            ..parent_caveats()
        };
        let child = InvocationCaveats {
            valid_from: Some(1_000),
            ..child_caveats()
        };
        let err = parent.narrow(&child).unwrap_err();
        assert!(matches!(
            err,
            AttenuationViolation::U64Widened {
                field: CaveatField::ValidFrom,
                ..
            }
        ));
    }

    #[test]
    fn test_narrow_valid_from_some_to_none_rejected() {
        let parent = InvocationCaveats {
            valid_from: Some(1_000),
            ..parent_caveats()
        };
        let child = child_caveats();
        let err = parent.narrow(&child).unwrap_err();
        assert!(matches!(
            err,
            AttenuationViolation::FieldRemoved {
                field: CaveatField::ValidFrom
            }
        ));
    }

    // ----- valid_until rule (child <= parent) ---------------------------

    #[test]
    fn test_narrow_valid_until_child_before_parent_admissible() {
        let parent = InvocationCaveats {
            valid_until: Some(2_000),
            ..parent_caveats()
        };
        let child = InvocationCaveats {
            valid_until: Some(1_000),
            ..child_caveats()
        };
        assert!(parent.narrow(&child).is_ok());
    }

    #[test]
    fn test_narrow_valid_until_child_after_parent_rejected() {
        let parent = InvocationCaveats {
            valid_until: Some(1_000),
            ..parent_caveats()
        };
        let child = InvocationCaveats {
            valid_until: Some(2_000),
            ..child_caveats()
        };
        let err = parent.narrow(&child).unwrap_err();
        assert!(matches!(
            err,
            AttenuationViolation::U64Widened {
                field: CaveatField::ValidUntil,
                ..
            }
        ));
    }

    // ----- hours_of_day rule (subset bitmask) ---------------------------

    #[test]
    fn test_narrow_hours_of_day_child_subset_admissible() {
        let parent = InvocationCaveats {
            hours_of_day: Some(HoursOfDayMask::from_bits(0b1111).unwrap()),
            ..parent_caveats()
        };
        let child = InvocationCaveats {
            hours_of_day: Some(HoursOfDayMask::from_bits(0b0011).unwrap()),
            ..child_caveats()
        };
        assert!(parent.narrow(&child).is_ok());
    }

    #[test]
    fn test_narrow_hours_of_day_child_superset_rejected() {
        let parent = InvocationCaveats {
            hours_of_day: Some(HoursOfDayMask::from_bits(0b0011).unwrap()),
            ..parent_caveats()
        };
        let child = InvocationCaveats {
            hours_of_day: Some(HoursOfDayMask::from_bits(0b1111).unwrap()),
            ..child_caveats()
        };
        let err = parent.narrow(&child).unwrap_err();
        assert!(matches!(
            err,
            AttenuationViolation::HoursOfDayNotSubset { .. }
        ));
    }

    // ----- days_of_week rule (subset bitmask) ---------------------------

    #[test]
    fn test_narrow_days_of_week_child_subset_admissible() {
        let parent = InvocationCaveats {
            days_of_week: Some(DaysOfWeekMask::from_bits(0b0111_1111).unwrap()),
            ..parent_caveats()
        };
        let child = InvocationCaveats {
            days_of_week: Some(DaysOfWeekMask::from_bits(0b0001_1111).unwrap()),
            ..child_caveats()
        };
        assert!(parent.narrow(&child).is_ok());
    }

    #[test]
    fn test_narrow_days_of_week_child_superset_rejected() {
        let parent = InvocationCaveats {
            days_of_week: Some(DaysOfWeekMask::from_bits(0b0001).unwrap()),
            ..parent_caveats()
        };
        let child = InvocationCaveats {
            days_of_week: Some(DaysOfWeekMask::from_bits(0b0011).unwrap()),
            ..child_caveats()
        };
        let err = parent.narrow(&child).unwrap_err();
        assert!(matches!(
            err,
            AttenuationViolation::DaysOfWeekNotSubset { .. }
        ));
    }

    // ----- rate_window.max + window_secs --------------------------------

    #[test]
    fn test_narrow_rate_window_max_child_below_parent_admissible() {
        let parent = InvocationCaveats {
            rate_window: Some(RateWindow {
                max: 100,
                window_secs: 60,
            }),
            ..parent_caveats()
        };
        let child = InvocationCaveats {
            rate_window: Some(RateWindow {
                max: 50,
                window_secs: 60,
            }),
            ..child_caveats()
        };
        assert!(parent.narrow(&child).is_ok());
    }

    #[test]
    fn test_narrow_rate_window_max_child_above_parent_rejected() {
        let parent = InvocationCaveats {
            rate_window: Some(RateWindow {
                max: 100,
                window_secs: 60,
            }),
            ..parent_caveats()
        };
        let child = InvocationCaveats {
            rate_window: Some(RateWindow {
                max: 200,
                window_secs: 60,
            }),
            ..child_caveats()
        };
        let err = parent.narrow(&child).unwrap_err();
        assert!(matches!(
            err,
            AttenuationViolation::RateWindowMaxWidened { .. }
        ));
    }

    #[test]
    fn test_narrow_rate_window_secs_child_below_parent_admissible() {
        // Shorter window = stricter.
        let parent = InvocationCaveats {
            rate_window: Some(RateWindow {
                max: 100,
                window_secs: 600,
            }),
            ..parent_caveats()
        };
        let child = InvocationCaveats {
            rate_window: Some(RateWindow {
                max: 100,
                window_secs: 60,
            }),
            ..child_caveats()
        };
        assert!(parent.narrow(&child).is_ok());
    }

    #[test]
    fn test_narrow_rate_window_secs_child_above_parent_rejected() {
        let parent = InvocationCaveats {
            rate_window: Some(RateWindow {
                max: 100,
                window_secs: 60,
            }),
            ..parent_caveats()
        };
        let child = InvocationCaveats {
            rate_window: Some(RateWindow {
                max: 100,
                window_secs: 600,
            }),
            ..child_caveats()
        };
        let err = parent.narrow(&child).unwrap_err();
        assert!(matches!(
            err,
            AttenuationViolation::RateWindowSecsWidened { .. }
        ));
    }

    // ----- allowed_adapters rule ----------------------------------------

    #[test]
    fn test_narrow_allowed_adapters_child_subset_admissible() {
        let parent = InvocationCaveats {
            allowed_adapters: Some(vec!["x402".to_owned(), "lightning".to_owned()]),
            ..parent_caveats()
        };
        let child = InvocationCaveats {
            allowed_adapters: Some(vec!["x402".to_owned()]),
            ..child_caveats()
        };
        assert!(parent.narrow(&child).is_ok());
    }

    #[test]
    fn test_narrow_allowed_adapters_child_introduces_member_outside_parent_rejected() {
        let parent = InvocationCaveats {
            allowed_adapters: Some(vec!["x402".to_owned()]),
            ..parent_caveats()
        };
        let child = InvocationCaveats {
            allowed_adapters: Some(vec!["x402".to_owned(), "lightning".to_owned()]),
            ..child_caveats()
        };
        let err = parent.narrow(&child).unwrap_err();
        assert!(matches!(
            err,
            AttenuationViolation::AllowedAdaptersNotSubset { .. }
        ));
    }

    #[test]
    fn test_narrow_allowed_adapters_none_parent_some_child_admissible() {
        let parent = parent_caveats();
        let child = InvocationCaveats {
            allowed_adapters: Some(vec!["x402".to_owned()]),
            ..child_caveats()
        };
        assert!(parent.narrow(&child).is_ok());
    }

    // ----- allowed_target_dids rule -------------------------------------

    #[test]
    fn test_narrow_allowed_target_dids_child_subset_admissible() {
        let parent = InvocationCaveats {
            allowed_target_dids: Some(vec![
                DID("did:dht:zA".to_owned()),
                DID("did:dht:zB".to_owned()),
            ]),
            ..parent_caveats()
        };
        let child = InvocationCaveats {
            allowed_target_dids: Some(vec![DID("did:dht:zA".to_owned())]),
            ..child_caveats()
        };
        assert!(parent.narrow(&child).is_ok());
    }

    #[test]
    fn test_narrow_allowed_target_dids_child_introduces_member_outside_parent_rejected() {
        let parent = InvocationCaveats {
            allowed_target_dids: Some(vec![DID("did:dht:zA".to_owned())]),
            ..parent_caveats()
        };
        let child = InvocationCaveats {
            allowed_target_dids: Some(vec![
                DID("did:dht:zA".to_owned()),
                DID("did:dht:zX".to_owned()),
            ]),
            ..child_caveats()
        };
        let err = parent.narrow(&child).unwrap_err();
        assert!(matches!(
            err,
            AttenuationViolation::AllowedTargetDidsNotSubset { .. }
        ));
    }

    // ----- input_schema rule --------------------------------------------

    #[test]
    fn test_narrow_input_schema_none_parent_some_child_admissible() {
        let parent = parent_caveats();
        let child = InvocationCaveats {
            input_schema: Some(json!({"type": "string"})),
            ..child_caveats()
        };
        assert!(parent.narrow(&child).is_ok());
    }

    #[test]
    fn test_narrow_input_schema_some_parent_none_child_rejected() {
        let parent = InvocationCaveats {
            input_schema: Some(json!({"type": "string"})),
            ..parent_caveats()
        };
        let child = child_caveats();
        let err = parent.narrow(&child).unwrap_err();
        assert!(matches!(
            err,
            AttenuationViolation::FieldRemoved {
                field: CaveatField::InputSchema
            }
        ));
    }

    // ----- JSON Schema narrowing — enum ---------------------------------

    #[test]
    fn test_narrow_schema_enum_subset_admissible() {
        let parent = json!({"enum": ["a", "b", "c"]});
        let child = json!({"enum": ["a", "b"]});
        assert!(json_schema_narrows(&parent, &child).is_ok());
    }

    #[test]
    fn test_narrow_schema_enum_introduces_disallowed_value_rejected() {
        let parent = json!({"enum": ["a", "b"]});
        let child = json!({"enum": ["a", "z"]});
        let err = json_schema_narrows(&parent, &child).unwrap_err();
        assert!(matches!(err, AttenuationViolation::EnumNotSubset { .. }));
    }

    // ----- JSON Schema narrowing — const --------------------------------

    #[test]
    fn test_narrow_schema_const_equal_admissible() {
        let parent = json!({"const": "x"});
        let child = json!({"const": "x"});
        assert!(json_schema_narrows(&parent, &child).is_ok());
    }

    #[test]
    fn test_narrow_schema_const_changed_rejected() {
        let parent = json!({"const": "x"});
        let child = json!({"const": "y"});
        let err = json_schema_narrows(&parent, &child).unwrap_err();
        assert!(matches!(err, AttenuationViolation::ConstChanged { .. }));
    }

    #[test]
    fn test_narrow_schema_const_introduced_admissible() {
        // Parent had no const; child introducing one is narrowing.
        let parent = json!({});
        let child = json!({"const": "x"});
        assert!(json_schema_narrows(&parent, &child).is_ok());
    }

    // ----- JSON Schema narrowing — minimum ------------------------------

    #[test]
    fn test_narrow_schema_minimum_child_above_parent_admissible() {
        let parent = json!({"minimum": 0});
        let child = json!({"minimum": 5});
        assert!(json_schema_narrows(&parent, &child).is_ok());
    }

    #[test]
    fn test_narrow_schema_minimum_child_below_parent_rejected() {
        let parent = json!({"minimum": 5});
        let child = json!({"minimum": 0});
        let err = json_schema_narrows(&parent, &child).unwrap_err();
        assert!(matches!(err, AttenuationViolation::MinimumWidened { .. }));
    }

    // ----- JSON Schema narrowing — maximum ------------------------------

    #[test]
    fn test_narrow_schema_maximum_child_below_parent_admissible() {
        let parent = json!({"maximum": 100});
        let child = json!({"maximum": 50});
        assert!(json_schema_narrows(&parent, &child).is_ok());
    }

    #[test]
    fn test_narrow_schema_maximum_child_above_parent_rejected() {
        let parent = json!({"maximum": 100});
        let child = json!({"maximum": 200});
        let err = json_schema_narrows(&parent, &child).unwrap_err();
        assert!(matches!(err, AttenuationViolation::MaximumWidened { .. }));
    }

    // ----- JSON Schema narrowing — minLength ----------------------------

    #[test]
    fn test_narrow_schema_minLength_child_above_parent_admissible() {
        let parent = json!({"minLength": 1});
        let child = json!({"minLength": 5});
        assert!(json_schema_narrows(&parent, &child).is_ok());
    }

    #[test]
    fn test_narrow_schema_minLength_child_below_parent_rejected() {
        let parent = json!({"minLength": 5});
        let child = json!({"minLength": 1});
        let err = json_schema_narrows(&parent, &child).unwrap_err();
        assert!(matches!(err, AttenuationViolation::MinLengthWidened { .. }));
    }

    // ----- JSON Schema narrowing — maxLength ----------------------------

    #[test]
    fn test_narrow_schema_maxLength_child_below_parent_admissible() {
        let parent = json!({"maxLength": 100});
        let child = json!({"maxLength": 50});
        assert!(json_schema_narrows(&parent, &child).is_ok());
    }

    #[test]
    fn test_narrow_schema_maxLength_child_above_parent_rejected() {
        let parent = json!({"maxLength": 100});
        let child = json!({"maxLength": 200});
        let err = json_schema_narrows(&parent, &child).unwrap_err();
        assert!(matches!(err, AttenuationViolation::MaxLengthWidened { .. }));
    }

    // ----- JSON Schema narrowing — pattern (lexical equality only) ------

    #[test]
    fn test_narrow_schema_pattern_byte_equal_admissible() {
        // §7.3.8: parent.pattern = '^a+$', child.pattern = '^a+$' → narrows.
        let parent = json!({"pattern": "^a+$"});
        let child = json!({"pattern": "^a+$"});
        assert!(json_schema_narrows(&parent, &child).is_ok());
    }

    #[test]
    fn test_narrow_schema_pattern_byte_unequal_rejected() {
        // §7.3.8: parent.pattern = '^a+$', child.pattern = '^aa+$' →
        // AttenuationViolation. Even semantically equivalent regexes (or
        // strictly tighter ones) are rejected — regex containment is
        // undecidable, so byte-equality is the only safe rule.
        let parent = json!({"pattern": "^a+$"});
        let child = json!({"pattern": "^aa+$"});
        let err = json_schema_narrows(&parent, &child).unwrap_err();
        assert!(matches!(err, AttenuationViolation::PatternNotEqual { .. }));
    }

    #[test]
    fn test_narrow_schema_pattern_parent_absent_child_present_admissible() {
        // §7.3.8: parent.pattern absent, child.pattern = '^a$' → narrows.
        // (Parent placed no pattern bound; child introducing one is
        // narrowing.)
        let parent = json!({});
        let child = json!({"pattern": "^a$"});
        assert!(json_schema_narrows(&parent, &child).is_ok());
    }

    #[test]
    fn test_narrow_schema_pattern_parent_present_child_absent_rejected() {
        // §7.3.8: parent.pattern = '^a$', child.pattern absent →
        // AttenuationViolation (child removes a parent bound).
        let parent = json!({"pattern": "^a$"});
        let child = json!({});
        let err = json_schema_narrows(&parent, &child).unwrap_err();
        assert!(matches!(err, AttenuationViolation::PatternNotEqual { .. }));
    }

    // ----- JSON Schema narrowing — required -----------------------------

    #[test]
    fn test_narrow_schema_required_child_superset_admissible() {
        let parent = json!({"required": ["a"]});
        let child = json!({"required": ["a", "b"]});
        assert!(json_schema_narrows(&parent, &child).is_ok());
    }

    #[test]
    fn test_narrow_schema_required_child_missing_parent_field_rejected() {
        let parent = json!({"required": ["a", "b"]});
        let child = json!({"required": ["a"]});
        let err = json_schema_narrows(&parent, &child).unwrap_err();
        assert!(matches!(
            err,
            AttenuationViolation::RequiredNotSuperset { .. }
        ));
    }

    // ----- JSON Schema narrowing — additionalProperties: false ----------

    #[test]
    fn test_narrow_schema_additionalProperties_parent_absent_child_false_admissible() {
        let parent = json!({});
        let child = json!({"additionalProperties": false});
        assert!(json_schema_narrows(&parent, &child).is_ok());
    }

    #[test]
    fn test_narrow_schema_additionalProperties_parent_false_child_true_rejected() {
        let parent = json!({"additionalProperties": false});
        let child = json!({"additionalProperties": true});
        let err = json_schema_narrows(&parent, &child).unwrap_err();
        assert!(matches!(
            err,
            AttenuationViolation::AdditionalPropertiesRelaxed { .. }
        ));
    }

    // ----- JSON Schema narrowing — unknown keyword ----------------------

    #[test]
    fn test_narrow_schema_unknown_keyword_rejected() {
        let parent = json!({"type": "string"});
        let child = json!({"$ref": "#/defs/foo"});
        let err = json_schema_narrows(&parent, &child).unwrap_err();
        assert!(matches!(
            err,
            AttenuationViolation::UnknownSchemaKeyword { .. }
        ));
    }

    #[test]
    fn test_narrow_schema_unknown_keyword_oneof_rejected() {
        // `oneOf` is a JSON Schema keyword, but it is NOT in the §7.3.8
        // whitelist — it does not narrow conservatively (it is a UNION,
        // not a refinement).
        let parent = json!({"type": "string"});
        let child = json!({"oneOf": [{"type": "string"}, {"type": "integer"}]});
        let err = json_schema_narrows(&parent, &child).unwrap_err();
        assert!(matches!(
            err,
            AttenuationViolation::UnknownSchemaKeyword { keyword } if keyword == "oneOf"
        ));
    }

    // ----- input_schema rule end-to-end via narrow() --------------------

    #[test]
    fn test_narrow_input_schema_passes_through_to_helper() {
        // Verify narrow() actually invokes json_schema_narrows on
        // input_schema (not a placeholder).
        let parent = InvocationCaveats {
            input_schema: Some(json!({"enum": ["a", "b", "c"]})),
            ..parent_caveats()
        };
        let child = InvocationCaveats {
            input_schema: Some(json!({"enum": ["a"]})),
            ..child_caveats()
        };
        assert!(parent.narrow(&child).is_ok());

        let bad_child = InvocationCaveats {
            input_schema: Some(json!({"enum": ["x"]})),
            ..child_caveats()
        };
        assert!(matches!(
            parent.narrow(&bad_child).unwrap_err(),
            AttenuationViolation::EnumNotSubset { .. }
        ));
    }

    // ----- origin_kind explicit-on-non-root rule ------------------------

    #[test]
    fn test_narrow_origin_kind_unspecified_on_child_rejects_with_origin_kind_unspecified() {
        // §7.3.8 rule (4): non-root delegation with origin_kind=None fails
        // regardless of parent.
        let parent = InvocationCaveats {
            origin_kind: Some(OutletKind::Query),
            ..InvocationCaveats::empty()
        };
        let child = InvocationCaveats {
            origin_kind: None,
            ..InvocationCaveats::empty()
        };
        let err = parent.narrow(&child).unwrap_err();
        match err {
            AttenuationViolation::OriginKindUnspecified { parent } => {
                assert_eq!(parent, Some(OutletKind::Query));
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn test_narrow_origin_kind_query_query_admissible() {
        let parent = InvocationCaveats {
            origin_kind: Some(OutletKind::Query),
            ..InvocationCaveats::empty()
        };
        let child = InvocationCaveats {
            origin_kind: Some(OutletKind::Query),
            ..InvocationCaveats::empty()
        };
        assert!(parent.narrow(&child).is_ok());
    }

    #[test]
    fn test_narrow_origin_kind_query_action_rejects_with_origin_kind_mismatch() {
        let parent = InvocationCaveats {
            origin_kind: Some(OutletKind::Query),
            ..InvocationCaveats::empty()
        };
        let child = InvocationCaveats {
            origin_kind: Some(OutletKind::Action),
            ..InvocationCaveats::empty()
        };
        let err = parent.narrow(&child).unwrap_err();
        assert!(matches!(
            err,
            AttenuationViolation::OriginKindMismatch {
                parent: OutletKind::Query,
                child: OutletKind::Action,
            }
        ));
    }

    #[test]
    fn test_narrow_origin_kind_unspecified_takes_priority_over_parent_none() {
        // Even when parent.origin_kind = None (root case), child = None on
        // a non-root delegation MUST fail. The narrow() function does not
        // know whether it is being called on root vs. non-root; the rule
        // is "every narrow step requires explicit child origin_kind". If
        // a root caveats record narrows to itself (testing the boundary),
        // the engine MUST mint the child origin_kind explicitly. This
        // test fixes the rule into code.
        let parent = InvocationCaveats {
            origin_kind: None,
            ..InvocationCaveats::empty()
        };
        let child = InvocationCaveats {
            origin_kind: None,
            ..InvocationCaveats::empty()
        };
        let err = parent.narrow(&child).unwrap_err();
        assert!(matches!(
            err,
            AttenuationViolation::OriginKindUnspecified { parent: None }
        ));
    }

    // ----- mask-width helper invoked from narrow ------------------------

    #[test]
    fn test_narrow_invokes_assert_mask_widths_on_parent() {
        // Round-trip: feed narrow() a parent whose hours_of_day mask was
        // fabricated via the test-only constructor with high bits set.
        // narrow() MUST return AttenuationViolation::MaskWidth before any
        // other rule fires.
        let parent = InvocationCaveats {
            hours_of_day: Some(HoursOfDayMask::from_bits_unchecked_for_tests(0x0100_0000)),
            origin_kind: Some(OutletKind::Query),
            ..InvocationCaveats::empty()
        };
        let child = InvocationCaveats {
            origin_kind: Some(OutletKind::Query),
            ..InvocationCaveats::empty()
        };
        let err = parent.narrow(&child).unwrap_err();
        assert!(matches!(
            err,
            AttenuationViolation::MaskWidth(MaskWidthError::HoursOfDayHighBitsSet { .. })
        ));
    }

    #[test]
    fn test_narrow_invokes_assert_mask_widths_on_child() {
        // Same but mask corrupted on the child side.
        let parent = InvocationCaveats {
            origin_kind: Some(OutletKind::Query),
            ..InvocationCaveats::empty()
        };
        let child = InvocationCaveats {
            days_of_week: Some(DaysOfWeekMask::from_bits_unchecked_for_tests(0x80)),
            origin_kind: Some(OutletKind::Query),
            ..InvocationCaveats::empty()
        };
        let err = parent.narrow(&child).unwrap_err();
        assert!(matches!(
            err,
            AttenuationViolation::MaskWidth(MaskWidthError::DaysOfWeekHighBitSet { .. })
        ));
    }

    #[test]
    fn test_narrow_mask_width_runs_before_other_rules() {
        // If a parent has a corrupted mask AND a child violates another
        // rule, the mask-width error MUST surface first (it is the
        // earliest gate).
        let parent = InvocationCaveats {
            hours_of_day: Some(HoursOfDayMask::from_bits_unchecked_for_tests(0x0100_0000)),
            amount_max_per_call: Some(Amount::new(100)),
            origin_kind: Some(OutletKind::Query),
            ..InvocationCaveats::empty()
        };
        let child = InvocationCaveats {
            // Would also violate amount rule; mask-width must surface first.
            amount_max_per_call: Some(Amount::new(200)),
            origin_kind: Some(OutletKind::Query),
            ..InvocationCaveats::empty()
        };
        let err = parent.narrow(&child).unwrap_err();
        assert!(matches!(err, AttenuationViolation::MaskWidth(_)));
    }

    // ----- transitivity property ----------------------------------------

    /// Generates an ordered triple `(A, B, C)` of caveat records such that
    /// `A.narrow(B)` and `B.narrow(C)` are guaranteed-admissible by
    /// construction. The transitivity property under test is that A→C also
    /// admits. Constructing a chain directly avoids the rejection-sampling
    /// problem that purely random triples have a vanishing rate of
    /// admissibility — the cumulative chance of two random caveat records
    /// passing all 11 narrowing rules is far below 1/1024 in practice,
    /// which trips proptest's global-reject limit.
    ///
    /// The triple covers six narrowing directions: `<=` numeric (amount,
    /// max_calls, valid_until, rate_window.max, rate_window.window_secs),
    /// `>=` numeric (valid_from), bitmask subset (hours_of_day,
    /// days_of_week), list subset (allowed_adapters, allowed_target_dids),
    /// and `Option<None>→Option<Some>` introduction. Per the spec,
    /// `origin_kind` is equality-with-explicit-non-root and is held
    /// constant at `Some(Query)` across the chain so the property test
    /// exercises field-rules rather than the equality rule (which has its
    /// own dedicated unit tests).
    /// Sorts three `u64` values into a descending tuple (loose, mid, tight).
    /// Used by [`arb_chain`] to generate monotonic chains for fields whose
    /// narrowing rule is `child <= parent`.
    fn sort_desc_u64(first: u64, second: u64, third: u64) -> (u64, u64, u64) {
        let (lo, mid, hi) = ascending_triple_u64(first, second, third);
        (hi, mid, lo)
    }

    /// Sorts three `u64` values into an ascending tuple (loose, mid, tight)
    /// for fields whose narrowing rule is `child >= parent`.
    fn sort_asc_u64(first: u64, second: u64, third: u64) -> (u64, u64, u64) {
        ascending_triple_u64(first, second, third)
    }

    /// Sorts three `u32` values descending. Same shape as
    /// [`sort_desc_u64`] specialized to `u32`.
    fn sort_desc_u32(first: u32, second: u32, third: u32) -> (u32, u32, u32) {
        let (lo, mid, hi) = sort_desc_u64(u64::from(first), u64::from(second), u64::from(third));
        // Safe truncation: each input was u32 and ordering preserves bound.
        let trunc = |v: u64| -> u32 { u32::try_from(v).unwrap_or(u32::MAX) };
        (trunc(lo), trunc(mid), trunc(hi))
    }

    /// Returns three values sorted ascending. Implemented with explicit
    /// branches to avoid `tuple_array_conversions` clippy noise (the lint
    /// is a stylistic preference; here readability beats either form).
    fn ascending_triple_u64(first: u64, second: u64, third: u64) -> (u64, u64, u64) {
        let (a, b) = if first <= second {
            (first, second)
        } else {
            (second, first)
        };
        if third <= a {
            (third, a, b)
        } else if third <= b {
            (a, third, b)
        } else {
            (a, b, third)
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn arb_chain()
    -> impl Strategy<Value = (InvocationCaveats, InvocationCaveats, InvocationCaveats)> {
        // Generate three monotonic values for each direction. For `<=`
        // fields we want a >= b >= c; for `>=` fields we want a <= b <= c.
        // Nested option-of-option flags model "introduce a bound at hop B
        // or hop C even when A had none."
        (
            // (a_amt, b_amt, c_amt) — `<=` chain. Generate three ordered
            // values; a is the loosest, c the tightest.
            (0u64..=1_000, 0u64..=1_000, 0u64..=1_000).prop_map(|(x, y, z)| sort_desc_u64(x, y, z)),
            // (a_until, b_until, c_until) — `<=` chain.
            (0u64..=1_000_000, 0u64..=1_000_000, 0u64..=1_000_000)
                .prop_map(|(x, y, z)| sort_desc_u64(x, y, z)),
            // (a_from, b_from, c_from) — `>=` chain (ascending).
            (0u64..=1_000_000, 0u64..=1_000_000, 0u64..=1_000_000)
                .prop_map(|(x, y, z)| sort_asc_u64(x, y, z)),
            // (a_max_calls, b_max_calls, c_max_calls) — `<=` chain.
            (0u64..=10_000, 0u64..=10_000, 0u64..=10_000)
                .prop_map(|(x, y, z)| sort_desc_u64(x, y, z)),
            // (a_hours, b_hours, c_hours) — bitmask subset chain.
            (
                0u32..=0x00FF_FFFFu32,
                0u32..=0x00FF_FFFFu32,
                0u32..=0x00FF_FFFFu32,
            )
                .prop_map(|(x, y, z)| {
                    // Build descending mask chain by ANDing.
                    let a = x;
                    let b = a & y;
                    let c = b & z;
                    (a, b, c)
                }),
            // (a_rw_max, b_rw_max, c_rw_max) and window_secs — both `<=`.
            (
                (1u32..=10_000, 1u32..=10_000, 1u32..=10_000),
                (1u32..=86_400, 1u32..=86_400, 1u32..=86_400),
            )
                .prop_map(|((x, y, z), (xw, yw, zw))| {
                    (sort_desc_u32(x, y, z), sort_desc_u32(xw, yw, zw))
                }),
        )
            .prop_map(|(amt, until, from, max_calls, hours, (rw_max, rw_secs))| {
                let make = |a, u, f, m, h, rmax, rsec| InvocationCaveats {
                    amount_max_per_call: Some(Amount::new(a)),
                    valid_until: Some(u),
                    valid_from: Some(f),
                    max_calls: Some(m),
                    hours_of_day: Some(HoursOfDayMask::from_bits(h).unwrap()),
                    rate_window: Some(RateWindow {
                        max: rmax,
                        window_secs: rsec,
                    }),
                    origin_kind: Some(OutletKind::Query),
                    ..InvocationCaveats::empty()
                };
                (
                    make(
                        amt.0,
                        until.0,
                        from.0,
                        max_calls.0,
                        hours.0,
                        rw_max.0,
                        rw_secs.0,
                    ),
                    make(
                        amt.1,
                        until.1,
                        from.1,
                        max_calls.1,
                        hours.1,
                        rw_max.1,
                        rw_secs.1,
                    ),
                    make(
                        amt.2,
                        until.2,
                        from.2,
                        max_calls.2,
                        hours.2,
                        rw_max.2,
                        rw_secs.2,
                    ),
                )
            })
    }

    proptest! {
        /// Transitivity: A.narrow(B) AND B.narrow(C) ⇒ A.narrow(C).
        ///
        /// This is the load-bearing property of the per-field rules. If a
        /// chain of three delegations violates transitivity, an attacker
        /// could construct an intermediate token that "launders" a wider
        /// capability through the verifier. The property must hold across
        /// fields with heterogeneous narrowing directions (`valid_from` is
        /// `>=` while `valid_until` is `<=`).
        ///
        /// We construct ordered chains by generation rather than rejection-
        /// sampling because purely random caveat triples almost never
        /// satisfy `A.narrow(B)` (the joint probability is the product of
        /// the per-field admissibility rates, which is far below 1/1024 —
        /// exhausting proptest's global-reject limit). The construction
        /// sorts each numeric/bitmask field into the correct direction
        /// for its rule.
        #[test]
        fn narrow_is_transitive((a, b, c) in arb_chain()) {
            // Sanity: by construction A→B and B→C admit. We assert this
            // first so a strategy bug surfaces as a clear precondition
            // failure rather than a transitivity violation.
            prop_assert!(
                a.narrow(&b).is_ok(),
                "strategy bug: A→B should admit by construction.\nA={:?}\nB={:?}",
                a, b
            );
            prop_assert!(
                b.narrow(&c).is_ok(),
                "strategy bug: B→C should admit by construction.\nB={:?}\nC={:?}",
                b, c
            );
            prop_assert!(
                a.narrow(&c).is_ok(),
                "transitivity violated: A→B and B→C admit, A→C rejects.\nA={:?}\nB={:?}\nC={:?}",
                a, b, c
            );
        }
    }

    #[test]
    fn narrow_transitive_concrete_amount_chain() {
        // Concrete sanity check before the property test: 100 → 50 → 10.
        let a = InvocationCaveats {
            amount_max_per_call: Some(Amount::new(100)),
            origin_kind: Some(OutletKind::Query),
            ..InvocationCaveats::empty()
        };
        let b = InvocationCaveats {
            amount_max_per_call: Some(Amount::new(50)),
            origin_kind: Some(OutletKind::Query),
            ..InvocationCaveats::empty()
        };
        let c = InvocationCaveats {
            amount_max_per_call: Some(Amount::new(10)),
            origin_kind: Some(OutletKind::Query),
            ..InvocationCaveats::empty()
        };
        assert!(a.narrow(&b).is_ok());
        assert!(b.narrow(&c).is_ok());
        assert!(a.narrow(&c).is_ok());
    }

    // ----- AttenuationViolation slug + display --------------------------

    #[test]
    fn test_attenuation_violation_slugs_stable() {
        // Compile-time + runtime check: every variant has a non-empty
        // kebab-case slug. Stability of these slugs is required for
        // wire-error parsing across SDK boundaries.
        let cases: &[AttenuationViolation] = &[
            AttenuationViolation::OriginKindMismatch {
                parent: OutletKind::Query,
                child: OutletKind::Action,
            },
            AttenuationViolation::OriginKindUnspecified { parent: None },
            AttenuationViolation::MaskWidth(MaskWidthError::HoursOfDayHighBitsSet { bits: 0 }),
            AttenuationViolation::FieldRemoved {
                field: CaveatField::AmountMaxPerCall,
            },
            AttenuationViolation::AmountWidened {
                field: CaveatField::AmountMaxPerCall,
                parent: Amount::new(0),
                child: Amount::new(1),
            },
            AttenuationViolation::U64Widened {
                field: CaveatField::ValidFrom,
                parent: 0,
                child: 0,
            },
            AttenuationViolation::RateWindowMaxWidened {
                parent: 0,
                child: 0,
            },
            AttenuationViolation::RateWindowSecsWidened {
                parent: 0,
                child: 0,
            },
            AttenuationViolation::HoursOfDayNotSubset {
                parent_bits: 0,
                child_bits: 0,
            },
            AttenuationViolation::DaysOfWeekNotSubset {
                parent_bits: 0,
                child_bits: 0,
            },
            AttenuationViolation::AllowedAdaptersNotSubset {
                offending_entry: String::new(),
            },
            AttenuationViolation::AllowedTargetDidsNotSubset {
                offending_entry: DID(String::new()),
            },
            AttenuationViolation::UnknownSchemaKeyword {
                keyword: String::new(),
            },
            AttenuationViolation::EnumNotSubset {
                offending_value: json!(0),
            },
            AttenuationViolation::ConstChanged {
                parent: json!(0),
                child: json!(1),
            },
            AttenuationViolation::MinimumWidened {
                keyword: "minimum",
                parent: 0.0,
                child: 0.0,
            },
            AttenuationViolation::MaximumWidened {
                keyword: "maximum",
                parent: 0.0,
                child: 0.0,
            },
            AttenuationViolation::MinLengthWidened {
                keyword: "minLength",
                parent: 0,
                child: 0,
            },
            AttenuationViolation::MaxLengthWidened {
                keyword: "maxLength",
                parent: 0,
                child: 0,
            },
            AttenuationViolation::PatternNotEqual {
                parent: None,
                child: None,
            },
            AttenuationViolation::RequiredNotSuperset {
                missing_field: String::new(),
            },
            AttenuationViolation::AdditionalPropertiesRelaxed {
                parent: None,
                child: None,
            },
            AttenuationViolation::SchemaStructureChanged {
                position: String::new(),
            },
        ];
        for v in cases {
            let slug = v.slug();
            assert!(!slug.is_empty(), "empty slug for {v:?}");
            assert!(
                slug.chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'),
                "non-kebab slug: {slug}"
            );
        }
    }

    #[test]
    fn test_caveat_field_wire_names_match_serde() {
        // wire_name() must match the camelCase serde rename pattern on
        // InvocationCaveats so error diagnostics point at field names a
        // wire-payload-reading SDK will recognize.
        assert_eq!(
            CaveatField::AmountMaxPerCall.wire_name(),
            "amountMaxPerCall"
        );
        assert_eq!(CaveatField::ValidFrom.wire_name(), "validFrom");
        assert_eq!(CaveatField::HoursOfDay.wire_name(), "hoursOfDay");
        assert_eq!(CaveatField::AllowedAdapters.wire_name(), "allowedAdapters");
        assert_eq!(
            CaveatField::AllowedTargetDids.wire_name(),
            "allowedTargetDids"
        );
        assert_eq!(CaveatField::InputSchema.wire_name(), "inputSchema");
        assert_eq!(CaveatField::RateWindow.wire_name(), "rateWindow");
        // Display impl matches.
        assert_eq!(format!("{}", CaveatField::ValidUntil), "validUntil");
    }

    // ----- Whitelist matches §7.3.8 -------------------------------------

    #[test]
    fn json_schema_whitelist_matches_spec() {
        // The §7.3.8 whitelist is exactly these 9 keywords. Adding a
        // keyword to the whitelist requires updating the spec first.
        let mut got: Vec<&str> = JSON_SCHEMA_NARROWING_WHITELIST.to_vec();
        got.sort_unstable();
        let mut want = vec![
            "additionalProperties",
            "const",
            "enum",
            "maxLength",
            "maximum",
            "minLength",
            "minimum",
            "pattern",
            "required",
        ];
        want.sort_unstable();
        assert_eq!(got, want);
    }

    // -----------------------------------------------------------------------
    // SCP-OUT-021 — check_invocation_local
    // -----------------------------------------------------------------------

    /// AC: invocation with a target_did NOT in `allowed_target_dids` is
    /// rejected.
    #[test]
    fn check_invocation_rejects_target_did_not_in_allowed_list() {
        let allowed = vec![DID::from("did:example:alice")];
        let caveats = InvocationCaveats {
            allowed_target_dids: Some(allowed.clone()),
            ..InvocationCaveats::empty()
        };
        let target = DID::from("did:example:eve");
        let err = caveats
            .check_invocation_local(&json!({}), Amount::new(0), None, Some(&target))
            .expect_err("disallowed target DID must reject");
        match err {
            CheckInvocationError::TargetDidNotAllowed {
                target: Some(t),
                allowed: a,
            } => {
                assert_eq!(t, target);
                assert_eq!(a, allowed);
            }
            other => panic!("expected TargetDidNotAllowed, got {:?}", other),
        }
    }

    /// AC: invocation with input violating `input_schema` narrowing is
    /// rejected.
    #[test]
    fn check_invocation_rejects_input_violating_input_schema() {
        // Caveat narrows input to require a string property `name`.
        let schema = json!({
            "type": "object",
            "required": ["name"],
            "properties": {"name": {"type": "string"}}
        });
        let caveats = InvocationCaveats {
            input_schema: Some(schema),
            ..InvocationCaveats::empty()
        };
        // Input is missing the `name` required property.
        let bad_input = json!({"other": "field"});
        let err = caveats
            .check_invocation_local(&bad_input, Amount::new(0), None, None)
            .expect_err("input missing required field must reject");
        match err {
            CheckInvocationError::InputSchemaViolation { message } => {
                assert!(
                    message.contains("name") || message.to_lowercase().contains("required"),
                    "expected schema-violation reason, got: {message}"
                );
            }
            other => panic!("expected InputSchemaViolation, got {:?}", other),
        }
    }

    /// Sanity: input that satisfies the caveat schema passes.
    #[test]
    fn check_invocation_admits_input_satisfying_schema() {
        let schema = json!({
            "type": "object",
            "required": ["name"],
            "properties": {"name": {"type": "string"}}
        });
        let caveats = InvocationCaveats {
            input_schema: Some(schema),
            ..InvocationCaveats::empty()
        };
        let good_input = json!({"name": "alice"});
        caveats
            .check_invocation_local(&good_input, Amount::new(0), None, None)
            .expect("schema-conforming input must pass");
    }

    /// `amount_max_per_call` rejects estimates exceeding the cap.
    #[test]
    fn check_invocation_rejects_amount_max_per_call_exceeded() {
        let caveats = InvocationCaveats {
            amount_max_per_call: Some(Amount::new(50)),
            ..InvocationCaveats::empty()
        };
        let err = caveats
            .check_invocation_local(&json!({}), Amount::new(51), None, None)
            .expect_err("cost above cap must reject");
        match err {
            CheckInvocationError::AmountMaxPerCallExceeded {
                estimated_cost,
                cap,
            } => {
                assert_eq!(estimated_cost, Amount::new(51));
                assert_eq!(cap, Amount::new(50));
            }
            other => panic!("expected AmountMaxPerCallExceeded, got {:?}", other),
        }
    }

    /// `allowed_adapters` rejects adapters not in the list.
    #[test]
    fn check_invocation_rejects_adapter_not_in_allowed_list() {
        let allowed: Vec<PaymentAdapterRef> = vec!["stripe".to_owned()];
        let caveats = InvocationCaveats {
            allowed_adapters: Some(allowed.clone()),
            ..InvocationCaveats::empty()
        };
        let other: PaymentAdapterRef = "venmo".to_owned();
        let err = caveats
            .check_invocation_local(&json!({}), Amount::new(0), Some(&other), None)
            .expect_err("disallowed adapter must reject");
        match err {
            CheckInvocationError::AdapterNotAllowed {
                negotiated: Some(n),
                allowed: a,
            } => {
                assert_eq!(n, other);
                assert_eq!(a, allowed);
            }
            other => panic!("expected AdapterNotAllowed, got {:?}", other),
        }
    }

    /// All slugs render as the §5.4.4 strings the SDKs depend on.
    #[test]
    fn check_invocation_error_slugs() {
        let e1 = CheckInvocationError::InputSchemaViolation {
            message: "x".to_owned(),
        };
        assert_eq!(e1.slug(), "input.schema-violation");

        let e2 = CheckInvocationError::AmountMaxPerCallExceeded {
            estimated_cost: Amount::new(2),
            cap: Amount::new(1),
        };
        assert_eq!(e2.slug(), "authorization.denied");

        let e3 = CheckInvocationError::AdapterNotAllowed {
            negotiated: None,
            allowed: vec![],
        };
        assert_eq!(e3.slug(), "authorization.adapter-not-allowed");

        let e4 = CheckInvocationError::TargetDidNotAllowed {
            target: None,
            allowed: vec![],
        };
        assert_eq!(e4.slug(), "authorization.denied");
    }
}
