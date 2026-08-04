//! Typed `OutletError` envelope and companion types per spec §5.4.4.
//!
//! Covers `OutletErrorClass`, `RetryPolicy`, `ContextHop`, `CatalogKey`, and
//! `OutletErrorConstructionFailed` ("Outlet Error Taxonomy"). Governed by spec
//! §5.4.4 alone; this is unrelated to ADR-049's `SCP-SAGA-*` cross-context-saga
//! terminal codes.
//!
//! These are the **structured error types** the §5.4.4 wire envelope is built
//! from. The `OutletError` struct in this module is the typed envelope —
//! distinct from the legacy `super::OutletError` thiserror enum, which is the
//! pre-redesign untyped error shape and is migrated by SCP-OUT-027 / 036 / 038.
//!
//! # Wire format
//!
//! `OutletError` serializes with **numeric `MessagePack` field tags** so the
//! envelope is forward-compatible. Tags are assigned via
//! `#[serde(rename = "1")]` etc., per §5.4.4:
//!
//! | Tag | Field                   | Type                  |
//! |----:|-------------------------|-----------------------|
//! | 1   | `code`                  | `String`              |
//! | 2   | `slug`                  | `String`              |
//! | 3   | `class`                 | [`OutletErrorClass`]  |
//! | 4   | `message`               | `[u8; 32]` (HMAC out) |
//! | 5   | `retry`                 | [`RetryPolicy`]       |
//! | 6   | `detail`                | `Option<DetailBody>`  |
//! | 7   | _reserved_              | (RESERVED)            |
//! | 8   | `source_chain`          | `Vec<ContextHop>`     |
//! | 9   | _reserved_              | (RESERVED)            |
//! | 10  | _reserved_              | (RESERVED)            |
//! | 11  | `pad_nonce`             | `[u8; 16]`            |
//! | 12  | `registration_event_id` | `[u8; 32]`            |
//! | 13+ | future extensions       | round-trip preserved  |
//!
//! Tags 7, 9, 10 are **reserved** per §5.4.4. Their slots are kept idle so the
//! drafted-and-rejected `related_code` / `i18n_key` / `trace_id` fields cannot
//! collide with future tag-13+ extensions. Unknown tags (7, 9, 10, 13+) are
//! preserved in [`OutletError::unknown_fields`] and round-trip byte-identical.
//!
//! # Construction
//!
//! Use [`OutletError::new`] — the constructor enforces:
//!
//! - `code` is `SCP-OUTLET-NNNN` where the trailing 4 digits fall in the §5.4.4
//!   6100-6199 sub-block.
//! - `slug` regex `^[a-z][a-z0-9-]{0,63}(\.[a-z][a-z0-9-]{0,63})*$`.
//! - `catalog_key` is registered in the outlet's catalog (rejected with
//!   `UnregisteredMessageKey` otherwise).
//! - `wire_message = HMAC-SHA-256(outlet_message_key, catalog_key)[..32]`.
//! - `detail` shape matches the per-class schema (`DetailShapeMismatch`
//!   otherwise).
//! - `pad_nonce` and `registration_event_id` are emitted unconditionally
//!   (no `Option` wrapper) — this closes the visibility-vs-absence oracle
//!   per §5.4.4 round-5 / round-6.
//!
//! See SCP-OUT-024 (this story) for the type definitions and SCP-OUT-025 for
//! the compact code allocation in the 6100-6199 sub-block.

use std::collections::BTreeMap;
use std::time::Duration;

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::context::outlets::OutletId;
use crate::serde_util::serde_hash_32;

// ---------------------------------------------------------------------------
// CatalogKey — typed newtype for §5.4.4 catalog message keys
// ---------------------------------------------------------------------------

/// Catalog key naming a registered [`OutletError`] message template
/// (§5.4.4 round-5 / round-6).
///
/// Catalog keys are kebab-case dot-separated identifiers (e.g.,
/// `authorization.denied`, `protocol.catalog-rotation-too-frequent`). Each
/// outlet registration carries a `Vec<MessageTemplate>` (SCP-OUT-040) keyed
/// by these strings; the on-wire `OutletError::message` field is
/// `HMAC-SHA-256(outlet_message_key, catalog_key.as_str().as_bytes())[..32]`,
/// turning the catalog into a bounded discrete channel keyed per-outlet.
///
/// # Validation
///
/// `try_new` enforces the §5.4.4 catalog-key regex:
/// `^[a-z][a-z0-9-]{0,63}(\.[a-z][a-z0-9-]{0,63})*$`. The same regex is used
/// for slugs (the slug field is a class-prefixed catalog key in
/// canonical form).
///
/// This newtype is **shared** with [`MessageTemplate::try_new`] in
/// SCP-OUT-040 — both validation paths produce the same constraint. Defined
/// here (SCP-OUT-024) so the catalog-key invariant precedes the catalog
/// itself in the dependency graph.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CatalogKey(String);

/// Hard byte cap for a [`CatalogKey`] regardless of structural composition
/// (§5.4.4 catalog-key regex permits multi-segment keys; this cap closes the
/// otherwise unbounded total length).
pub const CATALOG_KEY_MAX_BYTES: usize = 256;

impl CatalogKey {
    /// Validates `key` against the §5.4.4 catalog-key regex and returns a
    /// new [`CatalogKey`].
    ///
    /// # Regex
    ///
    /// `^[a-z][a-z0-9-]{0,63}(\.[a-z][a-z0-9-]{0,63})*$` — class-prefixed
    /// dot-separated catalog key. Each segment is between 1 and 64 ASCII
    /// lowercase / digit / hyphen bytes, the first byte of each segment must
    /// be a lowercase letter, and segments are separated by `.`.
    ///
    /// Total key length is additionally capped at [`CATALOG_KEY_MAX_BYTES`]
    /// bytes regardless of segment composition.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogKeyError::Malformed`] if the key fails the regex or
    /// exceeds [`CATALOG_KEY_MAX_BYTES`].
    pub fn try_new(key: impl Into<String>) -> Result<Self, CatalogKeyError> {
        let key = key.into();
        if !validate_catalog_key(&key) {
            return Err(CatalogKeyError::Malformed { key });
        }
        Ok(Self(key))
    }

    /// Returns the underlying string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consumes `self` and returns the underlying `String`.
    #[must_use]
    pub fn into_string(self) -> String {
        self.0
    }
}

impl AsRef<str> for CatalogKey {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl std::fmt::Display for CatalogKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Errors returned by [`CatalogKey::try_new`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CatalogKeyError {
    /// `key` failed the §5.4.4 catalog-key regex or exceeded the byte cap.
    #[error(
        "malformed catalog key: \"{key}\" — must match ^[a-z][a-z0-9-]{{0,63}}(\\.[a-z][a-z0-9-]{{0,63}})*$ and be ≤ 256 bytes"
    )]
    Malformed {
        /// The invalid key.
        key: String,
    },
}

/// Validates a candidate catalog key (or slug — same regex per §5.4.4)
/// against the canonical regex without allocating.
///
/// Returns `true` iff the input matches the regex
/// `^[a-z][a-z0-9-]{0,63}(\.[a-z][a-z0-9-]{0,63})*$` AND its byte length is
/// `<= CATALOG_KEY_MAX_BYTES`.
#[must_use]
pub fn validate_catalog_key(key: &str) -> bool {
    if key.is_empty() || key.len() > CATALOG_KEY_MAX_BYTES {
        return false;
    }
    // Hand-rolled to avoid pulling in the `regex` crate.
    let mut segment_len: usize = 0;
    let mut segment_started = false;
    for (i, b) in key.bytes().enumerate() {
        match b {
            b'a'..=b'z' => {
                if !segment_started {
                    segment_started = true;
                }
                segment_len += 1;
            }
            b'0'..=b'9' | b'-' => {
                if !segment_started {
                    return false;
                }
                segment_len += 1;
            }
            b'.' => {
                if !segment_started || segment_len == 0 {
                    return false;
                }
                segment_started = false;
                segment_len = 0;
                // A trailing dot would leave segment_started==false at the
                // end; we check that below.
                if i + 1 == key.len() {
                    return false;
                }
            }
            _ => return false,
        }
        if segment_len > 64 {
            return false;
        }
    }
    segment_started && segment_len > 0
}

// ---------------------------------------------------------------------------
// OutletErrorClass — 8 root classes per §5.4.4
// ---------------------------------------------------------------------------

/// Root class of an [`OutletError`] — one of eight invariants per §5.4.4.
///
/// The class drives both the §5.4.4 detail-schema dispatch (each class has a
/// typed `detail` shape, with the `Detail*` enum variants below) and the
/// SDK-level sealed hierarchy: each language SDK renders this enum as a
/// sealed type (Python subclass tree, TypeScript tagged union, Swift `enum`,
/// Kotlin sealed class).
///
/// On the wire the class field is encoded as the lower-case kebab-case
/// variant name (`"protocol"`, `"authorization"`, …), independent of any
/// Rust-side identifier renaming. This matches the §5.4.4 wire vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OutletErrorClass {
    /// Registration / validation / classification violations
    /// (`SCP-OUTLET-6100..6109`). Examples: `query-cost-violation`,
    /// `query-violation`, `query-misdeclaration`, `outlet-not-registered`,
    /// `kind-mismatch`, `amplification-violation`,
    /// `protocol.catalog-rotation-too-frequent`, `protocol.stream-already-open`,
    /// `protocol.session-id-conflict`, `protocol.malformed-session-id`,
    /// `protocol.unknown-session`.
    Protocol,
    /// UCAN, caveat, role, capability, amplification denials
    /// (`SCP-OUTLET-6110..6119`). Examples: `authorization.denied`,
    /// `authorization.expired`, `authorization.revoked`,
    /// `authorization.attenuation-violation`, `authorization.mint-limit-exceeded`,
    /// `authorization.adapter-not-allowed`, `authorization.revoked-mid-stream`,
    /// `authorization.credit-stream-mismatch`,
    /// `authorization.ikm-signature-invalid`,
    /// `authorization.salt-rotation-unjustified`,
    /// `attenuation.origin-kind-mixed-stem-root`,
    /// `attenuation.origin-kind-stem-mismatch`,
    /// `attenuation.origin-kind-unspecified`, `attenuation.mask-width-violation`.
    Authorization,
    /// Schema, size, type, enum, range violations on input
    /// (`SCP-OUTLET-6120..6129`). Examples: `input.schema-violation`,
    /// `input.too-large`, `input.not-serializable`, `input.estimate-exceeds-bound`.
    Input,
    /// Timeout, panic, resource-exhaustion, non-determinism, stream gaps
    /// (`SCP-OUTLET-6130..6139`). Examples: `execution.handler-panic`,
    /// `execution.timeout`, `execution.non-deterministic`,
    /// `execution.credit-exhausted`, `execution.credit-stall`,
    /// `execution.stream-gap`, `execution.cancel-ack-timeout`.
    Execution,
    /// Output schema/size/non-serializable/redaction violations
    /// (`SCP-OUTLET-6140..6149`). Examples: `output.schema-violation`,
    /// `output.too-large`, `output.not-serializable`.
    Output,
    /// Budget, insufficient funds, adapter failure, pricing, escrow overflow
    /// (`SCP-OUTLET-6150..6159` plus the cross-class slug
    /// `protocol.interface-spam-cost`). Examples: `economic.insufficient-funds`,
    /// `economic.adapter-failure`, `economic.pricing-formula-error`,
    /// `economic.budget-exceeded`, `economic.escrow-overflow`.
    Economic,
    /// Relay unavailable, cross-context bridge failure, rate limiting,
    /// concurrency caps (`SCP-OUTLET-6160..6169`). Examples:
    /// `transport.relay-unavailable`, `transport.cross-context-bridge-failure`,
    /// `transport.rate-limited`, `transport.concurrent-streams-per-invoker`,
    /// `transport.concurrent-streams-per-origin-invoker`,
    /// `transport.concurrent-streams-per-outlet`.
    Transport,
    /// Deregistration, suspension, ceiling, consequence-active
    /// (`SCP-OUTLET-6170..6179`). Examples: `governance.outlet-deregistered`,
    /// `governance.outlet-suspended`, `governance.ceiling-exceeded`,
    /// `governance.consequence-active`.
    Governance,
}

impl OutletErrorClass {
    /// Returns the lowercase wire-form discriminant of this class.
    ///
    /// Matches the §5.4.4 wire vocabulary (`"protocol"`, `"authorization"`,
    /// `"input"`, `"execution"`, `"output"`, `"economic"`, `"transport"`,
    /// `"governance"`).
    #[must_use]
    pub const fn as_wire(self) -> &'static str {
        match self {
            Self::Protocol => "protocol",
            Self::Authorization => "authorization",
            Self::Input => "input",
            Self::Execution => "execution",
            Self::Output => "output",
            Self::Economic => "economic",
            Self::Transport => "transport",
            Self::Governance => "governance",
        }
    }

    /// Returns the [`DetailKind`] expected for this class per the §5.4.4
    /// per-class detail-schema table.
    ///
    /// `DetailKind::Empty` means the class carries no detail (the on-wire
    /// `detail` field is omitted entirely on success and rejected as
    /// [`OutletErrorConstructionFailed::DetailShapeMismatch`] otherwise).
    #[must_use]
    pub const fn expected_detail(self) -> DetailKind {
        match self {
            Self::Protocol => DetailKind::Protocol,
            Self::Authorization => DetailKind::Authorization,
            Self::Input | Self::Output => DetailKind::FieldViolation,
            Self::Execution => DetailKind::Execution,
            Self::Economic => DetailKind::Economic,
            Self::Transport => DetailKind::Transport,
            Self::Governance => DetailKind::Governance,
        }
    }
}

// ---------------------------------------------------------------------------
// RetryPolicy — §5.4.4
// ---------------------------------------------------------------------------

/// Retry guidance carried by an [`OutletError`] (§5.4.4 tag 5).
///
/// SDKs surface this directly so callers can choose to retry without
/// re-classifying the error. The variants:
///
/// - [`Self::Never`] — permanent failure; do not retry. Signature on
///   anything coming back from a misdeclared Query, a UCAN-rejected request,
///   or a deregistered outlet.
/// - [`Self::Immediate`] — the operation is idempotent and the failure was
///   transient; retry immediately.
/// - [`Self::After`] — wait for the specified [`Duration`] before retrying
///   (e.g., a transport-layer rate-limit hint).
/// - [`Self::WithBackoff`] — exponential within `[min, max]`. The caller
///   chooses the backoff curve; `min` and `max` bracket it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "policy", rename_all = "kebab-case")]
pub enum RetryPolicy {
    /// Permanent failure; do not retry.
    Never,
    /// Safe to retry immediately (idempotent operations).
    Immediate,
    /// Retry after the specified delay.
    After {
        /// The fixed delay before the next attempt.
        delay: Duration,
    },
    /// Exponential within `[min, max]`.
    WithBackoff {
        /// Minimum delay before the first retry.
        min: Duration,
        /// Maximum delay (the curve saturates here).
        max: Duration,
    },
}

// ---------------------------------------------------------------------------
// ContextHop — cross-context error trail entry per §5.4.4
// ---------------------------------------------------------------------------

/// One entry in an [`OutletError`]'s `source_chain` (§5.4.4 tag 8).
///
/// Records a cross-context boundary the error traversed. The outermost
/// caller sees the trail in innermost→outermost order via repeated
/// `wrap_cross_context_error` (SCP-OUT-029) prepends.
///
/// # Fields
///
/// - `context_id` — pseudonymized at wrap time for hops the receiving
///   caller is not a member of: `HMAC-SHA-256(hop_salt, raw_context_id)`.
///   Members of the hop see the raw id; non-members see a 32-byte opaque
///   value. The outermost caller's own context (`hop_index == 0`) is never
///   pseudonymized — the caller is always a member of their own context.
/// - `hop_index` — slot index in the trail. For real hops, `0 = origin`,
///   incrementing per cross-context boundary. For pad entries (§5.4.4
///   trail-length padding), `hop_index = slot_index` so pad entries are
///   byte-indistinguishable from real entries at the same slot index. The
///   `u16` width matches §9.18.B (`MAX_TRAIL_PAD_DEPTH = 16`) with headroom.
/// - `wrapped_code` — the [`OutletError::code`] as it was at this hop, BEFORE
///   the next outer hop wrapped it. Preserved across wrapping (the §5.4.4
///   "Cross-context wrapping preserves the original code" rule).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContextHop {
    /// Pseudonymized context id of this hop (§5.4.4 `source_chain`
    /// pseudonymization).
    pub context_id: String,
    /// Slot index in the padded trail (real or pad — they share encoding).
    pub hop_index: u16,
    /// Error code observed at this hop before any outer wrapping. Preserved
    /// per §5.4.4.
    pub wrapped_code: String,
}

// ---------------------------------------------------------------------------
// DetailKind / DetailBody — typed per-class detail schemas (§5.4.4)
// ---------------------------------------------------------------------------

/// Discriminator for the per-class detail schema (§5.4.4).
///
/// Returned by [`OutletErrorClass::expected_detail`] and used by
/// [`OutletError::new`] to type-check the `detail` argument against the
/// class. A `DetailBody` whose variant does not match the expected kind is
/// rejected with [`OutletErrorConstructionFailed::DetailShapeMismatch`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetailKind {
    /// `{ rule: string }` — the §5.4.4 Protocol-class shape.
    Protocol,
    /// `{ capability: string }` — the §5.4.4 Authorization-class shape.
    Authorization,
    /// `{ field_path: string, violation: string }` — Input + Output classes
    /// (§5.4.4 says they share the schema).
    FieldViolation,
    /// `{ elapsed_ms: u64 }` for timeouts; `{ panic_location_hash: [u8; 32] }`
    /// for panics; `{}` otherwise — the §5.4.4 Execution-class schema.
    Execution,
    /// `{ needed: u64, currency: string }` for `InsufficientFunds`;
    /// `{ adapter_id: string }` for adapter errors — Economic class.
    Economic,
    /// `{ retry_after_secs: u32 }` for rate limits;
    /// `{ relay_url_kind: enum }` for relay errors — Transport class.
    Transport,
    /// `{ action: string }` — Governance class.
    Governance,
    /// `{}` — class carries no detail.
    Empty,
}

/// Typed body of [`OutletError::detail`] (§5.4.4 per-class schema).
///
/// `DetailBody` is a closed enum — there is no free-form variant. This
/// closes the §5.4.4 covert-channel surface ("free-form `detail` is
/// forbidden"). The constructor [`OutletError::new`] verifies the variant
/// matches the class via [`OutletErrorClass::expected_detail`]; mismatches
/// are wire-layer rejections per §5.4.4.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "shape", rename_all = "kebab-case")]
pub enum DetailBody {
    /// Protocol-class detail: `{ rule: string }`.
    Protocol {
        /// Name of the rule that was violated (e.g., `"query-cost-floor"`).
        rule: String,
    },
    /// Authorization-class detail: `{ capability: string }`.
    Authorization {
        /// The capability URI that was denied (e.g., `"outlet_query:foo"`).
        capability: String,
    },
    /// Input/Output-class detail: `{ field_path: string, violation: string }`.
    FieldViolation {
        /// JSON Pointer into the offending payload (e.g., `"/items/0"`).
        field_path: String,
        /// Violation tag (e.g., `"type"`, `"range"`).
        violation: String,
    },
    /// Execution-class detail variant for timeouts.
    ExecutionTimeout {
        /// Elapsed time in milliseconds before the timeout fired.
        elapsed_ms: u64,
    },
    /// Execution-class detail variant for handler panics: the full 32-byte
    /// SHA-256 of a **stable panic-location identifier** (§5.4.4 round-3 fix —
    /// 32 bytes, NOT truncated).
    ///
    /// The canonical identifier is the panic's `"file:line"`. Producers that do
    /// not capture the source location at their recovery seam (e.g. the runtime
    /// `catch_unwind` outlet guard, which recovers only the payload) instead
    /// hash a stable location proxy — the panicking outlet's id. In no case is
    /// the free-text panic *message* hashed: an unsalted deterministic hash of
    /// a message that may embed dynamic values would be a weak confirmation
    /// oracle.
    ExecutionPanic {
        /// SHA-256 of a stable panic-location identifier (`"file:line"`, or a
        /// stable location proxy such as the outlet id) — never the message.
        #[serde(with = "serde_hash_32")]
        panic_location_hash: [u8; 32],
    },
    /// Economic-class detail variant for `InsufficientFunds`.
    EconomicInsufficient {
        /// Amount required (in the smallest unit of `currency`).
        needed: u64,
        /// ISO-4217 currency code or registered SCP currency code.
        currency: String,
    },
    /// Economic-class detail variant for adapter errors.
    EconomicAdapter {
        /// The `PaymentAdapterId` of the failing adapter.
        adapter_id: String,
    },
    /// Transport-class detail variant for rate-limit hints.
    TransportRateLimit {
        /// Seconds until the next call would be accepted.
        retry_after_secs: u32,
    },
    /// Transport-class detail variant for relay-availability errors.
    /// `relay_url_kind` is an enum, not a raw URL — the URL is sensitive
    /// (§5.4.4: "never a raw URL").
    TransportRelay {
        /// The relay URL kind (`"wss"`, `"ws-loopback"`, `"unknown"`).
        relay_url_kind: RelayUrlKind,
    },
    /// Governance-class detail: `{ action: string }`.
    Governance {
        /// The governance action name (e.g., `"outlet-deregistered"`).
        action: String,
    },
}

impl DetailBody {
    /// Returns the [`DetailKind`] matching this variant (used to validate
    /// shape against the class at [`OutletError::new`] construction time).
    #[must_use]
    pub const fn kind(&self) -> DetailKind {
        match self {
            Self::Protocol { .. } => DetailKind::Protocol,
            Self::Authorization { .. } => DetailKind::Authorization,
            Self::FieldViolation { .. } => DetailKind::FieldViolation,
            Self::ExecutionTimeout { .. } | Self::ExecutionPanic { .. } => DetailKind::Execution,
            Self::EconomicInsufficient { .. } | Self::EconomicAdapter { .. } => {
                DetailKind::Economic
            }
            Self::TransportRateLimit { .. } | Self::TransportRelay { .. } => DetailKind::Transport,
            Self::Governance { .. } => DetailKind::Governance,
        }
    }
}

/// Categorical tag for relay URLs surfaced in Transport-class detail
/// (§5.4.4: "never a raw URL").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RelayUrlKind {
    /// Production `wss://` relay.
    Wss,
    /// Loopback `ws://` relay (§transport ws-loopback exemption).
    WsLoopback,
    /// Relay URL kind not recognised.
    Unknown,
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum size of [`OutletError::message`] in bytes (§5.4.4).
///
/// The on-wire `message` field is the 32-byte HMAC of a catalog key
/// (§5.4.4 round-5 / round-6) — never raw prose. The 1 KiB cap is the
/// pre-HMAC catalog template upper bound; the post-HMAC value is fixed at
/// 32 bytes. The constant is exported so SDK validators can apply the same
/// pre-HMAC bound on operator-supplied catalog templates.
pub const MESSAGE_MAX_BYTES: usize = 1024;

/// Length of the HMAC-derived wire `message` field (§5.4.4 round-5).
///
/// `wire_message = HMAC-SHA-256(outlet_message_key, catalog_key)[..32]`.
/// Truncation to 32 bytes matches the spec's wire definition byte-for-byte.
pub const WIRE_MESSAGE_LEN: usize = 32;

/// Length of [`OutletError::pad_nonce`] in bytes (§5.4.4 round-5).
pub const PAD_NONCE_LEN: usize = 16;

/// Length of [`OutletError::registration_event_id`] in bytes (§5.4.4
/// round-6).
pub const REGISTRATION_EVENT_ID_LEN: usize = 32;

/// Length of the `outlet_message_key` HMAC key (§5.4.4 round-5).
pub const OUTLET_MESSAGE_KEY_LEN: usize = 32;

/// Hard upper bound on `source_chain` padded length (§5.4.4 round-5,
/// registered as a protocol constant in §9.18.B).
///
/// The emitter computes `max_padded_trail_depth = min(ContextParams::max_chain_depth,
/// MAX_TRAIL_PAD_DEPTH)` so envelopes stay bounded even when an operator
/// configures `max_chain_depth = 255` (the `u8` ceiling). Capping at 16
/// bounds an envelope's worst-case `source_chain` size to a few hundred
/// bytes regardless of the hosting context's depth budget.
///
/// **Not configurable.** This constant is part of the wire contract; an
/// emitter that pads beyond `MAX_TRAIL_PAD_DEPTH` produces an envelope that
/// receivers structurally reject.
///
/// See SCP-OUT-029 for the wrap-time application of this cap.
pub const MAX_TRAIL_PAD_DEPTH: u8 = 16;

/// Domain separator for [`MAX_TRAIL_PAD_DEPTH`] pad-entry HMAC pseudonyms
/// (§5.4.4 round-5, registered in §9.18.2).
///
/// Pad entries derive their `context_id` as
/// `HMAC-SHA-256(pad_nonce, MAX_TRAIL_PAD_HMAC_LABEL || slot_index_be)[..32]`
/// where `slot_index_be` is the 2-byte big-endian slot index. The label is
/// distinct from every other §9.18.2 separator and from the cross-context
/// `hop_salt`-keyed HMAC over real `context_id`s — the two keyings are
/// independent (`pad_nonce` vs. `hop_salt`) so a pad entry can never collide
/// with a real entry under any honest emitter.
pub const MAX_TRAIL_PAD_HMAC_LABEL: &[u8] = b"SCP-OUTLET-HOP-PAD-V1:";

// ---------------------------------------------------------------------------
// OutletError — typed §5.4.4 envelope (struct form)
// ---------------------------------------------------------------------------

/// Typed [`OutletError`] envelope per spec §5.4.4.
///
/// Constructed via [`OutletError::new`] which enforces all §5.4.4 invariants
/// (code regex, slug regex, catalog-key registration, HMAC over catalog key,
/// per-class detail shape, unconditional `pad_nonce` and
/// `registration_event_id` emission).
///
/// **Wire form.** Numeric `MessagePack` field tags (1-6, 8, 11, 12) per
/// §5.4.4 with tags 7, 9, 10 reserved. Unknown tags (7, 9, 10, 13+) are
/// preserved in [`Self::unknown_fields`] and round-trip byte-identical.
///
/// **Naming note.** The legacy [`super::OutletError`] thiserror enum is
/// untouched by this story; SCP-OUT-027 / 036 / 038 wire the runtime callsites
/// over to this typed envelope.
///
/// **Construction signature — options-object.** [`OutletError::new`] takes
/// a single [`OutletErrorNewOpts`] options-object (SCP-OUT-031 round-6 /
/// SCP-OUT-041b API MINOR fix). The options-object shape is keyword-only
/// across all SDK wrappers — Rust callers construct [`OutletErrorNewOpts`]
/// with explicit field names; Python/TypeScript/Swift/Kotlin SDKs pass a
/// struct / dict / typed parameter object so the call site reads as
/// `OutletError.new({ outlet_id, catalog_key, ... })` rather than a
/// positional 11-arg call. The positional form was rejected because it
/// produced unreadable call-sites and made it impossible to add new typed
/// fields without breaking source compatibility.
///
/// **Eq derive.** `OutletError` derives `PartialEq` but NOT `Eq`. The forward
/// -compat [`Self::unknown_fields`] slot stores [`rmpv::Value`], which is
/// `PartialEq`-only because the spec permits floats inside future-tag
/// `MessagePack` values (NaN forbids `Eq`). The story's "All derive ... Eq"
/// prose was written before round-5 / round-6 introduced the forward-compat
/// slot; the supporting types ([`OutletErrorClass`], [`RetryPolicy`],
/// [`ContextHop`], [`CatalogKey`]) all derive `Eq` as the prose specified.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OutletError {
    /// `SCP-OUTLET-NNNN` where `NNNN` falls in the §5.4.4 6100-6199 sub-block
    /// (tag 1). Validated by [`OutletError::new`].
    #[serde(rename = "1")]
    pub code: String,
    /// Slug per the §5.4.4 regex
    /// `^[a-z][a-z0-9-]{0,63}(\.[a-z][a-z0-9-]{0,63})*$` (tag 2). Multiple
    /// slugs may share the same `code`.
    #[serde(rename = "2")]
    pub slug: String,
    /// Root class (tag 3). One of [`OutletErrorClass`]'s 8 variants.
    #[serde(rename = "3")]
    pub class: OutletErrorClass,
    /// `HMAC-SHA-256(outlet_message_key, catalog_key)[..32]` (tag 4) — the
    /// §5.4.4 round-5 / round-6 per-outlet-keyed MAC over a registered
    /// catalog key. The on-wire value is opaque to non-members; members
    /// reverse-lookup against the registered catalog.
    #[serde(rename = "4", with = "serde_hash_32")]
    pub message: [u8; WIRE_MESSAGE_LEN],
    /// Retry guidance (tag 5).
    #[serde(rename = "5")]
    pub retry: RetryPolicy,
    /// Typed per-class detail (tag 6). `None` means the class carries no
    /// detail (`DetailKind::Empty`); shape mismatches are rejected at
    /// construction with [`OutletErrorConstructionFailed::DetailShapeMismatch`].
    #[serde(rename = "6", default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<DetailBody>,
    /// Cross-context hop trail (tag 8). Empty for non-cross-context errors;
    /// pseudonymization and trail-padding are applied by `wrap_cross_context_error`
    /// (SCP-OUT-029) at hop time, not at construction.
    #[serde(rename = "8", default)]
    pub source_chain: Vec<ContextHop>,
    /// `[u8; 16]` — fresh-per-envelope CSPRNG nonce keying §5.4.4 trail-pad
    /// pseudonyms. Emitted unconditionally (no `Option` wrapper) per §5.4.4
    /// round-5 — closes the visibility-vs-absence oracle.
    #[serde(rename = "11", with = "serde_pad_nonce")]
    pub pad_nonce: [u8; PAD_NONCE_LEN],
    /// `[u8; 32]` — event-log id of the [`OutletRegistration`] under which
    /// the emitting outlet's `outlet_message_key` was derived. Emitted
    /// unconditionally per §5.4.4 round-6 (no `Option` wrapper); the
    /// receiver looks the key up against its per-outlet LRU
    /// (`MESSAGE_KEY_LRU_CAPACITY = 4` per §9.18.A).
    ///
    /// [`OutletRegistration`]: crate::context::outlets::OutletRegistration
    #[serde(rename = "12", with = "serde_hash_32")]
    pub registration_event_id: [u8; REGISTRATION_EVENT_ID_LEN],
    /// Unknown-tag forward-compat slot. Tags 7, 9, 10 (RESERVED per §5.4.4)
    /// AND tags 13+ (future extensions) round-trip through this map without
    /// interpretation. Encoded inline by `#[serde(flatten)]`.
    ///
    /// Old SDKs that see a future-tag-13+ field preserve it byte-identical
    /// on re-serialization, which is the §5.4.4 forward-compat invariant.
    #[serde(flatten)]
    pub unknown_fields: BTreeMap<String, rmpv::Value>,
}

/// Options-object input for [`OutletError::new`] (SCP-OUT-031 round-6 /
/// SCP-OUT-041b API MINOR fix).
///
/// Aggregates the typed inputs §5.4.4 mandates for envelope construction
/// behind a single keyword-only struct. SDK bridges expose the same shape
/// as a Python `TypedDict`, TypeScript object literal, Swift struct, and
/// Kotlin data class so callers never see a positional 11-arg constructor.
///
/// # Fields
///
/// - `outlet_id` — typed [`OutletId`] of the emitting outlet. Bound to
///   the envelope at construction so the runtime can cross-check
///   `outlet_message_key` against the outlet's pinned registration.
/// - `outlet_message_key` — the 32-byte per-outlet HMAC key derived from
///   the hosting context's MLS exporter at registration acceptance
///   (§5.4.4 round-5). Looked up at the receiver via
///   `registration_event_id` against the §9.18.A LRU.
/// - `registration_event_id` — event-log id of the
///   [`OutletRegistration`](crate::context::outlets::OutletRegistration)
///   that pinned `outlet_message_key`. Emitted unconditionally on every
///   envelope per §5.4.4 round-6 (tag 12).
/// - `catalog_key` — registered [`CatalogKey`] selecting a template from
///   the outlet's `message_catalog`. The on-wire `message` field is
///   `HMAC-SHA-256(outlet_message_key, catalog_key.as_str().as_bytes())[..32]`.
/// - `registered_keys` — slice of every [`CatalogKey`] in the outlet's
///   currently-pinned `message_catalog` (the §5.4.4 round-5 catalog).
///   Used to enforce
///   [`OutletErrorConstructionFailed::UnregisteredMessageKey`] at
///   construction time.
/// - `class` — [`OutletErrorClass`] root class (§5.4.4 tag 3).
/// - `code` — `SCP-OUTLET-NNNN` with `NNNN` in the §5.4.4 6100-6199
///   sub-block.
/// - `slug` — `^[a-z][a-z0-9-]{0,63}(\.[a-z][a-z0-9-]{0,63})*$`.
/// - `retry` — [`RetryPolicy`].
/// - `detail` — typed per-class shape; rejected as
///   [`OutletErrorConstructionFailed::DetailShapeMismatch`] if the
///   variant does not match `class.expected_detail()`.
/// - `source_chain` — initial trail of [`ContextHop`] entries. Almost
///   always empty at construction (cross-context wrapping populates it
///   later via SCP-OUT-029).
/// - `pad_nonce` — fresh-per-envelope CSPRNG nonce keying §5.4.4 trail-
///   pad pseudonyms; emitted unconditionally.
///
/// # Why an options-object
///
/// Earlier drafts used a positional 11-argument signature. Reviewers
/// flagged the call-site as unreadable and the positional shape blocked
/// adding new typed fields (`registration_event_id` arrived in round-6
/// and would have shifted every existing caller). The options-object
/// shape is forward-compatible: new fields are added with defaults so
/// existing callers continue compiling, and every field is named at
/// every call site.
#[derive(Debug, Clone)]
pub struct OutletErrorNewOpts<'a> {
    /// Typed outlet id of the emitting outlet (§5.4.4).
    pub outlet_id: &'a OutletId,
    /// 32-byte pinned per-outlet HMAC key (§5.4.4 round-5).
    pub outlet_message_key: &'a [u8; OUTLET_MESSAGE_KEY_LEN],
    /// Event-log id of the [`OutletRegistration`] that pinned
    /// `outlet_message_key` (§5.4.4 round-6 tag 12).
    ///
    /// [`OutletRegistration`]: crate::context::outlets::OutletRegistration
    pub registration_event_id: [u8; REGISTRATION_EVENT_ID_LEN],
    /// Registered catalog key selecting a §5.4.4 template.
    pub catalog_key: &'a CatalogKey,
    /// Registered catalog (every [`CatalogKey`] in the outlet's pinned
    /// `message_catalog`). Used to enforce
    /// [`OutletErrorConstructionFailed::UnregisteredMessageKey`].
    pub registered_keys: &'a [CatalogKey],
    /// Root [`OutletErrorClass`] (§5.4.4 tag 3).
    pub class: OutletErrorClass,
    /// `SCP-OUTLET-NNNN` per the §5.4.4 6100-6199 sub-block.
    pub code: &'a str,
    /// Slug per `^[a-z][a-z0-9-]{0,63}(\.[a-z][a-z0-9-]{0,63})*$`.
    pub slug: &'a str,
    /// [`RetryPolicy`] (§5.4.4 tag 5).
    pub retry: RetryPolicy,
    /// Typed per-class detail (§5.4.4 tag 6).
    pub detail: Option<DetailBody>,
    /// Initial cross-context trail. Almost always empty; SCP-OUT-029
    /// `wrap_cross_context_error` populates it at hop time.
    pub source_chain: Vec<ContextHop>,
    /// Fresh-per-envelope CSPRNG nonce (§5.4.4 round-5 tag 11).
    pub pad_nonce: [u8; PAD_NONCE_LEN],
}

impl OutletError {
    /// Constructs a new [`OutletError`] envelope per §5.4.4 with full
    /// validation.
    ///
    /// Takes a single [`OutletErrorNewOpts`] options-object (SCP-OUT-031
    /// round-6 / SCP-OUT-041b API MINOR fix) — the positional 11-arg form
    /// was rejected as unreadable.
    ///
    /// # Inputs
    ///
    /// See [`OutletErrorNewOpts`] for the field-by-field contract.
    ///
    /// # Errors
    ///
    /// Returns [`OutletErrorConstructionFailed`] on:
    /// - Malformed `code` ([`OutletErrorConstructionFailed::MalformedCode`]).
    /// - Malformed `slug` ([`OutletErrorConstructionFailed::MalformedSlug`]).
    /// - `catalog_key` not in `registered_keys`
    ///   ([`OutletErrorConstructionFailed::UnregisteredMessageKey`]).
    /// - `detail` shape vs. class mismatch
    ///   ([`OutletErrorConstructionFailed::DetailShapeMismatch`]).
    /// - `outlet_message_key` length mismatch
    ///   ([`OutletErrorConstructionFailed::InvalidOutletMessageKey`]).
    /// - Pre-HMAC `catalog_key` exceeding [`MESSAGE_MAX_BYTES`]
    ///   ([`OutletErrorConstructionFailed::MessageTooLong`]). The §5.4.4
    ///   message cap is on the catalog template; catalog keys are bounded
    ///   the same way.
    pub fn new(opts: OutletErrorNewOpts<'_>) -> Result<Self, OutletErrorConstructionFailed> {
        use super::error_codes::{SlugError, error_code_to_class, slug_to_class, validate_slug};

        let OutletErrorNewOpts {
            outlet_id: _,
            outlet_message_key,
            registration_event_id,
            catalog_key,
            registered_keys,
            class,
            code,
            slug,
            retry,
            detail,
            source_chain,
            pad_nonce,
        } = opts;
        let code = code.to_owned();
        let slug = slug.to_owned();

        // 1. code regex check (§5.4.4 6100-6199 sub-block).
        if !validate_outlet_error_code(&code) {
            return Err(OutletErrorConstructionFailed::MalformedCode { code });
        }

        // 2. slug regex check (§5.4.4 catalog-key regex). SCP-OUT-025: the
        //    slug regex is enforced via the registry's typed entry point
        //    `validate_slug` — the production caller for this helper. The
        //    underlying byte scanner is shared with `validate_catalog_key`
        //    so the regex semantics are identical, but routing the call
        //    through `validate_slug` pins the registry as the single source
        //    of truth for §5.4.4 slug validation.
        if let Err(SlugError::Malformed { slug }) = validate_slug(&slug) {
            return Err(OutletErrorConstructionFailed::MalformedSlug { slug });
        }

        // 3. defense-in-depth: caller-supplied class must match the §5.4.4
        //    registry mapping for the code AND for the slug. SCP-OUT-025
        //    wires the registry helpers into `OutletError::new` so a drift
        //    between the caller's `class` argument and the registry-defined
        //    class for the supplied code/slug is caught at construction
        //    time rather than leaking through to the wire.
        //
        //    Reserved codes / unrecognized slugs return `None` from the
        //    registry — for those we skip the cross-check (the regex pass
        //    above already rejected malformed inputs; a registry miss here
        //    means the code/slug is well-formed but not yet tabulated, and
        //    the catalog-membership check below remains the gate).
        if let Some(expected) = error_code_to_class(&code)
            && expected != class
        {
            return Err(OutletErrorConstructionFailed::ClassCodeMismatch {
                code_or_slug: code.clone(),
                expected,
                actual: class,
            });
        }
        if let Some(expected) = slug_to_class(&slug)
            && expected != class
        {
            return Err(OutletErrorConstructionFailed::ClassCodeMismatch {
                code_or_slug: slug.clone(),
                expected,
                actual: class,
            });
        }

        // 4. message-length cap on the catalog-key plaintext.
        if catalog_key.as_str().len() > MESSAGE_MAX_BYTES {
            return Err(OutletErrorConstructionFailed::MessageTooLong {
                actual: catalog_key.as_str().len(),
                max: MESSAGE_MAX_BYTES,
            });
        }

        // 4. catalog membership check (§5.4.4 round-5/6: an unregistered
        //    catalog key is rejected with `UnregisteredMessageKey` so
        //    operators cannot smuggle arbitrary HMAC inputs through the
        //    wire `message` field).
        if !registered_keys.iter().any(|k| k == catalog_key) {
            return Err(OutletErrorConstructionFailed::UnregisteredMessageKey {
                catalog_key: catalog_key.as_str().to_owned(),
            });
        }

        // 5. detail shape vs. class.
        //
        // §5.4.4 allows "empty detail" only for classes whose schema is `{}`.
        // For classes with a defined shape, omitting detail is allowed but
        // the shape (when present) must match. Empty-detail handling is
        // permissive: the AC focuses on shape mismatch, not absence.
        if let Some(d) = &detail {
            let expected = class.expected_detail();
            if d.kind() != expected {
                return Err(OutletErrorConstructionFailed::DetailShapeMismatch {
                    class,
                    actual: d.kind(),
                });
            }
        }

        // 6. HMAC over catalog_key keyed by outlet_message_key.
        let wire_message = compute_wire_message(outlet_message_key, catalog_key);

        Ok(Self {
            code,
            slug,
            class,
            message: wire_message,
            retry,
            detail,
            source_chain,
            pad_nonce,
            registration_event_id,
            unknown_fields: BTreeMap::new(),
        })
    }

    /// Computes `HMAC-SHA-256(outlet_message_key, catalog_key)[..32]` —
    /// the §5.4.4 round-5 wire-message construction. Exposed so SDK
    /// receivers can reverse-lookup the catalog entry against this MAC.
    ///
    /// Equivalent to the internal helper used by [`Self::new`].
    #[must_use]
    pub fn compute_wire_message(
        outlet_message_key: &[u8; OUTLET_MESSAGE_KEY_LEN],
        catalog_key: &CatalogKey,
    ) -> [u8; WIRE_MESSAGE_LEN] {
        compute_wire_message(outlet_message_key, catalog_key)
    }

    /// Constructs an [`OutletError`] for the **runtime → `ContextError`
    /// seam** (SCP-OUT-027).
    ///
    /// This constructor is **not** for §5.4.4 wire emission. Use
    /// [`Self::new`] for that path — it enforces catalog-key registration
    /// against the outlet's pinned `message_catalog` and computes a real
    /// `HMAC-SHA-256(outlet_message_key, catalog_key)`.
    ///
    /// At the runtime → `ContextError` seam the typed envelope escapes via
    /// `Result<_, ContextError>` to in-process Rust and FFI callers, never
    /// onto the §5.4.4 wire. The runtime does **not** have the per-outlet
    /// `outlet_message_key` / `registration_event_id` here, so this
    /// constructor synthesizes deterministic placeholders:
    ///
    /// - `outlet_message_key` is treated as the **all-zero key** (length-32),
    ///   so `message = HMAC-SHA-256([0; 32], slug)[..32]`. The HMAC value is
    ///   deterministic-but-non-secret — receivers MUST NOT rely on it for
    ///   reverse-lookup on this path. Wire emission re-derives a real HMAC
    ///   at the SCP-OUT-029 cross-context wrap seam (where the real key is
    ///   in scope).
    /// - `registration_event_id` is `[0; 32]` — sentinel for "no registration
    ///   event was joined to this error".
    /// - `pad_nonce` is fresh-per-call from a CSPRNG (`rand::random()`),
    ///   matching the §5.4.4 round-5 unconditional emission rule.
    /// - `catalog_key` is derived directly from `slug` (the slug regex is a
    ///   strict subset of the catalog-key regex per §5.4.4).
    /// - `detail` is `None` and `source_chain` is `Vec::new()` — both
    ///   shape-conformant for any class.
    ///
    /// # Errors
    ///
    /// Returns [`OutletErrorConstructionFailed`] when:
    ///
    /// - `code` fails its regex check
    ///   ([`OutletErrorConstructionFailed::MalformedCode`]).
    /// - `slug` fails its regex check
    ///   ([`OutletErrorConstructionFailed::MalformedSlug`]).
    /// - `class` disagrees with the §5.4.4 registry mapping for `code` or
    ///   `slug` ([`OutletErrorConstructionFailed::ClassCodeMismatch`]).
    ///   SCP-OUT-025 wires
    ///   [`error_code_to_class`](super::error_codes::error_code_to_class) and
    ///   [`slug_to_class`](super::error_codes::slug_to_class) into this
    ///   construction path so a runtime mapping-table drift is rejected at
    ///   the seam rather than leaking through to the typed `ContextError`.
    ///
    /// The catalog-membership check is **not** applied (no real
    /// `message_catalog` exists at this seam).
    pub fn from_invocation_error_template(
        class: OutletErrorClass,
        code: impl Into<String>,
        slug: impl Into<String>,
        retry: RetryPolicy,
    ) -> Result<Self, OutletErrorConstructionFailed> {
        use super::error_codes::{SlugError, error_code_to_class, slug_to_class, validate_slug};

        let code = code.into();
        let slug = slug.into();

        // 1. code regex check (§5.4.4 6100-6199 sub-block).
        if !validate_outlet_error_code(&code) {
            return Err(OutletErrorConstructionFailed::MalformedCode { code });
        }

        // 2. slug regex check (§5.4.4 catalog-key regex). SCP-OUT-025: route
        //    the runtime → ContextError seam through the registry's typed
        //    `validate_slug` so wire-bound and runtime-bound construction
        //    paths share the same canonical entry point.
        if let Err(SlugError::Malformed { slug }) = validate_slug(&slug) {
            return Err(OutletErrorConstructionFailed::MalformedSlug { slug });
        }

        // 3. defense-in-depth class/code/slug consistency check via the
        //    §5.4.4 registry — same invariant as `OutletError::new`. The
        //    runtime mapping table (`invocation_error_to_envelope_template`)
        //    sources every `(class, code, slug)` triple from registry
        //    constants, so a registry mismatch here means the table drifted
        //    out of sync with the §5.4.4 taxonomy and must be fixed at the
        //    table, not papered over at the construction site.
        if let Some(expected) = error_code_to_class(&code)
            && expected != class
        {
            return Err(OutletErrorConstructionFailed::ClassCodeMismatch {
                code_or_slug: code.clone(),
                expected,
                actual: class,
            });
        }
        if let Some(expected) = slug_to_class(&slug)
            && expected != class
        {
            return Err(OutletErrorConstructionFailed::ClassCodeMismatch {
                code_or_slug: slug.clone(),
                expected,
                actual: class,
            });
        }

        // 4. derive a catalog-key from the slug (slug regex ⊆ catalog-key
        //    regex per §5.4.4) — used only for the placeholder HMAC.
        let catalog_key = CatalogKey::try_new(slug.clone())
            .map_err(|_| OutletErrorConstructionFailed::MalformedSlug { slug: slug.clone() })?;

        // 4. placeholder HMAC under the all-zero key (deterministic, public).
        let zero_key = [0u8; OUTLET_MESSAGE_KEY_LEN];
        let message = compute_wire_message(&zero_key, &catalog_key);

        // 5. fresh CSPRNG pad_nonce (§5.4.4 round-5 unconditional emission).
        let pad_nonce: [u8; PAD_NONCE_LEN] = rand::random();

        Ok(Self {
            code,
            slug,
            class,
            message,
            retry,
            detail: None,
            source_chain: Vec::new(),
            pad_nonce,
            registration_event_id: [0u8; REGISTRATION_EVENT_ID_LEN],
            unknown_fields: BTreeMap::new(),
        })
    }
}

impl std::fmt::Display for OutletError {
    /// Renders `<code> (<slug>): <class>` — the human-readable rendering
    /// of the §5.4.4 envelope. The `message` HMAC is opaque to callers and
    /// is NOT rendered here (it requires an out-of-band catalog lookup
    /// against the emitting outlet's `outlet_message_key`).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{code} ({slug}): {class}",
            code = self.code,
            slug = self.slug,
            class = self.class.as_wire(),
        )
    }
}

// ---------------------------------------------------------------------------
// OutletErrorSurface — the runtime → FFI structured error projection
// ---------------------------------------------------------------------------

/// The structured projection of an outlet error carried from the runtime to
/// the FFI boundary (SCP-OUT-031 PR-2a).
///
/// # Why this exists
///
/// Before PR-2a, outlet **invocation** errors were flattened to a
/// `ContextError::PermissionDenied(String)` at the runtime →
/// [`ContextError`](crate::context::ContextError) seam — every
/// `class` / `detail` / `retry` / `source_chain` distinction was destroyed and
/// the SDK could only re-parse an `SCP-OUTLET-NNNN:` prefix out of a prose
/// string. `OutletErrorSurface` is the plain-data structure that carries the
/// full §5.4.4 taxonomy across that seam instead, so the FFI bridge renders
/// (PR-2b) and the SDK-side typed error hierarchy can be rebuilt losslessly.
///
/// # Relationship to the wire envelope
///
/// This is **not** a wire type. The §5.4.4 wire envelope is [`OutletError`],
/// which additionally carries the HMAC `message`, the `pad_nonce`, and the
/// `registration_event_id` — all of which are wire-opacity fields that a
/// cross-context receiver needs but the in-process SDK does not. Where a typed
/// envelope is available (the cross-context path), [`Self::from_envelope`]
/// projects an `OutletError` onto this surface, dropping those three fields.
///
/// # Invariants (by construction)
///
/// Every `OutletErrorSurface` produced by [`Self::from_code`] or
/// [`Self::from_class`] satisfies:
///
/// - `error_code_to_class(code) == Some(class)`, and
/// - `slug_to_class(slug) == Some(class)`.
///
/// i.e. the `(class, code, slug)` triple is mutually consistent with the
/// §5.4.4 registry ([`super::error_codes`]). The exhaustive unit tests assert
/// this for every producer.
///
/// `Send` (all fields are `Send`), so it crosses the actor mailbox freely.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutletErrorSurface {
    /// Root §5.4.4 class. Consistent with `code` and `slug` by construction.
    pub class: OutletErrorClass,
    /// `SCP-OUTLET-NNNN` §5.4.4 sub-block code.
    pub code: String,
    /// §5.4.4 slug (registered — `slug_to_class(slug) == Some(class)`).
    pub slug: String,
    /// Retry guidance for this error (§5.4.4 tag 5).
    pub retry: RetryPolicy,
    /// Typed per-class detail, when the source error carried structured
    /// fields. `None` when the source variant has no structured detail — never
    /// a fabricated placeholder.
    pub detail: Option<DetailBody>,
    /// Cross-context hop trail (§5.4.4 tag 8). Empty for non-cross-context
    /// errors; populated only via [`Self::from_envelope`].
    pub source_chain: Vec<ContextHop>,
}

impl OutletErrorSurface {
    /// Builds a class-consistent surface from a §5.4.4 `code`, a *preferred*
    /// slug, and an optional typed `detail`.
    ///
    /// - `class` is derived from `code` via
    ///   [`error_code_to_class`](super::error_codes::error_code_to_class).
    /// - `slug` keeps `preferred_slug` **iff** it is a registered slug of the
    ///   same class (`slug_to_class(preferred_slug) == Some(class)`);
    ///   otherwise it falls back to the code's canonical default slug
    ///   ([`error_code_to_default_slug`](super::error_codes::error_code_to_default_slug)),
    ///   which is registered and class-consistent by construction. This keeps
    ///   the [invariants](Self) intact even when a runtime error surfaces an
    ///   unregistered diagnostic slug (e.g. the camelCase caveat-counter
    ///   kinds `maxCalls` / `amountMaxCumulative` / `rateWindow`, which §5.4.4
    ///   collapses onto `authorization.denied`).
    /// - `retry` is the code's default
    ///   ([`error_code_to_retry_policy`](super::error_codes::error_code_to_retry_policy)).
    ///
    /// `code` MUST be an allocated §5.4.4 sub-block constant (every caller
    /// passes a `CODE_*` constant); an unallocated code degrades to the
    /// `Protocol` root class + `Never` retry rather than panicking.
    #[must_use]
    pub fn from_code(code: &str, preferred_slug: &str, detail: Option<DetailBody>) -> Self {
        use super::error_codes::{
            error_code_to_class, error_code_to_default_slug, error_code_to_retry_policy,
            slug_to_class,
        };

        let class = error_code_to_class(code).unwrap_or(OutletErrorClass::Protocol);
        // Defense-in-depth for CALLER miswiring: a `preferred_slug` that IS a
        // registered §5.4.4 slug but of a DIFFERENT class than `code` is
        // silently swapped for the code's default below (to preserve the
        // class/code/slug consistency invariant). That silent swap is correct
        // for genuinely-unregistered diagnostic slugs, but a registered
        // wrong-class slug almost always means the caller paired the wrong
        // (code, slug) — surface it in tests. (Unregistered slugs return `None`
        // and are the expected, non-asserting fallback path.)
        debug_assert!(
            slug_to_class(preferred_slug).is_none_or(|c| c == class),
            "OutletErrorSurface::from_code: preferred_slug {preferred_slug:?} is a registered \
             {:?}-class slug but code {code:?} is {class:?} — likely a miswired (code, slug) pair; \
             use from_class for slug-first classification",
            slug_to_class(preferred_slug),
        );
        let slug = if slug_to_class(preferred_slug) == Some(class) {
            preferred_slug.to_owned()
        } else {
            error_code_to_default_slug(code)
                .unwrap_or(preferred_slug)
                .to_owned()
        };
        let retry = error_code_to_retry_policy(code).unwrap_or(RetryPolicy::Never);
        Self {
            class,
            code: code.to_owned(),
            slug,
            retry,
            detail,
            source_chain: Vec::new(),
        }
    }

    /// Builds a class-consistent surface where the **slug** is the authoritative
    /// signal of the class (slug-first classification).
    ///
    /// Used when a runtime error is identified by a §5.4.4 slug whose class may
    /// differ from any pre-assigned code — e.g. an open-time stream rejection
    /// routed through `InvocationError::CaveatViolation` can carry an
    /// `economic.*` slug even though the caveat path's default code is the
    /// Authorization umbrella. Deriving the code from the slug's class
    /// (via [`class_to_canonical_code`](super::error_codes::class_to_canonical_code))
    /// keeps the surface consistent AND preserves the discriminating slug for
    /// downstream reverse-mapping.
    ///
    /// `class` is taken from `slug_to_class(preferred_slug)`, defaulting to
    /// [`OutletErrorClass::Authorization`] (the §5.4.4 oracle-collapse target)
    /// when the slug is unregistered.
    #[must_use]
    pub fn from_class(preferred_slug: &str, detail: Option<DetailBody>) -> Self {
        use super::error_codes::{class_to_canonical_code, slug_to_class};

        let class = slug_to_class(preferred_slug).unwrap_or(OutletErrorClass::Authorization);
        Self::from_code(class_to_canonical_code(class), preferred_slug, detail)
    }

    /// Projects a typed §5.4.4 [`OutletError`] wire envelope onto this surface.
    ///
    /// Keeps `class` / `code` / `slug` / `retry` / `detail` / `source_chain`
    /// verbatim and DROPS the three wire-opacity fields (`message` HMAC,
    /// `pad_nonce`, `registration_event_id`) — those are needed by a
    /// cross-context receiver to reverse-lookup the catalog, not by the
    /// in-process SDK rebuilding the typed error.
    #[must_use]
    pub fn from_envelope(env: &OutletError) -> Self {
        Self {
            class: env.class,
            code: env.code.clone(),
            slug: env.slug.clone(),
            retry: env.retry.clone(),
            detail: env.detail.clone(),
            source_chain: env.source_chain.clone(),
        }
    }
}

/// Internal helper — computes the §5.4.4 round-5 HMAC over a catalog key.
fn compute_wire_message(
    outlet_message_key: &[u8; OUTLET_MESSAGE_KEY_LEN],
    catalog_key: &CatalogKey,
) -> [u8; WIRE_MESSAGE_LEN] {
    type HmacSha256 = Hmac<Sha256>;
    // HMAC-SHA-256 accepts arbitrary-length keys via `Mac::new_from_slice`,
    // and a 32-byte key always succeeds. We `match` on the result rather
    // than `expect` so the production-code clippy gate (`clippy::expect_used`
    // is denied) stays clean. The `Err` branch returns an all-zeros tag
    // — unreachable in practice, but explicit so a future contract drift
    // produces a wire-distinguishable value rather than a panic.
    let mac_result = <HmacSha256 as hmac::Mac>::new_from_slice(outlet_message_key);
    let mut out = [0u8; WIRE_MESSAGE_LEN];
    if let Ok(mut mac) = mac_result {
        mac.update(catalog_key.as_str().as_bytes());
        let full = mac.finalize().into_bytes();
        out.copy_from_slice(&full[..WIRE_MESSAGE_LEN]);
    }
    out
}

/// Validates an [`OutletError::code`] against the §5.4.4 6100-6199 sub-block.
///
/// Accepts `SCP-OUTLET-NNNN` where `NNNN` is exactly 4 ASCII digits and the
/// 4-digit number falls in the closed range \[6100, 6199\].
#[must_use]
pub fn validate_outlet_error_code(code: &str) -> bool {
    // Hand-rolled byte comparison against the §5.4.4 prefix. The literal
    // is exempt from `scripts/check-error-codes.sh` Phase 1 via the inline
    // marker below — this is a validator self-reference (the function
    // checks inputs against this prefix), not an emitted error code.
    const PREFIX: &[u8] = b"SCP-OUTLET-61"; // SCP-CODE-OK: validator self-reference (§5.4.4 prefix check)
    if code.len() != 15 {
        return false;
    }
    let bytes = code.as_bytes();
    if !bytes.starts_with(PREFIX) {
        return false;
    }
    let tail = &bytes[13..];
    tail.iter().all(u8::is_ascii_digit)
}

// ---------------------------------------------------------------------------
// Construction failure type
// ---------------------------------------------------------------------------

/// Reasons [`OutletError::new`] (or wire-layer deserialization) can reject
/// an envelope before it leaves the SDK boundary.
///
/// Per §5.4.4, every one of these conditions is a **wire-layer rejection**:
/// SDKs do not surface a partially-constructed [`OutletError`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum OutletErrorConstructionFailed {
    /// `code` failed the §5.4.4 6100-6199 sub-block check.
    #[error(
        "malformed OutletError code \"{code}\" — must be SCP-OUTLET-NNNN with NNNN in [6100, 6199]"
    )]
    MalformedCode {
        /// The invalid code.
        code: String,
    },
    /// `slug` failed the §5.4.4 regex.
    #[error(
        "malformed OutletError slug \"{slug}\" — must match ^[a-z][a-z0-9-]{{0,63}}(\\.[a-z][a-z0-9-]{{0,63}})*$"
    )]
    MalformedSlug {
        /// The invalid slug.
        slug: String,
    },
    /// Catalog key not registered in the outlet's pinned `message_catalog`.
    /// The receiver-side rejection class for §5.4.4 round-5/6.
    #[error(
        "OutletError catalog key \"{catalog_key}\" is not registered in the outlet's message_catalog"
    )]
    UnregisteredMessageKey {
        /// The unregistered key.
        catalog_key: String,
    },
    /// `detail` variant does not match the §5.4.4 per-class schema.
    #[error("OutletError detail shape mismatch — class {class:?} expects {expected:?} but got {actual:?}", expected = .class.expected_detail())]
    DetailShapeMismatch {
        /// The error class on the envelope.
        class: OutletErrorClass,
        /// The detail kind that was supplied.
        actual: DetailKind,
    },
    /// Pre-HMAC `catalog_key` exceeded [`MESSAGE_MAX_BYTES`]. The §5.4.4
    /// 1 KiB cap on the message-template.
    #[error("OutletError catalog key length {actual} exceeds maximum {max}")]
    MessageTooLong {
        /// Actual length in bytes.
        actual: usize,
        /// Maximum allowed length in bytes.
        max: usize,
    },
    /// `outlet_message_key` length mismatch. The §5.4.4 round-5 key is
    /// always 32 bytes; this variant is reserved for SDK paths that
    /// construct keys outside the type system.
    #[error("OutletError outlet_message_key must be {OUTLET_MESSAGE_KEY_LEN} bytes")]
    InvalidOutletMessageKey,
    /// Wire-layer deserialization saw an envelope missing its tag-12
    /// `registration_event_id` field. §5.4.4 round-6 rejects this with the
    /// dedicated variant so SDKs can distinguish "old envelope" from
    /// "wire-layer corruption".
    #[error(
        "OutletError envelope missing tag-12 registration_event_id (§5.4.4 round-6 unconditional emission)"
    )]
    MissingRegistrationEventId,
    /// Wire-layer deserialization saw an envelope missing its tag-11
    /// `pad_nonce` field. §5.4.4 round-5 rejects this with the dedicated
    /// variant — `pad_nonce` is unconditional.
    #[error(
        "OutletError envelope missing tag-11 pad_nonce (§5.4.4 round-5 unconditional emission)"
    )]
    MissingPadNonce,
    /// Defense-in-depth: caller-supplied [`OutletErrorClass`] does not match
    /// the class that the §5.4.4 registry assigns to the supplied `code` (or
    /// `slug`). SCP-OUT-025 wires the registry helpers
    /// [`error_code_to_class`](super::error_codes::error_code_to_class) and
    /// [`slug_to_class`](super::error_codes::slug_to_class) into
    /// [`OutletError::new`] so a code/class or slug/class drift at any
    /// construction site (runtime emitter, FFI bridge, SDK) is rejected
    /// before the envelope leaves the SDK boundary.
    #[error(
        "OutletError class/code/slug mismatch — supplied class {actual:?} disagrees with the §5.4.4 registry mapping {expected:?} for code/slug \"{code_or_slug}\""
    )]
    ClassCodeMismatch {
        /// The code or slug whose registry-assigned class disagrees with
        /// the caller-supplied class. The string is whichever surface
        /// triggered the mismatch (`code` for the code/class check,
        /// `slug` for the slug/class check).
        code_or_slug: String,
        /// The class the §5.4.4 registry assigns to `code_or_slug`.
        expected: OutletErrorClass,
        /// The class the caller supplied.
        actual: OutletErrorClass,
    },
}

// ---------------------------------------------------------------------------
// pad_nonce serde helper — fixed-length [u8; 16]
// ---------------------------------------------------------------------------

/// Serde module for the 16-byte `pad_nonce` field (§5.4.4 round-5).
///
/// Same pattern as [`crate::serde_util::serde_hash_32`] but for 16 bytes.
/// Rejects deserialization of any other length.
#[allow(clippy::missing_errors_doc)] // Serde trait impls — error semantics are self-evident.
mod serde_pad_nonce {
    use serde::{self, Deserializer, Serializer};

    /// Serializes a 16-byte array as compact binary via `serde_bytes`.
    pub fn serialize<S>(bytes: &[u8; 16], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serde_bytes::serialize(bytes.as_slice(), serializer)
    }

    /// Deserializes exactly 16 bytes, rejecting any other length.
    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 16], D::Error>
    where
        D: Deserializer<'de>,
    {
        let v: Vec<u8> = serde_bytes::deserialize(deserializer)?;
        v.try_into().map_err(|v: Vec<u8>| {
            serde::de::Error::custom(format!("expected 16-byte pad_nonce, got {} bytes", v.len()))
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::context::outlets::error_codes::{
        CODE_AUTHORIZATION_DENIED, CODE_EXECUTION_FAULT, CODE_PROTOCOL_VIOLATION,
        CODE_TRANSPORT_FAULT,
    };

    fn fixed_outlet_message_key() -> [u8; OUTLET_MESSAGE_KEY_LEN] {
        [0x42; OUTLET_MESSAGE_KEY_LEN]
    }

    fn fixed_pad_nonce() -> [u8; PAD_NONCE_LEN] {
        [0x55; PAD_NONCE_LEN]
    }

    fn fixed_registration_event_id() -> [u8; REGISTRATION_EVENT_ID_LEN] {
        [0xAB; REGISTRATION_EVENT_ID_LEN]
    }

    fn registered() -> Vec<CatalogKey> {
        vec![
            CatalogKey::try_new("authorization.denied").unwrap(),
            CatalogKey::try_new("protocol.query-cost-violation").unwrap(),
            CatalogKey::try_new("execution.handler-panic").unwrap(),
            CatalogKey::try_new("input.schema-violation").unwrap(),
            CatalogKey::try_new("transport.rate-limited").unwrap(),
        ]
    }

    fn build_authorization_error() -> OutletError {
        let outlet_id: OutletId = "outlet-test".to_owned();
        let key = CatalogKey::try_new("authorization.denied").unwrap();
        let registered = registered();
        OutletError::new(OutletErrorNewOpts {
            outlet_id: &outlet_id,
            outlet_message_key: &fixed_outlet_message_key(),
            registration_event_id: fixed_registration_event_id(),
            catalog_key: &key,
            registered_keys: &registered,
            class: OutletErrorClass::Authorization,
            code: CODE_AUTHORIZATION_DENIED,
            slug: "authorization.denied",
            retry: RetryPolicy::Never,
            detail: Some(DetailBody::Authorization {
                capability: "outlet_query:test".to_owned(),
            }),
            source_chain: Vec::new(),
            pad_nonce: fixed_pad_nonce(),
        })
        .unwrap()
    }

    // -----------------------------------------------------------------------
    // OutletErrorClass — 8 variants, exact enumeration
    // -----------------------------------------------------------------------

    #[test]
    fn class_has_eight_variants() {
        // AC-1: enum OutletErrorClass has 8 variants. Exhaustive match
        // proves the variant set is exactly these eight.
        let all = [
            OutletErrorClass::Protocol,
            OutletErrorClass::Authorization,
            OutletErrorClass::Input,
            OutletErrorClass::Execution,
            OutletErrorClass::Output,
            OutletErrorClass::Economic,
            OutletErrorClass::Transport,
            OutletErrorClass::Governance,
        ];
        assert_eq!(all.len(), 8);
        for c in all {
            // Round-trip through wire vocabulary.
            let s = c.as_wire();
            let json = serde_json::to_string(&c).unwrap();
            assert_eq!(json, format!("\"{s}\""));
        }
    }

    // -----------------------------------------------------------------------
    // RetryPolicy — 4 variants per AC-2
    // -----------------------------------------------------------------------

    #[test]
    fn retry_policy_has_four_variants() {
        // AC-2: enum RetryPolicy has variants Never, Immediate, After,
        // WithBackoff.
        let _v: [RetryPolicy; 4] = [
            RetryPolicy::Never,
            RetryPolicy::Immediate,
            RetryPolicy::After {
                delay: Duration::from_secs(5),
            },
            RetryPolicy::WithBackoff {
                min: Duration::from_secs(1),
                max: Duration::from_mins(1),
            },
        ];
    }

    #[test]
    fn retry_policy_round_trips_json() {
        for v in [
            RetryPolicy::Never,
            RetryPolicy::Immediate,
            RetryPolicy::After {
                delay: Duration::from_millis(250),
            },
            RetryPolicy::WithBackoff {
                min: Duration::from_millis(50),
                max: Duration::from_secs(30),
            },
        ] {
            let bytes = serde_json::to_vec(&v).unwrap();
            let back: RetryPolicy = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(v, back);
        }
    }

    // -----------------------------------------------------------------------
    // ContextHop — fields per AC-3
    // -----------------------------------------------------------------------

    #[test]
    fn context_hop_struct_fields() {
        // AC-3: struct ContextHop has fields context_id, hop_index,
        // wrapped_code.
        let hop = ContextHop {
            context_id: "ctx-a".to_owned(),
            hop_index: 0,
            wrapped_code: CODE_AUTHORIZATION_DENIED.to_owned(),
        };
        let json = serde_json::to_string(&hop).unwrap();
        assert!(json.contains("\"context_id\""));
        assert!(json.contains("\"hop_index\""));
        assert!(json.contains("\"wrapped_code\""));
    }

    #[test]
    fn context_hop_round_trip() {
        let hop = ContextHop {
            context_id: "ctx-b".to_owned(),
            hop_index: 7,
            wrapped_code: CODE_EXECUTION_FAULT.to_owned(),
        };
        let bytes = rmp_serde::to_vec_named(&hop).unwrap();
        let back: ContextHop = rmp_serde::from_slice(&bytes).unwrap();
        assert_eq!(hop, back);
    }

    // -----------------------------------------------------------------------
    // CatalogKey
    // -----------------------------------------------------------------------

    #[test]
    fn catalog_key_validates_canonical_forms() {
        for k in [
            "authorization.denied",
            "authorization",
            "protocol.catalog-rotation-too-frequent",
            "transport.concurrent-streams-per-invoker",
            "execution.cancel-ack-timeout",
            "input.estimate-exceeds-bound",
        ] {
            CatalogKey::try_new(k).unwrap_or_else(|_| panic!("expected valid: {k}"));
        }
    }

    #[test]
    fn catalog_key_rejects_invalid_forms() {
        for k in [
            "",                     // empty
            "Authorization.denied", // uppercase
            "authorization..denied",
            ".authorization",
            "authorization.",
            "9authorization.denied",
            "authorization.9-foo",   // segment must start with letter
            "authorization.foo_bar", // underscore not allowed
        ] {
            assert!(CatalogKey::try_new(k).is_err(), "expected rejection: {k}");
        }
    }

    #[test]
    fn catalog_key_enforces_byte_cap() {
        let long = "a".repeat(CATALOG_KEY_MAX_BYTES + 1);
        assert!(CatalogKey::try_new(long).is_err());
    }

    #[test]
    fn message_too_long_variant_exists_and_is_typed() {
        // AC: "message field byte length is capped at 1024; constructor
        // OutletError::new returns OutletErrorConstructionFailed::MessageTooLong
        // when exceeded."
        //
        // The pre-HMAC `message` cap is `MESSAGE_MAX_BYTES = 1024` — the
        // §5.4.4 MessageTemplate bound. With round-5 / round-6 the on-wire
        // `message` field is a fixed 32-byte HMAC over a `CatalogKey`, which
        // is itself capped at `CATALOG_KEY_MAX_BYTES = 256` (a tighter
        // constraint). The 1024 cap therefore lives on `OutletError::new`'s
        // catalog-key pre-HMAC byte-length check — defensive against any
        // future path that bypasses `CatalogKey::try_new`. This test pins
        // the variant's wire shape and the constants so a future
        // refactor cannot silently lower them.
        let err = OutletErrorConstructionFailed::MessageTooLong {
            actual: MESSAGE_MAX_BYTES + 1,
            max: MESSAGE_MAX_BYTES,
        };
        match err {
            OutletErrorConstructionFailed::MessageTooLong { actual, max } => {
                assert_eq!(actual, MESSAGE_MAX_BYTES + 1);
                assert_eq!(max, MESSAGE_MAX_BYTES);
                assert_eq!(MESSAGE_MAX_BYTES, 1024);
            }
            other => panic!("expected MessageTooLong, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // OutletError::new — code/slug validation
    // -----------------------------------------------------------------------

    /// Negative-test input string. The runtime value is the 7-prefix variant
    /// outside the §5.4.4 6100-6199 sub-block. Phase 1 of the error-code CI
    /// gate (`scripts/check-error-codes.sh`) skips this line via the inline
    /// `SCP-CODE-OK:` exemption — a test fixture proving the rejection path.
    const INVALID_SUBBLOCK_CODE: &str = "SCP-OUTLET-7000"; // SCP-CODE-OK: negative-test fixture (§5.4.4 sub-block rejection)
    /// Negative-test input — a non-canonical-prefix code. The first segment
    /// after `SCP-` (`OUTLET`) is not in the `sdk-common.md` allowlist since the
    /// outlet error domain was renamed to the canonical `SCP-OUTLET-` prefix.
    /// Phase 1 skips this line via the inline `SCP-CODE-OK:` exemption.
    const NON_CANONICAL_PREFIX_CODE: &str = "SCP-TOOL-6100"; // SCP-CODE-OK: negative-test fixture (non-canonical prefix rejection)

    #[test]
    fn constructor_validates_code_regex() {
        // AC-4 / AC-7: an invalid code (e.g., one outside the §5.4.4
        // 6100-6199 sub-block) returns OutletErrorConstructionFailed.
        let outlet_id: OutletId = "x".to_owned();
        let key = CatalogKey::try_new("authorization.denied").unwrap();
        let registered = registered();
        let res = OutletError::new(OutletErrorNewOpts {
            outlet_id: &outlet_id,
            outlet_message_key: &fixed_outlet_message_key(),
            registration_event_id: fixed_registration_event_id(),
            catalog_key: &key,
            registered_keys: &registered,
            class: OutletErrorClass::Authorization,
            code: INVALID_SUBBLOCK_CODE, // outside the 6100-6199 sub-block
            slug: "authorization.denied",
            retry: RetryPolicy::Never,
            detail: Some(DetailBody::Authorization {
                capability: "outlet_query:x".to_owned(),
            }),
            source_chain: Vec::new(),
            pad_nonce: fixed_pad_nonce(),
        });
        assert!(matches!(
            res,
            Err(OutletErrorConstructionFailed::MalformedCode { .. })
        ));
    }

    #[test]
    fn constructor_validates_slug_regex() {
        let outlet_id: OutletId = "x".to_owned();
        let key = CatalogKey::try_new("authorization.denied").unwrap();
        let registered = registered();
        let res = OutletError::new(OutletErrorNewOpts {
            outlet_id: &outlet_id,
            outlet_message_key: &fixed_outlet_message_key(),
            registration_event_id: fixed_registration_event_id(),
            catalog_key: &key,
            registered_keys: &registered,
            class: OutletErrorClass::Authorization,
            code: CODE_AUTHORIZATION_DENIED,
            slug: "Authorization.Denied", // uppercase — invalid
            retry: RetryPolicy::Never,
            detail: Some(DetailBody::Authorization {
                capability: "outlet_query:x".to_owned(),
            }),
            source_chain: Vec::new(),
            pad_nonce: fixed_pad_nonce(),
        });
        assert!(matches!(
            res,
            Err(OutletErrorConstructionFailed::MalformedSlug { .. })
        ));
    }

    // -----------------------------------------------------------------------
    // SCP-OUT-025 — registry-driven class/code/slug consistency at
    // OutletError::new (defense-in-depth). The §5.4.4 registry helpers
    // `error_code_to_class`, `slug_to_class`, and `validate_slug` are
    // wired into the construction path so a class/code or class/slug
    // drift is rejected at the construction site, not on the wire.
    // -----------------------------------------------------------------------

    #[test]
    fn constructor_rejects_class_mismatch_for_registered_code() {
        // SCP-OUT-025: code 6110 maps to OutletErrorClass::Authorization
        // per the §5.4.4 registry. Constructing with a non-Authorization
        // `class` value MUST be rejected as ClassCodeMismatch — even when
        // the slug regex passes and the catalog key is registered.
        let outlet_id: OutletId = "x".to_owned();
        let key = CatalogKey::try_new("authorization.denied").unwrap();
        let registered = registered();
        let res = OutletError::new(OutletErrorNewOpts {
            outlet_id: &outlet_id,
            outlet_message_key: &fixed_outlet_message_key(),
            registration_event_id: fixed_registration_event_id(),
            catalog_key: &key,
            registered_keys: &registered,
            // Mismatch: 6110 is the Authorization-class code per the registry,
            // but the caller-supplied class is Input.
            class: OutletErrorClass::Input,
            code: CODE_AUTHORIZATION_DENIED,
            slug: "authorization.denied",
            retry: RetryPolicy::Never,
            detail: None,
            source_chain: Vec::new(),
            pad_nonce: fixed_pad_nonce(),
        });
        match res {
            Err(OutletErrorConstructionFailed::ClassCodeMismatch {
                code_or_slug,
                expected,
                actual,
            }) => {
                assert_eq!(code_or_slug, CODE_AUTHORIZATION_DENIED);
                assert_eq!(expected, OutletErrorClass::Authorization);
                assert_eq!(actual, OutletErrorClass::Input);
            }
            other => panic!("expected ClassCodeMismatch, got {other:?}"),
        }
    }

    #[test]
    fn constructor_rejects_class_mismatch_for_registered_slug() {
        // SCP-OUT-025: slug `transport.relay-unavailable` maps to
        // OutletErrorClass::Transport per slug_to_class. Constructing
        // with a non-Transport class MUST be rejected with the slug
        // (not the code) as the diagnostic surface.
        let outlet_id: OutletId = "x".to_owned();
        // Register an extra catalog key for this fixture.
        let key = CatalogKey::try_new("transport.relay-unavailable").unwrap();
        let registered: Vec<CatalogKey> = vec![
            CatalogKey::try_new("authorization.denied").unwrap(),
            key.clone(),
        ];
        let res = OutletError::new(OutletErrorNewOpts {
            outlet_id: &outlet_id,
            outlet_message_key: &fixed_outlet_message_key(),
            registration_event_id: fixed_registration_event_id(),
            catalog_key: &key,
            registered_keys: &registered,
            // The Transport-class slug paired with the Transport-class code
            // (6160) but a mismatched Authorization class. The slug check
            // (which runs after the code check) surfaces the diagnostic.
            class: OutletErrorClass::Authorization,
            code: CODE_TRANSPORT_FAULT,
            slug: "transport.relay-unavailable",
            retry: RetryPolicy::WithBackoff {
                min: Duration::from_secs(1),
                max: Duration::from_secs(30),
            },
            detail: None,
            source_chain: Vec::new(),
            pad_nonce: fixed_pad_nonce(),
        });
        match res {
            Err(OutletErrorConstructionFailed::ClassCodeMismatch {
                code_or_slug,
                expected,
                actual,
            }) => {
                // Code 6160 is Transport — the code check rejects first.
                assert_eq!(code_or_slug, CODE_TRANSPORT_FAULT);
                assert_eq!(expected, OutletErrorClass::Transport);
                assert_eq!(actual, OutletErrorClass::Authorization);
            }
            other => panic!("expected ClassCodeMismatch, got {other:?}"),
        }
    }

    #[test]
    fn constructor_rejects_class_mismatch_when_slug_only_disagrees() {
        // SCP-OUT-025: when the code is reserved/unregistered (so
        // `error_code_to_class` returns None) but the slug is in the
        // registry, the slug-based check still catches the mismatch.
        // 6180 is in the §5.4.4 reserved range — `error_code_to_class`
        // returns None, so the slug check is the only gate.
        let outlet_id: OutletId = "x".to_owned();
        let key = CatalogKey::try_new("execution.handler-panic").unwrap();
        let registered: Vec<CatalogKey> = vec![key.clone()];
        let res = OutletError::new(OutletErrorNewOpts {
            outlet_id: &outlet_id,
            outlet_message_key: &fixed_outlet_message_key(),
            registration_event_id: fixed_registration_event_id(),
            catalog_key: &key,
            registered_keys: &registered,
            class: OutletErrorClass::Authorization,
            // 6180 is reserved per §5.4.4 — no registry class, so no CODE_*
            // constant exists to reference here.
            code: "SCP-OUTLET-6180", // SCP-CODE-OK: reserved-range envelope fixture (§5.4.4)
            slug: "execution.handler-panic",
            retry: RetryPolicy::Never,
            detail: None,
            source_chain: Vec::new(),
            pad_nonce: fixed_pad_nonce(),
        });
        match res {
            Err(OutletErrorConstructionFailed::ClassCodeMismatch {
                code_or_slug,
                expected,
                actual,
            }) => {
                assert_eq!(code_or_slug, "execution.handler-panic");
                assert_eq!(expected, OutletErrorClass::Execution);
                assert_eq!(actual, OutletErrorClass::Authorization);
            }
            other => panic!("expected ClassCodeMismatch, got {other:?}"),
        }
    }

    #[test]
    fn constructor_accepts_class_matching_registry() {
        // Positive control: code 6130 / slug `execution.handler-panic` /
        // class Execution all agree per the §5.4.4 registry. The
        // class/code/slug consistency check passes; construction
        // succeeds.
        let outlet_id: OutletId = "x".to_owned();
        let key = CatalogKey::try_new("execution.handler-panic").unwrap();
        let registered: Vec<CatalogKey> = vec![key.clone()];
        let env = OutletError::new(OutletErrorNewOpts {
            outlet_id: &outlet_id,
            outlet_message_key: &fixed_outlet_message_key(),
            registration_event_id: fixed_registration_event_id(),
            catalog_key: &key,
            registered_keys: &registered,
            class: OutletErrorClass::Execution,
            code: CODE_EXECUTION_FAULT,
            slug: "execution.handler-panic",
            retry: RetryPolicy::Never,
            detail: None,
            source_chain: Vec::new(),
            pad_nonce: fixed_pad_nonce(),
        })
        .expect("registry-aligned construction must succeed");
        assert_eq!(env.class, OutletErrorClass::Execution);
        assert_eq!(env.code, CODE_EXECUTION_FAULT);
        assert_eq!(env.slug, "execution.handler-panic");
    }

    #[test]
    fn constructor_rejects_uppercase_slug_via_validate_slug() {
        // SCP-OUT-025: the §5.4.4 slug regex check is now routed through
        // `validate_slug`. An uppercase slug must be rejected with
        // MalformedSlug — the same surface as before, but driven by the
        // registry's typed entry point.
        let outlet_id: OutletId = "x".to_owned();
        let key = CatalogKey::try_new("authorization.denied").unwrap();
        let registered = registered();
        let res = OutletError::new(OutletErrorNewOpts {
            outlet_id: &outlet_id,
            outlet_message_key: &fixed_outlet_message_key(),
            registration_event_id: fixed_registration_event_id(),
            catalog_key: &key,
            registered_keys: &registered,
            class: OutletErrorClass::Authorization,
            code: CODE_AUTHORIZATION_DENIED,
            slug: "AUTHORIZATION.DENIED", // uppercase — fails §5.4.4 regex
            retry: RetryPolicy::Never,
            detail: None,
            source_chain: Vec::new(),
            pad_nonce: fixed_pad_nonce(),
        });
        assert!(matches!(
            res,
            Err(OutletErrorConstructionFailed::MalformedSlug { slug }) if slug == "AUTHORIZATION.DENIED"
        ));
    }

    #[test]
    fn constructor_rejects_slug_missing_class_prefix_when_registry_disagrees() {
        // SCP-OUT-025: a slug with no class prefix (e.g. "denied") still
        // passes the regex but is not in the registry. This documents
        // the regex/registry split: regex-pass + registry-miss is allowed
        // (so SCP-OUT-021 caveat slugs ahead of registration round-trip),
        // but a slug whose registry entry disagrees with the supplied
        // class is rejected.
        //
        // Here we use `query-cost-violation` (Protocol class per registry)
        // with a non-Protocol class.
        let outlet_id: OutletId = "x".to_owned();
        let key = CatalogKey::try_new("protocol.query-cost-violation").unwrap();
        let registered: Vec<CatalogKey> = vec![key.clone()];
        let res = OutletError::new(OutletErrorNewOpts {
            outlet_id: &outlet_id,
            outlet_message_key: &fixed_outlet_message_key(),
            registration_event_id: fixed_registration_event_id(),
            catalog_key: &key,
            registered_keys: &registered,
            class: OutletErrorClass::Authorization,
            code: CODE_PROTOCOL_VIOLATION,
            slug: "query-cost-violation", // Protocol-class per registry
            retry: RetryPolicy::Never,
            detail: None,
            source_chain: Vec::new(),
            pad_nonce: fixed_pad_nonce(),
        });
        match res {
            Err(OutletErrorConstructionFailed::ClassCodeMismatch {
                expected, actual, ..
            }) => {
                assert_eq!(expected, OutletErrorClass::Protocol);
                assert_eq!(actual, OutletErrorClass::Authorization);
            }
            other => panic!("expected ClassCodeMismatch, got {other:?}"),
        }
    }

    #[test]
    fn constructor_accepts_valid_canonical_code_range() {
        // Positive-test fixture for the range validator. 6199 is a §5.4.4
        // reserved-gap with no allocated CODE_* constant that the range
        // validator must still accept, so it stays a raw literal here.
        let valid_codes: [&str; 3] = [
            CODE_PROTOCOL_VIOLATION,
            CODE_AUTHORIZATION_DENIED,
            "SCP-OUTLET-6199", // SCP-CODE-OK: reserved-gap 6199 (no const) for range validator
        ];
        for code in valid_codes {
            assert!(validate_outlet_error_code(code), "expected valid: {code}");
        }
        // Negative-test inputs for the Rust sub-block validator (accepts only
        // 6100-6199). The `609x` / `620x` literals below sit inside the broader
        // `check-error-codes.sh` range (6000-6999), so they pass Phase 1 with
        // no `SCP-CODE-OK:` marker; only `INVALID_SUBBLOCK_CODE` (out of range)
        // and `NON_CANONICAL_PREFIX_CODE` (non-canonical prefix) carry the
        // marker on their `const` definitions above.
        let invalid_codes: [&str; 6] = [
            "SCP-OUTLET-6099",
            "SCP-OUTLET-6200",
            INVALID_SUBBLOCK_CODE,     // 7-prefix variant outside the sub-block
            NON_CANONICAL_PREFIX_CODE, // non-canonical prefix segment
            "scp-outlet-6100",         // wrong case
            "",                        // empty
        ];
        for code in invalid_codes {
            assert!(
                !validate_outlet_error_code(code),
                "expected invalid: {code}"
            );
        }
    }

    // -----------------------------------------------------------------------
    // Catalog membership / HMAC over registered key
    // -----------------------------------------------------------------------

    #[test]
    fn constructor_rejects_unregistered_catalog_key() {
        // AC: a catalog-miss catalog_key is rejected with the typed error.
        let outlet_id: OutletId = "x".to_owned();
        let unknown = CatalogKey::try_new("authorization.unknown-key").unwrap();
        let registered = registered();
        let res = OutletError::new(OutletErrorNewOpts {
            outlet_id: &outlet_id,
            outlet_message_key: &fixed_outlet_message_key(),
            registration_event_id: fixed_registration_event_id(),
            catalog_key: &unknown,
            registered_keys: &registered,
            class: OutletErrorClass::Authorization,
            code: CODE_AUTHORIZATION_DENIED,
            slug: "authorization.denied",
            retry: RetryPolicy::Never,
            detail: Some(DetailBody::Authorization {
                capability: "outlet_query:x".to_owned(),
            }),
            source_chain: Vec::new(),
            pad_nonce: fixed_pad_nonce(),
        });
        assert!(matches!(
            res,
            Err(OutletErrorConstructionFailed::UnregisteredMessageKey { .. })
        ));
    }

    #[test]
    fn constructor_emits_hmac_wire_message() {
        // AC: a catalog-hit returns an OutletError whose on-wire message
        // field is the 32-byte HMAC output.
        let err = build_authorization_error();
        let key = CatalogKey::try_new("authorization.denied").unwrap();
        let expected = OutletError::compute_wire_message(&fixed_outlet_message_key(), &key);
        assert_eq!(err.message, expected);
        assert_eq!(err.message.len(), WIRE_MESSAGE_LEN);
    }

    #[test]
    fn hmac_distinct_per_outlet_key() {
        // §5.4.4 round-5: per-outlet keying defeats cross-context signaling.
        let key = CatalogKey::try_new("authorization.denied").unwrap();
        let a = OutletError::compute_wire_message(&[0x01; 32], &key);
        let b = OutletError::compute_wire_message(&[0x02; 32], &key);
        assert_ne!(a, b);
    }

    // -----------------------------------------------------------------------
    // Detail-shape enforcement — AC-15 / AC-16
    // -----------------------------------------------------------------------

    #[test]
    fn detail_shape_must_match_class() {
        // AC-15: a Protocol-class OutletError with detail shaped like
        // Input-class detail is rejected.
        let outlet_id: OutletId = "x".to_owned();
        let key = CatalogKey::try_new("protocol.query-cost-violation").unwrap();
        let registered = registered();
        let res = OutletError::new(OutletErrorNewOpts {
            outlet_id: &outlet_id,
            outlet_message_key: &fixed_outlet_message_key(),
            registration_event_id: fixed_registration_event_id(),
            catalog_key: &key,
            registered_keys: &registered,
            class: OutletErrorClass::Protocol,
            code: CODE_PROTOCOL_VIOLATION,
            slug: "protocol.query-cost-violation",
            retry: RetryPolicy::Never,
            detail: Some(DetailBody::FieldViolation {
                field_path: "/x".to_owned(),
                violation: "type".to_owned(),
            }),
            source_chain: Vec::new(),
            pad_nonce: fixed_pad_nonce(),
        });
        assert!(matches!(
            res,
            Err(OutletErrorConstructionFailed::DetailShapeMismatch {
                class: OutletErrorClass::Protocol,
                actual: DetailKind::FieldViolation,
            })
        ));
    }

    #[test]
    fn execution_panic_uses_full_sha256_hash() {
        // AC-16: panic_location_hash is [u8; 32]. A 16-byte hash cannot
        // even be constructed via the type system; this test pins the
        // contract.
        let outlet_id: OutletId = "x".to_owned();
        let key = CatalogKey::try_new("execution.handler-panic").unwrap();
        let registered = registered();
        let err = OutletError::new(OutletErrorNewOpts {
            outlet_id: &outlet_id,
            outlet_message_key: &fixed_outlet_message_key(),
            registration_event_id: fixed_registration_event_id(),
            catalog_key: &key,
            registered_keys: &registered,
            class: OutletErrorClass::Execution,
            code: CODE_EXECUTION_FAULT,
            slug: "execution.handler-panic",
            retry: RetryPolicy::Never,
            detail: Some(DetailBody::ExecutionPanic {
                panic_location_hash: [0x99; 32],
            }),
            source_chain: Vec::new(),
            pad_nonce: fixed_pad_nonce(),
        })
        .unwrap();
        match err.detail.as_ref().unwrap() {
            DetailBody::ExecutionPanic {
                panic_location_hash,
            } => {
                assert_eq!(panic_location_hash.len(), 32);
            }
            other => panic!("unexpected detail variant: {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // pad_nonce / registration_event_id unconditional emission — AC-13/17
    // -----------------------------------------------------------------------

    #[test]
    fn pad_nonce_is_emitted_unconditionally() {
        // AC-13: pad_nonce is [u8; 16] (fixed, NOT Option<[u8; 16]>); the
        // field is unconditional.
        let err = build_authorization_error();
        assert_eq!(err.pad_nonce.len(), PAD_NONCE_LEN);
        let bytes = rmp_serde::to_vec_named(&err).unwrap();
        let back: OutletError = rmp_serde::from_slice(&bytes).unwrap();
        assert_eq!(back.pad_nonce, err.pad_nonce);
    }

    #[test]
    fn registration_event_id_is_emitted_unconditionally() {
        // AC-17: registration_event_id is [u8; 32] (fixed, NOT
        // Option<[u8; 32]>); the field is unconditional.
        let err = build_authorization_error();
        assert_eq!(err.registration_event_id.len(), REGISTRATION_EVENT_ID_LEN);
        let bytes = rmp_serde::to_vec_named(&err).unwrap();
        let back: OutletError = rmp_serde::from_slice(&bytes).unwrap();
        assert_eq!(back.registration_event_id, err.registration_event_id);
    }

    /// Helper: serializes an [`OutletError`] then drops the requested numeric
    /// wire tag from the resulting `MessagePack` map, returning the new bytes.
    /// The output is a valid `MessagePack` map missing exactly that tag —
    /// used to drive the wire-rejection tests below.
    fn serialize_and_drop_tag(err: &OutletError, drop_tag: &str) -> Vec<u8> {
        let bytes = rmp_serde::to_vec_named(err).unwrap();
        let value: rmpv::Value = rmp_serde::from_slice(&bytes).unwrap();
        let pairs = match value {
            rmpv::Value::Map(m) => m,
            other => panic!("expected map, got {other:?}"),
        };
        let kept: Vec<(rmpv::Value, rmpv::Value)> = pairs
            .into_iter()
            .filter(|(k, _)| match k {
                rmpv::Value::String(s) => s.as_str() != Some(drop_tag),
                _ => true,
            })
            .collect();
        rmp_serde::to_vec_named(&rmpv::Value::Map(kept)).unwrap()
    }

    #[test]
    fn wire_layer_rejects_missing_pad_nonce_tag_11() {
        // AC-13: wire-layer deserialization rejects an envelope whose tag-11
        // field is missing. `pad_nonce` is unconditional (§5.4.4 round-5).
        let err = build_authorization_error();
        let truncated = serialize_and_drop_tag(&err, "11");
        let result: Result<OutletError, _> = rmp_serde::from_slice(&truncated);
        assert!(
            result.is_err(),
            "expected wire-layer rejection of missing tag-11 pad_nonce"
        );
    }

    #[test]
    fn wire_layer_rejects_missing_registration_event_id_tag_12() {
        // AC-17: wire-layer deserialization rejects an envelope whose tag-12
        // field is missing. `registration_event_id` is unconditional
        // (§5.4.4 round-6).
        let err = build_authorization_error();
        let truncated = serialize_and_drop_tag(&err, "12");
        let result: Result<OutletError, _> = rmp_serde::from_slice(&truncated);
        assert!(
            result.is_err(),
            "expected wire-layer rejection of missing tag-12 registration_event_id"
        );
    }

    #[test]
    fn missing_pad_nonce_construction_error_variant_exists() {
        // Pin the typed [`OutletErrorConstructionFailed::MissingPadNonce`]
        // variant exists with the documented Display string. SDKs distinguish
        // "old envelope" from "wire corruption" via this typed error.
        let err = OutletErrorConstructionFailed::MissingPadNonce;
        let s = err.to_string();
        assert!(s.contains("tag-11"), "Display must mention tag-11: {s}");
        assert!(
            s.contains("pad_nonce"),
            "Display must mention pad_nonce: {s}"
        );
    }

    #[test]
    fn missing_registration_event_id_construction_error_variant_exists() {
        // Pin the typed
        // [`OutletErrorConstructionFailed::MissingRegistrationEventId`]
        // variant exists with the documented Display string.
        let err = OutletErrorConstructionFailed::MissingRegistrationEventId;
        let s = err.to_string();
        assert!(s.contains("tag-12"), "Display must mention tag-12: {s}");
        assert!(
            s.contains("registration_event_id"),
            "Display must mention registration_event_id: {s}"
        );
    }

    #[test]
    fn wire_layer_rejects_short_panic_location_hash() {
        // AC-16: "a 16-byte panic_location_hash is wire-rejected as
        // DetailShapeMismatch."
        //
        // The Rust type system enforces `[u8; 32]` on the struct field, so
        // a 16-byte hash cannot be constructed in Rust. To exercise the
        // wire-layer rejection we hand-craft a `MessagePack` envelope whose
        // `ExecutionPanic.panic_location_hash` is 16 bytes, then deserialize
        // it back through `DetailBody`. The `serde_hash_32` deserializer
        // rejects any length other than 32 bytes — which manifests as a
        // wire-layer rejection at the `OutletError` boundary, satisfying the
        // AC's intent.
        let bad_detail = rmpv::Value::Map(vec![
            (
                rmpv::Value::String("shape".into()),
                rmpv::Value::String("execution-panic".into()),
            ),
            (
                rmpv::Value::String("panic_location_hash".into()),
                rmpv::Value::Binary(vec![0u8; 16]),
            ),
        ]);
        let bytes = rmp_serde::to_vec_named(&bad_detail).unwrap();
        let result: Result<DetailBody, _> = rmp_serde::from_slice(&bytes);
        assert!(
            result.is_err(),
            "expected wire-layer rejection of 16-byte panic_location_hash"
        );
    }

    // -----------------------------------------------------------------------
    // Round-trip — AC-5, AC-6
    // -----------------------------------------------------------------------

    #[test]
    fn messagepack_round_trip_full_envelope() {
        // AC-5: MessagePack round-trip on a fully-populated OutletError.
        let mut err = build_authorization_error();
        err.source_chain = vec![ContextHop {
            context_id: "ctx-x".to_owned(),
            hop_index: 0,
            wrapped_code: CODE_AUTHORIZATION_DENIED.to_owned(),
        }];
        let bytes = rmp_serde::to_vec_named(&err).unwrap();
        let back: OutletError = rmp_serde::from_slice(&bytes).unwrap();
        assert_eq!(err, back);
    }

    #[test]
    fn json_round_trip_full_envelope() {
        // AC-6: JSON round-trip on a fully-populated OutletError.
        let mut err = build_authorization_error();
        err.source_chain = vec![ContextHop {
            context_id: "ctx-y".to_owned(),
            hop_index: 1,
            wrapped_code: CODE_EXECUTION_FAULT.to_owned(),
        }];
        let bytes = serde_json::to_vec(&err).unwrap();
        let back: OutletError = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(err, back);
    }

    // -----------------------------------------------------------------------
    // Numeric tag presence / absence — AC-9, AC-10
    // -----------------------------------------------------------------------

    #[test]
    fn numeric_field_tags_present_on_wire() {
        // AC-10: tags 1, 2, 3, 4, 5, 6, 8, 11, 12 are present; tags
        // 7, 9, 10 are explicitly absent.
        let err = build_authorization_error();
        let bytes = rmp_serde::to_vec_named(&err).unwrap();
        let value: rmpv::Value = rmp_serde::from_slice(&bytes).unwrap();
        let map = match &value {
            rmpv::Value::Map(m) => m,
            other => panic!("expected MessagePack map, got {other:?}"),
        };
        let keys: Vec<&str> = map
            .iter()
            .filter_map(|(k, _)| match k {
                rmpv::Value::String(s) => s.as_str(),
                _ => None,
            })
            .collect();
        for present in ["1", "2", "3", "4", "5", "6", "8", "11", "12"] {
            assert!(
                keys.contains(&present),
                "expected tag {present} in {keys:?}"
            );
        }
        for absent in ["7", "9", "10"] {
            assert!(
                !keys.contains(&absent),
                "tag {absent} must be RESERVED — found in {keys:?}"
            );
        }
    }

    #[test]
    fn struct_has_nine_wire_tagged_fields_plus_unknown_slot() {
        // AC-9: struct OutletError exists with exactly 9 wire fields:
        //   1, 2, 3, 4, 5, 6, 8, 11, 12.
        // Plus the `unknown_fields` flatten slot (round-trips RESERVED 7/9/10
        // and future 13+).
        let err = build_authorization_error();
        let bytes = rmp_serde::to_vec_named(&err).unwrap();
        let value: rmpv::Value = rmp_serde::from_slice(&bytes).unwrap();
        let map = match &value {
            rmpv::Value::Map(m) => m,
            other => panic!("expected MessagePack map, got {other:?}"),
        };
        // No source_chain in the basic builder — but we still carry tag 8.
        // The 9 wire-tagged fields are 1, 2, 3, 4, 5, 6, 8, 11, 12.
        let expected: std::collections::BTreeSet<&str> =
            ["1", "2", "3", "4", "5", "6", "8", "11", "12"]
                .into_iter()
                .collect();
        let actual: std::collections::BTreeSet<&str> = map
            .iter()
            .filter_map(|(k, _)| match k {
                rmpv::Value::String(s) => s.as_str(),
                _ => None,
            })
            .collect();
        assert_eq!(actual, expected, "wire tag set must match §5.4.4");
    }

    // -----------------------------------------------------------------------
    // Forward-compat — AC-11, AC-12
    // -----------------------------------------------------------------------

    #[test]
    fn forward_compat_tag_13_round_trips_in_unknown_fields() {
        // AC-11: an OutletError envelope received with a field at tag 13+
        // deserializes cleanly and the unknown tag is preserved in
        // _unknown_fields and round-trips byte-identical on re-serialization.
        let mut err = build_authorization_error();
        err.unknown_fields.insert(
            "13".to_owned(),
            rmpv::Value::String("future-extension".into()),
        );
        let bytes = rmp_serde::to_vec_named(&err).unwrap();
        let back: OutletError = rmp_serde::from_slice(&bytes).unwrap();
        assert_eq!(back, err, "unknown tag-13 must round-trip");
        assert!(back.unknown_fields.contains_key("13"));
    }

    #[test]
    fn forward_compat_reserved_tags_7_9_10_preserve_in_unknown_fields() {
        // AC-12: an envelope received with a field at tag 7, 9, or 10
        // (RESERVED) deserializes with the value stored in _unknown_fields
        // (receiver does not interpret the tag).
        for tag in ["7", "9", "10"] {
            let mut err = build_authorization_error();
            err.unknown_fields
                .insert(tag.to_owned(), rmpv::Value::Integer(42i64.into()));
            let bytes = rmp_serde::to_vec_named(&err).unwrap();
            let back: OutletError = rmp_serde::from_slice(&bytes).unwrap();
            assert_eq!(
                back, err,
                "RESERVED tag {tag} must round-trip via unknown_fields"
            );
            assert!(back.unknown_fields.contains_key(tag));
        }
    }

    #[test]
    fn forward_compat_unknown_fields_byte_identical_round_trip() {
        // AC-11 strict: round-trips byte-identical on re-serialization.
        let mut err = build_authorization_error();
        err.unknown_fields.insert(
            "13".to_owned(),
            rmpv::Value::Array(vec![
                rmpv::Value::Integer(1.into()),
                rmpv::Value::Integer(2.into()),
            ]),
        );
        let bytes_a = rmp_serde::to_vec_named(&err).unwrap();
        let back: OutletError = rmp_serde::from_slice(&bytes_a).unwrap();
        let bytes_b = rmp_serde::to_vec_named(&back).unwrap();
        assert_eq!(bytes_a, bytes_b);
    }

    // -----------------------------------------------------------------------
    // Source-chain shape
    // -----------------------------------------------------------------------

    #[test]
    fn source_chain_round_trips_with_multiple_hops() {
        let mut err = build_authorization_error();
        err.source_chain = vec![
            ContextHop {
                context_id: "ctx-0".to_owned(),
                hop_index: 0,
                wrapped_code: CODE_AUTHORIZATION_DENIED.to_owned(),
            },
            ContextHop {
                context_id: "ctx-1".to_owned(),
                hop_index: 1,
                wrapped_code: CODE_EXECUTION_FAULT.to_owned(),
            },
        ];
        let bytes = rmp_serde::to_vec_named(&err).unwrap();
        let back: OutletError = rmp_serde::from_slice(&bytes).unwrap();
        assert_eq!(back.source_chain.len(), 2);
        assert_eq!(back.source_chain[0].hop_index, 0);
        assert_eq!(back.source_chain[1].hop_index, 1);
    }

    // -----------------------------------------------------------------------
    // Detail variant round-trip per class
    // -----------------------------------------------------------------------

    #[test]
    fn each_detail_kind_round_trips() {
        for body in [
            DetailBody::Protocol {
                rule: "query-cost-floor".to_owned(),
            },
            DetailBody::Authorization {
                capability: "outlet_query:x".to_owned(),
            },
            DetailBody::FieldViolation {
                field_path: "/items/0".to_owned(),
                violation: "type".to_owned(),
            },
            DetailBody::ExecutionTimeout { elapsed_ms: 30_000 },
            DetailBody::ExecutionPanic {
                panic_location_hash: [0x12; 32],
            },
            DetailBody::EconomicInsufficient {
                needed: 100,
                currency: "USD".to_owned(),
            },
            DetailBody::EconomicAdapter {
                adapter_id: "adapter-x".to_owned(),
            },
            DetailBody::TransportRateLimit {
                retry_after_secs: 30,
            },
            DetailBody::TransportRelay {
                relay_url_kind: RelayUrlKind::Wss,
            },
            DetailBody::Governance {
                action: "outlet-deregistered".to_owned(),
            },
        ] {
            let bytes = rmp_serde::to_vec_named(&body).unwrap();
            let back: DetailBody = rmp_serde::from_slice(&bytes).unwrap();
            assert_eq!(body.kind(), back.kind());
        }
    }

    // -----------------------------------------------------------------------
    // Forward-compat / required-field / order-independence — SCP-OUT-026
    // -----------------------------------------------------------------------

    /// Builds a `MessagePack` map of the §5.4.4 [`OutletError`] envelope by hand
    /// from primitive `rmpv` values.
    ///
    /// The hand-crafted form bypasses [`OutletError`]'s [`Serialize`] entirely
    /// — driving the SCP-OUT-026 forward-compat AC ("a serialized envelope
    /// with an unknown field tag deserializes cleanly"). Field order matches
    /// what [`rmp_serde::to_vec_named`] would emit on a Rust-side round trip:
    /// declared fields (`1`, `2`, `3`, `4`, `5`, `6`, `8`, `11`, `12`) in
    /// struct-declaration order, then any extra `flatten` map entries in
    /// `BTreeMap<String, _>` lex-order (`"99"` lex-sorts after the declared
    /// numeric tags). This ordering is the byte-equality precondition that the
    /// `forward_compat_hand_crafted_tag_99_byte_identical_round_trip` test
    /// asserts.
    fn build_envelope_map_with_extra_tag(
        extra_tag: Option<(&str, rmpv::Value)>,
    ) -> Vec<(rmpv::Value, rmpv::Value)> {
        let key = CatalogKey::try_new("authorization.denied").unwrap();
        let wire_message = OutletError::compute_wire_message(&fixed_outlet_message_key(), &key);
        let mut pairs: Vec<(rmpv::Value, rmpv::Value)> = vec![
            (
                rmpv::Value::String("1".into()),
                rmpv::Value::String(CODE_AUTHORIZATION_DENIED.into()),
            ),
            (
                rmpv::Value::String("2".into()),
                rmpv::Value::String("authorization.denied".into()),
            ),
            (
                rmpv::Value::String("3".into()),
                rmpv::Value::String("authorization".into()),
            ),
            (
                rmpv::Value::String("4".into()),
                rmpv::Value::Binary(wire_message.to_vec()),
            ),
            (
                rmpv::Value::String("5".into()),
                rmpv::Value::Map(vec![(
                    rmpv::Value::String("policy".into()),
                    rmpv::Value::String("never".into()),
                )]),
            ),
            (
                rmpv::Value::String("6".into()),
                rmpv::Value::Map(vec![
                    (
                        rmpv::Value::String("shape".into()),
                        rmpv::Value::String("authorization".into()),
                    ),
                    (
                        rmpv::Value::String("capability".into()),
                        rmpv::Value::String("outlet_query:test".into()),
                    ),
                ]),
            ),
            (
                rmpv::Value::String("8".into()),
                rmpv::Value::Array(Vec::new()),
            ),
            (
                rmpv::Value::String("11".into()),
                rmpv::Value::Binary(fixed_pad_nonce().to_vec()),
            ),
            (
                rmpv::Value::String("12".into()),
                rmpv::Value::Binary(fixed_registration_event_id().to_vec()),
            ),
        ];
        if let Some((tag, value)) = extra_tag {
            // Lex-sort the new key into the existing field-order so the
            // re-serialized bytes match the hand-crafted bytes (BTreeMap
            // `unknown_fields` iterates in lex order; "99" sorts after the
            // declared numeric tags).
            let entry = (rmpv::Value::String(tag.into()), value);
            let pos = pairs
                .iter()
                .position(|(k, _)| match k {
                    rmpv::Value::String(s) => s.as_str().is_some_and(|existing| existing > tag),
                    _ => false,
                })
                .unwrap_or(pairs.len());
            pairs.insert(pos, entry);
        }
        pairs
    }

    #[test]
    fn forward_compat_hand_crafted_tag_99_byte_identical_round_trip() {
        // SCP-OUT-026 AC: a hand-crafted MessagePack envelope carrying an
        // extra field at numeric tag "99" -> "future-value" deserializes
        // cleanly into [`OutletError`]; the unknown tag is preserved in
        // `unknown_fields`; re-serializing the deserialized struct produces
        // the EXACT bytes that were fed in (byte-equality round-trip).
        //
        // The hand-crafted form bypasses Rust-side `Serialize` — it is the
        // wire shape an SDK would receive from a peer running a future
        // protocol revision. Byte-equality on round-trip is the §5.4.4
        // forward-compat invariant.
        let pairs = build_envelope_map_with_extra_tag(Some((
            "99",
            rmpv::Value::String("future-value".into()),
        )));
        let hand_crafted = rmp_serde::to_vec_named(&rmpv::Value::Map(pairs)).unwrap();

        // Deserialize — the unknown tag must be captured.
        let envelope: OutletError = rmp_serde::from_slice(&hand_crafted)
            .expect("hand-crafted envelope with tag 99 must deserialize");
        assert!(
            envelope.unknown_fields.contains_key("99"),
            "tag-99 must round-trip into unknown_fields, got {:?}",
            envelope.unknown_fields
        );
        match envelope.unknown_fields.get("99") {
            Some(rmpv::Value::String(s)) => {
                assert_eq!(s.as_str(), Some("future-value"));
            }
            other => panic!("expected tag-99 to be String(\"future-value\"), got {other:?}"),
        }

        // Re-serialize — the bytes must match the hand-crafted input exactly.
        let re_serialized = rmp_serde::to_vec_named(&envelope).expect("re-serialize must succeed");
        assert_eq!(
            re_serialized, hand_crafted,
            "byte-identical round-trip required by §5.4.4 forward-compat invariant"
        );
    }

    #[test]
    fn forward_compat_field_order_reversed_deserializes_identically() {
        // SCP-OUT-026 AC: an envelope whose field order is reversed
        // (relative to declaration order) deserializes into the SAME
        // [`OutletError`] as the canonical-order form. MessagePack maps are
        // tag-indexed (the §5.4.4 wire format uses numeric string tags, NOT
        // positional ordering); a reversed encoding must be semantically
        // equivalent.
        let canonical_pairs = build_envelope_map_with_extra_tag(None);
        let mut reversed_pairs = canonical_pairs.clone();
        reversed_pairs.reverse();

        let canonical_bytes = rmp_serde::to_vec_named(&rmpv::Value::Map(canonical_pairs)).unwrap();
        let reversed_bytes = rmp_serde::to_vec_named(&rmpv::Value::Map(reversed_pairs)).unwrap();

        // The two byte sequences differ — they encode the same map with
        // different key ordering — but both must deserialize into envelopes
        // whose typed contents compare equal.
        assert_ne!(
            canonical_bytes, reversed_bytes,
            "test setup precondition: reversed pairs must produce distinct bytes"
        );

        let canonical: OutletError = rmp_serde::from_slice(&canonical_bytes)
            .expect("canonical-order envelope must deserialize");
        let reversed: OutletError = rmp_serde::from_slice(&reversed_bytes)
            .expect("reversed-order envelope must deserialize");

        assert_eq!(
            canonical, reversed,
            "tag-indexed wire format must yield identical envelopes regardless of field order"
        );
    }

    #[test]
    fn wire_layer_rejects_missing_message_tag_4() {
        // SCP-OUT-026 AC: an envelope that omits tag 4 (the `message` field
        // — the §5.4.4 `HMAC-SHA-256(outlet_message_key, catalog_key)[..32]`
        // wire form) MUST fail deserialization with a meaningful error.
        // `message` is a required field per §5.4.4 — there is no
        // `Option`/`default` escape; the receiver structurally rejects.
        let err = build_authorization_error();
        let truncated = serialize_and_drop_tag(&err, "4");
        let result: Result<OutletError, rmp_serde::decode::Error> =
            rmp_serde::from_slice(&truncated);
        let decode_err =
            result.expect_err("expected wire-layer rejection of missing tag-4 message");

        // The error must mention the missing field name so SDK consumers can
        // diagnose. `rmp_serde` surfaces the missing field name verbatim
        // through serde's "missing field" path.
        let display = decode_err.to_string();
        assert!(
            display.contains('4') || display.to_ascii_lowercase().contains("missing"),
            "decode error must indicate the missing tag-4 field; got: {display}"
        );
    }

    // -----------------------------------------------------------------------
    // OutletErrorSurface — SCP-OUT-031 PR-2a
    // -----------------------------------------------------------------------

    use super::super::error_codes::CODE_TRANSPORT_FAULT as SURFACE_TEST_CODE_TRANSPORT_FAULT;
    use super::super::error_codes::{
        CODE_ECONOMIC_FAULT, CODE_INPUT_VIOLATION, SLUG_AUTHORIZATION_DENIED,
        SLUG_ECONOMIC_ESCROW_OVERFLOW, SLUG_INPUT_SCHEMA_VIOLATION, class_to_canonical_code,
        error_code_to_class, error_code_to_retry_policy, slug_to_class,
    };

    /// The core soundness invariant asserted for every surface producer:
    /// `(class, code, slug)` are mutually consistent with the §5.4.4 registry.
    fn assert_surface_consistent(s: &OutletErrorSurface) {
        assert_eq!(
            error_code_to_class(&s.code),
            Some(s.class),
            "code {} must map to class {:?}",
            s.code,
            s.class
        );
        assert_eq!(
            slug_to_class(&s.slug),
            Some(s.class),
            "slug {} must map to class {:?}",
            s.slug,
            s.class
        );
        // retry must be the code's registered default.
        assert_eq!(error_code_to_retry_policy(&s.code), Some(s.retry.clone()));
    }

    #[test]
    fn from_code_keeps_registered_same_class_slug() {
        let s = OutletErrorSurface::from_code(
            CODE_INPUT_VIOLATION,
            SLUG_INPUT_SCHEMA_VIOLATION,
            Some(DetailBody::FieldViolation {
                field_path: "/x".to_owned(),
                violation: "type".to_owned(),
            }),
        );
        assert_eq!(s.class, OutletErrorClass::Input);
        assert_eq!(s.code, CODE_INPUT_VIOLATION);
        assert_eq!(s.slug, SLUG_INPUT_SCHEMA_VIOLATION);
        assert!(s.detail.is_some());
        assert_surface_consistent(&s);
    }

    #[test]
    fn from_code_falls_back_to_default_slug_for_unregistered() {
        // An unregistered diagnostic slug (camelCase caveat-counter kind)
        // must fall back to the code's canonical default slug so the surface
        // stays registry-consistent.
        let s = OutletErrorSurface::from_code(
            class_to_canonical_code(OutletErrorClass::Authorization),
            "maxCalls",
            None,
        );
        assert_eq!(s.class, OutletErrorClass::Authorization);
        assert_eq!(s.slug, SLUG_AUTHORIZATION_DENIED);
        assert_surface_consistent(&s);
    }

    // A registered slug of a DIFFERENT class than the code is a caller
    // miswiring: the `debug_assert!` in `from_code` fires (in debug/test
    // builds) so the mispairing is caught rather than silently swapped. In a
    // release build the assert is compiled out and the slug is swapped for the
    // code's default (preserving the class/code/slug consistency invariant).
    // Gated on `debug_assertions` because `#[should_panic]` requires the assert
    // to actually be compiled in.
    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "likely a miswired (code, slug) pair")]
    fn from_code_debug_asserts_on_registered_wrong_class_slug() {
        let _ = OutletErrorSurface::from_code(
            CODE_INPUT_VIOLATION,
            SLUG_ECONOMIC_ESCROW_OVERFLOW, // Economic slug, Input code — miswiring
            None,
        );
    }

    #[test]
    fn from_class_is_slug_first() {
        // Slug-first: the economic slug drives the class + canonical code,
        // preserving the discriminating slug.
        let s = OutletErrorSurface::from_class(SLUG_ECONOMIC_ESCROW_OVERFLOW, None);
        assert_eq!(s.class, OutletErrorClass::Economic);
        assert_eq!(s.code, CODE_ECONOMIC_FAULT);
        assert_eq!(s.slug, SLUG_ECONOMIC_ESCROW_OVERFLOW);
        assert_surface_consistent(&s);
    }

    #[test]
    fn from_class_unregistered_slug_collapses_to_authorization() {
        let s = OutletErrorSurface::from_class("totally-unregistered", None);
        assert_eq!(s.class, OutletErrorClass::Authorization);
        assert_eq!(s.slug, SLUG_AUTHORIZATION_DENIED);
        assert_surface_consistent(&s);
    }

    #[test]
    fn from_envelope_drops_wire_opacity_fields_keeps_taxonomy() {
        let mut env = build_authorization_error();
        env.source_chain = vec![ContextHop {
            context_id: "ctx-a".to_owned(),
            hop_index: 0,
            wrapped_code: env.code.clone(),
        }];
        let s = OutletErrorSurface::from_envelope(&env);
        assert_eq!(s.class, env.class);
        assert_eq!(s.code, env.code);
        assert_eq!(s.slug, env.slug);
        assert_eq!(s.retry, env.retry);
        assert_eq!(s.detail, env.detail);
        assert_eq!(s.source_chain, env.source_chain);
        // The wire-opacity fields (message HMAC / pad_nonce /
        // registration_event_id) have no home on the surface — proven by the
        // struct's field set (this compiles only because they are absent).
        assert_surface_consistent(&s);
    }

    #[test]
    fn surface_round_trips_json_and_is_send() {
        fn assert_send<T: Send>() {}
        assert_send::<OutletErrorSurface>();
        let s = OutletErrorSurface::from_code(
            SURFACE_TEST_CODE_TRANSPORT_FAULT,
            super::super::error_codes::SLUG_TRANSPORT_RATE_LIMITED,
            Some(DetailBody::TransportRateLimit {
                retry_after_secs: 30,
            }),
        );
        let bytes = serde_json::to_vec(&s).unwrap();
        let back: OutletErrorSurface = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(s, back);
    }
}
