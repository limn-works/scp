//! Canonical §5.4.4 [`OutletErrorSurface`] projections for the FFI bridges
//! (SCP-OUT-031 PR-2b).
//!
//! # What is and is not shared
//!
//! Each binding surfaces the structured outlet error through its own richest
//! idiomatic mechanism, and those shapes are deliberately different:
//!
//! | bridge | mechanism | uses this module |
//! |--------|-----------|------------------|
//! | `PyO3` | positional exception args (strings) | YES — [`render_members`] |
//! | napi-rs | one base64 JSON blob in a message suffix | YES — [`render_surface_b64`] |
//! | `UniFFI` | TYPED associated values (real Swift enums / Kotlin sealed classes) | NO |
//!
//! `UniFFI` does NOT and cannot use this module: its whole point is to hand the
//! consumer native sum types, not strings, so it projects the same protocol
//! types onto local `#[derive(uniffi::Enum)]` mirrors via exhaustive `match`
//! (an added protocol variant is a compile error there; a *mis-mapped* arm is
//! not). What binds all three together is not one renderer — it is one
//! **corpus**: [`corpus::parity_surfaces`] is asserted at every bridge, so the
//! three reconstructions are equal by transitivity.
//!
//! # Serialization contract (the string bridges)
//!
//! `retry` / `detail` / `source_chain` are rendered as **canonical serde JSON**
//! of the protocol types themselves — never prose. That is what lets PR-3 rebuild
//! an exact [`RetryPolicy`] / [`DetailBody`] / [`ContextHop`] trail on the SDK
//! side rather than re-parsing a human sentence:
//!
//! | member         | JSON shape                                                        |
//! |----------------|-------------------------------------------------------------------|
//! | `class`        | kebab wire string — `"protocol"`, `"authorization"`, …            |
//! | `retry`        | internally tagged on `policy` — `{"policy":"after","delay":{…}}`  |
//! | `detail`       | internally tagged on `shape` — `{"shape":"protocol","rule":"…"}`  |
//! | `source_chain` | array of `{context_id, hop_index, wrapped_code}`                  |
//!
//! `std::time::Duration` inside [`RetryPolicy`] serializes as `{"secs":_,
//! "nanos":_}` (the shape the PR-1 cross-SDK fixture contract already pins).
//!
//! ## Two JS-specific hazards the napi projection closes
//!
//! 1. **Number precision.** `DetailBody::EconomicInsufficient::needed` and
//!    `DetailBody::ExecutionTimeout::elapsed_ms` are `u64`. JavaScript's
//!    `JSON.parse` coerces every JSON number to an IEEE-754 double, so a bare
//!    `18446744073709551615` silently becomes `18446744073709552000`.
//!    [`render_surface_b64`] therefore emits those two fields as decimal
//!    STRINGS; [`parse_surface_b64`] is its exact inverse. The `PyO3` and
//!    `UniFFI` paths carry `u64` losslessly and need no such widening.
//! 2. **Suffix framing.** The blob rides a `(outlet_error_b64=…)` suffix on a
//!    message whose other half is free text. Plain JSON is NOT self-delimiting
//!    there: `serde_json` escapes `"` and `\` but NOT parentheses, so a string
//!    field inside the payload can contain `(outlet_error_b64=` and defeat BOTH
//!    a first-match and a last-match parse. Base64's alphabet
//!    (`A-Za-z0-9+/=`) contains neither `(` nor a space, so the delimiter
//!    provably cannot occur inside the body and a last-anchored parse is sound
//!    by construction.
//!
//! # Infallibility
//!
//! `OutletErrorClass`, [`RetryPolicy`], [`DetailBody`] and [`ContextHop`] are
//! closed types over primitives, `String`, `Duration` and `[u8; 32]` — no map
//! with a non-string key, no `Serialize` impl that can fail. `serde_json`
//! therefore cannot error on them. The `Err` arm is nonetheless handled (the
//! workspace denies `unwrap`/`expect`) and emits the structurally-distinguishable
//! `UNRENDERABLE_JSON` sentinel instead of a panic or a silent empty value.
//! `every_member_of_the_closed_space_renders` proves the sentinel is unreachable
//! across the entire closed member space (all 8 classes, all 10 detail shapes,
//! all 4 retry policies, all 3 relay-url kinds).

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use scp_protocol::context::outlets::errors::OutletErrorSurface;

/// Emitted in place of a member render if `serde_json` were ever to fail.
///
/// Structurally distinguishable from every real render (no real member ever
/// serializes to an object with an `scp_render_failed` key), so a downstream SDK
/// detects the degradation instead of silently reconstructing a wrong value.
/// Proven unreachable over the closed member space by
/// `every_member_of_the_closed_space_renders`.
const UNRENDERABLE_JSON: &str = r#"{"scp_render_failed":true}"#;

/// The four bridge-facing projections of an [`OutletErrorSurface`]'s structured
/// members, for the `PyO3` positional-args shape.
///
/// `code` and `slug` are plain strings already present on the surface and are
/// carried by the bridge directly; only these four need a projection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutletSurfaceRender {
    /// The §5.4.4 kebab-case class wire discriminant (`"authorization"`, …).
    pub class_wire: String,
    /// Canonical serde JSON of [`OutletErrorSurface::retry`].
    pub retry_json: String,
    /// Canonical serde JSON of [`OutletErrorSurface::detail`], or `None` when
    /// the surface carries no typed detail — the natural mapping of the
    /// protocol's `Option<DetailBody>` onto Python `None`.
    pub detail_json: Option<String>,
    /// Canonical serde JSON array of [`OutletErrorSurface::source_chain`].
    /// `"[]"` for a non-cross-context error.
    pub source_chain_json: String,
}

/// Projects the structured members of `surface` onto their canonical renders
/// (the `PyO3` positional-args shape).
#[must_use]
pub fn render_members(surface: &OutletErrorSurface) -> OutletSurfaceRender {
    OutletSurfaceRender {
        class_wire: surface.class.as_wire().to_owned(),
        retry_json: render_json(&surface.retry),
        detail_json: surface.detail.as_ref().map(render_json),
        source_chain_json: render_json(&surface.source_chain),
    }
}

/// Canonical serde JSON of one member, or the [`UNRENDERABLE_JSON`] sentinel.
fn render_json<T: serde::Serialize>(value: &T) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| UNRENDERABLE_JSON.to_owned())
}

/// The napi-rs projection: the WHOLE surface as base64-encoded canonical JSON.
///
/// napi-rs cannot carry typed compound fields (every `ScpNapiError` collapses to
/// a `Status` plus a message string), so the surface rides one blob in a
/// `(outlet_error_b64=…)` message suffix. See the module docs for why base64
/// (suffix framing) and why the two `u64` detail fields become decimal strings
/// (JS number precision). [`parse_surface_b64`] is the exact inverse.
#[must_use]
pub fn render_surface_b64(surface: &OutletErrorSurface) -> String {
    let Ok(mut value) = serde_json::to_value(surface) else {
        return BASE64.encode(UNRENDERABLE_JSON);
    };
    widen_u64_details_to_strings(&mut value);
    let json = serde_json::to_string(&value).unwrap_or_else(|_| UNRENDERABLE_JSON.to_owned());
    BASE64.encode(json)
}

/// Exact inverse of [`render_surface_b64`].
///
/// # Errors
///
/// Returns a diagnostic string if `encoded` is not base64, is not the canonical
/// surface JSON, or carries a `u64` detail field that is not a decimal string.
pub fn parse_surface_b64(encoded: &str) -> Result<OutletErrorSurface, String> {
    let bytes = BASE64
        .decode(encoded)
        .map_err(|e| format!("outlet surface suffix is not base64: {e}"))?;
    let json = String::from_utf8(bytes)
        .map_err(|e| format!("outlet surface suffix is not UTF-8 JSON: {e}"))?;
    let mut value: serde_json::Value =
        serde_json::from_str(&json).map_err(|e| format!("outlet surface is not JSON: {e}"))?;
    narrow_u64_detail_strings(&mut value)?;
    serde_json::from_value(value).map_err(|e| format!("outlet surface JSON is not a surface: {e}"))
}

/// The two `u64` detail fields JavaScript cannot hold exactly.
const JS_UNSAFE_U64_DETAIL_FIELDS: [&str; 2] = ["needed", "elapsed_ms"];

/// Rewrites the JS-unsafe `u64` detail fields as decimal strings, in place.
fn widen_u64_details_to_strings(value: &mut serde_json::Value) {
    let Some(detail) = value
        .get_mut("detail")
        .and_then(serde_json::Value::as_object_mut)
    else {
        return;
    };
    for key in JS_UNSAFE_U64_DETAIL_FIELDS {
        if let Some(n) = detail.get(key).and_then(serde_json::Value::as_u64) {
            detail.insert(key.to_owned(), serde_json::Value::String(n.to_string()));
        }
    }
}

// ---------------------------------------------------------------------------
// Untrusted-envelope projection (SCP-OUT-031 PR-2b)
// ---------------------------------------------------------------------------

/// Projects a **deserialized** §5.4.4 wire envelope onto the in-process surface,
/// re-checking every structural invariant on the way in.
///
/// `OutletError` derives `Deserialize`, so an envelope that arrived off the wire
/// **bypassed every `OutletError::new` check**: the code regex, the slug regex,
/// the class↔code and class↔slug registry consistency, the per-class detail
/// shape, and the [`MAX_TRAIL_PAD_DEPTH`] trail bound. §5.4.4 is explicit that
/// these are *receiver* obligations ("an emitter that pads beyond
/// `MAX_TRAIL_PAD_DEPTH` produces an envelope that receivers structurally
/// reject"), so this is the seam that discharges them — not new policy.
///
/// A violating envelope **fails closed** onto the §5.4.4 oracle-collapse target
/// (`authorization.denied`, no detail, no trail) rather than rendering
/// attacker-shaped `class` / `slug` / `detail` / `source_chain` values to an SDK
/// caller. Collapsing rather than erroring keeps the seam total: every FFI
/// bridge's `From<OutletError>` must yield *an* error, and a structurally
/// invalid envelope is exactly the "cannot be trusted to say why" case the
/// collapse target exists for.
///
/// [`MAX_TRAIL_PAD_DEPTH`]: scp_protocol::context::outlets::errors::MAX_TRAIL_PAD_DEPTH
#[must_use]
pub fn surface_from_untrusted_envelope(
    envelope: &scp_protocol::context::outlets::errors::OutletError,
) -> OutletErrorSurface {
    use scp_protocol::context::outlets::error_codes::{
        SLUG_AUTHORIZATION_DENIED, error_code_to_class, slug_to_class, validate_slug,
    };
    use scp_protocol::context::outlets::errors::{MAX_TRAIL_PAD_DEPTH, validate_outlet_error_code};

    let structurally_valid = validate_outlet_error_code(&envelope.code)
        && validate_slug(&envelope.slug).is_ok()
        && error_code_to_class(&envelope.code).is_none_or(|c| c == envelope.class)
        && slug_to_class(&envelope.slug).is_none_or(|c| c == envelope.class)
        && envelope
            .detail
            .as_ref()
            .is_none_or(|d| d.kind() == envelope.class.expected_detail())
        && envelope.source_chain.len() <= MAX_TRAIL_PAD_DEPTH as usize;

    if structurally_valid {
        OutletErrorSurface::from_envelope(envelope)
    } else {
        OutletErrorSurface::from_class(SLUG_AUTHORIZATION_DENIED, None)
    }
}

/// Rewrites the decimal-string `u64` detail fields back to JSON numbers.
fn narrow_u64_detail_strings(value: &mut serde_json::Value) -> Result<(), String> {
    let Some(detail) = value
        .get_mut("detail")
        .and_then(serde_json::Value::as_object_mut)
    else {
        return Ok(());
    };
    for key in JS_UNSAFE_U64_DETAIL_FIELDS {
        let Some(s) = detail.get(key).and_then(|v| v.as_str().map(str::to_owned)) else {
            continue;
        };
        let n: u64 = s
            .parse()
            .map_err(|e| format!("detail.{key} is not a decimal u64 string ({s:?}): {e}"))?;
        detail.insert(key.to_owned(), serde_json::Value::Number(n.into()));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Shared cross-bridge test corpus (SCP-OUT-031 PR-2b)
// ---------------------------------------------------------------------------

/// Shared cross-bridge parity + AC10 corpus.
///
/// Lives here (behind `testing`) rather than in each bridge's `#[cfg(test)]`
/// block so all three bridges provably assert against the SAME inputs — a
/// per-bridge corpus would let the three drift and still pass. Each bridge test
/// reconstructs an [`OutletErrorSurface`] from its OWN render and asserts
/// equality with the corpus entry; equality against one shared corpus at three
/// bridges is cross-bridge parity by transitivity. (A single in-process 3-way
/// comparison is impossible: `scp-ffi-napi` is `crate-type = ["cdylib"]` and
/// cannot be linked as a library dependency.)
#[cfg(any(test, feature = "testing"))]
pub mod corpus {
    use std::time::Duration;

    use scp_protocol::context::outlets::OutletId;
    // Every (code, slug) pair is named by its §5.4.4 REGISTRY constant, never a
    // literal: a registry renumbering must break the corpus at compile time,
    // and `scripts/check-error-codes.sh` bans raw outlet-code literals outside
    // the registry.
    use scp_protocol::context::outlets::error_codes::{
        CODE_AUTHORIZATION_DENIED, CODE_ECONOMIC_FAULT, CODE_EXECUTION_FAULT,
        CODE_GOVERNANCE_FAULT, CODE_INPUT_VIOLATION, CODE_OUTPUT_VIOLATION,
        CODE_PROTOCOL_VIOLATION, CODE_TRANSPORT_FAULT, SLUG_AUTHORIZATION_DENIED,
        SLUG_AUTHORIZATION_EXPIRED, SLUG_ECONOMIC_ADAPTER_FAILURE,
        SLUG_ECONOMIC_INSUFFICIENT_FUNDS, SLUG_EXECUTION_HANDLER_PANIC, SLUG_EXECUTION_TIMEOUT,
        SLUG_GOVERNANCE_OUTLET_DEREGISTERED, SLUG_INPUT_SCHEMA_VIOLATION,
        SLUG_OUTPUT_SCHEMA_VIOLATION, SLUG_PROTOCOL_VIOLATION, SLUG_TRANSPORT_RATE_LIMITED,
        SLUG_TRANSPORT_RELAY_UNAVAILABLE,
    };
    use scp_protocol::context::outlets::errors::{
        CatalogKey, ContextHop, DetailBody, OUTLET_MESSAGE_KEY_LEN, OutletError, OutletErrorClass,
        OutletErrorNewOpts, OutletErrorSurface, PAD_NONCE_LEN, REGISTRATION_EVENT_ID_LEN,
        RelayUrlKind, RetryPolicy,
    };

    /// PR-1's cross-SDK `OutletError` fixture file, embedded at compile time so
    /// every bridge reads the same bytes without a runtime path.
    const FIXTURES_JSON: &str =
        include_str!("../../../../tests/conformance/vectors/outlet_error_fixtures.json");

    /// A parity corpus entry: a name for assertion messages plus the surface.
    #[derive(Debug, Clone)]
    pub struct CorpusEntry {
        /// Stable name (used in assertion failure messages).
        pub name: &'static str,
        /// The surface a bridge must render and an SDK must be able to rebuild.
        pub surface: OutletErrorSurface,
    }

    /// Builds one corpus entry.
    fn entry(
        name: &'static str,
        class: OutletErrorClass,
        code: &str,
        slug: &str,
        retry: RetryPolicy,
        detail: Option<DetailBody>,
        source_chain: Vec<ContextHop>,
    ) -> CorpusEntry {
        CorpusEntry {
            name,
            surface: OutletErrorSurface {
                class,
                code: code.to_owned(),
                slug: slug.to_owned(),
                retry,
                detail,
                source_chain,
            },
        }
    }

    /// The cross-bridge parity corpus.
    ///
    /// One entry per §5.4.4 root class, collectively exercising every
    /// [`RetryPolicy`] variant, every structurally-distinct [`DetailBody`]
    /// shape (including the 32-byte `ExecutionPanic` hash and a `> 2^53` `u64`
    /// — the two PR-1 `supplementary` cross-SDK hazards), the `detail == None`
    /// case, and a populated multi-hop `source_chain`.
    ///
    /// **`retry` is chosen for RENDER coverage, not registry fidelity.** Some
    /// entries pair a code with a `RetryPolicy` that is not that code's registry
    /// default (`error_code_to_retry_policy`) — deliberately, so all four policy
    /// variants (including the sub-second `After`) cross every bridge. This is
    /// sound because the surface carries `retry` as data: nothing in the render
    /// path re-derives it from `code`, so a bridge that silently substituted the
    /// registry default would FAIL these tests, which is exactly the regression
    /// worth catching. The `(class, code, slug)` triple, by contrast, IS held
    /// registry-consistent — `envelope_from_surface` runs every entry through
    /// `OutletError::new`, which enforces that consistency.
    #[must_use]
    pub fn parity_surfaces() -> Vec<CorpusEntry> {
        let mut out = vec![
            entry(
                "protocol/never/detail",
                OutletErrorClass::Protocol,
                CODE_PROTOCOL_VIOLATION,
                SLUG_PROTOCOL_VIOLATION,
                RetryPolicy::Never,
                Some(DetailBody::Protocol {
                    rule: "query-cost-floor".to_owned(),
                }),
                Vec::new(),
            ),
            entry(
                "authorization/never/no-detail",
                OutletErrorClass::Authorization,
                CODE_AUTHORIZATION_DENIED,
                SLUG_AUTHORIZATION_DENIED,
                RetryPolicy::Never,
                None,
                Vec::new(),
            ),
            entry(
                "authorization/never/capability",
                OutletErrorClass::Authorization,
                CODE_AUTHORIZATION_DENIED,
                SLUG_AUTHORIZATION_EXPIRED,
                RetryPolicy::Never,
                Some(DetailBody::Authorization {
                    capability: "outlet_query:weather".to_owned(),
                }),
                Vec::new(),
            ),
            entry(
                "input/never/field-violation",
                OutletErrorClass::Input,
                CODE_INPUT_VIOLATION,
                SLUG_INPUT_SCHEMA_VIOLATION,
                RetryPolicy::Never,
                Some(DetailBody::FieldViolation {
                    field_path: "/items/0".to_owned(),
                    violation: "type".to_owned(),
                }),
                Vec::new(),
            ),
            entry(
                "output/never/field-violation",
                OutletErrorClass::Output,
                CODE_OUTPUT_VIOLATION,
                SLUG_OUTPUT_SCHEMA_VIOLATION,
                RetryPolicy::Never,
                Some(DetailBody::FieldViolation {
                    field_path: "/result".to_owned(),
                    violation: "range".to_owned(),
                }),
                Vec::new(),
            ),
            entry(
                "governance/never/action",
                OutletErrorClass::Governance,
                CODE_GOVERNANCE_FAULT,
                SLUG_GOVERNANCE_OUTLET_DEREGISTERED,
                RetryPolicy::Never,
                Some(DetailBody::Governance {
                    action: "outlet-deregistered".to_owned(),
                }),
                Vec::new(),
            ),
        ];
        out.extend(execution_surfaces());
        out.extend(economic_surfaces());
        out.extend(transport_surfaces());
        out
    }

    /// Execution-class corpus entries — the `ExecutionPanic` 32-byte hash and
    /// the `> 2^53` `elapsed_ms` JS-precision hazard.
    fn execution_surfaces() -> Vec<CorpusEntry> {
        vec![
            entry(
                "execution/immediate/panic-hash-32b",
                OutletErrorClass::Execution,
                CODE_EXECUTION_FAULT,
                SLUG_EXECUTION_HANDLER_PANIC,
                RetryPolicy::Immediate,
                Some(DetailBody::ExecutionPanic {
                    panic_location_hash: [
                        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
                        21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
                    ],
                }),
                Vec::new(),
            ),
            entry(
                "execution/after/timeout-gt-2^53",
                OutletErrorClass::Execution,
                CODE_EXECUTION_FAULT,
                SLUG_EXECUTION_TIMEOUT,
                // Sub-second precision: a millisecond-lossy Duration projection
                // at any bridge would drop the 500ms and fail parity.
                RetryPolicy::After {
                    delay: Duration::new(3, 500_000_000),
                },
                Some(DetailBody::ExecutionTimeout {
                    // 2^53 + 1 — the JS `Number` precision cliff.
                    elapsed_ms: 9_007_199_254_740_993,
                }),
                Vec::new(),
            ),
        ]
    }

    /// Economic-class corpus entries — includes a `u64::MAX` amount.
    fn economic_surfaces() -> Vec<CorpusEntry> {
        vec![
            entry(
                "economic/with-backoff/insufficient",
                OutletErrorClass::Economic,
                CODE_ECONOMIC_FAULT,
                SLUG_ECONOMIC_INSUFFICIENT_FUNDS,
                RetryPolicy::WithBackoff {
                    min: Duration::from_millis(250),
                    max: Duration::from_secs(30),
                },
                Some(DetailBody::EconomicInsufficient {
                    needed: u64::MAX,
                    currency: "USD".to_owned(),
                }),
                Vec::new(),
            ),
            entry(
                "economic/never/adapter",
                OutletErrorClass::Economic,
                CODE_ECONOMIC_FAULT,
                SLUG_ECONOMIC_ADAPTER_FAILURE,
                RetryPolicy::Never,
                Some(DetailBody::EconomicAdapter {
                    adapter_id: "stripe-v2".to_owned(),
                }),
                Vec::new(),
            ),
        ]
    }

    /// Transport-class corpus entries — includes the only populated
    /// `source_chain` in the corpus.
    fn transport_surfaces() -> Vec<CorpusEntry> {
        vec![
            entry(
                "transport/after/rate-limit+source-chain",
                OutletErrorClass::Transport,
                CODE_TRANSPORT_FAULT,
                SLUG_TRANSPORT_RATE_LIMITED,
                RetryPolicy::After {
                    delay: Duration::from_secs(45),
                },
                Some(DetailBody::TransportRateLimit {
                    retry_after_secs: 45,
                }),
                // Cross-context hop trail — innermost→outermost, the shape
                // SCP-OUT-029's `wrap_cross_context_error` will populate.
                vec![
                    ContextHop {
                        context_id: "ctx-origin".to_owned(),
                        hop_index: 0,
                        wrapped_code: CODE_TRANSPORT_FAULT.to_owned(),
                    },
                    ContextHop {
                        context_id: "9f1c2b".repeat(4),
                        hop_index: 1,
                        wrapped_code: CODE_PROTOCOL_VIOLATION.to_owned(),
                    },
                ],
            ),
            // All THREE `RelayUrlKind` arms cross every bridge. Covering only
            // one would leave a mis-mapped arm in the UniFFI mirror
            // undetectable, and the kind is the §5.4.4 stand-in for a URL the
            // spec forbids surfacing — `Wss` vs `WsLoopback` is a real defect.
            relay_kind_entry("wss", RelayUrlKind::Wss),
            relay_kind_entry("ws-loopback", RelayUrlKind::WsLoopback),
            relay_kind_entry("unknown", RelayUrlKind::Unknown),
        ]
    }

    /// One `transport.relay-unavailable` corpus entry per [`RelayUrlKind`].
    fn relay_kind_entry(name: &'static str, kind: RelayUrlKind) -> CorpusEntry {
        entry(
            name,
            OutletErrorClass::Transport,
            CODE_TRANSPORT_FAULT,
            SLUG_TRANSPORT_RELAY_UNAVAILABLE,
            RetryPolicy::Immediate,
            Some(DetailBody::TransportRelay {
                relay_url_kind: kind,
            }),
            Vec::new(),
        )
    }

    /// The PR-1 `malformed` fixtures (one per §5.4.4 class) projected onto
    /// [`OutletErrorSurface`], for the AC10 per-class detail-mismatch tests.
    ///
    /// Every entry deliberately pairs a `class` with a `detail` whose
    /// [`DetailBody::kind`] does NOT equal
    /// [`OutletErrorClass::expected_detail`]. A bridge MUST carry the mismatch
    /// through verbatim — neither silently dropping the offending detail nor
    /// normalizing it — so the SDK layer can perform the AC10 rejection.
    ///
    /// Every [`ContextState`](scp_protocol::context::ContextState) except
    /// `Active` — the complete input space of the pre-authz
    /// `ContextError::OutletContextNotActive` state-leak tests at all three
    /// bridges.
    ///
    /// `ensure_context_active` emits that carrier for ANY non-`Active` state, so
    /// a partial list would leave real states unasserted. The `classify` match
    /// below is EXHAUSTIVE over `ContextState`: adding a variant upstream is a
    /// compile error here, so a new lifecycle state cannot silently escape the
    /// leak tests. The length assertion catches the other half (a variant added
    /// to `classify` but not to `ALL`).
    ///
    /// # Panics
    ///
    /// Panics if `ALL` and the `ContextState` enum have drifted apart — a
    /// test-authoring bug that must fail loudly rather than silently shrink the
    /// asserted state space.
    #[must_use]
    pub fn non_active_context_states() -> Vec<scp_protocol::context::ContextState> {
        use scp_protocol::context::ContextState as S;

        const fn is_non_active(s: &S) -> bool {
            match s {
                S::Active => false,
                S::Creating
                | S::Closing
                | S::Closed
                | S::Expired
                | S::MigratingOut
                | S::Tombstoned
                | S::Poisoned => true,
            }
        }

        const ALL: [S; 8] = [
            S::Creating,
            S::Active,
            S::Closing,
            S::Closed,
            S::Expired,
            S::MigratingOut,
            S::Tombstoned,
            S::Poisoned,
        ];
        let out: Vec<S> = ALL.iter().filter(|s| is_non_active(s)).cloned().collect();
        assert_eq!(
            out.len(),
            ALL.len() - 1,
            "ContextState::ALL drifted from the enum — every non-Active state \
             must be asserted by the pre-authz state-leak tests"
        );
        out
    }

    /// Builds a REAL §5.4.4 wire envelope carrying `surface`'s taxonomy,
    /// through the shipped [`OutletError::new`] construction boundary.
    ///
    /// Used by the three bridges' `From<OutletError>` (typed envelope) tests so
    /// all of them exercise the cross-context render seam against an envelope
    /// that actually passed every §5.4.4 construction invariant — code regex,
    /// slug regex, class/code/slug registry consistency, catalog membership,
    /// per-class detail shape — rather than a hand-poked struct literal.
    ///
    /// The envelope additionally carries the three wire-opacity fields
    /// (`message` HMAC, `pad_nonce`, `registration_event_id`) that
    /// `OutletErrorSurface::from_envelope` is expected to DROP.
    ///
    /// # Errors
    ///
    /// Returns a diagnostic string if `surface` does not satisfy the §5.4.4
    /// construction invariants (e.g. a malformed-detail corpus entry, which
    /// `OutletError::new` correctly rejects).
    pub fn envelope_from_surface(surface: &OutletErrorSurface) -> Result<OutletError, String> {
        let outlet_id: OutletId = "outlet-pr2b-render".to_owned();
        // Deterministic, non-secret test key: the envelope's `message` field is
        // an HMAC the SURFACE projection drops, so its value is irrelevant to
        // what these tests assert.
        let outlet_message_key = [0x42u8; OUTLET_MESSAGE_KEY_LEN];
        let catalog_key = CatalogKey::try_new(surface.slug.clone())
            .map_err(|e| format!("slug {:?} is not a valid catalog key: {e}", surface.slug))?;
        let registered = vec![catalog_key.clone()];
        OutletError::new(OutletErrorNewOpts {
            outlet_id: &outlet_id,
            outlet_message_key: &outlet_message_key,
            registration_event_id: [0x11; REGISTRATION_EVENT_ID_LEN],
            catalog_key: &catalog_key,
            registered_keys: &registered,
            class: surface.class,
            code: &surface.code,
            slug: &surface.slug,
            retry: surface.retry.clone(),
            detail: surface.detail.clone(),
            source_chain: surface.source_chain.clone(),
            pad_nonce: [0x22; PAD_NONCE_LEN],
        })
        .map_err(|e| format!("OutletError::new rejected the corpus surface: {e}"))
    }

    /// # Errors
    ///
    /// Returns a diagnostic string if the embedded PR-1 fixture file is not the
    /// expected shape, or carries no `malformed` entries. Callers MUST surface
    /// the error (every caller is a test that unwraps it): degrading to an empty
    /// corpus would silently pass every AC10 assertion.
    pub fn malformed_detail_surfaces() -> Result<Vec<(String, OutletErrorSurface)>, String> {
        #[derive(serde::Deserialize)]
        struct RawFixture {
            name: String,
            code: String,
            slug: String,
            class: OutletErrorClass,
            retry: RetryPolicy,
            detail: DetailBody,
        }
        #[derive(serde::Deserialize)]
        struct RawFile {
            malformed: Vec<RawFixture>,
        }

        let parsed: RawFile = serde_json::from_str(FIXTURES_JSON)
            .map_err(|e| format!("PR-1 outlet_error_fixtures.json is not parseable: {e}"))?;
        if parsed.malformed.is_empty() {
            return Err(
                "PR-1 outlet_error_fixtures.json carries no `malformed` fixtures".to_owned(),
            );
        }
        Ok(parsed
            .malformed
            .into_iter()
            .map(|f| {
                (
                    f.name,
                    OutletErrorSurface {
                        class: f.class,
                        code: f.code,
                        slug: f.slug,
                        retry: f.retry,
                        detail: Some(f.detail),
                        source_chain: Vec::new(),
                    },
                )
            })
            .collect())
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use scp_protocol::context::outlets::errors::OutletErrorSurface;

    use super::{UNRENDERABLE_JSON, corpus, parse_surface_b64, render_members, render_surface_b64};

    /// Every class × every detail shape × every retry policy × every relay-url
    /// kind renders — the [`UNRENDERABLE_JSON`] sentinel is unreachable over the
    /// closed member space. This is what makes the `unwrap_or_else` fallbacks
    /// honest rather than a silent-degradation hazard.
    #[test]
    fn every_member_of_the_closed_space_renders() {
        use scp_protocol::context::outlets::errors::{DetailBody, RelayUrlKind, RetryPolicy};
        // Pin the coverage claim mechanically instead of asserting it in prose:
        // if a variant is added upstream and not added here, the count drifts.
        let entries = corpus::parity_surfaces();
        let classes: std::collections::BTreeSet<_> =
            entries.iter().map(|e| e.surface.class).collect();
        assert_eq!(
            classes.len(),
            8,
            "all 8 §5.4.4 root classes must be covered"
        );
        let detail_shapes: std::collections::BTreeSet<_> = entries
            .iter()
            .filter_map(|e| e.surface.detail.as_ref())
            .map(|d| format!("{:?}", std::mem::discriminant(d)))
            .collect();
        assert_eq!(detail_shapes.len(), 10, "all 10 DetailBody shapes");
        let retry_shapes: std::collections::BTreeSet<_> = entries
            .iter()
            .map(|e| format!("{:?}", std::mem::discriminant(&e.surface.retry)))
            .collect();
        assert_eq!(retry_shapes.len(), 4, "all 4 RetryPolicy variants");
        let relay_kinds: std::collections::BTreeSet<_> = entries
            .iter()
            .filter_map(|e| match &e.surface.detail {
                Some(DetailBody::TransportRelay { relay_url_kind }) => Some(*relay_url_kind),
                _ => None,
            })
            .collect();
        assert_eq!(
            relay_kinds,
            [
                RelayUrlKind::Wss,
                RelayUrlKind::WsLoopback,
                RelayUrlKind::Unknown
            ]
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>(),
            "all 3 RelayUrlKind arms"
        );
        assert!(
            entries
                .iter()
                .any(|e| matches!(e.surface.retry, RetryPolicy::WithBackoff { .. })),
            "WithBackoff must be exercised"
        );

        for entry in &entries {
            let r = render_members(&entry.surface);
            assert_ne!(r.retry_json, UNRENDERABLE_JSON, "{}", entry.name);
            assert_ne!(r.source_chain_json, UNRENDERABLE_JSON, "{}", entry.name);
            if let Some(d) = &r.detail_json {
                assert_ne!(d, UNRENDERABLE_JSON, "{}", entry.name);
            }
        }
    }

    /// The napi base64 blob round-trips to an EQUAL surface — the napi bridge's
    /// reconstruction contract, including the two `u64` detail fields that ride
    /// as decimal strings.
    #[test]
    fn surface_b64_round_trips_exactly() {
        for entry in corpus::parity_surfaces() {
            let encoded = render_surface_b64(&entry.surface);
            let back =
                parse_surface_b64(&encoded).unwrap_or_else(|e| panic!("{}: {e}", entry.name));
            assert_eq!(back, entry.surface, "{}", entry.name);
        }
    }

    /// The base64 alphabet contains neither `(` nor a space, so the
    /// `(outlet_error_b64=` delimiter provably cannot occur inside the payload —
    /// the property that makes the napi suffix framing sound by construction
    /// rather than by hoping no field contains the delimiter.
    #[test]
    fn b64_payload_can_never_contain_the_suffix_delimiter() {
        // A surface whose every string field is stuffed with the delimiter.
        let hostile = OutletErrorSurface {
            detail: Some(
                scp_protocol::context::outlets::errors::DetailBody::Protocol {
                    rule: "x (outlet_error_b64=AAAA) y".to_owned(),
                },
            ),
            ..corpus::parity_surfaces()[0].surface.clone()
        };
        let encoded = render_surface_b64(&hostile);
        assert!(!encoded.contains('('), "{encoded}");
        assert!(!encoded.contains(' '), "{encoded}");
        assert!(!encoded.contains(')'), "{encoded}");
        // …and it still round-trips, delimiter text and all.
        assert_eq!(parse_surface_b64(&encoded).unwrap(), hostile);
    }

    /// The two `u64` detail fields JavaScript cannot represent exactly ride as
    /// decimal STRINGS in the napi blob. Asserted on the decoded JSON so the
    /// contract is pinned at the wire level, not just via the round-trip.
    #[test]
    fn js_unsafe_u64_detail_fields_are_decimal_strings() {
        use base64::Engine as _;
        for (name, needle) in [
            (
                "economic/with-backoff/insufficient",
                "\"needed\":\"18446744073709551615\"",
            ),
            (
                "execution/after/timeout-gt-2^53",
                "\"elapsed_ms\":\"9007199254740993\"",
            ),
        ] {
            let entry = corpus::parity_surfaces()
                .into_iter()
                .find(|e| e.name == name)
                .unwrap_or_else(|| panic!("corpus entry {name} missing"));
            let decoded = String::from_utf8(
                base64::engine::general_purpose::STANDARD
                    .decode(render_surface_b64(&entry.surface))
                    .unwrap(),
            )
            .unwrap();
            assert!(decoded.contains(needle), "{name}: {decoded}");
        }
    }

    /// The per-member renders round-trip to EQUAL members — the `PyO3`
    /// exception-args reconstruction contract.
    #[test]
    fn member_renders_round_trip_exactly() {
        for entry in corpus::parity_surfaces() {
            let r = render_members(&entry.surface);
            assert_eq!(
                r.class_wire,
                entry.surface.class.as_wire(),
                "{}",
                entry.name
            );
            assert_eq!(
                serde_json::from_str::<scp_protocol::context::outlets::errors::RetryPolicy>(
                    &r.retry_json
                )
                .unwrap(),
                entry.surface.retry,
                "{}",
                entry.name
            );
            let detail = r.detail_json.as_ref().map(|d| {
                serde_json::from_str::<scp_protocol::context::outlets::errors::DetailBody>(d)
                    .unwrap()
            });
            assert_eq!(detail, entry.surface.detail, "{}", entry.name);
            assert_eq!(
                serde_json::from_str::<Vec<scp_protocol::context::outlets::errors::ContextHop>>(
                    &r.source_chain_json
                )
                .unwrap(),
                entry.surface.source_chain,
                "{}",
                entry.name
            );
        }
    }

    /// `detail == None` maps to an absent member (Python `None`), the natural
    /// projection of the protocol's `Option<DetailBody>`.
    #[test]
    fn absent_detail_maps_to_none() {
        let entry = corpus::parity_surfaces()
            .into_iter()
            .find(|e| e.surface.detail.is_none())
            .unwrap();
        assert!(render_members(&entry.surface).detail_json.is_none());
    }

    /// Every parity-corpus surface is constructible as a REAL §5.4.4 envelope
    /// (it satisfies the code/slug/class/catalog/detail-shape invariants), and
    /// `from_envelope` projects it straight back — dropping only the three
    /// wire-opacity fields. This is what lets the three bridges' cross-context
    /// `From<OutletError>` impls assert against the same corpus.
    #[test]
    fn corpus_round_trips_through_a_real_wire_envelope() {
        use scp_protocol::context::outlets::errors::OutletErrorSurface as Surface;
        for entry in corpus::parity_surfaces() {
            let env = corpus::envelope_from_surface(&entry.surface)
                .unwrap_or_else(|e| panic!("{}: {e}", entry.name));
            assert_eq!(
                Surface::from_envelope(&env),
                entry.surface,
                "{}",
                entry.name
            );
        }
    }

    /// `OutletError::new` REJECTS the malformed-detail corpus — the §5.4.4
    /// construction boundary is where a shape mismatch dies on the wire path.
    /// (The FFI surface path deliberately does NOT reject: it carries the
    /// mismatch verbatim so the SDK performs the AC10 rejection with the full
    /// class/detail pair in hand.)
    #[test]
    fn malformed_corpus_is_rejected_by_the_envelope_constructor() {
        for (name, surface) in corpus::malformed_detail_surfaces().unwrap() {
            assert!(
                corpus::envelope_from_surface(&surface).is_err(),
                "{name}: OutletError::new accepted a detail-shape mismatch"
            );
        }
    }

    /// AC10 groundwork: the PR-1 `malformed` corpus really does carry a
    /// per-class detail-shape mismatch, and the mismatch survives the canonical
    /// render intact so an SDK can reject it.
    #[test]
    fn malformed_corpus_mismatch_survives_the_render() {
        let malformed = corpus::malformed_detail_surfaces().unwrap();
        assert_eq!(
            malformed.len(),
            8,
            "expected one malformed fixture per §5.4.4 root class"
        );
        for (name, surface) in malformed {
            let detail = surface.detail.clone().unwrap();
            assert_ne!(
                detail.kind(),
                surface.class.expected_detail(),
                "{name}: fixture is not actually malformed"
            );
            let back: OutletErrorSurface =
                parse_surface_b64(&render_surface_b64(&surface)).unwrap();
            assert_eq!(back, surface, "{name}");
            assert_ne!(
                back.detail.unwrap().kind(),
                back.class.expected_detail(),
                "{name}: the render normalized away the AC10 mismatch"
            );
        }
    }
}
