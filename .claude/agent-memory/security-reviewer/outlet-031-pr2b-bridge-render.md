---
name: outlet-031-pr2b-bridge-render
description: SCP-OUT-031 PR-2b (FFI bridges render full §5.4.4 OutletErrorSurface) — info-disclosure audit findings, incl. the napi (outlet_error=…) suffix framing defect
metadata:
  type: project
---

# SCP-OUT-031 PR-2b — §5.4.4 structured outlet-error render at all 3 FFI bridges

Audited 2026-08 on `feat/outlet-031-pr2b-bridge-render` (uncommitted, base d1ebc5ab9).
Files: `crates/scp-ffi/common/src/outlet_error.rs` (new, shared render),
`crates/scp-ffi/src/error.rs` (PyO3), `crates/scp-ffi/napi/src/error.rs`,
`crates/scp-ffi/uniffi/src/bridge.rs`.

## What is NEWLY exposed vs. PR-2a

PR-2a's `ContextError::Outlet` `Display` was already `[{code}] {class}: {slug}` — so
**code, class and slug were already caller-visible**. PR-2b newly exposes only
**`retry`, `detail`, `source_chain`** in machine-readable form.

- `retry` and `class` are *derived from `code`* inside `OutletErrorSurface::from_code`
  (`error_code_to_class` / `error_code_to_retry_policy`) ⇒ **zero new information**
  for any in-process surface. No production code builds a surface by struct literal;
  every producer goes through `from_code` / `from_class` / `from_envelope`.
- `source_chain` is **always empty in-process** — `wrap_cross_context_error`
  (SCP-OUT-029) does not exist anywhere in the tree.
- `detail` is the only genuinely new channel. The §5.4.4 query-oracle collapse holds:
  `InvocationError::{InvokerNotAuthorized, OutletNotFound}` both →
  `from_class(SLUG_AUTHORIZATION_DENIED, None)` (invoke.rs ~3269) — identical, no detail.
  Grep confirms **no production producer** of `DetailBody::Authorization{capability}`,
  `EconomicInsufficient{needed}`, `EconomicAdapter`, `TransportRelay`, `Protocol`,
  `Governance`. Only FieldViolation (schema.rs), TransportRateLimit (outlets/mod.rs:581),
  ExecutionTimeout + ExecutionPanic (invoke.rs).

## Findings

1. **HIGH — napi `(outlet_error={json})` suffix framing is NOT self-delimiting.**
   `#[error("[{code}] outlet error: {message} (outlet_error={surface_json})")]`.
   The code claims END-anchoring makes decoys lose. FALSE: the decoy can live inside
   the *JSON payload's own string fields* (slug / detail.rule / adapter_id /
   context_id …), so it is the LAST occurrence. Both parsers break:
   - TS test regex `/\(outlet_error=(\{.*\})\)\s*$/` (leftmost-open + greedy) → garbage
   - Rust helper `rfind(" (outlet_error=")` → garbage
   Verified experimentally. Full spoof appears blocked by JSON `"`→`\"` escaping
   (a valid `OutletErrorSurface` needs unescaped quotes), so it is a denial-of-parse,
   not a forge. Reachable only via the not-yet-existing wire decoder, but it is the
   framing PR-3 will build on. **Fix: base64 the blob** (alphabet has no `(`/space,
   so ` (outlet_error=` can never occur inside it) + parse last-occurrence.
   Contrast: existing `(retry_after_ms=null|\d+)` / `(contended_context=<ctxid>)`
   suffixes are safe *by accident* — their bodies can't contain `)`.

2. **MEDIUM — `From<OutletError>` (wire envelope) renders a foreign envelope verbatim,
   validating nothing.** `OutletError`'s derived `Deserialize` bypasses
   `OutletError::new`'s invariants (code regex, slug regex, class/code/slug registry
   consistency, per-class detail shape). `from_envelope` copies verbatim; the bridges
   render verbatim. No `MAX_TRAIL_PAD_DEPTH` (=16) bound enforced on `source_chain`,
   no control-char scrub. This render seam is the untrusted-wire→SDK trust boundary.

3. **MEDIUM — `ContextHop.context_id` pseudonymization is doc-only.**
   Documented as `HMAC-SHA-256(hop_salt, raw_context_id)` "at wrap time"; the wrapper
   is unimplemented and nothing at the render seam enforces the shape. A foreign or
   future chain can carry a raw context id straight to the SDK.

4. **MEDIUM — `ExecutionPanic.panic_location_hash` is unsalted SHA-256(outlet_id)**
   (invoke.rs ~3314). Newly reachable by the SDK (PR-2a dropped `detail`). Offline
   name-confirmation oracle for outlet ids across a cross-context hop. The spec's own
   rationale rejects unsalted hashes of dynamic values as "a weak confirmation oracle."
   Fix: HMAC under the per-registration `outlet_message_key`, or the envelope `pad_nonce`.

5. **LOW — state-free test matrix incomplete.** All three bridges loop over
   `[Closing, Expired, MigratingOut, Tombstoned, Poisoned]`; `ContextState` has 7
   non-`Active` variants — **`Creating` and `Closed` are missing**.

## Verified CLEAN

- **`OutletContextNotActive` state-freedom is BY CONSTRUCTION at all 3 bridges**:
  `CE::OutletContextNotActive { .. }` mechanically discards the field; the surface is
  `from_code(CODE_PROTOCOL_SESSION, SLUG_PROTOCOL_CONTEXT_CLOSED_MID_STREAM, None)`
  (two constants); `ContextError`'s `Display` for that arm renders only those two
  constants. Nothing reads `current_state`.
- **§5.4.4 "never a raw URL"** preserved: `RelayUrlKind` stays an enum through the
  UniFFI mirror, the PyO3 JSON arg and the napi JSON blob.
- **Wire-opacity fields dropped**: `from_envelope` drops the `message` HMAC,
  `pad_nonce`, `registration_event_id`.
- Enforcement files only EXPANDED (6 new uniffi getter allowlist entries with reasons;
  new capability-matrix row `error_taxonomy_sealed_hierarchy` honestly all-`false` +
  per-SDK exemptions). No weakening.
- `corpus` (incl. the `[0x42; 32]` test HMAC key) is `#[cfg(any(test, feature="testing"))]`;
  no new feature edge added to any bridge Cargo.toml.

## Gotchas

- `cargo test -p scp-ffi-common --features testing,custody` fails to COMPILE on
  `tests/dht_capability_injection.rs` (E0599 on `DidPublisher::with_client*`) —
  pre-existing, unrelated to this diff. Use `--lib` to run the render tests (7 pass).
- Python SDK already maps the new bridge exception name: `BRIDGE_ERROR_MAP["OutletError"]`
  and `CODE_PREFIX_MAP["SCP-OUTLET"]` both exist ⇒ no fail-open. But PyO3 outlet errors
  moved from the `ContextError` Python class to the new `OutletError` class, and UniFFI
  added a new `ScpError::OutletSurface` variant — both are source-breaking for callers
  matching the old shapes.
