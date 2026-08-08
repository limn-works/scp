---
name: outlet031-pr2b-bridge-render
description: API review of SCP-OUT-031 PR-2b (three FFI bridges render the §5.4.4 outlet-error taxonomy) — NEEDS REVISION; blockers are the Outlet/OutletSurface two-arm split, 7 positional PyO3 args, and Arc-Object-for-lint
metadata:
  type: project
---

SCP-OUT-031 PR-2b review (branch `feat/outlet-031-pr2b-bridge-render`, off origin/main d1ebc5ab9), reviewed 2026-08-08. Verdict NEEDS REVISION.

**Why:** PR-3 builds four SDK sealed error hierarchies on top of this bridge surface. Anything ambiguous here forks four ways.

Blocking findings (all traced to file:line in the review):
1. `ScpError::Outlet` (unstructured) and `ScpError::OutletSurface` (structured) coexist on the same enum, but ~100 producers in `outlet_stream.rs`/`outlets.rs` still use the unstructured arm *while already holding a §5.4.4 (code, slug) pair* (`OpenStreamRejection::{error_code,slug}`, `cancel_error_to_code/slug`, `grant_error_to_code/slug`). The PR itself proves the fix works — `OutletContextNotActive` synthesizes via `OutletErrorSurface::from_code(code, slug, None)`. Collapse to one arm.
2. PyO3 uses 7 positional exception args; the Saga precedent it cites is (message, code, ONE datum) = 3. args[2]=slug and args[3]=class are both `str` and adjacent → silent transposition. Also PyO3 arg order (code, slug, class) diverges from the struct order (class, code, slug) used by napi JSON and the UniFFI accessors.
3. `Arc<uniffi::Object>` chosen to dodge `clippy::result_large_err`. Precedent for the cheaper fix already exists: `crates/scp-runtime/clippy.toml`. A by-value `uniffi::Record` restores Swift/Kotlin value semantics + Equatable and deletes 6 `ffi-export-allowlist.json` getter entries.

Recurring cross-binding traps recorded for future outlet/error work:
- `class` is a hard keyword in Python, Swift and Kotlin (legal in JS). Canonical accessor name must be `error_class` in ALL bindings; only the serde JSON key stays `class`.
- UniFFI mirror types collide by name with their `scp-protocol` counterparts (`OutletErrorClass`, `OutletErrorSurface`) while siblings are prefixed (`OutletRetryPolicy`, `OutletDetailBody`, …). Prefix all of them, and pin the prefixed names as the cross-SDK canonical set before PR-3.
- `from_core` mirrors use field ACCESS, not destructuring — a new field on a `scp-protocol` type is silently dropped at the UniFFI bridge (serde-based PyO3/napi carry it automatically). Destructure so it is a compile error.
- napi string-suffix contracts (`(outlet_error={json})`) must be extracted with `lastIndexOf`, not a greedy `/\(outlet_error=(\{.*\})\)$/` — `{message}` is unescaped and can contain the delimiter. The saga suffixes are safe only because their value charsets are bounded.

Over-engineering flagged: the "detail absent vs JSON null" distinction (`outlet_error.rs` `detail_json: Option<String>`) is unreachable — `Option<DetailBody>` has two states and `DetailBody` never serializes to `null`; napi's own blob emits `"detail":null` anyway. `render_retry`/`render_detail`/`render_source_chain`/`UNRENDERABLE_JSON` are `pub` with zero external callers.

Related: [[cross-sdk-shape-parity]], [[ts-python-trust-parity]].
