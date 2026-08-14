---
name: outlet031-pr2b-bridge-render
description: SCP-OUT-031 PR-2b (e1ce84f48) bug-catcher findings — three-bridge OutletErrorSurface render; verified-clean items + 7 defects.
metadata:
  type: project
---

# SCP-OUT-031 PR-2b bridge render (commit e1ce84f48) — bug-catcher pass

**Why:** PR-2b makes PyO3 / napi / UniFFI render the full §5.4.4 `OutletErrorSurface`.
**How to apply:** reuse the verification recipe below on any future FFI error-shape change.

## MECHANICALLY VERIFIED CLEAN (do not re-litigate)
- `bindings/swift/Sources/SCP/Internal/ScpBindings.swift` is **byte-identical** to freshly
  generated output. Recipe: `CARGO_TARGET_DIR=<iso> cargo build -p scp-ffi-uniffi` (debug is
  fine — checksums come from metadata, not profile) then
  `cargo run -p scp-ffi-uniffi --bin uniffi-bindgen -- generate --library <iso>/debug/libscp_ffi_uniffi.dylib --language swift --out-dir <gen>`
  and `diff bindings/swift/.../ScpBindings.swift <gen>/scp.swift`.
  `build-xcframework.sh` is a pure `cp`, so byte-diff is the right expectation.
- No `#[uniffi::export]` item is `#[cfg(feature="testing")]`-gated → generated bindings are
  feature-independent, so the new build-matrix staleness step is stable.
- Swift `ScpError` reader tags 1..11 match the Rust declaration order exactly
  (…Transport(5), Outlet(6), OutletSurface(7), Validation(8), Saga*(9-11)).
- Kotlin UniFFI bindings are **gitignored** (`.gitignore:28`) → no Kotlin staleness hazard.
- napi base64 suffix framing is sound: base64 alphabet excludes `(` and space, both parsers
  (Rust `rfind`, TS greedy `^[\s\S]*`) are last-anchored. No forgery.
- `scp-ffi-common` outlet_error lib tests: 9/9 pass. `check-sdk-coverage.py`,
  `check-bridge-symmetry.sh`, `check-error-codes.sh` all PASS.
- All new `unwrap`/`expect`/`panic!` are `#[cfg(test)]`-gated. No production panics.
- `surface_from_untrusted_envelope`'s `is_none_or` permissiveness for UNREGISTERED
  code/slug **mirrors `OutletError::new`** exactly (protocol-level, not a new asymmetry).
- Python: `scp.py:2687` bare `raise` cannot receive the 7-arg `OutletError` —
  `map_saga_error` only ever yields the three Saga arms. NOT a live bug.
- `wrap_cross_context_error` genuinely does not exist → `From<errors::OutletError>` has
  no production producer (agent's claim verified true).

## DEFECTS FOUND
1. **MEDIUM — fail-closed collapse defeated in the message.** All three
   `impl From<scp_core::context::outlets::errors::OutletError>` do
   `from_outlet_surface(format!("{e}"), &surface)`. `surface` may be COLLAPSED to
   `authorization.denied`, but `OutletError`'s `Display` (`errors.rs:1069`) renders
   `"{code} ({slug}): {class}"` from the RAW unvalidated envelope. Attacker-claimed
   taxonomy leaks into `.message` while the structured surface says something else.
   Fix: derive the message from the projected `surface`, matching `ContextError::Outlet`'s
   `#[error("[{code}] {class}: {slug}")]`.
2. **MEDIUM — `bindings/python/scp_sdk/_scp_core.pyi` stale.** Tracked stub explicitly
   mirrors `create_exception!`; lists all 14 others incl. the 3 saga terminals but NOT the
   new `OutletError`. `check-pyi-generated.sh` only enforces *function signature* parity →
   CI will not catch it. RECURRING CLASS: adding a PyO3 exception requires a .pyi edit.
3. **MEDIUM — TS `.message` carries the multi-KB base64 blob.** `mapBridgeError`
   (`bindings/typescript/src/errors.ts:360-374`) passes the whole napi Display through.
   PyO3/UniFFI messages are clean → cross-binding asymmetry in user-visible text.
4. **LOW — u64 widening incomplete.** Only `needed` / `elapsed_ms` are widened;
   `Duration.secs` inside `RetryPolicy` is also `u64` on the JSON wire and is unbounded
   on the untrusted path. Module doc over-claims the hazard is "closed".
5. **LOW — Swift `Duration` → `TimeInterval` (Double)** is lossy above ~2^53 ns (~104 d);
   Kotlin's `java.time.Duration` is exact. Doc says precision "survives intact".
6. **LOW — stale delimiter name** `(outlet_error=…)` (real: `outlet_error_b64`) in
   `sdk-capability-matrix.json` TS exemption and the napi test-module comment.
7. **LOW — `lib.rs` comment contradicts the module doc** ("shared by … UniFFI" vs
   `outlet_error.rs:13` "UniFFI does NOT and cannot use this module").

## Adjacent completeness gap (not introduced here)
`outlets::OutletError::to_surface()` (mod.rs:470) is documented as "single-sources the
legacy-enum → §5.4.4 taxonomy mapping so the FFI bridges never re-derive it" but is called
ONLY from its own unit tests. All three live `From<outlets::OutletError>` bridge impls
(and `From<InvocationError>`) still flatten to a hardcoded `SCP-OUTLET-6001` with no
class/slug/retry/detail. So the "dead path" claim is true only because the bridges decline
to call it — the *type* is `?`-reachable from registration/verification paths.
