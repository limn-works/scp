# Finding 012: Provenance advanced functions unwrapped in all 4 SDKs

## Severity: minor

## Summary

Three provenance functions exist in all FFI bridges but are not exposed in any SDK wrapper:
- `provenance_redact_counterparties`
- `provenance_pseudonymize_counterparties`
- `provenance_update_source_type`

## Evidence

**FFI bridge exports (all present):**
- PyO3: `crates/scp-ffi/src/provenance.rs`
- NAPI: `crates/scp-ffi/napi/src/provenance.rs`
- UniFFI: `crates/scp-ffi/uniffi/src/bridge.rs`

**SDK wrappers (all absent):**
- Python: `bindings/python/scp_sdk/provenance.py` — only basic 3 functions wrapped
- TypeScript: `bindings/typescript/src/` — basic provenance only
- Kotlin: `bindings/kotlin/scp-kt/src/` — basic provenance only
- Swift: `bindings/swift/Sources/SCP/Provenance.swift` — basic provenance only (UniFFI-generated bindings exist in ScpBindings.swift but not re-exported)

## Impact

SDK users cannot use provenance privacy features (redaction, pseudonymization, source type updates).

## Suggested Fix

Add wrapper functions in all 4 SDKs for these 3 provenance functions.
