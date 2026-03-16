# Finding 008: Excessive #[allow(dead_code)] annotations across FFI bridges

## Severity: minor

## Summary

47 `#[allow(dead_code)]` annotations exist across the codebase, with heavy concentration in FFI bridges and transport code. While some are legitimate (fields held for ownership, future wiring), several mask genuinely unreachable code.

## Evidence

**Notable instances:**

1. `crates/scp-ffi/napi/src/event_log.rs:574` — `decode_hex_hash` helper "Will be used when event_log_verify is wired to scp-core"
2. `crates/scp-ffi/napi/src/identity.rs:680,687` — `in_memory_custody()` and `scp_identity()` methods
3. `crates/scp-ffi/uniffi/src/bridge.rs:1180,1187,1193,1201,11280` — multiple struct fields
4. `crates/scp-ffi/uniffi/src/lib.rs:217` — type
5. `crates/scp-ffi/src/lib.rs:92` — `runtime()` function "Used by bridge functions added in subsequent stories"
6. `crates/scp-ffi/src/runtime.rs:1368` — type
7. `crates/scp-transport/src/native/client.rs:52,58,65,101,718,732,822,835` — 8 annotations in one file
8. `crates/scp-core/src/context/standing.rs:64` — field
9. `crates/scp-core/src/context/manager.rs:592` — field
10. `crates/scp-platform/src/testing/key_custody.rs:194,213` — "Retained for future pseudonym wiring"

## Expected Behavior

Dead code should either be used or removed. `#[allow(dead_code)]` should only be used for legitimate patterns (ownership anchoring, platform-conditional code).

## Root Cause

Incremental development left some code unreachable between stories.

## Suggested Fix

Audit each `#[allow(dead_code)]` annotation. Remove those that mask genuinely unused code. For legitimately retained code, ensure comments explain why.
