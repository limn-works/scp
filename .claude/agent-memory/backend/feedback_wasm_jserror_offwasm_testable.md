---
name: wasm-jserror-not-jsvalue-for-host-testable-errors
description: WASM #[wasm_bindgen] fns returning Result<_, JsValue> can't have their error arm tested off-wasm (JsValue conversion + JsError::new call wasm-bindgen imports that panic on host); factor validation into a helper and test the underlying validator
metadata:
  type: feedback
---

In `crates/scp-ffi/wasm`, host-target `#[test]` functions (the ones `cargo test -p scp-ffi-wasm` runs — there is NO `#[wasm_bindgen_test]` harness wired into the normal gate) CANNOT exercise the error arm of a `#[wasm_bindgen]` function that materializes a `JsValue` OR a `JsError`.

**Why:** `JsValue::from(...)`, `JsError::new(...)`, and `ScpWasmError::into_js()` all call wasm-bindgen imported functions, which panic off-wasm with `cannot call wasm-bindgen imported functions on non-wasm targets` (wasm-bindgen lib.rs). The happy path (returning `Ok`) is fine; only the `Err` construction panics. This bit me writing a malformed-DID rejection test for `identity_remove` — `assert!(identity_remove(bad).is_err())` panicked on the host.

**How to apply:**
- Return `Result<_, JsError>` (not `Result<_, JsValue>`) from wasm bridge fns when you want the SIGNATURE to be throwing — `JsError` is what UniFFI/wasm-bindgen idiomatically throws, and TS sees a thrown exception either way. But this still does NOT make the error arm host-testable, because constructing the `JsError` panics off-wasm too.
- To get a host-testable rejection assertion: test the UNDERLYING validator (`scp_ffi_common::validate::validate_did("not-a-did").is_err()`) — the exact `Result<(), ValidationError>` gate the op delegates to, which has no JsValue/JsError in it. Assert the validator rejects malformed + accepts a real registered DID, and separately assert the happy-path op returns `Ok`. This pins both reject and accept sides without a browser harness. The WASM discovery bridge's `validate_owner_did` follows the same factoring pattern.
- TS/Swift/Kotlin SDK wrappers over a now-throwing bridge fn need NO signature change for TS/Kotlin (unchecked exceptions propagate); Swift MUST become `throws` and the committed `ScpBindings.swift` must be regenerated (see [[swift-uniffi-bindings-are-regenerated-in-ci-from-rust-source]]).
