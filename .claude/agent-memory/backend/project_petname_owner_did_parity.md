---
name: petname-owner-did-parity
description: All petname FFI ops validate owner_did via the shared validate_did (DID-syntax), uniformly across PyO3/NAPI/UniFFI/WASM; address_resolve is the exception
metadata:
  type: project
---

Every petname FFI op that takes `owner_did` must validate it via the shared
`scp_ffi_common::validate::validate_did` (its per-bridge wrapper), NOT a bare
`is_empty()` check. `owner_did` is the per-identity petname-map partition key
(`BridgeInstance::petname_maps: Mutex<HashMap<String, PetnameMap>>`, keyed by
owner DID per spec §3.7), so DID-syntax validation is semantically correct.

**Why:** A bridge-symmetry review caught asymmetry — WASM's shared
`validate_owner_did` (`crates/scp-ffi/wasm/src/discovery.rs`) calls `validate_did`
for all petname ops, but the pre-existing native ops (`petname_set`,
`petname_remove`, `petname_set_context`, `petname_remove_context`,
`petname_resolve_did`, `petname_resolve_context`, `petname_get_for_did`,
`petname_get_for_context`) only checked `is_empty()`, making WASM stricter. The
§4.7 ops (`petname_apply_event`, `petname_did_count`, `petname_context_count`)
already validated via `validate_did` in all bridges.

**How to apply:** Per-bridge `validate_did(owner_did)` call counts must match:
PyO3/NAPI/UniFFI = 11 each (8 promoted + 3 §4.7); WASM = 12 (adds WASM-only
`petname_list_events`). Verify with grep for the bridge's validate-call form.
`address_resolve` is the ONE op that intentionally keeps `is_empty()` in ALL
four bridges (WASM included) — it stays symmetric that way, so do NOT promote it.
The empty case still errors after promotion (validate_did rejects empty) — only
the error code changes from `SCP-VALID-7110` to the shared `SCP-VALID-7000`.
Empty-owner tests assert only `.is_err()`, so they stay green. See
[[swift-uniffi-regen]] for the CI-vs-local Swift binding gotcha when touching
UniFFI petname signatures.
