# WASM CID Consistency: Store and Check Must Hash the Same Input

> **Resolved / ADR-055 (2026-06-29):** the WASM bridge was removed and `crates/scp-ffi/wasm/src/ucan.rs` no longer exists — the browser is a remote thin client, so there is no WASM-local CID reimplementation to drift. The specific defect below is historical. The general rule — store-CID and check-CID sites must hash the same canonical input — remains evergreen across the three remaining bridges (PyO3, NAPI, UniFFI) and the rest of the codebase.

**Rule**: When a content-hash CID is stored in one function and checked in another, both sites must hash the same canonical input. This applies across the entire codebase but is especially fragile in the WASM bridge where scp-core's helper functions cannot be used.

**Context (SCP-218)**: `ucan_revoke` in `crates/scp-ffi/wasm/src/ucan.rs` accepted a `token_id` (UUID nonce string) and stored `SHA-256(token_id)` in `revoked_tokens`. But `ucan_validate` retrieved the full JWT `token` string from its parameter and checked `SHA-256(full_jwt)`. These produce different hashes. A token revoked via `ucan_revoke` was never detected as revoked by `ucan_validate`.

**Contrast with PyO3 bridge**: `py_ucan_revoke` accepts the full JWT string, parses it via `parse_ucan`, and calls `scp_core::crypto::ucan::revoke::compute_revocation_cid(&parsed.payload)` — hashing the JSON-serialized payload struct. `py_ucan_validate` also calls `compute_revocation_cid` through the validation pipeline. Both sites use the same scp-core function on the same input.

**Fix**: In the WASM bridge, `ucan_revoke` must accept the full JWT string (matching the PyO3 bridge's `py_ucan_revoke` signature). Both `ucan_revoke` and `ucan_validate` should call `compute_token_cid` with the full JWT string so the SHA-256 input is identical.

**Lesson**: Whenever you write a "store CID" operation, immediately locate all "check CID" operations and confirm they hash the same type of input. This is especially risky in WASM bridges where convenience functions like scp-core's `compute_revocation_cid` are unavailable and both sides must independently re-implement the hash. Grep for all uses of the revocation set (`revoked_tokens.insert`, `revoked_tokens.contains`) to audit consistency.
