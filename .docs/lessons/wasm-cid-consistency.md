# A store site and a check site must hash one canonical CID input

**Status: defect resolved, rule evergreen.** ADR-055 removed a wasm-bindgen bridge on 2026-06-29 and `crates/scp-ffi/wasm/src/ucan.rs` no longer exists, so that WASM-local CID reimplementation can no longer drift. That rule still binds PyO3, NAPI, UniFFI, and every other store-then-check pair in this codebase.

## Rule

When one function stores a content-hash CID and another function checks it, both hash one canonical input.

## What went wrong (SCP-218)

`ucan_revoke` in that removed bridge took a `token_id` (a UUID nonce string) and stored `SHA-256(token_id)` into `revoked_tokens`. `ucan_validate` took a full JWT string and checked `SHA-256(full_jwt)`. Those two hashes never matched, so a token revoked through `ucan_revoke` still passed `ucan_validate`.

PyO3 avoided that split. `py_ucan_revoke` takes a full JWT, parses it through `parse_ucan`, and calls `scp_core::crypto::ucan::revoke::compute_revocation_cid(&parsed.payload)`, hashing a JSON-serialized payload struct. `py_ucan_validate` reaches that same function through its validation pipeline. One function, one input, on both sides.

A repair for that bridge would have taken a full JWT string into `ucan_revoke`, matching `py_ucan_revoke`, so both sites hashed identical bytes.

## How to apply

After writing a store-CID operation, find every check-CID operation and confirm each hashes one input type. Risk rises wherever a bridge cannot call a shared helper and each side re-implements hashing independently. Grep every use of a revocation set (`revoked_tokens.insert`, `revoked_tokens.contains`) and compare what each call hashes.
