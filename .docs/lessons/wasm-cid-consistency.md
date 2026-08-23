# A store site and a check site must hash one canonical CID input

**Status: defect resolved, rule evergreen.** `crates/scp-ffi/` holds six directories — `src` (PyO3), `napi`, `napi-test-stubs`, `uniffi`, `common`, and `tests` — and no `wasm` directory, so `crates/scp-ffi/wasm/src/ucan.rs` and its WASM-local CID reimplementation are gone and can no longer drift. ADR-057, in-browser client over shared MLS, records that bridge removal at its line 9 as correct and standing. That rule still binds PyO3, NAPI, UniFFI, and every other store-then-check pair in this codebase.

## Rule

When one function stores a content-hash CID and another function checks it, both hash one canonical input.

## What went wrong (SCP-218)

`ucan_revoke` in that removed bridge took a `token_id` (a UUID nonce string) and stored `SHA-256(token_id)` into `revoked_tokens`. `ucan_validate` took a full JWT string and checked `SHA-256(full_jwt)`. Those two hashes never matched, so a token revoked through `ucan_revoke` still passed `ucan_validate`.

Native bridges avoid that split by routing both sides through one function whose signature admits one input type. `crates/scp-protocol/src/crypto/ucan/revoke.rs:661` declares `pub fn compute_revocation_cid(encoded_token: &str) -> String`, and it hashes raw JWT bytes: `Sha256::digest(encoded_token.as_bytes())`, rendered as 64 lowercase hex characters. Every caller passes an encoded token string: `crypto/ucan/validate.rs:824` and `:1187` pass `&token.encoded` on a revocation check, and `:1538` passes `&parent.encoded` for a parent token in a delegation chain.

That function's own doc block rejects a deserialize-then-reserialize construction by name: "Hashing the raw JWT avoids the non-canonical serialization problem that arises from deserializing a payload and re-serializing it (e.g., `serde_json::to_vec` may produce different key orderings for `serde_json::Value` fields across platforms)." Hashing a re-serialized payload struct would reintroduce, across platforms, exactly what hashing a raw token removes.

A repair for that removed bridge would have taken a full JWT string into `ucan_revoke`, so both sites hashed identical bytes.

## How to apply

After writing a store-CID operation, find every check-CID operation and confirm each hashes one input type. Risk rises wherever a bridge cannot call a shared helper and each side re-implements hashing independently. Grep every use of a revocation set (`revoked_tokens.insert`, `revoked_tokens.contains`) and compare what each call hashes.
