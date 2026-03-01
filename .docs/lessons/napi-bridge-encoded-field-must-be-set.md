# NAPI Bridge: Opaque Handle Fields Must Be Populated Even in Stubs

**Date:** 2026-03-01
**Source:** SCP-219 fix — `crates/scp-ffi/napi/src/ucan.rs`

## The Bug

`ucan_mint` in the NAPI bridge was returning an error immediately:

```rust
pub async fn ucan_mint(...) -> napi::Result<NapiUcanToken> {
    let _ = (handle, member_did, capabilities);
    Err(ScpNapiError::Permission { ... }.into())
}
```

This means tokens could never be minted at all. But the underlying bug class is broader: the
`NapiUcanToken` struct carries an `encoded: String` field that must contain a valid JWT-format
string for revocation and validation to work. Had the function constructed the struct but left
`encoded` as `String::new()`, the token would appear to mint successfully while being structurally
broken — non-revokable and non-validatable.

## Why It's Subtle

The PyO3 bridge's `PyUcanToken` has no `encoded` field at all. Agents reading the PyO3 bridge
as a reference for "how to implement mint" will naturally not think about `encoded` — it simply
doesn't exist there. The NAPI bridge added the field for future use, but without documentation
of its required state.

## The Invariant

**Any field on an opaque FFI handle that is required for downstream operations must be populated
when the handle is constructed, even in a stub implementation.** An empty field is worse than
returning an error — it makes the stub appear to work while silently breaking consumers.

Specifically for `NapiUcanToken.encoded`:
- `ucan_revoke` will need to call `parse_ucan(encoded)` to compute the revocation CID
- `ucan_validate` will need the full JWT to verify
- The encoded string must be a valid 3-segment JWT: `b64url(header_json).b64url(payload_json).b64url(sig_bytes)`

## The Fix Pattern

When real signing is not available (e.g., KeyCustody not yet wired), produce a structurally
valid JWT with a placeholder signature (64 zero bytes encoded as base64url). This is parseable
by `parse_ucan` and structurally correct, even though signature verification will fail:

```rust
let header = UcanHeader::new();
let payload = UcanPayload { iss, aud, exp, nbf: None, nnc, att, prf: vec![], fct: None };

let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header)?);
let payload_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload)?);
let sig_b64 = URL_SAFE_NO_PAD.encode([0u8; 64]);
let encoded = format!("{header_b64}.{payload_b64}.{sig_b64}");
```

## How to Catch This When Reviewing

When reviewing a new FFI bridge stub that constructs an opaque handle:
1. Identify all fields on the return type.
2. For each field: does downstream code ever read this field? If yes, is it set?
3. A field that is set to empty/zero/default is a yellow flag — verify the downstream consumer
   handles this case explicitly or that the field is genuinely unused.

## Related

- `crates/scp-ffi/napi/CLAUDE.md` — documents the full NAPI/PyO3 divergence for `encoded`
- PyO3 `py_ucan_mint` in `crates/scp-ffi/src/ucan.rs` — reference: no `encoded` field at all
- `scp_core::crypto::ucan::validate::parse_ucan` — the parser that must accept `encoded`
