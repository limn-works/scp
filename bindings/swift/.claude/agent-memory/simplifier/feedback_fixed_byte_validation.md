---
name: Fixed-byte validation scattering
description: "must be exactly 32 bytes" validation inlined in ~20 sites across all 4 FFI bridges
type: feedback
---

Across scp-ffi (PyO3/NAPI/UniFFI/WASM) the same pattern — `<[u8; N]>::try_from(slice).map_err(|_| ScpXError::Validation { message: format!("FIELD must be exactly N bytes, got {}", slice.len()), code: VALID_7007 })` — is inlined everywhere a caller has to narrow a `Vec<u8>`/`Buffer`/`&[u8]` to a fixed-size array. `testing_seed`, `platform_key`, `sender_key_bytes`, `bridge_credential_key`, `implementation_hash`, `merkle_root`, `interface_id_hex`, `payment_receipt_id`. 20+ sites.

**Why:** each bridge uses its own error enum (ScpPyError / ScpNapiError / ScpError / ScpWasmError) and a field name prefix. Users want the length echoed in the message, so a simple `validate::expect_len(N, &slice)` in `scp-ffi-common/validate.rs` returning `Result<[u8; N], ValidationError>` with `ValidationError { field, expected, actual }` lets each bridge convert via its existing `From<ValidationError>` impl.

**How to apply:** when reviewing bridges for simplification, always treat "identical try_from + format! block" as a repetition finding worth consolidating. The conversion impls already exist — the only missing piece is a generic helper in `scp-ffi-common/src/validate.rs`. Propose it as a single function and enumerate all call sites so the cost/benefit is clear.
