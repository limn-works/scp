# Finding 009: PyO3 and UniFFI bridges use no-op crypto for MLS group management

## Severity: major (revised down from initial assessment)

## Summary

Both PyO3 (`NoOpCryptoProvider`) and UniFFI (`FfiBridgeCrypto`) bridges use no-op crypto providers for ContextManager initialization. MLS group management operations (create group, add/remove member, validate key package, sender key rotation) all succeed silently as no-ops. However, `encrypt_message` returns an explicit error in both bridges, preventing messages from being sent without encryption silently.

**Correction:** The initial assessment stated "messages are NOT encrypted by MLS" — this was inaccurate. `encrypt_message` raises an error, so messages _cannot_ be sent through the encrypted path at all. The actual gap is: MLS group operations (creating groups, adding/removing members, key package validation, sender key distribution) are silently no-ops.

Only NAPI has real `MlsCryptoProvider` wired (#1294). WASM has its own real MLS via OpenMLS with JS crypto backend.

## Evidence

**PyO3 (`crates/scp-ffi/src/runtime.rs`):**
- Line 147: `Box::new(NoOpCryptoProvider)` — initialized with no-op
- Lines 323-388: `NoOpCryptoProvider` — all group ops return `Ok(())`, `encrypt_message` returns `Err(...)`

**UniFFI (`crates/scp-ffi/uniffi/src/runtime.rs`):**
- Line 474: `FfiBridgeCrypto` struct
- Lines 476-551: All group ops return `Ok(())`, `encrypt_message` returns `Err("FfiBridgeCrypto::encrypt_message is not a real implementation...")`

**NAPI (`crates/scp-ffi/napi/src/runtime.rs`):**
- Line 169: `Box::new(scp_core::crypto::mls::provider::MlsCryptoProvider::new(did))` — real MLS

**ContextManager (`crates/scp-core/src/context/manager.rs`):**
- Line 2935-2936: `self.crypto.encrypt_message(...)` — called in encrypted message path

## Operations that silently succeed as no-ops (PyO3 + UniFFI)

| Operation | What it should do | Actual behavior |
|-----------|------------------|-----------------|
| `create_mls_group` | Initialize OpenMLS group | No-op (Ok) |
| `generate_sender_key` | Generate sender-side encryption key | No-op (Ok) |
| `validate_key_package` | Validate MLS key package from joiner | No-op (Ok) — **accepts anything** |
| `add_member` | Add member to MLS group with key package | No-op (Ok) |
| `remove_member` | Remove member from MLS group, trigger key rotation | No-op (Ok) |
| `distribute_sender_key` | Distribute sender key to new member | No-op (Ok) |
| `remove_member_sender_key` | Remove sender key on member exit | No-op (Ok) |
| `encrypt_message` | MLS + sender key encryption | **Returns error** |

## Impact

1. **Key package validation is bypassed** — any member can "join" without a valid MLS key package
2. **Member removal doesn't trigger key rotation** — no forward secrecy on member exit
3. **Sender key distribution is a no-op** — no sender-side encryption layer
4. **Messages cannot be sent in encrypted mode** — `encrypt_message` errors out
5. In practice, this means PyO3 and UniFFI bridges can only work with **broadcast mode** contexts, not encrypted mode contexts

## Suggested Fix

1. Wire `MlsCryptoProvider` into both PyO3 and UniFFI ContextManagers (same as NAPI uses at line 169)
2. Or route MLS operations through platform callbacks (UniFFI) / bridge-level crypto (PyO3)
3. The NAPI bridge proves this is achievable — it already has real MLS wired via issue #1294
