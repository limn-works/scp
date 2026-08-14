---
name: sender-layer-wasm-native-interop-1909
description: WASM↔native sender-key AEAD interop (#1909, part of #1877). Three divergences (AAD context-string, epoch semantics, replay tracker) grounded in spec §9.16. Native is WRONG on AAD; WASM lacks epoch+replay state.
metadata:
  type: project
---

# #1909 WASM↔native sender-layer ciphertext interop

**Why:** Alec expanded #1909 to FULL sender-layer interop (part of #1877 convergence). Live double-encryption wire path (AES-256-GCM under MLS). Pre-release, no migration.

**How to apply:** Code converges to spec §9.16, NOT to whichever bridge does X. Artifact flow is one-way.

## Shared primitive (already correct, byte-identical both families)
- WASM `crypto/sender_key.rs:7` RE-EXPORTS `scp_protocol::crypto::sender_keys::encrypt::{encrypt_sender_layer, decrypt_sender_layer}`. So `build_sender_aad` (private, encrypt.rs:129) is IDENTICAL by construction. Divergence is purely CALLER-LEVEL (what args passed), not primitive-level.
- AAD format (encrypt.rs:129, spec §9.16.1 line 1255): `BE32(len(context_id))||context_id||BE32(len(sender_did))||sender_did||epoch_BE8||sequence_BE8`. SPEC-CORRECT.
- `encrypt_sender_layer` uses INTERNAL OsRng nonce (encrypt.rs:59) — no nonce injection → full-ciphertext byte-KAT impossible; cross-family ROUNDTRIP test is nonce-independent and is the right test.
- `build_sender_header`/`parse_sender_header` (encrypt.rs:150/166) pub, `SENDER_HEADER_SIZE=16`. WASM does NOT yet re-export/call them (prior-plan header gap).

## Divergence 1: AAD context-string — NATIVE IS WRONG
- Spec §9.5.1 canonical `context_id` field encoding (lines 372/390/409...): `4-byte BE length + UTF-8 bytes` = RAW context_id string.
- WASM (manager.rs ~2178 encrypt, ~2313 decrypt): passes raw app `context_id` string → SPEC-CORRECT.
- Native (provider.rs seal ~1574, open ~1654): passes `hex::encode(context_id_bytes)` where `context_id_bytes = SHA-256(context_id_string)` (context/mod.rs:74). 64-hex-char string. SPEC-VIOLATING.
- Native has the ORIGINAL string reachable: `inner.context_id: String` (inner/mod.rs:161). Sibling `seal_envelope` (outer/ops.rs:83) ALREADY uses `&inner.context_id` (spec-correct). MlsCryptoProvider::seal deliberately switched to hex to match its own open — internally consistent, both wrong.
- FIX: native seal+open use the raw context_id string (the original, not hex). Must thread original string into open() (open only has [u8;32] today). Receive side: native open builds AAD from ctx_str=hex; change to original string.

## Divergence 2: epoch semantics — WASM IS WRONG
- Spec §9.16.1/§9.16.5 line 1250: epoch = sender's `sender_key_epoch` (per-sender monotonic, starts at 0 on keygen, +1 per ROTATION/block). NOT MLS group epoch.
- Native: `state.sender_key_epoch` (ContextCryptoState, provider.rs:765 starts at 1; provider.rs:229). Header+AAD carry it.
- WASM (manager.rs ~2178): passes `crypto.mls_group.epoch()` = MLS GROUP epoch (group.rs:557, starts 0, +1 per commit). WRONG axis entirely.
- Neither native MembershipState/MemberInfo (membership.rs:107/129) nor #1877 carries sender_key_epoch — it lives ONLY in ContextCryptoState. So #1909 is NOT blocked on #1877 MembershipState. WASM must add its own `sender_key_epoch: u64` to WasmCryptoState (crypto/state.rs), starting at 1 to match native, incremented in governance_rotate_sender_key + block.
- seq: WASM `member_sequence_numbers` (manager.rs:405, 1-based per #1902) is the CORRECT sequence axis — keep.

## Divergence 3: receive-side replay/epoch-ceiling — WASM MISSING
- Spec §9.16.1 lines after 1255 MANDATE (MUST): per-sender `(last_epoch,last_sequence)` tracker; reject epoch<last OR (epoch==last && seq<=last). AND epoch-poisoning: reject `epoch > current+1000`.
- Native: `recv_sequence_tracker: HashMap<String,(u64,u64)>` (provider.rs:242) + `MAX_EPOCH_ADVANCE=1000` (provider.rs:65) ceiling against `sender_key_store.epoch()` high-water (provider.rs ~1722-1758). SPEC-CORRECT.
- WASM `decrypt_message` (state.rs ~99): NO header parse, NO replay tracker, NO ceiling. MISSING entirely.
- WASM `sender_key_store` is bare `HashMap<String,SenderKey>` (state.rs:32) — lacks epoch high-water. Shared `scp_protocol::crypto::sender_keys::SenderKeyStore` (mod.rs:268) HAS keys+epochs maps, set_checked monotonicity (#1608), epoch() high-water. WASM SHOULD adopt shared SenderKeyStore to get the ceiling reference + monotonicity for free.

## Cross-family test strategy
- scp-ffi-wasm `#[cfg(test)]` runs NATIVELY on host with real openmls (state.rs tests prove it). Both families call SAME shared encrypt/decrypt. So: encrypt via WasmCryptoState, decrypt via the shared decrypt_sender_layer with native-derived AAD args, and vice versa — proves AAD+header+epoch agree without standing up two full MLS groups. The MLS layer is orthogonal (shared openmls); the contested surface is sender-layer AAD/header bytes.
- §26 conformance suite (specs/26) ENC-001/DEC-001/§9.16 KAT exist as descriptions; no cross-family ciphertext fixture yet. Add a sender-layer roundtrip + header KAT.
