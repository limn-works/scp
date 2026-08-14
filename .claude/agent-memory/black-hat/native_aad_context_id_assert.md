---
name: native-aad-context-id-assert
description: Verdict GO on #1909 native seal/open AAD binds raw context_id string; open's new hash-consistency assert; trust model + WASM interop
metadata:
  type: project
---

# #1909 native-aad: seal/open AAD raw context_id string + open hash assert (commit b8d1a7676)

Verdict: **GO**. Read-only adversarial review, 6 probes all passed.

## What the fix is
- File `crates/scp-runtime/src/crypto/mls/provider.rs` `seal` (~1565) + `open` (~1661).
- Sender-layer AEAD AAD binds the RAW `context_id` UTF-8 string (length-prefixed BE32) per §9.16.1, NOT hex of the 32-byte hash.
- `seal` asserts `context_id_bytes(inner.context_id) == *context_id`.
- `open` NOW ALSO asserts `context_id_bytes(context_id_str) == *context_id` fail-fast (CryptoFailed) before any deserialize/MLS/AEAD work — mirrors seal.
- Store lookup keyed by `hex(context_id)`; AAD keyed by raw str. Both bound to ONE verified id by the assert.

## Trust model (why it holds)
- `open(context_id, context_id_str, blob)`: only `blob` is wire/attacker-influenced. `context_id` + `context_id_str` are TRUSTED LOCAL routing state.
- Production caller chain: `deliver_incoming` (messaging_helpers.rs:1409) computes `context_id_bytes = context_id_bytes(context_id)` from the SAME local str → assert is a tautology on the prod path ("unreachable from current callers" is accurate).
- `context_id` str is the actor-registry routing key: `dispatch_command(ctx_id,...)` → `self.lookup(ctx_id)`. Message delivered to the actor registered under that str; same str feeds AAD. No wire field reaches the AAD.
- `context_id_bytes` = pure SHA-256(str). AAD builder `build_sender_aad` = length-prefixed binary (no delimiter injection).

## Attack results (probes in provider.rs test mod, throwaway)
- BLACK-AAD-01: relocation (open with mismatched str) → fail-fast assert. PASS.
- BLACK-AAD-02: self-consistent (hash(other),other) pair passes assert but hits "no MLS group for this context" — no decrypt. PASS.
- BLACK-AAD-03: 10k malformed rejects in 117ms, happy path unaffected — no self-DoS. PASS.
- BLACK-AAD-04: store hex-key and AAD str both bind one verified id. PASS.
- BLACK-AAD-05: failed asserts do NOT poison recv_sequence_tracker/epoch state (assert is before tracker mutation). PASS.
- BLACK-AAD-06: seal refuses divergent inner.context_id — divergent AAD can't be produced on wire. PASS.

## WASM interop (Phase 2, question 4) — NO GAP
- WASM `crypto/sender_key.rs:7` RE-EXPORTS the SAME `scp_protocol::...::{encrypt_sender_layer, decrypt_sender_layer}` native uses. Single shared AAD builder → byte-identical format. No reimpl, no divergence possible.
- WASM has NO 32-byte id representation (store keyed by str + sender_did); only ever holds the str. The (str, 32-byte-id) divergence the native assert guards does not EXIST in WASM, so the assert's absence there is not a gap.
- WASM `decrypt_message(context_id,...)` → `require_active_context_mut(context_id)`: str is the local context handle, used for BOTH lookup and AAD — mirrors native trust model.

## Bottom line
Assert closes the confused-deputy surface fail-fast without introducing DoS (cheap) or bypass (self-consistent wrong id dies at group lookup). Base fix sound: raw-string AAD shared across native+WASM. No new interop/forgery surface.
