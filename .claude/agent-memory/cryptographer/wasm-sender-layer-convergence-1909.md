---
name: wasm-sender-layer-convergence-1909
description: #1909 Phase 2 WASM sender-layer epoch/replay/header convergence with native (commit 6952efad) — GO, byte-identity via shared-code reuse
metadata:
  type: project
---

# #1909 Phase 2 — WASM sender-layer convergence (commit 6952efad) — GO

Reviewed 2026-06-28. WASM↔native sender-layer ciphertext interop complete (on top of Phase 1 raw-context_id AAD). Verdict GO, no blocking findings.

**Why it's sound:** convergence is SHARED-CODE REUSE, not parallel reimpl. WASM `crypto/sender_key.rs` re-exports `build_sender_header`/`parse_sender_header`/`encrypt_sender_layer`/`decrypt_sender_layer`/`SenderKeyStore` from `scp_protocol::crypto::sender_keys` — the SAME fns native seal/open call. Byte-identity is structural.

**How to apply:** if reviewing further sender-layer or epoch changes, the load-bearing facts:
- Header = `epoch.to_be_bytes()||sequence.to_be_bytes()||ct` (16B fixed, encrypt.rs:150). AAD = `BE32(len(ctx))||ctx||BE32(len(did))||did||epoch_BE||seq_BE` (encrypt.rs:129). Both bind `sender_key_epoch` (§9.16.5 per-sender axis, init 1), NOT MLS group epoch.
- WASM passes RAW context_id string to encrypt/decrypt (manager.rs:2197/2329). Native AAD uses raw `context_id_str` (provider.rs:1744); native `ctx_id_hex` is only the STORE key, never AAD.
- decrypt ordering (state.rs:223-277 == provider.rs open 1733-1785): parse header → ceiling (`epoch > high_water.saturating_add(MAX_EPOCH_ADVANCE)`) → replay (`epoch<last || (epoch==last && seq<=last)`) → decrypt → insert tracker ONLY on success. Forged/over-ceiling/undecryptable msg can't poison floor.
- `context_decrypt_message` FFI sig DROPPED epoch/sequence params — header is authoritative now.
- MAX_EPOCH_ADVANCE=1000 hoisted verbatim to scp_protocol::crypto::sender_keys (mod.rs:67); native imports it (provider.rs:56). Behavior-preserving.
- Snapshot: export/import → park in PerContextState.pending_replay_state → seed+`take()` on encrypted join (manager.rs:2495). WASM_EXPORT_VERSION 5→6, STRICT-equality gate (rejects newer AND older — correct for signed envelope).
- Proof: cross_family_sender_layer_header_and_aad_converge (wasm_conformance.rs:2019) asserts byte-identical header + cross-decrypt both dirs + tampered-header AEAD-fail-closed.

**LOW findings (non-blocking):**
- WASM governance_rotate_sender_key uses saturating_add (state.rs:365); native rotate uses checked_add+error (provider.rs:1241). Divergence only at u64::MAX (unreachable). Align if cheap.
- WASM has NO cross-member sender-key distribution path for encrypted MLS contexts (pre-existing). insert_sender_key uses set_unchecked → first install leaves receive-ceiling high-water at 0; ceiling tolerates (permits +MAX_EPOCH_ADVANCE). Eviction security via MLS layer-2 epoch advance, not sender-key redistribution. Documented at state.rs:135-147.

**SPEC CONTRADICTION (upstream fix, code is right):** §9.16.5 (09-security-model.md:1365) says epoch "starting at 0 on key generation"; §9.16.1 (:1270) says header epoch "starts at 1" and relies on it for SCPM_MAGIC non-collision. Impl (native+WASM) uses 1 = matches load-bearing §9.16.1. §9.16.5 "0" is the stale clause — fix flows DOWN per artifact-flow invariant.
