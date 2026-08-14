---
name: wasm-seq-rollback-and-signed-export
description: WASM send_message per-sender seq rollback (commit 3e1cc9a6b) AEAD-soundness + signed context-export final sweep — both SOUND
metadata:
  type: project
---

# WASM seq rollback (3e1cc9a6b) + signed context-export — SOUND

Reviewed commit 3e1cc9a6b (slice1-roles worktree, HEAD). READ HEAD: blob, not Read tool (serves stale in this worktree).

## send_message seq rollback — SOUND, native parity
- `crates/scp-ffi/wasm/src/manager.rs` send_message ~L2090-2174. Reserves+increments per-sender `member_sequence_numbers[sender_did]` BEFORE fallible encrypt; on ANY encrypt-closure error rolls back via `saturating_sub(1)`, and removes a fresh `0` entry if `!seq_was_present` (WASM-specific refinement; native members always pre-exist so native rollback never removes — `membership.rs::rollback_sequence_number` is plain saturating_sub).
- **No AEAD nonce-reuse risk.** Nonce is `OsRng.fill_bytes([0u8;12])` PER INVOCATION in `scp_protocol::crypto::sender_keys::encrypt::encrypt_sender_layer` (encrypt.rs:60-62), entirely independent of `sequence`. `sequence` feeds ONLY the AAD via `build_sender_aad` (length-prefixed BE: ctxlen|ctx|didlen|did|epoch_be|seq_be). seq reuse cannot collide GCM nonce.
- **No double-transmit of (epoch,seq).** Failed send returns Err with NO ciphertext recorded (closure returns before push_event). Successful encrypt -> push_event (infallible) -> dispatch_consequences (infallible, returns ()) -> Ok. NO `?` between increment-success and Ok(()). So each committed (epoch,seq) transmitted exactly once; rollback reissues the rolled-back seq to the NEXT (successful) send only.
- **No receiver desync.** decrypt_message (manager.rs:2233) takes `sequence` as a CALLER-SUPPLIED param; receiver has NO member_sequence_numbers increment on decrypt. AAD reconstructed from transmitted (epoch,seq). Rollback is sender-side AAD numbering only.
- Borrow safety: closure borrows only `ctx.crypto`; rollback touches `ctx.member_sequence_numbers` after closure returns — sequential, no interleaving mutation of the rollback target.
- publish_broadcast (~L5678) increment followed only by infallible push_event — no rollback needed (commit claim accurate).
- Test `send_message_failure_does_not_advance_sequence_wasm` drives REAL crypto (WasmCryptoState::new_for_context): success 0->1, invalid-base64 CRYPTO_4001 failure stays 1. Mutation-verified. PASSES on native target (`cargo test -p scp-ffi-wasm <name>`). NOTE: wasm32 target test build is BROKEN (scp_identity unlinked in identity.rs tests) — run unit tests on native target.

## Signed context-export — SOUND (final sweep, both impls)
TWO impls, both sound, byte-converged via shared `EXPORT_SCOPE_TAG_FULL` + `SCP-CONTEXT-EXPORT-V1:` separator:
- Native: `scp-runtime/src/context/export_import.rs` `canonical_snapshot_hash` = SHA-256(`SCP-CONTEXT-EXPORT-V1:` || scope.tag_byte() || JCS(snapshot)). Scope tag IMMEDIATELY after sep, before JCS. validate_export_for_import: (1) version==CURRENT (SCP-CTX-2094 distinct from sig err 2093); (2) exporter_did==role_state.creator_did BEFORE sig; (3) verify_strict over digest vs caller-resolved creator key; (4) recompute_event_log_root; (5) ct_eq vs SIGNED snapshot.event_log_merkle_root (sole authoritative binding; no unsigned envelope mirror). Truncation forgery CLOSED via append_unsigned_event seq/prev_hash replay.
- WASM: `manager.rs` export_context/import_context. `wasm_export_snapshot_digest` (L7685) = SHA-256(WASM_EXPORT_SIGN_DOMAIN `SCP-CONTEXT-EXPORT-V1:` || [EXPORT_SCOPE_TAG_FULL] || snapshot_json). WASM_EXPORT_VERSION=5 STRICT gate (rejects !=, 2094). exporter_did==creator_did check (2093). verify_snapshot_signature resolves creator #active->#agent key from creator_did (NEVER envelope field), verify_strict. HMAC (compute_export_hmac) is defense-in-depth self-import only, subsumed by Ed25519.
- **JCS determinism:** RFC 8785 JCS fixes object-key order but NOT array order. `canonicalize_snapshot_sets` (L7650) sorts ALL set/map-derived arrays (read_exclusion_list, revoked_tokens, seen_nonces_v3, executed_proposals, broadcast subscribers/block_lists) before signing; verifier applies identical sort before re-serialize. role_state sets sorted at source via scp_protocol::serde_util.
- **role_state signed verbatim:** ContextRoleState carried + restored as-is (members, assignments+tokens, ceiling, member_capabilities, suspended_capabilities) — closes BLACK-CEIL-01 (no recompute that re-granted suspended-then-widened member). Signature authenticates ORIGIN not WELL-FORMEDNESS, so ceiling grammar still validated post-verify (validate_entries belt).
- **crypto:None decouples sidecar (THE nonce-reuse firewall):** import_context sets `crypto: None` (L7068). member_sequence_numbers restored verbatim but bound to NO live AEAD key. Documented SECURITY note: reset/forged seq CANNOT cause GCM nonce reuse pre-Welcome; fresh Welcome starts counters at 0. Flagged: if a future change populates crypto from imported MLS state, sidecar becomes nonce-reuse vector — MUST re-eval.
- **UCAN/revoked_tokens verbatim:** revoked_tokens restored verbatim (L6997); assignment minted tokens inside role_state, all in signed preimage.
- DoS belt: MAX_CONTEXT_EXPORT_BYTES / WASM_MAX_EXPORT_BYTES bound input before JCS re-canonicalization (amplifier guard), fail-closed.

VERDICT: No blocking findings. Construction sound.
