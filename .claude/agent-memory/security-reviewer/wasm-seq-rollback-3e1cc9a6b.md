---
name: wasm-seq-rollback-3e1cc9a6b
description: WASM send_message per-sender sequence rollback on encrypt failure — security audit CLEAN, no nonce/AAD reuse
metadata:
  type: project
---

# WASM send_message sequence rollback (commit 3e1cc9a6b, slice1-roles) — 2026-06-24

Audit of: `send_message` now rolls back the reserved per-sender MLS sequence on any
encrypt-path failure (saturating_sub(1)), mirroring native
`MembershipState::rollback_sequence_number`. CLEAN / ship-ready.

**Why no AEAD reuse from rollback (the core question):**
- Sender-layer AEAD = AES-256-GCM, `scp-protocol/src/crypto/sender_keys/encrypt.rs::encrypt_sender_layer`.
  The 12-byte **nonce is RANDOM per invocation** (`OsRng.fill_bytes`), NOT derived from `sequence`.
  `sequence` (and epoch/context_id/sender_did) feed ONLY the **AAD** (`build_sender_aad`,
  length-prefixed BE). So AEAD nonce-uniqueness does not depend on sequence monotonicity at all.
- A rolled-back seq value reused by a later successful send is harmless: the failed send produced
  NO transmitted ciphertext (error returned before `push_event`/record). No two TRANSMITTED messages
  ever share (epoch, seq). Even if they did, the random nonce makes the AEAD safe; AAD reuse only
  means two messages would authenticate the same metadata tuple — not a confidentiality/integrity break.
- Net: rollback PREVENTS a sequence gap that two honest members would derive differently (equivocation
  surface §9.9.3), strictly improving convergence. No security regression.

**Borrow safety:** fallible work wrapped in a closure borrowing `ctx.crypto` mutably; rollback touches
`ctx.member_sequence_numbers` only AFTER the closure returns. Sequential `&mut`, compiles clean
(`cargo clippy -p scp-ffi-wasm --target wasm32-unknown-unknown` OK).

**Entry-cleanup correctness:** `seq_was_present` captured before `or_insert(0)`. On failure, if entry
was freshly created (was absent) and rolls back to 0, it's removed → map matches pre-send shape.
Existing entries decrement only. Sound.

**publish_broadcast unchanged & correct:** its `+=1` is followed only by infallible `push_event`
(no fallible `?` between increment and record), so no rollback needed. Verified.

**Test:** `send_message_failure_does_not_advance_sequence_wasm` drives REAL crypto
(`WasmCryptoState::new_for_context`): success→counter 1, invalid-base64 send fails CRYPTO_4001,
counter stays 1. Passes on host target. Mutation guard sound by construction (disable saturating_sub
→ entry stays 2, removal branch can't fire → reads Some(2) → RED).

**Rest of sweep (unchanged by this commit, re-confirmed):**
- Authz: positive-grant `member_has_capability(MessagesWrite)` is suspension-aware (single check covers
  read-only-role reject AND suspended-write reject); membership check before; economy fail-closed (paid
  context → WASM hard-reject SCP_ECON_WASM_CANNOT_VALIDATE_SPENDING_UCAN). No escalation, no split-brain.
- Export/import trust: untouched. §5.3.1.1 ceiling grammar enforced at deserialize (`try_from` +
  `validate_entries`). Comment-only fix: modify path → SCP-VALID-7000 (Validation); import path →
  SCP-CTX-2032 (deserialize). Inline comment now matches already-fixed block comment + docstring. Accurate.
- Secrets/leakage: error messages carry codes + benign context (DIDs, base64 parse err) — no key material.

**GOTCHA:** wasm32 test target fails to link `scp_identity` (pre-existing harness limit, unrelated).
Run wasm `mod tests` on HOST target: `cargo test -p scp-ffi-wasm <name>` (no --target).
