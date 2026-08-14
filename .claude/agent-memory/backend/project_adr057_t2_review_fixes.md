---
name: project-adr057-t2-review-fixes
description: ADR-057 T2 client-storage 8-lens review pass-1 fix batch (16 items) — context poisoning design, scp-mls snapshot DRY/format, poison-guard placement
metadata:
  type: project
---

ADR-057 T2 (scp-client storage wiring) review pass-1 batch — 16 findings applied, all verified, committed on `feat/adr057-t2-client-storage` (stacked on d4c96f87e): code fix `189cb7550`, artifacts `15ecc84cb`. NOT pushed, no PR (per instruction). Worktree = nested `.claude/worktrees/adr057-t1c/.claude/worktrees/adr057-t2`.

**Why:** validated adversarial-review findings on the T2 slice (context divergence on failed persist, error-code collision, unbound pending blob, missing zeroize-on-early-return, spec self-contradiction).

**How to apply / non-obvious decisions:**
- **Context poisoning** (the load-bearing fix): `PerContextState.poisoned` (pub(crate), NOT serialized — restored context is unpoisoned by construction). `persist_context` is `&mut self`; on ANY Err it sets poison then propagates (split into `build_and_put` + poison bookkeeping to avoid closure-capture-self). `context_mut`/`context_ref` reject poisoned with new terminal `ClientError::ContextPoisoned{context_id}` (=SCP-STORAGE-8013). DESIGN SPLIT: Result-returning queries (mls_epoch, local_sender_key_bytes) are LOUD (ContextPoisoned); Option-returning observers (member_dids/event_log_root/leaf_count/leaf_hashes) return `None` via new `live_context_ref` (avoids Option→Result ripple into wasm getters + ~10 test sites; still "doesn't mislead"). `close_context` deliberately does NOT go through the poison guard = escape hatch. `context_ids()` lists poisoned too.
- **scp-mls snapshot format is FREE to change** (serialize+deserialize both in-build, no cross-build KAT) — so DRY refactor onto private `ProviderSignerDump{mls_storage_entries,signer_bytes}` (owns Debug-redact + zeroize + Drop + capture/rebuild) is safe. But the NATIVE runtime `MlsCryptoSnapshot` (scp-runtime/src/crypto/mls/provider.rs) flat layout IS byte-locked by committed legacy KAT fixtures → deliberately NOT unified (documented in both crates + ADR). Runtime `MlsCryptoSnapshot` got a Drop{zeroize_secrets} too — SAFE only because export/restore never partially-move a field (all drain/replace/borrow-in-place; a partial move of a Drop type = compile error).
- **PendingJoinSnapshot** gained owner_did+context_id; `serialize_pending_join(provider,signer,owner_did,ctx)`, `restore_pending_join`→4-tuple `(provider,signer,owner_did,ctx)`; scp-client verifies both (StorageIdentityMismatch / StorageCorrupt) — verification lives at the scp-client layer, not scp-mls.
- **Error codes**: browser storage moved off Android-reserved 8001-8003 → 8010(backend)/8011(corrupt)/8012(identity)/8013(poisoned). Regression test checks numerically (>=8010), NOT via literal "SCP-STORAGE-800x" strings, so the grep-guard stays 0. Allocation table added to sdk-common.md.
- **ADR-057 has NO "T1c-a" bullet** (only T1c, describing scp-dht extraction); `scp-dht` crate is ABSENT from this T2 worktree. Marked T2 "(landed in this change set)" per T1 precedent; left T1c as "follows".
- **Spec §17.6** (NOT §17.5 — that's Serialization) "Browser Clients Run Storage In-Process" was self-contradictory (claimed receive-buffer + pre-join material "not persisted" while code persists both) — rewritten to one model.

Full green: workspace build, CI clippy all-features -D warnings, fmt, wasm32 fence (+--tests scp-client-wasm), nextest 9578 passed / 0 failed, no-shim + protocol-deps gates, `cargo tree -p scp-client` free of runtime/identity/platform/tokio, fuzz nightly check (+zeroize edge in lock). See [[project-adr057-3-client-wasm]], [[project-adr057-2-scp-client]].
