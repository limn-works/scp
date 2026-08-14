---
name: adr057-t2-client-storage
description: ADR-057 T2 scp-client snapshot/restore storage + poison/DRY/renumber fix batch — review outcome (clean, LOW doc only)
metadata:
  type: project
---

# ADR-057 T2 client-storage review (branch feat/adr057-t2-client-storage, base c102f8222)

Reviewed range c102f8222..15ecc84cb (feat d4c96f87e + fix 189cb7550 + docs 15ecc84cb).

**Verdict: CLEAN.** No CRITICAL/HIGH/MEDIUM. Only LOW doc-completeness.

## Context-poisoning pattern (new, sound)
- `PerContextState.poisoned` (in-memory only, NOT serialized). `persist_context(&mut self)` is the SOLE route that advances-then-persists; sets flag on ANY build_and_put error (serialize OR backend write) before returning Err. Correct: even a serialize failure means durable < live.
- All mutating ops route through `context_mut` (rejects poisoned → ContextPoisoned). Result-queries via `context_ref`. Pure Option observers via `live_context_ref` (poisoned→None/absent). `close_context` bypasses guard (idempotent deletes then remove) — safe escape hatch. No resurrection path (flag only cleared at construction/restore).
- `context_ids()` deliberately lists poisoned (documented, line 813-820). drain_events exactly-once preserved across reconstruction (failed persist keeps durable pre-drain buffer). Tested: failing_put_during_send_poisons_context_and_reconstruction_recovers.

## ProviderSignerDump DRY (scp-mls) — behavior-identical
- MlsGroupSnapshot/PendingJoinSnapshot now embed shared `ProviderSignerDump {mls_storage_entries, signer_bytes}`. Wire format is now NESTED vs d4c96f87e's flat — but self-consistent round-trip, and scp-mls snapshots are unreleased (both commits same PR), so NO compat issue. Drop-zeroize on every path + explicit double-zeroize = safe. No partial moves (mem::take on String bindings only; provider_signer via &mut rebuild) — Drop compiles (E0509 guarantee).

## Native runtime MlsCryptoSnapshot Drop backport — additive-only
- Only ADDED zeroize_secrets()+Drop. No format change → KAT/legacy fixtures unaffected. All restore-path field access is drain(..)/mem::take(&mut)/&ref/Copy — no move-out (compiles). Verified: 64 provider tests + crypto_state export/restore roundtrip + wrapping_key_persisted + legacy tests PASS.

## Renumber 8001-3 → 8010-13 — complete
- scp-client-wasm error.rs maps StorageBackend=8010, StorageCorrupt=8011, IdentityMismatch=8012, ContextPoisoned=8013. sdk-common.md table accurate. Numeric guard test (browser_storage_codes_avoid_the_android_reserved_low_block). No stale active 8001-3 (only reservation docs). 8000 selection code untouched.

## Pending binding — correct
- serialize_pending_join(&provider,&signer,self.did(),context_id) sole caller client.rs:329. restore verify order: owner (IdentityMismatch) THEN context-vs-key (StorageCorrupt), both fail-closed. Only 2 callers repo-wide, both updated. structs now pub(crate).

## LOW findings (doc-only)
1. scp-client-wasm lib.rs method `# Errors` docs systematically omit the new 8010/8013 codes the core now surfaces (mlsEpoch/localSenderKeyBytes/createContext/addMember/sendMessage/receiveMessage/drainEvents/installSenderKey). Behavior correct (map_err forwards all); docs stale. Also memberDids/eventLogRoot wasm docs say "undefined if not held" without "or poisoned".
2. spec 17 names concrete storage key `scp-client/pending/{context_id}` (impl detail in protocol spec) — borderline per feedback_no_impl_details_in_specs.

Tests: scp-client 31, scp-mls 144, scp-runtime provider 64, scp-client-wasm 9 — all pass. wasm32 compiles. clippy clean. Fence intact (no tokio/scp-runtime/scp-identity).
