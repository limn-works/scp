# ADR-057 T2 client-storage snapshot/restore (scp-client / scp-client-wasm) -- 2026-07-04

Range c102f8222..15ecc84cb (feat e31c063a6 mls primitives + d4c96f87e wiring + fix 189cb7550 + docs 15ecc84cb).
Pass-2 (at 15ecc84cb) verifying pass-1 fixes: **ZERO findings, CLEAN.** All 6 prior-finding fixes REAL + complete.

## Verified architecture (for future slices)
- `ScpClient` (crates/scp-client/src/client.rs): single-tab, `&mut self`, one snapshot blob per context
  via injected `Storage` (put/get/delete/list_keys), enumerate-by-prefix restore (no manifest).
  Keys: `scp-client/ctx/{id}`, `scp-client/pending/{id}`.
- **Poison contract**: persist_context sets `PerContextState.poisoned` on ANY build_and_put error
  (serialize OR backend write) AFTER in-memory ratchet advanced. context_mut/context_ref (Result ops)
  return ContextPoisoned; live_context_ref (Option observers) return None(absent); close_context is the
  escape hatch (bypasses guard). Flag NOT serialized -> restore always unpoisoned (correct: diverged
  state never reached durable). Recreation blocked by ContextAlreadyExists (poisoned ctx still in map).
- **Pending-join binding**: serialize_pending_join binds owner_did+context_id into blob;
  restore_from_storage verifies bound_owner_did==self.did (else StorageIdentityMismatch/8012) AND
  bound_context_id==storage-key-derived id (else StorageCorrupt/8011). ctx/pending key prefixes disjoint;
  crafted blob can't cross identity beyond the storage-AEAD boundary (= stated threat model).
- **ContextSnapshot** (snapshot.rs): §9.9.3 checkpoint = event_log_root recomputed on restore vs recorded
  (in-blob root, torn-write guard ONLY, NOT tamper-resistant). Receive buffer IS persisted
  (deliver-exactly-once; unrecoverable by relay post-ratchet-advance). owner_did verified in restore().
- **Zeroize**: scp-mls ProviderSignerDump (shared core of MlsGroupSnapshot+PendingJoinSnapshot, both now
  pub(crate)) has Drop::zeroize_secrets -> fires on early `?`. Same Drop backported to runtime
  MlsCryptoSnapshot (provider.rs ~240); safe because export/restore use drain/replace/load/borrow, NO
  partial move. ContextSnapshot Drop zeroizes mls_state+sender keys+buffered plaintext.

## Error codes (append-only)
SCP-STORAGE-8010 backend I/O, 8011 corrupt, 8012 identity-mismatch, 8013 poisoned. Deliberately start
at 8010 to avoid scp-kt-android 8001-8003. Documented in sdk-common.md per-number table + regression
test `browser_storage_codes_avoid_the_android_reserved_low_block`.

## Known accepted boundaries (NOT findings)
- Persisted blob = plaintext secrets by design -> storage MUST provide AEAD at rest (tab custody boundary).
- rmp_serde internal buffer holds plaintext transiently (inherent to producing a persistable blob;
  same as native runtime).
- Write-behind FIFO flush ordering is an EMBEDDER obligation (documented in scp-client-wasm/storage.rs +
  close_context comment); crate cannot enforce. Join/Close crash-consistency depend on it.
- committer_timestamp_secs UNAUTHENTICATED on wire (documented SECURITY comment client.rs ~557); MVP
  trusted dumb-pipe only; MUST be signed before real relay wiring. (Pre-existing, in scope of leaf-signing
  slice, not T2.)

GOTCHA: nested worktree path .claude/worktrees/adr057-t1c/.claude/worktrees/adr057-t2 (branch
feat/adr057-t2-client-storage). Bash cwd resets between calls.
