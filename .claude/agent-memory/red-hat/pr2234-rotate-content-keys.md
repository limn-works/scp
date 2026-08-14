---
name: pr2234-rotate-content-keys
description: Red-team verdict on PR #2234 fix/rotate-content-keys-review-followup — KEA leaf determinism sort + fail-closed convergent leaves + inline checkpoint counter. No exploitable chain.
metadata:
  type: project
---

PR #2234 `fix/rotate-content-keys-review-followup` (pass-3 final). VERDICT: NO EXPLOITABLE CHAIN — net security improvement.

**Why:** Reviewing governance ban / RotateContentKeys KEA (KeyEpochAdvance) event-log leaf emission.

**Key facts learned (reusable):**
- `checkpoint_events_since` (state.rs:915) is ONLY a threshold trigger for WHEN to snapshot a checkpoint (>=50 events, or >0 && 600s) in queries_helpers.rs `create_checkpoint_if_due_view`. Checkpoint CONTENT (`merkle_root`, `event_count`) is read DIRECTLY from the event log via `event_log_merkle_root()` / `event_log_entries().len()` in `build_checkpoint`. => counter drift only shifts checkpoint CADENCE, never forges Merkle root/count. Counter miscount is a hygiene/robustness concern, NOT a crypto-integrity vector. Remember this for any future "counter drift" finding on this field.
- KEA leaves only populate on the BROADCAST path (`broadcast_context.is_some()`); the MLS/H7 sender-key rotation path has empty `rotated_authors` and `needs_sender_key_rotation=true` only when `broadcast_context.is_none()`. Mutually exclusive → fail-closed KEA loop cannot skip H7 rotation.
- Real member-removal/key-rotation enforcement happens in the Class-S durable commit BEFORE the KEA leaf loop. KEA leaves are provenance RECORDS, not the enforcement. So fail-closed-KEA reports Err while ban is already durably in effect = SAFE direction (secure-but-reported-failed).
- Inline counter bump (`+= 1` after each `.await?` durable append) makes the counter consistent with durable leaves on EVERY exit path including mid-loop Err — strictly more correct than old post-loop coalesced `+= 1 + count`. In-place Class-C mutation is not rolled back on Err → counter always matches durable-leaf count.

**Determinism sort (broadcast/mod.rs):** `rotated_authors`/`key_rotations`/`rotate_all_author_keys` now `sort_unstable_by(author_did)`. author_dids are unique map keys → no ties → sort_unstable fully deterministic. Closes a real cross-replica Merkle divergence (HashMap iteration order randomized per process). All emit callers iterate in-order (`for x in &vec`), no re-sort. Genuine fix.

**Residual LOW (not attacker-exploitable, pre-existing):** fail-closed does NOT roll back already-appended durable leaves on mid-loop failure → replica with a storage failure at KEA[k] keeps [AccessRevoked, KEA0..k-1] durably while erroring; a naive retry re-appends → duplicate leaves. Convergence must come from higher-layer idempotent replay keyed on governance action id, not from this loop. Requires storage-failure injection to trigger → no protocol-level attacker capability. Fail-closed is still BETTER than old best-effort (which silently produced [AccessRevoked,KEA0,KEA2] skipping failed KEA1 with no error).

**Test seam SeedBroadcastAuthor (class_s.rs/commands.rs/handlers/broadcast.rs/supervisor.rs):** ALL `#[cfg(feature="testing")]`. Verified `testing` is NOT a default feature (default=["server"] in scp-ffi + napi + uniffi Cargo.toml) and not transitively pulled by server. Mirrors vetted SeedPeerPseudonym pattern. Not FFI-exported. NOT a production backdoor. Used only by tests/governance_integration.rs (`manager.seed_broadcast_author`).
