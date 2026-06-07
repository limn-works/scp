# PyO3 Passphrase Storage Restore + Redacting Debug (ed6290851, 2026-06-04)

Commit "restore PyO3 passphrase storage + attach supervisor on configure_local_transport"
on branch refactor/actor-per-context. Reviewed delta `git diff 797b59616 ed6290851`.

## Verdict: CLEAN. No security findings. All 6 scrutiny points sound.

1. **Fail-closed passphrase path**: `with_storage_py` Passphrase arm → `SqliteStorage::with_passphrase`
   (scp-platform/src/sqlite/mod.rs:226). Returns `StorageInitError::SqliteOpen` on bad passphrase /
   open failure — identical mapping to Raw arm. NO silent in-memory degrade. `with_passphrase` itself
   fails closed: refuses to regenerate salt beside existing DB (would brick), rejects wrong-length salt,
   delegates to `new` which lets SQLCipher reject wrong key on first query. Passphrase wrapped in
   Zeroizing<String> from dict boundary, dropped after construction. Round-trip + wrong-passphrase
   tests present (parity with NAPI).
2. **Exactly-one-of**: scp.rs match on (key_item, passphrase_item): both→ValidationError, neither→
   ValidationError, each single→correct variant. Messages are STATIC strings, never echo passphrase.
   Tests for all 4 cases.
3. **Redacting Debug**: hand-written `impl Debug for SqliteKeyMaterial` on all 3 bridges (PyO3/NAPI/
   UniFFI). Raw → "<redacted N bytes>", Passphrase → "<redacted>". `#[derive(Debug)]` removed from the
   enum on all 3. StorageConfig still derives Debug BUT composes through the custom impl (redaction holds).
   No production code logs config/key via {:?}.
4. **Dev-affordance**: `init_context_manager_with_local_transport` sets `new_in_memory_encrypted()` only
   when `storage_provider().is_none()` (OnceLock first-set-wins). Mirrors `init_context_manager_for_test`
   exactly. Does NOT clobber a user's sqlite (slot already set at construction). Documented in
   scp-ffi/CLAUDE.md as `ensure_default_instance_storage` pattern. Does not weaken with_storage(sqlite)
   fail-closed guarantee.
5. **No secret leakage**: StorageInitError::SqliteOpen carries only path + platform Display string.
   kdf errors are argon2 lib codes, never passphrase/derived-key. kdf module documents "MUST NOT log".
6. **Enforcement file**: sdk-capability-matrix.json — only the with_storage_sqlite notes string changed
   (passphrase variant doc + stale ContextManager→Supervisor ref fix). Boolean count diff = ZERO across
   all SDKs. No true→false flip, no entry removed.

## Compile state
- `cargo check -p scp-ffi` (PyO3, the fix target): CLEAN.
- `cargo check -p scp-ffi-napi -p scp-ffi-uniffi`: pre-existing actor-refactor breakage
  (crate::testing unresolved, missing identity_registry, missing *_c_callback symbols). ZERO errors
  reference SqliteKeyMaterial/Debug. The Debug-impl changes are trivially correct in isolation.

## Gotcha for future sessions
- Worktree is `.claude/worktrees/actor-per-context` @ ed6290851. The Bash tool resets cwd; a bare
  `cd /Users/alec/Developer/limn/scp` lands in the MAIN worktree (different HEAD/code). ALWAYS operate
  in the worktree path or use `git show <sha>:<file>`. Initial confusion: `with_passphrase` appeared
  missing because I was grepping main, not the worktree.
- `with_passphrase` lives ONLY in scp-platform/src/sqlite/mod.rs. FileKeyCustody (file.rs) has its own
  separate Argon2id path; don't conflate.
