# Storage Foundation (ADR-049 Steps 0-4, refactor/actor-per-context)

Review of c1bfeb418..17a6f2eb1. Most of the unit is solid (fail-closed
SQLCipher, salt brick-prevention, single-store invariant, build_actor_deps
self-sourcing all verified + tested). Findings:

## TS serializeStorageConfig neither-key TypeError (MEDIUM)
- bindings/typescript/src/scp.ts serializeStorageConfig: sqlite branch checks
  `"passphrase" in config` first, else falls to
  `typeof config.key === "string" ? config.key : Array.from(config.key as Uint8Array)`.
  If a dynamically-built `{type:"sqlite", path}` (no key, no passphrase) reaches it,
  `Array.from(undefined)` throws a raw TypeError instead of clean SCP-VALID-7005.
- Tests for both/neither call `addon.SCP.withStorage(JSON.stringify(...))` DIRECTLY,
  bypassing serializeStorageConfig — so the serializer path is untested for this case.
- Also: both-supplied dynamic config → serializer silently drops `key`, forwards only
  passphrase; NAPI never sees "both" → mutual-exclusion fail-closed subverted at TS layer.

## Over-strict null handling in JSON parse (LOW)
- NAPI scp.rs / PyO3 scp.rs: `(Some(_), Some(_))` both-check fires even when key or
  passphrase is JSON `null` (`config_obj.get("key")` returns Some for null value).
  Fail-safe (rejects), but error msg misleads. Minor.

## Verified CORRECT (no bug):
- build_actor_deps self-sources every ActorDeps field; mls/hpke transitive via
  crypto.mls_backend()/hpke_backend() (ptr-eq tested). local_dids line is a fresh
  ArcSwap snapshot — but byte-identical to pre-refactor, NOT introduced here (pre-existing
  snapshot-staleness concern; actor reads deps.local_dids.load() which won't see later
  supervisor identity_add. Out of diff scope.)
- key_package_store_for double-checked lock: correct, spawn is sync fn (no deadlock,
  no double-spawn). write_lock not reentrant-held across it.
- with_providers OnceLock: mls_storage set synchronously before Arc returned; can't be
  read unset by build_actor_deps. All 3 bridge init paths fail-closed on mls_storage_ref()=None.
- build_event_log_provider 3-tuple: storage_handle is the SAME Arc the repo wraps
  (Arc::clone). Test handle_and_repo_share_one_store proves one store. No drop-order bug.
- SqliteStorage::with_passphrase + load_or_init_salt: brick-prevention (db-exists/salt-missing)
  checked in BOTH; first-match returns; salt persisted before db create (reverse harmless).
  Wrong-passphrase fail-closed tested + passes.
- file.rs: Argon2 consolidated into shared kdf; SALT_LEN=16=ARGON2_SALT_LEN. O_EXCL atomic.
