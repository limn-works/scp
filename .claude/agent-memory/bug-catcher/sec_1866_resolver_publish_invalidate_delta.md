# SEC-1866 resolver re-publish + cache-invalidate delta (FIX A + FIX B)

Reviewed delta `5bb31c62d..origin/fix/1866-direct-execute-trust` (2 fixes on top of already-reviewed PR).

## FIX A (resolvers.rs) — CLEAN
- `IdentityBackedDidResolver.resolution_rt: OnceLock<Runtime>` — one multi_thread (2-worker) rt built lazily, reused forever.
- `resolve_sync` clones the `Handle` then `std::thread::scope`-spawns a fresh OS thread that calls `handle.block_on(...)`. Scope joins before return; `self` (owns rt) borrowed across whole call → rt can't drop mid-use. block_on from a non-worker thread w/ no runtime context = valid (no nested-runtime panic). Concurrent scoped threads block_on same multi_thread rt = fine.
- OnceLock init: build-fallibly-then-`set()`; race loser drops its rt (on the FFI calling thread, NOT a tokio worker → drop allowed). Sound.

## FIX B (PyO3 identity.rs + bridge_instance.rs + runtime.rs) — CLEAN for PyO3
- New `resolver_cache: OnceLock<Arc<DidCache>>` slot on CoreFields, set with the SAME Arc the `DualLayerResolver` was built over (resolver reads `self.cache`, resolver.rs:455). Invalidation hits the right cache. Verified: dht_client + cache + resolver are the 3 consistent slots seeded in `ensure_did_resolver_initialized_on`.
- All 4 single-DID mutations (rotate_key 1546, add_agent 1638, rotate_agent 1730, remove_agent 1822) call `invalidate_resolver_cache` on `result.is_ok()`. migrate (1994) invalidates BOTH old+new DIDs inline (inside block_on, direct await — no nested block_on).
- `rotation_publish_client` returns the SHARED resolver dht_client (throwaway only if resolver uninit — impossible post-identity_create, which always inits resolver before register_identity).
- `initialize_sequence` reads DHT current seq, sets local=max(stored,remote); next publish fetch_add(1) → strictly higher → overwrites. Cache anti-rollback floor (`cached_sequence`) sourced ONLY from cache; after remove() floor=None so higher-seq doc accepted.
- identity_create-family publishes (seq=1) correctly DON'T invalidate (new DID, nothing stale cached).
- TOCTOU publish→invalidate: a concurrent resolve that fetched the OLD doc pre-publish then inserts post-invalidate can re-pollute cache w/ stale seq. SELF-HEALING: next resolve sees DHT higher seq (floor doesn't block it), overwrites. Bounded to one resolution cycle, NOT the multi-day TTL. LOW, inherent to lock-free design.
- Tests: 782 Rust nextest PASS, 12 pytest PASS (incl new test_verify_uses_rotated_active_key_not_stale), clippy clean.

## FINDING (HIGH, cross-bridge gap — recurring "bulk-replacement missing call sites" pattern)
FIX B applied to PyO3 ONLY. NAPI + UniFFI have the IDENTICAL pre-existing stale-resolver defect, NOT fixed:
- **NAPI** `crates/scp-ffi/napi/src/identity.rs`: `make_dht_with_signer` (line 246-250) builds DidDht over THROWAWAY `InMemoryDhtClient::new()`. Used by rotate_key(452), add_agent_key, rotate_agent_key, remove_agent_key, migrate(815). Resolver reads `shared_dht_client()` (ensure_did_resolver_initialized_on:103-118). Rotated doc never reaches resolver DHT; no initialize_sequence; no cache invalidation → resolver permanently serves pre-rotation #active key. (create path IS correct via publish_to_shared_dht_for.) No `set_resolver_cache`/`invalidate_resolver_cache` anywhere in napi/.
- **UniFFI** `crates/scp-ffi/uniffi/src/bridge.rs`: `make_dht_with_signer` (line 305-309) builds DidDht over throwaway `new_ffi_dht_client!()`. Used by rotate_active_key(2198), add_agent_key(2368), remove_agent_key(2459), rotate_agent_key(2550), migrate_identity(14619/14707). Resolver built at 8203 over its own dht_client (not stored for sharing). Same staleness class; no cache invalidation in uniffi/.

Fix: port FIX B (rotation_publish_client → shared resolver dht_client + initialize_sequence + invalidate_resolver_cache) to NAPI and UniFFI rotation/agent-key/migration paths. This is the security purpose of rotation (revoke retired key) being silently defeated on 2 of 3 native bridges.
