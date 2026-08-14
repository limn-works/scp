---
name: sec1866-resolver-cache-rotation
description: SEC-1866 delta — rotation/agent-key/migrate publish to SHARED resolver DHT + invalidate resolver_cache; revocation guarantee analysis (PyO3 only)
metadata:
  type: project
---

# SEC-1866 resolver-cache rotation delta (origin/fix/1866-direct-execute-trust @ base 5bb31c62d)

PyO3-ONLY change (despite shared-crate touch). Files: bridge_instance.rs (resolver_cache OnceLock slot), resolvers.rs (long-lived resolution_rt, NOT cache-related), identity.rs (publish to shared client + invalidate), runtime.rs (invalidate_resolver_cache helper), test_scpid.py.

**Why:** before this, rotate built `DidDht` over a THROWAWAY `InMemoryDhtClient` → resolver kept serving stale pre-rotation doc → old #active key stayed live (rotation revocation defeated). Fix: publish into the per-instance resolver DHT client (resolver_dht_client) at higher BEP44 seq (initialize_sequence → max(remote) then fetch_add(1)) AND cache.remove(did) after success.

**Architecture (load-bearing):**
- `DualLayerResolver.resolve` Step 1 returns CACHED doc WITHOUT consulting DHT if cache entry fresh (multi-day TTL). So cache.remove() is REQUIRED — higher-seq DHT publish alone is insufficient while a fresh cache entry masks it.
- Two seq guards: (1) DualLayer Step5 `cache.cached_sequence` rollback reject — DISARMED for the DID right after remove() (returns None), but (2) `IdentityBackedDidResolver.seen_sequences` in-process ratchet is SEPARATE map, NOT cleared by invalidate → still rejects lower-seq replays. seen_sequences advances lazily on next resolve via check_sequence (all 4 resolve trait impls call it).
- cache.insert rejects seq < existing; remove() then next resolve re-fetches higher-seq from DHT and re-inserts.

**5 questions — all CLEAN:**
1. New #active served, old rejected: YES. publish higher seq + remove → next resolve fetches new doc, extract_public_key("active") returns rotated key; old-key sig fails. Window publish→invalidate is benign: a resolve landing in the gap re-caches the OLD doc, but invalidate then removes it; a resolve AFTER invalidate fetches the higher-seq new doc. No persistent stale-serve.
2. Downgrade: seen_sequences advances on resolve; lower-seq re-publish rejected at both DualLayer Step5 (once re-cached) and seen_sequences ratchet (persistent). initialize_sequence guarantees strictly-higher publish.
3. Migrate invalidates BOTH old_did and new_did (identity.rs ~1996). Old-DID alsoKnownAs republished at seq from initialize_sequence(old_did). Correct.
4. Fail-closed: rotate/agent/migrate map_err logs tracing::warn AND propagates Err; invalidate only runs on result.is_ok(); failed publish → op fails (reject), no silent stale-serve. Migrate cache.remove inside same async block after registry swap.
5. resolution_rt change (long-lived shared DID-resolution runtime replacing per-call current-thread rt) is perf, NOT cache; affects all non-WASM but no posture change — still spawns clean scoped thread for block_on, deadlock-free. resolver_cache slot is unused by NAPI/UniFFI (they don't call set_resolver_cache or the rotation publish path in this delta) → no change for them; their rotation paths NOT touched here (potential parity gap = OBSERVATION, not a regression in this delta).

OBSERVATION (not blocking): invalidate_resolver_cache is PyO3-only. If NAPI/UniFFI have their own rotate→throwaway-client pattern, they retain the original bug. This delta only fixes PyO3. Bridge-symmetry / FIX-B (#214) tracks the cross-bridge convergence separately.
