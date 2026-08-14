---
name: adr062-slice1-dht-e1-round2
description: ADR-062 Slice1 (SCP-CAPINJECT-001) round-2 re-review — resolver cache invalidation + initialize_sequence fail-closed VERIFIED SOUND
metadata:
  type: project
---

# ADR-062 Slice 1 / SCP-CAPINJECT-001 round-2 (branch feat/adr062-slice1-dht-e1, e54de4fae)

Round-1 findings A (cache invalidation napi+uniffi) and C (initialize_sequence fail-closed) VERIFIED RESOLVED. No new crypto findings.

**Why:** rotation without cache invalidation kept serving pre-rotation #active key for multi-day TTL (fail-open on revocation); swallowed resolve error republished beneath live BEP44 record.

**How to apply:** when reviewing further ADR-062 slices touching resolver/rotation:
- Canonical-cache invariant: resolver MUST be built over `bi.core.resolver_cache()` (OnceLock set-if-unset then RE-READ winner), and `invalidate_resolver_cache` targets that same Arc. `DualLayerResolver::resolve` does `Arc::clone(&self.cache)` then `cache.get` (resolver.rs:461); DidCache is `Mutex<HashMap>` interior-mutable so remove on any clone hits all. Set-then-reread pattern makes client+cache winners independently consistent even under concurrent first-init.
- napi client = process-global SHARED_DHT_CLIENT (publish + resolve share it); cache = per-instance. uniffi client+cache both per-instance (rotation_publish_client = bi.core.dht_client()). Publish-client == resolve-client on both.
- Coverage: napi 5 ops (rotate_active/add/rotate/remove agent + migrate BOTH dids). uniffi rotate×2 branches + add/remove/rotate agent + migrate×2 branches (both dids each). pyo3 ref = 4 helper calls + inline migrate both-dids (cache.remove old+new @2065-66). Full parity.
- initialize_sequence (dht.rs:807): `Err(e)=>return Err(e.into())` → IdentityError::DhtResolveFailed. Only Pkarr::resolve returns Err; Disabled/InMemory resolve always Ok(None)/Ok(record) → Disabled-node startup + in-memory tests + honest first-publish (Ok(None)=seq0) unaffected. Create path uses publish_to_shared_dht_for(seq=1) NOT initialize_sequence, so create never fail-closes. Only re-publish paths (rotate/migrate/republish) fail-closed on genuine resolve failure — correct revocation-safety.

**Ordering hazard (INFORMATIONAL, not blocking, pre-existing in pyo3 ref):** invalidate-after-publish leaves a bounded re-cache-stale race — a concurrent resolve whose DHT read straddles the publish (reads old seq N) AND whose cache.insert lands after the invalidate re-populates a stale entry (insert has no monotonicity guard when entry absent post-remove, cache.rs:184). Bounded by TTL, not a forgery (old doc validly signed), inherent to invalidate-after-write w/ concurrent reads. publish→invalidate is the CORRECT order (invalidate-before-publish strictly worse). If strict read-after-rotation ever required: version-gated invalidation (stamp min-seq floor). Out of scope.

Tests pass: initialize_sequence_fails_closed_on_dht_resolve_error (scp-identity), rotate_key_invalidates_resolver_cache (napi + uniffi). Test proves cache-removal (load-bearing); stops short of asserting re-resolved key identity (DHT-has-new-doc covered by rotation round-trip tests). Minor test-strength note only.
