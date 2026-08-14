---
name: adr062-slice1-dht-e1
description: ADR-062 Slice1 SCP-CAPINJECT-001 DHT E1 retype crypto review — rotation cache-invalidation bridge asymmetry finding
metadata:
  type: project
---

# ADR-062 Slice 1 / SCP-CAPINJECT-001 (DHT E1) crypto review (branch feat/adr062-slice1-dht-e1, 9ff9eadde..0161e39fe)

Removes `DidDht<D=InMemoryDhtClient>` default param + `impl Default` + `new()`; shared `enum FfiDhtClient{Pkarr, #[cfg(testing)]InMemory}`; `ClientDhtConfig::into_client -> Result<_,DhtInitError>` fail-closed; rotation routed through process-shared client + `initialize_sequence` bootstrap. **Why:** in-memory DHT was a §17.17.3 resolve nullifier reachable by omission.

## SOUND (verified unchanged / correct)
- Pre-rotation commitment `SHA-256(revealed_key)==commitment` (dht.rs:1160-1192) + migrate (1457+) + rotation event chain: NOT in diff, byte-unchanged.
- BEP44 signer binding: publish_document signs `bep44_signable(value,seq)` with `identity.identity_key.id()`; record pubkey = extract_public_key(&did) = identity key (never rotates). No signer/key mixup across FfiDhtClient enum arms (delegates same pk,sig,value,seq).
- BEP44 monotonicity: rotate uses `current_sequence+1`; initialize_sequence sets self.sequence = max(store, DHT record.seq) before each rotate/agent/migrate publish so republish strictly overwrites. Concurrent same-identity rotation = lost-update no-op, not a security break (LOW).
- DisabledDhtClient: resolve→Ok(None) honest-not-found (never fabricated doc), publish→Err(DhtError::Disabled) fail-closed. Cannot forge/suppress rotation proof; DualLayerResolver relay arm still runs.
- verify_did free fn reimpl via extract_public_key(...).is_ok_and(byte-eq): equivalent to trait verify — canonicality guard (zbase32 round-trip, dht.rs:2796-2804) preserved. Public-key compare, timing irrelevant.

## FINDING (HIGH, bridge asymmetry) — napi + uniffi rotation paths do NOT invalidate resolver cache
- Resolver (resolver.rs:461) Step-1 SHORT-CIRCUITS on any cached entry within TTL (24h active / 7d inactive, cache.rs) — returns cached doc WITHOUT re-querying DHT.
- pyo3 (reference) invalidates on ALL rotation paths: `invalidate_resolver_cache(&self.inner,&did,rt)` at scp-ffi/src/identity.rs 1541/1633/1725/1817 (PRE-EXISTING at base). Shares resolver cache via set_resolver_cache.
- napi: has NO invalidate fn/plumbing (runtime.rs no resolver_cache); make_dht_with_signer uses fresh DidCache::new(); rotate updates registry doc but never invalidates resolver cache. This slice ADDED initialize_sequence ("Mirrors the PyO3 bridge") but omitted the cache-invalidation half.
- uniffi: has set_resolver_cache (bridge.rs:9063) but NO invalidate_resolver_cache call anywhere; make_dht_with_signer fresh cache (363).
- IMPACT: after self-DID rotation, if local resolver cached the self DID (UCAN issuer self-resolution), the retired (possibly compromised) #active key keeps validating locally for up to TTL. napi make_dht_with_signer docstring CLAIMS "the retired key is rejected on the next resolve" — FALSE for a cached DID. Bounded (local cache only; remote parties read real Mainline DHT which has new doc). FIX: add invalidate_resolver_cache to napi (needs runtime plumbing like pyo3) + uniffi (plumbing exists) on all 5 rotation paths.

## FINDING (MEDIUM) — initialize_sequence swallows DHT resolve error (fail-open on revocation)
- initialize_sequence (dht.rs:778-790) logs+swallows DHT resolve Err → best_seq stays 0. On transient Mainline failure at rotation time, republish built on stale seq → Pkarr/Mainline rejects lower-seq write by BEP44 monotonicity → old key stays live on DHT, rotation silently non-propagating. Pre-existing best-effort semantics, newly on the rotation path. Recommend fail-closed (surface error) on rotate/migrate.
