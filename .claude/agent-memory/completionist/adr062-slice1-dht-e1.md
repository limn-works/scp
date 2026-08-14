---
name: adr062-slice1-dht-e1
description: Completeness verdict + gap-hiding lessons for SCP-CAPINJECT-001 (ADR-062 Slice 1, DidDht in-memory default removal / ship Pkarr)
metadata:
  type: project
---

SCP-CAPINJECT-001 (ADR-062 Slice 1, DHT E1) verified COMPLETE at commit e54de4fae
(PR #2150, branch feat/adr062-slice1-dht-e1). All 15 ACs (AC0–AC14) met.

**Why this matters:** removes the `= InMemoryDhtClient` DidDht default (a §17.17.3
resolve nullifier) so the shipped graph cannot name the in-memory DHT; ships real
Pkarr on all prod FFI paths; adds fail-closed `DhtMode::Disabled`, gates
`DhtMode::Memory` test-harness-only.

**How to apply / gap-hiding lessons for future DHT/feature-gate slices:**
- The soundness proof is: `InMemoryDhtClient` is `#[cfg(any(test, feature="testing"))]`
  in scp-dht, gated behind a `scp-dht/testing` feature that appears ONLY in `testing = [...]`
  feature lists and `[dev-dependencies]` — NEVER in default/server/resolvers. Verify this
  with `grep -rn 'scp-dht/testing' --include=Cargo.toml`, then confirm a bare
  `cargo build --workspace` (no features) compiles → feature-absence == type-absence.
  The bare build passing IS the end-to-end proof no production path references the type.
- scp-testing carries `scp-dht = { features=["testing"] }` as a NORMAL dep (lib-level
  helpers use InMemory); all other consumers use it only in testing-feature + dev-deps.
  scp-runtime correctly does NOT list scp-dht/testing in its testing feature — its InMemory
  usage is all `#[cfg(test)] mod tests`, so the dev-dep alone suffices. Do not flag that as a gap.
- Two AC greps are written imprecisely (literal grep returns 0 / >0 but intent is met):
  (1) bridge_instance.rs field is `dht_client: OnceLock<Arc<crate::dht::FfiDhtClient>>` —
  the AC grep omits the `crate::dht::` path qualifier. (2) server.rs `InMemoryDhtClient::new()`
  literally returns 2 lines but both are under `#[cfg(any(test, feature="testing"))]`; the
  production arm (`#[cfg(not(...))]`) uses `ClientDhtConfig::default().into_client()?`.
- Rotation cache-invalidation (round-1 finding A) is the real completeness risk: napi + uniffi
  each wire `invalidate_resolver_cache` into all 5 rotation paths (rotate_active/add_agent/
  rotate_agent/remove_agent/migrate) after publish, and both bridges have a REAL
  `rotate_key_invalidates_resolver_cache` test that seeds the resolver cache, rotates, and
  asserts the entry is gone. pyo3 was pre-existing.
- Out-of-AC edits were all fix-driven, not scope creep: ci.yml adds `,testing` to Python/napi
  SDK test builds (root-cause fix for round-1 Python-governance + TS-timeout failures — multi-party
  tests need the in-memory DHT seam for same-process DID resolution); `shared_did_method()` +
  identityLoad throwaway-client removal = finding A/D; +630 uniffi lines = finding-A plumbing + tests.
- Observation (NOT a finding for this slice): `RepublishManager<D, R: RelayPublisher =
  InMemoryRelayPublisher>` still has an in-memory RELAY default — analogous nullifier but
  relay is Slice 11 scope, not DHT E1.
