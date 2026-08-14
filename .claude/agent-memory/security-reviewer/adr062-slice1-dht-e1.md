---
name: adr062-slice1-dht-e1
description: ADR-062 Slice 1 (SCP-CAPINJECT-001) DHT nullifier removal audit — feature-graph soundness, fail-closed paths, and the best-effort-publish fail-open regression
metadata:
  type: project
---

# ADR-062 Slice 1 / SCP-CAPINJECT-001 — DHT E1 nullifier removal (branch feat/adr062-slice1-dht-e1, 9ff9eadde..0161e39fe)

Removes InMemoryDhtClient as a DID-resolution default; ships real Pkarr on prod paths; adds `DisabledDhtClient` (publish→Err(Disabled), resolve→Ok(None)); gates InMemoryDhtClient behind `#[cfg(any(test, feature="testing"))]`.

**Why:** InMemoryDhtClient is the §17.17.3 nullifier (silent publish success + resolves nothing).

**How to apply / findings:**
- G1 feature-graph invariant HOLDS: `scp-dht/testing` appears ONLY in `testing=[...]` lists + dev-deps, never in default/server/resolvers/production-dht. All prod deps use `features=["production-dht"]` (Pkarr, non-optional). `dep:scp-testing` (via allow_in_memory_custody) does NOT pull scp-dht/testing (scp-testing has scp-dht only as dev-dep). Shipped graph => InMemoryDhtClient not nameable. VERIFIED SOUND.
- Fail-closed VERIFIED: `ClientDhtConfig::into_client` (scp-ffi/common/src/dht.rs) only ever builds Pkarr, returns DhtInitError, never substitutes in-memory. napi + uniffi `build_ffi_dht_client` fail-closed with IDENT_1001; `make_dht_with_signer`/shared-client getters `ok_or_else` IDENT_1001. No `unwrap_or`→in-memory anywhere. `start_node_in_memory(None)` returns Err(AutoGenerateUnavailable) in shipped builds.
- **TOP FINDING (MEDIUM, fail-open regression):** `publish_did_document_best_effort` (scp-node/src/lib.rs:3190) swallows publish Err for ALL no-domain nodes, NOT just Disabled. `build_no_domain_inner` is generic over D and reached by production `Node::start` (Reach::NatTraversal) + domain-TLS-failure fallthrough — so a genuine Pkarr publish failure is downgraded to a warn log; node starts & reports success but DID is unpublished/undiscoverable. Prior code was fatal (`.publish().await?`). NOT a resolve-fabrication nullifier (remote resolves honestly fail), but violates ADR-062 M3 "fail-closed everywhere." The docstring's "leans on periodic republish" is FALSE for stable-tier nodes: `apply_tier_change`/`spawn_tier_reevaluation` republish ONLY on NAT tier change (lib.rs:2388-2429), so a stable node never self-heals. FIX: discriminate `DhtError::Disabled` (non-fatal) from genuine Pkarr failures (fatal on Production), or gate best-effort on DhtMode.
- SHARED_DHT_CLIENT (napi/uniffi process-global OnceLock<Arc<FfiDhtClient>>): no prod cross-tenant leak — Pkarr client is stateless transport, each publish carries its own BEP44 signature from caller custody. Init race benign in prod (dup stateless Pkarr). The dropped `Once` guard (was in old ensure_did_resolver_initialized_on) reintroduces a benign resolver/SHARED divergence race that only matters for the stateful in-memory testing arm. LOW observation.
- napi identity rotate/add/remove/migrate now call `initialize_sequence` before publishing (BEP44 monotonic overwrite) — correct, mirrors PyO3.
