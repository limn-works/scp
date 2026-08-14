---
name: adr062-slice1-dht-e1-round2
description: ADR-062 Slice 1 (SCP-CAPINJECT-001) DHT E1 fix — round-2 re-review verdict, all round-1 findings resolved, no regressions
metadata:
  type: project
---

# ADR-062 Slice 1 / SCP-CAPINJECT-001 (DHT E1) — Round-2 re-review (2026-07-15)

Branch feat/adr062-slice1-dht-e1, PR #2150. Fixes delta 0161e39fe..e54de4fae. VERDICT: all round-1 findings RESOLVED, no security regressions. CLEARED.

## Round-1 findings status
- A (napi+uniffi cache invalidation) RESOLVED — `invalidate_resolver_cache` added on all 5 rotation paths + migrate (both DIDs) in napi & uniffi; napi runtime plumbing (resolver_cache OnceLock on CoreFields) added.
- B (best-effort publish swallow) RESOLVED — `publish_did_document_best_effort` → `publish_did_document_for_mode(dht_mode,…)`; DhtMode threaded ConfigTail→build_node_domain(fall-through)→build_no_domain_inner. Disabled SKIPS publish (info only); Production/Memory publish FATAL via `?`. Match exhaustive both configs (Memory variant + arm both `#[cfg(any(test,feature="testing"))]`) — compile-verified prod+testing. Tests: no_domain_production_publish_failure_fails_closed / _disabled_starts_without_publishing.
- C (initialize_sequence swallow) RESOLVED — dht.rs:790 `Err(e)=>return Err(e.into())`; Ok(None) still seq-0 first publish. DisabledDhtClient.resolve=Ok(None) so Disabled rotation NOT broken. Test initialize_sequence_fails_closed_on_dht_resolve_error.
- E (ADR framing) RESOLVED — ADR-062 A2↔A4 now honestly states self-DID resolution regression (co-located governance inert Slice1→Slice11).
- F (Once TOCTOU) RESOLVED — get-or-init (build candidate → OnceLock set-if-unset → RE-READ winner) for shared client (napi process-global) + per-instance DidCache (napi+uniffi) + uniffi per-instance dht_client. set_resolver_cache/set_dht_client/init_shared_dht_client all set-if-unset (bridge_instance.rs:2184 OnceLock.set). No orphan-client/cache bind under concurrent init; loser resolver still wraps canonical.
- D (napi SHARED_DHT_CLIENT global) deferred per orchestrator (outside ACs), ratchet-allowlisted, not a nullifier (ships Pkarr). Correctly still deferred.

## SOUND items re-confirmed post-churn
- FfiDhtClient::InMemory `#[cfg(feature="testing")]` — absent from shipped enum; into_client only ever Pkarr, fail-closed (gateway validated, build err propagated). build_ffi_dht_client: non-testing = ClientDhtConfig::into_client (Pkarr); testing = InMemory seam.
- DisabledDhtClient: publish→Err(Disabled) fail-closed, resolve→Ok(None) honest.

## NEW-surface checks (all clean)
- CI (point 3): `testing` added ONLY to FUNCTIONAL test lanes (Python maturin develop :669, NAPI addon build :701) + parity lanes. Production-config guards UNCHANGED & build WITHOUT testing: rust-test-napi-production (:522 `-p scp-ffi-napi --features server`), rust-build-pyo3-production (:555), rust-build-uniffi-production (:582). Shipped-artifact nullifier-absence preserved. NOT a finding.
- identityLoad DHT fallback (napi scp.rs:823, point 5): external handle = scp_identity:None, in_memory_custody:None, document:Some(public), custody_type:"external", verifying_key_hex:None. Per-instance registry lookup first (with_identity on bi) — B never sees A's keys. Signing ops fail closed via extract_in_memory_state → IDENT_1007 error (ok_or_else, no panic). Key/storage isolation genuinely holds. TS test asserts custodyType==="external".
- get-or-init: no use-after-invalidate / cross-identity leak — cache.remove(did) keyed per-DID; migrate removes old+new.

Compile-verified: scp-identity (testing) + scp-node (prod, no testing) both clean.

## ROUND 3 (delta e54de4fae..5584761bc, PR#2150) -- 2026-07-16 -- NO SECURITY REGRESSION
- R2-1/R2-2 publish-path: build_domain_inner + host_site now route publish through publish_did_document_for_mode. Disabled=Ok(skip, node still starts), Production/Memory=fatal map_err. Match is exhaustive explicit arms (no wildcard `_=>` that could mask Production). +2 tests (domain_disabled_starts_without_publishing / domain_production_publish_failure_fails_closed). build_host_site_node stopped re-deriving DhtMode from skip_nat -> threads real dht_mode (fixes {NatTraversal,Disabled} false-Err).
- R2-4 cfg tighten any(test,feature=testing)->feature=testing on DhtMode::Memory, Memory publish arm, InMemoryDhtClient, StoredItem, FfiDhtClient::InMemory (already testing-only). Strictly LESS reachable; removing `test` disjunct can only shrink cfg-true set. Shipped build (no test, no testing) = absent in both old+new. scp-dht adds SELF dev-dep features=["testing"] so its own cfg(test) unit tests still name InMemoryDhtClient (dev-deps test-only, never shipped graph). scp-dht shipped-config build PASSES.
- R2-6 build_ffi_dht_client hoisted to scp_ffi_common::dht: non-testing arm = ClientDhtConfig::default().into_client() (Pkarr, fail-closed), InMemory arm #[cfg(feature=testing)]. All 3 bridges delegate + map DhtInitError->IDENT_1058.
- R2-3 IDENT_1058 new code, message generic ("failed to initialize production DHT client for DID resolution: {e}") -- no path/internal leak, {e}=DhtInitError (gateway-URL or Pkarr build), fail-closed unchanged.
- GATEWAYS: validate_gateway_url hoisted to scp_dht (byte-identical logic), now shared by FFI into_client AND node build_pkarr_client (previously accepted any non-empty=divergent) -> strict improvement, fail-closed on malformed. R2-5: ci.yml adds `cargo test -p scp-ffi-common` default-features lane so #[cfg(not(feature=testing))] absence tripwires (ffi_dht_client_is_pkarr_only_in_shipped_build / disabled_node_resolution_returns_ok_none) actually run. Positive lane, not enforcement-file weakening.
- Minor obs (non-security): napi/uniffi import InMemoryDhtClient under bare #[cfg(test)] while their test-mod bodies also touch FfiDhtClient::InMemory (feature=testing-gated); compiles because CI runs bridge tests with testing on. Latent build-config coupling, not a shipped-code concern.
