# SEC-1866 delta: PyO3 resolver-DHT publish parity + resolve_sync rewrite

Branch fix/1866-direct-execute-trust, delta 08222318c..origin (7 files). Brings PyO3 to NAPI
parity: publish in-memory DID docs into per-instance resolver InMemoryDhtClient so governance
vote-verification / UCAN validation can resolve them. Fixes nested-block_on panics.

## Verdict: SUBSTANTIALLY CLEAN. 434 scp-ffi + 321 scp-ffi-common Rust tests pass; 25 py tests
pass (incl new test_verify_succeeds_for_in_memory_identity + governance:propose ceiling adds).
Clippy clean. Happy path verified end-to-end.

## Findings (all LOW):
- **resolve_sync drops healing tasks (LOW, non-issue in practice):** new resolve_sync builds a
  per-call current_thread runtime in std::thread::scope, dropped after block_on returns. DualLayerResolver
  §3.10.7 healing uses detached tokio::spawn (resolver.rs:645/660) — those tasks never run on a
  dropped current_thread rt. BUT FFI builds resolver with NoOpRelayQuerier + no healer, so healing
  never fires. Behavioral regression vs old block_in_place(shared-rt) path only if a real healer is
  wired later. Note for future.
- **OnceLock pair race resolver vs dht_client (LOW, GIL-closed):** ensure_did_resolver_initialized_on
  sets did_resolver OnceLock then dht_client OnceLock non-atomically. Under PEP-703 free-threaded
  Python, concurrent first-time identity_create on SAME instance could leave resolver=A's client X
  but dht_client=B's client Y (B wins dht set, loses resolver set) → published doc unresolvable.
  Closed on standard CPython (init runs under GIL, before py.allow_threads at identity.rs:894-896).
  NAPI has analogous cross-instance latent race (its own doc lines 75-83 claim std::sync::Once guard
  but code uses same two-OnceLock pattern — NAPI doc is stale/aspirational).
- **Stale test comment (LOW):** context.rs:6943 "in-memory test identities are never published" now
  FALSE for PyO3 post-PR. Test still passes (uses test_insert_member seam).

## Verified sound:
- Future genuinely Send: AsyncResolveFn returns Pin<Box<dyn Future + Send>>, Arc<dyn Fn+Send+Sync>. OK.
- _handle arg ignored: no caller relied on the retained handle (only resolve_sync used it; rewritten).
- sync_role_state_from_manager_async == sync version (same get_role_state + with_ffi_state, awaits
  vs block_on). All 4 governance callers in context.rs (propose/approve/reject/withdraw) are inside
  RUNTIME.block_on → MUST use async (sync would panic "runtime within runtime"). Remaining 2 sync
  callers (context.rs:6367,6955) are #[test] top-level, NOT inside block_on → safe.
- Same-DID re-create publish: InMemoryDhtClient.publish seq<=existing = silent idempotent no-op
  (dht_client/mod.rs:137-141). seq=1 always. Benign.
- Resolver's InMemoryDhtClient IS the same Arc the publish targets (Arc::clone of dht_client into
  both DualLayerResolver and set_resolver_dht_client). identity.rs:85-98.
- Publish only on 3 create paths (matches NAPI scp.rs:480/611/753); rotate/migrate/load don't
  republish — pre-existing shared-with-NAPI gap, out of delta scope.
- best-effort publish (swallow errors): correct — doc registered locally regardless; only resolver
  discoverability affected; tracing::warn on each failure path.
