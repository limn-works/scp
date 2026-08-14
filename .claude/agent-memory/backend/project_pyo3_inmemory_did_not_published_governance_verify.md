---
name: pyo3-inmemory-did-not-published-governance-verify
description: PyO3 bridge never publishes in-memory DID docs to its resolver DHT, so genuine governance_propose proposer self-vote verification fails with "unknown voter"; NAPI does publish (publish_to_shared_dht_for + SHARED_DHT_CLIENT)
metadata:
  type: project
---

On branch fix/1866-direct-execute-trust (PR #1870, #1866 direct-execute governance security fix), the two rewritten PyO3 e2e governance tests (test_change_role_after_join, test_remove_member in bindings/python/tests/test_e2e_relay.py) fail in CI.

**Two layered errors:**
1. (Task-stated, real) ceiling missing `governance:propose` → SCP-CTX-2041 permission denied. FIXED by adding `"governance:propose"` to both ceilings. Necessary but not sufficient.
2. (Deeper, uncovered after fix 1) `governance failed: unknown voter: cannot resolve public key for DID did:dht:...` — the genuine `governance_propose` flow (now used after commit c9db30486 closed the direct-execute quorum bypass) makes the runtime governance engine verify the proposer's single_admin SELF-VOTE signature via the production `document_vm_key_resolver` (scp-ffi/common/src/bridge_runtime.rs:95) → IdentityBackedDidResolver::verifying_key_for → resolve_sync → DID document resolution.

**Root cause:** PyO3 in-memory identities are NEVER published to the resolver's DHT.
- PyO3 `ensure_did_resolver_initialized_on` (scp-ffi/src/identity.rs:73) builds a per-instance DualLayerResolver over its OWN `InMemoryDhtClient::new()`.
- PyO3 `identity_create` (identity.rs:818) uses `DidDht::new()` (its own private client, no signer) and registers the document only in the bridge identity registry — never publishes to the resolver's DHT client.
- Verified at runtime: `identity_resolve(in_memory_did)` → SCP-IDENT-1001 "DID not found on DHT". So the governance key_resolver cannot resolve it.
- Bridge signs the proposal with the proposer's LOCAL custody key (resolve_signing_key, context.rs:3324) but the runtime verifies against the published-document-only resolver — mismatch.

**Canonical fix already exists in the NAPI sibling bridge** (scp-ffi/napi/src/identity.rs):
- process-wide `SHARED_DHT_CLIENT` (runtime::shared_dht_client / init_shared_dht_client), resolver built over it;
- `publish_to_shared_dht_for(identity, document, custody)` (napi identity.rs:142) called after identity_create: serializes doc JSON, extract_public_key from DID, bep44_signable(value, seq=1), custody.sign(identity.identity_key, signable), dht_client.publish(pubkey, sig, value, seq). Best-effort (warn on error).
- Comment at context.rs:1292-1293 confirms in-memory identities are deliberately not auto-published; the export path compensates with local-custody-first `resolve_export_verifying_key`. Governance has NO such local-custody-first fallback.

**Two correct fix options (a design decision — escalated, not chosen unilaterally on an auto-merge-armed branch):**
- (A) Port NAPI's shared-DHT publish into PyO3 identity_create (matches reference bridge; keeps governance verification honest against a real published doc). Touches scp-ffi/src/identity.rs + runtime.rs (shared_dht_client slot). Has FFI-conformance/bridge-symmetry implications.
- (B) Give the runtime governance key_resolver a local-custody-first fallback like the export path. Deeper core change.

**RESOLVED (Option A, approved + shipped).** identity_create / identity_create_with_agent_key / identity_create_with_custody now publish the in-memory DID document into a per-instance resolver `InMemoryDhtClient` (new `CoreFields.dht_client` OnceLock + `set_dht_client`/`dht_client`; PyO3 `set_resolver_dht_client`/`resolver_dht_client`; `publish_to_resolver_dht_for` = bep44_signable + custody.sign + dht_client.publish, best-effort). The resolver is built over the SAME retained client, so identity_resolve + the governance `document_vm_key_resolver` resolve in-memory DIDs.

**Option A unmasked TWO latent nested-`block_on` panics** ("Cannot start a runtime from within a runtime"), reachable only once resolution succeeds:
1. `resolvers.rs::IdentityBackedDidResolver::resolve_sync` used `block_in_place`+`Handle::block_on`, only sound on a tokio *worker* thread. PyO3 drives ops via `RUNTIME.block_on(...)` on the (non-worker) calling thread → inner block_on panicked. FIX: run resolution on a dedicated OS thread with its own current-thread runtime (codebase "regime-(c)" pattern, cf. context.rs export signing). NB: spawning back onto the shared runtime + awaiting JoinHandle DEADLOCKS on the current-thread fallback runtime. The `handle` ctor param is now ignored (`_handle`, kept for call-site stability across all 3 bridges).
2. `governance_propose/approve/reject/withdraw` called the SYNC `sync_role_state_from_manager` (own `rt.block_on`) from INSIDE their `rt.block_on` → nested panic. FIX: new `sync_role_state_from_manager_async` (awaits `sup.get_role_state`); 4 in-block_on callers use it. `governance_execute` already had an inline async workaround. 2 test callers keep the sync version.

**Test premise updated:** `test_scpid.py::TestScpIdVerify` — in-memory SCPID verify now SUCCEEDS (`test_verify_succeeds_for_in_memory_identity`); old expect-SCP-IDENT-1033 test was obsolete under Option A.

**bridge_parity local failures = ENVIRONMENTAL** (SCP-VALID-7008 `signed_at_override` needs `testing` feature in alt-bridge subprocess artifacts; wasm pkg-node not built locally) — not caused by this change. See [[feedback-worktree-absolute-path]] and [[feedback-edit-tool-overlay-divergence]].
