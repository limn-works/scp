---
name: sec1866-pyo3-inmemory-dht-publish
description: SEC-1866 delta — PyO3 publishes in-memory DID docs to per-instance InMemoryDhtClient for governance vote resolver parity with NAPI. CLEAN.
metadata:
  type: project
---

# SEC-1866 PyO3 in-memory DID publish (branch fix/1866-direct-execute-trust, delta 08222318c..origin)

Reviewed 2026-06-23. CLEAN, zero findings. 7-file delta atop already-reviewed by-id direct-execute fix.

**What it does:** PyO3 `identity_create*` (3 variants: create/with_agent_key/with_custody) now publish freshly-minted in-memory DID docs into a per-instance `InMemoryDhtClient` (new `CoreFields.dht_client` OnceLock, set alongside `set_did_resolver` with the SAME Arc the `DualLayerResolver` reads). Mirrors NAPI's `publish_to_shared_dht_for`/`SHARED_DHT_CLIENT` but per-instance (stronger isolation than NAPI's process-global). Lets the governance vote-verification resolver actually resolve the proposer's self-signed doc instead of failing "unknown voter".

**Why no spoofing/collision (Q1):** `InMemoryDhtClient::publish` (dht_client/mod.rs:126) is keyed by the 32-byte public key and does NOT verify sig — only enforces monotonic seq (`seq <= existing.seq` → no-op). Verification is at RESOLVE time: `DualLayerResolver`→`verify_and_deserialize` (resolver.rs:216) runs `verify_bep44_signature(extract_public_key(did), ...)` (verify_strict) + `verify_self_certification`. The DID string IS the z-base-32 Ed25519 pubkey (extract_public_key dht.rs:2776, canonicality-checked). Publish signs `bep44_signable(value,seq)` with `identity.identity_key` (whose public half == the DID). A doc forged under another DID fails verify_strict against the DID-embedded key. All 3 publish sites mint a BRAND-NEW DID (fresh key) → cannot overwrite another identity's slot; seq=1 correct for fresh doc. identity_load/migrate do NOT publish (no regression).

**Downgrade prevention (Q1) still effective:** two layers, both intact. (a) load-bearing `DidCache::cached_sequence` reject `rec.seq < min_seq` in DualLayerResolver::resolve (resolver.rs:517-545). (b) per-resolver-instance `IdentityBackedDidResolver::seen_sequences`/check_sequence ratchet (resolvers.rs:354) → `ResolutionError::Revoked` on lower seq. Publishing seq=1 in-memory docs doesn't weaken either.

**Trust model (Q2):** Does NOT bypass sig verification — makes the doc AVAILABLE so verification can run. Genuine vote verification = resolver verifies proposer's real published self-signed doc. Correct.

**resolve_sync rewrite (Q3):** dropped the borrowed `tokio::runtime::Handle` (new takes `_handle`, call-site-stable). Now drives resolution on a dedicated `std::thread::scope` OS thread owning a private current-thread runtime; join() back. Regime-(c) pattern. Reason: governance verification runs sync DidResolver deep inside `RUNTIME.block_on` on the CALLING (non-worker) thread → block_in_place invalid + nested Handle::block_on panics. New approach correct/deadlock-free from ALL caller postures. FAIL-CLOSED confirmed: runtime-build-fail/thread-panic → `ResolutionError::NetworkUnavailable`; all verifying_key_for/resolve_public_key paths propagate `?`; `document_vm_key_resolver` (bridge_runtime.rs:95-103) collapses ANY Err→None→governance REJECTS vote. Publish-fail (best-effort, logged) → doc not in DHT → resolve NotFound → None → reject. Never falls through to accept. Underlying DualLayerResolver has per-layer LAYER_TIMEOUT so no unbounded hang.

**Cross-bridge (Q4):** resolve_sync lives in shared scp-ffi-common so the rewrite affects NAPI/UniFFI too — but it's strictly MORE correct (no longer needs block_in_place worker / borrowed handle). NAPI/UniFFI publish path unchanged (they already had it). dht_client slot + publish helper are PyO3-only additions. No security-posture change for other bridges; only removes a latent panic/deadlock class.
