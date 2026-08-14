---
name: adr062-slice1-dht-e1-round2-verdict
description: Round-2 adversarial verdict on ADR-062 Slice 1 / SCP-CAPINJECT-001 (DHT E1) — nullifier removal, fail-closed publish, 4-bridge retype
metadata:
  type: project
---

# ADR-062 Slice 1 (SCP-CAPINJECT-001) DHT E1 — Round-2 Verdict: SHIP (one reservation)

Branch feat/adr062-slice1-dht-e1, verified at e54de4fae. Fix delta 0161e39fe..e54de4fae.

**Why:** Whole workstream exists to keep the in-memory DHT nullifier out of prod. Coder agents previously falsely reported "all green."

**Verified sound (empirically, not just read):**
- `cargo build -p scp-ffi --features server` (prod config, no testing) compiles clean → nullifier absent from shipped lib.
- All `InMemoryDhtClient` refs are `#[cfg(any(test, feature="testing"))]` or in `#[cfg(test)] mod tests`. Shared `FfiDhtClient` (scp-ffi/common/src/dht.rs) gates InMemory arm behind testing; `into_client` only builds Pkarr, fails closed.
- Publish fail-closed: `publish_did_document_for_mode` (scp-node/src/lib.rs) — Disabled=skip (no attempt), Production=FATAL on error, Memory testing-only. Both node tests PASS.
- Sequence fail-closed: `initialize_sequence` (scp-identity/src/dht.rs) propagates resolve Err (rotate/migrate/republish). Test PASSES.
- Cache invalidation coherent (napi+uniffi): all 5 rotation paths + migrate(both DIDs). Rotation republishes to SHARED client (rotation_publish_client / shared_dht_client) + invalidates SHARED cache. Atomic set-if-unset OnceLock init closes finding-F TOCTOU. Tests exercise real rotate_key, assert removal.
- napi identityLoad external handle: keyless (scp_identity/custody/verifying_key all None); all key ops fail closed SCP-IDENT-1007. Flipped TS test (`rejects`→`custodyType==="external"`) is the CORRECT assertion; old one encoded the bug being fixed.
- Default flip Memory→Disabled correct; Memory now `#[cfg(any(test,testing))]`. Finding-E ADR framing honestly discloses self-DID regression (co-located governance inert until Slice 11).

**ci.yml testing opt-in = LEGITIMATE, not a bypass.** Change touches ONLY the two functional-test-harness build steps (Python maturin, TS napi). The three production-guard jobs (rust-build-pyo3-production :534, rust-build-uniffi-production :566, rust-test-napi-production :499) UNTOUCHED — they still prove nullifier absence in prod config. `dht_capability_injection.rs` assertion tests pass in non-testing build.

**Findings (none blocking):**
- MEDIUM: the two `#[cfg(not(feature="testing"))]` assertion tests in dht_capability_injection.rs are compiled OUT of EVERY CI lane (all enable testing via workspace nextest feature unification) → never execute in CI. Real guarantee still held by prod build jobs; tripwire value latent. Fix: add a `cargo test -p scp-ffi-common` (default features) CI lane.
- LOW (part of deferred finding D): napi SHARED_DHT_CLIENT process-global; two instances with different gateways → first-init wins silently. Stateless Pkarr in prod = not a nullifier. Correctly deferred to per-instance refactor before later slices.

**Reservation (honest boundary):** did NOT run full Python governance-E2E / TS integration suites (the round-1 failures the testing seam is meant to fix). Mechanism sound; did not observe green.
