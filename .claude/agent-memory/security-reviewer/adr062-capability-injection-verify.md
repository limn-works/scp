---
name: adr062-capability-injection-verify
description: ADR-062 (capability injection / prove-absent nullifiers) docs deliverable security verification — PASS, no blocking findings
metadata:
  type: project
---

# ADR-062 Capability Injection — Security Verification (2026-07-14, HEAD 5482c6917)

Docs deliverable: ADR-062, PRD adr062-capability-injection.json (6 stories 000/001/006/009/010/011), spec §9.7.4.1 reframe, §17.17.
**Verdict: PASS, no residual nullifier reachable in any shipped path.**

## Security thesis (verified against real source)
- Four in-memory NULLIFIERS (custody, attestation, DHT, pre-rotation) → `#[cfg(feature="testing")]`, severed from shipped graphs.
- **G1** (scripts/check-shipped-feature-graph.sh) = SOLE closed ⊆-allowlist, permits durability-only features ONLY (in-memory-storage/in-memory-push), ZERO nullifiers. Asserts scp-platform/testing + scp-dht/testing + scp-testing + scp-core/testing→scp-protocol/testing→scp-did/testing did:key chain absent. Four names are TEST INPUTS not the check (avoids fail-open denylist). Runs per artifact incl. --features server.
- Pre-rotation FAIL-CLOSED is real: `InMemoryPreRotationCustody` is the ONLY impl of trait (scp-platform/src/testing/pre_rotation_custody.rs:67; trait traits.rs:740). Create sigs REQUIRE PreRotationCustody non-optional (dht.rs:1076). config.rs create_inner mints the nullifier on prod path. Story 006 AC (real, machine-verifiable): new IdentityError variant + weld sites stop constructing + async test asserts typed err on no-testing build.

## Verified code facts
- allow_in_memory_custody exists in scp-ffi:27/napi:15/uniffi:32 (all pull scp-platform/testing) — deleted in Slice 6.
- server.rs F1: :22 imports testing::{InMemoryKeyCustody,InMemoryStorage}; :322/:435 IdentitySource<InMemoryKeyCustody> phantoms; :455 InMemoryDhtClient::new(). All enumerated across Stories 000/001/006.
- E2 impl Default for InMemoryCredentialStore (credentials.rs:556) — live SCP-CAPSEL-8000/8011, Story 009 deletes.
- E3 impl Default for BlobStorageBackend (storage.rs:561) — live SCP-CAPSEL-8011, Story 010 deletes.
- E4 NoOpRelayQuerier::query returns `async { Ok(None) }` (resolver.rs) — FAILS CLOSED, correctly NOT a nullifier. Story 011 = completeness (real MultiRelayQuerier §3.10.12).
- did:key edge: scp-protocol/Cargo.toml:47 testing=["scp-did/testing","scp-event-log/testing"]. (lines 58-59 scp-did/testing are dev-deps, don't ship.)
- §9:187 device-attestation-decline authority ACCURATE ("Its absence is expected … not penalizing").

## Spec §9.7.4.1 unwind (point 4): NO guarantee dropped
- Commit 95ae37df5 removed 3a(a) server-KMS floor + 3a(b) passphrase-strength floor; kept 3a core RULE (principal-distinctness), 3a(c) migration-not-daily, at-rest para; added RFC #2130 pointer.
- ZERO shipped code implements pre-rotation realization (grep argon2|passphrase|kms|hsm|shamir|bip39 near pre-rotation = 0). Removed clauses constrained realizations never built. Nothing unconstrained.

## Non-blocking observations
1. G1 classification-completeness limit honestly stated (proves GATED nullifiers absent, not that a future ungated one won't appear); mitigated by A5 single-activation-path + classification table+review. Adding AST/source check would be the over-engineered denylist ADR line 110 rejects. Correct convergent choice.
2. Item 4 menu reverted to "any one is sufficient" — dropped explicit 3a(a)/(b) cross-ref; normative 3a RULE still governs. Suggest a forward-ref in item 4 so constraint survives the RFC #2130 boundary.
3. server.rs:302/329 hardcodes in-memory storage (durability-only, G1-permitted, not a nullifier). Minor SCP-CAPSEL-8000 mandatory-selection tension if it's a real shipped node path.
