---
name: c3c-attestation-count-freshness-bypass
description: c3c-ts attestation_count trust-inflation — caller-controlled CachedAttestation.verified_at/ttl_secs skips signature+revocation verify; persists into durable store
metadata:
  type: project
---

# c3c-ts (ADR-055/ADR-011-amend) attestation_count freshness bypass

**Branch:** c3c-ts. **Finding:** HIGH trust inflation in the credential-layer `attestation_count` participation fact.

Root cause: `AttestationCache::get_verified_attestations` (crates/scp-protocol/src/trust/aggregate.rs:202-235) only re-verifies an entry when `is_expired(now)` (verified_at+ttl_secs < now). FRESH entries are returned with NO `verify_attestation` call (no Ed25519 sig check, no expiry, no revocation). `CachedAttestation.verified_at` and `ttl_secs` are PUBLIC + Deserialize, so a caller supplying `cached_attestations_json` to the bridge `participation_record` op fully controls freshness (set verified_at=now, ttl_secs=u64::MAX → never re-verified).

Path: PyO3/NAPI/UniFFI `participation_record` → `scp_ffi_common::trust_store::verified_attestations` (trust_store.rs:203) → `store.store_cached_attestation(ca)` for each caller entry (PERSISTS to durable ProtocolRepositoryTrustBridge, runtime/store/trust.rs:282, no verify) → `cache.get_verified_attestations` returns fresh entries as-is → `compute_participation_record`'s `credential_attestation_history` only filters `subject==subject_did` && `revocation_status==Active` (both caller-set fields) → `attestation_count` inflated.

**Escalation (persistence poisoning):** because population WRITES the forged entries to the durable store, one `participation_record(ctx, subject, forgedJson)` call poisons the store; subsequent `evaluate_trust(ctx, subject)` calls (which pass empty `"[]"`) read the still-fresh poisoned entries → inflated count even on the default path.

PoC: added a test to trust_store.rs (reverted) — forged attestation (sig=[0u8;64], foreign issuer, fresh) is RETURNED by `verified_attestations` while `verify_attestation` on the same input FAILS. Test passed.

**Docs falsely claim verification:** trust_store.rs:180-182 "currently-valid (non-expired, non-revoked, signature-verified)"; supervisor.rs participation_record doc "accessible, currently-valid attestations".

Mitigators (why HIGH not CRITICAL): `produce_participation_profile` (the SIGNED, externally-trusted artifact) is TEST-ONLY (no bridge wiring) — so a forged count cannot enter a remotely-trusted signed profile yet; default `evaluate_trust` passes empty JSON (needs prior poisoning call); semantics are "verifier-relative". Pre-existing in `aggregate_trust_input`'s verified_attestations path, but newly elevated to a typed cross-binding trust fact here.

**Fix:** caller-supplied cached attestations must be verified on ingest (route through `verify_and_cache` / `verify_attestation`), OR `get_verified_attestations` must not trust a caller-set `verified_at` (treat externally-supplied entries as unverified and verify before count/persist). The cache's invariant "entries are pre-verified" is violated by the raw `store_cached_attestation` population path.

## Same-branch surfaces that are SOUND (audited, no finding)
- UCAN diagnostic (validate.rs `evaluate_ucan`): optional-capability None mode only skips step-6 grant-match; all six bools start false and set true only on pass; within_ceiling still runs; `validate_ucan` enforcement gate unchanged+mandatory. mapBridgeError only ever throws (never exception→success). Audience binding correct (presenting_agent=subject, stricter not weaker).
- PyO3 NoOp→Merkle provider swap: premise overstated — prod paths already used MerkleEventLogProvider on main; delta deletes dead NoOp + upgrades a test. participation_record consumer is read-only; context keying SHA-256(context_id) collision-free; no double-write introduced. test_append_event_log is cfg(testing).
- Convergent leaves: subject_did written by runtime is the affected-member, deterministic; H18 ADVERSE_ACTION_TYPES allowlist strings exactly match GovernanceAction::variant_name() (no spelling-suppression). Leaves currently committer-appended-only (replication dormant) so no live equivocation surface.

## Lower notes
- LOW (by-design / threat-model): governance_actions_against (negative signal) excludes ChangeRole-demotion and RemoveSigner (not in H18 allowlist) — a hostile admin can demote-to-no-capability via ChangeRole to avoid the adverse count. Documented H18 ambiguity choice; flag for threat model.
- LOW: scp.ts:2387 evaluateTrust swallows ContextError into zeroed record via `/event log is empty/i` message-substring match (prose-coupled, the exact anti-pattern ADR-053 removes) — fail-safe direction (zeroes, never inflates).
- LOW (replication-future): undecodable/empty GovernanceActionExecuted payload → target None → never counted against; safe now (committer-written) but a suppression vector once cross-member leaf replication lands.
