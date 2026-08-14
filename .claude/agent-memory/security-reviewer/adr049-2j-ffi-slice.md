---
name: adr049-2j-ffi-slice
description: ADR-049 Phase 2J FFI joiner slice (reserve_key_package + context_join_from_welcome) security review — CLEAN
metadata:
  type: project
---

# ADR-049 Phase 2J FFI joiner slice — CLEAN (2026-07-03)

Branch feat/adr049-2j-ffi-slice, HEAD 92bcff46c. Makes spawn-from-Welcome joiner path production-reachable.

**Verdict: no blocking findings.** Custody enforcement sound on all 3 bridges.

Key security facts verified:
- `Supervisor::reserve_key_package(owning_did)` + `spawn_actor_from_welcome(owning_did, req)` now
  genuinely-`pub` bare-`DID` (ADR-049 §5 bridge-external axis, same trust model as `create_context`).
  NOT on OwnedIdentityDid axis because they return only PUBLIC/context state, never per-identity secret.
- Reservation scoping = NO cross-identity reach: ConfirmConsume routed through
  `build_actor_deps(&owning_did).key_package_store`, so a forged/foreign ReservationId lands in the
  caller's OWN per-identity KeyPackage actor reserved map and simply fails to match. ReservationId is a
  pure lookup key (serde-transparent String), not a capability.
- Reserve returns ONLY public KP bytes (key_package_actor.rs Reserve doc: private signer-state stays in
  actor). No private key crosses FFI.
- Ordering identical on all 3 bridges: custody gate BEFORE irreversible KP consume.
  PyO3/napi custody = identity-registry membership (ensure_local_custody / derive_member_pseudonym →
  SCP-IDENT-1054/1001). UniFFI custody = identity.core_id.is_none() check + check_handle(instance_id).
  Reversible FFI-state register (Occupied hard-fail pre-consume) → spawn → rollback via remove_context.
- Core crash-safety ladder (supervisor.rs ~10489): reversible prechecks A–D (live-actor, real pseudonym
  Precheck B rejects [0u8;32] sentinel, param/ceiling validation, durable first-writer-wins) ALL before
  ConfirmConsume; LIFECYCLE_TIMEOUT bounds the locked region (welcome_bytes MLS DoS guard).
- welcome_bytes NEVER formatted into any error string. No secret leakage in errors/logs. SDK wrappers
  are thin pass-throughs, no logging.
- Enforcement edits ALL additive: matrix +2 rows; pipeline_wiring floor 48→52 + 4 new reach-assertions;
  bridge-aliases +2 canonical; check-sdk-coverage +2 ALIASES. Nothing weakened.

Observations only (non-blocking):
- ReservationId doc-comment "no public string constructor to forge one" is slightly overstated — serde
  Deserialize IS the FFI reconstruction path — but harmless (lookup key scoped to caller's own actor).
- Genuinely-pub bare-DID entrypoints: security rests on the CONVENTION that every caller gates custody
  at the bridge; no compile-time enforcement (matches create_context). pipeline_wiring checks the seam
  is REACHED, not that a custody gate precedes it. Defense-in-depth gap shared with create_context.
