---
name: adr049-2j-ffi-slice
description: ADR-049 Phase 2J FFI slice (reserve_key_package + context_join_from_welcome) crypto review — SOUND; Swift uniffi checksum regen-faithfulness proof
metadata:
  type: project
---

# ADR-049 Phase 2J FFI joiner-handshake slice (branch feat/adr049-2j-ffi-slice, HEAD 92bcff46c)

Exposes MLS joiner handshake across PyO3/NAPI/UniFFI + 4 SDKs: `reserve_key_package(owning_did) -> (ReservationId, public KP bytes)` then `context_join_from_welcome(...)`. Reviewed SOUND, no blocking crypto findings.

**Why:** verify no private key material crosses FFI, §9.10.4 pseudonym correctness, single-use guarantee, discovery linkability, Swift checksum regen.

**How to apply:** reference facts below for future 2J follow-ons / bridge parity reviews.

- NO private key material crosses FFI anywhere. Reserve returns ONLY `(ReservationId string, public KP bytes)` — private signer_state stays fused in KeyPackageStoreActor `reserved` map (`KeyPackageCommand::Reserve` reply is `(ReservationId, Vec<u8>)` public bytes, key_package_actor.rs:411). `context_join_from_welcome` takes welcome_bytes (encrypted MLS Welcome, not our secret). Pseudonym derived internally via custody; only 32-byte PUBLIC routing key surfaces. `PersistedKeyPackage` has hand Drop zeroizing signer_state (key_package_actor.rs:341).
- §9.10.4 pseudonym: derived via `derive_member_pseudonym`/`derive_member_pseudonym_required` at each bridge from locally-custodied identity_key (custody.derive_pseudonym), NEVER caller-supplied. Encrypted path HARD-FAILS on missing custody (IDENT_1054/1055/1056) — no [0u8;32]/constant fallback. Runtime `spawn_actor_from_welcome` ALSO rejects `local_pseudonym==None` for encrypted (supervisor.rs:10565) — belt-and-suspenders, no silent sentinel.
- Discovery routing_id: identical to context_create. join_from_welcome uses derived pseudonym directly (always Some for encrypted). Plain context_join + create both use `local_pseudonym.unwrap_or_else(|| if broadcast {broadcast_routing_id} else {context_routing_id})`. context_routing_id else-branch is effectively unreachable for encrypted (always Some). No linkability regression.
- Single-use INTACT through new public paths: `register_ffi_state` Entry::Occupied HARD-fails BEFORE `spawn_actor_from_welcome` consumes KP (atomic DashMap entry, no TOCTOU) — PyO3 context.rs, napi runtime.rs:register_ffi_state. Bogus reservation → handle_confirm early `InvalidState` lookup miss, burns NOTHING. Double-consume impossible: reservation removed+tombstoned on confirm; init-key replay marker (A2 crypto backstop) with 2-fact own-prior-completion guard. Runtime-join failure → FFI+known-context rollback (remove_context). Reservations per-identity + custody-gated owning_did → no cross-identity reservation theft.
- **Swift ScpBindings.swift `tool_invoke_cross_context_saga` checksum 59585→1312 is REGEN-FAITHFUL, not manual.** PROOF: Kotlin generated bindings dir is gitignored (.gitignore:44); on-disk scp.kt is freshly regenerated (mtime today) against current tree and independently carries saga=1312, reserve=25723, join_from_welcome=31910 — byte-identical to committed Swift. Whole Swift file is a clean wholesale regen (new ReservedKeyPackage struct+FfiConverter+lift/lower+methods). Saga Rust signature byte-identical main vs HEAD. Root cause of drift: commit 11354f1e1 (#2002 scp-primitives→scp_clock/scp_did/scp_crypto dissolution) was newest bridge.rs change but did NOT regen the CHECKED-IN Swift bindings → origin/main ScpBindings.swift saga checksum was STALE (59585); this slice's honest regen corrects it. IMPLICATION: Swift on origin/main was latently broken (uniffiCheckApiChecksums mismatch) for the saga method; this slice fixes it as a side effect. ASYMMETRY: Swift bindings checked-in (must manually regen+commit), Kotlin gitignored (regen at build).
