# Saga gating granularity (ADR-049 §3a) — re-attack notes (worktree saga-gating, HEAD 5e64ee386)

Per-participant-context-set saga reservation replacing the instance-wide AtomicBool. CI gate `scripts/check-saga-gating-granularity.sh`.

## Concern #1 canonical-key — SOUND (spec-mandated)
- Canonical [u8;32] of ANY context in a saga field is the RAW digest, NOT context_id_bytes(prefixed_string).
- Spec NORMATIVE: 05-contexts.md:1640 (§5.14.13 host/broadcast), :1804 (§5.15.8 derived_context_id = raw digest before prefix+hex), 06-cross-context.md:272/304 (§6.2.4 caller/target id-form). All three saga types carry raw digest; standing = derive_standing_context_digest(local,peer). StandingPairCreate reserves hex(raw_digest) — matches.
- Two known [u8;32] derivations exist (context_id_bytes=SHA256(str), context_routing_id=SHA256(sep||str)) but spec forbids feeding the prefixed string into saga [u8;32] fields. No divergent id form.
- Test `overlap_is_set_membership_across_saga_types` empirically proves it (feeds standing raw digest into cross-context field, asserts SagaBusy collision).

## Concern #2 gate laundering — RESIDUAL: signed-atomic type-list gap (LOW, CI-completeness)
- NEG_TYPE (line 154) lists only UNSIGNED atomics (AtomicBool|U8|U16|U32|U64|Usize) + Mutex<unit/bool/small-unsigned>. SIGNED atomics (AtomicI8/I16/I32/I64/Isize) MISSED.
- CONFIRMED BYPASS: `saga_inflight_count: std::sync::atomic::AtomicI64` Supervisor field passes the gate (in-set name, type not listed), passes clippy (AtomicI64 not a disallowed type), passes no-mutable-globals (struct field not module static). A real instance-wide CAS wedge in start_saga + keeping per-set code cosmetic satisfies P1-P6.
- Fix is ADDITIVE (allowed under NEVER-WEAKEN): add I8|I16|I32|I64|Isize to NEG_TYPE.
- Arbitrary field-NAME misses (e.g. `serialize_all: AtomicBool`) = the gate's HONESTLY DISCLOSED tripwire limit (header lines 20-24). Not a closable defect (infinite namespace). Header is honest, not over-claiming.
- Module-level static / lazy_static / OnceLock wedge: BLOCKED by check-no-mutable-globals.sh (separate NEVER-WEAKEN gate).

## Concern #3 wedge/leak — SOUND
- _reservation is a stack local in async start_saga; RAII drops on every return (Ok/Err/?-propagated journal-IO err) + panic-unwind. FSM runs inline (no tokio::spawn detach), no mem::forget. NeedsRepair returns control → drops → releases.
- Future-cancellation (caller drops start_saga future) RELEASES (safe). Durable non-terminal journal re-take = documented PR-2D replay obligation (field doc supervisor.rs:558-567, excludes NeedsRepair).
- TestForceNeedsRepair: all 7 sites #[cfg(any(test, feature="testing"))]; variant un-constructable in prod FFI build.

## Concern #4 Phase-2C authz gap — DOCUMENTED FORWARD, not exploitable today
- start_saga reachable only via SupervisorHandle::start_saga; ZERO FFI callers (wrap ctor #[allow(dead_code)], "first prod caller commit 11"). All 3 prod variants NotImplemented at Prepare → immediate abort + release.
- Forward-obligation doc supervisor.rs:4408-4427 spells out the victim-context-naming availability attack + "authorize initiator over each named context BEFORE try_reserve_context_set" requirement.

## Verdict: control SOUND. Only residual = signed-atomic NEG_TYPE completeness gap (LOW, additive fix). Everything else is honest-tripwire-limit or documented-forward.
